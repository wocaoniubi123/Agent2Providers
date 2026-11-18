//! Kiro 事件 → 中立的增量事件（文本 / 思考 / 工具调用 / 用量）。
//!
//! ── 思考标签 ────────────────────────────────────────────────
//! 一部分模型（Claude）把思考写在回复正文的 `<thinking>…</thinking>` 里。
//! 这个解析器负责把两段切开，**跨 chunk** 也能正确切：标签可能被拆在
//! 两次增量里（`<thin` + `king>`），所以未闭合的后缀要暂存到下一次。
//!
//! ── 用量 ────────────────────────────────────────────────────
//! Kiro 通常只给 `contextUsagePercentage`（上下文用了百分之几），不给 token
//! 数。此时按「窗口大小 × 百分比」估算输入，输出按正文字符数 / 4 估算；
//! 两者都只是**估算**，但比报 0 有用（报表能看出量级）。

use agent2api_wasm_sdk::{json, Value};

use super::eventstream::Frame;
use super::errors;

/// 一条增量事件。
pub enum Event {
    Text(String),
    Think(String),
    ToolStart { id: String, name: String },
    ToolArgs(String),
    Stop { reason: String, usage: Usage },
    Error { status: Option<u16>, text: String },
}

/// 一次回复的用量（OpenAI chat 的口径）。
#[derive(Clone, Copy, Default)]
pub struct Usage {
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
    /// Kiro 真的给了 tokenUsage（否则输入是估算的）
    pub reported: bool,
}

/// 事件解码器：把一帧变成零到多个事件，并在流结束时给收尾事件。
pub struct Decoder {
    think: ThinkParser,
    pending: Vec<Event>,
    usage: Usage,
    percentage: f64,
    said: usize,
    tools: usize,
    current_tool: Option<String>,
    stop_reason: String,
    failed: Option<String>,
    finished: bool,
    window: i64,
    split_thinking: bool,
}

impl Decoder {
    pub fn new(window: i64, split_thinking: bool) -> Self {
        Self {
            think: ThinkParser::default(),
            pending: Vec::new(),
            usage: Usage::default(),
            percentage: 0.0,
            said: 0,
            tools: 0,
            current_tool: None,
            stop_reason: String::new(),
            failed: None,
            finished: false,
            window,
            split_thinking,
        }
    }

    /// 已经结束（收尾事件已排空）。
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// 吃一帧。
    pub fn frame(&mut self, frame: &Frame) {
        if frame.is_error() {
            let text = errors::exception_text(&frame.error_kind(), &String::from_utf8_lossy(&frame.payload));
            self.failed = Some(text);
            return;
        }
        let payload = String::from_utf8_lossy(&frame.payload).to_string();
        let Ok(value) = serde_json::from_str::<Value>(&payload) else {
            return;
        };
        match frame.event_type.as_str() {
            "assistantResponseEvent" => {
                let text = value.get("content").and_then(Value::as_str).unwrap_or("");
                if text.is_empty() {
                    return;
                }
                self.said += text.chars().count();
                if self.split_thinking {
                    let produced = self.think.feed(text);
                    self.pending.extend(produced);
                } else {
                    self.pending.push(Event::Text(text.to_string()));
                }
            }
            "reasoningContentEvent" => {
                if let Some(text) = value.get("text").and_then(Value::as_str) {
                    if !text.is_empty() {
                        self.said += text.chars().count();
                        self.pending.push(Event::Think(text.to_string()));
                    }
                }
            }
            "toolUseEvent" => self.tool_event(&value),
            "metadataEvent" | "messageMetadataEvent" => {
                if let Some(reason) = value.get("stopReason").and_then(Value::as_str) {
                    self.stop_reason = reason.to_string();
                }
                if let Some(usage) = value.get("tokenUsage").filter(|value| value.is_object()) {
                    self.usage.reported = true;
                    // `uncachedInputTokens` 已排除缓存；只有它缺失时才用
                    // `inputTokens`（部分实现在那里给总数），两者不能相加。
                    let uncached = number(usage.get("uncachedInputTokens"));
                    self.usage.input += if uncached > 0 { uncached } else { number(usage.get("inputTokens")) };
                    self.usage.output += number(usage.get("outputTokens"));
                    self.usage.cache_read += number(usage.get("cacheReadInputTokens"));
                    self.usage.cache_write += number(usage.get("cacheWriteInputTokens"));
                    let percentage = number_f(value.get("contextUsagePercentage").unwrap_or(&Value::Null));
                    if percentage > 0.0 {
                        self.percentage = percentage;
                    }
                }
            }
            "contextUsageEvent" => {
                let percentage = number_f(value.get("contextUsagePercentage").unwrap_or(&Value::Null));
                if percentage > 0.0 {
                    self.percentage = percentage;
                }
            }
            _ => {}
        }
    }

    /// 取下一个事件（流结束时自动补收尾事件）。
    pub fn next(&mut self) -> Option<Event> {
        if !self.pending.is_empty() {
            return self.pending.drain(..1).next();
        }
        if self.finished {
            return None;
        }
        None
    }

    /// 流结束：冲刷思考残留，落收尾事件（`Stop` 或 `Error`）。
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.split_thinking {
            for event in self.think.end() {
                self.pending.push(event);
            }
        }
        if let Some(error) = self.failed.take() {
            let status = if errors::stream_error_is_too_long(&error) {
                Some(400)
            } else if errors::stream_error_is_quota(&error) {
                Some(429)
            } else {
                None
            };
            self.pending.push(Event::Error { status, text: error });
            return;
        }
        if self.usage.input == 0 && self.percentage > 0.0 && self.window > 0 {
            self.usage.input = ((self.percentage / 100.0) * self.window as f64) as i64;
        }
        if self.usage.output == 0 {
            self.usage.output = ((self.said as i64 + 3) / 4).max(0);
        }
        let full = self.stop_reason.eq_ignore_ascii_case("model_context_window_exceeded");
        if full && self.said == 0 && self.tools == 0 {
            self.pending.push(Event::Error {
                status: Some(400),
                text: format!(
                    "{}{}",
                    errors::TOO_LONG,
                    "the reply stopped as the model's context window was full (MODEL_CONTEXT_WINDOW_EXCEEDED)"
                ),
            });
            return;
        }
        let reason = if self.tools > 0 {
            "tool_calls"
        } else if full {
            "length"
        } else if self.stop_reason.eq_ignore_ascii_case("max_tokens") {
            "length"
        } else if self.stop_reason.eq_ignore_ascii_case("content_filtered") {
            "content_filter"
        } else {
            "stop"
        };
        self.pending.push(Event::Stop { reason: reason.to_string(), usage: self.usage });
    }

    fn tool_event(&mut self, value: &Value) {
        let id = value.get("toolUseId").and_then(Value::as_str).unwrap_or("").to_string();
        let name = value.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        if !id.is_empty() && self.current_tool.as_deref() != Some(id.as_str()) {
            // 同一工具的后续增量不重复发 ToolStart。
            self.current_tool = Some(id.clone());
            self.tools += 1;
            self.pending.push(Event::ToolStart { id, name });
        }
        if let Some(input) = value.get("input").filter(|value| !value.is_null()) {
            if let Some(text) = input.as_str() {
                if !text.is_empty() {
                    self.said += text.chars().count();
                    self.pending.push(Event::ToolArgs(text.to_string()));
                }
            } else {
                let encoded = serde_json::to_string(input).unwrap_or_default();
                if encoded != "{}" {
                    self.said += encoded.chars().count();
                    self.pending.push(Event::ToolArgs(encoded));
                }
            }
        }
    }
}

fn number(value: Option<&Value>) -> i64 {
    value.and_then(Value::as_i64).unwrap_or(0)
}

fn number_f(value: &Value) -> f64 {
    value.as_f64().unwrap_or(0.0)
}

/// `<thinking>` 标签切分器（与参考实现的 `ThinkParser` 同构）。
#[derive(Default)]
pub struct ThinkParser {
    state: u8,
    buffer: String,
    said: bool,
}

const OPEN: &str = "<thinking>";
const CLOSE: &str = "</thinking>";

impl ThinkParser {
    fn feed(&mut self, text: &str) -> Vec<Event> {
        self.buffer.push_str(text);
        let mut out = Vec::new();
        loop {
            match self.state {
                0 => {
                    let trimmed = self.buffer.trim_start_matches([' ', '\t', '\r', '\n']).to_string();
                    if trimmed.starts_with(OPEN) {
                        self.buffer = trimmed[OPEN.len()..].to_string();
                        self.state = 1;
                        continue;
                    }
                    if trimmed.len() < OPEN.len() && OPEN.starts_with(&trimmed) {
                        return out;
                    }
                    self.state = 2;
                }
                1 => {
                    if !self.said {
                        self.buffer = self.buffer.trim_start_matches(['\r', '\n']).to_string();
                        if self.buffer.is_empty() {
                            return out;
                        }
                    }
                    if let Some(index) = self.buffer.find(CLOSE) {
                        if index > 0 {
                            out.push(Event::Think(self.buffer[..index].to_string()));
                            self.said = true;
                        }
                        self.buffer = self.buffer[index + CLOSE.len()..]
                            .trim_start_matches(['\r', '\n'])
                            .to_string();
                        self.state = 2;
                        continue;
                    }
                    let hold = partial_suffix(&self.buffer, CLOSE);
                    let keep = self.buffer.len().saturating_sub(hold);
                    if keep > 0 {
                        // 按字符边界切，避免把多字节字符砍断。
                        let cut = floor_boundary(&self.buffer, keep);
                        if cut > 0 {
                            out.push(Event::Think(self.buffer[..cut].to_string()));
                            self.buffer = self.buffer[cut..].to_string();
                            self.said = true;
                        }
                    }
                    return out;
                }
                _ => {
                    if !self.buffer.is_empty() {
                        out.push(Event::Text(std::mem::take(&mut self.buffer)));
                    }
                    return out;
                }
            }
        }
    }

    pub fn end(&mut self) -> Vec<Event> {
        if self.buffer.is_empty() {
            return Vec::new();
        }
        let event = if self.state == 1 {
            Event::Think(std::mem::take(&mut self.buffer))
        } else {
            Event::Text(std::mem::take(&mut self.buffer))
        };
        self.state = 2;
        vec![event]
    }
}

/// 结尾有多长的「可能是标签开头」的后缀。
fn partial_suffix(text: &str, tag: &str) -> usize {
    let limit = (tag.len() - 1).min(text.len());
    for length in (1..=limit).rev() {
        if text.ends_with(&tag[..length]) {
            return length;
        }
    }
    0
}

/// 不超过 `limit` 的最大字符边界。
fn floor_boundary(text: &str, limit: usize) -> usize {
    let mut cut = limit.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

/// 错误帧的 JSON 形态（网关按 `{error:{message,type,status}}` 认）。
pub fn error_payload(status: u16, message: &str) -> Value {
    json!({
        "error": {
            "type": if status == 429 { "rate_limit_error" } else { "api_error" },
            "message": message,
            "status": status,
        }
    })
}
