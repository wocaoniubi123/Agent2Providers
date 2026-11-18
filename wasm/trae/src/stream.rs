//! 上游 SOLO SSE → OpenAI 形状的转换。
//!
//! ── 这条流上有三件事必须先想清楚再写代码 ──────────────────
//! 1. **上游不发 `[DONE]`**。结束帧是 `event: done`，`[DONE]` 是这里补的；
//!    上游中途断掉（没有 done）也要补，否则客户端永远等在最后一片上。
//! 2. **业务错误藏在 200 的流里**（`event: error`）。它不是 chunk，
//!    而是一条 `event: error` + 之后的 `[DONE]`；分类见 `errors.rs`。
//! 3. `token_usage` 随下一帧发送；EOF 或传输失败时仍须冲刷已收到的用量。
//!
//! 帧的**键顺序**不是契约（Go 的 map 序列化按 key 排序，serde 按插入顺序），
//! 所以对拍比的是解析后的 JSON；`id` 与 `created` 每次运行都不同。

use agent2api_wasm_sdk::{json, Value};

use super::errors::{error_event_fields, stream_error_kind, ErrorKind};

/// 上游流里的一行（不含行尾换行）。切行要跨 chunk 累积：一帧被切在 chunk
/// 边界上是本文件最难查的一类 bug（症状是"偶尔少开头几个字"）。
#[derive(Default)]
pub struct ByteLines {
    buffer: Vec<u8>,
}

impl ByteLines {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                let line = std::mem::take(&mut self.buffer);
                lines.push(String::from_utf8_lossy(&line).into_owned());
            } else if self.buffer.len() < 1024 * 1024 {
                self.buffer.push(*byte);
            }
        }
        lines
    }

    pub fn finish(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let line = std::mem::take(&mut self.buffer);
        Some(String::from_utf8_lossy(&line).into_owned())
    }
}

/// 一条已解析的上游事件。`metadata` / `timing_cost` / `extra_info` / 未知名
/// 都归到 `Other`：当前实现**不处理**它们（这是参考实现的既有行为）。
#[derive(Clone, Debug, PartialEq)]
pub enum SoloEvent {
    Output { response: String, reasoning: String, tool_calls: Option<Value> },
    TokenUsage(Value),
    Done { finish_reason: String },
    Error { code: i64, message: String },
    Other,
}

/// 解析一条完整事件（`data` 是同一事件内多行 `data:` 累加后的结果）。
/// JSON 不合法时返回 `None` —— 参考实现是"忽略这一帧"，不是"报错断流"。
pub fn parse_solo_event(event: &str, data: &str) -> Option<SoloEvent> {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return Some(match event {
            "done" | "response_done" | "stream_done" => SoloEvent::Done { finish_reason: "stop".to_string() },
            _ if data.trim() == "[DONE]" => SoloEvent::Done { finish_reason: "stop".to_string() },
            _ => SoloEvent::Other,
        });
    }
    let mut parsed: Value = serde_json::from_str(data).ok()?;
    if let Some(inner) = parsed.as_str().and_then(|text| serde_json::from_str::<Value>(text).ok()) {
        if inner.is_object() {
            parsed = inner;
        }
    }
    let event = if event.is_empty() {
        parsed
            .get("event")
            .or_else(|| parsed.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    } else {
        event
    };
    let (code, message) = error_event_fields(&parsed);
    if event == "error"
        || parsed.get("error").is_some_and(|error| !error.is_null())
        || (code != 0 && !message.is_empty() && !parsed.get("response").is_some_and(Value::is_string))
    {
        return Some(SoloEvent::Error { code, message });
    }
    Some(match event {
        "" | "output" | "message" | "delta" | "content" | "text" | "answer" | "chunk" | "output_delta"
        | "message_delta" => {
            let empty = Value::Null;
            let delta = parsed.get("delta").filter(|value| value.is_object()).unwrap_or(&empty);
            let response = first_text(&[
                parsed.get("response"),
                parsed.get("content"),
                delta.get("content"),
                parsed.get("delta"),
                parsed.get("text"),
                parsed.get("message"),
            ]);
            let reasoning = first_text(&[
                parsed.get("reasoning_content"),
                parsed.get("reasoning"),
                delta.get("reasoning_content"),
                delta.get("reasoning"),
            ]);
            SoloEvent::Output {
                response,
                reasoning,
                tool_calls: parsed
                    .get("tool_calls")
                    .or_else(|| delta.get("tool_calls"))
                    .cloned()
                    .filter(|value| !value.is_null()),
            }
        }
        "token_usage" => SoloEvent::TokenUsage(parsed.get("usage").cloned().unwrap_or(parsed)),
        "done" | "response_done" | "stream_done" => SoloEvent::Done { finish_reason: finish_reason(&parsed) },
        _ => SoloEvent::Other,
    })
}

fn first_text(values: &[Option<&Value>]) -> String {
    values
        .iter()
        .filter_map(|value| value.and_then(Value::as_str))
        .find(|text| !text.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn finish_reason(value: &Value) -> String {
    let reason = value
        .get("finish_reason")
        .or_else(|| value.get("stop_reason"))
        .or_else(|| value.get("finishReason"))
        .and_then(Value::as_str)
        .unwrap_or("stop");
    match reason {
        "max_tokens" | "max_output_tokens" | "max_length" => "length",
        "sensitive" => "content_filter",
        "" => "stop",
        other => other,
    }
    .to_string()
}

/// 一行一行的 SSE 状态机（跨行累积 `event:` 与多个 `data:`）。
#[derive(Default, Debug)]
pub struct SseScanner {
    event: String,
    data: String,
}

impl SseScanner {
    /// 喂一行（不含行尾换行）。返回该行**触发**的事件；一行可以触发一个，
    /// 也可以像大多数行那样返回 `None`（累积中）。
    pub fn feed_line(&mut self, line: &str) -> Option<SoloEvent> {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if self.event.is_empty() && self.data.is_empty() {
                self.reset();
                return None;
            }
            let event = parse_solo_event(&self.event, &self.data);
            self.reset();
            return event;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            self.event = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            // 刻意不 trim：参考实现是**直接拼接**，多行 data 之间因此留下
            // 一个空格（`{"response":` + ` "y"}`），拼出来才是合法 JSON。
            self.data.push_str(rest);
        }
        // `:` 开头是注释行，忽略；其它前缀（含 `id:`）同样忽略。
        None
    }

    pub fn finish(&mut self) -> Option<SoloEvent> {
        let event = parse_solo_event(&self.event, &self.data);
        self.reset();
        event
    }

    fn reset(&mut self) {
        self.event.clear();
        self.data.clear();
    }
}

/// 转换后的一帧出站内容。
#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    /// 一个 OpenAI chunk（`data: {…}`）。
    Chunk(Value),
    /// 流内业务错误：一句转义后的文案（native 的 `render` 用它补一条
    /// `{"error": …}` 事件，读的人自己判失败）。
    Error { code: i64, message: String, kind: ErrorKind },
    /// `data: [DONE]`
    Done,
}

/// 流式转换器。
pub struct SoloStream {
    id: String,
    created: i64,
    scanner: SseScanner,
    /// `token_usage` 读到后欠着，随下一帧一起发。
    pending_usage: Option<Value>,
    reasoning: String,
    last_reasoning: String,
    had_error: bool,
    saw_output: bool,
    tool_calls_seen: bool,
    saw_done: bool,
    completed: bool,
}

impl SoloStream {
    pub fn new(id: String, created: i64) -> Self {
        Self {
            id,
            created,
            scanner: SseScanner::default(),
            pending_usage: None,
            reasoning: String::new(),
            last_reasoning: String::new(),
            had_error: false,
            saw_output: false,
            tool_calls_seen: false,
            saw_done: false,
            completed: false,
        }
    }

    /// 喂一行，返回该行产生的帧。
    pub fn feed_line(&mut self, line: &str) -> Vec<Frame> {
        if self.completed {
            return Vec::new();
        }
        let Some(event) = self.scanner.feed_line(line) else {
            return Vec::new();
        };
        self.apply(event)
    }

    fn apply(&mut self, event: SoloEvent) -> Vec<Frame> {
        match event {
            SoloEvent::Output { response, reasoning, tool_calls } => {
                if self.had_error {
                    return Vec::new();
                }
                let mut delta = serde_json::Map::new();
                if !response.is_empty() {
                    delta.insert("content".to_string(), json!(response));
                }
                let reasoning = self.reasoning_delta(reasoning);
                if !reasoning.is_empty() {
                    delta.insert("reasoning_content".to_string(), json!(reasoning));
                }
                if let Some(calls) = tool_calls {
                    let calls = normalize_stream_tool_calls(calls);
                    if calls.as_array().is_some_and(|calls| !calls.is_empty()) {
                        self.tool_calls_seen = true;
                        delta.insert("tool_calls".to_string(), calls);
                    }
                }
                if delta.is_empty() {
                    return Vec::new();
                }
                self.saw_output = true;
                vec![self.chunk(Value::Object(delta), None)]
            }
            SoloEvent::TokenUsage(usage) => {
                self.pending_usage = Some(usage);
                Vec::new()
            }
            SoloEvent::Done { finish_reason } => {
                self.completed = true;
                let sent = self.saw_done;
                self.saw_done = true;
                let finish = if finish_reason == "stop" && self.tool_calls_seen {
                    "tool_calls".to_string()
                } else {
                    finish_reason
                };
                let mut frames = if self.had_error {
                    if self.pending_usage.is_some() {
                        vec![self.chunk(json!({}), None)]
                    } else {
                        Vec::new()
                    }
                } else {
                    vec![self.chunk(json!({}), Some(finish))]
                };
                if !sent {
                    frames.push(Frame::Done);
                }
                frames
            }
            SoloEvent::Error { code, message } => {
                self.had_error = true;
                let kind = stream_error_kind(code, &message);
                // error 后仍读取可能到来的用量；只有完整 done 事件结束读取。
                vec![Frame::Error { code, message, kind }]
            }
            SoloEvent::Other => Vec::new(),
        }
    }

    fn reasoning_delta(&mut self, incoming: String) -> String {
        let duplicate = (incoming == self.last_reasoning && incoming.chars().count() >= 8)
            || (self.reasoning.chars().count() >= 16
                && incoming.chars().count() >= 16
                && self.reasoning.ends_with(&incoming));
        self.last_reasoning = incoming.clone();
        if duplicate {
            return String::new();
        }
        let delta = if self.reasoning.chars().count() >= 16 {
            incoming.strip_prefix(&self.reasoning).unwrap_or(&incoming).to_string()
        } else {
            incoming
        };
        self.reasoning.push_str(&delta);
        delta
    }

    pub fn completed(&self) -> bool {
        self.completed
    }

    /// 补发的 [DONE] 只供客户端收尾，不代表上游正常结束；判定前须冲刷尾事件。
    pub fn missing_terminal(&self) -> bool {
        self.saw_output && !self.completed && !self.had_error
    }

    pub fn flush_pending(&mut self) -> Vec<Frame> {
        let mut frames = match self.scanner.finish() {
            Some(event) => self.apply(event),
            None => Vec::new(),
        };
        if self.pending_usage.is_some() {
            frames.push(self.chunk(json!({}), None));
        }
        frames
    }

    /// EOF 时保留已收到的尾数据与用量，结束标记只发一次。
    pub fn finish(&mut self) -> Vec<Frame> {
        let mut frames = self.flush_pending();
        if !self.saw_done {
            frames.push(Frame::Done);
        }
        self.saw_done = true;
        frames
    }

    fn chunk(&mut self, delta: Value, finish_reason: Option<String>) -> Frame {
        let mut choice = serde_json::Map::new();
        choice.insert("index".to_string(), json!(0));
        choice.insert("delta".to_string(), delta);
        if let Some(reason) = finish_reason {
            choice.insert("finish_reason".to_string(), json!(reason));
        }
        let mut chunk = serde_json::Map::new();
        chunk.insert("id".to_string(), json!(self.id));
        chunk.insert("object".to_string(), json!("chat.completion.chunk"));
        chunk.insert("created".to_string(), json!(self.created));
        // `model` 在这里留空：对外名字由 `forward::render` 改写成客户端请求的那个
        // （上游帧里 `model` 恒为空串，参考实现如此）。
        chunk.insert("model".to_string(), json!(""));
        chunk.insert("choices".to_string(), Value::Array([Value::Object(choice)].to_vec()));
        if let Some(usage) = self.pending_usage.take() {
            chunk.insert("usage".to_string(), usage);
        }
        Frame::Chunk(Value::Object(chunk))
    }
}

/// 流式 tool_call 片段的字段整形：`function_call` → `function`，
/// 并剥掉 SOLO 专属的 `namespace` / `partial_arguments`（上游带着它们）。
fn normalize_stream_tool_calls(calls: Value) -> Value {
    let Value::Array(list) = calls else {
        return if calls.is_object() { Value::Array(vec![normalize_one_call(calls)]) } else { json!([]) };
    };
    Value::Array(list.into_iter().filter(|call| call.is_object()).map(normalize_one_call).collect())
}

fn normalize_one_call(call: Value) -> Value {
    let Value::Object(mut call) = call else {
        return call;
    };
    if let Some(function) = call.remove("function_call") {
        call.insert("function".to_string(), strip_solo_only_fields(function));
    } else if let Some(function) = call.get("function").cloned() {
        call.insert("function".to_string(), strip_solo_only_fields(function));
    }
    Value::Object(call)
}

fn strip_solo_only_fields(function: Value) -> Value {
    let Value::Object(mut function) = function else {
        return function;
    };
    function.remove("namespace");
    function.remove("partial_arguments");
    Value::Object(function)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(solo: &mut SoloStream, lines: &[&str]) -> Vec<Frame> {
        let mut frames = Vec::new();
        for line in lines {
            frames.extend(solo.feed_line(line));
        }
        frames
    }

    #[test]
    fn output_event_becomes_openai_chunk() {
        let mut solo = SoloStream::new("chatcmpl-1".into(), 7);
        let frames = feed(&mut solo, &["event: output", r#"data: {"response":"he"}"#, ""]);
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], Frame::Chunk(_)));
        if let Frame::Chunk(chunk) = &frames[0] {
            assert_eq!(chunk["choices"][0]["delta"]["content"], "he");
            assert_eq!(chunk["object"], "chat.completion.chunk");
            assert_eq!(chunk["model"], "");
            assert!(chunk["choices"][0]["finish_reason"].is_null());
        }
    }

    #[test]
    fn multi_line_data_is_concatenated() {
        // 上游按行切 JSON（`{"response":` + ` "y"}`），拼出来才是合法 JSON
        let mut solo = SoloStream::new("chatcmpl-1".into(), 0);
        let frames = feed(&mut solo, &["event: output", r#"data: {"response":"#, r#"data: "y"}"#, ""]);
        assert!(matches!(frames[0], Frame::Chunk(_)));
        if let Frame::Chunk(chunk) = &frames[0] {
            assert_eq!(chunk["choices"][0]["delta"]["content"], "y");
        }
    }

    #[test]
    fn usage_is_owed_to_the_next_frame() {
        let mut solo = SoloStream::new("chatcmpl-1".into(), 0);
        let frames = feed(&mut solo, &["event: token_usage", r#"data: {"usage":{"prompt_tokens":3}}"#, ""]);
        assert!(frames.is_empty());
        let frames = feed(&mut solo, &["event: done", r#"data: {"finish_reason":"stop"}"#, ""]);
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0], Frame::Chunk(_)));
        if let Frame::Chunk(chunk) = &frames[0] {
            assert_eq!(chunk["usage"]["prompt_tokens"], 3);
            assert_eq!(chunk["choices"][0]["finish_reason"], "stop");
        }
        assert_eq!(frames[1], Frame::Done);
        assert!(solo.completed());
    }

    #[test]
    fn error_event_keeps_reading_and_skips_later_output() {
        let mut solo = SoloStream::new("chatcmpl-1".into(), 0);
        let frames = feed(&mut solo, &["event: error", r#"data: {"code":1005,"message":"quota"}"#, ""]);
        assert!(matches!(frames[0], Frame::Error { .. }));
        if let Frame::Error { code, message, kind } = &frames[0] {
            assert_eq!(*code, 1005);
            assert_eq!(message, "quota");
            assert_eq!(*kind, ErrorKind::PlanLimit);
        }
        // error 之后上游还会继续发帧：内容不再转出，但用量仍要收下
        let frames = feed(&mut solo, &["event: output", r#"data: {"response":"x"}"#, ""]);
        assert!(frames.is_empty());
        let frames = feed(&mut solo, &["event: done", r#"data: {}"#, ""]);
        assert_eq!(frames, vec![Frame::Done]);
    }

    #[test]
    fn tool_calls_finish_reason() {
        let mut solo = SoloStream::new("chatcmpl-1".into(), 0);
        let frames = feed(&mut solo, &[
            "event: output",
            r#"data: {"tool_calls":[{"function_call":{"name":"f","arguments":"{}","namespace":"n"}}]}"#,
            "",
        ]);
        assert!(matches!(frames[0], Frame::Chunk(_)));
        if let Frame::Chunk(chunk) = &frames[0] {
            assert_eq!(chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["name"], "f");
            // SOLO 专属字段被剥掉
            assert!(chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["namespace"].is_null());
        }
        let frames = feed(&mut solo, &["event: done", r#"data: {}"#, ""]);
        assert!(matches!(frames[0], Frame::Chunk(_)));
        if let Frame::Chunk(chunk) = &frames[0] {
            // 见过 tool_calls 时 stop 要翻成 tool_calls
            assert_eq!(chunk["choices"][0]["finish_reason"], "tool_calls");
        }
    }

    #[test]
    fn missing_terminal_only_when_output_seen() {
        let mut solo = SoloStream::new("chatcmpl-1".into(), 0);
        feed(&mut solo, &["event: output", r#"data: {"response":"x"}"#, ""]);
        assert!(solo.missing_terminal());
        let frames = solo.finish();
        assert_eq!(frames.last(), Some(&Frame::Done));
    }
}
