//! 上游 **v1internal / Gemini SSE** → 标准 chat SSE（状态机）。
//!
//! 逐条镜像网关的 `core::protocol::antigravity_stream`（native 侧由网关翻译，
//! wasm 侧没有翻译层，所以这一层搬进插件）。
//!
//! ── 信封解包 ────────────────────────────────────────────────
//! 上游每帧是 v1internal 包装：真正的 Gemini 响应在 `response` 键下，
//! **缺省回退顶层**（两套参考实现都是这个取值链）。
//!
//! ── parts 折叠 ─────────────────────────────────────────────
//! ```text
//!   .text + thought != true   → delta.content
//!   .text + thought == true   → delta.reasoning_content
//!   functionCall{name,args,id} → **一次给全**的 tool_calls 增量
//!                                （本家的工具调用是整体事件，不是「宣告帧 + 参数帧」）
//!   inlineData                → chat 形态装不下，跳过
//!   独占一帧的签名 part        → 暂存给紧随其后的 functionCall
//! ```
//!
//! ── finishReason / usage / 收尾时序 ────────────────────────
//!   · 归一表见 [`map_finish_reason`]；发过工具调用且归一结果是 `stop` 时强制
//!     `tool_calls`（否则客户端把「还要继续调工具」当成对话结束）；
//!   · `usageMetadata` → chat usage（`completion = candidates + thoughts`）；
//!   · 完成信号 = `finishReason` **或** `data: [DONE]`；EOF 前一个都没见到
//!     → 按截断报错（错误帧 + `[DONE]`，**不补** finish）。

use agent2api_wasm_sdk::{json, Value};

use super::endpoints;

/// 上游 `finishReason` → chat `finish_reason`。
fn map_finish_reason(raw: &str) -> String {
    match raw.trim().to_ascii_uppercase().as_str() {
        "MAX_TOKENS" => "length".to_string(),
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => "content_filter".to_string(),
        _ => "stop".to_string(),
    }
}

/// `usageMetadata` → chat usage。
fn usage_metadata(usage: &Value) -> Value {
    let number = |key: &str| usage.get(key).and_then(Value::as_i64).unwrap_or(0);
    let prompt = number("promptTokenCount");
    let thoughts = number("thoughtsTokenCount");
    let mut candidates = number("candidatesTokenCount");
    let total = number("totalTokenCount");
    if candidates == 0 && total > 0 {
        candidates = (total - prompt - thoughts).max(0);
    }
    let cached = number("cachedContentTokenCount");
    json!({
        "prompt_tokens": prompt,
        "completion_tokens": candidates + thoughts,
        "total_tokens": if total > 0 { total } else { prompt + candidates + thoughts },
        "prompt_tokens_details": { "cached_tokens": cached },
    })
}

/// 上游错误状态码 → 下行 `error.type`。
fn error_type(status: u16) -> &'static str {
    match status {
        400 | 422 => "invalid_request_error",
        401 | 403 => "authentication_error",
        404 => "not_found",
        429 => "rate_limit_error",
        500 | 502 => "upstream_error",
        503 => "temporarily_unavailable",
        _ => "upstream_error",
    }
}

/// 一帧上游 JSON → 零到多个 chat 帧的状态机。
pub struct Translator {
    model: String,
    id: String,
    created: i64,
    started: bool,
    finished: bool,
    saw_finish: bool,
    finish_reason: Option<String>,
    tool_index: i64,
    tools_emitted: bool,
    pending_signature: Option<String>,
    usage: Option<Value>,
}

impl Translator {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            id: String::new(),
            created: agent2api_wasm_sdk::now() / 1000,
            started: false,
            finished: false,
            saw_finish: false,
            finish_reason: None,
            tool_index: 0,
            tools_emitted: false,
            pending_signature: None,
            usage: None,
        }
    }

    /// 已经收尾。
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// `data: [DONE]`：立即收尾（没有 finishReason 时按 stop 兜底）。
    pub fn done(&mut self) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        self.saw_finish = true;
        let reason = self.finish_reason.clone().unwrap_or_else(|| "stop".to_string());
        self.complete(&reason)
    }

    /// 一帧上游 JSON → 零到多个 chat 帧。
    pub fn consume(&mut self, event: &Value) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        // 信封解包：真身在 `response` 键下，缺省回退顶层。
        let inner = event.get("response").filter(|value| value.is_object()).unwrap_or(event);
        if let Some(error) = inner.get("error").filter(|value| !value.is_null()) {
            return self.fail(error);
        }
        if self.id.is_empty() {
            if let Some(id) = inner.get("responseId").and_then(Value::as_str).filter(|id| !id.is_empty()) {
                self.id = id.to_string();
            }
        }
        if let Some(usage) = inner.get("usageMetadata").filter(|value| value.is_object()) {
            self.usage = Some(usage_metadata(usage));
        }
        let Some(candidate) = inner.pointer("/candidates/0") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(parts) = candidate.pointer("/content/parts").and_then(Value::as_array) {
            for part in parts {
                out.extend(self.consume_part(part));
            }
        }
        if let Some(raw) = candidate
            .get("finishReason")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
        {
            self.saw_finish = true;
            self.finish_reason = Some(map_finish_reason(raw));
        }
        out
    }

    /// 一个 part → 零到多个 chat 帧。
    fn consume_part(&mut self, part: &Value) -> Vec<Value> {
        let Some(object) = part.as_object() else {
            return Vec::new();
        };
        let signature = object
            .get("thoughtSignature")
            .or_else(|| object.get("thought_signature"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|signature| !signature.is_empty())
            .map(str::to_string);
        let text = object.get("text").and_then(Value::as_str).unwrap_or("");
        let is_thought = object.get("thought").and_then(Value::as_bool).unwrap_or(false);
        // 签名先记住：任何带签名的 part 都可能是紧随其后的 functionCall 的来源。
        if signature.is_some() {
            self.pending_signature = signature;
        }
        if let Some(call) = object.get("functionCall").and_then(Value::as_object).filter(|call| !call.is_empty()) {
            let signature = self.pending_signature.take();
            return self.tool_call_frames(&Value::Object(call.clone()), signature);
        }
        if text.is_empty() {
            // `inlineData`（响应侧图片）在 chat 形态里装不下：跳过。
            return Vec::new();
        }
        let mut out = self.start();
        if is_thought {
            out.push(self.delta_frame(json!({ "reasoning_content": text })));
        } else {
            out.push(self.delta_frame(json!({ "content": text })));
        }
        out
    }

    /// `functionCall` → 一次给全的 `tool_calls` 增量。
    fn tool_call_frames(&mut self, call: &Value, signature: Option<String>) -> Vec<Value> {
        let name = call.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let raw_id = call.get("id").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let id = if raw_id.is_empty() {
            format!("call_{}", endpoints::message_id())
        } else {
            raw_id
        };
        let arguments = match call.get("args") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Null) | None => "{}".to_string(),
            Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
        };
        let index = self.tool_index;
        self.tool_index += 1;
        self.tools_emitted = true;
        let mut tool = serde_json::Map::new();
        tool.insert("index".to_string(), json!(index));
        tool.insert("id".to_string(), json!(id));
        tool.insert("type".to_string(), json!("function"));
        tool.insert("function".to_string(), json!({ "name": name, "arguments": arguments }));
        if let Some(signature) = signature {
            // 签名随增量带出（Google 自家 OpenAI 兼容端点的字段位置）。
            tool.insert("extra_content".to_string(), json!({ "google": { "thought_signature": signature } }));
        }
        let mut out = self.start();
        out.push(self.delta_frame(json!({ "tool_calls": [Value::Object(tool)] })));
        out
    }

    /// 首帧（role assistant），只发一次。
    fn start(&mut self) -> Vec<Value> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
        if self.id.is_empty() {
            self.id = format!("chatcmpl-{}", endpoints::message_id());
        }
        vec![self.delta_frame(json!({ "role": "assistant", "content": "" }))]
    }

    /// 收尾：finish 帧 + usage 帧（调用方负责 `[DONE]`）。
    fn complete(&mut self, reason: &str) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        if !self.started && self.finish_reason.is_none() {
            self.finished = true;
            return vec![self.error_frame("上游返回空响应（没有任何内容帧）", "rate_limit_error", 429, None)];
        }
        self.finished = true;
        // 发过工具调用时把 stop 修补成 tool_calls。
        let finish = match reason {
            "stop" if self.tools_emitted => "tool_calls",
            other => other,
        };
        let mut out = self.start();
        out.push(json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": finish }],
            "usage": self.usage_payload(),
        }));
        out
    }

    /// 上游错误对象 → 错误帧。
    fn fail(&mut self, error: &Value) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let message = {
            let text = error.get("message").and_then(Value::as_str).unwrap_or("");
            if text.trim().is_empty() {
                error.to_string()
            } else {
                text.to_string()
            }
        };
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .or_else(|| error.get("code").and_then(Value::as_str).and_then(|text| text.trim().parse().ok()));
        // Google 把语义写在 `error.status` 字符串里：数字 code 缺失/越界时按它兜底。
        let status = code
            .and_then(|code| u16::try_from(code).ok())
            .filter(|status| (100..=599).contains(status))
            .unwrap_or_else(|| {
                match error.get("status").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase().as_str() {
                    "RESOURCE_EXHAUSTED" => 429,
                    "PERMISSION_DENIED" | "UNAUTHENTICATED" => 401,
                    "NOT_FOUND" => 404,
                    "UNAVAILABLE" => 503,
                    "DEADLINE_EXCEEDED" | "INTERNAL" => 502,
                    _ => 502,
                }
            });
        vec![self.error_frame(&message, error_type(status), status, code)]
    }

    /// 协议级失败 → chat 错误帧。
    pub fn fail_message(&mut self, message: &str, status: u16) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        vec![self.error_frame(message, error_type(status), status, None)]
    }

    /// 空流（一个完成信号都没见到就 EOF）→ 截断错误帧。
    pub fn truncated(&mut self) -> Vec<Value> {
        if self.finished {
            return Vec::new();
        }
        if !self.saw_finish {
            return self.fail_message("上游流在收到结束原因之前结束（响应被截断）", 502);
        }
        let reason = self.finish_reason.clone().unwrap_or_else(|| "stop".to_string());
        self.complete(&reason)
    }

    /// chat 口径的 usage（没有 usageMetadata 时给零值）。
    fn usage_payload(&self) -> Value {
        self.usage.clone().unwrap_or_else(|| {
            json!({ "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 })
        })
    }

    fn error_frame(&self, message: &str, kind: &str, status: u16, code: Option<i64>) -> Value {
        let mut error = json!({
            "message": message,
            "type": kind,
            "status": status,
        });
        if let Some(code) = code {
            error["code"] = json!(code);
        }
        let mut frame = json!({ "error": error });
        if status == 429 {
            frame["retry_after"] = json!(30);
        }
        frame
    }

    fn delta_frame(&self, delta: Value) -> Value {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": delta, "finish_reason": Value::Null }],
        })
    }
}
