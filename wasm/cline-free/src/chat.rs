//! Cline 的对话转发：OpenAI 兼容 `chat/completions`，请求体按白名单重建。
//!
//! ── 白名单重建（移植自 cline-proxy 的 `buildUpstreamBody`）────
//! ```text
//!   固定键   model（**原样保留**，含池前缀 —— 那是上游的通道选择器）
//!            max_tokens（客户端 max_tokens → max_completion_tokens → 128000）
//!            session_id（本轮生成，与 X-Task-ID 头同值）
//!            reasoning_effort（显式值优先，否则 high）
//!   保留     messages / stream
//!   透传     白名单里的可选键（tools / temperature / response_format …）
//! ```
//! 白名单之外的键不上行：上游是 OpenAI 兼容网关，未知键没有意义（照抄参照
//! 实现的口径）。
//!
//! ── 两种错误边界 ────────────────────────────────────────────
//! 还没下发任何帧时直接报错（网关换账号）；已下发过内容时只补一个错误帧 +
//! `[DONE]`，不能把半截回答从头重发。

use agent2api_wasm_sdk::{self as sdk, json, sse::SseDecoder, Error, Result, Value};

use super::{refresh, upstream};

/// `max_tokens` 缺失时的默认值（cline-proxy 同值）。
const DEFAULT_MAX_TOKENS: i64 = 128_000;

/// `reasoning_effort` 缺失时的默认档位（cline-proxy 同值）。
const DEFAULT_REASONING_EFFORT: &str = "high";

/// 白名单透传键（照抄 cline-proxy 的 `passThroughKeys`）。
const PASS_THROUGH_KEYS: &[&str] = &[
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "functions",
    "function_call",
    "temperature",
    "top_p",
    "top_k",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "response_format",
    "user",
    "n",
    "logit_bias",
    "seed",
    "logprobs",
    "top_logprobs",
    "stream_options",
    "metadata",
];

/// 客户端显式给的思考档位（`reasoning_effort` / 驼峰 `reasoningEffort`）。
fn explicit_reasoning_effort(body: &Value) -> Option<String> {
    let object = body.as_object()?;
    for key in ["reasoning_effort", "reasoningEffort"] {
        if let Some(text) = object.get(key).and_then(Value::as_str).filter(|text| !text.trim().is_empty()) {
            return Some(text.trim().to_string());
        }
    }
    None
}

/// 上游请求体的白名单重建。
fn build_upstream_body(body: &Value, session_id: &str) -> Value {
    let get = |key: &str| body.get(key);
    let mut out = serde_json::Map::new();
    if let Some(model) = get("model") {
        out.insert("model".to_string(), model.clone());
    }
    // 数值统一按 f64 读（手写体里可能是 8192.0 这类形态）。
    let max_tokens = get("max_tokens")
        .and_then(Value::as_f64)
        .or_else(|| get("max_completion_tokens").and_then(Value::as_f64))
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|value| value as i64)
        .unwrap_or(DEFAULT_MAX_TOKENS);
    out.insert("max_tokens".to_string(), Value::from(max_tokens));
    out.insert("session_id".to_string(), Value::from(session_id));
    out.insert(
        "reasoning_effort".to_string(),
        Value::from(explicit_reasoning_effort(body).unwrap_or_else(|| DEFAULT_REASONING_EFFORT.to_string())),
    );
    if let Some(messages) = get("messages") {
        out.insert("messages".to_string(), messages.clone());
    }
    out.insert("stream".to_string(), Value::Bool(true));
    for key in PASS_THROUGH_KEYS {
        if let Some(value) = get(key) {
            out.insert((*key).to_string(), value.clone());
        }
    }
    Value::Object(out)
}

/// 下发状态。
#[derive(Default)]
struct Output {
    started: bool,
    complete: bool,
}

impl Output {
    fn start(&mut self) -> Result<()> {
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
        }
        Ok(())
    }

    /// 透传一帧（上游已经是 chat SSE 方言）。
    fn event(&mut self, data: &str) -> Result<()> {
        if self.complete {
            return Ok(());
        }
        let trimmed = data.trim();
        if trimmed == "[DONE]" {
            self.start()?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            self.complete = true;
            return Ok(());
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if value.get("error").is_some_and(|error| !error.is_null()) {
                let class = upstream::classify(502, &value);
                let status = class["status"].as_u64().unwrap_or(502) as u16;
                let message = class["message"].as_str().unwrap_or("Cline 返回了一个错误");
                if !self.started {
                    return Err(Error::http(status, message.to_string()));
                }
                sdk::stream_event(&upstream::error_event(status, message))?;
                sdk::stream_bytes(b"data: [DONE]\n\n")?;
                self.complete = true;
                return Err(Error::http(status, message.to_string()));
            }
        }
        self.start()?;
        sdk::stream_bytes(format!("data: {trimmed}\n\n").as_bytes())
    }

    fn finish(&mut self) -> Result<()> {
        if self.complete {
            return Ok(());
        }
        if !self.started {
            return Err(Error::http(502, "Cline 上游没有返回任何内容帧"));
        }
        sdk::stream_bytes(b"data: [DONE]\n\n")?;
        self.complete = true;
        Ok(())
    }
}

/// `conversation` 的入口。
pub fn forward(params: &Value) -> Result<()> {
    let mut output = Output::default();
    match run(params, &mut output) {
        Ok(()) => Ok(()),
        Err(error) if output.started && !output.complete => {
            let status = error.status.unwrap_or(502);
            sdk::stream_event(&upstream::error_event(status, &error.message))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn run(params: &Value, output: &mut Output) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let mut credentials = refresh::ensure(false)?;
    let session_id = format!("sess_{}", sdk::now());
    let request = build_upstream_body(body, &session_id);
    let mut response = upstream::stream(&credentials, &session_id, &request)?;
    // token 被拒：强刷一次再试（刷新失败时保留原始错误）。
    if response.status == 401 || response.status == 403 {
        if let Ok(refreshed) = refresh::ensure(true) {
            credentials = refreshed;
            response = upstream::stream(&credentials, &session_id, &request)?;
        }
    }
    let content_type = response.headers["content-type"].as_str().unwrap_or("").to_ascii_lowercase();
    if content_type.contains("application/json") {
        let value = response.json()?;
        return whole(&value, output);
    }
    let mut decoder = SseDecoder::default();
    while let Some(bytes) = response.read()? {
        for event in decoder.push(&bytes)? {
            output.event(&event)?;
            if output.complete {
                return Ok(());
            }
        }
    }
    output.finish()
}

/// 上游忽略了 `stream`：把整段回答折成一帧再收尾。
fn whole(value: &Value, output: &mut Output) -> Result<()> {
    if value.get("error").is_some_and(|error| !error.is_null()) {
        let class = upstream::classify(502, value);
        return Err(Error::http(
            class["status"].as_u64().unwrap_or(502) as u16,
            class["message"].as_str().unwrap_or("Cline 返回了一个错误").to_string(),
        ));
    }
    let choice = value["choices"].get(0).cloned().unwrap_or(Value::Null);
    let message = choice["message"].clone();
    let finish = choice["finish_reason"].as_str().unwrap_or("stop").to_string();
    let mut chunk = json!({
        "id": value["id"].clone(),
        "object": "chat.completion.chunk",
        "created": value["created"].clone(),
        "model": value["model"].clone(),
        "choices": [{ "index": 0, "delta": message, "finish_reason": Value::Null }],
    });
    if value.get("usage").is_some() {
        chunk["usage"] = value["usage"].clone();
    }
    output.event(&chunk.to_string())?;
    let tail = json!({
        "id": value["id"].clone(),
        "object": "chat.completion.chunk",
        "created": value["created"].clone(),
        "model": value["model"].clone(),
        "choices": [{ "index": 0, "delta": {}, "finish_reason": finish }],
    });
    output.event(&tail.to_string())?;
    output.event("[DONE]")
}
