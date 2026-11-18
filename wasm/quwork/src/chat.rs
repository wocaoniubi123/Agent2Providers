//! QuWork 的对话转发：OpenAI 兼容 `chat/completions`，插件自己发、自己推 SSE。
//!
//! ── 为什么不用 `chat` ───────────────────────────────────────
//! 网关对 wasm 包的 `build_chat_request_async` 直接回 501，`forwards_response()`
//! 对 wasm 恒为 true —— 所以 `conversation` 是唯一会被调用的入口。
//!
//! ── 首帧判定（两种错误边界）──────────────────────────────────
//! 上游有两种失败形态，处置完全不同：
//!   · **还没下发任何帧**：直接报错（`Err`）→ 网关按状态码换账号 / 冷却；
//!   · **已经下发过帧**：只能补一个 chat 错误帧 + `[DONE]`，再返回 Err 让
//!     网关记账 —— 不能把半截回答从头重发（客户端已经收到内容了）。
//!
//! ── 目录是白名单 ────────────────────────────────────────────
//! native 在发送前查目录：目录里没有的模型直接报「请先刷新模型列表」，
//! 不把任意模型名发到上游（也顺带拿到该模型的 `compat` 开关）。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::{account, errors, models, upstream};

/// 一次对话的状态：是否已下发首帧、是否已收尾。
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

    /// 透传一帧。
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
        // 流内错误：OpenAI 兼容实现既可能给 `{"error":{…}}`，也可能给一帧
        // 带 `error` 字段的正常帧。未下发时按错误码报，已下发时补错误帧。
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if value.get("error").is_some_and(|error| !error.is_null()) {
                let error = errors::http_error_of(502, &value);
                if !self.started {
                    return Err(error);
                }
                sdk::stream_event(&errors::error_event(&error))?;
                sdk::stream_bytes(b"data: [DONE]\n\n")?;
                self.complete = true;
                return Err(error);
            }
        }
        self.start()?;
        sdk::stream_bytes(format!("data: {trimmed}\n\n").as_bytes())
    }

    /// 上游正常结束（读到 EOF，但没有 `[DONE]`）。
    fn finish(&mut self) -> Result<()> {
        if self.complete {
            return Ok(());
        }
        if !self.started {
            return Err(Error::http(502, "QuWork 上游没有返回任何内容帧"));
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
        // 已下发内容后出错：补一帧错误再返回，让网关知道这次是失败而不是正常结束。
        Err(error) if output.started && !output.complete => {
            sdk::stream_event(&errors::error_event(&error))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn run(params: &Value, output: &mut Output) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let requested = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| body["model"].as_str().map(str::to_string))
        .ok_or_else(|| Error::http(400, "请求缺少模型名称"))?;
    let catalog = models::current();
    let row = catalog
        .model(&requested)
        .ok_or_else(|| Error::http(400, "QuWork 当前目录没有这个模型，请先刷新模型列表"))?
        .clone();
    let token = account::model_token()?;
    let body = adapt(body, &requested, &row);
    let mut headers = upstream::headers();
    headers["authorization"] = json!(format!("Bearer {token}"));
    headers["content-type"] = json!("application/json");
    headers["accept"] = json!("text/event-stream");
    let url = format!("{}/chat/completions", upstream::MODEL_ORIGIN);
    let mut response = http::open("POST", &url, headers, Some(&body))?;
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = response.bytes(1024 * 1024)?;
        let error: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(errors::http_error_of(status, &error));
    }
    let content_type = response.headers["content-type"].as_str().unwrap_or("").to_ascii_lowercase();
    if content_type.contains("application/json") {
        // 上游忽略了 stream=true：把整段回答折成一帧再收尾。
        let value = response.json()?;
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(errors::http_error_of(502, &value));
        }
        let choice = value["choices"].get(0).cloned().unwrap_or(Value::Null);
        let message = choice["message"].clone();
        let finish = choice["finish_reason"].as_str().unwrap_or("stop").to_string();
        let mut delta = json!({
            "id": value["id"].clone(),
            "object": "chat.completion.chunk",
            "created": value["created"].clone(),
            "model": requested,
            "choices": [{ "index": 0, "delta": message, "finish_reason": Value::Null }],
        });
        if value.get("usage").is_some() {
            delta["usage"] = value["usage"].clone();
        }
        output.event(&delta.to_string())?;
        let tail = json!({
            "id": value["id"].clone(),
            "object": "chat.completion.chunk",
            "created": value["created"].clone(),
            "model": requested,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": finish }],
        });
        output.event(&tail.to_string())?;
        return output.event("[DONE]");
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

/// 按目录里的 `compat` 改写请求体（逐条来自 native `chat::build`）。
fn adapt(body: &Value, model: &str, row: &Value) -> Value {
    let compat = row.get("compat").unwrap_or(&Value::Null);
    let mut body = body.clone();
    body["model"] = json!(model);
    body["stream"] = json!(true);
    body["stream_options"] = json!({ "include_usage": true });
    if compat.get("supportsStore").and_then(Value::as_bool) == Some(false) {
        if let Some(object) = body.as_object_mut() {
            object.remove("store");
        }
    }
    if compat.get("maxTokensField").and_then(Value::as_str) == Some("max_tokens") {
        if let Some(limit) = body.as_object_mut().and_then(|object| object.remove("max_completion_tokens")) {
            body["max_tokens"] = limit;
        }
    }
    let deepseek = compat.get("thinkingFormat").and_then(Value::as_str) == Some("deepseek");
    if deepseek {
        if let Some(level) = read_client_level(&body) {
            if body.get("thinking").is_none_or(Value::is_null) {
                let levels = row.get("reasoningEfforts").and_then(Value::as_object);
                let normalized = if level == "none" { "off" } else { level.as_str() };
                if let Some(wire) = levels
                    .and_then(|levels| levels.get(normalized))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                {
                    if normalized == "off" {
                        body["thinking"] = json!({ "type": "disabled" });
                        if let Some(object) = body.as_object_mut() {
                            object.remove("reasoning_effort");
                        }
                    } else {
                        body["thinking"] = json!({ "type": "enabled" });
                        body["reasoning_effort"] = json!(wire);
                    }
                }
            }
        }
    }
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if compat.get("supportsDeveloperRole").and_then(Value::as_bool) == Some(false)
                && message.get("role").and_then(Value::as_str) == Some("developer")
            {
                message["role"] = json!("system");
            }
            if compat
                .get("requiresReasoningContentOnAssistantMessages")
                .and_then(Value::as_bool)
                == Some(true)
                && message.get("role").and_then(Value::as_str) == Some("assistant")
                && message.get("reasoning_content").is_none_or(Value::is_null)
            {
                message["reasoning_content"] = message
                    .get("reasoning")
                    .filter(|value| value.is_string())
                    .cloned()
                    .unwrap_or(json!(""));
            }
        }
    }
    body
}

/// 客户端显式给的思考档位（`reasoning_effort` 或 `reasoning.effort`）。
fn read_client_level(body: &Value) -> Option<String> {
    body.get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/reasoning/effort").and_then(Value::as_str))
        .map(str::trim)
        .filter(|level| !level.is_empty())
        .map(str::to_string)
}
