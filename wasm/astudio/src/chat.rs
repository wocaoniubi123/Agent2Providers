//! AStudio 的会话式转发：Responses 请求 → 标准 chat SSE。
//!
//! ── 为什么走 `conversation` ────────────────────────────────
//! 上游说 OpenAI Responses，网关的 `UpstreamKind` 只有 Chat / Anthropic /
//! Ndjson / Gemini / 混合快照。插件自己读 Responses 的 SSE 事件、翻成 chat
//! 帧，就不用扩协议；账号轮换、冷却、统计仍由网关负责。
//!
//! ── 非流式请求也按流式发 ────────────────────────────────────
//! 上游的 Responses 流是逐事件下发的；插件统一推 SSE 帧，非流式请求由网关
//! 侧聚合（与豆包工作等有状态家同一处置）。
//!
//! ── 两种错误边界（与 atomcode / kiro 同一条纪律）─────────────
//!   · **还没下发任何帧**：`Err` 直接冒泡 → 网关按状态码换账号 / 冷却；
//!   · **已经下发过帧**：补一个 chat 错误帧 + `[DONE]` 再返回 Err —— 客户端
//!     已经看到内容了，不能把半截回答从头重发。

use agent2api_wasm_sdk::{self as sdk, json, sse::SseDecoder, Error, Result, Value};

use super::{account, client, responses};

/// 一帧 chat 增量。
fn chunk(model: &str, id: &str, delta: Value, finish: Option<&str>) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": sdk::now() / 1000,
        "model": model,
        "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
    })
}

/// 收尾帧（带 usage）。
fn usage_chunk(model: &str, id: &str, reason: &str, usage: (i64, i64, i64)) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": sdk::now() / 1000,
        "model": model,
        "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }],
        "usage": {
            "prompt_tokens": usage.0.max(0),
            "completion_tokens": usage.1.max(0),
            "total_tokens": (usage.0 + usage.1).max(0),
            "prompt_tokens_details": { "cached_tokens": usage.2.max(0) },
        },
    })
}

/// `conversation` 的入口。
pub fn forward(params: &Value) -> Result<()> {
    let mut started = false;
    match run(params, &mut started) {
        Ok(()) => Ok(()),
        Err(error) if started => {
            sdk::stream_event(&json!({
                "error": {
                    "message": error.message,
                    "type": if error.status == Some(429) { "rate_limit_error" } else { "api_error" },
                    "status": error.status.unwrap_or(502),
                }
            }))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn run(params: &Value, started: &mut bool) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| body["model"].as_str().map(str::to_string))
        .unwrap_or_else(|| "astronclaw-auto".to_string());
    let key = account::model_key()?;
    let request = responses::build_request(body, &model, true);
    let mut response = client::responses(&key, &request)?;
    let content_type = response.headers["content-type"].as_str().unwrap_or("").to_ascii_lowercase();
    if content_type.contains("application/json") {
        // 上游忽略了 stream=true：把整段响应折成 chat 帧。
        let value = response.json()?;
        return whole(&value, &model, started);
    }
    let id = format!("chatcmpl-{}", sdk::now());
    let mut decoder = SseDecoder::default();
    let mut tool_index: i64 = -1;
    let mut tool_args_sent = false;
    let mut text_sent = false;
    let mut usage = (0i64, 0i64, 0i64);
    while let Some(bytes) = response.read()? {
        for payload in decoder.push(&bytes)? {
            let trimmed = payload.trim();
            if trimmed == "[DONE]" {
                if !*started {
                    return Err(Error::http(502, "AStudio 在开始回答前就结束了响应"));
                }
                sdk::stream_event(&usage_chunk(&model, &id, "stop", usage))?;
                sdk::stream_bytes(b"data: [DONE]\n\n")?;
                return Ok(());
            }
            let Ok(event) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
            match kind {
                "response.created" | "response.in_progress" => continue,
                "error" | "response.failed" => {
                    let message = failure_message(&event);
                    let status = classify_message(&message);
                    if !*started {
                        return Err(Error::http(status, message));
                    }
                    sdk::stream_event(&client::error_body(status, &message))?;
                    sdk::stream_bytes(b"data: [DONE]\n\n")?;
                    return Ok(());
                }
                "response.completed" | "response.done" | "response.incomplete" => {
                    usage = responses::usage_of(&event);
                    let reason = if kind == "response.incomplete" { "length" } else { "stop" };
                    if !*started {
                        start(&model, &id, started)?;
                    }
                    sdk::stream_event(&usage_chunk(&model, &id, reason, usage))?;
                    sdk::stream_bytes(b"data: [DONE]\n\n")?;
                    return Ok(());
                }
                _ => {}
            }
            if !*started {
                start(&model, &id, started)?;
            }
            match kind {
                "response.output_item.added" => {
                    let item = event.get("item").cloned().unwrap_or(Value::Null);
                    if item.get("type").and_then(Value::as_str) == Some("function_call") {
                        let call_id = item
                            .get("call_id")
                            .and_then(Value::as_str)
                            .or_else(|| item.get("id").and_then(Value::as_str))
                            .unwrap_or("")
                            .to_string();
                        let name = item.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                        tool_index += 1;
                        tool_args_sent = false;
                        sdk::stream_event(&chunk(
                            &model,
                            &id,
                            json!({
                                "tool_calls": [{
                                    "index": tool_index,
                                    "id": call_id,
                                    "type": "function",
                                    "function": { "name": name, "arguments": "" },
                                }]
                            }),
                            None,
                        ))?;
                    }
                }
                "response.output_text.delta" | "response.text.delta" => {
                    if let Some(text) = event.get("delta").and_then(Value::as_str) {
                        if !text.is_empty() {
                            text_sent = true;
                            sdk::stream_event(&chunk(&model, &id, json!({ "content": text }), None))?;
                        }
                    }
                }
                "response.output_text.done" | "response.text.done" => {
                    // 只有没收到增量时才用整段（避免重复）。
                    if !text_sent {
                        if let Some(text) = event.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                text_sent = true;
                                sdk::stream_event(&chunk(&model, &id, json!({ "content": text }), None))?;
                            }
                        }
                    }
                }
                "response.reasoning_summary_text.delta"
                | "response.reasoning_text.delta"
                | "response.reasoning.delta" => {
                    if let Some(text) = event.get("delta").and_then(Value::as_str) {
                        if !text.is_empty() {
                            sdk::stream_event(&chunk(&model, &id, json!({ "reasoning_content": text }), None))?;
                        }
                    }
                }
                "response.function_call_arguments.delta" => {
                    if let Some(args) = event.get("delta").and_then(Value::as_str) {
                        if !args.is_empty() && tool_index >= 0 {
                            tool_args_sent = true;
                            sdk::stream_event(&chunk(
                                &model,
                                &id,
                                json!({ "tool_calls": [{ "index": tool_index, "function": { "arguments": args } }] }),
                                None,
                            ))?;
                        }
                    }
                }
                "response.function_call_arguments.done" => {
                    // 有些实现只在 done 里给完整参数；增量没来过时补一次。
                    if !tool_args_sent && tool_index >= 0 {
                        if let Some(args) = event.get("arguments").and_then(Value::as_str) {
                            if !args.is_empty() {
                                tool_args_sent = true;
                                sdk::stream_event(&chunk(
                                    &model,
                                    &id,
                                    json!({ "tool_calls": [{ "index": tool_index, "function": { "arguments": args } }] }),
                                    None,
                                ))?;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // 没有 response.completed 也没 [DONE]：补一帧收尾，别让客户端一直等。
    if !*started {
        return Err(Error::http(502, "AStudio 在开始回答前就结束了响应"));
    }
    sdk::stream_event(&usage_chunk(&model, &id, "stop", usage))?;
    sdk::stream_bytes(b"data: [DONE]\n\n")
}

/// 下发首帧（role assistant），只做一次。
fn start(model: &str, id: &str, started: &mut bool) -> Result<()> {
    if *started {
        return Ok(());
    }
    sdk::stream_head(200)?;
    sdk::stream_event(&chunk(model, id, json!({ "role": "assistant", "content": "" }), None))?;
    *started = true;
    Ok(())
}

/// 非流式（上游回了一整个 JSON）：把 `output` 数组折成 chat 帧。
fn whole(value: &Value, model: &str, started: &mut bool) -> Result<()> {
    let id = format!("chatcmpl-{}", sdk::now());
    let items = value.get("output").and_then(Value::as_array).cloned().unwrap_or_default();
    start(model, &id, started)?;
    let mut tool_index: i64 = -1;
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                for part in item.get("content").and_then(Value::as_array).into_iter().flatten() {
                    if part.get("type").and_then(Value::as_str) == Some("output_text") {
                        if let Some(text) = part.get("text").and_then(Value::as_str).filter(|text| !text.is_empty()) {
                            sdk::stream_event(&chunk(model, &id, json!({ "content": text }), None))?;
                        }
                    }
                }
            }
            Some("reasoning") => {
                for part in item.get("summary").and_then(Value::as_array).into_iter().flatten() {
                    if let Some(text) = part.get("text").and_then(Value::as_str).filter(|text| !text.is_empty()) {
                        sdk::stream_event(&chunk(model, &id, json!({ "reasoning_content": text }), None))?;
                    }
                }
            }
            Some("function_call") => {
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("id").and_then(Value::as_str))
                    .unwrap_or("");
                let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = item.get("arguments").and_then(Value::as_str).unwrap_or("{}");
                tool_index += 1;
                sdk::stream_event(&chunk(
                    model,
                    &id,
                    json!({
                        "tool_calls": [{
                            "index": tool_index,
                            "id": call_id,
                            "type": "function",
                            "function": { "name": name, "arguments": arguments },
                        }]
                    }),
                    None,
                ))?;
            }
            _ => {}
        }
    }
    sdk::stream_event(&usage_chunk(model, &id, "stop", responses::usage_of(value)))?;
    sdk::stream_bytes(b"data: [DONE]\n\n")
}

/// 错误事件里的文案。
fn failure_message(event: &Value) -> String {
    event
        .pointer("/response/error/message")
        .and_then(Value::as_str)
        .or_else(|| event.get("message").and_then(Value::as_str))
        .or_else(|| event.pointer("/error/message").and_then(Value::as_str))
        .unwrap_or("AStudio 返回了一个错误")
        .to_string()
}

/// 错误文案 → HTTP 状态（尽力而为，与 native 同判据）。
fn classify_message(message: &str) -> u16 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("rate limit")
        || lower.contains("too many requests")
        || lower.contains("quota")
        || lower.contains("balance")
        || lower.contains("credit")
        || lower.contains("积分")
        || lower.contains("额度")
    {
        return 429;
    }
    if lower.contains("context")
        || lower.contains("too long")
        || lower.contains("maximum length")
        || lower.contains("too large")
    {
        return 400;
    }
    502
}
