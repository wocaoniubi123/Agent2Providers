//! Kiro 的会话式转发：发一次 `generateAssistantResponse`，把事件流翻成
//! OpenAI chat SSE。
//!
//! ── 为什么必须走 `conversation` ─────────────────────────────
//! 上游响应是 AWS event stream，网关的 `UpstreamKind` 没有这个变体。走
//! `conversation` 之后，插件自己读帧、自己推标准 chat 帧，网关的账号轮换、
//! 冷却与统计照旧工作。
//!
//! ── 先读第一帧再决定状态码 ────────────────────────────────
//! 上游经常先回 200、再把错误放进流里（`throttlingException` 等）。如果直接
//! 推 200，网关与客户端都会当成一次成功回答。所以这里**预读事件**：
//! 是错误就在还没下发任何帧时直接报错 —— 网关据此换账号或透传给客户端；
//! 已经下发过内容之后才出的错，只补一个 chat 错误帧 + `[DONE]`。

use agent2api_wasm_sdk::{self as sdk, http, json, Result, Value};

use super::credentials::Credentials;
use super::events::{self, Decoder, Event, Usage};
use super::{endpoints, errors, models, refresh, request};

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
fn usage_chunk(model: &str, id: &str, reason: &str, usage: Usage) -> Value {
    let prompt = usage.input + usage.cache_read.max(0);
    let completion = usage.output;
    let mut value = json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": sdk::now() / 1000,
        "model": model,
        "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }],
        "usage": {
            "prompt_tokens": prompt.max(0),
            "completion_tokens": completion.max(0),
            "total_tokens": (prompt + completion).max(0),
            "prompt_tokens_details": { "cached_tokens": usage.cache_read.max(0) },
        },
    });
    if usage.cache_write > 0 {
        value["usage"]["cache_creation_input_tokens"] = json!(usage.cache_write);
    }
    value
}

/// `conversation` 的入口。
pub fn forward(params: &Value) -> Result<()> {
    let mut output = Output::default();
    match run(params, &mut output) {
        Ok(()) => Ok(()),
        // 已下发内容后出错：补一帧错误 + `[DONE]`，不能让半截回答静默中断。
        Err(error) if output.started && !output.complete => {
            let status = error.status.unwrap_or(502);
            sdk::stream_event(&events::error_payload(status, &error.message))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// 下发状态（首帧是否已发、是否已收尾）。
#[derive(Default)]
struct Output {
    started: bool,
    complete: bool,
}

impl Output {
    fn start(&mut self) {
        if !self.started {
            let _ = sdk::stream_head(200);
            self.started = true;
        }
    }
}

fn run(params: &Value, output: &mut Output) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(agent2api_wasm_sdk::Error::http(400, "请求体必须是 JSON 对象"));
    }
    let (record, mut credentials) = refresh::ensure(false)?;
    let account_id = record["id"].as_str().unwrap_or("").to_string();
    // profile：缺失时补一次（额度、目录与对话都要它；失败不阻断）。
    if !credentials.is_api_key() && !credentials.is_local() && credentials.profile.is_empty() {
        if let Ok(profile) = refresh::lookup_profile(&credentials) {
            if !profile.is_empty() {
                credentials.profile = profile;
                let expect = record["secret"].clone();
                let mut next = expect.clone();
                credentials.write_into(&mut next);
                let _ = sdk::host(
                    "account.update",
                    json!({ "expect": expect, "secret": next, "public": super::credentials::public(&next) }),
                );
            }
        }
    }
    let model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| body["model"].as_str().map(str::to_string))
        .unwrap_or_else(|| "auto".to_string());
    let budget = request::thinking_budget(body, &model);
    let native = models::native_of(&account_id, &model);
    let profile = if credentials.is_api_key() { String::new() } else { credentials.profile.clone() };
    let envelope = request::build(body, &model, &profile, budget, native.as_ref());

    let mut response = ask(&credentials, &envelope)?;
    // token 被拒：强刷一次再试（刷新失败时保留原始错误）。
    if response.status == 401 || response.status == 403 {
        if let Ok((_, refreshed)) = refresh::ensure(true) {
            credentials = refreshed;
            response = ask(&credentials, &envelope)?;
        }
    }
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = response.bytes(1024 * 1024)?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        return Err(errors::http_error(status, &text));
    }

    let names = request::tool_names(body);
    let split_thinking = budget.is_some();
    let window = models::window_of(&account_id, &model);
    let mut decoder = Decoder::new(window, split_thinking);
    let mut frames = super::eventstream::FrameReader::default();
    let id = format!("chatcmpl-{}", endpoints::message_id());
    let mut tool_index: i64 = -1;
    let mut tool_open = false;

    loop {
        // 先把已解码的事件全部消费掉。
        while let Some(event) = decoder.next() {
            emit(event, output, &model, &id, &names, &mut tool_index, &mut tool_open)?;
            if output.complete {
                return Ok(());
            }
        }
        if decoder.finished() {
            break;
        }
        let Some(bytes) = response.read()? else {
            decoder.finish();
            while let Some(event) = decoder.next() {
                emit(event, output, &model, &id, &names, &mut tool_index, &mut tool_open)?;
                if output.complete {
                    return Ok(());
                }
            }
            break;
        };
        frames.push(&bytes);
        while let Some(frame) = frames.take()? {
            decoder.frame(&frame);
        }
    }
    if frames.leftover() > 0 {
        return Err(agent2api_wasm_sdk::Error::http(502, "Kiro 的事件流提前结束了"));
    }
    if !output.complete {
        // 事件流安静结束：给一个收尾帧，别让客户端一直等。
        output.start();
        sdk::stream_event(&usage_chunk(&model, &id, "stop", Usage::default()))?;
        sdk::stream_bytes(b"data: [DONE]\n\n")?;
        output.complete = true;
    }
    Ok(())
}

/// 发一次 `generateAssistantResponse`。
fn ask(credentials: &Credentials, body: &Value) -> Result<http::Response> {
    let region = credentials.region();
    let url = format!("{}/generateAssistantResponse", endpoints::runtime(&region));
    let user_agent = endpoints::streaming_user_agent();
    let mut headers = json!({
        "authorization": format!("Bearer {}", credentials.access),
        "x-amzn-codewhisperer-optout": "true",
        "x-amzn-kiro-agent-mode": "vibe",
        "content-type": "application/json",
        "accept": "application/vnd.amazon.eventstream",
        "amz-sdk-invocation-id": endpoints::uuid_v4(),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amz-user-agent": user_agent,
        "user-agent": user_agent,
    });
    if let Some(kind) = credentials.token_type() {
        headers["tokentype"] = json!(kind);
    }
    http::open("POST", &url, headers, Some(body))
}

/// 把一个中立事件落成 chat 帧。
fn emit(
    event: Event,
    output: &mut Output,
    model: &str,
    id: &str,
    names: &[(String, String)],
    tool_index: &mut i64,
    tool_open: &mut bool,
) -> Result<()> {
    match event {
        Event::Text(text) => {
            output.start();
            sdk::stream_event(&chunk(model, id, json!({ "content": text }), None))?;
        }
        Event::Think(text) => {
            output.start();
            sdk::stream_event(&chunk(model, id, json!({ "reasoning_content": text }), None))?;
        }
        Event::ToolStart { id: call_id, name } => {
            *tool_index += 1;
            *tool_open = true;
            let name = names
                .iter()
                .find(|(mapped, _)| mapped == &name)
                .map(|(_, original)| original.clone())
                .unwrap_or(name);
            output.start();
            sdk::stream_event(&chunk(
                model,
                id,
                json!({
                    "tool_calls": [{
                        "index": *tool_index,
                        "id": call_id,
                        "type": "function",
                        "function": { "name": name, "arguments": "" },
                    }]
                }),
                None,
            ))?;
        }
        Event::ToolArgs(args) => {
            if !*tool_open {
                return Ok(());
            }
            output.start();
            sdk::stream_event(&chunk(
                model,
                id,
                json!({ "tool_calls": [{ "index": *tool_index, "function": { "arguments": args } }] }),
                None,
            ))?;
        }
        Event::Stop { reason, usage } => {
            output.start();
            sdk::stream_event(&usage_chunk(model, id, &reason, usage))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            output.complete = true;
        }
        Event::Error { status, text } => {
            let status = status.unwrap_or(502);
            if !output.started {
                // 还没下发：直接报错，让网关按状态码换账号。
                return Err(agent2api_wasm_sdk::Error::http(status, text));
            }
            sdk::stream_event(&events::error_payload(status, &text))?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            output.complete = true;
        }
    }
    Ok(())
}
