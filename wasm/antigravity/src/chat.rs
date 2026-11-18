//! Antigravity 的会话式转发：v1internal `:streamGenerateContent?alt=sse` →
//! 标准 chat SSE。
//!
//! ── 为什么插件自己翻译 ──────────────────────────────────────
//! native 报 `UpstreamKind::Gemini`，由网关的 `AntigravityToChatStream` 翻译；
//! wasm 侧**没有翻译层**，所以 `stream` 模块把网关那份状态机搬了进来。
//!
//! ── 基址取 daily ────────────────────────────────────────────
//! `sandbox → daily → prod` 是环境而不是地区；聊天流量取 `daily`（9router 的
//! 长期选择，且不是最容易 429 的 prod）。端点级 failover 由网关的换账号承担。
//!
//! ── 两种错误边界 ────────────────────────────────────────────
//!   · 还没下发任何帧：`Err` 直接冒泡（网关按状态码换账号 / 冷却）；
//!   · 已下发过内容：补一个 chat 错误帧 + `[DONE]`，不能让半截回答静默中断。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::credentials::AntigravityCredentials;
use super::{endpoints, models, outbound, refresh, stream};

/// `conversation` 的入口。
pub fn forward(params: &Value) -> Result<()> {
    let mut started = false;
    match run(params, &mut started) {
        Ok(()) => Ok(()),
        Err(error) if started => {
            sdk::stream_event(&json!({
                "error": {
                    "message": error.message,
                    "type": if error.status == Some(429) { "rate_limit_error" } else { "upstream_error" },
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
    let requested = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| body["model"].as_str().map(str::to_string));
    let Some(requested) = requested else {
        return Err(Error::http(
            400,
            "Antigravity 请求缺少 model 字段（本家的模型名放在请求体里，没有路径段的模型名可用）",
        ));
    };
    let (_, mut credentials) = refresh::ensure(false)?;
    let wire_model = models::upstream_model_id(&requested);
    let envelope = outbound::request_from_chat(body, &wire_model, &credentials.project_id, enterprise(&credentials))
        .map_err(|error| Error::http(400, format!("Antigravity 请求转换失败：{error}")))?;
    let url = endpoints::stream_generate_url(endpoints::V1_BASE_URL_DAILY);
    let mut response = ask(&credentials, &wire_model, &url, &envelope)?;
    // token 被拒：强刷一次再试（刷新失败时保留原始错误）。
    if response.status == 401 || response.status == 403 {
        if let Ok((_, refreshed)) = refresh::ensure(true) {
            credentials = refreshed;
            response = ask(&credentials, &wire_model, &url, &envelope)?;
        }
    }
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = response.bytes(1024 * 1024)?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(upstream_error(status, &value));
    }
    let content_type = response.headers["content-type"].as_str().unwrap_or("").to_ascii_lowercase();
    if content_type.contains("application/json") {
        // 上游忽略了 alt=sse：把整段响应当一帧处理。
        let value = response.json()?;
        return whole(&value, &wire_model, started);
    }
    let mut decoder = SseDecoder::default();
    let mut translator = stream::Translator::new(&wire_model);
    while let Some(bytes) = response.read()? {
        for payload in decoder.push(&bytes)? {
            let trimmed = payload.trim();
            if trimmed == "[DONE]" {
                for frame in translator.done() {
                    emit(frame, started, false)?;
                }
                if !*started {
                    return Err(Error::http(502, "Antigravity 在开始回答前就结束了响应"));
                }
                sdk::stream_bytes(b"data: [DONE]\n\n")?;
                return Ok(());
            }
            let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            for frame in translator.consume(&value) {
                emit(frame, started, translator.finished())?;
            }
            if translator.finished() {
                if !*started {
                    // 一帧内容都没下发就收尾：多半是上游错误或空响应。
                    return Err(Error::http(502, "Antigravity 上游没有返回可转发的内容"));
                }
                sdk::stream_bytes(b"data: [DONE]\n\n")?;
                return Ok(());
            }
        }
    }
    for frame in translator.truncated() {
        emit(frame, started, translator.finished())?;
    }
    if !*started {
        return Err(Error::http(502, "Antigravity 上游流提前中断，未收到任何内容帧"));
    }
    sdk::stream_bytes(b"data: [DONE]\n\n")
}

/// 发一次 `:streamGenerateContent`。
fn ask(credentials: &AntigravityCredentials, wire_model: &str, url: &str, body: &Value) -> Result<http::Response> {
    // Claude 模型另带 `anthropic-beta`（判据取**上游真名**）。
    let headers = if models::is_claude_model(wire_model) {
        endpoints::claude_content_headers(&credentials.access_token)
    } else {
        endpoints::content_headers(&credentials.access_token)
    };
    http::open("POST", url, headers, Some(body))
}

/// 企业账号标记（非 gmail / googlemail 的邮箱视为企业账号）。
fn enterprise(credentials: &AntigravityCredentials) -> bool {
    let email = credentials.email.trim();
    !email.is_empty() && !email.ends_with("@gmail.com") && !email.ends_with("@googlemail.com")
}

/// 下发一帧；`terminal` 表示这是收尾帧。
fn emit(frame: Value, started: &mut bool, _terminal: bool) -> Result<()> {
    if !*started {
        sdk::stream_head(200)?;
        *started = true;
    }
    sdk::stream_event(&frame)
}

/// 上游非 2xx → 错误（`RESOURCE_EXHAUSTED` 抬成 429，与 native 同判据）。
fn upstream_error(status: u16, body: &Value) -> Error {
    let raw = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| body.get("message").and_then(Value::as_str))
        .unwrap_or("上游错误");
    let lowered = raw.to_ascii_uppercase();
    if lowered.contains("RESOURCE_EXHAUSTED") {
        return Error::http(429, format!("上游返回 {status}: {raw}")).with_code("quota_limited");
    }
    if status == 401 || status == 403 {
        return Error::http(401, format!("上游返回 {status}: {raw}")).with_code("token_expired");
    }
    if status == 429 {
        return Error::http(429, format!("上游返回 {status}: {raw}")).with_code("quota_limited");
    }
    Error::http(status.max(400), format!("上游返回 {status}: {raw}"))
}

/// 非流式（上游回了一整个 JSON）：把 candidates 折成 chat 帧。
fn whole(value: &Value, model: &str, started: &mut bool) -> Result<()> {
    let mut translator = stream::Translator::new(model);
    for frame in translator.consume(&value) {
        emit(frame, started, false)?;
    }
    for frame in translator.done() {
        emit(frame, started, true)?;
    }
    if !*started {
        return Err(Error::http(502, "Antigravity 上游没有返回可转发的内容"));
    }
    sdk::stream_bytes(b"data: [DONE]\n\n")
}
