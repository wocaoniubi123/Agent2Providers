//! Loomy 的对话转发：一次 HTTP 请求 = 一次回答（无状态）。
//!
//! ── 为什么本家有两条出口 ────────────────────────────────────
//! `conversation`（有状态流通道）与 `chat`（无状态「怎么构造请求」）在协议里是
//! 两件事。本家是**无状态**的（`stateful: false`），而主程序对 Wasm 插件只放行
//! 标准流通道（`build_chat_request_async` 里对 wasm 明确回 501），所以真正跑在
//! 生产上的是 `conversation`：插件自己发请求、自己把上游协议折成 chat SSE。
//! `chat` 仍按 native `build_chat` 的语义实现（交出 `{url, headers, body,
//! upstream}`），保证协议映射表里的那一条不是空的。
//!
//! ── 本家为什么需要翻译层 ────────────────────────────────────
//! 模型目录里带 `protocol` 的条目要走 Anthropic Messages（`{model_base}/messages`），
//! 其余走 Chat Completions。native 侧这两种由网关的翻译机统一折回 chat SSE；
//! Wasm 侧没有那一层，所以 Anthropic 那半边由 `anthropic.rs` 自己折（见该文件模块头）。
//!
//! ── 流式为什么不用先探测再吐 ────────────────────────────────
//! 上游头一到就 `stream.head`，之后边读边吐：本家的失败几乎都在「HTTP 非 2xx」与
//! 「HTTP 200 + JSON 信封」这两种形态里，读 `content-type` 就能判，不需要像
//! atomcode 那样靠正文特征缓冲一堆帧再决定。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::{anthropic, client, credentials, endpoints, errors, headers, ids, models};

/// 上游请求体上限（对话请求带历史，给足余量）
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// 错误响应的读取上限
const MAX_ERROR_BYTES: usize = 1024 * 1024;

/// 取发送名：主程序给的 `wire_model` 优先，缺省退回请求体里的 `model`。
fn wire_model(params: &Value, body: &Value) -> Result<String> {
    let from_params = params["wire_model"].as_str().unwrap_or("").trim();
    if !from_params.is_empty() {
        return Ok(from_params.to_string());
    }
    let from_body = body["model"].as_str().unwrap_or("").trim();
    if from_body.is_empty() {
        return Err(Error::http(400, "Loomy 请求缺少模型名"));
    }
    Ok(from_body.to_string())
}

/// 该模型该走哪套协议。
///
/// ── 为什么目录里找不到时要先刷一次再判 ──────────────────────
/// 与本家 native 的 `build_chat` 同一顺序：目录可能还是旧的（用户刚上新模型），
/// 直接按默认 Chat 发会拿上游 400。刷新失败就如实报错 —— 拿不准协议时硬发一次
/// 只是把「目录过期」变成更难查的「参数错误」。
fn resolve_protocol(model: &str, session: &str) -> Result<String> {
    if let Some(protocol) = models::protocol_of(model) {
        return Ok(protocol);
    }
    let list = models::fetch(session)?;
    let found = list["models"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find_map(|item| {
                item["id"]
                    .as_str()
                    .filter(|id| id.eq_ignore_ascii_case(model.trim()))
                    .map(|_| {
                        item["protocol"]
                            .as_str()
                            .unwrap_or("openai")
                            .trim()
                            .to_ascii_lowercase()
                    })
            })
        })
        .unwrap_or_else(|| "openai".to_string());
    Ok(if found == "anthropic" { found } else { "openai".to_string() })
}

/// 组装一次上游请求（`conversation` 与 `chat` 共用同一套分派）。
fn build(params: &Value, requested: &str) -> Result<(String, Vec<(String, String)>, Value, &'static str)> {
    let credentials = credentials::snapshot()?;
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "Loomy 请求体必须是 JSON 对象"));
    }
    body["model"] = json!(requested);
    body["stream"] = json!(true);
    let protocol = resolve_protocol(requested, &credentials.session)?;
    let mut headers = headers::chat(&credentials.session, &params["headers"]);
    if protocol == "anthropic" {
        let body = anthropic::request_from_chat(&body, requested)?;
        // Anthropic 的鉴权头与 chat 的 `token` 头并列带上：本家模型网关
        // 认 `token`，Messages 端点还认官方的 `x-api-key` + `anthropic-version`。
        headers.push(("anthropic-version".to_string(), "2023-06-01".to_string()));
        headers.push(("x-api-key".to_string(), credentials.session.clone()));
        return Ok((
            format!("{}/messages", endpoints::model_base_url()),
            headers,
            body,
            "anthropic",
        ));
    }
    Ok((
        format!("{}/chat/completions", endpoints::model_base_url()),
        headers,
        body,
        "chat",
    ))
}

/// `chat` 方法：交出「要发出去的 HTTP 请求」（native `build_chat` 的直译）。
///
/// 主程序当前对 Wasm 插件不接受这条路径（Wasm 对话必须走标准流通道），
/// 但协议映射里它是 `build_chat` 的对应物，保留完整语义而不是留一个空壳。
pub fn plan(params: &Value) -> Result<Value> {
    let body = params["body"].clone();
    let requested = wire_model(params, &body)?;
    let (url, headers, outbound, upstream) = build(params, &requested)?;
    if outbound.to_string().len() > MAX_REQUEST_BYTES {
        return Err(Error::http(413, "Loomy 请求体过大"));
    }
    Ok(json!({
        "url": url,
        "headers": headers,
        "body": outbound,
        "upstream": upstream,
    }))
}
/// 取响应头里的 `content-type`（键名大小写不敏感：主程序回的头不一定全是小写）。
fn content_type_of(headers: &Value) -> String {
    headers
        .as_object()
        .and_then(|object| {
            object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone())
        })
        .and_then(|value| {
            value.as_str().map(str::to_string).or_else(|| {
                value
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        })
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// `conversation` 方法：自己发请求、自己折协议、自己吐 chat SSE。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    let requested = wire_model(params, &body)?;
    let (url, headers, outbound, upstream) = build(params, &requested)?;
    let serialized = outbound.to_string();
    if serialized.len() > MAX_REQUEST_BYTES {
        return Err(Error::http(413, "Loomy 请求体过大"));
    }

    let response = http::open("POST", &url, headers::object(&headers), Some(&outbound))?;
    let status = response.status;
    let content_type = content_type_of(&response.headers);

    if !(200..300).contains(&status) {
        let bytes = response.bytes(MAX_ERROR_BYTES)?;
        let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(errors::http_error(status, &payload));
    }

    // 上游回了 JSON：要么是业务拒绝（native 的 `is_error_response` 口径），
    // 要么是它忽略了 `stream: true` —— 后者按一次性折叠降级，不能当 SSE 解。
    if content_type.contains("application/json") || content_type.contains("+json") {
        let payload = response.json()?;
        return passthrough_json(&payload, upstream, &requested, status);
    }
    if content_type.contains("text/html") {
        return Err(Error::http(502, "Loomy 返回了网页而不是模型回答"));
    }

    sdk::stream_head(status)?;
    if upstream == "anthropic" {
        stream_anthropic(response, &requested)
    } else {
        stream_chat(response)
    }
}

/// HTTP 200 且正文是 JSON 时的两条路：降级折叠 or 诚实报错。
fn passthrough_json(payload: &Value, upstream: &str, model: &str, status: u16) -> Result<()> {
    let business_code = client::business_code(payload);
    let explicit_error = payload.get("error").is_some_and(|value| !value.is_null())
        || (!business_code.is_empty() && business_code != client::SUCCESS_CODE);
    if explicit_error {
        return Err(errors::http_error(status, payload));
    }
    let looks_like_chat = payload["choices"].is_array();
    let looks_like_message = payload["type"].as_str() == Some("message")
        || (payload["content"].is_array() && payload["stop_reason"].is_string());
    if upstream == "anthropic" {
        if !looks_like_message {
            return Err(errors::http_error(502, payload));
        }
        let fallback = ids::random_id("chatcmpl");
        sdk::stream_head(status)?;
        for frame in anthropic::frames_from_message(payload, model, &fallback) {
            sdk::stream_bytes(frame.as_bytes())?;
        }
        return Ok(());
    }
    if !looks_like_chat {
        return Err(errors::http_error(502, payload));
    }
    // chat 的非流式体 → 一帧 delta（`message` 改名成 `delta`）+ 收尾帧 + [DONE]
    let mut chunk = payload.clone();
    chunk["object"] = json!("chat.completion.chunk");
    if let Some(choices) = chunk["choices"].as_array_mut() {
        for choice in choices.iter_mut() {
            choice["delta"] = choice["message"].clone();
            if let Some(object) = choice.as_object_mut() {
                object.remove("message");
            }
        }
    }
    sdk::stream_head(status)?;
    sdk::stream_bytes(format!("data: {chunk}\n\n").as_bytes())?;
    sdk::stream_bytes(b"data: [DONE]\n\n")?;
    Ok(())
}

/// Anthropic SSE → chat SSE。
fn stream_anthropic(mut response: http::Response, model: &str) -> Result<()> {
    let mut decoder = SseDecoder::default();
    let mut stream = anthropic::Stream::new(model);
    while let Some(bytes) = response.read()? {
        let payloads = decoder.push(&bytes)?;
        for frame in stream.push(&payloads) {
            sdk::stream_bytes(frame.as_bytes())?;
        }
        if stream.is_finished() {
            break;
        }
    }
    // 没有 `message_stop` 的流在这里兜底收尾（补 finish_reason / usage / [DONE]）
    for frame in stream.finish() {
        sdk::stream_bytes(frame.as_bytes())?;
    }
    // 流内错误（`error` 事件 / 空流）的收尾帧已经在下发字节里了，这里只把
    // 失败如实抛给主程序 —— 不再补一条错误事件，否则下游会收到两条错误帧。
    match stream.take_failure() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Chat SSE 直通（本家 OpenAI 协议那半边上游本来就吐 chat SSE）。
fn stream_chat(mut response: http::Response) -> Result<()> {
    let mut decoder = SseDecoder::default();
    let mut done = false;
    while let Some(bytes) = response.read()? {
        for payload in decoder.push(&bytes)? {
            if payload.trim() == "[DONE]" {
                done = true;
            }
        }
        sdk::stream_bytes(&bytes)?;
        if done {
            break;
        }
    }
    // 上游正常结束却没带 `[DONE]`：补一个，否则下游聚合器会一直等结束标记。
    if !done {
        sdk::stream_bytes(b"data: [DONE]\n\n")?;
    }
    Ok(())
}
