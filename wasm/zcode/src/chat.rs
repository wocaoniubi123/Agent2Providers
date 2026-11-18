//! 对话转发：`conversation`（真正跑在网关上的那条）与 `chat`（构造请求的直译）。
//!
//! ── 为什么本家必须走 `conversation` ──────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对**任何** wasm 包
//! 直接回 501（插件不能只回答「怎么构造请求」），真正生效的是 `conversation`：
//! 插件自己发上游请求、自己把上游协议折成 **chat SSE** 字节回传。
//! `chat` 仍按 native `build_chat` 的语义实现（交出 `{url, headers, body,
//! upstream}`），保证协议映射表里那一条不是空的 —— 但它不是生产路径。
//!
//! ── 本家为什么需要翻译层 ────────────────────────────────────
//! 套餐池通道（`start-plan`）的上游是 Anthropic Messages。native 侧由网关的
//! 翻译层折回 chat SSE；Wasm 侧没有那一层，所以往返两份转换都在插件里
//! （见 `anthropic.rs` 的模块头）。编码套餐通道（`coding-plan`）上游本来就吐
//! chat SSE，直接透传。
//!
//! ── 出错边界（照抄 atomcode 的判定，别改）─────────────────────
//! 「已经 `stream.head` 之后才出错」与「还没下发就出错」是两种情况：
//!   · 前者：下游已收到 200 与部分帧，只能用**流内错误帧**收尾（再抛给主程序
//!     让它记一条失败），不能悄悄重发；
//!   · 后者：直接抛错，由网关按 HTTP 错误回给客户端。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::common::headers_object;
use super::{account, anthropic, captcha, errors, http as net, models, plan, plan::Plan};

/// 上游请求体上限（对话请求带历史，给足余量）。
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// 错误响应的读取上限。
const MAX_ERROR_BYTES: usize = 1024 * 1024;

/// 取发送名：网关给的 `wire_model` 优先，缺省退回请求体里的 `model`。
fn wire_model(params: &Value, body: &Value) -> Result<String> {
    let from_params = params["wire_model"].as_str().unwrap_or("").trim();
    if !from_params.is_empty() {
        return Ok(models::wire_id(from_params));
    }
    let from_body = body["model"].as_str().unwrap_or("").trim();
    if from_body.is_empty() {
        return Err(Error::http(400, "ZCode 请求缺少模型名"));
    }
    Ok(models::wire_id(from_body))
}

/// 客户端入站头（网关给的是小写键的 `{k: v}` 对象）。
fn inbound_headers(params: &Value) -> serde_json::Map<String, Value> {
    params["headers"]
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// 组装一次上游请求（`conversation` 与 `chat` 共用同一套分派）。
///
/// 分派依据是**账号上的 `zcodePlan`**（不是模型名）：两条通道的凭证不能互相
/// 替代，走错门的症状是业务拒绝而不是鉴权失败，所以选择权在用户手里。
fn build(params: &Value, body: &Value, requested: &str) -> Result<Plan> {
    let record = account::require_account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    match account::plan_of(&secret) {
        account::PLAN_START => {
            let jwt = account::jwt(&secret);
            // 设备标识：记录里没有就现场生成并落盘（见 `account::device_mid_or_create`）
            let device_mid = account::device_mid(&secret);
            let device_mid = if device_mid.is_empty() {
                account::device_mid_or_create()?.unwrap_or_default()
            } else {
                device_mid
            };
            // 顺带一次「到点没」的风控配置同步（native `config_sync::ensure_captcha_config`）
            if captcha::sync_due() {
                sync_captcha_config();
            }
            plan::start_plan(&jwt, body, requested, &inbound_headers(params), &device_mid)
        }
        _ => plan::coding_plan(&account::access_token(&secret), body, requested),
    }
}

/// 拉一次上游的风控配置并更新令牌池（native `config_sync::ensure_captcha_config`）。
///
/// 失败**静默**：配置只决定「要不要带验证码头」，拉不到时沿用上一次的判定
/// （3007 会把它改回「要」），比因为一次配置拉取失败而拒绝整条推理好。
fn sync_captcha_config() {
    let url = format!(
        "{}/api/v1/client/configs?{}",
        super::region::ZCODE_ORIGIN,
        plan::version_query()
    );
    let Ok(reply) = net::send("GET", &url, &[], None) else {
        return;
    };
    if !reply.ok() {
        return;
    }
    let captcha_config = reply.payload.pointer("/data/configs/captcha");
    let Some(config) = captcha_config.filter(|value| value.is_object()) else {
        return;
    };
    let enabled = config.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let skip = config
        .get("skip_model_request")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    captcha::apply_config(enabled, skip);
    captcha::note_synced();
}

/// `chat` 方法：交出「要发出去的 HTTP 请求」（native `build_chat` 的直译）。
///
/// 主程序当前对 Wasm 插件不接受这条路径（`build_chat_request_async` 对 wasm
/// 回 501），但协议映射里它是 `build_chat` 的对应物，保留完整语义而不是留一个
/// 空壳 —— 将来网关放开这条路时不必再补一遍。
pub fn plan_request(params: &Value) -> Result<Value> {
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let requested = wire_model(params, &body)?;
    let built = build(params, &body, &requested)?;
    if built.body.to_string().len() > MAX_REQUEST_BYTES {
        return Err(Error::http(413, "ZCode 请求体过大"));
    }
    Ok(built.to_json())
}

/// `conversation` 方法：自己发请求、自己折协议、自己吐 chat SSE。
pub fn forward(params: &Value) -> Result<()> {
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    // 推理请求恒为流式：native 侧由网关把 `stream` 定成 true（`is_error_response`
    // 的注释：ZCode 的 JSON 响应是业务拒绝）。插件拿到的是客户端原始体，这里
    // 与 native 保持同一口径 —— 不发 `stream:true` 会让上游回整段 JSON，白走
    // 一次降级折叠。
    body["stream"] = json!(true);
    let requested = wire_model(params, &body)?;
    let built = build(params, &body, &requested)?;
    let serialized = built.body.to_string();
    if serialized.len() > MAX_REQUEST_BYTES {
        return Err(Error::http(413, "ZCode 请求体过大"));
    }

    let response = http::open(
        "POST",
        &built.url,
        headers_object(&built.headers),
        Some(&built.body),
    )?;
    let status = response.status;
    let content_type = net::content_type(&response.headers);

    if !(200..300).contains(&status) {
        let bytes = response.bytes(MAX_ERROR_BYTES)?;
        let payload = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        return Err(errors::http_error(status, &payload));
    }

    // HTTP 200 但正文是 JSON：要么是业务拒绝（native `is_error_response` 的
    // 口径），要么是上游忽略了 `stream: true` —— 后者按一次性折叠降级。
    if content_type.contains("application/json") || content_type.contains("+json") {
        let bytes = response.bytes(MAX_ERROR_BYTES)?;
        let payload = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        return degrade_json(&payload, status, &requested, built.upstream);
    }
    if content_type.contains("text/html") {
        return Err(Error::http(502, "ZCode 返回了网页而不是模型回答"));
    }

    sdk::stream_head(status)?;
    let result = if built.upstream == "anthropic" {
        stream_anthropic(response, &requested)
    } else {
        stream_chat(response)
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            // 已下发响应头与部分帧：只能补一条流内错误帧，不能把请求悄悄重发
            sdk::stream_event(&errors_event(&error))?;
            Err(error)
        }
    }
}

/// 上游给了 JSON 时的两条路：降级折叠 or 诚实报错。
fn degrade_json(payload: &Value, status: u16, requested: &str, upstream: &str) -> Result<()> {
    let explicit_error = payload.get("error").is_some_and(|value| !value.is_null());
    let biz = plan::biz_code(payload);
    let biz_failed = biz.is_some_and(|code| code != 0);
    if explicit_error || biz_failed {
        return Err(errors::http_error(status, payload));
    }
    let looks_like_message = payload.get("type").and_then(Value::as_str) == Some("message")
        || (payload["content"].is_array() && payload["stop_reason"].is_string());
    let looks_like_chat = payload["choices"].is_array();
    if upstream == "anthropic" {
        if !looks_like_message {
            return Err(errors::http_error(502, payload));
        }
        sdk::stream_head(status)?;
        for frame in anthropic::frames_from_message(payload, requested) {
            sdk::stream_bytes(frame.as_bytes())?;
        }
        return Ok(());
    }
    if !looks_like_chat {
        return Err(errors::http_error(502, payload));
    }
    // chat 的非流式体 → 一帧 delta（`message` 改名成 `delta`）+ `[DONE]`
    let mut chunk = payload.clone();
    chunk["object"] = json!("chat.completion.chunk");
    if let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) {
        for choice in choices.iter_mut() {
            let message = choice.get("message").cloned().unwrap_or(Value::Null);
            if let Some(object) = choice.as_object_mut() {
                object.insert("delta".to_string(), message);
                object.remove("message");
            }
        }
    }
    sdk::stream_head(status)?;
    sdk::stream_bytes(format!("data: {chunk}\n\n").as_bytes())?;
    sdk::stream_bytes(b"data: [DONE]\n\n")?;
    Ok(())
}

/// Anthropic SSE → chat SSE（状态机在 `anthropic::Stream`）。
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
    // 流内错误（`error` 事件 / 空流）的收尾帧已经在下发字节里了，这里只把失败
    // 如实抛给主程序 —— 不再补一条错误事件，否则下游会收到两条错误帧。
    match stream.take_failure() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Chat SSE 直通（编码套餐通道的上游本来就吐 chat SSE）。
///
/// 只在帧边界上判断 `[DONE]`：整块字节照原样下发（**不重新序列化** —— 上游帧
/// 里可能有本插件不认识的字段，重排会让下游看到不一样的东西）。
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

/// 错误 → 流内错误帧（`data: {"error": {...}}`）。
fn errors_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({
        "error": {
            "message": error.message,
            "status": status,
            "type": "upstream_error",
        }
    })
}
