//! Loomy 推理请求的追踪上下文；Chat 使用客户端版本头，Images 使用生图用途。
//!
//! ── 这些头是谁要求的 ────────────────────────────────────────
//! 官方客户端每个推理请求都带 `traceparent` / `ChatId` / `MsgId` / `TurnId` /
//! `InvokeOrigin` / `X-Loomy-Request-Purpose`（`electron/` 里统一的请求包装）。
//! 缺了它们实测不一定失败，但「一次性会话」类限流与日志会走另一条分支 ——
//! 与 native 侧保持同一套头，行为才一致。
//!
//! ── 客户端的追踪头要透传吗 ──────────────────────────────────
//! 透传（并做格式校验）：调用方自己带 `traceparent` / `ChatId` 时应当沿用它的
//! 关联关系，否则一条链在日志里会断成两截。非法或缺失的一律自己生成。

use agent2api_wasm_sdk::Value;

use super::endpoints;
use super::ids;

/// 追踪头里 id 类字段的长度上限（与网关的白名单同口径）
const MAX_ID_LENGTH: usize = 256;

/// 从客户端头对象里取一个值（键名大小写不敏感；非法值当作没有）。
fn header(headers: &Value, name: &str) -> Option<String> {
    let object = headers.as_object()?;
    let found = object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)?;
    let value = found.as_str()?.trim();
    (!value.is_empty()
        && value.len() <= MAX_ID_LENGTH
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| value.to_string())
}

/// W3C `traceparent` 的形态校验（`00-<32 hex>-<16 hex>-<2 hex>`，且 id 不全零）。
fn valid_traceparent(value: &str) -> bool {
    let mut parts = value.split('-');
    let (Some(version), Some(trace), Some(span), Some(flags)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let hex = |part: &str, length: usize| {
        part.len() == length && part.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    version == "00"
        && hex(trace, 32)
        && hex(span, 16)
        && hex(flags, 2)
        && trace.bytes().any(|byte| byte != b'0')
        && span.bytes().any(|byte| byte != b'0')
        && parts.next().is_none()
}

/// 两种用途共用的一套追踪头 + 各自追加的那一个。
fn tracking_headers(session: &str, client_headers: &Value, purpose: &str) -> Vec<(String, String)> {
    let chat_id = header(client_headers, "chatid")
        .or_else(|| header(client_headers, "x-session-id"))
        .unwrap_or_else(ids::uuid_v4);
    let message_id = header(client_headers, "msgid")
        .or_else(|| header(client_headers, "x-request-id"))
        .unwrap_or_else(ids::message_id);
    let turn_id = header(client_headers, "turnid").unwrap_or_else(|| message_id.clone());
    let traceparent = header(client_headers, "traceparent")
        .filter(|value| valid_traceparent(value))
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| format!("00-{}-{}-01", ids::message_id(), ids::span_id()));

    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("token".to_string(), session.to_string()),
        ("Authorization".to_string(), format!("Bearer {session}")),
        ("traceparent".to_string(), traceparent),
        ("ChatId".to_string(), chat_id),
        ("MsgId".to_string(), message_id),
        ("TurnId".to_string(), turn_id),
        ("InvokeOrigin".to_string(), "user".to_string()),
        ("X-Loomy-Request-Purpose".to_string(), purpose.to_string()),
    ]
}

/// Chat / Messages 请求的头（`Accept` 由调用方按协议再定）。
pub fn chat(session: &str, client_headers: &Value) -> Vec<(String, String)> {
    let mut headers = tracking_headers(session, client_headers, "chat.message");
    headers.push(("Accept".to_string(), "text/event-stream".to_string()));
    headers.push(("loomy-version".to_string(), endpoints::client_version()));
    headers
}

/// 转成 SDK 要的请求头对象。
pub fn object(headers: &[(String, String)]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in headers {
        map.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(map)
}
