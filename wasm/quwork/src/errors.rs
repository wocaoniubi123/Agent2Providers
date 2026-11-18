//! QuWork 的错误分类（与 native `chat::classify` 同一套判据）。
//!
//! ── 判据顺序为什么要紧 ──────────────────────────────────────
//! 同一句话在不同状态码下含义不同，native 的顺序是：
//!   1. 内容拦截（`content_filter` / 文案含「内容安全」）→ `content_blocked`；
//!   2. 401 或 `invalid_api_key` / `token_expired` / `invalid_token` → `token_expired`；
//!   3. 余额不足（文案 / `insufficient_quota`）或 429 / 402 → `quota_limited`；
//!   4. 其余 → `fatal`。
//! 429 只在「不是余额不足」时给 60 秒的重置时间（那是频率限制，不是余额）。

use agent2api_wasm_sdk::{json, Error, Value};

use super::upstream;

/// 非 2xx 的分类（`classify` 的返回形状）。
pub fn classify(status: u16, body: &Value) -> Value {
    let message = upstream::message(body);
    let lower = message.to_ascii_lowercase();
    let code = body
        .pointer("/error/code")
        .or_else(|| body.get("code"))
        .and_then(Value::as_i64);
    let kind = body
        .pointer("/error/code")
        .or_else(|| body.pointer("/error/type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if kind == "content_filter"
        || kind == "content_policy_violation"
        || lower.contains("content policy")
        || message.contains("内容安全")
        || message.contains("内容审核")
    {
        return json!({
            "kind": "content_blocked", "status": status, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 401 || matches!(kind, "invalid_api_key" | "token_expired" | "invalid_token") {
        return json!({
            "kind": "token_expired", "status": 401, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    let balance = matches!(kind, "insufficient_quota" | "insufficient_balance")
        || [
            "余额不足",
            "积分不足",
            "额度不足",
            "额度已用完",
            "insufficient quota",
            "insufficient balance",
            "quota exceeded",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
    if balance || status == 429 || status == 402 {
        let reset = if status == 429 && !balance {
            json!(agent2api_wasm_sdk::now() + 60_000)
        } else {
            Value::Null
        };
        return json!({
            "kind": "quota_limited", "status": status, "message": message,
            "reset_at": reset, "upstream_code": code,
        });
    }
    json!({
        "kind": "fatal", "status": status.max(400), "message": message,
        "reset_at": Value::Null, "upstream_code": code,
    })
}

/// 把一帧上游错误翻成 SDK 错误（带分类后的状态码与文案）。
pub fn http_error_of(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let message = class["message"].as_str().unwrap_or("QuWork 上游请求未成功").to_string();
    let status = class["status"].as_u64().unwrap_or(502) as u16;
    let mut error = Error::http(status, if message.is_empty() { "QuWork 上游请求未成功".to_string() } else { message });
    if let Some(kind) = class["kind"].as_str() {
        error = error.with_code(kind);
    }
    error.with_reset(class["reset_at"].as_i64())
}

/// 流内错误帧（网关按 `{error:{message,type,status}}` 认）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({
        "error": {
            "message": error.message,
            "type": if status == 429 { "rate_limit_error" } else { "upstream_error" },
            "status": status,
        }
    })
}
