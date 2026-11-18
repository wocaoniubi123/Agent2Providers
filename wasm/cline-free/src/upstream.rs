//! Cline 的出网、错误分类与 429 冷却时长解析。
//!
//! ── 固定四个请求头 ──────────────────────────────────────────
//! ```text
//!   Content-Type: application/json
//!   Accept: text/event-stream
//!   Authorization: Bearer workos:<token>
//!   X-Task-ID: <与 body 的 session_id 同值>
//! ```
//! 其余客户端头由 `admin_panels: upstream_headers` 的覆盖表**覆盖式**合并
//! （后写赢）。wasm 侧读不到网关的那张覆盖表（它是用户配置），所以这里只发
//! 固定四个头 —— 这是 native → wasm 的唯一一处功能差，写在报告里。
//!
//! ── 429 的「Try again in 17h 59m」为什么必须解析 ─────────────
//! 免费池的真实冷却可达小时级；只按 10 分钟兜底冷却会反复打无效请求。
//! 解析出恢复时间戳后由网关的 `mark_account_limited` 直接采用。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::credentials::{self, ClineCredentials};

/// 非 2xx 的分类。
pub fn classify(status: u16, body: &Value) -> Value {
    let message = message_of(body);
    let lower = message.to_ascii_lowercase();
    let code = body
        .pointer("/error/code")
        .or_else(|| body.get("code"))
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())));
    let kind = body
        .pointer("/error/type")
        .or_else(|| body.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if kind == "content_filter"
        || lower.contains("content policy")
        || message.contains("内容安全")
        || message.contains("内容审核")
    {
        return json!({
            "kind": "content_blocked", "status": status, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 401 || status == 403 || matches!(kind, "invalid_api_key" | "token_expired" | "invalid_token") {
        return json!({
            "kind": "token_expired", "status": 401, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    let quota = status == 429
        || status == 402
        || ["quota", "insufficient", "balance", "credit", "rate limit", "额度", "积分", "余额"]
            .iter()
            .any(|marker| lower.contains(marker));
    if quota {
        let reset = if status == 429 { inference_cap_reset_at(body) } else { None };
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

/// 上游错误文案（`error.message` 优先）。
pub fn message_of(body: &Value) -> String {
    body.pointer("/error/message")
        .or_else(|| body.get("message"))
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(400)
        .collect()
}

/// 一帧错误事件的 JSON 形态。
pub fn error_event(status: u16, message: &str) -> Value {
    json!({
        "error": {
            "type": if status == 429 { "rate_limit_error" } else { "api_error" },
            "message": message,
            "status": status,
        }
    })
}

/// 429 的恢复时间戳（`now + Try again in …`）。
pub fn inference_cap_reset_at(body: &Value) -> Option<i64> {
    let text = serde_json::to_string(body).ok()?;
    let duration = try_again_ms(&text)?;
    Some(agent2api_wasm_sdk::now() + duration)
}

/// `Try again in` 之后的片段（到下一个 `"` / 换行 / `}` 为止）→ 毫秒。
fn try_again_ms(text: &str) -> Option<i64> {
    const MARKER: &str = "Try again in";
    let index = text.find(MARKER)?;
    let rest = &text[index + MARKER.len()..];
    let end = rest.find(['"', '\n', '\r', '}']).unwrap_or(rest.len());
    human_duration_ms(rest[..end].trim())
}

/// 人话时长 → 毫秒（支持 `d` / `h` / `m` / `ms` / `s` 组合）。
fn human_duration_ms(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut total: i64 = 0;
    let mut number: i64 = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'0'..=b'9' => {
                number = number.saturating_mul(10).saturating_add((bytes[index] - b'0') as i64);
                index += 1;
                continue;
            }
            b'd' => {
                total = total.saturating_add(number.saturating_mul(24 * 3600 * 1000));
                number = 0;
                index += 1;
                continue;
            }
            b'h' => {
                total = total.saturating_add(number.saturating_mul(3600 * 1000));
                number = 0;
                index += 1;
                continue;
            }
            b'm' => {
                // `ms` 是毫秒，`m` 是分钟。
                if bytes.get(index + 1) == Some(&b's') {
                    total = total.saturating_add(number);
                    number = 0;
                    index += 2;
                } else {
                    total = total.saturating_add(number.saturating_mul(60 * 1000));
                    number = 0;
                    index += 1;
                }
                continue;
            }
            b's' => {
                total = total.saturating_add(number.saturating_mul(1000));
                number = 0;
                index += 1;
                continue;
            }
            _ => {
                // 未知字符：重置累积（半截 token 不算数）。
                number = 0;
                index += 1;
            }
        }
    }
    if total <= 0 {
        None
    } else {
        Some(total)
    }
}

/// 打一次 GET（余额类接口）。
pub fn get(path: &str, token: &str) -> Result<Value> {
    let url = format!("{}{path}", credentials::API_BASE_URL);
    let mut headers = headers(token, "");
    headers["accept"] = json!("application/json");
    let response = http::open("GET", &url, headers, None)?;
    let status = response.status;
    let bytes = response.bytes(4 * 1024 * 1024)?;
    if !(200..300).contains(&status) {
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let class = classify(status, &value);
        return Err(Error::http(
            class["status"].as_u64().unwrap_or(502) as u16,
            class["message"].as_str().unwrap_or("Cline 上游请求未成功"),
        )
        .with_code(class["kind"].as_str().unwrap_or("cline_upstream")));
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::http(502, "Cline 返回的不是有效 JSON"))
}

/// 固定请求头（Authorization 用 `Bearer workos:` 形态）。
pub fn headers(token: &str, session_id: &str) -> Value {
    let mut headers = json!({
        "content-type": "application/json",
        "accept": "text/event-stream",
    });
    if !token.trim().is_empty() {
        headers["authorization"] = json!(format!("Bearer {}", credentials::ensure_token_prefix(token)));
    }
    if !session_id.is_empty() {
        headers["x-task-id"] = json!(session_id);
    }
    headers
}

/// 一次流式对话请求。
pub fn stream(credentials: &ClineCredentials, session_id: &str, body: &Value) -> Result<http::Response> {
    let url = format!("{}/chat/completions", credentials::API_BASE_URL);
    let response = http::open("POST", &url, headers(&credentials.bearer_token(), session_id), Some(body))?;
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    let status = response.status;
    let bytes = response.bytes(1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let class = classify(status, &value);
    Err(Error::http(
        class["status"].as_u64().unwrap_or(502) as u16,
        class["message"].as_str().unwrap_or("Cline 上游请求未成功"),
    )
    .with_code(class["kind"].as_str().unwrap_or("cline_upstream"))
    .with_reset(class["reset_at"].as_i64()))
}
