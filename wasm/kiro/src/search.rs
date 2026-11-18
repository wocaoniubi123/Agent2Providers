//! Kiro 独立网页搜索（`InvokeMCP`）：只解析来源，不创建对话、不运行模型。
//!
//! ── 两套认证形态 ────────────────────────────────────────────
//! ```text
//!   OAuth    body 与头里都带 profileArn（x-amzn-kiro-profile-arn）
//!   API key  不带 profile，带 tokentype: API_KEY
//! ```
//!
//! ── 为什么只有明确的登录失效才续期 ──────────────────────────
//! 普通 403（无权限）不能当成令牌过期反复打 —— 那会把一次权限问题变成一串
//! 刷新请求。判据取 native 的原话：401，或 403 且 reason 属于
//! `INVALID_TOKEN` / `EXPIRED_TOKEN` / `TOKEN_EXPIRED`、或文案里明确说 token 过期。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::credentials::Credentials;
use super::{endpoints, refresh};

/// 查询词的长度上限（`web-search.capabilities` 里如实报出去）。
const MAX_QUERY_CHARS: usize = 200;

/// 来源条数上限。
const MAX_SOURCES: usize = 50;

/// `admin.action` 的两个搜索动作。
pub fn dispatch(action: &str, payload: &Value) -> Result<Value> {
    if action == "web-search.capabilities" {
        return Ok(json!({
            "version": 1, "search": true, "fetch": false,
            "max_query_chars": MAX_QUERY_CHARS,
        }));
    }
    let query = payload
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .ok_or_else(|| Error::http(400, "请填写要搜索的内容"))?;
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(Error::http(400, format!("搜索内容不能超过 {MAX_QUERY_CHARS} 个字符")));
    }
    let (_, mut credentials) = refresh::ensure(false)?;
    let mut outcome = search_once(&credentials, query);
    if let Err(error) = &outcome {
        // 只有明确的登录失效才强刷一次（见模块头）。
        if error.code.as_deref() == Some("kiro_search_token") && !credentials.is_api_key() {
            if let Ok((_, refreshed)) = refresh::ensure(true) {
                credentials = refreshed;
                outcome = search_once(&credentials, query);
            }
        }
    }
    outcome
}

/// 打一次 `InvokeMCP`。
fn search_once(credentials: &Credentials, query: &str) -> Result<Value> {
    if credentials.access.is_empty() {
        return Err(Error::http(401, "Kiro 账号缺少可用的访问令牌").with_code("kiro_search_token"));
    }
    if !credentials.is_api_key() && credentials.profile.is_empty() {
        return Err(Error::http(400, "Kiro 账号缺少搜索所需的 profile，请重新登录").with_code("configuration"));
    }
    let mut body = json!({
        "jsonrpc": "2.0",
        "id": endpoints::uuid_v4(),
        "method": "tools/call",
        "params": { "name": "web_search", "arguments": { "query": query } },
    });
    if !credentials.is_api_key() {
        body["profileArn"] = json!(credentials.profile);
    }
    let url = format!("{}/", endpoints::runtime(&credentials.region()));
    let user_agent =
        "aws-sdk-rust/1.0.0 ua/2.1 os/other lang/rust api/codewhispererstreaming#1.28.3 m/E app/AmazonQ-For-CLI";
    let mut headers = json!({
        "authorization": format!("Bearer {}", credentials.access),
        "content-type": "application/x-amz-json-1.0",
        "accept": "application/json",
        "x-amz-target": endpoints::TARGET_MCP,
        "x-amzn-codewhisperer-optout": "true",
        "amz-sdk-invocation-id": endpoints::uuid_v4(),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amz-user-agent": user_agent,
        "user-agent": user_agent,
    });
    if let Some(kind) = credentials.token_type() {
        headers["tokentype"] = json!(kind);
    }
    if !credentials.is_api_key() {
        headers["x-amzn-kiro-profile-arn"] = json!(credentials.profile);
    }
    let response = http::open("POST", &url, headers, Some(&body))?;
    let status = response.status;
    let bytes = response.bytes(2 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let reason = value.get("reason").and_then(Value::as_str).unwrap_or("");
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let expired = status == 401
            || (status == 403
                && (matches!(reason, "INVALID_TOKEN" | "EXPIRED_TOKEN" | "TOKEN_EXPIRED")
                    || ["token is expired", "expired token", "invalid token", "invalid bearer token"]
                        .iter()
                        .any(|needle| message.contains(needle))));
        let code = if expired { "kiro_search_token" } else { "kiro_search_rejected" };
        return Err(Error::http(if expired { 401 } else { status }, format!("Kiro 搜索失败（HTTP {status}）"))
            .with_code(code));
    }
    parse_result(&value)
}

/// 解析 `tools/call` 的回包 → `{sources:[…]}`。
fn parse_result(value: &Value) -> Result<Value> {
    let invalid = || Error::http(502, "Kiro 搜索返回的内容无法解析").with_code("kiro_search_invalid");
    if value.get("error").is_some_and(|error| !error.is_null()) {
        return Err(invalid());
    }
    let mut result = value.get("result").cloned().ok_or_else(invalid)?;
    if let Some(text) = result.as_str() {
        result = serde_json::from_str(text).map_err(|_| invalid())?;
    }
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(invalid());
    }
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|item| item.get("type").and_then(Value::as_str) == Some("text"))
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let content: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    if content.get("error").is_some_and(|error| !error.is_null()) {
        return Err(invalid());
    }
    let items = content.get("results").and_then(Value::as_array).ok_or_else(invalid)?;
    Ok(json!({ "sources": sources(items) }))
}

/// 来源行（只收 http(s)、不带用户名密码的地址）。
fn sources(items: &[Value]) -> Vec<Value> {
    items
        .iter()
        .take(MAX_SOURCES)
        .filter_map(|item| {
            let raw = item.get("url")?.as_str()?.trim();
            let lower = raw.to_ascii_lowercase();
            let accepted = (lower.starts_with("http://") || lower.starts_with("https://"))
                && !raw.contains(' ')
                && raw
                    .split("://")
                    .nth(1)
                    .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/') && !rest.contains('@'));
            if !accepted {
                return None;
            }
            let title: String = item
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(raw)
                .trim()
                .chars()
                .take(300)
                .collect();
            let content: String = item
                .get("snippet")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .chars()
                .take(2000)
                .collect();
            let date = item.get("publishedDate").and_then(|value| {
                if let Some(text) = value.as_str().filter(|text| !text.trim().is_empty()) {
                    return Some(text.trim().chars().take(100).collect::<String>());
                }
                let millis = value.as_i64().filter(|value| *value > 0)?;
                chrono::DateTime::from_timestamp_millis(millis).map(|date| date.to_rfc3339())
            });
            Some(json!({ "url": raw, "title": title, "content": content, "publishedDate": date }))
        })
        .collect()
}
