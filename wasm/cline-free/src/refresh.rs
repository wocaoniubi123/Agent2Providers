//! Cline 凭证续期：`POST /api/v1/auth/refresh` + 账号锁 + 比较再写。
//!
//! ── 三处实测踩出来的口径（别按直觉改）───────────────────────
//! ```text
//!   1. grantType 是 camelCase（不是 OAuth 标准的 grant_type）
//!   2. 返回的 accessToken 不带 workos: 前缀（登录返回的带），
//!      发请求时**必须带** —— 写入前统一过 ensure_token_prefix
//!   3. expiresAt 是 ISO 8601 字符串（与桌面端 providers.json 的毫秒数同名不同型）
//! ```
//!
//! ── 为什么值得单飞 ─────────────────────────────────────────
//! refresh_token 在服务端是一次性轮换语义：并发刷新时后到的那次可能拿着已作废
//! 的 refresh_token → 401 → 用户被踢下线。wasm 用宿主账号锁串行化，锁内重读
//! 账号（前一轮已刷好的结果直接复用）。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::credentials::{self, ClineCredentials, TOKEN_PREFIX};

/// 续期端点。
const REFRESH_PATH: &str = "/auth/refresh";

/// 一次续期得到的 token 三件套。
struct Refreshed {
    access: String,
    refresh: String,
    expires_at: Option<f64>,
}

/// 打一次续期。
fn refresh_once(credentials: &ClineCredentials) -> Result<Refreshed> {
    if credentials.refresh_token.trim().is_empty() {
        return Err(Error::http(401, "Cline 的登录态已失效，请重新登录").with_code("cline_refresh_missing"));
    }
    let body = json!({
        "refreshToken": credentials.refresh_token,
        "grantType": "refresh_token",
    });
    let response = http::open(
        "POST",
        &format!("{}{REFRESH_PATH}", credentials::API_BASE_URL),
        json!({ "content-type": "application/json", "accept": "application/json" }),
        Some(&body),
    )?;
    let status = response.status;
    let bytes = response.bytes(2 * 1024 * 1024)?;
    if !(200..300).contains(&status) {
        let code = if matches!(status, 400 | 401 | 403) {
            "cline_refresh_rejected"
        } else {
            "cline_refresh_failed"
        };
        return Err(Error::http(
            if matches!(status, 400 | 401 | 403) { 401 } else { 502 },
            if matches!(status, 400 | 401 | 403) {
                "Cline 的登录态已失效，请重新登录".to_string()
            } else {
                format!("刷新 Cline 登录态失败（HTTP {status}）")
            },
        )
        .with_code(code));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::http(502, "刷新 Cline 登录态的返回不是 JSON").with_code("cline_refresh_failed"))?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(Error::http(401, "Cline 的登录态已失效，请重新登录").with_code("cline_refresh_rejected"));
    }
    let data = value.get("data").filter(|value| value.is_object()).unwrap_or(&value);
    let access = data.get("accessToken").and_then(Value::as_str).unwrap_or("").to_string();
    if access.is_empty() {
        return Err(Error::http(502, "Cline 续期没有返回 accessToken").with_code("cline_refresh_failed"));
    }
    let expires_at = data
        .get("expiresAt")
        .and_then(|value| value.as_str())
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .map(|date| date.timestamp_millis() as f64)
        .or_else(|| credentials::expires_at_from_jwt(&access));
    Ok(Refreshed {
        access,
        refresh: data
            .get("refreshToken")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .unwrap_or(&credentials.refresh_token)
            .to_string(),
        expires_at,
    })
}

/// 当前账号的凭证（临期就刷一次）。
pub fn ensure(force: bool) -> Result<ClineCredentials> {
    let record = sdk::account()?;
    let credentials = credentials::from_secret(&record["secret"]);
    if credentials.access_token.is_empty() && credentials.refresh_token.is_empty() {
        return Err(Error::http(401, "Cline 账号缺少凭证，请重新登录"));
    }
    if !force && !credentials.is_expiring() {
        return Ok(credentials);
    }
    refresh_locked(&record, &credentials)
}

/// 锁内刷新并写回。
fn refresh_locked(record: &Value, credentials: &ClineCredentials) -> Result<ClineCredentials> {
    let _lock = sdk::AccountLock::acquire();
    let current = sdk::account()?;
    let latest = credentials::from_secret(&current["secret"]);
    if latest.access_token != credentials.access_token && !latest.is_expiring() {
        return Ok(latest);
    }
    let refreshed = refresh_once(&latest)?;
    let mut next = latest.clone();
    // 上游回的是裸 JWT：落盘统一带前缀（发请求时 `ensure_token_prefix` 仍幂等）。
    next.access_token = format!("{TOKEN_PREFIX}{}", refreshed.access.trim());
    next.refresh_token = refreshed.refresh;
    next.expires_at = refreshed.expires_at.or(latest.expires_at);
    let expect = current["secret"].clone();
    let mut secret = expect.clone();
    secret["accessToken"] = json!(next.access_token);
    secret["refreshToken"] = json!(next.refresh_token);
    if let Some(expires) = next.expires_at {
        secret["expiresAt"] = json!(expires as i64);
    }
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": secret, "public": credentials::public(&secret) }),
    );
    match result {
        Ok(value) if value["updated"] == true => Ok(next),
        // 期间被改动过：用新令牌，但不覆盖记录（与 native 同一告知口径）。
        _ => {
            let _ = record;
            Ok(next)
        }
    }
}
