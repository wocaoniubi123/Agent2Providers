//! Antigravity 的 Google OAuth：`grant_type=refresh_token` 刷新 + project 发现。
//!
//! ── 协议（两套参考实现逐字一致）────────────────────────────
//! ```text
//! POST https://oauth2.googleapis.com/token
//! Content-Type: application/x-www-form-urlencoded
//! User-Agent: vscode/1.X.X (Antigravity/{ver})
//!
//! client_id / client_secret / refresh_token / grant_type=refresh_token
//! 200 → {access_token, expires_in(秒), token_type, refresh_token?, id_token?}
//! ```
//! **`refresh_token` 通常不回传**（Google 只在首次授权时下发）：那时保留旧值，
//! 绝不把已有字段洗成空。
//!
//! ── `invalid_grant` 的处置 ─────────────────────────────────
//! 报一个**可识别的永久性错误**让用户重新授权（本仓没有「停用账号」这条产品
//! 路径）：401 + 「refresh token 已失效或被撤销，请重新授权后粘贴新的
//! refresh_token」；`invalid_client` / `unauthorized_client` 同样 401；其余
//! 上游失败 502（可重试）。
//!
//! ── project 发现 ────────────────────────────────────────────
//! ```text
//! POST {prod}/v1internal:loadCodeAssist  → cloudaicompanionProject（有就直接用）
//! POST {prod}/v1internal:onboardUser     → 无 project 时开通并取回
//! ```
//! project 只影响聊天请求（目录 / 额度 / loadCodeAssist 都忽略它），所以发现
//! 失败一律不阻断账号可用性。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::credentials::AntigravityCredentials;
use super::endpoints;

/// 上游没给 `expires_in` 时的保守默认。
const DEFAULT_EXPIRES_IN_SECONDS: i64 = 3600;

/// 上游错误文的截断长度。
const MAX_ERROR_CHARS: usize = 300;

/// 一次 token 端点的结果。
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub token_type: String,
}

/// 截断上游错误文（按字符，UTF-8 安全）。
fn truncate(text: &str) -> String {
    let collapsed: String = text.chars().filter(|character| !character.is_control()).collect();
    match collapsed.char_indices().nth(MAX_ERROR_CHARS) {
        Some((index, _)) => format!("{}…", &collapsed[..index]),
        None => collapsed,
    }
}

/// 上游错误体里的 `(error, error_description)`。
fn upstream_error(payload: &Value) -> (String, String) {
    (
        payload.get("error").and_then(Value::as_str).unwrap_or("").trim().to_string(),
        payload
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
    )
}

/// `expires_in` 接受数字与数字字符串两种形态。
fn expires_in_of(payload: &Value) -> i64 {
    match payload.get("expires_in") {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(0),
        Some(Value::String(text)) => text.trim().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

/// 表单编码。
fn form(fields: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (key, value) in fields {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&urlencode(key));
        out.push('=');
        out.push_str(&urlencode(value));
    }
    out
}

/// query 编码（表单与 URL 共用）。
pub fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 从 token 响应里读一位（缺 access_token 按调用方给的文案报错）。
fn read_token_response(payload: &Value, missing: &str) -> Result<TokenResponse> {
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(502, missing.to_string()))?;
    let refresh_token = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let token_type = payload
        .get("token_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("Bearer")
        .to_string();
    Ok(TokenResponse {
        access_token,
        refresh_token,
        expires_in: expires_in_of(payload),
        token_type,
    })
}

/// 把一次失败响应翻成错误（三档处置见模块头）。
fn classify_failure(status: u16, text: &str, payload: &Value) -> Error {
    let (code, description) = upstream_error(payload);
    let detail = if description.is_empty() { truncate(text) } else { truncate(&description) };
    match code.as_str() {
        "invalid_grant" => Error::http(
            401,
            "Antigravity 的 refresh token 已失效或被撤销（Google 返回 invalid_grant）：请在 Google 账号授权页重新授权后，把新的 refresh_token 粘贴进本账号",
        ),
        "invalid_client" | "unauthorized_client" => Error::http(
            401,
            format!(
                "Antigravity 的 OAuth 客户端未被 Google 接受（{code}）：本网关内置的 client 与该 refresh token 不匹配，请重新授权后粘贴新的 refresh_token"
            ),
        ),
        _ => {
            let hint = if detail.is_empty() { String::new() } else { format!("：{detail}") };
            Error::http(502, format!("Antigravity 刷新 token 失败（{status}）{hint}"))
        }
    }
}

/// 打一次 token 端点（纯网络 + 解析，不落盘）。
pub fn refresh_access_token(refresh_token: &str) -> Result<TokenResponse> {
    let refresh_token = refresh_token.trim();
    if refresh_token.is_empty() {
        return Err(Error::http(
            401,
            "Antigravity 账号缺少 refresh token，请重新粘贴（Google OAuth 的 refresh_token）",
        ));
    }
    let body = form(&[
        ("client_id", endpoints::CLIENT_ID),
        ("client_secret", endpoints::CLIENT_SECRET),
        ("refresh_token", refresh_token),
        ("grant_type", endpoints::GRANT_TYPE_REFRESH),
    ]);
    let response = http::open(
        "POST",
        endpoints::TOKEN_URL,
        json!({
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "user-agent": endpoints::oauth_user_agent(),
        }),
        Some(&json!(body)),
    )?;
    let status = response.status;
    let bytes = response.bytes(1024 * 1024)?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(classify_failure(status, &text, &payload));
    }
    read_token_response(&payload, "Antigravity 刷新响应缺少 access_token，旧凭证未被覆盖")
}

/// 换码：授权码 → token（网页登录用）。
pub fn exchange_code(code: &str, redirect_uri: &str) -> Result<TokenResponse> {
    let code = code.trim();
    if code.is_empty() {
        return Err(Error::http(400, "缺少授权码，请重新发起网页登录"));
    }
    let body = form(&[
        ("client_id", endpoints::CLIENT_ID),
        ("client_secret", endpoints::CLIENT_SECRET),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", endpoints::GRANT_TYPE_AUTHORIZATION_CODE),
    ]);
    let response = http::open(
        "POST",
        endpoints::TOKEN_URL,
        json!({
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "user-agent": endpoints::oauth_user_agent(),
        }),
        Some(&json!(body)),
    )?;
    let status = response.status;
    let bytes = response.bytes(1024 * 1024)?;
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let (code, description) = upstream_error(&payload);
        let detail = if description.is_empty() { String::new() } else { format!("：{}", truncate(&description)) };
        return Err(Error::http(
            if code == "invalid_grant" || code == "redirect_uri_mismatch" {
                400
            } else if matches!(code.as_str(), "invalid_client" | "unauthorized_client") {
                401
            } else {
                502
            },
            match code.as_str() {
                "invalid_grant" => format!("Antigravity 授权码已失效或已被使用，请重新发起网页登录{detail}"),
                "redirect_uri_mismatch" => format!("Antigravity 授权回调地址与发起时不一致，请重新发起网页登录{detail}"),
                "invalid_client" | "unauthorized_client" => {
                    format!("Antigravity 的 OAuth 客户端未被 Google 接受（{code}）：请重新发起网页登录{detail}")
                }
                _ => format!("Antigravity 网页登录换取凭证失败（{status}）{detail}"),
            },
        ));
    }
    read_token_response(&payload, "Antigravity 换码响应缺少 access_token，账号未保存")
}

/// 取 userinfo 的 `email`（best-effort：v2 → v1）。
pub fn fetch_email(access_token: &str) -> Option<String> {
    let token = access_token.trim();
    if token.is_empty() {
        return None;
    }
    for url in [endpoints::USERINFO_URL_V2, endpoints::USERINFO_URL_V1] {
        let response = match http::open(
            "GET",
            url,
            json!({
                "accept": "application/json",
                "user-agent": endpoints::oauth_user_agent(),
                "authorization": format!("Bearer {token}"),
            }),
            None,
        ) {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !(200..300).contains(&response.status) {
            continue;
        }
        let Ok(value) = response.json() else {
            continue;
        };
        let email = value.get("email").and_then(Value::as_str).map(str::trim).filter(|text| !text.is_empty());
        if let Some(email) = email {
            return Some(email.to_string());
        }
    }
    None
}

/// project 发现：`loadCodeAssist` → `onboardUser`（固定 prod）。
pub fn discover_project(access_token: &str) -> Result<String> {
    let token = access_token.trim();
    if token.is_empty() {
        return Err(Error::http(401, "Antigravity 账号缺少 access token"));
    }
    let response = http::open(
        "POST",
        &endpoints::load_code_assist_url(),
        endpoints::admin_headers(token, ""),
        Some(&json!({ "metadata": { "pluginType": "GEMINI" } })),
    )?;
    if (200..300).contains(&response.status) {
        let value = response.json()?;
        if let Some(project) = value
            .get("cloudaicompanionProject")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            return Ok(project.to_string());
        }
    }
    // 没有 project：按 onboarding 的逻辑开通（带 tierId，缺省 LEGACY）。
    let response = http::open(
        "POST",
        &endpoints::onboard_user_url(),
        endpoints::admin_headers(token, ""),
        Some(&json!({ "tierId": "LEGACY", "metadata": { "pluginType": "GEMINI" } })),
    )?;
    if !(200..300).contains(&response.status) {
        return Err(Error::http(502, "Antigravity project 发现失败"));
    }
    let value = response.json()?;
    Ok(value
        .pointer("/response/cloudaicompanionProject")
        .or_else(|| value.get("cloudaicompanionProject"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string())
}

/// 读账号并保证 access token 可用（临期或强刷）。
pub fn ensure(force: bool) -> Result<(Value, AntigravityCredentials)> {
    let record = sdk::account()?;
    let secret = record["secret"].clone();
    let credentials = AntigravityCredentials::from_secret(&secret);
    if !force && !credentials.expiring() && !credentials.access_token.is_empty() {
        return Ok((record, credentials));
    }
    if !credentials.can_refresh() {
        if credentials.access_token.is_empty() {
            return Err(Error::http(
                401,
                "Antigravity 账号缺少 refresh token，无法续期，请重新粘贴",
            ));
        }
        // 手动粘贴的账号可能没有 expiresAt：没有 refresh token 也照用现有令牌。
        return Ok((record, credentials));
    }
    let _lock = sdk::AccountLock::acquire();
    let current = sdk::account()?;
    let latest = AntigravityCredentials::from_secret(&current["secret"]);
    if !force && !latest.access_token.is_empty() && !latest.expiring() {
        return Ok((current, latest));
    }
    let response = refresh_access_token(&latest.refresh_token)?;
    let mut fresh = latest.clone();
    fresh.access_token = response.access_token.trim().to_string();
    if let Some(refresh) = response.refresh_token {
        fresh.refresh_token = refresh.trim().to_string();
    }
    let expires_in = if (1..=7 * 24 * 3600).contains(&response.expires_in) {
        response.expires_in
    } else {
        DEFAULT_EXPIRES_IN_SECONDS
    };
    fresh.expires_at = sdk::now() + expires_in * 1000;
    let _ = response.token_type;
    // best-effort：project 缺失时补一次（只影响聊天，失败不阻断刷新）。
    if fresh.project_id.trim().is_empty() {
        if let Ok(project) = discover_project(&fresh.access_token) {
            if !project.trim().is_empty() {
                fresh.project_id = project;
            }
        }
    }
    let expect = current["secret"].clone();
    let mut next = expect.clone();
    fresh.write_into(&mut next);
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": super::credentials::public(&next) }),
    );
    match result {
        Ok(value) if value["updated"] == true => Ok((current, fresh)),
        // 期间被改动过：用新令牌，但不覆盖记录。
        _ => Ok((current, fresh)),
    }
}
