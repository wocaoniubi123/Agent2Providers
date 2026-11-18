//! Kiro 凭证续期：社交登录 / AWS OIDC / 外部 IdP，以及首次补 profile。
//!
//! ── 三条刷新链路 ────────────────────────────────────────────
//! ```text
//!   social        POST https://prod.{region}.auth.desktop.kiro.dev/refreshToken
//!                 {"refreshToken":"…"} → {accessToken, refreshToken, expiresIn}
//!   idc           POST https://oidc.{region}.amazonaws.com/token
//!                 {clientId, clientSecret, refreshToken, grantType}
//!   external-idp  宿主 `credential.kiro.external.refresh`（见下）
//!   apikey        没有续期接口
//!   本机登录态    现读本机 → 需要时按上面三条刷新，结果只进会话缓存
//! ```
//!
//! ── 为什么 external-idp 走宿主 ──────────────────────────────
//! 外部 IdP 的 token 端点是**账号自带的任意域名**（`tokenURL`），
//! `wasm.json` 的 `origins` 是精确匹配，静态白名单写不下。宿主为此开了
//! `credential.kiro.external.refresh`（能力 `credential.kiro-external-refresh.v1`，
//! 只有 kiro 能用）：它只打账号里已保存的那一个端点，并把一次性刷新凭据的
//! 消费记在插件状态里（防重复使用）。参数为空、返回 `{accessToken,
//! refreshToken, expiresAt}`。
//!
//! ── 为什么本机登录态不写回 ──────────────────────────────────
//! 本机续期的宿主辅助 `desktop.refresh.kiro.v1` 要求插件提交宿主算出的
//! `sourceRevision`，而读接口（`desktop.credentials.read`）只回 secret、不回
//! revision —— 插件拿不到这个值，硬编就是必然失败。所以本机账号的刷新结果
//! 只进会话缓存（给本轮与接下来的几轮用），账号里只更新读数；客户端自己
//! 续期后下一次读取会覆盖它。这与 quwork 本机账号同一处置。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::credentials::Credentials;
use super::endpoints;

/// 一次刷新得到的 token 三件套。
struct Refreshed {
    access: String,
    refresh: String,
    expires_in: i64,
}

/// 会话缓存键（本机账号刷新结果的短期复用）。
fn local_key(account: &str) -> String {
    format!("kiro:local:{account}")
}

/// 打一次 JSON 接口。
fn post_json(url: &str, body: &Value, headers: Value) -> Result<Value> {
    let mut headers = headers;
    headers["content-type"] = json!("application/json");
    headers["accept"] = json!("application/json");
    let response = http::open("POST", url, headers, Some(body))?;
    let status = response.status;
    if !(200..300).contains(&status) {
        if matches!(status, 400 | 401 | 403) {
            return Err(Error::http(401, "Kiro 的登录态已失效，请重新登录 Kiro"));
        }
        return Err(Error::http(502, format!("刷新 Kiro 登录态失败（HTTP {status}）")));
    }
    response.json()
}

/// 打一次刷新请求（按 method 分派）。
fn refresh_once(credentials: &Credentials) -> Result<Refreshed> {
    if credentials.refresh.is_empty() {
        return Err(Error::http(401, "Kiro 的登录态已失效，请重新登录 Kiro"));
    }
    let region = credentials.region();
    match credentials.method.as_str() {
        "social" => {
            let value = post_json(
                &endpoints::refresh_url(&region),
                &json!({ "refreshToken": credentials.refresh }),
                json!({ "user-agent": endpoints::DESKTOP_UA }),
            )?;
            Ok(Refreshed {
                access: value.get("accessToken").and_then(Value::as_str).unwrap_or("").to_string(),
                refresh: value.get("refreshToken").and_then(Value::as_str).unwrap_or("").to_string(),
                expires_in: value.get("expiresIn").and_then(Value::as_i64).unwrap_or(0),
            })
        }
        "idc" => {
            let value = post_json(
                &format!("{}/token", endpoints::oidc(&region)),
                &json!({
                    "clientId": credentials.client_id,
                    "clientSecret": credentials.client_secret,
                    "refreshToken": credentials.refresh,
                    "grantType": "refresh_token",
                }),
                json!({ "user-agent": endpoints::ide_user_agent() }),
            )?;
            Ok(Refreshed {
                access: value.get("accessToken").and_then(Value::as_str).unwrap_or("").to_string(),
                refresh: value.get("refreshToken").and_then(Value::as_str).unwrap_or("").to_string(),
                expires_in: value.get("expiresIn").and_then(Value::as_i64).unwrap_or(0),
            })
        }
        "external-idp" => {
            // 端点由账号自带，只允许宿主代打（见模块头）。
            let value = sdk::host("credential.kiro.external.refresh", json!({})).map_err(|error| {
                if error.status == Some(401) || error.status == Some(403) {
                    Error::http(401, "Kiro 的登录态已失效，请用 kiro-cli 重新登录")
                } else {
                    Error::http(502, format!("刷新 Kiro 外部授权失败：{}", error.message))
                }
            })?;
            Ok(Refreshed {
                access: value.get("accessToken").and_then(Value::as_str).unwrap_or("").to_string(),
                refresh: value.get("refreshToken").and_then(Value::as_str).unwrap_or("").to_string(),
                expires_in: value
                    .get("expiresAt")
                    .and_then(Value::as_i64)
                    .map(|expires| (expires - sdk::now()) / 1000)
                    .unwrap_or(0),
            })
        }
        _ => Err(Error::http(401, "Kiro 的登录态已失效，请重新登录 Kiro")),
    }
}

/// 把一次刷新落到一份凭证上（就地）。
fn apply(credentials: &mut Credentials, refreshed: Refreshed) -> Result<()> {
    if refreshed.access.is_empty() {
        return Err(Error::http(401, "Kiro 的登录态已失效，请重新登录 Kiro"));
    }
    credentials.access = refreshed.access;
    if !refreshed.refresh.is_empty() {
        credentials.refresh = refreshed.refresh;
    }
    let seconds = if refreshed.expires_in > 0 { refreshed.expires_in } else { 3600 };
    credentials.expires = sdk::now() + seconds * 1000;
    Ok(())
}

/// 读宿主提供的本机登录态（`desktop.credentials.read`）。
pub fn read_local() -> Result<Value> {
    sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(
            400,
            format!(
                "Kiro 的本机登录态不存在或不可读：{}（请先在 kiro-cli 或 Kiro IDE 里登录）",
                error.message
            ),
        )
    })
}

/// 读账号并把凭证准备到「现在能用」。
pub fn ensure(force: bool) -> Result<(Value, Credentials)> {
    let record = sdk::account()?;
    let account_id = record["id"].as_str().unwrap_or("").to_string();
    let secret = record["secret"].clone();
    let mut credentials = Credentials::from_secret(&secret);
    if credentials.is_local() {
        let live = read_local()?;
        let mut live = Credentials::from_secret(&live);
        if !live.fresh(endpoints::EARLY_MS) || force {
            live = refresh_local(&account_id, &live)?;
        }
        if live.profile.is_empty() {
            if let Ok(profile) = lookup_profile(&live) {
                live.profile = profile;
            }
        }
        return Ok((record, live));
    }
    if force || !credentials.fresh(endpoints::EARLY_MS) {
        credentials = guarded_refresh(&record, &credentials)?;
    }
    // OAuth 登录态第一次用时补 profile（额度、目录与对话都要它）。
    if !credentials.is_api_key() && credentials.profile.is_empty() {
        if let Ok(profile) = lookup_profile(&credentials) {
            if !profile.is_empty() {
                credentials.profile = profile;
                let mut next = secret.clone();
                credentials.write_into(&mut next);
                let _ = sdk::host(
                    "account.update",
                    json!({ "expect": secret, "secret": next, "public": super::credentials::public(&next) }),
                );
            }
        }
    }
    Ok((record, credentials))
}

/// 本机账号的刷新：结果只进会话缓存（见模块头）。
fn refresh_local(account_id: &str, credentials: &Credentials) -> Result<Credentials> {
    let key = local_key(account_id);
    if let Ok(cached) = sdk::session_get(&key) {
        let cached = Credentials::from_secret(&cached);
        if cached.fresh(endpoints::EARLY_MS) {
            return Ok(cached);
        }
    }
    let mut next = credentials.clone();
    let refreshed = refresh_once(credentials)?;
    apply(&mut next, refreshed)?;
    let mut value = json!({});
    next.write_into(&mut value);
    let _ = sdk::session_put(&key, value, 2 * 60 * 60_000);
    Ok(next)
}

/// 单飞刷新：账号锁内重读，前一轮已刷好的结果直接复用。
fn guarded_refresh(record: &Value, credentials: &Credentials) -> Result<Credentials> {
    let _lock = sdk::AccountLock::acquire();
    let current = sdk::account()?;
    let latest = Credentials::from_secret(&current["secret"]);
    if latest.access != credentials.access && latest.fresh(endpoints::EARLY_MS) {
        return Ok(latest);
    }
    let mut next = latest.clone();
    let refreshed = refresh_once(&latest)?;
    apply(&mut next, refreshed)?;
    let expect = current["secret"].clone();
    let mut secret = expect.clone();
    next.write_into(&mut secret);
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": secret, "public": super::credentials::public(&secret) }),
    )?;
    if result["updated"] != true {
        // 期间被改动过：用刷出来的令牌，但不覆盖记录（与 native 同一告知口径）。
        return Ok(next);
    }
    let _ = record;
    Ok(next)
}

/// 首次为凭证补 profile（Builder ID 用固定 profile，其余问控制面）。
pub fn lookup_profile(credentials: &Credentials) -> Result<String> {
    if credentials.login_provider == "builderid" {
        return Ok(endpoints::BUILDER_ID_PROFILE.to_string());
    }
    let region = credentials.region();
    let mut last = String::new();
    for attempt in [region.as_str(), "us-east-1", "eu-central-1"] {
        let url = format!("{}/List-Available-Profiles?origin=KIRO_CLI", endpoints::management(attempt));
        let mut headers = json!({
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": format!("Bearer {}", credentials.access),
        });
        if let Some(kind) = credentials.token_type() {
            headers["tokentype"] = json!(kind);
        }
        let response = match http::open("POST", &url, headers, Some(&json!({}))) {
            Ok(response) => response,
            Err(error) => {
                last = error.message;
                continue;
            }
        };
        let status = response.status;
        let bytes = response.bytes(1024 * 1024).unwrap_or_default();
        if !(200..300).contains(&status) {
            let text = String::from_utf8_lossy(&bytes).to_string();
            if credentials.method == "idc" && status == 403 && text.contains("Builder ID") {
                return Ok(endpoints::BUILDER_ID_PROFILE.to_string());
            }
            last = format!("HTTP {status}");
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(arn) = value
            .get("profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(|profile| profile.get("arn").and_then(Value::as_str))
        {
            return Ok(arn.to_string());
        }
    }
    Err(Error::http(
        502,
        if last.is_empty() {
            "Kiro 没有为这个登录态提供 profile".to_string()
        } else {
            format!("Kiro 没有为这个登录态提供 profile（{last}）")
        },
    ))
}
