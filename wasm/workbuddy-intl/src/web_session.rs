//! 官网登录态（Cookie）只绑定当前账号、身份和固定 HTTPS 域。
//!
//! ── 这一层为什么存在 ────────────────────────────────────────
//! 国际版官网（`www.workbuddy.ai`）的鉴权是**官网 session cookie**，不是 Bearer。
//! 拿 Bearer 去发网页通道的请求（`POST /console/as/conversations/` 建会话 = 每日
//! 活跃的判定通道）会被当成未登录。所以要先拿一次性 device code 换一张
//! `session=…` 的 Cookie。
//!
//! ── 与 native 的差别（存储位置）────────────────────────────
//! native 把 Cookie 写进**账号记录**的私有键（`workbuddyWebSession`）并做比较再写。
//! wasm 插件没有「改账号记录」以外的存储（`account.update` 只换 secret），而把
//! Cookie 混进 secret 会让账号视图与续期链都多背一个无关字段。这里改用**宿主的
//! 会话存储**（`session.get` / `session.put`，带 TTL）：键里带账号身份摘要，
//! 身份一变旧 Cookie 自然取不到（等价于 native 的 `authority` 校验）。
//!
//! ── 重定向 ──────────────────────────────────────────────────
//! `/console/client-login` 是 **302 + Set-Cookie** 的形态。宿主是否自动跟随重定向
//! 由它决定，所以这里两条路都走：先看本跳的 `set-cookie`，没有再按 `location`
//! 手动跟（最多 6 跳），并且始终限定在同一个 origin、只 `https`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::contract;
use crate::httpio::{self, ApiResponse};
use crate::util;

/// 一次网页登录态的最长生命周期（7 天，与 native 同值）。
const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60_000;

/// 一次网页请求能带的额外头白名单（其余一律丢弃）。
///
/// 这些是**不能**从调用方带进来的头：Cookie 由这里接管，Authorization 会覆盖官网
/// 登录态，Host / Origin 被固定成官网域。
const BLOCKED: &[&str] = &[
    "authorization",
    "cookie",
    "host",
    "origin",
    "x-refresh-token",
    "x-user-id",
    "x-enterprise-id",
    "x-tenant-id",
    "x-domain",
];

/// 账号身份的稳定摘要（Cookie 的作用域键）。
fn identity_key(session: &Value) -> String {
    let authority = crate::catalog::authority(session).to_string();
    let uid = session
        .pointer("/account/uid")
        .and_then(Value::as_str)
        .unwrap_or("");
    let endpoint = crate::outbound::session_endpoint_of(session);
    util::derive_id("websession", &format!("{uid}|{authority}|{endpoint}"))
}

fn storage_key(identity: &str) -> String {
    format!("workbuddy-web:{identity}")
}

/// 取现存的 Cookie（过期 / 形态不对就当作没有）。
fn cached(identity: &str) -> Option<String> {
    let saved = agent2api_wasm_sdk::session_get(&storage_key(identity)).ok()?;
    let cookie = saved.get("cookie").and_then(Value::as_str)?.to_string();
    let expires_at = saved.get("expiresAt").and_then(Value::as_i64)?;
    if expires_at <= util::now_ms() || !valid_cookie(&cookie) {
        return None;
    }
    Some(cookie)
}

fn remember(identity: &str, cookie: &str, expires_at: i64) {
    let ttl = expires_at.saturating_sub(util::now_ms()).max(1_000);
    let _ = agent2api_wasm_sdk::session_put(
        &storage_key(identity),
        json!({ "cookie": cookie, "expiresAt": expires_at }),
        ttl,
    );
}

/// 发一次网页接口请求（自动带 Cookie，401 时换一张再试一次）。
pub fn request(
    session: &Value,
    _id: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    extra: &[(String, String)],
) -> Result<ApiResponse> {
    let origin = contract::web_origin();
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(Error::http(400, "网页接口路径无效"));
    }
    let url = format!("{origin}{path}");
    if util::origin_of(&url).as_deref() != Some(origin) {
        return Err(Error::http(400, "网页登录态不得跨域使用"));
    }
    let identity = identity_key(session);
    let mut cookie = match cached(&identity) {
        Some(cookie) => cookie,
        None => acquire(session, &identity)?,
    };
    for attempt in 0..2 {
        let mut headers: Vec<(String, String)> = vec![
            ("Cookie".to_string(), cookie.clone()),
            ("Accept".to_string(), "application/json, text/plain, */*".to_string()),
            ("User-Agent".to_string(), crate::growth::WEB_UA.to_string()),
            ("Origin".to_string(), origin.to_string()),
            (
                "Referer".to_string(),
                format!("{origin}/profile/growth-center"),
            ),
        ];
        for (key, value) in extra {
            if BLOCKED.iter().any(|name| key.eq_ignore_ascii_case(name)) {
                continue;
            }
            if key.eq_ignore_ascii_case("referer")
                && util::origin_of(value).as_deref() != Some(origin)
            {
                continue;
            }
            headers.push((key.clone(), value.clone()));
        }
        let response = httpio::send(method, &url, &headers, body)?;
        if response.status == 401 && attempt == 0 {
            // Cookie 被服务端拒了：换一张再试一次（native 同口径）
            cookie = acquire(session, &identity)?;
            continue;
        }
        return Ok(response);
    }
    Err(Error::http(401, "官网登录态被拒绝"))
}

/// 换一张新的官网 Cookie（device code → client-login → Set-Cookie）。
fn acquire(session: &Value, identity: &str) -> Result<String> {
    let origin = contract::web_origin();
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
        ("User-Agent".to_string(), "node".to_string()),
        ("Accept-Language".to_string(), "*".to_string()),
        ("Sec-Fetch-Mode".to_string(), "cors".to_string()),
    ];
    for (key, value) in crate::auth::build_auth_headers(session) {
        // X-Department-Info 不在网页换码的白名单里（native 明确排除）
        if !key.eq_ignore_ascii_case("X-Department-Info") {
            headers.push((key, value));
        }
    }
    if let Some(token) = session
        .pointer("/auth/refreshToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
    {
        headers.push(("X-Refresh-Token".to_string(), token.to_string()));
    }
    let response = httpio::send(
        "POST",
        &format!("{origin}/v2/plugin/device/auth/code"),
        &headers,
        Some(&json!({})),
    )
    .map_err(|error| httpio::transport_error("获取网页登录码", error))?;
    if !(200..300).contains(&response.status) {
        return Err(Error::http(
            response.status.max(400),
            "官方未签发网页登录码，请检查当前登录态",
        ));
    }
    if response.code().is_some_and(|code| code != 0) {
        let status = if response.code() == Some(12153) { 401 } else { 502 };
        return Err(Error::http(status, "官方未签发网页登录码，请检查当前登录态"));
    }
    let code = response
        .payload
        .as_ref()
        .and_then(|value| value.pointer("/data/deviceCode"))
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty())
        .ok_or_else(|| Error::http(502, "官方响应缺少一次性网页登录码"))?
        .to_string();

    let mut url = format!(
        "{origin}/console/client-login?code={}&target=%2Fprofile%2Fgrowth-center",
        util::encode_component(&code)
    );
    let mut cookie: Option<(String, i64)> = None;
    let mut expires = util::now_ms().saturating_add(MAX_AGE_MS);
    for _ in 0..6 {
        if util::origin_of(&url).as_deref() != Some(origin) {
            break;
        }
        let mut headers = vec![
            (
                "Accept".to_string(),
                "text/html,application/xhtml+xml".to_string(),
            ),
            ("User-Agent".to_string(), crate::growth::WEB_UA.to_string()),
        ];
        if let Some((value, _)) = &cookie {
            headers.push(("Cookie".to_string(), value.clone()));
        }
        let response = match httpio::send("GET", &url, &headers, None) {
            Ok(response) => response,
            // 已拿过 Cookie 就停：登录已经完成，后面那一跳的失败不影响结果
            Err(error) if cookie.is_some() => {
                let _ = error;
                break;
            }
            Err(error) => return Err(httpio::transport_error("官网登录", error)),
        };
        for value in set_cookies(&response.headers) {
            if let Some((value, expiry)) = parse_cookie(&value, util::authority_of(&url).as_str()) {
                cookie = Some((value, expiry));
                expires = expiry;
            }
        }
        let location = util::header_of(&response.headers, "location");
        if !(300..400).contains(&response.status) || location.is_empty() {
            if !(200..400).contains(&response.status) && cookie.is_none() {
                return Err(Error::http(
                    response.status.max(400),
                    "官网 client-login 拒绝了登录码",
                ));
            }
            break;
        }
        url = match location.starts_with("http") {
            true => location,
            false => format!("{origin}{location}"),
        };
    }
    let (cookie, _) = cookie
        .filter(|(value, _)| valid_cookie(value))
        .ok_or_else(|| Error::http(502, "官网没有返回有效 session Cookie"))?;
    remember(identity, &cookie, expires);
    Ok(cookie)
}

/// 从响应头里取全部 `set-cookie`（可能是字符串、也可能是数组）。
fn set_cookies(headers: &Value) -> Vec<String> {
    let raw = headers
        .get("set-cookie")
        .cloned()
        .or_else(|| {
            headers
                .as_object()
                .into_iter()
                .flatten()
                .find(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, value)| value.clone())
        })
        .unwrap_or(Value::Null);
    match raw {
        Value::String(text) => vec![text],
        Value::Array(items) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Cookie 的形态判据：`session=` 开头、长度合理、全可打印且不含分隔符。
pub fn valid_cookie(cookie: &str) -> bool {
    cookie.starts_with("session=")
        && cookie.len() > 8
        && cookie.len() <= 16_384
        && cookie
            .get(8..)
            .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_graphic() && byte != b';' && byte != b','))
}

/// 解析一条 `Set-Cookie`（domain 必须与本站一致、path 必须是 `/`）。
fn parse_cookie(header: &str, host: &str) -> Option<(String, i64)> {
    let mut parts = header.split(';');
    let cookie = parts.next()?.trim().to_string();
    if !valid_cookie(&cookie) {
        return None;
    }
    let now = util::now_ms();
    let mut expires = now.saturating_add(MAX_AGE_MS);
    for part in parts {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "domain" if value.trim_start_matches('.') != host => return None,
            "path" if value != "/" => return None,
            "max-age" => {
                expires = now.saturating_add(
                    value
                        .parse::<i64>()
                        .ok()?
                        .max(0)
                        .min(MAX_AGE_MS / 1000)
                        .saturating_mul(1000),
                )
            }
            "expires" => {
                if let Ok(time) = chrono::DateTime::parse_from_rfc2822(value) {
                    expires = expires.min(time.timestamp_millis());
                }
            }
            _ => {}
        }
    }
    (expires > now).then_some((cookie, expires))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_must_start_with_session() {
        assert!(valid_cookie("session=abc123456"));
        assert!(!valid_cookie("JSESSIONID=abc"));
        assert!(!valid_cookie("session="));
        assert!(!valid_cookie("session=ab;cd"));
    }

    #[test]
    fn set_cookie_parsing_reads_max_age() {
        let (cookie, expires) = parse_cookie(
            "session=okvalue123; Path=/; Max-Age=3600; Domain=www.workbuddy.ai",
            "www.workbuddy.ai",
        )
        .unwrap_or_default();
        assert_eq!(cookie, "session=okvalue123");
        assert!(expires > util::now_ms());
        // domain 不一致 → 丢弃
        assert!(parse_cookie("session=okvalue123; Domain=evil.example", "www.workbuddy.ai").is_none());
    }
}
