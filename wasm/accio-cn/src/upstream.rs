//! Accio 的请求封装与用户资料查询。
//!
//! ── 与另外几家的差别：token 不进请求头 ──────────────────────
//! 桌面端的业务接口**不走 Authorization**：GET 把 `accessToken` 拼进 query
//! （`GET /api/entitlement/quota?accessToken=…`），POST 放进 JSON body
//! （`POST /api/auth/refresh_token {accessToken, refreshToken}`）。本模块把
//! 这个约定收在两处构造里（[`get_with_token`] / [`post_json`]），别处不再各写。
//!
//! ── HTTP 成功 ≠ 业务成功 ────────────────────────────────────
//! 上游把业务结果放在 `{success, code, message, data}` 信封里，**HTTP 200 也可能
//! 是失败**（`code` 非 `0` / `200`、`success: false`、`message: NOT_LOGIN`）。
//! [`payload_of`] 负责把这层判掉，并按「鉴权 / 额度 / 其它」映射成网关认识的
//! 401 / 429 / 502 —— 编排层据此刷新重试或换号。
//!
//! ── 读 body 为什么用 `bytes` 而不是 `json()` ──────────────────
//! `http::Response::json()` 在非 2xx 上直接返回错误，**拿不到错误体** ——
//! 而上游的「登录态失效 / 额度耗尽」恰恰写在 4xx 的 body 里（`code` / `msg`）。
//! 所以这里先按原样取字节，再自己解析：状态码与信封一起判才完整。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{http, Error, Result, Value};

use super::credential::{self, Credential};
use super::protocol::{self, UpstreamKind};
use super::region::{self, Region};

/// 单次响应的读取上限（目录与额度都不该超过这个量级）
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

/// 一次业务请求（失败文案带传输层原因，便于排障）。
pub fn request(method: &str, url: &str, body: Option<&Value>, headers: Value) -> Result<http::Response> {
    http::open(method, url, headers, body).map_err(|error| {
        if matches!(error.status, Some(504)) {
            Error::http(504, "Accio 请求超时，请检查网络后重试").with_code("accio_transport")
        } else {
            Error::http(502, "无法连接 Accio，请检查网络").with_code("accio_transport")
        }
    })
}

/// GET + token 进 query（业务接口的约定之一）。
pub fn get_with_token(path: &str, token: &str, query: &[(&str, &str)]) -> Result<Value> {
    let mut url = format!("{}{path}", region::gateway_base());
    let mut separator = '?';
    for (key, value) in query {
        url.push(separator);
        url.push_str(&super::codec::urlencode(key));
        url.push('=');
        url.push_str(&super::codec::urlencode(value));
        separator = '&';
    }
    if !token.is_empty() {
        url.push(separator);
        url.push_str("accessToken=");
        url.push_str(&super::codec::urlencode(token));
    }
    let response = request("GET", &url, None, region::api_headers(region::REGION))?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT)?;
    payload_of(status, decode(&bytes), "查询")
}

/// POST + JSON body（业务接口的约定之二）。
pub fn post_json(region: Region, path: &str, body: &Value, action: &str) -> Result<Value> {
    let url = format!("{}{path}", region::gateway_base());
    let response = request("POST", &url, Some(body), region::api_headers(region))?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT)?;
    payload_of(status, decode(&bytes), action)
}

/// 字节 → JSON（解析不了按 Null：上游在 502/风控页上会回 HTML）。
fn decode(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

/// 上游信封 → `data`（或原对象）。
///
/// `action` 进错误文案（「Accio 授权码换令牌失败（HTTP 200，业务码 401）…」），
/// 用户能据此判断是哪一步不通。
fn payload_of(status: u16, body: Value, action: &str) -> Result<Value> {
    let code = credential::text(&body, &["code"]);
    let message = credential::text(&body, &["message", "msg"]);
    let upstream_code = code.parse::<i64>().ok();
    let ok = (200..300).contains(&status);
    let business_failed = body.get("success").and_then(Value::as_bool) == Some(false)
        || (!code.is_empty() && code != "0" && code != "200")
        || message.eq_ignore_ascii_case("NOT_LOGIN");
    if !ok || business_failed {
        let classification_status = if ok {
            upstream_code
                .and_then(|code| u16::try_from(code).ok())
                .unwrap_or(status)
        } else {
            status
        };
        let kind = protocol::classify_upstream_error(classification_status, &format!("{code} {message}"));
        let mapped = match kind {
            UpstreamKind::Auth => 401,
            UpstreamKind::Quota => 429,
            UpstreamKind::Other if !ok => status,
            UpstreamKind::Other => 502,
        };
        let mut detail = format!("HTTP {status}");
        if !code.is_empty() {
            detail.push_str(&format!("，业务码 {code}"));
        }
        if !message.is_empty() && message != "0" {
            detail.push_str(&format!("，{message}"));
        }
        let hint = match kind {
            UpstreamKind::Auth => "，登录授权不可用，请尝试刷新凭证或重新登录",
            UpstreamKind::Quota => "，请检查剩余额度或稍后重试",
            UpstreamKind::Other => "",
        };
        return Err(
            Error::http(mapped, format!("Accio {action}失败（{detail}）{hint}")).with_code("accio_upstream"),
        );
    }
    Ok(body)
}

/// 取 `data`（上游常见两层信封；取不到就回原对象）。
pub fn unwrap_data(payload: Value) -> Value {
    match payload.get("data") {
        Some(Value::Object(_)) => payload.get("data").cloned().unwrap_or(payload),
        _ => payload,
    }
}

/// 查用户资料（`GET /api/auth/userinfo?accessToken=…`）。
///
/// 上游把资料放在 `data` 里还是顶层，两种形态都见过 —— 都接受。
pub fn fetch_profile(token: &str) -> Result<Value> {
    let payload = get_with_token(region::USER_INFO_PATH, token, &[])?;
    Ok(unwrap_data(payload))
}

/// 把资料里的身份/名字搬进凭证。查询失败**不算失败**：拿不到资料照常建账号
/// （id 走凭证指纹兜底、名字走备注名），只是少一行副标题。
pub fn apply_profile(credential: &mut Credential, profile: &Value) {
    let user_id = credential::text(profile, &["id", "userId", "user_id", "uid"]);
    if !user_id.is_empty() {
        credential.user_id = user_id;
    }
    let name = credential::text(profile, &["nickname", "name", "displayName", "userName"]);
    if !name.is_empty() {
        credential.name = name.chars().take(100).collect();
    }
    let email = credential::text(profile, &["email", "emailAddress"]);
    if !email.is_empty() {
        credential.email = email.chars().take(320).collect();
    }
    let device_id = credential::text(profile, &["deviceId", "device_id"]);
    if !device_id.is_empty() && credential.device_id.is_empty() {
        credential.device_id = device_id;
    }
}
