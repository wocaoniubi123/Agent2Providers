//! 旧凭证续期可返回 IAM；迁移成功后不再保留旧刷新令牌。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::credentials::Credentials;
use crate::errors as upstream_errors;
use crate::{iam, jwt, upstream};

/// 调 `POST {authBase}/refresh` 换一份新凭证。
///
/// 判定链与 native 逐条一致：
///   ① 传输失败 → 502「刷新 token 请求失败」；
///   ② 非 2xx 或业务码非 0 → 401（上游说是凭证问题）或 502；
///   ③ `data.access_token` 为空 → 401「未返回新的 access_token」；
///   ④ 回来的若是 IAM token → 立刻用 `user_info` 校验一次（IAM 没有 refresh
///      grant，续期结果必须当场自证可用），并**丢弃**刷新令牌。
///
/// native 侧这次请求带 30 秒超时（`AUTH_REQUEST_TIMEOUT_MS`）；wasm 宿主的
/// 出网层统一管超时，插件没有按次设超时的入口 —— 这是**能力差异**，不是漏写。
pub fn call(credentials: &Credentials) -> Result<Credentials> {
    let url = format!("{}/refresh", upstream::auth_api_base());
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {}", jwt::strip_bearer(&credentials.token)),
        ),
    ];
    let body = json!({ "refresh_token": credentials.refresh_token });
    let response = upstream::send("POST", &url, &headers, Some(&body))
        .map_err(|error| upstream::transport("小浣熊刷新 token 请求失败", error))?;
    let payload = response.payload;
    let code = upstream_errors::business_code(&payload);
    if !response.ok || code.is_some_and(|code| code != 0) {
        let status = if response.status == 401 || upstream_errors::token_expired(&payload) {
            401
        } else {
            502
        };
        return Err(with_code(
            Error::http(
                status,
                format!(
                    "小浣熊刷新接口失败（HTTP {}）: {}",
                    response.status,
                    upstream_errors::message(&payload)
                ),
            ),
            code,
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let access_token = data
        .get("access_token")
        .and_then(Value::as_str)
        .map(jwt::strip_bearer)
        .unwrap_or_default();
    if access_token.is_empty() {
        return Err(with_code(
            Error::http(401, "小浣熊刷新接口未返回新的 access_token"),
            code,
        ));
    }
    let profile = if jwt::is_iam_token(&access_token) {
        Some(iam::user_info(&access_token)?)
    } else {
        None
    };
    let next_refresh = if profile.is_some() {
        String::new()
    } else {
        data.get("refresh_token")
            .and_then(Value::as_str)
            .map(jwt::strip_bearer)
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| credentials.refresh_token.clone())
    };
    let next_user_id = profile
        .as_ref()
        .and_then(|profile| profile.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            jwt::decode_jwt_claims(&access_token)
                .as_ref()
                .map(jwt::extract_user_id)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| credentials.user_id.clone());
    Ok(Credentials {
        id: credentials.id.clone(),
        expires_at: jwt::jwt_expiry_ms(&access_token).or(credentials.expires_at),
        user_id: next_user_id,
        org_code: credentials.org_code.clone(),
        token: access_token,
        refresh_token: next_refresh,
    })
}

/// 把上游业务码挂到错误上（网关据此做限额事件与排障）。
fn with_code(mut error: Error, code: Option<i64>) -> Error {
    error.upstream_code = code;
    error
}
