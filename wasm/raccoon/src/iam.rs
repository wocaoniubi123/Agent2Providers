//! IAM 首次迁移通过 user_info 校验；仅业务码 200901 触发一次 iam/confirm。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::errors as upstream_errors;
use crate::{headers, jwt, upstream};

/// 业务码 200901：IAM 账号首次访问业务接口时要求确认一次（幂等）。
const IAM_CONFIRMATION_REQUIRED: i64 = 200_901;

/// 解包一次 `user_info` 的应答。
///
/// 判定顺序与 native 一致：401 / 凭证过期 → 401；非 2xx 或业务码不是 0 →
/// 502 带上游文案；`data` 必须是对象。
fn result(response: upstream::Raw) -> Result<Value> {
    let payload = response.payload;
    let code = upstream_errors::business_code(&payload);
    if response.status == 401 || upstream_errors::token_expired(&payload) {
        return Err(with_code(
            Error::http(401, "小浣熊 IAM 登录态无效，请重新登录"),
            code,
        ));
    }
    if !response.ok || code != Some(0) {
        return Err(with_code(
            Error::http(502, upstream_errors::message(&payload)),
            code,
        ));
    }
    payload
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .ok_or_else(|| Error::http(502, "小浣熊账号资料响应结构异常"))
}

/// 查账号资料（IAM 专用）。
///
/// ── 为什么要先 validate 一次 ────────────────────────────────
/// 这条链只服务 IAM 登录态（旧 JWT 没有这个接口的必要），而 IAM 的 issuer /
/// sub / exp 三条判据只有本地知道。先校验能挡住「拿旧 JWT 来问资料」这条
/// 必然 4xx 的请求，也让错误文案直接指向「重新登录」。
pub fn user_info(token: &str) -> Result<Value> {
    jwt::validate_iam_token(token, &upstream::iam_issuer())?;
    let mut headers = headers::desktop_client_headers();
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    let base = upstream::auth_api_base();
    let user_url = format!("{base}/user_info");
    let response =
        upstream::send("GET", &user_url, &headers, None).map_err(|error| {
            upstream::transport("小浣熊账号资料查询失败", error)
        })?;
    let needs_confirmation =
        upstream_errors::business_code(&response.payload) == Some(IAM_CONFIRMATION_REQUIRED);
    let data = if needs_confirmation {
        let confirmation = upstream::send(
            "POST",
            &format!("{base}/iam/confirm"),
            &headers,
            Some(&json!({})),
        )
        .map_err(|error| upstream::transport("小浣熊 IAM 确认失败", error))?;
        let payload = confirmation.payload.clone();
        if !confirmation.ok || upstream_errors::business_code(&payload) != Some(0) {
            let status = if confirmation.status == 401
                || upstream_errors::token_expired(&payload)
            {
                401
            } else {
                502
            };
            return Err(with_code(
                Error::http(status, upstream_errors::message(&payload)),
                upstream_errors::business_code(&payload),
            ));
        }
        // 确认之后**重新查一次**：确认接口只表示「可以查了」，资料本身要再取。
        let retried = upstream::send("GET", &user_url, &headers, None)
            .map_err(|error| upstream::transport("小浣熊账号资料查询失败", error))?;
        result(retried)?
    } else {
        result(response)?
    };
    // 平台用户 ID 是账号标识的唯一来源；缺失就不能落库（否则两条同名记录）。
    if !data
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty() && id.len() <= 256)
    {
        return Err(Error::http(502, "小浣熊账号资料缺少平台用户 ID"));
    }
    Ok(data)
}

fn with_code(mut error: Error, code: Option<i64>) -> Error {
    error.upstream_code = code;
    error
}
