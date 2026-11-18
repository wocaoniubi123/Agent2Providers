//! 控制面请求的统一出口：SDK-HMAC / V11 签名 + 发请求 + 响应错误归一 + 脱敏。
//!
//! native 的 `upstream::call` 与 `subscription::call` 是本模块的两个调用方：
//! 前者签 `https://agentarts…/v1/claw/*` 与 `https://iam…/v3/projects`（SDK 算法），
//! 后者签 `/v1/subscription*`、`/v1/model-token-rates`（V11 算法，挂在**网关根**）。
//!
//! ── 三个稳定错误码（都过线到网关，前端按 code 分支）────────
//!   · [`CONTROL_TOKEN_EXPIRED`]：临时凭据过期 ⇒ 调用方先续期再重试一次；
//!   · [`RESULT_UNCERTAIN`]：POST 的结果没拿到（网络断 / 5xx / 非 JSON）⇒
//!     **不许重试**，让用户去官方客户端核对（写请求重放可能变成第二笔订单）；
//!   · [`SUBSCRIPTION_UNCERTAIN`]：开通动作的结果不确定（同上，但语义更窄）。
//!
//! ── 为什么这里不用 `http::open` 的 JSON 便捷路径 ─────────────
//! `Response::json()` 只在 2xx 时成功，而本家需要**读到非 2xx 的正文**才能把
//! `error_code` / `error_msg` 翻成人话（判「过期」还是「没权限」全看正文）。
//! 所以统一走 `open_raw` + `bytes`，自己判状态码与 JSON。
//!
//! ── 脱敏 ────────────────────────────────────────────────────
//! 上游的错误正文偶尔会回显请求里的材料（AK / STS / app secret）。这些字符串
//! 会被原样塞进给用户看的错误文案，所以每个外出的文案都过 [`clean`]。

use agent2api_wasm_sdk::{http, Error, Result, Value};

use super::credentials::OfficeAceCredential;
use super::signer::{self, Algorithm};
use super::util;

/// 临时凭据过期（调用方据此续期后重试一次）。
pub const CONTROL_TOKEN_EXPIRED: &str = "officeace_control_token_expired";
/// POST 结果不确定（**不许重试**）。
///
/// 与开通动作共用同一个字符串：前端只按「这条要不要重试」分支，两处语义一致
/// （native 也是同一个常量值，见 `upstream::RESULT_UNCERTAIN` 与 `SUBSCRIPTION_UNCERTAIN`）。
pub const RESULT_UNCERTAIN: &str = "officeace_subscription_uncertain";
/// 响应体的读取预算（控制面回的都是小 JSON；超了说明对面不是我们要的东西）。
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

/// 调一次控制面接口，返回解析后的 JSON。
pub fn call(
    credential: &OfficeAceCredential,
    method: &str,
    url: &str,
    algorithm: Algorithm,
    body: Option<Value>,
    extra_headers: &[(&str, &str)],
) -> Result<Value> {
    let signing = credential.signing().map_err(|reason| Error::http(400, reason))?;
    if signing.security_token.is_empty() {
        return Err(Error::http(
            400,
            "OfficeAce 缺少临时安全令牌，请重新登录补齐授权",
        ));
    }
    let payload = body.as_ref().map(Value::to_string).unwrap_or_default();
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    if body.is_some() {
        headers.push(("Content-Type".to_string(), "application/json;charset=utf8".to_string()));
    }
    let signed = signer::sign(&signer::SignRequest {
        algorithm,
        method,
        url,
        headers: &headers,
        body: payload.as_bytes(),
        credential: &signing,
        region: signer::DEFAULT_REGION,
    })
    .map_err(|reason| uncertain(method, Error::http(502, format!("OfficeAce 请求签名失败：{reason}"))))?;

    let header_object = header_object(&signed);
    let request_body = if payload.is_empty() { None } else { Some(payload.as_bytes()) };
    let response = http::open_raw(method, url, header_object, request_body).map_err(|error| {
        uncertain(
            method,
            Error::http(
                502,
                format!("OfficeAce 请求未能确认结果：{}", clean(&error.message, credential)),
            ),
        )
    })?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT).map_err(|error| {
        uncertain(
            method,
            Error::http(
                502,
                format!("OfficeAce 响应读取失败：{}", clean(&error.message, credential)),
            ),
        )
    })?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let parsed = serde_json::from_str::<Value>(&text).ok();
    let payload = parsed.as_ref().unwrap_or(&Value::Null);
    if let Some(error) = response_error(status, payload, credential) {
        return Err(if status >= 500 || status == 408 {
            uncertain(method, error)
        } else {
            error
        });
    }
    // 协议确认那一发上游回**空体 + 2xx**（实测），空体不是"解析失败"
    if text.trim().is_empty() && method == "POST" && url.ends_with("/v1/agreement") {
        return Ok(Value::Null);
    }
    parsed.ok_or_else(|| {
        uncertain(
            method,
            Error::http(502, "OfficeAce 接口响应不是有效 JSON，请查询实际状态后再操作"),
        )
    })
}

/// 把一个响应判成错误（`None` = 成功）。
///
/// ── 判据不是只有状态码 ──────────────────────────────────────
/// 本家的上游会把失败包装成 `HTTP 200 + {error_code, error_msg}`（APIG 那一层），
/// 也会用 `{success:false}` / `{status:"FAILED"}` 表达。三种都认，否则「开通失败」
/// 会被当成成功继续往下走。
///
/// ── 过期判定的两段 ──────────────────────────────────────────
/// `APIG.0307` 单独成判（它就是「security token 过期」那条）；其余三个码要配合
/// 文案里的过期措辞 —— 只看码会把「权限不足」误判成「过期」，然后去续期一个
/// 根本不需要续的凭据（续期是**一次性**的，白花一次 refresh token）。
pub fn response_error(status: u16, payload: &Value, credential: &OfficeAceCredential) -> Option<Error> {
    let code = payload.get("error_code").and_then(Value::as_str).unwrap_or("");
    let detail = ["error_msg", "error_message", "failed_reason", "message"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
        .unwrap_or("");
    let failed = !(200..300).contains(&status)
        || !matches!(code, "" | "0" | "200")
        || payload.get("success").and_then(Value::as_bool) == Some(false)
        || payload.get("status").and_then(Value::as_str) == Some("FAILED");
    if !failed {
        return None;
    }
    let lower = detail.to_ascii_lowercase();
    let expired = code == "APIG.0307"
        || matches!(code, "APIG.0602" | "APIG.1002" | "APIG.0301")
            && [
                "security token has expired",
                "access token is expired",
                "token expires",
                "token has expired",
                "token expired",
            ]
            .iter()
            .any(|marker| lower.contains(marker));
    let reason = if expired {
        "OfficeAce 临时凭证已过期，需要刷新登录凭证"
    } else if status == 403 {
        "OfficeAce 拒绝访问，请检查服务开通、账号权限或实名认证；这不代表凭证过期"
    } else if status == 401 {
        "OfficeAce 身份校验失败，请检查登录授权或请求签名；尚不能确认凭证过期"
    } else {
        "OfficeAce 接口拒绝了请求"
    };
    let mut message = format!("{reason}（HTTP {status}）");
    for part in [code, detail].into_iter().filter(|part| !part.is_empty()) {
        message.push_str(&format!("：{}", clean(part, credential)));
    }
    let error_status = if expired {
        401
    } else if (200..300).contains(&status) {
        502
    } else {
        status
    };
    let error = Error::http(error_status, message);
    Some(if expired {
        error.with_code(CONTROL_TOKEN_EXPIRED)
    } else {
        error
    })
}

/// POST 的失败一律打上「结果不确定」标记（GET 重放无害，POST 可能重复下单）。
fn uncertain(method: &str, error: Error) -> Error {
    if method == "POST" {
        error.with_code(RESULT_UNCERTAIN)
    } else {
        error
    }
}

/// 把签名算出的头集合转成 `http::open` 要的对象形态。
pub fn header_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// 文案脱敏：抹掉五个凭据材料、折掉空白、截 240 字符。
pub fn clean(text: &str, credential: &OfficeAceCredential) -> String {
    let mut value = text.to_string();
    for secret in [
        &credential.access_key_id,
        &credential.secret_access_key,
        &credential.security_token,
        &credential.model_app_key,
        &credential.model_app_secret,
    ]
    .into_iter()
    .filter(|secret| !secret.is_empty())
    {
        value = value.replace(secret.as_str(), "[已隐藏]");
    }
    util::truncate_chars(
        &value.split_whitespace().collect::<Vec<_>>().join(" "),
        240,
    )
}
