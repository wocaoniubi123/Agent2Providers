//! Loomy 上游错误的分类：业务码 / 内容策略拦截 / 登录失效 / 限额。
//!
//! ── 为什么这些判据必须与 native 逐字一致 ──────────────────────
//! 分类结果直接决定主程序怎么处置：`token_expired` 落 `needsRelogin`、
//! `quota_limited` 换账号、`content_blocked` 不罚账号只换提示词、`fatal` 原样
//! 透传。判错一档的症状是具体的：限额被当 fatal → 账号永不轮换；凭证过期被当
//! fatal → 用户看到 401。所以本文件的表与文案都照 native 搬，不自行改写。
//!
//! ── 本家哪种响应「其实是错误」────────────────────────────────
//! 网关向上游恒请求流式（`stream: true`），所以 HTTP 200 + `application/json`
//! 是**业务拒绝**而不是 SSE —— 不能当流吞掉（见 [`is_error_response`]）。

use agent2api_wasm_sdk::{json, Error, Value};

use super::client;

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）
const CONTENT_BLOCK_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 内容策略拦截的提示（与网关 `content_block::CONTENT_BLOCK_HINT` 逐字一致）
const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 从响应头对象里取 `content-type`（键名大小写不敏感）。
fn content_type(headers: &Value) -> String {
    headers
        .as_object()
        .and_then(|object| {
            object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone())
        })
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_array().and_then(|items| items.first()).and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_default()
}

/// 上游这一份响应是不是「其实是错误」（native `Provider::is_error_response` 的移植）。
///
/// 非 2xx 一律算；HTTP 200 但 `content-type` 是 JSON 也算 —— 本家恒请求流式，
/// 200 的 JSON 信封只可能是业务拒绝。
pub fn is_error_response(status: u16, headers: &Value) -> bool {
    if !(200..300).contains(&status) {
        return true;
    }
    let raw = content_type(headers);
    let mime = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime == "application/json" || mime.ends_with("+json")
}

/// 分类结果（与 `proto::ErrorClass` 的 serde 形状逐字段一致）。
///
/// 返回 JSON 而不是强类型：Wasm 侧的 `classify` 是**字符串方法名 + JSON**，
/// 由主程序反序列化成它自己的枚举。
pub fn classify(status: u16, body: &Value) -> Value {
    let raw = client::upstream_message(body);
    let message = if raw.is_empty() {
        format!("上游返回 {status}：Loomy 未返回有效的流式响应")
    } else {
        format!("上游返回 {status}: {raw}")
    };
    let body_code = client::business_code(body);
    let code = body_code.parse::<i64>().ok();
    let authentication_error =
        body.pointer("/error/type").and_then(Value::as_str) == Some("authentication_error");
    if status == 401 || client::is_auth_error_code(&body_code) || authentication_error {
        return json!({ "kind": "token_expired", "message": message });
    }
    if status == 429 {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": code,
            "status": 429,
        });
    }
    // HTTP 2xx 走到这里说明上游回的是业务失败：状态码归 502（网关的既有口径）
    let status = if (200..300).contains(&status) { 502 } else { status };
    let blocked = status >= 400 && {
        let lowered = client::upstream_message(body).to_lowercase();
        CONTENT_BLOCK_PATTERNS
            .iter()
            .any(|pattern| lowered.contains(pattern))
    };
    if blocked {
        json!({
            "kind": "content_blocked",
            "status": status,
            "message": format!("{message}{CONTENT_BLOCK_HINT}"),
            "upstream_code": code,
        })
    } else {
        json!({
            "kind": "fatal",
            "status": status,
            "message": message,
            "upstream_code": code,
        })
    }
}

/// 把一次上游失败翻译成插件错误（`classify` 的同一套判据，附加错误码）。
pub fn http_error(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let kind = class["kind"].as_str().unwrap_or("fatal");
    let message = class["message"]
        .as_str()
        .unwrap_or("Loomy 上游请求未成功");
    let upstream_code = class["upstream_code"].as_i64();
    let mut error = match kind {
        "token_expired" => Error::http(401, message),
        "quota_limited" => Error::http(429, message).with_reset(class["reset_at"].as_i64()),
        _ => Error::http(
            class["status"]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .unwrap_or(502),
            message,
        ),
    };
    error.code = Some(
        match kind {
            "token_expired" => "loomy_token_expired",
            "quota_limited" => "loomy_quota_limited",
            "content_blocked" => "content_filter",
            _ => "loomy_upstream",
        }
        .to_string(),
    );
    error.upstream_code = upstream_code;
    error
}

#[cfg(test)]
mod tests {
    use super::{classify, is_error_response};
    use agent2api_wasm_sdk::{json, Value};

    #[test]
    fn auth_codes_and_401_become_token_expired() {
        for (status, body) in [
            (401, json!({ "desc": "unauthorized" })),
            (200, json!({ "code": "020002", "desc": "登录态失效" })),
            (200, json!({ "code": "100002" })),
            (400, json!({ "error": { "type": "authentication_error", "message": "bad" } })),
        ] {
            let class = classify(status, &body);
            assert_eq!(class["kind"], Value::String("token_expired".into()), "漏判: {status} {body}");
        }
    }

    #[test]
    fn rate_limit_and_business_failure_keep_their_classes() {
        let limited = classify(429, &json!({ "code": "999999", "desc": "too many" }));
        assert_eq!(limited["kind"], Value::String("quota_limited".into()));
        assert_eq!(limited["status"], Value::from(429));

        // HTTP 200 + 业务失败：状态码归 502（网关既有口径），分类是 fatal
        let failed = classify(200, &json!({ "code": "500000", "desc": "参数错误" }));
        assert_eq!(failed["kind"], Value::String("fatal".into()));
        assert_eq!(failed["status"], Value::from(502));
        assert_eq!(failed["upstream_code"], Value::from(500000));

        // 完全没有文案时给出统一的兜底话术
        let empty = classify(502, &Value::Null);
        assert!(empty["message"]
            .as_str()
            .is_some_and(|text| text.contains("未返回有效的流式响应")));
    }

    #[test]
    fn content_policy_markers_become_content_blocked() {
        for marker in [
            "blocked by security policy",
            "unapproved channel",
            "illegal api invocation",
        ] {
            let class = classify(400, &json!({ "desc": marker }));
            assert_eq!(
                class["kind"],
                Value::String("content_blocked".into()),
                "漏判 {marker}"
            );
            assert!(class["message"]
                .as_str()
                .is_some_and(|text| text.contains("内容策略拒绝")));
        }
    }

    #[test]
    fn json_on_http_200_counts_as_error_response() {
        assert!(is_error_response(500, &json!({})));
        assert!(is_error_response(
            200,
            &json!({ "content-type": "application/json; charset=utf-8" })
        ));
        assert!(is_error_response(200, &json!({ "Content-Type": "application/problem+json" })));
        assert!(!is_error_response(
            200,
            &json!({ "content-type": "text/event-stream" })
        ));
        assert!(!is_error_response(200, &json!({})));
    }
}
