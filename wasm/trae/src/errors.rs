//! Trae正式业务错误：4001/4023仅通道路由不匹配；1005/4008限额；
//! 401/1001/20101失效；4011/9074软拒绝。只检查错误信封，绝不扫描回答正文。
//! 对外固定脱敏文案+数字业务码，不回上游完整响应或携带凭据的URL。

use super::util;
use agent2api_wasm_sdk::{json, Error, Value};

/// 给错误文案打一个诊断标签，**不动 `code` 与 `upstream_code`**。
///
/// 为什么不用 `with_code`：`code` 参与续期（`trae_session_expired`）与路由重试
/// （`route_retry` 读 `upstream_code`）的判断，改它会把正常流程改坏。
/// 标签只进 message，面板上看到 `[tag] 原文案`，用于区分「上游真拒绝」与
/// 「我们读错了出站分支」（2026-11-19 长上下文 502）。
///
/// 为什么用独立函数而不是扩展 trait：trait 方法在 wasm 优化后可能被内联到
/// 调用点之外，实测标签没出现在最终文案里；普通函数调用行为确定。
pub fn tag_error(mut error: Error, tag: &str) -> Error {
    error.message = format!("[{tag}] {}", error.message);
    error
}

pub fn code(value: &Value) -> Option<i64> {
    [
        value.pointer("/error/code"),
        value.pointer("/error/upstream_code"),
        value.get("code"),
        value.get("Code"),
        value.pointer("/ResponseMetadata/Error/Code"),
        value.pointer("/ResponseMetadata/Error/CodeN"),
        value.get("upstreamCode"),
    ]
    .into_iter()
    .flatten()
    .find_map(util::integer)
}

fn raw_message(value: &Value) -> &str {
    [
        value.pointer("/error/message"),
        value.get("message"),
        value.get("msg"),
        value.get("Message"),
        value.pointer("/ResponseMetadata/Error/Message"),
        value.get("__Message.error"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .find(|v| !v.is_empty())
    .unwrap_or("")
}

pub fn message(value: &Value) -> String {
    raw_message(value).to_ascii_lowercase()
}

pub fn failed(value: &Value) -> bool {
    code(value).is_some_and(|c| c != 0)
        || [value.get("code"), value.get("Code")]
            .into_iter()
            .flatten()
            .any(|v| !v.is_null() && util::integer(v).is_none())
        || value
            .get("error")
            .is_some_and(|v| !v.is_null() && *v != false && v.as_str() != Some(""))
        || value
            .pointer("/ResponseMetadata/Error")
            .is_some_and(|v| !v.is_null())
        || value["success"] == false
}

fn input_too_large(text: &str) -> bool {
    [
        "too long",
        "too many tokens",
        "context length",
        "maximum context",
        "context window",
        "request entity too large",
        "input too large",
        "输入过长",
        "内容过长",
        "上下文过长",
        "上下文长度",
        "超出模型上限",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

pub fn upstream(status: u16, body: &Value) -> Error {
    let c = code(body);
    let text = message(body);
    let meta_code = body
        .pointer("/ResponseMetadata/Error/Code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let marker = [
        body.get("providerCode"),
        body.pointer("/error/code"),
        body.get("code"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .find(|v| v.starts_with("trae_") || *v == "local_precondition")
    .unwrap_or("");
    let (status, marker, message) = if marker == "local_precondition" {
        (
            status.clamp(400, 599),
            "local_precondition",
            "Trae 当前操作缺少必要条件",
        )
    } else if marker == "trae_route_capability" {
        let detail = match raw_message(body) {
            "Trae 当前账号目录明确此模型不支持图片，请选择支持图片的模型" => {
                "Trae 当前账号目录明确此模型不支持图片，请选择支持图片的模型"
            }
            "Trae 当前账号目录未声明所选思考档位" => {
                "Trae 当前账号目录未声明所选思考档位"
            }
            _ => "Trae 当前账号目录不支持本次请求所需的模型能力",
        };
        (400, "trae_route_capability", detail)
    } else if status == 413 || marker == "trae_input_too_large" || input_too_large(&text) {
        (
            413,
            "trae_input_too_large",
            "Trae 请求超出模型上下文或输入长度限制",
        )
    } else if matches!(c, Some(20401 | 20405)) || marker == "trae_device_rejected" {
        (
            403,
            "trae_device_rejected",
            "Trae 设备绑定被拒绝或设备数已达上限，请在官方客户端确认",
        )
    } else if status == 401
        || matches!(c, Some(1001 | 401 | 20101))
        || marker == "trae_session_expired"
        || matches!(
            meta_code.as_str(),
            "unauthorized" | "invalidtoken" | "tokenexpired"
        )
        || text.contains("not able to authenticate")
        || text.contains("unable to authenticate")
        || text.contains("refresh token is invalid")
    {
        (
            401,
            "trae_session_expired",
            "Trae 登录凭据已被拒绝，需要续期或重新登录",
        )
    } else if matches!(c, Some(1005 | 4008)) || marker == "trae_plan_limit" {
        (429, "trae_plan_limit", "Trae 当前模型或套餐额度不足")
    } else if status == 429 || matches!(c, Some(4011 | 9074)) || marker == "trae_rate_limited" {
        (
            429,
            "trae_rate_limited",
            "Trae 暂时拒绝本次请求，请稍后手动重试",
        )
    } else if matches!(c, Some(4001 | 4023)) || marker == "trae_model_unavailable" {
        (
            404,
            "trae_model_unavailable",
            "Trae 当前目录通道不支持这个模型",
        )
    } else if c == Some(10101) {
        (
            400,
            "trae_client_mismatch",
            "Trae 续期凭据与登录应用归属不匹配",
        )
    } else if marker == "trae_content_blocked"
        || matches!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("content_filter" | "content_policy_violation")
        )
    {
        (403, "trae_content_blocked", "Trae 内容策略拒绝本次请求")
    } else {
        (
            if status >= 400 { status.min(599) } else { 502 },
            "trae_upstream",
            // 上下文过长时 Trae 不返回错误码，只回一条 progress_notice 后断流
            // （2026-11-19 实测：121 KB / 1.15 MB 的请求只换回 23 字节）。
            // 兜底文案因此补一句可操作的提示，不让用户以为是网络问题。
            "Trae 上游未接受本次请求（上下文过长时会被静默断流，可压缩会话后重试）",
        )
    };
    let mut error = Error::http(status, message).with_code(marker);
    error.upstream_code = c;
    if marker == "trae_session_expired" {
        error.credential_scope = Some("account".into());
    }
    error
}

pub fn expired() -> Error {
    upstream(401, &json!({ "code": 1001 }))
}

pub fn classify(status: u16, value: &Value) -> Value {
    let error = upstream(status, value);
    let kind = match error.code.as_deref() {
        Some("trae_session_expired") => "token_expired",
        Some("trae_plan_limit" | "trae_rate_limited") => "quota_limited",
        Some("trae_content_blocked") => "content_blocked",
        _ => "fatal",
    };
    // 这条出口返回的是 JSON 而不是 `Error`，宿主拿到 `message` 后直接当错误文案
    // 用 —— 所有 `tag_error` 在这里都不生效。把宿主给的 status、上游业务码、
    // 站点域名和响应片段拼进 message，才有希望看清流中途到底发生了什么。
    let mut body = value.clone();
    if body.to_string().len() > 200 {
        body = json!(body.to_string().chars().take(200).collect::<String>());
    }
    let message = format!("[trae_classify status={status} code={:?} body={body}] {}", 
        error.code, error.message);
    json!({ "kind": kind, "status": error.status, "message": message, "upstream_code": error.upstream_code, "reset_at": null })
}

pub fn transport(error: Error) -> Error {
    match error.code.as_deref() {
        Some("timeout") => Error::http(504, "Trae 请求超时").with_code("timeout"),
        Some("aborted") => Error::http(499, "Trae 请求已取消").with_code("aborted"),
        Some("forbidden") => {
            Error::http(403, "Trae 请求未获主程序授权").with_code("local_precondition")
        }
        _ => Error::http(502, "Trae 网络请求失败，请检查出口网络").with_code("trae_transport"),
    }
}

pub fn stream(error: &Error) -> Value {
    json!({ "error": { "message": error.message, "code": error.code, "upstream_code": error.upstream_code,
        "status": error.status.unwrap_or(502), "type": "upstream_error" } })
}

pub fn route_retry(error: &Error, original_status: u16) -> bool {
    !matches!(original_status, 401 | 403 | 429)
        && matches!(error.upstream_code, Some(4001 | 4023 | 1005))
        && error.code.as_deref() != Some("trae_input_too_large")
}

pub fn terminal_code(error: &Error) -> bool {
    error.status == Some(401)
        || error.status == Some(403)
        || error.status == Some(429)
        || error
            .code
            .as_deref()
            .is_some_and(|code| matches!(code, "local_precondition" | "aborted" | "timeout"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_capability_preserves_local_messages_and_code() {
        let img = classify(
            400,
            &json!({
                "providerCode": "trae_route_capability",
                "message": "Trae 当前账号目录明确此模型不支持图片，请选择支持图片的模型"
            }),
        );
        assert_eq!(img["kind"], json!("fatal"));
        assert_eq!(img["status"], json!(400));
        assert_eq!(
            img["message"],
            json!("Trae 当前账号目录明确此模型不支持图片，请选择支持图片的模型")
        );

        let fallback = upstream(
            400,
            &json!({ "providerCode": "trae_route_capability", "message": "raw secret text" }),
        );
        assert_eq!(fallback.code.as_deref(), Some("trae_route_capability"));
        assert_eq!(
            fallback.message,
            "Trae 当前账号目录不支持本次请求所需的模型能力"
        );
    }
}
