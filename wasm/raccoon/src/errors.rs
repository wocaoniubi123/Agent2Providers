//! 1.1.5 的 accountRequests 与 Box-Agent 区分鉴权、积分不足和短期限流；
//! 内容策略拦截沿用共用规则（native 侧 `content_block.rs`）。
//!
//! ── 为什么内容拦截单独成一段 ────────────────────────────────
//! 上游按**逐字精确匹配**审核（不是语义审核），客户端注入的 system 模板句
//! 命中即整单拦截。此时账号本身健康：余额够、没限流、session 没死 —— 换账号
//! 再试是白扔另一个账号的额度（同一份 body 换谁发都会被拦）。所以分类结果
//! `content_blocked` 在网关编排层**不罚账号**，而是走「降级到中性提示词后
//! 同账号重试一次」。

use agent2api_wasm_sdk::{json, Error, Value};

fn code_value(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

/// 上游业务码（`code` 或 `error.code`，数字与字符串两种形态都认）。
pub fn business_code(body: &Value) -> Option<i64> {
    body.get("code")
        .and_then(code_value)
        .or_else(|| body.pointer("/error/code").and_then(code_value))
}

fn code_text(body: &Value) -> String {
    body.get("code")
        .or_else(|| body.pointer("/error/code"))
        .map(crate::jwt::js_text)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// 上游错误说明（按 `message` → `msg` → `error.message` → `error` 的顺序取）。
pub fn message(body: &Value) -> String {
    ["/message", "/msg", "/error/message", "/error"]
        .iter()
        .find_map(|path| {
            body.pointer(path)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "上游未返回错误说明".to_string())
}

/// 是不是「登录态被上游拒绝」（业务码 200003 / 200009 或 `authorization_verify_error`）。
pub fn token_expired(body: &Value) -> bool {
    matches!(business_code(body), Some(200_003 | 200_009))
        || code_text(body) == "authorization_verify_error"
        || message(body).contains("authorization_verify_error")
}

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）
const CONTENT_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 客户端可见的**内容拦截提示**：附在「上游返回 {status}: {上游原文}」之后。
///
/// 与网关 `CONTENT_BLOCK_HINT` 逐字一致 —— 两处文案分叉会让同一件事在
/// 「内置家」与「插件家」的账号上呈现不同措辞。
pub const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 是否命中内容策略拦截的文案特征（状态码只要求 >= 400）。
fn content_matched(status: u16, body: &Value) -> bool {
    if status < 400 {
        return false;
    }
    let Some(message) = body.get("message").and_then(Value::as_str) else {
        return false;
    };
    let lowered = message.to_lowercase();
    CONTENT_PATTERNS
        .iter()
        .any(|pattern| lowered.contains(pattern))
}

/// 上游错误 → 四档分类（`{kind, status, message, reset_at, upstream_code}`）。
///
/// 形状与 atomcode 的 `errors::classify` 一致：网关按 `kind` 选处置，
/// 其余字段进日志与限额事件。
pub fn classify(status: u16, body: &Value) -> Value {
    let raw = message(body);
    let message = format!("上游返回 {status}: {raw}");
    if status == 401 || token_expired(body) {
        return json!({
            "kind": "token_expired",
            "status": 401,
            "message": message,
            "reset_at": Value::Null,
            "upstream_code": Value::Null,
        });
    }
    let code = code_text(body);
    let lowered = raw.to_ascii_lowercase();
    let quota = business_code(body) == Some(1_000_007)
        || ["insufficient_points", "insufficient_quota", "arrearage"].contains(&code.as_str())
        || [
            "insufficient_points",
            "insufficient quota",
            "积分不足",
            "余额不足",
            "欠费",
        ]
        .iter()
        .any(|marker| lowered.contains(marker));
    if quota || status == 429 {
        // 短期限流（rate limit）与「额度真没了」同属 quota_limited，但短期限流
        // 有一个可恢复时刻（1 分钟后重试）。判据：不是额度问题、且文案/业务码
        // 指向频率限制 —— 与 native 的 transient 判据逐条相同。
        let transient = !quota
            && (matches!(
                code.as_str(),
                "rate_limit" | "rate_limit_exceeded" | "user_model_rate_limited"
            ) || [
                "rate limit",
                "too many requests",
                "请求过于频繁",
                "频率",
                "rpm",
                "tpm",
            ]
            .iter()
            .any(|marker| lowered.contains(marker)));
        return json!({
            "kind": "quota_limited",
            "status": status,
            "message": message,
            "reset_at": if transient { json!(agent2api_wasm_sdk::now() + 60_000) } else { Value::Null },
            "upstream_code": business_code(body),
        });
    }
    if content_matched(status, body) {
        return json!({
            "kind": "content_blocked",
            "status": status,
            "message": format!("{message}{CONTENT_BLOCK_HINT}"),
            "reset_at": Value::Null,
            "upstream_code": business_code(body),
        });
    }
    json!({
        "kind": "fatal",
        "status": status,
        "message": message,
        "reset_at": Value::Null,
        "upstream_code": business_code(body),
    })
}

/// 分类结果 → SDK 错误（流式转发路径用：插件自己发的请求，宿主看不到 body，
/// 所以必须由插件先分类再抛）。
pub fn http_error(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let message = class["message"].as_str().unwrap_or("小浣熊上游错误").to_string();
    let kind = class["kind"].as_str().unwrap_or("fatal").to_string();
    let mapped = class["status"].as_u64().unwrap_or(502) as u16;
    let mut error = Error::http(mapped, message).with_code(kind);
    error.upstream_code = class["upstream_code"].as_i64();
    error.reset_at = class["reset_at"].as_i64();
    error
}

/// 已经下发内容之后只报告中断（网关据此结束这一条流）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({ "error": { "message": error.message, "status": status, "type": "upstream_error" } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_are_token_expired() {
        // 状态码 401
        assert_eq!(classify(401, &json!({}))["kind"], "token_expired");
        // 业务码 200003 / 200009（HTTP 200 也算）
        assert_eq!(classify(200, &json!({ "code": 200_003 }))["kind"], "token_expired");
        assert_eq!(classify(200, &json!({ "code": "200009" }))["kind"], "token_expired");
        // 业务码藏在 error.code 里
        assert_eq!(
            classify(200, &json!({ "error": { "code": "authorization_verify_error" } }))["kind"],
            "token_expired"
        );
    }

    #[test]
    fn quota_and_short_rate_limit_both_rotate() {
        // 积分不足（业务码 1000007）→ 额度问题，没有可恢复时刻
        let class = classify(200, &json!({ "code": 1_000_007 }));
        assert_eq!(class["kind"], "quota_limited");
        assert!(class["reset_at"].is_null());
        // 纯限流（429 + rate limit 文案）→ 也给 quota_limited，但带 1 分钟后的恢复时刻
        let class = classify(429, &json!({ "message": "too many requests" }));
        assert_eq!(class["kind"], "quota_limited");
        assert!(class["reset_at"].as_i64().is_some_and(|at| at > 0));
        // 文案里的「积分不足」同样算额度
        assert_eq!(
            classify(400, &json!({ "message": "当前账号积分不足" }))["kind"],
            "quota_limited"
        );
    }

    #[test]
    fn security_policy_rejections_are_content_blocked() {
        let class = classify(
            400,
            &json!({ "message": "blocked by security policy (rule 11-128)" }),
        );
        assert_eq!(class["kind"], "content_blocked");
        // 提示必须带上（两处文案分叉会让同一件事在插件家与内置家措辞不同）
        let message = class["message"].as_str().unwrap_or("");
        assert!(message.contains("内容被上游内容策略拒绝"), "{message}");
        // 200 的正文不算内容拦截（判据要求 status >= 400）
        assert_eq!(
            classify(200, &json!({ "message": "blocked by security policy" }))["kind"],
            "fatal"
        );
    }

    #[test]
    fn everything_else_is_fatal_with_upstream_code() {
        let class = classify(500, &json!({ "code": 12345, "message": "内部错误" }));
        assert_eq!(class["kind"], "fatal");
        assert_eq!(class["status"], 500);
        assert_eq!(class["upstream_code"], 12345);
    }

    #[test]
    fn http_error_carries_classification() {
        let error = http_error(401, &json!({}));
        assert_eq!(error.status, Some(401));
        assert_eq!(error.code.as_deref(), Some("token_expired"));
        let quota = http_error(429, &json!({ "code": 1_000_007 }));
        assert_eq!(quota.status, Some(429));
        assert_eq!(quota.upstream_code, Some(1_000_007));
    }
}
