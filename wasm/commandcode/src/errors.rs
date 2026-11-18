//! 上游错误分类：四档语义 + 内容拦截判定 + 重试建议。
//!
//! ── 分类口径（照抄 native `mod.rs::classify`，逐条注解保留）──────────
//!   - 400 / 422 → `Fatal(400)`（请求体非法，不重试；命中内容拦截文案时
//!     走共用的内容拦截判定 —— 那档不罚账号、换提示词补救）；
//!   - 401 / 403 → `TokenExpired`（编排层刷新一次（本家刷新必然拿回同一个
//!     key）再换账号）；
//!   - 402 → `QuotaLimited`（**下游状态码按 429**：规格明确「付费失败按限流」）；
//!   - 404 → `Fatal(404)`；429 → `QuotaLimited(429)`；
//!   - 500 / 502 → `Fatal(502)`；503 → `Fatal(503)`；其余 → `Fatal(502)`。
//!
//! ── 为什么 `is_error_response` 恒 false（与 native 默认一致）────────
//! 本家 **HTTP 恒 200**：认证失败 / 限流 / 余额不足都在流内 `{"type":"error"}`
//! 表达，`4xx/5xx` 只出现在真正的网关层故障上。而且正常响应也可能标
//! `application/json`（NDJSON 的常见 content-type），按 content-type 判错会把
//! **好流打成错误**。所以这一位保持 native 的默认值 false；真正的内容拦截判定
//! 在 [`classify`] 里（`400/422` + 逐字文案特征 → `content_blocked`）。
//! 另外：会话式通道下网关**不会调用**这一位（它不读上游响应，见 `chat.rs`），
//! 保留它只是为了方法表完整。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Value};

/// 内容拦截的文案特征（全部小写；匹配前把上游文案转小写）
///
/// ── 为什么这份规则在插件里重复了一份 ──────────────────────────
/// 网关的 `providers::content_block` 是**网关内部**模块，插件看不到。
/// 这段规则本身是「上游侧知识」，按分层约定本就属于 provider —— 搬过来
/// 是归位，不是复制。
const CONTENT_BLOCK_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 内容拦截的提示文案（附在上游原文之后，给用户两条可执行的路）
const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 上游错误说明（`message` 优先，缺失时给兜底文案）
pub fn message_of(body: &Value) -> String {
    body.get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误")
        .to_string()
}

/// 上游错误码（`code`；字符串数字也认）
pub fn code_of(body: &Value) -> Option<i64> {
    body.get("code").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
    })
}

/// 命中内容拦截文案 → `ContentBlocked`（并补提示），否则 → `Fatal`
fn content_or_fatal(status: u16, body: &Value, message: String, code: Option<i64>) -> Value {
    let matched = status >= 400
        && body
            .get("message")
            .and_then(Value::as_str)
            .map(|text| {
                let lowered = text.to_lowercase();
                CONTENT_BLOCK_PATTERNS
                    .iter()
                    .any(|pattern| lowered.contains(pattern))
            })
            .unwrap_or(false);
    if matched {
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

/// 上游错误 → 四档分类（`{kind, status, message, reset_at, upstream_code}`）。
///
/// 形状与网关 `proto::ErrorClass` 的序列化形态逐字一致（internally tagged，
/// `kind` 是判别键）：网关按 `kind` 选处置，其余字段进日志与限额事件。
pub fn classify(status: u16, body: &Value) -> Value {
    let raw = message_of(body);
    let message = format!("上游返回 {status}: {raw}");
    let code = code_of(body);
    match status {
        400 | 422 => content_or_fatal(400, body, message, code),
        401 | 403 => json!({
            "kind": "token_expired",
            "status": 401,
            "message": message,
            "reset_at": Value::Null,
            "upstream_code": Value::Null,
        }),
        402 => json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": format!(
                "{message}（余额 / 套餐不足：请在 commandcode.ai 充值或换一个账号，本网关按限流处理）"
            ),
            "upstream_code": code,
            // 规格的有意映射：402 → 下游 429
            "status": 429,
        }),
        429 => json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": code,
            "status": 429,
        }),
        404 => json!({
            "kind": "fatal",
            "status": 404,
            "message": message,
            "upstream_code": code,
        }),
        503 => json!({
            "kind": "fatal",
            "status": 503,
            "message": message,
            "upstream_code": code,
        }),
        // 500 / 502 与未列出的一切 → 502（规格的兜底）
        _ => json!({
            "kind": "fatal",
            "status": 502,
            "message": message,
            "upstream_code": code,
        }),
    }
}

/// 分类结果 → SDK 错误（流式转发路径用：插件自己发的请求，宿主看不到 body，
/// 所以必须由插件先分类再抛）。
pub fn http_error(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let message = class["message"]
        .as_str()
        .unwrap_or("Command Code 上游错误")
        .to_string();
    let kind = class["kind"].as_str().unwrap_or("fatal").to_string();
    let mapped = class["status"]
        .as_i64()
        .or_else(|| class["status"].as_u64().map(|value| value as i64))
        .unwrap_or(502);
    let mut error = Error::http(u16::try_from(mapped.max(400)).unwrap_or(502), message)
        .with_code(kind)
        .with_reset(class["reset_at"].as_i64());
    error.upstream_code = class["upstream_code"].as_i64();
    error
}

/// 错误分类的 kind → OpenAI 口径的 `error.type`（流内错误帧用）。
///
/// NDJSON 折叠层（`ndjson.rs`）按上游状态码映射更细的类型；这一条只服务于
/// **已经变成 SDK 错误之后**再补一帧的场景（正文已下发、随后断流）。
pub fn frame_type(kind: &str) -> &'static str {
    match kind {
        "quota_limited" => "rate_limit_error",
        "token_expired" => "authentication_error",
        "content_blocked" => "invalid_request_error",
        _ => "upstream_error",
    }
}

/// 内容拦截 / 已下发后的中断：给客户端一条错误帧。
///
/// 与 WorkBuddy / AtomCode 同形：`{error:{message,status,type}}`。
/// `type` 按 [`frame_type`] 取，`status` 是**额外**字段（帧形态是网关聚合器
/// 认的超集，多这一个键让流式客户端与抓包能直接看出上游报的是 429 还是 503）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    let kind = error.code.as_deref().unwrap_or("fatal");
    json!({
        "error": {
            "message": error.message,
            "status": status,
            "type": frame_type(kind),
        },
    })
}

/// 上游响应是否「其实是错误」—— 恒 false（理由见模块头）。
pub fn is_error_response(_status: u16, _headers: &Value) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_are_token_expired() {
        assert_eq!(classify(401, &json!({}))["kind"], "token_expired");
        assert_eq!(classify(403, &json!({}))["kind"], "token_expired");
        assert_eq!(classify(401, &json!({}))["status"], json!(401));
    }

    #[test]
    fn payment_failure_becomes_a_429() {
        let class = classify(402, &json!({ "message": "insufficient credits", "code": 40201 }));
        assert_eq!(class["kind"], "quota_limited");
        // 规格的有意映射：402 → 下游 429
        assert_eq!(class["status"], json!(429));
        assert!(class["message"]
            .as_str()
            .unwrap_or("")
            .contains("余额 / 套餐不足"));
        assert_eq!(class["upstream_code"], json!(40201));
    }

    #[test]
    fn rate_limit_stays_429() {
        let class = classify(429, &json!({ "message": "too many requests" }));
        assert_eq!(class["kind"], "quota_limited");
        assert_eq!(class["status"], json!(429));
        assert_eq!(class["reset_at"], Value::Null);
    }

    #[test]
    fn security_policy_text_is_content_blocked() {
        let body = json!({ "message": "Illegal API invocation from an unapproved channel" });
        let class = classify(400, &body);
        assert_eq!(class["kind"], "content_blocked");
        assert!(class["message"]
            .as_str()
            .unwrap_or("")
            .contains("内容被上游内容策略拒绝"));
        // 200 的正文不算（判据要求 status >= 400）
        assert_eq!(
            classify(200, &json!({ "message": "blocked by security policy" }))["kind"],
            "fatal"
        );
    }

    #[test]
    fn unlisted_statuses_fall_back_to_502() {
        for status in [500u16, 502, 418, 0] {
            let class = classify(status, &json!({}));
            assert_eq!(class["kind"], "fatal");
            assert_eq!(class["status"], json!(502));
        }
        assert_eq!(classify(404, &json!({}))["status"], json!(404));
        assert_eq!(classify(503, &json!({}))["status"], json!(503));
        assert_eq!(classify(422, &json!({}))["status"], json!(400));
    }

    #[test]
    fn http_error_carries_the_kind_and_reset() {
        let error = http_error(429, &json!({ "message": "slow down", "code": 7 }));
        assert_eq!(error.status, Some(429));
        assert_eq!(error.code.as_deref(), Some("quota_limited"));
        assert_eq!(error.upstream_code, Some(7));
        assert!(error.reset_at.is_none());
        // 402 也必须是 429（下游按限流退避）
        let paid = http_error(402, &json!({}));
        assert_eq!(paid.status, Some(429));
        assert_eq!(paid.code.as_deref(), Some("quota_limited"));
    }

    #[test]
    fn error_frames_use_openai_types() {
        let error = http_error(401, &json!({}));
        let frame = error_event(&error);
        assert_eq!(frame["error"]["type"], json!("authentication_error"));
        assert_eq!(frame["error"]["status"], json!(401));
        let quota = error_event(&http_error(429, &json!({})));
        assert_eq!(quota["error"]["type"], json!("rate_limit_error"));
        let fatal = error_event(&http_error(503, &json!({})));
        assert_eq!(fatal["error"]["type"], json!("upstream_error"));
        assert_eq!(fatal["error"]["status"], json!(503));
    }

    #[test]
    fn error_response_detection_stays_false() {
        assert!(!is_error_response(500, &json!({})));
        assert!(!is_error_response(200, &json!({ "content-type": "application/json" })));
    }
}
