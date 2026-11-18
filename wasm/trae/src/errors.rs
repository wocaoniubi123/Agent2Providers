//! Trae HTTP 与流内业务错误分类。
//!
//! 4001 / 4023 表示模型与通道不匹配；1005 也可能只限当前通道。
//! 这些错误仅首个内容帧之前尝试同模型的其它目录路由，耗尽后才分类限额。
//! 401 / 1001 / 20101 是凭据失效，4011 是限流，不能当成模型路由失败。
//!
//! ── 与网关契约的那一层要窄 ──────────────────────────────────
//! 网关的 `upstream::provider_loop` 只认识四档处置（限额换号 / 凭证刷新 /
//! 内容拦截降级 / 终态透传），多出来的分类会**静默落进 Fatal**。所以
//! `classify` 只把本家的 `ErrorKind` 翻成那四档，不发明第五档。

use agent2api_wasm_sdk::{json, Error, Value};

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）。
const CONTENT_PATTERNS: [&str; 3] = [
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 客户端可见的**内容拦截提示**：附在 `上游返回 {status}: {上游原文}` 之后。
/// 与网关 `CONTENT_BLOCK_HINT` 逐字一致 —— 两处文案分叉会让同一件事在
/// 「内置家」与「插件家」的账号上呈现不同措辞。
pub const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；若为对话内容本身触发审核，请调整后重试";

/// 错误类别。字符串形态与参考实现 `ErrKind.String()` 逐字一致 ——
/// 对拍报告与日志里两边要能直接对照。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// 成功
    None,
    /// 1005 / 4008：计划或模型配额不足
    PlanLimit,
    /// 429 / 9074：软限流
    SoftRate,
    /// 401：会话失效
    SessionDead,
    /// 404
    NotFound,
    /// 5xx
    Server,
    /// 其它 4xx
    Client,
    /// 413 或过大文案：请求级问题，**不冷却账号**
    InputTooLarge,
    /// 流内 4001：模型在当前 function 通道不可用，请求级、**不冷却也不累计**
    ModelUnavailable,
}

impl ErrorKind {
    /// 分类名（日志与排障用）。
    ///
    /// `#[allow(dead_code)]`：本家当前的日志没有一处直接打这个字符串。留着它是
    /// 因为**它是分类表的自述**（新增一档时不会漏），下一批要接的请求日志会用。
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PlanLimit => "plan_limit",
            Self::SoftRate => "soft_rate",
            Self::SessionDead => "session_dead",
            Self::NotFound => "not_found",
            Self::Server => "server",
            Self::Client => "client",
            Self::InputTooLarge => "input_too_large",
            Self::ModelUnavailable => "model_unavailable",
        }
    }
}

/// 「输入过大」的子串词表（大小写不敏感；中文原样匹配）。
///
/// 这条判定的意义不是文案好看，而是**别冷却健康账号**：同一个超大 body
/// 换任何账号都会被拒，把它算成账号错误会连着拖垮整条链。
const INPUT_TOO_LARGE_MARKERS: [&str; 12] = [
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
];

pub fn msg_indicates_input_too_large(message: &str) -> bool {
    let lower = message.to_lowercase();
    INPUT_TOO_LARGE_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// 流内业务码里"配额/计划不足"的那几个（与非 2xx 路径共用同一张表，
/// 免得同一个码在两条路径上得到两种语义）。
pub const PLAN_LIMIT_CODES: [i64; 2] = [1005, 4008];

/// 模型在当前 function 不可用。
pub fn is_model_mismatch_code(code: i64) -> bool {
    matches!(code, 4001 | 4023)
}

/// 首包前遇到这些错误时换同模型的下一条目录路由。
pub fn retry_route(status: u16, code: Option<i64>, message: &str) -> bool {
    !matches!(status, 401 | 403 | 429)
        && code.is_some_and(|code| matches!(code, 4001 | 4023 | 1005))
        && !msg_indicates_input_too_large(message)
}

/// 流内 `event: error` 的分类。
///
/// 顺序敏感：`4001` 配 "prompt is too long…" 仍归**过大**（那是输入问题，
/// 不是通道问题），所以过大判定在通道判定之前。
pub fn stream_error_kind(code: i64, message: &str) -> ErrorKind {
    if PLAN_LIMIT_CODES.contains(&code) {
        return ErrorKind::PlanLimit;
    }
    if msg_indicates_input_too_large(message) {
        return ErrorKind::InputTooLarge;
    }
    if is_model_mismatch_code(code) {
        return ErrorKind::ModelUnavailable;
    }
    if matches!(code, 1001 | 401 | 20101) {
        return ErrorKind::SessionDead;
    }
    if code == 4011 {
        return ErrorKind::SoftRate;
    }
    ErrorKind::Client
}

/// HTTP 状态 + 响应体 → 分类。判定顺序照参考实现 v0.12.51 的注释：
/// 413 提到最顶，避免 body 恰好带 "1005…plan" 字样时被宽松的 plan 匹配
/// 劫持成长冷却。
pub fn classify(status: u16, body: &str) -> ErrorKind {
    let lower = body.to_lowercase();
    if status == 413 {
        return ErrorKind::InputTooLarge;
    }
    if body.contains("\"code\":1005") || (body.contains("1005") && lower.contains("plan")) {
        return ErrorKind::PlanLimit;
    }
    if body.contains("\"code\":4008") {
        return ErrorKind::PlanLimit;
    }
    if (400..500).contains(&status) && msg_indicates_input_too_large(body) {
        return ErrorKind::InputTooLarge;
    }
    if status == 401 {
        return ErrorKind::SessionDead;
    }
    if status == 429 {
        return ErrorKind::SoftRate;
    }
    if status == 404 {
        return ErrorKind::NotFound;
    }
    if status >= 500 {
        return ErrorKind::Server;
    }
    // 通道不可用放在账号级状态（401/429/404）之后兜底：鉴权失败永远优先按会话失效处理。
    if (400..500).contains(&status) && body.contains("\"code\":4001") {
        return ErrorKind::ModelUnavailable;
    }
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let (code, message) = parsed.as_ref().map(error_event_fields).unwrap_or_default();
    if matches!(code, 1001 | 401 | 20101) {
        return ErrorKind::SessionDead;
    }
    if code != 0 {
        let kind = stream_error_kind(code, &message);
        if kind != ErrorKind::Client {
            return kind;
        }
    }
    if status >= 400 {
        return ErrorKind::Client;
    }
    ErrorKind::None
}

/// 目录与流内错误兼容数字 / 数字字符串及外层 error 包裹。
pub fn error_event_fields(data: &Value) -> (i64, String) {
    let detail = data.get("error").filter(|error| error.is_object()).unwrap_or(data);
    let code = detail
        .get("code")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .unwrap_or(0);
    let message = detail
        .get("message")
        .or_else(|| detail.get("msg"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (code, message)
}

/// 错误类别 → 客户端可见状态码（映射表见 `forward.rs` 模块头）。
///
/// 额度与签到那条链复用同一张表：两处各写一份的话，"余额查询报 401 时
/// 上层该不该刷新重试"就会和转发侧悄悄不一致。
pub fn status_for(kind: ErrorKind) -> u16 {
    match kind {
        ErrorKind::SessionDead => 401,
        ErrorKind::SoftRate | ErrorKind::PlanLimit => 429,
        ErrorKind::InputTooLarge => 413,
        ErrorKind::ModelUnavailable => 404,
        ErrorKind::NotFound => 404,
        _ => 502,
    }
}

/// 是否命中内容策略拦截的文案特征。
pub fn matched_content_block(status: u16, body: &Value) -> bool {
    if status < 400 {
        return false;
    }
    let Some(message) = body.get("message").and_then(Value::as_str) else {
        return false;
    };
    let lowered = message.to_lowercase();
    CONTENT_PATTERNS.iter().any(|pattern| lowered.contains(pattern))
}

/// 错误体归一：网关可能把上游原文当字符串给，也可能给解析后的对象。
/// 判据要的是**结构**（`code` / `error` / `response`），所以字符串先尝试解析，
/// 解析不了就包成 `{"message": 原文}` —— 那时分类里的文案判定（过大 / 内容拦截）
/// 仍然生效，不会因为"这不是 JSON"把一次 413 误判成 502。
pub fn normalize_body(body: &Value) -> Value {
    match body {
        Value::String(text) => serde_json::from_str(text).unwrap_or_else(|_| json!({ "message": text })),
        Value::Null => json!({}),
        other => other.clone(),
    }
}

/// `classify` 方法的实现：`ErrorKind` → 网关认识的四档。
///
/// 一条本家特有的处置：`InputTooLarge` / `ModelUnavailable` / `NotFound` 都归到
/// `Fatal`（不冷却账号）。大输入与「模型在这个通道不可用」是**请求级**问题 ——
/// 同一份 body 换任何账号都会被拒，冷却健康账号只会把一次坏请求摊成
/// 一串被罚的账号。
pub fn class_of(status: u16, raw_body: &Value) -> Value {
    let error_body = normalize_body(raw_body);
    let detail = error_body
        .get("message")
        .or_else(|| error_body.get("msg"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误");
    let code = error_body
        .get("code")
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())))
        .filter(|code| *code != 0);
    let message = format!("上游返回 {status}: {detail}");
    // 判据吃的是**整份错误体**而不是那句文案：参考实现的分类靠在 body 里
    // 找 `"code":1005` / `"code":4008` 这类片段，只传文案就会漏掉这套判据。
    match classify(status, &error_body.to_string()) {
        ErrorKind::SessionDead => json!({ "kind": "token_expired", "message": message }),
        // 429 软限流与 1005/4008 计划限额都会换账号，区别只在冷却时长
        // （编排层按类别给时长，本家不提供 reset_at：上游没给可读的恢复时刻）。
        ErrorKind::SoftRate | ErrorKind::PlanLimit => json!({
            "kind": "quota_limited", "reset_at": Value::Null, "message": message,
            "upstream_code": code, "status": status
        }),
        // 只有落到「其它 4xx」这一档才交给跨家的内容拦截判定：本家的
        // 请求级分类（过大 / 通道不可用 / 404）必须优先，把它们误判成
        // 内容拦截会触发一次无意义的同账号重试。
        ErrorKind::Client if matched_content_block(status, &error_body) => json!({
            "kind": "content_blocked", "status": status,
            "message": format!("{message}{CONTENT_BLOCK_HINT}"), "upstream_code": code
        }),
        _ => json!({ "kind": "fatal", "status": status, "message": message, "upstream_code": code }),
    }
}

/// 200 响应里塞业务错误这件事，在网关眼里要怎么判。
///
/// 上游把额度/凭证类失败做成 HTTP 200 + `event: error`（1005 / 4008 / 4001），
/// 所以只看状态码会把"成功但没话"当成成功。判据与 native 的首包门同源：
/// 状态 >= 400，或载荷本身带着非零业务码 / `error` 对象。
pub fn is_error_response(status: u16, raw_body: &Value) -> bool {
    if status >= 400 {
        return true;
    }
    let body = normalize_body(raw_body);
    if body.get("error").is_some_and(|error| !error.is_null()) {
        return true;
    }
    let (code, message) = error_event_fields(&body);
    code != 0 && !message.is_empty() && !body.get("response").is_some_and(Value::is_string)
}

/// `error.policy`：这条错误要不要**停止重试**（同账号、同请求都不再发）。
///
/// 请求级错误（输入过大 / 通道不可用）换账号也不会变好，重发只是多烧一份额度，
/// 所以让编排层直接收摊。凭证与限额类相反：它们该刷新 / 换号，不能 stop。
pub fn policy(status: u16, raw_body: &Value) -> Value {
    let body = normalize_body(raw_body);
    let kind = classify(status, &body.to_string());
    let (code, message) = error_event_fields(&body);
    let request_level = matches!(kind, ErrorKind::InputTooLarge | ErrorKind::ModelUnavailable)
        || is_model_mismatch_code(code)
        || msg_indicates_input_too_large(&message);
    json!({ "stop": request_level })
}

/// 流内错误 → 一条对客户端可见的 `data: {...}` 事件（收尾用）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    let mut event = json!({
        "error": { "message": error.message, "status": status, "type": "upstream_error" }
    });
    if let Some(code) = &error.code {
        event["error"]["code"] = json!(code);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_order_matters() {
        // 413 压过 plan 文案：否则一次超大输入会被判成 12 小时冷却
        assert_eq!(classify(413, r#"{"code":1005,"plan":"x"}"#), ErrorKind::InputTooLarge);
        assert_eq!(classify(200, r#"{"code":1005}"#), ErrorKind::PlanLimit);
        assert_eq!(classify(400, r#"{"code":4008}"#), ErrorKind::PlanLimit);
        assert_eq!(classify(401, "{}"), ErrorKind::SessionDead);
        assert_eq!(classify(429, "{}"), ErrorKind::SoftRate);
        assert_eq!(classify(404, "{}"), ErrorKind::NotFound);
        assert_eq!(classify(500, "{}"), ErrorKind::Server);
        // 过大判定在通道判定之前：4001 + "prompt is too long" 仍是输入问题
        assert_eq!(
            classify(400, r#"{"code":4001,"message":"prompt is too long"}"#),
            ErrorKind::InputTooLarge
        );
        assert_eq!(classify(400, r#"{"code":4001}"#), ErrorKind::ModelUnavailable);
        assert_eq!(classify(400, r#"{"code":1,"message":"nope"}"#), ErrorKind::Client);
        // 1001 是凭据失效，不是通道问题
        assert_eq!(stream_error_kind(1001, ""), ErrorKind::SessionDead);
        assert_eq!(stream_error_kind(4011, ""), ErrorKind::SoftRate);
    }

    #[test]
    fn status_table() {
        assert_eq!(status_for(ErrorKind::SessionDead), 401);
        assert_eq!(status_for(ErrorKind::SoftRate), 429);
        assert_eq!(status_for(ErrorKind::PlanLimit), 429);
        assert_eq!(status_for(ErrorKind::InputTooLarge), 413);
        assert_eq!(status_for(ErrorKind::ModelUnavailable), 404);
        assert_eq!(status_for(ErrorKind::Server), 502);
    }

    #[test]
    fn class_of_covers_the_four_buckets() {
        assert_eq!(class_of(401, &json!({}))["kind"], "token_expired");
        assert_eq!(class_of(429, &json!({}))["kind"], "quota_limited");
        let blocked = class_of(400, &json!({"message": "blocked by security policy"}));
        assert_eq!(blocked["kind"], "content_blocked");
        assert!(blocked["message"].as_str().unwrap_or_default().contains("内容策略"));
        // 请求级错误归 Fatal（不冷却账号）
        assert_eq!(class_of(413, &json!({"message": "输入过长"}))["kind"], "fatal");
        assert_eq!(class_of(400, &json!({"code": 4001}))["kind"], "fatal");
    }

    #[test]
    fn error_response_detection() {
        assert!(is_error_response(500, &json!({})));
        assert!(is_error_response(200, &json!({"code": 1001, "message": "dead"})));
        assert!(!is_error_response(200, &json!({"code": 0, "message": ""})));
        // 字符串形态的错误体也要能认（上游原文直接透传上来时）
        assert!(is_error_response(200, &json!("{\"code\":1005,\"message\":\"quota\"}")));
    }

    #[test]
    fn policy_stops_only_request_level() {
        assert_eq!(policy(413, &json!({"message": "too long"}))["stop"], true);
        assert_eq!(policy(400, &json!({"code": 4001}))["stop"], true);
        assert_eq!(policy(401, &json!({}))["stop"], false);
        assert_eq!(policy(429, &json!({}))["stop"], false);
    }

    #[test]
    fn retry_route_skips_account_level_failures() {
        assert!(retry_route(400, Some(4001), "channel"));
        assert!(retry_route(400, Some(1005), "quota"));
        assert!(!retry_route(401, Some(4001), "channel"));
        assert!(!retry_route(429, Some(1005), "quota"));
        // 输入过大不换路由：换哪条通道都一样被拒
        assert!(!retry_route(400, Some(4001), "prompt is too long"));
    }
}
