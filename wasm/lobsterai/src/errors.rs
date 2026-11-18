//! LobsterAI 的错误分类，以及**两种「成功状态下的失败」**的识别。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/errors.rs`。
//!
//! ── 判定顺序即优先级（别重排，`errors.go:55-94` 的原话）──────────
//! ```text
//!   1. HTTP 402              -> 余额耗尽（状态码最权威）
//!   2. 正文含余额耗尽关键词  -> 余额耗尽
//!   3. 正文含 40100 / 40101  -> 会话已死（只能重新登录）
//!   4. HTTP 429              -> 软限流
//!   5. HTTP 404              -> 上游偶发
//!   6. HTTP >= 500           -> 上游故障
//!   7. HTTP >= 400           -> 交共用内容拦截分类
//! ```
//! **为什么正文关键词要排在状态码之前（402 除外）**：实测上游用 **HTTP 400 +
//! 中文「积分不足」**表达余额耗尽（`errors.go:64-66`），只按状态码会把这类错误
//! 判成「可重试的客户端错误」，于是反复重试一个**永远不会成功**的账号。
//!
//! ── 映射到本仓的四档（这是本文件与 Go 唯一需要「翻译」的地方）──────
//! Go / TS 各有自己的类别名（hard-credit / soft-rate / session-dead / …），
//! 本仓的编排层只认四档（见 `ErrorClass` 的注释），所以：
//!   · **余额耗尽 → `QuotaLimited`**：它要做的事与 Go 的 `CoolHard` 逐字相同
//!     ——「标记冷却 + 换下一个账号」（另一个账号可能有额度）。归成 `Fatal`
//!     会把一个「该换号」的错误当成终态直接抛给用户。
//!   · **会话已死 → `TokenExpired`**：刷新后用同一账号重试一次；本家刷新被拒
//!     （40100 / 40101）时刷新本身会失败，编排层随即把它降级成可读错误。
//!   · **软限流 → `QuotaLimited`**（Go 的 `CoolSoft`，同款动作）。
//!   · **404 / 5xx → `Fatal`**（本仓没有「偶发 404 短冷却」这一档，如实透传）。
//!
//! ── 两种「HTTP 200 的假成功」────────────────────────────────
//!   1. **流内错误帧**：`HTTP 200` + SSE 正文是 `{"error":{"message":"…"}}`
//!      —— 额度耗尽正是以这个形态下发的（native 未实测，见下），换号循环若不认它，
//!      用户就会看到「一个账号用完出错、但池里还有账号也不切换」；
//!   2. **信封不变量**：`code:0` 配 `data:null` = 令牌已失效 —— 这一条在
//!      `oauth::unwrap_envelope` 里接上（把 `data:null` 判成 401）。
//!
//! ── ✅ native 的已知缺口在这里补上了 ─────────────────────────
//! native 的 `silent_failure_in_frame` 是「纯函数 + 测试，没有调用点」：逐帧
//! 出口由通用层持有，插件拿不到挂点。wasm 侧**流是插件自己读的**（`chat.rs`
//! 逐帧解析），所以「首包之前出现错误帧」这条现在真的接到了分类上 ——
//! 见 [`crate::chat`] 的 `Output::fail_before_head`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Value};

/// 余额耗尽关键词（中英双通道**必需**）。
///
/// 中英都要，是因为同一后端在不同场景下会返回中文或英文（实测两种都出现过，
/// `errors.go:40-42`）。中英比较策略：整串先转小写再比，中文小写后与自己相等
/// （冗余但无害，与 TS `lobsterai-errors.ts:111-113` 一致）。
///
/// ⚠️ **与 Go 的一处差异（如实记下）**：Go 的 `hardCreditMarkers`
/// （`errors.go:43-48`）**少了**「额度已用完」「升级套餐」两条，而 TS 原版
/// （`lobsterai-errors.ts:54-66`）有，并在注里说明它们是根据**真实报障**补上的
/// （额度耗尽的**实际文案**就是「免费额度已用完，请升级套餐」，早期表里只有
/// 「额度用尽」——「已用完」与「用尽」字面不同，于是这个最主要的失败模式被判成
/// 不换号）。本实现取**并集**：漏判这一个模式的代价（账号用完不切换）比多两条
/// 关键词的代价大得多。英文同类文案（`free quota` 等）一并保留。
pub const HARD_CREDIT_MARKERS: &[&str] = &[
    "insufficient credit",
    "no credit",
    "credit exhausted",
    "out of credit",
    "quota exceeded",
    "quota exhaust",
    "payment required",
    "credit not enough",
    "not enough credit",
    "freecreditsused",
    "free credits used",
    "free quota",
    "quota used up",
    "upgrade your plan",
    "upgrade to continue",
    "积分不足",
    "额度不足",
    "余额不足",
    "积分用完",
    "额度用尽",
    "没有积分",
    "积分耗尽",
    "额度已用完",
    "升级套餐",
];

/// 会话已死标记（`errors.go:51-53`）：刷新被拒的业务码，终态、重试无意义。
pub const SESSION_DEAD_MARKERS: &[&str] = &[
    "40100",
    "40101",
    "token rejected",
    "refresh token was rejected",
];

/// 会话已死的两个业务码（数值形态，归一化层会把它们填进 `code`）
const SESSION_DEAD_CODES: [i64; 2] = [40100, 40101];

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）。
///
/// 逐字照抄 native `content_block.rs`：上游按**逐字精确匹配**审核（不是语义
/// 审核），客户端注入的 system 模板句命中即整单拦截。此时账号本身健康 ——
/// 换账号再试是白扔另一个账号的额度（同一份 body 换谁发都会被拦）。
const CONTENT_BLOCK_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 客户端可见的**内容拦截提示**（与 native `content_block::CONTENT_BLOCK_HINT`
/// 逐字一致 —— 两处文案分叉会让同一件事在内置家与插件家呈现不同措辞）。
pub const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 正文（大小写不敏感）或原串里是否含余额耗尽关键词
pub fn mentions_hard_credit(text: &str) -> bool {
    markers_hit(text, HARD_CREDIT_MARKERS)
}

/// 正文里是否含会话已死标记（`40100` / `40101` 也是文本，所以按文本判）
pub fn mentions_session_dead(text: &str) -> bool {
    markers_hit(text, SESSION_DEAD_MARKERS)
}

/// 关键词命中（英文走小写比对、中文走原文比对，见 [`HARD_CREDIT_MARKERS`]）
fn markers_hit(text: &str, markers: &[&str]) -> bool {
    if text.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    markers
        .iter()
        .any(|marker| lower.contains(&marker.to_lowercase()) || text.contains(marker))
}

/// 从归一化后的错误体里取一行可读文案。
///
/// `message` 字段是归一化时留下的（`message` / `msg` / `error.message` 里第一个
/// 非空的），所以这里读字符串是对的，别改成只读结构字段。
pub fn message_of(error_body: &Value) -> String {
    error_body
        .get("message")
        .or_else(|| error_body.get("msg"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误")
        .to_string()
}

/// 关键词匹配的**全部原料**：归一化文案 + 整个体的原文序列化。
///
/// 两处都要：`message` 是归一化后的可读串（英文关键词多半在这里），而有些形态
/// （如 `code:40100` 与中文文案同时出现）只在原文里看得全。体最大 1 MiB 量级，
/// 拼接成本可忽略。
fn haystack(error_body: &Value) -> String {
    format!("{}\n{}", message_of(error_body), error_body)
}

/// 从归一化体里取业务码（数字与数字字符串都认）。
fn code_of(error_body: &Value) -> Option<i64> {
    if let Some(number) = error_body.get("code").and_then(Value::as_i64) {
        return Some(number);
    }
    error_body
        .get("code")
        .and_then(Value::as_str)
        .and_then(|text| text.trim().parse::<i64>().ok())
}

/// 内容策略拦截是否命中（状态码只要求 `>= 400`，文案大小写不敏感）。
fn content_blocked(status: u16, error_body: &Value) -> bool {
    if status < 400 {
        return false;
    }
    let Some(message) = error_body.get("message").and_then(Value::as_str) else {
        return false;
    };
    let lowered = message.to_lowercase();
    CONTENT_BLOCK_PATTERNS
        .iter()
        .any(|pattern| lowered.contains(pattern))
}

/// LobsterAI 上游错误的分类。
///
/// 返回的是 `ErrorClass` 的 serde 形状（`{kind, ...}`），网关按 `kind` 决定处置：
/// `quota_limited` / `token_expired` / `content_blocked` / `fatal`。
///
/// 判定顺序是契约（见模块头），别重排。
pub fn classify(status: u16, error_body: &Value) -> Value {
    let raw = message_of(error_body);
    let message = format!("上游返回 {status}: {raw}");
    let upstream_code = code_of(error_body);
    let text = haystack(error_body);

    // 1) 402：余额耗尽最直接的信号
    if status == 402 {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": format!("LobsterAI 积分不足（402）：{raw}"),
            "upstream_code": upstream_code,
            "status": 402,
        });
    }

    // 2) 正文关键词命中余额耗尽（**排在状态码之前**，见模块头）
    if mentions_hard_credit(&text) {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": format!("LobsterAI 积分不足：{raw}"),
            "upstream_code": upstream_code,
            // 上游常用 HTTP 400 表达额度耗尽；对外统一按 402 呈现（这一档的语义）
            "status": 402,
        });
    }

    // 3) 会话已死：40100 / 40101（数值码或文案），只能重新登录
    if upstream_code.is_some_and(|code| SESSION_DEAD_CODES.contains(&code))
        || mentions_session_dead(&text)
    {
        return json!({
            "kind": "token_expired",
            "message": format!("LobsterAI 登录态已失效（{raw}），请重新登录"),
        });
    }

    // 4) 429 软限流
    if status == 429 {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": upstream_code,
            "status": 429,
        });
    }

    // 5) 404 上游偶发（本仓没有「偶发短冷却」这一档，如实透传）
    if status == 404 {
        return json!({
            "kind": "fatal",
            "status": 404,
            "message": format!("LobsterAI 上游返回 404：{raw}"),
            "upstream_code": upstream_code,
        });
    }

    // 6) 5xx 上游故障
    if status >= 500 {
        return json!({
            "kind": "fatal",
            "status": status,
            "message": message,
            "upstream_code": upstream_code,
        });
    }

    // 7) 其余 4xx / 业务错误：审核文案 → ContentBlocked，否则透传
    if content_blocked(status, error_body) {
        return json!({
            "kind": "content_blocked",
            "status": status,
            "message": format!("{message}{CONTENT_BLOCK_HINT}"),
            "upstream_code": upstream_code,
        });
    }
    json!({
        "kind": "fatal",
        "status": status.max(400),
        "message": message,
        "upstream_code": upstream_code,
    })
}

/// 这一帧 / 这个响应算不算错误（内容拦截判定的挂点）。
///
/// 口径与 native 一致：非 2xx 一律算；2xx 时只有「带 error 字段」的体才算。
pub fn is_error_response(status: u16) -> bool {
    status >= 400
}

/// 是否**停手**（不再换账号）。
///
/// 本家的失败模式里没有「请求本身有问题、换谁都一样」的那一类：额度耗尽与
/// 会话已死都该换号 / 刷新，404 与 5xx 由网关按 `fatal` 透传。所以恒为 false ——
/// 如实回一个空策略，而不是编一条「某些错误停手」的规则。
pub fn error_policy(_status: u16, _error_body: &Value) -> Value {
    json!({ "stop": false })
}

/// 流内错误帧的识别结果（HTTP 200 下发的业务失败）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StreamFailure {
    /// 帧里是余额耗尽
    HardCredit {
        /// 上游给的原文 message
        message: String,
    },
    /// 帧里是会话已死
    SessionDead {
        /// 上游给的原文 message
        message: String,
    },
    /// 帧里是别的业务错误（Go 的 default 分支：**也换号**）
    Other {
        /// 上游给的原文 message
        message: String,
    },
}

/// 识别**流内错误帧**：`HTTP 200` + SSE 正文是 `{"error":{"message":"…"}}`。
///
/// ── 为什么不能复用 [`classify`] ──────────────────────────────────
/// 那个函数的优先级里**状态码排在最前**，而流内错误的 HTTP 状态是 **200** ——
/// 那些分支全失效，只剩关键词表可用；传 200 进去未命中关键词时只能得到「成功」，
/// 而「成功」意味着**不换号**（TS `lobsterai-errors.ts:126-161` 专门说明了这点）。
/// 所以本函数只回答「帧里是不是一类业务失败」，默认值给 [`StreamFailure::Other`]
/// （Go 的 handler 里 default 分支同样 `continue` 换号，防雪崩）。
///
/// ✅ native 里这是**没有调用点**的纯函数；wasm 侧 `chat.rs` 真的用它。
pub fn silent_failure_in_frame(payload: &str) -> Option<StreamFailure> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    // `{"error":{"message":…}}` 才是这个形态；`{"error":"…"}` 也认（宽容读取）
    let message = match parsed.get("error") {
        Some(Value::Object(error)) => error
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
        Some(Value::String(text)) => text.trim().to_string(),
        _ => return None,
    };
    if mentions_hard_credit(&message) || mentions_hard_credit(trimmed) {
        return Some(StreamFailure::HardCredit { message });
    }
    if mentions_session_dead(&message) || mentions_session_dead(trimmed) {
        return Some(StreamFailure::SessionDead { message });
    }
    Some(StreamFailure::Other { message })
}

/// 帧里错误自带的 HTTP 状态（在 400..600 内才认，否则 `None`）。
///
/// 上游的错误帧有时带 `error.status` / `error.code`（数值），有时什么都不带 ——
/// 两者都要能进 [`classify`]，否则「未下发就失败」只能报一句没有状态的 502。
pub fn frame_status(payload: &str) -> Option<u16> {
    let parsed: Value = serde_json::from_str(payload.trim()).ok()?;
    let error = parsed.get("error")?;
    let candidate = error
        .get("status")
        .and_then(Value::as_u64)
        .or_else(|| error.get("code").and_then(Value::as_u64))
        .or_else(|| {
            error
                .get("code")
                .and_then(Value::as_str)
                .and_then(|text| text.trim().parse::<u64>().ok())
        })?;
    if (400..600).contains(&candidate) {
        Some(candidate as u16)
    } else {
        None
    }
}

/// 业务信封是否是「`code:0` + `data:null`」= **令牌已失效**的形态。
///
/// 这一条已经接上：`oauth::unwrap_envelope` 直接调它把 `data` 为 null / 缺失判成
/// 401「登录态可能已失效，请重新登录」。
pub fn envelope_reports_dead_session(payload: &Value) -> bool {
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        return false;
    }
    matches!(payload.get("data"), None | Some(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(value: Value) -> Value {
        value
    }

    #[test]
    fn decision_order_is_the_contract() {
        // 402 优先于一切
        let class = classify(402, &body(json!({ "message": "积分不足" })));
        assert_eq!(class["kind"], json!("quota_limited"));
        assert_eq!(class["status"], json!(402));

        // 400 + 「积分不足」必须判成额度耗尽（排在任何状态码分支之前）
        let class = classify(400, &body(json!({ "message": "积分不足，请充值" })));
        assert_eq!(class["kind"], json!("quota_limited"));
        assert_eq!(class["status"], json!(402));

        // 40100 是会话已死，不是额度
        let class = classify(400, &body(json!({ "code": 40100, "message": "token expired" })));
        assert_eq!(class["kind"], json!("token_expired"));

        // 429 → 额度
        let class = classify(429, &body(json!({ "message": "too many" })));
        assert_eq!(class["kind"], json!("quota_limited"));
        assert_eq!(class["status"], json!(429));

        // 404 / 5xx → 透传
        assert_eq!(classify(404, &body(json!({ "message": "not found" })))["kind"], json!("fatal"));
        assert_eq!(classify(503, &body(json!({ "message": "down" })))["kind"], json!("fatal"));
    }

    #[test]
    fn english_and_chinese_quota_markers_both_hit() {
        for text in [
            "free quota exhausted",
            "Insufficient Credit",
            "免费额度已用完，请升级套餐",
            "您的额度用尽",
        ] {
            let class = classify(400, &body(json!({ "message": text })));
            assert_eq!(class["kind"], json!("quota_limited"), "文案未命中：{text}");
        }
        // 关键词在体的其它字段里也算（haystack 是整份体）
        let class = classify(400, &body(json!({ "message": "bad", "detail": "额度已用完" })));
        assert_eq!(class["kind"], json!("quota_limited"));
    }

    #[test]
    fn content_block_only_applies_to_the_generic_4xx_bucket() {
        let blocked = body(json!({ "message": "blocked by security policy" }));
        let class = classify(400, &blocked);
        assert_eq!(class["kind"], json!("content_blocked"));
        assert!(class["message"]
            .as_str()
            .is_some_and(|text| text.contains("内容被上游内容策略拒绝")));
        // 同一句文案配 500 仍然是上游故障（5xx 分支在前）
        assert_eq!(classify(500, &blocked)["kind"], json!("fatal"));
        // 普通 400 不掺内容拦截提示
        let class = classify(400, &body(json!({ "message": "role 不正确" })));
        assert_eq!(class["kind"], json!("fatal"));
        assert!(!class["message"]
            .as_str()
            .is_some_and(|text| text.contains("内容策略")));
    }

    #[test]
    fn stream_frames_are_classified_without_status_codes() {
        // 额度耗尽的流内形态
        let frame = r#"{"error":{"message":"免费额度已用完，请升级套餐"}}"#;
        assert!(matches!(
            silent_failure_in_frame(frame),
            Some(StreamFailure::HardCredit { .. })
        ));
        // 会话已死
        let frame = r#"{"error":{"code":"40101","message":"refresh token was rejected"}}"#;
        assert!(matches!(
            silent_failure_in_frame(frame),
            Some(StreamFailure::SessionDead { .. })
        ));
        // 其它业务错误：默认给 Other（Go 的 default 分支同样换号）
        let frame = r#"{"error":{"message":"模型不存在"}}"#;
        assert!(matches!(
            silent_failure_in_frame(frame),
            Some(StreamFailure::Other { .. })
        ));
        // 字符串形态的错误也认
        assert!(matches!(
            silent_failure_in_frame(r#"{"error":"额度用尽"}"#),
            Some(StreamFailure::HardCredit { .. })
        ));
        // 正常帧 / 空 / 非法 JSON → None（不能把正常内容判成错误）
        assert!(silent_failure_in_frame(r#"{"choices":[{"delta":{"content":"hi"}}]}"#).is_none());
        assert!(silent_failure_in_frame("").is_none());
        assert!(silent_failure_in_frame("not-json").is_none());
        assert!(silent_failure_in_frame("[DONE]").is_none());
    }

    #[test]
    fn frame_status_only_accepts_plausible_codes() {
        assert_eq!(frame_status(r#"{"error":{"status":402}}"#), Some(402));
        assert_eq!(frame_status(r#"{"error":{"code":"429"}}"#), Some(429));
        // 业务码（40101）不是 HTTP 状态，不能当状态码用
        assert_eq!(frame_status(r#"{"error":{"code":40101}}"#), None);
        assert_eq!(frame_status(r#"{"error":{"message":"x"}}"#), None);
        assert_eq!(frame_status(r#"{"choices":[]}"#), None);
    }

    #[test]
    fn dead_session_envelope_is_detected() {
        assert!(envelope_reports_dead_session(&json!({ "code": 0, "data": Value::Null })));
        assert!(envelope_reports_dead_session(&json!({ "code": 0 })));
        assert!(!envelope_reports_dead_session(&json!({ "code": 0, "data": {} })));
        assert!(!envelope_reports_dead_session(&json!({ "code": 5, "data": Value::Null })));
    }

    #[test]
    fn policy_never_stops_rotation() {
        // 本家的失败模式都该换号 / 刷新，没有「换谁都一样」的那一类
        assert_eq!(error_policy(400, &json!({})), json!({ "stop": false }));
        assert_eq!(error_policy(500, &json!({})), json!({ "stop": false }));
    }

    #[test]
    fn is_error_response_follows_the_status() {
        assert!(!is_error_response(200));
        assert!(is_error_response(400));
        assert!(is_error_response(502));
    }
}
