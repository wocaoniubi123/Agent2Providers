//! 上游错误：两类**账号级失败判据** + 四档分类（native `errors.rs` + `mod.rs`
//! 的 `classify` / `content_or_fatal`）。
//!
//! ── 为什么合成一个文件 ──────────────────────────────────────
//! native 把「判据」放在 `errors.rs`、把「分类」放在 `mod.rs`。两边读的是同一份
//! 「状态码 + 上游文案」，分开写迟早出现「判据说命中、分类说不命中」的分叉。
//! wasm 侧一次分类要同时服务两条路（`classify` 方法回 JSON、`conversation` 里
//! 回 `Error`），所以做成一个 [`Classified`] 中间态 + 两个出口。
//!
//! ── 两类是什么（附上游真实报文）──────────────────────────────
//! ```text
//!   ① 魔粒耗尽   429 {"error":{"message":"insufficient balance","request_id":"…"}}
//!       账号的魔粒用完了。充魔粒之前这把令牌确实不可用 —— 按「当日禁用」处理，
//!       跨过午夜再试一次（充了值就恢复）。
//!   ② 未验证邮箱 403 正文含 "email verification" / "verified accounts" /
//!       "/my/settings/account"
//!       账号没完成邮箱验证，魔粒推理接口直接拒绝服务，充魔粒也救不回来 ——
//!       唯一出路是去账号设置页完成验证。
//! ```
//!
//! ── 顺序要紧（改分类时先读这段）───────────────────────────────
//! 两条「账号级」判据必须在裸 401/403 与裸 429 之前，否则它们会被归成
//! 「令牌失效」或「速率窗口」，各自的正确处置就都丢了：
//!   - 魔粒耗尽不是速率窗口：充值之前这把令牌**一直**不可用，按分钟冷却只会在
//!     当天反复白撞；
//!   - ⚠️ 漏了「未验证邮箱」后果最糟：403 会被当成「令牌失效」，界面提示用户去
//!     **重新粘贴一个本来就好好的令牌**，而真正要做的是去账号设置页完成验证。
//!
//! ── 插件里还有一条，本实现**有意不照搬**（说明理由，免得将来被当成遗漏）──
//! 参考插件把 `503 + "model_not_ready"`（上游 vLLM 还在加载权重）当作**整家
//! 不可用**摘掉。本实现**不做**：那件事与账号无关（本家每把令牌都会被同样
//! 拒绝），罚账号是错的。这里的默认处置是 `Fatal`（不罚账号，如实回给客户端、
//! 由客户端重试）。
//!
//! ⚠️ 判据一律大小写不敏感的子串匹配，且只在「这次请求已经失败」的分支上
//! 调用 —— 子串匹配本身不区分「上游报的错」与「模型自己生成的内容」。

use agent2api_wasm_sdk::{json, Error, Value};

use super::time;

/// 内容拦截的文案特征（全部小写；匹配前把上游文案转小写）。
const CONTENT_BLOCK_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 内容拦截的提示文案（native 原话，逐字沿用）。
const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 一次失败分类后的中间态。
struct Classified {
    kind: &'static str,
    status: u16,
    message: String,
    reset_at: Option<i64>,
    upstream_code: Option<i64>,
    /// 给客户端按 code 分支的第二条判据（`insufficient_quota` 这类）；
    /// 本家没有专属语义的分类给 None。
    code: Option<&'static str>,
}

/// 一次失败是否意味着**账号魔粒耗尽**（429 + `insufficient balance`）。
///
/// 只看文案不看状态码也可以，但两样都看更稳 —— 别的 4xx 里出现这串字的
/// 场合不存在，多一道闸门不损失什么。
pub fn is_insufficient_balance(status: u16, message: &str) -> bool {
    status == 429 && contains_ci(message, "insufficient balance")
}

/// 一次失败是否意味着**账号未完成邮箱验证**（403 + 三选一的特征串）。
///
/// **必须同时看状态码与文案**：403 还有别的权限语义，只看状态码会把无关失败
/// 误判成「账号未验证」，而那会让用户去查一个不存在的问题。
pub fn is_unverified_account(status: u16, message: &str) -> bool {
    if status != 403 {
        return false;
    }
    [
        "email verification",
        "verified accounts",
        "/my/settings/account",
    ]
    .iter()
    .any(|marker| contains_ci(message, marker))
}

/// 大小写不敏感的子串匹配（空值一律 false）。
fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// 上游文案：顶层 `message` / `Message`，再认 `error.message` 与 `msg`。
///
/// ── 为什么要认 `error.message`（与 native 的一处差异，记在这里）──────
/// native 只读**顶层** `message`/`Message`，而它自己模块头抄下来的真实报文是
/// `{"error":{"message":"insufficient balance"}}` —— 按顶层读会得到空串，于是
/// 两条账号级判据在最常见的报文形态上永远不命中。这里同时认两层，判据才有
/// 机会生效；顶层优先，行为对已有的顶层形态逐字不变。
pub fn upstream_text(body: &Value) -> String {
    for candidate in [
        body.get("message"),
        body.get("Message"),
        body.get("msg"),
        body.pointer("/error/message"),
        body.pointer("/error/Message"),
    ] {
        if let Some(text) = candidate.and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// 上游业务码：顶层 `code` / `Code`，再认 `error.code`；数字与数字字符串都认。
pub fn upstream_code(body: &Value) -> Option<i64> {
    for candidate in [
        body.get("code"),
        body.get("Code"),
        body.pointer("/error/code"),
        body.pointer("/error/status"),
    ] {
        let Some(value) = candidate else { continue };
        if let Some(code) = value.as_i64() {
            return Some(code);
        }
        if let Some(code) = value.as_str().and_then(|text| text.trim().parse::<i64>().ok()) {
            return Some(code);
        }
    }
    None
}

/// 分类：两条账号级判据 → 401/403 → 429 → 内容拦截 / 透传。
fn classify(status: u16, body: &Value, raw: String) -> Classified {
    let upstream_code = upstream_code(body);
    let message = format!("上游返回 {status}: {raw}");
    let label = super::upstream::LABEL;

    if is_insufficient_balance(status, &raw) {
        return Classified {
            kind: "quota_limited",
            status,
            message: format!(
                "ModelScope {label}账号的魔粒已耗尽（上游：{raw}），将在下一个自然日\
                 （北京时间 0 点）自动恢复；给账号充值后立即恢复"
            ),
            reset_at: Some(time::next_day_boundary_ms(agent2api_wasm_sdk::now())),
            upstream_code,
            code: Some("insufficient_quota"),
        };
    }
    if is_unverified_account(status, &raw) {
        return Classified {
            kind: "quota_limited",
            status,
            message: format!(
                "ModelScope {label}账号未完成邮箱验证，魔粒推理接口拒绝服务\
                 （上游：{raw}）——请到魔搭账号设置页完成邮箱验证，验证后次日自动恢复"
            ),
            reset_at: Some(time::next_day_boundary_ms(agent2api_wasm_sdk::now())),
            upstream_code,
            code: Some("unverified_account"),
        };
    }
    if status == 401 || status == 403 {
        return Classified {
            kind: "token_expired",
            // `TokenExpired` 在协议里没有自己的状态码，恒按 401 呈现
            status: 401,
            message,
            reset_at: None,
            upstream_code: None,
            code: Some("token_expired"),
        };
    }
    if status == 429 {
        return Classified {
            kind: "quota_limited",
            status,
            message,
            // 不给结构化恢复时间：由网关的限额标记给兜底冷却
            reset_at: None,
            upstream_code,
            code: Some("rate_limit_exceeded"),
        };
    }
    if status >= 400 && matched_content_block(&raw) {
        return Classified {
            kind: "content_blocked",
            status,
            message: format!("{message}{CONTENT_BLOCK_HINT}"),
            reset_at: None,
            upstream_code,
            code: Some("content_filter"),
        };
    }
    Classified { kind: "fatal", status: status.max(400), message, reset_at: None, upstream_code, code: None }
}

/// 上游文案是否命中内容拦截特征（只在失败分支上调用）。
fn matched_content_block(raw: &str) -> bool {
    let lowered = raw.to_lowercase();
    CONTENT_BLOCK_PATTERNS
        .iter()
        .any(|pattern| lowered.contains(pattern))
}

/// `classify` 方法的返回（与 `proto::ErrorClass` 的 JSON 形态逐字段一致）。
pub fn class_of(status: u16, body: &Value) -> Value {
    let raw = upstream_text(body);
    let raw = if raw.is_empty() { "上游错误".to_string() } else { raw };
    let class = classify(status, body, raw);
    json!({
        "kind": class.kind,
        "status": class.status,
        "message": class.message,
        "reset_at": class.reset_at,
        "upstream_code": class.upstream_code,
    })
}

/// `conversation` 里非 2xx 的分类结果 → `Error`（编排层按状态码与 code 换账号）。
///
/// `raw_text` 是响应体的原样文本：上游回 HTML 错误页时 `body` 解析不出任何字段，
/// 文案只能从这里取（截断到 2000 字符，避免把整页 HTML 塞进客户端提示）。
pub fn response_error(status: u16, body: &Value, raw_text: &str, truncated: bool) -> Error {
    let mut raw = upstream_text(body);
    if raw.is_empty() {
        raw = snippet(raw_text);
    }
    if raw.is_empty() {
        raw = "上游错误".to_string();
    }
    if truncated {
        raw.push_str("（诊断体已截断）");
    }
    into_error(classify(status, body, raw))
}

/// 流内 `{"error":{…}}` 帧 → `Error`。
///
/// 状态码取帧里的 `error.status` / `error.code`（只认 400…599），否则按 502：
/// 帧里没有状态码时，把它当成一次「上游说不清为什么」的失败，而不是猜一个。
pub fn frame_error(value: &Value) -> Error {
    let status = value
        .pointer("/error/status")
        .and_then(Value::as_u64)
        .or_else(|| value.pointer("/error/code").and_then(Value::as_u64))
        .filter(|status| (400..600).contains(status))
        .map(|status| status as u16)
        .unwrap_or(502);
    let mut raw = upstream_text(value);
    if raw.is_empty() {
        raw = "上游错误".to_string();
    }
    into_error(classify(status, value, raw))
}

/// 给客户端补一条 SSE 错误事件（已下发内容后再出错时用）。
///
/// 形状与 atomcode / codearts 的 wasm 实现一致：客户端的聚合器认
/// `{"error":{…}}` 这一帧，补一条它就能立刻结束等待，而不是挂到超时。
pub fn error_event(error: &Error) -> Value {
    json!({
        "error": {
            "message": error.message,
            "status": error.status.unwrap_or(502),
            "type": "upstream_error",
        }
    })
}

fn into_error(class: Classified) -> Error {
    let mut error = Error::http(class.status, class.message);
    if let Some(code) = class.code {
        error = error.with_code(code);
    }
    error.with_reset(class.reset_at)
}

/// 诊断体摘一段可读文本（按字符，不按字节 —— 中文按字节切会切出半个字符）。
fn snippet(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut output: String = trimmed.chars().take(2000).collect();
    if trimmed.chars().count() > 2000 {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 报文的两种形态都要命中「魔粒耗尽」：顶层 message 与 error.message。
    #[test]
    fn the_balance_marker_is_recognized_in_both_envelopes() {
        assert!(is_insufficient_balance(429, "insufficient balance"));
        assert!(is_insufficient_balance(429, "Insufficient Balance"));
        assert!(!is_insufficient_balance(402, "insufficient balance"), "状态码也要看");

        let nested = json!({ "error": { "message": "insufficient balance" } });
        assert_eq!("insufficient balance", upstream_text(&nested));

        let class = class_of(429, &nested);
        assert_eq!("quota_limited", class["kind"].as_str().unwrap_or_default());
        assert!(class["reset_at"].as_i64().is_some_and(|reset| reset > 0));
    }

    /// 未验证邮箱：必须同时是 403 且带特征串。
    #[test]
    fn the_unverified_marker_requires_both_status_and_text() {
        let body = json!({ "message": "please finish email verification first" });
        assert!(is_unverified_account(403, "email verification"));
        assert!(!is_unverified_account(401, "email verification"), "401 是令牌失效");
        assert!(!is_unverified_account(403, "permission denied"), "403 还有别的语义");
        let class = class_of(403, &body);
        assert_eq!("quota_limited", class["kind"].as_str().unwrap_or_default());
        assert!(class["message"]
            .as_str()
            .unwrap_or_default()
            .contains("邮箱验证"));
    }

    /// 裸 401 / 403 / 429 的处置。
    #[test]
    fn bare_status_codes_fall_into_their_own_buckets() {
        assert_eq!(
            "token_expired",
            class_of(401, &json!({ "message": "invalid token" }))["kind"]
                .as_str()
                .unwrap_or_default()
        );
        let limited = class_of(429, &json!({ "message": "too many requests" }));
        assert_eq!("quota_limited", limited["kind"].as_str().unwrap_or_default());
        assert!(limited["reset_at"].is_null(), "速率窗口不给结构化恢复时间");
    }

    /// 内容拦截：500 + 特征串 → content_blocked，并补上提示。
    #[test]
    fn a_content_block_is_flagged_without_punishing_the_account() {
        let class = class_of(500, &json!({ "message": "Blocked by security policy" }));
        assert_eq!(
            "content_blocked",
            class["kind"].as_str().unwrap_or_default()
        );
        assert!(class["message"]
            .as_str()
            .unwrap_or_default()
            .contains("内容被上游内容策略拒绝"));
    }

    /// 流内帧：状态码取 error.status，取不到按 502。
    #[test]
    fn a_stream_error_frame_picks_its_status_from_the_frame() {
        let error = frame_error(&json!({ "error": { "status": 429, "message": "rate limited" } }));
        assert_eq!(Some(429), error.status);
        assert_eq!(Some("rate_limit_exceeded".to_string()), error.code);

        let unknown = frame_error(&json!({ "error": { "message": "boom" } }));
        assert_eq!(Some(502), unknown.status);
    }
}
