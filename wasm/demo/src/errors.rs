//! 错误分类与退避建议（native `classify` / `retry_advice`）。
//!
//! ── 示例只演示四档的判定形状 ────────────────────────────────
//! 真实 provider 的判据各不同（见迁移规格里「错误分类」一节）：
//! 有些上游把限额与速率窗口都用 429 表达，只能靠文案区分；有些把业务码
//! 放在 `error.code` 里而 HTTP 状态是 200。示例只画形状，真实判据按家另写。
//!
//! ── 四档是网关编排唯一认识的处置方式（不要加第五档）──────────
//! 网关 `upstream::provider_loop` 只按四种行动：
//!   * `quota_limited` → 标记账号对该模型冷却 + 换账号；
//!   * `token_expired` → 刷新凭证后**同一账号**重试一次；
//!   * `content_blocked` → **不罚账号**，换中性提示词重试一次；
//!   * `fatal` → 原样透传给客户端。
//! 多出来的分类在网关侧没有对应分支，会**静默落进 fatal** ——
//! 于是「该轮换账号」的错误被当成终态发给用户。
//!
//! ── 返回形状为什么是 JSON 而不是 Rust 枚举 ──────────────────
//! 插件返回的 JSON 由网关按 `crate::chat::ErrorClass` 反序列化
//! （`#[serde(tag = "kind", rename_all = "snake_case")]`），字段名保持
//! snake_case。这里手写形状而不是引协议 crate：wasm 目标编不了它。

use agent2api_wasm_sdk::{json, Value};

/// 从错误体里取文案（取不到时给一句中文兜底，与 native 一致）。
fn message_of(body: &Value) -> String {
    body.get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("上游返回错误")
        .to_string()
}

/// 从错误体里取上游业务码（只认整数；字符串码原样留给文案）。
fn upstream_code_of(body: &Value) -> Option<i64> {
    body.get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
}

/// `classify`：HTTP 状态 + 错误体 → 网关认识的四个分类之一。
///
/// 判定顺序与 native 的 `match status` 逐条一致；`400 + 文案含 sensitive`
/// 那一支先于兜底，因为内容拦截**不该**罚账号。
pub fn classify(status: u16, body: &Value) -> Value {
    let message = message_of(body);
    let upstream_code = upstream_code_of(body);
    match status {
        429 => json!({
            "kind": "quota_limited",
            // 示例不解析恢复时间：真实 provider 从上游头 / 文案里取。
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": upstream_code,
            "status": status,
        }),
        401 | 403 => json!({
            "kind": "token_expired",
            "message": message,
        }),
        400 if message.contains("sensitive") => json!({
            "kind": "content_blocked",
            "status": status,
            "message": message,
            "upstream_code": upstream_code,
        }),
        _ => json!({
            "kind": "fatal",
            "status": status,
            "message": message,
            "upstream_code": upstream_code,
        }),
    }
}

/// `retry_advice`：正文含 `retry_later` 时给一条退避建议。
///
/// 返回形状是 `crate::chat::RetryAdvice`（`{delay_ms, reason}`）；
/// 不建议重试时返回 `null`（网关对 `null` 的处置就是「不重试」）。
///
/// `budget` 是网关本轮的重试预算，`attempt` 从 0 起：
/// `attempt + 1 >= budget` 表示这已经是最后一次机会，不再给建议。
pub fn retry_advice(body: &Value, attempt: usize, budget: usize) -> Value {
    let text = body.to_string();
    if !text.contains("retry_later") || attempt + 1 >= budget {
        return Value::Null;
    }
    json!({
        // 线性退避：500ms ×（第几次）。真实 provider 多为指数 + 抖动。
        "delay_ms": 500_u64.saturating_mul(attempt as u64 + 1),
        "reason": "示例：上游要求稍后重试",
    })
}
