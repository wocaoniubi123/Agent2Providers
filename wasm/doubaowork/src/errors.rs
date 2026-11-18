//! 错误分类、响应判定与重试/思考档位策略。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/api.rs` 的 `classify` 与
//! `mod.rs` 的 `reasoning_patch`。
//!
//! ── 分类为什么必须与 native 同口径 ──────────────────────────
//! 网关只按四档行动：`quota_limited` 冷却并换账号、`token_expired` 刷新后同一
//! 账号重试、`content_blocked` 换提示词重试、`fatal` 透传。判错的后果很具体：
//! 限额被当 Fatal → 账号永不轮换；凭证过期被当 Fatal → 用户只看到 401。
//! 本家把「人机验证」也归到 429（`api::error` 里由 `extra.decision` 判出），
//! 因为编排层对 429 的处置正是「把这个账号从本模型挪开、换下一个候选」。
//!
//! ── 内容拦截为什么回 false ──────────────────────────────────
//! 本家没有内容拦截标记（native `metadata.json` 的 `refusal_markers` /
//! `refusal_finishes` 都是空表）。回 false 表示「不额外判定」，
//! 与 native 未覆写该钩子等价。

use agent2api_wasm_sdk::{json, Value};

use super::api;

/// `classify`：状态码 + 错误体 → 四档之一。
pub fn classify(status: u16, body: &Value) -> Value {
    api::classify(status, body)
}

/// `is_error_response`：参数是 `{status, headers}`；本家没有流内拦截标记。
pub fn is_error_response(_params: &Value) -> bool {
    false
}

/// `error.policy`：本家不需要额外的停止 / 切换策略（返回空对象即默认策略）。
pub fn policy(_params: &Value) -> Value {
    json!({})
}

/// `reasoning_patch`：客户端已指定档位就不动；否则写进 `reasoning_effort`。
///
/// 与 native 的区别只有一处注释：真正落地档位的是 `prompt::payload`
/// （模式条目要把档位翻成 3–7 的数字），这里只负责说「要不要注入」。
pub fn reasoning_patch(level: &str, body: &Value) -> Value {
    if !body["reasoning_effort"].is_null() {
        return json!({"action": "skip", "reason": "客户端已指定思考档位"});
    }
    if matches!(level, "low" | "medium" | "high" | "xhigh" | "max") {
        json!({"action": "set", "field": "reasoning_effort", "value": level})
    } else {
        json!({"action": "skip", "reason": "豆包工作不支持该思考档位"})
    }
}

/// `cooldown_models`：本家按账号冷却，不按模型细分。
pub fn cooldown_models() -> Value {
    json!({"models": []})
}
