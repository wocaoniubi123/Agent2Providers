//! Cline 模型目录：从 metadata 的内置清单按池过滤。
//!
//! ── 内置清单与 native 的关系 ────────────────────────────────
//! native 的 `models::list(pool)` 在没有远程目录时返回 `FALLBACK_MODELS`；
//! 本包的 `metadata.json.default_models` 就是同一份快照（生成脚本抄的），
//! 所以这里直接按池过滤它 —— 两个池各拿到自己那几条，不会把一个池的 id
//! 混进另一个池（那会让界面把「订阅池的模型」发给免费池的账号）。
//!
//! ── 远程目录 ────────────────────────────────────────────────
//! native 的 `refresh_models` 会问一次上游推荐清单并种默认映射；那是网关侧
//! 的「模型规则」职责（用户配置）。wasm 侧没有写配置的通道，因此
//! `models.refresh` 如实回 `{refreshed:false, count}` —— 清单已经由 metadata
//! 提供，界面拿到的就是可用集合，不假装拉过远程。

use agent2api_wasm_sdk::{json, Value};

use super::pool::Pool;

/// 通道前缀（判断一个 id 属不属于某个池）。
const KNOWN_PREFIXES: [&str; 2] = ["cline-free/", "cline-pass/"];

/// 这个 id 属不属于本池。
fn belongs(pool: Pool, id: &str) -> bool {
    if id.starts_with(pool.prefix()) {
        return true;
    }
    // 免费池还有**不带前缀的裸 id**（native 模块头第 2 条）：
    // 只把它们算给免费池，避免同一模型在两个池里重复出现。
    pool == Pool::Free && !KNOWN_PREFIXES.iter().any(|prefix| id.starts_with(prefix))
}

/// `models.list`。
pub fn list(metadata: &Value, pool: Pool) -> Value {
    let models: Vec<Value> = metadata
        .get("default_models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|model| model.get("id").and_then(Value::as_str).is_some_and(|id| belongs(pool, id)))
        .cloned()
        .collect();
    json!({ "models": models, "meta": { "remote": false, "refreshed_at": 0 } })
}

/// `models.refresh`：清单随包内置，这里只回计数（不改用户配置）。
pub fn refresh(_force: bool, metadata: &Value, pool: Pool) -> Value {
    let count = list(metadata, pool)["models"].as_array().map(Vec::len).unwrap_or(0);
    json!({
        "refreshed": false,
        "count": count,
        "message": "Cline 的模型清单随插件内置；远程目录由网关的模型规则维护",
    })
}
