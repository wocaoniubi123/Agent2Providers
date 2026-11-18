//! 模型目录（native `models` / `refresh_models`）。
//!
//! ── 示例的语义：目录是**内置**的 ────────────────────────────
//! native 的 `models()` 直接返回 `meta().default_models`，并把
//! `CatalogMeta { remote: false, refreshed_at: 0 }` 一起给出去 —— 表示
//! 「这份清单是内置静态兜底，从没从上游拉过」。界面上的「来源 / 更新日期」
//! 两列就靠这两个值区分「内置」与「某次真的拉回来的」。
//!
//! ── wasm 侧多出来的一条硬要求 ──────────────────────────────
//! `models.refresh` 在 `refreshed: true` 时，网关会把**整个返回值**再按
//! `ModelList` 解析一遍，并要求 `meta.remote == true`、
//! `count == models.len()`、每条记录都有非空 `id`
//! （`plugin_host/rpc.rs:1186-1195`）。所以手动刷新这一支用
//! `sdk::catalog::refreshed`：它一次给全 `{refreshed, count, models, meta}`。
//! native 的 `RefreshOutcome::refreshed(n)` 只带一个计数 —— 那是给老通道用的
//! 形状，wasm 侧照抄会被判「刷新缺少同次真实远程模型快照」。
//!
//! ── 自动路径为什么不真打上游 ────────────────────────────────
//! `force == false` 是网关的周期刷新：native 的示例在这里返回
//! `RefreshOutcome::unchanged()`（「按缓存跳过」是正常行为，不是失败）。
//! 示例照抄 —— 这也让「刷新失败」与「没刷新」两条语义各自可读。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 内置目录（与 `metadata.json` 的 `default_models` 同一份内容）。
///
/// 为什么在这里再写一份而不是读 metadata：`metadata()` 在 `lib.rs` 里，
/// 让目录模块反过来依赖入口模块会绕出一个环。两处内容必须一致 ——
/// `metadata.json` 是界面看到的，这里是转发与刷新用到的。
fn builtin() -> Vec<Value> {
    vec![
        json!({ "id": "demo-fast", "name": "Demo Fast", "context_length": 8192 }),
        json!({ "id": "demo-slow", "name": "Demo Slow", "context_length": 32768 }),
    ]
}

/// `models.list`：清单 + 缓存元数据（`ModelList`）。
pub fn list() -> Value {
    json!({
        "models": builtin(),
        // 内置清单：`remote=false`、`refreshed_at=0`，与 native 逐字段一致。
        "meta": { "remote": false, "refreshed_at": 0 },
    })
}

/// `models.refresh`：`force` 为真才当作「用户手动点了刷新」。
pub fn refresh(force: bool) -> Value {
    if !force {
        // 自动路径：按缓存跳过（正常行为，不是失败）。
        return sdk::catalog::unchanged(0);
    }
    // 手动路径：示例把内置清单当作「刚拉回来的一份」，并如实标明 remote。
    sdk::catalog::refreshed(builtin())
}
