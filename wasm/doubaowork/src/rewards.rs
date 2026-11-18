//! 任务领奖（`claim` / `claim.status`）。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/rewards.rs`。
//!
//! ── 为什么这里只剩一次宿主调用 ──────────────────────────────
//! native 自己扫活动详情、找可领任务、提交 `/alice/ug/campaign/item/reward/claim/`
//! 再回查。wasm 侧这条路径由宿主固定入口接管：
//!   · 能力 `claim.doubao-tasks.v1`（只有本包能声明）；
//!   · 宿主 `doubao_rewards` 会自己读 launch / 活动详情 / 待确认快照，
//!     提交与回查都由它完成，插件**只能**在本次原调用上下文里调
//!     `claim.doubao.tasks`（无参数），拿回已经核过的结果；
//!   · 宿主 `wasm/http.rs` 同时把 `/alice/ug/campaign/item/reward/claim` 列为
//!     保留路径，插件自己 POST 会被拒。
//!
//! 所以这里的方法体就是「把宿主的结论原样交出去」。`claim` 与 `claim.status`
//! 走同一个宿主方法名（由宿主按 `params.claim` 是否为空决定语义）。

use agent2api_wasm_sdk::{self as sdk, json, Result, Value};

/// 调宿主固定入口；参数必须是空对象（宿主会核对）。
///
/// 错误原样往外传：宿主给的 `code` / `status`（`plugin_busy`、`timeout`、
/// `doubao_tasks_unconfirmed` …）已经是最终语义，包一层只会把它们压成 502。
fn exchange() -> Result<Value> {
    sdk::host("claim.doubao.tasks", json!({}))
}

pub fn status() -> Result<Value> {
    exchange()
}

pub fn claim() -> Result<Value> {
    exchange()
}
