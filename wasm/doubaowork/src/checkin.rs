//! 每日签到（`checkin.claim`）。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/checkin.rs` +
//! `checkin_state.rs`（滚动台账）。
//!
//! ── wasm 侧整条链路由宿主固定入口执行 ──────────────────────
//! 网关 `plugin_host/wasm/checkin_call/doubao_daily/` 是豆包专用的签到实现：
//! 插件执行**之前**，宿主已经完成
//!   ① 绑定账号快照（`persistence.bind`，要求能力 `checkin.rolling.v1`）；
//!   ② 选原签到任务并查询官方状态（`observe_original_daily`）；
//!   ③ 官方显示今日未签时**自己**提交签到（`network::submit_checkin`，
//!      路径 `/alice/ug/campaign/landing/checkin`）并回查确认；
//! 执行**之后**，宿主用 `persistence.settle` 把真实官方事实与插件回执合并成
//! 最终结果（`Settlement::claim()`）。
//!
//! 插件能不能自己发那次签到？不能：宿主 `wasm/http.rs` 的
//! `guard_token_exchange` 把 `/alice/ug/campaign/landing/checkin` 与
//! `/alice/ug/campaign/item/reward/claim` 列为保留路径，插件直接 POST 会被
//! 拒成 forbidden。所以本模块只做一件事：如实报告「本次不由插件提交」，
//! 让宿主的官方事实成为唯一结论。
//!
//! ── 滚动台账 ────────────────────────────────────────────────
//! native 用 `ledger` 记「待确认领取」防重复提交；wasm 侧这份记忆由宿主的
//! `credential_version::doubao_state` 持有（`SnapshotReceipt` 的 unknown /
//! official 两栏），插件不再自己写台账 —— 写了也不会被当成事实。这也是
//! `checkin.rolling.v1` 这条能力在豆包身上的真实含义。

use agent2api_wasm_sdk::{json, Result, Value};

/// `checkin.claim`：回执形状（`proto::CheckinReport`）。
///
/// 宿主 `checkin_call/result/projection.rs` 只认这六个 `outcome`；`details`
/// 不写，避免与官方事实冲突（`completed` 等展示字段由宿主补齐）。
pub fn claim() -> Result<Value> {
    Ok(json!({
        "outcome": "inactive",
        "credit": Value::Null,
        "streak": Value::Null,
        "message": "豆包工作签到由主程序按官方活动状态提交并回查；插件不重复提交领取，\
                    结果以官方 checked_in_today 为准",
    }))
}
