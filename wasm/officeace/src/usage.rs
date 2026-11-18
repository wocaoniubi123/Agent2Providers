//! 余额 / 积分：读订阅快照（`GET /v1/subscription`，V11 签名），归一成
//! `usage.query` 契约的形状（见 [`crate::subscription::summarize`]）。
//!
//! 控制面临时凭据（AK/SK）缺失时回 `usage_not_configured`（400 + 中性标记）——
//! 手工只导入网关 Basic 凭据的账号就会走到这条，前端显示成「未配置查询」而不是失败。
//!
//! ── 为什么额度链走 `control` 而不是直接读账号 ────────────────
//! 「先判临期、临期就续」必须是**唯一**入口（见 `control::credential_of`）。余额页
//! 是用户最常点的一处，也是闲置之后第一个撞 401 的地方 —— 它若自己读盘上那份，
//! 用户看到的「查询失败」与真实原因（临时凭据 2 小时到期）会差得很远。

use agent2api_wasm_sdk::{Result, Value};

use super::{control, subscription};

/// 查询某 OfficeAce 账号的可领余额 / 积分。
pub fn query() -> Result<Value> {
    let mut credential = control::credential_of()?;
    let snapshot = control::subscription_of(&mut credential)?;
    Ok(subscription::summarize(&snapshot))
}

/// 额度来源（`admin.action = quota.sources`）：把这次报告里的明细行摊成来源清单。
///
/// 面板问这个是为了画「额度来源」那一栏；本家的来源在 `usage.query` 的 `credits[]`
/// 里已经给全，所以这里**只读一次报告**、不额外打上游。
///
/// ── 查不到就给空表，不抛错 ──────────────────────────────────
/// 这一栏是**展示用**的旁路：控制面凭据缺失（手工只导入网关 Basic 的那批账号）
/// 时 `usage.query` 会回 `usage_not_configured`，若把那个错误抛出去，面板会把
/// 「额度来源」整块画成红色失败 —— 而它本来就没有来源可列（native 的
/// `quota_sources` 对空报告也是回空数组）。
pub fn sources() -> Result<Value> {
    match query() {
        Ok(report) => Ok(Value::Array(subscription::quota_sources(&report))),
        Err(_) => Ok(Value::Array(Vec::new())),
    }
}
