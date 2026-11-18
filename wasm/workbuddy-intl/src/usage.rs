//! `usage.query` / `checkin.claim` 两个具名方法的执行体（native `mod.rs` 里的
//! `usage` / `checkin` 两个 trait 方法）。
//!
//! ── 为什么既有形状不归一化（这是硬要求）─────────────────────
//! `{kind, unlimited, totalLeft, planLeft, bonusLeft}` 是改造前就有的既有契约，
//! 前端一直按它渲染（余额列的读数，见 `ui/accounts-table.js` 的 `usageSummary`，
//! 后端 `usage_records::extract_remaining` 也认 `totalLeft` 这一个键）。
//! 把它包装成 trait 文档里那套 `{available, unit, wallets, subscription}` 会让那
//! 一格的显示退化。所以这里是**加**不是换：五个既有键原样，新挂上去的只有：
//!
//!   * `credits[]`      —— 逐份积分包明细（面额 / 已用 / 剩余 / 领取 / 到期），
//!                        账号页的「积分明细」弹层读它（能力位 `creditDetail`）；
//!   * `subscription`   —— 当前生效套餐的名字与到期时刻，弹层头部那一行。
//!
//! ── 为什么是 `query_usage` 而不是 `query_credits_summary` ─────
//! 后者只回三个数（它内部那次查询的 `resources` 被丢掉了）。这里要明细，就得拿
//! 查询的完整成果；两个都调会让**同一个上游接口被打两次**（批量查询时按账号翻倍）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::account;
use crate::billing;
use crate::outbound;

/// 指定账号的会话形状（没有可用凭证时给可读错误）。
fn session() -> Result<Value> {
    let secret = account::secret()?;
    if !secret.is_object() {
        return Err(Error::http(401, "该账号没有可用凭证，无法查询积分"));
    }
    Ok(outbound::session_of_record(&secret))
}

/// 查积分简报 + 逐份明细 + 当前套餐。
pub fn query() -> Result<Value> {
    let session = session()?;
    let usage = billing::query_usage(&session, None)?;
    let mut document = billing::credits_summary_from(&usage);
    // 企业账号没有资源包（那份额度是「本周期已用 / 上限」一笔账）：
    // 明细与套餐两项都不挂，界面退回单行读数
    let packs = billing::credit_packs_from(&usage);
    if !packs.is_empty() {
        document["credits"] = json!(packs);
    }
    if let Some(subscription) = billing::subscription_of(&usage) {
        document["subscription"] = subscription;
    }
    Ok(document)
}

/// 每日签到（`checkin.claim`）。
///
/// ── 国际版没有普通签到 ──────────────────────────────────────
/// `capabilities.checkin` 对国际版是 `false`（网关不会调到这里）；它的「每日
/// 活跃」走 `admin.action` 的 `activity.run`（见 [`crate::keepalive`]）。
/// 真被调到就明确说清楚，而不是打一条注定失败的国内版接口 —— 与 native
/// `checkin()` 里那句「WorkBuddy 国际版没有普通签到（它的每日活跃在套餐领取入口）」
/// 同一语义。
pub fn checkin() -> Result<Value> {
    Err(Error::http(
        400,
        "WorkBuddy 国际版没有普通签到（它的每日活跃在 activity.run 里）",
    ))
}
