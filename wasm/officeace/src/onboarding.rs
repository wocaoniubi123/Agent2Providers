//! 「新手任务 / 奖励活动」：把订阅里的 `bonus_skus` 当**已到账**的奖励账本列出来。
//!
//! ── 关键事实：账本条目 = 已发放（2026-10-13 实测确认）───────
//! `bonus_skus` 的条目是**发放凭证**：出现即已到账（官方 `AK()` 把所有未过期
//! 条目的 `points` 计入 `totalCredits`；实测三项 6000 分全在 `available` 里，
//! 6499.33 = 500 套餐 + 6000 奖励 − 0.668 已用）。所以「任务」一律显示为已领取，
//! `unclaimed` 恒 0 —— 未发放的那一天，条目**还没出现在账本里**。
//!
//! ── 领取动作做什么（`claim_all` 与签到是同一个上游调用）─────
//! 上游按天结算一批，已在官方客户端结算过时返回空列表 `{"bonus_skus": []}`。
//! 所以 claim 之后要**重查一次订阅**才是展示用的全量账本。
//!
//! ── `settled` 为什么还要本地台账 ─────────────────────────────
//! 上游不直接回答「今天经本网关结算过没有」。台账（`officeaceBonus`）的 `all` 位
//! 就是这个事实：置位后当天不再自动补打 claim。日界口径复用北京时间自然日
//! ——上游活动周期就是 UTC+8 零点，两处同源才不会有「今天」的分歧。
//!
//! ── 与 native 的差别只有存储 ────────────────────────────────
//! native 走 `ctx.ledger_get/put(account_id, kind)`；插件走宿主的
//! `ledger.get/put {kind}`（宿主按当前账号作用域存）。键名与内容形状一字未改，
//! 所以升级前后「今天领过没有」的答案是一致的。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::collections::BTreeSet;

use agent2api_wasm_sdk::{json, Result, Value};

use super::{control, subscription, util};

/// 任务分组名（签到中心按它分块显示）。
const TASK_GROUP: &str = "奖励积分";

/// 本地领取台账：`{ "day": "YYYY-MM-DD", "items": ["<activityId>"…], "all": bool }`。
///
/// ── 它现在管什么（2026-10-13 收窄，别再拿它判 done）────────────
/// `done` 的判据已改为「账本条目 = 已发放 = 已领取」（见 [`build_tasks`]），
/// 台账只剩 `all` 有用：它回答「**今天经本网关结算过没有**」——`get_tasks` 的
/// `settled` 位与「进页面是否还自动打一发 claim」都读它。
/// `claimed`（今天领过哪些 key）保留为记录：`mark_claimed` 的语义要它完整，
/// 上游哪天按 key 判断也有据可查。
struct Ledger {
    day: String,
    claimed: BTreeSet<String>,
    /// 今天是否**整体领过一次**（签到或「一键领取」成功即置位）。
    all: bool,
}

/// 台账的 ledger 键名。
pub const LEDGER_KIND: &str = "officeaceBonus";

/// 读台账；跨天（或没台账 / 记录坏了）都当空表 —— 只回答「**今天**领过没有」。
fn ledger_of() -> Ledger {
    let day = util::beijing_today_key();
    let empty = Ledger { day: day.clone(), claimed: BTreeSet::new(), all: false };
    let stored = control::ledger_get(LEDGER_KIND);
    if !stored.is_object() || stored.get("day").and_then(Value::as_str) != Some(day.as_str()) {
        return empty;
    }
    let claimed = stored
        .get("items")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let all = stored.get("all").and_then(Value::as_bool).unwrap_or(false);
    Ledger { day, claimed, all }
}

fn persist_ledger(ledger: &Ledger) {
    let payload = json!({
        "day": ledger.day,
        "items": ledger.claimed.iter().cloned().collect::<Vec<_>>(),
        "all": ledger.all,
    });
    if control::ledger_put(LEDGER_KIND, &payload).is_err() {
        // 落盘失败不改签到结果：上游那边可能已经发下来了，把成功报成失败本末倒置。
        // 这里连日志都不打 —— wasm 插件没有日志通道，静默比谎报更诚实。
    }
}

/// 把一批活动记进「今天已处理」台账（签到与领取共用），并置「整体领过」位。
///
/// ── 为什么签到也要调它 ──────────────────────────────────────
/// OfficeAce 的签到与新手任务是**同一个上游动作**（一次 claim 就把当天该发的都发
/// 了）。台账的 `all` 位 = 「今天经本网关结算过」：置位后签到中心不再为这个账号
/// 自动补打 claim，当天也就到此为止。
pub fn mark_claimed(bonuses: &[subscription::Bonus]) {
    let mut ledger = ledger_of();
    // 即便这次一个活动都没列出来（上游当时没给 bonus_skus），也置位：
    // 这次 claim 本身已经把当天能领的都领了。
    ledger.all = true;
    for bonus in bonuses {
        ledger.claimed.insert(bonus.activity_id.clone());
    }
    persist_ledger(&ledger);
}

/// 任务行 + 汇总：返回 `(tasks, total, earned, unclaimed)`。
///
/// ── `done` 的判据（2026-10-13 修正，别再改回去）───────────────
/// **上游账本里的条目本身就是发放凭证**：出现的都已到账。官方口径同此。实测三项
/// 全部计入 `available`，而 claim 返回 `{"bonus_skus": []}` ——「列表里的都已发、
/// 没有新可领」。
///
/// 上一版拿本地台账判 done：官方客户端发出的奖励它不知道 ⇒ 已到账的显示成
/// 「可领取」，用户点 claim 又拿到空列表 ⇒ 「领了没反应」。台账现在只服务
/// `settled`（今天经本网关结算过），不参与 done。
fn build_tasks(bonuses: &[subscription::Bonus]) -> (Vec<Value>, f64, f64, usize) {
    let total: f64 = bonuses.iter().map(|bonus| bonus.total).sum();
    let tasks: Vec<Value> = bonuses
        .iter()
        .map(|bonus| {
            json!({
                "key": bonus.activity_id,
                "title": bonus.name,
                "group": TASK_GROUP,
                "points": bonus.total,
                // 账本条目 = 已发放 ⇒ 一律已领取（见函数文档）
                "done": true,
                "claimable": false,
                "remaining": bonus.remaining(),
                "expiresAt": bonus.expires_at,
            })
        })
        .collect();
    // unclaimed 恒 0：账本里没有「待领」的东西（待领的那一天，条目还不在账本里）
    (tasks, total, total, 0)
}

/// 任务状态（只读）：列订阅里的奖励活动（`claim.status` 的实现）。
///
/// ── `refresh` 在本家为什么**不改变取数**────────────────────
/// 别家（Loomy / CodeArts / 小浣熊）的新人礼是**一次性**的，结清后写进
/// `onboarding_memory` 永久记忆，`refresh=false` 就直接吃记忆、零上游请求。
/// 本家不是那个形状：奖励**每天**由上游结算一批（官方客户端每小时自动打一发
/// claim），第二天上游会开新一批活动 —— 用「永久结清」那份记忆会把明天新开的
/// 活动也判成已领完。所以本家用**按天**的台账，它今天没结清就照样实查；而这里的
/// 读请求只是一次 `GET /v1/subscription`（无副作用、不领东西），真正会白打的那一发
/// （claim）已经由台账在 [`claim_all`] 里挡住。
/// `settled` 字段给的是「**今天经本网关结算过**」（台账 all 位）——界面据此在领完后
/// 跳过自动查询。注意它**不能**用 `unclaimed == 0` 代替：账本条目一律已发放，
/// 那个数恒为 0（见 [`build_tasks`]）。
pub fn get_tasks() -> Result<Value> {
    let mut credential = control::credential_of()?;
    let snapshot = control::subscription_of(&mut credential)?;
    let bonuses = subscription::bonuses_of(&snapshot);
    let ledger = ledger_of();
    let (tasks, total, earned, unclaimed) = build_tasks(&bonuses);
    Ok(json!({
        "tasks": tasks,
        "earned": earned,
        "total": total,
        "unclaimed": unclaimed,
        // 今天经本网关结算过 ⇒ 界面可跳过自动查询（次日台账按天复位）
        "settled": ledger.all,
        "provider": super::credentials::ID,
        "note": "OfficeAce 的奖励由上游按天自动发放（官方客户端每小时打一发 claim）；这里列出的是**已到账**的奖励账本，「一键领取」= 立即触发今天的结算",
    }))
}

/// 领取后重新读取完整奖励账本（`claim` 的实现）；领取响应只包含本次新发放的条目。
pub fn claim_all() -> Result<Value> {
    let claim = super::checkin::claim()?;
    let claimed_points = claim.get("gained").and_then(Value::as_f64).unwrap_or(0.0);
    let mut current = get_tasks().unwrap_or_else(|_| {
        json!({ "provider": super::credentials::ID, "settled": true })
    });
    let message = claim.get("msg").and_then(Value::as_str).unwrap_or("奖励领取请求已完成");
    let rewards = claim
        .get("rewards")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    current["claimed"] = json!(rewards.len());
    current["results"] = json!(rewards);
    current["claimedPoints"] = json!(claimed_points);
    current["failed"] = json!(0);
    current["settled"] = json!(true);
    current["message"] = json!(message);
    Ok(current)
}
