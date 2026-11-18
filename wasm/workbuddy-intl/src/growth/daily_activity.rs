//! WorkBuddy **国内版每日活跃上报**（成长中心连登 / 活跃地图的唯一点亮通道）。
//!
//! ── 为什么单开一个模块 ──────────────────────────────────────
//! 上游有两套互不相通的连签，名字都叫 streak，事实源却完全不同：
//!
//! ```text
//! 签到活动   POST /v2/billing/meter/daily-checkin
//!            → checkin-activity-status 的 streak_days（签到连签，签到就涨）
//! 成长中心   POST /v2/report  的一条 chat_request_send 事件
//!            → activity/growth/streak 的 streak.days（连登 / 活跃地图）
//! ```
//!
//! 2026-10-19 实测（真实国内版账号）：调 `daily-checkin` 后签到连签 14 → 15，而
//! 成长中心的 `streak.days` 与当日热力格**一格未动**；同一账号补发一条
//! `chat_request_send` 后，`streak.days` 0 → 1、当日热力格 0 → 2。所以「签到」与
//! 「点亮活跃地图」是两件事，后者必须单独发。
//!
//! 不发这一发的两个后果：
//!   1. 账号页 / 成长任务行的「连登 N 天」永远停在 0；
//!   2. 连登管家的补签判据读热力图 —— 整张地图恒为 0 时它每天都会判「昨日漏签」，
//!      有补签卡就逐日烧掉一张。
//!
//! ── 每天一条就够 ────────────────────────────────────────────
//! 上报按自然日幂等：同一天重复发不会让连登天数翻倍，只会让热力格的分累加（实测）。
//! 参考实现按「每号每天 1 次」的风控口径，这里用**宿主会话存储**里的
//! `uid → 日键` 记忆把「单签 / 批量 / 定时」几条入口压成每天一条。
//! 记忆只在**上报成功后**才写：失败不记，同一天的下一条入口还能补。
//! 会话存储带 TTL（到当天结束），宿主重启会丢掉记忆、当天多发一条 —— 幂等，无副作用。
//!
//! ── 企业版 ──────────────────────────────────────────────────
//! 企业号没有个人成长体系（`/activity/growth/*` 上游一律 403），上报是**零收益**
//! 的（上游仍回 200、不报错，因此最容易静默白发）。门控在调用方。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use crate::util;

use super::{events, growth_streak, GrowthAccount};

/// 一次每日活跃上报的结果。
pub struct DailyActivityReport {
    /// 本次是否真的发出了上报（false = 今天已经报过，直接跳过）
    pub sent: bool,
    /// 上报后回读的连登天数（回读失败为 None —— 上报本身已成功）
    pub streak_days: Option<i64>,
}

/// 「今天已经报过」的记忆键（宿主会话存储）。
fn reported_key(uid: &str) -> String {
    format!("workbuddy-daily:{uid}:{}", util::today_key())
}

fn reported_today(uid: &str) -> bool {
    let today = util::today_key();
    sdk::session_get(&reported_key(uid))
        .ok()
        .and_then(|value| value.get("day").and_then(Value::as_str).map(str::to_string))
        .is_some_and(|day| day == today)
}

fn mark_reported(uid: &str) {
    let day = util::today_key();
    let ttl = util::beijing_day_start(util::now_ms())
        .saturating_add(util::DAY_MS)
        .saturating_sub(util::now_ms())
        .max(1_000);
    let _ = sdk::session_put(&reported_key(uid), json!({ "day": day }), ttl);
}

/// 发一条活跃上报并回读连登天数。
///
/// 返回 `Ok(sent=false)` 表示今天已经报过（按天幂等，不必再打上游）；`Err` 只表示
/// **这一次没报成**（网络 / 凭证 / 缺 uid），调用方按「附加收益失败」处理，绝不影响
/// 签到结果。
pub fn report(account: &GrowthAccount) -> Result<DailyActivityReport, String> {
    // 缺 userId 时上游回 200 但静默丢弃事件（实测），等于白发一发 ——
    // 与其装作成功，不如把原因交回调用方记日志。
    if account.uid.trim().is_empty() {
        return Err("会话缺少账号 uid，无法上报活跃".to_string());
    }
    if reported_today(&account.uid) {
        return Ok(DailyActivityReport {
            sent: false,
            streak_days: None,
        });
    }
    events::report_chat_send(account, false)?;
    // 成功才记忆：失败留给同一天的下一条入口补发
    mark_reported(&account.uid);
    Ok(DailyActivityReport {
        sent: true,
        // 只读回读（上报 200 ≠ 计分：缺 userId 时上游会静默丢弃）；
        // 回读失败不撤销上报结果，只是这一行没有读数
        streak_days: settled_streak(growth_streak(account)),
    })
}

/// 过滤「刚上报、计分还没落地」的竞态读数。
///
/// 实测（2026-10-19，四个真实国内版账号）：上报返回 200 之后立刻读
/// `growth/streak`，偶尔仍拿到**旧的 0**；隔几秒再读才是新值。这个 0 会被调用方
/// 当成「连登 0 天」落库，把前一天已经攒下的天数覆盖掉。
///
/// 处理方式是**不落这个 0**（返回 None = 本次没有可信读数），而不是在这里加 sleep
/// 重试：批量签到是串行的，每个账号多等几秒会让几十个账号的整轮超过管理 API 的
/// 60 秒转发超时 —— 那时后端其实还在跑，前端却已经报错。
fn settled_streak(days: Option<i64>) -> Option<i64> {
    match days {
        Some(0) => None,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_readings_are_dropped() {
        assert_eq!(settled_streak(Some(0)), None);
        assert_eq!(settled_streak(Some(3)), Some(3));
        assert_eq!(settled_streak(None), None);
    }

    #[test]
    fn report_keys_differ_per_day() {
        let key = reported_key("u-1");
        assert!(key.starts_with("workbuddy-daily:u-1:"));
        assert!(key.ends_with(&util::today_key()));
    }
}
