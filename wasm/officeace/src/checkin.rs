//! 签到：只触发当天奖励结算，**不代替**套餐开通或协议确认。
//!
//! ── 一次 claim 全领 ─────────────────────────────────────────
//! `POST /v1/subscription/bonus/claim` 是「立即触发今天的结算」：上游按天结算一批
//! （官方客户端每小时自动打这一发），已在官方客户端结算过时返回空列表
//! `{"bonus_skus": []}`。所以签到与新手任务是**同一个上游动作**，幂等由上游保证。
//!
//! ── 为什么签到前要先查一次订阅 ──────────────────────────────
//! 未开通 / 已到期 / 被冻结的账号去 claim，上游只会给一句模糊的拒绝。先读
//! `subscribe_status` 能把三种情形分开，用户拿到的下一步动作完全不同（去开通 /
//! 去官方客户端 / 直接重试）。
//!
//! ── 台账（`dailyCheckin`）在这个动作里干什么 ────────────────
//! 只回答「今天经本网关签到过没有」。上游的 `success: true` 覆盖两种情形（真的
//! 领到 / 今天已领过），所以 `gained` 为 0 时要归 `done` 而不是 `claimed` —— 那
//! 决定调度链要不要记一笔「今天签到了」。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{control, subscription, util};

/// 签到台账的键名（`ledger.get` / `ledger.put` 的 `kind`）。
pub const LEDGER_KIND: &str = "dailyCheckin";

/// 签到结果 → 协议档位（`checkin.claim` 的返回）。
///
/// 本家的 `success: true` 覆盖两种情形（真的领到 / 今天已领过），所以 `gained`
/// 为 0 时要归 `Done` 而不是 `Claimed`。
pub fn claim() -> Result<Value> {
    let previous = control::ledger_get(LEDGER_KIND);
    let result = claim_inner();
    let (completed, status, message) = match &result {
        Ok(value) => (
            true,
            if value.get("gained").and_then(Value::as_f64).unwrap_or(0.0) > 0.0 {
                "claimed"
            } else {
                "done"
            },
            value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("已签到")
                .to_string(),
        ),
        Err(error) => (false, "failed", error.message.clone()),
    };
    let already_completed = previous
        .get("completed")
        .and_then(Value::as_bool)
        == Some(true)
        && previous
            .get("at")
            .and_then(Value::as_i64)
            .and_then(util::date_key_of_ms)
            .is_some_and(|day| day == util::beijing_today_key());
    // 之前已经签过、这次又失败：不要把「今天签过了」那条记录改成失败
    if !completed && already_completed {
        return result;
    }
    let daily = json!({
        "kind": "daily",
        "at": util::now_ms(),
        "completed": completed,
        "status": status,
        "message": message,
        "completedCount": usize::from(completed),
        "totalCount": 1,
        "sourcesComplete": completed,
    });
    // 台账写不进去不改签到结果：上游那边可能已经发下来了，把成功报成失败本末倒置
    let _ = control::ledger_put(LEDGER_KIND, &daily);
    result
}

fn claim_inner() -> Result<Value> {
    let mut credential = control::credential_of()?;
    let before = control::subscription_of(&mut credential)?;
    match before.get("subscribe_status").and_then(Value::as_str) {
        Some("UNSUBSCRIBED") => {
            return Err(Error::http(
                409,
                "果办尚未开通体验套餐，请先到签到中心开通零元体验套餐，再领取奖励",
            )
            .with_code("officeace_subscription_required"))
        }
        Some("EXPIRED" | "FROZEN") => {
            return Err(Error::http(
                409,
                "果办套餐已到期或被冻结，请到官方客户端处理；这里不会自动续费",
            ))
        }
        Some("SUBSCRIBED") => {}
        _ => {
            return Err(Error::http(
                502,
                "无法确认果办套餐状态，未执行签到，请先查询套餐",
            ))
        }
    }
    control::resolve_project(&mut credential)?;
    let claimed = control::claim_bonus(&mut credential)?;
    let items = claimed
        .get("bonus_skus")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "官方未返回有效的奖励领取结果，请查询积分后再操作"))?;
    let bonuses = subscription::bonuses_of(&claimed);
    let gained: f64 = bonuses.iter().map(subscription::Bonus::remaining).sum();
    // 条目数与解出来的活动数对不上，说明有我们没认出来的形状 —— 不能报成功
    if items.len() != bonuses.len() || !gained.is_finite() || !items.is_empty() && gained <= 0.0 {
        return Err(Error::http(
            502,
            "官方返回了奖励条目，但未能确认到账积分，请查询积分明细",
        ));
    }
    super::onboarding::mark_claimed(&bonuses);
    let message = if gained > 0.0 {
        format!("已领取 {gained:.0} 积分")
    } else {
        "今天没有可领的奖励（或已领过）".to_string()
    };
    let rewards: Vec<Value> = bonuses
        .iter()
        .map(|bonus| {
            json!({
                "key": bonus.activity_id,
                "title": bonus.name,
                "ok": true,
                "already": false,
                "gained": bonus.remaining(),
            })
        })
        .collect();
    Ok(json!({ "success": true, "msg": message, "gained": gained, "rewards": rewards }))
}

/// 把 `{success, msg, gained}` 翻成网关认的四档结论（`checkin.claim` 的最终形态）。
///
/// 与 [`claim`] 的分工：那个返回本家的原始形状（`onboarding::claim_all` 读它），
/// 这个把它翻成 `{outcome, credit, streak, message}`。
pub fn report_of(claim: &Value) -> Value {
    let success = claim.get("success").and_then(Value::as_bool).unwrap_or(false);
    let message = claim
        .get("msg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let gained = claim
        .get("gained")
        .and_then(Value::as_f64)
        .filter(|points| *points > 0.0);
    let credit = gained.map(|points| format!("{points:.0} 积分"));
    // 没有增量读数（领取前那次查询失败）时按 `success` 判：上游说成了就是成了
    let outcome = if !success {
        "failed"
    } else if gained.is_some() || claim.get("gained").is_none() {
        "claimed"
    } else {
        // `gained: 0` = 今天没有可领的（上游已结算过）
        "done"
    };
    json!({
        "outcome": outcome,
        "credit": credit,
        "streak": Value::Null,
        "message": message,
    })
}

/// `checkin.claim` 的实现入口：跑一次签到并翻成协议档位。
pub fn checkin() -> Result<Value> {
    match claim() {
        Ok(value) => Ok(report_of(&value)),
        Err(error) => Ok(json!({
            "outcome": "failed",
            "credit": Value::Null,
            "streak": Value::Null,
            "message": error.message,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_maps_gained_zero_to_done() {
        let report = report_of(&json!({ "success": true, "msg": "今天没有可领的奖励", "gained": 0.0 }));
        assert_eq!(report["outcome"], json!("done"));
        assert_eq!(report["credit"], Value::Null);
        let report = report_of(&json!({ "success": true, "msg": "已领取 1000 积分", "gained": 1000.0 }));
        assert_eq!(report["outcome"], json!("claimed"));
        assert_eq!(report["credit"], json!("1000 积分"));
        // 没有增量读数时按 success 判
        let report = report_of(&json!({ "success": true, "msg": "已签到" }));
        assert_eq!(report["outcome"], json!("claimed"));
        let report = report_of(&json!({ "success": false, "msg": "套餐已到期" }));
        assert_eq!(report["outcome"], json!("failed"));
        assert_eq!(report["message"], json!("套餐已到期"));
    }
}
