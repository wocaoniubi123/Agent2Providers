//! 每日签到（`checkin.claim`）：**读一次登录信息就是签到**。
//!
//! ── 本家为什么没有「签到接口」────────────────────────────────
//! 魔搭的当日魔粒是「打开网页站 / 读一次 `users/login/info`」时发放的，没有
//! 单独的领取端点。所以签到 = 打一次登录信息，然后**去流水里确认**：
//! 返回的那一发只给身份，不给「今天领没领到」。
//!
//! ── 三条不能想当然的口径（每一条都对应一次实测）──────────────
//!   1. **完成状态必须由当日发放流水确认**，不能拿登录接口的返回值当结论 ——
//!      它只回身份字段；
//!   2. **可用余额还会受消费、冻结和过期影响**，不能拿「签到前后的余额差」
//!      当领取金额 —— 只有流水里 `daily_active` 那笔涨了多少才是真的领到多少；
//!   3. **发放可能异步入账**：打完登录信息后立刻读流水可能还看不到那一笔。
//!      这里最多再确认 3 轮（每轮间隔 2 秒）；仍确认不到就如实报 `failed`
//!      让宿主稍后重试，而不是把「登录已触达」说成「已签到」。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::transactions::{self, Transactions};
use super::{account, time, upstream, usage};

pub const LOGIN_INFO_PATH: &str = "/api/v1/users/login/info";

/// 签到确认的轮数上限（第一轮立刻读，后面两轮各等 2 秒）。
const CONFIRM_ROUNDS: usize = 3;
/// 两轮确认之间的等待（毫秒）。
const CONFIRM_DELAY_MS: u64 = 2000;

/// `checkin.claim` 的实现。
pub fn claim() -> Result<Value> {
    let token = account::ensure()?;
    let day = time::today_key()
        .ok_or_else(|| Error::new("读不到宿主时钟，无法确认北京日期"))?;

    // ① 先看今天是不是已经签过 / 流水够不够判断
    let before = transactions::read(&token, &day)?;
    if before.signed_on(&day) {
        return Ok(confirmed("done", &before, None, &day));
    }
    if !before.complete {
        return Ok(json!({
            "outcome": "failed",
            "credit": Value::Null,
            "streak": Value::Null,
            "message": "发放流水尚未读全，暂不触发签到，请稍后重试",
        }));
    }

    // ② 读登录信息（这一发就是「签到」本身）
    upstream::site_json(&token, LOGIN_INFO_PATH, "每日签到")?;

    // ③ 流水确认（异步入账，最多三轮）
    let mut observed_day = day.clone();
    for attempt in 0..CONFIRM_ROUNDS {
        if attempt > 0 {
            sdk::sleep(CONFIRM_DELAY_MS)?;
        }
        let Some(current) = time::today_key() else {
            // 时钟读不到就没法判断「今天」，再等也不会变好
            break;
        };
        observed_day = current;
        let after = transactions::read(&token, &observed_day)?;
        if after.signed_on(&observed_day) {
            // 跨过午夜时「今天」变了，前后两次读数不可比 —— 只报已确认，不报金额
            let gained = if observed_day == day {
                after.daily_increase(&before, &day)
            } else {
                None
            };
            // `confirmed` 按「有没有真涨」自己拼 credit 与文案，这里只决定档位：
            // 涨了 = 这次真的领到（claimed），只确认到已签 = 今天早就签过（done）。
            let outcome = if gained.is_some() { "claimed" } else { "done" };
            let mut report = confirmed(outcome, &after, gained, &observed_day);
            // 余额只是给文案补一句「现在还剩多少」，读失败不影响签到结论
            if let Ok(Some(balance)) = usage::current_balance(&token) {
                if let Some(message) = report
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                {
                    report["message"] = json!(format!(
                        "{message}（当前 {} 魔粒）",
                        transactions::amount_text(balance)
                    ));
                }
            }
            return Ok(report);
        }
    }

    Ok(json!({
        "outcome": "failed",
        "credit": Value::Null,
        "streak": Value::Null,
        "message": format!("登录已触达，但 {observed_day} 的签到发放尚未确认，稍后重试"),
    }))
}

/// 已确认的签到报告。
///
/// `gained` 是这次**真的**涨了多少（`None` = 确认不到金额：可能今天早就签过、
/// 也可能是跨午夜前后不可比）。文案要把这两种「没有金额」的情形分开说。
fn confirmed(outcome: &str, ledger: &Transactions, gained: Option<f64>, day: &str) -> Value {
    let message = match gained {
        Some(amount) => format!("已确认领取 {} 魔粒", transactions::amount_text(amount)),
        None => match ledger
            .complete
            .then(|| ledger.total_on(day, true))
            .flatten()
        {
            Some(amount) => format!(
                "今日签到已确认，日常发放共 {} 魔粒",
                transactions::amount_text(amount)
            ),
            None => "今日签到已确认，发放金额未读全".to_string(),
        },
    };
    json!({
        "outcome": outcome,
        "credit": gained.map(|amount| format!("+{} 魔粒", transactions::amount_text(amount))),
        "streak": Value::Null,
        "message": message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::transactions::Grant;

    fn ledger(grants: Vec<Grant>) -> Transactions {
        Transactions {
            grants,
            raw: Vec::new(),
            complete: true,
        }
    }

    fn grant(rule: &str, amount: f64) -> Grant {
        Grant {
            day: "2026-11-19".to_string(),
            rule: rule.to_string(),
            title: "魔粒发放".to_string(),
            amount: Some(amount),
            expires_at: None,
        }
    }

    /// 有金额：文案说「已确认领取」，credit 带「+N 魔粒」。
    #[test]
    fn a_confirmed_amount_is_reported_as_claimed() {
        let report = confirmed(
            "claimed",
            &ledger(vec![grant("daily_active", 30.0)]),
            Some(30.0),
            "2026-11-19",
        );
        assert_eq!("claimed", report["outcome"].as_str().unwrap_or_default());
        assert_eq!("+30 魔粒", report["credit"].as_str().unwrap_or_default());
        assert!(report["message"]
            .as_str()
            .unwrap_or_default()
            .contains("已确认领取 30 魔粒"));
    }

    /// 没有金额但流水读全：用当日日常发放合计说清楚。
    #[test]
    fn a_done_checkin_reports_the_daily_total() {
        let report = confirmed(
            "done",
            &ledger(vec![grant("daily_active", 25.0), grant("aliyun_bindlogin", 5.0)]),
            None,
            "2026-11-19",
        );
        assert_eq!("done", report["outcome"].as_str().unwrap_or_default());
        assert!(report["credit"].is_null());
        assert_eq!(
            "今日签到已确认，日常发放共 30 魔粒",
            report["message"].as_str().unwrap_or_default()
        );
    }

    /// 流水没读全时，文案老实说「发放金额未读全」，不编数字。
    #[test]
    fn an_incomplete_ledger_never_invents_an_amount() {
        let incomplete = Transactions {
            grants: Vec::new(),
            raw: Vec::new(),
            complete: false,
        };
        let report = confirmed("done", &incomplete, None, "2026-11-19");
        assert_eq!(
            "今日签到已确认，发放金额未读全",
            report["message"].as_str().unwrap_or_default()
        );
    }
}
