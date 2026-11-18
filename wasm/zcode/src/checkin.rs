//! 每日签到 —— 就是「领当天那份赠送套餐」（native `zcode/checkin.rs` 的移植）。
//!
//! ── 为什么签到就是领取 ──────────────────────────────────────
//! ZCode 没有独立的签到接口，但上游每天给账号下发一份**带日期段的新套餐**
//! （`zcode-v3-start-plan-<日期>` / `zcode-v3-start-plan-1024` 这类），用户在
//! 客户端里点一下就领 —— 那一下就是这一家的「签到」。判据与 `claim.rs` 一致：
//! 同一期再领回 `1003 already claimed`。
//!
//! ── 顺序：补报激活 → 探测 → 领取 ───────────────────────────
//! 资格由激活事件（`app_launch` / `app_daily_active`）发放，而本家不跑官方
//! 客户端，那一步不会自动发生（见 `claim::report_activation`）。所以签到先补报
//! 一次激活再探测，与手动领取那条链同序。
//!
//! ── 窗口判断优先用上游时间 ──────────────────────────────────
//! 官方公告是「每日 19:00 起可领当日赠送额度」，但上游会在 `billing/preview`
//! 的 `plans` 里给出每期活动的 `starts_at` / `ends_at`。本地常量只在「一个套餐
//! 都没探到」时决定文案与 `retryAt` —— 容器 `TZ=UTC` 时本地时钟到不了 19:00，
//! 再把本地常量当唯一判据就会把「活动已经开了」误判成「窗口还没开」。
//!
//! ── 验证 ────────────────────────────────────────────────────
//! 自动签到没有界面可弹验证码：上游回 3007 时如实返回 `captcha`（不写「已领取」、
//! 也不当成「等待活动」重试）。用户手动领取那条路由 `admin.action` 的
//! `claim.claim` 带上界面上解出的 verifyParam。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! `panic = "abort"`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Result, Value};

use super::common::{beijing_datetime, now_ms};
use super::{account, claim, region};

/// 每日窗口的开启时刻（北京时间秒偏移）：**19:00**（见模块头）。
const DAILY_WINDOW_HOUR: i64 = 19;

/// 一轮领取的时间上限（毫秒）：native 用 100 秒，剩余不足 45 秒时收尾。
const ROUND_TIMEOUT_MS: i64 = 100_000;

/// 今天的窗口开启时刻（Unix 毫秒，北京时间口径）。
fn daily_window_start(now: i64) -> i64 {
    let offset = super::common::BEIJING_OFFSET_SECONDS * 1000;
    (now + offset).div_euclid(86_400_000) * 86_400_000 + DAILY_WINDOW_HOUR * 3_600_000 - offset
}

/// 中性未领取（不落「已签到」，按 `retryAt` 稍后重试）。
fn inactive(message: impl Into<String>, retry_at: Option<i64>) -> Value {
    let mut value = json!({
        "success": false,
        "outcome": "inactive",
        "msg": message.into(),
    });
    if let Some(at) = retry_at {
        if let Some(object) = value.as_object_mut() {
            // 网关的重试链只认毫秒；上游给的是秒（`failure_ends_at`），调用方已换算
            object.insert(
                "retryAt".to_string(),
                Value::from(at.max(now_ms() + 600_000)),
            );
        }
    }
    value
}

/// 失败（进 `failed` 台账）。措辞以「读得懂」为准，不暴露协议细节。
fn failed_soft(message: impl Into<String>) -> Value {
    json!({ "success": false, "msg": message.into() })
}

/// 执行一次签到（`checkin.claim`）。
pub fn claim_daily() -> Result<Value> {
    let record = account::require_account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    let jwt = account::jwt(&secret);
    if jwt.trim().is_empty() {
        // 没有套餐 JWT 就没有领取资格：这条链服务的是「网页登录」建的账号，
        // 手工粘贴 API Key 的账号领不了（无人值守路径，措辞要说清这是账号形态）
        return Ok(failed_soft(format!(
            "该 ZCode {}账号没有套餐令牌（jwt），无法领取每日赠送额度；请用网页登录重新添加",
            region::LABEL
        )));
    }
    let device_mid = {
        let existing = account::device_mid(&secret);
        if existing.is_empty() {
            account::device_mid_or_create()?.unwrap_or_default()
        } else {
            existing
        }
    };
    let mid = (!device_mid.trim().is_empty()).then_some(device_mid.as_str());
    let user_id = account::user_id(&secret);

    // ── 1. 补报激活事件（资格的前置动作）──────────────────────
    // 失败不阻断：领取有它自己的路径，且激活事件本来只是「把资格补上」的加试。
    if !user_id.trim().is_empty() {
        let _ = claim::report_activation(&user_id, &device_mid);
    }

    let snapshot = match claim::preview(&jwt, mid, false) {
        Ok(snapshot) => snapshot,
        Err(error) => return Ok(failed_soft(error.message)),
    };
    // ── 2. 用上游 starts_at 判断「开始没有」────────────────────
    let now = now_ms();
    let (plans, upcoming): (Vec<_>, Vec<_>) = snapshot
        .plans
        .into_iter()
        .partition(|plan| plan.starts_at.is_none_or(|start| start.saturating_mul(1000) <= now));
    if plans.is_empty() {
        if let Some(start) = upcoming.iter().filter_map(|plan| plan.starts_at).min() {
            let at = start.saturating_mul(1000);
            let message = match beijing_datetime(at) {
                Some(time) => format!(
                    "今日赠送套餐的活动将于 {} 开始，稍后自动重试",
                    time.format("%m-%d %H:%M")
                ),
                None => "今日赠送套餐的活动窗口还没开（每天 19:00 起可领），稍后自动重试".to_string(),
            };
            return Ok(inactive(message, Some(at + 60_000)));
        }
        if snapshot.preview_error.is_some()
            || snapshot.marketing_error.is_some()
            || snapshot.ownership_error.is_some()
        {
            return Ok(failed_soft(
                "部分套餐来源查询失败，尚不能确认今日领取状态",
            ));
        }
        // 一个套餐都没探到：本地常量兜底（上游没给 starts_at / 活动还没上架）
        let window = daily_window_start(now);
        if now < window {
            return Ok(inactive(
                "今日赠送套餐的活动窗口还没开（每天 19:00 起可领），稍后自动重试",
                Some(window + 60_000),
            ));
        }
        return Ok(inactive("当前没有可领取的赠送套餐", None));
    }
    let expected = plans.len();
    let started = now;
    let mut results: Vec<Value> = Vec::new();
    for plan in &plans {
        if ROUND_TIMEOUT_MS - (now_ms() - started) < 45_000 {
            results.push(inactive(
                "本轮领取时间已用完，剩余套餐稍后继续",
                Some(now_ms() + 600_000),
            ));
            break;
        }
        let attempt = claim::claim_upstream(&jwt, &plan.plan_id, "", None, mid);
        let stop = match &attempt {
            Ok(outcome) => matches!(
                outcome,
                claim::ClaimOutcome::Failed {
                    failure: claim::ClaimFailure::Captcha | claim::ClaimFailure::LoginRequired,
                    ..
                }
            ),
            Err(_) => true,
        };
        results.push(plan_result(&plan.plan_id, &plan.name, attempt));
        if stop {
            break;
        }
    }
    Ok(combine_results(results, expected))
}

/// 单个套餐的领取结果 → 一行结果。
fn plan_result(
    plan_id: &str,
    plan_name: &str,
    attempt: Result<claim::ClaimOutcome>,
) -> Value {
    match attempt {
        Ok(outcome) => match outcome {
            claim::ClaimOutcome::Claimed { ends_at, .. } => {
                let until = ends_at
                    .and_then(|at| beijing_datetime(at.saturating_mul(1000)))
                    .map(|time| time.format("%m-%d %H:%M").to_string());
                let msg = match until {
                    Some(until) => format!("领到「{plan_name}」（{plan_id}），有效期至 {until}"),
                    None => format!("领到「{plan_name}」（{plan_id}）"),
                };
                json!({
                    "success": true,
                    "msg": msg,
                    "planId": plan_id,
                    "planName": plan_name,
                })
            }
            claim::ClaimOutcome::Failed {
                failure,
                code,
                message,
                failure_ends_at,
                ..
            } => match failure {
                claim::ClaimFailure::AlreadyClaimed => json!({
                    "success": false,
                    "alreadyCompleted": true,
                    "msg": format!("「{plan_name}」已领取"),
                    "planId": plan_id,
                }),
                claim::ClaimFailure::Unavailable | claim::ClaimFailure::QuotaExhausted => inactive(
                    format!("「{plan_name}」{}（{code}）：{message}", failure.label()),
                    failure_ends_at.map(|at| at.saturating_mul(1000)),
                ),
                claim::ClaimFailure::Captcha => json!({
                    "success": false,
                    "outcome": "captcha",
                    "planId": plan_id,
                    "planName": plan_name,
                    "msg": format!("「{plan_name}」需要人工验证：请到账号页手动领取"),
                }),
                other => failed_soft(format!(
                    "「{plan_name}」{}（{code}）：{message}",
                    other.label()
                )),
            },
        },
        Err(error) => failed_soft(error.message),
    }
}

/// 多套餐结果汇总（判据与 native `combine_results` 同序）。
fn combine_results(results: Vec<Value>, expected: usize) -> Value {
    let succeeded = results
        .iter()
        .any(|row| row.get("success").and_then(Value::as_bool) == Some(true));
    let completed = !results.is_empty()
        && results.len() == expected
        && results.iter().all(|row| {
            row.get("success").and_then(Value::as_bool) == Some(true)
                || row.get("alreadyCompleted").and_then(Value::as_bool) == Some(true)
        });
    let needs_verification = results
        .iter()
        .any(|row| row.get("outcome").and_then(Value::as_str) == Some("captcha"));
    let pending = results
        .iter()
        .any(|row| row.get("outcome").and_then(Value::as_str) == Some("inactive"));
    let failed = results.iter().any(|row| {
        row.get("success").and_then(Value::as_bool) != Some(true)
            && row.get("alreadyCompleted").and_then(Value::as_bool) != Some(true)
            && !matches!(
                row.get("outcome").and_then(Value::as_str),
                Some("inactive" | "captcha")
            )
    });
    let msg = results
        .iter()
        .filter_map(|row| row.get("msg").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("；");
    let mut result = json!({
        "success": succeeded && completed,
        "alreadyCompleted": !succeeded && completed,
        "msg": msg,
        "outcome": if completed { if succeeded { "claimed" } else { "done" } }
            else if failed { "failed" } else if needs_verification { "captcha" }
            else if pending { "inactive" } else { "failed" },
        "results": results,
    });
    let retry_at = result["results"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .filter_map(|row| row.get("retryAt").and_then(Value::as_i64))
                .min()
        });
    if let Some(at) = retry_at {
        result["retryAt"] = json!(at);
    }
    result
}

/// 签到结果 → 协议 `CheckinReport`（`{outcome, credit, streak, message}`）。
///
/// 判据与 native `checkin_report` 同序：`alreadyCompleted` 优先于 `success`
/// （今天已领要说成 `done` 而不是「刚领到」—— 后者会误导界面播报积分），
/// 中性未领取走 `inactive`（不落账、按 `retryAt` 重试），其余是 `failed`。
pub fn report(value: &Value) -> Value {
    let outcome = if value.get("alreadyCompleted").and_then(Value::as_bool) == Some(true) {
        "done"
    } else if value.get("success").and_then(Value::as_bool) == Some(true) {
        "claimed"
    } else if value.get("outcome").and_then(Value::as_str) == Some("captcha") {
        "captcha"
    } else if value.get("outcome").and_then(Value::as_str) == Some("inactive") {
        "inactive"
    } else {
        "failed"
    };
    let mut report = json!({
        "outcome": outcome,
        // 收益文案已经是人话（「领到「ZCode 1024 Dev Day」…」），直接透出
        "credit": value.get("planName").and_then(Value::as_str),
        "streak": Value::Null,
        "message": value.get("msg").and_then(Value::as_str),
    });
    // 重试时刻与逐套餐明细随汇总一起返回（协议允许透传额外键）
    if let Some(at) = value.get("retryAt").and_then(Value::as_i64) {
        report["retryAt"] = json!(at);
    }
    if let Some(results) = value.get("results") {
        report["details"] = results.clone();
    }
    report
}
