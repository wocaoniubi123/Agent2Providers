//! Qoder 每日签到（campaign 领取链路；本包只做中国版）。
//!
//! ── 上游长什么样（2026-09-27 在真实账号上实测）────────────────
//! 每日权益以**活动（campaign）**形式下发：中国版 Pro Trial 账号的活动窗口
//! `startAt → endAt` 是**当天 10:00 → 次日 09:59**（UTC+8），与官方客户端
//! 「每天 10:00 刷新」一致；领取返回
//! `{"status":"CLAIMED","replayed":false,"benefit":{...,"amount":100}}`，
//! 紧接着查 `/api/v2/quota/usage`，`addOnQuota` 从「上游不返回该键」变成
//! `{total:100, remaining:100, unit:"credits"}` —— **签到额度落在 `addOnQuota`
//! 这个桶里**（余额面板「资源包」那一行，见 `usage.rs`）。
//!
//! ── 国际版那套为什么不迁 ───────────────────────────────────
//! native 的 `checkin.rs` 里有一大段「带 UMID 设备风控头两段拉取」的分支
//! （`risk.rs`，靠本机子进程生成 `Cosy-MachineToken`）。那只服务
//! `qoder-intl`：中国版不需要风控头就能领。`risk.rs` 整体不迁（依赖子进程与
//! 文件系统，wasm 里做不了），`checkin.claim` 因此只走中国版那一条直领路径。
//!
//! ── 没有签到活动的账号 ─────────────────────────────────────
//! 中国版 Free 套餐实测没有活动下发（Pro/试用才有）：返回一条中性结果
//! （`outcome: "inactive"` + 说明），不是错误 —— 上游给不给活动是账号侧状态。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::auth;
use super::claims::{self, campaign_time, CampaignSession, STATUS_CLAIMABLE, STATUS_CLAIMED};

/// 上游没给 `benefit.amount` 时的缺省奖励额（实测就是 100）
const DEFAULT_REWARD: f64 = 100.0;

/// Qoder 中国版的每日签到。
///
/// 返回 `CheckinReport` 形状：`success` 的口径是「**本次真的领到了**」：
///   - 领到 → `outcome: "claimed"`，`message` 带金额与有效期，`credit` 给
///     「100 credits」（界面显示「本次 +N」）；
///   - 今天已领 → `outcome: "done"` + 「今日已领取」；
///   - 没有活动 → `outcome: "inactive"` + 「当前没有可领取的签到活动」。
pub fn claim() -> Result<Value> {
    let session = claims::load()?;
    claim_from(session)
}

fn claim_from(session: CampaignSession) -> Result<Value> {
    let rows = session
        .list
        .get("campaigns")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "Qoder 签到活动响应缺少 campaigns，未确认领取状态"))?;

    let now = agent2api_wasm_sdk::now();
    let mut claimable: Option<&Value> = None;
    let mut claimed = false;
    for row in rows {
        if !claims::is_daily(row) {
            continue;
        }
        if campaign_time(row.get("startAt")).is_some_and(|start| start > now)
            || campaign_time(row.get("endAt")).is_some_and(|end| end <= now)
        {
            continue;
        }
        match row.get("claimStatus").and_then(Value::as_str) {
            Some(STATUS_CLAIMABLE) if claimable.is_none() => claimable = Some(row),
            Some(STATUS_CLAIMED) => claimed = true,
            _ => {}
        }
    }

    let Some(target) = claimable else {
        return Ok(no_claim(claimed));
    };
    let campaign_id = target.get("campaignId").and_then(Value::as_str).unwrap_or("");
    if campaign_id.is_empty() {
        return Err(Error::http(502, "Qoder 签到活动缺少活动标识，无法领取"));
    }

    let response = claims::submit(&session, campaign_id)?;
    // 409 只有带 ALREADY_CLAIMED 才能证明已领；401 交给 SDK 统一刷新重试一次。
    if matches!(response.status, 200..=299 | 409)
        && result_of(&response).as_deref() == Some(claims::RESULT_ALREADY_CLAIMED)
    {
        return Ok(json!({ "outcome": "done", "message": "今日已领取" }));
    }
    let body = claims::unwrap_data(auth::payload(response, "签到领取")?);

    if body.get("status").and_then(Value::as_str) != Some(STATUS_CLAIMED) {
        let status = body.get("status").and_then(Value::as_str).unwrap_or("未知");
        return Ok(json!({
            "outcome": "failed",
            "message": format!("签到未完成（上游状态 {status}）"),
        }));
    }
    if body.get("replayed").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(json!({ "outcome": "done", "message": "今日已领取" }));
    }

    let reward = body
        .get("benefit")
        .and_then(|benefit| benefit.get("amount"))
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_REWARD);
    let valid_days = body
        .get("benefit")
        .and_then(|benefit| benefit.get("validity"))
        .and_then(|validity| validity.get("days"))
        .and_then(Value::as_f64);
    // 文案不重复「签到成功」：调用方已经用它作日志前缀，这里只说领到了什么
    let message = match valid_days {
        Some(days) if days > 0.0 => format!("获得 {reward} credits，{days} 天有效"),
        _ => format!("获得 {reward} credits"),
    };
    Ok(json!({
        "outcome": "claimed",
        "message": message,
        "credit": format!("{reward} credits"),
    }))
}

/// 领取响应的 `result` 字段（并发/重放标记），拿不到给 None。
fn result_of(response: &auth::ApiResponse) -> Option<String> {
    let payload = response.payload.as_ref()?;
    let body = payload.get("data").filter(|value| value.is_object()).unwrap_or(payload);
    let value = body.get("result")?.as_str()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// 「这次没领到」的结果：区分「今天已领」与「没有可领的活动」。
///
/// 中国版没有活动是账号侧状态（实测 Free 套餐账号如此，Pro/试用账号才有），
/// 明确说「没有可领的」而不是报错。
fn no_claim(claimed: bool) -> Value {
    if claimed {
        return json!({ "outcome": "done", "message": "今日已领取" });
    }
    json!({
        "outcome": "inactive",
        "message": "当前没有可领取的签到活动",
    })
}
