//! QuWork 的每日奖励（签到）、月度赠送（预览）与权益兑换。
//!
//! ── 「先查后领、未知不重提」这条纪律 ────────────────────────
//! native 的台账状态机逐条照搬：
//! ```text
//!   查到已领 / 台账 claimed          → done（不提交）
//!   不可领 / 已过重置时刻            → inactive
//!   台账 confirming（上次结果未确认） → inactive + 提示稍后查询，绝不重复提交
//!   否则                             → 先写 confirming，再 POST 领取
//!     ├─ granted=true                → claimed，台账改 claimed
//!     ├─ 回查已是 claimed            → done，台账改 claimed
//!     ├─ 明确被拒（4xx / success=false）→ rejected + 报错文案
//!     └─ 其余                        → inactive（待确认）
//! ```
//! 台账在 wasm 侧走宿主 `ledger.get` / `ledger.put`（能力 `accounts.cas.v1`），
//! 与 native 的 `ctx.ledger_get/put` 同一语义：按账号 + 名称存取。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::{account, refresh, upstream};

/// 每日奖励的台账名称。
const LEDGER: &str = "quworkDailyReward";

/// 一次每日奖励状态读数。
pub struct Status {
    pub claimed: bool,
    pub can_claim: bool,
    pub points: f64,
    pub streak: u32,
    pub reset_at: i64,
}

/// 查一次每日奖励状态（字段缺一个都算格式异常，不猜）。
fn status() -> Result<Status> {
    let reply = refresh::protected("GET", upstream::DAILY_STATUS_PATH, None)?;
    let data = reply.data("每日奖励查询")?;
    let invalid = || Error::http(502, "QuWork 每日奖励状态格式异常，未提交领取");
    Ok(Status {
        claimed: data.get("claimed").and_then(Value::as_bool).ok_or_else(invalid)?,
        can_claim: data.get("can_claim").and_then(Value::as_bool).ok_or_else(invalid)?,
        points: upstream::number(data.get("points")).ok_or_else(invalid)?,
        streak: data
            .get("consecutive_days")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(invalid)?,
        reset_at: upstream::timestamp(data.get("next_refresh_at")).ok_or_else(invalid)?,
    })
}

/// 台账里这一轮（按重置时刻区分）记的状态。
fn saved_state(status: &Status) -> &'static str {
    let saved = sdk::host("ledger.get", json!({ "kind": LEDGER })).unwrap_or(Value::Null);
    // 宿主可能把值包在 `value` 里，两种形态都认。
    let saved = saved.get("value").cloned().unwrap_or(saved);
    if saved.get("resetAt").and_then(Value::as_i64) != Some(status.reset_at) {
        return "";
    }
    match saved.get("state").and_then(Value::as_str) {
        Some("confirming") => "confirming",
        Some("claimed") => "claimed",
        _ => "",
    }
}

fn put_ledger(value: Value) -> Result<()> {
    sdk::host("ledger.put", json!({ "kind": LEDGER, "value": value })).map(|_| ())
}

/// 一次领取的回应（`checkin.claim` 的形状）。
fn report(outcome: &str, status: Option<&Status>, message: &str, points: Option<f64>, retry_at: Value) -> Value {
    json!({
        "outcome": outcome,
        "credit": points.map(|points| format!("{points} 积分")),
        "streak": status.map(|status| status.streak),
        "message": message,
        "retryAt": retry_at,
    })
}

/// `checkin.claim`：每日奖励。
pub fn checkin() -> Result<Value> {
    let before = status()?;
    let saved = saved_state(&before);
    if before.claimed || saved == "claimed" {
        return Ok(report("done", Some(&before), "QuWork 今日奖励已领取", None, Value::Null));
    }
    if !before.can_claim || before.reset_at <= sdk::now() {
        return Ok(report("inactive", Some(&before), "QuWork 当前没有可领取的每日奖励", None, Value::Null));
    }
    if saved == "confirming" {
        return Ok(report(
            "inactive",
            Some(&before),
            "QuWork 上次领取结果待确认，请稍后查询；不会重复提交领取",
            None,
            Value::Null,
        ));
    }
    put_ledger(json!({ "resetAt": before.reset_at, "state": "confirming", "at": sdk::now() }))?;
    let secret = refresh::ensure(false)?;
    let access = account::require_login(&secret)?;
    let response = upstream::request("POST", upstream::DAILY_CLAIM_PATH, &access, None);
    if let Ok(reply) = &response {
        if let Ok(data) = reply.data("每日奖励领取") {
            if data.get("granted").and_then(Value::as_bool) == Some(true) {
                let points = upstream::number(data.get("points"));
                let streak = data
                    .get("consecutive_days")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(before.streak);
                let granted = Status { streak, ..before };
                let _ = put_ledger(json!({ "resetAt": granted.reset_at, "state": "claimed" }));
                return Ok(report("claimed", Some(&granted), "QuWork 每日奖励领取成功", points, Value::Null));
            }
        }
    }
    if let Ok(after) = status() {
        if after.claimed && after.reset_at == before.reset_at {
            let _ = put_ledger(json!({ "resetAt": before.reset_at, "state": "claimed" }));
            return Ok(report("done", Some(&after), "QuWork 已确认今日奖励到账", None, Value::Null));
        }
    }
    if let Ok(reply) = response {
        let rejected = (400..500).contains(&reply.status) && reply.status != 408
            || ((200..300).contains(&reply.status)
                && reply.body.get("success").is_some()
                && !upstream::success(reply.body.get("success")));
        if rejected {
            let _ = put_ledger(json!({ "resetAt": before.reset_at, "state": "rejected" }));
            // 明确被拒：把上游文案原样报出去（换账号救不了这种失败）。
            let message = upstream::message(&reply.body);
            return Ok(report(
                "failed",
                Some(&before),
                if message.is_empty() { "QuWork 每日奖励未领取" } else { &message },
                None,
                Value::Null,
            ));
        }
    }
    Ok(report(
        "inactive",
        Some(&before),
        "QuWork 领取结果待确认，请稍后查询；不会重复提交领取",
        None,
        Value::Null,
    ))
}

/// 一条每日奖励的活动视图。
fn daily_view(status: &Status, saved: &str) -> Value {
    json!({
        "campaignId": format!("daily:{}", status.reset_at),
        "title": "QuWork 每日奖励",
        "titleEn": "QuWork daily reward",
        "description": "与每日签到共用领取状态，不会重复领取。",
        "descriptionEn": "Shares its claim state with daily check-in; rewards are never claimed twice.",
        "amount": status.points,
        "unit": "积分",
        "status": if status.claimed || saved == "claimed" {
            "claimed"
        } else if saved == "confirming" {
            "confirming"
        } else if status.can_claim {
            "claimable"
        } else {
            "ineligible"
        },
        "startsAt": Value::Null,
        "endsAt": status.reset_at,
        "claimedAt": Value::Null,
        "expiresAt": Value::Null,
        "validDays": Value::Null,
    })
}

/// 月度赠送记录（`monthly-gifts`）。
fn monthly_rows() -> Result<Vec<Value>> {
    let reply = refresh::protected("GET", upstream::MONTHLY_GIFTS_PATH, None)?;
    let data = reply.data("月度赠送查询")?;
    if !data.is_object() {
        return Err(Error::http(502, "QuWork 月度赠送记录格式异常"));
    }
    let mut rows = Vec::new();
    let Some(list) = data.get("list").filter(|value| !value.is_null()) else {
        return Ok(rows);
    };
    let orders = list
        .as_array()
        .filter(|orders| orders.len() <= 100)
        .ok_or_else(|| Error::http(502, "QuWork 月度赠送记录格式异常"))?;
    for order in orders {
        let id = order
            .get("order_id")
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| value.as_u64().map(|value| value.to_string()))
            })
            .unwrap_or_default();
        for (index, period) in order
            .get("periods")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(120)
            .enumerate()
        {
            let gift = upstream::number(period.get("gift_status")).map(|value| value as i64);
            rows.push(json!({
                "id": format!("{id}:{index}"),
                "orderId": id,
                "period": index + 1,
                "amount": upstream::number(period.get("points")).or_else(|| upstream::number(period.get("quota"))),
                "scheduledAt": upstream::timestamp(period.get("expected_gift_date")),
                "grantedAt": upstream::timestamp(period.get("actual_gift_date")),
                "status": match gift {
                    Some(1) => "pending",
                    Some(2) => "granted",
                    Some(3) => "failed",
                    Some(4) => "cancelled",
                    Some(5) => "processing",
                    _ => "unknown",
                },
            }));
        }
    }
    Ok(rows)
}

/// `claim.status`：可领活动清单（每日奖励 + 月度赠送）。
pub fn preview() -> Result<Value> {
    let secret = refresh::ensure(false)?;
    if account::text(&secret, &["accessToken"]).is_empty() {
        return Err(Error::http(401, "QuWork 需要完整登录态（accessToken）才能查询奖励"));
    }
    let mut notices: Vec<String> = Vec::new();
    let campaigns = match status() {
        Ok(status) => vec![daily_view(&status, saved_state(&status))],
        Err(error) => {
            notices.push(error.message);
            Vec::new()
        }
    };
    let monthly_gifts = match monthly_rows() {
        Ok(rows) => Some(rows),
        Err(error) => {
            notices.push(error.message);
            None
        }
    };
    Ok(json!({
        "campaigns": campaigns,
        "riskNote": Value::Null,
        "monthlyGifts": monthly_gifts,
        "notice": notices.join("；"),
        "redemption": { "supported": true },
    }))
}

/// `claim`：按活动 id 领取（只认当前这一轮的每日奖励）。
pub fn claim(params: &Value) -> Result<Value> {
    let id = params["campaignId"]
        .as_str()
        .or_else(|| params["id"].as_str())
        .unwrap_or("")
        .to_string();
    let before = status()?;
    if id != format!("daily:{}", before.reset_at) {
        return Ok(json!({ "campaignId": id, "outcome": "inactive", "campaign": Value::Null }));
    }
    let result = checkin()?;
    let outcome = match result["outcome"].as_str().unwrap_or("") {
        "claimed" => "claimed",
        "done" => "already_claimed",
        "inactive" => "inactive",
        _ => "failed",
    };
    let latest = status();
    let current = latest.as_ref().unwrap_or(&before);
    let saved = saved_state(current);
    Ok(json!({
        "campaignId": id,
        "outcome": if saved == "confirming" && !current.claimed { "confirming" } else { outcome },
        "campaign": daily_view(current, saved),
        "message": result["message"].clone(),
    }))
}

/// `admin.action = benefits.redeem`：权益兑换（订单号）或邀请码激活。
pub fn redeem(params: &Value) -> Result<Value> {
    let payload = &params["payload"];
    let code = account::text(payload, &["code"]);
    if code.is_empty() || code.len() > 32 || code.chars().any(char::is_control) {
        return Err(Error::new("请填写 QuWork 权益兑换码或 16 位订单号"));
    }
    let secret = refresh::ensure(false)?;
    let access = account::require_login(&secret)?;
    let order = code.len() == 16 && code.bytes().all(|byte| byte.is_ascii_digit());
    let device = if order {
        String::new()
    } else {
        let configured = account::text(&secret, &["deviceIdentifier"]);
        if configured.is_empty() {
            return Err(Error::http(
                400,
                "未找到 QuWork 本机设备标识：邀请码激活需要原设备标识，请到官方客户端完成兑换，或在账号里补充 deviceIdentifier",
            ));
        }
        configured
    };
    let key = format!("quworkRedemption:{}", account::fingerprint(&code));
    let previous = sdk::host("ledger.get", json!({ "kind": key })).unwrap_or(Value::Null);
    let previous = previous.get("value").cloned().unwrap_or(previous);
    match previous.get("state").and_then(Value::as_str) {
        Some("succeeded") => return Ok(json!({ "outcome": "already_claimed" })),
        Some("confirming") => return Ok(json!({ "outcome": "confirming" })),
        _ => {}
    }
    sdk::host("ledger.put", json!({ "kind": key, "value": { "state": "confirming", "at": sdk::now() } }))?;
    let body = if order {
        json!({ "order_id": code })
    } else {
        json!({
            "invite_code": code,
            "device_identifier": device,
            "device_uuid": account::text(&secret, &["deviceUuid"]),
        })
    };
    let path = if order { upstream::REDEEM_PATH } else { upstream::ACTIVATE_PATH };
    let response = upstream::request("POST", path, &access, Some(&body));
    let (state, outcome, message) = match response {
        Ok(reply) if reply.ok() => ("succeeded", "claimed", String::new()),
        Ok(reply)
            if (400..500).contains(&reply.status) && reply.status != 408
                || ((200..300).contains(&reply.status)
                    && reply.body.get("success").is_some()
                    && !upstream::success(reply.body.get("success"))) =>
        {
            let message = upstream::message(&reply.body).replace(&code, "[已隐藏]");
            ("rejected", "failed", message)
        }
        _ => ("confirming", "confirming", String::new()),
    };
    let _ = sdk::host("ledger.put", json!({ "kind": key, "value": { "state": state, "at": sdk::now() } }));
    Ok(json!({ "outcome": outcome, "message": message }))
}
