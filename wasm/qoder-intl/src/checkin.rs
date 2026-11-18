//! Qoder **国际版**每日签到（campaign 领取链路；两段拉取 + 设备风控身份）。
//!
//! ── 上游长什么样（native 在真实账号上实测，2026-09-27）────────────
//! 每日权益以**活动（campaign）**形式下发，走 `sash` 一族接口：
//! `GET {openapi}/sash/api/v1/me/campaigns?forceRefresh=true`，
//! 领取是 `POST …/{campaignId}/claim`。领取返回
//! `{"status":"CLAIMED","replayed":false,"benefit":{…,"amount":100}}`，
//! 额度落在 `/api/v2/quota/usage` 的 `addOnQuota` 桶里（余额面板「资源包」那一行）。
//! 领取后活动行**不消失**，`claimStatus` 由 `CLAIMABLE` 变 `CLAIMED` —— 所以
//! 「今天已领取」直接从活动列表读，不需要本地记账。
//!
//! ── 国际版为什么要风控身份（issue #140，CreditDaddy 实测结论）──────
//! 国际版服务端**只对带设备风控头**（`Cosy-MachineToken` / `Cosy-MachineCode` /
//! `Cosy-MachineType`）的请求下发「每天领 100 Credits」活动；不带时活动列表里
//! 永远只有 `VIEW_DETAILS` 促销。那三个头由 Qoder 的 UMID 组件在本机生成 ——
//! native 自己起子进程，本包改走**网关宿主通道**（见 `risk.rs`）。所以这里
//! 只需要把 `CampaignSession.risk_note`（没带上头的原因）如实转成文案。
//!
//! ── 为什么还要判「窗口」──────────────────────────────────────
//! 官方文档：每日 100 Credits 的窗口每天 **10:00（UTC+8）** 开启。窗口没开时
//! 上游本来就不下发活动 —— 把它报成「没有可领的」会让用户以为账号有问题。
//! 因此窗口未开单独给一句说明；窗口开了一小时后仍没有，就是「**今天**没有
//! 可领的」（native 的 `RETRY_GRACE_MS` 同一条结论：上游当天不会变了）。
//!
//! ── legacy 的 daily-check-in 一次都不碰 ───────────────────────
//! `GET /sash/api/v1/me/daily-check-in/status` 在国际版直接 404，它的 claim
//! 兄弟端点已被上游全局停用。所以这里**只读活动列表**。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::auth;
use super::claims::{self, campaign_time, CampaignSession, STATUS_CLAIMABLE, STATUS_CLAIMED};

/// 上游没给 `benefit.amount` 时的缺省奖励额（实测就是 100）
const DEFAULT_REWARD: f64 = 100.0;

/// 「窗口已开、上游还没给这个账号下发活动」时的自动重试间隔（native 同值）。
const RETRY_GAP_MS: i64 = 10 * 60_000;

/// 「窗口已开但上游没下发」的**宽限截止点**：窗口开启后 1 小时。
///
/// ── 为什么必须有个头（native 2026-10 的修复，原样带过来）──────────
/// 无上限的 `retryAt` 会让签到记录里堆几十条「未领取」，而实情是「上游当天
/// 就是没给这个账号派活动」—— 再问一百次也不会变。窗口后留 1 小时足够覆盖
/// 上游延迟下发，之后给终态。
const RETRY_GRACE_MS: i64 = 60 * 60_000;

/// 国际版的每日签到窗口起点：当天 10:00（UTC+8）对应的毫秒时间戳。
///
/// 算法与 native 逐字一致：把时间平移到 UTC+8、按天取整、再加 2 小时
/// （UTC+8 的 10:00 = 当天 UTC 02:00）。
fn daily_window_start() -> i64 {
    (sdk::now() + 8 * 3_600_000).div_euclid(86_400_000) * 86_400_000 + 2 * 3_600_000
}

/// Qoder 国际版的每日签到。
///
/// 返回网关的 `CheckinReport` 形状（`outcome` / `message` / `credit`）：
///   - 领到 → `outcome: "claimed"`，`message` 带金额与有效期；
///   - 今天已领 → `outcome: "done"` + 「今日已领取」；
///   - 没有活动 / 窗口未开 / 缺风控组件 → `outcome: "inactive"` + 如实说明。
pub fn claim() -> Result<Value> {
    if sdk::now() < daily_window_start() {
        return Ok(no_claim(false, None));
    }
    let session = claims::load()?;
    claim_from(session)
}

fn claim_from(session: CampaignSession) -> Result<Value> {
    let rows = session
        .list
        .get("campaigns")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "Qoder 国际版签到活动响应缺少 campaigns，未确认领取状态"))?;

    let now = sdk::now();
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
        // 国际版只认**本窗口**（今天 10:00 之后开始）的活动：更早的活动是
        // 昨天那条的残留，领了也不算今天。
        if campaign_time(row.get("startAt")).is_some_and(|start| start < daily_window_start()) {
            continue;
        }
        match row.get("claimStatus").and_then(Value::as_str) {
            Some(STATUS_CLAIMABLE) if claimable.is_none() => claimable = Some(row),
            Some(STATUS_CLAIMED) => claimed = true,
            _ => {}
        }
    }

    let Some(target) = claimable else {
        return Ok(no_claim(claimed, session.risk_note.clone()));
    };
    let campaign_id = target.get("campaignId").and_then(Value::as_str).unwrap_or("");
    if campaign_id.is_empty() {
        return Err(Error::http(502, "Qoder 国际版签到活动缺少活动标识，无法领取"));
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

/// 「这次没领到」的结果：依次区分「今天已领」「缺风控身份」「窗口未开」
/// 「宽限期内再试」「今天不再重试」。
///
/// 文案口径照抄 native `checkin.rs::no_claim` 的国际版分支 —— 那里每一条都对应
/// 一次实测结论，措辞改了用户就看不出「该装组件」还是「该等窗口」。
fn no_claim(claimed: bool, risk_note: Option<String>) -> Value {
    if claimed {
        return json!({ "outcome": "done", "message": "今日已领取" });
    }
    if let Some(note) = risk_note {
        return json!({
            "outcome": "inactive",
            "message": format!(
                "未领取：{note}。国际版签到需要本机安装 Qoder 客户端或 qodercli（Linux 可在签到中心一键安装组件）"
            ),
            "riskNote": note,
        });
    }
    let now = sdk::now();
    let window = daily_window_start();
    if now < window {
        return json!({
            "outcome": "inactive",
            "message": "每日积分活动窗口还没开启（每天 10:00 开启），到点再试",
        });
    }
    if now < window + RETRY_GRACE_MS {
        return json!({
            "outcome": "inactive",
            "message": format!(
                "上游暂未给该账号下发每日积分活动，{} 分钟后再试",
                RETRY_GAP_MS / 60_000
            ),
        });
    }
    json!({
        "outcome": "inactive",
        "message": "该账号今天没有可领取的每日积分活动（上游未下发，与本机环境无关），今天不再重试",
    })
}
