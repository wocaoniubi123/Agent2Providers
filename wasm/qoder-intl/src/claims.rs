//! Qoder 活动（campaign）：只读清单 + 领取请求 + 领取台账（native `campaigns.rs`
//! 与 `benefits.rs` 合并）。
//!
//! 每日签到（`checkin.rs`）与手动福利（本文件的 `claim`）共用同一套鉴权与清单，
//! 但互不代领：签到只领「每日权益」，`claim` 只领上游明确下发的非每日 Credits
//! 活动，不触碰付费促销。
//!
//! ── 上游长什么样（2026-09-27 在真实账号上实测）────────────────
//! ```text
//! GET  {openapi}/sash/api/v1/me/campaigns?forceRefresh=true
//!   → {uid, showCampaign, claimable, campaigns:[{campaignId, campaignKey,
//!        actionType, claimStatus, startAt, endAt,
//!        benefit:{kind:"CREDITS", amount:100,
//!                 validity:{mode:"RELATIVE_DAYS", days:30}}}]}
//! POST {openapi}/sash/api/v1/me/campaigns/{campaignId}/claim   body {}
//!   → {status:"CLAIMED", replayed, benefit:{...}, claimedAt, grantedAt, expiresAt}
//! ```
//! 领取后活动行**不消失**，`claimStatus` 由 `CLAIMABLE` 变 `CLAIMED` —— 所以
//! 「今天已领取」直接从活动列表读，不需要本地记账。顶层的 `claimable` 标志
//! **不能当判据**：领完之后它仍是 `true`（同账号还有一条可领的促销活动）。
//!
//! ── 与 native 的差别：台账存哪 ──────────────────────────────
//! native 用账号台账（`ctx.ledger_get/put`，落盘 JSON）。Wasm 侧用宿主的
//! **账号作用域状态**（`state.get` / `state.compare_exchange`）—— 同样是
//! 「带版本号、比较再写」的持久键值，正好对应 native 台账的语义。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::Credentials;
use super::refresh;
use super::site;

/// 台账在宿主状态里的键名与 schema 版本
const LEDGER_KEY: &str = "qoderCampaignClaims";
const LEDGER_SCHEMA: u32 = 1;

/// 活动状态：可领取
pub const STATUS_CLAIMABLE: &str = "CLAIMABLE";
/// 活动状态：已领取
pub const STATUS_CLAIMED: &str = "CLAIMED";
/// 领取响应的 `result` 字段（上游在并发/重放时会给这个值）
pub const RESULT_ALREADY_CLAIMED: &str = "ALREADY_CLAIMED";

/// 一次活动会话：凭证 + 头束 + 已拉到的清单 + 风控身份缺失的原因
pub struct CampaignSession {
    pub credentials: Credentials,
    pub headers: Vec<(String, String)>,
    pub list: Value,
    /// 风控身份没带上时的原因（进签到结果文案；带上了就是 `None`）
    pub risk_note: Option<String>,
}

/// 拉活动清单（401 时强制续期一次再拉）。
pub fn load() -> Result<CampaignSession> {
    let credentials = refresh::ensure_fresh(false)?;
    match load_with(credentials.clone()) {
        Err(error) if error.status == Some(401) => {
            let credentials = refresh::ensure_fresh(true)?;
            load_with(credentials)
        }
        result => result,
    }
}

/// 拉一次清单，**国际版要两段**（native `campaigns::load_with` 同一口径）。
///
/// ── 为什么必须两段 ──────────────────────────────────────────
/// 国际版服务端只对带设备风控头的请求下发「每日 100 Credits」活动，而风控身份
/// 是按 **uid** 生成的 —— uid 又在活动列表的**顶层字段**里。于是顺序只能是：
/// 先拉一次拿 uid → 叠风控头重拉 → 才可能看到积分活动。第一段拿到的清单在
/// 有风控组件时会被第二段整体替换；没组件时保留第一段并带一句原因回去。
fn load_with(credentials: Credentials) -> Result<CampaignSession> {
    let headers = site::sash_headers(&credentials.access_token);
    let mut list = fetch(&credentials, &headers)?;
    let uid = list.get("uid").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let (headers, risk_note) =
        super::risk::augment_headers(headers, &credentials.access_token, &uid);
    if risk_note.is_none() {
        list = fetch(&credentials, &headers)?;
    }
    Ok(CampaignSession { credentials, headers, list, risk_note })
}

/// 拉一次活动列表，并校验形状。
///
/// ── 为什么这里对形状挑得这么细 ──────────────────────────────
/// 「没领到」与「已经领过」在界面上的动作完全不同（后者按钮要变「已签到」）。
/// 形状不对时返回错误，而不是把一份读不懂的正文当成「今天没有活动」。
pub fn fetch(_credentials: &Credentials, headers: &[(String, String)]) -> Result<Value> {
    let url = format!(
        "{}{}{}",
        site::OPEN_API,
        site::CAMPAIGNS_PATH,
        site::CAMPAIGNS_QUERY
    );
    let response = super::auth::request("GET", &url, None, headers)?;
    let value = unwrap_data(super::auth::payload(response, "活动查询")?);
    if let Some(rows) = value.get("campaigns").and_then(Value::as_array) {
        let mut ids = std::collections::HashSet::new();
        if rows.iter().all(|row| {
            row.is_object()
                && row
                    .get("campaignId")
                    .and_then(Value::as_str)
                    .is_some_and(|id| !id.trim().is_empty() && ids.insert(id.to_string()))
        }) {
            return Ok(value);
        }
    }
    Err(Error::http(502, "活动清单格式异常，未确认领取状态"))
}

/// 提交一次领取。
pub fn submit(session: &CampaignSession, campaign_id: &str) -> Result<super::auth::ApiResponse> {
    let url = format!(
        "{}{}/{}/claim",
        site::OPEN_API,
        site::CAMPAIGNS_PATH,
        campaign_id
    );
    let mut headers = session.headers.clone();
    headers.push(("content-type".to_string(), "application/json".to_string()));
    headers.push(("origin".to_string(), site::OPEN_API.to_string()));
    super::auth::request("POST", &url, Some(&json!({})), &headers)
}

/// 正文可能是 `{data:{…}}` 也可能是 `{data:[…]}`（后者补成 campaigns 数组）。
pub fn unwrap_data(value: Value) -> Value {
    match value.get("data") {
        Some(data) if data.is_object() => data.clone(),
        Some(data) if data.is_array() => json!({ "campaigns": data }),
        _ => value,
    }
}

/// 活动时间戳：秒 / 毫秒数字或 RFC3339 文本，统一成毫秒。
pub fn campaign_time(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(number) = value.as_i64().or_else(|| value.as_str()?.parse().ok()) {
        return (number > 0)
            .then(|| if number < 100_000_000_000 { number.saturating_mul(1000) } else { number });
    }
    chrono::DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .map(|time| time.timestamp_millis())
}

/// 活动文案：优先取官方活动页的 placements（`POPUP` → `USAGE`），再退到顶层字段。
pub fn campaign_text(row: &Value, locale: &str, field: &str) -> String {
    let placements = row.get("placements").and_then(Value::as_array);
    let text = placements.and_then(|placements| {
        ["POPUP", "USAGE"].into_iter().find_map(|kind| {
            placements
                .iter()
                .filter(|placement| placement.get("type").and_then(Value::as_str) == Some(kind))
                .find_map(|placement| {
                    placement
                        .get("content")?
                        .get(locale)?
                        .get(field)?
                        .as_str()
                        .filter(|text| !text.trim().is_empty())
                })
        })
    });
    text.or_else(|| row.get(field).and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 是不是「可领取的 Credits 活动」（所有活动类判定的底座）
pub fn is_credit_benefit(row: &Value) -> bool {
    row.get("actionType").and_then(Value::as_str) == Some("CLAIM_BENEFIT")
        && row.pointer("/benefit/kind").and_then(Value::as_str) == Some("CREDITS")
        && row
            .get("campaignId")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.trim().is_empty())
}

/// 是不是「每日权益」活动（每日签到只认它）。
///
/// 判据顺序：
///   1. 带 `modelScope` 且不是 `ALL_MODELS` → 是模型专属活动（如 Sonus 限时），
///      不是每日权益；标题里出现 `sonus` / `sota` 同理；
///   2. 标题里有「每日 / 每天 / daily」→ 每日权益；
///   3. 旧活动未附标题时，仅认已确认的「100 Credits、30 天有效、单日窗口」。
pub fn is_daily(row: &Value) -> bool {
    if !is_credit_benefit(row) {
        return false;
    }
    let title = [
        campaign_text(row, "zh", "title"),
        campaign_text(row, "en", "title"),
    ]
    .join(" ")
    .to_lowercase();
    let scope = row.pointer("/benefit/modelScope");
    let all_models = scope
        .and_then(|scope| scope.pointer("/modelSeries/key"))
        .and_then(Value::as_str)
        == Some("ALL_MODELS");
    let scoped = !all_models
        && scope.is_some_and(|scope| {
            !scope.is_null()
                && scope
                    .as_object()
                    .map(|object| !object.is_empty())
                    .unwrap_or(true)
        });
    if scoped || title.contains("sonus") || title.contains("sota") {
        return false;
    }
    if title.contains("每日")
        || title.contains("每天")
        || title.contains("daily")
        || title.contains("every day")
    {
        return true;
    }
    let one_day = match (campaign_time(row.get("startAt")), campaign_time(row.get("endAt"))) {
        (Some(start), Some(end)) => end > start && end - start <= 86_400_000,
        _ => false,
    };
    one_day
        && row.pointer("/benefit/amount").and_then(Value::as_f64) == Some(100.0)
        && row.pointer("/benefit/validity/days").and_then(Value::as_f64) == Some(30.0)
}

// ─── 手动福利（`claim.status` / `claim`）────────────────────────

/// 手动福利只认「非每日」的 Credits 活动。
fn is_reward(row: &Value) -> bool {
    is_credit_benefit(row) && !is_daily(row)
}

fn reward_rows(list: &Value) -> Vec<Value> {
    list.get("campaigns")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter(|row| is_reward(row)).cloned().collect())
        .unwrap_or_default()
}

fn status(row: &Value) -> &'static str {
    if row.get("claimStatus").and_then(Value::as_str) == Some(STATUS_CLAIMED) {
        return "claimed";
    }
    let now = sdk::now();
    if campaign_time(row.get("startAt")).is_some_and(|start| start > now)
        || campaign_time(row.get("endAt")).is_some_and(|end| end <= now)
    {
        return "inactive";
    }
    if row.get("claimStatus").and_then(Value::as_str) == Some(STATUS_CLAIMABLE) {
        "claimable"
    } else {
        "ineligible"
    }
}

fn view(row: &Value) -> Value {
    let title = campaign_text(row, "zh", "title");
    let title_en = campaign_text(row, "en", "title");
    let fallback = row.get("campaignKey").and_then(Value::as_str).unwrap_or("Qoder");
    json!({
        "campaignId": row.get("campaignId"),
        "title": if title.is_empty() { if title_en.is_empty() { fallback } else { &title_en } } else { &title },
        "titleEn": title_en,
        "description": campaign_text(row, "zh", "description"),
        "descriptionEn": campaign_text(row, "en", "description"),
        "amount": row.pointer("/benefit/amount").and_then(Value::as_f64).filter(|amount| *amount >= 0.0),
        "status": status(row),
        "startsAt": campaign_time(row.get("startAt")),
        "endsAt": campaign_time(row.get("endAt")),
        "claimedAt": campaign_time(row.get("claimedAt")),
        "expiresAt": campaign_time(row.get("expiresAt"))
            .or_else(|| campaign_time(row.pointer("/benefit/validity/fixedEnd"))),
        "validDays": row.pointer("/benefit/validity/days").and_then(Value::as_f64).filter(|days| *days > 0.0),
    })
}

/// 读台账（版本号 + 值）；形状不对时给一份空的。
///
/// `identity` 变了（换了账号）就整份重建：否则上一个账号的领取记录会被当成
/// 这个账号的。
fn ledger(identity: &str) -> Result<(u64, Value)> {
    let snapshot = sdk::state::get(sdk::state::Scope::Account, LEDGER_KEY, LEDGER_SCHEMA)?;
    if !snapshot.compatible {
        return Ok((snapshot.revision, json!({ "identity": identity, "claims": {} })));
    }
    let mut value = snapshot.value;
    if value.get("identity").and_then(Value::as_str) != Some(identity) {
        value = json!({ "identity": identity, "claims": {} });
    }
    if !value.get("claims").is_some_and(Value::is_object) {
        if let Some(object) = value.as_object_mut() {
            object.insert("claims".to_string(), json!({}));
        }
    }
    // 只留 90 天内的记录（native 同款保留期）
    if let Some(claims) = value.get_mut("claims").and_then(Value::as_object_mut) {
        let now = sdk::now();
        claims.retain(|_, claim| {
            claim
                .get("at")
                .and_then(Value::as_i64)
                .is_some_and(|at| now.saturating_sub(at) < 90 * 86_400_000)
        });
    }
    Ok((snapshot.revision, value))
}

fn save(revision: u64, value: &Value) -> Result<bool> {
    sdk::state::compare_exchange(
        sdk::state::Scope::Account,
        LEDGER_KEY,
        LEDGER_SCHEMA,
        revision,
        value.clone(),
        0,
    )
}

/// 把台账里记的状态叠加到实时视图上（同一次活动窗口才叠加）。
fn apply_saved(mut campaign: Value, saved: Option<&Value>) -> Value {
    if let Some(saved) = saved.filter(|saved| {
        saved.get("startsAt") == campaign.get("startsAt")
            && saved.get("endsAt") == campaign.get("endsAt")
    }) {
        if campaign.get("status").and_then(Value::as_str) == Some("claimable") {
            if let Some(saved_status) = saved
                .get("status")
                .and_then(Value::as_str)
                .filter(|value| matches!(*value, "claimed" | "confirming"))
            {
                if let Some(object) = campaign.as_object_mut() {
                    object.insert("status".to_string(), json!(saved_status));
                }
            }
        }
        for field in ["claimedAt", "expiresAt"] {
            if let Some(value) = saved.get(field).filter(|value| !value.is_null()) {
                if let Some(object) = campaign.as_object_mut() {
                    object.insert(field.to_string(), value.clone());
                }
            }
        }
    }
    campaign
}

/// `claim.status`：可领取的活动清单（含台账里记的领取状态）。
pub fn preview() -> Result<Value> {
    let session = load()?;
    let identity = format!("{}:{}", site::PROVIDER_ID, session.credentials.user_id);
    let (_, saved) = ledger(&identity)?;
    let campaigns: Vec<Value> = reward_rows(&session.list)
        .iter()
        .map(|row| {
            let id = row.get("campaignId").and_then(Value::as_str).unwrap_or("");
            apply_saved(view(row), saved.get("claims").and_then(|claims| claims.get(id)))
        })
        .collect();
    Ok(json!({ "campaigns": campaigns, "riskNote": session.risk_note }))
}

/// `claim`：领取一个活动（写前持久化——请求超时 / 进程重启后只能回查，
/// 不能盲目再领一次）。
pub fn claim(params: &Value) -> Result<Value> {
    let id = ["campaignId", "campaign", "id"]
        .iter()
        .find_map(|key| params[*key].as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if id.is_empty() || id.len() > 256 || id == "." || id == ".." || id.chars().any(char::is_control) {
        return Err(Error::http(400, "请选择要领取的活动"));
    }
    // ── 为什么这里不取账号锁 ────────────────────────────────────
    // 领取链路的互斥由**台账的比较再写**保证（native 用进程内的 flight 表做
    // 同一件事）。不再套一层账号锁的原因很实际：`claim_locked` 里遇到 401 会
    // 强制续期，而续期自己要拿账号锁 —— 同一账号锁重入会卡死这次调用。
    claim_locked(&id)
}

fn claim_locked(id: &str) -> Result<Value> {
    let mut session = load()?;
    let identity = format!("{}:{}", site::PROVIDER_ID, session.credentials.user_id);
    let (revision, mut saved) = ledger(&identity)?;
    let Some(target) = reward_rows(&session.list)
        .into_iter()
        .find(|row| row.get("campaignId").and_then(Value::as_str) == Some(id))
    else {
        return Ok(result(id, "inactive", None));
    };
    let campaign = apply_saved(view(&target), saved.get("claims").and_then(|claims| claims.get(id)));
    match campaign.get("status").and_then(Value::as_str) {
        Some("claimed") => return Ok(result(id, "already_claimed", Some(campaign))),
        Some("confirming") => return Ok(result(id, "confirming", Some(campaign))),
        Some("inactive") => return Ok(result(id, "inactive", Some(campaign))),
        Some("ineligible") => return Ok(result(id, "ineligible", Some(campaign))),
        _ => {}
    }
    if saved["claims"].as_object().is_some_and(|claims| claims.len() >= 256) {
        return Err(Error::http(409, "活动领取记录已满，请稍后再试"));
    }
    // 写前持久化：请求超时、页面关闭或进程重启后只能回查，不能盲目再领一次
    let entry = json!({
        "at": sdk::now(), "status": "confirming",
        "startsAt": campaign.get("startsAt"), "endsAt": campaign.get("endsAt"),
    });
    if let Some(claims) = saved.get_mut("claims").and_then(Value::as_object_mut) {
        claims.insert(id.to_string(), entry);
    }
    if !save(revision, &saved)? {
        return Err(Error::http(409, "活动领取记录已被改动，请刷新后重试"));
    }

    let mut response = submit(&session, id);
    if response.as_ref().is_ok_and(|response| response.status == 401) {
        // 401 交给续期重试一次（与 native 同一处置）
        let fresh = refresh::ensure_fresh(true).and_then(|credentials| {
            // 401 之后重拉也要叠风控头：不叠就退回「只有 VIEW_DETAILS 促销」
            // 的那一份清单，回查会误判成 inactive。
            let headers = site::sash_headers(&credentials.access_token);
            let mut list = fetch(&credentials, &headers)?;
            let uid = list.get("uid").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let (headers, risk_note) =
                super::risk::augment_headers(headers, &credentials.access_token, &uid);
            if risk_note.is_none() {
                list = fetch(&credentials, &headers)?;
            }
            Ok(CampaignSession { credentials, headers, list, risk_note })
        });
        session = fresh?;
        let target = reward_rows(&session.list)
            .into_iter()
            .find(|row| row.get("campaignId").and_then(Value::as_str) == Some(id));
        match target {
            Some(row) if status(&row) == "claimed" => {
                return finish(id, saved, revision_of()?, "already_claimed", view(&row));
            }
            Some(row) if status(&row) == "claimable" => response = submit(&session, id),
            Some(row) => return finish(id, saved, revision_of()?, status(&row), view(&row)),
            None => return finish(id, saved, revision_of()?, "inactive", campaign),
        }
    }

    let mut rejected = false;
    if let Ok(response) = &response {
        let body = unwrap_data(response.payload.clone().unwrap_or(Value::Null));
        let already = body.get("result").and_then(Value::as_str) == Some(RESULT_ALREADY_CLAIMED);
        if (response.ok || response.status == 409) && already {
            return finish(id, saved, revision_of()?, "already_claimed", receipt(campaign, &body));
        }
        if response.ok && body.get("status").and_then(Value::as_str) == Some(STATUS_CLAIMED) {
            let outcome = if body.get("replayed").and_then(Value::as_bool) == Some(true) {
                "already_claimed"
            } else {
                "claimed"
            };
            return finish(id, saved, revision_of()?, outcome, receipt(campaign, &body));
        }
        rejected = matches!(response.status, 400..=499) && response.status != 408;
    }

    // 提交结果不明：回查一次上游状态（能确认就落定，不能就留在 confirming）
    if let Ok(list) = fetch(&session.credentials, &session.headers) {
        if let Some(row) = reward_rows(&list)
            .into_iter()
            .find(|row| row.get("campaignId").and_then(Value::as_str) == Some(id))
        {
            if status(&row) == "claimed" {
                return finish(id, saved, revision_of()?, "already_claimed", view(&row));
            }
            if rejected && status(&row) != "claimable" {
                return finish(id, saved, revision_of()?, status(&row), view(&row));
            }
        }
    }
    let outcome = if rejected { "failed" } else { "confirming" };
    finish(id, saved, revision_of()?, outcome, campaign)
}

/// 重新读一次台账版本号（回查分支里值可能已变；读失败按 0 处理，写回会失败
/// 并如实报给用户，而不是覆盖别人的记录）。
fn revision_of() -> Result<u64> {
    let snapshot = sdk::state::get(sdk::state::Scope::Account, LEDGER_KEY, LEDGER_SCHEMA)?;
    Ok(snapshot.revision)
}

fn receipt(mut campaign: Value, body: &Value) -> Value {
    for (field, value) in [
        ("claimedAt", campaign_time(body.get("claimedAt"))),
        ("expiresAt", campaign_time(body.get("expiresAt"))),
    ] {
        if let Some(value) = value {
            if let Some(object) = campaign.as_object_mut() {
                object.insert(field.to_string(), json!(value));
            }
        }
    }
    if let Some(amount) = body
        .pointer("/benefit/amount")
        .and_then(Value::as_f64)
        .filter(|amount| *amount >= 0.0)
    {
        campaign["amount"] = json!(amount);
    }
    campaign
}

fn finish(
    id: &str,
    mut saved: Value,
    revision: u64,
    outcome: &str,
    mut campaign: Value,
) -> Result<Value> {
    let state = match outcome {
        "claimed" | "already_claimed" => "claimed",
        "confirming" => "confirming",
        "inactive" => "inactive",
        _ => "ineligible",
    };
    if let Some(object) = campaign.as_object_mut() {
        object.insert("status".to_string(), json!(state));
    }
    if matches!(state, "claimed" | "confirming") {
        let entry = json!({
            "at": sdk::now(), "status": state,
            "startsAt": campaign.get("startsAt"), "endsAt": campaign.get("endsAt"),
            "claimedAt": campaign.get("claimedAt"), "expiresAt": campaign.get("expiresAt"),
        });
        if let Some(claims) = saved.get_mut("claims").and_then(Value::as_object_mut) {
            claims.insert(id.to_string(), entry);
        }
    } else if let Some(claims) = saved.get_mut("claims").and_then(Value::as_object_mut) {
        claims.remove(id);
    }
    // 台账写失败不阻断本次结论：下次查询以上游状态为准（native 同一条口径）
    let _ = save(revision, &saved);
    Ok(result(id, outcome, Some(campaign)))
}

fn result(id: &str, outcome: &str, campaign: Option<Value>) -> Value {
    json!({ "campaignId": id, "outcome": outcome, "campaign": campaign })
}
