//! LobsterAI 的每日活动签到：**三步、幂等靠客户端**。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/checkin.rs`。
//!
//! ── 三步协议（`credits.go:305-368`）──────────────────────────
//! ```text
//!   1. GET  /api/client-activities/slot?placement=…&clientVersion=…&…
//!        -> 找到「每日签到」那个活动位：slotState / activity.activityCode /
//!           activity.configRevision
//!   2. GET  /api/client-activities/{code}/context?configRevision=…
//!        -> 活动状态：state.claimedToday 与 actions[]（含不含 check_in）
//!   3. POST /api/client-activities/{code}/actions/check_in
//!        体 {configRevision, idempotencyKey:<uuid4>, payload:{}}
//! ```
//!
//! ── 幂等是**客户端**的事，所以两道前置检查都必须做 ──────────────
//! 上游没有「今天签过了就返回已签」的幂等语义（否则不需要 idempotencyKey）：
//! 幂等靠 ① 请求里那个 uuid4 的 `idempotencyKey`，② 第二步的两道预检
//! （`state.claimedToday` 与 `actions` 里有没有 `check_in`）。**两道都要**：
//! 只看 `claimedToday` 会漏掉「活动在、但今天不可签」那一格（`credits.go:26-29`
//! 的原话）。预检命中时如实回一句中性的「今天已签到」，**不**再去打签到接口 ——
//! 那会在上游不幂等的情况下把一天的奖励签重。
//!
//! ── 发放额字段有**三段回退** ─────────────────────────────────
//! `data.result` 里的奖励名随活动 / 版本变化：`creditsGranted` → `rewardCredits`
//! → `credits`，取第一个能读到的（`credits.go:349-360` 的原文注释）。
//!
//! ── 返回形状（与 native 的一处差异）──────────────────────────
//! native 回的是网关内置版的 `{success, msg, alreadyCompleted}`，再由
//! `checkin_report_of` 翻成 `CheckinReport`。wasm 侧直接回协议化的
//! `CheckinReport` 形状 —— 网关 `rpc.rs::checkin_claim_with_options` 就是按
//! `proto::CheckinReport` 反序列化的（`outcome` / `credit` / `streak` / `message`）。
//! 「今天已签到」这句仍然带「已签到」三字，与 native 的中性文案一致。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::account;
use super::codec;
use super::credentials::Credentials;
use super::oauth::unwrap_envelope;
use super::upstream::{
    self, MAX_BODY_BYTES, USER_AGENT, activity_checkin_url, activity_context_url, activity_slot_url,
};
use super::version;

/// 活动上下文里表示「今天可签」的动作名
pub const CHECK_IN_ACTION: &str = "check_in";

/// 活动位（第一步 `data` 里我们关心的三个字段）
#[derive(Clone, Debug, Default)]
struct ActivitySlot {
    /// `slotState`（`available` 才可能可签）
    slot_state: String,
    /// `activity.activityCode`
    activity_code: String,
    /// `activity.configRevision`（原样留着，写进第二步的 query 与第三步的 body）
    config_revision: Value,
}

/// 装配好的签到报告（`CheckinReport` 的形状）。
fn report(outcome: &str, message: &str, credit: Option<String>) -> Value {
    json!({
        "outcome": outcome,
        "message": message,
        "credit": credit,
        "streak": Value::Null,
    })
}

/// 从活动位 `data` 里取三个字段
fn parse_slot(data: &Value) -> ActivitySlot {
    let activity = data.get("activity");
    ActivitySlot {
        slot_state: data
            .get("slotState")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
        activity_code: activity
            .and_then(|value| value.get("activityCode"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
        config_revision: activity
            .and_then(|value| value.get("configRevision"))
            .cloned()
            .unwrap_or(Value::Null),
    }
}

/// `configRevision` 渲染成 query / body 里那个数（整数不带小数尾巴，与 Go
/// `formatNumber` 同口径；读不出数时给 `0`，不猜）。
fn config_revision_string(value: &Value) -> String {
    if let Some(number) = value.as_i64() {
        return number.to_string();
    }
    if let Some(number) = value.as_f64() {
        if number.fract() == 0.0 {
            return (number as i64).to_string();
        }
        return format!("{number}");
    }
    if let Some(text) = value.as_str() {
        if let Ok(number) = text.trim().parse::<f64>() {
            if number.fract() == 0.0 {
                return (number as i64).to_string();
            }
            return format!("{number}");
        }
    }
    "0".to_string()
}

/// `configRevision` 作为 **JSON 数字**放进签到体（原样透传数字形态；字符串数字
/// 也折成数字，非数字给 0）
fn config_revision_json(value: &Value) -> Value {
    if value.as_f64().is_some() || value.as_i64().is_some() {
        return value.clone();
    }
    if let Some(text) = value.as_str() {
        if let Ok(number) = text.trim().parse::<f64>() {
            return Value::from(number);
        }
    }
    Value::from(0)
}

/// 今天是否已经签过（第一步预检）
fn claimed_today(context_data: &Value) -> bool {
    context_data
        .get("state")
        .and_then(|state| state.get("claimedToday"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// 活动上下文里的 `actions[]` 是否包含 `check_in`（第二步预检）
fn has_check_in_action(context_data: &Value) -> bool {
    context_data
        .get("actions")
        .and_then(Value::as_array)
        .map(|actions| {
            actions
                .iter()
                .filter_map(Value::as_str)
                .any(|action| action.trim() == CHECK_IN_ACTION)
        })
        .unwrap_or(false)
}

/// 从签到结果的 `data.result` 里取发放额（`creditsGranted` → `rewardCredits`
/// → `credits`，见模块头）。返回 `(amount, found)`。
fn credit_from_result(result: &Value) -> (f64, bool) {
    for key in ["creditsGranted", "rewardCredits", "credits"] {
        let Some(value) = result.get(key) else {
            continue;
        };
        let number = value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse::<f64>().ok()));
        if let Some(number) = number {
            return (number, true);
        }
    }
    (0.0, false)
}

/// 发一次带鉴权的 JSON 请求（活动位 / 活动上下文 / 签到共用）。
///
/// 非 JSON 响应给「凭据已失效」这类可读原因，而不是抛一个解析错误。
fn request_json(
    method: &str,
    url: &str,
    credentials: &Credentials,
    body: Option<&Value>,
    what: &str,
) -> Result<Value> {
    let headers = vec![
        (
            "authorization".to_string(),
            format!("Bearer {}", credentials.access_token),
        ),
        ("accept".to_string(), "application/json".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("user-agent".to_string(), USER_AGENT.to_string()),
    ];
    let reply = upstream::send(method, url, &headers, body, MAX_BODY_BYTES)?;
    if matches!(reply.status, 401 | 403) {
        return Err(Error::http(
            401,
            format!(
                "LobsterAI 凭据已失效（HTTP {}），请重新登录该账号",
                reply.status
            ),
        ));
    }
    if !reply.ok() {
        return Err(Error::http(
            reply.status,
            format!("LobsterAI {what}返回 HTTP {}", reply.status),
        ));
    }
    reply
        .json()
        .ok_or_else(|| Error::http(502, format!("LobsterAI {what}响应不是 JSON")))
}

/// 每日签到（三步）。
///
/// ── 三种结局对应用户看到的三种话 ─────────────────────────────
///   · **今天已签**：`done` +「今天已签到」（中性、不重签）；
///   · **不可签**：`inactive` + 中性文案（活动未下发 / `check_in` 不在 `actions` 里）；
///   · **真签上**：`claimed` + 发放积分（字段三段回退）。
/// 传输 / 信封层面的失败才返回 `Err`（由网关放进结果的 `error`）。
pub fn claim() -> Result<Value> {
    let credentials = Credentials::from_secret(&account::current_secret()?)?;
    // 版本号是活动位 query 的必填参数
    let client_version = version::resolve();

    // ── 第一步：活动位 ─────────────────────────────────────────
    let slot_payload = request_json(
        "GET",
        &activity_slot_url(&client_version),
        &credentials,
        None,
        "活动槽位查询",
    )?;
    let slot_data = unwrap_envelope(&slot_payload, "活动槽位查询")?;
    let slot = parse_slot(&slot_data);
    if slot.slot_state != "available" || slot.activity_code.is_empty() {
        let message = format!("今天没有可签到的活动（slotState={}）", slot.slot_state);
        return Ok(report("inactive", &message, None));
    }

    // ── 第二步：两道预检（幂等靠客户端，缺一不可，见模块头）─────────
    let revision = config_revision_string(&slot.config_revision);
    let context_payload = request_json(
        "GET",
        &activity_context_url(&slot.activity_code, &revision),
        &credentials,
        None,
        "活动上下文查询",
    )?;
    let context_data = unwrap_envelope(&context_payload, "活动上下文查询")?;
    if claimed_today(&context_data) {
        return Ok(report("done", "今天已签到", None));
    }
    if !has_check_in_action(&context_data) {
        return Ok(report("inactive", "当前不可签到（活动未开放 check_in）", None));
    }

    // ── 第三步：真签（幂等键是 uuid4，客户端生成）───────────────────
    let idempotency_key = codec::uuid_v4()?;
    let body = json!({
        "configRevision": config_revision_json(&slot.config_revision),
        "idempotencyKey": idempotency_key,
        "payload": {},
    });
    let checkin_payload = request_json(
        "POST",
        &activity_checkin_url(&slot.activity_code),
        &credentials,
        Some(&body),
        "签到",
    )?;
    let data = unwrap_envelope(&checkin_payload, "签到")?;
    let result = data.get("result").cloned().unwrap_or(Value::Null);
    let (credit, granted) = credit_from_result(&result);
    let message = if granted {
        format!("签到成功，获得 {credit} 积分")
    } else {
        "签到成功".to_string()
    };
    let credit_text = if granted {
        Some(format!("{credit} 积分"))
    } else {
        None
    };
    Ok(report("claimed", &message, credit_text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_parsing_reads_the_three_fields() {
        let data = json!({
            "slotState": "available",
            "activity": { "activityCode": "daily", "configRevision": 7 }
        });
        let slot = parse_slot(&data);
        assert_eq!(slot.slot_state, "available");
        assert_eq!(slot.activity_code, "daily");
        assert_eq!(config_revision_string(&slot.config_revision), "7");
        // 缺字段一律给空串 / 0（不猜）
        let slot = parse_slot(&json!({}));
        assert_eq!(slot.slot_state, "");
        assert_eq!(slot.activity_code, "");
        assert_eq!(config_revision_string(&slot.config_revision), "0");
    }

    #[test]
    fn config_revision_is_rendered_without_a_decimal_tail() {
        assert_eq!(config_revision_string(&json!(7)), "7");
        assert_eq!(config_revision_string(&json!(7.0)), "7");
        assert_eq!(config_revision_string(&json!("7")), "7");
        assert_eq!(config_revision_string(&json!(7.5)), "7.5");
        assert_eq!(config_revision_string(&json!("abc")), "0");
        // body 里要的是 JSON 数字
        assert_eq!(config_revision_json(&json!(7)), json!(7));
        assert_eq!(config_revision_json(&json!("7")), json!(7.0));
        assert_eq!(config_revision_json(&json!("abc")), json!(0));
    }

    #[test]
    fn both_prechecks_are_required() {
        // claimedToday 命中
        assert!(claimed_today(&json!({ "state": { "claimedToday": true } })));
        assert!(!claimed_today(&json!({ "state": { "claimedToday": false } })));
        assert!(!claimed_today(&json!({})));
        // actions 里有没有 check_in
        assert!(has_check_in_action(&json!({ "actions": ["check_in", "share"] })));
        assert!(!has_check_in_action(&json!({ "actions": ["share"] })));
        assert!(!has_check_in_action(&json!({})));
        // 只有 claimedToday=false 而 actions 缺 check_in → 仍然不可签（第二道预检）
        let data = json!({ "state": { "claimedToday": false }, "actions": [] });
        assert!(!claimed_today(&data));
        assert!(!has_check_in_action(&data));
    }

    #[test]
    fn credit_falls_back_across_three_field_names() {
        assert_eq!(credit_from_result(&json!({ "creditsGranted": 100 })), (100.0, true));
        assert_eq!(credit_from_result(&json!({ "rewardCredits": "50" })), (50.0, true));
        assert_eq!(credit_from_result(&json!({ "credits": 10.5 })), (10.5, true));
        // 三个都没有 → 没读到（不是 0 积分）
        assert_eq!(credit_from_result(&json!({})), (0.0, false));
        assert_eq!(credit_from_result(&json!({ "creditsGranted": "abc" })), (0.0, false));
    }

    #[test]
    fn report_shape_is_the_protocol_one() {
        let claimed = report("claimed", "签到成功", Some("100 积分".to_string()));
        assert_eq!(claimed["outcome"], json!("claimed"));
        assert_eq!(claimed["credit"], json!("100 积分"));
        assert_eq!(claimed["streak"], Value::Null);
        let done = report("done", "今天已签到", None);
        assert_eq!(done["outcome"], json!("done"));
        assert_eq!(done["credit"], Value::Null);
        // 「已签到」三字必须在（与 native 的中性文案一致）
        assert!(done["message"].as_str().is_some_and(|text| text.contains("已签到")));
    }
}
