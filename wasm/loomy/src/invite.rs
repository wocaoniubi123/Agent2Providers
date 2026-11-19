//! 邀请码 / 兑换码 —— **本 fork 的自用改动**。
//!
//! 上游 loomy 包没有这三个能力（`account_features` 里也没有 `invite_code` 位），
//! 这里按网关 `api/invite_code.rs` 的契约补上：
//!
//! ```text
//!   invite.status  → GET  /api/v1/points/activation          （已填的码 + 自己的码）
//!   invite.bind    → POST /api/v1/points/activation          body { inviteCode, deviceId }
//!   invite.redeem  → POST /api/v1/points/redemption-codes/redeem  body { code }
//! ```
//!
//! ── 为什么路径写死在这里 ──────────────────────────────────────
//! 三条路径取自 native 实现的实测值
//! （`crates/providers/src/providers/loomy/balance.rs`），上游 wasm 包没有这部分，
//! 所以没有别处可复用。改路径前先确认上游接口还在。
//!
//! ── 为什么复用上游的 client / account ────────────────────────
//! `client::token_request` 的签名与 native 实现逐字相同（method / path / session /
//! body / operation），`account::current()` / `account::token()` 是上游标准的账套
//! 读取方式。用它们就不用把 native 那套 `credentials` / `crypto` / `ids` 搬过来 ——
//! 那几个模块与上游 loomy 的结构不兼容。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, client, errors, sign};

const ACTIVATION_PATH: &str = "/api/v1/points/activation";
const INVITATION_CODES_PATH: &str = "/api/v1/invitation-codes";
const REDEEM_PATH: &str = "/api/v1/points/redemption-codes/redeem";

/// 邀请码绑定要带的设备标识。
///
/// 上游客户端给它的是 `loomy-campus-<uuid v4>` 形态的字符串，服务端只用来做
/// 「同一设备不重复绑」的去重，不校验真伪。
///
/// UUID 直接用上游 [`sign::uuid`]（version 位固定 4、variant 位 `8/9/a/b` 随机），
/// 不自拼 —— native 那版是手工拼的（variant 固定 `a`），转录时没必要跟着绕。
/// 拿不到宿主随机源时给一个形态合法的兜底值：让它退化成「可能被判重复」，
/// 而不是让整条绑定失败。
fn campus_device_id() -> String {
    match sign::uuid() {
        Ok(uuid) => format!("loomy-campus-{uuid}"),
        Err(_) => "loomy-campus-00000000-0000-4000-8000-000000000000".to_string(),
    }
}

/// 邀请码状态：已填的码 + 这个号自己的码。
///
/// 返回形状：
/// ```text
/// activated             是否已经填过别人的码
/// appliedInvitationCode 填的是哪个码
/// invitationCodes       自己的码 + 使用情况 [{ inviteCode, usedCount, maxUses, status }]
/// ```
///
/// 列表那一段失败**不让整个查询失败**：填没填是主信息，列表只是补充。
pub fn status() -> Result<Value> {
    let record = account::current()?;
    let session = account::token(&record["secret"])?;
    let activation =
        client::token_request("GET", ACTIVATION_PATH, &session, None, "邀请码状态查询")?;
    errors::ensure_success(&activation, "邀请码状态查询", &session)?;
    let mut data = activation.get("data").cloned().unwrap_or(Value::Null);
    let list = match client::token_request(
        "GET",
        INVITATION_CODES_PATH,
        &session,
        None,
        "邀请码列表查询",
    ) {
        Ok(payload) => payload
            .get("data")
            .and_then(|value| value.get("list"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        Err(_) => Value::Array(Vec::new()),
    };
    if let Some(object) = data.as_object_mut() {
        object.insert("invitationCodes".to_string(), list);
    }
    Ok(data)
}

/// 绑定邀请码（上游按 `inviteeReward` 给这个号加积分）。
///
/// 已绑过的号上游返回 `alreadyActivated: true`：那是「本来就有」而不是「这次失败」，
/// 原样透出交给界面判断，这里不当错误处理。
pub fn bind(code: &str) -> Result<Value> {
    let value = code.trim();
    if value.is_empty() {
        return Err(Error::http(400, "缺少邀请码"));
    }
    if value.len() > 64 || value.chars().any(char::is_control) {
        return Err(Error::http(400, "邀请码格式不合法"));
    }
    let record = account::current()?;
    let session = account::token(&record["secret"])?;
    let body = json!({
        "inviteCode": value,
        "deviceId": campus_device_id(),
    });
    let payload =
        client::token_request("POST", ACTIVATION_PATH, &session, Some(&body), "绑定邀请码")?;
    errors::ensure_success(&payload, "绑定邀请码", &session)?;
    Ok(payload.get("data").cloned().unwrap_or(Value::Null))
}

/// 兑换一个兑换码。
///
/// 与邀请码是两条独立的上游路径（`redemption-codes/redeem` vs `activation`）：
/// 兑换码只带 `code`、不需要 `deviceId`，且一个号可以兑多个不同的码
/// （上游各自校验），所以这里不做「兑过就拒」的判断。
pub fn redeem(code: &str) -> Result<Value> {
    let value = code.trim();
    if value.is_empty() {
        return Err(Error::http(400, "缺少兑换码"));
    }
    if value.len() > 128 || value.chars().any(char::is_control) {
        return Err(Error::http(400, "兑换码格式不合法"));
    }
    let record = account::current()?;
    let session = account::token(&record["secret"])?;
    let body = json!({ "code": value });
    let payload = client::token_request("POST", REDEEM_PATH, &session, Some(&body), "兑换码兑换")?;
    errors::ensure_success(&payload, "兑换码兑换", &session)?;
    Ok(payload.get("data").cloned().unwrap_or(Value::Null))
}
