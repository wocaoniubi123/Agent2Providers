//! Loomy 积分 / 余额查询：`GET {集成网关}/api/v2/points/records` 的摘要字段。
//!
//! ── 为什么余额藏在流水接口里（客户端就是这么读的）──────────────
//! Loomy **没有独立的余额接口**。客户端的积分详情页读的是 V2 流水接口 ——
//! 它的响应 `data` 里同时带账户摘要：
//!
//! ```text
//! GET /api/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat
//!   → {code:"000000", data:{ balance,           ← 永久积分（长期积分）
//!                          dailyBalance,       ← 每日赠送积分（每日登录刷回 5000）
//!                          dailyLimitPoints, dailyConsumedPoints, dailyRemainingPoints,
//!                          list:[…], total }}
//! ```
//!
//! 这里按账号页的统一形状（`{available, unit, wallets, credits, raw}`）归一化：
//! 两个钱包各一行，`available` 取两者之和（实际可用的总量）。

use agent2api_provider_sdk::PluginCtx;
use serde_json::{json, Value};

use super::client;
use super::credentials;

/// 流水查询路径（相对集成网关；pageSize 取 1 只为拿摘要，不看流水本身）
const RECORDS_PATH: &str =
    "/api/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat";

/// 从 `data` 里取一个非负数字（字段缺失 / 非法时给 None）
fn pick_number(data: &Value, key: &str) -> Option<f64> {
    let value = data.get(key)?;
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    // 上游有把数字序列化成字符串的形态（如 "5000"）
    value
        .as_str()
        .and_then(|text| text.trim().parse::<f64>().ok())
}

/// 查询某 Loomy 账号的双账户余额。
pub async fn query_usage(ctx: &PluginCtx, account: &str) -> Result<Value, String> {
    let client = crate::http::control_client(None, &ctx.env.proxy);
    let credentials = credentials::snapshot(ctx, account).await?;
    let payload =
        client::token_request(&client, "GET", RECORDS_PATH, &credentials.session, None, "积分查询")
            .await?;

    let code = client::business_code(&payload);
    if client::is_auth_error_code(&code) {
        return Err("Loomy 登录态已失效，无法查询积分（请重新登录）".to_string());
    }
    if code != client::SUCCESS_CODE {
        let message = client::upstream_message(&payload);
        return Err(if message.trim().is_empty() {
            format!("积分查询失败（上游 code={code}）")
        } else {
            format!("积分查询失败：{message}")
        });
    }

    // 摘要可能在 data 或 data.data 两层（V2 接口的形态在不同版本里出现过两种）
    let data = payload
        .get("data")
        .and_then(|value| value.get("data"))
        .unwrap_or_else(|| payload.get("data").unwrap_or(&Value::Null));

    let permanent = pick_number(data, "balance").unwrap_or(0.0);
    let daily = pick_number(data, "dailyBalance").unwrap_or(0.0);
    let daily_remaining = pick_number(data, "dailyRemainingPoints");
    let daily_limit = pick_number(data, "dailyLimitPoints");

    let mut wallets = vec![
        json!({
            "type": "permanent_points",
            "displayName": "永久积分",
            "balance": permanent,
        }),
        json!({
            "type": "daily_points",
            "displayName": "每日赠送积分",
            "balance": daily,
        }),
    ];
    // 赠送额度的「剩余 / 上限」是独立的展示口径，有就带上，没有不编造
    if let (Some(remaining), Some(limit)) = (daily_remaining, daily_limit) {
        if let Some(object) = wallets.get_mut(1).and_then(Value::as_object_mut) {
            object.insert("remaining".to_string(), Value::from(remaining));
            object.insert("limit".to_string(), Value::from(limit));
        }
    }

    // 逐份明细（`credits[]`，账号页「积分明细」弹层的输入）：两行与 `wallets`
    // 同序同口径。`daily: true` 是界面「每日重置」的判据 —— 余额读到 0 时也不
    // 折进「已用完」（明天回满）。
    //
    // `dailyRemainingPoints` / `dailyLimitPoints` **不折进这两行**：它们是赠送
    // 额度的另一个展示口径，与 `dailyBalance` 是否同源未经证实 —— 混进来的
    // 「剩 x / 共 y」可能对不上真正的余额（宁可少给，不编）。
    let credits = vec![
        json!({ "name": "永久积分", "remain": permanent }),
        json!({ "name": "每日赠送积分", "remain": daily, "daily": true }),
    ];

    let mut document = json!({
        "available": permanent + daily,
        "unit": "积分",
        "wallets": wallets,
        "raw": payload,
    });
    if let Some(object) = document.as_object_mut() {
        object.insert("credits".to_string(), Value::Array(credits));
    }
    Ok(document)
}

// ─── 邀请码（激活）─────────────────────────────────────────────

/// 邀请码激活接口：查状态用 GET、绑码用 POST，同一个路径。
///
/// 依据：Loomy 桌面端 `electron/points-service.js` 的
/// `checkActivation()` / `bindInviteCode()`。
const ACTIVATION_PATH: &str = "/api/v1/points/activation";

/// 这个号**自己产出的邀请码**（含使用次数）。客户端另起一个接口
/// （`points-service.js` 的 `queryInvitationCodes()`），这里合并进状态查询，
/// 界面一次请求就能同时拿到「填了没」和「我的码用了几次」。
///
/// 返回形态：`{ data: { list: [{ inviteCode, usedCount, maxUses, status }] } }`，
/// `status` 取值 `active` / `exhausted`。
const INVITATION_CODES_PATH: &str = "/api/v1/invitation-codes";

/// 兑换码兑换接口。客户端 `points-service.js` 的 `redeemRedemptionCode()`：
/// `POST { body: { code } }`，成功返回的 `data` 结构与激活接口同族。
const REDEEM_PATH: &str = "/api/v1/points/redemption-codes/redeem";

/// 生成绑定用的 `deviceId`。
///
/// 客户端那套是「系统钥匙串 → 本地存储 → 机器指纹 → 随机 UUID」四级兜底
/// （`campus-device-id-service.js`），前缀固定 `loomy-campus-`。网关侧不需要
/// 稳定身份（每次绑定都是一次性动作），所以直接用随机 UUID 形态 —— 实测
/// 上游接受，不校验是否与真实设备一致。
fn campus_device_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_ok() {
        // UUID v4 形态：8-4-4-4-12
        let hex = |range: std::ops::Range<usize>| -> String {
            bytes[range].iter().map(|b| format!("{b:02x}")).collect()
        };
        return format!(
            "loomy-campus-{}-{}-4{}-a{}-{}",
            hex(0..4),
            hex(4..6),
            &hex(6..7)[1..],
            &hex(8..9)[1..],
            hex(10..16),
        );
    }
    // 拿不到系统随机源时退回时间戳：形状不重要，唯一即可
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("loomy-campus-{nanos:032x}")
}

/// 把上游响应归一成「业务码成功就返回 data，否则 Err」。
///
/// 与 `query_usage` 同一套判定：`000000` 成功、`020002`/`100002` 登录态失效、
/// 其余取上游文案。
fn activation_data(payload: &Value, what: &str) -> Result<Value, String> {
    let code = client::business_code(payload);
    if client::is_auth_error_code(&code) {
        return Err("Loomy 登录态已失效，请重新登录".to_string());
    }
    if code != client::SUCCESS_CODE {
        let message = client::upstream_message(payload);
        return Err(if message.trim().is_empty() {
            format!("{what}失败（上游 code={code}）")
        } else {
            format!("{what}失败：{message}")
        });
    }
    Ok(payload.get("data").cloned().unwrap_or(Value::Null))
}

/// 查某个账号的邀请码状态。
///
/// 返回两段信息（客户端要打两个接口，这里合成一次返回）：
///
/// ```text
/// activated             是否已经填过别人的码
/// appliedInvitationCode 填的是哪个码
/// invitationCodes       这个号自己的码 + 使用次数
///                       [{ inviteCode, usedCount, maxUses, status }]
/// ```
///
/// `invitationCodes` 里 `status` 为 `active` 的还能被邀，`exhausted` 是次数用尽
/// （`usedCount == maxUses`）—— 界面按 `usedCount/maxUses` 显示成 `0/20`、`1/1`。
pub async fn invite_status(ctx: &PluginCtx, account: &str) -> Result<Value, String> {
    let client = crate::http::control_client(None, &ctx.env.proxy);
    let credentials = credentials::snapshot(ctx, account).await?;
    let activation = client::token_request(
        &client,
        "GET",
        ACTIVATION_PATH,
        &credentials.session,
        None,
        "邀请码状态查询",
    )
    .await?;
    let mut data = activation_data(&activation, "邀请码状态查询")?;

    // 列表这一段失败不该让整个状态查询失败：填没填是主信息，列表只是补充。
    let list = match client::token_request(
        &client,
        "GET",
        INVITATION_CODES_PATH,
        &credentials.session,
        None,
        "邀请码列表查询",
    )
    .await
    {
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

/// 兑换一个兑换码（上游按活动档位发积分）。
///
/// 与 `bind_invite` 的区别：兑换码只带 `code`，不需要 `deviceId`；一个号可以
/// 兑换多个不同的码（上游各自校验），所以这里不做「已用过就不发」的判断。
pub async fn redeem_code(ctx: &PluginCtx, account: &str, code: &str) -> Result<Value, String> {
    let value = code.trim();
    if value.is_empty() {
        return Err("缺少兑换码".to_string());
    }
    if value.len() > 128 || value.chars().any(char::is_control) {
        return Err("兑换码格式不合法".to_string());
    }
    let body = json!({ "code": value });
    let client = crate::http::control_client(None, &ctx.env.proxy);
    let credentials = credentials::snapshot(ctx, account).await?;
    let payload = client::token_request(
        &client,
        "POST",
        REDEEM_PATH,
        &credentials.session,
        Some(&body),
        "兑换码兑换",
    )
    .await?;
    // 判定与邀请码同一套（000000 成功 / 020002·100002 登录失效 / 其余取上游文案）
    activation_data(&payload, "兑换码兑换")
}

/// 绑定邀请码（上游会按 `inviteeReward` 给这个号加积分）。
///
/// 已绑过的号上游会返回 `alreadyActivated: true`，这里原样透出交给界面判断，
/// 不当成错误 —— 它是「本来就有」而不是「这次失败」。
pub async fn bind_invite(ctx: &PluginCtx, account: &str, invite_code: &str) -> Result<Value, String> {
    let code = invite_code.trim();
    if code.is_empty() {
        return Err("缺少邀请码".to_string());
    }
    if code.len() > 64 || code.chars().any(char::is_control) {
        return Err("邀请码格式不合法".to_string());
    }
    let body = json!({
        "inviteCode": code,
        "deviceId": campus_device_id(),
    });
    let client = crate::http::control_client(None, &ctx.env.proxy);
    let credentials = credentials::snapshot(ctx, account).await?;
    let payload = client::token_request(
        &client,
        "POST",
        ACTIVATION_PATH,
        &credentials.session,
        Some(&body),
        "绑定邀请码",
    )
    .await?;
    activation_data(&payload, "绑定邀请码")
}
