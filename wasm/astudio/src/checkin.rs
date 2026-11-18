//! AStudio 每日签到：执行桌面端启动时的账号初始化，触发每日登录奖励。
//!
//! ── 发奖动作与到账核对 ──────────────────────────────────────
//! POST `tenant-app/v2/init-app`（无 body、带 Cookie）才触发每日奖励；
//! 查询会员/积分或关闭弹窗不发奖。所以流程是：
//! 读余额 → 初始化账号 → 等 2.5 秒 → 再读余额，分别核对通用与星火积分。
//! **余额没涨不等于今日已领**，也不能断言没有活动：只报告本次未观测到新到账，
//! 让编排层保留重试（native 的取舍，逐条照搬）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::{account, client};

/// 到账等待（native 的 `REWARD_WAIT_MS`）。
const REWARD_WAIT_MS: u64 = 2500;

/// 一次积分读数。
struct Balance {
    points: Option<f64>,
    spark: Option<f64>,
}

/// `checkin.claim`。
pub fn checkin() -> Result<Value> {
    let secret = account::current()?;
    let credentials = account::Credentials::from_secret(&secret);
    if credentials.key.is_empty() {
        return Err(Error::http(401, "AStudio 账号缺少 modelBearerToken，请重新登录或粘贴"));
    }
    if !credentials.has_session() {
        return Ok(report(
            "ineligible",
            None,
            None,
            Some("该账号只有模型凭据（无网页会话），无法执行每日登录签到"),
        ));
    }
    let config = match client::studio_json(&credentials, client::PLAN_CONFIG, "签到配置") {
        Ok(value) => value,
        Err(client::StudioError::Expired(message)) => return Err(Error::http(401, message)),
        Err(error) => return Ok(report("failed", None, None, Some(error.message()))),
    };
    if config.get("dailyLoginEnabled").and_then(Value::as_bool) == Some(false) {
        return Ok(report("inactive", None, None, Some("当前没有每日登录积分活动")));
    }
    let before = match read_balance(&credentials) {
        Ok(value) => value,
        Err(client::StudioError::Expired(message)) => return Err(Error::http(401, message)),
        Err(error) => return Ok(report("failed", None, None, Some(error.message()))),
    };
    // 不能用只读查询替代每日登录动作；上游拒绝时直接返回，不能继续报「余额没涨」。
    if let Err(error) = client::init_app(&credentials) {
        return match error {
            client::StudioError::Expired(message) => Err(Error::http(401, message)),
            client::StudioError::Failed(message) => Ok(report("failed", None, None, Some(&message))),
        };
    }
    sdk::sleep(REWARD_WAIT_MS)?;
    let after = match read_balance(&credentials) {
        Ok(value) => value,
        Err(client::StudioError::Expired(message)) => return Err(Error::http(401, message)),
        Err(error) => return Ok(report("failed", None, None, Some(error.message()))),
    };
    let deltas = [
        ("通用积分", balance_delta(before.points, after.points)),
        ("星火积分", balance_delta(before.spark, after.spark)),
    ];
    if deltas.iter().all(|(_, delta)| delta.is_none()) {
        return Ok(report(
            "failed",
            None,
            None,
            Some("签到前后积分读数不完整，无法确认奖励到账"),
        ));
    }
    // 两个余额池独立核对：只到账星火积分也算成功，缺失读数不能当成 0。
    let rewards: Vec<String> = deltas
        .iter()
        .filter_map(|(label, delta)| delta.filter(|value| *value > 0.0).map(|value| format!("{label} +{value}")))
        .collect();
    if !rewards.is_empty() {
        let credit = rewards.join("，");
        return Ok(json!({
            "outcome": "claimed",
            "credit": credit,
            "streak": Value::Null,
            "message": format!("每日登录奖励已到账：{credit}"),
        }));
    }
    // 初始化成功不是领奖凭证；未到账保留重试，不能按「今日无活动」结束。
    Ok(report(
        "failed",
        None,
        None,
        Some("每日登录已执行，但未观测到新增积分（可能今日已领取或暂未到账）"),
    ))
}

/// 组一条签到报告。
fn report(outcome: &str, credit: Option<&str>, streak: Option<u32>, message: Option<&str>) -> Value {
    json!({
        "outcome": outcome,
        "credit": credit,
        "streak": streak,
        "message": message,
    })
}

fn read_balance(credentials: &account::Credentials) -> std::result::Result<Balance, client::StudioError> {
    let value = client::studio_json(credentials, client::POINTS_BALANCE, "积分余额")?;
    let balance = Balance {
        points: balance_number(value.get("totalBalance")),
        spark: balance_number(value.get("sparkTotalBalance")),
    };
    if balance.points.is_none() && balance.spark.is_none() {
        return Err(client::StudioError::Failed("积分余额读数不完整".into()));
    }
    Ok(balance)
}

fn balance_number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse::<f64>().ok()))
        })
        .filter(|number| number.is_finite() && *number >= 0.0)
}

fn balance_delta(before: Option<f64>, after: Option<f64>) -> Option<f64> {
    let delta = after? - before?;
    delta.is_finite().then_some(delta)
}
