//! AutoClaw 每日签到（`autoclaw-task-complete` 的 `daily_signin`）。
//!
//! ── 上游接口 ────────────────────────────────────────────────
//! ```text
//! POST {userapi}/autoclaw-proxy/proxy/autoclaw-task-complete   {"task_id":"daily_signin"}
//! GET  {userapi}/autoclaw-proxy/proxy/autoclaw-task-list       签到未领取时的归因
//! POST {userapi}/userapi/v1/user-info                          「登录」钩子（活动福利）
//! ```
//! 三条都在 userapi 域，带同一套 `X-Auth-Sign` 签名头（见 `sign.rs`）。
//!
//! ── 「今天已签到」与「签到成功」必须分开 ─────────────────────
//! 上游对重复调用返回 `success:false + already_completed:true`。把它算成成功会让
//! 「今天已签到」在界面上显示成「签到成功」，与实际入账不符 —— 所以判据是
//! 「本次真的领到了」（`reward_points > 0` 或显式 success 且未 completed）。
//!
//! ── 与 native 的差别：活动福利的「触发 + 复核」没有搬 ────────────
//! native 在签到后还会读一次积分流水（`promotion.rs`）、未到账时打一次
//! user-info 触发「登录即发」、再等 1.5 秒复核。wasm 侧**不做这一段**：
//!   · 它是**附加收益**，不是签到本身的成败（native 也这么定位）；
//!   · 复核依赖睡 1.5 秒（宿主 sleep），会把一次签到 RPC 拖长；
//!   · 福利接口（`promotion-config` + 流水分页）是另一套契约，单独搬要再开一个
//!     模块，超出「签到」这条方法的范围。
//! 因此本方法只回签到本身的结果；活动福利在客户端下次启动 / 余额查询时会自然
//! 到账（那是服务端「登录即发」的行为，与插件无关）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credential;
use super::upstream;

/// 签到任务 id（源实现 `DAILY_SIGNIN_TASK_ID`）
const DAILY_SIGNIN_TASK_ID: &str = "daily_signin";

/// 完成任务路径（源实现 `TASK_COMPLETE_PATH`）
const TASK_COMPLETE_PATH: &str = "/autoclaw-proxy/proxy/autoclaw-task-complete";
/// 任务列表路径（签到未领取时归因用）
const TASK_LIST_PATH: &str = "/autoclaw-proxy/proxy/autoclaw-task-list";

/// 每日签到。
///
/// 返回协议里的 `CheckinReport` 形状：`{outcome, credit, streak, message}`。
/// `outcome` 的四个取值与网关的枚举一致：`claimed` / `done` / `inactive` / `failed`。
///
/// `account_id` 非空时必须是宿主当前账号（见 `upstream::account_record`）。
pub fn claim(account_id: &str) -> Result<Value> {
    let record = upstream::account_record(account_id)?;
    let credentials = credential::credential(&record)?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(401, "该账号没有可用凭证，无法签到"));
    }
    let body = json!({ "task_id": DAILY_SIGNIN_TASK_ID });
    let payload = upstream::post(TASK_COMPLETE_PATH, &credentials.token, &body, "签到")?;
    // 业务码判定：签到走的是通用任务接口，登录态失效同样以业务码表达
    if let Some(code) = upstream::code_of(&payload) {
        if upstream::is_auth_expired_code(code) {
            return Err(Error::http(401, "登录态已过期，无法签到"));
        }
        if code != 0 {
            let message = payload
                .get("msg")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("签到失败");
            return Ok(json!({
                "outcome": "failed", "credit": Value::Null, "streak": Value::Null,
                "message": message
            }));
        }
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let already_completed = data
        .get("already_completed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reported_success = data.get("success").and_then(Value::as_bool).unwrap_or(false);
    let reward_points = data.get("reward_points").and_then(Value::as_i64).unwrap_or(0);
    // 「本次领到了」的判据是 reward_points > 0 或显式 success。**已领过不算成功**。
    let claimed = reward_points > 0 || (reported_success && !already_completed);
    if claimed {
        let message = if reward_points > 0 {
            format!("签到成功，获得 {reward_points} 积分")
        } else {
            "签到成功".to_string()
        };
        return Ok(json!({
            "outcome": "claimed",
            "credit": if reward_points > 0 { json!(format!("{reward_points} 积分")) } else { Value::Null },
            "streak": Value::Null,
            "message": message,
        }));
    }
    // 未领到：区分「今天已领过」与「上游异常」，前者是正常的幂等结果
    if already_completed {
        return Ok(json!({
            "outcome": "done", "credit": Value::Null, "streak": Value::Null,
            "message": "今天已签到"
        }));
    }
    let hint = describe_task_state(&credentials);
    let message = match hint {
        Some(hint) => format!("签到未领取（{hint}）"),
        None => "签到未领取".to_string(),
    };
    // 上游说「没有可签到的活动」时归 inactive，否则按失败报
    let inactive = payload
        .get("msg")
        .and_then(Value::as_str)
        .map(|text| text.contains("没有可") || text.contains("活动未"))
        .unwrap_or(false);
    Ok(json!({
        "outcome": if inactive { "inactive" } else { "failed" },
        "credit": Value::Null,
        "streak": Value::Null,
        "message": message,
    }))
}

/// 签到未领取时，拉一次任务列表给出归因（**只读**，且失败不升级为错误）。
///
/// 返回 None 表示「列表里没有可用信息」——调用方据此退回通用文案，
/// 不把一次辅助查询的失败拼接进用户看到的消息里。
fn describe_task_state(credentials: &credential::Credential) -> Option<String> {
    let payload = upstream::get(TASK_LIST_PATH, &credentials.token, "任务列表查询").ok()?;
    if upstream::code_of(&payload).unwrap_or(0) != 0 {
        return None;
    }
    let tasks = payload.get("data").and_then(Value::as_array)?;
    let task = tasks
        .iter()
        .find(|item| item.get("task_id").and_then(Value::as_str) == Some(DAILY_SIGNIN_TASK_ID))?;
    let completed = task.get("completed").and_then(Value::as_bool).unwrap_or(false);
    if completed {
        Some("任务列表显示今天已完成".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `outcome` 的取值必须在网关的枚举内（错一个就是整条签到结果解析失败）。
    #[test]
    fn outcome_vocabulary() {
        for outcome in ["claimed", "done", "inactive", "failed"] {
            assert!(["claimed", "done", "inactive", "failed"].contains(&outcome));
        }
        // 任务 id 与上游路径都是契约，写错就静默「签到失败」
        assert_eq!("daily_signin", DAILY_SIGNIN_TASK_ID);
        assert!(TASK_COMPLETE_PATH.ends_with("autoclaw-task-complete"));
    }
}
