//! WorkBuddy **猫猫旅行**（growth 域的 buddy 子系统；从参考项目
//! `internal/upstream/travel.go` + `internal/scheduler/travel.go` 移植）。
//!
//! ── 这是什么 ────────────────────────────────────────────────
//! 上游的养成玩法：账号领养一只猫（Buddy），每天把猫派出去旅行一次，到站后领奖
//! （积分）。状态机很小：
//!
//! ```text
//! 无猫          → 同意协议 + 领养（buddy/first，+300c+8e；门槛未达时预期 400）
//! idle          → 派出（每日 1 次；已达当日上限则跳过）
//! traveling     → 在途，跳过（等下一趟）
//! arrived       → 领奖（带 record_id；reward_credit 入账）
//! ```
//!
//! ── 跳过与失败为什么必须分开 ────────────────────────────────
//! 跳过是**预期**的正常态（在途、已达当日上限、领养门槛未达、防抖挡下），失败是
//! 上游真的报错。混在一起会让界面天天显示「失败」，用户对真正的故障就麻木了。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Value};

use crate::util;

use super::{chat_call, GrowthAccount};

/// 派出地点固定 4（古镇客栈）：4 个地点的收益/时长区间完全相同，无最优解。
const TRAVEL_LOCATION_ID: i64 = 4;

/// 领养门槛未达的业务错误关键词（HTTP 400 时出现，属预期正常态）。
const BUDDY_TASK_INCOMPLETE_MARKER: &str = "first_buddy task not completed yet";

/// 猫猫旅行状态。
#[derive(Clone, Debug, Default)]
pub struct TravelState {
    /// idle / traveling / arrived / 未知
    pub state: String,
    /// 今日已派出过（自然日 00:00 CST 重置）
    pub daily_limit_reached: bool,
    /// 在途/到站记录 id（claim 必带）
    pub record_id: i64,
    /// 到站可领奖励积分
    pub reward_credit: i64,
}

impl TravelState {
    fn from_value(data: &Value) -> Self {
        Self {
            state: data
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            daily_limit_reached: data
                .get("daily_limit_reached")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            record_id: data.get("record_id").and_then(Value::as_i64).unwrap_or(0),
            reward_credit: data
                .get("reward_credit")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        }
    }
}

/// 猫档案（id + 名字）。
pub struct Buddy {
    /// 只作档案投影：派出的 `location_id` 是固定 4、领奖用 `record_id`，
    /// 上游没有任何动作按猫 id 走。留着它是为了让「有猫 / 无猫」的判据读的是
    /// 上游真实形状（空对象与 null 都算无猫）。
    #[allow(dead_code)]
    pub id: i64,
    pub name: String,
}

/// 查当前猫档案：`Ok(None)` = 无猫（data.buddy 为 null / 缺失）。
pub fn buddy_info(account: &GrowthAccount) -> std::result::Result<Option<Buddy>, String> {
    let call = chat_call(account, "GET", "/activity/growth/buddy/info", None, &[])?;
    if !call.ok() {
        return Err(format!(
            "猫档案查询失败（HTTP {} code={:?}）",
            call.status,
            call.code()
        ));
    }
    let buddy = call.data().get("buddy").cloned().unwrap_or(Value::Null);
    if buddy.is_null() {
        return Ok(None);
    }
    // 空对象也按「无猫」处理（上游的 null / {} 两种形态都出现过）
    if let Some(object) = buddy.as_object() {
        if object.is_empty() {
            return Ok(None);
        }
    }
    Ok(Some(Buddy {
        id: buddy.get("id").and_then(Value::as_i64).unwrap_or(0),
        name: buddy
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    }))
}

/// 查旅行状态（GET /activity/growth/buddy/travel/status）。
pub fn travel_status(account: &GrowthAccount) -> std::result::Result<TravelState, String> {
    let call = chat_call(
        account,
        "GET",
        "/activity/growth/buddy/travel/status",
        None,
        &[],
    )?;
    if !call.ok() {
        return Err(format!(
            "旅行状态查询失败（HTTP {} code={:?}）",
            call.status,
            call.code()
        ));
    }
    Ok(TravelState::from_value(&call.data()))
}

/// 派出（POST /activity/growth/buddy/travel/depart，地点固定 4）。
fn travel_depart(account: &GrowthAccount) -> std::result::Result<(), String> {
    let call = chat_call(
        account,
        "POST",
        "/activity/growth/buddy/travel/depart",
        Some(&json!({ "location_id": TRAVEL_LOCATION_ID })),
        &[],
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!(
            "派出失败（HTTP {} code={:?} {}）",
            call.status,
            call.code(),
            call.msg()
        ))
    }
}

/// 领奖（POST /activity/growth/buddy/travel/claim，带 record_id）→ reward_credit。
fn travel_claim(account: &GrowthAccount, record_id: i64) -> std::result::Result<i64, String> {
    let call = chat_call(
        account,
        "POST",
        "/activity/growth/buddy/travel/claim",
        Some(&json!({ "record_id": record_id })),
        &[],
    )?;
    if !call.ok() {
        return Err(format!(
            "领奖失败（HTTP {} code={:?} {}）",
            call.status,
            call.code(),
            call.msg()
        ));
    }
    Ok(call
        .data()
        .get("reward_credit")
        .and_then(Value::as_i64)
        .unwrap_or(0))
}

/// 领养（同意协议 → buddy/first；实现是单一事实源，在 `growth` 主模块）。
fn adopt(account: &GrowthAccount) -> (bool, bool, String) {
    let (ok, message) = super::adopt_buddy(account);
    // 门槛未达的判据：`adopt_buddy` 把它翻成中文文案；英文 marker 兜底
    // （上游文案若变化，仍按关键词识别，避免把预期正常态报成失败）
    let threshold_short =
        message.contains("门槛未达") || message.to_lowercase().contains(BUDDY_TASK_INCOMPLETE_MARKER);
    (ok, threshold_short, message)
}

// ─── 当日防抖（领养门槛未达时不反复打上游）──────────────────

/// 当天的防抖键（宿主会话存储，按自然日失效）。
///
/// native 用进程内的 `uid → 日键` 表；wasm 实例不保证跨调用存活，所以换成宿主的
/// 会话存储（`session.get` / `session.put`），键里带日期、值里也记日期 —— 两道
/// 判据都能挡住「同一天重复打上游」。
fn adopt_tried_key(uid: &str) -> String {
    format!("workbuddy-adopt:{uid}:{}", util::today_key())
}

fn adopt_tried_today(uid: &str) -> bool {
    let today = util::today_key();
    agent2api_wasm_sdk::session_get(&adopt_tried_key(uid))
        .ok()
        .and_then(|value| value.get("day").and_then(Value::as_str).map(str::to_string))
        .is_some_and(|day| day == today)
}

fn mark_adopt_tried(uid: &str) {
    let day = util::today_key();
    // TTL 取到当天结束：次日自动失效，不需要任何定时器
    let ttl = util::beijing_day_start(util::now_ms())
        .saturating_add(util::DAY_MS)
        .saturating_sub(util::now_ms())
        .max(1_000);
    let _ = agent2api_wasm_sdk::session_put(&adopt_tried_key(uid), json!({ "day": day }), ttl);
}

// ─── 单账号一趟巡检 ─────────────────────────────────────────

/// 一趟巡检的结论（界面按它渲染）。
pub struct TravelReport {
    /// no_buddy / adopt / depart / claim / skip / failed
    pub outcome: &'static str,
    /// 界面文案（如实描述这一步做了什么 / 为什么跳过）
    pub message: String,
    /// 本次入账积分（领奖 / 领养时可能非零）
    pub credit: i64,
}

/// 单账号单趟状态机：查有无猫 → 查状态 → 最多一个动作，不轮询不等待。
pub fn run_once(account: &GrowthAccount) -> TravelReport {
    let buddy = match buddy_info(account) {
        Ok(buddy) => buddy,
        Err(error) => {
            return TravelReport {
                outcome: "failed",
                message: error,
                credit: 0,
            }
        }
    };
    let Some(buddy) = buddy else {
        // 无猫：走领养链路（当日门槛未达过则跳过，不反复打）
        if adopt_tried_today(&account.uid) {
            return TravelReport {
                outcome: "skip",
                message: "领养门槛今日已判定未达（对话量不够），明天自动重试".to_string(),
                credit: 0,
            };
        }
        let (ok, threshold_short, message) = adopt(account);
        if ok {
            return TravelReport {
                outcome: "adopt",
                message,
                credit: 300,
            };
        }
        if threshold_short {
            mark_adopt_tried(&account.uid);
            return TravelReport {
                outcome: "skip",
                message,
                credit: 0,
            };
        }
        return TravelReport {
            outcome: "failed",
            message,
            credit: 0,
        };
    };

    let status = match travel_status(account) {
        Ok(status) => status,
        Err(error) => {
            return TravelReport {
                outcome: "failed",
                message: error,
                credit: 0,
            }
        }
    };
    match status.state.as_str() {
        "arrived" => {
            if status.record_id == 0 {
                return TravelReport {
                    outcome: "skip",
                    message: format!("已到站但缺 record_id，跳过（猫：{}）", buddy.name),
                    credit: 0,
                };
            }
            match travel_claim(account, status.record_id) {
                Ok(reward) => TravelReport {
                    outcome: "claim",
                    message: format!("到站领奖成功，积分 +{reward}（猫：{}）", buddy.name),
                    credit: reward,
                },
                Err(error) => TravelReport {
                    outcome: "failed",
                    message: error,
                    credit: 0,
                },
            }
        }
        "idle" => {
            if status.daily_limit_reached {
                return TravelReport {
                    outcome: "skip",
                    message: format!("今日已派出过（猫：{}），明天再来", buddy.name),
                    credit: 0,
                };
            }
            match travel_depart(account) {
                Ok(()) => TravelReport {
                    outcome: "depart",
                    message: format!("已派出旅行（猫：{}，地点：古镇客栈）", buddy.name),
                    credit: 0,
                },
                Err(error) => TravelReport {
                    outcome: "failed",
                    message: error,
                    credit: 0,
                },
            }
        }
        "traveling" => TravelReport {
            outcome: "skip",
            message: format!("猫在旅行途中（记录 {}），等下一趟", status.record_id),
            credit: 0,
        },
        other => TravelReport {
            outcome: "skip",
            message: format!("未知状态「{other}」，保守跳过"),
            credit: 0,
        },
    }
}

// ─── 多账号批量巡检（定时排程用）────────────────────────────

/// 一个账号的巡检汇总。
pub struct AccountTravelReport {
    pub account_id: String,
    pub name: String,
    /// run_once 的 outcome（no_buddy 不会出现：无猫走 adopt）
    pub outcome: &'static str,
    pub message: String,
    pub credit: i64,
}

/// 对一批账号跑一趟巡检。
///
/// ── 与 native 的差别（宿主没有账号列表）────────────────────
/// native 自己 `store.list` 遍历全部账号并在账号之间插 800ms；wasm 插件的 ABI 里
/// 没有账号列表，所以这里对**宿主给的账号**跑（通常一个），账号间错峰留在网关的
/// 调度器那一层。
///
/// ── 门控 ────────────────────────────────────────────────────
/// 只服务 WorkBuddy 国内版的个人账号（企业版没有成长体系）。
pub fn run_for_accounts(accounts: &[Value]) -> Vec<AccountTravelReport> {
    let mut reports: Vec<AccountTravelReport> = Vec::new();
    for account in accounts {
        let id = account.get("id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() || !super::supports_growth(account) {
            continue;
        }
        // 企业版没有个人成长体系（上游固定 400 code 10001）
        if account
            .get("enterpriseId")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            continue;
        }
        let name = account
            .get("name")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .or_else(|| account.get("nickname").and_then(Value::as_str))
            .unwrap_or(id)
            .to_string();
        let Some(growth_account) = super::account_of(account) else {
            continue;
        };
        let report = run_once(&growth_account);
        reports.push(AccountTravelReport {
            account_id: id.to_string(),
            name,
            outcome: report.outcome,
            message: report.message,
            credit: report.credit,
        });
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn travel_state_reads_upstream_fields() {
        let state = TravelState::from_value(&json!({
            "state": "arrived", "daily_limit_reached": true,
            "record_id": 12, "reward_credit": 40
        }));
        assert_eq!(state.state, "arrived");
        assert!(state.daily_limit_reached);
        assert_eq!(state.record_id, 12);
        assert_eq!(state.reward_credit, 40);
    }

    #[test]
    fn missing_fields_default_to_empty_not_error() {
        let state = TravelState::from_value(&json!({}));
        assert_eq!(state.state, "");
        assert_eq!(state.record_id, 0);
    }
}
