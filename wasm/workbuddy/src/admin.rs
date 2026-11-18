//! WorkBuddy 的**管理动作**（协议方法 `admin.action` 的实现）。
//!
//! ── 这些动作原来是网关的 HTTP 端点 ───────────────────────────
//! ```text
//!   GET  /api/accounts/{id}/growth           → action = "growth.status"
//!   POST /api/accounts/{id}/growth/task      → action = "growth.task"
//!   POST /api/accounts/{id}/growth/school    → action = "growth.school"
//!   POST /api/accounts/{id}/growth/travel    → action = "growth.travel"
//!   POST /api/growth/travel/run              → action = "growth.travel.batch"
//!   （签到末尾的连登管家）                     → action = "growth.streak.batch"
//!   GET  /api/usage / /api/checkin …          → action = "billing.*"
//! ```
//! 迁移时**返回形状逐字保留**：前端读的就是这些键，形状一变界面就白屏。
//!
//! ── 为什么不用具名方法 ──────────────────────────────────────
//! 签到（`checkin`）是跨家有共识的语义，协议里有具名方法；这里是 WorkBuddy 独有的
//! 一整棵任务树 + 猫猫旅行 + 开学季 + 计费运营动作，别家没有对应概念。
//!
//! ── 批量动作在 wasm 侧只跑当前账号 ─────────────────────────
//! native 的 `.batch` 动作自己 `store.list` 列出本家全部账号再逐个跑。wasm 插件的
//! ABI 里**没有账号列表**这一项，所以这里对宿主给的当前账号跑一趟，返回**单元素**
//! 结果数组（键名与形状不变）—— 网关的调度器逐账号调用即可，账号间错峰留在调度器
//! 那一层。`growth.streak.batch` / `growth.travel.batch` 都按这条走。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::billing::ops;
use crate::growth::{
    self, school, spec,
    travel::{self, AccountTravelReport},
    GrowthAccount, TaskOutcome,
};
use crate::outbound;
use crate::search;

/// 本家支持的全部管理动作（网关只透传，取值域由这里定义）。
pub const ACTIONS: &[&str] = &[
    // ── 登录方式申报（不需要账号，见 `login::methods`）─────────────
    // wasm 包的登录方式走**动态契约**：网关把 `admin.action = auth.methods` 的
    // 返回直接反序列化成 `LoginMethodsMetadata`（`api/session.rs:263-280`，
    // wasm 恒走这条），不认 `metadata.json` 的静态形态。缺这一条时
    // `/api/session/login/methods` 回 501，添加账号面板整个打不开。
    "auth.methods",
    "growth.status",
    "growth.task",
    "growth.school",
    "growth.travel",
    "growth.travel.batch",
    "growth.streak",
    "growth.streak.batch",
    "growth.daily",
    "activity.run",
    // ── 计费 / 运营（见 `billing::ops`）───────────────────────────
    "billing.checkin-status",
    "billing.checkin-claim",
    "billing.reward",
    "billing.banner",
    "billing.ambassador",
    // ── 原生搜索（见 `search`）────────────────────────────────
    search::CAPABILITIES,
    search::SEARCH,
];

/// 分发一次管理动作。
///
/// `payload` 是厂商自定义参数（网关不理解内容）。
pub fn dispatch(action: &str, payload: &Value) -> Result<Value> {
    // ── 登录方式申报：不碰账号，最先分流 ────────────────────────
    // 网关在「打开添加账号面板」这一刻就会问这条（早于任何账号存在），而下面
    // 的白名单校验与读账号都在后面 —— 不在最前面返回，面板必然打不开
    if action == "auth.methods" {
        return Ok(crate::login::methods());
    }
    // ── 原生搜索：不碰账号体系之外的状态，先分流 ────────────────
    if matches!(action, search::CAPABILITIES | search::SEARCH) {
        return search::dispatch(action, payload);
    }
    // ── 计费 / 运营动作：与成长任务无关，先分流 ────────────────
    if action.starts_with("billing.") {
        return billing_action(action, payload);
    }
    // 国际版才有的「每日活跃」动作：本包是国内版，明确说清楚
    if action == "activity.run" {
        return Err(Error::http(
            400,
            "该账号不支持成长任务（仅 WorkBuddy 国内版）",
        ));
    }
    // 取值域先校验：不认识的动作不该走到「读账号」那一步（否则在没有账号的环境里
    // 会被误报成凭证错误，排障时会往错的方向找）
    if !ACTIONS.contains(&action) {
        return Err(Error::http(
            501,
            format!(
                "WorkBuddy 不认识管理动作「{action}」（可用：{}）",
                ACTIONS.join(" / ")
            ),
        )
        .with_code("unsupported"));
    }
    let account_id = sdk::account()?
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    match action {
        "growth.status" => {
            let account = growth_account()?;
            growth_status(&account_id, &account)
        }
        "growth.task" => {
            let account = growth_account()?;
            growth_task(&account_id, &account, payload)
        }
        "growth.school" => {
            let account = growth_account()?;
            growth_school(&account_id, &account, payload)
        }
        "growth.travel" => {
            let account = growth_account()?;
            growth_travel(&account_id, &account)
        }
        "growth.travel.batch" => batch_travel(),
        "growth.streak" | "growth.streak.batch" => streak_report(),
        "growth.daily" => {
            let account = growth_account()?;
            Ok(daily_report(&account))
        }
        // 取值域已在上面校验过；走到这里说明 ACTIONS 与 match 分支不同步
        other => Err(Error::http(
            501,
            format!("WorkBuddy 管理动作「{other}」尚未接线（插件缺陷）"),
        )
        .with_code("unsupported")),
    }
}

/// 计费 / 运营动作的分流。
fn billing_action(action: &str, payload: &Value) -> Result<Value> {
    let secret = crate::account::secret()?;
    if !secret.is_object() {
        return Err(Error::http(401, "该账号没有可用凭证"));
    }
    let session = outbound::session_of_record(&secret);
    match action {
        "billing.checkin-status" => ops::checkin_status(&session),
        "billing.checkin-claim" => ops::claim_daily(&session),
        "billing.reward" => {
            let kind = payload.get("kind").and_then(Value::as_str).unwrap_or("");
            ops::claim_reward(&session, kind)
        }
        "billing.banner" => Ok(ops::banner(&session)),
        "billing.ambassador" => Ok(ops::ambassador(&session)),
        other => Err(Error::http(
            400,
            format!("WorkBuddy 不认识计费动作「{other}」"),
        )),
    }
}

/// 跑连登管家并把报告摊成 JSON（形状与 native `streak_report` 逐字相同）。
fn streak_report() -> Result<Value> {
    let record = sdk::account()?;
    let reports = growth::streak::run_for_accounts(std::slice::from_ref(&record));
    let done: usize = reports.iter().map(|report| report.done).sum();
    let failed: usize = reports.iter().map(|report| report.failed).sum();
    Ok(json!({
        "results": reports.iter().map(|report| json!({
            "accountId": report.account_id,
            "name": report.name,
            "done": report.done,
            "failed": report.failed,
            "messages": report.messages,
        })).collect::<Vec<Value>>(),
        "done": done,
        "failed": failed,
    }))
}

/// 每日活跃上报的结果行（网关把它挂在签到结果行的 `growth` 键上）。
///
/// 形状与网关 `checkin_for` 里那段逐字一致：`{reported, streakDays, error}`。
/// **失败也是 200**（`error` 字段带原因）：这是一项附加收益，报成失败会让一次成功
/// 的签到看起来像出错了。
fn daily_report(account: &GrowthAccount) -> Value {
    match growth::daily_activity::report(account) {
        Ok(report) => json!({
            "reported": report.sent,
            "streakDays": report.streak_days.map(Value::from).unwrap_or(Value::Null),
            "error": Value::Null,
        }),
        Err(error) => json!({
            "reported": false,
            "streakDays": Value::Null,
            "error": error,
        }),
    }
}

/// 把扁平 secret 折成会话，再派生 growth 上下文。
fn growth_account() -> Result<GrowthAccount> {
    let secret = crate::account::secret()?;
    if !secret.is_object() {
        return Err(Error::http(400, "账号没有可用凭证，请先刷新登录态"));
    }
    growth::account_of(&secret).ok_or_else(|| Error::http(400, "账号没有可用 accessToken，请重新登录"))
}

/// 任务行的展示形状（界面按它渲染任务清单）。
fn task_row(task: &Value) -> Value {
    let code = task.get("task_code").and_then(Value::as_str).unwrap_or("");
    let spec = spec::spec_of(code);
    let progress = task.get("progress").cloned().unwrap_or(Value::Null);
    json!({
        "code": code,
        "title": task.get("title").and_then(Value::as_str).unwrap_or(""),
        "description": task.get("description").and_then(Value::as_str).unwrap_or(""),
        "status": task.get("accept_status").and_then(Value::as_str).unwrap_or(""),
        "current": progress.get("current").and_then(Value::as_i64).unwrap_or(0),
        "target": progress.get("target").and_then(Value::as_i64).unwrap_or(0),
        "locked": task.get("locked").and_then(Value::as_bool).unwrap_or(false),
        "unlockAt": task.get("unlock_at").cloned().unwrap_or(Value::Null),
        // 是否在映射表里（未映射任务在执行时会保守跳过 —— 界面如实标注）
        "supported": spec.is_some(),
        "unforgeable": spec.as_ref().map(|spec| spec.unforgeable).unwrap_or(false),
        "unforgeableReason": spec.as_ref().map(|spec| spec.reason).unwrap_or(""),
        "kind": spec.as_ref().map(|spec| spec.kind).unwrap_or(""),
        "source": spec.as_ref().map(|spec| spec.src).unwrap_or(""),
    })
}

/// `growth.status` —— 任务盘点（只读，不发任何写请求）。
///
/// 返回四块：成长任务清单、能量/连登读数、猫猫旅行状态、开学季概况。
/// 各块相互独立：某一块拉取失败只在该块给 `error`，不影响其余。
fn growth_status(account_id: &str, account: &GrowthAccount) -> Result<Value> {
    // ── 成长任务清单 ──
    // 两个口径都要拉：小程序限定任务只在带 `X-Client-Platform: miniprogram` 的
    // 列表里下发。合并时默认口径优先（同码不重复）。
    let tasks_block = match growth::list_tasks(account, false) {
        Ok(default_tasks) => {
            let mut rows: Vec<Value> = default_tasks.iter().map(task_row).collect();
            let mut known: Vec<String> = rows
                .iter()
                .filter_map(|row| row.get("code").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            if let Ok(mp_tasks) = growth::list_tasks(account, true) {
                for task in &mp_tasks {
                    let code = task.get("task_code").and_then(Value::as_str).unwrap_or("");
                    if code.is_empty() || known.iter().any(|item| item == code) {
                        continue;
                    }
                    known.push(code.to_string());
                    rows.push(task_row(task));
                }
            }
            json!({ "tasks": rows, "error": Value::Null })
        }
        Err(error) => json!({ "tasks": [], "error": error }),
    };

    // ── 能量 / 连登读数（只读 oracle，失败给 null）──
    let energy = growth::energy_balance(account);
    let streak = growth::growth_streak(account);

    // ── 猫猫旅行状态 ──
    let travel_block = match travel::buddy_info(account) {
        Ok(Some(buddy)) => {
            let status = travel::travel_status(account);
            match status {
                Ok(status) => json!({
                    "hasBuddy": true,
                    "buddyName": buddy.name,
                    "state": status.state,
                    "dailyLimitReached": status.daily_limit_reached,
                    "recordId": status.record_id,
                    "rewardCredit": status.reward_credit,
                    "error": Value::Null,
                }),
                Err(error) => json!({
                    "hasBuddy": true,
                    "buddyName": buddy.name,
                    "state": "",
                    "error": error,
                }),
            }
        }
        Ok(None) => json!({
            "hasBuddy": false,
            "buddyName": "",
            "state": "",
            "error": Value::Null,
        }),
        Err(error) => json!({ "hasBuddy": Value::Null, "error": error }),
    };

    // ── 开学季概况（任务列表 + 抽奖余额）──
    let school_block = match school::fetch_tasks(account) {
        Ok((tasks, in_period)) => {
            let lottery = school::fetch_lottery(account);
            let chance = lottery
                .as_ref()
                .ok()
                .map(|(_, chance)| {
                    json!({
                        "balance": chance.get("balance").and_then(Value::as_i64).unwrap_or(0),
                        "totalEarned": chance.get("total_earned").and_then(Value::as_i64).unwrap_or(0),
                    })
                })
                .unwrap_or(Value::Null);
            json!({
                "inPeriod": in_period,
                "tasks": tasks.iter().map(|task| {
                    let code = task.get("task_code").and_then(Value::as_str).unwrap_or("");
                    json!({
                        "code": code,
                        "title": task.get("title").and_then(Value::as_str).unwrap_or(""),
                        "status": task.get("status").and_then(Value::as_str).unwrap_or(""),
                        "current": task.get("progress").and_then(Value::as_i64).unwrap_or(0),
                        "target": task.get("target_count").and_then(Value::as_i64).unwrap_or(0),
                        "rewardCredit": task.get("reward_credit").and_then(Value::as_i64).unwrap_or(0),
                    })
                }).collect::<Vec<Value>>(),
                "lottery": chance,
                "error": Value::Null,
            })
        }
        Err(error) => json!({ "inPeriod": false, "tasks": [], "lottery": Value::Null, "error": error }),
    };

    Ok(json!({
        "id": account_id,
        "uid": account.uid,
        "nick": account.nick,
        "energy": energy,
        "streak": streak,
        "tasks": tasks_block,
        "travel": travel_block,
        "school": school_block,
    }))
}

/// `growth.task` —— 执行**单个**任务（`payload = {code, mode}`）。
///
/// `mode=full`（缺省）：accept（若未接单）→ 点亮上报 → 回读 → claim；
/// `mode=claim`：只领奖（已完成/已领走幂等 claim，未完成跳过）。
fn growth_task(account_id: &str, account: &GrowthAccount, payload: &Value) -> Result<Value> {
    let code = payload.get("code").and_then(Value::as_str).unwrap_or("");
    if code.is_empty() {
        return Err(Error::http(400, "缺少任务码（code）"));
    }
    let mode = payload.get("mode").and_then(Value::as_str).unwrap_or("full");
    // 列表口径按任务的域走：小程序任务只在带 mp 头的列表里下发
    let mp = spec::spec_of(code).map(|spec| spec.mp).unwrap_or(false);
    let tasks = growth::list_tasks(account, mp)
        .map_err(|error| Error::http(502, error))?;
    let Some(task) = growth::find_task(&tasks, code) else {
        return Ok(json!({
            "id": account_id,
            "code": code,
            "outcome": "skipped",
            "message": "任务不存在（可能已下线）",
            "credit": 0,
            "energy": 0,
        }));
    };
    let report = if mode == "claim" {
        // 只领奖：未完成的任务不动（服务端对未完成任务 claim 返回 not completed）
        let accept_status = task.get("accept_status").and_then(Value::as_str).unwrap_or("");
        let progress = task.get("progress").cloned().unwrap_or(Value::Null);
        let current = progress.get("current").and_then(Value::as_i64).unwrap_or(0);
        let target = progress.get("target").and_then(Value::as_i64).unwrap_or(1);
        if accept_status != "completed" && accept_status != "claimed" && current < target {
            growth::TaskReport::skipped(
                code,
                format!("未完成（{current}/{target}），未点亮不领取"),
            )
        } else {
            // 小程序限定任务的 claim 必须带 `X-Client-Platform: miniprogram`
            let (result, credit, energy, message) = growth::claim_task(account, code, mp);
            growth::TaskReport::claimed(
                code,
                match result {
                    1 => TaskOutcome::Done,
                    2 => TaskOutcome::Already,
                    _ => TaskOutcome::Failed,
                },
                message,
                credit,
                energy,
            )
        }
    } else if code == "first_buddy" {
        growth::process_first_buddy(account, &task)
    } else {
        growth::process_task(account, code, &task)
    };
    Ok(json!({
        "id": account_id,
        "code": report.code,
        "outcome": report.outcome.as_str(),
        "message": report.message,
        "credit": report.credit,
        "energy": report.energy,
    }))
}

/// `growth.school` —— 开学季任务 + 可选抽奖（`payload = {only, lottery}`）。
fn growth_school(account_id: &str, account: &GrowthAccount, payload: &Value) -> Result<Value> {
    let only: Vec<String> = payload
        .get("only")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let lottery = payload
        .get("lottery")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (reports, lottery_result) = school::run_all(account, &only, lottery);
    let rows: Vec<Value> = reports
        .iter()
        .map(|report| {
            json!({
                "code": report.code,
                "outcome": report.outcome,
                "message": report.message,
            })
        })
        .collect();
    Ok(json!({
        "id": account_id,
        "results": rows,
        "lottery": lottery_result.unwrap_or(Value::Null),
    }))
}

/// `growth.travel` —— 猫猫旅行巡检一次（一趟只推进一步）。
fn growth_travel(account_id: &str, account: &GrowthAccount) -> Result<Value> {
    let report = travel::run_once(account);
    Ok(json!({
        "id": account_id,
        "outcome": report.outcome,
        "message": report.message,
        "credit": report.credit,
    }))
}

/// `growth.travel.batch` —— 定时排程那一趟（wasm 侧只跑宿主给的当前账号）。
///
/// 返回网关 `growth_scheduler::summarize` 的同形摘要（它直接落进配置的
/// `lastResult`，前端那格读的就是这几个键）。
fn batch_travel() -> Result<Value> {
    let record = sdk::account()?;
    let reports: Vec<AccountTravelReport> = travel::run_for_accounts(std::slice::from_ref(&record));
    let actions: Vec<Value> = reports
        .iter()
        .filter(|report| matches!(report.outcome, "adopt" | "depart" | "claim" | "failed"))
        .map(|report| {
            json!({
                "accountId": report.account_id,
                "name": report.name,
                "outcome": report.outcome,
                "message": report.message,
                "credit": report.credit,
            })
        })
        .collect();
    let credit: i64 = reports.iter().map(|report| report.credit).sum();
    let failed = reports
        .iter()
        .filter(|report| report.outcome == "failed")
        .count();
    Ok(json!({
        "at": crate::util::now_ms(),
        "accounts": reports.len(),
        "actions": actions,
        "credit": credit,
        "failed": failed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_cover_billing_growth_and_search() {
        for action in [
            "auth.methods",
            "growth.status",
            "growth.task",
            "growth.school",
            "growth.travel",
            "growth.travel.batch",
            "growth.streak",
            "growth.streak.batch",
            "growth.daily",
            "billing.checkin-status",
            "billing.checkin-claim",
            "billing.reward",
            "billing.banner",
            "billing.ambassador",
            "web-search.capabilities",
            "web-search.search",
        ] {
            assert!(ACTIONS.contains(&action), "{action} 未登记");
        }
    }

    #[test]
    fn activity_run_is_rejected_for_the_cn_package() {
        let error = dispatch("activity.run", &json!({})).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
    }

    /// `auth.methods` 必须在**读账号之前**返回：网关打开添加账号面板时就问它，
    /// 那一刻还没有任何账号。
    #[test]
    fn auth_methods_needs_no_account() {
        let value = dispatch("auth.methods", &json!({})).unwrap_or(Value::Null);
        let methods = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, methods.len());
        assert_eq!("oauth", methods[0]["type"].as_str().unwrap_or(""));
        assert_eq!("网页登录", methods[0]["label"].as_str().unwrap_or(""));
    }

    #[test]
    fn unknown_actions_report_unsupported() {
        let error = dispatch("growth.unknown", &json!({})).err();
        let error = match error {
            Some(error) => error,
            None => Error::new("未按预期失败"),
        };
        assert_eq!(error.status, Some(501));
        assert_eq!(error.code.as_deref(), Some("unsupported"));
    }

    #[test]
    fn search_capabilities_needs_no_account() {
        let value = dispatch("web-search.capabilities", &json!({})).unwrap_or(Value::Null);
        assert_eq!(value["search"], json!(true));
    }

    #[test]
    fn task_rows_mark_unmapped_tasks() {
        let row = task_row(&json!({
            "task_code": "unknown_x", "title": "x", "progress": { "current": 1, "target": 2 }
        }));
        assert_eq!(row["supported"], json!(false));
        let row = task_row(&json!({
            "task_code": "Sequential_Tasks_6", "progress": { "current": 0, "target": 10 }
        }));
        assert_eq!(row["supported"], json!(true));
        assert_eq!(row["kind"], json!("minichat"));
    }
}
