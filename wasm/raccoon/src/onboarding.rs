//! 小浣熊新手任务（onboarding）：首次登录奖励（电脑端 / 手机端）的查询与领取。
//!
//! ── 上游契约（已确认 + 实测）────────────────────────────
//! 小浣熊没有 Loomy 那种「任务表 + 逐项上报」的新手任务接口，它的新手福利
//! 是两条**各领一次**的首次登录奖励，电脑端与手机端各有一条专属端点：
//!
//! ```text
//! POST {主站}/api/web/desktop/v1/login/points/grant   桌面端身份头
//! POST {主站}/api/web/mobile/v1/login/points/grant    手机端身份头（app-android）
//!   头: Authorization: Bearer <token>（两端同一把，token 无平台绑定）
//!   → {code:0, data:{ granted: true|false, popup?:{ source, points, expire_at } }}
//! ```
//!
//! 官方客户端每次启动 / 回前台都会打它；服务端对**首次**登录的账号发放一笔
//! 积分（名义各 3000，实际数额以响应 `popup.points` 为准），已发放过的账号
//! 返回 `granted=false`（幂等，不重复加分）。两条端点互不共享额度：桌面端
//! 早已领过的账号，手机端那条照样能拿满（实测确认）。
//!
//! ── 「已领取」状态从哪来（结算台账）────────────────────────
//! 上游没有「这个账号领没领过首登奖励」的只读判定口（账单 event_name 的取值
//! 没有足量样本，按词匹配不可靠；bills 又慢，不能挂在状态查询上）。因此状态
//! 查询**不打任何上游请求**，唯一的真实性来源是本插件自己的**结算台账**：
//! 领取一步无论 `granted` 真假（两种都代表奖励已落定）都落一条台账，此后
//! 查询恒报「已领取」。代价是台账没落之前（奖励早被官方客户端领掉的老账号）
//! 状态未知、如实显示「待领取」—— 一次领取即收敛为「已领取」。
//!
//! ── 台账存在哪（与 native 的结构差异）──────────────────────
//! native 侧走 `ctx.ledger_get` / `ledger_put`（网关的 `pluginLedger.<kind>`），
//! 并把它拆成两份（`onboardingGrants` 与签到中心快照 `onboarding`）。
//! wasm ABI 没有台账方法，能做到「跨调用持久 + 条件更新」的只有宿主的状态区
//! （`state.get` / `state.compare_exchange`，账号作用域）。因此这里把两份合成
//! 一份：`{ grants: { <taskKey>: <毫秒时刻> } }`。签到中心那份快照本来就是
//! **从 grants 推出来的**（native 的 `settled_view`），不需要单独落盘。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::credentials;
use crate::errors as upstream_errors;
use crate::{headers, upstream};

/// 首次电脑端登录奖励的任务 key
pub const TASK_KEY_DESKTOP: &str = "desktop_login_grant";
/// 首次手机端登录奖励的任务 key
pub const TASK_KEY_MOBILE: &str = "mobile_login_grant";

/// 台账在宿主状态区里的键与版本。
const LEDGER_KEY: &str = "onboarding";
const LEDGER_SCHEMA: u32 = 1;
/// CAS 冲突时的重试次数（并发领取/查询导致版本变化时重读重试）。
const LEDGER_ATTEMPTS: usize = 3;

/// 任务分组
pub const TASK_GROUP: &str = "初识小浣熊";
/// 奖励的名义分值（上游名义值，仅用于界面展示与台账外没有实测时的兜底；
/// 实际入账以响应 popup.points 与账单为准）
pub const TASK_POINTS: i64 = 3000;
/// 全部任务的分值合计（get_tasks / claim_all 的 `total`）
pub const TOTAL_POINTS: i64 = TASK_POINTS * 2;

/// 一条新手任务 = 一条一次性登录奖励端点。
///
/// `mobile` 只决定请求带哪套客户端身份头，**不**影响凭证 —— 两端认同一把
/// Bearer token。
struct Task {
    key: &'static str,
    title: &'static str,
    path: &'static str,
    mobile: bool,
}

/// 任务表（数组顺序即界面展示顺序）
const TASKS: [Task; 2] = [
    Task {
        key: TASK_KEY_DESKTOP,
        title: "首次电脑端登录奖励",
        path: "/api/web/desktop/v1/login/points/grant",
        mobile: false,
    },
    Task {
        key: TASK_KEY_MOBILE,
        title: "首次手机端登录奖励",
        path: "/api/web/mobile/v1/login/points/grant",
        mobile: true,
    },
];

/// 台账里某条任务的结算时刻（0 = 未结算，状态未知）。
fn settled_at(ledger: &Value, key: &str) -> i64 {
    ledger
        .pointer(&format!("/grants/{key}"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// 读结算台账（读不到 / 不是对象 → 空台账）。
fn load_ledger() -> Value {
    match sdk::state::get(sdk::state::Scope::Account, LEDGER_KEY, LEDGER_SCHEMA) {
        Ok(snapshot) if snapshot.value.is_object() => snapshot.value,
        _ => json!({ "grants": {} }),
    }
}

/// 把若干条结算时刻写进台账（**比较再写**，冲突重试）。
///
/// 返回 false = 三次都没写进去（并发太高）。调用方照 native 的口径只记日志：
/// 上游那边该领的已经领了，不能因为一次落库失败把结果说成没领。
fn save_grants(entries: &[(String, i64)]) -> Result<bool> {
    for _ in 0..LEDGER_ATTEMPTS {
        let snapshot = sdk::state::get(sdk::state::Scope::Account, LEDGER_KEY, LEDGER_SCHEMA)?;
        if !snapshot.compatible {
            return Err(Error::new("小浣熊新手任务台账格式已变化，请更新插件后再试"));
        }
        let mut value = if snapshot.value.is_object() {
            snapshot.value.clone()
        } else {
            json!({ "grants": {} })
        };
        if !value.get("grants").is_some_and(Value::is_object) {
            value["grants"] = json!({});
        }
        if let Some(grants) = value.get_mut("grants").and_then(Value::as_object_mut) {
            for (key, at) in entries {
                grants.insert(key.clone(), Value::from(*at));
            }
        }
        if sdk::state::compare_exchange(
            sdk::state::Scope::Account,
            LEDGER_KEY,
            LEDGER_SCHEMA,
            snapshot.revision,
            value,
            0,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 按台账组装任务行（界面直接渲染的形状）。
fn task_rows(ledger: &Value) -> Vec<Value> {
    TASKS
        .iter()
        .map(|task| {
            json!({
                "key": task.key,
                "title": task.title,
                "group": TASK_GROUP,
                "points": TASK_POINTS,
                "done": settled_at(ledger, task.key) > 0,
            })
        })
        .collect()
}

/// 已结算任务的分值合计（`earned`；按任务名义值算）。
fn earned_of(ledger: &Value) -> i64 {
    TASKS
        .iter()
        .filter(|task| settled_at(ledger, task.key) > 0)
        .map(|_| TASK_POINTS)
        .sum()
}

/// 未结算的任务数。
fn unclaimed_of(rows: &[Value]) -> usize {
    rows.iter()
        .filter(|row| !row.get("done").and_then(Value::as_bool).unwrap_or(false))
        .count()
}

/// 两条台账里较晚的结算时刻（两条都结算时才是有效值；未结算用 0）。
fn settled_at_of(ledger: &Value) -> i64 {
    TASKS
        .iter()
        .map(|task| settled_at(ledger, task.key))
        .max()
        .unwrap_or(0)
}

/// 签到中心快照用：两条都结算过就给一份「已结清」的记忆（零上游），否则 None
/// —— 与 Loomy / CodeArts 的 `onboardingSettled` 同形，消费方不必按 provider 分叉。
///
/// ⚠️ wasm ABI 目前**没有**「签到中心快照」这条方法（native 侧也是给了函数、
/// 挂着 `allow(dead_code)` 等挂点）。判据先立住：等协议给出挂点（`Provider`
/// trait 上加一支）时直接接上，免得届时的实现者再重新推一遍「什么时候算结清」。
#[allow(dead_code)]
pub fn settled_view(ledger: &Value) -> Option<Value> {
    let rows = task_rows(ledger);
    if unclaimed_of(&rows) > 0 {
        return None;
    }
    Some(json!({
        "at": settled_at_of(ledger),
        "tasks": rows,
        "earned": earned_of(ledger),
        "total": TOTAL_POINTS,
    }))
}

/// 打一次 grant 探测（幂等），返回上游 `data` 对象。
///
/// 请求失败在这里就是失败（返回 Err），不降级 —— 调用方据此向界面如实报错。
/// 401（登录态失效）由调用方截住整体失败。
fn probe_grant(task: &Task) -> Result<Value> {
    let credentials = credentials::snapshot()?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(401, "该账号没有可用凭证，无法领取新手任务"));
    }
    let mut request_headers = if task.mobile {
        crate::balance::mobile_client_headers()
    } else {
        crate::balance::desktop_client_headers()
    };
    headers::append_org(&mut request_headers, &credentials.org_code)?;
    let url = format!("{}{}", upstream::main_site(), task.path);
    request_headers.push((
        "Authorization".to_string(),
        format!("Bearer {}", crate::jwt::strip_bearer(&credentials.token)),
    ));
    request_headers.push(("Accept".to_string(), "application/json".to_string()));
    // native 的 `request_json_ex` 对这条链路是不带 body 的 POST，这里保持一致
    // （上游按身份头与空 body 结算，带一个 `{}` 反而多一种没验证过的形态）。
    let response = upstream::send("POST", &url, &request_headers, None)
        .map_err(|error| upstream::transport("新手任务领取失败", error))?;
    let payload = response.payload;
    if response.status == 401 || upstream_errors::token_expired(&payload) {
        return Err(Error::http(401, "登录态已过期，无法领取新手任务"));
    }
    if !response.ok {
        return Err(Error::http(
            502,
            format!("新手任务领取返回 HTTP {}", response.status),
        ));
    }
    if let Some(code) = upstream_errors::business_code(&payload) {
        if code != 0 {
            return Err(Error::http(502, upstream_errors::message(&payload)));
        }
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    if data.is_object() {
        Ok(data)
    } else {
        Err(Error::http(502, "新手任务领取响应缺少 data"))
    }
}

/// 探测结果 →（是否本轮刚发放，本轮入账分值）。
///
/// 实际数额以响应 `popup.points` 为准（手机端实测带该字段），取不到回落名义值
/// —— `granted=false` 时本轮没有入账，分值记 0。
fn granted_outcome(data: &Value) -> Result<(bool, i64)> {
    let granted = data
        .get("granted")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::http(502, "登录奖励响应缺少 granted，尚未确认领取"))?;
    let points = if granted {
        data.pointer("/popup/points")
            .and_then(Value::as_i64)
            .filter(|points| *points > 0)
            .unwrap_or(TASK_POINTS)
    } else {
        0
    };
    Ok((granted, points))
}

/// `claim.status`：查询任务状态（**只读**：不发任何上游请求）。
///
/// 响应形状与 Loomy 对齐：`{tasks:[…], earned, total, unclaimed, settled, settledAt}`。
/// `done` 来自结算台账：结算过恒「已领取」，没结算过恒「待领取」—— 状态未知
/// 就说未知，不假装知道上游的真实发放状态。
///
/// `refresh` 在本家**没有实查可做**：上游没有「领没领过」的只读判定口，
/// 台账就是唯一真实性来源。参数只为接口形状与另外两家一致。
pub fn get_tasks(params: &Value) -> Result<Value> {
    let _ = params;
    // 记录存在性先确认（账号被删时该报 404，而不是回一份空任务表）
    sdk::account().map_err(|_| Error::http(404, "未找到小浣熊账号"))?;
    let ledger = load_ledger();
    let rows = task_rows(&ledger);
    let unclaimed = unclaimed_of(&rows);
    let settled_at = if unclaimed == 0 {
        settled_at_of(&ledger)
    } else {
        0
    };
    Ok(json!({
        "tasks": rows,
        "earned": earned_of(&ledger),
        "total": TOTAL_POINTS,
        "unclaimed": unclaimed,
        // 两条都结算过 ⇒ 一次性福利到此为止（界面据此不再重复查询）。
        "settled": unclaimed == 0,
        // 结算时刻：`settled` 为真时给两条台账里较晚的那个，否则 null
        "settledAt": if unclaimed == 0 { json!(settled_at) } else { Value::Null },
    }))
}

/// `claim`：领取（只对**未结算**的任务逐条探测，串行）。
///
/// 探测成功（无论 `granted` 真假）都落结算台账 —— 这一步就是「已领取」标记的
/// 写入点。台账里已结算的不发请求也不进 `results`。响应形状与
/// `loomy::onboarding::claim_all` 对齐（results / claimed / failed /
/// claimedPoints / tasks / earned / total / unclaimed / settled / settledAt）。
pub fn claim_all(params: &Value) -> Result<Value> {
    let _ = params;
    sdk::account().map_err(|_| Error::http(404, "未找到小浣熊账号"))?;
    let ledger_before = load_ledger();
    let now = sdk::now();
    let mut rows: Vec<Value> = Vec::new();
    let mut claimed = 0_i64;
    let mut failed = 0_i64;
    let mut claimed_points = 0_i64;
    // 结算台账的本次增量：探测成功才写（失败的任务保持未结算，可重试）
    let mut settled: Vec<(String, i64)> = Vec::new();

    for task in TASKS.iter() {
        if settled_at(&ledger_before, task.key) > 0 {
            continue;
        }
        match probe_grant(task).and_then(|data| granted_outcome(&data)) {
            Ok((granted, points)) => {
                claimed += 1;
                claimed_points += points;
                settled.push((task.key.to_string(), now));
                rows.push(json!({
                    "key": task.key,
                    "ok": true,
                    "already": !granted,
                    "points": points,
                }));
            }
            Err(error) => {
                if error.status == Some(401) {
                    return Err(error);
                }
                failed += 1;
                rows.push(json!({
                    "key": task.key,
                    "ok": false,
                    "error": error.message,
                }));
            }
        }
    }

    if !settled.is_empty() {
        // 落库失败不影响本次结果：上游已经结清，界面不该再显示「待领取」
        // 引着用户去点一颗注定幂等的按钮。
        let _ = save_grants(&settled);
    }

    // 响应里的任务行 = 台账旧状态 ∪ 本次增量
    let mut merged = ledger_before;
    if !merged.get("grants").is_some_and(Value::is_object) {
        merged["grants"] = json!({});
    }
    if let Some(grants) = merged.get_mut("grants").and_then(Value::as_object_mut) {
        for (key, at) in settled.iter() {
            grants.insert(key.clone(), Value::from(*at));
        }
    }
    let rows_all = task_rows(&merged);
    let unclaimed = unclaimed_of(&rows_all);
    let settled_at = if unclaimed == 0 {
        settled_at_of(&merged)
    } else {
        0
    };

    Ok(json!({
        "results": rows,
        "claimed": claimed,
        "failed": failed,
        "claimedPoints": claimed_points,
        "tasks": rows_all,
        "earned": earned_of(&merged),
        "total": TOTAL_POINTS,
        "unclaimed": unclaimed,
        "settled": unclaimed == 0,
        "settledAt": if unclaimed == 0 { json!(settled_at) } else { Value::Null },
    }))
}
