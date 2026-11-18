//! WorkBuddy 小程序**开学季活动域**（学校开放日任务 + 幸运转盘）。
//!
//! ── 这是什么（从参考项目 school_open_day_2026.py 逐条移植）──
//! 上游小程序里的开学季活动：一组任务（与 AI 对话 3 次、用开学季专家、分享活动、
//! 桌面端对话 1 次）与一个抽奖转盘。任务完成后领取「抽奖机会」，转盘抽积分/实物
//! 券。任务判据是**小程序指纹事件**（`source=mini_program` +
//! `activityId=school_open_day_2026`），与 growth 成长任务是两套任务空间
//! （端点也不同：`/portal/activity/school/*`）。
//!
//! ── 端点（全部在 www.codebuddy.cn）──────────────────────────
//! ```text
//! GET  /portal/activity/school/tasks               任务列表 + in_period
//! POST /portal/activity/school/tasks/{code}/viewed 「接任务」（pending→in_progress）
//! POST /portal/activity/school/tasks/share-complete 分享完成（channel=wechat）
//! POST /portal/activity/school/tasks/{code}/claim  领奖（发抽奖机会）
//! GET  /portal/activity/school/config              转盘盘面 + 抽奖余额
//! POST /portal/activity/school/wheel/draw          抽一次（draw_uuid 一次性）
//! ```
//!
//! ── 与参考项目的差异（有意为之）───────────────────────────
//! · 参考脚本是命令行工具（默认 dry-run、--yes 才写）；本仓是界面动作，用户点击
//!   即执行 —— 因此这里没有 dry-run 开关，但**抽奖有余额上限**（抽到余额归零即停，
//!   40900「no chance」为正常边界）。
//! · 学生认证（task_student_verify）是人工环节，一律跳过（本仓同款）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use crate::util;

use super::{growth_request, GrowthAccount, GrowthCall, MP_UA};

/// 活动端点基址。
pub const CLOUD_AGENT: &str = "https://www.codebuddy.cn";
/// 活动 code（事件 activityId 字段值）。
pub const ACTIVITY_ID: &str = "school_open_day_2026";

/// school 域请求（带小程序 UA）。
fn school_request(
    account: &GrowthAccount,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::result::Result<GrowthCall, String> {
    let headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), MP_UA.to_string()),
    ];
    growth_request(account, method, &format!("{CLOUD_AGENT}{path}"), body, &headers)
}

/// 任务列表（GET /portal/activity/school/tasks）→ (tasks, in_period)。
pub fn fetch_tasks(account: &GrowthAccount) -> std::result::Result<(Vec<Value>, bool), String> {
    let call = school_request(account, "GET", "/portal/activity/school/tasks", None)?;
    if !call.ok() {
        return Err(format!(
            "开学季任务列表拉取失败（HTTP {} code={:?} {}）",
            call.status,
            call.code(),
            call.msg()
        ));
    }
    let data = call.data();
    let tasks = data
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let in_period = data
        .get("in_period")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok((tasks, in_period))
}

/// 「接任务」（POST /tasks/{code}/viewed，pending → in_progress）。
fn post_viewed(account: &GrowthAccount, code: &str) -> std::result::Result<(), String> {
    let call = school_request(
        account,
        "POST",
        &format!("/portal/activity/school/tasks/{code}/viewed"),
        None,
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!("viewed HTTP {} code={:?}", call.status, call.code()))
    }
}

/// 分享完成（POST /tasks/share-complete，body `{channel:"wechat"}`）。
fn post_share_complete(account: &GrowthAccount) -> std::result::Result<(), String> {
    let call = school_request(
        account,
        "POST",
        "/portal/activity/school/tasks/share-complete",
        Some(&json!({ "channel": "wechat" })),
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!(
            "share-complete HTTP {} code={:?}",
            call.status,
            call.code()
        ))
    }
}

/// 领奖（POST /tasks/{code}/claim，发抽奖机会）。
fn post_claim(account: &GrowthAccount, code: &str) -> std::result::Result<(), String> {
    let call = school_request(
        account,
        "POST",
        &format!("/portal/activity/school/tasks/{code}/claim"),
        None,
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!(
            "claim HTTP {} code={:?} {}",
            call.status,
            call.code(),
            call.msg()
        ))
    }
}

// ─── 幸运转盘 ───────────────────────────────────────────────

/// 转盘配置 + 抽奖余额（GET /config → (config, chance)）。
pub fn fetch_lottery(account: &GrowthAccount) -> std::result::Result<(Value, Value), String> {
    let call = school_request(account, "GET", "/portal/activity/school/config", None)?;
    if !call.ok() {
        return Err(format!(
            "转盘配置拉取失败（HTTP {} code={:?}）",
            call.status,
            call.code()
        ));
    }
    let data = call.data();
    let chance = data.get("chance").cloned().unwrap_or(Value::Null);
    Ok((data, chance))
}

/// 抽一次转盘（POST /wheel/draw，body `{draw_uuid}` 一次性随机）。
///
/// 返回 (ok, prize_code, credit, chance_balance, message)：
///   余额 0 时上游返回 HTTP 409 code=40900「no chance」—— 正常边界，不算失败。
fn post_draw(
    account: &GrowthAccount,
    draw_uuid: &str,
) -> std::result::Result<(bool, String, i64, i64, String), String> {
    let call = school_request(
        account,
        "POST",
        "/portal/activity/school/wheel/draw",
        Some(&json!({ "draw_uuid": draw_uuid })),
    )?;
    if call.status == 409 || call.code() == Some(40900) {
        return Ok((false, String::new(), 0, 0, "抽奖次数已用尽".to_string()));
    }
    if !call.ok() {
        return Err(format!(
            "抽奖失败（HTTP {} code={:?} {}）",
            call.status,
            call.code(),
            call.msg()
        ));
    }
    let data = call.data();
    let prize_code = data
        .get("prize_code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let credit = data.get("credit_amount").and_then(Value::as_i64).unwrap_or(0);
    let balance = data
        .get("chance_balance")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Ok((true, prize_code, credit, balance, String::new()))
}

/// 奖品码 → 展示文案（未知码原样返回，不编造内容）。
pub fn prize_label(prize_code: &str, credit: i64) -> String {
    let label = match prize_code {
        "school_credit_6" => return format!("6 积分（+{credit} Credit）"),
        "school_credit_66" => return format!("66 积分（+{credit} Credit）"),
        "school_voucher_luckin" => "瑞幸咖啡 15 元券",
        "school_voucher_kfc_ok" => "肯德基 OK 餐券",
        "school_voucher_kfc_ice" => "肯德基冰淇淋券",
        "school_voucher_kugou" => "酷狗会员月卡券",
        other => other,
    };
    label.to_string()
}

// ─── 任务判据事件（小程序指纹）───────────────────────────────

/// 小程序对话事件（chat_3_times 判据；**必带 activityId**，否则不关联任务）。
///
/// `conversation_id` 为 None 时自动生成（school_season 复用本构造器时同款）。
pub fn mini_chat_event(account: &GrowthAccount, conversation_id: Option<&str>) -> Value {
    let now = util::now_ms();
    let cid = conversation_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("wbmp-{now}"));
    json!({
        "eventCode": "chat_request_send", "timestamp": now, "reportDelay": 0,
        "source": "mini_program", "ideName": "wx_app_cloud", "ideType": "WorkBuddy_MP",
        "extName": "workbuddy-mp", "extVersion": "SaaS", "mode": "chat",
        "conversationId": cid, "requestId": cid,
        "inputLength": 12,
        "activityId": ACTIVITY_ID, "mentionContexts": [], "mentionContextCount": 0,
        "userId": account.uid,
    })
}

/// 开学季专家清单里的一个专家（BackToSchool 分类）。
const SCHOOL_EXPERT_CATEGORY: &str = "16-BackToSchool";
const SCHOOL_EXPERT_FALLBACK: &[(&str, &str, &str)] = &[
    ("ex_jB0dyFIQJEWa", "论小舟", "论文写作导师"),
    ("ex_lQjkerakvIex", "英语学习教练", "大学英语学习教练"),
];

/// 拉一个 BackToSchool 分类的开学季专家（失败回落已知专家）。
fn fetch_school_expert(account: &GrowthAccount) -> (String, String, String) {
    let body = json!({
        "edition_mode": "all,domestic", "page": 1, "page_size": 20,
        "sort_by": "use_count", "sort_order": "desc",
        "categories": [SCHOOL_EXPERT_CATEGORY], "expert_type": "agent",
    });
    if let Ok(call) = school_request(
        account,
        "POST",
        "/v2/operation-platform/market/expert/list",
        Some(&body),
    ) {
        if call.ok() {
            if let Some(expert) = call
                .data()
                .get("experts")
                .and_then(Value::as_array)
                .and_then(|experts| experts.first())
            {
                if let Some(id) = expert.get("expert_id").and_then(Value::as_str) {
                    let name = expert
                        .get("display_name_zh")
                        .and_then(|value| value.get("zh").and_then(Value::as_str).or_else(|| value.as_str()))
                        .unwrap_or(id)
                        .to_string();
                    let profession = expert
                        .get("profession_zh")
                        .and_then(|value| value.get("zh").and_then(Value::as_str).or_else(|| value.as_str()))
                        .unwrap_or("")
                        .to_string();
                    return (id.to_string(), name, profession);
                }
            }
        }
    }
    let (id, name, title) = SCHOOL_EXPERT_FALLBACK[0];
    (id.to_string(), name.to_string(), title.to_string())
}

/// 专家使用事件（expert_use 判据；必带 activityId + conversationId）。
fn expert_use_event(
    account: &GrowthAccount,
    expert_id: &str,
    expert_name: &str,
    conversation_id: &str,
) -> Value {
    let now = util::now_ms();
    json!({
        "eventCode": "expert_actual_use", "timestamp": now, "reportDelay": 0,
        "source": "mini_program", "ideName": "wx_app_cloud", "ideType": "WorkBuddy_MP",
        "extName": "workbuddy-mp", "extVersion": "SaaS",
        "machineId": account.derive_id("machine"), "os": "android", "osVersion": "14",
        "arch": "arm64", "timezone": "Asia/Shanghai",
        "userId": account.uid, "userNickname": account.nick,
        "id": expert_id, "name": expert_id, "expertTitle": expert_name,
        "type": "send_message", "characterCount": 12, "expertType": "agent",
        "conversationId": conversation_id,
        "activityId": ACTIVITY_ID,
    })
}

/// 事件上报（POST {host}/v2/report；school 与 mp 任务共用）。
pub fn report_events(account: &GrowthAccount, events: &[Value]) -> std::result::Result<(), String> {
    let headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), MP_UA.to_string()),
    ];
    let call = growth_request(
        account,
        "POST",
        &format!("{CLOUD_AGENT}/v2/report"),
        Some(&Value::Array(events.to_vec())),
        &headers,
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!(
            "school 事件上报 HTTP {} code={:?}",
            call.status,
            call.code()
        ))
    }
}

/// 一个 school 任务的完成定义（参考项目 KNOWN_TASKS 的对等物）。
struct SchoolTaskSpec {
    /// report / share / manual
    mode: &'static str,
    /// report 模式下的判据种类：mini_chat / expert / desktop_seq
    report_kind: &'static str,
    /// 界面提示
    note: &'static str,
}

fn school_task_spec(code: &str) -> Option<SchoolTaskSpec> {
    let spec = match code {
        "task_student_verify" => SchoolTaskSpec {
            mode: "manual",
            report_kind: "",
            note: "微信学生认证（人工环节，不碰）",
        },
        "share_invite" => SchoolTaskSpec {
            mode: "share",
            report_kind: "",
            note: "分享活动给好友（share-complete 点亮）",
        },
        "chat_3_times" => SchoolTaskSpec {
            mode: "report",
            report_kind: "mini_chat",
            note: "与 AI 对话 3 次（小程序对话事件点亮）",
        },
        "desktop_chat_1_time" => SchoolTaskSpec {
            mode: "report",
            report_kind: "desktop_seq",
            note: "桌面端对话 1 次（桌面 6 连事件点亮）",
        },
        "expert_use" => SchoolTaskSpec {
            mode: "report",
            report_kind: "expert",
            note: "使用开学季专家对话",
        },
        _ => return None,
    };
    Some(spec)
}

/// 单个 school 任务处理结果行。
pub struct SchoolReport {
    pub code: String,
    /// done / already / skipped / failed
    pub outcome: &'static str,
    pub message: String,
}

/// 处理单个 school 任务（viewed 激活 → 判据触发 → 回读 → claim）。
pub fn process_task(account: &GrowthAccount, code: &str, task: &Value) -> SchoolReport {
    let status = task
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let cur = task.get("progress").and_then(Value::as_i64).unwrap_or(0);
    let target = task
        .get("target_count")
        .and_then(Value::as_i64)
        .unwrap_or(1);

    if status == "completed" || status == "claimed" {
        return SchoolReport {
            code: code.to_string(),
            outcome: "already",
            message: format!("已完成/已领（{cur}/{target}）"),
        };
    }
    let Some(spec) = school_task_spec(code) else {
        return SchoolReport {
            code: code.to_string(),
            outcome: "skipped",
            message: "未映射任务（人工/未知），跳过".to_string(),
        };
    };
    if spec.mode == "manual" {
        return SchoolReport {
            code: code.to_string(),
            outcome: "skipped",
            message: spec.note.to_string(),
        };
    }

    // 1) pending → viewed 激活
    if status == "pending" {
        if let Err(error) = post_viewed(account, code) {
            return SchoolReport {
                code: code.to_string(),
                outcome: "failed",
                message: format!("viewed 激活失败：{error}"),
            };
        }
        let _ = sdk::sleep(super::GROWTH_WRITE_GAP_MS);
    }

    // 2) 判据触发（share 一次；desktop_seq 一次 6 连；其余按 target-进度循环）
    let rounds = match spec.report_kind {
        "share" => 1,
        "desktop_seq" => 1,
        _ => (target - cur).max(1) as usize,
    };
    let mut current = cur;
    for _ in 0..rounds {
        let outcome = match spec.mode {
            "share" => post_share_complete(account),
            _ => {
                let events = match spec.report_kind {
                    "mini_chat" => vec![mini_chat_event(account, None)],
                    "expert" => {
                        let (expert_id, expert_name, _) = fetch_school_expert(account);
                        vec![expert_use_event(
                            account,
                            &expert_id,
                            &expert_name,
                            &format!("wbexp-{}", util::now_ms()),
                        )]
                    }
                    "desktop_seq" => desktop_seq_with_activity(account),
                    _ => Vec::new(),
                };
                if events.is_empty() {
                    Ok(())
                } else {
                    report_events(account, &events)
                }
            }
        };
        if let Err(error) = outcome {
            return SchoolReport {
                code: code.to_string(),
                outcome: "failed",
                message: format!("判据触发失败：{error}"),
            };
        }
        let _ = sdk::sleep(super::GROWTH_WRITE_GAP_MS);
        // 每轮回读，到目标即止
        if let Ok((tasks, _)) = fetch_tasks(account) {
            if let Some(after) = super::find_task(&tasks, code) {
                let after_status = after
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();
                let after_progress = after.get("progress").and_then(Value::as_i64).unwrap_or(0);
                if after_progress > current {
                    current = after_progress;
                }
                if after_status == "completed"
                    || after_status == "claimed"
                    || after_progress >= target
                {
                    break;
                }
            }
        }
    }

    // 3) 回读 + claim
    let (after_status, after_progress) = match fetch_tasks(account) {
        Ok((tasks, _)) => super::find_task(&tasks, code)
            .map(|task| {
                (
                    task.get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_lowercase(),
                    task.get("progress").and_then(Value::as_i64).unwrap_or(0),
                )
            })
            .unwrap_or((String::new(), 0)),
        Err(_) => (String::new(), 0),
    };
    if after_status == "claimed" {
        return SchoolReport {
            code: code.to_string(),
            outcome: "already",
            message: "本轮已领取".to_string(),
        };
    }
    if after_status == "completed" || after_progress >= target {
        return match post_claim(account, code) {
            Ok(()) => SchoolReport {
                code: code.to_string(),
                outcome: "done",
                message: format!("已点亮并领奖（{after_progress}/{target}）"),
            },
            Err(error) => SchoolReport {
                code: code.to_string(),
                outcome: "failed",
                message: format!("已点亮但领奖失败：{error}（可稍后补领）"),
            },
        };
    }
    SchoolReport {
        code: code.to_string(),
        outcome: "skipped",
        message: format!("判据上报未达 target（{after_progress}/{target}）"),
    }
}

/// 桌面 6 连 + activityId（desktop_chat_1_time 判据）。
///
/// 参考项目实测：桌面上报走 **copilot 域**（发 codebuddy.cn 不点亮桌面任务），
/// 头带 `X-Product: SaaS` 与桌面 UA。
fn desktop_seq_with_activity(account: &GrowthAccount) -> Vec<Value> {
    let now = util::now_ms();
    let conv = format!("wbdesk-{now}");
    // 复用 growth 的桌面链（同一构造函数，避免第二份形状）
    let seq = super::events::desktop_chat_sequence(account, &conv, &conv, &conv);
    seq.into_iter()
        .map(|mut event| {
            if let Some(object) = event.as_object_mut() {
                object.insert("activityId".to_string(), Value::from(ACTIVITY_ID));
            }
            event
        })
        .collect()
}

/// 执行开学季任务全流程（任务逐个处理 → 汇总）+ 可选抽奖。
///
/// `lottery` 为 true 时在任务后把抽奖余额抽空（护栏 20 次，防上游异常时空转）。
pub fn run_all(account: &GrowthAccount, only: &[String], lottery: bool) -> (Vec<SchoolReport>, Option<Value>) {
    let (tasks, in_period) = match fetch_tasks(account) {
        Ok(result) => result,
        Err(error) => {
            return (
                vec![SchoolReport {
                    code: "(tasks)".to_string(),
                    outcome: "failed",
                    message: error,
                }],
                None,
            )
        }
    };
    if !in_period {
        return (
            vec![SchoolReport {
                code: "(activity)".to_string(),
                outcome: "skipped",
                message: "活动非进行期（in_period=false）".to_string(),
            }],
            None,
        );
    }
    let mut reports = Vec::new();
    for task in &tasks {
        let code = task.get("task_code").and_then(Value::as_str).unwrap_or("");
        if code.is_empty() || (!only.is_empty() && !only.iter().any(|item| item == code)) {
            continue;
        }
        reports.push(process_task(account, code, task));
    }
    let lottery_result = if lottery {
        Some(run_lottery(account, 20))
    } else {
        None
    };
    (reports, lottery_result)
}

/// 生成一次性 draw_uuid（UUID v4 形态）。
///
/// native 用 getrandom；wasm 里没有熵源，改用时间戳 + 计数的哈希派生
/// （`util::uuid_v4`）—— 抽奖接口只要求「每轮一个新值」，不校验随机性。
fn random_uuid() -> String {
    util::uuid_v4()
}

/// 抽奖（抽到余额归零或到护栏上限为止）。返回结果 JSON（如实列出每个中奖物）。
pub fn run_lottery(account: &GrowthAccount, max_draws: usize) -> Value {
    let (config, chance) = match fetch_lottery(account) {
        Ok(result) => result,
        Err(error) => return json!({ "success": false, "message": error }),
    };
    if !config
        .get("in_period")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return json!({ "success": false, "message": "活动非进行期，抽奖跳过" });
    }
    let mut balance = chance.get("balance").and_then(Value::as_i64).unwrap_or(0);
    if balance <= 0 {
        return json!({
            "success": true,
            "drawn": 0,
            "credit": 0,
            "prizes": [],
            "message": "没有可用的抽奖次数",
        });
    }
    let mut prizes: Vec<Value> = Vec::new();
    let mut total_credit: i64 = 0;
    let mut previous = balance;
    let mut stall = 0;
    let mut draws = 0usize;
    while balance > 0 && draws < max_draws {
        let uuid = random_uuid();
        match post_draw(account, &uuid) {
            Ok((ok, prize_code, credit, new_balance, message)) => {
                if !ok {
                    // 40900「no chance」或异常：如实停
                    prizes.push(json!({ "label": message, "credit": 0 }));
                    balance = 0;
                    break;
                }
                let label = prize_label(&prize_code, credit);
                total_credit += credit;
                prizes.push(json!({ "code": prize_code, "label": label, "credit": credit }));
                balance = new_balance;
                draws += 1;
                if balance >= previous {
                    stall += 1;
                    if stall >= 3 {
                        // 余额未递减（服务端异常），防死循环
                        break;
                    }
                } else {
                    stall = 0;
                }
                previous = balance;
                let _ = sdk::sleep(super::GROWTH_WRITE_GAP_MS);
            }
            Err(error) => {
                return json!({
                    "success": false,
                    "drawn": draws,
                    "credit": total_credit,
                    "prizes": prizes,
                    "message": format!("抽奖中断：{error}"),
                });
            }
        }
    }
    json!({
        "success": true,
        "drawn": draws,
        "credit": total_credit,
        "remaining": balance,
        "prizes": prizes,
        "message": format!("共抽 {} 次，积分 +{}", draws, total_credit),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prize_labels_are_readable_and_unknown_codes_pass_through() {
        assert_eq!(prize_label("school_credit_6", 6), "6 积分（+6 Credit）");
        assert_eq!(prize_label("school_voucher_kugou", 0), "酷狗会员月卡券");
        assert_eq!(prize_label("mystery", 0), "mystery");
    }

    #[test]
    fn mini_chat_event_carries_the_activity_id() {
        let account = GrowthAccount {
            uid: "u-1".into(),
            nick: "n".into(),
            token: "t".into(),
            domain: String::new(),
            session: json!({}),
        };
        let event = mini_chat_event(&account, None);
        assert_eq!(event["activityId"], json!(ACTIVITY_ID));
        assert_eq!(event["source"], json!("mini_program"));
        // 显式会话 id 优先
        let event = mini_chat_event(&account, Some("c-9"));
        assert_eq!(event["conversationId"], json!("c-9"));
    }

    #[test]
    fn manual_tasks_are_skipped() {
        let account = GrowthAccount {
            uid: "u-1".into(),
            nick: "n".into(),
            token: "t".into(),
            domain: String::new(),
            session: json!({}),
        };
        let report = process_task(
            &account,
            "task_student_verify",
            &json!({ "status": "pending", "progress": 0, "target_count": 1 }),
        );
        assert_eq!(report.outcome, "skipped");
        // 未映射任务同样跳过
        let report = process_task(&account, "unknown_task", &json!({ "status": "pending" }));
        assert_eq!(report.outcome, "skipped");
    }
}
