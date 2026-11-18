//! WorkBuddy **国际版**的管理动作（协议方法 `admin.action` 的实现）。
//!
//! ── 国际版只有三条面 ────────────────────────────────────────
//! ```text
//!   activity.run        每日活跃（探测 + 条件领取 + 两发保活）→ native keepalive.rs
//!   billing.*           计费 / 运营（签到状态、banner、大使；领取与一次性奖励被拒）
//!   web-search.*        原生搜索（两家共用，打的是账号端点 /agenttool/v1/search）
//! ```
//! 成长任务树（`growth.*`）**国际版没有**：它只服务国内版，`metadata.admin_panels`
//! 因此是 `["daily_keepalive"]` 而不是 `["growth_tasks"]`。native 的
//! `admin::dispatch` 里那句「WorkBuddy 国际版只有「activity.run」这一个管理动作」
//! 就是这条边界的原文。
//!
//! ── 为什么还保留 growth 模块 ────────────────────────────────
//! native 是**同一个目录**服务两个地区：`growth/*` 的实现只有一份，国际版实例在
//! 分派处就把它挡住了。本包沿用这个结构（`growth/` 整块保留、不再有调用方），
//! 好处是两包之间仍能逐行对照 —— 代价是那块代码在本包里是「不生效的实现」，
//! 已在 `lib.rs` 的 `mod growth` 上标注 `#[allow(dead_code)]` 并写明理由。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::billing::ops;
use crate::keepalive;
use crate::outbound;
use crate::search;

/// native 的定义（两家共用一张表）：本包只放行其中的 `activity.run`、`billing.*`
/// 与 `web-search.*`，其余（成长任务）在国际版没有对应上游能力。
#[allow(dead_code)]
pub const ACTIONS: &[&str] = &[
    "growth.status",
    "growth.task",
    "growth.school",
    "growth.travel",
    "growth.travel.batch",
    "growth.streak",
    "growth.streak.batch",
    "growth.daily",
    "activity.run",
    "billing.checkin-status",
    "billing.checkin-claim",
    "billing.reward",
    "billing.banner",
    "billing.ambassador",
    search::CAPABILITIES,
    search::SEARCH,
];

/// 本包**真正可用**的动作（错误文案里列它，而不是上面那张全表）。
///
/// `auth.methods` 排在第一位：它不是业务动作，而是**登录方式申报**，网关
/// 打开添加账号面板时就会问（`api/session.rs:263-280` 对 wasm 恒走动态契约）。
pub const INTL_ACTIONS: &[&str] = &[
    "auth.methods",
    "activity.run",
    "billing.checkin-status",
    "billing.checkin-claim",
    "billing.reward",
    "billing.banner",
    "billing.ambassador",
    search::CAPABILITIES,
    search::SEARCH,
];

/// 分发一次管理动作。
///
/// `payload` 是厂商自定义参数（网关不理解内容）：
///   · `activity.run`：`{mode: "full"|"claim"|"keepalive", models: [..]}`
///   · `billing.reward`：`{kind: "gift"|"compensation"}`
pub fn dispatch(action: &str, payload: &Value) -> Result<Value> {
    // ── 登录方式申报：不碰账号，最先分流 ────────────────────────
    // 国内版那里是「白名单全表 + 分流」，本包没有白名单（兜底是 400），
    // 所以分流必须加在最前面：下面每一条分支都要先读账号，而登录方式是在
    // 还没有任何账号时被问的
    if action == "auth.methods" {
        return Ok(crate::login::methods());
    }
    // ── 原生搜索：不碰账号体系之外的状态，先分流 ────────────────
    if matches!(action, search::CAPABILITIES | search::SEARCH) {
        return search::dispatch(action, payload);
    }
    // ── 计费 / 运营动作：与活跃任务无关，先分流 ────────────────
    // 国际版可用的是签到**状态**、banner 与大使；签到领取与一次性奖励在
    // `billing::ops` 里按地区拒绝（native 同款文案）。
    if action.starts_with("billing.") {
        return billing_action(action, payload);
    }
    // ── 成长侧只剩一条：每日活跃 ──────────────────────────────
    if action == "activity.run" {
        let secret = crate::account::secret()?;
        if !secret.is_object() {
            return Err(Error::http(401, "该账号没有可用凭证"));
        }
        let mode = keepalive::Mode::parse(payload.get("mode").and_then(Value::as_str));
        let models: Vec<String> = payload
            .get("models")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        return keepalive::run(&secret, mode, &models);
    }
    // 成长任务树在国际版没有上游能力：与 native 同一句文案
    Err(Error::http(
        400,
        format!(
            "WorkBuddy 国际版只有「activity.run」这一个管理动作（收到「{action}」）"
        ),
    )
    .with_code("unsupported"))
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

/// 本包可用动作的清单（网关 `/api/providers` 的排障页用得上）。
#[allow(dead_code)]
pub fn available_actions() -> Value {
    json!(INTL_ACTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intl_actions_are_a_subset_of_the_native_table() {
        for action in INTL_ACTIONS {
            // `auth.methods` 是 wasm 侧新增的登录方式申报（native 走静态表单），
            // native 的动作表里没有它
            if *action == "auth.methods" {
                continue;
            }
            assert!(ACTIONS.contains(action), "{action} 不在 native 的表里");
        }
        assert!(!ACTIONS.contains(&"auth.methods"));
        // 成长任务在国际版不可用（只在 native 表里）
        assert!(!INTL_ACTIONS.contains(&"growth.status"));
        assert!(ACTIONS.contains(&"growth.status"));
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
    fn growth_actions_are_rejected_with_the_native_message() {
        let error = dispatch("growth.status", &json!({})).err();
        let error = match error {
            Some(error) => error,
            None => Error::new("未按预期失败"),
        };
        assert_eq!(error.status, Some(400));
        assert!(
            error.message.contains("只有「activity.run」这一个管理动作"),
            "{}",
            error.message
        );
    }

    #[test]
    fn search_capabilities_needs_no_account() {
        let value = dispatch("web-search.capabilities", &json!({})).unwrap_or(Value::Null);
        assert_eq!(value["search"], json!(true));
    }
}
