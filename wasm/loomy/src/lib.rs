//! Loomy 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/loomy/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//! ```text
//!   crypto.rs        签名链的自实现原语（HMAC-SHA1 / MD5 / base64）
//!   sign.rs          CAccount 请求签名（9 段待签串）
//!   endpoints.rs     上游地址与客户端内置签名对（设置可覆盖）
//!   ids.rs           随机 id（nonce / traceid / 追踪头）
//!   client.rs        两种出站请求 + 业务码口径
//!   credentials.rs   凭证解析 / 脱敏 / normalize / 账号视图
//!   login.rs         手机验证码登录（短信面板 + 协议通用形态）
//!   models.rs        模型目录（解析、能力位、刷新）
//!   headers.rs       推理请求的追踪头
//!   anthropic.rs     Anthropic Messages ↔ Chat 的双向转换（本家非标准协议那段）
//!   chat.rs          对话转发（conversation 流式 / chat 计划）
//!   errors.rs        上游错误分类（四档）
//!   reasoning.rs     思考档位的通用口径
//!   checkin.rs       每日首次登录刷新赠送积分
//!   balance.rs       双账户余额 + 邀请码 / 兑换码（本 fork 自用能力）
//!   onboarding.rs    新手任务（状态查询 / 一键领取）
//! ```
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`（`metadata.json` 承担）；`build_chat()` → `chat` /
//! `conversation`；`ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`models()` → `models.list`；`refresh_models()` →
//! `models.refresh`；`usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `claim()` / `claim_status()` → `claim` / `claim.status`；`normalize_account()` →
//! `account.normalize`；`account_view()` → `account.view`；`account_identity()` →
//! `account.identity`；`classify()` → `classify`；`is_error_response()` →
//! `is_error_response`；`reasoning_patch()` → `reasoning_patch`；`login_*` →
//! `login.start` / `login.callback` / `login.cancel`；`admin_action()` → `admin.action`。
//!
//! ── 本家没有的东西（不是漏实现）─────────────────────────────
//!   - `token.refresh`：上游没有 refresh / renew 接口，session 14 天到期只能重登；
//!   - `login.poll`：短信登录是两步同步调用，没有可轮询的状态；
//!   - `retry_advice` / `cooldown_models`：native 侧也未实现（恒空）；
//!   - 图片生成 / 编辑：native 支持，但 Wasm 侧的图片通道需要额外的
//!     `images.v1` 契约与资源上传，本插件不申报该能力（见 `images.capabilities`）。

mod anthropic;
mod balance;
mod checkin;
mod chat;
mod client;
mod credentials;
mod crypto;
mod endpoints;
mod errors;
mod headers;
mod ids;
mod login;
mod models;
mod onboarding;
mod reasoning;
mod sign;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致。
///
/// 包含 `account_features.invite_code` 这类自用扩展位 —— 网关用本 fork 的
/// `agent2api-provider-protocol` 反序列化，位在就生效，不需要额外接线。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

/// 当前时间的**秒**级戳（chat chunk 的 `created` 字段要秒）。
fn now_seconds() -> i64 {
    sdk::now() / 1000
}

/// 思考档位 → 上游字段（native `Provider::reasoning_patch` 的移植）。
///
/// 通用 6 档折成三档：`minimal|low → low`、`medium|high → medium`、
/// `xhigh|max → high`。客户端显式指定时让位；`off` / `none` 不注入；
/// 表外自定义等级不注入（上游对未知档位要么忽略要么 400）。
fn reasoning_patch(params: &Value) -> Result<Value> {
    let level = params["level"].as_str().unwrap_or("");
    let body = &params["body"];
    if reasoning::is_thinking_off(level) {
        return Ok(json!({
            "action": "skip",
            "reason": "Loomy 没有「关闭思考」的可靠表达，跳过注入",
        }));
    }
    if reasoning::read_client_level(body).is_some() {
        return Ok(json!({
            "action": "skip",
            "reason": "客户端请求体里已指定思考等级，绑定让位",
        }));
    }
    let Some(rank) = reasoning::effort_rank(level) else {
        return Ok(json!({
            "action": "skip",
            "reason": "该等级不在通用档位表内，Loomy 不注入未知档位",
        }));
    };
    let effort = match rank {
        0 | 1 => "low",
        2 | 3 => "medium",
        _ => "high",
    };
    Ok(json!({
        "action": "set",
        "field": "reasoning_effort",
        "value": effort,
    }))
}

/// 管理动作（`admin.action`）：登录方式声明、短信两步登录、邀请码 / 兑换码。
///
/// ── 为什么短信登录走 `admin.action` 而不是 `login.start` ──────
/// 主程序的短信面板按 `login_settings.sms` 的声明分两步调
/// `login.sms.send` / `login.sms.verify`，它只接受 `admin.action` 这条通道
/// （`call_wasm_sms`）。`login.start` / `login.callback` 那套是协议通用形态，
/// 两条路共用同一份发码/登录实现（见 `login.rs`）。
fn admin_action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    let payload = &params["payload"];
    match action {
        "auth.methods" => Ok(login::methods(
            payload["locale"].as_str().unwrap_or("zh-CN"),
        )),
        "login.sms.send" => login::sms_send(payload),
        "login.sms.verify" => login::sms_verify(payload),
        "invite.status" => balance::invite_status(),
        "invite.bind" => balance::bind_invite(
            payload["code"]
                .as_str()
                .or_else(|| payload["inviteCode"].as_str())
                .unwrap_or(""),
        ),
        "invite.redeem" => balance::redeem_code(payload["code"].as_str().unwrap_or("")),
        // 本家没有限额来源上报（余额是积分不是窗口额度）
        "quota.sources" => Ok(json!([])),
        other => Err(Error::http(
            400,
            format!(
                "Loomy 不认识管理动作「{other}」（可用：auth.methods / login.sms.send / \
                 login.sms.verify / invite.status / invite.bind / invite.redeem）"
            ),
        )),
    }
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),
        "admin.action" => admin_action(&params),
        "account.normalize" => credentials::normalize(&params),
        "account.view" => credentials::account_view(&params["secret"]),
        "account.identity" => Ok(json!(credentials::identity_of(&params["secret"]))),
        // 本家**没有续期**，也**不预测失效**：只回答「记录里有没有 session」。
        // 服务端拒了（020002 / 100002 / 401）才是真的失效，那时由 `classify`
        // 归成 token_expired 并给账号落 needsRelogin。
        "token.ensure" => Ok(json!(credentials::snapshot()?.session)),
        "token.refresh" => Err(Error::http(
            401,
            "Loomy 没有续期接口（session 14 天到期只能重新短信登录）",
        )),
        // 恒 false：本家没有可预测的到期时刻（上游不返回，估算值会误杀仍可用的账号）
        "token.expiring" => Ok(json!(false)),
        "models.list" => Ok(models::cached()),
        "models.refresh" => {
            // 「一个账号都没有」不是失败 —— 那是「用户还没添加账号」的正常状态，
            // 返回 `{refreshed:false}`（脚本 / CI 不该看到一个红色失败）。
            // native 侧在此还会打一条 info 日志，Wasm 没有日志通道，只保留语义。
            if params["account"].as_str().unwrap_or("").is_empty() {
                Ok(json!({ "refreshed": false, "count": 0 }))
            } else {
                Ok(models::refresh(params["force"].as_bool().unwrap_or(false)))
            }
        }
        "usage.query" => balance::query_usage(),
        "checkin.claim" => checkin::claim(),
        "claim" => onboarding::claim(params["claim"].as_str().unwrap_or("")),
        "claim.status" => onboarding::status(params["refresh"].as_bool().unwrap_or(false)),
        "chat" => chat::plan(&params),
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        "login.start" => login::start(&params),
        // 短信登录没有可轮询的状态：主程序回的是「等用户填码」那条路
        "login.poll" => Err(Error::unsupported()),
        "login.cancel" => Ok(Value::Null),
        "login.callback" => login::callback(&params),
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["headers"],
        ))),
        // 本家没有「遇到特定错误就停止重试」的场景（与 native 侧默认实现一致）
        "error.policy" => Ok(json!({ "stop": false })),
        "retry_advice" => Ok(Value::Null),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => reasoning_patch(&params),
        // native 侧的图片通道没有迁过来：Wasm 的图片契约要额外的 `images.v1`
        // 与资源上传流程，本插件不申报该能力。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),
        _ => Err(Error::unsupported()),
    }
}
