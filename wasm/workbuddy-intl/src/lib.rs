//! WorkBuddy 国际版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/workbuddy/`（native，同一个目录用
//! `Region` 分叉服务两个地区）。本包是其中的 **`Region::Intl`** 那一半 ——
//! 国内版在 `wasm/workbuddy/`，两个包各自完整、互相不引用。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! | native trait 方法 | wasm method |
//! |---|---|
//! | `meta()` | `init` / `provider.info`（`metadata.json`） |
//! | `build_chat()` | `chat`（**死路径**：网关对任何 wasm 包直接 501） |
//! | （会话式） | `conversation`（**真正生效的对话通道**，见 `chat.rs`） |
//! | `ensure_token()` / `refresh_token()` / `token_expiring()` | `token.ensure` / `token.refresh` / `token.expiring` |
//! | `models()` / `refresh_models()` | `models.list` / `models.refresh` |
//! | `usage()` | `usage.query` |
//! | `checkin()` | `checkin.claim`（**国际版恒拒绝**：没有普通签到） |
//! | `normalize_account()` / `account_view()` / `account_identity()` | `account.normalize` / `account.view` / `account.identity` |
//! | `login_start()` / `login_poll()` / `login_cancel()` | `login.start` / `login.poll` / `login.cancel` |
//! | `admin_action()` | `admin.action`（`activity.run` + `billing.*` + 原生搜索） |
//! | `classify()` / `error_policy()` / `retry_advice()` / `retry_decision()` | 同名 |
//! | `is_error_response()` / `reasoning_patch()` | 同名 |
//!
//! ── 国际版与国内版的差别（全部落点）───────────────────────────
//! ```text
//!   region.rs         provider id workbuddy-intl / 版本 intl / 回落改为国际版
//!   endpoints.rs      站点 www.workbuddy.ai / platform workbuddy-ai /
//!                     客户端 5.8.4 + CLI 2.161.0 / 产品名 WorkBuddy AI
//!   contract.rs       官网 origin www.workbuddy.ai / 网络策略 Null
//!   outbound.rs       不带 X-Agent-Runtime；X-Domain 固定 www.workbuddy.ai
//!   auth.rs           404 文案指向国内版站点
//!   login.rs          资料接口 /v2/plugin/login/account?state= + 三个 X-No-* 头
//!   account.rs        本机登录态文件名 workbuddy-desktop-ai.info
//!   billing/ops.rs    签到状态走「活跃探测」（不带 /v2）；领取与一次性奖励拒绝
//!   keepalive.rs      **新增**：每日活跃（activity.run）—— 国内版没有这条链路
//!   admin.rs          **重写**：只放行 activity.run / billing.* / 搜索
//!   growth/*          整块保留但无调用方（国际版没有 CN 任务中心），见下
//! ```
//!
//! ── 为什么 growth 模块留着一份 ──────────────────────────────
//! native 用同一份代码服务两个地区（`growth` 的实现在分派处按 `Region` 挡住）。
//! 本包照搬这个结构：`mod growth` 上标了 `#[allow(dead_code)]` —— 那块代码在本包
//! 里**不生效**，留着是为了与 native 和国内版包逐行对照（事件形状与 `supports_growth`
//! 判据都还在这里，缺了反而更难对）。
//!
//! ── 有意报 `unsupported` 的方法 ─────────────────────────────
//! `login.callback`（轮询型登录，回调永不回本机）、`claim` / `claim.status`
//! （`capabilities.claims = false`）、`images.generate` / `images.edit`
//! （wasm 侧契约不可核实，`images.capabilities` 如实报 false），以及本表之外的
//! 一切方法。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本包零 unwrap/expect/panic。

mod account;
mod admin;
mod auth;
mod billing;
mod builtin;
mod catalog;
mod chat;
mod contract;
mod endpoints;
mod errors;
// 国际版没有 CN 成长任务中心（`metadata.admin_panels = ["daily_keepalive"]`）：
// 这块实现保留但无调用方，见模块头的说明。
#[allow(dead_code)]
mod growth;
mod httpio;
mod keepalive;
mod login;
mod normalize;
mod outbound;
mod quota_reset;
mod reasoning;
mod refresh_identity;
mod region;
mod search;
mod usage;
mod util;
mod web_session;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

pub use region::Region;

/// 与 native 侧 `meta()` 逐字段一致（`Region::Intl` 那一支）。
///
/// **两处与 native 有意不同**（网关装包时逐条硬校验）：
///   - `capabilities.anonymous_default_session` / `env_credentials` 必须是
///     `false` —— wasm 沙箱里既没有默认登录态也没有环境变量，网关明文拒绝
///     「Wasm 不允许隐式本机凭证，请使用显式账号或已授权的原生辅助」；
///   - `capabilities.model_refresh = true` ⇒ `wasm.json` 的 `requires` 必须含
///     `catalog.v1`（否则装包报「Wasm 提供商能力缺少授权声明」）。
///
/// 其余位（`checkin: false`、`admin_panels: ["daily_keepalive"]`、
/// `account_features.edition: false`）都是 native `Region::Intl` 的原值，未动。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 数据面 ────────────────────────────────────────────
        // `chat` 在 wasm 上恒 501（网关 `build_chat_request_async` 直接拒），保留它
        // 只是为了方法表完整。真正生效的是 `conversation`。
        "chat" | "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 凭证 ──────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring()?)),

        // ── 目录 ──────────────────────────────────────────────
        "models.list" => Ok(catalog::list()),
        "models.refresh" => catalog::refresh(params["force"].as_bool().unwrap_or(false)),

        // ── 余额 / 签到 ───────────────────────────────────────
        "usage.query" => usage::query(),
        // 国际版没有普通签到（`capabilities.checkin = false`，网关不会调到这里）；
        // 它的「每日活跃」在 `admin.action` 的 `activity.run` 里。
        "checkin.claim" => usage::checkin(),

        // ── 账号 ──────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 登录（轮询型）─────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作（每日活跃 / 计费运营 / 原生搜索）───────────
        "admin.action" => {
            let action = params["action"].as_str().unwrap_or("");
            if action.is_empty() {
                return Err(Error::http(400, "缺少管理动作名（action）"));
            }
            admin::dispatch(action, &params["payload"])
        }

        // ── 分类与策略 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["headers"],
        ))),
        "error.policy" => Ok(errors::policy(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "retry_advice" => Ok(errors::retry_advice(
            &params["body"],
            params["attempt"].as_u64().unwrap_or(0) as usize,
            params["budget"].as_u64().unwrap_or(0) as usize,
        )),
        "retry.decision" => Ok(errors::retry(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
            params["attempt"].as_u64().unwrap_or(0) as usize,
            params["budget"].as_u64().unwrap_or(0) as usize,
        )),
        // native 没有覆写 `cooldown_models`（默认只冷却请求的那个模型）
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => {
            let model = catalog::model(params["model"].as_str().unwrap_or(""));
            Ok(reasoning::patch(
                params["level"].as_str().unwrap_or(""),
                model.as_ref(),
                &params["body"],
            ))
        }

        // ── 图片 ──────────────────────────────────────────────
        // 本包不申报图片能力（`images.generate` / `images.edit` 的契约在本仓库里
        // 没有可核对的实现）。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}
