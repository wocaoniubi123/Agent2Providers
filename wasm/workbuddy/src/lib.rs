//! WorkBuddy 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/workbuddy/`（native，39 个文件）。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! | native trait 方法 | wasm method |
//! |---|---|
//! | `meta()` | `init` / `provider.info`（`metadata.json`） |
//! | `build_chat()` | `chat`（**死路径**：网关对任何 wasm 包直接 501） |
//! | （会话式） | `conversation`（**真正生效的对话通道**，见 `chat.rs`） |
//! | `ensure_token()` / `refresh_token()` / `token_expiring()` | `token.ensure` / `token.refresh` / `token.expiring` |
//! | `models()` / `refresh_models()` | `models.list` / `models.refresh` |
//! | `usage()` / `checkin()` | `usage.query` / `checkin.claim` |
//! | `normalize_account()` / `account_view()` / `account_identity()` | `account.normalize` / `account.view` / `account.identity` |
//! | `login_start()` / `login_poll()` / `login_cancel()` | `login.start` / `login.poll` / `login.cancel` |
//! | `admin_action()` | `admin.action`（成长任务 / 猫猫旅行 / 开学季 / 计费运营 / 原生搜索） |
//! | `classify()` / `error_policy()` / `retry_advice()` / `retry_decision()` | 同名 |
//! | `is_error_response()` | `is_error_response` |
//! | `reasoning_patch()` | `reasoning_patch` |
//!
//! ── 只做国内版 ──────────────────────────────────────────────
//! native 目录导出 `workbuddy` 与 `workbuddy-intl` 两个 id；本次只迁国内版，国际版
//! 由 `wasm/workbuddy-intl/` 那个包负责。网关 `provenance.rs` 硬性要求 wasm 包的
//! `providers.len() == 1`，所以 `pack.json` 里只有一条。
//!
//! ── 有意报 `unsupported` 的方法 ─────────────────────────────
//! `login.callback`（本家登录是**轮询型**，授权页在上游域名终结、回调永不回本机）、
//! `claim` / `claim.status`（本家没有领取类活动，`capabilities.claims = false`）、
//! `images.generate` / `images.edit`（wasm 侧那对方法的契约在本仓库里没有可核对的
//! 实现，`images.capabilities` 如实申报 false），以及本表之外的一切方法。
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
mod growth;
mod httpio;
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

/// 与 native 侧 `meta()` 逐字段一致。
///
/// 包含 `account_features.invite_code` 这类自用扩展位 —— 网关用本 fork 的
/// `agent2api-provider-protocol` 反序列化，位在就生效，不需要额外接线。
///
/// **两处与 native 有意不同**（网关装包时逐条硬校验，见 `metadata.json` 里
/// 的同名注释与 `wasm.json` 的 `requires`）：
///   - `capabilities.anonymous_default_session` / `env_credentials` 必须是
///     `false` —— wasm 沙箱里既没有默认登录态也没有环境变量，网关明文拒绝
///     「Wasm 不允许隐式本机凭证，请使用显式账号或已授权的原生辅助」；
///   - `capabilities.model_refresh = true` ⇒ `wasm.json` 的 `requires` 必须含
///     `catalog.v1`（否则装包报「Wasm 提供商能力缺少授权声明」）。
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
        // 只是为了方法表完整 —— native 里同一个实现挂两个名字。真正生效的是
        // `conversation`：插件自己发上游请求，再用 stream_head / stream_bytes 把
        // SSE 回给宿主。
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
        "checkin.claim" => usage::checkin(),

        // ── 账号 ──────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 登录（轮询型）─────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作（成长任务 / 计费运营 / 原生搜索）───────────
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
        // 本包不申报图片能力：`images.generate` / `images.edit` 的请求与回包契约
        // 在本仓库里没有可核对的实现，硬写一个不核实的结果比不提供更坏。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}
