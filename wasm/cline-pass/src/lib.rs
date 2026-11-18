//! Cline **订阅池**（`cline-pass`）的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/cline/`（native，`ClineProvider::PASS`）。
//!
//! ── 与 `cline-free` 是同一份实现 ───────────────────────────
//! 两个池在上游是**同一个账号上的两个额度池**，差别只在三处（provider id、
//! 模型 id 前缀、免费池没有默认限流器）。所以本包不复制源码：下面每个
//! `#[path = "../../cline-free/src/…"]` 都指向免费池那套模块，唯一的注入点是
//! `POOL = Pool::Pass`。
//!
//! 为什么必须是两个包：网关装包要求一个 wasm 包只声明一个 provider
//! （`provenance.rs:90`），而 cline-free 还有一条专属能力
//! `credential.cline-free-refresh.v1` 只允许 cline-free 声明。拆包是唯一
//! 能同时满足两者的形状（规格第 8 节的 A 方案）。
//!
//! ── 订阅池的续期 ────────────────────────────────────────────
//! 与免费池同一条 `POST /api/v1/auth/refresh`；专属的宿主固定换证通道只服务
//! cline-free，本包不申报 `credential.cline-free-refresh.v1`（申报了也不会
//! 被 `manifest.rs` 接受 —— 那条能力与 provider id 硬绑定）。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

#[path = "../../cline-free/src/pool.rs"]
mod pool;
#[path = "../../cline-free/src/credentials.rs"]
mod credentials;
#[path = "../../cline-free/src/upstream.rs"]
mod upstream;
#[path = "../../cline-free/src/refresh.rs"]
mod refresh;
#[path = "../../cline-free/src/chat.rs"]
mod chat;
#[path = "../../cline-free/src/login.rs"]
mod login;
#[path = "../../cline-free/src/account.rs"]
mod account;
#[path = "../../cline-free/src/balance.rs"]
mod balance;
#[path = "../../cline-free/src/models.rs"]
mod models;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 本包服务的池。
const POOL: pool::Pool = pool::Pool::Pass;

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号面 ──────────────────────────────────────────
        "account.normalize" => account::normalize(&params, POOL),
        "account.view" => Ok(credentials::public(&params["secret"])),
        "account.identity" => Ok(json!(credentials::identity(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        "token.ensure" => {
            let credentials = refresh::ensure(false)?;
            Ok(json!(credentials.bearer_token()))
        }
        "token.refresh" => {
            let credentials = refresh::ensure(true)?;
            Ok(json!(credentials.bearer_token()))
        }
        "token.expiring" => {
            let secret = params.get("secret").cloned().unwrap_or_else(|| params.clone());
            let credentials = credentials::from_secret(&secret);
            Ok(json!(credentials.can_refresh() && credentials.is_expiring()))
        }

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list(&metadata(), POOL)),
        "models.refresh" => Ok(models::refresh(params["force"].as_bool().unwrap_or(false), &metadata(), POOL)),

        // ── 额度 ────────────────────────────────────────────
        "usage.query" => balance::query(POOL),

        // ── 对话 ────────────────────────────────────────────
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作 ────────────────────────────────────────
        "admin.action" => admin_action(&params),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(upstream::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(params["status"].as_u64().unwrap_or(0) >= 400)),
        "error.policy" => Ok(json!({ "stop": false })),
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "Cline 的思考档位按请求体白名单透传，插件不额外注入"
        })),
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}

/// 管理动作：登录方式与额度来源。
fn admin_action(params: &Value) -> Result<Value> {
    match params["action"].as_str().unwrap_or("") {
        "auth.methods" => Ok(login::methods()),
        "quota.sources" => Ok(json!([])),
        other => Err(Error::http(
            400,
            format!("Cline 不认识管理动作「{other}」（可用：auth.methods / quota.sources）"),
        )),
    }
}
