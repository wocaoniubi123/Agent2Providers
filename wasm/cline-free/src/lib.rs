//! Cline **免费池**（`cline-free`）的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/cline/`（native，`ClineProvider::FREE`）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `pool`        两个额度池的参数（provider id / 标签 / 通道前缀）
//!   `credentials` 凭证形态（`workos:` 前缀幂等补、JWT 取 exp / 账号 id）
//!   `upstream`    出网、固定四个头、错误分类与 429 冷却时长解析
//!   `refresh`     `POST /auth/refresh` + 账号锁 + 比较再写
//!   `chat`        `conversation`：白名单重建 + SSE 透传
//!   `login`       WorkOS 设备授权（页面输入授权码）
//!   `account`     归一化（本机导入 / 表单 / 文件）
//!   `balance`     积分余额与套餐
//!   `models`      按池过滤内置清单
//!
//! ── 这个包只声明一个 provider ──────────────────────────────
//! 网关装包要求 `providers.len() == 1`（`provenance.rs:90`），而且 cline-free
//! 的**专属能力** `credential.cline-free-refresh.v1` 只允许 cline-free 声明
//! （`manifest.rs` 的同名校验）。所以免费池与订阅池是两个包，源码共享：
//! `cline-pass/src/lib.rs` 用 `#[path]` 引本目录的模块，只换 `POOL`。
//!
//! ── 专属通道怎么配合 ──────────────────────────────────────
//! 宿主 `plugin_host/wasm/cline_free_enrollment/binding.rs` 对执行体有硬要求：
//! `REQUIRED = ["accounts.cas.v1","accounts.identity.v1","login.forms.v1",
//! "credential.cline-free-refresh.v1"]` 全部在 `wasm.json` 的 `requires` 里，
//! 且 `artifact.wasm_provider() == Some("cline-free")`（= 本包只声明一个
//! provider 且就是它）。本包的 `wasm.json` 逐条满足，见那个文件。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

#[path = "pool.rs"]
mod pool;
#[path = "credentials.rs"]
mod credentials;
#[path = "upstream.rs"]
mod upstream;
#[path = "refresh.rs"]
mod refresh;
#[path = "chat.rs"]
mod chat;
#[path = "login.rs"]
mod login;
#[path = "account.rs"]
mod account;
#[path = "balance.rs"]
mod balance;
#[path = "models.rs"]
mod models;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 本包服务的池（订阅池那个包写 `Pool::Pass`）。
const POOL: pool::Pool = pool::Pool::Free;

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
///
/// `upstream_headers`（客户端头覆盖表）没有 wasm 侧的读写通道：它是网关的
/// 用户配置，插件只能读自己的设置项，而设置命名空间又只授权了本 provider。
/// 所以这里如实不提供该动作。
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
