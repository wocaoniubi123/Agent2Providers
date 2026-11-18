//! 小浣熊 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/raccoon/`（native，19 个文件）。
//! 参照样板：`wasm/atomcode/`（上游官方已完成的 wasm provider）。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! | native trait 方法 | wasm method |
//! |---|---|
//! | `meta()` | `init` / `provider.info`（`metadata.json`） |
//! | `build_chat()` | `chat`（插件自己发 + 自己转 SSE，见 `chat.rs`） |
//! | `conversation()`（有状态家才有） | `conversation`（同一份实现） |
//! | `ensure_token()` / `refresh_token()` / `token_expiring()` | `token.ensure` / `token.refresh` / `token.expiring` |
//! | `models()` / `refresh_models()` | `models.list` / `models.refresh` |
//! | `usage()` / `checkin()` | `usage.query` / `checkin.claim` |
//! | `claim_status()` / `claim()` | `claim.status` / `claim` |
//! | `normalize_account()` / `account_view()` / `account_identity()` | `account.normalize` / `account.view` / `account.identity` |
//! | `login_start()` / `login_callback()` / `login_cancel()` | `login.start` / `login.callback` / `login.cancel`（另有 `login.poll`） |
//! | `classify()` / `reasoning_patch()` | `classify` / `reasoning_patch` |
//! | `is_error_response()` / `error_policy()` / `retry_advice()` / `cooldown_models()` | 同名（native 未覆写，这里返回同样的默认值） |
//! | `login.*` / `admin.action` | 同名（`admin.action` 只实现 `auth.methods`：登录方式清单） |
//!
//! ── native 有、wasm 没有的三块能力（都写在各文件的模块头）──────
//!   1. **桌面端实时登录态**：读 `~/.box-agent/config/auth.json`。wasm 没有文件
//!      系统 → `account.normalize` 的 `desktop` 来源给可读错误；
//!   2. **环境变量**：`RACCOON_TOKEN` / `RACCOON_*` 换成宿主设置（`upstream.rs`）；
//!   3. **图片生成 / 参考图编辑**：这套 ABI 没有图片方法（`image.rs`）。
//!
//! ── 没实现的统一 `unsupported` ───────────────────────────────
//! `admin.action` 里除 `auth.methods` 之外的其它动作（本家没有别的管理面动作，
//! metadata 的 `admin_panels` 也是空的）、`abort` / `credit` / `shutdown` 这类
//! 宿主侧控制方法，以及任何本表之外的方法。

mod account;
mod balance;
mod chat;
mod client_identity;
mod conversation;
mod credentials;
mod errors;
mod fallback;
mod headers;
mod iam;
mod image;
mod jwt;
mod login;
mod models;
mod oauth;
mod onboarding;
mod reasoning;
mod refresh_api;
mod upstream;
mod url;

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

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 数据面 ────────────────────────────────────────────
        // `chat` 与 `conversation` 走同一份实现：小浣熊是无状态家
        // （`capabilities.stateful = false`），两条路都不需要工具循环状态，
        // 差别只在宿主怎么编排；插件这一侧都是「自己发、自己转」。
        "chat" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 凭证 ──────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::ensure(&params)?)),
        "token.refresh" => Ok(json!(account::refresh(&params)?)),
        "token.expiring" => Ok(json!(account::expiring(&params)?)),

        // ── 目录 ──────────────────────────────────────────────
        "models.list" => models::list(),
        "models.refresh" => models::refresh(
            params["account"].as_str().unwrap_or(""),
            params["force"].as_bool().unwrap_or(false),
        ),

        // ── 余额 / 签到 / 领取 ────────────────────────────────
        "usage.query" => balance::query_usage(&params),
        "checkin.claim" => balance::claim(&params),
        // 新手任务：`claim.status` 只读（零上游），`claim` 才真的打 grant 端点
        "claim.status" => onboarding::get_tasks(&params),
        "claim" => onboarding::claim_all(&params),

        // ── 账号 ──────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 登录 ──────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),
        "login.callback" => login::callback(&params),

        // 网关问「登录方式」时回**动态契约**（见 `login::login_methods`）。
        // 本家只有这一条管理面动作，其余动作落到 `_` 分支的 `unsupported`。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::login_methods(
            params["payload"]["locale"]
                .as_str()
                .or_else(|| params["locale"].as_str())
                .unwrap_or("zh-CN"),
        )),

        // ── 分类与策略 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // native 没有覆写 `is_error_response`（默认 false）：小浣熊的失败一律
        // 带非 2xx 或流内错误帧，没有「200 但正文是失败话术」这一形态。
        "is_error_response" => Ok(json!(false)),
        // native 的 `error_policy` 默认值是 null（不额外约束处置）
        "error.policy" => Ok(Value::Null),
        // native 的 `retry_advice` 默认 None（没有专属退避建议，走网关通用规则）
        "retry_advice" => Ok(Value::Null),
        // native 的 `cooldown_models` 默认值（限额只冷却请求的那个模型）
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(reasoning::patch(
            params["level"].as_str().unwrap_or(""),
            params["model"].as_str().unwrap_or(""),
            &params["body"],
        )),

        // ── 图片 ──────────────────────────────────────────────
        // 只有能力申报：这套 ABI 没有图片方法，见 `image.rs`
        "images.capabilities" => Ok(image::capabilities()),

        _ => Err(Error::unsupported()),
    }
}
