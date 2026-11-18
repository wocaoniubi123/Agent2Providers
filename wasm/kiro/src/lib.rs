//! Kiro 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/kiro/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `endpoints`   地址 / scopes / UA / 随机与 UUID（宿主 `random.bytes`）
//!   `credentials` 凭证形态、公开视图、去重身份
//!   `refresh`     刷新（social / idc / external-idp）与 profile 发现
//!   `request`     Chat → `conversationState`（含工具配对与思考档位）
//!   `eventstream` AWS event stream 帧解析（预读头、跳过 CRC）
//!   `events`      事件 → 中立增量（文本 / 思考 / 工具 / 用量）
//!   `chat`        `conversation`：首帧门 + chat SSE
//!   `models`      目录（控制面两套路径）与缓存
//!   `usage`       额度（`Get-Usage-Limits`）与窗口口径
//!   `search`      独立网页搜索（`InvokeMCP`）
//!   `login`       网页登录（回调回填）+ 本机导入 + API key
//!   `account`     归一化（本机 / 表单 / 文件）
//!   `errors`      四档分类与「输入过长」透传
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`conversation()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh_token()` → `token.refresh`；
//! `token_expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`normalize_account()` → `account.normalize`；
//! `admin.action`（含 `web-search.*`）→ `admin.action`。
//!
//! ── 保留的自用改动 ─────────────────────────────────────────
//! `ziyong` 相对 `upstream/beta` 在 `kiro/mod.rs` 加了一行
//! `AccountFeatures.invite_code: false`（账号页的「邀请码」按钮位）。
//! 本包的 `metadata.json` 里 `account_features.invite_code` 就是这一位，
//! 网关用本 fork 的 protocol crate 反序列化，位在就生效。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

mod account;
mod chat;
mod credentials;
mod endpoints;
mod errors;
mod events;
mod eventstream;
mod login;
mod models;
mod refresh;
mod request;
mod search;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

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
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(credentials::identity(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        "token.ensure" => {
            let (_, credentials) = refresh::ensure(false)?;
            Ok(json!(credentials.access))
        }
        "token.refresh" => {
            let (_, credentials) = refresh::ensure(true)?;
            Ok(json!(credentials.access))
        }
        "token.expiring" => Ok(json!(expiring(&params))),

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh_catalog(params["force"].as_bool().unwrap_or(false)),

        // ── 额度 ────────────────────────────────────────────
        "usage.query" => usage::query(),

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
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(params["status"].as_u64().unwrap_or(0) >= 400)),
        "error.policy" => Ok(json!({ "stop": false })),
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(reasoning_patch(&params)),
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}

/// `token.expiring`：判据与续期用同一把尺（`LEAD_MS`）。
///
/// 本机登录态要现读一次才能知道有效期；读不到就回 false（别把一条读不出来的
/// 账号塞进批量维护队列，那会变成每轮一条稳定失败）。
fn expiring(params: &Value) -> bool {
    let secret = params.get("secret").cloned().unwrap_or_else(|| params.clone());
    let credentials = credentials::Credentials::from_secret(&secret);
    if credentials.is_api_key() {
        return false;
    }
    if credentials.is_local() {
        let Ok(live) = refresh::read_local() else {
            return false;
        };
        let live = credentials::Credentials::from_secret(&live);
        return !live.fresh(endpoints::LEAD_MS);
    }
    !credentials.fresh(endpoints::LEAD_MS)
}

/// 管理动作：登录方式、独立网页搜索、额度来源。
fn admin_action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    match action {
        "auth.methods" => Ok(login::methods()),
        "web-search.capabilities" | "web-search.search" => search::dispatch(action, &params["payload"]),
        "quota.sources" => Ok(json!([])),
        other => Err(Error::http(
            400,
            format!(
                "Kiro 不认识管理动作「{other}」（可用：auth.methods / web-search.capabilities / web-search.search / quota.sources）"
            ),
        )),
    }
}

/// 思考档位：写进 `reasoning_effort`，由 `request` 翻成 Kiro 的预算。
fn reasoning_patch(params: &Value) -> Value {
    let body = &params["body"];
    if body.get("reasoning_effort").is_some_and(|value| !value.is_null()) {
        return json!({ "action": "skip", "reason": "客户端已指定思考档位" });
    }
    let level = params["level"].as_str().unwrap_or("");
    if matches!(level, "low" | "medium" | "high" | "xhigh" | "max") {
        json!({ "action": "set", "field": "reasoning_effort", "value": level })
    } else {
        json!({ "action": "skip", "reason": "Kiro 不支持该思考档位" })
    }
}
