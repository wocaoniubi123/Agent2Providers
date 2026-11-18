//! AStudio 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/astudio/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `account`   两套凭据（模型 Bearer / 网页 Cookie）、归一化、公开视图、身份
//!   `client`    模型目录、账号面（Cookie 信封）、Responses 请求、错误体
//!   `responses` Chat 请求 → Responses 请求（含用量取值链）
//!   `chat`      `conversation`：读 Responses SSE、翻成 chat 帧
//!   `models`    目录拉取 / 解析 / 会话缓存 / 静态兜底
//!   `usage`     积分与会员读数
//!   `checkin`   每日登录签到（先读余额 → 初始化 → 再读余额）
//!   `login`     动态登录方式（粘贴凭据 + 本机导入）
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`models()` → `models.list`；
//! `refresh_models()` → `models.refresh`；`usage()` → `usage.query`；
//! `checkin()` → `checkin.claim`；`normalize_account()` → `account.normalize`；
//! `admin.action` → `admin.action`。
//!
//! ── 本家 `refresh = false` ─────────────────────────────────
//! 上游没有续期接口：`modelBearerToken` 由官方客户端维护，过期只能重新登录。
//! 所以 `token.refresh` 原样返回当前令牌、`token.expiring` 恒 false ——
//! 这与 native 的 `Capabilities.refresh = false` 是同一件事。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

mod account;
mod chat;
mod checkin;
mod client;
mod login;
mod models;
mod responses;
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
        "account.view" => Ok(account::public(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 凭据（本家没有续期接口，见模块头）───────────────
        "token.ensure" => Ok(json!(account::model_key()?)),
        "token.refresh" => Ok(json!(account::model_key()?)),
        "token.expiring" => Ok(json!(false)),

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => Ok(models::refresh(params["force"].as_bool().unwrap_or(false))),

        // ── 额度 / 签到 ─────────────────────────────────────
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::checkin(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),
        "login.callback" => login::callback(&params),

        // ── 管理动作 ────────────────────────────────────────
        "admin.action" => admin_action(&params),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(classify(
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
            "reason": "AStudio 的思考档位由客户端在 Responses 的 reasoning.effort 里直接给"
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
            format!("AStudio 不认识管理动作「{other}」（可用：auth.methods / quota.sources）"),
        )),
    }
}

/// 非 2xx 的分类。
///
/// 上游的账号面错误有自己的 `code`（80000 = 会话失效），模型面则是标准
/// OpenAI 错误体；这里按「状态码 + 文案」归四档，与 native 的
/// `client::error_body` / `classify_message` 同一套判据。
fn classify(status: u16, body: &Value) -> Value {
    let raw = body
        .get("message")
        .or_else(|| body.pointer("/error/message"))
        .or_else(|| body.get("desc"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let lower = raw.to_ascii_lowercase();
    let message = if raw.trim().is_empty() {
        format!("上游返回 {status}")
    } else {
        format!("上游返回 {status}: {}", raw.trim())
    };
    let kind = body
        .pointer("/error/type")
        .or_else(|| body.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if kind == "content_filter"
        || lower.contains("content policy")
        || raw.contains("内容安全")
        || raw.contains("内容审核")
    {
        return json!({
            "kind": "content_blocked", "status": status, "message": message,
            "reset_at": Value::Null, "upstream_code": Value::Null,
        });
    }
    if status == 401
        || status == 403
        || lower.contains("重新登录")
        || body.get("code").and_then(Value::as_i64) == Some(80000)
    {
        return json!({
            "kind": "token_expired", "status": 401, "message": message,
            "reset_at": Value::Null, "upstream_code": Value::Null,
        });
    }
    let quota = status == 429
        || status == 402
        || [
            "quota",
            "balance",
            "credit",
            "invalid_quota",
            "insufficient",
            "额度",
            "积分",
            "余额",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        || ["额度", "积分", "余额"].iter().any(|marker| raw.contains(marker));
    if quota {
        return json!({
            "kind": "quota_limited", "status": if status < 400 { 429 } else { status },
            "message": message, "reset_at": Value::Null, "upstream_code": Value::Null,
        });
    }
    json!({
        "kind": "fatal", "status": status.max(400), "message": message,
        "reset_at": Value::Null, "upstream_code": Value::Null,
    })
}
