//! QuWork 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/quwork/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `upstream`  账号服务 / 模型网关的地址、公共头、回包解析与脱敏
//!   `account`   凭证解析、公开视图、稳定身份、本机登录态引用
//!   `refresh`   登录会话续期（账号锁 + 比较再写 + 会话缓存）
//!   `models`    公开模型目录（校验 + 会话缓存 + 内置兜底）
//!   `chat`      `conversation`：模型白名单、compat 改写、SSE 透传
//!   `usage`     积分余额
//!   `plans`     每日奖励（签到）、月度赠送预览、权益兑换
//!   `login`     动态登录方式（本机导入 + 粘贴凭证）与本机导入流程
//!   `errors`    错误分类与流内错误帧
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`；`admin.action` → `admin.action`。
//!
//! ── 这个包只声明一个 provider ──────────────────────────────
//! 网关装包要求 `providers.len() == 1`（`provenance.rs:90`），多一个 id
//! 整包不启动。所以本包不做别名、不做代理，只有 `quwork`。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

mod account;
mod chat;
mod errors;
mod login;
mod models;
mod plans;
mod refresh;
mod upstream;
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

        // ── 凭据 ────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::model_token()?)),
        "token.refresh" => {
            refresh::refresh(true)?;
            Ok(json!(account::model_token()?))
        }
        "token.expiring" => {
            let secret = params.get("secret").cloned().unwrap_or_else(|| params.clone());
            Ok(json!(account::expiring(&secret)))
        }

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),

        // ── 额度 / 签到 / 领取 ──────────────────────────────
        "usage.query" => usage::query(),
        "checkin.claim" => plans::checkin(),
        "claim.status" => plans::preview(),
        "claim" => plans::claim(&params),

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

/// 管理动作：登录方式、权益兑换、额度来源。
fn admin_action(params: &Value) -> Result<Value> {
    match params["action"].as_str().unwrap_or("") {
        // 动态契约：locale 由网关放在 payload 里（本包只有简体中文文案）。
        "auth.methods" => Ok(login::methods()),
        "benefits.redeem" => plans::redeem(params),
        // 本家没有独立的额度来源声明（积分由 `usage.query` 一处给出）。
        "quota.sources" => Ok(json!([])),
        other => Err(Error::http(
            400,
            format!("QuWork 不认识管理动作「{other}」（可用：auth.methods / benefits.redeem / quota.sources）"),
        )),
    }
}

/// 思考档位：按目录里的 `reasoningEfforts` 翻成上游值。
///
/// 三条闸门与 native 同款：客户端已显式指定 → 让位；`thinking` 已存在 → 让位；
/// 目录里没有这个档位 → 不注入。
fn reasoning_patch(params: &Value) -> Value {
    let skip = |reason: &str| json!({ "action": "skip", "reason": reason });
    let body = &params["body"];
    let client_level = body
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/reasoning/effort").and_then(Value::as_str));
    if client_level.is_some_and(|level| !level.trim().is_empty())
        || body.get("thinking").is_some_and(|value| !value.is_null())
    {
        return skip("QuWork 按模型目录和客户端设置处理思考档位");
    }
    let level = params["level"].as_str().unwrap_or("");
    let model = params["model"].as_str().unwrap_or("");
    let normalized = if level == "none" { "off" } else { level };
    let catalog = models::current();
    let Some(wire) = catalog
        .model(model)
        .and_then(|row| row.get("reasoningEfforts"))
        .and_then(|levels| levels.get(normalized))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return skip("该等级不在 QuWork 当前目录的档位内");
    };
    json!({ "action": "set", "field": "reasoning_effort", "value": wire })
}
