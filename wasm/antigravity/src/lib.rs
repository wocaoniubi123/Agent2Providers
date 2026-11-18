//! Antigravity 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/antigravity/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `endpoints`   OAuth 常量 / v1internal 三个基址 / 逐字请求头 / UA
//!   `credentials` 凭证形态（refreshToken 主 + accessToken 缓存）与临期判定
//!   `refresh`     Google token 端点（form）+ project 发现
//!   `models`      `:fetchAvailableModels` + 兜底清单 + 对外 id → 上游真名
//!   `schema`      工具参数 JSON Schema 清洗（Gemini 不认全集）
//!   `outbound`    Chat → v1internal 信封（contents / tools / generationConfig）
//!   `stream`      v1internal SSE → chat SSE 状态机（从网关搬进来）
//!   `chat`        `conversation`：发请求 + 两种错误边界
//!   `balance`     `:retrieveUserQuotaSummary` + `loadCodeAssist`
//!   `login`       网页登录（回调回填）+ 粘贴 refresh token
//!   `account`     归一化（表单 / 文件）
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`（+ `stream` 翻译）；
//! `ensure_token()` → `token.ensure`；`refresh_token()` → `token.refresh`；
//! `token_expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`normalize_account()` → `account.normalize`；
//! `admin.action` → `admin.action`。
//!
//! ── 本家跟随系统代理 ───────────────────────────────────────
//! native 的 `system_proxy_when_unset = true`（仓内唯一）：Google 多数网络里
//! 只有经代理才可达。wasm 的出口由宿主按账号代理配置决定，插件侧没有「跟随
//! 系统代理」这个开关位；metadata 里那一位保留原值，实际出网由宿主负责。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

mod account;
mod balance;
mod chat;
mod credentials;
mod endpoints;
mod login;
mod models;
mod outbound;
mod refresh;
mod schema;
mod stream;

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
            Ok(json!(credentials.access_token))
        }
        "token.refresh" => {
            let (_, credentials) = refresh::ensure(true)?;
            Ok(json!(credentials.access_token))
        }
        "token.expiring" => {
            let secret = params.get("secret").cloned().unwrap_or_else(|| params.clone());
            let credentials = credentials::AntigravityCredentials::from_secret(&secret);
            Ok(json!(credentials.can_refresh() && credentials.expiring()))
        }

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list(&metadata())),
        "models.refresh" => models::refresh_catalog(params["force"].as_bool().unwrap_or(false)),

        // ── 额度 ────────────────────────────────────────────
        "usage.query" => {
            let (_, credentials) = refresh::ensure(false)?;
            balance::query(&credentials)
        }

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
        "classify" => Ok(classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(params["status"].as_u64().unwrap_or(0) >= 400)),
        "error.policy" => Ok(json!({ "stop": false })),
        "retry_advice" => Ok(retry_advice(&params)),
        "retry.decision" => Ok(json!({ "action": "default" })),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(reasoning_patch(&params)),
        "images.capabilities" => Ok(json!({
            "generation": false,
            "editing": false,
            "note": "wasm 侧没有通用图片通道：native 的生图/改图能力无法保留"
        })),

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
            format!("Antigravity 不认识管理动作「{other}」（可用：auth.methods / quota.sources）"),
        )),
    }
}

/// 非 2xx 的分类（规格 §7 的映射表 + 本仓的四档口径）。
///
/// 判据**先看文案再看状态码**：Google 把业务语义放在 `error.status` 里
/// （`RESOURCE_EXHAUSTED` / `PERMISSION_DENIED` / `UNAVAILABLE`），HTTP 状态
/// 只是它的投影。
fn classify(status: u16, body: &Value) -> Value {
    let raw = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| body.get("message").and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误");
    let message = format!("上游返回 {status}: {raw}");
    let code = body
        .pointer("/error/code")
        .or_else(|| body.get("code"))
        .and_then(Value::as_i64);
    let lowered = raw.to_ascii_uppercase();
    if lowered.contains("RESOURCE_EXHAUSTED") {
        return json!({
            "kind": "quota_limited", "status": 429, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 401 || status == 403 {
        return json!({
            "kind": "token_expired", "status": 401, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 429 {
        return json!({
            "kind": "quota_limited", "status": status, "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 400 {
        // 400 档交给共用的内容拦截判定：文案里带 safety 的按内容拦截处理。
        let blocked = ["safety", "blocked", "prohibited", "content_filter"]
            .iter()
            .any(|marker| lowered.to_ascii_lowercase().contains(marker));
        if blocked {
            return json!({
                "kind": "content_blocked", "status": 403, "message": message,
                "reset_at": Value::Null, "upstream_code": code,
            });
        }
    }
    json!({
        "kind": "fatal", "status": status.max(400), "message": message,
        "reset_at": Value::Null, "upstream_code": code,
    })
}

/// 原地退避建议：Google 把瞬时故障写成 `UNAVAILABLE` / `overloaded`。
fn retry_advice(params: &Value) -> Value {
    let raw = params["body"]
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| params["body"].get("message").and_then(Value::as_str))
        .unwrap_or("");
    let lowered = raw.to_ascii_lowercase();
    let transient = ["unavailable", "internal", "deadline_exceeded", "overloaded", "try again", "timeout"]
        .iter()
        .any(|pattern| lowered.contains(pattern));
    if !transient {
        return Value::Null;
    }
    json!({ "delay_ms": 10_000, "reason": format!("上游暂时不可用（{raw}），稍后重试") })
}

/// 思考档位：写成 body 顶层的 `reasoning_effort`，由 `outbound` 翻成
/// `generationConfig.thinkingConfig.thinkingBudget`。
fn reasoning_patch(params: &Value) -> Value {
    let body = &params["body"];
    let explicit = body
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/reasoning/effort").and_then(Value::as_str))
        .filter(|level| !level.trim().is_empty());
    if explicit.is_some() {
        return json!({ "action": "skip", "reason": "客户端请求体里已指定思考档位" });
    }
    let level = params["level"].as_str().unwrap_or("");
    if matches!(level, "low" | "medium" | "high" | "xhigh" | "max") {
        json!({ "action": "set", "field": "reasoning_effort", "value": level })
    } else {
        json!({ "action": "skip", "reason": "该等级不在本家接受的档位内（本家只认通用档位）" })
    }
}
