//! CodeArts 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/codearts/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//!   `upstream`     上游地址 / 公共头 / 宿主会话 / 编码工具
//!   `credentials`  凭据解析、账号面、临期续期入口
//!   `signer`       SDK-HMAC-SHA256（按 Go `net/url` 语义）
//!   `chat`         出站构造、首包门、聚合、流式透传
//!   `stream_fault` 流内错误信封判定与话术翻译
//!   `tool_names`   函数名超 64 字符的改写与还原
//!   `models`       三源目录发现 / 解析 / 缓存
//!   `usage`        套餐统计与额度
//!   `welfare`      每日福利（签到）与新人注册礼
//!   `login`        网页登录（监听与换证在宿主里）
//!   `redact`       错误文本脱敏
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `chat` / `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`；`login.*` → `login.*`；
//! `admin.action` → `admin.action`。
//!
//! ── 为什么整条发送链走 `conversation`（`stateful = true`）────
//! 无状态路径假设「网关自己发请求、插件只回答怎么构造」。本家两件事做不到：
//!   1. 要先占一个上游会话槽（心跳 busy/idle），那是**跨请求**的状态；
//!   2. 失败判据在**流里**（HTTP 200 + 一帧 `InferHub.4291.200 / insufficient
//!      quota`），必须由插件在首包门里判掉才能触发换账号。
//! 所以 `conversation` 是唯一会发上游请求的入口，`chat` 保留为不支持。
//!
//! ── 这个包只声明一个 provider ──────────────────────────────
//! 网关 `codearts_enrollment` 的绑定按 `artifact.wasm_provider() == Some("codearts")`
//! 认领执行体，`pack.json` 的 `providers` 里多一个 id 就会让那层绑定直接拒收。
//! 因此本包不做别名、不做代理，只有一个 `codearts`。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap/expect/panic。

mod chat;
mod credentials;
mod login;
mod models;
mod redact;
mod signer;
mod stream_fault;
mod tool_names;
mod upstream;
mod usage;
mod welfare;

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

        // ── 账号面 ──────────────────────────────────────────
        "account.normalize" => credentials::normalize(&params),
        "account.view" => Ok(credentials::account_view(&params["secret"])),
        "account.identity" => Ok(json!(credentials::identity_of(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // `token.ensure` / `token.refresh` 返回的都是**可用的 access key**：
        // 宿主用它判断「这个账号此刻有没有令牌」，不是拿它去签请求（签名在插件里）。
        "token.ensure" => Ok(json!(credentials::ensure(false)?.access_key_id)),
        "token.refresh" => Ok(json!(credentials::ensure(true)?.access_key_id)),
        "token.expiring" => Ok(json!(expiring(&params))),

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),

        // ── 额度 / 签到 / 领取 ──────────────────────────────
        "usage.query" => usage::query(),
        "checkin.claim" => welfare::checkin(),
        "claim.status" => welfare::tasks(),
        "claim" => welfare::claim_newbie(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        // 本家的发送链是有状态的（会话槽 + 首包门），无状态 `chat` 没有可回答的
        // 内容：这里如实报不支持，而不是伪装成「已构造」。
        "chat" => Err(Error::unsupported()),

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
        "is_error_response" => Ok(json!(is_error_response(&params))),
        "error.policy" => Ok(error_policy(&params)),
        "retry_advice" => Ok(Value::Null),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "本家没有「关闭思考」这一档：off/none 会在出站前被摘掉，其余档位原样透传"
        })),
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}

/// `token.expiring`：临期判定必须与续期用同一个提前量。
///
/// 回 false 等于把这个账号从批量维护范围里永久剔除，而本家凭据默认只活一小时，
/// 所以这里宁可判「要刷」（坏时间戳也算）也不能漏。
fn expiring(params: &Value) -> bool {
    let secret = params.get("secret").cloned().unwrap_or_else(|| params.clone());
    match credentials::Credential::from_payload(&secret) {
        Ok(credential) => {
            credential.can_refresh()
                && credential.needs_refresh(credentials::REFRESH_LEAD_MS, sdk::now())
        }
        Err(_) => false,
    }
}

/// 非 2xx 的分类。
///
/// **注意**：CodeArts 的业务失败常常不体现在状态码上（额度耗尽是 HTTP 200
/// SSE 里的信封），那部分由首包门 + `stream_fault` 负责；这里只管真的是状态码
/// 的错。三条口径与参考实现一致：403 = 额度、429 = 限流、401 = 令牌过期、其余透传。
fn classify(status: u16, body: &Value) -> Value {
    let raw = body
        .get("message")
        .or_else(|| body.get("error_msg"))
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let message = if raw.trim().is_empty() {
        format!("上游返回 {status}")
    } else {
        format!("上游返回 {status}: {}", raw.trim())
    };
    let message = stream_fault::humanize_fault_message(message, "");
    let (kind, status, code) = match status {
        403 => ("quota_limited", 403, Some("insufficient_quota")),
        429 => ("quota_limited", 429, Some("rate_limit_exceeded")),
        401 => ("token_expired", 401, None),
        _ => ("fatal", status.max(400), None),
    };
    json!({
        "kind": kind,
        "status": status,
        "message": message,
        "reset_at": Value::Null,
        "upstream_code": Value::Null,
        "code": code,
    })
}

/// 这一帧/这个响应算不算错误（内容拦截判定的挂点）。
///
/// 两条判据：HTTP 状态在 4xx/5xx；或者体里/流里的帧是一枚**错误信封**
/// （`error_code` 非空且非成功码）。编解码由 `stream_fault` 负责，这里只回答
/// 「是不是错误」，让编排层决定停手还是换账号。
fn is_error_response(params: &Value) -> bool {
    let status = params["status"].as_u64().unwrap_or(0) as u16;
    if status >= 400 {
        return true;
    }
    let body = &params["body"];
    let text = match body.as_str() {
        Some(text) => text.to_string(),
        None => body.to_string(),
    };
    if text.trim().is_empty() {
        return false;
    }
    // 整段体可能是一帧，也可能是一串 `data: {...}`；逐帧判
    for line in text.lines() {
        let payload = line.trim().strip_prefix("data:").unwrap_or(line.trim()).trim();
        if payload.is_empty() || payload == stream_fault::DONE_SENTINEL {
            continue;
        }
        if stream_fault::stream_frame_fault(payload).is_some() {
            return true;
        }
    }
    false
}

/// 是否**停手**（不再换账号）。
///
/// 只有「请求本身有问题」才停：体积被拒、参数无效、模型名不存在 —— 换任何一个
/// 账号都会撞同一堵墙，继续轮转只是把同一份体重发一遍。额度/限流不停手（那正是
/// 要换账号的场景），内容闸门也不停手（换一家可能答得出来）。
fn error_policy(params: &Value) -> Value {
    let status = params["status"].as_u64().unwrap_or(0) as u16;
    let body = &params["body"];
    let text = body.as_str().map(str::to_string).unwrap_or_else(|| body.to_string());
    let lowered = text.to_lowercase();
    let stop = lowered.contains("parse_request_data_exception")
        || lowered.contains("request entity too large")
        || lowered.contains("inferhub.001001005.400")
        || lowered.contains("inferhub.001001017.413")
        || lowered.contains("model is not registered")
        || chat::size_rejection_text(&text).is_some()
        || status == 413;
    json!({ "stop": stop })
}

/// 管理动作：每日福利的「预读 / 领取」，以及登录方式与额度来源。
///
/// ```text
///   welfare.preview → GET /v1/ops/delivery（只读，一个写请求都不发）
///   welfare.claim   → 真的去领（payload.auto=true 时走 6 次/10 分钟的写闸）
/// ```
///
/// 领完顺手把余额读回来：面板上「领到了」与「积分确实变了」是两件事，一次点击
/// 能同时回答最好（余额读失败给 null，不影响领取结果）。
fn admin_action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    match action {
        "welfare.preview" => welfare::preview(sdk::now()),
        "welfare.claim" => {
            // 缺省必须是 **false（手动）**：限流两道闸存在的理由是「别在没人看着的
            // 时候反复花掉领取机会」。非布尔也按手动处理 —— 认字符串会让手滑的调用
            // 方绕过限流。
            let auto = params["payload"]["auto"].as_bool().unwrap_or(false);
            let run = welfare::claim_rewards(sdk::now(), !auto, false)?;
            let usage = welfare::refresh_usage();
            Ok(json!({
                "result": run.outcome.label(),
                "confirmed": matches!(run.outcome, welfare::Outcome::Confirmed),
                "usage": usage,
                "note": "领取到账的是套餐赠送积分",
            }))
        }
        // 登录方式走**动态契约**（见 `login::methods` 的说明）：网关按
        // `LoginMethodsMetadata` 解析，`locale` 由网关放在 `payload` 里传进来。
        "auth.methods" => Ok(login::methods(
            params["payload"]["locale"].as_str().unwrap_or("zh-CN"),
        )),
        // 本家没有独立的额度来源声明（总积分由套餐统计一处给出）
        "quota.sources" => Ok(json!([])),
        other => Err(Error::http(
            400,
            format!("CodeArts 不认识管理动作「{other}」（可用：welfare.preview / welfare.claim / auth.methods / quota.sources）"),
        )),
    }
}
