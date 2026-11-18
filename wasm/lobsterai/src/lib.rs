//! LobsterAI 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/`（native，10 个文件）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//! ```text
//!   upstream      上游地址 / 身份常量 / 出站薄封装 / URL 拼装
//!   credentials   凭证解析（uuid + 两个 keyfrom 是载荷件）/ 账号视图 / 身份
//!   codec         base64 解码与 uuid v4（缺的原语自己写 + 已知向量测试）
//!   version       客户端版本解析（settings 钉住 → 会话缓存 → 接口 → 兜底）
//!   errors        状态码 + 业务码 → 网关认识的四个分类；流内错误帧识别
//!   models        目录（19 条兜底 + 远程刷新）/ 模型名解析
//!   oauth         换码 / 续期 / 业务信封 / 回调解析
//!   login         登录编排（start / poll / callback / cancel）
//!   chat          conversation 转发（四处改写 + 首包门 + SSE 透传）
//!   usage         积分读数（profile-summary）归一
//!   checkin       每日签到三步协议
//!   account       账号面（凭证读取 / 续期写回 / 导入拒绝）
//! ```
//!
//! ── 四条装包期硬校验（不满足 = 整包加载失败）───────────────
//! 1. `capabilities.chat == true` → requires 必须有 `chat.stream.v1` 和 `accounts.cas.v1`
//! 2. `capabilities.model_refresh == true` → requires 必须有 `catalog.v1`
//! 3. `capabilities.web_login == true` → requires 必须有 `login.forms.v1`
//! 4. `capabilities.anonymous_default_session` / `env_credentials` 必须都是 false
//! 另有：`settings_schema.storage_provider`（若有）必须是本包自己的 provider id。
//! 生成脚本已按这五条配好，改 metadata 时别破坏。
//!
//! ── 对话只能走 `conversation` ───────────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回
//! 501，`forwards_response()` 对 wasm 恒为 true —— 所以 wasm 包的对话一律走
//! 会话式通道：插件自己 `http::open` 发请求，再用 `stream_head` /
//! `stream_bytes` 回传 SSE。`chat` 写了也不会被调用，因此这里如实报
//! `unsupported`（而不是伪装成「已构造」）。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh_token()` → `token.refresh`；
//! `token_expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`；`account_view()` → `account.view`；
//! `account_identity()` → `account.identity`；`login.*` → `login.*`。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，绝不 unwrap / expect / panic（`metadata()` 的
//! `unwrap_or` 是兜底而不是解包：编译期常量坏了也不该带走整个实例）。

mod account;
mod chat;
mod checkin;
mod codec;
mod credentials;
mod errors;
mod login;
mod models;
mod oauth;
mod upstream;
mod usage;
mod version;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

/// `models.refresh`：把宿主的 `account` / `force` 交给目录模块。
///
/// 账号 id 为空 = 还没添加账号，那是正常状态（返回 unchanged，不是失败）；
/// 非空时读该账号的 secret —— 宿主 `context.rs` 会用 `params["account"]`
/// 绑定账号上下文，所以 `sdk::account()` 拿到的就是它。
fn models_refresh(params: &Value) -> Result<Value> {
    let account_id = params["account"].as_str().unwrap_or("").trim().to_string();
    let force = params["force"].as_bool().unwrap_or(false);
    let secret = if account_id.is_empty() {
        None
    } else {
        account::record()
            .ok()
            .and_then(|record| record.get("secret").cloned())
            .filter(Value::is_object)
    };
    Ok(models::refresh(force, &account_id, secret.as_ref()))
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号面 ──────────────────────────────────────────
        // 本家只能网页登录（粘贴不出 uuid / keyfrom），所以 normalize 如实拒绝。
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 令牌 ────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring(&params))),

        // ── 目录 / 额度 / 签到 ──────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models_refresh(&params),
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),

        // ── 对话 ────────────────────────────────────────────
        // 唯一的发送入口：插件自己发上游请求 + 回传 SSE（见文件头）。
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        // `chat` 是死路径：网关对 wasm 包直接 501，不会走到这里。
        "chat" => Err(Error::unsupported()),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16
        ))),
        "error.policy" => Ok(errors::error_policy(
            params["status"].as_u64().unwrap_or(0) as u16,
            &params["body"],
        )),

        // ── 平台协作位 ──────────────────────────────────────
        // 本家没有跨家重试建议：通道级重试由网关按 `classify` 的结论处理。
        "retry_advice" => Ok(Value::Null),
        // 冷却标记在 native 里由 `store_mark_limited` 落账号库；插件侧交给编排层
        // 按 `classify` 的结论处理，所以这里没有按模型的冷却清单。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 思考档位原样透传：本家认 `reasoning_effort`（缺 `thinking-level-control-v1`
        // 能力位时上游 500，而那个能力位是**客户端头**里声明的，不需要平台再补）。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "按上游原始请求透传思考设置（能力位已在客户端头里声明）"
        })),
        // 本家没有生图 / 改图通道（wasm 侧也只有豆包能走那条路）。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),
        // 平台只有「额度来源」这一个面板问本家；本家的来源已在 `usage.query`
        // 的 `credits[]` 里给全，这里回空表即可（与 atomcode / trae 同口径）。
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),
        // 平台问「登录方式」：必须回**动态契约**那份（网关对 wasm 恒走
        // `dynamic_login()`，见 `api/session.rs:263-280`），数据源是
        // `metadata.json` 的 `login_methods`（映射规则见 `login::methods`）
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods()),

        _ => Err(Error::unsupported()),
    }
}

