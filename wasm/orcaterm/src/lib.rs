//! OrcaTerm 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/orcaterm/`（native）。
//!
//! ── 与 native 的对应关系（trait → JSON 方法名）──────────────
//! | native trait 方法 | wasm method |
//! |---|---|
//! | `meta()` | `metadata.json` |
//! | `build_chat()` / `conversation()` | `chat` / `conversation` |
//! | `ensure_token()` | `token.ensure` |
//! | `refresh_token()` | `token.refresh` |
//! | `token_expiring()` | `token.expiring` |
//! | `models()` | `models.list` |
//! | `refresh_models()` | `models.refresh` |
//! | `usage()` | `usage.query` |
//! | `checkin()` / 领取 | `checkin.claim`（本家没有签到，如实不支持） |
//! | `normalize_account()` | `account.normalize` |
//! | `account_view()` | `account.view` |
//! | `account_identity()` | `account.identity` |
//! | `classify()` | `classify` |
//! | 内容拦截判定 | `is_error_response` |
//! | `error_policy` | `error.policy` |
//! | `retry_advice` / `cooldown_models` / `reasoning_patch` | 同名 |
//! | `login_start` / `login_callback` | `login.start` / `login.callback` |
//!
//! ── 四条装包期硬校验（不满足 = 整包加载失败）───────────────
//! 1. `capabilities.chat == true` → requires 必须有 `chat.stream.v1` 和 `accounts.cas.v1`
//! 2. `capabilities.model_refresh == true` → requires 必须有 `catalog.v1`
//! 3. `capabilities.web_login == true` → requires 必须有 `login.forms.v1`
//! 4. `capabilities.anonymous_default_session` / `env_credentials` 必须都是 false
//! 另有：`settings_schema.storage_provider`（若有）必须是本包自己的 provider id。
//!
//! 本家 `model_refresh` 取 **false**（上游没有可拉的清单接口，目录是静态表），
//! 所以 `catalog.v1` 不在 requires 里；其余三条按现状满足。
//!
//! ── 对话只能走 `conversation` ───────────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回
//! 501，`forwards_response()` 对 wasm 恒为 true —— 所以 wasm 包的对话一律走
//! 会话式通道：插件自己 `http::open` 发请求，再用 `stream_head` /
//! `stream_bytes` 回传 SSE。`chat` 写了也不会被调用，这里如实报不支持。
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   account   凭据形态 / JWT 声明 / 续期回写 / 账号面 / 导入归一化
//!   upstream  地址 / 头 / JSON 动作（CGI）/ SSE 出站 / 错误翻译
//!   chat      建会话 → assistant SSE → OpenAI 帧（含 401 自愈与信封解包）
//!   models    静态目录与模型名归一
//!   errors    状态码 → 网关认识的分类 / 流内错误帧形态
//!   login     微信扫码授权页 / 回调换令牌 / 登录方式声明
//!   usage     `DescribeUserBillingStatus` 的月度配额 → usage 形状
//!   codec     base64 / 十六进制 / 随机源 / UUID
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 全部文件零 `unwrap` / `expect` / `panic`：宿主里一个 panic 会带走整个实例。

mod account;
mod chat;
mod codec;
mod errors;
mod login;
mod models;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    // 文件是编译期常量，解析失败只可能是有人改坏了它；返回 Null 让界面缺元数据，
    // 而不是在启动路径上 panic（`unwrap` 在这里等于「整包加载失败」）。
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
        "account.identity" => Ok(json!(account::identity_of(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // 这两个方法返回的是**可用的 accessToken**：宿主用它判断「这个账号此刻
        // 有没有令牌」，真正发请求时插件自己再读一遍账号（凭证可能已被续期）。
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring(&token_secret(&params)))),

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        // 目录是客户端内置的静态表，没有可拉的上游接口；如实回报「没刷新」，
        // 而不是造一个空目录把现有绑定冲掉。
        "models.refresh" => Ok(json!({
            "refreshed": false,
            "count": models::count(),
            "message": "OrcaTerm 的模型清单来自客户端内置，上游没有可拉的清单接口",
        })),

        // ── 额度 ────────────────────────────────────────────
        "usage.query" => usage::query(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" => {
            chat::run(&params)?;
            Ok(Value::Null)
        }
        // 网关对 wasm 包的 `chat` 直接 501，写了也不会被调用 —— 如实报不支持，
        // 而不是伪装成「已构造出请求」。
        "chat" => Err(Error::unsupported()),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作 ────────────────────────────────────────
        // 登录方式走**动态契约**（见 `login::methods` 的说明）：网关按
        // `LoginMethodsMetadata` 解析，`locale` 由网关放在 `payload` 里传进来。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods(
            params["payload"]["locale"].as_str().unwrap_or("zh-CN"),
        )),
        // 本家的额度只有一个来源（月度 AI 配额），已在 `usage.query` 里给全
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
        ))),
        "error.policy" => Ok(errors::policy()),
        // 冷却与重试都在编排层：本家上游没有 429（限额错误在流内帧里），
        // 且配额按月重置，做账号级冷却的收益为负。
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 上游请求体的 `setting` 里没有思考档位开关，原样透传即可
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "上游请求体没有思考档位开关，按原样透传",
        })),
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}

/// `token.expiring` 的 secret：宿主可能给 `params.secret`，也可能把 secret 本身当参数。
fn token_secret(params: &Value) -> Value {
    params.get("secret").cloned().unwrap_or_else(|| params.clone())
}
