//! Command Code 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/commandcode/`（native）。
//!
//! ── 当前阶段 ────────────────────────────────────────────────
//! 业务模块已补齐（凭证 / 指纹 / 8 键信封 / 目录 / 错误分类 / NDJSON 折叠），
//! `handle` 里逐条挂上方法名。
//!
//! ── 本家与非标准协议的硬事实（native `mod.rs` 的模块头，原样带过来）─────
//! ```text
//!   1. 生成走 POST /alpha/generate，请求体是**自有信封**
//!      （config / memory / taste / skills / permissionMode / [threadId] / mode / params），
//!      而不是 OpenAI 的 {model, messages}；
//!   2. 响应是 **NDJSON**（一行一个 JSON 事件），且 **HTTP 恒 200** ——
//!      认证失败 / 限流 / 余额不足都在流内 {"type":"error"} 表达；
//!   3. 发正式请求前必须先上报「设备指纹 + 生命周期」两条预请求。
//! ```
//! ── 响应为什么在 native 里走 `UpstreamKind::Ndjson` 而不是会话式转发 ──
//! 第 2 条只需在「上游响应协议」上选一个变体，由网关的翻译层把 NDJSON 折成
//! 标准 chat SSE —— 账号轮换、限额冷却、退避重试、usage 与取消处理全部留在
//! 网关编排层。若改走 `conversation`，那五样都要在插件里重写一遍，且本家
//! 并没有多步会话协议，没有理由付那份代价。**本家 `stateful` 恒 false。**
//!
//! 迁移到 wasm 之后「翻译层」这一侧变了：`plugin_host/rpc.rs` 的
//! `build_chat_request_async` 对任何 wasm 包直接 501，对话只能走 `conversation`，
//! 而 wasm 侧**没有**翻译层 —— 于是 `ndjson.rs` 把这台状态机原样搬进了插件。
//! 编排层那五样仍然留在网关（插件只推标准 chat SSE 帧）。
//!
//! ── 本家没有的东西（如实声明，别照抄别家）──────────────────────
//!   - **没有续期**：单个静态 API Key，上游没有 refresh 接口 → `refresh = false`；
//!   - **没有网页登录**：粘贴式凭证，不开窗口（`web_login` 默认 false）；
//!   - **不做签到**：没有可自动领的奖励活动（`checkin = false`）；
//!   - **不做余额查询**：`/alpha/billing/*` 只在添加账号时用来探活
//!     （`usage = false`）。
//!
//! ── 只改协议层、不动能力位 ──────────────────────────────────
//! `capabilities` / `login_methods` / `default_models` / `account_features` 与
//! native `meta()` 逐字段一致，已按装包期硬校验修正过（见下），本次迁移没有
//! 改动其中任何一位。
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
//! `stream_bytes` 回传 SSE。`chat` 写了也不会被调用。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`。
//!
//! 本包**不实现**的方法（走 `_ => Err(Error::unsupported())`）：
//!   - `chat`：wasm 上恒 501，写了也不会被调用（见上）；
//!   - `usage.query` / `checkin.claim` / `claim` / `claim.status`：
//!     本家 `usage` / `checkin` / `claims` 三个能力位都是 false；
//!   - `login.start` / `login.poll` / `login.callback`：`web_login = false`，
//!     添加账号走粘贴式 `account.normalize`；
//!   - `images.generate` / `images.edit` / `images.capabilities`：本家没有图片
//!     生成能力（`metadata.json` 不申报）；
//!   - `admin.action`：只有 `auth.methods` 一条（添加账号面板的登录方式
//!     清单，见 `login_methods`）；`quota.sources` 之类本家没有。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本包零 unwrap/expect/panic。

mod account;
mod chat;
mod credentials;
mod endpoints;
mod errors;
mod fingerprint;
mod models;
mod ndjson;
mod plan;
mod sha1;
mod util;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 为什么必须申报（哪怕只有一条）──────────────────────────
/// 网关对 wasm 包恒走动态通道（`api/session.rs` 的 `dynamic_login()` 恒为真），
/// 插件不给这份清单就回 501「插件不支持此操作」，**添加账号面板整个打不开**；
/// 网关也不会回退到 `metadata.json` 的 `login_methods`。
///
/// ── 本家只有「粘贴 API Key」这一条 ──────────────────────────
/// `metadata.json` 的 `login_methods` 只有 `kind: "token"`（`web_login = false`，
/// 没有网页登录），所以这里只输出 0 号 api 方式，没有 oauth 分支。
///
/// 字段名用 `token`：`account.normalize` 的 manual 分支按
/// `apiKey / accessToken / token / key` 依次取（面板提交的 `inputs` 被网关原样
/// 透传进去），`token` 能直接命中那个列表。
fn login_methods() -> Value {
    json!({ "methods": [{
        "methodIndex": 0, "type": "api", "label": "API Key", "prompts": [{
            "key": "token", "type": "text", "label": "API Key",
            "placeholder": "粘贴 user_ 开头的 API Key", "secret": true
        }],
        "instructions": "粘贴 user_ 开头的 API Key"
    }] })
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 数据面 ────────────────────────────────────────────
        // 只挂 `conversation`：`chat` 在 wasm 上恒 501（网关
        // `build_chat_request_async` 直接拒），挂上去也永远不会被调用。
        // 插件自己发上游请求，把 NDJSON 折成 chat SSE 后用
        // stream_head / stream_bytes 回给宿主。
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 凭证 ──────────────────────────────────────────────
        // 静态 key：`ensure` = 读记录 + 形态检查 + 指纹 best-effort；
        // `refresh` 恒 401 可读文案（上游没有续期接口）；`expiring` 恒 false。
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => account::refresh(),
        "token.expiring" => Ok(json!(account::expiring())),

        // ── 目录 ──────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => Ok(models::refresh(params["force"].as_bool().unwrap_or(false))),

        // ── 账号 ──────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => account::identity(&params["secret"]).map(Value::String),

        // ── 管理动作 ──────────────────────────────────────────
        // 只有一条：添加账号面板要的登录方式清单（见 `login_methods`）。
        // 其余动作本家没有，落到最后的 `_` 分支如实报不支持。
        "admin.action" if params["action"] == "auth.methods" => Ok(login_methods()),

        // ── 分类与策略 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // 本家 HTTP 恒 200（错误在流内），且正常流也可能标 application/json ——
        // 这一位恒 false，与 native 的默认实现一致（理由见 `errors.rs` 模块头）。
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["headers"],
        ))),
        // native 没有覆写 `error_policy`：返回 null = 交给网关的默认处置。
        "error.policy" => Ok(Value::Null),
        // native 没有覆写 `retry_advice`：null = 不退避，网关走通用规则。
        "retry_advice" => Ok(Value::Null),
        // native 的默认 `retry_decision` 是 Default（不特判）。
        "retry.decision" => Ok(json!({ "action": "default" })),
        // native 没有覆写 `cooldown_models`（默认只冷却请求的那个模型）。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // native 的默认 `reasoning_patch` 是 Skip：不往 body 里注入任何东西。
        // 本家的思考强度由客户端自己在 `reasoning_effort` 里给（`plan.rs` 原样透传）。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "Command Code 的思考强度由请求体 reasoning_effort 原样透传，插件不注入档位",
        })),

        _ => Err(Error::unsupported()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 网关对 wasm 包只认动态登录方式：清单为空或形状不对 = 添加账号面板
    /// 整块空白。本家只有一条 api 方式，字段名必须能被 `account.normalize` 认出来。
    #[test]
    fn auth_methods_declare_one_api_method() {
        let value = login_methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, list.len());
        assert_eq!(0, list[0]["methodIndex"].as_u64().unwrap_or(u64::MAX));
        assert_eq!("api", list[0]["type"].as_str().unwrap_or(""));
        assert!(!list[0]["label"].as_str().unwrap_or("").trim().is_empty());
        let prompts = list[0]["prompts"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, prompts.len());
        assert_eq!("token", prompts[0]["key"].as_str().unwrap_or(""));
        assert_eq!("text", prompts[0]["type"].as_str().unwrap_or(""));
        assert_eq!(true, prompts[0]["secret"].as_bool().unwrap_or(false));
        assert!(!prompts[0]["placeholder"].as_str().unwrap_or("").trim().is_empty());
    }

    /// `auth.methods` 必须能从 `handle` 走到（网关的调用形状是
    /// `admin.action` + `action` 参数）。
    #[test]
    fn handle_serves_auth_methods() {
        let value = handle("admin.action", json!({ "action": "auth.methods" })).unwrap_or(Value::Null);
        assert!(value["methods"].is_array());
        // 其余管理动作仍如实报不支持（501），不假装成功。
        assert!(handle("admin.action", json!({ "action": "quota.sources" })).is_err());
    }
}
