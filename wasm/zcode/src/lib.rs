//! ZCode 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/zcode/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//! ```text
//!   region.rs         国内版常量（zcode 平面 / 推理平面 / 监控平面 / 业务域）
//!   hostenv.rs        宿主平台与架构（runtime.platform / runtime.architecture）
//!   common.rs         取值原语、随机源、UUID、时间（全部走宿主能力）
//!   http.rs           出站请求统一入口（读完整回应 + 保留错误体）
//!   account.rs        凭证形态 / 公开视图 / 去重身份 / 取令牌 / 设备标识
//!   models.rs         静态模型表（本家没有远程目录）
//!   errors.rs         上游错误四档分类与重试判据
//!   reasoning.rs      GLM 家族的思考档位契约（两条通道各一套装配）
//!   anthropic.rs      Anthropic Messages ↔ Chat 的双向转换（本家非标准协议那段）
//!   system_prompt.rs  套餐池三段提示词 + 缓存断点 + 上下文前缀
//!   request_context.rs 套餐池请求的会话归因
//!   captcha.rs        人机验证令牌池（放 session，见该文件模块头）
//!   plan.rs           两条通道的请求装配 + 客户端身份头
//!   chat.rs           对话转发（conversation 流式 / chat 计划）
//!   usage.rs          余额读数（billing 桶 + 监控窗口的候选链）
//!   claim.rs          限时套餐探测 / 领取 / 营销回执 / 激活事件
//!   checkin.rs        每日签到（= 领当天那份赠送套餐）
//!   login.rs          网页登录（服务端中介的 CLI 轮询）
//!   coding_key.rs     登录链的凭证换取（OAuth 令牌 → 编码套餐 API Key）
//!   admin.rs          管理动作（登录方式 / 验证码池 / 提示词 / 领取）
//! ```
//!
//! 本包只做**国内版**（provider id `zcode`）：`region.rs` 里是全套国内常量，
//! 国际版（`zcode-intl`）由 `wasm/zcode-intl/` 那个孪生包负责，两边不共享
//! 源码 —— 两地差异（域名 / OAuth 命名空间 / 中转页参数名 / 业务域凭证形态 /
//! `{provider}` 模板值 / 账号 id 前缀）都各自在自己的文件里，不靠运行时判地区。
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
//! `meta()` → `metadata()`（`metadata.json` 承担）；`build_chat()` → `chat` /
//! `conversation`；`ensure_token()` → `token.ensure`；`refresh_token()` →
//! `token.refresh`；`expiring()` → `token.expiring`；`classify()` → `classify`；
//! `is_error_response()` → `is_error_response`；`retry_decision()` →
//! `retry.decision`；`reasoning_patch()` → `reasoning_patch`；`models()` →
//! `models.list`；`usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `claim()` / `claim_status()` → `claim` / `claim.status`；`normalize_account()` →
//! `account.normalize`；`account_view()` → `account.view`；`account_identity()` →
//! `account.identity`；`login_*` → `login.start` / `login.poll` / `login.cancel`；
//! `admin_action()` → `admin.action`。
//!
//! ── 本家没有的东西（不是漏实现）─────────────────────────────
//!   - `token.refresh`：上游没有续期协议，被拒只能重新登录（如实报错）；
//!   - `token.expiring`：恒 false（没有可信的到期判据，声称临期会每轮白刷）；
//!   - `models.refresh`：静态模型表，没有远程目录可刷；
//!   - `retry_advice` / `cooldown_models` / `refusal_markers`：native 侧也为空；
//!   - 图片生成 / 编辑：本家没有这条通道，不申报 `images.v1`。

mod account;
mod admin;
mod anthropic;
mod captcha;
mod chat;
mod checkin;
mod claim;
mod coding_key;
mod common;
mod errors;
mod hostenv;
mod http;
mod login;
mod models;
mod plan;
mod reasoning;
mod region;
mod request_context;
mod system_prompt;
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

        // ── 账号面 ────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),
        // 取可用令牌：只读账号里的凭证，**不续期**（上游没有续期协议）
        "token.ensure" => Ok(json!(account::ensure_token()?)),
        "token.refresh" => Ok(json!(account::refresh_token()?)),
        // 恒 false：本家没有可预测的到期时刻（声称临期会每轮白刷一次）
        "token.expiring" => Ok(json!(account::expiring())),

        // ── 目录（静态表，没有远程目录）───────────────────────
        "models.list" => Ok(models::list()),
        // `model_refresh: false`：这家**没有**远程目录，如实回答而不是假装刷了一次
        "models.refresh" => Ok(json!({
            "refreshed": false,
            "count": 0,
            "message": "该提供商使用内置模型清单，没有远程目录可刷新",
        })),

        // ── 数据面 ────────────────────────────────────────────
        // `chat` 交出「要发出去的请求」（native `build_chat` 的直译）
        "chat" => chat::plan_request(&params),
        // 真正跑在网关上的那条：插件自己发请求、自己折协议、自己吐 chat SSE
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 余额 / 签到 / 领取 ────────────────────────────────
        "usage.query" => usage::query(),
        "checkin.claim" => Ok(checkin::report(&checkin::claim_daily()?)),
        // 领取一个套餐（`claim` 参数是套餐 id；空串 = 领第一个可领的）
        "claim" => {
            let payload = json!({ "planId": params["claim"].clone() });
            admin::action(&json!({ "action": "claim.claim", "payload": payload }))
        }
        // 领取类活动的只读状态（界面点开活动福利卡时看到的清单）
        "claim.status" => admin::action(&json!({ "action": "claim.preview" })),

        // ── 登录（服务端中介的 CLI 轮询）──────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作 ──────────────────────────────────────────
        "admin.action" => admin::action(&params),

        // ── 错误分类与重试 ────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["headers"],
        ))),
        // 风控拒绝（3012）要叫停重试；其余走网关默认策略
        "error.policy" => Ok(errors::error_policy(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "retry.decision" => Ok(errors::retry_decision(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // native 侧未实现退避建议（恒 null）
        "retry_advice" => Ok(Value::Null),
        // 本家的限额不分模型组（一个账号一条通道），不需要连带冷却
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 本家没有流内拒绝标记（metadata 的 refusal_markers 为空）
        "refusal_markers" => Ok(json!({ "finishes": [], "markers": [] })),
        "reasoning_patch" => Ok(reasoning::patch(&params)),

        // ── 图片 ──────────────────────────────────────────────
        // 本家没有图片生成 / 编辑通道（不申报 `images.v1`）
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}
