//! 豆包工作 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/doubaowork/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//! ```text
//!   account    Cookie 集合规范化、账号导入归一化、公开视图、身份
//!   api        上游地址 / 查询串 / 请求头 / 错误分类（provider_http 元数据）
//!   catalog    目录拉取（launch + brief_list）、台账缓存、按名字解析、任务模型
//!   prompt     消息校验、工具桥、/chat/completion 信封
//!   stream     上游 SSE 方言与内容块（含 10010 / 10084 两种图片块）
//!   chat       会话式对话转发（首包门 + 工具调用整轮读）
//!   images     生图（images.generate）：对话里派任务 → 取图 → 资源
//!   upload     对话图片输入：data URL → 资源 → 宿主固定上传入口
//!   usage      额度 / 余额（两个控制面接口）
//!   checkin    每日签到（提交与回查由宿主固定入口完成）
//!   rewards    任务领奖（claim.doubao.tasks 固定入口）
//!   login      网页登录（回调型）
//!   errors     四档分类、响应判定、思考档位
//!   codec      base64 解码与十六进制
//!   random     随机源（宿主 random.bytes）
//! ```
//!
//! ── 本包声明的两条 provider 专属能力 ────────────────────────
//!   · `http.doubao-turn.v1`：`POST /chat/completion` 与 `/chat/async/chunk_stream`
//!     必须走宿主 `doubao_turn`（凭证逐项核对、设备号核对、轮次回执、停止任务）；
//!   · `claim.doubao-tasks.v1`：任务领奖只能由宿主 `doubao_rewards` 执行，
//!     插件在 `claim` / `claim.status` 上下文里调 `claim.doubao.tasks`。
//! 两条都只授权给 `doubaowork`（网关 `wasm/manifest.rs` 硬校验）。
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

mod account;
mod api;
mod catalog;
mod chat;
mod checkin;
mod codec;
mod errors;
mod images;
mod login;
mod prompt;
mod random;
mod rewards;
mod stream;
mod upload;
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
        "account.view" => account::view(&params["secret"]),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // 本家只有 Cookie、没有续期接口（native 模块头写死）：`token.ensure`
        // 交出的就是可直接用的 Cookie 头；`token.refresh` 因此没有实现，
        // 拿到 501 是如实回答。`token.expiring` 恒 false：Cookie 的过期时间
        // 由浏览器域管着，插件读不到，也不该凭空猜「临期」。
        "token.ensure" => {
            let secret = account::current_secret()?;
            Ok(json!(account::cookie_header(&secret)?))
        }
        "token.expiring" => Ok(json!(false)),

        // ── 目录 / 额度 / 签到 / 领奖 ────────────────────────
        "models.list" => catalog::list(),
        "models.refresh" => {
            let secret = account::current_secret()?;
            let credentials = account::credential(&secret)?;
            catalog::refresh(&credentials, params["force"].as_bool().unwrap_or(false))
        }
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),
        "claim.status" => rewards::status(),
        "claim" => rewards::claim(),

        // ── 对话 / 生图 ─────────────────────────────────────
        // 对话只能走会话式通道（见 `chat` 模块头）；`chat` 写了也不会被调用，
        // 这里如实报不支持。
        "conversation" => {
            chat::run(&params)?;
            Ok(Value::Null)
        }
        "chat" => Err(Error::unsupported()),
        // 唯一被允许调用图片方法的包（网关 `wasm/runtime.rs` 硬校验）。
        "images.generate" => images::generate(&params),
        "images.edit" => Err(Error::coded(
            "豆包工作生图不支持参考图",
            "unsupported",
        )),
        "images.capabilities" => Ok(json!({
            // 网关 `RpcAdapter::load_capabilities` 只认 `generation` / `editing`
            // 两个键：少了 `generation=true`，生图请求根本不会派到本包。
            "generation": true,
            "editing": false,
        })),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(&params))),
        "error.policy" => Ok(errors::policy(&params)),
        "reasoning_patch" => Ok(errors::reasoning_patch(
            params["level"].as_str().unwrap_or(""),
            &params["body"],
        )),
        "retry_advice" => Ok(Value::Null),
        "cooldown_models" => Ok(errors::cooldown_models()),

        // 添加账号面板的登录方式清单：网关对 wasm 包恒问这条动态通道，
        // 缺了它面板直接打不开（见 `login::methods` 的注释）。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods()),

        // 本家没有「额度来源」之外的只读面板；`quota.sources` 已在
        // `usage.query` 的 `quotaSources` 里给全，这里回空表。
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        _ => Err(Error::unsupported()),
    }
}
