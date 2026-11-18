//! MonkeyCode 国际版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/monkeycode/`（native）。
//!
//! ── 当前阶段 ────────────────────────────────────────────────
//! 已完整迁移：账号面 / 登录 / 目录 / 会话转发（建任务 + 任务流 + ACP 翻译）
//! 全部就位，未实现的方法统一 `Err(Error::unsupported())`。
//!
//! ── 本包只声明一个 provider ────────────────────────────────
//! 网关 `plugin_host/packages/provenance.rs` 的 `wasm_provider()` 要求
//! `providers.len() == 1`，所以 native 那个「一份实现、两个实例」的
//! `Region` 拆法在这里行不通：本包只有 `monkeycode-intl`（国际站
//! `monkeycode-ai.net`），国内站 `monkeycode` 由另一个包负责。
//!
//! 本包取的是 native `Region::Intl` 那一列：站点 `https://monkeycode-ai.net`、
//! 地区短标识 `intl`、展示名「国际版」、登录窗口域三条（站点 + GitHub + Google）。
//! **cookie 名（`monkeycode_ai_session`）与 `host_id`（`public_host`）与国内版
//! 逐字相同** —— native `endpoints.rs` 的这两项是全局常量，没有地区分叉。
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   region         国际版站点身份（域名 / provider id / 登录窗口域）
//!   endpoints      路径 / cookie 名 / 请求头 / URL 拼装
//!   credentials    凭证快照（session + image_id + 过期时刻）
//!   client         出站薄封装（业务码 / 停任务 / 运行中任务列表）
//!   errors         错误四档分类 + 两条码表
//!   login          粘贴 session 的归一化与校验（含 image_id 自动发现）
//!   accounts       账号归一化 / 公开视图 / 稳定身份
//!   web_login      网页登录（内嵌窗口 → 宿主交回 cookie → 复核）
//!   models         模型目录（映射 / 会话缓存 / 模型名 → 上游 UUID）
//!   task           输入侧翻译与建任务（含 10811 自愈）
//!   startup        等任务环境就绪
//!   wire           任务流帧的 base64(JSON) 编解码
//!   base64         自实现的 base64（沙箱里没有 base64 crate）
//!   translate      ACP 事件 → OpenAI 帧的纯状态机
//!   stream         WebSocket 连接 / auto-approve / 驱动 / 收尾停止任务
//!   inflight       在途任务表（10811 自愈时跳过并发请求正在用的任务）
//!   conversation   装配层（⑦ 步全在这里串起来）
//!   logging        日志占位与短标识
//! ```
//!
//! ── 专用宿主通道 `http.managed-task.v1` / `crypto.monkeycode-cap.v1`：都没申报 ──
//! 前者是网关为 MonkeyCode 准备的「固定受控任务」内部模块，模块头自己写着
//! 「服务实现未接准入/ABI，不是已开放的插件能力」；后者是**签到**（`checkin`）
//! 用的官方计算验证（宿主侧做题，`checkin_call` 上下文里的专用入口）。本家
//! `checkin: false`（没有签到接口），因此两条都不申报 —— 申报 `crypto.monkeycode-cap.v1`
//! 还会连带要求 `http.timeout.v1`，那是纯多余的授权。
//!
//! 任务流走的是通用的 `websocket.v1`（与国内版同一个能力），`wasm.json` 的
//! `requires` 必须带上它，否则建完任务就连不上流。
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

mod accounts;
mod base64;
mod client;
mod conversation;
mod credentials;
mod endpoints;
mod errors;
mod inflight;
mod logging;
mod login;
mod models;
mod region;
mod startup;
mod stream;
mod task;
mod translate;
mod web_login;
mod wire;

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

        // ── 账号 ────────────────────────────────────────────
        "account.normalize" => accounts::normalize(&params),
        "account.view" => Ok(accounts::account_view(&params["secret"])),
        "account.identity" => Ok(json!(accounts::identity_of(&params["secret"]))),

        // ── 令牌（本家没有续期机制，见 `credentials.rs` 模块头）─────
        // `token.ensure` 只做「记录里有没有 session」的检查：session 30 天硬限制、
        // 上游无 refresh 接口，过期只能重新粘贴。
        "token.ensure" => Ok(json!(credentials::current()?.session)),
        // ── 临期判定 ──
        // 宿主 `credentials_expiring_async` 只带 `account`（不带 `secret`，见
        // `rpc.rs:743` 的 `with_account`），所以这里要在 `secret` 缺失时回落到
        // `sdk::account()` 读同一条记录 —— 只看 `params["secret"]` 会永远回 false，
        // 「凭证临期」也就永远不会被提示。
        "token.expiring" => {
            let secret = &params["secret"];
            let credentials = if secret.is_object() {
                credentials::from_secret(secret)
            } else {
                credentials::current()
            };
            Ok(json!(credentials
                .map(|credentials| credentials.expiring())
                .unwrap_or(false)))
        }
        // `token.refresh` 不存在：`capabilities.refresh = false`，网关不会问；
        // 真问到了就走 `_` 的 unsupported（本家没有这条协议，别假装有）。

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh(
            params["force"].as_bool().unwrap_or(false),
            params["account"].as_str().unwrap_or(""),
        ),

        // ── 对话（只有这一条路径，`chat` 是死路径）──────────────
        "conversation" => {
            conversation::run(&params)?;
            Ok(Value::Null)
        }

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
        ))),
        "error.policy" => Ok(errors::policy(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),

        // ── 登录（网页登录 + 粘贴 session，见 `web_login.rs`）─────
        "login.start" => web_login::start(&params),
        "login.poll" => web_login::poll(&params),
        "login.cancel" => web_login::cancel(&params),
        "login.callback" => web_login::callback(&params),

        // 平台问「登录方式」时回**动态契约**的那份（见 `web_login::methods`：
        // `metadata.json` 里的静态 `login_methods` 形态在新契约下会被判 502）
        "admin.action" if params["action"] == "auth.methods" => Ok(web_login::methods()),
        // 本家没有余额 / 积分 / 套餐任何一个可查的额度来源（`usage: false`）
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // ── 平台通用钩子 ────────────────────────────────────
        // 本家没有跨家重试建议：错误处置由 `classify` 与编排层决定
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        // 上游不给结构化冷却时间（429 无 reset_at），没有按模型的冷却清单
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 建任务接口不接收思考档位（`task.rs` 的请求体里没有这个字段），
        // 注入到 body 也不会被上游读到 —— 明确跳过，不制造「显示改了、实际没变」。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "MonkeyCode 建任务接口没有思考档位字段，按原样透传",
        })),
        // 本家不出图也不改图
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}
