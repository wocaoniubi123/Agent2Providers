//! KukuAI 库库 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/kuku/`（native）。
//!
//! ── 模块分工（一眼看清谁管什么）────────────────────────────
//! ```text
//!   account   凭证解析（Cookie 头 / 数组 / 对象）、三条添加路径、账号面、真实校验
//!   engine    passport 换发 genflowpro 作用域 STOKEN（纯算法 MD5 签名）
//!   md5       纯算法 MD5（RFC 1321，只为上面的签名服务）
//!   session   会话三件套（bdstoken / uinfo / uk）缓存与 -6 自愈
//!   upstream  出站常量 / 头集合 / JSON·表单·SSE 三种请求
//!   chat      对话三步时序 + 上游 SSE → OpenAI chat SSE 翻译
//!   models    静态兜底清单 + 远程目录刷新
//!   usage     余额 / 积分读数
//!   checkin   30 天签到（主链路）+ 旧 freepoint 任务（兜底）
//!   login     回调型网页登录（主站窗口 + 壳侧交回完整 Cookie）
//!   errors    状态码分类与错误事件
//! ```
//!
//! ── 本包只声明一个 provider ────────────────────────────────
//! 网关 `provenance.rs` 的 `wasm_provider()` 要求 `providers.len() == 1`，
//! `pack.json` 里多一个 id 就会让整个包不启动。kuku 在 native 侧就是单 id，
//! 这里不做别名、不做代理。
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
mod chat;
mod checkin;
mod engine;
mod errors;
mod login;
mod md5;
mod models;
mod session;
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
        "account.view" => Ok(account::account_view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity_of(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // 返回的是 BDUSS：宿主拿它判断「这个账号此刻有没有凭据」，真正出站的
        // Cookie 头（含 STOKEN / extras / gfprotpl）由插件自己拼。
        "token.ensure" => Ok(json!(account::current_token()?)),
        // 本家没有刷新接口（`refresh: false`）：这条只是把「当前凭据」再读一遍，
        // 不会去上游换任何东西 —— 凭据失效只能重新登录 / 重新导入。
        "token.refresh" => Ok(json!(account::current_token()?)),
        // BDUSS 是登录态 Cookie，读不到到期时刻 —— 恒判「不临期」，
        // 让后台维护任务不必每一轮为它白打一次 userreport。
        "token.expiring" => Ok(json!(account::expiring(&params["secret"]))),

        // ── 目录 / 额度 / 签到 ──────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),

        // ── 对话 ────────────────────────────────────────────
        // wasm 包的对话只能走会话式通道（网关对 wasm 的 `chat` 直接回 501）。
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        // 上游是「建会话 → 分配算力 → SSE」三步时序，没有可交给主程序代发的
        // 单次请求；这条如实报不支持，而不是伪装成「已构造」。
        "chat" => Err(Error::unsupported()),

        // ── 登录（回调型）───────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),
        "login.callback" => login::callback(&params),

        // ── 管理动作 ────────────────────────────────────────
        // 添加账号面板的登录方式清单：网关对 wasm 包恒问这条动态通道，
        // 缺了它面板直接打不开（见 `login::methods` 的注释）。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods()),

        // 本家没有独立的额度来源声明：转发用的三个 Cookie 就是查余额的凭证，
        // `usage.query` 已经把读数给全（与 atomcode 同口径）。
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // native 没有实现「内容拦截判定」，本家也没有拒绝话术白名单
        // （`metadata.refusal_markers` / `refusal_finishes` 都为空）：只按状态码判。
        "is_error_response" => Ok(json!(params["status"].as_u64().unwrap_or(0) >= 400)),
        // 本家的失败几乎都是凭证 / 风控 / 上游业务码：换账号有意义，因此不停手。
        "error.policy" => Ok(json!({ "stop": false })),
        "retry.decision" => Ok(json!({ "action": "default" })),
        // 没有跨家重试建议：时序级容错已在 `chat` 内部做完（分配算力 / 切会话）。
        "retry_advice" => Ok(Value::Null),
        // 冷却标记在 native 里由编排层落账号库；这里没有按模型的冷却清单。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 上游 `think_mode` 的档位语义没有实测证据，按「没有证据就不注入」保持
        // 默认（请求体里恒用 `DEFAULT_THINK_MODE`）。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "本家不接思考档位绑定：上游 think_mode 档位语义无实测证据，请求体恒用默认档",
        })),
        // 上游没有图片生成 / 改图能力（对话链路只回文本）。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        _ => Err(Error::unsupported()),
    }
}
