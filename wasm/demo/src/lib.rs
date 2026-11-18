//! 示例提供商 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/demo/`（native）。
//!
//! ── 模块分工 ────────────────────────────────────────────────
//! ```text
//!   upstream      假上游地址三来源（请求头 → 设置项 → 回环 18080）/ 头 / 一次 POST
//!   account       凭证读取与条件回写 / 规范化 / 公开视图 / 身份
//!   chat          conversation（真正生效）+ chat（死路径的请求计划对照）
//!   models        内置目录 / 手动刷新（remote 快照）/ 自动路径跳过
//!   errors        四档错误分类 / 退避建议
//!   usage         余额读数
//!   plans         签到
//!   login         设备授权型 + 回调型两种登录流程
//! ```
//!
//! ── 这一家在验证链条里为什么特殊 ────────────────────────────
//! 它是**唯一一个真的会跑「假上游」的包**：别的包都在对接真上游，只有它
//! 指着一个本地假上游（native 的 `127.0.0.1:18080`）。但 wasm 沙箱的
//! `check_url` 只放行 https + 精确 origin（`wasm/manifest.rs:277-288`），
//! 所以默认配置下 `conversation` 会在发请求前停下并说清原因 —— 判据、
//! 文案与「换成 https 上游后照常转发」的那条分支都在 `chat.rs`。
//!
//! ── 写新 provider 时怎么用这个文件（native 模块头的四条，原样带过来）──
//! 抄结构，不要抄逻辑。要点：
//!   1. `meta()` 申报能力位 —— **默认值不是结论**，能做的才填 true；
//!   2. 只实现你真正支持的方法，其余保持默认（默认会返回「不支持」）；
//!   3. 所有出网都走 `reqwest::Client`，代理用 `req.proxy`；
//!   4. 错误返回 `Err(String)`，不要 panic（crate 已 deny unwrap/expect）。
//!
//! 第 3、4 条在 wasm 侧的等价物：
//!   * 出网走 `sdk::http::open`（代理由宿主按账号选，插件这一层拿不到也
//!     不需要 `req.proxy`）；
//!   * 错误返回 `Error`（`message` / `code` / `status`），并且**零** unwrap /
//!     expect / panic —— release 是 `panic = "abort"`，一次 panic 会带走
//!     整个插件实例。
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
//! ── 与 native 的方法面差异（逐条都有理由）────────────────────
//! | 方法 | native | 这里 | 为什么 |
//! |---|---|---|---|
//! | `account.view` | trait 默认 | 实现 | 宿主 `ACCOUNT_VIEW` 只给 `secret`，界面刷新要一份公开视图 |
//! | `login.callback` | 未实现 | 实现 | 示例的「回调型」分支只摆了开场；两端闭合才叫两种流程 |
//! | `token.refresh` | 未实现 | 返回 `unsupported` | 示例没有续期接口；501 让网关按「这家没有强制刷新」处置 |
//! | `retry.decision` | 无此方法 | **不实现** | 网关只在收到 501 时才回退到 `retry_advice`；实现了就等于把 native 的退避建议关掉 |
//! | `error.policy` / `is_error_response` | 无 | 不实现 | native 的示例没写，网关对这些走默认（`is_error_response` 按状态码判） |
//! | `cooldown_models` | 无 | 回空表 | 网关对本家没有这条调用点，回空表只为对齐协议方法名 |
//! | `refusal_markers` | 有（返回两个数组） | 写进 `metadata.json` | 网关从**握手**读这两组标记（`rpc.rs:462-467`），运行期不再问 |
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 全部文件零 unwrap / expect / panic（`metadata()` 的 `unwrap_or` 是兜底
//! 而不是解包：编译期常量坏了也不该带走整个实例）。

mod account;
mod chat;
mod errors;
mod login;
mod models;
mod plans;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

/// 参数里的状态码（缺字段或越界时用兜底；不 panic）。
fn status_of(params: &Value, fallback: u16) -> u16 {
    params["status"]
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(fallback)
}

/// `reasoning_patch`：native 的三条分支，原样搬过来。
///
/// 返回形状是协议里的 `ReasoningPatch`（`#[serde(tag = "action")]`）：
/// `set` 让网关把 body 顶层的 `field` 设成 `value`；`skip` 时 body 一个字节
/// 都不动，`reason` 只进详细日志 —— 所以「为什么没注入」必须写得能读懂。
fn reasoning_patch(params: &Value) -> Value {
    let level = params["level"].as_str().unwrap_or("").trim();
    match level {
        "low" | "medium" | "high" => json!({
            "action": "set",
            "field": "reasoning_effort",
            "value": level,
        }),
        "" => json!({
            "action": "skip",
            "reason": "请求没有绑定思考档位",
        }),
        other => json!({
            "action": "skip",
            "reason": format!("示例 provider 只认 low/medium/high，收到 {other}"),
        }),
    }
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号面 ──────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 令牌 ────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::ensure()?)),
        // 示例没有续期接口：501 让网关按「这家没有强制刷新」处置
        // （native 的 trait 默认实现同样是「留空」）。
        "token.refresh" => Err(Error::unsupported()),
        "token.expiring" => Ok(json!(account::expiring(&params))),

        // ── 目录 / 余额 / 签到 ──────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => Ok(models::refresh(
            params["force"].as_bool().unwrap_or(false),
        )),
        "usage.query" => Ok(usage::query(&params["account"])),
        "checkin.claim" => Ok(plans::claim()),

        // ── 对话 ────────────────────────────────────────────
        // 唯一真正生效的发送入口（见文件头「对话只能走 conversation」）。
        "conversation" => {
            chat::conversation(&params)?;
            Ok(Value::Null)
        }
        // `chat` 是死路径：网关对 wasm 包直接 501，走不到这里。
        // 保留它只为对照 native `build_chat` 的「请求计划」形状。
        "chat" => chat::chat_plan(&params),

        // ── 登录（两种流程）──────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(errors::classify(status_of(&params, 502), &params["body"])),
        "retry_advice" => Ok(errors::retry_advice(
            &params["body"],
            params["attempt"].as_u64().unwrap_or(0) as usize,
            params["budget"].as_u64().unwrap_or(1) as usize,
        )),
        "reasoning_patch" => Ok(reasoning_patch(&params)),

        // 网关对本家不调这条（`rpc.rs` 里没有 `COOLDOWN_MODELS` 的调用点），
        // 但协议里有这个名字：回一张空表比回 501 更省一次日志噪音。
        "cooldown_models" => Ok(json!({ "models": [] })),

        _ => Err(Error::unsupported()),
    }
}
