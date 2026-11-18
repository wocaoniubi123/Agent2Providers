//! Qoder 国际版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/qoder/`（native，21 个文件）。
//! 本包只申报 `qoder-intl` 一个 provider id（网关硬性要求 wasm 包的
//! `providers.len() == 1`）；native 目录里同时导出的 `qoder` / `qwenwork` /
//! `qwenwork-intl` 不在本包范围内。
//!
//! ── 本包相对 `wasm/qoder`（中国版）多出来的东西 ────────────────
//!   1. **推理基址按令牌前缀分派**（`site::inference_base`）：作业令牌 `jt-`
//!      打 `api2.qoder.sh`，设备流令牌打 `api3.qoder.sh`（native
//!      `Site::inference_base` 的国际版分支）；
//!   2. **签到的设备风控身份**（`risk.rs`）：国际版只对带 `Cosy-Machine*`
//!      风控头的请求下发「每日 100 Credits」。那一组头要 Qoder 的 UMID 组件
//!      在本机生成 —— wasm 起不了子进程，改走**网关宿主通道**
//!      `native.helpers.v1` 的 `desktop.qoder-umid.v1`（网关
//!      `plugin_host/wasm/qoder_umid/` 已实现，只对 `qoder-intl` 生效）。
//!      `admin.action` 的 `risk.status` / `risk.install` 也原样转给宿主。
//!   3. 签到多一条「每日窗口 10:00 开启」的判断与两段拉取（`checkin.rs`）。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `chat` / `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`；`account_view()` → `account.view`；
//! `account_identity()` → `account.identity`；`login.*` → `login.*`；
//! `admin.action` → `admin.action`；`claim_status()` / `claim()` →
//! `claim.status` / `claim`。
//!
//! ── 子模块 ─────────────────────────────────────────────────
//!   site.rs        站点常量（单站点裁剪版 endpoints，含国际版基址分派）
//!   risk.rs        设备风控身份（**走宿主通道**，不是本机子进程）
//!   crypto.rs      纯 Rust 的 base64 / MD5 / AES-128-CBC / RSA / 随机源
//!   cosy.rs        COSY 请求签名 + 请求体编码
//!   machine.rs     设备标识
//!   credentials.rs 凭证格式（兼容 Qoder-Proxy 的 access/refresh）
//!   auth.rs        PAT 换取令牌 / 用户资料 / 通用请求
//!   refresh.rs     续期（账号锁 + 比较再写）
//!   account.rs     账号面（归一化 / 公开视图 / 身份 / ensure）
//!   models.rs      模型目录（静态兜底 + 远程刷新）
//!   protocol.rs    OpenAI ↔ Qoder 协议转换（消息/tools/思考档位/上游信封）
//!   context.rs     上下文档位（200K/400K/1M）
//!   errors.rs      上游错误分类（状态码 + 业务码表 + 排队态判定）
//!   stream.rs      上游 SSE 信封解包 + 思考标签拆解（跨分片）
//!   chat.rs        会话式转发（预读 → 报头 → 翻译 → 收尾）
//!   usage.rs       额度查询
//!   checkin.rs     每日签到（两段拉取 + 每日窗口）
//!   claims.rs      活动福利（清单 + 领取 + 台账）
//!   login.rs       设备授权登录（PKCE 轮询）
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 依赖只有 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`；
//! 零 unwrap/expect/panic（宿主按 abort 处理）。

mod account;
mod auth;
mod chat;
mod checkin;
mod claims;
mod context;
mod cosy;
mod credentials;
mod crypto;
mod errors;
mod login;
mod machine;
mod models;
mod protocol;
mod refresh;
mod risk;
mod site;
mod stream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（`metadata.json` 已按 native 的 `meta()`
/// 产出：capabilities / login_methods / checkin / account_features / default_models）。
const METADATA: &str = include_str!("metadata.json");

/// 解析随包的元数据。解析失败给 `Null`（宿主会把它当成「没有元数据」，
/// 比 abort 好，也不做 unwrap）。
///
/// 解析结果只做一次（`OnceLock`）：`models::fallback()` 会在每次 `models.list`
/// 与模型解析时读 `default_models`，重复解析一份 8 KiB 的 JSON 是白花的开销。
pub(crate) fn metadata() -> Value {
    static PARSED: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    PARSED
        .get_or_init(|| serde_json::from_str(METADATA).unwrap_or(Value::Null))
        .clone()
}

/// 通用思考档位表（与网关 `EFFORT_LEVELS` 逐字相同）。
///
/// 只用于 `reasoning_patch` 判「这个值值不值得注入」—— 本家对未知档位不报错
/// （回退到模型默认档），所以注入表外值不会弄坏请求，但也不会生效，日志里却
/// 会出现一行「已注入」。那正是「绑了没生效还查不出」的典型来源。
const EFFORT_LEVELS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max"];

/// 映射上绑的思考等级注入到请求体的哪个键。
///
/// `protocol::resolve_thinking` 认 `reasoning_effort` / `reasoning` / `thinking`
/// 三个键，选 `reasoning_effort` 的理由：它是最标准、客户端最常传的那个，
/// 注入与「客户端已指定」在 body 上同形。
const REASONING_FIELD: &str = "reasoning_effort";

/// 思考等级绑定 → `reasoning_effort`（值**原样**交给本家的归一逻辑）。
///
/// ── 为什么本家不做档位映射 ────────────────────────────────────
/// 「这一家收哪些档位」在 Qoder 是**模型级**知识：上游目录每个模型条目自己
/// 声明 `thinking_config.enabled.efforts`（Qwen3.8 系列是 low / medium /
/// xhigh），`protocol::resolve_thinking` 已经按它归一与回退。在这里再折一层
/// 等于把同一件事做两遍，而且**必然做错**：适配器这一层只看得到模型名字，
/// 拿不到那个模型声明的档位表。
fn reasoning_patch(params: &Value) -> Value {
    let level = params["level"]
        .as_str()
        .or_else(|| params["reasoning"].as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let body = &params["body"];
    if protocol::client_specified_reasoning(body) {
        return json!({
            "action": "skip",
            "reason": "客户端请求体里已指定思考档位，绑定不覆盖",
        });
    }
    if level.is_empty() || !EFFORT_LEVELS.iter().any(|known| known.eq_ignore_ascii_case(&level)) {
        return json!({
            "action": "skip",
            "reason": "该等级不在通用候选表内，本家无法判断上游收不收（档位由各模型自己声明）",
        });
    }
    json!({
        "action": "set",
        "field": REASONING_FIELD,
        "value": level,
    })
}

/// `admin.action`：厂商专属、网关不该认识的动作。
///
/// ── 为什么走这个通道而不加独立方法 ────────────────────────────
/// 组件（`risk.*`）是**机器级**的，既不是某个账号的属性，也不属于任何一次
/// 转发。`admin.action` 正是为这类动作准备的通用通道。
///
/// ── 本包支持哪些 ────────────────────────────────────────────
///   - `auth.methods`：添加账号弹窗里的登录方式（按 locale 选文案）；
///   - `quota.sources`：额度来源申报（本家不上报，回空数组）；
///   - `risk.status` / `risk.install`：**国际版专用**（UMID 设备风控组件）。
///     两个动作都**原样转给网关宿主**（`desktop.qoder-umid.v1`）—— 组件发现、
///     平台判断、npm 下载解包、子进程执行全在宿主那一侧，wasm 沙箱里做不了。
///     宿主返回的形状（`available` / `source` / `installSupported` /
///     `installing`）正是网关 `api::qoder_umid` 与前端读的键名，所以只做窄化、
///     不改名（见 `risk.rs`）。
fn admin(params: &Value) -> Result<Value> {
    match params["action"].as_str().unwrap_or("") {
        "auth.methods" => {
            let locale = params["payload"]["locale"].as_str().unwrap_or("zh-CN");
            let _ = locale;
            Ok(login::methods())
        }
        "quota.sources" => Ok(json!([])),
        "risk.status" => risk::status(),
        "risk.install" => risk::install(),
        other => Err(Error::coded(
            format!(
                "Qoder 国际版 不认识管理动作「{other}」（可用：auth.methods / quota.sources / risk.status / risk.install）"
            ),
            "unsupported",
        )),
    }
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),
        "admin.action" => admin(&params),
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring(&params["secret"]))),
        "models.list" => models::list_response(),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),
        "claim.status" => claims::preview(),
        "claim" => claims::claim(&params),
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => Ok(login::cancel()),
        "login.callback" => login::callback(),
        // 有状态家：`conversation` 是正路；`chat` 走同一段实现（两者的参数形状
        // 只差 `wire_model` / `reasoning` 两个键，本家都不需要）
        "chat" | "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // ── 为什么恒为 false ──────────────────────────────────
        // 这个方法问的是「HTTP 200 但正文其实是失败话术」。Qoder 的业务错误
        // 全在 SSE 信封里（`statusCodeValue`），而这里只看得到状态码与响应头、
        // 拿不到正文 —— 按状态码猜必然误伤（上游成功响应的状态码永远是 200，
        // 失败也一样）。真正的判定在 `classify` 与流内的 `stream::SseEvent::Error`。
        "is_error_response" => Ok(json!(false)),
        // native 没有覆盖 `error_policy` 的默认实现（默认 `Null` = 不附加策略）
        "error.policy" => Ok(Value::Null),
        // native 没有实现 `retry_advice`（排队的退避在 `chat.rs` 内部完成）
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        // native 的 `CooldownModels::default()`：不连带冷却别的模型名
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(reasoning_patch(&params)),
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),
        _ => Err(Error::unsupported()),
    }
}
