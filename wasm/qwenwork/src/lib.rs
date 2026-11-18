//! 千问办公 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/qoder/`（native，21 个文件；该目录
//! 按 `Site` 参数化，同时导出 `qoder` / `qoder-intl` / `qwenwork` /
//! `qwenwork-intl` 四家）。本包只申报 `qwenwork` 一个 provider id（网关硬性要求
//! wasm 包的 `providers.len() == 1`）。
//!
//! ── 为什么从 `wasm/qoder` 复制而不是另写一份 ───────────────────
//! 两家是**同一套协议栈**：同一个聊天路径、同一套 `Bearer COSY.<payload>.<sig>`
//! 信封、同一把服务端 RSA 公钥。差异集中在「客户端身份常量 + 账号接口路径」，
//! 所以这里保留 `wasm/qoder` 的模块划分与全部协议/签名实现，只按 native 的
//! 站点分支改值（每处改动都写了对应的 native 分支）。
//!
//! ── 本包相对 `wasm/qoder` 改了哪些（对应 native 的哪个分支）────
//!   site.rs        主机（`gateway.qwenwork.cn`）、`cosyVersion 1.1.52`、
//!                  `ClientType 6`、`Data-Policy agree`、`session_type qoder_work`、
//!                  `Cosy-Scene/Business-*` 三个头、`client_id` / `redirect_uri`、
//!                  账号上下文与钱包路径、`max_input_tokens 1.02M`
//!   cosy.rs        `Cosy-Clientip` 用机器标识；三个 `Cosy-Business-*` / `Scene` 头
//!   protocol.rs    `model_config` 换成客户端那一份更宽的字段集
//!   models.rs      `qwork` 场景、`enable` 全量保留、可见性一律 shown、
//!                  上下文窗口读 `max_input_tokens` / 1.02M
//!   auth.rs        资料走 `account-context`（拆 `data.user`）、无 PAT 交换
//!   refresh.rs     续期请求体多带 `target: "c"`、只走设备端点
//!   credentials.rs 临期窗口 1 小时
//!   usage.rs       账号上下文 + 三档积分池（`wallets`）
//!   account.rs     身份前缀 `qwenwork-`、默认名按邮箱
//!   login.rs       只有网页登录；授权 URL 带 `client_id` / `redirect_uri`
//!   machine.rs     设备标识种子前缀 `qwenwork-machine`（与 Qoder 分开）
//!   checkin.rs / claims.rs  **不编译**：这家没有 campaign 接口，也没有作业令牌
//!                  （`metadata.json` 的 `capabilities.checkin` / `claims` 是
//!                  false）。两个文件留在目录里只为与 native 对照，不进 `mod`。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `chat` / `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`normalize_account()` → `account.normalize`；
//! `account_view()` → `account.view`；`account_identity()` → `account.identity`；
//! `login.*` → `login.*`；`admin.action` → `admin.action`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 依赖只有 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`；
//! 零 unwrap/expect/panic（宿主按 abort 处理）。

mod account;
mod auth;
mod chat;
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
/// 与模型解析时读 `default_models`，重复解析一份 JSON 是白花的开销。
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
const REASONING_FIELD: &str = "reasoning_effort";

/// 思考等级绑定 → `reasoning_effort`（值**原样**交给本家的归一逻辑）。
///
/// ── 为什么本家不做档位映射 ────────────────────────────────────
/// 「这一家收哪些档位」是**模型级**知识：上游目录每个模型条目自己声明
/// `thinking_config.enabled.efforts`，`protocol::resolve_thinking` 已经按它
/// 归一与回退。在这里再折一层等于把同一件事做两遍，而且**必然做错**：
/// 适配器这一层只看得到模型名字，拿不到那个模型声明的档位表。
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
/// ── 本包支持哪些 ────────────────────────────────────────────
///   - `auth.methods`：添加账号弹窗里的登录方式（**只有网页登录**，这家没有 PAT）；
///   - `quota.sources`：额度来源申报（本家不上报，回空数组）。
///
/// `risk.*`（UMID 设备风控组件）**只有 Qoder 国际版有**：网关侧那条宿主通道
/// （`desktop.qoder-umid.v1`）的 `candidate` 里写着 `provider != "qoder-intl"`
/// 就返回 None，本包申报它连授权都过不去。所以这里如实回一句，而不是假装支持。
fn admin(params: &Value) -> Result<Value> {
    match params["action"].as_str().unwrap_or("") {
        "auth.methods" => Ok(login::methods()),
        "quota.sources" => Ok(json!([])),
        "risk.status" | "risk.install" => Err(Error::coded(
            "千问办公 没有设备风控组件（UMID 只用于 Qoder 国际版的签到链路）",
            "unsupported",
        )),
        other => Err(Error::coded(
            format!(
                "千问办公 不认识管理动作「{other}」（可用：auth.methods / quota.sources）"
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
        // 这家没有 campaign 接口：能力位已是 false，界面不会挂入口。真被调到
        // 就给一条中性结果（native `checkin::claim_daily_checkin` 的同一个兜底），
        // 不报错也不打上游。
        "checkin.claim" => Ok(json!({
            "outcome": "inactive",
            "message": "千问办公 没有每日签到活动",
        })),
        // 手动福利（活动领取）只有 Qoder 两个站点有：`claim` 能力位是 false，
        // 这里如实报「没有这个能力」。
        "claim.status" | "claim" => Err(Error::coded(
            "千问办公 没有可领取的活动（campaign）接口",
            "unsupported",
        )),
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
        // 这个方法问的是「HTTP 200 但正文其实是失败话术」。本家的业务错误全在
        // SSE 信封里（`statusCodeValue`），而这里只看得到状态码与响应头、拿不到
        // 正文 —— 按状态码猜必然误伤（上游成功响应的状态码永远是 200）。
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
