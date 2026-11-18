//! Trae 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/trae/`（native，21 个文件）。
//!
//! ── 这一家在网关眼里长什么样 ──────────────────────────────
//! 上游不是 OpenAI 兼容端点，而是 `trae-api-cn.mchost.guru` 上的
//! `POST /api/agent/v3/llm_utils_chat`：请求体是「白名单重建」的自定义信封
//! （见 `payload.rs`），响应恒是 SSE 且**业务错误塞在 200 的流里**
//! （见 `stream.rs` 与 `errors.rs`）。所以本家走 stateful 路径，由自己掌控
//! 出站与流解析。
//!
//! 与 codearts 最大的差别是**这里没有签名层**：鉴权就是一个
//! `Cloud-IDE-JWT <token>` 加一批身份头（`headers.rs`），唯一的密码学是
//! 登录时的 PKCE(S256) 与设备公钥（`device.rs` + `p256.rs`）。
//!
//! ── 聊天通道按模型目录选择 ───────────────────────────────────
//! Agent、IDE 与旧 SOLO 的 config 共用 `llm_utils_chat`，但每条读数的
//! `function` / `model_name` 不同。批量目录归并后记录候选路由；首包前遇到
//! 4001 / 4023 / 1005 时，才尝试目录里同一模型的下一条通道。
//! 对外基础模型用上游 `config_name`；上游存在 `__max` 档位时另广告一个
//! `<id>-max`，只有显式选它才走 Max 路由。
//!
//! 国际版账号仍未接入本 provider；参考实现同样为两地分别维护身份与目录，
//! 不能把国际版令牌发往 CN 主机。
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
//! | `checkin()` | `checkin.claim` |
//! | `normalize_account()` | `account.normalize` |
//! | `account_view()` | `account.view` |
//! | `account_identity()` | `account.identity` |
//! | `classify()` | `classify` |
//! | 内容拦截判定 | `is_error_response` |
//! | `error_policy` | `error.policy` |
//! | `retry_advice` | `retry_advice` |
//! | `cooldown_models` | `cooldown_models` |
//! | `reasoning_patch` | `reasoning_patch` |
//! | `login.*` | `login.start` / `login.poll` / `login.cancel` / `login.callback` |
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   account       凭据形态 / 续期 / 账号面 / 导入归一化
//!   refresh       refreshToken 续期链（多候选 ClientID + host）
//!   oauth         授权地址 / guidance / 回调解析 / 授权码换证
//!   login         登录流程编排（start / poll / callback / cancel）
//!   device        设备密钥对（P-256）与一次性标识
//!   p256          标量乘与 SPKI / PKCS#8 编码（只为登录服务）
//!   profile       GetUserInfo 与身份合并
//!   models        目录拉取、路由缓存、刷新结果
//!   catalog       目录归并（config → models + routes）
//!   payload       出站信封（白名单重建）
//!   stream        SSE 方言解析（无 [DONE]、usage 欠一帧）
//!   forward       有状态转发（首包门 + 翻帧 + 401 强制换证）
//!   errors        状态码 + 业务码 → 网关认识的四个分类
//!   headers       身份头与客户端画像
//!   upstream      出站薄封装（host / 头 / 一次 POST / 候选失败文案）
//!   usage         额度 / 用量读数
//!   checkin       每日签到
//!   codec         base64 / 十六进制 / 随机源
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 全部文件零 unwrap / expect / panic：宿主里一个 panic 会带走整个实例。

mod account;
mod catalog;
mod checkin;
mod codec;
mod device;
mod errors;
mod forward;
mod headers;
mod login;
mod models;
mod oauth;
mod p256;
mod payload;
mod profile;
mod refresh;
mod stream;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（`crates/providers/src/providers/trae/adapter.rs`）。
///
/// 包含 `account_features.invite_code` 这类自用扩展位 —— 网关用本 fork 的
/// `agent2api-provider-protocol` 反序列化，位在就生效，不需要额外接线。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    // 文件是编译期常量，解析失败只可能是有人改坏了它；返回 Null 让界面缺元数据，
    // 而不是在启动路径上 panic（`unwrap` 在这里等于"整包加载失败"）。
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号 ────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 令牌 ────────────────────────────────────────────
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring())),

        // ── 目录 / 额度 / 签到 ──────────────────────────────
        "models.list" => models::list(),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" | "chat" => {
            forward::run(&params)?;
            Ok(Value::Null)
        }

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(errors::class_of(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        ))),
        "error.policy" => Ok(errors::policy(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // 添加账号面板的登录方式清单（网关对 wasm 包恒问这条动态通道；
        // 缺了它面板直接打不开，见 `login::methods` 的模块注释）。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods()),

        // 平台只有「额度来源」这一个面板问本家；本家的来源已在
        // `usage.query` 的 `credits[]` 里给全，这里回空表即可（与 atomcode 同口径）。
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // 本家没有跨家重试建议：通道级重试在 `forward` 内部完成，账号级由
        // 编排层按 `classify` 决定。
        "retry_advice" => Ok(Value::Null),
        // 冷却标记在 native 里由 `store_mark_limited` 落账号库；插件侧交给编排层
        // 按 `classify` 的结论处理，所以这里没有按模型的冷却清单。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 思考档位按目录路由在 `payload::prepare_body` 里改写，不需要平台再补。
        "reasoning_patch" => Ok(json!({ "action": "skip", "reason": "按模型目录的思考档位在请求体内改写" })),

        _ => Err(Error::unsupported()),
    }
}
