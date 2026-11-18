//! Accio 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/accio/`（native）。
//!
//! ── 与国际版包的关系 ────────────────────────────────────────
//! 两个包共用同一份 `src/`，唯一的差别是 `region::REGION`（本包 = `Region::Cn`）
//! 与 `wasm.json` 的 `origins`（本包只列国内版登录站点）。上游的业务网关两个
//! 地区是同一个（`phoenix-gw.alibaba.com`），差别只在登录站点与
//! `x-package-region` 头。
//!
//! ── 这一家在网关眼里长什么样 ──────────────────────────────
//! 上游不是 OpenAI 兼容端点：请求体要先转成 **Gemini 风格信封**
//! （`contents` / `system_instruction` / `tools`，见 `protocol.rs`），响应是
//! ADK 自己的帧（`content.parts` / `turn_complete`，见 `stream.rs`），业务错误
//! 常是 HTTP 200 + 帧里的 `error_code`。所以本家走**会话式**通道，由自己掌控
//! 出站与帧翻译。
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
//! `stream_bytes` 回传 SSE。`chat` 写了也不会被调用（这里仍接同一条实现，
//! 只为让「误发过来的 chat」不至于静默失败）。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata.json`；`build_chat()` / `conversation()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh_token()` → `token.refresh`；
//! `token_expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`normalize_account()` → `account.normalize`；
//! `account_view()` → `account.view`；`account_identity()` → `account.identity`；
//! `login.*` → `login.start` / `login.poll` / `login.callback` / `login.cancel`；
//! `admin.action` → `admin.action`（`auth.methods` / `quota.sources`）。
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   region      地区常量（登录站点 / x-package-region / 网关基址）
//!   credential  凭证形态 / 续期 / 账号视图 / 身份
//!   upstream    出站薄封装（token 进 query 或 body、信封判定）
//!   protocol    OpenAI ↔ ADK Gemini 信封（含 md5 的 sg_k）
//!   stream      ADK SSE 帧解析与翻译
//!   chat        会话式转发（首帧预读 + 流式下发 + 401 重试一次）
//!   models      模型目录（静态兜底 + 远程刷新 + 思考档位落点）
//!   oauth       PKCE / 授权地址 / 换码
//!   login       登录流程编排（start / poll / callback / cancel + auth.methods）
//!   usage       额度与订阅
//!   md5         RFC 1321（sg_k 与凭证指纹）
//!   codec       base64url / hex / 随机 / 查询串
//! ```
//!
//! ── 与 native 的能力缺口（刻意保留，不是漏做）────────────────
//!   · 图片生成/编辑：wasm 侧没有通用图片通道（规格第 11 节），本家 native 也
//!     没有申报图片能力，故不实现；
//!   · 环境变量覆盖（`ACCIO_*`）：沙箱没有环境变量，改读 `sdk::settings::get`
//!     （见 `region.rs` 的模块头）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 全部文件零 unwrap / expect / panic：宿主里一个 panic 会带走整个实例。

mod chat;
mod codec;
mod credential;
mod login;
mod md5;
mod models;
mod oauth;
mod protocol;
mod region;
mod stream;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
///
/// 包含 `account_features` 这类自用扩展位 —— 网关用本 fork 的
/// `agent2api-provider-protocol` 反序列化，位在就生效，不需要额外接线。
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

        // ── 账号 ────────────────────────────────────────────
        "account.normalize" => normalize(&params),
        "account.view" => Ok(credential::view(&params["secret"])),
        "account.identity" => Ok(json!(credential::identity(&params["secret"]))),

        // ── 令牌 ────────────────────────────────────────────
        "token.ensure" => Ok(json!(credential::ensure()?)),
        "token.refresh" => Ok(json!(credential::refresh()?)),
        "token.expiring" => Ok(json!(credential::expiring())),

        // ── 目录 / 额度 ─────────────────────────────────────
        "models.list" => Ok(json!({
            "models": models::list(),
            "meta": { "remote": !models::remote_models().is_empty(), "refreshed_at": models::last_refreshed_at() },
        })),
        "models.refresh" => {
            let force = params["force"].as_bool().unwrap_or(false);
            // 没有账号时返回「没刷」而不是错误：不用本家的用户点「刷新模型」
            // 时不该看到一条红色失败（与 native 的 `unchanged` 同口径）。
            match credential::record() {
                Ok(record) => match credential::credential(&record) {
                    Ok(credentials) => models::refresh(&credentials, force),
                    Err(error) => Ok(sdk::catalog::failed(&error.message)),
                },
                Err(_) => Ok(sdk::catalog::unchanged(0)),
            }
        }
        "usage.query" => usage::query(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" | "chat" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(classify(&params)),
        "is_error_response" => Ok(json!(is_error_response(&params))),
        // 本家的错误都是「换号 / 刷新」量级，没有请求级（原文过大之类）的停止位
        "error.policy" => Ok(json!({ "stop": false })),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // 添加账号面板的登录方式清单（网关对 wasm 包恒问这条动态通道；
        // 缺了它面板直接打不开）。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::methods()),
        // 本家的额度来源已在 `usage.query` 的 `wallets[]` 里给全，这里回空表即可。
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // 本家没有跨家重试建议：账号级由编排层按 `classify` 决定。
        "retry_advice" => Ok(Value::Null),
        // 冷却标记在 native 里落账号库；插件侧交给编排层按 `classify` 的结论处理。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 思考档位在 `chat::build_plan` 里按目录条目的 `protocol` 改写，不需要平台补。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "按模型目录的思考档位在请求体内改写"
        })),

        _ => Err(Error::unsupported()),
    }
}

/// 添加账号：两条路径（粘贴凭据 / 文本文件），地区由 provider 身份决定。
///
/// ── `payload.inputs` 必须先解一层（规格第 17 节的坑）──────────
/// 网关把 api 表单整包放进 `NormalizeSource::Manual { payload: { methodIndex, inputs } }`。
/// 只读平铺键的话，「登录凭据」按钮点下去会报「缺凭据」。
fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            let payload = &source["payload"];
            // 面板塞进来的 `{methodIndex, inputs}`：取 `inputs`
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        Some("file_text") => serde_json::from_str(source["content"].as_str().unwrap_or(""))
            .map_err(|_| Error::http(400, "凭证文件不是合法 JSON"))?,
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "Accio 没有可导入的二进制凭证文件（凭证是令牌），请粘贴 accessToken",
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "Accio 不支持导入桌面端登录态，请用「网页登录」或粘贴凭证添加",
            ))
        }
    };
    // 面板只贴了一个裸 token 时也认
    let payload = if let Some(raw) = payload.as_str() {
        json!({ "accessToken": raw })
    } else {
        payload
    };
    let mut credentials = credential::Credential::from_secret(&payload)?;
    // 身份是 best-effort 的读数（昵称 / 邮箱只影响显示与去重）：粘贴的凭据
    // 一般不带头像资料，这里替用户问一次上游。问不到也照样落账号。
    if credentials.user_id.is_empty() {
        if let Ok(profile) = upstream::fetch_profile(&credentials.access_token) {
            upstream::apply_profile(&mut credentials, &profile);
        }
    }
    credentials.ensure_identity();
    let mut account = login::account_of(&credentials, "manual");
    // 显式备注名优先（`account_of` 用的是凭证自带的名字）
    if let Some(name) = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let name: String = name.chars().take(100).collect();
        // 逐层判对象再写：`Value` 的下标赋值在类型不符时会 panic（panic=abort
        // 等于整个实例挂掉），这里不赌结构。
        if let Some(public) = account["public"].as_object_mut() {
            public.insert("name".to_string(), json!(name.clone()));
        }
        if let Some(secret) = account["secret"].as_object_mut() {
            secret.insert("name".to_string(), json!(name));
        }
    }
    Ok(account)
}

/// 非 2xx 的分类（网关读 `kind` / `status` / `message` / `upstream_code`）。
///
/// ── 业务错误多数不体现在状态码上 ────────────────────────────
/// 流内错误由 `chat` 直接转成带状态码的错误；这里服务的是「网关自己拿到的
/// 非 2xx 响应」（例如上游在前置校验阶段就回了 4xx）。
fn classify(params: &Value) -> Value {
    let status = params["status"].as_u64().unwrap_or(502) as u16;
    let body = &params["body"];
    let detail = body
        .get("message")
        .or_else(|| body.get("msg"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误");
    let code = body
        .get("code")
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())))
        .filter(|code| *code != 0);
    let message = format!("上游返回 {status}: {detail}");
    match protocol::classify_upstream_error(status, detail) {
        protocol::UpstreamKind::Auth => json!({ "kind": "token_expired", "message": message }),
        protocol::UpstreamKind::Quota => json!({
            "kind": "quota_limited", "reset_at": Value::Null, "message": message,
            "upstream_code": code, "status": status
        }),
        protocol::UpstreamKind::Other => json!({
            "kind": "fatal", "status": status, "message": message, "upstream_code": code
        }),
    }
}

/// 200 响应里塞业务错误这件事，在网关眼里要怎么判。
///
/// 上游把额度/鉴权错误做成 HTTP 200 + 帧内 `error_code`，所以只看状态码会把
/// 「成功但没话」当成成功。判据：状态 >= 400，或载荷本身带着 `error` 对象 /
/// `error_code`。
fn is_error_response(params: &Value) -> bool {
    let status = params["status"].as_u64().unwrap_or(200) as u16;
    if status >= 400 {
        return true;
    }
    let body = &params["body"];
    if body.get("error").is_some_and(|error| !error.is_null()) {
        return true;
    }
    body.get("error_code").is_some_and(|code| !code.is_null())
        || body.get("errorCode").is_some_and(|code| !code.is_null())
}

// ── 模块清单提示：编译期确认子模块都被引用 ─────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// `metadata` 必须能被解析，且能力位与 `wasm.json` 的四条硬校验一致。
    #[test]
    fn metadata_matches_packaging_contract() {
        let value = metadata();
        assert_eq!(region::REGION.provider_id(), value["id"].as_str().unwrap_or(""));
        assert_eq!(true, value["capabilities"]["chat"].as_bool().unwrap_or(false));
        assert_eq!(true, value["capabilities"]["model_refresh"].as_bool().unwrap_or(false));
        assert_eq!(true, value["capabilities"]["web_login"].as_bool().unwrap_or(false));
        // wasm 沙箱既没有文件系统也没有环境变量，这两个位必须是 false
        assert_eq!(false, value["capabilities"]["anonymous_default_session"].as_bool().unwrap_or(true));
        assert_eq!(false, value["capabilities"]["env_credentials"].as_bool().unwrap_or(true));
    }

    /// 200 + 帧内错误码必须被判成错误（否则「额度耗尽」会被当成一次成功）。
    #[test]
    fn error_response_detects_business_codes() {
        assert!(is_error_response(&json!({ "status": 200, "body": { "error_code": "429" } })));
        assert!(is_error_response(&json!({ "status": 500, "body": {} })));
        assert!(!is_error_response(&json!({ "status": 200, "body": { "choices": [] } })));
    }
}
