//! AutoClaw 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/autoclaw/`（native）。
//!
//! ── 这一家在网关眼里长什么样 ──────────────────────────────
//! 上游是 **OpenAI 兼容代理**（`{upstream}/chat/completions`），所以对话本身是
//! 「透传 + 三处改写 + 帧回写」；真正麻烦的是四道上游闸与登录（见 `chat.rs` /
//! `prompt.rs` / `login.rs` 的模块头）。
//!
//! ── 两个地区是两个包 ────────────────────────────────────────
//! `wasm/autoclaw`（国内版）与 `wasm/autoclaw-intl`（国际版）共用同一份 `src/`，
//! 只有 `region::REGION` 与 `wasm.json` 的 origins / requires 不同。国内版走
//! **手机验证码**登录，国际版走 **Zai / Google OAuth**（`login.rs` 按地区分流）。
//!
//! ── 四条装包期硬校验（不满足 = 整包加载失败）───────────────
//! 1. `capabilities.chat == true` → requires 必须有 `chat.stream.v1` 和 `accounts.cas.v1`
//! 2. `capabilities.model_refresh == true` → requires 必须有 `catalog.v1`
//! 3. `capabilities.web_login == true` → requires 必须有 `login.forms.v1`
//! 4. `capabilities.anonymous_default_session` / `env_credentials` 必须都是 false
//! 另有：`settings_schema.storage_provider`（若有）必须是本包自己的 provider id。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata.json`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh_token()` → `token.refresh`；
//! `token_expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`；`account_view()` → `account.view`；
//! `account_identity()` → `account.identity`；
//! `login.*` → `login.start` / `login.poll` / `login.callback` / `login.cancel`；
//! `admin.action` → `admin.action`（`auth.methods` 与登录管理动作）。
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   region      地区常量（两套域名 / provider id / 登录方式）
//!   sign        客户端指纹头（X-Auth-Sign / 品牌头 / 透传头）
//!   credential  凭证解析 / 身份 / 续期 / 回写
//!   upstream    userapi 出站封装与信封判定
//!   models      静态路由表与路由解析
//!   catalog     远程模型目录（5 分钟缓存）
//!   prompt      system 提示规范化（上游身份闸门）
//!   chat        会话式转发（四道闸 + SSE 回写 + 401 重试）
//!   login       登录（国内短信 / 国际 OAuth）+ auth.methods
//!   usage       积分钱包 + 订阅
//!   checkin     每日签到
//!   md5         签名用的 MD5
//!   codec       hex / base64 / JWT 载荷 / 查询串
//! ```
//!
//! ── 与 native 的能力缺口（刻意保留，不是漏做）────────────────
//!   · **桌面端登录态导入**：wasm 没有文件系统（`account.normalize` 如实回绝）；
//!   · **环境变量旁路**（`AUTOCLAW_TOKEN`）：沙箱没有环境变量，且装包期硬校验
//!     明确要求 `env_credentials = false`；
//!   · **`enc:` 密文解密**：缺少桌面端的 os_crypt 密钥；
//!   · **活动福利的触发与复核**：见 `checkin.rs` 模块头（附加收益，不搬）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 全部文件零 unwrap / expect / panic：宿主里一个 panic 会带走整个实例。

mod catalog;
mod chat;
mod checkin;
mod codec;
mod credential;
mod login;
mod md5;
mod models;
mod oauth;
mod prompt;
mod region;
mod sign;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
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

        // ── 目录 / 额度 / 签到 ──────────────────────────────
        "models.list" => Ok(json!({
            "models": models::list(),
            "meta": {
                "remote": !catalog::remote_models().is_empty(),
                "refreshed_at": catalog::last_refreshed_at(),
            },
        })),
        "models.refresh" => {
            let force = params["force"].as_bool().unwrap_or(false);
            // 没有可用登录态时返回「没刷」而不是错误：脚本 / CI 用户走这条时
            // 本就不该刷目录，报红色失败只会让他以为哪里坏了（与 native 同口径）。
            match credential::record() {
                Ok(record) => match credential::credential(&record) {
                    Ok(credentials) => catalog::refresh(&credentials, force),
                    Err(_) => Ok(sdk::catalog::unchanged(0)),
                },
                Err(_) => Ok(sdk::catalog::unchanged(0)),
            }
        }
        "usage.query" => usage::query(params["account"].as_str().unwrap_or("")),
        "checkin.claim" => checkin::claim(params["account"].as_str().unwrap_or("")),

        // ── 对话 ────────────────────────────────────────────
        "conversation" | "chat" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(classify(&params)),
        "is_error_response" => Ok(json!(is_error_response(&params))),
        "error.policy" => Ok(json!({ "stop": false })),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.callback" => login::callback(&params),
        "login.cancel" => login::cancel(&params),

        // ── 管理动作 ────────────────────────────────────────
        "admin.action" => {
            let action = params["action"].as_str().unwrap_or("");
            match action {
                "auth.methods" => Ok(login::methods()),
                // 本家的额度来源已在 `usage.query` 的 `wallets[]` / `credits[]` 里给全
                "quota.sources" => Ok(json!([])),
                other => login::admin_action(other, &params),
            }
        }

        // 本家没有跨家重试建议：账号级由编排层按 `classify` 决定。
        "retry_advice" => Ok(Value::Null),
        "cooldown_models" => Ok(json!({ "models": [] })),
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "AutoClaw 由上游路由表决定思考档位，插件不再注入"
        })),

        _ => Err(Error::unsupported()),
    }
}

/// 添加账号：粘贴 token / 文本文件（桌面端导入与二进制文件如实回绝）。
///
/// ── `payload.inputs` 必须先解一层（规格第 17 节的坑）──────────
/// 网关把 api 表单整包放进 `NormalizeSource::Manual { payload: { methodIndex, inputs } }`。
/// 只读平铺键的话，「登录凭据」按钮点下去会报「缺凭据」。
///
/// ── 为什么必须出网校验一次 ──────────────────────────────────
/// 令牌是不透明的（身份在 JWT 声明里，但上游认不认得出网才知道）。校验走
/// `user-info`：它顺带读回 `user_id` / 邮箱 —— 这两样决定账号 id 与展示名。
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
            .map_err(|_| {
                Error::http(
                    400,
                    "不是合法 JSON（请选择 AutoClaw 客户端登录后导出的凭证内容）",
                )
            })?,
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "AutoClaw 不支持二进制凭证文件，请粘贴明文 token（或从客户端导出凭据）",
            ))
        }
        // 桌面端登录态导入需要读本机文件（wasm 没有文件系统）
        _ => {
            return Err(Error::http(
                400,
                "AutoClaw 的 wasm 插件读不到本机登录态（沙箱没有文件系统）；请用手机验证码 / 网页登录，或粘贴明文 token",
            ))
        }
    };
    // 面板只贴了一个裸 token 时也认
    let payload = if let Some(raw) = payload.as_str() {
        json!({ "token": raw })
    } else {
        payload
    };
    let token = credential::text(&payload, &["token", "accessToken", "access_token"]);
    if token.is_empty() {
        return Err(Error::http(
            400,
            "请提供 AutoClaw 的访问令牌（token / accessToken）",
        ));
    }
    let mut secret = payload.clone();
    if let Some(object) = secret.as_object_mut() {
        // 归一成明文 token（剥 `Bearer `），并补 deviceId（user-info 要它）
        object.insert(
            "token".to_string(),
            Value::String(codec::strip_bearer(&token)),
        );
        let device_id = credential::text(&payload, &["deviceId"]);
        object.insert(
            "deviceId".to_string(),
            Value::String(if device_id.is_empty() {
                credential::new_device_id()
            } else {
                device_id
            }),
        );
    }
    // 出网校验：问一次 user-info。失败 = 这个令牌现在不能用（添加时验证，
    // 要的就是「现在真的能用」）。
    let parsed = credential::from_record(&secret, region::REGION)?;
    match fetch_user_info(&parsed) {
        Ok(found) => {
            if let Some(object) = secret.as_object_mut() {
                let email = credential::text(&found, &["email", "mail"]);
                if !email.is_empty() {
                    object.insert("email".to_string(), Value::String(email));
                }
                let user_id = credential::text(&found, &["user_id", "userId", "id"]);
                if !user_id.is_empty() {
                    object.insert("userId".to_string(), Value::String(user_id));
                }
            }
        }
        Err(error) => {
            return Err(Error::http(
                400,
                format!("AutoClaw 校验失败：{}", error.message),
            ))
        }
    }
    if let Some(name) = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(object) = secret.as_object_mut() {
            object.insert(
                "name".to_string(),
                Value::String(name.chars().take(100).collect()),
            );
        }
    }
    login::account_from_secret(secret)
}

/// 问一次 `user-info`（校验令牌 + 读回身份 / 邮箱）。
fn fetch_user_info(credential: &credential::Credential) -> Result<Value> {
    let body = json!({ "source_id": "autoclaw", "device_id": credential.device_id });
    let payload = upstream::post("/userapi/v1/user-info", &credential.token, &body, "用户信息查询")?;
    upstream::data_or_error(&payload, "用户信息查询")
}

/// 非 2xx 的分类（网关读 `kind` / `status` / `message` / `upstream_code`）。
fn classify(params: &Value) -> Value {
    let status = params["status"].as_u64().unwrap_or(502) as u16;
    let body = &params["body"];
    let detail = body
        .get("message")
        .or_else(|| body.get("msg"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    let code = body
        .get("code")
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())))
        .filter(|code| *code != 0);
    let message = match detail {
        Some(text) => format!("上游返回 {status}: {text}"),
        None if status == 406 => format!("上游返回 406: 上游错误{}", prompt::UPSTREAM_406_HINT),
        None => format!("上游返回 {status}: 上游错误"),
    };
    if status == 401 {
        return json!({ "kind": "token_expired", "message": message });
    }
    if status == 429 {
        return json!({
            "kind": "quota_limited", "reset_at": Value::Null, "message": message,
            "upstream_code": code, "status": status
        });
    }
    json!({ "kind": "fatal", "status": status, "message": message, "upstream_code": code })
}

/// 200 响应里塞业务错误这件事，在网关眼里要怎么判。
fn is_error_response(params: &Value) -> bool {
    let status = params["status"].as_u64().unwrap_or(200) as u16;
    if status >= 400 {
        return true;
    }
    let body = &params["body"];
    if body.get("error").is_some_and(|error| !error.is_null()) {
        return true;
    }
    // 上游把额度 / 登录态错误写成非零 `code`（`410000` / `400000` / `630xxx`）
    upstream::code_of(body).is_some_and(|code| code != 0)
}

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
        // wasm 沙箱既没有文件系统也没有环境变量，这两个位必须是 false
        assert_eq!(false, value["capabilities"]["anonymous_default_session"].as_bool().unwrap_or(true));
        assert_eq!(false, value["capabilities"]["env_credentials"].as_bool().unwrap_or(true));
    }

    /// `models.refresh` / `usage.query` 之外，错误判定要认 200 + 非零业务码。
    #[test]
    fn error_response_detects_business_codes() {
        assert!(is_error_response(&json!({ "status": 200, "body": { "code": 410_000 } })));
        assert!(is_error_response(&json!({ "status": 500, "body": {} })));
        assert!(!is_error_response(&json!({ "status": 200, "body": { "code": 0, "data": {} } })));
    }
}
