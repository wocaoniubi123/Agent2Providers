//! 账号面：设备授权收尾 / PAT 兑换 + 归一化 + 公开视图（native `accounts.rs`）。
//!
//! ── 两条添加路径 ────────────────────────────────────────────
//! ```text
//!   Manual{payload}  粘贴凭证（Qoder 还可以粘贴 PAT）→ 拉资料 → 落账号
//!   Desktop          不支持（没有客户端登录态文件）
//!   FileText/Base64  不支持（凭证是令牌，不是文件）
//! ```
//! 网页登录（设备授权）由 `login.rs` 走另一条路，收尾时调 [`account_of`]
//! （与手工粘贴共用同一份落库形态）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::auth;
use super::credentials::{self, Credentials};
use super::site;

/// 账号名长度上限
const MAX_NAME_LENGTH: usize = 64;

/// 截断文本（按字符，不按字节 —— 中文名不会被切成半个字）
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect()
}

/// 添加账号入口。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            let payload = &source["payload"];
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        Some("desktop") => return Err(Error::http(400, "Qoder 中国版请使用网页登录添加")),
        Some("file_text") | Some("file_base64") => {
            return Err(Error::http(
                400,
                "Qoder 没有可导入的凭证文件，请用网页登录或粘贴账号记录",
            ))
        }
        _ => return Err(Error::http(400, "Qoder 请使用网页登录或手动填写令牌")),
    };
    let payload = if let Some(raw) = payload.as_str() {
        json!({ "accessToken": raw })
    } else {
        payload
    };
    let credentials = auth::prepare_account(&payload)?;
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate(value, MAX_NAME_LENGTH));
    Ok(account_of(&credentials, "manual", name))
}

/// 凭证 → 可落库的账号（网页登录与手工粘贴两条路共用）。
///
/// 记录字段就是 `Credentials::to_value()` 的产出（`accessToken` / `refreshToken`
/// / `mode` / `userId` / `machineId` / `expiresAt` …）。
pub fn account_of(credentials: &Credentials, source: &str, explicit_name: Option<String>) -> Value {
    let mut secret = match credentials.to_value() {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    secret.insert("mode".to_string(), Value::String("cn".to_string()));
    secret.insert("source".to_string(), Value::String(source.to_string()));
    let name = explicit_name
        .or_else(|| {
            let upstream = credentials.name.trim();
            if upstream.is_empty() {
                None
            } else {
                Some(upstream.to_string())
            }
        })
        .unwrap_or_else(|| default_name(credentials));
    secret.insert("name".to_string(), Value::String(name));
    let secret = Value::Object(secret);
    json!({
        "secret": secret.clone(),
        "public": view(&secret),
        "identity": identity(&secret),
        "desktop": false,
    })
}

/// 没给名字时怎么命名（native：`Qoder <uid>`，没有 uid 就用展示名）。
fn default_name(credentials: &Credentials) -> String {
    if credentials.user_id.is_empty() {
        site::display_name().to_string()
    } else {
        format!("{} {}", site::PRODUCT, credentials.user_id)
    }
}

/// 账号公开视图（界面账号页读的那几个键）。
///
/// **绝不能含 accessToken / refreshToken 本体** —— 只留令牌尾号与
/// 「有没有令牌」两个布尔。这条是安全边界。
pub fn view(secret: &Value) -> Value {
    let access_token = credentials::text(secret, &["accessToken", "access_token", "token"]);
    let user_id = credentials::text(secret, &["userId", "user_id"]);
    let explicit_name = credentials::text(secret, &["name"]);
    let name = if !explicit_name.is_empty() {
        explicit_name
    } else if !user_id.is_empty() {
        format!("{} {}", site::PRODUCT, user_id)
    } else {
        site::display_name().to_string()
    };
    let email = credentials::text(secret, &["email"]);
    let tail: String = access_token
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut view = json!({
        "name": name,
        "uid": user_id,
        "tokenTail": tail,
        // 站点身份（徽章显示用；值就是落盘的 provider id）
        "edition": site::PROVIDER_ID,
        "editionLabel": site::LABEL,
        "source": credentials::text(secret, &["source"]),
        "hasSession": !access_token.is_empty(),
        // 有刷新令牌 = 能续期（网页登录与 PAT 都带）
        "hasAccessToken": !access_token.is_empty(),
        "hasRefreshToken": !credentials::text(secret, &["refreshToken", "refresh_token"]).is_empty(),
        "canRefresh": !credentials::text(secret, &["refreshToken", "refresh_token"]).is_empty(),
        "desktop": false,
    });
    if !email.is_empty() {
        view["email"] = Value::String(email);
    }
    let expires_at = secret
        .get("expiresAt")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0);
    if let Some(expires_at) = expires_at {
        view["expiresAt"] = Value::from(expires_at);
    }
    view
}

/// 账号的稳定身份（没有 userId 时返回空串让网关按凭证去重）。
///
/// 前缀是**同 provider 内**的去重键，改前缀会让存量账号在下次导入时被当成
/// 新账号。
pub fn identity(secret: &Value) -> String {
    let user_id = credentials::text(secret, &["userId", "user_id"]);
    if user_id.is_empty() {
        return String::new();
    }
    format!("qoder-{user_id}")
}

/// 取一个现在能用的 token（临期主动续期）。
pub fn ensure() -> Result<String> {
    let (_, credentials) = super::refresh::snapshot()?;
    if credentials.expiring() {
        return refresh();
    }
    Ok(credentials.access_token)
}

/// 强制续期一次并返回新 token。
pub fn refresh() -> Result<String> {
    let credentials = super::refresh::ensure_fresh(true)?;
    Ok(credentials.access_token)
}

/// 临期判定（给 `token.expiring`）。`secret` 缺失时读当前账号。
pub fn expiring(secret: &Value) -> bool {
    let owned;
    let secret = if secret.is_object() {
        secret
    } else {
        owned = sdk::account().unwrap_or(Value::Null)["secret"].clone();
        &owned
    };
    match Credentials::from_payload(secret) {
        Ok(credentials) => credentials.expiring(),
        Err(_) => false,
    }
}
