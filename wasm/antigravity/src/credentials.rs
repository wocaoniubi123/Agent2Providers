//! Antigravity 凭证：`refreshToken` 是主凭证，`accessToken` 只是缓存。
//!
//! ── 为什么 refresh token 才是主凭证 ─────────────────────────
//! Google 的 access token 只活约一小时，且**不会**在下发时说明还能用多久；
//! 真正决定账号还能不能用的是 refresh token（撤销授权 / 连续数月不用 / 撞上
//! 同一 client 的 100 个上限时才失效）。所以 `account.view` 里的 `canRefresh`
//! 判的是 refresh token 在不在。
//!
//! ── 临期判定 ────────────────────────────────────────────────
//! 提前 15 分钟刷（`EXPIRY_LEAD_MS`）：给网络抖动与时钟漂移留余量，也避免
//! 「刚判完不临期、请求发出去就过期」。

use agent2api_wasm_sdk::{json, Value};

/// 提前刷新的窗口（15 分钟）。
pub const EXPIRY_LEAD_MS: i64 = 15 * 60 * 1000;

/// 一份 Antigravity 凭证。
#[derive(Clone, Debug, Default)]
pub struct AntigravityCredentials {
    pub refresh_token: String,
    pub access_token: String,
    /// 毫秒时间戳；0 = 不知道
    pub expires_at: i64,
    /// `cloudaicompanionProject`
    pub project_id: String,
    /// 展示用（同时决定信封里的 `userAgent` 标记）
    pub email: String,
    pub name: String,
}

/// 取第一个非空字符串。
pub fn text(secret: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = secret.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// 取第一个正数（数字或数字字符串）。
fn number(secret: &Value, keys: &[&str]) -> i64 {
    for key in keys {
        if let Some(value) = secret.get(*key).and_then(Value::as_i64) {
            if value > 0 {
                return value;
            }
        }
        if let Some(value) = secret.get(*key).and_then(Value::as_str) {
            if let Ok(parsed) = value.trim().parse::<i64>() {
                if parsed > 0 {
                    return parsed;
                }
            }
        }
    }
    0
}

impl AntigravityCredentials {
    pub fn from_secret(secret: &Value) -> Self {
        Self {
            refresh_token: text(secret, &["refreshToken", "refresh_token"]),
            access_token: text(secret, &["accessToken", "access_token", "token"]),
            expires_at: number(secret, &["expiresAt", "expires_at"]),
            project_id: text(secret, &["projectId", "project_id", "cloudaicompanionProject"]),
            email: text(secret, &["email"]),
            name: text(secret, &["name"]),
        }
    }

    /// 写回 `secret`（保留未知字段）。
    pub fn write_into(&self, secret: &mut Value) {
        let Some(object) = secret.as_object_mut() else {
            *secret = json!({});
            return;
        };
        object.insert("refreshToken".into(), json!(self.refresh_token));
        object.insert("accessToken".into(), json!(self.access_token));
        object.insert("expiresAt".into(), json!(self.expires_at));
        if !self.project_id.is_empty() {
            object.insert("projectId".into(), json!(self.project_id));
        }
        if !self.email.is_empty() {
            object.insert("email".into(), json!(self.email));
        }
        if !self.name.is_empty() {
            object.insert("name".into(), json!(self.name));
        }
    }

    /// 能不能续期。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.is_empty()
    }

    /// 临期（提前 15 分钟）。
    pub fn expiring(&self) -> bool {
        self.expires_at > 0
            && self.expires_at.saturating_sub(EXPIRY_LEAD_MS) <= agent2api_wasm_sdk::now()
    }
}

/// 令牌尾 4 位（多字节安全）。
fn tail_of(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 公开视图。
///
/// `identifier: userId` 的语义是「身份键存的就是 email」（native 的
/// `account_features.identifier`），所以这里把 `userId` 设成 email。
pub fn public(secret: &Value) -> Value {
    let credentials = AntigravityCredentials::from_secret(secret);
    let name = if !credentials.name.is_empty() {
        credentials.name.clone()
    } else if !credentials.email.is_empty() {
        credentials.email.clone()
    } else {
        "Antigravity".to_string()
    };
    let mut view = json!({
        "name": name,
        "userId": credentials.email.clone(),
        "email": credentials.email.clone(),
        "projectId": credentials.project_id.clone(),
        "tokenTail": tail_of(&credentials.access_token),
        "hasCredentials": !credentials.access_token.is_empty() || credentials.can_refresh(),
        "hasAccessToken": !credentials.access_token.is_empty(),
        "hasRefreshToken": credentials.can_refresh(),
        "canRefresh": credentials.can_refresh(),
    });
    if credentials.expires_at > 0 {
        view["expiresAt"] = json!(credentials.expires_at);
    }
    view
}

/// 稳定身份：email 优先，其次 refresh token 的摘要。
pub fn identity(secret: &Value) -> String {
    use sha2::{Digest, Sha256};
    let credentials = AntigravityCredentials::from_secret(secret);
    if !credentials.email.is_empty() {
        return format!("antigravity:{}", credentials.email.to_lowercase());
    }
    if credentials.refresh_token.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(credentials.refresh_token.as_bytes());
    let hex: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    format!("antigravity:token:{hex}")
}
