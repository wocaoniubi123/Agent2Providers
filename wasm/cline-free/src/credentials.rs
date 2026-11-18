//! Cline 凭证：账号记录 / 本机登录态解析出的统一形态。
//!
//! ── 两种 token 形态 ─────────────────────────────────────────
//! ```text
//!   登录返回      workos:eyJhbGciOi…    ← 发请求必须带这个前缀
//!   续期返回      eyJhbGciOi…           ← 裸 JWT，写入前要补前缀
//! ```
//! `ensure_token_prefix` 是幂等的：两种形态都规范化成带前缀，避免
//! 「看着填对了却稳定 401」这种最难排查的形态（native 的原话）。
//!
//! ── JWT 里能读到什么 ───────────────────────────────────────
//! ```text
//!   exp          过期时间（秒）→ 手填 token 的 expiresAt 兜底来源
//!   external_id  Cline 的账号 id（usr-…），余额接口路径认它
//!   email        展示名首选（界面要求显示邮箱）
//! ```

use agent2api_wasm_sdk::{json, Value};

/// 上游 API 根（完整路径 `/api/v1/chat/completions`）。
pub const API_BASE_URL: &str = "https://api.cline.bot/api/v1";

/// WorkOS 身份服务根（设备授权与换票）。
pub const WORKOS_BASE_URL: &str = "https://api.workos.com";

/// WorkOS 的公开客户端 id（随官方客户端分发，不是用户机密）。
pub const WORKOS_CLIENT_ID: &str = "client_01K3A541FN8TA3EPPHTD2325AR";

/// 设备授权页的兜底地址（响应里没给 `verification_uri` 时用它）。
pub const DEVICE_VERIFY_FALLBACK: &str = "https://authkit.cline.bot/device";

/// access token 的前缀（幂等补）。
pub const TOKEN_PREFIX: &str = "workos:";

/// 提前刷新的窗口（10 分钟，与 native 同值）。
pub const PROACTIVE_REFRESH_MARGIN_MS: i64 = 10 * 60 * 1000;

/// 一份 Cline 凭证。
#[derive(Clone, Debug, Default)]
pub struct ClineCredentials {
    /// access token（解析后**不含**前缀；发请求时统一补）
    pub access_token: String,
    pub refresh_token: String,
    /// 过期时间（毫秒时间戳；None = 无从判断）
    pub expires_at: Option<f64>,
    /// 账号 id（`usr-…` 形态，余额接口路径认的那个）
    pub account: String,
    /// 展示名（email 优先）
    pub name: String,
}

impl ClineCredentials {
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    /// 临期判定：判不出过期时间时返回 false（无从判断不该让维护任务白跑）。
    pub fn is_expiring(&self) -> bool {
        match self.expires_at {
            Some(expires) => (expires as i64).saturating_sub(agent2api_wasm_sdk::now()) <= PROACTIVE_REFRESH_MARGIN_MS,
            None => false,
        }
    }

    /// 发请求用的 access token（带 `workos:` 前缀）。
    pub fn bearer_token(&self) -> String {
        ensure_token_prefix(&self.access_token)
    }
}

/// 确保 token 带 `workos:` 前缀（幂等）。
pub fn ensure_token_prefix(token: &str) -> String {
    let token = token.trim();
    if token.is_empty() {
        return String::new();
    }
    if token.starts_with(TOKEN_PREFIX) || token.starts_with("Bearer ") {
        token.to_string()
    } else {
        format!("{TOKEN_PREFIX}{token}")
    }
}

/// 去掉前缀（落盘统一存裸 JWT）。
fn strip_prefix(token: &str) -> String {
    let token = token.trim();
    token.strip_prefix(TOKEN_PREFIX).unwrap_or(token).trim().to_string()
}

/// 从 `secret` / 账号记录读一份凭证。
pub fn from_secret(secret: &Value) -> ClineCredentials {
    let auth = secret.get("auth").filter(|value| value.is_object()).cloned();
    let source = auth.clone().unwrap_or_else(|| secret.clone());
    let access = text(&source, &["accessToken", "access_token", "token"]);
    let refresh = text(&source, &["refreshToken", "refresh_token"]);
    let expires = source
        .get("expiresAt")
        .and_then(expires_at)
        .or_else(|| parse_rfc3339(text(&source, &["expiresAt"]).as_str()))
        .or_else(|| expires_at_from_jwt(&access));
    let account = text(&source, &["accountId", "account"])
        .or_else_nonempty(|| account_id_from_jwt(&access).unwrap_or_default());
    let name = text(&source, &["name"]).or_else_nonempty(|| identity_from_jwt(&access).0);
    ClineCredentials {
        access_token: strip_prefix(&access),
        refresh_token: refresh,
        expires_at: expires,
        account,
        name,
    }
}

fn text(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// 小工具：空串时取另一个来源。
trait OrElseNonEmpty {
    fn or_else_nonempty(self, other: impl FnOnce() -> String) -> String;
}

impl OrElseNonEmpty for String {
    fn or_else_nonempty(self, other: impl FnOnce() -> String) -> String {
        if self.is_empty() {
            other()
        } else {
            self
        }
    }
}

/// `expiresAt` 的两种形态：毫秒数 / 秒数（< 1e11 视为秒）。
fn expires_at(value: &Value) -> Option<f64> {
    if let Some(number) = value.as_f64().filter(|value| *value > 0.0) {
        return Some(if number < 100_000_000_000.0 { number * 1000.0 } else { number });
    }
    let text = value.as_str()?;
    parse_rfc3339(text)
}

/// RFC3339 → 毫秒。
fn parse_rfc3339(text: &str) -> Option<f64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(text).ok()?;
    Some(parsed.timestamp_millis() as f64)
}

/// JWT 的 payload（`workos:` 前缀之后的第一段）。
pub fn jwt_claims(token: &str) -> Option<Value> {
    let bare = token.trim().trim_start_matches(TOKEN_PREFIX);
    let payload = bare.split('.').nth(1)?;
    let bytes = base64url_decode(payload.trim_end_matches('='))?;
    serde_json::from_slice(&bytes).ok()
}

/// 从 JWT 解出 `exp`（秒）→ 毫秒。
pub fn expires_at_from_jwt(token: &str) -> Option<f64> {
    let claims = jwt_claims(token)?;
    let exp = claims.get("exp")?.as_f64()?;
    if exp <= 0.0 {
        return None;
    }
    Some(exp * 1000.0)
}

/// 从 JWT 解出 Cline 的账号 id（`external_id` 声明）。
pub fn account_id_from_jwt(token: &str) -> Option<String> {
    let claims = jwt_claims(token)?;
    claims
        .get("external_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 从 JWT 解出展示名与账号 id（展示名 email 优先）。
pub fn identity_from_jwt(token: &str) -> (String, String) {
    let Some(claims) = jwt_claims(token) else {
        return (String::new(), String::new());
    };
    let field = |key: &str| {
        claims
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let email = field("email");
    let external = field("external_id");
    let cline_user = field("clineUserId");
    let sub = field("sub");
    let account = if !external.is_empty() {
        external
    } else if !cline_user.is_empty() {
        cline_user
    } else {
        sub
    };
    let first = field("firstName");
    let last = field("lastName");
    let person = format!("{last}{first}");
    let name = if !email.is_empty() {
        email
    } else if !person.is_empty() {
        person
    } else {
        account.clone()
    };
    (name, account)
}

/// base64url 解码（`-`/`_` 变体，允许填充）。
fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// 公开视图（界面读的键名沿用既有契约）。
pub fn public(secret: &Value) -> Value {
    let credentials = from_secret(secret);
    let tail: String = {
        let chars: Vec<char> = credentials.access_token.chars().collect();
        let start = chars.len().saturating_sub(4);
        chars[start..].iter().collect()
    };
    let name = if !credentials.name.is_empty() {
        credentials.name.clone()
    } else if !credentials.account.is_empty() {
        credentials.account.clone()
    } else {
        "Cline".to_string()
    };
    let mut view = json!({
        "name": name,
        "accountId": credentials.account.clone(),
        "tokenTail": tail,
        "hasCredentials": !credentials.access_token.is_empty(),
        "hasAccessToken": !credentials.access_token.is_empty(),
        "hasRefreshToken": credentials.can_refresh(),
        "canRefresh": credentials.can_refresh(),
    });
    if let Some(expires) = credentials.expires_at {
        view["expiresAt"] = json!(expires as i64);
    }
    if secret.get("desktop").and_then(Value::as_bool) == Some(true)
        || secret.get("source").and_then(Value::as_str) == Some("desktop")
    {
        view["desktop"] = json!(true);
    }
    view
}

/// 去重身份：账号 id 优先，其次 token 的哈希。
pub fn identity(secret: &Value) -> String {
    use sha2::{Digest, Sha256};
    let credentials = from_secret(secret);
    if !credentials.account.is_empty() {
        return format!("cline:{}", credentials.account);
    }
    if credentials.access_token.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(credentials.access_token.as_bytes());
    let hex: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    format!("cline:key:{hex}")
}

/// 组装一条可落库的账号。
pub fn account_of(credentials: &ClineCredentials, name: &str, desktop: bool) -> Value {
    let mut secret = json!({
        "accessToken": ensure_token_prefix(&credentials.access_token),
        "refreshToken": credentials.refresh_token,
        "accountId": credentials.account,
        "name": if name.trim().is_empty() { credentials.name.clone() } else { name.trim().chars().take(128).collect() },
    });
    if let Some(expires) = credentials.expires_at {
        secret["expiresAt"] = json!(expires as i64);
    }
    if desktop {
        secret["desktop"] = json!(true);
        secret["source"] = json!("desktop");
    }
    json!({
        "identity": identity(&secret),
        "public": public(&secret),
        "secret": secret,
        "desktop": desktop,
    })
}
