//! LobsterAI 凭证：**uuid 与两个 keyfrom 是载荷件，丢了账号就永远续不了期**。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/credentials.rs`。
//!
//! ── 为什么这一家的凭证字段比别家多 ──────────────────────────────
//! 上游的续期接口不认「只给 refresh token」：它要的是**一组身份字段**再加
//! refresh token（参考实现 `auth.go:191-196` 的 `refreshBody`）：
//!
//! ```text
//!   { firstKeyfrom, latestKeyfrom, version, [uuid], [userId], refreshToken }
//! ```
//!
//! 而 `uuid` 与那两个 keyfrom 只在**换码那一刻**由上游下发，此后再也拿不到。
//! 所以落账号时**必须把它们一起存下来** —— 只存 access/refresh 两个 token 的
//! 账号，看起来能用到 access 过期，之后既续不了期也修不回来（只能重新登录）。
//! 参考实现把这条写成模块头的第一句警告，这里照抄这个约束。
//!
//! `latest_keyfrom` 还额外有个「故意不更新」的口径：续期响应里即使带了新的
//! keyfrom 也不覆盖它，永远保持登录时那一份 —— 这是**唯一经过生产验证**的形态
//! （Go 参考 `auth.go:49-53` 与 TS 版 `lobsterai.ts:378-410` 都这么做，并在
//! 注里写明「不是为了省事，是照实测」）。本实现跟随。
//!
//! ── 过期时刻 ────────────────────────────────────────────────
//! 上游给 `expiresIn`（秒），落盘时算成 `expiresAt`（毫秒）。access token 是
//! HS512 的 JWT（30 天），所以**判不出 `expiresAt` 时可以退回读 JWT 的 `exp`**；
//! 两条都没有就返回 0 = 判不出来（不猜，见 [`Credentials::expiring`]）。
//!
//! ── 与 native 的一处形态差异 ────────────────────────────────
//! native 的 `from_record` 吃的是 `store::record` 拼出来的**平铺**记录
//! （secret 摊平 + `id` / `provider` / `name`）。wasm 侧 `sdk::account()` 给的
//! 是 `{id, provider, name, secret, public, identity}`，所以本模块直接吃
//! **secret 本体**；`account.rs` / `chat.rs` 负责从记录里把它取出来。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::codec;

/// 到期前 1 小时算临期（与 native 的提前续期窗口一致）
pub const REFRESH_WINDOW_MS: i64 = 3600 * 1000;

/// 一次转发 / 查询用的 LobsterAI 凭证快照
///
/// ── 为什么有的字段解析了却没人读 ────────────────────────────
/// `id` / `uid` / `nickname` 是 native 凭证快照的成员（`LobsterCredentials`）。
/// 转发链只用 `access_token`，账号视图读的是 secret 本体，所以这三个字段在本包里
/// 暂时没有消费点；保留它们是**为了 parity**：字段集合与 native 逐字对齐，
/// 将来要按账号写冷却 / 展示名时不必再改一次解析。`#[allow(dead_code)]`
/// 只抑制「没读」，不改变任何取值口径。
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// 账号记录 id
    pub id: String,
    /// 访问令牌（HS512 JWT，约 30 天）
    pub access_token: String,
    /// 续期令牌（可能为空 —— 那种账号只能重新登录）
    pub refresh_token: String,
    /// 过期时刻（毫秒）。0 = 推不出来
    pub expires_at: i64,
    /// 上游用户 id（积分接口与 keyfrom 都用）
    pub uid: String,
    /// keyfrom 载荷件之二（见模块头）
    pub user_id: String,
    /// 展示名
    pub nickname: String,
    /// **载荷件**：换码时下发，续期必须原样回传
    pub uuid: String,
    /// **载荷件**：登录时那一份，续期时原样回传且**永不更新**
    pub first_keyfrom: String,
    /// **载荷件**：同 [`Self::first_keyfrom`]
    pub latest_keyfrom: String,
}

impl Credentials {
    /// 从 secret 本体解析（**唯一入口**）。
    ///
    /// 字段兼容：本项目的驼峰名（`accessToken` / `refreshToken` / `firstKeyfrom`…）
    /// 与 Go 参考里的下划线名（`access_token` / `first_keyfrom`…）都认 ——
    /// 记录可能被手工编辑过，宽容读取比「认一个名」稳。
    pub fn from_secret(secret: &Value) -> Result<Self> {
        let access_token = pick(secret, &["accessToken", "access_token"]);
        if access_token.is_empty() {
            return Err(Error::http(401, "LobsterAI 账号缺少访问令牌，请重新登录"));
        }
        let created_at = pick_ms(secret, &["createdAt", "created_at"]);
        let expires_in = pick_secs(secret, &["expiresIn", "expires_in"]);
        let explicit_expiry = pick_ms(secret, &["expiresAt", "expires_at"]);
        let expires_at = if explicit_expiry > 0 {
            explicit_expiry
        } else {
            expires_at_from(created_at, expires_in, &access_token)
        };
        Ok(Self {
            id: pick(secret, &["id"]),
            refresh_token: pick(secret, &["refreshToken", "refresh_token"]),
            access_token,
            expires_at,
            uid: pick(secret, &["uid", "userId", "user_id"]),
            user_id: pick(secret, &["userId", "user_id"]),
            nickname: pick(secret, &["name", "nickname"]),
            uuid: pick(secret, &["uuid", "UUID"]),
            first_keyfrom: pick(secret, &["firstKeyfrom", "first_keyfrom"]),
            latest_keyfrom: pick(secret, &["latestKeyfrom", "latest_keyfrom"]),
        })
    }

    /// 还能不能续期：有 refresh token **且** 载荷件齐全。
    ///
    /// 缺任一载荷件时上游会拒（或更糟：给一个不认识的错误），所以这里先判死 ——
    /// 让「这个账号续不了期」在界面上是一句可读的话，而不是一次玄学失败。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
            && !self.first_keyfrom.trim().is_empty()
            && !self.latest_keyfrom.trim().is_empty()
    }

    /// 是否已过期或进入提前续期窗口（到期前 1 小时）。
    ///
    /// `expires_at == 0`（推不出到期时刻）时**判不出来就报不临期**：宁可漏刷，
    /// 也不要凭猜测打上游 —— 与网关 `token_expiring` 的兜底方向一致。
    pub fn expiring(&self, now_ms: i64) -> bool {
        self.expires_at > 0 && self.expires_at.saturating_sub(REFRESH_WINDOW_MS) <= now_ms
    }

    /// keyfrom 载荷（`firstKeyfrom` / `latestKeyfrom` / `version` 恒在，
    /// `uuid` 与 `userId` 非空才带）。
    ///
    /// 两个消费点共用这一份：目录端点把它拼成 **query**（`models.go:523-551`，
    /// 特意不带 refresh token —— query 会进服务端访问日志），续期端点把它当
    /// **body** 再补一个 `refreshToken`。
    pub fn keyfrom_fields(&self, client_version: &str) -> Vec<(&'static str, String)> {
        let mut fields: Vec<(&'static str, String)> = vec![
            ("firstKeyfrom", self.first_keyfrom.clone()),
            ("latestKeyfrom", self.latest_keyfrom.clone()),
            ("version", client_version.to_string()),
        ];
        if !self.uuid.trim().is_empty() {
            fields.push(("uuid", self.uuid.clone()));
        }
        if !self.user_id.trim().is_empty() {
            fields.push(("userId", self.user_id.clone()));
        }
        // 与 Go 的 `url.Values.Encode()` 同序（按 key 排序），
        // 让同样的账号每次拼出同样的串 —— 便于逐字节对拍与排错
        fields.sort_by(|a, b| a.0.cmp(b.0));
        fields
    }
}

/// 从一条取值链里挑第一个非空字符串（记录可能被手工编辑过，宽容读取）。
pub fn pick(secret: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = secret
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 读一个毫秒时刻（数字或数字字符串都认）
pub fn pick_ms(secret: &Value, keys: &[&str]) -> i64 {
    for key in keys {
        let Some(value) = secret.get(*key) else {
            continue;
        };
        if let Some(number) = value.as_i64() {
            if number > 0 {
                return number;
            }
        }
        if let Some(text) = value.as_str() {
            if let Ok(number) = text.trim().parse::<i64>() {
                if number > 0 {
                    return number;
                }
            }
        }
    }
    0
}

/// 读一个秒数（`expiresIn`）
pub fn pick_secs(secret: &Value, keys: &[&str]) -> i64 {
    for key in keys {
        if let Some(number) = secret.get(*key).and_then(Value::as_i64) {
            if number > 0 {
                return number;
            }
        }
    }
    0
}

/// 从 JWT 里读 `exp`（毫秒）。读不出来返回 `None`。
///
/// access token 是 HS512 的三段点分 JWT，`exp` 在第二段的 claims 里。
/// **只解码不验签**：这是本地判过期用的，签名由上游校验。
pub fn jwt_exp_ms(token: &str) -> Option<i64> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let raw = codec::base64_decode(payload.trim())?;
    let claims: Value = serde_json::from_slice(&raw).ok()?;
    let exp = claims.get("exp").and_then(Value::as_f64)?;
    if !exp.is_finite() || exp <= 0.0 {
        return None;
    }
    Some((exp * 1000.0) as i64)
}

/// 由 `createdAt + expiresIn` 或 JWT `exp` 推出过期时刻（毫秒），都没有则 0。
pub fn expires_at_from(created_at_ms: i64, expires_in_secs: i64, access_token: &str) -> i64 {
    if created_at_ms > 0 && expires_in_secs > 0 {
        return created_at_ms.saturating_add(expires_in_secs.saturating_mul(1000));
    }
    // 退回 JWT 的 exp（HS512，实测 30 天）
    jwt_exp_ms(access_token).unwrap_or(0)
}

/// 令牌尾 4 字符（公开视图的展示字段，与 `store::token_tail` 逐字一致）。
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 账号展示名（昵称优先，其次 uid，最后 user id）
pub fn display_name(nickname: &str, uid: &str, id: &str) -> String {
    for candidate in [nickname, uid, id] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "LobsterAI 账号".to_string()
}

/// 账号公开视图（界面账号页读的那几个键）。
///
/// ── 为什么必须在这里给出，而不是让网关猜 ────────────────────
/// 网关的公开视图只读插件给的 `public`（`secret` 被整块剥掉）。插件若把
/// 「账号名」只写进 `secret`，界面就是一片空白。所以这个函数是
/// **secret → public** 的唯一入口：登录落账号与刷新视图共用它。
pub fn account_view(secret: &Value) -> Value {
    let uid = pick(secret, &["uid", "userId", "user_id"]);
    let nickname = pick(secret, &["name", "nickname"]);
    let user_id = pick(secret, &["userId", "user_id"]);
    let access_token = pick(secret, &["accessToken", "access_token"]);
    let can_refresh = !pick(secret, &["refreshToken", "refresh_token"]).is_empty()
        && !pick(secret, &["firstKeyfrom", "first_keyfrom"]).is_empty()
        && !pick(secret, &["latestKeyfrom", "latest_keyfrom"]).is_empty();
    let mut view = json!({
        "name": display_name(&nickname, &uid, &user_id),
        "uid": uid,
        "nickname": nickname,
        "tokenTail": token_tail(&access_token),
        "hasSession": true,
        "canRefresh": can_refresh,
    });
    let expires_at = pick_ms(secret, &["expiresAt", "expires_at"]);
    if expires_at > 0 {
        if let Some(object) = view.as_object_mut() {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
    }
    view
}

/// 账号的稳定身份（去重用）：userId → uid → 令牌尾段。
///
/// 与 native `add_lobsterai_account` 的 identity 推导逐字一致 ——
/// 两处口径分叉会让「同一个账号重新登录」变成「新增一条记录」。
pub fn identity_of(secret: &Value) -> String {
    let user_id = pick(secret, &["userId", "user_id"]);
    if !user_id.is_empty() {
        return user_id;
    }
    let uid = pick(secret, &["uid", "id"]);
    if !uid.is_empty() {
        return uid;
    }
    let access_token = pick(secret, &["accessToken", "access_token"]);
    let tail: String = access_token
        .chars()
        .rev()
        .take(12)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    format!("tok{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Value {
        json!({
            "accessToken": "header.payload.signature",
            "refreshToken": "refresh-1",
            "uuid": "u-1",
            "firstKeyfrom": "1000",
            "latestKeyfrom": "2000",
            "userId": "user-9",
            "uid": "uid-7",
            "name": "有道用户",
            "expiresAt": 4_000_000_000_000i64,
        })
    }

    #[test]
    fn parses_camel_and_snake_names() {
        // `unwrap_or_default()` 而不是 expect：解析失败会得到空凭证，
        // 下面的断言直接失败并打出实际值（生产代码与本文件都不允许 panic）
        let camel = Credentials::from_secret(&secret()).unwrap_or_default();
        assert_eq!(camel.access_token, "header.payload.signature");
        assert_eq!(camel.user_id, "user-9");
        assert!(camel.can_refresh());
        let snake = Credentials::from_secret(&json!({
            "access_token": "t",
            "refresh_token": "r",
            "first_keyfrom": "1",
            "latest_keyfrom": "2",
        }))
        .unwrap_or_default();
        assert_eq!(snake.access_token, "t");
        assert_eq!(snake.first_keyfrom, "1");
        assert!(snake.can_refresh());
    }

    #[test]
    fn missing_access_token_is_a_401() {
        let error = Credentials::from_secret(&json!({ "refreshToken": "r" }));
        assert!(error.is_err());
        assert_eq!(error.err().and_then(|error| error.status), Some(401));
    }

    #[test]
    fn can_refresh_requires_all_payload_pieces() {
        let mut value = secret();
        value["firstKeyfrom"] = json!("");
        let credentials = Credentials::from_secret(&value).unwrap_or_default();
        // 缺一个载荷件就续不了期（见模块头）
        assert!(!credentials.can_refresh());
        let mut value = secret();
        value["refreshToken"] = json!("");
        assert!(!Credentials::from_secret(&value)
            .unwrap_or_default()
            .can_refresh());
    }

    #[test]
    fn expiring_uses_a_one_hour_window() {
        let value = json!({ "accessToken": "t", "expiresAt": 10_000_000i64 });
        let credentials = Credentials::from_secret(&value).unwrap_or_default();
        assert_eq!(credentials.expires_at, 10_000_000);
        // 窗口内 → 临期
        assert!(credentials.expiring(10_000_000 - REFRESH_WINDOW_MS + 1));
        // 窗口外 → 不临期
        assert!(!credentials.expiring(10_000_000 - REFRESH_WINDOW_MS - 1));
        // 到期时刻推不出来 → 一律不临期（不猜）
        let unknown = Credentials::from_secret(&json!({ "accessToken": "t" })).unwrap_or_default();
        assert_eq!(unknown.expires_at, 0);
        assert!(!unknown.expiring(i64::MAX));
    }

    #[test]
    fn keyfrom_fields_are_sorted_and_skip_empty_pieces() {
        let credentials = Credentials::from_secret(&secret()).unwrap_or_default();
        let fields = credentials.keyfrom_fields("2026.9.4");
        let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(keys, vec!["firstKeyfrom", "latestKeyfrom", "userId", "uuid", "version"]);
        let mut minimal = secret();
        minimal["uuid"] = json!("");
        minimal["userId"] = json!("");
        let credentials = Credentials::from_secret(&minimal).unwrap_or_default();
        let keys: Vec<&str> = credentials
            .keyfrom_fields("v")
            .iter()
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(keys, vec!["firstKeyfrom", "latestKeyfrom", "version"]);
    }

    #[test]
    fn jwt_exp_is_read_without_verification() {
        // `{"exp":1}` 的 base64url（无 padding）：eyJleHAiOjF9
        assert_eq!(jwt_exp_ms("h.eyJleHAiOjF9.s"), Some(1000));
        // 一段 / 非 JSON / 无 exp → None
        assert_eq!(jwt_exp_ms("only-one-part"), None);
        assert_eq!(jwt_exp_ms("h.bm90LWpzb24.s"), None);
        // 有 expiresIn 时优先用它，不读 JWT
        assert_eq!(expires_at_from(1000, 30, "h.bm90LWpzb24.s"), 31_000);
        // 两条都没有 → 0（判不出来，不猜）
        assert_eq!(expires_at_from(0, 0, "h.bm90LWpzb24.s"), 0);
    }

    #[test]
    fn identity_prefers_user_id_then_uid_then_tail() {
        let value = json!({ "userId": "u9", "uid": "u7", "accessToken": "abcdefghijklmnop" });
        assert_eq!(identity_of(&value), "u9");
        let value = json!({ "uid": "u7", "accessToken": "abcdefghijklmnop" });
        assert_eq!(identity_of(&value), "u7");
        let value = json!({ "accessToken": "abcdefghijklmnop" });
        // 尾 12 字符
        assert_eq!(identity_of(&value), "tokefghijklmnop");
    }

    #[test]
    fn account_view_exposes_the_fields_the_ui_reads() {
        let view = account_view(&secret());
        assert_eq!(view["name"], json!("有道用户"));
        assert_eq!(view["uid"], json!("uid-7"));
        assert_eq!(view["tokenTail"], json!("ture"));
        assert_eq!(view["canRefresh"], json!(true));
        assert_eq!(view["expiresAt"], json!(4_000_000_000_000i64));
        // 缺昵称时退回 uid，再退回固定文案
        let view = account_view(&json!({ "accessToken": "abcd" }));
        assert_eq!(view["name"], json!("LobsterAI 账号"));
        assert_eq!(view["tokenTail"], json!("abcd"));
    }
}
