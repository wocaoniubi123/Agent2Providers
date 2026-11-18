//! 千问办公凭证格式：兼容既有实现的 access / refresh / expires 字段。
//!
//! ── 只有一种来源 ────────────────────────────────────────────
//! 网页设备流：`dt-`（访问令牌）/ `drt-`（刷新令牌）。这家**没有**个人访问
//! 令牌（`/api/v1/jobToken/exchange` 不存在），所以 native 里那条
//! `pat|<PAT>|<作业刷新令牌>` 的打包形态在这里没有对应物 —— 解析仍然容忍它
//! （老记录不会因为多一段就炸），但绝不会主动产生它。
//!
//! `refreshToken` 的内部打包形态是 `"<刷新令牌>|<userId>|<machineId>"`。这段
//! 打包**只在本仓库内部**存在，发往上游时只取第一段（见
//! [`Credentials::oauth_refresh`]）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`（宿主也按 abort 处理）：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::machine;
use super::site;

/// token 长度上限（与网关 `account_store::MAX_TOKEN_LENGTH` 同值）
pub const MAX_TOKEN_LENGTH: usize = 8192;

/// 临期判定窗口：**1 小时**（native `QWENWORK_REFRESH_MARGIN_MS`）。
///
/// 比 Qoder 的 5 分钟宽得多：这家的设备令牌寿命短、轮换频繁（dumate2api 实测
/// 续期一次 30 天但访问令牌容易先过期），提前一小时续期能躲开「刚好在请求
/// 途中失效」那类 401。
pub const REFRESH_MARGIN_MS: i64 = 60 * 60 * 1000;

#[derive(Clone, Debug, Default)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: Option<i64>,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub machine_id: String,
    /// 派生设备标识用的种子（账号 id）。登录/粘贴阶段为空。
    seed: String,
}

impl Credentials {
    /// 从账号 secret（或用户粘贴的 JSON）解析凭证。
    pub fn from_payload(payload: &Value) -> Result<Self> {
        if !payload.is_object() {
            return Err(Error::http(400, "账号内容必须是 JSON 对象"));
        }
        let access_token = secret(payload, &["accessToken", "access", "token", "access_token"])?;
        if access_token.is_empty() {
            return Err(Error::http(400, "缺少 access / accessToken"));
        }
        let refresh = secret(payload, &["refreshToken", "refresh", "refresh_token"])?;
        let parts: Vec<&str> = refresh.split('|').collect();
        let (packed_user, packed_machine) = match parts.as_slice() {
            ["pat", pat, _, user, machine] if !pat.is_empty() => (*user, *machine),
            [_, user, machine] => (*user, *machine),
            [_] => ("", ""),
            _ => return Err(Error::http(400, "refresh 格式无效，请粘贴完整账号记录")),
        };
        let user_id = identity(payload, &["userId", "user_id", "uid"])?;
        if !user_id.is_empty() && !packed_user.is_empty() && user_id != packed_user {
            return Err(Error::http(400, "userId 与刷新凭证中的用户不一致"));
        }
        let machine_id = identity(payload, &["machineId", "machine_id"])?;
        if !machine_id.is_empty() && !packed_machine.is_empty() && machine_id != packed_machine {
            return Err(Error::http(400, "machineId 与刷新凭证中的设备不一致"));
        }
        let user_id = if user_id.is_empty() { packed_user.to_string() } else { user_id };
        let machine_id = if machine_id.is_empty() { packed_machine.to_string() } else { machine_id };
        validate_identity(&user_id)?;
        validate_identity(&machine_id)?;
        let expires_at = ["expiresAt", "expires", "expires_at", "tokenExpiresAt"]
            .iter()
            .find_map(|key| timestamp(payload.get(*key)));
        let mut credentials = Self {
            access_token,
            refresh_token: refresh.clone(),
            expires_at,
            user_id,
            email: text(payload, &["email"]).chars().take(320).collect(),
            name: text(payload, &["nickname", "name", "username"]).chars().take(100).collect(),
            machine_id,
            seed: text(payload, &["id"]),
        };
        if parts.len() == 1 && !refresh.is_empty() {
            credentials.refresh_token =
                format!("{}|{}|{}", refresh, credentials.user_id, credentials.machine_id);
        }
        Ok(credentials)
    }

    /// 补齐身份：缺 `userId` 直接拒（无法标识账号），缺 `machineId` 按种子派生。
    pub fn complete_identity(&mut self) -> Result<()> {
        if self.user_id.is_empty() {
            return Err(Error::http(
                400,
                "缺少 userId，无法标识账号，请重新登录或粘贴完整账号记录",
            ));
        }
        validate_identity(&self.user_id)?;
        if self.machine_id.is_empty() {
            let seed = if self.seed.is_empty() { &self.user_id } else { &self.seed };
            self.machine_id = machine::machine_id("", seed);
        }
        validate_identity(&self.machine_id)?;
        // 刷新串的两段后缀固定是「用户 | 设备」（PAT 来源是「pat | PAT | 作业刷新
        // 令牌」+ 这两段，设备流来源是「刷新令牌」+ 这两段）。这里只重写后缀、
        // 保住前缀：PAT 与刷新令牌的形态由上游决定，按 `|` 切分再取下标会在段数
        // 不足时越界 panic，因此按**段数**分支、不足三段时整串当前缀（拼出的串
        // 上游会拒绝，但不会崩）。
        if !self.refresh_token.is_empty() {
            let parts: Vec<&str> = self.refresh_token.split('|').collect();
            let prefix = if parts.len() >= 3 {
                parts[..parts.len() - 2].join("|")
            } else {
                self.refresh_token.clone()
            };
            self.refresh_token = format!("{prefix}|{}|{}", self.user_id, self.machine_id);
        }
        if self.refresh_token.len() > MAX_TOKEN_LENGTH {
            return Err(Error::http(400, "刷新凭证过长"));
        }
        Ok(())
    }

    /// 发往续期端点的刷新令牌（**只取打包的第一段**）。
    ///
    /// 老记录有可能带 `pat|<PAT>|<刷新令牌>|…` 前缀（本家没有 PAT，出现即历史
    /// 数据）—— 那时跳过字面量 `pat` 与 PAT 本体、取第三段，而不是把字符串
    /// `"pat"` 或 PAT 本身当令牌发出去（上游只会回一句令牌无效，且看不出原因）。
    pub fn oauth_refresh(&self) -> &str {
        let mut parts = self.refresh_token.split('|');
        let first = parts.next().unwrap_or("");
        if first == "pat" {
            parts.next();
            parts.next().filter(|value| !value.is_empty()).unwrap_or("")
        } else {
            first
        }
    }

    pub fn can_refresh(&self) -> bool {
        !self.oauth_refresh().is_empty()
    }

    /// 临期判定：有刷新能力、且到期时间进了 5 分钟窗口。
    pub fn expiring(&self) -> bool {
        self.can_refresh()
            && self
                .expires_at
                .is_some_and(|expiry| expiry <= agent2api_wasm_sdk::now().saturating_add(REFRESH_MARGIN_MS))
    }

    /// 落库形态（空串按 null，理由见下）。
    pub fn to_value(&self) -> Value {
        // 空串按 null 落进记录：网关用「空值不覆盖」的合并规则，缺失的
        // refreshToken / expiresAt 不该把既有值洗成空串。
        let text_or_null = |value: &str| -> Value {
            if value.is_empty() {
                Value::Null
            } else {
                Value::String(value.to_string())
            }
        };
        let mut value = json!({
            "mode": site::MODE,
            "accessToken": text_or_null(&self.access_token),
            "refreshToken": text_or_null(&self.refresh_token),
            "expiresAt": self.expires_at,
            "userId": text_or_null(&self.user_id),
            "email": text_or_null(&self.email),
            "nickname": text_or_null(&self.name),
            "machineId": text_or_null(&self.machine_id),
        });
        if !self.seed.is_empty() {
            value["id"] = Value::String(self.seed.clone());
        }
        value
    }

    /// 从账号记录反推种子（账号 id），供 `ensure` 时补派生设备标识。
    pub fn set_seed(&mut self, seed: &str) {
        if !seed.is_empty() {
            self.seed = seed.to_string();
        }
    }
}

/// 按给定键序取第一个非空文本（数字也收）
pub fn text(payload: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| match payload.get(*key) {
            Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_string()),
            Some(Value::Number(value)) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// 取一个「令牌类」值：去 `Bearer ` 前缀、限长、挡控制字符。
pub fn secret(payload: &Value, keys: &[&str]) -> Result<String> {
    let mut value = keys
        .iter()
        .find_map(|key| {
            payload
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or("");
    if value.get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case("Bearer ")) {
        value = value[7..].trim();
    }
    if value.len() > MAX_TOKEN_LENGTH || value.chars().any(char::is_control) {
        return Err(Error::http(400, "凭证过长或包含非法控制字符"));
    }
    Ok(value.to_string())
}

fn identity(payload: &Value, keys: &[&str]) -> Result<String> {
    let value = text(payload, keys);
    validate_identity(&value)?;
    Ok(value)
}

fn validate_identity(value: &str) -> Result<()> {
    if value.len() > 256 || value.contains('|') || value.chars().any(char::is_control) {
        return Err(Error::http(400, "用户或设备标识无效"));
    }
    Ok(())
}

/// 时间戳：数字（秒 / 毫秒）或 RFC3339 文本。
pub fn timestamp(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    let number = value
        .as_i64()
        .or_else(|| value.as_str()?.trim().parse::<i64>().ok());
    if let Some(number) = number.filter(|value| *value > 0) {
        return if number < 100_000_000_000 {
            number.checked_mul(1000)
        } else {
            Some(number)
        };
    }
    chrono::DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .map(|time| time.timestamp_millis())
}

#[cfg(test)]
mod tests {
    //! 凭证打包/解包的契约：`|用户|设备` 后缀、PAT 段、身份不一致要拒。
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn unpacks_packed_refresh_token() {
        let credentials = Credentials::from_payload(&json!({
            "accessToken": "dt-abc",
            "refreshToken": "drt-xyz|uid-1|machine-1",
        }))
        .unwrap_or_default();
        assert_eq!(credentials.user_id, "uid-1");
        assert_eq!(credentials.machine_id, "machine-1");
        assert_eq!(credentials.oauth_refresh(), "drt-xyz");
        assert!(credentials.can_refresh());
    }

    #[test]
    fn mismatched_user_is_rejected() {
        let result = Credentials::from_payload(&json!({
            "accessToken": "dt-abc",
            "refreshToken": "drt-xyz|uid-1|machine-1",
            "userId": "uid-2",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn legacy_pat_record_keeps_the_real_refresh_token() {
        // 本家没有 PAT；万一读到老形态的 `pat|…` 记录，不能把字面量 `pat`
        // 当成刷新令牌发出去。
        let credentials = Credentials::from_payload(&json!({
            "accessToken": "dt-abc",
            "refreshToken": "pat|the-pat|drt-refresh|uid-1|machine-1",
        }))
        .unwrap_or_default();
        assert_eq!(credentials.user_id, "uid-1");
        assert_eq!(credentials.oauth_refresh(), "drt-refresh");
        assert!(credentials.can_refresh());
    }

    #[test]
    fn bare_refresh_token_gets_identity_suffix() {
        let mut credentials = Credentials::from_payload(&json!({
            "accessToken": "dt-abc",
            "refreshToken": "drt-xyz",
        }))
        .unwrap_or_default();
        credentials.user_id = "uid-9".to_string();
        credentials.complete_identity().unwrap_or_default();
        assert_eq!(credentials.refresh_token, "drt-xyz|uid-9|".to_string() + &credentials.machine_id);
        assert!(!credentials.machine_id.is_empty());
    }

    #[test]
    fn timestamp_accepts_seconds_millis_and_rfc3339() {
        assert_eq!(timestamp(Some(&json!(1_700_000_000))), Some(1_700_000_000_000));
        assert_eq!(timestamp(Some(&json!(1_700_000_000_000i64))), Some(1_700_000_000_000));
        assert_eq!(
            timestamp(Some(&json!("2026-11-19T00:00:00Z"))),
            Some(1_795_046_400_000)
        );
    }
}
