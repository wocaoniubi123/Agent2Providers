//! Accio 凭证：`accessToken` / `refreshToken` / `expiresAt` + 账号标识。
//!
//! ── 上游给的东西（桌面端 `/api/oauth/token` 与 `/api/auth/refresh_token`
//!    的返回）──────────────────────────────────────────────────
//! ```jsonc
//! { "accessToken": "…", "refreshToken": "…", "expiresAt": 1789…, "sid": "…", "sgcookie": "…" }
//! ```
//! `sid` / `sgcookie` 是浏览器侧会话的伴随标识，桌面端主要用在「账号切换」
//! （`/api/auth/safe/refresh_token` 那条多账号链路）。
//!
//! - **`sid` 不落库**：本插件续期走普通那条，用不上它 —— 少存一个敏感值。
//! - **`sgcookie` 要留**：推理请求把它当一个「有就带」的伴随头（见
//!   `chat::build_plan`）。少了它请求照样成立，但带上更接近真实客户端。
//!
//! ── 身份用什么标识 ──────────────────────────────────────────
//! Accio 的 token 是**不透明串**（不是 JWT，解不出 userId），因此账号身份由
//! `/api/auth/userinfo` 查回的资料里的 id 决定（见 `upstream::fetch_profile`）。
//! 「粘贴凭证」这条路查一次资料拿到 id；查不到时退回按凭证指纹生成 id ——
//! 至少能保证同一串凭证重复添加时命中同一条记录，不会堆出一串重复账号。
//!
//! ── `deviceId`（utdid）是干嘛的 ─────────────────────────────
//! 推理请求要带 `utdid`（设备指纹）。桌面端每台机器一个（装机时生成、落盘）。
//! 本插件按**账号**生成并落进记录：多账号池化时每个账号带自己的指纹，
//! 与「一个账号一台设备」的真实形态一致（同一指纹挂十个账号才是可疑形态）。
//!
//! **这个头不能缺**：阿里网关把 utdid 当**风控基线**，缺了它会回 HTTP 200 +
//! `text/html` 的拦截页（`bixi-intl.alicdn.com/punish` 跳转脚本），症状是
//! 「模型不回复 / 空响应」而不是明确报错。所以发请求那一侧一律走
//! [`Credential::utdid`]（缺字段也能给出一个稳定值），不要直接读 `deviceId`。
//!
//! ── 与 native 的差别：单飞表 → 账号锁 + 会话缓存 ────────────────
//! native 用进程内的单飞表合并并发续期；插件里没有跨调用共享的内存，等价的
//! 纪律是「拿账号锁 + 锁后再读一次 + 成功后写回（比较再写）」—— 排队期间
//! 别人已经换过一轮的话直接用落盘那份，**绝不再拿刚被轮换掉的旧串去打一次**。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::codec;
use super::md5;
use super::region::{self, Region};
use super::upstream;

/// 提前多久认为 token 该续期（与另外几家同一量级）
pub const REFRESH_MARGIN_MS: i64 = 5 * 60 * 1000;

/// 凭证长度上限（超过就说明贴错了东西）
const MAX_TOKEN_LENGTH: usize = 64 * 1024;

/// `sgcookie` 的长度上限（字符）。正常值一两千字符（浏览器整条 cookie 串的量级），
/// 超过就说明贴错了东西 —— 与其截断出一条坏 cookie 发出去，不如直接不带。
const MAX_SGCOOKIE_CHARS: usize = 4096;

/// 上游没给到期时间时的保守默认：1 小时（续期链路用）。
const DEFAULT_TTL_MS: i64 = 60 * 60 * 1000;

#[derive(Clone, Default)]
pub struct Credential {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: Option<i64>,
    /// 上游账号标识（userinfo 的 id / userId）
    pub user_id: String,
    pub email: String,
    pub name: String,
    /// 推理请求的设备指纹（本插件按账号生成）
    pub device_id: String,
    /// 浏览器会话的伴随标识（可选；有就随推理请求带上）
    pub sgcookie: String,
}

impl Credential {
    /// 从账号记录 / 添加请求解析凭证。
    ///
    /// 接受的键名与其它家保持一致的宽口径（`accessToken` / `access_token` /
    /// `token`），前端「填写凭证」与导入路径都可能给不同形态。
    pub fn from_secret(secret: &Value) -> Result<Self> {
        if !secret.is_object() {
            return Err(Error::http(400, "Accio 账号内容必须是 JSON 对象"));
        }
        let access_token = secret_text(secret, &["accessToken", "access_token", "token"])?;
        if access_token.is_empty() {
            return Err(Error::http(400, "缺少 Accio accessToken"));
        }
        let expires_at = ["expiresAt", "expires_at", "expires"]
            .iter()
            .find_map(|key| timestamp(secret.get(*key)));
        Ok(Self {
            access_token,
            refresh_token: secret_text(secret, &["refreshToken", "refresh_token"])?,
            expires_at,
            user_id: text(secret, &["userId", "user_id", "uid"]),
            email: text(secret, &["email"]).chars().take(320).collect(),
            name: text(secret, &["nickname", "name"]).chars().take(100).collect(),
            device_id: text(secret, &["deviceId", "device_id"]),
            sgcookie: sgcookie(secret),
        })
    }

    /// 补齐设备指纹（新账号 / 登录时调）。
    ///
    /// 用密码学随机的十六进制串（`codec::random_bytes`）而不是凭证摘要：
    /// 设备指纹会随请求头发出去，**不该可反推凭证**。
    pub fn ensure_identity(&mut self) {
        if self.device_id.is_empty() {
            self.device_id = format!("desktop-{}", codec::hex_lower(&codec::random_bytes(16)));
        }
    }

    /// 推理请求一定要带上的 utdid。
    ///
    /// 正常路径上 `ensure_identity`（添加账号 / 登录 / 续期）已经补过值，这里
    /// 兜的是「记录是手改的 / 从旧版本迁过来的」那一档：**缺字段也不能让头消失**
    /// —— 上游把 utdid 当风控基线，缺了就直接回 HTML 拦截页（见模块头）。
    ///
    /// 兜底值按账号身份派生，**绝不共用**：`user_id` 优先（它最稳）；拿不到身份
    /// 时退回 `access_token` 的摘要 —— 这样至少「一个账号一个指纹」。
    pub fn utdid(&self) -> String {
        if header_safe(&self.device_id) {
            return self.device_id.clone();
        }
        let seed = if !self.user_id.is_empty() {
            self.user_id.as_str()
        } else {
            self.access_token.as_str()
        };
        format!("desktop-{}", md5::hex(seed))
    }

    /// 有刷新凭证 + 有到期时间，且快到点了
    pub fn expiring(&self) -> bool {
        self.can_refresh()
            && self
                .expires_at
                .is_some_and(|expiry| expiry <= sdk::now().saturating_add(REFRESH_MARGIN_MS))
    }

    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.is_empty()
    }

    /// 落进账号记录的形态。空串按 null 落（合并规则是「空值不覆盖」，缺项不该
    /// 把既有值洗成空）。
    pub fn to_secret(&self, region: Region) -> Value {
        let text_or_null = |value: &str| -> Value {
            if value.is_empty() {
                Value::Null
            } else {
                Value::String(value.to_string())
            }
        };
        json!({
            "mode": region.edition(),
            "accessToken": text_or_null(&self.access_token),
            "refreshToken": text_or_null(&self.refresh_token),
            "expiresAt": self.expires_at,
            "userId": text_or_null(&self.user_id),
            "email": text_or_null(&self.email),
            "nickname": text_or_null(&self.name),
            "deviceId": text_or_null(&self.device_id),
            "sgcookie": text_or_null(&self.sgcookie),
        })
    }
}

/// 取 `sgcookie`：接受驼峰 / 全小写两种键名；不是可见 ASCII 或超长的按「贴错了」
/// 丢弃（不截断）。
pub fn sgcookie(payload: &Value) -> String {
    let value = text(payload, &["sgcookie", "sgCookie"]);
    if !header_safe(&value) || value.chars().count() > MAX_SGCOOKIE_CHARS {
        return String::new();
    }
    value
}

/// 能不能安全放进 HTTP 头：只接受**可见 ASCII**（含空格），空串按不安全处理。
///
/// 宿主遇到非法头值会让整条请求失败（不是这一个头失效），所以脏值必须在拼头
/// 之前挡掉 —— 手改的账号记录、上游回填的 deviceId 都可能出现非 ASCII。
fn header_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// 取一个文本字段（空串按缺失处理）
pub fn text(payload: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| match payload.get(*key) {
            Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_string()),
            Some(Value::Number(value)) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// 取一个密钥字段：去 `Bearer ` 前缀、限长、拒绝控制字符。
pub fn secret_text(payload: &Value, keys: &[&str]) -> Result<String> {
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
        return Err(Error::http(400, "Accio 凭证过长或包含非法控制字符"));
    }
    Ok(value.to_string())
}

/// 时间戳（毫秒）；接受秒级数字与 RFC3339 字符串。0 / 负数 / 解析不出 → None。
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

// ─── 账号面（视图 / 身份）─────────────────────────────────────

/// 账号的稳定身份。
///
/// ── 为什么是 `<地区>:<userId 或令牌摘要>` ────────────────────
/// 两个地区是两家 provider，id 空间独立 —— 但同一个人在两地各有一个账号时，
/// 带上地区才能保证「同一条记录恒定、不同账号不同」。没有 userId 时按
/// accessToken 派生（用 md5：不需要抗碰撞，只要稳定且不泄露 token）。
pub fn identity(secret: &Value) -> String {
    let edition = region::REGION.edition();
    let user_id = text(secret, &["userId", "user_id", "uid"]);
    if !user_id.is_empty() {
        return format!("accio-{edition}-{user_id}");
    }
    let access_token = text(secret, &["accessToken", "access_token", "token"]);
    if access_token.is_empty() {
        return String::new();
    }
    format!("accio-{edition}-{}", md5::hex(&access_token))
}

/// Accio 专属的公开字段；账号 id 与 provider 由网关注入。
pub fn view(secret: &Value) -> Value {
    let access_token = text(secret, &["accessToken", "access_token", "token"]);
    let user_id = text(secret, &["userId", "user_id", "uid"]);
    let can_refresh = !text(secret, &["refreshToken", "refresh_token"]).is_empty();
    let mut view = json!({
        "name": text(secret, &["name"]),
        "userId": user_id,
        "email": text(secret, &["email"]),
        "nickname": text(secret, &["nickname"]),
        "source": text(secret, &["source"]),
        "tokenTail": token_tail(&access_token),
        "edition": region::REGION.edition(),
        "editionLabel": region::REGION.label(),
        "hasRefreshToken": can_refresh,
        "desktop": false,
        // 有 accessToken 就算「当前可用」（refreshToken 只决定能不能续期）
        "available": !access_token.trim().is_empty(),
    });
    let expires_at = ["expiresAt", "expires_at", "expires"]
        .iter()
        .find_map(|key| secret.get(*key).and_then(Value::as_i64))
        .filter(|value| *value > 0);
    if let Some(object) = view.as_object_mut() {
        if let Some(expires_at) = expires_at {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
    }
    view
}

/// 令牌尾巴（界面识别用；永不回显完整值）
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

// ─── 账号记录与令牌 ──────────────────────────────────────────

/// 当前账号记录（宿主没给账号时按 native 的口径报 401）。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if record.is_null() {
        return Err(Error::http(401, "没有可用的 Accio 账号，请先在「账号」页添加"));
    }
    Ok(record)
}

/// 记录 → 凭证。
pub fn credential(record: &Value) -> Result<Credential> {
    Credential::from_secret(&record["secret"])
}

/// 去掉 secret 里的展示用字段（`name` / `source` 这类写入值保留）。
fn secret_view(record: &Value) -> Value {
    let secret = record["secret"].clone();
    if secret.is_object() {
        secret
    } else {
        json!({})
    }
}

/// 取可用令牌：临期（5 分钟窗口）才续期。
pub fn ensure() -> Result<String> {
    let record = record()?;
    let mut credential = credential(&record)?;
    if credential.expiring() {
        credential = renew(&record, &credential)?;
    }
    if credential.access_token.trim().is_empty() {
        return Err(Error::http(401, "Accio 账号缺少 accessToken，请重新登录"));
    }
    Ok(credential.access_token)
}

/// 401 之后的**强制**续期：不看临期窗口（token 可能时间上还新但已被服务端
/// 失效 —— 只调 ensure 会拿回同一个被拒的 token）。
pub fn refresh() -> Result<String> {
    let record = record()?;
    let credential = credential(&record)?;
    Ok(renew(&record, &credential)?.access_token)
}

/// 后台凭证维护问「这条账号是不是快到期了」。
///
/// 没有 refreshToken 的账号恒 false：续期手段都没有，交给维护只会变成每轮
/// 一条稳定失败。
pub fn expiring() -> bool {
    let Ok(record) = sdk::account() else { return false };
    if record.is_null() {
        return false;
    }
    credential(&record)
        .map(|credential| credential.expiring())
        .unwrap_or(false)
}

/// 换发并回写（比较再写）。
///
/// ── 期望值已变时为什么报 409 而不是静默重读 ─────────────────
/// 记录在续期期间被别人改过（并发登录 / 手工粘贴）时，**不能**把这次换发结果
/// 写进去；报一句让用户知道下一次重试会以落盘那份为准。
fn renew(record: &Value, credential: &Credential) -> Result<Credential> {
    if !credential.can_refresh() {
        return Err(Error::http(
            401,
            "Accio 账号没有 refreshToken，无法续期，请重新登录或粘贴完整凭证",
        ));
    }
    // 并发续期：拿账号锁 + 锁后再读一次。排队期间别人已经换过一轮的话直接用
    // 落盘那份，绝不再拿刚被轮换掉的旧串去打一次。
    let _guard = AccountLock::acquire()?;
    // 注意：这里的参数名 `record` 遮蔽了同名函数，所以重读走显式路径
    let current_record = self::record()?;
    let expect = secret_view(record);
    let current = secret_view(&current_record);
    if current != expect && current.is_object() {
        if let Ok(fresh) = Credential::from_secret(&current) {
            if !fresh.access_token.trim().is_empty()
                && fresh.access_token != credential.access_token
            {
                return Ok(fresh);
            }
        }
    }
    let body = json!({
        "accessToken": credential.access_token,
        "refreshToken": credential.refresh_token,
    });
    let data = upstream::post_json(region::REGION, region::REFRESH_TOKEN_PATH, &body, "凭证续期")?;
    let data = upstream::unwrap_data(data);
    let token = secret_text(&data, &["accessToken", "access_token", "token"])?;
    if token.is_empty() {
        return Err(Error::http(
            502,
            "Accio 续期响应缺少 accessToken，旧凭证未被覆盖",
        ));
    }
    let mut fresh = credential.clone();
    fresh.access_token = token;
    let refresh = secret_text(&data, &["refreshToken", "refresh_token"])?;
    if !refresh.is_empty() {
        fresh.refresh_token = refresh;
    }
    // 续期响应带回新的 sgcookie 就换掉；没带就沿用旧的（clone 已经带上）
    let sgcookie = sgcookie(&data);
    if !sgcookie.is_empty() {
        fresh.sgcookie = sgcookie;
    }
    fresh.expires_at = Some(
        timestamp(data.get("expiresAt").or_else(|| data.get("expires_at")))
            .unwrap_or_else(|| sdk::now().saturating_add(DEFAULT_TTL_MS)),
    );
    // 身份/地区不允许被续期结果改掉：那意味着串号（换到了另一个账号的凭证）
    if !credential.user_id.is_empty() {
        fresh.user_id = credential.user_id.clone();
    }
    fresh.device_id = credential.device_id.clone();

    let next = merge_secret(&expect, &fresh);
    let account_id = record["id"].as_str().unwrap_or("");
    if account_id.is_empty() {
        return Err(Error::http(409, "Accio 续期结果无法写回（账号记录缺 id），请重新添加该账号"));
    }
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": view(&next) }),
    )?;
    if result["updated"] != true {
        return Err(Error::http(
            409,
            "Accio 续期结果与账号记录不匹配（期间被改过），本次换发未落盘，请重试",
        ));
    }
    Ok(fresh)
}

/// 把续期结果并进既有 secret（**空值不覆盖**）。
///
/// 与 native `update_accio_credentials_if_current` 的「只并非空字段」逐条对齐：
/// 重新登录时只给了一个 accessToken，不该把上次的 refreshToken / expiresAt 洗掉。
pub fn merge_secret(expect: &Value, fresh: &Credential) -> Value {
    let mut next = expect.clone();
    if !next.is_object() {
        next = json!({});
    }
    if let Some(object) = next.as_object_mut() {
        for (key, value) in [
            ("accessToken", fresh.access_token.clone()),
            ("refreshToken", fresh.refresh_token.clone()),
            ("userId", fresh.user_id.clone()),
            ("email", fresh.email.clone()),
            ("nickname", fresh.name.clone()),
            ("deviceId", fresh.device_id.clone()),
            ("sgcookie", fresh.sgcookie.clone()),
        ] {
            if value.is_empty() {
                continue;
            }
            object.insert(key.to_string(), Value::String(value));
        }
        object.insert(
            "mode".to_string(),
            Value::String(region::REGION.edition().to_string()),
        );
        if let Some(expires_at) = fresh.expires_at {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Bearer ` 前缀必须剥掉，否则上游按空格切分拿到的是字面量（稳定 401）。
    #[test]
    fn strips_bearer_prefix() {
        let secret = json!({ "accessToken": "Bearer abc.def" });
        assert_eq!("abc.def", Credential::from_secret(&secret).map(|c| c.access_token).unwrap_or_default());
    }

    /// 脏值不进头：非 ASCII 的 deviceId 会退回按身份派生的稳定指纹。
    #[test]
    fn utdid_falls_back_for_dirty_device_id() {
        let mut credential = Credential { user_id: "u1".to_string(), device_id: "设备".to_string(), ..Credential::default() };
        let utdid = credential.utdid();
        assert!(utdid.starts_with("desktop-"));
        assert!(utdid.bytes().all(|byte| byte.is_ascii()));
        // 有合法值时原样用
        credential.device_id = "desktop-abc".to_string();
        assert_eq!("desktop-abc", credential.utdid());
    }

    /// 秒级时间戳要按秒升到毫秒；RFC3339 也要认（上游两种形态都出现过）。
    #[test]
    fn timestamps_are_normalized() {
        assert_eq!(Some(1_789_000_000_000), timestamp(Some(&json!(1_789_000_000))));
        assert_eq!(Some(1_789_000_000_000), timestamp(Some(&json!(1_789_000_000_000_i64))));
        assert_eq!(None, timestamp(Some(&json!(0))));
        assert_eq!(
            Some(1_700_000_000_000),
            timestamp(Some(&json!("2023-11-14T22:13:20Z")))
        );
    }

    /// 身份带地区：两地同 userId 不能撞同一条记录。
    #[test]
    fn identity_is_region_scoped() {
        let identity = identity(&json!({ "userId": "42" }));
        assert_eq!(format!("accio-{}-42", region::REGION.edition()), identity);
    }
}
