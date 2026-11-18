//! AutoClaw 凭证：解析、身份、续期与写回。
//!
//! ── 与 native 的差别：四个来源 → 一个来源 ─────────────────────
//! native 的凭证来源有优先级链（账号记录 → 桌面端 `auth.json` → 网关配置 →
//! 环境变量）。wasm 沙箱**没有文件系统、没有环境变量**，能用的只有**账号记录**
//! 一条 —— 这不是取舍，是沙箱的边界。三处后果都写在这里，别在别处再猜：
//!   · 「导入桌面端登录态」这条路不存在（`account.normalize` 会如实回绝）；
//!   · 账号记录里的 `enc:` 密文**无法解密**（DPAPI 的 os_crypt 密钥拿不到），
//!     因此只接受明文 token —— 用户需要先在桌面端手动导出凭据；
//!   · 刷新结果**必须回写账号库**（native 对桌面态「不回写」的那条纪律在这里
//!     不适用：本插件没有别的落点）。
//!
//! ── 身份从哪来 ──────────────────────────────────────────────
//! AutoClaw 的 token 是 JWT（能解出 `user_id` / `device_id` / `exp`，**不验签**），
//! 所以身份优先读记录字段，其次读 JWT 声明。都没有时返回空串（让账号落库时按
//! 「未知账号」处理，而不是造一个随机身份 —— 那会在每次重登时堆出重复账号）。
//!
//! ── 设备指纹 device_id ──────────────────────────────────────
//! 官方客户端是「ed25519 公钥的 SHA-256」，但服务端只把它当一个不透明的 64 位
//! 十六进制串。生成密码学随机的 32 字节十六进制串即可 —— 它承担的全部职责
//! 就是「区分不同设备」，且是 `agent-send-code` / `zai-oauth-url` 的必填项
//! （不带会得到误导性的 `400001 请求数据有问题`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::codec;
use super::region::{self, Region};
use super::upstream;

/// 临期窗口（对齐官方 `DESKTOP_REFRESH_AHEAD_MS`：5 分钟）
pub const REFRESH_AHEAD_MS: i64 = 5 * 60 * 1000;

/// 「每小时无条件刷一次」的间隔。目的不是等 token 快过期，而是把 refresh_token
/// 温着（服务端会轮换它，长期闲置的那一份可能被判失效）。
const HOURLY_REFRESH_MS: i64 = 60 * 60 * 1000;

/// 上游没给到期时间时的保守默认：1 小时
const DEFAULT_TTL_MS: i64 = 60 * 60 * 1000;

/// 桌面端账号的固定记录 id（代表「客户端此刻登录的那个号」）。
///
/// wasm 侧读不到桌面端登录态，这个 id 只在识别**旧版本留下的记录**时用到：
/// 命中它时一律按「无法读取本机登录态」回绝，而不是拿空 token 去打上游。
pub const DESKTOP_ACCOUNT_ID: &str = "desktop-auth";

/// 一次刷新 / 一次转发用到的凭证快照。
#[derive(Clone, Default)]
pub struct Credential {
    /// 记录 id（账号库主键；空串表示还没有落库）
    pub id: String,
    pub token: String,
    pub refresh_token: String,
    pub device_id: String,
    pub user_id: String,
    pub email: String,
    pub expires_at: Option<i64>,
    /// 是否来自「桌面端登录态」记录（wasm 侧读不到，只用于给出准确的错误文案）
    pub desktop: bool,
}

impl Credential {
    /// 记录里的明文 token 是否可用（不触发网络）。
    pub fn valid(&self) -> bool {
        !self.token.trim().is_empty()
    }

    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    /// 临期判定（5 分钟窗口）。
    pub fn is_expiring(&self) -> bool {
        self.expires_at
            .is_some_and(|expiry| expiry <= sdk::now().saturating_add(REFRESH_AHEAD_MS))
    }
}

/// `js_text`：JS `String(x)` 的等价物（JWT 里的数字 user_id 也要能取出来）。
pub fn js_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// `js_number`：JS `Number(x)` 的等价物（只给 JWT 的 exp 用）。
pub fn js_number(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

/// 取一个文本字段（空串按缺失处理）。
pub fn text(payload: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| match payload.get(*key) {
            Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_string()),
            Some(Value::Number(value)) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// 记录 → 凭证。
///
/// `fallback` 是「调用方以为它属于谁」；记录里自己的 `provider` 才是事实来源。
pub fn from_record(record: &Value, fallback: Region) -> Result<Credential> {
    let _region = record
        .get("provider")
        .and_then(Value::as_str)
        .and_then(Region::from_provider_id)
        .unwrap_or(fallback);
    // 源实现的取法是「token 非空就用 token，否则看 accessToken」—— **不是**
    // `token ?? accessToken`：`token` 存在但是空串时也要落到 `accessToken`
    // （账号记录被手工编辑过就是这个形态）。
    let pick = |key: &str| -> String {
        record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let mut raw_token = pick("token");
    if raw_token.is_empty() {
        raw_token = pick("accessToken");
    }
    let raw_refresh = pick("refreshToken");
    if raw_token.starts_with("enc:") || raw_refresh.starts_with("enc:") {
        return Err(Error::http(
            401,
            "AutoClaw 记录里是加密凭证（enc:），wasm 插件无法解密（缺少桌面端的 os_crypt 密钥）；\
             请在桌面端导出明文 token 后重新添加",
        ));
    }
    let token = codec::strip_bearer(&raw_token);
    if token.is_empty() {
        return Err(Error::http(401, "AutoClaw 账号缺少 token，请重新添加"));
    }
    let claims = codec::jwt_claims(&token);
    let user_id = {
        let explicit = text(record, &["userId", "user_id"]);
        if !explicit.is_empty() {
            explicit
        } else {
            claims
                .as_ref()
                .and_then(|claims| claims.get("user_id"))
                .map(js_text)
                .unwrap_or_default()
        }
    };
    let device_id = {
        let explicit = text(record, &["deviceId"]);
        if !explicit.is_empty() {
            explicit
        } else {
            claims
                .as_ref()
                .and_then(|claims| claims.get("device_id"))
                .map(js_text)
                .unwrap_or_default()
        }
    };
    let expires_at = {
        // 账号记录里的过期时间优先（可能是上次刷新后写回的值，比 JWT 更贴近实际）。
        // 两个键都认：`expiresAt` 是网关口径，`tokenExpiresAt` 是本插件旧口径
        // （写回时两套同时写，见 `write_back`）；都在时取较新的那个。
        let explicit = ["expiresAt", "tokenExpiresAt"]
            .iter()
            .filter_map(|key| record.get(*key).and_then(js_number))
            .reduce(f64::max);
        explicit
            .filter(|value| *value > 0.0)
            .map(|value| value as i64)
            .or_else(|| {
                claims
                    .as_ref()
                    .and_then(|claims| claims.get("exp"))
                    .and_then(js_number)
                    .filter(|value| *value > 0.0)
                    .map(|value| (value * 1000.0) as i64)
            })
    };
    Ok(Credential {
        id: text(record, &["id"]),
        token,
        refresh_token: codec::strip_bearer(&raw_refresh),
        device_id,
        user_id,
        email: text(record, &["email"]),
        expires_at,
        desktop: record.get("desktop").and_then(Value::as_bool).unwrap_or(false)
            || text(record, &["id"]) == DESKTOP_ACCOUNT_ID,
    })
}

/// 账号的公开视图（界面账号页读的那几个键）。
///
/// ── 为什么邮箱很重要（别删）─────────────────────────────────
/// 国际版的主登录方式是 Zai / Google OAuth，换回来的 token 里**没有邮箱**
/// （JWT 只有 `user_id` / `device_id` / `guid`），界面副标题就只剩上游用户名；
/// 同一个人在两地的账号、或几个同类账号之间分不清。邮箱由本模块在网页登录 /
/// 余额查询时补写到记录里，这里读它。
pub fn view(secret: &Value) -> Value {
    let token = text(secret, &["token", "accessToken", "access_token"]);
    let email = text(secret, &["email"]);
    let user_id = text(secret, &["userId", "user_id"]);
    let name = {
        let explicit = text(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !email.is_empty() {
            email.clone()
        } else if !user_id.is_empty() {
            format!("AutoClaw {}账号 {user_id}", region::REGION.label())
        } else {
            format!("AutoClaw {}账号", region::REGION.label())
        }
    };
    let desktop = secret.get("desktop").and_then(Value::as_bool).unwrap_or(false);
    let mut view = json!({
        "name": name,
        "userId": user_id,
        "email": email,
        "tokenTail": token_tail(&token),
        "hasSession": true,
        "desktop": desktop,
        "region": region::REGION.provider_id(),
        "canRefresh": !text(secret, &["refreshToken"]).is_empty(),
    });
    // 与 `from_record` 同一口径：`expiresAt`（网关）与 `tokenExpiresAt`（旧投影）
    // 都认，都在时取较新的那个。
    let expires_at = ["tokenExpiresAt", "expiresAt"]
        .iter()
        .filter_map(|key| secret.get(*key).and_then(js_number))
        .reduce(f64::max);
    if let Some(expires_at) = expires_at.filter(|value| *value > 0.0) {
        if let Some(object) = view.as_object_mut() {
            object.insert("tokenExpiresAt".to_string(), json!(expires_at as i64));
            object.insert("expiresAt".to_string(), json!(expires_at as i64));
        }
    }
    view
}

/// 账号的稳定身份（去重用）：`user-<userId>`（国际版 `intl-user-<userId>`）。
pub fn identity(secret: &Value) -> String {
    let user_id = text(secret, &["userId", "user_id"]);
    if user_id.is_empty() {
        return String::new();
    }
    // 桌面端账号固定 id（每个地区一条，代表「客户端此刻登录的那个号」）
    if secret.get("desktop").and_then(Value::as_bool).unwrap_or(false) {
        return format!("{}-desktop", region::REGION.provider_id());
    }
    format!("{}{user_id}", region::REGION.account_id_prefix())
}

/// 令牌尾巴（界面识别用；永不回显完整值）。
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(6);
    chars[start..].iter().collect()
}

// ─── 账号记录与令牌 ──────────────────────────────────────────

/// 当前账号记录（宿主没给账号时按 native 的口径报 401）。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if record.is_null() {
        return Err(Error::http(401, "没有可用的 AutoClaw 账号，请先在「账号」页添加"));
    }
    Ok(record)
}

/// 记录 → 凭证（附带「桌面态」的准确回绝）。
pub fn credential(record: &Value) -> Result<Credential> {
    let credential = from_record(record, region::REGION)?;
    if credential.desktop {
        return Err(Error::http(
            401,
            format!(
                "AutoClaw {}的「桌面端登录态」记录无法在 wasm 插件里读取（沙箱没有文件系统）；\
                 请改用手机验证码 / 网页登录，或粘贴明文 token",
                region::REGION.label()
            ),
        ));
    }
    Ok(credential)
}

/// 去掉展示用的空值（`name` / `email` 这些留空串即可，不必删）。
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
    if !credential.is_expiring() || !credential.can_refresh() {
        return Ok(credential.token);
    }
    credential = renew(&record, &credential)?;
    Ok(credential.token)
}

/// 401 之后的**强制**续期：不看临期窗口，直接换发。
///
/// 为什么必须这样：`ensure` 只在「临期」时刷新，而 401 完全可能发生在一个
/// 时间上还很新的 token 上（服务端侧失效、账号被顶下线、refreshToken 轮换）。
/// 此时只调 ensure 会拿回同一个被拒的 token，编排层的「刷新后重试一次」就
/// 退化成「用同一个坏 token 再打一次」。
pub fn refresh() -> Result<String> {
    let record = record()?;
    let credential = credential(&record)?;
    Ok(renew(&record, &credential)?.token)
}

/// 后台凭证维护问「这条账号是不是快到期了」。
///
/// ── 每小时强制刷新 ────────────────────────────────────────
/// 除了临期窗口，还接上官方那条「每小时无条件刷一次」的语义。只在本方法做、
/// 不在 `is_expiring()` 里做 —— 后者被转发链路每请求调用一次，在那里「每小时
/// 一次」会退化成「每请求一次」。
pub fn expiring() -> bool {
    let Ok(record) = sdk::account() else { return false };
    if record.is_null() {
        return false;
    }
    let Ok(credential) = credential(&record) else { return false };
    if !credential.can_refresh() {
        return false;
    }
    credential.is_expiring() || hourly_due()
}

/// 「每小时一次」的节拍：用宿主 session 记上次强制刷新的时刻。
fn hourly_due() -> bool {
    let key = format!("autoclaw.hourly:{}", region::REGION.provider_id());
    match sdk::session_get(&key) {
        Ok(value) => value["at"]
            .as_i64()
            .map(|at| sdk::now().saturating_sub(at) >= HOURLY_REFRESH_MS)
            .unwrap_or(true),
        // 没有记录 = 这一轮该刷（新实例 / 宿主重启过）
        Err(_) => true,
    }
}

fn mark_hourly() {
    let key = format!("autoclaw.hourly:{}", region::REGION.provider_id());
    let _ = sdk::session_put(&key, json!({ "at": sdk::now() }), HOURLY_REFRESH_MS);
}

/// 换发并回写（比较再写）。
fn renew(record: &Value, credential: &Credential) -> Result<Credential> {
    if !credential.can_refresh() {
        return Err(Error::http(
            401,
            "该账号没有 refreshToken，无法刷新；请在 AutoClaw 客户端重新登录后重新添加",
        ));
    }
    // 并发续期：拿账号锁 + 锁后再读一次。排队期间别人已经换过一轮的话直接用
    // 落盘那份，绝不再拿刚被轮换掉的旧串去打一次（那才会真把账号弄丢）。
    // 注意：参数名 `record` 遮蔽了同名函数，所以重读走显式路径
    let _guard = AccountLock::acquire()?;
    let current_record = self::record()?;
    let expect = secret_view(record);
    let current = secret_view(&current_record);
    if current != expect && current.is_object() {
        if let Ok(fresh) = from_record(&current, region::REGION) {
            if fresh.valid() && fresh.token != credential.token {
                return Ok(fresh);
            }
        }
    }
    let mut payload = upstream::call_refresh_unauth(credential, "/userapi/v1/refresh")?;
    // 若 `code == 400002`（刷新签名校验失败）→ 降级 `agent-refresh` 再试一次
    if payload.get("code").and_then(js_number).map(|code| code as i64) == Some(400_002) {
        payload = upstream::call_refresh_unauth(credential, "/userapi/v1/agent-refresh")?;
    }
    let code = payload.get("code").and_then(js_number);
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let access_token = data
        .get("access_token")
        .map(js_text)
        .map(|text| codec::strip_bearer(&text))
        .unwrap_or_default();
    if code != Some(0.0) || access_token.is_empty() {
        // 状态码口径照抄源实现：`code === 41e4 || code === 401` → 401，其余 502。
        // **注意 `41e4` 是 JS 的科学计数法 = 410000**（不是 41000000），写成数字
        // 字面量时极易看错位数，这里显式写成 410_000 并注明来源。
        let unauthorized = code == Some(401.0) || code == Some(410_000.0);
        return Err(Error::http(
            if unauthorized { 401 } else { 502 },
            format!(
                "AutoClaw token 刷新失败 code={} msg={}",
                payload.get("code").map(js_text).unwrap_or_else(|| "null".to_string()),
                payload
                    .get("msg")
                    .or_else(|| payload.get("message"))
                    .map(js_text)
                    .unwrap_or_else(|| "服务器未返回新 token".to_string()),
            ),
        ));
    }
    let next_refresh = data
        .get("refresh_token")
        .map(js_text)
        .map(|text| codec::strip_bearer(&text))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| credential.refresh_token.clone());
    let claims = codec::jwt_claims(&access_token);
    let mut next = Credential {
        id: credential.id.clone(),
        token: access_token,
        refresh_token: next_refresh,
        device_id: credential.device_id.clone(),
        user_id: claims
            .as_ref()
            .and_then(|claims| claims.get("user_id"))
            .map(js_text)
            .unwrap_or_default(),
        email: credential.email.clone(),
        expires_at: claims
            .as_ref()
            .and_then(|claims| claims.get("exp"))
            .and_then(js_number)
            .filter(|value| *value > 0.0)
            .map(|value| (value * 1000.0) as i64)
            .or_else(|| Some(sdk::now().saturating_add(DEFAULT_TTL_MS))),
        desktop: false,
    };
    // JWT 解不出身份 / 设备时保留旧值（服务端偶尔不回这些声明）
    if next.user_id.is_empty() {
        next.user_id = credential.user_id.clone();
    }
    if next.device_id.is_empty() {
        next.device_id = credential.device_id.clone();
    }
    write_back(record, credential, &next)?;
    mark_hourly();
    Ok(next)
}

/// 刷新结果回写账号库（**两套键同时写**）。
///
/// ── 为什么两套键都写（issue #22）──────────────────────────────
/// `token` / `tokenExpiresAt` 是本插件与旧投影的口径；`accessToken` /
/// `expiresAt` 是网关账号存储与界面读的口径（`account_store::state` 读后者）。
/// 只写前者时网关那两栏读不到，回写等于白写。
fn write_back(record: &Value, previous: &Credential, next: &Credential) -> Result<()> {
    let expect = secret_view(record);
    let mut secret = expect.clone();
    if !secret.is_object() {
        secret = json!({});
    }
    if let Some(object) = secret.as_object_mut() {
        for (key, value) in [
            ("token", next.token.clone()),
            ("accessToken", next.token.clone()),
            ("refreshToken", next.refresh_token.clone()),
            ("deviceId", next.device_id.clone()),
        ] {
            if value.is_empty() {
                continue;
            }
            object.insert(key.to_string(), Value::String(value));
        }
        if !next.user_id.is_empty() {
            object.insert("userId".to_string(), Value::String(next.user_id.clone()));
        }
        if !next.email.is_empty() {
            object.insert("email".to_string(), Value::String(next.email.clone()));
        }
        if let Some(expires_at) = next.expires_at {
            object.insert("tokenExpiresAt".to_string(), json!(expires_at));
            object.insert("expiresAt".to_string(), json!(expires_at));
        }
    }
    // 没刷新就不必写（token 逐字相同）
    if previous.token == next.token && previous.refresh_token == next.refresh_token {
        return Ok(());
    }
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": secret, "public": view(&secret) }),
    )?;
    if result["updated"] != true {
        return Err(Error::http(
            409,
            "AutoClaw 续期结果与账号记录不匹配（期间被改过），本次换发未落盘，请重试",
        ));
    }
    Ok(())
}

/// 生成设备 id（32 字节随机 → 64 位十六进制）。
pub fn new_device_id() -> String {
    codec::random_hex_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Bearer ` 前缀必须剥掉；`token` 为空时落到 `accessToken`。
    #[test]
    fn record_parsing_prefers_token_then_access_token() {
        let record = json!({ "id": "user-1", "token": "Bearer a.b.c", "refreshToken": "r" });
        let credential = from_record(&record, region::REGION).unwrap_or_default();
        assert_eq!("a.b.c", credential.token);
        let record = json!({ "id": "user-1", "token": "", "accessToken": "plain" });
        let credential = from_record(&record, region::REGION).unwrap_or_default();
        assert_eq!("plain", credential.token);
    }

    /// 加密凭证在 wasm 侧必须如实回绝（解密需要桌面端的 os_crypt 密钥）。
    #[test]
    fn encrypted_tokens_are_rejected() {
        let record = json!({ "token": "enc:AAAA" });
        let error = from_record(&record, region::REGION).err();
        assert_eq!(Some(401), error.and_then(|error| error.status));
    }

    /// 身份带地区前缀：两地同 userId 不能撞同一条记录。
    #[test]
    fn identity_is_region_scoped() {
        let identity = identity(&json!({ "userId": "42" }));
        assert_eq!(format!("{}{}", region::REGION.account_id_prefix(), "42"), identity);
    }

    /// 到期时间两套键都认，取较新的那个。
    #[test]
    fn expiry_reads_both_keys() {
        let record = json!({ "token": "a", "expiresAt": 1000, "tokenExpiresAt": 2000 });
        assert_eq!(Some(2000), from_record(&record, region::REGION).unwrap_or_default().expires_at);
    }
}
