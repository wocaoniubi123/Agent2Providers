//! Trae 账号面：凭据形态、续期、公开视图、稳定身份、导入归一化。
//!
//! ── 哪些是长期的、哪些是短期的 ────────────────────────────
//! `accessToken` 是 **Cloud-IDE-JWT**，约 14 天到期；`refreshToken` 长期但
//! **每次 ExchangeToken 都轮换**（一次性）。所以"能不能续"取决于 refreshToken
//! 在不在，而"要不要续"取决于 accessToken 的到期时刻 —— 到期时刻优先信
//! JWT 自己的 `exp`，落盘字段只作兜底（参考实现两处都读）。
//!
//! 另外三个字段是**设备指纹**：`machineId` / `deviceId` 与登录时上传的公钥
//! 一起被服务端绑定（`CheckLogin` 会回 `BoundDeviceID` / `DeviceBindStatus`）。
//! 它们必须与凭据同生共死：换掉它们等于换了一台设备，社区明确把
//! "每次随机 deviceId" 标成风控隐患。
//!
//! ── 身份怎么认（为什么不能按令牌尾巴去重）──────────────────
//! 去重键是 `(variant, uid)`，uid 由 `profile` 那条优先级决定
//! （GetUserInfo → 回调回显 → 每个 variant 固定的 unknown 名）。
//! 参考实现在这里摔过并被用户报告（v0.12.25）：拿 per-login 的 trace id 兜底
//! 时，同一个账号登两次就落两条记录。所以 `identity_of` 也**只由这两项派生**。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::profile;
use super::refresh::{self, MAX_ISSUE_AGE_MS, REFRESH_LEAD_MS};

pub const DEFAULT_VARIANT: &str = "solo";

/// 拒绝 Intl 谱系时给的那句理由（三处入口共用一份文案，别说三种话）。
pub const INTL_UNSUPPORTED: &str = "Trae 国际版（intl / solo-intl）暂未接入：本提供商支持 trae.cn 国内账号，按模型目录选择 Agent / IDE 聊天通道。请使用国内账号；国际版需要独立的提供商身份与目录，不能复用国内令牌。";

/// 账号名长度上限（与网关 `truncate_text(&record_name, 100)` 同口径）。
const MAX_NAME_LENGTH: usize = 100;

/// 一条 Trae 凭据。字段名与落盘形态一致（驼峰），因为账号存储就是按
/// 参考实现的 auth 文件形状读写（嵌套 `{type, provider, auth{…}, account{…}}`
/// 与平铺两种都认，见 `from_payload`）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Credential {
    pub access_token: String,
    pub refresh_token: String,
    /// accessToken 的到期时刻（Unix 秒或毫秒都接受，读的时候归一）。
    pub expires_at: i64,
    pub domain: String,
    /// OAuth/积分那条链的 host（`ExchangeToken` 的第一候选）。
    pub api_host: String,
    pub machine_id: String,
    pub device_id: String,
    pub variant: String,
    pub uid: String,
    pub enterprise_id: String,
    pub nickname: String,
    /// 登录时那套设备密钥的**公钥**（SPKI PEM，随 ExchangeToken 上传过的那份）。
    ///
    /// 落盘它不是为了再用它发请求，而是为了让"这台设备绑定过哪个账号"这件事
    /// 在凭据里可读回来 —— 服务端按 DevicePublicKey + DeviceID/MachineID 做绑定，
    /// 出问题时（20405 那族）第一件事就是要能看见当时上传的是哪把公钥。
    pub device_public_key: String,
    /// 登录时那套设备密钥的私钥（PKCS#8 PEM）。
    ///
    /// 参考实现**只写不读**（全目录 grep `devicePrivateKey` 只有写入与
    /// "重建时不许丢"的夹具测试）。这里同样只存不用，但必须存：
    /// 写回凭据时把它抹掉，就等于把这台设备的绑定关系弄断了。
    pub device_private_key: String,
    /// 这张 refreshToken **当初是在哪个 OAuth 应用里 mint 的**（上游在
    /// `ExchangeToken` 响应里回显 `Result.ClientID`，CPA 的 auth 文件里同名
    /// 字段叫 `authClientId`）。
    ///
    /// 空串 = 不知道（老数据 / 手工粘贴没带），那时才回退到按 variant 推。
    pub auth_client_id: String,
}

/// 国际版谱系（`intl` / `solo-intl`）。
///
/// 本 provider 只服务国内账号，国际版必须另立身份与目录。
/// 两地令牌不通用，不能因为共用部分聊天信封就放行国际版凭据。
/// 大小写无关，账号导入与转发入口使用同一道闸门。
pub fn is_intl_variant(variant: &str) -> bool {
    matches!(variant.trim().to_lowercase().as_str(), "intl" | "solo-intl")
}

impl Credential {
    pub fn valid(&self) -> bool {
        !self.access_token.trim().is_empty()
    }

    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    /// ClientID 按 variant 选，未知值兜到 solo。
    pub fn variant(&self) -> &str {
        match self.variant.as_str() {
            "cn" | "solo" | "intl" | "solo-intl" => &self.variant,
            _ => DEFAULT_VARIANT,
        }
    }

    /// 到期时刻统一成**毫秒**。
    ///
    /// 上游与各家客户端在秒与毫秒之间来回漂过（参考实现为此留了
    /// `normalizeExpiresAt`），所以按数量级判：小于 1e11 的当秒用
    /// （1e11 秒 ≈ 公元 5138 年，真毫秒值不可能小于它）。
    pub fn expires_at_ms(&self) -> i64 {
        if self.expires_at <= 0 {
            return 0;
        }
        if self.expires_at < 100_000_000_000 {
            self.expires_at.saturating_mul(1000)
        } else {
            self.expires_at
        }
    }

    /// JWT 里的到期时刻（毫秒），解不出来返回 None。
    ///
    /// 只看第二段、不验签：这不是安全判定，只是"还有多久要续"的读数来源。
    ///
    /// ── 为什么除 `exp` 之外还认 `TokenExpireAt` ────────────────
    /// 中国版的令牌把到期写在**自定义声明** `TokenExpireAt` 里而不是标准 `exp`；
    /// 旧解析只认 `exp`，中国版的令牌解出来是 None ⇒ 有效期落到落盘字段，
    /// 而落盘那份在换证时同样是坏的（中国版 `TokenExpireAt` 是**字符串**）。
    pub fn jwt_expires_at_ms(&self) -> Option<i64> {
        let from_claim = |claim: &str| {
            jwt_claim(&self.access_token, claim).map(|raw| {
                if raw < 100_000_000_000 {
                    raw.saturating_mul(1000)
                } else {
                    raw
                }
            })
        };
        from_claim("exp")
            .or_else(|| from_claim("TokenExpireAt"))
            .or_else(|| from_claim("tokenExpireAt"))
    }

    /// JWT 里的 `iat`（秒）。参考实现额外用它在签发龄超 15 天时强制轮换
    /// （服务端有吊销旧凭据的风险），所以这个读数不是装饰。
    pub fn jwt_issued_at_seconds(&self) -> Option<i64> {
        jwt_claim(&self.access_token, "iat")
    }

    /// 有效到期时刻：JWT 声明优先，落盘字段兜底。
    pub fn effective_expiry_ms(&self) -> i64 {
        self.jwt_expires_at_ms().unwrap_or_else(|| self.expires_at_ms())
    }

    /// 是否需要续期：临期（`lead` 之内）**或**签发龄超过 `max_age`。
    ///
    /// 两个条件都要：只看临期的话，一个刚签发但服务端已吊销的令牌会被
    /// 当成"还早"，等到真用它时才 401（那时 refreshToken 可能也已经换过一轮）。
    pub fn needs_refresh(&self, lead_ms: i64, max_issue_age_ms: i64, now_ms: i64) -> bool {
        let expiry = self.effective_expiry_ms();
        if expiry > 0 && expiry - now_ms <= lead_ms {
            return true;
        }
        if max_issue_age_ms <= 0 {
            return false;
        }
        self.jwt_issued_at_seconds()
            .map(|issued| now_ms.saturating_sub(issued * 1000) >= max_issue_age_ms)
            .unwrap_or(false)
    }

    /// 从账号记录里读凭据：嵌套（CPA auth 文件形状）与平铺都认。
    ///
    /// 只认驼峰键（与参考实现落盘一致）。看到 `access_key_id` 那一类蛇形键
    /// **直接报错**而不是当空凭据收下 —— 那是别家的形状，静默接受会让一个
    /// 明显有数据的账号显示成"缺凭据"。
    pub fn from_payload(payload: &Value) -> std::result::Result<Self, String> {
        let auth = payload.get("auth").filter(|value| value.is_object()).unwrap_or(payload);
        let account = payload.get("account").filter(|value| value.is_object());
        let text = text_of;
        let number = |object: &Value, key: &str| -> i64 {
            object.get(key).and_then(Value::as_f64).map(|value| value as i64).unwrap_or(0)
        };
        // OAuth 归属（哪把 ClientID mint 的这张 refreshToken）。四种写法都认：
        // 本家与 CPA 落盘是 `authClientId`，上游响应回显是 `ClientID`，
        // 手工粘贴可能给小写 `clientId`；嵌套 `auth{}` 与平铺 payload 两个位置都找。
        let auth_client_id = [
            text(auth, "authClientId"),
            text(auth, "ClientID"),
            text(auth, "clientId"),
            text(payload, "authClientId"),
        ]
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default();
        let credential = Self {
            access_token: text(auth, "accessToken"),
            refresh_token: text(auth, "refreshToken"),
            expires_at: number(auth, "expiresAt"),
            domain: text(auth, "domain"),
            api_host: text(auth, "apiHost"),
            machine_id: text(auth, "machineId"),
            device_id: text(auth, "deviceId"),
            variant: text(auth, "variant"),
            uid: text_either(account, auth, "uid"),
            enterprise_id: text_either(account, auth, "enterpriseId"),
            nickname: text_either(account, auth, "nickname"),
            device_public_key: text(auth, "devicePublicKey"),
            device_private_key: text(auth, "devicePrivateKey"),
            auth_client_id,
        };
        if credential.access_token.trim().is_empty() && credential.refresh_token.trim().is_empty() {
            return Err("Trae 凭据里既没有 accessToken 也没有 refreshToken".to_string());
        }
        Ok(credential)
    }

    /// 写回账号记录用的那部分字段（**只并这些键**，不重建整条记录）。
    ///
    /// 参考实现里出过事故的那条：面板签到前的预刷新走了"重建"路径，
    /// refreshToken 保住了但设备密钥与一堆对拍扩展字段被抹掉。
    /// 所以这里给的是"字段补丁"，落盘侧只做覆盖写。
    pub fn patch_fields(&self) -> Vec<(&'static str, Value)> {
        let mut fields = vec![
            ("accessToken", Value::String(self.access_token.clone())),
            ("refreshToken", Value::String(self.refresh_token.clone())),
            // 落盘**统一成毫秒**。手工粘贴与 CPA auth 文件是秒（`1791009732`），
            // 上游刷新响应是毫秒。存秒会让面板显示成「1970 年到期」。
            ("expiresAt", Value::from(self.expires_at_ms())),
            ("domain", Value::String(self.domain.clone())),
            ("apiHost", Value::String(self.api_host.clone())),
            ("machineId", Value::String(self.machine_id.clone())),
            ("deviceId", Value::String(self.device_id.clone())),
            ("variant", Value::String(self.variant().to_string())),
        ];
        if !self.device_public_key.is_empty() {
            fields.push(("devicePublicKey", Value::String(self.device_public_key.clone())));
        }
        if !self.device_private_key.is_empty() {
            fields.push(("devicePrivateKey", Value::String(self.device_private_key.clone())));
        }
        // 只在知道的时候写：空串落盘会把 CPA 那边迁来的 `authClientId` 抹掉，
        // 而那个值一旦没了，续期就又只能按 variant 猜（猜错就是 10101）
        if !self.auth_client_id.is_empty() {
            fields.push(("authClientId", Value::String(self.auth_client_id.clone())));
        }
        fields
    }
}

/// `account` 段优先，取不到（或为空）再回落到 `auth` 段。
///
/// 参考实现把身份放在 `account{uid,nickname,enterpriseId}`，而手工粘贴的
/// 凭据常常是平铺的 —— 两个位置都读一次，才不会让"明明填了昵称却显示空"。
fn text_either(account: Option<&Value>, auth: &Value, key: &str) -> String {
    let from_account = account.map(|object| text_of(object, key)).unwrap_or_default();
    if from_account.is_empty() {
        text_of(auth, key)
    } else {
        from_account
    }
}

fn text_of(object: &Value, key: &str) -> String {
    object
        .get(key)
        .map(|value| match value {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// 取 JWT 的一个数字声明（不验签）。
fn jwt_claim(token: &str, claim: &str) -> Option<i64> {
    let mut parts = token.trim().split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    // 声明值数字与**字符串数字**都认：中国版把 `TokenExpireAt` 放进 payload 时
    // 是字符串形态。
    let value: Value = serde_json::from_slice(&super::codec::base64_url_decode(payload.trim_end_matches('='))?).ok()?;
    match value.get(claim)? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
    .map(|number| number as i64)
}

// ── 账号记录：读、比较再写 ─────────────────────────────────────

/// 只移除记录投影补入的字段；凭证本来含有的 name 等字段必须参与比较再写。
pub fn secret_view(record: &Value) -> Value {
    if let Some(original) = record.get("_agent2apiOriginalSecret") {
        return original.clone();
    }
    let mut secret = record.clone();
    if let Some(object) = secret.as_object_mut() {
        let injected = object.remove("_agent2apiRecordKeys");
        match injected.as_ref().and_then(Value::as_array) {
            Some(keys) => {
                for key in keys.iter().filter_map(Value::as_str) {
                    object.remove(key);
                }
            }
            None => {
                for key in ["id", "provider", "name"] {
                    object.remove(key);
                }
            }
        }
        if let Some(Value::Object(originals)) = object.remove("_agent2apiOriginalIdentity") {
            for (key, value) in originals {
                object.insert(key, value);
            }
        }
        if let Some(proxy) = object.remove("_agent2apiOriginalProxy") {
            object.insert("proxy".to_string(), proxy);
        }
    }
    secret
}

/// 在 secret 上原地改几个字段（其余字段原样保留：整份替换会丢身份载荷件）。
pub fn with_fields(secret: &Value, fields: &[(&str, Value)]) -> Value {
    let mut next = if secret.is_object() { secret.clone() } else { json!({}) };
    let Some(object) = next.as_object_mut() else { return next };
    for (key, value) in fields {
        object.insert((*key).to_string(), value.clone());
    }
    next
}

/// 从 secret 里取一个非空字符串（多候选键，宽容读取）。
pub fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record.get(*key).and_then(Value::as_str).map(str::trim).unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 令牌尾 4 字符（公开视图的展示字段）。
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 当前账号记录。宿主没给账号时按 native 的口径报 401。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if record.is_null() {
        return Err(Error::http(401, "没有可用的 Trae 账号，请先在「账号」页添加"));
    }
    Ok(record)
}

/// 记录 → 凭据（secret 是 `record["secret"]`，投影字段先剥掉）。
pub fn credential(record: &Value) -> Result<Credential> {
    Credential::from_payload(&secret_view(&record["secret"]))
        .map_err(|reason| Error::http(400, reason))
}

// ── 账号视图 / 身份 / 归一化 ─────────────────────────────────

/// 账号公开视图（界面账号页读的那几个键，与 native
/// `to_trae_public_account` 逐键对应）。
///
/// ── 为什么 `expiresAtMs` 与 `expiresAt` 都给 ────────────────
/// 面板的有效期那一列与别家共用同一套按毫秒的读法（`expiresAtMs`），而
/// `expiresAt` 是落盘字段（历史上有秒也有毫秒）。两个都给，界面读哪个都对。
pub fn view(secret: &Value) -> Value {
    let access_token = pick(secret, &["accessToken"]);
    let refresh_token = pick(secret, &["refreshToken"]);
    let uid = pick(secret, &["uid"]);
    let nickname = pick(secret, &["nickname"]);
    let variant = pick(secret, &["variant"]);
    let name = {
        let explicit = pick(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !nickname.is_empty() {
            nickname.clone()
        } else {
            format!(
                "Trae {}",
                if variant.is_empty() { DEFAULT_VARIANT } else { variant.as_str() }
            )
        }
    };
    // 到期读数：先按结构体那条链（JWT 声明优先），读不出再退回落盘字段
    let expires_at_ms = Credential::from_payload(secret)
        .map(|credential| credential.effective_expiry_ms())
        .unwrap_or(0);
    let mut view = json!({
        "name": name,
        "uid": uid,
        "nickname": nickname,
        "enterpriseId": pick(secret, &["enterpriseId"]),
        "source": pick(secret, &["source"]),
        "tokenTail": token_tail(&access_token),
        "variant": variant,
        "hasRefreshToken": !refresh_token.trim().is_empty(),
        // 有 accessToken 才算「当前可用」；只有续期串的账号要先刷一次才能用
        "available": !access_token.trim().is_empty(),
        "desktop": false,
    });
    if let Some(object) = view.as_object_mut() {
        if expires_at_ms > 0 {
            object.insert("expiresAtMs".to_string(), Value::from(expires_at_ms));
            object.insert("expiresAt".to_string(), Value::from(expires_at_ms));
        }
    }
    view
}

/// 账号的稳定身份：`trae-<variant>-<uid>`。
///
/// ── 没有 uid 时为什么退到令牌指纹 ───────────────────────────
/// 不给随机 id（那会造出重复账号，见模块头）。登录链路里
/// `profile::Identity::merged` 已经保证了 unknown 兜底；手工粘贴如果真连 uid
/// 都没有，按 accessToken 派生 —— 同一串凭证重复粘贴仍然命中同一条记录。
pub fn identity(secret: &Value) -> String {
    let variant = {
        let raw = pick(secret, &["variant"]);
        if raw.is_empty() { DEFAULT_VARIANT.to_string() } else { raw }
    };
    let uid = pick(secret, &["uid"]);
    if !uid.is_empty() {
        return format!("trae-{variant}-{uid}");
    }
    let access_token = pick(secret, &["accessToken"]);
    if access_token.is_empty() {
        return String::new();
    }
    format!("trae-{variant}-token-{access_token}")
}

/// 凭据 → 可落库的账号（网页登录与手工粘贴两条路共用）。
///
/// 谱系闸门在这里判：Intl 凭据落库后必然在转发时报一句难懂的 401，
/// 所以在**入口**就拒，而不是收下一条永远不会工作的记录。
pub fn account_of(credential: &Credential, source: &str, explicit_name: Option<String>) -> Result<Value> {
    // 到期读数要在拆字段**之前**算：`effective_expiry_ms()` 读的是整份结构体
    // （JWT 声明 + 落盘字段），拆完之后拿不到完整的那一份。
    let expires_at_ms = credential.effective_expiry_ms();
    if is_intl_variant(&credential.variant) {
        return Err(Error::http(400, INTL_UNSUPPORTED));
    }
    let normalized_variant = match credential.variant.as_str() {
        "cn" | "solo" | "intl" | "solo-intl" => credential.variant.clone(),
        _ => DEFAULT_VARIANT.to_string(),
    };
    if credential.access_token.trim().is_empty() && credential.refresh_token.trim().is_empty() {
        return Err(Error::http(400, "Trae 凭据里既没有 accessToken 也没有 refreshToken"));
    }
    let mut secret = serde_json::Map::new();
    // 只写**已知**字段：手工粘贴的凭据常常只有一把 accessToken，这时空的
    // `refreshToken` / `expiresAt` **不能**写进已有记录（等于把上次登录拿到的
    // 续期串洗掉）—— 宿主按 identity 命中同一条后做的是字段合并。
    for (key, value) in [
        ("accessToken", credential.access_token.as_str()),
        ("refreshToken", credential.refresh_token.as_str()),
        ("domain", credential.domain.as_str()),
        ("apiHost", credential.api_host.as_str()),
        ("machineId", credential.machine_id.as_str()),
        ("deviceId", credential.device_id.as_str()),
        ("uid", credential.uid.as_str()),
        ("nickname", credential.nickname.as_str()),
        ("enterpriseId", credential.enterprise_id.as_str()),
        ("devicePublicKey", credential.device_public_key.as_str()),
        ("devicePrivateKey", credential.device_private_key.as_str()),
        // 空串落盘会把 CPA 那边迁来的 `authClientId` 抹掉，之后续期只能按
        // variant 猜（猜错是 10101「refresh token is not matched to the client」）
        ("authClientId", credential.auth_client_id.as_str()),
    ] {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            secret.insert(key.to_string(), Value::String(trimmed.to_string()));
        }
    }
    secret.insert("variant".to_string(), Value::String(normalized_variant.clone()));
    if expires_at_ms > 0 {
        secret.insert("expiresAt".to_string(), Value::from(expires_at_ms));
    }
    secret.insert("source".to_string(), Value::String(source.to_string()));
    // 名字：显式给的 > 上游昵称 > 「Trae <variant>」。写进 secret 是为了让
    // `view` 能读到它（界面读的是 public，而 public 由 secret 派生）。
    let name = explicit_name
        .or_else(|| Some(credential.nickname.clone()).filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| format!("Trae {normalized_variant}"));
    secret.insert("name".to_string(), Value::String(name));
    let secret = Value::Object(secret);
    Ok(json!({
        "secret": secret,
        "public": view(&secret),
        "identity": identity(&secret),
        // 本家没有「实时读本机客户端」这条来源，恒 false
        "desktop": false,
    }))
}

/// `account.normalize`：只认手工粘贴（网页登录走 `login.*`）。
///
/// native 侧明确拒掉的两条路在这里原样保留理由：
///   * 桌面端登录态在客户端自己的加密存储里，插件读不到；
///   * 凭证是令牌不是文件，没有"导入文件"这回事。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => manual_payload(inputs_of(&source["payload"]))?,
        Some("desktop") => {
            return Err(Error::http(400, "Trae 不支持导入桌面端登录态，请用「网页登录」或粘贴凭证添加账号"))
        }
        Some("file_text") | Some("file_base64") => {
            return Err(Error::http(400, "Trae 没有可导入的凭证文件（凭证是令牌），请粘贴 accessToken / 整份 auth 文件内容"))
        }
        _ => return Err(Error::http(400, "Trae 请用「网页登录」或粘贴凭据添加账号")),
    };
    let mut credential = Credential::from_payload(&payload).map_err(|reason| Error::http(400, reason))?;
    // 身份是 best-effort 的读数（昵称 / uid 只影响显示与去重）：粘贴的凭据
    // 一般不带 uid，这里替用户问一次上游。问不到也照样落账号 ——
    // 「登录已成功却因为读不到昵称而判失败」是本家明确要避免的那种行为。
    if credential.uid.is_empty() {
        if let Ok(identity) = profile::get_user_info(&credential) {
            credential.uid = identity.uid;
            credential.nickname = identity.nickname;
            credential.enterprise_id = identity.enterprise_id;
        }
    }
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_NAME_LENGTH).collect::<String>());
    account_of(&credential, "manual", name)
}

/// 面板表单字段的位置：`auth.methods` 的 api 方式把输入包在 `inputs` 里
/// 交给网关，网关按 `NormalizeSource::Manual` 原样透传 —— 不解包就会把整个
/// `{methodIndex, inputs}` 当成凭据正文（粘贴任何东西都报「缺 accessToken」）。
/// 裸文本（手工粘贴的老路径）没有 `inputs`，原样返回。
fn inputs_of(payload: &Value) -> &Value {
    payload
        .get("inputs")
        .filter(|inputs| inputs.is_object())
        .unwrap_or(payload)
}

/// 表单贴进来的东西：可能整份是 JSON（CPA auth 文件），也可能只是一把
/// accessToken —— 两种都收，形状不对才报"缺凭据"。
fn manual_payload(payload: &Value) -> Result<Value> {
    let text = match payload {
        Value::String(text) => text.clone(),
        Value::Object(object) => object
            .get("credentialJson")
            .or_else(|| object.get("content"))
            .or_else(|| object.get("text"))
            .or_else(|| object.get("token"))
            .or_else(|| object.get("accessToken"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| payload.to_string()),
        _ => payload.to_string(),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Error::http(400, "Trae 凭据不能为空：请粘贴 accessToken 或整份 auth 文件内容"));
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) if value.is_object() => Ok(value),
        _ => Ok(json!({ "accessToken": trimmed })),
    }
}

// ── 取令牌与续期 ─────────────────────────────────────────────

/// 取可用令牌：临期（24h 窗口）或签发龄超 15 天时主动续期并回写。
pub fn ensure() -> Result<String> {
    let record = record()?;
    let mut credential = credential(&record)?;
    if credential.needs_refresh(REFRESH_LEAD_MS, MAX_ISSUE_AGE_MS, sdk::now()) {
        credential = renew(&record, &credential)?;
    }
    if credential.access_token.trim().is_empty() {
        return Err(Error::http(401, "Trae 账号缺少 accessToken，请重新登录"));
    }
    Ok(credential.access_token)
}

/// 401 后的强制刷新：**无视临期判定直接换发**。
///
/// 上游在被拒时不会告诉我们「还剩多久」，所以这条路径不能走 `ensure` 的临期
/// 门（那会原样返回刚被拒的串，让编排层的「刷新后重试一次」退化成「用同一个
/// 坏 token 再打一次」）。
pub fn refresh() -> Result<String> {
    let record = record()?;
    let credential = credential(&record)?;
    Ok(renew(&record, &credential)?.access_token)
}

/// 临期（或签发龄超上限）才换发；否则原样返回。
pub fn renew_if_due(record: &Value, credential: &Credential) -> Result<Credential> {
    if credential.needs_refresh(REFRESH_LEAD_MS, MAX_ISSUE_AGE_MS, sdk::now()) {
        return renew(record, credential);
    }
    Ok(credential.clone())
}

/// 无视临期判定直接换发（401 / 1001 之后救一次用的就是这条）。
pub fn renew_forced(record: &Value, credential: &Credential) -> Result<Credential> {
    renew(record, credential)
}

/// 后台凭证维护问「这条账号是不是快到期了」。
///
/// 漏写的症状不是报错，而是**定时维护与「立即维护」每轮都跳过本家**：
/// 账号页长期挂着「已过期」，直到某次转发撞 401 才被懒刷新救回来 ——
/// 而 Trae 的 refreshToken 一次一换，越晚刷越容易撞上「串已被别的程序换掉」。
/// 判据与续期用的是同一把尺（`needs_refresh`），所以不会出现
/// 「维护说没到期、转发时又判要刷」的分叉。
pub fn expiring() -> bool {
    let Ok(record) = sdk::account() else { return false };
    if record.is_null() {
        return false;
    }
    match credential(&record) {
        // 没有 refreshToken 的账号（手工粘贴只给了 accessToken 是常态）
        // 判 false：续期手段都没有，交给维护只会变成每轮一条稳定失败。
        Ok(credential) if credential.can_refresh() => {
            credential.needs_refresh(REFRESH_LEAD_MS, MAX_ISSUE_AGE_MS, sdk::now())
        }
        _ => false,
    }
}

/// 换发并回写。
///
/// ── 写回为什么是「比较再写」─────────────────────────────────
/// 网关那份用 `update_trae_credentials_if_current`：逐键比对 5 个字段后整份
/// 写入。插件侧的 `account.update` 是同一语义（`expect` 是读到时的那份 secret，
/// 宿主只在它没变时才写）。
///
/// ── 期望值已变时为什么报 409 而不是静默重读 ─────────────────
/// 记录在续期期间被别人改过（并发登录 / 手工粘贴）时，**不能**把这次换发结果
/// 写进去，也不能把新串丢掉不管 —— 报一句让用户知道 refreshToken 可能已经被
/// 服务端轮换过，下一次重试会以落盘那份为准。
fn renew(record: &Value, credential: &Credential) -> Result<Credential> {
    if !credential.can_refresh() {
        return Err(Error::http(401, "Trae 账号里没有 refreshToken，无法续期（请在「账号」页重新登录）"));
    }
    // 并发续期：native 是进程内的单飞表，插件里没有跨调用共享的内存，等价的
    // 纪律是「拿账号锁 + 锁后再读一次」—— 排队期间别人已经换过一轮的话直接用
    // 落盘那份，**绝不再拿刚被轮换掉的旧串去打一次**（那才会真把账号弄丢）。
    let _guard = AccountLock::acquire()?;
    let current_record = sdk::account()?;
    let expect = secret_view(&record["secret"]);
    let current = secret_view(&current_record["secret"]);
    if current != expect && current.is_object() {
        let fresh = Credential::from_payload(&current).map_err(|reason| Error::http(409, reason))?;
        if fresh.valid() {
            return Ok(fresh);
        }
    }
    let renewed = refresh_shared(credential)?;
    let next = merge_credential(&expect, &renewed);
    if record["id"].as_str().unwrap_or("").is_empty() {
        return Err(Error::http(409, "Trae 续期结果无法写回（账号记录缺 id），请重新添加该账号"));
    }
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": view(&next) }),
    )?;
    if result["updated"] != true {
        return Err(Error::http(409, "Trae 续期结果与账号记录不匹配（期间被改过），本次换发未落盘，请重试"));
    }
    Ok(renewed)
}

/// 带「短期合并」的续期。
///
/// native 侧这里是一张进程内的单飞表：同一凭据的并发请求只有一个真打上游。
/// wasm 里没有跨调用共享的内存（宿主可能每次都新建实例），等价物是宿主会话
/// 缓存 —— 刚成功写回的那一把在 5 秒内直接复用，避免两个并发请求各自换出一把
/// 新串、后存的把前一个覆盖掉（那等于把账号弄丢）。
fn refresh_shared(credential: &Credential) -> Result<Credential> {
    let key = format!("trae.refresh:{}", fingerprint(&credential.refresh_token));
    if let Ok(recent) = sdk::session_get(&key) {
        if let Ok(cached) = Credential::from_payload(&recent["credential"]) {
            if cached.access_token == credential.access_token && !cached.refresh_token.is_empty() {
                return Ok(cached);
            }
        }
    }
    let renewed = refresh::refresh_once(credential)?;
    let mut patch = serde_json::Map::new();
    for (key, value) in renewed.patch_fields() {
        patch.insert(key.to_string(), value);
    }
    let _ = sdk::session_put(&key, json!({ "credential": Value::Object(patch) }), 5_000);
    Ok(renewed)
}

/// 令牌指纹（只做缓存键，不做安全判定）。
fn fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(token.trim().as_bytes()))
}

/// 把换发结果并进既有 secret（空值不覆盖）。
///
/// 与网关 `update_trae_credentials_if_current` 的「只并非空字段」逐条对齐：
/// 手工粘贴的凭据常常只有一把 accessToken，这时 `refreshToken` / `expiresAt`
/// 之类的空值**不能**写进已有记录（等于把上次登录拿到的续期串洗掉）。
fn merge_credential(expect: &Value, renewed: &Credential) -> Value {
    let mut fields: Vec<(&str, Value)> = Vec::new();
    for (key, value) in renewed.patch_fields() {
        if value.is_null() || matches!(&value, Value::String(text) if text.is_empty()) {
            continue;
        }
        fields.push((key, value));
    }
    // tokenTail 是展示字段，网关那份也单独写它
    fields.push(("tokenTail", Value::String(token_tail(&renewed.access_token))));
    with_fields(expect, &fields)
}

// 账号级出口代理的解析在 native 侧是 `proxy_util::resolve_account_proxy`。
// 宿主的 `http.open` 不接收代理参数（出网策略由网关按账号配置决定），
// 所以这里不再重复解析 —— 但**保留这条注释**：native 的纪律是「代理配置
// 坏了要如实失败，不静默直连」，这条纪律现在由宿主负责。
