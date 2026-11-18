//! Loomy 凭证：**只有一条来源** —— 账号记录里的登录 session。
//!
//! ── 与别家最大的不同：没有续期，也没有桌面端导入 ─────────────
//! 客户端实测（`electron/xfyun/account-service.js` + 全包检索）：
//!   - 登录接口的 `expire` 是 14 天，**没有任何 refresh / renew 接口**；
//!     过期（业务码 `020002` / `100002`）只能重新走短信登录。
//!   - 登录态只存在于客户端自己的存储里（Electron 会话 / 加密区），
//!     没有 `auth.json` 那种稳定可读的文件形态 —— 因此不提供「导入桌面端
//!     登录态」入口（与 Accio / ZCode 同一处境）。
//!
//! ── 到期时刻：**不估算，只认上游的拒绝** ─────────────────────
//! 登录响应只有 `{session, userid, phone}`，没有到期时刻。曾经按「登录时刻 +
//! 14 天」估一个 `expiresAt` 写进记录，界面上当成有效期展示 —— 结果是账号用满
//! 两周就红着写「已过期」，而上游照常放行（实测：估算到期后仍能签到、能转发）。
//! 估算值不是事实，所以现在**不再写、也不再展示**它。
//!
//! 真正的失效判据只有一个：上游回 `020002` / `100002`（或 HTTP 401/403）。
//! 那时网关会把该账号标记成「需要重新登录」（`needsRelogin`），用户重新登录
//! 成功后标记自动清掉。在此之前，session 一律按「可用」对待。
//!
//! ── 插件形态下的凭证 ────────────────────────────────────────
//! 凭证不再是账号记录的顶层字段，而是主程序 `account.get` 拿到的**不透明 JSON**
//! （`secret`）：
//! ```json
//! { "session": "…", "userId": "…", "phone": "…", "addedAt": 1760000000000 }
//! ```
//! 形状由本模块自己定义、自己解释，主程序不解析。
//!
//! 老记录上可能还留着历史估算的 `expiresAt`：本模块**读它但不据此判失效**
//! （见 [`from_record`] 的说明），界面也不再展示它。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::ids;

/// 一条 Loomy 登录态。
#[derive(Clone, Debug)]
pub struct Credentials {
    /// 账号 id（主程序那条记录的 id）。
    ///
    /// 本家没有「按账号 id 出网」的路径，这个字段只用于把它们串起来排查
    /// （native 侧同样只在日志里用），所以标记为允许未读。
    #[allow(dead_code)]
    pub id: String,
    /// 登录 session（**同时是**模型网关的 `token`）
    pub session: String,
    /// 讯飞侧 userid（转发链不读，但台账/日志用它认人）
    #[allow(dead_code)]
    pub userid: String,
    /// 手机号（同上）
    #[allow(dead_code)]
    pub phone: String,
}

/// 从一条取值链里挑第一个非空字符串（凭证可能被手工编辑过，宽容读取）
pub fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record
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

/// session 的三个落盘名（本插件写 `session`，另两个是粘贴形态）
const SESSION_KEYS: [&str; 3] = ["session", "accessToken", "token"];
/// userId 的三个落盘名
const USERID_KEYS: [&str; 3] = ["userId", "userid", "user_id"];

/// 从 `secret` 解析凭证（**唯一入口**）。
///
/// 记录上的 `expiresAt` **一律不读**：老记录里那份是历史估算值（登录时刻 +
/// 14 天），不是上游给的事实，按它判失效会误杀仍然可用的账号。失效只认上游
/// 的 `020002` / `100002`（见模块头）。
pub fn from_record(record: &Value) -> Result<Credentials> {
    let secret = &record["secret"];
    let session = pick(secret, &SESSION_KEYS);
    if session.is_empty() {
        return Err(Error::http(
            400,
            "Loomy 账号缺少 session，请重新登录或粘贴凭证",
        ));
    }
    Ok(Credentials {
        id: record["id"].as_str().unwrap_or("").to_string(),
        session,
        userid: pick(secret, &USERID_KEYS),
        phone: pick(secret, &["phone"]),
    })
}

/// 取**本次调用上下文**那条账号的凭证。
///
/// 主程序把 `params.account` 解析成账号上下文后才让插件读 `account.get`，
/// 所以这里不需要（也拿不到）别的账号 —— 每次调用天然限定在一个账号上。
pub fn snapshot() -> Result<Credentials> {
    let record = sdk::account().map_err(|error| {
        Error::http(
            400,
            format!("读取 Loomy 账号失败：{}", error.message),
        )
    })?;
    from_record(&record)
}

/// 手机号脱敏（保留前 3 后 4）。
///
/// ── 为什么按 `char` 而不按字节切 ────────────────────────────────
/// `phone` 是**请求体原样**进来的（只 trim + 按字符数截断，不校验格式），
/// 所以它完全可能不是 11 位 ASCII 数字。按字节回切会落在多字节字符中间 ——
/// 一次 panic 就会打断整个插件实例（`panic = "abort"`，没有 unwind）。按字符
/// 取则与内容无关地安全。
pub fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 7 {
        return phone.to_string();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****{tail}")
}

/// session 尾 4 字符（公开形态的展示字段）
pub fn session_tail(session: &str) -> String {
    let chars: Vec<char> = session.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 截断到 `max` 个**字符**（不是字节；昵称可能有中文）
fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect()
}

/// 默认展示名：脱敏手机号 → userId → 通用名
pub fn default_name(phone: &str, user_id: &str) -> String {
    if phone.chars().count() >= 11 {
        format!("Loomy {}", mask_phone(phone))
    } else if !user_id.is_empty() {
        format!("Loomy {user_id}")
    } else {
        "Loomy 账号".to_string()
    }
}

/// 账号的稳定身份（去重用）。
pub fn identity_of(secret: &Value) -> String {
    let user_id = pick(secret, &USERID_KEYS);
    if !user_id.is_empty() {
        return format!("loomy-{user_id}");
    }
    let phone = pick(secret, &["phone"]);
    if !phone.is_empty() {
        return format!("loomy-{phone}");
    }
    let session = pick(secret, &SESSION_KEYS);
    format!("loomy-{}", session_tail(&session))
}

/// 账号的公开视图（凭证更新后刷新界面用）。
///
/// 不输出 `expiresAt`：老记录里那份是历史估算值（登录时刻 + 14 天），拿它当
/// 有效期展示会让仍然可用的账号红着写「已过期」。失效由主程序的 `needsRelogin`
/// 表达（上游回 `020002` / `100002` 时才落，见模块头）。
pub fn account_view(secret: &Value) -> Result<Value> {
    let session = pick(secret, &SESSION_KEYS);
    if session.is_empty() {
        return Err(Error::http(400, "Loomy 凭证里没有 session"));
    }
    let user_id = pick(secret, &USERID_KEYS);
    let phone = pick(secret, &["phone"]);
    Ok(json!({
        "name": default_name(&phone, &user_id),
        "uid": user_id,
        "phone": phone,
        "tokenTail": session_tail(&session),
    }))
}

/// 一条登录成功的账号（`account.normalize` 与 `login.*` 共用同一个产出形状）。
pub fn account_bundle(session: &str, user_id: &str, phone: &str) -> Value {
    let user_id = truncate_chars(user_id.trim(), 256);
    let phone = truncate_chars(phone.trim(), 256);
    let identity = if user_id.is_empty() {
        format!("loomy-{phone}")
    } else {
        format!("loomy-{user_id}")
    };
    json!({
        "secret": {
            "session": session,
            "userId": user_id,
            "phone": phone,
            // 不写 `expiresAt`：上游不给到期时刻，估算值不是事实（见模块头）
            "addedAt": sdk::now(),
        },
        "public": {
            "name": default_name(&phone, &user_id),
            "uid": user_id,
            "phone": phone,
            "tokenTail": session_tail(session),
        },
        "identity": identity,
        "desktop": false,
    })
}

/// 规范化一条账号（手填 / 文本文件）。
///
/// ── 身份从哪来（去重靠它）──────────────────────────────────
/// 优先 `userId`（稳定），没有就退回手机号。两者都没有时**不是**「用凭证兜底」
/// 而是明确报错：没有可辨认身份的账号在界面上会是两条长得一样的记录。
///
/// ── 为什么 normalize 阶段不做探活 ──────────────────────────
/// 上游没有「查当前登录态」的只读接口（GetUserInfo 那条是 CGI 的，Loomy 没有）。
/// 唯一能验证 session 的方式是调一次业务接口 —— 那会真的消耗额度 / 触发每日
/// 积分刷新。所以这里只做本地校验（非空、长度），可用性由第一次转发如实报出。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let (session, user_id, phone, payload_name) = match source["kind"].as_str() {
        Some("manual") => {
            let payload = &source["payload"];
            (
                pick(payload, &SESSION_KEYS),
                pick(payload, &USERID_KEYS),
                pick(payload, &["phone"]),
                payload
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
            )
        }
        Some("file_text") => {
            let text = source["content"].as_str().unwrap_or("").trim().to_string();
            // 文本文件既可能是裸 session，也可能是一份 JSON
            match serde_json::from_str::<Value>(&text) {
                Ok(parsed) if parsed.is_object() => (
                    pick(&parsed, &SESSION_KEYS),
                    pick(&parsed, &USERID_KEYS),
                    pick(&parsed, &["phone"]),
                    None,
                ),
                _ => (text, String::new(), String::new(), None),
            }
        }
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "Loomy 不支持二进制文件导入，请粘贴 session",
            ))
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "Loomy 不支持导入桌面端登录态（登录态不在可读文件里），请用手机号登录或粘贴 session",
            ))
        }
        _ => return Err(Error::http(400, "Loomy 不认识的凭证来源")),
    };
    let session = session.trim().to_string();
    if session.is_empty() {
        return Err(Error::http(
            400,
            "缺少 session（session / accessToken / token）",
        ));
    }
    if session.chars().count() > 8192 {
        return Err(Error::http(
            400,
            "session 过长（超过 8192 字符，多半是粘错了内容）",
        ));
    }
    if user_id.trim().is_empty() && phone.trim().is_empty() {
        return Err(Error::http(
            400,
            "缺少 userId 或手机号：至少给一个才能生成可辨认的账号身份",
        ));
    }
    let mut bundle = account_bundle(&session, &user_id, &phone);
    let display = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(payload_name);
    if let Some(display) = display {
        bundle["public"]["name"] = json!(display);
    }
    Ok(bundle)
}

/// 生成一个一次性的 `deviceId`（邀请码绑定用）。
///
/// 客户端那套是「系统钥匙串 → 本地存储 → 机器指纹 → 随机 UUID」四级兜底
/// （`campus-device-id-service.js`），前缀固定 `loomy-campus-`。网关侧不需要
/// 稳定身份（每次绑定都是一次性动作），所以直接用随机 UUID 形态 —— 实测
/// 上游接受，不校验是否与真实设备一致。
pub fn campus_device_id() -> String {
    let bytes = ids::random_bytes(16);
    if bytes.len() != 16 {
        return format!("loomy-campus-{}", ids::hex_token(16));
    }
    // UUID v4 形态：8-4-4-4-12（第 13 位固定 4、第 17 位固定 a，与客户端同形）
    let hex = super::crypto::hex(&bytes);
    format!(
        "loomy-campus-{}-{}-4{}-a{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32],
    )
}
