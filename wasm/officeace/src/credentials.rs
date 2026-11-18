//! OfficeAce 凭证：**两层**，别混。
//!
//! ── 两层各是什么（依据：officeace2api 与 opencode-officeace-auth 的实现）──
//!   · **网关凭据**（转发用）：`model_app_key` : `model_app_secret`，拼成一个
//!     `Authorization: Basic <base64>` 发给模型网关。**不过期**。
//!   · **控制面凭据**（问云端 / 续期用）：`HSTA…` 的 AK/SK + `security_token`
//!     + `project_id`。实测活 **2 小时**；用来签 `client-permission-validate`、
//!     额度与签到接口。
//!
//! 上游干活只用网关凭据 —— 所以「导入过一次」就有稳定可用的账号；控制面凭据
//! 过期只影响额度/签到与自动续期，不影响转发。
//!
//! ── 账号记录里怎么存 ────────────────────────────────────────
//! 复用本仓既有的「账号是一个 JSON 对象」约定，字段：
//!
//! ```text
//! baseUrl           模型网关基址（不含 /v2 也要能收，见 `chat::chat_endpoint`）
//! modelAppKey       网关凭据 key（与 modelAppSecret 成对）
//! modelAppSecret
//! accessKeyId       控制面临时 AK（可缺：手工只导入网关凭据时没有）
//! secretAccessKey
//! securityToken
//! projectId
//! expiresAt         控制面凭据的到期时刻（毫秒；缺省 0 = 未知）
//! refreshToken      一次性轮换的续期令牌（自助 OAuth 才有）
//! dpopKeyPair       登录时那把 P-256 私钥（续期签 proof 要用同一把）
//! ```
//!
//! 手工导入那条路只给前三个（`baseUrl` + 两个 key）；自助 OAuth 给全部。
//!
//! ── wasm 侧与 native 的唯一差别：怎么把新凭据写回去 ──────────
//! native 直接调 `store::save`；插件没有账号库句柄，走宿主的
//! `account.update {expect, secret, public}`（**比较再写**：宿主只在
//! `expect` 与当前 secret 相等时才落盘，返回 `{updated}`）。这条语义与 native
//! 的「比较再写」一一对应，所以并发续期的判定逻辑不用改。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::chat;
use super::signer;
use super::util;

/// provider id（落盘契约）。
pub const ID: &str = "officeace";

/// 控制面临期窗口：到期前 30 分钟提示（与 officeace2api 的续期提前量同级）。
pub const EXPIRY_MARGIN_MS: i64 = 30 * 60 * 1000;

/// 账号名长度上限（与网关 `truncate_chars(&record_name, 100)` 同口径）。
const MAX_NAME_LENGTH: usize = 100;

/// 一次转发用的凭证快照。
#[derive(Clone, Debug, Default)]
pub struct OfficeAceCredential {
    /// 账号记录 id（错误归因与冷却键用）
    pub id: String,
    /// 模型网关基址（未规范化，交给 `chat` 去拼端点）
    pub base_url: String,
    /// 网关凭据：转发用的那一对
    pub model_app_key: String,
    pub model_app_secret: String,
    /// 控制面临时凭据（手工只导入网关凭据时全空）
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: String,
    pub project_id: String,
    /// 控制面凭据到期时刻（毫秒；0 = 未知）
    pub expires_at: i64,
}

impl OfficeAceCredential {
    /// 转发可用的最低条件：基址 + 一对网关凭据。
    pub fn can_forward(&self) -> bool {
        !self.base_url.is_empty()
            && !self.model_app_key.is_empty()
            && !self.model_app_secret.is_empty()
    }

    /// 控制面凭据齐不齐（额度 / 签到 / 续期要用）。
    pub fn has_control_plane(&self) -> bool {
        !self.access_key_id.is_empty() && !self.secret_access_key.is_empty()
    }

    /// 控制面临期判定：到期前 [`EXPIRY_MARGIN_MS`] 算临期。
    pub fn control_plane_expiring(&self) -> bool {
        self.expires_at > 0 && self.expires_at - EXPIRY_MARGIN_MS <= util::now_ms()
    }

    /// 转成签名层要的凭据（控制面请求用；没有临时 AK/SK 时返回 Err）。
    pub fn signing(&self) -> std::result::Result<signer::Credential, String> {
        if !self.has_control_plane() {
            return Err("OfficeAce 账号没有控制面凭据（导入时只给了网关 Basic 那一对）".to_string());
        }
        Ok(signer::Credential {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            security_token: self.security_token.clone(),
            project_id: self.project_id.clone(),
        })
    }
}

/// 从账号记录解析凭证（**唯一入口**）。
///
/// 字段兼容三种粘贴形态（候选表与 native 逐字一致）：
///   · 本仓落盘名：`baseUrl` / `modelAppKey` / `modelAppSecret`
///   · 桌面端 `models.json` 的字段：`api_base` / `api_key`
///   · 常见别名：`base_url` / `appKey` / `appSecret`
pub fn from_record(record: Option<&Value>) -> Result<OfficeAceCredential> {
    let Some(record) = record else {
        return Err(Error::http(503, "没有可用的 OfficeAce 账号：请在账号页添加账号"));
    };
    let credential = OfficeAceCredential {
        id: util::text(record, &["id", "accountId"]),
        base_url: util::text(record, &["baseUrl", "base_url", "api_base", "apiBase"]),
        model_app_key: util::text(record, &["modelAppKey", "appKey", "model_app_key"]),
        model_app_secret: util::text(record, &["modelAppSecret", "appSecret", "model_app_secret"]),
        access_key_id: util::text(record, &["accessKeyId", "access_key_id", "accessKey"]),
        secret_access_key: util::text(record, &["secretAccessKey", "secret_access_key", "secretKey"]),
        security_token: util::text(record, &["securityToken", "security_token"]),
        project_id: util::text(record, &["projectId", "project_id"]),
        expires_at: record.get("expiresAt").and_then(Value::as_i64).unwrap_or(0),
    };
    if !credential.can_forward() {
        return Err(Error::http(
            401,
            "OfficeAce 账号缺少网关凭据（需要 baseUrl 与 modelAppKey/modelAppSecret 两项）",
        ));
    }
    Ok(credential)
}

// ── 当前账号 ────────────────────────────────────────────────

/// 当前账号的完整记录（`secret` + `public` + `id`）。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if !record.is_object() {
        return Err(Error::http(503, "没有可用的 OfficeAce 账号：请在账号页添加并启用账号"));
    }
    Ok(record)
}

/// 当前账号的 secret（对象形态；不可用时 503）。
pub fn secret() -> Result<Value> {
    let record = record()?;
    let secret = record["secret"].clone();
    if !secret.is_object() {
        return Err(Error::http(503, "OfficeAce 账号缺少凭据材料，请重新登录"));
    }
    Ok(secret)
}

/// 当前账号的 secret + 凭据（所有上游调用的统一入口）。
pub fn current() -> Result<(Value, OfficeAceCredential)> {
    let record = record()?;
    let secret = record["secret"].clone();
    if !secret.is_object() {
        return Err(Error::http(503, "OfficeAce 账号缺少凭据材料，请重新登录"));
    }
    let mut credential = from_record(Some(&secret))?;
    credential.id = util::text(&record, &["id"]);
    Ok((secret, credential))
}

/// 把一份新 secret 写回账号（比较再写）。
///
/// 返回 `true` = 宿主确认落盘。`false` = 期间有人改过（并发续期 / 手工编辑），
/// 调用方必须**回读**再判，不能假定自己这份生效了。
pub fn save(expect: &Value, next: &Value) -> Result<bool> {
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": account_view(next) }),
    )?;
    Ok(result["updated"].as_bool().unwrap_or(false))
}

// ── 账号面 ───────────────────────────────────────────────────

/// 账号公开视图（界面账号页读的那几个键）。
///
/// ── 为什么把「有没有控制面凭据」显式给出来 ──────────────────
/// 手工只导入网关 Basic 那对时，转发完全可用但额度/签到查不了。界面按
/// `hasControlPlane` 决定「积分」按钮是否可点（点了会回 `usage_not_configured`，
/// 那是个中性提示，不是失败）。
pub fn account_view(secret: &Value) -> Value {
    let app_key = util::text(secret, &["modelAppKey", "appKey", "model_app_key"]);
    let base_url = util::text(secret, &["baseUrl", "base_url", "api_base", "apiBase"]);
    let has_control = !util::text(secret, &["accessKeyId", "access_key_id", "accessKey"]).is_empty();
    let email = util::text(secret, &["email"]);
    let name = {
        let explicit = util::text(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !email.is_empty() {
            email
        } else if !app_key.is_empty() {
            // 网关凭据的前 6 位足以让用户认出是哪一个 app（完整 key 不落界面）
            format!("OfficeAce {}", app_key.chars().take(6).collect::<String>())
        } else {
            "OfficeAce 账号".to_string()
        }
    };
    json!({
        "name": name,
        "baseUrl": base_url,
        "hasControlPlane": has_control,
        "hasSession": true,
        "canRefresh": has_control,
    })
}

/// 账号的稳定身份（去重用）：`officeace-<hash>`。
///
/// ── 为什么不是 `app-<modelAppKey>` ───────────────────────────
/// 这个 id 是**落盘契约**：内置版时代落库的账号 id 就是 `officeace-<hash>`
/// （hash 取「规范化基址 + app key」的 FNV-1a 64 位前 12 位）。插件若换一套
/// 派生规则，升级后重新导入同一套凭据会**多出一条重复账号**，而老账号还占着
/// 队列位置。所以这里逐字复刻内置版的算法（含基址的 `/v2` 规范化）。
pub fn identity_of(secret: &Value) -> String {
    let app_key = util::text(secret, &["modelAppKey", "appKey", "model_app_key"]);
    if app_key.is_empty() {
        return String::new();
    }
    let base_url = util::text(secret, &["baseUrl", "base_url", "api_base", "apiBase"]);
    format!(
        "officeace-{}",
        util::short_hash(&format!("{}|{}", chat::normalize_base(&base_url), app_key))
    )
}

/// 登录换来的 secret → 落库形态的 `NormalizedAccount`。
///
/// ── 账号名怎么定 ────────────────────────────────────────────
/// 上游显示名 → 用户级 principal id → 账号级 account id → 派生 id 的前 8 位。
/// **不退到种子名「OfficeAce 果办」** —— 多个账号会同名而分不出来。
/// principal 排在 account 之前：同一华为云账号下的不同 IAM 用户共用 account_id，
/// 那串十六进制分不开他们。
pub fn normalized(secret: Value) -> Value {
    let identity = identity_of(&secret);
    let app_key = util::text(&secret, &["modelAppKey", "appKey"]);
    let tail: String = identity
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let name = {
        let upstream = util::text(&secret, &["accountName", "principalId", "accountId"]);
        if !upstream.is_empty() {
            upstream
        } else if app_key.is_empty() {
            "OfficeAce 果办".to_string()
        } else {
            format!("OfficeAce {tail}")
        }
    };
    let mut secret = secret;
    if let Some(object) = secret.as_object_mut() {
        object.insert("name".to_string(), Value::String(name));
    }
    json!({
        "secret": secret,
        "public": account_view(&secret),
        "identity": identity_of(&secret),
        "desktop": false,
    })
}

// ── 手工导入 ─────────────────────────────────────────────────

/// 手工导入路径：`{baseUrl, modelAppKey|appKey, modelAppSecret|appSecret}`。
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
        Some("file_text") => serde_json::from_str::<Value>(source["content"].as_str().unwrap_or("").trim())
            .map_err(|_| {
                Error::http(
                    400,
                    "不是合法 JSON（请选择一份包含 baseUrl 与 modelAppKey / modelAppSecret 的文件）",
                )
            })?,
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "OfficeAce 不支持二进制凭证文件，请粘贴 API 基址与网关凭据",
            ))
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "OfficeAce 不支持导入本机登录态（客户端不落可复用的登录文件），\
                 请粘贴 API 基址与网关凭据",
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "OfficeAce 需要粘贴 API 基址与网关凭据（baseUrl / modelAppKey / modelAppSecret），\
                 或整份包含这几个字段的 JSON",
            ))
        }
    };
    // 唯一硬校验：网关 Basic 那一对必须齐（这是转发的前提）
    let payload = match payload.as_str() {
        Some(raw) => serde_json::from_str::<Value>(raw)
            .map_err(|_| Error::http(400, "OfficeAce 凭据不是合法 JSON"))?,
        None => payload,
    };
    let credential = from_record(Some(&payload))?;
    let mut secret = json!({
        "baseUrl": credential.base_url,
        "modelAppKey": credential.model_app_key,
        "modelAppSecret": credential.model_app_secret,
    });
    // 控制面那一半可选（手工导入时通常没有）
    for (key, value) in [
        ("accessKeyId", credential.access_key_id),
        ("secretAccessKey", credential.secret_access_key),
        ("securityToken", credential.security_token),
        ("projectId", credential.project_id),
    ] {
        if !value.is_empty() {
            secret[key] = Value::String(value);
        }
    }
    if credential.expires_at > 0 {
        secret["expiresAt"] = Value::from(credential.expires_at);
    }
    let refresh_token = util::text(&payload, &["refreshToken", "refresh_token"]);
    if !refresh_token.is_empty() {
        secret["refreshToken"] = Value::String(refresh_token);
    }
    if let Some(key_pair) = payload.get("dpopKeyPair").filter(|value| value.is_object()) {
        secret["dpopKeyPair"] = key_pair.clone();
    }
    for key in ["accountId", "principalId", "accountName"] {
        let value = util::text(&payload, &[key]);
        if !value.is_empty() {
            secret[key] = Value::String(value);
        }
    }
    if let Some(name) = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        secret["name"] = Value::String(util::truncate_chars(name, MAX_NAME_LENGTH));
    }
    Ok(normalized(secret))
}

/// 该账号有没有续期材料：`refreshToken` 字符串 + `dpopKeyPair` 对象。
///
/// native 的 `control::can_refresh` 与 `credentials_expiring` 都读这一条。
pub fn can_refresh(secret: &Value) -> bool {
    !util::text(secret, &["refreshToken", "refresh_token"]).is_empty()
        && secret.get("dpopKeyPair").is_some_and(Value::is_object)
}

/// 该账号的控制面凭据是否临期（到期前 30 分钟算临期）。
///
/// 临期判定必须与续期用同一个提前量，否则会「判要刷但刷出来还是临期」。
pub fn credentials_expiring(record: &Value) -> bool {
    can_refresh(record)
        && from_record(Some(record)).is_ok_and(|credential| credential.control_plane_expiring())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_uses_normalized_base() {
        let a = json!({ "baseUrl": "https://gw.example.com/v2", "modelAppKey": "k1" });
        let b = json!({ "baseUrl": "https://gw.example.com/v2/", "modelAppKey": "k1" });
        let c = json!({ "baseUrl": "https://gw.example.com", "modelAppKey": "k1" });
        assert_eq!(identity_of(&a), identity_of(&b), "尾斜杠不该改变身份");
        assert_eq!(identity_of(&a), identity_of(&c), "缺 /v2 会被规范化补上");
        assert_eq!(identity_of(&a).len(), "officeace-".len() + 12);
        assert!(identity_of(&json!({})).is_empty(), "没有 app key 就没有身份");
    }

    #[test]
    fn view_hides_the_full_app_key() {
        let view = account_view(&json!({ "baseUrl": "https://x", "modelAppKey": "abcdef123456" }));
        let name = view["name"].as_str().unwrap_or_default();
        assert_eq!(name, "OfficeAce abcdef", "界面只露前 6 位");
        assert_eq!(view["hasControlPlane"], json!(false));
        assert_eq!(view["canRefresh"], json!(false));
    }

    #[test]
    fn record_requires_the_gateway_pair() {
        assert!(from_record(Some(&json!({ "baseUrl": "https://x" }))).is_err());
        assert!(from_record(Some(&json!({ "modelAppKey": "k", "modelAppSecret": "s" }))).is_err());
        assert!(from_record(None).is_err());
        let ok = from_record(Some(&json!({
            "baseUrl": "https://x", "modelAppKey": "k", "modelAppSecret": "s"
        })));
        assert!(ok.is_ok_and(|credential| credential.can_forward() && !credential.has_control_plane()));
    }
}
