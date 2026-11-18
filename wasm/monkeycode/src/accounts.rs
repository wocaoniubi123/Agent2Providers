//! MonkeyCode 账号面：**粘贴 session** 校验 + 归一化 + 落库形态。
//!
//! ── 链路（一步校验 + 一次 best-effort 发现）────────────────────
//! ```text
//! GET {站点}/api/v1/users/status   Cookie: monkeycode_ai_session=…
//!   → {"code":0,"data":{"user":{"id":"uuid","subscription_level":"pro"}}}
//! GET {站点}/api/v1/users/tasks?page=1&size=5
//!   → data.tasks[].image.id           （best-effort 发现 image_id）
//! ```
//!
//! ── 没有桌面端导入 / 没有文件导入 ─────────────────────────────
//! 本家的登录态就是浏览器 cookie，没有客户端 `auth.json` 那种可读文件
//! （与 Accio / ZCode 同一处境）。`Desktop` 与 `FileBase64` / `FileText`
//! 三种来源都要给出可读的回绝理由，而不是静默失败。
//!
//! ── 与 native 的两处必要差异（都是宿主契约逼出来的）─────────────
//! 1. **令牌尾只有 6 个字符**：native 的 `token_tail` 取末 8 位，而宿主的
//!    公开视图校验（`plugin_host/wasm/public_view.rs` 的 `safe_scalar`）对
//!    `tokenTail` 这类键只放行 **≤ 6 个字符**的字符串，超了整次添加账号会被拒
//!    （「插件公开视图包含受保护内容或字段类型无效」）。功能上尾 6 位足够区分。
//! 2. **`edition` 是固定值**：native 用 `region.provider_id()`；本包只有一个地区，
//!    直接写字面量，含义不变（国际版包会是 `monkeycode-intl`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::{pick, SESSION_TTL_MS};
use super::login;
use super::region;

/// 账号名长度上限
const MAX_NAME_LENGTH: usize = 64;
/// 身份 / 镜像 id 的长度上限（与账号存储的 `MAX_IDENTITY_LENGTH` 同量级）
const MAX_IDENTITY_LENGTH: usize = 128;
/// 令牌尾长度（宿主公开视图校验的上限，见模块头第 1 条）
const TOKEN_TAIL_LENGTH: usize = 6;

/// 按字符截断（不按字节切：粘贴进来的东西可能带中文）。
fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// 添加账号入口（`account.normalize`）。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            // 表单可能把字段平铺，也可能包在 `inputs` 里（与 atomcode / modelscope 同口径）
            let payload = &source["payload"];
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                format!(
                    "MonkeyCode {}不支持导入桌面端登录态，请粘贴 session（monkeycode_ai_session）添加账号",
                    region::REGION_LABEL
                ),
            ))
        }
        Some("file_text") | Some("file_base64") => {
            return Err(Error::http(
                400,
                format!(
                    "MonkeyCode {}没有可导入的凭证文件（登录态是浏览器 cookie），请粘贴 session 添加账号",
                    region::REGION_LABEL
                ),
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "MonkeyCode 请粘贴 session（monkeycode_ai_session）添加账号",
            ))
        }
    };
    let payload = if let Some(raw) = payload.as_str() {
        json!({ "session": raw })
    } else {
        payload
    };
    let session = pick(&payload, &["session", "accessToken", "token"]);
    if session.is_empty() {
        return Err(Error::http(
            400,
            "请粘贴 MonkeyCode 的 session cookie（monkeycode_ai_session）",
        ));
    }
    let provided_image = pick(&payload, &["imageId", "image_id"]);
    let provided_image = if provided_image.is_empty() { None } else { Some(provided_image) };
    // 真实校验：`GET /users/status`（参考实现与文档都把它列为权威端点）
    let verified = login::verify_session(
        &session,
        provided_image.as_deref(),
    )?;
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate_chars(value, MAX_NAME_LENGTH));
    Ok(account_of(&verified, "manual", name))
}

/// 校验后的凭证 → 可落库的账号。
///
/// ── 记录结构与网关 `add_monkeycode_account` 的字段逐一对应 ─────
/// `accessToken`（session）/ `userId` / `imageId` / `tokenTail` / `expiresAt`
/// / `source` / `name`。这样 `credentials::from_secret` 能逐字复用（它读的
/// 就是这几个键），账号页的公开视图也不变。
pub fn account_of(verified: &Value, source: &str, explicit_name: Option<String>) -> Value {
    let session = pick(verified, &["session"]);
    let user_id = truncate_chars(&pick(verified, &["userId"]), MAX_IDENTITY_LENGTH);
    let image_id = truncate_chars(&pick(verified, &["imageId"]), MAX_IDENTITY_LENGTH);
    let upstream_name = pick(verified, &["name"]);
    let name = explicit_name
        .or_else(|| {
            if upstream_name.is_empty() {
                None
            } else {
                Some(upstream_name)
            }
        })
        .unwrap_or_else(|| {
            if user_id.is_empty() {
                "MonkeyCode 账号".to_string()
            } else {
                format!("MonkeyCode {user_id}")
            }
        });
    let now = sdk::now();
    let mut secret = serde_json::Map::new();
    secret.insert("accessToken".to_string(), json!(session));
    secret.insert("tokenTail".to_string(), json!(token_tail(&session)));
    secret.insert(
        "expiresAt".to_string(),
        json!(verified
            .get("expiresAt")
            .and_then(Value::as_i64)
            .unwrap_or(now.saturating_add(SESSION_TTL_MS))),
    );
    secret.insert("source".to_string(), json!(source));
    secret.insert("name".to_string(), json!(name));
    if !user_id.is_empty() {
        secret.insert("userId".to_string(), json!(user_id));
    }
    // imageId 空值**不写**：重新粘贴一次 session 不该把上次发现的 image_id
    // 洗掉（与网关 `add_monkeycode_account` 同一条规则）
    if !image_id.is_empty() {
        secret.insert("imageId".to_string(), json!(image_id));
    }
    let secret = Value::Object(secret);
    json!({
        "secret": secret.clone(),
        "public": account_view(&secret),
        "identity": identity_of(&secret),
        "desktop": false,
    })
}

/// 令牌尾（展示用，见模块头第 1 条：**6** 个字符）
fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(TOKEN_TAIL_LENGTH);
    chars[start..].iter().collect()
}

/// 账号公开视图（界面账号页读的那几个键，与网关
/// `to_monkeycode_public_account` 逐键对应）。
pub fn account_view(secret: &Value) -> Value {
    let session = pick(secret, &["accessToken", "session", "token"]);
    let user_id = pick(secret, &["userId", "user_id"]);
    let image_id = pick(secret, &["imageId", "image_id"]);
    let name = {
        let explicit = pick(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !user_id.is_empty() {
            format!("MonkeyCode {user_id}")
        } else {
            "MonkeyCode 账号".to_string()
        }
    };
    json!({
        "name": name,
        "userId": user_id,
        // 有没有 image_id：没有时界面上「创建任务」注定失败，前端据此提示先补
        "imageId": if image_id.is_empty() { Value::Null } else { Value::String(image_id.clone()) },
        "hasImageId": !image_id.is_empty(),
        "tokenTail": pick(secret, &["tokenTail"]),
        "edition": region::PROVIDER_ID,
        "editionLabel": region::REGION_LABEL,
        "source": pick(secret, &["source"]),
        "expiresAt": secret.get("expiresAt").cloned().unwrap_or(Value::Null),
        // 本家没有续期协议（30 天硬限制）
        "hasRefreshToken": false,
        "hasSession": !session.is_empty(),
        "desktop": false,
    })
}

/// 账号的稳定身份：`monkeycode-<userId>`（没有 userId 时返回空串，让网关按
/// 凭证去重 —— 与网关 `anonymous_account_id` 的「不去重」同一取舍）。
///
/// 本包**没有**申报 `accounts.identity.v1`，所以宿主不要求这里非空
/// （`host.rs::validate_identity` 只在申报了那条能力时才拦空串）。
pub fn identity_of(secret: &Value) -> String {
    let user_id = pick(secret, &["userId", "user_id"]);
    if user_id.is_empty() {
        return String::new();
    }
    format!("{}-{user_id}", region::PROVIDER_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_tail_is_six_chars_on_char_boundary() {
        assert_eq!("", token_tail(""));
        assert_eq!("abc", token_tail("abc"));
        assert_eq!("456789", token_tail("0123456789"));
        // 中文不会把字符切成半个
        assert_eq!("符中文标识符", token_tail("中文标识符中文标识符"));
    }

    #[test]
    fn view_follows_the_native_keys() {
        let secret = json!({
            "accessToken": "session-value-123456",
            "userId": "u-1",
            "imageId": "img-9",
            "tokenTail": "345678",
            "source": "manual",
            "expiresAt": 123i64,
        });
        let view = account_view(&secret);
        assert_eq!("MonkeyCode u-1", view["name"].as_str().unwrap_or(""));
        assert_eq!(true, view["hasImageId"].as_bool().unwrap_or(false));
        assert_eq!(false, view["hasRefreshToken"].as_bool().unwrap_or(true));
        assert_eq!("monkeycode", view["edition"].as_str().unwrap_or(""));
        assert_eq!("国内版", view["editionLabel"].as_str().unwrap_or(""));
        assert_eq!("345678", view["tokenTail"].as_str().unwrap_or(""));

        // 没有 imageId 时公开视图给 null + hasImageId=false（界面据此提示补填）
        let view = account_view(&json!({ "accessToken": "s", "userId": "u-2" }));
        assert!(view["imageId"].is_null());
        assert_eq!(false, view["hasImageId"].as_bool().unwrap_or(true));
    }

    #[test]
    fn identity_is_provider_prefixed_and_empty_without_user() {
        assert_eq!("monkeycode-u-1", identity_of(&json!({ "userId": "u-1" })));
        assert_eq!("", identity_of(&json!({ "accessToken": "s" })));
    }

    #[test]
    fn desktop_and_file_sources_are_refused_with_a_reason() {
        for kind in ["desktop", "file_text", "file_base64"] {
            let error = normalize(&json!({ "source": { "kind": kind } }))
                .err()
                .unwrap_or_else(|| Error::new("必须拒绝"));
            assert_eq!(Some(400), error.status);
            assert!(error.message.contains("session"));
        }
        // 手工填写但没给 session
        let error = normalize(&json!({ "source": { "kind": "manual", "payload": {} } }))
            .err()
            .unwrap_or_else(|| Error::new("必须拒绝"));
        assert_eq!(Some(400), error.status);
    }

    #[test]
    fn truncate_keeps_chars_not_bytes() {
        assert_eq!("中文", truncate_chars("中文", 4));
        assert_eq!("中文中", truncate_chars("中文中文", 3));
    }
}
