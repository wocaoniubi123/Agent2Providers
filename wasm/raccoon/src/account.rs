//! 账号视图、账号规范化与「取一个现在能用的 token」。
//!
//! ── 公开视图只含令牌尾部；完整 token 绝不下发 ────────────────
//! 与内置版的公开形态同一批键名：`name` / `uid` / `tokenTail` / `expiresAt` /
//! `officeIdentity`…。`tokenTail` 让用户能认出「这是哪把 token」。
//!
//! ── 桌面端登录态（native 的能力，wasm 没有）──────────────────
//! native 的 `account_view` 在 `desktop: true` 的记录上会**实时读**
//! `~/.box-agent/config/auth.json` 取最新 token 与过期时刻。wasm 插件跑在
//! 宿主沙箱里，读不到用户主目录，因此这里只按记录里的字段渲染 ——
//! 「导入本机登录态」这条入口在 wasm 侧整体不可用（见 `normalize` 的 desktop 分支）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::{credentials, iam, jwt, upstream};

/// 从一份对象里取第一个非空字符串（多候选键，宽容读取）。
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

/// token 尾 4 字符（源实现 `token.slice(-4)`）
fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

fn snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for ch in key.chars() {
        if ch.is_ascii_uppercase() {
            out.push('_');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// 账号公开视图（界面账号页读的那几个键）。
pub fn account_view(secret: &Value, fallback_name: &str) -> Value {
    let desktop = secret.get("desktop").and_then(Value::as_bool) == Some(true);
    let token = secret
        .get("accessToken")
        .and_then(Value::as_str)
        .unwrap_or("");
    let user_id = secret.get("userId").and_then(Value::as_str).unwrap_or("");
    let explicit = secret
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let name = if !explicit.is_empty() {
        explicit.to_string()
    } else if !fallback_name.trim().is_empty() {
        fallback_name.trim().to_string()
    } else if !user_id.is_empty() {
        format!("账号 {user_id}")
    } else {
        "小浣熊账号".to_string()
    };
    // canRefresh：IAM 没有 refresh grant；桌面端记录的凭证不在记录里。
    let can_refresh = !desktop
        && !jwt::is_iam_token(token)
        && !pick(secret, &["refreshToken", "refresh_token"]).is_empty();
    let mut view = json!({
        "name": name,
        "uid": user_id,
        "userId": user_id,
        "tokenTail": token_tail(token),
        "hasSession": !token.is_empty(),
        "canRefresh": can_refresh,
    });
    if let Some(expiry) = secret.get("expiresAt").and_then(Value::as_f64) {
        view["expiresAt"] = json!(expiry);
    }
    for key in ["officeIdentity", "officeOrgName", "officeOrgRole"] {
        let value = secret
            .get(key)
            .or_else(|| secret.get(&snake_case(key)))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            view[key] = json!(value);
        }
    }
    view
}

/// 账号视图（`account.view` 方法）。
pub fn view(secret: &Value) -> Value {
    account_view(secret, "")
}

/// 账号的稳定身份（用于去重）：`user-<userId>`；userId 缺失时给空串。
pub fn identity(secret: &Value) -> String {
    let user_id = pick(secret, &["userId"]);
    if user_id.is_empty() {
        String::new()
    } else {
        format!("user-{user_id}")
    }
}

// ─── 凭证获取（trait 的 ensure_token / refresh_token / token_expiring）──

/// `token.ensure`：取一个现在能用的 token（临期主动刷新）。
///
/// - `account` 非空 → 该账号的凭证
/// - `account` 为空 → 设置里的静态凭证（若配置）→ 否则宿主给的默认账号
pub fn ensure(params: &Value) -> Result<String> {
    let account = params["account"].as_str().unwrap_or("");
    // 静态凭证优先于账号列表 —— 仅在**没有指定账号**时才看它
    // （源实现 `resolveCredentials` 的真实优先级是「账号列表 > 环境变量」，
    // 但那条链里的「账号列表」指的是**用户显式选中的账号**）。
    if account.is_empty() {
        if let Some(token) = upstream::env_token() {
            if jwt::is_iam_token(&token) {
                jwt::validate_iam_token(&token, &upstream::iam_issuer())?;
            }
            return Ok(token);
        }
    }
    let credentials = credentials::snapshot()?;
    let refreshed = credentials::refresh(&credentials, false)?;
    Ok(refreshed.token)
}

/// `token.refresh`：401（token 被上游拒绝）后的**强制**刷新。
///
/// 为什么必须与 ensure 分成两条：ensure 只在「临期」时刷新，而 401 完全可能
/// 发生在一个时间上还很新的 token 上（服务端侧失效、账号被顶下线、
/// refreshToken 轮换）。此时只调 ensure 会拿回同一个被拒的 token。
pub fn refresh(params: &Value) -> Result<String> {
    let account = params["account"].as_str().unwrap_or("");
    if account.is_empty() && upstream::env_token().is_some() {
        // 静态凭证是用户手填的一串，没有可续期的来源
        return Err(Error::http(
            401,
            "静态凭证（设置项 envToken）无法续期，请改用账号列表添加账号",
        ));
    }
    let credentials = credentials::snapshot()?;
    let refreshed = credentials::refresh(&credentials, true)?;
    Ok(refreshed.token)
}

/// `token.expiring`：临期判定（凭证自己的 `is_expiring()` 与 `can_refresh()`）。
///
/// 先确认记录存在：`snapshot` 在读不到记录时会失败，而「账号已被删除」不该
/// 被回答成「需要刷新」（维护任务随后会拿这个不存在的 id 去刷新）。
pub fn expiring(params: &Value) -> Result<bool> {
    if params["account"].as_str().unwrap_or("").is_empty() {
        return Ok(false);
    }
    match credentials::snapshot() {
        Ok(credentials) => Ok(credentials.can_refresh() && credentials.is_expiring()),
        Err(_) => Ok(false),
    }
}

// ─── 账号规范化（`account.normalize`）────────────────────────

/// 把各种来源统一成一条可落库的账号。
///
/// ── 三种来源的语义差别（与内置版 `api::accounts` 的分支逐条对齐）──
///   - `manual`：payload 里可能是嵌套的 auth.json（`access_token` 那套），
///     也可能是用户直接粘的 JWT。两种都认；
///   - `file_text`：同上，只是多一个文件名（错误文案里带上）；
///   - `desktop`：native 侧**不落凭证**、只建一条指向本机文件的记录；
///     wasm 没有文件系统，这条入口直接给出可读的错误（见下）。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let explicit_name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let account = match source["kind"].as_str() {
        Some("manual") => {
            // 表单提交的原始 JSON；宿主把输入框整包放在 `inputs` 里时先拆一层
            let payload = &source["payload"];
            let payload = if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            };
            from_payload(&payload, explicit_name)?
        }
        Some("file_text") => {
            let content = source["content"].as_str().unwrap_or("");
            let parsed: Value = serde_json::from_str(content).map_err(|_| {
                let label = source["file_name"].as_str().unwrap_or("凭证文件");
                Error::http(
                    400,
                    format!("{label} 不是合法 JSON（请选择小浣熊客户端登录后生成的 auth.json）"),
                )
            })?;
            from_payload(&parsed, explicit_name)?
        }
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "小浣熊不支持二进制凭证文件（请选择 auth.json 这类 JSON 文件）",
            ))
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "Wasm 插件读不到本机登录态文件（宿主的沙箱里没有文件系统）。\
请在设置里导出客户端生成的 auth.json，然后用「登录态 JSON」这一项粘贴导入",
            ))
        }
        _ => return Err(Error::http(400, "未知的小浣熊账号来源")),
    };
    enrich_iam(account)
}

/// IAM 登录态的额外补全（native `normalize_account` 的后半段）。
///
/// ── 为什么要单独查一次资料 ──────────────────────────────────
/// IAM token 的 `sub` 是 subject，**不是**平台用户 ID；账号标识必须取
/// `user_info` 里的 `id`。名字同理：IAM token 常常没有 `name` 声明，
/// 只有在资料接口里才有。
fn enrich_iam(mut account: Value) -> Result<Value> {
    let token = pick(&account["secret"], &["accessToken"]);
    if !jwt::is_iam_token(&token) {
        return Ok(account);
    }
    let profile = iam::user_info(&token)?;
    let user_id = pick(&profile, &["id"]);
    let previous_id = pick(&account["secret"], &["userId"]);
    let previous_name = pick(&account["secret"], &["name"]);
    let auto_named = previous_name == format!("账号 {previous_id}")
        || account["desktop"].as_bool() == Some(true)
            && previous_name == format!("桌面端登录账号（{previous_id}）");
    if auto_named {
        let name = pick(&profile, &["name"]);
        account["secret"]["name"] = json!(if name.is_empty() {
            format!("账号 {user_id}")
        } else {
            name
        });
    }
    account["secret"]["userId"] = json!(user_id);
    if pick(&account["secret"], &["officeIdentity", "office_identity"]).is_empty() {
        let identity = pick(&profile, &["officeIdentity", "office_identity"]);
        account["secret"]["officeIdentity"] = json!(if identity.is_empty() {
            "personal".to_string()
        } else {
            identity
        });
    }
    if account["desktop"].as_bool() != Some(true) {
        account["identity"] = json!(format!("user-{user_id}"));
    }
    let public = account_view(&account["secret"], "");
    account["public"] = public;
    Ok(account)
}

/// 从一份 JSON 载荷里解析账号（手填与文件导入共用）。
///
/// 兼容两种形态：嵌套的 auth.json（`access_token` / `refresh_token` 那套）与
/// 用户直接粘的一串 JWT。
fn from_payload(payload: &Value, explicit_name: Option<&str>) -> Result<Value> {
    // 直接粘 JWT：整串当一个 token 处理
    let raw_token = payload.as_str().map(str::trim).unwrap_or("");
    if !raw_token.is_empty() {
        return from_token(raw_token, "", explicit_name);
    }
    let token = pick(payload, &["token", "accessToken", "access_token", "auth_token"]);
    if token.is_empty() {
        return Err(Error::http(400, "缺少 token（accessToken / access_token）"));
    }
    let refresh_token = pick(payload, &["refreshToken", "refresh_token"]);
    let mut account = from_token(&token, &refresh_token, explicit_name)?;
    // office_* 三件套原样保留（组织身份要用它们）
    let Some(secret) = account["secret"].as_object_mut() else {
        return Ok(account);
    };
    for (target, keys) in [
        ("officeIdentity", &["officeIdentity", "office_identity"][..]),
        ("officeOrgName", &["officeOrgName", "office_org_name"][..]),
        ("officeOrgRole", &["officeOrgRole", "office_org_role"][..]),
    ] {
        for key in keys {
            let value = payload
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            if !value.is_empty() {
                secret.insert(target.to_string(), Value::String(value.to_string()));
                break;
            }
        }
    }
    let public = account_view(&account["secret"], &pick(payload, &["name", "nickname"]));
    account["public"] = public;
    Ok(account)
}

/// 从一枚 JWT 造账号（**必须**是有效 JWT：userId 与过期时刻都从它读）。
fn from_token(token: &str, refresh_token: &str, explicit_name: Option<&str>) -> Result<Value> {
    let token = jwt::strip_bearer(token);
    let Some(claims) = jwt::decode_jwt_claims(&token) else {
        return Err(Error::http(400, "token 不是有效的 JWT"));
    };
    if jwt::is_iam_token(&token) {
        jwt::validate_iam_token(&token, &upstream::iam_issuer())?;
    }
    let extracted = jwt::extract_user_id(&claims);
    let user_id = if extracted.is_empty() {
        "unknown".to_string()
    } else {
        extracted
    };
    let mut secret = json!({
        "accessToken": token.clone(),
        "userId": user_id,
    });
    if !refresh_token.trim().is_empty() && !jwt::is_iam_token(&token) {
        secret["refreshToken"] = Value::String(jwt::strip_bearer(refresh_token));
    }
    if let Some(expires_at) = jwt::jwt_expiry_ms(&token) {
        secret["expiresAt"] = Value::from(expires_at);
    }
    let display = jwt::display_name(&claims);
    let name = explicit_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            if display.trim().is_empty() {
                None
            } else {
                Some(display)
            }
        })
        .unwrap_or_else(|| format!("账号 {user_id}"));
    secret["name"] = Value::String(name.clone());
    Ok(json!({
        "public": account_view(&secret, &name),
        "secret": secret,
        "identity": format!("user-{user_id}"),
        "desktop": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_exposes_only_the_token_tail() {
        let secret = json!({
            "accessToken": "eyJhbGciOiJIUzI1NiJ9abcdefghijk",
            "refreshToken": "r1",
            "userId": "7160938",
            "expiresAt": 1_700_000_000_000.0,
            "office_identity": "org-x",
            "office_org_name": "某公司",
        });
        let view = account_view(&secret, "");
        assert_eq!(view["uid"], "7160938");
        assert_eq!(view["userId"], "7160938");
        // 令牌只暴露尾 4 位，完整 token 绝不下发
        assert_eq!(view["tokenTail"], "hijk");
        assert!(!view.to_string().contains("eyJhbGciOiJIUzI1NiJ9abcdefghijk"));
        assert_eq!(view["hasSession"], true);
        assert_eq!(view["canRefresh"], true);
        assert_eq!(view["expiresAt"], 1_700_000_000_000.0);
        // 下划线命名的组织字段也要能读出来（导入的 auth.json 用的是这套键名）
        assert_eq!(view["officeIdentity"], "org-x");
        assert_eq!(view["officeOrgName"], "某公司");
        // 备注名缺省时按 userId 取名
        assert_eq!(view["name"], "账号 7160938");
    }

    #[test]
    fn view_reports_why_it_cannot_refresh() {
        // 桌面端记录：凭证不在记录里，不能续期
        let view = account_view(&json!({ "desktop": true, "userId": "1" }), "");
        assert_eq!(view["canRefresh"], false);
        assert_eq!(view["hasSession"], false);
        // 没有 refreshToken 的手填账号
        let view = account_view(&json!({ "accessToken": "a", "userId": "1" }), "");
        assert_eq!(view["canRefresh"], false);
        // 完全空的记录：给一个能显示的兜底名
        assert_eq!(account_view(&json!({}), ""), json!({
            "name": "小浣熊账号",
            "uid": "",
            "userId": "",
            "tokenTail": "",
            "hasSession": false,
            "canRefresh": false,
        }));
    }

    #[test]
    fn identity_is_stable_and_empty_without_user_id() {
        assert_eq!(identity(&json!({ "userId": "42" })), "user-42");
        assert_eq!(identity(&json!({})), "");
    }

    #[test]
    fn pick_reads_the_first_non_empty_candidate() {
        let record = json!({ "a": "  ", "b": "value" });
        assert_eq!(pick(&record, &["a", "b"]), "value");
        assert_eq!(pick(&record, &["missing"]), "");
    }
}
