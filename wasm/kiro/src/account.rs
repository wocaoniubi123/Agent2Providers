//! Kiro 账号：添加（API key / 本机登录态 / 文件）、公开视图、去重身份。
//!
//! ── 三条添加路径 ────────────────────────────────────────────
//! ```text
//!   manual     粘贴 ksk_… 的 API key（可选账号名）
//!   desktop    读宿主提供的本机登录态，只记来源、不落 token
//!   file_text  kiro-auth-token.json（OAuth 凭证）或一整行 API key
//! ```
//!
//! ── 为什么 API key 不探活 ───────────────────────────────────
//! 它的 profile / 邮箱 / 套餐只有问上游才知道，但添加账号是本地操作：探活失败
//! 不该让用户加不进账号。真正不可用的 key 会在第一次对话时得到明确的 401/403
//! （native 的取舍，逐条照搬）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credentials::{self, Credentials};
use super::refresh;

/// 从表单 / 文件内容里取一个非空字符串。
fn pick(payload: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = payload.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// `account.normalize`。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let name = params["name"].as_str().unwrap_or("").to_string();
    match kind {
        "desktop" => {
            let secret = read_local_secret()?;
            Ok(normalized(secret, &name, true))
        }
        "manual" => {
            // 动态登录方式把表单整包放进 `payload.inputs`；旧入口是平铺字段。
            let payload = &source["payload"];
            let fields = payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload);
            add(fields, &name)
        }
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("").trim();
            if content.starts_with('{') {
                add_json(content, &name)
            } else if content.is_empty() {
                Err(Error::http(400, "文件是空的"))
            } else {
                add_key(&json!({ "apiKey": content }), &name)
            }
        }
        "file_base64" => Err(Error::http(
            400,
            "Kiro 不支持导入二进制文件，请粘贴 API key 或导入本机登录态",
        )),
        _ => Err(Error::http(400, "Kiro 请使用本机导入、API key 或 kiro-auth-token.json")),
    }
}

/// 读本机登录态并折成 secret（宿主回的是 secret 形态）。
fn read_local_secret() -> Result<Value> {
    let raw = refresh::read_local()?;
    let credentials = Credentials::from_secret(&raw);
    let mut secret = json!({
        "method": credentials.method,
        "source": credentials.source,
        "region": credentials.region,
        "loginProvider": credentials.login_provider,
        "uid": credentials.uid,
    });
    // 本机登录态的邮箱 / 套餐是读数，best-effort 补进账号名。
    if let Ok(payload) = super::usage::fetch(&credentials) {
        let email = payload.pointer("/userInfo/email").and_then(Value::as_str).unwrap_or("");
        let title = payload
            .pointer("/subscriptionInfo/subscriptionTitle")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !email.is_empty() {
            secret["accountId"] = json!(email);
        }
        if !title.is_empty() {
            secret["plan"] = json!(super::usage::plan_name(title));
        }
    }
    Ok(secret)
}

/// 表单：API key 或一整段 auth JSON。
fn add(fields: &Value, name: &str) -> Result<Value> {
    if let Some(raw) = fields
        .get("credentialJson")
        .or_else(|| fields.get("json"))
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    {
        return add_json(raw, name);
    }
    add_key(fields, name)
}

/// 粘贴 API key。
fn add_key(payload: &Value, name: &str) -> Result<Value> {
    let key = pick(payload, &["apiKey", "accessToken", "token", "key"]);
    if key.is_empty() {
        return Err(Error::http(400, "请填写 Kiro API key（ksk_ 开头）"));
    }
    if key.len() > 8192 {
        return Err(Error::http(400, "这份凭据异常地长，请确认只粘贴了 Kiro API key"));
    }
    let credentials = Credentials {
        method: "apikey".into(),
        access: key,
        region: "us-east-1".into(),
        ..Default::default()
    };
    let mut secret = json!({ "name": if name.is_empty() { "Kiro API" } else { name } });
    credentials.write_into(&mut secret);
    Ok(normalized(secret, "", false))
}

/// 导入 `kiro-auth-token.json` 形态的 OAuth 凭证。
fn add_json(text: &str, name: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(text)
        .map_err(|_| Error::http(400, "这不是有效的 JSON，请粘贴 kiro-auth-token.json 或 API key"))?;
    let access = pick(&value, &["accessToken", "access", "token"]);
    if access.is_empty() {
        return Err(Error::http(400, "JSON 里没有 accessToken"));
    }
    let mut credentials = Credentials {
        access,
        refresh: pick(&value, &["refreshToken", "refresh"]),
        expires: value.get("expiresAt").and_then(expiring_ms).unwrap_or(0),
        region: {
            let region = pick(&value, &["region"]);
            if region.is_empty() {
                "us-east-1".to_string()
            } else {
                region
            }
        },
        profile: pick(&value, &["profileArn", "profile"]),
        client_id: pick(&value, &["clientId"]),
        client_secret: pick(&value, &["clientSecret"]),
        token_url: pick(&value, &["tokenURL", "tokenUrl", "tokenEndpoint", "token_endpoint"]),
        method: "idc".into(),
        login_provider: "enterprise".into(),
        uid: "enterprise".into(),
        ..Default::default()
    };
    if credentials.refresh.is_empty() {
        credentials.method = "social".into();
    }
    if credentials.client_id.is_empty() && credentials.method == "idc" {
        credentials.method = "social".into();
    }
    if !credentials.token_url.is_empty() && credentials.method == "idc" {
        // 带自有 token 端点的只能按外部 IdP 走（宿主代打）。
        credentials.method = "external-idp".into();
    }
    let mut secret = json!({ "name": if name.is_empty() { "Kiro" } else { name } });
    credentials.write_into(&mut secret);
    Ok(normalized(secret, "", false))
}

/// `expiresAt` 的两种形态：数字毫秒或 RFC3339 字符串。
fn expiring_ms(value: &Value) -> Option<i64> {
    if let Some(millis) = value.as_i64().filter(|value| *value > 0) {
        return Some(if millis < 100_000_000_000 { millis.saturating_mul(1000) } else { millis });
    }
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text).ok().map(|date| date.timestamp_millis())
}

/// 组装一条可落库的账号。
fn normalized(secret: Value, name: &str, desktop: bool) -> Value {
    let mut secret = secret;
    if !name.trim().is_empty() {
        secret["name"] = json!(name.trim().chars().take(128).collect::<String>());
    }
    json!({
        "identity": credentials::identity(&secret),
        "public": credentials::public(&secret),
        "secret": secret,
        "desktop": desktop,
    })
}

/// `account.view`。
pub fn view(secret: &Value) -> Value {
    credentials::public(secret)
}
