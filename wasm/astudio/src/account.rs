//! AStudio 账号：模型凭据（`modelBearerToken`）与网页会话（Cookie）是两套。
//!
//! ── 两套凭据各管一段（上游事实）────────────────────────────→
//! ```text
//!   modelBearerToken   调模型（`/model-gateway/v1/responses`）与拉模型目录
//!   网页会话 Cookie    积分余额、会员档、每日签到（agent.xfyun.cn）
//! ```
//! 只有模型凭据的账号**能对话**，但没有余额与签到 —— 面板上会标 `noSession`，
//! 而不是把「没有会话」显示成「余额 0」。
//!
//! ── 本机登录态从哪来 ────────────────────────────────────────
//! native 自己找注册表 / `ASTUDIO_HOME` / `~/.acode`；wasm 没有文件系统，
//! 走宿主 `desktop.credentials.read`（能力 `desktop.credentials.v1` +
//! helper `desktop.credentials.astudio.v1`）。宿主回的是
//! `{"credentials": {...}}`，字段与 native 读到的一致。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// 一份 AStudio 凭据。
#[derive(Clone, Default)]
pub struct Credentials {
    pub name: String,
    /// modelBearerToken（调模型）
    pub key: String,
    pub uid: String,
    /// 网页会话 token（积分 / 签到）
    pub token: String,
    pub account_id: String,
    pub sso_session_id: String,
    /// `desktop` / `paste`
    pub source: String,
    /// 读桌面端时命中的来源说明（排错用，不显示在界面上）
    pub origin: String,
}

/// 取第一个非空字符串。
pub fn text(secret: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = secret.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

impl Credentials {
    pub fn from_secret(secret: &Value) -> Self {
        let session = secret.get("session").cloned().unwrap_or(Value::Null);
        Self {
            name: text(secret, &["name"]),
            key: text(secret, &["key", "modelBearerToken", "apiKey"]),
            uid: text(secret, &["uid"]),
            token: text(&session, &["token"]),
            account_id: text(&session, &["accountId"]),
            sso_session_id: text(&session, &["ssoSessionId"]),
            source: text(secret, &["source"]),
            origin: text(secret, &["origin"]),
        }
    }

    pub fn write_into(&self, secret: &mut Value) {
        let Some(object) = secret.as_object_mut() else {
            *secret = json!({});
            return;
        };
        object.insert("key".into(), json!(self.key));
        object.insert("uid".into(), json!(self.uid));
        object.insert("source".into(), json!(self.source));
        if !self.name.is_empty() {
            object.insert("name".into(), json!(self.name));
        }
        if !self.origin.is_empty() {
            object.insert("origin".into(), json!(self.origin));
        }
        if !self.token.is_empty() && !self.account_id.is_empty() {
            let mut session = json!({ "token": self.token, "accountId": self.account_id });
            if !self.sso_session_id.is_empty() {
                session["ssoSessionId"] = json!(self.sso_session_id);
            }
            object.insert("session".into(), session);
        }
    }

    /// 有网页会话（余额与签到要它）。
    pub fn has_session(&self) -> bool {
        !self.token.is_empty() && !self.account_id.is_empty()
    }

    /// 账号面 Cookie 头（与桌面端 `buildAstronCookieHeader` 同序）。
    pub fn cookie_header(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.sso_session_id.is_empty() {
            parts.push(format!("ssoSessionId={}", self.sso_session_id));
            parts.push(format!("sso_sessionid={}", self.sso_session_id));
        }
        if !self.account_id.is_empty() {
            parts.push(format!("account_id={}", self.account_id));
        }
        if !self.token.is_empty() {
            parts.push(format!("token={}", self.token));
        }
        parts.join("; ")
    }
}

/// 公开视图。
pub fn public(secret: &Value) -> Value {
    let credentials = Credentials::from_secret(secret);
    let name = if !credentials.name.is_empty() {
        credentials.name.clone()
    } else if !credentials.uid.is_empty() {
        credentials.uid.clone()
    } else if !credentials.account_id.is_empty() {
        credentials.account_id.clone()
    } else {
        "AStudio".to_string()
    };
    let mut view = json!({
        "name": name,
        "uid": credentials.uid.clone(),
        "accountId": credentials.account_id.clone(),
        "tokenTail": tail_of(&credentials.key),
        "hasCredentials": !credentials.key.is_empty(),
    });
    if credentials.source == "desktop" {
        view["desktop"] = json!(true);
    }
    if !credentials.has_session() {
        view["noSession"] = json!(true);
    }
    view
}

/// 去重身份：uid 优先，其次 accountId，最后 key 的哈希。
pub fn identity_of(credentials: &Credentials) -> String {
    if !credentials.uid.is_empty() {
        return format!("astudio:{}", credentials.uid);
    }
    if !credentials.account_id.is_empty() {
        return format!("astudio:{}", credentials.account_id);
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(credentials.key.as_bytes());
    let hex: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    format!("astudio:key:{hex}")
}

/// 从 secret 读身份。
pub fn identity(secret: &Value) -> String {
    identity_of(&Credentials::from_secret(secret))
}

fn tail_of(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 组装一条可落库的账号。
pub fn account_of(mut credentials: Credentials, remark: &str) -> Value {
    let mut secret = json!({});
    if !remark.is_empty() {
        credentials.name = remark.to_string();
    }
    credentials.write_into(&mut secret);
    let identity = identity_of(&credentials);
    let view = public(&secret);
    json!({ "secret": secret, "public": view, "identity": identity, "desktop": credentials.source == "desktop" })
}

/// `account.normalize`：桌面导入 / 表单（含 `payload.inputs`）/ 文本文件。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let name = params["name"].as_str().unwrap_or("").to_string();
    let credentials = match kind {
        "desktop" => read_desktop()?,
        "manual" => {
            // 动态登录方式把字段包在 `payload.inputs`，旧入口是平铺字段。
            let payload = &source["payload"];
            let fields = payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload);
            from_payload(fields)?
        }
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("").trim();
            if content.starts_with('{') {
                from_json(content)?
            } else if content.is_empty() {
                return Err(Error::http(400, "文件是空的"));
            } else {
                paste_credential(content, "", "", "", "")?
            }
        }
        "file_base64" => {
            return Err(Error::http(
                400,
                "AStudio 不支持导入二进制文件，请粘贴 modelBearerToken 或导入本机登录态",
            ))
        }
        _ => return Err(Error::http(400, "AStudio 请使用本机导入或粘贴 modelBearerToken")),
    };
    Ok(account_of(credentials, &name))
}

/// 读宿主提供的本机登录态。
fn read_desktop() -> Result<Credentials> {
    let raw = sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(
            400,
            format!(
                "AStudio 桌面端登录态读不出来：{}。请先启动 AStudio 并登录，或改用「粘贴 modelBearerToken」方式。",
                error.message
            ),
        )
    })?;
    let credentials = raw.get("credentials").cloned().unwrap_or(raw.clone());
    if credentials.get("banned").and_then(Value::as_bool) == Some(true) {
        return Err(Error::http(400, "AStudio 账号已被封禁"));
    }
    let key = text(&credentials, &["key", "modelBearerToken", "token"]);
    if key.is_empty() {
        return Err(Error::http(400, "AStudio 本机登录态里没有 modelBearerToken，请改为粘贴凭据"));
    }
    Ok(Credentials {
        key,
        uid: text(&credentials, &["uid"]),
        token: text(&credentials, &["token"]),
        account_id: text(&credentials, &["accountId"]),
        sso_session_id: text(&credentials, &["ssoSessionId"]),
        source: "desktop".into(),
        origin: text(&credentials, &["origin"]),
        ..Default::default()
    })
}

fn from_payload(payload: &Value) -> Result<Credentials> {
    let key = text(payload, &["modelBearerToken", "key", "apiKey", "token"]);
    if key.is_empty() {
        return Err(Error::http(400, "请填写 modelBearerToken"));
    }
    paste_credential(
        &key,
        &text(payload, &["uid"]),
        &text(payload, &["sessionToken"]),
        &text(payload, &["accountId"]),
        &text(payload, &["ssoSessionId"]),
    )
}

fn from_json(content: &str) -> Result<Credentials> {
    let value: Value = serde_json::from_str(content)
        .map_err(|_| Error::http(400, "这不是有效的 JSON，请粘贴 astron-session.json 或 modelBearerToken"))?;
    if value.get("banned").and_then(Value::as_bool) == Some(true) {
        return Err(Error::http(400, "AStudio 账号已被封禁"));
    }
    let key = text(&value, &["modelBearerToken", "key", "token"]);
    if key.is_empty() {
        return Err(Error::http(400, "JSON 里没有 modelBearerToken/token"));
    }
    paste_credential(
        &key,
        &text(&value, &["uid"]),
        &text(&value, &["token"]),
        &text(&value, &["accountId"]),
        &text(&value, &["ssoSessionId"]),
    )
}

fn paste_credential(key: &str, uid: &str, token: &str, account_id: &str, sso_session_id: &str) -> Result<Credentials> {
    let key = key.trim();
    if key.is_empty() {
        return Err(Error::http(400, "modelBearerToken 必填"));
    }
    if key.len() > 8192 {
        return Err(Error::http(400, "这份凭据异常地长，请确认只粘贴了 modelBearerToken"));
    }
    Ok(Credentials {
        key: key.to_string(),
        uid: uid.trim().to_string(),
        token: token.trim().to_string(),
        account_id: account_id.trim().to_string(),
        sso_session_id: sso_session_id.trim().to_string(),
        source: "paste".into(),
        ..Default::default()
    })
}

/// 当前账号的 secret。
pub fn current() -> Result<Value> {
    let record = sdk::account()?;
    let secret = record["secret"].clone();
    if secret.get("source").and_then(Value::as_str) != Some("desktop") {
        return Ok(secret);
    }
    // 桌面账号：凭据归客户端所有，每次现读（客户端切号后能立刻报出来）。
    let live = read_desktop()?;
    if identity(&json!({ "key": live.key, "uid": live.uid })) != identity(&secret) {
        return Err(Error::http(
            409,
            "AStudio 客户端已切换账号，请重新导入；不会把原账号自动替换成其他账号",
        ));
    }
    let mut secret = secret;
    secret["key"] = json!(live.key);
    secret["uid"] = json!(live.uid);
    secret["token"] = json!(live.token);
    secret["accountId"] = json!(live.account_id);
    secret["ssoSessionId"] = json!(live.sso_session_id);
    Ok(secret)
}

/// 对话要用的模型凭据。
pub fn model_key() -> Result<String> {
    let secret = current()?;
    let key = text(&secret, &["key", "modelBearerToken"]);
    if key.is_empty() {
        return Err(Error::http(401, "AStudio 账号缺少 modelBearerToken，请重新登录或粘贴"));
    }
    Ok(key)
}
