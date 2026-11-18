//! Antigravity 账号：粘贴 refresh token / 导入 JSON、归一化、公开视图。
//!
//! ── 为什么添加时要真刷一次 ────────────────────────────────
//! Google 的 refresh token 看起来都像 `1//…`，但被撤销过的那条只会在第一次
//! 转发时炸。添加账号时打一次 token 端点，能把「这条不能用」挡在账号页上
//! （native 的 `add` 也是这么做的）。
//!
//! ── 归一化的输入形态（三条，都认）──────────────────────────
//! ```text
//!   refreshToken   直接给串（可带 Bearer 前缀 / 引号）
//!   credentialJson 一整段 JSON（Google 的 authorized_user 形态或本包的 secret）
//!   整段 JSON      表单里直接粘 JSON
//! ```

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credentials::{self, AntigravityCredentials};
use super::refresh;

/// 从一段文本里挑出新 refresh token（去引号、去 `Bearer`）。
fn normalize_token(raw: &str) -> String {
    let text = raw.trim().trim_matches('"').trim_matches('\'').trim();
    let text = text.strip_prefix("Bearer ").unwrap_or(text).trim();
    text.to_string()
}

/// `account.normalize`。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let name = params["name"].as_str().unwrap_or("").to_string();
    let fields = match kind {
        "manual" => {
            // 动态登录方式把字段包在 `payload.inputs`，旧入口是平铺字段。
            let payload = &source["payload"];
            payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload)
                .clone()
        }
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("").trim();
            if content.is_empty() {
                return Err(Error::http(400, "文件是空的"));
            }
            if content.starts_with('{') {
                let value: Value = serde_json::from_str(content)
                    .map_err(|_| Error::http(400, "凭证文件不是合法 JSON"))?;
                Value::Object(coerce(value))
            } else {
                json!({ "refreshToken": content })
            }
        }
        "desktop" => {
            return Err(Error::http(
                400,
                "Antigravity 没有本机登录态导入通道，请用网页登录或粘贴 refresh token",
            ))
        }
        "file_base64" => {
            return Err(Error::http(
                400,
                "Antigravity 不支持导入二进制文件，请粘贴 refresh token 或 use 网页登录",
            ))
        }
        _ => return Err(Error::http(400, "Antigravity 请使用网页登录或粘贴 refresh token")),
    };
    let mut secret = if let Some(raw) = fields
        .get("credentialJson")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    {
        let value: Value = serde_json::from_str(raw).map_err(|_| Error::http(400, "凭证 JSON 格式不正确"))?;
        Value::Object(coerce(value))
    } else {
        Value::Object(coerce(fields))
    };
    let refresh_token = normalize_token(&credentials::text(&secret, &["refreshToken", "refresh_token"]));
    if refresh_token.is_empty() {
        return Err(Error::http(
            400,
            "请填写 Google refresh token（以 1// 开头）；oauth2 形态的 JSON 也可以直接粘贴",
        ));
    }
    // 真校验一次：撤销过的 refresh token 只会在这里被挡住。
    let token = refresh::refresh_access_token(&refresh_token)?;
    let expires_in = if (1..=7 * 24 * 3600).contains(&token.expires_in) {
        token.expires_in
    } else {
        3600
    };
    let email = refresh::fetch_email(&token.access_token).unwrap_or_default();
    let project = refresh::discover_project(&token.access_token).unwrap_or_default();
    let parsed = AntigravityCredentials {
        refresh_token: token.refresh_token.unwrap_or(refresh_token),
        access_token: token.access_token,
        expires_at: agent2api_wasm_sdk::now() + expires_in * 1000,
        project_id: if project.is_empty() {
            credentials::text(&secret, &["projectId"])
        } else {
            project
        },
        email: if email.is_empty() { credentials::text(&secret, &["email"]) } else { email },
        name: name.clone(),
    };
    secret = json!({});
    parsed.write_into(&mut secret);
    if !name.trim().is_empty() {
        secret["name"] = json!(name.trim().chars().take(128).collect::<String>());
    }
    Ok(json!({
        "identity": credentials::identity(&secret),
        "public": credentials::public(&secret),
        "secret": secret,
        "desktop": false,
    }))
}

/// 把几种已知的 JSON 形态折成字段表（Google `authorized_user` / 本包 secret）。
fn coerce(value: Value) -> serde_json::Map<String, Value> {
    if let Some(installed) = value.get("installed").filter(|entry| entry.is_object()) {
        return installed.as_object().cloned().unwrap_or_default();
    }
    if let Some(web) = value.get("web").filter(|entry| entry.is_object()) {
        return web.as_object().cloned().unwrap_or_default();
    }
    value.as_object().cloned().unwrap_or_default()
}

/// `account.view`。
pub fn view(secret: &Value) -> Value {
    credentials::public(secret)
}
