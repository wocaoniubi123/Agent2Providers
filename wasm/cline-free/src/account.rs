//! Cline 账号：归一化（本机导入 / 表单 / 文件）、公开视图、身份。
//!
//! ── 本机登录态从哪来 ────────────────────────────────────────
//! native 直接读 `~/.cline/data/settings/providers.json`；wasm 没有文件系统，
//! 走宿主 `desktop.credentials.read`（能力 `desktop.credentials.v1` + helper
//! `desktop.credentials.cline.v1`）。宿主回的是
//! `{sourceRevision, content:"{\"providers\":{\"cline\":{\"settings\":{\"auth\":{…}}}}}"}`，
//! 字段名与客户端那份逐字一致，所以解析规则照搬 native。
//!
//! ── 本机账号的 token 不落盘 ────────────────────────────────
//! 账号里只留 `desktop: true` 与身份标记；每次用的时候现读。好处是 Cline
//! 客户端自己续期后网关立刻跟上，代价是这条来源**无法回写**（宿主没有给
//! cline 的「写回客户端」通道）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::{self, ClineCredentials};

/// `account.normalize`。
pub fn normalize(params: &Value, pool: super::pool::Pool) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let name = params["name"].as_str().unwrap_or("").to_string();
    match kind {
        "desktop" => {
            let credentials = read_desktop()?;
            let _ = pool;
            Ok(credentials::account_of(&credentials, &name, true))
        }
        "manual" => {
            // 动态登录方式把字段包在 `payload.inputs`，旧入口是平铺字段。
            let payload = &source["payload"];
            let fields = payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload);
            from_fields(fields, &name)
        }
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("").trim();
            if content.is_empty() {
                return Err(Error::http(400, "文件是空的"));
            }
            if content.starts_with('{') {
                let value: Value = serde_json::from_str(content)
                    .map_err(|_| Error::http(400, "这不是有效的 JSON，请粘贴 Cline 的 auth 或 accessToken"))?;
                from_fields(&value, &name)
            } else {
                from_fields(&json!({ "accessToken": content }), &name)
            }
        }
        "file_base64" => Err(Error::http(
            400,
            "Cline 不支持导入二进制文件，请粘贴 accessToken 或导入本机登录态",
        )),
        _ => Err(Error::http(400, "Cline 请使用浏览器登录、本机导入或填写凭证")),
    }
}

/// 表单 / JSON：`auth` 包一层、`credentialJson` 再嵌一层，两种都认。
fn from_fields(fields: &Value, name: &str) -> Result<Value> {
    let mut value = fields.clone();
    if let Some(raw) = value
        .get("credentialJson")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    {
        value = serde_json::from_str(raw).map_err(|_| Error::http(400, "凭证 JSON 格式不正确"))?;
    }
    // `{providers:{cline:{settings:{auth:{…}}}}}` 与 `{auth:{…}}` 都折到 auth。
    let auth = value
        .pointer("/providers/cline/settings/auth")
        .cloned()
        .or_else(|| value.get("auth").filter(|value| value.is_object()).cloned())
        .unwrap_or(value);
    let credentials = credentials::from_secret(&auth);
    if credentials.access_token.is_empty() {
        return Err(Error::http(400, "请填写 accessToken"));
    }
    if credentials.access_token.len() > 16_384 {
        return Err(Error::http(400, "这份凭据异常地长，请确认只粘贴了 accessToken"));
    }
    Ok(credentials::account_of(&credentials, name, false))
}

/// 读宿主提供的本机登录态。
fn read_desktop() -> Result<ClineCredentials> {
    let raw = sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(
            400,
            format!(
                "本机 Cline 登录态不存在或不可读：{}（请先在 Cline 客户端登录，或改用「填写凭证」添加）",
                error.message
            ),
        )
    })?;
    let content = raw
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| raw.get("auth").map(|value| json!({ "auth": value }).to_string()));
    let Some(content) = content else {
        return Err(Error::http(400, "本机 Cline 登录态内容为空，请改用「填写凭证」添加"));
    };
    let value: Value = serde_json::from_str(&content)
        .map_err(|_| Error::http(400, "本机 Cline 登录态不是有效 JSON，请改用「填写凭证」添加"))?;
    let auth = value
        .pointer("/providers/cline/settings/auth")
        .cloned()
        .unwrap_or(value);
    let credentials = credentials::from_secret(&auth);
    if credentials.access_token.is_empty() {
        return Err(Error::http(400, "本机 Cline 登录态里没有 accessToken，请先在客户端登录"));
    }
    Ok(credentials)
}

/// 当前账号的凭证（本机账号现读一次）。
pub fn current(pool: super::pool::Pool) -> Result<(ClineCredentials, bool)> {
    let record = sdk::account()?;
    let secret = record["secret"].clone();
    let desktop = secret.get("desktop").and_then(Value::as_bool) == Some(true);
    let credentials = if desktop {
        read_desktop()?
    } else {
        credentials::from_secret(&secret)
    };
    if credentials.access_token.is_empty() && credentials.refresh_token.is_empty() {
        return Err(Error::http(
            401,
            format!("{} 账号缺少凭证，请重新登录", pool.label()),
        ));
    }
    Ok((credentials, desktop))
}
