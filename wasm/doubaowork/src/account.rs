//! 凭证解析、账号导入归一化与公开视图。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/accounts.rs`。
//!
//! ── wasm 侧的三处删减（都因为沙箱没有文件系统与进程）───────
//!   1. `desktop`（导入本机登录态）：要读本机客户端的 SQLite + DPAPI 解密，
//!      wasm 做不到 —— 这条来源直接拒绝，并说明改用网页登录 / 粘贴 Cookie；
//!   2. 老记录「只存身份、实时读客户端」的分支：同上，wasm 侧不存在这种记录；
//!   3. `upgrade_snapshot`（顺手把老记录升级成快照）：只服务上面那条老路径。
//!
//! ── Cookie 一律按集合规范化 ────────────────────────────────
//! 宿主 `checkin_call/doubao_daily/credentials.rs` 会把账号 secret 里的 Cookie
//! 解析成一份 BTreeMap，再要求插件实际发出的 `Cookie` 头**逐项相等**。所以
//! 这里与它用同一套规则（域过滤、路径过滤、过期过滤、键值字符集），
//! 拼出来的头才能在宿主那里通过核对。

use std::collections::BTreeMap;

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::api;

const MAX_COOKIE_BYTES: usize = 64 * 1024;
const MAX_SECRET: usize = 256 * 1024;

fn domain_allowed(domain: &str) -> bool {
    let domain = domain.trim_start_matches('.');
    domain == "doubao.com" || domain == "www.doubao.com"
}

fn valid_pair(name: &str, value: &str) -> bool {
    !name.is_empty()
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_control() || b"=;, ".contains(&byte))
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b';')
}

/// 把凭据里能表达 Cookie 的字段统一成「名字 → 值」。
pub fn pairs(value: &Value) -> Result<BTreeMap<String, String>> {
    let mut result: BTreeMap<String, String> = BTreeMap::new();
    let source = value
        .get("cookies")
        .or_else(|| value.get("cookieHeader"))
        .or_else(|| value.get("cookie"))
        .or_else(|| value.get("token"))
        .unwrap_or(value);
    match source {
        Value::String(text) => {
            let text = text
                .trim()
                .strip_prefix("Cookie:")
                .unwrap_or(text.trim())
                .trim();
            if text.len() > MAX_COOKIE_BYTES {
                return Err(Error::http(400, "豆包工作 Cookie 过长"));
            }
            if text.starts_with('[') || text.starts_with('{') {
                let parsed: Value = serde_json::from_str(text)
                    .map_err(|_| Error::http(400, "Cookie JSON 无法解析"))?;
                return pairs(&parsed);
            }
            for part in text
                .split(';')
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                let Some((name, value)) = part.split_once('=') else {
                    return Err(Error::http(
                        400,
                        "请粘贴完整 Cookie（含 sessionid=…），不能只填令牌值",
                    ));
                };
                if !valid_pair(name.trim(), value.trim()) {
                    return Err(Error::http(400, "Cookie 含非法字符"));
                }
                result.insert(name.trim().into(), value.trim().into());
            }
        }
        Value::Array(rows) => {
            let now = clock() / 1000;
            for row in rows {
                if row["domain"]
                    .as_str()
                    .is_some_and(|domain| !domain_allowed(domain))
                    || row["path"].as_str().is_some_and(|path| path != "/")
                {
                    continue;
                }
                let expires = row["expires"]
                    .as_f64()
                    .or_else(|| row["expirationDate"].as_f64());
                if expires.is_some_and(|expiry| expiry > 0.0 && expiry <= now as f64) {
                    continue;
                }
                let name = row["name"].as_str().unwrap_or("");
                let value = row["value"].as_str().unwrap_or("");
                if !valid_pair(name, value) {
                    return Err(Error::http(400, "Cookie 列表含非法名称或值"));
                }
                result.insert(name.into(), value.into());
            }
        }
        Value::Object(object) => {
            for (name, value) in object {
                if let Some(value) = value.as_str() {
                    if valid_pair(name, value) {
                        result.insert(name.clone(), value.into());
                    }
                }
            }
        }
        _ => return Err(Error::http(400, "缺少豆包工作 Cookie")),
    }
    if !["sessionid", "sessionid_ss"]
        .iter()
        .any(|name| result.get(*name).is_some_and(|value| !value.is_empty()))
    {
        return Err(Error::http(
            401,
            "豆包工作 Cookie 缺少 sessionid，请重新登录后复制完整 Cookie",
        ));
    }
    let size: usize = result
        .iter()
        .map(|(name, value)| name.len() + value.len() + 3)
        .sum();
    if size > MAX_COOKIE_BYTES {
        return Err(Error::http(400, "豆包工作 Cookie 过长"));
    }
    Ok(result)
}

fn clock() -> i64 {
    agent2api_wasm_sdk::now()
}

/// 出站 `Cookie` 头：有原样保留的 `cookieHeader` 就用它，否则按集合拼。
pub fn cookie_header(secret: &Value) -> Result<String> {
    let cookies = pairs(secret)?;
    if let Some(header) = secret["cookieHeader"].as_str() {
        if header.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(Error::http(400, "Cookie 含非法字符"));
        }
        return Ok(header.to_string());
    }
    Ok(cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; "))
}

/// 账号的稳定身份：`doubaowork-<userId>-<enterpriseType>`。
pub fn identity(secret: &Value) -> String {
    let user = secret["userId"].as_str().unwrap_or("");
    if user.is_empty() {
        return String::new();
    }
    format!(
        "doubaowork-{user}-{}",
        secret["enterpriseType"].as_str().unwrap_or("0")
    )
}

fn tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 公开视图。绝不能带上 Cookie / 设备号的原文（宿主 `public_view` 会拒收）。
pub fn view(secret: &Value) -> Result<Value> {
    let cookies = pairs(secret)?;
    let tail = tail(
        cookies
            .get("sessionid")
            .or_else(|| cookies.get("sessionid_ss"))
            .map(String::as_str)
            .unwrap_or(""),
    );
    Ok(json!({
        "name": secret["name"],
        "nickname": secret["name"],
        "userId": secret["userId"],
        "email": secret["email"],
        "avatar": secret["avatar"],
        "tokenTail": tail,
        "hasCredentials": true,
        "desktop": false,
    }))
}

/// 把各种形态的入参整理成一条可落库的 secret。
///
/// 与 native `accounts::credentials` 同口径：拒绝「非国内版」的标记，
/// 从 Cookie 集合派生 `deviceId` / `webId` / `fingerprint`，并保留导入时
/// 存过的身份字段。`cookies` 是数组时只留数组（不留 `cookieHeader`），
/// 免得宿主看到两份 Cookie 源直接拒收。
fn secret_from(value: &Value) -> Result<Value> {
    if value["edition"]
        .as_str()
        .is_some_and(|edition| edition != "doubaowork")
        || value["baseUrl"]
            .as_str()
            .is_some_and(|base| base.trim_end_matches('/') != api::BASE_URL)
    {
        return Err(Error::http(400, "凭证不是豆包工作国内版账号"));
    }
    let pairs = pairs(value)?;
    let pick = |name: &str| pairs.get(name).cloned();
    let mut secret = json!({
        "cookieHeader": pairs.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("; "),
        "deviceId": pick("device_id"),
        "webId": pick("web_id"),
        "fingerprint": pick("s_v_web_id").or(pick("fp")),
    });
    if let Some(cookies) = value.get("cookies").filter(|cookies| cookies.is_array()) {
        secret["cookies"] = cookies.clone();
    }
    for key in [
        "name",
        "userId",
        "enterpriseType",
        "email",
        "avatar",
        "clientVersion",
        "channel",
        "userAgent",
        "chromiumVersion",
        "teaUuid",
        "webTabId",
    ] {
        if let Some(field) = value.get(key) {
            secret[key] = field.clone();
        }
    }
    for key in ["deviceId", "webId", "fingerprint"] {
        if let Some(field) = value.get(key).filter(|field| field.is_string()) {
            secret[key] = field.clone();
        }
    }
    if value.get("cookies").is_some_and(Value::is_array) {
        if let Some(object) = secret.as_object_mut() {
            object.remove("cookieHeader");
        }
    }
    Ok(secret)
}

/// 探活：拿账号身份（`userId` / `enterpriseType` / 昵称 / 头像）。
pub fn identify(credentials: &api::Credential) -> Result<Value> {
    let url = format!(
        "{}/passport/account/info/v2/?account_sdk_source=web&sdk_version=2.2.5&aid=582478\
         &real_aid=582478&device_platform=web&samantha_web=1&use-olympus-account=1",
        api::BASE_URL
    );
    let response = http::open("GET", &url, credentials.headers(), None)?;
    let value = api::json_response(response, false)?;
    if value["message"]
        .as_str()
        .is_some_and(|message| message != "success")
    {
        return Err(Error::http(401, "豆包工作登录态已失效，请重新登录"));
    }
    let data = value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(&value);
    let user = api::identifier(&data["user_id_str"])
        .ok_or_else(|| Error::http(401, "豆包工作未返回账号身份，请重新登录"))?;
    Ok(json!({
        "userId": user,
        "enterpriseType": api::identifier(&data["passport_enterprise_user_type"]).unwrap_or_else(|| "0".into()),
        "name": data["name"].as_str().unwrap_or(&user),
        "email": data["email"],
        "avatar": data["avatar_url"],
    }))
}

/// 面板表单字段的位置：`auth.methods` 的 api 方式把输入包在 `inputs` 里交给
/// 网关，网关按 `NormalizeSource::Manual` 原样透传 —— 不解包就会把整个
/// `{methodIndex, inputs}` 当成 Cookie 集合（`pairs()` 读不到 `token`）。
/// 裸对象（手工粘贴的老路径）没有 `inputs`，原样返回。
fn inputs_of(payload: &Value) -> &Value {
    payload
        .get("inputs")
        .filter(|inputs| inputs.is_object())
        .unwrap_or(payload)
}

/// `account.normalize`：手填 Cookie / 文本文件 / 本机导入三种来源归一化。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let value = match kind {
        "manual" => inputs_of(&source["payload"]).clone(),
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("");
            if content.len() > MAX_SECRET {
                return Err(Error::http(400, "导入文件过大"));
            }
            serde_json::from_str::<Value>(content)
                .map_err(|_| Error::http(400, "请导入包含 Cookie 的 JSON 文件"))?
        }
        "desktop" => {
            return Err(Error::http(
                400,
                "Wasm 插件读不到本机豆包工作客户端的登录数据；请改用网页登录或粘贴完整 Cookie",
            ))
        }
        "file_base64" => {
            return Err(Error::http(
                400,
                "豆包工作不导入加密 Cookies 数据库，请使用网页登录或粘贴 Cookie",
            ))
        }
        _ => return Err(Error::http(400, "不支持的账号导入来源")),
    };
    let mut secret = secret_from(&value)?;
    let credentials = api::Credential::new(&secret)?;
    let profile = identify(&credentials)?;
    let display = params["name"]
        .as_str()
        .map(str::to_string)
        .or_else(|| value["name"].as_str().map(str::to_string))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| profile["name"].as_str().unwrap_or("豆包工作").into());
    for key in ["userId", "enterpriseType", "email", "avatar"] {
        secret[key] = profile[key].clone();
    }
    secret["name"] = json!(display);
    Ok(json!({
        "secret": secret,
        "public": view(&secret)?,
        "identity": identity(&secret),
        "desktop": false,
    }))
}

/// 拼一份可直接出站的凭据（native `accounts::resolve` 的无本机分支）。
pub fn credential(secret: &Value) -> Result<api::Credential> {
    api::Credential::new(secret)
}

/// 当前调用账号的 secret（宿主 `account.get` 的 `secret` 字段）。
///
/// 宿主在每次调用前已经替插件读过一次账号（`runtime.rs` 的
/// `context.invoke("account.get")`），但那份结果不会塞进 JSON 参数，
/// 所以插件要自己再取一次 —— 这是受控入口，不涉及任何本机文件。
pub fn current_secret() -> Result<Value> {
    let record = agent2api_wasm_sdk::account()?;
    match record.get("secret").filter(|secret| secret.is_object()) {
        Some(secret) => Ok(secret.clone()),
        None => Err(Error::http(401, "豆包工作账号缺少凭据，请重新登录")),
    }
}

/// Cookie 归一化的自检：宿主 `doubao_daily::credentials` 对这份集合逐项比对，
/// 两边的过滤规则必须一致，否则整条对话通道会被判成「来源已变化」。
#[cfg(test)]
mod tests {
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn 解析完整_cookie_头() {
        let pairs = pairs(&json!({"cookieHeader": "Cookie: sessionid=abc; sid_guard=x=y"}))
            .unwrap_or_default();
        assert_eq!(pairs.get("sessionid").map(String::as_str), Some("abc"));
        assert_eq!(pairs.get("sid_guard").map(String::as_str), Some("x=y"));
    }

    #[test]
    fn 缺_sessionid_时拒绝() {
        assert!(pairs(&json!({"cookieHeader": "a=b"})).is_err());
        assert!(pairs(&json!({"cookieHeader": "没有等号"})).is_err());
    }

    #[test]
    fn cookie_数组按域与路径过滤() {
        let secret = json!({"cookies": [
            {"domain": ".doubao.com", "path": "/", "name": "sessionid", "value": "abc"},
            {"domain": ".other.com", "path": "/", "name": "token", "value": "leak"},
            {"domain": ".doubao.com", "path": "/x", "name": "drop", "value": "1"},
        ]});
        let pairs = pairs(&secret).unwrap_or_default();
        assert_eq!(pairs.get("sessionid").map(String::as_str), Some("abc"));
        assert!(!pairs.contains_key("token"));
        assert!(!pairs.contains_key("drop"));
    }

    #[test]
    fn 身份与公开视图不带凭据原文() {
        let secret = json!({
            "cookieHeader": "sessionid=0123456789abcdef",
            "name": "工作号",
            "userId": "42",
            "enterpriseType": "1",
        });
        assert_eq!(identity(&secret), "doubaowork-42-1");
        let view = view(&secret).unwrap_or_default();
        assert_eq!(view["tokenTail"], "cdef");
        assert_eq!(view["hasCredentials"], true);
        assert_eq!(view["desktop"], false);
        assert!(!view.to_string().contains("0123456789abcdef"));
    }

    #[test]
    fn 本机导入来源在沙箱里被拒绝() {
        let error = normalize(&json!({
            "provider": "doubaowork",
            "source": {"kind": "desktop"},
        }));
        assert!(error.is_err());
    }
}
