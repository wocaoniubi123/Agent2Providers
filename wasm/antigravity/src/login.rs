//! Antigravity 的网页登录：Google 授权页 → **回调 URL 回填** → 换凭据。
//!
//! ── 与 native 的结构差别（迁移时改的）───────────────────────
//! native 每轮自绑一个 loopback 端口收回调；wasm 没有 socket，改成回填：
//!
//! ```text
//!   login.start    → 造 Google 授权地址 + 把 state / redirect_uri 存进登录状态
//!   login.poll     → 只读状态（网关按 poll_interval_ms 来问）
//!   login.callback → 用户把地址栏那条 URL 粘回来 → 当场换码 → 状态翻成 done
//!   login.cancel   → 清掉那一条
//! ```
//!
//! ── `redirect_uri` 必须逐字一致 ────────────────────────────
//! Google 会比对发起授权时与换码时的 `redirect_uri`，差一个字符就
//! `redirect_uri_mismatch`。所以它作为常量只出现一次（[`REDIRECT_URI`]），
//! 两处都取同一个值；浏览器跳不到这个地址是**预期**的 —— 用户复制地址栏即可。
//!
//! ── 流程标识用网关给的那一个 ────────────────────────────────
//! 宿主在 `login.start` 分配 `flow` 并在回调时逐字比对，所以**原样回传
//! `params["flow"]`**，上游自己的 `state` 存在登录状态里、只在本地比对。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::AntigravityCredentials;
use super::endpoints;
use super::refresh;

/// 登录状态在宿主 Login 作用域里的键。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

/// 一次登录的有效期（10 分钟）。
const TTL_MS: i64 = 10 * 60 * 1000;

/// 本轮回填用的回环回调（**两处逐字共用**）。
pub const REDIRECT_URI: &str = "http://localhost:3129/oauth-callback";

/// `admin.action = auth.methods`。
///
/// 两条：Google 授权页（回填回调 URL）+ 粘贴 refresh token。native 的
/// `login_methods` 就是这两条；`desktop`（本机导入）在本家没有宿主 helper
/// （`desktop_credentials::helper("antigravity")` 为空），所以不列。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "oauth",
            "label": "网页登录",
            "instructions": "打开 Google 授权页，完成后把地址栏里那条完整 URL 粘贴回来（本机访问 Google 需经代理时，请先开启系统代理）",
            "prompts": [],
            "browserMode": "choice",
            "manualCallback": true,
            "callbackInput": "url",
            "validatesCallback": true,
            "localOnly": false
        },
        {
            "methodIndex": 1,
            "type": "api",
            "label": "登录凭据",
            "instructions": "粘贴 Google refresh token（以 1// 开头）。",
            "prompts": [{
                "key": "refreshToken",
                "type": "text",
                "label": "refresh token",
                "placeholder": "1//…",
                "secret": true,
                "optional": false
            }],
            "browserMode": "choice",
            "localOnly": false,
            "manualCallback": false,
            "callbackInput": "url"
        }
    ] })
}

fn put_state(value: Value) -> Result<()> {
    let snapshot = sdk::host("state.get", json!({ "scope": "login", "key": STATE_KEY, "schema": SCHEMA }))
        .unwrap_or(Value::Null);
    let revision = snapshot.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let updated = sdk::host(
        "state.compare_exchange",
        json!({
            "scope": "login", "key": STATE_KEY, "schema": SCHEMA,
            "revision": revision, "value": value, "ttl_ms": TTL_MS,
        }),
    )?;
    if updated["updated"] != true {
        return Err(Error::new("登录状态已被另一轮流程改写，请重新发起"));
    }
    Ok(())
}

fn get_state() -> Value {
    sdk::host("state.get", json!({ "scope": "login", "key": STATE_KEY, "schema": SCHEMA }))
        .ok()
        .and_then(|value| value.get("value").cloned())
        .unwrap_or(Value::Null)
}

fn clear_state() {
    let snapshot = sdk::host("state.get", json!({ "scope": "login", "key": STATE_KEY, "schema": SCHEMA }))
        .unwrap_or(Value::Null);
    let revision = snapshot.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let _ = sdk::host(
        "state.compare_exchange",
        json!({ "scope": "login", "key": STATE_KEY, "schema": SCHEMA, "revision": revision, "value": Value::Null, "ttl_ms": 1000 }),
    );
}

/// 宿主随机字节 → base64url（无填充）。
fn random_state() -> Result<String> {
    let value = sdk::host("random.bytes", json!({ "length": 24 }))
        .map_err(|_| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    let raw = value
        .as_str()
        .ok_or_else(|| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    let bytes = base64_decode(raw).ok_or_else(|| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    Ok(base64url_encode(&bytes))
}

fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        out.push(ALPHABET[(value >> 18) as usize & 63] as char);
        out.push(ALPHABET[(value >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(value >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[value as usize & 63] as char);
        }
    }
    out
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// `login.start`。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    let index = params["methodIndex"].as_u64().unwrap_or(0);
    if method != "browser" && method != "" {
        return Err(Error::http(400, "Antigravity 的登录请用「网页登录」或「登录凭据」"));
    }
    if index != 0 {
        return Err(Error::http(400, "Antigravity 登录凭据请直接在账号页粘贴，不需要登录流程"));
    }
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let state = random_state()?;
    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&include_granted_scopes=true&state={}",
        endpoints::AUTH_URL,
        refresh::urlencode(endpoints::CLIENT_ID),
        refresh::urlencode(REDIRECT_URI),
        refresh::urlencode(&endpoints::SCOPES.join(" ")),
        refresh::urlencode(&state),
    );
    put_state(json!({ "flow": flow, "phase": "waiting", "state": state }))?;
    Ok(json!({
        "flow": flow,
        "url": url,
        "poll_interval_ms": 2000,
        "instructions": "在打开的页面里完成 Google 授权。页面最后会停在「无法访问 localhost」——这是正常的：请把地址栏里那条完整 URL 复制回填",
        "external_browser": true,
        "login_ui": {
            "browserMode": "choice",
            "manualCallback": true,
            "callbackInput": "url",
            "captureCallback": false
        }
    }))
}

/// `login.poll`：只读状态。
pub fn poll(params: &Value) -> Result<Value> {
    let state = get_state();
    if !state.is_object() {
        return Ok(json!({ "state": "failed", "message": "这次登录已失效，请重新发起" }));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if !flow.is_empty() && state["flow"].as_str() != Some(flow) {
        return Ok(json!({ "state": "pending", "hint": "另一轮登录正在进行，请等待它完成" }));
    }
    match state["phase"].as_str() {
        Some("done") => {
            let account = state["account"].clone();
            clear_state();
            Ok(json!({ "state": "done", "account": account }))
        }
        Some("failed") => {
            let message = state["message"].as_str().unwrap_or("这轮登录没有成功").to_string();
            clear_state();
            Ok(json!({ "state": "failed", "message": message }))
        }
        _ => Ok(json!({
            "state": "pending",
            "hint": "等待你在浏览器里完成授权，然后把地址栏那条 URL 回填"
        })),
    }
}

/// `login.callback`：用户把回调 URL 贴回来 → 换码 → 收账号。
pub fn callback(params: &Value) -> Result<Value> {
    let state = get_state();
    if !state.is_object() {
        return Ok(json!({ "state": "failed", "message": "这次登录已失效，请重新发起" }));
    }
    let flow = params["flow"].as_str().unwrap_or("").to_string();
    if !flow.is_empty() && state["flow"].as_str() != Some(flow.as_str()) {
        return Ok(json!({ "state": "failed", "message": "这次登录已失效，请重新发起" }));
    }
    let raw = params["url"]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .or_else(|| params["code"].as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let query = match raw.split_once('?') {
        Some((_, query)) => query.to_string(),
        None => raw,
    };
    let mut code = String::new();
    let mut received = String::new();
    let mut error_text = String::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value);
        match key {
            "code" => code = value,
            "state" => received = value,
            "error" => error_text = value,
            "error_description" => {
                if error_text.is_empty() {
                    error_text = value;
                }
            }
            _ => {}
        }
    }
    if !error_text.is_empty() {
        return fail(&flow, &format!("Google 授权被拒绝：{error_text}"));
    }
    if code.is_empty() {
        return Ok(json!({ "state": "failed", "message": "回调里没有授权码" }));
    }
    if received != state["state"].as_str().unwrap_or("") {
        return Ok(json!({ "state": "failed", "message": "登录 state 与本次发起的不一致，请重新发起" }));
    }
    let token = match refresh::exchange_code(&code, REDIRECT_URI) {
        Ok(token) => token,
        Err(error) => return fail(&flow, &error.message),
    };
    let refresh_token = match token.refresh_token {
        Some(refresh) if !refresh.trim().is_empty() => refresh,
        _ => {
            return fail(
                &flow,
                "Google 未返回 refresh token（该授权此前完成过，重复授权不会再次下发）：请在 Google 账号的「第三方访问 / 已授权的应用」里撤销本应用后重新发起网页登录",
            )
        }
    };
    let expires_in = if (1..=7 * 24 * 3600).contains(&token.expires_in) {
        token.expires_in
    } else {
        3600
    };
    let email = refresh::fetch_email(&token.access_token).unwrap_or_default();
    let project = refresh::discover_project(&token.access_token).unwrap_or_default();
    let credentials = AntigravityCredentials {
        refresh_token,
        access_token: token.access_token,
        expires_at: sdk::now() + expires_in * 1000,
        project_id: project,
        email,
        name: String::new(),
    };
    let mut secret = json!({});
    credentials.write_into(&mut secret);
    let account = json!({
        "identity": super::credentials::identity(&secret),
        "public": super::credentials::public(&secret),
        "secret": secret,
        "desktop": false,
    });
    if flow.is_empty() {
        return Ok(json!({ "state": "done", "account": account }));
    }
    let _ = put_state(json!({ "flow": flow, "phase": "done", "account": account }));
    Ok(json!({ "state": "done", "account": account }))
}

fn fail(flow: &str, message: &str) -> Result<Value> {
    if !flow.is_empty() {
        let _ = put_state(json!({ "flow": flow, "phase": "failed", "message": message }));
    }
    Ok(json!({ "state": "failed", "message": message }))
}

/// `login.cancel`。
pub fn cancel(params: &Value) -> Result<Value> {
    let state = get_state();
    if state.is_object() {
        let flow = params["flow"].as_str().unwrap_or("");
        if flow.is_empty() || state["flow"].as_str() == Some(flow) {
            clear_state();
        }
    }
    Ok(Value::Null)
}

/// 百分号解码。
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                output.push(decoded);
                index += 3;
                continue;
            }
        }
        if bytes[index] == b'+' {
            output.push(b' ');
        } else {
            output.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&output).to_string()
}
