//! Kiro 网页登录：授权页 → **回调 URL 回填** → 换凭据 → 收账号。
//!
//! ── 与 native 的结构差别（迁移时改的）───────────────────────
//! native 每轮登录会自己绑一个回环端口收回调；wasm 没有 socket，这条链改成：
//!
//! ```text
//!   login.start    → 造授权地址 + 把 PKCE verifier / state 存进登录状态
//!   login.poll     → 只读状态（网关按 poll_interval_ms 来问）
//!   login.callback → 用户把地址栏那条 URL 粘回来 → 当场换证 → 状态翻成 done
//!   login.cancel   → 清掉那一条
//! ```
//!
//! ── 必须原样回传网关的 `flow` ───────────────────────────────
//! 宿主在 `login.start` 里分配流程标识，并在 `login.callback` 时逐字比对。
//! 插件自己编的串等于让回调当场 502，所以这里**只用 `params["flow"]`**，
//! 上游自己的 `state` 存在登录状态里、只在本地比对。
//!
//! ── 为什么报 `poll_interval_ms > 0` ────────────────────────
//! 「轮询型」在协议里的含义是「网关主动问插件要结果」，与授权在哪里终结
//! 无关。回调落在用户浏览器的地址栏里，网关必须来问。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::credentials::{self, Credentials};
use super::endpoints;
use super::refresh;

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

/// 一次登录的有效期（native 的 `SIGN_IN_TIMEOUT_MS`）。
const TTL_MS: i64 = 10 * 60 * 1000;

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// 与 native 的 `login_methods::methods` 一一对应，只把「本机导入」从
/// `oauth + localOnly` 改成了网关认的 `desktop` 形态（`localOnly:true` +
/// `browserMode:"none"` + 空 prompts）；企业 SSO 的授权码流需要自注册客户端
/// 与固定回环回调，wasm 侧没有这两条，因此不列。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "oauth",
            "label": "Kiro 网页登录",
            "instructions": "打开 Kiro 登录页完成授权。若最后停在「无法访问 localhost」页面，请把地址栏里的完整 URL 粘贴回来。",
            "prompts": [],
            "browserMode": "choice",
            "manualCallback": true,
            "callbackInput": "url",
            "validatesCallback": true,
            "localOnly": false
        },
        {
            "methodIndex": 1,
            "type": "desktop",
            "label": "导入 kiro-cli / Kiro IDE 登录态",
            "instructions": "读取运行网关的电脑上 kiro-cli 或 Kiro IDE 的登录态，不是当前浏览器所在电脑的账号。",
            "prompts": [],
            "browserMode": "none",
            "localOnly": true,
            "manualCallback": false,
            "callbackInput": "url"
        },
        {
            "methodIndex": 2,
            "type": "api",
            "label": "Kiro API key",
            "instructions": "粘贴 ksk_ 开头的 API key。",
            "prompts": [{
                "key": "apiKey",
                "type": "text",
                "label": "API key",
                "placeholder": "ksk_…",
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

/// 写登录状态（CAS：并发发起时后到的那个会失败，而不是把前一轮的参数改掉）。
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
fn random_token(bytes: usize) -> Result<String> {
    let value = sdk::host("random.bytes", json!({ "length": bytes }))
        .map_err(|_| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    let raw = value
        .as_str()
        .ok_or_else(|| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    let decoded = base64_decode(raw).ok_or_else(|| Error::new("无法生成安全的登录凭据，请重新发起"))?;
    Ok(base64url_encode(&decoded))
}

/// PKCE 的 S256 challenge。
fn challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    base64url_encode(&Sha256::digest(verifier.as_bytes()))
}

/// base64url（无填充）编码。
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

/// base64（标准 / url 两种字母表都认）解码。
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

/// query 编码。
fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// `login.start`。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    let index = params["methodIndex"].as_u64().unwrap_or(0);
    if method != "browser" && method != "" {
        return Err(Error::http(400, "Kiro 的登录请用「Kiro 网页登录」或「导入本机登录态」"));
    }
    match index {
        1 => return Err(Error::http(400, "Kiro 本机登录态请用「导入本机登录态」方式添加")),
        2 => return Err(Error::http(400, "Kiro API key 请用「粘贴 API key」方式添加")),
        0 => {}
        _ => return Err(Error::http(400, "请选择有效的 Kiro 登录方式")),
    }
    // 网关分配的流程标识：原样回传（见模块头）。
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let state = random_token(24)?;
    let verifier = random_token(48)?;
    let url = format!(
        "{}/signin?state={}&code_challenge={}&code_challenge_method=S256&redirect_uri={}&redirect_from=KiroIDE",
        endpoints::PORTAL,
        urlencode(&state),
        urlencode(&challenge(&verifier)),
        urlencode(endpoints::REDIRECT_URI),
    );
    put_state(json!({
        "flow": flow,
        "phase": "waiting",
        "state": state,
        "verifier": verifier,
    }))?;
    Ok(json!({
        "flow": flow,
        "url": url,
        "poll_interval_ms": 1500,
        "instructions": "在打开的页面里完成 Kiro 授权。页面最后可能停在「无法访问 localhost」——这是正常的：请把地址栏里那条完整 URL 复制回填",
        "external_browser": true,
        "allowed_hosts": ["app.kiro.dev", "awsapps.com", "amazonaws.com", "signin.aws"],
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

/// `login.callback`：用户把回调 URL 贴回来 → 当场换证。
pub fn callback(params: &Value) -> Result<Value> {
    let state = get_state();
    if !state.is_object() {
        return Ok(json!({ "state": "failed", "message": "这次登录已失效，请重新发起" }));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if !flow.is_empty() && state["flow"].as_str() != Some(flow) {
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
        return fail(&received, &format!("Kiro 授权被拒绝：{error_text}"));
    }
    if code.is_empty() {
        return Ok(json!({ "state": "failed", "message": "Kiro 回调里没有授权码" }));
    }
    if received != state["state"].as_str().unwrap_or("") {
        return Ok(json!({ "state": "failed", "message": "登录 state 与本次发起的不一致，请重新发起" }));
    }
    let verifier = state["verifier"].as_str().unwrap_or("").to_string();
    let exchanged = exchange(&code, &verifier);
    let credentials = match exchanged {
        Ok(credentials) => credentials,
        Err(error) => return fail(&received, &error.message),
    };
    let account = finish_account(credentials);
    let _ = put_state(json!({ "flow": flow, "phase": "done", "account": account }));
    Ok(json!({ "state": "done", "account": account }))
}

/// 换码：`POST https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token`。
fn exchange(code: &str, verifier: &str) -> Result<Credentials> {
    let body = json!({
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": endpoints::REDIRECT_URI,
    });
    let response = http::open(
        "POST",
        &format!("{}/oauth/token", endpoints::AUTH_SERVICE),
        json!({
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": endpoints::ide_user_agent(),
        }),
        Some(&body),
    )?;
    if !(200..300).contains(&response.status) {
        return Err(Error::http(400, "Kiro 登录被拒绝，请重新发起授权"));
    }
    let token = response.json()?;
    let access = token.get("accessToken").and_then(Value::as_str).unwrap_or("").to_string();
    if access.is_empty() {
        return Err(Error::http(502, "Kiro 没有返回登录凭证"));
    }
    let seconds = token.get("expiresIn").and_then(Value::as_i64).filter(|value| *value > 0).unwrap_or(3600);
    Ok(Credentials {
        access,
        refresh: token.get("refreshToken").and_then(Value::as_str).unwrap_or("").to_string(),
        expires: sdk::now() + seconds * 1000,
        method: "social".into(),
        login_provider: "portal".into(),
        uid: "portal".into(),
        region: "us-east-1".into(),
        profile: token.get("profileArn").and_then(Value::as_str).unwrap_or("").to_string(),
        ..Default::default()
    })
}

/// 登录收尾：补 profile 与邮箱/套餐，产出可落库的账号。
fn finish_account(mut credentials: Credentials) -> Value {
    if credentials.profile.is_empty() {
        if let Ok(profile) = refresh::lookup_profile(&credentials) {
            credentials.profile = profile;
        }
    }
    if let Ok(payload) = super::usage::fetch(&credentials) {
        if let Some(email) = payload.pointer("/userInfo/email").and_then(Value::as_str) {
            credentials.account_id = email.to_string();
        }
        if let Some(title) = payload.pointer("/subscriptionInfo/subscriptionTitle").and_then(Value::as_str) {
            credentials.plan = super::usage::plan_name(title);
        }
    }
    let name = if credentials.account_id.is_empty() {
        "Kiro 账号".to_string()
    } else {
        format!("{} (Kiro)", credentials.account_id)
    };
    let mut secret = json!({ "name": name });
    credentials.write_into(&mut secret);
    json!({
        "identity": credentials::identity(&secret),
        "public": credentials::public(&secret),
        "secret": secret,
        "desktop": false,
    })
}

/// 把这一轮标成失败并回报。
fn fail(_state: &str, message: &str) -> Result<Value> {
    let current = get_state();
    if current.is_object() {
        let flow = current["flow"].as_str().unwrap_or("").to_string();
        let _ = put_state(json!({ "flow": flow, "phase": "failed", "message": message }));
    }
    Ok(json!({ "state": "failed", "message": message }))
}

/// `login.cancel`：清掉状态（native 是收监听器、释放端口，这里是同一件事）。
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

/// 百分号解码（回调串里的 `%3A` 之类）。
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
