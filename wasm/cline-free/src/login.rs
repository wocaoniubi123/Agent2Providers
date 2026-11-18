//! Cline 的登录：WorkOS 设备授权（页面显示授权码）+ 本机登录态导入。
//!
//! ── 设备授权三步（逐字来自 native `login.rs`）───────────────
//! ```text
//!   ① POST {workos}/user_management/authorize/device   （form: client_id）
//!        → {device_code, user_code, verification_uri?, expires_in?}
//!   ② 用户在浏览器打开 verification_uri（兜底 https://authkit.cline.bot/device）
//!        并输入 user_code
//!   ③ POST {workos}/user_management/authenticate       （form）
//!        grant_type=urn:ietf:params:oauth:grant-type:device_code
//!        &device_code=…&client_id=<内置 client id>
//!        → {access_token, refresh_token, user:{…}}（待授权时回 400/404）
//! ```
//!
//! ── 流程标识用网关给的那一个 ────────────────────────────────
//! native 把 `device_code` 当 flow 用；wasm 申报了 `login.interaction.v1`，
//! 宿主在 `login.start` 分配 `flow` 并在回调时逐字比对，所以**原样回传
//! `params["flow"]`**，`device_code` 存在登录状态里（`login.poll` 自己读）。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::credentials::{self, ClineCredentials, DEVICE_VERIFY_FALLBACK, WORKOS_BASE_URL, WORKOS_CLIENT_ID};

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

/// 一次登录的有效期（设备码默认 10 分钟）。
const TTL_MS: i64 = 10 * 60 * 1000;

/// `admin.action = auth.methods`。
///
/// 三条：设备码网页登录（`manualCallback: false` —— 授权在浏览器里完成，
/// 插件靠轮询拿票）、本机导入（`desktop` 形态）、粘贴凭据（`api`）。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "oauth",
            "label": "浏览器登录",
            "instructions": "打开 Cline 的授权页，输入页面上显示的授权码即可（本机不需要回调端口）。",
            "prompts": [],
            "browserMode": "external",
            "manualCallback": false,
            "callbackInput": "url",
            "localOnly": false
        },
        {
            "methodIndex": 1,
            "type": "desktop",
            "label": "导入 Cline 本机登录态",
            "instructions": "读取运行网关的电脑上 Cline 客户端的登录态（~/.cline/data/settings/providers.json），只保存引用。",
            "prompts": [],
            "browserMode": "none",
            "localOnly": true,
            "manualCallback": false,
            "callbackInput": "url"
        },
        {
            "methodIndex": 2,
            "type": "api",
            "label": "填写凭证",
            "instructions": "粘贴 accessToken（可带 workos: 前缀）或 auth JSON；只填 accessToken 时无法自动续期。",
            "prompts": [
                {
                    "key": "accessToken",
                    "type": "text",
                    "label": "accessToken",
                    "placeholder": "workos:eyJ…（或裸 JWT）",
                    "secret": true,
                    "optional": false
                },
                {
                    "key": "refreshToken",
                    "type": "text",
                    "label": "refreshToken（可选）",
                    "placeholder": "填了才能自动续期",
                    "secret": true,
                    "optional": true
                }
            ],
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

/// `login.start`。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    let index = params["methodIndex"].as_u64().unwrap_or(0);
    if method != "browser" && method != "" {
        return Err(Error::http(400, "Cline 请使用浏览器登录、本机导入或填写凭证"));
    }
    match index {
        1 => return Err(Error::http(400, "Cline 本机登录态请用「导入本机登录态」方式添加")),
        2 => return Err(Error::http(400, "Cline 凭证请用「填写凭证」方式添加")),
        0 => {}
        _ => return Err(Error::http(400, "请选择有效的 Cline 登录方式")),
    }
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    // ① 申请设备码（form 编码）。
    let response = http::open(
        "POST",
        &format!("{WORKOS_BASE_URL}/user_management/authorize/device"),
        json!({
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }),
        Some(&json!(format!("client_id={WORKOS_CLIENT_ID}"))),
    )?;
    if !(200..300).contains(&response.status) {
        return Err(Error::http(502, "Cline 设备授权没有返回设备码"));
    }
    let value = response.json()?;
    let device_code = value
        .get("device_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .ok_or_else(|| Error::http(502, "Cline 设备授权响应缺少 device_code"))?
        .to_string();
    let user_code = value
        .get("user_code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let verify = value
        .get("verification_uri")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .or_else(|| value.get("verification_uri_complete").and_then(Value::as_str))
        .unwrap_or(DEVICE_VERIFY_FALLBACK)
        .to_string();
    put_state(json!({ "flow": flow, "phase": "waiting", "device_code": device_code }))?;
    Ok(json!({
        "flow": flow,
        "url": verify,
        "poll_interval_ms": 3000,
        "instructions": if user_code.is_empty() {
            "在打开的页面里完成 Cline 授权，完成后会自动收下账号".to_string()
        } else {
            format!("在打开的页面里输入授权码 {user_code}，完成后会自动收下账号")
        },
        "external_browser": true,
    }))
}

/// `login.poll`：轮询设备票（还在等授权时回 pending）。
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
            return Ok(json!({ "state": "done", "account": account }));
        }
        Some("failed") => {
            let message = state["message"].as_str().unwrap_or("这轮登录没有成功").to_string();
            clear_state();
            return Ok(json!({ "state": "failed", "message": message }));
        }
        _ => {}
    }
    let device_code = state["device_code"].as_str().unwrap_or("").to_string();
    if device_code.is_empty() {
        return Ok(json!({ "state": "failed", "message": "这次登录缺少设备码，请重新发起" }));
    }
    // ③ 换票。
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={WORKOS_CLIENT_ID}"
    );
    let response = http::open(
        "POST",
        &format!("{WORKOS_BASE_URL}/user_management/authenticate"),
        json!({
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }),
        Some(&json!(form)),
    )?;
    if !(200..300).contains(&response.status) {
        // 还在等用户授权：这不是失败，下一次轮询再看。
        return Ok(json!({
            "state": "pending",
            "hint": "等待你在浏览器里完成授权（页面会显示授权码）"
        }));
    }
    let value = response.json()?;
    let access = value
        .get("access_token")
        .or_else(|| value.get("accessToken"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if access.is_empty() {
        return Ok(json!({ "state": "pending", "hint": "等待你在浏览器里完成授权" }));
    }
    let refresh = value
        .get("refresh_token")
        .or_else(|| value.get("refreshToken"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (name, account_id) = credentials::identity_from_jwt(&access);
    let mut credentials = ClineCredentials {
        access_token: credentials::ensure_token_prefix(&access),
        refresh_token: refresh,
        expires_at: credentials::expires_at_from_jwt(&access),
        account: account_id,
        name: name.clone(),
        ..Default::default()
    };
    if credentials.name.is_empty() {
        credentials.name = "Cline".to_string();
    }
    let account = credentials::account_of(&credentials, "", false);
    let _ = put_state(json!({ "flow": flow, "phase": "done", "account": account }));
    Ok(json!({ "state": "done", "account": account }))
}

/// `login.callback`：设备码流程没有浏览器回调。
pub fn callback(_params: &Value) -> Result<Value> {
    Ok(json!({ "state": "pending", "hint": "Cline 设备授权不需要回调，请等待轮询结果" }))
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
