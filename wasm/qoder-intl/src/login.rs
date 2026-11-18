//! 设备授权登录（PKCE，轮询型）。verifier 只留在后端，不能进入前端状态或日志。
//!
//! ── 流程（2026-11-03 在 native 侧复核过，四个站点同一条）────────
//!   1. 生成 PKCE verifier + challenge（S256）、一个**标准 UUID** 的 `nonce`、
//!      一个设备标识 `machine_id`；
//!   2. 把用户引到 `https://qoder.com/device/selectAccounts?challenge=…`；
//!   3. 网关按 `poll_interval_ms` 回调 `login.poll`，插件去
//!      `GET {openapi}/api/v1/deviceToken/poll?nonce=…&verifier=…&challenge_method=S256`
//!      问进度（202 / 404 = 还没授权）；
//!   4. 拿到令牌后补一份用户资料，落成账号。
//!
//! ── `nonce` 必须是标准 UUID（带横线）────────────────────────
//! 上游按 UUID 解析它，去横线会让整条 query 被判非法
//! （`400 INVALID_DEVICE_FLOW`，`details.field=query`）。native 曾经踩过这个
//! 坑并误判成「入口已停用」—— 这里保持带横线的 `uuid_v4`。
//!
//! ── 为什么 verifier 存宿主状态而不是插件全局 ─────────────────
//! native 用进程内 `HashMap`（单进程、一次登录几分钟）。Wasm 里每次调用都是
//! 新实例，进程内表活不过一次调用 —— 于是把 `{state, poll_url, machine_id}`
//! 写进宿主的**登录作用域状态**（带版本号、比较再写），语义与 native 那张表
//! 等价，且多了「宿主重启也不丢」的好处。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};
use sha2::{Digest, Sha256};

use super::crypto;
use super::credentials::{self, Credentials};
use super::machine;
use super::site;

/// 登录作用域里存设备流状态的键与 schema
const LOGIN_KEY: &str = "device";
const LOGIN_SCHEMA: u32 = 1;

/// 一次设备授权会话
struct DeviceLogin {
    /// 插件侧生成的一次性标识（进 flow id，排障用）
    state: String,
    auth_url: String,
    poll_url: String,
    machine_id: String,
}

/// 简单的 query 值转义（只保留 RFC 3986 的 unreserved 字符）。
///
/// PKCE 串、UUID 本身都在 unreserved 集合里，这里只是不把「拼接」交给运气。
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl DeviceLogin {
    fn new() -> Self {
        let verifier = crypto::random_secret();
        let challenge = crypto::b64_url_nopad(&Sha256::digest(verifier.as_bytes()));
        // nonce 必须是标准 UUID（带横线）：上游按 UUID 解析它（见模块头）
        let nonce = crypto::uuid_v4();
        let machine_id = machine::login_machine_id();
        let mut auth_url = format!(
            "{}?challenge={}&challenge_method=S256&machine_id={}&nonce={}",
            site::device_login_url(),
            encode_query(&challenge),
            encode_query(&machine_id),
            encode_query(&nonce),
        );
        // `client_id` / `redirect_uri`：只有声明了它们的站点才发（千问办公必须带，
        // Qoder 两站历史上一律不发 —— 加上会动到已发布的登录链路）。
        if let Some(client_id) = site::DEVICE_CLIENT_ID {
            auth_url.push_str("&client_id=");
            auth_url.push_str(&encode_query(client_id));
        }
        if let Some(redirect) = site::DEVICE_REDIRECT {
            auth_url.push_str("&redirect_uri=");
            auth_url.push_str(&encode_query(redirect));
        }
        let poll_url = format!(
            "{}?nonce={}&verifier={}&challenge_method=S256",
            site::open_api_url(site::DEVICE_POLL_PATH),
            encode_query(&nonce),
            encode_query(&verifier),
        );
        Self {
            state: crypto::random_secret(),
            auth_url,
            poll_url,
            machine_id,
        }
    }

    /// 问一次上游：`Ok(None)` = 还在等授权。
    fn poll(&self) -> Result<Option<Credentials>> {
        let response = super::auth::request(
            "GET",
            &self.poll_url,
            None,
            &super::auth::account_headers(None),
        )?;
        if response.status == 202 || response.status == 404 {
            return Ok(None);
        }
        let data = super::auth::payload(response, "设备授权")?;
        let token = credentials::secret(&data, &["token", "device_token"])?;
        if token.is_empty() {
            return Err(Error::http(502, "设备授权响应缺少 token"));
        }
        let refresh_token = credentials::secret(&data, &["refresh_token"])?;
        if refresh_token.contains('|') {
            return Err(Error::http(502, "设备授权响应的 refresh_token 格式无效"));
        }
        let user_id = credentials::text(&data, &["user_id", "uid"]);
        let mut credentials = Credentials::from_payload(&json!({
            "mode": site::MODE,
            "accessToken": token,
            "refreshToken": if refresh_token.is_empty() { String::new() }
                else { format!("{}|{}|{}", refresh_token, user_id, self.machine_id) },
            "userId": user_id,
            "machineId": self.machine_id,
            // 设备令牌的绝对到期时刻；缺省按 30 天算
            "expiresAt": credentials::timestamp(data.get("expires_at"))
                .unwrap_or_else(|| sdk::now() + 30 * 24 * 60 * 60 * 1000),
        }))?;
        match super::auth::fetch_profile(&credentials.access_token) {
            Ok(profile) => super::auth::apply_profile(&mut credentials, &profile)?,
            Err(error) if credentials.user_id.is_empty() => return Err(error),
            Err(_) => {}
        }
        credentials.complete_identity()?;
        Ok(Some(credentials))
    }
}

/// 读登录状态里那份设备流（拿不到给 None）
fn load_flow() -> Option<Value> {
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA).ok()?;
    if !snapshot.compatible || !snapshot.value.is_object() {
        return None;
    }
    Some(snapshot.value)
}

/// 写一份设备流状态（比较再写）
fn store_flow(revision: u64, value: Value) -> Result<()> {
    let updated = sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        revision,
        value,
        600_000,
    )?;
    if !updated {
        return Err(Error::new("登录状态已变化，请重新发起"));
    }
    Ok(())
}

/// 清掉设备流状态（成功、失败、取消都清：它是一次性的）
fn clear_flow() {
    let Ok(snapshot) = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA) else {
        return;
    };
    let _ = sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        Value::Null,
        1000,
    );
}

/// 添加账号弹窗里可用的登录方式（与 `metadata.json` 的 `login_methods` 同序）。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "api", "label": "个人访问令牌（PAT）",
            "prompts": [
                { "key": "pat", "type": "text", "label": "Qoder 个人访问令牌（PAT）", "secret": true }
            ],
            "instructions": "在 Qoder 设置页创建一个个人访问令牌后粘贴到这里；插件会用它换取账号令牌。"
        },
        {
            "methodIndex": 1, "type": "oauth", "label": "网页登录", "prompts": [],
            "browserMode": "choice", "manualCallback": false,
            "instructions": "在打开的页面里完成 Qoder 的授权，完成后会自动收下账号"
        }
    ] })
}

/// 发起登录：`methodIndex == 0`（PAT）应走账号表单，设备授权走这一条。
pub fn start(params: &Value) -> Result<Value> {
    let index = params["payload"]["methodIndex"]
        .as_u64()
        .or_else(|| params["methodIndex"].as_u64())
        .unwrap_or(1);
    if index == 0 {
        return Err(Error::http(
            400,
            "「填写凭证」请直接在账号页粘贴个人访问令牌（PAT）；网页登录请点「网页登录」",
        ));
    }
    let flow = params["flow"].as_str().unwrap_or("").trim().to_string();
    if flow.is_empty() {
        return Err(Error::new("主程序未分配登录流程"));
    }
    let device = DeviceLogin::new();
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    store_flow(
        snapshot.revision,
        json!({
            "state": device.state,
            "poll_url": device.poll_url,
            "machine_id": device.machine_id,
        }),
    )?;
    Ok(json!({
        "flow": flow,
        "url": device.auth_url,
        // 轮询型：授权在上游域名终结，网关按这个间隔问 `login.poll`
        "poll_interval_ms": 2000,
        "instructions": "在打开的页面里完成 Qoder 的授权，完成后会自动收下账号",
        "external_browser": true,
        "allowed_hosts": site::allowed_login_hosts(),
        "login_ui": {
            "browserMode": "choice",
            "manualCallback": false,
            "callbackInput": "url",
            "cookieCapture": null,
            "captureCallback": false,
        },
    }))
}

/// 轮询登录进度（设备授权型）。
pub fn poll(params: &Value) -> Result<Value> {
    let _ = params;
    let Some(value) = load_flow() else {
        return Ok(json!({
            "state": "failed",
            "message": "这次登录流程已失效（插件重启过或已取消），请重新发起",
        }));
    };
    let poll_url = value["poll_url"].as_str().unwrap_or("").to_string();
    let state = value["state"].as_str().unwrap_or("").to_string();
    let machine_id = value["machine_id"].as_str().unwrap_or("").to_string();
    if poll_url.is_empty() || machine_id.is_empty() {
        clear_flow();
        return Ok(json!({ "state": "failed", "message": "登录状态损坏，请重新发起" }));
    }
    let device = DeviceLogin { state, auth_url: String::new(), poll_url, machine_id };
    match device.poll() {
        Ok(None) => Ok(json!({ "state": "pending", "hint": "等待你在浏览器里完成授权…" })),
        Ok(Some(credentials)) => {
            clear_flow();
            Ok(json!({
                "state": "done",
                "account": super::account::account_of(&credentials, "web", None),
            }))
        }
        // 暂时不可达：继续等（与网关同一条处置）
        Err(error) if error.code.as_deref() == Some("qoder_transport") => {
            Ok(json!({ "state": "pending", "hint": "授权服务暂时不可达，正在重试…" }))
        }
        Err(error) => {
            clear_flow();
            Ok(json!({ "state": "failed", "message": error.message }))
        }
    }
}

/// 取消一次登录。
pub fn cancel() -> Value {
    clear_flow();
    Value::Null
}

/// 设备授权是轮询型：内嵌窗口拦下回调也没有东西可兑换，按错误回。
pub fn callback() -> Result<Value> {
    Err(Error::http(400, "Qoder 国际版的网页登录是设备授权型，不接受回调"))
}
