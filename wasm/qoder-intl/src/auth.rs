//! Qoder 账号接口：PAT 交换、用户资料、通用请求封装。
//!
//! ── 错误信息不回显凭证或轮询 URL ────────────────────────────
//! 轮询 URL 里带 `verifier`（PKCE 秘密），任何把它写进错误文案的路径都等于
//! 泄密；这里所有失败文案都是固定句式 + 上游状态码。
//!
//! ── 与 native 的差别 ───────────────────────────────────────
//!   - 没有 `WireProxy`：账号级代理由宿主按 `params.proxy` 应用（插件侧只
//!     发 URL，出网路径由宿主决定），因此 native 的 `account_proxy` 不迁；
//!   - 超时不在插件侧设：Wasm 的 `http.*` 没有超时参数，等待上限由宿主管。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::credentials::{self, Credentials};
use super::site;

/// 上游一次响应（与 native `ApiResponse` 同形：状态码 + ok + 已解析正文）
pub struct ApiResponse {
    pub status: u16,
    pub ok: bool,
    pub payload: Option<Value>,
}

/// 发一次账号类请求。
pub fn request(
    method: &str,
    url: &str,
    body: Option<&Value>,
    headers: &[(String, String)],
) -> Result<ApiResponse> {
    let encoded = match body {
        Some(body) => body.to_string().into_bytes(),
        None => Vec::new(),
    };
    let response = http::open_raw(
        method,
        url,
        site::headers_object(headers),
        if body.is_some() { Some(&encoded) } else { None },
    )
    .map_err(|error| {
        let status = error.status.unwrap_or(0);
        if status == 504 {
            Error::http(504, "请求超时，请检查网络后重试").with_code("qoder_transport")
        } else {
            Error::http(502, "无法连接上游，请检查网络或账号代理设置").with_code("qoder_transport")
        }
    })?;
    let status = response.status;
    let bytes = response.bytes(4 * 1024 * 1024).unwrap_or_default();
    let payload = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(&bytes).ok()
    };
    Ok(ApiResponse {
        status,
        ok: (200..300).contains(&status),
        payload,
    })
}

/// 把响应正文拆成 JSON 对象；失败时给一句带动作名与状态码的文案。
pub fn payload(response: ApiResponse, action: &str) -> Result<Value> {
    if !response.ok {
        let hint = match response.status {
            401 | 403 => "，请确认凭证有效且站点选择正确",
            429 => "，请稍后重试",
            _ => "",
        };
        return Err(Error::http(
            response.status.max(400),
            format!("{action}失败（HTTP {}）{hint}", response.status),
        ));
    }
    response
        .payload
        .filter(Value::is_object)
        .ok_or_else(|| Error::http(502, format!("{action}未返回有效 JSON 对象")))
}

/// 账号类请求的头（Qoder 的固定头束，见 `site::open_api_headers`）。
pub fn account_headers(token: Option<&str>) -> Vec<(String, String)> {
    site::open_api_headers(token)
}

/// 拉用户资料。
pub fn fetch_profile(token: &str) -> Result<Value> {
    let response = request(
        "GET",
        &site::open_api_url(site::USER_INFO_PATH),
        None,
        &account_headers(Some(token)),
    )?;
    payload(response, "用户信息查询")
}

/// 把资料里的身份字段并进凭证。
pub fn apply_profile(credentials: &mut Credentials, profile: &Value) -> Result<()> {
    let user_id = credentials::text(profile, &["id", "userId", "user_id", "uid"]);
    if !user_id.is_empty() {
        if !credentials.user_id.is_empty() && credentials.user_id != user_id {
            return Err(Error::http(400, "凭证中的用户与账号资料不一致"));
        }
        credentials.user_id = user_id;
    }
    let name = credentials::text(profile, &["name", "username", "user_name"]);
    if !name.is_empty() {
        credentials.name = name.chars().take(100).collect();
    }
    let email = credentials::text(profile, &["email"]);
    if !email.is_empty() {
        credentials.email = email.chars().take(320).collect();
    }
    Ok(())
}

/// PAT → 作业令牌（`jt-` / `jrt-`），再拉资料补齐身份。
pub fn exchange_pat(pat: &str) -> Result<Credentials> {
    let pat = credentials::secret(&json!({ "pat": pat }), &["pat"])?;
    if pat.is_empty() || pat.contains('|') {
        return Err(Error::http(400, "请填写有效的个人访问令牌（PAT）"));
    }
    let response = request(
        "POST",
        &site::open_api_url(site::EXCHANGE_PATH),
        Some(&json!({ "personal_token": pat })),
        &site::open_api_headers(None),
    )?;
    let data = payload(response, "PAT 换取令牌")?;
    let token = credentials::secret(&data, &["token"])?;
    let job_refresh = credentials::secret(&data, &["refresh_token"])?;
    if token.is_empty() || job_refresh.contains('|') {
        return Err(Error::http(502, "PAT 响应缺少有效 token 或 refresh_token 格式无效"));
    }
    let profile = fetch_profile(&token)?;
    let user_id = credentials::text(&profile, &["id"]);
    let machine_id = super::machine::machine_id("", &user_id);
    let mut credentials = Credentials::from_payload(&json!({
        "mode": site::MODE,
        "accessToken": token,
        "refreshToken": format!("pat|{pat}|{job_refresh}|{user_id}|{machine_id}"),
        "expiresAt": credentials::timestamp(data.get("expires_at"))
            .unwrap_or_else(|| agent2api_wasm_sdk::now() + 24 * 60 * 60 * 1000),
        "userId": user_id,
        "machineId": machine_id,
    }))?;
    apply_profile(&mut credentials, &profile)?;
    credentials.complete_identity()?;
    Ok(credentials)
}

/// 手动添加的凭证准备：PAT 优先，否则按完整账号记录解析。
pub fn prepare_account(payload: &Value) -> Result<Credentials> {
    if payload.get("importDesktop").and_then(Value::as_bool) == Some(true) {
        return Err(Error::http(400, "Qoder 国际版请使用网页登录添加账号"));
    }
    let pat = credentials::secret(payload, &["pat", "personalAccessToken", "personal_token"])?;
    if !pat.is_empty() {
        return exchange_pat(&pat);
    }
    let mut credentials = Credentials::from_payload(payload)?;
    if credentials.user_id.is_empty() {
        let profile = fetch_profile(&credentials.access_token)?;
        apply_profile(&mut credentials, &profile)?;
    }
    credentials.complete_identity()?;
    Ok(credentials)
}
