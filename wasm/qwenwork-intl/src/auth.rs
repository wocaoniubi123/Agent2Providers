//! 千问办公账号接口：用户资料（`account-context`）、通用请求封装。
//!
//! ── 这一家的账号接口与 Qoder 的三处差别 ──────────────────────
//!   1. **没有 `/api/v1/userinfo`**：资料在
//!      `GET {gateway}/api/v1/adapter/user/account-context?include=…` 里，且把
//!      用户包在 `data.user`、计划包在 `data.plan`（见 [`profile_view`]）；
//!   2. **没有 PAT 交换**（`/api/v1/jobToken/exchange` 不存在），所以没有
//!      `exchange_pat` 这一路；
//!   3. **头束最小**：只带 `Accept` + `qoderwork/1.1.0`（+ `Bearer`），不带
//!      `Cosy-*`（见 `site::open_api_headers` 的理由）。
//!
//! ── 错误信息不回显凭证或轮询 URL ────────────────────────────
//! 轮询 URL 里带 `verifier`（PKCE 秘密），任何把它写进错误文案的路径都等于
//! 泄密；这里所有失败文案都是固定句式 + 上游状态码。
//!
//! ── 与 native 的差别 ───────────────────────────────────────
//!   - 没有 `WireProxy`：账号级代理由宿主按 `params.proxy` 应用（插件侧只
//!     发 URL，出网路径由宿主决定），因此 native 的 `account_proxy` 不迁；
//!   - 超时不在插件侧设：Wasm 的 `http.*` 没有超时参数，等待上限由宿主管。

use agent2api_wasm_sdk::{http, Error, Result, Value};

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

/// 账号类请求的头（**最小束**，见 `site::open_api_headers`）。
pub fn account_headers(token: Option<&str>) -> Vec<(String, String)> {
    site::open_api_headers(token)
}

/// 拉用户资料。
///
/// 千问办公**没有** `/api/v1/userinfo`：用户资料、计划与额度都在
/// `account-context` 那一份里（`include=user,plan,quota,page,data_sharing`），
/// 这是 native `Site::user_info_path` 的取值。
pub fn fetch_profile(token: &str) -> Result<Value> {
    let response = request(
        "GET",
        &site::open_api_url(site::ACCOUNT_CONTEXT_PATH),
        None,
        &account_headers(Some(token)),
    )?;
    payload(response, "用户信息查询")
}

/// 把资料正文拆成「用户对象」那一层。
///
/// 千问办公的 `account-context` 把用户包在 `data.user` 里；计划信息在
/// `data.plan`（用户对象自己不带），并进去供名字 / 套餐显示。拆不到就原样回，
/// 由 [`apply_profile`] 的取值链自己找（native `auth::profile_view` 同口径）。
pub fn profile_view(profile: &Value) -> Value {
    let data = profile
        .get("data")
        .filter(|value| value.is_object())
        .unwrap_or(profile);
    match data.get("user") {
        Some(user) if user.is_object() => {
            let mut merged = user.clone();
            if let Some(plan) = data.get("plan").filter(|value| value.is_object()) {
                if let Some(object) = merged.as_object_mut() {
                    object.insert("plan".to_string(), plan.clone());
                }
            }
            merged
        }
        _ => data.clone(),
    }
}

/// 把资料里的身份字段并进凭证。
pub fn apply_profile(credentials: &mut Credentials, profile: &Value) -> Result<()> {
    let view = profile_view(profile);
    let user_id = credentials::text(&view, &["id", "userId", "user_id", "uid"]);
    if !user_id.is_empty() {
        if !credentials.user_id.is_empty() && credentials.user_id != user_id {
            return Err(Error::http(400, "凭证中的用户与账号资料不一致"));
        }
        credentials.user_id = user_id;
    }
    let name = credentials::text(&view, &["name", "username", "user_name"]);
    if !name.is_empty() {
        credentials.name = name.chars().take(100).collect();
    }
    let email = credentials::text(&view, &["email"]);
    if !email.is_empty() {
        credentials.email = email.chars().take(320).collect();
    }
    Ok(())
}

/// 手动添加的凭证准备：这家**只有**完整账号记录（没有 PAT 交换）。
///
/// 千问办公不带 `/api/v1/jobToken/exchange`（`Site::supports_pat` 为假），所以
/// native 的 `exchange_pat` 在这里没有对应物 —— 粘贴一个 PAT 只会得到一个
/// 404，不如当场说清楚该走网页登录。
pub fn prepare_account(payload: &Value) -> Result<Credentials> {
    if payload.get("importDesktop").and_then(Value::as_bool) == Some(true) {
        return Err(Error::http(400, "千问办公请使用网页登录添加账号"));
    }
    let pat = credentials::text(payload, &["pat", "personalAccessToken", "personal_token"]);
    if !pat.is_empty() {
        return Err(Error::http(
            400,
            "千问办公没有个人访问令牌（PAT），请用网页登录添加账号",
        ));
    }
    let mut credentials = Credentials::from_payload(payload)?;
    if credentials.user_id.is_empty() {
        let profile = fetch_profile(&credentials.access_token)?;
        apply_profile(&mut credentials, &profile)?;
    }
    credentials.complete_identity()?;
    Ok(credentials)
}
