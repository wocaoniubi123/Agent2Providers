//! AStudio 的两套出网：模型（Bearer）与账号面（Cookie）。
//!
//! ── 账号面的信封 ────────────────────────────────────────────
//! `{flag: true, code: 0, data: …}` 才算成功。HTTP 401/403、`code: 80000`、
//! `desc` 里含「重新登录」表示网页会话失效；其余 `flag: false` 或非 0 的
//! `code` 是业务失败，都必须透出去，不能被折叠成「余额无变化」。
//!
//! ── 平台头从哪来 ────────────────────────────────────────────
//! native 用 `cfg!(target_os)` 判 `clientType`（Windows 21 / macOS 22）；
//! wasm 的编译目标是固定的 `wasm32-unknown-unknown`，真实平台只能问宿主
//! `runtime.platform`。拿不到就不发这个头（与 native 的非 Win/macOS 分支同）。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

/// Responses 端点（OpenAI Responses 协议）。
pub const RESPONSES_URL: &str =
    "https://astronstudio-api-volces-prod.xf-yun.com/model-gateway/v1/responses";

/// 模型目录。
pub const MODEL_MANAGER_URL: &str =
    "https://astronstudio-api-volces-prod.xf-yun.com/api/v1/model-manager/models";

/// 账号面根（注意结尾斜杠：相对路径拼在它后面）。
pub const STUDIO_API_BASE: &str = "https://agent.xfyun.cn/xingchen-studio/";

/// 账号面接口的相对路径。
pub const POINTS_BALANCE: &str = "points/balance";
pub const MEMBERSHIP_ME: &str = "membership/me";
pub const PLAN_CONFIG: &str = "membership/plan-config";
/// 当日首次调用触发每日登录奖励（POST，无请求体）；签到与登录共用。
pub const INIT_APP: &str = "tenant-app/v2/init-app";

/// 桌面端版本（`studioVersion` 头）。
const STUDIO_VERSION: &str = "3.5.1";

/// 账号面失败的两种形态。
pub enum StudioError {
    /// 网页会话失效（让用户重新登录）。
    Expired(String),
    /// 其他失败（网络 / 5xx / 业务拒绝）。
    Failed(String),
}

impl StudioError {
    pub fn message(&self) -> &str {
        match self {
            Self::Expired(message) | Self::Failed(message) => message,
        }
    }
}

/// 账号面请求共用桌面端身份头，登录、余额与签到不能各自漏带。
fn decorate(headers: &mut Value) {
    let platform = sdk::host("runtime.platform", json!({}))
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default();
    match platform.as_str() {
        "win" | "windows" => {
            headers["clientType"] = json!("21");
        }
        "mac" | "macos" => {
            headers["clientType"] = json!("22");
        }
        _ => {}
    }
    headers["studioVersion"] = json!(STUDIO_VERSION);
}

/// 读账号面信息（GET）。
pub fn studio_json(credentials: &super::account::Credentials, path: &str, operation: &str) -> std::result::Result<Value, StudioError> {
    studio_request(credentials, "GET", path, operation)
}

/// 复用桌面端启动时的每日登录动作：带 Cookie 的 POST，不附带请求体。
pub fn init_app(credentials: &super::account::Credentials) -> std::result::Result<(), StudioError> {
    // 路径逐字来自 native endpoints::INIT_APP。
    let value = studio_request(credentials, "POST", INIT_APP, "每日登录")?;
    match value.get("banned").and_then(Value::as_bool) {
        Some(false) => Ok(()),
        Some(true) => Err(StudioError::Failed("AStudio 账号已被封禁，无法签到".into())),
        None => Err(StudioError::Failed("每日登录返回的账号状态不完整".into())),
    }
}

fn studio_request(
    credentials: &super::account::Credentials,
    method: &str,
    path: &str,
    operation: &str,
) -> std::result::Result<Value, StudioError> {
    let url = format!("{}{}", STUDIO_API_BASE, path.trim_start_matches('/'));
    let mut headers = json!({ "accept": "application/json", "cookie": credentials.cookie_header() });
    decorate(&mut headers);
    let response = http::open(method, &url, headers, None)
        .map_err(|error| StudioError::Failed(format!("{operation}网络失败：{}", error.message)))?;
    let status = response.status;
    if status == 401 || status == 403 {
        return Err(StudioError::Expired(format!(
            "AStudio 会话已失效（HTTP {status}），请重新登录 AStudio"
        )));
    }
    let bytes = response
        .bytes(1024 * 1024)
        .map_err(|error| StudioError::Failed(format!("读取{operation}响应失败：{}", error.message)))?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|_| StudioError::Failed(format!("{operation}返回的不是 JSON（HTTP {status}）")))?;
    let envelope = payload
        .as_object()
        .ok_or_else(|| StudioError::Failed(format!("{operation}返回的结果格式异常")))?;
    let code = envelope.get("code").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse::<i64>().ok()))
    });
    let flag = envelope.get("flag").and_then(Value::as_bool);
    let failed = !(200..300).contains(&status) || flag == Some(false) || code.is_some_and(|code| code != 0);
    if failed {
        let desc = envelope.get("desc").and_then(Value::as_str).unwrap_or("").to_string();
        if code == Some(80000) || desc.contains("重新登录") {
            return Err(StudioError::Expired("AStudio 会话已失效，请重新登录 AStudio".into()));
        }
        return Err(StudioError::Failed(if desc.is_empty() {
            format!("{operation}失败（HTTP {status}）")
        } else {
            format!("{operation}失败（HTTP {status}：{desc}）")
        }));
    }
    if flag != Some(true) || code != Some(0) {
        return Err(StudioError::Failed(format!("{operation}返回的成功状态不完整")));
    }
    envelope
        .get("data")
        .filter(|value| !value.is_null())
        .cloned()
        .ok_or_else(|| StudioError::Failed(format!("{operation}返回的数据不完整")))
}

/// 目录拉取的失败（与余额查询共用「会话失效」判据）。
pub enum CatalogError {
    Expired,
    Failed(String),
}

/// 拉模型目录（`GET /api/v1/model-manager/models`）。
pub fn fetch_catalog(key: &str) -> std::result::Result<Value, CatalogError> {
    let response = http::open(
        "GET",
        MODEL_MANAGER_URL,
        json!({ "authorization": format!("Bearer {key}"), "accept": "application/json" }),
        None,
    )
    .map_err(|error| CatalogError::Failed(error.message))?;
    let status = response.status;
    if status == 401 || status == 403 {
        return Err(CatalogError::Expired);
    }
    if !(200..300).contains(&status) {
        return Err(CatalogError::Failed(format!("HTTP {status}")));
    }
    response.json().map_err(|_| CatalogError::Failed("目录不是有效 JSON".into()))
}

/// 一次 Responses 请求（流式）。
pub fn responses(key: &str, body: &Value) -> Result<http::Response> {
    let response = http::open(
        "POST",
        RESPONSES_URL,
        json!({
            "authorization": format!("Bearer {key}"),
            "content-type": "application/json",
            "accept": "text/event-stream",
        }),
        Some(body),
    )?;
    let status = response.status;
    if (200..300).contains(&status) {
        return Ok(response);
    }
    let bytes = response.bytes(1024 * 1024).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let message = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.get("message"))
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            if text.trim().is_empty() {
                format!("AStudio 返回 HTTP {status}")
            } else {
                text.chars().take(500).collect()
            }
        });
    Err(Error::http(
        if status == 401 || status == 403 {
            401
        } else if status == 429 {
            429
        } else {
            status
        },
        message,
    ))
}

/// 错误体（网关按 OpenAI chat 错误解析）。
pub fn error_body(status: u16, message: &str) -> Value {
    json!({
        "error": {
            "type": if status == 429 { "rate_limit_error" } else { "api_error" },
            "message": message,
        }
    })
}
