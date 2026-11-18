//! OrcaTerm 出站请求：地址、请求头、JSON 动作（CGI）与 SSE 对话流。
//!
//! ── 为什么收在一处 ──────────────────────────────────────────
//! CGI 网关（`cgi/api`）与 assistant 网关（`lightai`）共用同一套鉴权头
//! （`Authorization: Bearer <JWT>`）与错误翻译口径；各写一份会让「哪个状态码
//! 算登录失效」这类判据分叉。
//!
//! ── 错误翻译口径（逐条沿用 native 的 `http.rs`）──────────────
//!   - 连接 / 超时 → 502；
//!   - HTTP 401 / 403 → 401（JWT 失效，调用方走「强制刷新后重试一次」）；
//!   - 其余非 2xx → 原状态码 + 响应体前 240 字符。
//! CGI 的业务错误**不在这里判**：它 HTTP 恒 200，业务码在
//! `data.Response.Error`，由调用方各自翻译。
//!
//! ── 与 native 的差别 ────────────────────────────────────────
//! native 的 `post_json` 吃 `reqwest::Client`（带代理 / 超时 / UA 覆写策略）。
//! 宿主的 `http.open` 不接收客户端对象：出网策略（代理、超时、空闲上限）由网关
//! 按账号配置决定，插件只给 URL / 头 / 体。这里因此不再造 client，但**保留**
//! native 的判据与文案 —— 那些是「客户端该看到什么」，不是客户端实现细节。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::account::Credentials;

/// CGI 网关（账号 / 配额 / 续期）。
pub const CGI_BASE: &str = "https://api.orcaterm.cloud.tencent.com";

/// AI 助手网关（对话 + 会话管理）。
pub const LIGHTAI_BASE: &str = "https://lightai.cloud.tencent.com";

/// 上游认的站点来源（`Origin` / `Referer` 两处都用它）。
pub const SITE_ORIGIN: &str = "https://orcaterm.cloud.tencent.com";

/// 出站 User-Agent（Web 版同款；上游对默认 UA 敏感）。
pub const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
);

/// assistant 接口的固定 query。
pub const ASSISTANT_QUERY: &str = "name=orcaterm&mode=0&csrfCode=&sseresume=true";

/// 单次 JSON 响应的读取上限（管理接口都是几 KB 的小对象）。
const JSON_LIMIT: usize = 4 * 1024 * 1024;

/// 错误响应体的读取上限（只要前 240 字符，读太多纯属浪费内存）。
const ERROR_LIMIT: usize = 64 * 1024;

/// CGI 网关的请求头（`uin` 在 query 上，不在头里）。
pub fn cgi_headers(credentials: &Credentials) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), format!("Bearer {}", credentials.access_token)),
        ("Origin".to_string(), SITE_ORIGIN.to_string()),
        ("Referer".to_string(), format!("{SITE_ORIGIN}/")),
    ]
}

/// assistant 网关的请求头（`X-Product: orcaterm` 是本家的产品标识）。
pub fn lightai_headers(credentials: &Credentials, seq_id: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), format!("Bearer {}", credentials.access_token)),
        ("X-Product".to_string(), "orcaterm".to_string()),
        ("x-seqid".to_string(), seq_id.to_string()),
        ("Origin".to_string(), SITE_ORIGIN.to_string()),
        ("Referer".to_string(), format!("{SITE_ORIGIN}/")),
    ]
}

/// `Vec<(键, 值)>` → 宿主要的头表（小写键）。
///
/// 小写是契约：宿主的头表按小写比较，`Authorization` 写成大写会被当成另一个头。
/// 返回 `Map` 而不是 `Value`，是为了让调用方用 `insert` 补公共头 —— `Value` 的
/// 下标赋值在类型不符时会 panic，而 panic 在 wasm 里等于整个实例挂掉。
pub fn header_map(headers: &[(String, String)]) -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    for (key, value) in headers {
        object.insert(key.to_ascii_lowercase(), Value::String(value.clone()));
    }
    object
}

/// 一次 JSON POST，返回已解析的 JSON。
pub fn post_json(url: &str, headers: &[(String, String)], body: &Value) -> Result<Value> {
    let mut all = header_map(headers);
    all.insert("content-type".to_string(), json!("application/json"));
    all.insert("accept".to_string(), json!("application/json"));
    all.insert("user-agent".to_string(), json!(USER_AGENT));
    let response = http::open("POST", url, Value::Object(all), Some(body)).map_err(|error| {
        Error::http(502, format!("OrcaTerm 请求发不出去（{url}）：{}", error.message))
    })?;
    let status = response.status;
    let bytes = response.bytes(JSON_LIMIT).map_err(|error| {
        Error::http(502, format!("OrcaTerm 读取响应失败（{url}）：{}", error.message))
    })?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    if !(200..300).contains(&status) {
        return Err(translate(status, url, &text));
    }
    serde_json::from_str(&text).map_err(|error| {
        Error::http(502, format!("OrcaTerm 返回非 JSON 响应（{url}）：{error}"))
    })
}

/// 非 2xx 的统一翻译。
fn translate(status: u16, url: &str, body: &str) -> Error {
    if status == 401 || status == 403 {
        return Error::http(
            401,
            format!(
                "OrcaTerm 登录态已失效，请重新导入或重新粘贴该账号的 accessToken（HTTP {status}，{url}）"
            ),
        );
    }
    let head: String = body.chars().take(240).collect();
    Error::http(status, format!("OrcaTerm 返回 HTTP {status}（{url}）：{head}"))
}

/// 发起一次 SSE 流式 POST（对话流；**不设总超时**，长推理不被截断）。
///
/// 返回原始响应，调用方自己逐段读。空闲兜底由宿主管 —— 插件拿不到 socket 选项，
/// 也不该重复做一份。
pub fn sse_post(
    url: &str,
    headers: &[(String, String)],
    body: &Value,
    what: &str,
) -> Result<http::Response> {
    let mut all = header_map(headers);
    all.insert("content-type".to_string(), json!("application/json"));
    all.insert("accept".to_string(), json!("text/event-stream"));
    all.insert("user-agent".to_string(), json!(USER_AGENT));
    let response = http::open("POST", url, Value::Object(all), Some(body))
        .map_err(|error| Error::http(502, format!("{what}失败：{}", error.message)))?;
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    let status = response.status;
    if status == 401 || status == 403 {
        return Err(Error::http(
            401,
            format!(
                "OrcaTerm 登录态已失效，请重新导入或重新粘贴该账号的 accessToken（HTTP {status}）"
            ),
        ));
    }
    let head = error_head(response);
    Err(Error::http(status, format!("OrcaTerm 返回 HTTP {status}（{what}）：{head}")))
}

/// 读错误响应体的前 240 字符（读不到就给空串，不让读取失败盖掉状态码）。
fn error_head(response: http::Response) -> String {
    match response.bytes(ERROR_LIMIT) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).chars().take(240).collect(),
        Err(_) => String::new(),
    }
}

/// 调一次 CGI 动作（`POST {CGI}/cgi/api?action=<Action>&uin=<uid>`）。
///
/// HTTP 恒 200，业务码在 `data.Response.Error` —— 这里只拆出 `data.Response`，
/// 错误判定归调用方。
pub fn cgi_action(credentials: &Credentials, action: &str, data: Value) -> Result<Value> {
    let url = format!("{CGI_BASE}/cgi/api?action={action}&uin={}", credentials.user_id);
    let body = json!({ "action": action, "data": data });
    let value = post_json(&url, &cgi_headers(credentials), &body)?;
    Ok(value
        .get("data")
        .and_then(|data| data.get("Response"))
        .cloned()
        .unwrap_or(Value::Null))
}

/// 调一次**匿名** CGI 动作（不带 `Authorization`，也不带 `uin`）。
///
/// `OAuthExchangeToken` 是登录**之前**的动作：此时还没有令牌可带，凭据就是
/// 请求体里的 `sessionId` 本身（一次性、由本进程生成、只出现在我们自己窗口的
/// URL 里）—— 安全性由「不可预测 + 一次性」承担。
pub fn cgi_action_anonymous(action: &str, data: Value) -> Result<Value> {
    let url = format!("{CGI_BASE}/cgi/api?action={action}");
    let headers = vec![
        ("Origin".to_string(), SITE_ORIGIN.to_string()),
        ("Referer".to_string(), format!("{SITE_ORIGIN}/")),
    ];
    let body = json!({ "action": action, "data": data });
    let value = post_json(&url, &headers, &body)?;
    Ok(value
        .get("data")
        .and_then(|data| data.get("Response"))
        .cloned()
        .unwrap_or(Value::Null))
}

/// `GetUserInfo`（探活 + 补身份）。返回 `(userId, nickname)`。
pub fn fetch_user_info(credentials: &Credentials) -> Result<(String, String)> {
    let response = cgi_action(credentials, "GetUserInfo", json!({}))?;
    if let Some(error) = response.get("Error") {
        let code = error.get("Code").and_then(Value::as_str).unwrap_or("UNKNOWN");
        let message = error.get("Message").and_then(Value::as_str).unwrap_or("上游错误");
        return Err(Error::http(
            401,
            format!("OrcaTerm 凭证被上游拒绝（{code}：{message}）"),
        ));
    }
    let user_id = response
        .get("userId")
        .map(|value| match value {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| credentials.user_id.clone());
    // 展示名按「第一个非空的候选」取：上游这三段的**存在性并不稳定** ——
    // 微信登录实测是 `nickName: ""` + `username: "一颗苹果"`，只按键存在与否
    // 判断会把昵称丢成空串。
    let nickname = ["nickName", "username", "displayName"]
        .iter()
        .filter_map(|key| response.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_string();
    Ok((user_id, nickname))
}

/// 这个错误是不是「登录态失效」（调用方据此强制续期后重试一次）。
pub fn is_auth(error: &Error) -> bool {
    matches!(error.status, Some(401) | Some(403))
}
