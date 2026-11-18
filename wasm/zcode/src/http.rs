//! 出站 HTTP 的统一入口。
//!
//! ── 为什么要包一层 ──────────────────────────────────────────
//! native 用 `crate::http::send_raw`，它同时给了三件事：总超时、把响应体
//! 一次性读成 JSON（畸形给 `None`）、以及「非 2xx 也把 body 带回来」。
//! SDK 的 `http::Response::json()` 在非 2xx 时直接报错、把错误体丢掉 ——
//! 而这一家的**每一个**业务接口都靠错误体里的 `code` / `msg` 判语义
//! （3001 / 3007 / 1003 …），所以统一走 [`reply`]：先读字节再自己解。
//!
//! ── 超时 ────────────────────────────────────────────────────
//! native 给每个控制面请求设 15 秒（`REQUEST_TIMEOUT_MS`），理由是 egress 的
//! 默认读超时是 600 秒（给 SSE 长连接留的），不设就会让「查询余额」转圈十分钟。
//! SDK 的 `http::open` 不暴露 `timeout_ms`（那个参数要 `http.timeout.v1`
//! 且走宿主私有字段），所以这里不设：超时由宿主给每次插件调用设的总 deadline
//! 兜底。**这是与 native 的已知差异**，记在此处而不是静默着。

use agent2api_wasm_sdk::{http, Error, Result, Value};

/// 一次上游回应：状态码 + 解析后的正文（解析不出来时 `Value::Null`）。
pub struct Reply {
    pub status: u16,
    pub payload: Value,
}

impl Reply {
    /// HTTP 2xx 且没有业务错误体时算成功（调用方还要各自判 `code`）。
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 取响应头里的 `content-type`（主程序回的头不一定全是小写）。
pub fn content_type(headers: &Value) -> String {
    headers
        .as_object()
        .and_then(|object| {
            object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone())
        })
        .and_then(|value| {
            value.as_str().map(str::to_string).or_else(|| {
                value
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        })
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// 发一个请求并读完整回应。
///
/// `headers` 用 `(name, value)` 对：这一家的头顺序在注释里被当成「与官方
/// 客户端同序」的证据（`Authorization → Content-Type → 验证码 → 版本 → 平台
/// → 设备标识`），用对而不是对象是为了保住插入顺序。
pub fn send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
) -> Result<Reply> {
    let response = http::open(method, url, headers_value(headers), body)?;
    let status = response.status;
    // 4 MiB 上限与本家其它读法一致（`Response::json` 的默认上限）。
    let bytes = response.bytes(4 * 1024 * 1024)?;
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
    };
    Ok(Reply { status, payload })
}

/// `(name, value)` 对 → `sdk::http::open` 要的头对象。
pub fn headers_value(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// 传输失败 → 可读中文（native `transport_error` 的等价物）。
///
/// 插件这一层看不到「是不是超时」（宿主只回一句错误文案），因此统一报 502
/// 并把宿主原文带上 —— 编一个 504 会让「上游 IP 不通」被误读成「上游太慢」。
pub fn transport_error(what: &str, error: &Error) -> Error {
    Error::http(502, format!("{what}：{}", error.message))
}
