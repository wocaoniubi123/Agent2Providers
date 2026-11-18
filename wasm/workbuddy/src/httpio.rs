//! 一次上游请求的最小封装 + 响应信封解包。
//!
//! native 用 `crate::http::send_raw`（reqwest + 代理 + 超时）拿到
//! `ApiResponse { status, ok, payload }`，全仓（登录/计费/目录/成长）都按这个形状
//! 判「HTTP 成功 + 业务码」。wasm 侧只剩 `sdk::http::open`，所以把**同一个形状**
//! 收口到这里，让上层那些判定逻辑可以逐字保留。
//!
//! ── 超时 ────────────────────────────────────────────────────
//! native 每个调用点给不同超时（登录 30s / 计费 20s / 身份核对 4s）。wasm 的
//! `http.open` 没有超时参数（宿主统一管），所以这里不再传 —— 影响是「上游卡住
//! 时由宿主的默认超时收尾」，而不是插件自己那一档。

use agent2api_wasm_sdk::{http, Error, Result, Value};

use crate::util;

/// 一次上游响应的统一形态（与 native `http::ApiResponse` 同字段）。
pub struct ApiResponse {
    pub status: u16,
    pub ok: bool,
    /// 已解析的 JSON 体；非 JSON（HTML / 空体）时为 None
    pub payload: Option<Value>,
    /// 响应头（小写键），判 `content-type` 用
    pub headers: Value,
}

impl ApiResponse {
    /// 业务信封的 `code`（缺失为 None）。
    pub fn code(&self) -> Option<i64> {
        self.payload
            .as_ref()
            .and_then(|value| value.get("code"))
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
            })
    }

    /// `data` 段（缺失为 Null）。
    #[allow(dead_code)]
    pub fn data(&self) -> Value {
        self.payload
            .as_ref()
            .and_then(|value| value.get("data"))
            .cloned()
            .unwrap_or(Value::Null)
    }
}

/// 单次请求的读体上限（响应体不可能是巨物；超过就按「非 JSON」处理）。
const MAX_BODY: usize = 4 * 1024 * 1024;

/// 发一次请求（`body` 为 None 时不带请求体）。
pub fn send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
) -> Result<ApiResponse> {
    let response = http::open(method, url, util::headers_value(headers), body)?;
    let status = response.status;
    let headers_value = response.headers.clone();
    let bytes = response.bytes(MAX_BODY)?;
    let payload = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(&bytes).ok()
    };
    Ok(ApiResponse {
        status,
        ok: (200..300).contains(&status),
        payload,
        headers: headers_values(headers_value),
    })
}

/// 让 `headers` 恒为对象（宿主可能给数组形态的 [[name, value]]）。
fn headers_values(value: Value) -> Value {
    match value {
        Value::Array(pairs) => {
            let mut object = serde_json::Map::new();
            for pair in pairs {
                if let Some(items) = pair.as_array() {
                    let name = items.first().and_then(Value::as_str).unwrap_or("");
                    let value = items.get(1).cloned().unwrap_or(Value::Null);
                    if !name.is_empty() {
                        object.insert(name.to_ascii_lowercase(), value);
                    }
                }
            }
            Value::Object(object)
        }
        other => other,
    }
}

/// 传输层失败的统一文案（native `http::describe_chain` 的同义物）。
///
/// 不透传 SDK 的原始错误串：那里面可能带 URL 与查询串（登录 state 属于凭据）。
pub fn transport_error(action: &str, error: Error) -> Error {
    Error::http(502, format!("{action}失败：上游连接或响应不可用（{}）", error.message))
}

/// 解包 `{code, data, msg}` 信封（native `auth_http::unwrap_response` 的插件侧副本）。
///
/// 三档：非 JSON 且非 2xx、非 2xx（取 `error.message` / `message` / `msg`）、
/// 以及 2xx 但业务码非 0。返回 `data` 段。
pub fn unwrap_response(response: &ApiResponse, api_name: &str) -> Result<Value> {
    let payload = response.payload.as_ref();
    if payload.is_none() && !response.ok {
        return Err(Error::http(
            response.status,
            format!("{api_name} 返回非 JSON 响应（HTTP {}）", response.status),
        ));
    }
    if !response.ok {
        let message = payload
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .or_else(|| value.get("message").and_then(Value::as_str))
                    .or_else(|| value.get("msg").and_then(Value::as_str))
            })
            .unwrap_or("")
            .to_string();
        let message = if message.is_empty() {
            format!("HTTP {}", response.status)
        } else {
            message
        };
        let code = payload
            .and_then(|value| value.get("code"))
            .and_then(Value::as_i64);
        return Err(code.map_or_else(
            || Error::http(response.status, format!("{api_name} 失败: {message}")),
            |code| {
                Error::http(response.status, format!("{api_name} 失败: {message}"))
                    .with_code(code.to_string())
            },
        ));
    }
    if let Some(code) = response.code() {
        if code != crate::endpoints::RESPONSE_CODE_OK {
            let detail = payload
                .and_then(|value| {
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .or_else(|| value.get("msg").and_then(Value::as_str))
                })
                .unwrap_or("")
                .trim()
                .to_string();
            let message = if detail.is_empty() {
                format!("{api_name} 失败: code={code}")
            } else {
                format!("{api_name} 失败: code={code} {detail}")
            };
            let mut error = Error::http(502, message).with_code(code.to_string());
            error.upstream_code = Some(code);
            return Err(error);
        }
    }
    Ok(payload
        .and_then(|value| value.get("data"))
        .cloned()
        .unwrap_or(Value::Null))
}
