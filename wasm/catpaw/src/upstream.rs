//! CatPaw 上游 HTTP 传输层：请求头、短请求 POST、状态回报、打断、turn 建流。
//!
//! ── 为什么单独一个文件（native `upstream_http.rs` 同一条理由）────
//! 这一层只管「怎么把一个请求发出去、怎么读一个短响应、发不出去时报什么」，
//! 不含任何轮次语义。与通用转发层的差别只有三点，都来自 CatPaw 的协议特性：
//!
//! ```text
//!   1. 请求头是 Cookie 形态（X-Passport-Token）而不是 Bearer（§9.1）；
//!   2. 短响应要过 unwrapApiData（上游把业务码写在 code 字段里）；
//!   3. turn 是 SSE：不读体，按行交给翻译层。
//! ```
//!
//! ── 迁移到 wasm 时改了什么 ────────────────────────────────
//!   - 出网从 `egress::control_client(proxy)` 换成宿主的 `http.open`：
//!     账号级代理由宿主按调用上下文统一生效（插件拿不到代理控制权）；
//!   - `CATPAW_UPSTREAM_BASE_URL` 环境变量在 wasm 沙箱里不存在，改读用户设置
//!     `upstream_base`（`settings.v1`），缺省仍是官方地址；
//!   - 没有请求级总超时旋钮（宿主按 `http.timeout.v1` 的能力上限统一管），
//!     所以这里不再传 timeout —— 语义上等价于「按网关的超时设置走」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic；不持锁。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Value};

use super::account::Credentials;
use super::errors::CatPawError;
use super::openai::unwrap_api_data;

/// 上游 base URL（架构文档 §9；`catpaw-upstream-client.mjs` 的
/// `DEFAULT_BASE_URL`）。
pub const DEFAULT_BASE_URL: &str = "https://ai.catpaw.meituan.com";

/// 上游 `source` 字段的固定取值（`catpaw-upstream-client.mjs`
/// 的 `DEFAULT_SOURCE`）。round / turn 请求体都要带上。
pub const DEFAULT_SOURCE: &str = "CatX";

/// 上游 `mode` 字段的固定取值（`DEFAULT_MODE`）
pub const DEFAULT_MODE: &str = "CATX_APP";

/// 上游 `permissionMode` 的固定取值（原实现写死在 round/turn 请求体里）
pub const PERMISSION_MODE: &str = "unsafeBypassPermissions";

/// 上游 `toolVersion` 字段（`DEFAULT_TOOL_VERSION`）。
/// 它对应桌面端客户端版本，改动会让上游按不同的工具语义解释请求。
pub const DEFAULT_TOOL_VERSION: &str = "2.0.2";

/// 桌面端客户端版本（`X-Agent-Version` 头）
pub const DEFAULT_CLIENT_VERSION: &str = "1.0.1";

/// `M-APPKEY` 头的固定值（架构文档 §9.1）：标识「外部版 CatPaw 客户端」。
pub const APP_KEY: &str = "fe_com.sankuai.catpaw.external.front";

/// 上游 base URL：用户设置 `upstream_base` 可覆盖（native 用同名环境变量）。
///
/// 保留这个覆盖点而不是写死常量：联调 / 私有部署时会指向别的 host。注意
/// `wasm.json` 的 `origins` 是硬白名单，改到白名单外的域名会被宿主直接拒 ——
/// 那是预期行为（插件不能自己扩大网络授权）。
pub fn base_url() -> String {
    sdk::settings::get("upstream_base")
        .ok()
        .and_then(|value| value.as_str().map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// 上游请求头集合（架构文档 §9.1 / 原实现 `createHeaders`）。
///
/// 客户端的 `authorization` / `cookie` **不透传**（§9.1）：代理凭证与客户端
/// 凭证是两套独立体系，透传会把客户端的 key 泄露给上游。
pub fn request_headers(credentials: &Credentials, accept: &str) -> Value {
    let mut headers = json!({
        "accept": accept,
        "content-type": "application/json",
        // M-TRACEID 每次请求都是新的随机串（去掉连字符，与原实现一致）
        "m-traceid": super::ids::new_trace_id(),
        "m-appkey": APP_KEY,
        "gray-set": "new-agent-sdk",
        "enableheartbeat": "true",
        "x-agent-version": DEFAULT_CLIENT_VERSION,
    });
    if !credentials.token.trim().is_empty() {
        headers["cookie"] = json!(format!("X-Passport-Token={}", credentials.token.trim()));
    }
    if !credentials.uid.trim().is_empty() {
        headers["user-uid"] = json!(credentials.uid.trim());
    }
    headers
}

/// 短请求的响应（状态码已在调用点校验，这里只留解包后的 JSON）。
struct Short {
    payload: Value,
}

/// 一次「一问一答」类型的上游 POST：发请求 → 读体 → 校验 HTTP → `unwrapApiData`。
///
/// round / event / turn/stop 三个端点都是短请求，共用这一个函数。
///
/// ── 为什么不是 async ────────────────────────────────────────
/// wasm 侧的 `http::open` / `http.read` 是**同步的宿主调用**（宿主在自己的
/// 线程上完成 IO 再把结果回给插件），插件里没有 await 的必要。整条链路因此
/// 都是同步函数：`handle` → `conversation::run` → 本模块。
fn post_json(path: &str, credentials: &Credentials, body: &Value) -> Result<Short, CatPawError> {
    let url = format!("{}{path}", base_url());
    let headers = request_headers(credentials, "application/json");
    let response = http::open("POST", &url, headers, Some(body))
        .map_err(|error| CatPawError::upstream(format!("上游请求失败: {}", error.message)))?;
    let status = response.status;
    // 短响应上限 256 KiB：控制类响应都是几十字节，超了就是上游行为异常
    let bytes = response
        .bytes(256 * 1024)
        .map_err(|error| CatPawError::upstream(format!("上游响应读取失败: {}", error.message)))?;
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&bytes).trim().chars().take(500).collect::<String>();
        return Err(CatPawError::http(
            status,
            if text.is_empty() {
                format!("上游 {path} HTTP {status}")
            } else {
                format!("上游 {path} HTTP {status}: {text}")
            },
        ));
    }
    if bytes.is_empty() {
        return Ok(Short { payload: Value::Null });
    }
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(Short { payload: unwrap_api_data(parsed)? })
}

/// `event`：状态回报（`running` / `completed` / `failed` / `canceled`）
pub fn report_status(
    credentials: &Credentials,
    conversation_id: &str,
    status: &str,
    error: Option<&CatPawError>,
) -> Result<Value, CatPawError> {
    let mut data = serde_json::Map::new();
    data.insert("status".to_string(), Value::String(status.to_string()));
    if let Some(error) = error {
        // 失败原因与业务码一起回报（原实现 `reportStatus` 的 data 字段：
        // failReason / failCode / unifyCode）
        data.insert("failReason".to_string(), Value::String(error.message.clone()));
        if let Some(code) = error.code {
            data.insert("failCode".to_string(), Value::from(code));
        }
        if let Some(code) = error.unify_code {
            data.insert("unifyCode".to_string(), Value::from(code));
        }
    }
    let body = json!({
        "conversationId": conversation_id,
        "eventType": "conversation",
        "data": Value::Object(data),
    });
    let result = post_json("/api/agent/conversation/event", credentials, &body)?;
    Ok(result.payload)
}

/// 终态上报（**吞掉失败**）：原实现 `reportTerminalStatus`。
///
/// 为什么吞：终态上报失败不该把已经成功的轮次变成失败 —— 客户端已经拿到完整
/// 回答了。它只影响上游侧的状态机（下一轮 round 可能被拒），而那条路径有
/// `conversation.rs` 的 `submit_round_with_self_heal` 兜底。
pub fn report_terminal(
    credentials: &Credentials,
    conversation_id: &str,
    status: &str,
    error: Option<&CatPawError>,
) {
    if conversation_id.is_empty() {
        return;
    }
    if let Err(failure) = report_status(credentials, conversation_id, status, error) {
        super::logging::verbose(&format!("终态 {status} 上报失败: {}", failure.message));
    }
}

/// `turn/stop`：打断一个正在执行的轮次（原实现 `stopTurn`，**尽力而为**）。
///
/// 失败只记日志：打断是收尾动作，把它的失败报成请求失败会掩盖真正的错误。
pub fn stop_turn(credentials: &Credentials, conversation_id: &str, turn_request_id: &str) {
    if conversation_id.is_empty() || turn_request_id.is_empty() {
        return;
    }
    let body = json!({
        "conversationId": conversation_id,
        "turnRequestId": turn_request_id,
    });
    if let Err(error) = post_json("/api/agent/conversation/turn/stop", credentials, &body) {
        super::logging::verbose(&format!("turn/stop 失败: {}", error.message));
    }
}

/// 发 turn 请求（SSE），返回可逐块读取的响应。
///
/// HTTP 非 2xx 在这里就失败（上游拒绝执行轮次，比如会话状态不对）：那时响应体
/// 是错误 JSON 而不是 SSE，读出来当文案比让执行层去解析它更清楚。
pub fn turn_open(credentials: &Credentials, body: &Value) -> Result<http::Response, CatPawError> {
    let url = format!("{}/api/agent/conversation/turn", base_url());
    let headers = request_headers(credentials, "text/event-stream");
    let response = http::open("POST", &url, headers, Some(body))
        .map_err(|error| CatPawError::upstream(format!("上游请求失败: {}", error.message)))?;
    let status = response.status;
    if !(200..300).contains(&status) {
        let bytes = response.bytes(256 * 1024).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes).trim().chars().take(500).collect::<String>();
        return Err(CatPawError::http(
            status,
            if text.is_empty() {
                format!("上游 turn HTTP {status}")
            } else {
                format!("上游 turn HTTP {status}: {text}")
            },
        ));
    }
    Ok(response)
}

/// 发一次 round（请求体由 `conversation.rs` 组装）。
///
/// round 承载对话内容，是唯一「上游真的收到了消息」的写操作：失败必须原样
/// 返回给调用方（自愈重试的判据就是这里抛出的 `执行中` 文案）。
pub fn submit_round(credentials: &Credentials, body: &Value) -> Result<Value, CatPawError> {
    let short = post_json("/api/agent/conversation/round", credentials, body)?;
    Ok(short.payload)
}

/// 短响应的业务码解包失败（供 `catalog.rs` 复用同一套错误文案）。
///
/// `#[allow(dead_code)]`：本文件当前的错误都在 `post_json` / `turn_open` 里
/// 就地构造；保留它是因为 `catalog.rs` 也要产出同一形状的短响应错误，
/// 将来合并两处时需要这个入口。
#[allow(dead_code)]
pub fn upstream_error(status: u16, message: impl Into<String>) -> Error {
    Error::http(status, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_carry_cookie_and_uid() {
        let credentials = Credentials::new("tk", "u1");
        let headers = request_headers(&credentials, "application/json");
        assert_eq!(headers["cookie"], json!("X-Passport-Token=tk"));
        assert_eq!(headers["user-uid"], json!("u1"));
        assert_eq!(headers["m-appkey"], json!(APP_KEY));
        assert_eq!(headers["x-agent-version"], json!(DEFAULT_CLIENT_VERSION));
    }

    #[test]
    fn headers_skip_empty_credentials() {
        let headers = request_headers(&Credentials::default(), "text/event-stream");
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("user-uid").is_none());
        assert_eq!(headers["accept"], json!("text/event-stream"));
    }
}
