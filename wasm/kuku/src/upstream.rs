//! KukuAI 出站请求的薄封装：公共常量、头集合、JSON / 表单 / SSE 三种请求。
//!
//! ── 为什么收在一处（照 native `kuku/http.rs` 的模块头）──────────
//! 对话链路（`userreport` / `sendmsg` / `idallochstr` / `getchatcontent`）共用同一套
//! 头集合与错误翻译；各写一份会让「哪个状态码算登录失效」这类判据分叉。
//!
//! ── 错误翻译口径（与 native 逐条一致）──────────────────────
//!   - HTTP 401 / 403 → 401（登录态失效，用户看到「请重新登录」）；
//!   - 其余非 2xx → 原状态码 + 响应体前 240 字符（排障用）；
//!   - 业务码（`errno` / `status.code`）**不在这里判**：各接口的成功判定不同
//!     （userreport 看 `errno`、sendmsg 看 `status.code`），由调用方各自翻译。
//!
//! ── 代理 ────────────────────────────────────────────────────
//! native 侧 `send_raw` 收一个 `proxy` 参数（编排层解析好的账号代理）。插件协议里
//! 出站代理由宿主按账号设置自动套用（`account_egress`），插件不碰这一层 —— 因此
//! 本文件的每个函数都没有代理参数。
//!
//! ── 超时 ────────────────────────────────────────────────────
//! native 给管理接口 30 秒、目录 10 秒、余额 15 秒。wasm 侧要单独设超时得申请
//! `http.timeout.v1`（本包没申请），出站超时统一由宿主按调用截止时间控制。
//! 这不影响语义：真正需要「不设总超时」的只有对话 SSE，而宿主对 `conversation`
//! 用的是流式读（逐块），不会被一次性超时截断。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::errors;

/// 主站（对话 / 目录 / 积分全在这一个域上）
pub const BASE_URL: &str = "https://kuku.baidu.com";

/// 客户端硬编码的 app_id（`123971023`；另一个 `123971202` 是云盘流媒体专用的，
/// 别混用 —— 缺了这个值 freepoint / sendmsg 会 400 `params error`）
pub const APP_ID: i64 = 123971_023;

/// 客户端硬编码的 channel
pub const CHANNEL: &str = "chunlei";

/// 对话链路 query（kuku2api 实测的**网页形态**：`clienttype=400&web=1&version=1.4.4`）。
///
/// 为什么对话不用桌面客户端形态（`401/1.6.7`）：sendmsg / getchatcontent 的实测记录
/// 来自 kuku2api（网页形态），桌面形态只有 freepoint 的实测。两组接口各认各的形态，
/// 照抄各自的实测值。余额接口（`/bizapi/gfpro/getgfvipremain`）**不带 app_id**
/// （客户端 `http.get` 的 params 为空，见 `usage`），这里没有它的常量。
pub const WEB_QUERY: &str = "clienttype=400&app_id=123971023&web=1&channel=chunlei&version=1.4.4";

/// 出站 User-Agent（kuku2api 实测可用；上游对 UA 敏感，不能用默认值）
pub const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
);

/// 30 天签到活动页。风控接口按来源页校验，Referer 不能省。
pub const ACTIVITY_REFERER: &str = "https://kuku.baidu.com/operation/activitys/kukuPcSignAct/main";

/// 默认模型（上游自动选路；未知模型名显式回退它，避免上游静默降级）
pub const DEFAULT_MODEL: &str = "auto";

/// 思考模式默认档（参考实现固定 3；本包不接思考等级绑定 ——
/// 上游 `think_mode` 的档位语义没有实测证据，按「没有证据就不注入」保持默认）
pub const DEFAULT_THINK_MODE: i64 = 3;

/// 普通响应体上限（管理接口的 JSON 都很小，给 4 MiB 足够）
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// 非 2xx 诊断体的读取预算（与 native 的 240 字符口径配合）
const ERROR_BODY_BUDGET: usize = 8 * 1024;

/// 诊断体进文案的字符上限（native 用 240 字符）
const ERROR_HEAD_CHARS: usize = 240;

/// 通用头集合（Cookie + UA + 同源 Referer/Origin + 语言）。
pub fn headers(cookie: &str) -> Value {
    json!({
        "cookie": cookie,
        "user-agent": USER_AGENT,
        "referer": format!("{BASE_URL}/genflowpro"),
        "origin": BASE_URL,
        "accept-language": "zh-CN,zh;q=0.9",
    })
}

/// 对话 SSE 的头集合（多了 `accept: text/event-stream`）。
pub fn sse_headers(cookie: &str) -> Value {
    let mut value = headers(cookie);
    value["accept"] = json!("text/event-stream");
    value["content-type"] = json!("application/json");
    value
}

/// 30 天签到活动用的头集合。Referer 必须是活动页 —— 风控按来源页判定。
pub fn activity_headers(cookie: &str) -> Value {
    let mut value = headers(cookie);
    value["referer"] = json!(ACTIVITY_REFERER);
    value["accept"] = json!("application/json, text/plain, */*");
    value
}

/// 一次 GET，返回已解析的 JSON（非 2xx / 解析失败都翻译成网关错误）。
pub fn get_json(url: &str, headers: &Value) -> Result<Value> {
    let response = http::open("GET", url, headers.clone(), None)?;
    read_json(response, url)
}

/// 一次 JSON POST，返回已解析的 JSON。
pub fn post_json(url: &str, headers: &Value, body: &Value) -> Result<Value> {
    let response = http::open("POST", url, headers.clone(), Some(body))?;
    read_json(response, url)
}

/// 一次表单 POST（`freepoint/taskComplete` / 30 天签到这类
/// `x-www-form-urlencoded` 接口），返回已解析的 JSON。
///
/// 表单值由调用方给定：签到任务的 `task_type` 是 `LOGIN` / `CHAT` 这类常量，
/// 不含需要百分号编码的字符，按 `k=v` 直接拼接（与上游客户端一致）。
pub fn post_form(url: &str, headers: &Value, form: &[(&str, &str)]) -> Result<Value> {
    let mut outgoing = headers.clone();
    outgoing["content-type"] = json!("application/x-www-form-urlencoded;charset=UTF-8");
    outgoing["accept"] = json!("application/json, text/plain, */*");
    let body = form
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let response = http::open_raw("POST", url, outgoing, Some(body.as_bytes()))?;
    read_json(response, url)
}

/// 发起一次 SSE 流式 POST（对话流）。
///
/// 返回原始 `http::Response`（调用方逐块读）。**非 2xx 在这里就翻译成错误**：
/// 那时一个字节都没下发，正好让编排层换账号。连接建立后读失败由调用方处理
/// （那时已经下发过 `stream.head`，属于「已下发后出错」分支）。
pub fn sse_open(url: &str, headers: &Value, body: &Value) -> Result<http::Response> {
    let response = http::open("POST", url, headers.clone(), Some(body))?;
    let status = response.status;
    if !(200..300).contains(&status) {
        let head = read_head(response, ERROR_BODY_BUDGET);
        return Err(errors::http_error(status, url, &head));
    }
    Ok(response)
}

/// 把一次响应翻成「已解析的 JSON」，非 2xx 走统一翻译。
fn read_json(response: http::Response, url: &str) -> Result<Value> {
    let status = response.status;
    if !(200..300).contains(&status) {
        let head = read_head(response, ERROR_BODY_BUDGET);
        return Err(errors::http_error(status, url, &head));
    }
    let bytes = response.bytes(MAX_RESPONSE_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::http(502, format!("KukuAI 返回非 JSON 响应（{url}）")))
}

/// 读一段诊断体（最多 `limit` 字节），返回可给人的摘要。
///
/// 读失败也把手上已有的一段返回：诊断体本身不完整不影响「上游返回了什么」
/// 这个判断，如实标注比丢掉更有用。
fn read_head(mut response: http::Response, limit: usize) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(buffer.len());
                if chunk.len() > room {
                    buffer.extend_from_slice(&chunk[..room]);
                    break;
                }
                buffer.extend_from_slice(&chunk);
                if buffer.len() >= limit {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    errors::truncate_chars(text.trim(), ERROR_HEAD_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 常量一旦被改错，上游会静默降级或 400 `params error` —— 这条测试钉住实测值。
    #[test]
    fn constants_match_the_measured_client_shape() {
        assert_eq!("chunlei", CHANNEL);
        assert_eq!(123_971_023, APP_ID);
        assert!(WEB_QUERY.contains("clienttype=400"));
        assert!(WEB_QUERY.contains("version=1.4.4"));
        assert!(!WEB_QUERY.contains("app_id=123971202"));
        assert_eq!("auto", DEFAULT_MODEL);
        assert_eq!(3, DEFAULT_THINK_MODE);
    }

    /// 两套头的差别：对话要 SSE，签到要把 Referer 换成活动页（风控按来源页判）。
    #[test]
    fn header_sets_carry_the_right_referer() {
        let plain = headers("BDUSS=abc");
        assert_eq!(format!("{BASE_URL}/genflowpro"), plain["referer"].as_str().unwrap_or_default());
        assert_eq!(BASE_URL, plain["origin"].as_str().unwrap_or_default());

        let sse = sse_headers("BDUSS=abc");
        assert_eq!("text/event-stream", sse["accept"].as_str().unwrap_or_default());

        let activity = activity_headers("BDUSS=abc");
        assert_eq!(ACTIVITY_REFERER, activity["referer"].as_str().unwrap_or_default());
        assert_eq!(BASE_URL, activity["origin"].as_str().unwrap_or_default());
    }
}
