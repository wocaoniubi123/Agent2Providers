//! 上游错误 → 网关认识的分类 / 错误事件 / 出站错误翻译。
//!
//! ── 本家的错误形态（三种，来自实测记录）────────────────────
//!   1. HTTP 非 2xx：正文可能是 HTML（风控页）也可能是 JSON；
//!   2. HTTP 200 + 顶层 `{errno, show_msg | errmsg}`（`userreport` / `freepoint` /
//!      签到活动这一族接口的成功判据是 `errno == 0`）；
//!   3. HTTP 200 + 顶层 `{status: {code, msg}}`（`sendmsg` / `model/list` /
//!      `getgfvipremain` 这一族，判据是 `status.code == 0`）。
//!
//! 第 2、3 两种由各接口自己翻译（成功判据不同，见 `chat` / `models` /
//! `usage` / `checkin` 各自的模块头）；本文件只负责**状态码层面**的分类与
//! 「把分类折成一条 SSE 错误事件」。
//!
//! ── 与 native 的对应 ────────────────────────────────────────
//! native `kuku/mod.rs` 的 `classify()` 一律给 `ErrorClass::Fatal`：上游业务错误
//! 在 `chat::run_chat` 内部已经按参考实现的口径归一到状态码与文案，
//! `classify` 在正常路径上走不到。这里逐字沿用同一条口径（也保留这句判断
//! 依据：把本家错误再分档没有实测证据，凭空分档只会让编排层做出错的换号决定）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Value};

/// 上游错误文案的通用兜底。
pub const FALLBACK_MESSAGE: &str = "上游错误";

/// 从三种错误形态里尽力取一句人话（`message` / `show_msg` / `errmsg` /
/// `status.msg`），取不到给 `FALLBACK_MESSAGE`。
pub fn message_of(body: &Value) -> String {
    let direct = ["message", "msg", "show_msg", "errmsg", "error_description"]
        .iter()
        .find_map(|key| body.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty());
    if let Some(text) = direct {
        return text.to_string();
    }
    let nested = body
        .get("status")
        .and_then(|status| status.get("msg"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    match nested {
        Some(text) => text.to_string(),
        None => FALLBACK_MESSAGE.to_string(),
    }
}

/// 非 2xx 的分类（与 native `classify()` 同口径：一律 Fatal）。
pub fn classify(status: u16, body: &Value) -> Value {
    json!({
        "kind": "fatal",
        "status": status,
        "message": message_of(body),
        "reset_at": Value::Null,
        "upstream_code": Value::Null,
        "code": Value::Null,
    })
}

/// 非 2xx 的翻译：401 / 403 是登录态失效，其余原样带状态码与诊断体前 240 字符。
///
/// ── 为什么 401/403 要改写成 401 ─────────────────────────────
/// 本家的登录态是 Cookie（BDUSS / STOKEN），没有刷新接口 —— 403 在这家通常也是
/// 「这个 Cookie 不被认」，让编排层按 `token_expired` 处理比按 `fatal` 更准：
/// 用户看到的是「请重新登录」，而不是「上游请求未成功」这种无从下手的提示。
pub fn http_error(status: u16, url: &str, head: &str) -> Error {
    let head = head.trim();
    if status == 401 || status == 403 {
        return Error::http(
            401,
            format!("KukuAI 登录态已失效，请重新登录或重新导入该账号（HTTP {status}）"),
        )
        .with_code("token_expired");
    }
    let mut message = format!("KukuAI 返回 HTTP {status}（{url}）");
    if !head.is_empty() {
        message.push('：');
        message.push_str(head);
    }
    Error::http(status.max(400), message)
}

/// 一条 SSE 错误事件（已经下发过字节之后再出错时补在流里）。
///
/// 形状与 atomcode / codearts 一致：`{"error": {"message", "type", "status"}}`，
/// 网关的聚合器认得它，客户端也能按 OpenAI 错误体解析。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({
        "error": {
            "message": error.message,
            "type": "upstream_error",
            "status": status,
        },
    })
}

/// 按字符数截断（中文文案按字节截会切出半个字符）。
pub fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let mut out: String = value.chars().take(limit).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_falls_back_through_three_shapes() {
        assert_eq!("直接消息", message_of(&json!({ "message": "直接消息" })));
        assert_eq!("业务码消息", message_of(&json!({ "errno": -6, "show_msg": "业务码消息" })));
        assert_eq!("包络消息", message_of(&json!({ "status": { "code": 1, "msg": "包络消息" } })));
        assert_eq!(FALLBACK_MESSAGE, message_of(&json!({ "errno": -6 })));
    }

    #[test]
    fn auth_failures_become_401_with_token_expired() {
        let error = http_error(403, "https://kuku.baidu.com/x", "forbidden");
        assert_eq!(Some(401), error.status);
        assert_eq!(Some("token_expired"), error.code.as_deref());
        let error = http_error(500, "https://kuku.baidu.com/x", "boom");
        assert_eq!(Some(500), error.status);
        assert!(error.message.contains("boom"));
    }

    #[test]
    fn classification_is_always_fatal() {
        let class = classify(429, &json!({ "errno": 123, "errmsg": "稍后再试" }));
        assert_eq!("fatal", class["kind"].as_str().unwrap_or_default());
        assert_eq!(429, class["status"].as_u64().unwrap_or(0));
        assert_eq!("稍后再试", class["message"].as_str().unwrap_or_default());
    }
}
