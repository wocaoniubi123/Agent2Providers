//! OrcaTerm 错误分类。
//!
//! ── 为什么这里恒 `fatal` ────────────────────────────────────
//! 逐字沿用 native `mod.rs` 的决策：上游**没有 HTTP 429**（限额错误在流内
//! `LLM_ERROR` 帧里），且配额按月重置 —— 做冷却记账的收益为负（冷却键是
//! 账号级配额，误冷却一整个月比透传错误更糟）。所以网关那边换账号/冷却的
//! 那一套对本家一律不启用，只把状态码与文案如实交出去。
//!
//! ── 契约要窄 ────────────────────────────────────────────────
//! 网关的 `upstream::provider_loop` 只认识四档处置（限额换号 / 凭证刷新 /
//! 内容拦截降级 / 终态透传），多发明一档会静默落进 Fatal，反而更难查。

use agent2api_wasm_sdk::{json, Value};

/// 非 2xx 的分类（`classify`）。
pub fn classify(status: u16, body: &Value) -> Value {
    let message = body["message"]
        .as_str()
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误")
        .to_string();
    json!({
        "kind": "fatal",
        "status": status,
        "message": message,
        "reset_at": Value::Null,
        "upstream_code": Value::Null,
    })
}

/// 这个响应算不算错误（内容拦截判定的挂点）。
///
/// 本家没有「HTTP 200 里塞业务错误信封」的形态（流内错误由 `chat.rs` 在
/// 首帧门与流内帧各自判掉），所以只按状态码回答。
pub fn is_error_response(status: u16) -> bool {
    status >= 400
}

/// 是否停手（不再换账号）。
///
/// 本家没有「换账号也没用」的判据落在状态码上：额度是账号级月度配额，
/// 凭证失效 401 正是要换账号/续期的场景。所以一律不停手。
pub fn policy() -> Value {
    json!({ "stop": false })
}

/// 流内错误帧的形态（与 native `sse::error_bytes` 逐字一致：
/// `{"error":{"message":…,"type":"proxy_error"}}`）。
///
/// 客户端此时已经收到 200 与部分内容，唯一能告诉它「失败」的办法就是
/// 在流里写一条错误帧。
pub fn error_event(message: &str) -> Value {
    json!({ "error": { "message": message, "type": "proxy_error" } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_is_always_fatal() {
        let value = classify(500, &json!({ "message": "boom" }));
        assert_eq!(value["kind"], json!("fatal"));
        assert_eq!(value["message"], json!("boom"));
        // 空 message 要有兜底文案，不能把空串塞给界面
        assert_eq!(classify(502, &json!({}))["message"], json!("上游错误"));
    }

    #[test]
    fn error_frame_shape_matches_native() {
        let value = error_event("断了");
        assert_eq!(value["error"]["type"], json!("proxy_error"));
        assert_eq!(value["error"]["message"], json!("断了"));
    }

    #[test]
    fn only_http_errors_are_errors() {
        assert!(!is_error_response(200));
        assert!(is_error_response(400));
        assert_eq!(policy()["stop"], json!(false));
    }
}
