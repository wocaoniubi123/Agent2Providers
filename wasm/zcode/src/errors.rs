//! 上游业务错误的分类与重试判据（native `zcode/errors.rs` 的移植）。
//!
//! ── 顺序为什么不能改 ────────────────────────────────────────
//! 风控拒绝（3012 / 明确的「unusual activity」原文）必须**先于**限额、凭证与
//! 内容策略判定：它是最可达的结论（用户能照着做的是「换官方客户端核对」），
//! 而且它要阻止后续重试 —— 被当成限额处理会让网关不停换账号撞同一面墙。
//!
//! ── 与 native 的一处已知差异 ────────────────────────────────
//! native 最后一档走网关共享的 `content_block::classify_or_fatal`（一张跨家的
//! 内容策略关键词表）。插件拿不到那张表，这里按同一批关键词判断
//! （`content_filter` / `content_policy` / `safety` / `审核` / `敏感`）——
//! 漏判的后果是「内容拒绝被当 Fatal 透给客户端」，方向安全：不罚账号、
//! 也不会错误地换账号重试。

use agent2api_wasm_sdk::{json, Error, Value};

use super::common::{text_of, integer_of};

/// 上游业务码（`code` / `error.code`，数字与字符串两种写法都认）。
pub fn upstream_code(body: &Value) -> Option<i64> {
    [
        body.get("code"),
        body.pointer("/error/code"),
    ]
    .into_iter()
    .flatten()
    .find_map(integer_of)
}

/// 上游给的一句人话（`message` → `msg` → `error.message` → `error.msg`）。
pub fn message(body: &Value) -> Option<String> {
    let from_fields = text_of(body, &["message", "msg"]);
    if !from_fields.is_empty() {
        return Some(from_fields);
    }
    let nested = text_of(body.get("error").unwrap_or(&Value::Null), &["message", "msg"]);
    if !nested.is_empty() {
        return Some(nested);
    }
    body.as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

/// 风控拒绝（业务码 3012，或 403/405 且原文是上游那句 unusual activity）。
pub fn is_risk_rejection(status: u16, body: &Value) -> bool {
    match upstream_code(body) {
        Some(code) => code == 3012,
        None => {
            // 只有上游明确的风控原文才能补判；普通 405 不能等同于账号受限。
            matches!(status, 403 | 405)
                && message(body).is_some_and(|text| {
                    text.to_ascii_lowercase()
                        .contains("request has been blocked due to unusual activity")
                })
        }
    }
}

/// 业务码 3007（要人机验证）的说明。
pub fn code_hint(code: i64) -> Option<&'static str> {
    match code {
        3007 => Some(
            "上游要求人机验证（3007）：验证码令牌缺失或已失效。\
             令牌由打开着的主窗口或浏览器面板页自动铸造；若持续出现，请稍后重试",
        ),
        3012 => Some(
            "套餐池请求被上游拒绝（3012），不代表套餐额度已用尽。\
             已停止后续重试，不再刷新凭证或切换账号。\
             请用官方 ZCode 客户端核对同一账号、同一套餐池：若同样失败，\
             需联系上游支持核查；若仅网关失败，请检查提供商插件与请求兼容性。\
             反复重试或充值不能解除这类限制。\
             编码套餐与套餐池额度独立，切换通道不会转移这份额度",
        ),
        3001 => Some("上游判定参数错误（3001）：请重新登录该账号以刷新设备标识"),
        _ => None,
    }
}

/// 限额提示（429 / 1005 时补一句「额度在哪条通道上」）。
pub fn quota_hint(raw: &str) -> Option<&'static str> {
    let hit = raw.contains("余额不足")
        || raw.contains("资源包")
        || raw.to_lowercase().contains("insufficient balance");
    hit.then_some(
        "这条限额来自开放平台计费平面：编码套餐通道只消耗开放平台的额度\
         （订阅套餐 / 资源包 / 充值余额），与 ZCode 套餐池互不相通。\
         若这个账号的额度在套餐池里（新注册的体验额度、活动领取的额度），\
         请在账号设置里把使用套餐切到套餐池（Start Plan）",
    )
}

/// 内容策略拒绝的关键词（与 native 共享词表同一批；见模块头）。
fn is_content_blocked(status: u16, body: &Value) -> bool {
    if !matches!(status, 400 | 403 | 451) {
        return false;
    }
    let raw = body.to_string().to_ascii_lowercase();
    ["content_filter", "content_policy", "safety_violation", "sensitive"]
        .iter()
        .any(|marker| raw.contains(marker))
        || body.to_string().contains("内容审核")
        || body.to_string().contains("敏感词")
}

/// 上游错误 → 协议的四档分类（`classify` 方法的返回）。
pub fn classify(status: u16, body: &Value) -> Value {
    let raw = message(body).unwrap_or_else(|| {
        if status == 401 {
            "凭证被上游拒绝（套餐池通道认套餐 JWT、编码套餐认访问令牌）：\
             请在账号页重新登录该账号"
                .to_string()
        } else {
            "上游错误".to_string()
        }
    });
    let code = upstream_code(body);
    let risk_rejected = is_risk_rejection(status, body);
    let hint = if risk_rejected {
        code_hint(3012)
    } else {
        code
            .and_then(code_hint)
            .or_else(|| (status == 429 || code == Some(1005)).then(|| quota_hint(&raw)).flatten())
    };
    let message = match hint {
        Some(hint) => format!("上游返回 {status}: {raw}（{hint}）"),
        None => format!("上游返回 {status}: {raw}"),
    };
    // HTTP 200 + 业务错误体：状态码本身没有意义，统一按 502 呈现
    let failure_status = if (200..300).contains(&status) { 502 } else { status };
    if risk_rejected {
        return json!({
            "kind": "fatal",
            "status": failure_status,
            "message": message,
            "upstream_code": code,
        });
    }
    if status == 401 {
        return json!({ "kind": "token_expired", "message": message });
    }
    if status == 429 || code == Some(1005) {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": code,
            "status": 429,
        });
    }
    if is_content_blocked(failure_status, body) {
        return json!({
            "kind": "content_blocked",
            "status": failure_status,
            "message": message,
            "upstream_code": code,
        });
    }
    json!({
        "kind": "fatal",
        "status": failure_status,
        "message": message,
        "upstream_code": code,
    })
}

/// 重试判据（`retry.decision`）：只有风控拒绝要**停**，其余走网关默认策略。
pub fn retry_decision(status: u16, body: &Value) -> Value {
    if is_risk_rejection(status, body) {
        return json!({
            "action": "stop",
            "reason": "上游风控拒绝，停止本次请求，不再原地重发、刷新凭证或换账号",
        });
    }
    json!({ "action": "default" })
}

/// 流内 / 请求侧的「停止重试」标记（`error.policy`）。
///
/// 与 native 的 `retry_decision` 同一判据：只对 3012 那一档成立。网关拿它在
/// 换账号重试之前叫停（风控拒绝换账号只会扩大影响面）。
pub fn error_policy(status: u16, body: &Value) -> Value {
    json!({ "stop": is_risk_rejection(status, body) })
}

/// 上游错误 → 可直接抛给网关的 `Error`（带状态码、业务码与冷却提示）。
pub fn http_error(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let code = upstream_code(body);
    let status = class
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or_else(|| if status == 0 { 502 } else { status });
    let message = class
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("ZCode 上游错误")
        .to_string();
    let mut error = Error::http(status, message);
    if let Some(code) = code {
        error = error.with_code(format!("zcode_{code}"));
    }
    error
}

/// `is_error_response` 的判据（native `Provider::is_error_response`）。
///
/// 推理请求恒为 `stream: true`；这一家的 JSON 响应是**业务拒绝**（实测
/// 1005 / exceed quota limit 都是 HTTP 200 + JSON），HTTP 200 也要先读错误体，
/// 不能当 SSE 消费。
pub fn is_error_response(status: u16, headers: &Value) -> bool {
    if !(200..300).contains(&status) {
        return true;
    }
    super::http::content_type(headers)
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
}
