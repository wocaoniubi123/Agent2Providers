//! WorkBuddy 业务码决定错误语义；短时限流与授权限制不共用冷却。
//!
//! ── 分类口径（照抄 native `errors.rs`，逐条注解保留）──────────
//!   - 401 / 12153 → `token_expired`（刷新后同账号重试一次）
//!   - 429 / 402 / 6000-6008 等 → `quota_limited`（冷却 + 换账号）
//!   - 内容策略拦截（11-128 或审核文案）→ `content_blocked`（**不罚账号**：
//!     换中性提示词后同账号重试一次）
//!   - 其余 → `fatal`（原样透传）
//!
//! 文案逐字对齐改造前 `rotate::request_with_waf_retry` 的那三行
//! `format!("上游返回 {status}: {message}{hint}")`。

use agent2api_wasm_sdk::{json, Error, Value};

use crate::quota_reset::parse_quota_reset_at;
use crate::util;

/// 上游错误码 11-128（历史文案：Illegal API invocation from an unapproved channel）。
///
/// 实测语义：多为提示词命中上游敏感词审核而被拦截（并非单纯的频率风控）。
/// 常量名沿用 Node 版的历史命名，不要据此理解成「频率限制」。
/// 拦截会持续一小段时间，期间客户端失败自动重试会形成重试风暴并给拦截续期，
/// 因此命中 11-128 时值得退避重试 —— 次数与间隔统一走设置页的「请求重试」。
pub const RATE_LIMIT_CODE: i64 = 11_128;

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）。
///
/// 与网关 `core::providers::content_block` 同一份规则（native 侧只在 Loomy 里
/// 内联过一份，这一家按共用规则搬进来）。
const CONTENT_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 客户端可见的**内容拦截提示**：附在「上游返回 {status}: {上游原文}」之后。
///
/// 与网关 `CONTENT_BLOCK_HINT` 逐字一致 —— 两处文案分叉会让同一件事在
/// 「内置家」与「插件家」的账号上呈现不同措辞。
pub const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

/// 业务信封里的 code（只认 `code >= 1000` 的那个节点，最多下钻 6 层）。
pub fn code(body: &Value) -> Option<i64> {
    business_node(body, 6)?.get("code").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
    })
}

fn business_node(body: &Value, depth: usize) -> Option<&Value> {
    if depth == 0 {
        return None;
    }
    if body
        .get("code")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
        .is_some_and(|code| code >= 1000)
    {
        return Some(body);
    }
    [
        body.get("data"),
        body.get("error"),
        body.pointer("/response/data"),
    ]
    .into_iter()
    .flatten()
    .find_map(|node| business_node(node, depth - 1))
}

fn node_message(node: &Value) -> Option<&str> {
    ["message", "msg", "displayMsg"]
        .into_iter()
        .find_map(|key| {
            node.get(key)
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
        })
        .or_else(|| node.pointer("/error/message").and_then(Value::as_str))
}

/// 上游错误说明（业务节点优先，其次整份 body 的常见键，最后字符串体本身）。
pub fn message(body: &Value) -> &str {
    business_node(body, 6)
        .and_then(node_message)
        .or_else(|| node_message(body))
        .or_else(|| body.as_str())
        .unwrap_or("上游错误")
}

fn rate_limited(body: &Value) -> bool {
    let text = message(body).to_ascii_lowercase();
    [
        "rate limit",
        "rate-limiting",
        "rate-limited",
        "too many requests",
        "请求过于频繁",
        "限流",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

/// 账号被上游限制对话权限（11140 + 明确的「请求非法 / 账号受限」文案）。
fn restricted(body: &Value) -> bool {
    code(body) == Some(11140) && {
        let text = message(body).to_ascii_lowercase();
        text.contains("request illegal")
            || text.contains("account has been restricted")
            || text.contains("unusual activity")
            || text.contains("账号存在异常行为")
    }
}

/// 短暂繁忙 / 短时速率限制（按 30 秒退避）。
fn transient(code: Option<i64>) -> bool {
    matches!(code, Some(14003 | 6001 | 6002 | 6005 | 6006))
}

/// 额度耗尽（按次日 00:00 重置）。
fn exhausted(code: Option<i64>) -> bool {
    matches!(code, Some(14001 | 14012 | 14013 | 14014 | 14018 | 14019))
}

/// 下一个北京时间零点（毫秒）。
pub fn next_day_reset() -> i64 {
    util::beijing_day_start(util::now_ms()).saturating_add(util::DAY_MS)
}

/// 内容策略拦截判定（状态码只要求 >= 400，文案大小写不敏感）。
fn content_blocked(status: u16, body: &Value) -> bool {
    if status < 400 {
        return false;
    }
    let Some(message) = body.get("message").and_then(Value::as_str) else {
        return false;
    };
    let lowered = message.to_lowercase();
    CONTENT_PATTERNS
        .iter()
        .any(|pattern| lowered.contains(pattern))
}

/// 上游错误 → 四档分类（`{kind, status, message, reset_at, upstream_code}`）。
///
/// 形状与 atomcode / raccoon 的 `errors::classify` 一致：网关按 `kind` 选处置，
/// 其余字段进日志与限额事件。
pub fn classify(status: u16, body: &Value) -> Value {
    let code = code(body);
    let raw = message(body);
    let message = format!("上游返回 {status}: {raw}");
    if status == 401 || code == Some(12153) {
        return json!({
            "kind": "token_expired", "status": 401, "message": message,
            "reset_at": Value::Null, "upstream_code": Value::Null,
        });
    }
    if restricted(body)
        || matches!(code, Some(14015 | 14016 | 14017 | 11115 | 11101 | 11133 | 11158))
    {
        return json!({
            "kind": "fatal", "status": status.max(400), "message": message,
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    // ⚠ `11-128` 是 native 里的**原样写法**（在 Rust 里它是 `11 减 128`，即 -117，
    // 不是常量 `RATE_LIMIT_CODE = 11_128`）。迁移时按「逐字保留上游行为」处理，
    // 不在这里顺手改正 —— 否则本包与 native 的分类结果会分叉。真正兜住内容拦截
    // 的是下面 `content_blocked` 那三个文案特征。
    if code == Some(11 - 128) || content_blocked(status, body) {
        return json!({
            "kind": "content_blocked", "status": status.max(400),
            "message": format!("{message}{CONTENT_BLOCK_HINT}"),
            "reset_at": Value::Null, "upstream_code": code,
        });
    }
    if status == 402
        || exhausted(code)
        || status == 429
        || rate_limited(body)
        || matches!(code, Some(6000..=6008 | 14003 | 10105))
    {
        let now = util::now_ms();
        let parsed = parse_quota_reset_at(raw);
        // 上游没在文案里给出恢复时刻时，**不要在这里猜一个固定值**：交给网关
        // 按连击次数做指数退避（首撞 10 分钟，连续撞 20 / 30 分钟，避免
        // 「10 分钟后回来又撞」的循环）。例外是下面三种**确定的**语义：额度尽
        // 按次日重置、transient 短暂繁忙按 30 秒、10105 按 60 秒。
        let reset = if parsed > now {
            Some(parsed)
        } else if status == 402 || exhausted(code) {
            Some(next_day_reset())
        } else if transient(code) {
            Some(now.saturating_add(30_000))
        } else if code == Some(10105) {
            Some(now.saturating_add(60_000))
        } else {
            None
        };
        return json!({
            "kind": "quota_limited",
            "status": if status == 402 { 402 } else { 429 },
            "message": message, "reset_at": reset, "upstream_code": code,
        });
    }
    json!({
        "kind": "fatal", "status": status.max(400), "message": message,
        "reset_at": Value::Null, "upstream_code": code,
    })
}

/// 分类结果 → SDK 错误（流式转发路径用：插件自己发的请求，宿主看不到 body，
/// 所以必须由插件先分类再抛）。
pub fn http_error(status: u16, body: &Value) -> Error {
    let class = classify(status, body);
    let message = class["message"]
        .as_str()
        .unwrap_or("WorkBuddy 上游错误")
        .to_string();
    let kind = class["kind"].as_str().unwrap_or("fatal").to_string();
    let mapped = class["status"]
        .as_i64()
        .or_else(|| class["status"].as_u64().map(|value| value as i64))
        .unwrap_or(502);
    let mut error = Error::http(u16::try_from(mapped.max(400)).unwrap_or(502), message)
        .with_code(kind);
    error.upstream_code = class["upstream_code"].as_i64();
    error.reset_at = class["reset_at"].as_i64();
    error
}

/// 通用处置策略（`error.policy`）。
///
/// `stop` 表示「原样重发不可能修好」；`accountCooldownUntil` 表示该账号要冷到
/// 什么时候；`suspendAccount` 表示账号被上游限制，重新登录也解不开。
pub fn policy(status: u16, body: &Value) -> Value {
    let code = code(body);
    if restricted(body) {
        return json!({
            "stop": true,
            "suspendAccount": true,
            "reason": "WorkBuddy 已限制此账号的对话权限，请向官方申诉；重新登录通常不能解除限制",
        });
    }
    let account_state =
        matches!(code, Some(14015 | 14016 | 14017 | 10105)) || status == 402 || exhausted(code);
    if !account_state
        && !transient(code)
        && !rate_limited(body)
        && !matches!(code, Some(6000..=6008))
        && (matches!(code, Some(11115 | 11101 | 11133 | 11158))
            || matches!(status, 400 | 413 | 422) && code != Some(11 - 128))
    {
        return json!({ "stop": true, "reason": "请求参数、上下文或模型权限不满足上游要求，未重发相同请求" });
    }
    if matches!(code, Some(14015 | 14016 | 14017 | 10105)) || status == 402 || exhausted(code) {
        return json!({
            "accountCooldownUntil": if status == 402 || exhausted(code) {
                next_day_reset()
            } else {
                util::now_ms().saturating_add(60_000)
            },
            "reason": message(body),
        });
    }
    Value::Null
}

/// 上游是否明确要求「别再重试」（`retry_policy.retry == false`）。
pub fn retry_denied(body: &Value) -> bool {
    [
        "",
        "/data",
        "/error",
        "/error/data",
        "/error/error",
        "/error/error/data",
    ]
    .iter()
    .filter_map(|path| {
        if path.is_empty() {
            Some(body)
        } else {
            body.pointer(path)
        }
    })
    .find_map(|node| node.get("retry_policy"))
    .and_then(|policy| policy.get("retry"))
    .and_then(Value::as_bool)
        == Some(false)
}

/// 网关的重试决策（`retry.decision`）：`stop` / `retry` / `default`。
pub fn retry(status: u16, body: &Value, attempt: usize, budget: usize) -> Value {
    if retry_denied(body)
        || policy(status, body).get("stop").and_then(Value::as_bool) == Some(true)
    {
        return json!({ "action": "stop", "reason": "WorkBuddy 请求无法通过原样重发修复" });
    }
    if transient(code(body)) && attempt < budget {
        let delay = 500u64
            .saturating_mul(1u64 << attempt.min(6))
            .min(32_000);
        return json!({
            "action": "retry", "delay_ms": delay,
            "reason": "WorkBuddy 模型繁忙或短时速率限制，按预算退避后重试",
        });
    }
    json!({ "action": "default" })
}

/// 11-128 退避建议（native `retry_advice`）。
///
/// **循环**留在编排层（「11-128 退避逻辑保持在转发层」），这里只回答「这个错误
/// 要不要退避、退多久、为什么」——「哪个码是敏感词拦截」是 workbuddy 的知识。
///
/// ── 重试间隔在插件里取不到设置页的值 ────────────────────────
/// native 读 `config::retry_settings().delay_ms()`（设置页「请求重试」）。
/// wasm 侧没有那条配置回调，所以用**历史硬编码**那一档：10 秒（改造前的默认，
/// 也是设置页的出厂值）。影响面：用户把间隔改过之后，这条路径仍按 10 秒退避
/// —— 比不重试好，比读配置差一点。
pub fn retry_advice(error_body: &Value, attempt: usize, budget: usize) -> Value {
    let code = error_body.get("code").and_then(Value::as_i64);
    if code != Some(RATE_LIMIT_CODE) || attempt >= budget {
        return Value::Null;
    }
    json!({
        "delay_ms": 10_000,
        "reason": "上游敏感词拦截（11-128），请检查提示词中的敏感词",
    })
}

/// 内容拦截 / 已下发后的中断：给客户端一条错误帧。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({ "error": { "message": error.message, "status": status, "type": "upstream_error" } })
}

/// `is_error_response`：非 2xx，或 2xx 但 `content-type` 是 JSON。
///
/// 上游的失败可能**藏在 200 的 JSON 体里**（`{code: 11101, msg: …}`），所以
/// 只看状态码不够 —— 这一位让编排层在「200 + JSON」时也走错误分类。
pub fn is_error_response(status: u16, headers: &Value) -> bool {
    let content_type = crate::util::header_of(headers, "content-type").to_ascii_lowercase();
    !(200..300).contains(&status) || content_type.contains("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_are_token_expired() {
        assert_eq!(classify(401, &json!({}))["kind"], "token_expired");
        assert_eq!(classify(200, &json!({ "code": 12153 }))["kind"], "token_expired");
    }

    #[test]
    fn quota_codes_carry_a_reset_hint() {
        let class = classify(429, &json!({ "code": 6004 }));
        assert_eq!(class["kind"], "quota_limited");
        assert_eq!(class["status"], 429);
        // 402 与额度耗尽的码按次日零点重置
        let class = classify(402, &json!({ "code": 14001 }));
        assert_eq!(class["kind"], "quota_limited");
        assert!(class["reset_at"].as_i64().is_some_and(|at| at > 0));
        // transient（6001）按 30 秒
        let class = classify(429, &json!({ "code": 6001 }));
        assert!(class["reset_at"].as_i64().is_some_and(|at| at > 0));
    }

    #[test]
    fn security_policy_text_is_content_blocked() {
        let class = classify(400, &json!({ "message": "Illegal API invocation from an unapproved channel" }));
        assert_eq!(class["kind"], "content_blocked");
        assert!(class["message"]
            .as_str()
            .unwrap_or("")
            .contains("内容被上游内容策略拒绝"));
        // 200 的正文不算（判据要求 status >= 400）
        assert_eq!(
            classify(200, &json!({ "message": "blocked by security policy" }))["kind"],
            "fatal"
        );
    }

    #[test]
    fn restricted_accounts_are_told_to_appeal() {
        let body = json!({ "code": 11140, "message": "account has been restricted" });
        assert_eq!(classify(403, &body)["kind"], "fatal");
        let policy = policy(403, &body);
        assert_eq!(policy["stop"], json!(true));
        assert_eq!(policy["suspendAccount"], json!(true));
    }

    #[test]
    fn business_code_is_found_under_data() {
        let body = json!({ "code": 0, "data": { "code": 11101, "msg": "param error" } });
        assert_eq!(code(&body), Some(11101));
        assert_eq!(message(&body), "param error");
        // 小于 1000 的 code 不算业务码
        assert_eq!(code(&json!({ "code": 0 })), None);
    }

    #[test]
    fn retry_advice_only_for_the_rate_limit_code() {
        assert_eq!(retry_advice(&json!({ "code": 11_128 }), 0, 2)["delay_ms"], json!(10_000));
        assert_eq!(retry_advice(&json!({ "code": 11_128 }), 2, 2), Value::Null);
        assert_eq!(retry_advice(&json!({ "code": 6004 }), 0, 2), Value::Null);
    }

    #[test]
    fn error_response_detects_json_on_success_status() {
        assert!(is_error_response(500, &json!({})));
        assert!(is_error_response(200, &json!({ "content-type": "application/json" })));
        assert!(!is_error_response(200, &json!({ "content-type": "text/event-stream" })));
    }
}
