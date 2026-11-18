//! MonkeyCode 的错误分类与码表翻译。
//!
//! ── 上游是「HTTP 状态码 + 业务码」双轨 ──────────────────────────
//! 成功是 `{"code":0,...}`；失败可能落在 HTTP 层（401/403/429/5xx），也可能
//! 落在 HTTP 200 的 body 里（`code` 非 0，见 `task.rs` 的码表）。两条轨都要
//! 翻成网关认识的 `ErrorClass` 四档（`provider-protocol` 的封闭枚举）。
//!
//! ── `classify` 在本家事实上走不到（如实说明）──────────────────
//! 本家是会话式（`stateful`）：所有上游错误都在 `task.rs` / `startup.rs` /
//! `stream.rs` 里**现场**归一到 `Error`（状态码与文案已按建任务 / 任务流的码表
//! 翻译好），单请求路径不存在。保留 `classify` 是让契约完整 + 排障时一眼看到
//! 码表的映射意图（与 native `mod.rs` 的同一条注释一致）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，不碰网络。

use agent2api_wasm_sdk::{json, Error, Value};

use super::client;
use super::logging;
use super::region;

/// 一档 `ErrorClass`（`provider-protocol` 用 `tag = "kind"` + snake_case）。
///
/// 四档的处置由网关编排决定，**不要**发明第五档（多出来的会静默落进 Fatal）：
///   - `quota_limited` → 标记账号对该模型冷却 + 换账号；
///   - `token_expired` → 刷新凭证后同一账号重试一次（本家没有刷新接口，实际
///     效果是提示用户重贴 session）；
///   - `fatal` → 原样透传给客户端。
fn class(kind: &str, status: u16, message: &str, reset_at: Option<i64>, upstream_code: Option<i64>) -> Value {
    json!({
        "kind": kind,
        "status": status,
        "message": message,
        "reset_at": reset_at,
        "upstream_code": upstream_code,
    })
}

/// 上游错误分类：
///   - HTTP 401 / 403 → `token_expired`（登录态失效，重新粘贴 session）；
///   - HTTP 402 → `fatal`（额度不足：换账号也没用，用户得去官网处理）；
///   - HTTP 429 → `quota_limited`（上游不给结构化恢复时间）；
///   - 其余 → `fatal`。
pub fn classify(status: u16, body: &Value) -> Value {
    let upstream_message = body
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let hint = match status {
        402 => Some("（账户额度不足，请在 MonkeyCode 官网确认订阅 / 余额）"),
        _ => None,
    };
    let message = match (upstream_message, hint) {
        (Some(text), Some(hint)) => format!("上游返回 {status}: {text}{hint}"),
        (Some(text), None) => format!("上游返回 {status}: {text}"),
        (None, Some(hint)) => format!("上游返回 HTTP {status}{hint}"),
        (None, None) => format!("上游返回 HTTP {status}"),
    };
    let upstream_code = body.get("code").and_then(Value::as_i64);
    if status == 401 || status == 403 {
        return class("token_expired", status, &message, None, upstream_code);
    }
    if status == 429 {
        // 上游不给结构化恢复时间：`reset_at` 留空，由网关给兜底冷却。
        return class("quota_limited", status, &message, None, upstream_code);
    }
    class("fatal", status, &message, None, upstream_code)
}

/// 这个状态码是不是「上游已经明确失败」（内容拦截判定的入口）。
pub fn is_error_response(status: u16) -> bool {
    status >= 400
}

/// 错误处置策略：本家没有「一错就停」的语义（换账号由编排层按 `classify` 决定）。
pub fn policy(_status: u16, _body: &Value) -> Value {
    json!({ "stop": false })
}

/// HTTP 非 2xx → 网关错误（建任务 / 任务详情用的码表）。
///
/// 码表来源 `docs/10-appendices/02-error-codes.md`；5xx 归一成 502 —— 上游故障
/// 是**可重试**的，与 4xx 的参数 / 权限问题分开。
pub fn status_error(status: u16, payload: &Value, text: &str) -> Error {
    let detail = {
        let upstream = client::upstream_message(payload);
        if upstream.is_empty() {
            text.trim().chars().take(200).collect::<String>()
        } else {
            upstream
        }
    };
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!("：{detail}")
    };
    match status {
        401 | 403 => Error::http(
            401,
            format!("MonkeyCode 登录态已失效或无权访问（HTTP {status}）：请在账号页重新粘贴 session{suffix}"),
        ),
        402 => Error::http(
            402,
            format!("MonkeyCode 账户额度不足（HTTP 402），请确认订阅 / 余额后再试{suffix}"),
        ),
        404 => Error::http(
            404,
            format!("MonkeyCode 模型或镜像不存在（HTTP 404），请确认模型清单与账号的 image_id 仍然有效{suffix}"),
        ),
        409 => Error::http(
            409,
            format!("MonkeyCode 建任务冲突（HTTP 409，可能已有运行中的任务）{suffix}"),
        ),
        429 => Error::http(
            429,
            format!("MonkeyCode 请求过于频繁（HTTP 429），请稍后重试{suffix}"),
        ),
        _ if status >= 500 => Error::http(
            502,
            format!("MonkeyCode 建任务返回 HTTP {status}（上游故障，可稍后重试）{suffix}"),
        ),
        _ => Error::http(status, format!("MonkeyCode 建任务返回 HTTP {status}{suffix}")),
    }
}

/// HTTP 200 + 业务码非 0 → 网关错误（码表见 `task.rs` 模块头）。
///
/// `upstream_code` 必须挂上：`chat.rs` 的 10811 自愈就是按它判定的。
pub fn business_error(code: i64, message: &str) -> Error {
    let suffix = if message.is_empty() {
        String::new()
    } else {
        format!("：{message}")
    };
    let mut error = match code {
        40100 => Error::http(
            401,
            format!("MonkeyCode 登录态已失效（code 40100）：请在账号页重新粘贴 session{suffix}"),
        ),
        40002 | 40003 | 40004 => Error::http(
            403,
            format!("MonkeyCode 账号不可用（code {code}：密码错误 / 被封禁 / 未激活）{suffix}"),
        ),
        10811 => Error::http(
            409,
            format!(
                "MonkeyCode 该账号已有正在运行的任务（code 10811），自动清理残留任务后仍然失败：\
                 请到 {} 的任务列表手动停止该账号正在运行的任务，或稍等它自己结束{suffix}",
                region::SITE_ORIGIN
            ),
        ),
        50000 => Error::http(
            502,
            format!("MonkeyCode 上游服务端错误（code 50000，可稍后重试）{suffix}"),
        ),
        _ => Error::http(502, format!("MonkeyCode 建任务失败（业务码 {code}）{suffix}")),
    };
    logging::verbose(&format!("[MonkeyCode] 建任务业务码失败 code={code}"));
    error.upstream_code = Some(code);
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_follows_the_native_table() {
        let value = classify(401, &json!({ "message": "未授权" }));
        assert_eq!("token_expired", value["kind"].as_str().unwrap_or(""));
        assert!(value["message"].as_str().unwrap_or("").contains("未授权"));

        // 402 不是限额轮换：换账号没用，用户得去官网处理
        let value = classify(402, &json!({}));
        assert_eq!("fatal", value["kind"].as_str().unwrap_or(""));
        assert_eq!(402, value["status"].as_u64().unwrap_or(0));
        assert!(value["message"].as_str().unwrap_or("").contains("额度不足"));

        // 429 是限额：reset_at 留空（上游不给恢复时间）
        let value = classify(429, &json!({ "code": 429 }));
        assert_eq!("quota_limited", value["kind"].as_str().unwrap_or(""));
        assert!(value["reset_at"].is_null());
        assert_eq!(429, value["upstream_code"].as_i64().unwrap_or(0));
    }

    #[test]
    fn business_error_carries_upstream_code() {
        let error = business_error(10811, "已有任务");
        assert_eq!(Some(10811), error.upstream_code);
        assert_eq!(Some(409), error.status);
        let error = business_error(40003, "");
        assert_eq!(Some(403), error.status);
        // 未知码落 502，但业务码仍要带出去排障
        let error = business_error(12345, "");
        assert_eq!(Some(502), error.status);
        assert_eq!(Some(12345), error.upstream_code);
    }

    #[test]
    fn status_error_maps_5xx_to_502() {
        assert_eq!(Some(401), status_error(401, &json!({}), "").status);
        assert_eq!(Some(502), status_error(503, &json!({}), "").status);
        assert_eq!(Some(429), status_error(429, &json!({}), "").status);
    }
}
