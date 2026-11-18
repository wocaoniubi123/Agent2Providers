//! AutoClaw 的 userapi 出站封装（刷新 / 积分 / 签到 / 目录共用）。
//!
//! ── 一条链路上的三种信封 ────────────────────────────────────
//! ```text
//!   {code, msg, data}                   刷新 / 积分 / 签到 / 订阅（标准信封）
//!   {models: [...]}                      模型目录（**没有** code/data 信封）
//!   {error: {...}} / {code: 非零}        对话流里的业务错误
//! ```
//! 三种都在这里判，别在调用方各写一遍 —— 目录那次「按对象找 providers」的
//! 历史 bug 就是「每处自己解析」的代价。
//!
//! ── 为什么必须带签名头 ──────────────────────────────────────
//! 见 `sign.rs` 的模块头：`X-Auth-Sign = MD5(appId&ts&appKey)`。缺了就是
//! `code 400002`（刷新链降级 `agent-refresh`，其余链路直接失败）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::credential::{self, Credential};
use super::region;
use super::sign;

/// 单次响应的读取上限（积分 / 目录都不该超过这个量级）
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

/// 业务码判定：`code == 0` 才算成功。
pub fn code_of(payload: &Value) -> Option<i64> {
    payload
        .get("code")
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())))
}

/// 登录态失效的业务码（积分 / 签到 / 目录共用一组）。
///
/// ── 为什么这几个码要单独判 ──────────────────────────────────
/// 上游把「登录态过期」放在 HTTP 200 的 body 里（`code: 410000` / `400000`），
/// 只看状态码会把一次过期的查询当成成功（界面显示「积分 0」）。
pub const AUTH_EXPIRED_CODES: &[i64] = &[410_000, 400_000];

pub fn is_auth_expired_code(code: i64) -> bool {
    AUTH_EXPIRED_CODES.contains(&code)
}

/// 带签名的 GET（返回原始响应体：目录接口**没有** `{code,data}` 信封，
/// 需要调用方自己按 `{models:[…]}` 解析）。
pub fn raw_get(url: &str, token: &str) -> Result<http::Response> {
    http::open("GET", url, sign::signed_headers(token), None)
}

/// 带签名的 GET（userapi 域）。
pub fn get(path: &str, token: &str, what: &str) -> Result<Value> {
    let url = format!("{}{path}", region::userapi_base());
    let response = http::open("GET", &url, sign::signed_headers(token), None)?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT)?;
    expect(status, &bytes, what)
}

/// 带签名的 POST（userapi 域）。
pub fn post(path: &str, token: &str, body: &Value, what: &str) -> Result<Value> {
    let url = format!("{}{path}", region::userapi_base());
    let response = http::open("POST", &url, sign::signed_headers(token), Some(body))?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT)?;
    expect(status, &bytes, what)
}

/// 匿名签名的 POST（登录链路：还没有 token）。
pub fn post_anonymous(path: &str, body: &Value, what: &str) -> Result<Value> {
    post(path, "", body, what)
}

/// 刷新接口（`credential::renew` 用；两条路径共用同一份签名头）。
pub fn call_refresh_unauth(credential: &Credential, path: &str) -> Result<Value> {
    let mut body = json!({
        "refresh_token": credential.refresh_token,
        "source_id": "autoclaw",
    });
    if !credential.device_id.is_empty() {
        if let Some(object) = body.as_object_mut() {
            object.insert("device_id".to_string(), Value::String(credential.device_id.clone()));
        }
    }
    post(path, &credential.token, &body, "刷新")
}

/// HTTP 层与可解析性判定：非 2xx → 401（若是鉴权）/ 502，其余原样返回。
fn expect(status: u16, bytes: &[u8], what: &str) -> Result<Value> {
    let payload: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let mapped = if status == 401 { 401 } else { 502 };
        return Err(Error::http(
            mapped,
            format!("AutoClaw {what}失败（HTTP {status}）"),
        ));
    }
    if payload.is_null() {
        return Err(Error::http(502, format!("AutoClaw {what}未返回有效 JSON")));
    }
    Ok(payload)
}

/// 标准信封 → `data`（并在 `code` 非零时给出可读错误）。
pub fn data_or_error(payload: &Value, what: &str) -> Result<Value> {
    let code = code_of(payload).unwrap_or(0);
    if code == 0 {
        return Ok(payload.get("data").cloned().unwrap_or(Value::Null));
    }
    if is_auth_expired_code(code) {
        return Err(Error::http(401, format!("AutoClaw 登录态已过期，无法{what}")));
    }
    let message = payload
        .get("msg")
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游未给出原因");
    Err(Error::http(502, format!("AutoClaw {what}失败（code={code}）：{message}")))
}

/// 取一条账号记录（宿主只给当前账号；`account_id` 非空时必须与记录 id 一致）。
///
/// ── 为什么还要核一次 ────────────────────────────────────────
/// `usage.query` 与 `checkin.claim` 可能被网关用「指定账号」的方式调用
/// （`params.account`）。宿主给的 `account()` 已经是那一条，但对不上时必须报错
/// 而不是默默用别的账号 —— 拿 A 账号查 B 账号的余额，用户看到的是另一份数据，
/// 而且没有任何提示。
pub fn account_record(account_id: &str) -> Result<Value> {
    let record = credential::record()?;
    if account_id.is_empty() {
        return Ok(record);
    }
    match record["id"].as_str() {
        Some(id) if id == account_id => Ok(record),
        _ => Err(Error::http(
            404,
            format!(
                "AutoClaw {}账号 {account_id} 不存在或不属于该地区",
                region::REGION.label()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 登录态失效的两个业务码都要被判成 401（否则界面显示「积分 0」）。
    #[test]
    fn auth_expired_codes() {
        assert!(is_auth_expired_code(410_000));
        assert!(is_auth_expired_code(400_000));
        assert!(!is_auth_expired_code(0));
        let payload = json!({ "code": 410_000, "msg": "not login" });
        assert_eq!(Some(401), data_or_error(&payload, "查询积分").err().and_then(|error| error.status));
    }

    /// 标准信封成功时返回 `data`，不成功时把上游文案带出来。
    #[test]
    fn envelope_handling() {
        assert_eq!(json!({ "a": 1 }), data_or_error(&json!({ "code": 0, "data": { "a": 1 } }), "x").unwrap_or(Value::Null));
        let error = data_or_error(&json!({ "code": 630_202, "msg": "验证码不正确" }), "登录")
            .err()
            .unwrap_or_else(Error::unsupported);
        assert!(error.message.contains("验证码不正确"));
    }
}
