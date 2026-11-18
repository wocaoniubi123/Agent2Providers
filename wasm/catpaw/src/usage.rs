//! CatPaw 的余额 / 积分查询（native `balance.rs` 的移植）。
//!
//! ── 上游长什么样 ─────────────────────────────────────────────
//! ```text
//!   GET https://catx.nocode.cn/api/gateway/credit/balance
//!   X-Auth-Token: <auth.json 的 auth.accessToken>
//!   响应 {code, message, data: {availableCredits, userPlan{…}}, errorCode}
//! ```
//! `availableCredits` 是**数字字符串**（如 `"0.00"`），`userPlan` 带套餐名 /
//! 是否专业版 / 到期时间。没有 `totalCredits`／`frozenCredits`／`expiredCredits`。
//!
//! ── ⚠️ 为什么不打 `credit.catpaw.meituan.com`（native 已纠正，原样保留）──
//! 原实现打的是网页积分中心并要求用户**手填**一份 `token2` 网页会话凭证。
//! 逐条复现后确认这套归因是错的：
//!   1. 真正生效的 cookie 是 `mt_c_token`，`token2` 反而 401；
//!   2. `token2` 的值就是转发用的那个 `accessToken` —— 客户端把同一个 token
//!      批量写进多个 cookie 名，那不是服务端要求；
//!   3. `catx.nocode.cn` 这个网关 API 只认 **`X-Auth-Token`** 头，凭证同样是
//!      那个 `accessToken`。
//! 于是本模块**不需要任何额外配置**：凭证直接复用转发那条链的账号 secret。
//!
//! ── 兼容旧的 `balanceToken` / `balanceCookie.token2` ──────────
//! 老用户填过 `balanceToken`，旧数据里可能有 `balanceCookie.token2`。两者现在
//! 只当作**凭证来源的补充**：转发凭证拿不到时才回退到它们。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::account::{text, Credentials};

/// 积分查询接口（客户端自己的网关 API，凭证与转发同一个 `accessToken`）
const BALANCE_URL: &str = "https://catx.nocode.cn/api/gateway/credit/balance";

/// 鉴权头名。**只认这一个**：实测 `X-Passport-Token` / `Cookie` /
/// `Authorization` 在这个域名下全部 401（见模块头）。
const AUTH_HEADER: &str = "X-Auth-Token";

/// 账号记录里的旧余额凭证字段（用户可在账号设置里填）
const BALANCE_TOKEN_FIELD: &str = "balanceToken";

/// 查余额（`usage.query`）。
pub fn query() -> Result<Value> {
    let record = sdk::account().unwrap_or(Value::Null);
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    let token = resolve_token(&secret)?;
    let headers = json!({
        "accept": "application/json",
        AUTH_HEADER: token,
        // 客户端自己会带的标记头；实测非必需，但更接近官方调用
        "gray-set": "new-agent-sdk",
    });
    let response = http::open("GET", BALANCE_URL, headers, None)
        .map_err(|error| Error::http(502, format!("积分查询请求失败: {}", error.message)))?;
    let status = response.status;
    let bytes = response
        .bytes(1024 * 1024)
        .map_err(|error| Error::http(502, format!("积分查询读取失败: {}", error.message)))?;
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let code = payload.get("code").and_then(Value::as_i64);
    // 这个接口的两条凭证失效路径（实测）：4010 = 没带 token，4011 = token 无效。
    // HTTP 401 也同样处理（两条路径都要判）。
    let unauthorized = status == 401 || matches!(code, Some(4010) | Some(4011));
    if unauthorized {
        return Err(Error::http(
            401,
            "积分查询凭证已失效，请在客户端重新登录后重新导入登录态",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(Error::http(502, format!("积分查询返回 HTTP {status}")));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    if code != Some(0) || data.is_null() {
        return Err(Error::http(502, error_message(&payload)));
    }
    let user_plan = data.get("userPlan").cloned().unwrap_or(Value::Null);
    // 只有「可用」一个数：没有钱包概念，因此不给 total/frozen/expired 造零值
    // （缺失就是缺失，前端显示成「—」）。
    let wallets: Vec<Value> = [("available", "可用积分", data.get("availableCredits"))]
        .into_iter()
        .filter_map(|(kind, display_name, value)| {
            let balance = number_or_null(value)?;
            Some(json!({ "type": kind, "displayName": display_name, "balance": balance }))
        })
        .collect();
    let mut raw = serde_json::Map::new();
    raw.insert("balance".to_string(), data.clone());
    Ok(json!({
        "available": number_or_null(data.get("availableCredits")),
        // 美团侧的额度单位就是它自己的 credits
        "unit": "credits",
        "wallets": wallets,
        // 这个接口没有订阅对象，但套餐信息在 `userPlan` 里 —— 打包成前端已认得的
        // 订阅形状（`name` / `expireAt`），免得为一家新造一个展示分支。
        "subscription": subscription_of(&user_plan),
        "raw": Value::Object(raw),
    }))
}

/// 解析这次查询要用的 token。
///
/// 顺序：
///   1. **转发链路的凭证**（账号 secret → 桌面端实时读 / accessToken）——
///      新装与旧装用户都能直接命中，无需任何配置；
///   2. 旧字段回退：`balanceToken`，或旧数据里的 `balanceCookie.token2`。
///
/// 两处都没有才报「未配置」——那时账号本身多半也是没有凭证的。
fn resolve_token(secret: &Value) -> Result<String> {
    if let Ok(Credentials { token, .. }) = super::account::credentials_of(secret) {
        if !token.is_empty() {
            return Ok(token);
        }
    }
    if let Some(token) = legacy_balance_token(secret) {
        return Ok(token);
    }
    // 宿主把「未配置」映射成中性提示而不是红色失败
    Err(Error::http(503, "CatPaw 未配置可用的登录凭证，无法查询积分"))
}

/// 旧数据里的余额凭证：`balanceToken`，或旧数据里的 `balanceCookie.token2`。
fn legacy_balance_token(secret: &Value) -> Option<String> {
    let direct = text(secret, &[BALANCE_TOKEN_FIELD]);
    if !direct.is_empty() {
        return Some(direct);
    }
    let nested = text(secret, &["balanceCookie"]);
    if !nested.is_empty() {
        return Some(nested);
    }
    secret
        .get("balanceCookie")
        .and_then(|cookie| cookie.get("token2"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// `userPlan` → 前端已认得的订阅形状（`null` 表示这个账号没有套餐信息）
fn subscription_of(user_plan: &Value) -> Value {
    if !user_plan.is_object() {
        return Value::Null;
    }
    let name = ["planName", "planId"]
        .iter()
        .find_map(|key| user_plan.get(*key).and_then(Value::as_str))
        .unwrap_or("");
    json!({
        "name": name,
        "expireAt": user_plan.get("expireTime").cloned().unwrap_or(Value::Null),
        // 上游字段名照实带上：前端若要区分「专业版」都够用，不必在这里改名
        "autoRenew": user_plan.get("autoRenew").cloned().unwrap_or(Value::Null),
        "pro": user_plan.get("pro").cloned().unwrap_or(Value::Null),
    })
}

/// 上游的业务错误文案（`message` 为空时给一个带 code 的兜底）
fn error_message(payload: &Value) -> String {
    payload
        .get("message")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "积分查询返回异常{}",
                payload
                    .get("code")
                    .and_then(Value::as_i64)
                    .map(|value| format!(" code={value}"))
                    .unwrap_or_default()
            )
        })
}

/// 数值字段透传（缺失/非数字给 None —— 前端把它显示成「—」而不是 0）。
///
/// 上游把 `availableCredits` 给成**字符串**（`"0.00"`），因此这里必须同时接受
/// 字符串与数字两种形态。
fn number_or_null(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|item| item.is_finite()),
        Value::String(text) => text.trim().parse::<f64>().ok().filter(|item| item.is_finite()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_accepts_string_and_number() {
        assert_eq!(number_or_null(Some(&json!("0.00"))), Some(0.0));
        assert_eq!(number_or_null(Some(&json!(12.5))), Some(12.5));
        assert_eq!(number_or_null(Some(&json!(null))), None);
    }

    #[test]
    fn subscription_shape() {
        let plan = json!({ "planName": "专业版", "expireTime": 100, "autoRenew": true, "pro": true });
        let sub = subscription_of(&plan);
        assert_eq!(sub["name"], json!("专业版"));
        assert_eq!(sub["expireAt"], json!(100));
        assert_eq!(subscription_of(&Value::Null), Value::Null);
    }

    #[test]
    fn legacy_balance_token_reads_cookie() {
        let secret = json!({ "balanceCookie": { "token2": "tk" } });
        assert_eq!(legacy_balance_token(&secret), Some("tk".to_string()));
    }
}
