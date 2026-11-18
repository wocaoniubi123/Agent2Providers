//! QuWork 的出网与回应解析：账号服务（`llm.rrzu.com`）与模型网关
//! （`qurwork-llm.rrzu.com`）是两个平面。
//!
//! ── 迁移时改了什么（native → wasm）──────────────────────────
//! native 用 `reqwest` 的 `Client` + 超时 + 账户 UA；wasm 只有 `http::open`
//! （宿主代发、自带超时与出口选择）。其余契约逐条照搬：
//!   · 账号面信封 `{success, data, message}`：`success` 非真即失败；
//!   · 非 2xx 且不是 JSON 时合成一条 `{success:false, message:"上游返回 HTTP n"}`，
//!     让上层按同一条路报错；
//!   · 错误文案里出现凭证原文时替换成 `[已隐藏]`。
//!
//! ── 为什么超时与代理在这里没有对应实现 ──────────────────────
//! wasm 的 `http.open` 由宿主统一控超时、按账号代理出网；插件侧没有
//! `Duration` 与 `WireProxy` 这两个参数面。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

/// 客户端版本（`X-QurWork-Version`，与官方 1.6.0 一致）。
pub const CLIENT_VERSION: &str = "1.6.0";

/// 账号面根（登录会话、积分、每日奖励、权益兑换都在这一个平面）。
pub const ACCOUNT_ORIGIN: &str = "https://llm.rrzu.com";

/// 模型网关根（OpenAI 兼容 `chat/completions`）。
pub const MODEL_ORIGIN: &str = "https://qurwork-llm.rrzu.com/v1";

/// 公开模型目录（官方客户端拉的那一份）。
pub const CATALOG_URL: &str =
    "https://img1.rrzuji.cn/qurvis-package/latest/qurvis-desktop-model-config.json";

/// 账号自身信息。
pub const SELF_PATH: &str = "/api/user/self";
/// 登录会话续期（只换账号令牌，模型令牌独立）。
pub const REFRESH_PATH: &str = "/api/user/refresh";
/// 每日奖励状态 / 领取。
pub const DAILY_STATUS_PATH: &str = "/api/user/daily-reward/status";
pub const DAILY_CLAIM_PATH: &str = "/api/user/daily-reward/claim";
/// 月度赠送记录。
pub const MONTHLY_GIFTS_PATH: &str = "/api/user/benefit/monthly-gifts";
/// 权益兑换（订单号）与邀请码激活。
pub const REDEEM_PATH: &str = "/api/user/benefit/redeem";
pub const ACTIVATE_PATH: &str = "/api/user/activate";

/// 单次响应的字节上限（与 native 同值）。
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// 提前一小时续期（native 的 `REFRESH_WINDOW_MS`）。
pub const REFRESH_WINDOW_MS: i64 = 60 * 60_000;

/// 账号面公共头：官方客户端的两个标识头，缺了会被当成未知客户端。
pub fn headers() -> Value {
    json!({
        "accept": "application/json",
        "cache-control": "no-cache",
        "X-QurWork-Env": "prod",
        "X-QurWork-Version": CLIENT_VERSION,
    })
}

/// 一次账号面调用的结果（状态码 + 已解析的 JSON 体）。
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

impl Reply {
    /// `2xx` 且 `success` 为真才算成功。
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status) && success(self.body.get("success"))
    }

    /// 登录会话失效（401，或成功位为假且文案是「未登录」）。
    pub fn unauthorized(&self) -> bool {
        self.status == 401 || (!self.ok() && matches!(message(&self.body).as_str(), "未登录" | "用户未登录"))
    }

    /// 取 `data`；失败时按「未登录 → 401 / 上游状态码 → 原值 / 其余 → 502」报错。
    pub fn data(&self, operation: &str) -> Result<Value> {
        if !self.ok() {
            let detail = message(&self.body);
            let status = if self.unauthorized() {
                401
            } else if self.status >= 400 {
                self.status
            } else {
                502
            };
            return Err(Error::http(
                status,
                if detail.is_empty() {
                    format!("QuWork {operation}未成功")
                } else {
                    format!("QuWork {operation}未成功：{detail}")
                },
            ));
        }
        Ok(self.body.get("data").cloned().unwrap_or(Value::Null))
    }
}

/// 打一次账号面接口。
pub fn request(method: &str, path: &str, token: &str, body: Option<&Value>) -> Result<Reply> {
    let url = format!("{ACCOUNT_ORIGIN}{path}");
    let mut headers = headers();
    if !token.is_empty() {
        headers["authorization"] = json!(format!("Bearer {token}"));
    }
    if body.is_some() {
        headers["content-type"] = json!("application/json");
    }
    let response = http::open(method, &url, headers, body)?;
    read_reply(response, &[token])
}

/// 拉公开模型目录（不带任何凭证）。
pub fn public_config() -> Result<Value> {
    let response = http::open(
        "GET",
        CATALOG_URL,
        json!({ "accept": "application/json", "cache-control": "no-cache" }),
        None,
    )?;
    let reply = read_reply(response, &[])?;
    if !(200..300).contains(&reply.status) {
        return Err(Error::http(502, "QuWork 模型目录获取失败"));
    }
    Ok(reply.body)
}

/// 读回包：非 JSON 时按状态码合成信封，并把凭证原文从文案里抹掉。
fn read_reply(response: http::Response, secrets: &[&str]) -> Result<Reply> {
    let status = response.status;
    let bytes = response.bytes(MAX_RESPONSE_BYTES)?;
    let mut body: Value = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        Err(_) if !(200..300).contains(&status) => {
            json!({ "success": false, "message": format!("上游返回 HTTP {status}") })
        }
        Err(_) => return Err(Error::http(502, "QuWork 未返回有效的 JSON 数据")),
    };
    for path in ["/message", "/msg", "/error/message"] {
        if let Some(value) = body.pointer_mut(path) {
            if let Some(text) = value.as_str() {
                let mut text = text.to_string();
                for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
                    text = text.replace(secret, "[已隐藏]");
                }
                *value = json!(text.chars().take(300).collect::<String>());
            }
        }
    }
    Ok(Reply { status, body })
}

/// `success` 的三种形态（布尔 / 数字 / 字符串 `"true"`）。
pub fn success(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1"),
        _ => false,
    }
}

/// 回包里的错误文案（`error.message` 优先）。
pub fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .or_else(|| body.get("message"))
        .or_else(|| body.get("msg"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(300)
        .collect()
}

/// 非负数字（拒绝负数与 NaN）。
pub fn number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse::<f64>().ok()))
        })
        .filter(|number| number.is_finite() && *number >= 0.0)
}

/// 时间戳归一：秒 → 毫秒，RFC3339 → 毫秒。
pub fn timestamp(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(number) = number(Some(value)).filter(|value| *value > 0.0) {
        let number = number as i64;
        return Some(if number < 100_000_000_000 {
            number.saturating_mul(1000)
        } else {
            number
        });
    }
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|date| date.timestamp_millis())
}
