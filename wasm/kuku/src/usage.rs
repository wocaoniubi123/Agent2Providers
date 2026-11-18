//! KukuAI 余额查询：`GET /bizapi/gfpro/getgfvipremain` → `data.list[*].totalPoint`。
//!
//! ── 接口事实（2026-10-07 用真实凭证实测，照 native `kuku/balance.rs`）──
//!   - 路径在 `/bizapi/` 一级。query 按客户端形态带 `channel/clienttype/version`
//!     （实测**不带 query 也能返回**，但客户端与参考实现都带，带上更稳）；
//!     **不带 `app_id`** —— bizapi 不认它（参考实现明确删掉）；
//!   - 响应是**顶层包络**（不是初版误判的双层）：
//!     ```json
//!     { "status": { "code": 0, "msg": "success" },
//!       "data": { "uname": "…",
//!                 "list": [ { "assetType": 1, "assetName": "token",
//!                             "totalPoint": "1100", "bonusPoint": "1100", … },
//!                           { "assetName": "duration", … }, … ] } }
//!     ```
//!     判据是 `status.code === 0`；积分取 `list` 里 `assetName == "token"` 的
//!     `totalPoint`（参考实现同口径，回落第一项）—— 初版按双层 `data.status.code`
//!     解析，`data.status` 不存在取了默认 `-1`，这就是「status.code=-1：未知错误」
//!     的根因（真实凭证实测复现）；
//!   - `totalPoint` 是 **token 额度**（字符串）。
//!
//! ── 与 native 的差别：没有独立查询凭证 ────────────────────────
//! KukuAI 转发用的三个 Cookie 直接能查余额，因此每个账号都能查到（不像 CatPaw
//! 那种要另配查询凭证），这里也不接任何设置项。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::account;
use super::upstream;

/// `usage.query`：查询某账号的余额 / 积分（归一化形状见协议文档）。
pub fn query() -> Result<Value> {
    let credentials = account::current()?;
    // query 按客户端形态：channel/clienttype/version（bizapi 不认 app_id）
    let query = format!("channel={}&clienttype=400&version=1.4.4", upstream::CHANNEL);
    let url = format!("{}/bizapi/gfpro/getgfvipremain?{query}", upstream::BASE_URL);
    let headers = upstream::headers(&credentials.cookie_header());
    let value = upstream::get_json(&url, &headers)?;
    // 顶层包络：判据在 status.code（2026-10-07 真实凭证实测）
    let status = value.get("status").cloned().unwrap_or(Value::Null);
    let code = status.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let message = status.get("msg").and_then(Value::as_str).unwrap_or("未知错误");
        // 积分接口只看 BDUSS：走到这里基本是登录态失效或上游风控，按 401 交出去，
        // 用户看到的是「请重新登录」而不是一句无从下手的「查询失败」。
        return Err(Error::http(
            401,
            format!("KukuAI 积分查询失败（status.code={code}：{message}）"),
        )
        .with_code("token_expired"));
    }
    // data.list 是各类资产（token / duration / scheduled_task …）：取
    // assetName == "token" 的那项（参考实现同口径），找不到回落第一项。
    let list = value
        .get("data")
        .and_then(|inner| inner.get("list"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let token_item = list
        .iter()
        .find(|item| item.get("assetName").and_then(Value::as_str) == Some("token"))
        .or_else(|| list.first())
        .cloned()
        .unwrap_or(Value::Null);
    let total_point = token_item
        .get("totalPoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let available = parse_number(&total_point);
    Ok(json!({
        "available": available,
        "unit": "积分",
        "wallets": [{
            "type": "points",
            "displayName": "积分",
            "balance": available,
        }],
        "subscription": Value::Null,
        // 整份资产清单进 raw（诊断用；token 那一项的 totalPoint 已取到 available）
        "raw": { "vipRemain": list },
    }))
}

/// 上游把 `totalPoint` 给成字符串（`"1234"`），这里必须同时接受数字形态。
fn parse_number(text: &str) -> Value {
    let text = text.trim();
    if text.is_empty() {
        return Value::Null;
    }
    match text.parse::<f64>() {
        Ok(number) => Value::from(number),
        Err(_) => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_accept_string_and_numeric_forms() {
        assert_eq!(json!(1100.0), parse_number("1100"));
        assert_eq!(json!(12.5), parse_number(" 12.5 "));
        assert_eq!(Value::Null, parse_number(""));
        assert_eq!(Value::Null, parse_number("不是数字"));
    }
}
