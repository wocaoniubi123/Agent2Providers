//! 魔粒钱包与今日读数（`usage.query`）。
//!
//! 钱包与计数器是**快照**读数，发放逐笔是**记录**读数；两者混在一份报告里，
//! 各自标 `snapshot: true` / `record: true`，界面据此决定这一格能不能点开看明细。
//!
//! ── 三个接口的分工 ──────────────────────────────────────────
//! ```text
//!   GET /openapi/v1/magicubes/balance          可用余额 / 冻结余额（钱包快照）
//!   GET /openapi/v1/magicubes/transactions     逐笔发放（见 `transactions.rs`）
//!   GET /api/v1/inference/rate-limit           今日已用调用数（计数器快照）
//! ```
//! 钱包读失败是**硬失败**（没有余额就没有报告）；流水与计数器失败只记 `warnings`
//! —— 一份「余额在、明细缺」的报告比整条查询失败有用得多。
//!
//! ── wasm 侧与 native 的一处差别 ────────────────────────────
//! native 用 `tokio::join!` 并发打这三个接口；wasm 侧没有异步运行时可 join，
//! 只能顺序打。三发都是本机的直连请求，顺序执行多出的那点延迟换来的是
//! 「一次只能有一个在途请求」这种更简单的失败面，值得。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::transactions;
use super::{account, time, upstream};

pub const BALANCE_PATH: &str = "/openapi/v1/magicubes/balance";
const RATE_LIMIT_PATH: &str = "/api/v1/inference/rate-limit";

/// 只读一次余额（签到确认后用来给文案补一句「当前 X 魔粒」）。
pub fn current_balance(token: &str) -> Result<Option<f64>> {
    let payload = upstream::site_json(token, BALANCE_PATH, "魔粒余额查询")?;
    Ok(transactions::number(
        &upstream::data_of(&payload),
        "available_balance",
    ))
}

/// `usage.query` 的实现。
pub fn query() -> Result<Value> {
    let token = account::ensure()?;
    let day = time::today_key()
        .ok_or_else(|| Error::new("读不到宿主时钟，无法确认北京日期"))?;

    // ① 钱包（硬失败）
    let wallet = upstream::site_json(&token, BALANCE_PATH, "魔粒余额查询")?;
    let data = upstream::data_of(&wallet);
    let available = transactions::number(&data, "available_balance");
    let frozen = transactions::number(&data, "frozen_amount");
    let mut credits = vec![
        json!({ "key": "available", "name": "可用余额", "balance": available, "unit": "魔粒", "snapshot": true }),
        json!({ "key": "frozen", "name": "冻结余额", "balance": frozen, "unit": "魔粒", "snapshot": true }),
    ];
    let mut warnings: Vec<String> = Vec::new();
    let mut earned = None;

    // ② 逐笔发放（软失败）
    let ledger_raw = match transactions::read(&token, &day) {
        Ok(ledger) => {
            if ledger.complete {
                earned = ledger.total_on(&day, false);
                credits.push(json!({
                    "key": "earned-today", "name": "今日发放", "balance": earned,
                    "unit": "魔粒", "snapshot": true,
                }));
            } else {
                warnings.push("魔粒发放记录超过查询上限，今日合计未确认".to_string());
            }
            // 每一条发放单独一行（`record: true` = 记录读数，不是快照）
            credits.extend(ledger.grants.iter().map(|grant| grant.credit_row()));
            Value::Array(ledger.raw)
        }
        Err(error) => {
            warnings.push(error.message);
            Value::Null
        }
    };

    // ③ 今日调用数（软失败）
    let calls_raw = match upstream::site_json(&token, RATE_LIMIT_PATH, "今日用量查询") {
        Ok(payload) => {
            let used = transactions::number(
                &upstream::data_of(&payload),
                "currentUsagePerDay",
            );
            credits.push(json!({
                "key": "used-today", "name": "今日已用", "used": used,
                "unit": "次", "daily": true, "snapshot": true,
            }));
            payload
        }
        Err(error) => {
            warnings.push(error.message);
            Value::Null
        }
    };

    let mut report = json!({
        "available": available,
        "unit": "魔粒",
        "earnedToday": earned,
        "credits": credits,
        "wallets": [{
            "type": "magicubes", "displayName": "魔粒余额", "balance": available,
            "frozen": frozen, "unit": "魔粒", "snapshot": true,
        }],
        "warnings": warnings,
        "raw": { "balance": wallet, "transactions": ledger_raw, "rateLimit": calls_raw },
    });

    // 额度来源（`quotaSources`）：native 侧这是 trait 上的 `quota_sources`，由网关
    // 按报告现算；wasm ABI 没有这条方法，所以随报告一并给出。形状与网关
    // `quota::sources` 对 modelscope 的计算结果逐字段一致 —— 本家不在那张
    // 分家表里，只有「账号主额度」一行（魔粒钱包就是主额度）。
    let sources = quota_sources(&report);
    if let Some(sources) = sources {
        report["quotaSources"] = sources;
    }
    Ok(report)
}

/// 复刻网关 `quota::sources` 对本家的计算（见调用点的说明）。
fn quota_sources(report: &Value) -> Option<Value> {
    let unit = report.get("unit").and_then(Value::as_str).unwrap_or("");
    let remaining = report.get("available").and_then(Value::as_f64)?;
    Some(json!([{
        "id": "account",
        "label": "账号主额度",
        "provider": upstream::PROVIDER_ID,
        "unit": unit,
        "remaining": remaining,
        "total": Value::Null,
        "used": Value::Null,
        "unlimited": false,
    }]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 余额读得到 → 一行「账号主额度」；读不到 → 整块不写。
    #[test]
    fn the_quota_source_follows_the_available_balance() {
        let report = json!({ "available": 123.5, "unit": "魔粒" });
        let sources = quota_sources(&report).unwrap_or(Value::Null);
        assert_eq!(1, sources.as_array().map(|rows| rows.len()).unwrap_or(0));
        assert_eq!("account", sources[0]["id"].as_str().unwrap_or_default());
        assert_eq!("modelscope", sources[0]["provider"].as_str().unwrap_or_default());
        assert_eq!(123.5, sources[0]["remaining"].as_f64().unwrap_or(0.0));

        assert!(quota_sources(&json!({ "available": null })).is_none());
    }
}
