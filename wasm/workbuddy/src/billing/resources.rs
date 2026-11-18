//! 新版积分接口按 UTC+8 查询当天切片；缺字段和未完成分页都不能当成零余额。
//!
//! ── 与 native 的差别（只有一处）──────────────────────────────
//! native 用 `tokio::join!` 并发拉「汇总 / 付费包 / 免费包」三路。wasm 侧 SDK 是
//! 同步 http，只能顺序拉（三趟往返而不是一趟）。合并与去重规则不变。

use agent2api_wasm_sdk::{json, Result, Value};

use super::{call, commodity::codes};
use crate::util;

const PAGE_SIZE: usize = 200;
const MAX_PAGES: usize = 10;
const PAID: &[&str] = &[
    codes::PRO_MON,
    codes::PRO_MON_PLUS,
    codes::PRO_YEAR,
    codes::YOUTH,
    codes::ADVANCED,
    codes::FLAGSHIP,
    codes::EXTRA,
    codes::EXTRA38,
    codes::EXTRA_INTL,
];
const FREE: &[&str] = &[
    codes::FREE,
    codes::FREE_MON,
    codes::FREE_MON_INTL,
    codes::GIFT,
    codes::PRO_TRIAL_MON,
    codes::PRO_TRIAL_YEAR,
    codes::ACTIVITY,
    codes::BONUS28,
    codes::BONUS_INTL,
    codes::BONUS29,
    codes::BONUS30,
];

pub struct Resources {
    pub accounts: Vec<Value>,
    /// 上游汇总接口给的 (总额, 剩余)；缺失为 None（**不能**当成 0 余额）
    pub summary: Option<(f64, f64)>,
}

pub fn fetch(session: &Value, locale: Option<&str>) -> Result<Resources> {
    let locale = locale.unwrap_or_else(|| {
        if session.get("edition").and_then(Value::as_str) == Some("intl") {
            "en"
        } else {
            "zh"
        }
    });
    // 当天（UTC+8）—— 上游按这个自然日切免费额度
    let day = util::date_key_of_ms(util::now_ms());
    let paid = json!({ "NeedRenewInfo": true });
    let free = json!({
        "SlicePeriodStartTime": format!("{day} 00:00:00"),
        "SlicePeriodEndTime": format!("{day} 23:59:59"),
    });
    let summary = summary(session, locale).ok().flatten();
    let paid_rows = pages(
        session,
        locale,
        "/billing/meter/get-user-resource-paid-packages",
        PAID,
        &paid,
    )?;
    let free_rows = pages(
        session,
        locale,
        "/billing/meter/get-user-resource-free-packages",
        FREE,
        &free,
    )?;
    let mut seen: Vec<String> = Vec::new();
    let mut accounts = Vec::new();
    for account in paid_rows.into_iter().chain(free_rows) {
        let id = account
            .get("ResourceId")
            .filter(|value| !value.is_null())
            .map(Value::to_string)
            .filter(|value| value != "\"\"");
        if let Some(id) = id {
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
        }
        accounts.push(account);
    }
    Ok(Resources { accounts, summary })
}

fn summary(session: &Value, locale: &str) -> Result<Option<(f64, f64)>> {
    let body = json!({});
    let result = call::call(
        "POST",
        "/billing/meter/get-user-resource-summary",
        Some(&body),
        session,
        Some(locale),
        call::Options::default(),
    )?;
    let Some(packages) = data(&result.data).get("Packages").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut total = 0.0;
    let mut left = 0.0;
    for package in packages {
        let (Some(size), Some(remain)) = (
            number(package.get("CycleTotalCapacity")),
            number(package.get("CycleRemainCapacity")),
        ) else {
            return Ok(None);
        };
        total += size;
        left += remain.min(size);
    }
    Ok(Some((total, left)))
}

fn pages(
    session: &Value,
    locale: &str,
    path: &str,
    codes: &[&str],
    extra: &Value,
) -> Result<Vec<Value>> {
    let mut accounts: Vec<Value> = Vec::new();
    for page in 1..=MAX_PAGES {
        let mut body = json!({
            "PageNumber": page, "PageSize": PAGE_SIZE,
            "PackageCodes": codes, "Status": [0, 3],
        });
        if let (Some(fields), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                fields.insert(key.clone(), value.clone());
            }
        }
        let result = call::call(
            "POST",
            path,
            Some(&body),
            session,
            Some(locale),
            call::Options::default(),
        )?;
        let data = data(&result.data);
        let rows = data
            .get("Accounts")
            .and_then(Value::as_array)
            .ok_or_else(|| agent2api_wasm_sdk::Error::http(502, "积分包接口缺少 Accounts，余额未知"))?;
        let count = rows.len();
        if count > PAGE_SIZE {
            return Err(agent2api_wasm_sdk::Error::http(
                502,
                "积分包分页超过请求页长，余额未知",
            ));
        }
        let total = match data.get("TotalCount") {
            None | Some(Value::Null) => None,
            value => Some(
                number(value)
                    .filter(|value| {
                        value.fract() == 0.0 && *value <= (PAGE_SIZE * MAX_PAGES) as f64
                    })
                    .ok_or_else(|| {
                        agent2api_wasm_sdk::Error::http(502, "积分包总数无效或超过分页上限，余额未知")
                    })? as usize,
            ),
        };
        accounts.extend(rows.iter().cloned());
        if total.is_some_and(|total| accounts.len() >= total) {
            return Ok(accounts);
        }
        if count < PAGE_SIZE {
            if total.is_some_and(|total| accounts.len() < total) {
                return Err(agent2api_wasm_sdk::Error::http(
                    502,
                    "积分包分页数量不完整，余额未知",
                ));
            }
            return Ok(accounts);
        }
    }
    Err(agent2api_wasm_sdk::Error::http(
        502,
        "积分包超过分页上限，未将不完整列表作为余额",
    ))
}

fn data(value: &Value) -> &Value {
    value
        .pointer("/Response/Data")
        .or_else(|| value.pointer("/Response"))
        .or_else(|| value.get("data"))
        .unwrap_or(value)
}

/// 数值读取（数字或数字字符串；负数与非有限值当作「没给」）。
pub fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) if !value.trim().is_empty() => value.trim().parse().ok(),
        _ => None,
    }
    .filter(|value: &f64| value.is_finite() && *value >= 0.0)
}

/// 一份积分包的 (额度, 剩余)；`CapacityType == 4` 是「按日切片」形态。
pub fn capacity(resource: &Value) -> (Option<f64>, Option<f64>) {
    let slice = resource.get("CapacityType").and_then(Value::as_i64) == Some(4);
    let detail = if slice {
        resource
            .get("SlicePeriodUsageDetails")
            .and_then(Value::as_array)
            .and_then(|details| details.first())
    } else {
        None
    };
    let (total, left) = if let Some(detail) = detail {
        (
            number(detail.get("SlicePeriodCapacitySizePrecise")),
            number(detail.get("SlicePeriodCapacityRemainPrecise")),
        )
    } else {
        (
            number(resource.get("CycleCapacitySizePrecise")),
            number(resource.get("CycleCapacityRemainPrecise")),
        )
    };
    (
        total,
        left.map(|left| total.map(|total| left.min(total)).unwrap_or(left)),
    )
}
