//! 积分汇总、资源包与企业额度保持既有前端契约；未知数值不伪装成零。
//!
//! ── 为什么既有形状不归一化（这是硬要求）─────────────────────
//! `{kind, unlimited, totalLeft, planLeft, bonusLeft}` 是改造前就有的既有契约，
//! 前端一直按它渲染（余额列的读数），后端 `usage_records::extract_remaining`
//! 也认 `totalLeft` 这一个键。把它包装成统一钱包形状会让那一格的显示退化 ——
//! 那是明令禁止的。所以这里是**加**不是换：五个既有键原样产出，新挂上去的
//! 只有两项：
//!   * `credits[]`      —— 逐份积分包明细（面额 / 已用 / 剩余 / 领取 / 到期）
//!   * `subscription`   —— 当前生效套餐的名字与到期时刻

use agent2api_wasm_sdk::{json, Result, Value};

use super::commodity::{
    self, codes, is_bonus, is_daily_credit, is_plan_base, label_of, plan_priority,
};
use super::tools::{js_int_string, time_or_null, to_int};
use super::{call, resources};
use crate::util;

/// 查一次积分（自动分个人 / 企业两条链）。
pub fn query_usage(session: &Value, locale: Option<&str>) -> Result<Value> {
    if session
        .pointer("/account/enterpriseId")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty())
    {
        enterprise_usage(session)
    } else {
        personal_usage(session, locale)
    }
}

fn personal_usage(session: &Value, locale: Option<&str>) -> Result<Value> {
    let fetched = resources::fetch(session, locale)?;
    let mut packs: Vec<Value> = fetched.accounts.iter().map(resource_of).collect();
    packs.sort_by(|a, b| {
        plan_priority(a.get("packageCode").and_then(Value::as_str))
            .cmp(&plan_priority(b.get("packageCode").and_then(Value::as_str)))
            .then_with(|| {
                a.get("expireAt")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MAX)
                    .cmp(
                        &b.get("expireAt")
                            .and_then(Value::as_i64)
                            .unwrap_or(i64::MAX),
                    )
            })
    });
    let aggregate = |field: &str| {
        packs.iter().try_fold(0.0, |sum, item| {
            resources::number(item.get(field)).map(|value| sum + value)
        })
    };
    let total = fetched
        .summary
        .map(|(total, _)| total)
        .or_else(|| aggregate("total"));
    let left = fetched
        .summary
        .map(|(_, left)| left)
        .or_else(|| aggregate("left"));
    let used = total.zip(left).map(|(total, left)| (total - left).max(0.0));
    let find = |wanted: &[&str]| {
        packs.iter().find(|item| {
            item.get("packageCode")
                .and_then(Value::as_str)
                .is_some_and(|code| wanted.contains(&code))
        })
    };
    let flagship = find(&[codes::FLAGSHIP]);
    let advanced = find(&[codes::ADVANCED]);
    let pro = find(&[codes::PRO_YEAR, codes::PRO_MON, codes::PRO_MON_PLUS]);
    let youth = find(&[codes::YOUTH]);
    let trial = find(&[codes::PRO_TRIAL_MON, codes::PRO_TRIAL_YEAR]);
    let active = flagship
        .or(advanced)
        .or(pro)
        .or(youth)
        .or(trial)
        .or_else(|| packs.first());
    let edition = if flagship.is_some() {
        "flagship"
    } else if advanced.is_some() {
        "advanced"
    } else if youth.is_some() && pro.is_none() {
        "youth"
    } else if pro.is_some() {
        "pro"
    } else if trial.is_some() {
        "pro_trial"
    } else {
        "free"
    };
    Ok(json!({
        "kind": "personal", "editionType": edition, "isPro": pro.is_some(),
        "isTrial": trial.is_some() && pro.is_none() && advanced.is_none() && flagship.is_none() && youth.is_none(),
        "planName": active.and_then(|item| item.get("name")).and_then(Value::as_str).unwrap_or(""),
        "packageCode": active.and_then(|item| item.get("packageCode")),
        "usageTotal": total.map(js_int_string), "usageLeft": left.map(js_int_string), "usageUsed": used.map(js_int_string),
        "expireAt": active.and_then(|item| item.get("expireAt")),
        "refreshAt": active.and_then(|item| item.get("refreshAt")),
        "autoRenew": active.and_then(|item| item.get("autoRenew")).and_then(Value::as_bool).unwrap_or(false),
        "resources": packs,
    }))
}

/// 单份积分包 → 前端明细行。
fn resource_of(item: &Value) -> Value {
    let code = item
        .get("PackageCode")
        .and_then(Value::as_str)
        .unwrap_or("");
    let daily = is_daily_credit(code);
    let (total, left) = resources::capacity(item);
    let name = item
        .get("PackageName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .or_else(|| label_of(code))
        .unwrap_or(code);
    let mut pack = serde_json::Map::new();
    pack.insert("name".into(), json!(name));
    pack.insert("packageCode".into(), json!(code));
    pack.insert("isDaily".into(), json!(daily));
    if let Some(id) = item.get("ResourceId").filter(|id| !id.is_null()) {
        pack.insert("id".into(), id.clone());
    }
    for (key, value) in [
        ("total", total),
        ("left", left),
        (
            "used",
            total.zip(left).map(|(total, left)| (total - left).max(0.0)),
        ),
    ] {
        if let Some(value) = value {
            pack.insert(key.into(), util::json_number(value));
        }
    }
    let start = billing_time(item.get("DeductionStartTime"))
        .or_else(|| billing_time(item.get("CycleStartTime")));
    let expire = if daily {
        billing_time(item.get("CycleEndTime"))
    } else {
        billing_time(item.get("DeductionEndTime"))
            .or_else(|| billing_time(item.get("ExpiredTime")))
            .or_else(|| billing_time(item.get("PackageEndTime")))
            .or_else(|| billing_time(item.get("CycleEndTime")))
    };
    let refresh = if daily {
        None
    } else {
        billing_time(item.get("CycleEndTime")).map(|time| time.saturating_add(1000))
    };
    for (key, value) in [
        ("startAt", start),
        ("createAt", billing_time(item.get("CreateTime"))),
        ("expireAt", expire),
        ("refreshAt", refresh),
    ] {
        if let Some(value) = value {
            pack.insert(key.into(), json!(value));
        }
    }
    pack.insert(
        "autoRenew".into(),
        json!(resources::number(item.get("AutoRenewFlag")) == Some(1.0)),
    );
    if let Some(reason) = item
        .get("AccountAttributes")
        .and_then(Value::as_array)
        .and_then(|attributes| {
            attributes.iter().find(|attribute| {
                attribute.get("Key").and_then(Value::as_str) == Some("grantReason")
            })
        })
        .and_then(|attribute| attribute.get("Value"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
    {
        pack.insert("grantReason".into(), json!(reason));
    }
    Value::Object(pack)
}

/// 计费域时间字段 → 毫秒时间戳。
///
/// 两种形态都认：`"YYYY-MM-DD HH:MM:SS"`（UTC+8）与纯数字（秒 / 毫秒）。
fn billing_time(value: Option<&Value>) -> Option<i64> {
    use chrono::TimeZone;
    if let Some(text) = value.and_then(Value::as_str) {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(text.trim(), "%Y-%m-%d %H:%M:%S") {
            return chrono::FixedOffset::east_opt(8 * 3600)?
                .from_local_datetime(&naive)
                .single()
                .map(|time| time.timestamp_millis());
        }
    }
    time_or_null(value).filter(|time| *time > 0).map(|time| {
        if time < 100_000_000_000 {
            time.saturating_mul(1000)
        } else {
            time
        }
    })
}

fn enterprise_usage(session: &Value) -> Result<Value> {
    let result = call::call(
        "POST",
        "/v2/billing/meter/get-enterprise-user-usage",
        None,
        session,
        None,
        call::Options::default(),
    )?;
    let usage = result.data.get("data").unwrap_or(&result.data);
    let limit = usage
        .get("limitNum")
        .or_else(|| usage.get("limit_num"))
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
        .filter(|value| value.is_finite());
    let credit = resources::number(usage.get("credit").or_else(|| usage.get("used_num")));
    let unlimited = limit == Some(-1.0);
    let total = limit.filter(|value| *value >= 0.0);
    let left = total
        .zip(credit)
        .map(|(limit, credit)| (limit - credit).max(0.0));
    let account_type = session
        .pointer("/account/type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let edition = match account_type {
        "ultimate" => "ultimate",
        "exclusive" => "exclusive",
        _ => "enterprise",
    };
    Ok(json!({
        "kind": "enterprise", "editionType": edition, "unlimited": unlimited,
        "usageLeft": if unlimited { Some(commodity::UNLIMITED_USAGE_SENTINEL.to_string()) } else { left.map(js_int_string) },
        "usageTotal": if unlimited { Some(commodity::UNLIMITED_USAGE_SENTINEL.to_string()) } else { total.map(js_int_string) },
        "usageUsed": credit.map(js_int_string), "refreshAt": billing_time(usage.get("cycleResetTime")),
        "resources": [],
    }))
}

/// 积分简报（**既有五键逐字保留**）。
pub fn credits_summary_from(usage: &Value) -> Value {
    let kind = usage
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("personal");
    let unlimited = usage
        .get("unlimited")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if kind == "enterprise" {
        return json!({
            "kind": kind, "unlimited": unlimited,
            "totalLeft": if unlimited { None } else { usage.get("usageLeft").and_then(to_int) },
            "planLeft": Value::Null, "bonusLeft": Value::Null,
        });
    }
    let sum = |filter: fn(Option<&str>) -> bool| -> Option<i64> {
        usage
            .get("resources")
            .and_then(Value::as_array)?
            .iter()
            .filter(|item| filter(item.get("packageCode").and_then(Value::as_str)))
            .try_fold(0.0, |sum, item| {
                resources::number(item.get("left")).map(|left| sum + left)
            })
            .map(|sum| sum.floor() as i64)
    };
    json!({
        "kind": "personal", "unlimited": false,
        "totalLeft": usage.get("usageLeft").and_then(to_int),
        "planLeft": sum(is_plan_base), "bonusLeft": sum(is_bonus),
    })
}

/// 当前生效套餐（账号页弹层头部那一行）。
pub fn subscription_of(usage: &Value) -> Option<Value> {
    if usage.get("kind").and_then(Value::as_str) == Some("enterprise") {
        return None;
    }
    let edition = usage.get("editionType").and_then(Value::as_str)?;
    let name = match edition {
        "free" => "Free",
        "pro_trial" => "Trial",
        _ => usage
            .get("planName")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())?,
    };
    let mut subscription = json!({
        "planName": name,
        "status": match edition { "free" => "免费", "pro_trial" => "试用", _ => "付费" },
    });
    for (from, to) in [
        ("expireAt", "expireAt"),
        ("usageLeft", "remainQuota"),
        ("usageTotal", "totalQuota"),
    ] {
        if let Some(value) = usage.get(from).filter(|value| !value.is_null()) {
            subscription[to] = value.clone();
        }
    }
    Some(subscription)
}

/// 逐份积分包明细（`credits[]`）。
pub fn credit_packs_from(usage: &Value) -> Vec<Value> {
    usage
        .get("resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            let mut row = serde_json::Map::new();
            row.insert(
                "name".into(),
                item.get("name").cloned().unwrap_or(json!("")),
            );
            for (from, to) in [
                ("total", "total"),
                ("used", "used"),
                ("left", "remain"),
                ("createAt", "grantAt"),
                ("startAt", "startAt"),
                ("expireAt", "expireAt"),
                ("refreshAt", "refreshAt"),
                ("grantReason", "grantReason"),
            ] {
                if let Some(value) = item.get(from).filter(|value| !value.is_null()) {
                    row.insert(to.into(), value.clone());
                }
            }
            if item.get("isDaily").and_then(Value::as_bool) == Some(true) {
                row.insert("daily".into(), json!(true));
            }
            Value::Object(row)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_the_five_legacy_keys() {
        let usage = json!({
            "kind": "personal", "editionType": "pro", "planName": "专业版包月",
            "usageLeft": "1200", "usageTotal": "2000",
            "expireAt": 1_800_000_000_000_i64,
            "resources": [
                { "packageCode": codes::PRO_MON, "left": 1000, "name": "专业版包月" },
                { "packageCode": codes::ACTIVITY, "left": 200, "name": "成长计划" }
            ]
        });
        let summary = credits_summary_from(&usage);
        assert_eq!(summary["kind"], json!("personal"));
        assert_eq!(summary["unlimited"], json!(false));
        assert_eq!(summary["totalLeft"], json!(1200));
        assert_eq!(summary["planLeft"], json!(1000));
        assert_eq!(summary["bonusLeft"], json!(200));
        let subscription = subscription_of(&usage).unwrap_or(Value::Null);
        assert_eq!(subscription["planName"], json!("专业版包月"));
        assert_eq!(subscription["remainQuota"], json!("1200"));
    }

    #[test]
    fn enterprise_carries_no_packs() {
        let usage = json!({ "kind": "enterprise", "unlimited": true, "usageLeft": "unlimited" });
        let summary = credits_summary_from(&usage);
        assert_eq!(summary["unlimited"], json!(true));
        assert_eq!(summary["totalLeft"], Value::Null);
        assert!(subscription_of(&usage).is_none());
        assert!(credit_packs_from(&usage).is_empty());
    }

    #[test]
    fn credit_packs_rename_remaining_and_mark_daily() {
        let usage = json!({ "resources": [
            { "name": "免费版每日额度", "total": 100, "used": 40, "left": 60, "isDaily": true }
        ]});
        let packs = credit_packs_from(&usage);
        assert_eq!(packs[0]["remain"], json!(60));
        assert_eq!(packs[0]["daily"], json!(true));
    }
}
