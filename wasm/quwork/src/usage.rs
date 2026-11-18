//! QuWork 积分余额：账号面 `GET /api/user/self` 的 `points_entitlement`。
//!
//! ── 单位口径（踩过的坑）────────────────────────────────────
//! 账号 `amount` 的单位是**百积分**（native 的注释：`points_entitlement` 已是
//! 积分，不能再乘 100）；只有在没有 `points_entitlement` 时才回落到
//! `amount × 100` 并把结果标成估算值。
//!
//! ── 未知余额不许当 0 ────────────────────────────────────────
//! 一个字段都解析不出来时**报错**，而不是回一份「余额 0」的报告 ——
//! 那会让面板把「上游改字段了」显示成「你的积分用完了」。

use agent2api_wasm_sdk::{json, Result, Value};

use super::{refresh, upstream};

/// `usage.query`。
pub fn query() -> Result<Value> {
    let reply = refresh::protected("GET", upstream::SELF_PATH, None)?;
    let data = reply.data("积分查询")?;
    if !data.is_object() {
        return Err(agent2api_wasm_sdk::Error::http(502, "QuWork 积分返回格式异常"));
    }
    let entitlement = data.get("points_entitlement").unwrap_or(&Value::Null);
    let available = upstream::number(entitlement.get("total_points")).or_else(|| {
        upstream::number(data.get("amount"))
            .map(|amount| (amount * 100.0).round())
            .filter(|value| value.is_finite())
    });
    let mut credits: Vec<Value> = Vec::new();
    for (id, name, field) in [
        ("limited", "限时积分", "limited_points"),
        ("permanent", "永久积分", "permanent_points"),
    ] {
        if let Some(remaining) = upstream::number(entitlement.get(field)) {
            credits.push(json!({
                "id": id, "name": name, "balance": remaining, "remain": remaining,
                "unit": "积分", "snapshot": true,
            }));
        }
    }
    let subscription = entitlement
        .get("active_subscription")
        .filter(|value| value.is_object());
    let plan = subscription
        .and_then(|value| value.get("plan_name"))
        .and_then(Value::as_str);
    if let Some(subscription) = subscription {
        credits.push(json!({
            "id": "subscription",
            "name": plan.unwrap_or("订阅积分"),
            "remain": upstream::number(subscription.get("remaining_points")),
            "total": upstream::number(subscription.get("total_points")),
            "used": upstream::number(subscription.get("used_points")),
            "grantAt": upstream::timestamp(subscription.get("started_at")),
            "expireAt": upstream::timestamp(subscription.get("expires_at")),
            "unit": "积分",
        }));
    }
    if available.is_none() && credits.is_empty() {
        return Err(agent2api_wasm_sdk::Error::http(
            502,
            "QuWork 未返回可识别的积分余额，未将未知余额当作 0",
        ));
    }
    let mut sources: Vec<Value> = Vec::new();
    if let Some(available) = available {
        sources.push(json!({
            "id": "account", "label": "账号积分", "unit": "积分", "available": available,
        }));
    }
    Ok(json!({
        "available": available,
        "unit": "积分",
        "plan": plan,
        "credits": credits,
        "until": subscription.and_then(|value| upstream::timestamp(value.get("expires_at"))),
        "quotaSources": sources,
    }))
}
