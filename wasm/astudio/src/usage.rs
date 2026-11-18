//! AStudio 余额：网页会话读 `points/balance` 与 `membership/me`。
//!
//! ── 两种账号形态 ────────────────────────────────────────────
//! ```text
//!   有网页会话  →  通用积分 / 星火积分 / 会员档 / 到期时间（真实读数）
//!   只有模型凭据 →  用目录接口探活，显示「AStudio」与一个连通性结果
//! ```
//! 所有读取都不计费；只有模型调用才消耗积分。
//!
//! ── 单项失败不塌方 ──────────────────────────────────────────
//! 余额与会员信息是两条接口：一条挂了另一条还能显示。但**会话失效必须
//! 透传**（否则用户看到的是「账号信息读取失败」，而不是「请重新登录」）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, client};

fn number(value: Option<&Value>) -> Option<f64> {
    value.and_then(|value| value.as_f64()).filter(|number| number.is_finite())
}

/// `usage.query`。
pub fn query() -> Result<Value> {
    let secret = account::current()?;
    let credentials = account::Credentials::from_secret(&secret);
    if credentials.key.is_empty() {
        return Err(Error::http(401, "AStudio 账号缺少 modelBearerToken，请重新登录或粘贴"));
    }
    if !credentials.has_session() {
        // 只有模型凭据：用目录接口探活（与 native 的 usage 同处置）。
        return match client::fetch_catalog(&credentials.key) {
            Ok(_) => Ok(json!({ "provider": "astudio", "plan": "AStudio", "windows": [] })),
            Err(client::CatalogError::Expired) => {
                Err(Error::http(401, "AStudio 拒绝了这份凭据（HTTP 401/403），请重新登录"))
            }
            Err(client::CatalogError::Failed(message)) => Ok(json!({
                "provider": "astudio",
                "plan": "AStudio",
                "windows": [],
                "error": format!("AStudio 不可达：{message}"),
            })),
        };
    }
    let balance = client::studio_json(&credentials, client::POINTS_BALANCE, "积分余额");
    let membership = client::studio_json(&credentials, client::MEMBERSHIP_ME, "会员信息");
    let mut expired: Option<String> = None;
    let mut failures: Vec<String> = Vec::new();
    let balance = match balance {
        Ok(value) => Some(value),
        Err(client::StudioError::Expired(message)) => {
            expired = Some(message);
            None
        }
        Err(error) => {
            failures.push(error.message().to_string());
            None
        }
    };
    let membership = match membership {
        Ok(value) => Some(value),
        Err(client::StudioError::Expired(message)) => {
            expired = Some(message);
            None
        }
        Err(error) => {
            failures.push(error.message().to_string());
            None
        }
    };
    if let Some(message) = expired {
        return Err(Error::http(401, message));
    }
    if balance.is_none() && membership.is_none() {
        return Ok(json!({
            "provider": "astudio",
            "plan": "AStudio",
            "windows": [],
            "error": failures.join("；"),
        }));
    }
    let mut windows: Vec<Value> = Vec::new();
    if let Some(balance) = &balance {
        if let Some(total) = number(balance.get("totalBalance")) {
            let mut window = json!({
                "name": "通用积分",
                "label": "通用积分",
                "balance": total,
                "remaining": total,
                "display": format_number(total),
                "unit": "积分",
                "aside": false,
            });
            if let Some(activity) = number(balance.get("activityBalance")) {
                if activity > 0.0 {
                    if let Some(next) = balance.get("activityNextExpireTime").filter(|value| !value.is_null()) {
                        window["runsOutAt"] = next.clone();
                        window["runsOut"] = json!(activity);
                    }
                }
            }
            windows.push(window);
        }
        if let Some(spark) = number(balance.get("sparkTotalBalance")) {
            windows.push(json!({
                "name": "星火积分",
                "label": "星火积分",
                "balance": spark,
                "remaining": spark,
                "display": format_number(spark),
                "unit": "积分",
                "aside": false,
            }));
        }
    }
    let mut report = json!({ "provider": "astudio", "unit": "积分", "windows": windows });
    if let Some(membership) = &membership {
        if let Some(plan) = membership.get("planName").and_then(Value::as_str) {
            if !plan.is_empty() {
                report["plan"] = json!(plan);
            }
        }
        if let Some(uid) = membership.get("uid") {
            if !uid.is_null() {
                report["user"] = json!(uid.to_string());
            }
        }
        if let Some(until) = membership.get("endTime").filter(|value| !value.is_null()) {
            report["until"] = until.clone();
        }
    }
    if report.get("plan").is_none() {
        report["plan"] = json!("AStudio");
    }
    Ok(report)
}

fn format_number(value: f64) -> String {
    if value.fract().abs() < 0.005 {
        format!("{}", value.round() as i64)
    } else {
        format!("{value:.2}")
    }
}
