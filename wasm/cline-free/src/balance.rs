//! Cline 余额：`GET /users/{userId}/balance` + `/users/me/plan`。
//!
//! ── 账号 id 的三条来源 ──────────────────────────────────────
//! ```text
//!   1. 凭据里的 accountId（桌面端 providers.json 里就有）
//!   2. JWT 的 external_id（usr-… 形态）
//!   3. 兜底打一次 /users/me，用它的 data.id
//! ```
//! 三条都拿不到就如实报错（不把「拿不到 id」折叠成「余额 0」）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, credentials, pool::Pool, refresh, upstream};

/// 账号 id（`usr-…`）。
fn account_id(credentials: &credentials::ClineCredentials) -> Result<String> {
    if !credentials.account.is_empty() {
        return Ok(credentials.account.clone());
    }
    if let Some(id) = credentials::account_id_from_jwt(&credentials.bearer_token()) {
        return Ok(id);
    }
    let payload = upstream::get("/users/me", &credentials.bearer_token())?;
    payload
        .pointer("/data/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::http(502, "Cline 余额查询失败：拿不到账号 id（上游 /users/me 未返回 id）"))
}

/// `usage.query`。
pub fn query(pool: Pool) -> Result<Value> {
    let (credentials, _) = account::current(pool)?;
    let credentials = if credentials.is_expiring() {
        refresh::ensure(false).unwrap_or(credentials)
    } else {
        credentials
    };
    let token = credentials.bearer_token();
    let id = account_id(&credentials)?;
    let balance = upstream::get(&format!("/users/{id}/balance"), &token)?;
    let mut windows: Vec<Value> = Vec::new();
    let mut credits: Vec<Value> = Vec::new();
    if let Some(data) = balance.get("data").filter(|value| value.is_object()) {
        for (key, label) in [
            ("credits", "积分"),
            ("freeCredits", "免费积分"),
            ("paidCredits", "付费积分"),
        ] {
            if let Some(amount) = data.get(key).and_then(Value::as_f64).filter(|value| value.is_finite()) {
                windows.push(json!({
                    "name": label,
                    "label": label,
                    "balance": amount,
                    "remaining": amount,
                    "display": format!("{amount:.0}"),
                    "unit": "credits",
                }));
                credits.push(json!({
                    "name": label, "remain": amount, "unit": "credits",
                }));
            }
        }
    }
    // `/users/me/plan`：没订阅时 404 是正常状态（当成没有套餐，不报错）。
    let plan = upstream::get("/users/me/plan", &token)
        .ok()
        .and_then(|payload| payload.pointer("/data/name").and_then(Value::as_str).map(str::to_string));
    let mut report = json!({
        "provider": pool.provider_id(),
        "unit": "credits",
        "windows": windows,
        "credits": credits,
    });
    if let Some(plan) = plan {
        report["plan"] = json!(plan);
    }
    if !credentials.account.is_empty() {
        report["user"] = json!(credentials.account);
    }
    Ok(report)
}
