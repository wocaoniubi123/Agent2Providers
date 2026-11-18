//! 额度查询：归一成账号页的余额形态（`available` / `unit` / `wallets` / `credits`）。
//!
//! ── Qoder 的三个桶（2026-09-27 在真实账号上实测）──────────────────
//!   - `userQuota`：订阅套餐的额度（官方控制台「订阅版本的资源」，如总额 300、
//!     剩余 225）。`available` 的主口径，字段 `total/used/remaining/unit`；
//!   - `addOnQuota`：官方控制台叫「**个人资源包**」——通过活动/购买获得，
//!     每日签到每签一次发一个 100 credits、30 天有效的包（领 6 次就是 600）。
//!     **上游只在真有资源包时才返回这个键**：没有就整个键缺失（实测 Free 套餐
//!     账号如此），因此要判「有没有」，不能当成恒在的桶去读零；
//!   - `orgResourcePackage`：组织（团队）资源包。**字段形状与上面两个都不同**：
//!     总量叫 `cap`（不是 `total`）、另外多一个 `available` 布尔标它是否真的可用。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use serde_json::{json, Map, Value};

use agent2api_wasm_sdk::Result;

use super::auth;
use super::credentials::Credentials;
use super::refresh;
use super::site;

/// `expiresAt` 的「永不过期」哨兵值：上游给 `253402214400000`（9999-12-31）。
///
/// 原样透出会让余额面板显示「到期 9999/12/31」——那不是用户能用的信息。
/// 判据取 2100-01-01：真实订阅（含最长的年付）不可能超过它。
const EXPIRY_SENTINEL_MS: f64 = 4_102_444_800_000.0;

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok().filter(|value| value.is_finite()),
        _ => None,
    }
}

/// 一行钱包（账号页余额面板按 `displayName` + `balanceView` 渲染）。
fn wallet(kind: &str, name: &str, value: f64, unit: &str) -> Value {
    json!({
        "type": kind,
        "displayName": name,
        "balance": value,
        "balanceView": format!("{value} {unit}"),
    })
}

/// `addOnQuota` 桶本身（键在、是对象、且**不是空桶**）。
///
/// 判据只有这一份（「键缺失或全零 = 没有资源包」）：[`add_on`] 的钱包行与
/// [`credit_rows`] 的个人资源包行都从这里取桶 —— 两处各判一次迟早漂成两种口径。
fn add_on_bucket(raw: &Value) -> Option<&Value> {
    let bucket = raw.get("addOnQuota").filter(|value| value.is_object())?;
    let total = number(bucket.get("total"));
    let used = number(bucket.get("used"));
    let remaining = number(bucket.get("remaining"));
    if [total, used, remaining].iter().all(|value| value.unwrap_or(0.0) <= 0.0) {
        return None;
    }
    Some(bucket)
}

/// 个人资源包（`addOnQuota`）→ 钱包行 + 剩余额度。
///
/// 没有这个键、或全零（上游会返回空对象）时给空结果 —— 「全零」意味着没有
/// 资源包，而不是「有 0 个」。
fn add_on(raw: &Value, fallback_unit: &str) -> (Vec<Value>, Option<f64>) {
    let Some(bucket) = add_on_bucket(raw) else {
        return (Vec::new(), None);
    };
    let total = number(bucket.get("total"));
    let used = number(bucket.get("used"));
    let remaining = number(bucket.get("remaining"));
    let unit = bucket.get("unit").and_then(Value::as_str).unwrap_or(fallback_unit);
    let mut wallets = Vec::new();
    if let Some(value) = used {
        wallets.push(wallet("addon_used", "资源包已用", value, unit));
    }
    if let Some(value) = total {
        wallets.push(wallet("addon_total", "资源包总额", value, unit));
    }
    (wallets, remaining)
}

/// `orgResourcePackage` 桶本身（键在、是对象、且上游说它**可用**）。
fn org_bucket(raw: &Value) -> Option<&Value> {
    let bucket = raw.get("orgResourcePackage").filter(|value| value.is_object())?;
    let cap = number(bucket.get("cap")).or_else(|| number(bucket.get("total")));
    let used = number(bucket.get("used"));
    let remaining = number(bucket.get("remaining"));
    let usable = bucket.get("available").and_then(Value::as_bool).unwrap_or_else(|| {
        [cap, used, remaining].iter().any(|value| value.unwrap_or(0.0) > 0.0)
    });
    if usable {
        Some(bucket)
    } else {
        None
    }
}

/// 组织资源包（`orgResourcePackage`）→ 钱包行 + 剩余额度。
///
/// 判据与上面两桶**都不同**：
///   * 总量字段叫 `cap`（旧形状里叫 `total`，作兜底读）；
///   * 空桶也**整个键返回**，所以「键在不在」不能当判据；上游用 `available`
///     表明这份额度当前是否真的可用，`false` 时整桶跳过；
///   * `remaining` 只在可用时算进「还能花多少」。
fn org_package(raw: &Value, fallback_unit: &str) -> (Vec<Value>, Option<f64>) {
    let Some(bucket) = org_bucket(raw) else {
        return (Vec::new(), None);
    };
    let cap = number(bucket.get("cap")).or_else(|| number(bucket.get("total")));
    let used = number(bucket.get("used"));
    let remaining = number(bucket.get("remaining"));
    let unit = bucket.get("unit").and_then(Value::as_str).unwrap_or(fallback_unit);
    let mut wallets = Vec::new();
    if let Some(total) = cap.filter(|value| *value > 0.0) {
        wallets.push(wallet("org_total", "组织总额", total, unit));
    }
    if let Some(value) = used {
        wallets.push(wallet("org_used", "组织已用", value, unit));
    }
    (wallets, remaining)
}

/// 逐桶明细行（账号页「积分明细」弹层的输入）。
///
/// 三个数直接透传桶上的 `total` / `used` / `remaining`，**缺失不写键**
/// （界面 `Number(null) === 0`，写 null 会把「没读到」画成「只剩 0」）。
fn credit_rows(raw: &Value, doc_unit: &str) -> Vec<Value> {
    let mut rows: Vec<Value> = Vec::new();
    if let Some(bucket) = raw.get("userQuota").filter(|value| value.is_object()) {
        if let Some(row) = credit_row(
            "套餐额度",
            number(bucket.get("total")),
            number(bucket.get("used")),
            number(bucket.get("remaining")),
            bucket.get("unit").and_then(Value::as_str),
            doc_unit,
        ) {
            rows.push(row);
        }
    }
    if let Some(bucket) = add_on_bucket(raw) {
        if let Some(row) = credit_row(
            "个人资源包",
            number(bucket.get("total")),
            number(bucket.get("used")),
            number(bucket.get("remaining")),
            bucket.get("unit").and_then(Value::as_str),
            doc_unit,
        ) {
            rows.push(row);
        }
    }
    if let Some(bucket) = org_bucket(raw) {
        if let Some(row) = credit_row(
            "组织资源包",
            number(bucket.get("cap")).or_else(|| number(bucket.get("total"))),
            number(bucket.get("used")),
            number(bucket.get("remaining")),
            bucket.get("unit").and_then(Value::as_str),
            doc_unit,
        ) {
            rows.push(row);
        }
    }
    rows
}

/// 一行明细：`name` + 三个数 +（与文档级不同的）单位；三个数一个都没有时给
/// `None`（整行不出）。
fn credit_row(
    name: &str,
    total: Option<f64>,
    used: Option<f64>,
    remain: Option<f64>,
    unit: Option<&str>,
    doc_unit: &str,
) -> Option<Value> {
    if total.is_none() && used.is_none() && remain.is_none() {
        return None;
    }
    let mut row = Map::new();
    row.insert("name".to_string(), Value::String(name.to_string()));
    for (key, value) in [("total", total), ("used", used), ("remain", remain)] {
        if let Some(value) = value {
            row.insert(key.to_string(), json!(value));
        }
    }
    if let Some(unit) = unit.map(str::trim).filter(|value| !value.is_empty() && *value != doc_unit) {
        row.insert("unit".to_string(), Value::String(unit.to_string()));
    }
    Some(Value::Object(row))
}

/// 订阅到期时间；哨兵值、0 与 null 都按「没有到期时间」处理（不显示）。
fn expiry_of(raw: &Value) -> Option<Value> {
    let value = raw.get("expiresAt")?;
    if value.is_null() {
        return None;
    }
    if let Some(ms) = number(Some(value)) {
        if ms <= 0.0 || ms >= EXPIRY_SENTINEL_MS {
            return None;
        }
    }
    Some(value.clone())
}

/// 套餐名（`plan_tier_name`）。**best-effort**：失败只让这一行不显示。
fn plan_name(credentials: &Credentials) -> Option<String> {
    let response = auth::request(
        "GET",
        &site::open_api_url(site::PLAN_PATH),
        None,
        &site::open_api_headers(Some(&credentials.access_token)),
    )
    .ok()?;
    let name = response.payload?.get("plan_tier_name")?.as_str()?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// 额度文档的纯函数半边：三个桶合成钱包明细、`available` 与逐桶明细。
///
/// 抽出来是为了让「组织资源包计不计入 `available`」这类判据能被单独钉住——
/// 这一带的历史事故全是「明明读到了却显示成没有」，而症状在界面上。
fn usage_document(raw: &Value) -> Value {
    let quota = raw.get("userQuota");
    let remaining = quota.and_then(|quota| number(quota.get("remaining")));
    let total = quota.and_then(|quota| number(quota.get("total")));
    let used = quota.and_then(|quota| number(quota.get("used")));
    let unit = quota
        .and_then(|quota| quota.get("unit"))
        .and_then(Value::as_str)
        .unwrap_or("额度");
    let mut wallets = Vec::new();
    if let Some(value) = used {
        wallets.push(json!({ "type": "user_used", "displayName": "个人已用", "balance": value }));
    }
    if let Some(value) = total {
        wallets.push(json!({ "type": "user_total", "displayName": "个人总额", "balance": value }));
    }
    let (add_on_wallets, add_on_remaining) = add_on(raw, unit);
    wallets.extend(add_on_wallets);
    let (org_wallets, org_remaining) = org_package(raw, unit);
    wallets.extend(org_wallets);
    // 「还能花多少」= 套餐剩余 + 个人资源包剩余 + 组织资源包剩余（都能花）
    let available = [remaining, add_on_remaining, org_remaining]
        .into_iter()
        .flatten()
        .reduce(|acc, value| acc + value);
    let credits = credit_rows(raw, unit);
    let mut document = json!({
        "available": available,
        "unit": unit,
        "wallets": wallets,
    });
    if !credits.is_empty() {
        if let Some(object) = document.as_object_mut() {
            object.insert("credits".to_string(), Value::Array(credits));
        }
    }
    document
}

/// 额度查询。401 时**强制**续期一次再读（不看临期窗口：被服务端作废但时间上
/// 还很新的令牌正是这一档要救的）。
pub fn query() -> Result<Value> {
    let mut credentials = refresh::ensure_fresh(false)?;
    let url = site::open_api_url(site::USAGE_PATH);
    let mut response = auth::request(
        "GET",
        &url,
        None,
        &site::open_api_headers(Some(&credentials.access_token)),
    )?;
    if response.status == 401 && credentials.can_refresh() {
        credentials = refresh::ensure_fresh(true)?;
        response = auth::request(
            "GET",
            &url,
            None,
            &site::open_api_headers(Some(&credentials.access_token)),
        )?;
    }
    let raw = auth::payload(response, "额度查询")?;
    let mut document = usage_document(&raw);
    let mut subscription = Map::new();
    if let Some(name) = plan_name(&credentials) {
        subscription.insert("planName".to_string(), Value::String(name));
    }
    if let Some(value) = expiry_of(&raw) {
        subscription.insert("expireAt".to_string(), value);
    }
    if let Some(object) = document.as_object_mut() {
        object.insert("subscription".to_string(), Value::Object(subscription));
    }
    Ok(document)
}
