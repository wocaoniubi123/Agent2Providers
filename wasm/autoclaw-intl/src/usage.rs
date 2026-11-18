//! AutoClaw 额度查询：积分钱包 + 订阅信息（归一成账号页的统一形状）。
//!
//! ── 上游给的是什么 ──────────────────────────────────────────
//! 三条积分路径（两地相同）+ 一条订阅路径（**两地不同**）：
//! ```text
//!   GET /agent-assetmgr/api/v2/wallets?biz_app_id=autoclaw          v2 主链路
//!   GET /agent-assetmgr/api/v1/wallet-instances?wallet_type=all&wallet_scope=all   兜底
//!   GET /agent-assetmgr/api/v1/points/expiring?biz_app_id=autoclaw  即将过期
//!   GET /agentpay/v1/assistant/subscribe-info                       国内订阅
//!   GET /agentpay/v1/assistant/oversea-subscribe-info               国际订阅（Stripe）
//! ```
//!
//! ── 为什么订阅路径按地区分叉 ────────────────────────────────
//! 从客户端产物里核对出来的：国际版构建里 `getSubscribeInfo` 写死的是
//! `oversea-subscribe-info`，国内构建用 `subscribe-info` —— 订阅体系本身是两套。
//! 发错路径的表现是订阅块查不出来（而非整体失败），因此这里按地区给路径；
//! 积分那三条路径两地相同、不参与分叉。
//!
//! ── 归一形状（账号页读的键）──────────────────────────────────
//! `available`（总积分）/ `unit`（「积分」）/ `wallets[]` / `credits[]` /
//! `subscription{planName,status,expireAt,remainQuota,totalQuota}` / `raw`。
//! `credits[]` 只在非空时挂：界面按「键在不在 + 长度」决定要不要给这一格挂
//! 「可点开」的交互，给一个空数组会点出一个空框。
//!
//! ── 401 为什么原样透出 ──────────────────────────────────────
//! 契约要求：调用方据此走「刷新后重试一次」。上游把登录态过期放在 HTTP 200 的
//! body 里（`code: 410000` / `400000`），只判状态码会把一次过期查询当成成功。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credential;
use super::region::{self, Region};
use super::upstream;

/// 积分钱包路径（源实现 `POINTS_WALLET_PATH`，v2 主链路）
const POINTS_WALLET_PATH: &str = "/agent-assetmgr/api/v2/wallets?biz_app_id=autoclaw";
/// 旧版钱包路径（v2 拿不到时的兜底）
const POINTS_WALLET_LEGACY_PATH: &str =
    "/agent-assetmgr/api/v1/wallet-instances?wallet_type=all&wallet_scope=all";
/// 即将过期积分路径
const POINTS_EXPIRING_PATH: &str = "/agent-assetmgr/api/v1/points/expiring?biz_app_id=autoclaw";

/// v1 钱包实例的 scope → 展示名（源实现 `WALLET_SCOPE_LABELS`，逐字照抄）。
const WALLET_SCOPE_LABELS: &[(&str, &str)] = &[
    ("daily", "赠送积分"),
    ("monthly", "订阅积分"),
    ("long_term", "通用积分"),
    ("annual", "通用积分"),
    ("campaign", "活动积分"),
];

/// 订阅信息路径（按地区分叉，见模块头）。
fn subscribe_info_path(region: Region) -> &'static str {
    match region {
        Region::Cn => "/agentpay/v1/assistant/subscribe-info",
        Region::Intl => "/agentpay/v1/assistant/oversea-subscribe-info",
    }
}

/// 查一个账号的积分 / 订阅，归一成统一形状。
///
/// `account_id` 非空时必须是宿主当前账号（见 `upstream::account_record`）。
pub fn query(account_id: &str) -> Result<Value> {
    let record = upstream::account_record(account_id)?;
    let credentials = credential::credential(&record)?;
    let points = query_points(&credentials)?;
    let (subscription, subscription_error) = match query_subscription(&credentials) {
        Ok(value) => (value, Value::Null),
        Err(error) => (Value::Null, Value::String(error.message)),
    };
    let available = points.get("totalBalance").cloned().unwrap_or(Value::Null);
    let wallets = points.get("wallets").cloned().unwrap_or_else(|| json!([]));
    // 逐份明细只读上面这份 `points`（钱包清单 + 即将过期），不再打一次上游接口
    let credits = credit_rows_from(&points);
    let mut raw = serde_json::Map::new();
    raw.insert(
        "points".to_string(),
        points.get("raw").cloned().unwrap_or(Value::Null),
    );
    if let Some(expiring) = points.get("expiring") {
        if !expiring.is_null() {
            raw.insert("expiring".to_string(), expiring.clone());
        }
    }
    if !subscription_error.is_null() {
        raw.insert("subscriptionError".to_string(), subscription_error);
    }
    let mut document = json!({
        "available": available,
        // AutoClaw 的资产口径就是它自己的「积分」
        "unit": "积分",
        "wallets": wallets,
        "subscription": subscription,
        "raw": Value::Object(raw),
    });
    if !credits.is_empty() {
        if let Some(object) = document.as_object_mut() {
            object.insert("credits".to_string(), Value::Array(credits));
        }
    }
    Ok(document)
}

/// 查询积分钱包（源实现 `queryPoints`：v2 主链路 → v1 兜底 → expiring 附加）。
///
/// 返回 `{totalBalance, wallets, expiring, raw}`。
fn query_points(credentials: &credential::Credential) -> Result<Value> {
    let wallet_payload = upstream::get(POINTS_WALLET_PATH, &credentials.token, "积分查询")?;
    if let Some(code) = upstream::code_of(&wallet_payload) {
        if upstream::is_auth_expired_code(code) {
            return Err(Error::http(401, "登录态已过期，无法查询积分"));
        }
    }
    let code_ok = upstream::code_of(&wallet_payload) == Some(0);
    let data = wallet_payload.get("data").cloned().unwrap_or(Value::Null);
    let (total_balance, wallets, raw): (Value, Value, Value) = if code_ok
        && data.get("wallets").and_then(Value::as_array).is_some()
    {
        // v2：`data.wallets` 已是钱包数组（`balance` / `scope` / `expireAt`）
        let list = data.get("wallets").cloned().unwrap_or_else(|| json!([]));
        let total = data
            .get("totalBalance")
            .cloned()
            .or_else(|| data.get("total").cloned())
            .unwrap_or_else(|| json!(sum_balances(&list)));
        (total, list, data)
    } else {
        // v1 兜底：`data` 是 `wallet_instances` 数组
        let legacy = upstream::get(POINTS_WALLET_LEGACY_PATH, &credentials.token, "积分查询")?;
        if let Some(code) = upstream::code_of(&legacy) {
            if upstream::is_auth_expired_code(code) {
                return Err(Error::http(401, "登录态已过期，无法查询积分"));
            }
        }
        let legacy_data = legacy.get("data").cloned().unwrap_or(Value::Null);
        let instances = legacy_data
            .get("walletInstances")
            .or_else(|| legacy_data.get("wallet_instances"))
            .or_else(|| legacy_data.get("instances"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let list: Vec<Value> = instances.iter().map(normalize_legacy_wallet).collect();
        let list = Value::Array(list);
        (json!(sum_balances(&list)), list, legacy_data)
    };
    // 即将过期（附加，失败不影响主读数）
    let expiring = match upstream::get(POINTS_EXPIRING_PATH, &credentials.token, "即将过期积分查询") {
        Ok(payload) => payload.get("data").cloned().unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    Ok(json!({
        "totalBalance": total_balance,
        "wallets": wallets,
        "expiring": expiring,
        "raw": raw,
    }))
}

/// 钱包余额求和（`balance` / `amount` / `remain` 三种键名都认）。
fn sum_balances(list: &Value) -> f64 {
    let number = |value: &Value| -> Option<f64> {
        ["balance", "amount", "remain", "remainQuota"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_f64))
    };
    list.as_array()
        .map(|items| items.iter().filter_map(number).sum())
        .unwrap_or(0.0)
}

/// v1 钱包实例 → 统一钱包行（`scope` 决定展示名）。
fn normalize_legacy_wallet(instance: &Value) -> Value {
    let scope = instance
        .get("walletScope")
        .or_else(|| instance.get("wallet_scope"))
        .or_else(|| instance.get("scope"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let label = WALLET_SCOPE_LABELS
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(scope))
        .map(|(_, label)| (*label).to_string())
        .unwrap_or_else(|| "积分".to_string());
    let balance = sum_balances(&json!([instance]));
    let mut row = json!({
        "type": "credits",
        "displayName": label,
        "balance": balance,
        "unit": "积分",
    });
    if let Some(expire) = instance
        .get("expireAt")
        .or_else(|| instance.get("expireTime"))
        .or_else(|| instance.get("expiredAt"))
    {
        row["expireAt"] = expire.clone();
    }
    row
}

/// 钱包 / 即将过期 → `credits[]` 明细（界面「积分明细」那一栏）。
fn credit_rows_from(points: &Value) -> Vec<Value> {
    let mut rows: Vec<Value> = Vec::new();
    if let Some(wallets) = points.get("wallets").and_then(Value::as_array) {
        for wallet in wallets {
            let balance = sum_balances(&json!([wallet]));
            if balance <= 0.0 {
                continue;
            }
            let mut row = json!({
                "type": "credits",
                "displayName": wallet
                    .get("displayName")
                    .or_else(|| wallet.get("scope"))
                    .and_then(Value::as_str)
                    .unwrap_or("积分"),
                "balance": balance,
                "unit": "积分",
            });
            if let Some(expire) = wallet
                .get("expireAt")
                .or_else(|| wallet.get("expireTime"))
                .or_else(|| wallet.get("expiredAt"))
            {
                row["expireAt"] = expire.clone();
            }
            rows.push(row);
        }
    }
    if let Some(expiring) = points.get("expiring").and_then(Value::as_array) {
        for item in expiring {
            let amount = sum_balances(&json!([item]));
            if amount <= 0.0 {
                continue;
            }
            rows.push(json!({
                "type": "expiring",
                "displayName": "即将过期",
                "balance": amount,
                "unit": "积分",
                "expireAt": item.get("expireAt").or_else(|| item.get("expireTime")).cloned().unwrap_or(Value::Null),
            }));
        }
    }
    rows
}

/// 查订阅（失败不升级为错误，由调用方把文案挂进 `raw.subscriptionError`）。
fn query_subscription(credentials: &credential::Credential) -> Result<Value> {
    let payload = upstream::get(
        subscribe_info_path(region::REGION),
        &credentials.token,
        "订阅查询",
    )?;
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    Ok(normalize_subscription(&data))
}

/// 订阅响应 → 契约形状。
///
/// ── 为什么是「深搜候选键」而不是固定路径 ─────────────────────
/// 上游的订阅信息嵌在 `memberInfo` / `vipInfo` 等不同容器里（客户端自己也是
/// 在几个候选根里找），固定路径取值一旦上游换层就会静默变成一片 null。
fn normalize_subscription(data: &Value) -> Value {
    let nested = ["subscribeInfo", "subscribe", "data", "memberInfo", "vipInfo"]
        .iter()
        .filter_map(|key| data.get(*key))
        .find(|value| value.is_object());
    let mut roots: Vec<&Value> = vec![data];
    if let Some(nested) = nested {
        roots.push(nested);
    }
    // 在若干候选根里广度优先找第一个键命中且非空的值（层数上限 200，防膨胀）
    fn find_deep(roots: &[&Value], keys: &[&str]) -> Option<Value> {
        let mut pending: Vec<&Value> = roots.to_vec();
        let mut visited = 0usize;
        while let Some(current) = pending.pop() {
            visited += 1;
            if visited > 200 {
                break;
            }
            let Some(object) = current.as_object() else { continue };
            for (key, value) in object {
                if keys.contains(&key.as_str()) && !is_blank(value) {
                    return Some(value.clone());
                }
                if value.is_object() {
                    pending.push(value);
                }
            }
        }
        None
    }
    fn is_blank(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::String(text) => text.trim().is_empty(),
            _ => false,
        }
    }
    let text_of = |value: Option<Value>| -> String {
        match value {
            Some(Value::String(text)) if !text.trim().is_empty() => text.trim().to_string(),
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        }
    };
    let quota_of = |keys: &[&str]| -> Value {
        find_deep(&roots, keys)
            .and_then(|value| match value {
                Value::Number(number) => number.as_f64(),
                Value::String(text) => text.trim().parse::<f64>().ok(),
                _ => None,
            })
            .filter(|value| value.is_finite())
            .map(|value| json!(value))
            .unwrap_or(Value::Null)
    };
    json!({
        "planName": text_of(find_deep(&roots, &[
            "productName", "planName", "memberName", "subscribeName", "vipName",
        ])),
        "status": text_of(find_deep(&roots, &["status", "subscribeStatus", "memberStatus"])),
        "expireAt": find_deep(&roots, &[
            "expireAt", "expireTime", "expiredAt", "endTime", "validEndTime",
        ]).unwrap_or(Value::Null),
        "remainQuota": quota_of(&[
            "remainQuota", "remainingQuota", "remainCredits", "availableCredits", "leftQuota",
        ]),
        "totalQuota": quota_of(&["totalQuota", "credits", "totalCredits"]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 订阅路径两地不同（发错只是订阅块查不出来，所以必须有测试钉住）。
    #[test]
    fn subscription_paths_are_region_specific() {
        assert_eq!("/agentpay/v1/assistant/subscribe-info", subscribe_info_path(Region::Cn));
        assert_eq!(
            "/agentpay/v1/assistant/oversea-subscribe-info",
            subscribe_info_path(Region::Intl)
        );
    }

    /// 深搜能在 `vipInfo` 容器里找到套餐名与剩余积分。
    #[test]
    fn subscription_shape_is_deep() {
        let data = json!({
            "vipInfo": { "vipName": "Coding Plan", "remainQuota": 1200, "totalQuota": "2000", "endTime": "2026-01-01" }
        });
        let shape = normalize_subscription(&data);
        assert_eq!("Coding Plan", shape["planName"].as_str().unwrap_or(""));
        assert_eq!(1200.0, shape["remainQuota"].as_f64().unwrap_or(0.0));
        assert_eq!(2000.0, shape["totalQuota"].as_f64().unwrap_or(0.0));
    }

    /// 钱包余额求和与明细：v1 实例按 scope 取展示名。
    #[test]
    fn wallet_rows_and_sum() {
        let list = json!([{ "balance": 100 }, { "balance": 50.5 }]);
        assert!((150.5 - sum_balances(&list)).abs() < f64::EPSILON);
        let row = normalize_legacy_wallet(&json!({ "walletScope": "monthly", "balance": 10 }));
        assert_eq!("订阅积分", row["displayName"].as_str().unwrap_or(""));
    }
}
