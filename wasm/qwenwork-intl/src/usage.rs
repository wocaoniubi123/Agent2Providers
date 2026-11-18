//! 额度查询：归一成账号页的余额形态（`available` / `unit` / `credits` /
//! `subscription`）—— 千问办公的取数口径（native `balance.rs` 的 `qwenwork_*` 分支）。
//!
//! ── 上游长什么样（2026-10-31 复核）────────────────────────────
//!   1. `GET {gateway}/api/v1/adapter/user/account-context?include=user,plan,quota`
//!      → `{data:{user:{…}, plan:{name, next_refresh_date}, quota:{total, used,
//!      remaining}}}`
//!   2. `GET {gateway}/api/v1/adapter/user/wallets`（**只有国内版的个人账号有**；
//!      国际版未取证，本包 `site::WALLETS_PATH` 是 `None`，这一步不会发生）
//!      → `{data:{daily_credits:{total_balance}, monthly_credits:{…},
//!      longterm_credits:{…}}}`
//!
//! ── 为什么 `total` / `used` 可能是空 ────────────────────────
//! 个人账号的 `quota` 只给 `remaining`（`total` 与 `used` 都是 null）—— 那时只报
//! 余额，**不反推**一个「已用占比」：反推出来的 0 总额正是「明明用得好好的却显示
//! 0/0」那类工单的来源。企业账号或有总额的账号照常给「已用 / 总额」那一行。
//!
//! ── 三档积分池为什么只作明细行 ──────────────────────────────
//! 它们的和就是 `quota.remaining` 本身（「这份余额里都是什么」），叠加进
//! `available` 会算成两倍。所以只作 `credits[]` 的明细行，与 native 同口径。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use serde_json::{json, Map, Value};

use agent2api_wasm_sdk::{Error, Result};

use super::auth;
use super::credentials::Credentials;
use super::refresh;
use super::site;

/// 三档积分池：上游键 → 展示名。
///
/// 顺序固定（每日 → 每月 → 长期）：界面按数组顺序渲染，换了顺序同一份数据会
/// 看起来「跳了一下」。第三列是 native 的注释性键（保留原样，便于对拍）。
const POOLS: &[(&str, &str, &str)] = &[
    ("daily_credits", "每日积分", "daily_credits"),
    ("monthly_credits", "每月积分", "monthly_credits"),
    ("longterm_credits", "长期积分", "longterm_credits"),
];

/// 余额单位（这一家的额度就是 credits，不可配置）
const DEFAULT_UNIT: &str = "credits";

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok().filter(|value| value.is_finite()),
        _ => None,
    }
}

/// 一行明细：`name` + 三个数 +（与文档级不同的）单位；三个数一个都没有时给
/// `None`（整行不出）。
///
/// **缺失不写键**：界面 `Number(null) === 0`，写 null 会把「没读到」画成
/// 「只剩 0」。
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
    if let Some(unit) = unit
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != doc_unit)
    {
        row.insert("unit".to_string(), Value::String(unit.to_string()));
    }
    Some(Value::Object(row))
}

/// 正文的 `data` 层（这两条接口都把载荷包在 `data` 里）。
fn unwrap_data(value: &Value) -> &Value {
    value.get("data").filter(|value| value.is_object()).unwrap_or(value)
}

/// 钱包 → 逐档余额（每一格的 `total_balance` 是这一档**还剩多少**）。
///
/// 读不到的池直接不出行（不编造 0）；<= 0 的池也不出（「这一档空了」在界面
/// 上没有信息量，而四行里出现三个 0 会让用户以为读坏了）。
fn wallet_pools(wallets: &Value) -> Vec<(String, f64)> {
    let data = unwrap_data(wallets);
    let mut out = Vec::new();
    for (key, label, _) in POOLS {
        let pool = data.get(*key);
        let balance = pool
            .and_then(|pool| number(pool.get("total_balance")))
            .or_else(|| pool.and_then(|pool| number(pool.get("totalBalance"))));
        if let Some(balance) = balance.filter(|value| *value > 0.0) {
            out.push((label.to_string(), balance));
        }
    }
    out
}

/// 账号上下文 + 钱包 → 账号页的余额文档（native `qwenwork_document` 逐条对应）。
fn usage_document(context: &Value, wallets: Option<&Value>) -> Value {
    let data = unwrap_data(context);
    let plan = data.get("plan").filter(|value| value.is_object());
    let quota = data.get("quota").filter(|value| value.is_object());

    let mut credits: Vec<Value> = Vec::new();
    let mut available: Option<f64> = None;

    if let Some(quota) = quota {
        let total = number(quota.get("total"));
        let remaining = number(quota.get("remaining"));
        // `used` 缺失时按 total - remaining 推：这是**同一份数据**的算术，不是
        // 编造（个人账号两个都为 null，于是这里也不会得出任何值）。
        let used = number(quota.get("used")).or_else(|| match (total, remaining) {
            (Some(total), Some(remaining)) => Some(total - remaining),
            _ => None,
        });
        if let Some(row) = credit_row("积分", total, used, remaining, None, DEFAULT_UNIT) {
            credits.push(row);
        }
        available = remaining;
    }
    if let Some(wallets) = wallets {
        for (label, balance) in wallet_pools(wallets) {
            if let Some(row) = credit_row(&label, None, None, Some(balance), None, DEFAULT_UNIT) {
                credits.push(row);
            }
        }
    }

    let mut document = Map::new();
    document.insert(
        "available".to_string(),
        available.map_or(Value::Null, |value| json!(value)),
    );
    document.insert("unit".to_string(), Value::String(DEFAULT_UNIT.to_string()));
    // 这一家的余额不是「多档钱包」形状（三档池只作明细行），所以 wallets 恒为空
    // 数组 —— 但键要在：界面按「键在不在」决定渲不渲染那一节。
    document.insert("wallets".to_string(), Value::Array(Vec::new()));
    if !credits.is_empty() {
        document.insert("credits".to_string(), Value::Array(credits));
    }

    let mut subscription = Map::new();
    if let Some(name) = plan
        .and_then(|plan| plan.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        subscription.insert("planName".to_string(), Value::String(name.to_string()));
    }
    let renew = plan
        .and_then(|plan| plan.get("next_refresh_date").or_else(|| plan.get("next_due_date")))
        .and_then(Value::as_str)
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .map(|time| time.timestamp_millis());
    if let Some(renew) = renew {
        subscription.insert("expireAt".to_string(), json!(renew));
    }
    document.insert("subscription".to_string(), Value::Object(subscription));
    Value::Object(document)
}

/// 读一份账号接口（带令牌）。
fn read(path: &str, token: &str) -> Result<Value> {
    let response = auth::request(
        "GET",
        &site::open_api_url(path),
        None,
        &site::open_api_headers(Some(token)),
    )?;
    auth::payload(response, "额度查询")
}

/// 钱包要不要读：只有**国内版个人账号**有那三档池（本包 `WALLETS_PATH` 为
/// `None`，所以这个判据在国际版上一律为假）。
///
/// `is_biz` 为真（企业账号）时不读 —— 读回来是空对象，白花一次请求。字段名在
/// 上游有 snake / camel 两种形态，两个都认（magpie 与 dumate2api 各抄到一种）。
fn personal_account(context: &Value) -> bool {
    let user = unwrap_data(context)
        .get("user")
        .filter(|value| value.is_object());
    let is_biz = user.and_then(|user| user.get("is_biz").or_else(|| user.get("isBiz")));
    is_biz.and_then(Value::as_bool) != Some(true)
}

/// 额度查询。401 / 403 时**强制**续期一次再读（不看的临期窗口：被服务端作废但
/// 时间上还很新的令牌正是这一档要救的；native 同一条处置）。
pub fn query() -> Result<Value> {
    let mut credentials: Credentials = refresh::ensure_fresh(false)?;
    let path = site::ACCOUNT_CONTEXT_QUOTA_PATH;
    let mut context = read(path, &credentials.access_token);
    if matches!(&context, Err(error) if matches!(error.status, Some(401) | Some(403)))
        && credentials.can_refresh()
    {
        credentials = refresh::ensure_fresh(true)?;
        context = read(path, &credentials.access_token);
    }
    let context = context.map_err(|error| {
        if error.status.is_none() {
            Error::http(502, error.message)
        } else {
            error
        }
    })?;

    // 钱包读失败不阻断：余额本身已经在手，分项读不到就只少几行明细。
    let mut wallets: Option<Value> = None;
    if let Some(path) = site::WALLETS_PATH.filter(|_| personal_account(&context)) {
        wallets = read(path, &credentials.access_token).ok();
    }
    Ok(usage_document(&context, wallets.as_ref()))
}
