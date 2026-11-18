//! OfficeAce 的订阅 / 额度 / 奖励族接口：控制面 **V11-HMAC-SHA256** 签名。
//!
//! ── 挂在网关根，不是 chat 的 `/v2` ──────────────────────────
//! 账号里存的 `baseUrl` 是 `https://{host}/v2`（见 `oauth::gateway_of`），
//! 而 `/v1/subscription` 与 `/v1/subscription/bonus/claim` 都挂在**网关根**上；
//! [`gateway_base`] 去掉尾 `/v2` 再拼路径。
//!
//! ── 三条实测坑（写在这里，别在别处重推）──────────────────────
//!   1. 领奖励 `POST /v1/subscription/bonus/claim` **必须** body 给 `{}` 且带
//!      `Content-Type: application/json` —— 裸 POST（无体）会 500 `OfficeAce.11020001`。
//!   2. `x-subscription-type: v2` 是 `/v1/subscription` 与 bonus/claim 的必要头
//!      （usage / rates 不带）；它进签名头集合。
//!   3. 一天一个活动只领一次，**重复领不报错**（返回同一份列表）—— 幂等由上游保证。
//!
//! ── 上游的数值字段是字符串 ──────────────────────────────────
//! 实测样例：`"sku_value": "500"`、`"points": "4000"`、`"current_value":
//! "0.6682022857142857"`。所有数值都走 [`util::num`]，直接 `as_f64()` 会把余额
//! 与奖励全算成 0。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credentials::OfficeAceCredential;
use super::signer::Algorithm;
use super::{upstream, util};

/// 控制面订阅族的通行头（官方 `checkPermission` / `subscriptionClaw` 都带）。
pub const SUBSCRIPTION_TYPE_HEADER: (&str, &str) = ("x-subscription-type", "v2");

/// 账号里存的 `https://{host}/v2` → 网关根 `https://{host}`。
pub fn gateway_base(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    let without_version = trimmed.strip_suffix("/v2").unwrap_or(trimmed);
    without_version.trim_end_matches('/').to_string()
}

/// 调一次 V11 签名的订阅族接口，返回解析后的响应体。
fn call(
    credential: &OfficeAceCredential,
    method: &str,
    path: &str,
    body: Option<Value>,
    extra_headers: &[(&str, &str)],
) -> Result<Value> {
    if !credential.has_control_plane() {
        return Err(usage_not_configured());
    }
    let base = gateway_base(&credential.base_url);
    if base.is_empty() {
        return Err(Error::http(400, "OfficeAce 账号缺少模型网关基址"));
    }
    let url = format!("{base}{path}");
    upstream::call(credential, method, &url, Algorithm::V11, body, extra_headers)
}

/// 「该账号没有配置余额查询凭证」的统一形态：400 + `usage_not_configured`。
///
/// ── 为什么码必须逐字相同 ────────────────────────────────────
/// 前端按 `code`（不是文案）判定「这是未配置、不是失败」，并把它渲染成中性提示。
/// 码换一个，用户就会看到一个红色的「查询失败」，而实际只是「去补一次登录」。
pub fn usage_not_configured() -> Error {
    Error::http(
        400,
        format!(
            "该账号没有余额查询凭证（OfficeAce 果办 的 控制面临时凭据（AK/SK）），\
             请在账号设置里配置后再查询"
        ),
    )
    .with_code("usage_not_configured")
}

/// 读订阅快照（套餐 + 积分账本 + 奖励活动）。
pub fn fetch_subscription(credential: &OfficeAceCredential) -> Result<Value> {
    call(credential, "GET", "/v1/subscription", None, &[SUBSCRIPTION_TYPE_HEADER])
}

/// 每模型使用倍率：`GET /v1/model-token-rates`（控制面，要 V11 签名）。
///
/// 响应是 `{models: [{model_name, cost_coefficient, prompt_tokens_per_point, …}]}`，
/// `cost_coefficient` 就是官方客户端里那颗 `0.30x`。
pub fn fetch_model_token_rates(credential: &OfficeAceCredential) -> Result<Value> {
    call(credential, "GET", "/v1/model-token-rates", None, &[])
}

/// 领奖励积分：`POST /v1/subscription/bonus/claim`（body `{}`，幂等）。
///
/// 返回本次**新发放**的奖励；完整账本仍需读取订阅快照。
pub fn claim_bonus(credential: &OfficeAceCredential) -> Result<Value> {
    call(
        credential,
        "POST",
        "/v1/subscription/bonus/claim",
        Some(json!({})),
        &[SUBSCRIPTION_TYPE_HEADER],
    )
}

// ── 奖励活动 ─────────────────────────────────────────────────

/// 一个奖励活动的归一形态（从 `bonus_skus` 的条目解出）。
pub struct Bonus {
    pub activity_id: String,
    pub name: String,
    pub total: f64,
    pub used: f64,
    pub expires_at: i64,
}

impl Bonus {
    pub fn remaining(&self) -> f64 {
        (self.total - self.used).max(0.0)
    }
}

fn bonus_of(item: &Value) -> Option<Bonus> {
    let text = |field: &str| util::text_of(item, field);
    // 键的兜底：实测**奖励条目可能没有 `activity_id`**（样例只有 `activity_name`）——
    // 只认 `activity_id` 会把这些条目整条丢掉（表现为「没有任务」）。
    let key = text("activity_id")
        .or_else(|| text("cbc_resource_id"))
        .or_else(|| text("activity_name"))?;
    Some(Bonus {
        name: text("activity_name").unwrap_or_else(|| key.clone()),
        total: util::num(item.get("points")),
        used: util::num(item.get("current_value")),
        expires_at: parse_ms(item.get("expired_time")),
        activity_id: key,
    })
}

/// 从 `bonus_skus` 数组解出奖励活动。
pub fn bonuses_of(subscription: &Value) -> Vec<Bonus> {
    subscription
        .get("bonus_skus")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(bonus_of).collect())
        .unwrap_or_default()
}

/// 把「过期时刻」解成毫秒时间戳：上游给 RFC3339 串或数字。
fn parse_ms(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(0),
        Some(Value::String(text)) => util::parse_rfc3339_ms(text).unwrap_or(0),
        _ => 0,
    }
}

// ── 倍率 ─────────────────────────────────────────────────────

/// 解析 `{models: [{model_name, cost_coefficient, …}]}`。
///
/// `cost_coefficient` 两种形态都收（JSON 数字与 `"0.30"` 字符串）：上游这条链里
/// 「数值其实是字符串」是**已经踩过一次**的形态（订阅/额度那批字段就是字符串），
/// 而倍率解不出来只会静默少一列，不会报错。
/// 没有 `model_name`、数解不出来或**负数**的条目丢掉 —— 负数不是倍率，是脏数据。
pub fn parse_rates(payload: &Value) -> Vec<(String, f64)> {
    let rows = payload.get("models").and_then(Value::as_array);
    let mut out: Vec<(String, f64)> = Vec::new();
    for row in rows.into_iter().flatten() {
        let Some(name) = row.get("model_name").and_then(Value::as_str) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value = match row.get("cost_coefficient") {
            Some(Value::Number(number)) => number.as_f64(),
            Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
            _ => None,
        };
        let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) else {
            continue;
        };
        out.push((name.to_lowercase(), value));
    }
    out
}

/// 倍率数字 → 界面文本（`x0.7 credits`）：整数不带小数点，其余最多两位并裁尾零。
///
/// 两位是必要的 —— 实测读数里有 `0.25` 这种，一位会显示成 `0.3`。
pub fn credits_text(rate: f64) -> String {
    let rounded = (rate * 100.0).round() / 100.0;
    let plain = if (rounded - rounded.trunc()).abs() < 1e-9 {
        format!("{}", rounded.trunc() as i64)
    } else {
        format!("{rounded:.2}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    };
    format!("x{plain} credits")
}

/// 把倍率并进目录条目：写 `credits` 文本（界面那一列读它，与别家同一键同名同格式）。
///
/// ── 只按**精确 id** 匹配，不做前缀借用 ──────────────────────
/// 参考实现的面板 `rateFor()` 允许「表里没有这个 id 就蹭同名前缀」，它自己都警告
/// 这样出来的数是「看起来合理但是错的」（`glm-5.3` 蹭到 `glm-5` 的倍率）。倍率是
/// 给人决定用哪个模型的依据，**错一个数量级比空着坏得多** —— 所以这里宁可留 `—`。
/// 大小写不敏感（目录 id 与倍率表的命名偶有大小写差），分隔符不参与匹配。
pub fn attach_rates(models: Vec<Value>, rates: &[(String, f64)]) -> Vec<Value> {
    if rates.is_empty() {
        return models;
    }
    models
        .into_iter()
        .map(|mut model| {
            let id = model
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if let Some((_, value)) = rates.iter().find(|(name, _)| *name == id) {
                if let Some(object) = model.as_object_mut() {
                    object.insert("credits".to_string(), Value::String(credits_text(*value)));
                }
            }
            model
        })
        .collect()
}

// ── 归一成额度报告 ───────────────────────────────────────────

/// 积分数值取整（**向下**）—— 口径说明见 [`summarize`]；负值 / 非有限值一律 0。
fn whole_points(value: f64) -> f64 {
    if !value.is_finite() || value <= 0.0 {
        0.0
    } else {
        value.floor()
    }
}

/// 一行明细 → `(排序键, 名字, 行)`。
///
/// ── 谁缺谁不写，一个 `null` 都不许出去 ──────────────────────
/// 三个数（`total` / `used` / `remain`）与 `expireAt` 都收 `Option`，`None` 直接
/// 不出键：界面那道 `Number(null) === 0` 的闸就在这一层之后，写 0 或者写 `null`
/// 都会被画成「剩 0 / 共 0」这种看起来像读到了的假读数。
///
/// `unit` 只在与文档级单位（本文件的「积分」）不同的行上才有值 —— 这里只有联网
/// 搜索那一行（按**次**计），同单位的行不必每行再标一遍。
///
/// `expire_ms` 兼职排序键：**最近到期的排前面**（明细第一个要回答的问题是
/// 「哪笔先作废」），没给到期时刻的排最后（`i64::MAX`），同一时刻按名字比
/// （否则每次刷新行序都在跳，看起来像数据在变）。
fn credit_row(
    name: &str,
    total: Option<f64>,
    used: Option<f64>,
    remain: Option<f64>,
    unit: Option<&str>,
    expire_ms: i64,
) -> (i64, String, Value) {
    let name = name.trim();
    let mut row = serde_json::Map::new();
    row.insert("name".to_string(), Value::String(name.to_string()));
    for (key, value) in [("total", total), ("used", used), ("remain", remain)] {
        if let Some(value) = value.filter(|value| value.is_finite()) {
            row.insert(key.to_string(), json!(value));
        }
    }
    if let Some(unit) = unit {
        row.insert("unit".to_string(), Value::String(unit.to_string()));
    }
    if expire_ms > 0 {
        row.insert("expireAt".to_string(), json!(expire_ms));
    }
    (
        if expire_ms > 0 { expire_ms } else { i64::MAX },
        name.to_string(),
        Value::Object(row),
    )
}

/// 把 `/v1/subscription` 归一成 `usage.query` 的形状。
///
/// 只算**未过期**的额度（过期条目不计入，与参考实现的 `summarizeSubscription` 一致）；
/// `available` = 套餐剩余 + 奖励剩余。
///
/// ── 为什么剩余量要取整（2026-10-13，用户报「可用 6499.331797714286 积分」）──
/// 上游的 `current_value` 是**带小数的字符串**（实测 `"0.6682022857142857"`：
/// 模型调用的消耗按比例折算成积分的零头），相减之后剩余量就拖着一长串小数。
/// 而积分本身是整数概念（套餐 500、奖励按千发放），余额列又只有几十像素宽 ——
/// 6499.331797714286 既挤又读不出信息。口径取**向下取整**：积分的用途是
/// 「还能用多少」的判断依据，宁可少报不到 1 分的零头，也不虚报。
pub fn summarize(subscription: &Value) -> Value {
    summarize_at(subscription, util::now_ms())
}

/// 同 [`summarize`]，但「现在」由调用方给。
///
/// 分出这一层是为了可测：`sdk::now()` 在宿主之外恒为 0（`clock.now` 是宿主调用），
/// 拿它判「过期 / 未过期」会让单测永远走同一个分支，等于没测。
pub fn summarize_at(subscription: &Value, now: i64) -> Value {
    let mut plan_total = 0.0;
    let mut plan_used = 0.0;
    let mut plan_name = String::new();
    let mut plan_expire = 0i64;
    let mut search_total = 0.0;
    let mut search_used = 0.0;
    // 逐份明细（`credits[]`，账号页「积分明细」弹层的输入）的行在这里顺手收齐：
    // 排序键 + 名字 + 行，读的是同一个循环里的同一份 quotas —— 第二遍遍历只会让
    // 两处口径有机会分叉。循环里被 `continue` 排掉的过期配额不进明细：聚合读数
    // （`available` 与套餐钱包）本来就不计它们，弹层要回答的是「现在还能花什么」。
    let mut rows: Vec<(i64, String, Value)> = Vec::new();
    for sku in subscription
        .get("skus")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for quota in sku.get("quotas").and_then(Value::as_array).into_iter().flatten() {
            let expired = parse_ms(quota.get("expired_time"));
            if expired > 0 && expired <= now {
                continue;
            }
            match quota.get("sku_attr_code").and_then(Value::as_str) {
                Some("officeace_points") => {
                    plan_total += util::num(quota.get("sku_value"));
                    plan_used += util::num(quota.get("current_value"));
                    // 聚合之外逐条再出明细行（聚合是读数，明细是账本：一份配额一行）——
                    // 明细这条线走 num_opt，「上游没给」与「真的 0」不混
                    let total = util::num_opt(quota.get("sku_value"));
                    let used = util::num_opt(quota.get("current_value"));
                    // 剩余是减出来的：两个基数缺一个就**不写这个键**（拿 0 顶上等于
                    // 替上游宣布「没用过 / 没发过」）
                    let remain = total.zip(used).map(|(total, used)| whole_points(total - used));
                    // 配额自己没有名字，挂所属 sku 的；上游连 sku 名字都没给时写
                    // 「套餐积分」—— 界面的兜底名「积分包」分不出这是套餐还是活动发的
                    let sku_name = sku.get("sku_name").and_then(Value::as_str).unwrap_or("").trim();
                    let name = if sku_name.is_empty() { "套餐积分" } else { sku_name };
                    rows.push(credit_row(name, total, used, remain, None, expired));
                }
                Some("online_search_count") => {
                    search_total += util::num(quota.get("sku_value"));
                    search_used += util::num(quota.get("current_value"));
                }
                _ => {}
            }
        }
        if plan_name.is_empty() {
            plan_name = sku
                .get("sku_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        let expire = parse_ms(sku.get("expired_time"));
        if expire > 0 && (plan_expire == 0 || expire < plan_expire) {
            plan_expire = expire;
        }
    }
    let bonuses = bonuses_of(subscription);
    let bonus_total: f64 = bonuses
        .iter()
        .filter(|bonus| bonus.expires_at == 0 || bonus.expires_at > now)
        .map(|bonus| bonus.total)
        .sum();
    let bonus_used: f64 = bonuses
        .iter()
        .filter(|bonus| bonus.expires_at == 0 || bonus.expires_at > now)
        .map(|bonus| bonus.used)
        .sum();
    // 剩余量一律向下取整（口径见函数文档）：余额列 / 明细弹层读的都是这三处，
    // 取整后「可用 = 套餐 + 奖励」的加法仍自洽（三处同口径）
    let plan_remaining = whole_points(plan_total - plan_used);
    let bonus_remaining = whole_points(bonus_total - bonus_used);
    let available = plan_remaining + bonus_remaining;
    let status = subscription
        .get("subscribe_status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // 联网搜索聚合成一行：上游按 sku 把它们拆成多条，逐条摆出来只是同一件事的
    // 碎片。单位是「次」、与文档的「积分」不同，这一行才写 `unit`；上游没给搜索
    // 额度的到期时刻，`expireAt` 整个不写。
    // 非有限值不出发：`json!` 会把它写成 `null`，那与「没读到」在界面上同义。
    if search_total > 0.0 && search_total.is_finite() {
        rows.push(credit_row(
            "联网搜索",
            Some(search_total),
            Some(search_used),
            Some(whole_points(search_total - search_used)),
            Some("次"),
            0,
        ));
    }
    // 奖励活动**全部条目都出，含已过期的**：聚合读数只算未过期的（`available` /
    // 奖励钱包），明细要能回答「哪笔作废了」—— 界面对已过期的另有折叠分组，
    // 这个差异是刻意的。三个数走 `Bonus` 的既有口径（缺失折 0，与奖励钱包同源），
    // `remain` 与 `Bonus::remaining` 同式再套全文件的向下取整。
    for bonus in &bonuses {
        rows.push(credit_row(
            &bonus.name,
            Some(bonus.total),
            Some(bonus.used),
            Some(whole_points(bonus.remaining())),
            None,
            bonus.expires_at,
        ));
    }
    let mut document = json!({
        "available": available,
        "unit": "积分",
        "wallets": [
            { "type": "plan", "displayName": plan_name_or_default(&plan_name), "balance": plan_remaining },
            { "type": "bonus", "displayName": "奖励积分", "balance": bonus_remaining },
        ],
        "subscription": {
            "planName": plan_name_or_default(&plan_name),
            "status": status,
            "expireAt": plan_expire,
            "remainQuota": plan_remaining,
            "totalQuota": plan_total,
            "searches": if search_total > 0.0 {
                json!({ "remaining": whole_points(search_total - search_used), "total": search_total })
            } else {
                Value::Null
            },
        },
        "raw": subscription,
    });
    // 明细只在有行时挂（键在不在 + 长度就是界面的入口开关）：一条可写的行都没有的
    // 账户挂个空数组，只会多出一个点开什么都没有的入口
    if !rows.is_empty() {
        rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        if let Some(object) = document.as_object_mut() {
            object.insert(
                "credits".to_string(),
                Value::Array(rows.into_iter().map(|(_, _, row)| row).collect()),
            );
        }
    }
    document
}

fn plan_name_or_default(name: &str) -> String {
    if name.is_empty() {
        "OfficeAce 果办".to_string()
    } else {
        name.to_string()
    }
}

/// 额度来源清单（`admin.action = quota.sources` 的返回）。
///
/// 与 native `quota::sources` 的 `credits()` 分支逐条同形：一个明细行一条来源，
/// 逐行的 `id` / `planId` 用 `credit:<名字>:<授予时刻>:<到期时刻>` 的合成键，
/// `endsAt` 给到期时刻（0 = 上游没给）。
pub fn quota_sources(report: &Value) -> Vec<Value> {
    let unit = report.get("unit").and_then(Value::as_str).unwrap_or("");
    let mut sources = Vec::new();
    for row in report.get("credits").and_then(Value::as_array).into_iter().flatten() {
        if row.get("record").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let name = row.get("name").and_then(Value::as_str).unwrap_or("");
        let remaining = util::num_opt(row.get("remain"));
        let total = util::num_opt(row.get("total"));
        let used = util::num_opt(row.get("used"));
        if remaining.is_none() && total.is_none() && used.is_none() {
            continue;
        }
        let row_unit = match row.get("unit").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => text,
            _ => unit,
        };
        let id = format!(
            "credit:{name}:{}:{}",
            row.get("grantAt").unwrap_or(&Value::Null),
            row.get("expireAt").unwrap_or(&Value::Null)
        );
        sources.push(json!({
            "id": id,
            "label": name,
            "provider": super::credentials::ID,
            "unit": row_unit,
            "remaining": remaining,
            "total": total,
            "used": used,
            "unlimited": row.get("unlimited").cloned().unwrap_or(json!(false)),
            "startsAt": util::num_opt(row.get("startAt")).unwrap_or(0.0) as i64,
            "endsAt": util::num_opt(row.get("expireAt")).unwrap_or(0.0) as i64,
            "planId": id,
            "planName": name,
        }));
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_base_strips_the_version_segment() {
        assert_eq!(gateway_base("https://h/v2"), "https://h");
        assert_eq!(gateway_base("https://h/v2/"), "https://h");
        assert_eq!(gateway_base("https://h"), "https://h");
        assert_eq!(gateway_base("  https://h/v2  "), "https://h");
    }

    #[test]
    fn rates_accept_numbers_and_strings_and_drop_junk() {
        let payload = json!({ "models": [
            { "model_name": "GLM-5", "cost_coefficient": 0.3 },
            { "model_name": "DeepSeek-V4-Flash", "cost_coefficient": "0.25" },
            { "model_name": "bad", "cost_coefficient": -1 },
            { "cost_coefficient": 1 },
        ] });
        let rates = parse_rates(&payload);
        assert_eq!(rates.len(), 2);
        assert_eq!(rates[0], ("glm-5".to_string(), 0.3));
        assert_eq!(rates[1].1, 0.25);
    }

    #[test]
    fn credits_text_keeps_two_decimals_when_needed() {
        assert_eq!(credits_text(1.0), "x1 credits");
        assert_eq!(credits_text(0.25), "x0.25 credits");
        assert_eq!(credits_text(0.7), "x0.7 credits");
        assert_eq!(credits_text(0.666), "x0.67 credits");
    }

    #[test]
    fn summarize_counts_only_unexpired_quotas() {
        // 固定时钟：2026-10-10T05:15:00Z 之后一秒
        let now = 1_791_609_301_000i64;
        let subscription = json!({
            "subscribe_status": "SUBSCRIBED",
            "skus": [{
                "sku_name": "个人体验套餐",
                "expired_time": now + 86_400_000,
                "quotas": [
                    { "sku_attr_code": "officeace_points", "sku_value": "500", "current_value": "0.668" },
                    { "sku_attr_code": "officeace_points", "sku_value": "999", "current_value": "0", "expired_time": now - 1000 },
                    { "sku_attr_code": "online_search_count", "sku_value": "100", "current_value": "10" },
                ],
            }],
            "bonus_skus": [
                { "activity_id": "a1", "activity_name": "新人礼", "points": "4000", "current_value": "0" },
                { "activity_id": "a2", "activity_name": "过期礼", "points": "100", "current_value": "0",
                  "expired_time": "2020-01-01T00:00:00Z" },
            ],
        });
        let report = summarize_at(&subscription, now);
        // 套餐 500 - 0.668 = 499.332 → 向下取整 499；奖励只算未过期的 4000
        assert_eq!(report["available"], json!(4499.0));
        assert_eq!(report["subscription"]["searches"]["remaining"], json!(90.0));
        let rows = report["credits"].as_array().cloned().unwrap_or_default();
        // 套餐一行 + 联网搜索一行 + 两条奖励（含已过期的那条）
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().any(|row| row["unit"] == json!("次")));
        // 过期的那份配额不进明细（循环里就 continue 掉了）
        assert!(!rows.iter().any(|row| row["total"] == json!(999.0)));
    }

    #[test]
    fn quota_sources_skip_rows_without_numbers() {
        let report = json!({ "unit": "积分", "credits": [
            { "name": "套餐积分", "remain": 499, "total": 500, "used": 0.668 },
            { "name": "空行" },
        ] });
        let sources = quota_sources(&report);
        assert_eq!(sources.len(), 1, "没有数值的行不进额度来源");
        assert_eq!(sources[0]["provider"], json!("officeace"));
        assert_eq!(sources[0]["unit"], json!("积分"));
    }
}
