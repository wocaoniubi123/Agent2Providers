//! 余额 / 额度读数（native `zcode/balance.rs` + `zcode/monitor.rs` 的移植，
//! 保留**候选令牌链**与三处官方语义，删掉纯展示的排版代码）。
//!
//! ── 候选令牌链：两个通道，谁先有读数用谁 ────────────────────
//! 账号记录里有**两把互不替代的凭证**，各自能打开一个读数通道：
//!
//! | 凭证 | 通道 | 读到的 |
//! |---|---|---|
//! | `jwt`（套餐 JWT） | `{zcode}/api/v1/zcode-plan/billing/balance` | 余额桶 / 套餐 / 到期 |
//! | `accessToken`（编码套餐 API Key） | `{监控平面}/api/monitor/usage/quota/limit` | 窗口限额（每 N 小时 / 每周的已用比例）与套餐等级 |
//!
//! 顺序：
//!   1. 有 `jwt` → 走 billing（存量账号的行为逐字不变）；
//!   2. 上面没读数（缺 jwt，或 jwt 通道失败）→ 有 `accessToken` 就走监控通道；
//!   3. 两条都不行 → 「未配置」（一把凭证都没有）或错误（有凭证但都被拒）。
//!
//! 失败时**不合并两个通道的错误**：401 优先透出（它最可执行 ——「请重新登录」），
//! 否则取第一个错误。合并会让用户拿到一句看不出该做什么的话。
//!
//! ── billing 通道的三处官方语义（逐条移植，别当优化去掉）──────
//!   1. 套餐状态**按时间判**（`ends_at` 已过 → `expired`；生效时间还没到 →
//!      `pending`），`status` 只当兜底 —— 上游偶尔不刷状态，照直读会让过期套餐
//!      一直显示在身边；反过来只认 `status` 又会让**刚领到、还没到生效时间**的
//!      活动套餐整条消失；
//!   2. 现在还不能用的套餐（已过期 / 权益**全都**还没到生效时间）名下的余额桶
//!      **整条丢掉**（`user_plan_id` 优先、退回 `plan_id` 配对）—— 否则
//!      「昨天领的 1 亿」会永远挂在那里，而「今天 23:00 才生效的 1 亿」会提前
//!      顶替可用额度；
//!   3. 认不出归属的桶**保留**（宁可在读数里多一行，也不误删另一个有效套餐的余额）。
//!
//! ── 与 native 的删减（本文件是**读数**，不是排版）────────────
//! `balance.rs` 里 `with_credits` / `compact_number` 那几段是给账号页画逐桶
//! 明细用的展示层（额度桶的一行文案、千分位、截断）。这里保留字段
//! （`balance` / `total` / `used` / `remainingPercent` / `displayName`），
//! 文案由界面按同一批字段自己渲染 —— 插件不该替界面决定「1.0 亿」怎么缩写。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{beijing_mmdd_hhmm, integer_of, number_of, now_ms, text_of};
use super::{account, http, plan, region};

/// 余额路径（官方客户端 `zcodePlanBillingBalanceUrl` 的后半段）
const BALANCE_PATH: &str = "/api/v1/zcode-plan/billing/balance";

/// 监控端点路径（第三方实现逐字一致）
const QUOTA_PATH: &str = "/api/monitor/usage/quota/limit";

/// 取比例上限用（上游个别窗口会给 >100，钳住免得进度条越界）
const PERCENT_MAX: f64 = 100.0;

/// 查询某账号的余额（`usage.query`）。
pub fn query() -> Result<Value> {
    let record = account::require_account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    let jwt = account::jwt(&secret);
    let coding_key = account::access_token(&secret);
    let mut errors: Vec<Error> = Vec::new();
    if !jwt.is_empty() {
        let device_mid = {
            let existing = account::device_mid(&secret);
            if existing.is_empty() {
                account::device_mid_or_create()?.unwrap_or_default()
            } else {
                existing
            }
        };
        let mid = (!device_mid.trim().is_empty()).then_some(device_mid.as_str());
        match billing_channel(&jwt, mid) {
            Ok(value) => {
                // ── 「有套餐、但一个额度桶都没有」时补一条监控通道的窗口读数 ──
                // 活动套餐的额度不落在 billing 的桶里：实测一份「生效中、3 亿
                // token」的套餐 `balances` 是空的 —— 界面上只剩一个干读数，
                // **连进度条都画不出来**。开放平台的监控通道对同一把账号回的是
                // 窗口限额与剩余比例，那正是画条要的东西。
                //
                // 只在 billing 一个桶都没读到时合并：有桶就说明 billing 那侧是
                // 权威读数，硬塞一份窗口只会让两套口径混在同一列里。
                if !has_wallets(&value) && !coding_key.is_empty() {
                    if let Ok(windows) = monitor_channel(&coding_key) {
                        if has_wallets(&windows) {
                            return Ok(merge_monitor_windows(value, windows));
                        }
                    }
                }
                return Ok(value);
            }
            Err(error) => errors.push(error),
        }
    }
    if !coding_key.is_empty() {
        match monitor_channel(&coding_key) {
            Ok(value) => return Ok(value),
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        // 两把凭证都没有：用可识别的「未配置」而不是失败 —— 用户去账号设置里
        // 补上任意一把就能查（两把各能读一条通道，见上表）
        return Err(Error::coded(
            "ZCode 账号未配置可查询的凭证（套餐池 JWT 或编码套餐 API Key）",
            "usage_not_configured",
        ));
    }
    // 401 优先（「请重新登录」是用户能照着做的那一句），否则第一个错误
    let has_401 = errors.iter().any(|error| error.status == Some(401));
    let mut chosen = if has_401 {
        errors
            .into_iter()
            .find(|error| error.status == Some(401))
            .unwrap_or_else(|| Error::new("ZCode 余额查询失败"))
    } else {
        errors.remove(0)
    };
    // 缺凭证与「被拒」是两件事：这里已经有凭证了，把状态码补成可执行的那一档
    if chosen.status.is_none() {
        chosen.status = Some(502);
    }
    Err(chosen)
}

/// billing 通道：`GET {zcode}/api/v1/zcode-plan/billing/balance`（认套餐 JWT）。
pub fn billing_channel(jwt: &str, device_mid: Option<&str>) -> Result<Value> {
    let url = format!(
        "{}{BALANCE_PATH}?{}",
        region::ZCODE_ORIGIN,
        plan::version_query()
    );
    // 头集合：三个，一个不多（其余客户端身份头对这台网关无效）。
    // 设备标识没有值时**不发空头**：空头与缺失同效（都是 3001），
    // 但日志里能少一条误导性的记录。
    let mut headers: Vec<(String, String)> = vec![
        ("Authorization".to_string(), format!("Bearer {}", jwt.trim())),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    if let Some(mid) = device_mid.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    let reply = http::send("GET", &url, &headers, None)
        .map_err(|error| http::transport_error("ZCode 余额查询失败", &error))?;
    let code = plan::biz_code(&reply.payload);
    let message = text_of(&reply.payload, &["msg", "message"]);
    // 401：JWT 被拒（失效 / 吊销 / 换了账号）。原样透出 401，让调用方走它既有的
    // 「刷新后重试一次」处置 —— 本家没有续期协议，那条路最终会报一句可读的话。
    if reply.status == 401 || code == Some(401) {
        return Err(Error::http(401, "ZCode 套餐令牌已失效，请重新登录该账号"));
    }
    // 3001 = 参数错误：这台网关只有一种常见成因 —— 设备标识缺失或不是 UUID
    if code == Some(3001) {
        return Err(Error::http(
            502,
            "ZCode 余额查询被上游以「参数错误」拒绝（常见成因：设备标识无效），请重新登录该账号",
        ));
    }
    // 429 = 风控限速。响应体常常是空的，所以这一档要判在「取 message」的兜底之前。
    if reply.status == 429 {
        return Err(Error::http(
            502,
            "ZCode 余额查询被上游限流（429），请稍后重试或改为逐个查询",
        ));
    }
    if !(200..300).contains(&reply.status)
        || code != Some(0)
        || reply.payload.get("success").and_then(Value::as_bool) == Some(false)
    {
        let detail = if message.is_empty() {
            format!("HTTP {}", reply.status)
        } else {
            message
        };
        let label = code
            .filter(|code| *code != 0)
            .map(|code| format!("（{code}）"))
            .unwrap_or_default();
        return Err(Error::http(
            502,
            format!("ZCode 余额查询失败{label}：{detail}"),
        ));
    }
    let data = reply
        .payload
        .get("data")
        .filter(|data| data.is_object())
        .ok_or_else(|| Error::http(502, "ZCode 余额查询：上游未返回有效的套餐数据"))?;
    if data
        .get("plans")
        .is_some_and(|plans| !plans.is_null() && !plans.is_array())
    {
        return Err(Error::http(502, "ZCode 余额查询：上游套餐列表格式异常"));
    }
    Ok(normalize_billing(data))
}

/// 监控通道：`GET {monitor}/api/monitor/usage/quota/limit`（认编码套餐 API Key）。
///
/// ── `Authorization` 形态为什么不猜 ───────────────────────────
/// 第三方实现分成两派：多数写「裸令牌、不带 Bearer」（且都打国内站），另一些
/// 发 Bearer。与其猜一个，不如让上游用 401/403 告诉我们：先发**与转发同一形态**
/// 的 Bearer（那是我们确定能用的），被拒就换裸令牌再试一次 —— 只有鉴权失败才
/// 换形态，业务错误（没有套餐等）一次即返。
pub fn monitor_channel(token: &str) -> Result<Value> {
    let token = token.trim();
    if token.is_empty() {
        return Err(Error::http(
            401,
            "ZCode 账号缺少编码套餐 API Key，请重新登录或补填凭证",
        ));
    }
    let base = region::monitor_base_url();
    let url = format!("{base}{QUOTA_PATH}");
    let source = format!("{}/api/monitor", base.trim_start_matches("https://"));
    let forms: [(&str, String); 2] = [
        ("Bearer", format!("Bearer {token}")),
        ("Raw", token.to_string()),
    ];
    let mut auth_error: Option<Error> = None;
    for (index, (_, value)) in forms.iter().enumerate() {
        let headers = vec![("Authorization".to_string(), value.clone())];
        let reply = http::send("GET", &url, &headers, None)
            .map_err(|error| http::transport_error("ZCode 窗口限额查询失败", &error))?;
        if matches!(reply.status, 401 | 403) {
            auth_error = Some(Error::http(
                401,
                "ZCode 编码套餐 API Key 被上游拒绝（已失效，或不是这一地的密钥），\
                 请重新登录或更换凭证",
            ));
            if index + 1 < forms.len() {
                continue;
            }
            break;
        }
        return unpack_monitor(&source, reply.status, &reply.payload);
    }
    Err(auth_error.unwrap_or_else(|| {
        Error::http(401, "ZCode 窗口限额查询被上游拒绝")
    }))
}

/// 监控通道的信封解包：`{code, msg, data}`。
///
/// `code` 缺失视为成功（有的网关在成功时干脆不回这个键），非 0 才是失败。
fn unpack_monitor(source: &str, status: u16, payload: &Value) -> Result<Value> {
    let code = payload.get("code").and_then(integer_of).unwrap_or(0);
    if code == 401 {
        return Err(Error::http(
            401,
            "ZCode 编码套餐 API Key 已失效，请重新登录该账号",
        ));
    }
    if !(200..300).contains(&status) || code != 0 {
        let detail = {
            let text = text_of(payload, &["msg", "message"]);
            if text.is_empty() {
                format!("HTTP {status}")
            } else {
                text
            }
        };
        // 业务码为 0 表示「响应体里没有 code」（HTTP 层错误）—— 别拼一个莫名其妙的「（0）」
        let label = if code == 0 {
            String::new()
        } else {
            format!("（{code}）")
        };
        return Err(Error::http(
            502,
            format!("ZCode 窗口限额查询失败{label}：{detail}"),
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    Ok(normalize_monitor(source, &data))
}

/// 有没有可显示的额度桶。
fn has_wallets(value: &Value) -> bool {
    value
        .get("wallets")
        .and_then(Value::as_array)
        .is_some_and(|wallets| !wallets.is_empty())
}

// ─── billing 通道的归一化 ────────────────────────────────────

/// 套餐三态（按时间判，`status` 只当兜底；见模块头第 1 条）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum PlanState {
    Active,
    Pending,
    Expired,
}

/// 上游 `data` → 账号页的统一形状。
fn normalize_billing(data: &Value) -> Value {
    // 用**上游自己的时间**判「过没过期」：拿本机时间会在时区 / 时钟不准的机器上误判
    let now = data
        .get("server_time")
        .and_then(number_of)
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or_else(|| (now_ms() as f64) / 1000.0);
    let plans: Vec<&Value> = data
        .get("plans")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();
    // 每个套餐的：id / 状态 / 是否「当前可用」
    let mut plan_rows: Vec<Value> = Vec::new();
    let mut unusable: Vec<String> = Vec::new();
    for plan in &plans {
        let plan_id = text_of(plan, &["user_plan_id", "userPlanId", "plan_id", "planId"]);
        let state = plan_state(plan, now);
        let pending_until = pending_until(plan, now);
        let entitlements = entitlements_of(plan);
        let active = state == PlanState::Active;
        if !active {
            if !plan_id.is_empty() {
                unusable.push(plan_id.clone());
            }
        }
        plan_rows.push(json!({
            "planId": plan_id,
            "name": plan_display_name(plan),
            "state": match state {
                PlanState::Active => "active",
                PlanState::Pending => "pending",
                PlanState::Expired => "expired",
            },
            "startsAt": plan_bound(plan, &START_KEYS),
            "endsAt": plan_bound(plan, &END_KEYS),
            "pendingUntil": pending_until,
            "entitlements": entitlements,
        }));
    }
    // 桶：认得出归属且那个套餐不可用的整条丢掉；认不出归属的**保留**（模块头第 3 条）
    let unit_type = data
        .get("balances")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .map(|item| text_of(item, &["unit_type", "unitType"]))
        .unwrap_or_default();
    let mut wallets: Vec<Value> = Vec::new();
    let mut available_total: Option<f64> = None;
    let mut any_missing = false;
    let balances = data
        .get("balances")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    for bucket in balances {
        let owner = text_of(bucket, &["user_plan_id", "userPlanId", "plan_id", "planId"]);
        if !owner.is_empty() && unusable.iter().any(|id| id == &owner) {
            continue;
        }
        let total = bucket.get("total_units").and_then(number_of);
        let used = bucket.get("used_units").and_then(number_of);
        let reserved = bucket.get("reserved_units").and_then(number_of).unwrap_or(0.0);
        let remaining = bucket
            .get("remaining_units")
            .and_then(number_of)
            .or_else(|| bucket.get("available_units").and_then(number_of))
            .or_else(|| match (total, used) {
                (Some(total), Some(used)) => Some(total - used - reserved),
                _ => None,
            });
        match remaining {
            Some(value) => {
                available_total = Some(available_total.unwrap_or(0.0) + value.max(0.0));
            }
            None => any_missing = true,
        }
        let remaining_percent = match (remaining, total) {
            (Some(remaining), Some(total)) if total > 0.0 => {
                Some((remaining / total * PERCENT_MAX).clamp(0.0, PERCENT_MAX))
            }
            _ => None,
        };
        let show_name = text_of(bucket, &["show_name", "showName", "entitlement_id", "name"]);
        wallets.push(json!({
            "type": "zcode_bucket",
            "displayName": if show_name.is_empty() { "额度".to_string() } else { show_name },
            "planName": text_of(bucket, &["user_plan_id", "userPlanId", "plan_id", "planId"]),
            "balance": remaining,
            "total": total,
            "used": used,
            "remainingPercent": remaining_percent,
            "unit": text_of(bucket, &["unit_type", "unitType"]),
        }));
    }
    // 代表套餐：优先「生效中最晚结束」的那个
    let representative = plan_rows
        .iter()
        .filter(|row| row.get("state").and_then(Value::as_str) == Some("active"))
        .max_by_key(|row| row.get("endsAt").and_then(integer_of).unwrap_or(0));
    let mut subscription = serde_json::Map::new();
    if let Some(row) = representative {
        if let Some(name) = row.get("name").and_then(Value::as_str).filter(|name| !name.is_empty()) {
            subscription.insert("planName".to_string(), Value::String(name.to_string()));
        }
        if let Some(ends_at) = row.get("endsAt").and_then(integer_of) {
            // 账号页的到期列是**毫秒**（与各家同口径），而 billing 给的是秒
            subscription.insert("expireAt".to_string(), Value::from(ends_at.saturating_mul(1000)));
        }
        subscription.insert("status".to_string(), Value::String("active".to_string()));
    } else if !plan_rows.is_empty() {
        subscription.insert("status".to_string(), Value::String("inactive".to_string()));
    }
    let available_view = match available_total {
        Some(value) => format!("剩 {}", compact_number(value)),
        None if wallets.is_empty() => "无额度".to_string(),
        None => "已读取".to_string(),
    };
    let mut result = json!({
        "availableView": available_view,
        "unit": unit_type,
        "wallets": wallets,
        "plans": plan_rows,
        "subscription": subscription,
        "raw": data,
        "source": "billing",
    });
    // `available` 只在**所有**桶都读出了剩余量时给（有缺失就是「不知道」，
    // 写 0 会让「余额不足就跳过」那一档把账号剔掉）
    if let Some(total) = available_total.filter(|_| !any_missing && !wallets.is_empty()) {
        result["available"] = json!(total);
    }
    result
}

/// 套餐的起止时间候选键（上游换过几轮命名）。
const START_KEYS: &[&str] = &["starts_at", "start_at", "startsAt", "startAt", "effective_at", "not_before"];
const END_KEYS: &[&str] = &["ends_at", "end_at", "endsAt", "endAt", "expire_at", "expires_at"];

/// 从一个套餐里取某个边界的时刻（秒）。
fn plan_bound(plan: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| plan.get(*key).and_then(number_of).map(|value| value as i64))
}

/// 权益列表（`entitlements[]`，字段名逐条照抄官方接口）。
fn entitlements_of(plan: &Value) -> Vec<Value> {
    plan.get("entitlements")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "showName": text_of(item, &["show_name", "showName", "entitlement_id"]),
                        "unitType": text_of(item, &["unit_type", "unitType"]),
                        "grantUnits": item.get("grant_units").and_then(integer_of).unwrap_or(0),
                        "period": text_of(item, &["period"]),
                        "effectiveAt": item.get("effective_at").and_then(integer_of),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 套餐的生效时刻集合（`entitlements[].effective_at`；`0` = 立即生效哨兵）。
fn plan_effective_times(plan: &Value) -> Vec<f64> {
    plan.get("entitlements")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("effective_at").and_then(number_of))
                .filter(|value| *value > 0.0)
                .collect()
        })
        .unwrap_or_default()
}

/// 套餐状态：按时间判，`status` 只当兜底（详见模块头第 1 条）。
fn plan_state(plan: &Value, now: f64) -> PlanState {
    if let Some(end) = plan_bound(plan, END_KEYS) {
        if (end as f64) <= now {
            return PlanState::Expired;
        }
    }
    // 生效时间挂在**权益**上（`effective_at`，unix 秒；`0` = 立即生效）。
    // 套餐级 `starts_at` 是**领取 / 购买时间**，只在没有权益时兜底 —— 早期实现
    // 拿它当生效时间，于是把「领取那一刻」显示成了生效时间。
    let starts = plan_effective_times(plan);
    if !starts.is_empty() {
        if starts.iter().all(|at| *at > now) {
            return PlanState::Pending;
        }
        return PlanState::Active;
    }
    match plan_bound(plan, START_KEYS) {
        Some(start) if start as f64 > now => PlanState::Pending,
        _ => {
            // 时间字段都不在场时才看 `status`（上游偶尔不刷状态，见模块头）
            let status = text_of(plan, &["status", "state"]).to_lowercase();
            match status.as_str() {
                "expired" | "ended" => PlanState::Expired,
                "pending" | "not_started" => PlanState::Pending,
                _ => PlanState::Active,
            }
        }
    }
}

/// 待生效的那个时刻（秒）：全部权益都还没生效时给最早的一个。
fn pending_until(plan: &Value, now: f64) -> Option<i64> {
    let starts = plan_effective_times(plan);
    if starts.is_empty() || starts.iter().any(|at| *at <= now) {
        return None;
    }
    starts
        .into_iter()
        .fold(None::<f64>, |best, at| match best {
            Some(current) if current <= at => Some(current),
            _ => Some(at),
        })
        .map(|value| value as i64)
}

/// 套餐展示名（`show_name` → `name` → `plan_id`）。
fn plan_display_name(plan: &Value) -> String {
    let name = text_of(plan, &["show_name", "showName", "name", "display_name"]);
    if !name.is_empty() {
        return name;
    }
    text_of(plan, &["user_plan_id", "userPlanId", "plan_id", "planId"])
}

/// 一个数的紧凑写法（`1.2 亿` / `3.4 万` / `123`）。
///
/// 界面可以自己排版，但这个函数是**读数**的一部分（`availableView` 要一句话），
/// 所以留在插件里。
pub fn compact_number(value: f64) -> String {
    let abs = value.abs();
    if abs >= 100_000_000.0 {
        format!("{:.1} 亿", value / 100_000_000.0).replace(".0 ", " ")
    } else if abs >= 10_000.0 {
        format!("{:.1} 万", value / 10_000.0).replace(".0 ", " ")
    } else if abs.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

/// billing 读数里没有桶、但有监控窗口时，把**窗口读数**并进同一份文档。
///
/// 只并 `wallets` / `availableView`（它们本来就描述「这一列显示什么」），
/// **不动** `plans` / `subscription` / `available`（套餐清单与到期仍只认 billing；
/// `available` 保持缺失，见模块头 —— 窗口比例不是余额数字）。
fn merge_monitor_windows(mut billing: Value, windows: Value) -> Value {
    let Some(object) = billing.as_object_mut() else {
        return billing;
    };
    let wallets = windows.get("wallets").cloned().unwrap_or(Value::Null);
    object.insert("wallets".to_string(), wallets);
    if let Some(view) = windows.get("availableView") {
        object.insert("availableView".to_string(), view.clone());
    }
    object.insert(
        "source".to_string(),
        Value::String("billing+monitor".to_string()),
    );
    billing
}

// ─── 监控通道的归一化 ────────────────────────────────────────

/// 上游 `data` → 账号页的统一形状（**剩余**口径，见下）。
///
/// ── 读数方向一律「剩余」─────────────────────────────────────
/// 上游的 `percentage` 是**已用**百分比，而账号页的余额列与进度条都是**剩余**
/// 口径。两者混在一列里会让人读反，所以这里在归一化第一步就换算成剩余。
///
/// 表头读数（`availableView`）取**最紧张的那一档**（剩余比例最低的窗口）——
/// 它回答的是「现在离被拦还有多远」；窗口全都没有比例时退回绝对量读数。
///
/// 两处**刻意**不写（都是「这条通道没有这个数」的如实表达）：
///   · 不写 `available`：比例不是绝对量，写 0 会踩到「余额不足就跳过」那一档；
///   · 不写 `subscription.expireAt`：这个端点没有套餐到期时间。
fn normalize_monitor(source: &str, data: &Value) -> Value {
    let plan_name = monitor_plan_label(data);
    let limits: Vec<&Value> = data
        .get("limits")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();
    let mut wallets: Vec<Value> = Vec::new();
    // (剩余百分比, 窗口期文案) —— 表头用；取剩余**最少**（最紧张）的那个
    let mut tightest: Option<(f64, String)> = None;
    // 没有比例时的兜底读数（第一份带绝对量的窗口）
    let mut absolute: Option<String> = None;
    for limit in &limits {
        let kind = text_of(limit, &["type"]).to_uppercase();
        let unit = limit.get("unit").and_then(integer_of);
        let period = period_label(unit, limit.get("number").and_then(integer_of));
        let kind_label = kind_label(&kind);
        let unit_text = kind_unit(&kind);
        let total = limit.get("usage").and_then(number_of);
        let used = limit.get("currentValue").and_then(number_of);
        // 剩余量的取值链：`remaining` → 总额 − 已用
        let remaining = limit.get("remaining").and_then(number_of).or_else(|| {
            match (total, used) {
                (Some(total), Some(used)) => Some(total - used),
                _ => None,
            }
        });
        // 已用百分比：`percentage` → 总额与已用现算（2026-02 之后上游只回比例）
        let percent_used = limit
            .get("percentage")
            .and_then(number_of)
            .map(|value| value.clamp(0.0, PERCENT_MAX))
            .or_else(|| match (total, used) {
                (Some(total), Some(used)) if total > 0.0 => {
                    Some((used / total * PERCENT_MAX).clamp(0.0, PERCENT_MAX))
                }
                _ => None,
            });
        let remaining_percent =
            percent_used.map(|value| (PERCENT_MAX - value).clamp(0.0, PERCENT_MAX));
        let window = window_code(unit);
        if let Some(value) = remaining_percent {
            if tightest
                .as_ref()
                .map(|(current, _)| value < *current)
                .unwrap_or(true)
            {
                tightest = Some((value, period.clone()));
            }
        } else if absolute.is_none() {
            if let Some(remaining) = remaining {
                absolute = Some(format!("剩 {} {unit_text}", compact_number(remaining))
                    .trim_end()
                    .to_string());
            }
        }
        let mut view = match (total, used) {
            (Some(total), Some(used)) => {
                let left = remaining.unwrap_or((total - used).max(0.0));
                format!("剩 {} / {} {}", compact_number(left), compact_number(total), unit_text)
                    .trim_end()
                    .to_string()
            }
            _ => match remaining_percent {
                Some(value) => format!("剩 {}%", percent_text(value)),
                None => "已读取".to_string(),
            },
        };
        if let Some(text) = limit
            .get("nextResetTime")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .and_then(beijing_mmdd_hhmm)
        {
            view.push_str(" · ");
            view.push_str(&text);
            view.push_str(" 重置");
        }
        wallets.push(json!({
            "type": format!("zcode_window_{window}"),
            "displayName": format!("{kind_label}（{period}）"),
            "balance": remaining,
            "balanceView": view,
            "total": total,
            "used": used,
            "remainingPercent": remaining_percent,
            "planName": plan_name,
        }));
    }
    let available_view = headline_of(tightest, absolute, wallets.len())
        .unwrap_or_else(|| "无额度窗口".to_string());
    let mut subscription = serde_json::Map::new();
    if let Some(name) = plan_name {
        subscription.insert("planName".to_string(), Value::String(name));
    }
    json!({
        // `available` **不写**（见函数头最后一段）
        "availableView": available_view,
        // 形状与 billing 通道对齐的占位：这条通道的量纲是「次」，读数以比例为主
        "unit": "",
        "wallets": wallets,
        "subscription": subscription,
        "raw": data,
        "source": source,
    })
}

/// 表头读数的取值链：剩余最少的那个窗口 → 绝对量 → 「读到了几项」。
fn headline_of(
    tightest: Option<(f64, String)>,
    absolute: Option<String>,
    window_count: usize,
) -> Option<String> {
    if let Some((percent, period)) = tightest {
        return Some(format!("{period}剩 {}%", percent_text(percent)));
    }
    if let Some(text) = absolute {
        return Some(text);
    }
    // 窗口在但没有可读的数字（上游改了字段名之类）：如实说「读到了几项」，
    // 不编一个 0 出来
    (window_count > 0).then(|| format!("已读取 {window_count} 项额度窗口"))
}

/// 窗口期文案（`unit` 的数字语义：3 = 每 N 小时、4 = 每天、5 = 每月、6 = 每周）。
fn period_label(unit: Option<i64>, number: Option<i64>) -> String {
    match unit {
        // 每 N 小时：`number` 缺失时按 5（与第三方实现的缺省一致）
        Some(3) => format!("每 {} 小时", number.unwrap_or(5)),
        Some(4) => "每天".to_string(),
        Some(5) => "每月".to_string(),
        Some(6) => "每周".to_string(),
        _ => "每周期".to_string(),
    }
}

/// 窗口期标识（`type` 字段用，机器可读）。
fn window_code(unit: Option<i64>) -> String {
    match unit {
        Some(3) => "hours".to_string(),
        Some(4) => "daily".to_string(),
        Some(5) => "monthly".to_string(),
        Some(6) => "weekly".to_string(),
        _ => "cycle".to_string(),
    }
}

/// `type` → 量纲名。只认有证据的两档，认不出的**原样显示**（模块头第 2 条）。
///
/// 措辞对齐官方客户端的额度卡标题：`TOKENS_LIMIT` 那两行官方叫「5 小时 /
/// 每周」，`TIME_LIMIT` 那行官方叫「工具调用」。
fn kind_label(kind: &str) -> String {
    match kind {
        "TOKENS_LIMIT" => "提示次数".to_string(),
        "TIME_LIMIT" => "工具调用".to_string(),
        "" => "额度".to_string(),
        other => other.to_string(),
    }
}

/// 量纲的计量单位（`TIME_LIMIT` 是**工具调用次数**，不是时长）。
fn kind_unit(kind: &str) -> String {
    match kind {
        "TOKENS_LIMIT" => "次".to_string(),
        "TIME_LIMIT" => "次".to_string(),
        _ => String::new(),
    }
}

/// 套餐名：`planName` → `plan` → `plan_type` → `packageName` → `level` 归一。
fn monitor_plan_label(data: &Value) -> Option<String> {
    if let Some(text) = data
        .get("planName")
        .or_else(|| data.get("plan"))
        .or_else(|| data.get("plan_type"))
        .or_else(|| data.get("planType"))
        .or_else(|| data.get("packageName"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        return Some(text.to_string());
    }
    let level = data
        .get("level")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())?;
    let lower = level.to_lowercase();
    if lower.contains("max") {
        Some("Max".to_string())
    } else if lower.contains("pro") {
        Some("Pro".to_string())
    } else if lower.contains("lite") {
        Some("Lite".to_string())
    } else {
        Some(level.to_string())
    }
}

/// 百分比 → 紧凑串（`40.5` / `52`；一位小数，读的是量级）。
fn percent_text(value: f64) -> String {
    format!("{value:.1}").trim_end_matches(".0").to_string()
}
