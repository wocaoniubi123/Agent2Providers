//! 小浣熊的余额 / 积分与订阅查询（移植来源 `account-balance.mjs` 的
//! `queryPoints` / `querySubscription`）。
//!
//! ── 上游长什么样（逐条对照源实现）─────────────────────────────
//!   - 余额：`GET {pointsOrigin}/api/web/points/v1/balance`
//!     头 `Authorization: Bearer <token>`，响应 `{code, message?, data}`
//!     （`code` 非 0 视为失败，与源实现 `requestJson` 的判定一致）；
//!     `data.available_points` 是可用总量，另有四个钱包字段
//!     （`daily_points` / `monthly_points` / `reward_points` / `topup_points`）。
//!   - 订阅：`GET {pointsOrigin}/api/web/auth/v1/entitlement_info`
//!     `data.office` / `data.code` 两套权益，各带 `pro_enable` / `active_plan`
//!     / `pro_expired_time`。
//!
//! ── 域名别搞混（mainSite / pointsBase / authBase 三个配置点）────
//! 源实现读的是**主站 origin**（`RACCOON_MAIN_SITE_URL`），而鉴权接口基址是
//! 另一条配置（`RACCOON_AUTH_API_BASE`，含 `/api/web/auth/v1` 前缀）。两者默认
//! 指向同一个站点，但覆盖语义不同：本文件只复用主站 origin，**不从鉴权基址
//! 反推 origin** —— 那样会在用户只改了鉴权域（指向内网镜像）时把余额请求也
//! 一起改道，而这两条链路在源实现里是两个独立配置点。
//!
//! ── 超时 ────────────────────────────────────────────────────
//! native 侧余额 / 订阅是 20 秒、账单核对是 25 秒（都是独立超时）。wasm 宿主
//! 的出网层统一管超时，插件没有按次设超时的入口 —— 这是**能力差异**：
//! 「积分查询超时」那条 504 因此不会在本实现里出现，传输层失败统一报 502。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::credentials;
use crate::errors as upstream_errors;
use crate::{headers, upstream};

/// 钱包字段 → 展示名（逐字照抄源实现 `WALLET_LABELS`）。
///
/// 顺序即展示顺序：源实现用 `Object.entries(WALLET_LABELS)` 遍历，JS 对象的
/// 字符串键按插入序枚举，所以这里的数组顺序必须与源实现的对象字面量一致。
const WALLET_LABELS: &[(&str, &str)] = &[
    ("daily_points", "每日积分"),
    ("monthly_points", "每月会员积分"),
    ("reward_points", "奖励积分"),
    ("topup_points", "充值积分"),
    ("enterprise_topup_points", "企业加油包积分"),
];

/// 账单核对的拉取条数（源实现 `GRANT_CHECK_LIMIT`）
const GRANT_CHECK_LIMIT: usize = 20;

/// 客户端身份头：官方桌面端启动时带的两个头（源实现 `grantDesktopLoginPoints`）。
/// 每日签到（setting_info）与新手任务的首次登录奖励共用。
pub fn desktop_client_headers() -> Vec<(String, String)> {
    headers::desktop_client_headers()
}

/// 客户端身份头：官方手机端（Capacitor App）请求登录积分接口带的两个头。
///
/// 平台值是 App 壳的 `getPlatform()` 加 `app-` 前缀（`app-android` / `app-ios`，
/// 依据安卓包确认），版本头带 `v` 前缀（App 把自身版本号剥掉 `v` 再补回去）。
/// 这里固定报安卓 `v1.0.3`（实测样本）；上游只按账号结算一次性奖励，报哪端
/// 只影响走哪条端点，不影响凭证 —— 手机端接口认的也是桌面端登录签发的
/// 同一把 Bearer token（实测 + JWT claims 无平台字段双重确认）。
pub fn mobile_client_headers() -> Vec<(String, String)> {
    vec![
        ("X-Client-Platform".to_string(), "app-android".to_string()),
        ("X-Client-Version".to_string(), "v1.0.3".to_string()),
    ]
}

/// 查询某账号的余额 / 积分。
///
/// ── 订阅是「尽力而为」而不是必需 ──────────────────────────────
/// 源实现把余额与订阅拆成两个接口（`/api/accounts/balances` 与
/// `/api/accounts/subscriptions`），余额那条**只查积分**。这里合成一次调用，
/// 但订阅的失败**不影响余额结果**（`subscription` 给 null 并往 `raw` 里记一条
/// 原因）：订阅是附加信息，为了它把整个面板变成红色的「查询失败」得不偿失。
pub fn query_usage(params: &Value) -> Result<Value> {
    let _ = params;
    let credentials = credentials::snapshot()?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(401, "该账号没有可用凭证，无法查询积分"));
    }
    let origin = upstream::points_site();
    let mut org_headers = Vec::new();
    headers::append_org(&mut org_headers, &credentials.org_code)?;
    let points = request_json(
        &origin,
        "/api/web/points/v1/balance",
        &credentials.token,
        &org_headers,
    )?;
    if !points.is_object() {
        return Err(Error::http(
            502,
            "积分余额响应结构异常（期望一个 JSON 对象）",
        ));
    }

    let available = to_int(points.get("total_chargeable_points"))
        .or_else(|| to_int(points.get("available_points")));
    let wallets: Vec<Value> = WALLET_LABELS
        .iter()
        .filter_map(|(key, display_name)| {
            let balance = to_int(points.get(*key))?;
            Some(json!({
                "type": key,
                "displayName": display_name,
                "balance": balance,
            }))
        })
        .collect();

    // 逐份明细（账号页「积分明细」弹层的输入）：与上面 `wallets` 走**同一张
    // `WALLET_LABELS`、同一口径**（读不到数值就跳过这一行）—— 字段表只有一份，
    // 两处各抄一份迟早会漂。上游只给余额一个数（没有面额 / 已用 / 到期时刻），
    // 所以每行只有 `name` 与 `remain`：缺的键**不写**（写 0 会让界面把
    // 「没读到」画成「只剩 0」）。
    // 「每日积分」**不标 `daily`**：本文件里没有「这份余额按天重置」的依据
    // （每日积分走的是签到链路按天发放的那笔，不是余额清零）；缺一个标记只是
    // 少一句提示，编一个会让人以为余额明天回满。
    let credits: Vec<Value> = WALLET_LABELS
        .iter()
        .filter_map(|(key, display_name)| {
            let balance = to_int(points.get(*key))?;
            Some(json!({
                "name": display_name,
                "remain": balance,
            }))
        })
        .collect();

    // 订阅失败只记原因，不阻断余额展示（见上）
    let (subscription, subscription_error) = match request_json(
        &origin,
        "/api/web/auth/v1/entitlement_info",
        &credentials.token,
        &org_headers,
    ) {
        Ok(data) => (normalize_subscription(&data), Value::Null),
        Err(error) => (Value::Null, Value::String(error.message)),
    };

    let mut raw = serde_json::Map::new();
    raw.insert("points".to_string(), points);
    if !subscription_error.is_null() {
        raw.insert("subscriptionError".to_string(), subscription_error);
    }
    let mut document = json!({
        "available": available,
        // 小浣熊的积分口径就是「积分」（源实现的中文标签与文案都用它）
        "unit": "积分",
        "wallets": wallets,
        "subscription": subscription,
        "raw": Value::Object(raw),
    });
    // `credits[]` 只在非空时挂：空数组**整个不写这个键** —— 界面按「键在不在 +
    // 长度」决定要不要给这一格挂「可点开」的交互，给一个空数组会点出一个空框
    if !credits.is_empty() {
        if let Some(object) = document.as_object_mut() {
            object.insert("credits".to_string(), Value::Array(credits));
        }
    }
    // 额度来源（`quotaSources`）：native 侧这是 trait 上的 `quota_sources`，
    // 由网关按报告现算；wasm ABI 没有这条方法，所以随报告一并给出。
    // 形状与网关 `quota::sources` 对 raccoon 的计算结果逐字段一致
    // （账号主额度一行 + 每个钱包一行）。
    if let Some(sources) = quota_sources(&document) {
        document["quotaSources"] = sources;
    }
    Ok(document)
}

/// 复刻网关 `quota::sources` 对小浣熊的计算（见调用点的说明）。
fn quota_sources(report: &Value) -> Option<Value> {
    let mut sources: Vec<Value> = Vec::new();
    let unit = report.get("unit").and_then(Value::as_str).unwrap_or("");
    let available = report.get("available").and_then(Value::as_f64);
    if available.is_some() {
        sources.push(json!({
            "id": "account",
            "label": "账号主额度",
            "provider": "raccoon",
            "unit": unit,
            "remaining": available,
            "total": Value::Null,
            "used": Value::Null,
            "unlimited": false,
        }));
    }
    for row in report
        .get("wallets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = row.get("type").and_then(Value::as_str).unwrap_or("");
        let Some(remaining) = row.get("balance").and_then(Value::as_f64) else {
            continue;
        };
        if kind.is_empty() {
            continue;
        }
        sources.push(json!({
            "id": format!("wallet:{kind}"),
            "label": row.get("displayName").and_then(Value::as_str).unwrap_or(""),
            "provider": "raccoon",
            "unit": unit,
            "remaining": remaining,
            "total": Value::Null,
            "used": Value::Null,
        }));
    }
    if sources.is_empty() {
        None
    } else {
        Some(Value::Array(sources))
    }
}

/// 发一次 GET 并解包 `{code, message, data}`（源实现 `requestJson` 的判定链）。
fn request_json(
    origin: &str,
    path: &str,
    token: &str,
    headers: &[(String, String)],
) -> Result<Value> {
    request_json_ex(origin, "GET", path, token, headers)
}

/// `request_json` 的通用形态：方法与附加头可指定（每日签到与新手任务的
/// 桌面端链路需要 `X-Client-Platform` / `X-Client-Version` 头）。
///
/// 判定顺序逐条照抄源实现：
///   ① 传输失败 → 502「积分查询失败」（wasm 侧分不出超时，见模块头）；
///   ② HTTP 401 或业务码表示凭证失效 → 401「登录态已过期」（调用方据此刷新重试）；
///   ③ 非 2xx → 502 带上游状态码；
///   ④ `code` 存在且非 0 → 502 取 `message`；
///   ⑤ 取 `data ?? payload`（data 缺失或为 null 时回落 payload 本身）。
fn request_json_ex(
    origin: &str,
    method: &str,
    path: &str,
    token: &str,
    extra_headers: &[(String, String)],
) -> Result<Value> {
    let url = format!("{origin}{path}");
    let mut request_headers: Vec<(String, String)> = vec![
        ("Accept".to_string(), "application/json".to_string()),
        // 源实现 `token.replace(/^Bearer\s+/i, '')` 后再拼 Bearer：
        // 用户粘贴的 token 可能自带前缀，重复拼会得到 `Bearer Bearer xxx`。
        // 复用 `jwt::strip_bearer`（同一套「按字节前缀比较」的安全实现）。
        (
            "Authorization".to_string(),
            format!("Bearer {}", crate::jwt::strip_bearer(token)),
        ),
    ];
    request_headers.extend(extra_headers.iter().cloned());
    let response = upstream::send(method, &url, &request_headers, None)
        .map_err(|error| upstream::transport("积分查询失败", error))?;
    let payload = response.payload;
    if response.status == 401 || upstream_errors::token_expired(&payload) {
        return Err(Error::http(401, "登录态已过期，无法查询积分"));
    }
    if !response.ok {
        return Err(Error::http(
            502,
            format!("积分查询返回 HTTP {}", response.status),
        ));
    }
    if let Some(code) = upstream_errors::business_code(&payload) {
        if code != 0 {
            let message = payload
                .get("message")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("积分查询返回异常 code={code}"));
            return Err(Error::http(502, message));
        }
    }
    // `payload?.data ?? payload`：data 为 null（显式给了 null）时源实现的 `??`
    // 会落到 payload 本身，所以这里只在 data **缺失或为 null** 时回落
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    Ok(if data.is_null() { payload } else { data })
}

/// 订阅权益 → 统一形状的 `subscription`（源实现 `querySubscription` 的字段）。
///
/// 小浣熊有两套权益（办公端 `office` 与代码端 `code`），源实现两个都返回。
/// 统一形状里只留一组「套餐 / 状态 / 到期时间」，因此**优先取办公端的**
/// （那是小浣熊桌面端的主入口），办公端没有时回落代码端；两套都保留在
/// `raw` 里供排障。
///
/// `expireAt` 是上游给的字符串形态时间（源实现直接透出，不做解析），
/// 这里同样原样保留 —— 转换成时间戳会让「上游给的是本地时间串还是 ISO」
/// 这个不确定性冒到界面上。
fn normalize_subscription(data: &Value) -> Value {
    let office = data.get("office").filter(|value| value.is_object());
    let code = data.get("code").filter(|value| value.is_object());
    let pick = |key: &str| -> Option<Value> {
        office
            .and_then(|value| value.get(key))
            .or_else(|| code.and_then(|value| value.get(key)))
            .filter(|value| !value.is_null())
            .cloned()
    };
    let pro_enabled = office
        .and_then(|value| value.get("pro_enable"))
        .and_then(Value::as_bool)
        .or_else(|| {
            code.and_then(|value| value.get("pro_enable"))
                .and_then(Value::as_bool)
        })
        .unwrap_or(false);
    if office.is_none() && code.is_none() {
        return Value::Null;
    }
    let plan_type = pick("active_plan")
        .and_then(|plan| plan.get("type").cloned())
        .or_else(|| pick("plan_type"))
        .unwrap_or(Value::Null);
    let expired_at = pick("pro_expired_time")
        .or_else(|| {
            pick("active_plan").and_then(|plan| plan.get("subscription_expired_at").cloned())
        })
        .unwrap_or(Value::Null);
    json!({
        "planName": plan_type.as_str().unwrap_or(""),
        // 状态沿用上游语义：开了 pro 是 active，没开是 none
        // （源实现只给布尔 pro_enable，没有更细的状态机）
        "status": if pro_enabled { "active" } else { "none" },
        "expireAt": expired_at,
        "remainQuota": Value::Null,
        "totalQuota": Value::Null,
    })
}

/// 拉今日账单（最多 5 页，遇到前一日的记录就停）。
fn daily_bills(
    origin: &str,
    token: &str,
    headers: &[(String, String)],
    today: &str,
) -> Result<Vec<Value>> {
    let mut cursor = String::new();
    let mut seen: Vec<String> = Vec::new();
    let mut items = Vec::new();
    for _ in 0..5 {
        let mut query = format!(
            "paging.limit={}&type=all",
            crate::url::encode(&GRANT_CHECK_LIMIT.to_string())
        );
        if !cursor.is_empty() {
            query.push_str(&format!("&cursor={}", crate::url::encode(&cursor)));
        }
        let path = format!("/api/web/points/v2/bills?{query}");
        let data = request_json_ex(origin, "GET", &path, token, headers)?;
        let page = data
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::http(502, "积分账单响应缺少 items"))?;
        let reached_previous_day = page
            .iter()
            .any(|item| bill_date(item).is_some_and(|date| date.as_str() < today));
        items.extend(page.iter().cloned());
        if reached_previous_day || page.is_empty() {
            break;
        }
        let next = data
            .get("next_cursor")
            .or_else(|| data.get("cursor"))
            .or_else(|| data.pointer("/paging/next_cursor"))
            .or_else(|| data.pointer("/paging/cursor"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let has_more = data
            .get("has_more")
            .or_else(|| data.pointer("/paging/has_more"))
            .and_then(Value::as_bool)
            .unwrap_or(!next.is_empty());
        if !has_more || next.is_empty() || seen.iter().any(|known| known == next) {
            break;
        }
        seen.push(next.to_string());
        cursor = next.to_string();
    }
    Ok(items)
}

/// 一条账单记录落在北京时间的哪一天。
fn bill_date(item: &Value) -> Option<String> {
    let at = item
        .get("grant_at")
        .or_else(|| item.get("created_at"))?
        .as_str()?;
    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(at) {
        return Some(date_key(date.with_timezone(&beijing_offset())));
    }
    at.get(..10).map(str::to_string)
}

/// 一条账单是不是「今日·每日积分发放」。
fn daily_grant(item: &Value, today: &str) -> Option<Value> {
    let kind = item.get("biz_type").and_then(Value::as_str);
    let name = item.get("event_name").and_then(Value::as_str).unwrap_or("");
    let daily = kind == Some("daily_grant") || kind.is_none() && name == "每日积分发放";
    let points = to_int(item.get("points"))?;
    if !daily || points <= 0 || bill_date(item).as_deref() != Some(today) {
        return None;
    }
    let at = item.get("created_at").and_then(Value::as_str).unwrap_or("");
    Some(json!({
        "name": name,
        "points": points,
        "at": at.get(11..19).unwrap_or(""),
        "expireAt": item.get("expire_at"),
    }))
}

/// 数值取整（源实现 `toInt`：非有限值给 None，有限值取 floor）。
///
/// 返回 `Option<i64>` 而不是 f64：积分是整数口径，源实现也做 `Math.floor`。
fn to_int(value: Option<&Value>) -> Option<i64> {
    upstream::int_of(value)
}

// ─── 每日「签到」（桌面登录积分发放）─────────────────────────
//
// 小浣熊没有 WorkBuddy 那种「每日签到」接口；它的每日奖励走的是**桌面端
// 登录积分**链路：官方桌面客户端每次启动会打两个接口，服务端据此按天发放
// 每日积分。这里复刻同一条链路作为「签到」：
//   ① GET  /api/web/office/v3/setting_info —— **每日积分的发放触发器**
//      （按天幂等），发放通知在响应的 point_grant_popups / point_grant_toast；
//   ② GET  /api/web/points/v2/bills —— 核对今日实际入账，作为权威结果
//      （账单接口慢，失败降级，不影响 ① 的领取本身）。
//
// 同一条 grant 接口里的**首次**桌面登录奖励（一次性 3000，新手福利）原先也是
// 本函数的第①步，已拆到新手任务分组（`onboarding.rs`），不再随每日签到执行
// —— 一次性动作混进每日调度，之后每一轮都会白打一次。

/// 小浣熊账号的每日签到（`{success, msg, grantsToday, settings, ...}`）。
///
/// `success` 的口径是「**今日积分确有入账**」（账单核对），而不是某一步的
/// HTTP 成败：发放是服务端在 setting_info 上按天幂等完成的，重复执行
/// 不会重复入账，账单里看得到就是领到了。
pub fn claim_daily_grant(params: &Value) -> Result<Value> {
    let _ = params;
    let credentials = credentials::snapshot()?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(401, "该账号没有可用凭证，无法签到"));
    }
    let origin = upstream::main_site();
    let today = today_key();
    let mut org_headers = Vec::new();
    headers::append_org(&mut org_headers, &credentials.org_code)?;
    let previous = match daily_bills(&origin, &credentials.token, &org_headers, &today) {
        Ok(items) => Some(
            items
                .into_iter()
                .filter_map(|item| daily_grant(&item, &today))
                .collect::<Vec<_>>(),
        ),
        Err(error) if error.status == Some(401) => return Err(error),
        Err(_) => None,
    };
    let already_completed = previous.as_ref().is_some_and(|items| !items.is_empty());

    // ① 每日积分发放触发器（按天幂等）。失败必须体现在结果里 ——
    //    这步不成功当日就没有发放，账单核对会给出「今日未见入账」
    let mut settings_headers = desktop_client_headers();
    headers::append_org(&mut settings_headers, &credentials.org_code)?;
    settings_headers.push(("X-Raccoon-Language".to_string(), "zh".to_string()));
    let settings_path = if credentials.org_code.is_empty() {
        "/api/web/office/v3/setting_info"
    } else {
        "/api/web/org/user/office/v1/setting_info"
    };
    let settings = request_json_ex(
        &origin,
        "GET",
        settings_path,
        &credentials.token,
        &settings_headers,
    )
    .map(|data| {
        // 发放通知原样透出（结构与上游一致，界面不深入解析）
        json!({
            "popups": data.get("point_grant_popups").cloned().unwrap_or(Value::Null),
            "toast": data.get("point_grant_toast").cloned().unwrap_or(Value::Null),
        })
    })?;

    // ② 账单核对今日入账（慢接口；失败降级为 grantsError）。
    // 「今天」按**北京时间**（上游自然日即 UTC+8 零点），不跟机器时区：
    // 海外 / 容器部署下跟本地时区走会把 16 小时的账单认成昨天，
    // 让「今日积分 +N」与「今天已领过」的判定整体错位（issue #138）。
    let (grants, grants_error) = if already_completed {
        (previous.unwrap_or_default(), None)
    } else {
        match daily_bills(&origin, &credentials.token, &org_headers, &today) {
            Ok(items) => (
                items
                    .iter()
                    .filter_map(|item| daily_grant(item, &today))
                    .collect::<Vec<_>>(),
                None,
            ),
            Err(error) if error.status == Some(401) => return Err(error),
            Err(error) => (Vec::new(), Some(error.message)),
        }
    };

    let granted_today = grants
        .iter()
        .map(|item| to_int(item.get("points")).unwrap_or(0))
        .sum::<i64>();
    let mut msg_parts: Vec<String> = Vec::new();
    if granted_today > 0 {
        msg_parts.push(format!("今日积分 +{granted_today}"));
    } else if grants_error.is_some() {
        // 账单核对失败拿不到权威结果，不谎报成功
        msg_parts.push("未能核对今日入账".to_string());
    } else {
        msg_parts.push("今日未见积分入账，尚未确认领取".to_string());
    }
    if let Some(error) = grants_error.as_deref() {
        msg_parts.push(format!("账单核对失败：{error}"));
    }

    Ok(json!({
        "success": granted_today > 0,
        "alreadyCompleted": already_completed,
        "msg": msg_parts.join("；"),
        "grantsToday": grants,
        "settings": settings,
        "grantsError": grants_error.map(Value::String).unwrap_or(Value::Null),
    }))
}

/// 签到结果 → 协议化的 `CheckinReport`（native 的 `checkin_report_of`）。
pub fn checkin_report_of(claim: &Value) -> Value {
    let success = claim
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let message = claim
        .get("msg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let credit = claim
        .get("grantsToday")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("points").and_then(Value::as_i64))
                .sum::<i64>()
        })
        .filter(|points| *points > 0)
        .map(|points| format!("{points} 积分"));
    let text = message.clone().unwrap_or_default();
    let outcome = if claim.get("alreadyCompleted").and_then(Value::as_bool) == Some(true) {
        "done"
    } else if success {
        "claimed"
    } else if text.contains("未见") || text.contains("未能核对") {
        "inactive"
    } else {
        "failed"
    };
    json!({
        "outcome": outcome,
        "credit": credit,
        "streak": Value::Null,
        "message": message,
    })
}

/// `checkin.claim` 的完整实现：发一次发放 + 核对账单，再折成 CheckinReport。
pub fn claim(params: &Value) -> Result<Value> {
    let claim = claim_daily_grant(params)?;
    Ok(checkin_report_of(&claim))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkin_outcomes_map_from_the_claim_shape() {
        // 今日确有入账 → claimed，并把积分折成一句文案
        let report = checkin_report_of(&json!({
            "success": true,
            "alreadyCompleted": false,
            "msg": "今日积分 +10",
            "grantsToday": [{ "points": 10 }],
        }));
        assert_eq!(report["outcome"], "claimed");
        assert_eq!(report["credit"], "10 积分");
        assert_eq!(report["message"], "今日积分 +10");
        // 今天已经领过 → done
        let report = checkin_report_of(&json!({
            "success": false,
            "alreadyCompleted": true,
            "msg": "今日积分 +10",
            "grantsToday": [{ "points": 10 }],
        }));
        assert_eq!(report["outcome"], "done");
        // 账单核对失败 → 明确说没核对上，不当成失败也不谎报成功
        let report = checkin_report_of(&json!({
            "success": false,
            "alreadyCompleted": false,
            "msg": "未能核对今日入账；账单核对失败：boom",
            "grantsToday": [],
        }));
        assert_eq!(report["outcome"], "inactive");
        assert!(report["credit"].is_null());
        // 其它失败
        let report = checkin_report_of(&json!({ "success": false, "msg": "上游 500" }));
        assert_eq!(report["outcome"], "failed");
    }

    #[test]
    fn wallet_and_subscription_mapping() {
        // 「积分不足」这类空响应不该造出订阅对象
        assert!(normalize_subscription(&json!({})).is_null());
        let subscription = normalize_subscription(&json!({
            "office": {
                "pro_enable": true,
                "active_plan": { "type": "Pro", "subscription_expired_at": "2026-12-01" }
            }
        }));
        assert_eq!(subscription["status"], "active");
        assert_eq!(subscription["planName"], "Pro");
        assert_eq!(subscription["expireAt"], "2026-12-01");
        // 没开 pro → none，但到期时间仍原样透出
        let subscription = normalize_subscription(&json!({
            "code": { "pro_enable": false, "pro_expired_time": "2026-01-01" }
        }));
        assert_eq!(subscription["status"], "none");
        assert_eq!(subscription["expireAt"], "2026-01-01");
    }

    #[test]
    fn quota_sources_mirror_the_gateway_rules() {
        let report = json!({
            "available": 120,
            "unit": "积分",
            "wallets": [
                { "type": "daily_points", "displayName": "每日积分", "balance": 20 },
                { "type": "reward_points", "displayName": "奖励积分", "balance": 100 },
                // 没有可读余额的钱包不产出来源
                { "type": "topup_points", "displayName": "充值积分" }
            ],
        });
        let sources = quota_sources(&report).unwrap_or(Value::Null);
        let list = sources.as_array().cloned().unwrap_or_default();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["id"], "account");
        // 余额是 f64 口径（网关 `quota::number` 也按 f64 收），所以这里比 120.0
        assert_eq!(list[0]["remaining"], 120.0);
        assert_eq!(list[1]["id"], "wallet:daily_points");
        assert_eq!(list[1]["label"], "每日积分");
        assert_eq!(list[1]["provider"], "raccoon");
        assert_eq!(list[2]["remaining"], 100.0);
    }

    #[test]
    fn today_key_uses_beijing_time() {
        // 东八区固定偏移：日期键必须是 `YYYY-MM-DD` 的定长形态（字典序即时间序）。
        // 宿主时钟不可用时（单元测试跑在非 wasm 目标上）退到 1970-01-01，
        // 形态判据因此只查长度与分隔符，不查年份。
        let today = today_key();
        assert_eq!(today.len(), 10, "{today}");
        assert_eq!(today.as_bytes()[4], b'-', "{today}");
        assert_eq!(today.as_bytes()[7], b'-', "{today}");
        assert!(today.chars().filter(char::is_ascii_digit).count() == 8, "{today}");
    }
}

// ─── 北京时间（固定 UTC+8）—— 签到链路对「今天」的唯一定义 ────────

/// UTC+8 的固定偏移（秒）。中国标准时间没有夏令时，`Asia/Shanghai` 在 1970 年
/// 之后恒为 +08:00 —— 一个固定偏移就够，且不依赖宿主机的 tzdata。
const OFFSET_SECONDS: i32 = 8 * 3600;

fn beijing_offset() -> chrono::FixedOffset {
    // 8 小时恒在合法范围内；兜底给 UTC 偏移是为了守住「插件零 panic」的约定。
    chrono::FixedOffset::east_opt(OFFSET_SECONDS).unwrap_or_else(|| {
        use chrono::Offset;
        chrono::Utc.fix()
    })
}

fn date_key(now: chrono::DateTime<chrono::FixedOffset>) -> String {
    now.format("%Y-%m-%d").to_string()
}

/// 北京时间的今天（`YYYY-MM-DD`）。
pub fn today_key() -> String {
    match chrono::DateTime::from_timestamp_millis(sdk::now()) {
        Some(utc) => date_key(utc.with_timezone(&beijing_offset())),
        // 时间源异常（宿主时钟不可用）时退到 1970 那一天：账单核对会因为
        // 「今日未见入账」而如实报「未确认」—— 不谎报成功。
        None => "1970-01-01".to_string(),
    }
}
