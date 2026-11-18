//! 限时套餐的**探测 / 领取**与激活事件上报
//! （native `zcode/claim.rs` + `claim/*` + `activation.rs` 的移植）。
//!
//! ── 这个功能替代了本家的「签到」────────────────────────────
//! ZCode 没有签到活动 —— 它的运营玩法是**限时发放的体验套餐**（周末套餐 /
//! Global Build / ZCode Trust Build），用户在客户端里点一下就领，领到的额度在
//! 一段时间内可用。「每天领一次」是**套餐 id 实现的**：上游每天返回一个带日期
//! 段的新套餐（`zcode-v3-start-plan-trust-0928` → `…-0929`），于是「今天领过没」
//! 等价于「今天这个 plan_id 领过没」（同一期再领回 `1003 already claimed`）。
//!
//! ── 上游协议（两个接口 + 一条营销链路）────────────────────────
//! ```text
//!   探测  GET  {zcode}/api/v1/zcode-plan/billing/preview?app_version=&platform=
//!   领取  POST {zcode}/api/v1/zcode-plan/billing/claim   body {"plan_id": "..."}
//!   营销  GET  {zcode}/api/v1/marketing/touch?seq=0      （周末活动可能只在这里）
//!   回执  POST {zcode}/api/v1/marketing/touch/action     body {campaign_id, action_type:"confirm"}
//! ```
//!
//! ── `X-Device-Mid` 现在是硬要求（2026-09-28 实测）───────────
//! 缺它、或值不是 UUID 形态，网关一律回 `400 {"code":3001,"msg":"parameter error"}`
//! —— 连**匿名探测**也一样。设备标识还必须跨请求稳定（风控据此关联同一设备的
//! 请求），因此它随凭证落盘，见 `account::device_mid_or_create`。
//!
//! ── 验证码为什么是**参数**而不是本模块自己求解 ───────────────
//! claim 通常要带 `X-Aliyun-Captcha-Verify-Param`（阿里云无痕验证）。那套求解器
//! 要跑 WASM / DOM 桩，插件不该重复实现它：本项目已有的链路是**界面**用官方
//! SDK 求解、把 verifyParam 交给后端（`admin.action` 的 `claim.claim` 参数），
//! 本模块把它原样转发给上游。
//!
//! ── 与 native 的删减（逐条列清，不当成漏做）──────────────────
//!   · **领取台账**（`claim/state.rs`，落 session/state 的 claimed / ineligible /
//!     claim_periods）：native 用它是为了「上游预览消失后仍记得领过」。插件不做
//!     台账 = 每次以**上游**为准：领过的套餐上游会回 1003（`already_claimed`），
//!     结果一致，代价是多一次上游往返、且界面上的「今日已领」由上游实时给。
//!   · **匿名活动目录**（`claim/catalog.rs`，一个 60 秒 TTL 的匿名 preview）：
//!     它只是给管理页展示「本期活动有什么」，不影响领取判定。
//!   · **账号套餐归属**（`claim/ownership.rs`）：这里用 billing 的 `plans` 直接判
//!     （见 [`owned_plan_ids`]），不需要单独模块与 15 秒缓存。
//!   · **定时领取的验证编排**（`claim_verification.rs`）：那是「向已连接的管理
//!     界面要一次验证」的双向通道，插件侧由 `admin.action` 的 `claim.claim`
//!     参数承担（同一个入口，人工触发）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{integer_of, new_uuid, now_ms, text_of};
use super::{account, captcha, http, plan, region, usage};

/// 探测 / 领取的路径（参考实现 `client.ts` 的常量）
const PREVIEW_PATH: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM_PATH: &str = "/api/v1/zcode-plan/billing/claim";
/// 营销活动（只读取套餐元数据，不加载或执行营销资源）
const MARKETING_QUERY_PATH: &str = "/api/v1/marketing/touch";
const MARKETING_REPORT_PATH: &str = "/api/v1/marketing/touch/action";
/// 激活事件上报（资格的前置动作，见 [`report_activation`]）
const EVENT_REPORT_PATH: &str = "/api/v1/event/report";

/// 可领取套餐的统一形态（只留领取链真正用到的字段）。
#[derive(Clone, Debug)]
pub struct ClaimablePlan {
    pub plan_id: String,
    pub name: String,
    pub description: String,
    pub priority: i64,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub entitlements: Vec<Value>,
    /// 这条套餐是从营销活动拿到的（要领完再回执）
    pub marketing_campaign_ids: Vec<String>,
}

/// 领取的失败语义（参考实现 `ClaimFailureKind` 的移植）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimFailure {
    NotFound,
    Unavailable,
    AlreadyClaimed,
    Ineligible,
    QuotaExhausted,
    InvalidRequest,
    Captcha,
    LoginRequired,
    HttpError,
    Unknown,
}

impl ClaimFailure {
    /// 给用户看的一句话（进日志与界面）。
    pub fn label(self) -> &'static str {
        match self {
            Self::NotFound => "套餐不存在",
            Self::Unavailable => "活动已结束或尚未开始",
            Self::AlreadyClaimed => "该账号已领取过",
            Self::Ineligible => "账号或客户端版本不符合活动资格",
            Self::QuotaExhausted => "当日领取额度已用尽",
            Self::InvalidRequest => "参数错误（常见成因：缺少设备标识）",
            Self::Captcha => "验证码校验未通过",
            Self::LoginRequired => "登录态已失效，请重新登录",
            Self::HttpError => "上游 HTTP 错误",
            Self::Unknown => "未知失败",
        }
    }

    /// 前端用的稳定字符串（按它选文案，不按中文 label 匹配）。
    pub fn key(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::AlreadyClaimed => "already_claimed",
            Self::Ineligible => "ineligible",
            Self::QuotaExhausted => "quota_exhausted",
            Self::InvalidRequest => "invalid_request",
            Self::Captcha => "captcha",
            Self::LoginRequired => "login_required",
            Self::HttpError => "http_error",
            Self::Unknown => "unknown",
        }
    }

    /// biz code → 语义（与客户端 `$vt` 映射器逐条对齐）。
    fn from_code(code: i64) -> Self {
        match code {
            1001 => Self::NotFound,
            1002 => Self::Unavailable,
            1003 => Self::AlreadyClaimed,
            1004 => Self::Ineligible,
            1005 => Self::QuotaExhausted,
            3001 => Self::InvalidRequest,
            3007 => Self::Captcha,
            401 => Self::LoginRequired,
            _ => Self::Unknown,
        }
    }
}

/// 领取结果。
pub enum ClaimOutcome {
    Claimed {
        plan_id: String,
        starts_at: Option<i64>,
        ends_at: Option<i64>,
    },
    Failed {
        plan_id: String,
        failure: ClaimFailure,
        code: i64,
        message: String,
        failure_ends_at: Option<i64>,
    },
}

/// 一次预览的快照。
pub struct Snapshot {
    pub plans: Vec<ClaimablePlan>,
    /// 账号预览（`billing/preview`）成功过（决定 `deployed`）
    pub deployed: bool,
    pub activated: Option<bool>,
    pub activation_error: Option<String>,
    pub preview_error: Option<String>,
    pub marketing_error: Option<String>,
    pub ownership_error: Option<String>,
    /// 账号名下**已拥有**的套餐 id（来自 billing 的 plans）
    pub owned: Vec<(String, Option<i64>, Option<i64>, String)>,
}

impl Snapshot {
    /// 界面读的形状（与 native `PreviewSnapshot::to_json` 同键名）。
    pub fn to_json(&self) -> Value {
        let rows: Vec<Value> = self
            .plans
            .iter()
            .map(|plan| {
                let owned = self
                    .owned
                    .iter()
                    .find(|(id, _, _, _)| id == &plan.plan_id)
                    .filter(|(_, _, ends_at, state)| {
                        matches!(state.as_str(), "active" | "pending")
                            && ends_at.is_none_or(|end| end > now_ms() / 1000)
                    });
                let claimed = owned.is_some();
                let mut sources: Vec<Value> = Vec::new();
                if plan.marketing_campaign_ids.is_empty() {
                    sources.push(json!("preview"));
                } else {
                    sources.push(json!("marketing"));
                }
                json!({
                    "planId": plan.plan_id,
                    "name": plan.name,
                    "description": plan.description,
                    "priority": plan.priority,
                    "startsAt": plan.starts_at,
                    "endsAt": plan.ends_at,
                    "claimed": claimed,
                    "claimedAt": Value::Null,
                    "claimState": if claimed { "claimed" } else { "claimable" },
                    "claimMessage": Value::Null,
                    "source": sources[0],
                    "sources": sources,
                    "ownedPlan": owned.map(|(id, starts_at, ends_at, state)| json!({
                        "planId": id,
                        "state": state,
                        "startsAt": starts_at,
                        "endsAt": ends_at,
                    })),
                    "entitlements": plan.entitlements,
                })
            })
            .collect();
        json!({
            "plans": rows,
            "deployed": self.deployed,
            "activated": self.activated,
            "activationError": self.activation_error,
            "previewError": self.preview_error,
            "marketingError": self.marketing_error,
            // 这三项在插件侧没有对应链路（见模块头「与 native 的删减」）
            "catalogError": Value::Null,
            "ownershipError": self.ownership_error,
            "ledgerError": Value::Null,
            "dailyCheckin": Value::Null,
        })
    }

    /// 有没有任何一路成功（全失败时调用方要报错，而不是回空列表）。
    fn any_success(&self) -> bool {
        self.preview_error.is_none() || self.marketing_error.is_none()
    }
}

/// 探测可领套餐（`GET billing/preview`）。
///
/// 返回 `Ok(None)` = 上游 404（这一期没有这个接口），`Ok(Some(vec![]))` = 明确
/// 「没有可领的套餐」。两者对调用方的含义不同（见 `discovery` 的 `deployed`）。
pub fn preview_billing(jwt: &str, device_mid: Option<&str>) -> Result<Option<Vec<ClaimablePlan>>> {
    let url = format!(
        "{}{PREVIEW_PATH}?{}",
        region::ZCODE_ORIGIN,
        plan::version_query()
    );
    // 匿名探测不能携带空 Bearer 或账号凭证。
    let mut headers: Vec<(String, String)> = Vec::new();
    if !jwt.trim().is_empty() {
        headers.push(("Authorization".to_string(), format!("Bearer {}", jwt.trim())));
    }
    if let Some(mid) = device_mid.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    let reply = http::send("GET", &url, &headers, None)
        .map_err(|error| http::transport_error("套餐探测失败", &error))?;
    if reply.status == 404 {
        return Ok(None);
    }
    if reply.status == 401 {
        return Err(Error::http(401, "登录态已失效，无法探测套餐"));
    }
    let code = plan::biz_code(&reply.payload);
    let data = reply.payload.get("data");
    let plans = data.and_then(|value| value.get("plans"));
    // 无可领套餐时，上游可能省略 data / plans，或将它们置为 null。
    let invalid_data = data.is_some_and(|value| !value.is_null() && !value.is_object());
    let invalid_plans = plans.is_some_and(|value| !value.is_null() && !value.is_array());
    let succeeded = (200..300).contains(&reply.status)
        && code == Some(0)
        && reply.payload.get("success").and_then(Value::as_bool) != Some(false);
    if !succeeded || invalid_data || invalid_plans {
        let code_label = code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "缺失或无效".to_string());
        let detail = text_of(&reply.payload, &["msg", "message"]);
        let detail = if detail.is_empty() {
            format!("HTTP {}", reply.status)
        } else {
            detail
        };
        return Err(Error::http(
            502,
            format!("套餐探测失败（{code_label}）：{detail}"),
        ));
    }
    let parsed = plans
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_plan).collect())
        .unwrap_or_default();
    Ok(Some(parsed))
}

/// 营销活动里的可领套餐（`GET /api/v1/marketing/touch`）。
///
/// 周末活动可**仅**出现在这个接口的 `claim_zcode_plan` 按钮里，`billing/preview`
/// 为空不能排除这类套餐。只读套餐元数据，不加载或执行营销资源。
pub fn marketing_query(jwt: &str, device_mid: Option<&str>) -> Result<Vec<ClaimablePlan>> {
    let url = format!("{}{MARKETING_QUERY_PATH}?seq=0", region::ZCODE_ORIGIN);
    let mut headers: Vec<(String, String)> = vec![
        ("X-Client-Language".to_string(), "zh-CN".to_string()),
        ("X-ZCode-App-Version".to_string(), plan::app_version()),
    ];
    if !jwt.trim().is_empty() {
        headers.push(("Authorization".to_string(), format!("Bearer {}", jwt.trim())));
    }
    if let Some(mid) = device_mid.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    let reply = http::send("GET", &url, &headers, None)
        .map_err(|error| http::transport_error("营销套餐查询失败", &error))?;
    if reply.status == 404 {
        return Ok(Vec::new());
    }
    let code = plan::biz_code(&reply.payload);
    if !(200..300).contains(&reply.status)
        || code != Some(0)
        || reply.payload.get("success").and_then(Value::as_bool) == Some(false)
    {
        let detail = text_of(&reply.payload, &["msg", "message"]);
        return Err(Error::http(
            if reply.status == 401 || code == Some(401) { 401 } else { 502 },
            format!(
                "营销套餐查询失败：{}",
                if detail.is_empty() { format!("HTTP {}", reply.status) } else { detail }
            ),
        ));
    }
    let deliveries = reply
        .payload
        .pointer("/data/deliveries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "营销套餐查询：上游未返回有效的活动列表"))?;
    let mut plans: Vec<ClaimablePlan> = Vec::new();
    for delivery in deliveries {
        let Some(campaign) = delivery
            .get("campaign_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 128)
        else {
            continue;
        };
        let priority = delivery.get("priority").and_then(integer_of).unwrap_or(0);
        let mut found: Vec<ClaimablePlan> = Vec::new();
        for path in [
            "/banner/buttons",
            "/banner/success_popup/buttons",
            "/popup/buttons",
        ] {
            let Some(buttons) = delivery.pointer(path).and_then(Value::as_array) else {
                continue;
            };
            for button in buttons {
                let Some(action) = button.get("action") else {
                    continue;
                };
                if action.get("type").and_then(Value::as_str) != Some("claim_zcode_plan") {
                    continue;
                }
                let Some(plan_id) = action
                    .pointer("/args/plan_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty() && value.len() <= 128)
                else {
                    continue;
                };
                found.push(ClaimablePlan {
                    plan_id: plan_id.to_string(),
                    name: plan_id.to_string(),
                    description: String::new(),
                    priority,
                    starts_at: None,
                    ends_at: None,
                    entitlements: Vec::new(),
                    marketing_campaign_ids: vec![campaign.to_string()],
                });
            }
        }
        merge_plans(&mut plans, found);
    }
    Ok(plans)
}

/// 把新来的套餐并进列表（按 plan_id 去重，优先级高的排前面）。
fn merge_plans(plans: &mut Vec<ClaimablePlan>, incoming: Vec<ClaimablePlan>) {
    for plan in incoming {
        match plans.iter_mut().find(|item| item.plan_id == plan.plan_id) {
            Some(existing) => {
                if existing.name.is_empty() || existing.name == existing.plan_id {
                    existing.name = plan.name;
                }
                if existing.description.is_empty() {
                    existing.description = plan.description;
                }
                existing.priority = existing.priority.max(plan.priority);
                existing.starts_at = existing.starts_at.or(plan.starts_at);
                existing.ends_at = existing.ends_at.or(plan.ends_at);
                if existing.entitlements.is_empty() {
                    existing.entitlements = plan.entitlements;
                }
                for campaign in plan.marketing_campaign_ids {
                    if !existing.marketing_campaign_ids.contains(&campaign) {
                        existing.marketing_campaign_ids.push(campaign);
                    }
                }
            }
            None => plans.push(plan),
        }
    }
    plans.sort_by(|left, right| right.priority.cmp(&left.priority));
}

/// 解析一条可领套餐（上游 `plans[]` 的条目）。
fn parse_plan(raw: &Value) -> Option<ClaimablePlan> {
    let plan_id = text_of(raw, &["plan_id", "planId"]);
    if plan_id.is_empty() || plan_id.len() > 128 {
        return None;
    }
    let name = text_of(raw, &["name"]);
    let entitlements = raw
        .get("entitlements")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "showName": text_of(item, &["show_name", "entitlement_id"]),
                        "unitType": text_of(item, &["unit_type"]),
                        "grantUnits": item.get("grant_units").and_then(integer_of).unwrap_or(0),
                        "period": text_of(item, &["period"]),
                        "effectiveAt": item.get("effective_at").and_then(integer_of),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ClaimablePlan {
        name: if name.is_empty() { plan_id.clone() } else { name },
        plan_id,
        description: text_of(raw, &["description"]),
        priority: raw.get("priority").and_then(integer_of).unwrap_or(0),
        starts_at: raw.get("starts_at").and_then(integer_of),
        ends_at: raw.get("ends_at").and_then(integer_of),
        entitlements,
        marketing_campaign_ids: Vec::new(),
    })
}

/// 账号名下**已拥有**的套餐（来自 billing 的 `plans`）。
///
/// native 有一个带 15 秒缓存的 `ownership` 模块；这里直接读一次 billing（低频
/// 动作），失败只记一条 `ownershipError`，不影响可领列表。
fn owned_plan_ids(jwt: &str, device_mid: Option<&str>) -> Result<Vec<(String, Option<i64>, Option<i64>, String)>> {
    let value = usage::billing_channel(jwt, device_mid)?;
    let rows = value
        .get("plans")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|plan| {
                    let id = text_of(plan, &["planId"]);
                    if id.is_empty() {
                        return None;
                    }
                    Some((
                        id,
                        plan.get("startsAt").and_then(integer_of),
                        plan.get("endsAt").and_then(integer_of),
                        text_of(plan, &["state"]),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(rows)
}

/// 一次完整的预览（`billing/preview` + `marketing/touch` [+ 已拥有]）。
///
/// `display = true` 时额外查一次「账号名下已拥有」（界面要对已领的套餐显示
/// 「已领」，而自动领取只看可领列表 —— 多一次 billing 请求不值得）。
pub fn preview(jwt: &str, device_mid: Option<&str>, display: bool) -> Result<Snapshot> {
    let billing = preview_billing(jwt, device_mid);
    let marketing = marketing_query(jwt, device_mid);
    let mut snapshot = Snapshot {
        plans: Vec::new(),
        deployed: false,
        activated: None,
        activation_error: None,
        preview_error: None,
        marketing_error: None,
        ownership_error: None,
        owned: Vec::new(),
    };
    match billing {
        Ok(plans) => {
            snapshot.deployed = plans.is_some();
            if let Some(plans) = plans {
                merge_plans(&mut snapshot.plans, plans);
            }
        }
        Err(error) => snapshot.preview_error = Some(error.message),
    }
    match marketing {
        Ok(plans) => merge_plans(&mut snapshot.plans, plans),
        Err(error) => snapshot.marketing_error = Some(error.message),
    }
    if display && !jwt.trim().is_empty() {
        match owned_plan_ids(jwt, device_mid) {
            Ok(rows) => snapshot.owned = rows,
            Err(error) => snapshot.ownership_error = Some(error.message),
        }
    }
    if !snapshot.any_success() && snapshot.plans.is_empty() {
        let detail = [
            snapshot.preview_error.as_deref(),
            snapshot.marketing_error.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("；");
        return Err(Error::http(502, format!("套餐查询失败：{detail}")));
    }
    Ok(snapshot)
}

/// 挑一个领取目标：点名优先，否则优先级最高且**还没领过**的那个。
pub fn resolve_target(
    jwt: &str,
    device_mid: Option<&str>,
    requested: &str,
) -> Result<Option<ClaimablePlan>> {
    let requested = requested.trim();
    if !requested.is_empty() {
        if requested.len() > 128 {
            return Err(Error::http(400, "套餐标识无效"));
        }
        let snapshot = preview(jwt, device_mid, false).ok();
        if let Some(plan) = snapshot
            .and_then(|snapshot| snapshot.plans.into_iter().find(|plan| plan.plan_id == requested))
        {
            return Ok(Some(plan));
        }
        // 点名领取不依赖预览成功：上游 claim 才是资格的最终判据。
        return Ok(Some(ClaimablePlan {
            plan_id: requested.to_string(),
            name: requested.to_string(),
            description: String::new(),
            priority: 0,
            starts_at: None,
            ends_at: None,
            entitlements: Vec::new(),
            marketing_campaign_ids: Vec::new(),
        }));
    }
    let snapshot = preview(jwt, device_mid, false)?;
    let owned = snapshot
        .owned
        .iter()
        .map(|(id, _, _, _)| id.clone())
        .collect::<Vec<_>>();
    Ok(snapshot
        .plans
        .into_iter()
        .find(|plan| !owned.contains(&plan.plan_id)))
}

/// 领取一个套餐（`POST billing/claim`）。
///
/// 返回 `Err` 只用于「请求本身没打成」（网络 / 响应不是 JSON）；上游明确拒绝
/// （含验证码失败、已领过）一律走 `Ok(ClaimOutcome::Failed)` —— 那些是**业务
/// 结果**，调用方要靠 `failure` 决定下次何时再试。
pub fn claim_upstream(
    jwt: &str,
    plan_id: &str,
    captcha_verify_param: &str,
    captcha_region: Option<&str>,
    device_mid: Option<&str>,
) -> Result<ClaimOutcome> {
    if jwt.trim().is_empty() {
        return Ok(ClaimOutcome::Failed {
            plan_id: plan_id.to_string(),
            failure: ClaimFailure::LoginRequired,
            code: 401,
            message: "领取需要登录态（本账号没有 ZCode JWT）".to_string(),
            failure_ends_at: None,
        });
    }
    let url = format!("{}{CLAIM_PATH}", region::ZCODE_ORIGIN);
    // 头顺序与客户端一致：Authorization → Content-Type → 验证码 → 版本 → 平台
    // → 设备标识。顺序本身不是协议要求，但保持与参考实现同序便于逐条比对。
    //
    // ── 验证码头**只在有值时发**（一处容易想当然的地方）──────────
    // 上游的风控配置可能是 `enabled: false`（那一刻不要验证码），此时界面根本
    // 不会弹滑块、也就没有 verifyParam。若把空串也写成头，上游会把它当成
    // 「给了一个无效的验证串」而回 3007 —— 于是「不需要验证码」的那一刻反而
    // 领不了，而报错文案是「验证码校验未通过」，指向完全错误的方向。
    let mut headers: Vec<(String, String)> = vec![
        ("Authorization".to_string(), format!("Bearer {}", jwt.trim())),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let param = captcha_verify_param.trim();
    if !param.is_empty() {
        headers.push(("X-Aliyun-Captcha-Verify-Param".to_string(), param.to_string()));
    }
    if let Some(value) = captcha_region.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Aliyun-Captcha-Verify-Region".to_string(), value.to_string()));
    }
    headers.push(("X-ZCode-App-Version".to_string(), plan::app_version()));
    headers.push(("X-Platform".to_string(), plan::platform()));
    if let Some(mid) = device_mid.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    let body = json!({ "plan_id": plan_id });
    let reply = http::send("POST", &url, &headers, Some(&body))
        .map_err(|error| http::transport_error("套餐领取失败", &error))?;
    let biz_code = plan::biz_code(&reply.payload);
    let data = reply.payload.get("data");
    let plan = data.and_then(|value| value.get("plan"));
    // 成功：HTTP 2xx + biz code 0 + data.plan 存在（三者缺一不可 —— 只有它带
    // starts_at / ends_at）
    if (200..300).contains(&reply.status)
        && biz_code == Some(0)
        && reply.payload.get("success").and_then(Value::as_bool) != Some(false)
    {
        if let Some(plan) = plan.filter(|value| value.is_object()) {
            return Ok(ClaimOutcome::Claimed {
                plan_id: plan_id.to_string(),
                starts_at: plan.get("starts_at").and_then(integer_of),
                ends_at: plan.get("ends_at").and_then(integer_of),
            });
        }
    }
    // 失败：HTTP 层错误（无业务码）与业务码错误分开归类 —— 前者只有状态码可依
    // （401 判未登录，其余算 HTTP 错误），后者走 biz code 映射
    let failure = match biz_code {
        Some(code) => ClaimFailure::from_code(code),
        None if reply.status == 401 => ClaimFailure::LoginRequired,
        None => ClaimFailure::HttpError,
    };
    // 上游回了 3007 就把令牌池标记成「要验证码」（下一次推理请求会带）
    if failure == ClaimFailure::Captcha {
        captcha::note_challenge_and_require_token();
    }
    // 上游在失败响应里也可能带 plan（含 ends_at），那就是「下一个可尝试窗口」
    let failure_ends_at = plan
        .and_then(|value| value.get("ends_at"))
        .and_then(integer_of);
    Ok(ClaimOutcome::Failed {
        plan_id: plan_id.to_string(),
        failure,
        code: biz_code.unwrap_or(i64::from(reply.status)),
        message: {
            let text = text_of(&reply.payload, &["msg", "message"]);
            if text.is_empty() {
                format!("HTTP {}", reply.status)
            } else {
                text
            }
        },
        failure_ends_at,
    })
}

/// 营销活动回执（领到之后告诉上游「这个活动我领了」）。
///
/// 确认 POST 结果不确定时**不自动重发**，也不以 cancel 代替失败 —— 领没领到
/// 以 `claim` 的响应为准，回执只是运营统计。
pub fn marketing_confirm(jwt: &str, device_mid: Option<&str>, campaign_id: &str) -> Result<()> {
    let url = format!("{}{MARKETING_REPORT_PATH}", region::ZCODE_ORIGIN);
    let mut headers: Vec<(String, String)> = vec![
        ("X-Client-Language".to_string(), "zh-CN".to_string()),
        ("X-ZCode-App-Version".to_string(), plan::app_version()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    if !jwt.trim().is_empty() {
        headers.push(("Authorization".to_string(), format!("Bearer {}", jwt.trim())));
    }
    if let Some(mid) = device_mid.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    let body = json!({ "campaign_id": campaign_id, "action_type": "confirm" });
    let reply = http::send("POST", &url, &headers, Some(&body))
        .map_err(|error| http::transport_error("营销回执失败", &error))?;
    if !(200..300).contains(&reply.status) || plan::biz_code(&reply.payload) != Some(0) {
        return Err(Error::http(502, "营销回执失败：上游未确认"));
    }
    Ok(())
}

/// 激活事件上报（`POST {zcode}/api/v1/event/report`）—— 领取资格的解锁动作。
///
/// ── 为什么需要它（这是一条推断出来的因果，别当成可有可无的埋点）──
/// 领取有个先决条件：**账号得先被上游认成「今天活跃过」**。官方客户端的做法是
/// 启动 / 日活时打两条事件（`app_launch` / `app_daily_active`），运营系统据此
/// 发放资格，`preview` 才会把套餐列出来。本家走的不是客户端，那条链不会自动
/// 发生 —— 症状就是「明明有资格，探测却空 / 领取被判 1004」。
///
/// ── 端点特征（照参考实现，别自己发明）───────────────────────
///   · `{zcode_origin}/api/v1/event/report`，**两个地区同一个域**；
///   · **不带任何鉴权**：身份在请求体的 `user_id` + `device_mid` 里；
///   · 信封 `{code, msg}`，`code == 0` 才算成功；每条事件一个请求、一个新 UUID。
///
/// ── 两处环境取值在插件里取不到 ──────────────────────────────
/// native 用子进程读时区名（`tzutil`）与系统版本（注册表）。Wasm 沙盒起不了
/// 子进程，因此按 native 自己的兜底取值：时区 `unknown`、系统版本空串 ——
/// 那正是参考实现在认不出时的取值。
///
/// 返回 `Err` 是一句给用户看的原因；调用方**不因此把领取判失败**（上报是资格
/// 的前置动作，不是领取本身）。
pub fn report_activation(user_id: &str, device_mid: &str) -> std::result::Result<(), String> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err("该账号没有用户标识（手工粘贴 API Key 建的账号没有这一项），\
                    无法上报激活事件；用网页登录添加的账号才会带"
            .to_string());
    }
    let url = format!("{}{EVENT_REPORT_PATH}", region::ZCODE_ORIGIN);
    let mut first_error: Option<String> = None;
    for event in ["app_launch", "app_daily_active"] {
        // 每条事件一个**新** UUID：上游按 `event_id` 去重，重复用同一个会被判成
        // 重复事件（那正是「报了等于没报」）。
        let Some(event_id) = new_uuid() else {
            return Err(first_error
                .unwrap_or_else(|| "本机随机源不可用，无法生成事件 id（激活事件未上报）".to_string()));
        };
        let body = json!({
            "event_id": event_id,
            "client_timezone": "unknown",
            "client_language": "zh-CN",
            "element_name": event,
            "event_region": "app",
            "event_type": "view",
            "event_text": "",
            "event_extra_detail": {},
            "user_id": user_id,
            "screen_resolution": "2560x1440",
            "app_version": plan::app_version(),
            "device_os_category": plan::os_category(),
            // 插件取不到系统版本（native 读注册表）→ native 的兜底值
            "device_os_version": "",
            "device_mid": device_mid,
            // 这两个字段参考实现发的是空串 / 空对象的字符串形态，照抄
            "mac_id": "",
            "marketing_params": "{}",
        });
        let failure = match http::send("POST", &url, &[], Some(&body)) {
            Ok(reply) => {
                let code = reply.payload.get("code").and_then(integer_of).unwrap_or(-1);
                (code != 0).then(|| {
                    format!(
                        "激活事件上报被上游拒绝：{}",
                        {
                            let message = text_of(&reply.payload, &["msg", "message"]);
                            if message.is_empty() {
                                format!("业务码 {code}")
                            } else {
                                message
                            }
                        }
                    )
                })
            }
            Err(error) => Some(format!("激活事件上报失败：{}", error.message)),
        };
        if let Some(reason) = failure {
            if first_error.is_none() {
                first_error = Some(reason);
            }
        }
    }
    match first_error {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// 账号的 `jwt` / `deviceMid` / `userId` 三件套（领取链的入口参数）。
///
/// 缺 `jwt` 时给一句「这是账号形态问题」的文案（与 native `missing_jwt` 同义）：
/// 手工粘贴 API Key 建的账号领不了，那不是用户漏配了什么。
pub fn claim_context(secret: &Value) -> std::result::Result<(String, String, String), String> {
    let jwt = account::jwt(secret);
    if jwt.trim().is_empty() {
        return Err(format!(
            "该 ZCode {}账号没有套餐令牌（jwt），无法领取。请用网页登录重新添加，\
             或在账号里补填套餐 JWT",
            region::LABEL
        ));
    }
    Ok((
        jwt,
        account::device_mid(secret),
        account::user_id(secret),
    ))
}

/// 领取结果 → 界面读的 JSON（`claim` / `checkin.claim` 共用）。
pub fn outcome_json(outcome: &ClaimOutcome, marketing_error: Option<String>, claimed_at: Option<i64>) -> Value {
    match outcome {
        ClaimOutcome::Claimed {
            plan_id,
            starts_at,
            ends_at,
        } => json!({
            "claimed": true,
            "planId": plan_id,
            "startsAt": starts_at,
            "endsAt": ends_at,
            "marketingError": marketing_error,
            "claimedAt": claimed_at,
        }),
        ClaimOutcome::Failed {
            plan_id,
            failure,
            code,
            message,
            failure_ends_at,
        } => json!({
            "claimed": false,
            "planId": plan_id,
            "failure": failure.key(),
            "failureLabel": failure.label(),
            "code": code,
            "message": message,
            "failureEndsAt": failure_ends_at,
            "marketingError": marketing_error,
            "claimedAt": claimed_at,
        }),
    }
}
