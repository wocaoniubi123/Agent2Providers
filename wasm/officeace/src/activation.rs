//! 套餐开通（零元体验套餐）：`admin.action = subscription.preview` / `subscription.ensure`。
//!
//! ── 这一族动作的边界（每条都是刻意收窄的）─────────────────
//!   · **只买零元体验套餐**：下单前先查 SKU 定价，货币不是 CNY 或金额不是 0 就停，
//!     不购买付费套餐（[`zero_price_order`]）；
//!   · **只认官方网关**：账号基址不是 `*.officeace.cn-southwest-2.huaweicloud-
//!     agentarts.com` 时整条链拒绝（[`official_gateway`]）——这条链会真的下单；
//!   · **不自动续费**：订单参数写死 `auto_renewal: 0`，开通后再回读核对
//!     （[`no_auto_renew`]），读到「开了自动续费」如实告诉用户去官方客户端关；
//!   · **用户明确同意才动**：`ensure` 的 `confirmAgreements` 为 false 时一律不签协议、
//!     不下单；导入账号本身永远不触发这些动作；
//!   · **结果不确定就不重试**：`RESULT_UNCERTAIN` 折成 `pending`，并把
//!     「可能已提交」写进台账（[`Ledger`]）——重复下单比「用户多点一次查询」坏得多。
//!
//! ── 为什么这三个小模块（trial / agreement / 台账）合成一份 ────
//! native 把它们分成 `trial.rs` / `agreement.rs` / `activation_state.rs` 三个文件，
//! 但三者的调用点只有 `activation.rs` 一个，且共用「只认官方网关 + 结果不确定就不
//! 重试」这一套约束。合并之后这条链的顺序在这里能一眼读完，比跨四个文件拼起来可靠。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::credentials::{self, OfficeAceCredential};
use super::signer::Algorithm;
use super::{control, oauth, subscription, upstream, util};

// ── 常量 ─────────────────────────────────────────────────────

/// 零元体验套餐的 SKU 码。
pub const SKU: &str = "officeace.personal.package.trial";
/// 资源类型（华为云商品四段码的第三段）。
const RESOURCE_TYPE: &str = "hws.resource.type.agentarts.platform";
/// 套餐订单清单（只读）。
const RESOURCES: &str =
    "/v1/subscription/resources?type=OfficeAce&is_count_down_info=true&is_subscribed=true";
/// SKU 定价（零元校验用）。
const PRICING: &str = "/v1/skus/officeace.personal.package.trial?is_query_resource_rating=true&is_query_sales_cycle=true&period_type=2&period_num=1&product_num=1";
/// 服务声明路径（与官方客户端的 `privacy_statement` 一致）。
const STATEMENT: &str = "/declaration/officeace.html";
/// 台账键名。
const LEDGER: &str = "officeaceTrialOrder";
/// 「刚提交、还没生效」的判定窗口。
const PENDING_WINDOW_MS: i64 = 5 * 60 * 1000;
/// 开通后回读确认的次数与间隔（官方生效有延迟，实测 4 次 2 秒覆盖大多数情形）。
const CONFIRM_ROUNDS: u32 = 4;
const CONFIRM_INTERVAL_MS: u64 = 2_000;

// ── 视图与台账 ───────────────────────────────────────────────

/// `preview` 的返回形态：能不能动手 + 一句话原因。
fn view(status: &str, message: &str) -> Value {
    json!({
        "status": status,
        "canActivate": status == "inactive",
        "message": message,
        "checkedAt": util::now_ms(),
    })
}

/// `ensure` 的返回形态：这次做了什么。
fn report(status: &str, message: &str) -> Value {
    json!({ "status": status, "message": message, "checkedAt": util::now_ms() })
}

/// 台账：`{identity, status, submittedAt, sku, autoRenew, order_id…}`。
///
/// ── 它存在的理由 ────────────────────────────────────────────
/// 「下单」是一次**不可逆**的写动作，而网络在提交之后、响应之前断掉是完全可能的。
/// 台账在提交**之前**先落一条 `submitting`，之后无论是超时、插件重启还是调用方
/// 放弃，下一次进来都能看到「上一轮可能已经提交过」，从而选择「查询」而不是
/// 「再提交一次」。
fn ledger_identity(credential: &OfficeAceCredential) -> String {
    // 与 native `activation_state::identity` 同源：基址 + app key 的 sha256 前 16 字节
    let digest = super::p256::sha256(format!("{}|{}", credential.base_url, credential.model_app_key).as_bytes());
    util::hex_lower(&digest[..16])
}

fn ledger_for_credential(value: &Value, credential: &OfficeAceCredential) -> bool {
    value.get("identity").and_then(Value::as_str) == Some(ledger_identity(credential).as_str())
}

fn ledger_read() -> Result<Value> {
    Ok(control::ledger_get(LEDGER))
}

fn ledger_write(value: &Value) -> Result<()> {
    control::ledger_put(LEDGER, value).map_err(|error| {
        Error::http(
            502,
            format!("无法保存套餐开通记录，请先查询官方结果，勿重复提交：{}", error.message),
        )
    })
}

fn submitted(credential: &OfficeAceCredential) -> Value {
    json!({
        "identity": ledger_identity(credential),
        "status": "submitting",
        "submittedAt": util::now_ms(),
        "sku": SKU,
        "autoRenew": false,
    })
}

/// 台账说「上一轮还没落定」时给出该显示什么。
fn pending_view(ledger: &Value, resources: &[Value]) -> Option<Value> {
    if ledger.get("status").and_then(Value::as_str) == Some("active") {
        return Some(view(
            "expired",
            "这条账号曾开通过体验套餐，当前已无有效套餐；这里不会自动续费或重新购买",
        ));
    }
    if ledger.get("status").and_then(Value::as_str) == Some("rejected") {
        return None;
    }
    let submitted_at = ledger.get("submittedAt").and_then(Value::as_i64)?;
    let old = util::now_ms().saturating_sub(submitted_at) >= PENDING_WINDOW_MS;
    if has_open_order(resources) && !old {
        return Some(view(
            "pending",
            "官方存在未完成或正在生效的套餐订单，请稍后查询；不会重复下单",
        ));
    }
    Some(if old {
        view(
            "unknown",
            "开通已超过确认时间，但尚未查到生效套餐；为避免重复下单，请到官方客户端核对订单",
        )
    } else {
        view(
            "pending",
            "零元套餐订单已提交，正在等待官方生效，请稍后查询，不要重复提交",
        )
    })
}

// ── trial：资源、定价、订单 ──────────────────────────────────

/// 读套餐订单清单（会走续期重试）。
fn resources(credential: &mut OfficeAceCredential) -> Result<Vec<Value>> {
    let value = control::cloud_call(credential, "GET", RESOURCES, None)?;
    resource_rows(value)
}

/// 读套餐订单清单（只读，不续期）。
fn resources_readonly(credential: &OfficeAceCredential) -> Result<Vec<Value>> {
    let value = upstream::call(
        credential,
        "GET",
        &format!("{}{RESOURCES}", oauth::CLOUD_BASE),
        Algorithm::Sdk,
        None,
        &[],
    )?;
    resource_rows(value)
}

fn resource_rows(value: Value) -> Result<Vec<Value>> {
    value.as_array().cloned().ok_or_else(|| {
        Error::http(502, "官方未返回有效的套餐订单清单，暂不能确认是否可开通")
    })
}

/// 构造零元体验套餐的订单体（**先验价再下单**）。
fn zero_price_order(credential: &mut OfficeAceCredential) -> Result<Value> {
    let offer = control::cloud_call(credential, "GET", PRICING, None)?;
    let rating = offer.get("resource_rating").unwrap_or(&Value::Null);
    if offer.get("sku_code").and_then(Value::as_str) != Some(SKU)
        || offer.get("status").and_then(Value::as_str) != Some("active")
        || offer.get("purchase_model").and_then(Value::as_str) != Some("PERIOD")
        || offer.get("sub_product_code").and_then(Value::as_str) != Some(RESOURCE_TYPE)
        || rating.get("currency").and_then(Value::as_str) != Some("CNY")
        || !rating.get("amount").is_some_and(is_zero)
    {
        return Err(Error::http(
            409,
            "官方未确认个人体验套餐为零元，已停止开通；不会购买付费套餐",
        ));
    }
    let cycles: Vec<&Value> = offer
        .get("product_sales_cycles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|cycle| {
            cycle.get("status").and_then(Value::as_str) == Some("ONSALE")
                && cycle.get("resourceSpecCode").and_then(Value::as_str) == Some(SKU)
                && cycle.get("resourceType").and_then(Value::as_str) == Some(RESOURCE_TYPE)
                && cycle
                    .get("regionList")
                    .and_then(Value::as_array)
                    .is_some_and(|regions| {
                        regions.iter().any(|region| {
                            region.get("regionCode").and_then(Value::as_str) == Some(oauth::REGION)
                        })
                    })
                && cycle
                    .get("periodList")
                    .and_then(Value::as_array)
                    .is_some_and(|periods| {
                        periods.iter().any(|period| {
                            period.get("periodType").and_then(Value::as_str) == Some("MONTH")
                                && period
                                    .get("periodValueList")
                                    .and_then(Value::as_array)
                                    .is_some_and(|values| {
                                        values.iter().any(|value| is_one(&value["value"]))
                                    })
                        })
                    })
        })
        .collect();
    if cycles.len() != 1 {
        return Err(Error::http(
            409,
            "未找到唯一的零元一个月体验套餐，已停止开通",
        ));
    }
    let atomic = cycles[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| Error::http(502, "官方未返回体验套餐的产品标识，未提交订单"))?;
    Ok(json!({
        "service_type": "hws.service.type.agentarts",
        "subscribe_period_type": 2,
        "subscribe_period_value": 1,
        "auto_renewal": 0,
        "auto_pay": 1,
        "subscribe_sku_info": {
            "subscribe_quantity": 1,
            "subscribe_sku_code": SKU,
            "subscribe_sub_product_code": RESOURCE_TYPE,
            "subscribe_atomic_product_id": atomic,
        },
        "agreement_list": [{
            "agree_declaration": 1,
            "version": "1.0",
            "privacy_statement": "/declaration/agentarts.html",
        }],
    }))
}

/// 数值是不是「零」（上游有时给 `0`，有时给 `"0.00"`）。
fn is_zero(value: &Value) -> bool {
    if let Some(number) = value.as_number() {
        return number.to_string().chars().all(|ch| matches!(ch, '0' | '.'));
    }
    value.as_str().is_some_and(|text| {
        let text = text.trim();
        !text.is_empty()
            && text.chars().any(|ch| ch == '0')
            && text.chars().all(|ch| matches!(ch, '0' | '.'))
            && text.matches('.').count() <= 1
    })
}

fn is_one(value: &Value) -> bool {
    value.as_str() == Some("1") || value.as_u64() == Some(1)
}

/// 订单清单里「自动续费」的结论：`Some(true)` = 确认已关，`Some(false)` = 还开着。
fn no_auto_renew(rows: &[Value]) -> Option<bool> {
    let trials: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row.get("sku_code").and_then(Value::as_str) == Some(SKU)
                && row.get("status").and_then(Value::as_str) == Some("SUBSCRIBED")
        })
        .collect();
    if trials.is_empty() {
        return None;
    }
    let mut known = false;
    for row in trials {
        match row.get("is_auto_renew") {
            Some(value) if is_zero(value) => known = true,
            Some(value) if is_one(value) => return Some(false),
            _ => return None,
        }
    }
    known.then_some(true)
}

/// 清单里有没有「未完成 / 正在生效」的订单。
fn has_open_order(rows: &[Value]) -> bool {
    rows.iter().any(|row| {
        !matches!(
            row.get("status").and_then(Value::as_str),
            Some("FAILED" | "CANCELLED" | "CANCELED" | "UNSUBSCRIBED" | "EXPIRED" | "DELETED")
        )
    })
}

fn apply_renewal(result: &mut Value, rows: &[Value]) {
    match no_auto_renew(rows) {
        Some(true) => {
            result["autoRenew"] = json!(false);
            result["message"] = json!("体验套餐已生效，自动续费已关闭");
        }
        Some(false) => {
            result["autoRenew"] = json!(true);
            result["message"] = json!("套餐已生效，但官方返回自动续费已开启，请到官方客户端检查");
        }
        None => {
            result["message"] = json!("套餐已生效，不续费状态尚待官方同步，请稍后查询确认");
        }
    }
}

// ── agreement：服务声明 ──────────────────────────────────────

fn statements(value: &Value) -> Result<Vec<Value>> {
    let rows = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "官方未返回有效的服务声明清单，未自动确认协议"))?;
    if rows.is_empty()
        || rows.iter().any(|row| {
            row.get("type").and_then(Value::as_str) != Some("officeclaw")
                || row.get("privacy_statement").and_then(Value::as_str) != Some(STATEMENT)
                || row
                    .get("version")
                    .and_then(Value::as_str)
                    .is_none_or(|version| version.trim().is_empty())
        })
    {
        return Err(Error::http(
            409,
            "官方服务声明已变化，请在官方客户端查看并确认后再开通",
        ));
    }
    Ok(rows.clone())
}

fn accepted(row: &Value) -> bool {
    row.get("agree_flag")
        .or_else(|| row.get("agree_declaration"))
        .is_some_and(|value| value.as_str() == Some("1") || value.as_i64() == Some(1))
}

/// 确认服务声明（只在用户明确同意之后调用）。
fn confirm_agreement(credential: &mut OfficeAceCredential) -> Result<()> {
    let current = control::cloud_call(credential, "GET", "/v1/agreement?biz_type=officeclaw", None)?;
    let rows = statements(&current)?;
    let pending: Vec<Value> = rows
        .iter()
        .filter(|row| !accepted(row))
        .map(|row| {
            json!({
                "privacy_statement": STATEMENT,
                "version": row["version"],
                "agree_declaration": 1,
            })
        })
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let submitted = control::cloud_call(
        credential,
        "POST",
        "/v1/agreement",
        Some(json!({ "agreement_list": pending })),
    );
    if let Err(error) = &submitted {
        // 结果不确定时继续走回读确认（读得回来就算成）
        if error.code.as_deref() != Some(upstream::RESULT_UNCERTAIN) {
            return Err(error.clone());
        }
    }
    let checked = control::cloud_call(credential, "GET", "/v1/agreement?biz_type=officeclaw", None)?;
    if statements(&checked)?.iter().all(accepted) {
        Ok(())
    } else {
        Err(Error::http(
            409,
            "服务声明尚未确认生效，未提交套餐订单；请稍后查询或在官方客户端确认",
        ))
    }
}

// ── 官方网关校验 ────────────────────────────────────────────

/// 账号基址是不是官方果办网关。
///
/// ── 为什么要这条 ────────────────────────────────────────────
/// 这一族动作会在**云端真的下单**（零元也算一笔）。用户把 `baseUrl` 指向自建代理时，
/// 「套餐状态」「订单清单」这些读数都来自代理而不是官方 —— 用它来决定下单等于把
/// 一个第三方读数当成华为云的权威状态。所以这里只认官方域名，其余一律拒绝。
///
/// native 用 `url::Url::parse` 逐项校验；wasm 侧依赖清单里没有 `url`，这里按同一
/// 组条件手写校验（scheme / userinfo / 端口 / query / fragment / path / host 后缀）。
fn official_gateway(base_url: &str) -> Result<()> {
    let invalid = || Error::http(400, "账号未使用官方果办网关地址，未开通免费套餐");
    let rest = base_url.trim().split_once("://").map(|(scheme, rest)| {
        if scheme != "https" {
            return Err(invalid());
        }
        Ok(rest)
    });
    let rest = match rest {
        Some(Ok(rest)) => rest,
        _ => return Err(invalid()),
    };
    if rest.contains('?') || rest.contains('#') {
        return Err(invalid());
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.contains('@') || authority.is_empty() {
        return Err(invalid());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if port.is_some_and(|port| port != "443") {
        return Err(invalid());
    }
    if path.trim_end_matches('/') != "" && path.trim_end_matches('/') != "/v2" {
        return Err(invalid());
    }
    if !host.ends_with(".officeace.cn-southwest-2.huaweicloud-agentarts.com") {
        return Err(invalid());
    }
    Ok(())
}

// ── 对外：preview / ensure ──────────────────────────────────

/// `subscription.preview`：只读地告诉用户「能不能开通、为什么」。
///
/// **一个写请求都不发**：不签协议、不下单、不续期（临期就在文案里说清楚）。
pub fn preview() -> Result<Value> {
    let secret = credentials::secret()?;
    let credential = credentials::from_record(Some(&secret))?;
    if !credential.has_control_plane() || credential.security_token.is_empty() {
        return Ok(view(
            "credentials_missing",
            "缺少套餐开通凭证，请通过果办网页登录补齐授权",
        ));
    }
    if official_gateway(&credential.base_url).is_err() {
        return Ok(view(
            "unsupported",
            "账号未使用官方果办网关地址，无法在此开通免费套餐",
        ));
    }
    if credential.expires_at > 0 && credential.expires_at <= util::now_ms() {
        return Ok(view(
            "credentials_expired",
            "套餐查询凭证已过期，请先到账号页刷新凭证；此查询不会自动续期",
        ));
    }
    let snapshot = match subscription::fetch_subscription(&credential) {
        Ok(snapshot) => snapshot,
        Err(error) if error.code.as_deref() == Some(upstream::CONTROL_TOKEN_EXPIRED) => {
            return Ok(view("credentials_expired", &error.message))
        }
        Err(error) if matches!(error.status, Some(401) | Some(403)) => {
            return Ok(view("permission_denied", &error.message))
        }
        Err(error) => return Err(error),
    };
    let status = snapshot.get("subscribe_status").and_then(Value::as_str);
    let ledger = ledger_read()?;
    let own_ledger = ledger_for_credential(&ledger, &credential);
    if status == Some("SUBSCRIBED") {
        let mut result = view("active", "套餐已开通，无需重复操作");
        let has_trial = own_ledger
            || snapshot.get("skus").and_then(Value::as_array).is_some_and(|rows| {
                rows.iter()
                    .any(|row| row.get("sku_code").and_then(Value::as_str) == Some(SKU))
            });
        if has_trial {
            if let Ok(rows) = resources_readonly(&credential) {
                apply_renewal(&mut result, &rows);
            }
        }
        return Ok(result);
    }
    if status == Some("UNSUBSCRIBED") {
        let rows = resources_readonly(&credential)?;
        if own_ledger {
            if let Some(result) = pending_view(&ledger, &rows) {
                return Ok(result);
            }
        }
        if has_open_order(&rows) {
            return Ok(view(
                "unknown",
                "官方存在未完成或正在生效的套餐订单，请到官方客户端核对；这里不会重复下单",
            ));
        }
        if !rows.is_empty() {
            return Ok(view(
                "expired",
                "官方已有历史套餐记录，这里不会重复购买或续费；请在官方客户端处理",
            ));
        }
        return Ok(view(
            "inactive",
            "尚未开通套餐，可确认服务协议后开通零元体验套餐，不自动续费",
        ));
    }
    Ok(match status {
        Some("EXPIRED") => view(
            "expired",
            "原套餐已到期，请在官方客户端处理；这里不会自动续费或变更套餐",
        ),
        Some("FROZEN") => view(
            "frozen",
            "原套餐已冻结，请在官方客户端处理；这里不会自动续费或变更套餐",
        ),
        _ => view("unknown", "官方未返回明确的套餐状态，暂不能开通"),
    })
}

/// `subscription.ensure`：用户明确同意后，开通零元体验套餐并确认生效。
///
/// `consent = false` 时整条链只走到「检查」，不签协议、不下单。
pub fn ensure(consent: bool) -> Result<Value> {
    // 单飞：同一账号同时只允许一轮开通（重复点击不该产生两笔订单）
    let _lock = AccountLock::acquire()?;
    let secret = credentials::secret()?;
    let initial = credentials::from_record(Some(&secret))?;
    if !initial.has_control_plane() || initial.security_token.is_empty() {
        return Ok(report(
            "skipped",
            "缺少套餐开通凭证，请通过果办网页登录补齐授权",
        ));
    }
    official_gateway(&initial.base_url)?;
    let mut credential = control::credential_of()?;
    official_gateway(&credential.base_url)?;
    let before = control::subscription_of(&mut credential)?;
    match before.get("subscribe_status").and_then(Value::as_str) {
        Some("SUBSCRIBED") => {
            let mut result = report("already_active", "套餐已开通，无需重复操作");
            if let Ok(rows) = resources(&mut credential) {
                apply_renewal(&mut result, &rows);
            }
            return Ok(result);
        }
        Some("UNSUBSCRIBED") => {}
        Some("EXPIRED" | "FROZEN") => {
            return Ok(report(
                "skipped",
                "原套餐已到期或冻结，未自动变更或续费；请在官方客户端检查套餐",
            ))
        }
        _ => return Ok(report("skipped", "官方未返回明确的套餐状态，未自动开通")),
    }
    if !consent {
        return Ok(report(
            "skipped",
            "尚未开通体验套餐，请到签到中心确认服务协议后开通；导入账号不会自动同意协议或下单",
        ));
    }
    let ledger = ledger_read()?;
    control::resolve_project(&mut credential)?;
    let rows = resources(&mut credential)?;
    if ledger_for_credential(&ledger, &credential) {
        if let Some(result) = pending_view(&ledger, &rows) {
            return Ok(report(
                if result["status"] == "pending" { "pending" } else { "skipped" },
                result["message"].as_str().unwrap_or("请先核对已有订单"),
            ));
        }
    }
    if !rows.is_empty() {
        return Ok(report(
            "skipped",
            "官方已有套餐或历史订单，请在官方客户端核对；这里不会续费或重复购买",
        ));
    }
    verify_identity(&credential, &secret)?;
    // 协议确认和零元订单都只在用户明确同意后执行；可选的数据改进授权不在此流程中。
    zero_price_order(&mut credential)?;
    confirm_agreement(&mut credential)?;
    let body = zero_price_order(&mut credential)?;
    let latest = control::subscription_of(&mut credential)?;
    if latest.get("subscribe_status").and_then(Value::as_str) == Some("SUBSCRIBED") {
        return Ok(report("already_active", "套餐已开通，无需重复操作"));
    }
    if latest.get("subscribe_status").and_then(Value::as_str) != Some("UNSUBSCRIBED")
        || !resources(&mut credential)?.is_empty()
    {
        return Ok(report(
            "skipped",
            "套餐或订单状态已变化，未提交新订单，请重新查询",
        ));
    }
    // 提交前落盘；即使插件被换掉或调用方超时，也不会遗忘可能已到达上游的订单。
    let mut attempt = submitted(&credential);
    ledger_write(&attempt)?;
    let order = control::cloud_call(
        &mut credential,
        "POST",
        "/v1/subscription/period",
        Some(body),
    );
    match order {
        Ok(value) => {
            attempt["status"] = json!("submitted");
            for key in ["order_id", "cbc_order_id"] {
                if let Some(value) = value.get(key).and_then(Value::as_str) {
                    attempt[key] = json!(value);
                }
            }
            ledger_write(&attempt)?;
        }
        Err(error) if error.code.as_deref() == Some(upstream::RESULT_UNCERTAIN) => {
            return Ok(report(
                "pending",
                "零元套餐请求结果暂未确认，请稍后查询；不会自动重复下单",
            ))
        }
        Err(error) => {
            attempt["status"] = json!("rejected");
            ledger_write(&attempt)?;
            return Err(error);
        }
    }
    for index in 0..CONFIRM_ROUNDS {
        if index > 0 {
            let _ = sdk::sleep(CONFIRM_INTERVAL_MS);
        }
        let snapshot = match control::subscription_of(&mut credential) {
            Ok(value) => value,
            Err(_) => break,
        };
        if snapshot.get("subscribe_status").and_then(Value::as_str) != Some("SUBSCRIBED") {
            continue;
        }
        let resources = match resources(&mut credential) {
            Ok(value) => value,
            Err(_) => break,
        };
        let mut result = report("activated", "零元体验套餐已开通并确认生效，自动续费已关闭");
        match no_auto_renew(&resources) {
            Some(true) => {
                attempt["status"] = json!("active");
                ledger_write(&attempt)?;
                result["autoRenew"] = json!(false);
                return Ok(result);
            }
            Some(false) => {
                attempt["status"] = json!("active");
                ledger_write(&attempt)?;
                result["message"] = json!(
                    "套餐已生效，但官方返回自动续费已开启，与提交参数不符；请立即在官方客户端检查"
                );
                result["autoRenew"] = json!(true);
                return Ok(result);
            }
            None => {}
        }
    }
    Ok(report(
        "pending",
        "零元套餐订单已提交，正在等待套餐和不续费状态确认，请稍后查询",
    ))
}

/// 下单前核对「云端说的身份」与「账号记录里的身份」是不是同一个人。
///
/// ── 为什么要这一步 ──────────────────────────────────────────
/// 账号记录里的 `accountId` / `principalId` 是登录时写下的；而控制面凭据可能
/// 已经被续期过几轮。两者不一致意味着「这个账号的凭据被换成了别人的」——
/// 用别人的身份下单，比不下单严重得多。
fn verify_identity(credential: &OfficeAceCredential, record: &Value) -> Result<()> {
    let signing = credential.signing().map_err(|reason| Error::http(502, reason))?;
    let (account, principal, model_info) =
        oauth::fetch_permission(&signing).map_err(|message| Error::http(502, message))?;
    for (key, actual) in [("accountId", account.as_str()), ("principalId", principal.as_str())] {
        let expected = util::text(record, &[key]);
        if actual.is_empty() || !expected.is_empty() && expected != actual {
            return Err(Error::http(409, "果办登录身份与账号记录不一致，未开通套餐"));
        }
    }
    let (base, key, secret) = oauth::gateway_of(&model_info).map_err(|reason| Error::http(502, reason))?;
    if super::chat::normalize_base(&base) != super::chat::normalize_base(&credential.base_url)
        || key != credential.model_app_key
        || secret != credential.model_app_secret
    {
        return Err(Error::http(409, "果办模型凭证与登录身份不一致，未开通套餐"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_gateway_accepts_only_the_real_host() {
        assert!(official_gateway(
            "https://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2"
        )
        .is_ok());
        assert!(official_gateway(
            "https://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com"
        )
        .is_ok());
        // 自建代理 / 非官方域名 / 非 https / 带 query / 非 443 端口 一律拒绝
        assert!(official_gateway("https://gw.example.com/v2").is_err());
        assert!(official_gateway("http://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com").is_err());
        assert!(official_gateway(
            "https://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2?x=1"
        )
        .is_err());
        assert!(official_gateway(
            "https://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com:8443/v2"
        )
        .is_err());
        assert!(official_gateway(
            "https://user@abc.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2"
        )
        .is_err());
        assert!(official_gateway(
            "https://abc.officeace.cn-southwest-2.huaweicloud-agentarts.com/v1"
        )
        .is_err());
    }

    #[test]
    fn zero_and_one_cover_the_forms_the_upstream_sends() {
        assert!(is_zero(&json!(0)));
        assert!(is_zero(&json!("0.00")));
        assert!(is_zero(&json!("0")));
        assert!(!is_zero(&json!(1)));
        assert!(!is_zero(&json!("0.01")));
        assert!(!is_zero(&json!("")));
        assert!(is_one(&json!(1)));
        assert!(is_one(&json!("1")));
        assert!(!is_one(&json!(0)));
    }

    #[test]
    fn open_order_ignores_closed_states() {
        assert!(!has_open_order(&[]));
        assert!(has_open_order(&[json!({ "status": "SUBSCRIBED" })]));
        assert!(!has_open_order(&[json!({ "status": "EXPIRED" })]));
        assert!(!has_open_order(&[json!({ "status": "CANCELLED" })]));
        // 没有 status 的条目按「未完成」处理（宁可让用户去核对，也不重复下单）
        assert!(has_open_order(&[json!({})]));
    }

    #[test]
    fn auto_renew_conclusions() {
        assert_eq!(no_auto_renew(&[]), None);
        let rows = vec![json!({ "sku_code": SKU, "status": "SUBSCRIBED", "is_auto_renew": 0 })];
        assert_eq!(no_auto_renew(&rows), Some(true));
        let rows = vec![json!({ "sku_code": SKU, "status": "SUBSCRIBED", "is_auto_renew": "1" })];
        assert_eq!(no_auto_renew(&rows), Some(false));
        let rows = vec![json!({ "sku_code": SKU, "status": "SUBSCRIBED" })];
        assert_eq!(no_auto_renew(&rows), None);
    }

    #[test]
    fn views_carry_the_right_status_mapping() {
        assert_eq!(view("inactive", "x")["canActivate"], json!(true));
        assert_eq!(view("active", "x")["canActivate"], json!(false));
        assert!(report("skipped", "x").get("canActivate").is_none());
    }

    #[test]
    fn ledger_identity_is_stable_and_credential_bound() {
        let credential = OfficeAceCredential {
            base_url: "https://gw/v2".to_string(),
            model_app_key: "app-key".to_string(),
            ..Default::default()
        };
        let identity = ledger_identity(&credential);
        assert_eq!(identity.len(), 32);
        assert!(ledger_for_credential(&json!({ "identity": identity }), &credential));
        let other = OfficeAceCredential {
            base_url: "https://gw/v2".to_string(),
            model_app_key: "another-key".to_string(),
            ..Default::default()
        };
        assert!(!ledger_for_credential(&json!({ "identity": identity }), &other));
    }
}
