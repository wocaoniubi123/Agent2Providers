//! 管理动作（`admin.action`）：登录方式声明、验证码令牌池、提示词信息、
//! 风控配置与领取（native `zcode/admin.rs` + `mod.rs::admin_action` 的移植）。
//!
//! ── 形状为什么照抄网关 ──────────────────────────────────────
//! 这几个动作对应的前端界面读的是 `api::zcode_claim` 的既有键名（`deployed` /
//! `failureLabel` / `activated` / `failure` …）。形状一变界面就白屏，所以逐字
//! 复刻，不做「统一格式」的整理。
//!
//! ── 与 native 的两处删减（逐条列清）────────────────────────
//!   · `claim.verification.poll` / `claim.verification.complete`：native 有一个
//!     「向已连接的管理界面请求一次官方 SDK 验证」的进程内 broker。插件没有
//!     「已连接界面」这条通道，等价能力由界面在 `claim.claim` 里直接带上
//!     `captchaVerifyParam`（同一个入口、人工触发）。这两个动作名在此**明确
//!     报错**，不返回一个假装成功的空结果。
//!   · `claim.captcha-config` 的进程内缓存：native 让调用方决定要不要缓存
//!     （一次领取取一次）。插件每次都打一次上游 —— 低频动作，值得简单。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{text_of, urlencode};
use super::{account, captcha, checkin, claim, http, login, plan, region, system_prompt};

/// 风控配置的路径（`data.configs.captcha` 里是阿里云 SDK 的三个必填项）。
const CLIENT_CONFIGS_PATH: &str = "/api/v1/client/configs";

/// 管理动作分派。
pub fn action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    match action {
        // 登录方式声明（界面据此渲染那颗「网页登录」按钮）。形状必须是网关的
        // 动态契约 `LoginMethodsMetadata`（见 `login::login_methods`），
        // 元数据里那份 `{kind, button, hint}` 会让整片报 502。
        "auth.methods" => Ok(login::login_methods(locale_of(params))),
        // 本家没有限额来源上报（余额是余额桶 / 窗口比例，不是「来源登记」）
        "quota.sources" => Ok(json!([])),
        // 网关自带提示词的三段正文与字符数（设置页那一栏的说明用）
        "prompt.info" => Ok(system_prompt::prompt_info()),
        // 验证码令牌池（界面铸造完成后推进来）
        "captcha.push" => push_tokens(&params["payload"]),
        "captcha.stats" => Ok(captcha::stats()),
        // 风控配置（滑块要不要弹、SDK 的三个必填项）
        "claim.captcha-config" => captcha_config(),
        // 领取类活动的只读状态（界面点开活动福利卡时看到的清单）
        "claim.preview" => preview(),
        // 领取（`payload.planId` 点名，空串 = 领第一个可领的）
        "claim.claim" => claim_action(&params["payload"]),
        // 签到（`checkin.claim` 的同一实现，界面那颗「签到」按钮也可以走这条）
        "checkin.claim" => checkin::claim_daily(),
        other if other.starts_with("claim.verification.") => Err(Error::http(
            501,
            "ZCode 的自动验证编排需要已连接的管理界面，插件侧请在领取时直接带上验证参数",
        )),
        other => Err(Error::http(
            400,
            format!(
                "ZCode 不认识管理动作「{other}」（可用：auth.methods / quota.sources / \
                 prompt.info / captcha.push / captcha.stats / claim.captcha-config / \
                 claim.preview / claim.claim / checkin.claim）"
            ),
        )),
    }
}

/// 取界面传来的 locale。
///
/// 网关的 `read_login_methods` 把它放在 `params["locale"]`；也认
/// `params["payload"]["locale"]`（`admin.action` 的常规信封），两种都兜住，
/// 缺省 `zh-CN`（本包元数据只有中文一份，locale 目前不参与取值）。
fn locale_of(params: &Value) -> &str {
    params["payload"]["locale"]
        .as_str()
        .or_else(|| params["locale"].as_str())
        .unwrap_or("zh-CN")
}

/// `captcha.push`：把界面铸造的令牌推进池子。
fn push_tokens(payload: &Value) -> Result<Value> {
    let accepted = payload
        .get("tokens")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    let param = item
                        .get("param")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .unwrap_or("");
                    if param.is_empty() {
                        return false;
                    }
                    let region_text = item.get("region").and_then(Value::as_str).unwrap_or("");
                    captcha::push(param, region_text);
                    true
                })
                .count()
        })
        .unwrap_or(0);
    Ok(json!({ "accepted": accepted, "ready": captcha::ready() }))
}

/// `claim.captcha-config`：取上游的风控配置（滑块要不要弹）。
///
/// 只有上游明确 `enabled: false` 才允许免验证，配置缺失不能当成关闭 ——
/// 这条判据在 native 里就是一处显式分支（`Ok(None)` = 配置不完整）。
fn captcha_config() -> Result<Value> {
    let url = format!(
        "{}{CLIENT_CONFIGS_PATH}?app_version={}&platform={}",
        region::ZCODE_ORIGIN,
        urlencode(&plan::app_version()),
        urlencode(&plan::platform())
    );
    let reply = http::send("GET", &url, &[], None)
        .map_err(|error| http::transport_error("领取验证配置查询失败", &error))?;
    if !(200..300).contains(&reply.status) {
        return Err(Error::http(
            502,
            format!("领取验证配置查询失败：HTTP {}", reply.status),
        ));
    }
    let config = reply.payload.pointer("/data/configs/captcha");
    let enabled = config
        .and_then(|value| value.get("enabled"))
        .and_then(Value::as_bool);
    let Some(enabled) = enabled else {
        return Err(Error::http(502, "领取验证配置不完整，请稍后重试"));
    };
    let prefix = text_of(config.unwrap_or(&Value::Null), &["prefix"]);
    let scene_id = text_of(config.unwrap_or(&Value::Null), &["sceneId", "scene_id"]);
    let captcha_region = text_of(config.unwrap_or(&Value::Null), &["region"]);
    let skip_model_request = config
        .and_then(|value| value.get("skip_model_request"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // 只有 enabled 为真时才要求 SDK 字段齐全（关闭时允许省略场景字段）
    if enabled && (prefix.is_empty() || scene_id.is_empty()) {
        return Err(Error::http(502, "领取验证配置不完整，请稍后重试"));
    }
    captcha::apply_config(enabled, skip_model_request);
    captcha::note_synced();
    Ok(json!({
        "enabled": enabled,
        "prefix": prefix,
        "sceneId": scene_id,
        "region": captcha_region,
        "skipModelRequest": skip_model_request,
    }))
}

/// `claim.preview`：探测当前可领的套餐（只读；界面活动卡的内容）。
///
/// ── 一处**有副作用**的分支（别当成纯只读）────────────────────
/// 探测结果为空时补报激活事件再重探一次 —— 空列表可能只是资格没登记，而那是
/// 本家不跑官方客户端的必然结果。列表非空时不报（读写分开的口径只在这一处被
/// 打破：预览是低频的用户点击动作，代价付得起）。
fn preview() -> Result<Value> {
    let record = account::require_account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    let (jwt, device_mid, user_id) = claim::claim_context(&secret)
        .map_err(|message| Error::http(400, message))?;
    let mid = if device_mid.trim().is_empty() {
        account::device_mid_or_create()?.unwrap_or_default()
    } else {
        device_mid
    };
    let mid_ref = (!mid.trim().is_empty()).then_some(mid.as_str());
    let mut snapshot = claim::preview(&jwt, mid_ref, true)?;
    if snapshot.plans.is_empty() && snapshot.deployed && !user_id.trim().is_empty() {
        let (activated, activation_error) = match claim::report_activation(&user_id, &mid) {
            Ok(()) => (Some(true), None),
            Err(reason) => (Some(false), Some(reason)),
        };
        snapshot.activated = activated;
        snapshot.activation_error = activation_error.clone();
        if let Ok(retried) = claim::preview(&jwt, mid_ref, true) {
            snapshot = retried;
            snapshot.activated = activated;
            snapshot.activation_error = activation_error;
        }
    }
    Ok(snapshot.to_json())
}

/// `claim.claim`：补报激活 →（没点名就探一次选优先级最高的）→ 领取。
///
/// 失败也返回 `Ok`（业务结果不是 HTTP 错误）：`already_claimed` /
/// `quota_exhausted` / `captcha` 都是正常结果，前端要靠 `failure` 给不同提示。
fn claim_action(payload: &Value) -> Result<Value> {
    let record = account::require_account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    let (jwt, device_mid, user_id) = claim::claim_context(&secret)
        .map_err(|message| Error::http(400, message))?;
    let mid = if device_mid.trim().is_empty() {
        account::device_mid_or_create()?.unwrap_or_default()
    } else {
        device_mid
    };
    let mid_ref = (!mid.trim().is_empty()).then_some(mid.as_str());
    let captcha_verify_param = payload
        .get("captchaVerifyParam")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    // 空值**放行**：上游的风控配置可能是「此刻不要验证码」，拦在这里会让
    // 「不需要验证码」的那一刻反而领不了。有没有值交给上游判（要就回 3007）。
    let captcha_region = payload
        .get("captchaRegion")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    // 补报激活（资格的前置动作；失败如实带回响应，不阻断领取）
    let (activated, activation_error) = if user_id.trim().is_empty() {
        // 手工粘贴 API Key 建的账号没有 userId：报也归不到名下
        (None, None)
    } else {
        match claim::report_activation(&user_id, &mid) {
            Ok(()) => (Some(true), None),
            Err(reason) => (Some(false), Some(reason)),
        }
    };
    let requested = payload
        .get("planId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let Some(target) = claim::resolve_target(&jwt, mid_ref, &requested)? else {
        return Ok(json!({
            "ok": false,
            "failure": "unavailable",
            "message": "当前没有可领取的套餐",
            "activated": activated,
            "activationError": activation_error,
        }));
    };
    let attempt = claim::claim_upstream(
        &jwt,
        &target.plan_id,
        &captcha_verify_param,
        captcha_region,
        mid_ref,
    )?;
    let claimed_at = Some(super::common::now_ms());
    let mut result = claim::outcome_json(&attempt, None, claimed_at);
    // 营销活动：领到之后回执一次（失败只记进 marketingError，不影响领取结果）
    if matches!(&attempt, claim::ClaimOutcome::Claimed { .. }) {
        if let Some(campaign) = target.marketing_campaign_ids.first() {
            if let Err(error) = claim::marketing_confirm(&jwt, mid_ref, campaign) {
                result["marketingError"] = json!(error.message);
            }
        }
    }
    result["ok"] = json!(result.get("claimed").and_then(Value::as_bool) == Some(true));
    result["activated"] = json!(activated);
    result["activationError"] = json!(activation_error);
    Ok(result)
}
