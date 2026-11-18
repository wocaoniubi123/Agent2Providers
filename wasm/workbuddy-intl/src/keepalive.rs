//! WorkBuddy **国际版每日活跃**（日活领取 + 两发保活 + 网页会话）。
//!
//! ── 这是什么 ──────────────────────────────────────────────
//! 国际版有一个「每日活跃奖励」：活动开放时领一份奖励，并且要求账号当天
//! 「活跃」。活跃判定分三件事（issue #277 的抓包结论）：
//!
//! ```text
//!   ①  POST /v2/report        一条 chat_request_send 事件 → 点亮成长中心连登
//!   ②  chat/completions       一次最小对话（免费模型）→ 维持「账号有调用」
//!   ③  POST /console/as/conversations/  网页通道建带 prompt 的会话
//!                             → **每日活跃计数只认它**
//! ```
//!
//! 参考客户端把三步挂在既有签到调度器上；本仓对应关系见网关的
//! `billing::activity::workbuddy_daily_activity`（本文件是它的执行体），
//! 协议入口是 `admin.action` 的 `activity.run`（metadata 的
//! `admin_panels = ["daily_keepalive"]`）。
//!
//! ── 为什么两发保活长得不一样 ────────────────────────────
//! 桌面端那发必须长得和真对话一模一样：头集合与 URL 直接复用
//! [`crate::outbound::chat_headers`] / [`crate::outbound::chat_completions_url`]
//! —— 两套实现必然漂移，漂移的后果是被客户端画像识别拦下。网页那发则要**剥掉
//! 全部桌面指纹**：网页链路只认 `Authorization: Bearer` 与 `X-User-Id`，UA 也是
//! 浏览器的，同一份账号凭据直接可用，无需网页登录。
//!
//! ── wasm 侧的三处替换 ───────────────────────────────────────
//! · 代理：出网由宿主按账号绑定（`http.open` 没有代理参数），`proxy_of` 那一支去掉；
//! · 超时：`tokio::time::timeout` 换成宿主 http 的默认超时（插件拿不到超时参数）；
//! · 读体：`reqwest` 的流式读取换成 `http::Response::bytes(limit)`，语义不变
//!   （响应体必须**读**——不读的请求上游可能没记活跃）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use crate::endpoints::RESPONSE_CODE_OK;
use crate::httpio;
use crate::outbound;
use crate::util;

/// 国际版每日活跃任务默认使用的免费模型，按可用性优先级尝试。
///
/// 这些模型在参考客户端中实测为 x0.00，不会消耗账号积分；它是**缺省值**
/// （payload 没写 `models` 时用它）。用户自定义后的链由网关放在 payload 里传进来
/// —— `checkinKeepalive.models` 是**用户的**配置，落在网关的 config.json 里，
/// 插件没有那层配置。
pub const DEFAULT_FREE_MODELS: &[&str] =
    &["deepseek-v4.1-flash", "hy3", "hy4-preview", "hy4-preview-f"];

/// 执行粒度（对应签到中心的三颗手动按钮）。
///
/// 定时与批量签到恒走 [`Mode::Full`]，粒度细分只是手动入口的事。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// 探测 + 条件领取 + 保活
    Full,
    /// 探测 + 条件领取
    Claim,
    /// 只保活（活动没开时只维持账号活跃）
    Keepalive,
}

impl Mode {
    /// API 层传来的 mode 字符串 → 粒度。未知值回落 [`Mode::Full`] ——
    /// 手动入口的缺省行为是「完整跑一遍」，比「悄悄少做一步」更接近点击者本意。
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("claim") => Self::Claim,
            Some("keepalive") => Self::Keepalive,
            _ => Self::Full,
        }
    }

    /// 结果行里回带的 mode（前端排查「这轮实际跑了哪几步」用）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Claim => "claim",
            Self::Keepalive => "keepalive",
        }
    }
}

/// 保活模型链：调用方传入（网关从 config.json 读），空则回落缺省链。
fn chain(models: &[String]) -> Vec<String> {
    let picked: Vec<String> = models
        .iter()
        .map(|model| model.trim().to_string())
        .filter(|model| !model.is_empty())
        .collect();
    if picked.is_empty() {
        DEFAULT_FREE_MODELS
            .iter()
            .map(|model| (*model).to_string())
            .collect()
    } else {
        picked
    }
}

/// 跑一次国际版每日活跃任务。
///
/// `record` 是账号的扁平 secret；`models` 是保活模型链（空 = 缺省链）。
/// 返回网关 `workbuddy_daily_activity` 的**同形 JSON**（`status` / `claim` /
/// `activity` 三段）。
pub fn run(record: &Value, mode: Mode, models: &[String]) -> Result<Value> {
    let session = outbound::session_of_record(record);
    let models = chain(models);

    // 只保活：跳过探测与领取。读数给 **null** 而不是 false ——
    // 「没查」与「查了说没开」是两回事；前端只认 `pokeSucceeded`。
    if mode == Mode::Keepalive {
        let report = report_activity(&session);
        let (poke_succeeded, poke_model) = poke_daily_activity(&session, &models);
        let web = create_web_conversation(&session, &models);
        let web_ok = web.get("succeeded").and_then(Value::as_bool) == Some(true);
        if web.get("status").and_then(Value::as_i64) == Some(401)
            || (report.get("status").and_then(Value::as_i64) == Some(401)
                && !web_ok
                && !poke_succeeded)
        {
            return Err(Error::http(401, "WorkBuddy 国际版保活登录态已失效"));
        }
        // msg 交代两发保活各自的走向：网页会话才是「当日活跃」的判定通道，
        // 桌面端那发失败不致命，网页会话失败要给出原因。
        let msg = if web_ok {
            "活跃保活完成（网页会话已建）".to_string()
        } else if poke_succeeded {
            format!(
                "免费模型保活完成，但网页会话失败：{}",
                web.get("msg").and_then(Value::as_str).unwrap_or("未知原因")
            )
        } else {
            "活跃保活失败".to_string()
        };
        return Ok(json!({
            "status": Value::Null,
            "claim": {
                "success": false,
                "code": 0,
                "msg": msg,
            },
            "activity": {
                "mode": mode.as_str(),
                "active": Value::Null,
                "todayCheckedIn": Value::Null,
                "statusAvailable": Value::Null,
                "report": report,
                "pokeSucceeded": poke_succeeded,
                "pokeModel": poke_model,
                "webConversation": web,
            },
        }));
    }

    // ── ① 活动探测（国际版的探活不带 `/v2`）──
    let status = billing_call(&session, "POST", "/billing/meter/checkin-activity-status", None, false);
    let (status_available, active, today_checked_in, status_value) = match status {
        Ok(call) => {
            let status_available = call.code == Some(RESPONSE_CODE_OK);
            let active = call
                .data
                .get("active")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let today_checked_in = call
                .data
                .get("today_checked_in")
                .or_else(|| call.data.get("todayCheckedIn"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (
                status_available,
                active,
                today_checked_in,
                normalize_activity_status(&call),
            )
        }
        Err(error) if error.status == Some(401) => return Err(error),
        Err(error) => (
            false,
            false,
            false,
            json!({
                "active": false,
                "todayCheckedIn": false,
                "statusAvailable": false,
                "code": -1,
                "msg": error.message,
            }),
        ),
    };

    // ── ② 活跃上报（Claim / Full 都做）──
    let report = report_activity(&session);

    // ── ③ 条件领取 ──
    let mut claim = if today_checked_in {
        // 上游幂等，但「今日已领」就不用再打一发 —— 少一发是一发。
        json!({
            "success": false,
            "code": 0,
            "msg": "今日已领取",
            "alreadyCompleted": true,
        })
    } else if active {
        match billing_call(&session, "POST", "/v2/billing/meter/daily-checkin", None, false) {
            Ok(call) => normalize_daily_claim(&call),
            Err(error) if error.status == Some(401) => return Err(error),
            Err(error) => json!({ "success": false, "code": -1, "msg": error.message }),
        }
    } else {
        json!({ "success": false, "code": 0, "msg": "活动未开启" })
    };
    let claim_succeeded = claim
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // ── ④ 保活（只完整模式做）──
    let (poke_succeeded, poke_model, web) = if mode == Mode::Full {
        let (succeeded, model) = poke_daily_activity(&session, &models);
        let web = create_web_conversation(&session, &models);
        (
            Value::Bool(succeeded),
            model.map(Value::String).unwrap_or(Value::Null),
            web,
        )
    } else {
        (Value::Null, Value::Null, Value::Null)
    };
    let web_ok = web.get("succeeded").and_then(Value::as_bool) == Some(true);
    if web.get("status").and_then(Value::as_i64) == Some(401)
        || (report.get("status").and_then(Value::as_i64) == Some(401)
            && !claim_succeeded
            && !today_checked_in
            && !web_ok)
    {
        return Err(Error::http(401, "WorkBuddy 国际版活跃登录态已失效"));
    }

    // 领取没有明确的成功/已领读数时，msg 给出这一轮**实际发生**的事。
    // 能走到这里的分支必然 !active：只写「已完成活跃上报」会让人以为积分该加没加
    // —— 两个事实都要交代。
    if mode == Mode::Full && !claim_succeeded && !today_checked_in && !active {
        let report_ok = report.get("succeeded").and_then(Value::as_bool) == Some(true);
        let poke = poke_succeeded.as_bool().unwrap_or(false);
        claim["msg"] = Value::String(if report_ok && (poke || web_ok) {
            "已完成活跃上报（连登已点亮）与保活，但活动未开启（本次没有可领的奖励）".to_string()
        } else if report_ok {
            "活跃上报完成，但保活未成功且活动未开启".to_string()
        } else if poke || web_ok {
            "活跃保活完成，但活跃上报失败且活动未开启".to_string()
        } else {
            "活跃上报与保活均未成功，且活动未开启".to_string()
        });
    }

    Ok(json!({
        "status": status_value,
        "claim": claim,
        "activity": {
            "mode": mode.as_str(),
            "active": active,
            "todayCheckedIn": today_checked_in,
            "statusAvailable": status_available,
            "report": report,
            "pokeSucceeded": poke_succeeded,
            "pokeModel": poke_model,
            "webConversation": web,
        },
    }))
}

/// 一次国际版计费/运营调用的成果（`{code, msg, data}`）。
struct BillingResult {
    code: Option<i64>,
    msg: Option<String>,
    data: Value,
}

/// 调一次国际版计费接口（`path` 是 `/v2/...` 或 `/billing/...` 形态，落点是会话端点）。
///
/// 与 [`crate::billing::call`] 的差别只有两处，都来自 native：401/403 一律映射成
/// 401（这条链路上的 403 也是「登录态不对」而不是权限问题）、失败文案带
/// HTTP 状态与上游 detail。
fn billing_call(
    session: &Value,
    method: &str,
    path: &str,
    body: Option<&Value>,
    expect_code_ok: bool,
) -> Result<BillingResult> {
    let endpoint = outbound::session_endpoint_of(session);
    let url = format!("{endpoint}{path}");
    let payload_body = if method == "GET" || method == "HEAD" {
        None
    } else {
        // Node 是 `JSON.stringify(body ?? spec.body ?? {})` —— 缺省体一律是空对象
        // （上游对缺 body 的 POST 会报 400）。
        Some(body.cloned().unwrap_or_else(|| json!({})))
    };
    let headers = crate::billing::headers::build_headers(session, &[]);
    let response = httpio::send(method, &url, &headers, payload_body.as_ref())
        .map_err(|error| httpio::transport_error("计费接口请求", error))?;

    let payload = response.payload.clone();
    let code = response.code();
    let msg = payload.as_ref().and_then(|value| {
        value
            .get("msg")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .or_else(|| {
                value
                    .get("message")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
            })
            .map(str::to_string)
    });
    if response.status == 401 || response.status == 403 {
        return Err(Error::http(401, "登录态已过期或被拒绝，无法调用计费接口"));
    }
    if !response.ok {
        let detail = payload
            .as_ref()
            .and_then(|value| {
                value
                    .get("msg")
                    .and_then(Value::as_str)
                    .or_else(|| value.get("message").and_then(Value::as_str))
            })
            .unwrap_or("");
        let message = if detail.is_empty() {
            format!("计费接口返回 HTTP {}", response.status)
        } else {
            format!("计费接口返回 HTTP {}: {detail}", response.status)
        };
        return Err(Error::http(response.status, message));
    }
    if let Some(code_value) = code {
        if code_value != RESPONSE_CODE_OK && expect_code_ok {
            let message = msg
                .clone()
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| format!("计费接口返回 code={code_value}"));
            return Err(Error::http(response.status, message));
        }
    }
    let data = payload
        .as_ref()
        .and_then(|value| value.get("data"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(BillingResult { code, msg, data })
}

/// 活跃探测响应归一化为网关能直接消费的形态。
///
/// 上游字段是蛇形（`today_checked_in` / `daily_credit`），归一成驼峰与国内版签到
/// 状态的键风格一致；`statusAvailable` 区分「接口说不活动」与「接口本身没答上」
/// —— 前者是正常状态，后者要留给排查。原始 data 原样带出（`raw`）。
fn normalize_activity_status(call: &BillingResult) -> Value {
    let data = &call.data;
    json!({
        "active": data.get("active").and_then(Value::as_bool).unwrap_or(false),
        "todayCheckedIn": data
            .get("today_checked_in")
            .or_else(|| data.get("todayCheckedIn"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "dailyCredit": data
            .get("daily_credit")
            .or_else(|| data.get("dailyCredit"))
            .cloned()
            .unwrap_or(Value::Null),
        "statusAvailable": call.code == Some(RESPONSE_CODE_OK) && !data.is_null(),
        "code": call.code,
        "msg": call.msg,
        "raw": data,
    })
}

/// 领取结果归一化为统一 claim 形状（成功带 `data` / `raw`，失败带 `code` / `msg`）。
fn normalize_daily_claim(call: &BillingResult) -> Value {
    if call.code == Some(RESPONSE_CODE_OK) && !call.data.is_null() {
        return json!({
            "success": true,
            "code": 0,
            "data": call.data,
            "raw": call.data,
        });
    }
    json!({
        "success": false,
        "code": call.code.unwrap_or(-1),
        "msg": call.msg.clone().unwrap_or_else(|| "签到失败".to_string()),
    })
}

/// 国际版对话活跃上报：`POST /v2/report` 的一条 `chat_request_send` 事件。
///
/// 事件形状照抄官方客户端的完整 24 字段，**`userId` 必填**（= 账号 uid）——
/// 缺失时上游返回 200 但**静默丢弃**事件。conversationId 无需真实会话，随机生成
/// 即可；每号每天一条（按天幂等由调用方/网关控制）。
fn report_activity(session: &Value) -> Value {
    let uid = session
        .pointer("/account/uid")
        .and_then(Value::as_str)
        .unwrap_or("");
    if uid.is_empty() {
        return json!({
            "succeeded": false,
            "streakDays": Value::Null,
            "msg": "会话缺少账号 uid，无法上报活跃",
        });
    }
    let conversation_id = format!("agent2api-{}", util::new_message_id());
    let now = util::now_ms();
    let event = json!({
        "eventCode": "chat_request_send",
        "timestamp": now,
        "reportDelay": 0,
        "mode": "craft",
        "conversationId": conversation_id,
        "requestId": conversation_id,
        "inputLength": 12,
        "requestModelId": "deepseek-v4.1-flash",
        "requestModelName": "DeepSeek V4.1 Flash",
        "isPlan": false,
        "isAutoExecuteTerminal": false,
        "isAutoModify": false,
        "codebaseEnable": false,
        "maxToken": 0,
        "maxSteps": 0,
        "temperature": 0,
        "maxRetries": 0,
        "mentionContexts": [],
        "knowledgeId": [],
        "knowledgeName": [],
        "codebaseId": "",
        "mentionContextCount": 0,
        "command": "",
        "expertId": "",
        "recommendId": "",
        "skillId": "",
        "skillCount": 0,
        "totalCount": 0,
        "fileUri": "",
        "presentAt": now,
        "traceId": "",
        "rootRequestId": conversation_id,
        "parentConversationId": conversation_id,
        "agentName": "default",
        "agentType": "conversation",
        "userId": uid,
    });
    let body = json!([event]);
    let result = billing_call(session, "POST", "/v2/report", Some(&body), true);
    let succeeded = result.is_ok();
    // 回读连登天数（只读 oracle）：上报 200 ≠ 计分，闭环验证用。
    let streak_days = if succeeded {
        read_growth_streak(session).ok()
    } else {
        None
    };
    let streak_text = streak_days
        .map(|days| format!("，连登 {days} 天"))
        .unwrap_or_default();
    json!({
        "succeeded": succeeded,
        "status": result.as_ref().err().and_then(|error| error.status),
        "streakDays": streak_days.map(Value::from).unwrap_or(Value::Null),
        "msg": if succeeded {
            format!("活跃上报成功{streak_text}")
        } else {
            "活跃上报失败".to_string()
        },
    })
}

/// 回读成长中心连登状态（`GET /activity/growth/streak`）→ `streak.days`。
fn read_growth_streak(session: &Value) -> Result<i64> {
    let call = billing_call(session, "GET", "/activity/growth/streak", None, true)?;
    Ok(call
        .data
        .get("streak")
        .and_then(|streak| streak.get("days"))
        .and_then(Value::as_i64)
        .unwrap_or(0))
}

/// 用免费模型发一次最小流式对话，维持账号「活跃」。
///
/// 模型链逐个尝试，第一个拿到 2xx 且响应体可读的收口；响应体读到上限就算数
/// （流式 SSE 没必要读完，但要**读**：不读的请求上游可能没记活跃）。
fn poke_daily_activity(session: &Value, models: &[String]) -> (bool, Option<String>) {
    const MAX_POKE_BYTES: usize = 1 << 20;
    for model in models {
        let body = json!({
            "model": model,
            "stream": true,
            "max_tokens": 16,
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "hi"},
            ],
        });
        // 头集合与真对话共用一份（chat_headers 已带全会话头族 / 链路头族，
        // 正是渠道校验的对齐项），这里不再补丁。
        let headers = outbound::chat_headers(session, Some("text/event-stream"));
        let response = match http::open(
            "POST",
            &outbound::chat_completions_url(session),
            util::headers_value(&headers),
            Some(&body),
        ) {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !(200..300).contains(&response.status) {
            continue;
        }
        // 必须读掉响应体（不读的请求上游可能没记活跃）；读失败就换下一个模型
        if response.bytes(MAX_POKE_BYTES).is_err() {
            continue;
        }
        return (true, Some(model.clone()));
    }
    (false, None)
}

/// 网页通道建一个带 prompt 的 agent 会话（issue #277 的修复主体）。
///
/// 国际版上游把「当日活跃」记在网页通道的会话上：`POST /console/as/conversations/`
/// 建会话即计活跃，桌面端 `chat/completions` 与 `/v2/report` 上报都**不**进这个
/// 计数。网页链路只认 Bearer + X-User-Id 两个头，同一份账号凭据直接可用。
///
/// 模型沿用同一条免费链；成功判定沿用参考实现口径 —— 响应 `code ∈ {0, 缺失}` 且
/// `data.id` 存在。返回 `{succeeded, conversationId, msg}`，原样进
/// `activity.webConversation` 给前端与台账读。
fn create_web_conversation(session: &Value, models: &[String]) -> Value {
    let id = session.get("id").and_then(Value::as_str).unwrap_or("");
    for model in models {
        let body = json!({
            "prompt": "Hi", "model": model, "conversationOrigin": "workbuddy-app",
            "plugins": [{"name": "weixinpay", "marketplace": "codebuddy-builtin"}],
        });
        let response = match crate::web_session::request(
            session,
            id,
            "POST",
            "/console/as/conversations/",
            Some(&body),
            &[],
        ) {
            Ok(response) => response,
            Err(error) => {
                return json!({
                    "succeeded": false,
                    "status": error.status,
                    "msg": error.message,
                })
            }
        };
        if response.status == 401 || response.status == 403 {
            return json!({
                "succeeded": false,
                "status": response.status,
                "msg": "WorkBuddy 国际版网页登录态被拒绝",
            });
        }
        if !response.ok {
            continue;
        }
        let Some(payload) = response.payload else {
            continue;
        };
        // 参考实现的判定口径：code 缺失 / null / 0 都算业务成功
        let code_ok = match payload.get("code") {
            None | Some(Value::Null) => true,
            Some(code) => code.as_i64() == Some(0),
        };
        let conversation_id = payload
            .pointer("/data/id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !code_ok || conversation_id.is_empty() {
            continue;
        }
        return json!({
            "succeeded": true,
            "conversationId": conversation_id,
            "model": model,
            "msg": "网页会话已创建",
        });
    }
    json!({
        "succeeded": false,
        "conversationId": Value::Null,
        "msg": "网页会话创建失败（模型链全部未建成）",
    })
}

/// 与网关 `supports_checkin` 同口径：国际版只有活跃任务这一条「签到」。
///
/// 保留给签名一致的可读性 —— 本文件所有动作都只服务国际版账号。
#[allow(dead_code)]
pub fn supports_checkin(account: &Value) -> bool {
    account.get("provider").and_then(Value::as_str) == Some(crate::Region::provider_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing_falls_back_to_full() {
        assert_eq!(Mode::parse(Some("claim")), Mode::Claim);
        assert_eq!(Mode::parse(Some("keepalive")), Mode::Keepalive);
        // 未知值 / 缺失都按「完整跑一遍」
        assert_eq!(Mode::parse(Some("whatever")), Mode::Full);
        assert_eq!(Mode::parse(None), Mode::Full);
        assert_eq!(Mode::Full.as_str(), "full");
    }

    #[test]
    fn chain_falls_back_to_the_free_models() {
        assert_eq!(chain(&[]), DEFAULT_FREE_MODELS.iter().map(|m| m.to_string()).collect::<Vec<_>>());
        // 空白项被丢弃；全空同样回落
        assert_eq!(chain(&["  ".to_string()]).len(), DEFAULT_FREE_MODELS.len());
        assert_eq!(chain(&["my-model".to_string()]), vec!["my-model".to_string()]);
    }

    #[test]
    fn activity_status_is_normalized() {
        let call = BillingResult {
            code: Some(0),
            msg: None,
            data: json!({ "active": true, "today_checked_in": true, "daily_credit": 20 }),
        };
        let status = normalize_activity_status(&call);
        assert_eq!(status["active"], json!(true));
        assert_eq!(status["todayCheckedIn"], json!(true));
        assert_eq!(status["dailyCredit"], json!(20));
        assert_eq!(status["statusAvailable"], json!(true));
    }

    #[test]
    fn daily_claim_shape_matches_the_gateway() {
        let ok = normalize_daily_claim(&BillingResult {
            code: Some(0),
            msg: None,
            data: json!({ "points": 10 }),
        });
        assert_eq!(ok["success"], json!(true));
        assert_eq!(ok["code"], json!(0));
        let failed = normalize_daily_claim(&BillingResult {
            code: Some(6004),
            msg: Some("已领取".to_string()),
            data: Value::Null,
        });
        assert_eq!(failed["success"], json!(false));
        assert_eq!(failed["msg"], json!("已领取"));
    }

    #[test]
    fn report_activity_requires_a_uid() {
        let report = report_activity(&json!({ "account": {} }));
        assert_eq!(report["succeeded"], json!(false));
        assert!(report["msg"].as_str().unwrap_or("").contains("uid"));
    }
}
