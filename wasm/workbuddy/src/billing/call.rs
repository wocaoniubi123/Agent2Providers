//! 一次计费接口调用的最小实现（网关 `BillingService::call_billing` 的插件侧等价物）。
//!
//! ── 与网关那份的差别 ────────────────────────────────────────
//! 网关那版带一套 `CallOptions`（签到重复领取容错、白名单头、查询串、跨站落点
//! 等）。这里把它们收进 [`Options`]；默认值仍是「只查积分」那一套 —— 查积分的
//! 调用点因此不必写一堆 `..Default::default()`。
//!
//! 判定顺序：401 身份失效、其它非 2xx、业务码失败；403 保留上游拒绝原因。
//!
//! ── 出口 ────────────────────────────────────────────────────
//! native 的 `call_billing` 收一个 `WireProxy`（账号级出口）。wasm 侧出网由宿主
//! 按账号绑定，SDK 的 `http.open` 没有代理参数，所以这一支整体去掉。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::endpoints::RESPONSE_CODE_OK;
use crate::httpio;
use crate::outbound;

use super::headers::{build_headers, whitelist_headers};

/// 一次计费调用的成果（与网关 `BillingCall` 逐字段对应）。
pub struct BillingCall {
    /// 上游业务码（`None` = 响应里没有这个字段）。
    pub code: Option<i64>,
    /// 上游文案（`msg` 优先，回退 `message`；空串当没有）。
    pub msg: Option<String>,
    /// 上游 `requestId`（签到失败分支会原样回给前端）。
    pub request_id: Option<Value>,
    /// `data` 段（缺失为 `Null`）
    pub data: Value,
    /// 整份响应体（企业额度的取值链要它）
    pub raw: Option<Value>,
    /// HTTP 状态码（判断「这次到底打没打成」）
    #[allow(dead_code)]
    pub status: u16,
}

/// 一次调用的选项（网关 `CallOptions` 的同义物）。
pub struct Options<'a> {
    /// 查询串（含前导 `?` 或为空）
    pub query: Option<&'a str>,
    /// 落点覆盖：`None` = 会话端点；`Some` = 固定站点。
    ///
    /// 只有**跨站**的一次性运营奖励用它（新手礼包 / 活动补偿挂在国内版计费站
    /// `www.codebuddy.cn` 上）：落点由上游运营侧固定，不跟账号的 `endpoint` 走。
    pub base: Option<&'a str>,
    /// 是否带运营活动需要的客户端白名单头（只有 banner 需要）
    pub whitelist_headers: bool,
    /// 非 0 业务码是否算失败
    pub expect_code_ok: bool,
    /// 把「今天已签到 / 已领取」的 400/409 放行成 `Ok`
    pub tolerate_duplicate_claim: bool,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            query: None,
            base: None,
            whitelist_headers: false,
            expect_code_ok: true,
            tolerate_duplicate_claim: false,
        }
    }
}

/// 调一次计费接口。
///
/// `path` 是 `/v2/...` 形态；落点取**会话端点**（账号自己的站点），除非
/// [`Options::base`] 给了固定站点。
pub fn call(
    method: &str,
    path: &str,
    body: Option<&Value>,
    session: &Value,
    locale: Option<&str>,
    options: Options<'_>,
) -> Result<BillingCall> {
    // 账户级端点：国内版/国际版账号各走自己的站点
    let endpoint = outbound::session_endpoint_of(session);
    let base = options.base.map(str::to_string).unwrap_or(endpoint);
    let url = format!("{base}{path}{}", options.query.unwrap_or(""));

    let mut extra: Vec<(String, String)> = Vec::new();
    if let Some(locale) = locale {
        extra.push(("Accept-Language".to_string(), accept_language(Some(locale))));
    }
    if options.whitelist_headers {
        extra.extend(whitelist_headers(session));
    }
    let headers = build_headers(session, &extra);
    let payload_body = if method == "GET" || method == "HEAD" {
        None
    } else {
        // Node 是 `JSON.stringify(body ?? spec.body ?? {})` —— 缺省体一律是空对象，
        // 不能省掉（上游对缺 body 的 POST 会报 400）
        Some(body.cloned().unwrap_or_else(|| json!({})))
    };

    let response = httpio::send(method, &url, &headers, payload_body.as_ref())
        .map_err(|error| httpio::transport_error("计费接口请求", error))?;

    let payload = response.payload.clone();
    let code = response.code();
    // Node: `payload?.msg || payload?.message` —— 空串也当「没有」，所以过滤空串
    let msg = payload
        .as_ref()
        .and_then(|value| {
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
        })
        .map(str::to_string);
    // Node 的 `requestId: payload?.requestId` 在缺失时是 undefined，
    // JSON 化会**丢掉这个键**；用 Option 表达同一语义（None = 不出键）
    let request_id = payload
        .as_ref()
        .and_then(|value| value.get("requestId"))
        .cloned();

    if response.status == 401 {
        // ── 为什么文案里带完整 URL（issue #381）────────────────────
        // 401 有两种成因，处置完全相反：
        //   ① 凭证真的失效 → 重新登录；
        //   ② 账号的 `endpoint` 拼错 / 落到了另一个地区的站点 → 改端点，
        //      重新登录也没用。
        // 排查时最缺的信息正是「这次到底打了哪个地址」—— 只给路径片段看不出
        // 域名错没错。所以这里把请求的完整 URL 写进错误。
        return Err(Error::http(
            401,
            format!(
                "登录态被上游拒绝（HTTP 401，请求地址 {url}）：若该地址与账号所在地区不符，\
                 请检查账号的端点（endpoint）配置；地址正确时才是凭证失效，需要重新登录"
            ),
        ));
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
        // ── 「今天已签到」不是错误（issue #137）────────────────────
        // 上游对重复领取回的是 **HTTP 400 +「今天已签到，请明天再来」**，而不是
        // 200 + 非 0 code。不放行的话这条正常终态会被丢成 `Err`，于是 claim 为
        // null —— 面板的「已签到」永远不亮、定时签到的 lastResult 恒显示
        // 「成功领取 0/N」，用户会反复重试。
        if options.tolerate_duplicate_claim && is_duplicate_claim(response.status, detail) {
            return Ok(BillingCall {
                code,
                msg,
                request_id,
                data: Value::Null,
                raw: payload,
                status: response.status,
            });
        }
        let message = if detail.is_empty() {
            format!("计费接口返回 HTTP {}", response.status)
        } else {
            format!("计费接口返回 HTTP {}: {detail}", response.status)
        };
        return Err(Error::http(response.status, message));
    }
    if let Some(code_value) = code {
        if code_value != RESPONSE_CODE_OK && options.expect_code_ok {
            let message = msg
                .clone()
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| format!("计费接口返回 code={code_value}"));
            let mut error = Error::http(response.status, message);
            error.upstream_code = Some(code_value);
            return Err(error);
        }
    }

    let data = payload
        .as_ref()
        .and_then(|value| value.get("data"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(BillingCall {
        code,
        msg,
        request_id,
        data,
        raw: payload,
        status: response.status,
    })
}

/// 这次非 2xx 响应是否表示「今天已经领过了」（签到重复领取）。
///
/// 判据刻意收得很紧 —— 不能宽到「只要没报错就算已签到」，否则网络错误、凭证
/// 失效会被误判成已签到而白丢一天：
///   · **只认 400 / 409**（400 是实测量到的当日已签到文案；500/502/504 是真
///     故障，放行会让一次没签上的日子被记成已签，**绝不放**）；
///   · **只认文案命中**：与网关 `checkin_completed_today` 第 3 条判据同源。
pub fn is_duplicate_claim(status: u16, detail: &str) -> bool {
    matches!(status, 400 | 409) && (detail.contains("已签到") || detail.contains("已领取"))
}

/// `Accept-Language` 的取值：上游按它挑文案语种，本家只区分「中文」与「其余」。
fn accept_language(locale: Option<&str>) -> String {
    match locale.map(str::trim).filter(|value| !value.is_empty()) {
        Some(locale) if locale.to_ascii_lowercase().starts_with("zh") => "zh-CN".to_string(),
        Some(locale) => locale.to_string(),
        None => "zh-CN".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::is_duplicate_claim;

    /// 上游真实的 400 文案（当日已签到时的原话）。
    const REAL_DUPLICATE: &str = "今天已签到，请明天再来";

    #[test]
    fn real_duplicate_message_is_recognized() {
        assert!(is_duplicate_claim(400, REAL_DUPLICATE));
        assert!(is_duplicate_claim(409, REAL_DUPLICATE));
        assert!(is_duplicate_claim(400, "今天已领取过了"));
    }

    #[test]
    fn only_400_and_409_are_tolerated() {
        for status in [500, 502, 503, 504, 429, 404] {
            assert!(!is_duplicate_claim(status, REAL_DUPLICATE), "status={status} 不该被放行");
        }
    }

    #[test]
    fn non_duplicate_message_still_fails() {
        for detail in ["参数错误", "请求内容不是有效 JSON", "活动已结束", ""] {
            assert!(!is_duplicate_claim(400, detail), "detail={detail:?} 不该被放行");
        }
    }
}
