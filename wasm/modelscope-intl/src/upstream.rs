//! ModelScope 国际站的上游形状：**两套域名、一个 `ms-` 令牌两用**。
//!
//! ── 迁移来源与拆包边界（native `modelscope/region.rs` 的决策记录）────
//! native 一个目录导出两家 provider（`modelscope` / `modelscope-intl`），靠
//! `Region` 参数化「一份实现、两个实例」：
//!
//! ```text
//!                推理（OpenAI 兼容）                      网页站（身份 / 魔粒 / 签到）
//!   国内  https://api-inference.modelscope.cn/v1        https://modelscope.cn
//!   国际  https://api-inference.modelscope.ai/v1        https://www.modelscope.ai
//! ```
//!
//! 网关的 wasm 宿主只认**一个包一个 provider id**（`provenance.rs` 的
//! `providers.len() != 1`），所以本包只做国际站：`Region` 枚举与 `Cn` 分支
//! 整体消失，国内站在另一个包 `agent2api-wasm-modelscope` 里。这不是
//! 「少迁了一半」，而是「一个包只能声明一个 id」的必然结果。
//!
//! 本包取的是 native `Region::Intl` 那一列：推理域 `api-inference.modelscope.ai`、
//! 网页站 `www.modelscope.ai`、账号 id 前缀 `modelscope-intl-`、展示名「国际版」。
//!
//! ── 一处**实测确认**的关键事实：一个 `ms-` key 两用 ────────────
//! 同一个 `ms-...` 令牌既作 `Authorization: Bearer` 调推理，又作
//! `Cookie: m_session_id=<key>` 调网页站的身份 / 魔粒接口 —— 两条链路都实测 200。
//! 因此本家**只有一个凭证字段**。
//!
//! ── 另一处实测确认：两个站点的账号体系是分开的 ──────────────────
//! 用国际站的 key 打 `https://modelscope.cn/api/v1/users/login/info`
//! 得到 `401 {"Code":10019901001,"Message":"access forbidden"}`；反过来同理。
//! 而**推理端点两地都能用同一个 key 打通**（模型网关的 key 是账号级的）。
//! 所以「站点」在本家不是可有可无的标签：**签到与魔粒必须打对站点**。
//! 本包里站点是常量，打错站点只可能是用户拿国内版令牌加了国际版账号 ——
//! 那正是 401 文案要提醒的情形（见 [`expired_message`]）。
//!
//! ── 为什么没有环境变量覆盖 ──────────────────────────────────
//! 这两个域名是**硬编码在官方 SDK / 客户端里的**、实测稳定，为它们加一层
//! `MODELSCOPE_*_BASE_URL` 只是多一条没人会用的分支。真要换域名时改本文件的
//! 两处常量比找环境变量更直接。（wasm 沙箱里也没有 `std::env`。）

use agent2api_wasm_sdk::{http, Value};

/// provider id（与 `pack.json` / `metadata.json` 一致）。
pub const PROVIDER_ID: &str = "modelscope-intl";

/// 展示名里跟在 `ModelScope` 后面的那一段（native `Region::label`，国际版）。
pub const LABEL: &str = "国际版";

/// 账号 id 前缀（native `Region::Intl` 的 `account_id_prefix`）。
///
/// native 给两地带前缀的理由：两站的身份 id 空间互不相通，但**同一个人在两地的
/// `HavanaId` 完全可能相同**（各自注册，服务端 id 生成规则同形就会撞）。撞了的话
/// 网关的跨 provider 撞 id 保护会拒绝，「两地账号并存」就变得不可能 —— 而并存
/// 正是当初拆两家的意义之一。本包只做国际站，前缀照旧带着：账号库里可能已经有
/// 国内版账号，前缀是两边不撞的唯一保证。
pub const ACCOUNT_PREFIX: &str = "modelscope-intl-";

/// 推理基址（**含** `api-inference` 主机与尾部的 `/v1`）。
///
/// 对话在它后面拼 `/chat/completions`，目录在它后面拼 `/models` ——
/// 两处都不要再写域名。
pub const INFERENCE_BASE: &str = "https://api-inference.modelscope.ai/v1";

/// 网页站基址（身份 / 魔粒余额 / 今日用量 / 签到都在这个域下，**不带尾部斜杠**）。
///
/// 国际站的网页域带 `www`（native `Region::Intl` 的 `site_base_url` 就是
/// `https://www.modelscope.ai`）。`wasm.json` 的 `origins` 按 origin 精确匹配，
/// 所以那里写的是 `https://www.modelscope.ai`，不是裸域。
pub const SITE_BASE: &str = "https://www.modelscope.ai";

/// 单次响应体的读取上限（余额、流水、目录都不该超过它）。
const BODY_LIMIT: usize = 4 * 1024 * 1024;

/// 推理域的请求头。
///
/// `Accept` 恒要 SSE：本插件只按流式读上游（非流式由网关把流折回 JSON，
/// 见 `lib.rs` 的说明）。`Content-Type` 在这里显式给 —— native 侧由网关的
/// 发送层自动补，wasm 侧 `http::open` 只发插件给的头。
pub fn inference_headers(token: &str, accept: &str) -> Value {
    agent2api_wasm_sdk::json!({
        "authorization": format!("Bearer {token}"),
        "accept": accept,
        "content-type": "application/json",
    })
}

/// 网页站的请求头：会话就是令牌本身（`Cookie: m_session_id=<key>`）。
pub fn site_headers(token: &str) -> Value {
    agent2api_wasm_sdk::json!({
        "cookie": format!("m_session_id={token}"),
        "accept": "application/json",
    })
}

/// 拼一个网页站 URL。
pub fn site_url(path: &str) -> String {
    format!("{SITE_BASE}{path}")
}

/// 拼一个推理域 URL。
pub fn inference_url(path: &str) -> String {
    format!("{INFERENCE_BASE}{path}")
}

/// 发一次 GET，回 `(状态码, 解析后的 JSON)`；非 JSON 体按 `null` 处理。
///
/// 不解状态码：调用方（[`checked`]）要按状态码给出各自的文案，先解析成值再判
/// 会让「上游回了 HTML 错误页」这类情形丢掉状态码。
fn get(url: &str, headers: Value, operation: &str) -> agent2api_wasm_sdk::Result<(u16, Value)> {
    let response = http::open("GET", url, headers, None)
        .map_err(|error| with_context(operation, error))?;
    let status = response.status;
    let bytes = response
        .bytes(BODY_LIMIT)
        .map_err(|error| with_context(operation, error))?;
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, payload))
}

/// 网页站读一次 JSON（身份 / 魔粒 / 流水 / 签到都走这条）。
pub fn site_json(
    token: &str,
    path: &str,
    operation: &str,
) -> agent2api_wasm_sdk::Result<Value> {
    let (status, payload) = get(&site_url(path), site_headers(token), operation)?;
    checked(status, payload, operation, true)
}

/// 推理域读一次 JSON（本包只用来拉 `/models` 目录）。
pub fn inference_json(
    token: &str,
    path: &str,
    operation: &str,
) -> agent2api_wasm_sdk::Result<Value> {
    let (status, payload) = get(
        &inference_url(path),
        inference_headers(token, "application/json"),
        operation,
    )?;
    checked(status, payload, operation, false)
}

/// 给传输层错误补一句「这步在干什么」，状态码与错误码原样保留。
fn with_context(operation: &str, error: agent2api_wasm_sdk::Error) -> agent2api_wasm_sdk::Error {
    agent2api_wasm_sdk::Error {
        message: format!("{operation}失败：{}", error.message),
        ..error
    }
}

/// 统一的状态码与信封校验（native `ControlClient::checked` 的逐条对照）。
///
/// 401 与 403 分开：401 是「令牌失效」，403 既可能是权限也可能是风控拒绝 ——
/// 一律提示重新登录会把用户支去粘贴一个本来就好好的令牌。
fn checked(
    status: u16,
    payload: Value,
    operation: &str,
    site: bool,
) -> agent2api_wasm_sdk::Result<Value> {
    use agent2api_wasm_sdk::Error;
    if status == 401 {
        return Err(Error::http(401, expired_message(status, site)));
    }
    if status == 403 {
        return Err(Error::http(
            403,
            format!("{operation}被上游拒绝（HTTP 403），请检查账号权限或稍后重试"),
        ));
    }
    if !(200..300).contains(&status) {
        return Err(Error::http(
            if status >= 400 { status } else { 502 },
            format!("{operation}返回 HTTP {status}"),
        ));
    }
    // 网页站的信封恒是对象；推理目录允许裸数组（native 同口径）
    if site && !payload.is_object() {
        return Err(Error::http(
            502,
            format!("{operation}返回无法识别的响应"),
        ));
    }
    if !site && !payload.is_object() && !payload.is_array() {
        return Err(Error::http(
            502,
            format!("{operation}返回无法识别的响应"),
        ));
    }
    if !succeeded(&payload) {
        return Err(Error::http(
            502,
            format!(
                "{operation}失败（Code={}）：{}",
                code_of(&payload),
                message_of(&payload)
            ),
        ));
    }
    if site && !data_of(&payload).is_object() {
        return Err(Error::http(
            502,
            format!("{operation}响应缺少业务数据"),
        ));
    }
    Ok(payload)
}

/// 响应信封的成功位；推理目录不带业务信封，交给调用方校验 `data`。
pub fn succeeded(payload: &Value) -> bool {
    for key in ["Success", "success"] {
        if let Some(flag) = payload.get(key) {
            return flag.as_bool() == Some(true);
        }
    }
    match payload.get("Code").or_else(|| payload.get("code")) {
        Some(code) => matches!(code.as_i64(), Some(0 | 200)),
        None => true,
    }
}

/// 响应信封里的**业务数据**（`Data` / `data` 两层都认）。
pub fn data_of(payload: &Value) -> Value {
    payload
        .get("Data")
        .or_else(|| payload.get("data"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// 响应信封里的**上游文案**（`Message` / `message` / `msg` 三种都认）。
pub fn message_of(payload: &Value) -> String {
    payload
        .get("Message")
        .or_else(|| payload.get("message"))
        .or_else(|| payload.get("msg"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 响应信封里的业务码（`Code` / `code`；都没有时给 0）。
pub fn code_of(payload: &Value) -> i64 {
    payload
        .get("Code")
        .or_else(|| payload.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// HTTP 401 的令牌失效文案。
///
/// 网页站额外点出站点：错误站点（拿国内版令牌加国际版账号）也会回 401，
/// 只说「令牌失效」会让用户反复重粘贴同一个本身有效的令牌。
pub fn expired_message(status: u16, site: bool) -> String {
    if site {
        format!(
            "ModelScope 令牌已失效或不属于该站点（{SITE_BASE}），请重新粘贴（HTTP {status}）"
        )
    } else {
        format!("ModelScope 令牌已失效，请重新粘贴（HTTP {status}）")
    }
}
