//! 上游请求装配：**两条通道**（编码套餐 / 套餐池）与客户端身份头
//! （native `zcode/mod.rs` 的 `coding_plan_request` + `plan.rs` 的移植）。
//!
//! ── 两条通道的分派依据是账号上的 `zcodePlan` ─────────────────
//! | `zcodePlan` | 上游 | 鉴权 | 协议 |
//! |---|---|---|---|
//! | `coding-plan`（默认） | `{openai_base}/chat/completions` | `accessToken` | OpenAI Chat |
//! | `start-plan` | `{plan}/anthropic/v1/messages` | 套餐 `jwt` | Anthropic Messages |
//!
//! 两条通道的凭证**不能互相替代**（编码套餐认 accessToken、套餐池认 JWT），
//! 走错门的症状是「套餐已到期」这类业务拒绝而不是鉴权失败 —— 所以通道选择
//! 做成账号级设置、由用户明确指定，不做自动探测。
//!
//! ── `wire_model` 与 `model` ─────────────────────────────────
//! 网关给的 `wire_model` 是**发送名**（备援改写之后、上游认识的那个名字），
//! 请求体里的 `model` 是客户端原来点名的那个。这一家不改写模型名（`models`
//! 是静态表，名字就是上游 id），所以两者相同时直接用；网关没给时回落到 body。
//!
//! ── 端点映射（native `endpoint_mapping`）为什么没迁 ──────────
//! 那是「上游经 `/api/v1/agent/configs` 下发的 from→to 表」，需要一份带 TTL
//! 的快照 + 后台刷新。它在 native 侧就是 **fail-open**（没快照 / 没命中时原样
//! 放行），插件不维护快照 = 恒走 fail-open 分支 —— 行为等价于「还没拉过快照」，
//! 差别只是失去了一次上游改域时的自动跟随。**这是本次迁移的一处已知删减**，
//! 记在此处而不是静默略过。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{integer_of, urlencode};
use super::region;
use super::system_prompt;

/// Anthropic 的协议版本头（官方客户端同值）。
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic SDK 的 UA 后缀（官方客户端在套餐池通道上拼的那一段）。
pub const ANTHROPIC_SDK_UA: &str = "ai-sdk/anthropic/3.0.81";

/// 套餐池的消息路径（拼在 [`region::plan_base_url`] 之后）。
pub const MESSAGES_PATH: &str = "/anthropic/v1/messages";

/// 客户端版本号的默认值（`settings.get("appVersion")` 没填时用它）。
///
/// ── 这个数字是活动的**入场门槛**，不是「随便填个新版本」──────────
/// 2026-10-23 实测（`GET billing/preview`，匿名 + 稳定 `X-Device-Mid`，
/// win32-x64 / darwin-arm64 / linux-x64 三个平台结果一致）：
///
/// | app_version | `data.plans` |
/// |---|---|
/// | 3.13.0 / 3.14.0 / 3.14.3 / 3.15.0 / 3.15.1 / 3.16.0 | `[]` |
/// | 3.16.1 / 3.16.2 / 3.17.0 | 含 `zcode-v3-start-plan-1024` |
///
/// 2026-11-03 起上游把每日赠送套餐改由 `GET /api/v1/marketing/touch` 下发
/// （`billing/preview` / `billing/current` 整段为空），同一账号实测：
/// `X-ZCode-App-Version: 3.16.3` → 0 条；`3.17.1` / `3.18.0` → 1 条。
/// 两条链路共用这一个版本号，默认值取两边都够用的更高版本 `3.18.0`。
///
/// ★ 门槛会随每期活动上移，上游抬门槛时的表现**不是报错**，而是静默返回空
/// `plans`。排障时先在设置页改 `appVersion` 试几个版本，不必改代码重发版。
pub const DEFAULT_APP_VERSION: &str = "3.18.0";

/// 一次上游请求的构造结果（`chat` 方法的返回形态）。
pub struct Plan {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
    /// 上游协议（`chat` / `anthropic`）—— 只用于排障与日志。
    pub upstream: &'static str,
}

impl Plan {
    /// `chat` 方法的 JSON 形态（`{url, headers, body, upstream}`）。
    pub fn to_json(&self) -> Value {
        json!({
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "upstream": self.upstream,
        })
    }
}

/// 客户端版本号（`appVersion` 设置项 → [`DEFAULT_APP_VERSION`]）。
///
/// native 还有一层 `ZCODE_APP_VERSION` 环境变量（最高优先）。硬约束禁止读
/// `std::env`，插件侧没有了；要在排障时试版本，改设置页那一格即可 —— 那本来
/// 就是「用户能自己动手」的那条路。
pub fn app_version() -> String {
    let from_settings = super::region::app_version_setting();
    if from_settings.is_empty() {
        DEFAULT_APP_VERSION.to_string()
    } else {
        from_settings
    }
}

/// 平台标识（native `claim::platform()` 的等价物，`{os}-{arch}`）。
///
/// native 用编译期 `cfg!`；插件是 wasm32，`cfg!(target_os)` 恒为 unknown，
/// 所以改问宿主（`runtime.platform` / `runtime.architecture`）。
/// 未知平台回落到 `win32-x64`：上游对未知值不报错，只是可能不满足活动的
/// 客户端白名单，那时会如实回 1004。
pub fn platform() -> String {
    let os = match super::hostenv::platform() {
        "mac" => "darwin",
        "linux" => "linux",
        _ => "win32",
    };
    let arch = match super::hostenv::architecture() {
        "aarch64" => "arm64",
        _ => "x64",
    };
    format!("{os}-{arch}")
}

/// 操作系统的**类别名**（`windows` / `macos` / `linux`）。
///
/// 客户端身份头 `X-Os-Category` 与激活事件体的 `device_os_category` 共用这一处。
pub fn os_category() -> &'static str {
    match super::hostenv::platform() {
        "mac" => "macos",
        "linux" => "linux",
        _ => "windows",
    }
}

/// 推理请求上的「客户端身份头」（参考实现 `buildLlmIdentityHeaders` 的移植）。
///
/// 编码套餐的入口是**给官方客户端用的**，上游按客户端形态识别请求。只发一个
/// 光秃秃的 `Authorization` 也能过鉴权，但上游一旦按形态限流或灰度，缺头就是
/// 难查的失败 —— 而这一套头是免费的。
///
/// 两处**故意**与参考不同（别当成漏抄）：
///   · 不发 `X-Os-Version`：参考实现取 `os.release()`，插件侧读不到系统版本，
///     而它是可选头（参考实现取不到时同样省略）；
///   · 不在这条路上发 `X-Device-Mid`：参考实现明确注明推理路径**从不**发它
///     （那是领取 / 余额那种控制面请求的要求）。
pub fn identity_headers(user_agent_suffix: Option<&str>) -> Vec<(String, String)> {
    let version = app_version();
    let user_agent = match user_agent_suffix.map(str::trim).filter(|text| !text.is_empty()) {
        Some(suffix) => format!("ZCode/{version} {suffix}"),
        None => format!("ZCode/{version}"),
    };
    vec![
        ("HTTP-Referer".to_string(), region::ZCODE_ORIGIN.to_string()),
        ("User-Agent".to_string(), user_agent),
        ("X-ZCode-App-Version".to_string(), version),
        ("X-Title".to_string(), "Z Code@cli".to_string()),
        ("X-Release-Channel".to_string(), "production".to_string()),
        ("X-Client-Language".to_string(), "unknown".to_string()),
        ("X-Client-Timezone".to_string(), "unknown".to_string()),
        ("X-ZCode-Agent".to_string(), "glm".to_string()),
        ("X-Platform".to_string(), platform()),
        ("X-Os-Category".to_string(), os_category().to_string()),
    ]
}

/// 客户端原始请求里的 `max_tokens` / `max_completion_tokens`。
///
/// 套餐池的预算装配要用**客户端原始值**（不是转换后的 payload：通用层可能已经
/// 按它自己的档位表抬过一次，那份额度不能当客户端的意图用）。
pub fn client_max_tokens(body: &Value) -> Option<i64> {
    ["max_tokens", "max_completion_tokens"]
        .iter()
        .find_map(|key| body.get(*key).and_then(Value::as_i64).filter(|value| *value > 0))
}

/// 编码套餐通道：`POST {openai_base}/chat/completions`。
///
/// 三点与 native 逐字一致：
///   1. `Authorization: Bearer {accessToken}`；
///   2. 思考等级只做**归一**（OpenAI 体里没有 budget 概念，`reasoning_effort`
///      是唯一的旋钮），见 `reasoning::apply_to_chat`；
///   3. 流式补 `stream_options.include_usage`：上游只在显式要求时才回用量帧，
///      不补的话这条通道的输入/输出/缓存三列恒为 0（面板看着像没计费）。
///      **不覆盖**客户端已有的取值（那是它的选择，网关补的是缺省值）。
pub fn coding_plan(token: &str, body: &Value, requested: &str) -> Result<Plan> {
    if token.trim().is_empty() {
        return Err(Error::http(400, "ZCode 账号缺少推理凭证，请重新登录"));
    }
    let mut headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
        ("Authorization".to_string(), format!("Bearer {}", token.trim())),
    ];
    headers.extend(identity_headers(None));
    let mut outgoing = if body.is_object() {
        body.clone()
    } else {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    };
    outgoing["model"] = json!(requested);
    super::reasoning::apply_to_chat(&mut outgoing, requested);
    ensure_include_usage(&mut outgoing);
    Ok(Plan {
        url: format!("{}/chat/completions", region::openai_base_url()),
        headers,
        body: outgoing,
        upstream: "chat",
    })
}

/// 流式请求补 `stream_options.include_usage = true`（缺省值，不覆盖客户端取值）。
fn ensure_include_usage(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if object.get("stream").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let options = object
        .entry("stream_options".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(options) = options.as_object_mut() {
        options
            .entry("include_usage".to_string())
            .or_insert_with(|| Value::Bool(true));
    }
}

/// 套餐池通道：`POST {plan}/anthropic/v1/messages`。
///
/// 装配顺序与 native `plan::build_request` 逐条一致（顺序本身就是协议）：
///   1. 校验 `jwt` 与模型名；
///   2. chat 体 → Anthropic 体（`anthropic::request_from_chat`）；
///   3. 思考档位：GLM-5.3 家族的预算装配（`reasoning::apply_to_anthropic`）；
///   4. 系统提示词三段 + 缓存断点 + 上下文前缀（`system_prompt::apply_start_plan`）；
///   5. 头：`Content-Type` / `Authorization` / `anthropic-version` → 验证码令牌
///      → 客户端身份头（UA 与版本与模板绑定）→ 会话归因 → `x-zcode-query-source`。
///
/// `official_prompt` 与 `override_blocks` 来自设置页（`gatewayPrompt` /
/// `gatewayPromptText`）：开关与正文都在网关的用户配置里，插件通过
/// `settings.get` 读到同一份 —— 否则界面上拨了开关、实际发出去的请求不变。
pub fn start_plan(
    jwt: &str,
    body: &Value,
    requested: &str,
    headers_in: &serde_json::Map<String, Value>,
    device_mid: &str,
) -> Result<Plan> {
    if jwt.trim().is_empty() {
        return Err(Error::http(
            400,
            "该 ZCode 账号的套餐凭据字段缺失（jwt），无法使用套餐池（Start Plan）：\
             请检查导入记录及存储格式；只有确认登录态未保存时才需要重新登录",
        ));
    }
    let model = requested.trim();
    if model.is_empty() {
        return Err(Error::http(
            400,
            "套餐池（Start Plan）通道需要明确的模型名：请在客户端指定模型后重试",
        ));
    }
    let mut payload = super::anthropic::request_from_chat(body, model)?;
    super::reasoning::apply_to_anthropic(
        &mut payload,
        model,
        body.get(super::reasoning::EFFORT_FIELD).and_then(Value::as_str),
        client_max_tokens(body),
    );
    let request_context = super::request_context::RequestContext::new(headers_in, body);
    let official_prompt = system_prompt::prompt_enabled();
    let override_blocks = system_prompt::prompt_blocks();
    system_prompt::apply_start_plan(
        &mut payload,
        model,
        device_mid,
        official_prompt,
        override_blocks.as_ref(),
        &request_context,
    )?;

    let mut headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Authorization".to_string(), format!("Bearer {}", jwt.trim())),
        ("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()),
    ];
    if super::captcha::required() {
        let (param, captcha_region) = super::captcha::take().ok_or_else(|| {
            Error::http(
                409,
                "上游当前要求套餐池（Start Plan）推理请求完成人机验证，但本机令牌池为空：\
                 请打开主窗口或浏览器面板页补充令牌；这不是账号失效或套餐额度不足",
            )
        })?;
        headers.push(("X-Aliyun-Captcha-Verify-Param".to_string(), param));
        if !captcha_region.trim().is_empty() {
            headers.push(("X-Aliyun-Captcha-Verify-Region".to_string(), captcha_region));
        }
    }
    let version = system_prompt::client_version().ok_or_else(|| {
        Error::http(500, "ZCode 套餐请求模板缺少对应的客户端版本，请更新提供商插件")
    })?;
    let mut identity = identity_headers(Some(ANTHROPIC_SDK_UA));
    // 套餐推理的版本与正文模板绑定；领取页的版本设置不能单独改写这份报文。
    for (name, value) in &mut identity {
        if name.eq_ignore_ascii_case("user-agent") {
            *value = format!("ZCode/{version} {ANTHROPIC_SDK_UA}");
        } else if name.eq_ignore_ascii_case("x-zcode-app-version") {
            *value = version.clone();
        }
    }
    headers.extend(identity);
    headers.extend(request_context.headers());
    headers.push(("x-zcode-query-source".to_string(), "main_turn".to_string()));
    Ok(Plan {
        url: format!("{}{MESSAGES_PATH}", region::plan_base_url()),
        headers,
        body: payload,
        upstream: "anthropic",
    })
}

/// 查询串（`?app_version=…&platform=…`，两个值都做百分号编码）。
pub fn version_query() -> String {
    format!(
        "app_version={}&platform={}",
        urlencode(&app_version()),
        urlencode(&platform())
    )
}

/// 上游信封里的业务码（`code` / `status`，数字与字符串都认）。
pub fn biz_code(payload: &Value) -> Option<i64> {
    payload
        .get("code")
        .or_else(|| payload.get("status"))
        .and_then(integer_of)
}
