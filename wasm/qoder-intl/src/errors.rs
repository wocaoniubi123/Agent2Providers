//! Qoder 上游错误分类：状态码 + 业务码 → 网关该走哪个动作（native `errors.rs`）。
//!
//! ── 上游错误长什么样（分类要顺着钻的缘由）────────────────────
//! 上游用 **403 同时表达三种完全不同的处置**，而且正文常常是**多层嵌套的
//! JSON 字符串**：
//!
//! ```text
//! {"code":"403","message":"{\"code\":\"10605\",\"message\":\"{\\\"isQueued\\\":true,…}\"}"}
//! ```
//!
//!   排队中（10605）→ 等一会儿重发；额度不足（110 / 112 / 113…）→ 换账号；
//!   登录态失效（105）或裸 403 → 刷新凭证重试。只看状态码必然把「排队」
//!   判成「登录失效」—— 那正是 10605 被误报成鉴权失败那条回归的根因。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Value};

use super::protocol::truthy;

/// 上游状态码/错误文本 → 下游能理解的语义分类（源实现 `classifyUpstreamError`）。
///
/// ── 顺序很重要 ──────────────────────────────────────────────
/// **先看响应体里的语义特征，再看状态码**：上游用 403 表达多种情况 ——
/// 带上 pricingUrl 是套餐/额度不足，裸 403 才是鉴权问题。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpstreamKind {
    /// 额度/套餐不足（可换账号重试）
    Quota,
    /// 触发限流（可换账号重试）
    Rate,
    /// 鉴权失败（HTTP 401 或业务码 105）
    Auth,
    /// 上游**拒绝访问**（裸 403，且没有排队 / 额度特征）：权限、地区或未开通。
    ///
    /// 与 [`UpstreamKind::Auth`] 分开的理由：这档刷凭证是白刷 —— 凭证本身是好的。
    Forbidden,
    /// 上游服务异常（可重试）
    Server,
    /// **模型排队中**（业务码 10605）：不是错误，是「暂时排不上号」。
    ///
    /// 上游对免费模型（`qfmodel` = Qwen3.8-Flash）走排队制：空闲时几秒内直接
    /// 出字，繁忙时用 403 承载 `{"isQueued":true,"serviceAvailable":false,
    /// "queueType":"p3","retryAfterSeconds":30}`（业务码 10605，官方错误码表
    /// 写作 "Model request is queued"）。官方 CLI 的做法是等一会儿再发同一
    /// 请求（其二进制里有 `queuePollCount` / `queueRecoveryAttempt` 这类计数）。
    ///
    /// **它必须与 Quota / Auth 分开**：排队既不是账号额度耗尽（不该落冷却、
    /// 不该换账号 —— 换谁都一样在排队），也不是登录态失效（不该刷新凭证，
    /// 更不该给用户一句「登录态已失效」把人引向重新登录）。
    Queued,
    /// 其它（换账号也没用）
    Unknown,
}

/// 上游排队态的信号（业务码 10605 那一族字段）。
#[derive(Clone, Debug, Default)]
pub struct QueueInfo {
    /// 上游建议的重试间隔（秒；`retryAfterSeconds` 优先，其次 `waitTime`）
    pub retry_after_secs: Option<u64>,
    /// 队列档位（`queueType`，实测 "p3"），排障用
    pub queue_type: Option<String>,
    /// 上游声称模型服务是否可用（`serviceAvailable`）
    pub service_available: Option<bool>,
    /// 队列里有多少条（`queueCount`）
    pub queue_count: Option<i64>,
}

/// 分类结果的文案与可重试性
pub struct ClassifiedError {
    pub kind: UpstreamKind,
    /// 面向客户端的人话
    pub message: String,
    /// 上游给出的套餐/定价页链接（有的话拼进提示）
    pub pricing_url: Option<String>,
    /// 排队信号（`kind == Queued` 时有值）
    pub queue: Option<QueueInfo>,
}

impl ClassifiedError {
    fn new(kind: UpstreamKind, message: impl Into<String>, pricing_url: Option<String>) -> Self {
        Self { kind, message: message.into(), pricing_url, queue: None }
    }
}

/// 内容策略拦截的文案特征（全部小写；匹配前把上游文案转小写）
const CONTENT_PATTERNS: &[&str] = &[
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];

/// 客户端可见的**内容拦截提示**（与网关 `CONTENT_BLOCK_HINT` 逐字一致）
pub const CONTENT_BLOCK_HINT: &str = "；内容被上游内容策略拒绝（这类拦截按逐字匹配，不是账号问题）：\
若为客户端 system 模板误报，可在设置页「通用 → 系统提示词」切到「替换」模式；\
若为对话内容本身触发审核，请调整后重试";

// ─── 上游业务码表（官方 SDK 错误码 + 参考实现实测）─────────────────
//
// 这些码**不体现在 HTTP 状态码上**：上游把业务错误放在 SSE 信封的
// `statusCodeValue` 里（或与 403 一起放在响应体里），正文常常是**多层嵌套的
// JSON 字符串**。因此取值要顺着 `message` / `body` / `data` 一路钻进去。

/// 排队中：官方错误码表 "10605 Model request is queued"
const QUEUE_CODES: &[&str] = &["10605"];
/// 登录态失效：官方错误码表 "105 Login or access token expired"
const AUTH_CODES: &[&str] = &["105"];
/// 额度类：110 每日用量上限、112 额度耗尽、113 用量配额耗尽、114 试用额度用完、
/// 115 免费用户配额用完、116/117/118 团队 / 成员 / 个人 Credits 用完、
/// 119 所选模型的免费额度用完、122 计费组上限
const QUOTA_CODES: &[&str] =
    &["110", "112", "113", "114", "115", "116", "117", "118", "119", "122"];

/// 嵌套 JSON 的钻取深度上限（防病态输入下的环；实测两层就到底了）
const SIGNAL_SCAN_DEPTH: usize = 5;

/// 扫出来的判定信号
#[derive(Default)]
struct ErrorSignals {
    codes: Vec<String>,
    queue: QueueInfo,
    is_queued: bool,
}

impl ErrorSignals {
    fn has_code(&self, table: &[&str]) -> bool {
        self.codes.iter().any(|code| table.contains(&code.as_str()))
    }

    /// 是不是排队态：业务码 10605 是硬信号；`isQueued` 为真；
    /// 或「声明服务不可用 + 带了队列档位」这一组合（上游换码时的兜底）
    fn queued(&self) -> bool {
        self.has_code(QUEUE_CODES)
            || self.is_queued
            || (self.queue.queue_type.is_some() && self.queue.service_available == Some(false))
    }
}

/// 顺着嵌套 JSON 抠出业务码与排队信号。
fn scan_signals(raw: &str) -> ErrorSignals {
    let mut signals = ErrorSignals::default();
    let mut current = Some(raw.to_string());
    let mut depth = 0usize;
    while let Some(text) = current.take() {
        depth += 1;
        if depth > SIGNAL_SCAN_DEPTH {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            break;
        };
        if let Some(code) = value.get("code") {
            match code {
                Value::String(text) => signals.codes.push(text.trim().to_string()),
                Value::Number(number) => signals.codes.push(number.to_string()),
                _ => {}
            }
        }
        if value.get("isQueued").map(truthy).unwrap_or(false) {
            signals.is_queued = true;
        }
        if signals.queue.retry_after_secs.is_none() {
            signals.queue.retry_after_secs = ["retryAfterSeconds", "waitTime"]
                .iter()
                .find_map(|key| value.get(*key).and_then(seconds_of));
        }
        if signals.queue.queue_type.is_none() {
            signals.queue.queue_type = value
                .get("queueType")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if signals.queue.service_available.is_none() {
            signals.queue.service_available = value.get("serviceAvailable").map(truthy);
        }
        if signals.queue.queue_count.is_none() {
            signals.queue.queue_count = value.get("queueCount").and_then(Value::as_i64);
        }
        // 下一层：内嵌的 JSON 字符串（上游一层套一层地放 message / body / data）
        current = ["message", "body", "data", "error"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .map(str::to_string)
            .filter(|text| text.trim_start().starts_with('{'));
    }
    signals
}

/// 秒数的两种形态（数字 / 数字字符串）
fn seconds_of(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// 裸文本兜底：正文不是 JSON 时也能认出业务码（转义形态去反斜杠后同形）。
fn raw_has_code(raw: &str, code: &str) -> bool {
    let flat: String = raw.chars().filter(|ch| *ch != '\\').collect();
    flat.contains(&format!("\"code\":\"{code}\""))
        || flat.contains(&format!("\"code\":{code}"))
        || flat.contains(&format!("\"code\": \"{code}\""))
}

/// 从文本里抠出定价页链接（源实现用正则 `/https?:\/\/[^"\\]*\/pricing[^"\\]*/i`）
///
/// ── 折叠为什么必须是 `to_ascii_lowercase` ────────────────────────
/// 这里拿**折叠后的下标**回切**原文**（`&raw[start..]`），前提是两者逐字节对齐。
/// `to_lowercase` 是 Unicode 折叠、**不保字节长度**：`ẞ` 三字节折成 `ß` 两字节、
/// `İ` 两字节折成 `i`+U+0307 三字节。下标一回切就可能落在字符中间或直接越界
/// —— release 是 panic=abort，进程当场死。上游错误正文完全不可控，这条路径
/// 等于把「上游文案里出现一个小写化会变长的字符」变成「网关整体宕机」。
/// `to_ascii_lowercase` 只动 ASCII 字节、长度恒定，且要匹配的 `http` /
/// `/pricing` 都是 ASCII，所以与源实现正则的 `/i` 等价。
fn pricing_url_of(raw: &str) -> Option<String> {
    let lowered = raw.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(offset) = lowered[search_from..].find("http") {
        let start = search_from + offset;
        let rest = &raw[start..];
        let end = rest
            .find(|ch: char| ch == '"' || ch == '\\' || ch.is_whitespace())
            .unwrap_or(rest.len());
        let candidate = &rest[..end];
        if candidate.to_ascii_lowercase().contains("/pricing") {
            return Some(candidate.to_string());
        }
        search_from = start + 4;
        if search_from >= raw.len() {
            break;
        }
    }
    None
}

/// 分类上游错误（源实现 `classifyUpstreamError` 的判定链，逐条对应）。
///
/// ── 顺序要点：排队 → 业务码 → 额度关键词 → 状态码 ──────────────
///   - **排队特征前置于额度关键词**：额度那一串泛词（`plan` / `trial` /
///     `credit`…）只要命中就判额度，而排队正文里带了 `serviceAvailable` 这类
///     字段，先判排队才不会被泛词截胡；
///   - **业务码前置于状态码**：上游用 403 同时表达「排队」「额度不足」
///     「登录态失效」三种完全不同的处置，只看状态码必然误判。
pub fn classify_upstream_error(status: u16, text: &str) -> ClassifiedError {
    let body = text.to_lowercase();
    let pricing = pricing_url_of(text);
    let signals = scan_signals(text);

    // ① 排队中（10605）：既不是额度也不是鉴权，只有「等一会儿再发」这一个动作
    if signals.queued() || raw_has_code(text, QUEUE_CODES[0]) {
        let queue = signals.queue;
        return ClassifiedError {
            kind: UpstreamKind::Queued,
            message: queued_message(&queue),
            pricing_url: None,
            queue: Some(queue),
        };
    }
    // ② 业务码：登录态失效（105）与额度类（110 / 112 / 113 …）
    if signals.has_code(AUTH_CODES) || AUTH_CODES.iter().any(|code| raw_has_code(text, code)) {
        return ClassifiedError::new(UpstreamKind::Auth, "登录态已失效，请重新登录", None);
    }
    if signals.has_code(QUOTA_CODES) || QUOTA_CODES.iter().any(|code| raw_has_code(text, code)) {
        return ClassifiedError::new(
            UpstreamKind::Quota,
            "当前账号额度不足或套餐不支持该模型",
            pricing,
        );
    }
    // ③ 额度关键词 / 定价页链接
    let quota_signals = [
        "pricingurl",
        "insufficient",
        "no_quota",
        "quota_exceed",
        "exceed_quota",
        "exceeded",
        "credit",
        "upgrade",
        "subscription",
        "plan",
        "trial",
    ];
    if pricing.is_some() || quota_signals.iter().any(|signal| body.contains(signal)) {
        return ClassifiedError::new(
            UpstreamKind::Quota,
            "当前账号额度不足或套餐不支持该模型",
            pricing,
        );
    }
    if status == 429 || body.contains("rate limit") || body.contains("too many") {
        return ClassifiedError::new(UpstreamKind::Rate, "请求过于频繁，请稍后重试", None);
    }
    if status == 401 {
        return ClassifiedError::new(UpstreamKind::Auth, "登录态已失效，请重新登录", None);
    }
    if status == 403 {
        // 走到这里说明没有排队、没有额度特征：按权限问题处理（**不**触发刷凭证）
        return ClassifiedError::new(
            UpstreamKind::Forbidden,
            "上游拒绝访问，可能是登录态失效或权限不足",
            None,
        );
    }
    if status >= 500 {
        return ClassifiedError::new(UpstreamKind::Server, "上游服务异常", None);
    }
    ClassifiedError::new(UpstreamKind::Unknown, "", None)
}

/// 排队态面向客户端的文案（说明「不是登录态 / 额度问题」是关键：
/// 改造前这句被写成「登录态已失效」，用户会去重新登录一个完全正常的账号）
fn queued_message(queue: &QueueInfo) -> String {
    match queue.retry_after_secs {
        Some(seconds) => format!(
            "上游模型排队中（模型暂不可服务，上游建议 {seconds} 秒后重试）：这不是登录态或额度问题"
        ),
        None => "上游模型排队中（模型暂不可服务）：这不是登录态或额度问题".to_string(),
    }
}

// ─── 面向宿主的两套产出 ────────────────────────────────────────

/// 一次上游往返的失败。
///
/// 排队与其它错误的**唯一**区别是「还能再试」：`Queued` 交给退避循环，
/// `Fatal` 原样交回编排层。把这条区别做成类型而不是「看状态码猜」，
/// 是因为排队态的状态码（403 → 曾经映射 401）会同时骗过刷新凭证与换账号
/// 两条动作 —— 那种错误没有任何日志会提示。
pub enum Attempt {
    Queued(Queued),
    /// 鉴权失败：**可以强制续期凭证后同账号重试一次**。
    Auth(Error),
    Fatal(Error),
}

impl Attempt {
    /// 落定成客户端可见的错误（等待预算用尽 / 流已开始 / 续期已试过一次时）。
    pub fn into_error(self) -> Error {
        match self {
            Self::Fatal(error) | Self::Auth(error) => error,
            Self::Queued(queued) => queued_error(&queued, 0),
        }
    }
}

/// 上游排队态（业务码 10605：「模型请求排队中」）。
///
/// ── 为什么它是「可重试」而不是「错误」─────────────────────────
/// 官方 CLI 的处理是**等一会儿再发同一请求**，参考实现（CLIProxyAPI 的
/// qoder2api 插件、9router 的队列增强分支）同样按上游建议时长退避重试。
pub struct Queued {
    /// 上游建议的重试间隔（毫秒，已带缺省与钳制）
    pub retry_after_ms: u64,
    /// 面向客户端的说明（等待预算用尽时作为错误文案）
    pub message: String,
    /// 上游原文（截断；进最终错误体，便于排障）
    pub raw: String,
}

/// 排队态落定：**503** + 一句「不是登录态或额度问题」。
///
/// 状态码不能是 401 / 429：那两档在编排层带动作（刷新凭证 / 落账号限额冷却），
/// 排队既不是凭证问题也不是账号问题 —— 换账号也一样在排队。与参考实现
/// （qoder2api 插件的 `qoder_model_busy`）取同一档。
pub fn queued_error(queued: &Queued, waited_ms: u64) -> Error {
    let detail: String = queued.raw.chars().take(300).collect();
    let waited = if waited_ms >= 1000 { waited_ms / 1000 } else { 0 };
    let waited_note = if waited > 0 {
        format!("（已按上游建议等待 {waited} 秒仍不可服务）")
    } else {
        String::new()
    };
    Error::http(503, format!("{}{waited_note}（上游原文：{detail}）", queued.message))
        .with_code("qoder_model_busy")
}

/// 单次排队等待的时长（毫秒）：跟随上游建议，缺省 15 秒，钳在 5～30 秒。
///
/// 上限 30 秒与实测的建议值区间（9～30 秒）同档：等得比上游建议更久没有意义，
/// 只会把客户端的首字等待拖长。
pub fn queue_wait_ms(retry_after_secs: Option<u64>) -> u64 {
    const MIN_SECS: u64 = 5;
    const MAX_SECS: u64 = 30;
    const FALLBACK_SECS: u64 = 15;
    retry_after_secs.unwrap_or(FALLBACK_SECS).clamp(MIN_SECS, MAX_SECS) * 1000
}

/// 分类结果 + 上游原文 → 排队态（退避时长在这里钳制）。
pub fn queued_of(classified: &ClassifiedError, raw: &str) -> Queued {
    let queue = classified.queue.clone().unwrap_or_default();
    Queued {
        retry_after_ms: queue_wait_ms(queue.retry_after_secs),
        message: classified.message.clone(),
        raw: raw.chars().take(300).collect(),
    }
}

/// 上游业务错误（信封里的 statusCodeValue / HTTP 错误体）→ 排队态或定论错误。
///
/// ── 状态码映射必须基于**分类结果**，不能只看业务码 ──────────────
/// 编排层要看的**不是**上游的业务码，而是「这条错误该触发哪个动作」：
///   排队        → **`Queued`**（调用方退避重发；不是错误，也不该刷新凭证/换号）；
///   额度 / 限流 → **429**（编排层据此标记该账号冷却并换下一个账号）；
///   鉴权        → **401**（编排层据此刷新凭证后同账号重试一次）；
///   其余        → 502（原样透传给客户端）。
/// 直接拿业务码当状态码会把「该充值」变成「登录失效」、把「排会儿队」变成
/// 「登录失效」，客户端与用户都会走错方向。
pub fn business_error(
    status: u16,
    kind: UpstreamKind,
    raw: &str,
    message: &str,
    pricing_url: Option<&str>,
    queue: Option<QueueInfo>,
) -> Attempt {
    if kind == UpstreamKind::Queued {
        let classified = ClassifiedError {
            kind,
            message: message.to_string(),
            pricing_url: None,
            queue,
        };
        return Attempt::Queued(queued_of(&classified, raw));
    }
    let detail: String = raw.chars().take(300).collect();
    let message = if message.is_empty() {
        format!("上游返回 {status}: {detail}")
    } else {
        let pricing = pricing_url.map(|url| format!(" 套餐与额度：{url}")).unwrap_or_default();
        format!("上游请求失败：{message}{pricing}（上游原文：{detail}）")
    };
    let mapped = match kind {
        UpstreamKind::Quota | UpstreamKind::Rate => 429,
        UpstreamKind::Auth | UpstreamKind::Forbidden => 401,
        _ => 502,
    };
    let error = Error::http(mapped, message).with_code(status.to_string());
    if kind == UpstreamKind::Auth {
        Attempt::Auth(error)
    } else {
        Attempt::Fatal(error)
    }
}

/// 把**失败的上游 HTTP 响应**转成「排队态或定论错误」。
pub fn http_error(status: u16, raw: &str) -> Attempt {
    let classified = classify_upstream_error(status, raw);
    if classified.kind == UpstreamKind::Queued {
        return Attempt::Queued(queued_of(&classified, raw));
    }
    business_error(
        status,
        classified.kind,
        raw,
        &classified.message,
        classified.pricing_url.as_deref(),
        None,
    )
}

/// `classify` 方法的返回（`ErrorClass` 的 JSON 形态）。
pub fn classify(status: u16, body: &Value) -> Value {
    // 正文可能是对象，也可能是一段裸文本（上游有的是把错误串当字符串回的）
    let raw = match body {
        Value::String(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => body
            .get("message")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| body.to_string()),
    };
    let classified = classify_upstream_error(status, &raw);
    let message = format!("上游返回 {status}: {raw}");
    let upstream_code = body
        .get("code")
        .and_then(Value::as_i64)
        .or_else(|| body.get("code").and_then(Value::as_str).and_then(|text| text.parse().ok()));
    match classified.kind {
        UpstreamKind::Auth => json!({ "kind": "token_expired", "message": message }),
        UpstreamKind::Quota | UpstreamKind::Rate => json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": message,
            "upstream_code": upstream_code,
            "status": if status == 0 { 429 } else { status },
        }),
        // 内容策略拦截（审核文案）→ ContentBlocked：不罚账号，交给编排层换
        // 中性提示词重试一次 + 触发降级
        _ if matched_content(status, body) => json!({
            "kind": "content_blocked",
            "status": status,
            "message": format!("{message}{CONTENT_BLOCK_HINT}"),
            "upstream_code": upstream_code,
        }),
        _ => json!({
            "kind": "fatal",
            "status": status.max(400),
            "message": message,
            "upstream_code": upstream_code,
        }),
    }
}

/// 是否命中内容策略拦截的文案特征（大小写不敏感，状态码要求 `>= 400`）。
fn matched_content(status: u16, error_body: &Value) -> bool {
    if status < 400 {
        return false;
    }
    let Some(message) = error_body.get("message").and_then(Value::as_str) else {
        return false;
    };
    let lowered = message.to_lowercase();
    CONTENT_PATTERNS.iter().any(|pattern| lowered.contains(pattern))
}

/// 流内错误帧（已下发内容后只能留在流里）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({ "error": { "message": error.message, "status": status, "type": "upstream_error" } })
}

#[cfg(test)]
mod tests {
    //! 判定链的几条硬结论：排队不能误判成鉴权、裸 403 不刷凭证、额度码归额度。
    use super::*;

    #[test]
    fn nested_queue_code_is_queued_not_auth() {
        // 上游的正文是「JSON 里套 JSON」，排队信号在第二层
        let inner = json!({ "code": "10605", "message": json!({ "isQueued": true, "retryAfterSeconds": 30 }).to_string() });
        let outer = json!({ "code": "403", "message": inner.to_string() }).to_string();
        let classified = classify_upstream_error(403, &outer);
        assert_eq!(classified.kind, UpstreamKind::Queued);
        assert_eq!(
            classified.queue.as_ref().and_then(|queue| queue.retry_after_secs),
            Some(30)
        );
    }

    #[test]
    fn quota_codes_map_to_quota() {
        let classified = classify_upstream_error(403, &json!({ "code": "112", "message": "exhausted" }).to_string());
        assert_eq!(classified.kind, UpstreamKind::Quota);
    }

    #[test]
    fn bare_403_is_forbidden_not_auth() {
        // 裸 403 不触发刷凭证（刷了也白刷），文案保留「可能是登录态失效或权限不足」
        let classified = classify_upstream_error(403, &json!({ "message": "forbidden" }).to_string());
        assert_eq!(classified.kind, UpstreamKind::Forbidden);
    }

    #[test]
    fn pricing_link_maps_to_quota() {
        let classified = classify_upstream_error(
            403,
            &json!({ "message": "see https://qoder.com/pricing for the plans" }).to_string(),
        );
        assert_eq!(classified.kind, UpstreamKind::Quota);
        assert!(classified.pricing_url.is_some());
    }

    #[test]
    fn queued_business_error_becomes_503() {
        // 排队不能用 401 / 429：那两档会带动「刷凭证」「落冷却」两个动作
        let attempt = business_error(403, UpstreamKind::Queued, "raw", "排队中", None, None);
        assert_eq!(attempt.into_error().status, Some(503));
    }

    #[test]
    fn classify_shape_matches_error_class() {
        let value = classify(429, &json!({ "message": "rate limit reached" }));
        assert_eq!(value["kind"], "quota_limited");
        let value = classify(401, &json!({ "message": "expired" }));
        assert_eq!(value["kind"], "token_expired");
        let value = classify(400, &json!({ "message": "blocked by security policy" }));
        assert_eq!(value["kind"], "content_blocked");
    }

    #[test]
    fn queue_wait_is_clamped() {
        assert_eq!(queue_wait_ms(Some(1)), 5_000);
        assert_eq!(queue_wait_ms(Some(9)), 9_000);
        assert_eq!(queue_wait_ms(Some(600)), 30_000);
        assert_eq!(queue_wait_ms(None), 15_000);
    }
}
