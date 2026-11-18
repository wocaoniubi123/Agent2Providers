//! OfficeAce 的对话链路：**出站构造**（无状态、恒流式）与 **`conversation` 转发**。
//!
//! ── 上游形状（两份独立实现一致，见 native `chat.rs` 的模块头）──
//!   · URL：`{base}/chat/completions`，其中 `base` 是 `model_api_url_base` 规范化
//!     成 `https://<host>/v2` 之后的形态（[`chat_endpoint`] 负责补 `/v2`）。
//!   · 头：`Authorization: Basic base64(model_app_key:model_app_secret)`，
//!     外加桌面端那三个关联头（`Chat-Id` / `Session-Id` / `lang: en`）。
//!   · 体：标准 OpenAI chat；上游**恒流式**，所以要 `stream:true` +
//!     `stream_options.include_usage`。
//!
//! ── 三个实测坑（都写在这里，别在别处重推）──────────────────────
//!   1. **推理预算**：上游把 `max_tokens` 当「推理 + 正文」的总预算，给小了会
//!      HTTP 200 但正文空串（`finish_reason=length`、`reasoning_tokens` 吃掉全部）。
//!      这里的做法是**追加**一个下限（默认 1024），不是 `max()` —— `max()` 会把
//!      「只想要 1 个 token」的意图改掉（见 `REASONING_ALLOWANCE`）。
//!      `max_tokens < 16` 原样透传：那种请求本来就要最小输出。
//!   2. **`thinking` 参数**：`glm-5.3` 系列不收 `thinking:{"type":"disabled"}`，
//!      上游回 400。这里**不预先删**（不知道哪些模型不收），也**不做剥参重试**
//!      （本仓编排层只有「按错误分类原地重发 / 换号」，没有「剥掉某个参数再试」）。
//!      于是客户端自带 `thinking` 时这一发会以 400 透传（同 body 重发结论不变），
//!      去掉该字段即可。本家**自己从不注入** `thinking`，`reasoning_patch` 也是空操作。
//!   3. **生成预算硬上限**：DeepSeek 为 393216，GLM 为 131072；超过时上游返回
//!      400 `ModelArts.81001`。追加推理预算后再限制上限，避免把合法请求加到越界。
//!
//! ── 为什么对话只能走 `conversation` ────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回 501
//! （「Wasm 对话必须使用标准流通道，不接受主程序代发计划」），而 `forwards_response()`
//! 对 wasm 恒为 true —— 所以 `chat` 写了也不会被调用，出站请求必须由插件自己发。
//!
//! ── 流式转发的两条铁律 ─────────────────────────────────────
//!   · **一个字节都没下发之前**判出错误 ⇒ 直接返回 `Err`，让编排层换账号；
//!   · **已经下发之后**再出错 ⇒ 补一条 SSE 错误事件再返回 `Err`，绝不假装成功
//!     （也绝不悄悄从头重发：客户端已经看到半段内容）。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件在对话链路上，零 `unwrap` / `expect` / `panic`。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::credentials::{self, OfficeAceCredential};
use super::util;

/// 推理预算的追加量（默认值；上游把 `max_tokens` 当总预算，见模块头）。
pub const REASONING_ALLOWANCE: i64 = 1024;
/// 小于这个值的 `max_tokens` 原样透传（客户端要的就是最小输出）。
pub const TINY_MAX_TOKENS: i64 = 16;
/// 首包门最多缓冲这么多字节；超过就认为「已经有内容」，直接放行。
const HEAD_BUFFER_LIMIT: usize = 64 * 1024;
/// 非 2xx 诊断体的读取预算。
///
/// 上游的错误正文通常只有几百字节；留 64 KiB 是为了 `messages` 条数超限那条
/// （它会回一段带计数的长文案）。用 [`read_limited`] 而不是 `bytes(limit)`：
/// 后者在**超出**预算时直接报错，于是诊断体会整个丢掉，只剩一句「上游返回 413」。
const ERROR_BODY_BUDGET: usize = 64 * 1024;
/// SSE 结束哨兵。
const DONE_SENTINEL: &str = "[DONE]";

// ── 地址与鉴权 ───────────────────────────────────────────────

/// 模型网关基址的规范形态：`https://<host>/v2`。
///
/// 输入可能是 `https://host`、`https://host/v2`、`https://host/v2/`，
/// 也可能是桌面端 `models.json` 里的 `api_base`（就带 `/v2`）。
pub fn normalize_base(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with("/v2") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v2")
    }
}

/// chat 端点：`{规范化基址}/chat/completions`。
pub fn chat_endpoint(base_url: &str) -> String {
    let base = normalize_base(base_url);
    if base.is_empty() {
        String::new()
    } else {
        format!("{base}/chat/completions")
    }
}

/// 把 `<app_key>:<app_secret>` 编成 Basic 头值。
pub fn basic_authorization(app_key: &str, app_secret: &str) -> String {
    let raw = format!("{app_key}:{app_secret}");
    format!("Basic {}", util::base64_encode(raw.as_bytes()))
}

/// 按推理预算规则改写 `max_tokens`（返回改后的值；`None` = 客户端没给）。
///
/// 规则：给了且 `>= TINY_MAX_TOKENS` 时**追加** [`REASONING_ALLOWANCE`]；
/// `< TINY_MAX_TOKENS` 或没给时原样不动。
pub fn apply_reasoning_allowance(body: &mut Value) -> Option<(i64, i64)> {
    let requested = body.get("max_tokens").and_then(Value::as_i64)?;
    if requested < TINY_MAX_TOKENS {
        return None;
    }
    let raised = requested.saturating_add(REASONING_ALLOWANCE);
    body["max_tokens"] = json!(raised);
    Some((requested, raised))
}

/// 果办上游明确报出的 `max_tokens` 参数上限：
/// DeepSeek：`max_tokens range is [1, 393216]`；GLM：`限制数值范围[1,131072]`。
/// Qwen 限制的是输入与生成的总长度，不套用这里的静态参数上限；未知模型同样不限制。
fn max_tokens_ceiling(wire_model: &str) -> Option<i64> {
    let name = wire_model.to_ascii_lowercase();
    if name.contains("deepseek") {
        Some(393_216)
    } else if name.contains("glm") {
        Some(131_072)
    } else {
        None
    }
}

/// 必须在追加推理预算之后调用；缺少字段或未超限时不改请求。
fn clamp_max_tokens(body: &mut Value) -> Option<i64> {
    let ceiling = max_tokens_ceiling(body.get("model").and_then(Value::as_str)?)?;
    let current = body.get("max_tokens").and_then(Value::as_i64)?;
    if current <= ceiling {
        return None;
    }
    body["max_tokens"] = json!(ceiling);
    Some(ceiling)
}

/// 流式补 `stream_options.include_usage`（**不覆盖**客户端已有的取值）。
pub fn ensure_include_usage(body: &mut Value) {
    if body.get("stream").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let object = match body.as_object_mut() {
        Some(object) => object,
        None => return,
    };
    let options = object
        .entry("stream_options".to_string())
        .or_insert_with(|| json!({}));
    if let Some(options) = options.as_object_mut() {
        options
            .entry("include_usage".to_string())
            .or_insert(Value::Bool(true));
    }
}

/// 上游那三个关联头。`Chat-Id` / `Session-Id` 由我们生成（桌面端也是自己生成的，
/// 不是上游下发），`lang` 固定 `en`。
fn correlation_headers() -> Vec<(String, String)> {
    vec![
        ("Chat-Id".to_string(), util::random_hex(16)),
        ("Session-Id".to_string(), util::random_hex(16)),
        ("lang".to_string(), "en".to_string()),
    ]
}

/// 构造一次 chat 请求的计划（URL + 头 + 体）。
pub struct ChatPlan {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

/// 由凭证与客户端体构造上游请求。
///
/// `client_body` 是**已经过入口协议翻译**的标准 chat 体（本仓编排层给的就是这个形态）。
/// 上游恒流式（依据：两份实现都强制 `stream:true`），所以这里不按客户端的 `stream`
/// 分流 —— 非流式请求由网关按 SSE 聚合回 JSON。
pub fn build_chat_plan(
    credential: &OfficeAceCredential,
    client_body: &Value,
    wire_model: &str,
) -> Result<ChatPlan> {
    if !credential.can_forward() {
        return Err(Error::http(400, "OfficeAce 凭据不完整（要 baseUrl 与网关 Basic 那一对）"));
    }
    let url = chat_endpoint(&credential.base_url);
    if url.is_empty() {
        return Err(Error::http(400, "OfficeAce 账号缺少模型网关基址"));
    }
    let mut body = client_body.clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    // 发送名：网关解析出的 `wire_model` 优先（模型目录收窄之后、上游认识的那个名字），
    // 缺省退回请求体里的 `model`。
    let model = if wire_model.trim().is_empty() {
        body.get("model").and_then(Value::as_str).unwrap_or("").trim().to_string()
    } else {
        wire_model.trim().to_string()
    };
    if model.is_empty() {
        return Err(Error::http(400, "请求缺少模型名称"));
    }
    body["model"] = json!(model);
    // 上游恒流式：强制 true（非流式由网关聚合）
    body["stream"] = json!(true);
    apply_reasoning_allowance(&mut body);
    clamp_max_tokens(&mut body);
    ensure_include_usage(&mut body);

    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
        (
            "Authorization".to_string(),
            basic_authorization(&credential.model_app_key, &credential.model_app_secret),
        ),
    ];
    headers.extend(correlation_headers());
    Ok(ChatPlan { url, headers, body })
}

// ── 错误分类 ─────────────────────────────────────────────────

/// 上游「请求太大」的判据（把超限折成可读的 413）。
///
/// 取值集合抄自实测：`81113` 是条数超限那条线给的码，其余几条是同一件事在
/// APIG / MaaS 两层的不同措辞。参数**要已小写**。
fn request_is_too_large(lower: &str) -> bool {
    [
        "81113",
        "exceeds the maximum size",
        "requestentitytoolarge",
        "payload too large",
        "request body is too large",
        "request body is too long",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// 上游错误分类（`classify` 方法的实现）。
///
/// **判据**取自实测码表，**动作**按四档语义走：
///   - `81113` / `exceeds the maximum size` → `fatal`，**状态码折成 413**：
///     上游给这条带的是 HTTP 429，不先判掉就会被下面的限额档吞掉
///   - `81111` / `81112` / `81114` / `0308` / `TPM` / `rate limit` /
///     `too many requests` / HTTP 429 → `quota_limited`（冷却「该凭据 + 该模型」）
///   - 其余 → `fatal`
pub fn classify(status: u16, body: &Value) -> Value {
    let text = body.to_string();
    let lower = text.to_ascii_lowercase();
    // ── 体积超限**必须先于** `status == 429` 那一条判掉 ──────────────
    // 上游给这条的 HTTP 码就是 429。落进限额档的后果有两层：① 账号被记一次
    // 限额冷却并换号 —— 可它拒的是这份 body 的条数，跟这个号无关，换号后同一份
    // body 照样被拒；② 客户端收到透传的 429，按「暂时忙」继续无限重试一个
    // **必然失败**的请求。上游原文自报了家门（`messages max size is: 5000`）。
    if request_is_too_large(&lower) {
        return json!({
            "kind": "fatal",
            "status": 413,
            "message": format!(
                "请求超过上游上限：{text}（这条拒的是 messages 的条数，上游实测上限 5000 条，\
                 与 token 数无关：把历史清短一些 —— 要减少条数，光把每条改短没用）"
            ),
            "reset_at": Value::Null,
            "upstream_code": Value::Null,
        });
    }
    let rate_limited = status == 429
        || ["81111", "81112", "81114", "0308", "tpm", "rate limit", "too many requests"]
            .iter()
            .any(|marker| lower.contains(marker) || text.contains(marker));
    if rate_limited {
        return json!({
            "kind": "quota_limited",
            "status": status,
            "message": format!("上游返回 {status}: {text}"),
            "reset_at": Value::Null,
            "upstream_code": Value::Null,
        });
    }
    json!({
        "kind": "fatal",
        "status": status,
        "message": format!("上游返回 {status}: {text}"),
        "upstream_code": Value::Null,
    })
}

/// 非 2xx 的响应 → 网关认的错误（带分类码，编排层的换号判据读它）。
fn upstream_error(status: u16, body: &Value, credential: &OfficeAceCredential) -> Error {
    let text = body.to_string();
    let lower = text.to_ascii_lowercase();
    if request_is_too_large(&lower) {
        return Error::http(
            413,
            super::upstream::clean(
                &format!(
                    "请求超过上游上限：{text}（这条拒的是 messages 的条数，上游实测上限 5000 条，\
                     与 token 数无关：把历史清短一些）"
                ),
                credential,
            ),
        )
        .with_code("request_too_large");
    }
    let message = super::upstream::clean(&format!("OfficeAce 上游返回 {status}：{text}"), credential);
    let error = Error::http(if (200..300).contains(&status) { 502 } else { status }, message);
    if status == 429
        || ["81111", "81112", "81114", "0308", "tpm", "rate limit", "too many requests"]
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return error.with_code("rate_limit_exceeded");
    }
    error
}

/// 已下发内容后再出错时补的那一帧（客户端据此知道流断了，而不是正常结束）。
pub fn error_event(error: &Error) -> Value {
    json!({
        "error": {
            "message": error.message,
            "code": error.code.clone().unwrap_or_else(|| "officeace_stream_error".to_string()),
            "status": error.status.unwrap_or(502),
        }
    })
}

// ── 视频/图片能力位 ──────────────────────────────────────────

/// 本家只有文本 chat：图片生成与编辑都没有上游通道。
pub fn images_capabilities() -> Value {
    json!({ "generation": false, "editing": false })
}

// ── 首包门 + 转发 ────────────────────────────────────────────

/// 首包门的状态。
///
/// ── 它守的是什么 ────────────────────────────────────────────
/// 上游把**内容审核**包装成 `HTTP 200 + finish_reason=content_filter` 的假答复
/// （正文是一句固定拒绝话术）。native 把这档声明成 `refusal_markers`，让编排层
/// 把它当**可轮换失败**：队列里还有别的账号/家就换，只剩这一家时给客户端一句
/// 可读错误（不再把套话当答案）。
///
/// 这条判据只有在**一个字节都没下发**之前判出来才有意义 —— 一旦下发，客户端已经
/// 看到内容，换账号也没法把半段回答接上。所以先攒缓冲，攒够了再一次性交出去。
#[derive(Default)]
struct Gate {
    /// 是否已经下发过 `stream.head`
    started: bool,
    /// 尚未下发的规范帧（`data: …\n\n` 形态，原样转发）
    pending: Vec<Vec<u8>>,
    /// 缓冲字节数（超过 [`HEAD_BUFFER_LIMIT`] 就放行）
    buffered: usize,
    /// 是否见过 `[DONE]`
    done: bool,
    /// 是否有过任何一帧（判「上游什么都没给」用）
    frames: usize,
}

impl Gate {
    /// 放行：发头 + 把攒下的帧一次性刷出去。
    fn start(&mut self) -> Result<()> {
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
        }
        for frame in self.pending.drain(..) {
            sdk::stream_bytes(&frame)?;
        }
        self.buffered = 0;
        Ok(())
    }

    /// 收一帧原始 `data:` 载荷，必要时顺手放行。
    fn push(&mut self, data: &str) -> Result<Frame> {
        if data.trim() == DONE_SENTINEL {
            self.done = true;
            // 一帧内容都没有就结束了 —— 这不是成功，得让编排层换账号
            if self.frames == 0 {
                return Ok(Frame::Empty);
            }
            // 有帧但全是空 delta（上游只发了角色帧）：仍要交出一个合法的 SSE 流，
            // 否则客户端拿到的是一个「头都没发过」的空响应，看着像插件没工作。
            if !self.started {
                self.start()?;
            }
            self.forward(data)?;
            return Ok(Frame::Done);
        }
        self.frames += 1;
        let value: Value = match serde_json::from_str(data) {
            Ok(value) => value,
            // 不是 JSON 的帧原样透传（上游偶尔会发注释帧）；不在这里判死
            Err(_) => {
                self.forward(data)?;
                return Ok(Frame::Pass);
            }
        };
        if let Some(error) = value.get("error").filter(|value| !value.is_null()) {
            return Ok(Frame::Fault(Box::new(error.clone())));
        }
        if let Some(reason) = value
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(|choice| choice.get("finish_reason").and_then(Value::as_str))
        {
            if matches!(reason, "content_filter" | "safety") {
                return Ok(Frame::Refused(reason.to_string()));
            }
        }
        let decisive = value
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|choice| {
                let delta = &choice["delta"];
                delta["content"].as_str().is_some_and(|text| !text.is_empty())
                    || delta["tool_calls"].as_array().is_some_and(|calls| !calls.is_empty())
                    || delta["reasoning_content"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty())
                    || delta["reasoning"].as_str().is_some_and(|text| !text.is_empty())
                    || choice.get("message").is_some_and(|value| value.is_object())
            });
        self.forward(data)?;
        if decisive {
            self.start()?;
        }
        Ok(Frame::Pass)
    }

    fn forward(&mut self, data: &str) -> Result<()> {
        let frame = format!("data: {data}\n\n").into_bytes();
        if self.started {
            sdk::stream_bytes(&frame)?;
            return Ok(());
        }
        self.buffered = self.buffered.saturating_add(frame.len());
        self.pending.push(frame);
        if self.buffered > HEAD_BUFFER_LIMIT {
            // 攒够了还没判定：按「有内容」放行，避免无界缓冲
            self.start()?;
        }
        Ok(())
    }
}

/// 读一段响应体，最多 `limit` 字节（超出部分直接放弃，但**不**把已读到的丢掉）。
fn read_limited(response: &mut http::Response, limit: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                if out.len().saturating_add(chunk.len()) > limit {
                    out.extend_from_slice(&chunk[..limit.saturating_sub(out.len())]);
                    break;
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            // 读失败就用已经拿到的部分：诊断体不完整也比没有强
            Err(_) => break,
        }
    }
    out
}

/// 从响应头对象里取一个头（**名字大小写不敏感**）。
///
/// HTTP/2 与部分代理会把头名全小写，而 `Value::get` 是严格字符串比较 —— 直接用
/// `headers["content-type"]` 在那种情形下恒取不到值，分支会静默走到"按 SSE 处理"。
fn header_value(headers: &Value, name: &str) -> String {
    headers
        .as_object()
        .into_iter()
        .flatten()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .unwrap_or("")
        .to_string()
}

/// 一帧的判定。
enum Frame {
    /// 普通内容帧
    Pass,
    /// 结束哨兵
    Done,
    /// 一帧内容都没有就结束了
    Empty,
    /// 流里带错误对象
    Fault(Box<Value>),
    /// 内容审核拒绝（`finish_reason`）
    Refused(String),
}

/// 转发一次对话（`conversation` 的实现）。
pub fn forward(params: &Value) -> Result<()> {
    let account_id = params["account"].as_str().unwrap_or("").trim().to_string();
    if account_id.is_empty() {
        return Err(Error::http(400, "没有可用的 OfficeAce 账号：请在账号页添加并启用账号"));
    }
    let (_, credential) = credentials::current()?;
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let wire_model = params["wire_model"].as_str().unwrap_or("");
    let plan = build_chat_plan(&credential, &body, wire_model)?;
    let payload = serde_json::to_vec(&plan.body)
        .map_err(|_| Error::http(400, "请求体序列化失败"))?;
    let headers = super::upstream::header_object(&plan.headers);
    let mut response = http::open_raw("POST", &plan.url, headers, Some(&payload)).map_err(|error| {
        // 这一条会真的发生时，原因通常不是"网络差"：`wasm.json` 的 `origins` 是硬白名单，
        // 账号里的网关域名（`*.officeace.cn-southwest-2.huaweicloud-agentarts.com`）没被
        // 覆盖时，请求会在出站那一刻被拒，而且编译期完全看不出来。所以把这句话写进错误里。
        Error::http(
            502,
            format!(
                "OfficeAce 上游请求发不出去：{}（如果是网络域被拒，检查本包 wasm.json 的 \
                 origins 是否覆盖账号的网关域名）",
                error.message
            ),
        )
    })?;

    // ① 非 2xx：原样带状态码 + 脱敏诊断体（此时一个字节都没下发，可以直接换账号）
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = read_limited(&mut response, ERROR_BODY_BUDGET);
        let text = String::from_utf8_lossy(&bytes).to_string();
        let body = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "raw": text }));
        return Err(upstream_error(status, &body, &credential));
    }

    // ② 上游偶尔会以 JSON 回一个非流式答复（不是恒流式那条线，但确实发生过）：
    // 这里折成一帧 chunk，让下游看到的是同一种 SSE。
    if header_value(&response.headers, "content-type")
        .to_ascii_lowercase()
        .contains("application/json")
    {
        let value = response.json()?;
        if let Some(error) = value.get("error").filter(|value| !value.is_null()) {
            return Err(upstream_error(502, error, &credential));
        }
        let mut gate = Gate::default();
        gate.push(&value.to_string())?;
        if !gate.done {
            gate.start()?;
            sdk::stream_bytes(format!("data: {DONE_SENTINEL}\n\n").as_bytes())?;
        }
        return Ok(());
    }

    // ③ 首包门：一个字节都没下发之前就决定「交出去」还是「换账号」
    let mut decoder = SseDecoder::default();
    let mut gate = Gate::default();
    let mut outcome: Option<Error> = None;
    loop {
        let chunk = match response.read() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                // 读流中断：已下发就补错误帧（见下面的收尾），未下发直接当失败
                outcome = Some(Error::http(
                    502,
                    format!("OfficeAce 上游流中断：{}", error.message),
                ));
                break;
            }
        };
        let events = match decoder.push(&chunk) {
            Ok(events) => events,
            Err(error) => {
                outcome = Some(error);
                break;
            }
        };
        for event in events {
            match gate.push(&event) {
                Ok(Frame::Pass) => {}
                Ok(Frame::Done) => break,
                Ok(Frame::Empty) => {
                    outcome = Some(Error::http(502, "OfficeAce 未返回有效内容或结束原因"));
                    break;
                }
                Ok(Frame::Fault(error)) => {
                    outcome = Some(upstream_error(502, &error, &credential));
                    break;
                }
                Ok(Frame::Refused(reason)) => {
                    outcome = Some(
                        Error::http(
                            403,
                            format!(
                                "OfficeAce 上游以内容审核拒绝了这次请求（finish_reason={reason}）；\
                                 换一个账号或换一家重试，或改写提示内容"
                            ),
                        )
                        .with_code("content_filter"),
                    );
                    break;
                }
                Err(error) => {
                    outcome = Some(error);
                    break;
                }
            }
        }
        if outcome.is_some() || gate.done {
            break;
        }
    }

    // ④ 收尾：把「已下发」与「未下发」两种失败分开处理
    match outcome {
        Some(error) if gate.started => {
            // 已下发内容后只报告中断，不能把整个请求悄悄从头重发
            sdk::stream_event(&error_event(&error))?;
            Err(error)
        }
        Some(error) => Err(error),
        None if gate.done => Ok(()),
        None if gate.frames == 0 => Err(Error::http(502, "OfficeAce 未返回有效内容或结束原因")),
        None => {
            // 上游没给 [DONE] 就断流了：把攒下的帧交出去并补结束哨兵，
            // 让客户端看到的是一个完整结束的流（而不是"卡住"）
            gate.start()?;
            sdk::stream_bytes(format!("data: {DONE_SENTINEL}\n\n").as_bytes())?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> OfficeAceCredential {
        OfficeAceCredential {
            base_url: "https://gw.example.com".to_string(),
            model_app_key: "app-key".to_string(),
            model_app_secret: "app-secret".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn normalize_base_appends_v2_once() {
        assert_eq!(normalize_base("https://h"), "https://h/v2");
        assert_eq!(normalize_base("https://h/v2"), "https://h/v2");
        assert_eq!(normalize_base("https://h/v2/"), "https://h/v2");
        assert_eq!(normalize_base("  "), "");
        assert_eq!(chat_endpoint("https://h"), "https://h/v2/chat/completions");
        assert_eq!(chat_endpoint(""), "");
    }

    #[test]
    fn basic_authorization_is_standard_base64() {
        // base64("app-key:app-secret") —— 与 openssl 的 base64 逐字一致
        assert_eq!(
            basic_authorization("app-key", "app-secret"),
            "Basic YXBwLWtleTphcHAtc2VjcmV0"
        );
    }

    #[test]
    fn reasoning_allowance_is_appended_not_maxed() {
        let mut body = json!({ "max_tokens": 100 });
        assert_eq!(apply_reasoning_allowance(&mut body), Some((100, 1124)));
        // 只想要 1 个 token 的请求原样透传（`max()` 会把它改成 1024）
        let mut tiny = json!({ "max_tokens": 1 });
        assert_eq!(apply_reasoning_allowance(&mut tiny), None);
        assert_eq!(tiny["max_tokens"], json!(1));
        // 没给就什么都不写
        let mut none = json!({});
        assert_eq!(apply_reasoning_allowance(&mut none), None);
        assert!(none.get("max_tokens").is_none());
    }

    #[test]
    fn max_tokens_is_clamped_after_the_allowance() {
        // 500000 + 1024 会越过 DeepSeek 的 393216，所以压在 393216
        let mut deepseek = json!({ "model": "DeepSeek-V4-Flash", "max_tokens": 500_000 });
        assert_eq!(clamp_max_tokens(&mut deepseek), Some(393_216));
        assert_eq!(deepseek["max_tokens"], json!(393_216));
        let mut glm = json!({ "model": "GLM-5.3", "max_tokens": 200_000 });
        assert_eq!(clamp_max_tokens(&mut glm), Some(131_072));
        // 没超上限的不动
        let mut small = json!({ "model": "DeepSeek-V4-Flash", "max_tokens": 393_000 });
        assert_eq!(clamp_max_tokens(&mut small), None);
        assert_eq!(small["max_tokens"], json!(393_000));
        // Qwen 不套静态上限
        let mut qwen = json!({ "model": "qwen3-max", "max_tokens": 900_000 });
        assert_eq!(clamp_max_tokens(&mut qwen), None);
    }

    #[test]
    fn include_usage_is_added_but_never_overridden() {
        let mut body = json!({ "stream": true });
        ensure_include_usage(&mut body);
        assert_eq!(body["stream_options"]["include_usage"], json!(true));
        let mut explicit = json!({ "stream": true, "stream_options": { "include_usage": false } });
        ensure_include_usage(&mut explicit);
        assert_eq!(explicit["stream_options"]["include_usage"], json!(false));
        // 非流式请求不补（上游那条链不看它）
        let mut plain = json!({ "stream": false });
        ensure_include_usage(&mut plain);
        assert!(plain.get("stream_options").is_none());
    }

    #[test]
    fn plan_forces_stream_and_names_the_model() {
        let plan = build_chat_plan(&credential(), &json!({ "model": "GLM-5" }), "")
            .unwrap_or_else(|_| panic_free_plan());
        assert_eq!(plan.url, "https://gw.example.com/v2/chat/completions");
        assert_eq!(plan.body["stream"], json!(true));
        assert_eq!(plan.body["stream_options"]["include_usage"], json!(true));
        assert!(plan
            .headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value.starts_with("Basic ")));
        assert!(plan
            .headers
            .iter()
            .any(|(name, _)| name == "Chat-Id"));
        // wire_model 优先于请求体里的 model
        let plan = build_chat_plan(&credential(), &json!({ "model": "alias" }), "GLM-5.3")
            .unwrap_or_else(|_| panic_free_plan());
        assert_eq!(plan.body["model"], json!("GLM-5.3"));
    }

    /// 测试辅助：出错时给一个空计划（避免在测试里写 `panic!`）。
    fn panic_free_plan() -> ChatPlan {
        ChatPlan {
            url: String::new(),
            headers: Vec::new(),
            body: Value::Null,
        }
    }

    #[test]
    fn missing_model_is_rejected() {
        assert!(build_chat_plan(&credential(), &json!({}), "").is_err());
        assert!(build_chat_plan(&credential(), &json!({ "model": "  " }), "").is_err());
        assert!(build_chat_plan(&OfficeAceCredential::default(), &json!({ "model": "x" }), "").is_err());
    }

    #[test]
    fn oversize_is_classified_before_the_rate_limit_branch() {
        // 上游给体积超限的 HTTP 码就是 429 —— 必须先判掉，否则会被当成限额冷却账号
        let value = classify(429, &json!({ "error_code": "81113", "error_msg": "messages max size is: 5000" }));
        assert_eq!(value["kind"], json!("fatal"));
        assert_eq!(value["status"], json!(413));
        // 普通 429 仍然是限额
        let value = classify(429, &json!({ "error_msg": "TPM limit exceeded" }));
        assert_eq!(value["kind"], json!("quota_limited"));
        // 其它 4xx 是 fatal
        let value = classify(400, &json!({ "error_msg": "model not found" }));
        assert_eq!(value["kind"], json!("fatal"));
        assert_eq!(value["status"], json!(400));
    }
}
