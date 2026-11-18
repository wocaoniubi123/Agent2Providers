//! LobsterAI 的对话转发：**同方言透传 + 四处上游强制的改写**。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/chat.rs` + `mod.rs` 的
//! `build_chat`。
//!
//! ── 为什么这一层也很薄 ──────────────────────────────────────
//! 对话端点是 OpenAI 兼容的原生协议（`POST /api/proxy/v1/chat/completions`），
//! 网关本身就是 OpenAI Chat Completions，所以 body 几乎逐字节上行、上游的 SSE
//! 帧逐字节下发（`executor.go:16-27` 的模块头：语言不同，但「原样透传 + 只改
//! 必须改的」这条口径一样）。剩下的只有四件格式本身表达不了的事。
//!
//! ── 只改四处，每处都有它非改不可的理由（全部实测）────────────────
//!   1. **`role: "developer"` → `"system"`**：上游不认 OpenAI 新版角色，
//!      带它的请求被上游以 **HTTP 502「角色信息不正确」**拒绝（system / user
//!      均 200）。两者在 OpenAI 规范里语义相同，按 `system` 下发
//!      （`executor.go:83-86` 的实测注 + `demoteDeveloperMessages`）。
//!      ⚠️ native 里通用转发层还会做一次同样的归一（`upstream::payload::send_body`
//!      的 ⓪ 角色归一层）；wasm 侧**没有**那一层（插件自己发请求），所以这一段
//!      在这里是**唯一**的一道 —— 删掉它上游就 502。
//!   2. **`tool_choice` 在 `""` / `"none"` / `null` 时删掉**：客户端可能原样
//!      转发一个上游拒绝的取值（`executor.go:114-123`）。
//!   3. **绝不下发 `prompt_cache_key`**：那是腾讯后端的机制，本家不知道认不认
//!      （`executor.go:63-64` 的原文）；存在就删。
//!   4. **`model` 走一次名字解析**（展示名 / 规范化别名 → 线上 id）：
//!      与 `atomcode/chat.rs` 同一手法，认不出时**原样发**，不猜。
//!      网关通常已按目录把 body 里的模型名改写成线上名，所以这一步一般是一次
//!      幂等的确认；留着它是为了「客户端直接点名一个规范化别名」那条路。
//!
//! ── 两处**刻意不做**的改写（都是实测结论）──────────────────────
//!   · **不转换图片**：上游只收 `{type:"image_url",image_url:{url}}`，收到
//!     `{type:"image"}` 会回 HTTP 500。我们**不做**形状修补 —— 让上游把它的
//!     真实错误如实报给客户端，好过我们替它猜一种可能不对的形状（与本仓
//!     「广告能力要有实测依据、不编造」的口径一致）。
//!   · **不改 `stream_options`**：上游没声明认它，native 也没发。
//!
//! ── 与 native 的一处**补强**：`stream` 在缺失时补 true ─────────────
//! native 的注释说「不动 `stream`」，理由是「本网关的转发入口恒以 `stream:true`
//! 请求上游」。那条不变式在网关侧确实成立（`rpc.rs` 的 `forward_conversation`
//! 恒发 `stream: true`），所以这里**不改写**已经是 true 的值；只在字段缺失或
//! 不是 true 时补上 —— 本家 `stream:false` 上游直接回 HTTP 500
//! （`executor.go:18-21` 实测），插件是这条要求的最后一道，补一个字段比让
//! 客户端收到一个「看起来像上游坏了」的 500 划算。
//!
//! ── 两条边界：已下发后出错 / 尚未下发就出错 ─────────────────────
//! ```text
//!   尚未下发：上游非 2xx           -> stream_head(上游状态) + 错误体
//!             首帧之前遇到错误帧   -> stream_head(按帧判定的状态) + 该帧
//!             两者都让网关「收齐 body -> 调 classify」走换号 / 刷新
//!   已下发后：错误帧原样下发（客户端能看见真实原因），流中断如实报中断
//! ```
//! 为什么尚未下发时不用 `Err(...)`：网关只有在错误对象带 `provider_http:` 前缀
//! 时才走分类，其余按「插件失败」处置（不换号、不刷新）。而 `stream_head(4xx/5xx)`
//! 会让网关收齐 body 后**调本插件的 `classify`**（`rpc.rs:2121-2178`），
//! 这条才是 native 的判定顺序真正生效的地方。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::account;
use super::credentials::Credentials;
use super::errors::{self, StreamFailure};
use super::models;
use super::upstream::{self, CLIENT_CAPABILITIES, MAX_BODY_BYTES, USER_AGENT, chat_url};
use super::version;

/// 上游不认的 OpenAI 角色名（带它会被上游以 HTTP 502「角色信息不正确」拒绝）
const DEVELOPER_ROLE: &str = "developer";
/// 归一后的角色名（两者在 OpenAI 规范里语义相同）
const DEMOTED_ROLE: &str = "system";

/// 把 `role: "developer"` 的消息改成 `"system"`（原地改写，非对象条目原样放过）。
///
/// 见模块头的实测表：这是上游的硬要求，不是风格偏好。
fn demote_developer_messages(object: &mut serde_json::Map<String, Value>) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(entry) = message.as_object_mut() else {
            continue;
        };
        let is_developer = entry
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(|role| role == DEVELOPER_ROLE);
        if is_developer {
            entry.insert("role".to_string(), Value::String(DEMOTED_ROLE.to_string()));
        }
    }
}

/// `tool_choice` 是否属于「上游会拒绝、必须删掉」的取值（`""` / `"none"` / `null`）。
fn tool_choice_must_go(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty() || text.trim().eq_ignore_ascii_case("none"),
        _ => false,
    }
}

/// 一次失败要用的 HTTP 状态码（网关据此走错误分支 + 调本插件的 `classify`）。
///
/// 优先级：帧里自带的 4xx/5xx（上游明说了）→ 按类别推断（额度 402 / 会话 401）
/// → 兜底 502。
fn failure_status(payload: &str) -> u16 {
    if let Some(status) = errors::frame_status(payload) {
        return status;
    }
    match errors::silent_failure_in_frame(payload) {
        Some(StreamFailure::HardCredit { .. }) => 402,
        // 会话已死：401 让网关走「刷新 + 同账号重试一次」
        Some(StreamFailure::SessionDead { .. }) => 401,
        // 其它业务错误按上游偶发处理（Go 的 default 分支同样换号）
        _ => 502,
    }
}

/// 把一段错误体折成「先给状态、再给正文」—— 网关会收齐正文并调 `classify`。
///
/// 这是「尚未下发就出错」的唯一出口（见模块头的边界表）。
fn head_failure(status: u16, body: &[u8]) -> Result<()> {
    let status = if (400..600).contains(&status) { status } else { 502 };
    sdk::stream_head(status)?;
    sdk::stream_bytes(body)?;
    Ok(())
}

/// 流式回传状态机。
///
/// ── 为什么自己维护「已下发」标志 ─────────────────────────────
/// 一旦调用过 `stream_head(200)`，状态码就发出去了 —— 此后**不能**再把这次请求
/// 变成「402 / 401 换号」，网关已经按成功开了一条流。所以首帧之前的错误必须
/// 在 `frame()` 里拦住，而不是等收尾时才发现（那会把一个「该换号」的错误变成
/// 「客户端收到一个半截流」）。
#[derive(Default)]
struct Output {
    /// 是否已经下发过响应头
    started: bool,
    /// 是否已经收到结束标记
    complete: bool,
    /// 已下发的 SSE 帧数（诊断用）
    frames: usize,
    /// 首帧之前遇到的错误帧原文（`Some` = 这一轮没成，按失败出口处理）
    rejected: Option<String>,
}

impl Output {
    fn start(&mut self) -> Result<()> {
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
        }
        Ok(())
    }

    /// 处理一帧 `data:` 内容；返回 `true` 表示还可以继续读流。
    fn frame(&mut self, data: &str) -> Result<bool> {
        if self.complete {
            return Ok(false);
        }
        let trimmed = data.trim();
        if trimmed.is_empty() {
            // 空帧（keep-alive 注释帧之类）不占行，跳过而不是下发一个空事件
            return Ok(true);
        }
        if trimmed == "[DONE]" {
            self.start()?;
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            self.complete = true;
            return Ok(false);
        }
        if !self.started {
            // 首包门：尚未下发时，错误帧不许进流（进流就等于把换号机会丢掉）
            if errors::silent_failure_in_frame(trimmed).is_some() {
                self.rejected = Some(trimmed.to_string());
                return Ok(false);
            }
        }
        self.start()?;
        let bytes = format!("data: {data}\n\n");
        sdk::stream_bytes(bytes.as_bytes())?;
        self.frames = self.frames.saturating_add(1);
        Ok(true)
    }

    /// 吃掉一个上游响应。
    fn consume(&mut self, mut response: http::Response) -> Result<()> {
        let content_type = response.headers["content-type"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        // 防御：本家「只收 SSE」（`stream:false` 会被上游 500），但真出现 JSON 时
        // 也要能读 —— 要么是错误体（交给失败出口），要么是一次性应答（折成 chunk）。
        if content_type.contains("application/json") {
            let text = upstream::read_limited(&mut response, MAX_BODY_BYTES);
            let parsed: Value =
                serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone()));
            if parsed.get("error").is_some_and(|error| !error.is_null()) {
                self.rejected = Some(text);
                return Ok(());
            }
            return self.one_shot(&parsed);
        }
        if content_type.contains("text/html") {
            return Err(Error::http(502, "LobsterAI 返回了网页而不是模型回答"));
        }
        let mut decoder = SseDecoder::default();
        while let Some(bytes) = response.read()? {
            for event in decoder.push(&bytes)? {
                if !self.frame(&event)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// 把一次性（非流式）应答折成一个标准 chunk，走同一条下发路径。
    ///
    /// 上游理论上不会走这里；保留它是因为「200 + application/json」在代理链路上
    /// 偶有出现，此时宁可把内容折成 SSE 交给客户端，也不要报一句看不懂的解析错误。
    fn one_shot(&mut self, value: &Value) -> Result<()> {
        let chunk = one_shot_chunk(value)?;
        self.frame(&chunk.to_string())?;
        self.frame("[DONE]")?;
        Ok(())
    }
}

/// 把一次性应答的 JSON 折成流式 chunk 的**纯函数**（`message` → `delta`）。
///
/// 抽出来是为了能脱网单测：`one_shot` 一旦真下发就要打宿主（`stream_head`）。
fn one_shot_chunk(value: &Value) -> Result<Value> {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return Err(Error::http(502, "LobsterAI 响应缺少 choices"));
    };
    let mut chunk = value.clone();
    chunk["object"] = json!("chat.completion.chunk");
    chunk["choices"] = Value::Array(
        choices
            .iter()
            .map(|choice| {
                let mut choice = choice.clone();
                // message → delta（流式帧的形状）
                choice["delta"] = choice.get("message").cloned().unwrap_or(Value::Null);
                if let Some(object) = choice.as_object_mut() {
                    object.remove("message");
                }
                choice
            })
            .collect(),
    );
    Ok(chunk)
}

/// 构造一次上游调用的 body（四处改写，见模块头）。
fn prepare_body(body: &Value) -> Result<Value> {
    if !body.is_object() {
        return Err(Error::http(400, "LobsterAI 请求体必须是 JSON 对象"));
    }
    let requested = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if requested.is_empty() {
        return Err(Error::http(400, "请求缺少 model 字段"));
    }
    let mut payload = body.clone();
    let Some(object) = payload.as_object_mut() else {
        return Err(Error::http(400, "LobsterAI 请求体不是 JSON 对象"));
    };
    // ① developer → system（上游 502「角色信息不正确」的唯一成因，见模块头）
    demote_developer_messages(object);
    // ② tool_choice：`""` / `"none"` / `null` 一律删掉
    if object.get("tool_choice").is_some_and(tool_choice_must_go) {
        object.remove("tool_choice");
    }
    // ③ 绝不下发 prompt_cache_key（腾讯后端机制，本家不认）
    object.remove("prompt_cache_key");
    // ④ 模型名解析：展示名 / 规范化别名 → 线上 id；认不出原样发
    let wire_model = models::upstream_id_for(&requested).unwrap_or_else(|| requested.clone());
    object.insert("model".to_string(), Value::String(wire_model));
    // ⑤ `stream` 兜底置 true。网关的对话入口**恒发** `stream: true`
    //    （`rpc.rs` 的 `forward_conversation`：非流式由网关自己聚合），所以
    //    native 那句「不要动 stream」在网关这一侧成立；但本家 `stream:false`
    //    会被上游直接 500（`executor.go:18-21` 实测），插件是该不变式的最后
    //    一道，所以只在缺失 / 非 true 时补上，不去改写已经是 true 的值。
    if object.get("stream").and_then(Value::as_bool) != Some(true) {
        object.insert("stream".to_string(), Value::Bool(true));
    }
    Ok(payload)
}

/// 一次对话转发（`conversation` 的实现）。
///
/// `params` 的关键字段：`account`（账号 id）、`body`（客户端请求体）、
/// `headers`（客户端头，本家不用）、`wire_model`（网关解析出的发送名）。
pub fn forward(params: &Value) -> Result<()> {
    let credentials = Credentials::from_secret(&account::current_secret()?)?;
    let payload = prepare_body(&params["body"])?;
    let headers = vec![
        (
            "authorization".to_string(),
            format!("Bearer {}", credentials.access_token),
        ),
        // 只收 SSE：Accept 两个都报（照 Go `chatHeaders` 的
        // `text/event-stream, application/json`）
        (
            "accept".to_string(),
            "text/event-stream, application/json".to_string(),
        ),
        // ⚠️ `Content-Type` **必须显式发**：reqwest 的 `.body()` 不会自动补这个头，
        // 而剥掉它之后上游回的是**鉴权之后的** `{"code":500,"message":"服务器内部错误"}`
        // （HTTP 500，约 46ms 即返），跨模型稳定复现，看上去像「网关坏了」而不是
        // 「少了个头」。判据：同一账号打同一个域名的其它 POST（换码 `/api/auth/exchange`、
        // 签到）都带了它且成功；伪令牌探针证明上游**先鉴权**（401 code 40100），
        // 所以 500 出在鉴权之后。两个参考实现也都把它列在四个基础头里。
        (
            "content-type".to_string(),
            "application/json".to_string(),
        ),
        // 两个客户端头都是功能性的（能力位过滤模型、版本决定被当成哪个客户端）
        (
            "x-lobsterai-client-capabilities".to_string(),
            CLIENT_CAPABILITIES.to_string(),
        ),
        (
            "x-lobsterai-client-version".to_string(),
            version::resolve(),
        ),
        // UA 固定不跟随真实版本（照抄参考实现，不是装饰）
        ("user-agent".to_string(), USER_AGENT.to_string()),
    ];

    let mut response = http::open("POST", &chat_url(), upstream::header_object(&headers), Some(&payload))
        .map_err(|error| Error::http(502, format!("LobsterAI 请求发不出去：{}", error.message)))?;

    // ── 尚未下发 · 边界一：上游给出了非 2xx ──────────────────────
    // 把状态码与错误体原样交给网关（它会收齐 body 再调 `classify`），
    // 于是 402 / 40100 / 429 / 5xx 的判定顺序与 native 逐条一致。
    let status = response.status;
    if !(200..300).contains(&status) {
        let body = upstream::read_limited(&mut response, MAX_BODY_BYTES);
        return head_failure(status, body.as_bytes());
    }

    // ── 2xx：进流 ───────────────────────────────────────────────
    let mut output = Output::default();
    output.consume(response)?;

    // 尚未下发 · 边界二：首帧之前出现了错误帧（HTTP 200 下的业务失败）
    if let Some(rejected) = output.rejected.clone() {
        let failure = failure_status(&rejected);
        return head_failure(failure, rejected.as_bytes());
    }
    if !output.complete {
        // 流断在半路。分开两种话说：已下发（客户端已见到部分内容，只能报中断）
        // 与未下发（一个字节都没给，可以如实报「没有收到有效内容」）。
        return Err(if output.started {
            Error::http(
                502,
                format!(
                    "LobsterAI 上游流提前中断（已下发 {} 帧），已下发的内容保留，请重试",
                    output.frames
                ),
            )
        } else {
            Error::http(502, "LobsterAI 上游没有返回任何内容就结束了")
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_role_is_demoted_in_place() {
        let mut object = json!({
            "messages": [
                { "role": "developer", "content": "规则" },
                { "role": "user", "content": "你好" },
                "not-an-object",
            ]
        });
        // 不写 expect：`if let` 拿不到映射时下面的断言会直接失败
        if let Some(map) = object.as_object_mut() {
            demote_developer_messages(map);
        }
        assert_eq!(object["messages"][0]["role"], json!("system"));
        assert_eq!(object["messages"][0]["content"], json!("规则"));
        // 其它角色不动、非对象条目原样放过
        assert_eq!(object["messages"][1]["role"], json!("user"));
        assert_eq!(object["messages"][2], json!("not-an-object"));
    }

    #[test]
    fn tool_choice_is_dropped_only_for_the_rejected_values() {
        assert!(tool_choice_must_go(&Value::Null));
        assert!(tool_choice_must_go(&json!("")));
        assert!(tool_choice_must_go(&json!("  ")));
        assert!(tool_choice_must_go(&json!("none")));
        assert!(tool_choice_must_go(&json!("NONE")));
        assert!(!tool_choice_must_go(&json!("auto")));
        assert!(!tool_choice_must_go(&json!("required")));
        assert!(!tool_choice_must_go(&json!({ "type": "function" })));
    }

    #[test]
    fn prepare_body_applies_all_four_rewrites() {
        let body = json!({
            "model": "glm-5",
            "stream": false,
            "prompt_cache_key": "tc-1",
            "tool_choice": "none",
            "messages": [{ "role": "developer", "content": "x" }],
        });
        let prepared = prepare_body(&body).unwrap_or(Value::Null);
        assert_eq!(prepared["model"], json!("glm-5"));
        assert_eq!(prepared["messages"][0]["role"], json!("system"));
        assert!(prepared.get("prompt_cache_key").is_none());
        assert!(prepared.get("tool_choice").is_none());
        // 本家只收 SSE：即使客户端要非流式，也按流式发上游
        assert_eq!(prepared["stream"], json!(true));
        // 原 body 不被改动（幂等确认：同一个 body 再来一次结果一样）
        assert_eq!(body["stream"], json!(false));
        let again = prepare_body(&prepared).unwrap_or(Value::Null);
        assert_eq!(again, prepared);
    }

    #[test]
    fn prepare_body_rejects_bad_shapes() {
        assert_eq!(
            prepare_body(&json!("字符串")).err().and_then(|error| error.status),
            Some(400)
        );
        assert_eq!(
            prepare_body(&json!({ "messages": [] })).err().and_then(|error| error.status),
            Some(400)
        );
        // 空白模型名同样算缺字段
        assert_eq!(
            prepare_body(&json!({ "model": "   " })).err().and_then(|error| error.status),
            Some(400)
        );
    }

    #[test]
    fn prepare_body_keeps_unknown_names_verbatim() {
        let prepared =
            prepare_body(&json!({ "model": "totally-new-model" })).unwrap_or(Value::Null);
        // 认不出就原样发（猜一个更接近的名字比原样发更糟）
        assert_eq!(prepared["model"], json!("totally-new-model"));
    }

    #[test]
    fn failure_status_follows_the_frame() {
        // 上游明说 4xx/5xx → 用它
        assert_eq!(failure_status(r#"{"error":{"status":429,"message":"too many"}}"#), 429);
        // 业务码不是 HTTP 状态 → 按文案判
        assert_eq!(
            failure_status(r#"{"error":{"code":40101,"message":"token rejected"}}"#),
            401
        );
        assert_eq!(failure_status(r#"{"error":{"message":"额度已用完"}}"#), 402);
        assert_eq!(failure_status(r#"{"error":{"message":"模型不存在"}}"#), 502);
    }

    #[test]
    fn one_shot_response_is_folded_into_a_chunk() {
        let chunk = one_shot_chunk(&json!({
            "id": "x",
            "choices": [{ "message": { "role": "assistant", "content": "你好" }, "finish_reason": "stop" }]
        }))
        .unwrap_or(Value::Null);
        assert_eq!(chunk["object"], json!("chat.completion.chunk"));
        assert_eq!(chunk["choices"][0]["delta"]["content"], json!("你好"));
        // message 必须被移走（否则客户端会同时看到两种字段）
        assert!(chunk["choices"][0].get("message").is_none());
        assert_eq!(chunk["choices"][0]["finish_reason"], json!("stop"));
        // 没有 choices 时如实报错
        assert_eq!(
            one_shot_chunk(&json!({ "id": "x" }))
                .err()
                .and_then(|error| error.status),
            Some(502)
        );
    }
}
