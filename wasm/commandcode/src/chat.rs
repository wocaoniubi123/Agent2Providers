//! 对话转发：插件自己发 `/alpha/generate`、自己把 NDJSON 折成 chat SSE。
//!
//! ── 为什么是 `conversation` 而不是 `chat` ────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对任何 wasm 包直接返回
//! 501「Wasm 对话必须使用标准流通道，不接受主程序代发计划」，而
//! `forwards_response()` 对 wasm 恒为 true。真正生效的是 `conversation`：插件自己
//! `http::open` 发上游请求，再用 `stream_head` / `stream_bytes` 把 SSE 回给宿主。
//! `chat` 写了也不会被调用（本包不在 `handle` 里挂它，`_` 分支给 unsupported）。
//!
//! ── 与 native 的分工差别（同一份 `build_chat` 的落点变了）──────
//! ```text
//!   native：build_chat 只构造 {url, headers, body} + 报 UpstreamKind::Ndjson，
//!           响应由网关的 ai_sdk_ndjson 状态机翻译；账号轮换 / 冷却 / 重试 /
//!           usage / 取消都在网关编排层。
//!   wasm  ：网关没有翻译层 —— 请求与翻译都必须在本文件 + `ndjson.rs` 里做完，
//!           只把「标准 chat SSE 帧」推给宿主，之后的编排仍归网关。
//! ```
//! 因此本文件要自己读上游字节、自己判断「首帧内容之前失败 = 干净失败」，
//! 而**不是**把上游响应原样转发。
//!
//! ── 缓冲策略（与 atomcode / workbuddy 同一手法）───────────────
//! 在**下发任何字节之前**不发 head：`Output.write` 第一次见到非空帧才
//! `stream_head(200)`。这样：
//!   - 上游回 200 但流内第一件事就是 `{"type":"error"}` → 一次干净的失败
//!     （HTTP 状态由分类结果决定，客户端不会看到「200 + 空回答」）；
//!   - 上游回 200 但没有完成信号就断流 → 同样是一次失败（502），
//!     **不补** `[DONE]` —— 那等于把截断谎报成完整回答；
//!   - 已经下发过正文之后再出错 → 只能补一条错误帧 + `[DONE]`，
//!     这不是选择，是 SSE 的物理约束（字节已经出去了）。
//!
//! ── 两条预请求放在哪 ────────────────────────────────────────
//! native 在 `ensure_token` 里上报指纹；wasm 的会话式通道**不会**先走
//! `token.ensure`（网关直接把 account/body/headers 交给插件），所以这里在
//! 构信封之前自己兜一次。两处共用同一张节流表，不会真的报两遍。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, Error, Result, Value};

use super::{account, errors, fingerprint, ndjson, plan, util};

/// 上游错误体的读取上限（超过就只报状态码）
const ERROR_BODY_LIMIT: usize = 1024 * 1024;

/// 已下发字节的缓冲：只记「head 有没有发出去」
#[derive(Default)]
struct Output {
    /// head 是否已经发出去
    started: bool,
}

impl Output {
    /// 把一帧写出去；第一次写之前先发 head。
    fn write(&mut self, frames: &str) -> Result<()> {
        if frames.is_empty() {
            return Ok(());
        }
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
        }
        sdk::stream_bytes(frames.as_bytes())
    }
}

/// 读上游流并折叠成 chat SSE。
fn pump(output: &mut Output, mut response: http::Response, model: &str) -> Result<()> {
    let mut fold = ndjson::Fold::new(model);
    loop {
        let Some(chunk) = response.read()? else {
            break;
        };
        let frames = fold.push(&chunk);
        output.write(&frames)?;
        // 先看错误（流内 `error` 事件与协议级失败都落在这里），再看终态：
        // `finished()` 为真也可能是「正常收尾」，两者的区别只有 `error` 知道。
        if let Some(error) = fold.take_error() {
            return Err(error);
        }
        if fold.finished() {
            return Ok(());
        }
    }
    let frames = fold.finish();
    output.write(&frames)?;
    if let Some(error) = fold.take_error() {
        return Err(error);
    }
    Ok(())
}

/// `conversation` 的实现。
///
/// 入参就是宿主传下来的同一份请求 JSON（`ConversationRequest` 的序列化形态）：
/// `{provider, account, body, headers, stream, client_stream, wire_model, …}`。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "Command Code 请求体必须是 JSON 对象"));
    }
    // ── 取凭证 ──────────────────────────────────────────────
    // 网关走会话式通道时不会先调 `token.ensure`（它只把 account 交下来），
    // 所以鉴权头必须在这里自己拼，设备指纹也必须在这里自己兜一次。
    let api_key = account::api_key()?;
    fingerprint::ensure_initialized(&api_key);

    // ── 构造 8 键信封 ───────────────────────────────────────
    let built = plan::build(&api_key, &body, &params["headers"]);
    let model = built.body["params"]["model"]
        .as_str()
        .unwrap_or(plan::DEFAULT_MODEL)
        .to_string();

    // ── 发请求 ──────────────────────────────────────────────
    let response = match http::open(
        "POST",
        &built.url,
        util::headers_value(&built.headers),
        Some(&built.body),
    ) {
        Ok(response) => response,
        Err(error) => {
            return Err(Error::http(
                502,
                format!("Command Code 上游请求失败：{}", error.message),
            ))
        }
    };

    // 本家 **HTTP 恒 200**：非 2xx 只可能是真正的网关层故障（或代理插了一手），
    // 按 native 的分类表处理即可。
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = response.bytes(ERROR_BODY_LIMIT)?;
        let error: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        return Err(errors::http_error(status, &error));
    }

    // 网页（风控页 / 反代首页）：绝不能当回答转出去。
    let content_type = util::header_of(&response.headers, "content-type").to_ascii_lowercase();
    if content_type.contains("text/html") {
        return Err(Error::http(502, "Command Code 返回了网页而不是模型回答"));
    }

    let mut output = Output::default();
    match pump(&mut output, response, &model) {
        Ok(()) => Ok(()),
        Err(error) => {
            if output.started {
                // 正文已经下发：只能补一条错误帧 + `[DONE]`（见模块头）。
                let _ = sdk::stream_event(&errors::error_event(&error));
                let _ = sdk::stream_bytes(b"data: [DONE]\n\n");
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_rejects_non_object_bodies_before_any_network_call() {
        let error = forward(&serde_json::json!({ "body": "not-json" })).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
    }

    #[test]
    fn forward_without_an_account_is_a_401_but_the_body_is_checked_first() {
        // 顺序是刻意的：请求体不合法时先报 400（不读账号、不发网络）
        let error = forward(&serde_json::json!({})).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
        // 请求体合法但宿主没有账号：account.get 失败 → 401
        let error = forward(&serde_json::json!({ "body": { "messages": [] } })).err();
        assert_eq!(error.and_then(|error| error.status), Some(401));
    }
}
