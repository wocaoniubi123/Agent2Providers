//! Trae 的转发（**有状态路径**）。
//!
//! ── 为什么本家不能走通用无状态路径 ─────────────────────────
//! 无状态路径的形状是「通用层序列化 body 原样发出、响应按 OpenAI 的 SSE 逐行
//! **透传**」。Trae 的出站方向两头都不合这个假设：
//!
//!   * 请求体是自定义白名单信封（`payload::prepare_body`，多带字段是被拒而不是
//!     被忽略）；
//!   * 响应是另一套 SSE 方言：**没有 `[DONE]`**（结束帧是 `event: done`）、
//!     `token_usage` 是欠到下一帧的、`event: error` 之后上游**还会继续发帧**。
//!
//! 所以这里自己发请求、自己翻帧、自己产出对客户端可见的字节。
//!
//! ── 首包门（本家最要紧的一段）──────────────────────────────
//! 上游的额度/凭证类失败**不带 HTTP 状态**：HTTP 200 + SSE 里一条
//! `event: error`（1005 / 4008 / 4001…）。不拦的话客户端拿到的是"成功但没话"，
//! 而网关这边一次失败连账号都不换。做法是先把流头预读出来（`prefetch`）：
//! 第一帧是错误就**在这里**判成带状态的 `Error` 返回，一个字节都不下发；
//! 第一帧是内容才开始 `stream_head(200)`。CPA 那边是插件自己做过一遍的同类修正。
//!
//! 状态码映射表（本家特有，别家照抄会错）：
//!   `SessionDead` → 401、`SoftRate` / `PlanLimit` → 429、`InputTooLarge` → 413、
//!   `ModelUnavailable` → 404、其余 → 502。
//! 为什么 1005/4008 在网关这边记 429 而不是参考实现内部那 12 小时冷却：
//! 429 是宿主唯一认识的「换账号」信号（有状态路径不自动换号），把冷却时长
//! 留在编排层手里更可控。
//!
//! ── 有状态路径**不会**换账号重试（必须自己续期）──────────────
//! 编排层对有状态家收到的错误是「一律透传」：不换号、不冷却、不重试。
//! 所以两件别家由编排层代劳的事在这里自己做：
//!   ① 临期主动续期（发送前）；② 真被拒 401 时**强制续一次再发一次**。
//! 第二条不能省：Trae 的 refreshToken 一次一换，被拒时手里那份 accessToken
//! 多半是"服务端已吊销"而不是"过期"，不重发就直接把一次可救的调用报成失败。
//!
//! ── 与 native 的两处差别（迁移时改的，必须知道）──────────────
//! * native 在 `punish` 里给账号/模型落冷却标记（`store_mark_limited`）；
//!   宿主没有这个接口，冷却由编排层按 `classify` 的结论处理 —— 本文件因此
//!   只负责状态码与文案，不再碰账号库。
//! * native 对 `stream: false` 会聚合成一个 JSON body；宿主的 `stream.head`
//!   **写死 `content-type: text/event-stream`**，插件没办法交出
//!   `application/json`。所以这里对非流式请求同样按 SSE 下发（首帧即内容），
//!   不再有 `drive_aggregate` 那条分支。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::account;
use super::catalog::Route;
use super::errors::{self, ErrorKind};
use super::headers::{solo_headers, HeaderIdentity};
use super::models;
use super::payload;
use super::stream::{ByteLines, Frame, SoloStream};
use super::upstream::{self, PROVIDER_ID};

const MISSING_TERMINAL: &str = "Trae 上游未给出完成事件即结束，本轮回答可能被截断";

/// 流式读空闲上限等参数由宿主管（插件拿不到 socket 选项），这里只保留
/// 「要不要在缺完成事件时补一条提示」这一个开关。
///
/// native 读的是环境变量 `AGENT2API_TRAE_NO_REQUIRE_TERMINAL`；插件里禁止
/// `std::env::var`，改读设置项 `noRequireTerminal`（默认 false = 要求完成事件）。
fn require_terminal() -> bool {
    !sdk::settings::get("noRequireTerminal")
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

/// 一次出站请求（URL + 头 + 已改写的 body）。
struct Plan {
    url: String,
    headers: Vec<(String, String)>,
    body: Value,
}

/// 目录里的 route 决定出站通道，客户端 model 只用于响应回显。
fn build_plan(credential: &account::Credential, body: &Value, route: &Route, session: &str) -> Result<Plan> {
    if credential.access_token.trim().is_empty() {
        return Err(Error::http(401, "Trae 账号缺少 accessToken，无法转发（请重新登录）"));
    }
    // 谱系闸门（**转发侧也放一份**，不只是落账号时）：账号可能是从迁移导入或
    // 手工写库进来的，那条路不经过 `account.normalize`。Intl 凭据打到 CN host
    // 只会收到一句没头没尾的 401，与其让人猜，不如在这里说清楚。
    if account::is_intl_variant(credential.variant()) {
        return Err(Error::http(400, account::INTL_UNSUPPORTED));
    }
    let identity = HeaderIdentity {
        access_token: credential.access_token.trim(),
        uid: credential.uid.trim(),
        machine_id: credential.machine_id.trim(),
        device_id: credential.device_id.trim(),
    };
    // 上游恒 `stream:true`（`prepare_body` 写死），Accept 因此恒 event-stream。
    let headers = solo_headers(&identity, true);
    Ok(Plan {
        url: format!("{}{}", upstream::AGENT_BASE, upstream::CHAT_PATH),
        headers,
        body: payload::prepare_body(body, route, session)?,
    })
}

/// 发一次请求（**不设总超时**：长推理会被总超时截断；读空闲由宿主管）。
fn send(plan: &Plan) -> Result<http::Response> {
    http::open("POST", &plan.url, upstream::header_object(&plan.headers), Some(&plan.body))
        .map_err(|error| Error::http(502, format!("Trae 请求发不出去：{}", error.message)))
}

/// HTTP 或 JSON 信封里的失败。
fn http_error(status: u16, response: &mut http::Response) -> Error {
    let text = upstream::read_limited(response, 1 << 20);
    let payload: Option<Value> = serde_json::from_str(&text).ok();
    let (code, detail) = payload.as_ref().map(errors::error_event_fields).unwrap_or_default();
    let kind = match status {
        401 => ErrorKind::SessionDead,
        429 => ErrorKind::SoftRate,
        403 => ErrorKind::Client,
        _ if code != 0 => errors::stream_error_kind(code, &detail),
        _ => errors::classify(status, &text),
    };
    let head: String = (if detail.is_empty() { &text } else { &detail }).chars().take(240).collect();
    let status = if status == 403 { 403 } else { errors::status_for(kind) };
    let mut error = Error::http(status, format!("Trae 上游返回 {status}: {head}"));
    if code != 0 {
        error.upstream_code = Some(code);
    }
    error
}

fn frame_error(code: i64, message: &str) -> Error {
    let kind = errors::stream_error_kind(code, message);
    let mut error = Error::http(
        errors::status_for(kind),
        format!("Trae 上游错误：code={code} msg={message}"),
    );
    error.code = Some(PROVIDER_ID.to_string());
    error.upstream_code = Some(code);
    error
}

/// 预读流头：返回「已读出的内容帧」。第一帧是错误就直接 Err。
///
/// 半行换手与 accio 同一处置：缓冲区里没成行的尾巴必须拼回流头，否则被切在
/// chunk 边界的那一帧会静默丢内容。
fn prefetch(response: &mut http::Response, scanner: &mut ByteLines, solo: &mut SoloStream) -> Result<Vec<Frame>> {
    let mut frames: Vec<Frame> = Vec::new();
    while let Some(chunk) = response.read()? {
        // ★ 一整段 chunk 处理完才返回 —— 中途 return 会把**同一段里后面的行**
        //   连同字节一起丢掉（那些行已经从连接里读进来了，换手也换不回来）。
        //   上游经常把 `output`+`token_usage`+`done` 挤在同一段里，所以这不是
        //   理论问题：症状是"用量恒为 0"和"error 帧凭空消失"。
        for line in scanner.push(&chunk) {
            for frame in solo.feed_line(&line) {
                if let Frame::Error { code, message, .. } = &frame {
                    // 门只拦"第一帧就是错误"：内容已经出去过之后再报错，
                    // HTTP 200 已经发出去了，只能留在流里如实告诉客户端。
                    if frames.is_empty() {
                        return Err(frame_error(*code, message));
                    }
                }
                frames.push(frame);
            }
            if solo.completed() {
                break;
            }
        }
        if solo.completed() || !frames.is_empty() {
            return Ok(frames);
        }
    }
    if let Some(line) = scanner.finish() {
        for frame in solo.feed_line(&line) {
            if let Frame::Error { code, message, .. } = &frame {
                if frames.is_empty() {
                    return Err(frame_error(*code, message));
                }
            }
            frames.push(frame);
        }
    }
    for frame in solo.flush_pending() {
        if let Frame::Error { code, message, .. } = &frame {
            if frames.is_empty() {
                return Err(frame_error(*code, message));
            }
        }
        frames.push(frame);
    }
    if frames.iter().any(|frame| matches!(frame, Frame::Chunk(_))) {
        return Ok(frames);
    }
    Err(Error::http(502, "Trae 上游在返回内容前结束，未收到有效回答"))
}

/// 把一帧写成对客户端可见的 SSE 字节。
///
/// `model` 在这里改写成**客户端请求的那个名字**：上游帧里 `model` 恒为空串
/// （参考实现如此，本家的 `SoloStream` 逐字节对齐它也如此），而 OpenAI 客户端
/// 拿空 model 会显示成"未知模型"。
fn render(frame: &Frame, requested: &str) -> Option<String> {
    match frame {
        Frame::Chunk(chunk) => {
            let mut chunk = chunk.clone();
            if !requested.is_empty() {
                if let Some(object) = chunk.as_object_mut() {
                    object.insert("model".to_string(), Value::String(requested.to_string()));
                }
            }
            Some(format!("data: {chunk}\n\n"))
        }
        Frame::Error { code, message, .. } => Some(format!(
            "data: {}\n\n",
            json!({"error": {"message": format!("solo error code={code} msg={message}"), "type": "upstream_error"}})
        )),
        Frame::Done => Some("data: [DONE]\n\n".to_string()),
    }
}

fn request_id() -> String {
    format!("chatcmpl-{}", sdk::now().saturating_mul(1000) % 1_000_000_000_000_000)
}

/// 有客户端会话标识时按账号隔离；没有时使用首条用户消息，工具回灌不另起会话。
fn session_id(body: &Value, session: &str, account: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let first = body
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.iter().find(|message| message.get("role").and_then(Value::as_str) == Some("user")))
        .and_then(|message| message.get("content"));
    let seed = if !session.trim().is_empty() {
        format!("session:{}", session.trim())
    } else if let Some(first) = first {
        format!("message:{first}")
    } else {
        return Ok(super::device::uuid_v4());
    };
    let digest = format!("{:x}", Sha256::digest(format!("trae:{account}:{seed}").as_bytes()));
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    ))
}

fn emit(frame: &Frame, requested: &str) -> Result<()> {
    if let Some(text) = render(frame, requested) {
        sdk::stream_bytes(text.as_bytes())?;
    }
    Ok(())
}

/// 流式下发。`Ok(())` 表示这一轮正常结束（含"上游 error 帧已如实下发"）。
fn drive(
    response: &mut http::Response,
    scanner: &mut ByteLines,
    solo: &mut SoloStream,
    prefetched: Vec<Frame>,
    requested: &str,
) -> Result<()> {
    for frame in prefetched {
        emit(&frame, requested)?;
    }
    if solo.completed() {
        return Ok(());
    }
    while let Some(chunk) = response.read()? {
        for line in scanner.push(&chunk) {
            for frame in solo.feed_line(&line) {
                emit(&frame, requested)?;
            }
            if solo.completed() {
                return Ok(());
            }
        }
    }
    if let Some(line) = scanner.finish() {
        for frame in solo.feed_line(&line) {
            emit(&frame, requested)?;
        }
    }
    // 尾事件可能就是完成通知，必须先解析，再决定是否报告截断。
    let missing = solo.missing_terminal();
    let frames = solo.finish();
    if missing && require_terminal() {
        // native 在这里补一条 `{"error": …}` 事件再发 [DONE]：客户端因此能看见
        // "回答可能被截断"，而不是拿到一个看起来正常的结尾。
        sdk::stream_bytes(
            format!(
                "data: {}\n\n",
                json!({ "error": { "message": MISSING_TERMINAL, "type": "upstream_error" } })
            )
            .as_bytes(),
        )?;
    }
    for frame in frames {
        emit(&frame, requested)?;
    }
    Ok(())
}

/// `conversation` 的入口。
pub fn run(params: &Value) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "Trae 请求体必须是 JSON 对象"));
    }
    let record = account::record()?;
    let account_id = record["id"].as_str().unwrap_or("").to_string();
    let requested = body.get("model").and_then(Value::as_str).unwrap_or_default().to_string();
    let wire_model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(requested.as_str())
        .to_string();
    let mut credential = account::credential(&record)?;
    credential = account::renew_if_due(&record, &credential)?;
    if account::is_intl_variant(credential.variant()) {
        return Err(Error::http(400, account::INTL_UNSUPPORTED));
    }
    // 目录：缓存新鲜就用缓存，否则刷新一次（失败保留旧清单）。native 的
    // `models::refresh(..., false)` 是同一个顺序。
    let cached = models::ensure(&credential);
    let mut routes = cached
        .as_ref()
        .map(|cached| models::routes_for(&cached.catalog, &wire_model))
        .unwrap_or_default();
    if routes.is_empty() {
        let have_catalog = cached.as_ref().is_some_and(|cached| !cached.catalog.is_empty());
        if have_catalog {
            return Err(Error::http(404, "Trae 当前账号的目录没有该模型，请重新获取模型或调整绑定"));
        }
        if payload::is_max_variant(&wire_model) {
            return Err(Error::http(404, "Trae 目录没有该模型的 Max 档位，已拒绝以普通模型代替"));
        }
        let config = payload::sanitize_model_name(&wire_model);
        let config = if config.is_empty() { payload::DEFAULT_CONFIG_NAME } else { config.as_str() };
        routes.push(Route::fallback(config, payload::PRIMARY_FUNCTION));
    }
    let session = session_id(body, params["session"].as_str().unwrap_or(""), &account_id)?;
    let mut renewed = false;
    let mut last_error: Option<Error> = None;
    for route in routes {
        let mut plan = build_plan(&credential, body, &route, &session)?;
        let mut response = send(&plan)?;
        loop {
            let status = response.status;
            let json_response = response
                .headers
                .get("content-type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("application/json"));
            let mut scanner = ByteLines::default();
            let mut solo = SoloStream::new(request_id(), sdk::now() / 1000);
            let prepared = if status >= 300 || json_response {
                Err(http_error(status, &mut response))
            } else {
                prefetch(&mut response, &mut scanner, &mut solo)
            };
            match prepared {
                Ok(prefetched) => {
                    models::remember_route(&wire_model, &route);
                    sdk::stream_head(200)?;
                    // 已下发内容后出错与还没下发就出错是两回事：后者原样抛给
                    // 宿主（可以换号/重试），前者只能补一条错误事件收尾。
                    return match drive(&mut response, &mut scanner, &mut solo, prefetched, &requested) {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            sdk::stream_event(&errors::error_event(&error))?;
                            Err(error)
                        }
                    };
                }
                Err(error) if error.status == Some(401) && !renewed => {
                    // 无状态路径不会替我们"刷新后同一账号重试一次"，这条要自己走。
                    let record = account::record()?;
                    let current = account::credential(&record)?;
                    credential = account::renew_forced(&record, &current)?;
                    renewed = true;
                    plan = build_plan(&credential, body, &route, &session)?;
                    response = send(&plan)?;
                }
                Err(error) if errors::retry_route(status, error.upstream_code, &error.message) => {
                    // 通道不可用：换同模型的下一条目录路由（首包前才允许）。
                    last_error = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::http(404, "Trae 没有可用的模型通道")))
}
