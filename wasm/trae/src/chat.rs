//! 当前账号目录决定function/物理模型。401首帧前仅续一次；4001/4023/1005仅换同模型真实目录路由。
//! 已输出后绝不重放；流后半正式quota错误返回主机，冷却记账能力未接，不私改账号状态。

use super::{
    account, client, credentials, endpoints, errors, events::{Decoder, Event}, headers, models,
    payload, refresh, stream::Output, util,
};
use super::errors::tag_error;
use agent2api_wasm_sdk::{self as sdk, http, Error, Result, Value};
use sha2::Digest;

fn session(params: &Value, record: &Value) -> Result<String> {
    let raw = params["session"].as_str().unwrap_or("").trim();
    if raw.len() > 4096 {
        return Err(Error::http(400, "Trae 会话标识过长"));
    }
    let first = params["body"]["messages"]
        .as_array()
        .and_then(|messages| messages.iter().find(|message| message["role"] == "user"))
        .and_then(|message| message.get("content"));
    let seed = if !raw.is_empty() {
        format!("session:{raw}")
    } else if let Some(first) = first {
        format!("message:{first}")
    } else {
        util::uuid()?
    };
    let caller = params["traeCaller"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or("host-local");
    let secret = credentials::parse(&record["secret"])?;
    let identity = if util::scalar(&secret["uid"]).is_empty() {
        util::digest(util::text(&secret, &["accessToken"]).as_bytes())
    } else {
        account::identity(&secret)
    };
    let mut bytes = sha2::Sha256::digest(
        format!(
            "trae:{}:{caller}:{identity}:{seed}",
            record["id"].as_str().unwrap_or("")
        )
        .as_bytes(),
    )
    .to_vec();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let digest = util::hex(&bytes[..16]);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    ))
}

fn event_name(event: &Event) -> &'static str {
    match event {
        Event::Done { .. } => "done",
        Event::Error(_) => "error",
        Event::Usage(_) => "usage",
        Event::Output { .. } => "output",
        Event::Other => "other",
    }
}

/// 读流并把过程写进 `diag`：上游给了什么状态码、什么 content-type、读了几次、
/// 一共多少字节、收到哪些 event 名、怎么结束的。
///
/// 为什么要这段：2026-11-19 排查 Trae 502 时，同一份请求体直连上游 7 个账号全部
/// 成功，过网关却只收到 23 字节。凭 `upstreamPayloadBytes` 一个数字分不出是
/// 「上游没给」还是「宿主没交到插件手上」，这段把过程摊开在错误文案里。
fn consume(mut response: http::Response, output: &mut Output, diag: &mut String) -> Result<()> {
    let status = response.status;
    let content_type = response.headers["content-type"].as_str().unwrap_or("").to_string();
    let mut decoder = Decoder::default();
    let mut reads = 0usize;
    let mut total = 0usize;
    let mut names: Vec<&'static str> = Vec::new();
    let mut closed = String::from("eof");
    let outcome = loop {
        let bytes = match response.read() {
            Ok(Some(bytes)) => {
                reads += 1;
                total += bytes.len();
                bytes
            }
            Ok(None) => {
                for event in decoder.finish()? {
                    output.apply(event)?;
                }
                closed = "eof".to_string();
                break output.end();
            }
            Err(error) => {
                closed = error.code.clone().unwrap_or_else(|| "err".to_string());
                output.fail(errors::transport(error))?;
                break output.end();
            }
        };
        for event in decoder.push(&bytes)? {
            if names.len() < 10 && names.last() != Some(&event_name(&event)) {
                names.push(event_name(&event));
            }
            output.apply(event)?;
            // 首内容前业务错误及时交给路由/续期；不消费错误后的正常文本。
            if !output.started && output.failure.is_some() {
                closed = "early-fail".to_string();
                *diag = describe(status, &content_type, reads, total, &names, &closed);
                return output.end();
            }
            if output.terminal {
                closed = "done".to_string();
                *diag = describe(status, &content_type, reads, total, &names, &closed);
                return output.end();
            }
        }
    };
    *diag = describe(status, &content_type, reads, total, &names, &closed);
    outcome
}

fn describe(status: u16, content_type: &str, reads: usize, total: usize,
    names: &[&'static str], closed: &str) -> String {
    let ct = if content_type.is_empty() { "<none>" } else { content_type };
    format!("stream: status={status} ct={ct} reads={reads} bytes={total} events={names:?} end={closed}")
}

pub fn forward(mut params: Value) -> Result<()> {
    let mut record = refresh::ensure(false, None)?;
    let model = params["wire_model"]
        .as_str()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| params["body"]["model"].as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if model.is_empty() || model.len() > 512 || model.chars().any(char::is_control) {
        return Err(Error::http(400, "请明确指定 Trae 当前目录中的模型"));
    }
    let shown = params["body"]["model"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or(&model)
        .to_string();
    let mut renewed = false;
    let routes = match models::for_chat(&record, &model) {
        Ok(routes) => routes,
        Err(error) if error.code.as_deref() == Some("trae_session_expired") => {
            record = refresh::ensure(true, Some(&record["secret"]))?;
            renewed = true;
            models::for_chat(&record, &model)?
        }
        Err(error) => return Err(error),
    };
    let session = session(&params, &record)?;
    let mut raw_body = Some(sdk::take_body(&mut params).unwrap_or(Value::Null));
    drop(params);
    let mut last = Error::http(404, "Trae 没有可用的模型通道");
    let mut iter = routes.into_iter().peekable();
    while let Some(route) = iter.next() {
        let source = if iter.peek().is_none() {
            raw_body.take().unwrap_or(Value::Null)
        } else {
            raw_body.as_ref().cloned().unwrap_or(Value::Null)
        };
        let body = match payload::prepare_body(source, &route, &session) {
            Ok(body) => body,
            Err(error) if error.code.as_deref() == Some("trae_route_capability") => {
                last = error;
                continue;
            }
            Err(error) => return Err(error),
        };
        loop {
            let secret = credentials::parse(&record["secret"])?;
            account::unchanged(&record["secret"])?;
            let response = http::open(
                "POST",
                &format!("{}{}", endpoints::AGENT, endpoints::CHAT),
                headers::chat(&secret, true)?,
                Some(&body),
            )
            .map_err(errors::transport)?;
            let status = response.status;
            let json_response = response.headers["content-type"]
                .as_str()
                .unwrap_or("")
                .contains("application/json");
            let mut output = Output::new(&shown)?;
            // 上游 f22828b 把「2xx 但 content-type 是 json」也并入失败分支，
            // 与我原来那条 `trae_json_stream` 诊断是同一件事，取上游的写法。
            let result = if !(200..300).contains(&status) || json_response {
                match client::read(response) {
                    Ok(reply) => Err(tag_error(errors::upstream(status, &reply.body), "trae_http_status")),
                    Err(error) => Err(tag_error(error, "trae_http_status")),
                }
            } else if json_response {
                match client::read(response) {
                    Ok(reply) => Err(tag_error(errors::upstream(status, &reply.body), "trae_json_stream")),
                    Err(error) => Err(tag_error(error, "trae_json_stream")),
                }
            } else {
                let mut diag = String::new();
                let outcome = consume(response, &mut output, &mut diag);
                match outcome {
                    Err(mut error) => {
                        // 诊断必须进**返回值**。`output.end()` 返回的是内部 `failure`
                        // ——那可能是 events 解码时产生的错误（`events.rs` 的
                        // `Event::Error(errors::upstream(..))`），它不带 diag；
                        // 先 fail 再 end 会把拼好的诊断丢掉（2026-11-19 踩过）。
                        if !diag.is_empty() {
                            error.message = format!("{}（{}）", error.message, diag);
                        }
                        let _ = output.fail(error.clone());
                        let _ = output.end();
                        Err(error)
                    }
                    ok => ok,
                }
            };
            if output.started || output.observed_tools() {
                if result.is_ok() {
                    let _ = models::remember(&record["secret"], &model, &route);
                }
                return result;
            }
            match result {
                Ok(()) => {
                    let _ = models::remember(&record["secret"], &model, &route);
                    return Ok(());
                }
                Err(error) if error.code.as_deref() == Some("trae_session_expired") && !renewed => {
                    record = refresh::ensure(true, Some(&record["secret"]))?;
                    renewed = true;
                    if !models::for_chat(&record, &model)?.contains(&route) {
                        return Err(Error::http(
                            409,
                            "Trae 续期后的模型通道已变化，请重新发送请求",
                        )
                        .with_code("local_precondition"));
                    }
                }
                Err(error) if errors::route_retry(&error, status) => {
                    last = error;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Err(last)
}
