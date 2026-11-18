//! 流内错误信封：CodeArts 的失败**有时不体现在 HTTP 状态上**。
//!
//! ── 为什么单独立一个模块 ────────────────────────────────────
//! 上游把「福利额度用尽」这类失败塞在 **HTTP 200 的 SSE 体里**：流干净地开始、
//! 干净地结束，中间只有一帧 `{"error_code":"InferHub.4291.200", "error_msg":
//! "insufficient quota"}`。如果只看 HTTP 状态，这就成了「成功但一个字都没答」——
//! 而**跨账号降级链的触发条件完全依赖错误分类是否正确**：分类错了，编排层就
//! 不会换下一个账号，用户拿到一个假的成功。所以这套判定是整套迁移里权重最高的
//! 逻辑之一。
//!
//! ── 三条不能想当然的规则 ───────────────────────────────────
//!   1. **`error_code` 为空、或 ∈ {`0`, `0000`, `success`} 不算故障**。空是普通
//!      数据帧；这三个值是这套信封的「成功」写法。
//!   2. **同一帧里只要带了任何答案，就绝不判故障**。`delta.content` /
//!      `delta.reasoning_content` / `delta.tool_calls` / `choices[].text` /
//!      非 `[DONE]` 的 `text` 都算答案 —— 带错误码又带内容的那种帧，丢内容
//!      比漏报一次故障更糟。
//!   3. **`details[]` 只取一条「短且不含冒号」的**。实测里 `details` 装的是
//!      `requestId: …` / `traceId: …` 这类 trace 装饰，它们重复同一个错误码、
//!      对排障毫无价值，还会把真正的消息挤没。
//!
//! 分类：`insufficient quota` → 403（额度耗尽，换账号）；含 `429` / `rate limit`
//! / `too many` → 429（限流）；其余 → 502。

use agent2api_wasm_sdk::{json, Error, Value};

/// SSE 的结束哨兵；它出现在 `text` 字段里时不算答案。
pub const DONE_SENTINEL: &str = "[DONE]";
/// 「这个模型不吃图片」的上游码片段（`InferHub.001001020.406`）。
pub const NOT_MULTIMODAL_CODE: &str = "001001020";
/// 这句英文是上游给「模型不是多模态」的固定话术（大小写不敏感）。
const NOT_MULTIMODAL_MARKER: &str = "is not multimodal";

/// 这套信封里的「成功」码（大小写不敏感）。
fn is_success_code(code: &str) -> bool {
    matches!(code.to_ascii_lowercase().as_str(), "0" | "0000" | "success")
}

/// 一帧里带的答案内容；`null` / 空 / 只有 role 的 delta 都算「没内容」。
fn delta_has_content(delta: &Value) -> bool {
    let Some(object) = delta.as_object() else {
        return false;
    };
    let content = match object.get("content") {
        // 字符串形态
        Some(Value::String(text)) => !text.is_empty(),
        // 数组形态（多模态分段）：里面只要有非空 text 就算
        Some(Value::Array(parts)) => parts.iter().any(|part| {
            part.get("text")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty())
        }),
        _ => false,
    };
    if content {
        return true;
    }
    if object
        .get("reasoning_content")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return true;
    }
    object
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
}

/// `choices[]` 里任何一处带了答案都算「这帧有内容」。
fn choices_have_content(choices: &Value) -> bool {
    let Some(items) = choices.as_array() else {
        return false;
    };
    items.iter().any(|choice| {
        delta_has_content(choice.get("delta").unwrap_or(&Value::Null))
            || delta_has_content(choice.get("message").unwrap_or(&Value::Null))
            || choice
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty())
    })
}

/// 一帧的失败判定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFault {
    /// 上游业务码（写进日志与错误信封）
    pub code: String,
    /// 面向人的消息（含上游码与原始 error_msg）
    pub message: String,
    /// 映射后的 HTTP 状态：403 额度 / 429 限流 / 502 其它
    pub status: u16,
}

/// 这段文案说的是不是「当前模型不支持多模态输入」。
///
/// 三条来路共用这一份判据：流内信封、非 2xx 诊断体、以及折成 `Error` 之后。
pub fn is_not_multimodal(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains(NOT_MULTIMODAL_CODE) || lowered.contains(NOT_MULTIMODAL_MARKER)
}

/// 把「模型不吃图片」这条错误换成一句**用户能照着做**的话；其余错误原样返回。
///
/// ── 为什么值得翻译 ──────────────────────────────────────────
/// 原始文案 `The request model is not multimodal` 缺两样东西：不说「是谁」不支持
/// （用户第一反应是账号或网关坏了），也不说「怎么办」（换掉图片或换个模型就行）。
///
/// ── 为什么保留上游原文 ──────────────────────────────────────
/// 上游码是排障与提工单的唯一凭据。翻译只加一句人话，**不删**原文。
///
/// ── 为什么提示里不点名具体模型 ──────────────────────────────
/// 「该换哪个」取决于账号：目录是三个源合并的账号级清单，各账号可见的支持图片
/// 模型并不相同。写死一个名字会在没有它的账号上变成新的误导。
pub fn humanize_fault_message(message: String, model: &str) -> String {
    if !is_not_multimodal(&message) {
        return message;
    }
    let model = model.trim();
    let subject = if model.is_empty() {
        "当前模型".to_string()
    } else {
        format!("模型 {model} ")
    };
    format!(
        "{subject}不支持图片输入：请去掉消息里的图片改用纯文本，\
         或在模型列表里换一个支持图片的模型（上游原文：{message}）"
    )
}

/// 判一帧（已去掉 `data:` 前缀并解成 JSON 的载荷）是不是故障帧。
///
/// 载荷不是 JSON 对象、是空串、是 `[DONE]`、是成功码、或**带了任何答案**时一律
/// 返回 `None` —— 宁可漏报一帧，也不要把内容丢掉。
pub fn stream_frame_fault(payload: &str) -> Option<StreamFault> {
    let payload = payload.trim();
    if payload.is_empty() || payload == DONE_SENTINEL {
        return None;
    }
    let frame: Value = serde_json::from_str(payload).ok()?;
    if !frame.is_object() {
        return None;
    }
    let code = frame
        .get("error_code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if code.is_empty() || is_success_code(&code) {
        return None;
    }
    // 有答案就不算故障（规则 2）。三个位置都要看：顶层 `delta`、`choices[]`、顶层 `text`
    let text = frame.get("text").and_then(Value::as_str).unwrap_or("").trim();
    let has_answer = delta_has_content(frame.get("delta").unwrap_or(&Value::Null))
        || choices_have_content(frame.get("choices").unwrap_or(&Value::Null))
        || (!text.is_empty() && text != DONE_SENTINEL);
    if has_answer {
        return None;
    }

    let mut message = format!("上游报告 {code}");
    if let Some(detail) = frame.get("error_msg").and_then(Value::as_str).map(str::trim) {
        if !detail.is_empty() {
            message.push('：');
            message.push_str(detail);
        }
    }
    // details 里只认「一条短且不含冒号」的补充说明（规则 3）
    if let Some(items) = frame.get("details").and_then(Value::as_array) {
        for item in items {
            // error_msg 优先，**取不到就退到 error_code**：尺寸那两道墙的标记恰好只写在
            // `error_code` 上（`PARSE_REQUEST_DATA_EXCEPTION`），只看 error_msg 会把它
            // 整条丢掉 —— 于是这句面向人的话里再也没有任何尺寸线索。
            let detail = ["error_msg", "error_code"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_str))
                .unwrap_or("")
                .trim();
            if detail.is_empty() || message.contains(detail) || detail.contains(':') {
                continue;
            }
            message.push_str(&format!("（{detail}）"));
            break;
        }
    }
    let lowered = message.to_lowercase();
    let status = if lowered.contains("insufficient quota") {
        403
    } else if code.contains("429") || lowered.contains("rate limit") || lowered.contains("too many") {
        429
    } else {
        502
    };
    Some(StreamFault { code, message, status })
}

/// 把流内故障转成编排层能用的错误：**带上分类后的状态码**，好让上游循环按
/// 「额度/限流」去换账号，而不是当成一次普通失败。
///
/// `code` 是给**客户端**的第二条判据（状态码那条太粗：403 在本家既可能是额度
/// 也可能是内容闸门）。不少 SDK 拿 `insufficient_quota` 决定要不要停手。
pub fn fault_to_error(fault: &StreamFault) -> Error {
    let error = Error::http(fault.status, fault.message.clone());
    match fault.status {
        403 => error.with_code("insufficient_quota"),
        429 => error.with_code("rate_limit_exceeded"),
        _ => error,
    }
}

/// 流内故障 → 错误，顺带把「模型不吃图片」这条翻成人话。
///
/// 状态码与 `code` 的映射属于 [`fault_to_error`] 的既有口径，这里只补**文案**那
/// 一层，且只在认得出「不支持多模态」时动手（其余错误逐字透传）。
pub fn fault_error(fault: &StreamFault, model: &str) -> Error {
    let error = fault_to_error(fault);
    if !is_not_multimodal(&error.message) {
        return error;
    }
    Error { message: humanize_fault_message(error.message.clone(), model), ..error }
}

/// 给客户端补一条 SSE 错误事件（已下发内容后再出错时用）。
pub fn error_event(error: &Error) -> Value {
    let status = error.status.unwrap_or(502);
    json!({ "error": { "message": error.message, "status": status, "type": "upstream_error" } })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-21 从**真实**上游响应里抓到的额度耗尽信封（HTTP 200 的 SSE 体
    /// 内），一字未改 —— 参考实现也拿它当金向量。
    const QUOTA_FAULT_FRAME: &str = r#"{"error_code":"InferHub.4291.200","error_msg":"insufficient quota","details":[{"error_code":"InferHub.4291.200","error_msg":"requestId: abe754a5417344caa306d5b38a57923b"},{"error_code":"InferHub.4291.200","error_msg":"timestamps: 202609211921"},{"error_code":"InferHub.4291.200","error_msg":"modelId: glm-5.3-flash"},{"error_code":"InferHub.4291.200","error_msg":"traceId: 17c59748cd004b6fadf4660383301ad1"}]}"#;

    /// 测试里的取值助手：没有这个值就是这条测试失败。
    /// 生产代码零 `unwrap` / `expect`；这里的 `panic!` 只存在于 `cfg(test)`。
    fn fault_of(payload: &str) -> StreamFault {
        match stream_frame_fault(payload) {
            Some(fault) => fault,
            None => panic!("这一帧应当被判成故障"),
        }
    }

    #[test]
    fn quota_envelope_is_classified_as_forbidden() {
        let fault = fault_of(QUOTA_FAULT_FRAME);
        assert_eq!("InferHub.4291.200", fault.code);
        assert_eq!(403, fault.status, "额度耗尽要映射成 403（换账号）");
        assert!(fault.message.contains("InferHub.4291.200"));
        assert!(fault.message.contains("insufficient quota"));
        assert!(
            !fault.message.contains("requestId") && !fault.message.contains("traceId"),
            "trace 装饰不能进消息：{}",
            fault.message
        );
    }

    /// 参考实现里那组「绝不能报故障」的帧。
    #[test]
    fn ordinary_traffic_never_reports_a_fault() {
        for (name, payload) in [
            ("空", ""),
            ("结束哨兵", "[DONE]"),
            ("半截 JSON", r#"{"error_code":"#),
            ("成功信封", r#"{"error_code":"0000","error_msg":"success","result":{}}"#),
            ("零码带内容", r#"{"error_code":"0","choices":[{"delta":{"content":"hi"}}]}"#),
            ("普通增量", r#"{"choices":[{"index":0,"delta":{"content":"2"},"finish_reason":"stop"}]}"#),
            ("用量帧", r#"{"id":"x","model":"glm-5.2","usage":{"total_tokens":9}}"#),
            ("带错误码但有内容", r#"{"error_code":"InferHub.4291.200","choices":[{"delta":{"content":"partial"}}]}"#),
            ("原生阶段帧", r#"{"type":"stage","stage":[{"name":"plan"}]}"#),
        ] {
            assert!(
                stream_frame_fault(payload).is_none(),
                "{name}：不该被判成故障（丢了内容比漏报更糟）"
            );
        }
    }

    #[test]
    fn rate_limit_shapes_are_classified_as_too_many() {
        let fault = fault_of(r#"{"error_code":"InferHub.429.429","error_msg":"rate limit exceeded"}"#);
        assert_eq!(429, fault.status);
    }

    #[test]
    fn not_multimodal_message_is_translated_and_keeps_the_upstream_text() {
        let message = humanize_fault_message(
            "上游报告 InferHub.001001020.406：The request model is not multimodal".to_string(),
            "kimi-k3",
        );
        assert!(message.contains("kimi-k3"));
        assert!(message.contains("不支持图片输入"));
        assert!(message.contains("InferHub.001001020.406"), "上游原文不能被删掉");
    }

    #[test]
    fn fault_to_error_carries_the_client_side_code() {
        let error = fault_to_error(&StreamFault {
            code: "InferHub.4291.200".to_string(),
            message: "insufficient quota".to_string(),
            status: 403,
        });
        assert_eq!(Some("insufficient_quota".to_string()), error.code);
        assert_eq!(Some(403), error.status);
    }
}
