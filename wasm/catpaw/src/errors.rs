//! CatPaw 协议层错误与错误分类。
//!
//! ── 为什么协议层自己定义一个错误类型（native `models.rs` 同一条理由）──
//! 上游失败时除了文案还要回报 `event(status, failReason, failCode, unifyCode)`，
//! 其中 `failCode` / `unifyCode` 来自上游错误体的 `code` / `unifyCode`。
//! `sdk::Error` 只有一个数值型的 `upstream_code` 装不下这两个码，而上游侧的
//! 排障恰恰靠它们。因此协议层用自己的 [`CatPawError`]，在返回给客户端前才
//! 降级成 `sdk::Error`（[`CatPawError::to_error`]）。
//!
//! ── 分类口径照抄 native `adapter.rs` 的 `classify` ──────────────
//! 状态码由协议层归一化后透传，**不**凭 HTTP 状态推断账号限额：
//! 本家没有 429 轮换语义（见 `conversation.rs` 模块头），所有失败都是
//! `fatal`，由编排层决定要不要换账号。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Value};

/// 协议层错误（客户端可见文案 + 上游业务码）。
#[derive(Clone, Debug)]
pub struct CatPawError {
    /// 客户端可见的 HTTP 状态码（上游 4xx 原样，其余 502）
    pub status: u16,
    /// 客户端可见文案
    pub message: String,
    /// 上游业务码（`failCode`）
    pub code: Option<i64>,
    /// 上游统一错误码（`unifyCode`）
    pub unify_code: Option<i64>,
}

impl CatPawError {
    /// 入站参数错误（400，文案照抄 native / 原实现）
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self { status: 400, message: message.into(), code: None, unify_code: None }
    }

    /// 上游/传输错误（502）
    pub fn upstream(message: impl Into<String>) -> Self {
        Self { status: 502, message: message.into(), code: None, unify_code: None }
    }

    /// 上游 HTTP 错误：状态码按原实现归一（4xx 原样，其余 502）
    pub fn http(status: u16, message: impl Into<String>) -> Self {
        let mapped = if (400..500).contains(&status) { status } else { 502 };
        Self { status: mapped, message: message.into(), code: None, unify_code: None }
    }

    /// 挂上游业务码（`failCode` / `unifyCode`）
    ///
    /// `#[allow(dead_code)]`：当前唯一的构造点（`openai::unwrap_api_data` /
    /// `response_error`）都是直接写结构体字面量。保留它是因为「错误带码」是
    /// 上游协议的一部分（`failCode` / `unifyCode` 进终态上报，UPSTREAM_PROTOCOL
    /// §3.3），构造路径不该只有一处字面量。
    #[allow(dead_code)]
    pub fn with_codes(mut self, code: Option<i64>, unify_code: Option<i64>) -> Self {
        self.code = code;
        self.unify_code = unify_code;
        self
    }

    /// 转成插件 SDK 的错误（宿主只认这一种）。
    ///
    /// `upstream_code` 取 `code`：宿主把它透到客户端错误体里，排障时能对上
    /// 上游 `failCode`。`unify_code` 没有对应位，只进终态上报（见 `upstream.rs`）。
    pub fn to_error(&self) -> Error {
        let mut error = Error::http(self.status, self.message.clone());
        if let Some(code) = self.code {
            error = error.with_code(format!("catpaw_upstream_{code}"));
        }
        error
    }

    /// 上游是否报了「会话正在执行中」这一类拒绝。
    ///
    /// 为什么是文案匹配而不是错误码：上游这个拒绝没有稳定的业务码
    /// （原实现也只靠文案描述这一现象），匹配失败只会退化成「不自愈」，
    /// 不会误伤别的错误。
    pub fn is_busy(&self) -> bool {
        self.message.contains("执行中")
    }
}

impl From<Error> for CatPawError {
    fn from(error: Error) -> Self {
        Self {
            status: error.status.unwrap_or(502),
            message: error.message,
            code: error.upstream_code,
            unify_code: None,
        }
    }
}

/// `classify` 的返回（与 native `classify` 逐字段一致）。
///
/// 本家**只有 fatal**：没有 429 限额语义、没有内容拦截位（上游把内容拦截写成
/// 普通业务错误）。把状态码原样透出去，编排层据此决定是否换账号。
pub fn classify(status: u16, body: &Value) -> Value {
    let message = body
        .get("message")
        .or_else(|| body.get("msg"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("上游错误")
        .to_string();
    json!({
        "kind": "fatal",
        "status": status,
        "message": message,
        "reset_at": Value::Null,
        "upstream_code": Value::Null,
    })
}

/// `is_error_response`：本家把 4xx/5xx 一律当错误体（与 native 同口径）。
pub fn is_error_response(status: u16) -> bool {
    status >= 400
}

/// `error.policy`：本地参数错误另带固定标记，宿主据此停止无效换号。
///
/// 判据照抄 native `adapter::error_policy`：`400` + 业务码
/// `catpaw_invalid_request`（本插件在入站参数错误时统一挂这个码）。
/// 上游拒绝与凭证问题**不**挂它 —— 那些换号确实可能解决。
pub fn policy(status: u16, body: &Value) -> Value {
    let code = body.get("code").and_then(Value::as_str);
    if status == 400 && code == Some(super::INVALID_REQUEST_CODE) {
        return json!({
            "stop": true,
            "reason": "CatPaw 请求参数或消息格式不符合要求，换账号无法解决，已停止重试",
        });
    }
    Value::Null
}

/// 入站参数错误的统一包装：挂 `catpaw_invalid_request` 并把状态码固定 400。
///
/// 与 native 的 `run_conversation` 同一处置（`prepare` 的失败一律带这个码），
/// 这样 `error.policy` 才能把「本地格式错误」与「上游拒绝」分开。
pub fn invalid(error: CatPawError) -> Error {
    error.to_error().with_code(super::INVALID_REQUEST_CODE)
}
