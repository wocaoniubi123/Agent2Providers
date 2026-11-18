//! 对话进程的身份与页面业务身份分开。
//!
//! ── 这一层在 wasm 侧变了什么（逐条列清）────────────────────
//!   - `X-Client-Platform` / `X-Stainless-OS` / `X-Stainless-Arch`：native 侧
//!     用 `cfg!(target_os)` + `std::env::consts` 读本机；wasm 目标恒为
//!     `unknown`，因此由设置给出（`clientPlatform` / `clientArch`），
//!     再按 native 的同一张表折成 Stainless 的词表。
//!   - `X-Stainless-Read-Timeout`：native 读调用级超时快照；wasm 宿主没有
//!     这个入口，用与网关默认值一致的常量（见 `READ_TIMEOUT_SECONDS`）。
//!   - `X-Client-OS-Version`：native 读注册表 / `/proc`；wasm 没有文件系统，
//!     改由设置 `clientOsVersion` 提供，为空时**不发**这个头（与 native
//!     「读不到就不发」同一行为）。

use crate::upstream;

const CLIENT_NAME: &str = "@raccoon/office-desktop";
const SDK_VERSION: &str = "2.8.0";
const PYTHON_VERSION: &str = "3.12.13";

/// 网关默认的读超时（`Timeouts` 默认 headers 300 秒 / stream_idle 300 秒，
/// `read_timeout_backstop_ms` 取两者的更大值）。native 侧把它折成秒数写进
/// `X-Stainless-Read-Timeout`（`300` → `300.0`）。
const READ_TIMEOUT_SECONDS: u64 = 300;

/// 对话请求带的「OpenAI Python SDK」身份头。
///
/// 这是官方面向 OpenAI 兼容网关的进程自述；上游按它决定用哪套信封，
/// 与「页面业务身份」（`headers::desktop_client_headers`）是两件事，
/// 所以两套都要发、且**不能被对方覆盖**（同名键由 `upstream::headers_value`
/// 按后写者胜合并，调用顺序因此有意义）。
pub fn headers() -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "User-Agent".to_string(),
            format!("AsyncOpenAI/Python {SDK_VERSION}"),
        ),
        ("X-Stainless-Lang".to_string(), "python".to_string()),
        (
            "X-Stainless-Package-Version".to_string(),
            SDK_VERSION.to_string(),
        ),
        ("X-Stainless-OS".to_string(), stainless_os().to_string()),
        ("X-Stainless-Arch".to_string(), stainless_arch().to_string()),
        ("X-Stainless-Runtime".to_string(), "CPython".to_string()),
        (
            "X-Stainless-Runtime-Version".to_string(),
            PYTHON_VERSION.to_string(),
        ),
        ("X-Stainless-Async".to_string(), "async:asyncio".to_string()),
        ("X-Stainless-Retry-Count".to_string(), "0".to_string()),
        (
            "X-Stainless-Read-Timeout".to_string(),
            format!("{READ_TIMEOUT_SECONDS}.0"),
        ),
        ("X-Client-Name".to_string(), CLIENT_NAME.to_string()),
        (
            "X-Client-Platform".to_string(),
            format!("desktop-{}-{}", desktop_os(), desktop_arch()),
        ),
        ("X-Client-Version".to_string(), upstream::client_version()),
        ("X-Client-Channel".to_string(), "official".to_string()),
    ];
    if let Some(version) = clean(&upstream::client_os_version()) {
        headers.push(("X-Client-OS-Version".to_string(), version));
    }
    headers
}

/// 头部值的清洗规则（与 native 一致）：去空白、只留可打印 ASCII、最长 256 字符。
fn clean(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return None;
    }
    Some(value.chars().take(256).collect())
}

/// 设置里的平台值 `desktop-windows` → `windows`（`headers::desktop_client_headers`
/// 用的就是这个前缀形态，这里只取后缀）。
fn desktop_os() -> String {
    let platform = upstream::client_platform();
    platform
        .strip_prefix("desktop-")
        .unwrap_or(platform.as_str())
        .to_string()
}

fn desktop_arch() -> String {
    upstream::client_arch()
}

/// Stainless 的词表（native 侧同一张映射表）。
fn stainless_os() -> &'static str {
    match desktop_os().as_str() {
        "windows" => "Windows",
        "macos" => "MacOS",
        "linux" => "Linux",
        _ => "Unknown",
    }
}

/// Stainless 的架构词表。
///
/// 与 native 逐条对齐的一点：Python 的 `platform.machine()` 在 Windows x64 上
/// 返回 `AMD64`，所以 Windows + x64 要报 `other:amd64` 而不是 `x64`。
fn stainless_arch() -> &'static str {
    let os = desktop_os();
    match upstream::client_arch().as_str() {
        "x64" if os == "windows" => "other:amd64",
        "x64" => "x64",
        "x86" => "x32",
        "arm64" => "arm64",
        "arm" => "arm",
        _ => "unknown",
    }
}
