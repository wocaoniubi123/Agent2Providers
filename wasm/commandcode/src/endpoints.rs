//! Command Code 上游地址、协议版本与**逐字请求头**。
//!
//! ── 上游长什么样（从网关 `providers/commandcode/endpoints.rs` 原样搬来）──
//! ```text
//!   POST /alpha/generate              聊天生成（唯一生成入口）
//!   POST /alpha/fingerprint/record    设备指纹上报（每 key 首次 + 每 8h+2h）
//!   POST /alpha/lifecycle-events      生命周期事件上报（与指纹并行、同频）
//!   GET  /provider/v1/models          模型目录（5 分钟缓存，失败回落内置清单）
//!   GET  /alpha/billing/credits       额度 / 限流窗口（本家只用它做 key 探活）
//! ```
//! 单一域名 `https://api.commandcode.ai`，**没有国内 / 国际两套域名**，
//! 因此本家是单 provider、单地区。
//!
//! ── 以官方 CLI 的形态请求：头集合就是协议的一部分 ─────────────────────
//! 上游按「像不像官方 CLI」做风控，参考实现逐字对齐了 CLI 的常量表：
//!   - `User-Agent: cli`（**不是** reqwest 默认值）；
//!   - `x-command-code-version` 报「**已实现的**协议版本」而不是 npm 上的最新版；
//!   - 指纹预请求与生成请求**共用同一张头表**；
//!   - **不发 `x-co-flag`**（不在 CLI 常量表里，发出去是破绽）。
//!
//! ── 环境变量覆盖改成设置项（wasm 侧的唯一一处结构差异）──────────────
//! native 用 `COMMANDCODE_API_BASE` / `CC_API_BASE` 等五个环境变量做覆盖；
//! wasm 沙箱没有环境变量，因此改为读本提供商自己的设置项（`sdk::settings::get`），
//! 拿不到就用常量。**注意 `baseUrl` 不是自由的**：`wasm.json` 的 `origins` 是
//! 宿主侧的硬白名单（`manifest.rs::check_url` 逐字比对 origin），指到白名单外的
//! 域会被宿主直接拒绝 —— 这个设置项只用于把默认值改回同一来源，不是绕过口子。
//!
//! ── 硬约束 ────────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, Value};

/// 默认基址（`origins` 里声明的那一个，也是唯一一个）
pub const DEFAULT_BASE_URL: &str = "https://api.commandcode.ai";

/// 本插件**实际实现**的 wire 协议版本（对齐 `command-code@1.53.1` 的方言）。
///
/// 不要写成「npm 上的最新版」：这个值是自称的协议版本，代码里的字段形状才是
/// 实际方言；两者一旦分叉，上报的版本号就成了自相矛盾的证据。
pub const PROTOCOL_VERSION: &str = "1.53.1";

/// 官方 CLI 的 User-Agent 常量（一个字都不能改）
pub const CLI_USER_AGENT: &str = "cli";

/// CLI 环境标识的默认值
pub const CLI_ENVIRONMENT: &str = "production";

/// 生成请求的路径
pub const GENERATE_PATH: &str = "/alpha/generate";
/// 设备指纹上报路径
pub const FINGERPRINT_PATH: &str = "/alpha/fingerprint/record";
/// 生命周期事件路径
pub const LIFECYCLE_PATH: &str = "/alpha/lifecycle-events";
/// 模型目录路径
pub const MODELS_PATH: &str = "/provider/v1/models";
/// 额度 / 限流窗口路径（key 探活用）
pub const BILLING_CREDITS_PATH: &str = "/alpha/billing/credits";

/// 读一个设置项（空值视为未设置）。
///
/// 宿主没有声明这个设置项时 `settings.get` 会给 `null` 或报错，两种情况都按
/// 「未设置」处理 —— 与 native「空值视为未设置」的口径一致。
pub fn setting(name: &str) -> Option<String> {
    sdk::settings::get(name)
        .ok()
        .filter(|value| value.is_string())
        .map(|value: Value| value.as_str().unwrap_or("").trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 基址：设置项 `baseUrl` 可覆盖（去尾部斜杠），默认常量。
pub fn base_url() -> String {
    setting("baseUrl")
        .map(|value| value.trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
}

/// 协议版本：设置项 `protocolVersion` 可覆盖
pub fn protocol_version() -> String {
    setting("protocolVersion").unwrap_or_else(|| PROTOCOL_VERSION.to_string())
}

/// CLI 环境标识：设置项 `cliEnvironment` 可覆盖
pub fn cli_environment() -> String {
    setting("cliEnvironment").unwrap_or_else(|| CLI_ENVIRONMENT.to_string())
}

/// 全 URL（含路径）
pub fn url(path: &str) -> String {
    format!("{}{path}", base_url())
}

/// 一家共用的 CLI 客户端头（生成 / 指纹 / 生命周期三处都要这几项）。
///
/// `User-Agent` 显式给 `cli`：HTTP 客户端的默认 UA 会自报「我不是 CLI」。
pub fn cli_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), CLI_USER_AGENT.to_string()),
        ("x-command-code-version".to_string(), protocol_version()),
        ("x-cli-environment".to_string(), cli_environment()),
    ]
}

/// 鉴权头（`Authorization: Bearer <user_key>`）
pub fn auth_headers(api_key: &str) -> Vec<(String, String)> {
    vec![(
        "Authorization".to_string(),
        format!("Bearer {}", api_key.trim()),
    )]
}

/// 条件头 `x-cmd-zdr: 1`（零数据留存；仅当客户端带了 `x-cmd-zdr: 1` 时下发）。
pub fn zdr_header(client_headers: &Value) -> Option<(String, String)> {
    let requested = client_headers
        .get("x-cmd-zdr")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    (requested == "1").then(|| ("x-cmd-zdr".to_string(), "1".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zdr_is_only_forwarded_when_the_client_asked() {
        assert_eq!(
            zdr_header(&serde_json::json!({ "x-cmd-zdr": "1" })),
            Some(("x-cmd-zdr".to_string(), "1".to_string()))
        );
        assert_eq!(zdr_header(&serde_json::json!({ "x-cmd-zdr": "0" })), None);
        assert_eq!(zdr_header(&serde_json::json!({})), None);
    }

    #[test]
    fn auth_header_is_bearer_with_trimmed_key() {
        let headers = auth_headers("  user_abc  ");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Authorization");
        assert_eq!(headers[0].1, "Bearer user_abc");
    }

    #[test]
    fn urls_join_without_double_slash() {
        // 设置项在测试环境里读不到（宿主不可用）→ 落在默认基址上
        assert_eq!(url(GENERATE_PATH), "https://api.commandcode.ai/alpha/generate");
    }
}
