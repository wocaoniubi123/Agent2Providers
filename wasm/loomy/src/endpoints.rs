//! Loomy（讯飞）上游地址与**客户端内置签名对**（插件设置可覆盖）。
//!
//! ── 上游长什么样（依据：Loomy 桌面端 `app.asar`）──────────
//! ```text
//!   账号 CAccount     https://account.xfinfr.com        （HMAC-SHA1 签名头）
//!   集成网关（积分）  https://loomyad.xunfei.cn          （明文 session 放 `token` 头）
//!   模型网关          {集成网关}/api/v1                  （按目录 protocol 选择 Chat / Messages）
//! ```
//!
//! 前两个值来自安装包内加密的 `.env.prod`；模型网关没有独立配置 —— 客户端把
//! 它拼成「积分基址 + `/api/v1`」。
//!
//! ── 签名对为什么内置 ────────────────────────────────────────
//! CAccount 的每个请求都要用**客户端内置的** AccessKey 对签 HMAC-SHA1
//! （随安装包分发、不是用户账号凭证），没有它登录接口一个都调不通。
//! 与 native 侧同一处置：内置为默认值，设置项可覆盖，改动不需要重新编译。
//!
//! ── 为什么要走 `settings.get` 而不是环境变量 ──────────────────
//! Wasm 插件没有进程环境（硬约束禁止读环境变量），覆盖值只能由主程序经
//! `settings.get` 交给插件。键名与 native 的环境变量一一对应，注释里标注。

use agent2api_wasm_sdk as sdk;

/// 账号（CAccount）默认基址
pub const DEFAULT_XFYUN_BASE_URL: &str = "https://account.xfinfr.com";

/// 集成网关默认基址（积分、每日登录刷新与模型网关都挂在这个域下）
pub const DEFAULT_INTEGRATION_BASE_URL: &str = "https://loomyad.xunfei.cn";

/// 客户端内置 AccessKeyId
pub const DEFAULT_ACCESS_KEY_ID: &str = "2thryby66wxi53sk";

/// 客户端内置 AccessKeySecret
pub const DEFAULT_ACCESS_KEY_SECRET: &str = "zsak6eadrbawz683wf5r3m2snrwj868r";

/// 客户端 AppID（请求信封 `base.appid`；Loomy 桌面端的固定值）
pub const DEFAULT_APP_ID: &str = "GM3LOOMY";

/// 推理请求版本头，与 Loomy 桌面端 package.json 一致。
pub const DEFAULT_CLIENT_VERSION: &str = "0.9.39";

/// 读一条设置项；空值 / 类型不对一律视为未设置。
fn setting(key: &str) -> Option<String> {
    sdk::settings::get(key)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// 基址类覆盖：去掉尾部斜杠（拼路径时不能出现 `//api/v1`）。
fn base_setting(key: &str) -> Option<String> {
    setting(key)
        .map(|text| text.trim_end_matches('/').to_string())
        .filter(|text| !text.is_empty())
}

/// 账号（CAccount）基址 —— 对应 native 的 `LOOMY_XFYUN_BASE_URL`。
pub fn xfyun_base_url() -> String {
    base_setting("xfyunBase").unwrap_or_else(|| DEFAULT_XFYUN_BASE_URL.to_string())
}

/// 集成网关基址 —— 对应 native 的 `LOOMY_POINTS_BASE_URL`。
pub fn integration_base_url() -> String {
    base_setting("pointsBase").unwrap_or_else(|| DEFAULT_INTEGRATION_BASE_URL.to_string())
}

/// 模型网关基址：`{集成网关}/api/v1`
pub fn model_base_url() -> String {
    let base = integration_base_url();
    if base.ends_with("/api/v1") {
        base
    } else {
        format!("{base}/api/v1")
    }
}

/// 推理请求版本头（`loomy-version`）。
pub fn client_version() -> String {
    setting("clientVersion").unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string())
}

/// 签名用 AccessKeyId
pub fn access_key_id() -> String {
    setting("accessKeyId").unwrap_or_else(|| DEFAULT_ACCESS_KEY_ID.to_string())
}

/// 签名用 AccessKeySecret
pub fn access_key_secret() -> String {
    setting("accessKeySecret").unwrap_or_else(|| DEFAULT_ACCESS_KEY_SECRET.to_string())
}

/// 请求信封 `base.appid`
pub fn app_id() -> String {
    setting("appId").unwrap_or_else(|| DEFAULT_APP_ID.to_string())
}
