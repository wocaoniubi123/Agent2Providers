//! WorkBuddy 的端点与客户端身份（native `crate/workbuddy_shared/endpoints.rs` 的
//! 插件侧副本）。
//!
//! ── 为什么整份搬 ────────────────────────────────────────────
//! 这是整个后端的「唯一事实来源」：登录/账号接口带 prefixPath（`/v2/plugin/...`），
//! 计费/签到/LLM 接口不带（直接 `/v2/...`），UI 与客户端身份头都读这里的常量。
//! 转发头、计费头、growth 的任务请求共用同一批取值 —— 拆成两份必然漂移。
//!
//! ── 两版协议一致，本包只服务国内版 ──────────────────────────
//! `workbuddy`（国内版，`copilot.tencent.com` / `www.workbuddy.cn`）与
//! `workbuddy-intl`（国际版，`www.workbuddy.ai`）协议完全相同，差别只在站点与
//! 客户端身份（UA / platform / 产品名）。国际版由**另一个 wasm 包**负责，
//! 本包 `providers` 只有 `workbuddy` 一条（网关 `provenance.rs` 要求
//! `providers.len() == 1`）。
//!
//! 国际版的那份 `EditionInfo` 仍然保留：存量账号记录的 `edition` 字段可能是
//! `intl`，`resolve_edition` 要能把它解出来给展示用（账号页的版本徽章）。
//! **但它不构成第二个 provider** —— 转发端点仍取账号自己的 `endpoint`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

// 本模块是「端点 / 版本身份」这张表的**完整视图**（native 同名模块也整份保留）：
// 预发布端点、产品名、登录轮询业务码等条目在本包里没有调用方，但删掉之后对照
// native 那份会缺一半，改端点时容易漏改。与 native 同样的处理：保留 + allow。
#![allow(dead_code)]

use agent2api_wasm_sdk::{self as sdk, Value};

/// 默认端点（国内版）
pub const DEFAULT_ENDPOINT: &str = "https://www.workbuddy.cn";
/// 预发布端点（仅文档价值：本包不会主动打它，改端点要靠设置项）
pub const STAGING_ENDPOINT: &str = "https://staging-copilot.tencent.com";
/// 桌面端版本（X-IDE-Version / User-Agent 用）
pub const WORKBUDDY_CLIENT_VERSION: &str = "5.9.3";
/// 产品名
pub const WORKBUDDY_PRODUCT: &str = "WorkBuddy";
/// 桌面端内置 CLI 版本（User-Agent 的 `CLI/<版本>` 段）。
///
/// 服务端按该段识别桌面 CLI 通道：缺失时 `/v3/config` 只下发旧版兼容模型清单
/// （37 个，无 v4.1/5.3/hy4/modelPromotions），带上才下发完整清单（51 个）。
pub const WORKBUDDY_CLI_VERSION: &str = "2.165.0";
/// 鉴权 platform 参数（auth/state?platform=…）
pub const WORKBUDDY_PLATFORM: &str = "workbuddy";
/// 鉴权路径前缀（国内版 /plugin）
pub const DEFAULT_PREFIX_PATH: &str = "/plugin";
/// 管理/计费接口成功码
pub const RESPONSE_CODE_OK: i64 = 0;
/// 登录轮询「token 未就绪」的业务码（auth.token 的 retryCode）
pub const SERVER_CODES_RETRY_FETCH_TOKEN: i64 = 11217;
/// 登录轮询「账号未就绪」的业务码（auth.account 的 retryCode）
pub const SERVER_CODES_RETRY_FETCH_ACCOUNT: i64 = 12151;

/// 一个版本（国内版 / 国际版）的完整身份。
#[derive(Clone, Copy, Debug)]
pub struct EditionInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub endpoint: &'static str,
    pub prefix_path: &'static str,
    /// 鉴权 platform 参数（auth/state?platform=…）
    pub platform: &'static str,
    /// UA 里的客户端段（两版都是 WorkBuddy）
    pub ua_platform: &'static str,
    /// UA 里的产品段（国际版是 WorkBuddy AI）
    pub product_name: &'static str,
    pub client_version: &'static str,
    pub cli_version: &'static str,
    /// 对话链路（`/v2/chat/completions`）的 `X-IDE-Version`。
    ///
    /// 与 `client_version` 分开的原因：2026-10-16 对国际版客户端 5.8.4 抓包后
    /// 确认上游渠道校验按对话请求的身份头识别客户端，过旧的版本号本身是一处
    /// 网关特征；而计费 / 登录 / 目录链路没有对应抓包、也不吃这套身份，
    /// `client_version` 维持原值不动 —— 两套取值不能共用一个字段。
    pub chat_ide_version: &'static str,
    /// 对话链路的完整 UA（含 CLI 扩展段）。
    pub chat_ua: &'static str,
}

/// 国内版 WorkBuddy：copilot.tencent.com / platform workbuddy
pub const EDITION_CN: EditionInfo = EditionInfo {
    id: "cn",
    label: "国内版",
    endpoint: DEFAULT_ENDPOINT,
    prefix_path: DEFAULT_PREFIX_PATH,
    platform: "workbuddy",
    ua_platform: "WorkBuddy",
    product_name: "WorkBuddy",
    client_version: WORKBUDDY_CLIENT_VERSION,
    cli_version: WORKBUDDY_CLI_VERSION,
    chat_ide_version: WORKBUDDY_CLIENT_VERSION,
    chat_ua: "WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0",
};

/// 国际版 WorkBuddy AI：www.workbuddy.ai / platform workbuddy-ai
pub const EDITION_INTL: EditionInfo = EditionInfo {
    id: "intl",
    label: "国际版",
    endpoint: "https://www.workbuddy.ai",
    prefix_path: DEFAULT_PREFIX_PATH,
    platform: "workbuddy-ai",
    ua_platform: "WorkBuddy",
    product_name: "WorkBuddy AI",
    client_version: "5.8.4",
    cli_version: "2.161.0",
    chat_ide_version: "5.8.4",
    chat_ua: "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0",
};

/// 本包服务的版本（国内版）。`providers` 只有一条，恒等于它。
pub fn edition() -> &'static EditionInfo {
    &EDITION_CN
}

/// 本包的 provider id。
pub fn provider_id() -> &'static str {
    "workbuddy"
}

/// 宽松解析版本 id：接受 cn/intl 及若干常见写法，未知值回落国内版
/// （对照 native `resolve_edition`，别名名单逐字保留）。
pub fn resolve_edition(value: Option<&str>) -> &'static EditionInfo {
    let id = value.unwrap_or("").trim().to_lowercase();
    match id.as_str() {
        "" | "cn" | "china" | "mainland" | "workbuddy" | "zh" | "cn-intl" => &EDITION_CN,
        "intl" | "international" | "global" | "ai" | "workbuddy-ai" | "workbuddyai" | "en" => {
            &EDITION_INTL
        }
        _ => &EDITION_CN,
    }
}

/// 带 CLI 扩展段的完整 UA。
///
/// 产品名/客户端版本按版本区分（国际版 v5.8.4 / WorkBuddy AI），platform 段
/// 两版都用 `WorkBuddy`，末尾固定追加 `CLI/<版本>`。
pub fn user_agent_for_edition(edition: Option<&str>) -> String {
    let info = resolve_edition(edition);
    if info.id == "intl" {
        return format!(
            "workbuddy-ai/{version} WorkBuddy/{version} CLI/{cli}",
            version = info.client_version,
            cli = info.cli_version
        );
    }
    format!(
        "{ua}/{version} {product}/{version} CLI/{cli}",
        ua = info.ua_platform,
        version = info.client_version,
        product = info.product_name,
        cli = info.cli_version
    )
}

/// 去掉端点末尾的斜杠（对应 native `normalize_endpoint`）。
pub fn normalize_endpoint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return DEFAULT_ENDPOINT.to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}

/// 按端点推断鉴权前缀（海外站点不带 `/plugin`，对照 native `default_prefix_path`）。
pub fn default_prefix_path(endpoint: &str) -> &'static str {
    let host = normalize_endpoint(endpoint);
    if host == "https://www.codebuddy.ai" || host.starts_with("https://staging-codebuddy") {
        ""
    } else {
        DEFAULT_PREFIX_PATH
    }
}

// ─── 设置项（native 的环境变量旁路）──────────────────────────

/// 读一个设置项的非空字符串值（空白串视为未设置）。
///
/// ── 为什么不是环境变量 ──────────────────────────────────────
/// wasm 沙箱里没有 `std::env`（宿主也不允许读宿主进程环境），native 的
/// `WORKBUDDY_ENDPOINT` / `WORKBUDDY_PREFIX_PATH` 因此改成设置项。
/// 用途不变：staging / 自建网关用户的落点覆盖。
pub fn setting_text(key: &str) -> Option<String> {
    sdk::settings::get(key)
        .ok()
        .and_then(|value| match value {
            Value::String(text) => Some(text),
            Value::Null => None,
            other => Some(other.to_string()),
        })
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// 本地区的端点覆盖（设置项 `endpoint`，对应 native `WORKBUDDY_ENDPOINT`）。
pub fn endpoint_override() -> Option<String> {
    setting_text("endpoint")
}

/// 鉴权前缀覆盖（设置项 `prefixPath`，对应 native `WORKBUDDY_PREFIX_PATH`）。
pub fn prefix_override() -> Option<String> {
    setting_text("prefixPath")
}

// ─── 请求上下文 ─────────────────────────────────────────────

/// 一个请求上下文：`{ base_url, prefix, platform, edition }`。
///
/// prefix 优先级与 native `Context::make` 一致：
///   显式 prefixPath > 显式版本的 prefixPath > 端点推断。
#[derive(Clone, Debug)]
pub struct Context {
    pub base_url: String,
    pub prefix: String,
    pub platform: String,
    pub edition: String,
}

impl Context {
    /// 显式构造上下文；`prefix_path` 为 None 时按「版本已显式给出则用它，
    /// 否则按端点推断」。
    pub fn make(
        endpoint: Option<&str>,
        prefix_path: Option<&str>,
        platform: Option<&str>,
        edition: Option<&str>,
    ) -> Context {
        let explicit_edition = edition.map(|value| !value.trim().is_empty()).unwrap_or(false);
        let info = resolve_edition(edition);
        let base_url = match endpoint.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => normalize_endpoint(value),
            None => info.endpoint.to_string(),
        };
        let prefix = match prefix_path {
            Some(value) => value.to_string(),
            None if explicit_edition => info.prefix_path.to_string(),
            None => default_prefix_path(&base_url).to_string(),
        };
        Context {
            base_url,
            prefix,
            platform: platform
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(info.platform)
                .to_string(),
            edition: info.id.to_string(),
        }
    }

    /// 本包的上下文（端点/前缀可被设置项覆盖）。
    pub fn cn() -> Context {
        let info = edition();
        Context::make(
            endpoint_override().as_deref(),
            prefix_override().as_deref(),
            Some(info.platform),
            Some(info.id),
        )
    }

    /// 鉴权/账号接口基址：`{endpoint}/v2{prefixPath}`
    pub fn auth_api_base(&self) -> String {
        format!("{}/v2{}", self.base_url, self.prefix)
    }

    /// 带 prefixPath 的鉴权接口 URL（`/v2/plugin/...`）
    pub fn auth_url(&self, path: &str) -> String {
        format!("{}/v2{}{}", self.base_url, self.prefix, path)
    }

    /// 端点 authority（`host`），解析失败时为空串。
    /// 对应 native `Context::authority`：`auth.domain` 缺省时用它兜底 X-Domain。
    pub fn authority(&self) -> String {
        crate::util::authority_of(&self.base_url)
    }
}
