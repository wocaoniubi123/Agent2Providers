//! 本包只服务**国际版**（`zcode-intl`），因此 native `region.rs` 的
//! `Region` 枚举在这里收成一个常量集合。
//!
//! ── 为什么仍然单独一个文件 ──────────────────────────────────
//! native 的注释里逐条记着「哪两地相同、哪两地不同」，那些事实是迁移时最
//! 容易搞错的一处（`zcode` 平面两地相同、推理平面两地不同）。插件只做国际版
//! 之后，把这些事实固化成注释 + 常量，将来国内版那个包要对照的正是这份文件。
//!
//! ── 国际版的实际地址（逐条对照 native `Region::Intl`）──────
//! ```text
//!   zcode 平面（登录 / 领取 / 余额）  https://zcode.z.ai
//!   推理平面（OpenAI 兼容）          https://api.z.ai/api/coding/paas/v4
//!   监控平面（窗口限额）              https://api.z.ai
//!   编码套餐业务域（换 API Key）      https://api.z.ai
//! ```
//!
//! `ZCODE_INTL_OPENAI_BASE_URL` / `ZCODE_INTL_MONITOR_BASE_URL` /
//! `ZCODE_INTL_PLAN_BASE_URL` 这三个环境变量覆盖口子搬到插件后改走
//! `settings.get`（硬约束：不许读 `std::env`）：键名分别是
//! `openaiBaseUrl` / `monitorBaseUrl` / `planBaseUrl`。
//!
//! ★ 覆盖值的**域名必须仍在 `wasm.json` 的 `origins` 白名单里**（当前只有
//! `https://api.z.ai` 与 `https://zcode.z.ai`）—— 宿主对每个出站请求做白名单
//! 校验，白名单外的地址会在请求那一刻失败（不是编译错误）。因此这三个口子
//! 现在只对「同域换路径 / 换前缀」有用；上游真换域时要同时改本文件的常量和
//! `wasm.json` 的 `origins` 并重新发版 —— 这与 native 时期「改个环境变量就
//! 生效」不同，是本架构的硬边界。

use agent2api_wasm_sdk::{self as sdk, Value};

/// 展示名里「ZCode」后面那一段。
pub const LABEL: &str = "国际版";

/// zcode 平面基址（登录 / 领取 / 余额 / 客户端配置；**两地相同**）。
pub const ZCODE_ORIGIN: &str = "https://zcode.z.ai";

/// 推理平面：OpenAI 兼容基址（**不含**尾斜杠）。
const OPENAI_BASE_URL: &str = "https://api.z.ai/api/coding/paas/v4";

/// 监控平面基址（`/api/monitor/usage/quota/limit` 挂在它下面）。
const MONITOR_BASE_URL: &str = "https://api.z.ai";

/// 编码套餐业务域（`/api/auth/z/login` 与 `/api/biz/*` 挂在它下面）。
pub const BIZ_HOST: &str = "https://api.z.ai";

/// OAuth 链路里的 `provider` 取值（上游命名空间，**不是**我们的 provider id）。
///
/// 它同时是 `/oauth/cli/init` 请求体里的 `provider` 与 `/oauth/cli/poll`
/// 响应里那个分支键（`data.zai.access_token`）。国际版是 `zai`，国内版是
/// `bigmodel` —— 这两个命名空间不能混。
pub const UPSTREAM_PROVIDER: &str = "zai";

/// 账号记录 id 的前缀（native `Region::account_id_prefix`）。
///
/// 带前缀让两地的记录天然不相交：同一个人在国内 / 国际两套系统里的 userId
/// 可能相同，撞 id 会让存储层的保护拒绝写入。
pub const ACCOUNT_ID_PREFIX: &str = "zcode-intl-user-";

/// 读一个设置项（空值 / 类型不对 / 宿主拒绝一律视为「没设置」）。
///
/// `settings.get` 可能直接回字符串，也可能回 `{value: "…"}`（宿主版本差异），
/// 这里两种都收敛成字符串。
fn setting(key: &str) -> Option<String> {
    let value = sdk::settings::get(key).ok()?;
    let text = match value {
        Value::String(text) => text,
        Value::Object(object) => object
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default(),
        _ => String::new(),
    };
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// 带尾斜杠清理的覆盖值。
fn override_base(key: &str, fallback: &str) -> String {
    setting(key)
        .map(|value| value.trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// 推理基址（`settings.get("openaiBaseUrl")` 可覆盖）。
pub fn openai_base_url() -> String {
    override_base("openaiBaseUrl", OPENAI_BASE_URL)
}

/// 监控平面基址（`settings.get("monitorBaseUrl")` 可覆盖）。
pub fn monitor_base_url() -> String {
    override_base("monitorBaseUrl", MONITOR_BASE_URL)
}

/// 套餐池（Start Plan）通道的基址前缀（`settings.get("planBaseUrl")` 可覆盖）。
///
/// native `plan::plan_base_url`：`{zcode_origin}/api/v1/zcode-plan`，
/// 消息端点再拼 `/anthropic/v1/messages`。
pub fn plan_base_url() -> String {
    override_base("planBaseUrl", &format!("{ZCODE_ORIGIN}/api/v1/zcode-plan"))
}

/// 设置页的「客户端版本号」（`appVersion`）。
///
/// ── 为什么固定读本 provider 的键 ────────────────────────────
/// native 用固定的 `zcode` 作为设置所有者，让国内版与国际版**共用**同一个版本号
/// （门槛不分地区）。Wasm 插件的 `settings.get` 天然只读本 provider 的键，
/// 所以这里就是 `zcode-intl` 自己那一份 —— 同一台机器上装了两个包时，两个版本
/// 号各改各的。这是与 native 的一处已知差异（不影响协议，只影响「改一次两地
/// 生效」这个便利）。
pub fn app_version_setting() -> String {
    setting("appVersion").unwrap_or_default()
}
