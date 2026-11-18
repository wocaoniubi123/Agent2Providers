//! 本包只服务**国内版**（`zcode`），因此 native `region.rs` 的
//! `Region` 枚举在这里收成一个常量集合。
//!
//! ── 为什么仍然单独一个文件 ──────────────────────────────────
//! native 的注释里逐条记着「哪两地相同、哪两地不同」，那些事实是迁移时最
//! 容易搞错的一处（`zcode` 平面两地相同、推理平面与业务域两地不同）。本包只
//! 做国内版之后，把这些事实固化成注释 + 常量；国际版那个包（`wasm/zcode-intl`）
//! 对照的正是同一份事实的另一半。
//!
//! ── 国内版的实际地址（逐条对照 native `Region::Cn`）────────
//! ```text
//!   zcode 平面（登录 / 领取 / 余额）  https://zcode.z.ai
//!   推理平面（OpenAI 兼容）          https://open.bigmodel.cn/api/coding/paas/v4
//!   监控平面（窗口限额）              https://open.bigmodel.cn
//!   编码套餐业务域（换 API Key）      https://bigmodel.cn
//! ```
//!
//! 三处**不要想当然**的地方（native 都有实测注记）：
//!   · zcode 平面两地**相同**（同一个 `zcode.z.ai`），地区只影响推理平面、
//!     监控平面与业务域 —— 所以本包的 `origins` 里必须有 `zcode.z.ai`；
//!   · 监控平面与推理平面**同域不同路径**（`open.bigmodel.cn`）；
//!   · 业务域是 `bigmodel.cn` 而**不是** `open.bigmodel.cn`（参考实现的
//!     `resolveCodingPlanCredential` 硬编码前者，实测跑通的就是它）。
//!
//! `ZCODE_OPENAI_BASE_URL` / `ZCODE_MONITOR_BASE_URL` /
//! `ZCODE_PLAN_BASE_URL` 这三个环境变量覆盖口子搬到插件后改走
//! `settings.get`（硬约束：不许读 `std::env`）：键名分别是
//! `openaiBaseUrl` / `monitorBaseUrl` / `planBaseUrl`。
//!
//! ★ 覆盖值的**域名必须仍在 `wasm.json` 的 `origins` 白名单里**（当前是
//! `https://zcode.z.ai`、`https://open.bigmodel.cn`、`https://bigmodel.cn`）
//! —— 宿主对每个出站请求做白名单校验，白名单外的地址会在请求那一刻失败
//! （不是编译错误）。因此这三个口子现在只对「同域换路径 / 换前缀」有用；
//! 上游真换域时要同时改本文件的常量和 `wasm.json` 的 `origins` 并重新发版
//! —— 这与 native 时期「改个环境变量就生效」不同，是本架构的硬边界。

use agent2api_wasm_sdk::{self as sdk, Value};

/// 展示名里「ZCode」后面那一段。
pub const LABEL: &str = "国内版";

/// zcode 平面基址（登录 / 领取 / 余额 / 客户端配置；**两地相同**）。
pub const ZCODE_ORIGIN: &str = "https://zcode.z.ai";

/// 推理平面：OpenAI 兼容基址（**不含**尾斜杠）。
const OPENAI_BASE_URL: &str = "https://open.bigmodel.cn/api/coding/paas/v4";

/// 监控平面基址（`/api/monitor/usage/quota/limit` 挂在它下面）。
///
/// 国内版与推理平面**同域**（只有路径不同），国际版才是独立的 `api.z.ai`。
const MONITOR_BASE_URL: &str = "https://open.bigmodel.cn";

/// 编码套餐业务域（`/api/biz/*` 挂在它下面）。
///
/// ── 国内版为什么是 `bigmodel.cn` 而不是 `open.bigmodel.cn` ──
/// 参考实现里这两个域是分开的：它的 `ProviderDef.bizHost` 是
/// `open.bigmodel.cn`（给另一处「API Key 解析」用），而真正跑登录换取的
/// `resolveCodingPlanCredential` **硬编码**了 `https://bigmodel.cn`。本常量
/// 服务的正是后者那条链（native `Region::Cn::biz_host` 同值）。
///
/// 国内版**没有** `/api/auth/z/login` 那一步（国际版才有，用于换 biz 令牌），
/// 所以这个域下只剩两个接口：`customer/getCustomerInfo` 与 `api_keys`。
pub const BIZ_HOST: &str = "https://bigmodel.cn";

/// OAuth 链路里的 `provider` 取值（上游命名空间，**不是**我们的 provider id）。
///
/// 它同时是 `/oauth/cli/init` 请求体里的 `provider` 与 `/oauth/cli/poll`
/// 响应里那个分支键（`data.bigmodel.access_token`）。国内版是 `bigmodel`，
/// 国际版是 `zai` —— 这两个命名空间不能混（混了的表现是登录轮询永远拿不到
/// 访问令牌，报「缺少 zai.access_token」）。
pub const UPSTREAM_PROVIDER: &str = "bigmodel";

/// 账号记录 id 的前缀（native `Region::Cn::account_id_prefix`）。
///
/// 带前缀让两地的记录天然不相交：同一个人在国内 / 国际两套系统里的 userId
/// 可能相同，撞 id 会让存储层的保护拒绝写入。
pub const ACCOUNT_ID_PREFIX: &str = "zcode-user-";

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
/// ── 国内版正好与 native 同口径 ──────────────────────────────
/// native 用固定的 `zcode` 作为设置所有者（国内 / 国际共用同一个版本号，门槛
/// 不分地区）。本包的 provider id 就是 `zcode`，`settings_schema.storage_provider`
/// 也是 `zcode`，`settings.get` 读到的正是 native 那一份同名设置 —— 这一点比
/// 国际版包更贴近 native（国际版包只能读自己那份 `zcode-intl` 设置）。
pub fn app_version_setting() -> String {
    setting("appVersion").unwrap_or_default()
}
