//! AutoClaw 的**地区**（国内版 / 国际版）：两套域名与两条 provider 身份。
//!
//! ── 为什么地区要成为一等公民 ────────────────────────────────
//! AutoClaw 是同一套客户端代码的两个**构建**（`isOversea` 编译期常量：
//! 国内 `false` / 国际 `true`），它们共用同一套账号体系接口与同一套
//! `X-Auth-Sign` 客户端指纹（appId/appKey 两地逐字相同，实测确认），
//! 但**站点不同**：
//!
//! ```text
//!            userapi（账号 / 积分 / 签到）                       LLM 代理
//!   国内  https://autoglm-acceleration-api.zhipuai.cn  .../autoclaw-proxy/proxy/autoclaw
//!   国际  https://autoglm-api.autoglm.ai               .../autoclaw-proxy/proxy/autoclaw
//! ```
//!
//! 因此「这一家的域名」不能是模块级常量 —— 本文件是**地区 → 域名 / 身份**的
//! 唯一事实来源，别处不要再写 `"https://autoglm-api.autoglm.ai"` 这类字面量。
//!
//! ── 为什么是两个 provider 而不是「一家的一个选项」────────────────
//! 与 native 同一条思路：地区做成「一家上的一个字段」后，地区成了**账号的
//! 属性**，界面上混在一起，「哪个账号走哪个站点」在列表里看不出来；更要紧的是
//! 账号库里的记录无法按地区隔离，用户给两个地区各加一个账号时，界面与选路都会
//! 把它们当成同一家的两条记录。
//!
//! 现在按**两个 provider** 建模（`autoclaw` 国内版 / `autoclaw-intl` 国际版）：
//! 各自有独立的账号、清单、启停与映射，界面上各占一个分组。
//!
//! ── 国内版的 provider id 为什么**不改名** ────────────────────
//! 注册表里 `autoclaw` 这个 id 已经在用户的 accounts.json 里了（`provider`
//! 字段是落盘契约）。把它改成 `autoclaw-cn` 会让全部存量账号在升级后变成
//! 「未知 provider」，账号从列表里静默消失。所以**只改展示名**，id 保持
//! `autoclaw`；新增的国际版取 `autoclaw-intl`。
//!
//! ── 与 native 的差别：环境变量 → 用户设置 ─────────────────────
//! native 用 `AUTOCLAW_UPSTREAM_BASE_URL` / `AUTOCLAW_DEFAULT_ROUTE` 等覆盖；
//! wasm 沙箱**没有环境变量**，同样的覆盖改读 `sdk::settings::get`
//! （`upstreamBase` / `userapiBase` / `defaultRoute`）。读不到就用常量 ——
//! 与 native「没设环境变量」完全一致。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{settings, Value};

/// 两个地区的 provider id（字符串常量；插件侧不依赖网关的 `ProviderKind` 枚举）。
pub const PROVIDER_ID_CN: &str = "autoclaw";
/// 国际版的 provider id。
pub const PROVIDER_ID_INTL: &str = "autoclaw-intl";

/// 客户端版本号（源实现 `createUpstreamClient` 的 `desktopAppVersion` 默认值；
/// `server.mjs` 从不覆盖它，所以这里是常量而不是配置项）。
///
/// 它进 `X-Version` 头：上游按它识别 AutoClaw 客户端版本，改动会让上游按不同
/// 的兼容路径解释请求。
pub const DESKTOP_APP_VERSION: &str = "1.17.8";

/// userapi 请求头上的客户端版本（**另一份**，别与转发头混用）。
///
/// ── 为什么必须带这个头（2026-09-22 实测）─────────────────────
/// 服务端按 `X-Version` 对 `autoclaw-model-config` 做**版本门控**：同一个账号、
/// 同一个 URL，不带这个头时国际版只下发 4 条（缺 `tdpsk_deepseek-v4-flash-202605`
/// 与 `zai_glm-5.3-flash`）、国内版只下发 3 条（缺 `zai_glm-5.3-flash`）；补上
/// `X-Version: 1.18.5` 后两地都下发全量目录。客户端在**所有** userapi 请求上
/// 都发它，所以这里跟着签名头一起发，而不是只给目录请求加。
pub const USERAPI_CLIENT_VERSION: &str = "1.18.5";

/// 上游语言 / 通道（源实现的 `lang` / `channel` 默认值，`server.mjs` 同样不覆盖）
pub const CLIENT_LANG: &str = "zh-CN";
pub const CLIENT_CHANNEL: &str = "official";

/// AutoClaw 的地区。
///
/// 顺序 = 注册表顺序（国内版在前）：`ALL` 的遍历顺序决定模型目录合并时同名模型
/// 先归谁家。**国内版在前**是因为它是历史已有的一家（存量账号都归它）。
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Region {
    /// 国内版（智谱加速域；历史已有的那一家，provider id 仍是 `autoclaw`）
    #[default]
    Cn,
    /// 国际版（autoglm.ai；provider id 是 `autoclaw-intl`）
    Intl,
}

/// 本包固定代表哪一个地区（`wasm/autoclaw` = 国内版，`wasm/autoclaw-intl` = 国际版）。
///
/// 一个 wasm 包只申报一个 provider id（网关 `provenance.rs` 的硬约束），所以
/// 地区在编译期就定了。两个包的 `src/` 逐字相同，只有下面这一行不同。
///
/// 本包是**国际版**：`https://autoglm-api.autoglm.ai`，provider id
/// `autoclaw-intl`，登录方式是 Zai / Google OAuth（没有手机验证码）。
pub const REGION: Region = Region::Intl;

#[allow(dead_code)]
impl Region {
    /// 两个地区（注册表顺序：国内版在前）
    pub const ALL: [Region; 2] = [Region::Cn, Region::Intl];

    /// 本地区的 provider id（`"autoclaw"` / `"autoclaw-intl"`）。
    ///
    /// 插件侧没有 `ProviderKind` 枚举（那是网关编译期的概念），所以这里是
    /// 字符串常量的唯一映射点 —— id 是落盘契约，两边必须相同。
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::Cn => PROVIDER_ID_CN,
            Self::Intl => PROVIDER_ID_INTL,
        }
    }

    /// provider id → 地区（`autoclaw` 系之外的 id 返回 None）
    pub fn from_provider_id(provider_id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|region| region.provider_id() == provider_id)
    }

    /// 展示名（界面上跟在 `AutoClaw` 后面的那一段）
    pub fn label(self) -> &'static str {
        match self {
            Self::Cn => "国内版",
            Self::Intl => "国际版",
        }
    }

    /// 上游 LLM 代理基址（**含**尾部的 `/autoclaw`）
    pub fn upstream_base_url(self) -> &'static str {
        match self {
            Self::Cn => "https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw",
            Self::Intl => "https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw",
        }
    }

    /// 用户中心（userapi）基址 —— 刷新 / 积分 / 签到 / 登录都在这个域
    pub fn userapi_base_url(self) -> &'static str {
        match self {
            Self::Cn => "https://autoglm-acceleration-api.zhipuai.cn",
            Self::Intl => "https://autoglm-api.autoglm.ai",
        }
    }

    /// 本地区账号记录 id 的**前缀**（id 生成用）。
    ///
    /// ── 为什么国际版要带前缀、国内版不带 ────────────────────────
    /// 账号 id 是 `accounts.json` 的主键，**在整份账号集合里唯一**。
    ///
    /// 国内版必须保持裸 `user-<userId>`：存量账号的 id 就长这样，换前缀会让它们
    /// 在升级后变成「找不到的记录」。
    ///
    /// 国际版**要**带前缀：两地的 userId 空间互不相通，但**同一个人在两地的
    /// userId 完全可能相同**（同一手机号在两套系统里各自注册，而服务端的 id
    /// 生成规则一旦同形就会撞）。带上前缀之后两地的 id 天然不相交。
    pub fn account_id_prefix(self) -> &'static str {
        match self {
            Self::Cn => "user-",
            Self::Intl => "intl-user-",
        }
    }

    /// 本地区有没有网页授权登录。
    ///
    /// 国内版：`oauth-captcha-config` 返回 `enabled:false`，登录页不渲染 OAuth
    /// 按钮 —— 唯一官方入口是手机验证码（`login.rs`）。
    /// 国际版：手机表单被死代码消除，唯一入口是 Zai / Google OAuth（`oauth.rs`）。
    pub fn web_login(self) -> bool {
        matches!(self, Self::Intl)
    }

    /// 本地区要不要申报短信登录（与 [`Self::web_login`] 互补）。
    pub fn sms_login(self) -> bool {
        matches!(self, Self::Cn)
    }
}

/// 读一个字符串设置（空串 / 非字符串按「没设」处理）。
fn setting_text(key: &str) -> Option<String> {
    settings::get(key)
        .ok()
        .and_then(|value: Value| value.as_str().map(str::to_string))
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

/// 上游 LLM 代理基址（`upstreamBase` 设置可覆盖；末尾不带斜杠）
pub fn upstream_base() -> String {
    setting_text("upstreamBase").unwrap_or_else(|| REGION.upstream_base_url().to_string())
}

/// 用户中心基址（`userapiBase` 设置可覆盖）
pub fn userapi_base() -> String {
    setting_text("userapiBase").unwrap_or_else(|| REGION.userapi_base_url().to_string())
}

/// 默认路由覆盖值（`defaultRoute` 设置可覆盖；空值回落到 `zai_auto`）。
pub fn default_route() -> String {
    setting_text("defaultRoute").unwrap_or_else(|| "zai_auto".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个地区的域名必须成对且各不相同 —— 孪生包复制时最容易漏改这里，
    /// 而漏改的症状是运行期「插件请求地址未获网络授权」（`origins` 精确匹配）。
    #[test]
    fn regions_are_distinct() {
        assert_ne!(Region::Cn.upstream_base_url(), Region::Intl.upstream_base_url());
        assert_ne!(Region::Cn.userapi_base_url(), Region::Intl.userapi_base_url());
        assert_ne!(Region::Cn.provider_id(), Region::Intl.provider_id());
        assert_ne!(Region::Cn.account_id_prefix(), Region::Intl.account_id_prefix());
        // 登录方式互补：国内短信、国际网页
        assert!(Region::Cn.sms_login() && !Region::Cn.web_login());
        assert!(Region::Intl.web_login() && !Region::Intl.sms_login());
    }

    /// 两个地区的域名必须都落在本包 `wasm.json` 的 origins 里（对端不在本包内）。
    #[test]
    fn own_origins_only() {
        let own = match REGION {
            Region::Cn => "https://autoglm-acceleration-api.zhipuai.cn",
            Region::Intl => "https://autoglm-api.autoglm.ai",
        };
        assert!(REGION.upstream_base_url().starts_with(own));
        assert!(REGION.userapi_base_url().starts_with(own));
    }
}
