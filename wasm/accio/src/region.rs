//! Accio 的**地区**与端点常量：两个地区共用一套业务网关，只有登录站点不同。
//!
//! ── 上游长什么样（依据：Accio Work 桌面端安装包的 app.asar）──────
//! ```text
//!   业务网关（国际 / 国内同一个）  https://phoenix-gw.alibaba.com
//!     /api/oauth/token                 授权码 → accessToken / refreshToken
//!     /api/auth/refresh_token          续期（body 带 accessToken + refreshToken）
//!     /api/auth/userinfo               用户资料（GET，accessToken 走 query）
//!     /api/entitlement/quota           额度用量百分比 + 重置倒计时
//!     /api/entitlement/currentSubscription  订阅详情
//!     /api/llm/config                  模型目录（POST，body {token}）—— 本网关用它
//!     /api/llm/config/v2               模型目录的精简版（旧路径，回落用）
//!   推理网关（ADK）                https://phoenix-gw.alibaba.com/api/adk/llm
//!     POST /generateContent?sg_k=<md5(requestId)>   SSE，Gemini 风格信封
//!   登录站点
//!     国际版  https://www.accio.com      （域名 accio.com → 区域 GLOBAL）
//!     国内版  https://www.accio-ai.com   （域名 accio-ai.com → 区域 CN）
//! ```
//!
//! 三个事实决定了本模块的形状（都是实测/读码得到的，不是推测）：
//!   1. **网关是同一个** —— 两个地区的账号打的是同一个 host，差别只在
//!      `x-package-region`（`GLOBAL` / `CN`）与登录站点。因此「这一家的域名」
//!      不能散落在各处，必须由 [`Region`] 给。
//!   2. **`client_id` 两地逐字相同**（`accio-work`）：桌面端两个构建共用它。
//!   3. **token 不走 Authorization 头**：业务接口的 GET 把 `accessToken` 拼进
//!      query、POST 放进 JSON body；推理接口把 `token` 放进 body。这一点与
//!      其它家都不同，见 `upstream.rs` 与 `chat.rs`。
//!
//! ── 为什么地区是一等公民而不是「一家上的一个字段」────────────────
//! 与 native 的 `autoclaw::region` 同一条思路：地区做成账号上的字段，界面与
//! 选路就分不清「哪条账号走哪个站点」。两个地区 = 两家 provider
//! （`accio` / `accio-cn`），各自一个 wasm 包；包内用 [`REGION`] 固定身份。
//!
//! ── 与 native 的差别：环境变量 → 用户设置 ─────────────────────
//! native 用 `ACCIO_GATEWAY_BASE` / `ACCIO_APP_KEY` / `ACCIO_APP_VERSION`
//! 覆盖预发与版本号；wasm 沙箱**没有环境变量**，同样的覆盖改读
//! `sdk::settings::get`（原始值仍是那几个键的驼峰形态）。读不到就用本文件的
//! 常量 —— 行为与 native 的「没设环境变量」完全一致。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, Value};

/// 业务网关基址（两个地区共用；`gatewayBase` 设置可覆盖，预发/自建代理用）
pub const DEFAULT_GATEWAY_BASE: &str = "https://phoenix-gw.alibaba.com";

/// 推理网关路径前缀（拼在网关基址之后）
pub const ADK_LLM_PATH: &str = "/api/adk/llm";

/// OAuth 授权码换令牌
pub const OAUTH_TOKEN_PATH: &str = "/api/oauth/token";
/// 刷新令牌（多账号场景桌面端用 `/api/auth/safe/refresh_token`，本网关用普通那条）
pub const REFRESH_TOKEN_PATH: &str = "/api/auth/refresh_token";
/// 用户资料
pub const USER_INFO_PATH: &str = "/api/auth/userinfo";
/// 额度用量
pub const QUOTA_PATH: &str = "/api/entitlement/quota";
/// 订阅详情
pub const SUBSCRIPTION_PATH: &str = "/api/entitlement/currentSubscription";
/// 模型目录（完整版）。
///
/// ── 为什么是 v1 而不是 v2（2026-09 实测）───────────────────
/// 两条路径都返回同一个信封（`data` 是 provider 数组），差别在**清单本身**：
/// 用国际版账号实测，v1 给 9 家 provider / 69 个模型 / 41 个可见，
/// v2 只给 6 家 / 46 个 / 26 个 —— v2 **少了 deepseek、moonshot、zhipu 三家**
/// （DeepSeek / Kimi / GLM 全都看不到）。此外 v1 每条模型多出 `protocol`
/// 与 `group` 两个字段，前者正是思考档位落点要用的（见 `models.rs`）。
/// 因此目录刷新打 v1，`MODEL_CONFIG_PATH_V2` 只作为回落。
pub const MODEL_CONFIG_PATH: &str = "/api/llm/config";
/// 模型目录的精简版（旧路径）。只在 v1 意外失败时回落一次，见 `models::refresh`
pub const MODEL_CONFIG_PATH_V2: &str = "/api/llm/config/v2";

/// OAuth 客户端 id（桌面端常量；两地逐字相同）
pub const CLIENT_ID: &str = "accio-work";

/// ADK 推理请求的租户（桌面端默认值 `ADK_TENANT || "accio-agent"`）
pub const DEFAULT_TENANT: &str = "accio-agent";
/// ADK 推理请求的来源标记（桌面端默认值 `ADK_IAI_TAG || "phoenix-desktop"`）
pub const DEFAULT_IAI_TAG: &str = "phoenix-desktop";
/// 推理请求头里的客户端版本（桌面端取 appVersion）。
///
/// 2026-10 对齐当时官方客户端的 `0.34.4`；版本太旧将来可能被上游当成不支持 ——
/// 可用 `appVersion` 设置覆盖，见 [`app_version`]。
pub const DEFAULT_APP_VERSION: &str = "0.34.4";

/// 推理请求的 User-Agent。
///
/// 上游**不要求**这个头（参考实现根本不发 UA，照样通），但 2026-09 用通用的
/// `undici` 标识时见过 HTTP 200 的 HTML 挑战页；换成独立标识后没再复现。
/// 真正决定吃不吃拦截页的是 `utdid`（见 `credential` 模块头），这里保留一个
/// 独立 UA 只是多一层区分度 —— 别因为「上游不校验」就删掉它。
pub const ADAPTER_USER_AGENT: &str = "agent2api-accio/3.3.0";

/// 推理请求头 `appKey`（**必填**，见下）。
///
/// ── 为什么它必须有（2026-09 实测）────────────────────────────
/// 不带这个头打 `generateContent`，上游**不报错**，而是回一段普通文本
/// ：「Your app version is no longer supported. Please update…」——
/// HTTP 200、`data:` 帧，形态与正常回答完全一样，会被当成模型输出吐给下游。
/// 带上任意**非空**取值即恢复（实测 `35298846` / `12345678` / 任意字符串
/// 都通，空串等同于没带）—— 上游只校验「有没有」，不校验取值。
///
/// 默认值取官方客户端的那一枚 `OneChat`。`appKey` 设置可覆盖。
pub const DEFAULT_APP_KEY: &str = "OneChat";

/// 业务请求的默认语言（桌面端按界面语言给 `zh` / `en`；网关侧固定 en ——
/// 额度与目录的文案不参与界面展示，语言只影响上游返回的消息文本）
pub const ACCEPT_LANGUAGE: &str = "en";

/// Accio 的两个地区。**两个地区 = 两个 provider**（见模块头）。
///
/// 每个包只构造其中一个（[`REGION`]），另一个变体留在源码里让孪生包共用同一份
/// 实现 —— 所以这条 `allow` 是两份源码共用的记号，不是「没人用的死代码」。
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Region {
    /// 国际版（`www.accio.com`，`x-package-region: GLOBAL`）
    Global,
    /// 国内版（`www.accio-ai.com`，`x-package-region: CN`）
    Cn,
}

/// 本包固定代表哪一个地区。
///
/// ── 为什么是「常量」而不是「运行时判定」─────────────────────
/// 一个 wasm 包只申报一个 provider id（网关 `provenance.rs` 的硬约束），
/// 所以地区在编译期就定了：`wasm/accio` 是国际版、`wasm/accio-cn` 是国内版。
/// 两个包的 `src/` 逐字相同，只有下面这一行不同 —— 复制的包改这一行即可。
pub const REGION: Region = Region::Global;

#[allow(dead_code)]
impl Region {
    /// 本地区的 provider id（`"accio"` / `"accio-cn"`）
    pub const fn provider_id(self) -> &'static str {
        match self {
            Self::Global => "accio",
            Self::Cn => "accio-cn",
        }
    }

    /// 落进账号记录的 `edition` 值（与其它家同一套取值：`intl` / `cn`）
    pub const fn edition(self) -> &'static str {
        match self {
            Self::Global => "intl",
            Self::Cn => "cn",
        }
    }

    /// 界面与日志里的名字
    pub const fn label(self) -> &'static str {
        match self {
            Self::Global => "国际版",
            Self::Cn => "国内版",
        }
    }

    /// 登录站点（OAuth 授权页所在域；`loginBase` 设置可覆盖，预发用）。
    ///
    /// ── 两个包唯一的域名差异就在这一行 ────────────────────────
    /// 国际版 `https://www.accio.com`、国内版 `https://www.accio-ai.com`。
    /// `wasm.json` 的 `origins` 按包各列自己那一个（精确匹配，父域不覆盖子域）。
    pub const fn login_base(self) -> &'static str {
        match self {
            Self::Global => "https://www.accio.com",
            Self::Cn => "https://www.accio-ai.com",
        }
    }

    /// 模型目录与推理请求的 `x-package-region` 头。
    ///
    /// 取值来自桌面端：区域名单就是 `["CN", "GLOBAL"]` 两项。
    pub const fn package_region(self) -> &'static str {
        match self {
            Self::Global => "GLOBAL",
            Self::Cn => "CN",
        }
    }
}

/// 读一个字符串设置（空串 / 非字符串按「没设」处理）。
///
/// 「没设」与 native 的「环境变量为空」同一口径：一律回落常量。
fn setting_text(key: &str) -> Option<String> {
    sdk::settings::get(key)
        .ok()
        .and_then(|value: Value| value.as_str().map(str::to_string))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 业务网关基址（末尾不带斜杠）
pub fn gateway_base() -> String {
    setting_text("gatewayBase")
        .unwrap_or_else(|| DEFAULT_GATEWAY_BASE.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// 推理网关基址（`{gw}/api/adk/llm`）
pub fn llm_base() -> String {
    format!("{}{}", gateway_base(), ADK_LLM_PATH)
}

/// `appKey` 请求头的取值（**只用于推理接口**：业务接口实测带不带都一样，
/// 多带只会扩大请求面）。
pub fn app_key() -> String {
    setting_text("appKey").unwrap_or_else(|| DEFAULT_APP_KEY.to_string())
}

/// 客户端版本号的取值。
///
/// `x-app-version` 与 `version` **两个头共用这一份**：一个被设置改掉、另一个
/// 还留在默认值，会让同一请求的版本号自相矛盾 —— 比「版本旧」更像异常。
pub fn app_version() -> String {
    setting_text("appVersion").unwrap_or_else(|| DEFAULT_APP_VERSION.to_string())
}

/// 登录站点（`loginBase` 设置可覆盖）。
pub fn login_base() -> String {
    setting_text("loginBase")
        .map(|value| value.trim_end_matches('/').to_string())
        .unwrap_or_else(|| REGION.login_base().to_string())
}

/// 业务接口的通用请求头（桌面端在拦截器里统一加的那一组里我们认得全的部分）。
///
/// ── 为什么只带这几项 ────────────────────────────────────────
/// 桌面端还带 `x-source` / `x-deploy-target` / `x-cna` / `bx-ua` 等，
/// 其中 `bx-ua` 由它内置的风控 SDK 生成（本插件没有那个 SDK，值也不可复现），
/// `x-cna` 是设备指纹、`x-deploy-target` 是部署形态标记 —— 都不是鉴权项。
/// **刻意不带 `Authorization`**：桌面端一个请求都不带它，鉴权全靠 body/query
/// 里的 `accessToken`；多一个上游没见过的头只会扩大请求面。
pub fn api_headers(region: Region) -> Value {
    serde_json::json!({
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": ACCEPT_LANGUAGE,
        "x-language": ACCEPT_LANGUAGE,
        "x-platform": "desktop",
        // wasm 侧没有 `std::env::consts::OS` 的可靠答案（宿主可能是任何平台），
        // 官方客户端在 Windows 上就是 `windows`，取它最接近真实客户端
        "x-os": "windows",
        "x-app-version": app_version(),
        "x-package-region": region.package_region(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个地区的域名与身份必须成对且各不相同 —— 孪生包复制时最容易漏改这里，
    /// 而漏改的症状是运行期「插件请求地址未获网络授权」（`origins` 精确匹配）。
    #[test]
    fn regions_are_distinct() {
        assert_ne!(Region::Global.login_base(), Region::Cn.login_base());
        assert_ne!(Region::Global.provider_id(), Region::Cn.provider_id());
        assert_ne!(Region::Global.package_region(), Region::Cn.package_region());
        assert_eq!("intl", Region::Global.edition());
        assert_eq!("cn", Region::Cn.edition());
    }
}
