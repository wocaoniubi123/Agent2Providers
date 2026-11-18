//! Qoder 中国版的**站点常量**（native `endpoints.rs` 的单站点裁剪版）。
//!
//! ── 为什么只留一个站点 ──────────────────────────────────────
//! native 那一份按 `Site` 参数化，同时服务 `qoder` / `qoder-intl` /
//! `qwenwork` / `qwenwork-intl` 四家。本包只申报 `qoder` 一个 provider id
//! （网关 `plugin_host` 硬性要求 wasm 包的 `providers.len() == 1`），所以这里
//! 把 Qoder 中国版那一列常量钉死，函数签名里不再出现站点参数。
//!
//! ── 常量各自的依据（照抄 native，改动前先复核）──────────────────
//!   - 推理网关 `gateway.qoder.com.cn/`：`/algo/...` 这一族的根，**含尾斜杠**；
//!   - 账号接口 `openapi.qoder.com.cn`：设备授权轮询、续期、用户资料、额度、
//!     活动（`sash` 一族）；
//!   - 门户 `qoder.com.cn`：人看的授权页主机；
//!   - `cosyVersion 1.1.38` / `Cosy-ClientType 5` / `Data-Policy disagree`：
//!     Qoder 既有实现的取值（国际版同值），**不能**照抄千问办公的 1.1.52 / 6
//!     （那一族要求 `session_type` 与 `Cosy-ClientType` 自洽，混用会被直接拒）；
//!   - `session_type qodercli` / `business.product cli` / `version 1.0.0`：
//!     必须与上面那组头一致，见 `protocol::build_upstream_body`。

use agent2api_wasm_sdk::Value;

/// provider id（落盘契约：存量账号的 provider 就是它）
pub const PROVIDER_ID: &str = "qoder";
/// 产品名（日志与文案前缀）
pub const PRODUCT: &str = "Qoder";
/// 版本名（已发布的叫法）
pub const LABEL: &str = "中国版";

/// 展示名（`Qoder 中国版`）
pub fn display_name() -> &'static str {
    "Qoder 中国版"
}

/// 网页门户基址（授权页所在的那台主机）
pub const WEB_ORIGIN: &str = "https://qoder.com.cn";
/// 账号接口基址
pub const OPEN_API: &str = "https://openapi.qoder.com.cn";
/// 推理 / 模型目录基址（**含尾斜杠**）
///
/// 对话链路直接用这一台：native 里只有 Qoder **国际版**按令牌前缀分流
/// （作业令牌 `jt-` 打 `api2.qoder.sh`），中国版本就是一台网关。
pub const GATEWAY: &str = "https://gateway.qoder.com.cn/";

/// COSY 协议版本（`Cosy-Version` / payload 里的 `cosyVersion`）
pub const COSY_VERSION: &str = "1.1.38";
/// `Cosy-ClientType`（IDE 形态）
pub const COSY_CLIENT_TYPE: &str = "5";
/// `Cosy-Data-Policy`
pub const COSY_DATA_POLICY: &str = "disagree";
/// 请求体 `session_type`（**必须与 `COSY_CLIENT_TYPE` 自洽**）
pub const SESSION_TYPE: &str = "qodercli";
/// 请求体 `business.product`
pub const BUSINESS_PRODUCT: &str = "cli";
/// 请求体 `business.version`
pub const BUSINESS_VERSION: &str = "1.0.0";

/// 设备授权页路径（`nonce` 必须是标准 UUID，去横线会被判成非法参数）
pub const DEVICE_LOGIN_PATH: &str = "/device/selectAccounts";
/// 设备授权轮询端点
pub const DEVICE_POLL_PATH: &str = "/api/v1/deviceToken/poll";
/// PAT → 作业令牌交换
pub const EXCHANGE_PATH: &str = "/api/v1/jobToken/exchange";
/// 用户资料
pub const USER_INFO_PATH: &str = "/api/v1/userinfo";
/// 额度
pub const USAGE_PATH: &str = "/api/v2/quota/usage";
/// 套餐查询（返回 `plan_tier_name`）
pub const PLAN_PATH: &str = "/api/v2/user/plan";

/// 活动/签到接口前缀。
///
/// **与 openapi 同主机、但鉴权口径完全不同**：只要一个 `Bearer <dt->` 加
/// `cosy-clienttype: 10`，**不打 COSY 签名**（见 [`sash_headers`]）。
pub const CAMPAIGNS_PATH: &str = "/sash/api/v1/me/campaigns";
/// 活动列表查询串（`forceRefresh=true` 让上游跳过缓存给实时的 `claimStatus`）
pub const CAMPAIGNS_QUERY: &str = "?forceRefresh=true";

/// `cosy-clienttype` 的值：桌面端（QoderWork）形态。
///
/// **这个头在门控返回内容，不是可有可无的装饰**：实测同一个账号用
/// `Cosy-ClientType: 5`（IDE 形态）打活动接口，上游返回 `showCampaign:false`
/// + 空活动列表；换成 `10` 才给出完整活动包（含可领取的签到活动）。
pub const SASH_CLIENT_TYPE: &str = "10";
/// 活动接口的 `user-agent`（抓包确认的客户端标识）
pub const SASH_USER_AGENT: &str = "Qoder";

/// 设备流凭据（`dt-` / `drt-`）的续期端点，挂在 [`OPEN_API`] 上。
///
/// ── 为什么不是 `{center}/algo/api/v3/user/refresh_token` ──────────
/// 那条「认证中心」端点是给 PAT 换来的作业令牌（`jt-` / `jrt-`）用的，且要求
/// `appcode: cosy` + `Date` + `signature = md5("cosy&<secret>&<date>")` 这套签名头。
/// 我们的设备流凭据走那条路会连签名都没有，被 WAF 直接丢弃（实测两个地区都
/// 稳定返回 `403 {"errorMessage":"Request discarded"}`）。设备流凭据的续期在
/// **openapi 主机**上、且**不需要任何签名**。
pub const DEVICE_REFRESH_PATH: &str = "/api/v1/deviceToken/refresh";
/// 作业令牌（`jrt-`）的续期端点（同一台主机、同样不要签名，只有路径不同）。
///
/// 两者**不可互换**：把 `drt-` 交给作业端点、或把 `jrt-` 交给设备端点，
/// 上游都按「令牌无效」拒绝。
pub const JOB_REFRESH_PATH: &str = "/api/v1/jobToken/refresh";

/// 设备授权页的完整地址
pub fn device_login_url() -> String {
    format!("{WEB_ORIGIN}{DEVICE_LOGIN_PATH}")
}

/// 授权页允许的域名（网关据此拦截把用户引去别处的登录地址）
pub fn allowed_login_hosts() -> Vec<String> {
    vec![
        "qoder.sh".to_string(),
        "qoder.com".to_string(),
        "qoder.com.cn".to_string(),
    ]
}

/// 账号类请求的头（`Authorization` 之外的那几个）。
///
/// Qoder 的历史实现一直这么跑：`Cosy-Version 1.0.1` + `Cosy-ClientType 5` +
/// 自己的 UA。这套头与 COSY 签名无关（账号接口不做签名），只用于标识客户端。
pub fn open_api_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Cosy-Version".to_string(), "1.0.1".to_string()),
        ("Cosy-ClientType".to_string(), COSY_CLIENT_TYPE.to_string()),
        ("User-Agent".to_string(), "qoder-local-proxy".to_string()),
    ];
    if let Some(token) = token {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    headers
}

/// 续期请求的头：**不带任何签名，也不带 Authorization**。
///
/// 鉴权凭据在请求体里（`{"refresh_token": "…"}`），带旧令牌没有意义。
pub fn refresh_headers() -> Vec<(String, String)> {
    vec![("User-Agent".to_string(), "qoder-local-proxy".to_string())]
}

/// 活动/签到接口的请求头：**最小束、无签名**（小写头名照抄抓包结果）。
pub fn sash_headers(token: &str) -> Vec<(String, String)> {
    vec![
        ("authorization".to_string(), format!("Bearer {token}")),
        ("cosy-clienttype".to_string(), SASH_CLIENT_TYPE.to_string()),
        ("accept".to_string(), "application/json".to_string()),
        ("accept-language".to_string(), "zh-CN".to_string()),
        ("user-agent".to_string(), SASH_USER_AGENT.to_string()),
    ]
}

/// 头列表 → `http::open*` 要的 JSON 对象形态。
pub fn headers_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in headers {
        object.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// 拼一个账号接口 URL（不带查询串）
pub fn open_api_url(path: &str) -> String {
    format!("{OPEN_API}{path}")
}

/// 拼一个推理 / 目录 URL（`GATEWAY` 自带尾斜杠）
pub fn gateway_url(path: &str) -> String {
    format!("{GATEWAY}{path}")
}

/// 平台标识（COSY 头的 `machineOs`，`{arch}_{platform}` 形态）。
///
/// native 读的是编译期的 `cfg!`；wasm 插件编译目标恒为 `wasm32`，真正的宿主
/// 平台由宿主决定 —— 这里按「Windows 上的 x86_64 客户端」取值，与 native 在
/// 本项目的实际部署形态一致。这是**已知的近似**（跨平台部署时这个头会不准，
/// 上游并不据此做鉴权，只用于客户端指纹画像）。
pub fn machine_os() -> &'static str {
    "x86_64_windows"
}

/// 一个 JSON 字面量的文本形态（拼接 COSY payload 用）
pub fn json_text(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

