//! 千问办公**国内版**的站点常量（native `endpoints.rs` 的单站点裁剪版）。
//!
//! ── 千问办公和 Qoder 是什么关系（为什么共用一份实现）──────────────
//! **同一套协议栈**：同一个聊天路径
//! （`/algo/api/v2/service/pro/sse/agent_chat_generation`）、同一套
//! `Bearer COSY.<payload>.<sig>` 信封、同一把服务端 RSA 公钥、同一个
//! `client_id`（国内版与 Qoder CN 逐字相同）。差异只有一批**客户端身份常量**
//! 与账号接口路径，所以 `wasm/qwenwork` 是从 `wasm/qoder` 复制后按站点改值，
//! 而不是另写一份。
//!
//! ── 常量各自的依据（native 模块头里的三方实测证据，改动前先复核）────
//!   1. `dumate2api` 的 `src/qwenwork/`（2026-10-14 直连 gateway.qwenwork.cn
//!      签名成功、19 帧正常出流；2026-10-31 复核模型目录）—— 提供
//!      `cosyVersion 1.1.52` / `clientType 6` / `data_policy agree` /
//!      `business qoder_work` / `scene qwork` / `session_type qoder_work` /
//!      `user-agent qoderwork/1.1.0` / 账号上下文与钱包路径；
//!   2. `magpie-plugins` 的 `packages/qoder`（0.2.37，对着 QwenWorkCN.app
//!      1.2.1 写）—— 提供 `client_id` / `redirect_uri` / `walletsPath` /
//!      `modelScene=listAllModels`；
//!   3. 本仓库归档的 Bun 参考（分支 `legacy-bun-reference`，
//!      `runtime/vendor/qoder/qwenwork-*.mjs`）—— 同一份协议的本项目实现，
//!      逐字段与上面两份互相印证。
//!
//! ── 这一组常量必须自洽（混用会被直接拒）────────────────────────
//! `session_type` / `Cosy-ClientType` / `business.version` 是一组：千问办公的
//! 服务端会因为「body 说 qodercli、头说 6」这种自相矛盾**直接拒绝**。所以
//! 本文件把 `COSY_VERSION = 1.1.52` + `COSY_CLIENT_TYPE = 6` +
//! `SESSION_TYPE = qoder_work` + `BUSINESS_VERSION = 1.1.52` 钉在一起，
//! 任何一处都不许照抄 Qoder 的 1.1.38 / 5 / qodercli。
//!
//! ── 账号接口不是 COSY ──────────────────────────────────────
//! `account-context` / `wallets` / 设备轮询都是**普通 REST**，不做签名：上游看到
//! 的客户端身份来自请求头。三份参考实现都只带 `Accept` + 自己的 `User-Agent`
//! （+ `Bearer`），没有一份带 `Cosy-*`，所以 [`open_api_headers`] 走最小束。
//! 带 Qoder 那套头没有依据，还会让「头说 IDE、body 说桌面端」重新出现。
//!
//! ── 签到 / PAT：这家没有 ────────────────────────────────────
//! 它没有 `/api/v1/jobToken/exchange`（没有作业令牌，设备令牌就是对话令牌，
//! 见 [`DEVICE_ONLY`]），也没有 campaign 接口。所以 `metadata.json` 的
//! `capabilities.checkin` / `claims` 是 false，本包不编译 checkin / claims 两个
//! 模块（文件留着只为对照 native，见 `lib.rs` 的说明）。

use agent2api_wasm_sdk::Value;

/// provider id（落盘契约：存量账号的 provider 就是它）
pub const PROVIDER_ID: &str = "qwenwork";
/// 产品名（日志与文案前缀）
pub const PRODUCT: &str = "千问办公";
/// 版本名（本项目「国内版 / 国际版」的既有措辞）
pub const LABEL: &str = "国内版";

/// 展示名（`千问办公 国内版`）
pub fn display_name() -> &'static str {
    "千问办公 国内版"
}

/// 凭证记录里的 `mode` 字段（native `Site::id()`：国内版是 `cn`）。
///
/// **它不是权威**：站点一律以 provider 身份为准，这个字段只在「同一条记录被两家
/// 站点读到」时提供一个人可读的地区标注。
pub const MODE: &str = "cn";

/// 网页门户基址（授权页所在的那台主机）。
///
/// 千问办公把网页、账号接口与推理网关**都放在 gateway 这一台主机上**，所以
/// [`WEB_ORIGIN`] / [`OPEN_API`] / [`GATEWAY`] 三项取同一个域。
pub const WEB_ORIGIN: &str = "https://gateway.qwenwork.cn";
/// 账号接口基址（与门户同主机）
pub const OPEN_API: &str = "https://gateway.qwenwork.cn";
/// 推理 / 模型目录基址（`/algo/...` 这一族的根，含尾斜杠）
pub const GATEWAY: &str = "https://gateway.qwenwork.cn/";

/// COSY 协议版本（`Cosy-Version` / payload 里的 `cosyVersion`）
pub const COSY_VERSION: &str = "1.1.52";
/// `Cosy-ClientType`（桌面端形态）
pub const COSY_CLIENT_TYPE: &str = "6";
/// `Cosy-Data-Policy`（客户端是 `agree`；dumate2api 只在 `agree` 下打通签名）
pub const COSY_DATA_POLICY: &str = "agree";
/// `Cosy-Scene`：这一家要发（Qoder 不发）
pub const COSY_SCENE: Option<&str> = Some("qwork");
/// `Cosy-Business-Product`：这一家要发
pub const COSY_BUSINESS_PRODUCT: Option<&str> = Some("qoder_work");
/// `Cosy-Business-Type`：这一家要发
pub const COSY_BUSINESS_TYPE: Option<&str> = Some("agent");
/// 请求体 `session_type`（**必须与 `COSY_CLIENT_TYPE` 自洽**）
pub const SESSION_TYPE: &str = "qoder_work";
/// 请求体 `business.product`
pub const BUSINESS_PRODUCT: &str = "qoder_work";
/// 请求体 `business.version`（客户端自己的版本，与 `cosyVersion` 同值）
pub const BUSINESS_VERSION: &str = "1.1.52";
/// 账号类请求的 `User-Agent`（客户端自己的标识）
pub const USER_AGENT: &str = "qoderwork/1.1.0";

/// 设备授权页路径（`nonce` 必须是标准 UUID，去横线会被判成非法参数）
pub const DEVICE_LOGIN_PATH: &str = "/device/selectAccounts";
/// 设备授权轮询端点
pub const DEVICE_POLL_PATH: &str = "/api/v1/deviceToken/poll";
/// 设备流凭据（`dt-` / `drt-`）的续期端点（与 Qoder 同路径、同主机）
pub const DEVICE_REFRESH_PATH: &str = "/api/v1/deviceToken/refresh";
/// 续期请求体里的 `target`（`c` = 客户端形态）。
///
/// **不带会拿到另一族的令牌** —— 这是 native `Site::refresh_target` 的实测
/// 结论（dumate2api 同款）。
pub const REFRESH_TARGET: Option<&str> = Some("c");
// 这一家**没有作业令牌**（`/api/v1/jobToken/exchange` 不存在）：设备令牌本身
// 就是对话令牌，续期也只有设备端点这一条。native 用 `Site::device_only` 表达
// 这件事，本包把结论直接写在 `refresh.rs` 里 —— 少一个「恒为真的开关」。

/// 账号上下文（用户资料 + 计划 + 额度都在这一份里）。
///
/// `include` 带 `page,data_sharing` 是客户端自己的取值（拖一次拿全，省一轮）。
pub const ACCOUNT_CONTEXT_PATH: &str =
    "/api/v1/adapter/user/account-context?include=user,plan,quota,page,data_sharing";
/// 额度读取路径（只要 user/plan/quota 三项 —— 与客户端一致）
pub const ACCOUNT_CONTEXT_QUOTA_PATH: &str =
    "/api/v1/adapter/user/account-context?include=user,plan,quota";
/// 三档积分池（每日 / 每月 / 长期）。**只有国内版的个人账号有**。
///
/// 国际版未取证，`None` = 不读（见 native `Site::wallets_path`：它只对
/// `QwenworkCn` 返回路径，国际版与 Qoder 都是 `None`）。
pub const WALLETS_PATH: Option<&str> = Some("/api/v1/adapter/user/wallets");

/// 模型目录要读的那个场景：整份目录都在 `qwork` 里。
pub const MODEL_SCENE: &str = "qwork";
/// 目录里那些 `enable: false` 的条目要不要一起列出来：要。
///
/// 千问办公的 `enable` 是「本套餐能不能用」，而它的客户端把这些模型**都列
/// 出来**（含未开通的）。
pub const LIST_ALL_MODELS: bool = true;
/// 上下文窗口上限（千问办公客户端声明的值）。
///
/// dumate2api 二分实测到 ~1.02M（超过即整轮失败，不是截断），所以这个值只能
/// 如实写，不能往上抬；目录条目自己声明了 `max_input_tokens` 时以条目为准。
pub const MAX_INPUT_TOKENS: i64 = 1_024_000;

/// 账号身份前缀（同 provider 内的去重键；改前缀会让存量账号被当成新账号）
pub const IDENTITY_PREFIX: &str = "qwenwork";

/// 设备流授权的 `client_id`（桌面客户端的；与 Qoder CN 的 CLI 生产 client_id
/// 逐字相同 —— 这是「两家用同一个 client」的唯一证据来源，别乱改）。
pub const DEVICE_CLIENT_ID: Option<&str> = Some("e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb");
/// 设备流授权的 `redirect_uri`（客户端自己的深链；授权页只认它）
pub const DEVICE_REDIRECT: Option<&str> = Some("qwenwork-cn://");

/// 设备授权页的完整地址（在 gateway 主机上，会 302 到标准 OAuth 页）
pub fn device_login_url() -> String {
    format!("{WEB_ORIGIN}{DEVICE_LOGIN_PATH}")
}

/// 授权页允许的域名（网关据此拦截把用户引去别处的登录地址）
pub fn allowed_login_hosts() -> Vec<String> {
    vec!["qwenwork.cn".to_string(), "gateway.qwenwork.cn".to_string()]
}

/// 账号类请求的头：**最小束**（`Accept` + 自己的 UA [+ `Bearer`]）。
pub fn open_api_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), USER_AGENT.to_string()),
    ];
    if let Some(token) = token {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    headers
}

/// 续期请求的头：UA + `Login-Version` + 一个请求 id（dumate2api 的实测形态）。
///
/// 与 Qoder 那一份（只带 UA）不同：千问办公的续期端点认 `Login-Version: v2`。
/// 鉴权凭据在请求体里，所以这里也不带 `Authorization`。
pub fn refresh_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Login-Version".to_string(), "v2".to_string()),
        ("X-Request-Id".to_string(), super::crypto::uuid_v4()),
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

/// 拼一个账号接口 URL（路径可能自带查询串）
pub fn open_api_url(path: &str) -> String {
    format!("{OPEN_API}{path}")
}

/// 拼一个推理 / 目录 URL（`GATEWAY` 自带尾斜杠）
pub fn gateway_url(path: &str) -> String {
    format!("{GATEWAY}{path}")
}

/// `Cosy-Clientip`：千问办公的客户端把头填成**机器标识**（magpie 与
/// dumate2api 都如此）；机器标识为空时退回回环地址。
pub fn client_ip(machine_id: &str) -> String {
    let machine_id = machine_id.trim();
    if machine_id.is_empty() {
        "127.0.0.1".to_string()
    } else {
        machine_id.to_string()
    }
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
