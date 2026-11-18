//! 上游基址、可配置项与「发一次请求再解 JSON」的公共形态。
//!
//! ── 环境变量 → settings ────────────────────────────────────
//! native 侧这一层读的是进程环境变量（`RACCOON_LLM_BASE_URL` /
//! `RACCOON_AUTH_API_BASE` / `RACCOON_MAIN_SITE_URL` / `RACCOON_POINTS_SITE_URL`
//! / `RACCOON_DEFAULT_MODEL` / `RACCOON_IAM_ISSUER` / `RACCOON_TOKEN`）。
//! wasm32-unknown-unknown **没有环境变量**，因此同一批配置改由宿主设置读取
//! （`settings.get`，键名见下面的常量）。语义逐个保持原样：去空白、
//! 去末尾斜杠、空串视为未设置。
//!
//! ── 关于协议校验（原实现的差异，有意保留）──────────────────
//! 源实现会校验「只允许 https 或本机 http」并在非法时抛错；native 侧已经
//! 改成「非法值原样使用，请求失败时由传输层报出可读错误」。这里沿用后者：
//! 插件零 panic，配置项错在最外层暴露比在这里猜更准。

use agent2api_wasm_sdk::{self as sdk, http, Error, Result, Value};

/// 默认 LLM 网关地址（源实现 `DEFAULT_LLM_BASE_URL`）
pub const DEFAULT_LLM_BASE_URL: &str = "https://xiaohuanxiong.com/api/web/llm/v2";

/// 默认鉴权站点（源实现 `DEFAULT_AUTH_ORIGIN` + `DEFAULT_AUTH_API_PREFIX`）
pub const DEFAULT_AUTH_ORIGIN: &str = "https://xiaohuanxiong.com";
pub const DEFAULT_AUTH_API_PREFIX: &str = "/api/web/auth/v1";

/// 默认主站 origin（余额 / 签到 / 新手任务那一族接口的站点）
pub const DEFAULT_MAIN_SITE_URL: &str = "https://xiaohuanxiong.com";

/// 积分余额接口的默认 origin（见 `balance::points_origin` 的说明：
/// apex 把 `/api/web/points/*` 拦成 403，同一 token 打 www 返回 200）
pub const DEFAULT_POINTS_SITE_URL: &str = "https://www.xiaohuanxiong.com";

/// 静态兜底清单里的默认对话模型 id（源实现 `DEFAULT_MODEL_ID`）
pub const DEFAULT_MODEL_ID: &str = "raccoon-405a1c";

/// 上游 JSON 应答的读取上限（4 MiB，与 SDK 的 `Response::json` 同一口径）。
pub const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

/// 设置键名（宿主设置页可见的键就是这些）。
pub mod keys {
    /// LLM 网关基址（含 `/api/web/llm/v2` 前缀）
    pub const LLM_BASE: &str = "llmBase";
    /// 鉴权 API 基址（含 `/api/web/auth/v1` 前缀）
    pub const AUTH_BASE: &str = "authBase";
    /// 主站 origin（余额 / 签到 / 新手任务）
    pub const MAIN_SITE: &str = "mainSite";
    /// 积分余额 origin（默认 www）
    pub const POINTS_SITE: &str = "pointsBase";
    /// 静态兜底清单里的默认对话模型
    pub const DEFAULT_MODEL: &str = "defaultModel";
    /// IAM issuer 的覆盖值（不给则从鉴权基址反推）
    pub const IAM_ISSUER: &str = "iamIssuer";
    /// 静态凭证旁路（替代 native 的 `RACCOON_TOKEN`）
    pub const ENV_TOKEN: &str = "envToken";
    /// 桌面端身份头的平台值（插件无法探测宿主 OS，所以做成配置）
    pub const CLIENT_PLATFORM: &str = "clientPlatform";
    /// 桌面端身份头的架构值（`desktop-{os}-{arch}` 的那一段）
    pub const CLIENT_ARCH: &str = "clientArch";
    /// 桌面端身份头的 OS 版本号（`X-Client-OS-Version`；不给就不发这个头）
    pub const CLIENT_OS_VERSION: &str = "clientOsVersion";
    /// 桌面端身份头的版本值
    pub const CLIENT_VERSION: &str = "clientVersion";
    /// 外部头部覆盖表（替代 native 的 `raccoon-headers.json`）
    pub const EXTERNAL_HEADERS: &str = "externalHeaders";
}

/// 读一条设置；读不到 / 主程序报错一律返回 `Null`（配置项缺失不是错误）。
pub fn setting(key: &str) -> Value {
    sdk::settings::get(key).unwrap_or(Value::Null)
}

/// 读一条字符串设置（去空白；空串视为未设置）。
pub fn setting_text(key: &str) -> String {
    setting(key)
        .as_str()
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 读一条「基址」设置：去空白、去末尾斜杠；为空则用默认值。
fn base(key: &str, fallback: &str) -> String {
    let value = setting_text(key);
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

/// LLM 网关地址（设置 `llmBase` 可覆盖，末尾斜杠去掉）。
pub fn llm_base() -> String {
    base(keys::LLM_BASE, DEFAULT_LLM_BASE_URL)
}

/// 鉴权 API 基址（设置 `authBase` 可覆盖；默认 `{origin}{prefix}`）。
pub fn auth_api_base() -> String {
    let fallback = format!("{DEFAULT_AUTH_ORIGIN}{DEFAULT_AUTH_API_PREFIX}");
    base(keys::AUTH_BASE, &fallback)
}

/// 主站 origin（设置 `mainSite` 可覆盖）。
///
/// ⚠️ 本家有两个消费点各自读同一个配置：网页登录的授权页（`login.rs`）
/// 与余额 / 签到（`balance.rs`）。两处都沿用同一个 `mainSite` 键，
/// **不**提供第三份读法 —— 三个同样的读法只会让「换域名」时漏改一处。
pub fn main_site() -> String {
    base(keys::MAIN_SITE, DEFAULT_MAIN_SITE_URL)
}

/// 积分余额 origin（设置 `pointsBase` 可覆盖；默认 www）。
pub fn points_site() -> String {
    base(keys::POINTS_SITE, DEFAULT_POINTS_SITE_URL)
}

/// 静态兜底清单里的默认对话模型 id（设置 `defaultModel` 可覆盖）。
///
/// 覆盖值只在静态兜底清单里生效，远程目录回来时以远程为准 —— 它是
/// **用户可见的模型名**（客户端点名要它时上游要认得）。
pub fn default_model() -> String {
    let value = setting_text(keys::DEFAULT_MODEL);
    if value.is_empty() {
        DEFAULT_MODEL_ID.to_string()
    } else {
        value
    }
}

/// IAM issuer（设置 `iamIssuer` 可覆盖；否则从鉴权基址的 host 推 `{host}/iam`）。
///
/// native 侧的顺序是「环境变量 → 从 `RACCOON_AUTH_API_BASE` 的 host 反推」，
/// 这里逐条照搬，只是第一段的来源从环境变量换成了设置。
pub fn iam_issuer() -> String {
    let configured = setting_text(keys::IAM_ISSUER);
    if !configured.is_empty() {
        return configured;
    }
    let host = crate::url::host_with_port(&auth_api_base());
    if host.is_empty() {
        "xiaohuanxiong.com/iam".to_string()
    } else {
        format!("{host}/iam")
    }
}

/// 桌面端身份头的平台值（默认 `desktop-windows`）。
///
/// native 侧用 `cfg!(target_os = ...)` 判本机；wasm 目标既不是 windows 也不是
/// macos/linux（`cfg!` 会一律落到 linux 分支），所以改成可配置项 ——
/// 默认值与网关的主流部署形态一致，换平台时不必重编插件。
pub fn client_platform() -> String {
    let value = setting_text(keys::CLIENT_PLATFORM);
    if value.is_empty() {
        "desktop-windows".to_string()
    } else {
        value
    }
}

/// 桌面端身份头的版本值（默认 `v1.1.5`，与官方客户端 1.1.5 对齐）。
pub fn client_version() -> String {
    let value = setting_text(keys::CLIENT_VERSION);
    if value.is_empty() {
        "v1.1.5".to_string()
    } else {
        value
    }
}

/// 桌面端身份头的架构值（默认 `x64`）。
pub fn client_arch() -> String {
    let value = setting_text(keys::CLIENT_ARCH);
    if value.is_empty() {
        "x64".to_string()
    } else {
        value
    }
}

/// 桌面端身份头里的 OS 版本号（可为空 = 不发这个头）。
pub fn client_os_version() -> String {
    setting_text(keys::CLIENT_OS_VERSION)
}

/// 外部头部覆盖表（设置 `externalHeaders`，JSON 对象）。
///
/// 上游头部的取值（尤其 `X-Client-Version`）随客户端版本变化，写死在
/// 二进制里意味着每次对不上都要重编插件。native 侧读的是
/// `/var/lib/agent2api/raccoon-headers.json`；wasm 没有文件系统，
/// 因此同一份表改由设置承载：写成 `{"X-Client-Version": "v1.2.0"}`
/// 这样的 JSON 对象即可覆盖同名头，其余键追加。不是 JSON 对象时整体跳过。
pub fn external_headers() -> Value {
    setting(keys::EXTERNAL_HEADERS)
}

/// 静态凭证（设置 `envToken`；空白串视为未设置）。
///
/// native 侧的对应物是环境变量 `RACCOON_TOKEN`（脚本 / CI 的常规入口）。
/// wasm 读不到进程环境变量，改由设置提供同一份旁路：只在**没有指定账号**
/// 时才生效（见 `account::ensure` 的说明）。
pub fn env_token() -> Option<String> {
    let value = crate::jwt::strip_bearer(&setting_text(keys::ENV_TOKEN));
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// `Vec<(String, String)>` → SDK 要的 headers 对象。
///
/// ── 为什么要做大小写不敏感的合并 ────────────────────────────
/// native 侧的头部是 `Vec`（`upsert` 用 `eq_ignore_ascii_case` 判同名），
/// 换成 JSON 对象后同名不同大小写的项会变成两个键，出网层未必按
/// HTTP 语义合并 —— 那样 `X-Client-Version` 就会出现两次。
/// 这里先按同一判据合并（后来者覆盖），再转对象。
pub fn headers_value(headers: &[(String, String)]) -> Value {
    let mut merged: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        match merged
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            Some((_, current)) => *current = value.clone(),
            None => merged.push((name.clone(), value.clone())),
        }
    }
    let mut object = serde_json::Map::new();
    for (name, value) in merged {
        object.insert(name, Value::String(value));
    }
    Value::Object(object)
}

/// 一次请求的原始结果（**不看状态码**的形态）。
///
/// native 侧的 `send_raw` 返回 `ApiResponse { status, ok, payload }`：非 2xx
/// 也照样解析 body，因为各家的错误判定链都要读业务码。wasm SDK 的
/// `Response::json` 在非 2xx 时直接报错，所以这里自己读字节再解 ——
/// 判定顺序与 native 逐条一致。
pub struct Raw {
    pub status: u16,
    pub ok: bool,
    pub payload: Value,
}

/// 发一次请求并尽力解析 JSON（解析失败给 `Null`，不报错）。
pub fn send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
) -> Result<Raw> {
    let response = http::open(method, url, headers_value(headers), body)?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT)?;
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Ok(Raw {
        status,
        ok: (200..300).contains(&status),
        payload,
    })
}

/// 把一个 SDK 错误改写成「本家口径」的错误（带可读中文前缀）。
///
/// 传输层的原始文案（`connect error` 这类）对用户没有信息量，但它是排障
/// 的唯一线索，所以只加前缀、不替换内容。
pub fn transport(prefix: &str, error: Error) -> Error {
    Error::http(502, format!("{prefix}: {}", error.message))
}

/// 小整型解析（业务码 / 计数字段共用）。
pub fn int_of(value: Option<&Value>) -> Option<i64> {
    let number = match value? {
        Value::Number(number) => number.as_f64()?,
        // 上游偶尔把数字写成字符串（源实现的 `Number(value)` 两种都认）
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if number.is_finite() {
        Some(number.floor() as i64)
    } else {
        None
    }
}
