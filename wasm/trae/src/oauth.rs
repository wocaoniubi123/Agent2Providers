//! Trae 的网页登录链路：PKCE、授权地址、回调解析、授权码换凭据。
//!
//! ── 这条链上最要紧的三件事 ────────────────────────────────
//! 1. **回调地址的形状是死的**。官方授权页在前端就把 `auth_callback_url`
//!    硬校验成 `^http://127.0.0.1:<port>/authorize$` —— 别的 host 或路径会在
//!    登录 UI 出现**之前**渲染"登录失败/网络错误"（参考实现 2026-09-02 实测）。
//!    插件侧**不能**自己监听端口（Wasm 没有 socket），所以地址里用一个固定
//!    端口，授权完成后浏览器停在"无法访问"页，用户把地址栏那条 URL 粘回来
//!    —— 这正是 native 为"远程浏览器 / 容器"准备的 `login.callback` 那条路。
//! 2. **授权地址里参数的顺序与编码方式不是风格问题**。`auth_callback_url`
//!    刻意**不**编码（官方页面对它做正则匹配，编码后就匹配不上了），
//!    其余按 `application/x-www-form-urlencoded`（空格是 `+`）。
//!    顺序也保留。
//! 3. **`DeviceInfo.DevicePublicKey` 不能空**（空值 = HTTP 401 / 业务码 20405，
//!    设备绑定被拒），所以每次登录现生成一套 EC P-256，见 `device.rs`。
//!
//! 授权页只把 `authCode`（或 `refreshToken`）与它自己的 `loginHost` 带回回调，
//! 没有我们的 ticket —— 所以**同一时刻只允许一个进行中的登录**：状态位放在
//! 宿主的 Login 作用域里，新的 `login.start` 直接覆盖旧的。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::device;
use super::headers::{IDE_VERSION, IDE_VERSION_CODE};
use super::refresh::parse_refresh_response;
use super::upstream::{describe_candidates, post_json, trim, url_encode};

pub const PLUGIN_VERSION: &str = "1.0.0";
pub const DEVICE_NAME: &str = "DESKTOP-CPASOLO";
pub const DEVICE_TYPE: &str = "windows";
pub const DEVICE_BRAND: &str = "83DG";
pub const OS_VERSION: &str = "Windows 11 Pro";
pub const ENV: &str = "prod";
pub const APP_TYPE: &str = "trae";
/// 回调路径 —— 官方前端只认这一个。
pub const CALLBACK_PATH: &str = "/authorize";
/// 回调地址里的端口。
///
/// native 是**绑定成功后**拿真实端口拼地址；插件没有 socket，这里用固定端口：
/// 上游那个正则只校验形状（`http://127.0.0.1:<port>/authorize`），端口号本身
/// 不参与校验，真正的事件由用户粘贴回来的 URL 驱动（见模块头）。
pub const CALLBACK_PORT: u16 = 41595;
/// 授权码换证的路径（与 refreshToken 续期**不是**同一个）。
pub const AUTH_CODE_EXCHANGE_PATH: &str = "/trae/api/v3/oauth/ExchangeToken";
/// GetLoginGuidance 的候选（依次试；全失败时 CN 兜到默认登录 host）。
pub const GUIDANCE_URLS_CN: [&str; 3] = [
    "https://api.trae.cn/cloudide/api/v3/trae/GetLoginGuidance",
    "https://api.trae.com.cn/cloudide/api/v3/trae/GetLoginGuidance",
    "https://www.trae.cn/cloudide/api/v3/trae/GetLoginGuidance",
];
/// 兜底登录 host（guidance 全挂时用，参考实现同一条：CN 不因它阻塞登录流程）。
pub const DEFAULT_LOGIN_HOST: &str = "https://api.trae.cn";
/// 兜底换证 host 列表（回调没带回 loginHost 时用）。
const ACCOUNT_API_ORIGINS: [&str; 2] = ["https://api.trae.cn", "https://api.trae.com.cn"];

/// SOLO 那个 OAuth 应用的 ClientID（参考实现同值，`SOLO stable`）。
pub const SOLO_CLIENT_ID: &str = "en1oxy7wnw8j9n";
/// 非 SOLO（TRAE CN IDE / 国际版）那一个的 ClientID。
pub const IDE_CLIENT_ID: &str = "ono9krqynydwx5";

pub fn client_id_for(variant: &str) -> &'static str {
    match variant {
        "solo" | "solo-intl" => SOLO_CLIENT_ID,
        _ => IDE_CLIENT_ID,
    }
}

/// 同一张表里的"另一把"：续期时归属未知、或按 variant 推的那把被上游拒了，
/// 备选就是它（本家只认这两把）。
pub fn other_client_id(client_id: &str) -> Option<&'static str> {
    match client_id {
        SOLO_CLIENT_ID => Some(IDE_CLIENT_ID),
        IDE_CLIENT_ID => Some(SOLO_CLIENT_ID),
        // 来路不明的第三把（将来上游换了应用）不给候选 —— 猜一把没有依据的
        // ClientID 只是多打一发，不如就让这一家失败得干净
        _ => None,
    }
}

/// 下面三张表都只认 `"solo"` 这一个值 —— 参考实现比的是
/// `variant == variantSolo`，`"solo-intl"` 走的是**非 solo 分支**
/// （auth_from=trae、PlatformCode=IDE_PC、不带 hide_saas_login）。
/// 只有 ClientID 是查表，solo 与 solo-intl 同值。
pub fn auth_from_for(variant: &str) -> &'static str {
    if variant == "solo" { "solo" } else { "trae" }
}

pub fn platform_code_for(variant: &str) -> &'static str {
    if variant == "solo" { "SOLO_PC" } else { "IDE_PC" }
}

pub fn hide_saas_login_for(variant: &str) -> bool {
    variant == "solo"
}

/// `DeviceInfo.DeviceBrand`：官方客户端把 OS 映成厂商名，
/// 而 `DeviceModel` 保留登录地址里那个原始 `x_device_brand`（两者不同值）。
pub fn device_brand_for_context(device_type: &str) -> &'static str {
    match device_type {
        "mac" => "Apple",
        _ => "Microsoft",
    }
}

/// 一次进行中的登录所需的全部状态（PKCE 对 + 设备指纹 + 回调地址）。
#[derive(Clone)]
pub struct LoginContext {
    pub login_trace_id: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub device_id: String,
    pub machine_id: String,
    pub callback_url: String,
    pub variant: String,
    /// 公钥随登录一起生成，私钥要跟着凭据落盘（见 `device.rs`）。
    pub device_public_pem: String,
    pub device_private_pem: String,
}

impl LoginContext {
    /// 生成一轮登录的上下文。
    pub fn new(variant: &str) -> Result<Self> {
        let key_pair = device::key_pair()?;
        let (code_verifier, code_challenge) = device::pkce_pair()?;
        Ok(Self {
            login_trace_id: device::uuid_v4(),
            code_verifier,
            code_challenge,
            device_id: device::random_digits(16),
            machine_id: device::uuid_v4(),
            callback_url: format!("http://127.0.0.1:{CALLBACK_PORT}{CALLBACK_PATH}"),
            variant: variant.to_string(),
            device_public_pem: key_pair.public_pem,
            device_private_pem: key_pair.private_pem,
        })
    }

    /// 存进宿主状态的那一形态（登录状态要跨 RPC）。
    pub fn to_json(&self) -> Value {
        json!({
            "login_trace_id": self.login_trace_id,
            "code_verifier": self.code_verifier,
            "code_challenge": self.code_challenge,
            "device_id": self.device_id,
            "machine_id": self.machine_id,
            "callback_url": self.callback_url,
            "variant": self.variant,
            "device_public_pem": self.device_public_pem,
            "device_private_pem": self.device_private_pem,
        })
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            login_trace_id: value["login_trace_id"].as_str()?.to_string(),
            code_verifier: value["code_verifier"].as_str()?.to_string(),
            code_challenge: value["code_challenge"].as_str()?.to_string(),
            device_id: value["device_id"].as_str()?.to_string(),
            machine_id: value["machine_id"].as_str()?.to_string(),
            callback_url: value["callback_url"].as_str()?.to_string(),
            variant: value["variant"].as_str()?.to_string(),
            device_public_pem: value["device_public_pem"].as_str()?.to_string(),
            device_private_pem: value["device_private_pem"].as_str()?.to_string(),
        })
    }
}

/// 用户要打开的授权地址。参数顺序与编码方式由向量钉住，别"顺手整理"。
pub fn verification_uri(login_host: &str, context: &LoginContext) -> String {
    let login_host = ensure_https_scheme(login_host);
    let mut query: Vec<String> = Vec::new();
    let mut push = |key: &str, value: String, encode: bool| {
        query.push(format!("{key}={}", if encode { url_encode(&value) } else { value }));
    };
    push("login_version", "1".into(), false);
    push("auth_from", auth_from_for(&context.variant).into(), false);
    push("login_channel", "native_ide".into(), false);
    push("plugin_version", PLUGIN_VERSION.into(), true);
    push("auth_type", "local".into(), false);
    push("client_id", client_id_for(&context.variant).into(), false);
    push("redirect", "0".into(), false);
    push("login_trace_id", context.login_trace_id.clone(), true);
    // 刻意不编码：官方页面对它做正则匹配。
    push("auth_callback_url", context.callback_url.clone(), false);
    push("machine_id", context.machine_id.clone(), true);
    push("device_id", context.device_id.clone(), true);
    push("x_device_id", context.device_id.clone(), true);
    push("x_machine_id", context.machine_id.clone(), true);
    push("x_device_brand", DEVICE_BRAND.into(), true);
    push("x_device_type", DEVICE_TYPE.into(), true);
    push("x_os_version", OS_VERSION.into(), true);
    push("x_env", ENV.into(), true);
    push("x_app_version", IDE_VERSION.into(), true);
    push("x_app_type", APP_TYPE.into(), true);
    push("code_challenge", context.code_challenge.clone(), true);
    push("code_challenge_method", "S256".into(), false);
    if hide_saas_login_for(&context.variant) {
        push("hide_saas_login", "true".into(), false);
    }
    format!("{}/authorization?{}", login_host.trim_end_matches('/'), query.join("&"))
}

/// guidance 返回的是裸域名（`www.trae.cn`），不加 scheme 会被浏览器当成
/// 相对路径打到网关自己身上 → 一个"404 page not found"的假故障。
pub fn ensure_https_scheme(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("https://{}", trimmed.trim_start_matches('/'))
}

/// CN 谱系的默认账号 API 源（参考实现 `traeCNDefaultOrigins`，**三条**）。
///
/// 第三条 `www.trae.cn` 是兜底源，别当成噪音删掉：回调没带回 loginHost 时
/// （生产里真出现过），前两把都在 TLB 边缘回过 404，只有它能换通。
const CN_DEFAULT_ORIGINS: [&str; 3] = ["https://api.trae.cn", "https://api.trae.com.cn", "https://www.trae.cn"];

/// 去掉 scheme / 路径，只留 host（参考实现 `hostOnly`）。
fn host_only(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    rest.split(['/', '?', '#']).next().unwrap_or_default().to_string()
}

/// 取 scheme，没有就按 `https`（参考实现 `schemeOf`：`i > 0` 才认，
/// 所以一个以 `://` 开头的畸形串也走默认）。
fn scheme_of(url: &str) -> &str {
    match url.find("://") {
        Some(index) if index > 0 => &url[..index],
        _ => "https",
    }
}

fn dedup_keep_order(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        if !value.is_empty() && !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// 换证要试的**候选 origin**（参考实现 `candidateAPIOorigins` 的 CN 分支）：
/// loginHost 派生的在前（`www.x` 还额外派生一把 `api.x`），CN 默认源垫在后面。
pub fn candidate_api_origins(login_host: &str) -> Vec<String> {
    let mut origins: Vec<String> = Vec::new();
    let derived = ensure_https_scheme(login_host);
    let host = host_only(&derived);
    if !derived.is_empty() && !host.is_empty() {
        origins.push(format!("{}://{}", scheme_of(&derived), host));
        if let Some(stripped) = host.strip_prefix("www.") {
            origins.push(format!("{}://api.{}", scheme_of(&derived), stripped));
        }
    }
    origins.extend(CN_DEFAULT_ORIGINS.iter().map(|origin| origin.to_string()));
    dedup_keep_order(origins)
}

/// 授权码换证要依次试的地址（参考实现 `authCodeExchangeURLsCN` 逐字对齐）：
/// 先把两把官方账号 API 源钉在最前，再接 `candidate_api_origins` 的全部候选，
/// 最后整体去重保序 —— 顺序**就是语义**（`www.*` 那类 host 会回一整页 HTML，
/// 所以它只能垫在后面当兜底）。
pub fn auth_code_exchange_urls(login_host: &str) -> Vec<String> {
    let onto = |origin: &str| format!("{}{AUTH_CODE_EXCHANGE_PATH}", origin.trim_end_matches('/'));
    let mut urls: Vec<String> = ACCOUNT_API_ORIGINS.iter().map(|origin| onto(origin)).collect();
    urls.extend(candidate_api_origins(login_host).iter().map(String::as_str).map(onto));
    dedup_keep_order(urls)
}

/// 回调 query 的键值对（**只做一次**百分号还原，保留重复键与顺序）。
///
/// 暴露出来是给 `profile::callback_identity` 复用同一份解析 —— 回调里除了
/// 授权材料还有一份 `userInfo`（账号身份回显），那是另一把键、另一套候选名，
/// 但"怎么切 query、怎么还原转义"必须是同一个实现。
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

/// 回调带回来的东西。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Callback {
    pub auth_code: String,
    pub refresh_token: String,
    pub login_host: String,
    pub user_tag: String,
    pub error: String,
}

impl Callback {
    /// 解析回调 query。
    ///
    /// 键名候选集合是**上游历史包袱**的一部分（同一件事有四五种写法），
    /// 顺序即优先级。空值不算命中（`authCode=&code=X` 要取到 X）。
    ///
    /// 错误分支**先于**其余字段并直接返回，其他字段一律留空：参考实现
    /// 在 `error`/`isRedirect=false` 处 `return`，那时 authCode 还没被读过
    /// （`isRedirect=false&authCode=AC-1` 的答案是 authCode=""）。把它读出来
    /// 看着无害，实际会让上层以为"拿到码了，只是顺带有个错误"。
    pub fn from_query(query: &str) -> Self {
        let pairs = query_pairs(query);
        let lookup = |keys: &[&str]| -> String {
            keys.iter()
                .find_map(|key| {
                    pairs
                        .iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| value.clone())
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_default()
        };
        // 错误键只看**非空**值（Go 用 vals.Get 后判 != ""，`error=` 不算失败）。
        let error_key = ["error", "error_code", "err", "errorCode"].iter().find_map(|key| {
            pairs
                .iter()
                .find(|(name, value)| name == key && !value.is_empty())
                .map(|(name, value)| format!("{name}={value}"))
        });
        if let Some(error) = error_key {
            return Self { error: format!("oauth callback error: {error}"), ..Default::default() };
        }
        if lookup(&["isRedirect"]) == "false" {
            return Self { error: "oauth callback: isRedirect=false".to_string(), ..Default::default() };
        }
        let login_host = lookup(&["loginHost", "login_host", "LoginHost", "host", "consoleHost"]);
        let user_tag = lookup(&["userTag", "user_tag", "UserTag"]);
        let refresh_token = lookup(&["refreshToken", "refresh_token", "RefreshToken", "refresh-token"]);
        let mut auth_code = lookup(&["authCode", "auth_code", "AuthCode", "authorization_code", "code"]);
        if auth_code.is_empty() {
            for key in ["authCodeInfo", "auth_code_info", "AuthCodeInfo"] {
                let Some(raw) = pairs
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                if let Some(code) = extract_auth_code(&raw) {
                    auth_code = code;
                    break;
                }
            }
        }
        Self { auth_code, refresh_token, login_host, user_tag, error: String::new() }
    }

    /// 这次回调是否把登录推进到了可判定的状态。
    pub fn resolves_login(&self) -> bool {
        !self.error.is_empty() || !self.auth_code.is_empty() || !self.refresh_token.is_empty()
    }
}

fn extract_auth_code(raw: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(raw).ok()?;
    let keys = ["authCode", "auth_code", "AuthCode", "AuthCodeToken", "code"];
    fn walk(value: &Value, keys: &[&str]) -> Option<String> {
        if let Value::Object(map) = value {
            for key in keys {
                if let Some(text) = map.get(*key).and_then(Value::as_str).filter(|text| !text.trim().is_empty()) {
                    return Some(text.to_string());
                }
            }
            for nested in map.values() {
                if nested.is_object() || nested.is_array() {
                    if let Some(found) = walk(nested, keys) {
                        return Some(found);
                    }
                }
            }
        }
        if let Value::Array(items) = value {
            for item in items {
                if let Some(found) = walk(item, keys) {
                    return Some(found);
                }
            }
        }
        None
    }
    walk(&parsed, &keys)
}

/// 只做 `+` 与 `%XX` 的还原（query 语义，不是 path 语义）。
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                // 在**字节片**上做十六进制解析，不能 `&value[i+1..i+3]`：那是按字节
                // 偏移切 `&str`，而 `%` 后面完全可能紧跟一个多字节字符
                // （回调 query 是外部输入，`%你` 这种串一个 HTTP 请求就能送进来），
                // 结束偏移落在字符中间 → 切片 panic —— wasm 里 panic 会整实例 abort。
                // 切不动就当"这不是转义"，原样留一个 `%`。
                let byte = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|text| u8::from_str_radix(text, 16).ok());
                match byte {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 换证成功后的凭据材料。
pub struct Exchanged {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_ms: i64,
    /// 原始响应留一份：区域回显、设备绑定状态、refreshToken 的到期都在里面。
    pub raw: String,
}

/// 用授权码换凭据。
pub fn exchange_auth_code(context: &LoginContext, auth_code: &str, login_host: &str) -> Result<Exchanged> {
    let body = json!({
        "ClientID": client_id_for(&context.variant),
        "AuthCode": auth_code,
        "CodeVerifier": context.code_verifier,
        "IDEVersion": IDE_VERSION,
        "DeviceInfo": device_info(context),
    });
    let headers = vec![
        ("x-cloudide-token".to_string(), String::new()),
        ("User-Agent".to_string(), format!("Trae/{PLUGIN_VERSION} antigravity-cockpit-tools")),
    ];
    let urls = auth_code_exchange_urls(login_host);
    let mut errors = Vec::new();
    for url in &urls {
        match post_json(url, &body, &headers) {
            Ok(reply) if reply.status >= 400 => {
                errors.push(format!("{} => HTTP {} {}", url, reply.status, trim(&reply.body)))
            }
            Ok(reply) => match parse_refresh_response(&reply.body) {
                Ok((access_token, refresh_token, expires_at_ms)) => {
                    return Ok(Exchanged { access_token, refresh_token, expires_at_ms, raw: reply.body });
                }
                Err(reason) => errors.push(format!("{} => {reason}", url)),
            },
            Err(error) => errors.push(format!("{} => {}", url, error.message)),
        }
    }
    Err(Error::http(502, describe_candidates(&urls, &errors)))
}

/// `DeviceInfo`：官方客户端形状。`DevicePublicKey` 空值会被判成设备绑定拒绝。
pub fn device_info(context: &LoginContext) -> Value {
    json!({
        "DeviceID": context.device_id,
        "MachineID": context.machine_id,
        "PlatformCode": platform_code_for(&context.variant),
        "DeviceType": "PC",
        "DeviceName": DEVICE_NAME,
        "DeviceModel": DEVICE_BRAND,
        "ClientVersion": IDE_VERSION,
        "DevicePublicKey": context.device_public_pem,
        "DeviceBrand": device_brand_for_context(DEVICE_TYPE),
        "DeviceCPU": "",
        "OSInfo": DEVICE_TYPE,
        "OSVersion": OS_VERSION,
    })
}

/// 问上游"该去哪个登录页"。全挂时兜到默认 host（CN 不因它阻塞登录流程）。
pub fn request_login_guidance() -> String {
    let body = json!({ "loginTraceID": "", "login_trace_id": "" });
    let headers = vec![("User-Agent".to_string(), format!("Trae/{PLUGIN_VERSION} antigravity-cockpit-tools"))];
    for url in GUIDANCE_URLS_CN {
        // 5 秒量级：这条请求**同步**发生在"点登录"到"给出链接"之间，
        // 三个候选各等很久会让面板先超时（参考实现 v0.12.9 的教训）。
        // 宿主不暴露单请求超时，这里靠候选数量兜住总时长。
        if let Ok(reply) = post_json(url, &body, &headers) {
            if reply.status < 400 {
                if let Some(host) = extract_login_host(&reply.body) {
                    return host;
                }
            }
        }
    }
    DEFAULT_LOGIN_HOST.to_string()
}

/// guidance 响应里登录 host 的位置在几个版本间漂过，逐个试。
///
/// 层次顺序照参考实现：顶层 → `Result`/`result` → `data` → `data.Result`/
/// `data.result`，每层内部按同一串候选键。
/// 判空用"是不是空串"而不是"是不是空白"—— Go 的 `jsonString` 只区分类型，
/// 一个 `" "` 会被它原样带回。
pub fn extract_login_host(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    const KEYS: [&str; 5] = ["LoginHost", "loginHost", "LoginURL", "loginUrl", "login_url"];
    let pick = |value: &Value| {
        KEYS.iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str).filter(|text| !text.is_empty()).map(str::to_string))
    };
    let layer = |value: &Value, key: &str| value.get(key).filter(|nested| nested.is_object()).cloned();
    let result = layer(&parsed, "Result");
    let nested_result = layer(&parsed, "result");
    let data = layer(&parsed, "data");
    let data_result = layer(&parsed, "data").and_then(|data| layer(&data, "Result"));
    let data_nested = layer(&parsed, "data").and_then(|data| layer(&data, "result"));
    for candidate in [Some(&parsed), result.as_ref(), nested_result.as_ref(), data.as_ref(), data_result.as_ref(), data_nested.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(found) = pick(candidate) {
            return Some(found);
        }
    }
    None
}

/// 客户端版本串（与目录表版本同源，别各写一份）。
///
/// `#[allow(dead_code)]`：请求头里用的是 `IDE_VERSION`（另一条常量），
/// 这个函数是给「按版本挑目录表」那类判断留的读数（native 同一条）。
#[allow(dead_code)]
pub fn client_version() -> &'static str {
    IDE_VERSION_CODE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> LoginContext {
        LoginContext {
            login_trace_id: "trace-1".into(),
            code_verifier: "verifier-1".into(),
            code_challenge: "challenge-1".into(),
            device_id: "0123456789abcdef".into(),
            machine_id: "machine-1".into(),
            callback_url: format!("http://127.0.0.1:{CALLBACK_PORT}{CALLBACK_PATH}"),
            variant: "solo".into(),
            device_public_pem: "PUB".into(),
            device_private_pem: "PRIV".into(),
        }
    }

    #[test]
    fn auth_url_keeps_order_and_callback_shape() {
        let url = verification_uri("www.trae.cn", &context());
        // 裸域名必须补 scheme，否则会打到网关自己身上
        assert!(url.starts_with("https://www.trae.cn/authorization?"));
        // 回调地址刻意不编码（官方页面对它做正则匹配）
        let callback = format!("auth_callback_url=http://127.0.0.1:{CALLBACK_PORT}/authorize");
        assert!(url.contains(&callback));
        // 参数顺序即语义：login_version 第一，code_challenge_method 最后
        assert!(url.contains("?login_version=1&auth_from=solo&login_channel=native_ide&"));
        assert!(url.ends_with("&code_challenge_method=S256&hide_saas_login=true"));
        // solo-intl 走非 solo 分支：参数集合不同（没有 hide_saas_login、platform 是 IDE）
        let mut other = context();
        other.variant = "solo-intl".into();
        let url = verification_uri("api.trae.cn", &other);
        assert!(url.contains("&auth_from=trae&"));
        assert!(!url.contains("hide_saas_login"));
        assert_eq!(client_id_for("solo"), client_id_for("solo-intl"));
    }

    #[test]
    fn callback_prefers_error_and_skips_empty_values() {
        let parsed = Callback::from_query("isRedirect=false&authCode=AC-1");
        assert_eq!(parsed.auth_code, "");
        assert_eq!(parsed.error, "oauth callback: isRedirect=false");

        let parsed = Callback::from_query("error=&authCode=AC-1&loginHost=api.trae.cn");
        assert!(parsed.error.is_empty());
        assert_eq!(parsed.auth_code, "AC-1");
        assert_eq!(parsed.login_host, "api.trae.cn");
        assert!(parsed.resolves_login());

        let parsed = Callback::from_query("refresh_token=RT-1");
        assert_eq!(parsed.refresh_token, "RT-1");
    }

    #[test]
    fn callback_extracts_code_from_json_envelope() {
        let raw = "%7B%22authCode%22%3A%22AC-9%22%7D"; // {"authCode":"AC-9"}
        let parsed = Callback::from_query(&format!("authCodeInfo={raw}"));
        assert_eq!(parsed.auth_code, "AC-9");
    }

    #[test]
    fn percent_decode_keeps_bad_escapes() {
        assert_eq!(query_pairs("a=%E4%BD%A0&b=x+y"), vec![
            ("a".to_string(), "你".to_string()),
            ("b".to_string(), "x y".to_string())
        ]);
        // 畸形转义原样保留，不 panic
        assert_eq!(query_pairs("a=%zz")[0].1, "%zz");
    }

    #[test]
    fn login_host_layers() {
        assert_eq!(extract_login_host(r#"{"loginHost":"www.trae.cn"}"#), Some("www.trae.cn".into()));
        assert_eq!(extract_login_host(r#"{"data":{"Result":{"LoginHost":"api.trae.cn"}}}"#), Some("api.trae.cn".into()));
        assert_eq!(extract_login_host(r#"{"Result":{}}"#), None);
    }
}
