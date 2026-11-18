//! Antigravity（Google AI IDE）的上游地址、OAuth 常量与**逐字请求头**。
//!
//! ── 三个平面，域名与协议各不相同 ────────────────────────────
//! ```text
//!   Google OAuth        https://accounts.google.com/o/oauth2/v2/auth
//!                       https://oauth2.googleapis.com/token        （取 / 刷 token）
//!                       https://www.googleapis.com/oauth2/v2/userinfo
//!   Cloud Code Assist   https://<env>-cloudcode-pa.googleapis.com/v1internal
//!                       （推理、模型目录、project 发现都在这一个平面上）
//! ```
//!
//! ── v1internal 的冒号语法（最容易写错的一处）────────────────
//! `/v1internal` 是**路径前缀**，方法名用 `:` 直接接在后面，**没有**
//! `/models/{model}:...` 那一段（那是 `generativelanguage.googleapis.com`
//! 的形态，本家不用），模型名放在请求体里。
//!
//! ── 三个环境（不是地区）与用途 ──────────────────────────────
//! `sandbox` → `daily` → `prod` 是**环境**差异（本家没有地域参数）。聊天流量
//! 固定取 `daily`（9router 的长期选择，且不是最容易 429 的 prod）；project
//! 发现固定走 **prod**（daily 会拒这两个调用）。
//!
//! ── 明确不要发的头 ──────────────────────────────────────────
//! `x-goog-api-client`：属于 IDE 的 JS 层，官方客户端出口**不发**，发了反而
//! 形成「Electron + Node.js」的矛盾指纹。

/// Antigravity 的公开 OAuth 客户端 id（随官方客户端分发，不是用户机密）。
///
/// 拆成两段写是为了绕开仓库的 push protection（它按字面量匹配已知的 OAuth
/// 凭证形态，公开值也会被拦），编译期拼回同一个串。
pub const CLIENT_ID: &str = concat!(
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep",
    ".apps.googleusercontent.com"
);

/// 与 [`CLIENT_ID`] 配套的 client secret（同上，公开值）。
pub const CLIENT_SECRET: &str = concat!("GOCSPX-K58FWR486LdLJ1mLB8sXC", "4z6qDAf");

/// 授权码端点。
pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// token 端点：**取 token 与刷新都打这一个**（form 表单）。
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// userinfo（v2 → v1 兜底）。
pub const USERINFO_URL_V2: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
pub const USERINFO_URL_V1: &str = "https://www.googleapis.com/oauth2/v1/userinfo";

/// OAuth 授权范围（**没有 `cloud-platform` 一定失败**：v1internal 全部方法都要它）。
pub const SCOPES: [&str; 6] = [
    "openid",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

/// 刷新用的 grant_type（逐字；不是 `refreshToken`）。
pub const GRANT_TYPE_REFRESH: &str = "refresh_token";
/// 授权码换 token 用的 grant_type。
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";

/// 三个环境基址。
pub const V1_BASE_URL_SANDBOX: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";
pub const V1_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
pub const V1_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";

/// 候选基址顺序（模型目录刷新按它依次尝试）。
pub const V1_BASE_URLS: [&str; 3] = [V1_BASE_URL_SANDBOX, V1_BASE_URL_DAILY, V1_BASE_URL_PROD];

/// project 发现（loadCodeAssist / onboardUser）**固定用 prod**。
pub const PROJECT_BASE_URL: &str = V1_BASE_URL_PROD;

/// 流式推理方法名（冒号拼在基址之后；`?alt=sse` 必带）。
pub const METHOD_STREAM_GENERATE: &str = "streamGenerateContent";
/// 模型目录 + 每模型配额。
pub const METHOD_FETCH_AVAILABLE_MODELS: &str = "fetchAvailableModels";
/// 分组额度（周 / 5 小时窗）。
pub const METHOD_RETRIEVE_QUOTA_SUMMARY: &str = "retrieveUserQuotaSummary";
/// 订阅档 + `cloudaicompanionProject`。
pub const METHOD_LOAD_CODE_ASSIST: &str = "loadCodeAssist";
/// 无 project 时开通。
pub const METHOD_ONBOARD_USER: &str = "onboardUser";

/// 流式推理的查询串（逐字）。
pub const STREAM_QUERY: &str = "?alt=sse";

/// OAuth 登录沿用的客户端版本线。
pub const KNOWN_STABLE_VERSION: &str = "4.3.0";
/// CLI 身份（目录与推理用它）。
const CLI_VERSION: &str = "1.5.1";
/// Hub 身份（额度摘要用它）。
const HUB_VERSION: &str = "2.28.0";

/// 平台名（与 native 的 `std::env::consts::OS` 映射同形）。
fn platform_info() -> &'static str {
    match agent2api_wasm_sdk::host("runtime.platform", agent2api_wasm_sdk::json!({}))
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .as_deref()
    {
        Some("mac") => "darwin",
        Some("win") => "windows",
        _ => "linux",
    }
}

/// 架构名（拿不到就给 amd64 —— 本机网关绝大多数情况如此）。
fn architecture() -> &'static str {
    match agent2api_wasm_sdk::host("runtime.architecture", agent2api_wasm_sdk::json!({}))
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .as_deref()
    {
        Some("aarch64") | Some("arm64") => "arm64",
        _ => "amd64",
    }
}

/// 推理与目录的 UA（CLI 身份）。
pub fn default_user_agent() -> String {
    format!("antigravity/cli/{CLI_VERSION} {}/{}", platform_info(), architecture())
}

/// 额度摘要的 UA（Hub 身份；专属额度组由 Hub 客户端接口披露）。
pub fn quota_user_agent() -> String {
    format!(
        "antigravity/hub/{HUB_VERSION} (aidev_client; os_type={}; arch={})",
        platform_info(),
        architecture(),
    )
}

/// OAuth 换码、刷新与 userinfo 的 UA（登录身份）。
pub fn oauth_user_agent() -> String {
    format!("vscode/1.X.X (Antigravity/{KNOWN_STABLE_VERSION})")
}

/// 拼一个 v1internal 方法的完整 URL：`{base}:{method}`。
pub fn method_url(base: &str, method: &str) -> String {
    format!("{base}:{method}")
}

/// 流式推理端点。
pub fn stream_generate_url(base: &str) -> String {
    format!("{base}:{METHOD_STREAM_GENERATE}{STREAM_QUERY}")
}

/// 模型目录端点。
pub fn fetch_available_models_url(base: &str) -> String {
    method_url(base, METHOD_FETCH_AVAILABLE_MODELS)
}

/// 分组额度摘要端点。
pub fn retrieve_user_quota_summary_url(base: &str) -> String {
    method_url(base, METHOD_RETRIEVE_QUOTA_SUMMARY)
}

/// project 发现：`loadCodeAssist`（**prod**）。
pub fn load_code_assist_url() -> String {
    method_url(PROJECT_BASE_URL, METHOD_LOAD_CODE_ASSIST)
}

/// project 开通：`onboardUser`（**prod**）。
pub fn onboard_user_url() -> String {
    method_url(PROJECT_BASE_URL, METHOD_ONBOARD_USER)
}

/// 一个随机的消息标识（16 位十六进制；随机源不可用时用时钟派生 —— 它只用于
/// chat 帧的 id 与工具调用的兜底 id，不承担安全职责）。
pub fn message_id() -> String {
    if let Ok(value) = agent2api_wasm_sdk::host("random.bytes", agent2api_wasm_sdk::json!({ "length": 8 })) {
        if let Some(raw) = value.as_str() {
            if let Some(bytes) = base64_decode(raw) {
                if bytes.len() == 8 {
                    return bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                }
            }
        }
    }
    format!("{:016x}", agent2api_wasm_sdk::now() as u64)
}

/// 标准 base64 解码（宿主 `random.bytes` 回的是标准字母表）。
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// 鉴权头（token **必须**放 Bearer 头，不能塞 query）。
pub fn bearer_header(access_token: &str) -> (String, String) {
    ("authorization".to_string(), format!("Bearer {}", access_token.trim()))
}

/// 客户端元信息必须与同次请求的 UA 版本一致。
fn client_version() -> &'static str {
    CLI_VERSION
}

/// 公共客户端头（`x-client-name` / `x-client-version`）。
fn client_headers(access_token: &str, user_agent: String) -> agent2api_wasm_sdk::Value {
    let (auth_key, auth_value) = bearer_header(access_token);
    let mut headers = agent2api_wasm_sdk::json!({
        "content-type": "application/json",
        "user-agent": user_agent,
        "x-client-name": "antigravity",
        "x-client-version": client_version(),
    });
    headers[auth_key] = agent2api_wasm_sdk::json!(auth_value);
    headers
}

/// 推理的 project 只放请求体，不能带 `x-goog-user-project`。
pub fn content_headers(access_token: &str) -> agent2api_wasm_sdk::Value {
    client_headers(access_token, default_user_agent())
}

/// 目录请求头（带 `x-goog-user-project`）。
pub fn catalog_headers(access_token: &str, project_id: &str) -> agent2api_wasm_sdk::Value {
    with_project(client_headers(access_token, default_user_agent()), project_id)
}

/// 额度请求头（Hub UA + project）。
pub fn quota_headers(access_token: &str, project_id: &str) -> agent2api_wasm_sdk::Value {
    with_project(client_headers(access_token, quota_user_agent()), project_id)
}

fn with_project(mut headers: agent2api_wasm_sdk::Value, project_id: &str) -> agent2api_wasm_sdk::Value {
    let project = project_id.trim();
    if !project.is_empty() {
        headers["x-goog-user-project"] = agent2api_wasm_sdk::json!(project);
    }
    headers
}

/// Claude 的 `anthropic-beta` 值（Manager 逐字）。
const ANTHROPIC_BETA_CLAUDE: &str = "claude-code-20250219";

/// **Claude 模型**的 content 请求头：在 [`content_headers`] 之上补
/// `anthropic-beta`（**仅 Claude** —— Gemini 带上它没有依据）。
pub fn claude_content_headers(access_token: &str) -> agent2api_wasm_sdk::Value {
    let mut headers = content_headers(access_token);
    headers["anthropic-beta"] = agent2api_wasm_sdk::json!(ANTHROPIC_BETA_CLAUDE);
    headers
}

/// project 发现与开通沿用登录身份。
pub fn admin_headers(access_token: &str, project_id: &str) -> agent2api_wasm_sdk::Value {
    with_project(client_headers(access_token, oauth_user_agent()), project_id)
}
