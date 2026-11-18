//! Kiro（kiro.dev）的地址与协议常量。
//!
//! ── 依据 ────────────────────────────────────────────────────
//! native 侧参考实现是 magpie 社区的 `@magpie-community/opencode-kiro-auth`
//! （MIT），本包逐条照搬其地址与请求形态：
//!
//! ```text
//!   登录（Kiro 门户）   https://app.kiro.dev/signin
//!   换码 / 刷新（社交） https://prod.{region}.auth.desktop.kiro.dev
//!   AWS OIDC            https://oidc.{region}.amazonaws.com
//!   控制面（目录/用量）  https://management.{region}.kiro.dev
//!   推理                https://runtime.{region}.kiro.dev/generateAssistantResponse
//! ```
//!
//! ── 地区只有两个 ────────────────────────────────────────────
//! `us-east-1` 与 `eu-central-1`。账号的 profile ARN 里带地区，登录地区是兜底；
//! 两边共用同一套账号体系与令牌，只是端点不同，所以**不拆家**。
//! `origins` 因此可以逐条写死（没有通配）—— 两个地区各两条端点。
//!
//! ── `redirect_uri` 为什么是固定串 ───────────────────────────
//! native 每轮自绑一个回环端口；wasm 没有 socket，收不到浏览器回调，改成
//! 「回填地址栏 URL」（`manualCallback: true`）。授权时用的 `redirect_uri`
//! 仍是本机回环（Kiro 的 desktop 客户端允许任意 loopback 端口），这里固定
//! 取 Kiro IDE 常用的 3128，换取码时逐字回传同一个串。

/// Kiro 门户（浏览器登录入口）。
pub const PORTAL: &str = "https://app.kiro.dev";

/// 社交登录换码服务（与地区无关：门户固定 us-east-1 的 auth 服务）。
pub const AUTH_SERVICE: &str = "https://prod.us-east-1.auth.desktop.kiro.dev";

/// Kiro IDE / kiro-cli 给 Builder ID 用的 profile。
///
/// 本包不提供企业 SSO（需要自注册客户端 + 固定回环回调，wasm 侧没有这两条），
/// 但 Builder ID 的固定 profile 仍用于「导入本机登录态」那类账号的额度与目录
/// 请求：它们的 `login_provider` 就是 `builderid`。
pub const BUILDER_ID_PROFILE: &str = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX";

/// 本轮回填用的回环回调（逐字回传给 token 端点）。
pub const REDIRECT_URI: &str = "http://localhost:3128";

/// 刷新窗口：请求前 token 距过期不足这么久就先刷。
pub const EARLY_MS: i64 = 2 * 60 * 1000;

/// 后台续期的提前量（网关的 `token.expiring` 用它）。
pub const LEAD_MS: i64 = 10 * 60 * 1000;

/// 镜像 UA：`KiroIDE-<version>-<hash>`，hash 由主机名派生。
///
/// wasm 拿不到主机名，用固定串 `wasm` 派生 —— 同一台网关上稳定，换机器就变，
/// 与 native 的「每台机器一个指纹」同一形态。
pub fn ide_user_agent() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"agent2api:");
    hasher.update(b"wasm");
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("KiroIDE-1.1.70-{hex}")
}

/// 刷新社交登录时 Kiro 桌面端自报的 UA。
pub const DESKTOP_UA: &str = "Kiro-Desktop/0.2.13 (darwin; arm64)";

/// 控制面地址。
pub fn management(region: &str) -> String {
    format!("https://management.{region}.kiro.dev")
}

/// 推理地址。
pub fn runtime(region: &str) -> String {
    format!("https://runtime.{region}.kiro.dev")
}

/// AWS OIDC 地址。
pub fn oidc(region: &str) -> String {
    format!("https://oidc.{region}.amazonaws.com")
}

/// 社交登录的刷新地址。
pub fn refresh_url(region: &str) -> String {
    format!("https://prod.{region}.auth.desktop.kiro.dev/refreshToken")
}

/// 从 profile ARN 里取地区；取不到时按登录地区判（EU → eu-central-1）。
pub fn region_of(profile: &str, signed_in: &str) -> String {
    let parts: Vec<&str> = profile.split(':').collect();
    if parts.len() > 4 && !parts[3].is_empty() {
        return parts[3].to_string();
    }
    if signed_in.starts_with("eu-") {
        "eu-central-1".to_string()
    } else {
        "us-east-1".to_string()
    }
}

/// AWS JSON 1.0 的 `x-amz-target`（控制面操作名）。
pub const TARGET_USAGE_LIMITS: &str = "AmazonCodeWhispererService.GetUsageLimits";
pub const TARGET_KEY_MODELS: &str = "KiroControlPlaneBearerService.ListAvailableModels";
/// 独立网页搜索的操作名（`InvokeMCP`）。
pub const TARGET_MCP: &str = "AmazonCodeWhispererStreamingService.InvokeMCP";

/// 推理请求的 UA（native 逐字）。
pub fn streaming_user_agent() -> String {
    format!(
        "aws-sdk-rust/1.0.0 ua/2.1 os/other lang/rust api/codewhispererstreaming#1.28.3 m/E app/AmazonQ-For-CLI md/appVersion-1.28.3-{}",
        // 每次请求一个随机尾号，与 native 的 `new_message_id()` 同用途。
        message_id()
    )
}

/// 一个随机的消息标识（16 位十六进制；随机源不可用时给空串 —— 它只用于
/// 请求侧的幂等尾号，不承担安全职责）。
pub fn message_id() -> String {
    sdk_random_bytes(8)
        .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect())
        .unwrap_or_default()
}

/// 一个 UUID v4 形态的串（native 用 `ids::uuid_v4()`）。
pub fn uuid_v4() -> String {
    let mut bytes = sdk_random_bytes(16).unwrap_or_else(|_| vec![0u8; 16]);
    // 版本位与变体位按 RFC 4122 修正（随机源不可用时退化成全零形态）。
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// 宿主的随机字节（`random.bytes`，能力 `random.v1`，回 base64）。
///
/// 随机源不可用时**报错而不是退化**：这里的字节要喂给 OAuth 的 `state` 与
/// PKCE `verifier`，用时间派生的伪随机等于把 CSRF 防护削掉。调用点会把它
/// 变成一条可读错误（「无法生成安全的登录凭据」）。
fn sdk_random_bytes(length: usize) -> Result<Vec<u8>, String> {
    let value = agent2api_wasm_sdk::host(
        "random.bytes",
        agent2api_wasm_sdk::json!({ "length": length }),
    )
    .map_err(|_| "无法生成安全的登录凭据，请重新发起".to_string())?;
    let encoded = value
        .as_str()
        .ok_or_else(|| "无法生成安全的登录凭据，请重新发起".to_string())?;
    let bytes = base64_decode(encoded).ok_or_else(|| "无法生成安全的登录凭据，请重新发起".to_string())?;
    if bytes.len() != length {
        return Err("无法生成安全的登录凭据，请重新发起".to_string());
    }
    Ok(bytes)
}

/// 标准 base64 解码（宿主给的是带填充的标准字母表）。
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
