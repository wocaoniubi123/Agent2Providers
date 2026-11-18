//! LobsterAI（网易有道「有道龙虾」）上游地址、身份常量与出站薄封装。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/endpoints.rs`。
//!
//! ── 上游长什么样 ────────────────────────────────────────────
//! 网易有道系的桌面 Agent，两个域都在有道名下（CNAME 都指向网易广州 ALB）：
//!
//! ```text
//!   登录门户   https://lobsterai.youdao.com        浏览器授权页（手机号 / 微信）
//!   API        https://lobsterai-server.youdao.com  换码 / 续期 / 目录 / 对话 / 积分 / 活动
//! ```
//!
//! 对话端点是 **OpenAI 兼容的原生协议**（`POST /api/proxy/v1/chat/completions`），
//! 但**只收 SSE**：`stream:false` 上游直接回 HTTP 500（Go 参考 `executor.go:18-21`
//! 实测）。本插件恒以 `stream:true` 请求上游，所以这条要求天然满足 ——
//! 调用方**不要**去动 `stream` 字段。
//!
//! ── 两个 `X-LobsterAI-Client-*` 头是功能性的，不是装饰 ──────────
//! `ClientCapabilities` 声明客户端能力，服务端**按它过滤**：
//!
//! ```text
//!   不带该头             -> 目录里 25 个模型（没有 kimi-k3）
//!   带 kimi-k3-agentic-v1 -> 26 个（kimi-k3 才出现）
//! ```
//!
//! 另一个能力位 `thinking-level-control-v1` 是「把思考关掉」这条参数的前提 ——
//! 缺它时发 `reasoning_effort: "off"` 会得到 HTTP 500。两个都实测过
//! （参考实现的 `lobsterai-product.ts` 与 `headers.go` 的注释）。
//!
//! 版本头走的是**日期式版本**（形如 `2026.9.4`），由上游的更新接口给出；
//! 而 `User-Agent` 照抄参考实现里那个固定的 `LobsterAI/0.1.0` —— 它**故意不跟**
//! 真实版本，动态的那份只由 `X-LobsterAI-Client-Version` 承载。
//!
//! ── 没有任何签名 ────────────────────────────────────────────
//! 纯 `Bearer`。没有 HMAC / DPoP / PKCE，也没有腾讯系的 `X-Domain` /
//! `X-Product` / `X-IDE-*` 那批归属头 —— 那些发过去轻则被忽略、重则把请求归到
//! 错误的客户端形态上（参考实现的模块头原话）。所以本插件不需要任何签名模块，
//! 也没有「缺密码学原语」这一项（与 codearts / trae / qoder 不同）。
//!
//! ── 为什么不提供主机覆盖（与 native 的一处差异）──────────────────
//! native 的 `api_base()` / `portal_base()` 认 `LOBSTERAI_API_BASE` /
//! `LOBSTERAI_PORTAL_BASE` 环境变量。wasm 沙箱没有环境变量，而 `wasm.json`
//! 的 `origins` 是**硬白名单**：可配置主机 = 多一个「配了但被白名单拦掉」的
//! 静默失败面（编译不报错，运行期请求直接失败）。这里跟随 trae 的口径保持
//! 常量；要换出口请改宿主的出网设置，那里改的是同一条链路，不是主机名。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{http, Error, Result, Value};

/// 上游 API 主机（换码 / 续期 / 目录 / 对话 / 积分 / 活动都在它下面）
pub const API_BASE: &str = "https://lobsterai-server.youdao.com";

/// 浏览器登录门户主机（插件**不**向它发请求，只把它的地址交给浏览器）
pub const PORTAL_BASE: &str = "https://lobsterai.youdao.com";

/// 客户端版本查询接口。**这是第三方主机，响应不是业务信封**：版本号在
/// `data.value.version`（参考实现 `lobsterai-product.ts:443` 的说明）。
pub const CLIENT_VERSION_API: &str =
    "https://api-overmind.youdao.com/openapi/get/luna/hardware/lobsterai/prod/update";

/// 查不到版本时用的兜底值
pub const FALLBACK_CLIENT_VERSION: &str = "2026.9.4";

/// `User-Agent`：照抄参考实现，**故意固定**不跟随真实版本
pub const USER_AGENT: &str = "LobsterAI/0.1.0";

/// 声明的客户端能力。两个能力位都是功能性的：
/// `kimi-k3-agentic-v1` 是模型列表的准入门（缺它少一个模型）、
/// `thinking-level-control-v1` 是 `reasoning_effort: "off"` 的前提（缺它 HTTP 500）。
pub const CLIENT_CAPABILITIES: &str = "kimi-k3-agentic-v1,thinking-level-control-v1";

/// 用授权码换令牌（**不带 Authorization**）
pub const EXCHANGE_PATH: &str = "/api/auth/exchange";
/// 续期（**不带 Authorization**）
pub const REFRESH_PATH: &str = "/api/auth/refresh";
/// 模型目录
pub const MODELS_PATH: &str = "/api/models/available";
/// 对话（OpenAI 兼容，SSE only）
pub const CHAT_PATH: &str = "/api/proxy/v1/chat/completions";
/// 登录回调路径（见 `login.rs`：跟随参考实现的裸路径，不加家名后缀）
pub const CALLBACK_PATH: &str = "/auth/callback";
/// 积分余额
pub const PROFILE_SUMMARY_PATH: &str = "/api/user/profile-summary";

/// 每日签到第一步：查活动位
pub const ACTIVITY_SLOT_PATH: &str = "/api/client-activities/slot";
/// 每日签到第二、三步的公共前缀（活动码拼在路径后面）
pub const ACTIVITY_CONTEXT_PATH: &str = "/api/client-activities";

/// 活动位查询的三个固定参数（照抄真实客户端的形态）。
///
/// `platform=win32` 是**按桌面客户端的形态标识**，与运行本网关的宿主系统无关 ——
/// 参考实现特意注明这一点。
pub const SLOT_PLACEMENT: &str = "desktop_sidebar";
/// 见 [`SLOT_PLACEMENT`]
pub const SLOT_CONTAINER_API_VERSION: &str = "2";
/// 见 [`SLOT_PLACEMENT`]
pub const SLOT_PLATFORM: &str = "win32";

/// 一次响应体读取的上限（错误体 / 目录 / 余额都在 1 MiB 以内）。
///
/// 留上限不是为了省内存：上游异常时会回一整页 HTML，没有截断的话一次
/// 「换个账号重试」会把整页拼进错误消息里，日志与客户端都会被淹掉。
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// 极小的 query 转义（本家只有版本号 / 活动码 / 修订版三个值要拼进 URL）。
///
/// 不引依赖：这些值都可能来自上游响应（活动码、configRevision），一旦含
/// `&` / `=` / `?` 就会截断 query，所以必须转义而不是直接拼。
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 对话端点完整 URL
pub fn chat_url() -> String {
    format!("{API_BASE}{CHAT_PATH}")
}

/// 目录端点 URL（`keyfrom` 作为查询串，与参考实现一致）
pub fn models_url(keyfrom: &str) -> String {
    format!("{API_BASE}{MODELS_PATH}?{}", keyfrom.trim())
}

/// 余额端点 URL
pub fn profile_summary_url() -> String {
    format!("{API_BASE}{PROFILE_SUMMARY_PATH}")
}

/// 活动位 URL（三个固定参数）
pub fn activity_slot_url(client_version: &str) -> String {
    format!(
        "{API_BASE}{ACTIVITY_SLOT_PATH}?placement={SLOT_PLACEMENT}&clientVersion={}&containerApiVersion={SLOT_CONTAINER_API_VERSION}&platform={SLOT_PLATFORM}",
        urlencode(client_version),
    )
}

/// 某个活动的上下文 URL
///
/// ⚠️ 末尾那个 `/context` 段不能省：上游的路径是三段式
/// `{code}/context?configRevision=…`，少了它整条请求落到 `/api/client-activities/{code}`
/// 上、直接被回 **HTTP 404**（签到因此稳定失败，报「活动上下文查询返回 HTTP 404」）。
/// 参考实现（Go `fetchActivityContext`、TS `lobsterai-credits.ts`）都是三段式。
pub fn activity_context_url(code: &str, config_revision: &str) -> String {
    format!(
        "{API_BASE}{ACTIVITY_CONTEXT_PATH}/{}/context?configRevision={}",
        urlencode(code),
        urlencode(config_revision),
    )
}

/// 某个活动的 check_in URL
pub fn activity_checkin_url(code: &str) -> String {
    format!(
        "{API_BASE}{ACTIVITY_CONTEXT_PATH}/{}/actions/check_in",
        urlencode(code),
    )
}

/// 把 `(名字, 值)` 列表变成 `http::open` 要的头对象。
pub fn header_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// 一次请求的结果。HTTP 状态本身**不**在这里判成错误 ——
/// 登录换码要按 401/403 说「请重新登录」，目录要按 5xx 说「上游故障」，
/// 两条口径不同，判定交给各自的调用点。
pub struct Reply {
    /// 上游 HTTP 状态码
    pub status: u16,
    /// 响应体原文（已按上限截断）
    pub body: String,
}

impl Reply {
    /// 2xx 判定
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// 把响应体当 JSON 解析（不是 JSON 时给 `None`，由调用点决定文案）
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// 发一次请求（`GET` / `POST`），把结果原样交给调用点。
///
/// ── 为什么这里不判状态码 ────────────────────────────────────
/// 见 [`Reply`] 的注释。真正的分类在 `errors.rs`，登录链在 `oauth.rs`。
///
/// 网络层失败归一成 502（「上游没答」）：宿主拿去当插件失败处理，不会再
/// 换账号 —— 连通性问题上换账号没有意义。
pub fn send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
    limit: usize,
) -> Result<Reply> {
    let mut response = http::open(method, url, header_object(headers), body)
        .map_err(|error| Error::http(502, format!("LobsterAI 请求发不出去：{}", error.message)))?;
    let status = response.status;
    let body = read_limited(&mut response, limit);
    Ok(Reply { status, body })
}

/// 读响应体，最多 `limit` 字节（超出部分丢弃而不是报错：我们只要错误原文
/// 的前一段，报错会把「上游 500」变成「读回应失败」）。
pub fn read_limited(response: &mut http::Response, limit: usize) -> String {
    let mut output: Vec<u8> = Vec::new();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(output.len());
                if room == 0 {
                    break;
                }
                output.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) => break,
            // 读到一半断了：已有字节仍然有用（错误体通常是完整的前半段），
            // 把「读失败」变成「读到这些」比丢掉更可诊断。
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_matches_rfc3986_unreserved() {
        // 未保留字符原样、其余按 %XX 大写（与 `endpoints::urlencode` 逐字一致）
        assert_eq!(urlencode("2026.9.4"), "2026.9.4");
        assert_eq!(urlencode("a b&c=d?e"), "a%20b%26c%3Dd%3Fe");
        assert_eq!(urlencode("中文"), "%E4%B8%AD%E6%96%87");
        assert_eq!(urlencode(""), "");
    }

    #[test]
    fn activity_urls_keep_the_three_segment_shape() {
        // 少了 `/context` 会稳定 404（见函数注释）
        let context = activity_context_url("daily", "7");
        assert!(context.ends_with("/api/client-activities/daily/context?configRevision=7"));
        let checkin = activity_checkin_url("daily");
        assert!(checkin.ends_with("/api/client-activities/daily/actions/check_in"));
        // 活动码里的 `&` 必须被转义，否则 query 被截断
        assert!(activity_context_url("a&b", "1").contains("a%26b/context"));
    }

    #[test]
    fn slot_url_carries_the_three_fixed_params() {
        let url = activity_slot_url("2026.9.4");
        assert!(url.contains("placement=desktop_sidebar"));
        assert!(url.contains("clientVersion=2026.9.4"));
        assert!(url.contains("containerApiVersion=2"));
        assert!(url.contains("platform=win32"));
    }
}
