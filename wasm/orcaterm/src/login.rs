//! OrcaTerm 登录：官方 OAuth 链路（微信扫码 → 回调 → 换令牌）。
//!
//! ── 链路（2026-10-17 实测）────────────────────────────────
//!   1. 打开 `https://orcaterm.com/oauth/authorize?provider=wechat&source=desktop
//!      &session_id=<uuid>&return_url=orcaterm://oauth_callback` —— 该页
//!      **302 直达**微信二维码，不需要点按钮；
//!   2. 用户扫码；上游把浏览器重定向到 `return_url` 并带上 `session_id`；
//!   3. 网关把回调 URL 交给 `login.callback`，本模块用 `OAuthExchangeToken`
//!      换令牌（该 CGI 动作**匿名可调**，凭据就是那个一次性 `session_id`）。
//!
//! ── 与「回调带 code」的家不同 ───────────────────────────────
//! 这里的回调 URL 只带 `session_id`（我们自己生成的 UUID，既是 CSRF 凭据
//! 也是换令牌的入参）。所以 [`start`] 生成的 `flow` 与 URL 里的
//! `session_id` 是**同一个值** —— 回调侧只能看到 URL 里那个，两者分开就要
//! 在插件里再存一份映射表（而它们本来就一一对应）。
//!
//! ── wasm 侧与 native 的一处差别 ─────────────────────────────
//! native 的 `login_start("desktop")` 返回一条「空 flow」的启动结果，由网关接着
//! 调 `normalize(Desktop)` 去读 `%APPDATA%`。wasm 沙箱没有文件系统，这条入口在
//! 这里就回一句可读错误 —— 比让用户走完一轮再在 `normalize` 里失败更清楚。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, codec, upstream};

/// 回调地址（自定义协议）。上游把登录成功后的浏览器重定向到它。
pub const CALLBACK_URL: &str = "orcaterm://oauth_callback";

/// 回调 URL 里承载一次性凭据的参数名。
pub const CALLBACK_QUERY_KEY: &str = "session_id";

/// 登录窗口需要放行的域（网关据此做导航白名单）。
pub const ALLOWED_HOSTS: &[&str] = &["orcaterm.com", "open.weixin.qq.com", "wx.qq.com"];

/// 授权页。
const AUTH_PAGE: &str = "https://orcaterm.com/oauth/authorize";

/// 生成登录 state / OAuth session_id（**必须是合法 UUID**）。
///
/// 实测上游对 `sessionId` 做格式校验，非 UUID 直接回
/// `api-params-verify-fail: sessionId must be a UUID`。
pub fn new_state() -> String {
    codec::uuid_v4()
}

/// 授权页地址（`session_id` 进 query，`return_url` 做最小转义）。
pub fn build_url(state: &str) -> String {
    format!(
        "{AUTH_PAGE}?provider=wechat&source=desktop&session_id={state}&return_url={}",
        encode(CALLBACK_URL)
    )
}

/// 最小 URL 编码（`return_url` 的取值里只有这几个字符需要转义）。
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            other => out.push(other),
        }
    }
    out
}

/// 从回调 URL 里取出 `session_id`。
pub fn callback_session_id(callback_url: &str) -> Option<String> {
    let query = callback_url.split_once('?')?.1;
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else { continue };
        if key == CALLBACK_QUERY_KEY && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// `admin.action = auth.methods`：添加账号弹窗里的登录方式。
///
/// ── 为什么是这份形状 ────────────────────────────────────────
/// wasm 包的登录方式走**动态契约**：网关 `api/session.rs::read_login_methods`
/// 把这条 `admin.action` 的结果按 `LoginMethodsMetadata` 反序列化，每条的 `type`
/// 只能是 `oauth` / `api` / `sms` / `desktop`，`methodIndex` 必须唯一。回
/// `metadata.json` 那份 native 静态形态（`kind:"browser"`）会直接 502
/// 「插件返回的登录方式元数据无法解析」，添加账号面板整个打不开。
///
/// ── 条目按 `metadata.json` 的 `login_methods` 顺序映射 ───────────
///   - 0 号 `api`：粘贴 accessToken。`prompts[].key` 取 `accessToken` ——
///     `account::normalize` 的 `pick_token_payload` 首选就是这个键，键名对不上
///     会报「缺少令牌」。
///   - 1 号 `oauth`：微信扫码（回调型，见 `start`）。
///
/// ── 为什么没有 native 的第三条「导入本机登录态」 ─────────────────
/// wasm 沙箱没有文件系统，`desktop` 这条点下去只能失败；本包的 `wasm.json`
/// 也没有声明 `desktop.credentials.v1`（网关 `session.rs` 对 wasm 的 desktop
/// 有硬校验，缺能力位一律 502）。文件导入由 `account.normalize` 的
/// `file_text` / `file_base64` 承担，不需要在这份清单里出现。
///
/// 文案只维护简体中文一套；`locale` 由网关传入，补多语言时在这里分叉即可。
pub fn methods(_locale: &str) -> Value {
    json!({ "methods": [
        { "methodIndex": 0, "type": "api", "label": "accessToken",
          "prompts": [
            { "key": "accessToken", "type": "text", "label": "accessToken",
              "placeholder": "粘贴 OrcaTerm 的 JWT，或整个 data.bin 的内容", "secret": true }
          ],
          "instructions": "粘贴 OrcaTerm 的 JWT，或整个 data.bin 的内容" },
        { "methodIndex": 1, "type": "oauth", "label": "微信扫码登录", "prompts": [],
          "browserMode": "choice",
          "instructions": "打开 OrcaTerm 授权页，扫码后自动回填账号" }
    ] })
}

/// `login.start`：只生成授权地址（回调型流程，不轮询）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"]
        .as_str()
        .or_else(|| params["kind"].as_str())
        .unwrap_or("browser");
    match method {
        // 「浏览器登录」是回调型：网关打开 URL，等用户完成后调 login.callback
        "" | "browser" | "web" | "oauth" => {
            let state = new_state();
            Ok(json!({
                // flow 与 URL 里的 session_id 是同一个值（见模块头）
                "flow": state,
                "url": build_url(&state),
                "instructions": "用微信扫码完成登录；扫码成功后会自动回到应用",
                // 0 = 回调型：网关不轮询，等用户完成登录后把回调 URL 交回 login.callback
                "poll_interval_ms": 0,
                // 微信登录页偶尔会拒绝 WebView —— 交给系统浏览器更稳
                "external_browser": true,
                "allowed_hosts": ALLOWED_HOSTS,
            }))
        }
        "desktop" => Err(Error::http(
            400,
            "Wasm 插件读不到本机登录态文件（宿主沙箱里没有文件系统）。\
             请在 %APPDATA%\\com.orcaterm-desktop.app\\data.bin 上点「文件导入」，\
             或直接粘贴 accessToken",
        )),
        other => {
            // 粘贴令牌也是登录入口之一：`payload.token` 里有值就直接告诉用户走哪条路
            let token = params["payload"]["token"].as_str().unwrap_or("");
            if token.trim().is_empty() {
                return Err(Error::http(400, format!("OrcaTerm 不支持这种登录方式（{other}）")));
            }
            Err(Error::http(400, "OrcaTerm 的粘贴登录请用「添加账号」，不需要走登录流程"))
        }
    }
}

/// `login.poll`：本家是回调型（`poll_interval_ms = 0`），网关不会来问。
///
/// 仍然实现它，是因为「被问到」时回一句 pending 比抛 unsupported 更无害：
/// 抛错会让网关把整轮登录标成失败。
pub fn poll(params: &Value) -> Result<Value> {
    let _ = params;
    Ok(json!({ "state": "pending", "hint": "等待你在浏览器里完成扫码登录" }))
}

/// `login.cancel`：本家没有需要释放的资源（授权在浏览器里），回答成功即可。
pub fn cancel(params: &Value) -> Result<Value> {
    let _ = params;
    Ok(Value::Null)
}

/// `login.callback`：用 `session_id` 换令牌并产出账号。
pub fn callback(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("").trim();
    let url = params["url"].as_str().unwrap_or("");
    let code = params["code"].as_str().unwrap_or("");
    // 回调 URL 里可能带 session_id（壳侧把整条 URL 交回来），也可能只有 code
    let session_id = callback_session_id(url)
        .or_else(|| callback_session_id(code))
        .unwrap_or_else(|| code.trim().to_string());
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Ok(failed("回调里没有 session_id，无法换取登录态"));
    }
    // 逐字比对发起时那个 flow（深度防御：上游已校验过 state，但「只有本模块
    // 知道该长什么样」的校验放在这里最可靠）。
    if !flow.is_empty() && session_id != flow {
        return Ok(failed("回调的 session_id 与本次登录不匹配，请重新发起网页登录"));
    }
    match exchange_session(session_id) {
        Ok(credentials) => Ok(json!({
            "state": "done",
            "account": account::account_of(&credentials),
        })),
        Err(error) => Ok(failed(error.message)),
    }
}

fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}

/// 用一次性 `session_id` 换令牌，并探活补齐身份。
///
/// ── 为什么敢匿名调 ──────────────────────────────────────────
/// 实测该动作匿名可调，凭据就是 `session_id` 本身（一次性、由本进程生成、
/// 只出现在我们自己窗口的 URL 里）—— 安全性由「不可预测 + 一次性」承担。
fn exchange_session(session_id: &str) -> Result<account::Credentials> {
    let response = upstream::cgi_action_anonymous(
        "OAuthExchangeToken",
        json!({ "sessionId": session_id }),
    )
    .map_err(|error| {
        Error::http(
            error.status.unwrap_or(502),
            format!("OrcaTerm 换取登录态失败：{}（{}）", error.message, upstream::CGI_BASE),
        )
    })?;
    if let Some(error) = response.get("Error") {
        let code = error["Code"].as_str().unwrap_or("UNKNOWN");
        let message = error["Message"].as_str().unwrap_or("上游错误");
        // 会话过期是用户可行动的错误（重新扫一次），给一句更直白的文案
        if code == "TOKEN_EXPIRED" {
            return Err(Error::http(
                400,
                "OrcaTerm 登录会话已过期（扫码可能没完成或等待过久），请重新发起网页登录",
            ));
        }
        return Err(Error::http(
            502,
            format!("OrcaTerm 换取登录态失败（{code}：{message}）"),
        ));
    }
    let token = account::normalize_token(
        response["AccessToken"]
            .as_str()
            .or_else(|| response["accessToken"].as_str())
            .unwrap_or(""),
    );
    if token.split('.').count() != 3 {
        return Err(Error::http(
            502,
            "OrcaTerm 换回来的登录态不是有效令牌（JWT 应为三段点分），请重试",
        ));
    }
    let mut parsed = account::credentials_from_payload(&Value::String(token.clone()))?;
    parsed.access_token = token;
    // 探活补齐身份：落账号要用 nickname / user_id，且探活能兜住「铸造成功
    // 但账号被冻结」这类边缘情形（与粘贴入口同一口径）。
    let (user_id, nickname) = upstream::fetch_user_info(&parsed)?;
    if parsed.user_id.is_empty() {
        parsed.user_id = user_id;
    }
    if parsed.nickname.is_empty() {
        parsed.nickname = nickname;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_uuid_shaped() {
        let state = new_state();
        assert_eq!(state.len(), 36);
        assert_eq!(state.split('-').count(), 5);
    }

    #[test]
    fn url_carries_state_and_escaped_return_url() {
        let state = new_state();
        let url = build_url(&state);
        assert!(url.starts_with(AUTH_PAGE), "{url}");
        assert!(url.contains(&format!("session_id={state}")), "{url}");
        assert!(url.contains("return_url=orcaterm%3A%2F%2Foauth_callback"), "{url}");
        assert!(url.contains("provider=wechat"), "{url}");
    }

    #[test]
    fn extracts_session_id_from_callback() {
        assert_eq!(
            callback_session_id("orcaterm://oauth_callback?session_id=abc-123"),
            Some("abc-123".to_string())
        );
        assert_eq!(
            callback_session_id("orcaterm://oauth_callback?code=x&session_id=abc-123"),
            Some("abc-123".to_string())
        );
        // 空值不算（上游未登录成功时会回一个空 session_id）
        assert_eq!(callback_session_id("orcaterm://oauth_callback?session_id="), None);
        assert_eq!(callback_session_id("orcaterm://oauth_callback"), None);
    }

    #[test]
    fn desktop_is_rejected_with_readable_message() {
        let error = start(&json!({ "method": "desktop" })).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
    }

    #[test]
    fn browser_start_is_callback_style() {
        let value = start(&json!({ "method": "browser" })).unwrap_or(Value::Null);
        assert_eq!(value["poll_interval_ms"], json!(0));
        assert_eq!(value["external_browser"], json!(true));
        assert_eq!(value["allowed_hosts"].as_array().map(Vec::len), Some(3));
        assert_eq!(value["flow"].as_str().map(str::len), Some(36));
    }
}
