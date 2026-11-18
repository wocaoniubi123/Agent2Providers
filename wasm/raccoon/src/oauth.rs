//! 小浣熊**网页登录**（`office-raccoon://` 授权码换凭证）。
//!
//! 移植来源：源项目的 `raccoon-oauth.mjs`（`buildRaccoonAuthorizeUrl` /
//! `isRaccoonAuthCallbackUrl` / `parseRaccoonAuthCallback` /
//! `exchangeRaccoonAuthorizationCode`）。协议本身很短：
//!
//! ```text
//! ① 打开 {mainOrigin}/authorize?login_source=desktop&appname=<客户端名>&state=<state>
//! ② 用户登录成功 → 官方页面跳转 office-raccoon://auth/callback?code=…&state=…
//! ③ POST {authApiBase}/login_with_authorization_code  body {"authorization_code": code}
//!      → data.access_token / data.refresh_token / data.office_* （code 200035 = 授权码已失效）
//! ```
//!
//! ── 为什么 state 必须在这里生成、且回调时逐字比对 ────────────
//! `state` 是**一次性随机串**，它回答的是「这次带着 code 跳回来的页面，是不是
//! 由本次登录刚刚发起的那一次」。回调落在自定义协议上，任何本机程序都能构造
//! 一个 `office-raccoon://auth/callback?code=…&state=…` 丢进登录窗口，因此
//! 不校验 state 就等于把「用别人的 code 换来的凭证写进你的账号库」这条口子
//! 敞开着（换来的凭证指向谁，取决于别人手里的 code）。源实现同样逐字比对。
//!
//! ── state 的熵源（wasm 侧的唯一降级，明写在这里）─────────────
//! native 侧用 `ids::uuid_v4()`（混入 `RandomState` 的随机种子 + 单调计数 +
//! 纳秒时间戳）。wasm32-unknown-unknown 上**没有任何随机源**（SDK 不暴露
//! `random`），只能拿宿主时钟（毫秒）与账号上下文做 SHA-256 派生。因此这一次
//! 迁移里 state 的可预测性弱于 native：它仍然一次性、仍然要过逐字比对，
//! 但**不再具备密码学随机性**。需要恢复时由宿主提供随机源是最短路径。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件在登录链路上，绝不 unwrap/expect/panic：取值走 Option 链与 `unwrap_or`，
//! 所有失败都转成中文错误。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};
use sha2::{Digest, Sha256};

use crate::{jwt, upstream};

/// 授权页路径（源实现 `new URL('/code/authorize', mainOrigin)` 的实际取值）
const AUTHORIZE_PATH: &str = "/authorize";

/// 登录来源标记：官方页面据此走「桌面端登录」分支（源实现固定 `desktop`）
const LOGIN_SOURCE: &str = "desktop";

/// 申请授权时上报的客户端名（源实现 `DEFAULT_APP_NAME`）
const APP_NAME: &str = "办公小浣熊客户端";

/// 回调的协议 / host / 路径（源实现 `isRaccoonAuthCallbackUrl` 的三个判据）。
///
/// 官方登录成功后**固定**跳这个形态，不能改：它就是小浣熊发起登录时登记的
/// 回调地址，改了官方页面就不会带 code 回来。
const CALLBACK_SCHEME: &str = "office-raccoon";
const CALLBACK_HOST: &str = "auth";
const CALLBACK_PATH: &str = "/callback";

/// state 长度上限（源实现 `MAX_STATE_LENGTH`）：超长一律拒绝，不截断 ——
/// 被截断的 state 已经不可能与发起时一致，报错比默默比对失败更清楚。
const MAX_STATE_LENGTH: usize = 512;

/// 授权码长度上限（源实现 `MAX_CODE_LENGTH`）
const MAX_CODE_LENGTH: usize = 8192;

/// 授权码已失效的上游业务码（源实现 `payload.code === 200035`）。
/// 它值得单独识别：这不是「登录服务坏了」，而是「用户把回调链接放太久、
/// 或者重复点了两次」，文案必须告诉用户重新发起，而不是让他等我们重试。
const CODE_EXPIRED: i64 = 200_035;

/// 主站 Origin（源实现 `mainOrigin`：配置 `mainSite` 可覆盖）。
///
/// 默认与鉴权 API 同一个站点 —— 两者在生产上就是同一个域，所以这里不重复写
/// 一遍字面量，避免将来换域名时漏改一处。
fn main_origin() -> String {
    upstream::main_site()
}

/// 构造授权地址（源实现 `buildRaccoonAuthorizeUrl`）。
///
/// ── 为什么逐个参数百分号编码 ────────────────────────────────
/// `appname` 是中文、`state` 是十六进制串，两者都必须正确编码；手拼一个 `&`
/// 或空格就会让官方页面拿到半个参数。`crate::url::encode` 的口径与 `url` crate
/// 的 form-urlencoded 序列化一致（见那里的说明）。
pub fn build_authorize_url(state: &str) -> String {
    let origin = main_origin();
    let parts = crate::url::split(&origin);
    let query = format!(
        "login_source={}&appname={}&state={}",
        crate::url::encode(LOGIN_SOURCE),
        crate::url::encode(APP_NAME),
        crate::url::encode(state),
    );
    if parts.scheme.is_empty() || parts.host.is_empty() {
        // origin 不可解析（用户把 `mainSite` 配成了非法值）：退回到「把路径拼在
        // 后面」的形态，让请求去打上游、由传输层报出可读错误 —— 与 native
        // 「不在这里返回错误」同一取舍（配置错在 HTTP 层比在这里更早暴露）。
        return format!("{origin}{AUTHORIZE_PATH}?{query}");
    }
    format!("{}://{}{AUTHORIZE_PATH}?{query}", parts.scheme, parts.host)
}

/// 生成一次登录的 `state`（理由与降级见模块头）。
pub fn new_login_state() -> String {
    let mut hash = Sha256::new();
    hash.update(b"raccoon-login-state");
    hash.update(sdk::now().to_string().as_bytes());
    hash.update(upstream::auth_api_base().as_bytes());
    hash.update(upstream::main_site().as_bytes());
    format!("{:x}", hash.finalize())
}

/// 回调地址 → 授权码（源实现 `isRaccoonAuthCallbackUrl` + `parseRaccoonAuthCallback`）。
///
/// ── 逐项比对而不是前缀匹配（安全）────────────────────────────
/// `office-raccoon://auth/callback@evil.com?…`、`office-raccoon://auth/callback.evil`
/// 这类字符串用 `starts_with` 判会全部放行。这里拆开后逐项比对 scheme / host /
/// path —— 与源实现 `new URL()` + 三个等值判断同一口径。
/// 注意自定义协议下 `//auth/callback` 的 `auth` 是 host，path 则是 `/callback`。
pub fn parse_callback_code(raw_url: &str, expected_state: &str) -> Result<String> {
    let parts = crate::url::split(raw_url.trim());
    if parts.scheme.is_empty() || parts.host.is_empty() {
        return Err(Error::http(400, "登录回调地址无效"));
    }
    // host 用**不区分大小写**比对：自定义协议不像 http(s) 那样被规范化成小写，
    // `office-raccoon://AUTH/callback` 会原样保留大小写。scheme 由解析器保证
    // 小写，path 保持精确（官方给的固定形态）。
    let host_matches = parts.host.eq_ignore_ascii_case(CALLBACK_HOST);
    if parts.scheme != CALLBACK_SCHEME || !host_matches || parts.path != CALLBACK_PATH {
        return Err(Error::http(400, "登录回调地址无效"));
    }
    let code = crate::url::query_param(&parts.query, "code");
    if code.is_empty() {
        return Err(Error::http(400, "登录回调里没有授权码"));
    }
    if code.chars().count() > MAX_CODE_LENGTH {
        return Err(Error::http(400, "授权码过长"));
    }
    let state = crate::url::query_param(&parts.query, "state");
    if state.is_empty() {
        return Err(Error::http(
            400,
            "登录回调里没有 state，无法确认这次登录由本机发起，请重新发起网页登录",
        ));
    }
    if state.chars().count() > MAX_STATE_LENGTH {
        return Err(Error::http(400, "登录回调 state 过长"));
    }
    if state != expected_state {
        return Err(Error::http(400, "登录回调 state 校验失败，请重新发起登录"));
    }
    Ok(code)
}

/// 用一次性授权码换凭证，返回一条可落库的账号
/// （源实现 `exchangeRaccoonAuthorizationCode` + 路由里的 `store.addAccount`）。
///
/// ── 错误语义 ────────────────────────────────────────────────
/// 传输失败 → 502（native 的超时分支给 504，wasm 分不出超时）；
/// 授权码失效（200035）→ **400** 且文案要求重新发起；上游 4xx → 原样透出该
/// 状态码（多半是 code 不合法）；其余 → 502。
pub fn exchange_code(code: &str, state: &str) -> Result<Value> {
    let code = code.trim();
    if code.is_empty() {
        return Err(Error::http(400, "缺少授权码"));
    }
    if code.chars().count() > MAX_CODE_LENGTH {
        return Err(Error::http(400, "授权码过长"));
    }
    // state 在这里再校验一次（深度防御）：调用链上游（登录接口）已比对过，
    // 但「这个 state 该长什么样」只有实现知道，多一道不会有代价。
    if state.trim().is_empty() {
        return Err(Error::http(400, "缺少登录 state"));
    }

    let url = format!(
        "{}/login_with_authorization_code",
        upstream::auth_api_base()
    );
    let body = json!({ "authorization_code": code });
    let headers: Vec<(String, String)> =
        vec![("Content-Type".to_string(), "application/json".to_string())];
    let response = upstream::send("POST", &url, &headers, Some(&body))
        .map_err(|error| upstream::transport("网页登录换取凭证失败", error))?;

    let payload = response.payload;
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let text_of = |key: &str| -> String {
        data.get(key)
            .map(jwt::js_text)
            .map(|text| jwt::strip_bearer(&text))
            .unwrap_or_default()
    };
    let access_token = text_of("access_token");
    let refresh_token = text_of("refresh_token");
    let upstream_code = payload.get("code").and_then(Value::as_i64);
    if upstream_code == Some(CODE_EXPIRED) {
        return Err(with_code(
            Error::http(400, "授权码已失效，请重新发起网页登录"),
            upstream_code,
        ));
    }
    let iam = jwt::is_iam_token(&access_token);
    if !response.ok
        || upstream_code != Some(0)
        || access_token.is_empty()
        || (!iam && refresh_token.is_empty())
    {
        let message = payload
            .get("message")
            .or_else(|| payload.get("msg"))
            .map(jwt::js_text)
            .filter(|text| !text.is_empty());
        let message = match message.as_deref() {
            // 上游把「内部异常」原样回下来，这句话对用户没有信息量
            Some("internal_server_error") => "登录服务异常，请稍后重试".to_string(),
            Some(text) => text.to_string(),
            None => format!("网页登录换取凭证失败（HTTP {}）", response.status),
        };
        let status = if (400..500).contains(&response.status) {
            response.status
        } else {
            502
        };
        return Err(with_code(Error::http(status, message), upstream_code));
    }

    // 折成「一条可落库的账号」：id 由 userId 推导（`user-<userId>`，与内置版
    // `add_raccoon_account` 的 id 形态逐字相同 —— 同一账号重新登录会被识别成
    // 更新而不是新增）。office_* 用上游返回的下划线键名。
    let profile = if iam {
        Some(crate::iam::user_info(&access_token)?)
    } else {
        None
    };
    let claims = jwt::decode_jwt_claims(&access_token);
    let user_id = profile
        .as_ref()
        .and_then(|profile| profile.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            claims
                .as_ref()
                .map(jwt::extract_user_id)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let mut secret = serde_json::Map::new();
    secret.insert(
        "accessToken".to_string(),
        Value::String(access_token.clone()),
    );
    if !iam {
        secret.insert("refreshToken".to_string(), Value::String(refresh_token));
    }
    secret.insert("userId".to_string(), Value::String(user_id.clone()));
    if let Some(expires_at) = jwt::jwt_expiry_ms(&access_token) {
        secret.insert("expiresAt".to_string(), Value::from(expires_at));
    }
    for key in ["office_identity", "office_org_name", "office_org_role"] {
        let value = data
            .get(key)
            .filter(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()))
            .or_else(|| profile.as_ref().and_then(|profile| profile.get(key)))
            .map(jwt::js_text)
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        if !value.is_empty() {
            secret.insert(key.to_string(), Value::String(value));
        }
    }
    if !secret.contains_key("office_identity") && iam {
        secret.insert(
            "office_identity".to_string(),
            Value::String("personal".to_string()),
        );
    }
    let display = profile
        .as_ref()
        .and_then(|profile| profile.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            claims
                .as_ref()
                .map(jwt::display_name)
                .unwrap_or_default()
        });
    let name = if display.trim().is_empty() {
        format!("账号 {user_id}")
    } else {
        display
    };
    let secret = Value::Object(secret);
    let public = crate::account::account_view(&secret, &name);
    Ok(json!({
        "public": public,
        "secret": secret,
        "identity": format!("user-{user_id}"),
        "desktop": false,
    }))
}

fn with_code(mut error: Error, code: Option<i64>) -> Error {
    error.upstream_code = code;
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "0123456789abcdef";

    #[test]
    fn authorize_url_carries_encoded_parameters() {
        // 没有设置时用默认 origin（`settings.get` 在非 wasm 目标上返回错误，
        // 走的就是「配置缺失」那条分支，正好覆盖默认值）。
        let url = build_authorize_url(STATE);
        assert!(url.starts_with("https://xiaohuanxiong.com/authorize?"), "{url}");
        assert!(url.contains("login_source=desktop"), "{url}");
        // 客户端名是中文，必须被百分号编码（不能原样出现）
        assert!(url.contains("appname=%E5%8A%9E%E5%85%AC%E5%B0%8F%E6%B5%A3%E7%86%8A"), "{url}");
        assert!(url.contains(&format!("state={STATE}")), "{url}");
    }

    #[test]
    fn callback_accepts_the_official_shape() {
        let url = format!("office-raccoon://auth/callback?code=abc123&state={STATE}");
        assert_eq!(parse_callback_code(&url, STATE).unwrap_or_default(), "abc123");
    }

    #[test]
    fn callback_rejects_spoofed_shapes() {
        // scheme 不对
        let url = format!("https://auth/callback?code=abc&state={STATE}");
        assert!(parse_callback_code(&url, STATE).is_err());
        // host 被换掉
        let url = format!("office-raccoon://evil.com/callback?code=abc&state={STATE}");
        assert!(parse_callback_code(&url, STATE).is_err());
        // path 尾巴上挂域名（前缀匹配会放行，逐项比对不会）
        let url = format!("office-raccoon://auth/callback@evil.com?code=abc&state={STATE}");
        assert!(parse_callback_code(&url, STATE).is_err());
        // state 不一致
        let url = "office-raccoon://auth/callback?code=abc&state=other";
        assert!(parse_callback_code(url, STATE).is_err());
        // 没有 code
        let url = format!("office-raccoon://auth/callback?state={STATE}");
        assert!(parse_callback_code(&url, STATE).is_err());
    }

    #[test]
    fn callback_host_compare_is_case_insensitive() {
        let url = format!("office-raccoon://AUTH/callback?code=abc&state={STATE}");
        assert_eq!(parse_callback_code(&url, STATE).unwrap_or_default(), "abc");
    }
}
