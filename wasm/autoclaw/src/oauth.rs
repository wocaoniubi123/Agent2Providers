//! AutoClaw **国际版**的 OAuth 网页登录（Zai / Google）两跳。
//!
//! ── 协议（三步，实测）───────────────────────────────────────
//! ```text
//! ① POST {intl}/userapi/overseasv1/oauth-captcha-config   {}
//!      → data {enabled, region, prefix, scene_id, captcha_supplier}
//!      ★ 这就是「这个构建要不要走 OAuth」的开关：国内版返回 enabled:false。
//! ② POST {intl}/userapi/overseasv1/{zai|google}-oauth-url
//!      {source_id, device_id, navigate_uri, ali_captcha_verify_param}
//!      → data.oauth_url（官方登录页）
//! ③ 浏览器在登录页完成登录 → 302 到 {navigate_uri}?code=…&state=…
//!    POST {intl}/userapi/overseasv1/{zai|google}-oauth-login
//!      {source_id, device_id, code, state, navigate_uri}
//!      → data {access_token, refresh_token, user_id, user_name, first_login}
//! ```
//!
//! ── 卡点：第 ② 步强制要求阿里云风控验证码 ────────────────────
//! 不带 `ali_captcha_verify_param` 得到 `631002 当前版本已停止服务`（一个与真实
//! 原因无关的误导码）；带假值得到 `630014 审核失败`。验证码是**浏览器端 JS SDK**，
//! 复刻算法成本高且会随上游更新失效 —— 因此不复刻，而是让插件**接收**前端跑完
//! SDK 得到的那个不透明字符串并原样转交（`login.oauth-start` 的
//! `captchaVerifyParam`）。第 ③ 步不需要验证码（用假 code 打 `zai-oauth-login`
//! 得到 `631001 User login error` 而不是 630014），所以换码可以完全在插件里做。
//!
//! ── navigate_uri 必须长成客户端那样（别改）─────────────────────
//! Zai 的 OAuth 服务按 client 登记的白名单逐字校验 `redirect_uri`：名单里只有
//! 官方客户端那四个 loopback 端口上的 `http://localhost:<端口>/auth/callback-zai`。
//! 端口不是那四个之一、host 写成 `127.0.0.1`、路径不对 —— 一律被拒，窗口里直接
//! 渲染 `{"detail":"Redirect URI not registered for this client"}`。
//! **Google 是另一套规则**（RFC 8252 的 loopback 宽松匹配，端口任意），所以同一
//! 份代码「谷歌能登、Zai 登不上」。
//!
//! ── 安全 ────────────────────────────────────────────────────
//! 回调地址不会被真的访问（插件没有监听器），授权码由用户回填。安全由
//! **一次性授权码**与登录状态表承担：code 一次性、流程必须进行中、换码失败即失败。
//! token 只进账号库，不进日志。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::upstream;

/// 验证码配置（同时是「这个构建要不要走 OAuth」的开关）
pub const CAPTCHA_CONFIG_PATH: &str = "/userapi/overseasv1/oauth-captcha-config";

/// 两个变体（顺序 = 界面上按钮的顺序：Zai 在前，与客户端一致）。
const VENDORS: [&str; 2] = ["zai", "google"];

/// 是不是认识的变体（不认识就**不静默回落到某一个**）。
pub fn is_vendor(name: &str) -> bool {
    VENDORS.contains(&name)
}

/// 界面上那个按钮的名字
fn label(vendor: &str) -> &'static str {
    match vendor {
        "google" => "Google",
        _ => "Zai",
    }
}

/// 取授权地址的端点
fn url_path(vendor: &str) -> &'static str {
    match vendor {
        "google" => "/userapi/overseasv1/google-oauth-url",
        _ => "/userapi/overseasv1/zai-oauth-url",
    }
}

/// 用授权码换凭证的端点
fn login_path(vendor: &str) -> &'static str {
    match vendor {
        "google" => "/userapi/overseasv1/google-oauth-login",
        _ => "/userapi/overseasv1/zai-oauth-login",
    }
}

/// 业务码 → 用户能看懂的原因（OAuth 这条链自己的码表，与短信那条分开）。
pub fn describe_error(code: i64, upstream_msg: &str) -> String {
    match code {
        631_002 => "本次登录缺少风控验证（验证码未通过或已过期），请重新点击登录再试一次".to_string(),
        630_014 => "风控验证未通过，请重新点击登录再试一次".to_string(),
        631_001 => "授权码无效或已过期，请重新点击登录".to_string(),
        400_001 => "请求参数有误（登录链路内部错误，请重试）".to_string(),
        400_002 => "请求签名校验失败（本机时钟可能有偏差），请校准系统时间后重试".to_string(),
        _ => {
            if upstream_msg.trim().is_empty() {
                format!("登录失败（上游 code={code}）")
            } else {
                format!("登录失败：{}", upstream_msg.trim())
            }
        }
    }
}

/// 取 OAuth 授权地址（**需要验证码参数**）。
///
/// 站点由 `region::userapi_base`（进而是 `region::REGION`）决定，这里不重复传。
pub fn request_oauth_url(
    vendor: &str,
    navigate_uri: &str,
    captcha_verify_param: &str,
    device_id: &str,
) -> Result<String> {
    let captcha = captcha_verify_param.trim();
    if captcha.is_empty() {
        // 本地就挡掉：不带它打上游必然得到那条误导性的 631002
        return Err(Error::http(400, "缺少风控验证参数，请先完成验证码"));
    }
    let body = json!({
        "source_id": "autoclaw",
        "device_id": device_id,
        "navigate_uri": navigate_uri,
        "ali_captcha_verify_param": captcha,
    });
    let what = format!("获取 {} 授权地址", label(vendor));
    let payload = upstream::post_anonymous(url_path(vendor), &body, &what)?;
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        let upstream_msg = payload.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(Error::http(400, describe_error(code, upstream_msg)));
    }
    let oauth_url = payload
        .get("data")
        .and_then(|data| data.get("oauth_url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if oauth_url.is_empty() {
        return Err(Error::http(502, "上游没有返回授权地址，请重试"));
    }
    Ok(oauth_url)
}

/// 用回调里的一次性授权码换凭证，返回可落库的扁平凭证（含 user_name）。
pub fn exchange_code(
    vendor: &str,
    code: &str,
    state: &str,
    navigate_uri: &str,
    device_id: &str,
) -> Result<Value> {
    let body = json!({
        "source_id": "autoclaw",
        "device_id": device_id,
        "code": code,
        "state": state,
        "navigate_uri": navigate_uri,
    });
    let what = format!("{} 登录换取凭证", label(vendor));
    let payload = upstream::post_anonymous(login_path(vendor), &body, &what)?;
    let status = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if status != 0 {
        let upstream_msg = payload.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(Error::http(400, describe_error(status, upstream_msg)));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let token = data
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(Error::http(502, "登录成功但上游没有返回 access_token"));
    }
    let refresh_token = data
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let user_name = data
        .get("user_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut credentials = json!({ "token": token, "deviceId": device_id });
    if let Some(object) = credentials.as_object_mut() {
        if !refresh_token.is_empty() {
            object.insert("refreshToken".to_string(), Value::String(refresh_token));
        }
        // 备注名兜底：OAuth 账号有用户名（手机验证码那条没有，用脱敏手机号）
        if !user_name.is_empty() {
            object.insert("userName".to_string(), Value::String(user_name));
        }
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 变体白名单与端点映射：不认识的名字不能被静默当成 zai。
    #[test]
    fn vendors_are_explicit() {
        assert!(is_vendor("zai"));
        assert!(is_vendor("google"));
        assert!(!is_vendor("wechat"));
        assert_eq!("/userapi/overseasv1/zai-oauth-url", url_path("zai"));
        assert_eq!("/userapi/overseasv1/google-oauth-login", login_path("google"));
    }

    /// 缺验证码参数在本地就挡掉（不打上游、不产生误导性的 631002）。
    #[test]
    fn missing_captcha_is_rejected_locally() {
        let error = request_oauth_url("zai", "http://localhost:18432/auth/callback-zai", "  ", "dev")
            .err()
            .unwrap_or_else(Error::unsupported);
        assert_eq!(Some(400), error.status);
        assert!(error.message.contains("风控验证"));
    }
}
