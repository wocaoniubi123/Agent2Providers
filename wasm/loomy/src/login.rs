//! Loomy 手机号验证码登录（**依据客户端实现**：接口从桌面端 `app.asar` 的
//! `electron/xfyun/account-service.js` 读出并逐字核对）。
//!
//! ── 链路（两步，没有窗口、没有轮询）──────────────────────────
//! ```text
//! POST {xfyun}/login/phone/sendMsgCode   {base, param:{ccode, phone, expire:300}}
//!   → data.msgid（验证码会话 id）
//! POST {xfyun}/login/phone/checkCode     {base, param:{ccode, phone, mcode, msgid,
//!                                         expire:1209600}}   ← 14 天
//!   → data.session / data.userid（登录态）
//! ```
//! 两个请求都带 HMAC-SHA1 签名头（见 `sign.rs`）。`base` 信封的字段取自
//! 客户端 `_makeBase()`：`appid=GM3LOOMY`、`modelid="Web"`、`version="1.0.0"`、
//! `devid="web"`、`ua`、`traceid`（随机十六进制）。
//!
//! ── 两套入口共用同一份实现 ──────────────────────────────────
//!   1. **短信面板**（主路径）：主程序按 `login_methods` 的 `sms` 声明渲染表单，
//!      分两步调 `admin.action`：`login.sms.send` / `login.sms.verify`。发码
//!      要把「上游 msgid」留到下一步，而主程序只允许插件经 `ticket` 携带不透明
//!      数据 —— 本插件把 `{msgid, phone}` 塞进 ticket，验证时原样取回。
//!   2. **协议通用形态**：`login.start` 发码、返回 `flow = "msgid|phone"`，
//!      用户在界面上填码后 `login.callback` 拆开继续。`flow` 携带状态而不是让
//!      插件记内存，是因为 Wasm 实例每次调用后销毁，记不住。
//!
//! 两条路都落到 [`send_code`] / [`login_with_code`]，不存在「两套实现」。
//!
//! ── msgid 由前端带回 ───────────────────────────────────────
//! 上游把「刚发的码」绑在发码响应的 msgid 上，登录必须带同一个。插件不替用户
//! 保存这个中间态（一次登录可以跨多次 HTTP 请求、也可以被放弃），回给前端让它
//! 随下一次请求带回是这里最省事又不丢正确性的做法。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{client, credentials, endpoints, ids};

/// 发码路径（客户端 `sendSmsCode`）
const SEND_CODE_PATH: &str = "/login/phone/sendMsgCode";
/// 验证码登录路径（客户端 `loginBySmsCode`）
const LOGIN_PATH: &str = "/login/phone/checkCode";

/// 客户端 `_makeBase()` 的常量：modelid / devid / ua / version
const WEB_MODEL_ID: &str = "Web";
const WEB_DEVICE_ID: &str = "web";
const CLIENT_UA: &str = "Loomy|Desktop|Electron|macOS";
const CLIENT_VERSION: &str = "1.0.0";

/// 短信面板的「多久能重发」（主程序要求 1..=3600 秒）
const RESEND_AFTER_SECONDS: i64 = 60;
/// 短信面板的「验证码多久过期」（上游发码 `expire` 就是 300；主程序要求 30..=900）
const EXPIRES_AFTER_SECONDS: i64 = 300;

/// 中国大陆手机号（与客户端 `sendSmsCode` 的 `^1[3-9]\d{9}$` 同口径，
/// 容忍 `+86` / `86` 前缀与空格、连字符）
pub fn normalize_phone(raw: &str) -> Result<String> {
    let trimmed: String = raw
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect();
    let digits = trimmed.strip_prefix("+86").unwrap_or(&trimmed);
    let digits = digits
        .strip_prefix("86")
        .filter(|rest| rest.len() == 11)
        .unwrap_or(digits);
    if digits.len() == 11
        && digits.starts_with('1')
        && digits
            .chars()
            .nth(1)
            .is_some_and(|ch| ('3'..='9').contains(&ch))
        && digits.chars().all(|ch| ch.is_ascii_digit())
    {
        Ok(digits.to_string())
    } else {
        Err(Error::http(400, "请填写 11 位中国大陆手机号"))
    }
}

/// 6 位数字验证码（客户端把 `mcode` 当字符串传；这里保持字符串形态）
fn normalize_code(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.len() == 6 && trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        Ok(trimmed.to_string())
    } else {
        Err(Error::http(400, "请填写 6 位数字验证码"))
    }
}

/// 请求信封 `base`（客户端 `_makeBase()`：traceid 是随机十六进制）
fn make_base() -> Value {
    json!({
        "appid": endpoints::app_id(),
        "modelid": WEB_MODEL_ID,
        "version": CLIENT_VERSION,
        "devid": WEB_DEVICE_ID,
        "ua": CLIENT_UA,
        "traceid": ids::hex_token(16),
    })
}

/// 业务码 → 用户能看懂的原因（未知码回落到上游文案）。
fn describe_login_error(code: &str, upstream_msg: &str) -> String {
    match code {
        "020002" | "100002" => "登录态已失效，请重新登录".to_string(),
        _ => {
            if upstream_msg.trim().is_empty() {
                format!("登录失败（上游 code={code}）")
            } else {
                format!("登录失败：{}", upstream_msg.trim())
            }
        }
    }
}

/// 从发码响应里取 msgid（上游字段名在不同版本里出现过 msgid / msgId 两种形态，
/// 且可能落在 `data` 或 `data.data` 两层 —— 这里按候选路径逐个试）。
fn extract_msgid(payload: &Value) -> String {
    let candidates = [
        payload.pointer("/data/msgid"),
        payload.pointer("/data/msgId"),
        payload.pointer("/data/data/msgid"),
        payload.pointer("/data/data/msgId"),
    ];
    for value in candidates {
        let text = value.and_then(Value::as_str).unwrap_or("").trim();
        if !text.is_empty() {
            return text.to_string();
        }
    }
    String::new()
}

/// 发送短信验证码。返回 `{msgid}`（调用方决定怎么携带它）。
pub fn send_code(phone: &str) -> Result<Value> {
    let phone = normalize_phone(phone)?;
    let body = json!({
        "base": make_base(),
        "param": { "ccode": "86", "phone": phone, "expire": EXPIRES_AFTER_SECONDS },
    });
    let payload = client::signed_post(SEND_CODE_PATH, &body, "发送验证码")?;
    let code = client::business_code(&payload);
    if code != client::SUCCESS_CODE {
        return Err(Error::http(
            400,
            describe_login_error(&code, &client::upstream_message(&payload)),
        ));
    }
    let msgid = extract_msgid(&payload);
    if msgid.is_empty() {
        return Err(Error::http(
            502,
            "验证码已发出但上游没有返回 msgid，请稍后重试",
        ));
    }
    // 不打手机号（它是个人信息）：日志里只留「发给了尾号」的可核对痕迹，
    // 而 Wasm 插件没有自己的日志通道，这里就完全不播报。
    Ok(json!({ "msgid": msgid }))
}

/// 用手机号 + 验证码登录，返回一份 `NormalizedAccount`
/// （`{secret, public, identity, desktop}`）。
pub fn login_with_code(phone: &str, code: &str, msgid: Option<&str>) -> Result<Value> {
    let phone = normalize_phone(phone)?;
    let code = normalize_code(code)?;
    let msgid = msgid.map(str::trim).filter(|value| !value.is_empty());
    let Some(msgid) = msgid else {
        return Err(Error::http(
            400,
            "缺少 msgid：请先点「发送验证码」，用本次发码返回的 msgid 登录",
        ));
    };
    let body = json!({
        "base": make_base(),
        "param": {
            "ccode": "86",
            "phone": phone,
            "mcode": code,
            "msgid": msgid,
            // 会话 14 天（客户端 loginBySmsCode 的同款取值）
            "expire": 14 * 24 * 3600,
        },
    });
    let payload = client::signed_post(LOGIN_PATH, &body, "登录")?;
    let status = client::business_code(&payload);
    if status != client::SUCCESS_CODE {
        return Err(Error::http(
            400,
            describe_login_error(&status, &client::upstream_message(&payload)),
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let session = data
        .get("session")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if session.is_empty() {
        return Err(Error::http(502, "登录成功但上游没有返回 session"));
    }
    let userid = data
        .get("userid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(credentials::account_bundle(&session, &userid, &phone))
}

// ─── 入口一：短信面板（admin.action）────────────────────────

/// `login.sms.send`：发码，把上游 msgid 编进 `ticket` 交给主程序保管。
///
/// 返回形状由主程序 `login::sms::SendResult` 决定（`status` 只用 `sent`；
/// `captcha` 那一档本家没有对应流程，不提供）。
pub fn sms_send(payload: &Value) -> Result<Value> {
    let phone = normalize_phone(payload["phone"].as_str().unwrap_or(""))?;
    let result = send_code(&phone)?;
    let msgid = result["msgid"].as_str().unwrap_or("").to_string();
    Ok(json!({
        "status": "sent",
        // ticket 是主程序替插件保管的不透明数据：验证码那一步原样回传
        "ticket": { "msgid": msgid, "phone": phone },
        "retryAfterSeconds": RESEND_AFTER_SECONDS,
        "expiresAfterSeconds": EXPIRES_AFTER_SECONDS,
    }))
}

/// `login.sms.verify`：用面板带回的 `ticket`（含 msgid）完成登录。
pub fn sms_verify(payload: &Value) -> Result<Value> {
    let phone = payload["phone"].as_str().unwrap_or("");
    let code = payload["code"].as_str().unwrap_or("");
    let msgid = payload["ticket"]["msgid"]
        .as_str()
        .or_else(|| payload["msgid"].as_str());
    login_with_code(phone, code, msgid)
}

// ─── 入口二：协议通用形态（login.start / login.callback）─────

/// `login.start`：发码，把「msgid + 手机号」编成 `flow` 回给主程序。
///
/// ── 为什么用 `flow` 携带而不是让插件记状态 ──────────────────
/// 一次登录可以跨多次 HTTP 请求、也可以被用户放弃。Wasm 实例每次调用后销毁，
/// 那份内存状态本来就存不住（而用户的表单还开着）。把两段信息编进 `flow`
/// 让这条流程**无状态**：主程序原样带回来，插件就能继续。
///
/// `url` 为空 + `poll_interval_ms = 0`：这是「用户还要填一个码」的流程，
/// 主程序不该开窗口、也不该轮询，等用户提交后走 `login.callback`。
pub fn start(params: &Value) -> Result<Value> {
    let payload = &params["payload"];
    // 主程序按旧契约把 `method` 固定成 "browser"，真正的登录方式在 payload 里；
    // 本家只有手机验证码一条路，有手机号就按发码处理。
    let phone = payload["phone"]
        .as_str()
        .or_else(|| payload["inputs"]["phone"].as_str())
        .unwrap_or("");
    let normalized = normalize_phone(phone)?;
    let result = send_code(&normalized)?;
    let msgid = result["msgid"].as_str().unwrap_or("").to_string();
    if msgid.is_empty() {
        return Err(Error::http(502, "上游没有返回 msgid"));
    }
    Ok(json!({
        // `msgid|phone`：回调时拆开即可，插件不需要记住中间态
        "flow": format!("{msgid}|{normalized}"),
        "url": "",
        "instructions": "填写手机收到的 6 位验证码",
        "poll_interval_ms": 0,
        "external_browser": false,
        "allowed_hosts": [],
    }))
}

/// `login.callback`：用户提交验证码（`flow` 是 `login.start` 给的那串）。
pub fn callback(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("");
    let (msgid, phone) = match flow.split_once('|') {
        Some((msgid, phone)) => (msgid.trim(), phone.trim()),
        None => ("", ""),
    };
    if msgid.is_empty() || phone.is_empty() {
        return Ok(json!({
            "state": "failed",
            "message": "登录会话已失效：请重新获取验证码",
        }));
    }
    // 主程序给的 `code` 优先；有些客户端把整条回调串塞进来，取最后一个
    // `code=` 参数兜底（与 native 的入口口径一致）。
    let mut code = params["code"].as_str().unwrap_or("").trim().to_string();
    if code.is_empty() {
        code = query_param(params["url"].as_str().unwrap_or(""), "code");
    }
    match login_with_code(phone, &code, Some(msgid)) {
        Ok(account) => Ok(json!({ "state": "done", "account": account })),
        Err(error) => Ok(json!({ "state": "failed", "message": error.message })),
    }
}

/// 从 URL 查询串里取一个参数（没有则空串）。
fn query_param(url: &str, key: &str) -> String {
    let Some(query) = url.split_once('?').map(|(_, rest)| rest) else {
        return String::new();
    };
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name == key {
            return value.trim().to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::{normalize_code, normalize_phone, query_param};

    #[test]
    fn phone_accepts_mainland_forms_only() {
        assert_eq!(normalize_phone("13800138000").ok().as_deref(), Some("13800138000"));
        assert_eq!(
            normalize_phone("+86 138-0013-8000").ok().as_deref(),
            Some("13800138000")
        );
        assert_eq!(normalize_phone("8613800138000").ok().as_deref(), Some("13800138000"));
        // 长度不对 / 号段不对 / 含字母 / 位数被 +86 骗过
        assert!(normalize_phone("1380013800").is_err());
        assert!(normalize_phone("12800138000").is_err());
        assert!(normalize_phone("1380013800a").is_err());
        assert!(normalize_phone("").is_err());
    }

    #[test]
    fn code_must_be_six_digits() {
        assert_eq!(normalize_code(" 123456 ").ok().as_deref(), Some("123456"));
        assert!(normalize_code("12345").is_err());
        assert!(normalize_code("12345a").is_err());
    }

    #[test]
    fn query_param_reads_last_segment_safely() {
        assert_eq!(query_param("https://x/cb?code=654321&state=s", "code"), "654321");
        assert_eq!(query_param("https://x/cb", "code"), "");
        assert_eq!(query_param("https://x/cb?state=s", "code"), "");
    }
}

// ─── 登录方式声明（admin.action: auth.methods）──────────────

/// 动态登录方式（主程序按这个渲染短信表单）。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 主程序对 `kind = sms` 的方式要求 `sms` 配置块（区号、手机号/验证码长度、
/// 重发冷却与有效期），而这些是**本家自己的规矩**（客户端 `^1[3-9]\d{9}$`
/// 与 6 位码）。硬编码在主程序里就得为每家改一次网关。
pub fn methods(locale: &str) -> Value {
    let (label, instructions, phone_label, phone_placeholder, country_label) = match locale {
        "en" => (
            "SMS sign-in",
            "Fill in the phone number, then the 6-digit SMS code",
            "Phone number",
            "11-digit mainland China mobile number",
            "Mainland China",
        ),
        "zh-Hant" => (
            "手機驗證碼登入",
            "填寫手機號，再填收到的 6 位驗證碼",
            "手機號",
            "11 位中國大陸手機號",
            "中國大陸",
        ),
        _ => (
            "手机验证码登录",
            "填写手机号，再填收到的 6 位验证码",
            "手机号",
            "11 位中国大陆手机号",
            "中国大陆",
        ),
    };
    json!({
        "methods": [{
            "methodIndex": 0,
            "type": "sms",
            "label": label,
            "instructions": instructions,
            "prompts": [],
            "manualCallback": false,
            "browserMode": "none",
            "sms": {
                "phoneLabel": phone_label,
                "phonePlaceholder": phone_placeholder,
                "countryCodes": [{ "value": "86", "label": country_label }],
                "phoneMinLength": 11,
                "phoneMaxLength": 11,
                "codeMinLength": 6,
                "codeMaxLength": 6,
                "resendAfterSeconds": RESEND_AFTER_SECONDS,
                "expiresAfterSeconds": EXPIRES_AFTER_SECONDS,
            },
        }],
    })
}
