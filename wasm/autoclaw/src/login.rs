//! AutoClaw 登录：**国内版手机验证码 / 国际版 Zai·Google OAuth**（两个地区各只有一条）。
//!
//! ── 两个地区的登录方式不一样，而且各只有一条 ────────────────
//! ```text
//!                        国内版（autoclaw）      国际版（autoclaw-intl）
//!   手机验证码登录        ✅ 唯一官方方式          ❌ 不提供（见下）
//!   OAuth 网页登录        ❌ 登录页不渲染按钮      ✅ 唯一登录方式（Zai / Google）
//!   oauth-captcha-config  enabled: false           enabled: true, supplier: aliyun
//! ```
//!
//! 国际版的手机验证码入口**曾经可用**（接口逐字相同、实测也通），移除它是产品
//! 决策而不是技术限制：国际版用户大量用 Zai / Google 注册、根本没绑手机号，
//! 留着那个入口只会稳定失败。所以这里对国际版直接返回人话错误。
//!
//! ── 国内版为什么是两次同步调用，而不是 `login.start` ──────────
//! 官方客户端唯一的自助入口就是「发码 → 填码 → 换 token」，没有授权码、没有
//! 窗口、没有轮询。硬套网页登录框架会让网关为一次短信建一个后台任务、还要把
//! deviceId 编进 flow 再拆出来。因此这里走**管理动作**（与 native 同构）：
//!
//! ```text
//!   login.sms-send    {phone}                        → {deviceId}
//!   login.sms-verify  {phone, code, deviceId, name?} → NormalizedAccount（网关落库）
//! ```
//!
//! ── 上游协议（依据桌面端 `app.asar`，实测确认）─────────────────
//! ```text
//! POST {userapi}/userapi/v1/agent-send-code   {"phone","source_id","device_id"}
//! POST {userapi}/userapi/v1/agent-login/      {"phone","code","platform","source_id","device_id"}
//! ```
//! `agent-login` **直接返回 token 对**（不经授权码）。`platform: "web"` 是网页端
//! 与桌面端唯一的差别。签名头与积分 / 签到链路完全一致（`sign::signed_headers`）。
//!
//! ── 国际版 OAuth 的三步与那个卡点 ────────────────────────────
//! ```text
//! ① POST {userapi}/userapi/overseasv1/oauth-captcha-config  → {enabled, region, prefix, scene_id, supplier}
//! ② POST .../{zai|google}-oauth-url  {source_id, device_id, navigate_uri, ali_captcha_verify_param}
//!      → oauth_url（官方登录页）
//! ③ 浏览器在登录页完成登录 → 302 到 navigate_uri?code=…&state=…
//!    POST .../{zai|google}-oauth-login {source_id, device_id, code, state, navigate_uri}
//!      → {access_token, refresh_token, user_id, user_name}
//! ```
//! 第 ② 步强制要求**阿里云风控验证码参数**：不带它得到 `631002 当前版本已停止
//! 服务`（一个与真实原因无关的误导码），带假值得到 `630014 审核失败`。验证码是
//! **浏览器端 JS SDK**，复刻算法成本高且会随上游更新失效 —— 因此不复刻，而是让
//! 插件**接收**前端跑完 SDK 得到的不透明字符串并原样转交（`login.oauth-start` 的
//! `captchaVerifyParam`）。第 ③ 步不需要验证码，所以换码可以完全在插件里做。
//!
//! ── `navigate_uri` 必须长成客户端那样（别改）───────────────────
//! Zai 的 OAuth 服务按 client 登记的白名单逐字校验 `redirect_uri`：名单里只有
//! 官方客户端那四个 loopback 端口上的 `http://localhost:<端口>/auth/callback-zai`。
//! 端口不是那四个之一、host 写成 `127.0.0.1`、路径不对 —— 一律被拒。
//! **Google 是另一套规则**（RFC 8252 的 loopback 宽松匹配，端口任意），所以同一
//! 份代码「谷歌能登、Zai 登不上」。
//!
//! ── 与 native 的差别：loopback 监听器 → 手工回填 ─────────────────
//! native 每轮登录借一个登记端口自己收回调；wasm 没有 socket，这条链改成
//! 「用户把地址栏那条 URL 粘回来」（`login.callback` / `login.oauth-callback`）。
//! `navigate_uri` 仍是登记端口的形态（白名单要求），只是不会被真的访问。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, state, Error, Result, Value};

use super::codec;
use super::credential::{self, Credential};
use super::oauth;
use super::region;
use super::upstream;

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

/// 登录状态有效期（15 分钟）
const STATE_TTL_MS: i64 = 900_000;

/// 官方向 Zai 登记的四个回调端口（`app.asar` 的 `ALL_PORTS` 逐字读出）。
///
/// 改这个列表前先确认两件事：官方客户端里的 `ALL_PORTS` 变了、以及上游放行了
/// 新端口 —— 猜一个端口只会换来窗口里一句 `Redirect URI not registered`。
const REGISTERED_CALLBACK_PORTS: [u16; 4] = [18432, 19654, 19723, 53699];

/// 本轮使用的回调端口（插件没有监听，只用来拼合法的 `navigate_uri`）。
const CALLBACK_PORT: u16 = REGISTERED_CALLBACK_PORTS[0];

fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 网关对 wasm 包恒走动态通道（`api/session.rs` 的 `dynamic_login()` 恒为真），
/// 拿不到这份清单就回 501，**添加账号面板整个打不开**；而且它不会回退到
/// `metadata.json` 的 `login_methods`。
///
/// ── 国内版：短信的契约（漏一个字段就 502）───────────────────
/// `sms` 是 camelCase 且 `deny_unknown_fields`：
/// `phoneLabel` / `phonePlaceholder` / `countryCodes[]` / `phoneMinLength` /
/// `phoneMaxLength` / `codeMinLength` / `codeMaxLength` / `resendAfterSeconds`
/// （1..=3600）/ `expiresAfterSeconds`（30..=900）。
/// 短信方式**不能**带 `browserMode` / `manualCallback` / `prompts` —— 网关会判
/// 「短信登录不能声明浏览器、回调或额外动态表单」（`session.rs:304`）。
///
/// ── 国际版：oauth 的契约 ────────────────────────────────────
/// `manualCallback: true` + `callbackInput: "url"`：插件没有 socket，收不到
/// 浏览器重定向，必须由用户回填（与 `login.start` 的 `login_ui` 逐字同值）。
pub fn methods() -> Value {
    if region::REGION.sms_login() {
        return json!({ "methods": [
            {
                "methodIndex": 0, "type": "sms", "label": "手机验证码登录", "prompts": [],
                "instructions": "用绑定的手机号登录：点「获取验证码」后填入即可",
                "sms": {
                    "phoneLabel": "手机号",
                    "phonePlaceholder": "11 位中国大陆手机号",
                    "countryCodes": [ { "value": "86", "label": "中国 +86" } ],
                    "phoneMinLength": 11,
                    "phoneMaxLength": 11,
                    "codeMinLength": 6,
                    "codeMaxLength": 6,
                    "resendAfterSeconds": 60,
                    "expiresAfterSeconds": 300
                }
            }
        ] });
    }
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "oauth", "label": "网页登录（Zai / Google）", "prompts": [],
            "browserMode": "choice", "manualCallback": true, "callbackInput": "url",
            "instructions": format!(
                "点按钮后先过一次滑块验证（官方风控），随后打开登录页。页面最后会停在「无法访问 localhost」——这是正常的：请把地址栏里那条完整 URL 复制回填，授权码就在其中。\n当前站点：{}",
                region::REGION.label()
            )
        }
    ] })
}

// ─── 国内版：手机验证码（两次同步调用）─────────────────────────

/// 发验证码路径（源实现 `sendCode`）
const SEND_CODE_PATH: &str = "/userapi/v1/agent-send-code";
/// 登录路径（源实现 `phoneCodeLogin`，注意结尾的斜杠是上游要求的）
const LOGIN_PATH: &str = "/userapi/v1/agent-login/";

/// 中国大陆手机号（源实现 `normalizePhone` 的等价物：`1[2-9]` 开头的 11 位，
/// 容忍 `+86` / `86` 前缀与空格、连字符）。
fn normalize_phone(raw: &str) -> Result<String> {
    let trimmed: String = raw.chars().filter(|ch| !ch.is_whitespace() && *ch != '-').collect();
    let digits = trimmed.strip_prefix("+86").unwrap_or(&trimmed);
    let digits = digits
        .strip_prefix("86")
        .filter(|rest| rest.len() == 11)
        .unwrap_or(digits);
    if digits.len() == 11
        && digits.starts_with('1')
        && digits.chars().nth(1).is_some_and(|ch| ('2'..='9').contains(&ch))
        && digits.chars().all(|ch| ch.is_ascii_digit())
    {
        Ok(digits.to_string())
    } else {
        Err(Error::http(400, "请填写 11 位中国大陆手机号"))
    }
}

/// 6 位数字验证码（源实现 `normalizeCode`）。
///
/// ── 为什么返回**数字**而不是字符串（实测踩过的坑，别改回去）──────
/// 上游要求 body 里的 `code` 是 **JSON 数字**，传字符串会得到
/// `400001 / 请求数据有问题` —— 一个与「验证码错误」完全无关的参数错误。
fn normalize_code(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.len() == 6 && trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        trimmed.parse::<u32>().ok()
    } else {
        None
    }
}

/// 业务码 → 用户能看懂的原因。
///
/// 上游的参数类错误一律给 `400001 / 请求数据有问题`，对用户没有指导意义、
/// 也分不清是哪个字段不对。这里按码翻成「该做什么」，未知码才回落到上游文案。
fn describe_login_error(code: i64, upstream_msg: &str) -> String {
    match code {
        400_001 => "请求参数有误，请检查手机号与验证码格式后重试".to_string(),
        630_202 => "验证码不正确，请检查后重试".to_string(),
        630_101 => "获取验证码过于频繁，请稍后再试".to_string(),
        410_000 | 400_000 => "登录态已失效，请重新登录".to_string(),
        400_002 => "请求签名校验失败（本机时钟可能有偏差），请校准系统时间后重试".to_string(),
        // 631002 原文是「当前版本已停止服务」—— 它不是版本问题，而是**缺少
        // 风控验证**（实测换任何 X-Version 都是这个码）。直译会把用户引向
        // 「升级客户端」这个死方向。
        631_002 => {
            "上游要求过风控验证，本次登录无法在此完成；请改用「填写凭证」（可从 AutoClaw 客户端导出明文 token）"
                .to_string()
        }
        630_014 => "风控验证未通过，请稍后重试；若持续失败请改用「填写凭证」".to_string(),
        _ => {
            if upstream_msg.trim().is_empty() {
                format!("登录失败（上游 code={code}）")
            } else {
                format!("登录失败：{}", upstream_msg.trim())
            }
        }
    }
}

/// 本模块的 OAuth 错误文案统一走 `oauth::describe_error`（码表只写一份）。
fn describe_oauth_error(code: i64, upstream_msg: &str) -> String {
    oauth::describe_error(code, upstream_msg)
}

/// 发送短信验证码（国内版专用）。
///
/// 返回 `{deviceId}`：上游把「刚发的码」绑在发码时的 device_id 上，登录必须
/// 带同一个。插件不替用户保存这个中间态（一次登录可跨多次 HTTP 请求、也可被
/// 放弃），回给前端让它随下一次请求带回。
pub fn send_code(params: &Value) -> Result<Value> {
    if !region::REGION.sms_login() {
        return Err(Error::http(
            400,
            "AutoClaw 国际版不支持手机号登录，请改用「网页登录（Zai / Google）」或「填写凭证」",
        ));
    }
    let phone = normalize_phone(params["phone"].as_str().unwrap_or(""))?;
    let device_id = credential::new_device_id();
    let body = json!({
        "phone": phone,
        "source_id": "autoclaw",
        "device_id": device_id,
    });
    let payload = upstream::post_anonymous(SEND_CODE_PATH, &body, "发送验证码")?;
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        let upstream_msg = payload.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(Error::http(400, describe_login_error(code, upstream_msg)));
    }
    let delivered = payload
        .get("data")
        .and_then(|data| data.get("result"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !delivered {
        return Err(Error::http(502, "验证码发送失败，请稍后重试"));
    }
    Ok(json!({ "deviceId": device_id }))
}

/// 用手机号 + 验证码登录，返回可直接落库的账号。
///
/// 返回形状与「粘贴 token 添加」的 `account.normalize` 产出**同形** —— 登录只是
/// 另一种拿到凭证的方式，落盘、命名、去重全部复用网关既有的落库通路。
pub fn verify_code(params: &Value) -> Result<Value> {
    if !region::REGION.sms_login() {
        return Err(Error::http(
            400,
            "AutoClaw 国际版不支持手机号登录，请改用「网页登录（Zai / Google）」",
        ));
    }
    let phone = normalize_phone(params["phone"].as_str().unwrap_or(""))?;
    let Some(code) = normalize_code(params["code"].as_str().unwrap_or("")) else {
        return Err(Error::http(400, "请填写 6 位数字验证码"));
    };
    let device_id = params["deviceId"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(credential::new_device_id);
    let body = json!({
        "phone": phone,
        "code": code,
        // 网页端与桌面端**唯一**的差别（源实现 `loginWebWithPhoneCode`）
        "platform": "web",
        "source_id": "autoclaw",
        "device_id": device_id,
    });
    let payload = upstream::post_anonymous(LOGIN_PATH, &body, "登录")?;
    let status = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if status != 0 {
        let upstream_msg = payload.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(Error::http(400, describe_login_error(status, upstream_msg)));
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
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let secret = json!({
        "token": token,
        "refreshToken": refresh_token,
        "deviceId": device_id,
        // 手机号脱敏：登录只是另一种拿凭证的方式，界面副标题用尾号区分账号
        "phoneTail": mask_phone(&phone),
        "name": name.unwrap_or_default(),
    });
    account_from_secret(secret)
}

/// 手机号脱敏（源实现 `maskPhone`：保留前 3 后 4）。
///
/// 按 `char` 切而非按字节：入参经 `normalize_phone` 归一化后是 11 位 ASCII 数字，
/// 但同款实现曾在别处被汉字打穿过 —— 这类切片错一次就是整个插件实例退出。
fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 7 {
        return phone.to_string();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****{tail}")
}

// ─── 国际版：Zai / Google OAuth ───────────────────────────────

/// 回调路径前缀（与官方客户端逐字同款）
const CALLBACK_PATH_PREFIX: &str = "/auth/callback-";

/// 回调基址（`http://localhost:<登记端口>`，与官方客户端同形）。
fn callback_base() -> String {
    format!("http://localhost:{CALLBACK_PORT}")
}

/// 拼这次登录的回调地址（同时也是交给上游的 `navigate_uri`）。
fn navigate_uri(vendor: &str) -> String {
    format!("{}{}{}", callback_base(), CALLBACK_PATH_PREFIX, vendor)
}

/// 解析回调路径里的变体（不认识返回 None —— 不静默回落到某一个变体）。
fn vendor_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix(CALLBACK_PATH_PREFIX)?;
    let name = rest.split('?').next().unwrap_or(rest);
    if oauth::is_vendor(name) {
        Some(name.to_string())
    } else {
        None
    }
}

/// 取验证码配置（前端据此初始化阿里云 SDK）。
///
/// 返回归一化形状 `{enabled, region, prefix, sceneId, supplier}`：上游用
/// snake_case，前端 camelCase，在**这一处**翻译完。`enabled: false` **不是错误**
/// —— 国内版就是这个值（它没有 OAuth）。
fn captcha_config() -> Result<Value> {
    let payload = upstream::post_anonymous(oauth::CAPTCHA_CONFIG_PATH, &json!({}), "获取风控验证配置")?;
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        let upstream_msg = payload.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(Error::http(502, describe_oauth_error(code, upstream_msg)));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let text = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    Ok(json!({
        "enabled": data.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        "region": text("region"),
        "prefix": text("prefix"),
        "sceneId": text("scene_id"),
        "supplier": text("captcha_supplier"),
    }))
}

/// 发起一次 OAuth 登录（`login.oauth-start` 的实现主体）。
///
/// 返回 `(flow, auth_url)`。
fn start_oauth(vendor: &str, captcha_verify_param: &str) -> Result<(String, String)> {
    if !region::REGION.web_login() {
        return Err(Error::http(
            400,
            "AutoClaw 国内版没有网页授权登录（上游的 OAuth 开关是关的），请改用「手机验证码登录」",
        ));
    }
    let captcha = captcha_verify_param.trim();
    if captcha.is_empty() {
        // 本地就挡掉：不带它打上游必然得到那条误导性的 631002
        return Err(Error::http(400, "缺少风控验证参数，请先完成验证码"));
    }
    let device_id = credential::new_device_id();
    let navigate = navigate_uri(vendor);
    let auth_url = oauth::request_oauth_url(vendor, &navigate, captcha, &device_id)?;
    let flow = format!("autoclaw-web-{}", codec::random_flow_id());
    put_state(
        json!({
            "flow": flow,
            "phase": "waiting",
            "vendor": vendor,
            "navigate_uri": navigate,
            "device_id": device_id,
        }),
        STATE_TTL_MS,
    )?;
    Ok((flow, auth_url))
}

/// 用回调 query 换码，产出可落库的扁平凭证。
fn finish_oauth(query: &str) -> Result<Value> {
    let params = codec::query_pairs(query);
    let find = |key: &str| {
        params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let error = find("error");
    if !error.trim().is_empty() {
        return Err(Error::http(400, format!("授权被拒绝（{error}）")));
    }
    let code = find("code");
    if code.trim().is_empty() {
        return Err(Error::http(400, "回调没有携带授权码"));
    }
    // 查询串里的 state 是**上游生成的**那个（换码要回传它），不是我们的 flow。
    let upstream_state = find("state");
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return Err(Error::http(400, "这次登录已取消或已过期，请重新发起"));
    }
    let vendor = snapshot.value["vendor"].as_str().unwrap_or("zai").to_string();
    let navigate = snapshot.value["navigate_uri"].as_str().unwrap_or("").to_string();
    let device_id = snapshot.value["device_id"].as_str().unwrap_or("").to_string();
    let mut credentials = oauth::exchange_code(
        &vendor,
        code.trim(),
        upstream_state.trim(),
        &navigate,
        &device_id,
    )?;
    // 邮箱：换回来的 token 里没有它（JWT 只有 user_id / device_id / guid），
    // 而账号在列表上得认得出是谁。best-effort：查不到照常建账号。
    if let Ok(found) = credential::from_record(&credentials, region::REGION) {
        if let Some(email) = profile_email(&found) {
            if let Some(object) = credentials.as_object_mut() {
                object.insert("email".to_string(), Value::String(email));
            }
        }
    }
    Ok(credentials)
}

/// 查一次 user-profile 拿邮箱（失败返回 None，不影响建账号）。
fn profile_email(credential: &Credential) -> Option<String> {
    let payload = upstream::post(
        "/userapi/v1/user-profile",
        &credential.token,
        &json!({ "source_id": "autotyper", "device_id": credential.device_id }),
        "用户资料查询",
    )
    .ok()?;
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let email = credential::text(&data, &["email", "mail"]).trim().to_string();
    (!email.is_empty()).then_some(email)
}

// ─── 登录状态（login.start / poll / callback / cancel）────────────

fn put_state(value: Value, ttl_ms: i64) -> Result<()> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !state::compare_exchange(state::Scope::Login, STATE_KEY, SCHEMA, snapshot.revision, value, ttl_ms)? {
        return Err(Error::new("登录状态已被另一轮流程改写，请重新发起"));
    }
    Ok(())
}

fn clear(revision: u64) {
    let _ = state::compare_exchange(state::Scope::Login, STATE_KEY, SCHEMA, revision, Value::Null, 1000);
}

/// 发起一次网页登录（国际版）。
///
/// ── 为什么这里能直接发起、而不必像 native 那样「只能走管理动作」──────
/// native 的 `login.start` 拿不到验证码参数（网关传的是空 payload），所以真正的
/// 发起只能走 `login.oauth-start`。wasm 侧的 `login.start` 能拿到 `params`
/// （网关会把面板填的东西一起送进来），因此这里先试 `params` 里的验证码参数：
/// 有就真正发起，没有就回一条清楚的说明（并保留 `admin.action` 那条路给面板）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"]
        .as_str()
        .or_else(|| params["kind"].as_str())
        .unwrap_or("browser");
    if !matches!(method, "" | "browser" | "web" | "oauth") {
        return Err(Error::http(
            400,
            "AutoClaw 的「填写凭证」请直接在账号页粘贴 token；网页登录请点「网页登录」",
        ));
    }
    if !region::REGION.web_login() {
        return Err(Error::http(
            400,
            "AutoClaw 国内版没有网页授权登录，请改用「手机验证码登录」",
        ));
    }
    let vendor = params["vendor"]
        .as_str()
        .map(str::trim)
        .filter(|value| oauth::is_vendor(value))
        .unwrap_or("zai")
        .to_string();
    let captcha = params["captchaVerifyParam"]
        .as_str()
        .or_else(|| params["captcha_verify_param"].as_str())
        .or_else(|| params["source"]["payload"]["captchaVerifyParam"].as_str())
        .unwrap_or("");
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("autoclaw-web-{}", codec::random_flow_id()));
    let (started_flow, url) = match start_oauth(&vendor, captcha) {
        Ok(value) => value,
        Err(error) if error.message.contains("缺少风控验证参数") => {
            return Err(Error::http(
                400,
                "AutoClaw 国际版的网页登录需要先完成一次风控验证：请回到「添加账号」弹窗用「网页登录（Zai / Google）」发起（面板会先拿到验证码配置），或改用「填写凭证」粘贴 token",
            ))
        }
        Err(error) => return Err(error),
    };
    // 网关分配的 flow 必须原样回传（规格第 17 节）
    put_state(
        json!({
            "flow": flow,
            "phase": "waiting",
            "vendor": vendor,
            "navigate_uri": navigate_uri(&vendor),
            "device_id": codec::random_hex_id(),
        }),
        STATE_TTL_MS,
    )?;
    let _ = started_flow;
    Ok(json!({
        "flow": flow,
        "url": url,
        "poll_interval_ms": 2000,
        "instructions": "在打开的页面里完成授权。页面最后会停在「无法访问 localhost」——这是正常的：请把地址栏里那条完整 URL 复制回填，授权码就在其中",
        "external_browser": false,
        "allowed_hosts": [],
        "login_ui": {
            "browserMode": "choice", "manualCallback": true, "callbackInput": "url",
            "cookieCapture": Value::Null, "captureCallback": false
        }
    }))
}

/// 轮询一次登录进度。
pub fn poll(params: &Value) -> Result<Value> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return Ok(failed("这次登录流程已失效（插件实例或宿主重启过？），请重新发起"));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if !flow.is_empty() && snapshot.value["flow"].as_str() != Some(flow) {
        return Ok(json!({ "state": "pending", "hint": "另一轮登录正在进行，请等待它完成" }));
    }
    match snapshot.value["phase"].as_str() {
        Some("done") => {
            let account = snapshot.value["account"].clone();
            clear(snapshot.revision);
            Ok(json!({ "state": "done", "account": account }))
        }
        Some("failed") => {
            let message = snapshot.value["message"].as_str().unwrap_or("这轮登录没有成功").to_string();
            clear(snapshot.revision);
            Ok(failed(message))
        }
        _ => Ok(json!({
            "state": "pending",
            "hint": "等待你在浏览器里完成授权，然后把地址栏那条 URL 回填"
        })),
    }
}

/// 用户把回调 URL 贴回来：当场换证并把账号放进状态。
pub fn callback(params: &Value) -> Result<Value> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return Ok(failed("这次登录流程已失效，请重新发起"));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if !flow.is_empty() && snapshot.value["flow"].as_str() != Some(flow) {
        return Ok(failed("这次登录流程已失效，请重新发起"));
    }
    let raw = if params["url"].as_str().is_some_and(|text| !text.trim().is_empty()) {
        params["url"].as_str().unwrap_or("").trim().to_string()
    } else {
        params["code"].as_str().unwrap_or("").trim().to_string()
    };
    if raw.is_empty() {
        return Ok(failed("回调地址为空"));
    }
    // 整条 URL / 裸查询串 / 裸授权码三种形态
    let query = if let Some(rest) = raw.strip_prefix(CALLBACK_PATH_PREFIX) {
        match rest.split_once('?') {
            Some((_, query)) => query.to_string(),
            None => String::new(),
        }
    } else if raw.contains("code=") {
        raw.trim_start_matches('?').to_string()
    } else {
        format!("code={raw}")
    };
    // 回调带的变体与这一轮不一致说明用户贴错了
    let path = raw.split('?').next().unwrap_or(&raw);
    if let Some(callback_vendor) = vendor_from_path(path) {
        let expected = snapshot.value["vendor"].as_str().unwrap_or("");
        if !expected.is_empty() && callback_vendor != expected {
            let message = format!(
                "回调属于 {callback_vendor}，与本次 {expected} 登录不一致，请重新发起"
            );
            mark_failed(snapshot.revision, &message);
            return Ok(failed(message));
        }
    }
    let credentials = match finish_oauth(&query) {
        Ok(credentials) => credentials,
        Err(error) => {
            // 换证失败按 `LoginPoll::Failed` 回，而不是把整条 RPC 变成错误：
            // 授权码已经花掉，这一轮就是「没成」，重做要用户重新点一次登录。
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    let account = match account_from_secret(credentials) {
        Ok(account) => account,
        Err(error) => {
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    put_done(snapshot.revision, &flow, &account);
    Ok(json!({ "state": "done", "account": account }))
}

/// 取消一轮登录（native 走的是「收监听器、释放端口」，插件侧没有端口可放，
/// 清状态就是同一件事）。
pub fn cancel(params: &Value) -> Result<Value> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if snapshot.compatible && !snapshot.value.is_null() {
        let flow = params["flow"].as_str().unwrap_or("");
        if flow.is_empty() || snapshot.value["flow"].as_str() == Some(flow) {
            let _ = state::compare_exchange(
                state::Scope::Login,
                STATE_KEY,
                SCHEMA,
                snapshot.revision,
                Value::Null,
                0,
            );
        }
    }
    Ok(Value::Null)
}

fn mark_failed(revision: u64, message: &str) {
    let _ = state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        revision,
        json!({ "phase": "failed", "message": message }),
        STATE_TTL_MS,
    );
}

fn put_done(revision: u64, flow: &str, account: &Value) {
    let _ = state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        revision,
        json!({ "phase": "done", "flow": flow, "account": account }),
        60_000,
    );
}

// ─── 管理动作（短信两段 + OAuth 三跳）───────────────────────────

/// `admin.action` 的分发（`lib.rs` 里按 action 名调进来）。
pub fn admin_action(action: &str, payload: &Value) -> Result<Value> {
    match action {
        "login.sms-send" => send_code(payload),
        "login.sms-verify" => verify_code(payload),
        "login.oauth-config" => captcha_config(),
        "login.oauth-start" => {
            let vendor = payload["vendor"].as_str().map(str::trim).unwrap_or("");
            if !oauth::is_vendor(vendor) {
                return Err(Error::http(
                    400,
                    format!("无法识别的登录方式「{vendor}」（只支持 zai / google）"),
                ));
            }
            let captcha = payload["captchaVerifyParam"].as_str().unwrap_or("");
            let (flow, auth_url) = start_oauth(vendor, captcha)?;
            Ok(json!({
                "state": flow,
                "authUrl": auth_url,
                "pollIntervalMs": 2000,
                "instructions": "在打开的页面里完成授权，完成后会自动收下账号",
            }))
        }
        "login.oauth-callback" => {
            let url = payload["url"].as_str().unwrap_or("");
            let query = if let Some(rest) = url.trim().strip_prefix(CALLBACK_PATH_PREFIX) {
                match rest.split_once('?') {
                    Some((_, query)) => query.to_string(),
                    None => String::new(),
                }
            } else if url.contains("code=") {
                url.trim_start_matches('?').to_string()
            } else if !url.trim().is_empty() {
                format!("code={}", url.trim())
            } else {
                String::new()
            };
            let credentials = finish_oauth(&query)?;
            let account = account_from_secret(credentials)?;
            let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
            if snapshot.compatible && !snapshot.value.is_null() {
                let flow = snapshot.value["flow"].as_str().unwrap_or("").to_string();
                put_done(snapshot.revision, &flow, &account);
            }
            Ok(json!({ "accepted": true }))
        }
        other => Err(Error::http(
            400,
            format!(
                "AutoClaw 不认识管理动作「{other}」（可用：login.sms-send / login.sms-verify / \
                 login.oauth-config / login.oauth-start / login.oauth-callback）"
            ),
        )),
    }
}

// ─── 凭证 → 账号 ──────────────────────────────────────────────

/// 把一份「扁平凭证」变成协议账号（解析 JWT 拿 user_id，再交给公开形态）。
pub fn account_from_secret(mut secret: Value) -> Result<Value> {
    let parsed = credential::from_record(&secret, region::REGION)?;
    if parsed.token.trim().is_empty() {
        return Err(Error::http(400, "AutoClaw token 为空"));
    }
    if let Some(object) = secret.as_object_mut() {
        object.insert("token".to_string(), Value::String(parsed.token.clone()));
        object.insert(
            "refreshToken".to_string(),
            Value::String(parsed.refresh_token.clone()),
        );
        if !parsed.user_id.is_empty() {
            object.insert("userId".to_string(), Value::String(parsed.user_id.clone()));
        }
        if let Some(expires_at) = parsed.expires_at {
            // 两套键同时写，与刷新回写口径一致：网关读 `expiresAt`，
            // 本插件 / 旧投影读 `tokenExpiresAt`。
            object.insert("tokenExpiresAt".to_string(), json!(expires_at));
            object.insert("expiresAt".to_string(), json!(expires_at));
        }
        // 空备注名不留键：留一个空串会让公开形态把它当成「用户指定的名字」
        if object
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|value| value.trim().is_empty())
        {
            object.remove("name");
        }
    }
    Ok(json!({
        "public": credential::view(&secret),
        "identity": credential::identity(&secret),
        "secret": secret,
        "desktop": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auth.methods` 必须随地区给出对应契约：
    /// 国内版 = sms（满足网关 `SmsConfig::validate`：手机号 11 位、验证码 6 位、
    /// 重发 1..=3600、有效期 30..=900）；国际版 = oauth（browserMode 合法 +
    /// manualCallback + callbackInput url）。两处错一条都是整份 502。
    #[test]
    fn methods_contract_matches_region() {
        let methods = methods();
        let list = methods["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, list.len());
        let method = &list[0];
        assert_eq!(0, method["methodIndex"].as_u64().unwrap_or(u64::MAX));
        assert!(!method["label"].as_str().unwrap_or("").trim().is_empty());
        assert!(method["prompts"].as_array().is_some_and(|prompts| prompts.is_empty()));
        if region::REGION.sms_login() {
            assert_eq!("sms", method["type"].as_str().unwrap_or(""));
            let sms = &method["sms"];
            assert_eq!(11, sms["phoneMinLength"].as_u64().unwrap_or(0));
            assert_eq!(11, sms["phoneMaxLength"].as_u64().unwrap_or(0));
            assert_eq!(6, sms["codeMinLength"].as_u64().unwrap_or(0));
            assert_eq!(6, sms["codeMaxLength"].as_u64().unwrap_or(0));
            let resend = sms["resendAfterSeconds"].as_u64().unwrap_or(0);
            assert!((1..=3600).contains(&resend));
            let expires = sms["expiresAfterSeconds"].as_u64().unwrap_or(0);
            assert!((30..=900).contains(&expires));
            // 短信方式不能有浏览器 / 回调声明
            assert!(method.get("browserMode").is_none() || method["browserMode"].is_null());
            assert_eq!(false, method["manualCallback"].as_bool().unwrap_or(false));
        } else {
            assert_eq!("oauth", method["type"].as_str().unwrap_or(""));
            assert!(matches!(
                method["browserMode"].as_str().unwrap_or(""),
                "choice" | "external" | "plugin" | "none"
            ));
            assert_eq!(true, method["manualCallback"].as_bool().unwrap_or(false));
            assert_eq!("url", method["callbackInput"].as_str().unwrap_or(""));
        }
    }

    /// 手机号归一化：容忍 +86 / 86 / 空格 / 连字符；拒绝非法形态。
    #[test]
    fn phone_normalization() {
        assert_eq!("13800138000", normalize_phone("+86 138-0013-8000").unwrap_or_default());
        assert!(normalize_phone("12345").is_err());
    }

    /// 验证码必须是 6 位数字（上游要 JSON 数字，字符串会被 400001）。
    #[test]
    fn code_normalization() {
        assert_eq!(Some(123456), normalize_code("123456"));
        assert_eq!(None, normalize_code("12345"));
        assert_eq!(None, normalize_code("abcdef"));
    }

    /// 脱敏按字符切，不会因非 ASCII 打穿。
    #[test]
    fn mask_phone_is_char_safe() {
        assert_eq!("138****8000", mask_phone("13800138000"));
        assert_eq!("短号", mask_phone("短号"));
    }
}
