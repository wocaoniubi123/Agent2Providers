//! KukuAI 登录：**主站网页登录** + 壳侧读完整会话 Cookie 收尾。
//!
//! ── 为什么不是纯 API 短信、也不是 passport 页面自动化（照 native 模块头）──
//! 百度 passport 的短信发码（`senddpass`）带一串 wappass 风控签名参数（由页面 JS
//! 的风控库生成），纯 HTTP 复刻既不稳定也随时可能随版本失效（2026-10-10 实测
//! `getcodetype` 等旧接口已 404）。passport 页面自动化也试过并放弃：登录页 DOM
//! 与风控行为随版本变，自动化链路脆弱。
//! 最终方案把「怎么登录」还给用户：打开 KukuAI **主站**，用户用手机验证码 /
//! 扫码正常登录（官方页面自己处理风控），壳侧从 WebView 的 Cookie 存储读完整
//! 会话交回。
//!
//! ── 流程（回调型：`poll_interval_ms = 0`）────────────────────
//!   1. 插件 `login.start` 返回主站地址 `https://kuku.baidu.com/`；
//!   2. 壳侧打开内嵌窗口（可见），用户在其中完成登录；
//!   3. 壳侧检测到 `BDUSS` 后把**全部百度域 Cookie**（BDUSS / STOKEN / BAIDUID /
//!      BAIDUID_BFESS …，含 HttpOnly）拼成 Cookie 头当回调 `code` 交回网关
//!      （桌面壳 `login.rs` 的 `submit_kuku_login` → `POST /api/session/login/kuku/complete`
//!      → 网关 `submit_login_callback` → 插件 `login.callback`，对 wasm 包同一路径）；
//!   4. 插件在这里解析 Cookie、打 `userreport` 复核并取 `uk`，产出账号。
//!
//! ── 为什么必须交回**完整**会话（2026-10-07 浏览器对照实测）────
//! `userreport` 校验完整浏览器会话：只带 BDUSS/STOKEN/gfprotpl 会被判「未登录」
//! （errno=-6），补上 BAIDUID / BAIDUID_BFESS 后立即可用。主站方案天然满足
//! （首访即下发 BAIDUID，登录后 BDUSS 一并写入）。
//!
//! ── 与 native 的差别：flow 由主程序分配 ─────────────────────
//! native 那份回一个固定 flow（`kuku-web`）。wasm 侧宿主为交互式登录分配一次性
//! flow（`login.<32 字节 hex>`），并要求插件原样返回（`host.rs` 的「交互式登录
//! 必须使用主程序分配的流程标识」）；回调时宿主按同一个 flow 找回登录任务。
//! 因此这里**只能**回传 `params.flow`，写死常量会让登录窗口打不开。
//!
//! ── 复核失败**不阻断**登录，但**带警告**────────────────────
//! 走到警告分支的情形：Cookie 缺 PTOKEN、换不了 genflowpro 作用域 STOKEN，且原
//! 凭证的 STOKEN 又过不了业务校验。用户在窗口里刚登录成功，凭证本身是有效的
//! （BDUSS 有效），因此失败时**仍返回账号**（uid 为空，去重按 cookie 尾兜底）——
//! 转发与模型刷新会在需要时重新拿三件套并再次尝试换发（`session::fetch` 的自愈
//! 路径）；同时把警告放进 `public.warning`，由前端告知补救办法。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::account::{self, KukuCredentials};
use super::errors;
use super::upstream;

/// 登录窗口的导航白名单（主站 + 百度通行证 + 风控页 + 顶级域兜底）。
///
/// ── 为什么要给 `baidu.com` 这一条 ────────────────────────────
/// 登录链路会从主站跳到 `passport.baidu.com`，成功后回跳主站；中间还可能经过
/// `wappass.baidu.com`（风控 / 二次确认）。少一条的表现是「点登录没反应」或
/// 「窗口一片空白」，而且网页形态不走壳、很难复现。
const ALLOWED_HOSTS: [&str; 4] = [
    "kuku.baidu.com",
    "passport.baidu.com",
    "wappass.baidu.com",
    "baidu.com",
];

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 网关对 wasm 包恒走动态通道（`api/session.rs` 的 `dynamic_login()` 恒为真），
/// 拿不到清单就回 501，添加账号面板整个打不开；它不会回退到 `metadata.json`
/// 的 `login_methods`。
///
/// ── 与 `metadata.json` 的对应（三条，顺序照抄）──────────────
/// 0 号 = `kind: "browser"`（网页登录）、1 号 = `kind: "token"`（Cookie）、
/// 2 号 = `kind: "desktop"`（导入本机登录态）。
///
/// 第 2 条能留是因为本包 `wasm.json` 的 `requires` 里有
/// `desktop.credentials.v1`（`helpers` 里那条 `desktop.credentials.kuku.v1`）：
/// 读本机登录态由宿主代读，插件自己不碰文件系统。少了那个能力位，
/// 网关会按「本机导入契约无效」整条拒掉，所以它必须带 `localOnly: true` 与
/// `browserMode: "none"`（`api/session.rs` 的校验就是这两条件）。
///
/// `manualCallback: false`：Cookie 由壳侧窗口自动交回，不需要用户回填地址。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "oauth", "label": "网页登录", "prompts": [],
            "browserMode": "choice", "manualCallback": false,
            "instructions": "打开库库 AI 网页版，登录成功后自动取回登录态"
        },
        {
            "methodIndex": 1, "type": "api", "label": "Cookie", "prompts": [{
                "key": "token", "type": "text", "label": "Cookie",
                "placeholder": "BDUSS=…; STOKEN=…（也可粘贴 Cookie 编辑器导出的 JSON）",
                "secret": true
            }],
            "instructions": "BDUSS=…; STOKEN=…（也可粘贴 Cookie 编辑器导出的 JSON）"
        },
        {
            "methodIndex": 2, "type": "desktop", "label": "导入本机登录态", "prompts": [],
            "localOnly": true, "browserMode": "none",
            "instructions": "读取库库 AI 桌面客户端已登录的 Cookies"
        }
    ] })
}

/// `login.start`：打开主站，壳侧登录完成后把 Cookie 当 `code` 交回。
///
/// `poll_interval_ms = 0` 是**关键约定**：百度通行证登录成功后的跳转不携带授权码
/// （凭证在 `.baidu` 域的 Cookie 里，跨域跳转不会带过去），没有可轮询的上游端点。
/// 网关据此走「打开窗口 → 等回调」那条路。
pub fn start(params: &Value) -> Result<Value> {
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .ok_or_else(|| Error::new("主程序未分配登录流程"))?;
    let mut hosts: Vec<Value> = Vec::with_capacity(ALLOWED_HOSTS.len());
    for host in ALLOWED_HOSTS {
        hosts.push(Value::String(host.to_string()));
    }
    Ok(json!({
        "flow": flow,
        "url": format!("{}/", upstream::BASE_URL),
        "instructions": "在弹出的窗口里完成登录（手机验证码 / 扫码均可），登录成功后会自动收下账号",
        // 0 = 回调型流程：宿主不要轮询，等回调
        "poll_interval_ms": 0,
        // 内嵌窗口：壳侧要从 WebView 的 Cookie 存储读登录态 —— 系统浏览器里
        // 读到的 Cookie 壳侧拿不到，这条流程必须走内嵌窗口
        "external_browser": false,
        "allowed_hosts": Value::Array(hosts),
    }))
}

/// `login.poll`：回调型流程不轮询。
///
/// 返回「还在等」而不是报「不支持」：宿主若因为某种原因仍然问了一次（旧版本的
/// 兼容路径），回一个 pending 不会中断流程；而报错会把一条正常的登录打成失败。
/// `poll_interval_ms = 0` 时宿主不会再问第二次。
pub fn poll(_params: &Value) -> Result<Value> {
    Ok(json!({
        "state": "pending",
        "hint": "在打开的页面里完成登录，成功后会自动收下账号",
    }))
}

/// `login.cancel`：无本地状态要清（登录任务与 flow 都在宿主侧）。
pub fn cancel(_params: &Value) -> Result<Value> {
    Ok(Value::Null)
}

/// `login.callback`：壳侧交回的完整 Cookie 头 → 复核 → 账号。
pub fn callback(params: &Value) -> Result<Value> {
    let code = params["code"].as_str().map(str::trim).unwrap_or("");
    let url = params["url"].as_str().map(str::trim).unwrap_or("");
    // 正常链路把 Cookie 头放在 `code`；`url` 是回调地址的兼容入口 ——
    // 若它带 `cookie=` / `code=` 查询参数就取出来，否则整段当 Cookie 头。
    let raw = if code.is_empty() { url } else { code };
    let cookie = cookie_from_callback(raw);
    if cookie.trim().is_empty() {
        return Ok(failed("登录窗口没有捕获到有效的 BDUSS（百度通行证登录态），请重新发起登录"));
    }
    let (bduss, stoken, extras) = account::parse_cookie_parts(&cookie);
    if bduss.chars().count() < 8 {
        return Ok(failed(
            "登录窗口没有捕获到有效的 BDUSS（百度通行证登录态），请重新发起登录",
        ));
    }
    let parsed = KukuCredentials {
        bduss,
        stoken,
        extras,
        uid: String::new(),
        nickname: String::new(),
    };
    match account::enrich(&parsed, true) {
        Ok(enriched) => Ok(json!({
            "state": "done",
            "account": account::account_from(&enriched, "web", false, None),
        })),
        Err(error) => {
            // 警告走账号的公开视图：协议里 `Done` 没有 warning 字段，前端按
            // 既有键名 `public.warning` 读（与网关 `payload.warning` 同义）。
            let mut account = account::account_from(&parsed, "web", false, None);
            if let Some(object) = account.get_mut("public").and_then(Value::as_object_mut) {
                object.insert(
                    "warning".to_string(),
                    json!(format!(
                        "登录态已收下，但复核未通过（{}）：账号已添加，模型刷新可能报「未登录」。请重新粘贴完整 Cookie（需含 PTOKEN），或稍后重试",
                        errors::truncate_chars(&error.message, 200)
                    )),
                );
            }
            Ok(json!({ "state": "done", "account": account }))
        }
    }
}

/// 登录失败的返回（宿主据此把登录任务标记为失败）。
fn failed(message: &str) -> Value {
    json!({ "state": "failed", "message": message })
}

/// 从回调内容里取 Cookie 头。
///
/// 三种形态（壳侧 / 旧调用方都会出现）：
///   1. 纯 Cookie 头：`BDUSS=…; STOKEN=…`；
///   2. 带查询串的地址：`http://127.0.0.1:…?state=…&cookie=…`；
///   3. JSON 包体：`{"cookie": "BDUSS=…"}`。
fn cookie_from_callback(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    if raw.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            for key in ["cookie", "code", "session"] {
                if let Some(text) = value.get(key).and_then(Value::as_str) {
                    let text = text.trim();
                    if !text.is_empty() {
                        return text.to_string();
                    }
                }
            }
        }
        return String::new();
    }
    // 地址形态：从查询串里找 cookie / code
    if let Some((_, query)) = raw.split_once('?') {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if matches!(key, "cookie" | "code") && !value.is_empty() {
                    return percent_decode_plus(value);
                }
            }
        }
    }
    raw.to_string()
}

/// 回调查询串的百分号解码（`+` 当空格，与 `application/x-www-form-urlencoded` 一致）。
fn percent_decode_plus(text: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    let raw = text.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => {
                bytes.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < raw.len() => {
                match (hex_value(raw[index + 1]), hex_value(raw[index + 2])) {
                    (Some(high), Some(low)) => {
                        bytes.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        bytes.push(raw[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requires_a_host_assigned_flow() {
        assert!(start(&json!({})).is_err());
        assert!(start(&json!({ "flow": "  " })).is_err());
        let value = start(&json!({ "flow": "login_abc" })).unwrap_or(Value::Null);
        assert_eq!("login_abc", value["flow"].as_str().unwrap_or_default());
        assert_eq!(0, value["poll_interval_ms"].as_u64().unwrap_or(1));
        assert_eq!(false, value["external_browser"].as_bool().unwrap_or(true));
        assert_eq!(
            "https://kuku.baidu.com/",
            value["url"].as_str().unwrap_or_default()
        );
        let hosts = value["allowed_hosts"].as_array().cloned().unwrap_or_default();
        assert_eq!(4, hosts.len());
        assert!(hosts.iter().any(|host| host.as_str() == Some("passport.baidu.com")));
    }

    #[test]
    fn callback_accepts_header_url_and_json_forms() {
        assert_eq!(
            "BDUSS=abc; STOKEN=s",
            cookie_from_callback("BDUSS=abc; STOKEN=s")
        );
        assert_eq!(
            "BDUSS=abc%2Bdef",
            cookie_from_callback("http://127.0.0.1:1/x?state=login_a&cookie=BDUSS%3Dabc%252Bdef")
        );
        assert_eq!(
            "BDUSS=abc",
            cookie_from_callback("{ \"cookie\": \"BDUSS=abc\" }")
        );
        assert_eq!("", cookie_from_callback(""));
        assert_eq!("", cookie_from_callback("{bad json}"));
    }

    #[test]
    fn invalid_cookie_produces_a_failed_state() {
        let value = callback(&json!({ "flow": "login_a", "code": "BDUSS=short" })).unwrap_or(Value::Null);
        assert_eq!("failed", value["state"].as_str().unwrap_or_default());
        let value = callback(&json!({ "flow": "login_a", "code": "" })).unwrap_or(Value::Null);
        assert_eq!("failed", value["state"].as_str().unwrap_or_default());
    }

    #[test]
    fn percent_decoding_matches_form_encoding() {
        assert_eq!("a b", percent_decode_plus("a+b"));
        assert_eq!("a=b", percent_decode_plus("a%3Db"));
        assert_eq!("%ZZ", percent_decode_plus("%ZZ"));
    }

    /// 形状必须与网关 `api/session.rs` 的 `LoginMethodsMetadata` 对得上：
    /// 索引唯一、`type` 在四个枚举内、`prompts` 恒为数组、oauth 带合法的
    /// `browserMode`，desktop 必须 `localOnly + browserMode="none"` 且无 prompts。
    #[test]
    fn methods_declare_the_gateway_contract() {
        let value = methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(3, list.len());
        let mut seen: Vec<u64> = Vec::new();
        for method in &list {
            let index = method["methodIndex"].as_u64().unwrap_or(u64::MAX);
            assert!(!seen.contains(&index), "methodIndex 重复或缺失");
            seen.push(index);
            assert!(!method["label"].as_str().unwrap_or("").trim().is_empty());
            assert!(method["prompts"].is_array());
            match method["type"].as_str().unwrap_or("") {
                "oauth" => assert!(matches!(
                    method["browserMode"].as_str().unwrap_or(""),
                    "choice" | "external" | "plugin" | "none"
                )),
                "api" => {
                    let prompts = method["prompts"].as_array().cloned().unwrap_or_default();
                    assert_eq!(1, prompts.len());
                    assert_eq!("token", prompts[0]["key"].as_str().unwrap_or(""));
                    assert_eq!(true, prompts[0]["secret"].as_bool().unwrap_or(false));
                }
                "desktop" => {
                    assert_eq!(true, method["localOnly"].as_bool().unwrap_or(false));
                    assert_eq!("none", method["browserMode"].as_str().unwrap_or(""));
                    assert_eq!(0, method["prompts"].as_array().map(Vec::len).unwrap_or(1));
                }
                other => assert_eq!("sms", other),
            }
        }
    }
}
