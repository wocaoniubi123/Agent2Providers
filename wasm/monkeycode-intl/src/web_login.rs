//! MonkeyCode「网页登录」：内嵌窗口完成官方登录，宿主把会话 cookie 交回。
//!
//! ── 流程（回调型：`poll_interval_ms = 0`）────────────────────
//!   1. 插件 `login.start` 返回国际站登录页 `https://monkeycode-ai.net/login`；
//!   2. 宿主打开内嵌窗口（`external_browser = false`），用户在里面完成验证码 /
//!      第三方授权（国际站的登录链路是 GitHub / Google 的 OAuth，见
//!      `region::LOGIN_HOSTS`；国内站那条百智云 `baizhi.cloud` 不在本包链路上）；
//!   3. 宿主从窗口的 Cookie 存储读出 HttpOnly 的 `monkeycode_ai_session`，把
//!      `{session, expiresAt}` 当回调内容交给网关 → 网关转 `login.callback`
//!      （与 kuku 同一条回调通道）；
//!   4. 插件在这里复核 `GET /users/status`，产出账号。
//!
//! ── 与 native 的差异 ────────────────────────────────────────
//! - **flow 由主程序分配**：native 自己生成 `monkeycode_login_<随机>`；wasm 宿主
//!   在声明了 `login.interaction.v1` 的包里会分配一次性 flow
//!   （`login.<32 字节 hex>`）并要求插件原样返回（`host.rs` 的「交互式登录必须
//!   使用主程序分配的流程标识」）。写死常量会让登录窗口打不开。
//! - **回调内容放宽到两种形态**：native 只认 JSON `{session, expiresAt}`；本包
//!   同时接受整行 Cookie（宿主把 Cookie 头直接当 `code` 交回时就是这种），解析
//!   走 `login::normalize_session`（与粘贴入口同一套归一化）。
//!
//! ── 为什么失败也回 `state = failed` 而不是抛错 ─────────────────
//! 抛错时宿主只看到一句协议错误，登录窗口里已经完成的动作（用户刚点了授权）
//! 与失败原因对不上。回 `failed` 让界面把原因原样显示出来（kuku 同款处置）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::accounts;
use super::credentials::SESSION_TTL_MS;
use super::login;
use super::region;

/// 回调内容长度上限（宿主交回的是 cookie 或一小段 JSON，超过就是粘错了东西）
const MAX_CALLBACK_LENGTH: usize = 16 * 1024;

/// `wasm.json`：只读它的 `requires`，判断「本机导入」这类方式能不能申报。
const MANIFEST: &str = include_str!("../wasm.json");

/// `admin.action = auth.methods`：平台「登录方式」列表。
///
/// ── 为什么不能直接回 `metadata.json` 的 `login_methods` ──────────
/// `metadata.json` 里的 `login_methods` 是 native 的**静态**形态
/// （`{kind:"browser"|"token", button/label, placeholder, extra_fields}`），
/// 而 wasm / 脚本插件的登录方式走**动态契约**：网关
/// `api/session.rs::read_login_methods` 在 `dynamic_login(provider)` 为真时
/// （wasm 包恒为真，见 `rpc.rs:252`）调 `admin.action=auth.methods`，并把结果按
/// `LoginMethodsMetadata` 解析 —— 每条必须有 `methodIndex`，`type` 只能是
/// `oauth` / `api` / `sms` / `desktop`。回旧形态会直接 502
/// 「插件返回的登录方式元数据无法解析」，登录面板整个打不开。
///
/// 因此两条登录方式都按新契约申报，**数据源是 `metadata.json` 的
/// `login_methods`**（文案不在 Rust 里抄第二遍，抄了就会漂）：
///   - 0 号 `oauth`：内嵌窗口登录（`browserMode = "plugin"`，**只**走内嵌窗口 ——
///     `start` 回的 `external_browser` 就是 `false`：只有窗口宿主能读到 HttpOnly 的
///     `monkeycode_ai_session`，系统浏览器读到的壳侧拿不到）；
///   - 1 号 `api`：粘贴 session（对应 `accounts::normalize` 的 manual 分支）。
///
/// ── 映射规则 ────────────────────────────────────────────────
/// ```text
///   kind: "browser" → { type: "oauth", label: button, instructions: hint,
///                       browserMode: "plugin", prompts: [] }
///   kind: "token"   → { type: "api", label: label, instructions: placeholder,
///                       prompts: [{key: "token", secret: true}] + extra_fields 各一条 }
///   kind: "desktop" → 不申报（wasm 里没有文件系统），
///                     除非 `wasm.json` 的 requires 含 `desktop.credentials.v1`
/// ```
/// `methodIndex` 按输出顺序从 0 编号（网关要求唯一，见 `session.rs:279-284`）。
///
/// ── 为什么 `browserMode` 是 `plugin` 而不是 `choice` ─────────
/// 网关的取值语义里 `plugin` = 只在插件内嵌窗口打开。本家的会话 cookie 是
/// HttpOnly，交系统浏览器打开则壳侧读不到 cookie，登录必然收不到回调。
pub fn methods() -> Value {
    let metadata: Value = serde_json::from_str(crate::METADATA).unwrap_or(Value::Null);
    let mut methods: Vec<Value> = Vec::new();
    if let Some(entries) = metadata.get("login_methods").and_then(Value::as_array) {
        for entry in entries {
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
            let method = match kind {
                "browser" => browser_method(entry, methods.len() as u64),
                "token" => token_method(entry, methods.len() as u64),
                // 本机导入读的是桌面端的文件，wasm 沙箱里没有；申报了只会让界面
                // 给出一个点了就失败的入口（`accounts::normalize` 也如实拒绝）
                "desktop" if requires("desktop.credentials.v1") => {
                    desktop_method(entry, methods.len() as u64)
                }
                // 本包 `login_methods` 里没有 sms 类方式，`wasm.json` 也没有
                // `login.sms.v1`：不产出 `type: "sms"`
                _ => continue,
            };
            methods.push(method);
        }
    }
    json!({ "methods": methods })
}

/// `kind: "browser"` → `oauth`（只走内嵌窗口，见上面 doc 的最后一段）。
fn browser_method(entry: &Value, index: u64) -> Value {
    json!({
        "methodIndex": index,
        "type": "oauth",
        "label": text_of(entry, "button"),
        "instructions": text_of(entry, "hint"),
        "browserMode": "plugin",
        "prompts": [],
    })
}

/// `kind: "token"` → `api`（一条主凭据 + `extra_fields` 各一条可选输入）。
fn token_method(entry: &Value, index: u64) -> Value {
    let label = text_of(entry, "label");
    let placeholder = text_of(entry, "placeholder");
    let mut prompts: Vec<Value> = vec![json!({
        "key": "token",
        "type": "text",
        "label": label.clone(),
        "placeholder": placeholder.clone(),
        "secret": true,
    })];
    if let Some(extras) = entry.get("extra_fields").and_then(Value::as_array) {
        for extra in extras {
            let key = text_of(extra, "key");
            // 键名会被网关逐字校验（`session.rs:325-333`），空键或非法键直接丢：
            // 一条不合法的字段会让整份清单 502
            if !valid_key(&key) {
                continue;
            }
            let extra_label = {
                let label = text_of(extra, "label");
                if label.is_empty() { key.clone() } else { label }
            };
            prompts.push(json!({
                "key": key,
                "type": "text",
                "label": extra_label,
                "placeholder": text_of(extra, "placeholder"),
                "optional": true,
            }));
        }
    }
    json!({
        "methodIndex": index,
        "type": "api",
        "label": label,
        "instructions": placeholder,
        "prompts": prompts,
    })
}

/// `kind: "desktop"` → `desktop`（只在申报了 `desktop.credentials.v1` 时才会走到）。
///
/// 网关对这条方式的校验很严（`session.rs:359-362`）：必须 `localOnly` +
/// `browserMode = "none"`、不能有回调、不能有输入字段。
fn desktop_method(entry: &Value, index: u64) -> Value {
    json!({
        "methodIndex": index,
        "type": "desktop",
        "label": text_of(entry, "button"),
        "instructions": text_of(entry, "hint"),
        "browserMode": "none",
        "localOnly": true,
        "prompts": [],
    })
}

/// 取一个字符串字段（缺字段 / 类型不对给空串：这些文案在 `metadata.json` 里都是可选的）。
fn text_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 网关对 `prompts[].key` 的要求（`session.rs:325-333`）：字母开头，其余字母数字与 `_` `-`。
fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }
    let mut bytes = key.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// `wasm.json` 的 `requires` 里是否申报了这条能力。
fn requires(capability: &str) -> bool {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap_or(Value::Null);
    manifest
        .get("requires")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(capability)))
}

/// `login.start`：打开国际站登录页，等宿主把会话 cookie 交回。
pub fn start(params: &Value) -> Result<Value> {
    // `api` 方式由账号表单提交（`account.normalize`），不该走到这里
    if params["payload"]["methodIndex"].as_u64().is_some_and(|index| index != 0) {
        return Err(Error::http(400, "此登录方式应通过账号表单提交"));
    }
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .ok_or_else(|| Error::new("主程序未分配登录流程"))?;
    let mut hosts: Vec<Value> = Vec::with_capacity(region::LOGIN_HOSTS.len());
    for host in region::LOGIN_HOSTS {
        hosts.push(Value::String(host.to_string()));
    }
    Ok(json!({
        "flow": flow,
        "url": format!("{}/login", region::SITE_ORIGIN),
        "instructions": "请在桌面内嵌窗口完成官方登录和验证码，成功后自动添加账号；浏览器面板请改用粘贴 session。",
        // 0 = 回调型流程：宿主不要轮询，等回调
        "poll_interval_ms": 0,
        // 内嵌窗口：宿主要从窗口的 Cookie 存储读 HttpOnly 的 session
        "external_browser": false,
        "allowed_hosts": Value::Array(hosts),
    }))
}

/// `login.poll`：回调型流程不轮询。
///
/// 返回「还在等」而不是报「不支持」：宿主若因为某种原因仍然问了一次（旧版本
/// 的兼容路径），回一个 pending 不会中断流程；而报错会把一条正常的登录打成失败。
pub fn poll(_params: &Value) -> Result<Value> {
    Ok(json!({
        "state": "pending",
        "hint": "在弹出的窗口里完成登录，成功后会自动收下账号",
    }))
}

/// `login.cancel`：无本地状态要清（登录任务与 flow 都在宿主侧）。
pub fn cancel(_params: &Value) -> Result<Value> {
    Ok(Value::Null)
}

/// `login.callback`：宿主交回的会话 → 复核 → 账号。
pub fn callback(params: &Value) -> Result<Value> {
    let code = params["code"].as_str().map(str::trim).unwrap_or("");
    let url = params["url"].as_str().map(str::trim).unwrap_or("");
    let raw = if code.is_empty() { url } else { code };
    if raw.len() > MAX_CALLBACK_LENGTH {
        return Ok(failed("MonkeyCode 登录凭证过长，请重新登录"));
    }
    let (session, expires_at) = match session_from_callback(raw) {
        Ok(value) => value,
        Err(message) => return Ok(failed(&message)),
    };
    let mut verified = match login::verify_session(&session, None) {
        Ok(verified) => verified,
        Err(error) => return Ok(failed(&error.message)),
    };
    if let Some(expiry) = expires_at {
        // 上游给的到期时刻不能被放大：最多按本家的 30 天硬限制算。
        let ceiling = sdk::now().saturating_add(SESSION_TTL_MS);
        verified["expiresAt"] = json!(expiry.min(ceiling));
    }
    Ok(json!({ "state": "done", "account": accounts::account_of(&verified, "web", None) }))
}

/// 从回调内容里取 `(session, expiresAt)`。
///
/// 两种形态（见模块头）：JSON `{session, expiresAt}`（native 的唯一形态）与
/// 整行 Cookie / 裸 session（宿主直接交回 Cookie 头时）。
fn session_from_callback(raw: &str) -> std::result::Result<(String, Option<i64>), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("登录窗口没有捕获到 MonkeyCode 登录态，请重新发起登录".to_string());
    }
    if raw.starts_with('{') {
        let parsed: Value = serde_json::from_str(raw)
            .map_err(|_| "MonkeyCode 登录凭证格式无效".to_string())?;
        let session = parsed
            .get("session")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        if session.is_empty() {
            return Err("MonkeyCode 登录凭证缺少 session".to_string());
        }
        let expires_at = parsed.get("expiresAt").and_then(Value::as_i64);
        if expires_at.is_some_and(|expiry| expiry <= sdk::now()) {
            return Err("MonkeyCode 登录凭证已经过期，请重新登录".to_string());
        }
        return Ok((session, expires_at));
    }
    let session = login::normalize_session(raw);
    if session.is_empty() {
        return Err(
            "登录窗口没有捕获到有效的 monkeycode_ai_session，请重新发起登录".to_string(),
        );
    }
    Ok((session, None))
}

/// 登录失败的返回（宿主据此把登录任务标记为失败）。
fn failed(message: &str) -> Value {
    json!({ "state": "failed", "message": message })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requires_a_host_assigned_flow() {
        assert!(start(&json!({})).is_err());
        assert!(start(&json!({ "flow": "  " })).is_err());
        // `api` 方式（粘贴 session）不该走登录窗口
        assert!(start(&json!({ "flow": "login_abc", "payload": { "methodIndex": 1 } })).is_err());
        let value = start(&json!({ "flow": "login_abc" })).unwrap_or(Value::Null);
        assert_eq!("login_abc", value["flow"].as_str().unwrap_or_default());
        assert_eq!(0, value["poll_interval_ms"].as_u64().unwrap_or(1));
        assert_eq!(false, value["external_browser"].as_bool().unwrap_or(true));
        assert_eq!(
            "https://monkeycode-ai.net/login",
            value["url"].as_str().unwrap_or_default()
        );
        let hosts = value["allowed_hosts"].as_array().cloned().unwrap_or_default();
        // native `Region::Intl` 的 `login_hosts()`：站点 + GitHub + Google 三条
        assert_eq!(3, hosts.len());
        assert!(hosts.iter().any(|host| host.as_str() == Some("github.com")));
        assert!(hosts
            .iter()
            .any(|host| host.as_str() == Some("accounts.google.com")));
    }

    #[test]
    fn callback_reads_json_and_cookie_forms() {
        let json_ok = session_from_callback(r#"{"session":"abc123"}"#).unwrap_or_default();
        assert_eq!("abc123", json_ok.0);
        assert_eq!(None, json_ok.1);
        // 上游明确给了个过去的到期时刻 → 必须报「已过期」，不能静默接受。
        // 用 0 而不是 1：单测跑在宿主 target 上时 `sdk::now()` 拿不到宿主时钟
        // （返回 0），只有 0 在两种目标下都稳定落入「已过期」。
        assert!(session_from_callback(r#"{"session":"abc123","expiresAt":0}"#).is_err());
        let cookie = session_from_callback("Cookie: monkeycode_ai_session=abc123")
            .unwrap_or_default();
        assert_eq!("abc123", cookie.0);
        assert_eq!(None, cookie.1);
        assert!(session_from_callback("").is_err());
        assert!(session_from_callback("foo=1; bar=2").is_err());
        assert!(session_from_callback("{bad json}").is_err());
    }

    #[test]
    fn callback_failure_is_a_state_not_an_error() {
        let value = callback(&json!({ "flow": "login_a", "code": "" })).unwrap_or(Value::Null);
        assert_eq!("failed", value["state"].as_str().unwrap_or_default());
        assert!(value["message"].as_str().unwrap_or("").contains("登录"));
    }

    /// 登录方式必须是**动态契约**的形态：网关按 `LoginMethodsMetadata` 解析，
    /// 每条要有 `methodIndex`，`type` 只能是 oauth / api / sms / desktop。
    #[test]
    fn methods_follow_the_dynamic_login_contract() {
        let value = methods();
        let methods_list = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(2, methods_list.len());
        let first = methods_list.first().cloned().unwrap_or(Value::Null);
        assert_eq!(0, first["methodIndex"].as_u64().unwrap_or(9));
        assert_eq!("oauth", first["type"].as_str().unwrap_or(""));
        // 只有内嵌窗口能读到 HttpOnly 的 session，不回退系统浏览器
        assert_eq!("plugin", first["browserMode"].as_str().unwrap_or(""));
        assert!(first["prompts"].as_array().is_some_and(|prompts| prompts.is_empty()));
        // label / instructions 来自 metadata.json 的 button / hint
        assert_eq!("网页登录", first["label"].as_str().unwrap_or(""));
        assert!(!first["instructions"].as_str().unwrap_or("").is_empty());

        let second = methods_list.get(1).cloned().unwrap_or(Value::Null);
        assert_eq!(1, second["methodIndex"].as_u64().unwrap_or(9));
        assert_eq!("api", second["type"].as_str().unwrap_or(""));
        let prompts = second["prompts"].as_array().cloned().unwrap_or_default();
        assert_eq!(2, prompts.len());
        // 主凭据键名是 `token`；`accounts::normalize` 的 `pick` 认它
        // （`&["session", "accessToken", "token"]`），粘贴入口照旧能落库
        assert_eq!("token", prompts.first().cloned().unwrap_or(Value::Null)["key"]
            .as_str()
            .unwrap_or(""));
        // `extra_fields` 的那条带着 `optional`
        let extra = prompts.get(1).cloned().unwrap_or(Value::Null);
        assert_eq!("imageId", extra["key"].as_str().unwrap_or(""));
        assert_eq!(true, extra["optional"].as_bool().unwrap_or(false));
        assert_eq!(true, prompts.first().cloned().unwrap_or(Value::Null)["secret"]
            .as_bool()
            .unwrap_or(false));
    }

    /// 索引必须从 0 开始且唯一（网关 `session.rs:279-284` 直接 502 重复索引）。
    #[test]
    fn method_index_is_unique_from_zero() {
        let value = methods();
        let methods_list = value["methods"].as_array().cloned().unwrap_or_default();
        for (index, method) in methods_list.iter().enumerate() {
            assert_eq!(index as u64, method["methodIndex"].as_u64().unwrap_or(9));
        }
    }

    /// 网关对 prompt 键名的规则（`session.rs:325-333`）。
    #[test]
    fn prompt_keys_pass_the_gateway_rule() {
        assert!(valid_key("token"));
        assert!(valid_key("imageId"));
        assert!(!valid_key(""));
        assert!(!valid_key("1token"));
        assert!(!valid_key(&"a".repeat(65)));
        // 本包没申报 desktop.credentials.v1、也没有 sms
        assert!(!requires("desktop.credentials.v1"));
        assert!(!requires("login.sms.v1"));
    }
}
