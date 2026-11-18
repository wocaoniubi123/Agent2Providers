//! 登录方法的接线（`login.start` / `login.poll` / `login.cancel` / `login.callback`）。
//!
//! 小浣熊是**回调型**网页登录：`login.start` 返回授权地址且
//! `poll_interval_ms = 0`（= 不要轮询），用户在浏览器里登录后官方页面跳
//! `office-raccoon://auth/callback?code=…&state=…`，宿主把回调交给
//! `login.callback` 换凭证。
//!
//! ── 与 native 的差别：state 存哪 ───────────────────────────
//! native 侧把 state 塞进返回的 `flow` 字段里（`flow = state`），回调时从
//! `callback.flow` 取回来比对。wasm 侧的 flow 由宿主分配（协议要求回调时原样
//! 带回），插件不能改写它的含义，所以 state 另存一份：宿主的**登录作用域**
//! 状态区（`state.get/compare_exchange`，`scope: login`）。语义不变：
//! 一次登录一个 state，回调时必须逐字命中。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::oauth;

/// 登录作用域里的键与版本。
const LOGIN_KEY: &str = "authorization";
const LOGIN_SCHEMA: u32 = 1;
/// state 的有效期（10 分钟：够用户走完登录页，又不至于长期留着一个可用 state）。
const LOGIN_TTL_MS: i64 = 600_000;

/// `auth.methods`：网关要的**动态登录方式清单**。
///
/// ── 为什么形状必须逐键给全 ──────────────────────────────────
/// wasm 包的 `dynamic_login()` 在网关恒为 true：网关把本函数的返回值直接
/// 反序列化成 `LoginMethodsMetadata`（`api/session.rs` 的 `read_login_methods`，
/// 数组会被包成 `{"methods": […]}`）。元素缺 `methodIndex` / `type` / `label`
/// 或 `methodIndex` 重复，立刻 502「插件返回的登录方式元数据无法解析」或
/// 「插件登录方式索引无效或重复」—— 具体表现是**添加账号面板整片打不开**，
/// 而网关不会回退到旧入口。所以这里按契约给键，不能回 `metadata.json` 里那份
/// `{kind, button, hint}`。
///
/// ── 三条映射（与 `metadata.json` 的 `login_methods` 逐条对应）──
///   0. `browser`「网页登录」   → `type: "oauth"`
///   1. `token`  「登录态 JSON」→ `type: "api"`（`extra_fields` 是空数组，没有补充字段）
///   2. `desktop`「导入本机登录态」→ **不输出**
///
/// ── 第 2 条为什么不输出 ────────────────────────────────────
/// 本包 `wasm.json` 的 requires 里**没有** `desktop.credentials.v1`，网关对
/// `type: "desktop"` 的校验必然失败（`session.rs:359`：无该能力 → 502
/// 「插件本机导入契约无效」）。插件侧也确实没有文件系统（见 `lib.rs` 模块头第 1 条），
/// 与其输出一条注定 502 的方式，不如只给网页登录与粘贴两条。
///
/// ── `browserMode` 取 `choice` 的依据 ────────────────────────
/// 本包是**回调型**网页登录：`start` 返回 `poll_interval_ms = 0`（宿主不轮询）、
/// 登录完成后由 `login.callback` 用 `office-raccoon://auth/callback` 里的 code
/// 换凭证。回调型在网关的取法是 `choice`（用户可选内嵌窗口或系统浏览器），
/// 与 atomcode / qoder 这两个已通过的包取法相同；`start` 没有 `login_ui`
/// 声明可抄，故按回调型取 `choice` 而不是 `external`。
///
/// `manualCallback` 显式写 `false`：回调由宿主按 `office-raccoon://` 收回，
/// 不需要用户复制回调地址（`manualCallback` 的语义就是「要不要手动粘贴」，
/// 写成 `true` 会让界面弹出一个根本没有内容可填的输入框）。
///
/// ── 文案来源 ────────────────────────────────────────────────
/// `label` / `instructions` / `placeholder` 全部取 `metadata.json` 的原文。
/// `locale` 参数按网关调用约定保留（网关传 `params["locale"]`），当前元数据
/// 只有中文一份，因此不参与取值。
pub fn login_methods(_locale: &str) -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "oauth",
            "label": "网页登录",
            "instructions": "打开小浣熊官方登录页，登录后自动回填账号",
            "prompts": [],
            "browserMode": "choice",
            "manualCallback": false,
        },
        {
            "methodIndex": 1,
            "type": "api",
            "label": "登录态 JSON",
            "instructions": "粘贴 auth.json 的内容，或直接粘贴 accessToken",
            "prompts": [
                {
                    "key": "token",
                    "type": "text",
                    "label": "登录态 JSON",
                    "placeholder": "粘贴 auth.json 的内容，或直接粘贴 accessToken",
                    "secret": true,
                },
            ],
        },
    ] })
}

/// `login.start`：给授权地址并记下本次 state。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("");
    if !method.is_empty() && method != "browser" {
        return Err(Error::http(
            400,
            format!("小浣熊不支持这种登录方式：{method}"),
        ));
    }
    let flow = params["flow"].as_str().unwrap_or("").to_string();
    if flow.is_empty() {
        return Err(Error::new("主程序未分配登录流程"));
    }
    let state = oauth::new_login_state();
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    if !sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        json!({ "state": state, "flow": flow }),
        LOGIN_TTL_MS,
    )? {
        return Err(Error::new("登录状态已变化，请重新发起"));
    }
    Ok(json!({
        "flow": flow,
        "url": oauth::build_authorize_url(&state),
        "instructions": "在打开的页面里完成登录，成功后会自动回到应用",
        // 0 = 回调型流程：宿主不要轮询，等回调
        "poll_interval_ms": 0,
        "external_browser": true,
        "allowed_hosts": ["xiaohuanxiong.com".to_string()],
    }))
}

/// `login.poll`：回调型流程不轮询。
///
/// 这里返回「还在等」而不是报「不支持」：宿主若因为某种原因仍然问了一次
/// （旧版本的兼容路径），回一个 pending 不会中断流程；而报错会让界面把一条
/// 正常的登录打成失败。`poll_interval_ms = 0` 时宿主不会再问第二次。
pub fn poll(params: &Value) -> Result<Value> {
    let _ = params;
    Ok(json!({
        "state": "pending",
        "hint": "在打开的页面里完成登录，成功后会自动回到应用",
    }))
}

/// `login.cancel`：清掉本次 state（用户取消或窗口关闭）。
pub fn cancel(params: &Value) -> Result<Value> {
    let _ = params;
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    // 写不回也不影响正确性：state 过期后回调会因「登录状态已过期」被拒。
    let _ = sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        Value::Null,
        1_000,
    );
    Ok(Value::Null)
}

/// `login.callback`：用回调里的一次性 code 换凭证。
///
/// ── state 校验为什么在这里再做一次 ─────────────────────────
/// 宿主那一侧已经比对过回调里的 state（它记着发起时那一个），但插件这一侧是
/// **真正拿 code 去换凭证**的地方 —— 多一道校验零成本，而漏掉它的后果是
/// 「用别人的 code 换来的凭证写进你的账号库」。
pub fn callback(params: &Value) -> Result<Value> {
    let expected = stored_state();
    if expected.is_empty() {
        return Ok(json!({
            "state": "failed",
            "message": "登录状态已过期或已被取消，请重新发起网页登录",
        }));
    }
    // `code` 与 `url` 两种入口给的形态不同：前者是纯 code，后者可能是
    // 整条 `office-raccoon://auth/callback?code=…&state=…`。
    let code_field = params["code"].as_str().unwrap_or("").trim().to_string();
    let url_field = params["url"].as_str().unwrap_or("").trim().to_string();
    let raw = if url_field.is_empty() {
        code_field.clone()
    } else {
        url_field.clone()
    };
    let code = if raw.contains("code=") {
        match oauth::parse_callback_code(&raw, &expected) {
            Ok(code) => code,
            Err(error) => {
                return Ok(json!({ "state": "failed", "message": error.message }));
            }
        }
    } else {
        code_field.trim().to_string()
    };
    if code.is_empty() {
        return Ok(json!({
            "state": "failed",
            "message": "回调里没有授权码，请重新发起登录",
        }));
    }
    match oauth::exchange_code(&code, &expected) {
        Ok(account) => {
            // 换成了就立刻作废 state：同一个 code 不能被用第二次。
            let _ = clear_state();
            Ok(json!({ "state": "done", "account": account }))
        }
        Err(error) => Ok(json!({ "state": "failed", "message": error.message })),
    }
}

/// 读出发起时记下的 state（读不到给空串）。
fn stored_state() -> String {
    sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)
        .ok()
        .filter(|snapshot| snapshot.compatible)
        .and_then(|snapshot| snapshot.value.get("state").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default()
}

/// 作废当前登录 state。
fn clear_state() -> Result<()> {
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    let _ = sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        Value::Null,
        1_000,
    )?;
    Ok(())
}
