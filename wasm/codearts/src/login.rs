//! 网页登录：OAuth 授权码 + PKCE + DPoP，**监听本机回调与换证都在宿主里**。
//!
//! ── 为什么插件不自己登录 ────────────────────────────────────
//! native 版 `login.rs` 会自绑一个 loopback 端口（授权页只认我们给的 `port`，
//! 回调路径由它自己拼成 `http://127.0.0.1:<port>/oauth/callback`），再用 P-256
//! 私钥签 DPoP 证明去换令牌。wasm 插件两条都做不到：没有 socket（监听不了端口，
//! 而回调是**浏览器发起**的入站连接），也没有椭圆曲线库。
//!
//! 宿主侧 `codearts.login.*` 就是这套链的宿主版实现（`login.codearts.v1`）：
//! 它绑端口、收回调、307 跳转、试 verifier、必要时走 ticket 兜底、最后把材料交给
//! `EnrollmentInput`。插件只做三件事：发起、轮询、取消 —— 并且**不碰任何凭据
//! 材料**（那是宿主的进件通道，插件拿不到也不该拿）。
//!
//! ── 两次回调 ────────────────────────────────────────────────
//! portal 先带 `secret` + `redirect` 回来一次并要求 307 跳到它给的 redirect，
//! 随后再带 `code` 回来。远程面板场景（网关在另一台机器上）用户把地址栏里那条
//! localhost 地址改成网关地址再走一遍，粘回来的是整条地址 —— 两条都由宿主接。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// 登录方法清单（`admin.action = auth.methods`）：**动态契约**那一条通道的答案。
///
/// ── 为什么不能把 `metadata.json` 的 `login_methods` 直接回出去 ──────
/// `metadata.json` 里那份是 native 的**静态**形态（`{kind:"browser"|"token",
/// button/label, placeholder, extra_fields}`）。wasm 包的登录方式走动态契约：网关
/// `api/session.rs::read_login_methods` 在 `dynamic_login(provider)` 为真时（wasm
/// 包恒为真）调 `admin.action = auth.methods`，把结果按 `LoginMethodsMetadata`
/// 反序列化 —— 每条的 `type` 只能是 `oauth` / `api` / `sms` / `desktop`，
/// `methodIndex` 必须唯一。回旧形态（`type:"browser"`）直接 502
/// 「插件返回的登录方式元数据无法解析」，添加账号面板整个打不开。
///
/// 条目与 `metadata.json` 的 `login_methods` 一一对应：
///   - 0 号 `oauth`：网页登录（监听端口与换证都在宿主里，见模块头）；
///   - 1 号 `api`：粘贴 AK/SK —— `prompts[].key` 必须是 `account.normalize`
///     真正读的那几个字段名，面板提交的 `inputs` 会原样落进
///     `source.payload.inputs`，键名对不上就会报「缺少 access_key_id」。
///
/// 文案只维护简体中文一套：`locale` 由网关每次传入（zh-CN / en / ja / ko /
/// pt-BR / zh-Hant），补多语言时在这个函数里分叉即可，条目结构不受影响。
pub fn methods(_locale: &str) -> Value {
    json!({ "methods": [
        { "methodIndex": 0, "type": "oauth", "label": "网页登录",
          "prompts": [], "browserMode": "choice",
          "instructions": "打开华为云授权页，完成后自动收下账号" },
        { "methodIndex": 1, "type": "api", "label": "登录凭据", "prompts": [
            { "key": "access_key_id", "type": "text", "label": "access_key_id", "secret": true },
            { "key": "secret_access_key", "type": "text", "label": "secret_access_key", "secret": true },
            { "key": "security_token", "type": "text", "label": "security_token", "secret": true, "optional": true },
            { "key": "domain_id", "type": "text", "label": "domain_id", "optional": true },
            { "key": "user_id", "type": "text", "label": "user_id", "optional": true },
            { "key": "expiration", "type": "text", "label": "到期时间（RFC3339）", "optional": true }
          ],
          "instructions": "粘贴账号的临时 AK/SK/STS；缺 refresh_token 时约一小时后需要重新登录。" }
    ] })
}

/// `login.start`。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    if method != "browser" {
        // 凭据型登录走 `account.normalize`（表单提交），不是流程
        return Err(Error::http(400, "此登录方式应通过账号表单提交"));
    }
    // 宿主只认「网页登录」这一档（methodIndex 缺省或 1）
    let value = sdk::host(
        "codearts.login.start",
        json!({ "method": "browser", "payload": { "methodIndex": 1 } }),
    )?;
    let flow = value["flow"]
        .as_str()
        .filter(|flow| !flow.trim().is_empty())
        .ok_or_else(|| Error::http(502, "CodeArts 登录没有返回流程标识"))?
        .to_string();
    Ok(json!({
        "flow": flow,
        "url": value["url"].clone(),
        "poll_interval_ms": value["poll_interval_ms"].as_i64().unwrap_or(1500),
        "instructions": value["instructions"]
            .as_str()
            .unwrap_or("在打开的页面里完成华为云账号登录，完成后会自动收下账号"),
        "external_browser": value["external_browser"].as_bool().unwrap_or(true),
        "allowed_hosts": value["allowed_hosts"].clone(),
    }))
}

/// `login.poll`。
pub fn poll(params: &Value) -> Result<Value> {
    let flow = flow_of(params)?;
    sdk::host("codearts.login.poll", json!({ "flow": flow }))
}

/// `login.cancel`（没有流程标识时什么都不做 —— 取消本来就是幂等的）。
pub fn cancel(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("").trim().to_string();
    if flow.is_empty() {
        return Ok(Value::Null);
    }
    sdk::host("codearts.login.cancel", json!({ "flow": flow })).map(|_| Value::Null)
}

/// `login.callback`：远程面板粘回来的那条完整回调地址。
pub fn callback(params: &Value) -> Result<Value> {
    let flow = flow_of(params)?;
    let url = params["url"]
        .as_str()
        .or_else(|| params["code"].as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::http(400, "CodeArts 登录回调缺少地址"))?;
    sdk::host("codearts.login.callback", json!({ "flow": flow, "url": url }))
}

/// 流程标识：宿主分配的 `codearts_login_…`。
fn flow_of(params: &Value) -> Result<String> {
    params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))
}
