//! WorkBuddy 的浏览器登录，改造成插件协议的「轮询型」。
//!
//! ── 链路（四步，对照网关 `core::login` 的 `login_interactive`）─────
//! ```text
//!   ① POST {endpoint}/v2{prefix}/auth/state?platform=<platform>   （匿名）
//!        → data.state + data.authUrl
//!   ② 用户在浏览器里打开 authUrl 完成登录
//!   ③ GET  {endpoint}/v2{prefix}/auth/token?state=<state>          （匿名）
//!        → accessToken / refreshToken / expiresIn / refreshExpiresIn
//!        未完成时上游回 code=11217，继续轮询
//!   ④ GET  {endpoint}/v2{prefix}/account                           （Bearer）
//!        → 账号详情（失败不影响登录，回退用 ⑤ 的列表）
//!   ⑤ GET  {endpoint}/v2{prefix}/accounts                          （Bearer）
//!        → data.accounts[]
//! ```
//!
//! ④⑤ 两步只为**补齐昵称等资料**：身份本身在 token 里（`sub`），所以两步全挂时
//! 登录仍然成功（三级兜底见 [`account_from_token_claims`]）。
//!
//! ── 与网关那份的差别（迁移时改的）───────────────────────────
//! | 网关 | 插件 |
//! |---|---|
//! | `login_interactive` 起 spawn 任务后 while 轮询 | [`start`] 只做 ①②，[`poll`] 每次轮询**一次** |
//! | `store.add_account(&session, …)` | 返回 `NormalizedAccount`，由网关落库 |
//!
//! ── 流程状态放哪 ────────────────────────────────────────────
//! 每次轮询都要知道「打哪个 state、哪个端点」。native 放进程内的表里；wasm 实例
//! 不保证跨调用存活，所以放宿主的状态存储（`state.get` / `state.compare_exchange`
//! 作用域 `login`，键 `authorization`，schema 1，TTL 10 分钟）。
//!
//! ── 端点覆盖 ────────────────────────────────────────────────
//! native 读 `WORKBUDDY_ENDPOINT` / `WORKBUDDY_PREFIX_PATH` 环境变量；wasm 里换成
//! 设置项 `endpoint` / `prefixPath`（见 [`crate::endpoints::Context::current`]）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::account;
use crate::auth;
use crate::contract;
use crate::endpoints::{Context, SERVER_CODES_RETRY_FETCH_ACCOUNT};
use crate::httpio;
use crate::util;

/// 轮询间隔（与网关 `LOGIN_POLL_INTERVAL_MS` 同值：桌面端 SIGN_IN_FETCH_INTERVAL）。
pub const POLL_INTERVAL_MS: u64 = 3_000;

/// 登录流程状态在宿主里的键与 schema。
const LOGIN_KEY: &str = "authorization";
const LOGIN_SCHEMA: u32 = 1;
/// 流程保留时长（10 分钟 —— 比网关「5 分钟总超时」宽松，更老的 flow 不可能还有人问）
const FLOW_KEEP_MS: i64 = 10 * 60_000;

/// 发起登录：问上游要 state + authUrl。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("");
    if !matches!(method, "" | "browser" | "web") {
        return Err(Error::http(
            400,
            format!("WorkBuddy 不支持登录方式「{method}」（可用：browser）"),
        ));
    }
    let context = Context::current();
    let headers = contract::login_headers(&context.authority(), true);
    let url = context.auth_url(&format!(
        "/auth/state?platform={}",
        util::encode_component(contract::platform())
    ));
    let response = httpio::send("POST", &url, &headers, Some(&json!({})))
        .map_err(|error| httpio::transport_error("登录接口请求", error))?;
    let data = httpio::unwrap_response(&response, "auth/state")?;
    let state = util::text_at(&data, &["state", "authState"]);
    let auth_url = data
        .get("authUrl")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if state.is_empty() || auth_url.is_empty() {
        return Err(Error::http(502, "auth/state 未返回 state/authUrl，无法发起登录"));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if flow.is_empty() {
        return Err(Error::new("主程序未分配登录流程"));
    }
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    let saved = json!({
        "state": state,
        "endpoint": context.base_url,
        "prefix": context.prefix,
        "platform": context.platform,
        "started_at": util::now_ms(),
    });
    if !sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        saved,
        FLOW_KEEP_MS,
    )? {
        return Err(Error::new("登录状态已变化，请重新发起"));
    }
    Ok(json!({
        // 必须回**宿主分配的** flow：声明了 `login.interaction.v1` 时宿主会逐字
        // 比对（`plugin_host/wasm/host.rs:428-432`「交互式登录必须使用主程序分配的
        // 流程标识」），回上游 state 会让登录窗口直接打不开。上游 state 已经存进
        // 登录状态，`poll` 从那里读，不需要回传。
        "flow": flow,
        "url": auth_url,
        "poll_interval_ms": POLL_INTERVAL_MS,
        "instructions": "在打开的页面里完成登录，完成后本页会自动继续",
        // 授权页在上游域名终结、回调永远不回到本机 —— 由网关轮询收尾
        "external_browser": true,
        "allowed_hosts": allowed_hosts(),
        "login_ui": {
            "browserMode": "choice", "manualCallback": false, "callbackInput": "url",
            "cookieCapture": Value::Null, "captureCallback": false,
        },
    }))
}

/// 轮询一次：拿到 token 就补齐账号资料并返回 `done`。
pub fn poll(_params: &Value) -> Result<Value> {
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
    if !snapshot.compatible {
        return Err(Error::new("登录状态格式已变化，请重新发起"));
    }
    let state = snapshot.value.get("state").and_then(Value::as_str).unwrap_or("");
    if state.is_empty() {
        return Ok(json!({ "state": "failed", "message": "登录流程不存在或已过期，请重新发起" }));
    }
    let started_at = snapshot.value.get("started_at").and_then(Value::as_i64).unwrap_or(0);
    if started_at > 0 && util::now_ms().saturating_sub(started_at) >= FLOW_KEEP_MS {
        return Ok(json!({ "state": "failed", "message": "登录流程已经过期，请重新发起" }));
    }
    let context = Context::make(
        snapshot.value.get("endpoint").and_then(Value::as_str),
        snapshot.value.get("prefix").and_then(Value::as_str),
        snapshot.value.get("platform").and_then(Value::as_str),
        Some(crate::Region::edition_id()),
    );
    let headers = contract::login_headers(&context.authority(), false);
    let url = context.auth_url(&format!("/auth/token?state={}", util::encode_component(state)));
    let pending = || json!({ "state": "pending" });
    let token_data = match httpio::send("GET", &url, &headers, None) {
        Ok(response) => match httpio::unwrap_response(&response, "auth/token") {
            Ok(data) => data,
            // 未完成登录时上游回 code=11217；其余错误也只继续等
            // （轮询期间的一次抖动不该打断用户正在进行的授权）
            Err(_) => return Ok(pending()),
        },
        Err(_) => return Ok(pending()),
    };
    let access_token = token_data
        .get("accessToken")
        .and_then(Value::as_str)
        .unwrap_or("");
    if access_token.is_empty() {
        return Ok(pending());
    }

    // ── 拿到 token：补资料 → 摘表 → 交账号 ─────────────────────
    let _ = sdk::state::compare_exchange(
        sdk::state::Scope::Login,
        LOGIN_KEY,
        LOGIN_SCHEMA,
        snapshot.revision,
        Value::Null,
        1_000,
    );
    let secret = build_secret(&token_data, state, &context);
    let uid = util::pick(&secret, &["uid"]);
    if uid.is_empty() {
        return Ok(json!({
            "state": "failed",
            "message": "登录成功但获取账号信息失败（缺少 uid），请重试",
        }));
    }
    Ok(json!({
        "state": "done",
        "account": {
            "public": account::view(&secret),
            "identity": account::identity(&secret),
            "secret": secret,
            "desktop": false,
        },
    }))
}

/// 取消一条流程（用户点了取消，或网关的总超时到了）。
pub fn cancel(_params: &Value) -> Result<Value> {
    let snapshot = sdk::state::get(sdk::state::Scope::Login, LOGIN_KEY, LOGIN_SCHEMA)?;
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

/// 拿到 token 之后拼出**落库形态**的 secret（扁平键，与存量记录同形）。
///
/// 身份的三步兜底（后一步只在前一步没给出 uid 时生效）：
///   ① `GET /account`（上游刚登录那次最全）
///   ② `/accounts` 列表里「最近登录过的那条」，退而求其次取第一条
///   ③ access token 自己的 JWT 声明（`sub`）
///
/// 第三步是**网络之外**的来源，不能省：前两步都是网络调用，任何一条卡住就会把整轮
/// 登录作废（2026-10-03 实测：国际版授权已成功、token 也拿到了，只因 `login/account`
/// 连了 30 秒没连上，用户看到的就是「缺少 uid」）。
fn build_secret(token_data: &Value, state: &str, context: &Context) -> Value {
    let enriched = auth::with_expires_at(token_data.clone());
    let mut row = Value::Object(serde_json::Map::new());
    if !state.is_empty() {
        if let Ok(data) = fetch_login_account(&enriched, state, context) {
            if data.is_object() {
                row = data;
            }
        }
    }
    let accounts = fetch_accounts(&enriched, context).unwrap_or_default();
    if row.get("uid").and_then(Value::as_str).unwrap_or("").is_empty() {
        row = accounts
            .iter()
            .find(|item| item.get("lastLogin").is_some_and(|value| !value.is_null()))
            .or_else(|| accounts.first())
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    }
    if row.get("uid").and_then(Value::as_str).unwrap_or("").is_empty() {
        if let Some(from_token) = account_from_token_claims(&enriched) {
            row = from_token;
        }
    }
    secret_of(&row, &enriched, context)
}

/// `GET /login/account?state=`（**国际版**；国内版是 `GET /account`）。
///
/// ── 国际版这一段与国内版的三处差别（native `login.rs` 的 region 分叉）──
///   1. 路径带 `state`：`/v2/plugin/login/account?state=<state>`（国内版是
///      `/v2/plugin/account`，不带参数）—— 上游用 state 找回「刚登录的这个身份」；
///   2. 额外带三个「跳过默认身份头」：`X-No-User-Id` / `X-No-Enterprise-Id` /
///      `X-No-Department-Info`（此时手里只有 token，还没有 uid / 企业身份）；
///   3. 其余（12151 未就绪重试、失败不影响登录）与国内版一致。
fn fetch_login_account(
    auth_value: &Value,
    state: &str,
    context: &Context,
) -> Result<Value> {
    let mut headers = bearer_headers(auth_value, context);
    for name in ["X-No-User-Id", "X-No-Enterprise-Id", "X-No-Department-Info"] {
        headers.push((name.to_string(), "true".to_string()));
    }
    let path = format!("/login/account?state={}", util::encode_component(state));
    let url = context.auth_url(&path);
    for attempt in 0..6 {
        let response = httpio::send("GET", &url, &headers, None)
            .map_err(|error| httpio::transport_error("登录账号资料", error))?;
        match httpio::unwrap_response(&response, "account") {
            Ok(data) => return Ok(data),
            Err(error) => {
                // 业务码 12151 = 资料未就绪：等 1 秒再来（最多 6 次）
                let code = error
                    .code
                    .as_deref()
                    .and_then(|text| text.parse::<i64>().ok());
                if code == Some(SERVER_CODES_RETRY_FETCH_ACCOUNT) && attempt < 5 {
                    let _ = sdk::sleep(1_000);
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(Error::http(502, "登录账号资料未就绪"))
}

/// `GET /accounts`（账号列表；失败不影响登录）。
fn fetch_accounts(auth_value: &Value, context: &Context) -> Result<Vec<Value>> {
    let headers = bearer_headers(auth_value, context);
    let url = context.auth_url("/accounts");
    let response = httpio::send("GET", &url, &headers, None)
        .map_err(|error| httpio::transport_error("账号列表", error))?;
    let data = httpio::unwrap_response(&response, "accounts")?;
    Ok(data
        .get("accounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// 企业扩展头 + Bearer。
fn bearer_headers(auth_value: &Value, context: &Context) -> Vec<(String, String)> {
    let session = json!({
        "auth": auth_value,
        "account": auth_value.get("account").unwrap_or(&Value::Null),
    });
    let mut headers = contract::framework_headers(&session, true);
    // 总是带 X-Domain（`auth.domain` 缺省时回退端点 authority）
    let domain = auth_value
        .get("domain")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| context.authority());
    if !domain.is_empty()
        && !headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("X-Domain"))
    {
        headers.push(("X-Domain".to_string(), domain));
    }
    headers
}

/// 从 access token 的 JWT 声明里取账号身份（`uid` + 昵称）。
///
/// 上游签发的是 Keycloak 风格 JWT，`sub` **就是账号主键**（与库里既有记录的 uid
/// 逐字相同，记录 id 形如 `user-<uid>`）。只解 payload、不验签：网关不做鉴权判定，
/// token 能不能用由上游说了算。
fn account_from_token_claims(auth_value: &Value) -> Option<Value> {
    let token = auth_value.get("accessToken").and_then(Value::as_str)?;
    let claims = util::decode_jwt_claims(token)?;
    let uid = util::text_at(&claims, &["sub", "userId", "uid"]);
    if uid.is_empty() {
        return None;
    }
    let mut row = serde_json::Map::new();
    row.insert("uid".to_string(), Value::String(uid));
    let name = util::text_at(&claims, &["nickname", "name", "preferred_username", "email"]);
    if !name.is_empty() {
        row.insert("nickname".to_string(), Value::String(name));
    }
    Some(Value::Object(row))
}

/// 把「资料 + 凭证」摊成扁平 secret。
///
/// 键名与网关 `account_store` 的存量记录逐字相同 —— 插件接手老账号时字段要能对上，
/// 界面列也要能读到。
fn secret_of(row: &Value, auth_value: &Value, context: &Context) -> Value {
    let text = |source: &Value, key: &str| -> String {
        source
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let mut secret = serde_json::Map::new();
    let uid = text(row, "uid");
    secret.insert("uid".to_string(), Value::String(uid.clone()));
    let access_token = text(auth_value, "accessToken");
    secret.insert("accessToken".to_string(), Value::String(access_token.clone()));
    for key in ["refreshToken", "domain", "tokenType"] {
        let value = text(auth_value, key);
        if !value.is_empty() {
            secret.insert(key.to_string(), Value::String(value));
        }
    }
    for key in ["expiresAt", "refreshExpiresAt"] {
        if let Some(value) = auth_value.get(key).filter(|value| !value.is_null()) {
            secret.insert(key.to_string(), value.clone());
        }
    }
    // 展示与组织字段（账号页按这些键渲染）
    let nickname = text(row, "nickname");
    for key in [
        "nickname",
        "type",
        "enterpriseId",
        "enterpriseName",
        "departmentFullName",
        "oneidAccountId",
        "idp",
    ] {
        if let Some(value) = row.get(key).filter(|value| value.is_string()) {
            secret.insert(key.to_string(), value.clone());
        }
    }
    // 端点三项：登录时的上下文就是这次账号的落点（staging / 自建网关也走它）
    secret.insert(
        "endpoint".to_string(),
        Value::String(context.base_url.clone()),
    );
    secret.insert(
        "prefixPath".to_string(),
        Value::String(context.prefix.clone()),
    );
    secret.insert(
        "platform".to_string(),
        Value::String(context.platform.clone()),
    );
    secret.insert(
        "edition".to_string(),
        Value::String(crate::Region::edition_id().to_string()),
    );
    secret.insert(
        "tokenTail".to_string(),
        Value::String(util::token_tail(&access_token)),
    );
    // 名字：昵称 > `账号 <uid 前 8 位>`（与内置 `add_account` 同款兜底）
    let name = if nickname.is_empty() {
        format!("账号 {}", util::truncate_text(&uid, 8))
    } else {
        nickname
    };
    secret.insert("name".to_string(), Value::String(name));
    Value::Object(secret)
}

/// 登录窗口的导航白名单（网关桌面壳 `WORKBUDDY_ALLOWED_HOSTS` 的同义物）。
///
/// 空列表会被网关解释成「不限制」，所以这里必须给全 —— 少一行的症状是「登录窗口
/// 白屏」，而日志上什么也看不出。这些是**浏览器要打开的页面域**，与
/// `wasm.json` 的 `origins`（插件自己发请求的域）不是一回事。
fn allowed_hosts() -> Vec<String> {
    [
        "copilot.tencent.com",
        "staging-copilot.tencent.com",
        "codebuddy.cn",
        "workbuddy.cn",
        "codebuddy.ai",
        "staging-codebuddy.tencent.com",
        "workbuddy.ai",
        "staging.workbuddy.ai",
        "tencent.com",
        "qq.com",
        "wechat.com",
        "weixin.qq.com",
        "tenpay.com",
    ]
    .iter()
    .map(|host| host.to_string())
    .collect()
}

// ─── 登录方式声明（`admin.action = auth.methods`）──────────────

/// `wasm.json`：只读它的 `requires`，判断「本机导入」这类方式能不能申报。
const MANIFEST: &str = include_str!("../wasm.json");

/// 动态登录方式：把 `metadata.json` 的 `login_methods` 逐条映射成网关要的契约。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 网关 `api/session.rs:263-280` 的 `read_login_methods` 对 wasm 包**恒**走
/// `dynamic_login()`（`plugin_host/rpc.rs:252` 对 wasm 恒为真），也就是把
/// `admin.action = auth.methods` 的返回直接按 `LoginMethodsMetadata` 反序列化；
/// 插件返回错误就原样冒泡（`session.rs:553` 明写「不会使用旧版兼容入口」）。
/// 没有这个分支时 `/api/session/login/methods` 回 501「插件不支持此操作」，
/// 添加账号面板整个打不开。
///
/// ── 形状要点（网关逐条硬校验，见 `session.rs:279-370`）────────
///   · `methodIndex` 按输出顺序从 0 编号，同一份清单里唯一；
///   · `type` 只能是 `oauth` / `api` / `sms` / `desktop`；
///   · `oauth` 要带 `browserMode`（`choice` / `external` / `plugin` / `none`）；
///   · `api` 要带 `prompts[]`，键名必须字母开头、只含字母数字与 `_` `-`；
///   · 其余字段都有默认值。
///
/// ── 数据源只有 `metadata.json` ──────────────────────────────
/// 文案不在这里抄第二遍（抄一遍就会与 `metadata.json` 漂移）。映射规则：
/// ```text
///   kind: "browser" → oauth，label = button，instructions = hint，prompts = []
///   kind: "token"   → api，label = label，instructions = placeholder，
///                     prompts = [{key: "token", secret: true}] + extra_fields 各一条
///   kind: "desktop" → 不申报（wasm 里没有文件系统），
///                     除非 `wasm.json` 的 requires 含 `desktop.credentials.v1`
/// ```
///
/// 与国内版（`wasm/workbuddy/`）是同一套映射，但**数据各读各的
/// `metadata.json`**：两包互不引用，改文案时两边都改。
pub fn methods() -> Value {
    let metadata: Value = serde_json::from_str(crate::METADATA).unwrap_or(Value::Null);
    let mut methods: Vec<Value> = Vec::new();
    if let Some(entries) = metadata.get("login_methods").and_then(Value::as_array) {
        for entry in entries {
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
            let method = match kind {
                // 轮询型浏览器登录：`start` 回的 `login_ui.browserMode` 就是
                // `choice`（授权页在上游域名终结，由网关轮询收尾）
                "browser" => browser_method(entry, methods.len() as u64),
                "token" => token_method(entry, methods.len() as u64),
                // 本机导入读的是桌面端的文件，wasm 沙箱里没有；申报了只会让界面
                // 给出一个点了就失败的入口，所以默认不申报
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

/// `kind: "browser"` → `oauth`。
fn browser_method(entry: &Value, index: u64) -> Value {
    json!({
        "methodIndex": index,
        "type": "oauth",
        "label": text_of(entry, "button"),
        "instructions": text_of(entry, "hint"),
        // 与 `start` 回的 `login_ui.browserMode` 同一个值
        "browserMode": "choice",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_hosts_cover_both_login_sites() {
        let hosts = allowed_hosts();
        assert!(hosts.iter().any(|host| host == "copilot.tencent.com"));
        assert!(hosts.iter().any(|host| host == "workbuddy.cn"));
        assert!(!hosts.is_empty());
    }

    #[test]
    fn token_claims_fill_the_uid_gap() {
        // {"sub":"u-1","nickname":"小明"} 的 url-safe base64 payload
        let token = "h.eyJzdWIiOiJ1LTEiLCJuaWNrbmFtZSI6IuWwj-aYjiJ9.s";
        let row = account_from_token_claims(&json!({ "accessToken": token })).unwrap_or(Value::Null);
        assert_eq!(row["uid"], json!("u-1"));
        assert_eq!(row["nickname"], json!("小明"));
    }

    #[test]
    fn secret_carries_the_endpoint_triplet() {
        // 本包的版本上下文（国际版：站点 / platform / 客户端身份都是 intl 那套）
        let context = Context::make(None, None, None, Some("intl"));
        let secret = secret_of(
            &json!({ "uid": "u-1", "nickname": "小明" }),
            &json!({ "accessToken": "abcdef", "refreshToken": "r" }),
            &context,
        );
        assert_eq!(secret["uid"], json!("u-1"));
        assert_eq!(secret["name"], json!("小明"));
        assert_eq!(secret["endpoint"], json!("https://www.workbuddy.ai"));
        assert_eq!(secret["prefixPath"], json!("/plugin"));
        assert_eq!(secret["platform"], json!("workbuddy-ai"));
        assert_eq!(secret["tokenTail"], json!("cdef"));
        assert_eq!(secret["edition"], json!("intl"));
        // 没昵称时按 uid 前 8 位取名
        let secret = secret_of(&json!({ "uid": "5877cabc-99" }), &json!({}), &context);
        assert_eq!(secret["name"], json!("账号 5877cabc"));
    }

    /// 登录方式必须是**动态契约**的形态：网关按 `LoginMethodsMetadata` 解析，
    /// 缺字段 / 类型不对会让 `/api/session/login/methods` 整个 502。
    #[test]
    fn methods_follow_the_dynamic_login_contract() {
        let value = methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        // 本包 `metadata.json` 只有一条 browser 方式
        assert_eq!(1, list.len());
        let first = list.first().cloned().unwrap_or(Value::Null);
        assert_eq!(0, first["methodIndex"].as_u64().unwrap_or(9));
        assert_eq!("oauth", first["type"].as_str().unwrap_or(""));
        // label / instructions 必须与 metadata.json 的 button / hint 一致
        assert_eq!("网页登录", first["label"].as_str().unwrap_or(""));
        assert_eq!(
            "在打开的页面里登录 WorkBuddy 账号，完成后本页会自动继续",
            first["instructions"].as_str().unwrap_or("")
        );
        assert_eq!("choice", first["browserMode"].as_str().unwrap_or(""));
        assert!(first["prompts"].as_array().is_some_and(|prompts| prompts.is_empty()));
    }

    #[test]
    fn method_index_is_unique_from_zero() {
        let value = methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        for (index, method) in list.iter().enumerate() {
            assert_eq!(index as u64, method["methodIndex"].as_u64().unwrap_or(9));
        }
    }

    #[test]
    fn prompt_keys_pass_the_gateway_rule() {
        assert!(valid_key("token"));
        assert!(!valid_key(""));
        assert!(!valid_key("1token"));
        assert!(!valid_key(&"a".repeat(65)));
        // 本包没申报 desktop.credentials.v1，desktop 方式不会被申报
        assert!(!requires("desktop.credentials.v1"));
        assert!(!requires("login.sms.v1"));
    }
}
