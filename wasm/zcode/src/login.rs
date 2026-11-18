//! 网页登录：服务端中介的 **CLI 轮询**流程（native `zcode/oauth.rs` +
//! `zcode/login.rs` 的移植）。
//!
//! ── 与其余各家的最大不同：没有本地回调 ──────────────────────
//! 参考实现把这条链路记为 `startOAuthWithPolling`，并专门写了一句：
//!
//! > No local callback server exists on this path. Building a direct
//! > chat.z.ai/bigmodel authorize URL with a localhost redirect_uri is
//! > rejected upstream (`Redirect URI not registered for this client`).
//!
//! 也就是说**不能**照抄「登记回调端口」那套做法。
//!
//! ── 四步 ────────────────────────────────────────────────────
//! ```text
//!   1. 生成 poll token（32 随机字节的十六进制）—— init 与 poll 都带它做 Bearer
//!   2. POST {zcode}/api/v1/oauth/cli/init   body {"provider": "bigmodel"}
//!      → {flow_id, poll_token, authorize_url, expires_at, poll_interval_sec}
//!   3. 把 authorize_url 补上一个「中转页」参数后交给用户打开 ——
//!      浏览器**不会**回到本机，授权在服务端记完就结束了
//!   4. GET {zcode}/api/v1/oauth/cli/poll/{flow_id}（每 poll_interval_sec 一次）
//!      直到 status 变成 ready → {token, user, bigmodel:{access_token}}
//! ```
//!
//! ── 第 3 步那个「中转页」参数是必须的（别省）─────────────────
//! `authorize_url` 是服务端给的，但直接打开时浏览器最后会跳到一个本机收不到的
//! `zcode://` 协议上，**授权结果不会被服务端记下**，于是 poll 永远停在 pending。
//! 客户端补的是自己那个中转页：
//!
//! ```text
//!   {zcode}/app/oauth/login?redirect=zcode://oauth/callback&app_version={ver}
//! ```
//!
//! 参数名**两地不同**：国际版（zai）是 `redirect_uri`，国内版（bigmodel）是
//! `redirect`。写错一个，对应那一地的登录会静默停在 pending 直到超时 ——
//! 这是本文件最容易出错、且症状最不直观的一处。本包只做国内版（`redirect`）。
//!
//! ── 轮询的错误语义（照抄参考实现，别自己发明）───────────────
//!   - 4xx（**408 / 429 除外**）、信封 `code != 0`、认不出的 status → **致命**；
//!   - 5xx / 网络错误 / 200 但响应体畸形 → **当 pending 处理**（继续轮询），
//!     因为这三类都是「这次没问成」而不是「问成了但被拒」。
//!
//! ── 流程状态放哪 ────────────────────────────────────────────
//! native 放进程内的表（`flow_id` → `CliLogin`）。插件的 `session.put` 就是
//! 「这个插件进程的临时状态」，语义相同且带 TTL（这里按 native 的
//! `FLOW_KEEP_MS = 10 分钟` 给 15 分钟上限，宿主上限是 900 秒）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! `panic = "abort"`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::common::{new_uuid, random_hex_32, text_of, urlencode};
use super::{account, coding_key, http, plan, region};

/// 登录流程的 session 键前缀（国内版自己的命名空间；国际版是 `zcode-intl:`）。
const FLOW_PREFIX: &str = "zcode:login:";

/// 流程条目的 session TTL（宿主上限 900 秒 = 15 分钟）。
const FLOW_TTL_MS: i64 = 900_000;

/// 轮询间隔的兜底值（上游没给 `poll_interval_sec` 时用）。
const DEFAULT_POLL_INTERVAL_SEC: i64 = 3;

/// `auth.methods`：网关要的**动态登录方式清单**。
///
/// ── 为什么形状必须逐键给全 ──────────────────────────────────
/// wasm 包的 `dynamic_login()` 在网关恒为 true：网关把本函数的返回值直接
/// 反序列化成 `LoginMethodsMetadata`（`api/session.rs` 的 `read_login_methods`，
/// 数组会被包成 `{"methods": […]}`）。元素缺 `methodIndex` / `type` / `label`
/// 或 `methodIndex` 重复，立刻 502「插件返回的登录方式元数据无法解析」或
/// 「插件登录方式索引无效或重复」—— 具体表现是**添加账号面板整片打不开**，
/// 而网关不会回退到旧入口。所以这里按契约给键，不能回 `metadata.json` 里那份
/// `{kind, button, hint}`（`admin.rs` 的 `auth.methods` 分支即因它报 502）。
///
/// ── 清单内容（与 `metadata.json` 的 `login_methods` 逐条对应）────
/// 本包只有一条：`browser`「网页登录」→ `type: "oauth"`，`label` 取元数据的
/// `button`，`instructions` 取元数据的 `hint`。
///
/// ── `browserMode` 取 `"external"` 的依据 ────────────────────
/// 本包是 CLI 轮询型登录：`start` 自己就声明 `external_browser: true`，授权页在
/// **上游域名**终结，浏览器的最后一跳是 `zcode://` 中转页 —— 这一步只有系统
/// 浏览器能走完，内嵌窗口收不到自定义协议跳转，`login.poll` 会一直停在 pending
/// 直到超时。回调型（需要用户粘贴回调）才取 `choice`；本包没有回调输入，
/// 故按「外部浏览器型」取 `external`。
///
/// ── 文案来源 ────────────────────────────────────────────────
/// `label` / `instructions` 全部取 `metadata.json` 的原文，与 native 版一致。
/// `locale` 参数按网关调用约定保留（网关传 `params["locale"]`），当前元数据
/// 只有中文一份，因此不参与取值。
pub fn login_methods(_locale: &str) -> Value {
    json!({ "methods": [{
        "methodIndex": 0,
        "type": "oauth",
        "label": "网页登录",
        "instructions": "打开 ZCode 授权页，完成后自动收下账号",
        "prompts": [],
        "browserMode": "external",
        "manualCallback": false,
    }] })
}

/// 一次登录流程的持久状态（存 session）。
struct Flow {
    poll_token: String,
    device_mid: String,
    expires_at: i64,
    poll_interval_sec: i64,
}

impl Flow {
    fn to_json(&self) -> Value {
        json!({
            "pollToken": self.poll_token,
            "deviceMid": self.device_mid,
            "expiresAt": self.expires_at,
            "pollIntervalSec": self.poll_interval_sec,
        })
    }

    fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            poll_token: value.get("pollToken")?.as_str()?.to_string(),
            device_mid: value
                .get("deviceMid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            expires_at: value.get("expiresAt").and_then(Value::as_i64).unwrap_or(0),
            poll_interval_sec: value
                .get("pollIntervalSec")
                .and_then(Value::as_i64)
                .unwrap_or(DEFAULT_POLL_INTERVAL_SEC),
        })
    }
}

/// 发起登录（`login.start`）。
///
/// `method` 目前只有一个取值（`web`，界面上叫「网页登录」）；其余取值如实报错
/// 而不是静默按网页登录处理 —— 静默会让「点了另一个按钮却跑了这套流程」变成
/// 查不出来的事。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("");
    if !matches!(method, "" | "web" | "browser") {
        return Err(Error::http(
            400,
            format!("ZCode 不支持登录方式「{method}」（可用：web）"),
        ));
    }
    let poll_token = random_hex_32().ok_or_else(|| {
        Error::http(502, "本机随机源不可用，无法发起登录（未生成流程令牌）")
    })?;
    let url = format!("{}/api/v1/oauth/cli/init", region::ZCODE_ORIGIN);
    let headers = vec![
        ("authorization".to_string(), format!("Bearer {poll_token}")),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let body = json!({ "provider": region::UPSTREAM_PROVIDER });
    let reply = http::send("POST", &url, &headers, Some(&body))
        .map_err(|error| http::transport_error("ZCode 登录发起失败", &error))?;
    if let Some(message) = envelope_error(&reply.payload) {
        return Err(Error::http(502, message));
    }
    let data = reply
        .payload
        .get("data")
        .ok_or_else(|| Error::http(502, "ZCode 登录发起：响应缺少 data"))?;
    let flow_id = required_str(data, "flow_id")?;
    let authorize_url = required_str(data, "authorize_url")?;
    // expires_at / poll_interval_sec 缺失时给兜底值而不是报错：它们是「调度建议」，
    // 不是凭证本身 —— 为它们失败会让一次本可成功的登录白跑。
    let expires_at = data.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    let poll_interval_sec = data
        .get("poll_interval_sec")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_POLL_INTERVAL_SEC);
    let flow = Flow {
        poll_token,
        device_mid: new_uuid().unwrap_or_default(),
        expires_at,
        poll_interval_sec,
    };
    let key = format!("{FLOW_PREFIX}{flow_id}");
    sdk::session_put(&key, flow.to_json(), FLOW_TTL_MS)
        .map_err(|error| Error::http(502, format!("登录流程保存失败：{}", error.message)))?;
    Ok(json!({
        "flow": flow_id,
        "url": apply_interstitial(&authorize_url),
        "instructions": "在打开的页面里完成授权，完成后本页会自动继续",
        "poll_interval_ms": (poll_interval_sec.max(1) as u64) * 1000,
        // 授权页在**上游域名**终结、回调永远不回到本机 —— 由网关轮询收尾
        "external_browser": true,
        "allowed_hosts": ["zcode.z.ai"],
    }))
}

/// 轮询一次（`login.poll`）。
pub fn poll(params: &Value) -> Result<Value> {
    let flow_id = params["flow"].as_str().unwrap_or("").trim().to_string();
    if flow_id.is_empty() {
        return Ok(failed("登录流程标识缺失，请重新发起"));
    }
    let key = format!("{FLOW_PREFIX}{flow_id}");
    let saved = sdk::session_get(&key).unwrap_or(Value::Null);
    let Some(flow) = Flow::from_json(&saved) else {
        return Ok(failed("登录流程不存在或已过期，请重新发起"));
    };
    let url = format!("{}/api/v1/oauth/cli/poll/{}", region::ZCODE_ORIGIN, flow_id);
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {}", flow.poll_token),
    )];
    let reply = match http::send("GET", &url, &headers, None) {
        Ok(reply) => reply,
        // 网络错误当 pending（模块头）：一次没问成不是「被拒」
        Err(_) => return Ok(pending()),
    };
    // 5xx 当 pending；4xx 里 408（超时）/ 429（限流）也当 pending ——
    // 它们是「这次没问成」，其余 4xx 是「问成了但被拒」
    if reply.status >= 500 || reply.status == 408 || reply.status == 429 {
        return Ok(pending());
    }
    if let Some(message) = envelope_error(&reply.payload) {
        let _ = sdk::session_remove(&key);
        return Ok(failed(message));
    }
    if reply.status >= 400 {
        let _ = sdk::session_remove(&key);
        return Ok(failed(format!(
            "ZCode 登录轮询被拒（HTTP {}）",
            reply.status
        )));
    }
    let Some(data) = reply.payload.get("data") else {
        return Ok(pending());
    };
    let status = data.get("status").and_then(Value::as_str).unwrap_or("");
    match status {
        "ready" => match finish(&flow_id, &flow, data) {
            Ok(account) => {
                let _ = sdk::session_remove(&key);
                Ok(json!({ "state": "done", "account": account }))
            }
            Err(error) => {
                // 流程已用尽：从表里摘掉，让下一次轮询得到「已过期」而不是
                // 反复拿同一个坏令牌去换
                let _ = sdk::session_remove(&key);
                Ok(failed(error.message))
            }
        },
        "failed" => {
            let _ = sdk::session_remove(&key);
            Ok(failed("ZCode 授权被拒绝或已失效，请重新发起登录"))
        }
        // pending / 其它认不出的 status：参考实现把「认不出的 status」记为致命，
        // 这里从宽当 pending —— 上游将来可能新增中间态（例如「已授权待激活」），
        // 把中间态当失败会让登录在升级后的上游上整体不可用；而网关侧有总超时。
        _ => Ok(pending()),
    }
}

/// 取消一条流程（`login.cancel`）。
pub fn cancel(params: &Value) -> Result<Value> {
    let flow_id = params["flow"].as_str().unwrap_or("").trim();
    if !flow_id.is_empty() {
        let _ = sdk::session_remove(&format!("{FLOW_PREFIX}{flow_id}"));
    }
    Ok(Value::Null)
}

/// `status: "ready"` 的响应体 → 落库账号。
///
/// 三个字段来自三个位置（参考实现 `CliPollData`）：
///   - `token` → 套餐 JWT（顶层，不是 `data.jwt`）
///   - `user.user_id` → 上游用户 id
///   - `data.bigmodel.access_token` → 推理访问令牌（键名是**上游的 provider 名**，
///     国内版是 `bigmodel`；读成 `zai` 会得到「缺少 bigmodel.access_token」）
///
/// ── 先把 OAuth 令牌换成推理凭证 ────────────────────────────
/// 轮询给的 `access_token` 直接用于推理必 401，要先换一把编码套餐的 API Key
/// （见 `coding_key` 的模块头）。换取失败即登录失败：不落半条「能领套餐但发不出
/// 请求」的账号。国内版那一步比国际版短：**没有** `POST /api/auth/z/login`，
/// 且拿不到 secretKey 时退回单段 API Key 就算成功。
fn finish(flow_id: &str, flow: &Flow, data: &Value) -> Result<Value> {
    let key = region::UPSTREAM_PROVIDER;
    let access_token = data
        .get(key)
        .and_then(|value| value.get("access_token"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::http(502, format!("ZCode 登录响应缺少 {key}.access_token"))
        })?;
    let jwt = text_of(data, &["token"]);
    let user_id = data
        .get("user")
        .and_then(|value| value.get("user_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    // 换取推理凭证（失败即登录失败）
    let api_key = coding_key::resolve(&access_token)?;
    let mut secret = json!({
        "accessToken": api_key,
        "jwt": jwt,
        "deviceMid": flow.device_mid,
        "userId": user_id,
        // 网页登录建的账号走编码套餐通道（套餐池要用户自己切）
        "zcodePlan": account::PLAN_CODING,
        "idPrefix": region::ACCOUNT_ID_PREFIX,
        // 排障用：哪个流程建的这条账号（不含任何凭证）
        "loginFlow": flow_id,
    });
    if !flow.expires_at.eq(&0) {
        secret["loginExpiresAt"] = json!(flow.expires_at);
    }
    Ok(json!({
        "public": account::view(&secret),
        "identity": account::identity(&secret),
        "secret": secret,
        "desktop": false,
    }))
}

/// 把中转页参数补进服务端给的 `authorize_url`（见模块头的第 3 步）。
///
/// ── 语义是「set」不是「append」────────────────────────────
/// 参考实现走 `URL.searchParams.set(param, …)`：**同名参数替换**。上游给的地址
/// 本来就带一个同名参数（国际版 `redirect_uri=…/cli/callback/zai`），所以这一步
/// 必然是替换。裸拼 `&{param}=…` 会留下两个同名参数，取哪个由授权端点自己决定
/// —— 取到原值就等于没补中转页，而症状是 poll 一直停在 pending。
///
/// ── 中转页地址要**整体**编码，不能裸拼 ──────────────────────
/// 参考实现把中转页塞进 `searchParams.set` 时整串会被 form-urlencoded 再编一次
/// （`&` → `%26`、`%` → `%25`）。少这一次编码有两处后果：`&app_version=…`
/// 会被**外层**查询吃掉（它变成 `authorize_url` 上的独立参数），而授权端点也
/// 多收到一个自己没定义的参数。因此这里对内层已编码的 `zcode%3A%2F%2F…` 再编
/// 一次，得到与参考逐字节相同的 `%253A%252F%252F…`：中转页解一次仍是
/// `zcode://oauth/callback`。
fn apply_interstitial(authorize_url: &str) -> String {
    // 国内版（bigmodel）：`redirect`（国际版是 `redirect_uri`，见模块头那处警告）
    let param = "redirect";
    let target = urlencode(&format!(
        "{}/app/oauth/login?redirect=zcode%3A%2F%2Foauth%2Fcallback&app_version={}",
        region::ZCODE_ORIGIN,
        plan::app_version()
    ));
    let prefix = format!("{param}=");
    let replacement = format!("{prefix}{target}");
    // 片段（`#…`）先摘下来：它不参与查询，替换完原样拼回
    let (head, fragment) = match authorize_url.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (authorize_url, None),
    };
    let (path, query) = match head.split_once('?') {
        Some((path, query)) => (path, query),
        None => (head, ""),
    };
    let mut replaced = false;
    let mut segments: Vec<String> = Vec::new();
    for segment in query.split('&').filter(|value| !value.is_empty()) {
        if segment.starts_with(&prefix) {
            // 重名参数只留一个（与 `set` 一致：它会把同名的全部删掉再放一个）
            if !replaced {
                segments.push(replacement.clone());
                replaced = true;
            }
            continue;
        }
        segments.push(segment.to_string());
    }
    if !replaced {
        segments.push(replacement);
    }
    let mut out = String::from(path);
    out.push('?');
    out.push_str(&segments.join("&"));
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// 信封错误：`code` 存在且不为 0 时返回一句人话，否则 None。
///
/// 上游的 `{code, data, msg}` 信封里 `code == 0` 才是成功。
fn envelope_error(payload: &Value) -> Option<String> {
    let code = payload.get("code").and_then(Value::as_i64)?;
    if code == 0 {
        return None;
    }
    let message = text_of(payload, &["msg", "message"]);
    Some(format!(
        "ZCode 登录失败（{code}）：{}",
        if message.is_empty() { "上游拒绝" } else { &message }
    ))
}

/// 取一个必填字符串字段（缺失或空白 → 报错）。
fn required_str(data: &Value, key: &str) -> Result<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(502, format!("ZCode 登录响应缺少 {key}")))
}

/// 还没完成（继续轮询）。
fn pending() -> Value {
    json!({ "state": "pending", "hint": Value::Null })
}

/// 失败（流程已结束）。
fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}
