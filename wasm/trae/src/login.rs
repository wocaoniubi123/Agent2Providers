//! Trae 网页登录：授权页 → **回调 URL 回填** → 换凭据 → 收账号。
//!
//! ── 与 native 的结构差别（迁移时改的）───────────────────────
//! native 侧每轮登录会**自己绑一个 loopback 端口**收回调（`callback_server.rs`），
//! wasm 没有 socket，这条链因此改成：
//!
//! ```text
//!   login.start    → 造授权地址 + 把 PKCE / 设备密钥 / loginHost 存进 Login 状态
//!   login.poll     → 只读状态（网关按 poll_interval_ms 来问）
//!   login.callback → 用户把地址栏那条 URL 粘回来 → 当场换证 → 状态翻成 done
//!   login.cancel   → 清掉那一条
//! ```
//!
//! ── 为什么报 `poll_interval_ms > 0`（本家明明是回调型）────────
//! 「轮询型」在协议里的含义是「**网关主动问插件要结果**」，与授权在哪里终结
//! 无关。回调落在用户浏览器的地址栏里，网关必须来问，所以这里报一个间隔；
//! 报 `0` 会让网关一直等一个不会自动到来的回调，没有任何报错。
//!
//! ── 为什么换证不另起后台任务 ────────────────────────────────
//! native 用后台任务是因为 `login.poll` 现场 await 换证超时会把回调消费掉、
//! 结果丢掉。wasm 没有线程，而 `login.callback` 本身就是一次同步 RPC ——
//! 换证放在它里面，成功/失败都直接落状态，没有"两个消费者抢一个 channel"的
//! 问题。所以 `poll` 只读状态，不发起网络。

use agent2api_wasm_sdk::{self as sdk, json, state, Error, Result, Value};

use super::account::{self, Credential, DEFAULT_VARIANT};
use super::oauth::{self, Callback, LoginContext};
use super::profile::{self, Identity};
use super::refresh;

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}

/// 写状态（CAS：并发发起时后到的那个会失败，而不是把前一轮的参数改掉）。
fn put_state(value: Value, ttl_ms: i64) -> Result<()> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !state::compare_exchange(state::Scope::Login, STATE_KEY, SCHEMA, snapshot.revision, value, ttl_ms)? {
        return Err(Error::new("登录状态已被另一轮流程改写，请重新发起"));
    }
    Ok(())
}

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 网关对 wasm 包恒走动态通道（`api/session.rs` 的 `dynamic_login()` 恒为真），
/// 拿不到这份清单就回 501，**添加账号面板整个打不开**；而且它不会回退到
/// `metadata.json` 的 `login_methods`（同一处注释写明「不会使用旧版兼容入口」）。
///
/// ── 与 `metadata.json` 的对应（顺序不许换）──────────────────
/// 0 号 = `kind: "browser"`（网页登录），1 号 = `kind: "token"`（登录凭据）。
/// 网关的托管登录只认 0 号（`core/login/managed/trae.rs` 的 `applies`：只判
/// `method == 0`），网页登录挪到别处就会被判成「不是网页登录」。
///
/// ── 两处不能省的契约 ────────────────────────────────────────
///   · `manualCallback: true` + `callbackInput: "url"`：插件没有 socket，收不到
///     浏览器重定向，必须由用户把地址栏那条 URL 回填（与 `login.start` 的
///     `login_ui` 逐字同值）。漏了它面板只显示「等待」，那颗回填框不会出现。
///   · `browserMode: "choice"`：`login.start` 的 `login_ui.browserMode` 就是它。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "oauth", "label": "网页登录", "prompts": [],
            "browserMode": "choice", "manualCallback": true, "callbackInput": "url",
            "instructions": "打开 Trae 授权页，完成后自动收下账号"
        },
        {
            "methodIndex": 1, "type": "api", "label": "登录凭据", "prompts": [{
                "key": "token", "type": "text", "label": "登录凭据",
                "placeholder": "粘贴 CPA auth 文件内容或 accessToken", "secret": true
            }],
            "instructions": "粘贴 CPA auth 文件内容或 accessToken"
        }
    ] })
}

/// 发起一次网页登录。
///
/// `method` 不是浏览器时如实回绝：粘贴凭据走 `account.normalize`，
/// 不是这条链（回一个「请直接粘贴」比让它落到一个空授权地址上清楚）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"]
        .as_str()
        .or_else(|| params["kind"].as_str())
        .unwrap_or("browser");
    if !matches!(method, "" | "browser" | "web" | "oauth") {
        return Err(Error::http(400, "Trae 的「填写凭证」请直接在账号页粘贴凭据；网页登录请点「网页登录」"));
    }
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("trae-web-{}", sdk::now()));
    let context = LoginContext::new(DEFAULT_VARIANT)?;
    // guidance 是"该去哪个登录页"，全挂时兜到默认 host（CN 不因它阻塞登录）。
    let login_host = oauth::request_login_guidance();
    let auth_url = oauth::verification_uri(&login_host, &context);
    // 15 分钟 = native `LOGIN_TTL` 那条（参考实现的登录有效期）。插件里超时由
    // 网关的登录超时驱动，这里只负责"过期后状态自己消失"，免得一条旧上下文
    // 一直躺在状态里被后来者误用。
    put_state(
        json!({
            "flow": flow,
            "phase": "waiting",
            "login_host": login_host,
            "context": context.to_json(),
        }),
        900_000,
    )?;
    Ok(json!({
        "flow": flow,
        "url": auth_url,
        "poll_interval_ms": 2000,
        "instructions": "在打开的页面里完成 Trae 授权。页面最后会停在「无法访问 127.0.0.1」——这是正常的：请把地址栏里那条完整 URL 复制回填，授权码就在其中",
        // 内嵌窗口：授权页会按用户选的登录方式继续跳不可穷举的主机，
        // 所以 allowed_hosts 留空（空 = 不限制，与 native 同口径）
        "external_browser": false,
        "allowed_hosts": [],
        // 插件收不到浏览器重定向（没有 socket），必须由用户回填回调 URL
        "login_ui": {
            "browserMode": "choice", "manualCallback": true, "callbackInput": "url",
            "cookieCapture": Value::Null, "captureCallback": false
        }
    }))
}

/// 轮询一次登录进度（网关按 `poll_interval_ms` 来问）。
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
        // 授权在浏览器里，插件这边能做的只有等回填
        _ => Ok(json!({ "state": "pending", "hint": "等待你在浏览器里完成授权，然后把地址栏那条 URL 回填" })),
    }
}

fn clear(revision: u64) {
    let _ = state::compare_exchange(state::Scope::Login, STATE_KEY, SCHEMA, revision, Value::Null, 1000);
}

/// 用户把回调 URL 贴回来：当场换证并把账号放进状态。
///
/// 网关给的 `code` 在插件家是整条回调 URL（历史约定：`url` 与 `code` 同值），
/// 而 `Callback::from_query` 只认查询串 —— 所以带 `?` 的取问号之后那段。
pub fn callback(params: &Value) -> Result<Value> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return Ok(failed("这次登录流程已失效，请重新发起"));
    }
    let flow = params["flow"].as_str().unwrap_or("");
    if !flow.is_empty() && snapshot.value["flow"].as_str() != Some(flow) {
        return Ok(failed("这次登录流程已失效，请重新发起"));
    }
    let Some(context) = LoginContext::from_json(&snapshot.value["context"]) else {
        return Ok(failed("这次登录的上下文已损坏，请重新发起"));
    };
    let raw = if params["url"].as_str().is_some_and(|text| !text.trim().is_empty()) {
        params["url"].as_str().unwrap_or("").trim().to_string()
    } else {
        params["code"].as_str().unwrap_or("").trim().to_string()
    };
    let query = match raw.split_once('?') {
        Some((_, query)) => query.to_string(),
        None => raw,
    };
    let parsed = Callback::from_query(&query);
    if !parsed.error.is_empty() {
        // 上游明说的失败（用户取消、errorCode=20405 设备绑定被拒、
        // isRedirect=false）要原样透出去：那是「这一轮没成」，不是「网关坏了」。
        let message = parsed.error.clone();
        mark_failed(snapshot.revision, &message);
        return Ok(failed(message));
    }
    if !parsed.resolves_login() {
        return Ok(failed("Trae 回调里没有授权码也没有续期串"));
    }
    // 回调带回的 loginHost 优先（它才是这次授权实际发生的站点），
    // 没有就退回发起时 guidance 的那一份。
    let login_host = if parsed.login_host.is_empty() {
        snapshot.value["login_host"].as_str().unwrap_or("").to_string()
    } else {
        parsed.login_host.clone()
    };
    let exchanged = match exchange(&context, &parsed, &login_host) {
        Ok(exchanged) => exchanged,
        Err(error) => {
            // 换证失败按 `LoginPoll::Failed` 回，而不是把整条 RPC 变成错误：
            // 授权码已经花掉，这一轮就是"没成"，重做要用户重新点一次登录。
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    let credential = Credential {
        access_token: exchanged.access_token,
        refresh_token: exchanged.refresh_token,
        expires_at: exchanged.expires_at_ms,
        // `domain` 是凭据的谱系标记（决定 ClientID 与目录血统），`api_host` 是
        // OAuth/积分那条链的第一候选 —— 两者都**不**跟着 loginHost 漂：
        // CN 账号的兑换永远打固定 origin。
        domain: "trae.cn".to_string(),
        api_host: oauth::DEFAULT_LOGIN_HOST.to_string(),
        machine_id: context.machine_id.clone(),
        device_id: context.device_id.clone(),
        variant: context.variant.clone(),
        uid: String::new(),
        enterprise_id: String::new(),
        nickname: String::new(),
        device_public_key: context.device_public_pem.clone(),
        device_private_key: context.device_private_pem.clone(),
        // 上游在这一次换证里承认的归属，落盘后就不再需要按 variant 猜
        auth_client_id: exchanged.auth_client_id,
    };
    if credential.access_token.is_empty() && credential.refresh_token.is_empty() {
        return Ok(failed("Trae 换证成功但响应里没有任何令牌，请重试"));
    }
    // 身份是**读数**，不是门槛：GetUserInfo 挂了就用回调回显，两个都没有就落一个
    // 每个 variant 固定的 unknown 名（用 per-login 的随机 id 兜底会造出重复账号）。
    let authoritative = profile::get_user_info(&credential).unwrap_or_default();
    let identity = Identity::merged(&authoritative, &profile::callback_identity(&query), &context.variant);
    let mut credential = credential;
    credential.uid = identity.uid;
    credential.nickname = identity.nickname;
    credential.enterprise_id = identity.enterprise_id;
    let account: Value = match account::account_of(&credential, "web", None) {
        Ok(account) => account,
        Err(error) => {
            // 谱系闸门（Intl 凭据）在这条链上只能报失败：账号不能落，
            // 但一次已经完成的授权要带上原因告诉用户，而不是静默丢掉。
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    put_done(snapshot.revision, &flow, &account);
    Ok(json!({ "state": "done", "account": account }))
}

/// 取消一轮登录：清掉那一条（native 走的是"收监听器、释放端口"，
/// 插件侧没有端口可放，清状态就是同一件事）。
pub fn cancel(params: &Value) -> Result<Value> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if snapshot.compatible && !snapshot.value.is_null() {
        let flow = params["flow"].as_str().unwrap_or("");
        if flow.is_empty() || snapshot.value["flow"].as_str() == Some(flow) {
            let _ = state::compare_exchange(state::Scope::Login, STATE_KEY, SCHEMA, snapshot.revision, Value::Null, 0);
        }
    }
    Ok(Value::Null)
}

/// 把这一轮标成失败（存的是**状态**的形态，`poll` 从 `phase` 读出来再翻成
/// `LoginPoll`；两处都用 `{state, message}` 那个响应形状的话，poll 会一直报
/// pending —— 因为存储里根本没有 `phase` 这个键）。
fn mark_failed(revision: u64, message: &str) {
    let _ = state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        revision,
        json!({ "phase": "failed", "message": message }),
        300_000,
    );
}

/// 换证完成后重写状态：保留 flow，带上账号（`poll` 从 `phase=done` 读出它）。
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

/// 换证结果（授权码与 refreshToken 两条分支的公共形状）。
struct Exchanged {
    access_token: String,
    refresh_token: String,
    expires_at_ms: i64,
    auth_client_id: String,
}

fn exchange(context: &LoginContext, callback: &Callback, login_host: &str) -> Result<Exchanged> {
    if callback.refresh_token.is_empty() {
        let exchanged = oauth::exchange_auth_code(context, &callback.auth_code, login_host)?;
        // 只有 refreshToken 回来时用它当 accessToken（参考实现
        // `if accessToken == "" { = refreshToken }`）。
        let access_token = if exchanged.access_token.is_empty() {
            exchanged.refresh_token.clone()
        } else {
            exchanged.access_token
        };
        let auth_client_id = refresh::response_client_id(&exchanged.raw);
        return Ok(Exchanged {
            access_token,
            refresh_token: exchanged.refresh_token,
            expires_at_ms: exchanged.expires_at_ms,
            auth_client_id,
        });
    }
    // ── refreshToken 分支 ────────────────────────────────────
    // 续期也失败时**不报错**：把这条串既当 accessToken 又当 refreshToken 存下
    // （参考实现同一条）。判成失败等于把一次已经花掉用户点击的授权丢掉，
    // 而存下来最坏也只是第一次转发时 401。
    let seed = Credential {
        refresh_token: callback.refresh_token.clone(),
        api_host: oauth::DEFAULT_LOGIN_HOST.to_string(),
        domain: "trae.cn".to_string(),
        machine_id: context.machine_id.clone(),
        device_id: context.device_id.clone(),
        variant: context.variant.clone(),
        device_public_key: context.device_public_pem.clone(),
        device_private_key: context.device_private_pem.clone(),
        ..Default::default()
    };
    match refresh::refresh_once(&seed) {
        Ok(next) => Ok(Exchanged {
            access_token: next.access_token,
            refresh_token: next.refresh_token,
            expires_at_ms: next.expires_at,
            auth_client_id: next.auth_client_id,
        }),
        Err(_) => Ok(Exchanged {
            access_token: seed.refresh_token.clone(),
            refresh_token: seed.refresh_token,
            expires_at_ms: 0,
            auth_client_id: String::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 形状必须与网关 `api/session.rs` 的 `LoginMethodsMetadata` 对得上：
    /// 索引唯一且非负、`type` 在四个枚举内、`prompts` 恒为数组、oauth 带合法的
    /// `browserMode`。错一条的后果是整份 502（面板打不开），而不是某条样式不对。
    #[test]
    fn methods_declare_the_gateway_contract() {
        let value = methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(2, list.len());
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
                    assert_eq!("text", prompts[0]["type"].as_str().unwrap_or(""));
                    assert_eq!(true, prompts[0]["secret"].as_bool().unwrap_or(false));
                }
                other => assert!(matches!(other, "sms" | "desktop")),
            }
        }
        // 网页登录必须是 0 号：网关托管登录只认这个索引。
        assert_eq!("oauth", list[0]["type"].as_str().unwrap_or(""));
        assert_eq!(true, list[0]["manualCallback"].as_bool().unwrap_or(false));
        assert_eq!("url", list[0]["callbackInput"].as_str().unwrap_or(""));
    }
}
