//! Accio 网页登录：授权页 → **回调 URL 回填** → 换凭据 → 收账号。
//!
//! ── 与 native 的结构差别（迁移时改的）───────────────────────
//! native 侧每轮登录会**自己绑一个 loopback 端口**收回调（`callback_server.rs`），
//! wasm 没有 socket，这条链因此改成：
//!
//! ```text
//!   login.start    → 造授权地址 + 把 PKCE / 回调地址存进 Login 状态
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
//! 换证放在它里面，成功/失败都直接落状态，没有「两个消费者抢一个 channel」的
//! 问题。所以 `poll` 只读状态，不发起网络。
//!
//! ── `flow` 必须原样回传（规格第 17 节的硬约束）─────────────────
//! 网关在 `login.start` 时把 `params.flow` 给插件，`login.callback` 时逐字
//! 比对 URL 里的 `state` 与当前 flow。插件若把**上游自己的 state** 当 `flow`
//! 返回，点「网页登录」会当场 502。上游 state 存在本模块的登录状态里，
//! 不进 flow。
//!
//! ── 交付给面板的两处契约（漏了面板就不对）────────────────────
//!   · `auth.methods` 必须由插件申报（网关对 wasm 恒走动态通道，不实现就 501）；
//!   · `manualCallback: true` + `callbackInput: "url"`：插件没有 socket，收不到
//!     浏览器重定向，必须由用户回填（与 `login.start` 的 `login_ui` 逐字同值）。

use agent2api_wasm_sdk::{self as sdk, json, state, Error, Result, Value};

use super::credential::{self, Credential};
use super::oauth;
use super::region;

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
const SCHEMA: u32 = 1;

/// 登录状态有效期（15 分钟；超时由网关的登录超时驱动，这里只负责「过期后
/// 状态自己消失」，免得一条旧上下文一直躺着被后来者误用）。
const STATE_TTL_MS: i64 = 900_000;

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

fn clear(revision: u64) {
    let _ = state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        revision,
        Value::Null,
        1000,
    );
}

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 与 `metadata.json` 的对应（顺序不许换）──────────────────
/// 0 号 = `kind: "browser"`（网页登录），1 号 = `kind: "token"`（登录凭据）。
/// 网关的托管登录只认 0 号（`core/login/managed/trae.rs` 的 `applies`：只判
/// `method == 0`），网页登录挪到别处就会被判成「不是网页登录」。
///
/// ── 两处不能省的契约 ────────────────────────────────────────
///   · `manualCallback: true` + `callbackInput: "url"`：插件没有 socket；
///   · `browserMode: "choice"`：`login.start` 的 `login_ui.browserMode` 就是它。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "oauth", "label": "网页登录", "prompts": [],
            "browserMode": "choice", "manualCallback": true, "callbackInput": "url",
            "instructions": format!(
                "打开 Accio {} 授权页完成登录；页面最后会停在「无法访问 127.0.0.1」——这是正常的：请把地址栏里那条完整 URL 复制回填，授权码就在其中",
                region::REGION.label()
            )
        },
        {
            "methodIndex": 1, "type": "api", "label": "登录凭据", "prompts": [{
                "key": "token", "type": "text", "label": "登录凭据",
                "placeholder": "粘贴 accessToken / refreshToken", "secret": true
            }],
            "instructions": "粘贴 Accio 的 accessToken（有 refreshToken 时一并粘贴，便于自动续期）"
        }
    ] })
}

/// 发起一次网页登录。
///
/// `method` 不是浏览器时如实回绝：粘贴凭据走 `account.normalize`，不是这条链
/// （回一个「请直接粘贴」比让它落到一个空授权地址上清楚）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"]
        .as_str()
        .or_else(|| params["kind"].as_str())
        .unwrap_or("browser");
    if !matches!(method, "" | "browser" | "web" | "oauth") {
        return Err(Error::http(
            400,
            "Accio 的「填写凭证」请直接在账号页粘贴凭据；网页登录请点「网页登录」",
        ));
    }
    // 网关分配的流程标识必须原样回传（见模块头）
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("accio-web-{}", sdk::now()));
    let (verifier, challenge) = oauth::new_pkce();
    // 上游的 state 由我们自己生成（回调回来时逐字比对），**不是** flow
    let upstream_state = super::protocol::new_request_id();
    let url = oauth::build_authorize_url(
        region::REGION,
        &upstream_state,
        &challenge,
        oauth::CALLBACK_REDIRECT,
    );
    put_state(
        json!({
            "flow": flow,
            "phase": "waiting",
            "upstream_state": upstream_state,
            "verifier": verifier,
            "redirect_uri": oauth::CALLBACK_REDIRECT,
        }),
        STATE_TTL_MS,
    )?;
    Ok(json!({
        "flow": flow,
        "url": url,
        "poll_interval_ms": 2000,
        "instructions": format!(
            "在打开的页面里完成 Accio {} 的授权。页面最后会停在「无法访问 127.0.0.1」——这是正常的：请把地址栏里那条完整 URL 复制回填，授权码就在其中",
            region::REGION.label()
        ),
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
        _ => Ok(json!({
            "state": "pending",
            "hint": "等待你在浏览器里完成授权，然后把地址栏那条 URL 回填"
        })),
    }
}

/// 用户把回调 URL 贴回来：当场换证并把账号放进状态。
///
/// 网关给的 `code` 在插件家是整条回调 URL（历史约定：`url` 与 `code` 同值），
/// 也接受裸授权码（`parse_callback` 会把它当成 `code=` 那条）。
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
    let (code, state_from_callback) = match oauth::parse_callback_url(&raw) {
        Ok(parsed) => parsed,
        // 裸授权码（网关的 login.callback 只抽出 code 参数时就是这样）
        Err(_) if !raw.contains("code=") && !raw.contains('?') => (raw.clone(), String::new()),
        Err(error) => {
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    let expected_state = snapshot.value["upstream_state"].as_str().unwrap_or("");
    if !state_from_callback.is_empty()
        && !expected_state.is_empty()
        && state_from_callback != expected_state
    {
        let message = "回调里的 state 与本次登录不一致，已拒绝";
        mark_failed(snapshot.revision, message);
        return Ok(failed(message));
    }
    let verifier = snapshot.value["verifier"].as_str().unwrap_or("").to_string();
    let redirect_uri = snapshot.value["redirect_uri"]
        .as_str()
        .unwrap_or(oauth::CALLBACK_REDIRECT)
        .to_string();
    if verifier.is_empty() {
        return Ok(failed("这次登录的上下文已损坏，请重新发起"));
    }
    let credential = match oauth::exchange_code(region::REGION, &code, &verifier, &redirect_uri) {
        Ok(credential) => credential,
        Err(error) => {
            // 换证失败按 `LoginPoll::Failed` 回，而不是把整条 RPC 变成错误：
            // 授权码已经花掉，这一轮就是「没成」，重做要用户重新点一次登录。
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    let account = account_of(&credential, "web");
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
        STATE_TTL_MS,
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

/// 凭证 → 可落库的账号（登录与手工粘贴两条路共用）。
///
/// 名字优先级：显式给的 > 上游昵称 > 邮箱 > userId > 「Accio <地区>账号」。
pub fn account_of(credential: &Credential, source: &str) -> Value {
    let mut secret = match credential.to_secret(region::REGION) {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    // 地区以 provider 身份为准（凭证里的 mode 只是兼容字段）
    secret.insert(
        "mode".to_string(),
        Value::String(region::REGION.edition().to_string()),
    );
    secret.insert("source".to_string(), Value::String(source.to_string()));
    let name = if !credential.name.is_empty() {
        credential.name.clone()
    } else if !credential.email.is_empty() {
        credential.email.clone()
    } else if !credential.user_id.is_empty() {
        format!("Accio {}", credential.user_id)
    } else {
        format!("Accio {}账号", region::REGION.label())
    };
    secret.insert("name".to_string(), Value::String(name.chars().take(100).collect()));
    let secret = Value::Object(secret);
    json!({
        "identity": credential::identity(&secret),
        "public": credential::view(&secret),
        "secret": secret,
        // 本家没有「实时读本机客户端」这条来源，恒 false
        "desktop": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 形状必须与网关 `api/session.rs` 的 `LoginMethodsMetadata` 对得上：
    /// 索引唯一且非负、`type` 在四个枚举内、`prompts` 恒为数组、oauth 带合法的
    /// `browserMode`、api 的 prompt 必须带 `type`。错一条的后果是整份 502。
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
                    // 缺 `type` 字段 = 网关 502（规格第 17 节）
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

    /// 粘贴的整条 URL / 裸查询串 / 裸 code 三种形态都要能取出授权码。
    #[test]
    fn callback_accepts_three_shapes() {
        let url = "http://127.0.0.1:17892/auth/callback-accio?code=abc&state=xyz";
        let (code, state) = oauth::parse_callback_url(url).unwrap_or_default();
        assert_eq!("abc", code);
        assert_eq!("xyz", state);
        let (code, _) = oauth::parse_callback_url("?code=abc&state=xyz").unwrap_or_default();
        assert_eq!("abc", code);
    }
}
