//! LobsterAI 网页登录：授权页 → **回调 URL 回填** → 换码 → 收账号。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/oauth.rs` + `mod.rs` 的
//! `login_start` / `login_callback`。
//!
//! ── 与 native 的结构差别（迁移时改的）───────────────────────
//! native 侧每轮登录会**自己绑一个 loopback 端口**收回调
//! （`oauth::loopback_base` 从 `HostEnv.loopback_port` 取端口），wasm 没有 socket，
//! 这条链因此改成：
//!
//! ```text
//!   login.start    → 造授权地址（state = 宿主分配的 flow）+ 把回调地址 / 时间存进 Login 状态
//!   login.poll     → 只读状态（网关按 poll_interval_ms 来问）
//!   login.callback → 用户把地址栏那条 URL 粘回来 → 当场换码 → 状态翻成 done
//!   login.cancel   → 清掉那一条
//! ```
//!
//! ── 回调地址从哪来（**关键决策**）──────────────────────────
//! 网关 `plugin_host/wasm/host.rs:369-373`：包声明了 `login.callback.v1` 时，
//! `login.start` 的 params 里会被注入
//!
//! ```text
//!   callback_url = http://127.0.0.1:<网关真实端口>/api/session/login/wasm-callback
//! ```
//!
//! 所以本包在 `wasm.json` 里申报 `login.callback.v1`，优先用宿主给的地址 ——
//! 那是**网关自己监听的端口**，浏览器 302 真能打到网关上，同时用户也能把地址栏
//! 那条 URL 手动粘回来（`login_ui.manualCallback = true`）。
//! 宿主没给（老宿主 / 能力没生效）时退回到一个固定端口的本机地址：门户只按
//! 形状回落（native 用动态端口也能跑），用户照样能手动回填。**绝不拼一个必然 404
//! 的地址装作能用** —— 与 trae 的取舍一致。
//!
//! ── 为什么 state 必须等于 flow ─────────────────────────────
//! 宿主在 `login.callback` 时校验回调 URL 里的 `state` 必须等于当前 flow
//! （`host.rs:387-393`），不相等直接拒。所以授权地址里的 `state` 填 flow，
//! 而不是 native 那种另造的随机串。
//!
//! ── 为什么报 `poll_interval_ms > 0`（本家明明是回调型）────────
//! 「轮询型」在协议里的含义是「**网关主动问插件要结果**」，与授权在哪里终结
//! 无关。回调落在用户浏览器的地址栏里，网关必须来问，所以这里报一个间隔；
//! 报 `0` 会让网关一直等一个不会自动到来的回调，没有任何报错（native 报 0 是因为
//! 它真的自己在监听端口 —— 那条路 wasm 走不了）。
//!
//! ── 为什么换码不另起后台任务 ────────────────────────────────
//! native 用后台任务是因为 `login_poll` 现场 await 换码超时会把回调消费掉、
//! 结果丢掉。wasm 没有线程，而 `login.callback` 本身就是一次同步 RPC ——
//! 换码放在它里面，成功/失败都直接落状态。所以 `poll` 只读状态，不发起网络。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, state, Error, Result, Value};

use super::codec;
use super::credentials;
use super::oauth;
use super::upstream::{CALLBACK_PATH, PORTAL_BASE};
use super::version;

/// 登录状态在宿主 Login 作用域里的键（同一时刻只允许一轮登录）。
const STATE_KEY: &str = "flow";
/// 状态结构版本（改动字段形状时必须加，网关会据它判「不兼容」）
const SCHEMA: u32 = 1;
/// 一轮登录的有效期（与网关登录任务的 15 分钟同一量级）
const LOGIN_TTL_MS: i64 = 900_000;
/// 换码完成后结果的驻留时长（够网关下一次 poll 取走）
const DONE_TTL_MS: i64 = 60_000;

/// 宿主没给回调地址时用的固定端口。
///
/// 41596 是本仓未占用的端口（trae 用 41595）。端口号本身不参与门户校验 ——
/// native 用网关的动态端口也能跑完这条链 —— 这里的作用只是让地址**形状正确**，
/// 真正的授权码靠用户从地址栏回填。
const FALLBACK_CALLBACK_PORT: u16 = 41596;

/// 登录页会跳到的域（壳侧据此做导航白名单，与 native `allowed_hosts` 一致）。
/// 微信扫码那条链会离开 portal，不能只列 lobsterai 自己。
const ALLOWED_HOSTS: [&str; 5] = [
    "lobsterai.youdao.com",
    "126.com",
    "163.com",
    "weixin.qq.com",
    "open.weixin.qq.com",
];

/// 失败应答（`LoginPoll::Failed` 的形状，网关也认 `state: "failed"`）。
fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}

/// 写状态（CAS：并发发起时后到的那个会失败，而不是把前一轮的参数改掉）。
fn put_state(value: Value, ttl_ms: i64) -> Result<()> {
    let snapshot = state::get(state::Scope::Login, STATE_KEY, SCHEMA)?;
    if !state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        snapshot.revision,
        value,
        ttl_ms,
    )? {
        return Err(Error::new("登录状态已被另一轮流程改写，请重新发起"));
    }
    Ok(())
}

/// 发起一次网页登录。
///
/// `method` 不是浏览器时如实回绝：本家没有「粘贴凭据」这条路
/// （`account.normalize` 也一律拒绝，理由见那里）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"]
        .as_str()
        .or_else(|| params["kind"].as_str())
        .unwrap_or("browser");
    if !matches!(method, "" | "browser" | "web" | "oauth") {
        return Err(Error::http(
            400,
            "LobsterAI 只能通过「浏览器登录」添加：它的续期需要换码时下发的 uuid 与 keyfrom，粘贴给不出这三项",
        ));
    }
    // 宿主分配流程标识（声明了 login.callback.v1 就一定会注入）；没有则自己造一个。
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("lobsterai-{}", sdk::now()));
    // 宿主注入的本机回调地址优先（那是网关真在监听的端口）；没有就退回固定端口。
    let redirect_uri = params["callback_url"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("http://127.0.0.1:{FALLBACK_CALLBACK_PORT}{CALLBACK_PATH}"));
    // state 必须等于 flow（宿主在 login.callback 时按它校验）
    let auth_url = oauth::build_authorize_url(&redirect_uri, &flow);
    put_state(
        json!({
            "flow": flow,
            "phase": "waiting",
            "redirect_uri": redirect_uri,
            "created_at": sdk::now(),
        }),
        LOGIN_TTL_MS,
    )?;
    Ok(json!({
        "flow": flow,
        "url": auth_url,
        "poll_interval_ms": 1500,
        "instructions": format!(
            "在打开的页面里完成 LobsterAI 登录（手机号 / 微信）。成功后浏览器会跳回本机，\
             页面可能显示「无法访问」—— 这是正常的：请把地址栏里那条完整 URL 复制回填，\
             授权码就在其中（授权页在 {PORTAL_BASE}）"
        ),
        // 内嵌窗口：微信扫码那条链会继续跳不可穷举的主机，所以 allowed_hosts
        // 只列已知的几个（与 native 的 allowed_hosts 逐条一致）
        "external_browser": false,
        "allowed_hosts": ALLOWED_HOSTS,
        // 插件收不到浏览器重定向（没有 socket），必须由用户回填回调 URL
        "login_ui": {
            "browserMode": "choice",
            "manualCallback": true,
            "callbackInput": "url",
            "cookieCapture": Value::Null,
            "captureCallback": false
        }
    }))
}

/// 轮询一次登录进度（网关按 `poll_interval_ms` 来问）。
pub fn poll(params: &Value) -> Result<Value> {
    // 宿主在 Login 作用域要求「本次调用已绑定登录流程」；绑定丢了（清理过、
    // 或宿主重启过）就如实回一句「请重新发起」，而不是把一个宿主错误抛给用户。
    let snapshot = match state::get(state::Scope::Login, STATE_KEY, SCHEMA) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(failed("这次登录流程已失效，请重新发起")),
    };
    if !snapshot.compatible || snapshot.value.is_null() {
        return Ok(failed(
            "这次登录流程已失效（插件实例或宿主重启过？），请重新发起",
        ));
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
            let message = snapshot.value["message"]
                .as_str()
                .unwrap_or("这轮登录没有成功")
                .to_string();
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

/// 用户把回调地址交回来：当场换码并把账号放进状态。
///
/// 网关给的 `code` 在个别壳侧是整条回调 URL（与 `url` 同值），两种形态都认
/// （见 `oauth::callback_code`）。
pub fn callback(params: &Value) -> Result<Value> {
    let snapshot = match state::get(state::Scope::Login, STATE_KEY, SCHEMA) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(failed("这次登录流程已失效，请重新发起")),
    };
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
    let code = oauth::callback_code(&raw, params["code"].as_str().unwrap_or(""));
    if code.trim().is_empty() {
        return Ok(failed("回调里没有授权码，请重新发起登录"));
    }
    let client_version = version::resolve();
    // `uuid` 与两个 keyfrom 由**插件生成**（参考实现同款）：`uuid` 是这次登录的
    // 安装标识、`firstKeyfrom` 是登录时刻（毫秒）、`latestKeyfrom` 取同一时刻 ——
    // 三者随换码下发，续期时要原样回传。
    let keyfrom = sdk::now().max(0).to_string();
    let uuid = match codec::uuid_v4() {
        Ok(uuid) => uuid,
        Err(error) => {
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };
    let bundle = match oauth::exchange(&code, &uuid, &keyfrom, &keyfrom, &client_version) {
        Ok(bundle) => bundle,
        Err(error) => {
            // 换码失败按「这一轮没成」回，而不是把整条 RPC 变成错误：
            // 授权码已经花掉，重做要用户重新点一次登录。
            mark_failed(snapshot.revision, &error.message);
            return Ok(failed(error.message));
        }
    };

    // 落账号的字段用本仓驼峰名（与内置版记录的形态一致，便于人工核对）
    let mut secret = serde_json::Map::new();
    secret.insert(
        "accessToken".to_string(),
        Value::String(bundle.access_token.clone()),
    );
    if !bundle.refresh_token.trim().is_empty() {
        secret.insert(
            "refreshToken".to_string(),
            Value::String(bundle.refresh_token.clone()),
        );
    }
    secret.insert("uuid".to_string(), Value::String(uuid));
    secret.insert("firstKeyfrom".to_string(), Value::String(keyfrom.clone()));
    secret.insert("latestKeyfrom".to_string(), Value::String(keyfrom));
    if !bundle.uid.trim().is_empty() {
        secret.insert("uid".to_string(), Value::String(bundle.uid.clone()));
    }
    if !bundle.user_id.trim().is_empty() {
        secret.insert("userId".to_string(), Value::String(bundle.user_id.clone()));
    }
    if !bundle.nickname.trim().is_empty() {
        secret.insert("name".to_string(), Value::String(bundle.nickname.clone()));
    }
    if bundle.expires_in > 0 {
        secret.insert("expiresIn".to_string(), Value::from(bundle.expires_in));
        // 落一个绝对到期时刻：界面与临期判定都读它（native 由 store 侧算，
        // 插件里必须自己写进 secret，否则账号页的到期列永远空白）
        secret.insert(
            "expiresAt".to_string(),
            Value::from(sdk::now().saturating_add(bundle.expires_in.saturating_mul(1000))),
        );
    }
    let secret = Value::Object(secret);
    let public = credentials::account_view(&secret);
    let identity = credentials::identity_of(&secret);
    let account = json!({
        "secret": secret,
        "public": public,
        "identity": identity,
        "desktop": false,
    });
    put_done(snapshot.revision, &flow, &account);
    Ok(json!({ "state": "done", "account": account }))
}

/// 取消一轮登录：清掉那一条（native 走的是「收监听器、释放端口」，
/// 插件侧没有端口可放，清状态就是同一件事）。
pub fn cancel(params: &Value) -> Result<Value> {
    // 取消是幂等的：拿不到状态（流程已清 / 宿主没绑定）就算已经取消过了。
    let Ok(snapshot) = state::get(state::Scope::Login, STATE_KEY, SCHEMA) else {
        return Ok(Value::Null);
    };
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

/// 清掉这一轮（`poll` 取走结果后调用）。
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

/// 把这一轮标成失败（存的是**状态**的形态，`poll` 从 `phase` 读出来再翻成
/// 失败应答；两处都用 `{state, message}` 那个响应形状的话，poll 会一直报
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

/// 换码完成后重写状态：保留 flow，带上账号（`poll` 从 `phase=done` 读出它）。
fn put_done(revision: u64, flow: &str, account: &Value) {
    let _ = state::compare_exchange(
        state::Scope::Login,
        STATE_KEY,
        SCHEMA,
        revision,
        json!({ "phase": "done", "flow": flow, "account": account }),
        DONE_TTL_MS,
    );
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
pub fn methods() -> Value {
    let metadata: Value = serde_json::from_str(crate::METADATA).unwrap_or(Value::Null);
    let mut methods: Vec<Value> = Vec::new();
    if let Some(entries) = metadata.get("login_methods").and_then(Value::as_array) {
        for entry in entries {
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
            let method = match kind {
                // 回调型浏览器登录：`login.start` 回的 `login_ui.browserMode` 就是
                // `choice`（由用户决定内嵌窗口还是系统浏览器，再用回填的地址栏 URL 收尾）
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
        // 与 `login.start` 的 `login_ui.browserMode` 同一个值
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
    fn allowed_hosts_cover_the_wechat_leg() {
        // 微信扫码那条链会离开 portal（native 的 allowed_hosts 同款）
        assert!(ALLOWED_HOSTS.contains(&"lobsterai.youdao.com"));
        assert!(ALLOWED_HOSTS.contains(&"open.weixin.qq.com"));
        assert_eq!(ALLOWED_HOSTS.len(), 5);
    }

    #[test]
    fn failed_reply_uses_the_poll_shape() {
        let value = failed("授权码无效");
        assert_eq!(value["state"], json!("failed"));
        assert_eq!(value["message"], json!("授权码无效"));
    }

    #[test]
    fn fallback_callback_address_has_the_expected_shape() {
        // 端口不参与门户校验，但形状必须对（`http://127.0.0.1:<port>/auth/callback`）
        let url = format!("http://127.0.0.1:{FALLBACK_CALLBACK_PORT}{CALLBACK_PATH}");
        assert_eq!(url, "http://127.0.0.1:41596/auth/callback");
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
        assert_eq!("浏览器登录", first["label"].as_str().unwrap_or(""));
        assert_eq!(
            "打开 LobsterAI 授权页，登录后自动回填账号",
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
        // 网关要求字母开头、只含字母数字与 `_` `-`（`session.rs:325-333`）
        assert!(valid_key("token"));
        assert!(valid_key("image_id"));
        assert!(valid_key("a-1"));
        assert!(!valid_key(""));
        assert!(!valid_key("1token"));
        assert!(!valid_key("to ken"));
        assert!(!valid_key(&"a".repeat(65)));
        // 本包没申报 desktop.credentials.v1，desktop 方式不会被申报
        assert!(!requires("desktop.credentials.v1"));
        assert!(!requires("login.sms.v1"));
    }
}
