//! CatPaw 登录：**网页登录在本包里没有接通，如实返回可读错误**。
//!
//! ── native 的网页登录长什么样（原样保留，作为未实现部分的依据）────
//! ```text
//! ① GET  {gateway}/api/gateway/passport/login-config        （无需鉴权）
//!      → data.loginEntryUrl（实测 https://catpaw.meituan.com/api/gateway/passport/login-entry）
//! ② 把 loginEntryUrl 拼上三个 query 参数交给浏览器打开：
//!      ?state=<本地随机>&redirect=<loopback 地址>&sid=<本地随机>
//!    上游 302 → 美团 passport 登录 → settoken → login-callback?state=&sid=&redirect=
//! ③ 登录完成后，`login-callback` 页面把 `{token, state}` **POST 到 redirect 地址**
//!    （CSP 的 form-action 只允许 http://127.0.0.1:* 与 http://localhost:*）
//! ④ 校验 state 后把 token 落账号（token 就是 auth.json 的 auth.accessToken）
//! ```
//! native 版在插件进程里**自绑一个 loopback 端口**收那次 POST（`callback_server.rs`），
//! 同时用 `sid` 轮询上游 `poll-token` 兜底（两条通道赛跑）。
//!
//! ── 为什么 wasm 侧做不到（卡点，逐条）───────────────────────
//!   1. wasm 沙箱**不能监听端口**：宿主的能力表里没有 listen/bind 这一类方法，
//!      第 ③ 步的回调无处可落；
//!   2. 网关确实为 catpaw 配了**托管 loopback**（`managed_policy.rs` 的
//!      `catpaw.passport.v1` profile），但那条通道属于 `login.managed.v1` +
//!      `login.loopback.v1` 能力，需要插件按宿主定义的一组方法
//!      （`login.context` / `login.input.take` / `login.step.publish` /
//!      `login.loopback.open` / `login.loopback.close`）走完整托管协议，
//!      并且要在 `wasm.json` 里声明 `managed_login` 配置。本包**没有申报**这条
//!      能力，因此也不实现这套协议 —— 申报了却只实现一半会在运行期直接报错，
//!      比明确不支持更糟。
//!   3. 折中做法（只做 poll-token 轮询、不要回调）也不可行：`poll-token` 需要
//!      浏览器把 `sid` 带回上游回调页，而登录入口 URL 的 `redirect` 参数必须
//!      指向一个本机地址 —— 没有它，上游登录完成后不会记录这次授权。
//!
//! ── 因此本包支持的登录方式 ──────────────────────────────────
//!   - **粘贴凭据**（`token`）：账号页直接走 `account.normalize`，不经过本模块；
//!   - **导入本机登录态**（`desktop`）：同样走 `account.normalize`，由宿主
//!     固定本机来源 `desktop.credentials.catpaw.v1` 读 `~/.meituan-catpaw/auth.json`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

/// `login.start`：明确告知网页登录未接通，并给出可用的替代入口。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("");
    match method {
        "browser" => Err(Error::http(
            501,
            "本包未接通 CatPaw 网页登录：wasm 插件无法在本机监听回调端口。请在 CatPaw 桌面端登录后点「导入本机登录态」，或在账号页粘贴 accessToken / auth.json 内容",
        )),
        // 粘贴与桌面导入都由账号页直接走 account.normalize，不会调到这里；
        // 真被调到就是调用方走错了入口，给一句指引而不是静默成功。
        "token" | "desktop" => Err(Error::http(
            400,
            "CatPaw 的粘贴凭据与本机导入不需要登录流程：请在账号页直接提交登录态",
        )),
        other => Err(Error::http(
            400,
            format!("CatPaw 不支持的登录方式「{other}」：可用的是粘贴凭据与本机登录态导入"),
        )),
    }
}

/// `login.poll`：没有进行中的流程（网页登录未接通，见模块头）。
pub fn poll(_params: &Value) -> Result<Value> {
    Err(Error::http(
        501,
        "本包没有进行中的 CatPaw 登录流程：网页登录未接通，请改用「导入本机登录态」或粘贴凭据",
    ))
}

/// `login.cancel`：没有流程可取消，幂等返回。
pub fn cancel(_params: &Value) -> Result<Value> {
    Ok(json!(null))
}

/// `auth.methods`：把 `metadata.json` 的 `login_methods` 翻译成网关的**动态登录契约**。
///
/// ── 为什么不能直接把元数据那份回给网关 ──────────────────────
/// 网关对 wasm 包的 `dynamic_login()` 恒为 true，拿到 `admin.action` 的
/// `auth.methods` 结果后**直接反序列化成 `LoginMethodsMetadata`**
/// （`api/session.rs` 的 `read_login_methods`：数组自动包成 `{"methods": […]}`），
/// 反序列化失败就冒泡成 502「插件返回的登录方式元数据无法解析」—— 表现是
/// 「添加账号」面板整个打不开，而且网关不会回退到旧入口。元数据里那份
/// `{kind, button, hint}` 因此不能原样返回。
///
/// ── 三条映射（与 `metadata.json` 的 `login_methods` 逐条对应）──
///   0. `browser`「网页登录」   → `type: "oauth"`
///   1. `token`  「登录凭据」   → `type: "api"`（附一个可选的 uid 补充字段）
///   2. `desktop`「导入本机登录态」→ `type: "desktop"`
///
/// ── `methodIndex 2`（`desktop`）那条为什么写 `localOnly` 而**不是** `desktopOnly` ──
/// 网关的 `desktopOnly` 语义是「这条 OAuth 只能在内嵌窗口打开」，校验见
/// `session.rs:285`：`desktopOnly` 为真却 `type != "oauth"` 或
/// `embeddedOnly != true` → 502「插件登录窗口契约无效」。本机导入那条的契约
/// 是另一组键（`session.rs:359` / 前端 `add-account-dynamic-fields.ts:205`）：
/// `type: "desktop"` + `localOnly: true` + `browserMode: "none"` + 空 `prompts`。
/// 本包 `wasm.json` 的 requires 含 `desktop.credentials.v1`，网关才认这条
/// （缺该能力同样 502「插件本机导入契约无效」）。
///
/// ── `browserMode` 取 `choice` 的依据 ────────────────────────
/// 本包的 `login.start` 对网页登录如实返回 501（wasm 起不了回调端口，见模块头），
/// 因此没有 `login_ui.browserMode` 可抄。native 侧是「loopback 端口收 POST 回调」
/// 的回调型流程，回调型在网关的取法是 `choice`（让用户决定内嵌窗口还是系统浏览器），
/// 与 atomcode / qoder 这两个已通过的包取法相同。
///
/// ── 文案来源 ────────────────────────────────────────────────
/// `label` / `instructions` / `placeholder` 全部取 `metadata.json` 的原文，
/// 界面上看到的按钮与提示与 native 版保持一致。`locale` 参数按网关调用约定保留
/// （网关传 `params["locale"]`），当前元数据只有中文一份，因此不参与取值。
pub fn login_methods(_locale: &str) -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "oauth",
            "label": "网页登录",
            "instructions": "打开美团 passport 授权页，完成后自动收下账号",
            "prompts": [],
            "browserMode": "choice",
            "manualCallback": false,
        },
        {
            "methodIndex": 1,
            "type": "api",
            "label": "登录凭据",
            "instructions": "粘贴 accessToken / auth.json 内容",
            "prompts": [
                {
                    "key": "token",
                    "type": "text",
                    "label": "登录凭据",
                    "placeholder": "粘贴 accessToken / auth.json 内容",
                    "secret": true,
                },
                {
                    "key": "uid",
                    "type": "text",
                    "label": "uid / 登录名",
                    "placeholder": "可选：账号的 uid 或登录名",
                    "secret": false,
                    "optional": true,
                },
            ],
        },
        {
            "methodIndex": 2,
            "type": "desktop",
            "label": "导入本机登录态",
            "instructions": "读取本机 CatPaw 客户端的登录态（~/.meituan-catpaw/auth.json）",
            "prompts": [],
            "browserMode": "none",
            "localOnly": true,
        },
    ] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_login_reports_unavailable() {
        let error = start(&json!({ "method": "browser" })).err();
        assert_eq!(error.and_then(|error| error.status), Some(501));
    }

    #[test]
    fn token_method_points_to_account_page() {
        let error = start(&json!({ "method": "token" })).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
    }

    #[test]
    fn cancel_is_idempotent() {
        assert!(cancel(&json!({})).is_ok());
    }
}
