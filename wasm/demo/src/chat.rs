//! 对话转发：`conversation`（真正生效）与 `chat`（死路径的示例）。
//!
//! 迁移来源：`crates/providers/src/providers/demo/mod.rs` 的
//! `build_chat`（无状态）与 `conversation`（有状态）。
//!
//! ── 为什么两条都保留，而只有一条会跑 ────────────────────────
//! native 的示例刻意同时演示两条转发路径。wasm 这边：
//!   * `chat`：网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对
//!     wasm 包**直接返回 501**（网关原文：「Wasm 对话必须使用标准流通道，
//!     不接受主程序代发计划」），而 `forwards_response()` 对 wasm 恒为 true
//!     —— 所以这条分支写了也**在网关侧走不到**。这里保留它只为对照 native
//!     的「请求计划怎么构造」，返回形态按 `ChatPlan` 给全；
//!   * `conversation`：唯一真正生效的发送入口 —— 插件自己发请求，再用
//!     `stream_head` / `stream_bytes` 把上游 SSE 回传给网关。
//!
//! ── 假上游在沙箱里到不了（这条判据写在代码里）────────────────
//! 宿主 `plugin_host/wasm/manifest.rs:277-288` 的 `check_url`：scheme 必须是
//! `https`、且 `url.origin()` 要**精确命中** `wasm.json` 的 `origins`；
//! `wasm/services.rs:388` 对每次 `http.open` 都先过这一关。
//! 默认假上游是 `http://127.0.0.1:18080`（回环 + 明文），两条都不满足，
//! 所以默认配置下这个分支**必然**在这里停下。
//!
//! 处置方式（为什么这样选，见迁移汇报）：把它翻成一句说清依据的中文错误
//! 返回，而不是让宿主统一回「插件请求地址未获网络授权」—— 后者看不出这是
//! 「示例包对着本地假上游」的固有边界，还是用户自己填错了地址。一旦有人把
//! 设置项 `upstream` 指向一个 **https** 假上游、并把它的 origin 写进
//! `origins`，下面 `send` 那条路就是完整可用的（拼地址、拼头、报头、逐段
//! 转发），一个字都不少。
//!
//! ── 与 native 的三处差别 ───────────────────────────────────
//!   * native 用 `reqwest::Client` + `ConversationSink`；wasm 用
//!     `sdk::http::open` + `stream_head` / `stream_bytes`；
//!   * native 把上游响应头逐条塞进 `StreamHead.headers`；宿主 `stream.head`
//!     固定只发 `content-type: text/event-stream`（`sdk/lib.rs:91-93`），
//!     插件这一层拿不到「透传上游头」的通道，所以只报状态码；
//!   * native 的 `with_account_user_agent()` 在 wasm 里由宿主代劳：它按账号
//!     `public.userAgent` 覆盖 `User-Agent`（`wasm/services.rs:389-405`）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account;
use super::upstream;

/// 请求体大小上限：宿主单帧 16 MiB，超过这个数的 body 走到上游也没有意义
/// （native 侧网关也在 14 MiB 处先拒图片请求）。
const MAX_BODY_BYTES: usize = 14 * 1024 * 1024;

/// 账号提示：优先用宿主给的账号 id（native 用 `store_get` 的返回值）。
///
/// 读不到账号不是错误 —— 示例的 `conversation` 允许在**没有账号**时也能演示
/// 出站形状（native 的 `store_get` 失败时会退回 `req.account` 原值）。
fn account_hint(params: &Value) -> String {
    account::record()
        .ok()
        .and_then(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| params["account"].as_str().unwrap_or("").to_string())
}

/// 「默认假上游在沙箱里到不了」的说明（默认配置下 `conversation` 的返回）。
///
/// 措辞里把三件事说全：默认地址是什么、宿主的两条放行条件是什么、要走通
/// 需要改什么。这样别人拿这个包当模板时不会以为是代码写错了。
fn blocked_message(base: &str) -> String {
    format!(
        "示例 provider（id={id}）的默认假上游 {base} 在 wasm 沙箱里到不了：\
         宿主只放行 https 地址，且 origin 必须精确命中 wasm.json 的 origins\
         （plugin_host/wasm/manifest.rs:277-288，services.rs:388 对每次 http.open 都先过这一关）。\
         这是示例包对着本地假上游时的固有边界，与配置是否写错无关。\
         要真的跑通：把设置项 upstream 指向一个 https 假上游，并把它的 origin 写进 origins；\
         那条路上的转发逻辑与 native 逐段一致。",
        id = upstream::ID,
    )
}

/// `conversation`：示例的会话式转发。
///
/// 与 native 的三步对应：读账号（回调）→ 发请求 → 报头 + 逐段推正文。
pub fn conversation(params: &Value) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "示例 provider 的请求体必须是 JSON 对象"));
    }
    if body.to_string().len() > MAX_BODY_BYTES {
        return Err(Error::http(413, "示例 provider 的请求体超过 14 MiB"));
    }
    let hint = account_hint(params);
    // 地址三来源（请求头 → 设置项 upstream → 回环 18080），见 upstream.rs。
    let base = upstream::base(&params["headers"]);
    if !upstream::is_https(&base) {
        // 503 而不是 502：这条是「这一家此刻在这台宿主上的前置条件不成立」，
        // 不是上游返回了一个坏响应。文案才是给用户看的那一句。
        return Err(Error::http(503, blocked_message(&base)));
    }
    let url = upstream::chat_url(&base);
    let headers = upstream::headers(&hint, &params["headers"]);
    let mut response = upstream::post(&url, headers, body)?;
    // 先报头：网关据此决定状态码与翻译机（status >= 400 时它会收齐 body
    // 再调本插件的 `classify`，那条路才是 native 判定顺序生效的地方）。
    sdk::stream_head(response.status)?;
    // 逐段推正文。宿主 `stream.chunk` 自带背压（额度用完会挂起），
    // 所以不要先缓冲整段回答，那会让背压失效（native 的同一条注释）。
    while let Some(chunk) = response.read()? {
        sdk::stream_bytes(&chunk)?;
    }
    Ok(())
}

/// `chat`：native `build_chat` 的对照实现（**网关不会调用这条**）。
///
/// 返回形态按协议 `ChatPlan`：`{url, headers: [[k, v], …], body, upstream}`。
/// 保留它的理由见模块头：这份包的价值之一是「拿它当写新 provider 的模板」，
/// 而 native 的模板正好演示了无状态路径要构造什么。
pub fn chat_plan(params: &Value) -> Result<Value> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "示例 provider 的请求体必须是 JSON 对象"));
    }
    let hint = account_hint(params);
    let base = upstream::base(&params["headers"]);
    let wire_model = params["wire_model"].as_str().unwrap_or("");
    let pairs: Vec<Value> = upstream::header_pairs(&hint, &params["headers"])
        .into_iter()
        .map(|(key, value)| json!([key, value]))
        .collect();
    Ok(json!({
        "url": upstream::chat_url(&base),
        "headers": pairs,
        // native 的 `build_chat` 会把 model 换成网关解析出的发送名
        // （`conversation` 那条路不换 —— 网关在进插件前已经改好了）。
        "body": upstream::send_body(body, wire_model),
        "upstream": "chat",
    }))
}
