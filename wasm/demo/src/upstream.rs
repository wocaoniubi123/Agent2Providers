//! 示例 provider 的出站面：假上游地址、请求头、一次 POST。
//!
//! 迁移来源：`crates/providers/src/providers/demo/mod.rs` 的两处地址解析
//! （`build_chat` 与 `conversation` 各写了一遍，这里合成一份）。
//!
//! ── 这家没有真实上游 ──────────────────────────────────────
//! 它是「示例 provider」：请求指向端到端验证脚本起的**本地假上游**
//! （native 的 `scripts/verify-plugin-host.mjs` 起在 `127.0.0.1:18080`）。
//! 把这条假上游完整搬过来，是这一个包在验证链条里最有价值的地方 ——
//! 其余包都对真上游，只有它能对着本地假上游跑端到端。
//!
//! ── 地址的三个来源（优先级从高到低，与 native 逐条一致）──────
//!   1. `x-demo-upstream` 请求头：测试与验证脚本用它**逐请求**指定端口
//!      （一个测试进程里会有多个假上游；插件的配置在进程起来之后不便于
//!      反复改，所以逐请求指定这条必须留着）；
//!   2. 设置项 `upstream`：部署时的静态配置。native 读的是
//!      `std::env::var("DEMO_UPSTREAM")`，wasm 沙箱里没有环境变量，改读
//!      `sdk::settings::get("upstream")`（设置项由 `metadata.json` 的
//!      `settings_schema` 声明，界面里可编辑）；
//!   3. 回环 18080：没有配置时的兜底。
//!
//! ── 默认配置在沙箱里发不出去（这条必须写在代码里，别只写进文档）──
//! 宿主 `plugin_host/wasm/manifest.rs:277-288` 的 `check_url` 要求：
//!   * `url.scheme() == "https"`；
//!   * `url.username()` 为空、无密码、无 fragment；
//!   * `url.origin().ascii_serialization()` **精确命中** `wasm.json` 的
//!     `origins`（`Vec::contains`，字符串全等 —— 并非后缀匹配）。
//! 而 `wasm/services.rs:388` 对每一次 `http.open` 都先过 `check_url`。
//! `http://127.0.0.1:18080` 在「scheme 必须是 https」这一条上就不成立，
//! 所以哪怕把 origin 写进白名单也过不去。
//!
//! 所以 `chat.rs` 在发请求**之前**就把这条判据翻成中文报给用户，而不是
//! 让宿主统一回一句「插件请求地址未获网络授权」（那句话看不出是
//! 「demo 的假上游」这一家的示例限制，还是用户自己填错了地址）。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 示例 provider 的 id（`pack.json` 与 `metadata.json` 里都是它）。
pub const ID: &str = "demo";

/// 假上游兜底地址（native 的同一份）。
pub const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:18080";

/// 对话路径（native 的 `{base}/v1/chat/completions`）。
pub const CHAT_PATH: &str = "/v1/chat/completions";

/// 设置项名（`metadata.json` 的 `settings_schema.fields[].key`）。
pub const SETTING_UPSTREAM: &str = "upstream";

/// 逐请求指定上游的请求头（native 的 `x-demo-upstream`）。
pub const HEADER_UPSTREAM: &str = "x-demo-upstream";

/// 设置项里的一段文本（不是文本就当作没有配置）。
fn setting_text(value: &Value) -> Option<String> {
    let text = match value {
        Value::String(text) => text.clone(),
        // 设置项将来改成数字端口也能用：`18080` 这种配置不该被静默忽略。
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// 假上游的基地址（末尾不带 `/`）。
///
/// 三个来源的优先级见模块头；任何一段读不到都往后落，不报错 ——
/// 地址解析失败在 native 里也只是退到兜底，不是错误路径。
pub fn base(headers: &Value) -> String {
    let from_header = headers
        .get(HEADER_UPSTREAM)
        .and_then(setting_text);
    let from_setting = sdk::settings::get(SETTING_UPSTREAM)
        .ok()
        .as_ref()
        .and_then(setting_text);
    from_header
        .or(from_setting)
        .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// 一次对话的完整 URL（native：`format!("{base}/v1/chat/completions")`）。
pub fn chat_url(base: &str) -> String {
    format!("{base}{CHAT_PATH}")
}

/// 这个基地址是不是 https（大小写不敏感，与 URL scheme 的规则一致）。
///
/// 这里只看前缀 —— 真正的放行判定在宿主 `check_url` 里，这个函数只负责
/// 让失败原因说得清楚。
pub fn is_https(base: &str) -> bool {
    base.len() > "https://".len() && base[.."https://".len()].eq_ignore_ascii_case("https://")
}

/// 一次出站的请求头（JSON 对象，`sdk::http::open` 要的形态）。
///
/// native 的两处差异都在这里落：
///   * `authorization` 用账号提示拼 `Bearer demo-<hint>`（示例没有真令牌）；
///   * 客户端带来的 `x-demo-*` 原样透传（native 的同一段循环）。
/// 客户端 UA 不在这里处理：宿主会按账号的 `public.userAgent` 覆盖
/// `User-Agent`（`wasm/services.rs:389-405`），插件再拼一份只会打架。
pub fn headers(hint: &str, incoming: &Value) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in header_pairs(hint, incoming) {
        object.insert(key, Value::String(value));
    }
    Value::Object(object)
}

/// 同样的头，但给 `chat` 的「请求计划」用（协议里 `ChatPlan.headers`
/// 是 `Vec<(String, String)>`，序列化成 `[["k","v"], …]`）。
pub fn header_pairs(hint: &str, incoming: &Value) -> Vec<(String, String)> {
    let mut pairs = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("authorization".to_string(), format!("Bearer demo-{hint}")),
    ];
    if let Some(map) = incoming.as_object() {
        for (key, value) in map {
            if !key.starts_with("x-demo-") {
                continue;
            }
            if let Some(text) = value.as_str() {
                pairs.push((key.clone(), text.to_string()));
            }
        }
    }
    pairs
}

/// 发一次 POST，返回响应（`http::open` 的薄封装）。
///
/// 网络层失败包一层中文：宿主给的是 `Error{message}`，插件这一层是
/// 「这家发不出去」的最后一句可读文案。
pub fn post(url: &str, headers: Value, body: &Value) -> agent2api_wasm_sdk::Result<sdk::http::Response> {
    sdk::http::open("POST", url, headers, Some(body)).map_err(|error| {
        agent2api_wasm_sdk::Error::http(502, format!("示例上游请求发不出去：{}", error.message))
    })
}

/// 对话请求的 body：`model` 换成网关解析出的发送名（native `build_chat`）。
///
/// `conversation` 那条路 native 是**原样**发 `req.body`（网关已经把 model
/// 改写成发送名了），所以这个函数只服务 `chat` 的示例分支。
pub fn send_body(body: &Value, wire_model: &str) -> Value {
    let mut body = body.clone();
    if let Some(object) = body.as_object_mut() {
        object.insert("model".to_string(), json!(wire_model));
    }
    body
}
