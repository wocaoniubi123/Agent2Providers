//! Trae 的出站薄封装：主机、请求头、一次 POST、候选失败的说明文案。
//!
//! ── 为什么单独一个文件 ──────────────────────────────────────
//! 登录、续期、目录、额度、签到五条链都要"POST 一个 JSON、拿到状态与原文"，
//! 而且都要**依次试多个 host，第一个拿到令牌的算数**。那个循环如果每个调用点
//! 各写一遍，就会出现"一处超时 5s、另一处 30s""一处截断一处不截"的漂移。

use agent2api_wasm_sdk::{http, Error, Result, Value};

/// 聊天与目录的上游（CN 与 SOLO 共用）。
pub const AGENT_BASE_URL: &str = "https://trae-api-cn.mchost.guru";
/// 积分 / 权益 / 签到那条链的域名（参考实现的包级常量 `UgHost`，
/// **不看账号 apiHost** —— 谱系/画像不匹配时上游会回 401 `code=1001`）。
pub const UG_HOST: &str = "https://api.trae.cn";
pub const CHAT_PATH: &str = "/api/agent/v3/llm_utils_chat";
pub const MODELS_PATH: &str = "/api/ide/v1/get_detail_param";
/// 一次获取各聊天 function 的目录，模型读数与请求路由一起归并。
pub const BATCH_MODELS_PATH: &str = "/api/ide/v1/batch_get_detail_param";

/// 提供商 id（注册表与 `pack.json` 用同一条）。
pub const PROVIDER_ID: &str = "trae";

/// 上游响应体的读取上限。
///
/// 参考实现是 1 MiB（`io.LimitReader`）。留上限不是为了省内存，而是
/// `www.*` 那类 host 会回一整个 HTML 页面：没有截断的话，一次"试下一个候选"
/// 会把整页 HTML 拼进错误消息里，日志与客户端都会被淹掉。
const MAX_BODY_BYTES: usize = 1 << 20;

/// 一次 POST 的结果。HTTP 状态本身**不**在这里判成错误 —— 多候选轮询
/// 要靠状态码决定换不换 host。
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// 两条链各自的出口主机。
///
/// ── 为什么这里**不**给主机覆盖 ──────────────────────────────
/// `wasm.json` 的 `origins` 是硬白名单：多一个可配置主机就多一个"配了但被白名单
/// 拦掉"的静默失败面（编译不报错，运行期请求直接失败）。native 里这两个 host
/// 是编译期常量，插件这一版保持常量；要换出口请改宿主的出网设置，那里改的是
/// 同一条链路，不是主机名。
pub const AGENT_BASE: &str = AGENT_BASE_URL;
pub const ACCOUNT_BASE: &str = UG_HOST;

/// 把 `(名字, 值)` 列表变成 `http.open` 要的头对象。
pub fn header_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// `POST` 一个 JSON 体。网络层错误归一成 502（"上游没答"）。
pub fn post_json(url: &str, body: &Value, headers: &[(String, String)]) -> Result<Reply> {
    let mut response = http::open("POST", url, header_object(headers), Some(body))
        .map_err(|error| Error::http(502, format!("Trae 请求发不出去：{}", error.message)))?;
    let status = response.status;
    let text = read_limited(&mut response, MAX_BODY_BYTES);
    Ok(Reply { status, body: text })
}

/// 读响应体，最多 `limit` 字节（超出部分丢弃而不是报错：我们只要错误原文
/// 的前一段，报错会把"上游 500"变成"读回应失败"）。
pub fn read_limited(response: &mut http::Response, limit: usize) -> String {
    let mut output: Vec<u8> = Vec::new();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(output.len());
                if room == 0 {
                    break;
                }
                output.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

/// 把多个候选 host 的失败拼成一条**能看懂**的报错。
///
/// 只给最后一个错是不够的：登录换证失败最常见的原因是某个 host 在 TLB 边缘
/// 直接 404，用户看到"404 page not found"会以为链接错了，而实际是候选顺序问题。
pub fn describe_candidates(urls: &[String], errors: &[String]) -> String {
    let mut message = format!("Trae 换证失败（试过 {} 个地址）", urls.len());
    for (index, error) in errors.iter().take(3).enumerate() {
        message.push_str(&format!("；{} {}", index + 1, error));
    }
    message
}

/// 上游错误体截断用（`www.*` 那类 host 会回一整页 HTML，不截会把日志淹掉）。
pub fn trim(text: &str) -> String {
    let collapsed: String = text.chars().filter(|character| !character.is_control()).collect();
    match collapsed.char_indices().nth(200) {
        Some((index, _)) => format!("{}…", &collapsed[..index]),
        None => collapsed,
    }
}

/// `application/x-www-form-urlencoded` 的转义（Go `url.QueryEscape` 同规则）：
/// 字母数字与 `-_.~` 原样，空格成 `+`，其余 `%XX` 大写。
/// ⚠️ `*` 是要转义的（`%2A`）—— 与 `encodeURIComponent` 那一组不同，
/// 别把 codearts 签名层的未保留字符集抄到这里。
pub fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
