//! 上游地址、公共请求头、宿主会话入口与编码工具。
//!
//! ── 这个模块存在的理由 ──────────────────────────────────────
//! 本家有三类上游（区域 API `snap-access`、福利网关 `opengw`、以及给浏览器打开
//! 的授权页 `codearts`），每类的地址、头集合与签名开关都不同。把它们收在一处，
//! 别处只按语义调用，免得「同一件事在两处各写一份、其中一处漏了某个头」——
//! 那正是签名类问题最难查的形态（错一个头就 401，且没有任何提示）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// 区域 API 的默认地址（cn-north-4 固定；本家没有多区域）。
pub const DEFAULT_BASE_URL: &str = "https://snap-access.cn-north-4.myhuaweicloud.com";
/// 福利网关的默认地址（与区域 API 不是一台主机）。
pub const DEFAULT_BENEFIT_GATEWAY_URL: &str = "https://opengw.developer.huaweicloud.com";
/// 对话端点（相对 base）。
pub const CHAT_PATH: &str = "/api/v2/chat/completions";
/// 客户端指纹的默认值（照参考实现的 config 默认档；参与签名，不能随手改）。
pub const DEFAULT_PLUGIN_NAME: &str = "snap_vscode";
pub const DEFAULT_PLUGIN_VERSION: &str = "26.9.101";
pub const DEFAULT_LANGUAGE: &str = "en-us";

/// 区域 API 根地址：`settings.get` 有配置就用配置，否则用默认值。
///
/// ── 为什么读 settings 而不是环境变量 ────────────────────────
/// wasm 插件拿不到进程环境（SDK 也没有对应能力），配置只走宿主保存的覆盖值。
/// 尾斜杠一律吃掉：拼路径时 `base + "/api/…"` 会出现 `//api/…`，那个双斜杠会
/// 进签名串（`canonicalURI` 先按 `/` 切段，空段编码成空串，于是多出一个分隔符），
/// 结果就是 401。
pub fn base() -> String {
    setting("baseUrl", DEFAULT_BASE_URL)
}

/// 福利网关根地址（同样允许覆盖）。
pub fn benefit_base() -> String {
    setting("benefitGatewayUrl", DEFAULT_BENEFIT_GATEWAY_URL)
}

fn setting(key: &str, fallback: &str) -> String {
    sdk::settings::get(key)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
        .trim()
        .trim_end_matches('/')
        .to_string()
}

/// 宿主代持的上游会话：占槽（busy）+ 后台心跳 + 注销（idle）全在宿主里。
///
/// ── 为什么必须走宿主 ────────────────────────────────────────
/// 上游对每个账号只允许 **3 路并发**对话，靠 `chat-session/heartbeat` 的
/// busy/idle 记账，且对话请求要带**同一个** `User-Session-Id` 头。wasm 插件
/// 没有定时器、活不过一次调用，既发不了后台心跳也留不住跨请求状态；宿主侧
/// `codearts.session.open/close` 正是为此准备的（权限 `http.codearts-session.v1`）。
///
/// ── 为什么还要一层 `Drop` ───────────────────────────────────
/// 出错提前返回时（`?`）也必须把槽还回去：不注销的话这个账号会一直被自己占着，
/// 攒够 3 个残留就再也发不出请求。`Drop` 里调 `codearts.session.close` 是最省事
/// 的兜底，正常路径另外显式 `close()` 一次（失败只记日志，不能改变主流程结论）。
pub struct Session {
    id: String,
    open: bool,
}

impl Session {
    /// 抢一个上游会话。失败即「这个账号此刻发不了对话」，原样上报。
    pub fn open() -> Result<Self> {
        let value = sdk::host("codearts.session.open", json!({}))?;
        let id = value["id"]
            .as_str()
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| Error::http(502, "CodeArts 会话没有返回会话标识"))?
            .to_string();
        Ok(Self { id, open: true })
    }

    /// 对话请求要带的会话头值。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 注销并等宿主把它落下去。重复调用安全（第二次什么都不做）。
    pub fn close(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        // 失败只影响槽位的释放时机，不能把一次成功的回答变成失败
        let _ = sdk::host("codearts.session.close", json!({}));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// 取一个非空字符串（多候选键，宽容读取）。账号记录与上游响应两处都用它。
pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value[*key].as_str().map(str::trim).filter(|text| !text.is_empty()))
        .unwrap_or_default()
        .to_string()
}

/// 表单口径（`application/x-www-form-urlencoded`）：空格编成 `+`。
///
/// 与 [`encode_uri_component`] 分开写是有意的：表单编码里空格是 `+`、而
/// `+` 自身要再编码，两套混用会让参数静默变形（服务端读到的是另一个值）。
pub fn form_escape(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push(HEX[(other >> 4) as usize] as char);
                out.push(HEX[(other & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 把 `Vec<(String, String)>` 的头集合转成 `http::open` 要的 JSON 对象。
///
/// 大小写：同名（大小写无关）后到覆盖前值 —— 与签名层的头集合规则一致，否则
/// 「签进去的头」和「发出去的头」会不一致。
pub fn header_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.to_ascii_lowercase(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// 发一次 GET（无体）。
pub fn get(url: &str, headers: Value) -> Result<sdk::http::Response> {
    sdk::http::open("GET", url, headers, None)
}

/// 读一个响应体（带上限），非 2xx 时返回带状态码的错误。
///
/// ── 为什么自己读而不直接 `response.json()` ─────────────────
/// 上游的错误体常常不是 JSON（整页 HTML / 空体），而 `json()` 会把「HTTP 400 +
/// 一段可读的诊断文本」压成「未返回有效 JSON」，把最有用的信息丢掉。这里统一
/// 先取字节，再由调用方决定当 JSON 解析还是当文本摘录。
pub fn read_body(mut response: sdk::http::Response, limit: usize) -> Result<(u16, Vec<u8>)> {
    let status = response.status;
    let mut body = Vec::new();
    while let Some(chunk) = response.read()? {
        let room = limit.saturating_sub(body.len());
        if chunk.len() > room {
            // 只留到限额为止：`room.min(chunk.len())` 保证切片不会越界
            body.extend_from_slice(&chunk[..room.min(chunk.len())]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}
