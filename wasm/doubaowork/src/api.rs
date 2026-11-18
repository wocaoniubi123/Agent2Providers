//! 上游地址、请求头、错误分类与一次控制面 POST。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/api.rs`。
//!
//! ── 设备号为什么单独提一行 ──────────────────────────────────
//! 上游风控认的是「这个账号在这台受信设备上」（native `client.rs` 模块头有
//! 完整实测）：只带 Cookie 会收到 `error_code=710022004 / rate limited` 的
//! 人机验证，补上 `device_id` 与它派生出的 `fp=verify_<device_id>` 才正常回答。
//! native 读本机客户端 `Local State` 拿设备号；wasm 沙箱**没有文件系统**，
//! 所以设备号只能来自账号自己的 Cookie（`device_id`）或导入时存下的
//! `deviceId`。宿主 `checkin_call/doubao_daily/credentials.rs` 的
//! `matches_turn_request` 会强制要求设备号非空、且 `fp == verify_<device_id>`，
//! 缺了就整条对话通道被拒 —— 这一点在 `chat` / `images` 入口处会先自检，
//! 把「请重新导入带 device_id 的 Cookie」直接说清楚。
//!
//! ── 文案前缀必须幂等 ────────────────────────────────────────
//! 转发失败时插件先把错误体推给宿主，宿主紧接着又拿**同一个体**回头调
//! `classify`；`classify` 会再走一次 [`error`]。不幂等的话用户看到的是
//! 「豆包工作：豆包工作：rate limited」。判据用「是否已带前缀」，不靠计数
//! （native 2026-11-02 在真实账号上逐字抓到过）。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::account;

pub const BASE_URL: &str = "https://www.doubao.com";
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
/// 上游按 `pc_version` 下发模型菜单；只有 `runtime_version` 时会成功返回空菜单。
const DEFAULT_CLIENT_VERSION: &str = "2.33.5";
const LABEL: &str = "豆包工作：";
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

pub fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

pub fn identifier(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|id| id.to_string()))
        .filter(|id| !id.trim().is_empty())
}

/// RFC 3986 未保留字符集之外的字节一律百分号编码（与 native 同一份规则）。
pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// 一次请求要用的凭据投影。
#[derive(Clone, Default)]
pub struct Credential {
    pub cookie: String,
    pub device_id: String,
    pub web_id: String,
    pub fingerprint: String,
    pub tea_uuid: String,
    pub web_tab_id: String,
    pub client_version: String,
    pub channel: String,
    pub chromium_version: String,
    pub user_agent: String,
}

impl Credential {
    pub fn new(secret: &Value) -> Result<Self> {
        let cookie = account::cookie_header(secret)?;
        let pairs = account::pairs(secret)?;
        let pick = |name: &str| pairs.get(name).cloned().unwrap_or_default();
        let field = |name: &str| {
            secret[name]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.trim().to_string())
                .unwrap_or_default()
        };
        // 设备号顺序与 native 一致：账号自己的 `deviceId` 优先，其次 Cookie 里的
        // `device_id`（网页登录态里可能带）。native 还有一层「读本机客户端」的兜底，
        // wasm 沙箱做不到 —— 见本模块头。
        let device_id = match field("deviceId") {
            value if !value.is_empty() => value,
            _ => pick("device_id"),
        };
        Ok(Self {
            cookie,
            device_id,
            web_id: match field("webId") {
                value if !value.is_empty() => value,
                _ => pick("web_id"),
            },
            fingerprint: match field("fingerprint") {
                value if !value.is_empty() => value,
                _ => {
                    let web = pick("s_v_web_id");
                    if web.is_empty() {
                        pick("fp")
                    } else {
                        web
                    }
                }
            },
            tea_uuid: field("teaUuid"),
            web_tab_id: field("webTabId"),
            client_version: field("clientVersion"),
            channel: field("channel"),
            chromium_version: field("chromiumVersion"),
            user_agent: field("userAgent"),
        })
    }

    /// 组装一次上游请求的完整地址（含查询串）。
    ///
    /// 查询参数集合与 native 一致；宿主 `doubao_turn` 会核对其中
    /// `device_id` / `web_id` / `channel` / `chromium_version` / `tea_uuid` /
    /// `web_tab_id` / `fp` 的取值，所以这几个键不能省、也不能换值。
    pub fn endpoint(&self, path: &str) -> String {
        let version = if self.client_version.trim().is_empty() {
            DEFAULT_CLIENT_VERSION
        } else {
            self.client_version.as_str()
        };
        let mut query = vec![
            ("aid", "1044603".to_string()),
            ("real_aid", "1044603".into()),
            ("device_platform", "web".into()),
            ("version_code", "20800".into()),
            ("samantha_web", "1".into()),
            ("web_platform", "desktop".into()),
            ("doubao_device_platform", "desktop".into()),
            ("client_platform", "pc_client".into()),
            ("pkg_type", "release_version".into()),
            ("runtime", "web".into()),
            ("runtime_version", "3.42.2".into()),
            ("pc_version", version.to_string()),
            ("doubao_pc_version", version.to_string()),
            ("use-olympus-account", "1".into()),
            ("language", "zh".into()),
            ("region", "CN".into()),
            ("sys_region", "CN".into()),
        ];
        for (wire, value) in [
            ("web_id", &self.web_id),
            ("chromium_version", &self.chromium_version),
            ("channel", &self.channel),
            ("tea_uuid", &self.tea_uuid),
            ("web_tab_id", &self.web_tab_id),
        ] {
            if !value.trim().is_empty() {
                query.push((wire, value.clone()));
            }
        }
        if !self.device_id.trim().is_empty() {
            query.push(("device_id", self.device_id.clone()));
            query.push(("fp", format!("verify_{}", self.device_id)));
        } else if !self.fingerprint.trim().is_empty() {
            query.push(("fp", self.fingerprint.clone()));
        }
        let query = query
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{BASE_URL}{path}?{query}")
    }

    /// 出站请求头（宿主会覆盖 `User-Agent`，这里仍按 native 带上）。
    pub fn headers(&self) -> Value {
        let agent = if self.user_agent.trim().is_empty() {
            USER_AGENT
        } else {
            self.user_agent.as_str()
        };
        json!({
            "cookie": self.cookie,
            "origin": BASE_URL,
            "referer": format!("{BASE_URL}/chat/"),
            "user-agent": agent,
            "agw-js-conv": "str",
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
        })
    }

    /// 对话 / 生图前自检：宿主固定对话通道要求设备号非空。
    pub fn require_device(&self) -> Result<()> {
        if self.device_id.trim().is_empty() {
            return Err(Error::http(
                401,
                "豆包工作账号缺少设备号（device_id）。请在该账号的豆包网页端登录后重新导入完整 Cookie；\
                 本插件运行在沙箱里，不能像本机客户端那样读取设备信息",
            ));
        }
        Ok(())
    }
}

/// 告知宿主本轮对话流已经完整结束（宿主固定入口 `doubao.turn.finish`）。
///
/// ── 为什么必须主动调 ────────────────────────────────────────
/// 宿主 `doubao_turn::Turn` 在**没有** finish 的情况下被丢弃时，会在后台补发
/// `break_stream_msg`（并逐个 terminate 任务线程）。正常答完的一轮也走这条路，
/// 等于每轮都额外发一次「停止」请求。调一次 `finish`（要求回执里
/// `SSE_REPLY_END` 的 `end_type == 3`）就把这次收尾认下来。
///
/// 失败一律忽略：回执不完整（上游提前结束、我们已不再读流）时它必然失败，
/// 那时宿主按未确认处理、照旧发停止请求 —— 与不调用时行为一致，不能因此把
/// 一次已经成功的回答改成错误。
pub fn finish_turn() {
    let _ = agent2api_wasm_sdk::host("doubao.turn.finish", json!({}));
}

/// 一次控制面 POST（自动带查询串与请求头）。
pub fn post(credentials: &Credential, path: &str, body: &Value) -> Result<Value> {
    let response = http::open(
        "POST",
        &credentials.endpoint(path),
        credentials.headers(),
        Some(body),
    )?;
    json_response(response, path.starts_with("/alice/ug/"))
}

/// 读完整回应并判成败：非 2xx 或业务码非 0 都算失败（`/alice/ug/` 允许 200）。
pub fn json_response(response: http::Response, ug: bool) -> Result<Value> {
    let status = response.status;
    let bytes = response.bytes(MAX_RESPONSE)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        Error::http(
            502,
            "豆包工作未返回有效 JSON，请检查登录态或稍后重试",
        )
    })?;
    if !(200..300).contains(&status)
        || number(&value["code"]).is_some_and(|code| code != 0 && !(ug && code == 200))
    {
        return Err(error(status, &value));
    }
    Ok(value)
}

/// 给上游文案加一次「豆包工作：」前缀（**幂等**，理由见模块头）。
fn label_once(message: &str) -> String {
    if message.starts_with(LABEL) {
        message.to_string()
    } else {
        format!("{LABEL}{message}")
    }
}

/// 上游风控的人机验证判据：命中时返回场景名（如 `doubao_message_web`）。
///
/// 豆包风控（`shark_admin`）把「要人工过滑块」伪装成
/// `error_code=710022004 / error_msg=rate limited`：照字面读就是一条账号限额，
/// 于是用户看到的文案既说不清原因、也给不出下一步。真类型只写在
/// `extra.decision` 里（一段 JSON **字符串**）：
/// `{"from":"shark_admin","type":"verify","subtype":"slide","verify_scene":"…"}`。
/// 只认 `type=verify`，解析不出来就当普通错误，不去猜。
fn risk_verify(value: &Value) -> Option<String> {
    /// `decision` 里还塞着一段加密的挑战载荷，给个上限免得为一条错误体做大解析。
    const MAX_DECISION: usize = 64 * 1024;
    let extra = value
        .get("extra")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let decision = extra.get("decision").or_else(|| value.get("decision"))?;
    let parsed = match decision {
        Value::String(text) if text.len() <= MAX_DECISION => {
            serde_json::from_str::<Value>(text).ok()?
        }
        Value::Object(_) => decision.clone(),
        _ => return None,
    };
    if parsed.get("type").and_then(Value::as_str) != Some("verify") {
        return None;
    }
    Some(
        parsed
            .get("verify_scene")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

/// 风控要求人工验证时的文案：说清「这不是额度问题」与「下一步做什么」。
///
/// 状态码仍取 **429** —— 编排层对此的处置正是我们要的（把这个账号从本模型上
/// 挪开、换下一个候选），而 `classify` 按状态码分档，改动它的语义会牵动
/// 「退避 / 熔断」那一套（那是给瞬时故障准备的，对一个需要人工介入的账号更不合适）。
fn verify_message(scene: &str) -> String {
    let scene = scene.trim();
    let scene = if scene.is_empty() {
        String::new()
    } else {
        format!("（场景 {scene}）")
    };
    format!(
        "触发了豆包上游的人机验证{scene}，不是账号额度问题（该账号当前所有模型都会被拦下）：\
         请在该账号的豆包网页端发一条消息、完成滑块验证后重试；\
         也可以等待约 30 分钟或更换出口网络再试。"
    )
}

/// 上游错误体 → 带状态码与业务码的错误。
///
/// `code` 同时写进 `provider_http:` 元数据：宿主 `plugin_host/errors.rs` 的
/// `control_error` 认这个前缀，会据此调本包的 `classify` 拿到
/// TokenExpired / QuotaLimited 这类处置结论 —— 少了它，401 只会被当成
/// 一条普通 502 透传，账号永远不会被换掉。
pub fn error(status: u16, value: &Value) -> Error {
    let detail = value
        .get("error_detail")
        .filter(|value| value.is_object())
        .or_else(|| value.get("error").filter(|value| value.is_object()))
        .unwrap_or(value);
    let code = number(&detail["code"])
        .or_else(|| number(&detail["error_code"]))
        .or_else(|| number(&value["code"]))
        .or_else(|| number(&value["error_code"]));
    let message = ["message", "msg", "error_msg", "error_message", "detail"]
        .iter()
        .find_map(|key| detail[*key].as_str().filter(|text| !text.trim().is_empty()))
        .or_else(|| value.as_str())
        .unwrap_or("上游返回了无法解析的错误");
    if let Some(scene) = risk_verify(value) {
        return wire_error(429, &label_once(&verify_message(&scene)), code);
    }
    let lower = message.to_ascii_lowercase();
    let status = if matches!(code, Some(710012001))
        || status == 401
        || lower.contains("not logged in")
        || lower.contains("login required")
    {
        401
    } else if status == 429 || matches!(code, Some(710022004)) {
        429
    } else if status >= 400 {
        status
    } else {
        502
    };
    wire_error(status, &label_once(message), code)
}

fn wire_error(status: u16, message: &str, code: Option<u64>) -> Error {
    let upstream = code.and_then(|code| i64::try_from(code).ok());
    let metadata = json!({
        "status": status,
        "code": Value::Null,
        "upstreamCode": upstream,
    });
    let mut error = Error::http(status, message);
    error.upstream_code = upstream;
    error.code = Some(format!("provider_http:{metadata}"));
    error
}

/// 状态码 + 错误体 → 网关认识的四个分类之一。
pub fn classify(status: u16, body: &Value) -> Value {    let error = error(status, body);
    let status = error.status.unwrap_or(502);
    if status == 401 {
        return json!({"kind": "token_expired", "message": error.message});
    }
    if status == 429 {
        return json!({
            "kind": "quota_limited",
            "reset_at": Value::Null,
            "message": error.message,
            "upstream_code": error.upstream_code,
            "status": 429,
        });
    }
    json!({
        "kind": "fatal",
        "status": status,
        "message": error.message,
        "upstream_code": error.upstream_code,
    })
}

/// 查询串与设备号的自检：宿主 `matches_turn_request` 会逐项核对，这里先钉住。
#[cfg(test)]
mod tests {
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn 只编码未保留字符() {
        assert_eq!(encode("a b/c~._-"), "a%20b%2Fc~._-");
        assert_eq!(encode("中"), "%E4%B8%AD");
    }

    #[test]
    fn 设备号进入查询串并派生指纹() {
        let secret = json!({"cookieHeader": "sessionid=abc; device_id=dev123; web_id=wid"});
        let credential = Credential::new(&secret);
        assert!(credential.is_ok());
        let credential = credential.unwrap_or_default();
        let url = credential.endpoint("/chat/completion");
        assert!(url.contains("device_id=dev123"), "{url}");
        assert!(url.contains("fp=verify_dev123"), "{url}");
        assert!(url.contains("web_id=wid"), "{url}");
        assert!(url.starts_with("https://www.doubao.com/chat/completion?"));
    }

    #[test]
    fn 缺设备号时自检失败() {
        let secret = json!({"cookieHeader": "sessionid=abc"});
        let credential = Credential::new(&secret);
        assert!(credential.is_ok());
        let credential = credential.unwrap_or_default();
        assert!(credential.require_device().is_err());
    }

    #[test]
    fn 鉴权失败归到_token_expired() {
        let class = classify(401, &json!({"message": "not logged in"}));
        assert_eq!(class["kind"], "token_expired");
        assert!(class["message"].as_str().is_some_and(|text| text.starts_with("豆包工作：")));
    }

    #[test]
    fn 人机验证归到限额档() {
        let body = json!({
            "error_code": 710022004,
            "error_msg": "rate limited",
            "extra": {"decision": "{\"from\":\"shark_admin\",\"type\":\"verify\",\"subtype\":\"slide\",\"verify_scene\":\"doubao_message_web\"}"},
        });
        let class = classify(429, &body);
        assert_eq!(class["kind"], "quota_limited");
        assert!(class["message"]
            .as_str()
            .is_some_and(|text| text.contains("人机验证") && !text.contains("豆包工作：豆包工作：")));
    }
}
