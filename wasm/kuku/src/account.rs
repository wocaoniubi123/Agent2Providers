//! KukuAI 凭证：解析 / 三条添加路径 / 账号面 / 真实校验。
//!
//! ── 凭证形态（照 native `kuku/credentials.rs` 模块头的实测记录）──────
//! 服务端只需要三个 Cookie 就能认证：`BDUSS`、`STOKEN`、`gfprotpl=genflowpro`。
//! 其中 `gfprotpl` 是恒定的（值就是 `genflowpro`），不在账号里存，拼 Cookie 头时
//! 固定附加。`BDUSS` 必填；`STOKEN` 可空（部分接口只用 BDUSS）。
//!
//! ── 为什么要保留 extras（2026-10-07/08 两次实测修正）──────────
//! 第一版以为「只带 BDUSS/STOKEN/gfprotpl 会被判未登录，补 BAIDUID 就好」——
//! 那只对客户端导入的凭证成立。10-08 结合客户端 asar 与换发实测定位到真正机制：
//! 业务接口（`userreport` 等）认的是**按产品签发的 STOKEN**（见 `engine.rs`），
//! 网页登录 Cookie 里那份通行证级 STOKEN 无论带多少 Cookie 都过不了；而 extras 里的
//! **PTOKEN 正是换发它的必要材料**（`ptoken_of` / `engine.rs`）。余额这类通用接口
//! 只看 BDUSS —— 所以症状是「余额正常、模型拉不下」。
//!
//! ── 三条添加路径（与 native 一一对应）────────────────────────
//! ```text
//!   manual      粘贴 Cookie（Cookie 头 / Cookie 编辑器 JSON / {BDUSS,STOKEN} 对象）
//!   desktop     本机客户端登录态（宿主代读 %APPDATA%\baidugenflowpro\Network\Cookies）
//!   file_base64 用户手选的 Cookies SQLite（宿主代解析，本次导入用完即弃）
//!   file_text   单账号 JSON 凭证快照（原生 Cookies 数据库走 file_base64）
//! ```
//!
//! ── wasm 侧与 native 的差别：文件系统归宿主 ───────────────────
//! native 自己开 SQLite（`rusqlite`）读 `value` 列。wasm 沙箱没有文件系统，也
//! 不该为读一个 Cookie 库去申请原生模块 —— 宿主为库库专门开了两条固定入口
//! （能力声明见 `wasm.json`）：
//!   - `desktop.credentials.read`（`desktop.credentials.v1` + helper
//!     `desktop.credentials.kuku.v1`）：只读本机固定路径，且只在「用户明确点了
//!     导入本机登录态」或「已保存的本机账号」两种上下文里授权；
//!   - `resource.cookie-file.take`（`resources.cookie-file.v1`，全网关只给库库）：
//!     只解析本次导入的 SQLite 字节，取一次即作废。
//! 两条入口返回同一形状 `{cookies: [{name, value, domain, path}]}`，因此下面的
//! `cookies_to_credentials` 是**唯一**一处「Cookie 列表 → 三件套」的判定。
//!
//! ── 三条路径的收尾一致 ──────────────────────────────────────
//! 解析 → `enrich` 真实校验（换发业务 STOKEN + `userreport` 换会话三件套 + `uk`）
//! → 落账号。**验证失败是错误**（添加时就要「现在真的能用」，与 native 同一口径）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::engine;
use super::session;

/// BDUSS 最小长度（百度通行证登录态，实测远大于此；只拦明显残缺的值）
const MIN_BDUSS_LENGTH: usize = 8;

/// 账号名长度上限（与账号存储的 `MAX_NAME_LENGTH` 同量级）
const MAX_NAME_LENGTH: usize = 64;

/// 一条 KukuAI 登录态（转信用核心三件套 + 同会话的其它 Cookie + 展示字段）。
#[derive(Clone, Debug, Default)]
pub struct KukuCredentials {
    pub bduss: String,
    pub stoken: String,
    /// 同一登录会话里的其它 Cookie（`BAIDUID` / `PTOKEN` / `PANPSC` 等）。
    pub extras: Vec<(String, String)>,
    /// `userreport` 返回的 `uk`（账号数字标识，兼作账号 id 来源）
    pub uid: String,
    /// 展示名（best-effort：取不到就留空，由账号层兜底）
    pub nickname: String,
}

impl KukuCredentials {
    /// 拼出请求用 Cookie 头（核心三件套 + extras + 恒附加 gfprotpl）。
    pub fn cookie_header(&self) -> String {
        let mut parts = vec![format!("BDUSS={}", self.bduss)];
        if !self.stoken.is_empty() {
            parts.push(format!("STOKEN={}", self.stoken));
        }
        for (name, value) in &self.extras {
            // 主字段与恒附加项不重复（extras 里若混入也跳掉）
            if name.eq_ignore_ascii_case("BDUSS")
                || name.eq_ignore_ascii_case("STOKEN")
                || name.eq_ignore_ascii_case("gfprotpl")
            {
                continue;
            }
            parts.push(format!("{name}={value}"));
        }
        parts.push("gfprotpl=genflowpro".to_string());
        parts.join("; ")
    }

    /// 脱敏尾段（**只用于账号身份兜底**，不进公开视图）。
    ///
    /// ── 为什么是 6 位而不是 native 的 8 位 ──────────────────────
    /// 网关 `public_view::safe_scalar` 对 `tokenTail` 的硬限制是「null 或
    /// ≤6 字符」，且公开视图里任何字符串都不许包含 secret 的受保护片段
    /// （`check` 的 `text.contains(secret)`）。native 的 8 位尾段在 wasm 侧
    /// 会让整个账号被拒收（「插件公开视图包含受保护内容或字段类型无效」），
    /// 所以这里只留 6 位，且公开视图里不放它。
    pub fn token_tail(&self) -> String {
        let chars: Vec<char> = self.bduss.chars().collect();
        if chars.len() <= 6 {
            return String::new();
        }
        chars[chars.len() - 6..].iter().collect()
    }

    /// 凭证指纹（会话缓存 key 用；不把整段 Cookie 塞进 key）。
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"agent2api:kuku:credential:v1");
        hasher.update(self.bduss.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.stoken.as_bytes());
        let digest = hasher.finalize();
        digest.iter().take(16).map(|byte| format!("{byte:02x}")).collect()
    }
}

/// 取对象里的第一个非空字符串（键名按顺序试）。
pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("")
        .to_string()
}

/// 从字符串里解析一对 `name=value`（取首个 `=` 后的全部，容忍两侧空白）。
fn cookie_pair(text: &str) -> Option<(String, String)> {
    let text = text.trim();
    let (name, value) = text.split_once('=')?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

/// 从 Cookie 头串提取核心三件套 + 其余 Cookie（保序、按名去重）。
///
/// 登录收尾（`login::callback`）复用同一套解析 —— 两处共用一份才不会出现
/// 「登录解析和账号解析认的字段不一样」的分叉。
pub fn parse_cookie_parts(text: &str) -> (String, String, Vec<(String, String)>) {
    let mut bduss = String::new();
    let mut stoken = String::new();
    let mut extras: Vec<(String, String)> = Vec::new();
    for segment in text.split(';') {
        let Some((name, value)) = cookie_pair(segment) else { continue };
        if name.eq_ignore_ascii_case("BDUSS") {
            bduss = value;
        } else if name.eq_ignore_ascii_case("STOKEN") {
            stoken = value;
        } else if !name.eq_ignore_ascii_case("gfprotpl") {
            push_extra(&mut extras, name, value);
        }
    }
    (bduss, stoken, extras)
}

/// 追加一个额外 Cookie（同名只留第一个；统计类不带 —— 对认证无用，只会把
/// Cookie 头撑长，与 native 读 SQLite 时的过滤口径一致）。
fn push_extra(extras: &mut Vec<(String, String)>, name: String, value: String) {
    let lowered = name.to_ascii_lowercase();
    if lowered.starts_with("hm_") || lowered == "hmaccount" {
        return;
    }
    if lowered.eq_ignore_ascii_case("bduss") || lowered.eq_ignore_ascii_case("stoken") || lowered.eq_ignore_ascii_case("gfprotpl") {
        return;
    }
    if extras
        .iter()
        .any(|(existing, _)| existing.eq_ignore_ascii_case(&name))
    {
        return;
    }
    extras.push((name, value));
}

/// 从对象里按大小写不敏感取核心字段 + 其余 Cookie。
fn parts_from_object(object: &serde_json::Map<String, Value>) -> (String, String, Vec<(String, String)>) {
    let mut bduss = String::new();
    let mut stoken = String::new();
    let mut extras: Vec<(String, String)> = Vec::new();
    for (key, value) in object {
        let Some(text) = value.as_str() else { continue };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if key.eq_ignore_ascii_case("BDUSS") {
            bduss = text.to_string();
        } else if key.eq_ignore_ascii_case("STOKEN") {
            stoken = text.to_string();
        } else if !key.eq_ignore_ascii_case("gfprotpl") {
            push_extra(&mut extras, key.clone(), text.to_string());
        }
    }
    (bduss, stoken, extras)
}

/// 从 `[{name, value}, …]` 数组形态取核心字段 + 其余 Cookie。
fn parts_from_array(items: &[Value]) -> (String, String, Vec<(String, String)>) {
    let mut bduss = String::new();
    let mut stoken = String::new();
    let mut extras: Vec<(String, String)> = Vec::new();
    for item in items {
        let Some(name) = item.get("name").and_then(Value::as_str) else { continue };
        let Some(value) = item.get("value").and_then(Value::as_str) else { continue };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("BDUSS") {
            bduss = value.to_string();
        } else if name.eq_ignore_ascii_case("STOKEN") {
            stoken = value.to_string();
        } else if !name.eq_ignore_ascii_case("gfprotpl") {
            push_extra(&mut extras, name.to_string(), value.to_string());
        }
    }
    (bduss, stoken, extras)
}

/// 从 payload 解析登录态，支持三种形态（与参考实现面板同口径）：
///   1. **字符串**：整段 Cookie 头（`BDUSS=…; STOKEN=…; …`）；
///   2. **数组**：Cookie 编辑器导出的 `[{name, value}, …]`；
///   3. **对象**：平铺 `{BDUSS, STOKEN}`、嵌套 `{auth: {…}}`，或
///      `{cookie | cookies: "<Cookie 头>"}` 再递归。
pub fn credentials_from_payload(payload: &Value) -> Result<KukuCredentials> {
    let (bduss, stoken, extras) = match payload {
        Value::String(text) => parse_cookie_parts(text),
        Value::Array(items) => parts_from_array(items),
        Value::Object(object) => {
            let direct = parts_from_object(object);
            if direct.0.is_empty() && direct.1.is_empty() {
                // 嵌套形态：auth / cookie / cookies / credentials 字段再取。
                // `token` 是面板那条「Cookie」表单的字段名（`auth.methods` 的 api
                // 方式把输入包在 `inputs.token` 里），值是整段 Cookie 头。
                let mut nested = (String::new(), String::new(), Vec::new());
                for key in ["auth", "cookie", "cookies", "credentials", "token"] {
                    let Some(inner) = object.get(key) else { continue };
                    nested = match inner {
                        Value::String(text) => parse_cookie_parts(text),
                        Value::Object(inner_map) => parts_from_object(inner_map),
                        Value::Array(items) => parts_from_array(items),
                        _ => continue,
                    };
                    if !nested.0.is_empty() || !nested.1.is_empty() {
                        break;
                    }
                }
                nested
            } else {
                direct
            }
        }
        _ => (String::new(), String::new(), Vec::new()),
    };
    let bduss = bduss.trim().to_string();
    let stoken = stoken.trim().to_string();
    if bduss.chars().count() < MIN_BDUSS_LENGTH {
        return Err(Error::http(
            400,
            "缺少有效的 BDUSS（粘贴 Cookie 头、Cookie 编辑器 JSON 或 {BDUSS, STOKEN} 对象）",
        ));
    }
    Ok(KukuCredentials {
        bduss,
        stoken,
        extras,
        uid: String::new(),
        nickname: String::new(),
    })
}

// ─── 宿主代读的两条本机入口 ───────────────────────────────────

/// Cookie 列表（宿主的 `{cookies: [{name, value, domain, path}]}`）→ 三件套。
///
/// ── 为什么 BDUSS/BDUSS_BFESS 与 STOKEN/STOKEN_BFESS 分开挑 ────
/// 客户端会在同一域下写两份（`BDUSS` 与其影子 `BDUSS_BFESS`，HttpOnly 那份
/// 有时只落在影子名上）。两份同名同值时去重，**不同值时以主名优先**：
/// 影子是刷新中的中间态，用它去认证会拿到「对不上的会话」。
fn cookies_to_credentials(value: &Value) -> Result<KukuCredentials> {
    let Some(rows) = value.get("cookies").and_then(Value::as_array) else {
        return Err(Error::http(502, "本机登录态读取结果缺少 cookies 列表（宿主返回异常）"));
    };
    let mut bduss = String::new();
    let mut bduss_shadow = String::new();
    let mut stoken = String::new();
    let mut stoken_shadow = String::new();
    let mut extras: Vec<(String, String)> = Vec::new();
    for row in rows {
        let name = row.get("name").and_then(Value::as_str).map(str::trim).unwrap_or("");
        let value = row.get("value").and_then(Value::as_str).map(str::trim).unwrap_or("");
        if name.is_empty() || value.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("BDUSS") {
            if bduss.is_empty() {
                bduss = value.to_string();
            }
        } else if name.eq_ignore_ascii_case("BDUSS_BFESS") {
            if bduss_shadow.is_empty() {
                bduss_shadow = value.to_string();
            }
        } else if name.eq_ignore_ascii_case("STOKEN") {
            if stoken.is_empty() {
                stoken = value.to_string();
            }
        } else if name.eq_ignore_ascii_case("STOKEN_BFESS") {
            if stoken_shadow.is_empty() {
                stoken_shadow = value.to_string();
            }
        } else {
            push_extra(&mut extras, name.to_string(), value.to_string());
        }
    }
    if bduss.is_empty() {
        bduss = bduss_shadow;
    }
    if stoken.is_empty() {
        stoken = stoken_shadow;
    }
    if bduss.chars().count() < MIN_BDUSS_LENGTH {
        return Err(Error::http(
            401,
            "本机客户端未登录（Cookies 里没有有效的 BDUSS）；请先在库库 AI 客户端登录",
        ));
    }
    Ok(KukuCredentials {
        bduss,
        stoken,
        extras,
        uid: String::new(),
        nickname: String::new(),
    })
}

/// 读本机客户端登录态（`desktop` 来源）。
///
/// 宿主只在「用户明确选择本机导入」或「这条账号本来就是本机导入型」两种上下文里
/// 授权这次读取；其余上下文会直接拒绝（错误文案由宿主给，这里只转述）。
fn read_desktop() -> Result<KukuCredentials> {
    let value = sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(400, format!("读取本机库库客户端登录态失败：{}", error.message))
    })?;
    cookies_to_credentials(&value)
}

/// 解析本次导入的 Cookies SQLite（`file_base64` 来源，取一次即作废）。
fn read_cookie_file() -> Result<KukuCredentials> {
    let value = sdk::host("resource.cookie-file.take", json!({})).map_err(|error| {
        Error::http(
            400,
            format!("解析 Cookies 数据库失败：{}", error.message),
        )
    })?;
    cookies_to_credentials(&value)
}

// ─── 账号记录 ────────────────────────────────────────────────

/// 从账号 secret 取凭证（`accessToken` 存的是整段 Cookie 头）。
pub fn credentials_of(secret: &Value) -> Result<KukuCredentials> {
    let cookie = text(secret, &["accessToken", "access_token", "cookie"]);
    if cookie.is_empty() {
        return Err(Error::http(
            401,
            "KukuAI 没有可用的登录凭证：请在账号页添加账号（粘贴 Cookie 或导入本机客户端登录态）",
        ));
    }
    let (bduss, stoken, extras) = parse_cookie_parts(&cookie);
    if bduss.chars().count() < MIN_BDUSS_LENGTH {
        return Err(Error::http(
            401,
            "KukuAI 账号缺少有效的 BDUSS：请重新添加或重新导入该账号",
        ));
    }
    Ok(KukuCredentials {
        bduss,
        stoken,
        extras,
        uid: text(secret, &["uid"]),
        nickname: text(secret, &["loginName", "nickname", "name"]),
    })
}

/// 当前账号的凭证（宿主已按 `params.account` 选好号）。
pub fn current() -> Result<KukuCredentials> {
    let record = sdk::account()?;
    credentials_of(&record["secret"])
}

/// `token.ensure` / `token.refresh` 的返回值：BDUSS 本身。
///
/// ── 为什么 token 就是 BDUSS ─────────────────────────────────
/// 凭证是 Cookie 登录态，没有「访问令牌」可以换发（`refresh: false`）；
/// 宿主拿这个字符串只是判断「这个账号此刻有没有凭据」，真正出站用的 Cookie 头
/// 由插件自己拼（含 STOKEN / extras / gfprotpl）。
pub fn current_token() -> Result<String> {
    current().map(|credentials| credentials.bduss)
}

/// 本家没有刷新接口，也读不到到期时刻 —— 恒判「不临期」。
///
/// 判据依据：BDUSS 是登录态 Cookie，上游不给过期时间，`refresh: false`；
/// 返回 `true` 只会让后台维护任务反复白跑一次 userreport。
pub fn expiring(_secret: &Value) -> bool {
    false
}

/// 凭证的 PTOKEN（`PTOKEN` 优先，影子 `PTOKEN_BFESS` 兜底）。
///
/// PTOKEN 是换发「genflowpro 作用域 STOKEN」的必要材料（见 `engine.rs`），
/// 网页登录 / 手动粘贴完整 Cookie / 本机客户端登录态三条路径都带它。
pub fn ptoken_of(extras: &[(String, String)]) -> Option<String> {
    let pick = |want: &str| {
        extras
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case(want) && !value.trim().is_empty())
            .map(|(_, value)| value.trim().to_string())
    };
    pick("PTOKEN").or_else(|| pick("PTOKEN_BFESS"))
}

/// 尽力把凭证的 STOKEN 换成「genflowpro 作用域」的新令牌（见 `engine.rs`）。
///
/// 有 PTOKEN 且换发成功才替换，否则原样返回（失败只记在结果里，不阻断）：
/// 签到这类**直接打业务接口**、不经过 `session::ensure` 自愈路径的场景用它保障
/// 会话可用；每次换发就是一次 passport POST，签到一天一次的频率没有风控顾虑。
pub fn with_business_stoken(credentials: &KukuCredentials) -> (KukuCredentials, Option<String>) {
    let mut prepared = credentials.clone();
    let Some(ptoken) = ptoken_of(&prepared.extras) else {
        return (prepared, None);
    };
    match engine::exchange_genflowpro_stoken(&prepared.bduss, &ptoken) {
        Ok(stoken) => {
            prepared.stoken = stoken;
            (prepared, None)
        }
        // wasm 侧没有日志通道（宿主不提供 log 调用）：失败原因随返回值交回，
        // 由调用方决定是「忽略并继续」还是写进给用户看的文案。
        Err(error) => (prepared, Some(error.message)),
    }
}

/// 补上账号身份（uid）：换发业务会话令牌 → `userreport` 换会话三件套 → 取 `uk`。
///
/// `force = true` 跳过三件套缓存（添加账号时用，要的是「现在真的能用」的即时验证）。
pub fn enrich(credentials: &KukuCredentials, force: bool) -> Result<KukuCredentials> {
    let (prepared, _) = with_business_stoken(credentials);
    let triple = session::ensure(&prepared, force)?;
    let mut enriched = prepared;
    if !triple.uk.is_empty() {
        enriched.uid = triple.uk;
    }
    Ok(enriched)
}

// ─── 账号面 ──────────────────────────────────────────────────

/// 账号公开视图（界面账号页读的那几个键）。
pub fn account_view(secret: &Value) -> Value {
    let cookie = text(secret, &["accessToken", "access_token", "cookie"]);
    let uid = text(secret, &["uid"]);
    let explicit = text(secret, &["name"]);
    let name = if explicit.is_empty() {
        if uid.is_empty() {
            "KukuAI 账号".to_string()
        } else {
            format!("库库 AI {uid}")
        }
    } else {
        explicit
    };
    json!({
        "name": name,
        "uid": uid,
        "loginName": text(secret, &["loginName", "nickname"]),
        // ── 为什么这里给空串（native 给 8 位尾段）─────────────────
        // 网关 `public_view::safe_scalar` 对 `tokenTail` 的硬限制是「null 或
        // ≤6 字符」，且公开视图里的字符串不得包含 secret 的受保护片段 ——
        // native 那个 8 位尾段会让整个账号在 `account.normalize` 处被拒收
        // （「插件公开视图包含受保护内容或字段类型无效」）。账号识别改用
        // `uid` / `name`，这一列保持空。
        "tokenTail": "",
        // BDUSS 是 Cookie 登录态：没有 refreshToken，也没有过期时间
        "hasSession": !cookie.is_empty(),
        "canRefresh": false,
    })
}

/// 账号的稳定身份：`kuku-<uid>`；没有 uid 时退回 Cookie 尾（与 native 同一口径，
/// 去重结果一致）。
pub fn identity_of(secret: &Value) -> String {
    let uid = text(secret, &["uid"]);
    if !uid.is_empty() {
        return format!("kuku-{uid}");
    }
    let tail = text(secret, &["tokenTail"]);
    if !tail.is_empty() {
        return format!("kuku-{tail}");
    }
    String::new()
}

/// 校验后的凭证 → 可落库的账号（与 native `account_of` 逐字段一致）。
///
/// `pub`：网页登录收尾（`login::callback`）产出的是同一形状的账号，
/// 两处必须共用这一份构造逻辑，否则「手动添加」与「网页登录」落库的键会分叉。
pub fn account_from(
    credentials: &KukuCredentials,
    source: &str,
    desktop: bool,
    explicit_name: Option<String>,
) -> Value {
    let cookie = credentials.cookie_header();
    let nickname = credentials.nickname.trim().to_string();
    let name = explicit_name
        .or_else(|| {
            if nickname.is_empty() {
                None
            } else {
                Some(nickname.clone())
            }
        })
        .unwrap_or_else(|| {
            let uid = credentials.uid.trim();
            if uid.is_empty() {
                "KukuAI 账号".to_string()
            } else {
                format!("库库 AI {uid}")
            }
        });
    let mut secret = serde_json::Map::new();
    // `accessToken` 存的是**整段 Cookie 头**（`credentials_of` 按它反解三件套）
    secret.insert("accessToken".to_string(), Value::String(cookie));
    secret.insert("uid".to_string(), Value::String(credentials.uid.clone()));
    secret.insert("loginName".to_string(), Value::String(nickname));
    secret.insert("source".to_string(), Value::String(source.to_string()));
    secret.insert(
        "tokenTail".to_string(),
        Value::String(credentials.token_tail()),
    );
    secret.insert("name".to_string(), Value::String(name));
    let secret = Value::Object(secret);
    json!({
        "secret": secret,
        "public": account_view(&secret),
        "identity": identity_of(&secret),
        "desktop": desktop,
    })
}

/// `account.normalize`：四条来源路径的入口。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let (credentials, source_label, desktop) = match kind {
        "manual" => {
            let payload = &source["payload"];
            let payload = if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            };
            (credentials_from_payload(&payload)?, "manual", false)
        }
        "desktop" => (read_desktop()?, "desktop", true),
        "file_base64" => (read_cookie_file()?, "file", false),
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("");
            let payload: Value = serde_json::from_str(content).map_err(|_| {
                Error::http(
                    400,
                    "KukuAI 凭证文件不是合法 JSON，请选择 Cookies 数据库或单账号 JSON 文件",
                )
            })?;
            // 单账号快照形态（`{"accessToken": "<Cookie 头>"}`）取 accessToken 的值；
            // 其余形态把整份对象交给统一解析（兼容 `{BDUSS, STOKEN}` 与嵌套）。
            let credential_payload = payload
                .get("accessToken")
                .cloned()
                .unwrap_or_else(|| payload.clone());
            (credentials_from_payload(&credential_payload)?, "file", false)
        }
        other => {
            return Err(Error::http(
                400,
                format!("KukuAI 不认识的添加方式「{other}」：请粘贴 Cookie、导入本机客户端登录态或选择 Cookies 数据库文件"),
            ))
        }
    };

    // 真实校验：换发业务会话令牌 + userreport 换三件套 + uk（与 native 同一口径 ——
    // 添加时就要「现在真的能用」）。失败即拒绝，不落空记录。
    let verified = enrich(&credentials, true)?;
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| super::errors::truncate_chars(value, MAX_NAME_LENGTH));
    Ok(account_from(&verified, source_label, desktop, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(cookie: &str) -> KukuCredentials {
        let (bduss, stoken, extras) = parse_cookie_parts(cookie);
        KukuCredentials { bduss, stoken, extras, uid: String::new(), nickname: String::new() }
    }

    #[test]
    fn cookie_header_always_appends_gfprotpl_once() {
        let value = credentials("BDUSS=abc12345; STOKEN=st; BAIDUID=bai; gfprotpl=wrong");
        let header = value.cookie_header();
        assert!(header.starts_with("BDUSS=abc12345; STOKEN=st;"));
        assert!(header.ends_with("gfprotpl=genflowpro"));
        assert_eq!(1, header.matches("gfprotpl=").count());
        assert!(!header.contains("gfprotpl=wrong"));
        assert!(header.contains("BAIDUID=bai"));
    }

    #[test]
    fn parse_accepts_header_array_and_object_forms() {
        // 字符串（Cookie 头）
        let from_text = credentials_from_payload(&json!("BDUSS=0123456789abcdef; STOKEN=x"))
            .unwrap_or_default();
        assert_eq!("0123456789abcdef", from_text.bduss);
        assert_eq!("x", from_text.stoken);

        // 数组（Cookie 编辑器导出）
        let from_array = credentials_from_payload(&json!([
            { "name": "BDUSS", "value": "0123456789abcdef" },
            { "name": "PTOKEN", "value": "pt" }
        ]))
        .unwrap_or_default();
        assert_eq!("0123456789abcdef", from_array.bduss);
        assert_eq!(Some("pt".to_string()), ptoken_of(&from_array.extras));

        // 对象（平铺 / 嵌套 / cookie 字段）
        let plain = credentials_from_payload(&json!({ "BDUSS": "0123456789abcdef", "STOKEN": "s" }))
            .unwrap_or_default();
        assert_eq!("s", plain.stoken);
        let nested = credentials_from_payload(&json!({ "auth": { "BDUSS": "0123456789abcdef" } }))
            .unwrap_or_default();
        assert_eq!("0123456789abcdef", nested.bduss);
        let cookie_field = credentials_from_payload(&json!({ "cookie": "BDUSS=0123456789abcdef" }))
            .unwrap_or_default();
        assert_eq!("0123456789abcdef", cookie_field.bduss);
    }

    #[test]
    fn short_bduss_is_rejected() {
        assert!(credentials_from_payload(&json!("BDUSS=short")).is_err());
        assert!(credentials_from_payload(&json!({})).is_err());
        assert!(credentials_from_payload(&json!(12)).is_err());
    }

    #[test]
    fn host_cookie_rows_prefer_primary_names_but_accept_shadows() {
        let primary = cookies_to_credentials(&json!({ "cookies": [
            { "name": "BDUSS_BFESS", "value": "shadow-bduss-123456" },
            { "name": "BDUSS", "value": "primary-bduss-123456" },
            { "name": "STOKEN_BFESS", "value": "shadow-stoken" }
        ] }))
        .unwrap_or_default();
        assert_eq!("primary-bduss-123456", primary.bduss);
        assert_eq!("shadow-stoken", primary.stoken);

        let shadow_only = cookies_to_credentials(&json!({ "cookies": [
            { "name": "BDUSS_BFESS", "value": "shadow-bduss-123456" }
        ] }))
        .unwrap_or_default();
        assert_eq!("shadow-bduss-123456", shadow_only.bduss);

        assert!(cookies_to_credentials(&json!({ "cookies": [] })).is_err());
        assert!(cookies_to_credentials(&json!({})).is_err());
    }

    #[test]
    fn identity_and_view_follow_native_shape() {
        let secret = json!({
            "accessToken": "BDUSS=0123456789abcdef; STOKEN=s",
            "uid": "42", "tokenTail": "89abcdef", "name": "库库 AI 42"
        });
        assert_eq!("kuku-42", identity_of(&secret));
        let view = account_view(&secret);
        assert_eq!("库库 AI 42", view["name"].as_str().unwrap_or_default());
        assert_eq!("42", view["uid"].as_str().unwrap_or_default());
        assert_eq!(true, view["hasSession"].as_bool().unwrap_or(false));
        assert_eq!(false, view["canRefresh"].as_bool().unwrap_or(true));

        // 没有 uid 时退回 Cookie 尾；两者都没有给空串（网关据此按内容去重）
        assert_eq!("kuku-89abcdef", identity_of(&json!({ "tokenTail": "89abcdef" })));
        assert_eq!("", identity_of(&json!({})));
    }

    /// 公开视图的两条硬限制（网关 `public_view::safe_scalar` / `check`）：
    /// `tokenTail` 最多 6 字符，且公开视图里不能出现 secret 的受保护片段。
    #[test]
    fn public_view_respects_gateway_limits() {
        let value = credentials("BDUSS=0123456789abcdef; STOKEN=s");
        // 尾段 6 位（native 的 8 位会被安全门整包拒收）
        assert_eq!(6, value.token_tail().chars().count());
        // 公开视图不携带尾段（空串既满足 ≤6，也不含任何 secret 片段）
        let view = account_view(&json!({
            "accessToken": value.cookie_header(),
            "uid": "42",
            "tokenTail": value.token_tail(),
            "name": "库库 AI 42"
        }));
        assert_eq!("", view["tokenTail"].as_str().unwrap_or("x"));

        // 落库的 secret 里尾段也必须 ≤6：8 位会被 `collect` 当成受保护字符串，
        // 之后任何公开视图里的同值都会被判成「包含受保护内容」。
        let account = account_from(&value, "manual", false, None);
        let tail = account["secret"]["tokenTail"].as_str().unwrap_or("");
        assert!(tail.chars().count() <= 6, "尾段过长：{tail}");
        // 整段 Cookie 在 secret 里（受保护内容只允许出现在 secret 里）
        assert!(account["secret"]["accessToken"]
            .as_str()
            .unwrap_or("")
            .contains("BDUSS="));
    }
}
