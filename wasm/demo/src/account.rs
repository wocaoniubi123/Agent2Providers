//! 账号面：凭证读取、条件回写、规范化、公开视图与身份。
//!
//! 迁移来源：`crates/providers/src/providers/demo/mod.rs` 的
//! `ensure_token` / `token_expiring` / `normalize_account` / `account_identity`。
//!
//! ── native 的「账号读写回调」在 wasm 里对应什么 ──────────────
//! native 用的是 `ctx.store_get(ID, account)` 与 `ctx.store_update(...)`。
//! wasm 沙箱没有 ctx，宿主换了两条通道：
//!   * 读：`sdk::account()` → 宿主 `account.get`，返回整条账号记录
//!     （`{id, identity, secret, public, ...}`，账号上下文由宿主按
//!     `params.account` 绑定，插件不需要自己按 id 查）；
//!   * 写：`sdk::host("account.update", {expect, secret, public})` ——
//!     `expect` 是**读到时的那份 secret**，宿主持有 CAS：只有当前值仍等于
//!     它时才写入。这就是 native `store_update` 的「比较再写」语义
//!     （`wasm/services.rs:246-274`）。
//!
//! ── 为什么回写要带 `public` ────────────────────────────────
//! 宿主把 `public` 一并落库并当场校验：公开视图里出现受保护内容会被拒
//! （`wasm/public_view.rs`：键名含 token / password / cookie / secret 的
//! 字段只允许布尔或时间戳，`tokenTail` 最多 6 个字符）。所以这里给的
//! `public` 必须与 `secret` 一致，且整条令牌只能留在 `secret` 里。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// 临期阈值：剩不到 5 分钟就刷新（native 的同一份判据）。
const REFRESH_WINDOW_MS: i64 = 5 * 60 * 1000;

/// 示例「刷新」把有效期往后推多久（native 的同一份取值）。
const EXTENDED_MS: i64 = 3600 * 1000;

/// 示例账号的默认有效期（native `normalize_account` 里写死的一天）。
const DEFAULT_TTL_MS: i64 = 24 * 3600 * 1000;

/// 读当前账号记录（宿主已按本次调用绑定账号）。
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 一条 secret 里的令牌（缺字段/不是字符串都当空）。
pub fn token_of(secret: &Value) -> String {
    secret
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// 身份判据：令牌为空 = 桌面型；否则用令牌哈希前缀。
///
/// native 的 `account_identity` 逐字相同 —— 规则是「同一账号必须恒定，
/// 不同账号必须不同」，所以这里用稳定哈希而不是随机 id。
pub fn identity(secret: &Value) -> String {
    let token = token_of(secret);
    if token.is_empty() {
        "demo-desktop".to_string()
    } else {
        format!("demo-{:x}", simple_hash(&token))
    }
}

/// 公开视图（给界面看的字段，宿主会做受保护内容校验）。
///
/// 名称取自 secret 的 `name`：wasm 侧的 `account.view` 只能拿到 `secret`
/// （`rpc.rs` 的 `ACCOUNT_VIEW` 只塞 `secret` 一个字段），而 native 的
/// `account_view` 背后有整条记录 —— 所以规范化时把名字也落进 secret，
/// 否则刷新界面后账号名会变回默认值。
pub fn view(secret: &Value) -> Value {
    let name = secret
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("示例账号")
        .to_string();
    json!({
        "name": name,
        "uid": identity(secret),
        // 宿主校验：`tokenTail` 最多 6 个字符（这里 4 个）。
        "tokenTail": tail_of(&token_of(secret)),
        "expiresAt": secret.get("expires_at").and_then(Value::as_i64).unwrap_or(0),
    })
}

/// `token.ensure`：给一个现在能用的令牌；临期时**条件回写**新有效期。
///
/// 与 native `ensure_token` 的三步一一对应：读账号 → 取令牌 → 临期回写。
/// 区别只有通道（`ctx.store_get` / `ctx.store_update` → `account.get` /
/// `account.update`）。
pub fn ensure() -> Result<String> {
    let current_record = record()?;
    let current = current_record
        .get("secret")
        .cloned()
        .unwrap_or(Value::Null);
    let token = token_of(&current);
    if token.is_empty() {
        return Err(Error::http(401, "账号里没有令牌，请重新登录"));
    }
    let expires_at = current.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    let now = sdk::now();
    if expires_at > 0 && expires_at - now < REFRESH_WINDOW_MS {
        let mut next = current.clone();
        if let Some(object) = next.as_object_mut() {
            object.insert("expires_at".to_string(), json!(now + EXTENDED_MS));
        }
        // 条件回写：`expect` 是读到时的那份 secret，宿主持有 CAS。
        let result = sdk::host(
            "account.update",
            json!({ "expect": current, "secret": next, "public": view(&next) }),
        )?;
        if result["updated"] != true {
            // 并发改写过（另一条请求先刷了）：按最新那份作答，绝不覆盖。
            let latest = record()?;
            return Ok(token_of(&latest.get("secret").cloned().unwrap_or(Value::Null)));
        }
    }
    Ok(token)
}

/// `token.expiring`：这个账号的凭证此刻算不算临期。
///
/// 判不出来就 `false`（native 的同一句：宁可漏刷，也不要凭猜测打上游）。
pub fn expiring(params: &Value) -> bool {
    let secret = params
        .get("secret")
        .filter(|secret| secret.is_object())
        .cloned()
        .or_else(|| record().ok().and_then(|record| record.get("secret").cloned()))
        .unwrap_or(Value::Null);
    let expires_at = secret.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    expires_at > 0 && expires_at - sdk::now() < REFRESH_WINDOW_MS
}

/// `normalize` 的四种来源（native `NormalizeSource` 的同一套分支）。
fn payload_of(source: &Value) -> Result<Value> {
    match source.get("kind").and_then(Value::as_str) {
        Some("manual") => {
            let payload = &source["payload"];
            // 表单可能把输入套一层 `inputs`（宿主两套前端都出现过）。
            if payload["inputs"].is_object() {
                Ok(payload["inputs"].clone())
            } else {
                Ok(payload.clone())
            }
        }
        Some("file_text") => {
            let content = source.get("content").and_then(Value::as_str).unwrap_or("");
            serde_json::from_str(content).map_err(|error| {
                Error::http(400, format!("凭证文件不是合法 JSON：{error}"))
            })
        }
        Some("file_base64") => Err(Error::http(
            400,
            "示例 provider 的二进制文件导入这一路没有实现（native 也是同一个答复）",
        )),
        Some("desktop") => Err(Error::http(
            400,
            "示例 provider 在 wasm 沙箱里读不到本机客户端登录态，请改用手填令牌或文本文件导入",
        )),
        _ => Err(Error::http(400, "示例 provider 不认识的账号来源")),
    }
}

/// `account.normalize`：把用户给的输入折成一条可落库的账号。
///
/// ── 与 native 的一处差别（必须知道）──────────────────────────
/// native 的 `Desktop` 分支返回 `desktop: true` 的账号（「实时读本机客户端」
/// 型）。wasm 沙箱没有文件系统，宿主也会**当场否掉**这种账号
/// （`wasm/host.rs:455`：未选择本机导入时回「本机账号只能由用户明确选择
/// 本机导入后创建」）。与其让用户看到一句主程序的通用否掉文案，这里在
/// `payload_of` 里提前说清楚是什么原因。
pub fn normalize(params: &Value) -> Result<Value> {
    let payload = payload_of(&params["source"])?;
    let token = payload
        .get("token")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if token.is_empty() {
        return Err(Error::http(400, "令牌为空"));
    }
    let fallback_name = payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("示例账号")
        .to_string();
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or(fallback_name);
    let expires_at = sdk::now() + DEFAULT_TTL_MS;
    let secret = json!({
        "token": token,
        "expires_at": expires_at,
        // `account.view` 只能拿到 secret，所以名字要跟着 secret 走。
        "name": name,
        "desktop": false,
    });
    Ok(json!({
        "secret": secret,
        "public": {
            "name": name,
            "uid": identity(&secret),
            "tokenTail": tail_of(&token),
            "expiresAt": expires_at,
        },
        "identity": identity(&secret),
        "desktop": false,
    }))
}

/// 一个稳定的简单哈希（**不是**密码学哈希，示例专用；native 的同一份 FNV）。
///
/// 为什么不用 `sha2`：这里只要「同输入同输出、不同输入大概率不同」，
/// 用密码学哈希会让示例看起来在暗示「账号 id 需要抗碰撞」—— 那件事由
/// 上游的稳定 uid 负责，不是示例要教的。
fn simple_hash(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// 令牌尾部四位（界面显示用；宿主校验上限是 6 个字符）。
pub(super) fn tail_of(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}
