//! 人机验证令牌池（native `zcode/captcha.rs` 的移植）。
//!
//! ── 这个池子服务什么 ────────────────────────────────────────
//! 套餐池（Start Plan）的**推理请求**有时会被上游要求带一个
//! `X-Aliyun-Captcha-Verify-Param`（阿里云无痕验证的求解结果）。令牌由**界面**
//! （WebView 里跑官方 SDK）铸造、推进池子；插件只负责「按需取一个」并在
//! 3007 之后重新要求令牌。
//!
//! ── 为什么池子在 session 里而不是进程内静态 ──────────────────
//! native 用一个进程内 `Mutex<Pool>`。Wasm 插件跑在宿主的长驻实例里，静态
//! 变量确实能跨调用存活 —— 但它是**每个实例一份**，而宿主可能为不同 provider
//! 起多个实例、也可能重建实例。`session.put/get`（`sessions.v1`）由宿主统一
//! 保管，语义上就是「这个插件进程的临时状态」，并且带 TTL（我们用它兜住
//! native 的 2 分钟令牌寿命）。**这是与 native 的唯一实现差异**，行为等价：
//! 取不到池子 = 空池。
//!
//! ── 令牌寿命 ────────────────────────────────────────────────
//! native `TOKEN_TTL_MS = 120_000`：阿里云的无痕验证结果两分钟内有效。过期的
//! 令牌发出去只会换来 3007（「验证码校验未通过」），因此取用时就地丢弃。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use super::common::now_ms;

/// 池子的 session 键（同一插件进程内唯一；国内版自己的命名空间）。
const POOL_KEY: &str = "zcode:captcha_pool";

/// 令牌寿命（毫秒）。
pub const TOKEN_TTL_MS: i64 = 120_000;

/// 池子上限（native `POOL_MAX`）：界面连续推几千个令牌没有意义，
/// 而且 session 值有 64 KB 上限。
const POOL_MAX: usize = 500;

/// 池子写入的 session TTL：比令牌寿命长一截，保证「推进来就能取到」。
const SESSION_TTL_MS: i64 = TOKEN_TTL_MS * 3;

/// 风控配置的同步间隔（native `config_sync::SYNC_INTERVAL_MS` = 5 分钟）。
///
/// ── 为什么必须有这个间隔 ────────────────────────────────────
/// 套餐池的**每一次**推理请求都会经过 `sync_captcha_config`（那是 native
/// `ensure_captcha_config` 的位置）。不节流的话，每条推理请求都会多打一次
/// `/api/v1/client/configs` —— 一次便宜的 GET，但它把每条请求的延迟翻了一倍，
/// 而上游对这台网关的请求很敏感（余额那条通道的 429 就是证据）。native 用
/// 5 分钟的时间窗挡住这件事，这里照抄。
pub const SYNC_INTERVAL_MS: i64 = 5 * 60_000;

/// 读池子（不存在时给一个空池的形状）。
fn load() -> Value {
    let value = sdk::session_get(POOL_KEY).unwrap_or(Value::Null);
    if !value.is_object() {
        return json!({ "tokens": [], "required": false, "lastPush": 0 });
    }
    value
}

/// 写回池子（失败不报错：池子只是加速器，写不进去等于这一次 push 丢了）。
fn save(pool: &Value) {
    let _ = sdk::session_put(POOL_KEY, pool.clone(), SESSION_TTL_MS);
}

/// 是否要求推理请求带验证码头。
///
/// 三态来源（与 native 同序）：
///   1. 上游风控配置说 `enabled` 且**没有** `skip_model_request` → 要求；
///   2. 上游回了 3007 → 立刻置为要求（`note_challenge_and_require_token`）；
///   3. 其余情况 → 不要求（缺配置不能当成「要求」，也不能当成「免验证」：
///      这里只回答「要不要带」，由 `take()` 决定有没有可带的）。
pub fn required() -> bool {
    load()
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// 按上游的风控配置更新「要不要令牌」。
pub fn apply_config(enabled: bool, skip_model_request: bool) {
    let mut pool = load();
    let required = enabled && !skip_model_request;
    pool["required"] = Value::Bool(required);
    save(&pool);
}

/// 上游回了 3007（验证码缺失 / 失效）→ 恢复要求令牌。
pub fn note_challenge_and_require_token() {
    let mut pool = load();
    pool["required"] = Value::Bool(true);
    save(&pool);
}

/// 推入一个令牌（界面铸造完成后调用）。返回池子里**有效**令牌的数量。
pub fn push(param: &str, region: &str) -> usize {
    let param = param.trim();
    if param.is_empty() {
        return ready();
    }
    let now = now_ms();
    let mut pool = load();
    let mut tokens: Vec<Value> = pool
        .get("tokens")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    // 顺手清掉过期的（时间戳缺失的按过期处理：来源不明）
                    item.get("at")
                        .and_then(Value::as_i64)
                        .is_some_and(|at| now.saturating_sub(at) < TOKEN_TTL_MS)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    tokens.push(json!({ "param": param, "region": region.trim(), "at": now }));
    // 超出上限时丢最早的（新令牌更可能有效）
    if tokens.len() > POOL_MAX {
        let drop_count = tokens.len() - POOL_MAX;
        tokens.drain(0..drop_count);
    }
    let count = tokens.len();
    pool["tokens"] = Value::Array(tokens);
    pool["lastPush"] = json!(now);
    save(&pool);
    count
}

/// 取一个令牌（**先进先出**：先推进来的先被用掉，与 native 同序）。
///
/// 没有可用令牌时返回 `None` —— 调用方据此如实报错（`plan` 里那句
/// 「令牌池为空」），而不是发一个空头（空头与缺失同效，都是 3001/3007）。
pub fn take() -> Option<(String, String)> {
    let now = now_ms();
    let mut pool = load();
    let tokens = pool
        .get("tokens")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut picked: Option<(String, String)> = None;
    let mut rest: Vec<Value> = Vec::new();
    for item in tokens {
        let fresh = item
            .get("at")
            .and_then(Value::as_i64)
            .is_some_and(|at| now.saturating_sub(at) < TOKEN_TTL_MS);
        if !fresh {
            continue;
        }
        let param = item
            .get("param")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        if param.is_empty() {
            continue;
        }
        if picked.is_none() {
            let region = item
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            picked = Some((param, region));
            continue;
        }
        rest.push(item);
    }
    if picked.is_some() {
        pool["tokens"] = Value::Array(rest);
        save(&pool);
    }
    picked
}

/// 池子里**有效**令牌的数量。
pub fn ready() -> usize {
    let now = now_ms();
    load()
        .get("tokens")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    item.get("at")
                        .and_then(Value::as_i64)
                        .is_some_and(|at| now.saturating_sub(at) < TOKEN_TTL_MS)
                })
                .count()
        })
        .unwrap_or(0)
}

/// 池子的状态快照（`admin.action` 的 `captcha.stats`）。
pub fn stats() -> Value {
    let pool = load();
    let last_sync = pool.get("lastSync").and_then(Value::as_i64).unwrap_or(0);
    json!({
        "required": pool.get("required").and_then(Value::as_bool).unwrap_or(false),
        "ready": ready(),
        "lastSyncAt": last_sync,
        "lastPushAt": pool.get("lastPush").and_then(Value::as_i64).unwrap_or(0),
        "ttlMs": TOKEN_TTL_MS,
    })
}

/// 记录一次风控配置同步的时刻（`config_sync` 的等价物；排障用）。
pub fn note_synced() {
    let mut pool = load();
    pool["lastSync"] = json!(now_ms());
    save(&pool);
}

/// 距上次同步是否已到间隔（没同步过 = 该同步）。
///
/// 间隔见 [`SYNC_INTERVAL_MS`]：这条判据是「每条推理请求都调一次配置接口」
/// 与「永远不知道要不要验证码」之间的那道闸。
pub fn sync_due() -> bool {
    let pool = load();
    let last = pool.get("lastSync").and_then(Value::as_i64).unwrap_or(0);
    last <= 0 || now_ms().saturating_sub(last) >= SYNC_INTERVAL_MS
}
