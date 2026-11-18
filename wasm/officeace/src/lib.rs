//! OfficeAce 果办 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/officeace/`（native）。
//!
//! ── 模块分工（一眼看清谁管什么）─────────────────────────────
//! ```text
//!   util           base64 / hex / 随机源 / URL 编码 / RFC3339 / 北京时间 / FNV-1a
//!   p256           P-256 域算术 + ECDSA/ES256 签名（DPoP 用）
//!   signer         SDK-HMAC-SHA256 与 V11-HMAC-SHA256（含自写 HMAC）
//!   credentials    两层凭据、账号面、身份派生、手工导入归一化
//!   dpop           DPoP 密钥对 / JWK / proof
//!   upstream       控制面请求出口（签名 + 错误归一 + 脱敏）
//!   subscription   订阅快照 / 奖励活动 / 倍率 / 额度归一
//!   control        续期（写回账号）+ 云端调用 + project 补查 + 台账读写
//!   oauth          登录九步 + 续期换证
//!   login          login.start / poll / cancel
//!   models         目录拉取、官方白名单收窄、倍率合并、会话缓存
//!   usage          余额 / 额度来源
//!   checkin        每日签到（含 `dailyCheckin` 台账）
//!   onboarding     奖励账本（`claim.status` / `claim`，含 `officeaceBonus` 台账）
//!   activation     零元体验套餐开通（trial / 协议 / 开通台账）
//!   chat           出站构造 + `conversation` 首包门
//! ```
//!
//! ── 与 native 的差异（逐条对照，便于 parity 核对）──────────
//! ```text
//!   没迁： `probe.rs` 的逐模型可用性探测 —— 它要后台任务 + 「通知网关重读目录」，
//!          wasm 插件两样都没有（理由写在 `models` 的模块头）
//!   换法： 进程内静态状态 → 宿主会话/台账
//!          · 目录缓存、倍率读数、登录 flow → `session.*`（实例可能被换掉）
//!          · 签到 / 奖励 / 套餐开通三份台账 → `ledger.*`（宿主按账号作用域存）
//!   新增： `quota_sources` 在 wasm 侧是 `admin.action` 的 `quota.sources` 动作
//!   不变： 请求构造（推理预算 / 恒流式）、错误分类码表、官方白名单收窄、
//!          订阅与奖励的全部判定、两套签名（SDK/V11）、登录九步与续期
//! ```
//!
//! ── 四条装包期硬校验（不满足 = 整包加载失败）───────────────
//! 1. `capabilities.chat == true` → requires 必须有 `chat.stream.v1` 和 `accounts.cas.v1`
//! 2. `capabilities.model_refresh == true` → requires 必须有 `catalog.v1`
//! 3. `capabilities.web_login == true` → requires 必须有 `login.forms.v1`
//! 4. `capabilities.anonymous_default_session` / `env_credentials` 必须都是 false
//! 另有：`settings_schema.storage_provider`（若有）必须是本包自己的 provider id。
//! 生成脚本已按这五条配好，改 metadata 时别破坏。
//!
//! ── 对话只能走 `conversation` ───────────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回
//! 501，`forwards_response()` 对 wasm 恒为 true —— 所以 wasm 包的对话一律走
//! 会话式通道：插件自己 `http::open` 发请求，再用 `stream_head` /
//! `stream_bytes` 回传 SSE。`chat` 写了也不会被调用。
//!
//! ── 与 native 的对应关系 ────────────────────────────────────
//! `meta()` → `metadata()`；`build_chat()` → `conversation`；
//! `ensure_token()` → `token.ensure`；`refresh()` → `token.refresh`；
//! `expiring()` → `token.expiring`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `claim_status()` / `claim()` → `claim.status` / `claim`；
//! `normalize_account()` → `account.normalize`；
//! `admin_action()` → `admin.action`；`login.*` → `login.*`。

mod activation;
mod chat;
mod checkin;
mod control;
mod credentials;
mod dpop;
mod login;
mod models;
mod oauth;
mod onboarding;
mod p256;
mod signer;
mod subscription;
mod upstream;
mod usage;
mod util;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

/// 方法分发。
///
/// ── 为什么 `chat` 报 unsupported 而不是"顺手也实现一份" ────
/// 网关对 wasm 包的 `build_chat_request_async` 直接返回 501（「Wasm 对话必须使用
/// 标准流通道，不接受主程序代发计划」），所以那条分支**永远不会被调用**。留一个
/// 能返回计划的 `chat` 只会让读代码的人以为存在两条发送链。真正会跑的是
/// `conversation`（插件自己发请求 + `stream_*` 回传）。
fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号面 ──────────────────────────────────────────
        "account.normalize" => credentials::normalize(&params),
        "account.view" => Ok(credentials::account_view(&params["secret"])),
        "account.identity" => Ok(json!(credentials::identity_of(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // `token.ensure` 回空串：本家**没有可刷新的转发令牌**（网关 Basic 那对
        // 不过期），这条只是"这对凭据齐不齐"的存在性校验。不要把「恒回 401」写回来：
        // 编排层每次出站前都会问一次，那样每发一次请求就多一条噪声日志。
        "token.ensure" => {
            let (_, credential) = credentials::current()?;
            if credential.can_forward() {
                Ok(json!(""))
            } else {
                Err(Error::http(401, "OfficeAce 账号缺少网关凭据"))
            }
        }
        // 控制面续期：返回新的 access key（协议契约要一个非空串表成功）
        "token.refresh" => {
            let renewed = control::refresh(None)?;
            Ok(json!(renewed.access_key_id))
        }
        "token.expiring" => {
            let secret = params.get("secret").cloned().unwrap_or(Value::Null);
            Ok(json!(credentials::credentials_expiring(&secret)))
        }

        // ── 目录 ────────────────────────────────────────────
        "models.list" => Ok(models::list()),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),

        // ── 余额 / 签到 / 领取 ──────────────────────────────
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::checkin(),
        "claim.status" => onboarding::get_tasks(),
        "claim" => onboarding::claim_all(),

        // ── 对话 ────────────────────────────────────────────
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        "chat" => Err(Error::unsupported()),

        // ── 登录 ────────────────────────────────────────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),
        // 本家是**轮询型**登录（授权回调在云端终结，不回到本机），
        // 没有「用户把回调地址粘回来」这一档，如实报不支持。
        "login.callback" => Err(Error::http(
            400,
            "OfficeAce 的登录由网关自动轮询取回授权码，不需要回调地址",
        )),

        // ── 管理动作 ────────────────────────────────────────
        "admin.action" => admin_action(&params),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(chat::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(is_error_response(&params))),
        "error.policy" => Ok(error_policy(&params)),
        "retry_advice" => Ok(Value::Null),
        // 冷却标记在 native 里由 `store_mark_limited` 落账号库；插件侧交给编排层
        // 按 `classify` 的结论处理，所以这里没有按模型的冷却清单。
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 本家**自己从不注入** `thinking`（native 没有实现 `reasoning_patch`），
        // 所以平台想调思考档位时明确说"跳过"，而不是悄悄改一份给它会造成 400 的请求。
        "reasoning_patch" => Ok(json!({
            "action": "skip",
            "reason": "本家不接受 thinking 参数（glm-5.3 系列会回 400），请求体原样透传"
        })),
        "images.capabilities" => Ok(chat::images_capabilities()),

        _ => Err(Error::unsupported()),
    }
}

/// 管理动作。
///
/// ```text
///   subscription.preview → 只读检查（不发任何写请求）
///   subscription.ensure  → 用户明确同意后开通零元体验套餐（payload.confirmAgreements）
///   quota.sources        → 额度来源（面板那一栏）
///   auth.methods         → 登录方式清单
/// ```
fn admin_action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    match action {
        "subscription.preview" => activation::preview(),
        "subscription.ensure" => activation::ensure(
            params["payload"]["confirmAgreements"].as_bool() == Some(true),
        ),
        "quota.sources" => usage::sources(),
        // 登录方式走**动态契约**：网关 `api/session.rs::read_login_methods` 把这条
        // 结果按 `LoginMethodsMetadata` 反序列化，每条的 `type` 只能是
        // `oauth` / `api` / `sms` / `desktop`，`prompts[].type` 也是必需字段。
        // 回 `metadata.json` 的 native 静态形态（`type:"browser"`、prompt 只有
        // `label`）会直接 502「插件返回的登录方式元数据无法解析」，添加账号面板
        // 整个打不开 —— 网关不会回退旧入口。
        //
        // `prompts[].key` 必须与 `credentials::normalize` 读的字段名一致
        // （`baseUrl` / `modelAppKey` / `modelAppSecret`）：面板提交的 `inputs`
        // 会原样落进 `source.payload.inputs`。这条粘贴入口是免华为云账号的唯一
        // 添加路径，即使 `metadata.json` 的 `login_methods` 里没列它也必须保留。
        "auth.methods" => Ok(json!({ "methods": [
            { "methodIndex": 0, "type": "oauth", "label": "网页登录",
              "prompts": [], "browserMode": "external",
              "instructions": "完成华为云授权后，网关会自动轮询取回登录凭据" },
            { "methodIndex": 1, "type": "api", "label": "粘贴网关凭据", "prompts": [
                { "key": "baseUrl", "type": "text", "label": "API 基址（…/v2）",
                  "placeholder": "https://<网关主机>/v2" },
                { "key": "modelAppKey", "type": "text", "label": "modelAppKey",
                  "placeholder": "OfficeAce 客户端导出的模型网关凭据", "secret": true },
                { "key": "modelAppSecret", "type": "text", "label": "modelAppSecret",
                  "placeholder": "与 modelAppKey 成对出现", "secret": true }
              ],
              "instructions": "从 OfficeAce 客户端导出的模型网关凭据；只有这一对时额度/签到不可用" }
        ] })),
        other => Err(Error::http(
            400,
            format!(
                "OfficeAce 不认识管理动作「{other}」（可用：subscription.preview / subscription.ensure / quota.sources / auth.methods）"
            ),
        )),
    }
}

/// 这一帧/这个响应算不算错误。
///
/// 本家的失败**通常不在状态码上**：内容审核是 `HTTP 200 + finish_reason=
/// content_filter`，首包门（`chat::forward`）已经把它判掉；这里只回答「状态码层面
/// 是不是错误」，供编排层在聚合路径上复核一次。
fn is_error_response(params: &Value) -> bool {
    params["status"].as_u64().unwrap_or(0) >= 400
}

/// 是否**停手**（不再换账号）。
///
/// 只有「请求本身太大」才停：上游拒的是这份 body 的条数，换任何一个账号都会撞同一
/// 堵墙，继续轮转只是把同一份体重发一遍。额度/限流不停手（那正是要换账号的场景），
/// 内容闸门也不停手（换一家可能答得出来）。
fn error_policy(params: &Value) -> Value {
    let status = params["status"].as_u64().unwrap_or(0) as u16;
    let body = &params["body"];
    let text = body.as_str().map(str::to_string).unwrap_or_else(|| body.to_string());
    let lowered = text.to_ascii_lowercase();
    let stop = status == 413
        || ["81113", "exceeds the maximum size", "payload too large", "requestentitytoolarge"]
            .iter()
            .any(|marker| lowered.contains(marker));
    json!({ "stop": stop })
}

