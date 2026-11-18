//! ModelScope 国内版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/modelscope/`（native）。
//!
//! ── 模块分工（一眼看清谁管什么）──────────────────────────────
//! ```text
//!   upstream      两套域名的常量 / 请求头 / 网页站与推理域的一次 GET / 信封判定
//!   time          北京时间的「今天」与「次日零点」（签到与冷却的唯一日历）
//!   errors        两类账号级判据（魔粒耗尽 / 未验证邮箱）+ 四档分类
//!   account       凭证读取 / 账号面 / 导入归一化 / token.ensure
//!   probe         添加账号时的令牌探活（顺带当日签到）
//!   transactions  魔粒发放流水的翻页与判据
//!   usage         魔粒钱包 + 今日发放 + 今日已用（usage.query）
//!   checkin       读登录信息触发发放 + 流水确认（checkin.claim）
//!   models        目录拉取 / 10 分钟缓存 / 刷新结果
//!   chat          conversation：出站、首包门、SSE 中转
//! ```
//!
//! ── 这个包只声明一个 provider ────────────────────────────────
//! 网关 `plugin_host/packages/provenance.rs` 的 `wasm_provider()` 要求
//! `providers.len() == 1`，所以 native 那个「一份实现、两个实例」的
//! `Region` 拆法在这里行不通：本包只有 `modelscope`（国内站），国际站
//! `modelscope-intl` 由另一个包负责，两边的域名、账号前缀、站点完全分开。
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
//! `ensure_token()` → `token.ensure`；`classify()` → `classify`；
//! `models()` → `models.list`；`refresh_models()` → `models.refresh`；
//! `usage()` → `usage.query`；`checkin()` → `checkin.claim`；
//! `normalize_account()` → `account.normalize`。

mod account;
mod chat;
mod checkin;
mod errors;
mod models;
mod probe;
mod time;
mod transactions;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);

/// 与 native 侧 `meta()` 逐字段一致（已按装包期硬校验修正过能力位）。
const METADATA: &str = include_str!("metadata.json");

fn metadata() -> Value {
    serde_json::from_str(METADATA).unwrap_or(Value::Null)
}

fn handle(method: &str, params: Value) -> Result<Value> {
    match method {
        "init" => Ok(json!([metadata()])),
        "ping" => Ok(json!(true)),
        "provider.info" => Ok(metadata()),

        // ── 账号面 ──────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity(&params["secret"]))),

        // ── 凭据 ────────────────────────────────────────────
        // 本家的 `ms-` 令牌长期有效、上游没有续期接口：`token.refresh` 如实报错，
        // `token.expiring` 恒 false（判不出到期时刻的东西不该被批量维护链反复刷）。
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(false)),

        // ── 目录 / 额度 / 签到 ──────────────────────────────
        "models.list" => models::list(),
        "models.refresh" => models::refresh(params["force"].as_bool().unwrap_or(false)),
        "usage.query" => usage::query(),
        "checkin.claim" => checkin::claim(),

        // ── 对话 ────────────────────────────────────────────
        // 只有 `conversation` 会真的发上游请求（它自己 `http::open` + `stream_*`）。
        "conversation" => {
            chat::forward(&params)?;
            Ok(Value::Null)
        }
        // 死路径：网关 `rpc.rs` 的 `build_chat_request_async` 对 wasm 包恒回 501，
        // 这里如实报不支持，而不是伪装成「已构造好一个计划」。
        "chat" => Err(Error::unsupported()),

        // ── 错误分类与策略 ──────────────────────────────────
        "classify" => Ok(errors::class_of(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        // 本家没有「HTTP 200 但正文是失败话术」的形态：4xx/5xx 之外的响应都算成功
        // （与 native 未覆写该方法的口径一致）。
        "is_error_response" => Ok(json!(params["status"].as_u64().unwrap_or(0) >= 400)),
        // 不新增处置约束：停手与否由编排层按 `classify` 的结论决定
        "error.policy" => Ok(Value::Null),
        // 没有专属退避建议，交给网关的通用规则
        "retry_advice" => Ok(Value::Null),
        "retry.decision" => Ok(json!({ "action": "default" })),
        // 限额按账号算、不按模型分组，没有连带冷却的模型
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 上游 `/v1/models` 不给能力位，按 id 猜思考档位会在两个方向上一起猜错；
        // 思考设置原样透传，由用户显式绑定的模型规则决定
        "reasoning_patch" => Ok(json!({ "action": "skip", "reason": "ModelScope 不提供思考能力位，按上游原始请求透传" })),
        // Wasm 图片通道没有迁：本仓库里找不到 `images.generate` / `images.edit`
        // 的请求与回包契约（native 侧走的是 `ImagePlan::ModelscopeAsync`，出图
        // 要轮询 `/v1/tasks/{id}` 再下载产物，而产物域名无法在 `origins` 硬白名单
        // 里预先声明）。只申报真的实现了的能力，两个位都报 false。
        "images.capabilities" => Ok(json!({ "generation": false, "editing": false })),

        // ── 管理动作 ────────────────────────────────────────
        "admin.action" => admin_action(&params),

        _ => Err(Error::unsupported()),
    }
}

/// 管理面：登录方式与额度来源。
///
/// 额度来源已经随 `usage.query` 的 `quotaSources` 一起给出（wasm ABI 没有
/// `quota_sources` 这条方法），这里回空表即可。
fn admin_action(params: &Value) -> Result<Value> {
    let action = params["action"].as_str().unwrap_or("");
    match action {
        "quota.sources" => Ok(json!([])),
        // 登录方式走**动态契约**（见 `login_methods`）：回 metadata 那份静态
        // 形态（`kind:"token"`）会让网关反序列化失败，面板直接打不开。
        "auth.methods" => Ok(login_methods()),
        other => Err(Error::http(
            400,
            format!("ModelScope 不认识管理动作「{other}」（可用：auth.methods / quota.sources）"),
        )),
    }
}

/// `admin.action = auth.methods`：登录方式清单（**动态契约**）。
///
/// ── 为什么不能用 `metadata.json` 的形状 ──────────────────────────
/// `metadata.json` 的 `login_methods` 是 native 的静态形态
/// （`{kind:"token", label, placeholder, extra_fields}`）。wasm 包的登录方式走
/// 动态契约：网关 `api/session.rs::read_login_methods` 把这条 `admin.action` 的
/// 结果按 `LoginMethodsMetadata` 反序列化，每条必须有 `methodIndex` 与 `type`
/// （`oauth` / `api` / `sms` / `desktop`）、且 `prompts[].type` 不能缺。回静态形态
/// 直接 502「插件返回的登录方式元数据无法解析」，添加账号面板整个打不开 —— 而且
/// 网关明确不回退旧入口（`session.rs` 的 `login_methods` 注释）。
///
/// 本家只有粘贴令牌一条路（`metadata.json` 的 `login_methods` 也只有一条），
/// 因此只有一个 0 号 `api`：
///   - `prompts[].key` 用 `token` —— `account::token_from_payload` 认
///     `accessToken` / `apiKey` / `token` / `session`，面板提交的 `inputs` 会原样
///     落进 `source.payload.inputs`，键名对不上就会报「缺少令牌」。
fn login_methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "api",
            "label": "ms- 令牌",
            "prompts": [
                {
                    "key": "token",
                    "type": "text",
                    "label": "ms- 令牌",
                    "placeholder": "粘贴 ms- 开头的令牌",
                    "secret": true,
                }
            ],
            "instructions": "粘贴 ms- 开头的令牌",
        }
    ] })
}
