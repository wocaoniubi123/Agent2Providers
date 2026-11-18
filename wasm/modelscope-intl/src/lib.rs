//! ModelScope 国际版 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/modelscope/`（native）。
//!
//! ── 模块分工（一眼看清谁管什么）──────────────────────────────
//! ```text
//!   upstream      国际站的两处域名常量 / 请求头 / 网页站与推理域的一次 GET / 信封判定
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
//! `Region` 拆法在这里行不通：本包只有 `modelscope-intl`（国际站），国内站
//! `modelscope` 由另一个包负责，两边的域名、账号前缀、站点完全分开。
//!
//! 本包取的是 native `Region::Intl` 那一列：推理域 `api-inference.modelscope.ai`、
//! 网页站 `www.modelscope.ai`、账号 id 前缀 `modelscope-intl-`、展示名「国际版」。
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
            format!(
                "ModelScope {}不认识管理动作「{other}」（可用：auth.methods / quota.sources）",
                upstream::LABEL
            ),
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
/// 数据源是 `metadata.json` 的 `login_methods`（文案不在 Rust 里抄第二遍，
/// 抄了就会漂）；本家只有 `kind: "token"` 一条，映射成一个 0 号 `api`：
///   - `prompts[].key` 用 `token` —— `account::token_from_payload` 认
///     `accessToken` / `apiKey` / `token` / `session`，面板提交的 `inputs` 会原样
///     落进 `source.payload.inputs`（`account::normalize` 已先解一层 `inputs`），
///     键名对不上就会报「缺少令牌」。
///
/// `kind: "desktop"` 不申报：它要求 `wasm.json` 的 `requires` 含
/// `desktop.credentials.v1`，而 wasm 沙箱里也读不到桌面端登录态。真遇到这一类
/// 条目直接跳过 —— 申报一个点了就失败的入口比不申报更糟。
fn login_methods() -> Value {
    let metadata: Value = serde_json::from_str(METADATA).unwrap_or(Value::Null);
    let mut methods: Vec<Value> = Vec::new();
    if let Some(entries) = metadata.get("login_methods").and_then(Value::as_array) {
        for entry in entries {
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
            let method = match kind {
                "token" => token_method(entry, methods.len() as u64),
                // 本家没有 `browser` / `desktop` / `sms` 类登录方式（`web_login: false`）：
                // 遇到就跳过，不产出半截契约
                _ => continue,
            };
            methods.push(method);
        }
    }
    if methods.is_empty() {
        // `metadata.json` 是编译期内嵌的，正常不会走到这里；真出意外时给一条
        // 静态的粘贴入口，好过让「添加账号」面板整个空白。
        methods.push(token_method(&Value::Null, 0));
    }
    json!({ "methods": methods })
}

/// `kind: "token"` → `type: "api"`（一条主凭据 + `extra_fields` 各一条可选输入）。
fn token_method(entry: &Value, index: u64) -> Value {
    let label = {
        let label = text_of(entry, "label");
        if label.is_empty() { "ms- 令牌".to_string() } else { label }
    };
    let placeholder = {
        let placeholder = text_of(entry, "placeholder");
        if placeholder.is_empty() {
            "粘贴 ms- 开头的令牌".to_string()
        } else {
            placeholder
        }
    };
    let mut prompts: Vec<Value> = vec![json!({
        "key": "token",
        "type": "text",
        "label": label.clone(),
        "placeholder": placeholder.clone(),
        "secret": true,
    })];
    if let Some(extras) = entry.get("extra_fields").and_then(Value::as_array) {
        for extra in extras {
            let key = text_of(extra, "key");
            // 键名会被网关逐字校验（`session.rs:325-333`），空键或非法键直接丢：
            // 一条不合法的字段会让整份清单 502
            if !valid_key(&key) {
                continue;
            }
            let extra_label = {
                let label = text_of(extra, "label");
                if label.is_empty() { key.clone() } else { label }
            };
            prompts.push(json!({
                "key": key,
                "type": "text",
                "label": extra_label,
                "placeholder": text_of(extra, "placeholder"),
                "optional": true,
            }));
        }
    }
    json!({
        "methodIndex": index,
        "type": "api",
        "label": label,
        "instructions": placeholder,
        "prompts": prompts,
    })
}

/// 取一个字符串字段（缺字段 / 类型不对给空串：这些文案在 `metadata.json` 里都可选）。
fn text_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 网关对 `prompts[].key` 的要求（`session.rs:325-333`）：字母开头，其余字母数字与 `_` `-`。
fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }
    let mut bytes = key.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auth.methods` 必须是**动态契约**（与 monkeycode 的同类测试同口径）：
    /// 每条有 `methodIndex` 与 `type`，`prompts[].type` 不缺，文案取自
    /// `metadata.json` 的 `login_methods`（不是 Rust 里另抄的一份）。
    #[test]
    fn auth_methods_follow_the_dynamic_contract() {
        let value = login_methods();
        let methods = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, methods.len());
        let first = methods.first().cloned().unwrap_or(Value::Null);
        assert_eq!(0, first["methodIndex"].as_u64().unwrap_or(9));
        assert_eq!("api", first["type"].as_str().unwrap_or(""));
        assert_eq!("ms- 令牌", first["label"].as_str().unwrap_or(""));
        let prompts = first["prompts"].as_array().cloned().unwrap_or_default();
        assert_eq!(1, prompts.len());
        let prompt = prompts.first().cloned().unwrap_or(Value::Null);
        assert_eq!("token", prompt["key"].as_str().unwrap_or(""));
        assert_eq!("text", prompt["type"].as_str().unwrap_or(""));
        assert_eq!(true, prompt["secret"].as_bool().unwrap_or(false));
    }

    /// 未知管理动作要如实报错（面向上游可见文案），不能静默回 null。
    #[test]
    fn an_unknown_admin_action_is_reported() {
        let error = admin_action(&json!({ "action": "nope" }))
            .err()
            .unwrap_or_else(|| Error::new("必须报错"));
        assert_eq!(Some(400), error.status);
        assert!(error.message.contains("auth.methods"));
    }
}
