//! CatPaw 的 Wasm 插件实现。
//!
//! 迁移来源：`crates/providers/src/providers/catpaw/`（native）。
//!
//! ── 当前阶段 ────────────────────────────────────────────────
//! 骨架：只申报 metadata，其余方法返回 `unsupported`。业务模块补齐后，
//! 把 `handle` 里的分支从 `_` 挪出来。
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
//!
//! ── 子模块清单（一眼看清谁管什么）─────────────────────────
//! ```text
//!   account        凭证形态 / 账号面 / 导入归一化 / token 三方法
//!   upstream       出站薄封装（base url / 请求头 / round / event / stop / turn）
//!   conversation   轮次状态机（prepare → 判定 → round → running → turn → 收尾）
//!   decision       三条轮次判定规则（工具续接 / 长会话增量 / 全新会话）
//!   turn           turn 的 SSE 消费、翻译与收尾（两种错误边界）
//!   openai         上游 SSE → OpenAI chunk 翻译 + usage 口径修正
//!   sse            SSE 分帧（带 EOF 残帧收尾）
//!   messages       入站消息归一化（角色分派 / 相邻合并 / 工具配对 / 指令抽离）
//!   blocks         内容块与工具字段的归一化（消息流水线的下半层）
//!   fingerprint    归一化消息的 SHA-256 指纹链与增量定位
//!   tools          tools / tool_choice → 上游 toolConfigs
//!   models         modelType / effort / context 映射与解析
//!   catalog        模型目录（远程拉取 + 静态表回落）
//!   registry       会话记录（x-session-id → conversationId / 指纹链 / 工具索引）
//!   usage          余额 / 积分查询
//!   login          登录（网页登录未接通，如实报错）
//!   errors         协议错误、分类与错误策略
//!   ids / codec    随机标识与编码
//!   logging        日志占位与短标识
//! ```
//!
//! ── 专用宿主通道 `http.catpaw-turn.v1`：本包**没有申报** ─────────
//! 网关为 CatPaw 准备了一整套宿主代管轮次（`plugin_host/wasm/catpaw_turn/`：
//! `catpaw.turn.prepare/start/read/settle/close`，宿主自己发 round/running/turn、
//! 自己解析 SSE 并核对工具证据与结算）。申报它意味着插件必须完整按那套轮次
//! 协议交出「约束 + 消息数」并消费宿主的 base64 分片、逐字段对上宿主的结算
//! 证据 —— 那是另一项独立工程。本包选择**普通通道**（自己 `http::open` 上游 +
//! `stream_head` / `stream_bytes` 回传），因此 `wasm.json` 里没有
//! `http.catpaw-turn.v1`，`conversation` 也不会走宿主通道。
//!
//! ── 唯一的 `unwrap_or` 用法说明 ────────────────────────────
//! `metadata()` 里读 `include_str!` 的编译期常量：解析失败只可能是有人改坏了
//! 那个文件，返回 `Null` 让界面缺元数据，而不是在启动路径上 panic
//! （`unwrap` 在这里等于「整包加载失败」）。

mod account;
mod blocks;
mod catalog;
mod codec;
mod conversation;
mod decision;
mod errors;
mod fingerprint;
mod ids;
mod logging;
mod login;
mod messages;
mod models;
mod openai;
mod registry;
mod sse;
mod tools;
mod turn;
mod upstream;
mod usage;

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// CatPaw 提供商 id（注册表与 `pack.json` 用同一条）。
pub const PROVIDER_ID: &str = "catpaw";

/// 入站参数错误的统一错误码（`errors::policy` 据此停止无效换号）。
pub const INVALID_REQUEST_CODE: &str = "catpaw_invalid_request";

/// 当前 Unix 时间（秒），进 OpenAI 帧的 `created` 字段。
pub fn now_seconds() -> i64 {
    sdk::now() / 1000
}

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

        // ── 账号 ────────────────────────────────────────────
        "account.normalize" => account::normalize(&params),
        "account.view" => Ok(account::account_view(&params["secret"])),
        "account.identity" => Ok(json!(account::identity_of(&params["secret"]))),

        // ── 令牌（本家没有刷新机制，见 `account.rs` 模块头）─────
        "token.ensure" => Ok(json!(account::ensure()?)),
        "token.refresh" => Ok(json!(account::refresh()?)),
        "token.expiring" => Ok(json!(account::expiring(&params["secret"]))),

        // ── 目录 / 额度 ─────────────────────────────────────
        "models.list" => Ok(catalog::list()),
        "models.refresh" => catalog::refresh(params["force"].as_bool().unwrap_or(false))
            .map_err(|error| error.to_error()),
        "usage.query" => usage::query(),

        // ── 对话（只有这一条路径，`chat` 是死路径）──────────────
        "conversation" => {
            conversation::run(&params)?;
            Ok(Value::Null)
        }

        // ── 错误分类 ────────────────────────────────────────
        "classify" => Ok(errors::classify(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),
        "is_error_response" => Ok(json!(errors::is_error_response(
            params["status"].as_u64().unwrap_or(502) as u16,
        ))),
        "error.policy" => Ok(errors::policy(
            params["status"].as_u64().unwrap_or(502) as u16,
            &params["body"],
        )),

        // ── 登录（网页登录未接通，见 `login.rs` 模块头）─────────
        "login.start" => login::start(&params),
        "login.poll" => login::poll(&params),
        "login.cancel" => login::cancel(&params),

        // 平台问「登录方式」时回**动态契约**（见 `login::login_methods`）。
        // 注意别改回 `metadata()["login_methods"]`：那是 `{kind, button, hint}` 的
        // 元数据形状，网关反序列化 `LoginMethodsMetadata` 会失败 → 502，添加账号
        // 面板整片打不开（网关不会回退旧入口）。
        "admin.action" if params["action"] == "auth.methods" => Ok(login::login_methods(
            params["payload"]["locale"]
                .as_str()
                .or_else(|| params["locale"].as_str())
                .unwrap_or("zh-CN"),
        )),
        // 本家的额度来源只有「积分」一个数，已在 `usage.query` 的 `wallets` 里给全
        "admin.action" if params["action"] == "quota.sources" => Ok(json!([])),

        // ── 平台通用钩子 ────────────────────────────────────
        // 本家没有跨家重试建议：轮次内的自愈在 `conversation.rs` 内部完成，
        // 账号级由编排层按 `classify` 决定。
        "retry_advice" => Ok(Value::Null),
        // 上游没有 429 轮换语义（见 `conversation.rs` 模块头），没有按模型的冷却清单
        "cooldown_models" => Ok(json!({ "models": [] })),
        // 本家是**唯一需要归并档位**的一家（见 `models.rs` 的 `effort_for_level`）。
        "reasoning_patch" => {
            let level = params["level"].as_str().unwrap_or("");
            let body = &params["body"];
            // 客户端已指定档位就让位。`Err` 也算「指定过」（这一条容易写反）：
            // 客户端传了 medium 这类本家不认的值时，`resolve_effort` 报错，随后
            // prepare 会给出那条 400；此时注入绑定档位等于把用户传错的参数悄悄
            // 换掉 —— 请求变成成功，而他永远不知道自己传的值是无效的。
            let declared = match models::resolve_effort(body) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => true,
            };
            if declared {
                Ok(json!({
                    "action": "skip",
                    "reason": "客户端请求体里已指定思考档位，绑定不覆盖",
                }))
            } else {
                match models::effort_for_level(level) {
                    Some(effort) => Ok(json!({
                        "action": "set",
                        "field": "reasoning_effort",
                        "value": effort,
                    })),
                    None => Ok(json!({
                        "action": "skip",
                        "reason": "该等级不在本家接受的档位内（仅 low / high / max，通用 6 档已归并）",
                    })),
                }
            }
        }

        _ => Err(Error::unsupported()),
    }
}
