# Agent2Providers Native → Wasm 迁移规格

> 本文件是 2026-11-19 那次「35 个 provider 全部迁成独立 wasm 包」的实测记录与规格。
>
> **分工**：README 讲怎么用，这里讲怎么迁、以及为什么这么迁 —— 每一条约束都是装包
> 或运行期实际踩过之后写下来的，并括注了网关侧的源码位置（`plugin_host/wasm/host.rs`、
> `manifest.rs`、`api/session.rs` 等）。重做一遍或新增 provider 时照它做，能少走一遍弯路。
>
> **标注约定**：✅[实锤] = 有实测或源码依据；🔍[推断] = 有依据但未实测；❓[未知] = 待核实。

## 0. 目标

把 `crates/providers/src/providers/<name>/` 里的 native 实现，迁成
`wasm/<name>/` 下的独立 Wasm 插件包。

一个 provider 一个包，包 id 固定 `agent2api-wasm-<name>`。

## 1. 包结构（逐目录对照模板 `wasm/atomcode/`）

```
wasm/<name>/
├── Cargo.toml          # package.name = agent2api-wasm-<name>
├── pack.json           # 插件清单
├── wasm.json           # 权限声明
├── assets/logo.png     # 可选；写了 icons 就必须有封面图
└── src/
    ├── lib.rs          # export_provider! + metadata() + handle()
    ├── account.rs      # 凭证读取/校验/规范化
    ├── upstream.rs     # base url / headers / get / post
    ├── chat.rs         # 转发 + SSE 中转
    ├── models.rs       # 模型目录
    ├── errors.rs       # 错误分类
    ├── login.rs        # 登录流程（无登录则省略）
    ├── usage.rs        # 余额查询（无则省略）
    └── plans.rs        # 签到/领取（无则省略）
```

### Cargo.toml

```toml
[package]
name = "agent2api-wasm-<name>"
version = "<与 pack.json 完全一致>"
edition = "2021"
license = "AGPL-3.0-only"

[lib]
crate-type = ["cdylib"]

[dependencies]
agent2api-wasm-sdk = { path = "../sdk" }
serde_json = "1"
# 按需追加：sha2 = "0.10"、chrono = { version = "0.4", default-features = false, features = ["std"] }
```

**不要**依赖 `agent2api-provider-protocol` / `agent2api-provider-sdk` / `reqwest` —— 那些是 native 侧的，wasm 目标编不了。

### pack.json

```json
{
  "id": "agent2api-wasm-<name>",
  "name": "<显示名> · Wasm",
  "description": "<一句话>",
  "version": "0.1.0",
  "protocol": 1,
  "providers": [
    { "id": "<name>", "label": "<显示名>", "order": <数字>, "default_enabled": true }
  ],
  "entry": { "wasm32-unknown-unknown": "<name>.wasm" },
  "homepage": "https://github.com/ProvidersPlugin/Agent2Providers"
}
```

要点：
- `id` 必须等于 `Cargo.toml` 的 `package.name`（`wasm-build.yml` 会校验）
- `version` 必须等于 `Cargo.toml` 的 `package.version`
- 一个目录出多个 provider id 的（zcode → zcode + zcode-intl 等），在 `providers` 里写多条，顺序与 native 的 `with_providers` / manifest 一致
- `icons` 字段可选；不写就不带图标

### wasm.json

```json
{
  "abi": 1,
  "verified": false,
  "requires": ["http.v1", "accounts.cas.v1", "settings.v1", "clock.v1", "state.v1"],
  "origins": ["https://实际用到的域名1", "https://域名2"],
  "memory_mib": 64,
  "concurrency": 8
}
```

**`origins` 是硬白名单**：漏一个域名，那家的网络请求运行期直接失败，编译不报错。逐条核对 native 代码里出现的所有 host。

按需从下列能力里选（`wasm/atomcode/wasm.json` 的完整清单）：
`http.v1` `accounts.cas.v1` `settings.v1` `sessions.v1` `clock.v1` `random.v1` `locks.v1` `catalog.v1` `chat.stream.v1` `login.forms.v1` `checkin.rolling.v1` `errors.v1` `accounts.identity.v1` `catalog.accounts.v1` `state.v1` `login.interaction.v1`

## 2. SDK API（`agent2api_wasm_sdk`）

### 入口

```rust
use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

sdk::export_provider!(handle);          // 导出 a2a_abi_version / a2a_alloc / a2a_call

fn metadata() -> Value { json!({ ... }) }
fn handle(method: &str, params: Value) -> Result<Value> { match method { ... } }
```

### 通用

| 函数 | 说明 |
|---|---|
| `sdk::host(method, params) -> Result<Value>` | 任意宿主调用 |
| `sdk::now() -> i64` | 毫秒时间戳 |
| `sdk::sleep(ms) -> Result<()>` | 睡眠 |
| `sdk::account() -> Result<Value>` | 当前账号（含 `secret`） |
| `sdk::account_lock::AccountLock::acquire()` | 账号锁（Drop 自动释放） |
| `sdk::session_get(id)` / `session_put(id, value, ttl_ms)` / `session_remove(id)` | 会话状态（替代 native 的 ctx 内存状态） |
| `sdk::stream_head(status)` / `stream_bytes(&[u8])` / `stream_event(&Value)` | 流式回传 |
| `sdk::settings::get(key) -> Result<Value>` | 读用户设置覆盖值 |

### HTTP（`sdk::http`）

```rust
let mut response = http::open("POST", url, json!({...headers...}), Some(&body))?;
// status: u16, headers: Value
let value = response.json()?;                 // 2xx 才成功，否则 Err(Error::http(status, ..))
let bytes = response.bytes(limit)?;
while let Some(chunk) = response.read()? { ... }   // 流式读
http::open_raw(method, url, headers, Some(&bytes))?;
http::multipart(method, url, headers, fields, files)?;
```

### 错误

`Error { message, code, status, upstream_code, reset_at, credential_scope }`
- `Error::new(msg)` / `Error::coded(msg, code)` / `Error::http(status, msg)` /
  `Error::unsupported()` / `.with_code(..)` / `.with_reset(..)`

### SSE

`sdk::sse::SseDecoder::default().push(&bytes)? -> impl Iterator<Item = String>`

## 3. 方法映射（native trait → wasm method）

方法名常量见 `crates/provider-protocol/src/methods.rs` 的 `gateway` 模块。

| native | wasm method | params 关键字段 |
|---|---|---|
| `meta()` | `init` / `provider.info` | 返回 `metadata()`；`init` 要返回 `json!([metadata()])` |
| `provider_id()` | — | 由 `metadata().id` 承担 |
| `build_chat()` | `chat` | `params.body` / `params.headers` / `params.account` / `params.wire_model` |
| （会话式） | `conversation` | 同上，插件自己发请求 + `stream_*` 回传 |
| `classify(status, body)` | `classify` | `params.status` / `params.body` |
| 内容拦截判定 | `is_error_response` | `params.status` |
| `error_policy` | `error.policy` | `params.body` |
| `retry_advice` | `retry_advice` | — |
| `retry.decision` | `retry.decision` | — |
| `cooldown_models` | `cooldown_models` | — |
| `reasoning_patch` | `reasoning_patch` | — |
| `ensure_token()` | `token.ensure` | 返回 token 字符串 |
| `refresh()` | `token.refresh` | — |
| `expiring()` | `token.expiring` | `params.secret` |
| `models()` | `models.list` | — |
| `refresh_models()` | `models.refresh` | `params.force` |
| `usage()` | `usage.query` | — |
| `checkin()` / 领取 | `checkin.claim` | — |
| 独立福利领取 | `claim` / `claim.status` | — |
| `normalize_account()` | `account.normalize` | `params.secret` / `params.input` |
| `account_view()` | `account.view` | `params.secret` |
| `account_identity()` | `account.identity` | `params.secret` |
| `login_start` / `login_poll` / `login_cancel` | `login.start` / `login.poll` / `login.cancel` | — |
| 登录回调 | `login.callback` | — |
| `admin.action` | `admin.action` | `params.action`（如 `auth.methods` / `quota.sources`） |
| 图片能力 | `images.capabilities` | — |
| — | `ping` | 返回 `json!(true)` |

未实现的方法统一 `_ => Err(Error::unsupported())`（与 atomcode 一致）。

## 4. metadata() 字段

与 native 的 `ProviderMeta` 一一对应，字段名是 **snake_case**：

```json
{
  "id": "<name>", "label": "<显示名>", "order": <数字>,
  "capabilities": { "chat": true, "stateful": false, "refresh": false, "model_refresh": true,
                    "usage": false, "checkin": false, "claims": false, "web_login": false,
                    "refresh_uses_account": false, "supports_default_model": false,
                    "sse_model_rewrite": false, "sse_strip_newline_chunks": false,
                    "anonymous_default_session": false, "system_proxy_when_unset": false,
                    "env_credentials": false },
  "login_methods": [ ... ],
  "account_features": { ... },
  "checkin": { ... },
  "default_models": [ ... ]
}
```

`account_features` 里 **`invite_code`** 是我们自用的扩展位（native 侧在
`crates/provider-protocol/src/provider.rs` 的 `AccountFeatures`，带 `#[serde(default)]`）。
网关用我们 fork 的 protocol crate 反序列化，所以 wasm 插件只要写 `"invite_code": true` 就能生效。

> 目前只有 loomy 需要它（native：`loomy/mod.rs` 的 `AccountFeatures`）。

## 5. 必须保留的自用改动

`ziyong` 相对 `upstream/beta` 的差异，迁 wasm 时必须一起搬：

| 文件 | 内容 |
|---|---|
| `crates/provider-protocol/src/provider.rs` | `AccountFeatures.invite_code`（网关侧已生效，插件侧在 loomy 的 account_features 里申报） |
| `crates/providers/src/providers/loomy/balance.rs` | +180 行，余额解析 |
| `crates/providers/src/providers/loomy/mod.rs` | +19，接入 balance 与 invite_code |
| `crates/providers/src/providers/raccoon/balance.rs` | 16 行改动 |
| `crates/providers/src/providers/workbuddy/auth.rs` | 7 行 |
| `crates/providers/src/providers/workbuddy/growth/{events,mod,spec,streak}.rs` | +125，连登/成长 |
| `crates/providers/src/providers/astudio/mod.rs` | +1 |
| `crates/providers/src/providers/kiro/mod.rs` | +1 |

## 6. 协议差异（重点）

`UpstreamKind`（`crates/provider-protocol/src/chat.rs`）在 native 侧由网关的翻译层处理。
Wasm 侧**没有翻译层**，插件必须自己把上游流折成标准 chat SSE。

| provider | native UpstreamKind | wasm 侧要做的事 |
|---|---|---|
| 22 家（除下面 4 家） | `Chat` | 直接转发上游 SSE，几乎不用改（参照 `wasm/atomcode/src/chat.rs`） |
| `commandcode` | `Ndjson` | 自己把 AI SDK v5 NDJSON 折成 chat SSE（参照网关 `core/protocol/ai_sdk_ndjson.rs`） |
| `loomy` | `Anthropic` | 自己把 Anthropic Messages SSE 折成 chat SSE（参照 `core/protocol/anthropic.rs`） |
| `zcode`（及 zcode-intl） | `Anthropic` | 同上 |
| `antigravity` | `Gemini` | 自己把 Gemini 信封 SSE 折成 chat SSE（参照 `core/protocol/antigravity_stream.rs`） |

## 7. 已知坑

1. **`--locked` 构建**：`wasm/Cargo.lock` 必须与 members 同步。加新 crate 后要先 `cargo update` 或让 cargo 自己写回，否则 `node wasm/build.mjs` 报 lock 不一致。
2. **`CARGO_TARGET_DIR`**：`env.ps1` 把它钉到 `G:\ZCode\Agent2API-tool\target`，`build.mjs` 会照它找 `.wasm`。别在该变量生效的 shell 里假设产物在 `wasm/target/`。
3. **`wasm32-unknown-unknown` 无 std 的 `std::env`**：不能用 `std::env::var`，改 `sdk::settings::get`。
4. **crate 名与目录名**：`cargo -p agent2api-wasm-<name>`，目录名必须是 `[a-z][a-z0-9-]*`。
5. **`build.mjs` 的图标校验**：写了 `icons` 就必须在目录第一层有图片且 ≤2 MiB，不许软链。
6. **一个包多个 provider id**：`wasm_provider()` 在网关侧要求 `providers.len() == 1`（`provenance.rs:90`）。**这一条对多 id 的包是硬顶** —— 详见第 8 节。
7. **`panic = "abort"`**：wasm workspace 的 release profile 是 abort，插件内一次 panic = 该包整个实例挂掉（不影响网关）。

## 8. 待解决：多 provider id 的包

网关 `plugin_host/packages/provenance.rs:89-94`：

```rust
pub(...) fn wasm_provider(&self) -> Option<&str> {
    if self.target != TARGET || self.providers.len() != 1 || self.facts.wasm.is_none() {
        return None;
    }
```

即 **wasm 包只能声明 1 个 provider**，否则包不启动。

但 native 侧有 10 个 provider id 是"一个目录出多个"：`zcode`/`zcode-intl`、
`workbuddy`/`workbuddy-intl`、`modelscope`/`modelscope-intl`、`monkeycode`/`monkeycode-intl`、
`qoder`/`qoder-intl`、`qwenwork`/`qwenwork-intl`、`accio`/`accio-cn`、
`autoclaw`/`autoclaw-intl`、`cline-free`/`cline-pass`。

两条路：
- **A（不改网关）**：拆成 `<name>` 与 `<name>-intl` 两个 crate，共用一份源码模块（`#[path]` 或同 crate 多 bin）—— 但 `wasm_provider()` 仍只认 1 个，所以必须是**真的两个包**。
- **B（改网关）**：去掉 `providers.len() != 1`，改 7 个调用点（`provenance/startup.rs:47`、`provenance/registry.rs:173`、`wasm/install_source.rs:22`、`wasm/conversation/task_call.rs:100`、`wasm/cline_free_enrollment/binding.rs:61`、`wasm/codearts_enrollment/binding.rs:60`、`wasm/native/chatglm/call.rs:93`）。

**本迁移采用 A**：一家一个包，多 id 的拆成两个包（源码通过共享目录复用）。

## 9. 加载期硬校验（不满足 = 整包加载失败，实测踩过）

来源：网关 `plugin_host/wasm/host.rs:97-110`。装包时逐条卡，报错文案就是下面这些。

| # | 条件 | 不满足的后果 |
|---|---|---|
| 1 | `capabilities.chat == true` → `requires` 必须有 `chat.stream.v1` | 「Wasm 提供商能力缺少授权声明：chat.stream.v1」 |
| 2 | `capabilities.model_refresh == true` → `requires` 必须有 `catalog.v1` | 「Wasm 提供商能力缺少授权声明：catalog.v1」 |
| 3 | `capabilities.web_login == true` → `requires` 必须有 `login.forms.v1` | 「Wasm 提供商能力缺少授权声明：login.forms.v1」 |
| 4 | `capabilities.anonymous_default_session` 与 `capabilities.env_credentials` **必须都是 false** | 「Wasm 不允许隐式本机凭证，请使用显式账号或已授权的原生辅助」 |
| 5 | `capabilities.chat == true` → `requires` 必须有 `accounts.cas.v1` | 「Wasm 对话必须声明受控账号访问能力」 |

**第 4 条最容易踩**：`metadata.json` 是从 native `meta()` 原样生成的，而 native 里
`env_credentials` / `anonymous_default_session` 常为 true（表示「能从本机登录态或环境变量
拿凭证」）。wasm 沙箱既没有文件系统也没有环境变量，这两位必须改成 false。

### 实测记录（2026-11-19）

装进去后：loomy 7 + trae 7 + qoder 7 = **21 个账号立刻可见**，`hiddenAccounts` 从 97 降到 76。
raccoon（34 个账号）和 codearts（7 个）各自因为上表第 4 条、第 2 条被拒，修正后重装。
这直接证明「wasm 包声明了某个 provider id，该 provider 的隐藏账号就会恢复」的机制成立。

## 10. `chat` 是死路径，必须实现 `conversation`

- 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async`：包是 wasm 就返回
  **501「Wasm 对话必须使用标准流通道，不接受主程序代发计划」**。
- `rpc.rs` 的 `forwards_response()` 对 wasm **恒为 true**（`is_stateful() || wasm.is_some()`），
  所以 `provider_loop.rs` 的分流点 `if adapter.forwards_response() && images.is_none()`
  对 wasm 包一律成立 → 走会话式通道。
- 结论：**wasm 包的对话只能靠 `conversation`**（插件自己 `http::open` + `stream_head` /
  `stream_bytes`）。`chat` 写了也不会被调用，`stateful` 取什么值都不影响路由。
- `sdk::stream_head` 固定发 `content-type: text/event-stream`，非流式请求也按 SSE 下发，
  由网关聚合回 JSON。native 的「聚合后一次返回」分支不用迁。

## 11. 图片能力：wasm 侧没有通用入口（**前面判断有误，此处更正**）

`images.generate` / `images.edit` 在 wasm 侧**只有一条入口**：

- `wasm/runtime.rs:161` `invoke_doubao_image()`，由豆包对话流里的生图任务触发
- `wasm/runtime.rs:290` 硬校验：`method != "images.generate" || provider != "doubaowork"` 就报
  「豆包生图调用来源无效」

也就是说 **只有 `doubaowork` 能调图片方法**，且只服务它自己的对话流生图。

结论：
- racacoon / loomy / workbuddy 这些 native 支持生图/改图的家，wasm 化后**图片能力无法保留** ——
  不是子智能体没找到入口，是架构上就没有这条通道。
- 要恢复，必须在网关新增通用图片通道（新的 `InvocationContext` 变体 + 参数契约 + 回包处理），
  那是网关侧的功能开发，不在本次迁移范围内。
- **`doubaowork` 的图片必须实现**，它是这条通道唯一的用户。

`sdk::images::Resource`（`create` / `append` / `seal` / `read` / `remove`，
`image_result()` → `{resource: id}`）与 `sdk::images::response(images, usage)` 就是为这条通道准备的。


## 12. 设置命名空间：`storage_provider` 必须是本包自己的 id

来源：`plugin_host/provider_settings/schema.rs:187`。

```rust
if !host.callbacks.provider_allowed(schema.owner(id)) {
    return Err("插件设置只能使用本包获授权的提供商命名空间".into());
}
```

`schema.owner(id)` 取 `storage_provider`（缺省则取 `id`）。一个 wasm 包只授权了自己的
provider id，所以 **`metadata.json` 的 `settings_schema.storage_provider` 只能是本包的 id**。

实测：`zcode-intl` 从 native 抄来时 `storage_provider` 是 `"zcode"`（native 里国内/国际共用
一份版本号设置），装包直接被拒。改成 `"zcode-intl"` 后通过。

副作用：国内版与国际版不再共享同一份设置项，各自存各自的。这是拆包必然的结果，改不回去。

## 13. 装包加载失败的四条真实报错（排错速查）

| 报错 | 位置 | 修法 |
|---|---|---|
| `Wasm 提供商能力缺少授权声明：<cap>` | `host.rs:103` | 按第 9 节那张表把 `requires` 补齐 |
| `Wasm 不允许隐式本机凭证，请使用显式账号或已授权的原生辅助` | `host.rs:107` | `metadata.capabilities.anonymous_default_session` / `env_credentials` 改 false |
| `Wasm 对话必须声明受控账号访问能力` | `host.rs:110` | `requires` 加 `accounts.cas.v1` |
| `插件设置只能使用本包获授权的提供商命名空间` | `schema.rs:187` | `settings_schema.storage_provider` 改成本包 id |

## 14. 端到端实测结论（2026-11-19，3066 验证实例）

装进 13 个 wasm 包后：

- `hiddenAccounts`：**97 → 0**，108 个账号全部可见
- `host`：15 个 provider，`ready=true`、`running=true`、`crashes=0`
- 装过的包：atomcode / loomy / trae / qoder / raccoon / codearts / zcode-intl / workbuddy / workbuddy-intl / modelscope / orcaterm / commandcode / kuku —— 全部 `supportState = supported`
- native 的 `agent2api-providers`（v4.0.0）仍是 `legacy_unsupported`，但**不影响**同名 provider 的 wasm 包工作 —— `hidden_accounts.rs:61` 的取反 `any` 让「只要有一个 supported 包声明了这个 id 就不算 legacy」成立

## 15. `origins` 是**精确字符串匹配**，不支持通配或后缀

`wasm/manifest.rs:283`：

```rust
!self.manifest.origins.contains(&url.origin().ascii_serialization())
```

`url.origin()` 只到 host + port，所以 `https://a.example.com/x` 的 origin 是
`https://a.example.com`；`Vec::contains` 是**字符串全等** —— 写父域**不能**覆盖子域。

实测影响（2026-11-19）：

- `officeace` 的 chat 网关主机名来自登录返回的 `model_api_url_base`，native 的校验是
  `host.ends_with(".officeace.cn-southwest-2.huaweicloud-agentarts.com")`
  （`crates/providers/src/providers/officeace/activation.rs:248`），
  即**子域前缀是账号相关的动态值**，静态白名单写不下。
- 后果：该包的登录/账号/目录能跑，但 chat 会在 `check_url` 处被拒（
  「插件请求地址未获网络授权」）。

通用结论：**凡是上游主机名带动态子域的家，wasm 包都受这条限制**。要支持只有两条路：
① 网关给 origins 加通配（如 `https://*.xxx.yyy`）；② 该家接受这个功能缺口。

## 16. 排错速查：运行期被拒的两种文案

| 文案 | 位置 | 含义 |
|---|---|---|
| `插件请求地址未获网络授权` | `manifest.rs:285` | URL 的 origin 不在 `wasm.json` 的 `origins` 里（精确匹配） |
| `插件请求地址无效` | `manifest.rs:278` | URL 解析失败，或非 https / 带用户名密码 / 带 fragment |

**这两条只在运行期触发，装包不报错** —— 所以包能装上、界面能打开，一对话才失败。

## 17. `admin.action = auth.methods` 必须返回**动态登录元数据**，否则登录面板打不开

来源：`api/session.rs:263-280`。

```rust
let metadata = if dynamic_login(adapter.provider_id()) {
    adapter.admin_action(state.store(), "", "auth.methods", &json!({ "locale": ... })).await.map(Some)?
} else {
    adapter.login_methods_metadata(state.store()).await?   // ← 只有非 wasm 走这条，带 404/501 回退
};
let value = if value.is_array() { json!({ "methods": value }) } else { value };
let mut metadata: LoginMethodsMetadata = serde_json::from_value(value)
    .map_err(|_| GatewayError::with_status(502, "插件返回的登录方式元数据无法解析"))?;
```

`rpc.rs:252` 的 `dynamic_login()` 对 **wasm 恒为 true**。所以：

- **wasm 包必须自己实现 `admin.action` 的 `auth.methods` 分支**，返回正确形状；
- 返回**任何错误**（含 501）都会直接冒泡成接口错误 —— **走不到 `adapter.rs:1237` 那条 404/501 回退**（那条只服务非 wasm 包）；
- 返回数组会被自动包成 `{"methods": [...]}`，但**元素形状必须对**，否则 502。

### 正确形状（实测自 atomcode / loomy）

```json
{ "methods": [ {
    "methodIndex": 0,
    "type": "oauth",              // oauth | api | sms | desktop
    "label": "浏览器登录",
    "instructions": "…",
    "browserMode": "choice",      // choice | external | plugin | none
    "callbackInput": "url",       // url | code
    "desktopOnly": false,
    "embeddedOnly": false,
    "localOnly": false,
    "manualCallback": false,
    "dynamicPrompts": false,
    "validatesCallback": false,
    "prompts": []
} ] }
```

`type: "api"` 的方法用 `prompts[]` 描述输入项：

```json
"prompts": [ { "key": "accessToken", "label": "Access Token", "optional": false,
               "options": [], "placeholder": "", "secret": true, "type": "text" } ]
```

`type: "sms"` 还要 `sms: { codeMinLength, codeMaxLength, countryCodes[], phoneLabel, ... }`，
且**必须**申报 `login.sms.v1`（`session.rs:308` 对 wasm 有硬校验）。

### `desktop`（本机导入）的真实契约 —— 别写 `desktopOnly`

第一版文档写的是 `type:"desktop"` + `desktopOnly:true` + `localOnly:true`，**这是错的，会 502**。

`session.rs:285`：

```rust
if method.desktop_only && (!method.embedded_only || !matches!(method.kind, LoginMethodType::Oauth)) {
    return Err(GatewayError::with_status(502, "插件登录窗口契约无效"));
}
```

即 `desktopOnly: true` 要求 `type` 必须是 `oauth` 且 `embeddedOnly` 必须为真。

**desktop 的正确写法**（`session.rs:359` + 前端 `add-account-dynamic-fields.ts:205` 的判据）：

```json
{ "methodIndex": 2, "type": "desktop", "label": "导入本机登录态",
  "prompts": [], "instructions": "…",
  "browserMode": "none", "localOnly": true }
```

而且只有 `wasm.json` 的 `requires` 里有 `desktop.credentials.v1` 的包才能输出它。

### 另一个必踩的坑：申报了 `login.interaction.v1` 就必须回宿主的 `flow`

`plugin_host/wasm/host.rs:428-432`：

```rust
// 交互式登录必须使用主程序分配的流程标识
```

网关在 `login.start` 时把 `params.flow` 给插件，然后在 `login.callback` 时**逐字比对** URL 里的 `state` 与当前 flow。
插件若把**上游自己的 state** 当 `"flow"` 返回（native 就是这么干的，native 没有这个校验），
即使 `auth.methods` 修好、面板能打开，点「网页登录」也会当场 502。

**正确做法**：`login.start` 原样回 `params["flow"]`；上游 state 存在自己的登录状态里，
`login.poll` / `login.callback` 从那里读，不需要回传给网关。`workbuddy` / `workbuddy-intl` 踩过这个。

### 还有一处容易漏：`account.normalize` 要认面板塞进来的 `inputs`

网关把 api 表单整包放进 `NormalizeSource::Manual { payload: { methodIndex, inputs } }`
（`api/accounts.rs:166-180`）。插件若只读平铺的 `params.secret` / `params.payload.token`，
「登录凭据」按钮点下去会报「缺凭据」。

`trae` / `doubaowork` / `kuku` 都踩过，修法是先解一层 `payload.inputs`。



### 实测结果（2026-11-19，19 个包全探一遍 `/api/session/login/methods`）

| 结果 | 包 | 含义 |
|---|---|---|
| 200 ✅ | atomcode、loomy、qoder | 形状正确 |
| 502 ❌ | codearts、zcode-intl、modelscope、orcaterm、officeace、zcode、catpaw | 返回了数组但元素形状是 native 的 `login_methods`，解析不了 |
| 501 ❌ | raccoon、trae、commandcode、kuku、doubaowork、lobsterai、workbuddy、workbuddy-intl | 没实现 `admin.action`，错误直接冒泡 |

**也就是说：19 个包里只有 3 个的登录面板能用。这条不修，其余 16 家的「添加账号」入口全废。**

两条修法：
- **A（改包，彻底）**：每个包按上面形状实现 `auth.methods`（`metadata.json` 的 `login_methods` 可以映射过来：
  `Token { label, placeholder, extra_fields }` → `type:"api"` + 一条 `prompts`；
  `Browser { button, hint }` → `type:"oauth"` + `browserMode:"choice"` + `instructions: hint`）。
- **B（改网关，省事但留补丁）**：在 `session.rs` 的 wasm 分支也加 404/501 回退到静态 `login_methods`。


| 文案 | 位置 | 含义 |
|---|---|---|
| `插件请求地址未获网络授权` | `manifest.rs:285` | URL 的 origin 不在 `wasm.json` 的 `origins` 里（精确匹配） |
| `插件请求地址无效` | `manifest.rs:278` | URL 解析失败，或非 https / 带用户名密码 / 带 fragment |

**这两条只在运行期触发，装包不报错** —— 所以包能装上、界面能打开，一对话才失败。


装进 6 个 wasm 包后：

- `hiddenAccounts`：**97 → 35**，恢复 62 个账号（raccoon 34 + loomy 7 + trae 7 + qoder 7 + codearts 7）
- `host`：`providers` 出现 6 个 wasm provider，`ready=true`、`running=true`、`crashes=0`
- `packs`：`agent2api-providers`（native，v4.0.0）仍是 `legacy_unsupported`，但**不影响**同名 provider 的 wasm 包工作 —— `hidden_accounts.rs:61` 的取反 `any` 让"只要有一个 supported 包声明了这个 id 就不算 legacy"成立
- 剩下的是 `workbuddy` 33 个 + `zcode-intl` 2 个（当时还没迁完）


