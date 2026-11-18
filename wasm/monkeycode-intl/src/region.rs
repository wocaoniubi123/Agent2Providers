//! MonkeyCode **国际版**的站点身份：provider id / 域名 / 展示名 / 登录窗口域。
//!
//! ── 本包只做国际版（国内版在另一个包里）────────────────────────
//! native（`crates/providers/src/providers/monkeycode/`）用 `region::Region`
//! 参数化两个站点，同一个目录导出 `monkeycode` 与 `monkeycode-intl`。wasm 网关
//! 的 `plugin_host/packages/provenance.rs::wasm_provider` 要求**一个包只声明一个
//! provider id**，所以两个地区必须拆成两个包：
//!
//! ```text
//!   wasm/monkeycode/       → 国内版（另一个包）monkeycode-ai.com
//!   wasm/monkeycode-intl/  → 国际版（本包）    monkeycode-ai.net
//! ```
//!
//! 本文件因此**没有** `Region` 枚举：地区已经是包的身份，再在包里留一个可以
//! 取到 `.com` 的分支，只会有两种结局 —— 要么被误用（国际版包去连国内站），
//! 要么要在 `origins` 里同时申报两个域名（把国际版包的网络授权放大到国内站，
//! 那不是这个包该有的权限）。native 里「地区是一等公民」的设计原样保留，只是
//! 落点是「一个地区一个包」。
//!
//! ── 上游长什么样（依据 `Acankao/MonkeyCodeReverseEngineer`）──────
//! 长亭科技（chaitin）的开源 AI 开发平台，单体 Web 应用，网页与 API 同域：
//!
//! ```text
//!   站点      国际 https://monkeycode-ai.net
//!   认证      GET  /api/v1/users/status        Cookie: monkeycode_ai_session=…
//!   目录      GET  /api/v1/users/models        → {code:0,data:{models:[…]}}
//!   任务      POST /api/v1/users/tasks         （建任务；见 task.rs）
//!   任务流    WS   /api/v1/users/tasks/stream  （ACP 事件；见 stream.rs）
//! ```
//!
//! ── native `region.rs` 的一处决策注释（一并带过来）──────────────
//! 参考 `Acankao/MonkeyCodeReverseEngineer` 只覆盖了国内站 `.com`
//! （`mvp/config.py` 的 `BASE_URL` 默认值、文档里所有端点示例都是
//! `monkeycode-ai.com`）。国际站 `.net` 的**存在**由官方发布渠道确认为
//! 「MonkeyCode 在线托管版」（README / 多篇公告把 `.net` 指为 hosted 入口），
//! 但参考里**没有** `.net` 的实测端点、cookie 名或字段差异记录。
//! native 因此按「同一套协议、只换站点」建模（与 AutoClaw 两地同协议同值的
//! 情形一致），本包沿用同一口径：**域名、登录窗口域换成 `.net` 那一列，
//! cookie 名与 host_id 与国内版逐字相同**（native `endpoints.rs` 的
//! `SESSION_COOKIE_NAME` 与 `host_id()` 都没有地区分叉）。若将来实测出差异，
//! 改这一处即可。
//!
//! ── provider id 为什么国际版带 `-intl` ────────────────────────
//! 本家是 2026-10 新增的一家，国内版取无后缀的 `monkeycode`（用户直觉里
//! 「MonkeyCode 就是国内那个站」），国际版取 `monkeycode-intl` —— 与
//! AutoClaw / Qoder / ZCode 的命名口径一致。两个 id 一旦落进 accounts.json
//! 就是**落盘契约**，不要再改。本包只认 `monkeycode-intl`。
//!
//! ── 环境变量覆盖在 wasm 侧不存在（与 native 的差异，如实说明）──────
//! native 的 `Region::base_url()` / `host_id()` 分别读
//! `MONKEYCODE_INTL_BASE_URL` 与 `MONKEYCODE_INTL_HOST_ID`（自建 / 测试站点用）。
//! wasm 沙箱**没有环境变量**（`std::env::var` 在 `wasm32-unknown-unknown` 上不可用），
//! 而且就算改读 `sdk::settings::get`，换过的站址也不在 `wasm.json` 的 `origins` 里
//! —— 运行期会被 `manifest.rs::check_url` 判「插件请求地址未获网络授权」。
//! 因此本包**固定**用官方站点与公共宿主机，覆盖入口不开放（见 `endpoints.rs`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

/// 本包的 provider id（`pack.json` / `metadata.json` 用同一条）。
pub const PROVIDER_ID: &str = "monkeycode-intl";

/// 地区短标识（日志与缓存键里用，与 native `Region::Intl` 的 `Region::id()` 同值）。
pub const REGION_ID: &str = "intl";

/// 地区展示名后缀（界面上跟在 `MonkeyCode` 后面的那一段）。
pub const REGION_LABEL: &str = "国际版";

/// 站点 Origin（网页与 API 同域；native `Region::Intl` 的 `site_origin()`）。
///
/// ── 这一条必须与 `wasm.json` 的 `origins` 逐字相同 ──────────────
/// 网关的 `origins` 是**精确字符串匹配**（`manifest.rs:283` 的
/// `origins.contains(&url.origin().ascii_serialization())`），写父域覆盖不了子域，
/// 写多一个斜杠也匹配不上。`wss://` 的 WebSocket 会先被折成 `https://` 再比
/// （`manifest.rs:279`），所以任务流不必单独申报 `wss://` 来源。
pub const SITE_ORIGIN: &str = "https://monkeycode-ai.net";

/// 登录窗口的导航白名单（宿主内嵌窗口用，不是插件的出站白名单）。
///
/// 与 native `Region::Intl` 的 `login_hosts()` 逐条一致：国际站的登录链路是
/// GitHub / Google 的 OAuth（`github.com` / `accounts.google.com`），国内站那条
/// 百智云（`baizhi.cloud`）不在国际站链路上。这份清单交给宿主窗口做导航放行，
/// **不参与** `wasm.json` 的 `origins`（插件自己不向这些域发请求）。
pub const LOGIN_HOSTS: [&str; 3] = ["monkeycode-ai.net", "github.com", "accounts.google.com"];
