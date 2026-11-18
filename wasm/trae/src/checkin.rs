//! Trae 的每日签到（`checkin_credits/status` + `.../claim`）。
//!
//! ── 协议来源 ──────────────────────────────────────────────
//! 参考实现 `cpa-multi-plugins/plugins/trae`：协议层（CheckinStatus / CheckinClaim /
//! 探测体表 / 设备号生成）、节奏层（「不自动重试」的定案）、面板层（无 deviceId
//! 硬拦、回查未翻转不算成功）。这一条链上每一步看着都可以"顺手简化"，而每一处
//! 简化的后果都是官方风控。
//!
//! ── 一轮到底发几个请求（这是本模块的安全边界）──────────────────
//! 状态 1 发 + （未签时）领取 1 发 + 同设备号回查 1 发 = **常态 3 发**；
//! 请求体恒 `{}`（见 `probe_bodies`），最坏情况因 9074 不换方案而止于一发。
//! 撞上 `1001`（服务端作废这张 JWT）时驱动会换发新令牌后再走一轮，封顶两轮。
//! **不搬**参考实现的当日指数退避定时器（1m→2m→…→2h、每日 10 次）：那套是为
//! 「0 点整官方重置瞬间的洪峰」调的，而本仓的定时签到时刻由用户在设置页决定，
//! 再叠一层后台重试会把「一天三次」变成「一天几十次」——恰好是前科的成因。
//!
//! ── claim 的 `code:0` 是**假成功**陷阱 ──────────────────────
//! 当日已签过的账号对**任何** device_id 都回 `code:0`（参考实现实测）。
//! 所以判"这次真领到了"不看 claim 的码，只看**同一 device_id 回查**之后
//! `checked_in` / `did_checked_in` 有没有翻转。回查没确认就报 `success:false`，
//! 绝不报「签到成功」——那会让界面亮绿、当日台账落库，而实际什么也没到账。
//!
//! ⚠️ 数额口径：上游状态里 `credits` 与 `extra_credits` 是两个**并列分量**，
//!   不是可相加的两笔钱。实测一个账号状态报 `credits=100`、`extra_credits=100`，
//!   钱包实际只增加 100；把两者相加会显示成 200（参考实现 magpie 也踩过同坑）。
//!   因此到账数额按 `credits` 取，只有 `credits` 为 0 时才退到 `extra_credits`。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::account;
use super::device;
use super::errors::{self, ErrorKind};
use super::upstream::{post_json, Reply, UG_HOST};
use super::usage::ug_headers;

/// 签到状态查询（参考实现 `EpCheckinStatus`）。
const EP_CHECKIN_STATUS: &str = "/trae/api/v2/ug/checkin_credits/status";
/// 领取（参考实现 `EpCheckinClaim`）。
const EP_CHECKIN_CLAIM: &str = "/trae/api/v2/ug/checkin_credits/claim";

/// 业务码：成功。
const CODE_OK: i64 = 0;
/// 业务码：`当前参与用户太多，请稍后再试`。
///
/// 这一码有两家相反的说法：参考实现反编译官方后判「`req_source` 与令牌的产品
/// 谱系错配同样回 9074」；同族端点的另一家公开实现实测判「device 维度限流，
/// 换张派生号就领得到」。本仓的一手记录偏向后者，但 11 秒的间隔同样能解释成
/// "名额松开"，不足以下定论。维持现状：一发即回报、当日不自动重试。
/// 真要判别：下次撞 9074 时**复用同一个 device id** 再打一发。
const CODE_REJECTED: i64 = 9074;
/// 业务码：**服务端已作废这张 JWT**，而本地 `expiredAt` 看不出来。
///
/// 出处是同一族端点（`ug/checkin_credits/*` + `pay/ide_user_ent_usage`）上的
/// 第三方判定：`code == 1001` 与文案 `not able to authenticate` 一并当作鉴权
/// 失效，动作是换发新 JWT 后重放一次。本仓一手验证过语义：连拒 1001 的账号
/// 刷新令牌后当天就签到成功。
const CODE_TOKEN_DEAD: i64 = 1001;

/// 错误体进消息的截断长度（与 `usage.rs` 同一口径）。
const ERROR_BODY_HEAD: usize = 200;

/// 鉴权方案。参考实现：`Cloud-IDE-JWT` 优先，`Bearer` 兜底；非 9074 的业务码
/// 才换方案（9074 走"换探测体"那一支 —— 而探测体现在只有一发）。
#[derive(Clone, Copy, Debug, PartialEq)]
enum Scheme {
    Jwt,
    Bearer,
}

impl Scheme {
    fn next(self) -> Option<Scheme> {
        match self {
            Self::Jwt => Some(Self::Bearer),
            Self::Bearer => None,
        }
    }

    fn authorization(self, access_token: &str) -> String {
        match self {
            Self::Jwt => format!("Cloud-IDE-JWT {access_token}"),
            Self::Bearer => format!("Bearer {access_token}"),
        }
    }
}

/// 签到这一发的请求体：**恒为空对象**。
///
/// 这里以前照参考实现轮询三种 `req_source`，依据是「谱系错配会 9074」。收成
/// 一条的依据有两条，都不是猜的：同族端点的另一家实现恒发 `{}`；本仓第一次
/// 撞到的 9074 就是拿空体发出来的 —— 没有 `req_source` 可错配，"谱系探测不对"
/// 这条解释在那一发上直接不成立。真在自己日志里攒出一次 9074 时，这里就是
/// 加回序列的挂点。
pub fn probe_bodies() -> Vec<Value> {
    vec![json!({})]
}

/// 一轮签到的**设备号**：16 位随机数字串。
///
/// 三个约束都来自参考实现的实测：登录那套 hex32 设备号或 `machineId` 去打签到
/// **必败 9074**；空值 → 9004；**复用**上一轮的号 → 风控画像里的可疑项。
/// 所以每轮新生成，并在 status → claim → 回查这**三发之间保持不变**
/// （回查要按同一个号问「今天这个设备签过没有」，换号回查等于自证失败）。
pub fn checkin_device_id() -> String {
    device::random_digits(16)
}

/// `checkin_credits/status` 响应里本模块要用的字段。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Status {
    pub checked_in: bool,
    pub did_checked_in: bool,
    pub enable: bool,
    pub credits: i64,
    pub extra_credits: i64,
    pub code: i64,
    pub message: String,
}

impl Status {
    /// 「今天这个账号已经算签过了」——两个维度任一为真即真。
    ///
    /// `did_checked_in` 是**设备维度**（这个号今天签过），`checked_in` 是账号维度。
    pub fn done_today(&self) -> bool {
        self.checked_in || self.did_checked_in
    }

    /// 今日奖励的两个分量；到账数额见 [`Award::total`]（不是两者相加）。
    pub fn award(&self) -> Award {
        Award {
            credits: self.credits,
            extra_credits: self.extra_credits,
            credited: if self.credits > 0 { self.credits } else { self.extra_credits },
        }
    }
}

/// 响应体 → `Status`。缺字段一律按 `false` / `0` 收（**不猜**：`enable` 缺省
/// 按"没开"处理最保守，宁可少签一次也不多打一发请求）。
pub fn status_of(payload: &Value) -> Status {
    let number = |key: &str| payload.get(key).and_then(Value::as_i64).unwrap_or(0);
    Status {
        checked_in: flag(payload, "checked_in"),
        did_checked_in: flag(payload, "did_checked_in"),
        enable: flag(payload, "enable"),
        credits: number("credits"),
        extra_credits: number("extra_credits"),
        code: payload.get("code").and_then(Value::as_i64).unwrap_or(CODE_OK),
        message: payload.get("message").and_then(Value::as_str).unwrap_or("").trim().to_string(),
    }
}

fn flag(payload: &Value, key: &str) -> bool {
    payload.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// 一次往返后的业务码判定。
///
/// 参考实现分三路：码 0 → 收；码 9074 → 换下一个探测体（同方案）；其它非零
/// → 换下一个鉴权方案。比它多一档 `GiveUp`（1001）：既然这一码判为「服务端
/// 已作废这张 JWT」，换 `Bearer` 重试还是拿同一张死令牌去打 —— 那一发不会
/// 改变结果，只会把一次点击变成两发配额。
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Probe {
    Accept,
    NextBody,
    NextScheme,
    GiveUp,
}

pub fn probe_for(code: i64) -> Probe {
    match code {
        CODE_OK => Probe::Accept,
        CODE_REJECTED => Probe::NextBody,
        CODE_TOKEN_DEAD => Probe::GiveUp,
        _ => Probe::NextScheme,
    }
}

/// 状态 → 领取 → 回查 的**结论**（与网络层解耦）。
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// 上游没给这个账号开签到活动（中性，不算失败也不算成功）
    NotEnabled,
    /// 今天已经签过了（`already` 带的是当日奖励数额，可能为 0）
    AlreadyCheckedIn(Award),
    /// 本次真领到了（回查已确认），参数为奖励数额
    Claimed(Award),
    /// 领取被拒（`code` 是上游业务码，`message` 是上游原话）
    Rejected(i64, String),
    /// claim 回了 code:0 但同设备号回查没翻转 —— 服务端静默拒签，**不算成功**
    Unconfirmed,
}

/// 今日奖励的两个分量，以及**实际计入钱包的数额**。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Award {
    pub credits: i64,
    pub extra_credits: i64,
    /// 实际到账数额：`credits` 优先，`credits` 为 0 时才用 `extra_credits`。
    /// 两者绝不能相加（见模块头的 200/100 说明）。
    pub credited: i64,
}

impl Award {
    pub fn total(&self) -> i64 {
        self.credited
    }
}

/// 领取成功后的到账数额：claim 自己报了数额就以 claim 为准；它没报才用回查
/// 状态里的 `credits`。`credits` 与 `extra_credits` 仍然只取一个，绝不相加。
fn claimed_award(claim: &Status, after: &Status) -> Award {
    let (credits, extra_credits) = if claim.credits > 0 || claim.extra_credits > 0 {
        (claim.credits, claim.extra_credits)
    } else {
        (after.credits, after.extra_credits)
    };
    Award { credits, extra_credits, credited: if credits > 0 { credits } else { extra_credits } }
}

/// 拿到状态与（必要时）领取+回查后的判定。
pub fn decide(before: &Status, claim: &Status, after: Option<&Status>) -> Outcome {
    if !before.enable {
        return Outcome::NotEnabled;
    }
    if before.done_today() {
        return Outcome::AlreadyCheckedIn(before.award());
    }
    if claim.code != CODE_OK {
        return Outcome::Rejected(claim.code, claim.message.clone());
    }
    match after {
        // 回查确认：领取成功，数额按 claim → 回查的顺序取。
        Some(confirmed) if confirmed.done_today() => Outcome::Claimed(claimed_award(claim, confirmed)),
        Some(_) | None => Outcome::Unconfirmed,
    }
}

/// 这一行结果是不是「服务端把这张 JWT 作废了」。
///
/// 判据两条并列（码、文案），因为 1001 有时**不带文案**：只认码会在文案到位时
/// 仍走一遍，只认文案会在文案缺失时整条失效。文案两种写法都要认 —— 上游与
/// 参考实现各自转述过 `not able to authenticate` 和 `unable to authenticate`。
pub fn needs_reauth(row: &Value) -> bool {
    if row.get("code").and_then(Value::as_i64) == Some(CODE_TOKEN_DEAD) {
        return true;
    }
    let message = row.get("msg").and_then(Value::as_str).unwrap_or_default();
    message.contains("not able to authenticate") || message.contains("unable to authenticate")
}

/// `checkin.claim` 的实现。
///
/// 与 `usage.query` 同一条凭证链：读记录 → 组凭据 → **临期先续期**
/// （参考实现的"签到前保鲜"：token 过期时签到必撞会话类错误，而那一发错误
/// 看起来像"账号不行了"，会把健康账号拖进冷却）。
///
/// 之上多一条 **1001 的换发重放**：`renew_if_due` 是按本地 `expiredAt` 判临期的，
/// 而 `CODE_TOKEN_DEAD` 的意义恰恰是"本地那张表看不出来"。所以这一码单独走
/// `renew_forced`（无视临期直接换发），再打一轮，总共两轮封顶 —— 一次点击不该
/// 变成六发以上。
pub fn claim() -> Result<Value> {
    let record = account::record()?;
    let credential = account::credential(&record)?;
    let credential = account::renew_if_due(&record, &credential)?;
    let first = run(&credential, &UG_HOST)?;
    if !needs_reauth(&first) {
        return Ok(report(&first));
    }
    if !credential.can_refresh() {
        return Ok(report(&first));
    }
    let record = account::record()?;
    let credential = account::credential(&record)?;
    let renewed = match account::renew_forced(&record, &credential) {
        Ok(renewed) => renewed,
        Err(error) => {
            // 连 refreshToken 都换不出新令牌：这才是真的"要重新登录"。
            // 原行留着（码、文案都在），只在后面接一句我们做了什么的实话说。
            // ⚠️ 追加的句子不许出现「已签到」「已领取」。
            let mut row = first;
            if let Some(map) = row.as_object_mut() {
                map.insert("reauthAttempted".to_string(), json!(true));
                map.insert("reauthFailed".to_string(), json!(true));
                let head = map.get("msg").and_then(Value::as_str).unwrap_or_default().to_string();
                map.insert(
                    "msg".to_string(),
                    json!(format!("{head}；换发新令牌也失败（{}），请在「账号」页重新登录", error.message)),
                );
            }
            return Ok(report(&row));
        }
    };
    let mut row = run(&renewed, &UG_HOST).map_err(|error| {
        if error.status == Some(401) { error.with_code("checkin_auth_retry_exhausted") } else { error }
    })?;
    if let Some(map) = row.as_object_mut() {
        map.insert("reauthAttempted".to_string(), json!(true));
    }
    Ok(report(&row))
}

/// 一轮签到（凭证 → 结果行）。
fn run(credential: &account::Credential, base: &str) -> Result<Value> {
    let variant = credential.variant().to_string();
    if variant == "intl" || variant == "solo-intl" {
        // 参考实现里国际版根本没有签到（上游无此活动）。走到这里只可能是
        // 手工粘进来的谱系，如实说明而不是打一发注定失败的请求。
        return Ok(json!({
            "success": false,
            "msg": "国际版 Trae 没有签到通道（上游无此活动）",
        }));
    }
    if credential.access_token.trim().is_empty() {
        return Err(Error::http(401, "该 Trae 账号没有可用凭证，无法签到"));
    }
    if credential.device_id.trim().is_empty() {
        // 参考实现对缺 deviceId 的凭据是**硬拦**：这类凭据多半是手工粘贴的，
        // 服务端侧没有设备绑定，签到正好落在「绑定不一致 = 9074 高危画像」。
        // 与其打一发去撞风控，不如把话说明白：重新走一次网页登录再签。
        return Ok(json!({
            "success": false,
            "msg": "该账号没有 deviceId（多半是手工粘贴的凭据），官方按设备画像风控，请先重新登录再签到",
        }));
    }

    // 一轮一个号，三发之间不变（见 `checkin_device_id` 的说明）
    let device_id = checkin_device_id();
    let before = status(base, credential, &variant, &device_id)?;
    // 状态那一发自己回**非零业务码**时必须原样报成拒绝，不许退化成"活动没开"。
    // 退化是真的会发生的形状：`status_of` 对缺字段一律按 `enable=false` 收，
    // 于是 1001（这张 JWT 已被服务端作废）会被翻成「当前没有可领取的签到活动」
    // —— 把一个鉴权失败报成一件中性事，用户与定时链都会据此放弃这个账号。
    if before.code != CODE_OK {
        return Ok(complete(Outcome::Rejected(before.code, before.message.clone()), &device_id));
    }
    if !before.enable || before.done_today() {
        // 这一条分支根本没打领取；`decide` 在读 claim 之前就返回了，给一个空响应占位。
        return Ok(complete(decide(&before, &Status::default(), None), &device_id));
    }
    let claim_status = claim_one(base, credential, &variant, &device_id)?;
    if claim_status.code != CODE_OK {
        // 拒绝行要把第一发的状态读数带上（`with_status_probe`）—— 未知码的含义
        // 只能从「状态说什么 × 领取拒不拒」这个组合里夹出来。
        return Ok(with_status_probe(
            complete(decide(&before, &claim_status, None), &device_id),
            &before,
        ));
    }
    // 同设备号回查。回查本身失败（网络/会话）时按"未确认"处理 ——
    // 一发没被确认的 claim 报成成功，就是给用户一个假成功。
    let after = status(base, credential, &variant, &device_id).ok();
    Ok(complete(decide(&before, &claim_status, after.as_ref()), &device_id))
}

/// 判定 → 界面与日志消费的 `{success, msg, ...}`。
///
/// 设备号一并带回（`checkinDeviceId`）：这一轮用的哪个号，是把「上游回了 9074」
/// 与「官方客户端同日替用户签了」在后端日志里分开的唯一线索。
///
/// ⚠️ 两个雷区：
///   1. 数字口径：到账数额取 `credits`，`credits` 为 0 才用 `extra_credits`；
///      两者**不相加**（上游实测 100+100 名义、实际只到账 100）。
///   2. Rejected / Unconfirmed 的文案不许出现「已签到」「已领取」：编排层是
///      按 msg 子串判"当日已办"的，写进去就把一次失败洗成已签、当日不再重试。
fn complete(outcome: Outcome, device_id: &str) -> Value {
    let mut row = serde_json::Map::new();
    let awarded = match outcome {
        Outcome::NotEnabled => {
            row.insert("success".into(), json!(false));
            row.insert("msg".into(), json!("当前没有可领取的签到活动（上游未对该账号开放这一档）"));
            None
        }
        Outcome::AlreadyCheckedIn(award) => {
            row.insert("success".into(), json!(false));
            // `alreadyCompleted` 是给编排层看的：今天已经签过 = 当日台账要落库，
            // 定时链明天才照常再试，而不是把"已签"当成失败反复重打。
            row.insert("alreadyCompleted".into(), json!(true));
            row.insert(
                "msg".into(),
                json!(if award.total() > 0 {
                    format!("今日已签到（当日奖励 {} 积分）", award.total())
                } else {
                    "今日已签到".to_string()
                }),
            );
            Some(award)
        }
        Outcome::Claimed(award) => {
            row.insert("success".into(), json!(true));
            row.insert(
                "msg".into(),
                json!(if award.total() > 0 {
                    format!("签到成功（本次领取 {} 积分）", award.total())
                } else {
                    // 回查确认了"今天签过"，但上游没给数额 —— 不编一个数字出来
                    "签到成功（上游未给出奖励数额）".to_string()
                }),
            );
            Some(award)
        }
        Outcome::Rejected(code, message) => {
            row.insert("success".into(), json!(false));
            row.insert("code".into(), json!(code));
            // 上游给了文案就原样带出，没给才说"未给"。
            let reason = if message.is_empty() { "上游未给文案" } else { message.as_str() };
            let text = if code == CODE_REJECTED {
                // 两种读法都写出来，因为一手记录只到"偏向"的程度。
                format!(
                    "官方拒绝本次签到（{code}）：{reason}；这一码有两说 —— 参考实现判产品谱系/设备画像错配，\
                     同族端点的外部实测判「按 device id 限流、换张派生号就领得到」。本轮只发了一发，\
                     当日不再自动重试，想再试就再点一次签到"
                )
            } else if code == CODE_TOKEN_DEAD {
                format!(
                    "官方拒绝本次签到（{code}）：{reason}；这一码判为「服务端已作废这张登录态」\
                     （本地到期时间看不出来），处置是换发新令牌后重放一轮"
                )
            } else {
                // 不猜含义 —— 跨家搬码表正是把别家结论当自家事实的那类错。
                format!("官方拒绝本次签到（{code}）：{reason}；这一码本家没有实测依据，只按失败上报，当日台账不落")
            };
            row.insert("msg".into(), json!(text));
            None
        }
        Outcome::Unconfirmed => {
            row.insert("success".into(), json!(false));
            row.insert("claimUnconfirmed".into(), json!(true));
            row.insert(
                "msg".into(),
                json!("签到返回成功但同设备号回查未确认（服务端静默拒签），当日不再自动重试"),
            );
            None
        }
    };
    if let Some(award) = awarded {
        row.insert("awarded".into(), json!(award.total()));
        row.insert("checkinCredits".into(), json!(award.credits));
        row.insert("checkinExtraCredits".into(), json!(award.extra_credits));
    }
    row.insert("checkinDeviceId".into(), json!(device_id));
    Value::Object(row)
}

/// 把「本轮第一发状态读到了什么」原样挂到**拒绝行**上。
///
/// 为什么这一格值钱：未知业务码自己不含信息，能把它夹出来的是状态与领取的
/// **组合形状**。「活动开着但对这个账号今日不发货」和「有份额但被资格/风控拒了」
/// 在只带 code 的日志里长得一模一样；带上状态五格就能一眼分开。
/// 只挂在拒绝行：成功行的数额走 `awarded`（claim 优先、回查兜底），
/// 挂两份会供出两个不同的数。
fn with_status_probe(row: Value, status: &Status) -> Value {
    let mut row = row;
    if let Some(map) = row.as_object_mut() {
        map.insert("statusEnable".into(), json!(status.enable));
        map.insert("statusCheckedIn".into(), json!(status.checked_in));
        map.insert("statusDidCheckedIn".into(), json!(status.did_checked_in));
        map.insert("statusCredits".into(), json!(status.credits));
        map.insert("statusExtraCredits".into(), json!(status.extra_credits));
    }
    row
}

/// 状态查询（一轮里会发两次：领取前与领取后回查）。
fn status(base: &str, credential: &account::Credential, variant: &str, device_id: &str) -> Result<Status> {
    let payload = round_trip(base, EP_CHECKIN_STATUS, variant, device_id, credential)?;
    Ok(status_of(&payload))
}

/// 领取。回被采纳那份响应的 code 与 message（数额仍由回查读 —— 上游在 claim 里
/// 不保证给奖励数额，但它的**文案**是判别未知码的唯一线索，必须留下）。
fn claim_one(base: &str, credential: &account::Credential, variant: &str, device_id: &str) -> Result<Status> {
    let payload = round_trip(base, EP_CHECKIN_CLAIM, variant, device_id, credential)?;
    Ok(status_of(&payload))
}

/// 一发「方案 × 探测体」的往返，返回被采纳的那份响应体。
///
/// 分派规则：`code:0` 采纳；`9074` 换下一个探测体（同方案）；其它非零码换下一个
/// 鉴权方案。全部用尽仍非零时**返回最后一份**响应，由调用方按业务码判定 ——
/// 签到失败不是网关错误，不该冒成 5xx。只有 HTTP 层的会话失效（401 一类）才
/// 往上抛 `Error`，让批量签到把这一行报成失败并给出去重登的提示。
fn round_trip(base: &str, endpoint: &str, variant: &str, device_id: &str, credential: &account::Credential) -> Result<Value> {
    let url = format!("{base}{endpoint}");
    let bodies = probe_bodies();
    let mut scheme = Scheme::Jwt;
    let mut last = json!({});
    loop {
        for (index, body) in bodies.iter().enumerate() {
            let reply = post_checkin(&url, body, variant, device_id, &credential.access_token, scheme)?;
            let payload = reply.json().unwrap_or_else(|| json!({}));
            let code = payload.get("code").and_then(Value::as_i64).unwrap_or(CODE_OK);
            last = payload;
            match probe_for(code) {
                Probe::Accept => return Ok(last),
                Probe::GiveUp => return Ok(last),
                Probe::NextBody => {
                    // **体序列用尽就是这一发的终点**。这一格在只有一个体的今天
                    // 是主路径：9074 不是鉴权方案的错，换 Bearer 再打一遍只是
                    // 多花一次上游配额，还正好踩在"9074 之后再查 status 会加重
                    // 限流"那条外部实测上。
                    if index + 1 == bodies.len() {
                        return Ok(last);
                    }
                }
                Probe::NextScheme => break,
            }
        }
        let Some(next) = scheme.next() else {
            return Ok(last);
        };
        scheme = next;
    }
}

/// 真正发出去的那一发：ug 画像 + 指定鉴权方案 + 本轮固定设备号。
///
/// HTTP 层的状态码在这里就判成错误：ug 族带着 `Cloud-IDE-JWT` 在生产上是通的
/// （余额读数实测），所以一个 401 的含义是"这条会话真的死了"，而不是"该换
/// Bearer 了"。业务码的分派（9074 换体、其它非零换方案）在 `round_trip` 那一层。
fn post_checkin(
    url: &str,
    body: &Value,
    variant: &str,
    device_id: &str,
    access_token: &str,
    scheme: Scheme,
) -> Result<Reply> {
    let mut headers = ug_headers(variant, access_token, device_id);
    // `ug_headers` 写的是 Cloud-IDE-JWT；换 Bearer 兜底时**只换这一个头**，
    // 其余画像头保持逐字一致（混改会撞上"画像对不上"的风控）。
    if let Some(slot) = headers.iter_mut().find(|(name, _)| name == "Authorization") {
        slot.1 = scheme.authorization(access_token);
    }
    let reply = post_json(url, body, &headers)?;
    if reply.status >= 400 {
        let head: String = reply.body.chars().take(ERROR_BODY_HEAD).collect();
        let kind: ErrorKind = errors::classify(reply.status, &head);
        return Err(Error::http(
            errors::status_for(kind),
            format!("Trae 签到接口返回 {}: {}", reply.status, head.trim()),
        ));
    }
    Ok(reply)
}

/// 签到结果行 → 协议的 `CheckinReport`。
///
/// ── 为什么判据是 `success` 而不看 `code` ────────────────────
/// 本家的 claim 对**当日已签过**的账号回 `code:0`（假成功），所以上面已经把
/// 「真领到」翻成了 `success:true`（回查确认才给）。这里只做翻译，不再判一次
/// —— 两处各判一套的话，「今日已签」会时而算成功、时而算失败。
fn report(value: &Value) -> Value {
    let success = value.get("success").and_then(Value::as_bool).unwrap_or(false);
    let message = value
        .get("msg")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let already = value.get("alreadyCompleted").and_then(Value::as_bool).unwrap_or(false);
    let outcome = if success {
        "claimed"
    } else if already {
        // 今日已签：记为 Done（不再重试），不是失败
        "done"
    } else if message
        .as_deref()
        .is_some_and(|text| text.contains("不支持") || text.contains("无此活动"))
    {
        // 国际版没有签到活动（`run` 会明说）
        "ineligible"
    } else {
        "failed"
    };
    // 到账数额：`awarded` 已经按 credits / extra_credits 二选一算过，
    // 不再用两者之和（见模块头的 200/100 说明）。
    let credit = if success {
        ["awarded", "reward", "credit"].iter().find_map(|key| match value.get(*key)? {
            Value::Number(number) => number.as_i64().filter(|amount| *amount > 0).map(|amount| amount.to_string()),
            Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
            _ => None,
        })
    } else {
        None
    };
    json!({ "outcome": outcome, "credit": credit, "streak": Value::Null, "message": message })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_matrix() {
        // 活动没开：中性，不报失败也不报成功
        let before = Status::default();
        assert_eq!(decide(&before, &Status::default(), None), Outcome::NotEnabled);

        // 今日已签（账号维度）
        let before = Status { enable: true, checked_in: true, credits: 20, ..Default::default() };
        assert_eq!(
            decide(&before, &Status::default(), None),
            Outcome::AlreadyCheckedIn(Award { credits: 20, extra_credits: 0, credited: 20 })
        );

        // 领取被拒：码与文案原样带出
        let before = Status { enable: true, ..Default::default() };
        let claim = Status { code: CODE_REJECTED, message: "太多人".into(), ..Default::default() };
        assert_eq!(decide(&before, &claim, None), Outcome::Rejected(CODE_REJECTED, "太多人".into()));

        // 领取成功但设备维度回查没翻转 —— 不算成功
        let claim = Status::default();
        let after = Status { enable: true, ..Default::default() };
        assert_eq!(decide(&before, &claim, Some(&after)), Outcome::Unconfirmed);

        // 回查确认：数额按 credits 取，**不与 extra_credits 相加**
        let claim = Status { credits: 100, extra_credits: 100, ..Default::default() };
        let after = Status { enable: true, did_checked_in: true, ..Default::default() };
        assert_eq!(
            decide(&before, &claim, Some(&after)),
            Outcome::Claimed(Award { credits: 100, extra_credits: 100, credited: 100 })
        );
    }

    #[test]
    fn claim_code_zero_without_confirmation_is_not_success() {
        let row = complete(Outcome::Unconfirmed, "0123456789abcdef");
        assert_eq!(row["success"], false);
        assert_eq!(row["claimUnconfirmed"], true);
        // 文案不许出现「已签到 / 已领取」：编排层按子串判当日已办
        let message = row["msg"].as_str().unwrap_or_default();
        assert!(!message.contains("已领取"));
        assert!(!message.contains("已签到"));
    }

    #[test]
    fn report_translates_outcomes() {
        let claimed = report(&json!({"success": true, "msg": "签到成功", "awarded": 20}));
        assert_eq!(claimed["outcome"], "claimed");
        assert_eq!(claimed["credit"], "20");
        let done = report(&json!({"success": false, "alreadyCompleted": true, "msg": "今日已签到"}));
        assert_eq!(done["outcome"], "done");
        let inactive = report(&json!({"success": false, "msg": "国际版 Trae 没有签到通道（上游无此活动）"}));
        assert_eq!(inactive["outcome"], "ineligible");
        let failed = report(&json!({"success": false, "msg": "官方拒绝本次签到（9074）：x"}));
        assert_eq!(failed["outcome"], "failed");
    }

    #[test]
    fn probe_dispatch_follows_business_code() {
        assert_eq!(probe_for(CODE_OK), Probe::Accept);
        assert_eq!(probe_for(CODE_REJECTED), Probe::NextBody);
        assert_eq!(probe_for(CODE_TOKEN_DEAD), Probe::GiveUp);
        assert_eq!(probe_for(1234), Probe::NextScheme);
        assert!(needs_reauth(&json!({"code": CODE_TOKEN_DEAD})));
        assert!(needs_reauth(&json!({"msg": "we are not able to authenticate you"})));
        assert!(!needs_reauth(&json!({"code": 0, "msg": "ok"})));
    }
}
