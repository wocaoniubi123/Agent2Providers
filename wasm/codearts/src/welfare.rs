//! 每日福利（本家的「签到」）与新人注册礼。
//!
//! ── 上游那条链 ──────────────────────────────────────────────
//! ```text
//!   GET  /v1/ops/delivery?channel=IDE   活动清单（只读）
//!   POST /v1/ops/claim                  {campaignId, idempotentKey, channel:"IDE"}
//!   POST /v1/ops/confirm                {campaignId}
//!   GET  /v1/ops/delivery?channel=IDE   回读核实（`code:0` 只是受理）
//! ```
//! 三步缺一不可：**受理不等于到账**。只发 claim 就报「领取成功」，用户看到的是
//! 一次假的成功；服务端把 confirm 漏掉时积分永远不到账。
//!
//! ── 为什么台账必须存在 ──────────────────────────────────────
//! 一次性活动（新人礼）与每日活动的写请求都**不可重放**。台账记的是「今天试过
//! 几次、每笔的幂等键、哪些已经确认」，崩溃后重试据此仍打同一笔。所以：
//!   · 台账写不进去 ⇒ **不发写请求**（幂等键的意义就在于崩溃后重试还是同一笔）；
//!   · 台账读不懂（版本/日期/次数越界）⇒ 报错，不当作空台账重来 —— 那等于把上
//!     一轮的幂等键丢掉，上游会把重试当成**另一笔**领取。
//!
//! ── 限流只管「写」 ──────────────────────────────────────────
//! 读资格、判确认永远放行；每天最多 6 次写尝试、两次之间至少 10 分钟。用户在
//! 面板上主动点的那一次不受限流约束（`manual = true`），但资格仍每次重读。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::Credential;
use super::signer;
use super::upstream;

/// 三个端点。
pub const DELIVERY_PATH: &str = "/v1/ops/delivery?channel=IDE";
pub const CLAIM_PATH: &str = "/v1/ops/claim";
pub const CONFIRM_PATH: &str = "/v1/ops/confirm";
/// 台账版本（落盘契约：改版本等于让存量台账读不出来）。
pub const LEDGER_VERSION: i64 = 2;
/// 每天最多几次写尝试。
pub const MAX_ATTEMPTS_PER_DAY: i64 = 6;
/// 两次写尝试的最小间隔（毫秒）。
pub const MIN_ATTEMPT_GAP_MS: i64 = 10 * 60 * 1000;
/// 台账在宿主里的 kind（与网关版账号字段同名，便于人工对照）。
pub const LEDGER_KIND: &str = "codeartsWelfare";
/// 活动周期按北京时间零点算（上游如此），用固定偏移而不是时区名。
const DAY_ZONE_OFFSET_SECONDS: i64 = 8 * 60 * 60;
/// 新人注册礼的活动类。
const NEWBIE_KIND: &str = "NEW_USER_REGISTER";

/// 一个活动条目。
///
/// `id` 保持上游给的**原始 JSON**（字符串或数字都出现过）：发回 claim 时必须原样
/// 带回，转成字符串再发就会改变 JSON 类型。
#[derive(Clone, Debug, Default)]
pub struct Campaign {
    pub id: Value,
    pub kind: String,
    pub title: String,
    pub claimable: bool,
    pub status: String,
    pub benefit_amount: f64,
    pub benefit_unit: String,
}

impl Campaign {
    /// 活动标识的字符串形态（`123` 与 `"123"` 都算同一个活动）。空串 = 认不出，
    /// 认不出的条目**一律不自动领**（没有键就没法记台账，也没法回读确认）。
    pub fn key(&self) -> String {
        match &self.id {
            Value::String(text) => text.trim().to_string(),
            Value::Number(number) => number.to_string(),
            _ => String::new(),
        }
    }

    /// 官方口径的「已确认到账」：不可再领，且状态是 CONFIRMED / CONSUMED。
    pub fn is_confirmed(&self) -> bool {
        !self.claimable && (self.status == "CONFIRMED" || self.status == "CONSUMED")
    }

    /// 属于**可自动领**的那一类：每日登录送积分。
    ///
    /// 注册礼 / 学生礼 / 邀请礼都故意不自动领 —— 它们是一次性奖励，自动领等于替
    /// 用户做决定。
    pub fn is_daily_login_credit(&self) -> bool {
        self.kind == "USER_LOGIN" && self.benefit_unit == "CREDIT" && !self.key().is_empty()
    }

    /// 新人注册礼（每号只有一次）。
    pub fn is_newbie_gift(&self) -> bool {
        self.kind == NEWBIE_KIND && !self.key().is_empty()
    }

    /// 这一条还有活要干（可领，或已受理待确认）。
    pub fn has_work(&self) -> bool {
        self.claimable || self.status == "CLAIMED"
    }

    /// 面板展示用的中文标题（按 kind 翻，认不出回退上游原文）。
    ///
    /// 上游 `title` 是英文的（"Daily Check-in: Claim 1000 Credits"），面板是中文
    /// 界面，混着两行英文读起来是断裂的。金额不拼进标题：任务行右侧已有「+N」列。
    pub fn display_title(&self) -> String {
        let mapped = match self.kind.as_str() {
            "DAILY_CLAIM" => "每日签到",
            "USER_LOGIN" => "用户登录送积分",
            "NEW_USER_REGISTER" => "新用户注册礼",
            "STUDENT_CERTIFIED" => "学生认证",
            "INVITE_USER" => "邀请好友",
            _ => "",
        };
        if !mapped.is_empty() {
            return mapped.to_string();
        }
        if !self.title.trim().is_empty() {
            return self.title.clone();
        }
        self.kind.clone()
    }
}

/// 一次领取的结果。四种都有意义，别压成一个 bool。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 官方列表已回读确认到账
    Confirmed,
    /// 本来就已是 CONFIRMED / CONSUMED（不是失败，也不该报「领取成功」）
    Already,
    /// 这个账号没有可自动领的活动
    NotEligible,
    /// 被本地限流挡住（当天次数用尽或间隔不足）
    Skipped,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Confirmed => "官方已确认到账",
            Outcome::Already => "已领取并确认",
            Outcome::NotEligible => "暂无可领取活动",
            Outcome::Skipped => "等待重试",
        }
    }
}

/// 北京时间意义上的「今天」（`YYYY-MM-DD`）。
///
/// 用固定偏移而不是时区名：上游的活动周期就是 UTC+8 零点，为它带一份 tzdata
/// 不值得；而且宿主跑在 UTC 容器里时，「今天」也必须仍然是北京的那个今天。
pub fn today(now_ms: i64) -> String {
    let seconds = now_ms / 1000 + DAY_ZONE_OFFSET_SECONDS;
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|time| time.date_naive().format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// 一次 ops 请求：签名 GET/POST + `code == 0` 的 envelope 判定。
///
/// 头集合只有三项（`Content-Type` / `Agent-Type: PromptCenter` / `X-Language`），
/// 与目录、统计那两处都不同；区域 API 签名不带 Host。
fn welfare_request(method: &str, path: &str, body: Option<&Value>, credential: &Credential) -> Result<Value> {
    let url = format!("{}{path}", upstream::base());
    let payload = body
        .map(|value| value.to_string().into_bytes())
        .unwrap_or_default();
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Agent-Type".to_string(), "PromptCenter".to_string()),
        ("X-Language".to_string(), upstream::DEFAULT_LANGUAGE.to_string()),
    ];
    let signing = signer::Credential {
        access_key_id: credential.access_key_id.clone(),
        secret_access_key: credential.secret_access_key.clone(),
        security_token: credential.security_token.clone(),
        domain_id: credential.domain_id.clone(),
    };
    let signed = signer::sign(method, &url, &headers, &payload, &signing, false)
        .map_err(|reason| Error::http(500, format!("CodeArts 活动请求签名失败：{reason}")))?;
    let header_value = upstream::header_object(&signed);
    let response = match method {
        "POST" => sdk::http::open_raw("POST", &url, header_value, Some(&payload))?,
        _ => sdk::http::open("GET", &url, header_value, None)?,
    };
    let (status, body) = upstream::read_body(response, 128 * 1024)?;
    let text = String::from_utf8_lossy(&body).to_string();
    if status != 200 {
        let excerpt = super::redact::redact(&text, credential, false);
        return Err(Error::http(
            status,
            format!(
                "CodeArts 活动接口返回 HTTP {status}：{}",
                super::credentials::truncate_chars(excerpt.trim(), 300)
            ),
        ));
    }
    // `code` 缺失与 `code != 0` 同罪：**没确认成功就不能记为已领取**
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|_| Error::http(502, "CodeArts 活动接口响应不是合法 JSON，未记录为已领取"))?;
    match parsed.get("code").and_then(Value::as_i64) {
        Some(0) => {}
        other => {
            return Err(Error::http(
                502,
                format!("CodeArts 活动接口未确认成功（需要 code=0，实际 {other:?}），未记录为已领取"),
            ))
        }
    }
    Ok(parsed.get("data").cloned().unwrap_or(Value::Null))
}

/// 读活动列表。**缺少 `items` 判失败**（而不是当「今天没活动」）—— 上游换了形状
/// 时把「读不懂」显示成「没有活动」，用户会以为资格被取消了。
pub fn delivery(credential: &Credential) -> Result<Vec<Campaign>> {
    let data = welfare_request("GET", DELIVERY_PATH, None, credential)?;
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "CodeArts 活动列表响应缺少 items"))?;
    Ok(items
        .iter()
        .map(|item| Campaign {
            id: item.get("campaignId").cloned().unwrap_or(Value::Null),
            kind: item.get("type").and_then(Value::as_str).unwrap_or("").to_string(),
            title: item.get("title").and_then(Value::as_str).unwrap_or("").to_string(),
            claimable: item.get("claimable").and_then(Value::as_bool).unwrap_or(false),
            status: item.get("status").and_then(Value::as_str).unwrap_or("").to_string(),
            benefit_amount: item.get("benefitAmount").and_then(Value::as_f64).unwrap_or(0.0),
            benefit_unit: item.get("benefitUnit").and_then(Value::as_str).unwrap_or("").to_string(),
        })
        .collect())
}

/// 领一笔（`campaignId` 原样带回，不改类型）。
pub fn claim(credential: &Credential, campaign: &Campaign, idempotent_key: &str) -> Result<()> {
    let data = welfare_request(
        "POST",
        CLAIM_PATH,
        Some(&json!({
            "campaignId": campaign.id,
            "idempotentKey": idempotent_key,
            "channel": "IDE",
        })),
        credential,
    )?;
    // 响应里的活动 id 必须与请求的一致，否则**不进入确认阶段**：
    // 确认错活动会把别人的到账当成自己的
    let expected = campaign.key();
    let actual = Campaign {
        id: data.get("campaignId").cloned().unwrap_or(Value::Null),
        ..Campaign::default()
    }
    .key();
    if actual != expected || expected.is_empty() {
        return Err(Error::http(
            502,
            format!("CodeArts 领取响应活动 ID 不匹配（要 {expected}，回 {actual}），未进入确认阶段"),
        ));
    }
    Ok(())
}

/// 确认一笔。
pub fn confirm(credential: &Credential, campaign: &Campaign) -> Result<()> {
    welfare_request("POST", CONFIRM_PATH, Some(&json!({ "campaignId": campaign.id })), credential).map(|_| ())
}

// ── 台账 ─────────────────────────────────────────────────────

/// 一笔活动的进度。
#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub idempotent_key: String,
    pub claimed: bool,
    pub confirmed: bool,
}

/// 领取台账。
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    pub day: String,
    pub attempts: i64,
    pub last_attempt_ms: i64,
    pub accepted: bool,
    pub campaigns: Vec<(String, Progress)>,
}

impl Ledger {
    fn get(&self, key: &str) -> Option<&Progress> {
        self.campaigns.iter().find(|(name, _)| name == key).map(|(_, progress)| progress)
    }

    fn put(&mut self, key: &str, progress: Progress) {
        match self.campaigns.iter_mut().find(|(name, _)| name == key) {
            Some((_, slot)) => *slot = progress,
            None => self.campaigns.push((key.to_string(), progress)),
        }
    }

    fn from_value(value: &Value) -> Option<Ledger> {
        let day = value.get("day").and_then(Value::as_str)?.to_string();
        // 日期本身要能解析：一个读不懂的 day 不能当成「不是今天」
        chrono::NaiveDate::parse_from_str(&day, "%Y-%m-%d").ok()?;
        let attempts = value.get("attempts").and_then(Value::as_i64)?;
        if value.get("version").and_then(Value::as_i64)? != LEDGER_VERSION
            || !(0..=MAX_ATTEMPTS_PER_DAY).contains(&attempts)
        {
            return None;
        }
        let mut campaigns = Vec::new();
        if let Some(map) = value.get("campaigns").and_then(Value::as_object) {
            for (key, item) in map {
                campaigns.push((
                    key.clone(),
                    Progress {
                        idempotent_key: item
                            .get("idempotentKey")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        claimed: item.get("claimed").and_then(Value::as_bool).unwrap_or(false),
                        confirmed: item.get("confirmed").and_then(Value::as_bool).unwrap_or(false),
                    },
                ));
            }
        }
        Some(Ledger {
            day,
            attempts,
            last_attempt_ms: value.get("lastAttemptMs").and_then(Value::as_i64).unwrap_or(0).max(0),
            accepted: value.get("accepted").and_then(Value::as_bool).unwrap_or(false),
            campaigns,
        })
    }

    fn to_value(&self) -> Value {
        let mut campaigns = serde_json::Map::new();
        for (key, progress) in &self.campaigns {
            campaigns.insert(
                key.clone(),
                json!({
                    "idempotentKey": progress.idempotent_key,
                    "claimed": progress.claimed,
                    "confirmed": progress.confirmed,
                }),
            );
        }
        json!({
            "version": LEDGER_VERSION,
            "day": self.day,
            "attempts": self.attempts,
            "lastAttemptMs": self.last_attempt_ms,
            "accepted": self.accepted,
            "campaigns": Value::Object(campaigns),
        })
    }
}

/// 取台账并归一到「今天」。
///
/// ── 三种"读不出来"必须分开 ──────────────────────────────────
///   * **没有台账**（新账号）→ 从今天的空台账开始，正常；
///   * **有台账但读不懂**（版本不对 / 日期解析不出来 / attempts 越界）→ **报错，
///     一个写请求都不发**。当成空台账重来看着"自我修复"，实际是把上一轮的幂等键
///     丢了 —— 崩溃后重试会被上游当成**另一笔**领取；
///   * **台账日期在今天之后** → 报错。要么时钟倒退过，要么记录被手工改过。
fn ledger_of(now_ms: i64) -> Result<Ledger> {
    let day = today(now_ms);
    let fresh = || Ledger {
        day: day.clone(),
        ..Ledger::default()
    };
    let stored = match sdk::host("ledger.get", json!({ "kind": LEDGER_KIND })) {
        Ok(value) if value.is_object() => value,
        // 读不到（没有台账 / 宿主没有这条）一律当「新账号」：这不是错误分支
        _ => return Ok(fresh()),
    };
    let Some(ledger) = Ledger::from_value(&stored) else {
        return Err(Error::http(
            500,
            "CodeArts 领取台账无效，未发送领取请求（请先在账号页删除并重新添加该账号）",
        ));
    };
    match ledger.day.cmp(&day) {
        std::cmp::Ordering::Equal => Ok(ledger),
        // 新的一天：整份重来（昨天的 attempts / 幂等键与今天无关）
        std::cmp::Ordering::Less => Ok(fresh()),
        std::cmp::Ordering::Greater => Err(Error::http(
            500,
            format!("系统日期（{day}）早于领取记录（{}），先纠正时钟再领取", ledger.day),
        )),
    }
}

/// 落一份台账（失败即报错 —— 调用方据此**不往下发写请求**）。
fn save_ledger(ledger: &Ledger) -> Result<()> {
    sdk::host("ledger.put", json!({ "kind": LEDGER_KIND, "value": ledger.to_value() }))
        .map(|_| ())
        .map_err(|error| Error::http(502, format!("领取台账落盘失败：{}", error.message)))
}

/// 两次写尝试之间的剩余等待（None = 没在等）。
///
/// 全程 saturating：`lastAttemptMs` 是从账号记录里读出来的（可以被导入 / 手工
/// 编辑），一个极端值不该让减法绕回一个看起来"早就不等了"的小数。
pub fn gap_remaining(ledger: &Ledger, now_ms: i64) -> Option<i64> {
    if ledger.last_attempt_ms == 0 {
        return None;
    }
    let elapsed = now_ms.saturating_sub(ledger.last_attempt_ms);
    if elapsed >= MIN_ATTEMPT_GAP_MS {
        None
    } else {
        Some(MIN_ATTEMPT_GAP_MS.saturating_sub(elapsed))
    }
}

// ── 对外入口 ─────────────────────────────────────────────────

/// 只读预览（面板上「先看一眼」那一步）：**一个写请求都不发**。
pub fn preview(now_ms: i64) -> Result<Value> {
    let credential = super::credentials::ensure(false)?;
    let items = delivery(&credential)?;
    let daily: Vec<&Campaign> = items.iter().filter(|item| item.is_daily_login_credit()).collect();
    let ledger = ledger_of(now_ms)?;
    Ok(json!({
        "day": ledger.day,
        "attempts": ledger.attempts,
        "attemptsLeft": (MAX_ATTEMPTS_PER_DAY - ledger.attempts).max(0),
        "nextAttemptInMs": gap_remaining(&ledger, now_ms).unwrap_or(0),
        "acceptedToday": ledger.accepted,
        "campaigns": daily
            .iter()
            .map(|item| json!({
                "id": item.key(),
                "status": item.status,
                "claimable": item.claimable,
                "benefitAmount": item.benefit_amount,
                "benefitUnit": item.benefit_unit,
                "confirmed": item.is_confirmed(),
                "localClaimed": ledger.get(&item.key()).map(|p| p.claimed).unwrap_or(false),
            }))
            .collect::<Vec<_>>(),
        "eligible": daily.iter().any(|item| item.has_work()),
        "note": "领取到账的是套餐赠送积分，不增加福利模型 token 池",
    }))
}

/// 一次领取流程的结果。
///
/// native 版还带 `before` / `after` 两份活动清单；本实现的回读确认已经在
/// [`claim_rewards`] 内部完成（不确认就返回错误），调用方只需要结论。
pub struct Run {
    pub outcome: Outcome,
}

/// 每日福利领取（`checkin.claim` 与 `admin.action = welfare.claim` 共用）。
///
/// `manual = true`（用户在面板上点）时**不受本地限流约束**：限流保护的是「无人
/// 值守的自动重试」，用户主动看一眼不该被一句「等待重试」挡回去 —— 但资格仍每次
/// 重读。
pub fn claim_rewards(now_ms: i64, manual: bool, newbie: bool) -> Result<Run> {
    let credential = super::credentials::ensure(false)?;
    let mut ledger = ledger_of(now_ms)?;
    let items = delivery(&credential)?;
    let picked: Vec<Campaign> = items
        .into_iter()
        .filter(|item| if newbie { item.is_newbie_gift() } else { item.is_daily_login_credit() })
        .collect();
    let label = if newbie { "新人注册礼" } else { "每日福利" };
    // 四个提前返回都走「台账不动、不发写请求」那条路
    if picked.is_empty() {
        return Ok(Run { outcome: Outcome::NotEligible });
    }
    if picked.iter().all(Campaign::is_confirmed) {
        return Ok(Run { outcome: Outcome::Already });
    }
    // 限流只管**写**：读资格、判确认永远放行
    if !manual
        && (ledger.attempts >= MAX_ATTEMPTS_PER_DAY || gap_remaining(&ledger, now_ms).is_some())
    {
        return Ok(Run { outcome: Outcome::Skipped });
    }
    if !picked.iter().any(Campaign::has_work) {
        return Ok(Run { outcome: Outcome::NotEligible });
    }

    ledger.attempts = ledger.attempts.saturating_add(1).min(MAX_ATTEMPTS_PER_DAY);
    ledger.last_attempt_ms = now_ms;
    ledger.accepted = false;
    // 台账写不进去就**不能往下发写请求**（幂等键只存在于这份台账里）
    save_ledger(&ledger)?;

    for item in &picked {
        let id = item.key();
        if item.is_confirmed() {
            continue;
        }
        let mut progress = ledger.get(&id).cloned().unwrap_or_default();
        if item.status == "CLAIMED" {
            progress.claimed = true;
        }
        if !progress.claimed && item.claimable {
            if progress.idempotent_key.is_empty() {
                progress.idempotent_key = format!("claim_{id}_{now_ms}");
            }
            ledger.put(&id, progress.clone());
            // 键先落盘再发写请求
            save_ledger(&ledger)?;
            claim(&credential, item, &progress.idempotent_key)?;
            progress.claimed = true;
            ledger.put(&id, progress.clone());
            save_ledger(&ledger)?;
        }
        if progress.claimed {
            ledger.put(&id, progress.clone());
            confirm(&credential, item)?;
        }
    }

    // 回读二次确认：`code:0` 只是受理
    let verified = delivery(&credential)?;
    for item in picked.iter().filter(|item| item.has_work()) {
        let id = item.key();
        let confirmed = verified
            .iter()
            .any(|seen| seen.key() == id && seen.kind == item.kind && seen.is_confirmed());
        if !confirmed {
            return Err(Error::http(
                502,
                format!("{label}请求已提交，但官方活动列表尚未确认到账；将重试确认，不显示领取成功"),
            ));
        }
        let mut progress = ledger.get(&id).cloned().unwrap_or_default();
        progress.confirmed = true;
        ledger.put(&id, progress);
    }
    ledger.accepted = true;
    save_ledger(&ledger)?;
    Ok(Run { outcome: Outcome::Confirmed })
}

/// `checkin.claim`：映射成宿主认得的四档结论。
///
/// 映射必须与网关的 `checkin_completed_today` / `claim_pending` 口径对齐：
///   · `Confirmed` → `claimed`：今天真领到了；
///   · `Already` → `done`：上游说今天已经领过；
///   · `NotEligible` / `Skipped` → `inactive`：暂无可领取活动（中性未领取）。
pub fn checkin() -> Result<Value> {
    let now = sdk::now();
    let run = claim_rewards(now, false, false)?;
    let (outcome, retry_at) = match run.outcome {
        Outcome::Confirmed => ("claimed", Value::Null),
        Outcome::Already => ("done", Value::Null),
        Outcome::Skipped => {
            let ledger = ledger_of(now).ok();
            let wait = ledger
                .as_ref()
                .and_then(|ledger| gap_remaining(ledger, now))
                .unwrap_or(MIN_ATTEMPT_GAP_MS);
            ("inactive", Value::from(now.saturating_add(wait)))
        }
        Outcome::NotEligible => ("inactive", Value::from(now.saturating_add(10 * 60 * 1000))),
    };
    Ok(json!({
        "outcome": outcome,
        "message": run.outcome.label(),
        "credit": Value::Null,
        "streak": Value::Null,
        "retryAt": retry_at,
    }))
}

/// 读一次余额（领完顺手回读：面板上「领到了」与「积分确实变了」是两件事）。
pub fn refresh_usage() -> Value {
    match usage_snapshot() {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

fn usage_snapshot() -> Result<Value> {
    let credential = super::credentials::ensure(false)?;
    let statistics = super::usage::fetch(&credential)?;
    Ok(super::usage::usage_document(Some(&statistics)))
}

// ── 新人注册礼 ───────────────────────────────────────────────

/// 新人礼任务清单（`claim.status` 的实现）。
pub fn tasks() -> Result<Value> {
    let credential = super::credentials::ensure(false)?;
    let items = delivery(&credential)?;
    let rows: Vec<Value> = items
        .iter()
        .filter(|item| item.is_newbie_gift())
        .map(|item| {
            json!({
                "id": item.key(),
                "title": item.display_title(),
                "status": if item.is_confirmed() { "done" } else if item.claimable { "claimable" } else { "pending" },
                "claimable": item.claimable,
                "amount": item.benefit_amount,
                "unit": item.benefit_unit,
                "note": "一次性奖励：领一次就没了，且到账的是套餐赠送积分（不增加福利模型 token 池）",
            })
        })
        .collect();
    let unclaimed = rows
        .iter()
        .filter(|row| row["claimable"].as_bool() == Some(true))
        .count();
    Ok(json!({
        "tasks": rows,
        "unclaimed": unclaimed,
        "allSettled": unclaimed == 0,
    }))
}

/// 一键领取新人礼（`claim` 的实现）。
pub fn claim_newbie() -> Result<Value> {
    let now = sdk::now();
    let run = claim_rewards(now, true, true)?;
    Ok(json!({
        "result": run.outcome.label(),
        "confirmed": matches!(run.outcome, Outcome::Confirmed),
        "tasks": tasks()?,
        "note": "新人注册礼是一次性奖励，领早了撤不回",
    }))
}
