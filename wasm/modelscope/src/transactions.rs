//! 魔粒发放流水。上游按北京日期聚合，签到确认必须有 `daily_active` 发放记录。
//!
//! ── 三条实测口径（改解析前先读）──────────────────────────────
//!   1. `GET /openapi/v1/magicubes/transactions?page=1&page_size=50` 返回
//!      `data.records`；
//!   2. **同一页可混有消耗（`SPEND`）和过期记录**，不能只凭请求参数认定每行
//!      都是发放 —— 必须逐行看 `type == "EARN"`；
//!   3. 日常领取金额还包含 `aliyun_bindlogin`（绑定登录奖励），**不能把它单独
//!      当成签到完成凭据**：签到完成的判据只有 `rule_key == "daily_active"`
//!      且金额 > 0（见 [`Transactions::signed_on`]）。

use agent2api_wasm_sdk::{json, Error, Result, Value};
use chrono::{NaiveDate, NaiveDateTime};

use super::{time, upstream};

const PATH: &str = "/openapi/v1/magicubes/transactions";
const PAGE_SIZE: usize = 50;
/// 翻页上限：10 页 × 50 条 = 500 条。实测当天流水远小于这个数；
/// 读满还没到更早日期时，结果按「未读全」处理（见 `complete`）。
const MAX_PAGES: usize = 10;

/// 一条发放记录。
pub struct Grant {
    /// 北京日期键（`YYYY-MM-DD`）
    pub day: String,
    /// 上游的规则键（`daily_active` / `aliyun_bindlogin` / …）
    pub rule: String,
    /// 展示名
    pub title: String,
    pub amount: Option<f64>,
    pub expires_at: Option<i64>,
}

impl Grant {
    /// 算不算「日常」发放（签到金额只统计这两类）。
    pub fn is_daily(&self) -> bool {
        matches!(self.rule.as_str(), "daily_active" | "aliyun_bindlogin")
    }

    /// 一行领取明细（进 `usage.query` 的 `credits[]`）。
    pub fn credit_row(&self) -> Value {
        json!({
            "name": self.title,
            "record": true,
            "amount": self.amount,
            "unit": "魔粒",
            "expireAt": self.expires_at,
        })
    }
}

/// 一次流水读取的结果。
pub struct Transactions {
    pub grants: Vec<Grant>,
    /// 原始响应（进 `usage.query` 的 `raw.transactions`）
    pub raw: Vec<Value>,
    /// 当日记录是否**已经读全**：只有读全了才能用总额判断「今天签没签到」。
    pub complete: bool,
}

impl Transactions {
    /// 某一天的发放合计；任一金额读不出来就给 None（不拿残缺数据充数）。
    pub fn total_on(&self, day: &str, daily_only: bool) -> Option<f64> {
        let mut total = 0.0;
        for grant in self
            .grants
            .iter()
            .filter(|grant| grant.day == day && (!daily_only || grant.is_daily()))
        {
            total += grant.amount?;
        }
        total.is_finite().then_some(total)
    }

    /// 这一天是不是已经签到（`daily_active` 且金额 > 0）。
    pub fn signed_on(&self, day: &str) -> bool {
        self.grants.iter().any(|grant| {
            grant.day == day
                && grant.rule == "daily_active"
                && grant.amount.is_some_and(|amount| amount > 0.0)
        })
    }

    /// 签到前后两次读数的日常发放差额（读不全或没涨都给 None）。
    pub fn daily_increase(&self, before: &Self, day: &str) -> Option<f64> {
        if !self.complete || !before.complete {
            return None;
        }
        let gained = self.total_on(day, true)? - before.total_on(day, true)?;
        (gained.is_finite() && gained > 0.0).then_some(gained)
    }
}

/// 读当天（必要时翻页）的发放流水。
pub fn read(token: &str, day: &str) -> Result<Transactions> {
    let mut result = Transactions {
        grants: Vec::new(),
        raw: Vec::new(),
        complete: false,
    };
    for page in 1..=MAX_PAGES {
        let payload = upstream::site_json(
            token,
            &format!("{PATH}?page={page}&page_size={PAGE_SIZE}"),
            "魔粒发放记录查询",
        )?;
        let data = upstream::data_of(&payload);
        let records = match data.get("records") {
            Some(Value::Array(records)) => records.as_slice(),
            _ => {
                return Err(Error::http(
                    502,
                    "魔粒发放记录的响应格式无法识别",
                ))
            }
        };
        // 先整体校验再取数：缺日期或缺类型的行意味着判据本身不可信，
        // 这时候挑着读会得出「今天没签到」这种假结论。
        for record in records {
            if date_of(record).is_none() || text(record, "type").is_empty() {
                return Err(Error::http(
                    502,
                    "魔粒流水缺少有效的日期或类型，无法确认当日发放",
                ));
            }
        }
        // 流水按日期倒序；到达更早日期后，当日记录已读全。
        let reached_previous_day = records
            .iter()
            .any(|record| date_of(record).is_some_and(|date| date.as_str() < day));
        let count = records.len();
        for record in records {
            if text(record, "type") != "EARN" {
                continue;
            }
            let Some(date) = date_of(record) else { continue };
            if date != day {
                continue;
            }
            result.grants.push(Grant {
                day: date,
                rule: text(record, "rule_key").to_string(),
                title: match text(record, "title") {
                    "" => "魔粒发放".to_string(),
                    title => title.to_string(),
                },
                amount: number(record, "total_amount").filter(|amount| *amount >= 0.0),
                expires_at: text_time_ms(text(record, "expire_at")),
            });
        }
        result.raw.push(payload);
        if count < PAGE_SIZE || reached_previous_day {
            result.complete = true;
            break;
        }
    }
    result
        .grants
        .sort_by_key(|grant| grant.expires_at.unwrap_or(i64::MAX));
    Ok(result)
}

/// 取一个数字字段；数字与数字字符串都认，非有限值一律丢弃。
pub fn number(value: &Value, key: &str) -> Option<f64> {
    let raw = value.get(key)?;
    raw.as_f64()
        .or_else(|| raw.as_str()?.trim().parse().ok())
        .filter(|number| number.is_finite())
}

/// 取一个文本字段（去首尾空白）。
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
}

/// `gmt_created` 的日期部分（`YYYY-MM-DD`）；解析不出来给 None。
fn date_of(record: &Value) -> Option<String> {
    let text = text(record, "gmt_created");
    let date = text.split([' ', 'T']).next()?;
    NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .ok()
        .map(|date| date.to_string())
}

/// `YYYY-MM-DD HH:MM:SS`（北京时间）→ 毫秒时间戳。
fn text_time_ms(text: &str) -> Option<i64> {
    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S")
        .ok()?
        .and_local_timezone(time::offset())
        .single()
        .map(|time| time.timestamp_millis())
}

/// 金额文案：最多 4 位小数，去掉尾随零与落单的小数点（`12.5000` → `12.5`）。
pub fn amount_text(amount: f64) -> String {
    format!("{amount:.4}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(day: &str, rule: &str, amount: Option<f64>) -> Grant {
        Grant {
            day: day.to_string(),
            rule: rule.to_string(),
            title: "魔粒发放".to_string(),
            amount,
            expires_at: None,
        }
    }

    /// 签到完成只认 `daily_active` 且金额 > 0；`aliyun_bindlogin` 不算。
    #[test]
    fn only_a_positive_daily_active_proves_the_checkin() {
        let ledger = Transactions {
            grants: vec![
                grant("2026-11-19", "aliyun_bindlogin", Some(50.0)),
                grant("2026-11-19", "daily_active", Some(0.0)),
            ],
            raw: Vec::new(),
            complete: true,
        };
        assert!(!ledger.signed_on("2026-11-19"));
        assert!(!ledger.signed_on("2026-11-18"));
        assert_eq!(Some(50.0), ledger.total_on("2026-11-19", true));
        assert_eq!(Some(50.0), ledger.total_on("2026-11-19", false));
    }

    /// 金额缺失时合计给 None（不拿残缺数据充数）。
    #[test]
    fn a_missing_amount_makes_the_total_unknown() {
        let ledger = Transactions {
            grants: vec![
                grant("2026-11-19", "daily_active", Some(10.0)),
                grant("2026-11-19", "daily_active", None),
            ],
            raw: Vec::new(),
            complete: true,
        };
        assert_eq!(None, ledger.total_on("2026-11-19", true));
        assert!(ledger.signed_on("2026-11-19"), "签到只看有没有一条正数记录");
    }

    /// 前后差额：读不全或没涨都给 None。
    #[test]
    fn the_increase_needs_two_complete_readings() {
        let before = Transactions {
            grants: vec![grant("2026-11-19", "daily_active", Some(10.0))],
            raw: Vec::new(),
            complete: true,
        };
        let after = Transactions {
            grants: vec![grant("2026-11-19", "daily_active", Some(25.0))],
            raw: Vec::new(),
            complete: true,
        };
        assert_eq!(Some(15.0), after.daily_increase(&before, "2026-11-19"));

        let incomplete = Transactions {
            grants: Vec::new(),
            raw: Vec::new(),
            complete: false,
        };
        assert_eq!(None, after.daily_increase(&incomplete, "2026-11-19"));
    }

    /// 金额文案去尾零，整数不留小数点。
    #[test]
    fn the_amount_text_trims_trailing_zeroes() {
        assert_eq!("12.5", amount_text(12.5));
        assert_eq!("12", amount_text(12.0));
        assert_eq!("0.25", amount_text(0.25));
    }

    /// 日期与时间的解析。
    #[test]
    fn the_date_and_the_expiry_are_parsed_in_beijing_time() {
        let record = json!({ "gmt_created": "2026-11-19 08:30:00" });
        assert_eq!(Some("2026-11-19".to_string()), date_of(&record));
        // 北京时间 09:30 == UTC 01:30 == 2026-11-19T00:00:00Z + 5400 秒
        assert_eq!(Some(1_795_051_800_000), text_time_ms("2026-11-19 09:30:00"));
        assert_eq!(None, text_time_ms("2026-11-19"));
    }
}
