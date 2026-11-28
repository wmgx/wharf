//! 5 段 cron（分 时 日 月 周），按北京时间算。支持 `*`、`a-b`、`a,b`、`*/n`、`a-b/n`；
//! 周的 0 和 7 都是周日。日和周都不是 `*` 时，满足其一即可（和 crontab 一样）。

use chrono::{
  DateTime, Datelike, Duration, FixedOffset, Months, Timelike, Utc,
};
use wharf_api_types::ApiError;

const ALL_DOM: u64 = ((1 << 32) - 1) & !1;
const ALL_DOW: u64 = (1 << 7) - 1;

fn has(set: u64, value: u32) -> bool {
  set & (1 << value) != 0
}

pub struct Cron {
  offset: FixedOffset,
  minute: u64,
  hour: u64,
  dom: u64,
  month: u64,
  dow: u64,
  dom_any: bool,
  dow_any: bool,
}

impl Cron {
  pub fn parse(s: &str) -> Result<Cron, ApiError> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let [mi, h, d, mo, w] = parts.as_slice() else {
      return Err(
        ApiError::invalid(format!(
          "cron 要 5 段（分 时 日 月 周）：{s}"
        ))
        .with_hint("例如 `30 3 * * *` 是每天 3:30"),
      );
    };
    let mut dow = field(w, 0, 7)?;
    if dow & (1 << 7) != 0 {
      dow |= 1;
    }
    dow &= ALL_DOW;
    let dom = field(d, 1, 31)?;
    let month = field(mo, 1, 12)?;
    let dow_any = dow == ALL_DOW;
    let month_days = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if dow_any
      && !month_days.iter().enumerate().any(|(i, days)| {
        has(month, i as u32 + 1)
          && (1..=*days).any(|day| has(dom, day))
      })
    {
      return Err(ApiError::invalid("cron 指定的月和日永远不会出现"));
    }
    Ok(Cron {
      offset: beijing(),
      minute: field(mi, 0, 59)?,
      hour: field(h, 0, 23)?,
      dom,
      month,
      dow,
      dom_any: dom == ALL_DOM,
      dow_any,
    })
  }

  pub(crate) fn with_offset(mut self, offset: FixedOffset) -> Self {
    self.offset = offset;
    self
  }

  /// 这一分钟是否到点。
  pub fn matches(&self, t: DateTime<Utc>) -> bool {
    let t = t.with_timezone(&self.offset);
    has(self.minute, t.minute())
      && has(self.hour, t.hour())
      && has(self.month, t.month())
      && self.matches_day(t.day(), t.weekday().num_days_from_sunday())
  }

  fn matches_day(&self, day: u32, weekday: u32) -> bool {
    let dom = has(self.dom, day);
    let dow = has(self.dow, weekday);
    match (self.dom_any, self.dow_any) {
      (true, true) => true,
      (true, false) => dow,
      (false, true) => dom,
      (false, false) => dom || dow,
    }
  }

  pub fn prev_at_or_before(
    &self,
    at: DateTime<Utc>,
    max_lookback_mins: u32,
  ) -> Option<DateTime<Utc>> {
    let at = minute_floor(at);
    (0..=i64::from(max_lookback_mins.min(1440)))
      .map(|n| at - Duration::minutes(n))
      .find(|t| self.matches(*t))
  }

  /// `after` 之后（不含这一分钟）第一次到点的时间。
  pub fn next_after(
    &self,
    after: DateTime<Utc>,
  ) -> Option<DateTime<Utc>> {
    let start =
      minute_floor(after).checked_add_signed(Duration::minutes(1))?;
    let mut t = start.with_timezone(&self.offset).naive_local();
    let limit = t.checked_add_months(Months::new(48))?;
    while t <= limit {
      let midnight = || t.date().and_hms_opt(0, 0, 0);
      if !has(self.month, t.month()) {
        t = midnight()?
          .with_day(1)?
          .checked_add_months(Months::new(1))?;
      } else if !self
        .matches_day(t.day(), t.weekday().num_days_from_sunday())
      {
        t = midnight()?.checked_add_signed(Duration::days(1))?;
      } else if !has(self.hour, t.hour()) {
        t =
          t.with_minute(0)?.checked_add_signed(Duration::hours(1))?;
      } else if let Some(minute) =
        (t.minute()..60).find(|minute| has(self.minute, *minute))
      {
        return t
          .with_minute(minute)?
          .and_local_timezone(self.offset)
          .single()
          .map(|t| t.to_utc());
      } else {
        t =
          t.with_minute(0)?.checked_add_signed(Duration::hours(1))?;
      }
    }
    None
  }

  pub fn prev_before(
    &self,
    before: DateTime<Utc>,
  ) -> Option<DateTime<Utc>> {
    let mut t = minute_floor(before);
    if t == before {
      t -= Duration::minutes(1);
    }
    for _ in 0..366 * 24 * 60 {
      if self.matches(t) {
        return Some(t);
      }
      t -= Duration::minutes(1);
    }
    None
  }
}

pub fn minute_floor(t: DateTime<Utc>) -> DateTime<Utc> {
  t.with_second(0)
    .and_then(|t| t.with_nanosecond(0))
    .unwrap_or(t)
}

fn beijing() -> FixedOffset {
  FixedOffset::east_opt(8 * 3600).expect("固定时区")
}

/// 一段转成位集合。
fn field(s: &str, lo: u32, hi: u32) -> Result<u64, ApiError> {
  let bad = || {
    ApiError::invalid(format!(
      "cron 写法不对：`{s}`（范围 {lo}-{hi}）"
    ))
  };
  let mut set = 0u64;
  for part in s.split(',') {
    let (range, step) = match part.split_once('/') {
      Some((r, n)) => {
        (r, n.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(bad)?)
      }
      None => (part, 1),
    };
    let (a, b) = if range == "*" {
      (lo, hi)
    } else if let Some((a, b)) = range.split_once('-') {
      (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?)
    } else {
      let v: u32 = range.parse().map_err(|_| bad())?;
      // `5/10` 表示从 5 开始每 10。
      (v, if part.contains('/') { hi } else { v })
    };
    if a < lo || b > hi || a > b {
      return Err(bad());
    }
    for v in (a..=b).step_by(step as usize) {
      set |= 1 << v;
    }
  }
  Ok(set)
}

#[cfg(test)]
mod tests {
  use chrono::TimeZone;

  use super::*;

  fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
    beijing()
      .with_ymd_and_hms(y, mo, d, h, mi, 0)
      .unwrap()
      .to_utc()
  }

  #[test]
  fn cron_dom_any_impossible_date_and_jump() {
    let monday = Cron::parse("0 3 */1 * 1").unwrap();
    assert!(!monday.matches(at(2026, 11, 10, 3, 0)));
    assert!(monday.matches(at(2026, 11, 9, 3, 0)));
    assert!(Cron::parse("0 0 31 2 *").is_err());
    assert_eq!(
      Cron::parse("0 0 29 2 *")
        .unwrap()
        .next_after(at(2028, 2, 29, 0, 0)),
      Some(at(2032, 2, 29, 0, 0))
    );
  }

  #[test]
  fn schedules() {
    let daily = Cron::parse("30 3 * * *").unwrap();
    assert!(daily.matches(at(2026, 11, 7, 3, 30)));
    assert!(!daily.matches(at(2026, 11, 7, 4, 30)));
    assert_eq!(
      daily.next_after(at(2026, 11, 7, 3, 30)),
      Some(at(2026, 11, 8, 3, 30))
    );
    // 2026-11-08 是周日；日和周都写了时满足其一。
    let either = Cron::parse("0 9 1 * 7").unwrap();
    assert!(either.matches(at(2026, 11, 8, 9, 0)));
    assert!(either.matches(at(2026, 12, 1, 9, 0)));
    assert!(!either.matches(at(2026, 11, 9, 9, 0)));
    let every = Cron::parse("*/15 8-10 * * 1-5").unwrap();
    assert!(every.matches(at(2026, 11, 9, 10, 45)));
    assert!(!every.matches(at(2026, 11, 9, 10, 50)));
    assert!(Cron::parse("60 * * * *").is_err());
    assert!(Cron::parse("* * *").is_err());
  }
}
