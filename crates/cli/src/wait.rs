//! `wharf wait`：阻塞到某件事发生再返回，AI 不用自己反复轮询。
//! 每 5 秒查一次，进度打到标准错误；条件满足退出码 0，超时退出码 1。

use std::time::{Duration, Instant};

use serde_json::json;
use wharf_api_types::{
  ApiError,
  view::{
    Actual, CheckStatus, DoctorReport, Health, ServiceView, Status,
  },
};

use crate::{
  WaitCmd,
  client::{CliResult, Client},
  print,
};

const INTERVAL: Duration = Duration::from_secs(5);

/// `10m`、`90s`、`1h`，纯数字按秒。
pub fn parse_timeout(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let (num, unit) = match s.char_indices().last() {
    Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
    _ => (s, 's'),
  };
  let invalid = || format!("时长 {s} 看不懂，写成 90s、10m 或 1h");
  let n: u64 = num.parse().map_err(|_| invalid())?;
  let multiplier = match unit {
    's' => 1,
    'm' => 60,
    'h' => 3600,
    _ => return Err(invalid()),
  };
  let secs = n.checked_mul(multiplier).ok_or_else(invalid)?;
  Ok(Duration::from_secs(secs))
}

/// 一次检查的结果：满足了没有，以及现在的情况（一句话）。
type Check = (bool, String);

async fn check(c: &Client, cmd: &WaitCmd) -> CliResult<Check> {
  Ok(match cmd {
    WaitCmd::Service { name, .. } => {
      let v: ServiceView = c
        .get(&format!("/api/services/{}", crate::client::seg(name)))
        .await?;
      let Some(st) = v.status else {
        return Ok((false, "还查不到现状".into()));
      };
      let synced = match (&st.desired_hash, &st.actual_hash) {
        (Some(d), Some(a)) => d == a,
        _ => true,
      };
      let ok = if st.want_running {
        st.actual == Actual::Running
          && matches!(st.health, Health::Healthy | Health::None)
          && synced
      } else {
        st.actual == Actual::Stopped
      };
      (ok, st.summary)
    }
    WaitCmd::Route { hostname, .. } => {
      let v: DoctorReport = c
        .get(&format!(
          "/api/doctor?host={}",
          crate::client::seg(hostname)
        ))
        .await?;
      let bad: Vec<String> = v
        .routes
        .iter()
        .flat_map(|r| &r.checks)
        .filter(|ch| ch.status == CheckStatus::Bad)
        .map(|ch| format!("{}：{}", ch.layer, ch.detail))
        .collect();
      if bad.is_empty() {
        (true, "各层都通".into())
      } else {
        (false, bad.join("；"))
      }
    }
    WaitCmd::Clear { subject, .. } => {
      let v: Status = c.get("/api/status").await?;
      let open: Vec<String> = v
        .issues
        .iter()
        .filter(|i| match subject {
          None => true,
          Some(s) => i.subject.as_ref().is_some_and(|x| {
            &x.name == s || format!("{}/{}", x.kind, x.name) == *s
          }),
        })
        .map(|i| i.title.clone())
        .collect();
      if open.is_empty() {
        (true, "没有需要注意的事".into())
      } else {
        (false, open.join("；"))
      }
    }
  })
}

pub async fn run(c: &Client, cmd: WaitCmd, j: bool) -> CliResult<()> {
  let timeout = match &cmd {
    WaitCmd::Service { timeout, .. }
    | WaitCmd::Route { timeout, .. }
    | WaitCmd::Clear { timeout, .. } => {
      parse_timeout(timeout).map_err(ApiError::invalid)?
    }
  };
  let start = Instant::now();
  let mut last = String::new();
  loop {
    let (ok, now) = check(c, &cmd).await?;
    if now != last {
      eprintln!("{}s  {now}", start.elapsed().as_secs());
      last = now.clone();
    }
    if ok {
      if j {
        print::json(
          &json!({ "met": true, "state": now, "waited_secs": start.elapsed().as_secs() }),
        );
      }
      return Ok(());
    }
    if start.elapsed() + INTERVAL > timeout {
      if j {
        print::json(
          &json!({ "met": false, "state": now, "waited_secs": start.elapsed().as_secs() }),
        );
      }
      return Err(
        ApiError::invalid(format!("等了 {} 秒还没满足：{now}", start.elapsed().as_secs()))
          .with_hint("看现状再决定：wharf service show / wharf doctor / wharf status")
          .into(),
      );
    }
    tokio::time::sleep(INTERVAL).await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_timeouts() {
    assert_eq!(parse_timeout("90s"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_timeout("10m"), Ok(Duration::from_secs(600)));
    assert_eq!(parse_timeout("30"), Ok(Duration::from_secs(30)));
    assert!(parse_timeout("1d").is_err());
  }
}
