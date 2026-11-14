//! 域名注册到期和服务器续费日提醒。RDAP 结果只缓存在内存里。

use std::{
  collections::{BTreeMap, BTreeSet},
  net::IpAddr,
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use wharf_api_types::{
  ApiError,
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::{rules, snapshot, state::AppState};

#[derive(Clone)]
struct Entry {
  expires: Option<DateTime<Utc>>,
  checked_at: i64,
}

static CACHE: Mutex<BTreeMap<String, Entry>> =
  Mutex::new(BTreeMap::new());
static DAYS: Mutex<BTreeMap<String, i64>> =
  Mutex::new(BTreeMap::new());

fn candidates(host: &str) -> Vec<String> {
  let host = host.trim_end_matches('.').to_lowercase();
  if host.parse::<IpAddr>().is_ok()
    || [
      "local", "internal", "lan", "localhost", "ts.net",
      "sslip.io", "nip.io",
    ]
    .iter()
    .any(|s| host == *s || host.ends_with(&format!(".{s}")))
  {
    return vec![];
  }
  let parts: Vec<_> = host.split('.').collect();
  (0..parts.len().saturating_sub(1))
    .map(|i| parts[i..].join("."))
    .collect()
}

fn parse_expiry(body: &serde_json::Value) -> Option<DateTime<Utc>> {
  body.get("events")?.as_array()?.iter().find_map(|e| {
    if e.get("eventAction")?.as_str()? != "expiration" {
      return None;
    }
    DateTime::parse_from_rfc3339(e.get("eventDate")?.as_str()?)
      .ok()
      .map(|t| t.with_timezone(&Utc))
  })
}

fn days_until(date: &str, today: NaiveDate) -> Option<i64> {
  Some(
    (NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()? - today)
      .num_days(),
  )
}

pub fn expires_of(host: &str) -> Option<DateTime<Utc>> {
  let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
  candidates(host)
    .iter()
    .find_map(|h| cache.get(h).and_then(|e| e.expires))
}

pub fn issues() -> Vec<Issue> {
  let mut firing = BTreeMap::new();
  for (rule, urgent) in
    [("expiry_soon", false), ("expiry_urgent", true)]
  {
    for (subject, title) in rules::firing_subjects(rule) {
      firing.insert(subject, (urgent, title));
    }
  }
  let days = DAYS.lock().unwrap_or_else(|e| e.into_inner());
  firing.into_iter().filter_map(|(s, (urgent, title))| {
    let (kind, name) = s.split_once(':')?;
    let domain = kind == "domain";
    let title = days.get(&s).map_or(title, |n| {
      match (domain, *n < 0) {
        (true, true) => format!("域名 {name} 已经到期"),
        (false, true) => format!("服务器 {name} 的续费日已过"),
        (true, false) => format!("域名 {name} 还有 {n} 天到期"),
        (false, false) => format!("服务器 {name} 还有 {n} 天到期"),
      }
    });
    Some(Issue {
      code: if domain { "domain_expiring" } else { "server_expiring" }.into(),
      level: if urgent { IssueLevel::Fault } else { IssueLevel::Warn },
      subject: (!domain).then(|| IssueSubject {
        kind: "server".into(), name: name.into(),
      }),
      title,
      hint: None,
    })
  }).collect()
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let client = match reqwest::Client::builder()
      .timeout(Duration::from_secs(10)).build()
    {
      Ok(c) => c,
      Err(e) => { tracing::warn!("RDAP 客户端：{e}"); return; }
    };
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
      if let Err(e) = round(&state, &client).await {
        tracing::warn!("到期检查失败：{}", e.message);
      }
      tokio::time::sleep(Duration::from_secs(3600)).await;
    }
  });
}

async fn round(
  state: &AppState,
  client: &reqwest::Client,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let hosts: Vec<_> = snap.world.routes.keys()
    .map(|h| candidates(h)).collect();
  let all: BTreeSet<_> = hosts.iter().flatten().cloned().collect();
  // true 表示 404，才能继续试更短的候选；失败不能继续往下查。
  let mut checked = BTreeMap::new();
  for host in &hosts {
    for name in host {
      if let Some(missing) = checked.get(name) {
        if *missing { continue; }
        break;
      }
      let old = CACHE.lock().unwrap_or_else(|e| e.into_inner())
        .get(name).cloned();
      let missing = if let Some(e) = old
        .filter(|e| crate::db::now_ms() - e.checked_at < 86_400_000)
      {
        e.expires.is_none()
      } else {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let response = client.get(format!("https://rdap.org/domain/{name}"))
          .send().await;
        let expires = match response {
          Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => Some(None),
          Ok(r) if r.status() == reqwest::StatusCode::OK => r.json::<serde_json::Value>()
            .await.ok().and_then(|v| parse_expiry(&v)).map(Some),
          _ => None,
        };
        if let Some(expires) = expires {
          CACHE.lock().unwrap_or_else(|e| e.into_inner()).insert(
            name.clone(), Entry { expires, checked_at: crate::db::now_ms() },
          );
          expires.is_none()
        } else {
          checked.insert(name.clone(), false);
          break;
        }
      };
      checked.insert(name.clone(), missing);
      if !missing { break; }
    }
  }
  let mut days = BTreeMap::new();
  {
    let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    for host in &hosts {
      if let Some((name, expires)) = host.iter().find_map(|h| {
        cache.get(h).and_then(|e| e.expires).map(|t| (h, t))
      }) {
        days.insert(format!("domain:{name}"), (expires - Utc::now()).num_days());
      }
    }
  }
  let today = Utc::now().with_timezone(
    &FixedOffset::east_opt(8 * 3600).expect("固定时区"),
  ).date_naive();
  for (name, server) in &snap.world.servers {
    let n = server.settings.renew_at.as_deref()
      .and_then(|v| days_until(v, today)).unwrap_or(9999);
    days.insert(format!("server:{name}"), n);
  }
  for (subject, n) in &days {
    rules::observe(state, "expiry.days", subject, *n as f64, "").await;
  }
  for rule in ["expiry_soon", "expiry_urgent"] {
    for (s, _) in rules::firing_subjects(rule) {
      if let Some((kind, name)) = s.split_once(':')
        && match kind {
          "domain" => !all.contains(name),
          "server" => !snap.world.servers.contains_key(name),
          _ => false,
        }
      {
        rules::observe(state, "expiry.days", &s, 9999.0, "").await;
        days.insert(s, 9999);
      }
    }
  }
  *DAYS.lock().unwrap_or_else(|e| e.into_inner()) = days;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn candidate_domains() {
    assert_eq!(candidates("blog.example.com"), ["blog.example.com", "example.com"]);
    for h in ["203.0.113.1", "::1", "s1.local", "s1.internal", "s1.lan", "s1.ts.net", "s1.sslip.io", "s1.nip.io"] {
      assert!(candidates(h).is_empty());
    }
  }

  #[test]
  fn expiration_event() {
    let v = serde_json::json!({"events": [
      {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
      {"eventAction": "expiration", "eventDate": "2027-01-31T00:00:00Z"}
    ]});
    assert_eq!(parse_expiry(&v).unwrap().to_rfc3339(), "2027-01-31T00:00:00+00:00");
    assert!(parse_expiry(&serde_json::json!({})).is_none());
  }

  #[test]
  fn renewal_days() {
    let today = NaiveDate::from_ymd_opt(2027, 1, 21).unwrap();
    assert_eq!(days_until("2027-01-31", today), Some(10));
    assert_eq!(days_until("2027-01-20", today), Some(-1));
    assert_eq!(days_until("2027-02-30", today), None);
  }
}
