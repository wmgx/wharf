use std::{
  collections::HashMap,
  sync::{LazyLock, Mutex},
  time::{Duration, Instant},
};

use crate::{
  notify::Event, source_trust::classify_zone, state::AppState,
};

const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const MAX_TOTAL: u32 = 20;
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockScope {
  AdminLogin,
  GateKey,
}

impl LockScope {
  fn per_ip(self) -> u32 {
    match self {
      Self::AdminLogin => 5,
      Self::GateKey => 10,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginZone {
  Internal,
  Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockKind {
  PerIp,
  ZoneTotal,
}

#[derive(Debug, PartialEq, Eq)]
struct LockTriggered {
  scope: LockScope,
  zone: OriginZone,
  kind: LockKind,
  source: String,
  count: u32,
  minutes: u64,
}

type Bucket = (LockScope, OriginZone, Option<String>);

#[derive(Default)]
struct LockoutTable {
  entries: HashMap<Bucket, (u32, Instant)>,
}

impl LockoutTable {
  fn locked_at(
    &self,
    scope: LockScope,
    zone: OriginZone,
    key: &str,
    now: Instant,
  ) -> Option<u64> {
    [(Some(key.to_string()), scope.per_ip()), (None, MAX_TOTAL)]
      .into_iter()
      .filter_map(|(key, max)| {
        let &(count, at) = self.entries.get(&(scope, zone, key))?;
        let elapsed = now.saturating_duration_since(at);
        (count >= max && elapsed < LOCKOUT).then(|| {
          (LOCKOUT - elapsed).as_nanos().div_ceil(60_000_000_000)
            as u64
        })
      })
      .max()
  }

  fn increment(&mut self, bucket: Bucket, now: Instant) -> u32 {
    if self.entries.len() >= MAX_ENTRIES
      && !self.entries.contains_key(&bucket)
      && let Some(oldest) = self
        .entries
        .iter()
        .filter(|((_, _, key), _)| key.is_some())
        .min_by_key(|(_, (_, at))| *at)
        .map(|(key, _)| key.clone())
    {
      self.entries.remove(&oldest);
    }
    let (count, at) = self.entries.entry(bucket).or_insert((0, now));
    *count = count.saturating_add(1);
    *at = now;
    *count
  }

  fn record_at(
    &mut self,
    scope: LockScope,
    zone: OriginZone,
    key: &str,
    now: Instant,
  ) -> Option<LockTriggered> {
    self.entries.retain(|_, (_, at)| {
      now.saturating_duration_since(*at) < LOCKOUT
    });
    let total = (scope == LockScope::AdminLogin)
      .then(|| self.increment((scope, zone, None), now));
    let count =
      self.increment((scope, zone, Some(key.to_string())), now);
    let (kind, count) = if total == Some(MAX_TOTAL) {
      (LockKind::ZoneTotal, MAX_TOTAL)
    } else if count == scope.per_ip() {
      (LockKind::PerIp, count)
    } else {
      return None;
    };
    Some(LockTriggered {
      scope,
      zone,
      kind,
      source: key.to_string(),
      count,
      minutes: LOCKOUT.as_secs() / 60,
    })
  }

  fn clear(&mut self, scope: LockScope, zone: OriginZone, key: &str) {
    self.entries.remove(&(scope, zone, Some(key.to_string())));
  }
}

static FAILURES: LazyLock<Mutex<LockoutTable>> =
  LazyLock::new(Default::default);

fn table() -> std::sync::MutexGuard<'static, LockoutTable> {
  FAILURES.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn locked(scope: LockScope, key: &str) -> Option<u64> {
  let zone = classify_zone(key);
  table().locked_at(scope, zone, key, Instant::now())
}

pub fn clear(scope: LockScope, key: &str) {
  let zone = classify_zone(key);
  table().clear(scope, zone, key);
}

pub async fn record_and_notify(
  state: &AppState,
  scope: LockScope,
  key: &str,
  target: Option<&str>,
) {
  let zone = classify_zone(key);
  let triggered = table().record_at(scope, zone, key, Instant::now());
  let Some(event) = triggered else { return };
  notify(state, event, target).await;
}

async fn notify(
  state: &AppState,
  event: LockTriggered,
  target: Option<&str>,
) {
  let LockTriggered {
    scope,
    zone,
    kind,
    source,
    count,
    minutes,
  } = event;
  let zone = match zone {
    OriginZone::Internal => "组网/内网",
    OriginZone::Public => "公网",
  };
  let target = target
    .filter(|s| !s.is_empty())
    .map(|s| format!("访问 {s} 时"))
    .unwrap_or_default();
  let (title, body) = match (scope, kind) {
    (LockScope::GateKey, _) => (
      "门禁访问凭证触发锁定".into(),
      format!(
        "来源 {source} {target}连续凭证失败 {count} 次，已锁定 {minutes} 分钟"
      ),
    ),
    (LockScope::AdminLogin, LockKind::PerIp) => (
      format!("控制面登录触发锁定（{zone}）"),
      format!(
        "来源 {source} {target}连续输错 {count} 次，已锁定 {minutes} 分钟"
      ),
    ),
    (LockScope::AdminLogin, LockKind::ZoneTotal) => (
      format!("控制面{zone}登录触发汇总锁定"),
      format!(
        "{zone}来源合计输错 {count} 次（最近来源 {source}），已锁定 {minutes} 分钟"
      ),
    ),
  };
  tracing::warn!(%source, ?scope, %zone, ?kind, count, "触发来源锁定");
  crate::rules::notice(
    state,
    "login_lockout",
    None,
    false,
    Event { title, body },
  )
  .await;
}

#[cfg(test)]
pub(crate) fn clear_public_admin_failures_for_test() {
  table().entries.retain(|(scope, zone, _), _| {
    (*scope, *zone) != (LockScope::AdminLogin, OriginZone::Public)
  });
}

#[cfg(test)]
#[path = "lockout_tests.rs"]
mod tests;
