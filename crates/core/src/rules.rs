//! 告警和事件通知的统一入口。
//!
//! 规则通过 [observe] 接收采样，有状态及单次事件通过 [notice] 进入通知策略。
//! 开关、阈值、静默及通知级别存在 `alerts.config`，告警起止沿用 `notify.state.<key>`。
//! 正在触发的告警存在 `alert_firing`，推送尝试及跳过原因存在 `alert_history`（保留 7 天）。

use std::{
  collections::{BTreeMap, VecDeque},
  sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  view::{AlertHistoryView, AlertLevel, AlertTarget},
};

use crate::{
  db::{self, now_ms},
  notify::{self, Event},
  state::AppState,
};

#[path = "rules/api.rs"]
pub(crate) mod api;
#[path = "rules/availability.rs"]
mod availability;
#[path = "rules/digest.rs"]
pub(crate) mod digest;
#[path = "rules/policy.rs"]
pub(crate) mod policy;
#[path = "rules/suppression.rs"]
mod suppression;
pub(crate) use policy::MIGRATION;
use policy::{Delivery, push};

static UPDATE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

#[path = "external_alerts.rs"]
pub(crate) mod external;
#[path = "resource_alerts.rs"]
pub(crate) mod resources;

#[path = "rules/service_checks.rs"]
mod service_checks;

const CONFIG_KEY: &str = "alerts.config";
/// 每个序列最多留多少个点，也是"连续次数"的上限。
const KEEP: usize = 60;
/// 页面和 CLI 一次最多看多少条推送。
const HISTORY: usize = 200;
const KEEP_HISTORY_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 这么久没有新点的序列（服务器删了、服务停了监控）就丢掉。
const STALE_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Clone, Copy, PartialEq)]
enum Op {
  Lt,
  Gt,
  Ge,
}

impl Op {
  fn hit(self, v: f64, t: f64) -> bool {
    match self {
      Op::Lt => v < t,
      Op::Gt => v > t,
      Op::Ge => v >= t,
    }
  }

  fn text(self) -> &'static str {
    match self {
      Op::Lt => "<",
      Op::Gt => ">",
      Op::Ge => ">=",
    }
  }
}

#[derive(Clone, Copy)]
enum Mode {
  /// 最近 `for_n` 个点都满足。
  Consecutive,
  /// 最近这么多个点里有 `for_n` 个满足（且最新一个满足）触发，全都不满足才恢复。
  Window(usize),
  ServiceLog,
  Heartbeat,
}

/// 一次判断的上下文，用来拼推送内容。
struct Ctx<'a> {
  subject: &'a str,
  value: f64,
  detail: &'a str,
  threshold: f64,
  for_n: u32,
}

struct Rule {
  id: &'static str,
  name: &'static str,
  metric: &'static str,
  op: Op,
  threshold: f64,
  threshold_editable: bool,
  for_n: u32,
  mode: Mode,
  /// 有值时要回到这一侧（`op` 取反）才算恢复，中间状态保持不变。
  recover: Option<f64>,
  every: &'static str,
  /// 状态键，沿用改造前的，升级后不会重推。
  key: fn(&str) -> String,
  fire: fn(&Ctx) -> Event,
  ok: fn(&Ctx) -> Event,
}

fn ev(title: String, body: String) -> Event {
  Event { title, body }
}

/// `<服务器>:<程序>` 拆开。
fn split_unit(s: &str) -> (&str, &str) {
  s.split_once(':').unwrap_or((s, ""))
}

#[path = "rules/catalog.rs"]
mod catalog;
use catalog::RULES;

/// 事件通知：id 和名称。
const NOTICES: &[(&str, &str)] = &[
  ("exposure", "机器上新开了对公网的端口"),
  ("login", "从新的地址登录控制面"),
  ("recovery", "用掉了一个恢复码"),
  ("task", "定时任务失败和恢复（任务自己也要开通知）"),
  ("backup", "服务备份失败和恢复"),
  ("failover", "网关切到备用入口、切回"),
  ("update", "服务有新版本"),
  ("auto_update", "服务自动更新的结果"),
  ("unmanaged_container", "出现未纳管容器"),
  ("notify_hook", "服务和脚本发来的通知"),
];

/// 页面上改过的值，没改的字段用默认。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Override {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  enabled: Option<bool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  threshold: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  for_n: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  muted_until: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  level: Option<AlertLevel>,
}

impl Override {
  fn level(&self, id: &str) -> AlertLevel {
    self.level.unwrap_or_else(|| policy::default_level(id))
  }

  fn enabled(&self) -> bool {
    self.enabled.unwrap_or(true)
  }

  fn muted(&self, now: i64) -> bool {
    self.muted_until.is_some_and(|t| t > now)
  }
}

#[derive(Default)]
struct Memory {
  config: Option<BTreeMap<String, Override>>,
  /// （指标，对象）→ 最近的点和最后更新时间。
  series: BTreeMap<(String, String), (VecDeque<f64>, i64)>,
  /// （规则，对象）→（开始时间，标题），和表 `alert_firing` 一致，第一次用时从库里读。
  firing: BTreeMap<(String, String), (i64, String)>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Memory) -> T) -> T {
  let mut g = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  f(g.get_or_insert_with(Memory::default))
}

async fn config(state: &AppState) -> BTreeMap<String, Override> {
  if let Some(c) = with(|m| m.config.clone()) {
    return c;
  }
  let loaded = state
    .db
    .call(|c| {
      let cfg = db::setting(c, CONFIG_KEY)?;
      let mut stmt = c
        .prepare(
          "SELECT rule, subject, since, title FROM alert_firing",
        )
        .map_err(db::sql_err)?;
      let firing = stmt
        .query_map([], |r| {
          Ok(((r.get(0)?, r.get(1)?), (r.get(2)?, r.get(3)?)))
        })
        .and_then(Iterator::collect::<Result<BTreeMap<_, _>, _>>)
        .map_err(db::sql_err)?;
      Ok((cfg, firing))
    })
    .await;
  let (cfg, firing) = match loaded {
    Ok((cfg, firing)) => (
      cfg
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default(),
      firing,
    ),
    Err(e) => {
      tracing::warn!("读告警配置失败：{}", e.message);
      return BTreeMap::new();
    }
  };
  with(|m| {
    if m.config.is_none() {
      m.firing = firing;
    }
    m.config.get_or_insert(cfg).clone()
  })
}

enum Verdict {
  Fire,
  Recover,
  Hold,
}

fn judge(
  rule: &Rule,
  threshold: f64,
  for_n: u32,
  points: &VecDeque<f64>,
) -> Verdict {
  let Some(&last) = points.back() else {
    return Verdict::Hold;
  };
  let bad = |v: f64| rule.op.hit(v, threshold);
  let n = (for_n.max(1) as usize).min(KEEP);
  match rule.mode {
    Mode::Consecutive => {
      if points.len() >= n
        && points.iter().rev().take(n).all(|v| bad(*v))
      {
        return Verdict::Fire;
      }
      let recovered = match rule.recover {
        Some(r) => !rule.op.hit(last, r) && last != r,
        None => {
          !bad(last)
            && (!resources::is_report_metric(rule.metric)
              || last < threshold)
        }
      };
      if recovered {
        Verdict::Recover
      } else {
        Verdict::Hold
      }
    }
    Mode::ServiceLog if last == -f64::MAX => Verdict::Recover,
    Mode::ServiceLog
      if points.len() >= n
        && points
          .iter()
          .rev()
          .take(n)
          .all(|v| *v != -f64::MAX && bad(*v)) =>
    {
      Verdict::Fire
    }
    Mode::ServiceLog => Verdict::Hold,
    Mode::Heartbeat if last == f64::MAX => Verdict::Fire,
    Mode::Heartbeat if last == -f64::MAX => Verdict::Recover,
    Mode::Heartbeat
      if points.len() >= n
        && points.iter().rev().take(n).all(|v| bad(*v)) =>
    {
      Verdict::Fire
    }
    Mode::Heartbeat => Verdict::Hold,
    Mode::Window(w) => {
      let hits =
        points.iter().rev().take(w).filter(|v| bad(**v)).count();
      if bad(last) && hits >= n {
        Verdict::Fire
      } else if hits == 0 {
        Verdict::Recover
      } else {
        Verdict::Hold
      }
    }
  }
}

/// 上报一个指标的一个点。`detail` 是给推送内容用的说明（例如失败原因）。
pub async fn observe(
  state: &AppState,
  metric: &str,
  subject: &str,
  value: f64,
  detail: &str,
) {
  observe_at(state, now_ms(), metric, subject, value, detail).await;
}

async fn observe_at(
  state: &AppState,
  now: i64,
  metric: &str,
  subject: &str,
  value: f64,
  detail: &str,
) {
  let _guard = UPDATE.lock().await;
  let Some(points) = with(|m| {
    m.series.retain(|_, (_, at)| now - *at < STALE_MS);
    let (p, at) = m
      .series
      .entry((metric.to_string(), subject.to_string()))
      .or_default();
    if resources::is_report_metric(metric)
      && !resources::prepare_sample(p, *at, now)
    {
      return None;
    }
    p.push_back(value);
    while p.len() > KEEP {
      p.pop_front();
    }
    *at = now;
    Some(p.clone())
  }) else {
    return;
  };
  let cfg = config(state).await;
  for rule in RULES.iter().filter(|r| r.metric == metric) {
    let o = cfg.get(rule.id).cloned().unwrap_or_default();
    let fkey = (rule.id.to_string(), subject.to_string());
    let threshold = o.threshold.unwrap_or(rule.threshold);
    let for_n = o.for_n.unwrap_or(rule.for_n);
    let ctx = Ctx {
      subject,
      value,
      detail,
      threshold,
      for_n,
    };
    let since = firing_since(rule.id, subject);
    let (ok, event) = match judge(rule, threshold, for_n, &points) {
      Verdict::Hold if o.enabled() => continue,
      Verdict::Hold => {
        match set_firing(state, fkey, None, now, None).await {
          Ok((true, _)) => release(state, &cfg).await,
          Ok((false, _)) => {}
          Err(e) => {
            tracing::warn!("清理已关闭的告警失败：{}", e.message)
          }
        }
        continue;
      }
      Verdict::Fire => (false, (rule.fire)(&ctx)),
      Verdict::Recover => (true, (rule.ok)(&ctx)),
    };
    let (changed, transition) = match set_firing(
      state,
      fkey,
      (!ok && o.enabled()).then(|| (now, event.title.clone())),
      now,
      Some(((rule.key)(subject), ok)),
    )
    .await
    {
      Ok(result) => result,
      Err(e) => {
        tracing::warn!("记录告警状态失败：{}", e.message);
        continue;
      }
    };
    if transition || (changed && !ok && o.enabled()) {
      // 开始触发前已经连续离线了 for_n 分钟。
      let offline_since =
        since.map(|at| at - i64::from(for_n) * 60_000);
      push(
        state,
        Delivery {
          id: rule.id,
          subject: Some(subject),
          paired: true,
          ok,
          now,
          replay: false,
        },
        &cfg,
        event,
        offline_since,
      )
      .await;
    }
    if changed && (ok || !o.enabled()) {
      release(state, &cfg).await;
    }
  }
}

/// 有状态的事件只有在失败或恢复时通知，普通事件每次都处理。
pub async fn notice(
  state: &AppState,
  id: &'static str,
  subject: Option<&str>,
  key: Option<&str>,
  ok: bool,
  event: Event,
) -> Option<String> {
  let _guard = UPDATE.lock().await;
  let cfg = config(state).await;
  let now = now_ms();
  let paired = key.is_some();
  let changed = if let (Some(k), Some(subject)) = (key, subject) {
    let enabled = cfg.get(id).is_none_or(Override::enabled);
    match set_firing(
      state,
      (id.into(), subject.into()),
      (!ok && enabled).then(|| (now, event.title.clone())),
      now,
      Some((k.to_string(), ok)),
    )
    .await
    {
      Ok((changed, transition)) if transition || (changed && !ok) => {
        changed
      }
      Ok(_) => return None,
      Err(e) => {
        tracing::warn!("记录事件状态失败：{}", e.message);
        return Some(format!("处理失败：{}", e.message));
      }
    }
  } else {
    false
  };
  let skipped = push(
    state,
    Delivery {
      id,
      subject,
      paired,
      ok,
      now,
      replay: false,
    },
    &cfg,
    event,
    None,
  )
  .await;
  if changed && ok {
    release(state, &cfg).await;
  }
  skipped
}

/// 开始触发（已经在触发就保留原来的开始时间）或结束触发，内存和库一起改。
async fn set_firing(
  state: &AppState,
  key: (String, String),
  fire: Option<(i64, String)>,
  now: i64,
  transition: Option<(String, bool)>,
) -> Result<(bool, bool), ApiError> {
  let changed =
    with(|m| m.firing.contains_key(&key)) != fire.is_some();
  if !changed && transition.is_none() {
    return Ok((false, false));
  }
  let transitioned = state.db.call({
    let key = key.clone();
    let fire = fire.clone();
    move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      let (rule, subject) = key;
      if changed {
        match &fire {
          Some((since, title)) => tx.execute(
            "INSERT OR REPLACE INTO alert_firing (rule, subject, since, title) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![rule, subject, since, title],
          ),
          None => tx.execute(
            "DELETE FROM alert_firing WHERE rule = ?1 AND subject = ?2",
            rusqlite::params![rule, subject],
          ),
        }.map_err(db::sql_err)?;
        policy::update_ack(&tx, &rule, &subject, fire.is_some(), now).map_err(db::sql_err)?;
      }
      let transitioned = match transition {
        Some((key, ok)) => notify::transition(&tx, &key, ok)?,
        None => false,
      };
      tx.commit().map_err(db::sql_err)?;
      Ok(transitioned)
    }
  }).await?;
  if changed {
    with(|m| match fire {
      Some(fire) => m.firing.insert(key, fire),
      None => m.firing.remove(&key),
    });
  }
  Ok((changed, transitioned))
}

async fn release(state: &AppState, cfg: &BTreeMap<String, Override>) {
  if let Err(e) = suppression::release(state, cfg).await {
    tracing::warn!("检查告警抑制失败：{}", e.message);
  }
}

/// 最近的推送，新的在前。
async fn history(state: &AppState) -> Vec<AlertHistoryView> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT at, source, title, ok, skipped FROM alert_history ORDER BY id DESC LIMIT ?1",
        )
        .map_err(db::sql_err)?;
      stmt
        .query_map([HISTORY as i64], |r| {
          Ok(AlertHistoryView {
            at: r.get(0)?,
            source: r.get(1)?,
            title: r.get(2)?,
            ok: r.get(3)?,
            skipped: r.get(4)?,
          })
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)
    })
    .await
    .unwrap_or_else(|e| {
      tracing::warn!("读推送记录失败：{}", e.message);
      vec![]
    })
}

/// 某条规则正在触发的对象和标题：`(对象, 标题)`。
/// 关注项被删除或服务停止时，清除告警和通知状态，不发恢复通知。
pub async fn retain_subjects(
  state: &AppState,
  id: &str,
  keep: &std::collections::BTreeSet<String>,
) {
  let Some(rule) = RULES.iter().find(|r| r.id == id) else {
    return;
  };
  let _guard = UPDATE.lock().await;
  let cfg = config(state).await;
  let removed = with(|m| {
    let mut removed = std::collections::BTreeSet::new();
    m.series.retain(|(metric, subject), _| {
      let keep = metric != rule.metric || keep.contains(subject);
      if !keep {
        removed.insert(subject.clone());
      }
      keep
    });
    removed.extend(
      m.firing
        .keys()
        .filter(|(r, subject)| r == id && !keep.contains(subject))
        .map(|(_, subject)| subject.clone()),
    );
    removed
  });
  if !removed.is_empty() {
    for subject in removed {
      forget_subject(state, id, &subject, &(rule.key)(&subject))
        .await;
    }
    release(state, &cfg).await;
  }
}

async fn forget_subject(
  state: &AppState,
  id: &str,
  subject: &str,
  key: &str,
) {
  let now = now_ms();
  if let Err(e) =
    set_firing(state, (id.into(), subject.into()), None, now, None)
      .await
  {
    tracing::warn!("清理正在触发的告警失败：{}", e.message);
    return;
  }
  let key = format!("notify.state.{key}");
  let id = id.to_string();
  let subject = subject.to_string();
  if let Err(e) = state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      policy::forget_episode(&tx, &id, &subject, now)
        .map_err(db::sql_err)?;
      db::set_setting(&tx, &key, None)?;
      tx.commit().map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("清理告警状态失败：{}", e.message);
  }
}

pub(crate) fn issue_target(
  rule: &str,
  subject: &str,
) -> Option<AlertTarget> {
  firing_since(rule, subject).map(|_| AlertTarget {
    rule: rule.into(),
    subject: subject.into(),
  })
}

pub fn firing_since(rule: &str, subject: &str) -> Option<i64> {
  with(|m| {
    m.firing
      .get(&(rule.to_string(), subject.to_string()))
      .map(|(since, _)| *since)
  })
}

pub fn firing_subjects(rule: &str) -> Vec<(String, String)> {
  with(|m| {
    m.firing
      .iter()
      .filter(|((r, _), _)| r == rule)
      .map(|((_, s), (_, t))| (s.clone(), t.clone()))
      .collect()
  })
}

#[cfg(test)]
#[path = "rules/tests.rs"]
mod tests;
