//! 告警和事件通知的统一入口。
//!
//! - 告警 = 指标 + 规则：各模块每轮检查只上报数值（[observe]），这里按内置规则判断，
//!   "规则 + 对象"的状态变化（触发 → 恢复）时推送；
//! - 事件通知（定时任务、备份结果、切换入口、新版本）发生就推，有开关、级别和静默（[notice]）。
//!
//! 规则内置，页面上能改开关、级别、阈值、连续次数、静默，改动存在设置 `alerts.config`。
//! 状态沿用 `notify.state.<key>`（跨重启不重复推）；正在触发的存在 `alert_firing`，
//! 确认记录存在 `alert_acks`，待汇总存在 `alert_digest`，自定义抑制存在 `alert_suppressions`，
//! 推送记录存在 `alert_history`（保留 7 天）；指标序列只在内存里。

use std::{
  collections::{BTreeMap, VecDeque},
  sync::Mutex,
};

use serde::{Deserialize, Serialize};
use wharf_api_types::view::{
  AlertAck, AlertLevel, AlertRef, CustomSuppressionView,
};

use crate::{
  db::{self, now_ms},
  notify::{self, Event},
  state::AppState,
};

#[path = "external_alerts.rs"]
pub(crate) mod external;
#[path = "resource_alerts.rs"]
pub(crate) mod resources;

#[path = "rules/ack.rs"]
pub mod ack;
#[path = "rules/digest.rs"]
pub mod digest;
#[path = "rules/http.rs"]
mod http;
#[path = "rules/service_checks.rs"]
mod service_checks;
#[path = "rules/store.rs"]
mod store;
#[path = "rules/suppress.rs"]
pub mod suppress;

pub use http::{list, patch, set_options};
pub(crate) use store::MIGRATION;
use store::{config, mark_pushed, record_at, set_firing};

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
  level: AlertLevel,
  /// 状态键，沿用改造前的，升级后不会重推。
  key: fn(&str) -> String,
  fire: fn(&Ctx) -> Event,
  ok: fn(&Ctx) -> Event,
}

fn ev(title: String, body: String) -> Event {
  Event { title, body }
}

/// `<服务器>:<程序>` 拆开。
pub(super) fn split_unit(s: &str) -> (&str, &str) {
  s.split_once(':').unwrap_or((s, ""))
}

#[path = "rules/catalog.rs"]
mod catalog;
use catalog::RULES;

/// 事件通知：id、名称和默认级别。
const NOTICES: &[(&str, &str, AlertLevel)] = &[
  ("exposure", "机器上新开了对公网的端口", AlertLevel::Urgent),
  ("login", "从新的地址登录控制面", AlertLevel::Urgent),
  ("recovery", "用掉了一个恢复码", AlertLevel::Urgent),
  (
    "task",
    "定时任务失败和恢复（任务自己也要开通知）",
    AlertLevel::Urgent,
  ),
  ("backup", "服务备份失败和恢复", AlertLevel::Urgent),
  ("failover", "网关切到备用入口、切回", AlertLevel::Urgent),
  ("update", "服务有新版本", AlertLevel::Digest),
  ("auto_update", "服务自动更新的结果", AlertLevel::Digest),
  ("unmanaged_container", "出现未纳管容器", AlertLevel::Digest),
];

pub(super) fn source_name(id: &str) -> &str {
  if id == "digest" {
    return "每日汇总";
  }
  if let Some(r) = RULES.iter().find(|r| r.id == id) {
    return r.name;
  }
  if let Some((_, name, _)) =
    NOTICES.iter().find(|(n, _, _)| *n == id)
  {
    return name;
  }
  id
}

pub(super) fn default_level(id: &str) -> AlertLevel {
  if let Some(r) = RULES.iter().find(|r| r.id == id) {
    return r.level;
  }
  if let Some((_, _, level)) =
    NOTICES.iter().find(|(n, _, _)| *n == id)
  {
    return *level;
  }
  AlertLevel::Urgent
}

/// 页面上改过的值，没改的字段用默认。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Override {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub enabled: Option<bool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub level: Option<AlertLevel>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub threshold: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub for_n: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub muted_until: Option<i64>,
}

impl Override {
  pub(super) fn enabled(&self) -> bool {
    self.enabled.unwrap_or(true)
  }

  pub(super) fn muted(&self, now: i64) -> bool {
    self.muted_until.is_some_and(|t| t > now)
  }
}

#[derive(Debug, Clone)]
pub(super) struct FiringEntry {
  pub since: i64,
  pub title: String,
  pub body: String,
  pub pushed: bool,
}

#[derive(Debug, Clone)]
pub(super) struct AckEntry {
  pub by: String,
  pub at: i64,
  pub note: Option<String>,
  pub cleared_at: Option<i64>,
}

#[derive(Default)]
pub(super) struct Memory {
  pub config: Option<BTreeMap<String, Override>>,
  /// （指标，对象）→ 最近的点和最后更新时间。
  pub series: BTreeMap<(String, String), (VecDeque<f64>, i64)>,
  /// （规则，对象）→ 正在触发记录，和表 `alert_firing` 一致，第一次用时从库里读。
  pub firing: BTreeMap<(String, String), FiringEntry>,
  /// （规则，对象）→ 确认记录，和表 `alert_acks` 一致，第一次用时从库里读。
  pub acks: BTreeMap<(String, String), AckEntry>,
  /// 自定义抑制规则，和表 `alert_suppressions` 一致，第一次用时从库里读。
  pub suppressions: Vec<CustomSuppressionView>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

pub(super) fn with<T>(f: impl FnOnce(&mut Memory) -> T) -> T {
  let mut g = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  f(g.get_or_insert_with(Memory::default))
}

#[cfg(test)]
pub(super) fn reset_memory() {
  let mut g = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  *g = None;
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

pub(super) async fn observe_at(
  state: &AppState,
  now: i64,
  metric: &str,
  subject: &str,
  value: f64,
  detail: &str,
) {
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
    if !o.enabled() {
      set_firing(state, fkey, None).await;
      continue;
    }
    let threshold = o.threshold.unwrap_or(rule.threshold);
    let for_n = o.for_n.unwrap_or(rule.for_n);
    let ctx = Ctx {
      subject,
      value,
      detail,
      threshold,
      for_n,
    };
    let mut prev_firing = None;
    let (ok, event) = match judge(rule, threshold, for_n, &points) {
      Verdict::Hold => continue,
      Verdict::Fire => {
        let e = (rule.fire)(&ctx);
        ack::on_fire(state, &fkey, now).await;
        set_firing(
          state,
          fkey.clone(),
          Some(FiringEntry {
            since: now,
            title: e.title.clone(),
            body: e.body.clone(),
            pushed: false,
          }),
        )
        .await;
        (false, e)
      }
      Verdict::Recover => {
        prev_firing = with(|m| m.firing.get(&fkey).cloned());
        set_firing(state, fkey.clone(), None).await;
        ack::on_recover(state, &fkey, now).await;
        (true, (rule.ok)(&ctx))
      }
    };
    let prev_pushed = prev_firing.as_ref().is_some_and(|p| p.pushed);
    if notify::transition(state, &(rule.key)(subject), ok).await {
      let event = if ok && rule.id == "server_offline" {
        // 开始触发前已经连续离线了 for_n 分钟。
        let since = prev_firing
          .as_ref()
          .map(|p| p.since - i64::from(for_n) * 60_000);
        crate::alert_context::back_online(
          state, subject, since, event,
        )
        .await
      } else {
        event
      };
      let pushed = push_at(
        state,
        Push {
          now,
          id: rule.id,
          subject: Some(subject),
          over: &o,
          ok,
          prev_pushed,
        },
        event,
      )
      .await;
      if !ok && pushed {
        mark_pushed(state, &fkey).await;
      }
    }
    if ok && prev_firing.is_some() {
      suppress::recheck_suppressed(state, now).await;
    }
  }
}

/// 事件通知。`key` 有值时只在状态变化时发（失败 → 恢复），没有就每次都发。
pub async fn notice(
  state: &AppState,
  id: &'static str,
  key: Option<&str>,
  ok: bool,
  event: Event,
) {
  if let Some(k) = key
    && !notify::transition(state, k, ok).await
  {
    return;
  }
  let o = config(state).await.get(id).cloned().unwrap_or_default();
  push_at(
    state,
    Push {
      now: now_ms(),
      id,
      subject: None,
      over: &o,
      ok,
      prev_pushed: true,
    },
    event,
  )
  .await;
}

pub(super) struct Push<'a> {
  pub now: i64,
  pub id: &'a str,
  pub subject: Option<&'a str>,
  pub over: &'a Override,
  pub ok: bool,
  pub prev_pushed: bool,
}

/// 统一的推送出口：按优先级检查关闭、静默、确认、未推送恢复、抑制，最后按级别立即推或并入每日汇总。
/// 返回策略层是否放行（立即推送或并入汇总）。
pub(super) async fn push_at(
  state: &AppState,
  p: Push<'_>,
  event: Event,
) -> bool {
  let skipped = if !p.over.enabled() {
    Some("已关闭".to_string())
  } else if p.over.muted(p.now) {
    Some("静默中".to_string())
  } else if let Some(subj) = p.subject
    && ack::is_acked(state, p.id, subj, p.now).await
  {
    Some("已确认".to_string())
  } else if p.ok && p.subject.is_some() && !p.prev_pushed {
    Some("触发未推送".to_string())
  } else if !p.ok
    && let Some(subj) = p.subject
    && let Some(reason) = suppress::check(state, p.id, subj).await
  {
    Some(reason)
  } else {
    None
  };
  if skipped.is_some() {
    record_at(state, p.now, (p.id, p.subject), &event, p.ok, skipped)
      .await;
    return false;
  }
  let level = p.over.level.unwrap_or_else(|| default_level(p.id));
  if level == AlertLevel::Digest {
    digest::enqueue(
      state,
      p.now,
      p.id,
      p.subject,
      &event.title,
      p.ok,
    )
    .await;
    record_at(
      state,
      p.now,
      (p.id, p.subject),
      &event,
      p.ok,
      Some("并入每日汇总".to_string()),
    )
    .await;
    return true;
  }
  let event = if !p.ok {
    crate::alert_context::enrich(state, p.id, p.subject, event).await
  } else {
    event
  };
  let skipped = notify::deliver(state, &event).await;
  record_at(state, p.now, (p.id, p.subject), &event, p.ok, skipped)
    .await;
  true
}

/// 网关恢复等场景调用，补推解除抑制的告警。
pub async fn recheck_suppressed_now(state: &AppState) {
  suppress::recheck_suppressed(state, now_ms()).await;
}

/// 关注项被删除或服务停止时，清除告警、确认和通知状态，不发恢复通知。
pub async fn retain_subjects(
  state: &AppState,
  id: &str,
  keep: &std::collections::BTreeSet<String>,
) {
  let Some(rule) = RULES.iter().find(|r| r.id == id) else {
    return;
  };
  let _ = config(state).await;
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
  for subject in removed {
    let fkey = (id.to_string(), subject.clone());
    set_firing(state, fkey.clone(), None).await;
    ack::remove_quiet(state, fkey).await;
    let key = format!("notify.state.{}", (rule.key)(&subject));
    let _ =
      state.db.call(move |c| db::set_setting(c, &key, None)).await;
  }
}

pub fn firing_since(rule: &str, subject: &str) -> Option<i64> {
  with(|m| {
    m.firing
      .get(&(rule.to_string(), subject.to_string()))
      .map(|f| f.since)
  })
}

pub fn firing_subjects(rule: &str) -> Vec<(String, String)> {
  with(|m| {
    m.firing
      .iter()
      .filter(|((r, _), _)| r == rule)
      .map(|((_, s), f)| (s.clone(), f.title.clone()))
      .collect()
  })
}

pub async fn ensure_loaded(state: &AppState) {
  let _ = config(state).await;
}

pub fn ack_of(rule: &str, subject: &str) -> Option<AlertAck> {
  ack::active_ack(rule, subject, now_ms())
}

/// 若 `(rule, subject)` 正在触发，返回它的确认记录与告警引用，用于填入 `Issue`。
pub fn issue_alert(
  rule: &str,
  subject: &str,
) -> (Option<AlertAck>, Option<AlertRef>) {
  if firing_since(rule, subject).is_some() {
    (
      ack_of(rule, subject),
      Some(AlertRef {
        rule: rule.to_string(),
        subject: subject.to_string(),
      }),
    )
  } else {
    (None, None)
  }
}

#[cfg(test)]
#[path = "rules/tests.rs"]
mod tests;
