//! 告警和事件通知的统一入口。
//!
//! - 告警 = 指标 + 规则：各模块每轮检查只上报数值（[observe]），这里按内置规则判断，
//!   "规则 + 对象"的状态变化（触发 → 恢复）时推送；
//! - 事件通知（定时任务、备份结果、切换入口、新版本）发生就推，只有开关、级别和静默（[notice]）。
//!
//! 规则内置，页面上能改开关、阈值、连续次数、级别、静默，改动存在设置 `alerts.config`。
//! 状态沿用 `notify.state.<key>`（跨重启不重复推）；正在触发的存在 `alert_firing`，
//! 确认记录存在 `alert_acks`，待汇总条目存在 `alert_digest`，自定义抑制存在 `alert_suppressions`，
//! 推送记录存在 `alert_history`（保留 14 天）；指标序列只在内存里。

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  sync::Mutex,
};

use serde::{Deserialize, Serialize};
use wharf_api_types::view::{AlertAckView, AlertLevel, AlertTarget};

use crate::{
  db::{self, now_ms},
  notify::{self, Event},
  state::AppState,
  world::World,
};

#[path = "external_alerts.rs"]
pub(crate) mod external;
#[path = "resource_alerts.rs"]
pub(crate) mod resources;

#[path = "rules/ack.rs"]
mod ack;
#[path = "rules/api.rs"]
mod api;
#[path = "rules/catalog.rs"]
mod catalog;
#[path = "rules/custom.rs"]
mod custom;
#[path = "rules/digest.rs"]
mod digest;
#[path = "rules/service_checks.rs"]
mod service_checks;
#[path = "rules/service_overrides.rs"]
mod service_overrides;
#[path = "rules/store.rs"]
mod store;
#[path = "rules/suppress.rs"]
mod suppress;

use api::view;
use catalog::RULES;
use store::{
  AckEntry, Delivery, FiringEntry, SuppressionRule, record_at,
  set_firing, set_firing_delivery, set_firing_suppressed,
};

pub use ack::{ack_api, unack_api};
pub use api::{list, patch, set_options};
pub(crate) use custom::{
  MIGRATION as CUSTOM_MIGRATION, delete_service_rows,
};
pub use custom::{
  add_api as custom_add_api, issues as custom_issues,
  on_service_deleted, rm_api as custom_rm_api,
};
pub use digest::{preview_api as digest_preview_api, spawn};
pub use service_overrides::patch_service;
pub(crate) use store::MIGRATION;
pub use store::ensure_loaded;
pub use suppress::{
  add_api as suppress_add_api, list_api as suppress_list_api,
  rm_api as suppress_rm_api, sync_unavailable_gateways,
};

const CONFIG_KEY: &str = "alerts.config";
/// 每个序列最多留多少个点，也是"连续次数"的上限。
const KEEP: usize = 60;
/// 这么久没有新点的序列（服务器删了、服务停了监控）就丢掉。
const STALE_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq)]
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
  default_level: AlertLevel,
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

fn is_rule(id: &str) -> bool {
  RULES.iter().any(|r| r.id == id)
    || with(|m| m.custom_rules.contains_key(id))
}

pub(crate) fn default_level(id: &str) -> AlertLevel {
  if let Some(r) = RULES.iter().find(|r| r.id == id) {
    return r.default_level;
  }
  if let Some(lvl) = with(|m| m.custom_rules.get(id).map(|r| r.level))
  {
    return lvl;
  }
  if let Some((_, _, lvl)) = NOTICES.iter().find(|(n, _, _)| *n == id)
  {
    return *lvl;
  }
  AlertLevel::Urgent
}

pub(crate) fn rule_display_name(id: &str) -> String {
  display_name(id).to_string()
}

pub(crate) fn is_custom_rule(id: &str) -> bool {
  with(|m| m.custom_rules.contains_key(id))
}

fn display_name(id: &str) -> &str {
  if let Some(r) = RULES.iter().find(|r| r.id == id) {
    return r.name;
  }
  if let Some((_, name, _)) =
    NOTICES.iter().find(|(n, _, _)| *n == id)
  {
    return name;
  }
  if id == digest::SOURCE_ID {
    return "每日汇总";
  }
  id
}

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
  level: Option<AlertLevel>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  muted_until: Option<i64>,
}

impl Override {
  fn enabled(&self) -> bool {
    self.enabled.unwrap_or(true)
  }

  fn muted(&self, now: i64) -> bool {
    self.muted_until.is_some_and(|t| t > now)
  }
}

#[derive(Default)]
struct Memory {
  loaded: bool,
  config: BTreeMap<String, Override>,
  /// （指标，对象）→ 最近的点和最后更新时间。
  series: BTreeMap<(String, String), (VecDeque<f64>, i64)>,
  /// （规则，对象）→ 触发记录，和表 `alert_firing` 一致，第一次用时从库里读。
  firing: BTreeMap<(String, String), FiringEntry>,
  /// （规则，对象）→ 确认记录，和表 `alert_acks` 一致。
  acks: BTreeMap<(String, String), AckEntry>,
  /// 自定义抑制规则，和表 `alert_suppressions` 一致。
  suppressions: Vec<SuppressionRule>,
  /// 当前容器不在运行的网关名，用于内置网关抑制。
  unavailable_gateways: BTreeSet<String>,
  /// （规则，服务）→ 按服务覆盖，和表 `alert_service_overrides` 一致。
  service_overrides: BTreeMap<(String, String), Override>,
  /// 自定义规则名称 → 规则定义，和表 `alert_custom_rules` 一致。
  custom_rules: BTreeMap<String, custom::CustomRule>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Memory) -> T) -> T {
  let mut g = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  f(g.get_or_insert_with(Memory::default))
}

async fn config(state: &AppState) -> BTreeMap<String, Override> {
  ensure_loaded(state).await;
  with(|m| m.config.clone())
}

enum Verdict {
  Fire,
  Recover,
  Hold,
}

pub(super) fn judge_consecutive(
  op: Op,
  threshold: f64,
  for_n: u32,
  recover: Option<f64>,
  strict_report: bool,
  points: &VecDeque<f64>,
) -> Verdict {
  let Some(&last) = points.back() else {
    return Verdict::Hold;
  };
  let bad = |v: f64| op.hit(v, threshold);
  let n = (for_n.max(1) as usize).min(KEEP);
  if points.len() >= n && points.iter().rev().take(n).all(|v| bad(*v))
  {
    return Verdict::Fire;
  }
  let recovered = match recover {
    Some(r) => !op.hit(last, r) && last != r,
    None => !bad(last) && (!strict_report || last != threshold),
  };
  if recovered {
    Verdict::Recover
  } else {
    Verdict::Hold
  }
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
    Mode::Consecutive => judge_consecutive(
      rule.op,
      threshold,
      for_n,
      rule.recover,
      resources::is_report_metric(rule.metric),
      points,
    ),
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
  ensure_loaded(state).await;
  let has_builtin = RULES.iter().any(|r| r.metric == metric);
  let has_custom = with(|m| {
    m.custom_rules
      .values()
      .any(|r| r.metric == metric && r.service == subject)
  });
  if !has_builtin && !has_custom {
    return;
  }
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
  let (cfg, svc_overrides) =
    with(|m| (m.config.clone(), m.service_overrides.clone()));
  for rule in RULES.iter().filter(|r| r.metric == metric) {
    let svc_override =
      service_overrides::service_of_subject(rule.id, subject)
        .and_then(|svc| {
          svc_overrides.get(&(rule.id.to_string(), svc.to_string()))
        });
    let o = service_overrides::effective_override(
      cfg.get(rule.id),
      svc_override,
    );
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
    let mut prev = None;
    let (ok, event) = match judge(rule, threshold, for_n, &points) {
      Verdict::Hold => continue,
      Verdict::Fire => {
        let e = (rule.fire)(&ctx);
        set_firing(
          state,
          fkey.clone(),
          Some(FiringEntry {
            since: now,
            title: e.title.clone(),
            body: e.body.clone(),
            delivery: Delivery::None,
            suppressed: false,
          }),
        )
        .await;
        ack::on_firing_change(state, &fkey, true, now).await;
        (false, e)
      }
      Verdict::Recover => {
        prev = with(|m| m.firing.get(&fkey).cloned());
        set_firing(state, fkey.clone(), None).await;
        ack::on_firing_change(state, &fkey, false, now).await;
        (true, (rule.ok)(&ctx))
      }
    };
    if notify::transition(state, &(rule.key)(subject), ok).await {
      let event = if ok && rule.id == "server_offline" {
        // 开始触发前已经连续离线了 for_n 分钟。
        let since =
          prev.as_ref().map(|f| f.since - i64::from(for_n) * 60_000);
        crate::alert_context::back_online(
          state, subject, since, event,
        )
        .await
      } else {
        event
      };
      push_with_world(
        state,
        PushArgs {
          id: rule.id,
          subject: Some(subject),
          o: &o,
          ok,
          event,
          prev_delivery: prev.map(|f| f.delivery),
          now,
          world: None,
        },
      )
      .await;
      if ok {
        suppress::flush_unsuppressed(state, now).await;
      }
    }
  }
  if has_custom {
    custom::evaluate_at(
      state, now, metric, subject, value, detail, &points,
    )
    .await;
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
  notice_at(state, now_ms(), id, key, ok, event).await;
}

async fn notice_at(
  state: &AppState,
  now: i64,
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
  push_with_world(
    state,
    PushArgs {
      id,
      subject: None,
      o: &o,
      ok,
      event,
      prev_delivery: None,
      now,
      world: None,
    },
  )
  .await;
}

struct PushArgs<'a> {
  id: &'a str,
  subject: Option<&'a str>,
  o: &'a Override,
  ok: bool,
  event: Event,
  prev_delivery: Option<Delivery>,
  now: i64,
  world: Option<&'a World>,
}

/// 告警和事件通知的唯一推送出口：依次检查开关、静默、确认、抑制、级别。
async fn push_with_world(state: &AppState, args: PushArgs<'_>) {
  let PushArgs {
    id,
    subject,
    o,
    ok,
    event,
    prev_delivery,
    now,
    world,
  } = args;
  if !o.enabled() {
    record_at(
      state,
      now,
      id,
      subject,
      &event,
      ok,
      Some("已关闭".into()),
    )
    .await;
    return;
  }
  if o.muted(now) {
    record_at(
      state,
      now,
      id,
      subject,
      &event,
      ok,
      Some("静默中".into()),
    )
    .await;
    return;
  }
  if let Some(subj) = subject
    && ack::is_active(state, id, subj, now).await
  {
    record_at(
      state,
      now,
      id,
      subject,
      &event,
      ok,
      Some("已确认".into()),
    )
    .await;
    return;
  }
  let cfg = config(state).await;
  if !ok || subject.is_none() {
    if let Some(reason) =
      suppress::check(state, id, subject, &cfg, world).await
    {
      if !ok && let Some(subj) = subject {
        set_firing_suppressed(
          state,
          (id.to_string(), subj.to_string()),
          true,
        )
        .await;
      }
      record_at(
        state,
        now,
        id,
        subject,
        &event,
        ok,
        Some(format!("被抑制：{reason}")),
      )
      .await;
      return;
    }
  } else {
    match prev_delivery {
      Some(Delivery::None) => {
        let reason = match suppress::check(
          state, id, subject, &cfg, world,
        )
        .await
        {
          Some(r) => format!("被抑制：{r}"),
          None => "触发未推送".into(),
        };
        record_at(state, now, id, subject, &event, ok, Some(reason))
          .await;
        return;
      }
      Some(Delivery::Digest) => {
        digest::enqueue(
          state,
          id,
          subject,
          &event.title,
          true,
          false,
          now,
        )
        .await;
        record_at(
          state,
          now,
          id,
          subject,
          &event,
          ok,
          Some("并入每日汇总".into()),
        )
        .await;
        return;
      }
      Some(Delivery::Urgent) | None => {}
    }
  }
  let level = o.level.unwrap_or_else(|| default_level(id));
  if level == AlertLevel::Digest {
    digest::enqueue(
      state,
      id,
      subject,
      &event.title,
      ok,
      !is_rule(id),
      now,
    )
    .await;
    if !ok && let Some(subj) = subject {
      set_firing_delivery(
        state,
        (id.to_string(), subj.to_string()),
        Delivery::Digest,
      )
      .await;
    }
    record_at(
      state,
      now,
      id,
      subject,
      &event,
      ok,
      Some("并入每日汇总".into()),
    )
    .await;
    return;
  }
  let event = if !ok {
    crate::alert_context::enrich(state, id, subject, event).await
  } else {
    event
  };
  let skipped = notify::deliver(state, &event).await;
  if !ok && let Some(subj) = subject {
    set_firing_delivery(
      state,
      (id.to_string(), subj.to_string()),
      Delivery::Urgent,
    )
    .await;
  }
  record_at(state, now, id, subject, &event, ok, skipped).await;
}

/// 关注项被删除或服务停止时，清除告警、确认和通知状态，不发恢复通知。
pub async fn retain_subjects(
  state: &AppState,
  id: &str,
  keep: &BTreeSet<String>,
) {
  let Some(rule) = RULES.iter().find(|r| r.id == id) else {
    return;
  };
  ensure_loaded(state).await;
  let removed = with(|m| {
    let mut removed = BTreeSet::new();
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
    set_firing(state, (id.to_string(), subject.clone()), None).await;
    ack::delete_key(state, id, &subject).await;
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

/// 给“需要注意”条目对上正在触发的告警键和确认状态。
pub fn issue_alert(
  rule: &str,
  subject: &str,
) -> (Option<AlertTarget>, Option<AlertAckView>) {
  let now = now_ms();
  let firing = with(|m| {
    m.firing
      .contains_key(&(rule.to_string(), subject.to_string()))
  });
  if !firing {
    return (None, None);
  }
  (
    Some(AlertTarget {
      rule: rule.to_string(),
      subject: subject.to_string(),
    }),
    ack::view_of(rule, subject, now),
  )
}

#[cfg(test)]
#[path = "rules/tests.rs"]
mod tests;
