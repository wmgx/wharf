//! 告警和事件通知的统一入口。
//!
//! - 告警 = 指标 + 规则：各模块每轮检查只上报数值（[observe]），这里按内置规则判断，
//!   "规则 + 对象"的状态变化（触发 → 恢复）时推送；
//! - 事件通知（定时任务、备份结果、切换入口、新版本）发生就推，只有开关和静默（[notice]）。
//!
//! 规则内置，页面上能改开关、阈值、连续次数、静默，改动存在设置 `alerts.config`。
//! 状态沿用 `notify.state.<key>`（跨重启不重复推）；正在触发的存在 `alert_firing`，
//! 推送记录存在 `alert_history`（保留 7 天）；指标序列只在内存里。

use std::{
  collections::{BTreeMap, VecDeque},
  sync::{Arc, Mutex},
};

use axum::{
  Json,
  extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  view::{
    AlertHistoryView, AlertOptions, AlertPatch, AlertRuleView,
    AlertsView, FiringView, NoticeView, Perm,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  notify::{self, Event},
  state::AppState,
};

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

const RULES: &[Rule] = &[
  Rule {
    id: "server_offline",
    name: "服务器离线",
    metric: "server.online",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    key: |s| format!("agent.{s}"),
    fire: |c| {
      ev(
        format!("服务器 {} 离线", c.subject),
        format!(
          "{} 的 agent 已经 {} 分钟没有连上控制面：可能是机器关机、网络断了或 agent 挂了",
          c.subject, c.for_n
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务器 {} 恢复在线", c.subject),
        format!("{} 的 agent 已经连回控制面", c.subject),
      )
    },
  },
  Rule {
    id: "container_restarting",
    name: "容器反复重启",
    metric: "container.restarting",
    op: Op::Ge,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 2,
    mode: Mode::Window(10),
    recover: None,
    every: "每分钟一次",
    key: |s| format!("restart.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的容器在反复重启", c.subject),
        format!(
          "最近 10 分钟里有 {} 次看到容器处于重启中，多半是启动就崩溃。看日志：wharf service logs {}",
          c.for_n, c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 不再反复重启", c.subject),
        format!("最近 10 分钟没有看到 {} 的容器重启", c.subject),
      )
    },
  },
  Rule {
    id: "monitor_failed",
    name: "服务监控失败",
    metric: "monitor.ok",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    key: |s| format!("monitor.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的监控不正常", c.subject),
        format!(
          "连续 {} 次检查失败（每分钟一次）：{}",
          c.for_n, c.detail
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 的监控恢复正常", c.subject),
        c.detail.to_string(),
      )
    },
  },
  Rule {
    id: "domain_down",
    name: "域名打不开",
    metric: "probe.ok",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 2 分钟一次",
    key: |s| format!("probe.{s}"),
    fire: |c| {
      ev(
        format!("域名 {} 打不开", c.subject),
        format!(
          "连续 {} 次检查失败（每 2 分钟一次）：{}。诊断：wharf doctor {}",
          c.for_n, c.detail, c.subject
        ),
      )
    },
    ok: |c| {
      ev(format!("域名 {} 恢复了", c.subject), c.detail.to_string())
    },
  },
  Rule {
    id: "cert_expiring",
    name: "证书快到期",
    metric: "cert.days",
    op: Op::Lt,
    threshold: crate::cert::WARN_DAYS as f64,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 2 分钟一次",
    key: |s| format!("cert.{s}"),
    fire: |c| {
      ev(
        format!("域名 {} 的证书 {:.0} 天后到期", c.subject, c.value),
        format!("证书还剩 {:.0} 天", c.value),
      )
    },
    ok: |c| {
      ev(
        format!("域名 {} 的证书已续期", c.subject),
        format!("证书还剩 {:.0} 天", c.value),
      )
    },
  },
  Rule {
    id: "link_loss",
    name: "内网链路丢包",
    metric: "link.loss",
    op: Op::Ge,
    threshold: 20.0,
    threshold_editable: true,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 5 分钟一次",
    key: |s| format!("link.{s}"),
    fire: |c| {
      let (from, to) =
        c.subject.split_once('>').unwrap_or((c.subject, ""));
      ev(
        format!("链路 {from} → {to} 丢包严重"),
        format!(
          "{from} 到 {to} 的内网地址连续 {} 轮丢包不低于 {:.0}%（最近一轮 {:.0}%），跨机器的网关转发、构建、备份都会受影响。看详情：wharf network",
          c.for_n, c.threshold, c.value
        ),
      )
    },
    ok: |c| {
      let (from, to) =
        c.subject.split_once('>').unwrap_or((c.subject, ""));
      ev(
        format!("链路 {from} → {to} 恢复"),
        format!("{from} 到 {to} 的内网地址丢包降到 {:.0}%", c.value),
      )
    },
  },
  Rule {
    id: "http_5xx",
    name: "服务 5xx 变多",
    metric: "req.err_pct_5m",
    op: Op::Gt,
    threshold: 10.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: Some(2.0),
    every: "每分钟一次，最近 5 分钟合计",
    key: |s| format!("http5xx.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的 5xx 变多", c.subject),
        format!(
          "最近 5 分钟经网关的请求里 {:.1}% 返回 5xx。看日志：wharf service logs {}",
          c.value, c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 的 5xx 已恢复", c.subject),
        format!("最近 5 分钟 5xx 占比 {:.1}%", c.value),
      )
    },
  },
  Rule {
    id: "host_unit_down",
    name: "宿主机程序停了",
    metric: "hostunit.running",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    key: |s| {
      let (server, unit) = split_unit(s);
      format!("hostunit.{server}.{unit}")
    },
    fire: |c| {
      let (server, unit) = split_unit(c.subject);
      ev(
        format!("{server} 上的 {unit} 停了"),
        format!(
          "状态：{}。看日志：服务器 {server} → 宿主机程序",
          c.detail
        ),
      )
    },
    ok: |c| {
      let (server, unit) = split_unit(c.subject);
      ev(
        format!("{server} 上的 {unit} 恢复运行"),
        format!(
          "状态：{}。看日志：服务器 {server} → 宿主机程序",
          c.detail
        ),
      )
    },
  },
];

/// 事件通知：id 和名称。
const NOTICES: &[(&str, &str)] = &[
  ("task", "定时任务失败和恢复（任务自己也要开通知）"),
  ("backup", "服务备份失败和恢复"),
  ("failover", "网关切到备用入口、切回"),
  ("update", "服务有新版本"),
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
        None => !bad(last),
      };
      if recovered {
        Verdict::Recover
      } else {
        Verdict::Hold
      }
    }
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
  let now = now_ms();
  let points = with(|m| {
    m.series.retain(|_, (_, at)| now - *at < STALE_MS);
    let (p, at) = m
      .series
      .entry((metric.to_string(), subject.to_string()))
      .or_default();
    p.push_back(value);
    while p.len() > KEEP {
      p.pop_front();
    }
    *at = now;
    p.clone()
  });
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
    let (ok, event) = match judge(rule, threshold, for_n, &points) {
      Verdict::Hold => continue,
      Verdict::Fire => {
        let e = (rule.fire)(&ctx);
        set_firing(state, fkey, Some((now, e.title.clone()))).await;
        (false, e)
      }
      Verdict::Recover => {
        set_firing(state, fkey, None).await;
        (true, (rule.ok)(&ctx))
      }
    };
    if notify::transition(state, &(rule.key)(subject), ok).await {
      push(state, rule.id, Some(subject), &o, ok, event).await;
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
  if !o.enabled() {
    record(state, id, &event, ok, Some("已关闭".into())).await;
    return;
  }
  push(state, id, None, &o, ok, event).await;
}

async fn push(
  state: &AppState,
  id: &str,
  subject: Option<&str>,
  o: &Override,
  ok: bool,
  event: Event,
) {
  let skipped = if !o.enabled() {
    Some("已关闭".to_string())
  } else if o.muted(now_ms()) {
    Some("静默中".to_string())
  } else {
    None
  };
  let event = if skipped.is_none() && !ok {
    crate::alert_context::enrich(state, id, subject, event).await
  } else {
    event
  };
  let skipped = match skipped {
    Some(s) => Some(s),
    None => notify::deliver(state, &event).await,
  };
  record(state, id, &event, ok, skipped).await;
}

/// 开始触发（已经在触发就保留原来的开始时间）或结束触发，内存和库一起改。
async fn set_firing(
  state: &AppState,
  key: (String, String),
  fire: Option<(i64, String)>,
) {
  let changed = with(|m| match &fire {
    Some(v) if !m.firing.contains_key(&key) => {
      m.firing.insert(key.clone(), v.clone());
      true
    }
    Some(_) => false,
    None => m.firing.remove(&key).is_some(),
  });
  if !changed {
    return;
  }
  let result = state
    .db
    .call(move |c| {
      let (rule, subject) = key;
      match fire {
        Some((since, title)) => c.execute(
          "INSERT OR REPLACE INTO alert_firing (rule, subject, since, title) VALUES (?1, ?2, ?3, ?4)",
          rusqlite::params![rule, subject, since, title],
        ),
        None => c.execute(
          "DELETE FROM alert_firing WHERE rule = ?1 AND subject = ?2",
          rusqlite::params![rule, subject],
        ),
      }
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录正在触发的告警失败：{}", e.message);
  }
}

/// 记一条推送，顺手删掉 7 天前的。
async fn record(
  state: &AppState,
  id: &str,
  event: &Event,
  ok: bool,
  skipped: Option<String>,
) {
  let (id, title) = (id.to_string(), event.title.clone());
  let now = now_ms();
  let result = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO alert_history (at, source, title, ok, skipped) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![now, id, title, ok, skipped],
      )
      .and_then(|_| {
        c.execute(
          "DELETE FROM alert_history WHERE at < ?1",
          [now - KEEP_HISTORY_MS],
        )
      })
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录推送失败：{}", e.message);
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

/// 某条规则正在触发的标题，给"需要注意"用。
pub fn firing(rule: &str) -> Vec<String> {
  with(|m| {
    m.firing
      .iter()
      .filter(|((r, _), _)| r == rule)
      .map(|(_, (_, t))| t.clone())
      .collect()
  })
}

async fn view(state: &AppState) -> Result<AlertsView, ApiError> {
  let include_logs = state
    .db
    .call(|c| db::setting(c, "alerts.include_logs"))
    .await?
    .is_some();
  let cfg = config(state).await;
  let now = now_ms();
  let muted = |o: &Override| o.muted_until.filter(|t| *t > now);
  let rules = RULES
    .iter()
    .map(|r| {
      let o = cfg.get(r.id).cloned().unwrap_or_default();
      let threshold = o.threshold.unwrap_or(r.threshold);
      let for_n = o.for_n.unwrap_or(r.for_n);
      let times = match r.mode {
        Mode::Consecutive => format!("连续 {for_n} 次"),
        Mode::Window(w) => format!("最近 {w} 次里有 {for_n} 次"),
      };
      AlertRuleView {
        id: r.id.into(),
        name: r.name.into(),
        metric: r.metric.into(),
        condition: format!(
          "{} {} {threshold} {times}（{}）",
          r.metric,
          r.op.text(),
          r.every
        ),
        op: r.op.text().into(),
        threshold,
        for_n,
        threshold_editable: r.threshold_editable,
        enabled: o.enabled(),
        muted_until: muted(&o),
        customized: o.threshold.is_some()
          || o.for_n.is_some()
          || o.enabled == Some(false),
      }
    })
    .collect();
  let notices = NOTICES
    .iter()
    .map(|(id, name)| {
      let o = cfg.get(*id).cloned().unwrap_or_default();
      NoticeView {
        id: (*id).into(),
        name: (*name).into(),
        enabled: o.enabled(),
        muted_until: muted(&o),
      }
    })
    .collect();
  let history = history(state).await;
  Ok(with(|m| AlertsView {
    include_logs,
    rules,
    notices,
    firing: m
      .firing
      .iter()
      .map(|((rule, subject), (since, title))| FiringView {
        rule: rule.clone(),
        subject: subject.clone(),
        title: title.clone(),
        since: *since,
      })
      .collect(),
    history,
  }))
}

/// `GET /api/alerts`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Read)?;
  Ok(Json(view(&s).await?))
}

/// `PUT /api/alerts/{id}`：规则或事件通知的开关、阈值、连续次数、静默。
pub async fn patch(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
  Json(p): Json<AlertPatch>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  let rule = RULES.iter().find(|r| r.id == id);
  if rule.is_none() && !NOTICES.iter().any(|(n, _)| *n == id) {
    let ids: Vec<&str> = RULES
      .iter()
      .map(|r| r.id)
      .chain(NOTICES.iter().map(|n| n.0))
      .collect();
    return Err(
      ApiError::not_found(format!("没有告警 {id}"))
        .with_hint(format!("可选：{}", ids.join("、")))
        .into(),
    );
  }
  if rule.is_none() && (p.threshold.is_some() || p.for_n.is_some()) {
    return Err(
      ApiError::invalid("事件通知没有阈值和连续次数，只能开关和静默")
        .into(),
    );
  }
  if let Some(r) = rule {
    if p.threshold.is_some() && !r.threshold_editable {
      return Err(
        ApiError::invalid(format!(
          "{} 的阈值固定，改连续次数",
          r.name
        ))
        .into(),
      );
    }
    if p.threshold.is_some_and(|t| !t.is_finite()) {
      return Err(ApiError::invalid("阈值要是数字").into());
    }
    if p.for_n.is_some_and(|n| n == 0 || n as usize > KEEP) {
      return Err(
        ApiError::invalid(format!("连续次数在 1 到 {KEEP} 之间"))
          .into(),
      );
    }
  }
  let mut cfg = config(&s).await;
  let o = cfg.entry(id.clone()).or_default();
  if p.reset {
    *o = Override::default();
  }
  if let Some(v) = p.enabled {
    o.enabled = (!v).then_some(false);
  }
  if let Some(t) = p.threshold {
    o.threshold = rule.filter(|r| r.threshold != t).map(|_| t);
  }
  if let Some(n) = p.for_n {
    o.for_n = rule.filter(|r| r.for_n != n).map(|_| n);
  }
  if let Some(m) = p.mute_minutes {
    o.muted_until = (m > 0).then(|| now_ms() + i64::from(m) * 60_000);
  }
  cfg.retain(|_, o| {
    o.enabled.is_some()
      || o.threshold.is_some()
      || o.for_n.is_some()
      || o.muted_until.is_some()
  });
  let json = serde_json::to_string(&cfg)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  s.db
    .call(move |c| db::set_setting(c, CONFIG_KEY, Some(&json)))
    .await?;
  with(|m| m.config = Some(cfg));
  Ok(Json(view(&s).await?))
}

/// `PUT /api/alerts/options`：触发的告警是否附带服务日志。
pub async fn set_options(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(o): Json<AlertOptions>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  s.db
    .call(move |c| {
      db::set_setting(
        c,
        "alerts.include_logs",
        o.include_logs.then_some("1"),
      )
    })
    .await?;
  Ok(Json(view(&s).await?))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn rule(id: &str) -> &'static Rule {
    RULES.iter().find(|r| r.id == id).unwrap()
  }

  fn v(points: &[f64]) -> VecDeque<f64> {
    points.iter().copied().collect()
  }

  #[test]
  fn consecutive_fires_after_n_and_recovers_on_good() {
    let r = rule("server_offline");
    assert!(matches!(
      judge(r, 1.0, 3, &v(&[1.0, 0.0, 0.0])),
      Verdict::Hold
    ));
    assert!(matches!(
      judge(r, 1.0, 3, &v(&[0.0, 0.0, 0.0])),
      Verdict::Fire
    ));
    assert!(matches!(
      judge(r, 1.0, 3, &v(&[0.0, 0.0, 1.0])),
      Verdict::Recover
    ));
  }

  #[test]
  fn window_and_hysteresis() {
    let r = rule("container_restarting");
    assert!(matches!(
      judge(r, 1.0, 2, &v(&[1.0, 0.0, 1.0])),
      Verdict::Fire
    ));
    assert!(matches!(
      judge(r, 1.0, 2, &v(&[1.0, 0.0, 0.0])),
      Verdict::Hold
    ));
    assert!(matches!(
      judge(r, 1.0, 2, &v(&[0.0, 0.0])),
      Verdict::Recover
    ));
    let h = rule("http_5xx");
    assert!(matches!(judge(h, 10.0, 1, &v(&[12.0])), Verdict::Fire));
    assert!(matches!(judge(h, 10.0, 1, &v(&[5.0])), Verdict::Hold));
    assert!(matches!(
      judge(h, 10.0, 1, &v(&[1.0])),
      Verdict::Recover
    ));
  }
}
