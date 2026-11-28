//! 打点：一张通用的表，每个点是（名称，对象，时间，数值）。
//! - `host.*`：服务器资源，对象是服务器名，agent 每分钟上报；
//! - `svc.*`：服务（compose project）的容器资源，对象是 project 名；
//! - `link.*`：机器之间的链路质量，对象是 `<from>><to>`，见 quality.rs；
//! - `req.*`：经网关的请求，对象是服务名，见 http_stats.rs；
//! - 其余是事件：部署、备份的耗时和结果，自动重启，对象是服务名。
//!
//! 资源点 24 小时后合成 10 分钟一个，7 天后合成每小时一个，保留 14 天；事件保留 90 天。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Query, State},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{ApiError, agent::Metrics, view::Perm};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{now_ms, sql_err},
  planner::Step,
  state::AppState,
};

pub(crate) const MINUTE_MS: i64 = 60 * 1000;
pub(crate) const COARSE_MS: i64 = 10 * MINUTE_MS;
pub(crate) const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
const COARSE_KEEP_MS: i64 = 7 * DAY_MS;
#[cfg(test)]
const KEEP_RESOURCE_MS: i64 = 14 * DAY_MS;

/// 合成和按时间段平均的只有资源点，事件点原样保留。
const RESOURCE: &str = "(name LIKE 'host.%' OR name LIKE 'svc.%' OR name LIKE 'link.%' OR name LIKE 'req.%' OR name LIKE 'agent.%')";

fn insert(
  c: &Connection,
  at: i64,
  points: &[(&str, &str, f64)],
) -> Result<(), ApiError> {
  let mut stmt = c
    .prepare_cached(
      "INSERT OR REPLACE INTO points (name, subject, at, value) VALUES (?1, ?2, ?3, ?4)",
    )
    .map_err(sql_err)?;
  for (name, subject, value) in points {
    stmt
      .execute(params![name, subject, at, value])
      .map_err(sql_err)?;
  }
  Ok(())
}

/// 记一批现在的点，失败只记日志。
pub async fn insert_owned_at(
  state: &AppState,
  at: i64,
  points: Vec<(String, String, f64)>,
) {
  if points.is_empty() {
    return;
  }
  let result = state
    .db
    .call(move |c| {
      let rows: Vec<(&str, &str, f64)> = points
        .iter()
        .map(|(n, s, v)| (n.as_str(), s.as_str(), *v))
        .collect();
      let tx = c.transaction().map_err(sql_err)?;
      insert(&tx, at, &rows)?;
      tx.commit().map_err(sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录请求打点失败：{e}");
  }
}

/// 一轮链路质量：`link.loss`（丢包率），成功过才记 `link.ms`。
pub async fn record_links(
  state: &AppState,
  links: &[wharf_api_types::view::LinkView],
) {
  let rows: Vec<(String, String, f64)> = links
    .iter()
    .flat_map(|l| {
      let subject = format!("{}>{}", l.from, l.to);
      let mut v =
        vec![("link.loss".to_string(), subject.clone(), l.loss)];
      if let Some(ms) = l.ms {
        v.push(("link.ms".to_string(), subject, ms));
      }
      v
    })
    .collect();
  let result = state
    .db
    .call(move |c| {
      let points: Vec<(&str, &str, f64)> = rows
        .iter()
        .map(|(n, s, v)| (n.as_str(), s.as_str(), *v))
        .collect();
      let tx = c.transaction().map_err(sql_err)?;
      insert(&tx, now_ms(), &points)?;
      tx.commit().map_err(sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录链路质量失败：{}", e.message);
  }
}

/// agent 上报的资源采样。
pub async fn record_report_at(
  state: &AppState,
  server: &str,
  at: i64,
  m: &Metrics,
) {
  let owned = server.to_string();
  let m = m.clone();
  let result = state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let s = owned.as_str();
      crate::traffic::add(
        &tx,
        s,
        at,
        (m.net_rx, m.net_tx),
        m.net_rx_bytes.zip(m.net_tx_bytes),
      )?;
      insert(
        &tx,
        at,
        &[
          ("host.cpu", s, m.cpu as f64),
          ("host.mem", s, m.mem_used as f64),
          ("host.mem_total", s, m.mem_total as f64),
          ("host.net_rx", s, m.net_rx as f64),
          ("host.net_tx", s, m.net_tx as f64),
          ("host.disk", s, m.disk_used as f64),
          ("host.disk_total", s, m.disk_total as f64),
        ],
      )?;
      let inode_pct =
        m.inode_used.zip(m.inode_total).and_then(|(used, total)| {
          wharf_api_types::resources::percent(used, total)
        });
      for (name, value) in [
        ("host.inode_pct", inode_pct),
        ("agent.cpu", m.agent_cpu.map(f64::from)),
        ("agent.mem", m.agent_mem.map(|v| v as f64)),
      ] {
        if let Some(value) = value {
          insert(&tx, at, &[(name, s, value)])?;
        }
      }
      for (p, v) in &m.projects {
        let p = p.as_str();
        if let Some(cores) = m.cpu_cores {
          insert(
            &tx,
            at,
            &[(
              "svc.cpu.cores",
              p,
              f64::from(v.cpu) * f64::from(cores) / 100.0,
            )],
          )?;
        }
        if let Some(count) = v.containers {
          insert(
            &tx,
            at,
            &[("svc.containers.max", p, f64::from(count))],
          )?;
        }
        record_components(&tx, p, s, at, &v.components)?;
        insert(
          &tx,
          at,
          &[
            ("svc.cpu", p, v.cpu as f64),
            ("svc.mem", p, v.mem as f64),
            ("svc.net_rx", p, v.net_rx as f64),
            ("svc.net_tx", p, v.net_tx as f64),
          ],
        )?;
      }
      tx.commit().map_err(sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录 {server} 的资源采样失败：{e}");
  }
}

pub(crate) fn component_subject(
  instance: &str,
  server: &str,
  component: &str,
) -> String {
  serde_json::json!([instance, server, component]).to_string()
}

fn record_components(
  c: &Connection,
  service: &str,
  server: &str,
  at: i64,
  components: &BTreeMap<
    String,
    wharf_api_types::agent::ComponentMetrics,
  >,
) -> Result<(), ApiError> {
  if components.is_empty() {
    return Ok(());
  }
  let record: Option<(String, String)> = c.query_row(
    "SELECT d.instance_id, d.spec FROM resources r JOIN deployments d
       ON d.service = r.name AND d.instance_id = json_extract(r.meta, '$.instance_id')
     WHERE r.kind = 'service' AND r.name = ?1
       AND d.id = (SELECT latest.id FROM deployments latest
                   WHERE latest.service = r.name AND latest.instance_id = d.instance_id
                     AND latest.created_at <= ?3
                   ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1)
       AND d.server = ?2 AND d.spec IS NOT NULL",
    params![service, server, at],
    |row| Ok((row.get(0)?, row.get(1)?)),
  ).optional().map_err(sql_err)?;
  let Some((instance, spec)) = record else {
    return Ok(());
  };
  let Ok(spec) =
    serde_json::from_str::<wharf_api_types::spec::ServiceSpec>(&spec)
  else {
    return Ok(());
  };
  let wharf_api_types::spec::Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
  else {
    return Ok(());
  };
  let Ok(compose) = crate::render::parse_compose(content) else {
    return Ok(());
  };
  for (name, value) in components {
    if !compose["services"]
      .as_mapping()
      .is_some_and(|services| services.contains_key(name.as_str()))
    {
      continue;
    }
    let subject = component_subject(&instance, server, name);
    insert(
      c,
      at,
      &[
        ("svc.component.cpu.max", &subject, f64::from(value.cpu)),
        ("svc.component.mem.max", &subject, value.mem as f64),
      ],
    )?;
  }
  Ok(())
}

pub(crate) fn component_peaks(
  c: &Connection,
  subject: &str,
) -> Result<(Option<f64>, Option<u64>), ApiError> {
  c.query_row("SELECT MAX(CASE WHEN name = 'svc.component.cpu.max' THEN value END),
           MAX(CASE WHEN name = 'svc.component.mem.max' THEN value END)
       FROM points WHERE subject = ?1 AND at >= ?2
         AND name IN ('svc.component.cpu.max', 'svc.component.mem.max')",
    params![subject, now_ms() - 7 * DAY_MS], |r| {
      Ok((r.get(0)?, r.get::<_, Option<f64>>(1)?.map(|value| value as u64)))
    },
  ).map_err(sql_err)
}

/// 记一个事件点，失败只记日志。
pub async fn event(
  state: &AppState,
  name: &str,
  subject: &str,
  value: f64,
) {
  event_at(state, now_ms(), name, subject, value).await;
}

pub async fn event_at(
  state: &AppState,
  at: i64,
  name: &str,
  subject: &str,
  value: f64,
) {
  let (n, s) = (name.to_string(), subject.to_string());
  let result = state
    .db
    .call(move |c| insert(c, at, &[(&n, &s, value)]))
    .await;
  if let Err(e) = result {
    tracing::warn!("记录 {name} 失败：{e}");
  }
}

/// 执行完一个步骤：部署和备份记耗时，失败另记一个点。
pub async fn step_done(
  state: &AppState,
  step: &Step,
  took: Duration,
  ok: bool,
) {
  let (kind, subject) = match step {
    Step::ServiceLimitsUpdate { job, .. } => {
      ("deploy", job.project.as_str())
    }
    Step::ServiceUp { service, .. } | Step::Rebuild { service } => {
      ("deploy", service.as_str())
    }
    Step::Backup { service, .. } => ("backup", service.as_str()),
    Step::CoreBackup { .. } => ("backup", crate::core_backup::REPO),
    _ => return,
  };
  if ok {
    event(
      state,
      &format!("{kind}.secs"),
      subject,
      took.as_secs_f64(),
    )
    .await;
  } else {
    event(state, &format!("{kind}.fail"), subject, 1.0).await;
  }
}

/// 定时任务调用：旧的资源点先合成 10 分钟均值，超过 7 天再合成每小时均值，删掉过期的点。
pub async fn compact(state: &AppState) -> Result<(), ApiError> {
  state.db.call(|c| compact_at(c, now_ms())).await
}

const PEAK_METRICS: &str =
  "name IN ('host.cpu', 'host.mem', 'svc.mem')";
const MAX_SUFFIX: &str = "name LIKE '%.max'";

pub(crate) fn cutoffs(now: i64) -> (i64, i64) {
  (
    (now - DAY_MS) / COARSE_MS * COARSE_MS,
    (now - COARSE_KEEP_MS) / HOUR_MS * HOUR_MS,
  )
}

pub(crate) fn compact_at(
  c: &mut Connection,
  now: i64,
) -> Result<(), ApiError> {
  // 对齐到 10 分钟和整点，保证每个时间段一次合成完。合成后的点时间正好对齐，
  // 通过 `at % bucket != 0` 判断该桶里是否还有更细粒度的点需要合成并清理。
  let (coarse_cutoff, hourly_cutoff) = cutoffs(now);
  let tx = c.transaction().map_err(sql_err)?;
  tx.execute(
    &format!(
      "INSERT INTO points (name, subject, at, value)
       SELECT name || '.max', subject, at / ?2 * ?2, MAX(value) FROM points
       WHERE at < ?1 AND {PEAK_METRICS}
       GROUP BY name, subject, at / ?2
       HAVING SUM(CASE WHEN at % ?2 != 0 THEN 1 ELSE 0 END) > 0
       ON CONFLICT (subject, name, at) DO UPDATE SET value = MAX(value, excluded.value)"
    ),
    params![coarse_cutoff, COARSE_MS],
  ).map_err(sql_err)?;
  for (cutoff, bucket) in
    [(coarse_cutoff, COARSE_MS), (hourly_cutoff, HOUR_MS)]
  {
    tx.execute(
      &format!(
        "INSERT OR REPLACE INTO points (name, subject, at, value)
         SELECT name, subject, at / ?2 * ?2, CASE WHEN {MAX_SUFFIX} THEN MAX(value) ELSE AVG(value) END
         FROM points WHERE at < ?1 AND {RESOURCE}
         GROUP BY name, subject, at / ?2
         HAVING SUM(CASE WHEN at % ?2 != 0 THEN 1 ELSE 0 END) > 0"
      ),
      params![cutoff, bucket],
    ).map_err(sql_err)?;
    tx.execute(
      &format!("DELETE FROM points WHERE at < ?1 AND at % ?2 != 0 AND {RESOURCE}"),
      params![cutoff, bucket],
    ).map_err(sql_err)?;
  }
  tx.execute(
    &format!("DELETE FROM points WHERE at < ?1 AND {RESOURCE}"),
    params![
      now
        - i64::from(crate::config_api::number(
          &tx,
          "retention.metrics_days"
        )?)
          * DAY_MS
    ],
  )
  .map_err(sql_err)?;
  tx.execute(
    &format!("DELETE FROM points WHERE at < ?1 AND NOT {RESOURCE}"),
    params![
      now
        - i64::from(crate::config_api::number(
          &tx,
          "retention.events_days"
        )?)
          * DAY_MS
    ],
  )
  .map_err(sql_err)?;
  tx.commit().map_err(sql_err)
}

#[derive(Deserialize)]
pub struct MetricsQuery {
  /// 服务器名或服务名。
  pub subject: String,
  /// 逗号分隔；不给时按对象类型给资源点（`host.*` 或 `svc.*`）和事件。
  pub names: Option<String>,
  /// `1h`、`24h`（默认）、`7d`、`14d`、`30d`。
  pub range: Option<String>,
}

#[derive(Serialize)]
pub struct MetricsView {
  pub subject: String,
  pub from: i64,
  pub to: i64,
  /// 资源点按这个间隔平均。
  pub step_ms: i64,
  /// 名称到 `[时间, 数值]`。
  pub series: BTreeMap<String, Vec<(i64, f64)>>,
}

fn range_ms(range: &str) -> Result<(i64, i64), ApiError> {
  // 每个范围大约 150 到 336 个点。
  Ok(match range {
    "1h" => (3600 * 1000, MINUTE_MS),
    "24h" => (DAY_MS, 5 * MINUTE_MS),
    "7d" => (7 * DAY_MS, 30 * MINUTE_MS),
    "14d" => (14 * DAY_MS, HOUR_MS),
    "30d" => (30 * DAY_MS, 3 * HOUR_MS),
    other => {
      return Err(ApiError::invalid(format!(
        "范围 {other} 不认识，可以是 1h、24h、7d、14d、30d"
      )));
    }
  })
}

/// `GET /api/metrics?subject=&names=&range=`
pub async fn query(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<MetricsQuery>,
) -> ApiResult<MetricsView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &q.subject)?;
  let (span, step) = range_ms(q.range.as_deref().unwrap_or("24h"))?;
  let names: Vec<String> = q
    .names
    .as_deref()
    .map(|n| {
      n.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
    })
    .unwrap_or_default();
  let to = now_ms();
  let from = to - span;
  let subject = q.subject.clone();
  let mut series = s
    .db
    .call(move |c| read(c, &subject, &names, from, step))
    .await?;
  if auth.services.is_some() {
    series.retain(|name, _| {
      !name.starts_with("host.")
        && !name.starts_with("agent.")
        && !name.starts_with("link.")
    });
  }
  Ok(Json(MetricsView {
    subject: q.subject,
    from,
    to,
    step_ms: step,
    series,
  }))
}

type Series = BTreeMap<String, Vec<(i64, f64)>>;

pub(crate) fn read(
  c: &Connection,
  subject: &str,
  names: &[String],
  from: i64,
  step: i64,
) -> Result<Series, ApiError> {
  let wanted = |name: &str| {
    if names.is_empty() {
      !name.ends_with(".max")
    } else {
      names.iter().any(|n| n == name)
    }
  };
  let mut out: Series = BTreeMap::new();
  let mut stmt = c
    .prepare_cached(&format!(
      "SELECT name, at / ?3 * ?3 AS t, AVG(value) FROM points
       WHERE subject = ?1 AND at >= ?2 AND {RESOURCE}
       GROUP BY name, t ORDER BY name, t"
    ))
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![subject, from, step], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, i64>(1)?,
        r.get::<_, f64>(2)?,
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (name, at, v) = row.map_err(sql_err)?;
    if wanted(&name) {
      out.entry(name).or_default().push((at, v));
    }
  }
  let mut stmt = c
    .prepare_cached(&format!(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND NOT {RESOURCE} ORDER BY name, at"
    ))
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![subject, from], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, i64>(1)?,
        r.get::<_, f64>(2)?,
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (name, at, v) = row.map_err(sql_err)?;
    if wanted(&name) {
      out.entry(name).or_default().push((at, v));
    }
  }
  Ok(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn component_peaks_preserve_maxima_and_instance_identity() {
    let db = crate::db::Db::memory();
    let peaks = db
      .call(|c| {
        let now = now_ms();
        let old = (now - 2 * DAY_MS) / COARSE_MS * COARSE_MS;
        let subject = component_subject("svc_fixture", "s1", "db");
        insert(
          c,
          old + 1,
          &[
            ("svc.component.cpu.max", &subject, 25.0),
            ("svc.component.mem.max", &subject, 512.0),
          ],
        )?;
        insert(
          c,
          old + 2,
          &[
            ("svc.component.cpu.max", &subject, 75.0),
            ("svc.component.mem.max", &subject, 256.0),
          ],
        )?;
        insert(
          c,
          now,
          &[(
            "svc.component.mem.max",
            &component_subject("svc_other", "s1", "db"),
            1024.0,
          )],
        )?;
        compact_at(c, now)?;
        Ok((
          component_peaks(c, &subject)?,
          component_peaks(
            c,
            &component_subject("svc_fixture", "s2", "db"),
          )?,
        ))
      })
      .await
      .unwrap();
    assert_eq!(peaks, ((Some(75.0), Some(512)), (None, None)));
  }

  #[tokio::test]
  async fn late_component_sample_matches_deployment_at_sample_time() {
    use wharf_api_types::agent::ComponentMetrics;
    let db = crate::db::Db::memory();
    db.call(|c| {
      c.execute_batch(
        r#"INSERT INTO resources (kind,name,spec,meta,version,created_at,updated_at)
         VALUES ('service','app','{}','{"instance_id":"svc_fixture"}',1,0,0);"#,
      ).map_err(sql_err)?;
      let now = now_ms();
      let spec = |server: &str| serde_json::json!({
        "server":server, "source":{"compose":{"content":"services: {db: {image: db}}"}}
      }).to_string();
      for (server, time) in [("s1", now - 3000), ("s1", now - 2000), ("s2", now - 1000)] {
        c.execute(
          "INSERT INTO deployments (service,server,run_id,hash,compose,images,created_at,spec,instance_id)
           VALUES ('app',?1,'run','hash','','[]',?2,?3,'svc_fixture')",
          params![server, time, spec(server)],
        ).map_err(sql_err)?;
      }
      let sample = BTreeMap::from([("db".into(), ComponentMetrics { cpu: 75.0, mem: 512 })]);
      record_components(c, "app", "s1", now - 2500, &sample)?;
      assert_eq!(component_peaks(c, &component_subject("svc_fixture", "s1", "db"))?, (Some(75.0), Some(512)));
      let obsolete = BTreeMap::from([("db".into(), ComponentMetrics { cpu: 100.0, mem: 1024 })]);
      record_components(c, "app", "s1", now, &obsolete)?;
      assert_eq!(component_peaks(c, &component_subject("svc_fixture", "s1", "db"))?, (Some(75.0), Some(512)));
      Ok(())
    }).await.unwrap();
  }

  #[tokio::test]
  async fn compact_averages_old_points() {
    let db = crate::db::Db::memory();
    let s = db
      .call(|c| {
        let now = now_ms();
        let old = (now - 2 * DAY_MS) / COARSE_MS * COARSE_MS;
        insert(
          c,
          old + 1,
          &[("host.cpu", "a", 10.0), ("deploy.secs", "a", 5.0)],
        )?;
        insert(
          c,
          old + 2,
          &[("host.cpu", "a", 30.0), ("deploy.secs", "a", 7.0)],
        )?;
        insert(c, now - 15 * DAY_MS, &[("host.cpu", "a", 99.0)])?;
        insert(c, now, &[("host.cpu", "a", 50.0)])?;
        compact_at(c, now)?;
        Ok((old, now, read(c, "a", &[], 0, 1)?))
      })
      .await
      .unwrap();
    let (old, now, series) = s;
    assert_eq!(series["host.cpu"], vec![(old, 20.0), (now, 50.0)]);
    assert_eq!(series["deploy.secs"].len(), 2);
  }

  #[tokio::test]
  async fn compact_tiered_15_days() {
    let db = crate::db::Db::memory();
    let now = 1_700_000_000_000 / HOUR_MS * HOUR_MS + 123_456;
    let coarse_cutoff = (now - DAY_MS) / COARSE_MS * COARSE_MS;
    let hourly_cutoff = (now - COARSE_KEEP_MS) / HOUR_MS * HOUR_MS;
    let keep_cutoff = now - KEEP_RESOURCE_MS;
    let target_hour = (now - 10 * DAY_MS) / HOUR_MS * HOUR_MS;

    let points = db
      .call(move |c| {
        // 15 天前（超出 14 天保留期，应被删除）
        insert(c, now - 15 * DAY_MS, &[("host.cpu", "s1", 99.0)])?;
        insert(
          c,
          now - 14 * DAY_MS - HOUR_MS,
          &[("host.cpu", "s1", 88.0)],
        )?;
        // 7～14 天：在 target_hour 造 6 个 10 分钟桶（每个桶有 1～2 个原始点），
        // 10 分钟均值依次为 15, 30, 45, 60, 75, 90，整点均值应为 52.5。
        insert(c, target_hour + 1_000, &[("host.cpu", "s1", 10.0)])?;
        insert(c, target_hour + 2_000, &[("host.cpu", "s1", 20.0)])?;
        insert(
          c,
          target_hour + COARSE_MS + 1_000,
          &[("host.cpu", "s1", 25.0)],
        )?;
        insert(
          c,
          target_hour + COARSE_MS + 2_000,
          &[("host.cpu", "s1", 35.0)],
        )?;
        for (slot, val) in
          [(2, 45.0), (3, 60.0), (4, 75.0), (5, 90.0)]
        {
          insert(
            c,
            target_hour + slot * COARSE_MS + 1_000,
            &[("host.cpu", "s1", val)],
          )?;
        }
        // 8 天前与 13 天前再各补一点，验证整段 7～14 天全部对齐到整点。
        for d in [8, 13] {
          let h = (now - d * DAY_MS) / HOUR_MS * HOUR_MS;
          insert(c, h + 1_000, &[("host.cpu", "s1", 20.0)])?;
          insert(
            c,
            h + 2 * COARSE_MS + 1_000,
            &[("host.cpu", "s1", 40.0)],
          )?;
        }
        // 1～7 天：2 天前与 5 天前的原始点，应合成 10 分钟点。
        let t_mid = (now - 3 * DAY_MS) / COARSE_MS * COARSE_MS;
        insert(c, t_mid + 1_000, &[("host.cpu", "s1", 10.0)])?;
        insert(c, t_mid + 2_000, &[("host.cpu", "s1", 30.0)])?;
        insert(
          c,
          t_mid + COARSE_MS + 1_000,
          &[("host.cpu", "s1", 50.0)],
        )?;
        // 1 天内：原始点原样保留。
        let t_recent1 = now - 6 * HOUR_MS + 111;
        let t_recent2 = now - 6 * HOUR_MS + 222;
        insert(c, t_recent1, &[("host.cpu", "s1", 12.0)])?;
        insert(c, t_recent2, &[("host.cpu", "s1", 34.0)])?;

        // 连续压缩两次验证幂等性。
        compact_at(c, now)?;
        compact_at(c, now)?;
        let mut stmt = c
          .prepare(
            "SELECT at, value FROM points
             WHERE subject = 's1' AND name = 'host.cpu' ORDER BY at",
          )
          .map_err(sql_err)?;
        let rows = stmt
          .query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?))
          })
          .and_then(Iterator::collect::<Result<Vec<_>, _>>)
          .map_err(sql_err)?;
        Ok(rows)
      })
      .await
      .unwrap();

    // 14 天前没有任何点。
    assert!(points.iter().all(|(at, _)| *at >= keep_cutoff));
    // 7～14 天全是整点，且 target_hour 均值为 52.5。
    let hourly: Vec<_> = points
      .iter()
      .copied()
      .filter(|(at, _)| *at < hourly_cutoff)
      .collect();
    assert_eq!(hourly.len(), 3);
    assert!(hourly.iter().all(|(at, _)| at % HOUR_MS == 0));
    let target_val =
      hourly.iter().find(|(at, _)| *at == target_hour).unwrap().1;
    assert!((target_val - 52.5).abs() < 1e-9);
    // 1～7 天全是 10 分钟点。
    let coarse: Vec<_> = points
      .iter()
      .copied()
      .filter(|(at, _)| *at >= hourly_cutoff && *at < coarse_cutoff)
      .collect();
    assert_eq!(coarse.len(), 2);
    assert!(coarse.iter().all(|(at, _)| at % COARSE_MS == 0));
    assert!((coarse[0].1 - 20.0).abs() < 1e-9);
    assert!((coarse[1].1 - 50.0).abs() < 1e-9);
    // 1 天内仍是原始点（未对齐）。
    let recent: Vec<_> = points
      .iter()
      .copied()
      .filter(|(at, _)| *at >= coarse_cutoff)
      .collect();
    assert_eq!(recent.len(), 2);
    assert!(recent.iter().all(|(at, _)| at % COARSE_MS != 0));
  }
}

#[derive(Deserialize)]
pub struct UsageQuery {
  pub server: String,
}

/// 一个服务（或网关）最近 10 分钟的平均用量。
#[derive(Serialize)]
pub struct Usage {
  pub name: String,
  /// `service`、`gateway` 或 `agent`。
  pub kind: &'static str,
  pub cpu: Option<f64>,
  pub mem: Option<f64>,
  pub net_rx: Option<f64>,
  pub net_tx: Option<f64>,
}

/// `GET /api/metrics/usage?server=`：这台服务器上各服务的资源用量，按内存从大到小。
pub async fn usage(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<UsageQuery>,
) -> ApiResult<Vec<Usage>> {
  auth.require(Perm::Read)?;
  let snap = crate::snapshot::load(&s.db).await?;
  let mut subjects: Vec<(String, String, &'static str)> = snap
    .world
    .services
    .iter()
    .filter(|(n, _)| {
      crate::snapshot::service_runtime_server(&snap, n)
        == Some(q.server.as_str())
    })
    .map(|(n, _)| (n.clone(), n.clone(), "service"))
    .collect();
  subjects.extend(
    snap
      .world
      .gateways
      .iter()
      .filter(|(_, g)| g.spec.server == q.server)
      .map(|(n, _)| {
        (crate::world::gateway_project(n), n.clone(), "gateway")
      }),
  );
  let server = q.server;
  let agent_subject = server.clone();
  let from = now_ms() - 10 * 60 * 1000;
  let avg: BTreeMap<(String, String), f64> = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT name, subject, AVG(value) FROM points
           WHERE at >= ?1 AND (name LIKE 'svc.%' OR (name LIKE 'agent.%' AND subject = ?2))
           GROUP BY name, subject",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![from, server], |r| {
          Ok(((r.get::<_, String>(0)?, r.get::<_, String>(1)?), r.get(2)?))
        })
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  let get = |metric: &str, subject: &str| {
    avg
      .get(&(format!("svc.{metric}"), subject.to_string()))
      .copied()
      .unwrap_or(0.0)
  };
  let mut out: Vec<Usage> = subjects
    .into_iter()
    .map(|(subject, name, kind)| Usage {
      cpu: Some(get("cpu", &subject)),
      mem: Some(get("mem", &subject)),
      net_rx: Some(get("net_rx", &subject)),
      net_tx: Some(get("net_tx", &subject)),
      name,
      kind,
    })
    .collect();
  let agent_value = |metric: &str| {
    avg
      .get(&(format!("agent.{metric}"), agent_subject.clone()))
      .copied()
  };
  let cpu = agent_value("cpu");
  let mem = agent_value("mem");
  if cpu.is_some() || mem.is_some() {
    out.push(Usage {
      name: "wharf-agent".into(),
      kind: "agent",
      cpu,
      mem,
      net_rx: None,
      net_tx: None,
    });
  }
  out.sort_by(|a, b| {
    b.mem.unwrap_or(-1.0).total_cmp(&a.mem.unwrap_or(-1.0))
  });
  Ok(Json(out))
}

#[cfg(test)]
#[tokio::test]
async fn report_metrics_roll_back_traffic_if_point_write_fails() {
  let state = crate::rules::tests::test_state();
  state.db.call(|c| c.execute_batch(
    "CREATE TRIGGER reject_point BEFORE INSERT ON points WHEN NEW.name='host.net_rx' BEGIN SELECT RAISE(ABORT,'test'); END;"
  ).map_err(sql_err)).await.unwrap();
  record_report_at(
    &state,
    "s1",
    now_ms(),
    &Metrics {
      net_rx_bytes: Some(1000),
      net_tx_bytes: Some(100),
      ..Default::default()
    },
  )
  .await;
  state
    .db
    .call(|c| {
      let points: i64 = c
        .query_row("SELECT count(*) FROM points", [], |r| r.get(0))
        .map_err(sql_err)?;
      assert_eq!(points, 0);
      Ok(())
    })
    .await
    .unwrap();
}
