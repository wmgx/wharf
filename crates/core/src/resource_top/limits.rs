use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Query, State},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  resources::{LimitEvidence, LimitSuggestion},
  spec::{ServiceSpec, Source},
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, sql_err},
  metrics::{COARSE_MS, HOUR_MS, MINUTE_MS, cutoffs},
  snapshot,
  state::AppState,
};

const DAY: i64 = 24 * HOUR_MS;
const MAX_POINTS: usize = 200_000;
const MIB: f64 = 1_048_576.0;

#[derive(Deserialize)]
pub struct Filter {
  pub server: Option<String>,
  pub service: Option<String>,
  pub days: Option<i64>,
}

pub async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(filter): Query<Filter>,
) -> ApiResult<Vec<LimitSuggestion>> {
  auth.require(Perm::Read)?;
  let days = filter.days.unwrap_or(14);
  if !(1..=14).contains(&days) {
    return Err(ApiError::invalid("天数须为 1 到 14").into());
  }
  if let Some(name) = &filter.service {
    crate::token_scope::require_service(&auth, name)?;
  }
  let snap = snapshot::load_inner(&state.db).await?;
  if let Some(name) = &filter.service
    && !snap.world.services.contains_key(name)
  {
    return Err(crate::api::service_not_found(name).into());
  }
  let names: Vec<_> = snap
    .world
    .services
    .iter()
    .filter(|(name, _)| {
      auth
        .services
        .as_ref()
        .is_none_or(|allowed| allowed.contains(*name))
    })
    .filter(|(name, _)| {
      filter
        .service
        .as_ref()
        .is_none_or(|requested| *name == requested)
    })
    .filter_map(|(name, row)| {
      let server = snapshot::service_runtime_server(&snap, name)?;
      filter
        .server
        .as_deref()
        .is_none_or(|requested| server == requested)
        .then(|| {
          let metrics = snap
            .agent(server)
            .and_then(|a| a.report.as_ref())
            .and_then(|report| report.metrics.as_ref());
          let applied = snap.applied.get(name);
          Selected {
            name: name.clone(),
            server: server.into(),
            instance: row.instance_id.clone(),
            at: applied.map_or(0, |a| a.at.timestamp_millis()),
            spec: applied
              .and_then(|a| a.spec.clone())
              .unwrap_or_else(|| row.spec.clone()),
            skip: if applied.is_none() {
              Some("not_deployed")
            } else if applied.is_none_or(|a| a.spec.is_none()) {
              Some("runtime_unverified")
            } else if row.spec.stopped {
              Some("stopped")
            } else if server != row.spec.server
              || snap.pending.migrations.contains_key(name)
            {
              Some("migration")
            } else if !state.hub.is_online(server) {
              Some("offline")
            } else if metrics
              .is_none_or(|m| !m.projects.contains_key(name))
            {
              Some("runtime_unverified")
            } else {
              match metrics
                .and_then(|m| m.projects.get(name))
                .and_then(|p| p.containers)
              {
                Some(1) => None,
                Some(_) => Some("项目用量无法按容器分配"),
                None => Some("runtime_unverified"),
              }
            },
            mem_total: metrics.map_or(0, |m| m.mem_total),
            cpu_total: metrics
              .and_then(|m| m.cpu_cores)
              .unwrap_or_default(),
          }
        })
    })
    .collect();
  let rows = state
    .db
    .call(move |c| calculate(c, names, days, db::now_ms()))
    .await?;
  Ok(Json(rows))
}

struct Selected {
  name: String,
  server: String,
  instance: String,
  at: i64,
  spec: ServiceSpec,
  skip: Option<&'static str>,
  mem_total: u64,
  cpu_total: u32,
}

#[derive(Default)]
struct Samples {
  since: Option<i64>,
  until: Option<i64>,
  minutes: BTreeSet<i64>,
  points: usize,
  span: i64,
  weight: f64,
  peak: f64,
  lacks_peak: bool,
}

impl Samples {
  fn push(
    &mut self,
    at: i64,
    span: i64,
    value: f64,
    peak: Option<f64>,
  ) {
    self.since = Some(self.since.map_or(at, |old| old.min(at)));
    self.until =
      Some(self.until.map_or(at + span, |old| old.max(at + span)));
    self.minutes.extend(
      at.div_euclid(MINUTE_MS)..(at + span).div_euclid(MINUTE_MS),
    );
    self.points += 1;
    self.span = self.span.max(span);
    self.weight += value * span as f64;
    self.peak = self.peak.max(peak.unwrap_or(value));
    self.lacks_peak |= peak.is_none();
  }

  fn enough(&self, days: i64, start: i64, end: i64) -> bool {
    let hours: BTreeSet<_> =
      self.minutes.iter().map(|m| m.div_euclid(60)).collect();
    let half_hours = ((end - start).max(0) as u64)
      .div_ceil(2 * HOUR_MS as u64) as usize;
    if days == 1 {
      hours.len() >= 12
    } else {
      hours.len() >= half_hours
        && self.since.zip(self.until).is_some_and(|(a, b)| {
          a.div_euclid(DAY) < (b - 1).div_euclid(DAY)
        })
    }
  }

  fn evidence(&self) -> LimitEvidence {
    let weight_ms = self.minutes.len() as f64 * MINUTE_MS as f64;
    LimitEvidence {
      start_ms: self.since,
      end_ms: self.until,
      points: self.points,
      hours: self
        .minutes
        .iter()
        .map(|m| m.div_euclid(60))
        .collect::<BTreeSet<_>>()
        .len(),
      resolution_minutes: (self.span / MINUTE_MS) as u32,
      mean: (weight_ms > 0.0).then(|| self.weight / weight_ms),
      peak: (self.points > 0).then_some(self.peak),
      peak_is_lower_bound: self.lacks_peak,
    }
  }
}

fn calculate(
  c: &Connection,
  selected: Vec<Selected>,
  days: i64,
  end: i64,
) -> Result<Vec<LimitSuggestion>, ApiError> {
  let retention = i64::from(crate::config_api::number(
    c,
    "retention.metrics_days",
  )?);
  let (coarse, hourly) = cutoffs(end);
  let mut scanned = 0;
  let mut out = Vec::with_capacity(selected.len());
  let mut stmt = c.prepare_cached(
    "SELECT name, at, value FROM points
     WHERE subject=?1 AND at>=?2 AND at<?3
       AND name IN ('svc.cpu', 'svc.cpu.cores', 'svc.mem', 'svc.mem.max', 'oom.kill')
     ORDER BY at",
  ).map_err(sql_err)?;
  for mut service in selected {
    // 最近一次成功部署是当前名字、实例、机器和已应用版本共同可证明的起点。
    let at: Option<i64> = c.query_row(
      "SELECT MAX(created_at) FROM deployments WHERE service=?1 AND instance_id=?2",
      params![service.name, service.instance], |row| row.get(0),
    ).map_err(sql_err)?;
    let attributable = service.at > 0 && at == Some(service.at);
    let start = (end - days.min(retention) * DAY).max(service.at);
    let historical_multi: bool = c.query_row(
      "SELECT EXISTS(SELECT 1 FROM points WHERE subject=?1 AND name='svc.containers.max'
       AND at>=?2 AND at<?3 AND value>1)",
      params![service.name, start, end], |row| row.get(0),
    ).map_err(sql_err)?;
    if historical_multi {
      service.skip = service.skip.or(Some("项目用量无法按容器分配"));
    }
    let mut rows = stmt
      .query(params![
        service.name,
        if attributable { start } else { end },
        end
      ])
      .map_err(sql_err)?;
    let mut mem = Samples::default();
    let mut cpu = Samples::default();
    let mut fine_cpu = Samples::default();
    let mut oom = 0;
    let mut points = BTreeMap::<i64, [Option<f64>; 4]>::new();
    while let Some(row) = rows.next().map_err(sql_err)? {
      scanned += 1;
      if scanned > MAX_POINTS {
        return Err(
          ApiError::invalid("资源推荐查询超过统计预算")
            .with_hint("加 --service 或缩短窗口"),
        );
      }
      let metric: String = row.get(0).map_err(sql_err)?;
      let index = match metric.as_str() {
        "svc.mem" => 0,
        "svc.mem.max" => 1,
        "svc.cpu" => 2,
        "svc.cpu.cores" => 3,
        "oom.kill" => {
          oom += 1;
          continue;
        }
        _ => continue,
      };
      let value: f64 = row.get(2).map_err(sql_err)?;
      if value.is_finite() && value >= 0.0 {
        points.entry(row.get(1).map_err(sql_err)?).or_default()
          [index] = Some(value);
      }
    }
    for (at, [memory, maximum, usage, cores]) in points {
      let span = if at < hourly && at % HOUR_MS == 0 {
        HOUR_MS
      } else if at < coarse && at % COARSE_MS == 0 {
        COARSE_MS
      } else {
        MINUTE_MS
      };
      if at + span > end {
        continue;
      }
      if let Some(memory) = memory {
        let peak = if span == MINUTE_MS {
          Some(memory)
        } else {
          maximum
        };
        mem.push(at, span, memory / MIB, peak.map(|v| v / MIB));
      }
      if let Some(value) = usage {
        cpu.push(
          at,
          span,
          value,
          (span == MINUTE_MS).then_some(value),
        );
      }
      if let Some(cores) = cores
        && span == MINUTE_MS
        && at >= end - DAY
      {
        fine_cpu.push(at, span, cores * 1000.0, Some(cores * 1000.0));
      }
    }
    let can_suggest_memory = mem.enough(days, start, end);
    let can_suggest_cpu = fine_cpu.enough(1, start, end);
    out.push(suggest(
      service,
      attributable,
      can_suggest_memory,
      can_suggest_cpu,
      mem,
      cpu,
      fine_cpu,
      oom,
    ));
  }
  Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn suggest(
  selected: Selected,
  attributable: bool,
  enough_memory: bool,
  enough_cpu: bool,
  mem: Samples,
  cpu: Samples,
  fine_cpu: Samples,
  oom: usize,
) -> LimitSuggestion {
  let spec = &selected.spec;
  let components =
    crate::render::service_expected_components(&selected.name, spec);
  let component =
    components.iter().next().filter(|_| components.len() == 1);
  let component_limits =
    component.and_then(|name| spec.container_limits.get(name));
  let limits = component_limits
    .or(spec.limits.as_ref())
    .cloned()
    .unwrap_or_default();
  let memory = limits
    .memory_mb
    .filter(|&mb| mb > 0)
    .map(|mb| (u64::from(mb) << 20, false))
    .or_else(|| {
      crate::rules::resources::service_limit_with_source(spec)
    });
  let current_memory = memory.map(|(v, _)| v as f64 / MIB);
  let memory_source = memory.map(|(_, compose)| {
    if compose { "compose" } else { "wharf" }.into()
  });
  let compose_cpu = if let Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
  {
    crate::render::parse_compose_template(content)
      .ok()
      .and_then(|doc| {
        let svc =
          doc.get("services")?.as_mapping()?.values().next()?;
        let value = svc.get("cpus").or_else(|| {
          svc
            .get("deploy")?
            .get("resources")?
            .get("limits")?
            .get("cpus")
        })?;
        let cores =
          value.as_f64().or_else(|| value.as_str()?.parse().ok())?;
        (cores.is_finite()
          && cores > 0.0
          && cores <= f64::from(u32::MAX) / 1000.0)
          .then(|| (cores * 1000.0).ceil() as u32)
      })
  } else {
    None
  };
  let mut skip = selected.skip;
  if !attributable {
    skip = skip.or(Some("runtime_unverified"));
  }
  if components.len() != 1 {
    skip = skip.or(Some("项目用量无法按容器分配"));
  }
  if !enough_memory && !enough_cpu {
    skip = skip.or(Some("insufficient_samples"));
  }
  let memory_class = if oom > 0
    || current_memory.is_some_and(|v| mem.peak >= 0.8 * v)
  {
    "tight"
  } else if current_memory.is_none() {
    "uncapped"
  } else if current_memory
    .is_some_and(|v| v >= 3.0 * mem.peak && v - mem.peak >= 128.0)
    && !mem.lacks_peak
    && enough_memory
  {
    "overprovisioned"
  } else {
    "ok"
  };
  let mut mem_reason = None;
  let mut cpu_reason = None;
  let memory_mb = if skip.is_some() {
    None
  } else if !enough_memory {
    mem_reason = Some("insufficient_samples");
    None
  } else if memory.is_some_and(|(_, compose)| compose) {
    mem_reason = Some("compose_limits");
    None
  } else {
    let floor = if oom > 0 {
      current_memory.unwrap_or_default() + 1.0
    } else {
      0.0
    };
    let minimum = (mem.peak * 1.3).max(mem.peak + 32.0).max(floor);
    let value =
      (minimum.ceil() as u32).max(64).checked_next_power_of_two();
    match value.filter(|v| u64::from(*v) << 20 <= selected.mem_total)
    {
      Some(value)
        if mem.lacks_peak
          && current_memory.is_some_and(|v| f64::from(value) < v) =>
      {
        mem_reason = Some("peak_is_lower_bound");
        None
      }
      Some(value) => {
        mem_reason = (oom > 0).then_some("oom_observed");
        Some(value)
      }
      None => {
        mem_reason = Some("machine_capacity");
        None
      }
    }
  };
  let cpu_milli = if skip.is_some() {
    None
  } else if !enough_cpu {
    cpu_reason = Some("insufficient_fine_cpu_samples");
    None
  } else if limits.cpu_milli.is_none() && compose_cpu.is_some() {
    cpu_reason = Some("compose_limits");
    None
  } else {
    let value = (((fine_cpu.peak * 1.3 / 100.0).ceil() as u32)
      .max(1))
    .saturating_mul(100);
    if value <= selected.cpu_total.saturating_mul(1000) {
      Some(value)
    } else {
      cpu_reason = Some("machine_capacity");
      None
    }
  };
  LimitSuggestion {
    name: selected.name,
    server: selected.server,
    container: component
      .filter(|_| {
        matches!(spec.source, Source::Compose { .. })
          && (component_limits.is_some()
            || spec.limits.is_none()
            || spec.limits.as_ref().is_some_and(|l| l.is_empty()))
      })
      .cloned(),
    memory_source,
    cpu_source: limits
      .cpu_milli
      .map(|_| "wharf".into())
      .or_else(|| compose_cpu.map(|_| "compose".into())),
    current_memory_mb: current_memory,
    current_cpu_milli: limits.cpu_milli.or(compose_cpu),
    memory: mem.evidence(),
    cpu: cpu.evidence(),
    fine_cpu: fine_cpu.evidence(),
    oom_points: oom,
    memory_class: memory_class.into(),
    memory_mb,
    cpu_milli,
    skip: skip.map(str::to_owned),
    memory_reason: mem_reason.map(str::to_owned),
    cpu_reason: cpu_reason.map(str::to_owned),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[tokio::test]
  async fn recommendation_excludes_previous_instance_samples() {
    let db = db::Db::memory();
    db.call(|c| {
      let end=50*DAY;
      let start=end-DAY;
      c.execute(
        "INSERT INTO deployments(service,server,run_id,hash,compose,images,created_at,instance_id)
         VALUES ('app','s1','r1','fixture','','[]',?1,'current')", [start],
      ).map_err(sql_err)?;
      for (at,metric,value) in [(start-MINUTE_MS,"svc.mem",2048.0*MIB),(start+MINUTE_MS,"oom.kill",1.0)] {
        c.execute("INSERT INTO points(name,subject,at,value) VALUES(?1,'app',?2,?3)",params![metric,at,value]).map_err(sql_err)?;
      }
      for hour in 0..24 {
        c.execute("INSERT INTO points(name,subject,at,value) VALUES('svc.mem','app',?1,?2)",
          params![start+hour*HOUR_MS+MINUTE_MS,120.0*MIB]).map_err(sql_err)?;
      }
      let spec=serde_json::from_value(json!({"server":"s1","source":{"image":"fixture:1"},"limits":{"memory_mb":128}})).unwrap();
      let rows=calculate(c,vec![Selected {
        name:"app".into(),server:"s1".into(),instance:"current".into(),at:start,
        spec,skip:None,mem_total:1<<30,cpu_total:2,
      }],1,end)?;
      assert_eq!(rows[0].memory.peak,Some(120.0));
      assert_eq!(rows[0].memory_mb,Some(256));
      assert_eq!(rows[0].oom_points,1);
      Ok(())
    }).await.unwrap();
  }

  #[test]
  fn oom_raises_the_memory_tier_and_missing_cpu_peak_skips_cpu() {
    let spec = serde_json::from_value(json!({
      "server":"s1","source":{"image":"fixture:1"},"limits":{"memory_mb":128}
    })).unwrap();
    let result = suggest(
      Selected {
        name: "app".into(),
        server: "s1".into(),
        instance: "instance".into(),
        at: 0,
        spec,
        skip: None,
        mem_total: 1 << 30,
        cpu_total: 2,
      },
      true,
      true,
      false,
      Samples {
        peak: 120.0,
        ..Default::default()
      },
      Samples::default(),
      Samples::default(),
      1,
    );
    assert_eq!(result.memory_class, "tight");
    assert_eq!(result.memory_mb, Some(256));
    assert_eq!(result.cpu_milli, None);
  }
}
