//! 磁盘占用增长：每天测一次每个服务的 `/srv/<服务>`、容器日志、挂载的命名卷，
//! 存成打点（`disk.data` / `disk.logs` / `disk.vols`，对象是服务；几个服务共用的卷记 `disk.shared`，
//! 对象是 `<服务器>/<卷>`），保留 90 天。页面按服务看 1 天、7 天的增长。
//!
//! 测量要遍历文件，放在低优先级的辅助容器里跑，一天一次。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
  time::Duration,
};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ServiceDisk},
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms, sql_err},
  snapshot,
  state::AppState,
  world::server_not_found,
};

const EVERY_MS: i64 = 24 * 3600 * 1000;
const SETTING: &str = "disk.measured_at";
const DAY_MS: i64 = 24 * 3600 * 1000;

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(600)).await;
    loop {
      let last = state
        .db
        .call(|c| db::setting(c, SETTING))
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
      if now_ms() - last >= EVERY_MS {
        let at = now_ms().to_string();
        let _ = state
          .db
          .call(move |c| db::set_setting(c, SETTING, Some(&at)))
          .await;
        if let Ok(snap) = snapshot::load(&state.db).await {
          for server in snap.world.servers.keys() {
            if state.hub.is_online(server)
              && let Err(e) = measure(&state, server).await
            {
              tracing::warn!(
                "测量 {server} 的磁盘占用失败：{}",
                e.message
              );
            }
          }
        }
      }
      tokio::time::sleep(Duration::from_secs(600)).await;
    }
  });
}

/// 测一台机器并记打点。
async fn measure(
  state: &AppState,
  server: &str,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let services: Vec<String> = snap
    .world
    .services
    .iter()
    .filter(|(_, r)| r.spec.server == server)
    .map(|(n, _)| n.clone())
    .collect();
  if services.is_empty() {
    return Ok(());
  }
  let found: Vec<ServiceDisk> = state
    .hub
    .call(
      server,
      AgentOp::DiskUsage { services },
      Duration::from_secs(1900),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let rows = points(server, &found);
  let at = now_ms();
  state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare_cached(
          "INSERT OR REPLACE INTO points (name, subject, at, value) VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(sql_err)?;
      for (name, subject, value) in &rows {
        stmt
          .execute(params![name, subject, at, *value as f64])
          .map_err(sql_err)?;
      }
      Ok(())
    })
    .await
}

/// 几个服务都挂着的卷单列，不算进任何一个服务。
fn points(
  server: &str,
  found: &[ServiceDisk],
) -> Vec<(&'static str, String, u64)> {
  let mut users: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
  for d in found {
    for v in d.volumes.keys() {
      users.entry(v).or_default().insert(&d.service);
    }
  }
  let mut out = Vec::new();
  let mut shared: BTreeMap<&str, u64> = BTreeMap::new();
  for d in found {
    let mut own = 0;
    for (v, bytes) in &d.volumes {
      if users[v.as_str()].len() > 1 {
        shared.insert(v, *bytes);
      } else {
        own += bytes;
      }
    }
    out.push(("disk.data", d.service.clone(), d.data));
    out.push(("disk.logs", d.service.clone(), d.logs));
    out.push(("disk.vols", d.service.clone(), own));
  }
  for (v, bytes) in shared {
    out.push(("disk.shared", format!("{server}/{v}"), bytes));
  }
  out
}

#[derive(Serialize)]
pub struct DiskRow {
  /// 服务名，或共用卷的卷名。
  name: String,
  shared: bool,
  data: u64,
  logs: u64,
  vols: u64,
  total: u64,
  /// 和一天前、七天前比的增长（没有那时的数据时为空）。
  #[serde(skip_serializing_if = "Option::is_none")]
  day: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  week: Option<i64>,
  at: i64,
}

#[derive(Serialize)]
pub struct DiskView {
  rows: Vec<DiskRow>,
  #[serde(skip_serializing_if = "Option::is_none")]
  measured_at: Option<i64>,
}

/// `GET /api/servers/{name}/disk`
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
) -> ApiResult<DiskView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let services: Vec<String> = snap
    .world
    .services
    .iter()
    .filter(|(_, r)| r.spec.server == server)
    .map(|(n, _)| n.clone())
    .collect();
  Ok(Json(view(&s, &server, services).await?))
}

/// `POST /api/servers/{name}/disk/measure`：立即测一次，可能要几分钟。
pub async fn measure_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
) -> ApiResult<DiskView> {
  auth.require(Perm::Plan)?;
  measure(&s, &server).await?;
  show(State(s), auth, Path(server)).await
}

async fn view(
  s: &AppState,
  server: &str,
  services: Vec<String>,
) -> Result<DiskView, ApiError> {
  let server = server.to_string();
  s.db
    .call(move |c| {
      // 某个对象某项在某时刻前最近的一个值。
      let value = |name: &str, subject: &str, before: i64| -> Result<Option<(i64, f64)>, ApiError> {
        c.query_row(
          "SELECT at, value FROM points WHERE name = ?1 AND subject = ?2 AND at <= ?3 ORDER BY at DESC LIMIT 1",
          params![name, subject, before],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql_err)
      };
      let now = now_ms();
      let mut rows = Vec::new();
      let mut row = |name: String, subject: &str, kinds: &[&str], shared: bool| -> Result<(), ApiError> {
        let mut parts = [0u64; 3];
        let mut at = None;
        for (i, k) in kinds.iter().enumerate() {
          if let Some((t, v)) = value(k, subject, now)? {
            parts[i] = v as u64;
            at = Some(at.map_or(t, |a: i64| a.max(t)));
          }
        }
        let Some(at) = at else { return Ok(()) };
        let total: u64 = parts.iter().sum();
        let ago = |ms: i64| -> Result<Option<i64>, ApiError> {
          let mut sum = 0f64;
          let mut any = false;
          for k in kinds {
            if let Some((_, v)) = value(k, subject, at - ms + 3600 * 1000)? {
              sum += v;
              any = true;
            }
          }
          Ok(any.then(|| total as i64 - sum as i64))
        };
        let (data, logs, vols) = if shared {
          (0, 0, parts[0])
        } else {
          (parts[0], parts[1], parts[2])
        };
        rows.push(DiskRow {
          name,
          shared,
          data,
          logs,
          vols,
          total,
          day: ago(DAY_MS)?,
          week: ago(7 * DAY_MS)?,
          at,
        });
        Ok(())
      };
      for svc in &services {
        row(svc.clone(), svc, &["disk.data", "disk.logs", "disk.vols"], false)?;
      }
      let prefix = format!("{server}/");
      let mut stmt = c
        .prepare("SELECT DISTINCT subject FROM points WHERE name = 'disk.shared' AND subject LIKE ?1")
        .map_err(sql_err)?;
      let shared: Vec<String> = stmt
        .query_map(params![format!("{prefix}%")], |r| r.get(0))
        .map_err(sql_err)?
        .collect::<Result<_, _>>()
        .map_err(sql_err)?;
      for subject in shared {
        let name = subject.trim_start_matches(&prefix).to_string();
        row(name, &subject, &["disk.shared"], true)?;
      }
      // "上一次测量"之前的点（每天一次）：只留最近一次测量里出现的行。
      let latest = rows.iter().map(|r| r.at).max();
      if let Some(latest) = latest {
        rows.retain(|r| latest - r.at < 3600 * 1000);
      }
      rows.sort_by(|a, b| b.week.unwrap_or(0).cmp(&a.week.unwrap_or(0)).then(b.total.cmp(&a.total)));
      Ok(DiskView { measured_at: latest, rows })
    })
    .await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn shared_volume_counted_once() {
    let d = |svc: &str, vols: &[(&str, u64)]| ServiceDisk {
      service: svc.into(),
      data: 10,
      logs: 1,
      volumes: vols
        .iter()
        .map(|(v, b)| (v.to_string(), *b))
        .collect(),
    };
    let p = points(
      "home",
      &[
        d("a", &[("own", 5), ("both", 100)]),
        d("b", &[("both", 100)]),
      ],
    );
    assert!(p.contains(&("disk.vols", "a".into(), 5)));
    assert!(p.contains(&("disk.vols", "b".into(), 0)));
    assert!(p.contains(&("disk.shared", "home/both".into(), 100)));
  }
}
