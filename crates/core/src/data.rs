//! 数据归属：从服务配置算出每处挂载归谁管。
//! 只有 `/srv/<服务>/` 下的目录归 Wharf（迁移时同步、备份、迁走后清理）；
//! 其他宿主机目录和 docker 卷 Wharf 不碰，迁移和备份时要明确告诉用户。

use std::path::{Component, Path};

use chrono::{DateTime, Duration, Utc};
use serde_yaml_ng::Value;
use wharf_api_types::{
  spec::{ServiceSpec, Source},
  view::{DataKind, DataMount, DataStatus, DataView, ServiceData},
};

use crate::{db::sql_err, snapshot, state::AppState};

/// 超过这个时间没有成功的备份就算过期。
pub const STALE_AFTER_HOURS: i64 = 48;

pub fn mounts(name: &str, spec: &ServiceSpec) -> Vec<DataMount> {
  match &spec.source {
    Source::Image(_) | Source::Build(_) => spec
      .volumes
      .iter()
      .map(|v| DataMount {
        kind: DataKind::Managed,
        source: format!("/srv/{name}/{}", v.name),
        target: v.target.clone(),
        container: None,
      })
      .collect(),
    Source::Compose { content, .. } => {
      compose_mounts(name, content.as_deref().unwrap_or_default())
    }
  }
}

/// 一个服务的数据现状：有没有开备份、有没有全部覆盖、最近成功过没有。
pub fn status(
  backup: bool,
  mounts: &[DataMount],
  last_ok: Option<DateTime<Utc>>,
  last_failed: Option<DateTime<Utc>>,
  now: DateTime<Utc>,
) -> DataStatus {
  if mounts.is_empty() {
    return DataStatus::None;
  }
  if !backup {
    return DataStatus::Off;
  }
  // 最近一次尝试失败，或者成功已经太久：备份没在正常跑。
  let failed_lately = match (last_ok, last_failed) {
    (Some(ok), Some(failed)) => failed > ok,
    (None, Some(_)) => true,
    _ => false,
  };
  let fresh = last_ok.is_some_and(|t| {
    now.signed_duration_since(t) <= Duration::hours(STALE_AFTER_HOURS)
  });
  if !fresh || failed_lately {
    return DataStatus::Stale;
  }
  if mounts.iter().any(|m| m.kind != DataKind::Managed) {
    return DataStatus::Uncovered;
  }
  DataStatus::Ok
}

/// 最近一次成功和最近一次失败的时间。
type BackupTimes = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// 每个服务的数据在哪、备份有没有在跑，现查。
pub async fn overview(
  state: &AppState,
) -> Result<DataView, wharf_api_types::ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let rows: Vec<(String, Option<i64>, Option<i64>)> = state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT service,
                  MAX(CASE WHEN ok THEN created_at END),
                  MAX(CASE WHEN ok = 0 THEN created_at END)
           FROM backups GROUP BY service",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  let times: std::collections::BTreeMap<String, BackupTimes> = rows
    .into_iter()
    .map(|(name, ok, failed)| (name, (from_ms(ok), from_ms(failed))))
    .collect();
  let now = Utc::now();
  let mut services = Vec::new();
  for (name, row) in &snap.world.services {
    let mounts = mounts(name, &row.spec);
    let (last_ok, last_failed) =
      times.get(name).copied().unwrap_or_default();
    let target = row.spec.backup.as_ref().map(|b| b.to.clone());
    services.push(ServiceData {
      name: name.clone(),
      server: row.spec.server.clone(),
      last_ok,
      last_failed: last_failed
        .filter(|f| last_ok.is_none_or(|ok| *f > ok)),
      status: status(
        target.is_some(),
        &mounts,
        last_ok,
        last_failed,
        now,
      ),
      target,
      mounts,
    });
  }
  Ok(DataView { services })
}

fn from_ms(ms: Option<i64>) -> Option<DateTime<Utc>> {
  ms.and_then(DateTime::from_timestamp_millis)
}

pub fn describe(m: &DataMount) -> String {
  match m.kind {
    DataKind::Managed => format!("目录 {}", m.source),
    DataKind::ExternalDir => format!("外部目录 {}", m.source),
    DataKind::NamedVolume if m.source.is_empty() => {
      format!("匿名卷（挂在 {}）", m.target)
    }
    DataKind::NamedVolume => format!("命名卷 {}", m.source),
  }
}

/// compose 解析不了时返回空：部署时 compose 自己会报错。
fn compose_mounts(name: &str, content: &str) -> Vec<DataMount> {
  let Ok(doc) = serde_yaml_ng::from_str::<Value>(content) else {
    return Vec::new();
  };
  let top = doc.get("volumes");
  let mut out = Vec::new();
  let Some(services) =
    doc.get("services").and_then(Value::as_mapping)
  else {
    return out;
  };
  for (svc, def) in services {
    let svc = svc.as_str().unwrap_or_default();
    let Some(list) = def.get("volumes").and_then(Value::as_sequence)
    else {
      continue;
    };
    for v in list {
      let Some((kind, source, target)) = parse_mount(v) else {
        continue;
      };
      let (kind, source) = match kind {
        Mount::Bind => (classify_dir(name, &source), source),
        Mount::Volume => {
          (DataKind::NamedVolume, volume_name(top, source))
        }
      };
      out.push(DataMount {
        kind,
        source,
        target,
        container: Some(svc.to_string()),
      });
    }
  }
  out
}

enum Mount {
  Bind,
  Volume,
}

/// 短写法 `源:目标[:选项]` 或长写法 `{type, source, target}`；tmpfs 不算数据。
fn parse_mount(v: &Value) -> Option<(Mount, String, String)> {
  if let Some(s) = v.as_str() {
    let mut parts = s.splitn(3, ':');
    let first = parts.next()?.to_string();
    return Some(match parts.next() {
      None => (Mount::Volume, String::new(), first),
      Some(target) => {
        let kind = if is_path(&first) {
          Mount::Bind
        } else {
          Mount::Volume
        };
        (kind, first, target.to_string())
      }
    });
  }
  let get =
    |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
  let target = get("target").to_string();
  let source = get("source").to_string();
  match get("type") {
    "bind" => Some((Mount::Bind, source, target)),
    "volume" | "" => Some((Mount::Volume, source, target)),
    _ => None,
  }
}

fn is_path(s: &str) -> bool {
  s.starts_with('/')
    || s.starts_with('.')
    || s.starts_with('~')
    || s.starts_with('$')
}

/// 绝对路径、没有 `..`、在 `/srv/<服务>/` 下才算 Wharf 管理。
fn classify_dir(name: &str, source: &str) -> DataKind {
  let path = Path::new(source.trim_end_matches('/'));
  let clean = path.is_absolute()
    && path.components().all(|c| {
      matches!(c, Component::RootDir | Component::Normal(_))
    });
  if clean && path.starts_with(Path::new("/srv").join(name)) {
    DataKind::Managed
  } else {
    DataKind::ExternalDir
  }
}

/// 顶层 `volumes` 里写了 `name:` 时，docker 里的卷名以它为准。
fn volume_name(top: Option<&Value>, key: String) -> String {
  top
    .and_then(|t| t.get(key.as_str()))
    .and_then(|d| d.get("name"))
    .and_then(Value::as_str)
    .map_or(key, str::to_string)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn covers_five_states() {
    let now = Utc::now();
    let mount = |kind: DataKind, source: &str| DataMount {
      kind,
      source: source.into(),
      target: "/data".into(),
      container: None,
    };
    let managed = [mount(DataKind::Managed, "/srv/app/data")];
    let mixed = [
      mount(DataKind::Managed, "/srv/app/data"),
      mount(DataKind::ExternalDir, "/home/me"),
    ];
    let old = Some(now - Duration::hours(STALE_AFTER_HOURS + 1));
    use DataStatus as S;
    // 开了备份，最近成功过，挂载都归 Wharf 管。
    assert_eq!(status(true, &managed, Some(now), None, now), S::Ok);
    // 从没成功过。
    assert_eq!(
      status(true, &managed, None, Some(now), now),
      S::Stale
    );
    // 上次成功太久了。
    assert_eq!(status(true, &managed, old, None, now), S::Stale);
    // 最近一次尝试失败。
    assert_eq!(status(true, &managed, old, Some(now), now), S::Stale);
    // 有目录，但没开备份。
    assert_eq!(status(false, &managed, Some(now), None, now), S::Off);
    // 开了备份，但还有不归 Wharf 管的数据。
    assert_eq!(
      status(true, &mixed, Some(now), None, now),
      S::Uncovered
    );
    // 同时过期和没覆盖时按过期算。
    assert_eq!(status(true, &mixed, old, None, now), S::Stale);
    // 没有任何挂载。
    assert_eq!(status(true, &[], Some(now), None, now), S::None);
  }

  #[test]
  fn classifies_compose_mounts() {
    let compose = r#"
services:
  web:
    volumes:
      - /srv/app/data:/data
      - /srv/app:/all:ro
      - /srv/app2/x:/x
      - /srv/app/../etc:/etc2
      - /home/me/files:/files
      - ./conf:/conf
      - cache:/cache
      - /anon
      - type: bind
        source: /srv/app/logs
        target: /logs
      - type: tmpfs
        target: /tmp
volumes:
  cache:
    external: true
    name: blog_cache
"#;
    let kinds: Vec<(DataKind, String)> =
      compose_mounts("app", compose)
        .into_iter()
        .map(|m| (m.kind, m.source))
        .collect();
    use DataKind::*;
    assert_eq!(
      kinds,
      vec![
        (Managed, "/srv/app/data".into()),
        (Managed, "/srv/app".into()),
        (ExternalDir, "/srv/app2/x".into()),
        (ExternalDir, "/srv/app/../etc".into()),
        (ExternalDir, "/home/me/files".into()),
        (ExternalDir, "./conf".into()),
        (NamedVolume, "blog_cache".into()),
        (NamedVolume, "".into()),
        (Managed, "/srv/app/logs".into()),
      ]
    );
  }
}
