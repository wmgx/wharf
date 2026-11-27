//! 数据归属：从服务配置算出每处挂载归谁管。
//! 只有 `/srv/<服务>/` 下的目录归 Wharf（迁移时同步、备份、迁走后清理）；
//! 其他宿主机目录和 docker 卷 Wharf 不碰，迁移和备份时要明确告诉用户。

use std::{
  collections::BTreeMap,
  path::{Component, Path},
};

use chrono::{DateTime, Duration, Utc};
use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError,
  agent::{BackupSummary, EscapedMount},
  spec::{ServiceSpec, Source},
  view::{DataKind, DataMount, DataStatus, DataView, ServiceData},
};

use crate::{
  db::{Db, sql_err},
  snapshot::{self, Snapshot},
  state::AppState,
};

/// 超过这个时间没有成功的备份就算过期。
pub const STALE_AFTER_HOURS: i64 = 48;

pub fn has_relative_bind(spec: &ServiceSpec) -> bool {
  match &spec.source {
    Source::Compose {
      content: Some(content),
      ..
    } => compose_mounts("", content).iter().any(|mount| {
      mount.kind == DataKind::ExternalDir
        && !mount.source.is_empty()
        && !Path::new(&mount.source).is_absolute()
    }),
    _ => false,
  }
}

pub fn mounts(name: &str, spec: &ServiceSpec) -> Vec<DataMount> {
  match &spec.source {
    Source::Image(_) | Source::Build(_) => spec
      .volumes
      .iter()
      .map(|v| DataMount {
        resolved: None,
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

pub fn undeclared_mounts(
  service: &str,
  declared: &[DataMount],
  actual: &[wharf_api_types::agent::ContainerMount],
) -> Vec<DataMount> {
  let root = format!("/srv/{service}");
  actual
    .iter()
    .filter_map(|m| {
      let target = m.target.trim_end_matches('/');
      if declared.iter().any(|d| {
        d.target.trim_end_matches('/') == target
          && d
            .container
            .as_ref()
            .is_none_or(|name| *name == m.service)
      }) || Path::new(&m.source).starts_with(&root)
        || m.source.contains("/.wharf-secrets/")
        || m.source.contains(&format!("/projects/{service}/secrets/"))
      {
        return None;
      }
      let kind = match m.kind.as_str() {
        "volume" => DataKind::NamedVolume,
        "bind" => DataKind::ExternalDir,
        _ => return None,
      };
      let anonymous = kind == DataKind::NamedVolume
        && m.source.len() == 64
        && m.source.bytes().all(|b| b.is_ascii_hexdigit());
      Some(DataMount {
        kind,
        source: if anonymous {
          String::new()
        } else {
          m.source.clone()
        },
        target: target.into(),
        container: Some(m.service.clone()),
      })
    })
    .collect()
}

#[test]
fn undeclared_mounts_detects_image_anonymous_volume() {
  let m = wharf_api_types::agent::ContainerMount {
    container: "notes-db-1".into(),
    service: "db".into(),
    kind: "volume".into(),
    source: "a".repeat(64),
    target: "/var/lib/db/".into(),
  };
  let mounts = undeclared_mounts("notes", &[], &[m]);
  assert_eq!(mounts[0].target, "/var/lib/db");
  assert!(mounts[0].source.is_empty());
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

#[derive(Default)]
pub(crate) struct BackupHistory {
  pub ok: Option<i64>,
  pub failed: Option<i64>,
  pub escaped: Vec<EscapedMount>,
}

pub(crate) type History = BTreeMap<(String, String), BackupHistory>;

pub(crate) async fn history(db: &Db) -> Result<History, ApiError> {
  db.call(|c| {
    let mut stmt = c.prepare(
      "SELECT service, target, MAX(CASE WHEN ok THEN created_at END),
              MAX(CASE WHEN NOT ok THEN created_at END),
              (SELECT body FROM backups AS latest
               WHERE latest.service = backups.service AND latest.target = backups.target AND latest.ok
               ORDER BY latest.id DESC LIMIT 1)
       FROM backups GROUP BY service, target"
    ).map_err(sql_err)?;
    let rows = stmt.query_map([], |r| {
      let summary: Option<String> = r.get(4)?;
      let escaped = summary.and_then(|s| serde_json::from_str::<BackupSummary>(&s).ok())
        .map(|s| s.escaped_mounts).unwrap_or_default();
      Ok(((r.get(0)?, r.get(1)?), BackupHistory { ok: r.get(2)?, failed: r.get(3)?, escaped }))
    }).map_err(sql_err)?;
    rows.collect::<Result<_, _>>().map_err(sql_err)
  }).await
}

pub(crate) fn repo_verified_empty(
  state: &AppState,
  snap: &Snapshot,
  target: &str,
  service: &str,
  last_ok: Option<i64>,
) -> bool {
  state.hub.is_online(target)
    && snap.agent(target).is_some_and(|agent| {
      agent.last_seen.is_some_and(|seen| {
        last_ok.is_none_or(|ok| seen >= ok.saturating_add(120_000))
      }) && agent
        .report
        .as_ref()
        .and_then(|r| r.backup_repos.as_ref())
        .is_some_and(|repos| {
          repos.get(service).copied().unwrap_or_default() == 0
        })
    })
}

pub(crate) fn apply_escaped_mounts(
  mounts: &mut Vec<DataMount>,
  escaped: &[EscapedMount],
) {
  for link in escaped {
    let mut found = false;
    for mount in mounts.iter_mut() {
      let exact = mount.source == link.source;
      found |= exact;
      if (mount.kind == DataKind::Managed
        || (exact && mount.resolved.is_some()))
        && let Ok(suffix) =
          Path::new(&mount.source).strip_prefix(&link.source)
      {
        mount.kind = DataKind::ExternalDir;
        mount.resolved = Some(if suffix.as_os_str().is_empty() {
          link.resolved.clone()
        } else {
          Path::new(&link.resolved).join(suffix).display().to_string()
        });
      }
    }
    if !found {
      mounts.push(DataMount {
        kind: DataKind::ExternalDir,
        source: link.source.clone(),
        target: String::new(),
        container: None,
        resolved: Some(link.resolved.clone()),
      });
    }
  }
}

pub(crate) fn observed_mounts(
  name: &str,
  spec: &ServiceSpec,
  history: &History,
) -> Vec<DataMount> {
  let mut mounts = mounts(name, spec);
  if let Some(b) = &spec.backup
    && let Some(observed) =
      history.get(&(name.to_string(), b.to.clone()))
  {
    apply_escaped_mounts(&mut mounts, &observed.escaped);
  }
  mounts
}

/// 每个服务的数据在哪、备份有没有在跑，现查。
pub async fn overview(
  state: &AppState,
) -> Result<DataView, ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let history = history(&state.db).await?;
  let now = Utc::now();
  let mut services = Vec::new();
  for (name, row) in &snap.world.services {
    let mounts = observed_mounts(name, &row.spec, &history);
    let target = row.spec.backup.as_ref().map(|b| b.to.clone());
    let observed = target
      .as_ref()
      .and_then(|t| history.get(&(name.clone(), t.clone())));
    let ok = observed.and_then(|h| h.ok);
    let last_ok = from_ms(ok);
    let last_failed = from_ms(observed.and_then(|h| h.failed));
    let repo_empty = !mounts.is_empty()
      && target.as_ref().is_some_and(|t| {
        repo_verified_empty(state, &snap, t, name, ok)
      });
    let status = if repo_empty {
      DataStatus::Stale
    } else {
      status(target.is_some(), &mounts, last_ok, last_failed, now)
    };
    services.push(ServiceData {
      name: name.clone(),
      server: row.spec.server.clone(),
      last_ok,
      repo_empty,
      last_failed: last_failed
        .filter(|f| last_ok.is_none_or(|ok| *f > ok)),
      status,
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
  let Ok(doc) = crate::render::parse_compose(content) else {
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
        resolved: None,
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
  #[test]
  fn compose_mounts_expands_chained_anchors() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"compose": {"content":
        "x-a: &a {volumes: ['./data:/data']}\nx-b: &b {<<: *a}\nservices: {app: {<<: *b, image: nginx}}"
      }}
    })).unwrap();
    let found = mounts("app", &spec);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].source, "./data");
    assert!(has_relative_bind(&spec));
  }

  use super::*;

  #[test]
  fn detects_relative_bind_in_compose() {
    for (mount, expected) in [
      ("./data:/data", true),
      ("../shared:/s", true),
      ("/srv/app/data:/data", false),
      ("vol:/data", false),
    ] {
      let spec: ServiceSpec = serde_json::from_value(serde_json::json!({
        "server": "s1", "source": {"compose": {"content": format!("services: {{ app: {{ volumes: ['{mount}'] }} }}")}}
      })).unwrap();
      assert_eq!(has_relative_bind(&spec), expected, "{mount}");
    }
  }

  #[test]
  fn detects_relative_bind_without_dot_in_long_syntax() {
    for (mount, expected) in [
      ("{type: bind, source: data, target: /data}", true),
      ("{type: bind, source: config/app.yml, target: /data}", true),
      ("{type: bind, source: '~data', target: /data}", true),
      ("'sub/data:/data'", false),
    ] {
      let spec: ServiceSpec = serde_json::from_value(serde_json::json!({
        "server": "s1",
        "source": {"compose": {"content": format!("services: {{app: {{volumes: [{mount}]}}}}")}}
      })).unwrap();
      assert_eq!(has_relative_bind(&spec), expected, "{mount}");
    }
  }

  #[test]
  fn covers_five_states() {
    let now = Utc::now();
    let mount = |kind: DataKind, source: &str| DataMount {
      resolved: None,
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

#[test]
fn escaped_mount_downgrades_status_to_uncovered() {
  let mut mounts = vec![DataMount {
    source: "/srv/s1".into(),
    target: "/data".into(),
    kind: DataKind::Managed,
    resolved: None,
    container: None,
  }];
  let now = Utc::now();
  assert_eq!(
    status(true, &mounts, Some(now), None, now),
    DataStatus::Ok
  );
  apply_escaped_mounts(
    &mut mounts,
    &[EscapedMount {
      source: "/srv/s1/originals".into(),
      resolved: "/mnt/originals".into(),
    }],
  );
  assert_eq!(mounts[1].resolved.as_deref(), Some("/mnt/originals"));
  assert_eq!(
    status(true, &mounts, Some(now), None, now),
    DataStatus::Uncovered
  );
}

#[tokio::test]
async fn switching_backup_target_and_empty_repo_show_stale() {
  let state = crate::rules::tests::test_state();
  crate::backup::tests::seed_servers(&state).await;
  crate::backup::tests::seed_service(&state, "svc-a", true).await;
  state
    .hub
    .mock_agent("s2", false, |_| panic!("数据状态只读"));
  state.db.call(|c| {
    let seen = crate::db::now_ms();
    c.execute("INSERT INTO backups (service, server, target, run_id, ok, body, created_at)
      VALUES ('svc-a', 's1', 's2', 'r1', 1, '{}', ?1)", [seen - 180_000]).map_err(sql_err)?;
    let report = serde_json::to_string(&wharf_api_types::agent::AgentReport {
      backup_repos: Some(BTreeMap::new()), ..Default::default()
    }).map_err(crate::db::json_err)?;
    c.execute("INSERT INTO agents (server, report, last_seen) VALUES ('s2', ?1, ?2)",
      rusqlite::params![report, seen]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let view = overview(&state).await.unwrap();
  assert!(view.services[0].repo_empty);
  assert_eq!(view.services[0].status, DataStatus::Stale);
  state.db.call(|c| {
    c.execute("UPDATE resources SET spec = json_set(spec, '$.backup.to', 's3')
      WHERE kind = 'service' AND name = 'svc-a'", []).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let view = overview(&state).await.unwrap();
  assert_eq!(view.services[0].status, DataStatus::Stale);
  assert!(
    view.services[0].last_ok.is_none()
      && !view.services[0].repo_empty
  );
}

#[test]
fn nested_escaped_mount_is_listed_only_once() {
  let mut mounts = vec![DataMount {
    source: "/srv/s1/data/originals".into(),
    target: "/originals".into(),
    kind: DataKind::Managed,
    resolved: None,
    container: None,
  }];
  apply_escaped_mounts(
    &mut mounts,
    &[
      EscapedMount {
        source: "/srv/s1/data".into(),
        resolved: "/mnt/disk".into(),
      },
      EscapedMount {
        source: "/srv/s1/data/originals".into(),
        resolved: "/mnt/disk/originals".into(),
      },
    ],
  );
  assert_eq!(mounts.len(), 2);
  assert_eq!(mounts[0].target, "/originals");
  assert_eq!(
    mounts[0].resolved.as_deref(),
    Some("/mnt/disk/originals")
  );
  assert_eq!(mounts[0].kind, DataKind::ExternalDir);
  assert_eq!(mounts[1].source, "/srv/s1/data");
}

#[tokio::test]
async fn empty_backup_repo_does_not_mark_service_without_data_stale()
{
  let state = crate::rules::tests::test_state();
  crate::backup::tests::seed_servers(&state).await;
  crate::backup::tests::seed_service(&state, "svc-a", true).await;
  state
    .hub
    .mock_agent("s2", false, |_| panic!("数据状态只读"));
  state.db.call(|c| {
    c.execute("UPDATE resources SET spec = json_remove(spec, '$.volumes')
      WHERE kind = 'service' AND name = 'svc-a'", []).map_err(sql_err)?;
    let report = serde_json::to_string(&wharf_api_types::agent::AgentReport {
      backup_repos: Some(BTreeMap::new()), ..Default::default()
    }).map_err(crate::db::json_err)?;
    c.execute("INSERT INTO agents (server, report, last_seen) VALUES ('s2', ?1, ?2)",
      rusqlite::params![report, crate::db::now_ms()]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let view = overview(&state).await.unwrap();
  assert_eq!(view.services[0].status, DataStatus::None);
  assert!(!view.services[0].repo_empty);
}
