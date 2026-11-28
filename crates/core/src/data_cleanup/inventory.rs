use super::Filters;
use crate::{
  db::{self, now_ms, sql_err, to_time},
  jobs::cleanup_policy,
  snapshot::{self, Snapshot},
  state::AppState,
};
use futures_util::{StreamExt, stream};
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
  collections::{BTreeMap, BTreeSet},
  path::{Path, PathBuf},
  time::Duration,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentCleanupEntry, AgentOp, BACKUP_ROOT, CORE_BACKUP_ROOT,
    CleanupKind::{self, *},
    CleanupScanRequest, CleanupScanResult,
  },
  validate_name,
  view::{CleanupSkippedServer, DataCleanupItem, DataCleanupPolicy},
};

const RETIRED: &str = "backup_move.retired.";
const CORE: &str = "wharf-core";
const DAY_MS: i64 = 86_400_000;

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Record {
  Migration {
    due: i64,
    created: Option<i64>,
    instance: Option<String>,
    blocked: Option<String>,
  },
  Retired {
    key: String,
    value: String,
    moved: i64,
    expires: i64,
  },
}

#[derive(Deserialize)]
struct RetiredRepo {
  service: String,
  is_core: bool,
  server: String,
  path: String,
  moved_at: i64,
  expires_at: i64,
}

pub(super) struct Inventory {
  pub(super) policy: DataCleanupPolicy,
  pub(super) records: BTreeMap<(String, CleanupKind, String), Record>,
  tasks: BTreeSet<String>,
  moving_backups: BTreeSet<String>,
  core_backup: Option<String>,
}

fn string_set(
  c: &Connection,
  sql: &str,
) -> Result<BTreeSet<String>, ApiError> {
  c.prepare(sql)
    .map_err(sql_err)?
    .query_map([], |r| r.get(0))
    .map_err(sql_err)?
    .collect::<Result<_, _>>()
    .map_err(sql_err)
}

pub(super) fn inventory(
  c: &mut Connection,
) -> Result<Inventory, ApiError> {
  let mut records = BTreeMap::new();
  let mut rows = c.prepare("SELECT service, server, due_at, created_at, instance_id, blocked_reason FROM cleanups").map_err(sql_err)?;
  let rows = rows
    .query_map([], |r| {
      Ok((
        (
          r.get::<_, String>(1)?,
          MigrateOldData,
          r.get::<_, String>(0)?,
        ),
        Record::Migration {
          due: r.get(2)?,
          created: r.get(3)?,
          instance: r.get(4)?,
          blocked: r.get(5)?,
        },
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (key, record) = row.map_err(sql_err)?;
    records.insert(key, record);
  }
  for (key, value) in db::settings_with_prefix(c, RETIRED)? {
    let Ok(repo) = serde_json::from_str::<RetiredRepo>(&value) else {
      continue;
    };
    if repo.is_core != (repo.service == CORE)
      || validate_name("服务", &repo.service).is_err()
      || key != format!("{}@{}", repo.service, repo.server)
      || repo.path != repo_path(&repo.service)
    {
      continue;
    }
    records.insert(
      (repo.server, BackupMoveRetired, repo.service),
      Record::Retired {
        key: format!("{RETIRED}{key}"),
        value,
        moved: repo.moved_at,
        expires: repo.expires_at,
      },
    );
  }
  Ok(Inventory {
    policy: cleanup_policy(c)?,
    records,
    tasks: string_set(c, "SELECT name FROM tasks")?,
    moving_backups: string_set(
      c,
      "SELECT target_key FROM pending_steps WHERE kind = 'backup_move'",
    )?,
    core_backup: crate::core_backup::target(c)?,
  })
}

fn repo_path(service: &str) -> String {
  let root = if service == CORE {
    CORE_BACKUP_ROOT
  } else {
    BACKUP_ROOT
  };
  format!("{root}/{service}")
}

fn known_service(snap: &Snapshot, service: &str) -> bool {
  snap.world.services.contains_key(service)
    || snap.deployed.contains_key(service)
    || pending_service(snap, service)
}

fn pending_service(snap: &Snapshot, service: &str) -> bool {
  snap.pending.migrations.contains_key(service)
    || snap
      .pending
      .service_deletes
      .iter()
      .any(|p| p.service == service)
    || snap
      .pending
      .ensure_dirs
      .values()
      .any(|p| p.service == service)
}

pub(super) fn is_archive(kind: CleanupKind) -> bool {
  matches!(
    kind,
    MigrateTargetBackup | RestoreBackup | BackupMoveArchive
  )
}

fn compose_resource_declared(
  snap: &Snapshot,
  server: &str,
  item: &AgentCleanupEntry,
) -> bool {
  let section = match item.kind {
    OrphanVolume => "volumes",
    OrphanNetwork => "networks",
    _ => return false,
  };
  let target = if item.kind == OrphanNetwork {
    &item.display
  } else {
    &item.target
  };
  snap.world.services.iter().any(|(name, row)| {
    if row.spec.server != server
      && snap.deployed.get(name).is_none_or(|s| s != server)
    {
      return false;
    }
    let wharf_api_types::spec::Source::Compose {
      content: Some(content),
      ..
    } = &row.spec.source
    else {
      return false;
    };
    let Ok(doc) = crate::render::parse_compose(content) else {
      return true;
    };
    doc
      .get(section)
      .and_then(serde_yaml_ng::Value::as_mapping)
      .is_some_and(|map| {
        map.iter().any(|(key, config)| {
          let Some(key) = key.as_str() else {
            return false;
          };
          let explicit = config
            .get("name")
            .and_then(serde_yaml_ng::Value::as_str)
            .or_else(|| {
              config
                .get("external")
                .and_then(|node| node.get("name"))
                .and_then(serde_yaml_ng::Value::as_str)
            });
          if let Some(explicit) = explicit {
            return target == explicit || explicit.contains('$');
          }
          target == key || target == &format!("{name}_{key}")
        })
      })
  })
}

pub(super) fn active_resource(
  snap: &Snapshot,
  inv: &Inventory,
  server: &str,
  item: &AgentCleanupEntry,
  links: &Result<Vec<crate::link::LinkProject>, ApiError>,
) -> bool {
  let service = item.service.as_deref().unwrap_or_default();
  let registered = |kind| {
    inv
      .records
      .contains_key(&(server.into(), kind, service.into()))
  };
  match item.kind {
    OrphanServiceData => {
      !item.blocked_by.is_empty()
        || known_service(snap, service)
        || registered(MigrateOldData)
        || shared_directory_consumer(
          snap,
          service,
          server,
          &item.target,
        )
        .is_some()
    }
    OrphanTaskData => inv.tasks.contains(service),
    OrphanBackupRepo => {
      known_service(snap, service)
        || registered(BackupMoveRetired)
        || inv.moving_backups.contains(service)
    }
    OrphanContainer | OrphanVolume | OrphanNetwork | OrphanImage => {
      known_service(snap, service)
        || snap.world.gateways.contains_key(service)
        || service
          .strip_prefix(wharf_api_types::agent::TASK_DATA_PREFIX)
          .is_some_and(|task| inv.tasks.contains(task))
        || compose_resource_declared(snap, server, item)
    }
    OrphanCaddy => {
      snap
        .world
        .gateways
        .get(service)
        .is_some_and(|gw| gw.spec.server == server)
        || snap
          .pending
          .gateway_downs
          .iter()
          .any(|p| p.gateway == service && p.server == server)
        || snap.pending.gateways_after_dns.contains(service)
    }
    OrphanFrpc => {
      !snap.pending.links_after_dns.is_empty()
        || links.as_ref().ok().is_none_or(|links| {
          links.iter().any(|link| {
            link.server == server && link.project == item.target
          })
        })
    }
    _ => false,
  }
}

pub(super) fn desired_links(
  snap: &Snapshot,
) -> Result<Vec<crate::link::LinkProject>, ApiError> {
  crate::link::projects_for_servers(
    &snap.world,
    &snap.net(&snap.world),
    &snap.secrets,
    &BTreeMap::new(),
    |_| false,
  )
}

pub(super) fn obsolete_migration(
  snap: &Snapshot,
  item: &DataCleanupItem,
) -> Option<&'static str> {
  let service = item.service.as_deref()?;
  let row = snap.world.services.get(service);
  if row.is_some_and(|r| {
    Some(r.instance_id.as_str()) != item.instance_id.as_deref()
  }) {
    Some("服务已同名重建")
  } else if snapshot::service_runtime_server(snap, service)
    == Some(item.server.as_str())
    || row.is_some_and(|r| r.spec.server == item.server)
    || snap.deployed.get(service) == Some(&item.server)
  {
    Some("服务已回到该服务器")
  } else {
    None
  }
}

fn shared_directory_consumer<'a>(
  snap: &'a Snapshot,
  svc: &str,
  server: &str,
  target: &str,
) -> Option<&'a str> {
  let target = Path::new(target);
  crate::shared_volumes::consumers_on(&snap.world, svc, server)
    .next()
    .or_else(|| {
      snap.world.services.iter().find_map(|(name, row)| {
        let relevant = row.spec.server == server
          || snap.deployed.get(name).is_some_and(|s| s == server);
        (relevant
          && crate::data::mounts(name, &row.spec).iter().any(
            |mount| {
              let source = PathBuf::from(&mount.source);
              source.is_absolute()
                && (source.starts_with(target)
                  || target.starts_with(&source))
            },
          ))
        .then_some(name.as_str())
      })
    })
}

pub(crate) fn migration_block(
  snap: &Snapshot,
  service: &str,
  server: &str,
) -> Option<String> {
  if pending_service(snap, service) {
    return Some("服务有未完成的迁移、部署或删除".into());
  }
  shared_directory_consumer(
    snap,
    service,
    server,
    &format!("/srv/{service}"),
  )
  .map(|consumer| format!("服务 {consumer} 仍在引用数据目录"))
}

pub(super) fn cleanup_block(
  snap: &Snapshot,
  inv: &Inventory,
  item: &DataCleanupItem,
) -> Option<String> {
  let svc = item.service.as_deref()?;
  if item.kind == MigrateOldData
    && let Some(reason) = obsolete_migration(snap, item)
  {
    return Some(reason.into());
  }
  if matches!(
    item.kind,
    MigrateOldData
      | MigrateTargetBackup
      | RestoreBackup
      | OrphanServiceData
  ) {
    if pending_service(snap, svc) {
      return Some("服务有未完成的迁移、部署或删除".into());
    }
    let consumer = shared_directory_consumer(
      snap,
      svc,
      &item.server,
      &item.target,
    );
    if let Some(consumer) = consumer {
      return Some(format!("服务 {consumer} 仍在引用数据目录"));
    }
  }
  if matches!(
    item.kind,
    BackupMoveRetired | BackupMoveArchive | OrphanBackupRepo
  ) && (inv.moving_backups.contains(svc)
    || (item.kind != BackupMoveArchive
      && (if item.is_core {
        inv.core_backup.as_ref() == Some(&item.server)
      } else {
        snap
          .world
          .services
          .get(svc)
          .and_then(|r| r.spec.backup.as_ref())
          .is_some_and(|b| b.to == item.server)
      })))
  {
    return Some("备份仓库当前在用或正在迁移".into());
  }
  None
}

const fn source(kind: CleanupKind) -> &'static str {
  match kind {
    MigrateOldData => "迁移旧机目录",
    MigrateTargetBackup => "迁移目标留底",
    RestoreBackup => "恢复前留底",
    BackupMoveRetired => "换备份机旧仓库",
    BackupMoveArchive => "换备份机归档",
    OrphanServiceData => "孤儿服务数据",
    OrphanTaskData => "孤儿任务数据",
    OrphanBackupRepo => "孤儿备份仓库",
    OrphanContainer => "孤儿容器",
    OrphanVolume => "孤儿卷",
    OrphanNetwork => "孤儿网络",
    OrphanImage => "孤儿镜像",
    OrphanCaddy => "Caddy 残留",
    OrphanFrpc => "frpc 残留",
  }
}

pub(super) struct Candidate {
  pub(super) item: DataCleanupItem,
  pub(super) agent: AgentCleanupEntry,
  pub(super) record: Option<Record>,
}

impl Candidate {
  pub(super) fn new(
    server: &str,
    agent: AgentCleanupEntry,
    record: Option<Record>,
    days: u32,
  ) -> Self {
    let hash = hex::encode(Sha256::digest(format!(
      "{:?}|{server}|{}",
      agent.kind, agent.target
    )));
    let (created, expires, instance, blocked) = match &record {
      Some(Record::Migration {
        due,
        created,
        instance,
        blocked,
      }) => (
        created.or(Some(due.saturating_sub(7 * DAY_MS))),
        Some(*due),
        instance.clone(),
        blocked.clone(),
      ),
      Some(Record::Retired { moved, expires, .. }) => {
        (Some(*moved), Some(*expires), None, None)
      }
      None => (
        agent.created_at,
        agent.created_at.filter(|_| is_archive(agent.kind)).map(
          |created| created.saturating_add(i64::from(days) * DAY_MS),
        ),
        None,
        None,
      ),
    };
    let blocked_reason = mount_reason(&agent.blocked_by).or(blocked);
    let item = DataCleanupItem {
      id: format!("cln_{}", &hash[..12]),
      kind: agent.kind,
      source: source(agent.kind).into(),
      server: server.into(),
      service: agent.service.clone(),
      is_core: agent.is_core,
      target: agent.target.clone(),
      display: agent.display.clone(),
      size_bytes: agent.size_bytes,
      size_estimated: agent.size_estimated,
      created_at: created.map(to_time),
      expires_at: expires.map(to_time),
      expired: expires.is_some_and(|at| at <= now_ms()),
      instance_id: instance,
      blocked: blocked_reason.is_some(),
      blocked_reason,
      unlabeled: agent.unlabeled,
      detail: agent.detail.clone(),
      server_status: None,
    };
    Self {
      item,
      agent,
      record,
    }
  }

  pub(super) fn update_block(
    &mut self,
    snap: &Snapshot,
    inv: &Inventory,
  ) {
    if let Some(reason) = cleanup_block(snap, inv, &self.item) {
      self.item.blocked = true;
      self.item.blocked_reason = Some(reason);
    }
  }

  pub(super) fn from_record(
    server: &str,
    kind: CleanupKind,
    service: &str,
    record: &Record,
    days: u32,
    scan: Option<&CleanupScanResult>,
  ) -> Self {
    let target = if kind == MigrateOldData {
      format!("/srv/{service}")
    } else {
      repo_path(service)
    };
    let stats = scan.and_then(|scan| scan.path_stats.get(&target));
    let agent = AgentCleanupEntry {
      kind,
      service: Some(service.into()),
      target: target.clone(),
      display: target.clone(),
      is_core: kind == BackupMoveRetired && service == CORE,
      size_bytes: stats.and_then(|stat| {
        stat.size_bytes.or_else(|| (!stat.exists).then_some(0))
      }),
      size_estimated: stats.is_some_and(|stat| stat.size_estimated),
      created_at: None,
      unlabeled: false,
      blocked_by: stats
        .map(|stat| stat.blocked_by.clone())
        .unwrap_or_default(),
      detail: None,
      extra_project: None,
    };
    let mut item =
      Self::new(server, agent, Some(record.clone()), days);
    if let Some(stats) = stats {
      item.item.blocked_reason = mount_reason(&stats.blocked_by);
      item.item.blocked = item.item.blocked_reason.is_some();
    }
    item
  }
}

pub(super) fn mount_reason(users: &[String]) -> Option<String> {
  (!users.is_empty())
    .then(|| format!("仍有容器挂载：{}", users.join("、")))
}

pub(super) struct Listing {
  pub(super) policy: DataCleanupPolicy,
  pub(super) items: Vec<Candidate>,
  pub(super) skipped: Vec<CleanupSkippedServer>,
  pub(super) warnings: Vec<String>,
  pub(super) reclaimable: Option<u64>,
}

fn classify_and_filter(
  snap: &Snapshot,
  inv: &Inventory,
  server: &str,
  entries: Vec<AgentCleanupEntry>,
  links: &Result<Vec<crate::link::LinkProject>, ApiError>,
) -> Vec<Candidate> {
  entries
    .into_iter()
    .filter(|item| !active_resource(snap, inv, server, item, links))
    .map(|item| {
      let mut item =
        Candidate::new(server, item, None, inv.policy.keep_days);
      item.update_block(snap, inv);
      item
    })
    .collect()
}

pub(super) async fn list(
  state: &AppState,
  filters: &Filters,
  sizes: bool,
  cancel: &CancellationToken,
) -> Result<Listing, ApiError> {
  let snap = snapshot::load_inner(&state.db).await?;
  let inv = state.db.call(inventory).await?;
  if let Some(server) = &filters.server
    && !snap.world.servers.contains_key(server)
    && !inv.records.keys().any(|key| &key.0 == server)
  {
    return Err(crate::world::server_not_found(server));
  }
  let servers: BTreeSet<_> = snap
    .world
    .servers
    .keys()
    .chain(inv.records.keys().map(|key| &key.0))
    .filter(|server| {
      filters
        .server
        .as_ref()
        .is_none_or(|wanted| wanted == *server)
    })
    .cloned()
    .collect();
  let results = stream::iter(servers)
    .map(|server| {
      let request = CleanupScanRequest {
        compute_sizes: sizes,
        migrate_services: inv
          .records
          .keys()
          .filter(|(srv, kind, _)| {
            srv == &server && *kind == MigrateOldData
          })
          .map(|(_, _, svc)| svc.clone())
          .collect(),
        retired_repos: inv
          .records
          .keys()
          .filter(|(srv, kind, _)| {
            srv == &server && *kind == BackupMoveRetired
          })
          .map(|(_, _, svc)| repo_path(svc))
          .collect(),
      };
      async move {
        let result = match state.hub.require_data_cleanup(&server) {
          Ok(_) => {
            state
              .hub
              .call(
                &server,
                AgentOp::CleanupScan(request),
                Duration::from_secs(30),
                None,
                cancel,
              )
              .await
          }
          Err(e) => Err(e),
        };
        (server, result)
      }
    })
    .buffer_unordered(8)
    .collect::<BTreeMap<String, Result<CleanupScanResult, ApiError>>>(
    )
    .await;
  let links = desired_links(&snap);
  let mut items = Vec::new();
  let mut skipped = Vec::new();
  let mut warnings = Vec::new();
  let mut reclaimable = None::<u64>;
  for (server, result) in results {
    let (scan, status) = match result {
      Ok(scan) => (Some(scan), None),
      Err(e) => {
        let status = match e.code {
          ErrorCode::AgentOffline => "offline",
          ErrorCode::Conflict
            if !state.hub.supports_data_cleanup(&server) =>
          {
            "old_agent"
          }
          _ => "scan_failed",
        };
        warnings
          .push(format!("{server} 的清理扫描未完成（{status}）"));
        skipped.push(CleanupSkippedServer {
          server: server.clone(),
          reason: status.into(),
          hint: e.hint,
        });
        (None, Some(status.to_string()))
      }
    };
    for ((_, kind, service), record) in
      inv.records.iter().filter(|(key, _)| key.0 == server)
    {
      let mut item = Candidate::from_record(
        &server,
        *kind,
        service,
        record,
        inv.policy.keep_days,
        scan.as_ref(),
      );
      item.item.server_status = status.clone();
      item.update_block(&snap, &inv);
      items.push(item);
    }
    if let Some(scan) = scan {
      if let Some(bytes) = scan.prune_reclaimable_bytes {
        reclaimable =
          Some(reclaimable.unwrap_or(0).saturating_add(bytes));
      }
      warnings.extend(scan.warnings);
      items.extend(classify_and_filter(
        &snap,
        &inv,
        &server,
        scan.entries,
        &links,
      ));
    }
  }
  items.sort_by(|a, b| {
    b.item
      .expired
      .cmp(&a.item.expired)
      .then(b.item.size_bytes.cmp(&a.item.size_bytes))
      .then(a.item.server.cmp(&b.item.server))
      .then(a.item.id.cmp(&b.item.id))
  });
  Ok(Listing {
    policy: inv.policy,
    items,
    skipped,
    warnings,
    reclaimable,
  })
}
