use crate::{
  dirfd::{self, DirFd},
  docker::{Docker, containers_using_path, io_err},
  exec::Ctx,
  ops::Ops,
};
use chrono::{NaiveDateTime, Utc};
use std::{
  collections::BTreeMap,
  io,
  path::{Path, PathBuf},
  time::{Duration, Instant},
};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentCleanupEntry, BACKUP_ROOT, BindMountUser, CORE_BACKUP_ROOT,
    CleanupDeleteRequest, CleanupDeleteResult,
    CleanupKind::{self, *},
    CleanupScanRequest, CleanupScanResult, PathCleanupStat,
    TASK_DATA_PREFIX,
  },
  validate_name,
};

const SRV: &str = "/srv";
const MIGRATE: &str = ".wharf-migrate";
const RESTORE: &str = ".wharf-restore";
const ARCHIVE: &str = ".wharf-backup-archive";
const CORE: &str = "wharf-core";

mod runtime;
use runtime::{PROJECT, containers, docker_entries, label, runtime};

fn valid(name: &str) -> bool {
  validate_name("服务", name).is_ok()
}

fn reserved(project: &str) -> bool {
  matches!(
    project,
    CORE
      | "wharf-agent"
      | "wharf-tailscale"
      | "wharf-backup"
      | "wharf-backup-core"
      | "wharf-link"
  ) || project.starts_with("wharf-link-")
    || project.starts_with("wharf-gw-")
}

fn entry(
  kind: CleanupKind,
  service: Option<&str>,
  target: String,
) -> AgentCleanupEntry {
  AgentCleanupEntry {
    kind,
    service: service.map(str::to_string),
    display: target.clone(),
    target,
    is_core: false,
    size_bytes: None,
    size_estimated: false,
    created_at: None,
    unlabeled: false,
    blocked_by: vec![],
    detail: None,
    extra_project: None,
  }
}

fn backup_root(core: bool) -> &'static str {
  if core { CORE_BACKUP_ROOT } else { BACKUP_ROOT }
}

fn stamped<'a>(
  name: &'a str,
  marker: &str,
) -> Option<(&'a str, i64)> {
  let (name, stamp) = name.rsplit_once(marker)?;
  let stamp =
    NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S").ok()?;
  valid(name).then_some((name, stamp.and_utc().timestamp_millis()))
}

fn restore<'a>(
  name: &'a str,
  owner: Option<&'a str>,
) -> Option<(&'a str, i64)> {
  let (prefix, time) = crate::restic::restore_dir_stamp(name)?;
  let service = match owner {
    Some(service) if prefix == ".wharf-restore-before" => service,
    None => prefix.strip_suffix("-before")?,
    _ => return None,
  };
  valid(service)
    .then_some((service, time.and_utc().timestamp_millis()))
}

fn dir_entries(
  path: &Path,
) -> Result<Vec<wharf_api_types::agent::FileEntry>, ApiError> {
  match DirFd::open_absolute(path) {
    Ok(fd) => Ok(
      fd.read_entries(path)?
        .into_iter()
        .filter(|entry| entry.dir && !entry.link)
        .collect(),
    ),
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
    Err(e) => Err(dirfd::dir_error(path, e)),
  }
}

fn directory_entries(
  srv: &Path,
  projects: &Path,
  ctx: &Ctx,
) -> Result<Vec<AgentCleanupEntry>, ApiError> {
  let mut entries = Vec::new();
  for (root, marker, kind, core) in [
    (srv.join(MIGRATE), "-before-", MigrateTargetBackup, false),
    (srv.join(RESTORE), "", RestoreBackup, false),
    (
      srv.join("wharf-backup").join(ARCHIVE),
      "-replaced-",
      BackupMoveArchive,
      false,
    ),
    (
      srv.join("wharf-backup-core").join(ARCHIVE),
      "-replaced-",
      BackupMoveArchive,
      true,
    ),
  ] {
    for info in dir_entries(&root)? {
      cancelled(ctx)?;
      let parsed = if kind == RestoreBackup {
        restore(&info.name, None)
      } else {
        stamped(&info.name, marker)
      };
      if let Some((service, created)) = parsed {
        if core && service != CORE {
          continue;
        }
        let mut item = entry(
          kind,
          Some(service),
          root.join(&info.name).display().to_string(),
        );
        item.created_at = Some(created);
        item.is_core = core;
        entries.push(item);
      }
    }
  }
  for info in dir_entries(srv)? {
    cancelled(ctx)?;
    let path = srv.join(&info.name);
    let (kind, name) =
      if let Some(gw) = info.name.strip_prefix("wharf-gw-") {
        (OrphanCaddy, gw)
      } else if let Some(task) =
        info.name.strip_prefix(TASK_DATA_PREFIX)
      {
        (OrphanTaskData, task)
      } else if reserved(&info.name) {
        continue;
      } else {
        (OrphanServiceData, info.name.as_str())
      };
    if !valid(name) {
      continue;
    }
    let mut item =
      entry(kind, Some(name), path.display().to_string());
    if kind == OrphanCaddy {
      item.extra_project = Some(info.name.clone());
    }
    entries.push(item);
    if kind == OrphanServiceData {
      for backup in dir_entries(&path)? {
        if let Some((_, created)) = restore(&backup.name, Some(name))
        {
          let mut item = entry(
            RestoreBackup,
            Some(name),
            path.join(backup.name).display().to_string(),
          );
          item.created_at = Some(created);
          entries.push(item);
        }
      }
    }
  }
  let backups = srv.join("wharf-backup");
  for info in dir_entries(&backups)? {
    let path = backups.join(&info.name);
    if valid(&info.name)
      && info.name != CORE
      && !DirFd::open_absolute(&path)
        .map_err(|e| dirfd::dir_error(&path, e))?
        .read_entries(&path)?
        .is_empty()
    {
      entries.push(entry(
        OrphanBackupRepo,
        Some(&info.name),
        path.display().to_string(),
      ));
    }
  }
  for info in dir_entries(projects)? {
    if frpc_project(&info.name) {
      entries.push(entry(OrphanFrpc, None, info.name));
    } else if let Some(gw) = info
      .name
      .strip_prefix("wharf-gw-")
      .filter(|name| valid(name))
    {
      let target = srv.join(&info.name).display().to_string();
      if !entries
        .iter()
        .any(|item| item.kind == OrphanCaddy && item.target == target)
      {
        let mut item = entry(OrphanCaddy, Some(gw), target);
        item.extra_project = Some(info.name);
        entries.push(item);
      }
    }
  }
  Ok(entries)
}

fn frpc_project(name: &str) -> bool {
  name == "wharf-link"
    || name.strip_prefix("wharf-link-").is_some_and(valid)
}

fn cancelled(ctx: &Ctx) -> Result<(), ApiError> {
  if ctx.cancel.is_cancelled() {
    Err(ApiError::new(ErrorCode::Cancelled, "已取消"))
  } else {
    Ok(())
  }
}

fn stat_path(
  path: &Path,
  deadline: Option<Instant>,
  ctx: &Ctx,
) -> Result<PathCleanupStat, ApiError> {
  fn size(
    dir: &DirFd,
    left: &mut u32,
    bytes: &mut u64,
    deadline: Instant,
    depth: u32,
    ctx: &Ctx,
  ) -> io::Result<()> {
    if depth > 64 {
      return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    dir.visit_names(|name| {
      if *left == 0
        || ctx.cancel.is_cancelled()
        || Instant::now() >= deadline
      {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
      }
      *left -= 1;
      let st = dir.lstat(name)?;
      if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        let sub = dir.open_subdir(name)?;
        if !dir.same_mount(&sub)? {
          return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        size(&sub, left, bytes, deadline, depth + 1, ctx)?;
      } else if st.st_mode & libc::S_IFMT == libc::S_IFREG {
        *bytes = bytes.saturating_add(st.st_size.max(0) as u64);
      }
      Ok(())
    })
  }
  let dir = match DirFd::open_absolute(path) {
    Ok(fd) => fd,
    Err(e) if e.kind() == io::ErrorKind::NotFound => {
      return Ok(PathCleanupStat::default());
    }
    Err(e) => return Err(dirfd::dir_error(path, e)),
  };
  let metadata = dir.stat_self().map_err(io_err(path))?;
  let mut stat = PathCleanupStat {
    exists: true,
    modified_at: Some(metadata.st_mtime.saturating_mul(1000)),
    ..Default::default()
  };
  if let Some(deadline) = deadline {
    let mut total = 0;
    stat.size_estimated =
      size(&dir, &mut 200_000, &mut total, deadline, 0, ctx).is_err();
    cancelled(ctx)?;
    stat.size_bytes = Some(total);
  }
  Ok(stat)
}

fn blockers(target: &Path, binds: &[BindMountUser]) -> Vec<String> {
  let filtered: Vec<_> = binds
    .iter()
    .filter(|m| {
      ![
        (BACKUP_ROOT, "wharf-backup"),
        (CORE_BACKUP_ROOT, "wharf-backup-core"),
      ]
      .iter()
      .any(|(root, project)| {
        target.starts_with(root)
          && m.source == *root
          && m.project.as_deref() == Some(project)
      })
    })
    .cloned()
    .collect();
  containers_using_path(target, &filtered)
}

pub async fn scan(
  docker: &Docker,
  req: CleanupScanRequest,
  ctx: &Ctx,
) -> Result<CleanupScanResult, ApiError> {
  let (current, reclaimable) =
    tokio::join!(runtime(docker, ctx), async {
      if !req.compute_sizes {
        return None;
      }
      crate::host::docker_df(docker, ctx)
        .await
        .into_iter()
        .filter(|row| {
          matches!(row.kind.as_str(), "Images" | "Build Cache")
        })
        .filter_map(|row| docker_bytes(&row.reclaimable))
        .reduce(u64::saturating_add)
    });
  let current = current?;
  let mut entries = docker_entries(&current, docker, Utc::now());
  let projects = docker.project_dir("");
  let docker = docker.clone();
  let ctx = ctx.clone();
  tokio::task::spawn_blocking(move || {
    let deadline = req
      .compute_sizes
      .then(|| Instant::now() + Duration::from_secs(15));
    let mut dirs =
      directory_entries(Path::new(SRV), &projects, &ctx)?;
    let mut path_stats = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut stats =
      |path: &Path| -> Result<PathCleanupStat, ApiError> {
        cancelled(&ctx)?;
        match stat_path(path, deadline, &ctx) {
          Ok(mut stat) => {
            stat.blocked_by = blockers(path, &current.binds);
            Ok(stat)
          }
          Err(e) if e.code == ErrorCode::Cancelled => Err(e),
          Err(_) => {
            warnings.push(format!("无法统计 {}", path.display()));
            Ok(PathCleanupStat::default())
          }
        }
      };
    for item in &mut dirs {
      let path = if item.kind == OrphanFrpc {
        projects.join(&item.target)
      } else {
        PathBuf::from(&item.target)
      };
      let mut stat = stats(&path)?;
      if let Some(project) = &item.extra_project {
        let extra = stats(&projects.join(project))?;
        stat.size_estimated |= extra.size_estimated;
        stat.size_bytes = match (stat.size_bytes, extra.size_bytes) {
          (Some(a), Some(b)) => Some(a.saturating_add(b)),
          (a, b) => a.or(b),
        };
        stat.modified_at = stat.modified_at.or(extra.modified_at);
      }
      if matches!(item.kind, OrphanCaddy | OrphanFrpc) {
        let project =
          item.extra_project.as_deref().unwrap_or(&item.target);
        let binds = current.project_binds(&docker, project);
        stat.blocked_by = blockers(&path, &binds);
        if let Some(extra) = &item.extra_project {
          stat
            .blocked_by
            .extend(blockers(&projects.join(extra), &binds));
        }
        stat
          .blocked_by
          .extend(current.project_blockers(&docker, project));
      }
      item.size_bytes = stat.size_bytes;
      item.size_estimated = stat.size_estimated;
      item.created_at = item.created_at.or(stat.modified_at);
      item.blocked_by = stat.blocked_by;
    }
    for service in req.migrate_services.into_iter().filter(|name| {
      valid(name)
        && !reserved(name)
        && !name.starts_with(TASK_DATA_PREFIX)
    }) {
      let path = Path::new(SRV).join(service);
      path_stats.insert(path.display().to_string(), stats(&path)?);
    }
    for repo in req.retired_repos {
      let path = Path::new(&repo);
      if path.file_name().and_then(|s| s.to_str()).is_some_and(
        |key| repo_path(key, key == CORE) == path && valid(key),
      ) {
        path_stats.insert(repo.clone(), stats(path)?);
      }
    }
    entries.extend(dirs);
    Ok(CleanupScanResult {
      entries,
      path_stats,
      warnings,
      prune_reclaimable_bytes: reclaimable,
    })
  })
  .await
  .map_err(|_| ApiError::internal("清理扫描中断"))?
}

fn docker_bytes(text: &str) -> Option<u64> {
  let size = text.split_whitespace().next()?;
  let split = size.find(|c: char| c.is_ascii_alphabetic())?;
  let scale = match &size[split..] {
    "B" => 1.0,
    "kB" => 1_000.0,
    "MB" => 1_000_000.0,
    "GB" => 1_000_000_000.0,
    "TB" => 1_000_000_000_000.0,
    _ => return None,
  };
  Some((size[..split].parse::<f64>().ok()? * scale) as u64)
}

fn repo_path(service: &str, core: bool) -> PathBuf {
  Path::new(backup_root(core)).join(service)
}

fn directory_target(
  req: &CleanupDeleteRequest,
  srv: &Path,
  projects: &Path,
) -> Result<(PathBuf, PathBuf, String), ApiError> {
  let bad = || ApiError::invalid("清理目标不在允许的目录内");
  let path = Path::new(&req.target);
  let service = req.service.as_deref().filter(|name| valid(name));
  let key = service.unwrap_or_default();
  let name =
    path.file_name().and_then(|s| s.to_str()).ok_or_else(bad)?;
  let (base, rel, lock) = match req.kind {
    MigrateOldData | OrphanServiceData
      if service.is_some()
        && !reserved(key)
        && !key.starts_with(TASK_DATA_PREFIX)
        && path == srv.join(key) =>
    {
      (srv.into(), PathBuf::from(key), key.to_string())
    }
    OrphanTaskData
      if service.is_some()
        && path == srv.join(format!("{TASK_DATA_PREFIX}{key}")) =>
    {
      (srv.into(), name.into(), name.to_string())
    }
    MigrateTargetBackup
      if path == srv.join(MIGRATE).join(name)
        && stamped(name, "-before-")
          .is_some_and(|(owner, _)| Some(owner) == service) =>
    {
      (srv.into(), Path::new(MIGRATE).join(name), key.to_string())
    }
    RestoreBackup
      if path == srv.join(RESTORE).join(name)
        && restore(name, None)
          .is_some_and(|(owner, _)| Some(owner) == service) =>
    {
      (srv.into(), Path::new(RESTORE).join(name), key.to_string())
    }
    RestoreBackup
      if service.is_some()
        && path == srv.join(key).join(name)
        && restore(name, service).is_some() =>
    {
      (srv.join(key), name.into(), key.to_string())
    }
    BackupMoveRetired | OrphanBackupRepo
      if service.is_some()
        && req.is_core == (key == CORE)
        && path == repo_path(key, req.is_core) =>
    {
      (
        PathBuf::from(backup_root(req.is_core)),
        key.into(),
        key.to_string(),
      )
    }
    BackupMoveArchive
      if service.is_some()
        && req.is_core == (key == CORE)
        && path
          == Path::new(backup_root(req.is_core))
            .join(ARCHIVE)
            .join(name)
        && stamped(name, "-replaced-")
          .is_some_and(|(owner, _)| owner == key) =>
    {
      (
        PathBuf::from(backup_root(req.is_core)),
        Path::new(ARCHIVE).join(name),
        key.to_string(),
      )
    }
    OrphanCaddy
      if service.is_some()
        && path == srv.join(format!("wharf-gw-{key}"))
        && req.extra_project.as_deref() == Some(name) =>
    {
      (srv.into(), name.into(), name.to_string())
    }
    OrphanFrpc if frpc_project(&req.target) => (
      projects.into(),
      req.target.as_str().into(),
      req.target.clone(),
    ),
    _ => return Err(bad()),
  };
  Ok((base, rel, lock))
}

fn removed(freed_bytes: u64) -> CleanupDeleteResult {
  CleanupDeleteResult {
    removed: true,
    freed_bytes,
    blocked_by: vec![],
    detail: None,
  }
}

fn blocked(blocked_by: Vec<String>) -> CleanupDeleteResult {
  CleanupDeleteResult {
    removed: false,
    freed_bytes: 0,
    blocked_by,
    detail: None,
  }
}

pub async fn delete(
  ops: &Ops,
  req: CleanupDeleteRequest,
  ctx: &Ctx,
) -> Result<CleanupDeleteResult, ApiError> {
  let docker = &ops.docker;
  if matches!(
    req.kind,
    OrphanContainer | OrphanVolume | OrphanNetwork | OrphanImage
  ) {
    let current = runtime(docker, ctx).await?;
    let current = docker_entries(&current, docker, Utc::now())
      .into_iter()
      .find(|item| {
        item.kind == req.kind
          && item.target == req.target
          && item.service == req.service
          && item.is_core == req.is_core
      })
      .ok_or_else(|| {
        ApiError::new(
          ErrorCode::Conflict,
          "Docker 资源已变化或仍在使用",
        )
      })?;
    if !current.blocked_by.is_empty() {
      return Ok(blocked(current.blocked_by));
    }
    let command = match req.kind {
      OrphanContainer => "container",
      OrphanVolume => "volume",
      OrphanNetwork => "network",
      OrphanImage => "image",
      _ => unreachable!(),
    };
    docker
      .cmd()
      .args([command, "rm", "--", &req.target])
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await?
      .check("删除 Docker 资源")?;
    return Ok(removed(current.size_bytes.unwrap_or(0)));
  }

  let projects = docker.project_dir("");
  let (base, rel, key) =
    directory_target(&req, Path::new(SRV), &projects)?;
  let _project = ops.lock_data(&key, ctx).await?;
  let repo = matches!(
    req.kind,
    BackupMoveArchive | BackupMoveRetired | OrphanBackupRepo
  )
  .then(|| ops.cleanup_repo_lock(&key))
  .transpose()?;
  if matches!(
    req.kind,
    MigrateOldData | OrphanServiceData | OrphanTaskData
  ) && docker
    .project_dir(&key)
    .join("compose.yaml")
    .symlink_metadata()
    .is_ok()
  {
    return Ok(blocked(vec![key]));
  }
  let path = base.join(&rel);
  let extra = req
    .extra_project
    .as_ref()
    .filter(|_| req.kind == OrphanCaddy)
    .map(|p| projects.join(p));
  let current = containers(docker, ctx).await?;
  let project_cleanup = matches!(req.kind, OrphanCaddy | OrphanFrpc);
  let relevant_binds =
    project_cleanup.then(|| current.project_binds(docker, &key));
  let binds = relevant_binds.as_deref().unwrap_or(&current.binds);
  let mut users = blockers(&path, binds);
  if let Some(extra) = &extra {
    users.extend(blockers(extra, binds));
  }
  if project_cleanup {
    users.extend(current.project_blockers(docker, &key));
  }
  if repo.is_some() {
    users.extend(
      current
        .containers
        .iter()
        .filter(|c| {
          label(&c.5, "wharf.restic.service") == Some(&key)
            && !matches!(c.2.as_str(), "exited" | "dead")
        })
        .map(|c| c.1.clone()),
    );
  }
  users.sort_unstable();
  users.dedup();
  if !users.is_empty() {
    return Ok(blocked(users));
  }
  let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
    .map_err(io_err(Path::new("/proc/self/mountinfo")))?;
  if [&path].into_iter().chain(extra.iter()).any(|path| {
    mountinfo
      .lines()
      .filter_map(|line| line.split_whitespace().nth(4))
      .any(|mount| {
        let mount = mount
          .replace("\\040", " ")
          .replace("\\011", "\t")
          .replace("\\012", "\n")
          .replace("\\134", "\\");
        Path::new(&mount).starts_with(path)
      })
  }) {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "目标目录含有活跃挂载点",
    ));
  }
  let measure = path.clone();
  let extra_measure = extra.clone();
  let measure_ctx = ctx.clone();
  let bytes = tokio::task::spawn_blocking(move || {
    let deadline = Some(Instant::now() + Duration::from_secs(15));
    let mut bytes = stat_path(&measure, deadline, &measure_ctx)?
      .size_bytes
      .unwrap_or(0);
    if let Some(extra) = extra_measure {
      bytes = bytes.saturating_add(
        stat_path(&extra, deadline, &measure_ctx)?
          .size_bytes
          .unwrap_or(0),
      );
    }
    Ok::<_, ApiError>(bytes)
  })
  .await
  .map_err(|_| ApiError::internal("清理目录测量中断"))??;
  // 测量可能耗时，实际删除前再次核对挂载。
  let live = containers(docker, ctx).await?;
  let relevant_binds =
    project_cleanup.then(|| live.project_binds(docker, &key));
  let binds = relevant_binds.as_deref().unwrap_or(&live.binds);
  let mut users = blockers(&path, binds);
  if let Some(extra) = &extra {
    users.extend(blockers(extra, binds));
  }
  if project_cleanup {
    users.extend(live.project_blockers(docker, &key));
  }
  if !users.is_empty() {
    return Ok(blocked(users));
  }
  if project_cleanup {
    let ids = live.owned_stops(docker, &key);
    if !ids.is_empty() {
      docker
        .cmd()
        .args(["container", "rm", "--"])
        .args(ids)
        .timeout(Duration::from_secs(60))
        .run(ctx)
        .await?
        .check("移除孤儿项目的已停止容器")?;
    }
  }
  dirfd::remove_tree_under(&base, &rel, ctx).await?;
  if extra.is_some() {
    dirfd::remove_tree_under(&projects, Path::new(&key), ctx).await?;
  }
  Ok(removed(bytes))
}

#[cfg(test)]
mod tests;
