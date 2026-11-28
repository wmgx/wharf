use std::{
  collections::{BTreeMap, BTreeSet},
  fs,
  path::PathBuf,
  time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ContainerLimitsDelta, ProjectLimitsJob},
  spec::Limits,
};

use crate::{
  docker::{Docker, HASH_FILE, io_err, write_private},
  exec::Ctx,
};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const JOURNAL: &str = ".wharf-limits.json";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct Container {
  id: String,
  started: String,
  component: String,
  swap: i64,
}

#[derive(Serialize, Deserialize)]
struct Transaction {
  old_compose: String,
  before: String,
  after: String,
  containers: Vec<Container>,
  changes: BTreeMap<String, ContainerLimitsDelta>,
}

fn journal(docker: &Docker, project: &str) -> PathBuf {
  docker.project_dir(project).join(JOURNAL)
}

pub(crate) fn require_clear(
  docker: &Docker,
  project: &str,
) -> Result<(), ApiError> {
  match fs::symlink_metadata(journal(docker, project)) {
    Ok(_) => Err(
      ApiError::new(
        ErrorCode::Busy,
        format!("服务 {project} 有待恢复的限额更新"),
      )
      .with_hint("用 wharf run retry 重试原地更新步骤"),
    ),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      Ok(())
    }
    Err(error) => Err(io_err(&journal(docker, project))(error)),
  }
}

fn stale(project: &str) -> ApiError {
  ApiError::new(
    ErrorCode::PlanStale,
    format!("服务 {project} 的运行状态已变化"),
  )
  .with_hint("重新运行 wharf plan")
  .suggest("wharf plan")
}

fn unsupported(reason: &str) -> ApiError {
  ApiError::invalid(reason)
}

async fn inspect(
  docker: &Docker,
  ids: &[String],
  ctx: &Ctx,
) -> Result<Vec<Value>, ApiError> {
  if ids.is_empty() {
    return Ok(Vec::new());
  }
  let output = docker.cmd().args([
    "inspect", "--type", "container", "--format",
    r#"{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"labels":{{json .Config.Labels}},"limits":{{json .HostConfig}}}"#,
    "--",
  ]).args(ids).timeout(IO_TIMEOUT).run(ctx).await?.check("读取容器运行状态")?;
  let views = output
    .stdout
    .lines()
    .map(serde_json::from_str)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ApiError::internal("读取容器配置失败"))?;
  if views.len() != ids.len() {
    return Err(ApiError::internal("容器状态数量不一致"));
  }
  Ok(views)
}

fn running(view: &Value) -> bool {
  let state = &view["state"];
  state["Status"] == "running"
    && state["Running"] == true
    && state["Health"]["Status"]
      .as_str()
      .is_none_or(|health| health == "healthy")
}

fn matches_limits(view: &Value, limits: &Limits) -> bool {
  let host = &view["limits"];
  limits.memory_mb.is_none_or(|value| {
    host["Memory"].as_i64() == Some(i64::from(value) << 20)
  }) && limits.cpu_milli.is_none_or(|value| {
    host["NanoCpus"].as_i64() == Some(i64::from(value) * 1_000_000)
      && host["CpuQuota"].as_i64() == Some(0)
      && host["CpuPeriod"].as_i64() == Some(0)
  }) && limits.pids.is_none_or(|value| {
    host["PidsLimit"].as_u64() == Some(u64::from(value))
  })
}

async fn candidates(
  docker: &Docker,
  job: &ProjectLimitsJob,
  after: bool,
  ctx: &Ctx,
) -> Result<Vec<Container>, ApiError> {
  let project = &job.project;
  let dir = docker.project_dir(project);
  let out = docker
    .cmd()
    .args(["ps", "-aq", "--no-trunc", "--filter"])
    .arg(format!("label=com.docker.compose.project={project}"))
    .timeout(IO_TIMEOUT)
    .run(ctx)
    .await?
    .check("枚举项目容器")?;
  let ids = out
    .stdout
    .split_whitespace()
    .map(str::to_owned)
    .collect::<Vec<_>>();
  let views = inspect(docker, &ids, ctx).await?;
  let mut seen = BTreeSet::new();
  let mut targets = Vec::new();
  for (id, view) in ids.into_iter().zip(views) {
    let labels = &view["labels"];
    let component = labels["com.docker.compose.service"]
      .as_str()
      .ok_or_else(|| stale(project))?;
    if labels["com.docker.compose.project"] != project.as_str()
      || labels["com.docker.compose.oneoff"]
        .as_str()
        .is_some_and(|x| x.eq_ignore_ascii_case("true"))
      || labels["com.docker.compose.project.working_dir"]
        .as_str()
        .map(std::path::Path::new)
        != Some(dir.as_path())
      || view["id"] != id.as_str()
      || !running(&view)
      || job.images.get(component).map(String::as_str)
        != view["image"].as_str()
      || !job.images.contains_key(component)
    {
      return Err(stale(project));
    }
    seen.insert(component.to_string());
    let Some(change) = job.changes.get(component) else {
      continue;
    };
    if !matches_limits(
      &view,
      if after { &change.after } else { &change.before },
    ) {
      if !after
        && change.before.cpu_milli.is_some()
        && (view["limits"]["CpuQuota"].as_i64().unwrap_or_default()
          != 0
          || view["limits"]["CpuPeriod"].as_i64().unwrap_or_default()
            != 0)
      {
        return Err(unsupported(
          "容器使用 CPU quota 或 period，需要重建",
        ));
      }
      return Err(stale(project));
    }
    let swap =
      view["limits"]["MemorySwap"].as_i64().unwrap_or_default();
    if let Some(memory) = change.after.memory_mb {
      let max =
        memory.max(change.before.memory_mb.unwrap_or_default());
      if swap != -1 && swap < i64::from(max) << 20 {
        return Err(unsupported("现有 swap 无法安全保留，需要重建"));
      }
      if !after
        && change.before.memory_mb.is_some_and(|old| memory < old)
      {
        let stats = docker
          .cmd()
          .args([
            "stats",
            "--no-stream",
            "--format",
            "{{.MemUsage}}",
            &id,
          ])
          .timeout(IO_TIMEOUT)
          .run(ctx)
          .await?
          .check("读取容器内存占用")?;
        let used = crate::metrics::first_size(&stats.stdout);
        if used == 0
          || used.saturating_add(1 << 20) >= u64::from(memory) << 20
        {
          return Err(unsupported(
            "容器当前内存占用接近或超过目标上限，需要重建",
          ));
        }
      }
    }
    targets.push(Container {
      id,
      started: view["state"]["StartedAt"]
        .as_str()
        .filter(|at| !at.is_empty())
        .ok_or_else(|| stale(project))?
        .into(),
      component: component.into(),
      swap,
    });
  }
  if seen.iter().ne(job.images.keys()) || targets.is_empty() {
    return Err(stale(project));
  }
  targets.sort_unstable_by(|a, b| a.id.cmp(&b.id));
  Ok(targets)
}

async fn verify(
  docker: &Docker,
  project: &str,
  container: &Container,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let mut views =
    inspect(docker, std::slice::from_ref(&container.id), ctx).await?;
  let view = views.pop().ok_or_else(|| stale(project))?;
  if view["id"] != container.id.as_str()
    || view["state"]["StartedAt"] != container.started.as_str()
    || view["labels"]["com.docker.compose.project"] != project
    || view["labels"]["com.docker.compose.service"]
      != container.component.as_str()
    || !running(&view)
  {
    return Err(stale(project));
  }
  Ok(view)
}

async fn set_limits(
  docker: &Docker,
  project: &str,
  container: &Container,
  limits: &Limits,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let before = verify(docker, project, container, ctx).await?;
  if limits.memory_mb.is_some()
    && before["limits"]["MemorySwap"].as_i64() != Some(container.swap)
  {
    return Err(stale(project));
  }
  if matches_limits(&before, limits) {
    return Ok(());
  }
  let mut command = docker.cmd().arg("update");
  if let Some(memory) = limits.memory_mb {
    command = command.args([
      "--memory",
      &format!("{memory}m"),
      "--memory-swap",
      &container.swap.to_string(),
    ]);
  }
  if let Some(cpu) = limits.cpu_milli {
    command = command
      .args(["--cpus", &format!("{}.{:03}", cpu / 1000, cpu % 1000)]);
  }
  if let Some(pids) = limits.pids {
    command = command.args(["--pids-limit", &pids.to_string()]);
  }
  command
    .arg(&container.id)
    .timeout(IO_TIMEOUT)
    .run(ctx)
    .await?
    .check("docker update")?;
  let after = verify(docker, project, container, ctx).await?;
  if !matches_limits(&after, limits)
    || (limits.memory_mb.is_some()
      && after["limits"]["MemorySwap"].as_i64()
        != Some(container.swap))
  {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "容器未应用计划中的资源上限",
    ));
  }
  Ok(())
}

fn sync_dir(dir: &std::path::Path) -> Result<(), ApiError> {
  fs::File::open(dir)
    .and_then(|file| file.sync_all())
    .map_err(io_err(dir))
}

fn clear(docker: &Docker, project: &str) -> Result<(), ApiError> {
  let path = journal(docker, project);
  fs::remove_file(&path).map_err(io_err(&path))?;
  sync_dir(&docker.project_dir(project))
}

async fn recover(
  docker: &Docker,
  project: &str,
  tx: &Transaction,
  toward_new: bool,
) -> Result<(), ApiError> {
  let dir = docker.project_dir(project);
  let ctx = Ctx::detached();
  // 先全量核对身份，避免恢复一半才发现 Docker 已经换了容器。
  for container in &tx.containers {
    let view = verify(docker, project, container, &ctx).await?;
    let delta = &tx.changes[&container.component];
    if toward_new {
      if !matches_limits(&view, &delta.after) {
        return Err(stale(project));
      }
    } else if !matches_limits(&view, &delta.before)
      && !matches_limits(&view, &delta.after)
    {
      return Err(stale(project));
    }
  }
  if !toward_new {
    for container in tx.containers.iter().rev() {
      set_limits(
        docker,
        project,
        container,
        &tx.changes[&container.component].before,
        &ctx,
      )
      .await?;
    }
    write_private(&dir.join("compose.yaml"), &tx.old_compose)?;
    write_private(&dir.join(HASH_FILE), &tx.before)?;
    sync_dir(&dir)?;
  }
  clear(docker, project)
}

fn current_hash(
  docker: &Docker,
  project: &str,
) -> Result<String, ApiError> {
  fs::read_to_string(docker.project_dir(project).join(HASH_FILE))
    .map(|hash| hash.trim().into())
    .map_err(|_| stale(project))
}

pub(crate) async fn check(
  docker: &Docker,
  job: &ProjectLimitsJob,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  require_clear(docker, &job.project)?;
  if current_hash(docker, &job.project)? != job.before_hash {
    return Err(stale(&job.project));
  }
  candidates(docker, job, false, ctx).await?;
  Ok(())
}

pub(crate) async fn update(
  docker: &Docker,
  job: &ProjectLimitsJob,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let project = &job.project;
  let dir = docker.project_dir(project);
  let record = journal(docker, project);
  let hash = current_hash(docker, project)?;
  match fs::read_to_string(&record) {
    Ok(contents) => {
      let tx: Transaction = serde_json::from_str(&contents)
        .map_err(|_| stale(project))?;
      if hash != tx.before && hash != tx.after {
        return Err(stale(project));
      }
      if hash == tx.after
        && (hash != job.hash
          || docker.read_compose(project).ok().flatten().as_deref()
            != Some(job.compose.as_str()))
      {
        return Err(stale(project));
      }
      tokio::time::timeout(
        Duration::from_secs(300),
        recover(docker, project, &tx, hash == tx.after),
      )
      .await
      .map_err(|_| {
        ApiError::new(ErrorCode::Timeout, "恢复原地更新超时")
      })??;
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
    Err(error) => return Err(io_err(&record)(error)),
  }
  if hash == job.hash {
    if docker.read_compose(project).ok().flatten().as_deref()
      != Some(job.compose.as_str())
    {
      return Err(stale(project));
    }
    candidates(docker, job, true, ctx).await?;
    return Ok(());
  }
  if hash != job.before_hash {
    return Err(stale(project));
  }
  let containers = candidates(docker, job, false, ctx).await?;
  let tx = Transaction {
    before: hash,
    after: job.hash.clone(),
    old_compose: docker
      .read_compose(project)
      .ok()
      .flatten()
      .ok_or_else(|| stale(project))?,
    containers,
    changes: job.changes.clone(),
  };
  let encoded = serde_json::to_string(&tx)
    .map_err(|_| ApiError::internal("编码限额事务失败"))?;
  write_private(&record, &encoded)?;
  sync_dir(&dir)?;
  let result = async {
    for container in &tx.containers {
      set_limits(
        docker,
        project,
        container,
        &tx.changes[&container.component].after,
        ctx,
      )
      .await?;
    }
    if candidates(docker, job, true, ctx).await? != tx.containers {
      return Err(stale(project));
    }
    write_private(&dir.join("compose.yaml"), &job.compose)?;
    sync_dir(&dir)?;
    write_private(&dir.join(HASH_FILE), &job.hash)?;
    sync_dir(&dir)
  }
  .await;
  if let Err(error) = result {
    let committed = current_hash(docker, project)
      .is_ok_and(|hash| hash == tx.after);
    let restored = matches!(
      tokio::time::timeout(
        Duration::from_secs(300),
        recover(docker, project, &tx, committed)
      )
      .await,
      Ok(Ok(()))
    );
    if committed && restored {
      return Ok(());
    }
    let state = if restored {
      "已恢复原上限"
    } else {
      "恢复未完成，事务记录已保留"
    };
    return Err(ApiError::new(
      error.code,
      format!("服务 {project} 原地更新限额失败（{state}）"),
    ));
  }
  clear(docker, project)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::docker::fake_docker;

  #[tokio::test]
  async fn failed_second_replica_rolls_back_and_can_be_retried() {
    let (temp, docker) = fake_docker(
      r#"
case "$1" in
  ps) printf 'id1\nid2\n' ;;
  inspect)
    shift 6
    for id in "$@"; do
      if [ ! -e "$id" ]; then printf '500000000' > "$id"; fi
      cpu=$(cat "$id")
      printf '{"id":"%s","image":"sha256:fixture","state":{"Status":"running","Running":true,"StartedAt":"fixture"},' "$id"
      printf '"labels":{"com.docker.compose.project":"app","com.docker.compose.service":"web","com.docker.compose.project.working_dir":"%s/projects/app"},' "$(pwd)"
      printf '"limits":{"NanoCpus":%s,"CpuQuota":0,"CpuPeriod":0}}\n' "$cpu"
    done ;;
  update)
    if [ "$3" = "0.750" ]; then
      if [ "$4" = "id2" ] && [ -e fail ]; then exit 1; fi
      printf 750000000 > "$4"
    else
      printf 500000000 > "$4"
    fi ;;
  *) exit 1 ;;
esac
"#,
    );
    let before = Limits {
      cpu_milli: Some(500),
      ..Default::default()
    };
    let after = Limits {
      cpu_milli: Some(750),
      ..Default::default()
    };
    let job = ProjectLimitsJob {
      project: "app".into(),
      before_hash: "before".into(),
      hash: "after".into(),
      compose: "new".into(),
      changes: BTreeMap::from([(
        "web".into(),
        ContainerLimitsDelta { before, after },
      )]),
      images: BTreeMap::from([(
        "web".into(),
        "sha256:fixture".into(),
      )]),
    };
    docker.write_compose("app", "old").unwrap();
    docker.write_hash("app", "before").unwrap();
    fs::write(temp.path().join("fail"), "").unwrap();
    let ctx = Ctx::detached();
    assert!(
      update(&docker, &job, &ctx)
        .await
        .unwrap_err()
        .message
        .contains("已恢复原上限")
    );
    assert_eq!(
      fs::read_to_string(temp.path().join("id1")).unwrap(),
      "500000000"
    );
    assert_eq!(current_hash(&docker, "app").unwrap(), "before");
    assert_eq!(
      docker.read_compose("app").unwrap().as_deref(),
      Some("old")
    );
    fs::remove_file(temp.path().join("fail")).unwrap();
    update(&docker, &job, &ctx).await.unwrap();
    update(&docker, &job, &ctx).await.unwrap();
    assert_eq!(current_hash(&docker, "app").unwrap(), "after");
    assert_eq!(
      fs::read_to_string(temp.path().join("id2")).unwrap(),
      "750000000"
    );
  }
}
