//! 导入服务器上已有的容器：列出容器、读取配置、接管时停掉原来的容器。
//!
//! 只读出原始配置（`docker compose config`、`docker inspect`），
//! 转换成 Wharf 服务的事由控制面做。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::Path,
  time::Duration,
};

use serde_json::Value as Json;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    FoundContainer, ImportRaw, ImportTarget, ProjectContainerRaw,
    Retire, Retired,
  },
};

use crate::{docker::Docker, exec::Ctx};

const QUICK: Duration = Duration::from_secs(30);
const PROJECT_LABEL: &str = "com.docker.compose.project";

/// `docker ps` 的 Mounts 列：具名卷是名字，宿主机目录是路径，匿名卷是 64 位十六进制。
fn named_volumes(mounts: &str) -> Vec<String> {
  mounts
    .split(',')
    .map(str::trim)
    .filter(|m| {
      let anonymous =
        m.len() == 64 && m.bytes().all(|c| c.is_ascii_hexdigit());
      !(m.is_empty()
        || m.starts_with('/')
        || m.contains('…')
        || anonymous)
    })
    .map(str::to_string)
    .collect()
}

/// 删除容器，`volumes` 时再删它们的具名数据卷（还被别的容器用着的会失败，留着）。
pub async fn remove(
  docker: &Docker,
  containers: &[String],
  volumes: bool,
  ctx: &Ctx,
) -> Result<wharf_api_types::agent::RemovedContainers, ApiError> {
  let mut targets = Vec::new();
  for c in containers {
    check_container_name(c)?;
    if let Some(i) = info(docker, c, ctx).await? {
      if i.owned {
        return Err(ApiError::invalid(format!(
          "容器 {} 属于 Wharf 管理，不能作为未纳管容器删除",
          i.name
        )));
      }
      targets.push(i);
    }
  }
  let mut out = wharf_api_types::agent::RemovedContainers::default();
  let mut vols: Vec<String> = Vec::new();
  if volumes {
    for i in &targets {
      let r = docker
        .cmd()
        .args([
          "inspect",
          "-f",
          "{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}},{{end}}{{end}}",
          &i.id,
        ])
        .timeout(QUICK)
        .run(ctx)
        .await?
        .check("docker inspect")?;
      for v in named_volumes(&r.stdout) {
        if !vols.contains(&v) {
          vols.push(v);
        }
      }
    }
  }
  for i in &targets {
    docker
      .cmd()
      .args(["rm", "-f", &i.id])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("docker rm")?;
    out.containers.push(i.name.clone());
  }
  for v in vols {
    let r = docker
      .cmd()
      .args(["volume", "rm", &v])
      .timeout(QUICK)
      .run(ctx)
      .await?;
    if r.success {
      out.volumes.push(v);
    } else {
      out.kept_volumes.push(v);
    }
  }
  Ok(out)
}

fn labels(container: &Json) -> BTreeMap<&str, &str> {
  container["Config"]["Labels"]
    .as_object()
    .into_iter()
    .flatten()
    .filter_map(|(k, v)| Some((k.as_str(), v.as_str()?)))
    .collect()
}

fn wharf_owned(labels: &BTreeMap<&str, &str>) -> bool {
  [
    "wharf.temp",
    "wharf.system",
    "wharf.service",
    "wharf.gateway",
    "wharf.link",
    "wharf.network",
    "wharf.backup",
    "wharf.trial",
    "wharf.task",
    "wharf.sso-runner",
    "com.wharf.host-shell",
  ]
  .iter()
  .any(|key| labels.contains_key(key))
}

fn is_wharf_container(
  name: &str,
  labels: &BTreeMap<&str, &str>,
) -> bool {
  wharf_owned(labels)
    || matches!(
      name.trim_start_matches('/'),
      "wharf-core" | "wharf-agent"
    )
    || labels
      .get(PROJECT_LABEL)
      .is_some_and(|p| reserved_project(p))
}

fn reserved_project(project: &str) -> bool {
  matches!(
    project,
    "wharf-tailscale"
      | "wharf-backup"
      | "wharf-backup-core"
      | "wharf-link"
  ) || project.starts_with("wharf-gw-")
    || project.starts_with("wharf-link-")
    || project
      .starts_with(wharf_api_types::agent::TRIAL_PROJECT_PREFIX)
    || project.starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
}

/// 本机的全部容器，不含 agent 自己。
pub async fn discover(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Vec<FoundContainer>, ApiError> {
  Ok(
    inspect_many(docker, None, ctx)
      .await?
      .into_iter()
      .filter_map(|doc| {
        let name = doc["Name"].as_str()?.trim_start_matches('/');
        let labels = labels(&doc);
        if is_wharf_container(name, &labels) {
          return None;
        }
        let state =
          doc["State"]["Status"].as_str().unwrap_or_default();
        let ports = doc["NetworkSettings"]["Ports"]
          .as_object()
          .into_iter()
          .flatten()
          .flat_map(|(port, bindings)| {
            bindings.as_array().into_iter().flatten().filter_map(
              move |b| {
                Some(format!(
                  "{}:{}->{}",
                  b["HostIp"].as_str()?,
                  b["HostPort"].as_str()?,
                  port
                ))
              },
            )
          })
          .collect();
        let mounts = doc["Mounts"]
          .as_array()
          .into_iter()
          .flatten()
          .filter(|m| m["Type"] == "volume")
          .filter_map(|m| m["Name"].as_str())
          .collect::<Vec<_>>()
          .join(",");
        Some(FoundContainer {
          name: name.into(),
          image: doc["Config"]["Image"]
            .as_str()
            .unwrap_or_default()
            .into(),
          state: state.into(),
          status: state.into(),
          ports,
          project: labels.get(PROJECT_LABEL).map(|p| p.to_string()),
          volumes: named_volumes(&mounts),
        })
      })
      .collect(),
  )
}

async fn inspect_many(
  docker: &Docker,
  project: Option<&str>,
  ctx: &Ctx,
) -> Result<Vec<Json>, ApiError> {
  let mut cmd = docker.cmd().args(["ps", "-aq", "--no-trunc"]);
  if let Some(project) = project {
    cmd = cmd.args([
      "--filter",
      &format!("label={PROJECT_LABEL}={project}"),
    ]);
  }
  let out = cmd.timeout(QUICK).run(ctx).await?.check("docker ps")?;
  let ids: Vec<_> = out.stdout.split_whitespace().collect();
  if ids.is_empty() {
    return Ok(Vec::new());
  }
  let out = docker
    .cmd()
    .args(["container", "inspect", "--"])
    .args(ids.iter().copied())
    .timeout(QUICK)
    .run(ctx)
    .await?;
  // docker inspect still prints the surviving containers before returning 1.
  let missing_only = project.is_none()
    && out.code == Some(1)
    && !out.stderr.trim().is_empty()
    && out
      .stderr
      .lines()
      .map(str::trim)
      .filter(|line| !line.is_empty())
      .all(|line| {
        line
          .trim_start_matches("Error: ")
          .trim_start_matches("Error response from daemon: ")
          .strip_prefix("No such container: ")
          .is_some_and(|id| ids.contains(&id))
      });
  let out = if missing_only {
    out
  } else {
    out.check("docker container inspect")?
  };
  serde_json::from_str(&out.stdout).map_err(|_| {
    ApiError::new(ErrorCode::AgentFailed, "无法解析容器检查结果")
  })
}

pub async fn read(
  docker: &Docker,
  target: &ImportTarget,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  match (&target.project, &target.container) {
    (Some(project), None) => read_project(docker, project, ctx).await,
    (None, Some(name)) => read_container(docker, name, ctx).await,
    _ => Err(ApiError::invalid("compose 项目和容器二选一")),
  }
}

async fn inspect(
  docker: &Docker,
  what: &str,
  name: &str,
  ctx: &Ctx,
) -> Result<Option<serde_json::Value>, ApiError> {
  let out = docker
    .cmd()
    .args([what, "inspect", "--", name])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !out.success {
    return Ok(None);
  }
  let mut list: Vec<serde_json::Value> =
    serde_json::from_str(&out.stdout).map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("解析 inspect 失败：{e}"),
      )
    })?;
  Ok((!list.is_empty()).then(|| list.swap_remove(0)))
}

async fn read_container(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  check_container_name(name)?;
  let container = inspect(docker, "container", name, ctx)
    .await?
    .ok_or_else(|| ApiError::not_found(format!("没有容器 {name}")))?;
  let actual_name = container["Name"].as_str().unwrap_or(name);
  if is_wharf_container(actual_name, &labels(&container)) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      format!("容器 {name} 属于 Wharf 管理或系统组件，不能读取导入"),
    ));
  }
  let mut cache = BTreeMap::new();
  let raw = read_images(docker, container, &mut cache, ctx).await?;
  Ok(ImportRaw {
    inspect: Some(raw.inspect),
    image_inspect: raw.image_inspect,
    tag_image_id: raw.tag_image_id,
    ..Default::default()
  })
}

async fn read_images(
  docker: &Docker,
  container: Json,
  cache: &mut BTreeMap<String, Option<Json>>,
  ctx: &Ctx,
) -> Result<ProjectContainerRaw, ApiError> {
  let actual = container["Image"].as_str().unwrap_or_default();
  let declared =
    container["Config"]["Image"].as_str().unwrap_or_default();
  for image in [actual, declared] {
    if !image.is_empty() && !cache.contains_key(image) {
      cache.insert(
        image.into(),
        inspect(docker, "image", image, ctx).await?,
      );
    }
  }
  Ok(ProjectContainerRaw {
    image_inspect: cache.get(actual).cloned().flatten(),
    tag_image_id: cache
      .get(declared)
      .and_then(Option::as_ref)
      .and_then(|i| i["Id"].as_str())
      .map(str::to_string),
    inspect: container,
  })
}

const FILES_LABEL: &str = "com.docker.compose.project.config_files";
const ENV_LABEL: &str = "com.docker.compose.project.environment_file";
const DIR_LABEL: &str = "com.docker.compose.project.working_dir";

fn label_paths(
  labels: &BTreeMap<&str, &str>,
  label: &str,
) -> Vec<String> {
  labels
    .get(label)
    .into_iter()
    .flat_map(|s| s.split(','))
    .filter(|s| !s.is_empty())
    .map(str::to_string)
    .collect()
}

async fn read_project(
  docker: &Docker,
  project: &str,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  let forbidden = || {
    ApiError::new(
      ErrorCode::Forbidden,
      format!(
        "compose 项目 {project} 属于 Wharf 管理或系统组件，不能读取导入"
      ),
    )
  };
  if reserved_project(project) {
    return Err(forbidden());
  }
  let docs = inspect_many(docker, Some(project), ctx).await?;
  if docs.is_empty() {
    return Err(ApiError::not_found(format!(
      "没有 compose 项目 {project}"
    )));
  }
  if docs.iter().any(|d| {
    is_wharf_container(
      d["Name"].as_str().unwrap_or_default(),
      &labels(d),
    )
  }) {
    return Err(forbidden());
  }
  let first = docs
    .iter()
    .filter(|d| {
      labels(d).get(FILES_LABEL).is_some_and(|s| !s.is_empty())
    })
    .max_by_key(|d| d["State"]["Running"] == true)
    .map(labels)
    .unwrap_or_default();
  let dir = first.get(DIR_LABEL).copied().unwrap_or_default();
  let files = label_paths(&first, FILES_LABEL);
  let env_files = label_paths(&first, ENV_LABEL);
  if !Path::new(dir).is_absolute() || files.is_empty() {
    return Err(ApiError::invalid(format!(
      "compose 项目 {project} 没有记录 compose 文件的位置，按单个容器导入"
    )));
  }
  let mut warnings = Vec::new();
  if docs
    .iter()
    .any(|d| labels(d).get(FILES_LABEL) != first.get(FILES_LABEL))
  {
    warnings.push("原项目容器记录的 compose 文件不同，优先读取运行中容器记录的文件".into());
  }
  let mut args = vec![
    "compose".into(),
    "-p".into(),
    project.into(),
    "--project-directory".into(),
    dir.into(),
  ];
  for f in &files {
    args.extend(["-f".into(), f.clone()]);
  }
  for e in &env_files {
    args.extend(["--env-file".into(), e.clone()]);
  }
  args.push("config".into());
  let out = run_temp_compose_config(
    docker, dir, &files, &env_files, args, ctx,
  )
  .await?;
  if out
    .stderr
    .lines()
    .any(|l| l.contains("level=warning") || l.contains("WARN"))
  {
    warnings.push(
      "读取原 compose 配置时有警告，请核对原项目的变量与配置".into(),
    );
  }

  let mut cache = BTreeMap::new();
  let mut containers = Vec::with_capacity(docs.len());
  for doc in docs {
    containers.push(read_images(docker, doc, &mut cache, ctx).await?);
  }
  Ok(ImportRaw {
    compose: Some(out.stdout),
    containers,
    config_files: files,
    env_files,
    warnings,
    ..Default::default()
  })
}

fn collect_mount_args(
  dir: &str,
  files: &[String],
  env_files: &[String],
) -> Vec<String> {
  let root = Path::new(dir);
  let mut paths = BTreeSet::from([root.to_path_buf()]);
  for file in files.iter().chain(env_files) {
    let mut path = std::path::PathBuf::new();
    for part in root.join(file).components() {
      if part == std::path::Component::ParentDir {
        path.pop();
      } else {
        path.push(part);
      }
    }
    if !path.starts_with(root)
      && let Some(parent) =
        path.parent().filter(|p| *p != Path::new("/"))
    {
      paths.insert(parent.to_path_buf());
    } else if !path.starts_with(root) {
      paths.insert(path);
    }
  }
  paths
    .into_iter()
    .flat_map(|p| {
      let p = p.display();
      ["-v".into(), format!("{p}:{p}:ro")]
    })
    .collect()
}

async fn run_temp_compose_config(
  docker: &Docker,
  dir: &str,
  files: &[String],
  env_files: &[String],
  args: Vec<String>,
  ctx: &Ctx,
) -> Result<crate::exec::Output, ApiError> {
  static NEXT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
  let temp = format!(
    "wharf-temp-adopt-{}-{}-{}",
    chrono_suffix(),
    std::process::id(),
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
  );
  let wrapped = Path::new("/.dockerenv").exists();
  let cmd = if wrapped {
    let image = self_image(docker, ctx).await?;
    docker
      .cmd()
      .args([
        "run",
        "--rm",
        "--name",
        &temp,
        "--label",
        "wharf.temp=1",
        "--network",
        "none",
        "--env",
        "COMPOSE_PROFILES=",
        "-w",
        dir,
      ])
      .args(collect_mount_args(dir, files, env_files))
      .args(["--entrypoint", "docker", &image])
      .args(args)
  } else {
    docker
      .cmd()
      .cwd(Path::new(dir))
      .env("COMPOSE_PROFILES", "")
      .args(args)
  };
  let out = cmd.timeout(Duration::from_secs(120)).run(ctx).await;
  if wrapped && !out.as_ref().is_ok_and(|out| out.success) {
    let _ = docker
      .cmd()
      .args(["rm", "-f", &temp])
      .timeout(Duration::from_secs(10))
      .run(&Ctx::detached())
      .await;
  }
  let out = out?;
  if !out.success {
    let err =
      ApiError::new(ErrorCode::AgentFailed, "读取 compose 配置失败");
    if out.stderr.contains("no such file or directory")
      || out.stderr.contains("not found")
    {
      return Err(err.with_hint("compose 或 env 文件可能已移动或删除，补回文件后重试或改用 --container 单独导入"));
    }
    return Err(err);
  }
  Ok(out)
}

pub async fn verify_expected_images(
  docker: &Docker,
  expected: &BTreeMap<String, String>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  for (image, id) in expected {
    let out = docker
      .cmd()
      .args(["image", "inspect", "--format", "{{.Id}}", "--", image])
      .timeout(QUICK)
      .run(ctx)
      .await?;
    if !out.success || out.stdout.trim() != id {
      return Err(ApiError::new(ErrorCode::Conflict,
        format!("镜像 {image} 本机当前版本与原容器运行版本不一致，已中止接管"))
        .with_hint("重新运行导入预览以固定到原容器运行的版本"));
    }
  }
  Ok(())
}

/// agent 自己的镜像（里面有 docker 命令和 compose 插件）。
pub(crate) async fn self_image(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  if let Ok(image) = std::env::var("WHARF_SELF_IMAGE")
    && !image.is_empty()
  {
    return Ok(image);
  }
  let id = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| wharf_api_types::agent::container_id(&m))
    .ok_or_else(|| {
      ApiError::new(ErrorCode::AgentFailed, "找不到 agent 自己的容器")
    })?;
  let out = docker
    .cmd()
    .args(["inspect", "--format", "{{.Image}}", &id])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker inspect")?;
  Ok(out.stdout.trim().to_string())
}

/// 容器名只允许 docker 本身允许的字符，也防止被当成命令行参数。
fn check_container_name(name: &str) -> Result<(), ApiError> {
  let ok = name
    .chars()
    .next()
    .is_some_and(|c| c.is_ascii_alphanumeric())
    && name
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
  if ok {
    Ok(())
  } else {
    Err(ApiError::invalid(format!("容器名 {name} 不合法")))
  }
}

struct Info {
  id: String,
  name: String,
  project: String,
  service: String,
  restart: String,
  running: bool,
  owned: bool,
}

async fn info(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
) -> Result<Option<Info>, ApiError> {
  let out = docker
    .cmd()
    .args([
      "inspect",
      "--type",
      "container",
      "--format",
      "{{json .}}",
      "--",
      name,
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !out.success && out.stderr.contains("No such container:") {
    return Ok(None);
  }
  let out = out.check("docker inspect")?;
  let doc: serde_json::Value = serde_json::from_str(&out.stdout)
    .map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("无法读取容器 {name} 的检查结果：{e}"),
      )
    })?;
  let invalid = || {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("容器 {name} 的检查结果不完整"),
    )
  };
  let labels = match doc.pointer("/Config/Labels") {
    Some(serde_json::Value::Null) => BTreeMap::new(),
    Some(serde_json::Value::Object(map)) => map
      .iter()
      .map(|(k, v)| Ok((k.as_str(), v.as_str().ok_or_else(invalid)?)))
      .collect::<Result<_, ApiError>>()?,
    _ => return Err(invalid()),
  };
  let name = doc["Name"]
    .as_str()
    .ok_or_else(invalid)?
    .trim_start_matches('/');
  let policy = &doc["HostConfig"]["RestartPolicy"];
  let restart = policy["Name"].as_str().ok_or_else(invalid)?;
  let retries =
    policy["MaximumRetryCount"].as_u64().unwrap_or_default();
  Ok(Some(Info {
    id: doc["Id"].as_str().ok_or_else(invalid)?.into(),
    name: name.into(),
    project: labels
      .get(PROJECT_LABEL)
      .copied()
      .unwrap_or_default()
      .into(),
    service: labels
      .get("com.docker.compose.service")
      .copied()
      .unwrap_or_default()
      .into(),
    restart: if restart == "on-failure" && retries > 0 {
      format!("{restart}:{retries}")
    } else {
      restart.into()
    },
    running: doc
      .pointer("/State/Running")
      .and_then(serde_json::Value::as_bool)
      .ok_or_else(invalid)?,
    owned: is_wharf_container(name, &labels),
  }))
}

async fn docker_do(
  docker: &Docker,
  args: &[&str],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  docker
    .cmd()
    .args(args.iter().copied())
    .timeout(Duration::from_secs(90))
    .run(ctx)
    .await?
    .check(&format!("docker {}", args[0]))?;
  Ok(())
}

/// 停掉原来的容器，关掉自动重启。单个容器还要改名，让出名字给新容器，留着回退用。
pub async fn retire(
  docker: &Docker,
  r: &Retire,
  ctx: &Ctx,
) -> Result<Vec<Retired>, ApiError> {
  let mut targets: Vec<(Info, bool)> = Vec::new();
  if let Some(project) = &r.project {
    let docs = inspect_many(docker, Some(project), ctx).await?;
    for doc in &docs {
      let name = doc["Name"].as_str().unwrap_or_default();
      let labels = labels(doc);
      if is_wharf_container(name, &labels) {
        return Err(ApiError::invalid(format!(
          "容器 {name} 属于 Wharf 管理，不能接管"
        )));
      }
      let service = labels
        .get("com.docker.compose.service")
        .copied()
        .unwrap_or_default();
      if !r.expected_services.is_empty()
        && doc["State"]["Running"] == true
        && !r.expected_services.iter().any(|s| s == service)
      {
        return Err(missing_service(service));
      }
    }
    if project != &r.service {
      for doc in &docs {
        if let Some(id) = doc["Id"].as_str()
          && let Some(i) = info(docker, id, ctx).await?
        {
          if !r.expected_services.is_empty()
            && i.running
            && !r.expected_services.contains(&i.service)
          {
            return Err(missing_service(&i.service));
          }
          let rename = r.rename_containers.contains(&i.name);
          targets.push((i, rename));
        }
      }
    }
  }
  for name in &r.containers {
    check_container_name(name)?;
    match info(docker, name, ctx).await? {
      // 已经是新服务的容器：之前接管过了。
      Some(i) if i.owned || i.project != r.service => {
        if let Some((_, rename)) =
          targets.iter_mut().find(|(target, _)| target.id == i.id)
        {
          *rename = true;
        } else {
          targets.push((i, true));
        }
      }
      _ => {}
    }
  }
  if let Some((i, _)) = targets.iter().find(|(i, _)| i.owned) {
    return Err(ApiError::invalid(format!(
      "容器 {} 属于 Wharf 管理，不能接管",
      i.name
    )));
  }
  let mut touched = Vec::new();
  for (i, rename) in targets {
    if let Err(mut err) =
      retire_one(docker, i, rename, &mut touched, ctx).await
    {
      let recover = ctx.detached_with_progress();
      recover.say("停掉旧容器失败，正在恢复已改动的容器");
      match unretire(docker, &touched, &recover).await {
        Ok(()) => recover.say("已恢复原来的容器"),
        Err(back) => {
          recover
            .say(format!("恢复失败，需要手动处理：{}", back.message));
          err.message.push_str(&format!(
            "；恢复失败，需要手动处理：{}",
            back.message
          ));
        }
      }
      return Err(err);
    }
  }
  Ok(touched)
}

fn missing_service(service: &str) -> ApiError {
  ApiError::new(ErrorCode::Conflict,
    format!("正在运行的组件 {service} 不在默认配置中（--profile），已中止接管"))
    .with_hint("检查 profile 组件后重新导入")
}

async fn retire_one(
  docker: &Docker,
  i: Info,
  rename: bool,
  touched: &mut Vec<Retired>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let renamed = if rename {
    let mut to = format!("{}-wharf-old", i.name);
    if info(docker, &to, ctx).await?.is_some() {
      to = format!("{to}-{}", chrono_suffix());
    }
    Some(to)
  } else {
    None
  };
  // 请求取消时 Docker 可能已执行命令，先记录恢复所需的信息。
  touched.push(Retired {
    id: i.id,
    name: i.name,
    renamed: None,
    restart: String::new(),
    was_running: false,
  });
  let item = touched.last_mut().expect("刚加入恢复记录");
  item.renamed = renamed;
  if let Some(to) = &item.renamed {
    ctx.say(format!("原来的容器 {} 改名为 {to}", item.name));
    docker_do(docker, &["rename", &item.id, to], ctx).await?;
  }
  item.restart = if i.restart.is_empty() {
    "no".into()
  } else {
    i.restart
  };
  docker_do(docker, &["update", "--restart=no", &item.id], ctx)
    .await?;
  if i.running {
    item.was_running = true;
    ctx.say(format!("停止原来的容器 {}", item.name));
    docker_do(docker, &["stop", &item.id], ctx).await?;
  }
  Ok(())
}

fn chrono_suffix() -> String {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs().to_string())
    .unwrap_or_default()
}

/// 把 [retire] 停掉的容器恢复原样。
pub async fn unretire(
  docker: &Docker,
  items: &[Retired],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let mut errors = Vec::new();
  for item in items.iter().rev() {
    if item.renamed.is_some() {
      let result = async {
        check_container_name(&item.name)?;
        if info(docker, &item.id, ctx)
          .await?
          .is_some_and(|i| i.name != item.name)
        {
          docker_do(docker, &["rename", &item.id, &item.name], ctx)
            .await?;
        }
        Ok::<_, ApiError>(())
      }
      .await;
      if let Err(e) = result {
        errors.push(format!("{} 恢复原名：{}", item.name, e.message));
      }
    }
    if !item.restart.is_empty() {
      let policy = format!("--restart={}", item.restart);
      if let Err(e) =
        docker_do(docker, &["update", &policy, &item.id], ctx).await
      {
        errors
          .push(format!("{} 恢复重启策略：{}", item.name, e.message));
      }
    }
    if item.was_running {
      ctx.say(format!("启动原来的容器 {}", item.name));
      if let Err(e) =
        docker_do(docker, &["start", &item.id], ctx).await
      {
        errors.push(format!("{} 恢复运行：{}", item.name, e.message));
      }
    }
  }
  if errors.is_empty() {
    Ok(())
  } else {
    Err(ApiError::new(ErrorCode::AgentFailed, errors.join("；")))
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn finds_container_id_in_mountinfo() {
    use wharf_api_types::agent::container_id;
    let id = "a".repeat(64);
    let m = format!(
      "1 2 0:1 / / rw - overlay overlay rw\n3 1 8:1 /var/lib/docker/containers/{id}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
    );
    assert_eq!(container_id(&m), Some(id));
    assert_eq!(container_id("1 2 0:1 / / rw\n"), None);
  }
}

#[cfg(test)]
mod observation_tests {
  use super::*;

  #[test]
  fn skips_labelled_temporary_containers() {
    assert!(is_wharf_container(
      "tailscale",
      &BTreeMap::from([("wharf.network", "tailscale")])
    ));
    assert!(is_wharf_container("/wharf-core", &BTreeMap::new()));
    assert!(wharf_owned(&BTreeMap::from([
      ("foo", "bar"),
      ("wharf.temp", "1")
    ])));
    assert!(wharf_owned(&BTreeMap::from([(
      "com.wharf.host-shell",
      "1"
    )])));
    assert!(!wharf_owned(&BTreeMap::from([(
      PROJECT_LABEL,
      "wharf-test"
    )])));
  }
}

#[cfg(test)]
#[test]
fn adopt_rejects_wharf_owned_container_and_project() {
  for (name, raw, owned) in [
    ("wharf-core", "", true),
    ("system", "wharf.system=agent", true),
    ("gateway", "com.docker.compose.project=wharf-gw-edge", true),
    ("app", "com.docker.compose.project=custom", false),
  ] {
    assert_eq!(
      is_wharf_container(
        name,
        &raw.split(',').filter_map(|s| s.split_once('=')).collect()
      ),
      owned,
      "{name}"
    );
  }
}

#[cfg(test)]
mod adoption_tests {
  use super::*;
  use crate::docker::fake_docker;

  #[test]
  fn structured_labels_and_external_env_mounts() {
    let doc = serde_json::json!({"Config": {"Labels": {
      FILES_LABEL: "/app/a.yml,/opt/b.yml", ENV_LABEL: "/etc/app/job.env,/root.env",
      "custom": "hello,wharf.temp=1"
    }}});
    let labels = labels(&doc);
    assert!(!wharf_owned(&labels));
    let files = label_paths(&labels, FILES_LABEL);
    let env = label_paths(&labels, ENV_LABEL);
    assert_eq!(files, ["/app/a.yml", "/opt/b.yml"]);
    assert_eq!(
      collect_mount_args("/app", &files, &env),
      [
        "-v",
        "/app:/app:ro",
        "-v",
        "/etc/app:/etc/app:ro",
        "-v",
        "/opt:/opt:ro",
        "-v",
        "/root.env:/root.env:ro"
      ]
    );
  }

  #[tokio::test]
  async fn discover_keeps_containers_when_one_disappears() {
    let (_dir, docker) = fake_docker(
      r#"
case "$*" in
  'ps -aq --no-trunc') printf 'kept\ngone\n';;
  'container inspect -- kept gone')
    echo '[{"Id":"kept","Name":"/web","State":{"Status":"running"}}]'
    echo 'Error response from daemon: No such container: gone' >&2
    exit 1;;
  *) exit 2;;
esac
"#,
    );
    let found = discover(&docker, &Ctx::detached()).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "web");
  }

  #[tokio::test]
  async fn image_drift_conflicts_before_retire() {
    let (dir, docker) =
      fake_docker("echo \"$*\" >> log; echo sha256:new");
    let expected =
      BTreeMap::from([("img:1".into(), "sha256:old".into())]);
    let e =
      verify_expected_images(&docker, &expected, &Ctx::detached())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert_eq!(
      std::fs::read_to_string(dir.path().join("log"))
        .unwrap()
        .lines()
        .count(),
      1
    );
  }

  #[tokio::test]
  async fn retire_failure_recovers_all_targets_in_reverse() {
    let (dir, docker) = fake_docker(
      r#"
echo "$*" >> log
case "$1:$7" in
  inspect:*wharf-old) echo 'No such container:' >&2; exit 1;;
  inspect:*)
    name="$7"
    [ "$name" = c2 ] && [ -f renamed ] && name=c2-wharf-old
    printf '{"Id":"%s","Name":"/%s","Config":{"Labels":null},"HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":5}},"State":{"Running":true}}\n' "$7" "$name";;
  rename:*) touch renamed;;
  stop:*) [ "$2" != c2 ];;
  update:*) [ "$2 $3" != "--restart=on-failure:5 c2" ];;
esac
"#,
    );
    let request = Retire {
      service: "s1".into(),
      project: None,
      containers: vec!["c1".into(), "c1".into(), "c2".into()],
      rename_containers: vec![],
      expected_services: vec![],
    };
    let e = retire(&docker, &request, &Ctx::detached())
      .await
      .unwrap_err();
    let log =
      std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(e.message.contains("恢复失败"));
    assert_eq!(log.lines().filter(|l| *l == "stop c1").count(), 1);
    assert!(log.contains(
      "rename c2 c2\nupdate --restart=on-failure:5 c2\nstart c2"
    ));
    assert!(
      log.find("start c2").unwrap() < log.find("start c1").unwrap()
    );
  }

  #[tokio::test]
  async fn docker_up_creates_without_starting() {
    let (dir, docker) = fake_docker("echo \"$*\" >> log");
    docker.write_compose("s1", "services: {}").unwrap();
    docker.up("s1", true, &Ctx::detached()).await.unwrap();
    let log =
      std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(
      log.ends_with(" up --no-start --remove-orphans --pull never\n")
    );
  }
}
