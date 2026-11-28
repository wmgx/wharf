use std::{
  collections::BTreeMap,
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{RepairLease, ServiceRepairOp},
  validate_name,
  view::HostExecResponse,
};

use crate::{
  docker::{Docker, write_private},
  exec::Ctx,
};

const QUICK: Duration = Duration::from_secs(30);

fn root(docker: &Docker) -> PathBuf {
  docker.data_dir.join("repairs")
}

fn container(lease: &RepairLease) -> String {
  format!("wharf-repair-{}", lease.id)
}

fn lease_file(docker: &Docker, lease: &RepairLease) -> PathBuf {
  root(docker).join(format!("{}.json", lease.id))
}

fn refuse(reason: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("无法进入修复模式：{reason}"),
  )
}

async fn find(
  docker: &Docker,
  lease: &RepairLease,
  ctx: &Ctx,
) -> Result<Option<String>, ApiError> {
  let result = docker
    .cmd()
    .args([
      "ps",
      "-a",
      "--no-trunc",
      "--format",
      "{{.ID}}",
      "--filter",
    ])
    .arg(format!("label=wharf.repair.lease={}", lease.id))
    .arg("--filter")
    .arg(format!("label=wharf.repair.instance={}", lease.instance))
    .arg("--filter")
    .arg(format!("label=wharf.repair.service={}", lease.service))
    .arg("--filter")
    .arg(format!("name=^/{}$", container(lease)))
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("核实修复容器")?;
  let ids: Vec<_> = result
    .stdout
    .lines()
    .filter(|s| !s.trim().is_empty())
    .collect();
  match ids.as_slice() {
    [] => Ok(None),
    [id]
      if id.len() == 64
        && id.bytes().all(|b| b.is_ascii_hexdigit()) =>
    {
      Ok(Some((*id).into()))
    }
    _ => Err(refuse("修复容器归属不明")),
  }
}

async fn end(
  docker: &Docker,
  lease: &RepairLease,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  if let Some(id) = find(docker, lease, ctx).await? {
    let result = docker
      .cmd()
      .args(["rm", "--force", "--", &id])
      .timeout(QUICK)
      .run(ctx)
      .await?;
    if !result.success && find(docker, lease, ctx).await?.is_some() {
      return Err(refuse("修复容器尚未删除"));
    }
  }
  let file = lease_file(docker, lease);
  let _ = std::fs::remove_file(file.with_extension("env"));
  match std::fs::remove_file(file) {
    Ok(()) => {}
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
    Err(_) => return Err(ApiError::internal("清理修复租约失败")),
  }
  Ok(json!(true))
}

pub(crate) async fn sweep(docker: Docker) {
  loop {
    if let Ok(entries) = std::fs::read_dir(root(&docker)) {
      for entry in entries.flatten() {
        if entry.path().extension().and_then(|ext| ext.to_str())
          != Some("json")
        {
          continue;
        }
        let Some(lease) =
          std::fs::read(entry.path()).ok().and_then(|bytes| {
            serde_json::from_slice::<RepairLease>(&bytes).ok()
          })
        else {
          continue;
        };
        if validate_name("修复租约", &lease.id).is_ok()
          && lease_file(&docker, &lease) == entry.path()
          && lease.expires_ms <= chrono::Utc::now().timestamp_millis()
        {
          let _ = end(&docker, &lease, &Ctx::detached()).await;
        }
      }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
}

fn check_mounts(
  docker: &Docker,
  lease: &RepairLease,
  info: &Value,
) -> Result<Vec<String>, ApiError> {
  let data = Path::new("/srv").join(&lease.service);
  let project = docker.project_dir(&lease.service);
  let mut binds = Vec::new();
  let mounts = info["Mounts"]
    .as_array()
    .ok_or_else(|| refuse("无法核实挂载"))?;
  for mount in mounts {
    let source = mount["Source"]
      .as_str()
      .ok_or_else(|| refuse("无法核实挂载来源"))?;
    let target = mount["Destination"]
      .as_str()
      .ok_or_else(|| refuse("无法核实挂载目标"))?;
    let rw = mount["RW"]
      .as_bool()
      .ok_or_else(|| refuse("无法核实挂载权限"))?;
    let path = Path::new(source);
    if mount["Type"] != "bind"
      || !target.starts_with('/')
      || [source, target]
        .iter()
        .any(|v| v.contains([',', ':', '\n', '\0']))
      || (!path.starts_with(&data)
        && (rw || !path.starts_with(&project)))
      || !path.components().all(|part| {
        matches!(
          part,
          std::path::Component::RootDir
            | std::path::Component::Normal(_)
        )
      })
    {
      return Err(refuse("存在共享卷、外部或无法核实的挂载"));
    }
    if std::fs::canonicalize(path).ok().as_deref() != Some(path) {
      return Err(refuse("挂载来源经过了符号链接或不存在"));
    }
    binds.push(format!(
      "type=bind,src={source},dst={target}{}",
      if rw { "" } else { ",readonly" }
    ));
  }
  Ok(binds)
}

async fn start(
  docker: &Docker,
  lease: &RepairLease,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let state = docker.one_status(&lease.service, ctx).await?;
  let [source] = state.containers.as_slice() else {
    return Err(refuse("只支持单业务组件"));
  };
  if state.hash.as_deref() != Some(lease.hash.as_str())
    || source.foreign
    || source.is_active()
    || source.working_dir.as_deref().is_none_or(|dir| {
      Path::new(dir) != docker.project_dir(&lease.service)
    })
  {
    return Err(refuse("普通项目未确认停止或归属不明"));
  }
  if find(docker, lease, ctx).await?.is_some() {
    return Ok(json!(true));
  }
  let id = source
    .container_id
    .as_deref()
    .filter(|id| {
      id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
    })
    .ok_or_else(|| refuse("容器身份无法核实"))?;
  let output = docker
    .cmd()
    .args([
      "inspect",
      "--type",
      "container",
      "--format",
      "{{json .}}",
      "--",
      id,
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  let info: Value = serde_json::from_str(output.stdout.trim())
    .map_err(|_| refuse("无法检查已应用配置"))?;
  let host = &info["HostConfig"];
  if !output.success
    || info["Id"] != id
    || host["Privileged"] != false
    || ["Devices", "DeviceRequests", "CapAdd", "VolumesFrom"]
      .iter()
      .any(|key| {
        host[*key].as_array().is_some_and(|items| !items.is_empty())
      })
    || [
      "NetworkMode",
      "PidMode",
      "IpcMode",
      "UTSMode",
      "CgroupnsMode",
      "UsernsMode",
    ]
    .iter()
    .any(|key| {
      host[*key]
        .as_str()
        .is_some_and(|s| s == "host" || s.starts_with("container:"))
    })
  {
    return Err(refuse("存在特权、设备或宿主机命名空间"));
  }
  let image = info["Image"]
    .as_str()
    .filter(|id| {
      id.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
      })
    })
    .ok_or_else(|| refuse("已应用镜像 ID 不明"))?;
  let mounts = check_mounts(docker, lease, &info)?;
  let mut env = String::new();
  for entry in info["Config"]["Env"].as_array().into_iter().flatten()
  {
    let entry =
      entry.as_str().ok_or_else(|| refuse("环境变量格式不支持"))?;
    let (key, _) = entry
      .split_once('=')
      .ok_or_else(|| refuse("环境变量格式不支持"))?;
    if entry.contains(['\n', '\r', '\0'])
      || key.is_empty()
      || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
      return Err(refuse("环境变量格式不支持"));
    }
    if key != "WHARF_HEARTBEAT_URL" {
      env.push_str(entry);
      env.push('\n');
    }
  }
  std::fs::create_dir_all(root(docker))
    .map_err(|_| ApiError::internal("无法创建修复租约目录"))?;
  let lease_path = lease_file(docker, lease);
  write_private(
    &lease_path,
    &serde_json::to_string(lease)
      .map_err(|_| ApiError::internal("无法保存修复租约"))?,
  )?;
  let env_path = lease_path.with_extension("env");
  write_private(&env_path, &env)?;
  let name = container(lease);
  let mut cmd = docker
    .cmd()
    .args([
      "run",
      "--detach",
      "--pull=never",
      "--network=none",
      "--restart=no",
      "--no-healthcheck",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--entrypoint=/bin/sh",
      "--name",
      &name,
    ])
    .arg("--label")
    .arg(format!("wharf.repair.lease={}", lease.id))
    .arg("--label")
    .arg(format!("wharf.repair.instance={}", lease.instance))
    .arg("--label")
    .arg(format!("wharf.repair.service={}", lease.service))
    .arg("--env-file")
    .arg(env_path.to_string_lossy());
  for mount in mounts {
    cmd = cmd.arg("--mount").arg(mount);
  }
  let output = cmd
    .args([image, "-c", "while :; do sleep 60; done"])
    .timeout(QUICK)
    .run(ctx)
    .await;
  let _ = std::fs::remove_file(&env_path);
  let output = output?;
  if !output.success {
    let _ = end(docker, lease, &Ctx::detached()).await;
    if output.stderr.contains("/bin/sh") {
      return Err(
        ApiError::invalid("镜像没有可用 shell")
          .with_hint("改用离线备份或选择带 shell 的镜像后重试"),
      );
    }
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "创建修复容器失败",
    ));
  }
  Ok(json!(true))
}

pub(crate) async fn run(
  docker: &Docker,
  job: ServiceRepairOp,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let lease = match &job {
    ServiceRepairOp::Start { lease }
    | ServiceRepairOp::Exec { lease, .. }
    | ServiceRepairOp::End { lease } => lease,
  };
  validate_name("服务", &lease.service)?;
  validate_name("租约", &lease.id)?;
  if lease.instance.is_empty()
    || lease.instance.contains(['\n', '\0'])
  {
    return Err(refuse("实例无效"));
  }
  let now = chrono::Utc::now().timestamp_millis();
  if !matches!(&job, ServiceRepairOp::End { .. })
    && (lease.expires_ms <= now
      || lease.expires_ms > now + 31 * 60_000)
  {
    return Err(refuse("租约已过期或不合法"));
  }
  match &job {
    ServiceRepairOp::Start { .. } => start(docker, lease, ctx).await,
    ServiceRepairOp::End { .. } => end(docker, lease, ctx).await,
    ServiceRepairOp::Exec {
      command,
      timeout_secs,
      ..
    } => {
      let id = find(docker, lease, ctx)
        .await?
        .ok_or_else(|| refuse("修复容器不存在"))?;
      if command.is_empty()
        || command.len() > 64 * 1024
        || command.contains('\0')
        || !(1..=600).contains(timeout_secs)
      {
        return Err(ApiError::invalid("修复命令或超时不合法"));
      }
      let timeout = Duration::from_secs(*timeout_secs)
        .min(Duration::from_millis((lease.expires_ms - now) as u64));
      let started = Instant::now();
      let (output, expired) = crate::service_exec::run_task(
        docker,
        &id,
        command,
        &BTreeMap::new(),
        timeout,
        ctx,
      )
      .await?;
      if expired {
        return Err(ApiError::new(
          ErrorCode::Timeout,
          "修复命令超时",
        ));
      }
      Ok(json!(HostExecResponse {
        exit_code: output.code.unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        truncated: false,
        duration_ms: started.elapsed().as_millis() as u64,
      }))
    }
  }
}

#[test]
fn repair_mounts_keep_only_owned_data_and_project_files() {
  let temp = tempfile::tempdir().unwrap();
  let docker = Docker {
    bin: "docker".into(),
    data_dir: temp.path().into(),
  };
  let path = docker.project_dir("app").join("config");
  std::fs::create_dir_all(&path).unwrap();
  let at = std::fs::canonicalize(&path).unwrap();
  let mut docker = docker;
  docker.data_dir = std::fs::canonicalize(temp.path()).unwrap();
  let lease = RepairLease {
    service: "app".into(),
    instance: "svc_fixture".into(),
    id: "sample".into(),
    hash: "hash".into(),
    expires_ms: 0,
  };
  let mounts = |rw| {
    json!({"Mounts":[
      {"Source":at,"Destination":"/etc/app","RW":rw,"Type":"bind"}
    ]})
  };
  assert_eq!(
    check_mounts(&docker, &lease, &mounts(false)).unwrap().len(),
    1
  );
  assert!(check_mounts(&docker, &lease, &mounts(true)).is_err());
}
