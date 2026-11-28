use std::time::Duration;

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode, adopt_data::validate_host_bind,
  spec::VolumeSpec,
};

use crate::{docker::Docker, exec::Ctx};

const TIMEOUT: Duration = Duration::from_secs(25);

const CHECK: &str = r#"
set -eu
path=$1
current=/host
rest=$path
while [ -n "$rest" ]; do
  parent=$(stat -c '%u:%a' "$current")
  uid=${parent%%:*}
  mode=${parent#*:}
  [ "$uid" = 0 ] && [ $((0$mode & 022)) -eq 0 ] || exit 41
  rest=${rest#/}
  component=${rest%%/*}
  current="$current/$component"
  [ ! -L "$current" ] && [ -d "$current" ] || exit 42
  [ "$rest" != "$component" ] || break
  rest="/${rest#*/}"
done
# Docker's recursive bind exposes the same source tree as a workload bind.
awk -v path="/host$path" "$2" /proc/self/mountinfo
"#;

const CHECK_MOUNTS: &str = r#"
  $5 == "/host" { host_dev=$3; host_root=$4; next }
  $5 == "/source" { source_dev=$3; source_root=$4; next }
  index($5, "/source/") == 1 { bad=1 }
  $5 == path || index($5, path "/") == 1 { bad=1 }
  index($5, "/host/") == 1 && index(path, $5 "/") == 1 {
    if ($4 == "/" && ($5 == "/host/mnt" || $5 == "/host/media" || $5 == "/host/opt")) {
      data_dev=$3; data_mount=$5
    } else { bad=1 }
  }
  END {
    if (data_mount != "") {
      if (data_dev == host_dev) bad=1
      dev=data_dev; root=substr(path, length(data_mount)+1)
    } else {
      dev=host_dev; root=(host_root == "/" ? "" : host_root) substr(path, length("/host")+1)
    }
    exit (bad || host_dev == "" || source_dev != dev || source_root != root)
  }
"#;

fn error(path: &str) -> ApiError {
  ApiError::new(ErrorCode::Forbidden, format!("外部挂载 {path} 不允许"))
    .with_hint("选择批准数据根下已有且无符号链接或嵌套挂载的目录；上级目录须由管理员控制")
}

pub(super) async fn validate_sources(
  docker: &Docker,
  binds: &[VolumeSpec],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  if binds.is_empty() {
    return Ok(());
  }
  let image = crate::adopt::self_image(docker, ctx).await?;
  for bind in binds {
    let source = bind
      .host_path
      .as_deref()
      .ok_or_else(|| ApiError::invalid("外部卷缺少路径"))?;
    validate_host_bind(source, &bind.target)?;
    let name =
      format!("wharf-bind-check-{}", crate::build::random_suffix());
    let mount =
      format!("type=bind,src={source},dst=/source,readonly");
    let result = docker
      .cmd()
      .args([
        "run",
        "--rm",
        "--name",
        &name,
        "--label",
        "wharf.temp=1",
        "--network",
        "none",
        "--pull",
        "never",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--mount",
        "type=bind,src=/,dst=/host,readonly",
        "--mount",
        &mount,
        "--entrypoint",
        "/bin/sh",
      ])
      .arg(&image)
      .args(["-c", CHECK, "wharf-bind-check", source, CHECK_MOUNTS])
      .timeout(TIMEOUT)
      .run(ctx)
      .await;
    if !result.as_ref().is_ok_and(|out| out.success) {
      let _ = docker
        .cmd()
        .args(["rm", "-f", &name])
        .timeout(TIMEOUT)
        .run(&Ctx::detached())
        .await;
    }
    if !result?.success {
      return Err(error(source));
    }
  }
  Ok(())
}

pub(super) async fn verify_mounted(
  docker: &Docker,
  project: &str,
  binds: &[VolumeSpec],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let listed = docker
    .compose(project)
    .args(["ps", "--all", "--quiet"])
    .timeout(TIMEOUT)
    .run(ctx)
    .await?
    .check("检查外部挂载容器")?;
  let ids: Vec<_> = listed.stdout.split_whitespace().collect();
  if ids.is_empty() {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "外部挂载部署没有创建容器",
    ));
  }
  let inspected = docker
    .cmd()
    .arg("inspect")
    .args(ids)
    .timeout(TIMEOUT)
    .run(ctx)
    .await?
    .check("检查实际外部挂载")?;
  let containers: Vec<Value> =
    serde_json::from_str(&inspected.stdout)
      .map_err(|_| ApiError::internal("无法读取实际外部挂载"))?;
  for bind in binds {
    let source = bind.host_path.as_deref().unwrap_or_default();
    if containers.is_empty()
      || !containers.iter().all(|value| {
        value["Mounts"].as_array().is_some_and(|mounts| {
          mounts.iter().any(|mount| {
            mount["Type"].as_str() == Some("bind")
              && mount["Source"].as_str() == Some(source)
              && mount["Destination"].as_str()
                == Some(bind.target.as_str())
              && mount["RW"].as_bool() == Some(!bind.read_only)
              && mount["Propagation"].as_str() == Some("rprivate")
          })
        })
      })
    {
      return Err(error(source));
    }
  }
  Ok(())
}

#[test]
fn docker_bind_mount_table_rejects_overlaid_sources() {
  use std::{
    io::Write,
    process::{Command, Stdio},
  };

  let check = |data_dev: &str, source_root: &str, extra: &str| {
    let mut child = Command::new("awk")
      .args(["-v", "path=/host/mnt/data", CHECK_MOUNTS])
      .stdin(Stdio::piped())
      .spawn()
      .unwrap();
    write!(child.stdin.take().unwrap(),
      "15 14 8:1 / /host ro - ext4 /dev/root rw\n16 15 {data_dev} / /host/mnt ro - ext4 /dev/data rw\n18 14 {data_dev} {source_root} /source ro - ext4 /dev/data rw\n{extra}"
    ).unwrap();
    child.wait().unwrap().success()
  };
  assert!(check(
    "8:2",
    "/data",
    "17 16 8:2 /other /host/mnt/database ro - ext4 /dev/data rw\n"
  ));
  assert!(!check(
    "8:2",
    "/data",
    "17 16 8:1 /restricted /host/mnt/data ro - ext4 /dev/root rw\n"
  ));
  assert!(!check(
    "8:2",
    "/data",
    "17 16 8:1 /restricted /host/mnt/data/child ro - ext4 /dev/root rw\n"
  ));
  assert!(!check("8:1", "/data", ""));
  assert!(!check("8:2", "/other", ""));
}
