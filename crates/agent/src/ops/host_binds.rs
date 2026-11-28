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
awk -v path="$path" '
  $5 == path || index($5, path "/") == 1 { bad=1 }
  $5 != "/" && index(path, $5 "/") == 1 &&
    !($4 == "/" && ($5 == "/mnt" || $5 == "/media" || $5 == "/opt")) { bad=1 }
  END { exit bad }
' /host-mountinfo
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
    let result = docker.cmd().args([
      "run", "--rm", "--name", &name, "--label", "wharf.temp=1", "--network", "none",
      "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--mount", "type=bind,src=/,dst=/host,readonly",
      "--mount", "type=bind,src=/proc/1/mountinfo,dst=/host-mountinfo,readonly",
      "--entrypoint", "/bin/sh",
    ]).arg(&image).args(["-c", CHECK, "wharf-bind-check", source])
      .timeout(TIMEOUT).run(ctx).await;
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
