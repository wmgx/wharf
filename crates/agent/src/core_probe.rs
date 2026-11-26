//! 从控制面宿主机的数据目录读取同机挑战，回显只走加密会话。

use std::{
  fs::File,
  io::Read,
  path::{Component, Path},
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{CoreHostProbe, CoreHostProbeResult},
};

use crate::{
  dirfd::{DirFd, NOFOLLOW, component},
  docker::Docker,
  exec::Ctx,
};

fn hex_name(s: &str, min: usize) -> bool {
  (min..=64).contains(&s.len())
    && s
      .bytes()
      .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_path(s: &str) -> bool {
  let path = Path::new(s);
  path.is_absolute()
    && path
      .components()
      .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    && !s.contains(['\0', '\n', '\r', ',', '"'])
}

fn not_found() -> ApiError {
  ApiError::not_found("控制面不在这台机器上")
}

pub(crate) async fn run(
  docker: &Docker,
  probe: &CoreHostProbe,
  ctx: &Ctx,
) -> Result<CoreHostProbeResult, ApiError> {
  if !hex_name(&probe.challenge_id, 32) || !safe_path(&probe.data_dir)
  {
    return Err(ApiError::invalid(
      "控制面同机挑战的标识或数据目录不合法",
    ));
  }
  let host = if let Some(cid) = &probe.container_id {
    if !hex_name(cid, 64) {
      return Err(ApiError::invalid("控制面容器 ID 不合法"));
    }
    let out = docker
      .cmd()
      .args(["container", "inspect", cid])
      .timeout(crate::upgrade::QUICK)
      .run(ctx)
      .await?;
    if !out.success && out.stderr.contains("No such container:") {
      return Err(not_found());
    }
    let out = out.check("docker container inspect")?;
    let containers: Vec<serde_json::Value> =
      serde_json::from_str(&out.stdout)
        .map_err(|_| ApiError::internal("无法解析控制面容器信息"))?;
    let inspection = containers.first().ok_or_else(not_found)?;
    let source = inspection["Mounts"]
      .as_array()
      .and_then(|mounts| {
        mounts.iter().find(|m| {
          m["Type"] == "bind"
            && m["Destination"].as_str() == Some(&probe.data_dir)
        })
      })
      .and_then(|m| m["Source"].as_str())
      .ok_or_else(|| {
        ApiError::not_found("未找到控制面数据目录的绑定挂载")
      })?;
    source.to_owned()
  } else {
    probe.data_dir.clone()
  };
  if !safe_path(&host) {
    return Err(ApiError::invalid("控制面宿主机数据目录不合法"));
  }
  let in_container = Path::new("/.dockerenv").exists()
    || crate::upgrade::self_container().is_ok();
  let image = if in_container {
    Some(crate::adopt::self_image(docker, ctx).await?)
  } else {
    None
  };
  read_host(docker, &host, &probe.challenge_id, image.as_deref(), ctx)
    .await
}

async fn read_host(
  docker: &Docker,
  host: &str,
  challenge: &str,
  image: Option<&str>,
  ctx: &Ctx,
) -> Result<CoreHostProbeResult, ApiError> {
  // 容器内的同名路径可能属于自己的文件系统，必须从宿主机只读挂载读取。
  let Some(image) = image else {
    let raw = read_local(host, challenge).map_err(|e| {
      if e.kind() == std::io::ErrorKind::NotFound {
        not_found()
      } else {
        ApiError::new(
          ErrorCode::AgentFailed,
          "无法读取控制面挑战文件",
        )
      }
    })?;
    return result(raw);
  };
  let name =
    format!("wharf-core-probe-{}", crate::build::random_suffix());
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--label",
      "wharf.temp=1",
      "--log-driver",
      "none",
      "--network",
      "none",
      "--name",
      &name,
      "--entrypoint",
      "sh",
      "--mount",
      &format!("type=bind,src={host},dst=/probe,readonly"),
      image,
      "-c",
      r#"set -e
[ -d /probe/.core-probe ] && [ ! -L /probe/.core-probe ] || exit 73
f="/probe/.core-probe/$1"
[ -f "$f" ] && [ ! -L "$f" ] || exit 73
head -c 128 "$f""#,
      "_",
      challenge,
    ])
    .timeout(Duration::from_secs(20))
    .run(ctx)
    .await;
  match out {
    Ok(out) if out.success => result(out.stdout),
    Ok(out)
      if out.code == Some(73)
        || out.stderr.contains("bind source path does not exist") =>
    {
      Err(not_found())
    }
    Ok(_) => Err(ApiError::new(
      ErrorCode::AgentFailed,
      "无法在宿主机读取控制面挑战",
    )),

    Err(e) => {
      crate::build::remove_container(docker, &name).await;
      Err(e)
    }
  }
}

fn result(token: String) -> Result<CoreHostProbeResult, ApiError> {
  let token = token.trim().to_owned();
  if !hex_name(&token, 64) {
    return Err(not_found());
  }
  Ok(CoreHostProbeResult { token })
}

fn read_local(dir: &str, challenge: &str) -> std::io::Result<String> {
  let fd = DirFd::open_absolute(Path::new(dir))?
    .open_subdir(c".core-probe")?;
  let name = component(challenge.as_ref())?;
  let opened = fd.open_file(&name, libc::O_RDONLY | NOFOLLOW, 0)?;
  let file = File::from(opened);
  if !file.metadata()?.is_file() {
    return Err(std::io::Error::other("挑战不是普通文件"));
  }
  let mut token = String::new();
  file.take(128).read_to_string(&mut token)?;
  Ok(token)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{fs, os::unix::fs::PermissionsExt};

  #[tokio::test]
  async fn container_probe_uses_readonly_host_mount_over_same_name() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".core-probe");
    fs::create_dir(&local).unwrap();
    let name = "a".repeat(64);
    let local_value = format!("{:064x}", 1);
    let host_value = format!("{:064x}", 2);
    fs::write(local.join(&name), &local_value).unwrap();
    let fake = temp.path().join("docker");
    let host_path = temp.path().canonicalize().unwrap();
    let host = host_path.to_str().unwrap();
    fs::write(&fake, format!(
      "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = 'type=bind,src={host},dst=/probe,readonly' ]; then\n    printf '%s' '{host_value}'\n    exit 0\n  fi\ndone\nexit 125\n"
    )).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700))
      .unwrap();
    let docker = Docker {
      bin: fake.to_string_lossy().into_owned(),
      data_dir: host_path.clone(),
    };
    let ctx = Ctx::detached();
    let result = read_host(
      &docker,
      host,
      &name,
      Some("example.test/agent"),
      &ctx,
    )
    .await
    .unwrap();
    assert!(result.token == host_value);
    assert!(
      read_host(&docker, host, &name, None, &ctx)
        .await
        .unwrap()
        .token
        == local_value
    );
  }
}
