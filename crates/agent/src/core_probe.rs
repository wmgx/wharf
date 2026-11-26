//! 从控制面宿主机的数据目录读取同机挑战，回显只走加密会话。

use std::{
  fs::File,
  io::Read,
  path::{Component, Path},
  time::Duration,
};

use wharf_api_types::{
  ApiError,
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
    let inspection = match crate::upgrade::inspect(docker, cid, ctx)
      .await
    {
      Ok(info) => info,
      Err(e) if e.code == wharf_api_types::ErrorCode::AgentFailed => {
        return Err(not_found());
      }
      Err(e) => return Err(e),
    };
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
  if let Ok(token) = read_local(&host, &probe.challenge_id) {
    return result(token);
  }

  let image = crate::adopt::self_image(docker, ctx)
    .await
    .map_err(|_| not_found())?;
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
      &image,
      "-c",
      r#"set -e
[ -d /probe/.core-probe ] && [ ! -L /probe/.core-probe ]
f="/probe/.core-probe/$1"
[ -f "$f" ] && [ ! -L "$f" ] && head -c 128 "$f""#,
      "_",
      &probe.challenge_id,
    ])
    .timeout(Duration::from_secs(20))
    .run(ctx)
    .await;
  match out {
    Ok(out) if out.success => result(out.stdout),
    Ok(_) => Err(not_found()),
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
