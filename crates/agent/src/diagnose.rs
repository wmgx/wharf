//! 只读定位 compose 项目的端口监听和目录权限。

use std::{
  collections::BTreeMap,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  os::unix::fs::MetadataExt,
  path::Path,
  time::Duration,
};

use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  agent::{
    BindMountDiagnosis, ContainerDiagnosis, ContainerLogKeyword,
    ContainerUser, DirectoryPermissions,
  },
};

use crate::{docker::Docker, exec::Ctx};

const QUICK: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Container {
  id: String,
  name: String,
  state: State,
  restart_count: u64,
  config: Config,
  host_config: HostConfig,
  network_settings: NetworkSettings,
  mounts: Option<Vec<Mount>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
  running: bool,
  restarting: bool,
  exit_code: i32,
  #[serde(rename = "OOMKilled")]
  oom_killed: bool,
  started_at: String,
  status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
  user: String,
  labels: BTreeMap<String, String>,
}

type Bindings = BTreeMap<String, Option<Vec<Binding>>>;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
  network_mode: String,
  port_bindings: Option<Bindings>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
  ports: Option<Bindings>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Binding {
  host_port: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
  #[serde(rename = "Type")]
  kind: String,
  #[serde(rename = "RW")]
  rw: bool,
  source: String,
}

pub async fn run(
  docker: &Docker,
  project: &str,
  ports: &[u16],
  ctx: &Ctx,
) -> Result<Vec<ContainerDiagnosis>, ApiError> {
  let listed = docker
    .cmd()
    .args(["ps", "-aq", "--no-trunc", "--filter"])
    .arg(format!("label=com.docker.compose.project={project}"))
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker ps")?;
  let ids: Vec<_> = listed.stdout.split_whitespace().collect();
  if ids.is_empty() {
    return Ok(vec![]);
  }
  let inspected = docker
    .cmd()
    .args(["inspect", "--type", "container", "--"])
    .args(ids)
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker inspect")?;
  let mut containers: Vec<Container> =
    serde_json::from_str(&inspected.stdout).map_err(|_| {
      ApiError::internal("无法读取 docker inspect 的容器状态")
    })?;
  let project_dir = docker.project_dir(project);
  containers.retain(|c| {
    c.config
      .labels
      .get("com.docker.compose.project")
      .is_some_and(|p| p == project)
      && c
        .config
        .labels
        .get("com.docker.compose.project.working_dir")
        .is_none_or(|dir| Path::new(dir) == project_dir.as_path())
  });

  let mut selected: BTreeMap<usize, BTreeMap<u16, u16>> =
    BTreeMap::new();
  for &host in ports {
    if let Some((index, port)) = select_container(&containers, host) {
      selected.entry(index).or_default().insert(host, port);
    }
  }
  let mut results = Vec::new();
  for (index, ports) in selected {
    results
      .push(diagnose(docker, &containers[index], ports, ctx).await);
  }
  Ok(results)
}

fn select_container(
  containers: &[Container],
  host: u16,
) -> Option<(usize, u16)> {
  let mapped = |runtime| {
    containers
      .iter()
      .enumerate()
      .filter_map(|(index, c)| {
        let bindings = if runtime {
          &c.network_settings.ports
        } else {
          &c.host_config.port_bindings
        };
        let port =
          bindings.as_ref()?.iter().find_map(|(key, values)| {
            let port =
              key.strip_suffix("/tcp")?.parse::<u16>().ok()?;
            values
              .as_ref()?
              .iter()
              .any(|b| b.host_port.parse::<u16>().ok() == Some(host))
              .then_some(port)
          })?;
        Some((index, port))
      })
      .max_by_key(|(i, _)| {
        let state = &containers[*i].state;
        (
          state.running && !state.restarting,
          state.restarting,
          state.started_at.as_str(),
        )
      })
  };
  mapped(true).or_else(|| mapped(false)).or_else(|| {
    // host 网络没有端口映射，只能可靠定位单容器项目。
    let [container] = containers else { return None };
    (container.host_config.network_mode == "host")
      .then_some((0, host))
  })
}

async fn diagnose(
  docker: &Docker,
  container: &Container,
  ports: BTreeMap<u16, u16>,
  ctx: &Ctx,
) -> ContainerDiagnosis {
  let state = &container.state;
  let running = state.running && !state.restarting;
  let listeners = if running {
    listeners(docker, container, ctx).await
  } else {
    None
  };
  let user = if running {
    running_user(docker, &container.id, ctx).await
  } else {
    configured_user(&container.config.user)
  };
  let mounts = container
    .mounts
    .iter()
    .flatten()
    .filter(|m| m.kind == "bind" && m.rw)
    .filter_map(|m| bind_mount(&m.source, user))
    .collect();
  let log_keywords = if state.restarting
    || matches!(state.status.as_str(), "exited" | "dead")
  {
    log_keywords(docker, &container.id, ctx).await
  } else {
    vec![]
  };
  ContainerDiagnosis {
    name: container.name.trim_start_matches('/').to_string(),
    running: state.running,
    restarting: state.restarting,
    exit_code: state.exit_code,
    oom_killed: state.oom_killed,
    started_at: state.started_at.clone(),
    restart_count: container.restart_count,
    network_mode: container.host_config.network_mode.clone(),
    ports,
    listeners,
    user,
    mounts,
    log_keywords,
  }
}

async fn listeners(
  docker: &Docker,
  c: &Container,
  ctx: &Ctx,
) -> Option<Vec<SocketAddr>> {
  if c.host_config.network_mode == "host" {
    let tcp = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let tcp6 =
      std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let mut listeners = parse_tcp(&tcp);
    listeners.extend(parse_tcp(&tcp6));
    return Some(listeners);
  }

  let image = crate::adopt::self_image(docker, ctx).await.ok()?;
  let mut random = [0u8; 8];
  getrandom::fill(&mut random).ok()?;
  let name = format!("wharf-diagnose-{}", hex::encode(random));
  let result = docker.cmd()
    .args(["run", "--rm", "--label", "wharf.temp=1", "--name", &name,
      "--pull=never", "--read-only", "--network"])
    .arg(format!("container:{}", c.id))
    .args(["--entrypoint", "/usr/bin/timeout", "--", &image, "-s", "KILL", "4s", "sh", "-c",
      "cat /proc/net/tcp && if [ -r /proc/net/tcp6 ]; then cat /proc/net/tcp6; fi"])
    .timeout(Duration::from_secs(7))
    .run(ctx)
    .await;
  match result {
    Ok(out) if out.success => Some(parse_tcp(&out.stdout)),
    _ => {
      // Docker CLI 被取消时，辅助容器可能还未启动。
      let _ = docker
        .cmd()
        .args(["rm", "-f", &name])
        .timeout(QUICK)
        .run(&Ctx::detached())
        .await;
      None
    }
  }
}

fn parse_tcp(text: &str) -> Vec<SocketAddr> {
  text
    .lines()
    .filter_map(|line| {
      let mut cols = line.split_whitespace();
      let local = cols.nth(1)?;
      if cols.nth(1)? != "0A" {
        return None;
      }
      let (hex, port) = local.split_once(':')?;
      let ip = match hex.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
          u32::from_str_radix(hex, 16).ok()?.to_le_bytes(),
        )),
        32 if hex.is_ascii() => {
          let mut bytes = [0; 16];
          for (i, chunk) in bytes.chunks_exact_mut(4).enumerate() {
            let word =
              u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16)
                .ok()?;
            chunk.copy_from_slice(&word.to_le_bytes());
          }
          let ip = Ipv6Addr::from(bytes);
          ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
        }
        _ => return None,
      };
      Some(SocketAddr::new(ip, u16::from_str_radix(port, 16).ok()?))
    })
    .collect()
}

async fn running_user(
  docker: &Docker,
  id: &str,
  ctx: &Ctx,
) -> Option<ContainerUser> {
  let out = docker
    .cmd()
    .args(["top", id, "-eo", "uid,gid"])
    .timeout(QUICK)
    .run(ctx)
    .await
    .ok()?;
  if !out.success {
    return None;
  }
  let mut users = out.stdout.lines().skip(1).filter_map(|line| {
    let mut fields = line.split_whitespace();
    Some(ContainerUser {
      uid: fields.next()?.parse().ok()?,
      gid: Some(fields.next()?.parse().ok()?),
    })
  });
  let first = users.next()?;
  if first.uid != 0 {
    return Some(first);
  }
  users.find(|user| user.uid != 0).or(Some(first))
}

fn configured_user(config: &str) -> Option<ContainerUser> {
  if config.is_empty() {
    return Some(ContainerUser {
      uid: 0,
      gid: Some(0),
    });
  }
  if let Some((uid, gid)) = config.split_once(':') {
    return Some(ContainerUser {
      uid: uid.parse().ok()?,
      gid: Some(gid.parse().ok()?),
    });
  }
  Some(ContainerUser {
    uid: config.parse().ok()?,
    gid: None,
  })
}

fn bind_mount(
  source: &str,
  user: Option<ContainerUser>,
) -> Option<BindMountDiagnosis> {
  let root = Path::new("/srv");
  let path = Path::new(source);
  let metadata = (path != root && path.starts_with(root))
    .then(|| path.canonicalize().ok())
    .flatten()
    .filter(|p| p != root && p.starts_with(root))
    .and_then(|p| p.metadata().ok());
  if metadata.as_ref().is_some_and(|m| !m.is_dir()) {
    return None;
  }
  Some(BindMountDiagnosis {
    source: source.to_string(),
    permissions: metadata.map(|m| DirectoryPermissions {
      uid: m.uid(),
      gid: m.gid(),
      mode: m.mode() & 0o7777,
      writable: user
        .and_then(|u| can_write(u, m.uid(), m.gid(), m.mode())),
    }),
  })
}

fn can_write(
  user: ContainerUser,
  uid: u32,
  gid: u32,
  mode: u32,
) -> Option<bool> {
  if user.uid == 0
    || (user.uid == uid && mode & 0o300 == 0o300)
    || mode & 0o003 == 0o003
  {
    Some(true)
  } else if mode & 0o030 != 0o030 {
    Some(false)
  } else {
    user.gid.map(|group| group == gid)
  }
}

async fn log_keywords(
  docker: &Docker,
  id: &str,
  ctx: &Ctx,
) -> Vec<ContainerLogKeyword> {
  let Ok(out) = docker
    .cmd()
    .args(["logs", "--tail", "20", "--", id])
    .timeout(QUICK)
    .run(ctx)
    .await
  else {
    return vec![];
  };
  if !out.success {
    return vec![];
  }
  let logs =
    format!("{}\n{}", out.stdout, out.stderr).to_ascii_lowercase();
  use ContainerLogKeyword::*;
  [
    ("permission denied", PermissionDenied),
    ("eacces", Eacces),
    ("read-only file system", ReadOnlyFileSystem),
    ("exec format error", ExecFormatError),
  ]
  .into_iter()
  .filter_map(|(text, keyword)| {
    logs.contains(text).then_some(keyword)
  })
  .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_listening_tcp_and_tcp6() {
    let tcp = "      0: 0100007F:0BB8 00000000:0000 0A\n      1: 00000000:1F90 00000000:0000 0A\n      2: 0100007F:0BB9 00000000:0000 01";
    assert_eq!(
      parse_tcp(tcp),
      [
        "127.0.0.1:3000".parse().unwrap(),
        "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
      ]
    );
    let tcp6 = "      0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A\n      1: 0000000000000000FFFF00000100007F:0BB8 00000000000000000000000000000000:0000 0A";
    let addresses = parse_tcp(tcp6);
    assert_eq!(addresses.len(), 2);
    assert!(addresses.iter().all(|addr| addr.ip().is_loopback()));
  }

  #[test]
  fn directory_writability() {
    let root = ContainerUser {
      uid: 0,
      gid: Some(0),
    };
    let user = ContainerUser {
      uid: 1000,
      gid: Some(1000),
    };
    assert_eq!(can_write(root, 0, 0, 0o000), Some(true));
    assert_eq!(can_write(user, 0, 0, 0o755), Some(false));
    assert_eq!(can_write(user, 1000, 1000, 0o755), Some(true));
    assert_eq!(can_write(user, 0, 1000, 0o775), Some(true));
    assert_eq!(can_write(user, 0, 0, 0o777), Some(true));
  }
}
