use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use wharf_api_types::{
  ApiError, ErrorCode,
  net_probe::{
    ContainerProbeInfo, ContainerProbeScope, NetProbeError,
    NetProbeErrorKind, NetProbeJob, NetProbeResult,
  },
};

use crate::{
  diagnose::{Container, project_containers},
  docker::Docker,
  exec::{Ctx, tail_lines},
  net_probe,
};

const EGRESS_ERROR: &str = "从容器里探测不支持 --egress";

pub(crate) fn probe_cli(encoded: &str) -> anyhow::Result<()> {
  let job = decode_job(encoded)?;
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
  let result =
    runtime.block_on(net_probe::run(&job, &Ctx::detached()));
  // DNS 查询可能还占着阻塞线程，不能在退出时等它。
  runtime.shutdown_background();
  println!("{}", serde_json::to_string(&result)?);
  Ok(())
}

fn encode_job(
  job: &NetProbeJob,
) -> Result<String, serde_json::Error> {
  serde_json::to_vec(job).map(|json| URL_SAFE_NO_PAD.encode(json))
}

fn decode_job(encoded: &str) -> anyhow::Result<NetProbeJob> {
  let job: NetProbeJob =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
  anyhow::ensure!(
    job.container.is_none(),
    "探测子命令不接受容器范围"
  );
  anyhow::ensure!(!job.egress, EGRESS_ERROR);
  Ok(job)
}

pub(crate) async fn run(
  docker: &Docker,
  scope: ContainerProbeScope,
  job: &NetProbeJob,
  ctx: &Ctx,
) -> Result<NetProbeResult, ApiError> {
  if job.egress {
    return Err(ApiError::invalid(EGRESS_ERROR));
  }
  let project = &scope.project;
  let containers = project_containers(docker, project, ctx).await?;
  let c = select_container(
    &containers,
    project,
    scope.component.as_deref(),
  )?;
  let name = container_name(c);
  if !c.state.running || c.state.restarting {
    let status = &c.state.status;
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("容器 {name} 当前状态 {status}，没法进它的网络探测"),
      )
      .suggest(format!("wharf service logs {project}")),
    );
  }

  let mode = c.host_config.network_mode.as_str();
  let helper = !matches!(mode, "none" | "host");
  let mut result = match mode {
    "none" => failed("容器网络模式是 none，没有网络".into()),
    "host" => net_probe::run(job, ctx).await,
    _ => run_helper(docker, &c.id, job, ctx).await?,
  };
  result.container = Some(ContainerProbeInfo {
    name: name.into(),
    component: component_name(c).map(str::to_owned),
    network_mode: mode.into(),
    helper,
    proxy_env: proxy_env(c.config.env.as_deref().unwrap_or_default()),
  });
  Ok(result)
}

fn container_name(c: &Container) -> &str {
  c.name.trim_start_matches('/')
}

fn component_name(c: &Container) -> Option<&str> {
  c.config
    .labels
    .get("com.docker.compose.service")
    .map(String::as_str)
}

fn select_container<'a>(
  containers: &'a [Container],
  project: &str,
  component: Option<&str>,
) -> Result<&'a Container, ApiError> {
  let mut matched = containers.iter().filter(|c| {
    component.is_none_or(|name| component_name(c) == Some(name))
  });
  match (matched.next(), matched.next(), component) {
    (Some(c), None, _) => Ok(c),
    (None, _, None) => {
      Err(ApiError::not_found(format!("服务 {project} 没有容器")))
    }
    (None, _, Some(name)) => {
      let names = component_names(containers);
      Err(ApiError::not_found(format!(
        "服务 {project} 没有组件 {name}，现有组件：{names}"
      )))
    }
    (Some(_), Some(_), None) => {
      let names = component_names(containers);
      Err(ApiError::invalid(format!(
        "服务 {project} 有多个容器：{names}，请用 --component 指定"
      )))
    }
    (Some(_), Some(_), Some(name)) => {
      Err(ApiError::invalid(format!(
        "服务 {project} 的组件 {name} 有多个容器，无法唯一定位"
      )))
    }
  }
}

fn component_names(containers: &[Container]) -> String {
  if containers.is_empty() {
    return "无".into();
  }
  let mut names: Vec<_> = containers
    .iter()
    .map(|c| component_name(c).unwrap_or_else(|| container_name(c)))
    .collect();
  names.sort_unstable();
  names.dedup();
  names.join("、")
}

fn proxy_env(env: &[String]) -> Vec<String> {
  env
    .iter()
    .filter_map(|entry| {
      let (key, value) = entry.split_once('=')?;
      let key = key.to_ascii_uppercase();
      match key.as_str() {
        "NO_PROXY" => Some(key),
        "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" => {
          let address = Url::parse(value).ok().and_then(|url| {
            Some(format!(
              "{}:{}",
              url.host_str()?,
              url.port_or_known_default()?
            ))
          });
          Some(match address {
            Some(address) => format!("{key}={address}"),
            None => key,
          })
        }
        _ => None,
      }
    })
    .collect()
}

async fn run_helper(
  docker: &Docker,
  id: &str,
  job: &NetProbeJob,
  ctx: &Ctx,
) -> Result<NetProbeResult, ApiError> {
  let image = crate::adopt::self_image(docker, ctx).await?;
  let mut random = [0; 8];
  getrandom::fill(&mut random)
    .map_err(|_| ApiError::internal("无法生成探测容器名"))?;
  let name = format!("wharf-probe-{}", hex::encode(random));
  let encoded = encode_job(job)
    .map_err(|_| ApiError::internal("无法编码探测任务"))?;
  let timeout = Duration::from_secs(u64::from(job.timeout_secs) + 10);
  let output = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--label",
      "wharf.temp=1",
      "--name",
      &name,
      "--pull=never",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--memory",
      "64m",
      "--pids-limit",
      "64",
      "--network",
    ])
    .arg(format!("container:{id}"))
    .args([
      "--entrypoint",
      "wharf-agent",
      "--",
      &image,
      "net-probe",
      &encoded,
    ])
    .timeout(timeout)
    .run(ctx)
    .await;
  if let Ok(out) = &output
    && out.success
    && let Ok(result) =
      serde_json::from_str::<NetProbeResult>(&out.stdout)
  {
    return Ok(result);
  }

  let _ = docker
    .cmd()
    .args(["rm", "-f", &name])
    .timeout(Duration::from_secs(5))
    .run(&Ctx::detached())
    .await;
  let out = output?;
  let message = if out.success {
    "无法解析探测容器的输出"
  } else {
    "探测容器执行失败"
  };
  let stderr = tail_lines(&out.stderr, 1);
  let message = if stderr.is_empty() {
    message.into()
  } else {
    format!("{message}：{stderr}")
  };
  Ok(failed(message))
}

fn failed(message: String) -> NetProbeResult {
  NetProbeResult {
    error: Some(NetProbeError {
      kind: NetProbeErrorKind::Other,
      message,
    }),
    ..Default::default()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use wharf_api_types::net_probe::NetProbeKind;

  fn container(component: &str) -> Container {
    serde_json::from_value(json!({
      "Id": component, "Name": format!("/blog-{component}-1"),
      "State": { "Running": true, "Restarting": false, "ExitCode": 0,
        "OOMKilled": false, "StartedAt": "", "Status": "running" },
      "RestartCount": 0,
      "Config": { "User": "", "Labels": { "com.docker.compose.service": component } },
      "HostConfig": { "NetworkMode": "blog_default" },
      "NetworkSettings": {}
    })).unwrap()
  }

  #[test]
  fn selects_only_an_unambiguous_component() {
    let containers = [container("web"), container("worker")];
    assert_eq!(
      select_container(&containers[..1], "blog", None).unwrap().id,
      "web"
    );
    let error =
      select_container(&containers, "blog", None).err().unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert!(error.message.contains("web、worker"));
    let error = select_container(&containers, "blog", Some("db"))
      .err()
      .unwrap();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(error.message.contains("web、worker"));
  }

  #[test]
  fn redacts_proxy_environment() {
    let env = [
      "HTTPS_PROXY=http://user:pass@100.80.120.24:8118/path?secret",
      "HTTP_PROXY=http://proxy.example",
      "NO_PROXY=private.example",
      "all_proxy=socks5://proxy.example:1080",
      "PATH=/usr/bin",
    ]
    .map(str::to_owned);
    assert_eq!(
      proxy_env(&env),
      [
        "HTTPS_PROXY=100.80.120.24:8118",
        "HTTP_PROXY=proxy.example:80",
        "NO_PROXY",
        "ALL_PROXY=proxy.example:1080",
      ]
    );
  }

  #[test]
  fn round_trips_job_and_rejects_nested_scope() {
    let mut job = NetProbeJob {
      kind: NetProbeKind::Dns,
      target: "postgres".into(),
      timeout_secs: 5,
      egress: false,
      container: None,
    };
    assert_eq!(decode_job(&encode_job(&job).unwrap()).unwrap(), job);
    job.container = Some(ContainerProbeScope {
      project: "blog".into(),
      component: None,
    });
    let error = probe_cli(&encode_job(&job).unwrap()).unwrap_err();
    assert_eq!(error.to_string(), "探测子命令不接受容器范围");
  }
}
