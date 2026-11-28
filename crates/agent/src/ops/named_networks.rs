use std::{collections::BTreeMap, time::Duration};

use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  spec::{NetworkAttachment, named_network_name},
};

use crate::{docker::Docker, exec::Ctx};

const LABEL: &str = "wharf.named-network";
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspected {
  name: String,
  driver: String,
  internal: bool,
  labels: Option<BTreeMap<String, String>>,
}

async fn existing(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
) -> Result<Vec<Inspected>, ApiError> {
  let filter = format!("name=^{name}$");
  let ids = docker
    .cmd()
    .args([
      "network",
      "ls",
      "--quiet",
      "--no-trunc",
      "--filter",
      &filter,
    ])
    .timeout(TIMEOUT)
    .run(ctx)
    .await?
    .check("列出 Docker 网络")?;
  let ids: Vec<_> = ids.stdout.split_whitespace().collect();
  if ids.is_empty() {
    return Ok(Vec::new());
  }
  let result = docker
    .cmd()
    .args(["network", "inspect"])
    .args(ids)
    .timeout(TIMEOUT)
    .run(ctx)
    .await?
    .check("读取 Docker 网络")?;
  serde_json::from_str(&result.stdout)
    .map_err(|_| ApiError::internal("无法读取 Docker 网络属性"))
}

fn check(
  networks: &[Inspected],
  name: &str,
  internal: bool,
) -> Result<bool, ApiError> {
  match networks {
    [] => Ok(false),
    [network]
      if network.name == name
        && network.driver == "bridge"
        && network.internal == internal
        && network
          .labels
          .as_ref()
          .and_then(|l| l.get(LABEL))
          .is_some_and(|v| v == name) =>
    {
      Ok(true)
    }
    _ => Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("本机网络 {name} 与声明冲突"),
      )
      .with_hint("检查网络归属及 internal 属性，或换网络名"),
    ),
  }
}

pub(super) async fn ensure(
  docker: &Docker,
  networks: &BTreeMap<String, NetworkAttachment>,
  create: bool,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  for (name, spec) in networks {
    wharf_api_types::validate_name("网络", name)?;
    let name = named_network_name(name);
    if check(
      &existing(docker, &name, ctx).await?,
      &name,
      spec.internal,
    )? || !create
    {
      continue;
    }
    let label = format!("{LABEL}={name}");
    let mut cmd = docker.cmd().args([
      "network", "create", "--driver", "bridge", "--label", &label,
    ]);
    if spec.internal {
      cmd = cmd.arg("--internal");
    }
    let created = cmd.arg(&name).timeout(TIMEOUT).run(ctx).await?;
    if !check(
      &existing(docker, &name, ctx).await?,
      &name,
      spec.internal,
    )? {
      created.check("创建 Docker 网络")?;
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("创建后找不到网络 {name}"),
      ));
    }
  }
  Ok(())
}
