use std::{fs, path::PathBuf};

use serde_json::Value;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, agent::AgentMemory, resources::UNLIMITED_MEMORY,
};

use crate::{
  docker::Docker,
  exec::Ctx,
  upgrade::{QUICK, inspect, self_container},
};

pub fn sample() -> (Option<(bool, u64)>, Option<u64>) {
  let cgroup =
    fs::read_to_string("/proc/self/cgroup")
      .ok()
      .and_then(|text| {
        let path =
          text.lines().find_map(|line| line.strip_prefix("0::/"))?;
        Some(PathBuf::from("/sys/fs/cgroup").join(path))
      });
  let cpu = cgroup
    .as_ref()
    .and_then(|p| {
      let stat = fs::read_to_string(p.join("cpu.stat")).ok()?;
      field(&stat, "usage_usec ").map(|n| (true, n))
    })
    .or_else(|| process_cpu().map(|n| (false, n)));
  let mem = cgroup
    .and_then(|p| fs::read_to_string(p.join("memory.current")).ok())
    .and_then(|m| m.trim().parse().ok())
    .or_else(|| {
      field(&fs::read_to_string("/proc/self/status").ok()?, "VmRSS:")
        .map(|kb| kb * 1024)
    });
  (cpu, mem)
}

fn field(text: &str, key: &str) -> Option<u64> {
  text
    .lines()
    .find_map(|l| l.strip_prefix(key))?
    .split_whitespace()
    .next()?
    .parse()
    .ok()
}

fn process_cpu() -> Option<u64> {
  let stat = fs::read_to_string("/proc/self/stat").ok()?;
  let mut fields =
    stat.rsplit_once(')')?.1.split_whitespace().skip(11);
  let user: u64 = fields.next()?.parse().ok()?;
  let sys: u64 = fields.next()?.parse().ok()?;
  let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
    .ok()?;
  (user + sys).saturating_mul(1_000_000).checked_div(hz)
}

pub async fn configure(
  docker: Docker,
  mut requests: watch::Receiver<Option<u64>>,
  status: watch::Sender<Option<AgentMemory>>,
  cancel: CancellationToken,
) {
  let ctx = Ctx {
    cancel: cancel.clone(),
    progress: None,
  };
  loop {
    tokio::select! {
      changed = requests.changed() => if changed.is_err() { break; },
      _ = cancel.cancelled() => break,
    }
    let wanted = *requests.borrow_and_update();
    let Some(wanted) = wanted else { continue };
    let mut limit = None;
    let error = apply(&docker, wanted, &mut limit, &ctx)
      .await
      .err()
      .map(|e| {
        tracing::warn!("设置 agent 内存上限失败：{}", e.message);
        e.message
      });
    status.send_replace(Some(AgentMemory { limit, error }));
  }
}

fn limits(config: &Value) -> (u64, i64) {
  (
    config
      .pointer("/HostConfig/Memory")
      .and_then(Value::as_u64)
      .unwrap_or(0),
    config
      .pointer("/HostConfig/MemorySwap")
      .and_then(Value::as_i64)
      .unwrap_or(0),
  )
}

async fn apply(
  docker: &Docker,
  wanted: u64,
  observed: &mut Option<u64>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let id = self_container()?;
  let (memory, swap) = limits(&inspect(docker, &id, ctx).await?);
  let display_limit =
    |mem| if mem >= UNLIMITED_MEMORY { 0 } else { mem };
  *observed = Some(display_limit(memory));
  let target = if wanted == 0 {
    UNLIMITED_MEMORY
  } else {
    wanted
  };
  let target_swap = if wanted == 0 { -1 } else { wanted as i64 };
  if (memory == 0 && swap <= 0 && wanted == 0)
    || (memory, swap) == (target, target_swap)
  {
    return Ok(());
  }
  let out = docker
    .cmd()
    .args([
      "update",
      "--memory",
      &target.to_string(),
      "--memory-swap",
      &target_swap.to_string(),
      &id,
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker update")?;
  let (memory, swap) = limits(&inspect(docker, &id, ctx).await?);
  *observed = Some(display_limit(memory));
  if (memory, swap) != (target, target_swap) {
    return Err(ApiError::invalid(format!(
      "Docker 未应用内存上限 {}",
      out.stderr.trim()
    )));
  }
  Ok(())
}
