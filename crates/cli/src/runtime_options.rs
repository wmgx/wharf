use std::collections::BTreeMap;

use clap::Args;
use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError,
  spec::{
    ImagePullMode, Limits, LogMax, ServiceSpec, Source, Ulimit,
  },
};

use crate::{client::CliResult, commands::list_edits::remove_named};

#[derive(Args, Default)]
pub struct RuntimeOptions {
  #[arg(long, allow_hyphen_values = true)]
  command_arg: Vec<String>,
  #[arg(long, conflicts_with_all = ["command_arg", "unset_command"])]
  empty_command: bool,
  #[arg(long, conflicts_with = "command_arg")]
  unset_command: bool,
  #[arg(long)]
  shm_size: Option<String>,
  #[arg(long, conflicts_with = "shm_size")]
  unset_shm_size: bool,
  #[arg(long)]
  add_cap: Vec<String>,
  #[arg(long)]
  rm_cap: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_cap", "rm_cap"])]
  clear_caps: bool,
  #[arg(long)]
  add_ulimit: Vec<String>,
  #[arg(long)]
  rm_ulimit: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_ulimit", "rm_ulimit"])]
  clear_ulimits: bool,
  #[arg(long)]
  init: bool,
  #[arg(long, conflicts_with = "init")]
  no_init: bool,
  #[arg(long, conflicts_with_all = ["init", "no_init"])]
  unset_init: bool,
  #[arg(long)]
  add_group: Vec<String>,
  #[arg(long)]
  rm_group: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_group", "rm_group"])]
  clear_groups: bool,
  #[arg(long)]
  hostname: Option<String>,
  #[arg(long, conflicts_with = "hostname")]
  unset_hostname: bool,
  #[arg(long)]
  add_tmpfs: Vec<String>,
  #[arg(long)]
  rm_tmpfs: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_tmpfs", "rm_tmpfs"])]
  clear_tmpfs: bool,
  #[arg(long, allow_hyphen_values = true)]
  timezone: Option<String>,
  #[arg(long, conflicts_with = "timezone")]
  unset_timezone: bool,
  #[arg(long, value_parser = ["if_missing", "never", "always"])]
  pull_policy: Option<String>,
  #[arg(long, conflicts_with = "pull_policy")]
  unset_pull_policy: bool,
  #[arg(long)]
  log_max: Option<String>,
  #[arg(long, conflicts_with = "log_max")]
  unset_log_max: bool,
}

impl RuntimeOptions {
  fn image_edits(&self) -> bool {
    !self.command_arg.is_empty()
      || self.empty_command
      || self.unset_command
      || self.shm_size.is_some()
      || self.unset_shm_size
      || !self.add_cap.is_empty()
      || !self.rm_cap.is_empty()
      || self.clear_caps
      || !self.add_ulimit.is_empty()
      || !self.rm_ulimit.is_empty()
      || self.clear_ulimits
      || self.init
      || self.no_init
      || self.unset_init
      || !self.add_group.is_empty()
      || !self.rm_group.is_empty()
      || self.clear_groups
      || self.hostname.is_some()
      || self.unset_hostname
      || !self.add_tmpfs.is_empty()
      || !self.rm_tmpfs.is_empty()
      || self.clear_tmpfs
      || self.timezone.is_some()
      || self.unset_timezone
      || self.log_max.is_some()
      || self.unset_log_max
  }

  pub fn has_edits(&self) -> bool {
    self.image_edits()
      || self.pull_policy.is_some()
      || self.unset_pull_policy
  }

  pub fn apply(&self, spec: &mut ServiceSpec) -> CliResult<()> {
    if matches!(spec.source, Source::Compose { .. })
      && self.image_edits()
    {
      return Err(
        ApiError::invalid("运行参数只用于镜像和构建来源")
          .with_hint("在 Compose 的 services.<组件> 设置对应字段")
          .into(),
      );
    }
    if self.unset_command {
      spec.command = None;
    } else if self.empty_command || !self.command_arg.is_empty() {
      spec.command = Some(self.command_arg.clone());
    }
    if self.unset_shm_size || self.shm_size.is_some() {
      spec.shm_size = self
        .shm_size
        .as_deref()
        .map(|value| {
          size(value).ok_or_else(|| {
            ApiError::invalid("共享内存大小不合法")
              .with_hint("例如 --shm-size 128m")
          })
        })
        .transpose()?;
    }
    if self.unset_init || self.init || self.no_init {
      spec.init = (!self.unset_init).then_some(self.init);
    }
    if self.unset_hostname || self.hostname.is_some() {
      spec.hostname.clone_from(&self.hostname);
    }
    if self.unset_timezone || self.timezone.is_some() {
      spec.timezone =
        self.timezone.clone().or_else(|| Some("off".into()));
    }
    if self.unset_pull_policy || self.pull_policy.is_some() {
      spec.pull_policy = match self.pull_policy.as_deref() {
        Some("if_missing") => Some(ImagePullMode::IfMissing),
        Some("never") => Some(ImagePullMode::Never),
        Some("always") => Some(ImagePullMode::Always),
        None => None,
        Some(_) => {
          return Err(ApiError::invalid("拉取策略不合法").into());
        }
      };
    }
    if self.unset_log_max || self.log_max.is_some() {
      spec.log_max = self
        .log_max
        .as_deref()
        .map(|value| {
          let parse = || {
            let (bytes, files) = value.rsplit_once(':')?;
            let max_bytes = size(bytes)?;
            let max_files =
              files.parse::<u32>().ok().filter(|&n| n > 0)?;
            Some(LogMax {
              max_bytes,
              max_files,
            })
          };
          parse().ok_or_else(|| {
            ApiError::invalid("日志轮转需要正数大小和保留文件数")
              .with_hint("例如 --log-max 5m:1")
          })
        })
        .transpose()?;
    }
    if self.clear_caps {
      spec.cap_add.clear();
    }
    let cap_name = |cap: &str| {
      let upper = cap.to_ascii_uppercase();
      upper.strip_prefix("CAP_").unwrap_or(&upper).to_owned()
    };
    for cap in &self.rm_cap {
      remove_named(
        &mut spec.cap_add,
        &cap_name(cap),
        "内核能力",
        String::as_str,
      )?;
    }
    for cap in self.add_cap.iter().map(|cap| cap_name(cap)) {
      if !spec.cap_add.contains(&cap) {
        spec.cap_add.push(cap);
      }
    }
    if self.clear_groups {
      spec.group_add.clear();
    }
    for group in &self.rm_group {
      remove_named(
        &mut spec.group_add,
        group,
        "容器组",
        String::as_str,
      )?;
    }
    for group in &self.add_group {
      if !spec.group_add.contains(group) {
        spec.group_add.push(group.clone());
      }
    }
    if self.clear_ulimits {
      spec.ulimits.clear();
    }
    for name in &self.rm_ulimit {
      remove_key(&mut spec.ulimits, name, "ulimit")?;
    }
    for arg in &self.add_ulimit {
      let parse = || {
        let (name, values) = arg.split_once('=')?;
        let (soft, hard) = values.split_once(':')?;
        Some((
          name,
          Ulimit {
            soft: soft.parse().ok()?,
            hard: hard.parse().ok()?,
          },
        ))
      };
      let (name, limit) = parse().ok_or_else(|| {
        ApiError::invalid("ulimit 格式不合法")
          .with_hint("例如 --add-ulimit nofile=1024:2048")
      })?;
      spec.ulimits.insert(name.into(), limit);
    }
    if self.clear_tmpfs {
      spec.tmpfs.clear();
    }
    for path in &self.rm_tmpfs {
      remove_key(&mut spec.tmpfs, path, "tmpfs")?;
    }
    for arg in &self.add_tmpfs {
      let (path, bytes) = arg
        .rsplit_once(':')
        .and_then(|(path, value)| Some((path, size(value)?)))
        .ok_or_else(|| {
          ApiError::invalid("tmpfs 格式不合法")
            .with_hint("例如 --add-tmpfs /tmp:64m")
        })?;
      spec.tmpfs.insert(path.into(), bytes);
    }
    Ok(())
  }
}

fn remove_key<T>(
  items: &mut BTreeMap<String, T>,
  key: &str,
  label: &str,
) -> CliResult<()> {
  if items.remove(key).is_none() {
    return Err(
      ApiError::invalid(format!("{label} {key} 不存在"))
        .with_hint(format!(
          "现有{label}：{}",
          items.keys().cloned().collect::<Vec<_>>().join("、")
        ))
        .into(),
    );
  }
  Ok(())
}

fn size(value: &str) -> Option<u64> {
  let end = value
    .bytes()
    .position(|b| !b.is_ascii_digit())
    .unwrap_or(value.len());
  let count: u64 = value[..end].parse().ok()?;
  let scale = match value[end..].to_ascii_lowercase().as_str() {
    "" | "b" => 1,
    "k" => 1 << 10,
    "m" => 1 << 20,
    "g" => 1 << 30,
    _ => return None,
  };
  count.checked_mul(scale).filter(|&bytes| bytes > 0)
}

#[derive(Args, Debug, Default)]
pub struct LimitEdits {
  /// 内存上限（MiB），0 清除。
  #[arg(long)]
  pub memory: Option<u32>,
  /// CPU 核数，0 清除。
  #[arg(long)]
  pub cpus: Option<f64>,
  /// PID 上限，0 清除。
  #[arg(long)]
  pub pids: Option<u32>,
  #[arg(long, conflicts_with = "memory")]
  pub unset_memory: bool,
  #[arg(long, conflicts_with = "cpus")]
  pub unset_cpus: bool,
  #[arg(long, conflicts_with = "pids")]
  pub unset_pids: bool,
}

impl LimitEdits {
  pub fn has_edits(&self) -> bool {
    self.memory.is_some()
      || self.cpus.is_some()
      || self.pids.is_some()
      || self.unset_memory
      || self.unset_cpus
      || self.unset_pids
  }

  pub fn apply(
    &self,
    old: Option<Limits>,
  ) -> Result<Option<Limits>, ApiError> {
    let mut limits = old.unwrap_or_default();
    if self.unset_memory || self.memory.is_some() {
      limits.memory_mb = self.memory;
    }
    if self.unset_cpus || self.cpus.is_some() {
      limits.cpu_milli = self.cpus.map(cpu_milli).transpose()?;
    }
    if self.unset_pids || self.pids.is_some() {
      limits.pids = self.pids;
    }
    limits.normalize();
    Ok((!limits.is_empty()).then_some(limits))
  }
}

#[derive(Args, Debug, Default)]
pub struct TaskLimitEdits {
  #[command(flatten)]
  limits: LimitEdits,
  #[arg(long)]
  inherit_server_limits: bool,
  #[arg(long, conflicts_with = "inherit_server_limits")]
  no_inherit_server_limits: bool,
}

impl TaskLimitEdits {
  pub fn has_edits(&self) -> bool {
    self.limits.has_edits()
      || self.inherit_server_limits
      || self.no_inherit_server_limits
  }

  pub fn apply(
    &self,
    spec: &mut wharf_api_types::view::TaskSpec,
  ) -> Result<(), ApiError> {
    if self.limits.has_edits() {
      spec.limits = self.limits.apply(spec.limits.clone())?;
    }
    if self.inherit_server_limits || self.no_inherit_server_limits {
      spec.inherit_server_limits = self.inherit_server_limits;
    }
    Ok(())
  }
}

#[derive(Args)]
pub struct ServerTaskLimitEdits {
  #[arg(long)]
  task_memory: Option<u32>,
  #[arg(long)]
  task_cpus: Option<f64>,
  #[arg(long)]
  task_pids: Option<u32>,
  #[arg(long, conflicts_with = "task_memory")]
  unset_task_memory: bool,
  #[arg(long, conflicts_with = "task_cpus")]
  unset_task_cpus: bool,
  #[arg(long, conflicts_with = "task_pids")]
  unset_task_pids: bool,
}

impl ServerTaskLimitEdits {
  pub fn edits(&self) -> LimitEdits {
    LimitEdits {
      memory: self.task_memory,
      cpus: self.task_cpus,
      pids: self.task_pids,
      unset_memory: self.unset_task_memory,
      unset_cpus: self.unset_task_cpus,
      unset_pids: self.unset_task_pids,
    }
  }
}

fn cpu_milli(cpus: f64) -> Result<u32, ApiError> {
  let milli = cpus * 1000.0;
  if !cpus.is_finite()
    || !(0.0..=f64::from(u32::MAX)).contains(&milli)
    || (cpus != 0.0 && milli < 10.0)
  {
    return Err(
      ApiError::invalid("CPU 上限不合法")
        .with_hint("填写至少 0.01 的核数，0 表示去掉 CPU 上限"),
    );
  }
  Ok(milli.round() as u32)
}

pub fn select_component<'a>(
  compose: &'a Value,
  target: Option<&str>,
) -> Result<&'a str, ApiError> {
  let names = compose["services"]
    .as_mapping()
    .into_iter()
    .flat_map(|services| services.keys())
    .filter_map(Value::as_str)
    .collect::<Vec<_>>();
  match target {
    Some(name) => names
      .iter()
      .copied()
      .find(|value| *value == name)
      .ok_or_else(|| {
        ApiError::invalid(format!("Compose 中没有组件 {name}"))
          .with_hint(format!("可选组件：{}", names.join("、")))
      }),
    None if let [name] = names.as_slice() => Ok(name),
    None => Err(ApiError::invalid("请选择 Compose 组件").with_hint(
      format!("--container 可选组件：{}", names.join("、")),
    )),
  }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct LimitView<'a> {
  pub service: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub container: Option<&'a str>,
  pub limits: Option<Limits>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub effective: Option<EffectiveLimits>,
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct EffectiveLimits {
  pub memory_bytes: Option<u64>,
  pub cpu_milli: Option<u32>,
  pub pids: Option<u32>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn limit_edits_keep_other_dimensions() {
    let old = Limits {
      memory_mb: Some(512),
      cpu_milli: Some(500),
      pids: None,
    };
    let updated = LimitEdits {
      cpus: Some(0.75),
      pids: Some(128),
      ..Default::default()
    }
    .apply(Some(old))
    .unwrap()
    .unwrap();
    assert_eq!(
      (updated.memory_mb, updated.cpu_milli, updated.pids),
      (Some(512), Some(750), Some(128))
    );
  }
}
