use super::{
  ApiError, Args, CliResult, Client, ScriptRuntime, TaskKind,
  TaskSpec, TaskView, kind, out, seg,
};
use std::{collections::BTreeMap, io::Read};

#[derive(Args, Default)]
pub struct SetArgs {
  name: String,
  #[arg(long)]
  dry_run: bool,
  #[arg(long)]
  schedule: Option<String>,
  #[arg(long, conflicts_with = "schedule")]
  clear_schedule: bool,
  #[arg(long)]
  server: Option<String>,
  #[arg(long)]
  timeout: Option<u64>,
  #[arg(long)]
  notify: Option<bool>,
  #[arg(long)]
  skip_if_stopped: Option<bool>,
  #[arg(long)]
  catch_up: Option<u32>,
  #[arg(long, conflicts_with = "catch_up")]
  no_catch_up: bool,
  #[arg(long)]
  service: Option<String>,
  #[arg(long)]
  container: Option<String>,
  #[arg(long, conflicts_with = "container")]
  clear_container: bool,
  #[arg(last = true)]
  command: Vec<String>,
  #[arg(long, conflicts_with = "command")]
  clear_command: bool,
  #[arg(long)]
  image: Option<String>,
  #[arg(long, visible_alias = "env")]
  add_env: Vec<String>,
  #[arg(long, visible_alias = "unset-env")]
  rm_env: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_env", "rm_env"])]
  clear_env: bool,
  #[arg(long, visible_alias = "mount")]
  add_mount: Vec<String>,
  #[arg(long, visible_alias = "unset-mount")]
  rm_mount: Vec<String>,
  #[arg(long, conflicts_with_all = ["add_mount", "rm_mount"])]
  clear_mounts: bool,
  #[arg(long)]
  script: Option<String>,
  #[arg(long, value_parser = ["python", "node", "shell"])]
  runtime: Option<String>,
  #[arg(long)]
  script_image: Option<String>,
  #[arg(long, conflicts_with = "script_image")]
  clear_script_image: bool,
  #[arg(long)]
  deps: Option<String>,
  #[arg(long, conflicts_with = "deps")]
  clear_deps: bool,
  #[arg(long)]
  hook: bool,
  #[arg(long, conflicts_with = "hook")]
  no_hook: bool,
  #[arg(long)]
  grace: Option<u32>,
  #[arg(long)]
  artifacts_max_mb: Option<u32>,
  #[arg(long)]
  artifacts_keep: Option<u32>,
  #[arg(long, conflicts_with = "no_use_egress")]
  use_egress: bool,
  #[arg(long)]
  no_use_egress: bool,
}

impl SetArgs {
  fn edits(
    &self,
  ) -> [(bool, &'static str, &'static [&'static str]); 26] {
    [
      (self.schedule.is_some(), "--schedule", &[]),
      (self.use_egress || self.no_use_egress, "--use-egress", &[]),
      (
        self.clear_schedule,
        "--clear-schedule",
        &["脚本", "容器内", "一次性容器", "宿主机"],
      ),
      (self.server.is_some(), "--server", &[]),
      (self.timeout.is_some(), "--timeout", &[]),
      (self.notify.is_some(), "--notify", &[]),
      (
        self.skip_if_stopped.is_some(),
        "--skip-if-stopped",
        &["容器内"],
      ),
      (
        self.catch_up.is_some() || self.no_catch_up,
        "--catch-up/--no-catch-up",
        &[],
      ),
      (self.service.is_some(), "--service", &["容器内"]),
      (
        self.container.is_some() || self.clear_container,
        "--container/--clear-container",
        &["容器内"],
      ),
      (
        !self.command.is_empty(),
        "-- <命令>",
        &["容器内", "宿主机", "一次性容器"],
      ),
      (self.clear_command, "--clear-command", &["一次性容器"]),
      (self.image.is_some(), "--image", &["一次性容器"]),
      (
        !self.add_env.is_empty()
          || !self.rm_env.is_empty()
          || self.clear_env,
        "--add-env/--rm-env/--clear-env",
        &["一次性容器", "脚本"],
      ),
      (
        !self.add_mount.is_empty()
          || !self.rm_mount.is_empty()
          || self.clear_mounts,
        "--add-mount/--rm-mount/--clear-mounts",
        &["一次性容器"],
      ),
      (self.script.is_some(), "--script", &["脚本"]),
      (self.runtime.is_some(), "--runtime", &["脚本"]),
      (self.script_image.is_some(), "--script-image", &["脚本"]),
      (self.clear_script_image, "--clear-script-image", &["脚本"]),
      (self.deps.is_some(), "--deps", &["脚本"]),
      (self.clear_deps, "--clear-deps", &["脚本"]),
      (self.hook, "--hook", &["脚本"]),
      (self.no_hook, "--no-hook", &["脚本"]),
      (self.grace.is_some(), "--grace", &["外部报到"]),
      (
        self.artifacts_max_mb.is_some(),
        "--artifacts-max-mb",
        &["脚本", "一次性容器"],
      ),
      (
        self.artifacts_keep.is_some(),
        "--artifacts-keep",
        &["脚本", "一次性容器"],
      ),
    ]
  }

  fn has_edits(&self) -> bool {
    self.edits().iter().any(|(present, _, _)| *present)
  }
}

pub(super) fn parse_env(
  args: &[String],
) -> Result<BTreeMap<String, String>, ApiError> {
  args
    .iter()
    .map(|item| {
      item
        .split_once('=')
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .ok_or_else(|| ApiError::invalid("环境变量要写成 KEY=VALUE"))
    })
    .collect()
}

fn edit_env(
  env: &mut BTreeMap<String, String>,
  args: &SetArgs,
) -> Result<(), ApiError> {
  if args.clear_env {
    env.clear();
  }
  for key in &args.rm_env {
    env.remove(key);
  }
  env.extend(parse_env(&args.add_env)?);
  Ok(())
}

fn script_text(path: &str) -> Result<String, ApiError> {
  let text = if path == "-" {
    let mut code = String::new();
    std::io::stdin().read_to_string(&mut code).map(|_| code)
  } else {
    std::fs::read_to_string(path)
  };
  text.map_err(|_| ApiError::invalid("读取脚本失败"))
}

fn apply_task_set(
  spec: &mut TaskSpec,
  args: &SetArgs,
) -> Result<(), ApiError> {
  let current = kind(&spec.how);
  for (present, flag, allowed) in args.edits() {
    if present && !allowed.is_empty() && !allowed.contains(&current) {
      return Err(
        ApiError::invalid(format!(
          "当前任务是 {current}，不支持 {flag}"
        ))
        .with_hint("更换任务形式请用 wharf task add"),
      );
    }
  }
  if args.use_egress || args.no_use_egress {
    spec.use_egress = args.use_egress;
  }
  if let Some(server) = &args.server {
    spec.server.clone_from(server);
  }
  if let Some(schedule) = &args.schedule {
    spec.schedule.clone_from(schedule);
  }
  if args.clear_schedule {
    spec.schedule.clear();
  }
  if let Some(timeout) = args.timeout {
    spec.timeout_secs = timeout;
  }
  if let Some(notify) = args.notify {
    spec.notify = notify;
  }
  if let Some(skip) = args.skip_if_stopped {
    spec.skip_if_stopped = skip;
  }
  if args.no_catch_up || args.catch_up.is_some() {
    spec.catch_up_mins = args.catch_up;
  }
  if args.artifacts_max_mb.is_some() {
    spec.artifacts_max_mb = args.artifacts_max_mb;
  }
  if args.artifacts_keep.is_some() {
    spec.artifacts_keep = args.artifacts_keep;
  }
  let new_command = (!args.command.is_empty())
    .then(|| super::shell_join(&args.command));
  match &mut spec.how {
    TaskKind::Exec {
      service,
      container,
      command,
    } => {
      if let Some(value) = &args.service {
        service.clone_from(value);
      }
      if args.clear_container || args.container.is_some() {
        container.clone_from(&args.container);
      }
      if let Some(value) = new_command {
        *command = value;
      }
    }
    TaskKind::Host { command } => {
      if let Some(value) = new_command {
        *command = value;
      }
    }
    TaskKind::Container {
      image,
      command,
      env,
      mounts,
    } => {
      if let Some(value) = &args.image {
        image.clone_from(value);
      }
      if args.clear_command || new_command.is_some() {
        *command = new_command;
      }
      edit_env(env, args)?;
      if args.clear_mounts {
        mounts.clear();
      }
      mounts.retain(|m| !args.rm_mount.contains(m));
      for mount in &args.add_mount {
        if !mounts.contains(mount) {
          mounts.push(mount.clone());
        }
      }
    }
    TaskKind::Script {
      runtime,
      code,
      deps,
      image,
      env,
      hook,
    } => {
      if let Some(path) = &args.script {
        *code = script_text(path)?;
      }
      if let Some(value) = &args.runtime {
        *runtime = match value.as_str() {
          "python" => ScriptRuntime::Python,
          "node" => ScriptRuntime::Node,
          _ => ScriptRuntime::Shell,
        };
      }
      if args.clear_script_image || args.script_image.is_some() {
        image.clone_from(&args.script_image);
      }
      if let Some(path) = &args.deps {
        *deps = std::fs::read_to_string(path)
          .map_err(|_| ApiError::invalid("读取依赖清单失败"))?;
      }
      if args.clear_deps {
        deps.clear();
      }
      if args.no_hook {
        *hook = None;
      }
      if args.hook {
        hook.get_or_insert_with(String::new);
      }
      edit_env(env, args)?;
    }
    TaskKind::Ping { grace_mins, .. } => {
      if let Some(grace) = args.grace {
        *grace_mins = grace;
      }
    }
  }
  Ok(())
}

pub(super) async fn set(
  c: &Client,
  args: SetArgs,
  j: bool,
) -> CliResult<()> {
  let has_edits = args.has_edits();
  if !has_edits && args.dry_run {
    return Err(ApiError::invalid("--dry-run 需要修改参数").into());
  }
  let path = format!("/api/tasks/{}", seg(&args.name));
  let task: TaskView = c.get(&path).await?;
  if !has_edits {
    super::show(&task, false, j);
    if !j {
      println!(
        "提示：不带参数为只读查看。修改示例：wharf task set {} --timeout 300",
        args.name
      );
    }
    return Ok(());
  }
  let mut spec = task.spec.clone();
  apply_task_set(&mut spec, &args)?;
  save(c, &path, &args.name, &task.spec, &spec, args.dry_run, j).await
}

pub(super) async fn toggle(
  c: &Client,
  name: &str,
  enabled: bool,
  dry_run: bool,
  j: bool,
) -> CliResult<()> {
  let path = format!("/api/tasks/{}", seg(name));
  let task: TaskView = c.get(&path).await?;
  let spec = TaskSpec {
    enabled,
    ..task.spec.clone()
  };
  if spec.enabled == task.spec.enabled && !dry_run {
    out(j, &spec, |_| {
      println!(
        "定时任务 {name} 已{}",
        if enabled { "启用" } else { "停用" }
      )
    });
    return Ok(());
  }
  save(c, &path, name, &task.spec, &spec, dry_run, j).await
}

async fn save(
  c: &Client,
  path: &str,
  name: &str,
  before: &TaskSpec,
  after: &TaskSpec,
  dry_run: bool,
  j: bool,
) -> CliResult<()> {
  if dry_run {
    return crate::preview::show(
      j,
      &format!("task/{name}"),
      &serde_json::json!(before),
      &serde_json::json!(after),
    );
  }
  let spec: TaskSpec = c.put(path, after).await?;
  out(j, &spec, |_| println!("已保存定时任务 {name}"));
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn task_set_preserves_hook_and_catch_up() {
    let mut spec: TaskSpec = serde_json::from_value(serde_json::json!({
      "kind":"script", "runtime":"shell", "code":"true", "server":"s1", "schedule":"0 4 * * *",
      "env":{"A":"1","B":"2"}, "catch_up_mins":30, "hook":""
    })).unwrap();
    assert!(!SetArgs::default().has_edits());
    apply_task_set(
      &mut spec,
      &SetArgs {
        timeout: Some(120),
        add_env: vec!["C=3".into()],
        rm_env: vec!["A".into()],
        ..Default::default()
      },
    )
    .unwrap();
    assert_eq!(spec.timeout_secs, 120);
    assert_eq!(spec.catch_up_mins, Some(30));
    let TaskKind::Script { env, hook, .. } = spec.how else {
      panic!("任务类型变了")
    };
    assert_eq!(
      env,
      parse_env(&["B=2".into(), "C=3".into()]).unwrap()
    );
    assert_eq!(hook.as_deref(), Some(""));
  }
}
