async fn login(
  url: String,
  core_key: String,
  j: bool,
) -> CliResult<()> {
  crate::tunnel::parse_core_key(&core_key)?;
  let token = read_secret("API token：")?;
  let c = Client::with_key(
    Some(url.clone()),
    Some(token.clone()),
    Some(core_key.clone()),
  )?;
  // 验证一下能用。
  let _: Vec<ServerView> = c.get("/api/servers").await?;
  let path = Config {
    url: Some(url.trim_end_matches('/').to_string()),
    token: Some(token),
    core_key: Some(core_key.trim().to_string()),
  }
  .save()?;
  if j {
    print::json(&json!({ "saved": path }));
  } else {
    println!("已保存到 {}", path.display());
  }
  Ok(())
}

fn schema(resource: Option<&str>) -> CliResult<()> {
  if resource == Some("web") {
    print::json(&wharf_api_types::web_schema::web_schema());
    return Ok(());
  }
  use schemars::schema_for;
  use wharf_api_types::{plan, spec, view};
  let all: Vec<(&str, schemars::Schema)> = vec![
    ("fleet", schema_for!(spec::Fleet)),
    ("server", schema_for!(spec::ServerSettings)),
    ("service", schema_for!(spec::ServiceSpec)),
    ("gateway", schema_for!(spec::GatewaySpec)),
    ("route", schema_for!(spec::RouteSpec)),
    ("change", schema_for!(spec::Change)),
    ("plan", schema_for!(plan::Plan)),
    ("run", schema_for!(plan::Run)),
    ("status", schema_for!(view::Status)),
    ("error", schema_for!(ApiError)),
  ];
  match resource {
    None => {
      let map: BTreeMap<&str, &schemars::Schema> =
        all.iter().map(|(k, v)| (*k, v)).collect();
      print::json(&map);
    }
    Some(name) => {
      let found =
        all.iter().find(|(k, _)| *k == name).ok_or_else(|| {
          let names: Vec<&str> =
            all.iter().map(|(k, _)| *k).collect();
          ApiError::invalid(format!(
            "没有 {name}，可选：{}",
            names.join("、")
          ))
        })?;
      print::json(&found.1);
    }
  }
  Ok(())
}

// PLAN / APPLY

async fn plan_and_maybe_apply(
  c: &Client,
  req: PlanRequest,
  flags: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  let req = PlanRequest {
    note: flags.note.clone().or(req.note),
    ..req
  };
  let plan: Plan = c.post("/api/plan", &req).await?;
  if !flags.apply || plan.items.is_empty() {
    out(j, &plan, print::plan);
    return Ok(());
  }
  let missing: Vec<&String> = plan
    .needs_confirm
    .iter()
    .filter(|a| !flags.confirm.contains(a))
    .collect();
  if !missing.is_empty() {
    if !j {
      print::plan(&plan);
    }
    let flags: String =
      missing.iter().map(|a| format!(" --confirm {a}")).collect();
    let mut err = ApiError::new(
      ErrorCode::ConfirmRequired,
      format!(
        "计划里有高风险项，需要确认：{}",
        missing
          .iter()
          .map(|s| s.as_str())
          .collect::<Vec<_>>()
          .join("、")
      ),
    )
    .suggest(format!("wharf apply {}{flags}", plan.plan_id));
    if j {
      err = err.with_hint(format!("plan_id = {}", plan.plan_id));
    }
    return Err(err.into());
  }
  if !j {
    print::plan_with(&plan, false);
  }
  apply(c, &plan.plan_id, flags.confirm, true, j, Some(plan.clone()))
    .await
}

async fn apply(
  c: &Client,
  plan_id: &str,
  confirm: Vec<String>,
  wait: bool,
  j: bool,
  plan: Option<Plan>,
) -> CliResult<()> {
  let resp: ApplyResponse = c
    .post(
      "/api/apply",
      &ApplyRequest {
        plan_id: plan_id.to_string(),
        confirm,
      },
    )
    .await?;
  if !wait {
    out(j, &resp, |r| {
      println!(
        "已开始执行 {}。查看：wharf run show {}",
        r.run_id, r.run_id
      )
    });
    return Ok(());
  }
  let run = wait_run(c, &resp.run_id, j).await?;
  if j {
    match plan {
      Some(plan) => print::json(&json!({ "plan": plan, "run": run })),
      None => print::json(&run),
    }
  } else {
    print::run_summary(&run);
  }
  match run.status {
    RunStatus::Succeeded => Ok(()),
    _ => Err(CliError::Exit(4)),
  }
}

/// 轮询直到执行结束。人看的模式下边执行边打印步骤和日志。
/// Ctrl-C 只停止等待，不取消执行。
async fn wait_run(
  c: &Client,
  run_id: &str,
  j: bool,
) -> CliResult<Run> {
  let mut printed: Vec<(usize, bool)> = Vec::new();
  let path = format!("/api/runs/{}", seg(run_id));
  loop {
    let run: Run = tokio::select! {
      r = c.get(&path) => r?,
      _ = tokio::signal::ctrl_c() => {
        eprintln!("\n已停止等待，执行仍在继续。取消：wharf run cancel {run_id}");
        return Err(CliError::Exit(130));
      }
    };
    if !j {
      printed.resize(run.steps.len(), (0, false));
      for (i, step) in run.steps.iter().enumerate() {
        let (lines, finished) = &mut printed[i];
        let started = !matches!(
          step.status,
          wharf_api_types::plan::StepStatus::Pending
        );
        if !started {
          continue;
        }
        for line in step.log.iter().skip(*lines) {
          println!("    {line}");
        }
        *lines = step.log.len().max(*lines);
        if step_done(step) && !*finished {
          print::step_line(step);
          *finished = true;
        }
      }
    }
    if run.status.finished() {
      return Ok(run);
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
  }
}

fn step_done(step: &wharf_api_types::plan::RunStep) -> bool {
  use wharf_api_types::plan::StepStatus::*;
  matches!(step.status, Done | Failed | Skipped)
}

async fn run_cmd(c: &Client, cmd: RunCmd, j: bool) -> CliResult<()> {
  match cmd {
    RunCmd::List { limit } => {
      let runs: Vec<Run> =
        c.get(&format!("/api/runs?limit={limit}")).await?;
      out(j, &runs, |runs| {
        for r in runs {
          print::run_line(r);
        }
      });
      Ok(())
    }
    RunCmd::Show { run_id } => {
      let run: Run =
        c.get(&format!("/api/runs/{}", seg(&run_id))).await?;
      out(j, &run, print::run);
      Ok(())
    }
    RunCmd::Wait { run_id } => {
      let run = wait_run(c, &run_id, j).await?;
      out(j, &run, print::run_summary);
      match run.status {
        RunStatus::Succeeded => Ok(()),
        _ => Err(CliError::Exit(4)),
      }
    }
    RunCmd::Cancel { run_id } => {
      let v: Value = c
        .post(
          &format!("/api/runs/{}/cancel", seg(&run_id)),
          &json!({}),
        )
        .await?;
      out(j, &v, |_| println!("正在取消 {run_id}"));
      Ok(())
    }
  }
}

pub(crate) async fn changes(
  c: &Client,
  changes: Vec<Change>,
  flags: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  plan_and_maybe_apply(
    c,
    PlanRequest {
      changes,
      ..Default::default()
    },
    flags,
    j,
  )
  .await
}

async fn host_exec(
  c: &Client,
  server: String,
  timeout: Option<u64>,
  cwd: Option<String>,
  command: String,
  j: bool,
) -> CliResult<()> {
  let timeout = timeout.unwrap_or(30);
  let body = json!({
    "command": command,
    "timeout_secs": timeout,
    "cwd": cwd,
  });
  enum Wait {
    Done(CliResult<HostExecResponse>),
    Interrupted,
  }
  let path = format!("/api/servers/{}/exec", seg(&server));
  let wait = {
    let request = c.post_timeout(
      &path,
      &body,
      Duration::from_secs(timeout.saturating_add(45)),
    );
    tokio::pin!(request);
    tokio::select! {
      result = &mut request => Wait::Done(result),
      _ = tokio::signal::ctrl_c() => Wait::Interrupted,
    }
  };
  let result = match wait {
    Wait::Done(result) => result?,
    Wait::Interrupted => {
      if !j {
        eprintln!("\n正在取消，等待远端清理…");
      }
      // 关闭 HTTP 请求会触发控制面取消；agent 的独立清理预算是 10 秒。
      tokio::time::sleep(Duration::from_secs(20)).await;
      return Err(CliError::Exit(130));
    }
  };
  if j {
    print::json(&result);
  } else {
    std::io::stdout()
      .write_all(result.stdout.as_bytes())
      .map_err(anyhow::Error::from)?;
    std::io::stderr()
      .write_all(result.stderr.as_bytes())
      .map_err(anyhow::Error::from)?;
    if result.truncated {
      eprintln!("\n[输出已截断]");
    }
  }
  if result.exit_code == 0 {
    Ok(())
  } else {
    Err(CliError::Exit(result.exit_code))
  }
}

async fn shell_log(
  c: &Client,
  server: Option<String>,
  limit: u32,
  j: bool,
) -> CliResult<()> {
  let mut path = format!("/api/shell-log?limit={limit}");
  if let Some(server) = server {
    path.push_str("&server=");
    path.push_str(&seg(&server));
  }
  let rows: Vec<ShellLog> = c.get(&path).await?;
  out(j, &rows, |rows| {
    for row in rows {
      let at = row
        .at
        .with_timezone(&chrono::Local)
        .format("%m-%d %H:%M:%S");
      let kind = if row.kind == "terminal" {
        "终端"
      } else {
        "命令"
      };
      let result = match (&row.error, row.exit_code) {
        (Some(error), _) => error.clone(),
        (None, Some(code)) => format!("退出 {code}"),
        _ => "进行中".into(),
      };
      let duration = row
        .duration_ms
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_default();
      let command = row
        .command
        .as_deref()
        .map(command_summary)
        .unwrap_or_default();
      println!(
        "{at}  {:<12} {:<10} {:<4} {:<12} {:>8}{}{}",
        row.actor,
        row.server,
        kind,
        result,
        duration,
        if command.is_empty() { "" } else { "  " },
        command,
      );
    }
  });
  Ok(())
}

fn command_summary(command: &str) -> String {
  command
    .chars()
    .flat_map(char::escape_default)
    .take(100)
    .collect()
}

fn parse_kv(s: &str, what: &str) -> CliResult<(String, String)> {
  s.split_once('=')
    .map(|(k, v)| (k.trim().to_string(), v.to_string()))
    .filter(|(k, _)| !k.is_empty())
    .ok_or_else(|| {
      ApiError::invalid(format!("{what} {s} 格式不对，应为 名字=值"))
        .into()
    })
}

fn parse_port(s: &str) -> CliResult<PortSpec> {
  let (name, value) = parse_kv(s, "--port")?;
  let bad = || {
    ApiError::invalid(format!(
      "--port {s} 格式不对，应为 http=80、http=80:20080，compose 来源写 http=:41773、UDP 写 game=27015/udp"
    ))
  };
  let udp = value.ends_with("/udp");
  let value = value.strip_suffix("/udp").unwrap_or(&value);
  let (port, host) = match value.split_once(':') {
    Some((p, h)) => (p, Some(h)),
    None => (value, None),
  };
  // compose 来源只有宿主机端口，写成 `http=:41773`。
  let container = match port.trim() {
    "" => None,
    p => Some(p.parse().map_err(|_| bad())?),
  };
  Ok(PortSpec {
    udp,
    name,
    container,
    host: host
      .map(|h| h.trim().parse())
      .transpose()
      .map_err(|_| bad())?,
  })
}

async fn discover_service(
  c: &Client,
  server: String,
  j: bool,
) -> CliResult<()> {
  let v: Vec<Unmanaged> = c
    .get(&format!("/api/servers/{}/unmanaged", seg(&server)))
    .await?;
  out(j, &v, |v| {
    if v.is_empty() {
      println!("{server} 上没有未纳管的容器");
    }
    for u in v {
      let (kind, what) = match (&u.project, &u.container) {
        (Some(p), _) => ("--project", p.as_str()),
        (_, Some(c)) => ("--container", c.as_str()),
        _ => continue,
      };
      let ignored = if u.ignored { "（已忽略）" } else { "" };
      println!("{kind} {what}{ignored}");
      for c in &u.containers {
        println!("    {:<24} {:<10} {}", c.name, c.state, c.image);
      }
    }
  });
  Ok(())
}
