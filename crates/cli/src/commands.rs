//! 各子命令的实现。

use std::{collections::BTreeMap, time::Duration};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::UpgradeResult,
  plan::{
    ApplyRequest, ApplyResponse, Plan, PlanRequest, Run, RunStatus,
  },
  spec::{
    BackupSpec, Change, Fleet, GatewayKind, GatewaySpec, GatewayTls,
    PathRoute, PortSpec, PrivateAddr, PrivateNetwork, Region,
    RouteSpec, ServerSettings, ServiceSpec, Source, VolumeSpec,
  },
  view::{
    AccountView, BackupsView, CreatedToken, DeploymentView,
    GatewayView, ImportPreview, ImportRequest, JoinInfo, NetworkView,
    RestoreRequest, RollbackTarget, RouteView, SecretView,
    ServerView, ServiceView, Status, TokenView, Unmanaged,
  },
};

use crate::{
  AccountCmd, ApplyFlags, BackupCmd, BuildArgs, Cli, Command,
  GatewayCmd, RouteCmd, RunCmd, SecretCmd, ServerCmd, ServiceCmd,
  TokenCmd,
  client::{CliError, CliResult, Client, Config, read_secret, seg},
  fleet, print,
};

pub async fn run(cli: Cli) -> CliResult<()> {
  let j = cli.json;
  match cli.command {
    Command::Login { url } => login(url, j).await,
    Command::Schema { resource } => schema(resource.as_deref()),
    command => {
      let c = Client::new(cli.url, cli.token)?;
      dispatch(&c, command, j).await
    }
  }
}

/// 输出：JSON 模式原样输出，否则用 `human`。
pub(crate) fn out<T: serde::Serialize>(
  j: bool,
  value: &T,
  human: impl FnOnce(&T),
) {
  if j {
    print::json(value);
  } else {
    human(value);
  }
}

pub(crate) fn pretty<T: serde::Serialize>(value: &T) {
  print::json(value);
}

async fn dispatch(
  c: &Client,
  command: Command,
  j: bool,
) -> CliResult<()> {
  match command {
    Command::Login { .. } | Command::Schema { .. } => unreachable!(),
    Command::Status => {
      let s: Status = c.get("/api/status").await?;
      out(j, &s, print::status);
      Ok(())
    }
    Command::Deploy {
      dir,
      name,
      server,
      port,
      env,
      build,
      apply,
    } => {
      let name = match name {
        Some(n) => n,
        None => dir_name(&dir)?,
      };
      let cmd = ServiceCmd::Deploy {
        name,
        image: None,
        compose: None,
        server,
        port,
        env,
        unset_env: vec![],
        volume: vec![],
        build: BuildArgs {
          dir: Some(dir),
          opts: build,
          ..Default::default()
        },
        apply,
      };
      service(c, cmd, j).await
    }
    Command::Upgrade => upgrade(c, j).await,
    Command::Network { probe } => {
      let v: NetworkView = if probe {
        c.post("/api/network/probe", &json!({})).await?
      } else {
        c.get("/api/network").await?
      };
      out(j, &v, print::network);
      Ok(())
    }
    Command::Server(cmd) => server(c, cmd, j).await,
    Command::Service(cmd) => service(c, cmd, j).await,
    Command::Gateway(cmd) => gateway(c, cmd, j).await,
    Command::Route(cmd) => route(c, cmd, j).await,
    Command::Account(cmd) => account(c, cmd, j).await,
    Command::Secret(cmd) => secret(c, cmd, j).await,
    Command::Backup(cmd) => backup(c, cmd, j).await,
    Command::Edge(cmd) => crate::edge::edge(c, cmd, j).await,
    Command::Plan { file, apply } => {
      let req = match file {
        Some(path) => PlanRequest {
          changes: vec![],
          fleet: Some(fleet::load(&path)?),
        },
        None => PlanRequest::default(),
      };
      plan_and_maybe_apply(c, req, apply, j).await
    }
    Command::Apply {
      plan_id,
      confirm,
      no_wait,
    } => apply(c, &plan_id, confirm, !no_wait, j, None).await,
    Command::Run(cmd) => run_cmd(c, cmd, j).await,
    Command::Export { output } => {
      let fleet: Fleet = c.get("/api/export").await?;
      let text = fleet::to_toml(&fleet)?;
      match output {
        Some(path) => {
          std::fs::write(&path, text).map_err(|e| {
            ApiError::invalid(format!("写入 {}：{e}", path.display()))
          })?;
          if j {
            print::json(&json!({ "written": path }));
          } else {
            println!("已写入 {}", path.display());
          }
        }
        None if j => print::json(&fleet),
        None => print!("{text}"),
      }
      Ok(())
    }
    Command::Token(cmd) => token(c, cmd, j).await,
  }
}

async fn login(url: String, j: bool) -> CliResult<()> {
  let token = read_secret("API token：")?;
  let c = Client::new(Some(url.clone()), Some(token.clone()))?;
  // 验证一下能用。
  let _: Vec<ServerView> = c.get("/api/servers").await?;
  let path = Config {
    url: Some(url.trim_end_matches('/').to_string()),
    token: Some(token),
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
          print::run_summary(r);
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
      fleet: None,
    },
    flags,
    j,
  )
  .await
}

// SERVERS

async fn server(
  c: &Client,
  cmd: ServerCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    ServerCmd::List => {
      let v: Vec<ServerView> = c.get("/api/servers").await?;
      out(j, &v, |v| {
        for s in v {
          println!(
            "{:<10} {}  公网 {}{}",
            s.name,
            if !s.joined {
              "未加入"
            } else if s.online {
              "在线"
            } else {
              "离线"
            },
            s.public_ip.as_deref().unwrap_or("-"),
            if s.agent_outdated {
              "  agent 可升级"
            } else {
              ""
            }
          );
        }
      });
      Ok(())
    }
    ServerCmd::Show { name } => {
      let v: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      out(j, &v, pretty);
      Ok(())
    }
    ServerCmd::Add {
      name,
      rejoin,
      core_url,
      agent_image,
    } => {
      let v: JoinInfo = c
        .post(
          "/api/servers",
          &json!({
            "name": name,
            "rejoin": rejoin,
            "core_url": core_url,
            "agent_image": agent_image,
          }),
        )
        .await?;
      out(j, &v, |v| {
        println!(
          "已登记服务器 {}。在这台机器上执行下面任一命令加入（凭据 {} 前有效，只能用一次）：",
          v.server,
          v.expires_at
            .with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
        );
        for (kind, cmd) in &v.commands {
          println!("\n[{kind}]\n{cmd}");
        }
      });
      Ok(())
    }
    ServerCmd::Set {
      name,
      region,
      public_ip,
      mirror,
      clear_mirrors,
      mirrors_only,
      private_ip,
      network,
      build_env,
      clear_build_env,
      apply,
    } => {
      let current: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      let mut settings: ServerSettings = current.settings;
      if let Some(region) = region {
        settings.region = Some(if region == "cn" {
          Region::Cn
        } else {
          Region::Overseas
        });
      }
      if let Some(ip) = public_ip {
        settings.public_ip =
          (!ip.trim().is_empty()).then(|| ip.trim().to_string());
      }
      if clear_mirrors {
        settings.registry_mirrors.clear();
      }
      for m in mirror {
        let (registry, list) =
          m.split_once('=').ok_or_else(|| {
            ApiError::invalid(format!(
              "--mirror {m} 格式不对，应为 docker.io=镜像源1,镜像源2"
            ))
          })?;
        let list: Vec<String> = list
          .split(',')
          .map(str::trim)
          .filter(|s| !s.is_empty())
          .map(str::to_string)
          .collect();
        if list.is_empty() {
          settings.registry_mirrors.remove(registry.trim());
        } else {
          settings
            .registry_mirrors
            .insert(registry.trim().to_string(), list);
        }
      }
      if let Some(only) = mirrors_only {
        settings.mirrors_only = only;
      }
      if clear_build_env {
        settings.build_env.clear();
      }
      for e in &build_env {
        let (k, v) = parse_kv(e, "--build-env")?;
        if v.is_empty() {
          settings.build_env.remove(&k);
        } else {
          settings.build_env.insert(k, v);
        }
      }
      if let Some(ip) = private_ip {
        let ip = ip.trim();
        settings.private_addr = if ip.is_empty() {
          None
        } else {
          ip.parse::<std::net::IpAddr>().map_err(|_| {
            ApiError::invalid(format!(
              "--private-ip {ip} 不是 IP 地址"
            ))
          })?;
          Some(PrivateAddr {
            ip: ip.to_string(),
            network: if network == "overlay" {
              PrivateNetwork::Overlay
            } else {
              PrivateNetwork::Lan
            },
          })
        };
      }
      changes(
        c,
        vec![Change::UpdateServer { name, settings }],
        apply,
        j,
      )
      .await
    }
    ServerCmd::Rm { name } => {
      let v: Value =
        c.delete(&format!("/api/servers/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除服务器 {name}"));
      Ok(())
    }
    ServerCmd::Upgrade { name, all } => {
      let names = match (name, all) {
        (Some(name), _) => vec![name],
        (None, true) => {
          let v: Vec<ServerView> = c.get("/api/servers").await?;
          v.into_iter()
            .filter(|s| s.agent_outdated)
            .map(|s| s.name)
            .collect()
        }
        (None, false) => {
          return Err(
            ApiError::invalid("给出服务器名，或者用 --all")
              .suggest("wharf server upgrade --all")
              .into(),
          );
        }
      };
      upgrade_agents(c, names, j).await
    }
  }
}

async fn upgrade_agents(
  c: &Client,
  names: Vec<String>,
  j: bool,
) -> CliResult<()> {
  if names.is_empty() {
    out(j, &json!([]), |_| println!("全部 agent 都是最新版本"));
  }
  for name in names {
    let r: ApplyResponse = c
      .post(
        &format!("/api/servers/{}/upgrade", seg(&name)),
        &json!({}),
      )
      .await?;
    finish_task(c, &r.run_id, true, j).await?;
  }
  Ok(())
}

/// 控制面重启后，等它带着新构建号回来、agent 重新连上。
const CORE_RESTART_WAIT: Duration = Duration::from_secs(150);
const AGENT_RECONNECT_WAIT: Duration = Duration::from_secs(60);

async fn upgrade(c: &Client, j: bool) -> CliResult<()> {
  let before: Value = c.get("/api/version").await?;
  let r: UpgradeResult = c.post("/api/upgrade", &json!({})).await?;
  if !r.started {
    if !j {
      println!("控制面已经是最新版本");
    }
  } else {
    if !j {
      println!("控制面正在换成 {}", r.image);
    }
    let deadline = tokio::time::Instant::now() + CORE_RESTART_WAIT;
    loop {
      tokio::time::sleep(Duration::from_secs(3)).await;
      // 重启期间连不上是正常的。
      if let Ok(v) = c.get::<Value>("/api/version").await
        && v["build"] != before["build"]
      {
        if !j {
          println!(
            "控制面已换成构建 {}",
            v["build"].as_str().unwrap_or_default()
          );
        }
        break;
      }
      if tokio::time::Instant::now() > deadline {
        return Err(
          ApiError::new(ErrorCode::AgentFailed, "控制面没有换成新版本")
            .with_hint("接班容器会恢复旧的控制面；在控制面所在的机器上 docker logs wharf-agent-upgrade 查看原因")
            .into(),
        );
      }
    }
  }
  // agent 断线重连要几秒，最多等一分钟；还没连上的这次跳过。
  let deadline = tokio::time::Instant::now() + AGENT_RECONNECT_WAIT;
  let servers = loop {
    let v: Vec<ServerView> = c.get("/api/servers").await?;
    if !r.started
      || v.iter().all(|s| s.online)
      || tokio::time::Instant::now() > deadline
    {
      break v;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
  };
  for s in servers.iter().filter(|s| !s.online) {
    eprintln!("{} 不在线，跳过", s.name);
  }
  let names = servers
    .into_iter()
    .filter(|s| s.online && s.agent_outdated)
    .map(|s| s.name)
    .collect();
  upgrade_agents(c, names, j).await
}

// SERVICES

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
      "--port {s} 格式不对，应为 http=80 或 http=80:20080"
    ))
  };
  let (port, host) = match value.split_once(':') {
    Some((p, h)) => (p, Some(h)),
    None => (value.as_str(), None),
  };
  Ok(PortSpec {
    name,
    port: port.trim().parse().map_err(|_| bad())?,
    host_port: host
      .map(|h| h.trim().parse())
      .transpose()
      .map_err(|_| bad())?,
  })
}

async fn service(
  c: &Client,
  cmd: ServiceCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    ServiceCmd::List => {
      let v: Vec<ServiceView> = c.get("/api/services").await?;
      out(j, &v, |v| {
        for s in v {
          println!(
            "{:<14} {:<8} {}",
            s.name,
            s.spec.server,
            s.live.as_ref().map(|l| l.state.as_str()).unwrap_or("-")
          );
        }
      });
      Ok(())
    }
    ServiceCmd::Show { name } => {
      let v: ServiceView =
        c.get(&format!("/api/services/{}", seg(&name))).await?;
      out(j, &v, pretty);
      Ok(())
    }
    ServiceCmd::Logs {
      name,
      tail,
      follow: true,
    } => {
      use std::io::Write;
      let mut stdout = std::io::stdout();
      c.follow(
        &format!(
          "/api/services/{}/logs/stream?tail={tail}",
          seg(&name)
        ),
        |chunk| {
          let _ = stdout.write_all(chunk);
          let _ = stdout.flush();
        },
      )
      .await
    }
    ServiceCmd::Discover { server } => {
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
          println!("{kind} {what}");
          for c in &u.containers {
            println!(
              "    {:<24} {:<10} {}",
              c.name, c.state, c.image
            );
          }
        }
      });
      Ok(())
    }
    ServiceCmd::Import {
      server,
      project,
      container,
      name,
      print,
      apply,
    } => {
      let v: ImportPreview = c
        .post(
          "/api/import",
          &ImportRequest {
            server,
            project,
            container,
            name,
          },
        )
        .await?;
      if !j {
        println!("导入为服务 {}", v.name);
        for w in &v.warnings {
          println!("  提醒：{w}");
        }
        if print
          && let Source::Compose {
            content: Some(c), ..
          } = &v.spec.source
        {
          println!("{c}");
        }
      }
      changes(
        c,
        vec![Change::UpsertService {
          name: v.name,
          spec: v.spec,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Rollback { name, to, apply } => {
      let path = match to {
        Some(id) => {
          format!("/api/services/{}/rollback?to={id}", seg(&name))
        }
        None => format!("/api/services/{}/rollback", seg(&name)),
      };
      let target: RollbackTarget = c.get(&path).await?;
      if !j {
        println!(
          "回滚 {name} 到部署 #{}（{}）",
          target.deployment_id,
          target
            .deployed_at
            .with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
        );
      }
      changes(
        c,
        vec![Change::UpsertService {
          name,
          spec: target.spec,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Logs {
      name,
      tail,
      follow: false,
    } => {
      let v: Value = c
        .get(&format!(
          "/api/services/{}/logs?tail={tail}",
          seg(&name)
        ))
        .await?;
      out(j, &v, |v| {
        print!("{}", v["logs"].as_str().unwrap_or_default())
      });
      Ok(())
    }
    ServiceCmd::History { name } => {
      let v: Vec<DeploymentView> = c
        .get(&format!("/api/services/{}/deployments", seg(&name)))
        .await?;
      out(j, &v, |v| {
        for d in v {
          let images: Vec<String> = d
            .images
            .iter()
            .map(|i| {
              i.digest.clone().unwrap_or_else(|| i.image.clone())
            })
            .collect();
          println!(
            "#{} {} {} {}  {}",
            d.id,
            d.created_at.format("%m-%d %H:%M"),
            d.server,
            d.run_id,
            images.join(" ")
          );
        }
      });
      Ok(())
    }
    ServiceCmd::Deploy {
      name,
      image,
      compose,
      server,
      port,
      env,
      unset_env,
      volume,
      build,
      apply,
    } => {
      let existing = match c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await
      {
        Ok(v) => Some(v.spec),
        Err(CliError::Api(e)) if e.code == ErrorCode::NotFound => {
          None
        }
        Err(e) => return Err(e),
      };
      let first_port = port
        .first()
        .map(|p| parse_port(p))
        .transpose()?
        .map(|p| p.port);
      let built = crate::deploy::source(
        c,
        &name,
        &build,
        existing.as_ref().map(|s| &s.source),
        first_port,
      )
      .await?;
      let default_port = built.as_ref().map(|b| b.default_port);
      let source = match (image, compose, built) {
        (_, _, Some(b)) => Some(b.source),
        (Some(image), _, _) => Some(Source::Image(image)),
        (None, Some(path), _) => Some(Source::Compose {
          content: Some(std::fs::read_to_string(&path).map_err(
            |e| {
              ApiError::invalid(format!(
                "读取 {}：{e}",
                path.display()
              ))
            },
          )?),
          file: None,
        }),
        (None, None, None) => None,
      };
      let is_new = existing.is_none();
      let mut spec = match existing {
        Some(spec) => spec,
        None => {
          let source = source.clone().ok_or_else(|| {
            ApiError::invalid(format!("服务 {name} 不存在，新建时需要 --image、--compose、--dir 或 --git"))
              .suggest(format!("wharf service deploy {name} --image traefik/whoami --port http=80"))
          })?;
          let server = match server.clone() {
            Some(s) => s,
            None => pick_server(c).await?,
          };
          ServiceSpec {
            server,
            source,
            ports: vec![],
            env: BTreeMap::new(),
            volumes: vec![],
            backup: None,
            adopt: None,
          }
        }
      };
      if let Some(source) = source {
        spec.source = source;
      }
      if let Some(server) = server {
        spec.server = server;
      }
      if !port.is_empty() {
        spec.ports = port
          .iter()
          .map(|p| parse_port(p))
          .collect::<CliResult<_>>()?;
      } else if let (true, Some(p)) = (is_new, default_port) {
        spec.ports = vec![PortSpec {
          name: "http".into(),
          port: p,
          host_port: None,
        }];
      }
      for e in &env {
        let (k, v) = parse_kv(e, "--env")?;
        spec.env.insert(k, v);
      }
      for k in &unset_env {
        spec.env.remove(k);
      }
      for v in &volume {
        let (vname, target) = v.split_once(':').ok_or_else(|| {
          ApiError::invalid(format!(
            "--volume {v} 格式不对，应为 data:/data"
          ))
        })?;
        spec.volumes.retain(|x| x.name != vname);
        spec.volumes.push(VolumeSpec {
          name: vname.to_string(),
          target: target.to_string(),
        });
      }
      changes(c, vec![Change::UpsertService { name, spec }], apply, j)
        .await
    }
    ServiceCmd::Move { name, to, apply } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      if spec.server == to {
        return Err(
          ApiError::invalid(format!("服务 {name} 已经在 {to} 上"))
            .into(),
        );
      }
      spec.server = to;
      changes(c, vec![Change::UpsertService { name, spec }], apply, j)
        .await
    }
    ServiceCmd::Rm { name, apply } => {
      changes(c, vec![Change::RemoveService { name }], apply, j).await
    }
    ServiceCmd::Rebuild { name, no_wait } => {
      // 用 gh token 的服务先刷新密钥，gh 重新登录后旧 token 会失效。
      let v: ServiceView =
        c.get(&format!("/api/services/{}", seg(&name))).await?;
      if let Source::Build(b) = &v.spec.source
        && b.git.as_ref().and_then(|g| g.token_secret.as_deref())
          == Some(crate::gh::SECRET)
      {
        crate::gh::refresh(c).await?;
      }
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/rebuild", seg(&name)),
          &json!({}),
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
  }
}

/// 目录名转成服务名：小写，非字母数字换成 `-`。
fn dir_name(dir: &std::path::Path) -> CliResult<String> {
  let abs = std::fs::canonicalize(dir).map_err(|e| {
    ApiError::invalid(format!("{}：{e}", dir.display()))
  })?;
  let raw = abs
    .file_name()
    .map(|n| n.to_string_lossy().to_lowercase())
    .unwrap_or_default();
  let mut name: String = raw
    .chars()
    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
    .collect();
  name = name.trim_matches('-').to_string();
  while name.contains("--") {
    name = name.replace("--", "-");
  }
  name.truncate(48);
  if name.is_empty() {
    return Err(
      ApiError::invalid("从目录名取不出服务名，请用 --name 指定")
        .into(),
    );
  }
  Ok(name)
}

/// 只有一台已加入的服务器时自动选它。
async fn pick_server(c: &Client) -> CliResult<String> {
  let servers: Vec<ServerView> = c.get("/api/servers").await?;
  let joined: Vec<&ServerView> =
    servers.iter().filter(|s| s.joined).collect();
  match joined.as_slice() {
    [only] => Ok(only.name.clone()),
    [] => Err(
      ApiError::invalid("还没有已加入的服务器")
        .suggest("wharf server add <name>")
        .into(),
    ),
    many => Err(
      ApiError::invalid(format!(
        "有多台服务器，请用 --server 指定：{}",
        many
          .iter()
          .map(|s| s.name.as_str())
          .collect::<Vec<_>>()
          .join("、")
      ))
      .into(),
    ),
  }
}

// GATEWAYS / ROUTES

async fn gateway(
  c: &Client,
  cmd: GatewayCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    GatewayCmd::List => {
      let v: Vec<GatewayView> = c.get("/api/gateways").await?;
      out(j, &v, |v| {
        for g in v {
          println!(
            "{:<14} {:<8} {}{}  路由 {}",
            g.name,
            g.spec.server,
            g.spec.kind.as_str(),
            if g.spec.default { "（默认）" } else { "" },
            g.routes.join(" ")
          );
        }
      });
      Ok(())
    }
    GatewayCmd::Show { name } => {
      let v: GatewayView =
        c.get(&format!("/api/gateways/{}", seg(&name))).await?;
      out(j, &v, pretty);
      Ok(())
    }
    GatewayCmd::Config { name } => {
      let v: Value = c
        .get(&format!("/api/gateways/{}/config", seg(&name)))
        .await?;
      out(j, &v, |v| {
        println!(
          "# Caddyfile\n{}",
          v["caddyfile"].as_str().unwrap_or_default()
        );
        println!(
          "# compose.yaml\n{}",
          v["compose"].as_str().unwrap_or_default()
        );
      });
      Ok(())
    }
    GatewayCmd::Logs { name, tail } => {
      let v: Value = c
        .get(&format!(
          "/api/gateways/{}/logs?tail={tail}",
          seg(&name)
        ))
        .await?;
      out(j, &v, |v| {
        print!("{}", v["logs"].as_str().unwrap_or_default())
      });
      Ok(())
    }
    GatewayCmd::Add {
      name,
      server,
      kind,
      account,
      default,
      http_port,
      https_port,
      email,
      image,
      tls,
      apply,
    } => {
      let tls = match tls.as_str() {
        "internal" => GatewayTls::Internal,
        "off" => GatewayTls::Off,
        _ => GatewayTls::Auto,
      };
      let kind = match kind.as_str() {
        "cloudflare_tunnel" => GatewayKind::CloudflareTunnel,
        _ => GatewayKind::Caddy,
      };
      // 隧道网关只有一个厂商账号时自动选它。
      let account = match (kind, account) {
        (GatewayKind::CloudflareTunnel, None) => {
          let accounts: Vec<AccountView> =
            c.get("/api/accounts").await?;
          match accounts.as_slice() {
            [only] => Some(only.name.clone()),
            [] => {
              return Err(
                ApiError::invalid("还没有厂商账号，隧道要建在账号下")
                  .suggest("wharf account add cf --kind cloudflare")
                  .into(),
              );
            }
            _ => {
              return Err(
                ApiError::invalid(
                  "有多个厂商账号，请用 --account 指定",
                )
                .suggest("wharf account list")
                .into(),
              );
            }
          }
        }
        (_, account) => account,
      };
      let spec = GatewaySpec {
        kind,
        server,
        default,
        http_port,
        https_port,
        email,
        image,
        tls,
        account,
      };
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Rm { name, apply } => {
      changes(c, vec![Change::RemoveGateway { name }], apply, j).await
    }
  }
}

async fn route(c: &Client, cmd: RouteCmd, j: bool) -> CliResult<()> {
  match cmd {
    RouteCmd::List => {
      let v: Vec<RouteView> = c.get("/api/routes").await?;
      out(j, &v, |v| {
        for r in v {
          println!(
            "{}  →  {}  经 {}",
            r.url,
            r.spec.upstream.as_deref().unwrap_or(&r.spec.service),
            r.gateway.as_deref().unwrap_or("-")
          );
          for p in &r.spec.paths {
            println!(
              "    {}  →  {}",
              p.path,
              p.upstream
                .as_deref()
                .or(p.service.as_deref())
                .unwrap_or("-")
            );
          }
        }
      });
      Ok(())
    }
    RouteCmd::Add {
      hostname,
      service,
      upstream,
      port,
      gateway,
      auth,
      paths,
      tunnel,
      apply,
    } => {
      let spec = RouteSpec {
        link: if tunnel {
          wharf_api_types::spec::LinkMode::Tunnel
        } else {
          wharf_api_types::spec::LinkMode::Auto
        },
        hostname,
        service: service.unwrap_or_default(),
        upstream,
        port,
        gateway,
        auth,
        paths: paths
          .iter()
          .map(|p| parse_path_route(p))
          .collect::<Result<_, _>>()?,
      };
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Rm { hostname, apply } => {
      changes(c, vec![Change::RemoveRoute { hostname }], apply, j)
        .await
    }
  }
}

/// `/ws=svc`、`/ws=svc:port`、`/ws=127.0.0.1:17891`。目标的主机部分带 `.`、`:` 或是
/// `localhost` 时当作上游地址（服务名里不会有这些）。
fn parse_path_route(arg: &str) -> CliResult<PathRoute> {
  let (path, target) = arg.split_once('=').ok_or_else(|| {
    ApiError::invalid(format!(
      "--path {arg} 要写成 路径=目标，例如 /ws=relay"
    ))
  })?;
  let (host, port) = match target.rsplit_once(':') {
    Some((h, p)) => (h, Some(p)),
    None => (target, None),
  };
  let address =
    host.contains('.') || host.contains(':') || host == "localhost";
  Ok(PathRoute {
    path: path.to_string(),
    service: (!address).then(|| host.to_string()),
    port: if address {
      None
    } else {
      port.map(str::to_string)
    },
    upstream: address.then(|| target.to_string()),
  })
}

// ACCOUNTS / SECRETS / TOKENS

fn print_account(a: &AccountView) {
  println!("{}（{}，token {}）", a.name, a.kind, a.token);
  println!(
    "  zone：{}",
    if a.zones.is_empty() {
      "无".into()
    } else {
      a.zones.join("、")
    }
  );
  for w in &a.warnings {
    println!("  提醒：{w}");
  }
}

async fn account(
  c: &Client,
  cmd: AccountCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    AccountCmd::List => {
      let v: Vec<AccountView> = c.get("/api/accounts").await?;
      out(j, &v, |v| v.iter().for_each(print_account));
      Ok(())
    }
    AccountCmd::Add { name, kind } => {
      let token = read_secret("Cloudflare API token：")?;
      let v: AccountView = c
        .post(
          "/api/accounts",
          &json!({ "name": name, "kind": kind, "token": token }),
        )
        .await?;
      out(j, &v, print_account);
      Ok(())
    }
    AccountCmd::Discover { name } => {
      let v: AccountView = c
        .post(
          &format!("/api/accounts/{}/discover", seg(&name)),
          &json!({}),
        )
        .await?;
      out(j, &v, print_account);
      Ok(())
    }
    AccountCmd::Rm { name } => {
      let v: Value =
        c.delete(&format!("/api/accounts/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除账号 {name}"));
      Ok(())
    }
  }
}

async fn secret(
  c: &Client,
  cmd: SecretCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    SecretCmd::List => {
      let v: Vec<SecretView> = c.get("/api/secrets").await?;
      out(j, &v, |v| v.iter().for_each(|s| println!("{}", s.name)));
      Ok(())
    }
    SecretCmd::Set { name } => {
      let prompt = if name == "BASIC_AUTH" {
        "登录保护账号（用户名:密码）：".to_string()
      } else {
        format!("{name} 的值：")
      };
      let value = read_secret(&prompt)?;
      let v: SecretView = c
        .put(
          &format!("/api/secrets/{}", seg(&name)),
          &json!({ "value": value }),
        )
        .await?;
      out(j, &v, |v| println!("已设置密钥 {}", v.name));
      Ok(())
    }
    SecretCmd::Rm { name } => {
      let v: Value =
        c.delete(&format!("/api/secrets/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除密钥 {name}"));
      Ok(())
    }
  }
}

async fn backup(
  c: &Client,
  cmd: BackupCmd,
  j: bool,
) -> CliResult<()> {
  let set_backup = |name: String, backup: Option<BackupSpec>| async move {
    let mut spec = c
      .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
      .await?
      .spec;
    spec.backup = backup;
    Ok::<_, CliError>(Change::UpsertService { name, spec })
  };
  match cmd {
    BackupCmd::Enable { service, to, apply } => {
      let change =
        set_backup(service, Some(BackupSpec { to })).await?;
      changes(c, vec![change], apply, j).await
    }
    BackupCmd::Disable { service, apply } => {
      let change = set_backup(service, None).await?;
      changes(c, vec![change], apply, j).await
    }
    BackupCmd::Run { service, no_wait } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/backups", seg(&service)),
          &json!({}),
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
    BackupCmd::List { service } => {
      let v: BackupsView = c
        .get(&format!("/api/services/{}/backups", seg(&service)))
        .await?;
      out(j, &v, print::backups);
      Ok(())
    }
    BackupCmd::Restore {
      service,
      snapshot,
      confirm,
      no_wait,
    } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/restore", seg(&service)),
          &RestoreRequest {
            snapshot,
            confirm: confirm.unwrap_or_default(),
          },
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
  }
}

/// 单独发起的执行（备份、恢复）：等它结束，或者只给出 run_id。
pub(crate) async fn finish_task(
  c: &Client,
  run_id: &str,
  wait: bool,
  j: bool,
) -> CliResult<()> {
  if !wait {
    out(j, &json!({ "run_id": run_id }), |_| {
      println!(
        "已开始执行 {run_id}，查看进度：wharf run wait {run_id}"
      )
    });
    return Ok(());
  }
  let run = wait_run(c, run_id, j).await?;
  out(j, &run, print::run_summary);
  match run.status {
    RunStatus::Succeeded => Ok(()),
    _ => Err(CliError::Exit(4)),
  }
}

async fn token(c: &Client, cmd: TokenCmd, j: bool) -> CliResult<()> {
  match cmd {
    TokenCmd::List => {
      let v: Vec<TokenView> = c.get("/api/tokens").await?;
      out(j, &v, |v| {
        for t in v {
          println!("{:<14} {:?}", t.name, t.scope);
        }
      });
      Ok(())
    }
    TokenCmd::Create { name, scope } => {
      let v: CreatedToken = c
        .post("/api/tokens", &json!({ "name": name, "scope": scope }))
        .await?;
      out(j, &v, |v| {
        println!(
          "已创建 token {}（{:?}），只显示这一次：\n{}",
          v.name, v.scope, v.token
        )
      });
      Ok(())
    }
    TokenCmd::Rm { name } => {
      let v: Value =
        c.delete(&format!("/api/tokens/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除 token {name}"));
      Ok(())
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ports() {
    let p = parse_port("http=80").unwrap();
    assert_eq!(
      (p.name.as_str(), p.port, p.host_port),
      ("http", 80, None)
    );
    let p = parse_port("http=80:20080").unwrap();
    assert_eq!(p.host_port, Some(20080));
    assert!(parse_port("http").is_err());
    assert!(parse_port("http=x").is_err());
  }
}
