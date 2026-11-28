//! 各子命令的实现。

use std::{collections::BTreeMap, time::Duration};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::UpgradeResult,
  backup::{
    BackupDiffView, BackupKeepResult, BackupLsView, BackupPolicy,
    BackupRetention, BackupRunRequest, validate_backup_excludes,
  },
  plan::{
    ApplyRequest, ApplyResponse, Plan, PlanRequest, Run, RunStatus,
  },
  spec::{
    BackupSpec, Change, Fleet, GatewayKind, GatewaySpec, GatewayTls,
    NetworkMode, PathRoute, PortSpec, PrivateAddr, PrivateNetwork,
    Region, RouteSpec, ServerSettings, ServiceSpec, Source, SsoMode,
    UpdateIgnoreScope, UpdateIgnoreSpec, VolumeSpec, image_repo,
  },
  view::{
    AccountView, AppAccountView, AutoUpdateResult,
    BackupUnlockResult, BackupsView, CheckStatus, DataView,
    DeploymentView, DoctorReport, GatewayView, ImportPreview,
    ImportRequest, JoinInfo, NetworkView, RestoreRequest,
    RollbackTarget, RouteView, ScriptRuntime, SecretView, ServerView,
    ServiceView, ShellLog, SsoStepResult, SsoTestResult, Status,
    Unmanaged,
  },
};

use crate::{
  AccountCmd, AppAccountCmd, ApplyFlags, BackupCmd, BuildArgs, Cli,
  Command, EgressCmd, GatewayCmd, NotifyCmd, RouteCmd, RunCmd,
  SecretCmd, ServerCmd, ServiceCmd,
  client::{CliError, CliResult, Client, Config, read_secret, seg},
  fleet, print,
};

pub(crate) mod entry_protection;
mod list_edits;

pub async fn run(cli: Cli) -> CliResult<()> {
  let j = cli.json;
  match cli.command {
    Command::Login { url, core_key, token_file, token_cmd } => login(url, core_key, token_file, token_cmd, j).await,
    Command::Schema { resource, paths } => crate::schema::run(resource.as_deref(), paths, j),
    Command::Validate { file } => {
      let v = fleet::validate(&file);
      out(j, &v, |v| {
        let list = |k: &str| -> Vec<String> {
          v[k]
            .as_array()
            .map(|a| {
              a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
            })
            .unwrap_or_default()
        };
        for e in list("errors") {
          println!("错误：{e}");
        }
        for w in list("warnings") {
          println!("提醒：{w}");
        }
        if v["ok"] == true {
          println!(
            "{} 没有问题（{}）",
            v["file"].as_str().unwrap_or_default(),
            if v["kind"] == "partial" {
              "局部文件"
            } else {
              "完整状态"
            }
          );
        }
      });
      if v["ok"] == true {
        Ok(())
      } else {
        Err(CliError::Exit(1))
      }
    }
    Command::Commands { changes: true, .. } => {
      crate::selfcmd::command_changes(j)
    }
    Command::Commands { prefix, usable: true, .. } => {
      let c = Client::new(cli.url, cli.token).await?;
      let me = c.get("/api/whoami").await?;
      print::json(&crate::describe::usable(&prefix, &me));
      Ok(())
    }
    Command::Commands { prefix, .. } => {
      let all = crate::describe::commands(&[]);
      crate::selfcmd::save_snapshot(&all);
      // 紧凑输出：全部命令有上百条，省掉缩进能少一半多的字符。
      let output = if prefix.is_empty() { all } else { crate::describe::commands(&prefix) };
      if j {
        print::json(&output);
      } else {
        println!("{output}");
      }
      Ok(())
    }
    Command::Deploy { dir, name, port, add_port, build, detect_only: true, .. } => {
      let name = match name { Some(name) => name, None => dir_name(&dir)? };
      let port = port.first().or_else(|| add_port.first()).map(|p| parse_port(p)).transpose()?.and_then(|p| p.container);
      crate::deploy::detect_only(&dir, &name, &build, port, j)
    }
    Command::Token(cmd) => {
      crate::token::run(cmd, cli.url, cli.token, j).await
    }
    Command::Service(ServiceCmd::Logs { names, container: Some(_), .. }) if names.len() > 1 => {
      Err(ApiError::invalid("--container 只能用于单个服务").into())
    }
    Command::Service(ServiceCmd::Logs { follow: true, .. }) if j => {
      Err(ApiError::invalid("--json 需要一次性输出，跟随日志请去掉 --json 或 --follow").into())
    }
    Command::Service(ServiceCmd::Logs { names, follow: true, .. })
      if names.len() > 1 =>
    {
      Err(ApiError::invalid(
        "多服务合看不支持 -f，用 --since 看最近的日志，或单个服务用 -f",
      ).into())
    }
    command => {
      let c = Client::new(cli.url, cli.token).await?;
      dispatch(&c, command, j).await
    }
  }
}

async fn rotate_core_key(
  c: &Client,
  window_hours: Option<u16>,
  force: bool,
  commit: bool,
  rollback: bool,
  j: bool,
) -> CliResult<()> {
  use wharf_api_types::view::CoreKeyView;

  let mut config = crate::client::Config::load_checked()?;
  let env_key = std::env::var_os("WHARF_CORE_KEY").is_some();
  let same_server =
    config.url.as_deref().is_some_and(|url| c.is_for(url));
  if !commit && !env_key {
    if !same_server {
      return Err(
        ApiError::invalid("当前 CLI 配置不属于目标控制面")
          .with_hint("先执行 wharf login 保存目标控制面的配置")
          .into(),
      );
    }
    config.check_writable().map_err(|_| {
      ApiError::invalid("无法写入本机 config.toml")
        .with_hint("检查配置文件及目录权限后重试")
    })?;
  }
  let view: CoreKeyView = if commit {
    c.post("/api/core/key/commit", &json!({})).await?
  } else if rollback {
    c.post("/api/core/key/rollback", &json!({})).await?
  } else {
    c.post("/api/core/key/rotate", &json!({
      "window_hours": window_hours, "force": force, "client_ready": true,
    })).await?
  };
  if !commit {
    if env_key {
      eprintln!("请把 WHARF_CORE_KEY 更新为 {}", view.public_key);
    } else {
      config.core_key = Some(view.public_key.clone());
      config.save().map_err(|_| {
        ApiError::internal("控制面已切换公钥，本机配置保存失败")
          .with_hint(format!(
            "把 config.toml 的 core_key 更新为 {}",
            view.public_key
          ))
      })?;
      eprintln!("已更新本机控制面公钥");
    }
  }
  if !view.pending_agents.is_empty() {
    eprintln!(
      "警告：以下 agent 尚未用新公钥上线：{}",
      view.pending_agents.join("、"),
    );
  }
  out(j, &view, pretty);
  Ok(())
}

/// 输出：JSON 模式原样输出，否则用 `human`。
pub(crate) fn out<T: serde::Serialize>(
  j: bool,
  value: &T,
  human: impl FnOnce(&T),
) {
  if j {
    print::json(value);
  } else if print::is_quiet() {
    print::quiet_output(value);
  } else {
    human(value);
  }
}

pub(crate) fn pretty<T: serde::Serialize>(value: &T) {
  if print::is_quiet() {
    print::quiet_output(value);
  } else {
    print::json(value);
  }
}

fn out_quiet<T: serde::Serialize>(
  j: bool,
  value: &T,
  keys: impl FnOnce(&T) -> Vec<String>,
  human: impl FnOnce(&T),
) {
  if print::is_quiet() {
    for key in keys(value) {
      println!("{key}");
    }
  } else {
    out(j, value, human);
  }
}

async fn dispatch(
  c: &Client,
  command: Command,
  j: bool,
) -> CliResult<()> {
  match command {
    Command::Login { .. }
    | Command::Schema { .. }
    | Command::Validate { .. }
    | Command::Token(_) => unreachable!(),
    Command::Sso(crate::SsoCmd::Account(cmd)) => {
      app_account(c, cmd, j).await
    }
    Command::Sso(crate::SsoCmd::Oidc { hostname }) => {
      let mut view: wharf_api_types::view::OidcView =
        c.get("/api/oidc").await?;
      if let Some(host) = hostname {
        let host = wharf_api_types::normalize_host(&host);
        view.clients.retain(|c| c.client_id == host);
        if view.clients.is_empty() {
          return Err(
            ApiError::not_found(format!("域名 {host} 没有用 oidc 方式"))
              .suggest(format!(
                "wharf route sso {host} --mode oidc --redirect <回调路径>"
              ))
              .into(),
          );
        }
      }
      out(j, &view, |v| {
        println!(
          "issuer：{}",
          v.issuer
            .as_deref()
            .unwrap_or("不可用（控制面没有对外 https 地址）")
        );
        if let Some(d) = &v.discovery {
          println!("发现地址：{d}");
        }
        println!(
          "用户：{}  邮箱：{}",
          v.username,
          v.email.as_deref().unwrap_or("没设")
        );
        for client in &v.clients {
          println!(
            "{}  密钥 {}{}",
            client.client_id,
            client.secret_ref,
            if client.public { "  公开站点" } else { "" }
          );
          for uri in &client.redirect_uris {
            println!("    回调 {uri}");
          }
        }
      });
      Ok(())
    }
    Command::Sso(crate::SsoCmd::Email { email, clear }) => {
      if email.is_none() && !clear {
        let current: wharf_api_types::view::OidcView =
          c.get("/api/oidc").await?;
        out(j, &json!({"email": current.email}), pretty);
        return Ok(());
      }
      let _: serde_json::Value = c
        .put(
          "/api/oidc/settings",
          &wharf_api_types::view::OidcSettingsRequest {
            email: if clear { None } else { email },
          },
        )
        .await?;
      out(j, &json!({"ok": true}), |_| println!("已保存"));
      Ok(())
    }
    Command::Sso(crate::SsoCmd::Test { hostname }) => {
      let result: SsoTestResult = match c
        .post_timeout(
          &format!(
            "/api/routes/{}/sso/test",
            seg(&wharf_api_types::normalize_host(&hostname))
          ),
          &json!({}),
          Duration::from_secs(14 * 60),
        )
        .await
      {
        Err(CliError::Api(e)) if !j => {
          if let Some(hint) = e.hint {
            eprintln!("提示：{hint}");
          }
          for suggestion in e.suggest {
            eprintln!("可以试试：{suggestion}");
          }
          eprintln!("登录失败：{}", e.message);
          return Err(CliError::Exit(e.code.exit_code()));
        }
        result => result?,
      };
      out(j, &result, print_sso_test);
      if !result.ok {
        return Err(CliError::Exit(1));
      }
      Ok(())
    }
    Command::Status { brief } => {
      let mut s: Status = c
        .get(
          crate::plan_cmd::brief_path("/api/status", brief).as_ref(),
        )
        .await?;
      for service in &mut s.services {
        wharf_api_types::filter_note(
          &mut service.note,
          &mut service.has_sealed_note,
          false,
        );
      }
      for server in &mut s.servers {
        wharf_api_types::filter_note(
          &mut server.note,
          &mut server.has_sealed_note,
          false,
        );
      }
      for route in &mut s.routes {
        wharf_api_types::filter_note(
          &mut route.note,
          &mut route.has_sealed_note,
          false,
        );
      }
      out(j, &s, |s| {
        print::status(s);
        for route in &s.routes {
          if route.failover_pending.is_some() {
            println!("  {}", route.spec.hostname);
            print_failover_pending(route);
          }
        }
      });
      Ok(())
    }
    Command::Deploy {
      dir,
      name,
      server,
      port,
      add_port,
      rm_port,
      env,
      unset_env,
      build,
      ops,
      apply,
      ..
    } => {
      let name = match name {
        Some(n) => n,
        None => dir_name(&dir)?,
      };
      let cmd = ServiceCmd::Deploy {
        name,
        container: None,
        image: None,
        compose: None,
        from_run: None,
        compose_url: None,
        server,
        port,
        add_port,
        rm_port,
        clear_ports: false,
        env,
        unset_env,
        clear_env: false,
        unset_start_timeout: false,
        start_timeout: None,
        health_path: None,
        volume: vec![],
        unset_volume: vec![],
        build: Box::new(BuildArgs {
          dir: Some(dir),
          opts: build,
          ..Default::default()
        }),
        ops: Box::new(ops),
        apply,
      };
      service(c, cmd, j).await
    }
    Command::Data => {
      let v: DataView = c.get("/api/data").await?;
      out(j, &v, print::data);
      Ok(())
    }
    Command::Connect {
      service,
      port,
      component,
      local,
      ttl,
      relay,
    } => {
      crate::connect::run(
        c,
        crate::connect::Args {
          service,
          port,
          component,
          local,
          ttl,
          relay,
        },
        j,
      )
      .await
    }
    Command::Share {
      name,
      ttl,
      port,
      gateway,
      zone,
      apply,
    } => {
      let ttl = share_ttl(&ttl).map_err(ApiError::invalid)?;
      let gateways: Vec<GatewayView> = c.get("/api/gateways").await?;
      let gw = if let Some(name) = gateway {
        gateways.iter().find(|g| g.name == name).ok_or_else(|| {
          ApiError::not_found(format!("入口 {name} 不存在"))
        })?
      } else {
        gateways.iter().find(|g| g.spec.default).ok_or_else(|| {
          ApiError::invalid("没有默认入口，用 --gateway 指定")
        })?
      };
      if gw.spec.kind != GatewayKind::Caddy
        || gw.spec.wildcard.is_empty()
      {
        return Err(
          ApiError::invalid(format!(
            "入口 {} 没开泛域名证书，临时分享要用它",
            gw.name
          ))
          .suggest(format!(
            "wharf gateway wildcard {} --zone <zone> --apply",
            gw.name
          ))
          .into(),
        );
      }
      let zone = match zone {
        Some(zone) if gw.spec.wildcard.contains(&zone) => zone,
        Some(zone) => {
          return Err(
            ApiError::invalid(format!(
              "入口 {} 没开 {zone} 的泛域名证书",
              gw.name
            ))
            .into(),
          );
        }
        None if gw.spec.wildcard.len() == 1 => {
          gw.spec.wildcard[0].clone()
        }
        None => {
          return Err(
            ApiError::invalid(format!(
              "入口 {} 开了多个泛域名证书，用 --zone 选一个：{}",
              gw.name,
              gw.spec.wildcard.join("、")
            ))
            .into(),
          );
        }
      };
      let mut bytes = [0u8; 10];
      getrandom::fill(&mut bytes).map_err(|e| {
        ApiError::internal(format!("生成分享域名失败：{e}"))
      })?;
      let label: String = bytes
        .iter()
        .map(|b| {
          b"0123456789abcdefghijklmnopqrstuvwxyz"[(b % 36) as usize]
            as char
        })
        .collect();
      let hostname = format!("{label}.{zone}");
      let expires = chrono::Utc::now()
        + chrono::Duration::seconds(ttl.as_secs() as i64);
      if !j {
        println!(
          "分享地址 https://{hostname}，{} 到期",
          expires.with_timezone(&chrono::Local).format("%m-%d %H:%M")
        );
      }
      let spec = RouteSpec {
        sso: None,
        hostname,
        service: name,
        port,
        gateway: Some(gw.name.clone()),
        expires_at: Some(expires.timestamp_millis()),
        upstream: None,
        redirect: None,
        backup_gateway: None,
        dns_ttl: None,
        failover_minutes: None,
        auth: false,
        paths: vec![],
        caddy: None,
        link: Default::default(),
        rate_limit: None,
        block_scanners: false,
        internal: false,
        core_mesh_only: false,
        cf_origin_only: false,
      };
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    Command::Exec {
      server,
      args,
      command,
    } => {
      crate::exec_command::run(
        c,
        &server,
        false,
        None,
        args,
        command.into_iter().collect(),
        j,
      )
      .await
    }
    Command::Audit { actor, kind, limit } => {
      crate::audit::audit(c, actor, kind, limit, j).await
    }
    Command::ShellLog { server, limit } => {
      shell_log(c, server, limit, j).await
    }
    Command::Upgrade { skip_snapshot } => {
      upgrade(c, skip_snapshot, j).await
    }
    Command::SelfUpdate => crate::selfcmd::self_update(c, j).await,
    Command::Whoami => crate::selfcmd::whoami(c, j).await,
    Command::Core(crate::CoreCmd::Resume) => {
      let v: wharf_api_types::view::CoreSafeModeView =
        c.post("/api/core/resume", &json!({})).await?;
      out(j, &v, |v| {
        println!(
          "安全接管模式：{}",
          if v.safe_mode { "开启" } else { "关闭" }
        );
        if let Some(hint) = &v.hint {
          println!("{hint}");
        }
      });
      Ok(())
    }
    Command::Core(crate::CoreCmd::Snapshot(cmd)) => {
      core_snapshot(c, cmd, j).await
    }
    Command::Core(crate::CoreCmd::Key) => {
      let view: wharf_api_types::view::CoreKeyView =
        c.get("/api/core/key").await?;
      out(j, &view, pretty);
      Ok(())
    }
    Command::Core(crate::CoreCmd::RotateKey {
      window_hours,
      force,
      commit,
      rollback,
    }) => {
      rotate_core_key(c, window_hours, force, commit, rollback, j)
        .await
    }
    Command::Core(crate::CoreCmd::Addresses) => {
      let view: wharf_api_types::view::CoreAddresses =
        c.get("/api/core/addresses").await?;
      out(j, &view, |v| {
        for a in &v.addresses {
          println!("{}  {}", a.kind, a.url);
        }
      });
      Ok(())
    }
    Command::Core(crate::CoreCmd::Check) => {
      let value: Value =
        c.post("/api/version/check", &json!({})).await?;
      out(j, &value, pretty);
      Ok(())
    }
    Command::Core(crate::CoreCmd::Logs(args)) => {
      show_logs(c, "/api/core/logs", &args, j).await
    }
    Command::Egress { cmd } => {
      let v: Value = match cmd {
        Some(EgressCmd::Api {
          server: None,
          off: false,
        }) => c.get("/api/egress").await?,
        Some(EgressCmd::Api { server, .. }) => {
          let server = server.unwrap_or_default();
          c.put("/api/egress", &json!({ "via": server })).await?
        }
        Some(EgressCmd::Presets) => {
          let v = json!(wharf_api_types::egress::PRESETS
            .iter()
            .map(|(n, d, hosts)| json!({ "name": n, "label": d, "domains": hosts }))
            .collect::<Vec<_>>());
          out(j, &v, |_| {
            for (n, d, hosts) in wharf_api_types::egress::PRESETS {
              println!("{n:<11}{d}：{}", hosts.join(" "));
            }
          });
          return Ok(());
        }
        None => c.get("/api/egress").await?,
      };
      out(j, &v, |v| match v["via"].as_str() {
        Some(s) => println!("调厂商 API：按 {s} 出口的规则分流"),
        None => println!("调厂商 API：直连"),
      });
      Ok(())
    }
    Command::Notify(NotifyCmd::Test) => {
      let r: Value = c.post("/api/notify/test", &json!({})).await?;
      out(j, &r, |_| println!("已发送测试消息"));
      Ok(())
    }
    Command::Notify(NotifyCmd::Key(cmd)) => {
      match cmd {
        crate::NotifyKeyCmd::List => {
          let rows: Vec<Value> = c.get("/api/notify/keys").await?;
          out(j, &rows, |rows| {
            if rows.is_empty() {
              println!("还没有通知地址");
            }
            for r in rows {
              let used = r["last_used_at"]
                .as_i64()
                .and_then(chrono::DateTime::from_timestamp_millis)
                .map(|t| {
                  t.with_timezone(&chrono::Local)
                    .format("%m-%d %H:%M")
                    .to_string()
                })
                .unwrap_or_else(|| "没用过".into());
              println!(
                "{}\t[[{}]]\t{used}",
                r["name"].as_str().unwrap_or(""),
                r["secret"].as_str().unwrap_or("")
              );
            }
          });
        }
        crate::NotifyKeyCmd::Add { name, show } => {
          let mut r: Value = c
            .post(
              &format!("/api/notify/keys/{}", seg(&name)),
              &json!({}),
            )
            .await?;
          if !show && let Some(o) = r.as_object_mut() {
            o.remove("url");
          }
          out(j, &r, |r| {
            let secret = r["secret"].as_str().unwrap_or("");
            println!(
              "已生成，地址存在密钥 {secret}，服务的环境变量里写 [[{secret}]]"
            );
            if let Some(url) = r["url"].as_str() {
              println!("{url}");
            }
          });
        }
        crate::NotifyKeyCmd::Rm { name } => {
          let r: Value = c
            .delete(&format!("/api/notify/keys/{}", seg(&name)))
            .await?;
          out(j, &r, |_| println!("已删除"));
        }
      }
      Ok(())
    }
    Command::Metrics {
      subject,
      names,
      range,
    } => {
      let mut path = format!(
        "/api/metrics?subject={}&range={range}",
        seg(&subject)
      );
      if let Some(n) = &names {
        path.push_str(&format!("&names={}", seg(n)));
      }
      let v: serde_json::Value = c.get(&path).await?;
      out(j, &v, print::metrics);
      Ok(())
    }
    Command::Doctor {
      hostname,
      service,
      server,
    } => {
      let path = [
        ("host", hostname),
        ("service", service),
        ("server", server),
      ]
      .into_iter()
      .find_map(|(key, value)| {
        value.map(|v| format!("/api/doctor?{key}={}", seg(&v)))
      })
      .unwrap_or_else(|| "/api/doctor".into());
      let v: DoctorReport = c.get(&path).await?;
      let bad = v
        .servers
        .iter()
        .chain(&v.vendors)
        .chain(&v.config)
        .chain(&v.checks)
        .chain(v.routes.iter().flat_map(|r| &r.checks))
        .filter(|c| c.status == CheckStatus::Bad)
        .count();
      if bad > 0 && j {
        let mut value =
          serde_json::to_value(&v).map_err(anyhow::Error::from)?;
        value["error"] =
          json!(ApiError::invalid(format!("{bad} 项不通")));
        print::json(&value);
        return Err(CliError::Exit(1));
      }
      out(j, &v, print::doctor);
      if bad > 0 {
        return Err(
          ApiError::invalid(format!("{bad} 项不通")).into(),
        );
      }
      Ok(())
    }
    Command::External(cmd) => {
      crate::external::command(c, cmd, j).await
    }
    Command::Network {
      action: Some(action),
      ..
    } => crate::external::acl(c, action, j).await,
    Command::Network {
      probe,
      action: None,
    } => {
      let v: NetworkView = if probe {
        c.post("/api/network/probe", &json!({})).await?
      } else {
        c.get("/api/network").await?
      };
      out(j, &v, print::network);
      Ok(())
    }
    Command::Alert(cmd) => crate::alert::run(c, cmd, j).await,
    Command::Server(cmd) => server(c, cmd, j).await,
    Command::Top(args) => crate::top::run(c, args, j).await,
    Command::Report(args) => crate::report::run(c, args, j).await,
    Command::Service(cmd) => service(c, cmd, j).await,
    Command::Gateway(cmd) => gateway(c, cmd, j).await,
    Command::Route(cmd) => route(c, cmd, j).await,
    Command::Account(cmd) => account(c, cmd, j).await,
    Command::Secret(cmd) => secret(c, cmd, j).await,
    Command::Backup(cmd) => backup(c, cmd, j).await,
    Command::Task(cmd) => crate::task::task(c, cmd, j).await,
    Command::Edge(cmd) => crate::edge::edge(c, cmd, j).await,
    Command::Bookmark(cmd) => {
      crate::bookmark::bookmark(c, cmd, j).await
    }
    Command::Plan {
      cmd,
      file,
      partial,
      apply,
    } => {
      if let Some(cmd) = cmd {
        apply.check_read_only()?;
        if file.is_some()
          || partial
          || apply.brief
          || apply.dns_verify.mode().is_some()
        {
          return Err(
            ApiError::invalid("plan 子命令不能与生成计划的参数混用")
              .into(),
          );
        }
        return crate::plan_cmd::run(c, cmd, j).await;
      }
      let req = match file {
        Some(path) => {
          let fleet = fleet::load(&path)?;
          // 完整状态里一定有服务器；没有多半是局部导出的文件，按完整状态会删掉其余一切。
          if !partial && fleet.servers.is_empty() {
            return Err(
              ApiError::invalid(format!(
                "{} 里没有服务器，像是局部的意图文件；按完整期望状态计划会删掉文件里没写的服务、网关和路由",
                path.display()
              ))
              .with_hint("只改文件里写到的对象：加 --partial")
              .suggest(format!("wharf plan -f {} --partial", path.display()))
              .into(),
            );
          }
          if partial {
            PlanRequest {
              partial: Some(fleet),
              ..Default::default()
            }
          } else {
            PlanRequest {
              fleet: Some(fleet),
              ..Default::default()
            }
          }
        }
        None => PlanRequest::default(),
      };
      plan_and_maybe_apply(c, req, apply, j).await
    }
    Command::Apply {
      brief,
      plan_id,
      confirm,
      no_wait,
      skip_snapshot,
      dns_verify,
    } => {
      apply(
        c,
        ApplyRequest {
          plan_id,
          confirm,
          skip_snapshot,
          verify_before_dns: dns_verify.mode(),
        },
        !no_wait,
        j,
        None,
        brief,
      )
      .await
    }
    Command::Run(cmd) => run_cmd(c, cmd, j).await,
    Command::Export { output, service } => {
      let fleet: Fleet = c.get("/api/export").await?;
      let partial = !service.is_empty();
      let fleet = if partial {
        fleet::only_services(fleet, &service)?
      } else {
        fleet
      };
      let text = fleet::to_toml(&fleet, partial)?;
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
    Command::Gate(crate::GateCmd::Key(cmd)) => {
      match cmd {
        crate::GateKeyCmd::List => {
          let rows: Vec<wharf_api_types::view::GateKeyView> =
            c.get("/api/gate/keys").await?;
          out(j, &rows, |rows| {
            for row in rows {
              println!(
                "{}\t{}\t{}",
                row.name,
                row.hosts.join("、"),
                row
                  .last_used_at
                  .map(|t| t.to_string())
                  .unwrap_or_else(|| "没用过".into())
              );
            }
          });
        }
        crate::GateKeyCmd::Add { name, hosts } => {
          let result: Value = c
            .put(
              &format!("/api/gate/keys/{}", seg(&name)),
              &wharf_api_types::view::GateKeyRequest { hosts },
            )
            .await?;
          out(j, &result, |v| {
            if let Some(key) = v["key"].as_str() {
              println!("{key}");
            } else {
              println!("已修改域名");
            }
          });
        }
        crate::GateKeyCmd::Rm { name } => {
          let result: Value = c
            .delete(&format!("/api/gate/keys/{}", seg(&name)))
            .await?;
          out(j, &result, |_| println!("已删除"));
        }
      }
      Ok(())
    }
    Command::Wait(cmd) => crate::wait::run(c, cmd, j).await,
    Command::Commands { .. } => {
      unreachable!("不连控制面，在 run 里处理")
    }
  }
}

async fn login(
  url: String,
  core_key: String,
  token_file: Option<String>,
  token_cmd: Option<String>,
  j: bool,
) -> CliResult<()> {
  crate::tunnel::parse_core_key(&core_key)?;
  let (config, token) =
    login_credentials(&url, &core_key, token_file, token_cmd).await?;
  let c =
    Client::with_key(Some(url), Some(token), Some(core_key)).await?;
  let _: Vec<ServerView> = c.get("/api/servers").await?;
  let path = config.save()?;
  if j {
    print::json(&json!({ "saved": path }));
  } else {
    println!("已保存到 {}", path.display());
  }
  Ok(())
}

async fn login_credentials(
  url: &str,
  core_key: &str,
  token_file: Option<String>,
  token_cmd: Option<String>,
) -> CliResult<(Config, String)> {
  let mut config = Config {
    url: Some(url.trim_end_matches('/').to_string()),
    core_key: Some(core_key.trim().to_string()),
    token_file,
    token_cmd,
    ..Default::default()
  };
  let token =
    match crate::client::resolve_token(None, &config).await? {
      Some(token) => token,
      None => {
        let token = read_secret("API token：")?;
        config.token = Some(token.clone());
        token
      }
    };
  Ok((config, token))
}

// PLAN / APPLY

async fn plan_and_maybe_apply(
  c: &Client,
  req: PlanRequest,
  flags: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  plan_output(c, req, flags, j, Vec::new(), None).await
}

async fn deploy_plan(
  c: &Client,
  name: String,
  spec: ServiceSpec,
  flags: ApplyFlags,
  j: bool,
  warnings: Vec<String>,
  detected: Option<crate::deploy::DetectResult>,
) -> CliResult<()> {
  let req = PlanRequest {
    changes: vec![Change::UpsertService {
      name,
      spec,
      adopt: None,
      pins: None,
      commit: None,
    }],
    ..Default::default()
  };
  plan_output(c, req, flags, j, warnings, detected).await
}

async fn plan_output(
  c: &Client,
  req: PlanRequest,
  flags: ApplyFlags,
  j: bool,
  warnings: Vec<String>,
  detected: Option<crate::deploy::DetectResult>,
) -> CliResult<()> {
  let req = PlanRequest {
    note: flags.note.clone().or(req.note),
    ..req
  };
  let mut plan: Plan = c
    .post(
      crate::plan_cmd::brief_path("/api/plan", flags.brief).as_ref(),
      &req,
    )
    .await?;
  if j {
    for warning in warnings {
      if !plan.warnings.contains(&warning) {
        plan.warnings.push(warning);
      }
    }
  }
  if !flags.apply || plan.items.is_empty() {
    if j && let Some(detected) = detected {
      let mut value =
        serde_json::to_value(&plan).map_err(anyhow::Error::from)?;
      value["detected"] = detected.summary();
      print::json(&value);
    } else {
      out(j, &plan, print::plan);
    }
    return Ok(());
  }
  let verify_before_dns = flags.dns_verify.mode();
  let missing: Vec<&String> = plan
    .needs_confirm
    .iter()
    .filter(|a| !flags.confirm.contains(a))
    .collect();
  if !missing.is_empty() {
    if !j && !print::is_quiet() {
      print::plan(&plan);
    }
    let mut flags: String =
      missing.iter().map(|a| format!(" --confirm {a}")).collect();
    match verify_before_dns {
      Some(true) => flags.push_str(" --verify-before-dns"),
      Some(false) => flags.push_str(" --no-verify-before-dns"),
      None => {}
    }
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
      err = err
        .with_hint(format!("plan_id = {}", plan.plan_id))
        .with_details(wharf_api_types::plan::confirm_details(
          &plan, &missing,
        ));
    }
    return Err(err.into());
  }
  if !j && !print::is_quiet() {
    print::plan_with(&plan, false);
  }
  let req = ApplyRequest {
    plan_id: plan.plan_id.clone(),
    confirm: flags.confirm,
    skip_snapshot: false,
    verify_before_dns,
  };
  apply(c, req, true, j, Some((plan, detected)), flags.brief).await
}

async fn apply(
  c: &Client,
  req: ApplyRequest,
  wait: bool,
  j: bool,
  plan: Option<(Plan, Option<crate::deploy::DetectResult>)>,
  brief: bool,
) -> CliResult<()> {
  let resp: ApplyResponse = c.post("/api/apply", &req).await?;
  if !wait {
    out(j, &resp, |r| {
      println!(
        "已开始执行 {}。查看：wharf run show {}",
        r.run_id, r.run_id
      )
    });
    return Ok(());
  }
  let mut run = wait_run(c, &resp.run_id, j).await?;
  if j {
    if brief {
      crate::plan_cmd::compact_run(&mut run);
    }
    match plan {
      Some((plan, detected)) => {
        let mut value = json!({"plan": plan, "run": run});
        if let Some(detected) = detected {
          value["detected"] = detected.summary();
        }
        print::json(&value);
      }
      None => print::json(&run),
    }
  } else if print::is_quiet() {
    println!("{}", run.run_id);
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
  wait_run_with_interrupt(c, run_id, j, false).await
}

async fn wait_run_with_interrupt(
  c: &Client,
  run_id: &str,
  j: bool,
  cancel_on_interrupt: bool,
) -> CliResult<Run> {
  let path = format!("/api/runs/{}", seg(run_id));
  wait_run_until(
    run_id,
    j,
    cancel_on_interrupt,
    || c.get(&path),
    tokio::signal::ctrl_c(),
  )
  .await
}

async fn wait_run_until<F: Future<Output = CliResult<Run>>>(
  run_id: &str,
  j: bool,
  cancel_on_interrupt: bool,
  mut fetch: impl FnMut() -> F,
  interrupt: impl Future,
) -> CliResult<Run> {
  let mut printed: Vec<(usize, bool)> = Vec::new();
  tokio::pin!(interrupt);
  let mut retries = 0;
  let interrupted = || {
    if !j && !print::is_quiet() && !cancel_on_interrupt {
      eprintln!(
        "已停止等待，执行仍在继续。取消：wharf run cancel {run_id}"
      );
    }
    CliError::Exit(130)
  };
  loop {
    let result: CliResult<Run> = tokio::select! {
      biased;
      _ = &mut interrupt => return Err(interrupted()),
      r = fetch() => r,
    };
    let run = match result {
      Ok(run) => {
        retries = 0;
        run
      }
      Err(CliError::Api(error))
        if connection_lost(&error) && retries < 10 =>
      {
        retries += 1;
        tokio::select! {
          _ = tokio::time::sleep(Duration::from_secs(retries.min(3))) => {}
          _ = &mut interrupt => return Err(interrupted()),
        }
        continue;
      }
      Err(CliError::Api(error)) => {
        let command = format!("wharf run show {run_id}");
        return Err(
          error
            .with_hint(format!("执行可能仍在进行，查看：{command}"))
            .suggest(command)
            .into(),
        );
      }
      Err(error) => return Err(error),
    };
    if !j && !print::is_quiet() {
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
    tokio::select! {
      biased;
      _ = &mut interrupt => return Err(interrupted()),
      _ = tokio::time::sleep(Duration::from_millis(800)) => {}
    }
  }
}

fn step_done(step: &wharf_api_types::plan::RunStep) -> bool {
  use wharf_api_types::plan::StepStatus::*;
  matches!(step.status, Done | Failed | Skipped)
}

async fn run_cmd(c: &Client, cmd: RunCmd, j: bool) -> CliResult<()> {
  match cmd {
    RunCmd::List {
      limit,
      failed,
      status,
    } => {
      let mut url =
        format!("/api/runs?limit={limit}&failed={failed}");
      if let Some(status) = status {
        url.push_str(&format!("&status={status}"));
      }
      let runs: Vec<Run> = c.get(&url).await?;
      out_quiet(
        j,
        &runs,
        |runs| {
          runs.iter().map(|r| r.run_id.clone()).collect::<Vec<_>>()
        },
        |runs| {
          for r in runs {
            print::run_line(r);
          }
        },
      );
      Ok(())
    }
    RunCmd::Show { run_id } => {
      let run: Run =
        c.get(&format!("/api/runs/{}", seg(&run_id))).await?;
      out(j, &run, print::run);
      Ok(())
    }
    RunCmd::Logs {
      run_id,
      step,
      tail,
      all,
      grep,
      errors,
      max_line,
      search,
    } => {
      let mut path =
        format!("/api/runs/{}/logs?all={all}", seg(&run_id));
      if let Some(step) = step {
        path.push_str(&format!("&step={step}"));
      }
      show_logs(
        c,
        &path,
        &crate::LogArgs {
          tail,
          since: None,
          grep,
          errors,
          max_line,
          filters: Box::new(crate::log_options::LogOptions {
            search: *search,
            ..Default::default()
          }),
        },
        j,
      )
      .await
    }
    RunCmd::Wait { run_id } => {
      let run = wait_run(c, &run_id, j).await?;
      out(j, &run, print::run_summary);
      match run.status {
        RunStatus::Succeeded => Ok(()),
        _ => Err(CliError::Exit(4)),
      }
    }
    RunCmd::Retry { run_id, no_wait } => {
      let response: ApplyResponse = c
        .post(
          &format!("/api/runs/{}/retry", seg(&run_id)),
          &json!({}),
        )
        .await?;
      finish_task(c, &response.run_id, !no_wait, j).await
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
  let mut lines = command.lines();
  let first: String = lines
    .next()
    .unwrap_or_default()
    .chars()
    .flat_map(char::escape_default)
    .take(100)
    .collect();
  let count = 1 + lines.count();
  if count > 1 {
    format!("{first}（共 {count} 行）")
  } else {
    first
  }
}

// SERVERS

async fn server(
  c: &Client,
  cmd: ServerCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    ServerCmd::Probe(args) => crate::probe::server(c, args, j).await,
    ServerCmd::Apt { name, apply } => {
      crate::server::apt(c, &name, apply, j).await
    }
    ServerCmd::Dirs { name, path } => {
      crate::server::dirs(c, &name, &path, j).await
    }
    ServerCmd::Pack {
      name,
      path,
      service,
    } => {
      crate::server::pack(c, &name, &path, service.as_deref(), j)
        .await
    }
    ServerCmd::Sessions { name, end, rename } => {
      crate::server::sessions(c, &name, end, rename, j).await
    }
    ServerCmd::HostUnits { name } => {
      crate::server::host_units(c, &name, j).await
    }
    ServerCmd::HostLogs { name, unit, lines } => {
      crate::server::host_logs(c, &name, &unit, lines, j).await
    }
    ServerCmd::WatchUnit {
      name,
      unit,
      on,
      off,
    } => {
      if on || off {
        crate::server::watch_unit(c, &name, &unit, on, j).await
      } else {
        crate::server::show_watch_unit(c, &name, &unit, j).await
      }
    }
    ServerCmd::Usage { name } => {
      crate::server::usage(c, &name, j).await
    }
    ServerCmd::Traffic { name } => {
      crate::server::traffic(c, &name, j).await
    }
    ServerCmd::Exposure {
      name,
      refresh,
      ack,
      unack,
    } => {
      use wharf_api_types::view::{ExposureView, risk_text};
      let base = format!("/api/servers/{}/exposure", seg(&name));
      if refresh {
        let _: ExposureView =
          c.post(&format!("{base}/refresh"), &json!({})).await?;
      }
      if let Some(port) = ack.as_ref().or(unack.as_ref()) {
        let _: ExposureView = c
          .post(
            &format!("{base}/ack"),
            &json!({"port":port,"acked":ack.is_some()}),
          )
          .await?;
      }
      let v: ExposureView = c.get(&base).await?;
      out(j, &v, |v| {
        if v.outdated {
          println!("agent 版本太旧，没有数据");
          return;
        }
        if v.checked_at.is_none() {
          println!("还没有检查过");
          return;
        }
        println!("本机监听\n协议/端口  地址  归属  名字  状态");
        for p in &v.ports {
          let address = p.family.as_ref().map_or_else(
            || p.addr.clone(),
            |family| format!("{} ({family})", p.addr),
          );
          println!(
            "{}/{}  {}  {}  {}  {}",
            p.proto,
            p.port,
            address,
            p.owner,
            p.name,
            if p.expected {
              "预期"
            } else if p.acked {
              "已确认"
            } else {
              "未确认"
            }
          );
        }
        println!("权限较大的容器\n容器  所属  风险");
        for r in &v.risks {
          println!(
            "{}  {}  {}",
            r.container,
            if r.own {
              "Wharf 自身"
            } else {
              r.service.as_deref().unwrap_or("未纳管")
            },
            r.risks
              .iter()
              .map(|c| risk_text(c))
              .collect::<Vec<_>>()
              .join("、")
          );
        }
      });
      Ok(())
    }
    ServerCmd::RotateKey { name } => {
      let view: wharf_api_types::view::AgentKeyRotation = c
        .post(
          &format!("/api/servers/{}/rotate-key", seg(&name)),
          &json!({}),
        )
        .await?;
      out(j, &view, pretty);
      Ok(())
    }
    ServerCmd::List(filters) => {
      let mut v: Vec<ServerView> = c.get(&filters.path()).await?;
      for server in &mut v {
        wharf_api_types::filter_note(
          &mut server.note,
          &mut server.has_sealed_note,
          false,
        );
      }
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
    ServerCmd::Note { name, args } => {
      crate::note::run(c, "server", &name, args, j).await
    }
    ServerCmd::Show { name } => {
      let mut v: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      wharf_api_types::filter_note(
        &mut v.note,
        &mut v.has_sealed_note,
        false,
      );
      out(j, &v, crate::top::show_server);
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
      rm_mirror,
      clear_mirrors,
      mirrors_only,
      private_ip,
      network,
      mode,
      lan_ip,
      rm_lan_ip,
      clear_lan_ips,
      build_env,
      rm_build_env,
      clear_build_env,
      git_proxy,
      pull_proxy,
      egress,
      via,
      github_mirror,
      host_terminal,
      host_exec,
      host_docker,
      host_system,
      traffic_quota_gb,
      traffic_reset_day,
      renew_at,
      agent_memory,
      unset_public_ip,
      unset_private_ip,
      unset_git_proxy,
      unset_pull_proxy,
      unset_via,
      unset_github_mirror,
      unset_renew_at,
      unset_traffic_quota,
      unset_traffic_reset_day,
      unset_agent_memory,
      apply,
    } => {
      let current: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      let mut settings: ServerSettings = current.settings;
      if !(!mirror.is_empty()
        || !rm_mirror.is_empty()
        || clear_mirrors
        || !lan_ip.is_empty()
        || !rm_lan_ip.is_empty()
        || clear_lan_ips
        || !build_env.is_empty()
        || !rm_build_env.is_empty()
        || clear_build_env
        || region.is_some()
        || public_ip.is_some()
        || mirrors_only.is_some()
        || private_ip.is_some()
        || network.is_some()
        || mode.is_some()
        || git_proxy.is_some()
        || pull_proxy.is_some()
        || egress.is_some()
        || via.is_some()
        || github_mirror.is_some()
        || host_terminal.is_some()
        || host_exec.is_some()
        || host_docker.is_some()
        || host_system.is_some()
        || traffic_quota_gb.is_some()
        || traffic_reset_day.is_some()
        || renew_at.is_some()
        || agent_memory.is_some()
        || unset_public_ip
        || unset_private_ip
        || unset_git_proxy
        || unset_pull_proxy
        || unset_via
        || unset_github_mirror
        || unset_renew_at
        || unset_traffic_quota
        || unset_traffic_reset_day
        || unset_agent_memory)
      {
        apply.check_read_only()?;
        out(
          j,
          &json!({"server": name, "settings": settings}),
          pretty,
        );
        return Ok(());
      }
      if unset_public_ip {
        settings.public_ip = None;
      }
      if unset_private_ip {
        settings.private_addr = None;
      }
      if unset_git_proxy {
        settings.git_proxy = None;
      }
      if unset_pull_proxy {
        settings.pull_proxy = None;
      }
      if unset_via {
        settings.via = None;
      }
      if unset_github_mirror {
        settings.github_mirror = None;
      }
      if unset_renew_at {
        settings.renew_at = None;
      }
      if unset_traffic_quota {
        settings.traffic_quota_gb = None;
      }
      if unset_traffic_reset_day {
        settings.traffic_reset_day = None;
      }
      if unset_agent_memory {
        settings.agent_memory = None;
      }

      if let Some(value) = agent_memory {
        settings.agent_memory = Some(value);
      }
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
      for key in rm_mirror {
        if settings.registry_mirrors.remove(key.trim()).is_none() {
          return Err(
            ApiError::invalid(format!("镜像源 {key} 不存在")).into(),
          );
        }
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
      if clear_lan_ips {
        settings.lan_addrs.clear();
      }
      for ip in rm_lan_ip {
        list_edits::remove_named(
          &mut settings.lan_addrs,
          ip.trim(),
          "局域网地址",
          String::as_str,
        )?;
      }
      for ip in lan_ip {
        let ip = ip.trim().to_string();
        if !settings.lan_addrs.contains(&ip) {
          settings.lan_addrs.push(ip);
        }
      }
      if clear_build_env {
        settings.build_env.clear();
      }
      if let Some(q) = traffic_quota_gb {
        settings.traffic_quota_gb = (q > 0).then_some(q);
      }
      if let Some(d) = traffic_reset_day {
        settings.traffic_reset_day = (d > 0).then_some(d);
      }
      if let Some(v) = renew_at {
        settings.renew_at =
          (!v.trim().is_empty()).then(|| v.trim().to_string());
      }
      if let Some(p) = git_proxy {
        let p = p.trim();
        if !p.is_empty() && !p.starts_with("http://") {
          return Err(
            ApiError::invalid(format!(
              "--git-proxy {p} 要以 http:// 开头"
            ))
            .into(),
          );
        }
        settings.git_proxy = (!p.is_empty()).then(|| p.to_string());
      }
      if let Some(p) = pull_proxy {
        let p = p.trim();
        if !p.is_empty() && !p.starts_with("http://") {
          return Err(
            ApiError::invalid(format!(
              "--pull-proxy {p} 要以 http:// 开头"
            ))
            .into(),
          );
        }
        settings.pull_proxy = (!p.is_empty()).then(|| p.to_string());
      }
      if let Some(e) = egress {
        settings.egress = parse_egress(&e)?;
      }
      if let Some(v) = via {
        let v = v.trim();
        settings.via = (!v.is_empty()).then(|| v.to_string());
      }
      if let Some(m) = github_mirror {
        let m = m.trim().trim_end_matches('/');
        if !m.is_empty() && !m.starts_with("https://") {
          return Err(
            ApiError::invalid(format!(
              "--github-mirror {m} 要以 https:// 开头"
            ))
            .into(),
          );
        }
        settings.github_mirror =
          (!m.is_empty()).then(|| m.to_string());
      }
      for key in rm_build_env {
        if settings.build_env.remove(key.trim()).is_none() {
          return Err(
            ApiError::invalid(format!("构建参数 {key} 不存在"))
              .into(),
          );
        }
      }
      for e in &build_env {
        let (k, v) = parse_kv(e, "--build-env")?;
        if v.is_empty() {
          settings.build_env.remove(&k);
        } else {
          settings.build_env.insert(k, v);
        }
      }
      set_private_network(
        &mut settings,
        private_ip.as_deref(),
        network.as_deref(),
      )?;
      if let Some(mode) = mode {
        settings.network_mode = match mode.as_str() {
          "tailscale" => Some(NetworkMode::Tailscale),
          "lan" => Some(NetworkMode::Lan),
          "public" => Some(NetworkMode::Public),
          _ => None,
        };
      }
      if let Some(enabled) = host_terminal {
        settings.host_terminal = enabled;
      }
      if let Some(enabled) = host_exec {
        settings.host_exec = enabled;
      }
      if let Some(enabled) = host_docker {
        settings.host_docker = enabled;
      }
      if let Some(enabled) = host_system {
        settings.host_system = enabled;
      }
      changes(
        c,
        vec![Change::UpdateServer { name, settings }],
        apply,
        j,
      )
      .await
    }
    ServerCmd::Baseline {
      name,
      timezone,
      swap_gb,
      sysctl,
      docker_log,
      journal_max,
      security_updates,
      copy_from,
      unset_timezone,
      unset_swap,
      unset_docker_log,
      unset_journal_max,
      unset_sysctl,
      apply,
    } => {
      let edits = timezone.is_some()
        || swap_gb.is_some()
        || !sysctl.is_empty()
        || docker_log.is_some()
        || journal_max.is_some()
        || security_updates.is_some()
        || copy_from.is_some()
        || unset_timezone
        || unset_swap
        || unset_docker_log
        || unset_journal_max
        || !unset_sysctl.is_empty();
      if !edits && !apply.apply {
        apply.check_read_only()?;
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Report {
          diffs: Vec<String>,
          errors: Vec<String>,
        }
        let r: Report = c
          .post(
            &format!("/api/servers/{}/baseline/check", seg(&name)),
            &json!({}),
          )
          .await?;
        out(j, &r, |r| {
          if r.diffs.is_empty() && r.errors.is_empty() {
            println!("{name} 符合基线");
          }
          for d in &r.diffs {
            println!("差异  {d}");
          }
          for e in &r.errors {
            println!("问题  {e}");
          }
          if !r.diffs.is_empty() {
            println!("\n纠正：wharf server baseline {name} --apply");
          }
        });
        return Ok(());
      }
      let current: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      let mut settings = current.settings;
      let b = &mut settings.baseline;
      if let Some(from) = copy_from {
        let other: ServerView =
          c.get(&format!("/api/servers/{}", seg(&from))).await?;
        *b = other.settings.baseline;
      }
      if unset_timezone {
        b.timezone = None;
      }
      if unset_swap {
        b.swap_gb = None;
      }
      if unset_docker_log {
        b.docker_log_size = None;
        b.docker_log_files = None;
      }
      if unset_journal_max {
        b.journal_max = None;
      }
      for key in unset_sysctl {
        b.sysctl.remove(&key);
      }
      let text = |v: String| {
        let v = v.trim().to_string();
        (!v.is_empty()).then_some(v)
      };
      if let Some(tz) = timezone {
        b.timezone = text(tz);
      }
      if let Some(n) = swap_gb {
        b.swap_gb = (n > 0).then_some(n);
      }
      for kv in &sysctl {
        let (k, v) = parse_kv(kv, "--sysctl")?;
        if v.is_empty() {
          b.sysctl.remove(&k);
        } else {
          b.sysctl.insert(k, v);
        }
      }
      if let Some(d) = docker_log {
        match text(d) {
          None => {
            b.docker_log_size = None;
            b.docker_log_files = None;
          }
          Some(d) => {
            let (size, files) = match d.split_once(':') {
              Some((s, f)) => (
                s.to_string(),
                Some(f.parse::<u32>().map_err(|_| {
                  ApiError::invalid(format!(
                    "--docker-log {d} 格式不对，应为 20m:3"
                  ))
                })?),
              ),
              None => (d.clone(), None),
            };
            b.docker_log_size = Some(size);
            b.docker_log_files = files;
          }
        }
      }
      if let Some(m) = journal_max {
        b.journal_max = text(m);
      }
      if let Some(s) = security_updates {
        b.security_updates = match s.as_str() {
          "on" => Some(true),
          "off" => Some(false),
          _ => None,
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
    ServerCmd::Upgrade { name, all } => match (name, all) {
      (Some(name), _) => {
        let r: ApplyResponse = c
          .post(
            &format!("/api/servers/{}/upgrade", seg(&name)),
            &json!({}),
          )
          .await?;
        finish_task(c, &r.run_id, true, j).await
      }
      (None, true) => upgrade_outdated(c, j).await,
      (None, false) => Err(
        ApiError::invalid("给出服务器名，或者用 --all")
          .suggest("wharf server upgrade --all")
          .into(),
      ),
    },
    ServerCmd::Prune { name, restore_days } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/servers/{}/prune", seg(&name)),
          &json!({"restore_days": restore_days}),
        )
        .await?;
      finish_task(c, &r.run_id, true, j).await
    }
    ServerCmd::Logs { name, logs } => {
      let path = format!("/api/servers/{}/agent-logs", seg(&name));
      show_logs(c, &path, &logs, j).await
    }
    ServerCmd::Disk { name, measure } => {
      let path = format!("/api/servers/{}/disk", seg(&name));
      let mut v: Value = if measure {
        c.post(&format!("{path}/measure"), &json!({})).await?
      } else {
        c.get(&path).await?
      };
      if let Some(rows) = v["rows"].as_array_mut() {
        rows.sort_by_key(|r| {
          std::cmp::Reverse(r["total"].as_u64().unwrap_or(0))
        });
      }
      out(j, &v, |v| {
        let rows = v["rows"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
          println!("还没有测量结果，用 --measure 现在测一次");
          return;
        }
        let gb = |b: &Value| {
          let b = b.as_f64().unwrap_or(0.0);
          if b >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.1}G", b / 1024.0 / 1024.0 / 1024.0)
          } else {
            format!("{:.0}M", b / 1024.0 / 1024.0)
          }
        };
        println!(
          "{:<24}{:>8}{:>8}{:>8}{:>8}{:>10}",
          "服务", "合计", "数据", "日志", "数据卷", "7 天增长"
        );
        for r in rows {
          let name = r["name"].as_str().unwrap_or("");
          let name = if r["shared"].as_bool() == Some(true) {
            format!("{name}（共用卷）")
          } else {
            name.to_string()
          };
          let week = match r["week"].as_i64() {
            Some(w) if w >= 0 => format!("+{}", gb(&json!(w))),
            Some(w) => format!("-{}", gb(&json!(-w))),
            None => "-".into(),
          };
          println!(
            "{name:<24}{:>8}{:>8}{:>8}{:>8}{week:>10}",
            gb(&r["total"]),
            gb(&r["data"]),
            gb(&r["logs"]),
            gb(&r["vols"])
          );
        }
      });
      Ok(())
    }
    ServerCmd::Host { name } => {
      let v: wharf_api_types::agent::HostInfo =
        c.get(&format!("/api/servers/{}/host", seg(&name))).await?;
      out(j, &v, print::host);
      Ok(())
    }
  }
}

/// 升级全部在线、版本落后的 agent，逐台进行，一台失败不影响其余的。
async fn upgrade_outdated(c: &Client, j: bool) -> CliResult<()> {
  let (data, ok) = upgrade_agents(c, j).await?;
  if j {
    print::json(&data);
  }
  if ok { Ok(()) } else { Err(CliError::Exit(4)) }
}

async fn upgrade_agents(
  c: &Client,
  j: bool,
) -> CliResult<(Value, bool)> {
  let data: Value =
    c.post("/api/servers/upgrade", &json!({})).await?;
  let Some(id) = data["run_id"].as_str() else {
    if !j {
      println!("全部 agent 都是最新版本");
    }
    return Ok((data, true));
  };
  let run = wait_run(c, id, j).await?;
  if !j {
    print::run_summary(&run);
  }
  let ok = run.status == RunStatus::Succeeded;
  Ok((json!(run), ok))
}

/// 控制面重启后，等它带着新构建号回来、agent 重新连上。
const CORE_RESTART_WAIT: Duration = Duration::from_secs(300);
/// 控制面拉新镜像可能很慢（控制面那边最多 540 秒）。
const CORE_UPGRADE_REQUEST: Duration = Duration::from_secs(600);
const AGENT_RECONNECT_WAIT: Duration = Duration::from_secs(60);

/// 连不上或者代理报 5xx：请求没有拿到控制面自己的答复。
fn connection_lost(e: &ApiError) -> bool {
  // AgentOffline 也用于"某台 agent 不在线"，只有连不上控制面本身才算断线。
  (e.code == ErrorCode::AgentOffline
    && e.message.starts_with("无法连接控制面"))
    || (e.code == ErrorCode::Internal
      && (e.message.starts_with("控制面返回 HTTP 5")
        || e.message.starts_with("读取响应失败")))
}

async fn core_snapshot(
  c: &Client,
  cmd: crate::CoreSnapshotCmd,
  j: bool,
) -> CliResult<()> {
  use wharf_api_types::view::{CoreSnapshotsView, DbSnapshotInfo};
  let path = "/api/core/snapshots";
  match cmd {
    crate::CoreSnapshotCmd::List => {
      let view: CoreSnapshotsView = c.get(path).await?;
      out_quiet(
        j,
        &view,
        |v| {
          v.snapshots.iter().map(|s| s.id.clone()).collect::<Vec<_>>()
        },
        print::core_snapshots,
      );
    }
    crate::CoreSnapshotCmd::Create { reason } => {
      let info: DbSnapshotInfo =
        c.post(path, &json!({ "reason": reason })).await?;
      out(j, &info, |i| println!("已创建 {}", i.id));
    }
    crate::CoreSnapshotCmd::Rm { id } => {
      let value: Value =
        c.delete(&format!("{path}/{}", seg(&id))).await?;
      out(j, &value, |_| println!("已删除 {id}"));
    }
  }
  Ok(())
}

async fn upgrade(
  c: &Client,
  skip_snapshot: bool,
  j: bool,
) -> CliResult<()> {
  let mut data = json!({"pre_agents": null, "core": null, "post_agents": null, "cli": null});
  let mut post_agents_failed = false;
  let mut warnings = Vec::new();
  let result: CliResult<()> = async {
    let pre = upgrade_agents(c, j).await;
    match pre {
      Ok((run, passed)) => {
        data["pre_agents"] = run;
        if !passed {
          warnings
            .push("有 agent 没升级成功，继续升级控制面".to_string());
        }
      }
      Err(CliError::Api(error)) => {
        data["pre_agents"] = json!({"error": error});
        warnings
          .push("有 agent 没升级成功，继续升级控制面".to_string());
      }
      Err(error) => return Err(error),
    }
    if !j && let Some(warning) = warnings.last() {
      eprintln!("{warning}");
    }
    data["core"] =
      upgrade_core(c, skip_snapshot, j, &mut warnings).await?;
    let (run, passed) = upgrade_agents(c, j).await?;
    data["post_agents"] = run;
    if !passed {
      post_agents_failed = true;
      if !j {
        return Err(CliError::Exit(4));
      }
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "有 agent 没升级成功")
          .into(),
      );
    }
    data["cli"] = crate::selfcmd::self_update_data(c, j).await?;
    Ok(())
  }
  .await;
  if !j {
    return result;
  }
  data["warnings"] = json!(warnings);
  match result {
    Ok(()) => {
      print::json(&data);
      Ok(())
    }
    Err(CliError::Api(error)) => {
      let code = if post_agents_failed {
        4
      } else {
        error.code.exit_code()
      };
      data["error"] = json!(error);
      print::json(&data);
      Err(CliError::Exit(code))
    }
    Err(CliError::Exit(code)) => {
      data["error"] =
        json!(ApiError::new(ErrorCode::Cancelled, "升级等待已中止"));
      print::json(&data);
      Err(CliError::Exit(code))
    }
  }
}

async fn upgrade_core(
  c: &Client,
  skip_snapshot: bool,
  j: bool,
  warnings: &mut Vec<String>,
) -> CliResult<Value> {
  let before: Value = c.get("/api/version").await?;
  // 请求可能在控制面拉镜像或重启时被代理掐断（超时、502/524），这时按"正在换"处理，
  // 等新构建号出现；等不到再报原来的错误。
  let body = if skip_snapshot {
    json!({"skip_snapshot": true})
  } else {
    json!({})
  };
  let (r, lost) = match c
    .post_timeout::<_, UpgradeResult>(
      "/api/upgrade",
      &body,
      CORE_UPGRADE_REQUEST,
    )
    .await
  {
    Ok(r) => (r, None),
    Err(CliError::Api(e)) if connection_lost(&e) => {
      if !j {
        eprintln!(
          "请求断了（{}），控制面可能正在换，等它回来",
          e.message
        );
      }
      (
        UpgradeResult {
          image: "新版本".into(),
          started: true,
        },
        Some(e),
      )
    }
    Err(e) => return Err(e),
  };
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
        if let Some(e) = lost {
          return Err(e.into());
        }
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
    // 控制面刚换完，反向代理或连接可能还会断一下，重试到期限为止。
    let v: Vec<ServerView> = match c.get("/api/servers").await {
      Ok(v) => v,
      Err(e) if tokio::time::Instant::now() > deadline => {
        return Err(e);
      }
      Err(_) => {
        tokio::time::sleep(Duration::from_secs(3)).await;
        continue;
      }
    };
    if !r.started
      || v.iter().all(|s| s.online)
      || tokio::time::Instant::now() > deadline
    {
      break v;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
  };
  for server in servers.iter().filter(|s| !s.online) {
    let warning = format!("{} 不在线，跳过", server.name);
    if !j {
      eprintln!("{warning}");
    }
    warnings.push(warning);
  }
  Ok(json!(r))
}

/// 取日志并打印：服务、agent、控制面共用。
pub(crate) async fn follow_logs(
  c: &Client,
  path: &str,
) -> CliResult<()> {
  use std::io::Write;
  let mut stdout = std::io::stdout();
  c.follow(path, |chunk| {
    let _ = stdout.write_all(chunk);
    let _ = stdout.flush();
  })
  .await
}

pub(crate) async fn show_logs(
  c: &Client,
  path: &str,
  args: &crate::LogArgs,
  j: bool,
) -> CliResult<()> {
  let sep = if path.contains('?') { '&' } else { '?' };
  let mut path = format!("{path}{sep}tail={}", args.tail);
  if let Some(v) = &args.since {
    path.push_str(&format!("&since={}", seg(v)));
  }
  if let Some(v) = &args.grep {
    path.push_str(&format!("&grep={}", seg(v)));
  }
  if args.errors {
    path.push_str("&errors=true");
  }
  if let Some(v) = args.max_line {
    path.push_str(&format!("&max_line={v}"));
  }
  args.filters.append_query(&mut path);
  let v: Value = c.get(&path).await?;
  out(j, &v, |v| {
    if let Some(meta) = v["previous"].as_object() {
      eprintln!(
        "# 重建前日志 #{}（{} · {}，共 {} 份）",
        meta["index"],
        fmt_ms(meta["at"].as_i64().unwrap_or_default()),
        previous_log_reason(
          meta["reason"].as_str().unwrap_or_default()
        ),
        meta["available"]
      );
    }
    if let Some(groups) = v["groups"].as_array() {
      if groups.is_empty() {
        println!("没有报错（看了 {} 行）", v["scanned"]);
      }
      for g in groups {
        println!(
          "{} 次  {} ~ {}\n  {}",
          g["count"],
          g["first"].as_str().unwrap_or("-"),
          g["last"].as_str().unwrap_or("-"),
          g["line"].as_str().unwrap_or("")
        );
      }
    } else if !crate::log_options::print_rows(v) {
      print!("{}", v["logs"].as_str().unwrap_or_default());
      if let Some(n) = v["matched"].as_u64() {
        eprintln!("命中 {n} 行（看了 {} 行）", v["scanned"]);
      }
    }
    if let Some(hint) = v["hint"].as_str() {
      eprintln!("{hint}");
    }
    if let Some(warnings) = v["warnings"].as_array() {
      for warning in warnings.iter().filter_map(Value::as_str) {
        eprintln!("注意：{warning}");
      }
    }
    if let Some(errors) = v["errors"].as_array() {
      for error in errors {
        let service = error["service"].as_str().unwrap_or_default();
        let server = error["server"].as_str().unwrap_or_default();
        let message = error["message"]
          .as_str()
          .unwrap_or_default()
          .replace(['\r', '\n'], " ");
        eprintln!("没拿到 {service}（{server}）：{message}");
      }
    }
  });
  Ok(())
}

fn previous_log_reason(reason: &str) -> &str {
  match reason {
    "recreate" => "重建前",
    "rollback" => "回滚前",
    "remove" => "删除前",
    _ => reason,
  }
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
      "--port {s} 格式不对，应为 http=80、http=80:20080，compose 来源写 http=:41773、UDP 写 game=27015/udp"
    ))
  };
  let (value, protocol) =
    value.rsplit_once('/').unwrap_or((&value, "tcp"));
  let udp = protocol.eq_ignore_ascii_case("udp");
  if !udp && !protocol.eq_ignore_ascii_case("tcp") {
    return Err(bad().into());
  }
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

fn reconcile_source_switch(
  spec: &mut ServiceSpec,
  source: Source,
  refresh_compose_ports: bool,
) {
  let was_compose = matches!(spec.source, Source::Compose { .. });
  let is_compose = matches!(source, Source::Compose { .. });
  if is_compose && !was_compose {
    spec.volumes.clear();
  }
  if was_compose && !is_compose {
    spec.container = None;
    spec.ports.clear();
  }
  if is_compose && (!was_compose || refresh_compose_ports) {
    spec.ports.clear();
  }
  spec.source = source;
}

async fn service(
  c: &Client,
  cmd: ServiceCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    ServiceCmd::Probe(args) => {
      crate::probe::service(c, args, j).await
    }
    ServiceCmd::Origin { name } => {
      let value: Value = c
        .get(&format!("/api/services/{}/origin", seg(&name)))
        .await?;
      out(j, &value, pretty);
      Ok(())
    }
    ServiceCmd::LogAlert {
      name,
      action,
      off,
      apply,
    } => {
      if off && action.is_some() {
        return Err(
          ApiError::invalid("--off 和 add/rm 二选一").into(),
        );
      }
      crate::service_checks::log(c, name, action, off, apply, j).await
    }
    ServiceCmd::PortCheck(args) => {
      crate::service_checks::port(c, args, j).await
    }
    ServiceCmd::Heartbeat(args) => {
      crate::service_checks::heartbeat(c, args, j).await
    }
    ServiceCmd::UnmanagedIgnore {
      server,
      project,
      container,
      undo,
    } => {
      crate::service_checks::ignore(
        c, &server, project, container, undo, j,
      )
      .await
    }
    ServiceCmd::UnmanagedRemove {
      server,
      project,
      container,
      volumes,
    } => {
      let value: Value = c.post(
        &format!("/api/servers/{}/unmanaged/remove", seg(&server)),
        &json!({ "project": project, "container": container, "volumes": volumes }),
      ).await?;
      out(j, &value, pretty);
      Ok(())
    }
    ServiceCmd::List(filters) => {
      let mut v: Vec<ServiceView> = c.get(&filters.path()).await?;
      for service in &mut v {
        wharf_api_types::filter_note(
          &mut service.note,
          &mut service.has_sealed_note,
          false,
        );
      }
      out(j, &v, |v| {
        for s in v {
          println!(
            "{:<14} {:<8} {}",
            s.name,
            s.spec.server,
            crate::print::service_state(s)
          );
        }
      });
      Ok(())
    }
    ServiceCmd::Note { name, args } => {
      crate::note::run(c, "service", &name, args, j).await
    }
    ServiceCmd::Show { name, reveal } => {
      let mut path = format!("/api/services/{}", seg(&name));
      if reveal {
        path.push_str("?reveal=true");
      }
      let mut v: ServiceView = c.get(&path).await?;
      wharf_api_types::filter_note(
        &mut v.note,
        &mut v.has_sealed_note,
        false,
      );
      out(j, &v, |v| {
        pretty(v);
        print::monitor_settings(v.spec.monitor.as_ref());
        if !v.risks.is_empty() {
          println!(
            "风险：{}",
            v.risks
              .iter()
              .map(|r| wharf_api_types::view::risk_text(r))
              .collect::<Vec<_>>()
              .join("、")
          );
        }
      });
      Ok(())
    }
    ServiceCmd::Exec {
      name,
      container,
      args,
      command,
    } => {
      crate::exec_command::run(
        c, &name, true, container, args, command, j,
      )
      .await
    }
    ServiceCmd::Render { name } => {
      let v: wharf_api_types::view::ServiceRenderView = c
        .get(&format!("/api/services/{}/render", seg(&name)))
        .await?;
      out(j, &v, |v| {
        for warning in &v.warnings {
          eprintln!("提醒：{warning}");
        }
        print!("{}", v.compose);
        if let Some(init) = &v.init_cmd {
          println!("# init_cmd:");
          for line in init.lines() {
            println!("# {line}");
          }
        }
      });
      Ok(())
    }
    ServiceCmd::Logs {
      names,
      tail,
      container,
      follow: true,
      ..
    } => {
      let mut path = format!(
        "/api/services/{}/logs/stream?tail={tail}",
        seg(&names[0])
      );
      if let Some(container) = container {
        c.require_exec_v2_core().await?;
        path.push_str(&format!("&container={}", seg(&container)));
      }
      follow_logs(c, &path).await
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
          let ignored =
            if u.ignored { "（已忽略）" } else { "" };
          println!("{kind} {what}{ignored}");
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
      if !j && !print::is_quiet() {
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
          pins: None,
          commit: None,
          name: v.name,
          spec: v.spec,
          adopt: v.adopt,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Update { name, image, apply } => {
      changes(
        c,
        vec![Change::RefreshImages { name, image }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Retag {
      name,
      image,
      tag,
      apply,
    } => {
      changes(
        c,
        vec![Change::RetagImage { name, image, tag }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::AutoUpdate {
      name,
      on,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      if !on && !off {
        apply.check_read_only()?;
        return crate::service_checks::show_auto_update(
          &name,
          spec.auto_update,
          j,
        );
      }
      spec.auto_update = on;
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::AutoUpdateRun => {
      let results: Vec<AutoUpdateResult> = c
        .post_timeout(
          "/api/updates/auto",
          &json!({}),
          Duration::from_secs(90 * 60),
        )
        .await?;
      out(j, &results, |results| {
        if results.is_empty() {
          println!("没有要自动更新的服务");
        }
        for result in results {
          let status = match result.status.as_str() {
            "updated" => "已更新",
            "failed" => "失败",
            _ => "跳过",
          };
          println!(
            "{}  {status}  {}",
            result.service,
            result.reason.as_deref().unwrap_or_default()
          );
        }
      });
      if results.iter().any(|r| r.status == "failed") {
        Err(CliError::Exit(1))
      } else {
        Ok(())
      }
    }
    ServiceCmd::Rollback {
      name,
      to,
      apply,
      allow_unpinned,
    } => {
      let path = format!(
        "/api/services/{}/rollback?{}allow_unpinned={}",
        seg(&name),
        to.map(|id| format!("to={id}&")).unwrap_or_default(),
        u8::from(allow_unpinned)
      );
      let target: RollbackTarget = c.get(&path).await?;
      if !j && !print::is_quiet() {
        println!(
          "回滚 {name} 到部署 #{}（{}）",
          target.deployment_id,
          target
            .deployed_at
            .with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
        );
        for warning in &target.warnings {
          eprintln!("提醒：{warning}");
        }
      }
      let refresh = allow_unpinned
        && target.commit.is_none()
        && matches!(&target.spec.source, Source::Build(build) if build.git.is_some());
      let mut edits = vec![Change::UpsertService {
        name: name.clone(),
        spec: target.spec,
        adopt: None,
        pins: target.pins,
        commit: target.commit,
      }];
      if refresh {
        edits.push(Change::RefreshImages { name, image: None });
      }
      changes(c, edits, apply, j).await
    }
    ServiceCmd::Timeline {
      name,
      limit,
      before,
    } => {
      let mut path = format!(
        "/api/services/{}/timeline?limit={limit}",
        seg(&name)
      );
      if let Some(before) = before {
        path.push_str(&format!("&before={before}"));
      }
      let v: wharf_api_types::view::Timeline = c.get(&path).await?;
      out(j, &v, |v| {
        for item in &v.items {
          let result = match item.ok {
            Some(true) => "成功",
            Some(false) => "失败",
            None => "",
          };
          println!(
            "{}  {}  {}  {}  {}",
            fmt_ms(item.at),
            item.kind,
            item.title,
            result,
            item.actor.as_deref().unwrap_or_default()
          );
        }
      });
      Ok(())
    }
    ServiceCmd::Logs {
      names,
      tail,
      follow: false,
      container,
      previous,
      previous_list,
      since,
      grep,
      errors,
      max_line,
      filters,
    } => {
      if (previous.is_some() || previous_list) && names.len() != 1 {
        return Err(
          ApiError::invalid("查看重建前日志每次只能指定一个服务")
            .into(),
        );
      }
      if previous_list {
        let name = &names[0];
        let v: Value = c
          .get(&format!(
            "/api/services/{}/logs?previous_list=true",
            seg(name)
          ))
          .await?;
        out(j, &v, |v| {
          if let Some(entries) = v["entries"].as_array() {
            if entries.is_empty() {
              println!("服务 {name} 还没有留存的重建前日志");
            }
            for item in entries {
              let size =
                item["size_bytes"].as_u64().unwrap_or_default();
              println!(
                "#{}  {}  {}  {} KB",
                item["index"],
                fmt_ms(item["at"].as_i64().unwrap_or_default()),
                previous_log_reason(
                  item["reason"].as_str().unwrap_or_default()
                ),
                size.div_ceil(1024)
              );
            }
          }
        });
        return Ok(());
      }
      let args = crate::LogArgs {
        tail,
        since,
        grep,
        errors,
        max_line,
        filters,
      };
      let path = if let [name] = names.as_slice() {
        let mut path = format!("/api/services/{}/logs", seg(name));
        if let Some(index) = previous {
          path.push_str(&format!("?previous={index}"));
        } else if let Some(container) = container {
          c.require_exec_v2_core().await?;
          path.push_str(&format!("?container={}", seg(&container)));
        }
        path
      } else {
        format!(
          "/api/logs/services?services={}",
          seg(&names.join(","))
        )
      };
      show_logs(c, &path, &args, j).await
    }
    ServiceCmd::Files { cmd: Some(cmd), .. } => {
      crate::files::run(c, cmd, j).await
    }
    ServiceCmd::Files { name, path, .. } => {
      let name = name.ok_or_else(|| {
        ApiError::invalid("请指定服务名")
          .suggest("wharf service files --help")
      })?;
      crate::files::list(c, &name, path.as_deref().unwrap_or(""), j)
        .await
    }
    ServiceCmd::Download { name, path, output } => {
      crate::files::download(c, &name, &path, output, j).await
    }
    ServiceCmd::Upload { name, local, path } => {
      crate::files::upload(c, &name, &local, &path, j).await
    }
    ServiceCmd::Stop { .. } | ServiceCmd::Start { .. } => {
      let (name, apply, stopped) = match cmd {
        ServiceCmd::Stop { name, apply } => (name, apply, true),
        ServiceCmd::Start { name, apply } => (name, apply, false),
        _ => unreachable!(),
      };
      let v: ServiceView =
        c.get(&format!("/api/services/{}", seg(&name))).await?;
      let spec = ServiceSpec { stopped, ..v.spec };
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Restart { name, container } => {
      if container.is_some() {
        c.require_exec_v2_core().await?;
      }
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/restart", seg(&name)),
          &container
            .map_or_else(|| json!({}), |c| json!({"container": c})),
        )
        .await?;
      finish_task(c, &r.run_id, true, j).await
    }
    ServiceCmd::History { name } => {
      let v: Vec<DeploymentView> = c
        .get(&format!("/api/services/{}/deployments", seg(&name)))
        .await?;
      out_quiet(
        j,
        &v,
        |v| v.iter().map(|d| d.id.to_string()).collect(),
        |v| {
          for d in v {
            let images: Vec<String> = d
              .commit
              .iter()
              .map(|c| format!("commit {}", &c[..c.len().min(12)]))
              .chain(d.images.iter().map(|i| {
                i.digest.clone().unwrap_or_else(|| i.image.clone())
              }))
              .collect();
            println!(
              "#{} {} {} {}  {}",
              d.id,
              d.created_at.format("%m-%d %H:%M"),
              d.server,
              d.run_id,
              if d.started {
                images.join(" ")
              } else {
                format!("未启动 {}", images.join(" "))
              }
            );
          }
        },
      );
      Ok(())
    }
    ServiceCmd::Deploy {
      name,
      container,
      image,
      compose,
      from_run,
      compose_url,
      server,
      port,
      add_port,
      rm_port,
      clear_ports,
      env,
      unset_env,
      clear_env,
      start_timeout,
      health_path,
      volume,
      unset_volume,
      unset_start_timeout,
      build,
      ops,
      apply,
    } => {
      let mut existing = match c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await
      {
        Ok(view) => Some(view),
        Err(CliError::Api(e)) if e.code == ErrorCode::NotFound => {
          None
        }
        Err(e) => return Err(e),
      };
      if let Some(view) = &mut existing
        && !(image.is_some()
          || compose.is_some()
          || from_run.is_some()
          || compose_url.is_some()
          || container.is_some()
          || server.is_some()
          || !port.is_empty()
          || !add_port.is_empty()
          || !rm_port.is_empty()
          || clear_ports
          || clear_env
          || !env.is_empty()
          || !unset_env.is_empty()
          || start_timeout.is_some()
          || unset_start_timeout
          || health_path.is_some()
          || !volume.is_empty()
          || !unset_volume.is_empty()
          || build.has_edits()
          || ops.stop_grace.is_some()
          || ops.unset_stop_grace
          || ops.stop_signal.is_some()
          || ops.unset_stop_signal
          || ops.init_cmd.is_some()
          || ops.unset_init_cmd
          || ops.init_timeout.is_some())
      {
        apply.check_read_only()?;
        wharf_api_types::filter_note(
          &mut view.note,
          &mut view.has_sealed_note,
          false,
        );
        out(j, view, pretty);
        return Ok(());
      }
      let existing = existing.map(|view| view.spec);
      let first_port = port
        .first()
        .or_else(|| add_port.first())
        .map(|p| parse_port(p))
        .transpose()?
        .and_then(|p| p.container)
        .or_else(|| existing.as_ref()?.ports.first()?.container);
      let mut built = crate::deploy::source(
        c,
        &name,
        &build,
        existing.as_ref().map(|s| &s.source),
        first_port,
        j,
      )
      .await?;
      let detected =
        built.as_mut().and_then(|built| built.detected.take());
      let default_port = built.as_ref().map(|b| b.default_port);
      let draft = match &from_run {
        Some(command) => {
          let d: wharf_api_types::view::ServiceDraft = c
            .post(
              "/api/convert/docker-run",
              &wharf_api_types::view::DockerRunRequest {
                command: command.clone(),
                name: Some(name.clone()),
              },
            )
            .await?;
          if !j && !print::is_quiet() {
            for w in &d.warnings {
              eprintln!("提醒：{w}");
            }
          }
          Some(d)
        }
        None => None,
      };
      let url_compose = match &compose_url {
        Some(url) => {
          Some(crate::deploy::fetch_compose(url, j).await?)
        }
        None => None,
      };
      let refresh_ports = compose.is_some();
      let source = match (image, compose, built) {
        (_, _, Some(b)) => Some(b.source),
        _ if draft.is_some() => {
          draft.as_ref().map(|d| d.source.clone())
        }
        _ if url_compose.is_some() => Some(Source::Compose {
          content: url_compose,
          file: None,
        }),
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
            ApiError::invalid(format!("服务 {name} 不存在，新建时需要 --image、--compose、--from-run、--compose-url、--dir 或 --git"))
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
            stopped: false,
            monitor: None,
            start_timeout_secs: None,
            log_alerts: vec![],
            port_checks: Default::default(),
            heartbeat: None,
            limits: None,
            auto_update: false,
            update_ignore: vec![],
            container: None,
            files: vec![],
            stop_grace_secs: None,
            stop_signal: None,
            init_cmd: None,
            init_timeout_secs: None,
          }
        }
      };
      let was_compose = matches!(spec.source, Source::Compose { .. });
      if let Some(source) = source {
        reconcile_source_switch(
          &mut spec,
          source,
          refresh_ports && port.is_empty(),
        );
      }
      if unset_start_timeout || start_timeout.is_some() {
        spec.start_timeout_secs =
          start_timeout.filter(|seconds| *seconds != 0);
      }
      if let Some(path) = health_path {
        spec.monitor.get_or_insert_with(Default::default).path = path;
      }
      if let Some(server) = server {
        spec.server = server;
      }
      if ops.unset_stop_grace || ops.stop_grace.is_some() {
        spec.stop_grace_secs = ops.stop_grace.filter(|n| *n != 0);
      }
      if ops.unset_stop_signal {
        spec.stop_signal = None;
      }
      if let Some(signal) = ops.stop_signal {
        spec.stop_signal = if signal.is_empty() {
          None
        } else {
          Some(wharf_api_types::compose::normalize_stop_signal(
            &signal,
          )?)
        };
      }
      if let Some(secs) = ops.init_timeout {
        spec.init_timeout_secs = (secs != 0).then_some(secs);
      }
      if ops.unset_init_cmd {
        spec.init_cmd = None;
        spec.init_timeout_secs = None;
      }
      if let Some(cmd) = ops.init_cmd {
        if cmd.is_empty() {
          spec.init_cmd = None;
          spec.init_timeout_secs = None;
        } else {
          spec.init_cmd = Some(cmd);
        }
      }
      let warnings = draft
        .as_ref()
        .map(|d| d.warnings.clone())
        .unwrap_or_default();
      if let Some(d) = draft {
        spec.ports = d.ports;
        spec.env = d.env;
        spec.container = None;
        spec.volumes = d.volumes;
        spec.limits = d.limits;
      }
      if let Some(container) = container {
        spec.container = Some(container);
      }
      list_edits::apply_port_edits(
        &mut spec.ports,
        &port,
        &add_port,
        &rm_port,
        clear_ports,
      )?;
      if clear_ports || !port.is_empty() || !rm_port.is_empty() {
        spec.port_checks.retain(|name, _| {
          spec.ports.iter().any(|port| &port.name == name)
        });
      }
      if !clear_ports
        && rm_port.is_empty()
        && (is_new && default_port.is_some() || was_compose)
        && !matches!(spec.source, Source::Compose { .. })
        && spec.ports.is_empty()
        && from_run.is_none()
      {
        let p = default_port
          .unwrap_or_else(|| crate::deploy::ExposedPort::tcp(8080));
        spec.ports = vec![PortSpec {
          name: if p.udp { "udp" } else { "http" }.into(),
          container: Some(p.port),
          host: None,
          udp: p.udp,
        }];
      }
      if clear_env {
        spec.env.clear();
      }
      for k in &unset_env {
        spec.env.remove(k);
      }
      for e in &env {
        let (k, v) = parse_kv(e, "--env")?;
        spec.env.insert(k, v);
      }
      for name in unset_volume {
        let index = spec
          .volumes
          .iter()
          .position(|v| v.name == name)
          .ok_or_else(|| {
            ApiError::invalid(format!("数据卷 {name} 不存在"))
          })?;
        spec.volumes.remove(index);
      }
      for arg in &volume {
        let v = parse_volume_arg(arg)?;
        spec.volumes.retain(|x| x.name != v.name);
        spec.volumes.push(v);
      }
      deploy_plan(c, name, spec, apply, j, warnings, detected).await
    }
    ServiceCmd::Move {
      name,
      to,
      abort,
      apply,
    } => {
      let view = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?;
      let mut spec = view.spec;
      let to = if abort {
        let migration = view.migration.ok_or_else(|| {
          ApiError::invalid(format!(
            "服务 {name} 当前没有进行中的迁移"
          ))
        })?;
        if migration.phase == "up_done" {
          return Err(ApiError::invalid(format!("服务 {name} 已在 {} 启动成功，不能直接撤销；如需迁回请执行 wharf service move {name} --to {}", migration.to, migration.from)).into());
        }
        migration.from
      } else {
        to.ok_or_else(|| {
          ApiError::invalid("需要指定 --to 或 --abort")
        })?
      };
      if spec.server == to {
        return Err(
          ApiError::invalid(format!("服务 {name} 已经在 {to} 上"))
            .into(),
        );
      }
      spec.server = to;
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::UpdateIgnore {
      name,
      image,
      all,
      major,
      clear,
      apply,
    } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      if !all && !major && !clear {
        apply.check_read_only()?;
        out(j, &spec.update_ignore, |rules| {
          for rule in rules {
            println!(
              "{}  {}",
              rule.image,
              match rule.scope {
                UpdateIgnoreScope::All => "全部",
                UpdateIgnoreScope::Major => "大版本",
              }
            );
          }
        });
        return Ok(());
      }
      if clear {
        spec
          .update_ignore
          .retain(|r| image.as_ref().is_some_and(|i| &r.image != i));
      } else {
        let image = match image {
          Some(image) => image,
          None => infer_ignore_image(&spec.source)?,
        };
        let scope = if all {
          UpdateIgnoreScope::All
        } else {
          UpdateIgnoreScope::Major
        };
        spec.update_ignore.retain(|rule| rule.image != image);
        spec.update_ignore.push(UpdateIgnoreSpec { image, scope });
        spec.update_ignore.sort();
      }
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Monitor {
      name,
      start_timeout,
      path,
      port,
      expect,
      keyword,
      header,
      unset_header,
      clear_headers,
      interval,
      retries,
      off,
      on,
      unset_port,
      unset_expect,
      unset_keyword,
      unset_start_timeout,
      apply,
    } => {
      let view = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?;
      let mut spec = view.spec;
      let edit_monitor = off
        || on
        || unset_port
        || unset_expect
        || unset_keyword
        || path.is_some()
        || port.is_some()
        || expect.is_some()
        || keyword.is_some()
        || !header.is_empty()
        || !unset_header.is_empty()
        || clear_headers
        || interval.is_some()
        || retries.is_some();
      if !edit_monitor
        && start_timeout.is_none()
        && !unset_start_timeout
      {
        apply.check_read_only()?;
        return crate::service_checks::show_monitor(
          &name,
          &spec,
          view.monitor.as_ref(),
          j,
        );
      }
      if unset_start_timeout || start_timeout.is_some() {
        spec.start_timeout_secs =
          start_timeout.filter(|seconds| *seconds != 0);
      }
      let enable = on
        || path.is_some()
        || port.as_ref().is_some_and(|p| !p.trim().is_empty())
        || expect.is_some_and(|code| code != 0)
        || keyword.as_ref().is_some_and(|k| !k.is_empty())
        || !header.is_empty()
        || interval.is_some_and(|secs| secs != 0)
        || retries.is_some();
      if edit_monitor && (off || enable || spec.monitor.is_some()) {
        if off {
          spec.monitor = None;
        } else {
          let m = spec.monitor.get_or_insert_with(Default::default);
          if let Some(path) = path {
            m.path = path;
          }
          if unset_port || port.is_some() {
            m.port = port.filter(|port| !port.trim().is_empty());
          }
          if unset_expect || expect.is_some() {
            m.expect = expect.filter(|expect| *expect != 0);
          }
          if unset_keyword || keyword.is_some() {
            m.keyword = keyword.filter(|keyword| !keyword.is_empty());
          }
          if let Some(secs) = interval {
            m.interval_secs = (secs != 0).then_some(secs);
          }
          if retries.is_some() {
            m.retries = retries;
          }
          if clear_headers {
            m.headers.clear();
          }
          for key in unset_header {
            m.headers
              .retain(|old, _| !old.eq_ignore_ascii_case(&key));
          }
          for item in header {
            let split = item.find([':', '=']).ok_or_else(|| {
              ApiError::invalid(
                "请求头要写成 Key: Value 或 Key=Value",
              )
            })?;
            let (key, value) =
              (item[..split].trim(), item[split + 1..].trim());
            m.headers.retain(|old, _| !old.eq_ignore_ascii_case(key));
            m.headers.insert(key.to_string(), value.to_string());
          }
        }
      }
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Limits {
      name,
      container,
      memory,
      cpus,
      off,
      unset_memory,
      unset_cpus,
      apply,
    } => {
      if cpus.is_some_and(|n| {
        !n.is_finite() || n < 0.0 || n * 1000.0 > f64::from(u32::MAX)
      }) {
        return Err(
          ApiError::invalid("CPU 上限不合法")
            .with_hint("填写有限的非负核数，0 表示去掉 CPU 上限")
            .into(),
        );
      }
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      if container.is_none()
        && memory.is_none()
        && cpus.is_none()
        && !off
        && !unset_memory
        && !unset_cpus
      {
        apply.check_read_only()?;
        out(
          j,
          &json!({"service": name, "limits": spec.limits}),
          pretty,
        );
        return Ok(());
      }
      if let Some(container) = container {
        spec.container = Some(container);
      }
      if off {
        spec.limits = None;
      } else {
        let limits =
          spec.limits.get_or_insert(wharf_api_types::spec::Limits {
            memory_mb: None,
            cpu_milli: None,
          });
        if unset_memory || memory.is_some() {
          limits.memory_mb = memory.filter(|memory| *memory != 0);
        }
        if unset_cpus || cpus.is_some() {
          limits.cpu_milli = cpus
            .filter(|cpus| *cpus != 0.0)
            .map(|cpus| (cpus * 1000.0).round() as u32);
        }
      }
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::File {
      name,
      container,
      path,
      file,
      raw,
      rm,
      apply,
    } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      let Some(path) = path else {
        apply.check_read_only()?;
        let list: Vec<Value> = spec
          .files
          .iter()
          .map(
            |f| json!({ "path": f.path, "bytes": f.content.len() }),
          )
          .collect();
        out(j, &list, |l| {
          if l.is_empty() {
            println!("服务 {name} 没有配置文件");
          }
          for f in l {
            println!(
              "{}  {} 字节",
              f["path"].as_str().unwrap_or(""),
              f["bytes"]
            );
          }
        });
        return Ok(());
      };
      let missing = || -> CliError {
        ApiError::not_found(format!(
          "服务 {name} 没有配置文件 {path}"
        ))
        .suggest(format!("wharf service file {name}"))
        .into()
      };
      if rm {
        let before = spec.files.len();
        spec.files.retain(|f| f.path != path);
        if spec.files.len() == before {
          return Err(missing());
        }
      } else if let Some(src) = file {
        let content = (if src == "-" {
          std::io::read_to_string(std::io::stdin())
        } else {
          std::fs::read_to_string(&src)
        })
        .map_err(|e| {
          ApiError::invalid(format!("读不了文件 {src}：{e}"))
            .with_hint("只支持文本文件；从标准输入读用 --file -")
        })?;
        let next =
          wharf_api_types::spec::FileSpec { path, content, raw };
        if let Some(f) =
          spec.files.iter_mut().find(|f| f.path == next.path)
        {
          *f = next;
        } else {
          spec.files.push(next);
        }
      } else {
        apply.check_read_only()?;
        let f = spec
          .files
          .iter()
          .find(|f| f.path == path)
          .ok_or_else(missing)?;
        out(j, f, |f| print!("{}", f.content));
        return Ok(());
      }
      if let Some(container) = container {
        spec.container = Some(container);
      }
      changes(
        c,
        vec![Change::UpsertService {
          pins: None,
          commit: None,
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Rm {
      name,
      purge_data,
      apply,
    } => {
      changes(
        c,
        vec![Change::RemoveService { name, purge_data }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Rebuild {
      name,
      no_wait,
      sync_gh_token,
    } => {
      if sync_gh_token {
        let v: ServiceView =
          c.get(&format!("/api/services/{}", seg(&name))).await?;
        if !matches!(&v.spec.source, Source::Build(b) if b.git.as_ref().and_then(|g| g.token_secret.as_deref()) == Some(crate::gh::SECRET))
        {
          return Err(
            ApiError::invalid("该服务没有使用 GITHUB_TOKEN").into(),
          );
        }
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

pub(crate) fn fmt_ms(ms: i64) -> String {
  chrono::DateTime::from_timestamp_millis(ms)
    .map(|t| {
      t.with_timezone(&chrono::Local)
        .format("%m-%d %H:%M")
        .to_string()
    })
    .unwrap_or_default()
}

async fn gateway(
  c: &Client,
  cmd: GatewayCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    GatewayCmd::List(filters) => {
      let v: Vec<GatewayView> = c.get(&filters.path()).await?;
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
          "# {}\n{}",
          if v["kind"] == "cloudflare_tunnel" {
            "cloudflared"
          } else {
            "Caddyfile"
          },
          v["config"]
            .as_str()
            .or_else(|| v["caddyfile"].as_str())
            .unwrap_or_default()
        );
        println!(
          "# compose.yaml\n{}",
          v["compose"].as_str().unwrap_or_default()
        );
      });
      Ok(())
    }
    GatewayCmd::RotateLink {
      name,
      link_token,
      cert,
      apply,
      ..
    } => {
      let both = !link_token && !cert;
      let response = c
        .rotate_link(&name, link_token || both, cert || both)
        .await?;
      if apply.apply {
        if !j && !print::is_quiet() {
          print::rotate_link(&response);
        }
        plan_and_maybe_apply(c, PlanRequest::default(), apply, j)
          .await
      } else {
        out(j, &response, print::rotate_link);
        Ok(())
      }
    }
    GatewayCmd::Logs(args) => {
      crate::access_logs::gateway(c, args, j).await
    }
    GatewayCmd::ErrorPage {
      name,
      file,
      apply,
      default,
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      if file.is_none() && !default {
        apply.check_read_only()?;
        out(
          j,
          &json!({"gateway": name, "error_page": spec.error_page}),
          pretty,
        );
        return Ok(());
      }
      spec.error_page = match file {
        None => None,
        Some(path) => Some(
          (if path == "-" {
            std::io::read_to_string(std::io::stdin())
          } else {
            std::fs::read_to_string(&path)
          })
          .map_err(|e| {
            ApiError::invalid(format!("读不了文件 {path}：{e}"))
              .with_hint("检查路径；从标准输入读用 --file -")
          })?,
        ),
      };
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Wildcard {
      name,
      zone,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      let Some(zone) = zone else {
        apply.check_read_only()?;
        out(j, &spec.wildcard, pretty);
        return Ok(());
      };
      let zone = wharf_api_types::normalize_host(&zone);
      if off {
        spec.wildcard.retain(|z| z != &zone);
      } else if !spec.wildcard.contains(&zone) {
        spec.wildcard.push(zone);
      }
      spec.wildcard.sort();
      spec.wildcard.dedup();
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Timeouts(args) => {
      entry_protection::timeouts(c, args, j).await
    }
    GatewayCmd::TrustedProxies {
      name,
      cloudflare,
      cluster,
      add,
      rm,
      off,
      apply,
    } => {
      use wharf_api_types::trusted_proxies::parse_cidr;

      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      if cloudflare.is_none()
        && cluster.is_none()
        && add.is_empty()
        && rm.is_empty()
        && !off
      {
        apply.check_read_only()?;
        out(j, &spec.trusted_proxies, pretty);
        return Ok(());
      }
      if off {
        spec.trusted_proxies = None;
      } else {
        let mut proxies =
          spec.trusted_proxies.take().unwrap_or_default();
        proxies.cloudflare = cloudflare.unwrap_or(proxies.cloudflare);
        proxies.cluster = cluster.unwrap_or(proxies.cluster);
        proxies.normalize()?;
        for cidr in add {
          let cidr = parse_cidr(&cidr)?.to_string();
          if !proxies.cidrs.contains(&cidr) {
            proxies.cidrs.push(cidr);
          }
        }
        for cidr in rm {
          let cidr = parse_cidr(&cidr)?.to_string();
          proxies.cidrs.retain(|current| current != &cidr);
        }
        proxies.normalize()?;
        spec.trusted_proxies =
          (!proxies.is_empty()).then_some(proxies);
      }
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Forward {
      name,
      listen,
      udp,
      service,
      port,
      upstream,
      rm,
      apply,
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      if !rm && service.is_none() && upstream.is_none() {
        apply.check_read_only()?;
        let list: Vec<_> = spec
          .layer4
          .iter()
          .filter(|f| {
            listen.is_none_or(|port| f.listen == port)
              && (!udp || f.udp)
          })
          .collect();
        out(j, &list, pretty);
        return Ok(());
      }
      let listen =
        listen.ok_or_else(|| ApiError::invalid("要给 --listen"))?;
      let before = spec.layer4.len();
      spec.layer4.retain(|f| f.listen != listen || f.udp != udp);
      if rm {
        if before == spec.layer4.len() {
          let protocol = if udp { "UDP 端口" } else { "端口" };
          return Err(
            ApiError::invalid(format!(
              "入口 {name} 上没有{protocol} {listen} 的四层转发"
            ))
            .into(),
          );
        }
      } else {
        if service.is_none() && upstream.is_none() {
          return Err(
            ApiError::invalid("要给 --service 或 --upstream").into(),
          );
        }
        spec.layer4.push(wharf_api_types::spec::Layer4Forward {
          listen,
          udp,
          service,
          port,
          upstream,
        });
      }
      spec.layer4.sort_by_key(|f| (f.udp, f.listen));
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
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
      no_default,
      unset_account,
      unset_email,
      unset_image,
      unset_http_port,
      unset_https_port,
      apply,
    } => {
      let gateways: Vec<GatewayView> = c.get("/api/gateways").await?;
      let old = gateways.iter().find(|g| g.name == name);
      if let Some(old) = old
        && !(server.is_some()
          || kind.is_some()
          || account.is_some()
          || default
          || no_default
          || http_port.is_some()
          || https_port.is_some()
          || email.is_some()
          || image.is_some()
          || tls.is_some()
          || unset_email
          || unset_image
          || unset_account
          || unset_http_port
          || unset_https_port)
      {
        apply.check_read_only()?;
        out(j, old, pretty);
        return Ok(());
      }
      let old = old.map(|g| &g.spec);
      let email = gateway_text(email, unset_email);
      let image = gateway_text(image, unset_image);
      let account = gateway_text(account, unset_account);
      let http_port = gateway_port(http_port, unset_http_port, 80);
      let https_port =
        gateway_port(https_port, unset_https_port, 443);
      let kind = kind.map(|k| match k.as_str() {
        "cloudflare_tunnel" => GatewayKind::CloudflareTunnel,
        _ => GatewayKind::Caddy,
      });
      let tls = tls.map(|t| match t.as_str() {
        "internal" => GatewayTls::Internal,
        "off" => GatewayTls::Off,
        _ => GatewayTls::Auto,
      });
      let spec = match old {
        Some(old) => {
          if kind.is_some_and(|k| k != old.kind) {
            return Err(
              ApiError::invalid("不能改入口类型，删掉重建")
                .suggest(format!("wharf gateway rm {name}"))
                .into(),
            );
          }
          GatewaySpec {
            server: server.unwrap_or_else(|| old.server.clone()),
            default: default || !no_default && old.default,
            http_port: http_port.unwrap_or(old.http_port),
            https_port: https_port.unwrap_or(old.https_port),
            email: email.unwrap_or_else(|| old.email.clone()),
            image: image.unwrap_or_else(|| old.image.clone()),
            tls: tls.unwrap_or(old.tls),
            account: account.unwrap_or_else(|| old.account.clone()),
            ..old.clone()
          }
        }
        None => {
          let server = server.ok_or_else(|| {
            ApiError::invalid("新入口要给 --server").suggest(format!(
              "wharf gateway add {name} --server <服务器>"
            ))
          })?;
          let kind = kind.unwrap_or(GatewayKind::Caddy);
          // 隧道网关只有一个厂商账号时自动选它。
          let account = match (kind, account) {
            (GatewayKind::CloudflareTunnel, None) => {
              let accounts: Vec<AccountView> =
                c.get("/api/accounts").await?;
              match accounts.as_slice() {
                [only] => Some(only.name.clone()),
                [] => {
                  return Err(
                    ApiError::invalid(
                      "还没有厂商账号，隧道要建在账号下",
                    )
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
            (_, account) => account.flatten(),
          };
          GatewaySpec {
            kind,
            server,
            default,
            http_port: http_port.flatten(),
            https_port: https_port.flatten(),
            email: email.flatten(),
            image: image.flatten(),
            tls: tls.unwrap_or_default(),
            account,
            error_page: None,
            wildcard: vec![],
            layer4: vec![],
            trusted_proxies: None,
            read_header_timeout: None,
            idle_timeout: None,
            grace_period: None,
          }
        }
      };
      // 默认入口只能有一个：设了新的，同一个计划里取消旧的。
      let mut list = Vec::new();
      if default {
        for g in
          gateways.iter().filter(|g| g.name != name && g.spec.default)
        {
          list.push(Change::UpsertGateway {
            name: g.name.clone(),
            spec: GatewaySpec {
              default: false,
              ..g.spec.clone()
            },
          });
        }
      }
      list.push(Change::UpsertGateway { name, spec });
      changes(c, list, apply, j).await
    }
    GatewayCmd::Rm { name, apply } => {
      changes(c, vec![Change::RemoveGateway { name }], apply, j).await
    }
  }
}

fn gateway_text(
  value: Option<String>,
  unset: bool,
) -> Option<Option<String>> {
  if unset {
    return Some(None);
  }
  value.map(|value| {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
  })
}

fn gateway_port(
  value: Option<u16>,
  unset: bool,
  default: u16,
) -> Option<Option<u16>> {
  if unset {
    return Some(None);
  }
  value.map(|value| (value != 0 && value != default).then_some(value))
}

fn failover_label(r: &RouteView) -> &'static str {
  match (r.on_backup, r.failover_pinned) {
    (true, Some(_)) => "（备用 · 手动锁定）",
    (true, None) => "（备用）",
    _ => "",
  }
}

fn print_failover_pending(r: &RouteView) {
  if let Some(p) = &r.failover_pending {
    let target = if p.target_backup {
      "备用入口"
    } else {
      "主网关"
    };
    println!("    待切换到{target}（已尝试 {} 次）", p.attempts);
    if let Some(error) = &p.last_error {
      println!("    {error}");
    }
  }
}

async fn route(c: &Client, cmd: RouteCmd, j: bool) -> CliResult<()> {
  match cmd {
    RouteCmd::Failover {
      hostname,
      to,
      no_verify,
      force,
      reason,
    } => {
      use wharf_api_types::view::{
        FailoverTarget, RouteFailoverRequest, RouteFailoverView,
      };
      let path =
        format!("/api/routes/{}/failover", seg(hostname.trim()));
      let value: RouteFailoverView = if let Some(to) = to {
        let target = match to.as_str() {
          "backup" => FailoverTarget::Backup,
          "primary" => FailoverTarget::Primary,
          "auto" => FailoverTarget::Auto,
          _ => {
            return Err(
              ApiError::invalid(
                "主备切换目标须为 backup、primary 或 auto",
              )
              .into(),
            );
          }
        };
        c.post_timeout(
          &path,
          &RouteFailoverRequest {
            target,
            verify_before_dns: !no_verify,
            force,
            reason,
          },
          std::time::Duration::from_secs(120),
        )
        .await?
      } else {
        c.get(&path).await?
      };
      out(j, &value, |v| {
        let current = if v.on_backup {
          &v.backup_gateway
        } else {
          &v.primary_gateway
        };
        let pin = if v.pinned.is_some() {
          "（手动锁定）"
        } else {
          ""
        };
        println!(
          "{}  当前：{current}{pin}  主：{}  备：{}",
          v.hostname, v.primary_gateway, v.backup_gateway
        );
        if let Some(checked) = &v.verification {
          println!("  预验：{checked}");
        }
        if let Some(run) = &v.run_id {
          println!("  执行记录：{run}");
        }
      });
      Ok(())
    }
    RouteCmd::Logs(args) => {
      crate::access_logs::route(c, args, j).await
    }
    RouteCmd::DnsCheck { hostname } => {
      crate::external::dns(
        c,
        &wharf_api_types::normalize_host(&hostname),
        j,
      )
      .await
    }
    RouteCmd::Note { host, args } => {
      crate::note::run(c, "route", &host, args, j).await
    }
    RouteCmd::List(filters) => {
      let mut v: Vec<RouteView> = c.get(&filters.path()).await?;
      if print::is_quiet() {
        for route in &v {
          println!("{}", route.spec.hostname);
        }
        return Ok(());
      }
      for route in &mut v {
        wharf_api_types::filter_note(
          &mut route.note,
          &mut route.has_sealed_note,
          false,
        );
      }
      out(j, &v, |v| {
        for r in v {
          println!(
            "{}  →  {}  经 {}{}{}",
            r.url,
            r.spec
              .redirect
              .as_deref()
              .or(r.spec.upstream.as_deref())
              .unwrap_or(&r.spec.service),
            r.gateway.as_deref().unwrap_or("-"),
            failover_label(r),
            r.spec
              .expires_at
              .map(|ms| {
                if ms <= chrono::Utc::now().timestamp_millis() {
                  "（临时分享，已失效）".to_string()
                } else {
                  format!(
                    "（临时分享，{} 到期）",
                    chrono::DateTime::from_timestamp_millis(ms)
                      .unwrap()
                      .with_timezone(&chrono::Local)
                      .format("%m-%d %H:%M")
                  )
                }
              })
              .unwrap_or_default()
              + if r
                .spec
                .sso
                .as_ref()
                .is_some_and(|s| s.mode
                  == wharf_api_types::spec::SsoMode::Header)
              {
                "（门禁 · 传用户名）"
              } else if r.spec.sso.as_ref().is_some_and(|s| {
                s.mode == wharf_api_types::spec::SsoMode::Oidc
              }) {
                "（OIDC 登录）"
              } else if r.spec.sso.as_ref().is_some_and(|s| s.public)
              {
                "（公开 · 代登录入口）"
              } else if r.spec.sso.is_some() {
                "（门禁）"
              } else {
                ""
              }
          );
          if let Some(note) = &r.note {
            println!("    备注：{note}");
          }
          print_failover_pending(r);
          if let Some(ttl) = r.spec.dns_ttl {
            println!("    DNS TTL：{ttl}");
          }
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
      redirect,
      port,
      gateway,
      backup_gateway,
      failover_minutes,
      no_failover_minutes,
      dns_ttl,
      no_dns_ttl,
      auth,
      no_auth,
      paths,
      no_paths,
      add_path,
      rm_path,
      tunnel,
      no_tunnel,
      internal,
      no_internal,
      protection,
      unset_port,
      unset_backup_gateway,
      apply,
    } => {
      let host = wharf_api_types::normalize_host(&hostname);
      let mut old = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| r.spec.hostname == host);
      if let Some(old) = &mut old
        && !(service.is_some()
          || upstream.is_some()
          || redirect.is_some()
          || port.is_some()
          || unset_port
          || gateway.is_some()
          || backup_gateway.is_some()
          || unset_backup_gateway
          || failover_minutes.is_some()
          || no_failover_minutes
          || dns_ttl.is_some()
          || no_dns_ttl
          || auth
          || no_auth
          || !paths.is_empty()
          || !add_path.is_empty()
          || !rm_path.is_empty()
          || no_paths
          || tunnel
          || no_tunnel
          || internal
          || no_internal
          || protection.has_edits())
      {
        apply.check_read_only()?;
        wharf_api_types::filter_note(
          &mut old.note,
          &mut old.has_sealed_note,
          false,
        );
        out(j, old, pretty);
        return Ok(());
      }
      let old = old.map(|r| r.spec);
      let args = RouteAddArgs {
        hostname: host,
        service,
        upstream,
        redirect,
        port,
        gateway,
        backup_gateway: backup_gateway
          .or_else(|| unset_backup_gateway.then(String::new)),
        dns_ttl: dns_ttl.map(Some).or(no_dns_ttl.then_some(None)),
        failover_minutes: failover_minutes
          .map(Some)
          .or(no_failover_minutes.then_some(None)),
        auth: flag(auth, no_auth),
        paths: if no_paths {
          Some(vec![])
        } else if paths.is_empty() {
          None
        } else {
          Some(
            paths
              .iter()
              .map(|p| parse_path_route(p))
              .collect::<Result<_, _>>()?,
          )
        },
        tunnel: flag(tunnel, no_tunnel),
        internal: flag(internal, no_internal),
      };
      let mut spec = route_add_spec(old, args)?;
      list_edits::apply_path_edits(
        &mut spec.paths,
        &add_path,
        &rm_path,
      )?;
      if unset_port {
        spec.port = None;
      }
      protection.set(&mut spec);
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Sso {
      name,
      mode,
      skip,
      add_skip,
      rm_skip,
      add_redirect,
      rm_redirect,
      trust_internal,
      no_trust_internal,
      header,
      file,
      public,
      redirect,
      off,
      unset_skip,
      unset_header,
      apply,
    } => {
      let route = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| {
          r.spec.hostname == wharf_api_types::normalize_host(&name)
        })
        .ok_or_else(|| {
          ApiError::not_found(format!("域名 {name} 不存在"))
        })?;
      let mut spec = route.spec;
      let has_list_edits =
        [&add_skip, &rm_skip, &add_redirect, &rm_redirect]
          .iter()
          .any(|values| !values.is_empty());
      let Some(mode) =
        mode.or_else(|| off.then(|| "off".to_string()))
      else {
        if has_list_edits {
          let sso = spec.sso.as_mut().ok_or_else(|| {
            ApiError::invalid("请先用 --mode 设置门禁方式")
          })?;
          list_edits::apply_sso_list_edits(
            sso,
            &add_skip,
            &rm_skip,
            &add_redirect,
            &rm_redirect,
          )?;
          return changes(
            c,
            vec![Change::UpsertRoute { spec }],
            apply,
            j,
          )
          .await;
        }
        apply.check_read_only()?;
        if !j
          && let Some(sso) = &spec.sso
          && sso.mode == SsoMode::Login
          && let Some(login) = &sso.login
        {
          let accounts = if login.use_account {
            match c
              .get::<Vec<AppAccountView>>("/api/sso/accounts")
              .await
            {
              Ok(accounts) => Some(accounts),
              Err(CliError::Api(e))
                if e.code == ErrorCode::Forbidden =>
              {
                None
              }
              Err(e) => return Err(e),
            }
          } else {
            None
          };
          println!(
            "方式：代登录（{}）",
            if sso.public { "公开站点" } else { "门禁" }
          );
          println!(
            "入口：https://{}/_wharf/login → {}",
            spec.hostname,
            login.entry.as_deref().unwrap_or("/")
          );
          if let Some(script) = &login.script {
            let runtime = match script.runtime {
              ScriptRuntime::Python => "python",
              ScriptRuntime::Node => "node",
              ScriptRuntime::Shell => "shell",
            };
            println!(
              "登录：脚本（{runtime}，超时 {} 秒）",
              script.timeout_secs
            );
          } else {
            println!("登录：{} 步", login.steps.len());
          }
          if let Some(accounts) = accounts {
            if let Some(a) = accounts.iter().find(|a| {
              a.domains
                .iter()
                .any(|d| d.is_default && d.hostname == spec.hostname)
            }) {
              println!(
                "账号：使用默认账号 {}（{}）",
                a.name, a.username
              );
            } else {
              println!("账号：没有默认账号，代登录会失败");
            }
          }
          if let Some(takeover) = &login.takeover {
            let skip = if takeover.skip_query.is_empty() {
              String::new()
            } else {
              format!(
                "带 {} 参数时不接管，",
                takeover.skip_query.join("、")
              )
            };
            println!(
              "接管：{}（{skip}回退原生页 {} 分钟）",
              takeover.paths.join("、"),
              takeover.native_minutes
            );
          }
          if let Some(last) = &route.sso_login
            && let Some(at) =
              chrono::DateTime::from_timestamp_millis(last.at)
          {
            println!(
              "上次登录：{} {}",
              beijing_time(at),
              if last.ok { "成功" } else { "失败" }
            );
          }
          return Ok(());
        }
        out(j, &spec.sso, |sso| {
          println!(
            "{}",
            sso
              .as_ref()
              .map(|s| if s.mode == wharf_api_types::spec::SsoMode::Oidc {
                format!(
                  "用 Wharf 账号登录（OIDC）{}，看接入信息：wharf sso oidc {}",
                  if s.public { "，公开站点" } else { "，加门禁" },
                  spec.hostname
                )
              } else if s.public {
                format!(
                  "公开站点，代登录入口：https://{}/_wharf/login",
                  spec.hostname
                )
              } else {
                format!(
                  "门禁：已开启{}",
                  if s.skip_paths.is_empty() {
                    String::new()
                  } else {
                    format!("，排除 {}", s.skip_paths.join("、"))
                  }
                )
              })
              .unwrap_or_else(|| "门禁：没开".into())
          )
        });
        return Ok(());
      };
      if mode == "off" {
        if file.is_some() || !redirect.is_empty() || has_list_edits {
          return Err(
            ApiError::invalid("关闭门禁时不能增删门禁设置").into(),
          );
        }
        spec.sso = None;
        return changes(
          c,
          vec![Change::UpsertRoute { spec }],
          apply,
          j,
        )
        .await;
      }
      let old = spec.sso.as_ref();
      let skip = if skip.is_empty() && !unset_skip {
        old.map(|s| s.skip_paths.clone()).unwrap_or_default()
      } else {
        skip
      };
      let header = if !unset_header && mode == "header" {
        header.or_else(|| old.and_then(|s| s.header.clone()))
      } else {
        header
      };
      let redirect = if redirect.is_empty() && mode == "oidc" {
        old
          .and_then(|s| s.oidc.as_ref())
          .map(|oidc| oidc.redirect_uris.clone())
          .unwrap_or_default()
      } else {
        redirect
      };
      spec.sso = Some(wharf_api_types::spec::SsoSpec {
        login: if mode == "login" {
          if let Some(file) = file {
            let text = if file == "-" {
              std::io::read_to_string(std::io::stdin())
                .map_err(|_| ApiError::invalid("读取登录配置失败"))?
            } else {
              std::fs::read_to_string(file)
                .map_err(|_| ApiError::invalid("读取登录配置失败"))?
            };
            let value: serde_json::Value =
              serde_yaml_ng::from_str(&text).map_err(|_| {
                ApiError::invalid("登录配置不是有效的 YAML 或 JSON")
              })?;
            Some(serde_json::from_value(value).map_err(|_| {
              ApiError::invalid("登录配置字段不符合要求")
            })?)
          } else {
            Some(old.and_then(|s| s.login.clone()).ok_or_else(
              || ApiError::invalid("login 方式需要 --file"),
            )?)
          }
        } else {
          if file.is_some() {
            return Err(
              ApiError::invalid("只有 login 方式才能用 --file")
                .into(),
            );
          }
          None
        },
        oidc: if mode == "oidc" {
          if redirect.is_empty() && add_redirect.is_empty() {
            return Err(
                ApiError::invalid("oidc 方式至少要一个 --redirect")
                  .with_hint("回调路径看应用的 OIDC 文档，例如 Grafana 是 /login/generic_oauth")
                  .into(),
              );
          }
          Some(wharf_api_types::spec::OidcClientSpec {
            redirect_uris: redirect,
          })
        } else if !redirect.is_empty() {
          return Err(
            ApiError::invalid("只有 oidc 方式才能用 --redirect")
              .into(),
          );
        } else {
          None
        },
        mode: if mode == "oidc" {
          wharf_api_types::spec::SsoMode::Oidc
        } else if mode == "login" {
          wharf_api_types::spec::SsoMode::Login
        } else if mode == "header" {
          wharf_api_types::spec::SsoMode::Header
        } else {
          wharf_api_types::spec::SsoMode::Gate
        },
        header,
        trust_internal: !public
          && !no_trust_internal
          && (trust_internal
            || spec.sso.as_ref().is_some_and(|s| s.trust_internal)),
        skip_paths: skip,
        public,
      });
      if let Some(sso) = spec.sso.as_mut() {
        list_edits::apply_sso_list_edits(
          sso,
          &add_skip,
          &rm_skip,
          &add_redirect,
          &rm_redirect,
        )?;
      }
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Guard {
      name,
      rate,
      no_rate,
      block,
      no_block,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| {
          r.spec.hostname == wharf_api_types::normalize_host(&name)
        })
        .ok_or_else(|| {
          ApiError::not_found(format!("路由 {name} 不存在"))
            .suggest("wharf route list")
        })?
        .spec;
      if rate.is_none() && !no_rate && !block && !no_block && !off {
        apply.check_read_only()?;
        out(
          j,
          &json!({"rate_limit": spec.rate_limit, "block_scanners": spec.block_scanners}),
          pretty,
        );
        return Ok(());
      }
      if rate.is_some() || no_rate || off {
        spec.rate_limit = rate;
      }
      if block || no_block || off {
        spec.block_scanners = block;
      }
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Cert { name, retry } => {
      use wharf_api_types::view::{CertState, CertStatus};
      let host = seg(&wharf_api_types::normalize_host(&name));
      let path = format!("/api/routes/{host}/cert");
      if retry {
        let v: serde_json::Value = c
          .post_timeout(
            &format!("{path}/retry"),
            &serde_json::json!({}),
            std::time::Duration::from_secs(120),
          )
          .await?;
        out(j, &v, |v| {
          println!(
            "已让入口 {} 重新申请证书，1 到 3 分钟后执行 wharf route cert {name} 查看",
            v["gateway"].as_str().unwrap_or_default()
          );
        });
        return Ok(());
      }
      let st: CertStatus = c.get(&path).await?;
      let at = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(ms)
          .map(|t| {
            t.with_timezone(&chrono::Local)
              .format("%m-%d %H:%M:%S")
              .to_string()
          })
          .unwrap_or_default()
      };
      out(j, &st, |st| {
        let state = match st.state {
          CertState::Ok => "已签好",
          CertState::Obtaining => "申请中",
          CertState::Failed => "申请失败，网关会自动重试",
          CertState::Unknown => "最近的日志里没有申请记录",
        };
        println!("{}（入口 {}）：{state}", st.hostname, st.gateway);
        if let Some(t) = st.since {
          println!("  开始申请：{}", at(t));
        }
        if st.state == CertState::Failed || st.error.is_some() {
          if let Some(t) = st.failed_at {
            println!(
              "  上次失败：{}，已失败 {} 次",
              at(t),
              st.attempts
            );
          }
          if let Some(r) = &st.reason {
            println!("  原因：{r}");
          }
          if let Some(e) = &st.error {
            println!("  报错：{e}");
          }
        }
        if let Some(t) = st.next_retry_at {
          println!("  下次自动重试：{}", at(t));
        }
        if matches!(st.state, CertState::Failed | CertState::Unknown)
        {
          println!(
            "  立刻重试：wharf route cert {} --retry",
            st.hostname
          );
        }
      });
      Ok(())
    }
    RouteCmd::Caddy {
      name,
      file,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| {
          r.spec.hostname == wharf_api_types::normalize_host(&name)
        })
        .ok_or_else(|| {
          ApiError::not_found(format!("路由 {name} 不存在"))
            .suggest("wharf route list")
        })?
        .spec;
      if file.is_none() && !off {
        apply.check_read_only()?;
        out(j, &serde_json::json!({ "caddy": spec.caddy }), |_| {
          match &spec.caddy {
            Some(text) => print!("{text}"),
            None => println!("没有自定义配置"),
          }
        });
        return Ok(());
      }
      spec.caddy = match file {
        None => None,
        Some(path) => {
          let text = (if path == "-" {
            std::io::read_to_string(std::io::stdin())
          } else {
            std::fs::read_to_string(&path)
          })
          .map_err(|e| {
            ApiError::invalid(format!("读不了文件 {path}：{e}"))
              .with_hint("检查路径；从标准输入读用 --file -")
          })?;
          (!text.trim().is_empty()).then_some(text)
        }
      };
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Rm { hostname, apply } => {
      let hostname = wharf_api_types::normalize_host(&hostname);
      changes(c, vec![Change::RemoveRoute { hostname }], apply, j)
        .await
    }
  }
}

/// `/ws=svc`、`/ws=svc:port`、`/ws=127.0.0.1:17891`。目标的主机部分带 `.`、`:` 或是
/// `localhost` 时当作上游地址（服务名里不会有这些）。
/// 一对开关参数：给了 `--x` 是 true，给了 `--no-x` 是 false，都没给是 None。
fn flag(on: bool, off: bool) -> Option<bool> {
  (on || off).then_some(on)
}

/// `wharf route add` 的参数；`None` 表示没给。
struct RouteAddArgs {
  hostname: String,
  service: Option<String>,
  upstream: Option<String>,
  redirect: Option<String>,
  port: Option<String>,
  gateway: Option<String>,
  backup_gateway: Option<String>,
  dns_ttl: Option<Option<u32>>,
  failover_minutes: Option<Option<u32>>,
  auth: Option<bool>,
  paths: Option<Vec<PathRoute>>,
  tunnel: Option<bool>,
  internal: Option<bool>,
}

/// 新建或修改路由：修改已有域名时只改给出的参数。
fn route_add_spec(
  old: Option<RouteSpec>,
  a: RouteAddArgs,
) -> CliResult<RouteSpec> {
  let retarget = a.service.is_some()
    || a.upstream.is_some()
    || a.redirect.is_some();
  let mut spec = match old {
    Some(old) => old,
    None if !retarget => {
      return Err(
        ApiError::invalid(
          "新域名要给 --service、--upstream 或 --redirect 之一",
        )
        .suggest(format!(
          "wharf route add {} --service <服务>",
          a.hostname
        ))
        .into(),
      );
    }
    None => RouteSpec {
      hostname: a.hostname.clone(),
      service: String::new(),
      upstream: None,
      port: None,
      gateway: None,
      backup_gateway: None,
      dns_ttl: None,
      failover_minutes: None,
      sso: None,
      auth: false,
      paths: vec![],
      caddy: None,
      link: Default::default(),
      redirect: None,
      rate_limit: None,
      block_scanners: false,
      internal: false,
      core_mesh_only: false,
      cf_origin_only: false,
      expires_at: None,
    },
  };
  spec.hostname = a.hostname;
  if retarget {
    let same_service =
      a.service.as_deref().is_some_and(|s| s == spec.service);
    if !same_service {
      spec.port = None;
    }
    spec.service = a.service.unwrap_or_default();
    spec.upstream = a.upstream;
    spec.redirect = a.redirect;
  }
  if spec.redirect.is_some() {
    // 跳转不允许这些。
    spec.paths.clear();
    spec.sso = None;
    spec.auth = false;
    spec.internal = false;
    spec.rate_limit = None;
    spec.block_scanners = false;
  }
  if a.port.is_some() {
    spec.port = a.port;
  }
  if a.gateway.is_some() {
    spec.gateway = a.gateway;
  }
  if let Some(b) = a.backup_gateway {
    spec.backup_gateway = (!b.is_empty()).then_some(b);
  }
  if let Some(minutes) = a.failover_minutes {
    spec.failover_minutes = minutes;
  } else if spec.backup_gateway.is_none() {
    spec.failover_minutes = None;
  }
  if let Some(ttl) = a.dns_ttl {
    spec.dns_ttl = ttl;
  }
  if let Some(v) = a.auth {
    spec.auth = v;
  }
  if let Some(v) = a.paths {
    spec.paths = v;
  }
  if let Some(v) = a.tunnel {
    spec.link = if v {
      wharf_api_types::spec::LinkMode::Tunnel
    } else {
      wharf_api_types::spec::LinkMode::Auto
    };
  }
  if let Some(v) = a.internal {
    spec.internal = v;
  }
  Ok(spec)
}

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

fn print_sso_test(result: &SsoTestResult) {
  for step in &result.steps {
    print_sso_step(&format!("第 {} 步", step.number), step);
  }
  if let Some(check) = &result.check {
    print_sso_step("检查  ", check);
  }
  if result.ok {
    println!("登录成功");
  }
  if !result.would_write.is_empty() {
    println!("会写入浏览器：");
    for summary in &result.would_write {
      println!("  {summary}");
    }
  }
  if let Some(log) = &result.script_log
    && !log.trim().is_empty()
  {
    println!("脚本输出：");
    for line in log.lines() {
      println!("  {line}");
    }
  }
  if !result.ok {
    let error = result
      .steps
      .iter()
      .chain(result.check.iter())
      .find_map(|step| step.error.as_deref());
    if let Some(error) = error {
      println!("登录失败：{error}");
    } else {
      println!("登录失败");
    }
  }
}

fn print_sso_step(label: &str, step: &SsoStepResult) {
  if step.method == "SCRIPT" {
    let status = if step.error.is_some() {
      "失败"
    } else {
      "成功"
    };
    println!("{label}  脚本  {status}  {}ms", step.ms);
  } else {
    let status = step
      .status
      .map_or_else(|| "未响应".into(), |code| code.to_string());
    print!(
      "{label}  {} {}  {status}  {}ms",
      step.method, step.path, step.ms
    );
    if !step.extracted.is_empty() {
      let extracted = step
        .extracted
        .iter()
        .map(|(name, n)| format!("{name}（{n} 个字符）"))
        .collect::<Vec<_>>();
      print!("  取到：{}", extracted.join("、"));
    }
    println!();
  }
}

fn beijing_time(at: chrono::DateTime<chrono::Utc>) -> String {
  at.with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
    .format("%m-%d %H:%M")
    .to_string()
}

fn app_account_domains(account: &AppAccountView) -> String {
  account
    .domains
    .iter()
    .map(|d| {
      format!(
        "{}{}{}",
        d.hostname,
        if d.is_default { "（默认）" } else { "" },
        if d.exists {
          ""
        } else {
          "（域名不存在）"
        }
      )
    })
    .collect::<Vec<_>>()
    .join("、")
}

fn print_app_account(
  account: &AppAccountView,
  name_width: usize,
  username_width: usize,
) {
  let domains = app_account_domains(account);
  let domains = if domains.is_empty() {
    "没有关联域名"
  } else {
    &domains
  };
  println!(
    "{:<name_width$}  {:<username_width$}  {domains}  {}",
    account.name,
    account.username,
    beijing_time(account.updated_at)
  );
  let mut lines = account.note.lines();
  if let Some(first) = lines.next() {
    let indent = " ".repeat(name_width + 2);
    println!("{indent}备注：{first}");
    for line in lines {
      println!("{indent}      {line}");
    }
  }
}

async fn app_account(
  c: &Client,
  cmd: AppAccountCmd,
  j: bool,
) -> CliResult<()> {
  let path = |name: &str| format!("/api/sso/accounts/{}", seg(name));
  let domains = |name: &str, hostname: &str| {
    format!(
      "{}/domains/{}",
      path(name),
      seg(&wharf_api_types::normalize_host(hostname))
    )
  };
  let print_single = |a: &AppAccountView| {
    print_app_account(a, a.name.len(), a.username.chars().count())
  };
  match cmd {
    AppAccountCmd::List => {
      let accounts: Vec<AppAccountView> =
        c.get("/api/sso/accounts").await?;
      out(j, &accounts, |accounts| {
        if accounts.is_empty() {
          println!(
            "还没有应用账号，用 wharf sso account set <名称> 添加"
          );
          return;
        }
        let name_width = accounts
          .iter()
          .map(|a| a.name.len())
          .max()
          .unwrap_or_default();
        let username_width = accounts
          .iter()
          .map(|a| a.username.chars().count())
          .max()
          .unwrap_or_default();
        for account in accounts {
          print_app_account(account, name_width, username_width);
        }
      });
    }
    AppAccountCmd::Set {
      name,
      user,
      note,
      keep_password,
    } => {
      let password = if keep_password {
        None
      } else {
        Some(read_secret("应用账号密码：")?)
      };
      let account: AppAccountView = c.put(&path(&name), &json!({"username": user, "password": password, "note": note})).await?;
      out(j, &account, |account| {
        println!("已保存应用账号 {}", account.name)
      });
    }
    AppAccountCmd::Show { name, reveal } => {
      let account: AppAccountView = c.get(&path(&name)).await?;
      if reveal {
        #[derive(serde::Deserialize)]
        struct Password {
          password: String,
        }
        let wharf_password =
          rpassword::prompt_password("Wharf 登录密码：").map_err(
            |_| ApiError::invalid("需要在终端输入 Wharf 登录密码"),
          )?;
        let Password { password } = c
          .post(
            &format!("{}/password", path(&name)),
            &json!({"password": wharf_password}),
          )
          .await?;
        if j {
          #[derive(serde::Serialize)]
          struct Revealed<'a> {
            #[serde(flatten)]
            account: &'a AppAccountView,
            password: String,
          }
          print::json(&Revealed {
            account: &account,
            password,
          });
        } else {
          print_single(&account);
          println!("{password}");
        }
      } else {
        out(j, &account, print_single);
      }
    }
    AppAccountCmd::Rm { name } => {
      let result: Value = c.delete(&path(&name)).await?;
      out(j, &result, |_| println!("已删除应用账号 {name}"));
    }
    AppAccountCmd::Link {
      name,
      hostname,
      default,
    } => {
      let account: AppAccountView = c
        .put(
          &domains(&name, &hostname),
          &json!({"is_default": default}),
        )
        .await?;
      out(j, &account, print_single);
    }
    AppAccountCmd::Unlink { name, hostname } => {
      let account: AppAccountView =
        c.delete(&domains(&name, &hostname)).await?;
      out(j, &account, print_single);
    }
  }
  Ok(())
}

/// 密钥预览：不读也不显示值，只说新建、覆盖还是删除，以及谁在用。
async fn secret_preview(
  c: &Client,
  name: &str,
  deleting: bool,
  j: bool,
) -> CliResult<()> {
  let list: Vec<SecretView> = c.get("/api/secrets").await?;
  let before = list
    .iter()
    .find(|s| s.name == name)
    .map(|s| json!({"name": s.name, "used_by": s.used_by, "value": "（旧值）"}))
    .unwrap_or(Value::Null);
  if deleting && before.is_null() {
    return Err(
      ApiError::not_found(format!("密钥 {name} 不存在")).into(),
    );
  }
  let after = if deleting {
    Value::Null
  } else {
    json!({"name": name, "used_by": before["used_by"], "value": "（新值）"})
  };
  crate::preview::show(j, &format!("secret/{name}"), &before, &after)
}

async fn secret(
  c: &Client,
  cmd: SecretCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    SecretCmd::List { detail } => {
      let v: Vec<SecretView> = c.get("/api/secrets").await?;
      out(j || detail, &v, |v| v.iter().for_each(print_secret));
      Ok(())
    }
    SecretCmd::Rotate {
      name,
      keep_days,
      apply,
    } => {
      let value = read_secret(&format!("{name} 的新值："))?;
      let response = c
        .post(
          &format!("/api/secrets/{}/rotate", seg(&name)),
          &json!({ "value": value, "keep_days": keep_days }),
        )
        .await?;
      finish_secret_rotation(c, response, apply, j).await
    }
    SecretCmd::Rollback { name, apply } => {
      let response = c
        .post(
          &format!("/api/secrets/{}/rollback", seg(&name)),
          &json!({}),
        )
        .await?;
      finish_secret_rotation(c, response, apply, j).await
    }
    SecretCmd::ClearOld { name } => {
      let v: Value = c
        .delete(&format!("/api/secrets/{}/previous", seg(&name)))
        .await?;
      out(j, &v, |v| {
        if v["cleared"] == true {
          println!("已清除 {name} 的旧值");
        } else {
          println!("{name} 没有保留的旧值");
        }
      });
      Ok(())
    }
    SecretCmd::Show { name } => {
      let v: Vec<SecretView> = c.get("/api/secrets").await?;
      let row =
        v.into_iter().find(|s| s.name == name).ok_or_else(|| {
          ApiError::not_found(format!("密钥 {name} 不存在"))
        })?;
      out(j, &row, print_secret);
      Ok(())
    }
    SecretCmd::Restrict {
      name,
      services,
      clear,
    } => {
      if services.is_empty() && !clear {
        let secrets: Vec<SecretView> = c.get("/api/secrets").await?;
        let secret = secrets
          .into_iter()
          .find(|secret| secret.name == name)
          .ok_or_else(|| {
            ApiError::not_found(format!("密钥 {name} 不存在"))
          })?;
        out(
          j,
          &json!({"name": name, "services": secret.allowed_services}),
          pretty,
        );
        return Ok(());
      }
      let allowed = (!clear).then_some(services);
      let v: Option<Vec<String>> = c
        .put(
          &format!("/api/secrets/{}/restriction", seg(&name)),
          &allowed,
        )
        .await?;
      out(j, &v, |v| match v {
        Some(services) => {
          println!("{name}：仅限 {}", services.join("、"))
        }
        None => println!("已清除 {name} 的服务名单"),
      });
      Ok(())
    }
    SecretCmd::LeakCheck { repo } => {
      let v: Value = c
        .post_timeout(
          "/api/secret-leak-check",
          &json!({ "repo": repo }),
          Duration::from_secs(180),
        )
        .await?;
      pretty(&v);
      Ok(())
    }
    SecretCmd::Set {
      name,
      generate: true,
      ..
    } => {
      let v: SecretView = c
        .post(
          &format!("/api/secrets/{}/generate", seg(&name)),
          &json!({}),
        )
        .await?;
      out(j, &v, |v| println!("已生成密钥 {}", v.name));
      Ok(())
    }
    SecretCmd::Set {
      name,
      dry_run: true,
      ..
    } => secret_preview(c, &name, false, j).await,
    SecretCmd::Rm {
      name,
      dry_run: true,
    } => secret_preview(c, &name, true, j).await,
    SecretCmd::Set { name, .. } => {
      let prompt = if name.starts_with("BASIC_AUTH_") {
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
    SecretCmd::Rm { name, .. } => {
      let v: Value =
        c.delete(&format!("/api/secrets/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除密钥 {name}"));
      Ok(())
    }
  }
}

async fn finish_secret_rotation(
  c: &Client,
  response: wharf_api_types::view::RotateSecretResponse,
  flags: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  if flags.apply && response.needs_plan {
    if !j && !print::is_quiet() {
      pretty(&response);
    }
    return plan_and_maybe_apply(c, PlanRequest::default(), flags, j)
      .await;
  }
  if !print::is_quiet() {
    pretty(&response);
  }
  Ok(())
}

fn print_secret(secret: &SecretView) {
  match &secret.allowed_services {
    Some(services) => {
      println!("{}\t仅限 {}", secret.name, services.join("、"))
    }
    None => println!("{}", secret.name),
  }
}

fn backup_url(
  service: &str,
  suffix: &str,
  pairs: &[(&str, Option<&str>)],
) -> String {
  let base = format!("/api/services/{}/backups", seg(service));
  let base = format!("{base}{suffix}");
  let query = pairs
    .iter()
    .filter_map(|(k, v)| v.map(|v| format!("{k}={}", seg(v))))
    .collect::<Vec<_>>()
    .join("&");
  if query.is_empty() {
    base
  } else {
    format!("{base}?{query}")
  }
}

async fn backup(
  c: &Client,
  cmd: BackupCmd,
  j: bool,
) -> CliResult<()> {
  let get_service = |name: &str| {
    let url = format!("/api/services/{}", seg(name));
    async move { c.get::<ServiceView>(&url).await }
  };
  let change = |name, spec| Change::UpsertService {
    pins: None,
    commit: None,
    name,
    spec,
    adopt: None,
  };
  let repo_timeout = Duration::from_secs(30 * 60);
  match cmd {
    BackupCmd::Migrate => {
      let v: Value = c
        .post_timeout(
          "/api/backups/migrate",
          &json!({}),
          repo_timeout,
        )
        .await?;
      out(j, &v, |v| {
        if let Some(repos) = v["repositories"].as_array() {
          for r in repos {
            println!(
              "{} / {}：{}",
              r["target"].as_str().unwrap_or_default(),
              r["service"].as_str().unwrap_or_default(),
              r["status"].as_str().unwrap_or_default()
            );
            if let Some(message) = r["error"]["message"].as_str() {
              println!("  {message}");
            }
          }
        }
      });
      Ok(())
    }
    BackupCmd::CleanupLegacy {
      confirm,
      skip_snapshot,
    } => {
      let body = if skip_snapshot {
        json!({"confirm": confirm, "skip_snapshot": true})
      } else {
        json!({"confirm": confirm})
      };
      let v: Value = c
        .post_timeout(
          "/api/backups/cleanup-legacy",
          &body,
          repo_timeout,
        )
        .await?;
      out(j, &v, |v| {
        println!(
          "已摘除 {} 把旧钥匙，清理 {} 条旧凭据",
          v["removed_keys"], v["deleted_secrets"]
        );
      });
      Ok(())
    }
    BackupCmd::Move {
      service,
      core,
      to,
      from,
      dry_run,
      abort,
      confirm,
      no_wait,
    } => {
      let path = if core {
        "/api/core-backup/move".into()
      } else {
        let name = service
          .ok_or_else(|| ApiError::invalid("请指定服务或 --core"))?;
        format!("/api/services/{}/backups/move", seg(&name))
      };
      let body = json!({"from": from, "to": to, "dry_run": dry_run, "abort": abort, "confirm": confirm});
      let timeout = Duration::from_secs(8 * 60);
      if dry_run {
        let view: wharf_api_types::view::BackupMovePreview =
          c.post_timeout(&path, &body, timeout).await?;
        out(j, &view, |v| {
          println!(
            "{}：{} → {}，源快照 {} 份",
            v.service, v.from, v.to, v.source_snapshots
          );
          if v.resuming {
            println!("将从上次进度续传");
          }
          if let Some(confirm) = &v.confirm {
            println!(
              "{}，请添加 --confirm {confirm}",
              v.hint.as_deref().unwrap_or_default()
            );
          }
        });
      } else if abort {
        let view: wharf_api_types::view::BackupMoveAbort =
          c.post(&path, &body).await?;
        out(j, &view, |v| {
          println!("已放弃 {} 的续传进度，两端仓库已保留", v.service)
        });
      } else {
        let result: ApplyResponse =
          c.post_timeout(&path, &body, timeout).await?;
        if no_wait {
          finish_task(c, &result.run_id, false, j).await?;
        } else {
          let run =
            match wait_run_with_interrupt(c, &result.run_id, j, true)
              .await
            {
              Err(CliError::Exit(130)) => {
                let path =
                  format!("/api/runs/{}/cancel", seg(&result.run_id));
                c.post_timeout::<_, Value>(
                  &path,
                  &json!({}),
                  Duration::from_secs(15),
                )
                .await?;
                return Err(
                  ApiError::new(
                    ErrorCode::Cancelled,
                    "已请求取消备份迁移",
                  )
                  .with_hint("取消结束后重跑原命令续传")
                  .into(),
                );
              }
              result => result?,
            };
          out(j, &run, print::run_summary);
          if run.status != RunStatus::Succeeded {
            return Err(CliError::Exit(4));
          }
        }
      }
      Ok(())
    }
    BackupCmd::Enable {
      service,
      to,
      exclude,
      retention,
      apply,
    } => {
      let mut spec = get_service(&service).await?.spec;
      let mut policy = spec.backup.take().unwrap_or(BackupSpec {
        to: to.clone(),
        exclude: vec![],
        retention: None,
      });
      policy.to = to;
      policy.exclude.extend(exclude);
      policy.exclude = validate_backup_excludes(&policy.exclude)?;
      policy.retention = retention.merge(policy.retention)?;
      spec.backup = Some(policy);
      changes(c, vec![change(service, spec)], apply, j).await
    }
    BackupCmd::Set {
      service,
      to,
      exclude,
      unset_exclude,
      clear_exclude,
      retention,
      apply,
    } => {
      let mut spec = get_service(&service).await?.spec;
      let edited = to.is_some()
        || !exclude.is_empty()
        || !unset_exclude.is_empty()
        || clear_exclude
        || retention.edited();
      if !edited {
        if apply.apply
          || apply.note.is_some()
          || !apply.confirm.is_empty()
          || apply.dns_verify.mode().is_some()
        {
          return Err(
            ApiError::invalid("没有指定要修改的备份配置项")
              .with_hint("不带 --apply 可只读查看当前配置")
              .into(),
          );
        }
        let policy = spec.backup.as_ref();
        let result = BackupPolicy {
          service,
          enabled: policy.is_some(),
          to: policy.map(|p| p.to.clone()),
          exclude: policy
            .map(|p| p.exclude.clone())
            .unwrap_or_default(),
          retention: policy.and_then(|p| p.retention),
          effective_retention: policy
            .and_then(|p| p.retention)
            .unwrap_or_default(),
        };
        out(j, &result, |value| {
          if let Some(to) = &value.to {
            println!("{}：备份到 {to}", value.service);
            print::backup_policy(
              value.effective_retention,
              &value.exclude,
            );
          } else {
            println!("{}：没有开启备份", value.service);
          }
        });
        return Ok(());
      }
      let mut policy = match (spec.backup.take(), to.as_ref()) {
        (Some(policy), _) => policy,
        (None, Some(to)) => BackupSpec {
          to: to.clone(),
          exclude: vec![],
          retention: None,
        },
        (None, None) => return Err(
          ApiError::invalid("服务尚未开启备份")
            .with_hint(format!(
              "开启请运行 wharf backup enable {service} --to <server>"
            ))
            .into(),
        ),
      };
      if let Some(to) = to {
        policy.to = to;
      }
      let removed = validate_backup_excludes(&unset_exclude)?;
      policy
        .exclude
        .retain(|r| !clear_exclude && !removed.contains(r));
      policy.exclude.extend(exclude);
      policy.exclude = validate_backup_excludes(&policy.exclude)?;
      policy.retention = retention.merge(policy.retention)?;
      spec.backup = Some(policy);
      changes(c, vec![change(service, spec)], apply, j).await
    }
    BackupCmd::Disable { service, apply } => {
      let mut spec = get_service(&service).await?.spec;
      spec.backup = None;
      changes(c, vec![change(service, spec)], apply, j).await
    }
    BackupCmd::Run {
      service,
      no_wait,
      keep,
      note,
    } => {
      let options = BackupRunRequest { keep, note };
      options.validate()?;
      let r: ApplyResponse =
        c.post(&backup_url(&service, "", &[]), &options).await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
    BackupCmd::Ls {
      service,
      path,
      lookup,
      recursive,
      limit,
    } => {
      let url = backup_url(
        &service,
        "/ls",
        &[
          ("path", Some(&path)),
          ("snapshot", Some(&lookup.snapshot)),
          ("from", lookup.from.as_deref()),
          (
            "recursive",
            Some(if recursive { "true" } else { "false" }),
          ),
          ("limit", Some(&limit.to_string())),
        ],
      );
      let v: BackupLsView =
        c.get_timeout(&url, Duration::from_secs(7 * 60)).await?;
      out(j, &v, print::backup_ls);
      Ok(())
    }
    BackupCmd::Extract {
      service,
      path,
      lookup,
      output,
      force,
    } => {
      let url = backup_url(
        &service,
        "/extract",
        &[
          ("path", Some(&path)),
          ("snapshot", Some(&lookup.snapshot)),
          ("from", lookup.from.as_deref()),
        ],
      );
      crate::backup_extract::run(
        c,
        &url,
        &service,
        &path,
        output.as_deref(),
        force,
        j,
      )
      .await
    }
    BackupCmd::Diff {
      service,
      lookup,
      base,
      limit,
    } => {
      let url = backup_url(
        &service,
        "/diff",
        &[
          ("snapshot", Some(&lookup.snapshot)),
          ("from", lookup.from.as_deref()),
          ("base", base.as_deref()),
          ("limit", Some(&limit.to_string())),
        ],
      );
      let v: BackupDiffView =
        c.get_timeout(&url, Duration::from_secs(35 * 60)).await?;
      out(j, &v, print::backup_diff);
      Ok(())
    }
    BackupCmd::Keep {
      service,
      snapshot,
      from,
      off,
      note,
      unset_note,
    } => {
      let v: BackupKeepResult = c.post(&backup_url(&service, "/keep", &[]), &json!({
        "snapshot": snapshot, "keep": !off, "note": note, "clear_note": unset_note, "target": from,
      })).await?;
      out(j, &v, |v| {
        println!(
          "{}：{}",
          v.snapshot.short_id,
          if v.snapshot.keep {
            "已留底"
          } else {
            "已撤销留底"
          }
        )
      });
      Ok(())
    }
    BackupCmd::Unlock {
      service,
      from,
      stale_only,
    } => {
      let value: BackupUnlockResult = c
        .post(
          &format!("/api/services/{}/backups/unlock", seg(&service)),
          &json!({ "target": from, "stale_only": stale_only }),
        )
        .await?;
      out(j, &value, |v| {
        println!("已解锁 {} 上的备份仓库", v.target)
      });
      Ok(())
    }
    BackupCmd::Core {
      ref retention,
      ref to,
      run,
      unlock,
      verify_password,
      export,
      ..
    } if retention.edited()
      && (to.is_some()
        || run
        || unlock
        || verify_password
        || export) =>
    {
      Err(ApiError::invalid("修改保留策略需单独执行").into())
    }
    BackupCmd::Core {
      unlock: true,
      stale_only,
      ..
    } => {
      let value: BackupUnlockResult = c
        .post(
          "/api/core-backup/unlock",
          &json!({ "stale_only": stale_only }),
        )
        .await?;
      out(j, &value, |v| {
        println!("已解锁 {} 上的控制面备份仓库", v.target)
      });
      Ok(())
    }
    BackupCmd::Core {
      verify_password: true,
      ..
    } => {
      let password = read_secret("控制面登录密码：")?;
      let v: wharf_api_types::view::CoreBackupVerifyView = c
        .post_timeout(
          "/api/core-backup/verify-password",
          &json!({"password": password}),
          Duration::from_secs(390),
        )
        .await?;
      out(j, &v, |v| {
        let status = |ok| if ok { "✓" } else { "✗" };
        println!(
          "{} ({})  登录密码 {}  HTTP 认证 {}  仓库解密 {}  快照 {} 份",
          v.target,
          v.username,
          status(v.login_password_ok),
          status(v.htpasswd_ok),
          status(v.repo_decrypt_ok),
          v.snapshot_count
        );
        if let Some(latest) = &v.latest_snapshot {
          println!("最新快照 {}  {}", latest.short_id, latest.time);
        }
        if let Some(error) = &v.error {
          println!("{error}");
        }
        if let Some(hint) = &v.hint {
          println!("{hint}");
        }
      });
      if v.ok { Ok(()) } else { Err(CliError::Exit(1)) }
    }
    BackupCmd::Core {
      export: true,
      output,
      force,
      ..
    } => crate::core_export::download(c, output, force, j).await,
    BackupCmd::Core { to: Some(to), .. } => {
      let password = read_secret("登录密码（会成为恢复口令）：")?;
      let r: ApplyResponse = c
        .post(
          "/api/core-backup",
          &json!({ "to": to, "password": password }),
        )
        .await?;
      finish_task(c, &r.run_id, true, j).await
    }
    BackupCmd::Core {
      run: true,
      keep,
      note,
      ..
    } => {
      let options = BackupRunRequest { keep, note };
      options.validate()?;
      let r: ApplyResponse =
        c.post("/api/core-backup/run", &options).await?;
      finish_task(c, &r.run_id, true, j).await
    }
    BackupCmd::Core { retention, .. } if retention.edited() => {
      let v: Value = c.get("/api/core-backup").await?;
      let previous: Option<BackupRetention> =
        serde_json::from_value(v["retention"].clone())
          .map_err(|_| ApiError::internal("无法读取现有保留策略"))?;
      let retention = retention.merge(previous)?;
      let v: Value = c
        .put(
          "/api/core-backup/retention",
          &json!({"retention": retention}),
        )
        .await?;
      out(j, &v, |_| {
        print::backup_policy(retention.unwrap_or_default(), &[])
      });
      Ok(())
    }
    BackupCmd::Core { .. } => {
      let v: Value = c.get("/api/core-backup").await?;
      out(j, &v, print::core_backup);
      Ok(())
    }
    BackupCmd::List { service, from } => {
      let v: BackupsView = c
        .get(&backup_url(&service, "", &[("from", from.as_deref())]))
        .await?;
      out_quiet(
        j,
        &v,
        |v| {
          v.snapshots
            .iter()
            .map(|s| s.short_id.clone())
            .collect::<Vec<_>>()
        },
        print::backups,
      );
      Ok(())
    }
    BackupCmd::Restore {
      service,
      from,
      skip_snapshot,
      snapshot,
      confirm,
      no_wait,
    } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/restore", seg(&service)),
          &RestoreRequest {
            target: from,
            snapshot,
            confirm: confirm.unwrap_or_default(),
            skip_snapshot,
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

/// `--egress`：`off` 关闭，`all` 全部走，否则逗号分隔的预置分组名和域名。
fn parse_egress(
  v: &str,
) -> Result<Option<wharf_api_types::egress::EgressSpec>, CliError> {
  let v = v.trim();
  if v.is_empty() || v == "off" {
    return Ok(None);
  }
  let mut spec = wharf_api_types::egress::EgressSpec::default();
  for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
    match part {
      "all" => spec.all = true,
      p if p.contains('.') => spec.domains.push(p.to_lowercase()),
      p => spec.presets.push(p.to_string()),
    }
  }
  spec.validate().map_err(ApiError::invalid)?;
  Ok(Some(spec))
}

fn share_ttl(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let (num, unit) = s.split_at(
    s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()),
  );
  let n: u64 = num.parse().map_err(|_| format!("时长写错了：{s}"))?;
  let factor = match unit {
    "s" => 1,
    "" | "m" => 60,
    "h" => 3600,
    "d" => 86400,
    _ => return Err(format!("时长单位只能是 s、m、h、d：{s}")),
  };
  let secs = n
    .checked_mul(factor)
    .filter(|n| (60..=7 * 86400).contains(n))
    .ok_or("时长要在 1 分钟到 7 天之间")?;
  Ok(Duration::from_secs(secs))
}

fn infer_ignore_image(source: &Source) -> CliResult<String> {
  match source {
    Source::Image(image) => Ok(image_repo(image).to_string()),
    Source::Build(_) => Ok("*".into()),
    Source::Compose { content, .. } => {
      let compose = crate::deploy::parse_compose(
        content.as_deref().unwrap_or_default(),
      )
      .map_err(|_| ApiError::invalid("无法读取 Compose 镜像"))?;
      let mut images: Vec<_> = compose["services"]
        .as_mapping()
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|svc| svc.get("build").is_none())
        .filter_map(|svc| svc["image"].as_str())
        .map(str::trim)
        .filter(|i| {
          !i.is_empty()
            && !i.contains('@')
            && !i.contains('$')
            && !i.starts_with("sha256:")
        })
        .collect();
      images.sort_unstable();
      images.dedup();
      match images.as_slice() {
        [image] => Ok(image_repo(image).to_string()),
        _ => Err(
          ApiError::invalid(
            "请用 --image 指定镜像名，或传 --image '*' 匹配全部",
          )
          .with_hint(format!("Compose 镜像：{}", images.join("、")))
          .into(),
        ),
      }
    }
  }
}

fn parse_volume_arg(raw: &str) -> Result<VolumeSpec, ApiError> {
  let invalid = || {
    ApiError::invalid(format!("--volume {raw} 格式不对"))
      .with_hint("使用 name:/target[:ro|:rw] 或 [本地名=]服务:卷:/target[:ro|:rw]")
  };
  let (left, target) = raw.split_once(":/").ok_or_else(invalid)?;
  let (target, read_only) = match target.strip_suffix(":ro") {
    Some(target) => (target, true),
    None => (target.strip_suffix(":rw").unwrap_or(target), false),
  };
  if target.contains(':') {
    return Err(invalid());
  }
  let (alias, reference) = left
    .split_once('=')
    .map_or((None, left), |(alias, reference)| {
      (Some(alias), reference)
    });
  let (name, from_service) =
    if let Some((owner, volume)) = reference.split_once(':') {
      wharf_api_types::validate_name("服务", owner)
        .map_err(|_| invalid())?;
      wharf_api_types::validate_name("数据卷", volume)
        .map_err(|_| invalid())?;
      (alias.unwrap_or(volume), Some(reference.to_string()))
    } else if alias.is_none() {
      (reference, None)
    } else {
      return Err(invalid());
    };
  wharf_api_types::validate_name("数据卷", name)
    .map_err(|_| invalid())?;
  Ok(VolumeSpec {
    name: name.to_string(),
    target: format!("/{target}"),
    from_service,
    read_only,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn backup_move_wait_is_interruptible_between_polls() {
    let polls = std::cell::Cell::new(0);
    let run = Run {
      run_id: "r1".into(),
      plan_id: "p1".into(),
      status: RunStatus::Running,
      started_at: chrono::Utc::now(),
      actor: None,
      retry_of: None,
      finished_at: None,
      steps: vec![],
    };
    let result = tokio::time::timeout(
      Duration::from_secs(2),
      wait_run_until(
        "r1",
        true,
        true,
        || {
          polls.set(polls.get() + 1);
          std::future::ready(Ok(run.clone()))
        },
        async {
          tokio::task::yield_now().await;
          assert_eq!(polls.get(), 1);
        },
      ),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(CliError::Exit(130))));
  }

  #[test]
  fn source_switch_refreshes_compose_ports_only_when_requested() {
    let mut spec: ServiceSpec = serde_json::from_value(serde_json::json!({
      "server":"s1", "source":{"compose":{"content":"services: {}"}},
      "container":"app", "ports":[{"name":"http","host":8081}]
    })).unwrap();
    let new_compose = spec.source.clone();
    reconcile_source_switch(&mut spec, new_compose.clone(), false);
    assert_eq!(spec.ports[0].host, Some(8081));
    reconcile_source_switch(&mut spec, new_compose, true);
    assert!(spec.ports.is_empty());
    reconcile_source_switch(
      &mut spec,
      Source::Image("nginx".into()),
      false,
    );
    assert!(spec.container.is_none());
  }

  #[test]
  fn switching_image_to_compose_url_clears_container_ports() {
    let mut spec: ServiceSpec =
      serde_json::from_value(serde_json::json!({
        "server": "s1", "source": {"image": "nginx"},
        "ports": [{"name": "http", "container": 80}]
      }))
      .unwrap();
    let compose = Source::Compose {
      content: Some("services: {app: {image: nginx}}".into()),
      file: None,
    };
    reconcile_source_switch(&mut spec, compose, false);
    assert!(spec.ports.is_empty());
  }

  use clap::Parser;

  #[tokio::test]
  async fn login_token_file_saves_only_the_credential_source() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("t.tok");
    let saved = dir.path().join("config.toml");
    let fixture = format!("fixture-{}", std::process::id());
    std::fs::write(&file, &fixture).unwrap();
    let key = "11".repeat(32);
    let args = [
      "wharf",
      "login",
      "--url",
      "https://core.example.test",
      "--core-key",
      &key,
      "--token-file",
      file.to_str().unwrap(),
    ];
    let cli = Cli::try_parse_from(args).unwrap();
    let Command::Login {
      url,
      core_key,
      token_file,
      token_cmd,
    } = cli.command
    else {
      panic!("应解析为 login");
    };
    let (config, token) =
      login_credentials(&url, &core_key, token_file, token_cmd)
        .await
        .unwrap();
    assert!(token == fixture);
    config.save_to(&saved).unwrap();
    let text = std::fs::read_to_string(saved).unwrap();
    assert!(text.contains("token_file = "));
    assert!(!text.contains("token = "));
    assert!(!text.contains(&fixture));
    assert!(
      Cli::try_parse_from(
        args.into_iter().chain(["--token-cmd", "false"])
      )
      .is_err()
    );
  }

  #[test]
  fn rotate_link_yes_help_preserves_per_item_confirmation() {
    let credential = format!("fixture-{}", std::process::id());
    let cli = Cli::try_parse_from([
      "wharf",
      "gateway",
      "rotate-link",
      "gw-a",
      "--token",
      &credential,
      "--link-token",
      "--apply",
      "--yes",
    ])
    .unwrap();
    assert!(cli.token.as_deref() == Some(credential.as_str()));
    assert!(matches!(
      cli.command,
      Command::Gateway(GatewayCmd::RotateLink { link_token: true, cert: false, apply, .. })
        if apply.apply && apply.confirm.is_empty()
    ));
    let default = Cli::try_parse_from([
      "wharf",
      "gateway",
      "rotate-link",
      "gw-a",
    ])
    .unwrap();
    assert!(matches!(
      default.command,
      Command::Gateway(GatewayCmd::RotateLink {
        link_token: false,
        cert: false,
        ..
      })
    ));
    let Err(help) = Cli::try_parse_from([
      "wharf",
      "gateway",
      "rotate-link",
      "--help",
    ]) else {
      panic!("预期返回命令帮助");
    };
    assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    let help = help.to_string();
    assert!(help.contains("高风险项仍需逐项传入 --confirm"));
    assert!(help.contains("--link-token"));
    assert!(!help.contains("--api-token"));
  }

  #[test]
  fn route_add_keeps_unspecified_fields() {
    let old: RouteSpec = serde_json::from_value(serde_json::json!({
      "hostname": "a.example.com",
      "service": "blog",
      "sso": {"mode": "gate"},
      "paths": [{"path": "/ws", "upstream": "127.0.0.1:1"}]
    }))
    .unwrap();
    let spec = route_add_spec(
      Some(old),
      RouteAddArgs {
        hostname: "a.example.com".into(),
        service: None,
        upstream: None,
        redirect: None,
        port: None,
        gateway: None,
        backup_gateway: Some("edge2".into()),
        dns_ttl: Some(Some(120)),
        failover_minutes: Some(Some(2)),
        auth: None,
        paths: None,
        tunnel: None,
        internal: None,
      },
    )
    .unwrap_or_else(|_| panic!("应当成功"));
    assert_eq!(spec.backup_gateway.as_deref(), Some("edge2"));
    assert_eq!(spec.dns_ttl, Some(120));
    assert_eq!(spec.failover_minutes, Some(2));
    assert!(spec.sso.is_some());
    assert_eq!(spec.paths.len(), 1);
    assert_eq!(spec.service, "blog");
  }

  #[test]
  fn ports() {
    let p = parse_port("http=80").unwrap();
    assert_eq!(
      (p.name.as_str(), p.container, p.host),
      ("http", Some(80), None)
    );
    let p = parse_port("http=80:20080").unwrap();
    assert_eq!((p.container, p.host), (Some(80), Some(20080)));
    let p = parse_port("http=:41773").unwrap();
    assert_eq!((p.container, p.host), (None, Some(41773)));
    assert!(parse_port("http").is_err());
    assert!(parse_port("http=x").is_err());
  }

  #[test]
  fn exec_keeps_one_command_string() {
    let cli = Cli::try_parse_from([
      "wharf",
      "exec",
      "s1",
      "--",
      "printf '%s' hello",
    ])
    .unwrap();
    let Command::Exec { command, .. } = cli.command else {
      panic!("不是 exec");
    };
    assert_eq!(command.as_deref(), Some("printf '%s' hello"));
    assert_eq!(command_summary("a\x1b[31m"), r"a\u{1b}[31m");
    assert!(
      Cli::try_parse_from(["wharf", "exec", "s1", "--", "a", "b"])
        .is_err()
    );
  }
}

fn set_private_network(
  settings: &mut wharf_api_types::spec::ServerSettings,
  ip: Option<&str>,
  network: Option<&str>,
) -> Result<(), ApiError> {
  let network = network.map(|n| {
    if n == "overlay" {
      PrivateNetwork::Overlay
    } else {
      PrivateNetwork::Lan
    }
  });
  match (ip.map(str::trim), network) {
    (Some(""), Some(_)) => {
      return Err(ApiError::invalid(
        "清空 --private-ip 时不能同时指定 --network",
      ));
    }
    (Some(""), None) => settings.private_addr = None,
    (Some(ip), network) => {
      ip.parse::<std::net::IpAddr>().map_err(|_| {
        ApiError::invalid(format!("--private-ip {ip} 不是 IP 地址"))
      })?;
      let network = network
        .or_else(|| settings.private_addr.as_ref().map(|a| a.network))
        .unwrap_or(PrivateNetwork::Lan);
      settings.private_addr = Some(PrivateAddr {
        ip: ip.into(),
        network,
      });
    }
    (None, Some(network)) => {
      let addr = settings.private_addr.as_mut().ok_or_else(|| {
        ApiError::invalid("这台服务器还没有手动设置内网地址，请同时传 --private-ip")
          .with_hint("wharf server set <name> --private-ip <IP> --network overlay")
      })?;
      addr.network = network;
    }
    (None, None) => {}
  }
  Ok(())
}

#[test]
fn server_network_preserve_when_only_ip_changes() {
  let mut settings = wharf_api_types::spec::ServerSettings::default();
  assert!(
    set_private_network(&mut settings, None, Some("overlay"))
      .is_err()
  );
  set_private_network(
    &mut settings,
    Some("100.64.0.2"),
    Some("overlay"),
  )
  .unwrap();
  set_private_network(&mut settings, Some("100.64.0.3"), None)
    .unwrap();
  assert_eq!(
    settings.private_addr.unwrap().network,
    PrivateNetwork::Overlay
  );
}

#[test]
fn parse_volume_arg_handles_local_shared_alias_and_ro() {
  for (raw, name, reference, read_only) in [
    ("data:/data", "data", None, false),
    ("data:/data:ro", "data", None, true),
    (
      "photos:originals:/data:ro",
      "originals",
      Some("photos:originals"),
      true,
    ),
    (
      "pic=photos:originals:/data:rw",
      "pic",
      Some("photos:originals"),
      false,
    ),
  ] {
    let v = parse_volume_arg(raw).unwrap();
    assert_eq!(
      (
        v.name.as_str(),
        v.from_service.as_deref(),
        v.target.as_str(),
        v.read_only
      ),
      (name, reference, "/data", read_only)
    );
  }
  assert!(parse_volume_arg("a:b:c:/x").is_err());
}

#[test]
fn gateway_add_unset() {
  assert_eq!(gateway_text(Some(" ".into()), false), Some(None));
  assert_eq!(gateway_port(Some(80), false, 80), Some(None));
  assert_eq!(gateway_port(Some(0), false, 443), Some(None));
}

#[cfg(test)]
#[path = "commands/review_tests.rs"]
mod review_tests;
