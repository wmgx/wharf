//! 各子命令的实现。

use std::{collections::BTreeMap, io::Write, time::Duration};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::UpgradeResult,
  plan::{
    ApplyRequest, ApplyResponse, Plan, PlanRequest, Run, RunStatus,
  },
  spec::{
    BackupSpec, Change, Fleet, GatewayKind, GatewaySpec, GatewayTls,
    NetworkMode, PathRoute, PortSpec, PrivateAddr, PrivateNetwork,
    Region, RouteSpec, ServerSettings, ServiceSpec, Source, SsoMode,
    VolumeSpec,
  },
  view::{
    AccountView, AppAccountView, AutoUpdateResult, BackupsView,
    CheckStatus, DataView, DeploymentView, DoctorReport, GatewayView,
    HostExecResponse, ImportPreview, ImportRequest, JoinInfo,
    NetworkView, RestoreRequest, RollbackTarget, RouteView,
    ScriptRuntime, SecretView, ServerView, ServiceView, ShellLog,
    SsoStepResult, SsoTestResult, Status, Unmanaged,
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

pub async fn run(cli: Cli) -> CliResult<()> {
  let j = cli.json;
  match cli.command {
    Command::Login { url, core_key } => login(url, core_key, j).await,
    Command::Schema { resource } => schema(resource.as_deref()),
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
    Command::Commands { prefix, .. } => {
      let all = crate::describe::commands(&[]);
      crate::selfcmd::save_snapshot(&all);
      // 紧凑输出：全部命令有上百条，省掉缩进能少一半多的字符。
      if prefix.is_empty() {
        println!("{all}");
      } else {
        println!("{}", crate::describe::commands(&prefix));
      }
      Ok(())
    }
    Command::Token(cmd) => {
      crate::token::run(cmd, cli.url, cli.token, j).await
    }
    Command::Service(ServiceCmd::Logs { names, follow: true, .. })
      if names.len() > 1 =>
    {
      Err(ApiError::invalid(
        "多服务合看不支持 -f，用 --since 看最近的日志，或单个服务用 -f",
      ).into())
    }
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
        let host = host.trim().to_ascii_lowercase();
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
          &format!("/api/routes/{}/sso/test", seg(&hostname)),
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
        from_run: None,
        compose_url: None,
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
      timeout,
      cwd,
      command,
    } => host_exec(c, server, timeout, cwd, command, j).await,
    Command::Audit { actor, kind, limit } => {
      crate::audit::audit(c, actor, kind, limit, j).await
    }
    Command::ShellLog { server, limit } => {
      shell_log(c, server, limit, j).await
    }
    Command::Upgrade => {
      upgrade(c, j).await?;
      crate::selfcmd::self_update(c, j).await
    }
    Command::SelfUpdate => crate::selfcmd::self_update(c, j).await,
    Command::Whoami => crate::selfcmd::whoami(c, j).await,
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
        Some(EgressCmd::Api { server }) => {
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
    Command::Doctor { hostname } => {
      let path = match &hostname {
        Some(h) => format!("/api/doctor?host={}", seg(h)),
        None => "/api/doctor".to_string(),
      };
      let v: DoctorReport = c.get(&path).await?;
      out(j, &v, print::doctor);
      let bad = v
        .servers
        .iter()
        .chain(&v.vendors)
        .chain(&v.config)
        .chain(v.routes.iter().flat_map(|r| &r.checks))
        .filter(|c| c.status == CheckStatus::Bad)
        .count();
      if bad > 0 {
        return Err(anyhow::anyhow!("{bad} 项不通").into());
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
      file,
      partial,
      apply,
    } => {
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
      plan_id,
      confirm,
      no_wait,
    } => apply(c, &plan_id, confirm, !no_wait, j, None).await,
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

include!("commands/connection_and_plan.rs");
include!("commands/servers.rs");
include!("commands/services.rs");
include!("commands/gateways.rs");
include!("commands/routes.rs");
include!("commands/accounts_and_backup.rs");
