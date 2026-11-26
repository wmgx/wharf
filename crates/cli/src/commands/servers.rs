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
    ServerCmd::WatchUnit { name, unit, off } => {
      crate::server::watch_unit(c, &name, &unit, !off, j).await
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
          println!(
            "{}/{}  {}  {}  {}  {}",
            p.proto,
            p.port,
            p.addr,
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
    ServerCmd::Note { name, args } => {
      crate::note::run(c, "server", &name, args, j).await
    }
    ServerCmd::Show { name } => {
      let v: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
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
      clear_mirrors,
      mirrors_only,
      private_ip,
      network,
      mode,
      lan_ip,
      clear_lan_ips,
      build_env,
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
      apply,
    } => {
      let current: ServerView =
        c.get(&format!("/api/servers/{}", seg(&name))).await?;
      let mut settings: ServerSettings = current.settings;
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
      apply,
    } => {
      let edits = timezone.is_some()
        || swap_gb.is_some()
        || !sysctl.is_empty()
        || docker_log.is_some()
        || journal_max.is_some()
        || security_updates.is_some()
        || copy_from.is_some();
      if !edits && !apply.apply {
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
    ServerCmd::Prune { name } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/servers/{}/prune", seg(&name)),
          &json!({}),
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
  let r: Value = c.post("/api/servers/upgrade", &json!({})).await?;
  match r["run_id"].as_str() {
    Some(id) => finish_task(c, id, true, j).await,
    None => {
      out(j, &r, |_| println!("全部 agent 都是最新版本"));
      Ok(())
    }
  }
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

async fn upgrade(c: &Client, j: bool) -> CliResult<()> {
  // 替换控制面要靠同机的 agent，落后的 agent 先升到和控制面一致。
  // 只有控制面所在机器的那台必须成功，其余的失败了也接着换控制面。
  // 失败原因 finish_task 已经打印过了。
  if upgrade_outdated(c, j).await.is_err() {
    eprintln!("有 agent 没升级成功，继续升级控制面");
  }
  let before: Value = c.get("/api/version").await?;
  // 请求可能在控制面拉镜像或重启时被代理掐断（超时、502/524），这时按"正在换"处理，
  // 等新构建号出现；等不到再报原来的错误。
  let (r, lost) = match c
    .post_timeout::<_, UpgradeResult>(
      "/api/upgrade",
      &json!({}),
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
  for s in servers.iter().filter(|s| !s.online) {
    eprintln!("{} 不在线，跳过", s.name);
  }
  upgrade_outdated(c, j).await
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
  let v: Value = c.get(&path).await?;
  out(j, &v, |v| {
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
    } else {
      print!("{}", v["logs"].as_str().unwrap_or_default());
      if let Some(n) = v["matched"].as_u64() {
        eprintln!("命中 {n} 行（看了 {} 行）", v["scanned"]);
      }
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
