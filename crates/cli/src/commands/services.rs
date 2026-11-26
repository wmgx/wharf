// SERVICES

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
    ServiceCmd::Heartbeat {
      name,
      every,
      grace,
      off,
      apply,
    } => {
      crate::service_checks::heartbeat(
        c, name, every, grace, off, apply, j,
      )
      .await
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
    ServiceCmd::List => {
      let v: Vec<ServiceView> = c.get("/api/services").await?;
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
      let v: ServiceView = c.get(&path).await?;
      out(j, &v, |v| {
        pretty(v);
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
    ServiceCmd::Logs {
      names,
      tail,
      follow: true,
      ..
    } => {
      follow_logs(
        c,
        &format!(
          "/api/services/{}/logs/stream?tail={tail}",
          seg(&names[0])
        ),
      )
      .await
    }
    ServiceCmd::Discover { server } => {
      discover_service(c, server, j).await
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
    ServiceCmd::AutoUpdate { name, off, apply } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      spec.auto_update = !off;
      changes(
        c,
        vec![Change::UpsertService {
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
          adopt: None,
        }],
        apply,
        j,
      )
      .await
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
      since,
      grep,
      errors,
      max_line,
    } => {
      let args = crate::LogArgs {
        tail,
        since,
        grep,
        errors,
        max_line,
      };
      let path = if let [name] = names.as_slice() {
        format!("/api/services/{}/logs", seg(name))
      } else {
        format!(
          "/api/logs/services?services={}",
          seg(&names.join(","))
        )
      };
      show_logs(c, &path, &args, j).await
    }
    ServiceCmd::Files { name, path } => {
      crate::files::list(c, &name, &path, j).await
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
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
      .await
    }
    ServiceCmd::Restart { name } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/restart", seg(&name)),
          &json!({}),
        )
        .await?;
      finish_task(c, &r.run_id, true, j).await
    }
    ServiceCmd::History { name } => {
      let v: Vec<DeploymentView> = c
        .get(&format!("/api/services/{}/deployments", seg(&name)))
        .await?;
      out(j, &v, |v| {
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
      from_run,
      compose_url,
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
        .and_then(|p| p.container);
      let built = crate::deploy::source(
        c,
        &name,
        &build,
        existing.as_ref().map(|s| &s.source),
        first_port,
      )
      .await?;
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
          for w in &d.warnings {
            eprintln!("提醒：{w}");
          }
          Some(d)
        }
        None => None,
      };
      let url_compose = match &compose_url {
        Some(url) => Some(crate::deploy::fetch_compose(url).await?),
        None => None,
      };
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
            log_alerts: vec![],
            port_checks: Default::default(),
            heartbeat: None,
            limits: None,
            auto_update: false,
            container: None,
            files: vec![],
          }
        }
      };
      if let Some(source) = source {
        spec.source = source;
      }
      if let Some(server) = server {
        spec.server = server;
      }
      if let Some(d) = draft {
        spec.ports = d.ports;
        spec.env.extend(d.env);
        spec.volumes = d.volumes;
        spec.limits = d.limits;
      }
      if !port.is_empty() {
        spec.ports = port
          .iter()
          .map(|p| parse_port(p))
          .collect::<CliResult<_>>()?;
      } else if let (true, Some(p)) = (is_new, default_port) {
        spec.ports = vec![PortSpec {
          name: "http".into(),
          container: Some(p),
          host: None,
          udp: false,
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
      changes(
        c,
        vec![Change::UpsertService {
          name,
          spec,
          adopt: None,
        }],
        apply,
        j,
      )
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
      changes(
        c,
        vec![Change::UpsertService {
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
      path,
      port,
      expect,
      keyword,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      spec.monitor = if off {
        None
      } else {
        let cur = spec.monitor.take();
        Some(wharf_api_types::spec::MonitorSpec {
          path: path
            .or_else(|| cur.as_ref().map(|m| m.path.clone()))
            .unwrap_or_else(|| "/".into()),
          port: port
            .or_else(|| cur.as_ref().and_then(|m| m.port.clone())),
          expect: expect
            .or_else(|| cur.as_ref().and_then(|m| m.expect)),
          keyword: keyword
            .or_else(|| cur.as_ref().and_then(|m| m.keyword.clone()))
            .filter(|k| !k.is_empty()),
        })
      };
      changes(
        c,
        vec![Change::UpsertService {
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
      memory,
      cpus,
      off,
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
      if off {
        spec.limits = None;
      } else {
        let limits =
          spec.limits.get_or_insert(wharf_api_types::spec::Limits {
            memory_mb: None,
            cpu_milli: None,
          });
        if let Some(memory) = memory {
          limits.memory_mb = (memory != 0).then_some(memory);
        }
        if let Some(cpus) = cpus {
          limits.cpu_milli =
            (cpus != 0.0).then_some((cpus * 1000.0).round() as u32);
        }
      }
      changes(
        c,
        vec![Change::UpsertService {
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
      path,
      file,
      rm,
      apply,
    } => {
      let mut spec = c
        .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
        .await?
        .spec;
      let Some(path) = path else {
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
        match spec.files.iter_mut().find(|f| f.path == path) {
          Some(f) => f.content = content,
          None => spec
            .files
            .push(wharf_api_types::spec::FileSpec { path, content }),
        }
      } else {
        let f = spec
          .files
          .iter()
          .find(|f| f.path == path)
          .ok_or_else(missing)?;
        out(j, f, |f| print!("{}", f.content));
        return Ok(());
      }
      changes(
        c,
        vec![Change::UpsertService {
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
