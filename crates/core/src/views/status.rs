use super::*;

pub async fn status(
  state: &AppState,
  allowed: Option<&std::collections::BTreeSet<String>>,
) -> Result<Status, wharf_api_types::ApiError> {
  crate::rules::ensure_loaded(state).await;
  let snap = snapshot::load(&state.db).await?;
  let net = snap.net(&snap.world);
  let live = cached_live(state, &snap.world).await;
  let mut issues = Vec::new();
  let servers: Vec<ServerView> = snap
    .world
    .servers
    .keys()
    .filter_map(|n| server_view(state, &snap, n))
    .collect();
  for s in &servers {
    if !s.joined {
      issues.push(Issue {
        code: "server_not_joined".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: s.name.clone(),
        }),
        title: format!("服务器 {} 还没有完成 agent 加入", s.name),
        hint: None,
        ack: None,
        alert: None,
      });
    } else if !s.online {
      let (alert, ack) =
        crate::rules::issue_alert("server_offline", &s.name);
      issues.push(Issue {
        code: "server_offline".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: s.name.clone(),
        }),
        title: format!("服务器 {} 离线", s.name),
        hint: None,
        ack,
        alert,
      });
    }
    let disks = s
      .report
      .as_ref()
      .map(|r| [("磁盘", r.disk), ("Docker 所在磁盘", r.docker_disk)])
      .unwrap_or_default();
    for (label, d) in disks {
      if let Some(d) = d
        && low_disk(d)
      {
        let top = crate::disk::top(state, &s.name, 3).await;
        let hint = format!(
          "完整排行：wharf server disk {0}；镜像、构建缓存和日志：wharf server host {0}",
          s.name
        );
        let hint = if top.is_empty() {
          hint
        } else {
          format!(
            "占得最多的服务：{}。{hint}",
            crate::disk::top_text(&top)
          )
        };
        issues.push(Issue {
          code: "disk_low".into(),
          level: IssueLevel::Warn,
          subject: Some(IssueSubject {
            kind: "server".into(),
            name: s.name.clone(),
          }),
          title: format!(
            "服务器 {} {label}只剩 {:.1} GB",
            s.name,
            d.free as f64 / GB
          ),
          hint: Some(hint),
          ack: None,
          alert: None,
        });
      }
    }
  }
  let services: Vec<ServiceView> = snap
    .world
    .services
    .keys()
    .filter_map(|n| service_view(&snap, &net, n, Some(&live)))
    .collect();
  let gateways: Vec<GatewayView> = snap
    .world
    .gateways
    .keys()
    .filter_map(|n| gateway_view(&snap, &net, n, Some(&live)))
    .collect();
  for s in &services {
    if let Some(st) = &s.status
      && matches!(st.tone, Tone::Warn | Tone::Bad)
    {
      issues.push(Issue {
        code: "service_unhealthy".into(),
        level: if st.tone == Tone::Bad {
          IssueLevel::Fault
        } else {
          IssueLevel::Warn
        },
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: s.name.clone(),
        }),
        title: format!("服务 {}：{}", s.name, st.summary),
        hint: None,
        ack: None,
        alert: None,
      });
    }
  }
  for (kind, name, live) in
    gateways.iter().map(|g| ("网关", &g.name, &g.live))
  {
    let Some(live) = live else { continue };
    if live.state != "running" && live.state != "unknown" {
      issues.push(Issue {
        code: "gateway_state".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "gateway".into(),
          name: name.clone(),
        }),
        title: format!("{kind} {name} 状态是 {}", live.state),
        hint: None,
        ack: None,
        alert: None,
      });
    } else if live.in_sync == Some(false) {
      issues.push(Issue {
        code: "gateway_drift".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "gateway".into(),
          name: name.clone(),
        }),
        title: format!("{kind} {name} 和配置不一致"),
        hint: Some("，执行 wharf plan 查看".into()),
        ack: None,
        alert: None,
      });
    }
  }
  let edge_apps: Vec<EdgeAppView> = snap
    .world
    .edge_apps
    .keys()
    .filter_map(|n| edge_view(&snap, n))
    .collect();
  for app in &edge_apps {
    if let Some(d) = &app.drift {
      issues.push(Issue {
        code: "edge_drift".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "edge".into(),
          name: app.name.clone(),
        }),
        title: format!("边缘应用 {}：{d}", app.name),
        hint: None,
        ack: None,
        alert: None,
      });
    } else if let Some(EdgeLive { error: Some(e), .. }) = &app.live {
      issues.push(Issue {
        code: "edge_sync".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "edge".into(),
          name: app.name.clone(),
        }),
        title: format!("边缘应用 {} 同步失败：{e}", app.name),
        hint: None,
        ack: None,
        alert: None,
      });
    }
  }
  issues.extend(crate::link_cert::issues(&snap, &net));
  issues.extend(crate::totp::issues(&state.db).await?);
  issues.extend(crate::tasks::issues(state).await);
  issues.extend(crate::probe::issues());
  issues.extend(crate::exposure::issues(state).await?);
  issues.extend(crate::sso_login::issues(&snap));
  issues.extend(crate::alerts::issues());
  issues.extend(crate::rules::custom_issues(&snap.world));
  issues.extend(crate::external_checks::issues(&servers));
  issues.extend(crate::monitor::issues());
  issues.extend(crate::service_monitor::issues(&snap.world));
  issues
    .extend(crate::service_monitor::unmanaged::issues(state).await?);
  issues.extend(services.iter().filter_map(|s| {
    crate::service_monitor::stopped_issue(
      &s.name,
      &s.containers,
      crate::db::now_ms(),
    )
  }));
  issues.extend(crate::rdap::issues());
  issues.extend(crate::disk_forecast::issues());
  issues.extend(crate::clock::issues());
  issues.extend(crate::oom::issues());
  issues.extend(crate::traffic::issues());
  issues.extend(crate::baseline::issues());
  issues.extend(crate::host_units::issues());
  issues.extend(crate::net_conflict::issues(&snap));
  let updates = crate::updates::current(&snap);
  if let Some(updates) = &updates {
    for (name, check) in &updates.services {
      if check.newer && services.iter().any(|s| &s.name == name) {
        issues.push(Issue {
          code: "update_available".into(),
          level: IssueLevel::Info,
          subject: Some(IssueSubject {
            kind: "service".into(),
            name: name.clone(),
          }),
          title: format!("{name} 有新版本"),
          hint: None,
          ack: None,
          alert: None,
        });
      }
      if let Some(t) = check.tags.first()
        && services.iter().any(|s| &s.name == name)
      {
        let all = check
          .tags
          .iter()
          .map(|t| {
            let major = if t.major { "（大版本）" } else { "" };
            format!("{}{major}", t.tag)
          })
          .collect::<Vec<_>>()
          .join("、");
        issues.push(Issue {
          code: "tag_available".into(),
          level: IssueLevel::Info,
          subject: Some(IssueSubject {
            kind: "service".into(),
            name: name.clone(),
          }),
          title: format!("{name} 有更高版本的镜像：{all}"),
          hint: Some(format!(
            "换标签要改配置：wharf service retag {name} {} {}",
            t.image, t.tag
          )),
          ack: None,
          alert: None,
        });
      }
    }
    if let Some(pending) = &updates.pending
      && !pending.items.is_empty()
    {
      let items = &pending.items;
      issues.push(Issue {
        code: "pending_changes".into(),
        level: IssueLevel::Info,
        subject: None,
        title: format!(
          "有 {} 项改动还没执行：{}{}",
          items.len(),
          items
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("、"),
          if items.len() > 3 { " 等" } else { "" }
        ),
        hint: None,
        ack: None,
        alert: None,
      });
    }
  }
  issues.extend(crate::auto_update::issues());
  issues.extend(crate::share::issues(
    &snap.world,
    Utc::now().timestamp_millis(),
  ));
  let problems = problems_text(&issues);
  issues.sort_by_key(|i| {
    let rank = match i.level {
      IssueLevel::Fault => 0,
      IssueLevel::Warn => 1,
      IssueLevel::Info => 2,
    };
    (rank, i.ack.is_some())
  });
  let mut edge_unmanaged: Vec<EdgeProjectView> =
    snap.edge_accounts.values().flatten().cloned().collect();
  crate::edge_sync::mark_managed(&snap, &mut edge_unmanaged);
  edge_unmanaged.retain(|p| p.managed_as.is_none());
  let routes = snap
    .world
    .routes
    .keys()
    .filter_map(|h| route_view(&snap, &net, h))
    .collect();
  let mut bookmarks: Vec<_> = snap
    .world
    .bookmarks
    .iter()
    .map(|(id, r)| BookmarkView {
      id: id.clone(),
      spec: r.spec.clone(),
      version: r.version,
    })
    .collect();
  bookmarks.sort_by(|a, b| {
    a.spec
      .order
      .cmp(&b.spec.order)
      .then_with(|| a.spec.title.cmp(&b.spec.title))
  });
  let mut status = Status {
    bookmarks,
    servers,
    services,
    edge_apps,
    edge_unmanaged,
    gateways,
    routes,
    problems,
    issues,
    health: crate::doctor::last(),
    updates,
  };
  if let Some(allowed) = allowed {
    crate::scope_filter::filter_status(
      allowed,
      &snap.world,
      &mut status,
    );
  }
  Ok(status)
}
