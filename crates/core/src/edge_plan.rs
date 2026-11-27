//! 边缘应用的计划项：发布代码、绑定 / 解绑自定义域名。
//!
//! - 和上次发布成功的不一样（代码来源、账户、项目）才发布；上次发布没做完的重新发布；
//!   只纳管、没有代码来源的不发布；
//! - Workers 的域名由厂商连同 DNS 一起管：Wharf 自己写过的记录先删掉，
//!   别人的记录要确认接管；
//! - Pages 的域名走常规 DNS（CNAME 到 `<项目>.pages.dev`），再在项目上绑定。

use serde_json::json;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ResolveCommit},
  plan::{Action, Impact, Layer},
  spec::{EdgeAppSpec, EdgeKind},
};
use wharf_providers::{Owner, RemoteRecord};

use crate::{
  db::EdgeDomainRow,
  edge::{account, provider_kind},
  planner::{Builder, DnsSpec, RemoteRef, Step},
  snapshot::{self, Snapshot},
  state::AppState,
  world::{KIND_EDGE, KIND_ROUTE, World},
};

pub async fn edge_items(
  state: &AppState,
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) -> Result<(), ApiError> {
  deploy_items(state, b, snap, current, desired).await?;
  domain_items(b, snap, desired).await
}

/// 发布开始时写入，成功后换成配置指纹；停在这个值说明上次发布没做完。
pub const DEPLOYING: &str = "deploying";

/// settings 表里记上次发布成功的配置指纹的键。
pub fn deployed_key(app: &str) -> String {
  format!("edge.deployed.{app}")
}

/// 决定发布结果的配置：账户、类型、厂商项目、代码来源（不含在哪台机器上构建）。
pub fn fingerprint(name: &str, spec: &EdgeAppSpec) -> String {
  crate::render::hash(
    &json!({
      "account": spec.account,
      "kind": spec.kind,
      "project": spec.project_name(name),
      "source": spec.source,
    })
    .to_string(),
  )
}

async fn deploy_items(
  state: &AppState,
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) -> Result<(), ApiError> {
  for (name, app) in &desired.edge_apps {
    let Some(source) = &app.spec.source else {
      continue;
    };
    let before = current.edge_apps.get(name);
    let last = snap.edge_deployed.get(name).map(String::as_str);
    let project = app.spec.project_name(name);
    let target_changed = before.is_none_or(|old| {
      old.spec.account != app.spec.account
        || old.spec.kind != app.spec.kind
        || old.spec.project_name(name) != project
    });
    let up_to_date = match last {
      Some(fp) => fp == fingerprint(name, &app.spec),
      None => {
        !target_changed
          && before
            .is_some_and(|r| r.spec.source.as_ref() == Some(source))
      }
    };
    let pending = snap.pending.edge_deploys.contains(name);
    if up_to_date && !pending {
      continue;
    }
    let commit = plan_build(state, b, snap, name, &app.spec).await?;
    let remote_exists = if target_changed {
      let provider =
        snapshot::edge_provider(account(snap, &app.spec.account)?)?;
      snapshot::with_timeout(
        &format!("检查 Cloudflare 项目 {project}"),
        provider.get(provider_kind(app.spec.kind), project),
      )
      .await?
      .is_some()
    } else {
      false
    };
    let (action, impacts, reason) = deploy_decision(
      app.spec.kind,
      &app.spec.account,
      project,
      before.is_some(),
      target_changed,
      remote_exists,
      pending || last == Some(DEPLOYING),
    );
    let mut after = json!({ "project": project });
    let reason = if let Some(sha) = &commit {
      after["commit"] = json!(&sha[..12]);
      format!("{reason}（commit {}）", &sha[..12])
    } else {
      reason
    };
    let id = b.item(
      format!("{KIND_EDGE}/{name}"),
      Layer::Edge,
      action,
      None,
      Some(after),
      impacts,
      reason,
    );
    b.step(
      vec![id],
      format!("发布 {name}"),
      Step::EdgeDeploy {
        app: name.clone(),
        commit,
      },
    );
  }
  Ok(())
}

async fn plan_build(
  state: &AppState,
  b: &mut Builder,
  snap: &Snapshot,
  name: &str,
  spec: &EdgeAppSpec,
) -> Result<Option<String>, ApiError> {
  let Some(src) = &spec.source else {
    return Ok(None);
  };
  if src.script.is_some()
    && src.upload.is_some()
    && spec.kind == EdgeKind::Worker
  {
    return Ok(None);
  }
  let git = src.git.as_ref();
  let server = match crate::edge::builder(state, snap, spec) {
    Ok(s) => s,
    Err(e) if git.is_some() => return Err(e),
    Err(_) => return Ok(None),
  };
  if !state.hub.supports_build_v2(&server) {
    if git.is_some_and(|g| g.user.is_some()) {
      return Err(crate::build::old_git_agent(&server));
    }
    b.warnings.push(crate::build::old_agent_warning(&server));
  }
  let Some(git) = git else { return Ok(None) };
  let fetch = crate::build::code_fetch(
    state,
    &crate::secret_policy::non_system_secrets(&snap.secrets),
    &format!("边缘应用 {name}"),
    None,
    Some(git),
    None,
  )?;
  let commit: String = state
    .hub
    .call(
      &server,
      AgentOp::ResolveCommit(ResolveCommit {
        service: name.into(),
        fetch,
        pull: snapshot::committed_pull_policy(&snap.world, &server),
      }),
      crate::pins::COMMIT_TIMEOUT,
      None,
      &Default::default(),
    )
    .await
    .map_err(|e| {
      e.with_hint("检查 Git 仓库地址、分支名和私有仓库令牌")
    })?;
  if commit.len() != 40
    || !commit.bytes().all(|b| b.is_ascii_hexdigit())
  {
    return Err(ApiError::invalid("Git 版本必须是 40 位 commit"));
  }
  Ok(Some(commit))
}

pub(crate) fn deploy_decision(
  kind: EdgeKind,
  account: &str,
  project: &str,
  before_exists: bool,
  target_changed: bool,
  remote_exists: bool,
  unfinished: bool,
) -> (Action, Vec<Impact>, String) {
  let what = match kind {
    EdgeKind::Worker => "Worker",
    EdgeKind::Pages => "Pages",
  };
  let action = if before_exists {
    Action::Update
  } else {
    Action::Create
  };
  if target_changed && remote_exists {
    let impacts = if before_exists {
      vec![Impact::Overwrite]
    } else {
      vec![Impact::Public, Impact::Overwrite]
    };
    return (
      Action::Adopt,
      impacts,
      format!(
        "Cloudflare 账号 {account} 里已有未纳管的 {what} 项目 {project}，发布将覆盖其代码并继承现有绑定"
      ),
    );
  }
  if target_changed {
    return (
      action,
      vec![Impact::Public],
      format!("新建并发布到 Cloudflare {what}（将获得公网访问地址）"),
    );
  }
  let reason = if unfinished {
    format!("上次发布没有完成，重新发布到 Cloudflare {what}")
  } else {
    format!("发布到 Cloudflare {what}")
  };
  (action, vec![], reason)
}

/// 想要的绑定：域名 → 边缘应用的厂商项目。
fn wanted(desired: &World) -> Vec<EdgeDomainRow> {
  desired
    .edge_apps
    .iter()
    .flat_map(|(name, app)| {
      app.spec.domains.iter().map(move |host| EdgeDomainRow {
        hostname: host.clone(),
        app: name.clone(),
        account: app.spec.account.clone(),
        kind: app.spec.kind.as_str().to_string(),
        project: app.spec.project_name(name).to_string(),
      })
    })
    .collect()
}

async fn domain_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
) -> Result<(), ApiError> {
  let wanted = wanted(desired);
  for row in &snap.edge_domains {
    let same = |w: &EdgeDomainRow| {
      w.hostname == row.hostname
        && w.account == row.account
        && w.kind == row.kind
        && w.project == row.project
    };
    if wanted.iter().any(same) {
      continue;
    }
    let id = b.item(
      format!("{KIND_ROUTE}/{}", row.hostname),
      Layer::Edge,
      Action::Delete,
      Some(json!({ "project": row.project, "kind": row.kind })),
      None,
      vec![Impact::Downtime],
      format!("从 {} 解绑域名", row.project),
    );
    b.step(
      vec![id],
      format!("解绑 {}", row.hostname),
      Step::EdgeDetach {
        domain: row.clone(),
      },
    );
  }

  for want in &wanted {
    if snap.edge_domains.contains(want) {
      continue;
    }
    let takeover = if want.kind == EdgeKind::Worker.as_str() {
      worker_dns(b, snap, &want.hostname).await?
    } else {
      false
    };
    let id = b.item(
      format!("{KIND_ROUTE}/{}", want.hostname),
      Layer::Edge,
      Action::Create,
      None,
      Some(json!({ "project": want.project, "kind": want.kind })),
      if takeover {
        vec![Impact::Public, Impact::Overwrite]
      } else {
        vec![Impact::Public]
      },
      if takeover {
        format!(
          "{} 已有不是 Wharf 创建的 DNS 记录，绑定到 Worker 会覆盖它",
          want.hostname
        )
      } else {
        format!("绑定公网自定义域名到 {}", want.project)
      },
    );
    b.step(
      vec![id],
      format!("把 {} 绑定到 {}", want.hostname, want.app),
      Step::EdgeAttach {
        hostname: want.hostname.clone(),
        app: want.app.clone(),
        takeover,
      },
    );
  }
  Ok(())
}

/// Worker 绑定域名前的 DNS 处理：删掉 Wharf 以前为这个域名写的记录，
/// 返回是否有别人的记录要接管。
async fn worker_dns(
  b: &mut Builder,
  snap: &Snapshot,
  host: &str,
) -> Result<bool, ApiError> {
  let route_id = &crate::world::edge_owner(host);
  // 已删除路由留下的记录由常规 DNS 计划删除，这里只管这条路由自己的。
  for owned in snap
    .owned
    .iter()
    .filter(|o| o.hostname == host && &o.route_id == route_id)
  {
    let id = b.item(
      format!("{KIND_ROUTE}/{host}"),
      Layer::Dns,
      Action::Delete,
      Some(json!({ "account": owned.account, "remote_id": owned.remote_id })),
      None,
      vec![Impact::Remove],
      "改由 Worker 管理这个域名的 DNS",
    );
    b.step(
      vec![id],
      format!("删除 {host} 原来的 DNS 记录"),
      Step::DnsDelete {
        hostname: host.to_string(),
        account: owned.account.clone(),
        remote: RemoteRef {
          scope: owned.scope.clone(),
          remote_id: owned.remote_id.clone(),
        },
        owner: Some(owned.route_id.clone()),
      },
    );
  }
  let Some((account, _)) = snap.account_for(host) else {
    return Ok(false);
  };
  let provider = snapshot::dns_provider(account)?;
  let records = snapshot::with_timeout(
    &format!("读取 {host} 的 DNS 记录"),
    provider.list(host),
  )
  .await?;
  let owner = Owner {
    id: route_id.clone(),
  };
  let ours: Vec<&str> =
    snap.owned.iter().map(|o| o.remote_id.as_str()).collect();
  Ok(records.iter().any(|r: &RemoteRecord| {
    !provider.is_owned(r, &owner)
      && !ours.contains(&r.remote_id.as_str())
  }))
}

/// Pages 自定义域名要的 DNS 记录：CNAME 到项目的 pages.dev 地址。
pub async fn pages_record(
  snap: &Snapshot,
  name: &str,
  spec: &EdgeAppSpec,
) -> Result<DnsSpec, ApiError> {
  let provider =
    snapshot::edge_provider(account(snap, &spec.account)?)?;
  let kind = provider_kind(spec.kind);
  let project = snapshot::with_timeout(
    &format!("读取 Pages 项目 {}", spec.project_name(name)),
    provider.get(kind, spec.project_name(name)),
  )
  .await?
  .unwrap_or_else(|| wharf_providers::EdgeProject {
    name: spec.project_name(name).to_string(),
    ..Default::default()
  });
  let record =
    provider.domain_dns(kind, &project).ok_or_else(|| {
      ApiError::internal("Pages 项目没有可以指向的地址")
    })?;
  Ok(DnsSpec {
    record_type: "CNAME".into(),
    content: record.content,
    proxied: record.proxied,
    tunnel: None,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  use wharf_api_types::{ErrorCode, plan::PlanRequest, spec::Change};

  fn edge_app(name: &str, kind: EdgeKind) -> Change {
    let spec = serde_json::from_value(json!({
      "account": "cf", "kind": kind, "project": "demo"
    }))
    .unwrap();
    Change::UpsertEdgeApp {
      name: name.into(),
      spec,
    }
  }

  #[tokio::test]
  async fn edge_plan_rejects_new_duplicate_owner() {
    let state = crate::rules::tests::test_state();
    let mut snap = Snapshot::default();
    snap
      .world
      .apply_changes(&[edge_app("prod", EdgeKind::Worker)])
      .unwrap();
    let req = PlanRequest {
      changes: vec![edge_app("test", EdgeKind::Worker)],
      ..PlanRequest::default()
    };
    let Err(err) =
      crate::planner::make_plan_inner(&state, req, snap, false, true)
        .await
    else {
      panic!("计划接受了重复纳管");
    };
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(
      err.message.contains("prod") && err.message.contains("test")
    );
    assert!(err.hint.unwrap().contains("--project"));
  }

  #[test]
  fn edge_owner_conflict_prefers_existing_app_in_batch() {
    let mut current = crate::world::World::default();
    current
      .apply_changes(&[edge_app("prod", EdgeKind::Worker)])
      .unwrap();
    let mut desired = current.clone();
    desired
      .apply_changes(&[
        edge_app("a", EdgeKind::Worker),
        edge_app("b", EdgeKind::Worker),
      ])
      .unwrap();

    let err =
      crate::edge::validate_owners(&current, &desired).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(
      err.message,
      "边缘应用 a 和 prod 都指向厂商项目 cf/worker/demo"
    );
    assert_eq!(
      err.hint.as_deref(),
      Some("换一个 --project，或改用已有的应用名 prod")
    );
  }

  #[tokio::test]
  async fn edge_plan_warns_legacy_duplicates_and_allows_other_kind() {
    let state = crate::rules::tests::test_state();
    let mut snap = Snapshot::default();
    snap
      .world
      .apply_changes(&[
        edge_app("prod", EdgeKind::Worker),
        edge_app("legacy", EdgeKind::Worker),
      ])
      .unwrap();
    let plan = crate::planner::make_plan_inner(
      &state,
      PlanRequest::default(),
      Snapshot {
        world: snap.world.clone(),
        ..Snapshot::default()
      },
      false,
      true,
    )
    .await
    .unwrap();
    assert!(
      plan.writes.is_empty()
        && plan.steps.is_empty()
        && plan.plan.items.is_empty()
    );
    assert!(plan.plan.warnings.iter().any(|w| {
      w.contains("已有 1 个厂商项目被多个边缘应用纳管")
    }));

    let req = PlanRequest {
      changes: vec![edge_app("pages", EdgeKind::Pages)],
      ..PlanRequest::default()
    };
    let plan =
      crate::planner::make_plan_inner(&state, req, snap, false, true)
        .await
        .unwrap();
    assert_eq!(plan.writes.len(), 1);
    assert!(plan.steps.is_empty());
  }

  #[tokio::test]
  async fn skipped_initial_edge_deploy_is_replanned_from_pending_steps()
   {
    let mut snap = Snapshot::default();
    snap.world.edge_apps.insert(
      "site".into(),
      crate::world::EdgeRow {
        spec: serde_json::from_value(
          json!({"account": "cf", "kind": "worker",
        "source": {"upload": "abc", "script": "index.js"}}),
        )
        .unwrap(),
        version: 1,
      },
    );
    snap.pending.edge_deploys.insert("site".into());
    let mut b = Builder::default();
    deploy_items(&mut b, &snap, &snap.world, &snap.world)
      .await
      .unwrap();
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].address, "edge/site");
    assert!(b.items[0].reason.contains("上次发布没有完成"));
  }

  #[tokio::test]
  async fn redeploys_after_unfinished_deploy() {
    let spec: EdgeAppSpec = serde_json::from_value(json!({
      "account": "cf",
      "kind": "worker",
      "source": { "upload": "abc", "script": "index.js" },
    }))
    .unwrap();
    let mut world = World::default();
    world.edge_apps.insert(
      "w".into(),
      crate::world::EdgeRow {
        spec: spec.clone(),
        version: 1,
      },
    );
    let plan = async |deployed: &[(&str, &str)]| {
      let snap = Snapshot {
        edge_deployed: deployed
          .iter()
          .map(|(k, v)| (k.to_string(), v.to_string()))
          .collect(),
        ..Snapshot::default()
      };
      let mut b = Builder::default();
      let state = crate::rules::tests::test_state();
      deploy_items(&state, &mut b, &snap, &world, &world)
        .await
        .unwrap();
      b.items.len()
    };
    // 没有记录：沿用旧判断，配置没变就不发布。
    assert_eq!(plan(&[]).await, 0);
    assert_eq!(plan(&[("w", &fingerprint("w", &spec))]).await, 0);
    // 上次发布中途失败。
    assert_eq!(plan(&[("w", DEPLOYING)]).await, 1);
  }
}

#[cfg(test)]
#[test]
fn edge_deploy_marks_unmanaged_overwrite_and_public() {
  for (before, changed, remote, expected, expected_impacts) in [
    (
      false,
      true,
      true,
      Action::Adopt,
      vec![Impact::Public, Impact::Overwrite],
    ),
    (false, true, false, Action::Create, vec![Impact::Public]),
    (true, false, true, Action::Update, vec![]),
  ] {
    let (action, impacts, _) = deploy_decision(
      EdgeKind::Worker,
      "cf",
      "prod-api",
      before,
      changed,
      remote,
      false,
    );
    assert_eq!((action, impacts), (expected, expected_impacts));
  }
}
