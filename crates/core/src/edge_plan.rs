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
  plan::{Action, Impact, Layer},
  spec::{EdgeAppSpec, EdgeKind},
};
use wharf_providers::{Owner, RemoteRecord};

use crate::{
  db::EdgeDomainRow,
  edge::{account, provider_kind},
  planner::{Builder, DnsSpec, RemoteRef, Step},
  snapshot::{self, Snapshot},
  world::{KIND_EDGE, KIND_ROUTE, World},
};

pub async fn edge_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) -> Result<(), ApiError> {
  deploy_items(b, snap, current, desired).await?;
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
  if target_changed {
    if remote_exists {
      let mut impacts = Vec::new();
      if !before_exists {
        impacts.push(Impact::Public);
      }
      impacts.push(Impact::Overwrite);
      return (
        Action::Adopt,
        impacts,
        format!(
          "Cloudflare 账号 {account} 里已有未纳管的 {what} 项目 {project}，发布将覆盖其代码并继承现有绑定"
        ),
      );
    }
    return (
      if before_exists {
        Action::Update
      } else {
        Action::Create
      },
      vec![Impact::Public],
      format!("新建并发布到 Cloudflare {what}（将获得公网访问地址）"),
    );
  }
  let action = if before_exists {
    Action::Update
  } else {
    Action::Create
  };
  let reason = if unfinished {
    format!("上次发布没有完成，重新发布到 Cloudflare {what}")
  } else {
    format!("发布到 Cloudflare {what}")
  };
  (action, vec![], reason)
}

async fn deploy_items(
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
    let up_to_date = match last {
      Some(fp) => fp == fingerprint(name, &app.spec),
      // 记录指纹之前发布的：沿用原来的判断，只看代码来源变没变。
      None => {
        before.is_some_and(|r| r.spec.source.as_ref() == Some(source))
      }
    };
    if up_to_date {
      continue;
    }
    let project = app.spec.project_name(name);
    let target_changed = before.is_none_or(|old| {
      old.spec.account != app.spec.account
        || old.spec.kind != app.spec.kind
        || old.spec.project_name(name) != project
    });
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
      last == Some(DEPLOYING),
    );
    let id = b.item(
      format!("{KIND_EDGE}/{name}"),
      Layer::Edge,
      action,
      None,
      Some(json!({ "project": project })),
      impacts,
      reason,
    );
    b.step(
      vec![id],
      format!("发布 {name}"),
      Step::EdgeDeploy { app: name.clone() },
    );
  }
  Ok(())
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
    let db = crate::db::Db::memory();
    let mut snap = snapshot::load(&db).await.unwrap();
    let run = |snap: &mut Snapshot, deployed: &[(&str, &str)]| {
      snap.edge_deployed = deployed
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    };
    // 没有记录：沿用旧判断，配置没变就不发布。
    run(&mut snap, &[]);
    let mut b = Builder::default();
    deploy_items(&mut b, &snap, &world, &world).await.unwrap();
    assert_eq!(b.items.len(), 0);
    run(&mut snap, &[("w", &fingerprint("w", &spec))]);
    let mut b = Builder::default();
    deploy_items(&mut b, &snap, &world, &world).await.unwrap();
    assert_eq!(b.items.len(), 0);
    // 上次发布中途失败。
    run(&mut snap, &[("w", DEPLOYING)]);
    let mut b = Builder::default();
    deploy_items(&mut b, &snap, &world, &world).await.unwrap();
    assert_eq!(b.items.len(), 1);
  }

  #[test]
  fn edge_deploy_marks_unmanaged_overwrite_and_public() {
    let (action, impacts, _) = deploy_decision(
      EdgeKind::Worker,
      "cf",
      "prod-api",
      false,
      true,
      true,
      false,
    );
    assert_eq!(action, Action::Adopt);
    assert_eq!(impacts, vec![Impact::Public, Impact::Overwrite]);

    let (action, impacts, _) = deploy_decision(
      EdgeKind::Worker,
      "cf",
      "prod-api",
      false,
      true,
      false,
      false,
    );
    assert_eq!(action, Action::Create);
    assert_eq!(impacts, vec![Impact::Public]);

    let (action, impacts, _) = deploy_decision(
      EdgeKind::Worker,
      "cf",
      "prod-api",
      true,
      false,
      true,
      false,
    );
    assert_eq!(action, Action::Update);
    assert!(impacts.is_empty());

    let spec: EdgeAppSpec = serde_json::from_value(json!({
      "account": "cf",
      "kind": "worker",
      "project": "prod-api",
    }))
    .unwrap();
    let mut world = World::default();
    world.edge_apps.insert(
      "app-a".into(),
      crate::world::EdgeRow {
        spec: spec.clone(),
        version: 1,
      },
    );
    let err =
      crate::edge::validate_app(&world, "app-b", &spec).unwrap_err();
    assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
  }
}
