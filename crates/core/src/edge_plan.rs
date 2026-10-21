//! 边缘应用的计划项：发布代码、绑定 / 解绑自定义域名。
//!
//! - 代码来源变了（或新建）才发布；只纳管、没有代码来源的不发布；
//! - Workers 的域名由厂商连同 DNS 一起管：Wharf 自己写过的记录先删掉，
//!   别人的记录要确认接管；
//! - Pages 的域名走常规 DNS（CNAME 到 `<项目>.pages.dev`），再在项目上绑定。

use serde_json::json;
use wharf_api_types::{
  ApiError,
  plan::{Action, Layer, Risk},
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
  deploy_items(b, current, desired);
  domain_items(b, snap, desired).await
}

fn deploy_items(b: &mut Builder, current: &World, desired: &World) {
  for (name, app) in &desired.edge_apps {
    let Some(source) = &app.spec.source else {
      continue;
    };
    let before = current.edge_apps.get(name);
    if before.is_some_and(|r| r.spec.source.as_ref() == Some(source))
    {
      continue;
    }
    let what = match app.spec.kind {
      EdgeKind::Worker => "Worker",
      EdgeKind::Pages => "Pages",
    };
    let id = b.item(
      format!("{KIND_EDGE}/{name}"),
      Layer::Edge,
      if before.is_some() {
        Action::Update
      } else {
        Action::Create
      },
      None,
      Some(json!({ "project": app.spec.project_name(name) })),
      Risk::Safe,
      format!("发布到 Cloudflare {what}"),
    );
    b.step(
      vec![id],
      format!("发布 {name}"),
      Step::EdgeDeploy { app: name.clone() },
    );
  }
}

/// 路由想要的绑定：主机名 → 边缘应用的厂商项目。
fn wanted(desired: &World) -> Vec<EdgeDomainRow> {
  desired
    .routes
    .iter()
    .filter_map(|(host, route)| {
      let app = desired.edge_apps.get(&route.spec.service)?;
      Some(EdgeDomainRow {
        hostname: host.clone(),
        app: route.spec.service.clone(),
        account: app.spec.account.clone(),
        kind: app.spec.kind.as_str().to_string(),
        project: app
          .spec
          .project_name(&route.spec.service)
          .to_string(),
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
      Risk::Disruptive,
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
      worker_dns(b, snap, desired, &want.hostname).await?
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
        Risk::Destructive
      } else {
        Risk::Safe
      },
      if takeover {
        format!(
          "{} 已有不是 Wharf 创建的 DNS 记录，绑定到 Worker 会覆盖它",
          want.hostname
        )
      } else {
        format!("绑定到 {}", want.project)
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
  desired: &World,
  host: &str,
) -> Result<bool, ApiError> {
  let route_id = &desired.routes[host].id;
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
      Risk::Disruptive,
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
