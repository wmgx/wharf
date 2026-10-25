//! cloudflare_tunnel 网关：在厂商账号下建一条隧道（名字 `wharf-<网关>`），
//! 由 Wharf 独占它的入口规则；网关所在的服务器上跑 cloudflared 连接器。
//!
//! 同步顺序：找到或创建隧道 → 写入入口规则 → 部署连接器 → 等隧道变成 healthy。
//! 连接器的 token 只在执行时取，写进 0600 的 compose，不进计划、不算进哈希。

use std::{collections::BTreeMap, time::Duration};

use rusqlite::params;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, ProjectUp, ProjectUpResult},
};
use wharf_providers::{TunnelProvider, TunnelRef};

use crate::{
  apply::cancellable,
  db::{self, now_ms, sql_err},
  hub::ProgressFn,
  render,
  snapshot::{self, Snapshot},
  state::AppState,
  world::gateway_project,
};

const CONNECTOR_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const HEALTHY_WAIT: Duration = Duration::from_secs(60);

pub fn tunnel_name(gateway: &str) -> String {
  format!("wharf-{gateway}")
}

fn account<'a>(
  snap: &'a Snapshot,
  name: &str,
) -> Result<&'a db::AccountRow, ApiError> {
  snap
    .accounts
    .iter()
    .find(|a| a.name == name)
    .ok_or_else(|| {
      ApiError::invalid(format!("厂商账号 {name} 不存在"))
        .suggest("wharf account list")
    })
}

async fn call<T>(
  cancel: &CancellationToken,
  what: &str,
  fut: impl std::future::Future<
    Output = Result<T, wharf_providers::ProviderError>,
  >,
) -> Result<T, ApiError> {
  cancellable(cancel, snapshot::with_timeout(what, fut)).await
}

/// 找到这个网关的隧道：先看控制面的记录，再按名字到厂商那边找，都没有就创建。
async fn ensure_tunnel(
  state: &AppState,
  snap: &Snapshot,
  provider: &dyn TunnelProvider,
  gateway: &str,
  account_name: &str,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<TunnelRef, ApiError> {
  if let Some(row) = snap
    .tunnels
    .get(gateway)
    .filter(|row| row.account == account_name)
  {
    return Ok(TunnelRef {
      scope: row.scope.clone(),
      id: row.tunnel_id.clone(),
    });
  }
  let name = tunnel_name(gateway);
  let found = call(cancel, "查找隧道", provider.find(&name)).await?;
  let tunnel = match found {
    Some(t) => {
      progress(format!("找到已有的隧道 {name}"));
      t
    }
    None => {
      progress(format!("创建隧道 {name}"));
      call(cancel, "创建隧道", provider.create(&name)).await?
    }
  };
  let values = (
    gateway.to_string(),
    account_name.to_string(),
    tunnel.scope.clone(),
    tunnel.id.clone(),
  );
  state
    .db
    .call(move |c| {
      let (gateway, account, scope, id) = values;
      c.execute(
        "INSERT INTO tunnels (gateway, account, scope, tunnel_id, config_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, '', ?5)
         ON CONFLICT (gateway) DO UPDATE SET account = excluded.account, scope = excluded.scope,
           tunnel_id = excluded.tunnel_id, config_hash = ''",
        params![gateway, account, scope, id, now_ms()],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  Ok(tunnel)
}

pub async fn sync(
  state: &AppState,
  snap: &Snapshot,
  gateway: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let world = &snap.world;
  let gw = &world.gateways[gateway].spec;
  let account_name = gw.account.as_deref().ok_or_else(|| {
    ApiError::invalid(format!("网关 {gateway} 没有指定厂商账号"))
  })?;
  let provider =
    snapshot::tunnel_provider(account(snap, account_name)?)?;
  let net = snap.net(world);
  let r = snapshot::gateway_render(world, &net, gateway)?;

  let tunnel = ensure_tunnel(
    state,
    snap,
    provider.as_ref(),
    gateway,
    account_name,
    &progress,
    cancel,
  )
  .await?;

  let rules = r.tunnel_rules();
  progress(format!("写入隧道入口规则（{} 条）", rules.len()));
  for (host, service) in &rules {
    progress(format!("  {host} → {service}"));
  }
  call(
    cancel,
    "写入隧道入口规则",
    provider.put_rules(&tunnel, &rules),
  )
  .await?;
  let (g, hash) = (gateway.to_string(), r.config_hash.clone());
  state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE tunnels SET config_hash = ?1 WHERE gateway = ?2",
        params![hash, g],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;

  let token =
    call(cancel, "读取隧道连接器 token", provider.token(&tunnel))
      .await?;
  let compose = render::substitute(
    &r.compose,
    Some(&BTreeMap::from([(
      render::TUNNEL_TOKEN_SECRET.to_string(),
      token,
    )])),
  )?;
  let server = &gw.server;
  let result: ProjectUpResult = state
    .hub
    .call(
      server,
      AgentOp::ProjectUp(ProjectUp {
        project: gateway_project(gateway),
        compose,
        hash: r.compose_hash.clone(),
        pull: snapshot::pull_policy(&world.servers[server]),
        pull_missing_only: false,
        retire: None,
        rollback: false,
      }),
      CONNECTOR_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if result.containers.iter().any(|c| c.state != "running")
    || result.containers.is_empty()
  {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("网关 {gateway} 的 cloudflared 没有运行起来"),
      )
      .suggest(format!("wharf gateway logs {gateway}")),
    );
  }

  // 连接器起来后几秒内隧道才会变成 healthy。没等到不算失败，只提醒。
  let deadline = tokio::time::Instant::now() + HEALTHY_WAIT;
  loop {
    let status =
      call(cancel, "读取隧道状态", provider.status(&tunnel)).await?;
    if status == "healthy" {
      progress("隧道已连接（healthy）".into());
      break;
    }
    if tokio::time::Instant::now() > deadline {
      progress(format!(
        "提醒：隧道状态是 {status}，cloudflared 可能连不上 Cloudflare，查看 wharf gateway logs {gateway}"
      ));
      break;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
  }
  Ok(())
}

/// 网关删除后删掉它的隧道。控制面没有记录时什么也不做。
pub async fn destroy(
  state: &AppState,
  snap: &Snapshot,
  gateway: &str,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let Some(row) = snap.tunnels.get(gateway) else {
    return Ok(());
  };
  let provider =
    snapshot::tunnel_provider(account(snap, &row.account)?)?;
  progress(format!("删除隧道 {}", tunnel_name(gateway)));
  let tunnel = TunnelRef {
    scope: row.scope.clone(),
    id: row.tunnel_id.clone(),
  };
  call(cancel, "删除隧道", provider.delete(&tunnel)).await?;
  let g = gateway.to_string();
  state
    .db
    .call(move |c| {
      c.execute("DELETE FROM tunnels WHERE gateway = ?1", params![g])
        .map_err(sql_err)?;
      Ok(())
    })
    .await
}
