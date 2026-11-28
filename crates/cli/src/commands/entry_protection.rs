use clap::Args;
use wharf_api_types::spec::RouteSpec;

use super::{
  ApplyFlags, Change, CliResult, Client, GatewayView, changes, out,
  pretty, seg,
};

#[derive(Args)]
pub struct RouteProtectionArgs {
  /// 控制面页面仅向组网开放。只适用于指向控制面的 Caddy 路由。
  #[arg(long, num_args = 0..=1, default_missing_value = "true")]
  core_mesh_only: Option<bool>,
  /// 只允许 Cloudflare 官方 IP 直连。只适用于 Caddy 路由。
  #[arg(long, num_args = 0..=1, default_missing_value = "true")]
  cf_origin_only: Option<bool>,
}

impl RouteProtectionArgs {
  pub(crate) fn has_edits(&self) -> bool {
    self.core_mesh_only.is_some() || self.cf_origin_only.is_some()
  }

  pub(crate) fn set(self, spec: &mut RouteSpec) {
    if let Some(enabled) = self.core_mesh_only {
      spec.core_mesh_only = enabled;
    }
    if let Some(enabled) = self.cf_origin_only {
      spec.cf_origin_only = enabled;
    }
  }
}

#[derive(Args)]
pub struct TimeoutsArgs {
  name: String,
  /// 读请求头超时（秒）。
  #[arg(long)]
  read_header: Option<u32>,
  /// 空闲连接超时（秒）。
  #[arg(long)]
  idle: Option<u32>,
  /// 热重载宽限（秒）。
  #[arg(long)]
  grace_period: Option<u32>,
  /// 三项都恢复默认值。
  #[arg(long, visible_alias = "off", conflicts_with_all = ["read_header", "idle", "grace_period"])]
  default: bool,
  #[command(flatten)]
  apply: ApplyFlags,
}

pub(super) async fn timeouts(
  c: &Client,
  args: TimeoutsArgs,
  j: bool,
) -> CliResult<()> {
  let TimeoutsArgs {
    name,
    read_header,
    idle,
    grace_period,
    default,
    apply,
  } = args;
  let mut spec = c
    .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
    .await?
    .spec;
  if spec.kind != wharf_api_types::spec::GatewayKind::Caddy {
    return Err(
      wharf_api_types::ApiError::invalid(
        "连接超时和热重载宽限只支持 Caddy 网关",
      )
      .into(),
    );
  }
  if !default
    && read_header.is_none()
    && idle.is_none()
    && grace_period.is_none()
  {
    apply.check_read_only()?;
    out(
      j,
      &serde_json::json!({
        "read_header_timeout": spec.read_header_timeout.unwrap_or(10),
        "idle_timeout": spec.idle_timeout.unwrap_or(120),
        "grace_period": spec.grace_period.unwrap_or(10),
      }),
      pretty,
    );
    return Ok(());
  }
  if default {
    spec.read_header_timeout = None;
    spec.idle_timeout = None;
    spec.grace_period = None;
  } else {
    spec.read_header_timeout =
      read_header.or(spec.read_header_timeout);
    spec.idle_timeout = idle.or(spec.idle_timeout);
    spec.grace_period = grace_period.or(spec.grace_period);
  }
  changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
    .await
}
