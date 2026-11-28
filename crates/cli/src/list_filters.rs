use clap::Args;

use crate::client::seg;

fn path(base: &str, fields: &[(&str, Option<&str>)]) -> String {
  let mut out = base.to_owned();
  let mut sep = '?';
  for (key, value) in fields {
    if let Some(value) = value {
      out.push(sep);
      out.push_str(key);
      out.push('=');
      out.push_str(&seg(value));
      sep = '&';
    }
  }
  out
}

#[derive(Args)]
pub struct ServiceFilters {
  #[arg(long)]
  server: Option<String>,
  #[arg(long, value_parser = ["running", "stopped", "restarting", "partial", "missing", "offline", "unknown", "unhealthy", "abnormal"])]
  status: Option<String>,
  #[arg(long)]
  no_backup: bool,
  #[arg(long)]
  has_update: bool,
  /// 省略 Compose、Dockerfile 和配置文件正文。
  #[arg(long)]
  brief: bool,
}

impl ServiceFilters {
  pub fn path(&self) -> String {
    path(
      "/api/services",
      &[
        ("server", self.server.as_deref()),
        ("status", self.status.as_deref()),
        ("no_backup", self.no_backup.then_some("true")),
        ("has_update", self.has_update.then_some("true")),
        ("brief", self.brief.then_some("1")),
      ],
    )
  }
}

#[derive(Args)]
pub struct RouteFilters {
  #[arg(long)]
  gateway: Option<String>,
  #[arg(long)]
  service: Option<String>,
  #[arg(long, conflicts_with = "internal")]
  public: bool,
  #[arg(long, conflicts_with = "unprotected")]
  internal: bool,
  #[arg(long)]
  unprotected: bool,
}

impl RouteFilters {
  pub fn path(&self) -> String {
    path(
      "/api/routes",
      &[
        ("gateway", self.gateway.as_deref()),
        ("service", self.service.as_deref()),
        ("public", self.public.then_some("true")),
        ("internal", self.internal.then_some("true")),
        ("unprotected", self.unprotected.then_some("true")),
      ],
    )
  }
}

#[derive(Args)]
pub struct ServerFilters {
  #[arg(long, conflicts_with = "offline")]
  online: bool,
  #[arg(long)]
  offline: bool,
  #[arg(long)]
  outdated: bool,
}

impl ServerFilters {
  pub fn path(&self) -> String {
    path(
      "/api/servers",
      &[
        ("online", self.online.then_some("true")),
        ("offline", self.offline.then_some("true")),
        ("outdated", self.outdated.then_some("true")),
      ],
    )
  }
}

#[derive(Args)]
pub struct GatewayFilters {
  #[arg(long)]
  server: Option<String>,
  #[arg(long, value_parser = ["caddy", "cloudflare_tunnel"])]
  kind: Option<String>,
}

impl GatewayFilters {
  pub fn path(&self) -> String {
    path(
      "/api/gateways",
      &[
        ("server", self.server.as_deref()),
        ("kind", self.kind.as_deref()),
      ],
    )
  }
}
