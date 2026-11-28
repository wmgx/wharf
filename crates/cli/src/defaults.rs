use serde_json::{Value, json};
use wharf_api_types::{
  spec::{Change, ServiceDefaults},
  view::{ConfigItemView, ServerView},
};

use crate::{
  ApplyFlags,
  client::{CliResult, Client, seg},
  commands::{changes, out},
  runtime_options::{cpu_milli, parse_log_max},
};

const PATH: &str = "/api/config/defaults.global";

#[derive(clap::Args)]
pub struct Args {
  /// 服务器名。省略时查看或修改全局模板。
  #[arg(long)]
  server: Option<String>,
  #[arg(long, allow_hyphen_values = true)]
  timezone: Option<String>,
  #[arg(long, conflicts_with = "timezone")]
  unset_timezone: bool,
  #[arg(long)]
  log_max: Option<String>,
  #[arg(long, conflicts_with = "log_max")]
  unset_log_max: bool,
  #[arg(long)]
  memory: Option<u32>,
  #[arg(long, conflicts_with = "memory")]
  unset_memory: bool,
  #[arg(long)]
  cpus: Option<f64>,
  #[arg(long, conflicts_with = "cpus")]
  unset_cpus: bool,
  #[arg(long)]
  pids: Option<u32>,
  #[arg(long, conflicts_with = "pids")]
  unset_pids: bool,
  #[command(flatten)]
  apply: ApplyFlags,
}

pub(crate) async fn run(
  c: &Client,
  args: Args,
  j: bool,
) -> CliResult<()> {
  let mut patch = json!({});
  let mut limits = json!({});
  for (field, value, unset) in [
    ("memory_mb", args.memory, args.unset_memory),
    (
      "cpu_milli",
      args.cpus.map(cpu_milli).transpose()?,
      args.unset_cpus,
    ),
    ("pids", args.pids, args.unset_pids),
  ] {
    if value.is_some() || unset {
      limits[field] = json!(value);
    }
  }
  if limits != json!({}) {
    patch["limits"] = limits;
  }
  if args.timezone.is_some() || args.unset_timezone {
    patch["timezone"] = json!(args.timezone);
  }
  if args.log_max.is_some() || args.unset_log_max {
    patch["log_max"] =
      json!(args.log_max.as_deref().map(parse_log_max).transpose()?);
  }
  if let Some(name) = args.server {
    let mut settings = c
      .get::<ServerView>(&format!("/api/servers/{}", seg(&name)))
      .await?
      .settings;
    if patch != json!({}) {
      let mut local = settings.defaults.take().unwrap_or_default();
      local.patch(patch)?;
      settings.defaults = (!local.is_empty()).then_some(local);
      return changes(
        c,
        vec![Change::UpdateServer { name, settings }],
        args.apply,
        j,
      )
      .await;
    }
    args.apply.check_read_only()?;
    let global: ConfigItemView = c.get(PATH).await?;
    let inherited: ServiceDefaults =
      serde_json::from_value(global.value)
        .map_err(anyhow::Error::from)?;
    let customized = settings.defaults.is_some();
    let local = settings.defaults.unwrap_or_default();
    let mut effective = local.clone().with_fallback(&inherited);
    if matches!(effective.timezone.as_deref(), None | Some("default"))
    {
      let timezone: ConfigItemView =
        c.get("/api/config/core.timezone").await?;
      effective.timezone = serde_json::from_value(timezone.value)
        .map_err(anyhow::Error::from)?;
    }
    let item = ConfigItemView {
      key: format!("defaults.server.{name}"),
      value: json!(local),
      default_value: json!(inherited),
      customized,
      value_type: "service_defaults".into(),
      readonly: false,
      description: "新建服务的服务器默认值".into(),
    };
    let mut view = json!(item);
    view["effective"] = json!(effective);
    out(j, &view, |value: &Value| {
      println!("{} = {}", item.key, value["value"]);
      println!("有效值 = {}", value["effective"]);
    });
  } else {
    args.apply.check_read_only()?;
    let item: ConfigItemView = if patch == json!({}) {
      c.get(PATH).await?
    } else {
      c.put(PATH, &patch).await?
    };
    out(j, &item, |item| println!("{} = {}", item.key, item.value));
  }
  Ok(())
}
