use wharf_api_types::view::{
  RefReport, SearchResponse, TreeServiceNode, TreeView,
};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

#[derive(clap::Args)]
pub struct TreeArgs {
  target: Option<String>,
  #[arg(long)]
  server: Option<String>,
  #[arg(long)]
  service: Option<String>,
  #[arg(long)]
  route: Option<String>,
}

#[derive(clap::Args)]
pub struct SearchArgs {
  query: String,
  #[arg(long)]
  kind: Option<String>,
  #[arg(long, default_value_t = 50)]
  limit: usize,
}

pub async fn refs(
  c: &Client,
  target: &str,
  j: bool,
) -> CliResult<()> {
  let report: RefReport =
    c.get(&format!("/api/refs?target={}", seg(target))).await?;
  out(j, &report, |r| {
    println!("{}/{}：{} 处引用", r.kind, r.name, r.count);
    if r.kind == "secret" && r.exists && r.complete && r.count == 0 {
      println!("无引用：wharf secret rm {}", r.name);
    }
    let mut previous = None;
    for hit in &r.refs {
      let resource = (&hit.kind, &hit.name);
      if previous != Some(resource) {
        println!("  {}/{}", hit.kind, hit.name);
        previous = Some(resource);
      }
      println!("    {}  {}", hit.field, hit.relation);
    }
  });
  Ok(())
}

pub async fn tree(
  c: &Client,
  args: TreeArgs,
  j: bool,
) -> CliResult<()> {
  let mut query = Vec::new();
  for (key, value) in [
    ("target", args.target),
    ("server", args.server),
    ("service", args.service),
    ("route", args.route),
  ] {
    if let Some(value) = value {
      query.push(format!("{key}={}", seg(&value)));
    }
  }
  let result: TreeView =
    c.get(&format!("/api/tree?{}", query.join("&"))).await?;
  out(j, &result, |tree| {
    for r in &tree.routes {
      println!(
        "{} [{}{}{}]",
        r.hostname,
        if r.https { "HTTPS" } else { "HTTP" },
        if r.gate { " · gate" } else { "" },
        if r.basic_auth { " · Basic Auth" } else { "" }
      );
      if let Some(g) = &r.gateway {
        println!("├── 网关：{g}");
      }
      if let Some(g) = &r.backup_gateway {
        println!(
          "├── 备用：{g}{}",
          if r.backup_active {
            "（已启用）"
          } else {
            ""
          }
        );
      }
      if let Some(link) = &r.link {
        println!("├── 链路：{link}");
      }
      for s in r.service.iter().chain(&r.path_services) {
        service(s);
      }
    }
    if !tree.orphan_services.is_empty() && tree.servers.is_empty() {
      println!("[无域名服务]");
      tree.orphan_services.iter().for_each(service);
    }
    for server in &tree.servers {
      println!("{}", server.name);
      server.services.iter().for_each(service);
    }
  });
  Ok(())
}

fn service(s: &TreeServiceNode) {
  let server = s
    .server
    .as_deref()
    .map_or_else(String::new, |s| format!(" ({s})"));
  let ports = s
    .ports
    .iter()
    .map(|(p, v)| format!("{p}({v})"))
    .collect::<Vec<_>>()
    .join(" ");
  println!(
    "└── 服务：{}{server} {ports}{}",
    s.name,
    if s.stopped { " [已停用]" } else { "" }
  );
  if !s.dependencies.is_empty() {
    println!("    依赖：{}", s.dependencies.join("、"));
  }
  if let Some(backup) = &s.backup_to {
    println!("    备份：→ {backup}");
  }
}

pub async fn search(
  c: &Client,
  args: SearchArgs,
  j: bool,
) -> CliResult<()> {
  let mut path = format!(
    "/api/search?q={}&limit={}",
    seg(&args.query),
    args.limit
  );
  if let Some(kind) = args.kind {
    path.push_str(&format!("&kind={}", seg(&kind)));
  }
  let result: SearchResponse = c.get(&path).await?;
  out(j, &result, |r| {
    for hit in &r.hits {
      println!(
        "{}/{}  {}  {}",
        hit.kind, hit.name, hit.field, hit.match_text
      );
    }
    println!("共 {} 处匹配", r.total);
  });
  Ok(())
}
