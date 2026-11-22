//! 服务、服务器和域名的备注命令。

use clap::Args;
use serde_json::{Value, json};
use wharf_api_types::{ApiError, view::RouteView};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

#[derive(Args)]
pub struct NoteArgs {
  /// 备注文本，传空字符串清除。
  #[arg(required_unless_present = "clear", conflicts_with = "clear")]
  note: Option<String>,
  /// 清除备注。
  #[arg(long)]
  clear: bool,
  /// 只预览会改什么，不执行。
  #[arg(long)]
  dry_run: bool,
}

pub async fn run(
  c: &Client,
  kind: &str,
  name: &str,
  args: NoteArgs,
  j: bool,
) -> CliResult<()> {
  let name_segment = seg(name);
  let (target, path) = match kind {
    "service" => (
      format!("/api/services/{name_segment}"),
      format!("/api/services/{name_segment}/note"),
    ),
    "server" => (
      format!("/api/servers/{name_segment}"),
      format!("/api/servers/{name_segment}/note"),
    ),
    _ => (
      "/api/routes".into(),
      format!("/api/routes/{name_segment}/note"),
    ),
  };
  let note = args.note.as_deref().unwrap_or_default().trim();
  if args.dry_run {
    let before = if kind == "route" {
      let routes: Vec<RouteView> = c.get(&target).await?;
      let route = routes
        .into_iter()
        .find(|r| r.spec.hostname == name)
        .ok_or_else(|| {
          ApiError::not_found(format!("域名 {name} 不存在"))
            .with_hint("用 wharf route list 查看现有域名")
        })?;
      json!(route.note)
    } else {
      let value: Value = c.get(&target).await?;
      value["note"].clone()
    };
    let after = Some(note).filter(|n| !n.is_empty());
    return crate::preview::show(
      j,
      &format!("{kind}/{name}"),
      &json!({"note": before}),
      &json!({"note": after}),
    );
  }
  let value: Value = c.put(&path, &json!({"note": note})).await?;
  out(j, &value, |_| println!("已保存 {name} 的备注"));
  Ok(())
}
