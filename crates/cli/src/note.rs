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
  #[arg(conflicts_with = "clear")]
  note: Option<String>,
  /// 清除备注。
  #[arg(long, visible_alias = "off")]
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
  let normalized;
  let name = if kind == "route" {
    normalized = wharf_api_types::normalize_host(name);
    &normalized
  } else {
    name
  };
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
  let (note, _) = wharf_api_types::split_note(
    args.note.as_deref().unwrap_or_default(),
  );
  let read_only = args.note.is_none() && !args.clear;
  if read_only && args.dry_run {
    return Err(
      ApiError::invalid("--dry-run 需要提供备注内容或 --clear")
        .into(),
    );
  }
  if read_only || args.dry_run {
    let (mut before, mut has_sealed) = if kind == "route" {
      let routes: Vec<RouteView> = c.get(&target).await?;
      let route = routes
        .into_iter()
        .find(|r| r.spec.hostname == name)
        .ok_or_else(|| {
          ApiError::not_found(format!("域名 {name} 不存在"))
            .with_hint("用 wharf route list 查看现有域名")
        })?;
      (route.note, route.has_sealed_note)
    } else {
      let value: Value = c.get(&target).await?;
      (
        value["note"].as_str().map(str::to_string),
        value["has_sealed_note"].as_bool().unwrap_or(false),
      )
    };
    wharf_api_types::filter_note(&mut before, &mut has_sealed, false);
    if read_only {
      out(
        j,
        &json!({"target": format!("{kind}/{name}"), "note": before, "has_sealed_note": has_sealed}),
        |_| {
          println!("{}", before.as_deref().unwrap_or("没有备注"));
          if has_sealed {
            println!("（含页面加密私密内容）");
          }
        },
      );
      return Ok(());
    }
    let after = (!note.is_empty()).then_some(note);
    return crate::preview::show(
      j,
      &format!("{kind}/{name}"),
      &json!({"note": before}),
      &json!({"note": after, "sealed_preserved": has_sealed}),
    );
  }
  let value: Value = c.put(&path, &json!({"note": note})).await?;
  out(j, &value, |_| println!("已保存 {name} 的备注"));
  Ok(())
}
