//! `wharf audit`：操作和登录记录。

use wharf_api_types::view::AuditEntry;

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

pub async fn audit(
  c: &Client,
  actor: Option<String>,
  kind: Option<String>,
  limit: u32,
  j: bool,
) -> CliResult<()> {
  let mut path = format!("/api/audit?limit={limit}");
  if let Some(actor) = actor {
    path.push_str(&format!("&actor={}", seg(&actor)));
  }
  if let Some(kind) = kind {
    path.push_str(&format!("&kind={}", seg(&kind)));
  }
  let rows: Vec<AuditEntry> = c.get(&path).await?;
  out(j, &rows, |rows| {
    for row in rows {
      let at = chrono::DateTime::from_timestamp_millis(row.at)
        .map(|t| {
          t.with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
            .to_string()
        })
        .unwrap_or_default();
      println!(
        "{at}  {}  {} {}  {}  {}",
        row.actor,
        row.method,
        row.path,
        row.status.map(|s| s.to_string()).unwrap_or_default(),
        row.detail.as_deref().unwrap_or_default(),
      );
    }
  });
  Ok(())
}
