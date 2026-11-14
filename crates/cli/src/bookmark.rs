//! 首页书签：复用计划和执行，不触发机器动作。

use clap::Subcommand;
use wharf_api_types::{
  ApiError,
  spec::{BookmarkSpec, Change},
  view::Status,
};

use crate::{
  ApplyFlags,
  client::{CliResult, Client},
  commands::{changes, pretty},
};

#[derive(Subcommand)]
pub enum BookmarkCmd {
  List,
  Add {
    title: String,
    url: String,
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    order: Option<i32>,
    #[arg(long)]
    id: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  Remove {
    id: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

pub async fn bookmark(
  c: &Client,
  cmd: BookmarkCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    BookmarkCmd::List => {
      let status: Status = c.get("/api/status").await?;
      pretty(&status.bookmarks);
      Ok(())
    }
    BookmarkCmd::Add {
      title,
      url,
      group,
      order,
      id,
      apply,
    } => {
      let old = if let Some(id) = &id {
        let status: Status = c.get("/api/status").await?;
        Some(
          status
            .bookmarks
            .into_iter()
            .find(|b| &b.id == id)
            .ok_or_else(|| {
              ApiError::not_found(format!("书签 {id} 不存在"))
                .suggest("wharf bookmark list")
            })?
            .spec,
        )
      } else {
        None
      };
      let spec = BookmarkSpec {
        title,
        url,
        group: group
          .or_else(|| old.as_ref().and_then(|s| s.group.clone())),
        order: order
          .unwrap_or_else(|| old.as_ref().map_or(0, |s| s.order)),
      };
      changes(c, vec![Change::UpsertBookmark { id, spec }], apply, j)
        .await
    }
    BookmarkCmd::Remove { id, apply } => {
      changes(c, vec![Change::RemoveBookmark { id }], apply, j).await
    }
  }
}
