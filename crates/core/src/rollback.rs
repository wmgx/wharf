//! 回滚：找出要回到的那次部署，给出当时的服务配置。
//!
//! 回滚不是另一套流程：客户端拿到配置后照常提交 `UpsertService`，
//! 走同一个 plan / apply。image 来源固定到当时的镜像 digest，
//! 这样 `latest` 这类会变的标签也能回到当时的版本。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, Query, State},
};
use rusqlite::params;
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  agent::ImageInfo,
  spec::{ServiceSpec, Source},
  view::{RollbackTarget, TokenScope},
};

use crate::{
  api::{ApiResult, service_not_found},
  auth::Auth,
  db::{json_err, sql_err, to_time},
  snapshot,
  state::AppState,
};

#[derive(Deserialize)]
pub struct RollbackQuery {
  /// 部署记录 id。不给时回到上一个不同的版本。
  to: Option<i64>,
}

/// (id, hash, spec, images, created_at)
type Row = (i64, String, Option<String>, String, i64);

pub async fn target(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RollbackQuery>,
) -> ApiResult<RollbackTarget> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let current = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  let service = name.clone();
  let rows: Vec<Row> = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT id, hash, spec, images, created_at FROM deployments
           WHERE service = ?1 ORDER BY id DESC LIMIT 200",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![service], |r| {
          Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await?;
  let row = pick(&rows, q.to).ok_or_else(|| match q.to {
    Some(id) => ApiError::not_found(format!(
      "服务 {name} 没有 id 为 {id} 的部署记录"
    ))
    .suggest(format!("wharf service deployments {name}")),
    None => {
      ApiError::invalid(format!("服务 {name} 没有可以回滚的旧版本"))
    }
  })?;
  let (id, _, spec, images, created) = row;
  let spec: ServiceSpec = match spec {
    Some(spec) => serde_json::from_str(spec).map_err(json_err)?,
    None => {
      return Err(
        ApiError::invalid(format!(
          "部署 {id} 太早，没有记录当时的配置，不能回滚"
        ))
        .into(),
      );
    }
  };
  let images: Vec<ImageInfo> =
    serde_json::from_str(images).map_err(json_err)?;
  // 服务器和备份设置以现在为准：换服务器是迁移，不是回滚。
  let spec = ServiceSpec {
    server: current.spec.server.clone(),
    backup: current.spec.backup.clone(),
    ..pin_image(spec, &images)
  };
  Ok(Json(RollbackTarget {
    service: name,
    deployment_id: *id,
    deployed_at: to_time(*created),
    spec,
  }))
}

/// 指定了 id 就用它；否则跳过和最新一次相同的版本，取再往前的第一个。
fn pick(rows: &[Row], to: Option<i64>) -> Option<&Row> {
  match to {
    Some(id) => rows.iter().find(|r| r.0 == id),
    None => {
      let latest = &rows.first()?.1;
      rows.iter().find(|r| &r.1 != latest)
    }
  }
}

fn pin_image(spec: ServiceSpec, images: &[ImageInfo]) -> ServiceSpec {
  let Source::Image(image) = &spec.source else {
    return spec;
  };
  let digest = images
    .iter()
    .find(|i| &i.image == image)
    .and_then(|i| i.digest.clone());
  match digest {
    Some(digest) => ServiceSpec {
      source: Source::Image(digest),
      ..spec
    },
    None => spec,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn row(id: i64, hash: &str) -> Row {
    (id, hash.into(), None, "[]".into(), 0)
  }

  #[test]
  fn pick_skips_versions_equal_to_latest() {
    let rows =
      vec![row(5, "b"), row(4, "b"), row(3, "a"), row(2, "c")];
    assert_eq!(pick(&rows, None).map(|r| r.0), Some(3));
    assert_eq!(pick(&rows, Some(2)).map(|r| r.0), Some(2));
    assert!(pick(&[row(1, "a")], None).is_none());
  }
}
