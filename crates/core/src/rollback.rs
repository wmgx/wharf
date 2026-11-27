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
  view::{Perm, RollbackTarget},
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

/// (id, hash, spec, images, created_at, commit_sha)
type Row = (i64, String, Option<String>, String, i64, Option<String>);

pub async fn target(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RollbackQuery>,
) -> ApiResult<RollbackTarget> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let current = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  let service = name.clone();
  let instance_id = current.instance_id.clone();
  let requested = q.to;
  let (rows, unstarted): (Vec<Row>, Option<Row>) = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT id, hash, spec, images, created_at, commit_sha FROM deployments
           WHERE service = ?1 AND instance_id = ?2 AND started = 1 AND (?3 IS NULL OR id = ?3)
           ORDER BY id DESC LIMIT 200",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![service, instance_id, requested], |r| {
          Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
          ))
        })
        .map_err(sql_err)?;
      let rows = rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)?;
      if let Some(id) = requested
        && rows.is_empty()
        && c.query_row("SELECT EXISTS(SELECT 1 FROM deployments WHERE service = ?1 AND instance_id = ?2 AND id = ?3 AND started = 0)",
          params![service, instance_id, id], |r| r.get::<_, bool>(0)).map_err(sql_err)?
      {
        return Err(ApiError::invalid(format!("部署 #{id} 是在停机状态下创建的，从未启动运行过，不能作为回滚目标"))
          .with_hint(format!("运行 wharf service deployments {service} 查看已启动过的版本")));
      }
      if let Some(id) = requested
        && rows.is_empty()
        && c.query_row("SELECT EXISTS(SELECT 1 FROM deployments WHERE service = ?1 AND id = ?2)",
          params![service, id], |r| r.get::<_, bool>(0)).map_err(sql_err)?
      {
        let list = format!("wharf service deployments {service}");
        return Err(ApiError::invalid(format!("部署 #{id} 属于已删除的旧服务实例，不能回滚到它"))
          .with_hint(format!("运行 {list} 查看当前服务的可回滚版本")).suggest(list));
      }
      let unstarted = if requested.is_none() {
        c.query_row(
          "SELECT id, hash, spec, images, created_at, commit_sha FROM deployments
           WHERE service = ?1 AND instance_id = ?2 AND started = 0
             AND id = (SELECT MAX(id) FROM deployments WHERE service = ?1 AND instance_id = ?2)",
          params![service, instance_id],
          |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).optional().map_err(sql_err)?
      } else {
        None
      };
      Ok((rows, unstarted))
    })
    .await?;
  let row =
    pick(&rows, q.to, unstarted.as_ref()).ok_or_else(|| {
      match q.to {
        Some(id) => ApiError::not_found(format!(
          "服务 {name} 没有 id 为 {id} 的部署记录"
        ))
        .suggest(format!("wharf service deployments {name}")),
        None => ApiError::invalid(format!(
          "服务 {name} 没有可以回滚的旧版本"
        )),
      }
    })?;
  let (id, _, spec, images, created, commit) = row;
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
  // 服务器、备份、停止与否、资源上限以现在为准：换服务器是迁移，不是回滚。
  let spec = ServiceSpec {
    server: current.spec.server.clone(),
    backup: current.spec.backup.clone(),
    stopped: current.spec.stopped,
    limits: current.spec.limits.clone(),
    auto_update: false,
    ..pin_commit(pin_image(spec, &images), commit.as_deref())
  };
  Ok(Json(RollbackTarget {
    service: name,
    deployment_id: *id,
    deployed_at: to_time(*created),
    spec: crate::service_monitor::heartbeat::redact(&spec),
  }))
}

/// 指定了 id 就用它；否则跳过和最新一次相同的版本，取再往前的第一个。
fn pick<'a>(
  rows: &'a [Row],
  to: Option<i64>,
  unstarted: Option<&Row>,
) -> Option<&'a Row> {
  match to {
    Some(id) => rows.iter().find(|r| r.0 == id),
    None => {
      let latest = version(unstarted.or_else(|| rows.first())?);
      rows.iter().find(|r| version(r) != latest)
    }
  }
}

/// 一次部署的版本：配置、commit、实际用的镜像。同一个标签换了镜像也算不同版本。
fn version(r: &Row) -> (&str, Option<&str>, Vec<String>) {
  let mut images: Vec<String> =
    serde_json::from_str::<Vec<ImageInfo>>(&r.3)
      .unwrap_or_default()
      .into_iter()
      .map(|i| i.digest.unwrap_or(i.id))
      .collect();
  images.sort();
  (&r.1, r.5.as_deref(), images)
}

/// git 来源固定到那次部署实际构建的 commit。
fn pin_commit(
  spec: ServiceSpec,
  commit: Option<&str>,
) -> ServiceSpec {
  match (&spec.source, commit) {
    (Source::Build(b), Some(commit)) if b.git.is_some() => {
      let mut b = b.clone();
      if let Some(git) = &mut b.git {
        git.reference = commit.to_string();
      }
      ServiceSpec {
        source: Source::Build(b),
        ..spec
      }
    }
    _ => spec,
  }
}

fn pin_image(spec: ServiceSpec, images: &[ImageInfo]) -> ServiceSpec {
  let Source::Image(image) = &spec.source else {
    return spec;
  };
  let digest =
    images.iter().find(|i| &i.image == image).and_then(|i| {
      wharf_api_types::agent::normalize_image_digest(
        image,
        i.digest.as_deref()?,
      )
    });
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

  #[tokio::test]
  async fn rollback_ignores_deleted_instance_deployments() {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| c.execute_batch(
      "INSERT INTO resources (kind, name, spec, meta, version, created_at, updated_at)
       VALUES ('service', 'reader', '{\"server\":\"s1\",\"source\":{\"image\":\"fixture:1\"}}',
         '{\"instance_id\":\"svc_new\"}', 1, 2, 2);
       INSERT INTO deployments (id, service, server, run_id, hash, compose, images, created_at, instance_id)
       VALUES (1, 'reader', 's1', 'r1', 'h1', '', '[]', 1, 'svc_old'), (2, 'reader', 's1', 'r2', 'h2', '', '[]', 3, 'svc_new');"
    ).map_err(sql_err)).await.unwrap();
    let auth = || Auth {
      name: "fixture".into(),
      perms: [Perm::Read].into(),
      expires_at: None,
      allowed_from: vec![],
      services: None,
      human: true,
    };
    for (to, message) in [
      (None, "没有可以回滚的旧版本"),
      (Some(1), "属于已删除的旧服务实例"),
    ] {
      let err = target(
        State(state.clone()),
        auth(),
        Path("reader".into()),
        Query(RollbackQuery { to }),
      )
      .await
      .err()
      .unwrap()
      .0;
      assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
      assert!(err.message.contains(message));
    }
    let Json(history) = crate::api::deployments(
      State(state),
      auth(),
      Path("reader".into()),
    )
    .await
    .ok()
    .unwrap();
    assert_eq!(history.iter().map(|d| d.id).collect::<Vec<_>>(), [2]);
  }

  fn row(id: i64, hash: &str) -> Row {
    (id, hash.into(), None, "[]".into(), 0, None)
  }

  #[test]
  fn rollback_skips_unstarted_deployments() {
    let rows = [row(1, "v1")];
    let unstarted = row(2, "v2");
    assert_eq!(
      pick(&rows, None, Some(&unstarted)).map(|r| r.0),
      Some(1)
    );
    assert!(pick(&rows, Some(2), None).is_none());
  }

  #[test]
  fn pick_skips_versions_equal_to_latest() {
    let rows =
      vec![row(5, "b"), row(4, "b"), row(3, "a"), row(2, "c")];
    assert_eq!(pick(&rows, None, None).map(|r| r.0), Some(3));
    assert_eq!(pick(&rows, Some(2), None).map(|r| r.0), Some(2));
    assert!(pick(&[row(1, "a")], None, None).is_none());
  }

  #[test]
  fn pick_treats_new_digest_as_new_version() {
    let with = |id, digest: &str| {
      let mut r = row(id, "a");
      r.3 =
        format!(r#"[{{"image":"app:latest","digest":"{digest}"}}]"#);
      r
    };
    let rows = vec![with(3, "app@sha256:b"), with(2, "app@sha256:a")];
    assert_eq!(pick(&rows, None, None).map(|r| r.0), Some(2));
  }
}

#[test]
fn rollback_pins_old_mirror_digest_without_path() {
  let hash = "a".repeat(64);
  let spec: ServiceSpec = serde_json::from_value(serde_json::json!({
    "server":"s1", "source":{"image":"nginx:1.27"}
  }))
  .unwrap();
  let mut images: Vec<ImageInfo> = serde_json::from_value(serde_json::json!([{
    "image":"nginx:1.27", "digest":format!("docker.example.test/tok_secret_123456/library/nginx@sha256:{hash}")
  }])).unwrap();
  let expected = format!("nginx@sha256:{hash}");
  assert_eq!(
    pin_image(spec, &images).source,
    Source::Image(expected.clone())
  );
  wharf_api_types::agent::normalize_image_digests(&mut images);
  assert_eq!(images[0].digest.as_deref(), Some(expected.as_str()));
}
