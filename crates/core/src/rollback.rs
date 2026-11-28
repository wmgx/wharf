//! 回滚：找出要回到的那次部署，给出当时的服务配置。
//!
//! 回滚复用 `UpsertService`，镜像 digest 和 Git commit 单独传递。

use std::{collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::{Path, Query, State},
};
use rusqlite::{Connection, OptionalExtension, params};
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
  #[serde(default, deserialize_with = "allow_unpinned")]
  allow_unpinned: bool,
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
  let selected = s
    .db
    .call(move |c| select(c, &service, &instance_id, q.to))
    .await?;
  let (id, _, spec, images, created, commit) = selected;
  let spec: ServiceSpec = match spec {
    Some(spec) => serde_json::from_str(&spec).map_err(json_err)?,
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
    serde_json::from_str(&images).map_err(json_err)?;
  require_upload(&s, &name, id, &spec.source)?;
  let mut warnings = Vec::new();
  let spec = merge_settings(spec, &current.spec, &mut warnings);
  let (pins, commit) = extract_pins_and_commit(
    &name,
    id,
    &spec.source,
    &images,
    commit,
    q.allow_unpinned,
    &mut warnings,
  )?;
  Ok(Json(RollbackTarget {
    service: name,
    deployment_id: id,
    deployed_at: to_time(created),
    spec: crate::service_monitor::heartbeat::redact(&spec),
    pins,
    commit,
    warnings,
  }))
}

fn require_upload(
  state: &AppState,
  name: &str,
  id: i64,
  source: &Source,
) -> Result<(), ApiError> {
  if let Source::Build(build) = source
    && let Some(sha) = &build.upload
  {
    crate::uploads::check_sha(sha)?;
    if !crate::uploads::exists(state, sha) {
      return Err(ApiError::invalid(format!("部署 #{id} 的代码包 {} 已不在控制面上（可能已过期清理），无法回滚到这个版本", &sha[..12]))
        .with_hint("选择其他未过期的部署记录，或重新执行 wharf deploy 上传代码")
        .suggest(format!("wharf service history {name}")));
    }
  }
  Ok(())
}

fn allow_unpinned<'de, D: serde::Deserializer<'de>>(
  d: D,
) -> Result<bool, D::Error> {
  match String::deserialize(d)?.as_str() {
    "1" | "true" => Ok(true),
    "0" | "false" => Ok(false),
    _ => Err(serde::de::Error::custom(
      "allow_unpinned 要用 1/0 或 true/false",
    )),
  }
}

fn deployment(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
  Ok((
    row.get(0)?,
    row.get(1)?,
    row.get(2)?,
    row.get(3)?,
    row.get(4)?,
    row.get(5)?,
  ))
}

fn select(
  c: &Connection,
  name: &str,
  instance: &str,
  to: Option<i64>,
) -> Result<Row, ApiError> {
  let history = format!("wharf service history {name}");
  if let Some(id) = to {
    let (row, started, owner) = c.query_row(
      "SELECT id, hash, spec, images, created_at, commit_sha, started, instance_id FROM deployments
       WHERE id = ?1 AND service = ?2",
      params![id, name], |r| Ok((deployment(r)?, r.get::<_, bool>(6)?, r.get::<_, Option<String>>(7)?)),
    ).optional().map_err(sql_err)?.ok_or_else(|| ApiError::not_found(format!(
      "服务 {name} 没有 id 为 {id} 的部署记录")).suggest(&history))?;
    if owner.as_deref() != Some(instance) {
      return Err(
        ApiError::invalid(format!(
          "部署 #{id} 属于已删除的旧服务实例，不能回滚到它"
        ))
        .with_hint(format!("运行 {history} 查看当前服务的可回滚版本"))
        .suggest(history),
      );
    }
    if !started {
      return Err(
        ApiError::invalid(format!(
          "部署 #{id} 从未启动运行，不能作为回滚目标"
        ))
        .with_hint(format!("运行 {history} 查看已启动过的版本"))
        .suggest(history),
      );
    }
    return Ok(row);
  }
  let mut stmt = c.prepare(
    "SELECT id, hash, spec, images, created_at, commit_sha FROM deployments
     WHERE service = ?1 AND instance_id = ?2 AND started = 1 ORDER BY id DESC LIMIT 200",
  ).map_err(sql_err)?;
  let mut rows = stmt
    .query_map(params![name, instance], deployment)
    .map_err(sql_err)?;
  if let Some(first) = rows.next() {
    let latest = first.map_err(sql_err)?;
    let current = version(&latest);
    for row in rows {
      let row = row.map_err(sql_err)?;
      if version(&row) != current {
        return Ok(row);
      }
    }
  }
  Err(
    ApiError::invalid(format!("服务 {name} 没有可以回滚的旧版本"))
      .suggest(history),
  )
}

fn merge_settings(
  mut spec: ServiceSpec,
  current: &ServiceSpec,
  warnings: &mut Vec<String>,
) -> ServiceSpec {
  spec.server.clone_from(&current.server);
  spec.backup.clone_from(&current.backup);
  spec.stopped = current.stopped;
  spec.start_timeout_secs = current.start_timeout_secs;
  spec.stop_grace_secs = current.stop_grace_secs;
  spec.stop_signal.clone_from(&current.stop_signal);
  spec.init_cmd.clone_from(&current.init_cmd);
  spec.init_timeout_secs = current.init_timeout_secs;
  spec.limits.clone_from(&current.limits);
  spec.log_alerts.clone_from(&current.log_alerts);
  spec.update_ignore.clone_from(&current.update_ignore);
  if matches!(spec.source, Source::Build(_)) {
    spec.update_ignore.retain(|r| {
      r.image == "*"
        && r.scope == wharf_api_types::spec::UpdateIgnoreScope::All
    });
  }
  spec.heartbeat.clone_from(&current.heartbeat);
  if current.auto_update {
    warnings.push(
      "已临时关闭自动更新，避免再次升回故障版本；修好后可重新开启"
        .into(),
    );
  }
  spec.auto_update = false;
  if spec.ports.is_empty()
    && let Source::Compose {
      content: Some(content),
      ..
    } = &spec.source
  {
    spec.ports = crate::import::compose_ports(content);
  }
  spec.monitor = current.monitor.clone().filter(|m| {
    let valid = !spec.ports.is_empty()
      && m.port.as_ref().is_none_or(|name| {
        spec.ports.iter().any(|p| &p.name == name)
      });
    if !valid {
      warnings.push(
        "已跳过当前监控配置：目标版本的端口列表不含原监控端口".into(),
      );
    }
    valid
  });
  let mut skipped = Vec::new();
  spec.port_checks = current
    .port_checks
    .iter()
    .filter_map(|(name, check)| {
      if spec
        .ports
        .iter()
        .any(|p| &p.name == name && check.validate(p.udp).is_ok())
      {
        Some((name.clone(), check.clone()))
      } else {
        skipped.push(name.as_str());
        None
      }
    })
    .collect();
  if !skipped.is_empty() {
    warnings.push(format!(
      "已跳过目标版本不兼容的端口检查：{}",
      skipped.join("、")
    ));
  }
  spec
}

/// 一次部署的版本：配置、commit、实际用的镜像。同一个标签换了镜像也算不同版本。
fn version(r: &Row) -> (&str, Option<&str>, Vec<String>) {
  let mut recorded: Vec<ImageInfo> =
    serde_json::from_str(&r.3).unwrap_or_default();
  wharf_api_types::agent::normalize_image_digests(&mut recorded);
  let mut images: Vec<_> = recorded
    .into_iter()
    .map(|i| i.digest.unwrap_or(i.id))
    .collect();
  images.sort();
  (&r.1, r.5.as_deref().filter(|c| !c.is_empty()), images)
}

pub(crate) fn valid_commit(sha: &str) -> bool {
  (7..=40).contains(&sha.len())
    && sha.bytes().all(|c| c.is_ascii_hexdigit())
}

type VersionPins = (Option<BTreeMap<String, String>>, Option<String>);

fn extract_pins_and_commit(
  name: &str,
  id: i64,
  source: &Source,
  images: &[ImageInfo],
  commit: Option<String>,
  allow: bool,
  warnings: &mut Vec<String>,
) -> Result<VersionPins, ApiError> {
  let suggest = || {
    format!(
      "wharf service rollback {name} --to {id} --allow-unpinned"
    )
  };
  if matches!(source, Source::Build(b) if b.git.is_some()) {
    let commit = commit
      .filter(|sha| valid_commit(sha))
      .map(|sha| sha.to_ascii_lowercase());
    if commit.is_none() {
      let message = format!("部署 #{id} 没有记录有效的 Git commit");
      if !allow {
        return Err(
          ApiError::invalid(format!("{message}，无法精确回滚"))
            .with_hint("如需按分支拉取最新代码，加 --allow-unpinned")
            .suggest(suggest()),
        );
      }
      warnings.push(format!("{message}，将按分支拉取最新代码"));
    }
    return Ok((None, commit));
  }
  let want = crate::pins::images(source);
  let mut pins = BTreeMap::new();
  let mut missing = Vec::new();
  for image in &want {
    let digest =
      images.iter().filter(|i| &i.image == image).find_map(|i| {
        wharf_api_types::agent::normalize_image_digest(
          image,
          i.digest.as_deref()?,
        )
        .and_then(|reference| {
          reference
            .rsplit_once('@')
            .map(|(_, digest)| digest.to_string())
        })
      });
    if let Some(digest) = digest {
      pins.insert(image.clone(), digest);
    } else {
      missing.push(image.as_str());
    }
  }
  if !missing.is_empty() {
    let message = format!(
      "部署 #{id} 没有记录这些镜像的 digest（{}）",
      missing.join("、")
    );
    if !allow {
      return Err(
        ApiError::invalid(format!("{message}，无法精确回滚"))
          .with_hint("如需按标签重新拉取，加 --allow-unpinned")
          .suggest(suggest()),
      );
    }
    warnings.push(format!("{message}，将按标签重新拉取"));
  }
  if matches!(source, Source::Compose { content: Some(content), .. } if content.contains("${"))
    && images
      .iter()
      .any(|i| !i.image.contains('@') && !want.contains(&i.image))
  {
    warnings.push("Compose 中使用变量的镜像未固定到 digest".into());
  }
  Ok(((!want.is_empty()).then_some(pins), None))
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use wharf_api_types::spec::Change;

  #[tokio::test]
  async fn rollback_by_id_finds_deployment_beyond_200_and_excludes_other_instances()
   {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      c.execute_batch(
        "WITH RECURSIVE seq(id) AS (VALUES(1) UNION ALL SELECT id + 1 FROM seq WHERE id < 205)
         INSERT INTO deployments (id, service, server, run_id, hash, compose, images, created_at, instance_id, started)
         SELECT id, 'reader', 's1', 'r1', CASE WHEN id <= 203 THEN 'old' ELSE 'new' END, '', '[]', id,
           CASE WHEN id = 2 THEN 'svc_old' ELSE 'svc_new' END, id < 205 FROM seq;",
      ).map_err(sql_err)?;
      let select = |to| super::select(c, "reader", "svc_new", to);
      assert_eq!(select(None)?.0, 203);
      assert_eq!(select(Some(1))?.0, 1);
      assert!(select(Some(2)).unwrap_err().message.contains("旧服务实例"));
      assert!(select(Some(205)).unwrap_err().message.contains("从未启动"));
      assert_eq!(select(Some(206)).unwrap_err().code, wharf_api_types::ErrorCode::NotFound);
      Ok(())
    }).await.unwrap();
  }

  #[test]
  fn compose_rollback_pins_all_images_without_mutating_yaml() {
    let yaml = "services: {web: {image: 'web:latest'}, worker: {image: 'worker:latest'}}";
    let spec: ServiceSpec = serde_json::from_value(json!({
      "server":"s1", "source":{"compose":{"content":yaml}}
    }))
    .unwrap();
    let images: Vec<ImageInfo> = serde_json::from_value(json!([
      {"image":"web:latest", "digest":format!("mirror.example.test/web@sha256:{}", "a".repeat(64))},
      {"image":"worker:latest", "digest":format!("worker@sha256:{}", "b".repeat(64))}
    ])).unwrap();
    let (pins, commit) = extract_pins_and_commit(
      "app",
      1,
      &spec.source,
      &images,
      None,
      false,
      &mut vec![],
    )
    .unwrap();
    let mut world = crate::world::World::default();
    world
      .apply_changes(&[Change::UpsertService {
        name: "app".into(),
        spec: spec.clone(),
        adopt: None,
        pins,
        commit,
      }])
      .unwrap();
    let row = &world.services["app"];
    assert_eq!(row.spec.source, spec.source);
    assert_eq!(
      row.pins["web:latest"],
      format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
      row.pins["worker:latest"],
      format!("sha256:{}", "b".repeat(64))
    );
    let applied = serde_json::from_value(json!({
      "hash":"same", "at":"2026-01-01T00:00:00Z",
      "digests":{"web:latest":row.pins["web:latest"], "worker:latest":format!("sha256:{}", "c".repeat(64))}
    })).unwrap();
    let change =
      crate::pins::change(Some(&applied), &row.pins, None, true)
        .unwrap();
    assert_eq!(change.0, "worker:latest");
  }

  #[test]
  fn git_rollback_pins_commit_without_overwriting_reference() {
    let spec: ServiceSpec = serde_json::from_value(json!({
      "server":"s1", "source":{"build":{"git":{"repo":"https://example.test/app.git","ref":"main"}}}
    })).unwrap();
    let (pins, commit) = extract_pins_and_commit(
      "app",
      1,
      &spec.source,
      &[],
      Some("a".repeat(40)),
      false,
      &mut vec![],
    )
    .unwrap();
    let mut world = crate::world::World::default();
    world
      .apply_changes(&[Change::UpsertService {
        name: "app".into(),
        spec: spec.clone(),
        adopt: None,
        pins,
        commit,
      }])
      .unwrap();
    assert_eq!(world.services["app"].spec.source, spec.source);
    assert_eq!(world.services["app"].commit, Some("a".repeat(40)));
    world
      .apply_changes(&[Change::RefreshImages {
        name: "app".into(),
        image: None,
      }])
      .unwrap();
    assert_eq!(world.services["app"].commit, None);
  }

  #[test]
  fn rollback_blocks_unpinned_digest_and_missing_upload_by_default() {
    let source = Source::Image("app:latest".into());
    let mut warnings = vec![];
    assert!(
      extract_pins_and_commit(
        "app",
        1,
        &source,
        &[],
        None,
        false,
        &mut warnings
      )
      .is_err()
    );
    let (pins, _) = extract_pins_and_commit(
      "app",
      1,
      &source,
      &[],
      None,
      true,
      &mut warnings,
    )
    .unwrap();
    assert_eq!(pins, Some(BTreeMap::new()));
    assert_eq!(warnings.len(), 1);
    let state = crate::rules::tests::test_state();
    let build = Source::Build(wharf_api_types::spec::BuildSource {
      upload: Some("d".repeat(64)),
      ..Default::default()
    });
    assert!(
      require_upload(&state, "app", 1, &build)
        .unwrap_err()
        .message
        .contains("已过期清理")
    );
    for value in ["1", "true"] {
      let uri =
        format!("/rollback?allow_unpinned={value}").parse().unwrap();
      assert!(
        Query::<RollbackQuery>::try_from_uri(&uri)
          .unwrap()
          .allow_unpinned
      );
    }
  }

  #[test]
  fn rollback_preserves_current_start_timeout() {
    let mut old: ServiceSpec = serde_json::from_value(json!({
      "server": "s1", "source": {"image": "app:1"}
    }))
    .unwrap();
    let current: ServiceSpec = serde_json::from_value(json!({
      "server": "s2", "source": {"image": "app:2"}, "start_timeout_secs": 300
    }))
    .unwrap();
    let merged = merge_settings(old.clone(), &current, &mut vec![]);
    assert_eq!(merged.start_timeout_secs, Some(300));
    assert_eq!(merged.source, old.source);

    old.start_timeout_secs = Some(90);
    let current = ServiceSpec {
      start_timeout_secs: None,
      ..current
    };
    assert_eq!(
      merge_settings(old, &current, &mut vec![]).start_timeout_secs,
      None
    );
  }

  #[test]
  fn rollback_preserves_current_stop_and_init_settings() {
    let configured: ServiceSpec = serde_json::from_value(json!({
      "server": "s1", "source": {"image": "app:2"},
      "stop_grace_secs": 240, "stop_signal": "SIGINT",
      "init_cmd": "echo prepare", "init_timeout_secs": 90
    }))
    .unwrap();
    let defaults: ServiceSpec = serde_json::from_value(json!({
      "server": "s1", "source": {"image": "app:1"}
    }))
    .unwrap();
    for (historical, current) in
      [(&defaults, &configured), (&configured, &defaults)]
    {
      let merged =
        merge_settings(historical.clone(), current, &mut Vec::new());
      assert_eq!(merged.source, historical.source);
      assert_eq!(merged.stop_grace_secs, current.stop_grace_secs);
      assert_eq!(merged.stop_signal, current.stop_signal);
      assert_eq!(merged.init_cmd, current.init_cmd);
      assert_eq!(merged.init_timeout_secs, current.init_timeout_secs);
    }
  }

  #[test]
  fn rollback_preserves_monitoring_and_heartbeat_and_drops_incompatible_ports()
   {
    let mut state = crate::rules::tests::test_state();
    Arc::get_mut(&mut state).unwrap().public_url =
      Some("https://example.test".into());
    let mut current = crate::world::World::default();
    let mut spec: ServiceSpec = serde_json::from_value(json!({
      "server":"s1", "source":{"image":"app:2"},
      "ports":[{"name":"http","container":80},{"name":"metrics","container":81}],
      "monitor":{"port":"http"}, "log_alerts":[{"pattern":"FATAL"}],
      "port_checks":{"http":{"kind":"off"},"metrics":{"kind":"off"}},
      "heartbeat":{"every_mins":60}, "auto_update":true
    })).unwrap();
    spec.heartbeat.as_mut().unwrap().token = crate::auth::new_token();
    let change = |spec| Change::UpsertService {
      name: "app".into(),
      spec,
      adopt: None,
      pins: None,
      commit: None,
    };
    current.apply_changes(&[change(spec.clone())]).unwrap();
    let old = serde_json::from_value(json!({
      "server":"s1","source":{"image":"app:1"},"ports":[{"name":"http","container":80}]
    })).unwrap();
    let mut warnings = Vec::new();
    let merged = merge_settings(old, &spec, &mut warnings);
    let redacted = crate::service_monitor::heartbeat::redact(&merged);
    assert!(redacted.heartbeat.as_ref().unwrap().token.is_empty());
    assert_eq!(merged.monitor, spec.monitor);
    assert_eq!(merged.log_alerts, spec.log_alerts);
    assert_eq!(
      merged.port_checks.keys().collect::<Vec<_>>(),
      ["http"]
    );
    assert!(!merged.auto_update);
    assert!(warnings.iter().any(|w| w.contains("metrics")));
    let mut desired = current.clone();
    desired.apply_changes(&[change(redacted)]).unwrap();
    crate::service_monitor::heartbeat::prepare(
      &state,
      &current,
      &mut desired,
    )
    .unwrap();
    assert_eq!(
      desired.services["app"].spec.heartbeat,
      spec.heartbeat
    );
  }
}
