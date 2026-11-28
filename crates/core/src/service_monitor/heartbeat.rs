use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex, Weak},
};

use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension, params};
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  service_checks::{
    HeartbeatReportView, HeartbeatSpec, HeartbeatView,
  },
  spec::ServiceSpec,
};

use crate::{
  db::{now_ms, sql_err},
  snapshot::Snapshot,
  state::AppState,
  world::World,
};

const ENV: &str = "WHARF_HEARTBEAT_URL";
const METRIC: &str = "heartbeat.overdue_mins";

type ServiceLock = tokio::sync::Mutex<()>;
static SERVICE_LOCKS: Mutex<BTreeMap<String, Weak<ServiceLock>>> =
  Mutex::new(BTreeMap::new());

fn service_lock(name: &str) -> Arc<ServiceLock> {
  let mut locks =
    SERVICE_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
  locks.retain(|_, lock| lock.strong_count() != 0);
  if let Some(lock) = locks.get(name).and_then(Weak::upgrade) {
    return lock;
  }
  let lock = Arc::new(ServiceLock::default());
  locks.insert(name.to_string(), Arc::downgrade(&lock));
  lock
}

pub const MIGRATION: &str = "
CREATE TABLE service_heartbeats (
  service TEXT PRIMARY KEY, token TEXT NOT NULL UNIQUE, enabled_at INTEGER NOT NULL,
  last_at INTEGER, last_ok INTEGER, failed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE service_heartbeat_reports (
  id INTEGER PRIMARY KEY, service TEXT NOT NULL REFERENCES service_heartbeats(service) ON DELETE CASCADE,
  at INTEGER NOT NULL, ok INTEGER NOT NULL, output TEXT NOT NULL
);
CREATE INDEX service_heartbeat_recent ON service_heartbeat_reports(service, id);
CREATE TRIGGER service_heartbeat_create AFTER INSERT ON resources WHEN NEW.kind='service'
  AND json_extract(NEW.spec, '$.heartbeat.token') != ''
BEGIN
  INSERT INTO service_heartbeats (service, token, enabled_at)
    VALUES (NEW.name, json_extract(NEW.spec, '$.heartbeat.token'), NEW.updated_at);
END;
CREATE TRIGGER service_heartbeat_change AFTER UPDATE OF spec ON resources WHEN NEW.kind='service'
BEGIN
  DELETE FROM service_heartbeats WHERE service = NEW.name
    AND token IS NOT json_extract(NEW.spec, '$.heartbeat.token');
  INSERT INTO service_heartbeats (service, token, enabled_at)
    SELECT NEW.name, json_extract(NEW.spec, '$.heartbeat.token'), NEW.updated_at
    WHERE json_extract(NEW.spec, '$.heartbeat.token') != ''
    ON CONFLICT(service) DO NOTHING;
  UPDATE service_heartbeats SET enabled_at = NEW.updated_at, failed = 0 WHERE service = NEW.name
    AND COALESCE(json_extract(OLD.spec, '$.stopped'), 0) = 1
    AND COALESCE(json_extract(NEW.spec, '$.stopped'), 0) = 0;
END;
CREATE TRIGGER service_heartbeat_delete AFTER DELETE ON resources WHEN OLD.kind='service'
BEGIN
  DELETE FROM service_heartbeats WHERE service = OLD.name;
END;
";

pub(crate) fn base_url(
  world: &World,
  net: &crate::render::Net,
  listener: Option<u16>,
  configured: Option<&str>,
) -> Option<String> {
  configured
    .filter(|url| !url.is_empty())
    .map(str::to_string)
    .or_else(|| {
      crate::join::route_urls(world, net, listener?)
        .into_iter()
        .next()
    })
}

pub const ROTATE_MIGRATION: &str = "
DROP TRIGGER IF EXISTS service_heartbeat_change;
CREATE TRIGGER service_heartbeat_change AFTER UPDATE OF spec ON resources WHEN NEW.kind='service'
BEGIN
  DELETE FROM service_heartbeats WHERE service = NEW.name
    AND COALESCE(json_extract(NEW.spec, '$.heartbeat.token'), '') = '';
  INSERT INTO service_heartbeats (service, token, enabled_at)
    SELECT NEW.name, json_extract(NEW.spec, '$.heartbeat.token'), NEW.updated_at
    WHERE json_extract(NEW.spec, '$.heartbeat.token') != ''
    ON CONFLICT(service) DO UPDATE SET token = excluded.token, enabled_at = excluded.enabled_at,
      failed = 0 WHERE service_heartbeats.token != excluded.token;
  UPDATE service_heartbeats SET enabled_at = NEW.updated_at, failed = 0 WHERE service = NEW.name
    AND COALESCE(json_extract(OLD.spec, '$.stopped'), 0) = 1
    AND COALESCE(json_extract(NEW.spec, '$.stopped'), 0) = 0;
END;
";

pub fn reports(
  c: &Connection,
  service: &str,
  limit: u32,
) -> Result<Vec<HeartbeatReportView>, ApiError> {
  let mut stmt = c.prepare(
    "SELECT at, ok, output FROM service_heartbeat_reports WHERE service = ?1 ORDER BY id DESC LIMIT ?2",
  ).map_err(sql_err)?;
  stmt
    .query_map(params![service, limit.clamp(1, 50)], |row| {
      Ok(HeartbeatReportView {
        at: row.get(0)?,
        ok: row.get(1)?,
        output: row.get(2)?,
      })
    })
    .map_err(sql_err)?
    .collect::<Result<_, _>>()
    .map_err(sql_err)
}

pub fn prepare(
  current: &World,
  desired: &mut World,
  base: Option<&str>,
) -> Result<(), ApiError> {
  for (name, row) in &mut desired.services {
    let before = current.services.get(name).map(|r| &r.spec);
    let old = before.and_then(|spec| spec.heartbeat.as_ref());
    if let Some(h) = &mut row.spec.heartbeat {
      let rotate = std::mem::take(&mut h.rotate);
      h.token = old
        .filter(|h| !rotate && !h.token.is_empty())
        .map_or_else(crate::auth::new_token, |h| h.token.clone());
      h.targeted = old.is_some_and(|old| old.targeted);
      let config_changed = old.is_none_or(|old| {
        old.every_mins != h.every_mins
          || old.grace_mins != h.grace_mins
          || old.token.is_empty()
      }) || before
        .is_some_and(|spec| spec.container != row.spec.container);
      if (config_changed || rotate) && base.is_none_or(str::is_empty)
      {
        return Err(missing_url());
      }
      h.targeted |= config_changed;
      if h.targeted
        && let wharf_api_types::spec::Source::Compose {
          content: Some(yaml),
          ..
        } = &row.spec.source
      {
        crate::render::compose_target(
          name,
          yaml,
          row.spec.container.as_deref(),
        )
        .map_err(|e| {
          if row.spec.container.is_none() {
            let containers = e.hint.unwrap_or_default();
            ApiError::invalid(format!(
              "服务 {name} 要指定接收心跳变量的容器"
            ))
            .with_hint(format!(
              "加上 --container <容器名>。{containers}"
            ))
          } else {
            e
          }
        })?;
      }
    }
  }
  Ok(())
}

fn missing_url() -> ApiError {
  ApiError::invalid("没有控制面的访问地址，无法生成心跳链接")
    .with_hint("先给控制面绑一个域名，或配置 WHARF_PUBLIC_URL")
}

pub fn redact(spec: &ServiceSpec) -> ServiceSpec {
  let mut spec = spec.clone();
  if let Some(h) = &mut spec.heartbeat {
    h.token.clear();
  }
  spec
}

pub fn url(
  h: &HeartbeatSpec,
  base: Option<&str>,
  reveal: bool,
) -> String {
  if reveal {
    format!("{}/ping/{}", base.unwrap_or_default(), h.token)
  } else {
    format!("/ping/{}…", h.token.chars().take(4).collect::<String>())
  }
}

pub fn compose(
  text: &str,
  spec: &ServiceSpec,
  public: Option<&str>,
  resolved: bool,
) -> Result<String, ApiError> {
  let Some(h) = &spec.heartbeat else {
    return Ok(text.to_string());
  };
  let public =
    public.filter(|u| !u.is_empty()).ok_or_else(missing_url)?;
  let target = if h.targeted
    && matches!(
      spec.source,
      wharf_api_types::spec::Source::Compose { .. }
    ) {
    spec.container.as_deref()
  } else {
    None
  };
  inject(text, h, public, resolved, target)
}

fn inject(
  text: &str,
  h: &HeartbeatSpec,
  public: &str,
  resolved: bool,
  target: Option<&str>,
) -> Result<String, ApiError> {
  let invalid = || {
    ApiError::invalid("无法给 compose 容器注入心跳变量")
      .with_hint("检查 services 里的 environment，使用映射或列表")
  };
  let mut yaml: Value =
    serde_yaml_ng::from_str(text).map_err(|_| invalid())?;
  yaml.apply_merge().map_err(|_| invalid())?;
  let merged =
    crate::render::parse_compose(text).map_err(|_| invalid())?;
  let services = yaml
    .get_mut("services")
    .and_then(Value::as_mapping_mut)
    .ok_or_else(invalid)?;
  let token = if resolved {
    h.token.as_str()
  } else {
    "<heartbeat>"
  };
  let url = format!("{public}/ping/{token}").replace('$', "$$");
  if let Some(target) = target
    && !services.contains_key(Value::from(target))
  {
    let names = services
      .keys()
      .filter_map(Value::as_str)
      .collect::<Vec<_>>()
      .join("、");
    return Err(
      ApiError::invalid(format!("compose 里没有容器 {target}"))
        .with_hint(format!("可用容器：{names}")),
    );
  }
  for (name, service) in services {
    if target.is_some_and(|target| name.as_str() != Some(target)) {
      continue;
    }
    let inherited = merged["services"][name].get("environment");
    let service = service.as_mapping_mut().ok_or_else(invalid)?;
    let environment = service
      .entry(Value::from("environment"))
      .or_insert(Value::Null);
    if let Some(inherited) = inherited
      && environment != inherited
    {
      environment.clone_from(inherited);
    }
    if environment.is_null() {
      *environment = Value::Mapping(Mapping::new());
    }
    match environment {
      Value::Mapping(m) => {
        m.insert(Value::from(ENV), Value::from(url.as_str()));
      }
      Value::Sequence(seq) => {
        seq.retain(|v| {
          v.as_str().is_none_or(|s| s.split('=').next() != Some(ENV))
        });
        seq.push(Value::from(format!("{ENV}={url}")));
      }
      _ => return Err(invalid()),
    }
  }
  serde_yaml_ng::to_string(&yaml).map_err(|_| invalid())
}

pub struct Reading {
  enabled_at: i64,
  last_at: Option<i64>,
  last_ok: Option<i64>,
  failed: bool,
}

pub fn load(
  c: &Connection,
) -> Result<BTreeMap<String, Reading>, ApiError> {
  let mut stmt = c.prepare("SELECT service, enabled_at, last_at, last_ok, failed FROM service_heartbeats")
    .map_err(sql_err)?;
  stmt
    .query_map([], |r| {
      Ok((
        r.get(0)?,
        Reading {
          enabled_at: r.get(1)?,
          last_at: r.get(2)?,
          last_ok: r.get(3)?,
          failed: r.get(4)?,
        },
      ))
    })
    .and_then(Iterator::collect)
    .map_err(sql_err)
}

fn overdue(h: &HeartbeatSpec, elapsed_ms: i64) -> f64 {
  elapsed_ms as f64 / 60_000.0
    - f64::from(h.every_mins)
    - f64::from(h.grace_mins)
}

impl Reading {
  fn is_failed(&self, applied: Option<i64>) -> bool {
    self.failed
      && applied
        .is_none_or(|a| self.last_at.is_none_or(|last| last >= a))
  }

  fn value(
    &self,
    h: &HeartbeatSpec,
    applied: Option<i64>,
    now: i64,
  ) -> f64 {
    if self.is_failed(applied) {
      return f64::MAX;
    }
    let since = self
      .enabled_at
      .max(applied.unwrap_or_default())
      .max(self.last_ok.unwrap_or_default());
    overdue(h, now.saturating_sub(since))
  }
}

pub fn view(
  snap: &Snapshot,
  name: &str,
  base: Option<&str>,
  reveal: bool,
) -> Option<HeartbeatView> {
  let spec = &snap.world.services.get(name)?.spec;
  let h = spec.heartbeat.as_ref()?;
  let r = snap.heartbeats.get(name);
  let applied =
    snap.applied.get(name).map(|a| a.at.timestamp_millis());
  let firing = crate::rules::firing_subjects("heartbeat_late")
    .iter()
    .any(|(s, _)| s == name);
  let status = if spec.stopped {
    "已停止"
  } else if r.is_some_and(|r| r.is_failed(applied)) {
    "报到失败"
  } else if firing
    && r.is_some_and(|r| r.value(h, applied, now_ms()) > 0.0)
  {
    "超时"
  } else if r
    .and_then(|r| r.last_at)
    .is_some_and(|last| applied.is_none_or(|at| last >= at))
  {
    "正常"
  } else {
    "等待报到"
  };
  Some(HeartbeatView {
    url: url(h, base, reveal),
    last_at: r.and_then(|r| r.last_at),
    status: status.into(),
  })
}

pub async fn round(state: &AppState) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let subjects = snap
    .world
    .services
    .iter()
    .filter(|(_, row)| {
      !row.spec.stopped && row.spec.heartbeat.is_some()
    })
    .map(|(name, _)| name.to_string())
    .collect();
  crate::rules::retain_subjects(state, "heartbeat_late", &subjects)
    .await;
  for name in subjects {
    if crate::rules::op_silence::service_busy(state, &name)
      || snap.ops.get(&name).is_some_and(|op| {
        op.status == wharf_api_types::view::OpStatus::Running
      })
    {
      continue;
    }
    let h =
      snap.world.services[&name].spec.heartbeat.as_ref().unwrap();
    let applied =
      snap.applied.get(&name).map(|a| a.at.timestamp_millis());
    let reading = {
      let lock = service_lock(&name);
      let _guard = lock.lock().await;
      let service = name.clone();
      state.db.call(move |c| {
        c.query_row(
          "SELECT h.enabled_at, h.last_at, h.last_ok, h.failed,
                  (SELECT output FROM service_heartbeat_reports WHERE service=h.service ORDER BY id DESC LIMIT 1)
           FROM service_heartbeats h WHERE h.service = ?1",
          [service], |row| Ok((Reading { enabled_at: row.get(0)?, last_at: row.get(1)?, last_ok: row.get(2)?, failed: row.get(3)? }, row.get::<_, Option<String>>(4)?)),
        ).optional().map_err(sql_err)
      }).await
    };
    let Ok(Some((r, output))) = reading else {
      continue;
    };
    let value = r.value(h, applied, now_ms());
    let detail = if r.is_failed(applied) {
      output.unwrap_or_default()
    } else {
      r.last_at
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
          || "尚未报到".into(),
          |at| format!("最近报到：{}", at.to_rfc3339()),
        )
    };
    crate::rules::observe(state, METRIC, &name, value, &detail).await;
  }
}

pub async fn service_for_token(
  state: &AppState,
  token: &str,
) -> Result<Option<String>, ApiError> {
  let token = token.to_string();
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT service FROM service_heartbeats WHERE token = ?1",
        [token],
        |r| r.get(0),
      )
      .optional()
      .map_err(sql_err)
    })
    .await
}

pub async fn ping(
  state: &AppState,
  name: &str,
  token: &str,
  ok: bool,
  body: &str,
) -> (StatusCode, &'static str) {
  let token = token.to_string();
  let output: String =
    body.replace(&token, "…").chars().take(500).collect();
  let stored_output = output.clone();
  let written = {
    let lock = service_lock(name);
    let _guard = lock.lock().await;
    let name = name.to_string();
    state
      .db
      .call(move |c| {
        record(c, &name, &token, ok, &stored_output, now_ms())
      })
      .await
  };
  match written {
    Ok(Some((name, stopped))) => {
      if !stopped {
        let value = if ok { -f64::MAX } else { f64::MAX };
        let detail = if ok {
          "收到成功报到".into()
        } else {
          format!("收到失败报到\n{output}")
        };
        crate::rules::observe(state, METRIC, &name, value, &detail)
          .await;
      }
      (StatusCode::OK, "ok\n")
    }
    Ok(None) => (StatusCode::NOT_FOUND, "没有这个报到地址\n"),
    Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "稍后再试\n"),
  }
}

fn record(
  c: &mut Connection,
  name: &str,
  token: &str,
  ok: bool,
  output: &str,
  now: i64,
) -> Result<Option<(String, bool)>, ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let target = tx.query_row(
    "SELECT h.service, COALESCE(json_extract(r.spec, '$.stopped'), 0)
     FROM service_heartbeats h JOIN resources r ON r.kind='service' AND r.name=h.service WHERE h.token=?1 AND h.service=?2",
    params![token, name], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
  ).optional().map_err(sql_err)?;
  if let Some((name, _)) = &target {
    tx.execute(
      "UPDATE service_heartbeats SET last_at=?2, last_ok=CASE WHEN ?3 THEN ?2 ELSE last_ok END, failed=NOT ?3 WHERE service=?1",
      params![name, now, ok],
    ).map_err(sql_err)?;
    tx.execute("INSERT INTO service_heartbeat_reports(service, at, ok, output) VALUES (?1, ?2, ?3, ?4)",
      params![name, now, ok, output],
    ).map_err(sql_err)?;
    tx.execute("DELETE FROM service_heartbeat_reports WHERE service=?1 AND id <=
      (SELECT id FROM service_heartbeat_reports WHERE service=?1 ORDER BY id DESC LIMIT 1 OFFSET 50)",
      [name],
    ).map_err(sql_err)?;
  }
  tx.commit().map_err(sql_err)?;
  Ok(target)
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::extract::{Path, State};
  use serde_json::json;

  #[tokio::test]
  async fn heartbeat_route_fails_recovers_and_keeps_task_runs_unchanged()
   {
    let _g = crate::rules::tests::TEST_LOCK.lock().await;
    crate::rules::tests::reset_memory();
    let state = super::super::tests::state();
    state.db.call(|c| {
      let spec = json!({
        "server": "s1", "source": { "image": "nginx" },
        "heartbeat": { "every_mins": 10, "grace_mins": 5, "token": "fixture" }
      });
      c.execute("INSERT INTO resources (kind,name,spec,updated_at,created_at,version)
         VALUES ('service','heartbeat-test',?1,1000,1000,1)", [spec.to_string()]).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    let peer = || {
      axum::extract::ConnectInfo("203.0.113.1:1234".parse().unwrap())
    };
    let endpoint = || (State(state.clone()), Path("fixture".into()));
    let (s, path) = endpoint();
    let (status, _) = crate::ping::fail(
      s,
      path,
      peer(),
      Default::default(),
      "failed".into(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
      crate::rules::firing_subjects("heartbeat_late")
        .iter()
        .any(|(s, _)| s == "heartbeat-test")
    );
    let (s, path) = endpoint();
    let (status, _) = crate::ping::ok(
      s,
      path,
      peer(),
      Default::default(),
      String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
      !crate::rules::firing_subjects("heartbeat_late")
        .iter()
        .any(|(s, _)| s == "heartbeat-test")
    );
    let counts = state.db.call(|c| {
      c.query_row("SELECT (SELECT COUNT(*) FROM task_runs), (SELECT COUNT(*) FROM service_heartbeat_reports)",
        [], |r| Ok((r.get::<_, i32>(0)?, r.get::<_, i32>(1)?))).map_err(sql_err)
    }).await.unwrap();
    assert_eq!(counts, (0, 2));
  }

  #[test]
  fn heartbeat_deadline_and_env_injection() {
    let h = HeartbeatSpec {
      rotate: false,
      every_mins: 10,
      grace_mins: 5,
      token: "fixture".into(),
      targeted: false,
    };
    assert_eq!(overdue(&h, 14 * 60_000), -1.0);
    assert_eq!(overdue(&h, 16 * 60_000), 1.0);
    let rendered = inject("services:\n  web: {image: nginx, environment: [FOO=bar]}\n  app: {image: alpine}", &h, "https://wharf.example.test", true, None).unwrap();
    assert_eq!(
      rendered
        .matches("https://wharf.example.test/ping/fixture")
        .count(),
      2
    );
    assert!(rendered.contains("FOO=bar"));
  }

  #[test]
  fn compose_heartbeat_and_env_respect_container() {
    let spec = serde_json::from_value::<ServiceSpec>(json!({
      "server":"s1", "source":{"compose":{"content":"services:\n  app:\n    image: nginx\n    environment: {}\n  db:\n    image: redis\n"}},
      "container":"app", "env":{"FOO":"1"},
      "heartbeat":{"every_mins":5,"targeted":true}
    })).unwrap();
    let wharf_api_types::spec::Source::Compose {
      content: Some(yaml),
      ..
    } = &spec.source
    else {
      unreachable!()
    };
    let configured =
      crate::render::compose_with_settings("app", yaml, &spec)
        .unwrap();
    let rendered = compose(
      &configured,
      &spec,
      Some("https://wharf.example.test"),
      false,
    )
    .unwrap();
    let doc = crate::render::parse_compose(&rendered).unwrap();
    assert_eq!(doc["services"]["app"]["environment"]["FOO"], "1");
    assert!(doc["services"]["app"]["environment"].get(ENV).is_some());
    assert!(doc["services"]["db"].get("environment").is_none());
  }

  #[test]
  fn heartbeat_base_uses_core_route_without_explicit_url() {
    let row = |kind: &str, name: &str, spec| crate::db::ResourceRow {
      kind: kind.into(),
      name: name.into(),
      version: 1,
      meta: json!({}),
      spec,
    };
    let world = World::from_rows(vec![
      row("gateway", "gw", json!({"kind":"caddy","server":"s1"})),
      row("route", "wharf.example.test", json!({"hostname":"wharf.example.test","gateway":"gw","upstream":"127.0.0.1:7700"})),
    ]).unwrap();
    let net = crate::render::Net {
      core_server: Some("s1".into()),
      ..Default::default()
    };
    assert_eq!(
      base_url(&world, &net, Some(7700), None).as_deref(),
      Some("https://wharf.example.test")
    );
    assert_eq!(
      base_url(
        &world,
        &net,
        Some(7700),
        Some("https://legacy.example.test")
      )
      .as_deref(),
      Some("https://legacy.example.test")
    );
  }

  #[test]
  fn legacy_heartbeat_keeps_the_same_compose_and_spec() {
    let world = World::from_rows(vec![crate::db::ResourceRow {
      kind: "service".into(), name: "app".into(), version: 1, meta: json!({}),
      spec: json!({"server":"s1", "source":{"compose":{"content":"services: {app: {image: nginx}, db: {image: redis}}"}}, "container":"app", "heartbeat":{"every_mins":10,"token":"fixture"}}),
    }]).unwrap();
    let spec = &world.services["app"].spec;
    let wharf_api_types::spec::Source::Compose {
      content: Some(yaml),
      ..
    } = &spec.source
    else {
      unreachable!()
    };
    let mut desired = world.clone();
    let base = "https://wharf.example.test";
    prepare(&world, &mut desired, Some(base)).unwrap();
    assert!(desired.writes_from(&world).is_empty());
    let saved = spec.heartbeat.as_ref().unwrap();
    let expected = inject(yaml, saved, base, true, None).unwrap();
    assert_eq!(
      compose(yaml, &desired.services["app"].spec, Some(base), true)
        .unwrap(),
      expected
    );
    let changed = desired.services.get_mut("app").unwrap();
    changed.spec.heartbeat.as_mut().unwrap().every_mins = 30;
    prepare(&world, &mut desired, Some(base)).unwrap();
    assert!(!super::super::config_only(
      &world.services["app"],
      &desired.services["app"]
    ));
  }

  #[test]
  fn heartbeat_recovers_on_relax_and_redeploy() {
    let h = HeartbeatSpec {
      rotate: false,
      every_mins: 60,
      grace_mins: 1,
      token: String::new(),
      targeted: false,
    };
    let mut r = Reading {
      enabled_at: 0,
      last_at: Some(1000),
      last_ok: None,
      failed: true,
    };
    assert_eq!(r.value(&h, None, 600_000), f64::MAX);
    assert!(r.value(&h, Some(2000), 600_000) < 0.0);
    r.failed = false;
    assert!(r.value(&h, None, 600_000) < 0.0);
  }

  #[test]
  fn inject_preserves_environment_from_chained_anchors() {
    let text = concat!(
      "x-a: &a {environment: {A: '1'}}\n",
      "x-b: &b {<<: *a}\n",
      "services: {app: {<<: *b, image: nginx}}\n",
    );
    let heartbeat = HeartbeatSpec {
      rotate: false,
      every_mins: 10,
      grace_mins: 5,
      token: "fixture".into(),
      targeted: false,
    };
    let out =
      inject(text, &heartbeat, "https://example.test", true, None)
        .unwrap();
    let doc = crate::render::parse_compose(&out).unwrap();
    let env = &doc["services"]["app"]["environment"];
    assert_eq!(env["A"], "1");
    assert_eq!(env[ENV], "https://example.test/ping/fixture");
  }
}
