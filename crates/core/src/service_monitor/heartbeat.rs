use std::collections::BTreeMap;

use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension, params};
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  service_checks::{HeartbeatSpec, HeartbeatView},
  spec::ServiceSpec,
  view::OpStatus,
};

use crate::{
  db::{now_ms, sql_err},
  snapshot::Snapshot,
  state::AppState,
  world::World,
};

const ENV: &str = "WHARF_HEARTBEAT_URL";
const METRIC: &str = "heartbeat.overdue_mins";
static UPDATE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

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

pub fn prepare(
  state: &AppState,
  current: &World,
  desired: &mut World,
) -> Result<(), ApiError> {
  for (name, row) in &mut desired.services {
    let old = current
      .services
      .get(name)
      .and_then(|r| r.spec.heartbeat.as_ref());
    if let Some(h) = &mut row.spec.heartbeat {
      h.token = old
        .filter(|h| !h.token.is_empty())
        .map_or_else(crate::auth::new_token, |h| h.token.clone());
      if old != Some(h)
        && state.public_url.as_deref().is_none_or(str::is_empty)
      {
        return Err(missing_url());
      }
    }
  }
  Ok(())
}

fn missing_url() -> ApiError {
  ApiError::invalid("控制面没有公开地址，无法配置心跳")
    .with_hint("在控制面设置 WHARF_PUBLIC_URL=https://你的控制面地址，或用 --public-url 启动")
}

pub fn redact(spec: &ServiceSpec) -> ServiceSpec {
  let mut spec = spec.clone();
  if let Some(h) = &mut spec.heartbeat {
    h.token.clear();
  }
  spec
}

pub fn url(h: &HeartbeatSpec, reveal: bool) -> String {
  if reveal {
    format!(
      "{}/ping/{}",
      crate::gate::public_url().unwrap_or_default(),
      h.token
    )
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
  inject(text, h, public, resolved)
}

fn inject(
  text: &str,
  h: &HeartbeatSpec,
  public: &str,
  resolved: bool,
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
  for (name, service) in services {
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
  fn value(
    &self,
    h: &HeartbeatSpec,
    applied: Option<i64>,
    now: i64,
  ) -> f64 {
    if self.failed {
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
  reveal: bool,
) -> Option<HeartbeatView> {
  let spec = &snap.world.services.get(name)?.spec;
  let h = spec.heartbeat.as_ref()?;
  let r = snap.heartbeats.get(name);
  let firing = crate::rules::firing_subjects("heartbeat_late")
    .iter()
    .any(|(s, _)| s == name);
  let status = if spec.stopped {
    "已停止"
  } else if r.is_some_and(|r| r.failed) {
    "报到失败"
  } else if firing {
    "超时"
  } else if r.and_then(|r| r.last_at).is_some() {
    "正常"
  } else {
    "等待报到"
  };
  Some(HeartbeatView {
    url: url(h, reveal),
    last_at: r.and_then(|r| r.last_at),
    status: status.into(),
  })
}

pub async fn round(state: &AppState) {
  let _guard = UPDATE.lock().await;
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
    let Some(r) = snap.heartbeats.get(&name) else {
      continue;
    };
    if snap
      .ops
      .get(&name)
      .is_some_and(|op| op.status == OpStatus::Running)
    {
      continue;
    }
    let h =
      snap.world.services[&name].spec.heartbeat.as_ref().unwrap();
    let applied =
      snap.applied.get(&name).map(|a| a.at.timestamp_millis());
    let value = r.value(h, applied, now_ms());
    // 报到先落库。若控制面在提交后、通知前退出，重启后也能补上恢复。
    if !r.failed
      && crate::rules::firing_since("heartbeat_late", &name)
        .zip(r.last_ok)
        .is_some_and(|(since, ok)| ok >= since)
    {
      crate::rules::observe(
        state,
        METRIC,
        &name,
        -f64::MAX,
        "收到成功报到",
      )
      .await;
    }
    let detail = if r.failed {
      let service = name.clone();
      state.db.call(move |c| {
        c.query_row("SELECT output FROM service_heartbeat_reports WHERE service=?1 ORDER BY id DESC LIMIT 1",
          [service], |row| row.get::<_, String>(0)).optional().map_err(sql_err)
      }).await.ok().flatten().unwrap_or_default()
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

pub async fn ping(
  state: &AppState,
  token: &str,
  ok: bool,
  body: &str,
) -> (StatusCode, &'static str) {
  let _guard = UPDATE.lock().await;
  let token = token.to_string();
  let output: String =
    body.replace(&token, "…").chars().take(500).collect();
  let stored_output = output.clone();
  let written = state
    .db
    .call(move |c| record(c, &token, ok, &stored_output, now_ms()))
    .await;
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
  token: &str,
  ok: bool,
  output: &str,
  now: i64,
) -> Result<Option<(String, bool)>, ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let target = tx.query_row(
    "SELECT h.service, COALESCE(json_extract(r.spec, '$.stopped'), 0)
     FROM service_heartbeats h JOIN resources r ON r.kind='service' AND r.name=h.service WHERE h.token=?1",
    [token], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
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
    let endpoint = || (State(state.clone()), Path("fixture".into()));
    let (s, path) = endpoint();
    let (status, _) =
      crate::ping::fail(s, path, "failed".into()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
      crate::rules::firing_subjects("heartbeat_late")
        .iter()
        .any(|(s, _)| s == "heartbeat-test")
    );
    let (s, path) = endpoint();
    let (status, _) = crate::ping::ok(s, path, String::new()).await;
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
      every_mins: 10,
      grace_mins: 5,
      token: "fixture".into(),
    };
    assert_eq!(overdue(&h, 14 * 60_000), -1.0);
    assert_eq!(overdue(&h, 16 * 60_000), 1.0);
    let rendered = inject("services:\n  web: {image: nginx, environment: [FOO=bar]}\n  app: {image: alpine}", &h, "https://wharf.example.test", true).unwrap();
    assert_eq!(
      rendered
        .matches("https://wharf.example.test/ping/fixture")
        .count(),
      2
    );
    assert!(rendered.contains("FOO=bar"));
  }

  #[test]
  fn inject_preserves_environment_from_chained_anchors() {
    let text = concat!(
      "x-a: &a {environment: {A: '1'}}\n",
      "x-b: &b {<<: *a}\n",
      "services: {app: {<<: *b, image: nginx}}\n",
    );
    let heartbeat = HeartbeatSpec {
      every_mins: 10,
      grace_mins: 5,
      token: "fixture".into(),
    };
    let out =
      inject(text, &heartbeat, "https://example.test", true).unwrap();
    let doc = crate::render::parse_compose(&out).unwrap();
    let env = &doc["services"]["app"]["environment"];
    assert_eq!(env["A"], "1");
    assert_eq!(env[ENV], "https://example.test/ping/fixture");
  }
}
