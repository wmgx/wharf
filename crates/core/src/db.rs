//! SQLite：唯一事实来源。
//!
//! 服务器设置、服务、网关、路由统一存在 `resources` 表，每行有自己的
//! `version`，plan/apply 用它做乐观锁。其他表是运行数据。

use std::{
  path::Path,
  sync::{Arc, Mutex},
};

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use wharf_api_types::{
  ApiError,
  spec::AdoptSpec,
  view::{Applied, ImportRecord, LastOp, OpStatus},
};

const MIGRATIONS: &[&str] = &[
  r#"
CREATE TABLE resources (
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  spec TEXT NOT NULL,
  meta TEXT NOT NULL DEFAULT '{}',
  version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (kind, name)
);
CREATE TABLE agents (
  server TEXT PRIMARY KEY,
  public_key TEXT,
  join_token_hash TEXT UNIQUE,
  join_expires_at INTEGER,
  report TEXT,
  last_seen INTEGER
);
CREATE TABLE accounts (
  name TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  token TEXT NOT NULL,
  zones TEXT NOT NULL,
  warnings TEXT NOT NULL DEFAULT '[]',
  updated_at INTEGER NOT NULL
);
CREATE TABLE secrets (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE owned_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  route_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  account TEXT NOT NULL,
  scope TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (account, scope, remote_id)
);
CREATE TABLE plans (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  body TEXT NOT NULL,
  steps TEXT NOT NULL,
  writes TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  status TEXT NOT NULL,
  body TEXT NOT NULL,
  started_at INTEGER NOT NULL
);
CREATE TABLE deployments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL,
  server TEXT NOT NULL,
  run_id TEXT NOT NULL,
  hash TEXT NOT NULL,
  compose TEXT NOT NULL,
  images TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX deployments_service ON deployments (service, id);
CREATE TABLE api_tokens (
  name TEXT PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
"#,
  // 部署历史记下当时的服务配置，用于回滚。
  r#"
ALTER TABLE deployments ADD COLUMN spec TEXT;
"#,
  // 备份记录（含失败，用于定时备份的退避）和迁移后待删除的旧数据。
  r#"
CREATE TABLE backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL,
  server TEXT NOT NULL,
  target TEXT NOT NULL,
  run_id TEXT NOT NULL,
  ok INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX backups_service ON backups (service, id);
CREATE TABLE cleanups (
  service TEXT NOT NULL,
  server TEXT NOT NULL,
  due_at INTEGER NOT NULL,
  PRIMARY KEY (service, server)
);
"#,
  // cloudflare_tunnel 网关创建的隧道，和最近一次写入的入口规则哈希。
  r#"
CREATE TABLE tunnels (
  gateway TEXT PRIMARY KEY,
  account TEXT NOT NULL,
  scope TEXT NOT NULL,
  tunnel_id TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"#,
  // 构建来源的部署记下实际构建的 git commit，回滚和迁移时固定到它。
  r#"
ALTER TABLE deployments ADD COLUMN commit_sha TEXT;
"#,
  // 页面登录：唯一的管理员账号和浏览器会话。
  r#"
CREATE TABLE admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE sessions (
  hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
"#,
  // 绑定到边缘应用（Workers / Pages）的自定义域名，记下绑在厂商哪个项目上，解绑时用。
  r#"
CREATE TABLE edge_domains (
  hostname TEXT PRIMARY KEY,
  app TEXT NOT NULL,
  account TEXT NOT NULL,
  kind TEXT NOT NULL,
  project TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"#,
  // 边缘应用的同步结果（key 是 `app:<名字>` / `account:<账号>`），页面直接读它；
  // 以及 Wharf 记录的线上版本，用来发现别处改过。
  r#"
CREATE TABLE edge_cache (
  key TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  checked_at INTEGER NOT NULL
);
CREATE TABLE edge_expected (
  app TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  versions TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
"#,
  // 连通性探测结果：from 机器能不能直连 to 机器的内网地址。
  r#"
CREATE TABLE reach (
  from_server TEXT NOT NULL,
  to_server TEXT NOT NULL,
  ok INTEGER NOT NULL,
  checked_at INTEGER NOT NULL,
  PRIMARY KEY (from_server, to_server)
);
"#,
  // 零散的单值设置，例如控制面自身备份到哪台服务器。
  r#"
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"#,
  // 打点：资源曲线和部署、备份等事件，见 metrics.rs。
  r#"
CREATE TABLE points (
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  at INTEGER NOT NULL,
  value REAL NOT NULL,
  PRIMARY KEY (subject, name, at)
) WITHOUT ROWID;
CREATE INDEX points_at ON points (at);
"#,
  PORTS_MIGRATION,
  // 每个服务最近一次部署、启停、重启、迁移、恢复，服务状态的"执行"一层。
  r#"
CREATE TABLE service_ops (
  service TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  at INTEGER NOT NULL,
  error TEXT
);
"#,
  ADOPT_MIGRATION,
  EDGE_DOMAINS_MIGRATION,
  PINS_MIGRATION,
  COMMIT_MIGRATION,
];

/// git 构建来源固定到上次部署构建的 commit（仓库和分支没换过的）。当时没记下 commit 的留给 plan 提醒。
const COMMIT_MIGRATION: &str = r#"
UPDATE resources
SET meta = json_set(meta, '$.commit', (
  SELECT d.commit_sha FROM deployments d
  WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1))
WHERE kind = 'service' AND json_type(spec, '$.source.build.git') = 'object'
  AND (SELECT d.commit_sha FROM deployments d
       WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1) IS NOT NULL
  AND (SELECT json_extract(d.spec, '$.source.build.git.repo') || '#' || json_extract(d.spec, '$.source.build.git.ref')
       FROM deployments d WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1)
    = json_extract(spec, '$.source.build.git.repo') || '#' || json_extract(spec, '$.source.build.git.ref');
DELETE FROM plans WHERE status = 'pending';
"#;

/// image 来源固定到上次部署实际用的 digest，升级后不会因为补查版本而重新部署。
/// 部署记录里没有 digest 的（经镜像源拉取的旧部署）留给第一次 plan 去查。
const PINS_MIGRATION: &str = r#"
UPDATE resources
SET meta = json_set(meta, '$.pins', json_object(
  json_extract(spec, '$.source.image'),
  (SELECT substr(dg, instr(dg, '@') + 1) FROM (
    SELECT json_extract(d.images, '$[0].digest') AS dg FROM deployments d
    WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1))))
WHERE kind = 'service' AND json_type(spec, '$.source.image') = 'text'
  AND (SELECT json_extract(d.images, '$[0].digest') FROM deployments d
       WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1) LIKE '%@sha256:%';
DELETE FROM plans WHERE status = 'pending';
"#;

/// 指向边缘应用的路由挪进边缘应用的 `domains`。Pages 域名的 DNS 记录所有者从路由 id 改成 `edge:<域名>`。
const EDGE_DOMAINS_MIGRATION: &str = r#"
UPDATE resources
SET spec = json_set(spec, '$.domains', (
  SELECT json_group_array(name) FROM (
    SELECT r.name FROM resources r
    WHERE r.kind = 'route' AND json_extract(r.spec, '$.service') = resources.name
    ORDER BY r.name)))
WHERE kind = 'edge' AND EXISTS (
  SELECT 1 FROM resources r
  WHERE r.kind = 'route' AND json_extract(r.spec, '$.service') = resources.name);
UPDATE owned_records SET route_id = 'edge:' || hostname
WHERE route_id IN (
  SELECT json_extract(r.meta, '$.id') FROM resources r
  WHERE r.kind = 'route'
    AND json_extract(r.spec, '$.service') IN (SELECT name FROM resources WHERE kind = 'edge'));
DELETE FROM resources
WHERE kind = 'route'
  AND json_extract(spec, '$.service') IN (SELECT name FROM resources WHERE kind = 'edge');
DELETE FROM plans WHERE status = 'pending';
"#;

/// adopt 从服务配置移到导入记录：部署过的记为已完成，还没部署的挪到 meta 里等第一次部署；
/// 部署历史里的也去掉，免得回滚时又带回配置。未执行的计划里还是旧格式，删掉。
const ADOPT_MIGRATION: &str = r#"
CREATE TABLE imports (
  service TEXT PRIMARY KEY,
  server TEXT NOT NULL,
  project TEXT,
  containers TEXT,
  retired TEXT,
  done_at INTEGER
);
INSERT INTO imports (service, server, project, containers, done_at)
SELECT r.name, json_extract(r.spec, '$.server'),
       json_extract(r.spec, '$.adopt.project'),
       json_extract(r.spec, '$.adopt.containers'),
       (SELECT MIN(created_at) FROM deployments d WHERE d.service = r.name)
FROM resources r
WHERE r.kind = 'service' AND json_type(r.spec, '$.adopt') IS NOT NULL
  AND EXISTS (SELECT 1 FROM deployments d WHERE d.service = r.name);
UPDATE resources
SET meta = json_set(COALESCE(meta, '{}'), '$.import', json(json_extract(spec, '$.adopt')))
WHERE kind = 'service' AND json_type(spec, '$.adopt') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.service = resources.name);
UPDATE resources SET spec = json_remove(spec, '$.adopt')
WHERE kind = 'service' AND json_type(spec, '$.adopt') IS NOT NULL;
UPDATE deployments SET spec = json_remove(spec, '$.adopt')
WHERE spec IS NOT NULL AND json_type(spec, '$.adopt') IS NOT NULL;
DELETE FROM plans WHERE status = 'pending';
"#;

/// 端口字段 `{port, host_port}` 改成 `{container, host}`：旧的 `port` 在 compose 来源里
/// 是宿主机端口，其余来源是容器端口。服务配置和部署历史（回滚用）都转换；
/// 没执行的计划里是旧格式，直接删掉，用户重新 plan。
const PORTS_MIGRATION: &str = r#"
UPDATE resources SET spec = json_set(spec, '$.ports', (
  SELECT json_group_array(json(x)) FROM (
    SELECT CASE
      WHEN json_type(resources.spec, '$.source.compose') IS NOT NULL
        THEN json_object('name', json_extract(p.value, '$.name'),
                         'host', json_extract(p.value, '$.port'))
      WHEN json_extract(p.value, '$.host_port') IS NOT NULL
        THEN json_object('name', json_extract(p.value, '$.name'),
                         'container', json_extract(p.value, '$.port'),
                         'host', json_extract(p.value, '$.host_port'))
      ELSE json_object('name', json_extract(p.value, '$.name'),
                       'container', json_extract(p.value, '$.port'))
    END AS x
    FROM json_each(resources.spec, '$.ports') p ORDER BY p.key)))
WHERE kind = 'service' AND json_array_length(spec, '$.ports') > 0;

UPDATE deployments SET spec = json_set(spec, '$.ports', (
  SELECT json_group_array(json(x)) FROM (
    SELECT CASE
      WHEN json_type(deployments.spec, '$.source.compose') IS NOT NULL
        THEN json_object('name', json_extract(p.value, '$.name'),
                         'host', json_extract(p.value, '$.port'))
      WHEN json_extract(p.value, '$.host_port') IS NOT NULL
        THEN json_object('name', json_extract(p.value, '$.name'),
                         'container', json_extract(p.value, '$.port'),
                         'host', json_extract(p.value, '$.host_port'))
      ELSE json_object('name', json_extract(p.value, '$.name'),
                       'container', json_extract(p.value, '$.port'))
    END AS x
    FROM json_each(deployments.spec, '$.ports') p ORDER BY p.key)))
WHERE spec IS NOT NULL AND json_array_length(spec, '$.ports') > 0;

DELETE FROM plans WHERE status = 'pending';
"#;

pub fn setting(
  c: &Connection,
  key: &str,
) -> Result<Option<String>, ApiError> {
  c.query_row(
    "SELECT value FROM settings WHERE key = ?1",
    params![key],
    |r| r.get(0),
  )
  .optional()
  .map_err(sql_err)
}

/// `None` 删除。
pub fn set_setting(
  c: &Connection,
  key: &str,
  value: Option<&str>,
) -> Result<(), ApiError> {
  match value {
    Some(v) => c.execute(
      "INSERT INTO settings (key, value) VALUES (?1, ?2)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value",
      params![key, v],
    ),
    None => {
      c.execute("DELETE FROM settings WHERE key = ?1", params![key])
    }
  }
  .map_err(sql_err)?;
  Ok(())
}

#[derive(Clone)]
pub struct Db {
  conn: Arc<Mutex<Connection>>,
}

impl Db {
  pub fn open(path: &Path) -> anyhow::Result<Self> {
    let conn = Connection::open(path)?;
    Self::init(conn)
  }

  #[cfg(test)]
  pub fn memory() -> Self {
    Self::init(Connection::open_in_memory().unwrap()).unwrap()
  }

  fn init(mut conn: Connection) -> anyhow::Result<Self> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let current: usize =
      conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
      let tx = conn.transaction()?;
      tx.execute_batch(sql)?;
      tx.pragma_update(None, "user_version", i + 1)?;
      tx.commit()?;
    }
    Ok(Self {
      conn: Arc::new(Mutex::new(conn)),
    })
  }

  /// 在阻塞线程里执行一段数据库操作。
  pub async fn call<R, F>(&self, f: F) -> Result<R, ApiError>
  where
    R: Send + 'static,
    F:
      FnOnce(&mut Connection) -> Result<R, ApiError> + Send + 'static,
  {
    let conn = self.conn.clone();
    tokio::task::spawn_blocking(move || {
      let mut conn = conn.lock().unwrap_or_else(|p| p.into_inner());
      f(&mut conn)
    })
    .await
    .map_err(|e| ApiError::internal(format!("数据库任务失败：{e}")))?
  }
}

pub fn sql_err(e: rusqlite::Error) -> ApiError {
  tracing::error!("sqlite: {e}");
  ApiError::internal("数据库错误，详见控制面日志")
}

pub fn json_err(e: serde_json::Error) -> ApiError {
  ApiError::internal(format!("数据格式错误：{e}"))
}

pub fn now_ms() -> i64 {
  Utc::now().timestamp_millis()
}

pub fn to_time(ms: i64) -> DateTime<Utc> {
  Utc.timestamp_millis_opt(ms).single().unwrap_or_default()
}

// RESOURCES

#[derive(Debug, Clone)]
pub struct ResourceRow {
  pub kind: String,
  pub name: String,
  pub spec: Value,
  pub meta: Value,
  pub version: u64,
}

pub fn all_resources(
  conn: &Connection,
) -> Result<Vec<ResourceRow>, ApiError> {
  let mut stmt = conn
    .prepare(
      "SELECT kind, name, spec, meta, version FROM resources ORDER BY kind, name",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, String>(2)?,
        r.get::<_, String>(3)?,
        r.get::<_, i64>(4)?,
      ))
    })
    .map_err(sql_err)?;
  let mut out = Vec::new();
  for row in rows {
    let (kind, name, spec, meta, version) = row.map_err(sql_err)?;
    out.push(ResourceRow {
      kind,
      name,
      spec: serde_json::from_str(&spec).map_err(json_err)?,
      meta: serde_json::from_str(&meta).map_err(json_err)?,
      version: version as u64,
    });
  }
  Ok(out)
}

/// 配置写入，在 apply 的事务里执行。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Write {
  Upsert {
    kind: String,
    name: String,
    spec: Value,
    meta: Value,
  },
  Delete {
    kind: String,
    name: String,
  },
}

pub fn apply_write(
  conn: &Connection,
  write: &Write,
) -> Result<(), ApiError> {
  let now = now_ms();
  match write {
    Write::Upsert {
      kind,
      name,
      spec,
      meta,
    } => conn
      .execute(
        "INSERT INTO resources (kind, name, spec, meta, version, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
         ON CONFLICT (kind, name) DO UPDATE SET
           spec = excluded.spec, meta = excluded.meta,
           version = resources.version + 1, updated_at = excluded.updated_at",
        params![kind, name, spec.to_string(), meta.to_string(), now],
      )
      .map(|_| ())
      .map_err(sql_err),
    Write::Delete { kind, name } => {
      conn
        .execute(
          "DELETE FROM resources WHERE kind = ?1 AND name = ?2",
          params![kind, name],
        )
        .map_err(sql_err)?;
      if kind == crate::world::KIND_EDGE {
        conn
          .execute(
            "DELETE FROM edge_cache WHERE key = ?1",
            params![format!("app:{name}")],
          )
          .map_err(sql_err)?;
        conn
          .execute("DELETE FROM edge_expected WHERE app = ?1", params![name])
          .map_err(sql_err)?;
      }
      Ok(())
    }
  }
}

/// 边缘应用同步结果：key → （JSON，同步时间毫秒）。
pub fn edge_cache(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, (String, i64)>, ApiError>
{
  let mut stmt = c
    .prepare("SELECT key, data, checked_at FROM edge_cache")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn put_edge_cache(
  c: &Connection,
  key: &str,
  data: &str,
) -> Result<(), ApiError> {
  c.execute(
    "INSERT INTO edge_cache (key, data, checked_at) VALUES (?1, ?2, ?3)
     ON CONFLICT (key) DO UPDATE SET data = ?2, checked_at = ?3",
    params![key, data, now_ms()],
  )
  .map_err(sql_err)?;
  Ok(())
}

/// Wharf 记录的线上版本：应用 → （厂商项目，版本 id 用逗号连起来）。
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeExpected {
  pub target: String,
  pub versions: String,
}

pub fn edge_expected(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, EdgeExpected>, ApiError>
{
  let mut stmt = c
    .prepare("SELECT app, target, versions FROM edge_expected")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get(0)?,
        EdgeExpected {
          target: r.get(1)?,
          versions: r.get(2)?,
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn put_edge_expected(
  c: &Connection,
  app: &str,
  e: &EdgeExpected,
) -> Result<(), ApiError> {
  c.execute(
    "INSERT INTO edge_expected (app, target, versions, updated_at) VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT (app) DO UPDATE SET target = ?2, versions = ?3, updated_at = ?4",
    params![app, e.target, e.versions, now_ms()],
  )
  .map_err(sql_err)?;
  Ok(())
}

pub fn versions(
  conn: &Connection,
) -> Result<std::collections::BTreeMap<String, u64>, ApiError> {
  Ok(
    all_resources(conn)?
      .into_iter()
      .map(|r| (format!("{}/{}", r.kind, r.name), r.version))
      .collect(),
  )
}

// AGENTS

#[derive(Debug, Clone)]
pub struct AgentRow {
  pub server: String,
  pub public_key: Option<String>,
  pub report: Option<wharf_api_types::agent::AgentReport>,
  pub last_seen: Option<i64>,
}

pub fn agents(conn: &Connection) -> Result<Vec<AgentRow>, ApiError> {
  let mut stmt = conn
    .prepare(
      "SELECT server, public_key, report, last_seen FROM agents",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, Option<String>>(1)?,
        r.get::<_, Option<String>>(2)?,
        r.get::<_, Option<i64>>(3)?,
      ))
    })
    .map_err(sql_err)?;
  let mut out = Vec::new();
  for row in rows {
    let (server, public_key, report, last_seen) =
      row.map_err(sql_err)?;
    out.push(AgentRow {
      server,
      public_key,
      report: report.and_then(|r| serde_json::from_str(&r).ok()),
      last_seen,
    });
  }
  Ok(out)
}

pub fn agent(
  conn: &Connection,
  server: &str,
) -> Result<Option<AgentRow>, ApiError> {
  Ok(agents(conn)?.into_iter().find(|a| a.server == server))
}

// SECRETS

pub fn secrets(
  conn: &Connection,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  let mut stmt = conn
    .prepare("SELECT name, value FROM secrets")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

// REACH

pub type Reach = std::collections::BTreeMap<(String, String), bool>;

/// 探测结果超过这个时间就当作不知道：网络会变，旧结果不能拿来下结论。
pub const REACH_TTL_MS: i64 = 24 * 3600 * 1000;

pub fn reach(conn: &Connection) -> Result<Reach, ApiError> {
  let mut stmt = conn
    .prepare("SELECT from_server, to_server, ok FROM reach WHERE checked_at >= ?1")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([now_ms() - REACH_TTL_MS], |r| {
      Ok((
        (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
        r.get(2)?,
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

/// 连通性探测结果和探测时间（毫秒）。
pub fn reach_rows(
  conn: &Connection,
) -> Result<Vec<(String, String, bool, i64)>, ApiError> {
  let mut stmt = conn
    .prepare(
      "SELECT from_server, to_server, ok, checked_at FROM reach ORDER BY from_server, to_server",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn set_reach(
  conn: &Connection,
  results: &[(String, String, bool)],
  now: i64,
) -> Result<(), ApiError> {
  for (from, to, ok) in results {
    conn
      .execute(
        "INSERT INTO reach (from_server, to_server, ok, checked_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (from_server, to_server) DO UPDATE SET ok = excluded.ok, checked_at = excluded.checked_at",
        params![from, to, ok, now],
      )
      .map_err(sql_err)?;
  }
  Ok(())
}

/// 没有就生成一个随机值存进去，返回它。
pub fn ensure_secret(
  conn: &Connection,
  name: &str,
  now: i64,
) -> Result<String, ApiError> {
  let existing: Option<String> = conn
    .query_row(
      "SELECT value FROM secrets WHERE name = ?1",
      params![name],
      |r| r.get(0),
    )
    .optional()
    .map_err(sql_err)?;
  if let Some(v) = existing {
    return Ok(v);
  }
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  let value = hex::encode(bytes);
  conn
    .execute(
      "INSERT INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)",
      params![name, value, now],
    )
    .map_err(sql_err)?;
  Ok(value)
}

// ACCOUNTS

#[derive(Clone)]
pub struct AccountRow {
  pub name: String,
  pub kind: String,
  pub token: String,
  pub zones: Vec<String>,
  pub warnings: Vec<String>,
  pub updated_at: i64,
}

pub fn accounts(
  conn: &Connection,
) -> Result<Vec<AccountRow>, ApiError> {
  let mut stmt = conn
    .prepare(
      "SELECT name, kind, token, zones, warnings, updated_at FROM accounts ORDER BY name",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, String>(2)?,
        r.get::<_, String>(3)?,
        r.get::<_, String>(4)?,
        r.get::<_, i64>(5)?,
      ))
    })
    .map_err(sql_err)?;
  let mut out = Vec::new();
  for row in rows {
    let (name, kind, token, zones, warnings, updated_at) =
      row.map_err(sql_err)?;
    out.push(AccountRow {
      name,
      kind,
      token,
      zones: serde_json::from_str(&zones).map_err(json_err)?,
      warnings: serde_json::from_str(&warnings).map_err(json_err)?,
      updated_at,
    });
  }
  Ok(out)
}

// OWNED DNS RECORDS

#[derive(Debug, Clone, PartialEq)]
pub struct OwnedRecord {
  pub route_id: String,
  pub hostname: String,
  pub account: String,
  pub scope: String,
  pub remote_id: String,
}

pub fn owned_records(
  conn: &Connection,
) -> Result<Vec<OwnedRecord>, ApiError> {
  let mut stmt = conn
    .prepare(
      "SELECT route_id, hostname, account, scope, remote_id FROM owned_records ORDER BY id",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok(OwnedRecord {
        route_id: r.get(0)?,
        hostname: r.get(1)?,
        account: r.get(2)?,
        scope: r.get(3)?,
        remote_id: r.get(4)?,
      })
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn add_owned(
  conn: &Connection,
  r: &OwnedRecord,
) -> Result<(), ApiError> {
  conn
    .execute(
      "INSERT OR REPLACE INTO owned_records (route_id, hostname, account, scope, remote_id, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
      params![r.route_id, r.hostname, r.account, r.scope, r.remote_id, now_ms()],
    )
    .map(|_| ())
    .map_err(sql_err)
}

pub fn remove_owned(
  conn: &Connection,
  account: &str,
  scope: &str,
  remote_id: &str,
) -> Result<(), ApiError> {
  conn
    .execute(
      "DELETE FROM owned_records WHERE account = ?1 AND scope = ?2 AND remote_id = ?3",
      params![account, scope, remote_id],
    )
    .map(|_| ())
    .map_err(sql_err)
}

// TOKENS

pub fn token_scope(
  conn: &Connection,
  hash: &str,
) -> Result<Option<(String, String)>, ApiError> {
  let found: Option<(String, String)> = conn
    .query_row(
      "SELECT name, scope FROM api_tokens WHERE hash = ?1",
      params![hash],
      |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(sql_err)?;
  if let Some((name, _)) = &found {
    conn
      .execute(
        "UPDATE api_tokens SET last_used_at = ?1 WHERE name = ?2",
        params![now_ms(), name],
      )
      .map_err(sql_err)?;
  }
  Ok(found)
}

pub fn token_count(conn: &Connection) -> Result<i64, ApiError> {
  conn
    .query_row("SELECT COUNT(*) FROM api_tokens", [], |r| r.get(0))
    .map_err(sql_err)
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
  pub account: String,
  pub scope: String,
  pub tunnel_id: String,
  /// 最近一次写到厂商那边的入口规则的哈希，空表示还没写过。
  pub config_hash: String,
}

pub fn tunnels(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, TunnelRow>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT gateway, account, scope, tunnel_id, config_hash FROM tunnels",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get(0)?,
        TunnelRow {
          account: r.get(1)?,
          scope: r.get(2)?,
          tunnel_id: r.get(3)?,
          config_hash: r.get(4)?,
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

/// 已绑定到边缘应用的自定义域名。
#[derive(
  Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize,
)]
pub struct EdgeDomainRow {
  pub hostname: String,
  pub app: String,
  pub account: String,
  /// `worker` / `pages`
  pub kind: String,
  pub project: String,
}

pub fn edge_domains(
  c: &Connection,
) -> Result<Vec<EdgeDomainRow>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT hostname, app, account, kind, project FROM edge_domains ORDER BY hostname",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok(EdgeDomainRow {
        hostname: r.get(0)?,
        app: r.get(1)?,
        account: r.get(2)?,
        kind: r.get(3)?,
        project: r.get(4)?,
      })
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn put_edge_domain(
  c: &Connection,
  row: &EdgeDomainRow,
) -> Result<(), ApiError> {
  c.execute(
    "INSERT INTO edge_domains (hostname, app, account, kind, project, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT (hostname) DO UPDATE SET app = ?2, account = ?3, kind = ?4, project = ?5",
    params![row.hostname, row.app, row.account, row.kind, row.project, now_ms()],
  )
  .map_err(sql_err)?;
  Ok(())
}

pub fn delete_edge_domain(
  c: &Connection,
  hostname: &str,
) -> Result<(), ApiError> {
  c.execute(
    "DELETE FROM edge_domains WHERE hostname = ?1",
    params![hostname],
  )
  .map_err(sql_err)?;
  Ok(())
}

/// 每个服务最近一次部署所在的服务器。
pub fn deployed_servers(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT service, server, MAX(id) FROM deployments GROUP BY service",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

/// 导入后第一次部署成功：记进导入记录，清掉服务上的待办导入，之后部署不再接管。
pub fn finish_import(
  c: &Connection,
  service: &str,
  server: &str,
  adopt: &AdoptSpec,
  retired: &[String],
) -> Result<(), ApiError> {
  let tx = c.unchecked_transaction().map_err(sql_err)?;
  tx.execute(
    "INSERT OR REPLACE INTO imports (service, server, project, containers, retired, done_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![
      service,
      server,
      adopt.project,
      serde_json::to_string(&adopt.containers).map_err(json_err)?,
      serde_json::to_string(retired).map_err(json_err)?,
      now_ms()
    ],
  )
  .map_err(sql_err)?;
  tx.execute(
    "UPDATE resources SET meta = json_remove(meta, '$.import'), version = version + 1
     WHERE kind = 'service' AND name = ?1",
    params![service],
  )
  .map_err(sql_err)?;
  tx.commit().map_err(sql_err)
}

pub fn imports(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, ImportRecord>, ApiError>
{
  let mut stmt = c
    .prepare("SELECT service, server, project, containers, retired, done_at FROM imports")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      let list = |s: Option<String>| -> Vec<String> {
        s.and_then(|s| serde_json::from_str(&s).ok())
          .unwrap_or_default()
      };
      Ok((
        r.get::<_, String>(0)?,
        ImportRecord {
          server: r.get(1)?,
          project: r.get(2)?,
          containers: list(r.get(3)?),
          retired: list(r.get(4)?),
          done_at: r.get::<_, Option<i64>>(5)?.map(to_time),
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

/// 每个服务最近一次成功部署的哈希和时间。
pub fn applied(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, Applied>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT service, hash, created_at, images, commit_sha, json_extract(spec, '$.source.build.git.repo') || '#' || json_extract(spec, '$.source.build.git.ref') FROM deployments
       WHERE id IN (SELECT MAX(id) FROM deployments GROUP BY service)",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      let images: Vec<wharf_api_types::agent::ImageInfo> =
        serde_json::from_str(&r.get::<_, String>(3)?)
          .unwrap_or_default();
      Ok((
        r.get::<_, String>(0)?,
        Applied {
          hash: r.get(1)?,
          at: to_time(r.get(2)?),
          digest: images
            .iter()
            .find_map(|i| i.digest.as_deref()?.split_once('@'))
            .map(|(_, d)| d.to_string()),
          image: images.first().map(|i| i.image.clone()),
          image_id: images
            .first()
            .map(|i| i.id.clone())
            .filter(|i| !i.is_empty()),
          commit: r.get(4)?,
          git: r.get(5)?,
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn service_ops(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, LastOp>, ApiError> {
  let mut stmt = c
    .prepare("SELECT service, action, run_id, status, at, error FROM service_ops")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      let status = match r.get::<_, String>(3)?.as_str() {
        "running" => OpStatus::Running,
        "succeeded" => OpStatus::Succeeded,
        _ => OpStatus::Failed,
      };
      Ok((
        r.get::<_, String>(0)?,
        LastOp {
          action: r.get(1)?,
          run_id: r.get(2)?,
          status,
          at: to_time(r.get(4)?),
          error: r.get(5)?,
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn set_service_op(
  c: &Connection,
  service: &str,
  op: &LastOp,
) -> Result<(), ApiError> {
  let status = match op.status {
    OpStatus::Running => "running",
    OpStatus::Succeeded => "succeeded",
    OpStatus::Failed => "failed",
  };
  c.execute(
    "INSERT OR REPLACE INTO service_ops (service, action, run_id, status, at, error)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![service, op.action, op.run_id, status, op.at.timestamp_millis(), op.error],
  )
  .map_err(sql_err)?;
  Ok(())
}

/// 控制面重启时执行中的操作都断了。
pub fn interrupt_service_ops(c: &Connection) -> Result<(), ApiError> {
  c.execute(
    "UPDATE service_ops SET status = 'failed', error = '控制面重启，执行中断' WHERE status = 'running'",
    [],
  )
  .map_err(sql_err)?;
  Ok(())
}

#[cfg(test)]
mod tests {
  #[test]
  fn commit_migration() {
    let c = Connection::open_in_memory().unwrap();
    let git = |r: &str| {
      format!(
        r#"{{"source":{{"build":{{"git":{{"repo":"https://g/x","ref":"{r}"}}}}}}}}"#
      )
    };
    c.execute_batch(
      "CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT, meta TEXT NOT NULL DEFAULT '{}');
       CREATE TABLE deployments (id INTEGER, service TEXT, spec TEXT, commit_sha TEXT);
       CREATE TABLE plans (status TEXT);",
    )
    .unwrap();
    for (name, now, deployed, commit) in [
      ("same", "main", "main", Some("c1")),
      ("moved", "dev", "main", Some("c2")),
      ("unknown", "main", "main", None),
    ] {
      c.execute("INSERT INTO resources (kind, name, spec) VALUES ('service', ?1, ?2)", params![name, git(now)]).unwrap();
      c.execute(
        "INSERT INTO deployments VALUES (1, ?1, ?2, ?3)",
        params![name, git(deployed), commit],
      )
      .unwrap();
    }
    c.execute_batch(COMMIT_MIGRATION).unwrap();
    let meta: Vec<String> = c
      .prepare("SELECT meta FROM resources ORDER BY name")
      .unwrap()
      .query_map([], |r| r.get(0))
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert_eq!(meta, ["{}", r#"{"commit":"c1"}"#, "{}"]);
  }

  #[test]
  fn pins_migration() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
      r#"CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT, meta TEXT NOT NULL DEFAULT '{}');
       CREATE TABLE deployments (id INTEGER, service TEXT, images TEXT);
       CREATE TABLE plans (status TEXT);
       INSERT INTO resources VALUES
         ('service', 'web', '{"source":{"image":"nginx:1"}}', '{"host_ports":{"http":20000}}'),
         ('service', 'old', '{"source":{"image":"x:latest"}}', '{}'),
         ('service', 'blog', '{"source":{"compose":{"content":"x"}}}', '{}');
       INSERT INTO deployments VALUES
         (1, 'web', '[{"image":"nginx:1","id":"sha256:i1","digest":"nginx@sha256:aa"}]'),
         (2, 'web', '[{"image":"nginx:1","id":"sha256:i2","digest":"docker.io/library/nginx@sha256:bb"}]'),
         (3, 'old', '[{"image":"x:latest","id":"sha256:i3"}]'),
         (4, 'blog', '[{"image":"y","id":"sha256:i4","digest":"y@sha256:cc"}]');"#,
    )
    .unwrap();
    c.execute_batch(PINS_MIGRATION).unwrap();
    let meta: Vec<String> = c
      .prepare("SELECT meta FROM resources ORDER BY name")
      .unwrap()
      .query_map([], |r| r.get(0))
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert_eq!(
      meta,
      [
        "{}",
        "{}",
        r#"{"host_ports":{"http":20000},"pins":{"nginx:1":"sha256:bb"}}"#
      ]
    );
  }

  #[test]
  fn edge_domains_migration() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
      r#"CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT, meta TEXT NOT NULL DEFAULT '{}');
       CREATE TABLE owned_records (route_id TEXT, hostname TEXT);
       CREATE TABLE plans (status TEXT);
       INSERT INTO resources VALUES
         ('edge', 'site', '{"account":"cf","kind":"pages"}', '{}'),
         ('edge', 'idle', '{"account":"cf","kind":"worker"}', '{}'),
         ('service', 'web', '{"server":"a"}', '{}'),
         ('route', 'b.example.com', '{"hostname":"b.example.com","service":"site"}', '{"id":"rt_b"}'),
         ('route', 'a.example.com', '{"hostname":"a.example.com","service":"site"}', '{"id":"rt_a"}'),
         ('route', 'w.example.com', '{"hostname":"w.example.com","service":"web"}', '{"id":"rt_w"}');
       INSERT INTO owned_records VALUES ('rt_a', 'a.example.com'), ('rt_w', 'w.example.com');"#,
    )
    .unwrap();
    c.execute_batch(EDGE_DOMAINS_MIGRATION).unwrap();
    let get = |sql: &str| -> Vec<String> {
      c.prepare(sql)
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    };
    assert_eq!(
      get(
        "SELECT spec FROM resources WHERE kind = 'edge' ORDER BY name"
      ),
      [
        r#"{"account":"cf","kind":"worker"}"#,
        r#"{"account":"cf","kind":"pages","domains":["a.example.com","b.example.com"]}"#,
      ]
    );
    assert_eq!(
      get("SELECT name FROM resources WHERE kind = 'route'"),
      ["w.example.com"]
    );
    assert_eq!(
      get("SELECT route_id FROM owned_records ORDER BY hostname"),
      ["edge:a.example.com", "rt_w"]
    );
  }

  #[test]
  fn adopt_migration() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
      r#"CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT, meta TEXT NOT NULL DEFAULT '{}');
       CREATE TABLE deployments (service TEXT, spec TEXT, created_at INTEGER);
       CREATE TABLE plans (status TEXT);
       INSERT INTO resources (kind, name, spec) VALUES
         ('service', 'done', '{"server":"a","adopt":{"containers":["done"]}}'),
         ('service', 'todo', '{"server":"a","adopt":{"project":"blog"}}'),
         ('service', 'plain', '{"server":"a"}');
       INSERT INTO deployments VALUES ('done', '{"server":"a","adopt":{"containers":["done"]}}', 5);"#,
    )
    .unwrap();
    c.execute_batch(ADOPT_MIGRATION).unwrap();
    let rows: Vec<(String, String, String)> = c
      .prepare("SELECT name, spec, meta FROM resources ORDER BY name")
      .unwrap()
      .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
      .unwrap()
      .map(Result::unwrap)
      .collect();
    let meta =
      |n: &str| rows.iter().find(|r| r.0 == n).unwrap().2.clone();
    assert!(rows.iter().all(|r| !r.1.contains("adopt")));
    assert_eq!(meta("done"), "{}");
    assert_eq!(meta("todo"), r#"{"import":{"project":"blog"}}"#);
    let imports = imports(&c).unwrap();
    assert_eq!(imports.keys().collect::<Vec<_>>(), ["done"]);
    assert_eq!(imports["done"].containers, ["done"]);
    assert!(imports["done"].done_at.is_some());
    let spec: String = c
      .query_row("SELECT spec FROM deployments", [], |r| r.get(0))
      .unwrap();
    assert!(!spec.contains("adopt"));
  }

  #[test]
  fn ports_migration() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
      "CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT);
       CREATE TABLE deployments (spec TEXT);
       CREATE TABLE plans (status TEXT);
       INSERT INTO plans VALUES ('pending'), ('applied');",
    )
    .unwrap();
    let old = [
      r#"{"server":"a","source":{"compose":{"content":"x"}},"ports":[{"name":"http","port":41773}]}"#,
      r#"{"server":"a","source":{"image":"nginx"},"ports":[{"name":"http","port":80,"host_port":20080},{"name":"admin","port":81}]}"#,
      r#"{"server":"a","source":{"image":"nginx"}}"#,
    ];
    for spec in old {
      c.execute(
        "INSERT INTO resources VALUES ('service', 'x', ?1)",
        [spec],
      )
      .unwrap();
      c.execute("INSERT INTO deployments VALUES (?1)", [spec])
        .unwrap();
    }
    c.execute("INSERT INTO deployments VALUES (NULL)", [])
      .unwrap();
    c.execute_batch(PORTS_MIGRATION).unwrap();
    for table in ["resources", "deployments"] {
      let specs: Vec<Option<String>> = c
        .prepare(&format!("SELECT spec FROM {table} ORDER BY rowid"))
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
      let ports = |i: usize| {
        let v: serde_json::Value =
          serde_json::from_str(specs[i].as_deref().unwrap()).unwrap();
        v["ports"].clone()
      };
      assert_eq!(
        ports(0),
        serde_json::json!([{"name": "http", "host": 41773}])
      );
      assert_eq!(
        ports(1),
        serde_json::json!([
          {"name": "http", "container": 80, "host": 20080},
          {"name": "admin", "container": 81}
        ])
      );
      assert!(ports(2).is_null());
      // 转换后能按新格式读出来。
      for spec in specs.iter().flatten() {
        serde_json::from_str::<wharf_api_types::spec::ServiceSpec>(
          spec,
        )
        .unwrap();
      }
    }
    let plans: i64 = c
      .query_row("SELECT COUNT(*) FROM plans", [], |r| r.get(0))
      .unwrap();
    assert_eq!(plans, 1);
  }

  use super::*;
  use serde_json::json;

  #[tokio::test]
  async fn upsert_bumps_version() {
    let db = Db::memory();
    let w = Write::Upsert {
      kind: "service".into(),
      name: "a".into(),
      spec: json!({"x": 1}),
      meta: json!({}),
    };
    let w2 = w.clone();
    db.call(move |c| {
      apply_write(c, &w)?;
      apply_write(c, &w2)
    })
    .await
    .unwrap();
    let v = db.call(|c| versions(c)).await.unwrap();
    assert_eq!(v["service/a"], 2);
  }
}
