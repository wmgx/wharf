//! SQLite：唯一事实来源。
//!
//! 服务器设置、服务、网关、路由统一存在 `resources` 表，每行有自己的
//! `version`，plan/apply 用它做乐观锁。其他表是运行数据。

use std::{
  collections::BTreeSet,
  fs::{self, OpenOptions},
  io::Write as _,
  os::unix::fs::OpenOptionsExt,
  path::Path,
  sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
  ChaCha20Poly1305, KeyInit, Nonce,
  aead::{Aead, Payload},
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
  // 宿主机终端和命令执行审计；只记命令与统计，不保存终端输入和输出。
  r#"
CREATE TABLE shell_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  server TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('terminal', 'exec')),
  command TEXT,
  exit_code INTEGER,
  duration_ms INTEGER,
  output_bytes INTEGER,
  error TEXT
);
CREATE INDEX shell_log_at_id ON shell_log(at DESC, id DESC);
CREATE INDEX shell_log_server_at_id ON shell_log(server, at DESC, id DESC);
"#,
  // 服务备注：给人看的说明，不影响部署，直接改不走计划。
  r#"
CREATE TABLE service_notes (
  service TEXT PRIMARY KEY,
  note TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
"#,
  // 定时任务（直接改，不走计划）和运行记录，见 tasks.rs。
  r#"
CREATE TABLE tasks (
  name TEXT PRIMARY KEY,
  spec TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE task_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL,
  status TEXT NOT NULL,
  trigger TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  exit_code INTEGER,
  output TEXT NOT NULL DEFAULT ''
);
CREATE INDEX task_runs_task ON task_runs (task, id);
"#,
  // 告警：正在触发的和推送记录（保留 14 天），见 rules.rs。
  r#"
CREATE TABLE alert_firing (
  rule TEXT NOT NULL,
  subject TEXT NOT NULL,
  since INTEGER NOT NULL,
  title TEXT NOT NULL,
  PRIMARY KEY (rule, subject)
);
CREATE TABLE alert_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  source TEXT NOT NULL,
  title TEXT NOT NULL,
  ok INTEGER NOT NULL,
  skipped TEXT
);
CREATE INDEX alert_history_at ON alert_history (at);
"#,
  // 登录保护账号改为按域名：旧的全局账号复制给开了登录保护的域名，然后删掉。
  r#"
INSERT OR IGNORE INTO secrets (name, value, updated_at)
SELECT 'BASIC_AUTH_' || replace(r.name, '.', '_'), s.value, s.updated_at
FROM resources r, secrets s
WHERE r.kind = 'route' AND json_extract(r.spec, '$.auth') = 1 AND s.name = 'BASIC_AUTH';
DELETE FROM secrets WHERE name = 'BASIC_AUTH';
"#,
  r#"
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('api', 'login')),
  actor TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER,
  duration_ms INTEGER,
  detail TEXT,
  source TEXT
);
CREATE INDEX audit_log_actor ON audit_log (actor, id);
CREATE INDEX audit_log_at ON audit_log (at);
"#,
  r#"
ALTER TABLE alert_history ADD COLUMN subject TEXT;
"#,
  "ALTER TABLE task_runs ADD COLUMN mem_peak INTEGER;",
  "ALTER TABLE admin ADD COLUMN totp_secret TEXT;
   ALTER TABLE admin ADD COLUMN totp_pending TEXT;
   ALTER TABLE admin ADD COLUMN totp_last_step INTEGER;
   CREATE TABLE recovery_codes (hash TEXT PRIMARY KEY, used_at INTEGER);",
  "ALTER TABLE sessions ADD COLUMN source TEXT;
   ALTER TABLE sessions ADD COLUMN last_seen_at INTEGER;",
  "CREATE TABLE gate_keys (
    name TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    hosts TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  );",

  COMPOSE_PINS_MIGRATION,
  "CREATE TABLE app_accounts (
    name TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE app_account_domains (
    account TEXT NOT NULL REFERENCES app_accounts(name),
    hostname TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, hostname)
  );
  CREATE UNIQUE INDEX app_account_default ON app_account_domains (hostname) WHERE is_default = 1;",
  "CREATE TABLE notify_keys (
    name TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  );",
  "ALTER TABLE api_tokens ADD COLUMN expires_at INTEGER;
   ALTER TABLE api_tokens ADD COLUMN allowed_from TEXT;
   ALTER TABLE api_tokens ADD COLUMN services TEXT;",
  "CREATE TABLE resource_notes (
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    note TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (kind, name),
    FOREIGN KEY (kind, name) REFERENCES resources(kind, name) ON DELETE CASCADE
  );",
  crate::service_monitor::heartbeat::MIGRATION,
  crate::service_monitor::unmanaged::MIGRATION,
  crate::rules::MIGRATION,
  crate::rules::CUSTOM_MIGRATION,
  crate::host_access::MIGRATION,
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

/// compose 来源固定到上次部署实际用的各个镜像 digest，和 image 来源一样，升级后不用再执行一次“固定镜像版本”。
const COMPOSE_PINS_MIGRATION: &str = r#"
UPDATE resources
SET meta = json_set(COALESCE(meta, '{}'), '$.pins', (
  SELECT json_group_object(json_extract(j.value, '$.image'),
    substr(json_extract(j.value, '$.digest'), instr(json_extract(j.value, '$.digest'), '@') + 1))
  FROM json_each((SELECT d.images FROM deployments d
    WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1)) j
  WHERE json_extract(j.value, '$.digest') LIKE '%@sha256:%'))
WHERE kind = 'service' AND json_type(spec, '$.source.compose') = 'object'
  AND json_extract(COALESCE(meta, '{}'), '$.pins') IS NULL
  AND EXISTS (SELECT 1 FROM json_each((SELECT d.images FROM deployments d
    WHERE d.service = resources.name ORDER BY d.id DESC LIMIT 1)) j
    WHERE json_extract(j.value, '$.digest') LIKE '%@sha256:%');
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
/// 键以 `prefix` 开头的设置，返回时去掉前缀。
pub fn settings_with_prefix(
  c: &Connection,
  prefix: &str,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT key, value FROM settings WHERE substr(key, 1, length(?1)) = ?1",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![prefix], |r| {
      let key: String = r.get(0)?;
      Ok((key[prefix.len()..].to_string(), r.get(1)?))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

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
  credentials: Arc<CredentialsKey>,
}

impl Db {
  pub fn open(path: &Path) -> anyhow::Result<Self> {
    let conn = Connection::open(path)?;
    Self::init(conn, Some(&path.with_file_name(CREDENTIALS_KEY_FILE)))
  }

  #[cfg(test)]
  pub fn memory() -> Self {
    Self::init(Connection::open_in_memory().unwrap(), None).unwrap()
  }

  fn init(
    mut conn: Connection,
    key_path: Option<&Path>,
  ) -> anyhow::Result<Self> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let current: usize =
      conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
      let tx = conn.transaction()?;
      tx.execute_batch(sql)?;
      tx.pragma_update(None, "user_version", i + 1)?;
      tx.commit()?;
    }
    let credentials = match key_path {
      Some(path) => CredentialsKey::load(&conn, path)?,
      None => CredentialsKey::new(&[0; 32]),
    };
    if credentials
      .migrate(&mut conn)
      .map_err(|e| anyhow::anyhow!(e.message))?
    {
      conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    }
    Ok(Self {
      conn: Arc::new(Mutex::new(conn)),
      credentials: Arc::new(credentials),
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

  pub async fn call_credentials<R, F>(
    &self,
    f: F,
  ) -> Result<R, ApiError>
  where
    R: Send + 'static,
    F: FnOnce(&mut Connection, &CredentialsKey) -> Result<R, ApiError>
      + Send
      + 'static,
  {
    let key = self.credentials.clone();
    self.call(move |c| f(c, &key)).await
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

include!("db/resources_and_secrets.rs");
include!("db/runtime_records.rs");
