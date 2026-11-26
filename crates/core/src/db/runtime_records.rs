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

pub struct TokenRow {
  pub name: String,
  pub perms: String,
  pub expires_at: Option<i64>,
  pub allowed_from: Option<String>,
  pub services: Option<String>,
}

impl TokenRow {
  pub fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
    Ok(Self {
      name: r.get(0)?,
      perms: r.get(1)?,
      expires_at: r.get(2)?,
      allowed_from: r.get(3)?,
      services: r.get(4)?,
    })
  }
}

pub fn token_scope(
  conn: &Connection,
  hash: &str,
  track_activity: bool,
) -> Result<Option<TokenRow>, ApiError> {
  let found = conn
    .query_row(
      "SELECT name, scope, expires_at, allowed_from, services FROM api_tokens WHERE hash = ?1",
      params![hash],
      TokenRow::read,
    )
    .optional()
    .map_err(sql_err)?;
  if track_activity && let Some(row) = &found {
    conn
      .execute(
        // 每个请求都要过这里；一分钟内用过就不再写，磁盘忙时不拖慢请求。
        "UPDATE api_tokens SET last_used_at = ?1 WHERE name = ?2 \
         AND (last_used_at IS NULL OR last_used_at < ?1 - 60000)",
        params![now_ms(), row.name],
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
      "SELECT service, hash, created_at, images, commit_sha, json_extract(spec, '$.source.build.git.repo') || '#' || json_extract(spec, '$.source.build.git.ref'), spec FROM deployments
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
          // 和 image、image_id 一样只看第一个镜像；取别的镜像的 digest 会把它钉到第一个镜像上。
          digest: images
            .first()
            .and_then(|i| i.digest.as_deref()?.split_once('@'))
            .map(|(_, d)| d.to_string()),
          image: images.first().map(|i| i.image.clone()),
          image_id: images
            .first()
            .map(|i| i.id.clone())
            .filter(|i| !i.is_empty()),
          digests: images
            .iter()
            .filter_map(|i| {
              let (_, d) = i.digest.as_deref()?.split_once('@')?;
              Some((i.image.clone(), d.to_string()))
            })
            .collect(),
          image_ids: images
            .iter()
            .filter(|i| !i.id.is_empty())
            .map(|i| (i.image.clone(), i.id.clone()))
            .collect(),
          commit: r.get(4)?,
          git: r.get(5)?,
          spec: r
            .get::<_, Option<String>>(6)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        },
      ))
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub fn service_notes(
  c: &Connection,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  let mut stmt = c
    .prepare("SELECT service, note FROM service_notes")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

/// 写入或清空（空字符串）服务备注。
pub fn set_service_note(
  c: &Connection,
  service: &str,
  note: &str,
) -> Result<(), ApiError> {
  if note.is_empty() {
    c.execute("DELETE FROM service_notes WHERE service = ?1", params![service])
  } else {
    c.execute(
      "INSERT INTO service_notes (service, note, updated_at) VALUES (?1, ?2, ?3)
       ON CONFLICT (service) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at",
      params![service, note, Utc::now().timestamp_millis()],
    )
  }
  .map_err(sql_err)?;
  Ok(())
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
  fn compose_pins_migration() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
      r#"CREATE TABLE resources (kind TEXT, name TEXT, spec TEXT, meta TEXT);
       CREATE TABLE deployments (id INTEGER PRIMARY KEY, service TEXT, images TEXT);
       CREATE TABLE plans (status TEXT);
       INSERT INTO resources VALUES
         ('service', 'halo', '{"source":{"compose":{"content":"x"}}}', '{}'),
         ('service', 'local', '{"source":{"compose":{"content":"x"}}}', NULL);
       INSERT INTO deployments (service, images) VALUES
         ('halo', '[{"image":"db:8","id":"i","digest":"db@sha256:aa"},{"image":"app:2","id":"j","digest":"app@sha256:bb"},{"image":"wharf-build/x","id":"k"}]'),
         ('local', '[{"image":"wharf-build/x","id":"k"}]');"#,
    )
    .unwrap();
    c.execute_batch(COMPOSE_PINS_MIGRATION).unwrap();
    let meta = |n: &str| -> Option<String> {
      c.query_row(
        "SELECT meta FROM resources WHERE name=?1",
        [n],
        |r| r.get(0),
      )
      .unwrap()
    };
    assert_eq!(
      meta("halo").as_deref(),
      Some(r#"{"pins":{"db:8":"sha256:aa","app:2":"sha256:bb"}}"#)
    );
    assert_eq!(meta("local"), None);
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

  #[tokio::test]
  async fn plan_inputs_ignore_unreferenced_app_account_fields() {
    Db::memory()
      .call_credentials(|c, key| {
        let refs =
          BTreeSet::from(["account.used.username".to_string()]);
        let put = |name, user, pass| {
          key.put_app_account(c, name, user, pass, None, 0)
        };
        put("used", "fixture-user", "old")?;
        put("unused", "fixture-user", "old")?;
        let before = inputs(c, key, Some(&refs))?;
        put("unused", "other-user", "new")?;
        put("used", "fixture-user", "new")?;
        assert_eq!(before, inputs(c, key, Some(&refs))?);
        put("used", "other-user", "new")?;
        assert_ne!(before, inputs(c, key, Some(&refs))?);
        Ok(())
      })
      .await
      .unwrap();
  }

  #[test]
  fn credentials_round_trip_and_reject_tampering() {
    let key = CredentialsKey::new(&[5; 32]);
    let stored =
      key.encrypt("secrets", "example", "fixture-value").unwrap();
    assert_eq!(
      key.decrypt("secrets", "example", &stored).unwrap(),
      "fixture-value"
    );
    let mut raw = STANDARD
      .decode(stored.strip_prefix(ENCRYPTED).unwrap())
      .unwrap();
    *raw.last_mut().unwrap() ^= 1;
    let tampered = format!("{ENCRYPTED}{}", STANDARD.encode(raw));
    assert!(key.decrypt("secrets", "example", &tampered).is_err());
  }

  #[tokio::test]
  async fn credential_migration_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wharf.db");
    let db = Db::open(&path).unwrap();
    db.call(|c| {
      c.execute_batch(
        "INSERT INTO secrets VALUES ('example', 'fixture-secret', 0);
       INSERT INTO app_accounts (name, username, password, updated_at)
       VALUES ('example', 'fixture-user', 'fixture-value', 0);",
      )
      .map_err(sql_err)
    })
    .await
    .unwrap();
    drop(db);
    let read = |c: &mut Connection| {
      c.query_row(
        "SELECT value, password FROM secrets, app_accounts WHERE secrets.name = app_accounts.name",
        [],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
      ).map_err(sql_err)
    };
    let db = Db::open(&path).unwrap();
    let first = db.call(read).await.unwrap();
    assert!(
      first.0.starts_with(ENCRYPTED)
        && first.1.starts_with(ENCRYPTED)
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(db.call(read).await.unwrap(), first);
    db.call_credentials(|c, key| {
      assert_eq!(
        key.secret(c, "example")?.as_deref(),
        Some("fixture-secret")
      );
      assert_eq!(
        key.app_password(c, "example")?.as_deref(),
        Some("fixture-value")
      );
      Ok(())
    })
    .await
    .unwrap();
  }
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
