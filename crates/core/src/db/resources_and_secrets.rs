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
      if kind == crate::world::KIND_SERVICE {
        crate::rules::delete_service_rows(conn, name)?;
      }
      if kind == crate::world::KIND_GATEWAY {
        delete_scoped_secrets(conn, crate::link::GATEWAY_SECRET_PREFIXES, name)?;
      }
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

pub const CREDENTIALS_KEY_FILE: &str = "secrets.key";
const ENCRYPTED: &str = "enc:v1:";
const CREDENTIAL_COLUMNS: [(&str, &str); 2] =
  [("secrets", "value"), ("app_accounts", "password")];

pub struct CredentialsKey(ChaCha20Poly1305);

impl CredentialsKey {
  fn new(bytes: &[u8; 32]) -> Self {
    Self(ChaCha20Poly1305::new(bytes.into()))
  }

  fn load(conn: &Connection, path: &Path) -> anyhow::Result<Self> {
    use anyhow::Context;
    let read = fs::read(path);
    if let Ok(bytes) = &read
      && let Ok(bytes) = <&[u8; 32]>::try_from(bytes.as_slice())
    {
      return Ok(Self::new(bytes));
    }
    let missing = read
      .as_ref()
      .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    if !missing && let Err(e) = read {
      return Err(e)
        .with_context(|| format!("读取主密钥 {}", path.display()));
    }
    for (table, column) in CREDENTIAL_COLUMNS {
      let name: Option<String> = conn.query_row(
        &format!("SELECT name FROM {table} WHERE instr({column}, ?1) = 1 LIMIT 1"),
        [ENCRYPTED],
        |r| r.get(0),
      ).optional()?;
      if let Some(name) = name {
        anyhow::bail!("{}", Self::decrypt_error(&name).message);
      }
    }
    anyhow::ensure!(
      missing,
      "主密钥文件长度不对：{}",
      path.display()
    );
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
      .map_err(|_| anyhow::anyhow!("随机数不可用"))?;
    let mut file = OpenOptions::new()
      .create_new(true)
      .write(true)
      .mode(0o600)
      .open(path)
      .with_context(|| format!("创建主密钥 {}", path.display()))?;
    if let Err(e) =
      file.write_all(&bytes).and_then(|()| file.sync_all())
    {
      let _ = fs::remove_file(path);
      return Err(e)
        .with_context(|| format!("写入主密钥 {}", path.display()));
    }
    Ok(Self::new(&bytes))
  }

  fn decrypt_error(name: &str) -> ApiError {
    ApiError::internal(format!("主密钥不匹配，无法解密密钥 {name}"))
  }

  fn encrypt(
    &self,
    table: &str,
    name: &str,
    value: &str,
  ) -> Result<String, ApiError> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce)
      .map_err(|_| ApiError::internal("随机数不可用"))?;
    let aad = format!("{table}:{name}");
    let ciphertext = self
      .0
      .encrypt(
        Nonce::from_slice(&nonce),
        Payload {
          msg: value.as_bytes(),
          aad: aad.as_bytes(),
        },
      )
      .map_err(|_| {
        ApiError::internal(format!("无法加密密钥 {name}"))
      })?;
    let mut record = nonce.to_vec();
    record.extend(ciphertext);
    Ok(format!("{ENCRYPTED}{}", STANDARD.encode(record)))
  }

  fn decrypt(
    &self,
    table: &str,
    name: &str,
    value: &str,
  ) -> Result<String, ApiError> {
    let err = || Self::decrypt_error(name);
    let bytes = STANDARD
      .decode(value.strip_prefix(ENCRYPTED).ok_or_else(err)?)
      .map_err(|_| err())?;
    let (nonce, ciphertext) =
      bytes.split_at_checked(12).ok_or_else(err)?;
    let aad = format!("{table}:{name}");
    let plaintext = self
      .0
      .decrypt(
        Nonce::from_slice(nonce),
        Payload {
          msg: ciphertext,
          aad: aad.as_bytes(),
        },
      )
      .map_err(|_| err())?;
    String::from_utf8(plaintext).map_err(|_| err())
  }

  fn migrate(&self, conn: &mut Connection) -> Result<bool, ApiError> {
    let tx = conn.transaction().map_err(sql_err)?;
    let mut changed = false;
    for (table, column) in CREDENTIAL_COLUMNS {
      let mut read = tx
        .prepare(&format!("SELECT name, {column} FROM {table}"))
        .map_err(sql_err)?;
      let rows = read
        .query_map([], |row| {
          Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_err)?;
      let mut write = tx
        .prepare(&format!(
          "UPDATE {table} SET {column} = ?2 WHERE name = ?1"
        ))
        .map_err(sql_err)?;
      for (name, value) in rows {
        if value.starts_with(ENCRYPTED) {
          self.decrypt(table, &name, &value)?;
        } else {
          write
            .execute(params![
              name,
              self.encrypt(table, &name, &value)?
            ])
            .map_err(sql_err)?;
          changed = true;
        }
      }
    }
    tx.commit().map_err(sql_err)?;
    Ok(changed)
  }

  pub fn secret(
    &self,
    conn: &Connection,
    name: &str,
  ) -> Result<Option<String>, ApiError> {
    let value: Option<String> = conn
      .query_row(
        "SELECT value FROM secrets WHERE name = ?1",
        [name],
        |r| r.get(0),
      )
      .optional()
      .map_err(sql_err)?;
    value
      .map(|value| self.decrypt("secrets", name, &value))
      .transpose()
  }

  pub fn put_secret(
    &self,
    conn: &Connection,
    name: &str,
    value: &str,
    now: i64,
    replace: bool,
  ) -> Result<(), ApiError> {
    let value = self.encrypt("secrets", name, value)?;
    conn.execute(
      "INSERT INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)
       ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at WHERE ?4",
      params![name, value, now, replace],
    ).map_err(sql_err)?;
    Ok(())
  }

  pub fn app_password(
    &self,
    conn: &Connection,
    name: &str,
  ) -> Result<Option<String>, ApiError> {
    let value: Option<String> = conn
      .query_row(
        "SELECT password FROM app_accounts WHERE name = ?1",
        [name],
        |r| r.get(0),
      )
      .optional()
      .map_err(sql_err)?;
    value
      .map(|value| self.decrypt("app_accounts", name, &value))
      .transpose()
  }

  pub fn put_app_account(
    &self,
    conn: &Connection,
    name: &str,
    username: &str,
    password: &str,
    note: Option<&str>,
    now: i64,
  ) -> Result<(), ApiError> {
    let password = self.encrypt("app_accounts", name, password)?;
    conn.execute(
      "INSERT INTO app_accounts (name, username, password, note, updated_at) VALUES (?1, ?2, ?3, COALESCE(?4, ''), ?5)
       ON CONFLICT (name) DO UPDATE SET username = excluded.username, password = excluded.password,
       note = COALESCE(?4, app_accounts.note), updated_at = excluded.updated_at",
      params![name, username, password, note, now],
    ).map_err(sql_err)?;
    Ok(())
  }
}

pub fn secrets(
  conn: &Connection,
  key: &CredentialsKey,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  let mut stmt = conn
    .prepare("SELECT name, value FROM secrets")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })
    .map_err(sql_err)?;
  rows
    .map(|row| {
      let (name, value) = row.map_err(sql_err)?;
      let value = key.decrypt("secrets", &name, &value)?;
      Ok((name, value))
    })
    .collect()
}

pub fn service_values(
  conn: &Connection,
  key: &CredentialsKey,
  mut values: std::collections::BTreeMap<String, String>,
  account_refs: Option<&BTreeSet<String>>,
) -> Result<std::collections::BTreeMap<String, String>, ApiError> {
  if account_refs.is_some_and(BTreeSet::is_empty) {
    return Ok(values);
  }
  let mut stmt = conn
    .prepare("SELECT name, username, password FROM app_accounts")
    .map_err(sql_err)?;
  let mut rows = stmt.query([]).map_err(sql_err)?;
  while let Some(row) = rows.next().map_err(sql_err)? {
    let name: String = row.get(0).map_err(sql_err)?;
    let username = format!("account.{name}.username");
    if account_refs.is_none_or(|refs| refs.contains(&username)) {
      values.insert(username, row.get(1).map_err(sql_err)?);
    }
    let password = format!("account.{name}.password");
    if account_refs.is_none_or(|refs| refs.contains(&password)) {
      values.insert(
        password,
        key.decrypt(
          "app_accounts",
          &name,
          &row.get::<_, String>(2).map_err(sql_err)?,
        )?,
      );
    }
  }
  Ok(values)
}

/// 计划依赖、又不在资源版本里的输入的指纹：连通性结果、密钥、渲染要用的机器地址。
pub fn inputs_fingerprint(
  reach: &Reach,
  secrets: &std::collections::BTreeMap<String, String>,
  addresses: &crate::render::Addresses,
) -> String {
  let reach: Vec<_> = reach.iter().collect();
  crate::render::hash(
    &serde_json::json!({
      "reach": reach,
      "secrets": secrets,
      "addresses": addresses,
    })
    .to_string(),
  )
}

pub fn inputs(
  conn: &Connection,
  key: &CredentialsKey,
  account_refs: Option<&BTreeSet<String>>,
) -> Result<String, ApiError> {
  let world = crate::world::World::from_rows(all_resources(conn)?)?;
  let net =
    crate::render::Net::derive(&world.servers, &agents(conn)?);
  Ok(inputs_fingerprint(
    &reach(conn)?,
    &service_values(
      conn,
      key,
      crate::oidc::with_client_secrets(&world, &secrets(conn, key)?),
      account_refs,
    )?,
    &net.addresses(),
  ))
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
  key: &CredentialsKey,
  name: &str,
  now: i64,
) -> Result<String, ApiError> {
  ensure_secret_with(conn, key, name, now, random_secret)
}

fn random_secret() -> Result<String, ApiError> {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  Ok(hex::encode(bytes))
}

fn ensure_secret_with(
  conn: &Connection,
  key: &CredentialsKey,
  name: &str,
  now: i64,
  generate: impl FnOnce() -> Result<String, ApiError>,
) -> Result<String, ApiError> {
  if let Some(value) = key.secret(conn, name)? {
    return Ok(value);
  }
  key.put_secret(conn, name, &generate()?, now, false)?;
  key
    .secret(conn, name)?
    .ok_or_else(|| ApiError::internal("密钥写入后不存在"))
}

pub fn scoped_secret_name(
  prefix: &str,
  entity: &str,
) -> Result<String, ApiError> {
  if !prefix.starts_with("WHARF_") || !prefix.ends_with('_') {
    return Err(ApiError::invalid(
      "实体密钥前缀必须以 WHARF_ 开头并以下划线结尾",
    ));
  }
  wharf_api_types::validate_name("密钥所属实体", entity)?;
  Ok(format!("{prefix}{entity}"))
}

pub fn ensure_scoped_secret(
  conn: &Connection,
  key: &CredentialsKey,
  prefix: &str,
  entity: &str,
  now: i64,
) -> Result<String, ApiError> {
  ensure_scoped_secret_with(
    conn,
    key,
    prefix,
    entity,
    now,
    random_secret,
  )
}

pub fn ensure_scoped_secret_with(
  conn: &Connection,
  key: &CredentialsKey,
  prefix: &str,
  entity: &str,
  now: i64,
  generate: impl FnOnce() -> Result<String, ApiError>,
) -> Result<String, ApiError> {
  let name = scoped_secret_name(prefix, entity)?;
  ensure_secret_with(conn, key, &name, now, generate)
}

pub fn rotate_scoped_secret(
  conn: &Connection,
  key: &CredentialsKey,
  prefix: &str,
  entity: &str,
  now: i64,
) -> Result<String, ApiError> {
  let name = scoped_secret_name(prefix, entity)?;
  let value = random_secret()?;
  key.put_secret(conn, &name, &value, now, true)?;
  Ok(value)
}

pub fn delete_scoped_secrets(
  conn: &Connection,
  prefixes: &[&str],
  entity: &str,
) -> Result<usize, ApiError> {
  prefixes.iter().try_fold(0, |count, prefix| {
    let name = scoped_secret_name(prefix, entity)?;
    let deleted = conn
      .execute("DELETE FROM secrets WHERE name = ?1", [name])
      .map_err(sql_err)?;
    Ok(count + deleted)
  })
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
