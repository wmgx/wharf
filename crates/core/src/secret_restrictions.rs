//! 密钥允许使用者保存在独立表中，密钥删除时一起清理。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{Connection, params};
use wharf_api_types::{ApiError, validate_name, view::Perm};

use crate::{
  api::{ApiResult, check_secret_name},
  auth::Auth,
  db::{self, sql_err},
  secret_policy,
  state::AppState,
  world::World,
};

pub const MIGRATION: &str = "CREATE TABLE secret_allowed_services (
  secret TEXT NOT NULL REFERENCES secrets(name) ON DELETE CASCADE,
  service TEXT NOT NULL,
  PRIMARY KEY (secret, service)
);";

pub type Restrictions = BTreeMap<String, BTreeSet<String>>;

pub fn load(c: &Connection) -> Result<Restrictions, ApiError> {
  let mut stmt = c
    .prepare("SELECT secret, service FROM secret_allowed_services")
    .map_err(sql_err)?;
  let mut rows = stmt.query([]).map_err(sql_err)?;
  let mut restrictions = Restrictions::new();
  while let Some(row) = rows.next().map_err(sql_err)? {
    restrictions
      .entry(row.get(0).map_err(sql_err)?)
      .or_default()
      .insert(row.get(1).map_err(sql_err)?);
  }
  Ok(restrictions)
}

pub async fn put(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(allowed): Json<Option<BTreeSet<String>>>,
) -> ApiResult<Option<BTreeSet<String>>> {
  auth.require(Perm::Admin)?;
  check_secret_name(&name)?;
  secret_policy::refuse_managed(&name)?;
  secret_policy::reject_system_secret(&name, "服务名单")?;
  if let Some(allowed) = &allowed {
    if allowed.is_empty() {
      return Err(
        ApiError::invalid("服务名单不能为空，请用 --clear 清除")
          .into(),
      );
    }
    for service in allowed {
      validate_name("服务", service)?;
    }
  }
  let allowed = s.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    let exists: bool = tx.query_row(
      "SELECT EXISTS(SELECT 1 FROM secrets WHERE name = ?1)",
      [&name],
      |r| r.get(0),
    ).map_err(sql_err)?;
    if !exists {
      return Err(ApiError::not_found(format!("密钥 {name} 不存在")));
    }
    if let Some(allowed) = &allowed {
      let restrictions = [(name.clone(), allowed.clone())].into();
      let world = World::from_rows(db::all_resources(&tx)?)?;
      secret_policy::validate_restrictions(&world, &restrictions)?;
      for (task, spec, _) in crate::tasks::load_rows(&tx)? {
        secret_policy::validate_task_restrictions(&task, &spec.how, &restrictions)?;
      }
    }
    tx.execute("DELETE FROM secret_allowed_services WHERE secret = ?1", [&name])
      .map_err(sql_err)?;
    for service in allowed.iter().flatten() {
      tx.execute(
        "INSERT INTO secret_allowed_services (secret, service) VALUES (?1, ?2)",
        params![name, service],
      ).map_err(sql_err)?;
    }
    tx.commit().map_err(sql_err)?;
    Ok(allowed)
  }).await?;
  Ok(Json(allowed))
}
