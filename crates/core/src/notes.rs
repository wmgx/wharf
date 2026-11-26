//! 备注独立于部署配置，保存后立即生效。

use std::{collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::{Value, json};
use wharf_api_types::{ApiError, view::Perm};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms, sql_err},
  state::AppState,
  world::{KIND_ROUTE, KIND_SERVER, KIND_SERVICE, server_not_found},
};

// 私密内容在浏览器里加密后以 base64 存进来，比原文长不少。
const NOTE_LIMIT: usize = 20000;

#[derive(Deserialize)]
pub struct NoteRequest {
  note: String,
}

pub fn resource_notes(
  c: &Connection,
  kind: &str,
) -> Result<BTreeMap<String, String>, ApiError> {
  let mut stmt = c
    .prepare("SELECT name, note FROM resource_notes WHERE kind = ?1")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([kind], |r| Ok((r.get(0)?, r.get(1)?)))
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

pub async fn service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<NoteRequest>,
) -> ApiResult<Value> {
  save(s, auth, KIND_SERVICE, name, req).await
}

pub async fn server(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<NoteRequest>,
) -> ApiResult<Value> {
  save(s, auth, KIND_SERVER, name, req).await
}

pub async fn route(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(host): Path<String>,
  Json(req): Json<NoteRequest>,
) -> ApiResult<Value> {
  let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
  if auth.services.is_some() {
    let snap = crate::snapshot::load(&s.db).await?;
    crate::token_scope::require_route_by_host(
      &auth,
      &snap.world,
      &host,
    )?;
  }
  save(s, auth, KIND_ROUTE, host, req).await
}

async fn save(
  s: Arc<AppState>,
  auth: Auth,
  kind: &'static str,
  name: String,
  req: NoteRequest,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  let note = req.note.trim().to_string();
  if note.chars().count() > NOTE_LIMIT {
    return Err(
      ApiError::invalid(format!("备注最多 {NOTE_LIMIT} 个字")).into(),
    );
  }
  s.db.call(move |c| {
    let exists: bool = c.query_row(
      "SELECT EXISTS(SELECT 1 FROM resources WHERE kind = ?1 AND name = ?2)",
      params![kind, name], |r| r.get(0),
    ).map_err(sql_err)?;
    if !exists {
      return Err(match kind {
        KIND_SERVER => server_not_found(&name),
        KIND_SERVICE => crate::api::service_not_found(&name),
        _ => ApiError::not_found(format!("域名 {name} 不存在")).with_hint("用 wharf route list 查看现有域名"),
      });
    }
    if kind == KIND_SERVICE {
      return db::set_service_note(c, &name, &note);
    }
    if note.is_empty() {
      c.execute("DELETE FROM resource_notes WHERE kind = ?1 AND name = ?2", params![kind, name])
    } else {
      c.execute(
        "INSERT INTO resource_notes (kind, name, note, updated_at) VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(kind, name) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at",
        params![kind, name, note, now_ms()],
      )
    }.map_err(sql_err)?;
    Ok(())
  }).await?;
  Ok(Json(json!({ "ok": true })))
}
