use super::{
  ApiError, AppState, Auth, Cron, ErrorCode, OptionalExtension,
  RUN_COLS, TaskKind, TaskView, Utc, load, load_one_row, need_perm,
  params, run_view, sql_err, to_time, visible_services,
};

pub(super) async fn build_views(
  s: &AppState,
  auth: &Auth,
  only: Option<&str>,
  reveal: bool,
) -> Result<Vec<TaskView>, crate::api::AppError> {
  let tasks = match only {
    Some(name) => load_one_row(s, name).await?.into_iter().collect(),
    None => load(s).await?,
  };
  let snap = crate::snapshot::load(&s.db).await?;
  let base = reveal
    .then(|| crate::join::default_url_from(s, &snap))
    .flatten();
  let core_server =
    reveal.then(|| crate::join::core_server_of(&snap)).flatten();
  let visible = visible_services(auth)?;
  let mut out = Vec::new();
  let now = Utc::now();
  let offset = s.db.call(|c| crate::config_api::offset(c)).await?;
  for (name, spec, updated) in tasks {
    if let Some(services) = &auth.services
      && !matches!(&spec.how, TaskKind::Exec { service, .. } if services.contains(service))
    {
      continue;
    }
    if reveal {
      need_perm(auth, &spec, &snap.world, core_server.as_deref())
        .map_err(|_| {
          ApiError::new(
            ErrorCode::Forbidden,
            "查看完整触发/报到地址需要对应执行权限",
          )
        })?;
    }
    let n = name.clone();
    let allowed = visible.clone();
    let last = s
      .db
      .call(move |c| {
        c.query_row(
          &format!("SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 AND (?2 IS NULL OR service IN (SELECT value FROM json_each(?2))) ORDER BY id DESC LIMIT 1"),
          params![n, allowed],
          run_view,
        )
        .optional()
        .map_err(sql_err)
      })
      .await?;
    let next_at = spec
      .enabled
      .then(|| {
        Cron::parse(&spec.schedule)
          .ok()?
          .with_offset(offset)
          .next_after(now)
      })
      .flatten();
    let url = |prefix: &str, token: &str| {
      if token.is_empty() {
        return None;
      }
      if reveal {
        base.as_deref().map(|base| {
          format!("{}{prefix}{token}", base.trim_end_matches('/'))
        })
      } else {
        Some(crate::redact::mask_url_token(prefix, token))
      }
    };
    let ping_url = match &spec.how {
      TaskKind::Ping { token, .. } => url("/ping/", token),
      _ => None,
    };
    let hook_url = match &spec.how {
      TaskKind::Script {
        hook: Some(token), ..
      } => url("/hook/", token),
      _ => None,
    };
    let (target_server, migrating) =
      if let TaskKind::Exec { service, .. } = &spec.how {
        let target = super::exec_target(&snap, service).ok();
        (
          target.map(str::to_string),
          target.is_none()
            && snap.pending.migrations.contains_key(service),
        )
      } else {
        (None, false)
      };
    out.push(TaskView {
      target_server,
      migrating,
      data_bytes: None,
      name,
      spec: crate::redact::redact_task_spec(&spec),
      last,
      next_at,
      ping_url,
      hook_url,
      updated_at: to_time(updated),
    });
  }
  Ok(out)
}
