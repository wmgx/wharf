use super::{
  ApiError, AppState, Auth, Cron, ErrorCode, OptionalExtension,
  RUN_COLS, TaskKind, TaskView, Utc, load, need_perm, params,
  run_view, sql_err, to_time,
};

pub(super) async fn build_views(
  s: &AppState,
  auth: &Auth,
  only: Option<&str>,
  reveal: bool,
) -> Result<Vec<TaskView>, crate::api::AppError> {
  let tasks = load(s).await?;
  let base = if reveal {
    crate::join::default_url(s).await
  } else {
    None
  };
  let mut out = Vec::new();
  let now = Utc::now();
  for (name, spec, updated) in tasks {
    if only.is_some_and(|only| only != name.as_str()) {
      continue;
    }
    if let Some(services) = &auth.services
      && !matches!(&spec.how, TaskKind::Exec { service, .. } if services.contains(service))
    {
      continue;
    }
    if reveal {
      need_perm(auth, &spec).map_err(|_| {
        ApiError::new(
          ErrorCode::Forbidden,
          "查看完整触发/报到地址需要对应执行权限",
        )
      })?;
    }
    let n = name.clone();
    let last = s
      .db
      .call(move |c| {
        c.query_row(
          &format!("SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT 1"),
          params![n],
          run_view,
        )
        .optional()
        .map_err(sql_err)
      })
      .await?;
    let next_at = spec
      .enabled
      .then(|| Cron::parse(&spec.schedule).ok()?.next_after(now))
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
    out.push(TaskView {
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
