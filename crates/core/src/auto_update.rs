//! 自动更新复用普通的计划和执行，只执行指定服务的安全计划。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::{DateTime, FixedOffset, NaiveDate, Timelike, Utc};
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{ApplyRequest, Plan, PlanRequest, RunStatus},
  spec::Change,
  view::{AutoUpdateResult, Issue, IssueLevel, IssueSubject, Perm},
};

use crate::{apply, db, planner, snapshot, state::AppState, updates};

static RUN: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());
static DAY: Mutex<Option<NaiveDate>> = Mutex::new(None);
static FAILED: Mutex<BTreeMap<String, String>> =
  Mutex::new(BTreeMap::new());

fn in_window(now: DateTime<Utc>) -> bool {
  let hour = now
    .with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap())
    .hour();
  (3..6).contains(&hour)
}

fn safe_plan(plan: &Plan, name: &str) -> Result<(), String> {
  if plan.items.is_empty() {
    return Err("没有要更新的内容".into());
  }
  let address = format!("service/{name}");
  let other: BTreeSet<&str> = plan
    .items
    .iter()
    .filter(|i| i.address != address)
    .map(|i| i.address.as_str())
    .collect();
  if !other.is_empty() {
    return Err(format!(
      "还有别的改动没执行：{}",
      other.into_iter().collect::<Vec<_>>().join("、")
    ));
  }
  if !plan.needs_confirm.is_empty() {
    return Err("计划里有要确认的高风险项".into());
  }
  Ok(())
}

pub async fn tick(state: &Arc<AppState>) {
  let now = Utc::now();
  if !in_window(now) {
    return;
  }
  let today = now
    .with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap())
    .date_naive();
  {
    let mut day = DAY.lock().unwrap();
    if *day == Some(today) {
      return;
    }
    *day = Some(today);
  }
  run(state).await;
}

pub async fn run(state: &Arc<AppState>) -> Vec<AutoUpdateResult> {
  let Ok(_guard) = RUN.try_lock() else {
    return vec![];
  };
  updates::versions(state).await;
  let snap = match snapshot::load(&state.db).await {
    Ok(snap) => snap,
    Err(e) => {
      tracing::warn!("自动更新：读配置失败：{e}");
      return vec![];
    }
  };
  let names: BTreeSet<String> = snap
    .world
    .services
    .iter()
    .filter(|(_, row)| row.spec.auto_update && !row.spec.stopped)
    .map(|(name, _)| name.clone())
    .collect();
  FAILED
    .lock()
    .unwrap()
    .retain(|name, _| names.contains(name));
  let checks = updates::last().unwrap_or_default().services;
  let mut results = Vec::new();
  for name in names {
    let Some(check) = checks.get(&name) else {
      continue;
    };
    let Some(latest) = check.latest.clone() else {
      continue;
    };
    let key = format!("autoupdate.failed.{name}");
    let previous = state
      .db
      .call({
        let key = key.clone();
        let latest = latest.clone();
        move |c| {
          let previous = db::setting(c, &key)?;
          if previous.as_ref().is_some_and(|p| p != &latest) {
            db::set_setting(c, &key, None)?;
          }
          Ok(previous)
        }
      })
      .await;
    let result = match previous {
      Ok(Some(previous)) if previous == latest => Ok((
        "skipped",
        Some("这个版本上次自动更新失败过，等下一个版本".into()),
      )),
      Ok(_) if !check.newer => continue,
      Ok(_) => execute(state, &name).await,
      Err(e) => Err(e),
    };
    let (status, reason) = match result {
      Ok(result) => result,
      Err(e) => ("failed", Some(e.message)),
    };
    if status == "skipped" {
      tracing::info!(service = name, ?reason, "跳过自动更新");
    } else {
      let ok = status == "updated";
      crate::metrics::event(
        state,
        if ok {
          "autoupdate.ok"
        } else {
          "autoupdate.fail"
        },
        &name,
        1.0,
      )
      .await;
      let value = (!ok).then(|| latest.clone());
      if let Err(e) = state
        .db
        .call(move |c| db::set_setting(c, &key, value.as_deref()))
        .await
      {
        tracing::warn!("保存自动更新结果失败：{e}");
      }
      {
        let mut failed = FAILED.lock().unwrap();
        if ok {
          failed.remove(&name);
        } else {
          failed
            .insert(name.clone(), reason.clone().unwrap_or_default());
        }
      }
      let short: String = latest
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect();
      let event = if ok {
        crate::notify::Event {
          title: format!("服务 {name} 已自动更新"),
          body: format!(
            "更新到 {short}。看这次部署：wharf service history {name}"
          ),
        }
      } else {
        crate::notify::Event {
          title: format!("服务 {name} 自动更新失败，还在运行旧版本"),
          body: format!(
            "{}。这个版本不会再自动重试，等下一个版本；修好后手动更新：wharf plan --apply",
            reason.as_deref().unwrap_or_default()
          ),
        }
      };
      crate::rules::notice(state, "auto_update", None, ok, event)
        .await;
    }
    results.push(AutoUpdateResult {
      service: name,
      status: status.into(),
      latest: Some(latest),
      reason,
    });
  }
  results
}

async fn execute(
  state: &Arc<AppState>,
  name: &str,
) -> Result<(&'static str, Option<String>), ApiError> {
  let planned = planner::make_plan(
    state,
    PlanRequest {
      changes: vec![Change::RefreshImages { name: name.into() }],
      fleet: None,
    },
  )
  .await?;
  if let Err(reason) = safe_plan(&planned.plan, name) {
    return Ok(("skipped", Some(reason)));
  }
  planner::save(state, &planned).await?;
  let mut retries = 0;
  let run = loop {
    match apply::start(
      state.clone(),
      ApplyRequest {
        plan_id: planned.plan.plan_id.clone(),
        confirm: vec![],
      },
      BTreeSet::from([Perm::Read, Perm::Plan, Perm::Apply]),
    )
    .await
    {
      Ok(run) => break run,
      Err(e) if e.code == ErrorCode::Busy => {
        if retries == 10 {
          return Ok((
            "skipped",
            Some("一直有别的操作在执行".into()),
          ));
        }
        retries += 1;
        tokio::time::sleep(Duration::from_secs(60)).await;
      }
      Err(e) => return Err(e),
    }
  };
  let deadline =
    tokio::time::Instant::now() + Duration::from_secs(80 * 60);
  loop {
    let run = apply::load_run(state, &run.run_id).await?;
    if run.status == RunStatus::Succeeded {
      return Ok(("updated", None));
    }
    if run.status != RunStatus::Running {
      let reason = run
        .steps
        .iter()
        .find_map(|step| {
          step.error.as_ref().map(|e| e.message.clone())
        })
        .unwrap_or_else(|| "执行被取消".into());
      return Ok(("failed", Some(reason)));
    }
    if tokio::time::Instant::now() >= deadline {
      return Ok(("failed", Some("执行超过 80 分钟没有结束".into())));
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
  }
}

pub fn issues() -> Vec<Issue> {
  FAILED
    .lock()
    .unwrap()
    .keys()
    .map(|name| Issue {
      code: "auto_update_failed".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "service".into(),
        name: name.clone(),
      }),
      title: format!("服务 {name} 自动更新失败，还在运行旧版本"),
      hint: None,
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn beijing_update_window() {
    for (time, expected) in [
      ("2026-11-14T18:59:00Z", false),
      ("2026-11-14T19:00:00Z", true),
      ("2026-11-14T21:59:00Z", true),
      ("2026-11-14T22:00:00Z", false),
    ] {
      assert_eq!(in_window(time.parse().unwrap()), expected);
    }
  }

  #[test]
  fn plan_only_updates_one_service() {
    let mut plan: Plan = serde_json::from_value(serde_json::json!({
      "plan_id": "p1", "status": "pending",
      "created_at": "2026-11-14T19:00:00Z",
      "expires_at": "2026-11-14T20:00:00Z",
      "base_versions": {}, "items": [
        {"id": 1, "address": "service/app", "layer": "config", "action": "update", "reason": "修改配置"},
        {"id": 2, "address": "service/app", "layer": "container", "action": "update", "reason": "更新镜像版本"}
      ]
    })).unwrap();
    assert!(safe_plan(&plan, "app").is_ok());
    plan.items[1].address = "gateway/edge".into();
    assert_eq!(
      safe_plan(&plan, "app").unwrap_err(),
      "还有别的改动没执行：gateway/edge"
    );
  }
}
