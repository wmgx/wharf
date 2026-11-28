use std::{
  collections::{BTreeMap, BTreeSet},
  path::PathBuf,
  sync::{Arc, Mutex},
};

use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  db::now_ms,
  rules::op_silence::{Target, Windows},
};

#[derive(Default)]
pub struct OpLocks(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
  next: u64,
  silence: Windows,
  held: BTreeMap<u64, (Vec<LockSpec>, String, Option<String>)>,
}

impl State {
  fn check(&self, spec: &LockSpec) -> Result<(), ApiError> {
    if let Some((_, title, run_id)) =
      self.held.values().find(|(held, _, _)| {
        held.iter().any(|held| spec.conflicts(held))
      })
    {
      let error =
        ApiError::new(ErrorCode::Busy, format!("正在执行：{title}"));
      return Err(if let Some(id) = run_id {
        error
          .with_hint(format!("执行记录 {id}"))
          .suggest(format!("wharf run cancel {id}"))
      } else {
        error.with_hint("等当前操作结束后再试")
      });
    }
    Ok(())
  }
}

pub enum LockSpec {
  Global,
  Apply {
    services: BTreeSet<String>,
    block_backups: bool,
    bind_sources: Vec<PathBuf>,
  },
  Backup(String),
  CoreBackup,
  CoreMaintenance,
  BackupTarget(String),
  Cleanup(String),
  CleanupPath(PathBuf),
}

impl LockSpec {
  pub fn apply(services: impl IntoIterator<Item = String>) -> Self {
    Self::Apply {
      services: services.into_iter().collect(),
      block_backups: false,
      bind_sources: vec![],
    }
  }

  fn conflicts(&self, other: &Self) -> bool {
    use LockSpec::*;
    match (self, other) {
      (Global, _) | (_, Global) => true,
      (
        Apply { .. } | CoreMaintenance,
        Apply { .. } | CoreMaintenance,
      ) => true,
      (CoreBackup, CoreBackup | CoreMaintenance)
      | (CoreMaintenance, CoreBackup) => true,
      (Backup(_), Backup(_)) => true,
      (BackupTarget(a), BackupTarget(b)) => a == b,
      (Apply { bind_sources, .. }, CleanupPath(path))
      | (CleanupPath(path), Apply { bind_sources, .. }) => {
        bind_sources.iter().any(|source| {
          source.starts_with(path) || path.starts_with(source)
        })
      }
      (CleanupPath(a), CleanupPath(b)) => {
        a.starts_with(b) || b.starts_with(a)
      }
      (
        Apply {
          block_backups: true,
          ..
        },
        Backup(_) | CoreBackup,
      )
      | (
        Backup(_) | CoreBackup,
        Apply {
          block_backups: true,
          ..
        },
      ) => true,
      (
        Apply { services, .. },
        Backup(service) | Cleanup(service),
      )
      | (
        Backup(service) | Cleanup(service),
        Apply { services, .. },
      ) => services.contains(service),
      (Backup(a) | Cleanup(a), Cleanup(b))
      | (Cleanup(a), Backup(b)) => a == b,
      _ => false,
    }
  }
}

pub struct OpLockGuard {
  state: Arc<Mutex<State>>,
  id: u64,
}

impl OpLocks {
  pub(crate) fn has_alert_windows(&self, now: i64) -> bool {
    self
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .silence
      .any(now)
  }

  pub(crate) fn has_active_service_silence(
    &self,
    service: &str,
  ) -> bool {
    self
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .silence
      .active_service(service)
  }

  pub(crate) fn alert_sample(
    &self,
    targets: &BTreeSet<Target>,
    rule: &str,
    subject: &str,
    healthy: bool,
    now: i64,
  ) -> (bool, Vec<String>) {
    self
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .silence
      .sample(targets, rule, subject, healthy, now)
  }

  pub fn is_service_busy(&self, service: &str) -> bool {
    // 数据清理与持有该服务的操作互斥，复用同一冲突判定。
    let service = LockSpec::Cleanup(service.into());
    self
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .held
      .values()
      .any(|(specs, _, _)| {
        specs.iter().any(|spec| service.conflicts(spec))
      })
  }

  pub fn acquire(
    &self,
    spec: LockSpec,
    title: &str,
  ) -> Result<OpLockGuard, ApiError> {
    let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
    state.check(&spec)?;
    let id = state.next;
    state.next += 1;
    state.held.insert(id, (vec![spec], title.to_string(), None));
    Ok(OpLockGuard {
      state: self.0.clone(),
      id,
    })
  }
}

impl OpLockGuard {
  pub(crate) fn silence_alerts(
    &self,
    targets: BTreeSet<Target>,
    reason: String,
  ) {
    self
      .state
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .silence
      .start(self.id, targets, reason, now_ms());
  }

  pub(crate) fn finish_silence(&self, success: bool) {
    self
      .state
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .silence
      .finish(self.id, success, now_ms());
  }

  pub fn reserve_backup_target(
    &self,
    target: String,
  ) -> Result<(), ApiError> {
    self.reserve(LockSpec::BackupTarget(target))
  }

  pub(crate) fn reserve_cleanup_path(
    &self,
    path: PathBuf,
  ) -> Result<(), ApiError> {
    self.reserve(LockSpec::CleanupPath(path))
  }

  fn reserve(&self, spec: LockSpec) -> Result<(), ApiError> {
    let mut state =
      self.state.lock().unwrap_or_else(|p| p.into_inner());
    state.check(&spec)?;
    state
      .held
      .get_mut(&self.id)
      .expect("任务仍持有锁")
      .0
      .push(spec);
    Ok(())
  }

  pub fn set_run(&self, id: &str) {
    if let Some((_, _, run)) = self
      .state
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .held
      .get_mut(&self.id)
    {
      *run = Some(id.to_string());
    }
  }

  pub fn release_apply(&self, service: &str) {
    if let Some((spec, _, _)) = self
      .state
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .held
      .get_mut(&self.id)
    {
      spec[0] = LockSpec::Cleanup(service.to_string());
    }
  }
}

impl Drop for OpLockGuard {
  fn drop(&mut self) {
    let mut state =
      self.state.lock().unwrap_or_else(|p| p.into_inner());
    state.silence.finish(self.id, false, now_ms());
    state.held.remove(&self.id);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cleanup_path_conflicts_with_new_shared_bind_on_another_service()
  {
    let locks = OpLocks::default();
    let cleanup = locks
      .acquire(LockSpec::Cleanup("app".into()), "清理")
      .unwrap();
    cleanup.reserve_cleanup_path("/srv/app".into()).unwrap();
    let error = locks
      .acquire(
        LockSpec::Apply {
          services: BTreeSet::from(["reader".into()]),
          block_backups: false,
          bind_sources: vec!["/srv/app/shared".into()],
        },
        "部署共享卷消费者",
      )
      .err()
      .unwrap();
    assert_eq!(error.code, ErrorCode::Busy);
    assert!(
      locks
        .acquire(LockSpec::apply(["reader".into()]), "无挂载部署")
        .is_ok()
    );
  }

  #[test]
  fn backup_does_not_block_other_service_apply_or_failover() {
    let locks = OpLocks::default();
    let backup = locks
      .acquire(LockSpec::Backup("s1".into()), "备份 s1")
      .unwrap();
    backup.set_run("r_fixture");
    assert!(
      locks
        .acquire(LockSpec::apply(["s2".into()]), "部署")
        .is_ok()
    );
    assert!(locks.acquire(LockSpec::apply([]), "切换路由").is_ok());
    let err = locks
      .acquire(LockSpec::apply(["s1".into()]), "重启")
      .err()
      .unwrap();
    assert_eq!(err.code, ErrorCode::Busy);
    assert_eq!(err.suggest, ["wharf run cancel r_fixture"]);
    assert!(
      locks.acquire(LockSpec::CoreBackup, "控制面备份").is_ok()
    );
  }
}
