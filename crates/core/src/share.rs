//! 临时分享：到期后网关自己断开（见 render），这里只负责“哪些已经失效”，给待处理和域名体检用。

use crate::world::World;
use wharf_api_types::view::{Issue, IssueLevel, IssueSubject};

/// 已经失效的分享域名。
pub fn expired(world: &World, now_ms: i64) -> Vec<String> {
  world
    .routes
    .iter()
    .filter(|(_, r)| r.spec.expires_at.is_some_and(|ms| ms <= now_ms))
    .map(|(host, _)| host.clone())
    .collect()
}

/// 每个失效的分享一条待处理。
pub fn issues(world: &World, now_ms: i64) -> Vec<Issue> {
  expired(world, now_ms)
    .into_iter()
    .map(|host| Issue {
      code: "share_expired".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "route".into(),
        name: host.clone(),
      }),
      title: format!("临时分享 {host} 已失效"),
      hint: Some(format!("wharf route rm {host} --apply")),
      ack: None,
      alert: None,
    })
    .collect()
}
