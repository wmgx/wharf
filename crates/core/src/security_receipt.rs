//! 高危操作成功后发回执，正文只包含操作对象和请求来源。

use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  plan::{Action, Layer, PlanItem},
  spec::SsoSpec,
  view::Perm,
};

use crate::{notify::Event, planner::Step, state::AppState};

#[derive(Clone)]
pub(crate) struct Actor {
  pub name: String,
  pub source: String,
}

impl Actor {
  pub fn from_request(request: (&crate::auth::Auth, String)) -> Self {
    let (auth, source) = request;
    Self {
      name: auth.name.clone(),
      source,
    }
  }

  async fn send(&self, state: &AppState, title: String) {
    send(state, &self.name, &self.source, title).await;
  }
}

pub(crate) async fn send(
  state: &AppState,
  actor: &str,
  source: &str,
  title: String,
) {
  crate::rules::notice(
    state,
    "security_receipt",
    None,
    true,
    Event {
      title,
      body: format!("操作者：{actor}\n来源：{source}"),
    },
  )
  .await;
}

pub(crate) async fn token_created(
  state: &AppState,
  actor: &str,
  source: &str,
  name: &str,
  perms: &[Perm],
) {
  if perms.contains(&Perm::Admin) || perms.contains(&Perm::Host) {
    send(state, actor, source, format!("新建高权限令牌 {name}"))
      .await;
  }
}

fn config_title(item: &PlanItem) -> Option<String> {
  if item.layer != Layer::Config {
    return None;
  }
  let after = item.after.as_ref()?;
  let before = item.before.as_ref();
  let (kind, name) = item.address.split_once('/')?;
  match kind {
    "route" if item.action == Action::Update => {
      let gated = |spec: &serde_json::Value| {
        spec.get("sso").is_some_and(|sso| {
          SsoSpec::deserialize(sso).is_ok_and(|sso| sso.gated())
        })
      };
      (before.is_some_and(gated) && !gated(after))
        .then(|| format!("关闭路由 {name} 的门禁"))
    }
    "server" => {
      let enabled = |spec: &serde_json::Value| {
        spec.get("host_exec").and_then(serde_json::Value::as_bool)
          == Some(true)
      };
      (!before.is_some_and(enabled) && enabled(after))
        .then(|| format!("开启服务器 {name} 的宿主机命令执行"))
    }
    _ => None,
  }
}

pub(crate) async fn committed_config(
  state: &AppState,
  actor: Option<&Actor>,
  items: &[PlanItem],
) {
  if let Some(actor) = actor {
    for title in items.iter().filter_map(config_title) {
      actor.send(state, title).await;
    }
  }
}

pub(crate) async fn completed_step(
  state: &AppState,
  actor: Option<&Actor>,
  step: &Step,
  result: &Result<(), ApiError>,
) {
  if let (
    Some(actor),
    Step::ServiceDown {
      server,
      service,
      purge_data: true,
    },
    Ok(()),
  ) = (actor, step, result)
  {
    actor
      .send(
        state,
        format!("删除 {server} 上的服务 {service} 及其数据"),
      )
      .await;
  }
}

#[cfg(test)]
pub(crate) mod tests;
