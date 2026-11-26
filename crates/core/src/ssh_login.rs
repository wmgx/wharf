//! 轮询在线 agent，按服务器记住最近 30 天的成功登录来源。

use std::{
  collections::BTreeMap, net::IpAddr, sync::Arc, time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, SshLogin},
};

use crate::{db, notify::Event, state::AppState};

const EVERY: Duration = Duration::from_secs(5 * 60);
const LOOKBACK: TimeDelta = TimeDelta::days(30);

#[derive(Serialize, Deserialize)]
struct History {
  through: DateTime<Utc>,
  seen: BTreeMap<IpAddr, DateTime<Utc>>,
}

impl History {
  fn observe(
    &mut self,
    at: DateTime<Utc>,
    mut logins: Vec<SshLogin>,
  ) -> Vec<SshLogin> {
    if at < self.through {
      return Vec::new();
    }
    let cutoff = at - LOOKBACK;
    logins.sort_by_key(|login| login.at);
    let mut unfamiliar = Vec::new();
    for login in logins {
      if login.at < cutoff || login.at > at {
        continue;
      }
      let Ok(ip) = login.from.parse::<IpAddr>() else {
        continue;
      };
      let ip = ip.to_canonical();
      let last = self.seen.get(&ip).copied();
      if last.is_none_or(|last| login.at > last) {
        self.seen.insert(ip, login.at);
      }
      if login.at > self.through
        && last.is_none_or(|last| login.at - last > LOOKBACK)
      {
        unfamiliar.push(login);
      }
    }
    self.seen.retain(|_, last| *last >= cutoff);
    self.through = at;
    unfamiliar
  }
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut interval = tokio::time::interval(EVERY);
    interval.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      interval.tick().await;
      let servers = state.hub.ssh_login_servers();
      futures_util::future::join_all(servers.into_iter().map(
        |server| {
          let state = state.clone();
          async move {
            match poll(&state, &server).await {
              Ok(logins) if !logins.is_empty() => {
                tokio::spawn(async move {
                  send(&state, &server, logins).await;
                });
              }
              Ok(_) => {}
              Err(e) => tracing::warn!(
                "读取 {server} 的 SSH 登录失败：{}",
                e.message
              ),
            }
          }
        },
      ))
      .await;
    }
  });
}

async fn poll(
  state: &AppState,
  server: &str,
) -> Result<Vec<SshLogin>, ApiError> {
  let (at, logins) = state
    .hub
    .call::<(DateTime<Utc>, Vec<SshLogin>)>(
      server,
      AgentOp::SshLogins,
      Duration::from_secs(60),
      None,
      &CancellationToken::new(),
    )
    .await?;
  save_sample(&state.db, server, at, logins).await
}

async fn save_sample(
  db: &db::Db,
  server: &str,
  at: DateTime<Utc>,
  logins: Vec<SshLogin>,
) -> Result<Vec<SshLogin>, ApiError> {
  let key = format!("ssh_login.history.{server}");
  db.call(move |c| {
    let mut history = db::setting(c, &key)?
      .map(|raw| {
        serde_json::from_str::<History>(&raw).map_err(db::json_err)
      })
      .transpose()?
      .unwrap_or_else(|| History {
        through: at,
        seen: BTreeMap::new(),
      });
    let unfamiliar = history.observe(at, logins);
    let raw =
      serde_json::to_string(&history).map_err(db::json_err)?;
    db::set_setting(c, &key, Some(&raw))?;
    Ok(unfamiliar)
  })
  .await
}

async fn send(state: &AppState, server: &str, logins: Vec<SshLogin>) {
  for login in logins {
    crate::rules::notice(
      state,
      "ssh_login",
      None,
      false,
      event(server, login),
    )
    .await;
  }
}

fn event(server: &str, login: SshLogin) -> Event {
  Event {
    title: format!("{server} 有陌生来源的 SSH 登录"),
    body: format!(
      "服务器：{server}\n用户：{}\n来源：{}\n时间：{}",
      login.user,
      login.from,
      login.at.to_rfc3339(),
    ),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rules::tests::{
    TEST_LOCK, notice_titles, reset_memory, test_state,
  };

  fn login(at: DateTime<Utc>, from: &str) -> SshLogin {
    SshLogin {
      at,
      user: "operator".into(),
      from: from.into(),
      method: "publickey".into(),
    }
  }

  #[tokio::test]
  async fn reports_new_ip_once_per_server_in_rolling_window() {
    let _lock = TEST_LOCK.lock().await;
    reset_memory();
    let state = test_state();
    let at = Utc::now();
    let known = login(at - TimeDelta::hours(1), "203.0.113.1");
    let now = at + TimeDelta::minutes(5);
    save_sample(&state.db, "s1", at, vec![known.clone()])
      .await
      .unwrap();
    save_sample(
      &state.db,
      "s2",
      at,
      vec![login(known.at, "203.0.113.2")],
    )
    .await
    .unwrap();
    let unfamiliar =
      login(now - TimeDelta::seconds(1), "203.0.113.2");
    let familiar = login(now, &known.from);
    let batch = vec![familiar.clone(), unfamiliar.clone(), known];
    let detected = save_sample(&state.db, "s1", now, batch.clone())
      .await
      .unwrap();
    assert_eq!(
      detected.as_slice(),
      std::slice::from_ref(&unfamiliar)
    );
    let message = event("s1", unfamiliar.clone());
    assert_eq!(
      message.body,
      format!(
        "服务器：s1\n用户：operator\n来源：203.0.113.2\n时间：{}",
        unfamiliar.at.to_rfc3339(),
      )
    );
    send(&state, "s1", detected).await;
    assert_eq!(
      notice_titles(&state, "ssh_login").await,
      ["s1 有陌生来源的 SSH 登录"]
    );
    assert!(
      save_sample(&state.db, "s1", now, batch)
        .await
        .unwrap()
        .is_empty()
    );

    let later = now + LOOKBACK + TimeDelta::seconds(1);
    let returns = login(later, &familiar.from);
    assert_eq!(
      save_sample(&state.db, "s1", later, vec![returns.clone()])
        .await
        .unwrap(),
      [returns]
    );
  }

  #[tokio::test]
  async fn first_poll_silently_seeds_history() {
    let db = db::Db::memory();
    let at = Utc::now();
    let known = login(at - TimeDelta::hours(1), "203.0.113.1");
    assert!(
      save_sample(&db, "s1", at, vec![known.clone()])
        .await
        .unwrap()
        .is_empty()
    );
    let later = at + TimeDelta::minutes(5);
    assert!(
      save_sample(&db, "s1", later, vec![login(later, &known.from)])
        .await
        .unwrap()
        .is_empty()
    );
  }
}
