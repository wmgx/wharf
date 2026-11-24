use std::{sync::Arc, time::Duration};

use rusqlite::{Connection, params};
use wharf_api_types::{
  ApiError,
  view::{Issue, IssueLevel, IssueSubject, Unmanaged},
};

use crate::{
  db::{now_ms, sql_err},
  import_api,
  notify::Event,
  state::AppState,
};

const EVERY: Duration = Duration::from_secs(600);
const HOUR: i64 = 3_600_000;

pub const MIGRATION: &str = "
CREATE TABLE unmanaged_baseline (server TEXT PRIMARY KEY);
CREATE TABLE unmanaged_seen (
  server TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  missing_since INTEGER, pushed INTEGER NOT NULL DEFAULT 0,
  ignored INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server, kind, name)
);
";

pub fn target(item: &Unmanaged) -> (&'static str, &str) {
  if let Some(project) = &item.project {
    ("project", project)
  } else {
    ("container", item.container.as_deref().unwrap_or_default())
  }
}

pub async fn flags(
  state: &AppState,
  server: &str,
  out: &mut [Unmanaged],
) -> Result<(), ApiError> {
  let server = server.to_string();
  let flags = state.db.call(move |c| {
    let mut stmt = c.prepare("SELECT kind, name FROM unmanaged_seen WHERE server=?1 AND ignored").map_err(sql_err)?;
    stmt.query_map([server], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
      .and_then(Iterator::collect::<Result<std::collections::BTreeSet<_>, _>>)
      .map_err(sql_err)
  }).await?;
  for item in out {
    let (kind, name) = target(item);
    item.ignored = flags.contains(&(kind.into(), name.into()));
  }
  Ok(())
}

pub async fn set_ignored(
  state: &AppState,
  server: String,
  kind: &'static str,
  name: String,
  undo: bool,
) -> Result<(), ApiError> {
  state.db.call(move |c| {
    c.execute("INSERT INTO unmanaged_seen(server, kind, name, first_seen, ignored)
      VALUES(?1,?2,?3,?4,?5) ON CONFLICT(server,kind,name) DO UPDATE SET ignored=excluded.ignored",
      params![server, kind, name, now_ms(), !undo]).map_err(sql_err)?;
    Ok(())
  }).await
}

fn scan(
  c: &mut Connection,
  server: &str,
  found: &[Unmanaged],
  now: i64,
) -> Result<Vec<Seen>, ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let baseline = tx
    .execute(
      "INSERT OR IGNORE INTO unmanaged_baseline(server) VALUES(?1)",
      [server],
    )
    .map_err(sql_err)?
    == 1;
  tx.execute(
    "UPDATE unmanaged_seen SET missing_since=COALESCE(missing_since, ?2) WHERE server=?1",
    params![server, now],
  )
  .map_err(sql_err)?;
  tx.execute(
    "DELETE FROM unmanaged_seen WHERE server=?1 AND missing_since < ?2",
    params![server, now - 24 * HOUR],
  )
  .map_err(sql_err)?;
  for item in found {
    let (kind, name) = target(item);
    tx.execute("INSERT INTO unmanaged_seen(server,kind,name,first_seen,pushed)
      VALUES(?1,?2,?3,?4,?5)
      ON CONFLICT(server,kind,name) DO UPDATE SET missing_since=NULL,pushed=MAX(pushed,excluded.pushed)",
      params![server, kind, name, now, baseline]).map_err(sql_err)?;
  }
  let due = {
    let mut stmt = tx.prepare("UPDATE unmanaged_seen SET pushed=1
      WHERE server=?1 AND missing_since IS NULL AND NOT pushed AND NOT ignored AND first_seen <= ?2
      RETURNING server,kind,name,first_seen").map_err(sql_err)?;
    stmt
      .query_map(params![server, now - HOUR], Seen::read)
      .and_then(Iterator::collect)
      .map_err(sql_err)?
  };
  tx.commit().map_err(sql_err)?;
  Ok(due)
}

struct Seen {
  server: String,
  kind: String,
  name: String,
  first_seen: i64,
}

impl Seen {
  fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
    Ok(Self {
      server: r.get(0)?,
      kind: r.get(1)?,
      name: r.get(2)?,
      first_seen: r.get(3)?,
    })
  }

  fn issue(&self, now: i64) -> Issue {
    let hours = (now - self.first_seen) / HOUR;
    let server = &self.server;
    let kind = &self.kind;
    let name = format!("'{}'", self.name.replace('\'', "'\\''"));
    Issue {
      code: "unmanaged_container".into(),
      level: IssueLevel::Info,
      subject: Some(IssueSubject {
        kind: "server".into(),
        name: server.clone(),
      }),
      title: format!(
        "{server} 上的 {} 已出现 {hours} 小时，尚未纳管",
        self.name
      ),
      hint: Some(format!(
        "wharf service discover {server}；wharf service unmanaged-remove {server} --{kind} {name}；wharf service unmanaged-ignore {server} --{kind} {name}"
      )),
    }
  }
}

fn due_issues(
  c: &Connection,
  now: i64,
) -> Result<Vec<Issue>, ApiError> {
  let mut stmt = c.prepare("SELECT server,kind,name,first_seen FROM unmanaged_seen
    WHERE missing_since IS NULL AND NOT ignored AND first_seen <= ?1 ORDER BY server,kind,name").map_err(sql_err)?;
  stmt
    .query_map([now - HOUR], |row| {
      Seen::read(row).map(|s| s.issue(now))
    })
    .and_then(Iterator::collect)
    .map_err(sql_err)
}

pub async fn issues(
  state: &AppState,
) -> Result<Vec<Issue>, ApiError> {
  state.db.call(|c| due_issues(c, now_ms())).await
}

async fn round(state: &AppState) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let results = futures_util::future::join_all(
    snap
      .world
      .servers
      .keys()
      .filter(|server| state.hub.is_online(server))
      .map(|server| async {
        let found = import_api::discover(state, &snap.world, server)
          .await
          .ok()?;
        let server = server.clone();
        state
          .db
          .call(move |c| scan(c, &server, &found, now_ms()))
          .await
          .ok()
      }),
  )
  .await;
  for seen in results.into_iter().flatten().flatten() {
    let issue = seen.issue(now_ms());
    crate::rules::notice(
      state,
      "unmanaged_container",
      None,
      false,
      Event {
        title: issue.title,
        body: issue.hint.unwrap_or_default(),
      },
    )
    .await;
  }
  let _ = state.db.call(|c| {
    c.execute("DELETE FROM unmanaged_seen WHERE server NOT IN (SELECT name FROM resources WHERE kind='server')", [])
      .map_err(sql_err)?;
    c.execute("DELETE FROM unmanaged_baseline WHERE server NOT IN (SELECT name FROM resources WHERE kind='server')", [])
      .map_err(sql_err)?;
    Ok(())
  }).await;
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      tick.tick().await;
      round(&state).await;
    }
  });
}

#[cfg(test)]
mod tests {
  use super::*;

  fn item(name: &str) -> Unmanaged {
    Unmanaged {
      server: "s1".into(),
      project: Some(name.into()),
      container: None,
      containers: vec![],
      name: name.into(),
      ignored: false,
    }
  }

  #[test]
  fn discovery_baseline_delay_once_and_ignore() {
    let mut c = Connection::open_in_memory().unwrap();
    c.execute_batch(MIGRATION).unwrap();
    let now = 2 * 24 * HOUR;
    assert!(
      scan(&mut c, "s1", &[item("baseline")], now)
        .unwrap()
        .is_empty()
    );
    let found = [item("baseline"), item("new")];
    let at = now + HOUR;
    assert!(scan(&mut c, "s1", &found, at).unwrap().is_empty());
    assert_eq!(due_issues(&c, at).unwrap().len(), 1);
    assert!(
      scan(&mut c, "s1", &found, at + 59 * 60_000)
        .unwrap()
        .is_empty()
    );
    let due = scan(&mut c, "s1", &found, at + 61 * 60_000).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].name, "new");
    assert!(
      scan(&mut c, "s1", &found, at + 71 * 60_000)
        .unwrap()
        .is_empty()
    );
    c.execute(
      "UPDATE unmanaged_seen SET ignored=1 WHERE name='new'",
      [],
    )
    .unwrap();
    let issues = due_issues(&c, at + 71 * 60_000).unwrap();
    assert_eq!(issues.len(), 1);
    assert!(issues[0].title.contains("baseline"));
  }
}
