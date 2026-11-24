use super::*;

fn rule(id: &str) -> &'static Rule {
  RULES.iter().find(|r| r.id == id).unwrap()
}

fn v(points: &[f64]) -> VecDeque<f64> {
  points.iter().copied().collect()
}

#[test]
fn consecutive_fires_after_n_and_recovers_on_good() {
  let r = rule("server_offline");
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[1.0, 0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[0.0, 0.0, 0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[0.0, 0.0, 1.0])),
    Verdict::Recover
  ));
}

#[test]
fn oom_fires_once_in_a_thirty_sample_window() {
  let r = rule("oom_killed");
  assert_eq!(r.for_n, 1);
  assert!(matches!(r.mode, Mode::Window(30)));
  let event = (r.fire)(&Ctx {
    subject: "web",
    value: 1.0,
    detail: "上限 32 MB",
    threshold: r.threshold,
    for_n: r.for_n,
  });
  assert_eq!(event.title, "服务 web 因内存超限被杀");
}

#[test]
fn window_and_hysteresis() {
  let r = rule("container_restarting");
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[1.0, 0.0, 1.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[1.0, 0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[0.0, 0.0])),
    Verdict::Recover
  ));
  let h = rule("http_5xx");
  assert!(matches!(judge(h, 10.0, 1, &v(&[12.0])), Verdict::Fire));
  assert!(matches!(judge(h, 10.0, 1, &v(&[5.0])), Verdict::Hold));
  assert!(matches!(judge(h, 10.0, 1, &v(&[1.0])), Verdict::Recover));
}

#[test]
fn service_port_three_failures_and_one_success() {
  let r = rule("port_down");
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0, 0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0, 0.0, 1.0])),
    Verdict::Recover
  ));
}

#[test]
fn log_rule_holds_below_threshold_until_window_is_empty() {
  let r = rule("log_keyword");
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[-1.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[-f64::MAX])),
    Verdict::Recover
  ));
}

pub(super) fn notification_db() -> rusqlite::Connection {
  let c = rusqlite::Connection::open_in_memory().unwrap();
  c.execute_batch(
    "CREATE TABLE alert_firing (rule TEXT, subject TEXT, since INTEGER, title TEXT, PRIMARY KEY (rule, subject));
     CREATE TABLE alert_history (id INTEGER PRIMARY KEY, at INTEGER, source TEXT, subject TEXT, title TEXT, ok INTEGER, skipped TEXT);
     CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
  ).unwrap();
  c.execute_batch(MIGRATION).unwrap();
  c
}
