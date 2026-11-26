#[test]
fn strips_colors() {
  assert_eq!(
    super::strip_ansi("\x1b[2mT\x1b[0m \x1b[32m INFO\x1b[0m 已连接"),
    "T  INFO 已连接"
  );
}

#[test]
fn merges_logs_by_time() {
  let out = super::merge_by_time(
    "2026-11-22T01:00:02.000Z b\n2026-11-22T01:00:04.000Z d\n",
    "2026-11-22T01:00:01.000Z a\n2026-11-22T01:00:03.000Z c\n",
  );
  let order: Vec<&str> =
    out.lines().map(|l| l.rsplit(' ').next().unwrap()).collect();
  assert_eq!(order, ["a", "b", "c", "d"]);
}

#[test]
fn layer_progress_reports_counts() {
  let mut l = super::output::Layers::default();
  assert_eq!(l.feed("latest: Pulling from remsky/kokoro"), None);
  assert_eq!(l.feed("0a1b2c3d4e5f: Pulling fs layer"), None);
  assert_eq!(
    l.feed("1a1b2c3d4e5f: Already exists").as_deref(),
    Some("镜像层：已下载 1/2，已解压 1/2")
  );
  assert_eq!(
    l.feed("0a1b2c3d4e5f: Download complete").as_deref(),
    Some("镜像层：已下载 2/2，已解压 1/2")
  );
  assert_eq!(l.feed("0a1b2c3d4e5f: Verifying Checksum"), None);
  assert_eq!(
    l.feed("Status: Downloaded newer image").as_deref(),
    Some("Downloaded newer image")
  );
}

use super::*;

fn policy(only: bool) -> PullPolicy {
  PullPolicy {
    mirrors: BTreeMap::from([
      (
        "docker.io".to_string(),
        vec![
          "docker.1ms.run".to_string(),
          "docker.m.daocloud.io/".into(),
        ],
      ),
      ("ghcr.io".to_string(), vec!["ghcr.nju.edu.cn".to_string()]),
    ]),
    mirrors_only: only,
    attempt_timeout_secs: 60,
    git_proxy: None,
    github_mirror: None,
    registry_proxy: None,
  }
}

#[test]
fn candidates_follow_mirror_order() {
  assert_eq!(
    pull_candidates("traefik/whoami", &policy(false)),
    vec![
      "docker.1ms.run/traefik/whoami:latest",
      "docker.m.daocloud.io/traefik/whoami:latest",
      "traefik/whoami",
    ]
  );
  assert_eq!(
    pull_candidates("caddy:2", &policy(true)),
    vec![
      "docker.1ms.run/library/caddy:2",
      "docker.m.daocloud.io/library/caddy:2",
    ]
  );
  assert_eq!(
    pull_candidates("ghcr.io/acme/app:main", &policy(true)),
    vec!["ghcr.nju.edu.cn/acme/app:main"]
  );
  // 没有镜像源的 registry、带端口的私有 registry、digest 引用都直连。
  assert_eq!(
    pull_candidates("quay.io/a/b:1", &policy(true)),
    vec!["quay.io/a/b:1"]
  );
  assert_eq!(
    pull_candidates("localhost:5000/a:1", &policy(true)),
    vec!["localhost:5000/a:1"]
  );
  assert_eq!(
    pull_candidates("nginx@sha256:abc", &policy(false)),
    vec!["nginx@sha256:abc"]
  );
}

#[test]
fn digest_matches_repo() {
  assert_eq!(
    pick_digest(
      "traefik/whoami:latest",
      "docker.1ms.run/traefik/whoami@sha256:1,traefik/whoami@sha256:2"
    )
    .as_deref(),
    Some("traefik/whoami@sha256:2")
  );
}

#[test]
fn ps_groups_by_project() {
  let out = r#"{"Names":"whoami-whoami-1","State":"running","Status":"Up 2 minutes (healthy)","Image":"traefik/whoami","Labels":"com.docker.compose.project=whoami,com.docker.compose.project.working_dir=/opt/whoami,com.docker.compose.service=whoami"}
{"Names":"x","State":"exited","Status":"Exited (1)","Image":"a","Labels":"com.docker.compose.project=other,com.docker.compose.service=web"}
not json"#;
  let grouped = parse_ps(out);
  assert_eq!(grouped.len(), 2);
  let who = &grouped["whoami"][0];
  assert_eq!(who.service, "whoami");
  assert_eq!(who.health.as_deref(), Some("healthy"));
  assert_eq!(who.working_dir.as_deref(), Some("/opt/whoami"));
  assert_eq!(grouped["other"][0].state, "exited");
}
