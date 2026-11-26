use super::*;

use chrono::Utc;
use serde_json::json;
use wharf_api_types::{
  plan::{Plan, PlanStatus},
  spec::Change,
  view::Perm,
};

use crate::{token_scope, world::ServerRow};

fn world() -> World {
  let mut world = World::default();
  world.servers.insert(
    "s1".into(),
    ServerRow {
      settings: ServerSettings::default(),
      version: 1,
    },
  );
  world
}

fn service(content: &str, adopt: Option<AdoptSpec>) -> Change {
  Change::UpsertService {
    name: "app".into(),
    spec: serde_json::from_value(
      json!({"server":"s1","source":{"compose":{"content":content}}}),
    )
    .unwrap(),
    adopt,
  }
}

fn gateway(
  world: &mut World,
  image: Option<&str>,
  upstream: Option<&str>,
) {
  let layer4 = upstream
    .map(|up| json!({"listen": 19000, "upstream": up}))
    .into_iter()
    .collect::<Vec<_>>();
  world.apply_changes(&[Change::UpsertGateway {
    name: "gw".into(),
    spec: serde_json::from_value(json!({"kind":"caddy", "server":"s1", "image":image,"layer4":layer4})).unwrap(),
  }]).unwrap();
}

fn plan(
  current: &World,
  desired: &World,
  address: &str,
  action: Action,
  layer: Layer,
  steps: &[StepPlan],
) -> Plan {
  let mut items = vec![PlanItem {
    id: 1,
    address: address.into(),
    action,
    layer,
    before: None,
    after: None,
    impacts: vec![],
    reason: String::new(),
    changes: vec![],
    host_access: vec![],
  }];
  let (needs_host, _) =
    mark_plan(current, desired, &mut items, steps);
  let needs_confirm = items
    .iter()
    .filter(|i| i.needs_confirm())
    .map(|i| i.address.clone())
    .collect();
  Plan {
    plan_id: "p1".into(),
    status: PlanStatus::Pending,
    created_at: Utc::now(),
    expires_at: Utc::now(),
    base_versions: Default::default(),
    inputs: None,
    items,
    warnings: vec![],
    needs_host,
    needs_confirm,
    suggest: vec![],
    note: None,
  }
}

fn assert_host(plan: &Plan, reason: &str) {
  assert_eq!(plan.needs_host, [plan.items[0].address.as_str()]);
  assert!(
    plan.items[0]
      .host_access
      .iter()
      .any(|detail| detail.contains(reason))
  );
}

pub(crate) fn auth(
  perms: impl IntoIterator<Item = Perm>,
  human: bool,
) -> Auth {
  Auth {
    name: "test".into(),
    perms: perms.into_iter().collect(),
    expires_at: None,
    allowed_from: vec![],
    services: None,
    human,
  }
}

const PLAIN: &str = "services: {app: {image: nginx}}";
const PRIVILEGED: &str =
  "services: {app: {image: nginx, privileged: true}}";

#[test]
fn compose_host_features_require_host() {
  let current = world();
  let mut desired = current.clone();
  let content = r#"
x-priv: &priv { privileged: true }
services:
  app:
    <<: *priv
    image: nginx
    pid: host
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/kmsg"]
    security_opt: ["seccomp=unconfined"]
    volumes:
      - /var/run/docker.sock:/sock
      - /etc/shadow:/shadow
      - /srv/other/data:/other
      - ../secret:/secret
volumes:
  external:
    driver_opts: {o: bind, device: /other}
"#;
  desired.apply_changes(&[service(content, None)]).unwrap();
  let marked = plan(
    &current,
    &desired,
    "service/app",
    Action::Create,
    Layer::Config,
    &[],
  );
  for reason in [
    "privileged",
    "pid: host",
    "network_mode: host",
    "cap_add",
    "devices",
    "security_opt",
    "docker.sock",
    "/etc/shadow",
    "/srv/other/data",
    "../secret",
    "driver_opts",
  ] {
    assert_host(&marked, reason);
  }
  desired.apply_changes(&[service("services: {app: {image: nginx, volumes: ['/srv/app/data:/data', './cfg:/cfg', 'named:/named']}}\nvolumes: {named: {}}", None)]).unwrap();
  assert!(
    plan(
      &current,
      &desired,
      "service/app",
      Action::Create,
      Layer::Config,
      &[]
    )
    .needs_host
    .is_empty()
  );
}

#[test]
fn privileged_service_env_update_still_requires_host() {
  let mut current = world();
  current.apply_changes(&[service(PRIVILEGED, None)]).unwrap();
  let mut desired = current.clone();
  desired.apply_changes(&[service("services: {app: {image: nginx, privileged: true, environment: {MODE: prod}}}", None)]).unwrap();
  let steps = [StepPlan {
    items: vec![1],
    title: String::new(),
    step: Step::ServiceUp {
      service: "app".into(),
      expect: None,
    },
  }];
  let marked = plan(
    &current,
    &desired,
    "service/app",
    Action::Update,
    Layer::Container,
    &steps,
  );
  assert_host(&marked, "privileged");
  assert_eq!(marked.items[0].host_access.len(), 1);
  let drift = plan(
    &current,
    &current,
    "service/app",
    Action::Update,
    Layer::Container,
    &steps,
  );
  assert_host(&drift, "privileged");
}

#[test]
fn gateway_custom_image_requires_host() {
  let empty = world();
  let mut old = empty.clone();
  gateway(&mut old, None, None);
  let mut desired = old.clone();
  gateway(&mut desired, Some("custom/caddy"), None);
  for (current, action, reason) in [
    (&empty, Action::Create, "自定义网关镜像"),
    (&old, Action::Update, "修改网关镜像"),
  ] {
    assert_host(
      &plan(
        current,
        &desired,
        "gateway/gw",
        action,
        Layer::Config,
        &[],
      ),
      reason,
    );
  }
  let hot_reload = plan(
    &desired,
    &desired,
    "gateway/gw",
    Action::Update,
    Layer::Gateway,
    &[],
  );
  assert!(hot_reload.needs_host.is_empty());
}

#[test]
fn layer4_target_change_and_host_upstream_guarded() {
  let mut old = world();
  gateway(&mut old, None, Some("192.0.2.1:80"));
  let mut desired = old.clone();
  gateway(&mut desired, None, Some("169.254.169.254:80"));
  let err = desired.validate().unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  assert!(err.message.contains("云元数据"));
  gateway(&mut desired, None, Some("127.0.0.1:7700"));
  desired.validate().unwrap();
  let marked = plan(
    &old,
    &desired,
    "gateway/gw",
    Action::Update,
    Layer::Config,
    &[],
  );
  assert_host(&marked, "指向宿主机本地或保留端口");
  assert_eq!(marked.needs_confirm, ["gateway/gw"]);
  gateway(&mut desired, None, None);
  assert_eq!(
    plan(
      &old,
      &desired,
      "gateway/gw",
      Action::Update,
      Layer::Config,
      &[]
    )
    .needs_confirm,
    ["gateway/gw"]
  );
}

#[test]
fn direct_interfaces_require_host_and_their_switch() {
  let closed = ServerSettings::default();
  let token = auth([Perm::Host], false);
  let admin = auth([Perm::Admin], false);
  let human = auth(Perm::ALL, true);
  for (target, cap) in [
    (HostTarget::HostExec { server: "s1" }, HostCap::HostExec),
    (
      HostTarget::HostDir {
        server: "s1",
        action: "浏览宿主机目录",
      },
      HostCap::HostExec,
    ),
    (HostTarget::HostApt { server: "s1" }, HostCap::HostExec),
    (
      HostTarget::ImportPreview {
        server: "s1",
        target: "foreign",
      },
      HostCap::HostDocker,
    ),
    (
      HostTarget::RemoveUnmanaged {
        server: "s1",
        target: "foreign",
      },
      HostCap::HostDocker,
    ),
    (HostTarget::HostUnits { server: "s1" }, HostCap::HostSystem),
  ] {
    let open: ServerSettings =
      serde_json::from_value(json!({(cap.field()): true})).unwrap();
    let err =
      require_with(&token, target, Some(&closed), Some("core"))
        .unwrap_err()
        .0;
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains(cap.field()));
    assert!(
      require_with(&token, target, Some(&open), Some("core")).is_ok()
    );
    let err = require_with(&admin, target, None, None).unwrap_err().0;
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("需要 host 权限"));
    assert!(
      require_with(&human, target, Some(&closed), Some("core"))
        .is_ok()
    );
    let err = require_with(&token, target, None, Some("core"))
      .unwrap_err()
      .0;
    assert_eq!(err.code, ErrorCode::NotFound);
  }

  let terminal = HostTarget::HostTerminal { server: "s1" };
  let settings = ServerSettings {
    host_terminal: true,
    ..ServerSettings::default()
  };
  for token in [token, auth(Perm::ALL, false)] {
    let err = require_with(&token, terminal, Some(&settings), None)
      .unwrap_err()
      .0;
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("页面"));
  }
  assert!(
    require_with(&human, terminal, Some(&settings), None).is_ok()
  );
  assert_eq!(
    check_host_dir_settings(&admin, "s1", &settings)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert!(check_host_dir_settings(&human, "s1", &settings).is_ok());
}

#[test]
fn control_plane_host_requires_admin_even_if_switch_is_open() {
  let settings = ServerSettings {
    host_terminal: true,
    host_exec: true,
    host_docker: true,
    host_system: true,
    ..Default::default()
  };
  let target = HostTarget::HostExec { server: "s1" };
  for (core, reason) in [
    (Some("s1"), "是控制面所在机器"),
    (None, "无法确认控制面所在服务器"),
  ] {
    let err = require_with(
      &auth([Perm::Host], false),
      target,
      Some(&settings),
      core,
    )
    .unwrap_err()
    .0;
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains(reason));
    assert!(
      require_with(
        &auth([Perm::Host, Perm::Admin], false),
        target,
        Some(&settings),
        core
      )
      .is_ok()
    );
  }
}

#[test]
fn adopt_ownership_and_host_required() {
  let mut current = world();
  current.apply_changes(&[service(PLAIN, None)]).unwrap();
  let adopt = |p: &str| {
    Some(AdoptSpec {
      project: Some(p.into()),
      containers: vec![],
    })
  };
  let mut existing = current.clone();
  assert_eq!(
    existing
      .apply_changes(&[service(PLAIN, adopt("foreign"))])
      .unwrap_err()
      .code,
    ErrorCode::InvalidInput
  );
  for project in ["managed", crate::tailscale::PROJECT] {
    let mut candidate = world();
    candidate
      .services
      .insert("managed".into(), current.services["app"].clone());
    assert_eq!(
      candidate
        .apply_changes(&[service(PLAIN, adopt(project))])
        .unwrap_err()
        .code,
      ErrorCode::InvalidInput
    );
  }
  let current = world();
  let mut desired = current.clone();
  desired
    .apply_changes(&[service(PLAIN, adopt("foreign"))])
    .unwrap();
  let marked = plan(
    &current,
    &desired,
    "service/app",
    Action::Create,
    Layer::Config,
    &[],
  );
  assert_host(&marked, "接管宿主机上的未纳管容器");
  assert_eq!(
    token_scope::check_plan_scope(
      &BTreeSet::from(["app".into()]),
      &marked,
      &Default::default()
    ),
    Err(vec!["service/app".into()])
  );
}

#[test]
fn update_server_requires_host() {
  let current = world();
  let mut desired = current.clone();
  let mut settings = current.servers["s1"].settings.clone();
  settings.baseline.timezone = Some("Asia/Shanghai".into());
  settings.pull_proxy = Some("http://192.0.2.1:8118".into());
  desired
    .apply_changes(&[Change::UpdateServer {
      name: "s1".into(),
      settings,
    }])
    .unwrap();
  let marked = plan(
    &current,
    &desired,
    "server/s1",
    Action::Update,
    Layer::Config,
    &[],
  );
  assert_host(&marked, "修改服务器宿主机设置");
}

#[test]
fn redact_host_command_for_systemd_list() {
  assert_eq!(
    crate::redact::redact_command(
      "cloudflared tunnel run --token eyJhbGci --url https://u:p@a.com"
    ),
    "cloudflared tunnel run --token *** --url https://***:***@a.com",
  );
}

#[test]
fn plans_check_current_switch_and_control_plane() {
  let mut current = world();
  let mut desired = current.clone();
  desired.apply_changes(&[service(PRIVILEGED, None)]).unwrap();
  let compose = Step::ServiceUp {
    service: "app".into(),
    expect: None,
  };
  let baseline = Step::Baseline {
    server: "s1".into(),
  };
  let proxy = Step::DockerProxy {
    server: "s1".into(),
  };
  for (address, step, cap) in [
    ("service/app", compose, HostCap::HostDocker),
    ("baseline/s1", baseline, HostCap::HostSystem),
    ("docker/s1", proxy, HostCap::HostSystem),
  ] {
    let steps = [StepPlan {
      items: vec![1],
      title: String::new(),
      step,
    }];
    let mut plan = plan(
      &current,
      &desired,
      address,
      Action::Update,
      Layer::Container,
      &steps,
    );
    let (addresses, reqs) =
      mark_plan(&current, &desired, &mut plan.items, &steps);
    assert_eq!(addresses, [address]);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].cap, cap);
    assert_eq!(reqs[0].server, "s1");
    assert_eq!(reqs[0].address, address);
    let check = |current: &World, perms, core| {
      require_plan_host(
        &plan,
        &steps,
        Some(&reqs),
        &perms,
        false,
        current,
        core,
      )
    };
    let host = BTreeSet::from([Perm::Host]);
    let missing = require_plan_host(
      &plan,
      &steps,
      Some(&[]),
      &host,
      false,
      &current,
      Some("core"),
    )
    .unwrap_err();
    assert_eq!(
      (missing.code, missing.message),
      (
        ErrorCode::Forbidden,
        format!(
          "计划项 {address} 触达宿主机但没能确定目标服务器，需要 host 和 admin 权限"
        )
      ),
    );
    let admin = BTreeSet::from([Perm::Admin]);
    let err = check(&current, admin, Some("core")).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("需要 host 权限"));
    let err =
      check(&current, host.clone(), Some("core")).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains(cap.field()));
    let row = current.servers.get_mut("s1").unwrap();
    row.settings =
      serde_json::from_value(json!({(cap.field()): true})).unwrap();
    assert!(check(&current, host.clone(), Some("core")).is_ok());
    for core in [Some("s1"), None] {
      let err = check(&current, host.clone(), core).unwrap_err();
      assert_eq!(err.code, ErrorCode::Forbidden);
      assert!(err.message.contains("admin 权限"));
      assert!(
        check(
          &current,
          BTreeSet::from([Perm::Host, Perm::Admin]),
          core
        )
        .is_ok()
      );
    }
    current.servers.get_mut("s1").unwrap().settings =
      ServerSettings::default();
    assert!(check(&current, host, Some("core")).is_err());
  }
}

#[test]
fn api_plan_can_only_close_switches_with_host_system_enabled() {
  let mut current = world();
  let mut plan = plan(
    &current,
    &current,
    "server/s1",
    Action::Update,
    Layer::Config,
    &[],
  );
  let (_, reqs) = mark_plan(&current, &current, &mut plan.items, &[]);
  assert_eq!(reqs[0].cap, HostCap::HostSystem);
  let perms = Perm::ALL.into_iter().collect();
  for cap in [
    HostCap::HostTerminal,
    HostCap::HostExec,
    HostCap::HostDocker,
    HostCap::HostSystem,
  ] {
    let value = json!({(cap.field()): true});
    let settings = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(opened_switch(None, &settings), Some(cap.label()));
    assert_eq!(opened_switch(Some(&settings), &settings), None);
    plan.items[0].after = Some(value);
    let err = require_plan_host(
      &plan,
      &[],
      Some(&reqs),
      &perms,
      false,
      &current,
      Some("core"),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains(cap.label()));
    assert!(
      require_plan_host(
        &plan,
        &[],
        Some(&reqs),
        &perms,
        true,
        &current,
        None
      )
      .is_ok()
    );
  }
  current.servers.get_mut("s1").unwrap().settings.host_docker = true;
  plan.items[0].after = Some(json!({}));
  let err = require_plan_host(
    &plan,
    &[],
    Some(&reqs),
    &perms,
    false,
    &current,
    Some("core"),
  )
  .unwrap_err();
  assert!(err.message.contains("host_system"));
  current.servers.get_mut("s1").unwrap().settings.host_system = true;
  assert!(
    require_plan_host(
      &plan,
      &[],
      Some(&reqs),
      &perms,
      false,
      &current,
      Some("core")
    )
    .is_ok()
  );
}

#[test]
fn legacy_host_and_unverified_plans_must_be_replanned() {
  let current = world();
  let perms = Perm::ALL.into_iter().collect();
  for (address, stale) in [
    ("baseline/s1", true),
    ("service/app", true),
    ("gateway/gw", true),
    ("bookmark/sample", false),
  ] {
    let mut plan = plan(
      &current,
      &current,
      address,
      Action::Update,
      Layer::Config,
      &[],
    );
    plan.items[0].host_access.clear();
    plan.needs_host.clear();
    let result = require_plan_host(
      &plan,
      &[],
      None,
      &perms,
      true,
      &current,
      None,
    );
    if stale {
      let err = result.unwrap_err();
      assert_eq!(err.code, ErrorCode::PlanStale);
      assert_eq!(err.suggest, ["wharf plan"]);
    } else {
      assert!(result.is_ok());
    }
  }
  let plan = plan(
    &current,
    &current,
    "bookmark/sample",
    Action::Update,
    Layer::Config,
    &[],
  );
  let mut old = serde_json::to_value(&plan).unwrap();
  old["needs_admin"] = json!(["bookmark/sample"]);
  let old: Plan = serde_json::from_value(old).unwrap();
  assert_eq!(old.needs_host, ["bookmark/sample"]);
  assert_eq!(
    require_plan_host(&old, &[], None, &perms, false, &current, None)
      .unwrap_err()
      .code,
    ErrorCode::PlanStale
  );
}

#[test]
fn migration_preserves_existing_host_access_and_is_idempotent() {
  let db = rusqlite::Connection::open_in_memory().unwrap();
  db.execute_batch(r#"
    CREATE TABLE api_tokens (scope TEXT NOT NULL);
    CREATE TABLE resources (kind TEXT NOT NULL, spec TEXT NOT NULL);
    INSERT INTO api_tokens VALUES
      ('read,plan,apply,confirm,exec,admin'), ('read,plan,apply,exec'), ('apply_all');
    INSERT INTO resources VALUES
      ('server', '{"host_terminal":true,"host_exec":true}'),
      ('server', '{"host_terminal":true}'),
      ('server', '{}'),
      ('server', '{"host_docker":false,"host_system":false}'),
      ('service', '{}');
  "#).unwrap();
  let scope = |id| {
    db.query_row(
      "SELECT scope FROM api_tokens WHERE rowid = ?1",
      [id],
      |row| row.get::<_, String>(0),
    )
    .unwrap()
  };
  let spec = |id| {
    db.query_row(
      "SELECT spec FROM resources WHERE rowid = ?1",
      [id],
      |row| row.get::<_, String>(0),
    )
    .unwrap()
  };
  for _ in 0..2 {
    db.execute_batch(MIGRATION).unwrap();
    assert_eq!(scope(1), "read,plan,apply,confirm,exec,host,admin");
    assert_eq!(scope(2), "read,plan,apply,exec");
    assert_eq!(scope(3), "apply_all");
    let all = crate::auth::decode_perms(&scope(3)).unwrap();
    assert!(all.contains(&Perm::Host) && all.contains(&Perm::Admin));
    for (id, terminal, exec, docker, system) in [
      (1, true, true, true, true),
      (2, true, false, true, true),
      (3, false, false, true, true),
      (4, false, false, false, false),
    ] {
      let s: ServerSettings =
        serde_json::from_str(&spec(id)).unwrap();
      assert_eq!(
        (s.host_terminal, s.host_exec, s.host_docker, s.host_system),
        (terminal, exec, docker, system)
      );
    }
    assert_eq!(spec(5), "{}");
  }
  db.execute("INSERT INTO resources VALUES ('server', '{}')", [])
    .unwrap();
  let new: ServerSettings = serde_json::from_str(&spec(6)).unwrap();
  assert!(
    !new.host_terminal
      && !new.host_exec
      && !new.host_docker
      && !new.host_system
  );
}
