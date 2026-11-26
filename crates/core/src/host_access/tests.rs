use super::*;

use chrono::Utc;
use serde_json::json;
use wharf_api_types::{plan::PlanStatus, spec::Change};

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
  let needs_admin = mark_plan(current, desired, &mut items, steps);
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
    needs_admin,
    needs_confirm,
    suggest: vec![],
    note: None,
  }
}

fn limited() -> BTreeSet<Perm> {
  Perm::ALL
    .into_iter()
    .filter(|p| *p != Perm::Admin)
    .collect()
}

fn assert_admin(plan: &Plan, steps: &[StepPlan], reason: &str) {
  assert_eq!(plan.needs_admin, [plan.items[0].address.as_str()]);
  let error =
    require_plan_admin(plan, steps, &limited()).unwrap_err();
  assert_eq!(error.code, ErrorCode::Forbidden);
  assert!(error.message.contains(reason), "{}", error.message);
  assert!(
    require_plan_admin(plan, steps, &BTreeSet::from([Perm::Admin]))
      .is_ok()
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
fn compose_host_features_require_admin() {
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
    assert_admin(&marked, &[], reason);
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
    .needs_admin
    .is_empty()
  );
}

#[test]
fn privileged_service_env_update_still_requires_admin() {
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
  assert_admin(&marked, &steps, "privileged");
  assert_eq!(marked.items[0].host_access.len(), 1);
  let drift = plan(
    &current,
    &current,
    "service/app",
    Action::Update,
    Layer::Container,
    &steps,
  );
  assert_admin(&drift, &steps, "privileged");
}

#[test]
fn gateway_custom_image_requires_admin() {
  let empty = world();
  let mut old = empty.clone();
  gateway(&mut old, None, None);
  let mut desired = old.clone();
  gateway(&mut desired, Some("custom/caddy"), None);
  for (current, action, reason) in [
    (&empty, Action::Create, "自定义网关镜像"),
    (&old, Action::Update, "修改网关镜像"),
  ] {
    assert_admin(
      &plan(
        current,
        &desired,
        "gateway/gw",
        action,
        Layer::Config,
        &[],
      ),
      &[],
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
  assert!(hot_reload.needs_admin.is_empty());
  assert!(require_plan_admin(&hot_reload, &[], &limited()).is_ok());
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
  assert_admin(&marked, &[], "指向宿主机本地或保留端口");
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
fn host_terminal_requires_admin_and_human() {
  let terminal = || HostTarget::HostTerminal { server: "s1" };
  for token in [auth([Perm::Exec], false), auth(Perm::ALL, false)] {
    let err = require(&token, terminal()).unwrap_err().0;
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("页面"));
  }
  assert!(require(&auth(Perm::ALL, true), terminal()).is_ok());
}

#[test]
fn host_exec_dir_apt_require_admin_and_check_host_exec() {
  for target in [
    HostTarget::HostExec { server: "s1" },
    HostTarget::HostDir {
      server: "s1",
      action: "浏览宿主机目录",
    },
    HostTarget::HostApt { server: "s1" },
  ] {
    assert_eq!(
      require(&auth([Perm::Apply, Perm::Exec], false), target)
        .unwrap_err()
        .0
        .code,
      ErrorCode::Forbidden
    );
    assert!(require(&auth([Perm::Admin], false), target).is_ok());
  }
  let settings = ServerSettings {
    host_terminal: true,
    host_exec: false,
    ..Default::default()
  };
  assert_eq!(
    check_host_dir_settings(
      &auth([Perm::Admin], false),
      "s1",
      &settings
    )
    .unwrap_err()
    .code,
    ErrorCode::Forbidden
  );
  assert!(
    check_host_dir_settings(&auth(Perm::ALL, true), "s1", &settings)
      .is_ok()
  );
}

#[test]
fn adopt_ownership_and_admin_required() {
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
  assert_admin(&marked, &[], "接管宿主机上的未纳管容器");
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
fn update_server_requires_admin() {
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
  assert_admin(&marked, &[], "修改服务器宿主机设置");
}
