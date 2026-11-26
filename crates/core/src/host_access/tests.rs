use super::*;
use chrono::Utc;
use serde_json::json;
use wharf_api_types::{
  plan::PlanStatus,
  spec::{Change, ServiceSpec},
};

use crate::world::{GatewayRow, ServerRow};

fn auth(perms: &[Perm], human: bool) -> Auth {
  Auth {
    name: "tok".into(),
    perms: perms.iter().copied().collect(),
    expires_at: None,
    allowed_from: vec![],
    services: None,
    human,
  }
}

fn non_admin_perms() -> BTreeSet<Perm> {
  BTreeSet::from([
    Perm::Read,
    Perm::Plan,
    Perm::Apply,
    Perm::Exec,
    Perm::Confirm,
  ])
}

fn admin_perms() -> BTreeSet<Perm> {
  BTreeSet::from([Perm::Admin])
}

fn base_world() -> World {
  let mut w = World::default();
  w.servers.insert(
    "s1".into(),
    ServerRow {
      settings: ServerSettings::default(),
      version: 1,
    },
  );
  w
}

fn compose_row(
  content: &str,
  import: Option<AdoptSpec>,
) -> ServiceRow {
  let spec: ServiceSpec = serde_json::from_value(json!({
    "server": "s1",
    "source": { "compose": { "content": content } }
  }))
  .unwrap();
  ServiceRow {
    spec,
    host_ports: Default::default(),
    import,
    pins: Default::default(),
    commit: None,
    version: 1,
  }
}

fn make_item(
  id: u32,
  address: &str,
  layer: Layer,
  action: Action,
) -> PlanItem {
  PlanItem {
    id,
    address: address.into(),
    layer,
    action,
    before: None,
    after: None,
    impacts: vec![],
    reason: String::new(),
    changes: vec![],
    host_access: vec![],
  }
}

fn make_plan(
  current: &World,
  desired: &World,
  mut items: Vec<PlanItem>,
  steps: &[StepPlan],
) -> Plan {
  let needs_admin = mark_plan(current, desired, &mut items, steps);
  let now = Utc::now();
  Plan {
    plan_id: "p1".into(),
    status: PlanStatus::Pending,
    created_at: now,
    expires_at: now,
    base_versions: Default::default(),
    inputs: None,
    items,
    warnings: vec![],
    needs_admin,
    needs_confirm: vec![],
    suggest: vec![],
    note: None,
  }
}

#[test]
fn compose_host_features_require_admin() {
  let bad_cases = [
    "services:\n  app:\n    image: nginx\n    privileged: true\n",
    "services:\n  app:\n    image: nginx\n    pid: host\n",
    "services:\n  app:\n    image: nginx\n    network_mode: host\n",
    "services:\n  app:\n    image: nginx\n    cap_add: [NET_ADMIN]\n",
    "services:\n  app:\n    image: nginx\n    devices: [\"/dev/kmsg\"]\n",
    "services:\n  app:\n    image: nginx\n    security_opt: [\"seccomp=unconfined\"]\n",
    "services:\n  app:\n    image: nginx\n    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n",
    "services:\n  app:\n    image: nginx\n    volumes: [\"/etc/shadow:/s:ro\"]\n",
    "services:\n  app:\n    image: nginx\n    volumes: [\"/srv/other/data:/data\"]\n",
    "services:\n  app:\n    image: nginx\n    volumes: [\"../secret:/secret\"]\n",
    "services:\n  app:\n    image: nginx\n    volumes: [\"ext:/data\"]\nvolumes:\n  ext:\n    driver_opts:\n      type: none\n      o: bind\n      device: /etc\n",
    "x-priv: &priv\n  privileged: true\nservices:\n  app:\n    <<: *priv\n    image: nginx\n",
  ];
  let current = base_world();
  for yaml in bad_cases {
    let mut desired = base_world();
    desired
      .services
      .insert("app".into(), compose_row(yaml, None));
    let plan = make_plan(
      &current,
      &desired,
      vec![make_item(
        1,
        "service/app",
        Layer::Config,
        Action::Create,
      )],
      &[],
    );
    assert_eq!(plan.needs_admin, vec!["service/app"], "yaml: {yaml}");
    assert!(!plan.items[0].host_access.is_empty());
    let err =
      require_plan_admin(&plan, &[], &non_admin_perms()).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("service/app"));
    assert!(require_plan_admin(&plan, &[], &admin_perms()).is_ok());
  }

  let safe = "services:\n  app:\n    image: nginx\n    volumes:\n      - /srv/app/data:/data\n      - ./cfg:/cfg\n      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata: {}\n";
  let mut desired = base_world();
  desired
    .services
    .insert("app".into(), compose_row(safe, None));
  let plan = make_plan(
    &current,
    &desired,
    vec![make_item(1, "service/app", Layer::Config, Action::Create)],
    &[],
  );
  assert!(plan.needs_admin.is_empty());
  assert!(require_plan_admin(&plan, &[], &non_admin_perms()).is_ok());
}

#[test]
fn privileged_service_env_update_still_requires_admin() {
  let yaml =
    "services:\n  app:\n    image: nginx\n    privileged: true\n";
  let mut current = base_world();
  current
    .services
    .insert("priv".into(), compose_row(yaml, None));
  let mut desired = current.clone();
  desired
    .services
    .get_mut("priv")
    .unwrap()
    .spec
    .env
    .insert("A".into(), "1".into());
  let steps = vec![StepPlan {
    items: vec![1],
    title: "deploy".into(),
    step: Step::ServiceUp {
      service: "priv".into(),
      expect: None,
    },
  }];
  let plan = make_plan(
    &current,
    &desired,
    vec![make_item(
      1,
      "service/priv",
      Layer::Container,
      Action::Update,
    )],
    &steps,
  );
  assert_eq!(plan.needs_admin, vec!["service/priv"]);
  assert_eq!(
    require_plan_admin(&plan, &steps, &non_admin_perms())
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert!(require_plan_admin(&plan, &steps, &admin_perms()).is_ok());
}

#[test]
fn gateway_custom_image_requires_admin() {
  let gw = |image: Option<&str>| GatewayRow {
    spec: serde_json::from_value(json!({
      "kind": "caddy",
      "server": "s1",
      "image": image,
    }))
    .unwrap(),
    version: 1,
  };
  let current = base_world();
  let mut desired = base_world();
  desired
    .gateways
    .insert("edge".into(), gw(Some("evil/caddy")));
  let p1 = make_plan(
    &current,
    &desired,
    vec![make_item(1, "gateway/edge", Layer::Config, Action::Create)],
    &[],
  );
  assert_eq!(p1.needs_admin, vec!["gateway/edge"]);
  assert_eq!(
    require_plan_admin(&p1, &[], &non_admin_perms())
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert!(require_plan_admin(&p1, &[], &admin_perms()).is_ok());

  let mut cur2 = base_world();
  cur2.gateways.insert("edge".into(), gw(None));
  let mut des2 = base_world();
  des2
    .gateways
    .insert("edge".into(), gw(Some("custom/caddy")));
  let p2 = make_plan(
    &cur2,
    &des2,
    vec![make_item(1, "gateway/edge", Layer::Config, Action::Update)],
    &[],
  );
  assert_eq!(p2.needs_admin, vec!["gateway/edge"]);
  assert_eq!(
    require_plan_admin(&p2, &[], &non_admin_perms())
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );

  let p3 = make_plan(
    &cur2,
    &cur2,
    vec![make_item(
      1,
      "gateway/edge",
      Layer::Gateway,
      Action::Update,
    )],
    &[],
  );
  assert!(p3.needs_admin.is_empty());
  assert!(
    require_plan_admin(&p3, &[], &BTreeSet::from([Perm::Apply]))
      .is_ok()
  );
}

#[test]
fn layer4_target_change_and_host_upstream_guarded() {
  let mut w = base_world();
  w.gateways.insert(
    "edge".into(),
    GatewayRow {
      spec: serde_json::from_value(json!({
        "kind": "caddy",
        "server": "s1",
        "layer4": [{ "listen": 15432, "upstream": "169.254.169.254:80" }]
      }))
      .unwrap(),
      version: 1,
    },
  );
  assert_eq!(w.validate().unwrap_err().code, ErrorCode::InvalidInput);

  let current = base_world();
  let mut desired = base_world();
  desired.gateways.insert(
    "edge".into(),
    GatewayRow {
      spec: serde_json::from_value(json!({
        "kind": "caddy",
        "server": "s1",
        "layer4": [{ "listen": 15432, "upstream": "127.0.0.1:7700" }]
      }))
      .unwrap(),
      version: 1,
    },
  );
  let plan = make_plan(
    &current,
    &desired,
    vec![make_item(1, "gateway/edge", Layer::Config, Action::Create)],
    &[],
  );
  assert_eq!(plan.needs_admin, vec!["gateway/edge"]);
  assert_eq!(
    require_plan_admin(&plan, &[], &non_admin_perms())
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert!(require_plan_admin(&plan, &[], &admin_perms()).is_ok());

  let cur_gw: GatewaySpec = serde_json::from_value(json!({
    "kind": "caddy",
    "server": "s1",
    "layer4": [{ "listen": 15432, "upstream": "10.0.0.2:5432" }]
  }))
  .unwrap();
  let same = Layer4Forward {
    listen: 15432,
    udp: false,
    service: None,
    port: None,
    upstream: Some("10.0.0.2:5432".into()),
  };
  let changed = Layer4Forward {
    upstream: Some("10.0.0.3:5432".into()),
    ..same.clone()
  };
  assert!(!layer4_changed(Some(&cur_gw), &same));
  assert!(layer4_changed(Some(&cur_gw), &changed));
}

#[test]
fn host_terminal_requires_admin_and_human() {
  let target = || HostTarget::HostTerminal { server: "s1" };
  assert_eq!(
    require(&auth(&[Perm::Exec], false), target())
      .err()
      .unwrap()
      .0
      .code,
    ErrorCode::Forbidden
  );
  assert_eq!(
    require(&auth(&Perm::ALL, false), target())
      .err()
      .unwrap()
      .0
      .code,
    ErrorCode::Forbidden
  );
  assert!(require(&auth(&Perm::ALL, true), target()).is_ok());
}

#[test]
fn host_exec_dir_apt_require_admin_and_check_host_exec() {
  let non_admin = auth(&[Perm::Apply, Perm::Exec], false);
  let admin = auth(&[Perm::Admin], false);
  let human = auth(&Perm::ALL, true);
  for target in [
    HostTarget::HostExec { server: "s1" },
    HostTarget::HostDir {
      server: "s1",
      action: "浏览宿主机目录",
    },
    HostTarget::HostApt { server: "s1" },
  ] {
    assert_eq!(
      require(&non_admin, target).err().unwrap().0.code,
      ErrorCode::Forbidden
    );
  }
  assert!(
    require(&admin, HostTarget::HostExec { server: "s1" }).is_ok()
  );
  assert!(
    require(
      &admin,
      HostTarget::HostDir {
        server: "s1",
        action: "打包宿主机目录"
      }
    )
    .is_ok()
  );
  assert!(
    require(&admin, HostTarget::HostApt { server: "s1" }).is_ok()
  );

  let settings = ServerSettings {
    host_terminal: true,
    host_exec: false,
    ..Default::default()
  };
  assert_eq!(
    check_host_switch(&admin, "s1", &settings).unwrap_err().code,
    ErrorCode::Forbidden
  );
  assert!(check_host_switch(&human, "s1", &settings).is_ok());
}

#[test]
fn adopt_ownership_and_admin_required() {
  let mut w = base_world();
  let img: ServiceSpec = serde_json::from_value(json!({
    "server": "s1",
    "source": { "image": "nginx" }
  }))
  .unwrap();
  w.apply_changes(&[Change::UpsertService {
    name: "svc1".into(),
    spec: img.clone(),
    adopt: None,
  }])
  .unwrap();
  let err = w
    .apply_changes(&[Change::UpsertService {
      name: "svc1".into(),
      spec: img.clone(),
      adopt: Some(AdoptSpec {
        project: Some("other".into()),
        containers: vec![],
      }),
    }])
    .unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);

  for bad_project in ["svc1", crate::tailscale::PROJECT] {
    let err = w
      .apply_changes(&[Change::UpsertService {
        name: "svc2".into(),
        spec: img.clone(),
        adopt: Some(AdoptSpec {
          project: Some(bad_project.into()),
          containers: vec![],
        }),
      }])
      .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
  }

  let current = base_world();
  let mut desired = base_world();
  desired.services.insert(
    "app".into(),
    compose_row(
      "services:\n  web:\n    image: nginx\n",
      Some(AdoptSpec {
        project: None,
        containers: vec!["legacy-web".into()],
      }),
    ),
  );
  let plan = make_plan(
    &current,
    &desired,
    vec![make_item(1, "service/app", Layer::Config, Action::Create)],
    &[],
  );
  assert_eq!(plan.needs_admin, vec!["service/app"]);
  assert_eq!(
    require_plan_admin(&plan, &[], &non_admin_perms())
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  let scoped = BTreeSet::from(["app".to_string()]);
  assert!(
    crate::token_scope::check_plan_scope(
      &scoped,
      &plan,
      &Default::default()
    )
    .is_err()
  );
  assert!(require_plan_admin(&plan, &[], &admin_perms()).is_ok());
}

#[test]
fn update_server_requires_admin() {
  let current = base_world();
  let mut desired = current.clone();
  let mut settings = ServerSettings::default();
  settings.baseline.timezone = Some("Asia/Shanghai".into());
  settings.pull_proxy = Some("http://10.0.0.2:8118".into());
  desired
    .apply_changes(&[Change::UpdateServer {
      name: "s1".into(),
      settings,
    }])
    .unwrap();
  let plan = make_plan(
    &current,
    &desired,
    vec![make_item(1, "server/s1", Layer::Config, Action::Update)],
    &[],
  );
  assert_eq!(plan.needs_admin, vec!["server/s1"]);
  let err =
    require_plan_admin(&plan, &[], &non_admin_perms()).unwrap_err();
  assert_eq!(err.code, ErrorCode::Forbidden);
  assert!(err.message.contains("修改服务器宿主机设置"));
  assert!(require_plan_admin(&plan, &[], &admin_perms()).is_ok());
}
