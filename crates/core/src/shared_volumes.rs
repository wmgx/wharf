use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  ApiError,
  compose::owned_volumes,
  spec::{ServiceSpec, Source},
  validate_name,
  view::DataKind,
};

use crate::{
  planner::{Step, StepPlan},
  world::World,
};

pub fn parse_ref(raw: &str) -> Result<(&str, &str), ApiError> {
  raw
    .split_once(':')
    .filter(|(owner, vol)| {
      validate_name("服务", owner).is_ok()
        && validate_name("数据卷", vol).is_ok()
    })
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "共享卷引用 {raw:?} 格式不对，应为 <服务名>:<卷名>"
      ))
      .with_hint("例如 photos:originals")
    })
}

pub fn normalize(spec: &mut ServiceSpec) -> Result<(), ApiError> {
  for v in &mut spec.volumes {
    if let Some(raw) = &v.from_service {
      let (_, volume) = parse_ref(raw)?;
      if v.name.trim().is_empty() {
        v.name = volume.to_string();
      }
    }
  }
  Ok(())
}

pub fn owners(spec: &ServiceSpec) -> impl Iterator<Item = &str> {
  spec.volumes.iter().filter_map(|v| {
    let (owner, _) = parse_ref(v.from_service.as_deref()?).ok()?;
    Some(owner)
  })
}

pub fn uses(spec: &ServiceSpec) -> Vec<String> {
  let mut uses = crate::refs::uses(spec);
  for owner in owners(spec) {
    if !uses.iter().any(|name| name == owner) {
      uses.push(owner.to_string());
    }
  }
  uses
}

pub fn consumers_on<'a>(
  world: &'a World,
  owner: &str,
  server: &str,
) -> impl Iterator<Item = &'a str> {
  world.services.iter().filter_map(move |(name, row)| {
    (row.spec.server == server
      && owners(&row.spec).any(|n| n == owner))
    .then_some(name.as_str())
  })
}

pub fn validate_service(
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  if !spec.volumes.iter().any(|v| v.from_service.is_some()) {
    return Ok(());
  }
  if spec.backup.is_some()
    && spec.volumes.iter().all(|v| v.from_service.is_some())
  {
    return Err(
      ApiError::invalid(format!(
        "服务 {name} 只挂载共享卷，没有自有数据目录"
      ))
      .with_hint("请在被引用数据的拥有者服务上开启备份"),
    );
  }
  let mut targets = BTreeSet::new();
  for v in &spec.volumes {
    if let Some(raw) = &v.from_service {
      let (owner, _) = parse_ref(raw)?;
      if owner == name {
        return Err(
          ApiError::invalid(format!(
            "服务 {name} 的卷 {} 不能引用自己",
            v.name
          ))
          .with_hint("挂载自有卷只需填写 name 和 target"),
        );
      }
    }
    if let Some(path) =
      crate::render::normalized_mount_target(&v.target)
      && !targets.insert(path)
    {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的卷挂载点 {} 重复",
        v.target
      )));
    }
  }
  Ok(())
}

pub fn validate_world(world: &World) -> Result<(), ApiError> {
  let mut owned = BTreeMap::new();
  for (name, row) in &world.services {
    for v in &row.spec.volumes {
      let Some(raw) = &v.from_service else { continue };
      let (owner, vol) = parse_ref(raw)?;
      let other = world.services.get(owner).ok_or_else(|| {
        ApiError::invalid(format!(
          "服务 {name} 的共享卷 {} 引用的服务 {owner} 不存在",
          v.name
        ))
        .with_hint(format!(
          "先移除 {name} 对 {owner} 的共享卷引用，或一起删除"
        ))
        .suggest("wharf service list")
      })?;
      if other.spec.server != row.spec.server {
        return Err(ApiError::invalid(format!("服务 {name}（{}）与共享卷 {raw} 的拥有者（{}）不在同一台机器", row.spec.server, other.spec.server))
          .with_hint("把两个服务放到同一台机器，或在一次变更中一起迁移"));
      }
      if let Some(upstream) = other
        .spec
        .volumes
        .iter()
        .find(|v| v.name == vol)
        .and_then(|v| v.from_service.as_deref())
      {
        return Err(
          ApiError::invalid(format!(
            "服务 {name} 不能链式引用共享卷 {raw}"
          ))
          .with_hint(format!("直接引用 {upstream}")),
        );
      }
      let available = owned
        .entry(owner)
        .or_insert_with(|| owned_volumes(owner, &other.spec));
      if !available.contains(vol) {
        return Err(ApiError::invalid(format!("服务 {name} 引用的托管卷 {raw} 不存在"))
          .with_hint(format!("可用托管卷：{}。Compose 拥有者需挂载 /srv/{owner}/<卷名> 子目录", available.iter().cloned().collect::<Vec<_>>().join("、"))));
      }
    }
  }
  wharf_api_types::spec::validate_service_dependencies(
    world
      .services
      .iter()
      .map(|(name, row)| (name.as_str(), &row.spec)),
  )
}

pub fn implicit_warnings(
  world: &World,
  name: &str,
  spec: &ServiceSpec,
) -> Vec<String> {
  let Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
  else {
    return Vec::new();
  };
  crate::data::compose_mounts(name, content)
    .into_iter()
    .filter(|m| m.kind == DataKind::ExternalDir && m.source.starts_with("/srv/") && !m.source.contains(['$', '~']))
    .filter_map(|m| {
      let path = crate::render::normalized_mount_target(&m.source)?;
      let mut parts = path.strip_prefix("/srv").ok()?.iter();
      let owner = parts.next()?.to_str()?;
      if owner == name || !world.services.contains_key(owner) {
        return None;
      }
      let source = m.source;
      Some(match parts.next().and_then(|v| v.to_str()).filter(|v| validate_name("数据卷", v).is_ok()) {
        Some(vol) => format!("的 compose 直接挂载了服务 {owner} 的目录 {source}，可由 Image 或 Build 服务声明 from_service = \"{owner}:{vol}\""),
        None => format!("的 compose 直接挂载了服务 {owner} 的目录 {source}，可先把数据拆到子目录，再由 Image 或 Build 服务声明 from_service = \"{owner}:<卷名>\""),
      })
    })
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

pub fn sort_steps(
  steps: &mut [StepPlan],
  current: &World,
  desired: &World,
) {
  for (world, down) in [(desired, false), (current, true)] {
    let slots: Vec<_> = steps
      .iter()
      .enumerate()
      .filter_map(|(i, s)| match &s.step {
        Step::ServiceUp { service, .. } if !down => {
          Some((i, service.clone()))
        }
        Step::ServiceDown { service, .. } if down => {
          Some((i, service.clone()))
        }
        _ => None,
      })
      .collect();
    let mut deps: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (_, service) in &slots {
      let Some(row) = world.services.get(service) else {
        continue;
      };
      for owner in owners(&row.spec) {
        if down {
          deps.entry(owner).or_default().insert(service);
        } else {
          deps.entry(service).or_default().insert(owner);
        }
      }
      if !down {
        for dep in
          row.spec.wait_for.values().filter_map(|wait| wait.service())
        {
          deps.entry(service).or_default().insert(dep);
        }
      }
    }
    if deps.is_empty() {
      continue;
    }
    let mut pending: Vec<_> = slots
      .iter()
      .map(|(i, service)| (steps[*i].clone(), service.clone()))
      .collect();
    for (dest, _) in &slots {
      let first = pending
        .iter()
        .position(|(_, service)| {
          deps.get(service.as_str()).is_none_or(|set| {
            !pending.iter().any(|(_, n)| set.contains(n.as_str()))
          })
        })
        .unwrap_or(0);
      let (src, _) = pending.remove(first);
      steps[*dest] = src;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{render::Net, snapshot::Snapshot};
  use serde_json::json;
  use wharf_api_types::{spec::Change, view::DataStatus};

  fn shared_world() -> World {
    let mut world = World::default();
    world.servers.insert(
      "s1".into(),
      crate::world::ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    for (name, volume) in [
      ("photos", json!({"name":"data","target":"/data"})),
      (
        "reader",
        json!({"from_service":"photos:data","target":"/data"}),
      ),
    ] {
      world.apply_changes(&[Change::UpsertService {
        name: name.into(),
        spec: serde_json::from_value(json!({"server":"s1","source":{"image":"fixture:1"},"volumes":[volume]})).unwrap(),
        adopt: None,
        pins: None,
        commit: None,
        migrate: None,
      }]).unwrap();
    }
    world
  }

  #[test]
  fn wait_edges_order_startup_and_reject_cycles_with_shared_volumes()
  {
    use wharf_api_types::spec::WaitCondition;
    let mut world = shared_world();
    let mut steps: Vec<StepPlan> = ["reader", "photos"]
      .into_iter()
      .map(|service| StepPlan {
        items: vec![],
        title: service.into(),
        step: Step::ServiceUp {
          service: service.into(),
          instance_id: None,
          expect: None,
        },
      })
      .collect();
    world
      .services
      .get_mut("reader")
      .unwrap()
      .spec
      .wait_for
      .insert(
        "available".into(),
        WaitCondition::Service {
          service: "photos".into(),
        },
      );
    validate_world(&world).unwrap();
    sort_steps(&mut steps, &World::default(), &world);
    assert_eq!(steps[0].title, "photos");
    world
      .services
      .get_mut("photos")
      .unwrap()
      .spec
      .wait_for
      .insert(
        "reader".into(),
        WaitCondition::Service {
          service: "reader".into(),
        },
      );
    assert!(
      validate_world(&world)
        .unwrap_err()
        .message
        .contains("photos → reader → photos")
    );
  }

  #[test]
  fn shared_volume_data_status_and_views_deps() {
    let snap = Snapshot {
      world: shared_world(),
      ..Snapshot::default()
    };
    let state = crate::rules::tests::test_state();
    let view = |name| {
      crate::views::service_view(
        &state,
        &snap,
        &Net::default(),
        name,
        None,
        &Default::default(),
      )
      .unwrap()
    };
    let reader = view("reader");
    assert_eq!(reader.uses, ["photos"]);
    assert_eq!(view("photos").used_by, ["reader"]);
    assert_eq!(reader.data[0].kind, DataKind::Shared);
    let now = chrono::Utc::now();
    assert_eq!(
      crate::data::status(false, &reader.data, None, None, now),
      DataStatus::None
    );
    let mut mixed = reader.data;
    mixed.extend(view("photos").data);
    assert_eq!(
      crate::data::status(true, &mixed, Some(now), None, now),
      DataStatus::Ok
    );
  }

  #[test]
  fn batch_delete_keeps_shared_volume_order_with_reverse_env_reference()
   {
    let mut world = shared_world();
    world
      .services
      .get_mut("photos")
      .unwrap()
      .spec
      .env
      .insert("READER".into(), "[[@reader.http]]".into());
    let up = |name: &str| Step::ServiceUp {
      service: name.into(),
      instance_id: None,
      expect: None,
    };
    let down = |name: &str| Step::ServiceDown {
      service: name.into(),
      server: "s1".into(),
      instance_id: None,
      has_relative_mounts: false,
      purge_data: true,
    };
    let mut steps =
      [up("reader"), up("photos"), down("photos"), down("reader")]
        .map(|step| StepPlan {
          items: vec![],
          title: String::new(),
          step,
        });
    sort_steps(&mut steps, &world, &world);
    assert_eq!(
      steps.map(|s| s.step),
      [up("photos"), up("reader"), down("reader"), down("photos")]
    );
  }
}
