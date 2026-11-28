use std::collections::BTreeMap;

use serde_yaml_ng::Value;
use wharf_api_types::{
  agent::{ContainerLimitsDelta, ProjectState},
  spec::{Limits, Source},
  view::Applied,
};

pub(crate) struct Change {
  pub updates: BTreeMap<String, ContainerLimitsDelta>,
  pub images: BTreeMap<String, String>,
}

fn field(
  body: &mut Value,
  direct: &str,
  nested: &str,
) -> Option<Value> {
  let body = body.as_mapping_mut()?;
  let top = body.remove(direct);
  let deploy = body.get_mut("deploy").and_then(Value::as_mapping_mut);
  let Some(deploy) = deploy else { return top };
  let resources =
    deploy.get_mut("resources").and_then(Value::as_mapping_mut);
  let Some(resources) = resources else {
    return top;
  };
  let limits =
    resources.get_mut("limits").and_then(Value::as_mapping_mut);
  let Some(limits) = limits else { return top };
  let from_deploy = limits.remove(nested);
  if from_deploy.is_some() {
    if limits.is_empty() {
      resources.remove("limits");
    }
    if resources.is_empty() {
      deploy.remove("resources");
    }
    if deploy.is_empty() {
      body.remove("deploy");
    }
  }
  from_deploy.or(top)
}

fn milli(value: &Value) -> Option<u32> {
  let cpu =
    value.as_f64().or_else(|| value.as_str()?.parse().ok())? * 1000.0;
  (cpu.is_finite()
    && cpu >= 10.0
    && cpu <= f64::from(u32::MAX)
    && (cpu.round() - cpu).abs() < 0.000001)
    .then_some(cpu.round() as u32)
}

fn memory(value: &Value) -> Option<u32> {
  let mb = value
    .as_u64()
    .map(|bytes| bytes as f64 / (1 << 20) as f64)
    .or_else(|| crate::docker_run::memory_mb(value.as_str()?))?;
  (mb.is_finite()
    && mb >= 32.0
    && mb <= f64::from(u32::MAX)
    && mb.fract() == 0.0)
    .then_some(mb as u32)
}

fn pids(value: &Value) -> Option<u32> {
  value
    .as_u64()
    .and_then(|n| u32::try_from(n).ok())
    .or_else(|| value.as_str()?.parse().ok())
    .filter(|n| *n > 0)
}

type ComponentLimits = BTreeMap<String, (String, [Option<Value>; 3])>;

fn strip_limits(doc: &mut Value) -> Option<ComponentLimits> {
  if doc.get("include").is_some() {
    return None;
  }
  let services = doc.get_mut("services")?.as_mapping_mut()?;
  services
    .iter_mut()
    .map(|(name, body)| {
      if ["extends", "profiles", "env_file", "build"]
        .iter()
        .any(|field| body.get(*field).is_some())
      {
        return None;
      }
      let image = body["image"].as_str()?.to_owned();
      let limits = [
        field(body, "mem_limit", "memory"),
        field(body, "cpus", "cpus"),
        field(body, "pids_limit", "pids"),
      ];
      Some((name.as_str()?.to_owned(), (image, limits)))
    })
    .collect()
}

fn limits_delta(
  old: &[Option<Value>; 3],
  new: &[Option<Value>; 3],
) -> Result<ContainerLimitsDelta, &'static str> {
  let pair = |index: usize, parse: fn(&Value) -> Option<u32>| {
    let (old, new) = (&old[index], &new[index]);
    if old == new {
      return Ok((None, None));
    }
    let old = old
      .as_ref()
      .and_then(parse)
      .ok_or("新增上限或旧值不可验证，需要重建")?;
    let new = new
      .as_ref()
      .and_then(parse)
      .ok_or("清除上限或新值不可验证，需要重建")?;
    Ok::<_, &'static str>(if old == new {
      (None, None)
    } else {
      (Some(old), Some(new))
    })
  };
  let (old_memory, new_memory) = pair(0, memory)?;
  let (old_cpu, new_cpu) = pair(1, milli)?;
  let (old_pids, new_pids) = pair(2, pids)?;
  Ok(ContainerLimitsDelta {
    before: Limits {
      memory_mb: old_memory,
      cpu_milli: old_cpu,
      pids: old_pids,
    },
    after: Limits {
      memory_mb: new_memory,
      cpu_milli: new_cpu,
      pids: new_pids,
    },
  })
}

pub(crate) fn changes(
  before: &str,
  after: &str,
  applied: &Applied,
  live: &ProjectState,
) -> Result<Option<Change>, &'static str> {
  let Some(mut before) = crate::render::parse_compose(before).ok()
  else {
    return Ok(None);
  };
  let Some(mut after) = crate::render::parse_compose(after).ok()
  else {
    return Ok(None);
  };
  let (Some(old), Some(new)) =
    (strip_limits(&mut before), strip_limits(&mut after))
  else {
    return Ok(None);
  };
  if before != after
    || old.keys().ne(new.keys())
    || old.is_empty()
    || old == new
  {
    return Ok(None);
  }
  let mut updates = BTreeMap::new();
  let mut images = BTreeMap::new();
  for (component, (image, limits)) in &new {
    let delta = limits_delta(&old[component].1, limits)?;
    if !delta.before.is_empty() {
      updates.insert(component.clone(), delta);
    }
    let Some(id) = applied.image_ids.get(image).or_else(|| {
      (applied.image.as_ref() == Some(image))
        .then_some(applied.image_id.as_ref())
        .flatten()
    }) else {
      return Err("无法验证上次部署的镜像，需要重建");
    };
    images.insert(component.clone(), id.clone());
  }
  if live.containers.is_empty()
    || live.containers.iter().any(|c| {
      !c.is_running()
        || c
          .health
          .as_deref()
          .is_some_and(|status| status != "healthy")
        || !images.contains_key(&c.service)
    })
    || images
      .keys()
      .any(|name| !live.containers.iter().any(|c| &c.service == name))
  {
    return Err("容器不齐或没有健康运行，需要重建");
  }
  Ok((!updates.is_empty()).then_some(Change { updates, images }))
}

pub(crate) fn mentions_limits(compose: &str) -> bool {
  let Ok(value) = crate::render::parse_compose(compose) else {
    return true;
  };
  value["services"].as_mapping().is_none_or(|services| {
    services.values().any(|body| {
      ["mem_limit", "cpus", "pids_limit"]
        .iter()
        .any(|field| body.get(*field).is_some())
        || body["deploy"]["resources"].get("limits").is_some()
    })
  })
}

pub(crate) fn same_source_inputs(old: &Source, new: &Source) -> bool {
  match (old, new) {
    (
      Source::Compose { file: old, .. },
      Source::Compose { file: new, .. },
    ) => old == new,
    (old, new) => old == new,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn positive_cpu_changes_require_reversible_values() {
    let from =
      [None, Some(serde_yaml_ng::to_value("0.5").unwrap()), None];
    let to =
      [None, Some(serde_yaml_ng::to_value("0.75").unwrap()), None];
    let delta = limits_delta(&from, &to).unwrap();
    assert_eq!(
      (delta.before.cpu_milli, delta.after.cpu_milli),
      (Some(500), Some(750))
    );
    assert!(limits_delta(&from, &[None, None, None]).is_err());
  }
}
