use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use serde_yaml_ng::Value;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  adopt_data::*,
  agent::AgentOp,
  plan::{Action, Impact, Layer},
  spec::{ServiceSpec, Source},
  validate_name,
  view::DataKind,
};

use crate::{
  hub::ProgressFn,
  planner::{Builder, Step},
  snapshot::Snapshot,
  state::AppState,
  world::World,
};

type Selection = (Vec<AdoptSourceItem>, Vec<String>, String);

pub(crate) fn select_candidates(
  name: &str,
  spec: &ServiceSpec,
  overrides: &[AdoptMountSpec],
  ignored: &BTreeSet<String>,
) -> Result<Selection, ApiError> {
  let Source::Compose {
    content: Some(yaml),
    ..
  } = &spec.source
  else {
    return Err(ApiError::invalid(
      "该服务没有可收编的 compose 数据卷",
    ));
  };
  let mut doc = crate::render::parse_compose(yaml)?;
  let declared = crate::data::mounts(name, spec);
  let top = doc.get("volumes").cloned();
  let mut used: BTreeSet<_> = declared
    .iter()
    .filter(|m| m.kind == DataKind::Managed)
    .filter_map(|m| {
      m.source
        .strip_prefix(&format!("/srv/{name}/"))
        .and_then(|p| p.split('/').next())
        .map(str::to_string)
    })
    .collect();
  let mut selected =
    BTreeMap::<(AdoptSourceKind, String), AdoptSourceItem>::new();
  let mut matched = BTreeSet::new();
  let has_explicit = overrides.iter().any(|m| !m.rename_only);
  let mut warnings = Vec::new();
  let mut top_keys = BTreeSet::new();
  let Some(services) =
    doc.get_mut("services").and_then(Value::as_mapping_mut)
  else {
    return Err(ApiError::invalid("compose 缺少 services"));
  };
  let mut still_used = BTreeSet::new();
  for (component, config) in services.iter_mut() {
    let Some(component) = component.as_str() else {
      continue;
    };
    let Some(mounts) =
      config.get_mut("volumes").and_then(Value::as_sequence_mut)
    else {
      continue;
    };
    for mount in mounts {
      let Some((raw_source, target, ro)) = mount_parts(mount) else {
        continue;
      };
      let actual = declared.iter().find(|m| {
        m.container.as_deref() == Some(component)
          && m.target == target
      });
      let kind = match actual.map(|m| m.kind) {
        Some(DataKind::ExternalDir) => AdoptSourceKind::ExternalDir,
        Some(DataKind::NamedVolume) if !raw_source.is_empty() => {
          AdoptSourceKind::NamedVolume
        }
        _ => {
          if raw_source.is_empty() {
            warnings.push(format!(
              "{component}:{target} 是匿名卷，请先在 compose 声明"
            ));
          }
          continue;
        }
      };
      let Some(actual) = actual else {
        continue;
      };
      let mut source =
        actual.source.trim_end_matches('/').to_string();
      if kind == AdoptSourceKind::NamedVolume
        && source == raw_source
        && top
          .as_ref()
          .and_then(|top| top.get(raw_source.as_str()))
          .is_none_or(|def| {
            def.get("name").is_none()
              && def.get("external").is_none_or(|external| {
                external.as_bool() == Some(false)
              })
          })
      {
        source = format!("{name}_{raw_source}");
      }
      if kind == AdoptSourceKind::ExternalDir && source.is_empty() {
        source.push('/');
      }
      let mut explicit = false;
      let mut rename = None;
      for (index, selector) in overrides.iter().enumerate() {
        if selector.target.as_deref() == Some(target.as_str())
          || selector.source.as_deref().is_some_and(|s| {
            [raw_source.as_str(), source.as_str()].contains(&s)
          })
        {
          matched.insert(index);
          explicit |= !selector.rename_only;
          if let Some(requested) = selector.volume_name.as_deref()
            && rename
              .replace(requested)
              .is_some_and(|previous| previous != requested)
          {
            return Err(ApiError::invalid(
              "同一挂载不能指定多个目标卷名",
            ));
          }
        }
      }
      if !explicit && (ro || has_explicit) {
        if ro {
          warnings.push(format!("跳过只读挂载 {component}:{target}"));
        }
        if kind == AdoptSourceKind::NamedVolume {
          still_used.insert(raw_source);
        }
        continue;
      }
      let key = (kind, source.clone());
      if let Some(existing) = selected.get(&key)
        && rename.is_some_and(|name| name != existing.volume_name)
      {
        return Err(ApiError::invalid("同一源挂载的目标卷名须一致"));
      }
      let volume_name = if let Some(item) = selected.get(&key) {
        item.volume_name.clone()
      } else {
        let base = if kind == AdoptSourceKind::NamedVolume {
          raw_source
            .strip_prefix(&format!("{name}_"))
            .unwrap_or(&raw_source)
        } else {
          target
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("data")
        };
        let base = rename.map_or_else(
          || crate::import::service_name(base),
          str::to_string,
        );
        let base = if base.is_empty() { "data".into() } else { base };
        validate_name("卷", &base)?;
        let mut volume = base.clone();
        let mut index = 2;
        while used.contains(&volume) {
          if rename.is_some() {
            return Err(ApiError::invalid(format!(
              "目标卷 {volume} 已存在"
            )));
          }
          let stem = base.chars().take(39).collect::<String>();
          volume = format!("{stem}-{index}");
          index += 1;
        }
        volume
      };
      let item = AdoptSourceItem {
        kind,
        source,
        target: target.clone(),
        volume_name,
        read_only: ro,
      };
      if let Err(error) = item.validate() {
        if explicit {
          return Err(error);
        }
        warnings.push(format!(
          "跳过挂载 {component}:{target}：{}",
          error.message
        ));
        if kind == AdoptSourceKind::NamedVolume {
          still_used.insert(raw_source);
        }
        continue;
      }
      used.insert(item.volume_name.clone());
      if ignored.contains(&item.source) {
        if explicit {
          return Err(ApiError::invalid(
            "单文件挂载无法收编，请用 wharf service upload/download 处理",
          ));
        }
        warnings.push(format!("跳过单文件挂载 {component}:{target}，请用 wharf service upload/download"));
        selected.entry(key).or_insert(item);
        continue;
      }
      let path = format!("/srv/{name}/{}", item.volume_name);
      if let Some(raw) = mount.as_str() {
        let options = raw
          .splitn(3, ':')
          .nth(2)
          .map_or(String::new(), |s| format!(":{s}"));
        *mount = Value::String(format!("{path}:{target}{options}"));
      } else if let Some(map) = mount.as_mapping_mut() {
        map.insert(
          Value::String("source".into()),
          Value::String(path),
        );
        map.insert(
          Value::String("type".into()),
          Value::String("bind".into()),
        );
        map.remove("volume");
      }
      if kind == AdoptSourceKind::NamedVolume {
        top_keys.insert(raw_source);
      }
      selected.entry(key).or_insert(item);
    }
  }
  if matched.len() != overrides.len() {
    return Err(ApiError::invalid(
      "部分 --mount 或 --rename 未匹配可收编的挂载",
    ));
  }
  if let Some(top) =
    doc.get_mut("volumes").and_then(Value::as_mapping_mut)
  {
    for key in top_keys.difference(&still_used) {
      top.remove(key.as_str());
    }
    if top.is_empty()
      && let Some(doc) = doc.as_mapping_mut()
    {
      doc.remove("volumes");
    }
  }
  let yaml = serde_yaml_ng::to_string(&doc)
    .map_err(|_| ApiError::invalid("无法改写 compose 挂载"))?;
  Ok((
    selected
      .into_values()
      .filter(|item| !ignored.contains(&item.source))
      .collect(),
    warnings,
    yaml,
  ))
}

fn mount_parts(mount: &Value) -> Option<(String, String, bool)> {
  if let Some(raw) = mount.as_str() {
    let mut parts = raw.splitn(3, ':');
    let first = parts.next()?;
    let Some(target) = parts.next() else {
      return Some((String::new(), first.into(), false));
    };
    return Some((
      first.into(),
      target.into(),
      parts
        .next()
        .is_some_and(|part| part.split(',').any(|s| s == "ro")),
    ));
  }
  let target = mount.get("target")?.as_str()?;
  let source = mount
    .get("source")
    .and_then(Value::as_str)
    .unwrap_or_default();
  let read_only = mount
    .get("read_only")
    .and_then(Value::as_bool)
    .unwrap_or(false);
  Some((source.into(), target.into(), read_only))
}

pub(crate) async fn prepare(
  state: &AppState,
  snap: &Snapshot,
  desired: &mut World,
  name: &str,
  overrides: &[AdoptMountSpec],
  admin: bool,
) -> Result<(AdoptDataJob, Vec<String>), ApiError> {
  if !admin {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "收编外部数据需要管理权限",
    ));
  }
  if snap.pending.migrations.contains_key(name)
    || snap.pending.adopt_data.contains_key(name)
  {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "服务已有未完成的数据操作",
    ));
  }
  let row = desired
    .services
    .get_mut(name)
    .ok_or_else(|| crate::api::service_not_found(name))?;
  let settings = &desired
    .servers
    .get(&row.spec.server)
    .ok_or_else(|| crate::world::server_not_found(&row.spec.server))?
    .settings;
  if !settings.host_docker {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "收编数据需要先启用服务器的宿主机 Docker 开关",
    ));
  }
  let source = snap
    .applied
    .get(name)
    .and_then(|a| a.spec.as_ref())
    .unwrap_or(&row.spec);
  if source.source != row.spec.source
    || source.server != row.spec.server
  {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "服务配置尚未应用，先完成部署再收编数据",
    ));
  }
  let (items, mut warnings, mut content) =
    select_candidates(name, &row.spec, overrides, &BTreeSet::new())?;
  let mut nonce = [0; 16];
  getrandom::fill(&mut nonce)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  let mut job = AdoptDataJob {
    service: name.into(),
    items,
    nonce: hex::encode(nonce),
  };
  let conn = state.hub.require_data_ops(&row.spec.server)?;
  let cancel = CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  let inspected: AdoptDataInspectResult = state
    .hub
    .call_bound(
      (&row.spec.server, conn),
      AgentOp::AdoptDataInspect(job.clone()),
      Duration::from_secs(30),
      None,
      &cancel,
    )
    .await?;
  let single_file = inspected
    .entries
    .iter()
    .filter(|e| e.is_dir == Some(false))
    .map(|e| e.volume_name.as_str())
    .collect::<BTreeSet<_>>();
  if !single_file.is_empty() {
    let ignored = job
      .items
      .iter()
      .filter(|item| single_file.contains(item.volume_name.as_str()))
      .map(|item| item.source.clone())
      .collect();
    let (items, fresh_warnings, yaml) =
      select_candidates(name, &row.spec, overrides, &ignored)?;
    job.items = items;
    warnings = fresh_warnings;
    content = yaml;
  }
  warnings.extend(anonymous_warnings(
    name,
    &row.spec,
    &inspected.mounts,
  ));
  check_inspect(&inspected)?;
  if job.items.is_empty() {
    warnings.push(format!("服务 {name} 没有符合条件的外部数据卷"));
    return Ok((job, warnings));
  }
  row.spec.source = Source::Compose {
    content: Some(content),
    file: None,
  };
  warnings.push(format!("收编 {name} 后保留原目录和命名卷"));
  Ok((job, warnings))
}

fn anonymous_warnings(
  service: &str,
  spec: &ServiceSpec,
  actual: &[wharf_api_types::agent::ContainerMount],
) -> Vec<String> {
  crate::data::undeclared_mounts(
    service,
    &crate::data::mounts(service, spec),
    actual,
  )
  .into_iter()
  .filter(|mount| {
    mount.kind == DataKind::NamedVolume && mount.source.is_empty()
  })
  .map(|mount| {
    format!(
      "跳过镜像自带的匿名卷 {}:{}，请先在 compose 声明",
      mount.container.as_deref().unwrap_or(service),
      mount.target
    )
  })
  .collect()
}

fn check_inspect(
  inspected: &AdoptDataInspectResult,
) -> Result<(), ApiError> {
  let mut size = 0_u64;
  for entry in &inspected.entries {
    if entry.is_dir == Some(false) {
      continue;
    }
    size = size.saturating_add(entry.size_bytes);
    if !entry.in_use_by.is_empty() {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        format!(
          "数据卷 {} 仍被容器占用：{}",
          entry.volume_name,
          entry.in_use_by.join("、")
        ),
      ));
    }
    if entry.target_exists_nonempty {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("目标数据卷 {} 非空", entry.volume_name),
        )
        .with_hint("用 --rename 选择其他卷名"),
      );
    }
  }
  const MIB: u64 = 1 << 20;
  let required =
    size.saturating_add(size / 10).saturating_add(100 * MIB);
  if size > 0 && inspected.srv_avail_bytes < required {
    return Err(
      ApiError::invalid(format!(
        "收编数据需 {required} 字节，目标盘仅剩 {} 字节",
        inspected.srv_avail_bytes
      ))
      .with_details(serde_json::json!({
        "source_bytes": size, "required_bytes": required,
        "target_avail_bytes": inspected.srv_avail_bytes,
      })),
    );
  }
  Ok(())
}

pub(crate) fn add_step(
  b: &mut Builder,
  world: &World,
  job: AdoptDataJob,
) {
  let name = &job.service;
  let Some(row) = world.services.get(name) else {
    return;
  };
  let id = b.item(format!("service/{name}"), Layer::Volume, Action::Update,
    None, Some(serde_json::json!({ "volumes": job.items.iter().map(|v| &v.volume_name).collect::<Vec<_>>() })),
    if row.spec.stopped { vec![] } else { vec![Impact::Downtime] },
    "收编外部数据卷，保留原数据");
  b.step(
    vec![id],
    format!("收编 {name} 的数据卷"),
    Step::AdoptData {
      server: row.spec.server.clone(),
      instance_id: Some(row.instance_id.clone()),
      job,
    },
  );
}

pub(crate) async fn execute(
  state: &AppState,
  server: &str,
  job: &AdoptDataJob,
  stopped: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let conn = state.hub.require_data_ops(server)?;
  let inspection: AdoptDataInspectResult = state
    .hub
    .call_bound(
      (server, conn),
      AgentOp::AdoptDataInspect(job.clone()),
      Duration::from_secs(30),
      None,
      cancel,
    )
    .await?;
  if inspection.entries.iter().any(|e| e.is_dir == Some(false)) {
    return Err(ApiError::invalid(
      "收编源已变成单文件，请重新生成计划",
    ));
  }
  check_inspect(&inspection)?;
  let service = &job.service;
  let result = async {
    if !stopped {
      let _: bool = crate::apply::call_with_stop_timeout(
        state,
        (server, service),
        AgentOp::ProjectStop {
          project: service.clone(),
        },
        Duration::from_secs(300),
        progress,
        cancel,
      )
      .await?;
    }
    let _: serde_json::Value = state
      .hub
      .call_bound(
        (server, conn),
        AgentOp::AdoptDataCopy(job.clone()),
        Duration::from_secs(4 * 3600),
        Some(progress.clone()),
        cancel,
      )
      .await?;
    Ok(())
  }
  .await;
  if result.is_err() && !stopped {
    crate::migrate::restart_source(state, server, service, progress)
      .await;
  }
  result
}

#[cfg(test)]
fn fixture_spec(content: &str) -> ServiceSpec {
  serde_json::from_value(serde_json::json!({
    "server": "s1", "source": { "compose": { "content": content }}
  }))
  .unwrap()
}

#[test]
fn adopt_data_skips_unsafe_mounts_unless_explicit() {
  let spec = fixture_spec(
    "services: {app: {volumes: ['/opt/app:/data:z', '/var/run/docker.sock:/docker.sock', './conf:/conf', '/srv/other/data:/shared']}}",
  );
  let (items, warnings, yaml) =
    select_candidates("app", &spec, &[], &BTreeSet::new()).unwrap();
  assert_eq!(items.len(), 1);
  assert_eq!(warnings.len(), 3);
  assert!(yaml.contains("/srv/app/data:/data:z"));
  let explicit = AdoptMountSpec {
    target: Some("/docker.sock".into()),
    source: None,
    volume_name: None,
    rename_only: false,
  };
  assert!(
    select_candidates("app", &spec, &[explicit], &BTreeSet::new())
      .is_err()
  );
}

#[test]
fn adopt_data_rename_preserves_selection_and_combines_aliases() {
  let spec = fixture_spec(
    "services: {app: {volumes: ['/opt/a:/data', '/opt/b:/logs', '/opt/config:/config']}}",
  );
  let rename = AdoptMountSpec {
    target: Some("/data".into()),
    source: None,
    volume_name: Some("data2".into()),
    rename_only: true,
  };
  let ignored = BTreeSet::from(["/opt/config".into()]);
  let (items, warnings, _) = select_candidates(
    "app",
    &spec,
    std::slice::from_ref(&rename),
    &ignored,
  )
  .unwrap();
  assert_eq!(
    items
      .iter()
      .map(|item| item.volume_name.as_str())
      .collect::<Vec<_>>(),
    ["data2", "logs"]
  );
  assert!(warnings.iter().any(|w| w.contains("单文件")));
  let select = AdoptMountSpec {
    target: None,
    source: Some("/opt/a".into()),
    volume_name: None,
    rename_only: false,
  };
  let (items, _, _) =
    select_candidates("app", &spec, &[select, rename], &ignored)
      .unwrap();
  assert_eq!(items.len(), 1);
  assert_eq!(items[0].volume_name, "data2");
}

#[test]
fn adopt_data_resolves_legacy_external_volume_name() {
  let spec = fixture_spec(
    "services: {app: {volumes: [{type: volume, source: old_vol, target: /db}]}}\nvolumes: {old_vol: {external: {name: real-vol}}}",
  );
  let (items, _, yaml) =
    select_candidates("app", &spec, &[], &BTreeSet::new()).unwrap();
  assert_eq!(items[0].source, "real-vol");
  assert!(yaml.contains("/srv/app/old-vol"));
}

#[test]
fn adopt_data_checks_total_space_and_reports_undeclared_anonymous_volumes()
 {
  use serde_json::json;
  const MIB: u64 = 1 << 20;
  let entries = ["data", "logs"].map(|volume_name| json!({
    "volume_name": volume_name, "size_bytes": 100 * MIB, "is_dir": true,
    "target_exists_nonempty": false, "in_use_by": []
  }));
  let inspected: AdoptDataInspectResult = serde_json::from_value(json!({
    "srv_avail_bytes": 300 * MIB,
    "entries": entries,
    "mounts": [{"container": "app-db-1", "service": "db", "kind": "volume",
      "source": "a".repeat(64), "target": "/var/lib/db"}]
  })).unwrap();
  assert_eq!(
    check_inspect(&inspected).unwrap_err().details.unwrap()["required_bytes"],
    320 * MIB
  );
  let spec = fixture_spec("services: {db: {image: fixture:1}}");
  let warnings = anonymous_warnings("app", &spec, &inspected.mounts);
  assert_eq!(warnings.len(), 1);
  assert!(warnings[0].contains("db:/var/lib/db"));
}
