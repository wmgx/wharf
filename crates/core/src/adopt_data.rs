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
      let override_entry =
        overrides.iter().enumerate().find(|(_, select)| {
          select.target.as_deref() == Some(target.as_str())
            || select.source.as_deref() == Some(raw_source.as_str())
        });
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
      let override_entry = override_entry.or_else(|| {
        overrides.iter().enumerate().find(|(_, select)| {
          select.source.as_deref() == Some(actual.source.as_str())
        })
      });
      if let Some((index, _)) = override_entry {
        matched.insert(index);
      }
      if override_entry.is_none() && (ro || !overrides.is_empty()) {
        if ro {
          warnings.push(format!("跳过只读挂载 {component}:{target}"));
        }
        if kind == AdoptSourceKind::NamedVolume {
          still_used.insert(raw_source);
        }
        continue;
      }
      let rename = override_entry
        .and_then(|(_, opt)| opt.volume_name.as_deref());
      let mut source =
        actual.source.trim_end_matches('/').to_string();
      if kind == AdoptSourceKind::NamedVolume {
        let def =
          top.as_ref().and_then(|top| top.get(raw_source.as_str()));
        if let Some(named) =
          def.and_then(|def| def.get("name")).and_then(Value::as_str)
        {
          source = named.into();
        } else if !def
          .and_then(|def| def.get("external"))
          .and_then(Value::as_bool)
          .unwrap_or(false)
        {
          source = format!("{name}_{raw_source}");
        }
      }
      if kind == AdoptSourceKind::ExternalDir && source.is_empty() {
        source.push('/');
      }
      if kind == AdoptSourceKind::ExternalDir
        && ignored.contains(&source)
      {
        warnings.push(format!("跳过单文件挂载 {component}:{target}"));
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
        used.insert(volume.clone());
        volume
      };
      let item = AdoptSourceItem {
        kind,
        source,
        target: target.clone(),
        volume_name,
        read_only: ro,
      };
      item.validate()?;
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
  Ok((selected.into_values().collect(), warnings, yaml))
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
  if items.is_empty() {
    warnings.push(format!("服务 {name} 没有符合条件的外部数据卷"));
    return Ok((
      AdoptDataJob {
        service: name.into(),
        items,
        nonce: String::new(),
      },
      warnings,
    ));
  }
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
  let inspected: Vec<AdoptInspectEntry> = state
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
    .iter()
    .filter(|e| e.is_dir == Some(false))
    .map(|e| e.volume_name.as_str())
    .collect::<BTreeSet<_>>();
  if !single_file.is_empty() {
    if !overrides.is_empty() {
      return Err(ApiError::invalid(
        "单文件挂载无法收编，请用 wharf service upload/download 处理",
      ));
    }
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
  check_inspect(
    &inspected
      .into_iter()
      .filter(|e| e.is_dir != Some(false))
      .collect::<Vec<_>>(),
  )?;
  if job.items.is_empty() {
    return Ok((job, warnings));
  }
  row.spec.source = Source::Compose {
    content: Some(content),
    file: None,
  };
  warnings.push(format!("收编 {name} 后保留原目录和命名卷"));
  Ok((job, warnings))
}

pub(crate) fn check_inspect(
  entries: &[AdoptInspectEntry],
) -> Result<(), ApiError> {
  for entry in entries {
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
  let inspection: Vec<AdoptInspectEntry> = state
    .hub
    .call_bound(
      (server, conn),
      AgentOp::AdoptDataInspect(job.clone()),
      Duration::from_secs(30),
      None,
      cancel,
    )
    .await?;
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

#[test]
fn adopt_data_rewrites_short_and_long_mounts_and_rejects_system_path()
{
  let mut spec: ServiceSpec = serde_json::from_value(serde_json::json!({
    "server": "s1", "source": { "compose": { "content":
      "services: {app: {volumes: ['/opt/data:/data:z', {type: volume, source: old_vol, target: /db}]}}\nvolumes: {old_vol: {name: external-vol}}"
    }}
  })).unwrap();
  let (items, _, yaml) =
    select_candidates("app", &spec, &[], &BTreeSet::new()).unwrap();
  assert_eq!(items.len(), 2);
  assert!(
    yaml.contains("/srv/app/data:/data:z")
      && yaml.contains("/srv/app/old-vol")
  );
  if let Source::Compose { content, .. } = &mut spec.source {
    *content =
      Some("services: {app: {volumes: ['/etc:/config']}}".into());
  }
  assert!(
    select_candidates("app", &spec, &[], &BTreeSet::new()).is_err()
  );
}
