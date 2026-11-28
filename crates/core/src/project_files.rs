use std::{
  collections::{BTreeMap, BTreeSet},
  path::Path,
};

use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::ProjectFile,
  spec::{
    FileSpec, ServiceSpec, Source, parse_file_mode, parse_uid_gid,
  },
};

use crate::{
  render::{self, Net, normalized_mount_target},
  world::World,
};

pub(crate) fn needs_agent(spec: &ServiceSpec) -> bool {
  spec.files.iter().any(FileSpec::needs_agent)
    || spec.volumes.iter().any(|v| v.owner.is_some())
}

pub(crate) fn exec_changed(
  old: Option<&ServiceSpec>,
  new: &ServiceSpec,
) -> bool {
  new.files.iter().any(|file| {
    file
      .on_change
      .as_deref()
      .is_some_and(|c| c.starts_with("exec:"))
      && old.is_none_or(|old| {
        !old.files.contains(file)
          || old.container != new.container
          || old.server != new.server
      })
  })
}

fn directory(
  service: &str,
  instance: &str,
  file: &FileSpec,
) -> String {
  let parent =
    Path::new(&file.path).parent().expect("已校验绝对路径");
  let digest =
    render::hash(&format!("{instance}:{}", parent.display()));
  if file.init_only {
    format!("/srv/{service}/.wharf-init/{}", &digest[..24])
  } else {
    format!("./.wharf-hot/{}", &digest[..24])
  }
}

fn dedicated(path: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("配置文件 {path} 需要独立目录"),
  )
  .with_hint("选择应用专用目录，并核对现有挂载与镜像文件")
}

pub(crate) fn validate(
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  let mut parents = BTreeMap::new();
  for file in &spec.files {
    if file
      .mode
      .as_deref()
      .is_some_and(|mode| parse_file_mode(mode).is_none())
      || file
        .owner
        .as_deref()
        .is_some_and(|owner| parse_uid_gid(owner).is_none())
    {
      return Err(
        ApiError::invalid(format!(
          "配置文件 {} 的权限或属主格式不对",
          file.path
        ))
        .with_hint("mode 用 0600，owner 用 1000:1000"),
      );
    }
    if let Some(action) =
      file.on_change.as_deref().filter(|v| *v != "recreate")
      && (file.init_only
        || (action != "sighup"
          && !action.strip_prefix("exec:").is_some_and(|command| {
            !command.trim().is_empty()
              && command.len() <= 4096
              && !command.contains('\0')
          })))
    {
      return Err(
        ApiError::invalid(format!(
          "配置文件 {} 的重载动作不合法",
          file.path
        ))
        .with_hint(
          "首次文件不能重载；可用 recreate、sighup 或 exec:<命令>",
        ),
      );
    }
    if !file.managed_dir() {
      continue;
    }
    let parent = Path::new(&file.path)
      .parent()
      .ok_or_else(|| dedicated(&file.path))?;
    if parent.components().count() < 3
      || file.path.contains("//")
      || [
        "/dev",
        "/proc",
        "/sys",
        "/bin",
        "/sbin",
        "/usr",
        "/lib",
        "/lib64",
        "/boot",
        "/root",
        "/etc",
        "/srv",
        "/var/run",
        "/var/lib",
        "/run/wharf-secrets",
      ]
      .iter()
      .any(|base| parent.starts_with(base))
    {
      return Err(dedicated(&file.path));
    }
    let ids = file
      .owner
      .as_deref()
      .and_then(parse_uid_gid)
      .unwrap_or_default();
    let key =
      (file.init_only, if file.init_only { ids } else { (0, 0) });
    if parents
      .insert(parent, key)
      .is_some_and(|existing| existing != key)
    {
      return Err(dedicated(&file.path));
    }
    if spec.volumes.iter().any(|volume| {
      normalized_mount_target(&volume.target).is_some_and(|target| {
        target.starts_with(parent) || parent.starts_with(target)
      })
    }) {
      return Err(dedicated(&file.path));
    }
  }
  for parent in parents.keys() {
    if parents
      .keys()
      .any(|other| other != parent && other.starts_with(parent))
      || spec
        .files
        .iter()
        .filter(|f| !f.managed_dir())
        .any(|file| Path::new(&file.path).starts_with(parent))
    {
      return Err(dedicated(&parent.display().to_string()));
    }
  }
  if spec.files.iter().any(FileSpec::managed_dir)
    && let Source::Compose {
      content: Some(text),
      ..
    } = &spec.source
  {
    let target =
      render::compose_target(name, text, spec.container.as_deref())?;
    let doc = render::parse_compose_template(text)?;
    if !doc["services"][target.as_str()]["volumes_from"].is_null() {
      return Err(ApiError::invalid(
        "首次文件和热重载目录不能与 volumes_from 混用",
      ));
    }
  }
  Ok(())
}

pub(crate) fn compose(
  name: &str,
  instance: &str,
  spec: &ServiceSpec,
  text: String,
) -> Result<String, ApiError> {
  if !spec.files.iter().any(FileSpec::managed_dir) {
    return Ok(text);
  }
  let component =
    render::compose_target(name, &text, spec.container.as_deref())?;
  let mut doc = render::parse_compose(&text)?;
  let service = &mut doc["services"][component.as_str()];
  let mut targets = BTreeSet::new();
  for kind in ["volumes", "configs", "secrets", "tmpfs"] {
    let entries = match &service[kind] {
      Value::Sequence(entries) => entries.as_slice(),
      entry @ Value::String(_) if kind == "tmpfs" => {
        std::slice::from_ref(entry)
      }
      _ => continue,
    };
    for entry in entries {
      let target = if let Some(s) = entry.as_str() {
        if kind == "volumes" {
          s.split(':')
            .find(|part| part.starts_with('/'))
            .unwrap_or("")
            .to_string()
        } else if kind == "tmpfs" {
          s.split(':').next().unwrap_or_default().to_string()
        } else if kind == "secrets" {
          format!("/run/secrets/{s}")
        } else {
          format!("/{s}")
        }
      } else {
        entry["target"].as_str().unwrap_or_default().to_string()
      };
      if let Some(path) = normalized_mount_target(&target) {
        targets.insert(path);
      }
    }
  }
  let mut volumes = service["volumes"]
    .as_sequence()
    .cloned()
    .unwrap_or_default();
  let mut mounted = BTreeSet::new();
  for file in spec.files.iter().filter(|f| f.managed_dir()) {
    let parent = Path::new(&file.path)
      .parent()
      .ok_or_else(|| dedicated(&file.path))?;
    if targets.iter().any(|path| {
      path.starts_with(parent) || parent.starts_with(path)
    }) {
      return Err(dedicated(&file.path));
    }
    if !mounted.insert(parent) {
      continue;
    }
    let bind = serde_yaml_ng::to_value(serde_json::json!({
      "type": "bind", "source": directory(name, instance, file), "target": parent,
      "read_only": !file.init_only, "bind": {"create_host_path": false}
    })).map_err(|_| dedicated(&file.path))?;
    volumes.push(bind);
  }
  if !service.is_mapping() {
    *service = Value::Mapping(Mapping::new());
  }
  service["volumes"] = Value::Sequence(volumes);
  serde_yaml_ng::to_string(&doc)
    .map_err(|_| ApiError::internal("无法渲染配置目录挂载"))
}

pub(crate) fn resolved(
  world: &World,
  net: &Net,
  name: &str,
  compose: &str,
  secrets: &BTreeMap<String, String>,
) -> Result<Vec<ProjectFile>, ApiError> {
  let row = &world.services[name];
  let spec = &row.spec;
  if !spec.files.iter().any(FileSpec::needs_agent) {
    return Ok(Vec::new());
  }
  let component =
    render::compose_target(name, compose, spec.container.as_deref())?;
  spec
    .files
    .iter()
    .filter(|file| file.needs_agent())
    .map(|file| {
      let dir = file
        .managed_dir()
        .then(|| directory(name, &row.instance_id, file));
      let mut spec = file.clone();
      spec.content = if dir.is_some() {
        crate::snapshot::render_config_file(
          world,
          net,
          name,
          file,
          Some(secrets),
          &mut BTreeSet::new(),
        )?
      } else {
        String::new()
      };
      Ok(ProjectFile {
        spec,
        directory: dir,
        component: component.clone(),
      })
    })
    .collect()
}

pub(crate) fn fingerprint(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
  hash: String,
) -> Result<String, ApiError> {
  let mut files = Vec::new();
  for file in world.services[name]
    .spec
    .files
    .iter()
    .filter(|f| f.managed_dir())
  {
    let mut file = file.clone();
    file.content = crate::snapshot::render_config_file(
      world,
      net,
      name,
      &file,
      Some(secrets),
      &mut BTreeSet::new(),
    )?;
    files.push(file);
  }
  if files.is_empty() {
    return Ok(hash);
  }
  let files =
    serde_json::to_string(&files).map_err(crate::db::json_err)?;
  Ok(render::hash(&format!("{hash}\n# wharf.files={files}")))
}

pub(crate) fn only_managed_changed(
  old: &ServiceSpec,
  new: &ServiceSpec,
) -> bool {
  if old.files == new.files
    || old.files.len() != new.files.len()
    || old.stopped != new.stopped
  {
    return false;
  }
  let mut rest = new.clone();
  rest.files.clone_from(&old.files);
  rest == *old
    && old.files.iter().zip(&new.files).all(|(before, after)| {
      before == after
        || (before.path == after.path
          && before.managed_dir()
          && after.managed_dir()
          && before.init_only == after.init_only)
    })
}

#[test]
fn file_content_changes_keep_a_stable_dedicated_bind() {
  let spec = |text| {
    serde_json::from_value::<ServiceSpec>(serde_json::json!({
    "server": "s1", "source": {"image": "alpine"},
    "files": [{"path": "/app/config/current.json", "on_change": "sighup", "content": text}]
  })).unwrap()
  };
  let old = spec("A");
  let new = spec("B");
  let yaml = "services: {app: {image: alpine}}".to_string();
  assert!(only_managed_changed(&old, &new));
  assert_eq!(
    compose("app", "svc_fixture", &old, yaml.clone()).unwrap(),
    compose("app", "svc_fixture", &new, yaml).unwrap()
  );
}

#[test]
fn dedicated_file_parent_cannot_overlap_compose_tmpfs() {
  let spec: ServiceSpec = serde_json::from_value(serde_json::json!({
    "server": "s1", "source": {"image": "alpine"},
    "files": [{"path": "/app/seed/settings.json", "init_only": true, "content": "{}"}]
  })).unwrap();
  for tmpfs in ["'/app/seed'", "['/app/seed:size=1m']"] {
    let yaml =
      format!("services: {{app: {{image: alpine, tmpfs: {tmpfs}}}}}");
    assert_eq!(
      compose("app", "svc_fixture", &spec, yaml).unwrap_err().code,
      ErrorCode::Conflict
    );
  }
}
