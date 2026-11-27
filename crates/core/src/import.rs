//! 把服务器上已有的 compose 项目或 `docker run` 起的容器转换成 compose 来源的服务。
//!
//! - compose 项目：用 `docker compose config` 解析好的内容。服务名和原项目名相同时，
//!   Wharf 用同一个项目名部署，compose 认作同一个项目，配置一致时不重建容器；
//!   名字不同时原来的数据卷改为外部卷继续使用，原项目的容器在部署前停掉。
//! - 单个容器：按 `docker inspect` 生成 compose，去掉镜像自带的默认值。
//!   原容器部署前改名停掉，失败时恢复。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as Json;
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  agent::ProjectContainerRaw,
  spec::{AdoptSpec, PortSpec},
};

/// 转换结果。
#[derive(Debug, Clone, PartialEq)]
pub struct Converted {
  pub compose: String,
  pub ports: Vec<PortSpec>,
  pub adopt: Option<AdoptSpec>,
  pub warnings: Vec<String>,
  pub stopped: bool,
}

/// 把项目名、容器名变成合法的服务名。
pub fn service_name(raw: &str) -> String {
  let mut out = String::new();
  for c in raw.trim_start_matches('/').chars() {
    let c = c.to_ascii_lowercase();
    if c.is_ascii_alphanumeric() {
      out.push(c);
    } else if !out.ends_with('-') {
      out.push('-');
    }
  }
  out.trim_matches('-').chars().take(48).collect()
}

fn key(s: &str) -> Value {
  Value::String(s.to_string())
}

fn yaml_err(e: impl std::fmt::Display) -> ApiError {
  ApiError::invalid(format!("compose 内容解析失败：{e}"))
}

pub fn from_compose(
  config: &str,
  containers: &[ProjectContainerRaw],
  project: &str,
  name: &str,
) -> Result<Converted, ApiError> {
  // Compose config 会给输出里的字面量（包括映射键）加一层美元符号转义。
  let mut doc: Value =
    serde_yaml_ng::from_str(&config.replace("$$", "$"))
      .map_err(|_| yaml_err("无法解析，检查原项目配置"))?;
  let root = doc
    .as_mapping_mut()
    .ok_or_else(|| yaml_err("顶层不是映射"))?;
  root.insert(key("name"), key(name));
  let mut warnings = Vec::new();
  let mut adopt = AdoptSpec {
    project: Some(project.into()),
    ..Default::default()
  };
  let mut grouped: BTreeMap<&str, Vec<&ProjectContainerRaw>> =
    BTreeMap::new();
  let mut running = BTreeSet::new();
  let mut stopped_services = BTreeSet::new();
  for container in containers {
    let service = container.inspect["Config"]["Labels"]["com.docker.compose.service"]
      .as_str().unwrap_or_default();
    grouped.entry(service).or_default().push(container);
    if container.inspect["State"]["Running"] == true {
      running.insert(service);
    } else {
      stopped_services.insert(service);
    }
  }
  let stopped = !containers.is_empty() && running.is_empty();
  if stopped {
    warnings.push(
      "原 compose 项目当前全部已停止，接管后将保持停止（不启动容器）"
        .into(),
    );
  } else if !stopped_services.is_empty() {
    warnings.push(format!("原 compose 项目有部分组件当前已停止（{}），接管后可能随项目一起启动",
      service_list(stopped_services.iter().copied())));
  }
  let mut volumes = root.remove("volumes").unwrap_or(Value::Null);
  let mut has_env = false;
  if let Some(services) =
    root.get_mut("services").and_then(Value::as_mapping_mut)
  {
    let configured: BTreeSet<_> =
      services.keys().filter_map(Value::as_str).collect();
    let missing =
      service_list(running.difference(&configured).copied());
    if running.difference(&configured).next().is_some() {
      return Err(ApiError::invalid(format!(
        "compose 项目 {project} 中正在运行的组件 {missing} 不在默认配置里（通常由 --profile 启动）"
      )).with_hint("先在原 compose 文件中启用这些组件的默认配置，或改用 --container 单独导入"));
    }
    let missing_stopped =
      service_list(stopped_services.difference(&configured).copied());
    if !missing_stopped.is_empty() {
      warnings.push(format!("原项目里已停止的组件 {missing_stopped} 不在默认配置中，接管后不会重建"));
    }
    adopt.expected_services =
      configured.into_iter().map(str::to_string).collect();
    for (svc, body) in services.iter_mut() {
      let svc = svc.as_str().unwrap_or_default().to_string();
      let Some(body) = body.as_mapping_mut() else {
        continue;
      };
      if body.remove("build").is_some() {
        let image = body
          .get("image")
          .and_then(Value::as_str)
          .map(str::to_string)
          .unwrap_or_else(|| format!("{project}-{svc}"));
        body.insert(key("image"), key(&image));
        warnings.push(format!(
          "{svc} 的镜像是在本机构建的，导入后不再构建，沿用本机已有的 {image}"
        ));
      }
      has_env |= body
        .get("environment")
        .and_then(Value::as_mapping)
        .is_some_and(|m| !m.is_empty());
      let old = grouped
        .get(svc.as_str())
        .map(Vec::as_slice)
        .unwrap_or_default();
      if let Some((first, rest)) = old.split_first() {
        if rest
          .iter()
          .any(|c| c.inspect["Image"] != first.inspect["Image"])
        {
          return Err(ApiError::invalid(format!(
            "compose 项目 {project} 的组件 {svc} 有多个镜像版本，请统一后重新导入"
          )));
        }
        if let Some(image) = body.get("image").and_then(Value::as_str)
        {
          let pinned = resolve_pinned_image(
            image,
            &first.inspect,
            first.image_inspect.as_ref(),
            first.tag_image_id.as_deref(),
            &svc,
            &mut adopt,
            &mut warnings,
          )?;
          body.insert(key("image"), key(&pinned));
        }
      }
      fill_random_ports(body, old, &svc, &mut warnings)?;
      if name != project {
        if let Some(fixed) =
          body.get("container_name").and_then(Value::as_str)
          && containers.iter().any(|c| {
            c.inspect["Name"]
              .as_str()
              .is_some_and(|n| n.trim_start_matches('/') == fixed)
          })
          && !adopt.rename_containers.iter().any(|n| n == fixed)
        {
          adopt.rename_containers.push(fixed.into());
        }
        attach_anonymous_volumes(
          body,
          &mut volumes,
          old,
          project,
          &svc,
          &mut warnings,
        )?;
      }
    }
  }
  if containers.is_empty() && name == project {
    adopt = AdoptSpec::default();
  }
  if name != project {
    if let Some(volumes) = volumes.as_mapping_mut() {
      for (k, v) in volumes.iter_mut() {
        if v.is_null() {
          *v = Value::Mapping(Mapping::new());
        }
        if let Some(m) = v.as_mapping_mut()
          && m.get("external").and_then(Value::as_bool) != Some(true)
        {
          let real = m
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
              format!("{project}_{}", k.as_str().unwrap_or_default())
            });
          *m = external(&real);
        }
      }
    }
    if let Some(networks) =
      root.get_mut("networks").and_then(Value::as_mapping_mut)
    {
      for (k, v) in networks.iter_mut() {
        let own =
          format!("{project}_{}", k.as_str().unwrap_or_default());
        if let Some(m) = v.as_mapping_mut()
          && m.get("external").and_then(Value::as_bool) != Some(true)
          && m.get("name").and_then(Value::as_str)
            == Some(own.as_str())
        {
          m.remove("name");
        }
      }
    }
  }
  adopt.rename_containers.sort_unstable();
  if !volumes.is_null() {
    root.insert(key("volumes"), volumes);
  }
  escape_yaml_dollars(&mut doc);
  if has_env {
    warnings.push(env_warning());
  }
  let compose = format!(
    "# 由 Wharf 从服务器上的 compose 项目 {project} 导入。\n{}",
    serde_yaml_ng::to_string(&doc).map_err(yaml_err)?
  );
  Ok(Converted {
    ports: compose_ports(&compose),
    compose,
    adopt: Some(adopt),
    warnings,
    stopped,
  })
}

fn service_list<'a>(
  services: impl Iterator<Item = &'a str>,
) -> String {
  services
    .map(|s| if s.is_empty() { "未知组件" } else { s })
    .collect::<Vec<_>>()
    .join("、")
}

fn external(name: &str) -> Mapping {
  Mapping::from_iter([
    (key("external"), Value::Bool(true)),
    (key("name"), key(name)),
  ])
}

fn escape_yaml_dollars(value: &mut Value) {
  match value {
    Value::String(s) => *s = literal(s),
    Value::Sequence(a) => a.iter_mut().for_each(escape_yaml_dollars),
    Value::Mapping(m) => m.values_mut().for_each(escape_yaml_dollars),
    Value::Tagged(t) => escape_yaml_dollars(&mut t.value),
    _ => {}
  }
}

fn repo(image: &str) -> String {
  let name = image.split('@').next().unwrap_or_default();
  let name = if let Some((base, tag)) = name.rsplit_once(':')
    && !tag.contains('/')
  {
    base
  } else {
    name
  };
  let name = name
    .strip_prefix("index.docker.io/")
    .or_else(|| name.strip_prefix("docker.io/"))
    .unwrap_or(name);
  name.strip_prefix("library/").unwrap_or(name).to_string()
}

fn resolve_pinned_image(
  declared: &str,
  inspect: &Json,
  image_inspect: Option<&Json>,
  tag_image_id: Option<&str>,
  who: &str,
  adopt: &mut AdoptSpec,
  warnings: &mut Vec<String>,
) -> Result<String, ApiError> {
  let Some(actual) =
    inspect["Image"].as_str().filter(|s| !s.is_empty())
  else {
    return Ok(declared.into());
  };
  let digests = image_inspect
    .map(|i| strs(&i["RepoDigests"]))
    .unwrap_or_default();
  let digests = digests.iter().filter(|r| {
    r.split_once("@sha256:")
      .is_some_and(|(r, d)| !r.is_empty() && !d.is_empty())
  });
  let matching = digests.clone().find(|r| repo(r) == repo(declared));
  let written: String = if declared == actual
    || (inspect["Config"]["Image"].as_str() == Some(declared)
      && tag_image_id == Some(actual))
  {
    if let Some((_, digest)) = matching
      .or_else(|| digests.clone().next())
      .and_then(|r| r.split_once('@'))
      && !declared.contains('@')
      && !declared.starts_with("sha256:")
    {
      adopt.initial_pins.insert(declared.into(), digest.into());
    }
    declared.into()
  } else {
    let written = matching
      .or_else(|| digests.clone().next())
      .map(String::as_str)
      .unwrap_or(actual);
    warnings.push(format!("{who} 的本机镜像标签 {declared} 与实际镜像不一致，已固定到 {written}"));
    written.into()
  };
  if adopt
    .expected_images
    .insert(written.clone(), actual.into())
    .is_some_and(|id| id != actual)
  {
    return Err(ApiError::invalid(format!(
      "{who} 与其他组件使用同名镜像但版本不同"
    )));
  }
  Ok(written)
}

fn mount_path(path: &str) -> &str {
  let path = path.trim_end_matches('/');
  if path.is_empty() { "/" } else { path }
}

fn attach_anonymous_volumes(
  body: &mut Mapping,
  top: &mut Value,
  old: &[&ProjectContainerRaw],
  project: &str,
  service: &str,
  warnings: &mut Vec<String>,
) -> Result<(), ApiError> {
  let mut actual: BTreeMap<&str, BTreeMap<&str, bool>> =
    BTreeMap::new();
  for m in old.iter().flat_map(|c| {
    c.inspect["Mounts"].as_array().into_iter().flatten()
  }) {
    if m["Type"] == "volume"
      && let (Some(dest), Some(name)) =
        (m["Destination"].as_str(), m["Name"].as_str())
    {
      actual
        .entry(mount_path(dest))
        .or_default()
        .insert(name, m["RW"] == false);
    }
  }
  let mut mounts = body
    .remove("volumes")
    .and_then(|v| match v {
      Value::Sequence(items) => Some(items),
      _ => None,
    })
    .unwrap_or_default();
  let mut add = |dest: &str,
                 names: &BTreeMap<&str, bool>|
   -> Result<String, ApiError> {
    if names.len() != 1 {
      return Err(ApiError::invalid(format!(
        "compose 项目 {project} 的组件 {service} 在 {dest} 对应多个不同的数据卷（{}）",
        service_list(names.keys().copied())
      )).with_hint("使用同名导入保留旧容器，或先确认要保留的数据卷"));
    }
    if top.is_null() {
      *top = Value::Mapping(Mapping::new());
    }
    let top = top
      .as_mapping_mut()
      .ok_or_else(|| yaml_err("volumes 不是映射"))?;
    let base = format!("vol-{service}-{}", service_name(dest));
    let mut vol = base.clone();
    let mut n = 2;
    while top.contains_key(vol.as_str()) {
      vol = format!("{base}-{n}");
      n += 1;
    }
    top.insert(
      key(&vol),
      Value::Mapping(external(
        names.keys().next().expect("已确认一个卷"),
      )),
    );
    Ok(vol)
  };
  for mount in &mut mounts {
    let (dest, anonymous) = if let Some(s) = mount.as_str() {
      match s.split_once(':') {
        Some((_, rest)) => {
          (rest.split(':').next().unwrap_or_default(), false)
        }
        None => (s, true),
      }
    } else if let Some(dest) =
      mount.get("target").and_then(Value::as_str)
    {
      (
        dest,
        mount.get("type").and_then(Value::as_str) == Some("volume")
          && mount
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty(),
      )
    } else {
      continue;
    };
    let names = actual.remove(mount_path(dest));
    if !anonymous {
      continue;
    }
    if let Some(names) = names {
      let vol = add(dest, &names)?;
      if mount.is_mapping() {
        let m = mount.as_mapping_mut().expect("已确认映射");
        m.insert(key("source"), key(&vol));
      } else {
        *mount = key(&format!("{vol}:{dest}"));
      }
    } else {
      warnings.push(format!(
        "组件 {service} 在 {dest} 没有找到原匿名卷，保留配置"
      ));
    }
  }
  for (dest, names) in actual {
    let vol = add(dest, &names)?;
    let (real, ro) = names.into_iter().next().expect("已确认一个卷");
    let mut m = Mapping::from_iter([
      (key("type"), key("volume")),
      (key("source"), key(&vol)),
      (key("target"), key(dest)),
    ]);
    if ro {
      m.insert(key("read_only"), Value::Bool(true));
    }
    mounts.push(Value::Mapping(m));
    warnings.push(format!(
      "已保留组件 {service} 在 {dest} 上的隐式数据卷 {real}"
    ));
  }
  if !mounts.is_empty() {
    body.insert(key("volumes"), Value::Sequence(mounts));
  }
  Ok(())
}

fn fill_random_ports(
  body: &mut Mapping,
  old: &[&ProjectContainerRaw],
  service: &str,
  warnings: &mut Vec<String>,
) -> Result<(), ApiError> {
  for port in body
    .get_mut("ports")
    .and_then(Value::as_sequence_mut)
    .into_iter()
    .flatten()
  {
    if port.get("published").is_some_and(|v| {
      !v.is_null()
        && v.as_str() != Some("")
        && v.as_str() != Some("0")
        && v.as_u64() != Some(0)
    }) {
      continue;
    }
    let Some(target) = port.get("target").and_then(Value::as_u64)
    else {
      continue;
    };
    let protocol = port
      .get("protocol")
      .and_then(Value::as_str)
      .unwrap_or("tcp");
    let host_ip = port.get("host_ip").and_then(Value::as_str);
    let id = format!("{target}/{protocol}");
    let found: BTreeSet<_> = old
      .iter()
      .filter(|c| c.inspect["State"]["Running"] == true)
      .flat_map(|c| {
        c.inspect["NetworkSettings"]["Ports"][id.as_str()]
          .as_array()
          .into_iter()
          .flatten()
      })
      .filter(|b| {
        host_ip.is_none_or(|ip| b["HostIp"].as_str() == Some(ip))
      })
      .filter_map(|b| {
        b["HostPort"].as_str().filter(|p| !p.is_empty())
      })
      .collect();
    match found.len() {
      0 => warnings.push(format!("无法获知组件 {service} 在 {target}/{protocol} 上自动分配的端口")),
      1 => {
        let host = found.first().expect("已确认一个端口");
        port["published"] = key(host);
        warnings.push(format!("已固定组件 {service} 自动分配的端口 {host}->{target}"));
      }
      _ => return Err(ApiError::invalid(format!("组件 {service} 在 {target}/{protocol} 上有多个自动分配端口，请先指定要保留的端口"))),
    }
  }
  Ok(())
}

fn env_warning() -> String {
  "环境变量（可能含密码）以明文存进 Wharf，需要时改成 [[密钥名]] 引用"
    .into()
}

/// compose 内容里映射到宿主机的 TCP 端口，短写法（`18880:8880`、`127.0.0.1:80:80`）
/// 和长写法（`published`）都认。只写容器端口、端口范围、UDP 的跳过。
/// compose 来源没填 ports 时用它补上，这样服务有内网地址、路由也能指过来。
/// compose 里有没有容器挂载了目录或卷（解析不了的当作有）。
pub fn compose_has_volumes(content: &str) -> bool {
  let Ok(value) = serde_yaml_ng::from_str::<Value>(content) else {
    return true;
  };
  value["services"].as_mapping().is_none_or(|m| {
    m.values().any(|svc| {
      svc["volumes"].as_sequence().is_some_and(|v| !v.is_empty())
    })
  })
}

pub fn compose_ports(content: &str) -> Vec<PortSpec> {
  let Ok(doc) = serde_yaml_ng::from_str::<Value>(content) else {
    return Vec::new();
  };
  let mut published = Vec::new();
  let services = doc.get("services").and_then(Value::as_mapping);
  for body in services.into_iter().flat_map(|m| m.values()) {
    let ports = body.get("ports").and_then(Value::as_sequence);
    for p in ports.into_iter().flatten() {
      let port = match p {
        Value::String(s) => short_port(s),
        Value::Mapping(_) => {
          let tcp = p
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("tcp")
            == "tcp";
          match p.get("published") {
            Some(Value::String(s)) if tcp => s.parse().ok(),
            Some(Value::Number(n)) if tcp => {
              n.as_u64().and_then(|n| u16::try_from(n).ok())
            }
            _ => None,
          }
        }
        _ => None,
      };
      published.extend(port);
    }
  }
  port_specs(published)
}

fn short_port(s: &str) -> Option<u16> {
  let s = s.trim();
  let s = match s.split_once('/') {
    Some((p, "tcp")) => p,
    Some(_) => return None,
    None => s,
  };
  let parts: Vec<&str> = s.split(':').collect();
  if parts.len() < 2 {
    return None;
  }
  parts[parts.len() - 2].parse().ok()
}

fn port_specs(mut ports: Vec<u16>) -> Vec<PortSpec> {
  ports.sort_unstable();
  ports.dedup();
  let single = ports.len() == 1;
  ports
    .into_iter()
    .map(|port| PortSpec {
      name: if single {
        "http".into()
      } else {
        format!("p{port}")
      },
      container: None,
      host: Some(port),
      udp: false,
    })
    .collect()
}

fn strs(v: &Json) -> Vec<String> {
  v.as_array()
    .into_iter()
    .flatten()
    .filter_map(|s| s.as_str().map(str::to_string))
    .collect()
}

fn seq(items: Vec<String>) -> Value {
  Value::Sequence(items.into_iter().map(Value::String).collect())
}

/// compose 会对 `$` 做变量替换，原样保留要写成 `$$`。
fn literal(s: &str) -> String {
  s.replace('$', "$$")
}

pub fn from_container(
  inspect: &Json,
  image_inspect: Option<&Json>,
  tag_image_id: Option<&str>,
  name: &str,
) -> Result<Converted, ApiError> {
  let config = &inspect["Config"];
  let host = &inspect["HostConfig"];
  let image_cfg = image_inspect.map(|i| &i["Config"]);
  let original = inspect["Name"]
    .as_str()
    .unwrap_or_default()
    .trim_start_matches('/')
    .to_string();
  let image = config["Image"]
    .as_str()
    .filter(|i| !i.is_empty())
    .ok_or_else(|| {
      ApiError::invalid(format!("容器 {original} 没有镜像名"))
    })?;
  let mut warnings = Vec::new();
  let mut svc = Mapping::new();
  let mut volumes_top = Mapping::new();
  let mut networks_top = Mapping::new();
  let mut adopt = AdoptSpec {
    containers: vec![original.clone()],
    ..Default::default()
  };
  let image = resolve_pinned_image(
    image,
    inspect,
    image_inspect,
    tag_image_id,
    &original,
    &mut adopt,
    &mut warnings,
  )?;
  let stopped = inspect["State"]["Running"] == false;
  if stopped {
    warnings.push(
      "原容器当前已停止，接管后将保持停止（不启动容器）".into(),
    );
  }
  svc.insert(key("image"), key(&image));
  svc.insert(key("container_name"), key(&original));

  let differs = |field: &str| {
    let mine = &config[field];
    let theirs = image_cfg.map(|c| &c[field]).unwrap_or(&Json::Null);
    let empty = |v: &Json| {
      v.is_null() || v.as_array().is_some_and(Vec::is_empty)
    };
    !(mine == theirs || (empty(mine) && empty(theirs)))
  };
  for (field, out) in
    [("Entrypoint", "entrypoint"), ("Cmd", "command")]
  {
    if differs(field) {
      let items: Vec<String> =
        strs(&config[field]).iter().map(|s| literal(s)).collect();
      svc.insert(key(out), seq(items));
    }
  }
  for (field, out) in
    [("WorkingDir", "working_dir"), ("User", "user")]
  {
    if differs(field)
      && let Some(v) =
        config[field].as_str().filter(|v| !v.is_empty())
    {
      svc.insert(key(out), key(v));
    }
  }

  let base: BTreeSet<String> = image_cfg
    .map(|c| strs(&c["Env"]).into_iter().collect())
    .unwrap_or_default();
  let mut env = Mapping::new();
  for kv in strs(&config["Env"]) {
    if base.contains(&kv) {
      continue;
    }
    let (k, v) = kv.split_once('=').unwrap_or((&kv, ""));
    env.insert(key(k), key(&literal(v)));
  }
  if !env.is_empty() {
    svc.insert(key("environment"), Value::Mapping(env));
    warnings.push(env_warning());
  }

  match host["RestartPolicy"]["Name"].as_str().unwrap_or_default() {
    "" | "no" => {}
    "on-failure" => {
      let n = host["RestartPolicy"]["MaximumRetryCount"]
        .as_u64()
        .unwrap_or(0);
      let policy = if n > 0 {
        format!("on-failure:{n}")
      } else {
        "on-failure".into()
      };
      svc.insert(key("restart"), key(&policy));
    }
    p => {
      svc.insert(key("restart"), key(p));
    }
  }

  let mode = host["NetworkMode"].as_str().unwrap_or_default();
  if matches!(mode, "host" | "none") || mode.starts_with("container:")
  {
    svc.insert(key("network_mode"), key(mode));
    if mode.starts_with("container:") {
      warnings.push(format!(
        "网络模式 {mode} 依赖另一个容器，导入后要确认它还在"
      ));
    }
  } else {
    extract_container_networks(
      inspect,
      name,
      mode,
      &mut svc,
      &mut networks_top,
      &mut warnings,
    );
  }

  let (ports, published) = if mode == "host" {
    (Vec::new(), Vec::new())
  } else {
    extract_container_ports(inspect, &mut warnings)
  };
  if !ports.is_empty() {
    svc.insert(key("ports"), seq(ports));
  }
  let short_id = inspect["Id"].as_str().and_then(|id| id.get(..12));
  for (field, out) in
    [("Hostname", "hostname"), ("StopSignal", "stop_signal")]
  {
    if differs(field)
      && let Some(value) =
        config[field].as_str().filter(|s| !s.is_empty())
      && (field != "Hostname" || Some(value) != short_id)
    {
      svc.insert(key(out), key(&literal(value)));
    }
  }
  if let Some(timeout) = config["StopTimeout"].as_u64() {
    svc.insert(key("stop_grace_period"), key(&format!("{timeout}s")));
  }
  if let Some(shm) = host["ShmSize"]
    .as_u64()
    .filter(|n| *n != 0 && *n != 67_108_864)
  {
    let mib = 1024 * 1024;
    let size = if shm.is_multiple_of(mib) {
      key(&format!("{}m", shm / mib))
    } else {
      Value::Number(shm.into())
    };
    svc.insert(key("shm_size"), size);
  }
  if host["ReadonlyRootfs"] == true {
    svc.insert(key("read_only"), Value::Bool(true));
  }
  if differs("Healthcheck") {
    let check = &config["Healthcheck"];
    let test = strs(&check["Test"]);
    if !test.is_empty() {
      let mut m = Mapping::new();
      if test == ["NONE"] {
        m.insert(key("disable"), Value::Bool(true));
      } else {
        m.insert(
          key("test"),
          seq(test.iter().map(|s| literal(s)).collect()),
        );
        for (field, out) in [
          ("Interval", "interval"),
          ("Timeout", "timeout"),
          ("StartPeriod", "start_period"),
          ("StartInterval", "start_interval"),
        ] {
          if let Some(ns) = check[field].as_u64().filter(|n| *n > 0) {
            m.insert(key(out), key(&format_duration_ns(ns)));
          }
        }
        if let Some(retries) =
          check["Retries"].as_u64().filter(|n| *n > 0)
        {
          m.insert(key("retries"), Value::Number(retries.into()));
        }
      }
      svc.insert(key("healthcheck"), Value::Mapping(m));
    }
  }

  let mut mounts = Vec::new();
  for m in inspect["Mounts"].as_array().into_iter().flatten() {
    let dest = m["Destination"].as_str().unwrap_or_default();
    let ro = if m["RW"].as_bool() == Some(false) {
      ":ro"
    } else {
      ""
    };
    match m["Type"].as_str().unwrap_or_default() {
      "bind" => {
        let src = m["Source"].as_str().unwrap_or_default();
        let propagation = m["Propagation"]
          .as_str()
          .filter(|p| !p.is_empty() && *p != "rprivate");
        let opts = match (ro.is_empty(), propagation) {
          (true, Some(p)) => format!(":{p}"),
          (false, Some(p)) => format!(":ro,{p}"),
          (_, None) => ro.into(),
        };
        mounts.push(format!(
          "{}:{}{opts}",
          literal(src),
          literal(dest)
        ));
      }
      "volume" => {
        let vol = m["Name"].as_str().unwrap_or_default();
        mounts.push(format!("{vol}:{}{ro}", literal(dest)));
        let mut v = Mapping::new();
        v.insert(key("external"), Value::Bool(true));
        volumes_top.insert(key(vol), Value::Mapping(v));
      }
      other => {
        warnings.push(format!("挂载 {dest}（{other}）没有转换"))
      }
    }
  }
  if !mounts.is_empty() {
    svc.insert(key("volumes"), seq(mounts));
  }

  for (field, out) in [
    ("CapAdd", "cap_add"),
    ("CapDrop", "cap_drop"),
    ("ExtraHosts", "extra_hosts"),
    ("Dns", "dns"),
    ("SecurityOpt", "security_opt"),
  ] {
    let items = strs(&host[field]);
    if !items.is_empty() {
      svc.insert(key(out), seq(items));
    }
  }
  let devices: Vec<String> = host["Devices"]
    .as_array()
    .into_iter()
    .flatten()
    .map(|d| {
      format!(
        "{}:{}:{}",
        d["PathOnHost"].as_str().unwrap_or_default(),
        d["PathInContainer"].as_str().unwrap_or_default(),
        d["CgroupPermissions"].as_str().unwrap_or("rwm")
      )
    })
    .collect();
  if !devices.is_empty() {
    svc.insert(key("devices"), seq(devices));
  }
  if host["Privileged"].as_bool() == Some(true) {
    svc.insert(key("privileged"), Value::Bool(true));
  }
  if host["Init"].as_bool() == Some(true) {
    svc.insert(key("init"), Value::Bool(true));
  }
  for (field, out) in [("PidMode", "pid"), ("IpcMode", "ipc")] {
    if host[field].as_str() == Some("host") {
      svc.insert(key(out), key("host"));
    }
  }
  if let Some(mem) = host["Memory"].as_u64().filter(|m| *m > 0) {
    svc.insert(key("mem_limit"), Value::Number(mem.into()));
  }
  if let Some(cpus) = host["NanoCpus"].as_u64().filter(|c| *c > 0) {
    svc
      .insert(key("cpus"), Value::Number((cpus as f64 / 1e9).into()));
  }
  if let Some(tmpfs) =
    host["Tmpfs"].as_object().filter(|t| !t.is_empty())
  {
    let items = tmpfs
      .iter()
      .map(|(k, v)| match v.as_str().filter(|v| !v.is_empty()) {
        Some(opts) => format!("{k}:{opts}"),
        None => k.clone(),
      })
      .collect();
    svc.insert(key("tmpfs"), seq(items));
  }
  let image_labels = image_cfg.map(|c| &c["Labels"]);
  let mut labels = Mapping::new();
  for (k, v) in config["Labels"].as_object().into_iter().flatten() {
    let inherited = image_labels.is_some_and(|l| &l[k] == v);
    if !inherited && !k.starts_with("com.docker.compose.") {
      labels.insert(
        key(k),
        key(&literal(v.as_str().unwrap_or_default())),
      );
    }
  }
  if !labels.is_empty() {
    svc.insert(key("labels"), Value::Mapping(labels));
  }
  for (field, what) in [
    ("Links", "links"),
    ("VolumesFrom", "volumes_from"),
    ("Ulimits", "ulimits"),
    ("Sysctls", "sysctls"),
    ("DeviceRequests", "device_requests"),
    ("GroupAdd", "group_add"),
    ("UsernsMode", "userns_mode"),
    ("Runtime", "runtime"),
    ("CgroupnsMode", "cgroupns_mode"),
    ("OomScoreAdj", "oom_score_adj"),
    ("Domainname", "domainname"),
  ] {
    let value = if field == "Domainname" {
      &config[field]
    } else {
      &host[field]
    };
    let set = match value {
      Json::String(s) => !matches!(
        (field, s.as_str()),
        (_, "") | ("Runtime", "runc") | ("CgroupnsMode", "private")
      ),
      Json::Number(n) => n.as_i64().is_some_and(|n| n != 0),
      Json::Array(a) => !a.is_empty(),
      Json::Object(o) => !o.is_empty(),
      _ => false,
    };
    if set {
      warnings
        .push(format!("{what} 没有转换，需要时手动加到 compose 里"));
    }
  }
  let log = host["LogConfig"]["Type"].as_str().unwrap_or_default();
  if !log.is_empty() && log != "json-file" {
    warnings.push(format!("日志驱动 {log} 没有转换"));
  }

  let mut services = Mapping::new();
  services.insert(key(name), Value::Mapping(svc));
  let mut root = Mapping::new();
  root.insert(key("name"), key(name));
  root.insert(key("services"), Value::Mapping(services));
  if !volumes_top.is_empty() {
    root.insert(key("volumes"), Value::Mapping(volumes_top));
  }
  if !networks_top.is_empty() {
    root.insert(key("networks"), Value::Mapping(networks_top));
  }
  let compose = format!(
    "# 由 Wharf 从服务器上的容器 {original} 导入。\n{}",
    serde_yaml_ng::to_string(&Value::Mapping(root))
      .map_err(yaml_err)?
  );
  Ok(Converted {
    compose,
    ports: port_specs(published),
    adopt: Some(adopt),
    warnings,
    stopped,
  })
}

fn format_duration_ns(ns: u64) -> String {
  for (div, unit) in
    [(1_000_000_000, "s"), (1_000_000, "ms"), (1_000, "us")]
  {
    if ns.is_multiple_of(div) {
      return format!("{}{unit}", ns / div);
    }
  }
  format!("{ns}ns")
}

fn extract_container_networks(
  inspect: &Json,
  name: &str,
  mode: &str,
  svc: &mut Mapping,
  top: &mut Mapping,
  warnings: &mut Vec<String>,
) {
  let mut networks = Mapping::new();
  let id = inspect["Id"].as_str();
  if let Some(entries) = inspect["NetworkSettings"]["Networks"]
    .as_object()
    .filter(|e| !e.is_empty())
  {
    if entries.len() > 1 && entries.contains_key("bridge") {
      warnings.push("原容器同时连接了默认 bridge 与自定义网络，已保留自定义网络；如需默认 bridge 请手动确认".into());
    }
    for (network, ep) in
      entries.iter().filter(|(n, _)| *n != "bridge")
    {
      let mut settings = Mapping::new();
      let aliases: Vec<_> = strs(&ep["Aliases"])
        .into_iter()
        .filter(|a| {
          a != name
            && id != Some(a.as_str())
            && id.and_then(|s| s.get(..12)) != Some(a.as_str())
        })
        .collect();
      if !aliases.is_empty() {
        settings.insert(key("aliases"), seq(aliases));
      }
      for (field, out) in [
        ("IPv4Address", "ipv4_address"),
        ("IPv6Address", "ipv6_address"),
      ] {
        if let Some(ip) =
          ep["IPAMConfig"][field].as_str().filter(|s| !s.is_empty())
        {
          settings.insert(key(out), key(ip));
        }
      }
      top.insert(key(network), Value::Mapping(external(network)));
      networks.insert(key(network), Value::Mapping(settings));
    }
  } else if !matches!(mode, "" | "default" | "bridge") {
    top.insert(key(mode), Value::Mapping(external(mode)));
    networks.insert(key(mode), Value::Mapping(Mapping::new()));
  }
  if !networks.is_empty() {
    let value = if networks
      .values()
      .all(|v| v.as_mapping().is_some_and(Mapping::is_empty))
    {
      Value::Sequence(networks.into_iter().map(|(k, _)| k).collect())
    } else {
      Value::Mapping(networks)
    };
    svc.insert(key("networks"), value);
  }
}

fn format_host_ip(ip: &str) -> String {
  match ip {
    "" | "0.0.0.0" | "::" | "[::]" => String::new(),
    ip if ip.contains(':') && !ip.starts_with('[') => {
      format!("[{ip}]:")
    }
    ip => format!("{ip}:"),
  }
}

fn extract_container_ports(
  inspect: &Json,
  warnings: &mut Vec<String>,
) -> (Vec<String>, Vec<u16>) {
  let host = &inspect["HostConfig"];
  let running = inspect["State"]["Running"] == true;
  let actual = &inspect["NetworkSettings"]["Ports"];
  let mut ports = BTreeSet::new();
  let mut published = Vec::new();
  let mut dynamic = host["PublishAllPorts"] == true;
  for (bindings, is_actual) in
    [(actual, true), (&host["PortBindings"], false)]
  {
    if is_actual && !running {
      continue;
    }
    for (target, bindings) in
      bindings.as_object().into_iter().flatten()
    {
      let (port, proto) =
        target.split_once('/').unwrap_or((target, "tcp"));
      for b in bindings.as_array().into_iter().flatten() {
        let host_port = b["HostPort"]
          .as_str()
          .filter(|s| *s != "0")
          .unwrap_or_default();
        let ip = b["HostIp"].as_str().unwrap_or_default();
        if is_actual && host_port.is_empty() {
          continue;
        }
        if !is_actual
          && running
          && actual[target.as_str()].as_array().is_some_and(
            |entries| {
              entries.iter().any(|a| {
                a["HostPort"].as_str().is_some_and(|p| {
                  !p.is_empty()
                    && (host_port.is_empty() || p == host_port)
                }) && format_host_ip(
                  a["HostIp"].as_str().unwrap_or_default(),
                ) == format_host_ip(ip)
              })
            },
          )
        {
          continue;
        }
        dynamic |= host_port.is_empty();
        let proto_suffix = if proto == "tcp" {
          String::new()
        } else {
          format!("/{proto}")
        };
        let ip = format_host_ip(ip);
        let prefix = if !host_port.is_empty() || !ip.is_empty() {
          format!("{ip}{host_port}:")
        } else {
          String::new()
        };
        ports.insert(format!("{prefix}{port}{proto_suffix}"));
        if proto == "tcp" {
          published.extend(host_port.parse::<u16>().ok());
        }
      }
    }
  }
  if !running && dynamic {
    warnings.push("原容器使用自动分配端口但当前已停止，无法获知上次分配的端口，请启动原容器后重新导入或手动补充 ports".into());
  }
  (ports.into_iter().collect(), published)
}

#[cfg(test)]
mod tests {
  #[test]
  fn compose_ports_reads_short_and_long_syntax() {
    let c = "services:\n  a:\n    ports:\n      - \"18880:8880\"\n      - 127.0.0.1:9000:90\n      - 5000\n      - 53:53/udp\n  b:\n    ports:\n      - target: 80\n        published: 8081\n";
    let ports: Vec<_> = super::compose_ports(c)
      .into_iter()
      .map(|p| (p.name, p.host))
      .collect();
    assert_eq!(
      ports,
      vec![
        ("p8081".to_string(), Some(8081)),
        ("p9000".to_string(), Some(9000)),
        ("p18880".to_string(), Some(18880)),
      ]
    );
  }

  use super::*;

  const CONFIG: &str = r#"name: blog
services:
  web:
    build:
      context: /root/blog
    environment:
      A: "1"
    ports:
      - mode: ingress
        target: 80
        published: "8080"
        protocol: tcp
    volumes:
      - type: volume
        source: data
        target: /data
networks:
  default:
    name: blog_default
volumes:
  data:
    name: blog_data
"#;

  #[test]
  fn compose_same_name_keeps_project() {
    let c = from_compose(CONFIG, &[], "blog", "blog").unwrap();
    assert_eq!(c.adopt, Some(AdoptSpec::default()));
    assert_eq!(c.ports[0].host, Some(8080));
    assert!(c.compose.contains("image: blog-web"));
    assert!(!c.compose.contains("build"));
    crate::render::check_compose("blog", &c.compose).unwrap();
  }

  #[test]
  fn compose_new_name_reuses_volumes() {
    let c = from_compose(CONFIG, &[], "blog", "site").unwrap();
    assert_eq!(c.adopt.unwrap().project.as_deref(), Some("blog"));
    let doc: Value = serde_yaml_ng::from_str(&c.compose).unwrap();
    assert_eq!(doc["volumes"]["data"]["external"], Value::Bool(true));
    assert_eq!(doc["volumes"]["data"]["name"], key("blog_data"));
    assert!(doc["networks"]["default"].get("name").is_none());
  }

  #[test]
  fn container_drops_image_defaults() {
    let inspect = serde_json::json!({
      "Name": "/pairdrop",
      "Config": {
        "Image": "lscr.io/linuxserver/pairdrop:latest",
        "Env": ["PATH=/usr/bin", "PUID=1000", "X=$y"],
        "Cmd": ["node", "index.js"],
        "Labels": {"build": "x"}
      },
      "HostConfig": {
        "RestartPolicy": {"Name": "unless-stopped"},
        "NetworkMode": "bridge",
        "PortBindings": {"3000/tcp": [{"HostIp": "", "HostPort": "41773"}]}
      },
      "Mounts": [{"Type": "bind", "Source": "/srv/p", "Destination": "/config", "RW": true}]
    });
    let image = serde_json::json!({
      "Config": {"Env": ["PATH=/usr/bin"], "Cmd": ["node", "index.js"], "Labels": {"build": "x"}}
    });
    let c = from_container(&inspect, Some(&image), None, "pairdrop")
      .unwrap();
    let doc: Value = serde_yaml_ng::from_str(&c.compose).unwrap();
    let svc = &doc["services"]["pairdrop"];
    assert_eq!(svc["environment"]["PUID"], key("1000"));
    assert_eq!(svc["environment"]["X"], key("$$y"));
    assert!(svc["environment"].get("PATH").is_none());
    assert!(
      svc.get("command").is_none() && svc.get("labels").is_none()
    );
    assert_eq!(svc["ports"][0], key("41773:3000"));
    assert_eq!(svc["volumes"][0], key("/srv/p:/config"));
    assert_eq!(svc["restart"], key("unless-stopped"));
    assert_eq!(c.ports[0].host, Some(41773));
    assert_eq!(
      c.adopt.unwrap().containers,
      vec!["pairdrop".to_string()]
    );
  }

  #[test]
  fn names_are_sanitized() {
    assert_eq!(service_name("/My_App.v2"), "my-app-v2");
  }
}

#[cfg(test)]
mod adoption_tests {
  use super::*;
  use serde_json::json;

  fn old(
    service: &str,
    running: bool,
    mounts: Json,
  ) -> ProjectContainerRaw {
    ProjectContainerRaw {
      inspect: json!({
        "Name": format!("/{service}"),
        "State": {"Running": running},
        "Config": {"Labels": {"com.docker.compose.service": service}},
        "Mounts": mounts
      }),
      image_inspect: None,
      tag_image_id: None,
    }
  }

  #[test]
  fn image_uses_actual_digest_when_local_tag_moved() {
    let c = json!({"Name": "/db", "Image": "sha256:old", "Config": {"Image": "postgres:16"}});
    let image = json!({"RepoDigests": ["docker.io/library/postgres@sha256:digest"]});
    let pinned = "docker.io/library/postgres@sha256:digest";
    let moved =
      from_container(&c, Some(&image), Some("sha256:new"), "db")
        .unwrap();
    assert!(moved.compose.contains(pinned));
    assert!(moved.warnings.iter().any(|w| w.contains("已固定")));
    assert_eq!(
      moved.adopt.unwrap().expected_images[pinned],
      "sha256:old"
    );
    let stable =
      from_container(&c, Some(&image), Some("sha256:old"), "db")
        .unwrap();
    assert!(stable.compose.contains("image: postgres:16"));
    assert_eq!(
      stable.adopt.unwrap().initial_pins["postgres:16"],
      "sha256:digest"
    );
    let local = from_container(&c, None, None, "db").unwrap();
    assert!(local.compose.contains("image: sha256:old"));
  }

  #[test]
  fn rename_keeps_fixed_name_and_explicit_and_implicit_volumes() {
    let compose = "services:
  db:
    image: postgres:16
    container_name: db
    volumes: [/data]
";
    let c = old(
      "db",
      false,
      json!([
        {"Type": "volume", "Destination": "/data/", "Name": "v1"},
        {"Type": "volume", "Destination": "/implicit", "Name": "v2", "RW": false}
      ]),
    );
    let result =
      from_compose(compose, std::slice::from_ref(&c), "old", "db")
        .unwrap();
    let yaml: Value =
      serde_yaml_ng::from_str(&result.compose).unwrap();
    assert_eq!(yaml["volumes"]["vol-db-data"]["name"], key("v1"));
    assert_eq!(yaml["volumes"]["vol-db-implicit"]["name"], key("v2"));
    assert_eq!(
      yaml["services"]["db"]["volumes"][1]["read_only"],
      Value::Bool(true)
    );
    assert_eq!(result.adopt.unwrap().rename_containers, ["db"]);
    assert!(result.stopped);
    let other = old(
      "db",
      false,
      json!([{"Type": "volume", "Destination": "/data", "Name": "v3"}]),
    );
    let error =
      from_compose(compose, &[c, other], "old", "db").unwrap_err();
    assert!(error.message.contains("/data"));
  }

  #[test]
  fn rejects_running_profile_and_warns_for_stopped_components() {
    let compose = "services:
  db:
    image: postgres:16
";
    let containers =
      [old("db", true, Json::Null), old("worker", true, Json::Null)];
    for name in ["old", "db"] {
      let e =
        from_compose(compose, &containers, "old", name).unwrap_err();
      assert!(
        e.message.contains("worker")
          && e.message.contains("--profile")
      );
    }
    let containers = [
      old("db", true, Json::Null),
      old("worker", false, Json::Null),
    ];
    let result =
      from_compose(compose, &containers, "old", "old").unwrap();
    assert!(!result.stopped);
    assert!(result.warnings.iter().any(|w| w.contains("worker")));
    assert_eq!(result.adopt.unwrap().expected_services, ["db"]);
  }

  #[test]
  fn compose_keeps_literal_dollars_from_resolved_output() {
    let output = "services:
  app:
    image: img
    environment: { NOTE: p$$ss }
    command: [sh, -c, 'echo $$FOO']
    labels: { 'x$$y': 'z$$$$w' }
";
    let result = from_compose(output, &[], "old", "new").unwrap();
    let yaml: Value =
      serde_yaml_ng::from_str(&result.compose).unwrap();
    let body = &yaml["services"]["app"];
    assert_eq!(body["environment"]["NOTE"], key("p$$ss"));
    assert_eq!(body["command"][2], key("echo $$FOO"));
    assert_eq!(body["labels"]["x$y"], key("z$$$$w"));
  }

  #[test]
  fn single_container_preserves_endpoints_ports_and_options() {
    let inspect = json!({
      "Name": "/db", "Id": "0123456789abcdef", "State": {"Running": true},
      "Config": {"Image": "img", "Hostname": "box", "StopSignal": "SIGINT", "StopTimeout": 8,
        "Healthcheck": {"Test": ["CMD-SHELL", "echo $CHECK"], "Interval": 500000000}},
      "HostConfig": {"NetworkMode": "front", "PublishAllPorts": true,
        "ShmSize": 1073741824, "ReadonlyRootfs": true, "Runtime": "nvidia"},
      "NetworkSettings": {
        "Networks": {"front": {}, "back": {"Aliases": ["0123456789ab", "db-alias"],
          "IPAMConfig": {"IPv4Address": "203.0.113.9"}}},
        "Ports": {"80/tcp": [
          {"HostIp": "0.0.0.0", "HostPort": "32772"},
          {"HostIp": "::", "HostPort": "32772"},
          {"HostIp": "::1", "HostPort": "8080"}
        ]}
      },
      "Mounts": [{"Type": "bind", "Source": "/var/data", "Destination": "/data", "Propagation": "rslave", "RW": false}]
    });
    let result = from_container(&inspect, None, None, "new").unwrap();
    let yaml: Value =
      serde_yaml_ng::from_str(&result.compose).unwrap();
    let svc = &yaml["services"]["new"];
    assert!(svc["networks"]["front"].is_mapping());
    assert_eq!(
      svc["networks"]["back"]["aliases"],
      seq(vec!["db-alias".into()])
    );
    assert_eq!(
      svc["networks"]["back"]["ipv4_address"],
      key("203.0.113.9")
    );
    assert_eq!(
      svc["ports"],
      seq(vec!["32772:80".into(), "[::1]:8080:80".into()])
    );
    assert_eq!(result.ports[1].host, Some(32772));
    assert_eq!(svc["read_only"], Value::Bool(true));
    assert_eq!(svc["shm_size"], key("1024m"));
    assert_eq!(svc["healthcheck"]["interval"], key("500ms"));
    assert_eq!(svc["hostname"], key("box"));
    assert_eq!(svc["stop_signal"], key("SIGINT"));
    assert_eq!(svc["stop_grace_period"], key("8s"));
    assert_eq!(svc["volumes"][0], key("/var/data:/data:ro,rslave"));
    assert_eq!(svc["container_name"], key("db"));
    assert!(result.warnings.iter().any(|w| w.contains("runtime")));
  }

  #[test]
  fn stopped_container_warns_when_random_port_is_unknown() {
    let inspect = json!({"Name": "/db", "State": {"Running": false},
      "Config": {"Image": "img"}, "HostConfig": {"PublishAllPorts": true}});
    let result = from_container(&inspect, None, None, "db").unwrap();
    assert!(result.stopped);
    assert!(result.warnings.iter().any(|w| w.contains("保持停止")));
    assert!(
      result.warnings.iter().any(|w| w.contains("自动分配端口"))
    );
  }

  #[test]
  fn compose_reuses_random_published_port() {
    let mut c = old("app", true, Json::Null);
    c.inspect["NetworkSettings"] =
      json!({"Ports": {"80/tcp": [{"HostPort": "32772"}]}});
    let output = "services:
  app:
    image: img
    ports: [{target: 80}]
";
    let result = from_compose(output, &[c], "old", "new").unwrap();
    assert_eq!(result.ports[0].host, Some(32772));
  }
}
