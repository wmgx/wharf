use super::*;

mod gateway;
pub use gateway::*;

/// 服务数据目录：`/srv/<service>/<volume>`。
pub fn volume_dir(service: &str, volume: &str) -> String {
  format!("/srv/{service}/{volume}")
}

pub fn service_dirs(name: &str, spec: &ServiceSpec) -> Vec<String> {
  spec
    .volumes
    .iter()
    .map(|v| volume_dir(name, &v.name))
    .collect()
}

#[derive(Serialize)]
struct ComposeFile {
  name: String,
  services: BTreeMap<String, ComposeService>,
}

#[derive(Serialize)]
struct ComposeService {
  image: String,
  restart: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  mem_limit: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  cpus: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  network_mode: Option<&'static str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  entrypoint: Option<Vec<String>>,
  #[serde(skip_serializing_if = "Option::is_none")]
  command: Option<Vec<String>>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  environment: BTreeMap<String, String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  ports: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  volumes: Vec<String>,
  labels: BTreeMap<String, String>,
}

fn to_yaml(file: &ComposeFile) -> String {
  let body = serde_yaml_ng::to_string(file).unwrap_or_default();
  format!("# 由 Wharf 生成，不要手改。\n{body}")
}

/// 把 `[[NAME]]` 换成密钥。`secrets` 为空时原样保留（用于展示和部署历史）。
pub fn substitute(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  substitute_values(text, secrets, false)
}

fn substitute_values(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
  service_config: bool,
) -> Result<String, ApiError> {
  let Some(secrets) = secrets else {
    return Ok(text.to_string());
  };
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  let mut missing = Vec::new();
  while let Some((start, name)) = next_placeholder(rest) {
    let len = name.len();
    let is_name = !name.is_empty()
      && name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    out.push_str(&rest[..start]);
    let account = service_config.then(|| account_ref(name)).flatten();
    if is_name || account.is_some() {
      match secrets.get(name) {
        Some(value) => out.push_str(value),
        None if let Some(account) = account => {
          return Err(
            ApiError::invalid(format!("应用账号 {account} 不存在"))
              .with_hint("先设置应用账号，密码从标准输入读取")
              .suggest(format!(
                "wharf sso account set {account} --user <用户名>"
              )),
          );
        }
        None => missing.push(name.to_string()),
      }
    } else {
      out.push_str(&rest[start..start + 4 + len]);
    }
    rest = &rest[start + 4 + len..];
  }
  out.push_str(rest);
  if !missing.is_empty() {
    missing.sort();
    missing.dedup();
    let first = missing[0].clone();
    return Err(
      ApiError::invalid(format!(
        "密钥不存在：{}",
        missing.join("、")
      ))
      .with_hint("先设置密钥，值从标准输入读取，不会出现在命令行里")
      .suggest(format!("wharf secret set {first}")),
    );
  }
  Ok(out)
}

pub(crate) fn next_placeholder(text: &str) -> Option<(usize, &str)> {
  let start = text.find("[[")?;
  let rest = &text[start + 2..];
  Some((start, &rest[..rest.find("]]")?]))
}

pub fn service_account_refs(world: &World) -> BTreeSet<String> {
  world
    .services
    .values()
    .flat_map(|row| {
      crate::secret_policy::service_account_refs(&row.spec)
    })
    .map(|(name, _)| name.to_string())
    .collect()
}

pub(crate) fn account_ref(name: &str) -> Option<&str> {
  let (account, field) =
    name.strip_prefix("account.")?.split_once('.')?;
  (matches!(field, "username" | "password")
    && wharf_api_types::validate_name("应用账号", account).is_ok())
  .then_some(account)
}

/// 构建来源的镜像名：`wharf-build/<服务>:<指纹>`。指纹来自构建配置和端口
/// （端口决定模板里的 `$PORT`），配置不变就不用重新构建。
pub fn build_image(
  name: &str,
  build: &BuildSource,
  ports: &[PortSpec],
) -> String {
  // 模板只用到容器端口（`$PORT`），宿主机端口变了不用重新构建。
  let input =
    serde_json::json!({ "build": build, "port": build_port(ports) });
  let key = hash(&input.to_string());
  format!("{BUILD_IMAGE_PREFIX}{name}:{}", &key[..12])
}

/// 构建来源模板里的 `$PORT`：第一个端口，没有端口时 8080。
pub fn build_port(ports: &[PortSpec]) -> u16 {
  ports.first().and_then(|p| p.container).unwrap_or(8080)
}

/// compose 里 cpus 的写法：500 → "0.5"，1000 → "1"，1250 → "1.25"。
pub fn cpus_text(milli: u32) -> String {
  let s = format!("{:.3}", f64::from(milli) / 1000.0);
  s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// 服务设置作用的容器：写了 `container` 就是它，否则 compose 里只能有一个容器。
pub fn compose_target(
  name: &str,
  content: &str,
  container: Option<&str>,
) -> Result<String, ApiError> {
  let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content)
    .map_err(|e| {
      ApiError::invalid(format!("compose 内容解析失败：{e}"))
    })?;
  let names: Vec<String> = value
    .get("services")
    .and_then(|s| s.as_mapping())
    .into_iter()
    .flat_map(|m| m.keys())
    .filter_map(|k| k.as_str().map(str::to_string))
    .collect();
  match container {
    Some(c) if names.iter().any(|n| n == c) => Ok(c.to_string()),
    Some(c) => Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里没有容器 {c}"
    ))
    .with_hint(format!("可选的容器：{}", names.join("、")))),
    None if names.len() == 1 => Ok(names[0].clone()),
    None => Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里有 {} 个容器，要选环境变量和资源上限加在哪个容器上",
      names.len()
    ))
    .with_hint(format!("在设置里选择容器（{}）", names.join("、")))),
  }
}

/// 给 compose 里的一个容器加上服务设置里的资源上限和环境变量，其余文本保持原样
/// （注释、`[[密钥]]` 引用都不动，所以不重新生成 YAML，只插入几行）。
pub fn compose_with_settings(
  name: &str,
  content: &str,
  spec: &ServiceSpec,
) -> Result<String, ApiError> {
  let limits = spec.limits.clone().unwrap_or_default();
  if limits.memory_mb.is_none()
    && limits.cpu_milli.is_none()
    && spec.env.is_empty()
  {
    return Ok(content.to_string());
  }
  let target =
    compose_target(name, content, spec.container.as_deref())?;
  let unsupported = || {
    ApiError::invalid(format!(
      "服务 {name} 的 compose 写法没法自动加上环境变量或资源上限"
    ))
    .with_hint("直接写在 compose 文件里（environment、mem_limit、cpus），然后去掉设置里的")
  };
  let value: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(content).map_err(|_| unsupported())?;
  let body = &value["services"][target.as_str()];
  if (limits.memory_mb.is_some() || limits.cpu_milli.is_some())
    && ["mem_limit", "cpus", "deploy"]
      .iter()
      .any(|key| body.get(*key).is_some())
  {
    return Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里已经写了 mem_limit、cpus 或 deploy，不能再在这里设资源上限"
    )).with_hint("两处留一处：去掉 compose 里的，或者去掉这里的资源上限"));
  }
  let existing: Vec<String> = match body.get("environment") {
    Some(serde_yaml_ng::Value::Mapping(m)) => m
      .keys()
      .filter_map(|k| k.as_str().map(str::to_string))
      .collect(),
    Some(serde_yaml_ng::Value::Sequence(l)) => l
      .iter()
      .filter_map(|v| v.as_str())
      .map(|v| v.split('=').next().unwrap_or(v).to_string())
      .collect(),
    _ => vec![],
  };
  if let Some(dup) = spec.env.keys().find(|k| existing.contains(k)) {
    return Err(
      ApiError::invalid(format!(
        "环境变量 {dup} 在 compose 里已经写了"
      ))
      .with_hint("两处留一处：去掉 compose 里的，或者去掉设置里的"),
    );
  }

  // 按行定位：services 下的容器、容器里的 environment。
  let lines: Vec<(usize, &str)> = content
    .split_inclusive('\n')
    .scan(0, |offset, line| {
      let start = *offset;
      *offset += line.len();
      Some((start, line))
    })
    .collect();
  let code = |line: &str| {
    !line.trim().is_empty() && !line.trim_start().starts_with('#')
  };
  let indent =
    |line: &str| line.len() - line.trim_start_matches(' ').len();
  let key = |line: &str| {
    line
      .split(" #")
      .next()
      .unwrap()
      .trim()
      .strip_suffix(':')
      .map(|k| k.trim_matches(['"', '\'']).to_string())
  };
  if lines.iter().any(|(_, l)| l.contains('\t')) {
    return Err(unsupported());
  }
  let services = lines
    .iter()
    .position(|(_, l)| {
      code(l)
        && indent(l) == 0
        && key(l).as_deref() == Some("services")
    })
    .ok_or_else(unsupported)?;
  let n = lines[services + 1..]
    .iter()
    .find(|(_, l)| code(l))
    .map(|(_, l)| indent(l))
    .filter(|n| *n > 0)
    .ok_or_else(unsupported)?;
  let header = (services + 1..lines.len())
    .take_while(|i| !code(lines[*i].1) || indent(lines[*i].1) >= n)
    .find(|i| {
      let l = lines[*i].1;
      code(l)
        && indent(l) == n
        && key(l).as_deref() == Some(target.as_str())
    })
    .ok_or_else(unsupported)?;
  let body_end = (header + 1..lines.len())
    .find(|i| code(lines[*i].1) && indent(lines[*i].1) <= n)
    .unwrap_or(lines.len());
  let m = lines[header + 1..body_end]
    .iter()
    .find(|(_, l)| code(l))
    .map(|(_, l)| indent(l))
    .filter(|m| *m > n)
    .ok_or_else(unsupported)?;
  let eol = if lines[header].1.ends_with("\r\n") {
    "\r\n"
  } else {
    "\n"
  };
  let pad = " ".repeat(m);
  let quote = |v: &str| {
    serde_json::to_string(&v.replace('$', "$$")).unwrap_or_default()
  };
  let mut inserts: Vec<(usize, String)> = Vec::new();
  let memory = limits.memory_mb.map(|mb| format!("{mb}m"));
  let cpus = limits.cpu_milli.map(cpus_text);
  let mut added = String::new();
  if let Some(memory) = &memory {
    added.push_str(&format!("{pad}mem_limit: {memory}{eol}"));
  }
  if let Some(cpus) = &cpus {
    added.push_str(&format!("{pad}cpus: \"{cpus}\"{eol}"));
  }
  if !spec.env.is_empty() {
    let env_line = (header + 1..body_end).find(|i| {
      let l = lines[*i].1;
      code(l)
        && indent(l) == m
        && l.trim_start().starts_with("environment:")
    });
    match env_line {
      None => {
        added.push_str(&format!("{pad}environment:{eol}"));
        for (k, v) in &spec.env {
          added.push_str(&format!("{pad}  {k}: {}{eol}", quote(v)));
        }
      }
      Some(e) => {
        if key(lines[e].1).as_deref() != Some("environment") {
          return Err(unsupported());
        }
        let item = lines[e + 1..body_end]
          .iter()
          .find(|(_, l)| code(l))
          .filter(|(_, l)| indent(l) > m)
          .map(|(_, l)| *l)
          .ok_or_else(unsupported)?;
        let k_pad = " ".repeat(indent(item));
        let list = item.trim_start().starts_with("- ");
        let mut text = String::new();
        for (k, v) in &spec.env {
          if list {
            text.push_str(&format!(
              "{k_pad}- {}{eol}",
              quote(&format!("{k}={v}"))
            ));
          } else {
            text.push_str(&format!("{k_pad}{k}: {}{eol}", quote(v)));
          }
        }
        inserts.push((lines[e].0 + lines[e].1.len(), text));
      }
    }
  }
  if !added.is_empty() {
    inserts.push((lines[header].0 + lines[header].1.len(), added));
  }
  inserts.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
  let mut out = content.to_string();
  for (at, text) in inserts {
    out.insert_str(at, &text);
  }
  // 插完再解析一遍，确认加到了对的容器上。
  let parsed: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).map_err(|_| unsupported())?;
  let actual = &parsed["services"][target.as_str()];
  for (key, expected) in [("mem_limit", memory), ("cpus", cpus)] {
    if let Some(expected) = expected
      && actual.get(key).and_then(|v| v.as_str())
        != Some(expected.as_str())
    {
      return Err(unsupported());
    }
  }
  for k in spec.env.keys() {
    let found = match actual.get("environment") {
      Some(serde_yaml_ng::Value::Mapping(map)) => {
        map.get(k.as_str()).is_some()
      }
      Some(serde_yaml_ng::Value::Sequence(l)) => l
        .iter()
        .filter_map(|v| v.as_str())
        .any(|v| v.split('=').next() == Some(k.as_str())),
      _ => false,
    };
    if !found {
      return Err(unsupported());
    }
  }
  Ok(out)
}

/// 服务的 compose 文件。image 来源自动生成；compose 来源原样使用。
/// 端口只绑定 127.0.0.1 和内网地址，不绑定 0.0.0.0。
pub fn service_compose(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  bind_ips: &[String],
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  match &spec.source {
    Source::Compose { content, .. } => {
      let content = content.as_deref().unwrap_or_default();
      substitute_values(
        &compose_with_settings(name, content, spec)?,
        secrets,
        true,
      )
    }
    Source::Image(_) | Source::Build(_) => {
      let mut service = image_service(name, spec, secrets)?;
      for port in &spec.ports {
        let (Some(host), Some(container)) =
          (host_ports.get(&port.name), port.container)
        else {
          continue;
        };
        let protocol = if port.udp { "/udp" } else { "" };
        service
          .ports
          .push(format!("127.0.0.1:{host}:{container}{protocol}"));
        for ip in bind_ips {
          service
            .ports
            .push(format!("{ip}:{host}:{container}{protocol}"));
        }
      }
      service.volumes = spec
        .volumes
        .iter()
        .map(|v| {
          format!("{}:{}", volume_dir(name, &v.name), v.target)
        })
        .collect();
      let file = ComposeFile {
        name: name.to_string(),
        services: BTreeMap::from([(name.to_string(), service)]),
      };
      Ok(to_yaml(&file))
    }
  }
}

fn image_service(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<ComposeService, ApiError> {
  let image = match &spec.source {
    Source::Build(b) => build_image(name, b, &spec.ports),
    Source::Image(image) => image.clone(),
    Source::Compose { .. } => unreachable!(),
  };
  let mut environment = BTreeMap::new();
  for (key, value) in &spec.env {
    // compose 会对 `$` 做变量插值，原样传给容器要写成 `$$`。
    let value = substitute_values(value, secrets, true)?;
    environment.insert(key.clone(), value.replace('$', "$$"));
  }
  Ok(ComposeService {
    image,
    restart: "unless-stopped",
    mem_limit: spec
      .limits
      .as_ref()
      .and_then(|l| l.memory_mb)
      .map(|mb| format!("{mb}m")),
    cpus: spec
      .limits
      .as_ref()
      .and_then(|l| l.cpu_milli)
      .map(cpus_text),
    network_mode: None,
    entrypoint: None,
    command: None,
    environment,
    ports: Vec::new(),
    volumes: Vec::new(),
    labels: BTreeMap::from([(
      "wharf.service".to_string(),
      name.to_string(),
    )]),
  })
}

/// 试跑用的 compose：同一个镜像和环境变量，不发布端口、不自动重启。
/// 只用于 image、build 来源且没有数据卷的服务。
pub fn trial_compose(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  let mut service = image_service(name, spec, secrets)?;
  service.restart = "no";
  service.labels =
    BTreeMap::from([("wharf.trial".into(), name.into())]);
  Ok(to_yaml(&ComposeFile {
    name: format!("{TRIAL_PROJECT_PREFIX}{name}"),
    services: BTreeMap::from([(name.to_string(), service)]),
  }))
}

/// 配置文件内容里的 `[[密钥名]]` 只替换确实存在的密钥，别的原样保留
/// （TOML 的 `[[servers]]` 这类写法不能当成密钥引用）。`secrets` 为空时原样返回。
pub fn file_content(
  content: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> String {
  let Some(secrets) = secrets else {
    return content.to_string();
  };
  let mut out = String::with_capacity(content.len());
  let mut rest = content;
  while let Some((start, name)) = next_placeholder(rest) {
    let end = start + 4 + name.len();
    out.push_str(&rest[..start]);
    match secrets.get(name) {
      Some(value) => out.push_str(value),
      None => out.push_str(&rest[start..end]),
    }
    rest = &rest[end..];
  }
  out.push_str(rest);
  out
}

/// 把配置文件放进 compose：顶层 `configs` 用 `content` 写内容，容器的 `configs` 引用它。
/// compose 判断要不要重建容器时不看内容，所以名字里带内容的哈希，内容一变名字就变，容器跟着重建。
/// `files` 是（容器内路径，已替换好的内容）。没有配置文件时原样返回，不重新生成 YAML。
pub fn add_files(
  name: &str,
  spec: &ServiceSpec,
  compose: &str,
  files: &[(String, String)],
) -> Result<String, ApiError> {
  if files.is_empty() {
    return Ok(compose.to_string());
  }
  let target = match &spec.source {
    Source::Compose { .. } => {
      compose_target(name, compose, spec.container.as_deref())?
    }
    _ => name.to_string(),
  };
  let bad = || {
    ApiError::invalid(format!(
      "服务 {name} 的 compose 写法没法自动加上配置文件"
    ))
    .with_hint(
      "直接写在 compose 文件的 configs 里，然后去掉设置里的配置文件",
    )
  };
  let mut doc: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(compose).map_err(|_| bad())?;
  let key = |s: &str| serde_yaml_ng::Value::String(s.to_string());
  let mut defs = serde_yaml_ng::Mapping::new();
  let mut refs = Vec::new();
  for (i, (path, content)) in files.iter().enumerate() {
    let content = content.replace('$', "$$");
    let id = format!("wharf-file-{i}-{}", &hash(&content)[..12]);
    let mut def = serde_yaml_ng::Mapping::new();
    def.insert(key("content"), key(&content));
    defs.insert(key(&id), serde_yaml_ng::Value::Mapping(def));
    let mut r = serde_yaml_ng::Mapping::new();
    r.insert(key("source"), key(&id));
    r.insert(key("target"), key(path));
    refs.push(serde_yaml_ng::Value::Mapping(r));
  }
  let root = doc.as_mapping_mut().ok_or_else(bad)?;
  match root.entry(key("configs")).or_insert_with(|| {
    serde_yaml_ng::Value::Mapping(Default::default())
  }) {
    serde_yaml_ng::Value::Mapping(m) => m.extend(defs),
    _ => return Err(bad()),
  }
  let svc = root
    .get_mut("services")
    .and_then(|s| s.get_mut(target.as_str()))
    .and_then(|s| s.as_mapping_mut())
    .ok_or_else(bad)?;
  match svc
    .entry(key("configs"))
    .or_insert_with(|| serde_yaml_ng::Value::Sequence(vec![]))
  {
    serde_yaml_ng::Value::Sequence(list) => list.extend(refs),
    _ => return Err(bad()),
  }
  let head = if compose.starts_with('#') {
    compose
      .lines()
      .next()
      .map(|l| format!("{l}\n"))
      .unwrap_or_default()
  } else {
    String::new()
  };
  Ok(format!(
    "{head}{}",
    serde_yaml_ng::to_string(&doc).map_err(|_| bad())?
  ))
}

/// compose 来源的基本检查：必须有 services，P1 不支持 build。
pub fn check_compose(
  name: &str,
  content: &str,
) -> Result<(), ApiError> {
  let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content)
    .map_err(|e| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 不是合法的 YAML：{e}"
      ))
    })?;
  let services = value
    .get("services")
    .and_then(|s| s.as_mapping())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 里没有 services"
      ))
    })?;
  for (svc, body) in services {
    if body.get("build").is_some() {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的 compose 里 {} 用了 build，不在服务器上构建",
          svc.as_str().unwrap_or("?")
        ))
        .with_hint("先构建并推送镜像，compose 里改用 image"),
      );
    }
  }
  Ok(())
}
