//! 把服务器上已有的 compose 项目或 `docker run` 起的容器转换成 compose 来源的服务。
//!
//! - compose 项目：用 `docker compose config` 解析好的内容。服务名和原项目名相同时，
//!   Wharf 用同一个项目名部署，compose 认作同一个项目，配置一致时不重建容器；
//!   名字不同时原来的数据卷改为外部卷继续使用，原项目的容器在部署前停掉。
//! - 单个容器：按 `docker inspect` 生成 compose，去掉镜像自带的默认值。
//!   原容器部署前改名停掉，失败时恢复。

use std::collections::BTreeSet;

use serde_json::Value as Json;
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  spec::{AdoptSpec, PortSpec},
};

/// 转换结果。
#[derive(Debug, Clone, PartialEq)]
pub struct Converted {
  pub compose: String,
  pub ports: Vec<PortSpec>,
  pub adopt: Option<AdoptSpec>,
  pub warnings: Vec<String>,
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
  project: &str,
  name: &str,
) -> Result<Converted, ApiError> {
  let mut doc: Value =
    serde_yaml_ng::from_str(config).map_err(yaml_err)?;
  let root = doc
    .as_mapping_mut()
    .ok_or_else(|| yaml_err("顶层不是映射"))?;
  root.insert(key("name"), key(name));
  let mut warnings = Vec::new();
  let mut published = Vec::new();
  let mut has_env = false;
  if let Some(services) =
    root.get_mut("services").and_then(Value::as_mapping_mut)
  {
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
      for p in body
        .get("ports")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
      {
        let tcp =
          p.get("protocol").and_then(Value::as_str).unwrap_or("tcp")
            == "tcp";
        let port = match p.get("published") {
          Some(Value::String(s)) => s.parse::<u16>().ok(),
          Some(Value::Number(n)) => n.as_u64().map(|n| n as u16),
          _ => None,
        };
        if let (true, Some(port)) = (tcp, port) {
          published.push(port);
        }
      }
    }
  }
  // 同名时 Wharf 直接沿用这个项目，空的 adopt 只用来标记"刚导入，别拉新镜像"。
  let adopt = if name == project {
    Some(AdoptSpec::default())
  } else {
    // 换了项目名：原来的卷按原名继续用，网络让新项目自己建。
    if let Some(volumes) =
      root.get_mut("volumes").and_then(Value::as_mapping_mut)
    {
      for (k, v) in volumes.iter_mut() {
        let k = k.as_str().unwrap_or_default().to_string();
        if v.is_null() {
          *v = Value::Mapping(Mapping::new());
        }
        let Some(m) = v.as_mapping_mut() else {
          continue;
        };
        if m.get("external").and_then(Value::as_bool) != Some(true) {
          let real = m
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{project}_{k}"));
          m.clear();
          m.insert(key("external"), Value::Bool(true));
          m.insert(key("name"), key(&real));
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
    Some(AdoptSpec {
      project: Some(project.to_string()),
      containers: vec![],
    })
  };
  if has_env {
    warnings.push(env_warning());
  }
  let compose = format!(
    "# 由 Wharf 从服务器上的 compose 项目 {project} 导入。\n{}",
    serde_yaml_ng::to_string(&doc).map_err(yaml_err)?
  );
  Ok(Converted {
    compose,
    ports: port_specs(published),
    adopt,
    warnings,
  })
}

fn env_warning() -> String {
  "环境变量（可能含密码）以明文存进 Wharf，需要时改成 [[密钥名]] 引用"
    .into()
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
  svc.insert(key("image"), key(image));
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
  let host_net = mode == "host";
  match mode {
    "" | "default" | "bridge" => {}
    "host" | "none" => {
      svc.insert(key("network_mode"), key(mode));
    }
    m if m.starts_with("container:") => {
      svc.insert(key("network_mode"), key(m));
      warnings.push(format!(
        "网络模式 {m} 依赖另一个容器，导入后要确认它还在"
      ));
    }
    custom => {
      svc.insert(key("networks"), seq(vec![custom.to_string()]));
      let mut m = Mapping::new();
      m.insert(key("external"), Value::Bool(true));
      networks_top.insert(key(custom), Value::Mapping(m));
    }
  }

  let mut published = Vec::new();
  let mut ports = Vec::new();
  if !host_net
    && let Some(bindings) = host["PortBindings"].as_object()
  {
    for (container_port, list) in bindings {
      let (port, proto) = container_port
        .split_once('/')
        .unwrap_or((container_port, "tcp"));
      for b in list.as_array().into_iter().flatten() {
        let host_port = b["HostPort"].as_str().unwrap_or_default();
        let ip = b["HostIp"].as_str().unwrap_or_default();
        let mut spec = String::new();
        if !ip.is_empty() && ip != "0.0.0.0" && ip != "::" {
          spec.push_str(&format!("{ip}:"));
        }
        if !host_port.is_empty() {
          spec.push_str(&format!("{host_port}:"));
        }
        spec.push_str(port);
        if proto != "tcp" {
          spec.push_str(&format!("/{proto}"));
        } else if let Ok(p) = host_port.parse::<u16>() {
          published.push(p);
        }
        if !ports.contains(&spec) {
          ports.push(spec);
        }
      }
    }
  }
  if !ports.is_empty() {
    svc.insert(key("ports"), seq(ports));
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
        mounts.push(format!("{src}:{dest}{ro}"));
      }
      "volume" => {
        let vol = m["Name"].as_str().unwrap_or_default();
        mounts.push(format!("{vol}:{dest}{ro}"));
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
  ] {
    let set = match &host[field] {
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
    adopt: Some(AdoptSpec {
      project: None,
      containers: vec![original],
    }),
    warnings,
  })
}

#[cfg(test)]
mod tests {
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
    let c = from_compose(CONFIG, "blog", "blog").unwrap();
    assert_eq!(c.adopt, Some(AdoptSpec::default()));
    assert_eq!(c.ports[0].host, Some(8080));
    assert!(c.compose.contains("image: blog-web"));
    assert!(!c.compose.contains("build"));
    crate::render::check_compose("blog", &c.compose).unwrap();
  }

  #[test]
  fn compose_new_name_reuses_volumes() {
    let c = from_compose(CONFIG, "blog", "site").unwrap();
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
    let c =
      from_container(&inspect, Some(&image), "pairdrop").unwrap();
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
