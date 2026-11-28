//! 意图文件 fleet.toml 的读写。

use std::{
  collections::{BTreeMap, BTreeSet},
  io::Read,
  path::{Path, PathBuf},
};

use anyhow::Context;
use wharf_api_types::{
  references::{parse_placeholder, parse_service_ref, placeholders},
  spec::{Fleet, Source},
};

/// 加载单个意图文件，或按路径顺序合并目录中的意图片段。
pub fn load(path: &Path) -> anyhow::Result<Fleet> {
  load_files(path).map(|(fleet, _)| fleet)
}

fn load_files(path: &Path) -> anyhow::Result<(Fleet, Vec<PathBuf>)> {
  let meta = std::fs::symlink_metadata(path)
    .with_context(|| format!("读取 {}", path.display()))?;
  anyhow::ensure!(
    !meta.is_symlink() || !path.is_dir(),
    "意图目录不能是符号链接：{}",
    path.display()
  );
  if !meta.is_dir() {
    return Ok((load_one(path)?, vec![path.to_path_buf()]));
  }
  let files = collect_toml_files(path)?;
  let parts = files
    .iter()
    .map(|f| Ok((f.strip_prefix(path)?.to_path_buf(), load_one(f)?)))
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok((merge_fleets(parts)?, files))
}

fn collect_toml_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let mut pending = vec![dir.to_owned()];
  let mut files = Vec::new();
  while let Some(parent) = pending.pop() {
    for entry in std::fs::read_dir(&parent)
      .with_context(|| format!("读取目录 {}", parent.display()))?
    {
      let entry = entry?;
      if entry.file_name().to_string_lossy().starts_with('.') {
        continue;
      }
      let path = entry.path();
      let kind = entry.file_type()?;
      anyhow::ensure!(
        !kind.is_symlink() || !path.is_dir(),
        "意图目录不能是符号链接：{}",
        path.display()
      );
      if kind.is_dir() {
        pending.push(path);
      } else if path.extension().is_some_and(|ext| ext == "toml")
        && (kind.is_file() || kind.is_symlink() && path.is_file())
      {
        files.push(path);
      }
    }
  }
  files.sort_unstable();
  anyhow::ensure!(
    !files.is_empty(),
    "目录 {} 里没有 .toml 文件",
    dir.display()
  );
  Ok(files)
}

fn merge_fleets(
  parts: Vec<(PathBuf, Fleet)>,
) -> anyhow::Result<Fleet> {
  let mut merged = Fleet::default();
  let mut sources = BTreeMap::new();
  let mut duplicates = Vec::new();
  for (path, part) in parts {
    let mut first = |kind, name: &str| match sources
      .entry((kind, name.to_owned()))
    {
      std::collections::btree_map::Entry::Vacant(entry) => {
        entry.insert(path.clone());
        true
      }
      std::collections::btree_map::Entry::Occupied(entry) => {
        duplicates.push(format!(
          "- {kind} {name}：{} 与 {}",
          entry.get().display(),
          path.display()
        ));
        false
      }
    };
    macro_rules! merge {
      ($field:ident, $kind:literal) => {
        merged.$field.extend(
          part
            .$field
            .into_iter()
            .filter(|(name, _)| first($kind, name)),
        );
      };
    }
    merge!(servers, "服务器");
    merge!(services, "服务");
    merge!(gateways, "网关");
    merge!(edge_apps, "边缘应用");
    merge!(bookmarks, "书签");
    merged
      .routes
      .extend(part.routes.into_iter().filter(|route| {
        first(
          "路由",
          &route
            .hostname
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        )
      }));
  }
  anyhow::ensure!(
    duplicates.is_empty(),
    "合并目录失败，发现 {} 处重复定义：\n{}",
    duplicates.len(),
    duplicates.join("\n")
  );
  Ok(merged)
}

fn read_external(
  path: &Path,
  owner: &str,
  file: &str,
  bounded: bool,
) -> anyhow::Result<String> {
  let file = Path::new(file);
  anyhow::ensure!(
    !file.as_os_str().is_empty() && file.is_relative(),
    "{} 中的 {owner}：外置文件必须使用非空相对路径",
    path.display()
  );
  let full = path.parent().unwrap_or(Path::new(".")).join(file);
  let context = || {
    format!(
      "{} 中的 {owner}：读取 {}",
      path.display(),
      full.display()
    )
  };
  if !bounded {
    return std::fs::read_to_string(&full).with_context(context);
  }
  const MAX: usize = 64 * 1024;
  let mut content = String::new();
  let f = std::fs::File::open(&full).with_context(context)?;
  f.take((MAX + 1) as u64)
    .read_to_string(&mut content)
    .with_context(context)?;
  anyhow::ensure!(content.len() <= MAX, "{}：超过 64 KiB", context());
  Ok(content)
}

fn load_one(path: &Path) -> anyhow::Result<Fleet> {
  let text = std::fs::read_to_string(path)
    .with_context(|| format!("读取 {}", path.display()))?;
  // 类型本身容忍未知字段（新旧版本互通）；自己写的文件仍然报出来，防止拼错。
  let mut unknown = Vec::new();
  let de = toml::Deserializer::parse(&text)
    .with_context(|| format!("{} 格式不对", path.display()))?;
  let mut fleet: Fleet =
    serde_ignored::deserialize(de, |p| unknown.push(p.to_string()))
      .with_context(|| format!("{} 格式不对", path.display()))?;
  anyhow::ensure!(
    unknown.is_empty(),
    "{} 里有不认识的字段：{}（拼错了，或者本机 wharf 太旧）",
    path.display(),
    unknown.join("、")
  );
  for (name, service) in &mut fleet.services {
    if let Source::Compose { content, file } = &mut service.source {
      if let Some(file) = file.take() {
        anyhow::ensure!(
          content.is_none(),
          "{} 中的服务 {name}：compose 不能同时写 content 和 file",
          path.display()
        );
        *content = Some(read_external(
          path,
          &format!("服务 {name} 的 compose"),
          &file,
          false,
        )?);
      } else {
        anyhow::ensure!(
          content.is_some(),
          "服务 {name} 的 compose 需要 content 或 file"
        );
      }
    }
    for f in &mut service.files {
      if let Some(file) = f.file.take() {
        anyhow::ensure!(
          f.content.is_empty(),
          "{} 中的服务 {name}：配置 {} 不能同时写 content 和 file",
          path.display(),
          f.path
        );
        f.content = read_external(
          path,
          &format!("服务 {name} 的配置 {}", f.path),
          &file,
          true,
        )?;
      }
    }
  }
  for route in &mut fleet.routes {
    if let Some(file) = route.caddy_file.take() {
      let host = &route.hostname;
      anyhow::ensure!(
        route.caddy.is_none(),
        "{} 中的路由 {host} 不能同时写 caddy 和 caddy_file",
        path.display()
      );
      route.caddy = Some(read_external(
        path,
        &format!("路由 {host}"),
        &file,
        false,
      )?);
    }
  }
  Ok(fleet)
}

pub fn to_toml(
  fleet: &Fleet,
  partial: bool,
) -> anyhow::Result<String> {
  let body =
    toml::to_string_pretty(fleet).context("生成 TOML 失败")?;
  let how = if partial {
    "这是局部导出，修改后执行 wharf plan -f <文件> --partial 查看差异（不加 --partial 会删掉文件里没写的对象）。"
  } else {
    "修改后执行 wharf plan -f <文件> 查看差异。"
  };
  Ok(format!(
    "# Wharf 意图文件，由 wharf export 生成。\n# {how}\n\n{body}"
  ))
}

/// 局部导出：只留这些服务和指向它们的域名。
pub fn only_services(
  fleet: Fleet,
  names: &[String],
) -> Result<Fleet, wharf_api_types::ApiError> {
  if let Some(missing) =
    names.iter().find(|n| !fleet.services.contains_key(*n))
  {
    return Err(
      wharf_api_types::ApiError::not_found(format!(
        "服务 {missing} 不存在"
      ))
      .suggest("wharf service list"),
    );
  }
  Ok(Fleet {
    services: fleet
      .services
      .into_iter()
      .filter(|(n, _)| names.contains(n))
      .collect(),
    routes: fleet
      .routes
      .into_iter()
      .filter(|r| {
        names.contains(&r.service)
          || r.paths.iter().any(|p| {
            p.service.as_ref().is_some_and(|s| names.contains(s))
          })
      })
      .collect(),
    ..Default::default()
  })
}

/// `wharf validate`：不连控制面能查出来的问题。文件里有服务器时按完整状态查引用，
/// 没有时按局部文件查，引用不到的只提醒。
pub fn validate(path: &Path) -> serde_json::Value {
  use serde_json::json;
  let (fleet, files) = match load_files(path) {
    Ok(f) => f,
    Err(e) => {
      return json!({
        "ok": false,
        "file": path.display().to_string(),
        "files": [],
        "errors": [format!("{e:#}")],
        "warnings": [],
      });
    }
  };
  let complete = !fleet.servers.is_empty();
  let (mut errors, mut warnings) = (Vec::new(), Vec::new());
  let names = [
    ("服务器", fleet.servers.keys().collect::<Vec<_>>()),
    ("服务", fleet.services.keys().collect()),
    ("网关", fleet.gateways.keys().collect()),
    ("边缘应用", fleet.edge_apps.keys().collect()),
  ];
  for (kind, list) in names {
    for name in list {
      if let Err(e) = wharf_api_types::validate_name(kind, name) {
        errors.push(e.message);
      }
    }
  }
  // 引用不到：完整状态里是错，局部文件里以控制面为准，只提醒。
  let mut missing = Vec::new();
  for (name, server) in &fleet.servers {
    if let Some(via) = &server.via {
      if via == name {
        errors.push(format!("服务器 {name} 不能经自身出站"));
      } else if !fleet.servers.contains_key(via) {
        missing
          .push(format!("服务器 {name} 的出口 {via} 文件里没有"));
      }
    }
  }
  for (name, gateway) in &fleet.gateways {
    if !fleet.servers.contains_key(&gateway.server) {
      missing.push(format!(
        "网关 {name} 的服务器 {} 文件里没有",
        gateway.server
      ));
    }
    for rule in &gateway.layer4 {
      if let Some(service) = &rule.service
        && !fleet.services.contains_key(service)
      {
        missing.push(format!(
          "网关 {name} 的四层转发服务 {service} 文件里没有"
        ));
      }
    }
  }
  for (name, app) in &fleet.edge_apps {
    if let Some(server) = &app.builder
      && !fleet.servers.contains_key(server)
    {
      missing.push(format!(
        "边缘应用 {name} 的构建机 {server} 文件里没有"
      ));
    }
  }
  let mut referenced_secrets = BTreeSet::new();
  for (name, svc) in &fleet.services {
    let compose = match &svc.source {
      Source::Compose { content, .. } => content.as_deref(),
      _ => None,
    };
    for text in svc
      .env
      .values()
      .map(String::as_str)
      .chain(compose)
      .chain(svc.files.iter().map(|f| f.content.as_str()))
    {
      for p in placeholders(text) {
        if let Some(r) = parse_service_ref(p) {
          match fleet.services.get(r.service) {
            None => missing.push(format!(
              "服务 {name} 引用 [[{p}]]，目标服务文件里没有"
            )),
            Some(target)
              if r.port.map_or(target.ports.is_empty(), |port| {
                target.find_port(Some(port)).is_none()
              }) =>
            {
              missing.push(format!(
                "服务 {name} 引用 [[{p}]]，目标端口文件里没有"
              ))
            }
            Some(_) => {}
          }
        } else if let Ok(Some(secret)) = parse_placeholder(p, false) {
          referenced_secrets.insert(secret.name);
        }
      }
    }
    for volume in &svc.volumes {
      if let Some(reference) = &volume.from_service {
        let Some((owner, vol)) = reference.split_once(':') else {
          errors.push(format!(
            "服务 {name} 的共享卷引用 {reference} 应写成 服务:卷"
          ));
          continue;
        };
        if fleet
          .services
          .get(owner)
          .is_none_or(|s| !s.volumes.iter().any(|v| v.name == vol))
        {
          missing.push(format!(
            "服务 {name} 的共享卷来源 {reference} 文件里没有"
          ));
        }
      }
    }
    if let Some(backup) = &svc.backup {
      if backup.to == svc.server {
        errors.push(format!("服务 {name} 不能备份到自身服务器"));
      } else if !fleet.servers.contains_key(&backup.to) {
        missing.push(format!(
          "服务 {name} 的备份服务器 {} 文件里没有",
          backup.to
        ));
      }
    }
    if !fleet.servers.contains_key(&svc.server) {
      missing.push(format!(
        "服务 {name} 的服务器 {} 文件里没有",
        svc.server
      ));
    }
    if let Source::Compose {
      content: Some(text),
      ..
    } = &svc.source
    {
      match crate::deploy::parse_compose(text) {
        Err(e) => errors.push(format!(
          "服务 {name} 的 compose 不是合法的 YAML：{e}"
        )),
        Ok(doc)
          if doc
            .get("services")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .is_none_or(serde_yaml_ng::Mapping::is_empty) =>
        {
          errors
            .push(format!("服务 {name} 的 compose 缺少非空 services"))
        }
        Ok(_) => {}
      }
    }
  }
  let mut hosts = std::collections::BTreeSet::new();
  for route in &fleet.routes {
    let host =
      route.hostname.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() || !host.contains('.') {
      errors.push(format!("域名 {:?} 不完整", route.hostname));
    }
    if !hosts.insert(host.clone()) {
      errors.push(format!("域名 {host} 写了两次"));
    }
    for target in std::iter::once(&route.service)
      .chain(route.paths.iter().filter_map(|p| p.service.as_ref()))
    {
      if !target.is_empty() && !fleet.services.contains_key(target) {
        if fleet.edge_apps.contains_key(target) {
          errors.push(format!("路由不能指向边缘应用 {target}，请用 wharf edge domain 为边缘应用绑定域名"));
        } else {
          missing
            .push(format!("域名 {host} 的服务 {target} 文件里没有"));
        }
      }
    }
    for gw in route.gateway.iter().chain(&route.backup_gateway) {
      if !fleet.gateways.contains_key(gw) {
        missing.push(format!("域名 {host} 的网关 {gw} 文件里没有"));
      }
    }
  }
  for what in missing {
    if complete {
      errors.push(what);
    } else {
      warnings
        .push(format!("{what}（局部文件，plan 时以控制面为准）"));
    }
  }
  json!({
    "ok": errors.is_empty(),
    "file": path.display().to_string(),
    "files": files,
    "referenced_secrets": referenced_secrets,
    "kind": if complete { "complete" } else { "partial" },
    "counts": {
      "servers": fleet.servers.len(),
      "services": fleet.services.len(),
      "gateways": fleet.gateways.len(),
      "edge_apps": fleet.edge_apps.len(),
      "routes": fleet.routes.len(),
    },
    "errors": errors,
    "warnings": warnings,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn offline_validation_detects_invalid_compose_and_path_targets() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
      temp.path(),
      r#"
[services.api]
server = "s1"
source = { compose = { content = "name: invalid" } }
[[routes]]
hostname = "example.test"
service = "api"
paths = [{ path = "/images/*", service = "missing" }]
"#,
    )
    .unwrap();
    let result = validate(temp.path());
    assert_eq!(result["ok"], false);
    assert!(result["errors"].to_string().contains("非空 services"));
    assert!(result["warnings"].to_string().contains("missing"));
    let mut fleet = load(temp.path()).unwrap();
    fleet.routes[0].service = "other".into();
    fleet.routes[0].paths[0].service = Some("api".into());
    assert_eq!(
      only_services(fleet, &["api".into()]).unwrap().routes.len(),
      1
    );
  }

  #[test]
  fn round_trip_and_compose_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
      dir.path().join("blog.yaml"),
      "services:\n  blog:\n    image: ghost\n",
    )
    .unwrap();
    let path = dir.path().join("fleet.toml");
    std::fs::write(
      &path,
      r#"
[servers.node1]
region = "cn"
registry_mirrors = { "docker.io" = ["docker.1ms.run"] }

[services.whoami]
server = "node1"
source = { image = "traefik/whoami" }
ports = [{ name = "http", container = 80 }]

[services.blog]
server = "node1"
source = { compose = { file = "blog.yaml" } }

[gateways.edge]
kind = "caddy"
server = "node1"
default = true

[[routes]]
hostname = "who.example.com"
service = "whoami"
"#,
    )
    .unwrap();
    let fleet = load(&path).unwrap();
    assert_eq!(
      fleet.services["whoami"].source,
      Source::Image("traefik/whoami".into())
    );
    let Source::Compose { content, .. } =
      &fleet.services["blog"].source
    else {
      panic!("not compose");
    };
    assert!(content.as_deref().unwrap().contains("ghost"));
    let text = to_toml(&fleet, false).unwrap();
    let back: Fleet = toml::from_str(&text).unwrap();
    assert_eq!(back, fleet);

    // 自己写的文件拼错字段要报出来。
    std::fs::write(&path, "[services.x]\nserver = \"node1\"\nsource = { image = \"a\" }\nprots = []\n").unwrap();
    let err = load(&path).unwrap_err().to_string();
    assert!(err.contains("services.x.prots"), "{err}");
  }

  #[test]
  fn validates_partial_and_complete_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blog.toml");
    let body = "[services.blog]\nserver = \"node1\"\nsource = { image = \"ghost\" }\n\n[[routes]]\nhostname = \"blog.example.com\"\nservice = \"blog\"\n";
    std::fs::write(&path, body).unwrap();
    let v = validate(&path);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["kind"], "partial");
    assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
    std::fs::write(&path, format!("[servers.other]\n\n{body}"))
      .unwrap();
    let v = validate(&path);
    assert_eq!(v["ok"], false, "{v}");
  }
}

#[test]
fn validate_reports_template_and_volume_references() {
  let file = tempfile::NamedTempFile::new().unwrap();
  std::fs::write(
    file.path(),
    r#"
[servers.s1]
[services.api]
server = "s1"
source = { image = "app:1" }
env = { DB = "[[@missing-db]]", KEY = "[[API_KEY]]" }
volumes = [{ target = "/data", from_service = "missing-owner:data" }]
"#,
  )
  .unwrap();
  let result = validate(file.path());
  assert_eq!(result["ok"], false);
  assert_eq!(
    result["referenced_secrets"],
    serde_json::json!(["API_KEY"])
  );
  let errors = result["errors"].to_string();
  assert!(
    errors.contains("missing-db") && errors.contains("missing-owner")
  );
}

#[test]
fn fleet_directory_expands_files_and_reports_all_duplicates() {
  let dir = tempfile::tempdir().unwrap();
  let root = dir.path();
  std::fs::create_dir(root.join("services")).unwrap();
  std::fs::create_dir(root.join("routes")).unwrap();
  let write =
    |path, text| std::fs::write(root.join(path), text).unwrap();
  write("servers.toml", "[servers.s1]");
  let service = r#"[services.api]
server = "s1"
source = { image = "app:1" }
files = [{ path = "/etc/a.conf", file = "./a.conf" }]"#;
  write("services/api.toml", service);
  write("services/a.conf", "hello");
  let route = r#"[[routes]]
hostname = "api.example.test"
service = "api"
caddy_file = "./extra.caddy""#;
  write("routes/api.toml", route);
  write("routes/extra.caddy", "header X-Test yes");
  let (fleet, paths) = load_files(root).unwrap();
  assert_eq!(paths.len(), 3);
  assert_eq!(fleet.services["api"].files[0].content, "hello");
  assert!(fleet.services["api"].files[0].file.is_none());
  assert_eq!(
    fleet.routes[0].caddy.as_deref(),
    Some("header X-Test yes")
  );
  assert!(fleet.routes[0].caddy_file.is_none());
  write("services/dup.toml", service);
  write("routes/dup.toml", route);
  let err = load(root).unwrap_err().to_string();
  assert!(
    err.contains("2 处重复定义")
      && err.contains("services/dup.toml")
      && err.contains("routes/dup.toml")
  );
}
