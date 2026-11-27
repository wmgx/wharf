//! 意图文件 fleet.toml 的读写。

use std::path::Path;

use anyhow::Context;
use wharf_api_types::spec::{Fleet, Source};

/// 读取意图文件，把 `source = { compose = { file = "..." } }` 换成文件内容。
/// 相对路径以意图文件所在目录为准。
pub fn load(path: &Path) -> anyhow::Result<Fleet> {
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
  let base = path.parent().unwrap_or(Path::new("."));
  for (name, service) in &mut fleet.services {
    if let Source::Compose { content, file } = &mut service.source
      && content.is_none()
    {
      let Some(file) = file.take() else {
        anyhow::bail!("服务 {name} 的 compose 需要 content 或 file");
      };
      let full = base.join(&file);
      *content =
        Some(std::fs::read_to_string(&full).with_context(|| {
          format!("服务 {name}：读取 {}", full.display())
        })?);
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
  let fleet = match load(path) {
    Ok(f) => f,
    Err(e) => {
      return json!({
        "ok": false,
        "file": path.display().to_string(),
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
  for (name, svc) in &fleet.services {
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
          if !doc
            .get("services")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .is_some_and(|m| !m.is_empty()) =>
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
