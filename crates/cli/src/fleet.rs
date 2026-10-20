//! 意图文件 fleet.toml 的读写。

use std::path::Path;

use anyhow::Context;
use wharf_api_types::spec::{Fleet, Source};

/// 读取意图文件，把 `source = { compose = { file = "..." } }` 换成文件内容。
/// 相对路径以意图文件所在目录为准。
pub fn load(path: &Path) -> anyhow::Result<Fleet> {
  let text = std::fs::read_to_string(path)
    .with_context(|| format!("读取 {}", path.display()))?;
  let mut fleet: Fleet = toml::from_str(&text)
    .with_context(|| format!("{} 格式不对", path.display()))?;
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

pub fn to_toml(fleet: &Fleet) -> anyhow::Result<String> {
  let body =
    toml::to_string_pretty(fleet).context("生成 TOML 失败")?;
  Ok(format!(
    "# Wharf 意图文件，由 wharf export 生成。\n# 修改后执行 wharf plan -f <文件> 查看差异。\n\n{body}"
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

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
ports = [{ name = "http", port = 80 }]

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
    let text = to_toml(&fleet).unwrap();
    let back: Fleet = toml::from_str(&text).unwrap();
    assert_eq!(back, fleet);
  }
}
