use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::{collections::BTreeMap, path::Path};
use wharf_api_types::{ApiError, spec::FileSpec};

use crate::{
  render::{self, Net},
  snapshot,
  world::World,
};

pub(crate) fn validate_compose_structure(
  name: &str,
  doc: &Value,
) -> Result<(), ApiError> {
  let invalid = |reason| {
    ApiError::invalid(format!("服务 {name} 的 compose {reason}"))
      .with_hint("检查 YAML 缩进和字段格式")
  };
  let services = doc
    .get("services")
    .and_then(Value::as_mapping)
    .filter(|s| !s.is_empty())
    .ok_or_else(|| invalid("里没有 services".to_string()))?;
  for (key, body) in services {
    let component = key.as_str().unwrap_or("?");
    if !key.is_string() || !body.is_mapping() {
      return Err(invalid(format!("容器 {component} 的类型不对")));
    }
    if body.get("build").is_some() {
      return Err(
        invalid(format!(
          "里 {component} 用了 build，不在服务器上构建"
        ))
        .with_hint("先构建并推送镜像，compose 里改用 image"),
      );
    }
    if body
      .get("image")
      .and_then(Value::as_str)
      .is_none_or(|s| s.trim().is_empty())
    {
      return Err(
        invalid(format!("容器 {component} 缺少 image 字段"))
          .with_hint(
            "Wharf 不在 Compose 里直接构建，请填写 image: <镜像名>",
          ),
      );
    }
    for field in ["environment", "ports", "volumes", "configs"] {
      if body.get(field).is_some_and(|v| {
        !(v.is_null()
          || v.is_sequence()
          || field == "environment" && v.is_mapping())
      }) {
        return Err(invalid(format!(
          "容器 {component} 的 {field} 类型不对"
        )));
      }
    }
  }
  for field in ["configs", "volumes", "networks"] {
    if doc
      .get(field)
      .is_some_and(|v| !v.is_null() && !v.is_mapping())
    {
      return Err(invalid(format!("顶层 {field} 的类型不对")));
    }
  }
  Ok(())
}

pub(crate) fn validate_rendered_compose(
  name: &str,
  yaml: &str,
) -> Result<(), ApiError> {
  let bad = |reason| {
    ApiError::invalid(format!("服务 {name} 渲染后的 {reason}"))
      .with_hint("检查 compose 里的 [[@服务]] 或模板写法，有特殊字符的值请加引号")
  };
  let doc =
    render::parse_compose(yaml).map_err(|e| bad(e.message))?;
  if doc
    .get("services")
    .and_then(Value::as_mapping)
    .is_none_or(Mapping::is_empty)
  {
    return Err(bad("compose 里没有 services".into()));
  }
  Ok(())
}

pub(crate) fn validate_service_files(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
  log_values: &[String],
) -> Result<(), ApiError> {
  let mut mounts = Default::default();
  for file in &world.services[name].spec.files {
    if file.raw {
      continue;
    }
    if let Some(format) = file_format(file) {
      let rendered = snapshot::render_config_file(
        world,
        net,
        name,
        file,
        Some(secrets),
        &mut mounts,
      )?;
      validate_service_file(name, file, format, &rendered).map_err(
        |mut error| {
          let mut masks: Vec<_> = secrets.values().cloned().collect();
          crate::log_redact::add_encoded_values(&mut masks);
          masks.extend_from_slice(log_values);
          error.message =
            wharf_api_types::mask_values(&error.message, &masks);
          error
        },
      )?;
    }
  }
  Ok(())
}

fn file_format(file: &FileSpec) -> Option<&'static str> {
  let path = Path::new(&file.path);
  if path
    .file_name()?
    .to_str()?
    .eq_ignore_ascii_case("Caddyfile")
  {
    return Some("Caddyfile");
  }
  match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
    "json" => Some("JSON"),
    "yaml" | "yml" => Some("YAML"),
    "toml" => Some("TOML"),
    "caddy" => Some("Caddyfile"),
    _ => None,
  }
}

fn validate_service_file(
  name: &str,
  file: &FileSpec,
  format: &str,
  rendered: &str,
) -> Result<(), ApiError> {
  // 只从解析器取位置和固定分类，解析器的错误文本可能包含插入的密钥。
  let location = match format {
    "JSON" => serde_json::from_str::<serde_json::Value>(rendered)
      .err()
      .map(|e| format!("第 {} 行第 {} 列", e.line(), e.column())),
    "YAML" => serde_yaml_ng::Deserializer::from_str(rendered)
      .find_map(|doc| match Value::deserialize(doc) {
        Ok(mut value) => render::merge_compose(&mut value)
          .err()
          .map(|_| "锚点合并不合法".into()),
        Err(e) => Some(e.location().map_or_else(
          || "语法错误".into(),
          |loc| format!("第 {} 行第 {} 列", loc.line(), loc.column()),
        )),
      }),
    "TOML" => {
      toml::from_str::<toml::Value>(rendered).err().map(|e| {
        e.span()
          .and_then(|span| rendered.get(..span.start))
          .map_or_else(
            || "语法错误".into(),
            |before| {
              let line =
                before.bytes().filter(|&b| b == b'\n').count() + 1;
              let col = before
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1;
              format!("第 {line} 行第 {col} 列")
            },
          )
      })
    }
    "Caddyfile" => {
      crate::caddy_validate::check_caddyfile(rendered).err()
    }
    _ => unreachable!(),
  };
  if let Some(location) = location {
    let hint = if file.content.contains("[[") {
      "检查文件语法；密钥值含引号或换行时可用 [[json:密钥名]]，非标准格式可用 --raw 跳过预检"
    } else {
      "修正配置文件语法后重试；非标准格式可用 --raw 跳过预检"
    };
    return Err(
      ApiError::invalid(format!(
        "服务 {name} 的配置文件 {} 不是合法的 {format}（{location}）",
        file.path
      ))
      .with_hint(hint),
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn validates_json_yaml_toml_caddy_without_leaking_secrets() {
    let file = FileSpec {
      file: None,
      path: "/etc/app/config".into(),
      content: "[[S]]".into(),
      raw: false,
      init_only: false,
      mode: None,
      owner: None,
      on_change: None,
    };
    for (format, text, secret) in [
      ("JSON", "{\"key\":\"a\"b\"}", "a\"b"),
      ("TOML", "key = \"x\"y\nz\"", "x\"y"),
      ("YAML", "x: 1\n---\nx: 2\n  broken: 3", "broken"),
      ("Caddyfile", "} # 留在配置文件里", "留在配置文件里"),
    ] {
      let err = validate_service_file("app", &file, format, text)
        .unwrap_err();
      assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
      let escaped = serde_json::to_string(secret).unwrap();
      assert!(
        !serde_json::to_string(&err)
          .unwrap()
          .contains(&escaped[1..escaped.len() - 1])
      );
      assert!(err.message.contains("第 "));
    }
    assert!(
      validate_service_file("app", &file, "YAML", "x: 1\n---\nx: 2")
        .is_ok()
    );
  }
}
