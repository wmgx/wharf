use std::{
  collections::BTreeSet,
  path::{Component, Path},
};

use serde_yaml_ng::Value;

use crate::{
  ApiError,
  spec::{ServiceSpec, Source},
  validate_name,
};

pub fn normalize_stop_signal(raw: &str) -> Result<String, ApiError> {
  let mut signal = raw.trim().to_ascii_uppercase();
  if !signal.starts_with("SIG") {
    signal.insert_str(0, "SIG");
  }
  match signal.as_str() {
    "SIGTERM" | "SIGINT" | "SIGQUIT" | "SIGHUP" | "SIGUSR1" | "SIGUSR2"
    | "SIGWINCH" | "SIGALRM" | "SIGRTMIN+3" => Ok(signal),
    _ => Err(ApiError::invalid("停机信号不支持").with_hint(
      "常用信号：SIGTERM、SIGINT、SIGQUIT、SIGHUP、SIGUSR1、SIGUSR2、SIGWINCH",
    )),
  }
}

pub fn parse_compose_max_grace_secs(yaml: &str) -> u64 {
  let Ok(mut value) = serde_yaml_ng::from_str::<Value>(yaml) else {
    return 10;
  };
  if value.apply_merge().is_err() {
    return 10;
  }
  value
    .get("services")
    .and_then(Value::as_mapping)
    .into_iter()
    .flat_map(|services| services.values())
    .map(|service| {
      let grace = service.get("stop_grace_period");
      grace
        .and_then(Value::as_u64)
        .or_else(|| {
          grace.and_then(Value::as_str).and_then(duration_secs)
        })
        .unwrap_or(10)
        .min(600)
    })
    .max()
    .unwrap_or(10)
}

fn duration_secs(mut input: &str) -> Option<u64> {
  if let Ok(secs) = input.parse() {
    return Some(secs);
  }
  let mut total = 0.0;
  while !input.is_empty() {
    let end =
      input.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let n: f64 = input[..end].parse().ok()?;
    let (unit, scale) = [
      ("ms", 0.001),
      ("us", 0.000_001),
      ("µs", 0.000_001),
      ("ns", 0.000_000_001),
      ("h", 3600.0),
      ("m", 60.0),
      ("s", 1.0),
    ]
    .into_iter()
    .find(|(unit, _)| input[end..].starts_with(unit))?;
    total += n * scale;
    input = &input[end + unit.len()..];
  }
  Some(total.ceil() as u64)
}

pub fn merge_compose(
  value: &mut Value,
) -> Result<(), serde_yaml_ng::Error> {
  // 先展开被继承的映射，避免一层合并漏掉链式继承或改变优先级。
  match value {
    Value::Mapping(map) => {
      for child in map.values_mut() {
        merge_compose(child)?;
      }
      if map.contains_key("<<") {
        value.apply_merge()?;
      }
    }
    Value::Sequence(seq) => {
      for child in seq {
        merge_compose(child)?;
      }
    }
    Value::Tagged(tag) => merge_compose(&mut tag.value)?,
    _ => {}
  }
  Ok(())
}

pub fn parse_compose(content: &str) -> Result<Value, ApiError> {
  let mut doc: Value =
    serde_yaml_ng::from_str(content).map_err(|e| {
      let location = e.location().map_or_else(String::new, |loc| {
        format!("（第 {} 行第 {} 列）", loc.line(), loc.column())
      });
      ApiError::invalid(format!("compose 不是合法的 YAML{location}"))
    })?;
  merge_compose(&mut doc).map_err(|_| {
    ApiError::invalid("compose YAML 锚点合并不合法")
      .with_hint("检查 <<: *anchor 是否指向映射")
  })?;
  Ok(doc)
}

pub enum Mount {
  Bind,
  Volume,
}

/// 短写法 `源:目标[:选项]` 或长写法 `{type, source, target}`；tmpfs 不算数据。
pub fn parse_mount(v: &Value) -> Option<(Mount, String, String)> {
  if let Some(s) = v.as_str() {
    let mut parts = s.splitn(3, ':');
    let first = parts.next()?.to_string();
    return Some(match parts.next() {
      None => (Mount::Volume, String::new(), first),
      Some(target) => {
        let kind = if is_path(&first) {
          Mount::Bind
        } else {
          Mount::Volume
        };
        (kind, first, target.to_string())
      }
    });
  }
  let get =
    |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
  let target = get("target").to_string();
  let source = get("source").to_string();
  match get("type") {
    "bind" => Some((Mount::Bind, source, target)),
    "volume" | "" => Some((Mount::Volume, source, target)),
    _ => None,
  }
}

fn is_path(s: &str) -> bool {
  s.starts_with('/')
    || s.starts_with('.')
    || s.starts_with('~')
    || s.starts_with('$')
}

/// 绝对路径、没有 `..`、在 `/srv/<服务>/` 下才算 Wharf 管理。
pub fn is_managed_dir(name: &str, source: &str) -> bool {
  let path = Path::new(source.trim_end_matches('/'));
  let clean = path.is_absolute()
    && path.components().all(|c| {
      matches!(c, Component::RootDir | Component::Normal(_))
    });
  clean && path.starts_with(Path::new("/srv").join(name))
}

pub fn owned_volumes(
  name: &str,
  spec: &ServiceSpec,
) -> BTreeSet<String> {
  if let Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
  {
    let Ok(doc) = parse_compose(content) else {
      return BTreeSet::new();
    };
    let root = Path::new("/srv").join(name);
    doc
      .get("services")
      .and_then(Value::as_mapping)
      .into_iter()
      .flat_map(|services| services.values())
      .filter_map(|def| {
        def.get("volumes").and_then(Value::as_sequence)
      })
      .flatten()
      .filter_map(|mount| {
        let (Mount::Bind, source, _) = parse_mount(mount)? else {
          return None;
        };
        if !is_managed_dir(name, &source) {
          return None;
        }
        let volume =
          Path::new(&source).strip_prefix(&root).ok()?.to_str()?;
        validate_name("数据卷", volume).ok()?;
        Some(volume.to_string())
      })
      .collect()
  } else {
    spec
      .volumes
      .iter()
      .filter(|v| v.from_service.is_none())
      .map(|v| v.name.clone())
      .collect()
  }
}
