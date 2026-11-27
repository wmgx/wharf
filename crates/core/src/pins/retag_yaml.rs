//! YAML 解析决定改哪些镜像，扫描器只提供原文的字节区间。

use std::{collections::BTreeSet, mem::MaybeUninit, ops::Range};

use serde_yaml_ng::Value;
use wharf_api_types::ApiError;

use crate::render::{mark_compose_refs, parse_compose_template};

pub(super) fn rewrite(
  content: &str,
  image: &str,
  new: &str,
) -> Result<Option<String>, ApiError> {
  let mut expected = parse_compose_template(content)?;
  let mut prefix = "wharf-retag-marker-".to_string();
  while content.contains(&prefix) || image.starts_with(&prefix) {
    prefix.push('_');
  }
  let invalid = || {
    ApiError::invalid("无法只修改 compose 的镜像值")
      .with_hint("请直接编辑 compose 中对应容器的 image")
  };
  let targets: Vec<_> = expected
    .get("services")
    .and_then(Value::as_mapping)
    .into_iter()
    .flat_map(|services| services.iter())
    .filter(|(_, svc)| {
      svc.get("build").is_none()
        && svc["image"].as_str().is_some_and(|v| v.trim() == image)
    })
    .map(|(name, _)| name.clone())
    .collect();
  if targets.is_empty() {
    return Ok(None);
  }

  // 占位符可能不是合法的 YAML 标量，等长屏蔽后仍可直接用原文偏移。
  let masked =
    mark_compose_refs(content, |raw| "x".repeat(raw.len()));
  let ranges = scalar_ranges(&masked, image).ok_or_else(invalid)?;
  let mut marked = content.to_string();
  for (i, range) in ranges.iter().enumerate().rev() {
    marked.replace_range(range.clone(), &format!("{prefix}{i}"));
  }
  let marked =
    parse_compose_template(&marked).map_err(|_| invalid())?;
  let mut selected = BTreeSet::new();
  for name in targets {
    let marker = marked["services"][&name]["image"]
      .as_str()
      .and_then(|s| s.trim().strip_prefix(&prefix))
      .and_then(|s| s.parse::<usize>().ok())
      .filter(|i| *i < ranges.len())
      .ok_or_else(invalid)?;
    selected.insert(marker);
    let value = &mut expected["services"][&name]["image"];
    *value =
      Value::from(value.as_str().unwrap().replacen(image, new, 1));
  }

  let mut out = content.to_string();
  for i in selected.into_iter().rev() {
    out.replace_range(ranges[i].clone(), new);
  }
  let mut actual =
    parse_compose_template(&out).map_err(|_| invalid())?;
  // 镜像可定义在 x-* 锚点中。若别名同时被环境变量等使用，拒绝连带修改。
  for doc in [&mut expected, &mut actual] {
    doc.as_mapping_mut().ok_or_else(invalid)?.retain(|key, _| {
      !key.as_str().is_some_and(|key| key.starts_with("x-"))
    });
  }
  if actual != expected {
    return Err(invalid());
  }
  Ok(Some(out))
}

fn scalar_ranges(
  content: &str,
  image: &str,
) -> Option<Vec<Range<usize>>> {
  let input = content.strip_prefix('\u{feff}').unwrap_or(content);
  let bom = content.len() - input.len();
  let mut parser =
    MaybeUninit::<unsafe_libyaml::yaml_parser_t>::uninit();
  let parser = parser.as_mut_ptr();
  // SAFETY: libyaml initializes the parser and each successful token. Input
  // outlives scanning, and all tokens and the parser are released exactly once.
  unsafe {
    if unsafe_libyaml::yaml_parser_initialize(parser).fail {
      return None;
    }
    unsafe_libyaml::yaml_parser_set_input_string(
      parser,
      input.as_ptr(),
      input.len() as u64,
    );
    let mut ranges = Vec::new();
    let result = loop {
      let mut token = MaybeUninit::uninit();
      if unsafe_libyaml::yaml_parser_scan(parser, token.as_mut_ptr())
        .fail
      {
        break None;
      }
      let mut token = token.assume_init();
      let end = token.type_ == unsafe_libyaml::YAML_STREAM_END_TOKEN;
      if token.type_ == unsafe_libyaml::YAML_SCALAR_TOKEN {
        let scalar = token.data.scalar;
        let value = std::slice::from_raw_parts(
          scalar.value,
          scalar.length as usize,
        );
        if std::str::from_utf8(value).is_ok_and(|v| v.trim() == image)
        {
          let start = token.start_mark.index as usize + bom;
          let end = token.end_mark.index as usize + bom;
          // shortcut: 镜像值须含连续原文，遇到转义或折行拼接的镜像值请手动编辑。
          if let Some(at) =
            content.get(start..end).and_then(|raw| raw.find(image))
          {
            let start = start + at;
            ranges.push(start..start + image.len());
          }
        }
      }
      unsafe_libyaml::yaml_token_delete(&mut token);
      if end {
        break Some(ranges);
      }
    };
    unsafe_libyaml::yaml_parser_delete(parser);
    result
  }
}
