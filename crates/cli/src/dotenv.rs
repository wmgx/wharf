//! .env 文件解析，错误中只附行号。

use std::{
  collections::BTreeMap,
  io::{self, IsTerminal, Read},
  path::Path,
};

use wharf_api_types::ApiError;

pub(crate) fn read(
  file: Option<&Path>,
) -> Result<BTreeMap<String, String>, ApiError> {
  let text = match file {
    Some(p) if p != Path::new("-") => std::fs::read_to_string(p)
      .map_err(|_| {
        ApiError::invalid(format!("无法读取 {}", p.display()))
      })?,
    _ => {
      let stdin = io::stdin();
      if stdin.is_terminal() {
        return Err(ApiError::invalid(
          "请指定 .env 文件，或将内容重定向到标准输入",
        ));
      }
      let mut text = String::new();
      stdin
        .lock()
        .read_to_string(&mut text)
        .map_err(|_| ApiError::invalid("无法读取标准输入"))?;
      text
    }
  };
  parse(&text)
}

pub(crate) fn check_name(name: &str) -> bool {
  !name.is_empty()
    && name.len() <= 64
    && name
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(crate) fn parse(
  text: &str,
) -> Result<BTreeMap<String, String>, ApiError> {
  let mut entries = BTreeMap::new();
  for (i, line) in text.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let invalid =
      || ApiError::invalid(format!(".env 第 {} 行格式不对", i + 1));
    let (key, value) = line.split_once('=').ok_or_else(invalid)?;
    let key = key.trim();
    if !check_name(key) {
      return Err(invalid());
    }
    let value = parse_value(value, invalid)?;
    if entries.insert(key.to_owned(), value).is_some() {
      return Err(ApiError::invalid(format!(
        ".env 第 {} 行重复定义 {key}",
        i + 1
      )));
    }
  }
  Ok(entries)
}

fn parse_value(
  raw: &str,
  invalid: impl Fn() -> ApiError,
) -> Result<String, ApiError> {
  let value = raw.trim_start();
  let Some(quote @ ('\'' | '"')) = value.chars().next() else {
    let end = if value.starts_with('#') && raw.len() != value.len() {
      0
    } else {
      value
        .char_indices()
        .zip(value.chars().skip(1))
        .find_map(|((i, ch), next)| {
          (ch.is_whitespace() && next == '#').then_some(i)
        })
        .unwrap_or(value.len())
    };
    return Ok(value[..end].trim_end().into());
  };
  let mut out = String::new();
  let mut chars = value[1..].chars();
  while let Some(ch) = chars.next() {
    if ch == quote {
      let rest = chars.as_str().trim_start();
      if rest.is_empty() || rest.starts_with('#') {
        return Ok(out);
      }
      return Err(invalid());
    }
    if ch == '\\' && quote == '"' {
      out.push(match chars.next() {
        Some('n') => '\n',
        Some('r') => '\r',
        Some('t') => '\t',
        Some(c @ ('"' | '\\')) => c,
        _ => return Err(invalid()),
      });
    } else {
      out.push(ch);
    }
  }
  Err(invalid())
}

#[test]
fn parses_dotenv_and_omits_original_value_on_error() {
  let values = parse(
    "export A='value # literal'\nB=plain # tail\nC=\"a\\nb\"\n",
  )
  .unwrap();
  assert_eq!(values["A"], "value # literal");
  assert_eq!(values["B"], "plain");
  assert_eq!(values["C"], "a\nb");
  let error = parse("A=\"fixture-hidden").unwrap_err();
  assert!(error.message.contains("第 1 行"));
  assert!(!error.message.contains("fixture-hidden"));
}
