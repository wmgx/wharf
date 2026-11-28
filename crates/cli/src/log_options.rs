use std::fmt::Write;

use clap::Args;
use serde_json::Value;

use crate::client::seg;

#[derive(Args, Clone, Default)]
pub struct SearchArgs {
  /// 排除匹配的行，可重复。
  #[arg(long)]
  exclude: Vec<String>,
  /// 按不区分大小写的正则表达式匹配。
  #[arg(long)]
  regex: bool,
  /// 每次命中后多显示 N 行，最多 50。
  #[arg(
    short = 'A',
    long = "after-context",
    conflicts_with = "errors",
    value_name = "N"
  )]
  after_context: Option<usize>,
  /// 每次命中前多显示 N 行，最多 50。
  #[arg(
    short = 'B',
    long = "before-context",
    conflicts_with = "errors",
    value_name = "N"
  )]
  before_context: Option<usize>,
  /// 每次命中前后各多显示 N 行，可用 -A 或 -B 分别覆盖。
  #[arg(
    short = 'C',
    long,
    conflicts_with = "errors",
    value_name = "N"
  )]
  context: Option<usize>,
}

#[derive(Args, Clone, Default)]
pub struct LogOptions {
  #[command(flatten)]
  pub search: SearchArgs,
  /// 只看这之前的日志，例如 30m、2h、3d 或 RFC 3339 时间。
  #[arg(long)]
  pub(crate) until: Option<String>,
  /// 按 JSON 日志字段筛选，可重复，例 status>=500。
  #[arg(long = "where", value_name = "EXPR")]
  pub(crate) where_exprs: Vec<String>,
  /// 逗号分隔的 JSON 日志选列，例 time,method,path,status。
  #[arg(long, conflicts_with_all = ["errors", "after_context", "before_context", "context"])]
  pub(crate) cols: Option<String>,
}

impl LogOptions {
  pub fn append_query(&self, path: &mut String) {
    for (key, values) in [
      ("exclude", &self.search.exclude),
      ("where", &self.where_exprs),
    ] {
      for value in values {
        write!(path, "&{key}={}", seg(value)).unwrap();
      }
    }
    if self.search.regex {
      path.push_str("&regex=true");
    }
    for (key, count) in [
      ("before", self.search.before_context),
      ("after", self.search.after_context),
      ("context", self.search.context),
    ] {
      if let Some(count) = count {
        write!(path, "&{key}={count}").unwrap();
      }
    }
    for (key, value) in [("until", &self.until), ("cols", &self.cols)]
    {
      if let Some(value) = value {
        write!(path, "&{key}={}", seg(value)).unwrap();
      }
    }
  }
}

pub fn print_rows(value: &Value) -> bool {
  let (Some(columns), Some(rows)) =
    (value["columns"].as_array(), value["rows"].as_array())
  else {
    return false;
  };
  let skipped = value["non_json_skipped"].as_u64().unwrap_or(0);
  let scanned = value["scanned"].as_u64().unwrap_or(0);
  let summary = if skipped > 0 {
    format!("看了 {scanned} 行，跳过 {skipped} 行非 JSON")
  } else {
    format!("看了 {scanned} 行")
  };
  if rows.is_empty() {
    println!("没有匹配的 JSON 日志（{summary}）");
    return true;
  }
  let keys: Vec<_> =
    columns.iter().filter_map(Value::as_str).collect();
  let cells: Vec<Vec<_>> = rows
    .iter()
    .map(|row| {
      keys
        .iter()
        .map(|&key| match &row[key] {
          Value::Null => "-".into(),
          Value::String(s) => s.replace(['\r', '\n', '\t'], " "),
          other => other.to_string(),
        })
        .collect()
    })
    .collect();
  let widths: Vec<_> = keys
    .iter()
    .enumerate()
    .map(|(i, key)| {
      cells
        .iter()
        .map(|row| row[i].chars().count())
        .fold(key.chars().count(), usize::max)
    })
    .collect();
  let print_line = |values: &[&str]| {
    let mut line = String::new();
    for (value, &width) in values.iter().zip(&widths) {
      write!(line, "{value:<width$}  ").unwrap();
    }
    println!("{}", line.trim_end());
  };
  print_line(&keys);
  for row in &cells {
    print_line(&row.iter().map(String::as_str).collect::<Vec<_>>());
  }
  eprintln!("命中 {} 行（{summary}）", value["matched"]);
  true
}

#[cfg(test)]
mod tests {
  use crate::Cli;
  use clap::Parser;

  #[test]
  fn context_flags_parse_and_conflict_with_streaming() {
    assert!(
      Cli::try_parse_from([
        "wharf", "service", "logs", "app", "--grep", "panic", "-C",
        "3", "-A", "1"
      ])
      .is_ok()
    );
    assert!(
      Cli::try_parse_from([
        "wharf", "service", "logs", "app", "-f", "--until", "1h"
      ])
      .is_err()
    );
    assert!(
      Cli::try_parse_from([
        "wharf", "run", "logs", "r_1", "--grep", "panic", "-B", "1"
      ])
      .is_ok()
    );
  }

  #[test]
  fn files_legacy_and_explicit_list_parse() {
    for args in [
      ["wharf", "service", "files", "app", "logs", "-q"],
      ["wharf", "service", "files", "ls", "tail", "-q"],
    ] {
      assert!(Cli::try_parse_from(args).is_ok());
    }
  }
}
