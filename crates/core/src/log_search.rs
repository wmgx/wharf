//! 日志搜索：按关键字过滤、只看报错并按内容去重计数、限制每行长度，避免几万行日志把 AI 淹没。
//! 时间范围由 agent 的 `docker compose logs --since` 处理，这里只处理拿回来的文本。

use serde::Serialize;

/// 认作报错的词（小写比较）。
const ERROR_WORDS: &[&str] = &[
  "error",
  "exception",
  "fatal",
  "panic",
  "traceback",
  "failed",
  "critical",
  "level=err",
  "[err",
  " err ",
];

pub struct Options<'a> {
  /// 关键字，不分大小写。
  pub grep: Option<&'a str>,
  /// 只看报错，按内容去重计数。
  pub errors: bool,
  /// 每行最多多少字符，超出截断。
  pub max_line: usize,
  /// 最多返回多少行（或多少组）。
  pub limit: usize,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Group {
  pub count: usize,
  /// 第一次和最后一次出现的时间（日志里带的时间戳）。
  #[serde(skip_serializing_if = "Option::is_none")]
  pub first: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub last: Option<String>,
  /// 最后一次出现的原文。
  pub line: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Found {
  /// 拿回来的总行数。
  pub scanned: usize,
  /// 命中的行数。
  pub matched: usize,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub logs: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub groups: Option<Vec<Group>>,
}

/// `web-1  | 2026-11-22T02:00:00.123Z 消息` → (`web-1`, 时间, 消息)。没有前缀时整行都是消息。
fn split(line: &str) -> (&str, Option<&str>, &str) {
  let (container, rest) = match line.split_once(" | ") {
    Some((c, r)) => (c.trim(), r),
    None => ("", line),
  };
  match rest.split_once(' ') {
    Some((ts, msg))
      if ts.len() >= 20
        && ts.as_bytes()[4] == b'-'
        && ts.contains('T') =>
    {
      (container, Some(ts), msg)
    }
    _ => (container, None, rest),
  }
}

fn is_error(line: &str) -> bool {
  let l = line.to_lowercase();
  ERROR_WORDS.iter().any(|w| l.contains(w))
}

/// 去重用：带数字的词（id、耗时）都换成 `#`，同一种报错只是 id、耗时不同时算一组。
fn shape(container: &str, msg: &str) -> String {
  let mut out = format!("{container} ");
  let mut run = String::new();
  let flush = |run: &mut String, out: &mut String| {
    // 带数字的词（id、耗时、端口）都当成会变的部分。
    let id = run.chars().any(|c| c.is_ascii_digit());
    out.push_str(if id { "#" } else { run.as_str() });
    run.clear();
  };
  for c in msg.chars() {
    if c.is_ascii_alphanumeric() {
      run.push(c);
    } else {
      flush(&mut run, &mut out);
      out.push(c);
    }
  }
  flush(&mut run, &mut out);
  out
}

fn cut(line: &str, max: usize) -> String {
  if line.chars().count() <= max {
    return line.to_string();
  }
  let mut s: String = line.chars().take(max).collect();
  s.push('…');
  s
}

pub fn search(raw: &str, o: &Options) -> Found {
  let grep = o.grep.map(str::to_lowercase);
  let mut scanned = 0;
  let hits: Vec<&str> = raw
    .lines()
    .inspect(|_| scanned += 1)
    .filter(|l| !l.trim().is_empty())
    .filter(|l| {
      grep.as_ref().is_none_or(|g| l.to_lowercase().contains(g))
    })
    .filter(|l| !o.errors || is_error(l))
    .collect();
  let matched = hits.len();
  if !o.errors {
    let start = hits.len().saturating_sub(o.limit);
    let logs = hits[start..]
      .iter()
      .map(|l| cut(l, o.max_line))
      .collect::<Vec<_>>()
      .join("\n");
    return Found {
      scanned,
      matched,
      logs: Some(if logs.is_empty() { logs } else { logs + "\n" }),
      groups: None,
    };
  }
  let mut groups: Vec<(String, Group)> = Vec::new();
  for l in hits {
    let (container, ts, msg) = split(l);
    let key = shape(container, msg);
    match groups.iter_mut().find(|(k, _)| *k == key) {
      Some((_, g)) => {
        g.count += 1;
        g.last = ts.map(str::to_string);
        g.line = cut(l, o.max_line);
      }
      None => groups.push((
        key,
        Group {
          count: 1,
          first: ts.map(str::to_string),
          last: ts.map(str::to_string),
          line: cut(l, o.max_line),
        },
      )),
    }
  }
  let mut groups: Vec<Group> =
    groups.into_iter().map(|(_, g)| g).collect();
  groups.sort_by_key(|g| std::cmp::Reverse(g.count));
  groups.truncate(o.limit);
  Found {
    scanned,
    matched,
    logs: None,
    groups: Some(groups),
  }
}

/// `30m`、`2h`、`3d` 或 RFC 3339 时间，换成 docker 认的写法（天换成小时）。
pub fn since_arg(s: &str) -> Option<String> {
  let s = s.trim();
  if let Some(n) =
    s.strip_suffix('d').and_then(|n| n.parse::<u32>().ok())
  {
    return Some(format!("{}h", n * 24));
  }
  let relative = s.len() > 1
    && s[..s.len() - 1].bytes().all(|b| b.is_ascii_digit())
    && matches!(s.as_bytes()[s.len() - 1], b's' | b'm' | b'h');
  if relative || chrono::DateTime::parse_from_rfc3339(s).is_ok() {
    Some(s.to_string())
  } else {
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn groups_errors_that_differ_only_in_ids() {
    let raw = "\
web-1  | 2026-11-22T02:00:00.1Z started
web-1  | 2026-11-22T02:00:01.1Z ERROR request 4f3a9c failed after 120ms
web-1  | 2026-11-22T02:00:02.1Z ERROR request 9b1e2d failed after 98ms
web-1  | 2026-11-22T02:00:03.1Z panic: boom
";
    let o = Options {
      grep: None,
      errors: true,
      max_line: 500,
      limit: 20,
    };
    let f = search(raw, &o);
    assert_eq!((f.scanned, f.matched), (4, 3));
    let g = f.groups.unwrap();
    assert_eq!(g.len(), 2);
    assert_eq!(g[0].count, 2);
    assert_eq!(g[0].first.as_deref(), Some("2026-11-22T02:00:01.1Z"));
    assert_eq!(g[0].last.as_deref(), Some("2026-11-22T02:00:02.1Z"));
  }

  #[test]
  fn grep_keeps_last_lines_and_cuts_long_ones() {
    let raw = "a timeout x\nb ok\nc TIMEOUT yyyyyyyyyy\n";
    let o = Options {
      grep: Some("timeout"),
      errors: false,
      max_line: 8,
      limit: 1,
    };
    let f = search(raw, &o);
    assert_eq!(f.matched, 2);
    assert_eq!(f.logs.as_deref(), Some("c TIMEOU…\n"));
    assert_eq!(since_arg("2d").as_deref(), Some("48h"));
    assert_eq!(since_arg("30m").as_deref(), Some("30m"));
    assert!(since_arg("yesterday").is_none());
  }
}
