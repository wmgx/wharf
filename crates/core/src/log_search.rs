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
pub(crate) fn split(line: &str) -> (&str, Option<&str>, &str) {
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
  let mut search = RunSearch::new(o, usize::MAX, true);
  for line in raw.lines() {
    search.push(line);
  }
  search.finish(&[]).0
}

pub(crate) struct RunSearch {
  grep: Option<String>,
  errors: bool,
  filter_blank: bool,
  max_line: usize,
  limit: usize,
  budget: usize,
  bytes: usize,
  scanned: usize,
  matched: usize,
  truncated: bool,
  lines: std::collections::VecDeque<(usize, String, usize)>,
  groups: std::collections::HashMap<String, (usize, Group)>,
}

impl RunSearch {
  pub(crate) fn new(
    o: &Options<'_>,
    budget: usize,
    filter_blank: bool,
  ) -> Self {
    Self {
      grep: o.grep.map(str::to_lowercase),
      errors: o.errors,
      filter_blank,
      max_line: o.max_line,
      limit: o.limit,
      budget,
      bytes: 0,
      scanned: 0,
      matched: 0,
      truncated: false,
      lines: Default::default(),
      groups: Default::default(),
    }
  }

  pub(crate) fn scanned(&self) -> usize {
    self.scanned
  }

  pub(crate) fn push(&mut self, line: &str) {
    self.scanned += 1;
    if self.filter_blank && line.trim().is_empty()
      || self
        .grep
        .as_ref()
        .is_some_and(|grep| !line.to_lowercase().contains(grep))
      || self.errors && !is_error(line)
    {
      return;
    }
    self.matched += 1;
    let cut = cut(line, self.max_line);
    if self.errors {
      let (container, ts, msg) = split(line);
      let key = shape(container, msg);
      let (line, clipped) = fits(cut, self.budget / 2);
      self.truncated |= clipped;
      if let Some((_, group)) = self.groups.get_mut(&key) {
        let bytes = self.bytes - group.line.len() + line.len();
        group.count += 1;
        group.last = ts.map(str::to_string);
        if bytes <= self.budget.saturating_mul(4) {
          self.bytes = bytes;
          group.line = line;
        } else {
          self.truncated = true;
        }
      } else {
        let bytes = key.len() + line.len() + 128;
        if self.bytes.saturating_add(bytes)
          > self.budget.saturating_mul(4)
        {
          self.truncated = true;
          return;
        }
        self.bytes += bytes;
        self.groups.insert(
          key,
          (
            self.matched,
            Group {
              count: 1,
              first: ts.map(str::to_string),
              last: ts.map(str::to_string),
              line,
            },
          ),
        );
      }
    } else if self.limit > 0 {
      let (line, clipped) = fits(cut, self.budget.saturating_sub(2));
      let bytes = encoded_len(&line).saturating_add(2);
      if self.lines.len() == self.limit
        && let Some((_, _, old)) = self.lines.pop_front()
      {
        self.bytes -= old;
      }
      while self.bytes.saturating_add(bytes) > self.budget {
        let Some((_, _, removed)) = self.lines.pop_front() else {
          break;
        };
        self.bytes -= removed;
        self.truncated = true;
      }
      self.truncated |= clipped;
      self.bytes += bytes;
      self.lines.push_back((self.scanned, line, bytes));
    }
  }

  pub(crate) fn finish(
    self,
    headers: &[(usize, String)],
  ) -> (Found, bool) {
    let mut truncated = self.truncated;
    let (logs, groups) = if self.errors {
      let mut groups: Vec<_> = self.groups.into_values().collect();
      groups.sort_unstable_by_key(|(first, group)| {
        (std::cmp::Reverse(group.count), *first)
      });
      let mut bytes = 0;
      let groups = groups
        .into_iter()
        .take(self.limit)
        .map(|(_, group)| group)
        .take_while(|group| {
          if self.budget == usize::MAX {
            return true;
          }
          bytes += serde_json::to_vec(group)
            .map_or(self.budget, |v| v.len())
            + 1;
          truncated |= bytes > self.budget;
          bytes <= self.budget
        })
        .collect();
      (None, Some(groups))
    } else {
      let heading = |index| {
        headers
          .partition_point(|(start, _)| *start < index)
          .checked_sub(1)
      };
      let mut keep = self.lines.len();
      if !headers.is_empty() {
        let mut bytes = 0;
        let mut header = None;
        keep = 0;
        // 从尾部给日志行和所属步骤标题一起留空间。
        for (index, _, len) in self.lines.iter().rev() {
          let next = heading(*index);
          let cost = if next != header {
            next.map_or(0, |i| encoded_len(&headers[i].1) + 2)
          } else {
            0
          };
          if bytes + cost + len > self.budget {
            // 单条日志占满预算时仍保留最新一行。
            keep = keep.max(1);
            truncated = true;
            break;
          }
          bytes += cost + len;
          header = next;
          keep += 1;
        }
      }
      let mut text = String::new();
      let mut header = None;
      let mut bytes = 0;
      let skip = self.lines.len() - keep;
      for (index, line, len) in self.lines.into_iter().skip(skip) {
        let next = heading(index);
        if next != header {
          if let Some(i) = next {
            let title = &headers[i].1;
            let cost = encoded_len(title) + 2;
            if bytes + cost + len <= self.budget {
              text.push_str(title);
              text.push('\n');
              bytes += cost;
            } else {
              truncated = true;
            }
          }
          header = next;
        }
        text.push_str(&line);
        text.push('\n');
        bytes += len;
      }
      (Some(text), None)
    };
    (
      Found {
        scanned: self.scanned,
        matched: self.matched,
        logs,
        groups,
      },
      truncated,
    )
  }
}

fn encoded_len(text: &str) -> usize {
  text.chars().map(json_char_len).sum()
}

fn json_char_len(c: char) -> usize {
  match c {
    '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
    '\0'..='\x1f' => 6,
    _ => c.len_utf8(),
  }
}

fn fits(mut text: String, budget: usize) -> (String, bool) {
  let mut bytes = 0;
  for (index, c) in text.char_indices() {
    bytes += json_char_len(c);
    if bytes > budget {
      text.truncate(index);
      return (text, true);
    }
  }
  (text, false)
}

/// `30m`、`2h`、`3d` 或 RFC 3339 时间，换成 docker 认的写法（天换成小时）。
pub fn since_arg(s: &str) -> Option<String> {
  let s = s.trim();
  if let Some(n) =
    s.strip_suffix('d').and_then(|n| n.parse::<u32>().ok())
  {
    return Some(format!("{}h", n.checked_mul(24)?));
  }
  let relative = s.len() > 1
    && matches!(s.as_bytes()[s.len() - 1], b's' | b'm' | b'h')
    && s[..s.len() - 1].bytes().all(|b| b.is_ascii_digit());
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
  fn multistep_budget_preserves_final_error_line() {
    let options = Options {
      grep: None,
      errors: false,
      max_line: usize::MAX,
      limit: usize::MAX,
    };
    let mut search = RunSearch::new(&options, 32, false);
    for line in [
      "x".repeat(32),
      "a".repeat(8),
      "b".repeat(12),
      "ERROR!".into(),
    ] {
      search.push(&line);
    }
    let headers = [(0, "step 1".into()), (2, "step 2".into())];
    let (found, truncated) = search.finish(&headers);
    assert!(truncated);
    assert_eq!(
      found.logs.as_deref(),
      Some("step 2\nbbbbbbbbbbbb\nERROR!\n")
    );
  }

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
