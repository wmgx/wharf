//! 日志搜索：按关键字过滤、只看报错并按内容去重计数、限制每行长度，避免几万行日志把 AI 淹没。
//! 时间范围由 agent 的 `docker compose logs --since` 处理，这里只处理拿回来的文本。

use std::collections::VecDeque;

use chrono::{DateTime, Datelike, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use wharf_api_types::ApiError;

mod filters;
pub(crate) use filters::Filters;
use filters::{JsonFilter, Matcher};

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
  pub filters: Option<&'a Filters>,
  pub until: Option<DateTime<Utc>>,
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
  #[serde(skip_serializing_if = "Option::is_none")]
  pub columns: Option<Vec<String>>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rows: Option<Vec<Map<String, Value>>>,
  #[serde(skip_serializing_if = "is_zero")]
  pub non_json_skipped: usize,
}

fn is_zero(value: &usize) -> bool {
  *value == 0
}

/// `web-1  | 2026-11-22T02:00:00.123Z 消息` → (`web-1`, 时间, 消息)。没有前缀时整行都是消息。
pub(crate) fn split(line: &str) -> (&str, Option<&str>, &str) {
  let (container, rest) = match line.split_once(" | ") {
    Some((c, r)) if !c.contains('{') => (c.trim(), r),
    _ => ("", line),
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

#[cfg(test)]
pub(super) fn search(
  raw: &str,
  o: &Options<'_>,
) -> Result<Found, ApiError> {
  Ok(RunSearch::new(o, usize::MAX, true)?.text(raw))
}

type Line = (usize, Option<usize>, String, usize);

struct Context {
  before: usize,
  after: usize,
  index: usize,
  last_kept: usize,
  preceding: VecDeque<Line>,
  preceding_bytes: usize,
  hits: VecDeque<usize>,
}

impl Context {
  fn add(
    &mut self,
    raw: String,
    index: usize,
    matched: bool,
    search: &mut RunSearch,
  ) {
    self.index += 1;
    let position = self.index;
    let bytes = encoded_len(&raw).saturating_add(4);
    if matched {
      self.hits.push_back(position);
      if self.hits.len() > search.limit {
        self.hits.pop_front();
      }
      let oldest = self.hits[0].saturating_sub(self.before);
      while search
        .lines
        .front()
        .is_some_and(|(_, pos, _, _)| pos.is_some_and(|p| p < oldest))
      {
        if let Some((_, _, _, bytes)) = search.lines.pop_front() {
          search.bytes -= bytes;
        }
      }
      for previous in &self.preceding {
        if previous.1.is_some_and(|i| i > self.last_kept) {
          search.keep(previous.clone(), 5000);
        }
      }
    }
    let line = (index, Some(position), raw, bytes);
    if self
      .hits
      .back()
      .is_some_and(|hit| position - hit <= self.after)
    {
      search.keep(line.clone(), 5000);
      self.last_kept = position;
    }
    if self.before > 0 {
      while self.preceding.len() >= self.before
        || self.preceding_bytes.saturating_add(bytes) > search.budget
      {
        let Some((_, _, _, dropped)) = self.preceding.pop_front()
        else {
          break;
        };
        self.preceding_bytes -= dropped;
      }
      self.preceding_bytes += bytes;
      self.preceding.push_back(line);
    }
  }
}

pub(crate) struct RunSearch {
  grep: Option<Matcher>,
  exclude: Vec<Matcher>,
  until: Option<DateTime<Utc>>,
  last_ts: Option<DateTime<Utc>>,
  json_filter: JsonFilter,
  rows: VecDeque<(Map<String, Value>, usize)>,
  non_json_skipped: usize,
  context: Option<Context>,
  errors: bool,
  filter_blank: bool,
  max_line: usize,
  limit: usize,
  budget: usize,
  bytes: usize,
  scanned: usize,
  matched: usize,
  truncated: bool,
  lines: VecDeque<Line>,
  groups: std::collections::HashMap<String, (usize, Group)>,
}

impl RunSearch {
  pub(crate) fn new(
    o: &Options<'_>,
    budget: usize,
    filter_blank: bool,
  ) -> Result<Self, ApiError> {
    let empty = Filters::default();
    let f = o.filters.unwrap_or(&empty);
    let before = f.before.or(f.context).unwrap_or(0);
    let after = f.after.or(f.context).unwrap_or(0);
    let context = before > 0 || after > 0;
    if before > 50 || after > 50 {
      return Err(ApiError::invalid("上下文行数不能超过 50"));
    }
    if context
      && (o.errors || o.grep.is_none() && f.where_exprs.is_empty())
    {
      return Err(ApiError::invalid(
        "上下文需要 --grep 或 --where，且不能与 --errors 同用",
      ));
    }
    if f.cols.is_some() && (context || o.errors) {
      return Err(ApiError::invalid(
        "--cols 不能与上下文或 --errors 同用",
      ));
    }
    if f.exclude.len() > 20 || f.where_exprs.len() > 20 {
      return Err(ApiError::invalid(
        "--exclude 和 --where 各最多指定 20 条",
      ));
    }
    if f.regex
      && o.grep.is_none()
      && f.exclude.is_empty()
      && f.where_exprs.is_empty()
    {
      return Err(ApiError::invalid(
        "--regex 需要 --grep、--exclude 或 --where",
      ));
    }
    Ok(Self {
      grep: o
        .grep
        .map(|pat| Matcher::compile(pat, f.regex))
        .transpose()?,
      exclude: f
        .exclude
        .iter()
        .map(|pat| Matcher::compile(pat, f.regex))
        .collect::<Result<_, _>>()?,
      until: o.until,
      last_ts: None,
      json_filter: JsonFilter::compile(f)?,
      rows: VecDeque::new(),
      non_json_skipped: 0,
      context: context.then(|| Context {
        before,
        after,
        index: 0,
        last_kept: 0,
        preceding: VecDeque::new(),
        preceding_bytes: 0,
        hits: VecDeque::new(),
      }),
      errors: o.errors,
      filter_blank,
      max_line: o.max_line,
      limit: if context {
        o.limit.clamp(1, 5000)
      } else {
        o.limit
      },
      budget,
      bytes: 0,
      scanned: 0,
      matched: 0,
      truncated: false,
      lines: Default::default(),
      groups: Default::default(),
    })
  }

  pub(crate) fn text(mut self, raw: &str) -> Found {
    for line in raw.lines() {
      self.push(line);
    }
    self.finish(&[]).0
  }

  fn keep(&mut self, entry: Line, limit: usize) {
    let bytes = entry.3;
    if self.lines.len() == limit
      && let Some((_, _, _, old)) = self.lines.pop_front()
    {
      self.bytes -= old;
      self.truncated |= entry.1.is_some();
    }
    while self.bytes.saturating_add(bytes) > self.budget {
      let Some((_, _, _, removed)) = self.lines.pop_front() else {
        break;
      };
      self.bytes -= removed;
      self.truncated = true;
    }
    self.bytes += bytes;
    self.lines.push_back(entry);
  }

  pub(crate) fn scanned(&self) -> usize {
    self.scanned
  }

  pub(crate) fn push(&mut self, line: &str) {
    self.scanned += 1;
    if let Some(until) = self.until {
      if let Some(ts) = split(line).1.and_then(parse_rfc3339_utc) {
        self.last_ts = Some(ts);
      }
      if self.last_ts.is_some_and(|ts| ts > until) {
        return;
      }
    }
    if self.exclude.iter().any(|matcher| matcher.matches(line)) {
      return;
    }
    let blank = self.filter_blank && line.trim().is_empty();
    if blank && self.context.is_none() {
      return;
    }
    let mut matched = !blank
      && self.grep.as_ref().is_none_or(|grep| grep.matches(line))
      && (!self.errors || is_error(line));
    if self.json_filter.enabled() {
      let (container, ts, msg) = split(line);
      let json = msg.trim();
      let json = if json.starts_with('{') && json.ends_with('}') {
        serde_json::from_str::<Value>(json).ok()
      } else {
        None
      };
      if let Some(obj) = json {
        matched &= self.json_filter.matches(&obj, container, ts);
        if matched
          && let Some(row) = self.json_filter.project(
            &obj,
            container,
            ts,
            self.max_line,
          )
        {
          self.matched += 1;
          if self.limit > 0 {
            let bytes = serde_json::to_vec(&row)
              .map_or(usize::MAX, |v| v.len().saturating_add(1));
            if bytes > self.budget {
              self.truncated = true;
              return;
            }
            if self.rows.len() == self.limit
              && let Some((_, removed)) = self.rows.pop_front()
            {
              self.bytes -= removed;
            }
            while self.bytes.saturating_add(bytes) > self.budget {
              if let Some((_, removed)) = self.rows.pop_front() {
                self.bytes -= removed;
                self.truncated = true;
              }
            }
            self.bytes += bytes;
            self.rows.push_back((row, bytes));
          }
          return;
        }
      } else {
        self.non_json_skipped += usize::from(!blank);
        matched = false;
      }
    }
    if let Some(mut context) = self.context.take() {
      self.matched += usize::from(matched);
      let (line, clipped) =
        fits(cut(line, self.max_line), self.budget.saturating_sub(4));
      self.truncated |= clipped;
      context.add(line, self.scanned, matched, self);
      self.context = Some(context);
      return;
    }
    if !matched {
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
      self.truncated |= clipped;
      self.keep((self.scanned, None, line, bytes), self.limit);
    }
  }

  pub(crate) fn finish(
    self,
    headers: &[(usize, String)],
  ) -> (Found, bool) {
    let mut truncated = self.truncated;
    let columns = self.json_filter.columns;
    let rows = columns
      .as_ref()
      .map(|_| self.rows.into_iter().map(|(row, _)| row).collect());
    let (logs, groups) = if columns.is_some() {
      (None, None)
    } else if self.errors {
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
        for (index, _, _, len) in self.lines.iter().rev() {
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
      let mut previous = None;
      for (index, pos, line, len) in self.lines.into_iter().skip(skip)
      {
        if previous
          .zip(pos)
          .is_some_and(|(before, after)| before + 1 < after)
        {
          text.push_str("--\n");
        }
        previous = pos;
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
        matched: self
          .context
          .as_ref()
          .map_or(self.matched, |c| c.hits.len()),
        logs,
        groups,
        columns,
        rows,
        non_json_skipped: self.non_json_skipped,
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

pub fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
  DateTime::parse_from_rfc3339(value)
    .ok()
    .map(|time| time.with_timezone(&Utc))
}

pub fn anchor_time(
  value: &str,
  now: DateTime<Utc>,
) -> Option<String> {
  let value = since_arg(value)?;
  if let Some(time) = parse_rfc3339_utc(&value) {
    return Some(time.to_rfc3339());
  }
  let (unit, digits) = value.as_bytes().split_last()?;
  let multiplier = match unit {
    b's' => 1,
    b'm' => 60,
    b'h' => 3600,
    _ => return None,
  };
  let n: i64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
  let delta = TimeDelta::try_seconds(n.checked_mul(multiplier)?)?;
  let time = now.checked_sub_signed(delta)?;
  (0..=9999).contains(&time.year()).then(|| time.to_rfc3339())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn context_keeps_recent_matches_and_excludes_noise() {
    let f = Filters::query(Some(
      "context=1&after=2&exclude=healthcheck&regex=true",
    ))
    .unwrap();
    let mut o = Options {
      grep: Some("pan[i]c"),
      errors: false,
      max_line: 500,
      limit: 1,
      filters: Some(&f),
      until: None,
    };
    let raw = "1\n2\n3\nPANIC\nhealthcheck\n5\n6\n7\n8\npanic\n10";
    let found = search(raw, &o).unwrap();
    assert_eq!(
      (found.matched, found.logs.as_deref()),
      (1, Some("8\npanic\n10\n"))
    );
    o.limit = 2;
    assert_eq!(
      search(raw, &o).unwrap().logs.as_deref(),
      Some("3\nPANIC\n5\n6\n--\n8\npanic\n10\n")
    );
    o.grep = Some("[");
    assert!(search(raw, &o).is_err());
    o.grep = None;
    assert!(search(raw, &o).is_err());
  }

  #[test]
  fn blank_excludes_keep_logs_in_text_and_regex_modes() {
    for query in [
      "exclude=&exclude=+&exclude=skip",
      "exclude=&exclude=+&exclude=skip&regex=true",
    ] {
      let filters = Filters::query(Some(query)).unwrap();
      let options = Options {
        grep: None,
        errors: false,
        max_line: 500,
        limit: 20,
        filters: Some(&filters),
        until: None,
      };
      let found = search("keep this\nskip this\n", &options).unwrap();
      assert_eq!(found.logs.as_deref(), Some("keep this\n"));
    }
  }

  #[test]
  fn json_fields_and_cutoff_filter_before_projection() {
    let f = Filters::query(Some("where=status%3E%3D500&where=req.method%3DPOST&cols=time,req.path,status,ms")).unwrap();
    let mut o = Options {
      grep: None,
      errors: false,
      max_line: 500,
      limit: 10,
      filters: Some(&f),
      until: parse_rfc3339_utc("2026-01-01T10:15:00Z"),
    };
    let raw = r#"2026-01-01T10:00:00Z text
web | 2026-01-01T10:01:00Z {"status":502,"req":{"path":"/api","method":"POST"},"ms":1200}
web | 2026-01-01T10:02:00Z {"status":200,"req":{"method":"POST"}}
web | 2026-01-01T10:30:00Z {"status":503,"req":{"method":"POST"}}
续行"#;
    let found = search(raw, &o).unwrap();
    assert_eq!(
      (found.matched, found.non_json_skipped, found.logs),
      (1, 1, None)
    );
    assert_eq!(
      found.columns.unwrap(),
      ["time", "req.path", "status", "ms"]
    );
    let rows = found.rows.unwrap();
    assert_eq!(rows[0]["status"], 502);
    assert_eq!(rows[0]["time"], "2026-01-01T10:01:00Z");
    let invalid = Filters::query(Some("where=badexpr")).unwrap();
    o.filters = Some(&invalid);
    assert!(search(raw, &o).is_err());
  }

  #[test]
  fn multistep_budget_preserves_final_error_line() {
    let options = Options {
      grep: None,
      errors: false,
      max_line: usize::MAX,
      limit: usize::MAX,
      filters: None,
      until: None,
    };
    let mut search = RunSearch::new(&options, 32, false).unwrap();
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
      filters: None,
      until: None,
    };
    let f = search(raw, &o).unwrap();
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
      filters: None,
      until: None,
    };
    let f = search(raw, &o).unwrap();
    assert_eq!(f.matched, 2);
    assert_eq!(f.logs.as_deref(), Some("c TIMEOU…\n"));
    assert_eq!(since_arg("2d").as_deref(), Some("48h"));
    assert_eq!(since_arg("30m").as_deref(), Some("30m"));
    assert!(since_arg("yesterday").is_none());
  }
}
