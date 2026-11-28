use std::{borrow::Cow, cmp::Ordering};

use serde_json::{Map, Value};
use wharf_api_types::ApiError;

#[derive(Default)]
pub(crate) struct Filters {
  pub until: Option<String>,
  pub exclude: Vec<String>,
  pub regex: bool,
  pub before: Option<usize>,
  pub after: Option<usize>,
  pub context: Option<usize>,
  pub where_exprs: Vec<String>,
  pub cols: Option<String>,
}

impl Filters {
  pub fn query(raw: Option<&str>) -> Result<Self, ApiError> {
    let mut out = Self::default();
    let mut regex = None;
    for param in raw.unwrap_or_default().split('&') {
      let (key, value) = param.split_once('=').unwrap_or((param, ""));
      let key = urlencoding::decode(key)
        .map_err(|_| ApiError::invalid("日志查询参数编码不合法"))?;
      if !matches!(
        key.as_ref(),
        "until"
          | "exclude"
          | "regex"
          | "before"
          | "after"
          | "context"
          | "where"
          | "cols"
      ) {
        continue;
      }
      let value = value.replace('+', " ");
      let value = urlencoding::decode(&value)
        .map_err(|_| ApiError::invalid("日志查询参数编码不合法"))?;
      let duplicate =
        || ApiError::invalid(format!("日志参数 {key} 不能重复"));
      let num = || {
        value.parse().map_err(|_| {
          ApiError::invalid(format!("日志参数 {key} 须为非负整数"))
        })
      };
      match key.as_ref() {
        "exclude" if !value.trim().is_empty() => {
          out.exclude.push(value.into_owned());
        }
        "exclude" => {}
        "where" => out.where_exprs.push(value.into_owned()),
        "until" if out.until.is_none() => {
          out.until = Some(value.into_owned())
        }
        "cols" if out.cols.is_none() => {
          out.cols = Some(value.into_owned())
        }
        "regex" if regex.is_none() => {
          regex = Some(value.parse().map_err(|_| {
            ApiError::invalid("regex 须为 true 或 false")
          })?)
        }
        "before" if out.before.is_none() => out.before = Some(num()?),
        "after" if out.after.is_none() => out.after = Some(num()?),
        "context" if out.context.is_none() => {
          out.context = Some(num()?)
        }
        _ => return Err(duplicate()),
      }
    }
    out.regex = regex.unwrap_or_default();
    Ok(out)
  }

  pub fn active(&self) -> bool {
    self.until.is_some()
      || !self.exclude.is_empty()
      || self.regex
      || self.before.is_some()
      || self.after.is_some()
      || self.context.is_some()
      || !self.where_exprs.is_empty()
      || self.cols.is_some()
  }
}

pub(super) enum Matcher {
  Text(String),
  Regex(regex::Regex),
}

impl Matcher {
  pub fn compile(
    pattern: &str,
    regex: bool,
  ) -> Result<Self, ApiError> {
    if !regex {
      return Ok(Self::Text(pattern.to_lowercase()));
    }
    if pattern.chars().count() > 512 {
      return Err(ApiError::invalid(
        "日志正则表达式不能超过 512 字符",
      ));
    }
    regex::RegexBuilder::new(pattern)
      .case_insensitive(true)
      .size_limit(1 << 20)
      .dfa_size_limit(1 << 20)
      .build()
      .map(Self::Regex)
      .map_err(|_| {
        ApiError::invalid("日志正则表达式不合法")
          .with_hint("去掉 --regex 可按普通文本搜索")
      })
  }

  pub fn matches(&self, line: &str) -> bool {
    match self {
      Self::Text(pattern) => line.to_lowercase().contains(pattern),
      Self::Regex(pattern) => pattern.is_match(line),
    }
  }
}

#[derive(Clone, Copy)]
enum Op {
  Eq,
  Ne,
  Gt,
  Ge,
  Lt,
  Le,
  Contains,
  NotContains,
  Prefix,
}

struct Clause {
  field: String,
  op: Op,
  value: String,
  matcher: Option<Matcher>,
}

fn valid_field(field: &str) -> bool {
  !field.is_empty()
    && field.len() <= 128
    && !field.starts_with('.')
    && !field.ends_with('.')
    && !field.contains("..")
    && field.bytes().all(is_field_byte)
}

fn is_field_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b"_.-".contains(&b)
}

impl Clause {
  fn parse(expr: &str, regex: bool) -> Result<Self, ApiError> {
    let invalid = || {
      ApiError::invalid("--where 表达式不合法")
      .with_hint("例如 --where status>=500、--where path^=/api/（支持 =、!=、>、>=、<、<=、~、!~、^=）")
    };
    let expr = expr.trim();
    let at = expr.bytes().take_while(|b| is_field_byte(*b)).count();
    let (field, rest) = expr.split_at(at);
    if !valid_field(field) {
      return Err(invalid());
    }
    let rest = rest.trim_start();
    let (op, value) = [
      ("==", Op::Eq),
      ("!=", Op::Ne),
      (">=", Op::Ge),
      ("<=", Op::Le),
      ("!~", Op::NotContains),
      ("^=", Op::Prefix),
      ("=", Op::Eq),
      (">", Op::Gt),
      ("<", Op::Lt),
      ("~", Op::Contains),
    ]
    .into_iter()
    .find_map(|(spelling, op)| {
      rest.strip_prefix(spelling).map(|v| (op, v.trim()))
    })
    .filter(|(_, value)| !value.is_empty())
    .ok_or_else(invalid)?;
    let matcher = matches!(op, Op::Contains | Op::NotContains)
      .then(|| Matcher::compile(value, regex))
      .transpose()?;
    Ok(Self {
      field: field.into(),
      op,
      value: value.into(),
      matcher,
    })
  }

  fn matches(&self, value: Option<Cow<'_, Value>>) -> bool {
    let Some(value) = value else {
      return matches!(self.op, Op::Eq) && self.value == "null";
    };
    let text = value
      .as_str()
      .map_or_else(|| Cow::Owned(value.to_string()), Cow::Borrowed);
    let order = || {
      let numeric =
        |s: &str| s.parse::<f64>().ok().filter(|n| n.is_finite());
      match (numeric(&text), numeric(&self.value)) {
        (Some(a), Some(b)) => {
          a.partial_cmp(&b).unwrap_or(Ordering::Equal)
        }
        _ => text.as_ref().cmp(self.value.as_str()),
      }
    };
    match self.op {
      Op::Eq => order().is_eq(),
      Op::Ne => !order().is_eq(),
      Op::Gt => order().is_gt(),
      Op::Ge => !order().is_lt(),
      Op::Lt => order().is_lt(),
      Op::Le => !order().is_gt(),
      Op::Prefix => text.starts_with(&self.value),
      Op::Contains | Op::NotContains => {
        self.matcher.as_ref().is_some_and(|m| m.matches(&text))
          == matches!(self.op, Op::Contains)
      }
    }
  }
}

fn resolve<'a>(
  obj: &'a Value,
  container: &str,
  ts: Option<&str>,
  field: &str,
) -> Option<Cow<'a, Value>> {
  if let Some(value) =
    field.split('.').try_fold(obj, |node, key| node.get(key))
  {
    return Some(Cow::Borrowed(value));
  }
  match field {
    "_container" if !container.is_empty() => Some(container),
    "_ts" | "time" | "ts" => ts,
    _ => None,
  }
  .map(|text| Cow::Owned(Value::String(text.into())))
}

pub(super) struct JsonFilter {
  clauses: Vec<Clause>,
  pub columns: Option<Vec<String>>,
}

impl JsonFilter {
  pub fn compile(f: &Filters) -> Result<Self, ApiError> {
    let clauses = f
      .where_exprs
      .iter()
      .map(|v| Clause::parse(v, f.regex))
      .collect::<Result<_, _>>()?;
    let columns = if let Some(raw) = &f.cols {
      let mut columns = Vec::new();
      for part in raw.split(',').map(str::trim) {
        if !valid_field(part)
          || columns.len() >= 20 && !columns.contains(&part)
        {
          return Err(ApiError::invalid(
            "--cols 须为 1 到 20 个字段，例如 time,method,path,status",
          ));
        }
        if !columns.contains(&part) {
          columns.push(part);
        }
      }
      Some(columns.into_iter().map(str::to_owned).collect())
    } else {
      None
    };
    Ok(Self { clauses, columns })
  }

  pub fn enabled(&self) -> bool {
    !self.clauses.is_empty() || self.columns.is_some()
  }

  pub fn matches(
    &self,
    obj: &Value,
    container: &str,
    ts: Option<&str>,
  ) -> bool {
    self.clauses.iter().all(|clause| {
      clause.matches(resolve(obj, container, ts, &clause.field))
    })
  }

  pub fn project(
    &self,
    obj: &Value,
    container: &str,
    ts: Option<&str>,
    max_line: usize,
  ) -> Option<Map<String, Value>> {
    Some(
      self
        .columns
        .as_ref()?
        .iter()
        .map(|key| {
          let value = match resolve(obj, container, ts, key) {
            Some(v) => match v.as_ref() {
              Value::String(s) => {
                Value::String(super::cut(s, max_line))
              }
              _ => v.into_owned(),
            },
            None => Value::Null,
          };
          (key.clone(), value)
        })
        .collect(),
    )
  }
}
