//! JSON 输出的全局变换：`--page-size`/`--page` 分页，`--changed` 只看变化。
//! 都在 `--fields` 挑完字段之后做。

use std::path::PathBuf;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wharf_api_types::ApiError;

struct Settings {
  page: Option<(usize, usize)>,
  /// 上次结果的缓存文件。
  changed: Option<(String, PathBuf)>,
  include_volatile: bool,
}

static SETTINGS: std::sync::OnceLock<Settings> =
  std::sync::OnceLock::new();

/// `args` 是去掉 `--changed` 后的命令行，用来区分“同一条命令”。
pub fn set(
  page: Option<(usize, usize)>,
  changed_key: Option<(&str, &[String])>,
  include_volatile: bool,
) {
  let changed = changed_key.map(|(cursor, args)| {
    let digest =
      hex::encode(Sha256::digest(args.join("\0").as_bytes()));
    let path = cache_dir()
      .join("changed")
      .join(cursor)
      .join(format!("{}.json", &digest[..16]));
    (cursor.to_string(), path)
  });
  let _ = SETTINGS.set(Settings {
    page,
    changed,
    include_volatile,
  });
}

/// `~/.cache/wharf`（或 `$XDG_CACHE_HOME/wharf`）。
pub fn cache_dir() -> PathBuf {
  std::env::var_os("XDG_CACHE_HOME")
    .map(PathBuf::from)
    .or_else(|| {
      std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cache"))
    })
    .unwrap_or_else(|| PathBuf::from("."))
    .join("wharf")
}

pub fn apply(value: Value) -> Result<Value, ApiError> {
  let Some(s) = SETTINGS.get() else {
    return Ok(value);
  };
  let value = match s.page {
    Some((size, page)) => paginate(value, size, page)?,
    None => value,
  };
  Ok(match &s.changed {
    Some((cursor, path)) => {
      changed(value, path, cursor, s.include_volatile)
    }
    None => value,
  })
}

fn paginate(
  value: Value,
  size: usize,
  page: usize,
) -> Result<Value, ApiError> {
  if size == 0 || page == 0 {
    return Err(ApiError::invalid("页码和每页项数必须大于 0"));
  }
  let (mut object, key, nested) = match value {
    Value::Array(items) => (
      serde_json::Map::from_iter([(
        "items".into(),
        Value::Array(items),
      )]),
      "items".to_string(),
      false,
    ),
    Value::Object(object) => {
      let keys: Vec<_> = object
        .iter()
        .filter(|(_, value)| value.is_array())
        .map(|(key, _)| key)
        .collect();
      let known: Vec<_> = keys
        .iter()
        .copied()
        .filter(|key| {
          [
            "items",
            "entries",
            "events",
            "runs",
            "snapshots",
            "records",
            "commands",
            "logs",
            "reports",
            "rows",
            "matches",
            "groups",
          ]
          .contains(&key.as_str())
        })
        .collect();
      let key = match (known.as_slice(), keys.as_slice()) {
        ([key], _) | ([], [key]) => (*key).clone(),
        _ => return Err(pagination_error()),
      };
      (object, key, true)
    }
    _ => return Err(pagination_error()),
  };
  let Some(Value::Array(items)) = object.remove(&key) else {
    return Err(pagination_error());
  };
  let total = items.len();
  let pages = total.div_ceil(size).max(1);
  let mut pagination = json!({ "total": total, "page": page, "page_size": size, "pages": pages, "has_more": page < pages });
  if nested {
    pagination["field"] = json!(key);
  }
  object.insert(
    key,
    Value::Array(
      items
        .into_iter()
        .skip((page - 1).saturating_mul(size))
        .take(size)
        .collect(),
    ),
  );
  object.insert("pagination".into(), pagination);
  Ok(Value::Object(object))
}

fn pagination_error() -> ApiError {
  ApiError::invalid("当前输出不是单个列表，无法直接分页")
    .with_hint("用 --fields 选中一个列表，或改用具体的列表命令")
}

fn without_volatile(mut value: Value) -> Value {
  match &mut value {
    Value::Object(map) => {
      for key in [
        "rtt_ms",
        "last_seen",
        "clock_offset_ms",
        "observed_at",
        "checked_at",
        "elapsed_ms",
        "waited_secs",
        "expires_in_secs",
      ] {
        map.remove(key);
      }
      for value in map.values_mut() {
        *value = without_volatile(std::mem::take(value));
      }
    }
    Value::Array(items) => {
      for value in items {
        *value = without_volatile(std::mem::take(value));
      }
    }
    _ => {}
  }
  value
}

fn changed(
  value: Value,
  path: &PathBuf,
  cursor: &str,
  include_volatile: bool,
) -> Value {
  let before = std::fs::read_to_string(path)
    .ok()
    .and_then(|t| serde_json::from_str::<Value>(&t).ok());
  if let Some(dir) = path.parent() {
    let _ = std::fs::create_dir_all(dir);
  }
  let _ = std::fs::write(path, value.to_string());
  match before {
    None => json!({
      "first_run": true,
      "cursor": cursor,
      "changes": [{"path": "", "before": null, "after": value}],
    }),
    Some(before) => {
      let mut out = Vec::new();
      if include_volatile {
        diff("", &before, &value, &mut out);
      } else {
        diff(
          "",
          &without_volatile(before),
          &without_volatile(value),
          &mut out,
        );
      }
      json!({ "first_run": false, "cursor": cursor, "changes": out })
    }
  }
}

/// 列表里的对象按这些字段对齐，找不到就按位置。
const KEYS: [&str; 5] =
  ["name", "hostname", "id", "plan_id", "run_id"];

fn item_key(v: &Value) -> Option<(&'static str, String)> {
  KEYS.iter().find_map(|k| {
    v.get(*k).and_then(|x| match x {
      Value::String(s) => Some((*k, s.clone())),
      Value::Number(n) => Some((*k, n.to_string())),
      _ => None,
    })
  })
}

fn join(path: &str, seg: &str) -> String {
  if path.is_empty() {
    seg.to_string()
  } else {
    format!("{path}.{seg}")
  }
}

pub fn diff(path: &str, a: &Value, b: &Value, out: &mut Vec<Value>) {
  if a == b {
    return;
  }
  let change =
    |out: &mut Vec<Value>, p: String, x: &Value, y: &Value| {
      out.push(json!({"path": p, "before": x, "after": y}));
    };
  match (a, b) {
    (Value::Object(x), Value::Object(y)) => {
      for (k, va) in x {
        diff(
          &join(path, k),
          va,
          y.get(k).unwrap_or(&Value::Null),
          out,
        );
      }
      for (k, vb) in y.iter().filter(|(k, _)| !x.contains_key(*k)) {
        diff(&join(path, k), &Value::Null, vb, out);
      }
    }
    (Value::Array(x), Value::Array(y)) => {
      let keyed = x.iter().chain(y).all(|v| item_key(v).is_some());
      if !keyed {
        for i in 0..x.len().max(y.len()) {
          diff(
            &format!("{path}[{i}]"),
            x.get(i).unwrap_or(&Value::Null),
            y.get(i).unwrap_or(&Value::Null),
            out,
          );
        }
        return;
      }
      let label = |v: &Value| {
        let (k, id) = item_key(v).unwrap_or(("", String::new()));
        format!("{path}[{k}={id}]")
      };
      let find = |list: &Vec<Value>, v: &Value| {
        list.iter().find(|w| item_key(w) == item_key(v)).cloned()
      };
      for va in x {
        let vb = find(y, va).unwrap_or(Value::Null);
        diff(&label(va), va, &vb, out);
      }
      for vb in y.iter().filter(|v| find(x, v).is_none()) {
        change(out, label(vb), &Value::Null, vb);
      }
    }
    _ => change(out, path.to_string(), a, b),
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  #[test]
  fn paginates_log_rows_without_slicing_columns() {
    let v = super::paginate(
      json!({"columns":["status"],"rows":[{"status":500},{"status":502}]}),
      1,
      2,
    ).unwrap();
    assert_eq!(v["rows"], json!([{"status":502}]));
    assert_eq!(v["columns"], json!(["status"]));
    assert_eq!(v["pagination"]["total"], 2);
  }

  #[test]
  fn diffs_lists_by_name() {
    let a = json!([{"name": "a", "s": 1}, {"name": "b", "s": 1}]);
    let b = json!([{"name": "b", "s": 2}, {"name": "c", "s": 1}]);
    let mut out = Vec::new();
    super::diff("", &a, &b, &mut out);
    let paths: Vec<&str> =
      out.iter().map(|c| c["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["[name=a]", "[name=b].s", "[name=c]"]);
    assert_eq!(out[0]["after"], json!(null));
    assert_eq!(out[1]["before"], json!(1));
  }

  #[test]
  fn named_cursor_ignores_volatile_fields_by_default() {
    let cache = tempfile::tempdir().unwrap();
    let first = cache.path().join("first.json");
    let second = cache.path().join("second.json");
    let before = json!({"name": "s1", "rtt_ms": 1});
    let after = json!({"name": "s1", "rtt_ms": 2});
    assert_eq!(
      super::changed(before, &first, "first", false)["first_run"],
      true
    );
    let diff = super::changed(after.clone(), &first, "first", false);
    assert_eq!(diff["changes"], json!([]));
    assert_eq!(diff["cursor"], "first");
    assert_eq!(
      super::changed(after, &second, "second", false)["first_run"],
      true
    );
  }

  #[test]
  fn paginates_top_level_list() {
    let v = super::paginate(
      json!({"entries": [1, 2, 3, 4, 5], "matched": 5}),
      2,
      2,
    )
    .unwrap();
    assert_eq!(v["entries"], json!([3, 4]));
    assert_eq!(v["pagination"]["total"], 5);
  }
}
