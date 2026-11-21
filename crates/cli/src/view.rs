//! JSON 输出的全局变换：`--page-size`/`--page` 分页，`--changed` 只看变化。
//! 都在 `--fields` 挑完字段之后做。

use std::path::PathBuf;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Settings {
  page: Option<(usize, usize)>,
  /// 上次结果的缓存文件。
  changed: Option<PathBuf>,
}

static SETTINGS: std::sync::OnceLock<Settings> =
  std::sync::OnceLock::new();

/// `args` 是去掉 `--changed` 后的命令行，用来区分“同一条命令”。
pub fn set(
  page: Option<(usize, usize)>,
  changed_key: Option<&[String]>,
) {
  let changed = changed_key.map(|args| {
    let digest =
      hex::encode(Sha256::digest(args.join("\0").as_bytes()));
    cache_dir()
      .join("changed")
      .join(format!("{}.json", &digest[..16]))
  });
  let _ = SETTINGS.set(Settings { page, changed });
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

pub fn apply(value: Value) -> Value {
  let Some(s) = SETTINGS.get() else {
    return value;
  };
  let value = match s.page {
    Some((size, page)) => paginate(value, size, page),
    None => value,
  };
  match &s.changed {
    Some(path) => changed(value, path),
    None => value,
  }
}

fn paginate(value: Value, size: usize, page: usize) -> Value {
  let Value::Array(items) = value else {
    eprintln!("提示：输出不是列表，没有分页");
    return value;
  };
  let size = size.max(1);
  let total = items.len();
  let pages = total.div_ceil(size).max(1);
  eprintln!("共 {total} 项，第 {page}/{pages} 页");
  Value::Array(
    items
      .into_iter()
      .skip(page.saturating_sub(1) * size)
      .take(size)
      .collect(),
  )
}

fn changed(value: Value, path: &PathBuf) -> Value {
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
      "changes": [{"path": "", "before": null, "after": value}],
    }),
    Some(before) => {
      let mut out = Vec::new();
      diff("", &before, &value, &mut out);
      json!({ "first_run": false, "changes": out })
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
  fn paginates_top_level_list() {
    let v = super::paginate(json!([1, 2, 3, 4, 5]), 2, 3);
    assert_eq!(v, json!([5]));
  }
}
