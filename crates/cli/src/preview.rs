//! 不走计划的命令（定时任务、密钥、告警设置、备注）加 `--dry-run`：先显示会改什么，不执行。

use serde_json::{Value, json};

use crate::{client::CliResult, commands::out};

/// 比较前后两份内容，输出 `{dry_run, action, target, changes}`。`before` 是 null 表示新建，
/// `after` 是 null 表示删除。
pub fn show(
  j: bool,
  target: &str,
  before: &Value,
  after: &Value,
) -> CliResult<()> {
  let action = match (before.is_null(), after.is_null()) {
    (true, _) => "create",
    (_, true) => "delete",
    _ if before == after => "none",
    _ => "update",
  };
  let mut changes = Vec::new();
  crate::view::diff("", before, after, &mut changes);
  let v = json!({
    "dry_run": true,
    "action": action,
    "target": target,
    "changes": changes,
  });
  out(j, &v, |v| {
    let what = match action {
      "create" => "新建",
      "delete" => "删除",
      "none" => "没有变化",
      _ => "修改",
    };
    println!("预览（没有执行）：{what} {target}");
    if action == "update" {
      for c in v["changes"].as_array().into_iter().flatten() {
        println!(
          "  {}：{} → {}",
          c["path"].as_str().unwrap_or_default(),
          brief(&c["before"]),
          brief(&c["after"])
        );
      }
    }
  });
  Ok(())
}

fn brief(v: &Value) -> String {
  let text = match v {
    Value::Null => "（无）".to_string(),
    Value::String(s) => s.clone(),
    other => other.to_string(),
  };
  if text.chars().count() > 80 {
    format!("{}…", text.chars().take(80).collect::<String>())
  } else {
    text
  }
}

/// 不存在（404）时当成 null，其他错误照常返回。
pub async fn get_or_null(
  c: &crate::client::Client,
  path: &str,
) -> CliResult<Value> {
  match c.get::<Value>(path).await {
    Ok(v) => Ok(v),
    Err(crate::client::CliError::Api(e))
      if e.code == wharf_api_types::ErrorCode::NotFound =>
    {
      Ok(Value::Null)
    }
    Err(e) => Err(e),
  }
}
