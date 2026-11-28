use serde_json::Value;
use wharf_api_types::view::ConfigItemView;

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

#[derive(clap::Subcommand)]
pub enum ConfigCmd {
  /// 列出控制面配置。
  List,
  /// 查看一项配置。
  Get { key: String },
  /// 设置一项配置。
  Set { key: String, value: String },
  /// 恢复一项配置的默认值。
  Unset { key: String },
}

pub async fn run(
  c: &Client,
  cmd: Option<ConfigCmd>,
  j: bool,
) -> CliResult<()> {
  let item = match cmd.unwrap_or(ConfigCmd::List) {
    ConfigCmd::List => {
      let items: Vec<ConfigItemView> = c.get("/api/config").await?;
      out(j, &items, |items| items.iter().for_each(show));
      return Ok(());
    }
    ConfigCmd::Get { key } => {
      c.get(&format!("/api/config/{}", seg(&key))).await?
    }
    ConfigCmd::Set { key, value } => {
      let value = if key == "defaults.global" {
        serde_json::from_str(&value).map_err(|error| {
          wharf_api_types::ApiError::invalid(
            "默认值更新需为 JSON 对象",
          )
          .with_hint(error.to_string())
        })?
      } else {
        Value::String(value)
      };
      c.put(&format!("/api/config/{}", seg(&key)), &value).await?
    }
    ConfigCmd::Unset { key } => {
      c.delete(&format!("/api/config/{}", seg(&key))).await?
    }
  };
  out(j, &item, show);
  Ok(())
}

fn show(item: &ConfigItemView) {
  println!(
    "{} = {}（{}）",
    item.key,
    item.value,
    if item.customized {
      "已设置"
    } else {
      "默认"
    }
  );
}
