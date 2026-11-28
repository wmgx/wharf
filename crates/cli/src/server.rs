//! 服务器的直接查询和操作。

use std::time::Duration;

use serde_json::{Value, json};

use crate::{
  client::{CliResult, Client, seg},
  commands::{out, pretty},
};

pub async fn apt(
  c: &Client,
  name: &str,
  apply: bool,
  j: bool,
) -> CliResult<()> {
  let path = format!("/api/servers/{}/apt", seg(name));
  if apply {
    let value: String = c.post(&path, &json!({})).await?;
    out(j, &value, |v| println!("已开始安装系统更新 {v}"));
  } else {
    let value: Value = c.get(&path).await?;
    out(j, &value, pretty);
  }
  Ok(())
}

pub async fn dirs(
  c: &Client,
  name: &str,
  path: &str,
  j: bool,
) -> CliResult<()> {
  let values: Vec<String> = c
    .get(&format!(
      "/api/servers/{}/dirs?path={}",
      seg(name),
      seg(path)
    ))
    .await?;
  out(j, &values, |dirs| {
    for dir in dirs {
      println!("{dir}");
    }
  });
  Ok(())
}

pub async fn pack(
  c: &Client,
  name: &str,
  path: &str,
  service: Option<&str>,
  j: bool,
) -> CliResult<()> {
  let value: Value = c
    .post_timeout(
      &format!("/api/servers/{}/pack", seg(name)),
      &json!({"path": path, "service": service}),
      Duration::from_secs(16 * 60),
    )
    .await?;
  out(j, &value, pretty);
  Ok(())
}

pub async fn host_units(
  c: &Client,
  name: &str,
  j: bool,
) -> CliResult<()> {
  let units: Value = c
    .get(&format!("/api/servers/{}/host-units", seg(name)))
    .await?;
  out(j, &units, pretty);
  Ok(())
}

pub async fn host_logs(
  c: &Client,
  name: &str,
  unit: &str,
  lines: u32,
  j: bool,
) -> CliResult<()> {
  let logs: String = c
    .get(&format!(
      "/api/servers/{}/host-units/{}/logs?lines={lines}",
      seg(name),
      seg(unit)
    ))
    .await?;
  out(j, &logs, |logs| print!("{logs}"));
  Ok(())
}

pub async fn show_watch_unit(
  c: &Client,
  name: &str,
  unit: &str,
  j: bool,
) -> CliResult<()> {
  let units: Vec<Value> = c
    .get(&format!("/api/servers/{}/host-units", seg(name)))
    .await?;
  let value = units.into_iter().find(|value| value["unit"] == unit);
  let hint = "不带参数现为只读查看；开启请加 --on，关闭请加 --off";
  let status = value
    .as_ref()
    .and_then(|value| value["state"].as_str())
    .unwrap_or("没有在运行");
  let watched = value
    .as_ref()
    .and_then(|value| value["watched"].as_bool())
    .unwrap_or(false);
  out(
    j,
    &json!({"server": name, "unit": unit, "state": status, "watched": watched, "hint": hint}),
    |_| {
      println!(
        "{unit}  {status}  {}\n{hint}",
        if watched { "已监视" } else { "未监视" }
      );
    },
  );
  Ok(())
}

pub async fn watch_unit(
  c: &Client,
  name: &str,
  unit: &str,
  watch: bool,
  j: bool,
) -> CliResult<()> {
  let value: Value = c
    .put(
      &format!(
        "/api/servers/{}/host-units/{}/watch",
        seg(name),
        seg(unit)
      ),
      &json!({"watch": watch}),
    )
    .await?;
  out(j, &value, pretty);
  Ok(())
}

pub async fn usage(c: &Client, name: &str, j: bool) -> CliResult<()> {
  let value: Value = c
    .get(&format!("/api/metrics/usage?server={}", seg(name)))
    .await?;
  out(j, &value, pretty);
  Ok(())
}

pub async fn traffic(
  c: &Client,
  name: &str,
  j: bool,
) -> CliResult<()> {
  let value: Value = c
    .get(&format!("/api/servers/{}/traffic", seg(name)))
    .await?;
  out(j, &value, pretty);
  Ok(())
}

pub async fn sessions(
  c: &Client,
  name: &str,
  end: Option<String>,
  rename: Option<Vec<String>>,
  j: bool,
) -> CliResult<()> {
  let name = seg(name);
  if let Some(session) = end {
    let value: Value = c
      .delete(&format!(
        "/api/servers/{name}/sessions/{}",
        seg(&session)
      ))
      .await?;
    out(j, &value, |_| println!("已结束会话 {session}"));
  } else if let Some(names) = rename {
    let [from, to] = names.as_slice() else {
      return Err(
        wharf_api_types::ApiError::invalid("改名需要旧名和新名")
          .into(),
      );
    };
    let value: Value = c
      .put(
        &format!("/api/servers/{name}/sessions/{}", seg(from)),
        &json!({"to": to}),
      )
      .await?;
    out(j, &value, |_| println!("已将会话 {from} 改名为 {to}"));
  } else {
    let value: Value =
      c.get(&format!("/api/servers/{name}/sessions")).await?;
    out(j, &value, pretty);
  }
  Ok(())
}
