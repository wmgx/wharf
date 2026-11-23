//! `wharf service files/download/upload`：服务数据目录里的文件，接口和页面上的文件浏览相同。

use std::{io::Write, path::Path, time::Duration};

use serde_json::{Value, json};
use wharf_api_types::{ApiError, agent::FileEntry};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

/// 和控制面一致：上传整个放在内存里。
const MAX_UPLOAD: u64 = 100 << 20;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub async fn list(
  c: &Client,
  name: &str,
  path: &str,
  j: bool,
) -> CliResult<()> {
  let v: Vec<FileEntry> = c
    .get(&format!(
      "/api/services/{}/files?path={}",
      seg(name),
      seg(path)
    ))
    .await?;
  out(j, &v, |v| {
    if v.is_empty() {
      println!("（空目录）");
    }
    for f in v {
      let time = chrono::DateTime::from_timestamp_millis(f.modified)
        .map(|t| {
          t.with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
            .to_string()
        })
        .unwrap_or_default();
      let (size, suffix) = match (f.dir, f.link) {
        (true, _) => ("-".to_string(), "/"),
        (_, true) => ("-".to_string(), "@"),
        _ => (human_size(f.size), ""),
      };
      println!("{size:>8}  {time}  {}{suffix}", f.name);
    }
  });
  Ok(())
}

fn human_size(n: u64) -> String {
  format_size(n, &["B", "K", "M", "G"])
}

pub(crate) fn format_size(n: u64, units: &[&str]) -> String {
  let mut v = n as f64;
  let mut i = 0;
  while v >= 1024.0 && i + 1 < units.len() {
    v /= 1024.0;
    i += 1;
  }
  if i == 0 {
    format!("{n}{}", units[0])
  } else {
    format!("{v:.1}{}", units[i])
  }
}

pub async fn download(
  c: &Client,
  name: &str,
  path: &str,
  output: Option<String>,
  j: bool,
) -> CliResult<()> {
  let url = format!(
    "/api/services/{}/files/download?path={}",
    seg(name),
    seg(path)
  );
  if output.as_deref() == Some("-") {
    let mut stdout = std::io::stdout();
    c.download(&url, DOWNLOAD_TIMEOUT, |b| stdout.write_all(b))
      .await?;
    return stdout.flush().map_err(|e| {
      ApiError::internal(format!("写入失败：{e}")).into()
    });
  }
  let target = output.unwrap_or_else(|| {
    path.rsplit('/').next().unwrap_or("file").to_string()
  });
  // 先写临时文件，下载完整了再改名，中途失败不留半截文件。
  let tmp = format!("{target}.part");
  let mut file = std::fs::File::create(&tmp).map_err(|e| {
    ApiError::invalid(format!("不能写 {target}：{e}"))
  })?;
  let mut size = 0u64;
  let result = c
    .download(&url, DOWNLOAD_TIMEOUT, |b| {
      size += b.len() as u64;
      file.write_all(b)
    })
    .await;
  let result = result.and_then(|()| {
    std::fs::rename(&tmp, &target).map_err(|e| {
      ApiError::internal(format!("保存 {target} 失败：{e}")).into()
    })
  });
  if result.is_err() {
    let _ = std::fs::remove_file(&tmp);
  }
  result?;
  out(j, &json!({"path": target, "size": size}), |_| {
    println!("已下载到 {target}（{}）", human_size(size))
  });
  Ok(())
}

pub async fn upload(
  c: &Client,
  name: &str,
  local: &Path,
  path: &str,
  j: bool,
) -> CliResult<()> {
  let size = std::fs::metadata(local)
    .map_err(|e| {
      ApiError::invalid(format!("读不了 {}：{e}", local.display()))
    })?
    .len();
  if size > MAX_UPLOAD {
    return Err(
      ApiError::invalid(format!(
        "{} 有 {}，超过 100M 的上传上限",
        local.display(),
        human_size(size)
      ))
      .with_hint("大文件用 scp 传到服务器的 /srv/<服务>/ 下")
      .into(),
    );
  }
  let bytes = std::fs::read(local).map_err(|e| {
    ApiError::invalid(format!("读不了 {}：{e}", local.display()))
  })?;
  let v: Value = c
    .put_bytes(
      &format!(
        "/api/services/{}/files?path={}",
        seg(name),
        seg(path)
      ),
      bytes,
    )
    .await?;
  out(j, &v, |_| {
    println!("已上传到 {name}:{path}（{}）", human_size(size))
  });
  Ok(())
}
