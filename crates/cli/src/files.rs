//! `wharf service files/download/upload`：服务数据目录里的文件，接口和页面上的文件浏览相同。

use std::{
  fs::{File, OpenOptions},
  io::{self, Write},
  path::{Path, PathBuf},
  time::Duration,
};

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
  let size = download_to(c, &url, Path::new(&target)).await?;
  out(j, &json!({"path": target, "size": size}), |_| {
    println!("已下载到 {target}（{}）", human_size(size))
  });
  Ok(())
}

fn create_download_temp(
  target: &Path,
) -> io::Result<(File, PathBuf)> {
  let name = target
    .file_name()
    .ok_or_else(|| io::Error::other("输出文件名无效"))?;
  let mut bytes = [0; 8];
  getrandom::fill(&mut bytes)
    .map_err(|e| io::Error::other(e.to_string()))?;
  let mut tmp = std::ffi::OsString::from(".");
  tmp.push(name);
  tmp.push(format!(".wharf-dl-{}.tmp", hex::encode(bytes)));
  let tmp = target.with_file_name(tmp);
  let file =
    OpenOptions::new().write(true).create_new(true).open(&tmp)?;
  Ok((file, tmp))
}

async fn download_to(
  c: &Client,
  url: &str,
  target: &Path,
) -> CliResult<u64> {
  let mut staged: Option<(File, PathBuf)> = None;
  let mut size = 0;
  let result = c
    .download(url, DOWNLOAD_TIMEOUT, |chunk| {
      if staged.is_none() {
        staged = Some(create_download_temp(target)?);
      }
      let (file, _) = staged.as_mut().unwrap();
      file.write_all(chunk)?;
      size += chunk.len() as u64;
      Ok(())
    })
    .await;
  if let Err(e) = result {
    if let Some((file, tmp)) = staged {
      drop(file);
      let _ = std::fs::remove_file(tmp);
    }
    return Err(e);
  }
  let save_error = |e| {
    ApiError::internal(format!("保存 {} 失败：{e}", target.display()))
  };
  let (file, tmp) = staged
    .map_or_else(|| create_download_temp(target), Ok)
    .map_err(save_error)?;
  let synced = file.sync_all();
  drop(file);
  if let Err(e) = synced.and_then(|()| std::fs::rename(&tmp, target))
  {
    let _ = std::fs::remove_file(tmp);
    return Err(save_error(e).into());
  }
  Ok(size)
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

#[tokio::test]
async fn download_failure_preserves_existing_part_file() {
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
  };

  let root = tempfile::tempdir().unwrap();
  let part = root.path().join("archive.tar.part");
  std::fs::write(&part, "keep-me").unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let client = Client::test_endpoint(format!(
    "http://{}",
    listener.local_addr().unwrap()
  ));
  let server = tokio::spawn(async move {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
      request.push(socket.read_u8().await.unwrap());
    }
    socket
      .write_all(
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
      )
      .await
      .unwrap();
  });
  assert!(
    tokio::time::timeout(
      Duration::from_secs(5),
      download_to(&client, "/", &root.path().join("archive.tar"))
    )
    .await
    .unwrap()
    .is_err()
  );
  server.await.unwrap();
  assert_eq!(std::fs::read_to_string(&part).unwrap(), "keep-me");
  assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
