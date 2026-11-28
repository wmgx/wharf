//! `wharf service files/download/upload`：服务数据目录里的文件，接口和页面上的文件浏览相同。

use std::{
  fs::{File, OpenOptions},
  io::{self, Write},
  path::{Path, PathBuf},
  time::Duration,
};

use clap::Subcommand;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  agent::{
    FileEntry, FileGrepResult, FileMkdirResult, FileMvResult,
    FileRmResult, FileTailResult,
  },
};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

/// 和控制面一致：上传整个放在内存里。
const MAX_UPLOAD: u64 = 100 << 20;
pub(crate) const DOWNLOAD_TIMEOUT: Duration =
  Duration::from_secs(30 * 60);

#[derive(Subcommand)]
pub enum FilesCmd {
  /// 列出目录内容。
  Ls {
    name: String,
    #[arg(default_value = "")]
    path: String,
  },
  /// 查看文本文件的末尾。
  Tail {
    name: String,
    path: String,
    #[arg(short = 'n', long, default_value_t = 100)]
    lines: u32,
  },
  /// 在指定文件或目录内搜索文本。
  Grep {
    name: String,
    pattern: String,
    #[arg(default_value = "")]
    path: String,
    #[arg(long)]
    regex: bool,
    #[arg(long, default_value_t = 100)]
    limit: u32,
  },
  /// 删除文件或目录，需要 exec 权限。
  Rm {
    name: String,
    path: String,
    #[arg(short, long)]
    recursive: bool,
  },
  /// 在同一服务目录内移动文件或目录，需要 exec 权限。
  Mv {
    name: String,
    from: String,
    to: String,
    #[arg(long)]
    force: bool,
  },
  /// 建目录，需要 exec 权限。
  Mkdir {
    name: String,
    path: String,
    #[arg(short, long)]
    parents: bool,
  },
}

pub async fn run(
  c: &Client,
  cmd: FilesCmd,
  j: bool,
) -> CliResult<()> {
  let base =
    |name: &str| format!("/api/services/{}/files", seg(name));
  match cmd {
    FilesCmd::Ls { name, path } => {
      return list(c, &name, &path, j).await;
    }
    FilesCmd::Tail { name, path, lines } => {
      let r: FileTailResult = c
        .get(&format!(
          "{}/tail?path={}&lines={lines}",
          base(&name),
          seg(&path)
        ))
        .await?;
      out(j, &r, |r| {
        print!("{}", r.content);
        if r.truncated {
          eprintln!("已按大小上限截断");
        }
      });
    }
    FilesCmd::Grep {
      name,
      pattern,
      path,
      regex,
      limit,
    } => {
      let r: FileGrepResult = c
        .get(&format!(
          "{}/grep?path={}&pattern={}&regex={regex}&limit={limit}",
          base(&name),
          seg(&path),
          seg(&pattern)
        ))
        .await?;
      out(j, &r, |r| {
        for hit in &r.matches {
          println!("{}:{}: {}", hit.path, hit.line, hit.text);
        }
        eprintln!(
          "命中 {} 处（扫了 {} 个文件，跳过二进制 {} 个、超大文件 {} 个、软链 {} 个）",
          r.matches.len(),
          r.scanned_files,
          r.skipped_binary,
          r.skipped_large,
          r.skipped_links
        );
        if r.truncated {
          eprintln!("搜索达到上限");
        }
      });
    }
    FilesCmd::Rm {
      name,
      path,
      recursive,
    } => {
      let r: FileRmResult = c
        .delete(&format!(
          "{}?path={}&recursive={recursive}",
          base(&name),
          seg(&path)
        ))
        .await?;
      out(j, &r, |r| {
        println!("已删除 {name}:{}（{} 项）", r.path, r.removed)
      });
    }
    FilesCmd::Mv {
      name,
      from,
      to,
      force,
    } => {
      let r: FileMvResult = c
        .post(
          &format!("{}/mv", base(&name)),
          &json!({ "from": from, "to": to, "force": force }),
        )
        .await?;
      out(j, &r, |r| println!("已移动 {name}:{} → {}", r.from, r.to));
    }
    FilesCmd::Mkdir {
      name,
      path,
      parents,
    } => {
      let r: FileMkdirResult = c
        .post(
          &format!("{}/mkdir", base(&name)),
          &json!({ "path": path, "parents": parents }),
        )
        .await?;
      out(j, &r, |r| {
        println!(
          "{} {name}:{}",
          if r.created {
            "已创建目录"
          } else {
            "目录已存在"
          },
          r.path
        )
      });
    }
  }
  Ok(())
}

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

pub(crate) async fn download_to(
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
