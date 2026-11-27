//! 宿主机上的代码目录：列目录（页面浏览用）和打包上传（部署"服务器上的目录"）。
//! 都借 agent 自己的镜像起临时容器，只读挂载宿主机根目录，不用网络。
//! 打包在临时容器里跑 `wharf-agent pack`，规则和 CLI 的 `wharf deploy` 一样（`wharf-pack`）。

use std::{path::Path, time::Duration};

use sha2::{Digest, Sha256};
use tokio::{
  fs::File,
  io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
};
use tokio_util::io::ReaderStream;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{HostPackJob, PackedUpload},
};

use crate::{docker::Docker, exec::Ctx};

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const PACK_TIMEOUT: Duration = Duration::from_secs(600);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const PACK_CHUNK: usize = 64 * 1024;

async fn hash_file(
  file: &mut File,
) -> std::io::Result<(String, u64)> {
  let mut hasher = Sha256::new();
  let mut buf = vec![0; PACK_CHUNK];
  let mut size = 0;
  loop {
    let n = file.read(&mut buf).await?;
    if n == 0 {
      break;
    }
    hasher.update(&buf[..n]);
    size += n as u64;
  }
  Ok((hex::encode(hasher.finalize()), size))
}

/// 只接受规范的绝对路径：不含 `..`、不含换行和 NUL。
fn check_path(path: &str) -> Result<String, ApiError> {
  let p = path.trim();
  if !p.starts_with('/')
    || p.split('/').any(|seg| seg == "..")
    || p.contains(['\n', '\0'])
  {
    return Err(ApiError::invalid(format!(
      "路径要是绝对路径：{path}"
    )));
  }
  Ok(p.trim_end_matches('/').to_string())
}

fn host_mount() -> &'static str {
  "type=bind,src=/,dst=/host,readonly"
}

pub async fn list(
  docker: &Docker,
  path: &str,
  ctx: &Ctx,
) -> Result<Vec<String>, ApiError> {
  let path = check_path(path)?;
  let image = crate::adopt::self_image(docker, ctx).await?;
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--label",
      "wharf.temp=1",
      "--network",
      "none",
      "--entrypoint",
      "ls",
      "--mount",
      host_mount(),
    ])
    .arg(image)
    .args(["-1pA", "--"])
    .arg(format!("/host{path}/"))
    .timeout(LIST_TIMEOUT)
    .run(ctx)
    .await?;
  if !out.success {
    return Err(ApiError::invalid(format!(
      "读不了 {path}：{}",
      out.stderr.trim()
    )));
  }
  let mut names: Vec<String> = out
    .stdout
    .lines()
    .map(str::to_string)
    .filter(|l| !l.is_empty())
    .collect();
  // 目录在前。
  names.sort_by_key(|n| (!n.ends_with('/'), n.to_lowercase()));
  Ok(names)
}

pub async fn pack(
  docker: &Docker,
  data_dir: &Path,
  core_url: &str,
  job: &HostPackJob,
  ctx: &Ctx,
) -> Result<PackedUpload, ApiError> {
  let path = check_path(&job.path)?;
  let image = crate::adopt::self_image(docker, ctx).await?;
  let tmp = data_dir.join("tmp");
  std::fs::create_dir_all(&tmp).map_err(|e| {
    ApiError::internal(format!("{}：{e}", tmp.display()))
  })?;
  let name = format!("pack-{}.tar.gz", crate::build::random_suffix());
  let file = tmp.join(&name);
  ctx
    .say(format!("打包 {path}（按 .gitignore、.dockerignore 排除）"));
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--label",
      "wharf.temp=1",
      "--network",
      "none",
      "--entrypoint",
      "wharf-agent",
      "--mount",
      host_mount(),
      "--mount",
    ])
    .arg(format!("type=bind,src={},dst=/out", tmp.display()))
    .arg(image)
    .args(["pack", "--out"])
    .arg(format!("/out/{name}"))
    .arg(format!("/host{path}"))
    .timeout(PACK_TIMEOUT)
    .run(ctx)
    .await;
  let transfer = async {
    let out = out?;
    if !out.success {
      return Err(ApiError::invalid(format!(
        "打包失败：{}",
        out.stderr.trim()
      )));
    }
    let files = out.stdout.trim().parse().unwrap_or(0);
    let file_err =
      |e| ApiError::internal(format!("{}：{e}", file.display()));
    let mut archive = File::open(&file).await.map_err(file_err)?;
    let (sha256, size) =
      hash_file(&mut archive).await.map_err(file_err)?;
    archive.seek(SeekFrom::Start(0)).await.map_err(file_err)?;
    ctx.say(format!(
      "上传代码包（{files} 个文件，{} KiB）",
      size / 1024
    ));
    let url = format!(
      "{}/agent/uploads/{sha256}",
      core_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::builder()
      .timeout(UPLOAD_TIMEOUT)
      .build()
      .map_err(|e| ApiError::internal(e.to_string()))?
      .put(&url)
      .bearer_auth(&job.token)
      .header(reqwest::header::CONTENT_LENGTH, size)
      .body(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
        archive, PACK_CHUNK,
      )))
      .send()
      .await
      .map_err(|e| {
        ApiError::internal(format!("上传失败：{}", e.without_url()))
      })?;
    if !resp.status().is_success() {
      return Err(ApiError::internal(format!(
        "上传失败：HTTP {}",
        resp.status()
      )));
    }
    Ok(PackedUpload {
      sha256,
      size,
      files,
    })
  };
  let result = tokio::select! {
    result = transfer => result,
    _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "上传代码包已取消")),
  };
  let _ = tokio::fs::remove_file(&file).await;
  result
}

/// 临时容器里执行的 `wharf-agent pack`：写代码包，标准输出打印文件数。
pub fn pack_cli(dir: &Path, out: &Path) -> anyhow::Result<()> {
  let (_, _, files) = wharf_pack::pack_to_file(dir, out, &[])
    .map_err(|e| anyhow::anyhow!("{}", e.message))?;
  println!("{files}");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn chunked_hash_matches_whole_file() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let data: Vec<u8> =
      (0..PACK_CHUNK + 137).map(|i| (i % 251) as u8).collect();
    std::fs::write(tmp.path(), &data).unwrap();
    let mut file = File::open(tmp.path()).await.unwrap();
    let (sha, size) = hash_file(&mut file).await.unwrap();
    assert_eq!(size, data.len() as u64);
    assert_eq!(
      sha,
      hex::encode(Sha256::digest(std::fs::read(tmp.path()).unwrap()))
    );
  }
}
