use std::{
  io::Write,
  path::{Path, PathBuf},
};

use serde_json::json;
use wharf_api_types::{ApiError, view::TaskArtifactsView};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
  files::{DOWNLOAD_TIMEOUT, download_to},
};

#[derive(clap::Args)]
pub struct ArtifactArgs {
  name: String,
  /// 指定运行编号，默认取最近一次有产物的运行。
  #[arg(long)]
  run: Option<i64>,
  /// 下载产物，参数为列表中的相对路径。
  #[arg(long)]
  get: Option<String>,
  /// 下载到指定路径，- 表示标准输出。
  #[arg(short = 'o', long, requires = "get")]
  output: Option<PathBuf>,
}

pub async fn run(
  c: &Client,
  args: ArtifactArgs,
  j: bool,
) -> CliResult<()> {
  let name = seg(&args.name);
  let mut list_path = format!("/api/tasks/{name}/artifacts");
  if let Some(id) = args.run {
    list_path.push_str(&format!("?run={id}"));
  }
  let Some(path) = args.get else {
    let result: TaskArtifactsView = c.get(&list_path).await?;
    out(j, &result, |r| {
      for f in &r.artifacts {
        println!(
          "#{}  {}  {} B  {}",
          r.run_id.unwrap_or_default(),
          f.path,
          f.size,
          f.sha256.chars().take(12).collect::<String>()
        );
      }
      if let Some(hint) = &r.hint {
        println!("{hint}");
      }
    });
    return Ok(());
  };
  if j && args.output.as_deref() == Some(Path::new("-")) {
    return Err(
      ApiError::invalid("下载到标准输出时不能使用 --json").into(),
    );
  }
  let file = Path::new(&path)
    .file_name()
    .ok_or_else(|| ApiError::invalid("产物文件名不对"))?;
  let target = args.output.unwrap_or_else(|| PathBuf::from(file));
  let id = match args.run {
    Some(id) => id,
    None => {
      let result: TaskArtifactsView = c.get(&list_path).await?;
      result
        .run_id
        .ok_or_else(|| ApiError::not_found("该任务没有运行产物"))?
    }
  };
  let url = format!(
    "/api/tasks/{name}/runs/{id}/artifacts/download?path={}",
    seg(&path)
  );
  if target == Path::new("-") {
    let mut stdout = std::io::stdout();
    c.download(&url, DOWNLOAD_TIMEOUT, |data| stdout.write_all(data))
      .await?;
    return stdout
      .flush()
      .map_err(|_| ApiError::internal("写入标准输出失败").into());
  }
  let size = download_to(c, &url, &target).await?;
  out(
    j,
    &json!({ "task": args.name, "run_id": id, "path": target, "size": size }),
    |_| {
      println!("已下载到 {}（{size} B）", target.display());
    },
  );
  Ok(())
}
