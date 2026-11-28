use std::{
  io::{Read, Write},
  time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{ExecStreamEvent, HostExecResponse, ServiceExecResponse},
};

use crate::{
  client::{CliError, CliResult, Client, seg},
  print,
};

#[derive(Args)]
pub struct ExecArgs {
  /// 执行超时秒数（默认 30，最多 600）。
  #[arg(long)]
  timeout: Option<u64>,
  /// 工作目录，必须是绝对路径。
  #[arg(long)]
  cwd: Option<String>,
  /// 从本地文件读脚本，- 表示标准输入。
  #[arg(long, conflicts_with = "command")]
  script: Option<String>,
  /// 等命令结束后一次性返回输出。
  #[arg(long)]
  no_stream: bool,
}

const LIMIT: usize = 64 * 1024;

fn read_script(reader: impl Read) -> CliResult<String> {
  let mut bytes = Vec::new();
  reader
    .take((LIMIT + 1) as u64)
    .read_to_end(&mut bytes)
    .map_err(|_| ApiError::invalid("无法读取脚本"))?;
  if bytes.len() > LIMIT {
    return Err(ApiError::invalid("脚本不能超过 64 KiB").into());
  }
  String::from_utf8(bytes)
    .map_err(|_| ApiError::invalid("脚本必须使用 UTF-8").into())
}

fn read_exec_source(
  command: Vec<String>,
  script: Option<&str>,
) -> CliResult<String> {
  let command = match script {
    Some("-") => read_script(std::io::stdin().lock())?,
    Some(path) => {
      let file = std::fs::File::open(path).map_err(|e| {
        ApiError::invalid(format!("读取脚本 {path} 失败：{e}"))
      })?;
      read_script(file)?
    }
    None => match command.as_slice() {
      [only] => only.clone(),
      args => args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\"'\"'")))
        .collect::<Vec<_>>()
        .join(" "),
    },
  };
  if command.trim().is_empty() || command.contains('\0') {
    return Err(ApiError::invalid("命令不能为空或包含 NUL").into());
  }
  if command.len() > LIMIT {
    return Err(ApiError::invalid("命令不能超过 64 KiB").into());
  }
  Ok(command)
}

pub(crate) async fn run(
  c: &Client,
  name: &str,
  service: bool,
  container: Option<String>,
  args: ExecArgs,
  command: Vec<String>,
  j: bool,
) -> CliResult<()> {
  let command = read_exec_source(command, args.script.as_deref())?;
  let timeout = args.timeout.unwrap_or(30);
  if !(1..=600).contains(&timeout) {
    return Err(
      ApiError::invalid("超时必须在 1 到 600 秒之间").into(),
    );
  }
  let mut body = json!({ "command": command, "timeout_secs": timeout, "cwd": args.cwd });
  if let Some(container) = container {
    body["container"] = json!(container);
  }
  let resource = if service { "services" } else { "servers" };
  let path = format!("/api/{resource}/{}/exec", seg(name));
  let timeout = Duration::from_secs(timeout + 45);
  let request = async {
    if !j && !args.no_stream {
      let mut done = None;
      let fallback = c
        .post_stream(
          &format!("{path}?stream=1"),
          &body,
          timeout,
          |line| {
            if done.is_some() {
              return Err(
                ApiError::internal("执行流在结束后还有数据").into(),
              );
            }
            let event: ExecStreamEvent = serde_json::from_str(line)
              .map_err(|_| {
              ApiError::internal("执行流事件格式无效")
            })?;
            match event {
              ExecStreamEvent::Stdout { data } => {
                write(&mut std::io::stdout(), &decode(&data)?)?
              }
              ExecStreamEvent::Stderr { data } => {
                write(&mut std::io::stderr(), &decode(&data)?)?
              }
              ExecStreamEvent::Done {
                exit_code,
                truncated,
                ..
              } => {
                done = Some((exit_code, truncated));
              }
              ExecStreamEvent::Error { error } => {
                return Err(error.into());
              }
            }
            Ok(())
          },
        )
        .await?;
      if let Some(response) = fallback {
        let r: HostExecResponse = serde_json::from_slice(&response)
          .map_err(|_| {
          ApiError::internal("无法读取非流式执行结果")
        })?;
        sync_output(&r.stdout, &r.stderr)?;
        return finish(r.exit_code, r.truncated, false);
      }
      let (code, truncated) = done.ok_or_else(|| {
        ApiError::internal("执行流中断，未收到退出状态")
      })?;
      return finish(code, truncated, false);
    }
    if service {
      let r: ServiceExecResponse =
        c.post_timeout(&path, &body, timeout).await?;
      if j {
        print::json(&r);
      } else {
        sync_output(&r.stdout, &r.stderr)?;
      }
      finish(r.exit_code, r.truncated, j)
    } else {
      let r: HostExecResponse =
        c.post_timeout(&path, &body, timeout).await?;
      if j {
        print::json(&r);
      } else {
        sync_output(&r.stdout, &r.stderr)?;
      }
      finish(r.exit_code, r.truncated, j)
    }
  };
  tokio::select! {
    result = request => result,
    _ = tokio::signal::ctrl_c() => {
      if j {
        print::error(&ApiError::new(ErrorCode::Cancelled, "正在取消远端命令"), true);
      } else {
        eprintln!("正在取消，等待远端清理…");
      }
      Err(CliError::Exit(130))
    }
  }
}

fn decode(data: &str) -> CliResult<Vec<u8>> {
  STANDARD
    .decode(data)
    .map_err(|_| ApiError::internal("执行流输出编码无效").into())
}

fn write(out: &mut impl Write, data: &[u8]) -> CliResult<()> {
  out
    .write_all(data)
    .and_then(|()| out.flush())
    .map_err(anyhow::Error::from)?;
  Ok(())
}

fn sync_output(stdout: &str, stderr: &str) -> CliResult<()> {
  write(&mut std::io::stdout(), stdout.as_bytes())?;
  write(&mut std::io::stderr(), stderr.as_bytes())
}

fn finish(exit_code: i32, truncated: bool, j: bool) -> CliResult<()> {
  if truncated && !j {
    eprintln!("\n[输出已截断]");
  }
  if exit_code == 0 {
    Ok(())
  } else {
    Err(CliError::Exit(exit_code))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn exec_script_preserves_content_and_rejects_oversize() {
    let script = "echo '$VAR'\nprintf \"%s\\n\" \"$VAR\"\n";
    assert_eq!(read_script(script.as_bytes()).unwrap(), script);
    assert!(read_script(&vec![b'a'; LIMIT + 1][..]).is_err());
  }

  #[test]
  fn exec_passes_through_remote_two_in_json_mode() {
    assert!(matches!(finish(2, false, true), Err(CliError::Exit(2))));
  }
}
