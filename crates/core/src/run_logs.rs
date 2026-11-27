use std::{
  fs::{self, DirBuilder, File, OpenOptions},
  io::{self, BufWriter, Read, Write},
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::{Path, PathBuf},
  sync::Arc,
  time::{Duration, SystemTime},
};

use serde::Deserialize;
use serde_json::{Value, json};
use wharf_api_types::{ApiError, plan::Run};

use crate::{log_redact, log_search, state::AppState};

const MAX_STEP_RAW_BYTES: usize = 16 * 1024 * 1024;
const MAX_READ_BYTES: usize = MAX_STEP_RAW_BYTES + 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const KEEP_RUNS: usize = 100;
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
const OMITTED: &str = "[wharf] 单步日志超过 16 MiB 上限，后续已省略";
const WIRE_OMITTED: &str = "[wharf] 日志输出过快，省略了 ";

pub(crate) fn omitted_lines(line: &str) -> Option<u64> {
  line
    .strip_prefix(WIRE_OMITTED)?
    .strip_suffix(" 行")?
    .parse()
    .ok()
}

fn valid_id(id: &str) -> bool {
  !id.is_empty()
    && id
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn dir(data: &Path, id: &str) -> Option<PathBuf> {
  (!data.as_os_str().is_empty() && valid_id(id))
    .then(|| data.join("run-logs").join(id))
}

pub struct StepLogWriter {
  output: Option<(PathBuf, BufWriter<File>)>,
  bytes: usize,
  full: bool,
}

impl StepLogWriter {
  pub fn open(data: &Path, id: &str, index: usize) -> Self {
    let output = dir(data, id).and_then(|dir| {
      let path = dir.join(format!("step-{index}.log"));
      let file = DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .and_then(|()| {
          OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        });
      match file {
        Ok(file) => Some((path, BufWriter::new(file))),
        Err(error) => {
          tracing::warn!("创建执行日志失败：{error}");
          None
        }
      }
    });
    Self {
      output,
      bytes: 0,
      full: false,
    }
  }

  pub fn append(&mut self, line: &str) {
    let Some((_, output)) = &mut self.output else {
      return;
    };
    if self.full {
      return;
    }
    self.full =
      self.bytes.saturating_add(line.len()).saturating_add(1)
        > MAX_STEP_RAW_BYTES;
    let line = if self.full { OMITTED } else { line };
    self.bytes += line.len() + 1;
    if let Err(error) =
      writeln!(output, "{line}").and_then(|()| output.flush())
    {
      tracing::warn!("写入执行日志失败：{error}");
      self.full = true;
    }
  }

  pub fn finish(self) {
    if let Some((path, mut output)) = self.output {
      let result = output.flush();
      drop(output);
      if let Err(error) = result.and_then(|()| seal(&path)) {
        tracing::warn!("归档执行日志失败：{error}");
      }
    }
  }
}

fn seal(path: &Path) -> io::Result<()> {
  wharf_pack::gzip_file(path, &path.with_extension("log.gz"))?;
  fs::remove_file(path)
}

pub fn seal_run_dir(data: &Path, id: &str) {
  let Some(dir) = dir(data, id) else { return };
  if let Ok(entries) = fs::read_dir(dir) {
    for entry in entries.flatten() {
      let name = entry.file_name();
      let step = name
        .to_str()
        .and_then(|n| n.strip_prefix("step-"))
        .and_then(|n| n.strip_suffix(".log"))
        .and_then(|n| n.parse::<usize>().ok());
      if step.is_some()
        && entry.file_type().is_ok_and(|t| t.is_file())
        && let Err(error) = seal(&entry.path())
      {
        tracing::warn!("归档中断的执行日志失败：{error}");
      }
    }
  }
}

fn limited(path: &Path) -> io::Result<Vec<u8>> {
  let mut buf = Vec::new();
  File::open(path)?
    .take(MAX_READ_BYTES as u64 + 1)
    .read_to_end(&mut buf)?;
  if buf.len() > MAX_READ_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "执行日志超过读取上限",
    ));
  }
  Ok(buf)
}

fn read_step(
  data: &Path,
  id: &str,
  index: usize,
) -> io::Result<Option<(String, &'static str)>> {
  let Some(dir) = dir(data, id) else {
    return Ok(None);
  };
  let path = dir.join(format!("step-{index}.log"));
  let (bytes, source) = match limited(&path) {
    Ok(bytes) => (bytes, "live"),
    Err(e) if e.kind() == io::ErrorKind::NotFound => {
      match limited(&path.with_extension("log.gz")) {
        Ok(bytes) => (
          wharf_pack::gunzip_bytes(&bytes, MAX_READ_BYTES)?,
          "archive",
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
          return Ok(None);
        }
        Err(e) => return Err(e),
      }
    }
    Err(e) => return Err(e),
  };
  Ok(Some((String::from_utf8_lossy(&bytes).into_owned(), source)))
}

fn cleanup_dirs(state: &AppState) -> io::Result<()> {
  if state.data_dir.as_os_str().is_empty() {
    return Ok(());
  }
  let entries = match fs::read_dir(state.data_dir.join("run-logs")) {
    Ok(entries) => entries,
    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
    Err(e) => return Err(e),
  };
  let mut dirs = Vec::new();
  for entry in entries {
    let entry = entry?;
    if !entry.file_type()?.is_dir() {
      continue;
    }
    let name = entry.file_name();
    let Some(id) = name.to_str().filter(|id| valid_id(id)) else {
      continue;
    };
    if state.runs.is_active(id) {
      continue;
    }
    let path = entry.path();
    let modified = entry.metadata()?.modified()?;
    let mut bytes = 0;
    for f in fs::read_dir(&path)? {
      bytes += f?.metadata()?.len();
    }
    dirs.push((modified, id.to_string(), path, bytes));
  }
  dirs.sort_unstable_by(|a, b| b.cmp(a));
  let now = SystemTime::now();
  let mut count = 0;
  let mut bytes = 0;
  for (mtime, id, path, len) in dirs {
    if state.runs.is_active(&id) {
      continue;
    }
    if now.duration_since(mtime).unwrap_or_default() > MAX_AGE
      || count >= KEEP_RUNS
      || bytes + len > MAX_TOTAL_BYTES
    {
      fs::remove_dir_all(path)?;
    } else {
      count += 1;
      bytes += len;
    }
  }
  Ok(())
}

pub async fn cleanup(state: &Arc<AppState>) -> Result<(), ApiError> {
  let state = state.clone();
  tokio::task::spawn_blocking(move || cleanup_dirs(&state))
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))
}

#[derive(Deserialize)]
pub struct RunLogsQuery {
  step: Option<usize>,
  tail: Option<u32>,
  #[serde(default)]
  all: bool,
  grep: Option<String>,
  #[serde(default)]
  errors: bool,
  max_line: Option<usize>,
}

pub fn query(
  data: &Path,
  run: Run,
  query: RunLogsQuery,
) -> Result<Value, ApiError> {
  let mut source = "db";
  let n = run.steps.len();
  let range = match query.step {
    Some(step) if (1..=n).contains(&step) => step - 1..step,
    Some(step) => {
      return Err(ApiError::invalid(format!(
        "执行 {} 没有第 {step} 步（共有 {n} 步）",
        run.run_id
      )));
    }
    None => 0..n,
  };
  let filtered =
    query.grep.is_some() || query.errors || query.max_line.is_some();
  let mut search = log_search::RunSearch::new(
    &log_search::Options {
      grep: query.grep.as_deref(),
      errors: query.errors,
      max_line: query.max_line.unwrap_or(usize::MAX),
      limit: if query.all {
        usize::MAX
      } else {
        query.tail.unwrap_or(500).max(1) as usize
      },
    },
    MAX_RESPONSE_BYTES - 1024,
    filtered,
  );
  let mut total_lines = 0u64;
  let mut incomplete = false;
  let mut headers = Vec::new();
  for index in range {
    let step = &run.steps[index];
    let archived =
      read_step(data, &run.run_id, index).map_err(|e| {
        ApiError::internal(format!("读取执行日志失败：{e}"))
      })?;
    let raw = match archived {
      Some((raw, from)) => {
        if from == "live" || source == "db" {
          source = from;
        }
        raw
      }
      None => {
        incomplete |= step.log_truncated;
        step.log.join("\n")
      }
    };
    if raw.is_empty() {
      continue;
    }
    if n > 1 && query.step.is_none() && !query.errors {
      headers.push((
        search.scanned(),
        log_redact::redact_text(&format!(
          "=== [{}/{n}] {} ===",
          index + 1,
          step.title
        )),
      ));
    }
    let mut lines = 0u64;
    for line in raw.lines() {
      if let Some(dropped) = omitted_lines(line) {
        lines = lines.saturating_add(dropped);
        incomplete = true;
      } else if line == OMITTED {
        incomplete = true;
      } else {
        lines = lines.saturating_add(1);
      }
      search.push(&log_redact::redact_text(line));
    }
    incomplete |= lines < step.log_lines;
    total_lines =
      total_lines.saturating_add(lines.max(step.log_lines));
  }
  let (found, limited) = search.finish(&headers);
  let mut result = json!({
    "run_id": run.run_id, "status": run.status, "step": query.step, "source": source,
    "total_lines": total_lines, "truncated": incomplete || limited,
  });
  if limited {
    result["hint"] = json!("用 --step 或 --grep 缩小日志范围");
  }
  let Value::Object(mut found) =
    serde_json::to_value(found).map_err(crate::db::json_err)?
  else {
    unreachable!("日志查询结果是对象");
  };
  if !filtered {
    found.remove("scanned");
    found.remove("matched");
  }
  result.as_object_mut().unwrap().extend(found);
  Ok(result)
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::plan::{RunStatus, RunStep, StepStatus};

  #[test]
  fn archives_full_1200_lines_redacts_and_greps() {
    let temp = tempfile::tempdir().unwrap();
    let mut writer = StepLogWriter::open(temp.path(), "r_a", 0);
    let mut step = RunStep {
      items: vec![],
      title: "构建".into(),
      status: StepStatus::Done,
      log: vec![],
      log_lines: 0,
      log_truncated: false,
      error: None,
      started_at: None,
      finished_at: None,
    };
    for index in 1..=1200 {
      let line = if index == 50 {
        wharf_api_types::mask_values(
          "BOOM fixture-private-value",
          &["fixture-private-value".into()],
        )
      } else {
        format!("line {index}")
      };
      crate::apply::append_step_log(&mut step, &mut writer, &line);
    }
    writer.finish();
    assert_eq!(step.log.len(), 400);
    assert!(step.log_truncated);
    assert_eq!(step.log_lines, 1200);
    let run = Run {
      run_id: "r_a".into(),
      actor: None,
      retry_of: None,
      plan_id: String::new(),
      status: RunStatus::Succeeded,
      started_at: chrono::Utc::now(),
      finished_at: None,
      steps: vec![step],
    };
    let query =
      serde_json::from_value(json!({"grep": "boom"})).unwrap();
    let result = super::query(temp.path(), run, query).unwrap();
    assert_eq!(result["source"], "archive");
    assert_eq!(result["total_lines"], 1200);
    assert_eq!(result["logs"], "BOOM ***\n");
  }
}
