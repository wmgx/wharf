use std::{
  collections::HashMap,
  convert::Infallible,
  future::Future,
  sync::{Arc, Mutex},
};

use axum::{
  body::Body,
  http::header,
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  view::{ExecStreamEvent, HostExecResponse},
};

use crate::hub::ProgressFn;

#[derive(Deserialize)]
pub(crate) struct ExecQuery {
  #[serde(default, deserialize_with = "parse_stream")]
  pub stream: bool,
}

fn parse_stream<'de, D: serde::Deserializer<'de>>(
  d: D,
) -> Result<bool, D::Error> {
  match String::deserialize(d)?.as_str() {
    "1" | "true" => Ok(true),
    "0" | "false" => Ok(false),
    _ => Err(serde::de::Error::custom("stream 只能是 0 或 1")),
  }
}

/// 以字节流匹配密钥，保留可能跨块的前缀。stdout 和 stderr 各有自己的尾部。
struct Masker {
  patterns: HashMap<u8, Vec<Vec<u8>>>,
}

impl Masker {
  fn new(mut values: Vec<String>) -> Self {
    values.retain(|v| !v.is_empty());
    values.sort_unstable_by(|a, b| {
      b.len().cmp(&a.len()).then_with(|| a.cmp(b))
    });
    values.dedup();
    let mut patterns = HashMap::<u8, Vec<Vec<u8>>>::new();
    for value in values {
      let value = value.into_bytes();
      patterns.entry(value[0]).or_default().push(value);
    }
    Self { patterns }
  }

  fn take(
    &self,
    pending: &mut Vec<u8>,
    end: bool,
    truncated: bool,
  ) -> Vec<u8> {
    let mut out = Vec::with_capacity(pending.len());
    let mut offset = 0;
    while offset < pending.len() {
      let rest = &pending[offset..];
      if let Some(patterns) = self.patterns.get(&rest[0]) {
        if let Some(secret) =
          patterns.iter().find(|secret| rest.starts_with(secret))
        {
          if !end
            && patterns.iter().any(|pattern| {
              pattern.len() > rest.len() && pattern.starts_with(rest)
            })
          {
            break;
          }
          out.extend_from_slice(b"***");
          offset += secret.len();
          continue;
        }
        if patterns.iter().any(|secret| secret.starts_with(rest)) {
          if !end {
            break;
          }
          if truncated {
            out.extend_from_slice(b"***");
            offset = pending.len();
            continue;
          }
        }
      }
      out.push(rest[0]);
      offset += 1;
    }
    pending.drain(..offset);
    out
  }
}

#[derive(Default)]
struct Progress {
  pending: [Vec<u8>; 2],
  dropped: bool,
}

#[derive(Deserialize)]
struct Frame {
  s: String,
  d: String,
}

fn frame(i: usize, data: &[u8]) -> ExecStreamEvent {
  let data = STANDARD.encode(data);
  if i == 0 {
    ExecStreamEvent::Stdout { data }
  } else {
    ExecStreamEvent::Stderr { data }
  }
}

pub(crate) fn response<F, Fut>(
  values: Vec<String>,
  execute: F,
) -> Response
where
  F: FnOnce(ProgressFn, CancellationToken) -> Fut + Send + 'static,
  Fut: Future<
      Output = Result<(Option<String>, HostExecResponse), ApiError>,
    > + Send,
{
  let (tx, rx) = mpsc::channel::<ExecStreamEvent>(256);
  let cancel = CancellationToken::new();
  let guard = cancel.clone().drop_guard();
  let masker = Arc::new(Masker::new(values));
  let progress = Arc::new(Mutex::new(Progress::default()));
  let callback: ProgressFn = {
    let (tx, masker, progress) =
      (tx.clone(), masker.clone(), progress.clone());
    Arc::new(move |line| {
      let mut current =
        progress.lock().unwrap_or_else(|e| e.into_inner());
      let decoded =
        serde_json::from_str::<Frame>(&line).ok().and_then(|f| {
          let i = match f.s.as_str() {
            "out" => 0,
            "err" => 1,
            _ => return None,
          };
          Some((i, STANDARD.decode(f.d).ok()?))
        });
      if let Some((i, bytes)) = decoded {
        current.pending[i].extend_from_slice(&bytes);
        let output =
          masker.take(&mut current.pending[i], false, false);
        if !output.is_empty()
          && tx.try_send(frame(i, &output)).is_err()
        {
          current.dropped = true;
        }
      } else {
        current.pending.iter_mut().for_each(Vec::clear);
        current.dropped = true;
      }
    })
  };
  tokio::spawn(async move {
    let result = execute(callback, cancel).await;
    let mut current = {
      let mut lock =
        progress.lock().unwrap_or_else(|e| e.into_inner());
      std::mem::take(&mut *lock)
    };
    let truncated = current.dropped
      || result.as_ref().is_ok_and(|(_, r)| r.truncated);
    let incomplete = truncated || result.is_err();
    for (i, pending) in current.pending.iter_mut().enumerate() {
      let output = masker.take(pending, true, incomplete);
      if !output.is_empty()
        && tx.send(frame(i, &output)).await.is_err()
      {
        return;
      }
    }
    let event = match result {
      Ok((container, r)) => {
        // 旧 agent 的完整响应已在运行函数中打码。
        for (i, text) in [r.stdout, r.stderr].iter().enumerate() {
          if !text.is_empty()
            && tx.send(frame(i, text.as_bytes())).await.is_err()
          {
            return;
          }
        }
        ExecStreamEvent::Done {
          container,
          exit_code: r.exit_code,
          truncated,
          duration_ms: r.duration_ms,
        }
      }
      Err(error) => ExecStreamEvent::Error { error },
    };
    let _ = tx.send(event).await;
  });
  let body = futures_util::stream::unfold(
    (rx, guard),
    |(mut rx, guard)| async move {
      let event = rx.recv().await?;
      let line =
        serde_json::to_string(&event).expect("执行事件可以序列化");
      Some((Ok::<_, Infallible>(line + "\n"), (rx, guard)))
    },
  );
  (
    [
      (header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8"),
      (header::CACHE_CONTROL, "no-cache"),
      (header::HeaderName::from_static("x-accel-buffering"), "no"),
    ],
    Body::from_stream(body),
  )
    .into_response()
}

pub(crate) fn redact(
  text: &str,
  values: &[String],
  truncated: bool,
) -> String {
  let masker = Masker::new(values.to_vec());
  String::from_utf8_lossy(&masker.take(
    &mut text.as_bytes().to_vec(),
    true,
    truncated,
  ))
  .into_owned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn streaming_masks_secrets_across_byte_boundaries() {
    let mask = Masker::new(vec!["fixture-secret".into()]);
    let mut pending = b"ok fixture-".to_vec();
    assert_eq!(mask.take(&mut pending, false, false), b"ok ");
    pending.extend_from_slice(b"secret!");
    assert_eq!(mask.take(&mut pending, false, false), b"***!");
    pending.extend_from_slice(b"fixture-se");
    assert_eq!(mask.take(&mut pending, true, true), b"***");
  }
}
