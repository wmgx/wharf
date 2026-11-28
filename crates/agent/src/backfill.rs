use std::collections::VecDeque;

use wharf_api_types::agent::BufferedSample;

const MAX_AGE_MS: i64 = 15 * 60_000;
const MAX_SAMPLES: usize = 20;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_SINGLE_BYTES: usize = 512 * 1024;

pub fn unix_ms() -> i64 {
  chrono::Utc::now().timestamp_millis()
}

#[derive(Default)]
pub struct BackfillBuffer {
  entries: VecDeque<(usize, BufferedSample)>,
  bytes: usize,
  dropped: u32,
}

impl BackfillBuffer {
  fn evict(&mut self) {
    if let Some((bytes, _)) = self.entries.pop_front() {
      self.bytes -= bytes;
      self.dropped = self.dropped.saturating_add(1);
    }
  }

  fn expire(&mut self, now: i64) {
    while self
      .entries
      .front()
      .is_some_and(|(_, s)| s.at_ms < now - MAX_AGE_MS)
    {
      self.evict();
    }
  }

  pub fn push(&mut self, mut sample: BufferedSample, now: i64) {
    self.expire(now);
    let size = |s: &BufferedSample| {
      serde_json::to_vec(s).map_or(usize::MAX, |v| v.len())
    };
    let mut bytes = size(&sample);
    if bytes > MAX_SINGLE_BYTES {
      for hit in &mut sample.log_hits {
        hit.lines.clear();
      }
      bytes = size(&sample);
      if bytes > MAX_SINGLE_BYTES {
        self.dropped = self.dropped.saturating_add(1);
        return;
      }
    }
    if sample.metrics.is_none() && sample.log_hits.is_empty() {
      return;
    }
    while self.entries.len() >= MAX_SAMPLES
      || self.bytes + bytes > MAX_BYTES
    {
      self.evict();
    }
    self.entries.push_back((bytes, sample));
    self.bytes += bytes;
  }

  pub fn peek_all(&mut self, now: i64) -> (Vec<BufferedSample>, u32) {
    self.expire(now);
    (
      self.entries.iter().map(|(_, s)| s.clone()).collect(),
      self.dropped,
    )
  }

  pub fn clear(&mut self) {
    *self = Self::default();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn backfill_buffer_caps() {
    let mut buffer = BackfillBuffer::default();
    for at_ms in 0..25 {
      buffer.push(
        BufferedSample {
          at_ms,
          metrics: Some(Default::default()),
          log_hits: vec![],
        },
        at_ms,
      );
    }
    let (samples, dropped) = buffer.peek_all(25);
    assert_eq!(
      (samples.len(), samples[0].at_ms, dropped),
      (20, 5, 5)
    );
    let (samples, dropped) = buffer.peek_all(MAX_AGE_MS + 25);
    assert!(samples.is_empty());
    assert_eq!(dropped, 25);

    buffer.clear();
    for at_ms in 0..=5 {
      let bytes = if at_ms == 5 {
        MAX_SINGLE_BYTES + 1
      } else {
        MAX_SINGLE_BYTES - 1024
      };
      buffer.push(
        BufferedSample {
          at_ms,
          metrics: None,
          log_hits: vec![wharf_api_types::service_checks::LogHit {
            id: "fixture".into(),
            count: 1,
            at: at_ms,
            lines: vec!["x".repeat(bytes)],
          }],
        },
        at_ms,
      );
    }
    let (samples, dropped) = buffer.peek_all(5);
    assert_eq!((samples[0].at_ms, samples.len(), dropped), (1, 5, 1));
    assert!(buffer.bytes <= MAX_BYTES);
    assert!(samples[4].log_hits[0].lines.is_empty());
  }
}
