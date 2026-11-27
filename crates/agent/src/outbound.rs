use std::{
  collections::{BTreeMap, HashMap, VecDeque},
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use wharf_api_types::agent::AgentMsg;

use crate::exec::Progress;

pub struct Outbound {
  ctrl: mpsc::Receiver<AgentMsg>,
  progress: mpsc::Receiver<Log>,
  gaps: Arc<LogGaps>,
  data: Arc<DataMux>,
  streak: u8,
}

impl Outbound {
  pub fn new()
  -> (Self, mpsc::Sender<AgentMsg>, LogSender, Arc<DataMux>) {
    let (ctrl_tx, ctrl) = mpsc::channel(256);
    let (progress_tx, progress) = mpsc::channel(512);
    let data = Arc::new(DataMux::default());
    let gaps = Arc::new(LogGaps::default());
    (
      Self {
        ctrl,
        progress,
        gaps: gaps.clone(),
        data: data.clone(),
        streak: 0,
      },
      ctrl_tx,
      LogSender {
        tx: progress_tx,
        gaps,
      },
      data,
    )
  }

  pub async fn recv(&mut self) -> Option<AgentMsg> {
    loop {
      if let Ok(msg) = self.ctrl.try_recv() {
        return Some(msg);
      }
      if self.streak >= 16
        && let Some(msg) = self.data.pop()
      {
        self.streak = 0;
        return Some(msg);
      }
      if let Ok(log) = self.progress.try_recv() {
        if let Some(msg) = log.message() {
          self.streak = self.streak.saturating_add(1);
          return Some(msg);
        }
        continue;
      }
      if let Some((id, count)) =
        self.gaps.counts.lock().unwrap().pop_first()
      {
        self.streak = self.streak.saturating_add(1);
        return Some(AgentMsg::Progress {
          id,
          line: omitted(count),
        });
      }
      if let Some(msg) = self.data.pop() {
        self.streak = 0;
        return Some(msg);
      }
      if self.ctrl.is_closed()
        && self.progress.is_closed()
        && self.data.state.lock().unwrap().slots.is_empty()
      {
        return None;
      }
      tokio::select! {
        biased;
        Some(msg) = self.ctrl.recv() => return Some(msg),
        Some(log) = self.progress.recv() => {
          if let Some(msg) = log.message() {
            self.streak = self.streak.saturating_add(1);
            return Some(msg);
          }
        }
        _ = self.data.ready.notified() => {}
        _ = self.gaps.ready.notified() => {}
        else => return None,
      }
    }
  }
}

enum Log {
  Line { id: u64, line: String },
  Flushed(oneshot::Sender<()>),
}

impl Log {
  fn message(self) -> Option<AgentMsg> {
    match self {
      Self::Line { id, line } => {
        Some(AgentMsg::Progress { id, line })
      }
      Self::Flushed(done) => {
        let _ = done.send(());
        None
      }
    }
  }
}

#[derive(Default)]
struct LogGaps {
  counts: Mutex<BTreeMap<u64, usize>>,
  ready: Notify,
}

#[derive(Clone)]
pub struct LogSender {
  tx: mpsc::Sender<Log>,
  gaps: Arc<LogGaps>,
}

fn omitted(n: usize) -> String {
  format!("[wharf] 日志输出过快，省略了 {n} 行")
}

pub struct ProgressLog {
  out: LogSender,
  id: u64,
  sent: AtomicBool,
}

impl ProgressLog {
  pub fn new(out: LogSender, id: u64) -> Arc<Self> {
    Arc::new(Self {
      out,
      id,
      sent: false.into(),
    })
  }

  pub fn callback(self: &Arc<Self>) -> Progress {
    let log = self.clone();
    Arc::new(move |line| log.push(line))
  }

  fn message(&self, line: String) -> Log {
    Log::Line { id: self.id, line }
  }

  fn push(&self, line: String) {
    let mut gaps = self.out.gaps.counts.lock().unwrap();
    let dropped = gaps.remove(&self.id).unwrap_or_default();
    if dropped > 0
      && let Err(err) =
        self.out.tx.try_send(self.message(omitted(dropped)))
    {
      if matches!(err, mpsc::error::TrySendError::Full(_)) {
        gaps.insert(self.id, dropped.saturating_add(1));
        self.out.gaps.ready.notify_one();
      }
      return;
    }
    match self.out.tx.try_send(self.message(line)) {
      Ok(()) => self.sent.store(true, Ordering::Relaxed),
      Err(mpsc::error::TrySendError::Full(_)) => {
        gaps.insert(self.id, 1);
        self.out.gaps.ready.notify_one();
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
  }

  pub async fn finish(&self) {
    let n = self
      .out
      .gaps
      .counts
      .lock()
      .unwrap()
      .remove(&self.id)
      .unwrap_or_default();
    if n > 0
      && self.out.tx.send(self.message(omitted(n))).await.is_err()
    {
      return;
    }
    if n > 0 || self.sent.load(Ordering::Relaxed) {
      // 响应优先于别的请求，自己的最后一行必须先发完。
      let (tx, rx) = oneshot::channel();
      if self.out.tx.send(Log::Flushed(tx)).await.is_ok() {
        let _ = rx.await;
      }
    }
  }
}

#[derive(Default)]
pub struct DataMux {
  state: Mutex<MuxState>,
  ready: Notify,
}

#[derive(Default)]
struct MuxState {
  slots: HashMap<u64, Slot>,
  order: VecDeque<u64>,
}

struct Slot {
  buf: VecDeque<String>,
  cap: usize,
  space: Arc<Notify>,
  closed: bool,
}

pub struct DataSender {
  mux: Arc<DataMux>,
  id: u64,
  space: Arc<Notify>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
  Cancelled,
  Timeout,
}

impl DataMux {
  pub fn register(
    self: &Arc<Self>,
    id: u64,
    cap: usize,
  ) -> DataSender {
    let space = Arc::new(Notify::new());
    self.state.lock().unwrap().slots.insert(
      id,
      Slot {
        buf: VecDeque::new(),
        cap,
        space: space.clone(),
        closed: false,
      },
    );
    DataSender {
      mux: self.clone(),
      id,
      space,
    }
  }

  fn pop(&self) -> Option<AgentMsg> {
    let mut state = self.state.lock().unwrap();
    let id = state.order.pop_front()?;
    let slot = state.slots.get_mut(&id).unwrap();
    let msg = slot.buf.pop_front();
    slot.space.notify_one();
    if !slot.buf.is_empty() {
      state.order.push_back(id);
    } else if slot.closed {
      state.slots.remove(&id);
    }
    msg.map(|line| AgentMsg::Progress { id, line })
  }
}

impl DataSender {
  pub fn try_send(&self, msg: String) -> Result<(), String> {
    let mut state = self.mux.state.lock().unwrap();
    let slot = state.slots.get_mut(&self.id).unwrap();
    if slot.buf.len() == slot.cap {
      return Err(msg);
    }
    let ready = slot.buf.is_empty();
    slot.buf.push_back(msg);
    if ready {
      state.order.push_back(self.id);
      self.mux.ready.notify_one();
    }
    Ok(())
  }

  pub async fn send(
    &self,
    mut msg: String,
    cancel: &CancellationToken,
    timeout: Duration,
  ) -> Result<(), SendError> {
    tokio::select! {
      biased;
      _ = cancel.cancelled() => Err(SendError::Cancelled),
      result = tokio::time::timeout(timeout, async {
        loop {
          match self.try_send(msg) {
            Ok(()) => break,
            Err(pending) => msg = pending,
          }
          self.space.notified().await;
        }
      }) => result.map_err(|_| SendError::Timeout),
    }
  }

  pub async fn finish(&self) {
    loop {
      if self.mux.state.lock().unwrap().slots[&self.id]
        .buf
        .is_empty()
      {
        return;
      }
      self.space.notified().await;
    }
  }
}

impl Drop for DataSender {
  fn drop(&mut self) {
    let mut state = self.mux.state.lock().unwrap();
    let slot = state.slots.get_mut(&self.id).unwrap();
    if slot.buf.is_empty() {
      state.slots.remove(&self.id);
    } else {
      slot.closed = true;
    }
    self.mux.ready.notify_one();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn forward_backpressure_never_cancels_deploy_or_blocks_ctrl()
  {
    let (mut out, ctrl, tx, mux) = Outbound::new();
    let stream = mux.register(1, 32);
    for _ in 0..32 {
      assert!(stream.try_send(String::new()).is_ok());
    }
    assert!(stream.try_send(String::new()).is_err());
    let log = ProgressLog::new(tx, 2);
    for _ in 0..600 {
      log.push("build".into());
    }
    assert_eq!(
      log.out.gaps.counts.lock().unwrap().get(&2),
      Some(&88)
    );
    ctrl
      .send(AgentMsg::Response {
        id: 3,
        result: Ok(serde_json::Value::Null),
      })
      .await
      .unwrap();
    assert!(matches!(
      out.recv().await,
      Some(AgentMsg::Response { id: 3, .. })
    ));
    let omitted = tokio::time::timeout(
      Duration::from_secs(1),
      async {
        loop {
          if matches!(out.recv().await, Some(AgentMsg::Progress { id: 2, line }) if line.contains("省略了 88 行"))
          {
            break;
          }
        }
      },
    );
    omitted.await.unwrap();
    drop(ctrl);
    drop(stream);
    let finish = tokio::spawn(async move { log.finish().await });
    while out.recv().await.is_some() {}
    finish.await.unwrap();
  }
}
