use std::{
  collections::{HashMap, VecDeque},
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
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
  data: Arc<DataMux>,
  streak: u8,
}

impl Outbound {
  pub fn new() -> (
    Self,
    mpsc::Sender<AgentMsg>,
    mpsc::Sender<Log>,
    Arc<DataMux>,
  ) {
    let (ctrl_tx, ctrl) = mpsc::channel(256);
    let (progress_tx, progress) = mpsc::channel(512);
    let data = Arc::new(DataMux::default());
    (
      Self {
        ctrl,
        progress,
        data: data.clone(),
        streak: 0,
      },
      ctrl_tx,
      progress_tx,
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
        else => return None,
      }
    }
  }
}

pub enum Log {
  Line(AgentMsg),
  Flushed(oneshot::Sender<()>),
}

impl Log {
  fn message(self) -> Option<AgentMsg> {
    match self {
      Self::Line(msg) => Some(msg),
      Self::Flushed(done) => {
        let _ = done.send(());
        None
      }
    }
  }
}

pub struct ProgressLog {
  tx: mpsc::Sender<Log>,
  id: u64,
  dropped: AtomicUsize,
  sent: AtomicUsize,
}

impl ProgressLog {
  pub fn new(tx: mpsc::Sender<Log>, id: u64) -> Arc<Self> {
    Arc::new(Self {
      tx,
      id,
      dropped: 0.into(),
      sent: 0.into(),
    })
  }

  pub fn callback(self: &Arc<Self>) -> Progress {
    let log = self.clone();
    Arc::new(move |line| log.push(line))
  }

  fn message(&self, line: String) -> Log {
    Log::Line(AgentMsg::Progress { id: self.id, line })
  }

  fn omitted(&self, n: usize) -> Log {
    self.message(format!("[wharf] 日志输出过快，省略了 {n} 行"))
  }

  fn push(&self, line: String) {
    let n = self.dropped.swap(0, Ordering::Relaxed);
    if n > 0
      && let Err(err) = self.tx.try_send(self.omitted(n))
    {
      if matches!(err, mpsc::error::TrySendError::Full(_)) {
        self.dropped.fetch_add(n + 1, Ordering::Relaxed);
      }
      return;
    }
    match self.tx.try_send(self.message(line)) {
      Ok(()) => {
        self.sent.store(1, Ordering::Relaxed);
      }
      Err(mpsc::error::TrySendError::Full(_)) => {
        self.dropped.fetch_add(1, Ordering::Relaxed);
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
  }

  pub async fn finish(&self) {
    let n = self.dropped.swap(0, Ordering::Relaxed);
    if n > 0 && self.tx.send(self.omitted(n)).await.is_err() {
      return;
    }
    if n > 0 || self.sent.load(Ordering::Relaxed) != 0 {
      // 响应优先于别的请求，自己的最后一行必须先发完。
      let (tx, rx) = oneshot::channel();
      if self.tx.send(Log::Flushed(tx)).await.is_ok() {
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
  buf: VecDeque<AgentMsg>,
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
    msg
  }
}

impl DataSender {
  pub fn try_send(&self, msg: AgentMsg) -> Result<(), AgentMsg> {
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
    mut msg: AgentMsg,
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
    let frame = || AgentMsg::Progress {
      id: 1,
      line: String::new(),
    };
    for _ in 0..32 {
      assert!(stream.try_send(frame()).is_ok());
    }
    assert!(stream.try_send(frame()).is_err());
    let log = ProgressLog::new(tx, 2);
    for _ in 0..600 {
      log.push("build".into());
    }
    assert_eq!(log.dropped.load(Ordering::Relaxed), 88);
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
    drop(ctrl);
    drop(stream);
    let finish = tokio::spawn(async move { log.finish().await });
    let mut omitted = false;
    while let Some(msg) = out.recv().await {
      omitted |= matches!(msg, AgentMsg::Progress { id: 2, line } if line.contains("省略了 88 行"));
    }
    finish.await.unwrap();
    assert!(omitted);
  }
}
