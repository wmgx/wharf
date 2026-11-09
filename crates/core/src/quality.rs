//! 链路质量：每 [EVERY] 让每台在线机器对其余机器的探测端口连 [COUNT] 次，
//! 记延迟和丢包（打点 `link.ms`、`link.loss`，对象是 `<from>><to>`，和资源点一样保留 7 天）。
//!
//! - 告警：每轮把丢包率交给 [crate::rules]（规则 link_loss）；
//! - 中转建议：直连差、经第三台两段都好时给出建议。
//!
//! 最近一轮结果和连续计数只在内存里，控制面重启后等下一轮。

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, LinkSample, PROBE_PORT, ProbeTarget},
  view::{LinkView, RelayHint},
};

use crate::state::AppState;

const EVERY: Duration = Duration::from_secs(300);
const COUNT: u8 = 10;
const BAD_LOSS: f64 = 20.0;
/// 中转两段各自都要好于这个丢包率，合计还要比直连少一半以上。
const GOOD_LOSS: f64 = 5.0;
const TIMEOUT: Duration = Duration::from_secs(60);

type Pair = (String, String);

#[derive(Default)]
struct Memory {
  latest: BTreeMap<Pair, LinkView>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
      if let Err(e) = round(&state).await {
        tracing::warn!("链路质量检查失败：{}", e.message);
      }
      tokio::time::sleep(EVERY).await;
    }
  });
}

/// 最近一轮的结果和中转建议，只保留 `known` 里的机器。
pub fn view(known: &[String]) -> (Vec<LinkView>, Vec<RelayHint>) {
  let guard = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  let Some(m) = guard.as_ref() else {
    return (vec![], vec![]);
  };
  let links: Vec<LinkView> = m
    .latest
    .values()
    .filter(|l| known.contains(&l.from) && known.contains(&l.to))
    .cloned()
    .collect();
  let relays = relays(&links);
  (links, relays)
}

fn relays(links: &[LinkView]) -> Vec<RelayHint> {
  let loss = |a: &str, b: &str| {
    links
      .iter()
      .find(|l| l.from == a && l.to == b)
      .map(|l| l.loss)
  };
  let mut out = Vec::new();
  for direct in links.iter().filter(|l| l.loss >= BAD_LOSS) {
    let best = links
      .iter()
      .filter(|l| l.from == direct.from && l.to != direct.to)
      .filter_map(|first| {
        let second = loss(&first.to, &direct.to)?;
        (first.loss < GOOD_LOSS && second < GOOD_LOSS).then(|| {
          let total =
            100.0 - (100.0 - first.loss) * (100.0 - second) / 100.0;
          (first.to.clone(), total)
        })
      })
      .filter(|(_, total)| *total < direct.loss / 2.0)
      .min_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((via, via_loss)) = best {
      out.push(RelayHint {
        from: direct.from.clone(),
        to: direct.to.clone(),
        via,
        direct_loss: direct.loss,
        via_loss,
      });
    }
  }
  out
}

async fn round(state: &AppState) -> Result<(), ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;
  let net = snap.net(&snap.world);
  let names: Vec<String> =
    snap.world.servers.keys().cloned().collect();
  let calls = names
    .iter()
    .filter(|from| state.hub.is_online(from))
    .map(|from| {
      let to: Vec<String> = names
        .iter()
        .filter(|t| *t != from && net.private.contains_key(*t))
        .cloned()
        .collect();
      let targets = to
        .iter()
        .map(|t| {
          let ip = &net.private[t].ip;
          let host = if ip.contains(':') {
            format!("[{ip}]")
          } else {
            ip.clone()
          };
          ProbeTarget {
            server: t.clone(),
            addr: format!("{host}:{PROBE_PORT}"),
            plain: false,
          }
        })
        .collect::<Vec<_>>();
      async move {
        if to.is_empty() {
          return vec![];
        }
        let result: Result<Vec<LinkSample>, ApiError> = state
          .hub
          .call(
            from,
            AgentOp::Quality {
              targets,
              count: COUNT,
            },
            TIMEOUT,
            None,
            &CancellationToken::new(),
          )
          .await;
        match result {
          Ok(samples) if samples.len() == to.len() => to
            .into_iter()
            .zip(samples)
            .map(|(t, s)| ((from.clone(), t), s))
            .collect(),
          // 旧 agent 不认这个指令，跳过。
          _ => vec![],
        }
      }
    });
  let results: Vec<(Pair, LinkSample)> =
    futures_util::future::join_all(calls)
      .await
      .into_iter()
      .flatten()
      .collect();
  if results.is_empty() {
    return Ok(());
  }

  let at = chrono::Utc::now();
  let views: Vec<LinkView> = results
    .iter()
    .map(|((from, to), s)| LinkView {
      from: from.clone(),
      to: to.clone(),
      ms: s.avg_ms,
      loss: loss(s),
      at,
    })
    .collect();
  crate::metrics::record_links(state, &views).await;

  {
    let mut guard = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
    let m = guard.get_or_insert_with(Memory::default);
    m.latest
      .retain(|(f, t), _| names.contains(f) && names.contains(t));
    for v in &views {
      m.latest.insert((v.from.clone(), v.to.clone()), v.clone());
    }
  }
  for v in &views {
    crate::rules::observe(
      state,
      "link.loss",
      &format!("{}>{}", v.from, v.to),
      v.loss,
      "",
    )
    .await;
  }
  Ok(())
}

fn loss(s: &LinkSample) -> f64 {
  if s.sent == 0 {
    return 0.0;
  }
  100.0 * f64::from(s.sent - s.ok.min(s.sent)) / f64::from(s.sent)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn link(from: &str, to: &str, loss: f64) -> LinkView {
    LinkView {
      from: from.into(),
      to: to.into(),
      ms: Some(10.0),
      loss,
      at: chrono::Utc::now(),
    }
  }

  #[test]
  fn suggests_relay_when_both_hops_are_good() {
    let links = vec![
      link("home", "edge", 40.0),
      link("home", "relay", 0.0),
      link("relay", "edge", 0.0),
      link("edge", "home", 10.0),
    ];
    let hints = relays(&links);
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].via, "relay");
    assert_eq!(hints[0].from, "home");
  }

  #[test]
  fn no_relay_when_a_hop_is_bad() {
    let links = vec![
      link("home", "edge", 40.0),
      link("home", "relay", 0.0),
      link("relay", "edge", 10.0),
    ];
    assert!(relays(&links).is_empty());
  }
}
