use super::{Mode, Op, Rule, ev};

const BINARY: Rule = Rule {
  id: "",
  name: "",
  metric: "",
  op: Op::Gt,
  threshold: 0.5,
  threshold_editable: false,
  for_n: 1,
  mode: Mode::Consecutive,
  recover: None,
  every: "每 5 分钟一次",
  key: |_| unreachable!(),
  fire: |_| unreachable!(),
  ok: |_| unreachable!(),
};

pub(super) const KEY: Rule = Rule {
  id: "tailnet_key_expiring",
  name: "组网密钥快到期",
  metric: "tailnet.key_days",
  op: Op::Lt,
  threshold: 14.0,
  recover: Some(14.0),
  every: "每 6 小时一次",
  key: |s| format!("tailnet.key.{s}"),
  fire: |c| {
    ev(format!("{} 的组网密钥快到期", c.subject), c.detail.into())
  },
  ok: |c| {
    ev(format!("{} 的组网密钥已续期", c.subject), c.detail.into())
  },
  ..BINARY
};

pub(super) const RELAY: Rule = Rule {
  id: "tailnet_relay",
  name: "组网走中继",
  metric: "tailnet.relay",
  for_n: 6,
  // 0.5（空闲、查不到）打断连续采样，已触发时等到看到直连再恢复。
  recover: Some(0.5),
  key: |s| format!("tailnet.relay.{s}"),
  fire: |c| ev(format!("{} 组网走中继", c.subject), c.detail.into()),
  ok: |c| ev(format!("{} 恢复直连", c.subject), c.detail.into()),
  ..BINARY
};

pub(super) const INCIDENT: Rule = Rule {
  id: "external_incident",
  name: "外部服务故障",
  metric: "external.incident",
  key: |s| format!("external.incident.{}", s.to_lowercase()),
  fire: |c| ev(format!("{} 正在故障", c.subject), c.detail.into()),
  ok: |c| ev(format!("{} 状态已恢复", c.subject), c.detail.into()),
  ..BINARY
};

pub(super) const VENDOR: Rule = Rule {
  id: "vendor_token_invalid",
  name: "厂商账号不可用",
  metric: "vendor.invalid",
  every: "每天一次",
  key: |s| format!("vendor.invalid.{s}"),
  fire: |c| {
    ev(format!("{} 厂商账号不可用", c.subject), c.detail.into())
  },
  ok: |c| {
    ev(format!("{} 厂商账号已恢复", c.subject), c.detail.into())
  },
  ..BINARY
};

pub(crate) async fn clear_incident(
  state: &crate::state::AppState,
  name: &str,
) {
  let _guard = super::UPDATE.lock().await;
  let cfg = super::config(state).await;
  super::forget_subject(
    state,
    INCIDENT.id,
    name,
    &(INCIDENT.key)(name),
  )
  .await;
  super::release(state, &cfg).await;
}
