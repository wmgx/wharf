use super::*;

const BINARY: Rule = Rule {
  id: "",
  name: "",
  metric: "",
  op: Op::Lt,
  threshold: 1.0,
  threshold_editable: false,
  for_n: 1,
  mode: Mode::Consecutive,
  recover: None,
  every: "每分钟一次",
  key: |_| unreachable!(),
  fire: |_| unreachable!(),
  ok: |_| unreachable!(),
};

pub(super) const GATEWAY: Rule = Rule {
  id: "gateway_down",
  name: "网关不可用",
  metric: "gateway.running",
  key: |s| format!("gateway.down.{s}"),
  fire: |c| ev(format!("网关 {} 不可用", c.subject), c.detail.into()),
  ok: |c| ev(format!("网关 {} 已恢复", c.subject), c.detail.into()),
  ..BINARY
};

pub(super) const DISK: Rule = Rule {
  id: "disk_full",
  name: "磁盘已满",
  metric: "disk.available",
  key: |s| format!("disk.full.{s}"),
  fire: |c| {
    ev(format!("服务器 {} 的磁盘已满", c.subject), c.detail.into())
  },
  ok: |c| {
    ev(
      format!("服务器 {} 的磁盘已有可用空间", c.subject),
      c.detail.into(),
    )
  },
  ..BINARY
};

pub(super) const CERT: Rule = Rule {
  id: "cert_expired",
  name: "证书已过期",
  metric: "cert.valid",
  every: "每 2 分钟一次",
  key: |s| format!("cert.expired.{s}"),
  fire: |c| {
    ev(format!("域名 {} 的证书已过期", c.subject), c.detail.into())
  },
  ok: |c| {
    ev(format!("域名 {} 的证书已续期", c.subject), c.detail.into())
  },
  ..BINARY
};
