use wharf_api_types::view::AlertLevel;

use super::{Mode, Op, Rule, ev, split_unit};

pub(super) const LOG: Rule = Rule {
  id: "log_keyword",
  name: "日志关键字命中",
  metric: "log.count_over_minimum",
  op: Op::Ge,
  threshold: 0.0,
  threshold_editable: true,
  for_n: 1,
  mode: Mode::ServiceLog,
  recover: None,
  every: "窗口内次数减去配置的最少次数",
  default_level: AlertLevel::Urgent,
  key: |s| format!("log_keyword.{s}"),
  fire: |c| {
    ev(
      format!("服务 {} 命中日志关键字", split_unit(c.subject).0),
      c.detail.into(),
    )
  },
  ok: |c| {
    ev(
      format!(
        "服务 {} 的日志关键字告警恢复",
        split_unit(c.subject).0
      ),
      c.detail.into(),
    )
  },
};

pub(super) const PORT: Rule = Rule {
  id: "port_down",
  name: "宿主机端口不通",
  metric: "port.ok",
  op: Op::Lt,
  threshold: 1.0,
  threshold_editable: false,
  for_n: 3,
  mode: Mode::Consecutive,
  recover: None,
  every: "每分钟一次",
  default_level: AlertLevel::Urgent,
  key: |s| format!("port_down.{s}"),
  fire: |c| {
    ev(
      format!(
        "服务 {} 的端口 {} 不通",
        split_unit(c.subject).0,
        split_unit(c.subject).1
      ),
      c.detail.into(),
    )
  },
  ok: |c| {
    ev(
      format!(
        "服务 {} 的端口 {} 恢复",
        split_unit(c.subject).0,
        split_unit(c.subject).1
      ),
      c.detail.into(),
    )
  },
};

pub(super) const HEARTBEAT: Rule = Rule {
  id: "heartbeat_late",
  name: "服务心跳异常",
  metric: "heartbeat.overdue_mins",
  op: Op::Gt,
  threshold: 0.0,
  threshold_editable: true,
  for_n: 1,
  mode: Mode::Heartbeat,
  recover: None,
  every: "超过服务心跳间隔及宽限的分钟数",
  default_level: AlertLevel::Urgent,
  key: |s| format!("heartbeat_late.{s}"),
  fire: |c| {
    ev(format!("服务 {} 的心跳异常", c.subject), c.detail.into())
  },
  ok: |c| {
    ev(format!("服务 {} 的心跳恢复", c.subject), c.detail.into())
  },
};
