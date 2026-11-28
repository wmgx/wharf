use super::*;

/// 事件通知：id、名称和默认级别。
pub(super) const NOTICES: &[(&str, &str, AlertLevel)] = &[
  ("exposure", "机器上新开了对公网的端口", AlertLevel::Urgent),
  ("login", "从新的地址登录控制面", AlertLevel::Urgent),
  ("ssh_login", "从陌生地址登录 SSH", AlertLevel::Urgent),
  ("security_receipt", "高危操作回执", AlertLevel::Urgent),
  ("recovery", "用掉了一个恢复码", AlertLevel::Urgent),
  (
    "task",
    "定时任务失败和恢复（任务自己也要开通知）",
    AlertLevel::Urgent,
  ),
  ("heal", "服务自动重启放弃和恢复", AlertLevel::Urgent),
  ("backup", "服务备份失败和恢复", AlertLevel::Urgent),
  ("failover", "网关切到备用入口、切回", AlertLevel::Urgent),
  ("update", "服务有新版本", AlertLevel::Digest),
  ("auto_update", "服务自动更新的结果", AlertLevel::Digest),
  ("unmanaged_container", "出现未纳管容器", AlertLevel::Digest),
  (
    "login_lockout",
    "登录或门禁触发防爆破锁定",
    AlertLevel::Urgent,
  ),
];

fn expiry_fire(c: &Ctx) -> Event {
  let (kind, name) = split_unit(c.subject);
  let kind = if kind == "domain" {
    "域名"
  } else {
    "服务器"
  };
  ev(
    if c.value < 0.0 {
      format!("{kind} {name} 已经到期")
    } else {
      format!("{kind} {name} 还有 {} 天到期", c.value as i64)
    },
    "到期前处理：域名在注册商续费；服务器在服务商续费，然后在服务器设置里更新续费日".into(),
  )
}

fn expiry_ok(c: &Ctx) -> Event {
  let (kind, name) = split_unit(c.subject);
  let kind = if kind == "domain" {
    "域名"
  } else {
    "服务器"
  };
  if c.value >= 9999.0 {
    ev(
      format!("{kind} {name} 不再提醒到期"),
      "续费日已清除，或域名已经不在路由里".into(),
    )
  } else {
    ev(
      format!("{kind} {name} 已续期"),
      format!("距离到期还有 {} 天", c.value as i64),
    )
  }
}

pub(super) const RULES: &[Rule] = &[
  resources::HOST_CPU,
  resources::HOST_MEM,
  resources::SERVICE_MEM,
  resources::INODE,
  resources::MEM_FORECAST,
  resources::AGENT_MEM,
  external::KEY,
  external::RELAY,
  external::INCIDENT,
  external::VENDOR,
  service_checks::LOG,
  service_checks::PORT,
  service_checks::HEARTBEAT,
  Rule {
    id: "backup_spike",
    name: "备份体积异常暴涨",
    metric: "backup.spike_ratio",
    op: Op::Ge,
    threshold: 5.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每次成功备份",
    period_secs: 86_400,
    default_level: AlertLevel::Digest,
    key: |s| format!("backup.spike.{s}"),
    fire: |c| {
      ev(
        format!("{} 的备份体积异常暴涨", c.subject),
        c.detail.to_owned(),
      )
    },
    ok: |c| {
      ev(
        format!("{} 的备份体积恢复正常", c.subject),
        c.detail.to_owned(),
      )
    },
  },
  Rule {
    id: "traffic_quota",
    name: "流量快用完",
    metric: "traffic.used_pct",
    op: Op::Ge,
    threshold: 80.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 5 分钟一次，按本期用量",
    period_secs: 300,
    default_level: AlertLevel::Digest,
    key: |s| format!("traffic.{s}"),
    fire: |c| {
      ev(
        format!("服务器 {} 本期流量已用 {:.0}%", c.subject, c.value),
        format!(
          "{}。到额度后可能被限速或产生额外费用，可以在服务器设置里调整额度或重置日",
          c.detail
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务器 {} 的流量回到额度内", c.subject),
        c.detail.into(),
      )
    },
  },
  Rule {
    id: "clock_skew",
    name: "时间不准",
    metric: "clock.skew_s",
    op: Op::Gt,
    threshold: 5.0,
    threshold_editable: true,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: Some(2.0),
    every: "每 30 秒一次",
    period_secs: 30,
    default_level: AlertLevel::Urgent,
    key: |s| format!("clock.{s}"),
    fire: |c| {
      let n = c.value as i64;
      ev(
        format!("服务器 {} 的时间和控制面差了 {n} 秒", c.subject),
        format!(
          "这台机器的时间和控制面差了 {n} 秒（已扣除网络往返）。时间不准会让证书校验、两步验证、备份时间戳出问题。检查这台机器的时间同步服务（systemd-timesyncd 或 chrony）"
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务器 {} 的时间恢复正常", c.subject),
        format!("和控制面的时间差降到 {:.1} 秒", c.value),
      )
    },
  },
  Rule {
    id: "disk_forecast",
    name: "磁盘预计写满",
    metric: "disk.days_left",
    op: Op::Lt,
    threshold: 14.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: Some(21.0),
    every: "每小时一次，按近 7 天趋势",
    period_secs: 3600,
    default_level: AlertLevel::Digest,
    key: |s| format!("diskfc.{s}"),
    fire: |c| {
      let n = if c.value < 1.0 {
        "不到 1".into()
      } else {
        (c.value as i64).to_string()
      };
      ev(
        format!("服务器 {} 的磁盘预计 {n} 天后写满", c.subject),
        format!(
          "按近 7 天的增长速度，磁盘预计 {n} 天后写满。清理没在用的镜像：服务器 {} → 系统 → 磁盘；或扩容",
          c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务器 {} 的磁盘不再预计很快写满", c.subject),
        if c.value >= 9999.0 {
          "近 7 天磁盘没有增长".into()
        } else {
          format!("按近 7 天的趋势，预计还能用 {} 天", c.value as i64)
        },
      )
    },
  },
  Rule {
    id: "expiry_soon",
    name: "快到期",
    metric: "expiry.days",
    op: Op::Lt,
    threshold: 14.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每小时一次",
    period_secs: 3600,
    default_level: AlertLevel::Digest,
    key: |s| format!("expiry.soon.{s}"),
    fire: expiry_fire,
    ok: expiry_ok,
  },
  Rule {
    id: "expiry_urgent",
    name: "马上到期",
    metric: "expiry.days",
    op: Op::Lt,
    threshold: 3.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每小时一次",
    period_secs: 3600,
    default_level: AlertLevel::Urgent,
    key: |s| format!("expiry.urgent.{s}"),
    fire: expiry_fire,
    ok: expiry_ok,
  },
  Rule {
    id: "server_offline",
    name: "服务器离线",
    metric: "server.online",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Urgent,
    key: |s| format!("agent.{s}"),
    fire: |c| {
      ev(
        format!("服务器 {} 离线", c.subject),
        format!(
          "{} 的 agent 已经 {} 分钟没有连上控制面：可能是机器关机、网络断了或 agent 挂了",
          c.subject, c.for_n
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务器 {} 恢复在线", c.subject),
        format!("{} 的 agent 已经连回控制面", c.subject),
      )
    },
  },
  Rule {
    id: "container_restarting",
    name: "容器反复重启",
    metric: "container.restarting",
    op: Op::Ge,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 2,
    mode: Mode::Window(10),
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Urgent,
    key: |s| format!("restart.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的容器在反复重启", c.subject),
        format!(
          "最近 10 分钟里有 {} 次看到容器处于重启中，多半是启动就崩溃。看日志：wharf service logs {}",
          c.for_n, c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 不再反复重启", c.subject),
        format!("最近 10 分钟没有看到 {} 的容器重启", c.subject),
      )
    },
  },
  Rule {
    id: "oom_killed",
    name: "内存超限被杀",
    metric: "container.oom",
    op: Op::Ge,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 1,
    mode: Mode::Window(30),
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Urgent,
    key: |s| format!("oom.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 因内存超限被杀", c.subject),
        format!(
          "容器用的内存超过上限，被系统杀掉了（{}）。看内存曲线和日志：wharf service logs {}",
          c.detail, c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 没有再因内存超限被杀", c.subject),
        "最近 30 分钟没有再发生".into(),
      )
    },
  },
  Rule {
    id: "monitor_failed",
    name: "服务监控失败",
    metric: "monitor.ok",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Urgent,
    key: |s| format!("monitor.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的监控不正常", c.subject),
        format!(
          "连续 {} 次检查失败（每分钟一次）：{}",
          c.for_n, c.detail
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 的监控恢复正常", c.subject),
        c.detail.to_string(),
      )
    },
  },
  Rule {
    id: "domain_down",
    name: "域名打不开",
    metric: "probe.ok",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 2 分钟一次",
    period_secs: 120,
    default_level: AlertLevel::Urgent,
    key: |s| format!("probe.{s}"),
    fire: |c| {
      ev(
        format!("域名 {} 打不开", c.subject),
        format!(
          "连续 {} 次检查失败（每 2 分钟一次）：{}。诊断：wharf doctor {}",
          c.for_n, c.detail, c.subject
        ),
      )
    },
    ok: |c| {
      ev(format!("域名 {} 恢复了", c.subject), c.detail.to_string())
    },
  },
  Rule {
    id: "cert_expiring",
    name: "证书快到期",
    metric: "cert.days",
    op: Op::Lt,
    threshold: crate::cert::WARN_DAYS as f64,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 2 分钟一次",
    period_secs: 120,
    default_level: AlertLevel::Digest,
    key: |s| format!("cert.{s}"),
    fire: |c| {
      let detail = if c.value < 0.0 {
        format!("已过期 {:.0} 天", c.value.abs())
      } else if c.value == 0.0 {
        "已到期".into()
      } else {
        format!("{:.0} 天后到期", c.value)
      };
      ev(
        format!("域名 {} 的证书{detail}", c.subject),
        format!("证书{detail}"),
      )
    },
    ok: |c| {
      ev(
        format!("域名 {} 的证书已续期", c.subject),
        format!("证书还剩 {:.0} 天", c.value),
      )
    },
  },
  Rule {
    id: "link_cert_expiring",
    name: "隧道证书快到期",
    metric: "link_cert.days",
    op: Op::Lt,
    threshold: crate::link_cert::LEAF_ALERT_DAYS as f64,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Digest,
    key: |s| format!("link_cert.{s}"),
    fire: |c| {
      ev(
        format!("网关 {} 的隧道证书快到期", c.subject),
        format!("证书还剩 {:.0} 天", c.value),
      )
    },
    ok: |c| {
      ev(
        format!("网关 {} 的隧道证书已续期", c.subject),
        String::new(),
      )
    },
  },
  Rule {
    id: "link_ca_expiring",
    name: "隧道 CA 证书快到期",
    metric: "link_ca.days",
    op: Op::Lt,
    threshold: crate::link_cert::CA_WARN_DAYS as f64,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每分钟一次",
    period_secs: 60,
    default_level: AlertLevel::Digest,
    key: |_| "link_ca".into(),
    fire: |c| {
      ev(
        "集群隧道 CA 证书快到期".into(),
        format!("证书还剩 {:.0} 天", c.value),
      )
    },
    ok: |_| ev("集群隧道 CA 证书已续期".into(), String::new()),
  },
  Rule {
    id: "link_loss",
    name: "内网链路丢包",
    metric: "link.loss",
    op: Op::Ge,
    threshold: 20.0,
    threshold_editable: true,
    for_n: 3,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 5 分钟一次",
    period_secs: 300,
    default_level: AlertLevel::Urgent,
    key: |s| format!("link.{s}"),
    fire: |c| {
      let (from, to) =
        c.subject.split_once('>').unwrap_or((c.subject, ""));
      ev(
        format!("链路 {from} → {to} 丢包严重"),
        format!(
          "{from} 到 {to} 的内网地址连续 {} 轮丢包不低于 {:.0}%（最近一轮 {:.0}%），跨机器的网关转发、构建、备份都会受影响。看详情：wharf network",
          c.for_n, c.threshold, c.value
        ),
      )
    },
    ok: |c| {
      let (from, to) =
        c.subject.split_once('>').unwrap_or((c.subject, ""));
      ev(
        format!("链路 {from} → {to} 恢复"),
        format!("{from} 到 {to} 的内网地址丢包降到 {:.0}%", c.value),
      )
    },
  },
  Rule {
    id: "http_5xx",
    name: "服务 5xx 变多",
    metric: "req.err_pct_5m",
    op: Op::Gt,
    threshold: 10.0,
    threshold_editable: true,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: Some(2.0),
    every: "每分钟一次，最近 5 分钟合计",
    period_secs: 300,
    default_level: AlertLevel::Urgent,
    key: |s| format!("http5xx.{s}"),
    fire: |c| {
      ev(
        format!("服务 {} 的 5xx 变多", c.subject),
        format!(
          "最近 5 分钟经网关的请求里 {:.1}% 返回 5xx。看日志：wharf service logs {}",
          c.value, c.subject
        ),
      )
    },
    ok: |c| {
      ev(
        format!("服务 {} 的 5xx 已恢复", c.subject),
        format!("最近 5 分钟 5xx 占比 {:.1}%", c.value),
      )
    },
  },
  Rule {
    id: "host_unit_down",
    name: "宿主机程序停了",
    metric: "hostunit.running",
    op: Op::Lt,
    threshold: 1.0,
    threshold_editable: false,
    for_n: 1,
    mode: Mode::Consecutive,
    recover: None,
    every: "每 5 分钟一次",
    period_secs: 300,
    default_level: AlertLevel::Urgent,
    key: |s| {
      let (server, unit) = split_unit(s);
      format!("hostunit.{server}.{unit}")
    },
    fire: |c| {
      let (server, unit) = split_unit(c.subject);
      ev(
        format!("{server} 上的 {unit} 停了"),
        format!(
          "状态：{}。看日志：服务器 {server} → 宿主机程序",
          c.detail
        ),
      )
    },
    ok: |c| {
      let (server, unit) = split_unit(c.subject);
      ev(
        format!("{server} 上的 {unit} 恢复运行"),
        format!(
          "状态：{}。看日志：服务器 {server} → 宿主机程序",
          c.detail
        ),
      )
    },
  },
];
