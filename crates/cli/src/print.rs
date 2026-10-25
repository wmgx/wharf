//! 给人看的输出。AI 用 `--json`，结构由 api-types 决定。

use wharf_api_types::{
  ApiError,
  plan::{Action, Plan, Risk, Run, RunStatus, RunStep, StepStatus},
  spec::NetworkMode,
  view::{BackupsView, NetworkView, ServiceView, Status},
};

pub fn json<T: serde::Serialize>(value: &T) {
  println!(
    "{}",
    serde_json::to_string_pretty(value)
      .unwrap_or_else(|_| "null".into())
  );
}

pub fn error(e: &ApiError, as_json: bool) {
  if as_json {
    json(e);
    return;
  }
  eprintln!("错误 [{}]：{}", e.code.as_str(), e.message);
  if let Some(hint) = &e.hint {
    eprintln!("提示：{hint}");
  }
  for s in &e.suggest {
    eprintln!("可以试试：{s}");
  }
}

fn symbol(action: Action) -> &'static str {
  match action {
    Action::Create => "+",
    Action::Update => "~",
    Action::Delete => "-",
    Action::Adopt => "!",
  }
}

fn layer(l: wharf_api_types::plan::Layer) -> String {
  serde_json::to_value(l)
    .ok()
    .and_then(|v| v.as_str().map(str::to_string))
    .unwrap_or_default()
}

/// `next_step`：是否打印"下一步"（加了 --apply 时不打印）。
pub fn plan_with(p: &Plan, next_step: bool) {
  if p.items.is_empty() {
    println!("没有变化，现实和配置一致。");
  } else {
    println!(
      "计划 {}（{} 项，{} 前有效）",
      p.plan_id,
      p.items.len(),
      p.expires_at.with_timezone(&chrono::Local).format("%H:%M")
    );
    let width = p
      .items
      .iter()
      .map(|i| i.address.chars().count())
      .max()
      .unwrap_or(0);
    for item in &p.items {
      let risk = match item.risk {
        Risk::Safe => String::new(),
        Risk::Disruptive => "  [会中断]".into(),
        Risk::Destructive => "  [破坏性，需确认]".into(),
        Risk::ExposesPublic => "  [公网暴露，需确认]".into(),
      };
      println!(
        "  {} {:<width$}  {:<9}  {}{risk}",
        symbol(item.action),
        item.address,
        layer(item.layer),
        item.reason,
      );
    }
  }
  for w in &p.warnings {
    println!("提醒：{w}");
  }
  if next_step {
    for s in &p.suggest {
      println!("下一步：{s}");
    }
  }
}

pub fn plan(p: &Plan) {
  plan_with(p, true);
}

fn step_mark(s: StepStatus) -> &'static str {
  match s {
    StepStatus::Pending => "…",
    StepStatus::Running => "▶",
    StepStatus::Done => "✓",
    StepStatus::Failed => "✗",
    StepStatus::Skipped => "·",
  }
}

pub fn step_line(step: &RunStep) {
  println!("{} {}", step_mark(step.status), step.title);
  if let Some(e) = &step.error {
    println!("    错误：{}", e.message);
    if let Some(h) = &e.hint {
      println!("    提示：{h}");
    }
    for s in &e.suggest {
      println!("    可以试试：{s}");
    }
  }
}

pub fn run_summary(run: &Run) {
  let status = match run.status {
    RunStatus::Running => "执行中",
    RunStatus::Succeeded => "成功",
    // 备份、恢复这类执行不来自计划，没有写入配置。
    RunStatus::Failed if run.plan_id.is_empty() => "失败",
    RunStatus::Failed => {
      "失败（配置已写入，执行 wharf plan 查看剩下的差异）"
    }
    RunStatus::Cancelled => "已取消",
  };
  println!("执行 {}：{status}", run.run_id);
}

pub fn run(run: &Run) {
  run_summary(run);
  for step in &run.steps {
    step_line(step);
    for line in &step.log {
      println!("    {line}");
    }
  }
}

fn live(s: &ServiceView) -> String {
  match &s.live {
    None => "-".into(),
    Some(l) => {
      let sync = match l.in_sync {
        Some(false) => "（和配置不一致）",
        _ => "",
      };
      format!("{}{sync}", l.state)
    }
  }
}

pub fn status(s: &Status) {
  println!("服务器");
  for srv in &s.servers {
    let state = if !srv.joined {
      "未加入"
    } else if srv.online {
      "在线"
    } else {
      "离线"
    };
    let report = srv.report.as_ref();
    let private = srv
      .private_addr
      .as_ref()
      .map(|a| format!("{}（{}）", a.ip, a.network.as_str()))
      .unwrap_or_else(|| "-".into());
    let disk = report
      .and_then(|r| r.disk)
      .map(|d| format!("{} / {}", gb(d.free), gb(d.total)))
      .unwrap_or_else(|| "-".into());
    println!(
      "  {:<10} {:<4}  内网 {:<24}  公网 {:<15}  docker {:<8}  磁盘剩 {disk}",
      srv.name,
      state,
      private,
      srv.public_ip.as_deref().unwrap_or("-"),
      report
        .and_then(|r| r.docker_version.as_deref())
        .unwrap_or("-"),
    );
  }
  if !s.services.is_empty() {
    println!("服务");
    for svc in &s.services {
      let addrs: Vec<String> = svc
        .addresses
        .iter()
        .map(|(p, a)| format!("{p}→{a}"))
        .collect();
      println!(
        "  {:<14} {:<8} {:<10} {}",
        svc.name,
        svc.spec.server,
        live(svc),
        addrs.join(" ")
      );
    }
  }
  if !s.gateways.is_empty() {
    println!("网关");
    for gw in &s.gateways {
      println!(
        "  {:<14} {:<8} {}{}  {}  路由 {}",
        gw.name,
        gw.spec.server,
        gw.spec.kind.as_str(),
        if gw.spec.default { "（默认）" } else { "" },
        gw.live.as_ref().map(|l| l.state.as_str()).unwrap_or("-"),
        gw.routes.len()
      );
    }
  }
  if !s.routes.is_empty() {
    println!("路由");
    for r in &s.routes {
      println!(
        "  {}  →  {}:{}  经 {}（上游 {}）",
        r.url,
        r.spec.service,
        r.spec.port.as_deref().unwrap_or("默认端口"),
        r.gateway.as_deref().unwrap_or("-"),
        r.upstream.as_deref().unwrap_or("-")
      );
    }
  }
  if !s.problems.is_empty() {
    println!("需要注意");
    for p in &s.problems {
      println!("  - {p}");
    }
  }
}

fn gb(bytes: u64) -> String {
  format!("{:.1}G", bytes as f64 / (1u64 << 30) as f64)
}

pub fn backups(v: &BackupsView) {
  let local = |t: &chrono::DateTime<chrono::Utc>| {
    t.with_timezone(&chrono::Local)
      .format("%m-%d %H:%M")
      .to_string()
  };
  match &v.target {
    Some(t) => println!("{}：每天备份到 {t}", v.service),
    None => println!("{}：没有开启自动备份", v.service),
  }
  if let Some(e) = &v.snapshots_error {
    println!("读取快照失败：{e}");
  }
  if !v.snapshots.is_empty() {
    println!("快照：");
    for s in &v.snapshots {
      println!(
        "  {}  {}  来自 {}",
        s.short_id,
        local(&s.time),
        s.hostname
      );
    }
  }
  if !v.records.is_empty() {
    println!("最近的备份：");
    for r in v.records.iter().take(5) {
      let detail = match (&r.summary, &r.error) {
        (Some(s), _) => format!(
          "成功  {} 个文件，新增 {} 字节",
          s.files, s.added_bytes
        ),
        (None, Some(e)) => format!("失败  {e}"),
        _ => if r.ok { "成功" } else { "失败" }.to_string(),
      };
      println!(
        "  {}  {} → {}  {detail}",
        local(&r.created_at),
        r.server,
        r.target
      );
    }
  }
}

pub fn doctor(v: &wharf_api_types::view::DoctorReport) {
  use wharf_api_types::view::{CheckStatus, DoctorCheck};
  let line = |c: &DoctorCheck| {
    let mark = match c.status {
      CheckStatus::Ok => "✓",
      CheckStatus::Warn => "!",
      CheckStatus::Bad => "✗",
      CheckStatus::Skip => "-",
    };
    println!("  {mark} {:<9} {}  {}", c.layer, c.subject, c.detail);
  };
  println!("服务器");
  v.servers.iter().for_each(line);
  for r in &v.routes {
    let first_bad =
      r.checks.iter().find(|c| c.status == CheckStatus::Bad);
    match first_bad {
      Some(c) => println!("\n{}  ✗ 先看 {}", r.hostname, c.layer),
      None => println!("\n{}", r.hostname),
    }
    r.checks.iter().for_each(line);
  }
  println!(
    "\n检查于 {}",
    v.checked_at
      .with_timezone(&chrono::Local)
      .format("%m-%d %H:%M:%S")
  );
}

pub fn core_backup(v: &serde_json::Value) {
  let Some(to) = v["to"].as_str() else {
    println!("控制面备份没有开启：wharf backup core --to <server>");
    return;
  };
  println!("控制面每天备份到 {to}");
  if !v["user_key_current"].as_bool().unwrap_or(false) {
    println!(
      "登录密码改过了，恢复口令还是旧密码：wharf backup core --to {to} 重新输入一次"
    );
  }
  for r in v["records"].as_array().into_iter().flatten().take(5) {
    let at = r["created_at"].as_str().unwrap_or("-");
    let detail = if r["ok"].as_bool().unwrap_or(false) {
      "成功".to_string()
    } else {
      format!("失败  {}", r["error"].as_str().unwrap_or(""))
    };
    println!("  {at}  {detail}");
  }
  if let Some(cmd) = v["restore_command"].as_str() {
    println!(
      "\n控制面整个丢了时：新机器先加入同一个内网，执行下面的命令并输入登录密码，文件会恢复到 /var/lib/wharf-core，再启动控制面："
    );
    println!("{cmd}");
  }
}

pub fn network(v: &NetworkView) {
  for s in &v.servers {
    let mode = match s.mode {
      NetworkMode::Tailscale => "tailscale",
      NetworkMode::Lan => "lan",
      NetworkMode::Public => "public",
    };
    println!(
      "{:<10} {:<9}{} 内网 {:<16} 公网 {:<16} {}",
      s.name,
      mode,
      if s.configured { "*" } else { " " },
      s.private_ip.as_deref().unwrap_or("-"),
      s.public_ip.as_deref().unwrap_or("-"),
      if s.online { "在线" } else { "离线" }
    );
  }
  if v.reach.is_empty() {
    println!("\n还没有探测过，wharf network --probe");
    return;
  }
  println!("\n谁能连谁的内网地址：");
  for r in &v.reach {
    println!(
      "  {} → {}  {}  ({})",
      r.from,
      r.to,
      if r.ok { "通" } else { "不通" },
      r.checked_at
        .with_timezone(&chrono::Local)
        .format("%m-%d %H:%M")
    );
  }
}
