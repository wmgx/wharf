//! 宿主机上 systemd 跑的、自己装的程序（只读）：启动命令、监听端口、配置位置，
//! 以及宿主机上的 Caddy / nginx / cloudflared 配置里转发到这些端口的域名。
//!
//! 和宿主机信息一样借 agent 自己的镜像起辅助容器：只读挂宿主机根目录，
//! 共享宿主机的 pid、网络、cgroup 命名空间，`chroot /host` 跑 systemctl、ss。

use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use wharf_api_types::{ApiError, agent::HostUnit};

use crate::{docker::Docker, exec::Ctx};

const TIMEOUT: Duration = Duration::from_secs(60);

const SCRIPT: &str = r#"
H="chroot /host"
for u in $($H systemctl list-units --type=service --all --plain --no-legend | awk '{print $1}'); do
  echo "@unit $u"
  $H systemctl show "$u" -p Description,ExecStart,WorkingDirectory,EnvironmentFiles,FragmentPath,User,ActiveState,SubState,ActiveEnterTimestamp,MemoryCurrent
done
echo "@ss"
$H ss -ltnpH
for p in $($H ss -ltnpH | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
  echo "@cg $p $(head -1 /proc/$p/cgroup 2>/dev/null)"
done
for f in $(for u in $($H systemctl list-units --type=service --plain --no-legend | awk '{print $1}'); do
    $H systemctl show "$u" -p ExecStart --value | grep -oE '(--config|-config|-c|--conf)[ =][^ ;]+' | sed -E 's/^[^ =]+[ =]//'
  done | sort -u); do
  case "$f" in /*) [ -f "/host$f" ] && [ "$(wc -c < "/host$f")" -lt 200000 ] && { echo "@file $f"; cat "/host$f"; echo; } ;; esac
done
for f in /host/etc/caddy/Caddyfile /host/etc/caddy/*.caddy /host/etc/nginx/sites-enabled/* /host/etc/nginx/conf.d/*.conf /host/etc/cloudflared/*.yml /host/etc/cloudflared/*.yaml; do
  [ -f "$f" ] && { echo "@file ${f#/host}"; cat "$f"; echo; }
done
echo "@end"
"#;

pub async fn list(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Vec<HostUnit>, ApiError> {
  let out = run(docker, SCRIPT, ctx).await?;
  Ok(parse(&out))
}

pub async fn logs(
  docker: &Docker,
  unit: &str,
  lines: u32,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  if !unit
    .bytes()
    .all(|c| c.is_ascii_alphanumeric() || b"@._-:".contains(&c))
    || unit.is_empty()
  {
    return Err(ApiError::invalid(format!("unit 名不合法：{unit}")));
  }
  let script = format!(
    "chroot /host journalctl -u '{unit}' -n {} --no-pager -o short-iso",
    lines.clamp(1, 2000)
  );
  run(docker, &script, ctx).await
}

async fn run(
  docker: &Docker,
  script: &str,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let image = crate::adopt::self_image(docker, ctx).await?;
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--pid",
      "host",
      "--network",
      "host",
      "--cgroupns",
      "host",
      // 看宿主机进程的监听端口要读别的进程的 fd；仍然只读挂载、不开特权。
      "--cap-add",
      "SYS_PTRACE",
      "--cap-add",
      "DAC_READ_SEARCH",
      "--security-opt",
      "apparmor=unconfined",
      "-v",
      "/:/host:ro",
      "--entrypoint",
      "sh",
    ])
    .args([image.as_str(), "-c", script])
    .timeout(TIMEOUT)
    .run(ctx)
    .await?
    .check("读取宿主机程序")?;
  Ok(out.stdout)
}

/// 自己装的：unit 文件在 /etc/systemd/system 下，或者是常见的网关。
fn interesting(unit: &str, file: &str) -> bool {
  let name = unit.trim_end_matches(".service");
  if GATEWAYS.contains(&name) {
    return true;
  }
  file.starts_with("/etc/systemd/system/")
    && !name.starts_with("dbus-")
    && !name.starts_with("snap.")
    && !SYSTEM.contains(&name)
}

const GATEWAYS: [&str; 4] =
  ["caddy", "nginx", "cloudflared", "haproxy"];
/// 发行版和常见基础组件，即使 unit 文件被复制到 /etc 也不算。
const SYSTEM: [&str; 12] = [
  "sshd",
  "ssh",
  "syslog",
  "display-manager",
  "docker",
  "containerd",
  "tailscaled",
  "chronyd",
  "ntp",
  "ntpd",
  "smartd",
  "wharf-agent",
];

fn parse(out: &str) -> Vec<HostUnit> {
  let mut units: BTreeMap<String, BTreeMap<String, String>> =
    BTreeMap::new();
  let mut listens: Vec<(String, Vec<u32>)> = Vec::new();
  let mut cgroup: BTreeMap<u32, String> = BTreeMap::new();
  let mut files: Vec<(String, String)> = Vec::new();
  let mut section = "";
  let mut cur_unit = String::new();
  for line in out.lines() {
    if let Some(u) = line.strip_prefix("@unit ") {
      section = "unit";
      cur_unit = u.trim().to_string();
      units.entry(cur_unit.clone()).or_default();
    } else if line == "@ss" {
      section = "ss";
    } else if let Some(rest) = line.strip_prefix("@cg ") {
      if let Some((pid, cg)) = rest.split_once(' ')
        && let Ok(pid) = pid.parse()
        && let Some(unit) = cg_unit(cg)
      {
        cgroup.insert(pid, unit);
      }
    } else if let Some(path) = line.strip_prefix("@file ") {
      section = "file";
      files.push((path.trim().to_string(), String::new()));
    } else if line == "@end" {
      section = "";
    } else {
      match section {
        "unit" => {
          if let Some((k, v)) = line.split_once('=') {
            units
              .entry(cur_unit.clone())
              .or_default()
              .insert(k.to_string(), v.to_string());
          }
        }
        "ss" => {
          let cols: Vec<&str> = line.split_whitespace().collect();
          if let Some(addr) = cols.get(3) {
            let pids = line
              .split("pid=")
              .skip(1)
              .filter_map(|p| {
                p.split(|c: char| !c.is_ascii_digit())
                  .next()?
                  .parse()
                  .ok()
              })
              .collect();
            listens.push((addr.to_string(), pids));
          }
        }
        "file" => {
          if let Some((_, body)) = files.last_mut() {
            body.push_str(line);
            body.push('\n');
          }
        }
        _ => {}
      }
    }
  }

  // unit → 监听地址
  let mut unit_listens: BTreeMap<String, BTreeSet<String>> =
    BTreeMap::new();
  for (addr, pids) in &listens {
    for pid in pids {
      if let Some(u) = cgroup.get(pid) {
        unit_listens
          .entry(u.clone())
          .or_default()
          .insert(addr.clone());
      }
    }
  }
  // 端口 → 域名，网关 → 它的配置和全部域名
  let mut port_hosts: BTreeMap<u32, BTreeSet<String>> =
    BTreeMap::new();
  let mut gw_hosts: BTreeMap<&str, (BTreeSet<String>, Vec<String>)> =
    BTreeMap::new();
  for (path, body) in &files {
    let (gw, pairs) = if path.starts_with("/etc/caddy/") {
      ("caddy", caddy_sites(body))
    } else if path.starts_with("/etc/nginx/") {
      ("nginx", nginx_sites(body))
    } else if path.starts_with("/etc/cloudflared/")
      || body.contains("ingress:")
    {
      ("cloudflared", cloudflared_sites(body))
    } else {
      continue;
    };
    let e = gw_hosts.entry(gw).or_default();
    e.1.push(path.clone());
    for (host, port) in pairs {
      e.0.insert(host.clone());
      if let Some(p) = port {
        port_hosts.entry(p).or_default().insert(host);
      }
    }
  }

  units
    .into_iter()
    .filter_map(|(unit, p)| {
      let file = p.get("FragmentPath").cloned().unwrap_or_default();
      let active =
        p.get("ActiveState").map(String::as_str).unwrap_or("");
      // 只看在跑的和失败的（停掉的一次性 unit 太多）。
      if !interesting(&unit, &file)
        || !matches!(active, "active" | "failed" | "activating")
      {
        return None;
      }
      let name = unit.trim_end_matches(".service");
      let listens: Vec<String> = unit_listens
        .get(&unit)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
      let command = exec_argv(
        p.get("ExecStart").map(String::as_str).unwrap_or(""),
      );
      // 启动参数里引用的 cloudflared 配置（例如 `--config /etc/x.yml`）。
      let own: Vec<&(String, String)> = files
        .iter()
        .filter(|(path, body)| {
          body.contains("ingress:")
            && command
              .split_whitespace()
              .any(|a| a.ends_with(path.as_str()))
        })
        .collect();
      let gw_entry = gw_hosts.get(name).cloned().or_else(|| {
        (!own.is_empty()).then(|| {
          (
            own
              .iter()
              .flat_map(|(_, body)| cloudflared_sites(body))
              .map(|(h, _)| h)
              .collect(),
            own.iter().map(|(p, _)| p.clone()).collect(),
          )
        })
      });
      let (domains, configs, gateway) = match gw_entry.as_ref() {
        Some((hosts, cfgs)) => {
          (hosts.iter().cloned().collect(), cfgs.clone(), true)
        }
        None => {
          let hosts: BTreeSet<String> = listens
            .iter()
            .filter_map(|a| a.rsplit_once(':')?.1.parse::<u32>().ok())
            .filter_map(|port| port_hosts.get(&port))
            .flatten()
            .cloned()
            .collect();
          (hosts.into_iter().collect(), Vec::new(), false)
        }
      };
      let env_files: Vec<String> = p
        .get("EnvironmentFiles")
        .map(|v| {
          v.split_whitespace()
            .filter(|s| s.starts_with('/'))
            .map(str::to_string)
            .collect()
        })
        .unwrap_or_default();
      let sub = p.get("SubState").cloned().unwrap_or_default();
      Some(HostUnit {
        description: p
          .get("Description")
          .cloned()
          .unwrap_or_default(),
        command,
        working_dir: p
          .get("WorkingDirectory")
          .filter(|v| !v.is_empty())
          .cloned(),
        user: p.get("User").filter(|v| !v.is_empty()).cloned(),
        unit_file: file,
        configs: configs
          .into_iter()
          .chain(env_files.iter().cloned())
          .collect(),
        env_files,
        state: if active == "failed" {
          "failed".into()
        } else {
          sub
        },
        since: p
          .get("ActiveEnterTimestamp")
          .filter(|v| !v.is_empty())
          .cloned(),
        memory: p.get("MemoryCurrent").and_then(|v| v.parse().ok()),
        listens,
        domains,
        gateway,
        unit,
      })
    })
    .collect()
}

/// `0::/system.slice/api.service` → `api.service`。
fn cg_unit(cg: &str) -> Option<String> {
  cg.rsplit('/')
    .find(|s| s.ends_with(".service"))
    .map(str::to_string)
}

/// systemctl show 的 ExecStart：`{ path=... ; argv[]=/usr/bin/x --a ; ... }`，取 argv。
fn exec_argv(v: &str) -> String {
  v.split("argv[]=")
    .nth(1)
    .and_then(|s| s.split(" ;").next())
    .unwrap_or(v)
    .trim()
    .to_string()
}

/// 上游写法里的端口：`127.0.0.1:8080`、`localhost:8080`、`:8080`、`http://x:8080/path`。
fn upstream_port(s: &str) -> Option<u32> {
  let s = s.split("://").last()?;
  let hostport = s.split('/').next()?;
  hostport.rsplit_once(':')?.1.parse().ok()
}

/// Caddyfile 顶层站点块：`a.com, b.com {` 里的 reverse_proxy。只认常见写法。
fn caddy_sites(body: &str) -> Vec<(String, Option<u32>)> {
  let mut out = Vec::new();
  let mut depth = 0i32;
  let mut hosts: Vec<String> = Vec::new();
  for raw in body.lines() {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
      continue;
    }
    if depth == 0 && line.ends_with('{') {
      hosts = line
        .trim_end_matches('{')
        .split([',', ' '])
        .map(|h| {
          h.trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
        })
        .map(|h| h.split(':').next().unwrap_or("").to_string())
        .filter(|h| h.contains('.') && !h.starts_with('('))
        .collect();
      if hosts.is_empty() {
        // 全局选项块 `{`、片段 `(name) {`
      }
    } else if depth >= 1
      && let Some(rest) = line.strip_prefix("reverse_proxy")
    {
      for up in rest
        .split_whitespace()
        .filter(|t| !t.starts_with('/') && *t != "{")
      {
        if let Some(p) = upstream_port(up) {
          for h in &hosts {
            out.push((h.clone(), Some(p)));
          }
        }
      }
    }
    depth += line.matches('{').count() as i32
      - line.matches('}').count() as i32;
    if depth == 0 {
      for h in hosts.drain(..) {
        if !out.iter().any(|(x, _)| *x == h) {
          out.push((h, None));
        }
      }
    }
  }
  out
}

/// nginx 的 server 块：server_name 和 proxy_pass。
fn nginx_sites(body: &str) -> Vec<(String, Option<u32>)> {
  let mut out = Vec::new();
  for block in body.split("server {").skip(1) {
    let names: Vec<String> = block
      .lines()
      .filter_map(|l| l.trim().strip_prefix("server_name"))
      .flat_map(|v| {
        v.trim_end_matches(';')
          .split_whitespace()
          .map(str::to_string)
          .collect::<Vec<_>>()
      })
      .filter(|h| h.contains('.'))
      .collect();
    let ports: Vec<u32> = block
      .lines()
      .filter_map(|l| l.split("proxy_pass").nth(1))
      .filter_map(|v| upstream_port(v.split(';').next()?.trim()))
      .collect();
    for n in &names {
      if ports.is_empty() {
        out.push((n.clone(), None));
      }
      for p in &ports {
        out.push((n.clone(), Some(*p)));
      }
    }
  }
  out
}

/// cloudflared 的 ingress：`- hostname: a.com` 后面跟 `service: http://localhost:8080`。
fn cloudflared_sites(body: &str) -> Vec<(String, Option<u32>)> {
  let mut out = Vec::new();
  let mut host: Option<String> = None;
  for line in body.lines() {
    let t = line.trim().trim_start_matches("- ").trim();
    if let Some(h) = t.strip_prefix("hostname:") {
      host = Some(h.trim().trim_matches('"').to_string());
    } else if let Some(s) = t.strip_prefix("service:")
      && let Some(h) = host.take()
    {
      out.push((h, upstream_port(s.trim().trim_matches('"'))));
    }
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_unit_ports_and_domains() {
    let out = "\
@unit api.service
Description=My API
ExecStart={ path=/opt/api/api ; argv[]=/opt/api/api --port 8080 ; ignore_errors=no }
WorkingDirectory=/opt/api
FragmentPath=/etc/systemd/system/api.service
ActiveState=active
SubState=running
EnvironmentFiles=/etc/api.env (ignore_errors=no)
@unit cron.service
FragmentPath=/lib/systemd/system/cron.service
ActiveState=active
SubState=running
@unit caddy.service
FragmentPath=/lib/systemd/system/caddy.service
ActiveState=active
SubState=running
@ss
LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"api\",pid=11,fd=3))
LISTEN 0 4096 *:443 *:* users:((\"caddy\",pid=22,fd=3))
@cg 11 0::/system.slice/api.service
@cg 22 0::/system.slice/caddy.service
@file /etc/caddy/Caddyfile
{
  email a@b.c
}
api.example.com, www.example.com {
  encode gzip
  reverse_proxy 127.0.0.1:8080
}
static.example.com {
  root * /srv/www
}
@end
";
    let v = parse(out);
    assert_eq!(v.len(), 2, "cron 不算自己装的");
    let api = v.iter().find(|u| u.unit == "api.service").unwrap();
    assert_eq!(api.command, "/opt/api/api --port 8080");
    assert_eq!(api.listens, vec!["127.0.0.1:8080"]);
    assert_eq!(
      api.domains,
      vec!["api.example.com", "www.example.com"]
    );
    assert_eq!(api.env_files, vec!["/etc/api.env"]);
    let caddy = v.iter().find(|u| u.unit == "caddy.service").unwrap();
    assert!(caddy.gateway);
    assert_eq!(caddy.domains.len(), 3);
  }

  #[test]
  fn cloudflared_and_nginx() {
    let cf = "ingress:\n  - hostname: a.example.com\n    service: http://localhost:3000\n  - service: http_status:404\n";
    assert_eq!(
      cloudflared_sites(cf),
      vec![("a.example.com".into(), Some(3000))]
    );
    let ng = "server {\n  server_name b.example.com;\n  location / { proxy_pass http://127.0.0.1:9000; }\n}\n";
    assert_eq!(
      nginx_sites(ng),
      vec![("b.example.com".into(), Some(9000))]
    );
  }
}
