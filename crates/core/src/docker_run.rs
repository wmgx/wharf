//! 把一条 `docker run` 命令转成服务配置草稿。
//!
//! 只用到端口、环境变量、数据卷、内存和 CPU 的转成镜像来源；用了启动命令、网络模式、
//! 宿主机文件这类镜像来源表达不了的，转成 compose 来源。不认识的参数列进提醒，不悄悄丢掉。

use std::{collections::BTreeMap, sync::Arc};

use axum::{Json, extract::State};
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  spec::{Limits, PortSpec, Source, VolumeSpec},
  view::{DockerRunRequest, Perm, ServiceDraft},
};

use crate::{
  api::ApiResult, auth::Auth, import, render, state::AppState,
};

pub async fn convert(
  State(_): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<DockerRunRequest>,
) -> ApiResult<ServiceDraft> {
  auth.require(Perm::Read)?;
  if let Some(name) = &req.name {
    wharf_api_types::validate_name("服务", name)?;
  }
  Ok(Json(from_docker_run(&req.command, req.name.as_deref())?))
}

/// 带值的参数里，转成 compose 字段的（compose 键，是否列表）。
const COMPOSE_VALUE_FLAGS: &[(&[&str], &str, bool)] = &[
  (&["--entrypoint"], "entrypoint", false),
  (&["-w", "--workdir"], "working_dir", false),
  (&["-u", "--user"], "user", false),
  (&["-h", "--hostname"], "hostname", false),
  (&["--cap-add"], "cap_add", true),
  (&["--cap-drop"], "cap_drop", true),
  (&["--device"], "devices", true),
  (&["--shm-size"], "shm_size", false),
  (&["--add-host"], "extra_hosts", true),
  (&["--security-opt"], "security_opt", true),
  (&["--tmpfs"], "tmpfs", true),
  (&["--sysctl"], "sysctls", true),
  (&["--dns"], "dns", true),
  (&["--pid"], "pid", false),
  (&["--ipc"], "ipc", false),
  (&["--stop-signal"], "stop_signal", false),
  (&["-l", "--label"], "labels", true),
];

/// 不带值、转成 compose 字段的参数。
const COMPOSE_BOOL_FLAGS: &[(&str, &str)] = &[
  ("--init", "init"),
  ("--privileged", "privileged"),
  ("--read-only", "read_only"),
];

/// 不影响结果、直接跳过的参数（Wharf 固定后台运行、自动重启）。
const IGNORED_BOOL: &[&str] = &[
  "-d",
  "--detach",
  "-i",
  "--interactive",
  "-t",
  "--tty",
  "--rm",
];
const IGNORED_VALUE: &[&str] = &["--restart", "--pull"];

/// 已知带值、但转不了的参数。
const UNSUPPORTED_VALUE: &[&str] = &[
  "--env-file",
  "--mount",
  "--link",
  "--volumes-from",
  "-a",
  "--attach",
  "--platform",
  "--log-driver",
  "--log-opt",
  "--memory-swap",
  "--memory-reservation",
  "-c",
  "--cpu-shares",
  "--cpuset-cpus",
  "--ip",
  "--network-alias",
  "--mac-address",
  "--expose",
  "--health-cmd",
  "--health-interval",
  "--health-timeout",
  "--health-retries",
  "--runtime",
  "--gpus",
  "--ulimit",
  "--pids-limit",
  "--stop-timeout",
  "--userns",
  "--cgroupns",
];

/// 宿主机上的这些路径是系统的东西（socket、设备、系统配置），原样挂载，不搬进数据目录。
const SYSTEM_PATHS: &[&str] = &[
  "/var/run", "/run", "/etc", "/dev", "/sys", "/proc", "/lib", "/usr",
];

#[derive(Default)]
struct Parsed {
  name: Option<String>,
  image: String,
  command: Vec<String>,
  ports: Vec<(Option<u16>, u16, bool)>,
  /// compose 来源用的原始端口写法。
  port_texts: Vec<String>,
  env: BTreeMap<String, String>,
  /// (数据卷名, 容器内路径, 只读)。
  volumes: Vec<(String, String, bool)>,
  /// 原样保留的宿主机挂载。
  binds: Vec<String>,
  limits: Limits,
  network: Option<String>,
  extra: Mapping,
  warnings: Vec<String>,
  unsupported: Vec<String>,
}

pub fn from_docker_run(
  command: &str,
  name: Option<&str>,
) -> Result<ServiceDraft, ApiError> {
  let words = split_words(command)?;
  let mut p = parse(&words)?;
  if let Some(name) = name {
    p.name = Some(name.to_string());
  }
  Ok(draft(p))
}

fn bad(msg: impl Into<String>) -> ApiError {
  ApiError::invalid(msg.into()).with_hint(
    "贴完整的一条命令，例如 docker run -d -p 8080:80 -v data:/data nginx",
  )
}

/// 按 shell 的规则拆词：单引号、双引号、反斜杠续行。
/// 单行输入框或聊天记录里换行被去掉后，续行符会变成 `\` 后跟空格，也按续行跳过。
fn split_words(s: &str) -> Result<Vec<String>, ApiError> {
  let mut words = Vec::new();
  let mut cur = String::new();
  let mut has = false;
  let mut chars = s.chars().peekable();
  while let Some(c) = chars.next() {
    match c {
      '\\' => {
        let mut ahead = chars.clone();
        let mut spaces = 0usize;
        while let Some(&n) = ahead.peek() {
          if n.is_whitespace() && !matches!(n, '\n' | '\r') {
            ahead.next();
            spaces += 1;
          } else {
            break;
          }
        }
        match ahead.peek() {
          // 续行：反斜杠后只有空白到换行或结尾（兼容行尾多余空格和 CRLF）。
          Some('\n' | '\r') | None => {
            for _ in 0..spaces {
              chars.next();
            }
            if matches!(chars.next(), Some('\r'))
              && chars.peek() == Some(&'\n')
            {
              chars.next();
            }
          }
          // 换行被去掉后的续行：独立的 `\` 后跟空格，或 `\` 后跟多个空格；
          // 单个 `\ ` 紧接字符（如 `-e A=foo\ bar`）仍保留为空格。
          Some(_) if spaces > 0 && (!has || spaces >= 2) => {}
          Some(_) => {
            if let Some(n) = chars.next() {
              cur.push(n);
              has = true;
            }
          }
        }
      }
      '\'' => {
        has = true;
        loop {
          match chars.next() {
            Some('\'') => break,
            Some(n) => cur.push(n),
            None => return Err(bad("命令里的单引号没有配对")),
          }
        }
      }
      '"' => {
        has = true;
        loop {
          match chars.next() {
            Some('"') => break,
            Some('\\') => match chars.next() {
              Some(n @ ('"' | '\\' | '$' | '`')) => cur.push(n),
              Some('\n') => {}
              Some('\r') => {
                if chars.peek() == Some(&'\n') {
                  chars.next();
                }
              }
              Some(n) => {
                cur.push('\\');
                cur.push(n);
              }
              None => return Err(bad("命令里的双引号没有配对")),
            },
            Some(n) => cur.push(n),
            None => return Err(bad("命令里的双引号没有配对")),
          }
        }
      }
      c if c.is_whitespace() => {
        if has {
          words.push(std::mem::take(&mut cur));
          has = false;
        }
      }
      c => {
        cur.push(c);
        has = true;
      }
    }
  }
  if has {
    words.push(cur);
  }
  Ok(words)
}

fn parse(words: &[String]) -> Result<Parsed, ApiError> {
  let mut i = 0;
  while i < words.len()
    && matches!(words[i].as_str(), "sudo" | "docker" | "podman")
  {
    i += 1;
  }
  if words.get(i).map(String::as_str) == Some("container") {
    i += 1;
  }
  match words.get(i).map(String::as_str) {
    Some("run" | "create") => i += 1,
    _ => return Err(bad("这不是一条 docker run 命令")),
  }
  let mut p = Parsed::default();
  while i < words.len() {
    let w = &words[i];
    i += 1;
    if w == "--" {
      break;
    }
    if !w.starts_with('-') || w == "-" {
      p.image = w.clone();
      p.command = words[i..].to_vec();
      break;
    }
    // `--flag=value` 和 `-pVALUE` 两种连写。
    let (flag, inline) = match w.split_once('=') {
      Some((f, v)) if f.starts_with("--") => {
        (f.to_string(), Some(v.to_string()))
      }
      _ if !w.starts_with("--") && w.len() > 2 => {
        let short = &w[..2];
        if takes_value(short) {
          (short.to_string(), Some(w[2..].to_string()))
        } else {
          // `-dit` 这类合在一起的开关，逐个处理。
          for c in w[1..].chars() {
            flag_bool(&mut p, &format!("-{c}"));
          }
          continue;
        }
      }
      _ => (w.clone(), None),
    };
    if !takes_value(&flag) {
      if inline.is_some() {
        p.unsupported.push(w.clone());
      } else {
        flag_bool(&mut p, &flag);
      }
      continue;
    }
    let value = match inline {
      Some(v) => v,
      None => {
        let v = words
          .get(i)
          .cloned()
          .ok_or_else(|| bad(format!("参数 {flag} 后面缺少值")))?;
        i += 1;
        v
      }
    };
    flag_value(&mut p, &flag, &value)?;
  }
  if p.image.trim().is_empty() {
    return Err(bad("命令里没有镜像名"));
  }
  Ok(p)
}

fn takes_value(flag: &str) -> bool {
  matches!(
    flag,
    "--name"
      | "-p"
      | "--publish"
      | "-e"
      | "--env"
      | "-v"
      | "--volume"
      | "-m"
      | "--memory"
      | "--cpus"
      | "--network"
      | "--net"
  ) || IGNORED_VALUE.contains(&flag)
    || UNSUPPORTED_VALUE.contains(&flag)
    || COMPOSE_VALUE_FLAGS.iter().any(|(f, ..)| f.contains(&flag))
}

fn flag_bool(p: &mut Parsed, flag: &str) {
  if IGNORED_BOOL.contains(&flag) {
    return;
  }
  if let Some((_, key)) =
    COMPOSE_BOOL_FLAGS.iter().find(|(f, _)| *f == flag)
  {
    p.extra.insert(yk(key), Value::Bool(true));
    return;
  }
  p.unsupported.push(flag.to_string());
}

fn flag_value(
  p: &mut Parsed,
  flag: &str,
  value: &str,
) -> Result<(), ApiError> {
  match flag {
    "--name" => p.name = Some(value.to_string()),
    "-p" | "--publish" => port(p, value),
    "-e" | "--env" => match value.split_once('=') {
      Some((k, v)) => {
        p.env.insert(k.to_string(), v.to_string());
      }
      None => {
        p.env.insert(value.to_string(), String::new());
        p.warnings.push(format!(
          "环境变量 {value} 原来取自宿主机，转过来是空值，要自己填"
        ));
      }
    },
    "-v" | "--volume" => volume(p, value),
    "-m" | "--memory" => {
      p.limits.memory_mb = Some(
        memory_mb(value)
          .filter(|&mb| mb >= 1.0)
          .map(|mb| mb.round() as u32)
          .ok_or_else(|| {
            bad(format!("内存上限 {value} 看不懂，写成 512m 或 1g"))
          })?,
      )
    }
    "--cpus" => {
      let cpus: f64 = value.parse().map_err(|_| {
        bad(format!("CPU 上限 {value} 看不懂，写成 0.5 这样的数字"))
      })?;
      p.limits.cpu_milli = Some((cpus * 1000.0).round() as u32);
    }
    "--network" | "--net" => match value {
      "bridge" | "default" => {}
      _ => p.network = Some(value.to_string()),
    },
    f if IGNORED_VALUE.contains(&f) => {}
    f if UNSUPPORTED_VALUE.contains(&f) => {
      p.unsupported.push(format!("{f} {value}"))
    }
    f => {
      let (_, key, list) = COMPOSE_VALUE_FLAGS
        .iter()
        .find(|(fs, ..)| fs.contains(&f))
        .expect("takes_value 和这里的列表一致");
      let v = literal(value);
      if *list {
        let entry = p
          .extra
          .entry(yk(key))
          .or_insert_with(|| Value::Sequence(vec![]));
        if let Value::Sequence(s) = entry {
          s.push(v);
        }
      } else {
        p.extra.insert(yk(key), v);
      }
    }
  }
  Ok(())
}

fn yk(s: &str) -> Value {
  Value::String(s.to_string())
}

/// `[ip:][宿主机端口:]容器端口[/协议]`。
fn port(p: &mut Parsed, value: &str) {
  let (body, proto) = match value.rsplit_once('/') {
    Some((b, proto)) => (b, proto),
    None => (value, "tcp"),
  };
  let parts: Vec<&str> = body.rsplitn(3, ':').collect();
  let container = parts[0].parse::<u16>().ok();
  let host = match parts.get(1) {
    Some(h) if !h.is_empty() => h.parse::<u16>().map(Some).ok(),
    _ => Some(None),
  };
  match (container, host, proto) {
    (Some(c), Some(h), "tcp" | "udp") => {
      p.ports.push((h, c, proto == "udp"));
      let binding = match parts.as_slice() {
        [_] => format!("127.0.0.1::{value}"),
        [_, _] => format!("127.0.0.1:{value}"),
        _ => {
          if matches!(parts[2], "0.0.0.0" | "[::]") {
            p.warnings
              .push(format!("端口 {value} 显式绑定到所有网卡"));
          }
          value.to_string()
        }
      };
      p.port_texts.push(binding);
    }
    _ => p.unsupported.push(format!("-p {value}")),
  }
}

fn volume(p: &mut Parsed, value: &str) {
  let parts: Vec<&str> = value.split(':').collect();
  let (src, dst, opts) = match parts.as_slice() {
    [dst] => (None, *dst, ""),
    [src, dst] => (Some(*src), *dst, ""),
    [src, dst, opts] => (Some(*src), *dst, *opts),
    _ => {
      p.unsupported.push(format!("-v {value}"));
      return;
    }
  };
  let ro = opts.split(',').any(|o| o == "ro");
  let host_path = src.filter(|s| {
    s.starts_with('/') || s.starts_with('.') || s.starts_with('~')
  });
  if let Some(src) = host_path
    && (src.ends_with(".sock")
      || SYSTEM_PATHS.iter().any(|sys| {
        src == *sys || src.starts_with(&format!("{sys}/"))
      }))
  {
    p.binds.push(value.to_string());
    p.warnings.push(format!(
      "挂载的宿主机路径 {src} 原样保留，换机器时要确认新机器上也有"
    ));
    return;
  }
  let base = src
    .unwrap_or(dst)
    .trim_end_matches('/')
    .rsplit('/')
    .next()
    .unwrap_or_default();
  let mut name = import::service_name(base);
  if name.is_empty() {
    name = "data".into();
  }
  let taken = |n: &str| p.volumes.iter().any(|(v, ..)| v == n);
  if taken(&name) {
    let mut k = 2;
    while taken(&format!("{name}-{k}")) {
      k += 1;
    }
    name = format!("{name}-{k}");
  }
  if let Some(src) = host_path {
    p.warnings.push(format!(
      "宿主机目录 {src} 换成了数据卷 {name}（/srv/<服务>/{name}），原来的数据要自己拷过去"
    ));
  }
  p.volumes.push((name, dst.to_string(), ro));
}

pub(crate) fn memory_mb(v: &str) -> Option<f64> {
  let v = v.trim().to_ascii_lowercase();
  let v = v
    .strip_suffix("ib")
    .or_else(|| v.strip_suffix('b'))
    .unwrap_or(&v);
  let (num, unit) = match v.char_indices().last()? {
    (i, c) if c.is_ascii_alphabetic() => (&v[..i], c),
    _ => (v, 'b'),
  };
  let n: f64 = num.parse().ok()?;
  let mb = match unit {
    'k' => n / 1024.0,
    'm' => n,
    'g' => n * 1024.0,
    'b' => n / 1024.0 / 1024.0,
    _ => return None,
  };
  (mb.is_finite() && mb > 0.0).then_some(mb)
}

/// 镜像名的最后一段，去掉标签和 digest：`ghcr.io/owner/app:1.0` → `app`。
fn name_from_image(image: &str) -> String {
  let last = image.rsplit('/').next().unwrap_or(image);
  let last = last.split('@').next().unwrap_or(last);
  import::service_name(last.split(':').next().unwrap_or(last))
}

fn draft(mut p: Parsed) -> ServiceDraft {
  let name = p
    .name
    .as_deref()
    .map(import::service_name)
    .filter(|n| !n.is_empty())
    .unwrap_or_else(|| name_from_image(&p.image));
  if !p.unsupported.is_empty() {
    p.warnings.push(format!(
      "这些参数没有转换，需要的话改成 compose 自己加：{}",
      p.unsupported.join("、")
    ));
  }
  if !p.env.is_empty() {
    p.warnings.push(
      "环境变量（可能含密码）以明文存进 Wharf，需要时改成 [[密钥名]] 引用"
        .into(),
    );
  }
  let limits = (p.limits.memory_mb.is_some()
    || p.limits.cpu_milli.is_some())
  .then(|| p.limits.clone());
  let needs_compose = !p.command.is_empty()
    || !p.extra.is_empty()
    || !p.binds.is_empty()
    || p.network.is_some()
    || p.volumes.iter().any(|(.., ro)| *ro);
  if !needs_compose {
    let single = p.ports.iter().filter(|(.., udp)| !udp).count() == 1;
    let ports = p
      .ports
      .iter()
      .map(|(host, container, udp)| PortSpec {
        name: if single && !udp {
          "http".into()
        } else if *udp {
          format!("u{container}")
        } else {
          format!("p{container}")
        },
        container: Some(*container),
        host: *host,
        udp: *udp,
      })
      .collect();
    return ServiceDraft {
      name,
      source: Source::Image(p.image),
      ports,
      env: p.env,
      volumes: p
        .volumes
        .into_iter()
        .map(|(name, target, _)| VolumeSpec { name, target })
        .collect(),
      limits,
      warnings: p.warnings,
    };
  }
  let compose = compose_text(&name, &p);
  ServiceDraft {
    ports: import::compose_ports(&compose),
    name,
    source: Source::Compose {
      content: Some(compose),
      file: None,
    },
    env: BTreeMap::new(),
    volumes: vec![],
    limits: None,
    warnings: p.warnings,
  }
}

/// compose 会对 `$` 做变量替换，原样保留要写成 `$$`。
fn literal(s: &str) -> Value {
  Value::String(s.replace('$', "$$"))
}

fn compose_text(name: &str, p: &Parsed) -> String {
  let mut svc = Mapping::new();
  svc.insert(yk("image"), yk(&p.image));
  svc.insert(yk("restart"), yk("unless-stopped"));
  if !p.command.is_empty() {
    svc.insert(
      yk("command"),
      Value::Sequence(p.command.iter().map(|c| literal(c)).collect()),
    );
  }
  for (k, v) in &p.extra {
    svc.insert(k.clone(), v.clone());
  }
  if !p.env.is_empty() {
    let env: Mapping =
      p.env.iter().map(|(k, v)| (yk(k), literal(v))).collect();
    svc.insert(yk("environment"), Value::Mapping(env));
  }
  if let Some(mb) = p.limits.memory_mb {
    svc.insert(yk("mem_limit"), yk(&format!("{mb}m")));
  }
  if let Some(milli) = p.limits.cpu_milli {
    svc.insert(yk("cpus"), yk(&render::cpus_text(milli)));
  }
  match p.network.as_deref() {
    Some(mode @ ("host" | "none")) => {
      svc.insert(yk("network_mode"), yk(mode));
    }
    Some(mode) if mode.starts_with("container:") => {
      svc.insert(yk("network_mode"), yk(mode));
    }
    _ => {}
  }
  if !p.port_texts.is_empty() && p.network.as_deref() != Some("host")
  {
    svc.insert(
      yk("ports"),
      Value::Sequence(p.port_texts.iter().map(|t| yk(t)).collect()),
    );
  }
  let mut volumes: Vec<Value> = p
    .volumes
    .iter()
    .map(|(v, target, ro)| {
      let ro = if *ro { ":ro" } else { "" };
      yk(&format!("{}:{target}{ro}", render::volume_dir(name, v)))
    })
    .collect();
  volumes.extend(p.binds.iter().map(|b| yk(b)));
  if !volumes.is_empty() {
    svc.insert(yk("volumes"), Value::Sequence(volumes));
  }
  let mut services = Mapping::new();
  services.insert(yk(name), Value::Mapping(svc));
  let mut root = Mapping::new();
  root.insert(yk("services"), Value::Mapping(services));
  let mut out = String::from("# 由 Wharf 从 docker run 命令转换。\n");
  out.push_str(&serde_yaml_ng::to_string(&root).unwrap_or_default());
  if let Some(net) = p.network.as_deref().filter(|n| {
    !matches!(*n, "host" | "none") && !n.starts_with("container:")
  }) {
    out.push_str(&format!(
      "# 原命令用了自定义网络 {net}，没有转换；要连别的服务用 [[@服务]] 引用。\n"
    ));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn simple_run_becomes_image_source() {
    let d = from_docker_run(
      "docker run -d --name My_App --restart=always \\\n  -p 8080:80 -e TZ=Asia/Shanghai -e 'PASS=a b$c' \\\n  -v /opt/app/data:/data -v cache:/cache -m 512m --cpus 0.5 nginx:1.27",
      None,
    )
    .unwrap();
    assert_eq!(d.name, "my-app");
    assert_eq!(d.source, Source::Image("nginx:1.27".into()));
    assert_eq!(d.ports.len(), 1);
    assert_eq!(d.ports[0].name, "http");
    assert_eq!(d.ports[0].container, Some(80));
    assert_eq!(d.ports[0].host, Some(8080));
    assert_eq!(d.env["PASS"], "a b$c");
    let vols: Vec<_> = d
      .volumes
      .iter()
      .map(|v| (v.name.as_str(), v.target.as_str()))
      .collect();
    assert_eq!(vols, [("data", "/data"), ("cache", "/cache")]);
    let limits = d.limits.unwrap();
    assert_eq!(
      (limits.memory_mb, limits.cpu_milli),
      (Some(512), Some(500))
    );
    assert!(d.warnings.iter().any(|w| w.contains("/opt/app/data")));
  }

  #[test]
  fn extra_options_become_compose_and_unknown_are_listed() {
    let d = from_docker_run(
      "docker run -dit --network host --cap-add NET_ADMIN -v /var/run/docker.sock:/var/run/docker.sock -e 'K=a$b' --env-file .env --weird ghcr.io/o/tool:2 serve --port 9000",
      None,
    )
    .unwrap();
    assert_eq!(d.name, "tool");
    let Source::Compose {
      content: Some(c), ..
    } = &d.source
    else {
      panic!("应该是 compose 来源");
    };
    let v: Value = serde_yaml_ng::from_str(c).unwrap();
    let svc = &v["services"]["tool"];
    assert_eq!(svc["network_mode"], yk("host"));
    assert_eq!(svc["cap_add"][0], yk("NET_ADMIN"));
    assert_eq!(svc["command"][2], yk("9000"));
    assert_eq!(svc["environment"]["K"], yk("a$$b"));
    assert!(d.env.is_empty());
    assert_eq!(
      svc["volumes"][0],
      yk("/var/run/docker.sock:/var/run/docker.sock")
    );
    let w = d.warnings.join("\n");
    assert!(w.contains("--env-file .env") && w.contains("--weird"));
  }

  #[test]
  fn handles_flattened_and_crlf_continuations() {
    let d = from_docker_run(
      "docker run -d \\   --restart always \\   --name anisette-v3 \\   -e HOME=/home/Alcoholic -e NOTE=a\\ b \\  \r\n  -p 6969:6969 \\   -v anisette-v3_data:/home/Alcoholic/.config/anisette-v3/lib/ \\   dadoum/anisette-v3-server",
      None,
    )
    .unwrap();
    assert_eq!(d.name, "anisette-v3");
    assert_eq!(
      d.source,
      Source::Image("dadoum/anisette-v3-server".into())
    );
    assert_eq!(d.ports.len(), 1);
    assert_eq!(d.ports[0].container, Some(6969));
    assert_eq!(d.ports[0].host, Some(6969));
    assert_eq!(d.env["HOME"], "/home/Alcoholic");
    assert_eq!(d.env["NOTE"], "a b");
    assert_eq!(d.volumes.len(), 1);
    assert_eq!(d.volumes[0].name, "anisette-v3-data");
    assert_eq!(
      d.volumes[0].target,
      "/home/Alcoholic/.config/anisette-v3/lib/"
    );
  }

  #[test]
  fn rejects_non_run_command() {
    assert!(from_docker_run("docker ps -a", None).is_err());
    assert!(from_docker_run("docker run -d -p 80:80", None).is_err());
  }
}

#[test]
fn compose_defaults_to_loopback_and_escapes_label() {
  let result = from_docker_run(
    "docker run -p 8080:80 --init -l foo=$bar nginx",
    None,
  )
  .unwrap();
  let Source::Compose {
    content: Some(content),
    ..
  } = result.source
  else {
    panic!("应该是 compose 来源");
  };
  let yaml: Value = serde_yaml_ng::from_str(&content).unwrap();
  let service = &yaml["services"]["nginx"];
  assert_eq!(service["ports"][0].as_str(), Some("127.0.0.1:8080:80"));
  assert_eq!(service["labels"][0].as_str(), Some("foo=$$bar"));
}
