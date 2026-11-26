async fn route(c: &Client, cmd: RouteCmd, j: bool) -> CliResult<()> {
  match cmd {
    RouteCmd::Logs(args) => {
      crate::access_logs::route(c, args, j).await
    }
    RouteCmd::DnsCheck { hostname } => {
      crate::external::dns(c, &hostname, j).await
    }
    RouteCmd::Note { host, args } => {
      let host =
        host.trim().trim_end_matches('.').to_ascii_lowercase();
      crate::note::run(c, "route", &host, args, j).await
    }
    RouteCmd::List => {
      let v: Vec<RouteView> = c.get("/api/routes").await?;
      out(j, &v, |v| {
        for r in v {
          println!(
            "{}  →  {}  经 {}{}",
            r.url,
            r.spec
              .redirect
              .as_deref()
              .or(r.spec.upstream.as_deref())
              .unwrap_or(&r.spec.service),
            r.gateway.as_deref().unwrap_or("-"),
            r.spec
              .expires_at
              .map(|ms| {
                if ms <= chrono::Utc::now().timestamp_millis() {
                  "（临时分享，已失效）".to_string()
                } else {
                  format!(
                    "（临时分享，{} 到期）",
                    chrono::DateTime::from_timestamp_millis(ms)
                      .unwrap()
                      .with_timezone(&chrono::Local)
                      .format("%m-%d %H:%M")
                  )
                }
              })
              .unwrap_or_default()
              + if r
                .spec
                .sso
                .as_ref()
                .is_some_and(|s| s.mode
                  == wharf_api_types::spec::SsoMode::Header)
              {
                "（门禁 · 传用户名）"
              } else if r.spec.sso.as_ref().is_some_and(|s| {
                s.mode == wharf_api_types::spec::SsoMode::Oidc
              }) {
                "（OIDC 登录）"
              } else if r.spec.sso.as_ref().is_some_and(|s| s.public)
              {
                "（公开 · 代登录入口）"
              } else if r.spec.sso.is_some() {
                "（门禁）"
              } else {
                ""
              }
          );
          if let Some(note) = &r.note {
            println!("    备注：{note}");
          }
          for p in &r.spec.paths {
            println!(
              "    {}  →  {}",
              p.path,
              p.upstream
                .as_deref()
                .or(p.service.as_deref())
                .unwrap_or("-")
            );
          }
        }
      });
      Ok(())
    }
    RouteCmd::Add {
      hostname,
      service,
      upstream,
      redirect,
      port,
      gateway,
      backup_gateway,
      auth,
      no_auth,
      paths,
      no_paths,
      tunnel,
      no_tunnel,
      internal,
      no_internal,
      protection,
      apply,
    } => {
      let host = hostname.trim().to_ascii_lowercase();
      let old = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| r.spec.hostname == host)
        .map(|r| r.spec);
      let args = RouteAddArgs {
        hostname,
        service,
        upstream,
        redirect,
        port,
        gateway,
        backup_gateway,
        auth: flag(auth, no_auth),
        paths: if no_paths {
          Some(vec![])
        } else if paths.is_empty() {
          None
        } else {
          Some(
            paths
              .iter()
              .map(|p| parse_path_route(p))
              .collect::<Result<_, _>>()?,
          )
        },
        tunnel: flag(tunnel, no_tunnel),
        internal: flag(internal, no_internal),
      };
      let mut spec = route_add_spec(old, args)?;
      protection.set(&mut spec);
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Sso {
      name,
      mode,
      skip,
      trust_internal,
      no_trust_internal,
      header,
      file,
      public,
      redirect,
      apply,
    } => {
      let route = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| r.spec.hostname == name.trim().to_ascii_lowercase())
        .ok_or_else(|| {
          ApiError::not_found(format!("域名 {name} 不存在"))
        })?;
      let mut spec = route.spec;
      let Some(mode) = mode else {
        if !j
          && let Some(sso) = &spec.sso
          && sso.mode == SsoMode::Login
          && let Some(login) = &sso.login
        {
          let accounts = if login.use_account {
            match c
              .get::<Vec<AppAccountView>>("/api/sso/accounts")
              .await
            {
              Ok(accounts) => Some(accounts),
              Err(CliError::Api(e))
                if e.code == ErrorCode::Forbidden =>
              {
                None
              }
              Err(e) => return Err(e),
            }
          } else {
            None
          };
          println!(
            "方式：代登录（{}）",
            if sso.public { "公开站点" } else { "门禁" }
          );
          println!(
            "入口：https://{}/_wharf/login → {}",
            spec.hostname,
            login.entry.as_deref().unwrap_or("/")
          );
          if let Some(script) = &login.script {
            let runtime = match script.runtime {
              ScriptRuntime::Python => "python",
              ScriptRuntime::Node => "node",
              ScriptRuntime::Shell => "shell",
            };
            println!(
              "登录：脚本（{runtime}，超时 {} 秒）",
              script.timeout_secs
            );
          } else {
            println!("登录：{} 步", login.steps.len());
          }
          if let Some(accounts) = accounts {
            if let Some(a) = accounts.iter().find(|a| {
              a.domains
                .iter()
                .any(|d| d.is_default && d.hostname == spec.hostname)
            }) {
              println!(
                "账号：使用默认账号 {}（{}）",
                a.name, a.username
              );
            } else {
              println!("账号：没有默认账号，代登录会失败");
            }
          }
          if let Some(takeover) = &login.takeover {
            let skip = if takeover.skip_query.is_empty() {
              String::new()
            } else {
              format!(
                "带 {} 参数时不接管，",
                takeover.skip_query.join("、")
              )
            };
            println!(
              "接管：{}（{skip}回退原生页 {} 分钟）",
              takeover.paths.join("、"),
              takeover.native_minutes
            );
          }
          if let Some(last) = &route.sso_login
            && let Some(at) =
              chrono::DateTime::from_timestamp_millis(last.at)
          {
            println!(
              "上次登录：{} {}",
              beijing_time(at),
              if last.ok { "成功" } else { "失败" }
            );
          }
          return Ok(());
        }
        out(j, &spec.sso, |sso| {
          println!(
            "{}",
            sso
              .as_ref()
              .map(|s| if s.mode == wharf_api_types::spec::SsoMode::Oidc {
                format!(
                  "用 Wharf 账号登录（OIDC）{}，看接入信息：wharf sso oidc {}",
                  if s.public { "，公开站点" } else { "，加门禁" },
                  spec.hostname
                )
              } else if s.public {
                format!(
                  "公开站点，代登录入口：https://{}/_wharf/login",
                  spec.hostname
                )
              } else {
                format!(
                  "门禁：已开启{}",
                  if s.skip_paths.is_empty() {
                    String::new()
                  } else {
                    format!("，排除 {}", s.skip_paths.join("、"))
                  }
                )
              })
              .unwrap_or_else(|| "门禁：没开".into())
          )
        });
        return Ok(());
      };
      spec.sso =
        (mode != "off").then_some(wharf_api_types::spec::SsoSpec {
          login: if mode == "login" {
            let file = file.ok_or_else(|| {
              ApiError::invalid("login 方式需要 --file")
            })?;
            let text = if file == "-" {
              std::io::read_to_string(std::io::stdin())
                .map_err(|_| ApiError::invalid("读取登录配置失败"))?
            } else {
              std::fs::read_to_string(file)
                .map_err(|_| ApiError::invalid("读取登录配置失败"))?
            };
            let value: serde_json::Value =
              serde_yaml_ng::from_str(&text).map_err(|_| {
                ApiError::invalid("登录配置不是有效的 YAML 或 JSON")
              })?;
            Some(serde_json::from_value(value).map_err(|_| {
              ApiError::invalid("登录配置字段不符合要求")
            })?)
          } else {
            if file.is_some() {
              return Err(
                ApiError::invalid("只有 login 方式才能用 --file")
                  .into(),
              );
            }
            None
          },
          oidc: if mode == "oidc" {
            if redirect.is_empty() {
              return Err(
                ApiError::invalid("oidc 方式至少要一个 --redirect")
                  .with_hint("回调路径看应用的 OIDC 文档，例如 Grafana 是 /login/generic_oauth")
                  .into(),
              );
            }
            Some(wharf_api_types::spec::OidcClientSpec {
              redirect_uris: redirect,
            })
          } else if !redirect.is_empty() {
            return Err(
              ApiError::invalid("只有 oidc 方式才能用 --redirect").into(),
            );
          } else {
            None
          },
          mode: if mode == "oidc" {
            wharf_api_types::spec::SsoMode::Oidc
          } else if mode == "login" {
            wharf_api_types::spec::SsoMode::Login
          } else if mode == "header" {
            wharf_api_types::spec::SsoMode::Header
          } else {
            wharf_api_types::spec::SsoMode::Gate
          },
          header,
          trust_internal: !public
            && !no_trust_internal
            && (trust_internal
              || spec.sso.as_ref().is_some_and(|s| s.trust_internal)),
          skip_paths: skip,
          public,
        });
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Guard {
      name,
      rate,
      no_rate,
      block,
      no_block,
      apply,
    } => {
      if rate.is_none() && !no_rate && !block && !no_block {
        return Err(
          ApiError::invalid(
            "至少给一个：--rate、--no-rate、--block、--no-block",
          )
          .into(),
        );
      }
      let mut spec = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| r.spec.hostname == name.trim().to_ascii_lowercase())
        .ok_or_else(|| {
          ApiError::not_found(format!("路由 {name} 不存在"))
            .suggest("wharf route list")
        })?
        .spec;
      if rate.is_some() || no_rate {
        spec.rate_limit = rate;
      }
      if block || no_block {
        spec.block_scanners = block;
      }
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Cert { name, retry } => {
      use wharf_api_types::view::{CertState, CertStatus};
      let path = format!("/api/routes/{}/cert", seg(name.trim()));
      if retry {
        let v: serde_json::Value = c
          .post_timeout(
            &format!("{path}/retry"),
            &serde_json::json!({}),
            std::time::Duration::from_secs(120),
          )
          .await?;
        out(j, &v, |v| {
          println!(
            "已让入口 {} 重新申请证书，1 到 3 分钟后执行 wharf route cert {name} 查看",
            v["gateway"].as_str().unwrap_or_default()
          );
        });
        return Ok(());
      }
      let st: CertStatus = c.get(&path).await?;
      let at = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(ms)
          .map(|t| {
            t.with_timezone(&chrono::Local)
              .format("%m-%d %H:%M:%S")
              .to_string()
          })
          .unwrap_or_default()
      };
      out(j, &st, |st| {
        let state = match st.state {
          CertState::Ok => "已签好",
          CertState::Obtaining => "申请中",
          CertState::Failed => "申请失败，网关会自动重试",
          CertState::Unknown => "最近的日志里没有申请记录",
        };
        println!("{}（入口 {}）：{state}", st.hostname, st.gateway);
        if let Some(t) = st.since {
          println!("  开始申请：{}", at(t));
        }
        if st.state == CertState::Failed || st.error.is_some() {
          if let Some(t) = st.failed_at {
            println!(
              "  上次失败：{}，已失败 {} 次",
              at(t),
              st.attempts
            );
          }
          if let Some(r) = &st.reason {
            println!("  原因：{r}");
          }
          if let Some(e) = &st.error {
            println!("  报错：{e}");
          }
        }
        if let Some(t) = st.next_retry_at {
          println!("  下次自动重试：{}", at(t));
        }
        if matches!(st.state, CertState::Failed | CertState::Unknown)
        {
          println!(
            "  立刻重试：wharf route cert {} --retry",
            st.hostname
          );
        }
      });
      Ok(())
    }
    RouteCmd::Caddy {
      name,
      file,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<Vec<RouteView>>("/api/routes")
        .await?
        .into_iter()
        .find(|r| r.spec.hostname == name.trim().to_ascii_lowercase())
        .ok_or_else(|| {
          ApiError::not_found(format!("路由 {name} 不存在"))
            .suggest("wharf route list")
        })?
        .spec;
      if file.is_none() && !off {
        out(j, &serde_json::json!({ "caddy": spec.caddy }), |_| {
          match &spec.caddy {
            Some(text) => print!("{text}"),
            None => println!("没有自定义配置"),
          }
        });
        return Ok(());
      }
      spec.caddy = match file {
        None => None,
        Some(path) => {
          let text = (if path == "-" {
            std::io::read_to_string(std::io::stdin())
          } else {
            std::fs::read_to_string(&path)
          })
          .map_err(|e| {
            ApiError::invalid(format!("读不了文件 {path}：{e}"))
              .with_hint("检查路径；从标准输入读用 --file -")
          })?;
          (!text.trim().is_empty()).then_some(text)
        }
      };
      changes(c, vec![Change::UpsertRoute { spec }], apply, j).await
    }
    RouteCmd::Rm { hostname, apply } => {
      changes(c, vec![Change::RemoveRoute { hostname }], apply, j)
        .await
    }
  }
}

/// `/ws=svc`、`/ws=svc:port`、`/ws=127.0.0.1:17891`。目标的主机部分带 `.`、`:` 或是
/// `localhost` 时当作上游地址（服务名里不会有这些）。
/// 一对开关参数：给了 `--x` 是 true，给了 `--no-x` 是 false，都没给是 None。
fn flag(on: bool, off: bool) -> Option<bool> {
  (on || off).then_some(on)
}

/// `wharf route add` 的参数；`None` 表示没给。
struct RouteAddArgs {
  hostname: String,
  service: Option<String>,
  upstream: Option<String>,
  redirect: Option<String>,
  port: Option<String>,
  gateway: Option<String>,
  backup_gateway: Option<String>,
  auth: Option<bool>,
  paths: Option<Vec<PathRoute>>,
  tunnel: Option<bool>,
  internal: Option<bool>,
}

/// 新建或修改路由：修改已有域名时只改给出的参数。
fn route_add_spec(
  old: Option<RouteSpec>,
  a: RouteAddArgs,
) -> CliResult<RouteSpec> {
  let retarget = a.service.is_some()
    || a.upstream.is_some()
    || a.redirect.is_some();
  let mut spec = match old {
    Some(old) => old,
    None if !retarget => {
      return Err(
        ApiError::invalid(
          "新域名要给 --service、--upstream 或 --redirect 之一",
        )
        .suggest(format!(
          "wharf route add {} --service <服务>",
          a.hostname
        ))
        .into(),
      );
    }
    None => RouteSpec {
      hostname: a.hostname.clone(),
      service: String::new(),
      upstream: None,
      port: None,
      gateway: None,
      backup_gateway: None,
      sso: None,
      auth: false,
      paths: vec![],
      caddy: None,
      link: Default::default(),
      redirect: None,
      rate_limit: None,
      block_scanners: false,
      internal: false,
      core_mesh_only: false,
      cf_origin_only: false,
      expires_at: None,
    },
  };
  spec.hostname = a.hostname;
  if retarget {
    let same_service =
      a.service.as_deref().is_some_and(|s| s == spec.service);
    if !same_service {
      spec.port = None;
    }
    spec.service = a.service.unwrap_or_default();
    spec.upstream = a.upstream;
    spec.redirect = a.redirect;
  }
  if spec.redirect.is_some() {
    // 跳转不允许这些。
    spec.paths.clear();
    spec.sso = None;
    spec.auth = false;
    spec.internal = false;
    spec.rate_limit = None;
    spec.block_scanners = false;
  }
  if a.port.is_some() {
    spec.port = a.port;
  }
  if a.gateway.is_some() {
    spec.gateway = a.gateway;
  }
  if let Some(b) = a.backup_gateway {
    spec.backup_gateway = (!b.is_empty()).then_some(b);
  }
  if let Some(v) = a.auth {
    spec.auth = v;
  }
  if let Some(v) = a.paths {
    spec.paths = v;
  }
  if let Some(v) = a.tunnel {
    spec.link = if v {
      wharf_api_types::spec::LinkMode::Tunnel
    } else {
      wharf_api_types::spec::LinkMode::Auto
    };
  }
  if let Some(v) = a.internal {
    spec.internal = v;
  }
  Ok(spec)
}

fn parse_path_route(arg: &str) -> CliResult<PathRoute> {
  let (path, target) = arg.split_once('=').ok_or_else(|| {
    ApiError::invalid(format!(
      "--path {arg} 要写成 路径=目标，例如 /ws=relay"
    ))
  })?;
  let (host, port) = match target.rsplit_once(':') {
    Some((h, p)) => (h, Some(p)),
    None => (target, None),
  };
  let address =
    host.contains('.') || host.contains(':') || host == "localhost";
  Ok(PathRoute {
    path: path.to_string(),
    service: (!address).then(|| host.to_string()),
    port: if address {
      None
    } else {
      port.map(str::to_string)
    },
    upstream: address.then(|| target.to_string()),
  })
}

// ACCOUNTS / SECRETS / TOKENS

fn print_account(a: &AccountView) {
  println!("{}（{}，token {}）", a.name, a.kind, a.token);
  println!(
    "  zone：{}",
    if a.zones.is_empty() {
      "无".into()
    } else {
      a.zones.join("、")
    }
  );
  for w in &a.warnings {
    println!("  提醒：{w}");
  }
}

async fn account(
  c: &Client,
  cmd: AccountCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    AccountCmd::List => {
      let v: Vec<AccountView> = c.get("/api/accounts").await?;
      out(j, &v, |v| v.iter().for_each(print_account));
      Ok(())
    }
    AccountCmd::Add { name, kind } => {
      let token = read_secret("Cloudflare API token：")?;
      let v: AccountView = c
        .post(
          "/api/accounts",
          &json!({ "name": name, "kind": kind, "token": token }),
        )
        .await?;
      out(j, &v, print_account);
      Ok(())
    }
    AccountCmd::Discover { name } => {
      let v: AccountView = c
        .post(
          &format!("/api/accounts/{}/discover", seg(&name)),
          &json!({}),
        )
        .await?;
      out(j, &v, print_account);
      Ok(())
    }
    AccountCmd::Rm { name } => {
      let v: Value =
        c.delete(&format!("/api/accounts/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除账号 {name}"));
      Ok(())
    }
  }
}

fn print_sso_test(result: &SsoTestResult) {
  for step in &result.steps {
    print_sso_step(&format!("第 {} 步", step.number), step);
  }
  if let Some(check) = &result.check {
    print_sso_step("检查  ", check);
  }
  if result.ok {
    println!("登录成功");
  }
  if !result.would_write.is_empty() {
    println!("会写入浏览器：");
    for summary in &result.would_write {
      println!("  {summary}");
    }
  }
  if let Some(log) = &result.script_log
    && !log.trim().is_empty()
  {
    println!("脚本输出：");
    for line in log.lines() {
      println!("  {line}");
    }
  }
  if !result.ok {
    let error = result
      .steps
      .iter()
      .chain(result.check.iter())
      .find_map(|step| step.error.as_deref());
    if let Some(error) = error {
      println!("登录失败：{error}");
    } else {
      println!("登录失败");
    }
  }
}

fn print_sso_step(label: &str, step: &SsoStepResult) {
  if step.method == "SCRIPT" {
    let status = if step.error.is_some() {
      "失败"
    } else {
      "成功"
    };
    println!("{label}  脚本  {status}  {}ms", step.ms);
  } else {
    let status = step
      .status
      .map_or_else(|| "未响应".into(), |code| code.to_string());
    print!(
      "{label}  {} {}  {status}  {}ms",
      step.method, step.path, step.ms
    );
    if !step.extracted.is_empty() {
      let extracted = step
        .extracted
        .iter()
        .map(|(name, n)| format!("{name}（{n} 个字符）"))
        .collect::<Vec<_>>();
      print!("  取到：{}", extracted.join("、"));
    }
    println!();
  }
}

fn beijing_time(at: chrono::DateTime<chrono::Utc>) -> String {
  at.with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
    .format("%m-%d %H:%M")
    .to_string()
}
