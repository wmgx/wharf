fn app_account_domains(account: &AppAccountView) -> String {
  account
    .domains
    .iter()
    .map(|d| {
      format!(
        "{}{}{}",
        d.hostname,
        if d.is_default { "（默认）" } else { "" },
        if d.exists {
          ""
        } else {
          "（域名不存在）"
        }
      )
    })
    .collect::<Vec<_>>()
    .join("、")
}

fn print_app_account(
  account: &AppAccountView,
  name_width: usize,
  username_width: usize,
) {
  let domains = app_account_domains(account);
  let domains = if domains.is_empty() {
    "没有关联域名"
  } else {
    &domains
  };
  println!(
    "{:<name_width$}  {:<username_width$}  {domains}  {}",
    account.name,
    account.username,
    beijing_time(account.updated_at)
  );
  let mut lines = account.note.lines();
  if let Some(first) = lines.next() {
    let indent = " ".repeat(name_width + 2);
    println!("{indent}备注：{first}");
    for line in lines {
      println!("{indent}      {line}");
    }
  }
}

async fn app_account(
  c: &Client,
  cmd: AppAccountCmd,
  j: bool,
) -> CliResult<()> {
  let path = |name: &str| format!("/api/sso/accounts/{}", seg(name));
  let domains = |name: &str, hostname: &str| {
    format!("{}/domains/{}", path(name), seg(hostname))
  };
  let print_single = |a: &AppAccountView| {
    print_app_account(a, a.name.len(), a.username.chars().count())
  };
  match cmd {
    AppAccountCmd::List => {
      let accounts: Vec<AppAccountView> =
        c.get("/api/sso/accounts").await?;
      out(j, &accounts, |accounts| {
        if accounts.is_empty() {
          println!(
            "还没有应用账号，用 wharf sso account set <名称> 添加"
          );
          return;
        }
        let name_width = accounts
          .iter()
          .map(|a| a.name.len())
          .max()
          .unwrap_or_default();
        let username_width = accounts
          .iter()
          .map(|a| a.username.chars().count())
          .max()
          .unwrap_or_default();
        for account in accounts {
          print_app_account(account, name_width, username_width);
        }
      });
    }
    AppAccountCmd::Set {
      name,
      user,
      note,
      keep_password,
    } => {
      let password = if keep_password {
        None
      } else {
        Some(read_secret("应用账号密码：")?)
      };
      let account: AppAccountView = c.put(&path(&name), &json!({"username": user, "password": password, "note": note})).await?;
      out(j, &account, |account| {
        println!("已保存应用账号 {}", account.name)
      });
    }
    AppAccountCmd::Show { name, reveal } => {
      let account: AppAccountView = c.get(&path(&name)).await?;
      if reveal {
        #[derive(serde::Deserialize)]
        struct Password {
          password: String,
        }
        let wharf_password =
          rpassword::prompt_password("Wharf 登录密码：").map_err(
            |_| ApiError::invalid("需要在终端输入 Wharf 登录密码"),
          )?;
        let Password { password } = c
          .post(
            &format!("{}/password", path(&name)),
            &json!({"password": wharf_password}),
          )
          .await?;
        if j {
          #[derive(serde::Serialize)]
          struct Revealed<'a> {
            #[serde(flatten)]
            account: &'a AppAccountView,
            password: String,
          }
          print::json(&Revealed {
            account: &account,
            password,
          });
        } else {
          print_single(&account);
          println!("{password}");
        }
      } else {
        out(j, &account, print_single);
      }
    }
    AppAccountCmd::Rm { name } => {
      let result: Value = c.delete(&path(&name)).await?;
      out(j, &result, |_| println!("已删除应用账号 {name}"));
    }
    AppAccountCmd::Link {
      name,
      hostname,
      default,
    } => {
      let account: AppAccountView = c
        .put(
          &domains(&name, &hostname),
          &json!({"is_default": default}),
        )
        .await?;
      out(j, &account, print_single);
    }
    AppAccountCmd::Unlink { name, hostname } => {
      let account: AppAccountView =
        c.delete(&domains(&name, &hostname)).await?;
      out(j, &account, print_single);
    }
  }
  Ok(())
}

/// 密钥预览：不读也不显示值，只说新建、覆盖还是删除，以及谁在用。
async fn secret_preview(
  c: &Client,
  name: &str,
  deleting: bool,
  j: bool,
) -> CliResult<()> {
  let list: Vec<SecretView> = c.get("/api/secrets").await?;
  let before = list
    .iter()
    .find(|s| s.name == name)
    .map(|s| json!({"name": s.name, "used_by": s.used_by, "value": "（旧值）"}))
    .unwrap_or(Value::Null);
  if deleting && before.is_null() {
    return Err(
      ApiError::not_found(format!("密钥 {name} 不存在")).into(),
    );
  }
  let after = if deleting {
    Value::Null
  } else {
    json!({"name": name, "used_by": before["used_by"], "value": "（新值）"})
  };
  crate::preview::show(j, &format!("secret/{name}"), &before, &after)
}

async fn secret(
  c: &Client,
  cmd: SecretCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    SecretCmd::List => {
      let v: Vec<SecretView> = c.get("/api/secrets").await?;
      out(j, &v, |v| v.iter().for_each(|s| println!("{}", s.name)));
      Ok(())
    }
    SecretCmd::Set {
      name,
      dry_run: true,
    } => secret_preview(c, &name, false, j).await,
    SecretCmd::Rm {
      name,
      dry_run: true,
    } => secret_preview(c, &name, true, j).await,
    SecretCmd::Set { name, .. } => {
      let prompt = if name.starts_with("BASIC_AUTH_") {
        "登录保护账号（用户名:密码）：".to_string()
      } else {
        format!("{name} 的值：")
      };
      let value = read_secret(&prompt)?;
      let v: SecretView = c
        .put(
          &format!("/api/secrets/{}", seg(&name)),
          &json!({ "value": value }),
        )
        .await?;
      out(j, &v, |v| println!("已设置密钥 {}", v.name));
      Ok(())
    }
    SecretCmd::Rm { name, .. } => {
      let v: Value =
        c.delete(&format!("/api/secrets/{}", seg(&name))).await?;
      out(j, &v, |_| println!("已删除密钥 {name}"));
      Ok(())
    }
  }
}

async fn backup(
  c: &Client,
  cmd: BackupCmd,
  j: bool,
) -> CliResult<()> {
  let set_backup = |name: String, backup: Option<BackupSpec>| async move {
    let mut spec = c
      .get::<ServiceView>(&format!("/api/services/{}", seg(&name)))
      .await?
      .spec;
    spec.backup = backup;
    Ok::<_, CliError>(Change::UpsertService {
      name,
      spec,
      adopt: None,
    })
  };
  match cmd {
    BackupCmd::Enable { service, to, apply } => {
      let change =
        set_backup(service, Some(BackupSpec { to })).await?;
      changes(c, vec![change], apply, j).await
    }
    BackupCmd::Disable { service, apply } => {
      let change = set_backup(service, None).await?;
      changes(c, vec![change], apply, j).await
    }
    BackupCmd::Run { service, no_wait } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/backups", seg(&service)),
          &json!({}),
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
    BackupCmd::Core { to: Some(to), .. } => {
      let password = read_secret("登录密码（会成为恢复口令）：")?;
      let r: ApplyResponse = c
        .post(
          "/api/core-backup",
          &json!({ "to": to, "password": password }),
        )
        .await?;
      finish_task(c, &r.run_id, true, j).await
    }
    BackupCmd::Core { run: true, .. } => {
      let r: ApplyResponse =
        c.post("/api/core-backup/run", &json!({})).await?;
      finish_task(c, &r.run_id, true, j).await
    }
    BackupCmd::Core { .. } => {
      let v: Value = c.get("/api/core-backup").await?;
      out(j, &v, print::core_backup);
      Ok(())
    }
    BackupCmd::List { service } => {
      let v: BackupsView = c
        .get(&format!("/api/services/{}/backups", seg(&service)))
        .await?;
      out(j, &v, print::backups);
      Ok(())
    }
    BackupCmd::Restore {
      service,
      snapshot,
      confirm,
      no_wait,
    } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/services/{}/restore", seg(&service)),
          &RestoreRequest {
            snapshot,
            confirm: confirm.unwrap_or_default(),
          },
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
  }
}

/// 单独发起的执行（备份、恢复）：等它结束，或者只给出 run_id。
pub(crate) async fn finish_task(
  c: &Client,
  run_id: &str,
  wait: bool,
  j: bool,
) -> CliResult<()> {
  if !wait {
    out(j, &json!({ "run_id": run_id }), |_| {
      println!(
        "已开始执行 {run_id}，查看进度：wharf run wait {run_id}"
      )
    });
    return Ok(());
  }
  let run = wait_run(c, run_id, j).await?;
  out(j, &run, print::run_summary);
  match run.status {
    RunStatus::Succeeded => Ok(()),
    _ => Err(CliError::Exit(4)),
  }
}

/// `--egress`：`off` 关闭，`all` 全部走，否则逗号分隔的预置分组名和域名。
fn parse_egress(
  v: &str,
) -> Result<Option<wharf_api_types::egress::EgressSpec>, CliError> {
  let v = v.trim();
  if v.is_empty() || v == "off" {
    return Ok(None);
  }
  let mut spec = wharf_api_types::egress::EgressSpec::default();
  for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
    match part {
      "all" => spec.all = true,
      p if p.contains('.') => spec.domains.push(p.to_lowercase()),
      p => spec.presets.push(p.to_string()),
    }
  }
  spec.validate().map_err(ApiError::invalid)?;
  Ok(Some(spec))
}

fn share_ttl(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let (num, unit) = s.split_at(
    s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()),
  );
  let n: u64 = num.parse().map_err(|_| format!("时长写错了：{s}"))?;
  let factor = match unit {
    "s" => 1,
    "" | "m" => 60,
    "h" => 3600,
    "d" => 86400,
    _ => return Err(format!("时长单位只能是 s、m、h、d：{s}")),
  };
  let secs = n
    .checked_mul(factor)
    .filter(|n| (60..=7 * 86400).contains(n))
    .ok_or("时长要在 1 分钟到 7 天之间")?;
  Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::Parser;

  #[test]
  fn route_add_keeps_unspecified_fields() {
    let old: RouteSpec = serde_json::from_value(serde_json::json!({
      "hostname": "a.example.com",
      "service": "blog",
      "sso": {"mode": "gate"},
      "paths": [{"path": "/ws", "upstream": "127.0.0.1:1"}]
    }))
    .unwrap();
    let spec = route_add_spec(
      Some(old),
      RouteAddArgs {
        hostname: "a.example.com".into(),
        service: None,
        upstream: None,
        redirect: None,
        port: None,
        gateway: None,
        backup_gateway: Some("edge2".into()),
        auth: None,
        paths: None,
        tunnel: None,
        internal: None,
      },
    )
    .unwrap_or_else(|_| panic!("应当成功"));
    assert_eq!(spec.backup_gateway.as_deref(), Some("edge2"));
    assert!(spec.sso.is_some());
    assert_eq!(spec.paths.len(), 1);
    assert_eq!(spec.service, "blog");
  }

  #[test]
  fn ports() {
    let p = parse_port("http=80").unwrap();
    assert_eq!(
      (p.name.as_str(), p.container, p.host),
      ("http", Some(80), None)
    );
    let p = parse_port("http=80:20080").unwrap();
    assert_eq!((p.container, p.host), (Some(80), Some(20080)));
    let p = parse_port("http=:41773").unwrap();
    assert_eq!((p.container, p.host), (None, Some(41773)));
    assert!(parse_port("http").is_err());
    assert!(parse_port("http=x").is_err());
  }

  #[test]
  fn exec_keeps_one_command_string() {
    let cli = Cli::try_parse_from([
      "wharf",
      "exec",
      "s1",
      "--",
      "printf '%s' hello",
    ])
    .unwrap();
    let Command::Exec { command, .. } = cli.command else {
      panic!("不是 exec");
    };
    assert_eq!(command, "printf '%s' hello");
    assert_eq!(command_summary("a\x1b[31m"), r"a\u{1b}[31m");
    assert!(
      Cli::try_parse_from(["wharf", "exec", "s1", "--", "a", "b"])
        .is_err()
    );
  }
}
