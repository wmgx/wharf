#[derive(Subcommand)]
pub enum TokenCmd {
  List,
  /// 只读推演，不会真的发出被推演的请求或修改数据。
  Explain {
    name: String,
    /// 要推演的服务。
    #[arg(long)]
    service: Option<String>,
    /// 假设请求来自这个 IP 地址。
    #[arg(long)]
    from: Option<String>,
    /// 要推演的 HTTP 方法，例如 GET。
    #[arg(long, requires = "path")]
    method: Option<String>,
    /// 要推演的请求路径，以 /api/ 开头。
    #[arg(long, requires = "method")]
    path: Option<String>,
  },
  /// 新建 token（只显示这一次）。给 AI 常用 `--perms plan,apply,exec`。
  Create {
    name: String,
    /// 权限点，逗号分隔：read、plan、apply、confirm、exec、host、admin（read 总是带上）。
    #[arg(
      long,
      conflicts_with = "scope",
      required_unless_present = "scope"
    )]
    perms: Option<String>,
    /// 旧档位预设：read、plan、apply_safe、apply_all。
    #[arg(long, value_parser = ["read", "plan", "apply_safe", "apply_all"])]
    scope: Option<String>,
    /// 有效期，例如 30m、12h、7d 或 2026-12-31。
    #[arg(long)]
    expires: Option<String>,
    /// 允许的来源地址或网段，逗号分隔。
    #[arg(long)]
    from: Option<String>,
    /// 允许操作的服务，逗号分隔。
    #[arg(long)]
    services: Option<String>,
  },
  /// 修改访问令牌的权限和限制。
  Set {
    name: String,
    /// 权限点，逗号分隔。
    #[arg(long)]
    perms: Option<String>,
    /// 有效期，例如 30m、12h、7d、2026-12-31，或用 never 清除。
    #[arg(long)]
    expires: Option<String>,
    /// 允许的来源地址或网段，逗号分隔，或用 any 清除。
    #[arg(long)]
    from: Option<String>,
    /// 允许操作的服务，逗号分隔，或用 all 清除。
    #[arg(long)]
    services: Option<String>,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
  Rm {
    name: String,
  },
}

#[tokio::main]
async fn main() {
  let mut cli = Cli::parse();
  if let Some(fields) = &cli.fields {
    print::set_fields(fields);
    cli.json = true;
  }
  if cli.page_size.is_some() || cli.changed {
    cli.json = true;
  }
  if let Some(reason) = &cli.reason {
    let _ = client::REASON.set(reason.clone());
  }
  let key: Vec<String> = std::env::args()
    .skip(1)
    .filter(|a| a != "--changed")
    .collect();
  view::set(
    cli.page_size.map(|size| (size, cli.page)),
    cli.changed.then_some(key.as_slice()),
  );
  let as_json = cli.json;
  let code = match commands::run(cli).await {
    Ok(()) => 0,
    Err(client::CliError::Exit(code)) => code,
    Err(client::CliError::Api(e)) => {
      print::error(&e, as_json);
      e.code.exit_code()
    }
  };
  std::process::exit(code);
}

#[derive(Subcommand)]
pub enum NotifyCmd {
  /// 给所有已配置的渠道发一条测试消息。
  Test,
  /// 通知地址：给自己的服务和脚本发通知用，`POST <地址>`，正文就是消息，
  /// 或者发 JSON `{"title": "...", "text": "..."}`。每个凭证每分钟最多 20 条。
  #[command(subcommand)]
  Key(NotifyKeyCmd),
}

#[derive(Subcommand)]
pub enum NotifyKeyCmd {
  /// 新建（同名已有时换新地址，旧地址失效）。地址存进密钥 `NOTIFY_URL_<名字>`，
  /// 服务的环境变量里写 `[[NOTIFY_URL_<名字>]]` 引用。
  Add {
    name: String,
    /// 把地址打印出来（地址就是凭证，给 Wharf 以外的脚本用时才需要）。
    #[arg(long)]
    show: bool,
  },
  List,
  /// 删除，地址立即失效，对应的密钥一起删。
  Rm {
    name: String,
  },
}

#[derive(Subcommand)]
pub enum EgressCmd {
  /// 设置控制面调厂商 API 经哪台出口（按那台的规则分流）；空字符串直连。
  Api { server: String },
  /// 列出预置分组和包含的域名。
  Presets,
}

#[derive(Subcommand)]
pub enum GateCmd {
  #[command(subcommand)]
  Key(GateKeyCmd),
}
#[derive(Subcommand)]
pub enum GateKeyCmd {
  Add {
    name: String,
    #[arg(long = "host", required = true)]
    hosts: Vec<String>,
  },
  List,
  Rm {
    name: String,
  },
}
