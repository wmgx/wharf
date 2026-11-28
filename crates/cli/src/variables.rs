use clap::Subcommand;
use wharf_api_types::spec::{Change, VarView};

use crate::{
  ApplyFlags,
  client::{CliResult, Client, seg},
  commands::{changes, out},
};

#[derive(Subcommand)]
pub enum VarCmd {
  List,
  Get {
    name: String,
  },
  Set {
    name: String,
    value: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  Rm {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

async fn get(c: &Client, name: &str, j: bool) -> CliResult<()> {
  let v: VarView = c.get(&format!("/api/vars/{}", seg(name))).await?;
  out(j, &v, |v| println!("{}={}", v.name, v.value));
  Ok(())
}

pub async fn run(c: &Client, cmd: VarCmd, j: bool) -> CliResult<()> {
  match cmd {
    VarCmd::List => {
      let vars: Vec<VarView> = c.get("/api/vars").await?;
      out(j, &vars, |vars| {
        for v in vars {
          println!("{}={}", v.name, v.value);
        }
      });
      Ok(())
    }
    VarCmd::Get { name } => get(c, &name, j).await,
    VarCmd::Set {
      name,
      value: None,
      apply,
    } => {
      apply.check_read_only()?;
      get(c, &name, j).await
    }
    VarCmd::Set {
      name,
      value: Some(value),
      apply,
    } => {
      changes(c, vec![Change::UpsertVar { name, value }], apply, j)
        .await
    }
    VarCmd::Rm { name, apply } => {
      changes(c, vec![Change::RemoveVar { name }], apply, j).await
    }
  }
}
