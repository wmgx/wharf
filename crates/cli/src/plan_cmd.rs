use std::borrow::Cow;

use clap::Subcommand;
use wharf_api_types::plan::{Plan, PlanSummary, Run, StepStatus};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
  print,
};

#[derive(Subcommand)]
pub enum PlanCmd {
  /// 查看已生成的计划。
  Show {
    plan_id: String,
    #[arg(long)]
    brief: bool,
  },
  /// 列出近期计划。
  List {
    /// 只看尚未执行且未过期的计划。
    #[arg(long)]
    pending: bool,
    #[arg(long, default_value_t = 20)]
    limit: u32,
  },
}

pub fn brief_path(path: &str, brief: bool) -> Cow<'_, str> {
  if brief {
    Cow::Owned(format!("{path}?brief=1"))
  } else {
    Cow::Borrowed(path)
  }
}

pub async fn run(c: &Client, cmd: PlanCmd, j: bool) -> CliResult<()> {
  match cmd {
    PlanCmd::Show { plan_id, brief } => {
      let path = format!("/api/plans/{}", seg(&plan_id));
      let plan: Plan =
        c.get(brief_path(&path, brief).as_ref()).await?;
      out(j, &plan, print::plan);
    }
    PlanCmd::List { pending, limit } => {
      let plans: Vec<PlanSummary> = c
        .get(&format!("/api/plans?pending={pending}&limit={limit}"))
        .await?;
      out(j, &plans, |plans| {
        for plan in plans {
          println!(
            "{}  {:?}  剩余 {} 秒  {} 项  待确认 {}  {}  {}",
            plan.plan_id,
            plan.status,
            plan.expires_in_secs,
            plan.item_count,
            plan.needs_confirm.len(),
            plan.addresses.join("、"),
            plan.note.as_deref().unwrap_or_default(),
          );
        }
      });
    }
  }
  Ok(())
}

pub fn compact_run(run: &mut Run) {
  for step in &mut run.steps {
    if step.status == StepStatus::Done && step.log.len() > 5 {
      step.log = vec![format!("<omitted {} lines>", step.log.len())];
      step.log_truncated = true;
    }
  }
}
