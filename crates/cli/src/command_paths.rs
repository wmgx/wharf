use std::ffi::OsStr;

use clap::{ArgMatches, Command, CommandFactory, FromArgMatches};

use crate::Cli;

// 所有迁移只增加一级分组，原命令名和子树不变。
pub const MOVES: &[(&str, &str)] = &[
  ("top", "inspect"),
  ("report", "inspect"),
  ("metrics", "inspect"),
  ("audit", "inspect"),
  ("refs", "inspect"),
  ("tree", "inspect"),
  ("search", "inspect"),
  ("lint", "inspect"),
  ("upgrade", "ops"),
  ("self-update", "ops"),
  ("whoami", "ops"),
  ("core", "ops"),
  ("notify", "ops"),
  ("alert", "ops"),
  ("account", "ops"),
  ("bookmark", "ops"),
  ("task", "ops"),
  ("token", "ops"),
  ("egress", "network"),
  ("external", "network"),
  ("connect", "network"),
  ("sso", "network"),
  ("gate", "network"),
  ("edge", "network"),
  ("backup", "data"),
  ("defaults", "config"),
  ("var", "config"),
  ("export", "plan"),
  ("import", "plan"),
  ("validate", "plan"),
  ("exec", "server"),
  ("shell-log", "server"),
  ("share", "route"),
];

pub fn group(name: &str) -> Option<&'static str> {
  MOVES
    .iter()
    .find_map(|&(old, group)| (old == name).then_some(group))
}

pub fn business_path<'a, 'b>(path: &'a [&'b str]) -> &'a [&'b str] {
  match path {
    [parent, name, ..] if group(name) == Some(*parent) => &path[1..],
    _ => path,
  }
}

pub fn app() -> Command {
  let legacy = Cli::command();
  let app = legacy
    .clone()
    .mut_subcommands(|sub| {
      let hidden = group(sub.get_name()).is_some();
      sub.hide(hidden)
    })
    .subcommand(
      Command::new("inspect")
        .about("资源、审计和配置检查。")
        .subcommand_required(true)
        .arg_required_else_help(true),
    )
    .subcommand(
      Command::new("ops")
        .about("控制面维护、任务和访问管理。")
        .subcommand_required(true)
        .arg_required_else_help(true),
    );
  MOVES.iter().fold(app, |app, &(name, parent)| {
    let mut sub =
      legacy.find_subcommand(name).expect("旧命令").clone();
    if name == "backup" {
      sub = sub.mut_subcommands(|child| {
        let hidden =
          matches!(child.get_name(), "migrate" | "cleanup-legacy");
        child.hide(hidden)
      });
    }
    app.mut_subcommand(parent, |group| group.subcommand(sub))
  })
}

pub fn matched_path(mut matches: &ArgMatches) -> Vec<&str> {
  let mut path = Vec::new();
  while let Some((name, child)) = matches.subcommand() {
    path.push(name);
    matches = child;
  }
  path
}

fn legacy_diagnostic_tree() -> Command {
  // 旧 schema 只接受一个类型名，Clap 会用其他子命令的参数生成纠错提示。
  Cli::command().mut_subcommand("schema", |schema| {
    Command::new("schema")
      .args(
        schema
          .get_arguments()
          .filter(|arg| arg.get_id() != "command_query")
          .cloned(),
      )
      .mut_arg("resource", |arg| {
        arg.num_args(1).action(clap::ArgAction::Set)
      })
  })
}

pub fn parse(
  app: &Command,
  argv: &[impl AsRef<OsStr>],
) -> Result<(Cli, ArgMatches), clap::Error> {
  use clap::error::{ContextKind, ContextValue, ErrorKind};

  let args = || argv.iter().map(AsRef::as_ref);
  let matches =
    app.clone().try_get_matches_from(args()).or_else(|error| {
      if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
      ) {
        return Err(error);
      }
      let legacy = legacy_diagnostic_tree();
      let probe = legacy.clone().ignore_errors(true);
      let is_old = |matches: ArgMatches| {
        matches.subcommand_name().and_then(group).is_some()
      };
      if probe.clone().try_get_matches_from(args()).is_ok_and(is_old)
      {
        return legacy.try_get_matches_from(args());
      }
      // 仅探测命令路径，原始参数仍交给旧树生成诊断。
      if error.kind() == ErrorKind::UnknownArgument
        && let Some(ContextValue::String(flag)) =
          error.get(ContextKind::InvalidArg)
        && let Some(index) =
          args().enumerate().skip(1).find_map(|(i, arg)| {
            let arg = arg.to_str()?.split('=').next()?;
            (arg == flag).then_some(i)
          })
        && probe
          .try_get_matches_from(
            args()
              .enumerate()
              .filter(|(i, _)| *i != index)
              .map(|(_, arg)| arg),
          )
          .is_ok_and(is_old)
      {
        return legacy.try_get_matches_from(args());
      }
      Err(error)
    })?;
  let cli = decode(app, &matches)?;
  Ok((cli, matches))
}

fn decode(
  app: &Command,
  matches: &ArgMatches,
) -> Result<Cli, clap::Error> {
  if let Some((parent, nested)) = matches.subcommand()
    && nested.subcommand_name().and_then(group) == Some(parent)
  {
    let node = app.find_subcommand(parent).expect("已解析的分组");
    if node.get_arguments().any(|arg| {
      !arg.is_global_set()
        && nested.value_source(arg.get_id().as_str())
          == Some(clap::parser::ValueSource::CommandLine)
    }) {
      return Err(clap::Error::raw(
        clap::error::ErrorKind::ArgumentConflict,
        format!("{parent} 子命令不能与分组自身的参数混用"),
      ));
    }
    // Clap 已把全局参数同步到分组，这里的第一个子命令与旧入口同名。
    Cli::from_arg_matches(nested)
  } else {
    Cli::from_arg_matches(matches)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::error::ErrorKind;

  #[test]
  fn root_help_and_legacy_diagnostics_match_their_trees() {
    let mut app = app();
    app.build();
    assert_eq!(
      app
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .count(),
      21
    );
    let legacy = Cli::command();
    for &(old, parent) in MOVES {
      assert!(app.find_subcommand(old).unwrap().is_hide_set());
      for flag in ["--help", "--bad-flag"] {
        let argv = ["wharf", old, flag];
        let baseline =
          legacy.clone().try_get_matches_from(argv).unwrap_err();
        let actual = match parse(&app, &argv) {
          Err(error) => error,
          Ok(_) => panic!("{argv:?}"),
        };
        assert_eq!(actual.kind(), baseline.kind(), "{argv:?}");
        assert_eq!(
          actual.to_string(),
          baseline.to_string(),
          "{argv:?}"
        );
      }
      let argv = ["wharf", parent, old, "--help"];
      assert_eq!(
        app.clone().try_get_matches_from(argv).unwrap_err().kind(),
        ErrorKind::DisplayHelp,
        "{argv:?}"
      );
    }
    let backup = app
      .find_subcommand("data")
      .unwrap()
      .find_subcommand("backup")
      .unwrap();
    for name in ["migrate", "cleanup-legacy"] {
      assert!(backup.find_subcommand(name).unwrap().is_hide_set());
    }
  }

  #[test]
  fn unknown_flag_before_command_keeps_the_matching_tree_diagnostic()
  {
    for (argv, tree) in [
      (
        ["wharf", "--json", "--comman", "refs", "schema"],
        legacy_diagnostic_tree(),
      ),
      (["wharf", "--json", "--comman", "schema", "refs"], app()),
    ] {
      let expected = tree.try_get_matches_from(argv).unwrap_err();
      let Err(actual) = parse(&app(), &argv) else {
        panic!("{argv:?}");
      };
      assert_eq!(actual.kind(), expected.kind());
      assert_eq!(actual.to_string(), expected.to_string());
    }
  }
}
