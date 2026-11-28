use std::{
  collections::{BTreeMap, BTreeSet},
  ffi::{CStr, CString},
  fs::File,
  io::{self, Read, Write},
  os::unix::{
    fs::{MetadataExt, PermissionsExt},
    io::AsRawFd,
  },
  path::{Path, PathBuf},
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    ProjectFile, ProjectUp, ProjectUpResult, ServiceExecJob,
    ServiceExecOutcome,
  },
  spec::{parse_file_mode, parse_uid_gid},
};

use crate::{
  dirfd::DirFd,
  docker::{Docker, io_err},
  exec::Ctx,
};

const QUICK: Duration = Duration::from_secs(20);
const FILE_LIMIT: u64 = 64 * 1024;

#[derive(Default)]
pub(super) struct Writes(Vec<Undo>);

type FileState = (String, u32, (u32, u32));

struct Undo {
  dir: DirFd,
  name: CString,
  previous: Option<FileState>,
  init: bool,
  reload: Option<(String, String)>,
}

impl Writes {
  pub(super) fn commit(mut self) {
    self.0.clear();
  }

  pub(super) fn rollback(&mut self) -> bool {
    let mut ok = true;
    for undo in self.0.drain(..).rev() {
      if undo.init {
        continue;
      }
      let result = match undo.previous {
        Some((content, mode, owner)) => replace(
          &undo.dir, &undo.name, &content, mode, owner, false, None,
        ),
        None => undo
          .dir
          .unlink(&undo.name)
          .map_err(io_err(Path::new("配置目录"))),
      };
      ok &= result.is_ok();
    }
    ok
  }
}

impl Drop for Writes {
  fn drop(&mut self) {
    if !self.rollback() {
      tracing::warn!("恢复热重载配置文件失败");
    }
  }
}

fn path_error() -> ApiError {
  ApiError::invalid("受管配置文件路径不合法")
}

fn write_root(
  docker: &Docker,
  up: &ProjectUp,
  file: &ProjectFile,
) -> Result<(DirFd, CString), ApiError> {
  let path =
    Path::new(file.directory.as_deref().ok_or_else(path_error)?);
  let path = if file.spec.init_only {
    let expected =
      PathBuf::from(format!("/srv/{}/.wharf-init", up.project));
    let suffix =
      path.strip_prefix(&expected).map_err(|_| path_error())?;
    if suffix.components().count() != 1 {
      return Err(path_error());
    }
    path.to_path_buf()
  } else {
    let suffix = path
      .strip_prefix("./.wharf-hot")
      .map_err(|_| path_error())?;
    if suffix.components().count() != 1 {
      return Err(path_error());
    }
    docker
      .project_dir(&up.project)
      .join(".wharf-hot")
      .join(suffix)
  };
  let filename = Path::new(&file.spec.path)
    .file_name()
    .ok_or_else(path_error)?;
  let name = CString::new(filename.as_encoded_bytes())
    .map_err(|_| path_error())?;
  let id = path
    .file_name()
    .and_then(|name| name.to_str())
    .ok_or_else(path_error)?;
  if id.len() != 24 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
    return Err(path_error());
  }
  let root = path
    .parent()
    .and_then(Path::parent)
    .ok_or_else(path_error)?;
  if file.spec.init_only {
    let base = DirFd::open_absolute(Path::new("/srv"))
      .map_err(io_err(root))?;
    let project =
      CString::new(up.project.as_str()).map_err(|_| path_error())?;
    base.ensure_subdir(&project, 0o755).map_err(io_err(root))?;
  }
  let parent = DirFd::open_absolute(root).map_err(io_err(root))?;
  let meta = parent.stat_self().map_err(io_err(root))?;
  if meta.st_uid != 0 || meta.st_mode & 0o022 != 0 {
    return Err(path_error());
  }
  let state_dir = if file.spec.init_only {
    c".wharf-init"
  } else {
    c".wharf-hot"
  };
  let parent = parent
    .ensure_subdir(state_dir, 0o700)
    .map_err(io_err(root))?;
  let meta = parent.stat_self().map_err(io_err(root))?;
  if meta.st_uid != 0 || meta.st_mode & 0o077 != 0 {
    return Err(path_error());
  }
  let id = CString::new(id).map_err(|_| path_error())?;
  let dir = match parent.open_subdir(&id) {
    Ok(dir) => dir,
    Err(err) if err.kind() == io::ErrorKind::NotFound => {
      parent
        .mkdir(&id, if file.spec.init_only { 0o700 } else { 0o755 })
        .map_err(io_err(root))?;
      let dir = parent.open_subdir(&id).map_err(io_err(root))?;
      if file.spec.init_only {
        let (uid, gid) = owner(file)?;
        if let Err(error) = dir.fchown_self(uid, gid) {
          let _ = parent.unlink_dir(&id);
          return Err(io_err(root)(error));
        }
      }
      dir
    }
    Err(err) => return Err(io_err(root)(err)),
  };
  Ok((dir, name))
}

fn owner(file: &ProjectFile) -> Result<(u32, u32), ApiError> {
  match file.spec.owner.as_deref() {
    None => Ok((0, 0)),
    Some(raw) => parse_uid_gid(raw)
      .ok_or_else(|| ApiError::invalid("文件属主须填写 UID:GID")),
  }
}

fn mode(file: &ProjectFile) -> Result<u32, ApiError> {
  match file.spec.mode.as_deref() {
    Some(raw) => parse_file_mode(raw)
      .ok_or_else(|| ApiError::invalid("文件权限须填写四位八进制")),
    None if file.spec.init_only => Ok(0o600),
    None => Ok(0o444),
  }
}

fn read(
  dir: &DirFd,
  name: &CStr,
  init: bool,
) -> Result<Option<FileState>, ApiError> {
  let err = io_err(Path::new("配置目录"));
  let fd = match dir.open_file(
    name,
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    0,
  ) {
    Ok(fd) => fd,
    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
    Err(e) => return Err(err(e)),
  };
  let f = File::from(fd);
  let stat = f.metadata().map_err(&err)?;
  if !stat.is_file() {
    return Err(path_error());
  }
  let mut text = String::new();
  if !init {
    f.take(FILE_LIMIT + 1)
      .read_to_string(&mut text)
      .map_err(&err)?;
    if text.len() as u64 > FILE_LIMIT {
      return Err(ApiError::invalid("热重载旧配置超过大小上限"));
    }
  }
  Ok(Some((text, stat.mode() & 0o777, (stat.uid(), stat.gid()))))
}

fn replace(
  dir: &DirFd,
  name: &CStr,
  content: &str,
  mode: u32,
  owner: (u32, u32),
  init: bool,
  staging: Option<&DirFd>,
) -> Result<(), ApiError> {
  use crate::dirfd::check;
  let stage = staging.unwrap_or(dir);
  let err = io_err(Path::new("配置目录"));
  let tmp = CString::new(format!(
    ".wharf-new-{}",
    crate::build::random_suffix()
  ))
  .expect("临时文件名为 ASCII");
  let fd = stage
    .open_file(
      &tmp,
      libc::O_CREAT
        | libc::O_EXCL
        | libc::O_WRONLY
        | libc::O_NOFOLLOW,
      0o600,
    )
    .map_err(&err)?;
  let result = (|| {
    let mut file = File::from(fd);
    file.write_all(content.as_bytes()).map_err(&err)?;
    check(unsafe {
      libc::fchown(file.as_raw_fd(), owner.0, owner.1)
    })
    .map_err(&err)?;
    file
      .set_permissions(std::fs::Permissions::from_mode(mode))
      .map_err(&err)?;
    file.sync_all().map_err(&err)?;
    if init {
      stage.rename_noreplace(&tmp, dir, name).map_err(&err)?;
    } else {
      dir.rename(&tmp, name).map_err(&err)?;
    }
    Ok(())
  })();
  let _ = stage.unlink(&tmp);
  result
}

fn parse_tar_number(bytes: &[u8]) -> Option<u32> {
  u32::from_str_radix(
    std::str::from_utf8(bytes).ok()?.trim_matches(['\0', ' ']),
    8,
  )
  .ok()
}

async fn verify_image_dirs(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let paths: BTreeSet<_> = up
    .project_files
    .iter()
    .filter(|f| f.directory.is_some())
    .filter_map(|f| {
      Path::new(&f.spec.path)
        .parent()
        .map(|path| (f.component.as_str(), path))
    })
    .collect();
  if paths.is_empty() {
    return Ok(());
  }
  let doc = wharf_api_types::compose::parse_compose(&up.compose)?;
  for (component, parent) in paths {
    let image =
      doc["services"][component]["image"].as_str().ok_or_else(
        || ApiError::invalid("专用目录校验需要目标组件指定镜像"),
      )?;
    let name =
      format!("wharf-files-check-{}", crate::build::random_suffix());
    let outcome = async {
      docker
        .cmd()
        .args([
          "create",
          "--pull",
          "never",
          "--name",
          &name,
          "--label",
          "wharf.temp=1",
          "--network",
          "none",
          "--entrypoint",
          "/bin/true",
          image,
          "check",
        ])
        .timeout(QUICK)
        .run(ctx)
        .await?
        .check("检查镜像专用目录")?;
      let path = format!("{name}:{}", parent.display());
      let mut bytes = Vec::new();
      let (code, stderr) = docker
        .cmd()
        .args(["cp", &path, "-"])
        .timeout(QUICK)
        .stdout_to(ctx, 64 * 1024, &mut bytes)
        .await?;
      if code == Some(0) {
        // Docker 的目录 tar 只允许一个目录头，不能遮住现有镜像文件。
        if bytes.get(156) != Some(&b'5')
          || bytes
            .get(512..1024)
            .is_none_or(|b| b.iter().any(|n| *n != 0))
        {
          return Err(
            ApiError::new(
              ErrorCode::Conflict,
              format!(
                "镜像目录 {} 已有文件或含符号链接",
                parent.display()
              ),
            )
            .with_hint("换一个专用空目录"),
          );
        }
      } else if !stderr.contains("Could not find the file")
        && !stderr.contains("No such file or directory")
      {
        return Err(ApiError::new(
          ErrorCode::Conflict,
          "无法验证镜像专用目录",
        ));
      }
      Ok(())
    }
    .await;
    let cleanup = docker
      .cmd()
      .args(["rm", "-f", &name])
      .timeout(QUICK)
      .run(&Ctx::detached())
      .await;
    outcome?;
    if !cleanup.is_ok_and(|out| out.success) {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "无法清理配置目录检查容器",
      ));
    }
  }
  Ok(())
}

pub(super) async fn prepare(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<Writes, ApiError> {
  verify_image_dirs(docker, up, ctx).await?;
  write_files(docker, up)
}

fn write_files(
  docker: &Docker,
  up: &ProjectUp,
) -> Result<Writes, ApiError> {
  let mut writes = Writes::default();
  for file in
    up.project_files.iter().filter(|f| f.directory.is_some())
  {
    let (dir, name) = write_root(docker, up, file)?;
    let content = &file.spec.content;
    let mode = mode(file)?;
    let owner = owner(file)?;
    let previous = read(&dir, &name, file.spec.init_only)?;
    if previous.as_ref().is_some_and(|(old, m, o)| {
      file.spec.init_only
        || (old == content && (*m, *o) == (mode, owner))
    }) {
      continue;
    }
    let stage = file
      .spec
      .init_only
      .then(|| {
        let state = format!("/srv/{}/.wharf-init", up.project);
        DirFd::open_absolute(Path::new(&state))
          .map_err(io_err(Path::new("配置目录")))
      })
      .transpose()?;
    replace(
      &dir,
      &name,
      content,
      mode,
      owner,
      file.spec.init_only,
      stage.as_ref(),
    )?;
    writes.0.push(Undo {
      dir,
      name,
      previous,
      init: file.spec.init_only,
      reload: file
        .spec
        .on_change
        .as_ref()
        .filter(|action| *action != "recreate")
        .map(|action| (file.component.clone(), action.clone())),
    });
  }
  Ok(writes)
}

pub(super) async fn verify_metadata(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  for file in
    up.project_files.iter().filter(|f| f.directory.is_none())
  {
    let ids = docker
      .compose(&up.project)
      .args(["ps", "--all", "--quiet", &file.component])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("查配置文件目标容器")?;
    let mut checked = false;
    for id in ids.stdout.split_whitespace() {
      checked = true;
      let source = format!("{id}:{}", file.spec.path);
      let mut bytes = Vec::new();
      let (code, _) = docker
        .cmd()
        .args(["cp", &source, "-"])
        .timeout(QUICK)
        .stdout_to(ctx, FILE_LIMIT + 16 * 1024, &mut bytes)
        .await?;
      let verified = code == Some(0)
        && bytes.len() >= 512
        && matches!(bytes[156], b'0' | 0)
        && file.spec.mode.as_ref().is_none_or(|_| {
          parse_tar_number(&bytes[100..108]) == mode(file).ok()
        })
        && file.spec.owner.as_ref().is_none_or(|_| {
          owner(file).is_ok_and(|(uid, gid)| {
            parse_tar_number(&bytes[108..116]) == Some(uid)
              && parse_tar_number(&bytes[116..124]) == Some(gid)
          })
        });
      if !verified {
        return Err(
          ApiError::new(
            ErrorCode::Conflict,
            format!(
              "当前 Compose 不能兑现配置文件 {} 的权限或属主",
              file.spec.path
            ),
          )
          .with_hint("升级 Docker Compose，或取消文件元数据声明"),
        );
      }
    }
    if !checked {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "没有可校验配置文件的目标容器",
      ));
    }
  }
  Ok(())
}

fn reload_actions(
  changed: &Writes,
) -> BTreeMap<String, BTreeSet<String>> {
  let mut actions = BTreeMap::<_, BTreeSet<_>>::new();
  for (component, action) in
    changed.0.iter().filter_map(|undo| undo.reload.as_ref())
  {
    actions
      .entry(component.clone())
      .or_default()
      .insert(action.clone());
  }
  actions
}

async fn reload(
  docker: &Docker,
  up: &ProjectUp,
  actions: &BTreeMap<String, BTreeSet<String>>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  if up.no_start {
    return Ok(());
  }
  for (component, actions) in actions {
    let ids = docker
      .compose(&up.project)
      .args(["ps", "--status", "running", "--quiet", component])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("查重载目标容器")?;
    let active: Vec<_> = ids.stdout.split_whitespace().collect();
    if active.len() > 1
      && actions.iter().any(|action| action.starts_with("exec:"))
    {
      return Err(
        reload_error(&up.project)
          .with_hint("exec 热重载只支持单副本组件"),
      );
    }
    for id in active {
      for action in actions {
        if *action == "sighup" {
          let out = docker
            .cmd()
            .args(["kill", "--signal", "HUP", id])
            .timeout(QUICK)
            .run(ctx)
            .await?;
          if !out.success {
            return Err(reload_error(&up.project));
          }
        } else if let Some(command) = action.strip_prefix("exec:") {
          let quiet = Ctx {
            progress: None,
            cancel: ctx.cancel.clone(),
          };
          let result = crate::service_exec::run(
            docker,
            ServiceExecJob {
              project: up.project.clone(),
              container: Some(component.clone()),
              command: command.into(),
              timeout_secs: 20,
              cwd: None,
              stream: false,
            },
            &quiet,
          )
          .await;
          if !matches!(result, ServiceExecOutcome::Finished { result, .. } if result.exit_code == 0)
          {
            return Err(reload_error(&up.project));
          }
        }
      }
    }
  }
  if let Some(readiness) = &up.readiness {
    crate::settle::watch(
      docker,
      &up.project,
      crate::settle::WatchOptions {
        max_watch: crate::settle::max_watch(up.start_timeout_secs),
        readiness: Some(readiness),
      },
      ctx,
    )
    .await?;
  }
  Ok(())
}

fn reload_error(project: &str) -> ApiError {
  ApiError::new(
    ErrorCode::AgentFailed,
    format!("服务 {project} 的配置重载失败"),
  )
  .with_hint("检查目标容器的重载命令和日志，修正后重试")
}

pub(super) async fn refresh(
  docker: &Docker,
  up: &ProjectUp,
  from: &str,
  ctx: &Ctx,
) -> Result<ProjectUpResult, ApiError> {
  let stale = || {
    ApiError::new(
      ErrorCode::PlanStale,
      "运行结构已经变化，不能只更新配置文件",
    )
    .with_hint("重新生成计划")
  };
  let previous = docker.previous(&up.project).ok_or_else(stale)?;
  if previous.hash != from
    || previous.compose != up.compose
    || previous.project_env
      != up
        .project_env
        .as_ref()
        .map(crate::docker::dotenv)
        .transpose()?
  {
    return Err(stale());
  }
  let state = docker.one_status(&up.project, ctx).await?;
  if state.containers.is_empty()
    || state.containers.iter().any(|container| container.foreign)
  {
    return Err(stale());
  }
  let mut changed = write_files(docker, up)?;
  let actions = reload_actions(&changed);
  let result = async {
    if !actions.is_empty() {
      reload(docker, up, &actions, ctx).await?;
    }
    docker.write_hash(&up.project, &up.hash)
  }
  .await;
  if let Err(error) = result {
    let restored = changed.rollback();
    let recovered = actions.is_empty()
      || reload(docker, up, &actions, &Ctx::detached()).await.is_ok();
    ctx.say(format!(
      "配置文件恢复{}，重新加载旧配置{}",
      if restored { "成功" } else { "失败" },
      if recovered { "成功" } else { "失败" }
    ));
    return Err(error);
  }
  changed.commit();
  Ok(ProjectUpResult {
    containers: state.containers,
    images: Vec::new(),
    warnings: Vec::new(),
    retired: Vec::new(),
  })
}

#[test]
fn first_file_keeps_application_content() {
  let tmp = tempfile::tempdir().unwrap();
  let dir = DirFd::open_absolute(tmp.path()).unwrap();
  let owner =
    (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
  let name = c"settings.json";
  replace(&dir, name, "{\"n\":1}", 0o600, owner, true, None).unwrap();
  replace(&dir, name, "{\"n\":2}", 0o600, owner, false, None)
    .unwrap();
  assert!(
    replace(&dir, name, "{\"n\":3}", 0o600, owner, true, None)
      .is_err()
  );
  let (actual, mode, ids) = read(&dir, name, false).unwrap().unwrap();
  assert_eq!(
    (actual.as_str(), mode, ids),
    ("{\"n\":2}", 0o600, owner)
  );
}

#[test]
fn only_changed_hot_files_contribute_reload_actions() {
  let dir = tempfile::tempdir().unwrap();
  let undo = |action: &str| Undo {
    dir: DirFd::open_absolute(dir.path()).unwrap(),
    name: c"config".to_owned(),
    previous: None,
    init: false,
    reload: Some(("app".into(), action.into())),
  };
  let changed = Writes(vec![undo("sighup"), undo("sighup")]);
  assert_eq!(
    reload_actions(&changed),
    BTreeMap::from([(
      "app".into(),
      BTreeSet::from(["sighup".into()])
    )])
  );
  changed.commit();
}

#[tokio::test]
async fn rollback_restores_hot_file_before_old_container_starts() {
  use super::{HostShell, Ops, Previous, Reporter};
  let (root, docker) = crate::docker::fake_docker(
    r#"
case "$1:$6" in
  compose:up) [ "$(cat config)" = previous ] && touch restored;;
  ps:*) echo '{"Names":"app-app-1","Labels":"com.docker.compose.project=app","State":"running"}';;
esac
"#,
  );
  let ops = Ops::new(
    docker.clone(),
    Reporter::new(docker.clone(), None),
    String::new(),
    HostShell::prepare(docker.clone(), "s1".into()).await,
    root.path().into(),
  );
  let up: ProjectUp = serde_json::from_value(serde_json::json!({
    "project":"app","compose":"services: {app: {image: app:2}}","hash":"new",
    "pull":{"mirrors":{},"mirrors_only":false,"attempt_timeout_secs":1}
  })).unwrap();
  let previous = Previous {
    compose: "services: {app: {image: app:1}}".into(),
    hash: "old".into(),
    images: BTreeMap::new(),
    project_env: None,
  };
  std::fs::write(root.path().join("config"), "new").unwrap();
  let owner =
    (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
  let mut files = Writes(vec![Undo {
    dir: DirFd::open_absolute(root.path()).unwrap(),
    name: c"config".to_owned(),
    previous: Some(("previous".into(), 0o600, owner)),
    init: false,
    reload: None,
  }]);
  ops
    .restore_deployment(
      &up,
      Some(&previous),
      &mut files,
      &Ctx::detached(),
      ApiError::internal("fixture"),
    )
    .await;
  assert!(root.path().join("restored").exists());
}
