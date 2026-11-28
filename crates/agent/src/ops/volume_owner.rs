use std::{
  ffi::CString,
  io::{self, Read},
  os::unix::fs::OpenOptionsExt,
  path::Path,
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode, agent::ProjectUp, spec::parse_uid_gid,
};

use crate::{dirfd::DirFd, docker::Docker, exec::Ctx};

const TIMEOUT: Duration = Duration::from_secs(25);

pub(super) async fn prepare(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  if up.volume_owners.is_empty() {
    return Ok(());
  }
  let mut automatic = None;
  for (name, owner) in &up.volume_owners {
    wharf_api_types::validate_name("卷", name)?;
    let bad = || {
      ApiError::invalid(format!("无法确定卷 {name} 的运行用户"))
        .with_hint("为该卷明确填写 UID:GID")
    };
    let ids = if owner == "auto" {
      if automatic.is_none() {
        automatic =
          Some(image_ids(docker, up, ctx).await?.ok_or_else(bad)?);
      }
      automatic.expect("已解析运行用户")
    } else {
      parse_uid_gid(owner).ok_or_else(bad)?
    };
    let root = DirFd::open_absolute(Path::new("/srv"))
      .map_err(crate::docker::io_err(Path::new("/srv")))?;
    let name_c = CString::new(name.as_str()).expect("已验证卷名");
    let project = CString::new(up.project.as_str())
      .map_err(|_| ApiError::invalid("服务名不合法"))?;
    let project = root
      .ensure_subdir(&project, 0o755)
      .map_err(crate::docker::io_err(Path::new("/srv")))?;
    let stat = project
      .stat_self()
      .map_err(crate::docker::io_err(Path::new("/srv")))?;
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
      return Err(ApiError::new(
        ErrorCode::Forbidden,
        "服务数据根目录必须由管理员控制",
      ));
    }
    ensure_owned(&project, &name_c, name, ids)?;
  }
  Ok(())
}

fn ensure_owned(
  root: &DirFd,
  name: &std::ffi::CStr,
  display: &str,
  ids: (u32, u32),
) -> Result<(), ApiError> {
  let err = crate::docker::io_err(Path::new("/srv"));
  let verify = |dir: &DirFd| {
    let stat = dir.stat_self().map_err(&err)?;
    if (stat.st_uid, stat.st_gid) == ids {
      return Ok(());
    }
    Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("卷 {display} 已存在，属主与声明不一致"),
      )
      .with_hint("核对目录属主，或取消 owner 后重新计划"),
    )
  };
  match root.open_subdir(name) {
    Ok(dir) => return verify(&dir),
    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
    Err(error) => return Err(err(error)),
  }
  let stage = CString::new(format!(
    ".wharf-owner-{}",
    crate::build::random_suffix()
  ))
  .expect("临时目录名为 ASCII");
  root.mkdir(&stage, 0o755).map_err(&err)?;
  let result = (|| {
    let dir = root.open_subdir(&stage).map_err(&err)?;
    dir.fchown_self(ids.0, ids.1).map_err(&err)?;
    match root.rename_noreplace(&stage, root, name) {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
        verify(&root.open_subdir(name).map_err(&err)?)
      }
      Err(e) => Err(err(e)),
    }
  })();
  let _ = root.unlink_dir(&stage);
  result
}

async fn image_ids(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<Option<(u32, u32)>, ApiError> {
  let doc = wharf_api_types::compose::parse_compose(&up.compose)?;
  let body = &doc["services"][up.project.as_str()];
  let Some(image) = body["image"].as_str() else {
    return Ok(None);
  };
  let user = if let Some(user) = body["user"].as_str() {
    user.to_string()
  } else {
    let got = docker
      .cmd()
      .args([
        "image",
        "inspect",
        "--format",
        "{{json .Config.User}}",
        image,
      ])
      .timeout(TIMEOUT)
      .run(ctx)
      .await?
      .check("读取镜像运行用户")?;
    serde_json::from_str::<Option<String>>(&got.stdout)
      .map_err(|_| ApiError::internal("无法读取镜像运行用户"))?
      .unwrap_or_default()
  };
  if user.is_empty() {
    return Ok(Some((0, 0)));
  }
  if let Some(ids) = parse_uid_gid(&user) {
    return Ok(Some(ids));
  }
  let name =
    format!("wharf-owner-check-{}", crate::build::random_suffix());
  let result = async {
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
      .timeout(TIMEOUT)
      .run(ctx)
      .await?
      .check("创建镜像用户检查容器")?;
    let files = tempfile::tempdir()
      .map_err(|_| ApiError::internal("无法创建私有用户检查目录"))?;
    let passwd =
      copy_identity_file(docker, &name, "passwd", files.path(), ctx)
        .await?;
    let group =
      copy_identity_file(docker, &name, "group", files.path(), ctx)
        .await?;
    Ok(resolve_user(&user, &passwd, &group))
  }
  .await;
  let cleanup = docker
    .cmd()
    .args(["rm", "-f", &name])
    .timeout(TIMEOUT)
    .run(&Ctx::detached())
    .await;
  match result {
    Ok(_) if !cleanup.is_ok_and(|out| out.success) => {
      Err(ApiError::new(
        ErrorCode::AgentFailed,
        "无法删除镜像用户检查容器",
      ))
    }
    result => result,
  }
}

async fn copy_identity_file(
  docker: &Docker,
  name: &str,
  file: &str,
  root: &Path,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let source = format!("{name}:/etc/{file}");
  let dest = root.join(file);
  let out = docker
    .cmd()
    .args(["cp", "-L", &source])
    .arg(dest.display().to_string())
    .timeout(TIMEOUT)
    .run(ctx)
    .await?;
  if !out.success
    && (out.stderr.contains("Could not find the file")
      || out.stderr.contains("No such file or directory"))
  {
    return Ok(String::new());
  }
  out.check("读取镜像用户数据库")?;
  let reader = std::fs::OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
    .open(&dest)
    .map_err(crate::docker::io_err(&dest))?;
  if !reader
    .metadata()
    .map_err(crate::docker::io_err(&dest))?
    .is_file()
  {
    return Err(ApiError::invalid("镜像用户数据库必须是常规文件"));
  }
  let mut content = String::new();
  reader
    .take(1024 * 1024 + 1)
    .read_to_string(&mut content)
    .map_err(crate::docker::io_err(&dest))?;
  if content.len() > 1024 * 1024 {
    return Err(ApiError::invalid("镜像用户数据库超过 1 MiB"));
  }
  Ok(content)
}

fn resolve_user(
  user: &str,
  passwd: &str,
  group: &str,
) -> Option<(u32, u32)> {
  let (user, explicit_group) = user
    .split_once(':')
    .map_or((user, None), |(u, g)| (u, Some(g)));
  let valid_id = |value: &str| {
    value.parse::<u32>().ok().filter(|n| *n != u32::MAX)
  };
  let uid = valid_id(user);
  let found = passwd.lines().find_map(|line| {
    let mut fields = line.split(':');
    let name = fields.next()?;
    let uid_in_file = valid_id(fields.nth(1)?)?;
    let gid = valid_id(fields.next()?)?;
    (uid == Some(uid_in_file) || name == user)
      .then_some((uid_in_file, gid))
  });
  let (uid, default_gid) =
    found.or_else(|| uid.map(|uid| (uid, 0)))?;
  let gid = if let Some(explicit) = explicit_group {
    valid_id(explicit).or_else(|| {
      group.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == explicit)
          .then(|| fields.nth(1).and_then(valid_id))
          .flatten()
      })
    })?
  } else {
    default_gid
  };
  Some((uid, gid))
}

#[test]
fn image_user_uses_the_primary_group_unless_overridden() {
  let passwd = "app:x:1000:1001::/nonexistent:/bin/false";
  let groups = "writers:x:1002:";
  assert_eq!(resolve_user("app", passwd, groups), Some((1000, 1001)));
  assert_eq!(
    resolve_user("1000:writers", passwd, groups),
    Some((1000, 1002))
  );
  assert_eq!(resolve_user("missing", passwd, groups), None);
}
