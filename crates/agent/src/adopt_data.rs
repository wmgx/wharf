use std::{
  collections::BTreeSet,
  ffi::CString,
  path::{Path, PathBuf},
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode, adopt_data::*, agent::BindMountQuery,
};

use crate::{
  dirfd::DirFd,
  docker::{Docker, io_err},
  exec::Ctx,
};

fn validate(job: &AdoptDataJob) -> Result<(), ApiError> {
  wharf_api_types::validate_name("服务", &job.service)?;
  if job.nonce.len() != 32
    || !job.nonce.bytes().all(|c| c.is_ascii_hexdigit())
    || job.items.is_empty()
    || job.items.len() > 100
  {
    return Err(ApiError::invalid("收编数据请求不合法"));
  }
  let mut names = BTreeSet::new();
  for item in &job.items {
    item.validate()?;
    if !names.insert(&item.volume_name) {
      return Err(ApiError::invalid("收编数据的目标卷名重复"));
    }
  }
  Ok(())
}

async fn source_path(
  docker: &Docker,
  item: &AdoptSourceItem,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  if item.kind == AdoptSourceKind::ExternalDir {
    return Ok(item.source.clone());
  }
  let result = docker
    .cmd()
    .args(["volume", "inspect", &item.source])
    .timeout(Duration::from_secs(20))
    .run(ctx)
    .await?
    .check("docker volume inspect")?;
  let volumes: Vec<serde_json::Value> =
    serde_json::from_str(&result.stdout)
      .map_err(|_| ApiError::internal("无法读取 Docker 卷信息"))?;
  let volume = volumes
    .first()
    .ok_or_else(|| ApiError::not_found("Docker 卷不存在"))?;
  if volume["Driver"] != "local"
    || volume["Options"].as_object().is_some_and(|o| !o.is_empty())
  {
    return Err(ApiError::invalid(
      "只能收编没有自定义驱动选项的 Docker 本地卷",
    ));
  }
  volume["Mountpoint"]
    .as_str()
    .filter(|p| p.starts_with('/'))
    .map(str::to_string)
    .ok_or_else(|| ApiError::invalid("Docker 卷没有宿主机路径"))
}

fn service_dir(service: &str) -> Result<Option<DirFd>, ApiError> {
  match DirFd::open_service_root(Path::new("/srv"), service) {
    Ok(dir) => Ok(Some(dir)),
    Err(e) if e.code == ErrorCode::NotFound => Ok(None),
    Err(e) => Err(e),
  }
}

fn completed(
  dir: &DirFd,
  job: &AdoptDataJob,
  item: &AdoptSourceItem,
) -> Result<bool, ApiError> {
  let name =
    CString::new(item.volume_name.as_str()).expect("已验证卷名");
  match dir.open_subdir(&name) {
    Ok(target) => {
      let marker =
        CString::new(format!(".wharf-adopt-{}", job.nonce))
          .expect("已验证收编批号");
      Ok(
        target
          .lstat(&marker)
          .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG),
      )
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
    Err(e) => Err(io_err(Path::new("/srv"))(e)),
  }
}

pub(crate) async fn inspect(
  docker: &Docker,
  job: &AdoptDataJob,
  exclude_owner: bool,
  ctx: &Ctx,
) -> Result<Vec<AdoptInspectEntry>, ApiError> {
  validate(job)?;
  let dest = service_dir(&job.service)?;
  let mounts = if exclude_owner {
    docker
      .project_mounts(std::slice::from_ref(&job.service), ctx)
      .await?
      .remove(&job.service)
      .unwrap_or_default()
  } else {
    Vec::new()
  };
  let mut entries = Vec::new();
  for item in &job.items {
    let path = source_path(docker, item, ctx).await?;
    let mut used: Vec<_> = docker
      .mount_users(
        &BindMountQuery {
          path,
          running_only: true,
          writable_only: true,
          exclude_projects: if exclude_owner {
            vec![job.service.clone()]
          } else {
            vec![]
          },
        },
        true,
        ctx,
      )
      .await?
      .into_iter()
      .map(|u| u.container)
      .collect();
    used.sort_unstable();
    used.dedup();
    let mut target_exists_nonempty = false;
    if let Some(dir) = &dest
      && !completed(dir, job, item)?
    {
      let name =
        CString::new(item.volume_name.as_str()).expect("已验证卷名");
      match dir.open_subdir(&name) {
        Ok(target) => {
          target_exists_nonempty = !target
            .read_names()
            .map_err(io_err(Path::new("/srv")))?
            .is_empty();
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(Path::new("/srv"))(e)),
      }
    }
    let is_dir = if item.kind == AdoptSourceKind::ExternalDir
      && let Some(mount) = mounts.iter().find(|m| {
        m.kind == "bind"
          && m.source.trim_end_matches('/') == item.source
      }) {
      inspect_mount_type(mount, ctx).await?
    } else {
      None
    };
    entries.push(AdoptInspectEntry {
      is_dir,
      volume_name: item.volume_name.clone(),
      target_exists_nonempty,
      in_use_by: used,
    });
  }
  Ok(entries)
}

pub(crate) async fn copy(
  docker: &Docker,
  job: &AdoptDataJob,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let entries = inspect(docker, job, false, ctx).await?;
  if let Some(entry) = entries
    .iter()
    .find(|e| e.target_exists_nonempty || !e.in_use_by.is_empty())
  {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      format!(
        "收编目标 {} 非空或源挂载仍被写入：{}",
        entry.volume_name,
        entry.in_use_by.join("、")
      ),
    ));
  }
  crate::data_sync::mkdir(Path::new("/srv"), &job.service, "")?;
  let root = service_dir(&job.service)?
    .ok_or_else(|| ApiError::not_found("服务目录不存在"))?;
  let image = crate::adopt::self_image(docker, ctx).await?;
  for item in &job.items {
    if completed(&root, job, item)? {
      continue;
    }
    copy_one(docker, &image, &root, job, item, ctx).await?;
  }
  Ok(())
}

async fn copy_one(
  docker: &Docker,
  image: &str,
  root: &DirFd,
  job: &AdoptDataJob,
  item: &AdoptSourceItem,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let stage_name =
    format!(".wharf-adopt-{}", crate::build::random_suffix());
  let cstage = CString::new(stage_name.as_str())
    .expect("临时目录名是否合法由生成器保证");
  let root_path = PathBuf::from("/srv").join(&job.service);
  let stage_path = root_path.join(&stage_name);
  let err = io_err(&root_path);
  root.mkdir(&cstage, 0o700).map_err(&err)?;
  struct Stage(PathBuf);
  impl Drop for Stage {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }
  let _stage = Stage(stage_path.clone());
  let opts = match item.kind {
    AdoptSourceKind::ExternalDir => format!(
      "type=bind,src={},dst=/src,readonly,bind-recursive=disabled",
      item.source
    ),
    AdoptSourceKind::NamedVolume => format!(
      "type=volume,src={},dst=/src,readonly,volume-nocopy",
      item.source
    ),
  };
  let name = format!("wharf-adopt-{}", crate::build::random_suffix());
  let destination =
    format!("type=bind,src={},dst=/dst", stage_path.display());
  let bind = item.kind == AdoptSourceKind::ExternalDir;
  let timeout = Duration::from_secs(4 * 3600 - 30);
  let result = docker.cmd().args([
    "run", "--rm", "--name", &name, "--label", "wharf.temp=1", "--network", "none",
    "--mount", &opts, "--mount", &destination,
    "--entrypoint", "/bin/sh", image, "-ec",
    r#"
      if [ "$1" = bind ]; then
        root=$(awk '$5 == "/src" { print $4; exit }' /proc/self/mountinfo)
        [ "$root" = "$2" ] || exit 44
      fi
      [ -d /src ] && [ ! -L /src ] || exit 45
      used=$(du -sk /src | awk '{print $1}')
      avail=$(df -Pk /dst | awk 'NR == 2 {print $4}')
      [ "$avail" -ge "$((used + used / 10 + 102400))" ] || exit 46
      exec rsync -aH --numeric-ids --stats --exclude=.wharf-adopt-\* /src/ /dst/
    "#,
    "wharf-adopt", if bind { "bind" } else { "volume" }, &item.source,
  ]).timeout(timeout).stream(true).run(ctx).await;
  if !result.as_ref().is_ok_and(|out| out.success) {
    let _ = docker
      .cmd()
      .args(["rm", "-f", &name])
      .timeout(Duration::from_secs(15))
      .run(&Ctx::detached())
      .await;
  }
  let out = result?;
  match out.code {
    Some(44) => {
      return Err(ApiError::invalid(
        "外部挂载解析后与原路径不同，可能穿过软链或文件系统边界",
      ));
    }
    Some(45) => {
      return Err(ApiError::invalid(
        "收编只支持目录，单文件挂载请单独处理",
      ));
    }
    Some(46) => {
      return Err(ApiError::invalid("目标磁盘余量不足，未复制数据"));
    }
    _ => {
      out.check("复制外部数据卷")?;
    }
  }
  let stage = root.open_subdir(&cstage).map_err(&err)?;
  let marker = CString::new(format!(".wharf-adopt-{}", job.nonce))
    .expect("已验证收编批号");
  stage
    .open_file(
      &marker,
      libc::O_WRONLY
        | libc::O_CREAT
        | libc::O_EXCL
        | crate::dirfd::NOFOLLOW,
      0o600,
    )
    .map_err(&err)?;
  let target =
    CString::new(item.volume_name.as_str()).expect("已验证卷名");
  root.rename(&cstage, &target).map_err(err)
}

async fn inspect_mount_type(
  mount: &wharf_api_types::agent::ContainerMount,
  ctx: &Ctx,
) -> Result<Option<bool>, ApiError> {
  use base64::{Engine, engine::general_purpose::STANDARD};
  let name = mount.container.trim_start_matches('/');
  if name.is_empty()
    || !name.bytes().all(|b| {
      b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
    })
  {
    return Err(ApiError::invalid("容器名称不合法"));
  }
  let client = reqwest::Client::builder()
    .unix_socket("/var/run/docker.sock")
    .timeout(Duration::from_secs(10))
    .build()
    .map_err(|_| ApiError::internal("无法连接 Docker"))?;
  let request = client
    .head(format!("http://docker/containers/{name}/archive"))
    .query(&[("path", &mount.target)])
    .send();
  let response = tokio::select! {
    response = request => response.ok(),
    _ = ctx.cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "挂载检查已取消")),
  };
  let header = response
    .as_ref()
    .filter(|r| r.status().is_success())
    .and_then(|r| r.headers().get("X-Docker-Container-Path-Stat"));
  let stat = header
    .and_then(|h| STANDARD.decode(h.as_bytes()).ok())
    .and_then(|raw| {
      serde_json::from_slice::<serde_json::Value>(&raw).ok()
    });
  let mode = stat.as_ref().and_then(|v| v["mode"].as_u64());
  Ok(mode.map(|m| m & (1 << 31) != 0))
}
