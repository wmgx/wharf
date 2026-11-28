use std::{
  collections::BTreeSet,
  ffi::CString,
  io::Write,
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

fn receipt(
  job: &AdoptDataJob,
  target: &DirFd,
) -> std::io::Result<String> {
  let stat = target.stat_self()?;
  Ok(format!("{} {} {}", job.nonce, stat.st_dev, stat.st_ino))
}

fn record_copy(
  receipt_path: &Path,
  job: &AdoptDataJob,
  target: &DirFd,
) -> Result<(), ApiError> {
  let dir = receipt_path.parent().expect("有服务收编目录");
  let err = io_err(receipt_path);
  std::fs::create_dir_all(dir).map_err(&err)?;
  let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(&err)?;
  tmp
    .write_all(receipt(job, target).map_err(&err)?.as_bytes())
    .map_err(&err)?;
  tmp.as_file().sync_all().map_err(&err)?;
  tmp.persist(receipt_path).map_err(|e| err(e.error))?;
  Ok(())
}

fn legacy_marker(job: &AdoptDataJob) -> CString {
  CString::new(format!(".wharf-adopt-{}", job.nonce))
    .expect("已验证收编批号")
}

fn completed(
  target: &DirFd,
  job: &AdoptDataJob,
  receipt_path: &Path,
) -> Result<bool, ApiError> {
  let err = io_err(receipt_path);
  match std::fs::read_to_string(receipt_path) {
    Ok(value) if value == receipt(job, target).map_err(&err)? => {
      return Ok(true);
    }
    Ok(_) => {}
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
    Err(e) => return Err(err(e)),
  }
  Ok(
    target
      .lstat(&legacy_marker(job))
      .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG),
  )
}

pub(crate) async fn inspect(
  docker: &Docker,
  data_dir: &Path,
  job: &AdoptDataJob,
  exclude_owner: bool,
  ctx: &Ctx,
) -> Result<AdoptDataInspectResult, ApiError> {
  validate(job)?;
  let dest = service_dir(&job.service)?;
  let path = dest
    .as_ref()
    .map_or_else(|| PathBuf::from("/srv"), DirFd::fd_path);
  let (disk, _) = crate::report::disk_stat(&path)
    .ok_or_else(|| ApiError::internal("无法读取收编目标盘余量"))?;
  let receipts = data_dir.join("adopt-data").join(&job.service);
  let mounts = if exclude_owner {
    docker
      .project_mounts(std::slice::from_ref(&job.service), true, ctx)
      .await?
      .remove(&job.service)
      .unwrap_or_default()
  } else {
    Vec::new()
  };
  let image = if job.items.is_empty() {
    None
  } else {
    Some(crate::adopt::self_image(docker, ctx).await?)
  };
  let mut entries = Vec::new();
  for item in &job.items {
    let path = source_path(docker, item, ctx).await?;
    let mut used: Vec<_> = docker
      .mount_users(
        &BindMountQuery {
          path: path.clone(),
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
    let mut copied = false;
    if let Some(dir) = &dest {
      let name =
        CString::new(item.volume_name.as_str()).expect("已验证卷名");
      match dir.open_subdir(&name) {
        Ok(target) => {
          copied = completed(
            &target,
            job,
            &receipts.join(&item.volume_name),
          )?;
          target_exists_nonempty = !copied
            && !target
              .read_names_limited(1)
              .map_err(io_err(Path::new("/srv")))?
              .0
              .is_empty();
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(Path::new("/srv"))(e)),
      }
    }
    let bytes = if copied {
      Some(0)
    } else {
      probe_source(
        docker,
        image.as_deref().expect("有收编源"),
        &path,
        ctx,
      )
      .await?
    };
    entries.push(AdoptInspectEntry {
      is_dir: Some(bytes.is_some()),
      volume_name: item.volume_name.clone(),
      target_exists_nonempty,
      in_use_by: used,
      size_bytes: bytes.unwrap_or(0),
    });
  }
  Ok(AdoptDataInspectResult {
    entries,
    srv_avail_bytes: disk.free,
    mounts,
  })
}

pub(crate) async fn copy(
  docker: &Docker,
  data_dir: &Path,
  job: &AdoptDataJob,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let inspected = inspect(docker, data_dir, job, false, ctx).await?;
  if let Some(entry) = inspected.entries.iter().find(|e| {
    e.target_exists_nonempty
      || !e.in_use_by.is_empty()
      || e.is_dir == Some(false)
  }) {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      format!(
        "收编目标 {} 非空、源挂载仍被写入或不是目录：{}",
        entry.volume_name,
        entry.in_use_by.join("、")
      ),
    ));
  }
  crate::data_sync::mkdir(Path::new("/srv"), &job.service, "")?;
  let root = service_dir(&job.service)?
    .ok_or_else(|| ApiError::not_found("服务目录不存在"))?;
  let image = crate::adopt::self_image(docker, ctx).await?;
  let receipts = data_dir.join("adopt-data").join(&job.service);
  for item in &job.items {
    let receipt_path = receipts.join(&item.volume_name);
    let name =
      CString::new(item.volume_name.as_str()).expect("已验证卷名");
    match root.open_subdir(&name) {
      Ok(target) if completed(&target, job, &receipt_path)? => {
        let marker = legacy_marker(job);
        if target
          .lstat(&marker)
          .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
        {
          record_copy(&receipt_path, job, &target)?;
          target
            .unlink(&marker)
            .map_err(io_err(Path::new("/srv")))?;
        }
        continue;
      }
      Ok(_) => {}
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
      Err(e) => return Err(io_err(Path::new("/srv"))(e)),
    }
    copy_one(docker, &image, &root, job, item, &receipt_path, ctx)
      .await?;
  }
  Ok(())
}

async fn copy_one(
  docker: &Docker,
  image: &str,
  root: &DirFd,
  job: &AdoptDataJob,
  item: &AdoptSourceItem,
  receipt_path: &Path,
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
  let source = source_path(docker, item, ctx).await?;
  run_source(docker, image, &source, Some(&stage_path), ctx)
    .await?
    .check("复制外部数据卷")?;
  let stage = root.open_subdir(&cstage).map_err(&err)?;
  // 先登记临时目录的 inode，改名后才能识别为同批已完成的卷。
  record_copy(receipt_path, job, &stage)?;
  let target =
    CString::new(item.volume_name.as_str()).expect("已验证卷名");
  root.rename(&cstage, &target).map_err(err)
}

async fn probe_source(
  docker: &Docker,
  image: &str,
  source: &str,
  ctx: &Ctx,
) -> Result<Option<u64>, ApiError> {
  let out = run_source(docker, image, source, None, ctx).await?;
  if out.code == Some(45) {
    return Ok(None);
  }
  let out = out.check("读取外部数据卷大小")?;
  let bytes = out
    .stdout
    .split_whitespace()
    .next()
    .and_then(|n| n.parse::<u64>().ok())
    .ok_or_else(|| ApiError::internal("无法读取外部数据卷大小"))?;
  Ok(Some(bytes.saturating_mul(1024)))
}

// 宿主机和临时容器里的 mountinfo 都以文件系统为基准，需先换算宿主机路径。
const CHECK_SOURCE: &str = r#"
  awk '
    FNR == NR {
      path = ENVIRON["WHARF_ADOPT_SOURCE"]
      mount = $5
      if ((path == mount || mount == "/" || index(path, mount "/") == 1) &&
          length(mount) >= len) {
        len = length(mount)
        suffix = substr(path, mount == "/" ? 1 : len + 1)
        root = ($4 == "/" && suffix != "" ? "" : $4) suffix
        dev = $3
      }
      next
    }
    $5 == "/src" && $4 == root && $3 == dev { found = 1 }
    END { exit !found }
  ' "$1" "$2" || exit 44
"#;

async fn run_source(
  docker: &Docker,
  image: &str,
  source: &str,
  stage: Option<&Path>,
  ctx: &Ctx,
) -> Result<crate::exec::Output, ApiError> {
  if source.contains([',', '"', '\n', '\r', '\0']) {
    return Err(ApiError::invalid("外部数据卷路径含不支持的字符"));
  }
  let name = format!("wharf-adopt-{}", crate::build::random_suffix());
  let mount = format!(
    "type=bind,src={source},dst=/src,readonly,bind-recursive=disabled"
  );
  let encoded = source.replace('\\', "\\134").replace(' ', "\\040");
  let mut command = docker.cmd().args([
    "run",
    "--rm",
    "--name",
    &name,
    "--label",
    "wharf.temp=1",
    "--network",
    "none",
    "--pull",
    "never",
    "--read-only",
    "--mount",
    &mount,
    "--mount",
    "type=bind,src=/proc/1/mountinfo,dst=/host-mountinfo,readonly",
    "-e",
    &format!("WHARF_ADOPT_SOURCE={encoded}"),
  ]);
  if let Some(path) = stage {
    command = command.args([
      "--mount",
      &format!("type=bind,src={},dst=/dst", path.display()),
    ]);
  }
  let script = format!(
    r#"
    {CHECK_SOURCE}
    [ -d /src ] || exit 45
    used=$(du -sk /src) || exit 47
    used=${{used%%[!0-9]*}}
    if [ "$3" = inspect ]; then
      printf '%s\n' "$used"
      exit
    fi
    avail=$(df -Pk /dst | awk 'NR == 2 {{print $4}}')
    [ "$avail" -ge "$((used + used / 10 + 102400))" ] || exit 46
    exec rsync -aHS --numeric-ids --stats --exclude='.wharf-adopt-*' /src/ /dst/
  "#
  );
  let result = command
    .args([
      "--entrypoint",
      "/bin/sh",
      image,
      "-ec",
      &script,
      "wharf-adopt",
      "/host-mountinfo",
      "/proc/self/mountinfo",
      if stage.is_some() { "copy" } else { "inspect" },
    ])
    .timeout(Duration::from_secs(if stage.is_some() {
      4 * 3600 - 30
    } else {
      25
    }))
    .stream(stage.is_some())
    .run(ctx)
    .await;
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
    Some(44) => Err(ApiError::invalid(
      "外部挂载解析后与原路径不同，可能穿过软链",
    )),
    Some(45) if stage.is_some() => {
      Err(ApiError::invalid("收编只支持目录，单文件挂载请单独处理"))
    }
    Some(46) => {
      Err(ApiError::invalid("目标磁盘余量不足，未复制数据"))
    }
    _ => Ok(out),
  }
}

#[test]
fn adopt_bind_matches_filesystem_root_and_rejects_redirected_source()
{
  let tmp = tempfile::tempdir().unwrap();
  let host = tmp.path().join("host");
  let container = tmp.path().join("container");
  std::fs::write(
    &host,
    r"1 0 0:1 /@ / rw - btrfs /dev/sda rw
2 1 8:16 / /mnt/data rw - ext4 /dev/sdb rw
3 2 8:17 / /mnt/data-old rw - ext4 /dev/sdc rw
",
  )
  .unwrap();
  for (source, dev, root, expected) in [
    ("/mnt/data/app", "8:16", "/app", true),
    ("/mnt/data", "8:16", "/", true),
    (r"/opt/my\040app", "0:1", r"/@/opt/my\040app", true),
    ("/mnt/data/app", "8:17", "/app", false),
    ("/mnt/data/app", "8:16", "/different", false),
  ] {
    std::fs::write(
      &container,
      format!("4 0 {dev} {root} /src ro - ext4 none ro\n"),
    )
    .unwrap();
    let status = std::process::Command::new("sh")
      .args(["-ec", CHECK_SOURCE, "check"])
      .args([&host, &container])
      .env("WHARF_ADOPT_SOURCE", source)
      .status()
      .unwrap();
    assert_eq!(status.success(), expected, "{source} {dev} {root}");
  }
}

#[test]
fn adopt_copy_receipt_keeps_business_directory_clean_and_allows_retry()
 {
  let tmp = tempfile::tempdir().unwrap();
  let stage = tmp.path().join("stage");
  let volume = tmp.path().join("volume");
  let receipt = tmp.path().join("state").join("volume");
  std::fs::create_dir(&stage).unwrap();
  std::fs::write(stage.join("file"), "data").unwrap();
  let job = AdoptDataJob {
    service: "app".into(),
    items: vec![],
    nonce: "a".repeat(32),
  };
  record_copy(&receipt, &job, &DirFd::open_dir(&stage).unwrap())
    .unwrap();
  std::fs::create_dir(&volume).unwrap();
  assert!(
    !completed(&DirFd::open_dir(&volume).unwrap(), &job, &receipt)
      .unwrap()
  );
  std::fs::rename(&stage, &volume).unwrap();
  let target = DirFd::open_dir(&volume).unwrap();
  assert!(completed(&target, &job, &receipt).unwrap());
  assert_eq!(
    target.read_names().unwrap(),
    [CString::new("file").unwrap()]
  );
}
