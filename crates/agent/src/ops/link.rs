use std::{
  fs,
  io::ErrorKind,
  path::{Path, PathBuf},
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{LinkApply, ProjectUpResult},
};

use crate::{
  docker::{CONFIG_HASH_FILE, io_err, write_private},
  exec::Ctx,
};

use super::{Ops, recovery_error};

const CONFIG: &str = "frpc.toml";
const NEXT: &str = "frpc.toml.next";
const CA: &str = "ca.pem";

struct LinkFiles {
  conf: PathBuf,
  backups: Vec<(PathBuf, Option<PathBuf>)>,
  committed: bool,
}

impl LinkFiles {
  fn stage(
    conf: &Path,
    config: &str,
    ca: &str,
  ) -> Result<Self, ApiError> {
    fs::create_dir_all(conf).map_err(io_err(conf))?;
    let mut files = Self {
      conf: conf.into(),
      backups: Vec::new(),
      committed: false,
    };
    for name in [CONFIG, CA] {
      let path = conf.join(name);
      let backup = match fs::read_to_string(&path) {
        Ok(content) => {
          let backup = conf.join(format!("{name}.prev"));
          write_private(&backup, &content)?;
          Some(backup)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(io_err(&path)(error)),
      };
      files.backups.push((path, backup));
    }
    write_private(&conf.join(CA), ca)?;
    write_private(&conf.join(NEXT), config)?;
    Ok(files)
  }

  fn activate(&self) -> Result<(), ApiError> {
    let path = self.conf.join(CONFIG);
    fs::rename(self.conf.join(NEXT), &path).map_err(io_err(&path))
  }

  fn commit(mut self, hash: &str) -> Result<(), ApiError> {
    write_private(&self.conf.join(CONFIG_HASH_FILE), hash)?;
    self.committed = true;
    Ok(())
  }
}

fn remove(path: &Path) -> std::io::Result<()> {
  match fs::remove_file(path) {
    Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
    result => result,
  }
}

impl Drop for LinkFiles {
  fn drop(&mut self) {
    for (path, backup) in &self.backups {
      let result = match (&backup, self.committed) {
        (Some(backup), true) => remove(backup),
        (Some(backup), false) => fs::rename(backup, path),
        (None, false) => remove(path),
        (None, true) => Ok(()),
      };
      if let Err(e) = result {
        tracing::error!(
          "恢复 frpc 配置文件 {} 失败：{e}",
          path.display()
        );
      }
    }
    for name in
      [NEXT, "frpc.toml.tmp", "ca.tmp", ".wharf-config-hash.tmp"]
    {
      if let Err(e) = remove(&self.conf.join(name)) {
        tracing::error!("清理 frpc 暂存文件 {name} 失败：{e}");
      }
    }
    if !self.committed {
      let _ = fs::remove_dir(&self.conf);
    }
  }
}

fn ca_file(apply: &LinkApply) -> Result<&str, ApiError> {
  if apply.up.project.starts_with("wharf-link-")
    && apply.extra_files.len() == 1
    && let Some(ca) = apply.extra_files.get(CA)
  {
    return Ok(ca);
  }
  Err(ApiError::invalid(
    "frpc 项目或附属文件名无效，附属文件只允许 ca.pem",
  ))
}

impl Ops {
  pub(super) async fn link_apply(
    &self,
    apply: &LinkApply,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    let ca = ca_file(apply)?;
    let up = &apply.up;
    let project = &up.project;
    let conf = self.docker.project_dir(project).join("conf");
    let before = self.docker.one_status(project, ctx).await?;
    let reload = before.all_running()
      && before.hash.as_deref() == Some(&up.hash);
    let mut warnings = Vec::new();
    let previous = if !reload && before.all_running() {
      self
        .previous_for_rollback(project, ctx, &mut warnings)
        .await?
    } else {
      None
    };
    let images = std::slice::from_ref(&apply.image);
    let mut activated = false;
    let result = async {
      if !reload {
        self
          .docker
          .pull(&apply.image, &up.pull, ctx, &mut warnings)
          .await?;
      }
      let files = LinkFiles::stage(&conf, &apply.config, ca)?;
      self.verify_frpc(&apply.image, &conf, ctx).await?;
      files.activate()?;
      activated = true;
      let result = if reload {
        self.reload_frpc(project, ctx).await?;
        ProjectUpResult {
          containers: before.containers,
          images: self.docker.image_info(images, ctx).await,
          warnings,
          retired: vec![],
        }
      } else {
        self.finish_up(up, images, warnings, None, 10, ctx).await?
      };
      files.commit(&apply.config_hash)?;
      Ok::<_, ApiError>(result)
    }
    .await;
    // 先由 LinkFiles 还原磁盘配置，再让旧进程重新读它。
    let recover = ctx.detached_with_progress();
    match result {
      Err(error) if activated && reload => {
        recover.say("热重载失败，恢复旧 frpc 配置");
        Err(match self.reload_frpc(project, &recover).await {
          Ok(()) => error,
          Err(back) => recovery_error(error, back, "旧 frpc 配置"),
        })
      }
      Err(error) if activated => {
        if let Some(previous) = previous {
          Err(
            self
              .restore_project(
                project,
                &previous,
                &recover,
                error,
                "旧 frpc 项目",
                10,
              )
              .await,
          )
        } else {
          Err(error)
        }
      }
      Err(error) => Err(
        self.restore_before_up(previous.as_ref(), ctx, error).await,
      ),
      ok => ok,
    }
  }

  async fn verify_frpc(
    &self,
    image: &str,
    conf: &Path,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|_| {
      ApiError::internal("无法生成 frpc 校验容器名称")
    })?;
    let name = format!("wharf-frpc-verify-{}", hex::encode(suffix));
    ctx.say("校验 frpc 配置");
    let verify = self
      .docker
      .cmd()
      .args([
        "run",
        "--rm",
        "--name",
        &name,
        "--label",
        "wharf.temp=1",
        "--pull=never",
        "--network",
        "none",
        "-v",
      ])
      .arg(format!("{}:/etc/frp:ro", conf.display()))
      .args([
        "--entrypoint",
        "frpc",
        image,
        "verify",
        "-c",
        "/etc/frp/frpc.toml.next",
      ])
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await;
    if verify.as_ref().is_err() {
      let _ = self
        .docker
        .cmd()
        .args(["rm", "-f", &name])
        .timeout(Duration::from_secs(10))
        .run(&Ctx::detached())
        .await;
    }
    if !verify?.success {
      // frpc 的解析错误可能回显含密钥的 TOML。
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "frpc 配置校验失败",
      ));
    }
    Ok(())
  }

  async fn reload_frpc(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    ctx.say("热重载 frpc");
    let result = self
      .docker
      .compose(project)
      .args([
        "exec",
        "-T",
        "frpc",
        "frpc",
        "reload",
        "-c",
        "/etc/frp/frpc.toml",
      ])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?;
    if !result.success {
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "frpc 热重载失败")
          .with_hint(format!(
            "在目标服务器执行 docker compose -p {project} logs frpc"
          )),
      );
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::PermissionsExt;

  #[test]
  fn uncommitted_link_files_restore_private_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path();
    write_private(&conf.join(CONFIG), "current").unwrap();
    write_private(&conf.join(CA), "current-ca").unwrap();
    let files = LinkFiles::stage(conf, "next", "next-ca").unwrap();
    files.activate().unwrap();
    drop(files);
    assert_eq!(
      fs::read_to_string(conf.join(CONFIG)).unwrap(),
      "current"
    );
    assert_eq!(
      fs::read_to_string(conf.join(CA)).unwrap(),
      "current-ca"
    );
    assert_eq!(
      fs::metadata(conf.join(CONFIG))
        .unwrap()
        .permissions()
        .mode()
        & 0o777,
      0o600
    );
    assert_eq!(fs::read_dir(conf).unwrap().count(), 2);
  }
}
