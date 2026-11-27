use std::{
  collections::BTreeMap,
  fs,
  io::ErrorKind,
  path::{Path, PathBuf},
  time::Duration,
};

use wharf_api_types::{
  ApiError,
  agent::{GatewayApply, ProjectUpResult},
};

use crate::{
  docker::{CONFIG_HASH_FILE, io_err, write_private},
  exec::{Cmd, Ctx},
};

use super::{CADDY_ADMIN, Ops, recovery_error};

const MANAGED_GATEWAY_FILES: [&str; 2] = ["link.crt", "link.key"];

fn validate_names(
  extra: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  for name in extra.keys() {
    if !MANAGED_GATEWAY_FILES.contains(&name.as_str()) {
      return Err(ApiError::invalid(format!(
        "不支持的网关附属文件：{name}"
      )));
    }
  }
  Ok(())
}

fn remove(path: &Path) -> Result<(), ApiError> {
  match fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
    Err(e) => Err(io_err(path)(e)),
  }
}

struct GatewayFiles {
  conf: PathBuf,
  backups: Vec<(PathBuf, Option<PathBuf>)>,
  cert_changed: bool,
  committed: bool,
}

impl GatewayFiles {
  fn stage(
    conf: &Path,
    caddyfile: &str,
    extra: &BTreeMap<String, String>,
  ) -> Result<Self, ApiError> {
    let mut files = Self {
      conf: conf.to_path_buf(),
      backups: Vec::new(),
      cert_changed: false,
      committed: false,
    };
    for name in ["Caddyfile"].into_iter().chain(MANAGED_GATEWAY_FILES)
    {
      let path = conf.join(name);
      let old = match fs::read_to_string(&path) {
        Ok(old) => Some(old),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(io_err(&path)(e)),
      };
      let backup = if let Some(old) = &old {
        let backup = conf.join(format!("{name}.prev"));
        write_private(&backup, old)?;
        Some(backup)
      } else {
        None
      };
      if let Some(new) = extra.get(name) {
        files.cert_changed |= old.as_ref() != Some(new);
      }
      files.backups.push((path, backup));
    }
    // 校验看到的文件必须与应用成功后留在磁盘上的一致。
    for name in MANAGED_GATEWAY_FILES {
      let path = conf.join(name);
      if let Some(content) = extra.get(name) {
        write_private(&path, content)?;
      } else {
        remove(&path)?;
      }
    }
    write_private(&conf.join("Caddyfile.next"), caddyfile)?;
    Ok(files)
  }

  fn activate(&self) -> Result<(), ApiError> {
    let current = self.conf.join("Caddyfile");
    fs::rename(self.conf.join("Caddyfile.next"), &current)
      .map_err(io_err(&current))
  }

  fn commit(mut self, hash: &str) -> Result<(), ApiError> {
    write_private(&self.conf.join(CONFIG_HASH_FILE), hash)?;
    self.committed = true;
    Ok(())
  }
}

impl Drop for GatewayFiles {
  fn drop(&mut self) {
    for (path, backup) in &self.backups {
      let result = match (self.committed, backup) {
        (true, Some(backup)) => remove(backup),
        (true, None) => Ok(()),
        (false, Some(backup)) => {
          fs::rename(backup, path).map_err(io_err(path))
        }
        (false, None) => remove(path),
      };
      if let Err(error) = result {
        tracing::error!("清理网关配置失败：{}", error.message);
      }
    }
    if let Err(error) = remove(&self.conf.join("Caddyfile.next")) {
      tracing::error!("清理网关待校验配置失败：{}", error.message);
    }
  }
}

impl Ops {
  pub(super) async fn gateway_apply(
    &self,
    apply: &GatewayApply,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    validate_names(&apply.extra_files)?;
    let up = &apply.up;
    let conf = self.docker.project_dir(&up.project).join("conf");
    fs::create_dir_all(&conf).map_err(io_err(&conf))?;

    let before = self.docker.one_status(&up.project, ctx).await?;
    let compose_changed =
      before.hash.as_deref() != Some(up.hash.as_str());
    let running = before.all_running();

    let mut previous = if running && compose_changed {
      self.docker.previous(&up.project)
    } else {
      None
    };
    if let Some(prev) = &mut previous {
      let names = self.docker.images(&up.project, ctx).await?;
      prev.images =
        self.docker.running_images(&up.project, &names, ctx).await?;
    }
    let mut warnings = Vec::new();
    let images = vec![apply.image.clone()];
    let mut activated = false;
    let result = async {
      if !running || compose_changed {
        self
          .docker
          .pull(&apply.image, &up.pull, ctx, &mut warnings)
          .await?;
      }
      let files = GatewayFiles::stage(
        &conf,
        &apply.caddyfile,
        &apply.extra_files,
      )?;
      ctx.say("校验 Caddy 配置");
      Cmd::new(&self.docker.bin)
        .args([
          "run",
          "--rm",
          "--label",
          "wharf.temp=1",
          "--network",
          "none",
          "-v",
        ])
        .arg(format!("{}:/etc/caddy:ro", conf.display()))
        .args([
          apply.image.as_str(),
          "caddy",
          "validate",
          "--config",
          "/etc/caddy/Caddyfile.next",
          "--adapter",
          "caddyfile",
        ])
        .timeout(Duration::from_secs(60))
        .run(ctx)
        .await?
        .check("caddy validate")?;

      files.activate()?;
      activated = true;
      let result = if running && !compose_changed {
        ctx.say("热重载 Caddy");
        // 配置文本不变时，证书换了也要让 Caddy 重新加载。
        self
          .caddy_reload(&up.project, files.cert_changed, ctx)
          .await?;
        let state = self.docker.one_status(&up.project, ctx).await?;
        ProjectUpResult {
          containers: state.containers,
          images: self.docker.image_info(&images, ctx).await,
          warnings,
          retired: vec![],
        }
      } else {
        self.finish_up(up, &images, warnings, None, 10, ctx).await?
      };
      files.commit(&apply.caddyfile_hash)?;
      Ok::<_, ApiError>(result)
    }
    .await;
    // GatewayFiles 的守卫已经还原文件，旧容器现在才能读取旧配置。
    match result {
      Ok(result) => Ok(result),
      Err(error) if activated && running && !compose_changed => {
        let recover = ctx.detached_with_progress();
        recover.say("热重载失败，恢复旧网关配置");
        Err(
          match self.caddy_reload(&up.project, true, &recover).await {
            Ok(()) => error,
            Err(back) => recovery_error(error, back, "旧网关配置"),
          },
        )
      }
      Err(error) if activated && previous.is_some() => {
        let previous = previous.as_ref().unwrap();
        let recover = ctx.detached_with_progress();
        recover.say(format!("{}，恢复旧网关", error.message));
        Err(
          self
            .restore_project(
              &up.project,
              previous,
              &recover,
              error,
              "旧网关",
              wharf_api_types::compose::parse_compose_max_grace_secs(
                &up.compose,
              ),
            )
            .await,
        )
      }
      Err(error) => Err(
        self.restore_before_up(previous.as_ref(), ctx, error).await,
      ),
    }
  }

  /// `force`：配置没变也重载（Caddy 默认会跳过），证书管理随之重新开始。
  pub(super) async fn caddy_reload(
    &self,
    project: &str,
    force: bool,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    self
      .docker
      .compose(project)
      .args([
        "exec",
        "-T",
        "caddy",
        "caddy",
        "reload",
        "--config",
        "/etc/caddy/Caddyfile",
        "--adapter",
        "caddyfile",
        "--address",
        CADDY_ADMIN,
      ])
      .args(force.then_some("--force"))
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await?
      .check("caddy reload")?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gateway_validation_cannot_reuse_omitted_certificate_files() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path();
    let config = "tls /etc/caddy/link.crt /etc/caddy/link.key";
    write_private(&conf.join("Caddyfile"), config).unwrap();
    write_private(&conf.join("link.crt"), "旧证书").unwrap();
    write_private(&conf.join("link.key"), "旧文件").unwrap();

    let extra =
      BTreeMap::from([("link.crt".into(), "替换证书".into())]);
    let files = GatewayFiles::stage(conf, config, &extra).unwrap();
    assert!(!conf.join("link.key").exists());
    // 校验缺文件失败时，下一次启动仍能读取原来的证书和私钥。
    drop(files);
    assert_eq!(
      fs::read_to_string(conf.join("link.crt")).unwrap(),
      "旧证书"
    );
    assert_eq!(
      fs::read_to_string(conf.join("link.key")).unwrap(),
      "旧文件"
    );
  }

  #[test]
  fn gateway_extra_files_reject_unsafe_names_restore_and_clean_up() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path();
    let old = BTreeMap::from([
      ("link.crt".into(), "旧证书".into()),
      ("link.key".into(), "旧文件".into()),
    ]);
    for name in ["../pwn", "Caddyfile", "foo.txt"] {
      assert!(
        validate_names(&BTreeMap::from([(
          name.into(),
          String::new()
        )]))
        .is_err()
      );
    }
    assert_eq!(fs::read_dir(conf).unwrap().count(), 0);

    let new = BTreeMap::from([
      ("link.crt".into(), "新证书".into()),
      ("link.key".into(), "新文件".into()),
    ]);
    // 模拟 validate 返回错误：丢弃暂存，首次部署写入的文件一并删除。
    drop(GatewayFiles::stage(conf, "待校验", &new).unwrap());
    assert_eq!(fs::read_dir(conf).unwrap().count(), 0);
    let files = GatewayFiles::stage(conf, "旧配置", &old).unwrap();
    files.activate().unwrap();
    files.commit("old").unwrap();
    let files = GatewayFiles::stage(conf, "新配置", &new).unwrap();
    for name in MANAGED_GATEWAY_FILES {
      assert_eq!(
        fs::read_to_string(conf.join(name)).unwrap(),
        new[name]
      );
      assert_eq!(
        fs::metadata(conf.join(name)).unwrap().permissions().mode()
          & 0o777,
        0o600
      );
    }
    drop(files);
    for name in MANAGED_GATEWAY_FILES {
      assert_eq!(
        fs::read_to_string(conf.join(name)).unwrap(),
        old[name]
      );
      assert!(!conf.join(format!("{name}.prev")).exists());
    }
    assert_eq!(
      fs::read_to_string(conf.join("Caddyfile")).unwrap(),
      "旧配置"
    );
    assert_eq!(
      fs::read_to_string(conf.join(CONFIG_HASH_FILE)).unwrap(),
      "old"
    );
    let empty = BTreeMap::new();
    let files =
      GatewayFiles::stage(conf, "没有隧道", &empty).unwrap();
    files.activate().unwrap();
    files.commit("new").unwrap();
    assert!(
      MANAGED_GATEWAY_FILES
        .iter()
        .all(|name| !conf.join(name).exists())
    );
  }
}

#[cfg(test)]
#[tokio::test]
async fn gateway_rebuild_failure_restores_conf_before_old_compose() {
  let (dir, docker) = crate::docker::fake_docker(
    r#"
case "$1:$2:$6" in
  ps:-a:*) echo '{"Names":"gateway-caddy-1","Labels":"com.docker.compose.project=wharf-gw-gw","State":"running"}';;
  ps:-aq:*) echo container-id;;
  inspect:*) echo 'caddy:1|old-image';;
  compose:-p:config) echo 'caddy:1';;
  compose:-p:up)
    if grep -q NEW "$5"; then echo 'port conflict' >&2; exit 1; fi
    grep -q OLD projects/wharf-gw-gw/conf/Caddyfile && test -f retagged && touch recovered;;
  image:inspect:*) echo 'new-image|[]';;
  tag:old-image:*) grep -q OLD projects/wharf-gw-gw/conf/Caddyfile && touch retagged;;
  pull:*|run:*|logs:*) ;;
  *) exit 2;;
esac
"#,
  );
  let ops = Ops::new(
    docker.clone(),
    crate::report::Reporter::new(docker.clone(), None),
    String::new(),
    crate::host_shell::HostShell::prepare(
      docker.clone(),
      "s1".into(),
    )
    .await,
    dir.path().into(),
  );
  let project = "wharf-gw-gw";
  docker.write_compose(project, "OLD").unwrap();
  docker.write_hash(project, "old").unwrap();
  let conf = docker.project_dir(project).join("conf");
  fs::create_dir(&conf).unwrap();
  write_private(&conf.join("Caddyfile"), "OLD").unwrap();
  let apply: GatewayApply = serde_json::from_value(serde_json::json!({
    "up":{"project":project,"compose":"NEW","hash":"new",
      "pull":{"mirrors":{},"mirrors_only":false,"attempt_timeout_secs":1}},
    "image":"caddy:1","caddyfile":"NEW","caddyfile_hash":"new"
  })).unwrap();
  let error = ops
    .gateway_apply(&apply, &Ctx::detached())
    .await
    .unwrap_err();
  assert!(error.message.contains("已恢复旧网关"));
  assert!(dir.path().join("recovered").is_file());
  let old = docker.previous(project).unwrap();
  assert_eq!((&*old.compose, &*old.hash), ("OLD", "old"));
}
