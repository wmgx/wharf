//! 期望状态的内存表示：从数据库读出来，叠加 plan 请求里的修改，再整体校验。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  agent::TRIAL_PROJECT_PREFIX,
  spec::{
    AdoptSpec, BookmarkSpec, BuildSource, Change, EdgeAppSpec, Fleet,
    GatewayKind, GatewaySpec, GatewayTls, LinkMode, RouteSpec,
    ServerSettings, ServiceSpec, Source,
  },
  validate_name,
};

use crate::{
  caddy_validate::{
    check_custom_caddy_boundaries, check_error_page, redirect_host,
    valid_upstream, validate_gateway, validate_route_hostname,
    validate_route_path,
  },
  db::{ResourceRow, Write, json_err},
};

pub const KIND_SERVER: &str = "server";
pub const KIND_SERVICE: &str = "service";
pub const KIND_GATEWAY: &str = "gateway";
pub const KIND_ROUTE: &str = "route";
pub const KIND_EDGE: &str = "edge";
pub const KIND_BOOKMARK: &str = "bookmark";

/// 网关的 compose project 名前缀，服务名不能用。
pub const GATEWAY_PROJECT_PREFIX: &str = "wharf-gw-";
/// 自动分配的宿主机端口范围。
pub const HOST_PORTS: std::ops::RangeInclusive<u16> = 20000..=29999;

#[derive(Debug, Clone, PartialEq)]
pub struct ServerRow {
  pub settings: ServerSettings,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceRow {
  pub instance_id: String,
  pub spec: ServiceSpec,
  /// 端口名 → 宿主机端口。
  pub host_ports: BTreeMap<String, u16>,
  /// 还没完成的导入：第一次部署成功后清掉，记进导入记录。存在 meta 里，不是用户配置。
  pub import: Option<AdoptSpec>,
  /// 计划时固定的镜像版本：镜像 → `sha256:…`（image 来源）。存在 meta 里，只有检查更新才换。
  pub pins: BTreeMap<String, String>,
  /// 计划时固定的 commit（git 构建来源）。存在 meta 里，只有检查更新才换。
  pub commit: Option<String>,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayRow {
  pub spec: GatewaySpec,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EdgeRow {
  pub spec: EdgeAppSpec,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BookmarkRow {
  pub spec: BookmarkSpec,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteRow {
  pub id: String,
  pub spec: RouteSpec,
  pub version: u64,
}

pub const BACKUP_DEFAULT_DNS_TTL: u32 = 60;

pub fn effective_dns_ttl(route: &RouteSpec, proxied: bool) -> u32 {
  if proxied {
    1
  } else {
    route.dns_ttl.unwrap_or(if route.backup_gateway.is_some() {
      BACKUP_DEFAULT_DNS_TTL
    } else {
      1
    })
  }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct World {
  pub servers: BTreeMap<String, ServerRow>,
  pub services: BTreeMap<String, ServiceRow>,
  pub gateways: BTreeMap<String, GatewayRow>,
  pub edge_apps: BTreeMap<String, EdgeRow>,
  pub bookmarks: BTreeMap<String, BookmarkRow>,
  /// key 是 hostname。
  pub routes: BTreeMap<String, RouteRow>,
}

/// git 构建来源的 `仓库#分支`，和部署记录里的写法一致。
pub fn git_ref(spec: &ServiceSpec) -> Option<String> {
  match &spec.source {
    Source::Build(BuildSource { git: Some(g), .. }) => {
      Some(format!("{}#{}", g.repo, g.reference))
    }
    _ => None,
  }
}

pub fn edge_owner(host: &str) -> String {
  format!("edge:{host}")
}

pub fn gateway_project(name: &str) -> String {
  format!("{GATEWAY_PROJECT_PREFIX}{name}")
}

pub fn new_id(prefix: &str) -> String {
  let mut bytes = [0u8; 6];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  format!("{prefix}_{}", hex::encode(bytes))
}

pub fn new_service_instance_id() -> String {
  let mut bytes = [0; 8];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  format!("svc_{}", hex::encode(bytes))
}

impl World {
  pub fn from_rows(rows: Vec<ResourceRow>) -> Result<Self, ApiError> {
    let mut world = World::default();
    for row in rows {
      let version = row.version;
      match row.kind.as_str() {
        KIND_SERVER => {
          world.servers.insert(
            row.name,
            ServerRow {
              settings: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_SERVICE => {
          world.services.insert(
            row.name,
            ServiceRow {
              instance_id: row.meta["instance_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              host_ports: serde_json::from_value(
                row.meta["host_ports"].clone(),
              )
              .unwrap_or_default(),
              import: serde_json::from_value(
                row.meta["import"].clone(),
              )
              .unwrap_or_default(),
              pins: serde_json::from_value(row.meta["pins"].clone())
                .unwrap_or_default(),
              commit: row.meta["commit"].as_str().map(str::to_string),
              version,
            },
          );
        }
        KIND_GATEWAY => {
          world.gateways.insert(
            row.name,
            GatewayRow {
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_ROUTE => {
          world.routes.insert(
            row.name,
            RouteRow {
              id: row.meta["id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_EDGE => {
          world.edge_apps.insert(
            row.name,
            EdgeRow {
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_BOOKMARK => {
          world.bookmarks.insert(
            row.name,
            BookmarkRow {
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        other => tracing::warn!("未知资源类型 {other}，忽略"),
      }
    }
    Ok(world)
  }

  pub fn service_instances(&self) -> BTreeMap<String, String> {
    self
      .services
      .iter()
      .map(|(name, row)| {
        (format!("{KIND_SERVICE}/{name}"), row.instance_id.clone())
      })
      .collect()
  }

  /// 每个资源的版本，`kind/name` → version。
  pub fn versions(&self) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (name, r) in &self.servers {
      out.insert(format!("{KIND_SERVER}/{name}"), r.version);
    }
    for (name, r) in &self.services {
      out.insert(format!("{KIND_SERVICE}/{name}"), r.version);
    }
    for (name, r) in &self.gateways {
      out.insert(format!("{KIND_GATEWAY}/{name}"), r.version);
    }
    for (name, r) in &self.routes {
      out.insert(format!("{KIND_ROUTE}/{name}"), r.version);
    }
    for (name, r) in &self.edge_apps {
      out.insert(format!("{KIND_EDGE}/{name}"), r.version);
    }
    for (id, r) in &self.bookmarks {
      out.insert(format!("{KIND_BOOKMARK}/{id}"), r.version);
    }
    out
  }

  fn check_edge_import_name(
    &self,
    name: &str,
  ) -> Result<(), ApiError> {
    if let Some(existing) = self.edge_apps.get(name) {
      let target = crate::edge_sync::target(name, &existing.spec);
      return Err(
        ApiError::invalid(format!(
          "边缘应用 {name} 已经纳管厂商项目 {target}"
        ))
        .with_hint("换一个导入名称"),
      );
    }
    Ok(())
  }

  /// 叠加局部修改。
  pub fn apply_changes(
    &mut self,
    changes: &[Change],
  ) -> Result<(), ApiError> {
    for change in changes {
      if let Change::ImportEdgeApp { name, .. } = change {
        self.check_edge_import_name(name)?;
      }
    }
    for change in changes {
      match change {
        Change::UpsertBookmark { id, spec } => {
          let version = match id {
            Some(id) => {
              self
                .bookmarks
                .get(id)
                .ok_or_else(|| {
                  ApiError::not_found(format!("书签 {id} 不存在"))
                    .suggest("wharf bookmark list")
                })?
                .version
            }
            None => {
              if self.bookmarks.len() >= 200 {
                return Err(ApiError::invalid("书签最多 200 条"));
              }
              0
            }
          };
          let spec = check_bookmark(spec.clone())?;
          let id = id.clone().unwrap_or_else(|| new_id("bm"));
          self.bookmarks.insert(id, BookmarkRow { spec, version });
        }
        Change::RemoveBookmark { id } => {
          if self.bookmarks.remove(id).is_none() {
            return Err(
              ApiError::not_found(format!("书签 {id} 不存在"))
                .suggest("wharf bookmark list"),
            );
          }
        }
        Change::UpdateServer { name, settings } => {
          crate::link::validate_private_addr(
            name,
            settings.private_addr.as_ref(),
          )?;
          crate::egress::validate(name, settings, &self.servers)?;
          let server = self
            .servers
            .get_mut(name)
            .ok_or_else(|| server_not_found(name))?;
          validate_lan_addrs(&settings.lan_addrs)?;
          validate_baseline(&settings.baseline)?;
          if let Some(memory) = &settings.agent_memory {
            wharf_api_types::resources::parse_agent_memory(memory)?;
          }
          if settings
            .traffic_reset_day
            .is_some_and(|d| !(1..=28).contains(&d))
          {
            return Err(ApiError::invalid(
              "流量重置日要在 1 到 28 之间",
            ));
          }
          if let Some(v) = &settings.renew_at
            && chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d")
              .is_err()
          {
            return Err(
              ApiError::invalid(format!(
                "服务器 {name} 的续费日 {v} 格式不对"
              ))
              .with_hint("写成 2027-01-31"),
            );
          }
          if let Some(limit) = &settings.bg_bwlimit
            && wharf_api_types::resources::parse_bwlimit_kbps(limit)?
              == 0
          {
            return Err(ApiError::invalid(
              "请清除 bg_bwlimit 以关闭限速",
            ));
          }
          server.settings = settings.clone();
        }
        Change::AdoptData { .. } => {}
        Change::EditServiceTags { name, add, remove } => {
          let row = self
            .services
            .get_mut(name)
            .ok_or_else(|| crate::api::service_not_found(name))?;
          for tag in remove {
            row.spec.tags.remove(normalize_service_tag(tag)?);
          }
          for tag in add {
            row.spec.tags.insert(normalize_service_tag(tag)?.into());
          }
          validate_tags(&row.spec.tags)?;
        }
        Change::UpsertService {
          name,
          spec,
          adopt,
          pins: req_pins,
          commit: req_commit,
          ..
        } => {
          if let Source::Build(b) = &spec.source
            && b.dockerfile.is_some()
            && b.template.is_some()
            && !self
              .services
              .get(name)
              .is_some_and(|old| old.spec.source == spec.source)
          {
            return Err(
              ApiError::invalid(
                "dockerfile 和 template 不能同时设置",
              )
              .with_hint("指定内置模板时请清空 dockerfile 路径"),
            );
          }

          validate_name("服务", name)?;
          if name
            .starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
          {
            return Err(ApiError::invalid(
              "服务名不能以 wharf-task- 开头",
            ));
          }
          if name.starts_with(TRIAL_PROJECT_PREFIX) {
            return Err(
              ApiError::invalid(format!(
                "服务名 {name} 不能以 wharf-try- 开头"
              ))
              .with_hint("这个前缀留给部署时的试跑容器"),
            );
          }
          let old = self.services.get(name);
          crate::host_access::validate_adopt(
            self,
            name,
            old,
            adopt.as_ref(),
          )?;
          let host_ports =
            old.map(|s| s.host_ports.clone()).unwrap_or_default();
          let version = old.map(|s| s.version).unwrap_or(0);
          let instance_id = old
            .map_or_else(new_service_instance_id, |s| {
              s.instance_id.clone()
            });
          // 导入后、第一次部署前再改配置：导入还没做完，保留。
          let import = adopt
            .clone()
            .or_else(|| old.and_then(|s| s.import.clone()));
          // 改配置不换镜像版本；换了镜像的，旧的固定版本对不上，计划时重新查。
          let mut pins = old
            .map(|s| s.pins.clone())
            .or_else(|| {
              import.as_ref().map(|a| a.initial_pins.clone())
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|(image, _)| {
              crate::pins::images(&spec.source).contains(image)
            })
            .collect();
          // 改构建配置不换代码；换了仓库或分支的，计划时重新查。
          let mut commit = old
            .filter(|o| git_ref(&o.spec) == git_ref(spec))
            .and_then(|o| o.commit.clone());
          if let Some(requested) = req_pins {
            let images = crate::pins::images(&spec.source);
            for (image, digest) in requested {
              if !images.contains(image)
                || digest.strip_prefix("sha256:").is_none_or(|sha| {
                  crate::uploads::check_sha(sha).is_err()
                })
              {
                return Err(ApiError::invalid(format!(
                  "服务 {name} 的镜像 {image} 没有合法的固定版本"
                )));
              }
            }
            pins = requested.clone();
          }
          if let Some(sha) = req_commit {
            if git_ref(spec).is_none()
              || !crate::rollback::valid_commit(sha)
            {
              return Err(ApiError::invalid(format!(
                "服务 {name} 的固定 Git commit 不合法"
              )));
            }
            commit = Some(sha.to_ascii_lowercase());
          }
          // compose 来源没填端口时按 compose 里映射的端口补上，否则服务没有内网地址。
          let mut spec = spec.clone();
          if let Some(old) = old
            && changes.iter().any(|change| {
              matches!(change, Change::EditServiceTags { name: edited, .. } if edited == name)
            })
          {
            spec.tags.clone_from(&old.spec.tags);
          }
          spec.tags = spec
            .tags
            .iter()
            .map(|tag| normalize_service_tag(tag).map(str::to_owned))
            .collect::<Result<_, _>>()?;
          validate_deploy_options(name, &spec)?;
          if let Some(signal) = &mut spec.stop_signal {
            *signal =
              wharf_api_types::compose::normalize_stop_signal(
                signal,
              )?;
          }
          crate::shared_volumes::normalize(&mut spec)?;
          if spec.limits.as_ref().is_some_and(|l| {
            l.memory_mb.is_none() && l.cpu_milli.is_none()
          }) {
            spec.limits = None;
          }
          if let Source::Compose {
            content: Some(content),
            ..
          } = &spec.source
            && old.is_none_or(|old| {
              old.spec.source != spec.source
                || old.spec.container != spec.container
                || old.spec.limits != spec.limits
                || old.spec.env != spec.env
            })
          {
            crate::render::compose_with_settings(
              name, content, &spec,
            )?;
          }
          if let Some(limits) = &spec.limits {
            if limits.memory_mb.is_some_and(|n| n < 32) {
              return Err(ApiError::invalid("内存上限至少 32 MB"));
            }
            if limits.cpu_milli.is_some_and(|n| n < 10) {
              return Err(ApiError::invalid("CPU 上限至少 0.01 核"));
            }
          }
          if spec.auto_update {
            match &spec.source {
              Source::Compose { content, .. } => {
                if crate::pins::images(&spec.source).is_empty() {
                  return Err(
                    ApiError::invalid(format!(
                      "服务 {name} 的 compose 里没有可以检查更新的镜像"
                    ))
                    .with_hint("镜像写了 digest、用了变量或在本地构建时没法自动更新"),
                  );
                }
                if crate::import::compose_has_volumes(
                  content.as_deref().unwrap_or_default(),
                ) {
                  return Err(
                    ApiError::invalid(format!(
                      "服务 {name} 的 compose 里挂载了数据，不支持自动更新"
                    ))
                    .with_hint("有数据的服务升级可能要迁移数据，请手动检查更新"),
                  );
                }
              }
              Source::Build(build) if build.git.is_none() => {
                return Err(
                  ApiError::invalid(format!(
                    "服务 {name} 的代码是上传的，没有可以检查的新版本"
                  ))
                  .with_hint("自动更新只支持镜像来源和 git 构建来源"),
                );
              }
              Source::Image(image) if image.contains('@') => {
                return Err(
                  ApiError::invalid(format!(
                    "服务 {name} 的镜像固定在一个版本上，不会有新版本"
                  ))
                  .with_hint("镜像名去掉 @sha256:… 再开自动更新"),
                );
              }
              _ => {}
            }
            if !spec.volumes.is_empty() {
              return Err(ApiError::invalid(format!(
                "服务 {name} 有数据卷，新版本起不来时不能自动换回，不支持自动更新"
              )).with_hint(format!("用 wharf service update {name} 手动更新")));
            }
          }
          if spec.ports.is_empty()
            && let Source::Compose {
              content: Some(content),
              ..
            } = &spec.source
          {
            spec.ports = crate::import::compose_ports(content);
          }
          if let Some(m) = &spec.monitor {
            if !m.path.starts_with('/') {
              return Err(ApiError::invalid("监控路径要以 / 开头"));
            }
            if spec.ports.is_empty() {
              return Err(ApiError::invalid(format!(
                "服务 {name} 没有端口，监控不了"
              )));
            }
            if let Some(p) = &m.port
              && !spec.ports.iter().any(|x| &x.name == p)
            {
              return Err(ApiError::invalid(format!(
                "服务 {name} 没有端口 {p}"
              )));
            }
          }
          self.services.insert(
            name.clone(),
            ServiceRow {
              instance_id,
              spec,
              host_ports,
              import,
              pins,
              commit,
              version,
            },
          );
        }
        Change::RefreshImages { name, image } => {
          let row = self.services.get_mut(name).ok_or_else(|| {
            ApiError::not_found(format!("服务 {name} 不存在"))
              .suggest("wharf service list")
          })?;
          match image {
            Some(image) => {
              if !crate::pins::images(&row.spec.source)
                .contains(image)
              {
                return Err(
                  ApiError::invalid(format!(
                    "服务 {name} 里没有镜像 {image}"
                  ))
                  .with_hint("镜像名要和 compose 里写的一字不差")
                  .suggest(format!("wharf service show {name}")),
                );
              }
              row.pins.remove(image);
            }
            None => {
              row.pins.clear();
              row.commit = None;
            }
          }
        }
        Change::RetagImage { name, image, tag } => {
          let row = self.services.get_mut(name).ok_or_else(|| {
            ApiError::not_found(format!("服务 {name} 不存在"))
              .suggest("wharf service list")
          })?;
          row.spec.source =
            crate::pins::retag(&row.spec.source, image, tag)?;
          row.pins.remove(image);
        }
        Change::RemoveService { name, .. } => {
          if self.services.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("服务 {name} 不存在"))
                .suggest("wharf service list"),
            );
          }
        }
        Change::UpsertGateway { name, spec } => {
          validate_name("网关", name)?;
          let mut spec = spec.clone();
          if let Some(tp) = &mut spec.trusted_proxies {
            validate_gateway_proxies(name, spec.kind, tp)?;
            if tp.is_empty() {
              spec.trusted_proxies = None;
            }
          }
          let version =
            self.gateways.get(name).map(|g| g.version).unwrap_or(0);
          self
            .gateways
            .insert(name.clone(), GatewayRow { spec, version });
        }
        Change::RemoveGateway { name } => {
          if self.gateways.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("网关 {name} 不存在"))
                .suggest("wharf gateway list"),
            );
          }
        }
        Change::UpsertRoute { spec } => {
          let mut spec = spec.clone();
          spec.hostname = normalize_hostname(&spec.hostname)?;
          let existing = self.routes.get(&spec.hostname);
          if let Some(expires) = spec.expires_at
            && existing.and_then(|r| r.spec.expires_at)
              != Some(expires)
          {
            let now = chrono::Utc::now().timestamp_millis();
            if expires <= now {
              return Err(ApiError::invalid(format!(
                "临时分享 {} 的到期时间已经过了",
                spec.hostname
              )));
            }
            if expires > now + (7 * 86400 + 5 * 60) * 1000 {
              return Err(ApiError::invalid("临时分享最长 7 天"));
            }
          }
          let id = existing
            .map(|r| r.id.clone())
            .unwrap_or_else(|| new_id("rt"));
          let version = existing.map(|r| r.version).unwrap_or(0);
          self.routes.insert(
            spec.hostname.clone(),
            RouteRow { id, spec, version },
          );
        }
        Change::UpsertEdgeApp { name, spec }
        | Change::ImportEdgeApp { name, spec } => {
          if matches!(change, Change::ImportEdgeApp { .. }) {
            self.check_edge_import_name(name)?;
          }
          validate_name("边缘应用", name)?;
          let version =
            self.edge_apps.get(name).map(|r| r.version).unwrap_or(0);
          let mut spec = spec.clone();
          spec.domains = spec
            .domains
            .iter()
            .map(|d| normalize_hostname(d))
            .collect::<Result<_, _>>()?;
          spec.domains.sort();
          spec.domains.dedup();
          self
            .edge_apps
            .insert(name.clone(), EdgeRow { spec, version });
        }
        Change::RemoveEdgeApp { name } => {
          if self.edge_apps.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("边缘应用 {name} 不存在"))
                .suggest("wharf edge list"),
            );
          }
        }
        Change::RemoveRoute { hostname } => {
          let hostname = normalize_hostname(hostname)?;
          if self.routes.remove(&hostname).is_none() {
            return Err(
              ApiError::not_found(format!("路由 {hostname} 不存在"))
                .suggest("wharf route list"),
            );
          }
        }
      }
    }
    Ok(())
  }

  /// 用完整的意图文件替换期望状态。服务器只更新设置，不增删。
  /// 以意图文件为完整期望状态：文件里没有的服务、网关、路由、边缘应用、书签都删掉。
  pub fn replace_with(
    &mut self,
    fleet: &Fleet,
  ) -> Result<(), ApiError> {
    let keep_routes = route_hosts(fleet)?;
    self
      .services
      .retain(|name, _| fleet.services.contains_key(name));
    self
      .edge_apps
      .retain(|name, _| fleet.edge_apps.contains_key(name));
    self
      .gateways
      .retain(|name, _| fleet.gateways.contains_key(name));
    self.routes.retain(|host, _| keep_routes.contains(host));
    self
      .bookmarks
      .retain(|id, _| fleet.bookmarks.contains_key(id));
    self.merge_with(fleet)
  }

  /// 局部期望状态：只新建或整体替换文件里写到的对象，其余不动。
  pub fn merge_with(
    &mut self,
    fleet: &Fleet,
  ) -> Result<(), ApiError> {
    route_hosts(fleet)?;
    let mut changes = Vec::new();
    for (name, settings) in &fleet.servers {
      changes.push(Change::UpdateServer {
        name: name.clone(),
        settings: settings.clone(),
      });
    }
    for (id, spec) in &fleet.bookmarks {
      let version = self.bookmarks.get(id).map_or(0, |r| r.version);
      let spec = check_bookmark(spec.clone())?;
      self
        .bookmarks
        .insert(id.clone(), BookmarkRow { spec, version });
    }
    for (name, spec) in &fleet.services {
      changes.push(Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: name.clone(),
        spec: spec.clone(),
        adopt: None,
      });
    }
    for (name, spec) in &fleet.gateways {
      changes.push(Change::UpsertGateway {
        name: name.clone(),
        spec: spec.clone(),
      });
    }
    for (name, spec) in &fleet.edge_apps {
      changes.push(Change::UpsertEdgeApp {
        name: name.clone(),
        spec: spec.clone(),
      });
    }
    for spec in &fleet.routes {
      changes.push(Change::UpsertRoute { spec: spec.clone() });
    }
    self.apply_changes(&changes)
  }

  pub fn default_gateway(&self) -> Option<&str> {
    self
      .gateways
      .iter()
      .find(|(_, g)| g.spec.default)
      .map(|(name, _)| name.as_str())
  }

  /// 路由实际使用的网关。
  pub fn route_gateway<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    route.gateway.as_deref().or_else(|| self.default_gateway())
  }

  /// 路由经过的全部网关：主网关，加上备用入口。
  pub fn route_gateways<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Vec<&'a str> {
    let mut out: Vec<&str> =
      self.route_gateway(route).into_iter().collect();
    if let Some(b) = route.backup_gateway.as_deref()
      && !out.contains(&b)
    {
      out.push(b);
    }
    out
  }

  /// 现在 DNS 应该指向的网关：切到备用入口时是备用网关。
  pub fn live_gateway<'a>(
    &'a self,
    host: &str,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    match route.backup_gateway.as_deref() {
      Some(b) if crate::failover::active(host) => Some(b),
      _ => self.route_gateway(route),
    }
  }

  /// 绑定了这个域名的边缘应用。
  pub fn edge_domain(&self, host: &str) -> Option<(&str, &EdgeRow)> {
    self
      .edge_apps
      .iter()
      .find(|(_, a)| a.spec.domains.iter().any(|d| d == host))
      .map(|(n, a)| (n.as_str(), a))
  }

  /// Wharf 写的 DNS 记录归谁：路由用路由 id，边缘域名用 `edge:<域名>`。
  pub fn dns_owner(&self, host: &str) -> Option<String> {
    match self.routes.get(host) {
      Some(r) => Some(r.id.clone()),
      None => self.edge_domain(host).map(|_| edge_owner(host)),
    }
  }

  /// 路由的上游地址：直接写的地址，或按服务算出来的。
  pub fn route_upstream(
    &self,
    net: &crate::render::Net,
    gateway: &wharf_api_types::spec::GatewaySpec,
    host: &str,
    route: &RouteSpec,
  ) -> Result<String, ApiError> {
    if let Some(up) = &route.upstream {
      return Ok(up.clone());
    }
    let port = self.route_port(route).ok_or_else(|| {
      ApiError::invalid(format!("路由 {host} 没有可用的端口"))
    })?;
    crate::render::upstream(
      self,
      net,
      gateway,
      &route.service,
      port,
      route.link,
    )
  }

  /// 路由指向的端口名。
  pub fn route_port<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    self.service_port(&route.service, route.port.as_deref())
  }

  /// 服务的端口名：指定了就用，只有一个端口时取它。
  pub fn service_port<'a>(
    &'a self,
    service: &str,
    port: Option<&'a str>,
  ) -> Option<&'a str> {
    let service = self.services.get(service)?;
    match port {
      Some(port) => Some(port),
      None if service.spec.ports.len() == 1 => {
        Some(service.spec.ports[0].name.as_str())
      }
      None => None,
    }
  }

  fn validate_paths(
    &self,
    host: &str,
    route: &RouteSpec,
  ) -> Result<(), ApiError> {
    if route.paths.is_empty() {
      return Ok(());
    }
    let bad =
      |m: String| Err(ApiError::invalid(format!("路由 {host}：{m}")));
    if self.route_gateways(route).iter().any(|gw| {
      self
        .gateways
        .get(*gw)
        .is_some_and(|g| g.spec.kind != GatewayKind::Caddy)
    }) {
      return bad("按路径转发只支持 caddy 网关".into());
    }
    let mut seen = BTreeSet::new();
    for p in &route.paths {
      if let Err(message) = validate_route_path(&p.path) {
        return bad(format!("路径 {}：{message}", p.path));
      }
      if !seen.insert(p.path.as_str()) {
        return bad(format!("路径 {} 重复", p.path));
      }
      match (&p.service, &p.upstream) {
        (Some(service), None) => {
          if !self.services.contains_key(service) {
            return bad(format!(
              "路径 {} 指向的服务 {service} 不存在",
              p.path
            ));
          }
          let Some(port) =
            self.service_port(service, p.port.as_deref())
          else {
            return bad(format!(
              "路径 {} 要指定服务 {service} 的端口",
              p.path
            ));
          };
          if !self.services[service]
            .spec
            .ports
            .iter()
            .any(|x| x.name == port)
          {
            return bad(format!(
              "服务 {service} 没有名为 {port} 的端口"
            ));
          }
          if self.services[service]
            .spec
            .ports
            .iter()
            .any(|p| p.name == port && p.udp)
          {
            return bad(format!(
              "服务 {service} 的端口 {port} 是 UDP，不能给域名用"
            ));
          }
        }
        (None, Some(up)) => {
          if p.port.is_some() || !valid_upstream(up) {
            return bad(format!(
              "路径 {} 的上游 {up} 要写成 主机:端口，例如 127.0.0.1:8080",
              p.path
            ));
          }
        }
        _ => {
          return bad(format!(
            "路径 {} 要指定服务或上游（二选一）",
            p.path
          ));
        }
      }
    }
    Ok(())
  }

  fn check_route_gateway(
    &self,
    host: &str,
    route: &RouteSpec,
  ) -> Result<(), ApiError> {
    match self.route_gateway(route) {
      None => Err(
        ApiError::invalid(format!(
          "路由 {host} 没有指定网关，也没有默认网关"
        ))
        .with_hint("先创建一个默认网关")
        .suggest(
          "wharf gateway add <name> --server <server> --default",
        ),
      ),
      Some(gw) if !self.gateways.contains_key(gw) => Err(
        ApiError::invalid(format!("路由 {host} 的网关 {gw} 不存在"))
          .suggest("wharf gateway list"),
      ),
      Some(primary) => match route.backup_gateway.as_deref() {
        None => Ok(()),
        Some(b) if b == primary => Err(ApiError::invalid(format!(
          "路由 {host} 的备用入口和主网关是同一个 {b}"
        ))),
        Some(b) => match self.gateways.get(b) {
          None => Err(
            ApiError::invalid(format!(
              "路由 {host} 的备用入口 {b} 不存在"
            ))
            .suggest("wharf gateway list"),
          ),
          Some(g)
            if g.spec.server
              == self.gateways[primary].spec.server =>
          {
            Err(ApiError::invalid(format!(
              "路由 {host} 的备用入口 {b} 和主网关在同一台机器上，起不到备用作用"
            )))
          }
          Some(_) => Ok(()),
        },
      },
    }
  }

  fn check_redirect(
    &self,
    host: &str,
    route: &RouteSpec,
    target: &str,
  ) -> Result<(), ApiError> {
    if !route.service.is_empty()
      || route.upstream.is_some()
      || route.port.is_some()
      || !route.paths.is_empty()
      || route.auth
      || route.link != LinkMode::Auto
    {
      return Err(ApiError::invalid(format!(
        "路由 {host}：跳转不能和服务、上游、端口、按路径转发、登录保护、反向隧道同时设置"
      )));
    }
    let target_host = redirect_host(target).ok_or_else(|| {
      ApiError::invalid(format!(
        "路由 {host} 的跳转目标 {target} 不合法"
      ))
      .with_hint(
        "写成 https://主机[:端口][/路径]，不带 ?、#，末尾不带 /",
      )
    })?;
    if target_host.eq_ignore_ascii_case(host) {
      return Err(ApiError::invalid(format!(
        "路由 {host} 不能跳转到自己"
      )));
    }
    if self.route_gateways(route).iter().any(|name| {
      self.gateways[*name].spec.kind == GatewayKind::CloudflareTunnel
    }) {
      return Err(ApiError::invalid(format!(
        "路由 {host}：跳转只支持 caddy 网关"
      )));
    }
    Ok(())
  }

  /// 整体校验。`joined` 是已经完成 join 的服务器。
  #[cfg(test)]
  pub fn validate(&self) -> Result<(), ApiError> {
    self.validate_against(&Self::default())
  }

  pub fn validate_against(
    &self,
    current: &Self,
  ) -> Result<(), ApiError> {
    crate::oidc::validate_names(self)?;
    crate::secret_policy::validate_world(self)?;
    for (name, server) in &self.servers {
      crate::link::validate_private_addr(
        name,
        server.settings.private_addr.as_ref(),
      )?;
    }
    for (name, service) in &self.services {
      validate_service(self, name, &service.spec)?;
      if let Some(monitor) = &service.spec.monitor {
        let old = current
          .services
          .get(name)
          .and_then(|row| row.spec.monitor.as_ref());
        crate::monitor::validate(monitor, old)?;
      }
      crate::service_monitor::validate(
        &service.spec,
        current.services.get(name).map(|row| &row.spec),
      )?;
    }
    crate::shared_volumes::validate_world(self)?;
    for (name, app) in &self.edge_apps {
      crate::edge::validate_app(self, name, &app.spec)?;
    }
    let defaults: Vec<&String> = self
      .gateways
      .iter()
      .filter(|(_, g)| g.spec.default)
      .map(|(n, _)| n)
      .collect();
    if defaults.len() > 1 {
      return Err(ApiError::invalid(format!(
        "默认网关只能有一个，现在有：{}",
        defaults
          .iter()
          .map(|s| s.as_str())
          .collect::<Vec<_>>()
          .join("、")
      )));
    }
    let mut forwards = BTreeSet::new();
    for (name, gateway) in &self.gateways {
      validate_gateway(
        name,
        &gateway.spec,
        current.gateways.get(name).map(|old| &old.spec),
      )?;
      crate::entry_protection::validate_gateway(name, &gateway.spec)?;
      if !self.servers.contains_key(&gateway.spec.server) {
        return Err(server_not_found(&gateway.spec.server));
      }
      if let Some(tp) = &gateway.spec.trusted_proxies {
        validate_gateway_proxies(
          name,
          gateway.spec.kind,
          &mut tp.clone(),
        )?;
      }
      if gateway.spec.kind == GatewayKind::CloudflareTunnel {
        let s = &gateway.spec;
        if s.account.is_none() {
          return Err(
            ApiError::invalid(format!(
              "网关 {name} 是 cloudflare_tunnel，要指定在哪个厂商账号下建隧道"
            ))
            .suggest("wharf account list"),
          );
        }
        if s.http_port.is_some()
          || s.https_port.is_some()
          || s.email.is_some()
          || s.tls != GatewayTls::Auto
          || s.error_page.is_some()
        {
          return Err(ApiError::invalid(format!(
            "网关 {name}：http_port、https_port、email、tls、error_page 只适用于 caddy 网关"
          )));
        }
        if !s.layer4.is_empty() {
          return Err(ApiError::invalid(format!(
            "网关 {name}：四层转发只适用于 caddy 网关"
          )));
        }
        if !s.wildcard.is_empty() {
          return Err(ApiError::invalid(format!(
            "网关 {name}：泛域名证书只适用于 caddy 网关"
          )));
        }
        continue;
      }
      if gateway.spec.tls == GatewayTls::Off
        && !gateway.spec.wildcard.is_empty()
      {
        return Err(ApiError::invalid(format!(
          "入口 {name} 只走 HTTP，不能开泛域名证书"
        )));
      }
      let mut zones = std::collections::BTreeSet::new();
      for zone in &gateway.spec.wildcard {
        if zone.starts_with("*.")
          || normalize_hostname(zone).ok().as_ref() != Some(zone)
        {
          return Err(ApiError::invalid(format!(
            "入口 {name} 的泛域名证书写 zone 本身，例如 example.com"
          )));
        }
        if !zones.insert(zone) {
          return Err(ApiError::invalid(format!(
            "入口 {name} 的泛域名证书 {zone} 写了两次"
          )));
        }
      }
      let http = gateway.spec.http_port.unwrap_or(80);
      let https = gateway.spec.https_port.unwrap_or(443);
      if http == https {
        return Err(ApiError::invalid(format!(
          "网关 {name} 的 http_port 和 https_port 不能相同"
        )));
      }
      let server = &gateway.spec.server;
      for f in &gateway.spec.layer4 {
        let listen = f.listen;
        match (&f.service, &f.upstream) {
          (Some(svc), None) => {
            let service = self.services.get(svc).ok_or_else(|| ApiError::invalid(format!("入口 {name} 的四层转发 {listen} 指向的服务 {svc} 不存在")).suggest("wharf service list"))?;
            let port = self.service_port(svc, f.port.as_deref()).ok_or_else(|| ApiError::invalid(format!("入口 {name} 的四层转发 {listen}：找不到服务 {svc} 的端口")).with_hint("服务有多个端口时要写端口名"))?;
            let target = service.spec.ports.iter().find(|p| p.name == port).ok_or_else(|| ApiError::invalid(format!("入口 {name} 的四层转发 {listen}：找不到服务 {svc} 的端口")).with_hint("服务有多个端口时要写端口名"))?;
            if f.udp != target.udp {
              return Err(ApiError::invalid(format!(
                "入口 {name} 的四层转发 {listen}：协议和服务 {svc} 的端口 {port} 不一致"
              )));
            }
          }
          (None, Some(up)) => {
            if !valid_upstream(up) {
              return Err(ApiError::invalid(format!(
                "入口 {name} 的四层转发 {listen} 的上游 {up} 要写成 主机:端口"
              )));
            }
            if crate::host_access::is_metadata_upstream(up) {
              return Err(ApiError::invalid(format!(
                "入口 {name} 的四层转发 {listen} 不能指向云元数据或链路本地地址 {up}"
              )));
            }
          }
          _ => {
            return Err(ApiError::invalid(format!(
              "入口 {name} 的四层转发 {listen}：服务和上游二选一"
            )));
          }
        }
        if is_reserved_host_port(listen)
          || matches!(listen, 80 | 443)
          || self.gateways.values().any(|g| {
            g.spec.kind == GatewayKind::Caddy
              && g.spec.server == *server
              && (listen == g.spec.http_port.unwrap_or(80)
                || listen == g.spec.https_port.unwrap_or(443))
          })
        {
          return Err(ApiError::invalid(format!(
            "入口 {name} 的四层转发端口 {listen} 被 Wharf 占用或保留，换一个"
          )));
        }
        if !forwards.insert((server, f.udp, listen)) {
          return Err(ApiError::invalid(format!(
            "服务器 {server} 上的端口 {listen} 被多个四层转发使用"
          )));
        }
        for (svc, service) in &self.services {
          if service.spec.server == *server
            && service.host_ports.values().any(|p| *p == listen)
          {
            return Err(ApiError::invalid(format!(
              "服务器 {server} 上的端口 {listen} 已经给了服务 {svc}"
            )));
          }
        }
      }
      if let Some(page) = &gateway.spec.error_page {
        check_error_page(name, page)?;
      }
    }
    for (host, route) in &self.routes {
      validate_route_hostname(host, &route.spec.hostname)?;
      if self.edge_apps.contains_key(&route.spec.service) {
        return Err(
          ApiError::invalid(format!(
            "路由 {host} 指向边缘应用 {}：边缘应用的域名写在应用自己的 domains 里",
            route.spec.service
          ))
          .suggest(format!(
            "wharf edge domain add {} {host}",
            route.spec.service
          )),
        );
      }
      self.check_route_gateway(host, &route.spec)?;
      crate::entry_protection::validate_route(
        self,
        host,
        &route.spec,
      )?;
      if let Some(sso) = &route.spec.sso {
        crate::sso_login::validate(host, sso)?;
        if let Some(header) = &sso.header {
          if sso.mode != wharf_api_types::spec::SsoMode::Header {
            return Err(ApiError::invalid(format!(
              "域名 {host}：只有 header 方式才能设请求头名字"
            )));
          }
          if header.is_empty()
            || header.len() > 64
            || !header.as_bytes()[0].is_ascii_alphabetic()
            || !header
              .bytes()
              .all(|b| b.is_ascii_alphanumeric() || b == b'-')
          {
            return Err(ApiError::invalid(format!(
              "域名 {host}：请求头名字 {header} 写得不对"
            )));
          }
          let lower = header.to_ascii_lowercase();
          if matches!(
            lower.as_str(),
            "cookie" | "host" | "authorization" | "x-wharf-key"
          ) || lower.starts_with("x-forwarded-")
          {
            return Err(ApiError::invalid(format!(
              "域名 {host}：不能用 {header} 做用户名请求头"
            )));
          }
        }
        if route.spec.auth {
          return Err(ApiError::invalid(format!(
            "域名 {host}：门禁和登录保护只能开一个"
          )));
        }
        if route.spec.redirect.is_some() {
          return Err(ApiError::invalid(format!(
            "域名 {host}：跳转的域名不能开门禁"
          )));
        }
        if self.route_gateways(&route.spec).iter().any(|name| {
          self.gateways[*name].spec.kind != GatewayKind::Caddy
        }) {
          return Err(ApiError::invalid(format!(
            "域名 {host}：Cloudflare 隧道入口不支持门禁"
          )));
        }
        for path in &sso.skip_paths {
          if sso.skip_paths.len() > 20
            || crate::gate::normalize_skip_path(path).is_err()
          {
            return Err(ApiError::invalid(format!(
              "域名 {host}：排除的路径 {path} 写得不对"
            )));
          }
        }
      }
      if route.spec.caddy_file.is_some() {
        return Err(
          ApiError::invalid(format!(
            "路由 {host} 的 caddy_file 需要由 CLI 读取后提交"
          ))
          .with_hint("用 wharf plan -f 提交，CLI 会自动读取外置文件"),
        );
      }
      if let Some(custom) = &route.spec.caddy {
        let bad = |m: &str| {
          Err(ApiError::invalid(format!(
            "路由 {host}：自定义 Caddy 配置{m}"
          )))
        };
        if route.spec.redirect.is_some() {
          return bad("不能用在跳转上");
        }
        if self.route_gateways(&route.spec).iter().any(|name| {
          self.gateways[*name].spec.kind != GatewayKind::Caddy
        }) {
          return bad("只支持 caddy 网关");
        }
        if let Err(m) = check_custom_caddy_boundaries(custom) {
          return bad(m);
        }
      }
      if route.spec.rate_limit.is_some() || route.spec.block_scanners
      {
        if route.spec.redirect.is_some() {
          return Err(ApiError::invalid(format!(
            "路由 {host}：跳转不能设置限速和拦截扫描"
          )));
        }
        if self.route_gateways(&route.spec).iter().any(|name| {
          self.gateways[*name].spec.kind
            == GatewayKind::CloudflareTunnel
        }) {
          return Err(ApiError::invalid(format!(
            "路由 {host}：限速和拦截扫描只支持 caddy 网关"
          )));
        }
      }
      if route
        .spec
        .rate_limit
        .is_some_and(|n| !(10..=100000).contains(&n))
      {
        return Err(ApiError::invalid(format!(
          "路由 {host} 的限速要在每分钟 10 到 100000 次之间"
        )));
      }
      if let Some(minutes) = route.spec.failover_minutes {
        if !(1..=60).contains(&minutes) {
          return Err(ApiError::invalid(format!(
            "路由 {host} 的 failover_minutes 必须在 1 到 60 分钟之间"
          )));
        }
        if route.spec.backup_gateway.is_none() {
          return Err(ApiError::invalid(format!(
            "路由 {host} 配置 failover_minutes 前需要配置备用入口"
          )));
        }
      }
      if let Some(ttl) = route.spec.dns_ttl.filter(|ttl| *ttl != 1) {
        if !(60..=86400).contains(&ttl) {
          return Err(ApiError::invalid(format!(
            "路由 {host} 的 dns_ttl 必须是 1（自动）或 60 到 86400 秒之间"
          )));
        }
        if self.route_gateways(&route.spec).iter().all(|gw| {
          self.gateways[*gw].spec.kind
            == GatewayKind::CloudflareTunnel
        }) {
          return Err(ApiError::invalid(format!(
            "路由 {host} 走 Cloudflare 隧道（代理记录），TTL 固定由厂商自动管理，不能自定义 dns_ttl"
          )));
        }
      }
      if route.spec.internal {
        if route.spec.redirect.is_some() {
          return Err(ApiError::invalid(format!(
            "路由 {host}：跳转不能设成只在内网访问"
          )));
        }
        if self.route_gateways(&route.spec).iter().any(|name| {
          self.gateways[*name].spec.kind
            == GatewayKind::CloudflareTunnel
        }) {
          return Err(ApiError::invalid(format!(
            "路由 {host}：只在内网访问只支持 caddy 网关"
          )));
        }
        if route.spec.backup_gateway.is_some() {
          return Err(ApiError::invalid(format!(
            "路由 {host}：只在内网访问的域名不能设备用入口"
          )));
        }
        if let Some(gw) = self.route_gateway(&route.spec)
          && self.gateways[gw].spec.wildcard.contains(host)
        {
          return Err(ApiError::invalid(format!(
            "路由 {host}：它是入口 {gw} 泛域名证书的 zone 本身，不能设成只在内网访问"
          )));
        }
      }
      if route.spec.expires_at.is_some() {
        if route.spec.service.is_empty() {
          return Err(ApiError::invalid(format!(
            "路由 {host}：临时分享只能指向服务"
          )));
        }
        if route.spec.backup_gateway.is_some()
          || self.route_gateways(&route.spec).iter().any(|name| {
            self.gateways[*name].spec.kind
              == GatewayKind::CloudflareTunnel
          })
        {
          return Err(ApiError::invalid(format!(
            "路由 {host}：临时分享只支持 caddy 入口，不能设备用入口"
          )));
        }
        if let Some(gw) = self.route_gateway(&route.spec)
          && !self.gateways[gw].spec.wildcard.iter().any(|zone| {
            host.split_once('.').is_some_and(|(_, rest)| rest == zone)
          })
        {
          return Err(ApiError::invalid(format!(
            "路由 {host}：临时分享的域名要在入口 {gw} 的泛域名证书下"
          )).suggest(format!("wharf gateway wildcard {gw} --zone <zone> --apply"))
            .with_hint(format!("要关掉泛域名证书，先删掉这个分享：wharf route rm {host} --apply")));
        }
      }
      if let Some(target) = &route.spec.redirect {
        self.check_redirect(host, &route.spec, target)?;
        continue;
      }
      if let Some(up) = &route.spec.upstream {
        if !route.spec.service.is_empty() || route.spec.port.is_some()
        {
          return Err(ApiError::invalid(format!(
            "路由 {host}：服务和上游地址二选一"
          )));
        }
        if !valid_upstream(up) {
          return Err(ApiError::invalid(format!(
            "路由 {host} 的上游 {up} 要写成 主机:端口，例如 127.0.0.1:8080"
          )));
        }
        self.validate_paths(host, &route.spec)?;
        continue;
      }
      let Some(service) = self.services.get(&route.spec.service)
      else {
        return Err(
          ApiError::invalid(format!(
            "路由 {host} 指向的服务 {} 不存在",
            route.spec.service
          ))
          .suggest("wharf service list"),
        );
      };
      let Some(port) = self.route_port(&route.spec) else {
        let names: Vec<&str> = service
          .spec
          .ports
          .iter()
          .map(|p| p.name.as_str())
          .collect();
        return Err(if names.is_empty() {
          ApiError::invalid(format!(
            "服务 {} 没有声明端口，路由 {host} 无处可去",
            route.spec.service
          ))
          .with_hint("给服务加上 --port，例如 --port http=80")
        } else {
          ApiError::invalid(format!(
            "服务 {} 有多个端口，路由 {host} 需要指定 --port（可选：{}）",
            route.spec.service,
            names.join("、")
          ))
        });
      };
      if !service.spec.ports.iter().any(|p| p.name == port) {
        return Err(ApiError::invalid(format!(
          "服务 {} 没有名为 {port} 的端口",
          route.spec.service
        )));
      }
      if service.spec.ports.iter().any(|p| p.name == port && p.udp) {
        let svc = &route.spec.service;
        return Err(ApiError::invalid(format!(
          "路由 {host}：服务 {svc} 的端口 {port} 是 UDP，不能给域名用"
        )));
      }
      self.validate_paths(host, &route.spec)?;
    }
    Ok(())
  }

  /// 为 image 来源的服务分配宿主机端口：保留已有分配，新端口从 20000 起取最小空闲值。
  /// 宿主机端口在同一台服务器上唯一。
  #[cfg(test)]
  pub fn allocate_ports(&mut self) -> Result<(), ApiError> {
    self.allocate_ports_with(&BTreeMap::new())
  }

  pub fn allocate_ports_with(
    &mut self,
    reserved: &BTreeMap<String, BTreeMap<u16, String>>,
  ) -> Result<(), ApiError> {
    let mut used: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let mut take = |server: &str, port: u16| {
      used.entry(server.to_string()).or_default().insert(port)
    };
    // 第一轮：固定端口（填了 host 的）和已有分配。
    let names: Vec<String> = self.services.keys().cloned().collect();
    let mut pending: Vec<(String, String)> = Vec::new();
    for name in &names {
      let service = &self.services[name];
      let server = service.spec.server.clone();
      let mut assigned = BTreeMap::new();
      let mut compose_bindings = BTreeSet::new();
      for port in &service.spec.ports {
        let fixed = port.host;
        let chosen = fixed
          .or_else(|| service.host_ports.get(&port.name).copied());
        match chosen {
          Some(p) => {
            let shared = fixed.is_some()
              && matches!(
                service.spec.source,
                Source::Compose { .. }
              )
              && compose_bindings.contains(&(p, !port.udp))
              && !compose_bindings.contains(&(p, port.udp));
            if let Some(owner) = reserved
              .get(&server)
              .and_then(|r| r.get(&p))
              .filter(|owner| *owner != name)
            {
              if fixed.is_some() {
                return Err(ApiError::invalid(format!(
                  "服务器 {server} 上宿主机端口 {p} 仍被本轮稍后下线的服务 {owner} 占用"
                )).with_hint("先下线或迁走旧服务，或为新服务换一个端口"));
              }
              pending.push((name.clone(), port.name.clone()));
            } else if !shared && !take(&server, p) {
              if fixed.is_some() {
                return Err(ApiError::invalid(format!(
                  "服务器 {server} 上宿主机端口 {p} 被多个服务使用（服务 {name}）"
                )));
              }
              pending.push((name.clone(), port.name.clone()));
            } else {
              assigned.insert(port.name.clone(), p);
              if fixed.is_some() {
                compose_bindings.insert((p, port.udp));
              }
            }
          }
          None => pending.push((name.clone(), port.name.clone())),
        }
      }
      self.services.get_mut(name).unwrap().host_ports = assigned;
    }
    for gateway in self.gateways.values() {
      if gateway.spec.kind == GatewayKind::Caddy {
        for f in &gateway.spec.layer4 {
          used
            .entry(gateway.spec.server.clone())
            .or_default()
            .insert(f.listen);
        }
      }
    }
    for (name, port_name) in pending {
      let server = self.services[&name].spec.server.clone();
      let set = used.entry(server.clone()).or_default();
      let port = HOST_PORTS
        .clone()
        .find(|p| {
          !set.contains(p)
            && !reserved
              .get(&server)
              .is_some_and(|r| r.contains_key(p))
        })
        .ok_or_else(|| {
          ApiError::internal(format!(
            "服务器 {server} 上没有空闲端口了"
          ))
        })?;
      set.insert(port);
      self
        .services
        .get_mut(&name)
        .unwrap()
        .host_ports
        .insert(port_name, port);
    }
    Ok(())
  }

  /// 把期望状态和当前状态的差异转成数据库写入。
  pub fn writes_from(&self, current: &World) -> Vec<Write> {
    let mut out = Vec::new();
    diff_map(
      &current.servers,
      &self.servers,
      KIND_SERVER,
      |r| (to_json(&r.settings), json!({})),
      &mut out,
    );
    diff_map(
      &current.services,
      &self.services,
      KIND_SERVICE,
      |r| {
        let mut meta = json!({ "host_ports": r.host_ports, "instance_id": r.instance_id });
        if let Some(import) = &r.import {
          meta["import"] = to_json(import);
        }
        if !r.pins.is_empty() {
          meta["pins"] = to_json(&r.pins);
        }
        if let Some(commit) = &r.commit {
          meta["commit"] = json!(commit);
        }
        (to_json(&r.spec), meta)
      },
      &mut out,
    );
    diff_map(
      &current.gateways,
      &self.gateways,
      KIND_GATEWAY,
      |r| (to_json(&r.spec), json!({})),
      &mut out,
    );
    diff_map(
      &current.routes,
      &self.routes,
      KIND_ROUTE,
      |r| (to_json(&r.spec), json!({ "id": r.id })),
      &mut out,
    );
    diff_map(
      &current.edge_apps,
      &self.edge_apps,
      KIND_EDGE,
      |r| (to_json(&r.spec), json!({})),
      &mut out,
    );
    diff_map(
      &current.bookmarks,
      &self.bookmarks,
      KIND_BOOKMARK,
      |r| (to_json(&r.spec), json!({})),
      &mut out,
    );
    out
  }
}

fn check_bookmark(
  mut spec: BookmarkSpec,
) -> Result<BookmarkSpec, ApiError> {
  spec.title = spec.title.trim().to_string();
  if !(1..=40).contains(&spec.title.chars().count()) {
    return Err(ApiError::invalid("书签标题要 1 到 40 个字"));
  }
  if !(spec.url.starts_with("http://")
    || spec.url.starts_with("https://"))
    || spec.url.len() > 2048
    || spec.url.contains(char::is_whitespace)
  {
    return Err(ApiError::invalid(
      "书签网址要以 http:// 或 https:// 开头",
    ));
  }
  spec.group = spec
    .group
    .map(|g| g.trim().to_string())
    .filter(|g| !g.is_empty());
  if spec.group.as_ref().is_some_and(|g| g.chars().count() > 20) {
    return Err(ApiError::invalid("书签分组要 1 到 20 个字"));
  }
  Ok(spec)
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
  serde_json::to_value(v).unwrap_or(Value::Null)
}

fn diff_map<T>(
  before: &BTreeMap<String, T>,
  after: &BTreeMap<String, T>,
  kind: &str,
  encode: impl Fn(&T) -> (Value, Value),
  out: &mut Vec<Write>,
) {
  for (name, row) in after {
    let (spec, meta) = encode(row);
    let changed = match before.get(name) {
      None => true,
      Some(old) => encode(old) != (spec.clone(), meta.clone()),
    };
    if changed {
      out.push(Write::Upsert {
        kind: kind.to_string(),
        name: name.clone(),
        spec,
        meta,
      });
    }
  }
  for name in before.keys() {
    if !after.contains_key(name) {
      out.push(Write::Delete {
        kind: kind.to_string(),
        name: name.clone(),
      });
    }
  }
}

/// 代码来源（本机上传或 git）和相对路径的校验，服务和边缘应用共用。
/// `what` 例如"服务 api"。
pub fn check_code_source(
  what: &str,
  upload: Option<&String>,
  git: Option<&wharf_api_types::spec::GitSource>,
  paths: &[&Option<String>],
) -> Result<(), ApiError> {
  let bad = |m: &str| Err(ApiError::invalid(format!("{what} 的{m}")));
  match (upload, git) {
    (Some(sha), None) => {
      if sha.len() != 64
        || !sha.bytes().all(|c| c.is_ascii_hexdigit())
      {
        return bad("代码包 sha256 不合法");
      }
    }
    (None, Some(git)) => {
      let repo = git.repo.trim();
      if !repo.starts_with("https://")
        || repo.contains(char::is_whitespace)
        || repo.contains('@')
      {
        return Err(
          ApiError::invalid(format!(
            "{what} 的 git 仓库要写 https 地址，不要带账号密码"
          ))
          .with_hint(
            "私有仓库把 token 存成密钥，用 token_secret 引用",
          ),
        );
      }
      if git.reference.trim().is_empty()
        || git.reference.contains(char::is_whitespace)
        || git.reference.starts_with('-')
      {
        return bad("git ref 不合法");
      }
      if let Some(secret) = &git.token_secret {
        crate::api::check_secret_name(secret)?;
      }
      if git.user.as_deref().is_some_and(|user| {
        user.trim().is_empty()
          || user.len() > 64
          || user.contains(|c: char| {
            c.is_control() || matches!(c, ':' | '@')
          })
      }) {
        return bad("git 认证用户名不合法");
      }
    }
    _ => {
      return Err(ApiError::invalid(format!(
        "{what}：代码来源要给出 upload（本机目录）或 git 仓库，二选一"
      )));
    }
  }
  for p in paths.iter().copied().flatten() {
    let p = p.trim_start_matches("./");
    if p.is_empty()
      || p.starts_with('/')
      || p.split('/').any(|seg| seg == "..")
    {
      return bad(&format!("路径 {p} 不合法：要写代码里的相对路径"));
    }
  }
  Ok(())
}

/// 构建来源：代码来源二选一，路径只能是代码里的相对路径。
fn check_build(name: &str, b: &BuildSource) -> Result<(), ApiError> {
  let bad = |what: &str| {
    Err(ApiError::invalid(format!("服务 {name} 的{what}")))
  };
  check_code_source(
    &format!("服务 {name}"),
    b.upload.as_ref(),
    b.git.as_ref(),
    &[&b.path, &b.dockerfile],
  )?;
  if b.base.as_deref().is_some_and(|i| {
    i.trim().is_empty() || i.contains(char::is_whitespace)
  }) {
    return bad("基础镜像名不合法");
  }
  if b.start.as_deref().is_some_and(|s| s.trim().is_empty()) {
    return bad("启动命令为空");
  }
  if b.install.as_deref().is_some_and(|s| s.trim().is_empty()) {
    return bad("安装命令为空");
  }
  if let Some(t) = &b.template
    && !wharf_api_types::build::TEMPLATES
      .iter()
      .any(|(id, ..)| id == t)
  {
    return bad(&format!(
      "模板 {t} 不存在，可选：python、node、go、static"
    ));
  }
  if let Some(content) = &b.dockerfile_content {
    if content.trim().is_empty() {
      return bad("Dockerfile 内容为空");
    }
    if b.dockerfile.is_some()
      || b.template.is_some()
      || b.base.is_some()
      || b.start.is_some()
      || b.install.is_some()
    {
      return bad(
        "写了 Dockerfile 内容时，不再用 dockerfile、template、base、start、install",
      );
    }
  }
  Ok(())
}

pub fn server_not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("服务器 {name} 不存在"))
    .with_hint("先用 wharf server add 加入服务器")
    .suggest("wharf server list")
}

/// 意图文件里的域名（规范化后），同一个写了两次时报错。
fn route_hosts(fleet: &Fleet) -> Result<BTreeSet<String>, ApiError> {
  let mut hosts = BTreeSet::new();
  for route in &fleet.routes {
    let hostname = normalize_hostname(&route.hostname)?;
    if !hosts.insert(hostname.clone()) {
      return Err(ApiError::invalid(format!(
        "意图文件里路由 {hostname} 出现了两次"
      )));
    }
  }
  Ok(hosts)
}

fn validate_gateway_proxies(
  name: &str,
  kind: GatewayKind,
  spec: &mut wharf_api_types::trusted_proxies::TrustedProxiesSpec,
) -> Result<(), ApiError> {
  if kind != GatewayKind::Caddy {
    return Err(ApiError::invalid(format!(
      "网关 {name}：可信代理只适用于 caddy 网关"
    )));
  }
  spec.normalize()
}

pub fn normalize_hostname(
  hostname: &str,
) -> Result<String, ApiError> {
  wharf_providers::validate::normalize_hostname(hostname)
    .map_err(|e| ApiError::invalid(e.message))
}

pub(crate) fn is_reserved_host_port(port: u16) -> bool {
  [
    0,
    22,
    crate::link::FRPS_PORT,
    7700,
    wharf_api_types::agent::PROBE_PORT,
    wharf_api_types::agent::REST_SERVER_PORT,
    wharf_api_types::agent::CORE_REST_SERVER_PORT,
    wharf_api_types::egress::SERVE_PORT,
    wharf_api_types::egress::LOCAL_PORT,
  ]
  .contains(&port)
    || (30000..=39999).contains(&port)
}

fn validate_deploy_options(
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  if matches!(spec.source, Source::Compose { .. })
    && (spec.stop_grace_secs.is_some() || spec.stop_signal.is_some())
  {
    return Err(
      ApiError::invalid(format!(
        "服务 {name} 的停机选项仅支持镜像和构建来源"
      ))
      .with_hint(
        "在 compose 文件里设置 stop_grace_period 或 stop_signal",
      ),
    );
  }
  if spec
    .stop_grace_secs
    .is_some_and(|n| !(1..=600).contains(&n))
  {
    return Err(ApiError::invalid(format!(
      "服务 {name} 的优雅停机等待时长需在 1 到 600 秒之间"
    )));
  }
  if let Some(signal) = &spec.stop_signal {
    wharf_api_types::compose::normalize_stop_signal(signal).map_err(
      |mut err| {
        err.message = format!("服务 {name} 的停机信号不支持");
        err
      },
    )?;
  }
  if let Some(cmd) = &spec.init_cmd {
    if cmd.trim().is_empty() {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的初始化命令不能为空"
      )));
    }
    if cmd.len() > 4096 {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的初始化命令不能超过 4096 字节"
      )));
    }
    if let Source::Compose {
      content: Some(yaml),
      ..
    } = &spec.source
    {
      crate::render::compose_target(
        name,
        yaml,
        spec.container.as_deref(),
      )
      .map_err(|error| {
        error.with_hint(
          "在 container 中指定执行初始化命令的 compose 服务",
        )
      })?;
    }
  }
  if let Some(secs) = spec.init_timeout_secs {
    if !(10..=1800).contains(&secs) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的初始化超时需在 10 到 1800 秒之间"
      )));
    }
    if spec.init_cmd.is_none() {
      return Err(ApiError::invalid(format!(
        "服务 {name} 没有设置初始化命令，不能单独设置初始化超时"
      )));
    }
  }
  Ok(())
}

pub(crate) fn normalize_service_tag(
  tag: &str,
) -> Result<&str, ApiError> {
  let tag = tag.trim();
  if !(1..=32).contains(&tag.chars().count())
    || !tag
      .chars()
      .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
  {
    Err(
      ApiError::invalid("标签长度须为 1 到 32 个字符")
        .with_hint("使用字母、数字、连字符或下划线"),
    )
  } else {
    Ok(tag)
  }
}

fn validate_tags(tags: &BTreeSet<String>) -> Result<(), ApiError> {
  if tags.len() > 32 {
    return Err(ApiError::invalid("每个服务最多 32 个标签"));
  }
  for tag in tags {
    normalize_service_tag(tag)?;
  }
  Ok(())
}

fn validate_service(
  world: &World,
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  validate_name("服务", name)?;
  if spec
    .start_timeout_secs
    .is_some_and(|n| !(10..=1800).contains(&n))
  {
    return Err(ApiError::invalid(
      "启动等待上限需在 10 到 1800 秒之间",
    ));
  }
  validate_tags(&spec.tags)?;
  crate::updates::validate_ignore(spec)?;
  validate_deploy_options(name, spec)?;
  if name.starts_with(GATEWAY_PROJECT_PREFIX) {
    return Err(ApiError::invalid(format!(
      "服务名不能以 {GATEWAY_PROJECT_PREFIX} 开头，它留给网关用"
    )));
  }
  if name == crate::render::BACKUP_PROJECT {
    return Err(ApiError::invalid(format!(
      "服务名 {name} 留给备份服务用，换一个名字"
    )));
  }
  if matches!(
    name,
    crate::render::CORE_BACKUP_PROJECT | crate::core_backup::REPO
  ) {
    return Err(ApiError::invalid(format!(
      "服务名 {name} 留给控制面备份用，换一个名字"
    )));
  }
  if !world.servers.contains_key(&spec.server) {
    return Err(server_not_found(&spec.server));
  }
  if let Some(backup) = &spec.backup {
    wharf_api_types::backup::validate_backup_excludes(
      &backup.exclude,
    )?;
    if let Some(retention) = backup.retention {
      wharf_api_types::backup::validate_retention(retention)?;
    }
    if !world.servers.contains_key(&backup.to) {
      return Err(server_not_found(&backup.to));
    }
    if backup.to == spec.server {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的备份要存到另一台服务器，不能是它所在的 {}",
        spec.server
      )));
    }
    if spec.volumes.is_empty()
      && !matches!(spec.source, Source::Compose { .. })
    {
      return Err(ApiError::invalid(format!(
        "服务 {name} 没有数据卷，不需要备份"
      )));
    }
  }
  match &spec.source {
    Source::Image(image) => {
      if image.trim().is_empty()
        || image.contains(char::is_whitespace)
      {
        return Err(ApiError::invalid(format!(
          "服务 {name} 的镜像名不合法"
        )));
      }
    }
    Source::Build(b) => check_build(name, b)?,
    Source::Compose { content, file } => {
      let Some(content) = content else {
        return Err(
          ApiError::invalid(format!(
            "服务 {name} 的 compose 内容为空{}",
            file
              .as_ref()
              .map(|f| format!(
                "（file = {f} 需要由 CLI 读取后提交）"
              ))
              .unwrap_or_default()
          ))
          .with_hint("用 wharf CLI 提交，它会读取文件内容"),
        );
      };
      crate::render::check_compose_template(name, content)?;
      if !spec.volumes.is_empty() {
        return Err(ApiError::invalid(format!(
          "服务 {name}：compose 来源的数据卷请直接写在 compose 文件里"
        )));
      }
    }
  }
  crate::host_access::validate_service_ports(world, name, spec)?;
  let mut port_names = BTreeSet::new();
  for port in &spec.ports {
    validate_name("端口", &port.name)?;
    if !port_names.insert(&port.name) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的端口名 {} 重复",
        port.name
      )));
    }
    let p = &port.name;
    if port.container == Some(0) || port.host == Some(0) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的端口 {p} 不能是 0"
      )));
    }
    match spec.source {
      Source::Compose { .. } => {
        if port.container.is_some() {
          return Err(ApiError::invalid(format!(
            "服务 {name} 的端口 {p}：compose 来源只填宿主机端口 host，容器端口写在 compose 里"
          )));
        }
        if port.host.is_none() {
          return Err(ApiError::invalid(format!(
            "服务 {name} 的端口 {p}：compose 来源要填 compose 里发布的宿主机端口 host"
          )));
        }
      }
      Source::Image(_) | Source::Build(_) => {
        if port.container.is_none() {
          return Err(ApiError::invalid(format!(
            "服务 {name} 的端口 {p}：要填容器内端口 container"
          )));
        }
      }
    }
  }
  crate::shared_volumes::validate_service(name, spec)?;
  let mut volume_names = BTreeSet::new();
  for volume in &spec.volumes {
    validate_name("数据卷", &volume.name)?;
    if !volume_names.insert(&volume.name) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的数据卷名 {} 重复",
        volume.name
      )));
    }
    if !volume.target.starts_with('/') || volume.target.contains(':')
    {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的数据卷 {} 的挂载点必须是容器内的绝对路径",
        volume.name
      )));
    }
    if crate::render::reserved_secret_mount(&volume.target) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的数据卷 {} 不能挂载到 {} 或其子路径",
        volume.name,
        crate::render::SECRET_FILE_DIR
      )));
    }
  }
  check_files(name, &spec.files)?;
  for key in spec.env.keys() {
    let ok = !key.is_empty()
      && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
      && !key.as_bytes()[0].is_ascii_digit();
    if !ok {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的环境变量名 {key} 不合法"
      )));
    }
  }
  Ok(())
}

/// 配置文件：容器内绝对路径、不重复，单个 64 KB 以内，最多 20 个。
fn check_files(
  name: &str,
  files: &[wharf_api_types::spec::FileSpec],
) -> Result<(), ApiError> {
  if files.len() > 20 {
    return Err(ApiError::invalid(format!(
      "服务 {name} 的配置文件超过 20 个"
    )));
  }
  let mut paths = BTreeSet::new();
  for f in files {
    if f.file.is_some() {
      return Err(ApiError::invalid(format!("服务 {name} 的配置文件 {} 的 file 字段需要由 CLI 读取后提交", f.path))
        .with_hint("用 wharf plan -f 提交，CLI 会自动读取外置文件"));
    }
    let dir = crate::render::SECRET_FILE_DIR;
    if crate::render::reserved_secret_mount(&f.path) {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的配置文件路径 {} 不能放在 {dir}/ 下",
          f.path
        ))
        .with_hint(
          "该目录保留给 [[FILE:SECRET]]，普通配置文件请换其他路径",
        ),
      );
    }
    let ok = f.path.starts_with('/')
      && !f.path.ends_with('/')
      && !f.path.split('/').any(|p| p == ".." || p == ".")
      && !f.path.chars().any(|c| c.is_whitespace() || c == ':');
    if !ok {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的配置文件路径 {} 不对，要写容器内的绝对路径，例如 /etc/app/config.yaml",
        f.path
      )));
    }
    if !paths.insert(&f.path) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的配置文件 {} 重复",
        f.path
      )));
    }
    if f.content.len() > 64 * 1024 {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的配置文件 {} 超过 64 KB",
          f.path
        ))
        .with_hint("大文件放进数据卷，用 wharf 的文件上传"),
      );
    }
  }
  Ok(())
}

/// 额外绑定的地址只能是私有网段，否则服务端口会暴露到公网。
/// 基线的值会写进宿主机的配置文件，只允许安全的字符。
fn validate_baseline(
  b: &wharf_api_types::spec::Baseline,
) -> Result<(), ApiError> {
  let ok = |v: &str, extra: &[u8]| {
    !v.is_empty()
      && v
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
  };
  let size = |v: &str| {
    let digits = v.trim_end_matches(|c: char| "kKmMgG".contains(c));
    !digits.is_empty()
      && digits.bytes().all(|c| c.is_ascii_digit())
      && v.len() - digits.len() <= 1
  };
  if let Some(tz) = &b.timezone
    && !ok(tz, b"/_+-")
  {
    return Err(ApiError::invalid(format!(
      "时区 {tz} 不对，例如 Asia/Shanghai"
    )));
  }
  for (k, v) in &b.sysctl {
    if !ok(k, b"._-") || k.starts_with('.') || k.contains("..") {
      return Err(ApiError::invalid(format!(
        "内核参数名 {k} 不对，例如 net.ipv4.tcp_congestion_control"
      )));
    }
    if !ok(v, b" ._-") {
      return Err(ApiError::invalid(format!(
        "内核参数 {k} 的值 {v} 不对"
      )));
    }
  }
  for (label, v) in [
    ("容器日志大小", &b.docker_log_size),
    ("journald 上限", &b.journal_max),
  ] {
    if let Some(v) = v
      && !size(v)
    {
      return Err(ApiError::invalid(format!(
        "{label} {v} 不对，写成数字加单位，例如 20m、500M"
      )));
    }
  }
  if b.swap_gb.is_some_and(|g| g > 64)
    || b.docker_log_files == Some(0)
  {
    return Err(ApiError::invalid(
      "swap 最多 64G，容器日志至少保留 1 个文件",
    ));
  }
  Ok(())
}

fn validate_lan_addrs(addrs: &[String]) -> Result<(), ApiError> {
  for addr in addrs {
    let ok = addr
      .parse::<std::net::Ipv4Addr>()
      .is_ok_and(|ip| ip.is_private());
    if !ok {
      return Err(
        ApiError::invalid(format!(
          "局域网地址 {addr} 不是私有网段的 IPv4（10/8、172.16/12、192.168/16）"
        ))
        .with_hint("公网地址不能绑定，否则服务端口会直接暴露到公网"),
      );
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn compose_env_and_shared_tcp_udp_binding() {
    let mut w = sample();
    let mut spec = image_service("node1");
    spec.env.insert("TZ".into(), "UTC".into());
    let content = "services:\n  app:\n    image: alpine\n    ports:\n      - 11553:53/tcp\n      - 11553:53/udp";
    spec.ports.clear();
    spec.source = Source::Compose {
      content: Some(content.into()),
      file: None,
    };
    w.apply_changes(&[Change::UpsertService {
      name: "app".into(),
      spec,
      adopt: None,
      pins: None,
      commit: None,
      migrate: None,
    }])
    .unwrap();
    w.allocate_ports().unwrap();
    w.validate().unwrap();
    let spec = &w.services["app"].spec;
    assert_eq!(
      spec.ports.iter().map(|p| p.udp).collect::<Vec<_>>(),
      [false, true]
    );
    assert!(
      crate::render::compose_with_settings("app", content, spec)
        .unwrap()
        .contains("TZ")
    );
  }

  #[test]
  fn git_secret_names_allow_dash_but_new_dockerfile_template_conflicts_fail()
   {
    let mut w = sample();
    let mut spec = image_service("node1");
    let mut build: BuildSource = serde_json::from_value(json!({
      "git": {"repo": "https://example.test/one", "ref": "prod", "token_secret": "git-test"},
      "template": "node"
    })).unwrap();
    assert!(check_build("app", &build).is_ok());
    build.dockerfile = Some("Dockerfile".into());
    spec.source = Source::Build(build);
    assert!(
      w.apply_changes(&[Change::UpsertService {
        name: "app".into(),
        spec,
        adopt: None,
        pins: None,
        commit: None,
        migrate: None,
      }])
      .unwrap_err()
      .message
      .contains("不能同时")
    );
  }

  use wharf_api_types::spec::PortSpec;

  #[test]
  fn edge_import_accepts_free_name() {
    let mut world = World::default();
    let spec = serde_json::from_value(json!({
      "account": "cf", "kind": "pages", "project": "demo"
    }))
    .unwrap();
    world
      .apply_changes(&[Change::ImportEdgeApp {
        name: "new-app".into(),
        spec,
      }])
      .unwrap();
    world.validate().unwrap();
    assert_eq!(
      world.edge_apps["new-app"].spec.project_name("new-app"),
      "demo"
    );
  }

  #[test]
  fn edge_import_rejects_existing_name() {
    let mut world = World::default();
    let name = "app".to_string();
    let spec: EdgeAppSpec = serde_json::from_value(json!({
      "account": "cf", "kind": "worker", "project": "current",
      "domains": ["app.example.com"]
    }))
    .unwrap();
    world
      .apply_changes(&[Change::UpsertEdgeApp {
        name: name.clone(),
        spec: spec.clone(),
      }])
      .unwrap();
    let err = world
      .apply_changes(&[Change::ImportEdgeApp {
        name: name.clone(),
        spec: serde_json::from_value(json!({
          "account": "cf", "kind": "worker", "project": "demo"
        }))
        .unwrap(),
      }])
      .unwrap_err();
    assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
    assert!(err.message.contains("app"));
    assert!(err.message.contains("cf/worker/current"));
    assert_eq!(world.edge_apps[&name].spec, spec);
  }

  #[test]
  fn tunnel_gateway_rejects_trusted_proxies() {
    let mut world = World::default();
    world.servers.insert(
      "s1".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    let spec = serde_json::from_value(json!({
      "kind": "cloudflare_tunnel", "server": "s1", "account": "cf",
      "trusted_proxies": {"cloudflare": true},
    }))
    .unwrap();
    world
      .gateways
      .insert("edge".into(), GatewayRow { spec, version: 1 });
    assert!(
      world
        .validate()
        .unwrap_err()
        .message
        .contains("可信代理只适用于 caddy 网关")
    );
  }

  #[test]
  fn share_route_checks() {
    let mut w = sample();
    let server = w.servers.remove("node1").unwrap();
    w.servers.insert("s1".into(), server);
    w.apply_changes(&[
      Change::UpsertGateway { name: "edge".into(), spec: serde_json::from_value(json!({"kind":"caddy","server":"s1","default":true,"wildcard":["example.com"]})).unwrap() },
      Change::UpsertService { pins: None, commit: None, migrate: None, name: "app".into(), spec: image_service("s1"), adopt: None },
    ]).unwrap();
    w.allocate_ports().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let spec: RouteSpec = serde_json::from_value(json!({"hostname":"a.example.com","service":"app","expires_at":now + 60000})).unwrap();
    let upsert = |spec| Change::UpsertRoute { spec };
    assert!(
      w.apply_changes(&[upsert(RouteSpec {
        expires_at: Some(now - 1),
        ..spec.clone()
      })])
      .unwrap_err()
      .message
      .contains("到期时间已经过了")
    );
    assert_eq!(
      w.apply_changes(&[upsert(RouteSpec {
        expires_at: Some(now + 8 * 86400000),
        ..spec.clone()
      })])
      .unwrap_err()
      .message,
      "临时分享最长 7 天"
    );
    w.apply_changes(&[upsert(spec.clone())]).unwrap();
    w.validate().unwrap();
    w.routes
      .get_mut("a.example.com")
      .unwrap()
      .spec
      .service
      .clear();
    w.routes.get_mut("a.example.com").unwrap().spec.upstream =
      Some("127.0.0.1:80".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 a.example.com：临时分享只能指向服务"
    );
    w.routes.get_mut("a.example.com").unwrap().spec = spec.clone();
    w.gateways.get_mut("edge").unwrap().spec.wildcard.clear();
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 a.example.com：临时分享的域名要在入口 edge 的泛域名证书下"
    );
    w.gateways.get_mut("edge").unwrap().spec.wildcard =
      vec!["example.com".into()];
    let expired = RouteSpec {
      expires_at: Some(now - 1),
      ..spec.clone()
    };
    w.routes.get_mut("a.example.com").unwrap().spec = expired.clone();
    w.validate().unwrap();
    w.apply_changes(&[
      upsert(expired),
      upsert(RouteSpec {
        hostname: "b.example.com".into(),
        ..spec.clone()
      }),
      upsert(RouteSpec {
        hostname: "c.example.com".into(),
        expires_at: None,
        ..spec
      }),
    ])
    .unwrap();
    assert_eq!(crate::share::expired(&w, now), vec!["a.example.com"]);
  }

  #[test]
  fn failover_minutes_requires_backup_and_a_valid_range() {
    let mut world = World::default();
    for server in ["s1", "s2"] {
      world.servers.insert(
        server.into(),
        ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
    }
    for (name, server) in [("primary", "s1"), ("backup", "s2")] {
      world.gateways.insert(
        name.into(),
        GatewayRow {
          spec: serde_json::from_value(
            json!({"kind":"caddy","server":server}),
          )
          .unwrap(),
          version: 1,
        },
      );
    }
    let host = "minutes.example.test";
    for (backup, minutes, valid) in [
      (Some("backup"), 0, false),
      (Some("backup"), 61, false),
      (None, 3, false),
      (Some("backup"), 2, true),
    ] {
      let spec = serde_json::from_value(json!({
        "hostname":host, "upstream":"127.0.0.1:8080", "gateway":"primary",
        "backup_gateway":backup, "failover_minutes":minutes
      })).unwrap();
      world.routes.insert(
        host.into(),
        RouteRow {
          spec,
          id: "rt_fixture".into(),
          version: 1,
        },
      );
      assert_eq!(
        world.validate().is_ok(),
        valid,
        "{backup:?} {minutes}"
      );
    }
  }

  #[test]
  fn internal_route_checks() {
    let mut w = World::default();
    for server in ["s1", "s2"] {
      w.servers.insert(
        server.into(),
        ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
    }
    for (name, server) in [("edge", "s1"), ("backup", "s2")] {
      w.gateways.insert(
        name.into(),
        GatewayRow {
          spec: serde_json::from_value(
            serde_json::json!({"kind":"caddy", "server":server}),
          )
          .unwrap(),
          version: 1,
        },
      );
    }
    let valid: RouteSpec = serde_json::from_value(serde_json::json!({
      "hostname":"i.example.com", "gateway":"edge", "upstream":"127.0.0.1:8080", "internal":true
    })).unwrap();
    w.routes.insert(
      "i.example.com".into(),
      RouteRow {
        id: "r1".into(),
        spec: valid.clone(),
        version: 1,
      },
    );
    w.validate().unwrap();
    w.routes.get_mut("i.example.com").unwrap().spec.redirect =
      Some("https://example.com".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 i.example.com：跳转不能设成只在内网访问"
    );
    w.routes.get_mut("i.example.com").unwrap().spec = valid.clone();
    w.gateways.get_mut("edge").unwrap().spec.kind =
      GatewayKind::CloudflareTunnel;
    w.gateways.get_mut("edge").unwrap().spec.account =
      Some("cf".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 i.example.com：只在内网访问只支持 caddy 网关"
    );
    w.gateways.get_mut("edge").unwrap().spec.kind =
      GatewayKind::Caddy;
    w.gateways.get_mut("edge").unwrap().spec.account = None;
    w.routes
      .get_mut("i.example.com")
      .unwrap()
      .spec
      .backup_gateway = Some("backup".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 i.example.com：只在内网访问的域名不能设备用入口"
    );
    w.routes.get_mut("i.example.com").unwrap().spec = valid;
    w.gateways.get_mut("edge").unwrap().spec.wildcard =
      vec!["i.example.com".into()];
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 i.example.com：它是入口 edge 泛域名证书的 zone 本身，不能设成只在内网访问"
    );
  }

  #[test]
  fn wildcard_checks() {
    let mut w = sample();
    let spec: GatewaySpec = serde_json::from_value(
            serde_json::json!({"kind":"caddy", "server":"node1", "wildcard":["example.com"]}),
        )
        .unwrap();
    w.gateways
      .insert("edge".into(), GatewayRow { spec, version: 1 });
    w.validate().unwrap();
    let valid = w.gateways["edge"].spec.clone();
    {
      let spec = &mut w.gateways.get_mut("edge").unwrap().spec;
      spec.kind = GatewayKind::CloudflareTunnel;
      spec.account = Some("cf".into());
    }
    assert_eq!(
      w.validate().unwrap_err().message,
      "网关 edge：泛域名证书只适用于 caddy 网关"
    );
    w.gateways.get_mut("edge").unwrap().spec = GatewaySpec {
      tls: GatewayTls::Off,
      ..valid.clone()
    };
    assert_eq!(
      w.validate().unwrap_err().message,
      "入口 edge 只走 HTTP，不能开泛域名证书"
    );
    w.gateways.get_mut("edge").unwrap().spec = GatewaySpec {
      wildcard: vec!["*.example.com".into()],
      ..valid.clone()
    };
    assert_eq!(
      w.validate().unwrap_err().message,
      "入口 edge 的泛域名证书写 zone 本身，例如 example.com"
    );
    w.gateways.get_mut("edge").unwrap().spec = GatewaySpec {
      wildcard: vec!["example.com".into(), "example.com".into()],
      ..valid
    };
    assert_eq!(
      w.validate().unwrap_err().message,
      "入口 edge 的泛域名证书 example.com 写了两次"
    );
  }

  #[test]
  fn checks_bookmark_fields() {
    let spec = BookmarkSpec {
      title: " 路由器 ".into(),
      url: "http://router.example".into(),
      group: Some(" 家里 ".into()),
      order: 10,
    };
    let valid = check_bookmark(spec.clone()).unwrap();
    assert_eq!(
      (&*valid.title, valid.group.as_deref()),
      ("路由器", Some("家里"))
    );
    assert!(
      check_bookmark(BookmarkSpec {
        title: " ".into(),
        ..spec.clone()
      })
      .is_err()
    );
    assert!(
      check_bookmark(BookmarkSpec {
        url: "ftp://x".into(),
        ..spec.clone()
      })
      .is_err()
    );
    assert!(
      check_bookmark(BookmarkSpec {
        group: Some("字".repeat(21)),
        ..spec
      })
      .is_err()
    );
  }

  #[test]
  fn restores_exported_bookmarks_with_their_ids() {
    let mut original = World::default();
    original
      .apply_changes(&[Change::UpsertBookmark {
        id: None,
        spec: BookmarkSpec {
          title: "路由器".into(),
          url: "http://router.example".into(),
          group: Some("家里".into()),
          order: 20,
        },
      }])
      .unwrap();
    let fleet = crate::views::export(&original);
    let mut restored = World::default();
    restored.replace_with(&fleet).unwrap();
    assert_eq!(
      crate::views::export(&restored).bookmarks,
      fleet.bookmarks
    );
  }

  #[test]
  fn partial_fleet_keeps_unlisted_objects() {
    let mut w = sample();
    let add = |name: &str| Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: name.into(),
      spec: image_service("node1"),
      adopt: None,
    };
    w.apply_changes(&[add("a"), add("b")]).unwrap();
    let mut changed = image_service("node1");
    changed.source = Source::Image("nginx".into());
    let fleet = Fleet {
      services: [("a".to_string(), changed.clone())].into(),
      ..Default::default()
    };
    let mut merged = w.clone();
    merged.merge_with(&fleet).unwrap();
    assert!(merged.services.contains_key("b"));
    assert_eq!(merged.services["a"].spec.source, changed.source);
    let mut replaced = w;
    replaced.replace_with(&fleet).unwrap();
    assert!(!replaced.services.contains_key("b"));
  }

  pub fn sample() -> World {
    let mut w = World::default();
    w.servers.insert(
      "node1".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    w
  }

  fn image_service(server: &str) -> ServiceSpec {
    ServiceSpec {
      backup: None,
      stopped: false,
      monitor: None,
      start_timeout_secs: None,
      log_alerts: vec![],
      port_checks: Default::default(),
      heartbeat: None,
      limits: None,
      auto_update: false,
      update_ignore: vec![],
      container: None,
      files: vec![],
      stop_grace_secs: None,
      stop_signal: None,
      init_cmd: None,
      init_timeout_secs: None,
      tags: Default::default(),
      server: server.into(),
      source: Source::Image("traefik/whoami".into()),
      ports: vec![PortSpec {
        name: "http".into(),
        container: Some(80),
        host: None,
        udp: false,
      }],
      env: Default::default(),
      volumes: vec![],
    }
  }

  #[test]
  fn shared_volume_validation_blocks_cross_server_delete_chain_and_backup()
   {
    let mut w = sample();
    w.servers.insert(
      "s2".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    let mut owner = image_service("node1");
    let mut reader = owner.clone();
    owner.volumes = serde_json::from_value(
      serde_json::json!([{"name":"data","target":"/data"}]),
    )
    .unwrap();
    reader.volumes = serde_json::from_value(serde_json::json!([{"from_service":"photos:data","target":"/data"}])).unwrap();
    w.apply_changes(&[
      Change::UpsertService {
        name: "photos".into(),
        spec: owner,
        adopt: None,
        pins: None,
        commit: None,
        migrate: None,
      },
      Change::UpsertService {
        name: "reader".into(),
        spec: reader,
        adopt: None,
        pins: None,
        commit: None,
        migrate: None,
      },
    ])
    .unwrap();
    w.validate().unwrap();
    assert_eq!(w.services["reader"].spec.volumes[0].name, "data");
    for (service, server, reference, backup) in [
      ("photos", "s2", None, false),
      ("reader", "s2", None, false),
      ("photos", "node1", Some("reader:data"), false),
      ("reader", "node1", Some("photos:missing"), false),
      ("reader", "node1", None, true),
    ] {
      let mut changed = w.clone();
      let spec = &mut changed.services.get_mut(service).unwrap().spec;
      spec.server = server.into();
      if let Some(reference) = reference {
        spec.volumes[0].from_service = Some(reference.into());
      }
      if backup {
        spec.backup = Some(wharf_api_types::spec::BackupSpec {
          to: "s2".into(),
          exclude: vec![],
          retention: None,
        });
      }
      let err = changed.validate().unwrap_err();
      assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
      assert!(err.hint.is_some());
    }
    let mut cycle = w.clone();
    cycle.services.get_mut("reader").unwrap().spec.volumes.push(
      serde_json::from_value(
        serde_json::json!({"name":"local","target":"/local"}),
      )
      .unwrap(),
    );
    cycle.services.get_mut("photos").unwrap().spec.volumes.push(
      serde_json::from_value(serde_json::json!({"name":"other","from_service":"reader:local","target":"/other"})).unwrap(),
    );
    assert!(cycle.validate().unwrap_err().message.contains("成环"));
    for service in w.services.values_mut() {
      service.spec.server = "s2".into();
    }
    w.validate().unwrap();
    w.services.remove("photos");
    assert!(w.validate().is_err());
    w.services.remove("reader");
    w.validate().unwrap();
  }

  #[test]
  fn validates_start_timeout() {
    let mut spec = image_service("node1");
    spec.start_timeout_secs = Some(300);
    validate_service(&sample(), "app", &spec).unwrap();
    spec.start_timeout_secs = Some(5);
    assert_eq!(
      validate_service(&sample(), "app", &spec).unwrap_err().code,
      wharf_api_types::ErrorCode::InvalidInput
    );
  }

  #[test]
  fn compose_ports_must_match_published_and_reject_reserved() {
    use wharf_api_types::ErrorCode;
    let mut w = sample();
    w.apply_changes(&[Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: "app".into(),
      spec: image_service("node1"),
      adopt: None,
    }])
    .unwrap();
    let set_ports = |w: &mut World, host, udp, source| {
      let spec = &mut w.services.get_mut("app").unwrap().spec;
      spec.ports[0].host = Some(host);
      spec.ports[0].container =
        matches!(source, Source::Image(_)).then_some(80);
      spec.ports[0].udp = udp;
      spec.source = source;
    };
    let compose = |content: &str| Source::Compose {
      content: Some(content.into()),
      file: None,
    };
    for (host, message) in
      [(7700, "保留端口"), (18080, "没有在 compose")]
    {
      set_ports(
        &mut w,
        host,
        false,
        compose("services: {app: {image: nginx}}"),
      );
      let err = w.validate().unwrap_err();
      assert_eq!(err.code, ErrorCode::InvalidInput);
      assert!(err.message.contains(message));
    }
    set_ports(&mut w, 8119, false, Source::Image("nginx".into()));
    assert_eq!(
      w.validate().unwrap_err().code,
      ErrorCode::InvalidInput
    );
    let local =
      "services: {app: {image: nginx, ports: ['127.0.0.1:8080:80']}}";
    set_ports(&mut w, 8080, false, compose(local));
    assert!(w.validate().is_ok());
    set_ports(&mut w, 8080, true, compose(local));
    assert_eq!(
      w.validate().unwrap_err().code,
      ErrorCode::InvalidInput
    );
    let public = local.replace("127.0.0.1", "0.0.0.0");
    let binds = crate::host_access::compose_public_binds(&public);
    assert_eq!(binds.len(), 1);
    assert_eq!(binds[0].host_port, 8080);
    let ranges = r#"
x-ports: &ports
  ports:
    - '[::1]:8080-8082:80-82/udp'
    - {host_ip: '0.0.0.0', published: 8083, target: 83}
services:
  app:
    <<: *ports
    image: nginx
"#;
    set_ports(&mut w, 8082, true, compose(ranges));
    assert!(w.validate().is_ok());
    assert_eq!(
      crate::host_access::compose_public_binds(ranges).len(),
      1
    );
    set_ports(
      &mut w,
      8082,
      true,
      compose(&ranges.replace("[::1]", "[invalid]")),
    );
    assert_eq!(
      w.validate().unwrap_err().code,
      ErrorCode::InvalidInput
    );
  }

  #[test]
  fn layer4_checks() {
    let mut w = sample();
    let server = w.servers.remove("node1").unwrap();
    w.servers.insert("s1".into(), server);
    let gw: GatewaySpec = serde_json::from_value(
      json!({"kind":"caddy","server":"s1","default":true}),
    )
    .unwrap();
    w.apply_changes(&[
      Change::UpsertGateway {
        name: "edge".into(),
        spec: gw,
      },
      Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "app".into(),
        spec: image_service("s1"),
        adopt: None,
      },
    ])
    .unwrap();
    w.allocate_ports().unwrap();
    let forward = |listen, udp| {
      serde_json::from_value(json!({"listen":listen,"udp":udp,"upstream":"127.0.0.1:9999"})).unwrap()
    };
    w.gateways.get_mut("edge").unwrap().spec.layer4 =
      vec![forward(443, false)];
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains("被 Wharf 占用或保留")
    );
    w.gateways.get_mut("edge").unwrap().spec.layer4 =
      vec![forward(15432, false), forward(15432, false)];
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains("被多个四层转发使用")
    );
    w.gateways.get_mut("edge").unwrap().spec.layer4 =
      vec![forward(20000, false)];
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains("已经给了服务 app")
    );
    w.gateways.get_mut("edge").unwrap().spec.layer4 = vec![
      serde_json::from_value(
        json!({"listen":15432,"udp":true,"service":"app"}),
      )
      .unwrap(),
    ];
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains("协议和服务 app 的端口 http 不一致")
    );
    w.gateways.get_mut("edge").unwrap().spec.layer4 =
      vec![forward(15432, false), forward(15432, true)];
    w.validate().unwrap();
    w.services.get_mut("app").unwrap().spec.ports[0].udp = true;
    let route: RouteSpec = serde_json::from_value(
      json!({"hostname":"example.com","service":"app"}),
    )
    .unwrap();
    w.apply_changes(&[Change::UpsertRoute { spec: route }])
      .unwrap();
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains("是 UDP，不能给域名用")
    );
    w.routes.clear();
    w.services.clear();
    w.gateways.get_mut("edge").unwrap().spec.layer4 =
      vec![forward(20000, false)];
    w.validate().unwrap();
    w.apply_changes(&[Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: "new".into(),
      spec: image_service("s1"),
      adopt: None,
    }])
    .unwrap();
    w.allocate_ports().unwrap();
    assert_eq!(w.services["new"].host_ports["http"], 20001);
    w.validate().unwrap();
  }

  #[test]
  fn auto_update_requires_no_volumes() {
    let mut w = sample();
    let mut spec = image_service("node1");
    spec.auto_update = true;
    w.apply_changes(&[Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: "app".into(),
      spec: spec.clone(),
      adopt: None,
    }])
    .unwrap();
    spec.volumes.push(wharf_api_types::spec::VolumeSpec {
      from_service: None,
      read_only: false,
      name: "data".into(),
      target: "/data".into(),
    });
    let err = w
      .apply_changes(&[Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "app".into(),
        spec,
        adopt: None,
      }])
      .unwrap_err();
    assert!(err.message.contains("数据卷"));
  }

  #[test]
  fn trial_service_name_is_rejected() {
    let err = sample()
      .apply_changes(&[Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "wharf-try-s1".into(),
        spec: image_service("s1"),
        adopt: None,
      }])
      .unwrap_err();
    assert!(err.message.contains("不能以 wharf-try- 开头"));
  }

  #[test]
  fn task_service_name_is_rejected() {
    let err = sample()
      .apply_changes(&[Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "wharf-task-x".into(),
        spec: image_service("s1"),
        adopt: None,
      }])
      .unwrap_err();
    assert!(err.message.contains("不能以 wharf-task- 开头"));
  }

  #[test]
  fn error_page_checks_content() {
    assert!(
      check_error_page(
        "edge",
        "<style>body{margin:0}</style><p>{err.status_code}</p>"
      )
      .is_ok()
    );
    assert!(
      check_error_page("edge", &"x".repeat(64 * 1024 + 1)).is_err()
    );
    assert!(
      check_error_page("edge", "x WHARF_ERROR_PAGE y").is_err()
    );
    assert!(check_error_page("edge", "{$HOME}").is_err());
  }

  #[test]
  fn compose_service_needs_container_for_limits() {
    let mut w = sample();
    let mut spec = image_service("s1");
    spec.source = Source::Compose {
      content: Some("services:\n  web:\n    image: nginx\n  worker:\n    image: nginx\n".into()),
      file: None,
    };
    spec.limits = Some(wharf_api_types::spec::Limits {
      memory_mb: Some(512),
      cpu_milli: None,
    });
    let err = w
      .apply_changes(&[Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "s1".into(),
        spec,
        adopt: None,
      }])
      .unwrap_err();
    assert!(
      err.message.contains("要选环境变量和资源上限加在哪个容器上")
    );
  }

  #[test]
  fn ports_are_stable_and_unique() {
    let mut w = sample();
    w.apply_changes(&[
      Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "a".into(),
        spec: image_service("node1"),
        adopt: None,
      },
      Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "b".into(),
        spec: image_service("node1"),
        adopt: None,
      },
    ])
    .unwrap();
    w.allocate_ports().unwrap();
    assert_eq!(w.services["a"].host_ports["http"], 20000);
    assert_eq!(w.services["b"].host_ports["http"], 20001);
    // 删除 a 之后 b 的端口不变。
    w.apply_changes(&[Change::RemoveService {
      name: "a".into(),
      purge_data: false,
    }])
    .unwrap();
    w.allocate_ports().unwrap();
    assert_eq!(w.services["b"].host_ports["http"], 20001);
  }

  #[test]
  fn redirect_target_uses_safe_characters() {
    assert_eq!(redirect_host("https://a.com"), Some("a.com"));
    assert_eq!(
      redirect_host("http://a.com:8080/blog"),
      Some("a.com")
    );
    for target in [
      "a.com",
      "https://a.com/",
      "https://a.com/?x=1",
      "https://a.com/#top",
      "https://a.com/{uri}",
      "https://a.com/a b",
      "https://a.com/\"x",
    ] {
      assert_eq!(redirect_host(target), None, "{target}");
    }
  }

  #[test]
  fn route_guard_checks() {
    let mut w = sample();
    w.apply_changes(&[
      Change::UpsertGateway {
        name: "edge".into(),
        spec: serde_json::from_value(json!({
          "kind": "caddy", "server": "node1", "default": true
        }))
        .unwrap(),
      },
      Change::UpsertRoute {
        spec: serde_json::from_value(json!({
          "hostname": "a.example.com", "upstream": "127.0.0.1:80",
          "rate_limit": 10
        }))
        .unwrap(),
      },
    ])
    .unwrap();
    w.validate().unwrap();
    w.routes.get_mut("a.example.com").unwrap().spec.redirect =
      Some("https://b.example.com".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 a.example.com：跳转不能设置限速和拦截扫描"
    );
    w.routes.get_mut("a.example.com").unwrap().spec.redirect = None;
    w.gateways.get_mut("edge").unwrap().spec.kind =
      GatewayKind::CloudflareTunnel;
    w.gateways.get_mut("edge").unwrap().spec.account =
      Some("cf".into());
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 a.example.com：限速和拦截扫描只支持 caddy 网关"
    );
    w.gateways.get_mut("edge").unwrap().spec.kind =
      GatewayKind::Caddy;
    w.routes.get_mut("a.example.com").unwrap().spec.rate_limit =
      Some(9);
    assert_eq!(
      w.validate().unwrap_err().message,
      "路由 a.example.com 的限速要在每分钟 10 到 100000 次之间"
    );
  }

  #[test]
  fn route_needs_gateway_and_port() {
    let mut w = sample();
    w.apply_changes(&[
      Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "who".into(),
        spec: image_service("node1"),
        adopt: None,
      },
      Change::UpsertRoute {
        spec: RouteSpec {
          sso: None,
          hostname: "Who.EXAMPLE.com".into(),
          service: "who".into(),
          port: None,
          gateway: None,
          backup_gateway: None,
          dns_ttl: None,
          failover_minutes: None,
          auth: false,
          paths: vec![],
          caddy: None,
          caddy_file: None,
          upstream: None,
          link: Default::default(),
          redirect: None,
          rate_limit: None,
          block_scanners: false,
          internal: false,
          core_mesh_only: false,
          cf_origin_only: false,
          expires_at: None,
        },
      },
    ])
    .unwrap();
    assert!(w.routes.contains_key("who.example.com"));
    let err = w.validate().unwrap_err();
    assert!(err.message.contains("默认网关"), "{}", err.message);
    w.apply_changes(&[Change::UpsertGateway {
      name: "edge".into(),
      spec: GatewaySpec {
        kind: GatewayKind::Caddy,
        server: "node1".into(),
        default: true,
        http_port: None,
        https_port: None,
        tls: Default::default(),
        email: None,
        image: None,
        account: None,
        error_page: None,
        wildcard: vec![],
        layer4: vec![],
        trusted_proxies: None,
        read_header_timeout: None,
        idle_timeout: None,
        grace_period: None,
      },
    }])
    .unwrap();
    w.validate().unwrap();
    // 直接指向地址：不需要服务，和服务二选一。
    let mut up = w.routes["who.example.com"].spec.clone();
    up.hostname = "core.example.com".into();
    up.service = String::new();
    up.upstream = Some("127.0.0.1:7700".into());
    w.apply_changes(&[Change::UpsertRoute { spec: up.clone() }])
      .unwrap();
    w.validate().unwrap();
    up.service = "who".into();
    w.apply_changes(&[Change::UpsertRoute { spec: up }])
      .unwrap();
    let err = w.validate().unwrap_err();
    assert!(err.message.contains("二选一"), "{}", err.message);
  }

  #[test]
  fn backup_gateway_must_be_on_another_server() {
    let mut w = sample();
    w.servers.insert(
      "node2".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    let gw = |server: &str, default: bool| GatewaySpec {
      kind: GatewayKind::Caddy,
      server: server.into(),
      default,
      http_port: None,
      https_port: None,
      tls: Default::default(),
      email: None,
      image: None,
      account: None,
      error_page: None,
      wildcard: vec![],
      layer4: vec![],
      trusted_proxies: None,
      read_header_timeout: None,
      idle_timeout: None,
      grace_period: None,
    };
    let route = |backup: &str| RouteSpec {
      sso: None,
      hostname: "who.example.com".into(),
      service: "who".into(),
      port: None,
      gateway: None,
      backup_gateway: Some(backup.into()),
      dns_ttl: None,
      failover_minutes: None,
      auth: false,
      paths: vec![],
      caddy: None,
      caddy_file: None,
      upstream: None,
      link: Default::default(),
      redirect: None,
      rate_limit: None,
      block_scanners: false,
      internal: false,
      core_mesh_only: false,
      cf_origin_only: false,
      expires_at: None,
    };
    w.apply_changes(&[
      Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "who".into(),
        spec: image_service("node1"),
        adopt: None,
      },
      Change::UpsertGateway {
        name: "main".into(),
        spec: gw("node1", true),
      },
      Change::UpsertGateway {
        name: "same".into(),
        spec: gw("node1", false),
      },
      Change::UpsertGateway {
        name: "spare".into(),
        spec: gw("node2", false),
      },
      Change::UpsertRoute {
        spec: route("same"),
      },
    ])
    .unwrap();
    let err = w.validate().unwrap_err();
    assert!(err.message.contains("同一台机器"), "{}", err.message);
    w.apply_changes(&[Change::UpsertRoute {
      spec: route("spare"),
    }])
    .unwrap();
    w.validate().unwrap();
    let spec = &w.routes["who.example.com"].spec;
    assert_eq!(w.route_gateways(spec), vec!["main", "spare"]);
  }

  #[test]
  fn unknown_server_is_rejected() {
    let mut w = sample();
    w.apply_changes(&[Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: "x".into(),
      spec: image_service("nowhere"),
      adopt: None,
    }])
    .unwrap();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code, wharf_api_types::ErrorCode::NotFound);
  }

  #[test]
  fn refresh_one_image_keeps_other_pins() {
    let mut w = sample();
    let mut spec = image_service("node1");
    spec.source = serde_json::from_value(json!({"compose":{"content":"services:\n  db:\n    image: db:8\n  app:\n    image: app:2\n"}})).unwrap();
    w.apply_changes(&[Change::UpsertService {
      pins: None,
      commit: None,
      migrate: None,
      name: "x".into(),
      spec,
      adopt: None,
    }])
    .unwrap();
    let row = w.services.get_mut("x").unwrap();
    row.pins = BTreeMap::from([
      ("db:8".into(), "sha256:db".into()),
      ("app:2".into(), "sha256:app".into()),
    ]);
    w.apply_changes(&[Change::RefreshImages {
      name: "x".into(),
      image: Some("app:2".into()),
    }])
    .unwrap();
    assert_eq!(
      w.services["x"].pins,
      BTreeMap::from([("db:8".into(), "sha256:db".into())])
    );
    let err = w
      .apply_changes(&[Change::RefreshImages {
        name: "x".into(),
        image: Some("nope:1".into()),
      }])
      .unwrap_err();
    assert_eq!(err.message, "服务 x 里没有镜像 nope:1");
  }

  #[test]
  fn writes_only_include_changes() {
    let current = sample();
    let mut desired = current.clone();
    assert!(desired.writes_from(&current).is_empty());
    desired
      .apply_changes(&[Change::UpsertService {
        pins: None,
        commit: None,
        migrate: None,
        name: "x".into(),
        spec: image_service("node1"),
        adopt: None,
      }])
      .unwrap();
    desired.allocate_ports().unwrap();
    let writes = desired.writes_from(&current);
    assert_eq!(writes.len(), 1);
  }
  #[test]
  fn route_login_checks() {
    let mut sso: wharf_api_types::spec::SsoSpec = serde_json::from_value(json!({"mode":"login","login":{"steps":[{"path":"/login","extract":[{"from":"body","name":"csrf","between":["a=",";"]}]},{"method":"POST","path":"/login","form":{"csrf":"{{csrf}}","password":"{{secret.PASS}}"}}],"write":[{"cookies":"all"}],"check":{"path":"/me"}}})).unwrap();
    assert!(
      crate::sso_login::validate("a.example.com", &sso).is_ok()
    );
    sso.login.as_mut().unwrap().steps[0].path = "/{{missing}}".into();
    assert!(
      crate::sso_login::validate("a.example.com", &sso)
        .unwrap_err()
        .message
        .contains("前面没有取过")
    );
  }

  #[test]
  fn route_sso_checks() {
    let mut w = World::default();
    w.servers.insert(
      "s1".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    w.apply_changes(&[Change::UpsertGateway{name:"edge".into(),spec:serde_json::from_value(json!({"kind":"caddy","server":"s1","default":true})).unwrap()},Change::UpsertRoute{spec:serde_json::from_value(json!({"hostname":"a.example.com","upstream":"127.0.0.1:8080","sso":{"mode":"gate","skip_paths":["/api"]}})).unwrap()}]).unwrap();
    w.validate().unwrap();
    w.routes.get_mut("a.example.com").unwrap().spec.auth = true;
    assert!(w.validate().unwrap_err().message.contains("只能开一个"));
    w.routes.get_mut("a.example.com").unwrap().spec.auth = false;
    for path in [
      "/api*", "/", "//", "/.", "/./", "/a/..", "/api/../",
      "/api//v1", "/_wharf",
    ] {
      w.routes
        .get_mut("a.example.com")
        .unwrap()
        .spec
        .sso
        .as_mut()
        .unwrap()
        .skip_paths = vec![path.into()];
      assert!(
        w.validate().unwrap_err().message.contains("写得不对"),
        "{path}"
      );
    }
  }
  #[test]
  fn custom_caddy_stays_in_site() {
    assert!(
      check_custom_caddy_boundaries("@admin path /admin/*\nrespond @admin 403\nheader {\n\tX-A \"{host}\"\n}").is_ok()
    );
    assert!(
      check_custom_caddy_boundaries("}\nevil.example.com {\n")
        .is_err()
    );
  }
  #[test]
  fn route_header_checks() {
    let mut w = World::default();
    w.servers.insert(
      "s1".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    w.apply_changes(&[Change::UpsertGateway{name:"edge".into(),spec:serde_json::from_value(json!({"kind":"caddy","server":"s1","default":true})).unwrap()},Change::UpsertRoute{spec:serde_json::from_value(json!({"hostname":"a.example.com","upstream":"127.0.0.1:8080","sso":{"mode":"header"}})).unwrap()}]).unwrap();
    w.validate().unwrap();
    let sso = w
      .routes
      .get_mut("a.example.com")
      .unwrap()
      .spec
      .sso
      .as_mut()
      .unwrap();
    sso.header = Some("Remote-Name".into());
    w.validate().unwrap();
    for (header, message) in [
      ("", "写得不对"),
      ("1User", "写得不对"),
      ("Remote_User", "写得不对"),
      ("cookie", "不能用"),
      ("HOST", "不能用"),
      ("Authorization", "不能用"),
      ("X-Wharf-Key", "不能用"),
      ("x-forwarded-User", "不能用"),
    ] {
      w.routes
        .get_mut("a.example.com")
        .unwrap()
        .spec
        .sso
        .as_mut()
        .unwrap()
        .header = Some(header.into());
      assert!(w.validate().unwrap_err().message.contains(message));
    }
    let sso = w
      .routes
      .get_mut("a.example.com")
      .unwrap()
      .spec
      .sso
      .as_mut()
      .unwrap();
    sso.header = Some("Remote-User".into());
    sso.mode = wharf_api_types::spec::SsoMode::Gate;
    assert!(
      w.validate().unwrap_err().message.contains("只有 header")
    );
  }
}
