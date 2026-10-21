//! Cloudflare Workers / Pages。
//!
//! - 单文件 Worker 直接调接口上传，带上现有的兼容日期和 `keep_bindings`，
//!   面板里配置的变量、密钥、绑定都保留；
//! - 回滚用 Cloudflare 自己的版本：Workers 部署旧 version，Pages 回滚到旧 deployment；
//! - Workers 的自定义域名由 Cloudflare 连同 DNS 一起管；Pages 的自定义域名要另外写 CNAME。

use std::sync::{Arc, Mutex};

use reqwest::Method;
use serde_json::{Value, json};

use crate::{
  BoxFut, DnsRecordSpec, DnsRecordType, EdgeKind, EdgeProject,
  EdgeProvider, EdgeVersion, WorkerScript,
  error::{ProviderError, code},
  match_zone,
};

use super::client::{CloudflareClient, segment};

type Result<T> = std::result::Result<T, ProviderError>;

/// 新建 Worker 时的兼容日期。已有的 Worker 沿用它自己的。
const DEFAULT_COMPAT_DATE: &str = "2025-09-01";

pub(super) struct CloudflareEdge {
  pub(super) client: Arc<CloudflareClient>,
  account: Mutex<Option<String>>,
}

impl CloudflareEdge {
  pub(super) fn new(client: Arc<CloudflareClient>) -> Self {
    Self {
      client,
      account: Mutex::new(None),
    }
  }

  async fn account(&self) -> Result<String> {
    if let Some(id) = self.account.lock().unwrap().clone() {
      return Ok(id);
    }
    let id = self
      .client
      .single_account("Account → Workers Scripts → Edit，Account → Cloudflare Pages → Edit")
      .await?;
    *self.account.lock().unwrap() = Some(id.clone());
    Ok(id)
  }

  async fn get(&self, path: &str) -> Result<Value> {
    self.client.call(Method::GET, path, None).await
  }

  /// GET，对象不存在时返回 `None`。
  async fn get_opt(&self, path: &str) -> Result<Option<Value>> {
    match self.get(path).await {
      Ok(v) => Ok(Some(v)),
      Err(e) if CloudflareClient::is_not_found(&e) => Ok(None),
      Err(e) => Err(e),
    }
  }

  // WORKERS

  async fn worker_scripts(
    &self,
    account: &str,
  ) -> Result<Vec<Value>> {
    let data = self
      .get(&format!(
        "/accounts/{}/workers/scripts",
        segment(account)?
      ))
      .await?;
    Ok(data["result"].as_array().cloned().unwrap_or_default())
  }

  /// 账户的 workers.dev 子域名，没开通时为空。
  async fn workers_subdomain(&self, account: &str) -> Option<String> {
    let path = format!(
      "/accounts/{}/workers/subdomain",
      segment(account).ok()?
    );
    let data = self.get(&path).await.ok()?;
    data["result"]["subdomain"]
      .as_str()
      .filter(|s| !s.is_empty())
      .map(str::to_string)
  }

  async fn worker(
    &self,
    account: &str,
    name: &str,
  ) -> Result<Option<EdgeProject>> {
    let scripts = self.worker_scripts(account).await?;
    let Some(script) =
      scripts.iter().find(|s| s["id"].as_str() == Some(name))
    else {
      return Ok(None);
    };
    let mut project = worker_project(script);
    let base = format!(
      "/accounts/{}/workers/scripts/{}",
      segment(account)?,
      segment(name)?
    );
    let enabled = self
      .get_opt(&format!("{base}/subdomain"))
      .await?
      .is_some_and(|d| d["result"]["enabled"] == true);
    if enabled
      && let Some(sub) = self.workers_subdomain(account).await
    {
      project.url = Some(format!("https://{name}.{sub}.workers.dev"));
    }
    if let Some(d) =
      self.get_opt(&format!("{base}/deployments")).await?
    {
      let latest = d["result"]["deployments"]
        .as_array()
        .and_then(|list| {
          list.iter().max_by_key(|x| {
            x["created_on"].as_str().unwrap_or_default().to_string()
          })
        })
        .cloned();
      if let Some(latest) = latest {
        project.deployed_at = str_of(&latest["created_on"]);
        project.deployed_by = str_of(&latest["source"]);
      }
    }
    Ok(Some(project))
  }

  async fn worker_versions(
    &self,
    account: &str,
    name: &str,
  ) -> Result<Vec<EdgeVersion>> {
    let base = format!(
      "/accounts/{}/workers/scripts/{}",
      segment(account)?,
      segment(name)?
    );
    let active: Vec<String> = self
      .get_opt(&format!("{base}/deployments"))
      .await?
      .and_then(|d| {
        d["result"]["deployments"].as_array().and_then(|list| {
          list
            .iter()
            .max_by_key(|x| {
              x["created_on"].as_str().unwrap_or_default().to_string()
            })
            .cloned()
        })
      })
      .map(|latest| {
        latest["versions"]
          .as_array()
          .map(|vs| {
            vs.iter()
              .filter_map(|v| str_of(&v["version_id"]))
              .collect()
          })
          .unwrap_or_default()
      })
      .unwrap_or_default();
    let data = self.get(&format!("{base}/versions")).await?;
    let mut items: Vec<Value> = data["result"]["items"]
      .as_array()
      .cloned()
      .unwrap_or_default();
    items.sort_by_key(|v| {
      std::cmp::Reverse(v["number"].as_i64().unwrap_or(0))
    });
    Ok(
      items
        .iter()
        .filter_map(|v| {
          let id = str_of(&v["id"])?;
          Some(EdgeVersion {
            active: active.contains(&id),
            id,
            created_at: str_of(&v["metadata"]["created_on"])
              .unwrap_or_default(),
            source: str_of(&v["metadata"]["source"]),
            message: str_of(&v["annotations"]["workers/message"]),
            url: None,
          })
        })
        .collect(),
    )
  }

  async fn zone_id(&self, hostname: &str) -> Result<String> {
    let zones = self.client.list_zones().await?;
    let names: Vec<String> =
      zones.iter().map(|z| z.name.clone()).collect();
    let zone = match_zone(&names, hostname).ok_or_else(|| {
      ProviderError::new(
        code::ZONE_NOT_FOUND,
        format!("这个 token 管不到 {hostname} 所在的 zone"),
      )
    })?;
    Ok(
      zones
        .iter()
        .find(|z| z.name == zone)
        .map(|z| z.id.clone())
        .unwrap_or_default(),
    )
  }

  async fn worker_domains(
    &self,
    account: &str,
    name: &str,
  ) -> Result<Vec<Value>> {
    let data = self
      .get(&format!(
        "/accounts/{}/workers/domains?service={}",
        segment(account)?,
        segment(name)?
      ))
      .await?;
    Ok(
      data["result"]
        .as_array()
        .map(|list| {
          list
            .iter()
            .filter(|d| d["service"].as_str() == Some(name))
            .cloned()
            .collect()
        })
        .unwrap_or_default(),
    )
  }

  // PAGES

  async fn pages_project(
    &self,
    account: &str,
    name: &str,
  ) -> Result<Option<EdgeProject>> {
    Ok(
      self
        .get_opt(&format!(
          "/accounts/{}/pages/projects/{}",
          segment(account)?,
          segment(name)?
        ))
        .await?
        .map(|d| pages_project(&d["result"])),
    )
  }

  async fn pages_versions(
    &self,
    account: &str,
    name: &str,
  ) -> Result<Vec<EdgeVersion>> {
    let base = format!(
      "/accounts/{}/pages/projects/{}",
      segment(account)?,
      segment(name)?
    );
    let project = self.get(&base).await?;
    let canonical =
      str_of(&project["result"]["canonical_deployment"]["id"]);
    let data = self
      .get(&format!("{base}/deployments?env=production"))
      .await?;
    Ok(
      data["result"]
        .as_array()
        .map(|list| {
          list
            .iter()
            .filter_map(|d| {
              let id = str_of(&d["id"])?;
              Some(EdgeVersion {
                active: canonical.as_deref() == Some(id.as_str()),
                id,
                created_at: str_of(&d["created_on"]).unwrap_or_default(),
                source: str_of(&d["deployment_trigger"]["type"]),
                message: str_of(
                  &d["deployment_trigger"]["metadata"]["commit_message"],
                ),
                url: str_of(&d["url"]),
              })
            })
            .collect()
        })
        .unwrap_or_default(),
    )
  }
}

fn str_of(v: &Value) -> Option<String> {
  v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn worker_project(script: &Value) -> EdgeProject {
  EdgeProject {
    name: str_of(&script["id"]).unwrap_or_default(),
    modified_at: str_of(&script["modified_on"]),
    modules: script["has_modules"] == true,
    ..EdgeProject::default()
  }
}

fn pages_project(p: &Value) -> EdgeProject {
  let latest = &p["latest_deployment"];
  EdgeProject {
    name: str_of(&p["name"]).unwrap_or_default(),
    url: str_of(&p["subdomain"]).map(|s| format!("https://{s}")),
    modified_at: str_of(&latest["created_on"])
      .or_else(|| str_of(&p["created_on"])),
    modules: false,
    production_branch: str_of(&p["production_branch"]),
    subdomain: str_of(&p["subdomain"]),
    deployed_at: str_of(&latest["created_on"]),
    deployed_by: str_of(&latest["deployment_trigger"]["type"]),
  }
}

/// `content/v2` 对 module Worker 返回 multipart（每个模块一段），
/// 旧格式的直接是脚本。只支持一个模块，返回（文件名，内容）。
fn split_script(body: &str) -> Result<(String, String)> {
  let Some(boundary) = body
    .strip_prefix("--")
    .and_then(|rest| rest.lines().next())
    .map(|b| format!("--{}", b.trim_end()))
  else {
    return Ok(("worker.js".into(), body.to_string()));
  };
  let parts: Vec<&str> = body
    .split(boundary.as_str())
    .map(|p| p.trim_start_matches("\r\n").trim_start_matches('\n'))
    .filter(|p| !p.is_empty() && !p.starts_with("--"))
    .collect();
  let [part] = parts.as_slice() else {
    return Err(ProviderError::invalid(format!(
      "这个 Worker 有 {} 个模块，目前只支持拉取单文件 Worker",
      parts.len()
    )));
  };
  let (head, content) = part
    .split_once("\r\n\r\n")
    .or_else(|| part.split_once("\n\n"))
    .ok_or_else(|| {
      ProviderError::internal("读不懂 Cloudflare 返回的脚本")
    })?;
  let filename = head
    .split(';')
    .find_map(|kv| kv.trim().strip_prefix("filename=\""))
    .and_then(|v| v.split('"').next())
    .filter(|f| !f.is_empty() && !f.contains('/'))
    .unwrap_or("worker.js");
  let content = content
    .strip_suffix("\r\n")
    .or_else(|| content.strip_suffix('\n'))
    .unwrap_or(content);
  Ok((filename.to_string(), content.to_string()))
}

/// 主机名放进 URL 路径前校验一下。
fn host_segment(hostname: &str) -> Result<&str> {
  if hostname.is_empty()
    || !hostname
      .bytes()
      .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
  {
    return Err(ProviderError::invalid("域名不合法"));
  }
  Ok(hostname)
}

/// 上传单文件 Worker 的 metadata：沿用现有设置，保留现有绑定。
pub fn upload_metadata(
  script: &WorkerScript,
  settings: Option<&Value>,
) -> Value {
  let mut meta = json!({});
  if script.modules {
    meta["main_module"] = json!(script.filename);
  } else {
    meta["body_part"] = json!("script");
  }
  let date = settings
    .and_then(|s| str_of(&s["compatibility_date"]))
    .unwrap_or_else(|| DEFAULT_COMPAT_DATE.to_string());
  meta["compatibility_date"] = json!(date);
  if let Some(flags) = settings
    .and_then(|s| s["compatibility_flags"].as_array())
    .filter(|f| !f.is_empty())
  {
    meta["compatibility_flags"] = json!(flags);
  }
  let mut keep: Vec<String> = settings
    .and_then(|s| s["bindings"].as_array())
    .map(|b| b.iter().filter_map(|b| str_of(&b["type"])).collect())
    .unwrap_or_default();
  keep.sort();
  keep.dedup();
  // 带静态资源（Workers Assets）的 Worker：只换脚本，资源沿用上一个版本的。
  if keep.iter().any(|t| t == "assets") {
    meta["keep_assets"] = json!(true);
  }
  if !keep.is_empty() {
    meta["keep_bindings"] = json!(keep);
  }
  meta
}

impl EdgeProvider for CloudflareEdge {
  fn account_id(&self) -> BoxFut<'_, String> {
    Box::pin(self.account())
  }

  fn list(&self) -> BoxFut<'_, Vec<(EdgeKind, EdgeProject)>> {
    Box::pin(async move {
      let account = self.account().await?;
      let mut out: Vec<(EdgeKind, EdgeProject)> = self
        .worker_scripts(&account)
        .await?
        .iter()
        .map(|s| (EdgeKind::Worker, worker_project(s)))
        .collect();
      let pages = self
        .get(&format!(
          "/accounts/{}/pages/projects",
          segment(&account)?
        ))
        .await;
      match pages {
        Ok(data) => out.extend(
          data["result"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| (EdgeKind::Pages, pages_project(p))),
        ),
        // token 没有 Pages 权限时只列 Workers。
        Err(e) if e.code == code::AUTH_FAILED => {}
        Err(e) => return Err(e),
      }
      Ok(out)
    })
  }

  fn get<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Option<EdgeProject>> {
    Box::pin(async move {
      let account = self.account().await?;
      match kind {
        EdgeKind::Worker => self.worker(&account, name).await,
        EdgeKind::Pages => self.pages_project(&account, name).await,
      }
    })
  }

  fn download_worker<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, WorkerScript> {
    Box::pin(async move {
      let account = self.account().await?;
      let modules = self
        .worker_scripts(&account)
        .await?
        .iter()
        .find(|s| s["id"].as_str() == Some(name))
        .map(|s| s["has_modules"] == true)
        .ok_or_else(|| {
          ProviderError::new(
            code::PROVIDER_REJECTED,
            format!("Cloudflare 上没有 Worker {name}"),
          )
        })?;
      let content = self
        .client
        .get_text(&format!(
          "/accounts/{}/workers/scripts/{}/content/v2",
          segment(&account)?,
          segment(name)?
        ))
        .await?;
      let (filename, content) = split_script(&content)?;
      Ok(WorkerScript {
        filename,
        content,
        modules,
      })
    })
  }

  fn upload_worker<'a>(
    &'a self,
    name: &'a str,
    script: &'a WorkerScript,
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      let account = self.account().await?;
      let base = format!(
        "/accounts/{}/workers/scripts/{}",
        segment(&account)?,
        segment(name)?
      );
      let settings =
        self.get_opt(&format!("{base}/settings")).await?;
      let existed = settings.is_some();
      let meta = upload_metadata(
        script,
        settings.as_ref().map(|s| &s["result"]),
      );
      let meta = serde_json::to_vec(&meta)
        .map_err(|e| ProviderError::internal(e.to_string()))?;
      let (part, content_type) = if script.modules {
        (script.filename.as_str(), "application/javascript+module")
      } else {
        ("script", "application/javascript")
      };
      self
        .client
        .send_multipart(
          Method::PUT,
          &base,
          &[
            ("metadata", "blob", "application/json", &meta),
            (
              part,
              &script.filename,
              content_type,
              script.content.as_bytes(),
            ),
          ],
        )
        .await?;
      if !existed {
        // 新建的 Worker 打开 workers.dev 地址，方便直接访问。
        let _ = self
          .client
          .call(
            Method::POST,
            &format!("{base}/subdomain"),
            Some(&json!({ "enabled": true })),
          )
          .await;
      }
      Ok(())
    })
  }

  fn ensure_pages<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, EdgeProject> {
    Box::pin(async move {
      let account = self.account().await?;
      if let Some(p) = self.pages_project(&account, name).await? {
        return Ok(p);
      }
      let data = self
        .client
        .call(
          Method::POST,
          &format!("/accounts/{}/pages/projects", segment(&account)?),
          Some(&json!({ "name": name, "production_branch": "main" })),
        )
        .await?;
      Ok(pages_project(&data["result"]))
    })
  }

  fn versions<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Vec<EdgeVersion>> {
    Box::pin(async move {
      let account = self.account().await?;
      match kind {
        EdgeKind::Worker => {
          self.worker_versions(&account, name).await
        }
        EdgeKind::Pages => self.pages_versions(&account, name).await,
      }
    })
  }

  fn rollback<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    version: &'a str,
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      let account = self.account().await?;
      match kind {
        EdgeKind::Worker => {
          self
            .client
            .call(
              Method::POST,
              &format!(
                "/accounts/{}/workers/scripts/{}/deployments",
                segment(&account)?,
                segment(name)?
              ),
              Some(&json!({
                "strategy": "percentage",
                "versions": [{ "version_id": version, "percentage": 100 }],
                "annotations": { "workers/message": "Wharf 回滚" },
              })),
            )
            .await?;
        }
        EdgeKind::Pages => {
          self
            .client
            .call(
              Method::POST,
              &format!(
                "/accounts/{}/pages/projects/{}/deployments/{}/rollback",
                segment(&account)?,
                segment(name)?,
                segment(version)?
              ),
              None,
            )
            .await?;
        }
      }
      Ok(())
    })
  }

  fn domains<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Vec<String>> {
    Box::pin(async move {
      let account = self.account().await?;
      let list = match kind {
        EdgeKind::Worker => self
          .worker_domains(&account, name)
          .await?
          .iter()
          .filter_map(|d| str_of(&d["hostname"]))
          .collect(),
        EdgeKind::Pages => self
          .get(&format!(
            "/accounts/{}/pages/projects/{}/domains",
            segment(&account)?,
            segment(name)?
          ))
          .await?["result"]
          .as_array()
          .into_iter()
          .flatten()
          .filter_map(|d| str_of(&d["name"]))
          .collect(),
      };
      Ok(list)
    })
  }

  fn attach_domain<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    hostname: &'a str,
    takeover: bool,
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      let account = self.account().await?;
      if self
        .domains(kind, name)
        .await?
        .iter()
        .any(|d| d == hostname)
      {
        return Ok(());
      }
      match kind {
        EdgeKind::Worker => {
          let zone_id = self.zone_id(hostname).await?;
          let mut body = json!({
            "environment": "production",
            "hostname": host_segment(hostname)?,
            "service": name,
            "zone_id": zone_id,
          });
          if takeover {
            body["override_existing_dns_record"] = json!(true);
          }
          self
            .client
            .call(
              Method::PUT,
              &format!(
                "/accounts/{}/workers/domains",
                segment(&account)?
              ),
              Some(&body),
            )
            .await?;
        }
        EdgeKind::Pages => {
          self
            .client
            .call(
              Method::POST,
              &format!(
                "/accounts/{}/pages/projects/{}/domains",
                segment(&account)?,
                segment(name)?
              ),
              Some(&json!({ "name": host_segment(hostname)? })),
            )
            .await?;
        }
      }
      Ok(())
    })
  }

  fn detach_domain<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    hostname: &'a str,
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      let account = self.account().await?;
      let path = match kind {
        EdgeKind::Worker => {
          let domains = self.worker_domains(&account, name).await?;
          let Some(id) = domains
            .iter()
            .find(|d| d["hostname"].as_str() == Some(hostname))
            .and_then(|d| str_of(&d["id"]))
          else {
            return Ok(());
          };
          format!(
            "/accounts/{}/workers/domains/{}",
            segment(&account)?,
            segment(&id)?
          )
        }
        EdgeKind::Pages => format!(
          "/accounts/{}/pages/projects/{}/domains/{}",
          segment(&account)?,
          segment(name)?,
          host_segment(hostname)?
        ),
      };
      match self.client.call(Method::DELETE, &path, None).await {
        Ok(_) => Ok(()),
        Err(e) if CloudflareClient::is_not_found(&e) => Ok(()),
        Err(e) => Err(e),
      }
    })
  }

  fn domain_dns(
    &self,
    kind: EdgeKind,
    project: &EdgeProject,
  ) -> Option<DnsRecordSpec> {
    match kind {
      EdgeKind::Worker => None,
      EdgeKind::Pages => Some(DnsRecordSpec {
        record_type: DnsRecordType::CNAME,
        content: project
          .subdomain
          .clone()
          .unwrap_or_else(|| format!("{}.pages.dev", project.name)),
        ttl: 1,
        proxied: true,
      }),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn splits_module_script_out_of_multipart() {
    let body = "--b1\r\nContent-Disposition: form-data; name=\"index.js\"; filename=\"index.js\"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}\n\r\n--b1--\r\n";
    assert_eq!(
      split_script(body).unwrap(),
      ("index.js".to_string(), "export default {}\n".to_string())
    );
    assert_eq!(
      split_script("addEventListener()").unwrap().1,
      "addEventListener()"
    );
    let two = "--b\r\nA: x\r\n\r\na\r\n--b\r\nA: y\r\n\r\nb\r\n--b--";
    assert!(split_script(two).is_err());
  }

  #[test]
  fn upload_keeps_existing_settings_and_bindings() {
    let script = WorkerScript {
      filename: "worker.js".into(),
      content: "export default {}".into(),
      modules: true,
    };
    let settings = json!({
      "compatibility_date": "2024-05-01",
      "compatibility_flags": ["nodejs_compat"],
      "bindings": [
        { "type": "secret_text", "name": "A" },
        { "type": "kv_namespace", "name": "B" },
        { "type": "secret_text", "name": "C" },
      ],
    });
    assert_eq!(
      upload_metadata(&script, Some(&settings)),
      json!({
        "main_module": "worker.js",
        "compatibility_date": "2024-05-01",
        "compatibility_flags": ["nodejs_compat"],
        "keep_bindings": ["kv_namespace", "secret_text"],
      })
    );
    let with_assets = json!({
      "compatibility_date": "2025-01-01",
      "bindings": [{ "type": "assets", "name": "ASSETS" }, { "type": "d1", "name": "DB" }],
    });
    let meta = upload_metadata(&script, Some(&with_assets));
    assert_eq!(meta["keep_assets"], json!(true));
    assert_eq!(meta["keep_bindings"], json!(["assets", "d1"]));
    let old = WorkerScript {
      modules: false,
      ..script
    };
    assert_eq!(
      upload_metadata(&old, None),
      json!({ "body_part": "script", "compatibility_date": DEFAULT_COMPAT_DATE })
    );
  }
}
