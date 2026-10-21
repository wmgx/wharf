//! Cloudflare Tunnel：远程管理配置的隧道，由 Wharf 创建并独占。

use std::sync::Arc;

use serde_json::{Value, json};

use crate::{
  BoxFut, DnsRecordSpec, DnsRecordType, TunnelProvider, TunnelRef,
  error::ProviderError,
};

use super::client::CloudflareClient;

pub(super) struct CloudflareTunnel {
  pub(super) client: Arc<CloudflareClient>,
}

impl CloudflareTunnel {
  async fn account_id(&self) -> Result<String, ProviderError> {
    self
      .client
      .single_account("Account → Cloudflare Tunnel → Edit")
      .await
  }
}

/// 整份入口配置：给出的规则，最后一条 404 兜底。
pub fn ingress_config(rules: &[(String, String)]) -> Value {
  let mut ingress: Vec<Value> = rules
    .iter()
    .map(|(hostname, service)| {
      json!({ "hostname": hostname, "service": service })
    })
    .collect();
  ingress.push(json!({ "service": "http_status:404" }));
  json!({ "ingress": ingress })
}

impl TunnelProvider for CloudflareTunnel {
  fn find<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, Option<TunnelRef>> {
    Box::pin(async move {
      let account = self.account_id().await?;
      let tunnels = self.client.list_tunnels(&account).await?;
      Ok(
        tunnels
          .iter()
          .find(|t| t["name"].as_str() == Some(name))
          .and_then(|t| t["id"].as_str())
          .map(|id| TunnelRef {
            scope: account.clone(),
            id: id.to_string(),
          }),
      )
    })
  }

  fn create<'a>(&'a self, name: &'a str) -> BoxFut<'a, TunnelRef> {
    Box::pin(async move {
      let account = self.account_id().await?;
      let id = self.client.create_tunnel(&account, name).await?;
      Ok(TunnelRef { scope: account, id })
    })
  }

  fn put_rules<'a>(
    &'a self,
    tunnel: &'a TunnelRef,
    rules: &'a [(String, String)],
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      self
        .client
        .put_tunnel_config(
          &tunnel.scope,
          &tunnel.id,
          &ingress_config(rules),
        )
        .await
    })
  }

  fn token<'a>(
    &'a self,
    tunnel: &'a TunnelRef,
  ) -> BoxFut<'a, String> {
    Box::pin(async move {
      self.client.tunnel_token(&tunnel.scope, &tunnel.id).await
    })
  }

  fn status<'a>(
    &'a self,
    tunnel: &'a TunnelRef,
  ) -> BoxFut<'a, String> {
    Box::pin(async move {
      self.client.tunnel_status(&tunnel.scope, &tunnel.id).await
    })
  }

  fn delete<'a>(&'a self, tunnel: &'a TunnelRef) -> BoxFut<'a, ()> {
    Box::pin(async move {
      self.client.delete_tunnel(&tunnel.scope, &tunnel.id).await
    })
  }

  fn dns_target(&self, tunnel: &TunnelRef) -> DnsRecordSpec {
    DnsRecordSpec {
      record_type: DnsRecordType::CNAME,
      content: format!("{}.cfargotunnel.com", tunnel.id),
      ttl: 1,
      proxied: true,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn config_ends_with_catch_all() {
    let cfg = ingress_config(&[(
      "blog.example.com".into(),
      "http://127.0.0.1:20000".into(),
    )]);
    assert_eq!(
      cfg,
      json!({ "ingress": [
        { "hostname": "blog.example.com", "service": "http://127.0.0.1:20000" },
        { "service": "http_status:404" }
      ]})
    );
    assert_eq!(
      ingress_config(&[])["ingress"].as_array().unwrap().len(),
      1
    );
  }
}
