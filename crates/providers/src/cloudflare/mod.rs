//! Cloudflare provider: DNS records and tunnels.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::{
  BoxFut, Credentials, Discovery, DnsProvider, DnsRecordSpec,
  DnsRecordType, Owner, ProviderFactory, ProviderSet, RemoteRecord,
  dns_canonical,
  error::{ProviderError, code},
};

use client::{CloudflareClient, Zone};

mod client;
mod tunnel;

pub const FACTORY: ProviderFactory = ProviderFactory {
  kind: "cloudflare",
  build,
  discover,
};

fn discover(token: String) -> BoxFut<'static, Discovery> {
  Box::pin(async move {
    let client = CloudflareClient::new(&token)?;
    discover_with(&client).await
  })
}

async fn discover_with(
  client: &CloudflareClient,
) -> Result<Discovery, ProviderError> {
  let mut zones: Vec<String> = client
    .list_zones()
    .await?
    .into_iter()
    .map(|z| z.name)
    .collect();
  zones.sort();
  zones.dedup();
  let mut warnings = Vec::new();
  if zones.is_empty() {
    warnings.push(
      "这个 token 看不到任何 zone。需要的权限：Zone → Zone → Read，Zone → DNS → Edit".into(),
    );
  }
  Ok(Discovery { zones, warnings })
}

fn build(creds: Credentials) -> Result<ProviderSet, ProviderError> {
  let client = Arc::new(CloudflareClient::new(&creds.token)?);
  Ok(ProviderSet {
    dns: Some(Box::new(CloudflareDns {
      client: client.clone(),
      zones: creds.zones,
    })),
    tunnel: Some(Box::new(tunnel::CloudflareTunnel { client })),
  })
}

struct CloudflareDns {
  client: Arc<CloudflareClient>,
  /// Allowed zone names. Empty = any zone the token sees.
  zones: Vec<String>,
}

impl CloudflareDns {
  async fn zone_for(
    &self,
    hostname: &str,
  ) -> Result<Zone, ProviderError> {
    let zones = self.client.list_zones().await?;
    let allowed: Vec<String> = zones
      .iter()
      .filter(|z| {
        self.zones.is_empty()
          || self
            .zones
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&z.name))
      })
      .map(|z| z.name.clone())
      .collect();
    let name =
      crate::match_zone(&allowed, hostname).ok_or_else(|| {
        ProviderError::new(
          code::ZONE_NOT_FOUND,
          format!("没有可用的 Cloudflare zone 包含 '{hostname}'"),
        )
      })?;
    zones
      .into_iter()
      .find(|z| z.name == name)
      .ok_or_else(|| ProviderError::internal("matched zone vanished"))
  }
}

fn record_from(
  zone: &str,
  value: &Value,
) -> Result<RemoteRecord, ProviderError> {
  let bad = || {
    ProviderError::new(
      code::PROVIDER_RESPONSE,
      "Provider returned an invalid DNS record",
    )
  };
  let record_type = value["type"].as_str().ok_or_else(bad)?;
  let ttl = value["ttl"].as_u64().unwrap_or(1) as u32;
  Ok(RemoteRecord {
    remote_id: value["id"].as_str().ok_or_else(bad)?.to_string(),
    scope: zone.to_string(),
    canonical: dns_canonical(
      record_type,
      value["content"].as_str().ok_or_else(bad)?,
      ttl,
      value["proxied"].as_bool().unwrap_or(false),
    ),
    marker: value["comment"].as_str().map(str::to_string),
  })
}

impl DnsProvider for CloudflareDns {
  fn validate(
    &self,
    hostname: &str,
    spec: &DnsRecordSpec,
  ) -> Result<(), ProviderError> {
    if hostname.is_empty() || hostname.contains(['*', '/', ':']) {
      return Err(ProviderError::invalid(
        "An exact hostname is required",
      ));
    }
    let content_ok = match spec.record_type {
      DnsRecordType::A => {
        spec.content.parse::<std::net::Ipv4Addr>().is_ok()
      }
      DnsRecordType::AAAA => {
        spec.content.parse::<std::net::Ipv6Addr>().is_ok()
      }
      DnsRecordType::CNAME => {
        !spec.content.is_empty()
          && spec.content.bytes().all(|c| {
            c.is_ascii_alphanumeric()
              || matches!(c, b'-' | b'.' | b'_')
          })
      }
    };
    if !content_ok {
      return Err(ProviderError::invalid(format!(
        "Invalid {} record content",
        spec.record_type.as_str()
      )));
    }
    if spec.ttl != 1 && !(60..=86400).contains(&spec.ttl) {
      return Err(ProviderError::invalid(
        "TTL must be 0 (auto) or between 60 and 86400",
      ));
    }
    Ok(())
  }

  fn list<'a>(
    &'a self,
    hostname: &'a str,
  ) -> BoxFut<'a, Vec<RemoteRecord>> {
    Box::pin(async move {
      let zone = self.zone_for(hostname).await?;
      self
        .client
        .list_dns(&zone.id, hostname)
        .await?
        .iter()
        .filter(|r| {
          matches!(r["type"].as_str(), Some("A" | "AAAA" | "CNAME"))
        })
        .map(|r| record_from(&zone.id, r))
        .collect()
    })
  }

  fn upsert<'a>(
    &'a self,
    hostname: &'a str,
    spec: &'a DnsRecordSpec,
    owner: &'a Owner,
    existing: Option<&'a RemoteRecord>,
  ) -> BoxFut<'a, RemoteRecord> {
    Box::pin(async move {
      let body = json!({
        "type": spec.record_type.as_str(),
        "name": hostname,
        "content": spec.content,
        "ttl": if spec.proxied { 1 } else { spec.ttl },
        "proxied": spec.proxied,
        "comment": owner.marker(),
      });
      let (zone, result) = match existing {
        Some(existing) => (
          existing.scope.clone(),
          self
            .client
            .patch_dns(&existing.scope, &existing.remote_id, &body)
            .await?,
        ),
        None => {
          let zone = self.zone_for(hostname).await?;
          let result =
            self.client.create_dns(&zone.id, &body).await?;
          (zone.id, result)
        }
      };
      record_from(&zone, &result)
    })
  }

  fn delete<'a>(
    &'a self,
    scope: &'a str,
    remote_id: &'a str,
    owner: Option<&'a Owner>,
  ) -> BoxFut<'a, ()> {
    Box::pin(async move {
      let Some(current) =
        self.client.get_dns(scope, remote_id).await?
      else {
        return Ok(());
      };
      if let Some(owner) = owner {
        let record = record_from(scope, &current)?;
        if !self.is_owned(&record, owner) {
          // Someone replaced / re-claimed it. Not ours to delete anymore.
          tracing::warn!(
            "not deleting dns record {remote_id}: ownership marker is gone"
          );
          return Ok(());
        }
      }
      self.client.delete_dns(scope, remote_id).await
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn record_from_normalizes() {
    let record = record_from(
      "z1",
      &json!({"id":"r1","type":"A","content":"1.2.3.4","ttl":300,"proxied":false,"comment":"wharf:rt_1"}),
    )
    .unwrap();
    assert_eq!(record.remote_id, "r1");
    assert_eq!(record.marker.as_deref(), Some("wharf:rt_1"));
    assert_eq!(
      record.canonical,
      dns_canonical("A", "1.2.3.4", 300, false)
    );
  }
}
