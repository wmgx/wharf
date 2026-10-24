//! Provider abstraction. A provider kind (eg. `cloudflare`) is registered
//! once in [REGISTRY]: [DnsProvider] for records, [TunnelProvider] for
//! tunnel gateways, [EdgeProvider] for edge apps (Workers / Pages).
//!
//! Adding a vendor = one new module + one line in [REGISTRY].

use std::{fmt, future::Future, pin::Pin};

use serde_json::{Value, json};

mod cloudflare;
pub mod error;
pub mod tailscale;
pub mod validate;

pub use error::ProviderError;

pub type BoxFut<'a, T> =
  Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// Who owns remote objects: a Wharf route.
#[derive(Debug, Clone)]
pub struct Owner {
  /// Route id
  pub id: String,
}

impl Owner {
  /// Marker written on remote objects which support comments.
  pub fn marker(&self) -> String {
    format!("wharf:{}", self.id)
  }
}

// DNS

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
  A,
  AAAA,
  CNAME,
}

impl DnsRecordType {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::A => "A",
      Self::AAAA => "AAAA",
      Self::CNAME => "CNAME",
    }
  }
}

/// Fully resolved desired DNS record.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecordSpec {
  pub record_type: DnsRecordType,
  pub content: String,
  /// 1 = provider automatic
  pub ttl: u32,
  pub proxied: bool,
}

impl DnsRecordSpec {
  pub fn canonical(&self) -> Value {
    dns_canonical(
      self.record_type.as_str(),
      &self.content,
      self.ttl,
      self.proxied,
    )
  }
}

/// The normalized form compared by plan.
/// Providers MUST produce remote records in exactly this shape.
pub fn dns_canonical(
  record_type: &str,
  content: &str,
  ttl: u32,
  proxied: bool,
) -> Value {
  let content = content
    .parse::<std::net::IpAddr>()
    .map(|ip| ip.to_string())
    .unwrap_or_else(|_| {
      content.trim_end_matches('.').to_ascii_lowercase()
    });
  json!({
    "type": record_type,
    "content": content,
    // proxied records always have automatic ttl
    "ttl": if proxied || ttl == 0 { 1 } else { ttl },
    "proxied": proxied,
  })
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoteRecord {
  /// Provider object id
  pub remote_id: String,
  /// Provider container (eg. zone id), needed to write / delete
  pub scope: String,
  /// See [dns_canonical]
  pub canonical: Value,
  /// Ownership marker found on the record, if the provider has one.
  pub marker: Option<String>,
}

pub trait DnsProvider: Send + Sync {
  /// Local validation of the desired record. No network.
  fn validate(
    &self,
    hostname: &str,
    spec: &DnsRecordSpec,
  ) -> Result<(), ProviderError>;

  /// All address records (A / AAAA / CNAME) named exactly `hostname`.
  fn list<'a>(
    &'a self,
    hostname: &'a str,
  ) -> BoxFut<'a, Vec<RemoteRecord>>;

  /// Create the record, or update `existing`. Writes the ownership marker.
  fn upsert<'a>(
    &'a self,
    hostname: &'a str,
    spec: &'a DnsRecordSpec,
    owner: &'a Owner,
    existing: Option<&'a RemoteRecord>,
  ) -> BoxFut<'a, RemoteRecord>;

  /// Delete a record. With `owner`, it must be a no-op if the record
  /// is already gone or no longer carries the owner's marker.
  /// Without `owner` (explicitly confirmed take over), delete it anyway.
  fn delete<'a>(
    &'a self,
    scope: &'a str,
    remote_id: &'a str,
    owner: Option<&'a Owner>,
  ) -> BoxFut<'a, ()>;

  fn is_owned(&self, record: &RemoteRecord, owner: &Owner) -> bool {
    record.marker.as_deref() == Some(owner.marker().as_str())
  }
}

// TUNNEL

/// A tunnel at the provider: container (eg. account id) and object id.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelRef {
  pub scope: String,
  pub id: String,
}

/// Tunnels for `cloudflare_tunnel`-like gateways. Wharf creates the
/// tunnel and owns it entirely: the whole ingress configuration is
/// written by Wharf, so there is nothing to merge.
pub trait TunnelProvider: Send + Sync {
  /// A tunnel Wharf created earlier, by name (so a lost local record
  /// never leads to a second tunnel).
  fn find<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, Option<TunnelRef>>;

  fn create<'a>(&'a self, name: &'a str) -> BoxFut<'a, TunnelRef>;

  /// Replace the ingress with `rules` (hostname, origin url), followed
  /// by a catch-all 404.
  fn put_rules<'a>(
    &'a self,
    tunnel: &'a TunnelRef,
    rules: &'a [(String, String)],
  ) -> BoxFut<'a, ()>;

  /// Connector credential. Never log it.
  fn token<'a>(&'a self, tunnel: &'a TunnelRef)
  -> BoxFut<'a, String>;

  /// eg. `healthy`, `down`, `inactive`.
  fn status<'a>(
    &'a self,
    tunnel: &'a TunnelRef,
  ) -> BoxFut<'a, String>;

  /// No-op if already gone.
  fn delete<'a>(&'a self, tunnel: &'a TunnelRef) -> BoxFut<'a, ()>;

  /// Where hostnames of this tunnel should point.
  fn dns_target(&self, tunnel: &TunnelRef) -> DnsRecordSpec;
}

// EDGE

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
  Worker,
  Pages,
}

/// A Worker script or a Pages project at the provider.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EdgeProject {
  pub name: String,
  /// Default public url, if enabled.
  pub url: Option<String>,
  pub modified_at: Option<String>,
  /// Worker: ES module format.
  pub modules: bool,
  /// Pages: deployments to this branch are production.
  pub production_branch: Option<String>,
  /// Pages: `<x>.pages.dev`, where custom hostnames must point.
  pub subdomain: Option<String>,
  /// Latest production deployment: time and trigger (`wrangler`, `dashboard`...).
  pub deployed_at: Option<String>,
  pub deployed_by: Option<String>,
}

/// One version (Worker) or production deployment (Pages).
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeVersion {
  pub id: String,
  pub created_at: String,
  pub source: Option<String>,
  pub message: Option<String>,
  pub active: bool,
  pub url: Option<String>,
}

/// The main module of a Worker.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkerScript {
  pub filename: String,
  pub content: String,
  pub modules: bool,
}

/// Workers / Pages. Wharf never deletes provider projects: removing an
/// edge app only stops managing it.
pub trait EdgeProvider: Send + Sync {
  /// The provider account (eg. Cloudflare account id) wrangler deploys to.
  fn account_id(&self) -> BoxFut<'_, String>;

  /// Every Worker and Pages project the token can see.
  fn list(&self) -> BoxFut<'_, Vec<(EdgeKind, EdgeProject)>>;

  /// `None` if it does not exist.
  fn get<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Option<EdgeProject>>;

  fn download_worker<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, WorkerScript>;

  /// Upload a single file Worker as a new deployed version. Variables,
  /// secrets and bindings configured in the dashboard are kept.
  fn upload_worker<'a>(
    &'a self,
    name: &'a str,
    script: &'a WorkerScript,
  ) -> BoxFut<'a, ()>;

  /// Create the Pages project if missing.
  fn ensure_pages<'a>(
    &'a self,
    name: &'a str,
  ) -> BoxFut<'a, EdgeProject>;

  /// Newest first.
  fn versions<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Vec<EdgeVersion>>;

  fn rollback<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    version: &'a str,
  ) -> BoxFut<'a, ()>;

  /// Custom hostnames bound to the project.
  fn domains<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
  ) -> BoxFut<'a, Vec<String>>;

  /// Bind a custom hostname. `takeover`: replace an existing DNS record
  /// (Workers manage the record themselves).
  fn attach_domain<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    hostname: &'a str,
    takeover: bool,
  ) -> BoxFut<'a, ()>;

  /// No-op if not bound.
  fn detach_domain<'a>(
    &'a self,
    kind: EdgeKind,
    name: &'a str,
    hostname: &'a str,
  ) -> BoxFut<'a, ()>;

  /// The DNS record a custom hostname needs, when the provider does not
  /// create it with the binding (Pages). `None`: the provider manages it.
  fn domain_dns(
    &self,
    kind: EdgeKind,
    project: &EdgeProject,
  ) -> Option<DnsRecordSpec>;
}

// REGISTRY

/// Credentials of one account. No Debug output of the token.
#[derive(Clone)]
pub struct Credentials {
  pub name: String,
  pub token: String,
  /// Discovered zones the account may use. Empty = any visible zone.
  pub zones: Vec<String>,
}

impl fmt::Debug for Credentials {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Credentials")
      .field("name", &self.name)
      .field("token", &"***")
      .finish()
  }
}

/// What a token can see, so the UI / CLI never asks for ids.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Discovery {
  pub zones: Vec<String>,
  pub warnings: Vec<String>,
}

#[derive(Default)]
pub struct ProviderSet {
  pub dns: Option<Box<dyn DnsProvider>>,
  pub tunnel: Option<Box<dyn TunnelProvider>>,
  pub edge: Option<Box<dyn EdgeProvider>>,
}

pub struct ProviderFactory {
  pub kind: &'static str,
  pub build: fn(Credentials) -> Result<ProviderSet, ProviderError>,
  /// List the zones a token can access (read only).
  pub discover: fn(String) -> BoxFut<'static, Discovery>,
}

/// Add new vendors here.
pub static REGISTRY: &[ProviderFactory] = &[cloudflare::FACTORY];

pub fn factory(kind: &str) -> Option<&'static ProviderFactory> {
  REGISTRY.iter().find(|f| f.kind == kind)
}

/// Longest-suffix zone match: the zone `hostname` belongs to.
pub fn match_zone<'a>(
  zones: &'a [String],
  hostname: &str,
) -> Option<&'a str> {
  let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
  zones
    .iter()
    .filter(|zone| {
      hostname == **zone || hostname.ends_with(&format!(".{zone}"))
    })
    .max_by_key(|zone| zone.len())
    .map(String::as_str)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn zone_match_is_longest_suffix() {
    let zones =
      vec!["example.com".to_string(), "a.example.com".into()];
    assert_eq!(
      match_zone(&zones, "x.a.example.com"),
      Some("a.example.com")
    );
    assert_eq!(
      match_zone(&zones, "who.example.com"),
      Some("example.com")
    );
    assert_eq!(match_zone(&zones, "xexample.com"), None);
  }

  #[test]
  fn canonical_normalizes() {
    assert_eq!(
      dns_canonical("CNAME", "X.Example.com.", 300, true),
      json!({"type":"CNAME","content":"x.example.com","ttl":1,"proxied":true})
    );
  }
}
