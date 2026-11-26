use schemars::{SchemaGenerator, generate::SchemaSettings};
use serde_json::{Value, json};

use crate::{agent, egress, plan, spec, view};

/// 页面用到的序列化类型的 JSON Schema。
pub fn web_schema() -> Value {
  let mut generator =
    SchemaGenerator::new(SchemaSettings::default().for_serialize());
  let _ = generator.subschema_for::<view::SsoTestResult>();
  let _ = generator.subschema_for::<view::CertStatus>();
  let _ = generator.subschema_for::<view::AppAccountView>();
  let _ = generator.subschema_for::<view::GateKeyView>();
  let _ = generator.subschema_for::<view::GateKeyRequest>();
  let _ = generator.subschema_for::<view::OidcView>();
  let _ = generator.subschema_for::<view::OidcSettingsRequest>();
  let _ = generator.subschema_for::<view::OidcSecretView>();
  let _ = generator.subschema_for::<spec::PrivateNetwork>();
  let _ = generator.subschema_for::<view::CoreAddress>();
  let _ = generator.subschema_for::<view::CoreAddresses>();
  let _ = generator.subschema_for::<view::JoinInfo>();
  let _ = generator.subschema_for::<spec::PrivateAddr>();
  let _ = generator.subschema_for::<agent::AgentReport>();
  let _ =
    generator.subschema_for::<crate::access_logs::AccessLogsResult>();
  let _ = generator.subschema_for::<agent::ResolvedImage>();
  let _ = generator.subschema_for::<view::ServerView>();
  let _ = generator.subschema_for::<crate::resources::UsageRow>();
  let _ = generator.subschema_for::<crate::resources::ImagesView>();
  let _ = generator.subschema_for::<spec::BuildSource>();
  let _ = generator.subschema_for::<spec::Source>();
  let _ = generator.subschema_for::<spec::PortSpec>();
  let _ = generator.subschema_for::<spec::VolumeSpec>();
  let _ = generator.subschema_for::<spec::ServiceSpec>();
  let _ = generator.subschema_for::<spec::MonitorSpec>();
  let _ = generator.subschema_for::<view::MonitorView>();
  let _ = generator.subschema_for::<agent::FoundContainer>();
  let _ = generator.subschema_for::<view::Unmanaged>();
  let _ = generator.subschema_for::<spec::AdoptSpec>();
  let _ = generator.subschema_for::<view::ImportRecord>();
  let _ = generator.subschema_for::<view::ImportPreview>();
  let _ = generator.subschema_for::<view::DockerRunRequest>();
  let _ = generator.subschema_for::<view::ServiceDraft>();
  let _ = generator.subschema_for::<agent::ContainerInfo>();
  let _ = generator.subschema_for::<view::LiveState>();
  let _ = generator.subschema_for::<view::ServiceView>();
  let _ = generator.subschema_for::<view::ExposureView>();
  let _ = generator.subschema_for::<spec::GatewayTls>();
  let _ = generator.subschema_for::<spec::GatewaySpec>();
  let _ = generator.subschema_for::<view::GatewayView>();
  let _ = generator.subschema_for::<spec::RouteSpec>();
  let _ = generator.subschema_for::<view::RouteView>();
  let _ = generator.subschema_for::<view::ProbeView>();
  let _ = generator.subschema_for::<spec::EdgeKind>();
  let _ = generator.subschema_for::<spec::EdgeSource>();
  let _ = generator.subschema_for::<spec::EdgeAppSpec>();
  let _ = generator.subschema_for::<view::EdgeLive>();
  let _ = generator.subschema_for::<view::EdgeAppView>();
  let _ = generator.subschema_for::<view::EdgeProjectView>();
  let _ = generator.subschema_for::<view::EdgeVersionView>();
  let _ = generator.subschema_for::<view::IssueLevel>();
  let _ = generator.subschema_for::<view::IssueSubject>();
  let _ = generator.subschema_for::<view::Issue>();
  let _ = generator.subschema_for::<view::Status>();
  let _ = generator.subschema_for::<view::VersionCheck>();
  let _ = generator.subschema_for::<view::UpdatesView>();
  let _ = generator.subschema_for::<view::CheckStatus>();
  let _ = generator.subschema_for::<view::DoctorCheck>();
  let _ = generator.subschema_for::<view::RouteDiagnosis>();
  let _ = generator.subschema_for::<view::DoctorReport>();
  let _ = generator.subschema_for::<view::AccountView>();
  let _ = generator.subschema_for::<spec::BookmarkSpec>();
  let _ = generator.subschema_for::<view::BookmarkView>();
  let _ = generator.subschema_for::<spec::Change>();
  let _ = generator.subschema_for::<plan::Impact>();
  let _ = generator.subschema_for::<plan::PlanItem>();
  let _ = generator.subschema_for::<plan::Plan>();
  let _ = generator.subschema_for::<plan::StepStatus>();
  let _ = generator.subschema_for::<plan::RunStep>();
  let _ = generator.subschema_for::<plan::Run>();
  let _ = generator.subschema_for::<view::ShellLog>();
  let _ = generator.subschema_for::<agent::ImageInfo>();
  let _ = generator.subschema_for::<view::DeploymentView>();
  let _ = generator.subschema_for::<view::RollbackTarget>();
  let _ = generator.subschema_for::<agent::BackupSummary>();
  let _ = generator.subschema_for::<view::BackupRecord>();
  let _ = generator.subschema_for::<agent::Snapshot>();
  let _ = generator.subschema_for::<view::BackupsView>();
  let _ = generator.subschema_for::<spec::NetworkMode>();
  let _ = generator.subschema_for::<view::NetworkView>();
  let _ =
    generator.subschema_for::<crate::net_probe::NetProbeRequest>();
  let _ =
    generator.subschema_for::<crate::net_probe::NetProbeReport>();
  let _ = generator.subschema_for::<crate::external::AclView>();
  let _ =
    generator.subschema_for::<crate::external::ExternalStatus>();
  let _ = generator.subschema_for::<crate::external::DnsCheck>();
  let _ = generator.subschema_for::<view::SecretView>();
  let _ = generator.subschema_for::<view::CoreKeyView>();
  let _ = generator.subschema_for::<view::Perm>();
  let _ = generator.subschema_for::<view::TotpView>();
  let _ = generator.subschema_for::<view::SessionRow>();
  let _ = generator.subschema_for::<view::TokenView>();
  let _ = generator.subschema_for::<view::CreatedToken>();
  let _ = generator.subschema_for::<view::TokenSettings>();
  let _ = generator.subschema_for::<view::TokenExplain>();
  let _ = generator.subschema_for::<agent::PackageUpdate>();
  let _ = generator.subschema_for::<agent::DockerUsage>();
  let _ = generator.subschema_for::<agent::HostInfo>();
  let _ = generator.subschema_for::<agent::SshLogin>();
  let _ = generator.subschema_for::<agent::FileEntry>();
  let _ = generator.subschema_for::<view::DataKind>();
  let _ = generator.subschema_for::<view::DataMount>();
  let _ = generator.subschema_for::<view::DataStatus>();
  let _ = generator.subschema_for::<view::ServiceData>();
  let _ = generator.subschema_for::<view::DataView>();
  let _ = generator.subschema_for::<view::ServiceStatus>();
  let _ = generator.subschema_for::<view::TaskKind>();
  let _ = generator.subschema_for::<view::TaskSpec>();
  let _ = generator.subschema_for::<view::TaskStatus>();
  let _ = generator.subschema_for::<view::TaskRunView>();
  let _ = generator.subschema_for::<view::TaskView>();
  let _ = generator.subschema_for::<egress::EgressSpec>();
  let _ = generator.subschema_for::<view::AlertRuleView>();
  let _ = generator.subschema_for::<view::NoticeView>();
  let _ = generator.subschema_for::<view::AlertsView>();
  let _ = generator.subschema_for::<view::AlertPatch>();
  let _ = generator.subschema_for::<view::AuditEntry>();
  let _ = generator.subschema_for::<view::TimelineItem>();
  let _ = generator.subschema_for::<view::Timeline>();
  json!({ "$defs": generator.take_definitions(true) })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn service_required_fields() {
    let schema = web_schema();
    let service = &schema["$defs"]["ServiceSpec"];
    let mut required: Vec<_> = service["required"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap())
      .collect();
    required.sort_unstable();
    assert_eq!(required, ["server", "source"]);
  }
}
