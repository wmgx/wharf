use schemars::{SchemaGenerator, generate::SchemaSettings};
use serde_json::{Value, json};

use crate::{agent, egress, plan, spec, view};

/// 页面用到的序列化类型的 JSON Schema。
pub fn web_schema() -> Value {
  let mut generator =
    SchemaGenerator::new(SchemaSettings::default().for_serialize());
  macro_rules! types {
    ($($ty:ty),* $(,)?) => {
      $(let _ = generator.subschema_for::<$ty>();)*
    };
  }
  types!(
    spec::PrivateNetwork, view::CoreAddress, view::CoreAddresses,
    view::JoinInfo, spec::PrivateAddr, agent::AgentReport,
    view::ServerView, spec::BuildSource, spec::Source,
    spec::PortSpec, spec::VolumeSpec, spec::ServiceSpec,
    spec::MonitorSpec, view::MonitorView, agent::FoundContainer,
    view::Unmanaged, spec::AdoptSpec, view::ImportRecord,
    view::ImportPreview, agent::ContainerInfo, view::LiveState,
    view::ServiceView, spec::GatewayTls, spec::GatewaySpec,
    view::GatewayView, spec::RouteSpec, view::RouteView,
    view::ProbeView, spec::EdgeKind, spec::EdgeSource,
    spec::EdgeAppSpec, view::EdgeLive, view::EdgeAppView,
    view::EdgeProjectView, view::EdgeVersionView, view::IssueLevel,
    view::IssueSubject, view::Issue, view::Status,
    view::VersionCheck, view::UpdatesView, view::CheckStatus,
    view::DoctorCheck, view::RouteDiagnosis, view::DoctorReport,
    view::AccountView, spec::BookmarkSpec, view::BookmarkView,
    spec::Change, plan::Impact, plan::PlanItem, plan::Plan,
    plan::StepStatus, plan::RunStep, plan::Run, view::ShellLog,
    agent::ImageInfo, view::DeploymentView, view::RollbackTarget,
    agent::BackupSummary, view::BackupRecord, agent::Snapshot,
    view::BackupsView, spec::NetworkMode, view::NetworkView,
    view::SecretView, view::Perm, view::TokenView,
    view::CreatedToken, agent::PackageUpdate, agent::DockerUsage,
    agent::HostInfo, agent::SshLogin, agent::FileEntry,
    view::DataKind, view::DataMount, view::DataStatus,
    view::ServiceData, view::DataView, view::ServiceStatus,
    view::TaskKind, view::TaskSpec, view::TaskStatus,
    view::TaskRunView, view::TaskView, egress::EgressSpec,
    view::AlertRuleView, view::NoticeView, view::AlertsView,
    view::AlertPatch, view::AuditEntry, view::TimelineItem,
    view::Timeline,
  );
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
