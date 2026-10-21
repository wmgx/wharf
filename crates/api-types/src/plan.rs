//! plan / apply，见设计文档第 3、4 节。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
  ApiError,
  spec::{Change, Fleet},
};

#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
  /// 局部修改。和 `fleet` 二选一；都不给时只检查漂移。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub changes: Vec<Change>,
  /// 完整期望状态，文件里没有的服务、网关、路由会被计划删除。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub fleet: Option<Fleet>,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
  /// 控制面数据库里的配置。
  Config,
  Volume,
  Container,
  Gateway,
  Dns,
  Tunnel,
  /// 边缘应用（Workers / Pages）：发布、绑定自定义域名。
  Edge,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
  Create,
  Update,
  Delete,
  /// 接管一个不是 Wharf 创建的远端对象。
  Adopt,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
  /// 新增，或可以无损回滚的修改。
  Safe,
  /// 会重启服务或造成短暂中断。
  Disruptive,
  /// 删除服务、删除数据、覆盖别人的对象。
  Destructive,
  /// 对外暴露且未开启 auth。
  ExposesPublic,
}

impl Risk {
  /// 需要 `--confirm <address>` 的风险。
  pub fn needs_confirm(self) -> bool {
    matches!(self, Self::Destructive | Self::ExposesPublic)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlanItem {
  pub id: u32,
  /// 例如 `service/whoami`、`route/who.example.com`。
  pub address: String,
  pub layer: Layer,
  pub action: Action,
  #[serde(default)]
  pub before: Option<Value>,
  #[serde(default)]
  pub after: Option<Value>,
  pub risk: Risk,
  pub reason: String,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
  Pending,
  Applied,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Plan {
  pub plan_id: String,
  pub status: PlanStatus,
  pub created_at: DateTime<Utc>,
  /// 过期后不能 apply，需要重新 plan。
  pub expires_at: DateTime<Utc>,
  /// plan 时读到的资源版本。apply 时任何一个变了都拒绝执行。
  pub base_versions: BTreeMap<String, u64>,
  pub items: Vec<PlanItem>,
  /// 不阻止 apply 的提醒，例如某台服务器离线，查不到现状。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
  /// 需要 `--confirm` 的地址。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub needs_confirm: Vec<String>,
  /// 建议的下一步命令。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub suggest: Vec<String>,
}

impl Plan {
  pub fn is_empty(&self) -> bool {
    self.items.is_empty()
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
  pub plan_id: String,
  /// 确认高风险项的地址。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub confirm: Vec<String>,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
  Running,
  Succeeded,
  /// 有步骤失败。配置已经写入，再执行 `wharf plan` 可以看到剩下的差异。
  Failed,
  Cancelled,
}

impl RunStatus {
  pub fn finished(self) -> bool {
    self != Self::Running
  }
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
  Pending,
  Running,
  Done,
  Failed,
  /// 前面的步骤失败或执行被取消，没有执行。
  Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunStep {
  /// 对应的计划项 id。一个步骤可能完成多个计划项，例如配置写入。
  pub items: Vec<u32>,
  pub title: String,
  pub status: StepStatus,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub log: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<ApiError>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub started_at: Option<DateTime<Utc>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub finished_at: Option<DateTime<Utc>>,
}

/// 一次执行记录。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Run {
  pub run_id: String,
  pub plan_id: String,
  pub status: RunStatus,
  pub started_at: DateTime<Utc>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub finished_at: Option<DateTime<Utc>>,
  pub steps: Vec<RunStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApplyResponse {
  pub run_id: String,
}
