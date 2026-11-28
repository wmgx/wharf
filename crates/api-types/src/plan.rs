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
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service_action: Option<ServiceAction>,
  /// 局部修改。与 fleet、partial、service_action 互斥。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub changes: Vec<Change>,
  /// 完整期望状态，文件里没有的服务、网关、路由会被计划删除。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub fleet: Option<Fleet>,
  /// 局部期望状态：只新建或修改文件里写到的对象，没写到的不动，也不会删除。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub partial: Option<Fleet>,
  /// 计划备注，随计划保存，执行时记进操作记录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(
  tag = "action",
  rename_all = "snake_case",
  deny_unknown_fields
)]
pub enum ServiceAction {
  Restart {
    tag: String,
  },
  Stop {
    tag: String,
  },
  Update {
    tag: String,
  },
  Rename {
    source: String,
    target: String,
  },
  Clone {
    source: String,
    target: String,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    copy_data: bool,
  },
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
pub enum ServiceActionKind {
  Restart,
  Stop,
  Update,
  Clone,
  Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlannedServiceAction {
  pub action: ServiceActionKind,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tag: Option<String>,
  pub targets: Vec<String>,
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

/// 计划项会造成的影响，一项可以有多个。
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
pub enum Impact {
  /// 重建容器，断几秒。
  Restart,
  /// 较长时间不可用：迁移同步、停止服务、删除路由后域名打不开。
  Downtime,
  /// 删除服务、容器、网关、隧道或记录（数据保留）。
  Remove,
  /// 数据会被删，或迁移后服务看不到这些数据。
  DataLoss,
  /// 覆盖不是 Wharf 创建的东西：DNS 记录、同名 compose 里的容器。
  Overwrite,
  /// 对公网开放，且没开 auth。
  Public,
}

impl Impact {
  pub fn label(self) -> &'static str {
    match self {
      Self::Restart => "重启",
      Self::Downtime => "停服",
      Self::Remove => "删除",
      Self::DataLoss => "丢数据",
      Self::Overwrite => "覆盖",
      Self::Public => "公开",
    }
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
  /// 旧计划里没有这个字段（当时是单个 `risk`），读出来为空。
  #[serde(default)]
  pub impacts: Vec<Impact>,
  pub reason: String,
  /// 修改时具体改了哪些字段，由 `before`、`after` 算出。旧计划里没有。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub changes: Vec<FieldChange>,
  /// 触达宿主机的原因；非空时 apply 阶段需要 host 权限且目标服务器开启对应开关。旧计划里没有。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub host_access: Vec<String>,
}

/// 配置里改动的一个字段。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct FieldChange {
  /// 字段路径，例如 `env.TZ`、`source.compose.content`。
  pub path: String,
  /// 没有这个字段时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub before: Option<Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub after: Option<Value>,
  /// 多行文本（比如 compose）按行对比：`-` 删掉的行，`+` 新增的行，
  /// 空格开头是上下文，`…` 表示省略了没变的行。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub lines: Vec<String>,
}

/// 逐字段对比两份配置。对象按键展开，数组和标量整体比较。
pub fn field_changes(
  before: &Value,
  after: &Value,
) -> Vec<FieldChange> {
  let mut out = Vec::new();
  walk("", Some(before), Some(after), &mut out);
  out
}

fn walk(
  path: &str,
  before: Option<&Value>,
  after: Option<&Value>,
  out: &mut Vec<FieldChange>,
) {
  if before == after {
    return;
  }
  if let (Some(Value::Object(b)), Some(Value::Object(a))) =
    (before, after)
  {
    let keys: std::collections::BTreeSet<&String> =
      b.keys().chain(a.keys()).collect();
    for k in keys {
      let sub = if path.is_empty() {
        k.clone()
      } else {
        format!("{path}.{k}")
      };
      walk(&sub, b.get(k), a.get(k), out);
    }
    return;
  }
  // 字段从无到有或从有到无时，null 和缺失看作一样。
  let before = before.filter(|v| !v.is_null());
  let after = after.filter(|v| !v.is_null());
  if before == after {
    return;
  }
  let lines = match (before, after) {
    (Some(Value::String(b)), Some(Value::String(a)))
      if b.contains('\n') || a.contains('\n') =>
    {
      line_diff(b, a)
    }
    _ => vec![],
  };
  let (before, after) = if lines.is_empty() {
    (before.cloned(), after.cloned())
  } else {
    (None, None)
  };
  out.push(FieldChange {
    path: path.to_string(),
    before,
    after,
    lines,
  });
}

/// 按行对比（最长公共子序列），改动处前后各留 2 行上下文。
fn line_diff(before: &str, after: &str) -> Vec<String> {
  const CONTEXT: usize = 2;
  let b: Vec<&str> = before.lines().collect();
  let a: Vec<&str> = after.lines().collect();
  let (n, m) = (b.len(), a.len());
  let mut lcs = vec![vec![0u32; m + 1]; n + 1];
  for i in (0..n).rev() {
    for j in (0..m).rev() {
      lcs[i][j] = if b[i] == a[j] {
        lcs[i + 1][j + 1] + 1
      } else {
        lcs[i + 1][j].max(lcs[i][j + 1])
      };
    }
  }
  let mut ops: Vec<(char, &str)> = Vec::new();
  let (mut i, mut j) = (0, 0);
  while i < n || j < m {
    if i < n && j < m && b[i] == a[j] {
      ops.push((' ', b[i]));
      i += 1;
      j += 1;
    } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push(('-', b[i]));
      i += 1;
    } else {
      ops.push(('+', a[j]));
      j += 1;
    }
  }
  let near = |k: usize| {
    let lo = k.saturating_sub(CONTEXT);
    let hi = (k + CONTEXT + 1).min(ops.len());
    ops[lo..hi].iter().any(|(c, _)| *c != ' ')
  };
  let mut out = Vec::new();
  let mut skipped = false;
  for (k, (c, line)) in ops.iter().enumerate() {
    if near(k) {
      if skipped {
        out.push("…".to_string());
        skipped = false;
      }
      out.push(format!("{c} {line}"));
    } else {
      skipped = true;
    }
  }
  if skipped {
    out.push("…".to_string());
  }
  out
}

impl PlanItem {
  /// 触达宿主机，apply 时需要 `host` 权限且目标服务器开启对应开关。
  pub fn needs_host(&self) -> bool {
    !self.host_access.is_empty()
  }

  /// 要 `--confirm <address>`：丢数据、覆盖、公开，以及删除服务。
  pub fn needs_confirm(&self) -> bool {
    self.impacts.iter().any(|i| match i {
      Impact::DataLoss | Impact::Overwrite | Impact::Public => true,
      Impact::Remove => self.address.starts_with("service/"),
      _ => false,
    })
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
pub enum PlanStatus {
  Pending,
  Applied,
  Expired,
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
  /// plan 时连通性结果和密钥的指纹：直连还是走隧道、渲染出的配置都取决于它们，
  /// apply 时变了就拒绝执行。旧计划没有这个字段，不检查。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub inputs: Option<String>,
  pub items: Vec<PlanItem>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service_action: Option<PlannedServiceAction>,
  /// 不阻止 apply 的提醒，例如某台服务器离线，查不到现状。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
  /// 触达宿主机、apply 时需要 `host` 权限且目标服务器开启对应开关的地址。
  #[serde(
    default,
    alias = "needs_admin",
    skip_serializing_if = "Vec::is_empty"
  )]
  pub needs_host: Vec<String>,
  /// 需要 `--confirm` 的地址。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub needs_confirm: Vec<String>,
  /// 建议的下一步命令。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub suggest: Vec<String>,
  /// 生成计划时写的备注。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlanSummary {
  pub plan_id: String,
  pub status: PlanStatus,
  pub created_at: DateTime<Utc>,
  pub expires_at: DateTime<Utc>,
  pub expires_in_secs: i64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
  pub item_count: usize,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub needs_confirm: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub addresses: Vec<String>,
}

pub fn confirm_details(plan: &Plan, missing: &[&String]) -> Value {
  let items: Vec<_> = plan.items.iter()
    .filter(|item| missing.contains(&&item.address) && item.needs_confirm())
    .map(|item| serde_json::json!({
      "id": item.id, "address": item.address, "layer": item.layer,
      "action": item.action, "impacts": item.impacts, "reason": item.reason,
      "host_access": item.host_access,
    })).collect();
  serde_json::json!({
    "plan_id": plan.plan_id, "expires_at": plan.expires_at, "needs_confirm": missing,
    "items": items, "warnings": plan.warnings,
  })
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
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub skip_snapshot: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub verify_before_dns: Option<bool>,
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
  /// 本步骤收到的日志总行数。
  #[serde(default, skip_serializing_if = "run_log_lines_zero")]
  pub log_lines: u64,
  /// 摘要日志只保留尾部；完整日志可另行读取。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub log_truncated: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<ApiError>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub started_at: Option<DateTime<Utc>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub finished_at: Option<DateTime<Utc>>,
}

fn run_log_lines_zero(n: &u64) -> bool {
  *n == 0
}

/// 一次执行记录。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Run {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub actor: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retry_of: Option<String>,
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn confirm_follows_impacts() {
    let item = |address: &str, impacts: Vec<Impact>| PlanItem {
      id: 1,
      address: address.into(),
      layer: Layer::Config,
      action: Action::Delete,
      before: None,
      after: None,
      impacts,
      reason: String::new(),
      changes: vec![],
      host_access: vec![],
    };
    assert!(item("service/a", vec![Impact::Remove]).needs_confirm());
    // 删除网关、隧道只提示，不用确认。
    assert!(!item("gateway/a", vec![Impact::Remove]).needs_confirm());
    assert!(
      !item("service/a", vec![Impact::Restart]).needs_confirm()
    );
    assert!(
      item("route/a", vec![Impact::Restart, Impact::Public])
        .needs_confirm()
    );
  }

  #[test]
  fn field_changes_by_path() {
    let before = serde_json::json!({
      "env": {"TZ": "UTC", "OLD": "1"},
      "ports": [80],
      "source": {"compose": {"content": "a\nb\nc\nd\ne\nf\ng\n"}},
      "auth": null,
    });
    let after = serde_json::json!({
      "env": {"TZ": "Asia/Shanghai", "NEW": "2"},
      "ports": [80],
      "source": {"compose": {"content": "a\nb\nc\nd\nE\nf\ng\n"}},
    });
    let c = field_changes(&before, &after);
    let paths: Vec<&str> =
      c.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
      paths,
      ["env.NEW", "env.OLD", "env.TZ", "source.compose.content"]
    );
    assert_eq!(c[0].before, None);
    assert_eq!(c[0].after, Some(serde_json::json!("2")));
    assert_eq!(c[1].after, None);
    assert_eq!(
      c[3].lines,
      ["…", "  c", "  d", "- e", "+ E", "  f", "  g"]
    );
  }
}
