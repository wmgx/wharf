//! 周期报告（`GET /api/report` / `wharf report`）的返回类型。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 单个指标的本期值、上期值与环比变化百分比。
#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct MetricDelta {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub current: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub previous: Option<f64>,
  /// 相对上期的变化百分比（正数增加，负数减少）；上期无数据或上期为 0 且本期非 0 时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub change_pct: Option<f64>,
}

/// 报告实际覆盖的时间范围。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportCoverage {
  pub period_start: i64,
  pub period_end: i64,
  pub previous_start: i64,
  pub previous_end: i64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub earliest_at: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub latest_at: Option<i64>,
  pub has_current: bool,
  pub has_previous: bool,
}

/// 单台服务器的周期指标。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerReport {
  pub name: String,
  /// CPU 均值（%）。
  pub cpu_avg: MetricDelta,
  /// CPU 峰值（%）。
  pub cpu_peak: MetricDelta,
  /// 内存均值（字节）。
  pub mem_avg: MetricDelta,
  /// 内存峰值（字节）。
  pub mem_peak: MetricDelta,
  /// 整机内存容量（字节），用于判断峰值是否接近上限。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mem_total: Option<f64>,
  /// 周期内磁盘用量变化（字节，末值减初值）。
  pub disk_change: MetricDelta,
  /// 本期最新磁盘已用（字节）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub disk_used: Option<f64>,
  /// 本期最新磁盘总量（字节）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub disk_total: Option<f64>,
  /// 周期内网络接收总量（字节）。
  pub net_rx_bytes: MetricDelta,
  /// 周期内网络发送总量（字节）。
  pub net_tx_bytes: MetricDelta,
}

/// 单个服务的周期指标。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceReport {
  pub name: String,
  pub server: String,
  /// CPU 均值（%）。
  pub cpu_avg: MetricDelta,
  /// 内存均值（字节）。
  pub mem_avg: MetricDelta,
  /// 内存峰值（字节）。
  pub mem_peak: MetricDelta,
  /// 配置的内存上限（字节）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mem_limit: Option<u64>,
  /// 经网关的总请求数估算。
  pub requests: MetricDelta,
  /// 5xx 占比均值（%）。
  pub err_pct: MetricDelta,
  /// p95 延迟均值（毫秒）。
  pub p95_ms: MetricDelta,
}

/// 单条告警规则在周期内的触发次数对比。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AlertReport {
  pub rule: String,
  pub name: String,
  pub current: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub previous: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub change_pct: Option<f64>,
}

/// `GET /api/report` 的返回结构。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportView {
  pub days: u32,
  pub coverage: ReportCoverage,
  pub summary: Vec<String>,
  #[serde(default)]
  pub servers: Vec<ServerReport>,
  #[serde(default)]
  pub services: Vec<ServiceReport>,
  #[serde(default)]
  pub alerts: Vec<AlertReport>,
}
