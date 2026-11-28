use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LogAlertSpec {
  pub pattern: String,
  #[serde(default)]
  pub regex: bool,
  #[serde(default = "five")]
  pub window_mins: u32,
  #[serde(default = "one")]
  pub min_count: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
}

const fn five() -> u32 {
  5
}
const fn one() -> u32 {
  1
}

impl LogAlertSpec {
  pub fn compile(&self) -> Result<Option<regex::Regex>, ApiError> {
    if !(1..=1440).contains(&self.window_mins)
      || !(1..=10_000).contains(&self.min_count)
    {
      return Err(ApiError::invalid(
        "日志规则窗口须为 1 到 1440 分钟，最少次数须为 1 到 10000",
      ));
    }
    if self
      .container
      .as_ref()
      .is_some_and(|name| name.trim().is_empty())
    {
      return Err(ApiError::invalid("日志规则的容器名不能为空"));
    }
    self.compile_stored()
  }

  /// 继续运行升级前已保存的日志规则。
  pub fn compile_stored(
    &self,
  ) -> Result<Option<regex::Regex>, ApiError> {
    if self.pattern.is_empty()
      || self.pattern.len() > 4096
      || self.window_mins == 0
      || self.min_count == 0
    {
      return Err(ApiError::invalid(
        "日志规则的关键字长度须为 1 到 4096 字节，窗口和次数须大于 0",
      ));
    }
    if !self.regex {
      return Ok(None);
    }
    regex::RegexBuilder::new(&self.pattern)
      .size_limit(1024 * 1024)
      .dfa_size_limit(128 * 1024)
      .build()
      .map(Some)
      .map_err(|e| {
        ApiError::invalid(format!("日志正则无效：{e}"))
          .with_hint("检查正则表达式，或去掉 --regex 按普通文本匹配")
      })
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PortCheckSpec {
  Off,
  Dns { domain: String },
  Custom { send: String, expect: String },
}

impl PortCheckSpec {
  pub fn validate(&self, udp: bool) -> Result<(), ApiError> {
    self.validate_with_limits(udp, false)
  }

  /// 继续运行升级前已保存的端口检查。
  pub fn validate_stored(&self, udp: bool) -> Result<(), ApiError> {
    self.validate_with_limits(udp, true)
  }

  fn validate_with_limits(
    &self,
    udp: bool,
    stored: bool,
  ) -> Result<(), ApiError> {
    let valid = match self {
      Self::Off => true,
      Self::Dns { domain } => {
        udp
          && (domain == "." || {
            let domain = domain.trim_end_matches('.');
            domain.len() <= 253
              && domain.split('.').all(|label| {
                !label.is_empty()
                  && label.len() <= 63
                  && (stored
                    || (!label.starts_with('-')
                      && !label.ends_with('-')))
                  && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
              })
          })
      }
      Self::Custom { send, expect } => {
        udp
          && [send, expect].iter().all(|v| {
            !v.is_empty()
              && v.len() <= if stored { 65507 * 2 } else { 2048 }
              && v.len().is_multiple_of(2)
              && v.bytes().all(|b| b.is_ascii_hexdigit())
          })
      }
    };
    if valid {
      Ok(())
    } else {
      Err(ApiError::invalid("端口检查配置不合法")
        .with_hint("UDP 用 --udp-dns <域名>，或同时给 --udp-send 和 --udp-expect（十六进制）"))
    }
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct HeartbeatSpec {
  pub every_mins: u32,
  #[serde(default = "five")]
  pub grace_mins: u32,
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub token: String,
  /// 已按目标容器配置；旧心跳保留原来的全容器注入。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub targeted: bool,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub rotate: bool,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LogHit {
  pub id: String,
  pub count: u32,
  pub at: i64,
  pub lines: Vec<String>,
}

impl HeartbeatSpec {
  pub fn validate(&self) -> Result<(), ApiError> {
    if !(1..=43_200).contains(&self.every_mins)
      || self.grace_mins > 1440
    {
      return Err(ApiError::invalid(
        "心跳间隔须为 1 到 43200 分钟，宽限须为 0 到 1440 分钟",
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogWatch {
  pub id: String,
  pub project: String,
  pub spec: LogAlertSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortCheck {
  pub port: u16,
  pub udp: Option<PortCheckSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LogAlertView {
  pub pattern: String,
  pub last_hit: Option<i64>,
  pub firing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeartbeatView {
  pub url: String,
  pub last_at: Option<i64>,
  pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeartbeatReportView {
  pub at: i64,
  pub ok: bool,
  pub output: String,
}

#[test]
fn reject_out_of_range_service_checks() {
  let log = LogAlertSpec {
    pattern: "fixture".into(),
    regex: false,
    window_mins: 99999,
    min_count: 1,
    container: None,
  };
  assert!(log.compile().is_err());
  assert!(
    HeartbeatSpec {
      rotate: false,
      every_mins: 100000,
      grace_mins: 5,
      token: String::new(),
      targeted: false,
    }
    .validate()
    .is_err()
  );
  assert!(
    PortCheckSpec::Dns {
      domain: "-a.test".into()
    }
    .validate(true)
    .is_err()
  );
  assert!(
    PortCheckSpec::Custom {
      send: "ab".repeat(1025),
      expect: "ab".into()
    }
    .validate(true)
    .is_err()
  );
}
