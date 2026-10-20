use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 稳定的错误码。AI 和页面可以按它分支处理。
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
pub enum ErrorCode {
  InvalidInput,
  NotFound,
  AlreadyExists,
  Conflict,
  Unauthorized,
  Forbidden,
  /// plan 之后资源已被修改，需要重新 plan。CLI 退出码 3。
  PlanStale,
  /// 计划里有高风险项，需要 `--confirm`。CLI 退出码 2。
  ConfirmRequired,
  /// 已有一个 apply 在执行。
  Busy,
  AgentOffline,
  /// agent 执行外部命令失败，例如 docker 报错。
  AgentFailed,
  Timeout,
  Cancelled,
  /// 厂商（Cloudflare）接口出错。
  Provider,
  NotImplemented,
  Internal,
}

impl ErrorCode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::InvalidInput => "InvalidInput",
      Self::NotFound => "NotFound",
      Self::AlreadyExists => "AlreadyExists",
      Self::Conflict => "Conflict",
      Self::Unauthorized => "Unauthorized",
      Self::Forbidden => "Forbidden",
      Self::PlanStale => "PlanStale",
      Self::ConfirmRequired => "ConfirmRequired",
      Self::Busy => "Busy",
      Self::AgentOffline => "AgentOffline",
      Self::AgentFailed => "AgentFailed",
      Self::Timeout => "Timeout",
      Self::Cancelled => "Cancelled",
      Self::Provider => "Provider",
      Self::NotImplemented => "NotImplemented",
      Self::Internal => "Internal",
    }
  }

  /// API 返回时使用的 HTTP 状态码。
  pub fn http_status(self) -> u16 {
    match self {
      Self::InvalidInput => 400,
      Self::Unauthorized => 401,
      Self::Forbidden => 403,
      Self::NotFound => 404,
      Self::AlreadyExists
      | Self::Conflict
      | Self::PlanStale
      | Self::Busy => 409,
      Self::ConfirmRequired => 428,
      Self::NotImplemented => 501,
      Self::AgentOffline | Self::AgentFailed | Self::Provider => 502,
      Self::Timeout => 504,
      Self::Cancelled => 499,
      Self::Internal => 500,
    }
  }

  /// CLI 退出码，见设计文档第 6 节。
  pub fn exit_code(self) -> i32 {
    match self {
      Self::ConfirmRequired => 2,
      Self::PlanStale => 3,
      _ => 1,
    }
  }
}

/// 统一错误格式。`message` 可以直接给用户看，不含 token 和厂商原始响应。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
  pub code: ErrorCode,
  pub message: String,
  /// 怎么解决。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub hint: Option<String>,
  /// 可以直接执行的下一步命令。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub suggest: Vec<String>,
}

impl ApiError {
  pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
    Self {
      code,
      message: message.into(),
      hint: None,
      suggest: Vec::new(),
    }
  }

  pub fn invalid(message: impl Into<String>) -> Self {
    Self::new(ErrorCode::InvalidInput, message)
  }

  pub fn not_found(message: impl Into<String>) -> Self {
    Self::new(ErrorCode::NotFound, message)
  }

  pub fn internal(message: impl Into<String>) -> Self {
    Self::new(ErrorCode::Internal, message)
  }

  pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
    self.hint = Some(hint.into());
    self
  }

  pub fn suggest(mut self, command: impl Into<String>) -> Self {
    self.suggest.push(command.into());
    self
  }
}

impl fmt::Display for ApiError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}: {}", self.code.as_str(), self.message)?;
    if let Some(hint) = &self.hint {
      write!(f, "（{hint}）")?;
    }
    Ok(())
  }
}

impl std::error::Error for ApiError {}
