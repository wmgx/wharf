use std::fmt;

/// Stable error codes. AI / UI can switch on these.
pub mod code {
  pub const INVALID_CONFIG: &str = "InvalidConfig";
  pub const ZONE_NOT_FOUND: &str = "ZoneNotFound";
  pub const AUTH_FAILED: &str = "AuthFailed";
  pub const RATE_LIMITED: &str = "RateLimited";
  pub const PROVIDER_UNAVAILABLE: &str = "ProviderUnavailable";
  pub const PROVIDER_REJECTED: &str = "ProviderRejected";
  pub const PROVIDER_RESPONSE: &str = "ProviderResponse";
  pub const TIMEOUT: &str = "Timeout";
  pub const FOREIGN_CONFLICT: &str = "ForeignRecordConflict";
  pub const INTERNAL: &str = "Internal";
}

/// Error returned by every provider operation.
///
/// `message` is safe to show to users (no tokens, no provider response
/// bodies). `detail` keeps the original cause for server side logs only.
#[derive(Debug, Clone)]
pub struct ProviderError {
  pub code: &'static str,
  pub message: String,
  pub retryable: bool,
  pub detail: Option<String>,
}

impl ProviderError {
  pub fn new(code: &'static str, message: impl Into<String>) -> Self {
    Self {
      code,
      message: message.into(),
      retryable: false,
      detail: None,
    }
  }

  pub fn invalid(message: impl Into<String>) -> Self {
    Self::new(code::INVALID_CONFIG, message)
  }

  pub fn retryable(mut self) -> Self {
    self.retryable = true;
    self
  }

  /// Attach the original cause. Must not contain tokens.
  pub fn with_detail(mut self, detail: impl fmt::Display) -> Self {
    self.detail = Some(detail.to_string());
    self
  }

  pub fn internal(cause: impl fmt::Display) -> Self {
    Self::new(code::INTERNAL, "Internal error, see core logs")
      .with_detail(cause)
  }

  /// Log the original cause on the server.
  pub fn log(&self, context: &str) {
    tracing::error!(
      code = self.code,
      retryable = self.retryable,
      "provider error | {context} | {} | {}",
      self.message,
      self.detail.as_deref().unwrap_or("-")
    );
  }
}

impl fmt::Display for ProviderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}: {}", self.code, self.message)
  }
}

impl std::error::Error for ProviderError {}

/// Replace every occurrence of `secret` in `text`.
pub fn redact(text: &str, secret: &str) -> String {
  if secret.is_empty() {
    text.to_string()
  } else {
    text.replace(secret, "***")
  }
}
