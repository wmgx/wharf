//! 控制面、agent、CLI 共享的类型。
//!
//! - [spec]：用户可写的期望配置（意图文件 fleet.toml 也用它）；
//! - [view]：API 返回的视图；
//! - [plan]：plan / apply / 执行记录；
//! - [agent]：控制面和 agent 之间的 websocket 协议；
//! - [seal]：agent 通道的消息加密；
//! - [error]：统一错误格式 `{ code, message, hint, suggest }`。

pub mod agent;
pub mod build;
pub mod egress;
pub mod error;
pub mod plan;
pub mod seal;
pub mod spec;
pub mod tunnel;
pub mod view;

pub use error::{ApiError, ErrorCode};

/// CLI 和控制面在请求头里互相报告的版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// agent 和控制面之间的协议版本。版本不一致（含不发这个字段的旧 agent，当作 0）时控制面只接受升级请求。
/// 2：握手交换临时密钥，之后的消息全部加密（见 [seal]）。
pub const PROTOCOL: u32 = 2;

/// CLI 和控制面之间的接口版本，CLI 每个请求都带在 [CLI_API_HEADER] 里。
/// 新增字段都有默认值，旧 CLI 照常能用；只有控制面必须拿到旧 CLI 发不出的字段时，
/// 才把 [CLI_API] 和 [MIN_CLI_API] 一起加一，控制面会拦下旧 CLI 并提示更新。
/// 2：CLI 必须经加密通道（[tunnel]）访问控制面。
pub const CLI_API: u32 = 2;
pub const MIN_CLI_API: u32 = 2;
pub const CLI_API_HEADER: &str = "x-wharf-cli-api";
/// 控制面在每个响应里带上自己的构建号，CLI 比对后提醒更新。
pub const BUILD_HEADER: &str = "x-wharf-build";

/// 构建号：CI 构建镜像时传入的短提交号，本地构建是 `dev`。
/// 控制面拿它判断 agent 要不要升级，升级时拉 `sha-<构建号>` 标签的镜像。
pub const BUILD: &str = match option_env!("WHARF_BUILD") {
  Some(b) => b,
  None => "dev",
};

/// 名称规则：小写字母、数字、`-`，以字母或数字开头，最长 48 个字符。
/// 服务名同时是 compose project 名，所以规则比 compose 更严。
pub fn validate_name(kind: &str, name: &str) -> Result<(), ApiError> {
  let ok = !name.is_empty()
    && name.len() <= 48
    && name.bytes().all(|c| {
      c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
    })
    && !name.starts_with('-')
    && !name.ends_with('-');
  if ok {
    Ok(())
  } else {
    Err(
      ApiError::new(
        ErrorCode::InvalidInput,
        format!("{kind} 名称 '{name}' 不合法"),
      )
      .with_hint("只能用小写字母、数字和 -，不能以 - 开头或结尾，最长 48 个字符"),
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn names() {
    assert!(validate_name("服务", "whoami").is_ok());
    assert!(validate_name("服务", "a-1").is_ok());
    for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"a".repeat(49)] {
      assert!(validate_name("服务", bad).is_err(), "{bad}");
    }
  }
}
