//! 控制面、agent、CLI 共享的类型。
//!
//! - [spec]：用户可写的期望配置（意图文件 fleet.toml 也用它）；
//! - [view]：API 返回的视图；
//! - [plan]：plan / apply / 执行记录；
//! - [agent]：控制面和 agent 之间的 websocket 协议；
//! - [seal]：agent 通道的消息加密；
//! - [error]：统一错误格式 `{ code, message, hint, suggest }`。

pub mod access_logs;
pub mod agent;
pub mod backup;
pub mod build;
pub mod compose;
pub mod egress;
pub mod error;
pub mod external;
pub mod gateway_http;
pub mod net_probe;
pub mod plan;
pub mod report;
pub mod resources;
pub mod seal;
pub mod service_checks;
pub mod spec;
pub mod symlink;
pub mod token;
pub mod trusted_proxies;
pub mod tunnel;
pub mod view;
pub mod web_schema;

pub use error::{ApiError, ErrorCode};

pub const SEALED_NOTE_PREFIX: &str = "wharf-enc:v1:";

pub fn split_note(raw: &str) -> (String, Vec<&str>) {
  let (sealed, plain): (Vec<_>, Vec<_>) = raw
    .split('\n')
    .partition(|line| line.starts_with(SEALED_NOTE_PREFIX));
  (plain.join("\n").trim().to_string(), sealed)
}

pub fn normalize_host(raw: &str) -> String {
  raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 清理旧控制面返回的密文，或更新网页会话用的标记。
pub fn filter_note(
  note: &mut Option<String>,
  has_sealed_note: &mut bool,
  human: bool,
) {
  let Some(raw) = note else { return };
  let (plain, sealed) = split_note(raw);
  *has_sealed_note |= !sealed.is_empty();
  if !human {
    *note = (!plain.is_empty()).then_some(plain);
  }
}

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

pub fn mask_values(text: &str, values: &[String]) -> String {
  let mut values: Vec<_> =
    values.iter().filter(|s| !s.is_empty()).collect();
  values.sort_unstable_by(|a, b| {
    b.len().cmp(&a.len()).then_with(|| a.cmp(b))
  });
  values.dedup();
  values
    .into_iter()
    .fold(text.to_string(), |s, v| s.replace(v, "***"))
}

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

/// 校验传给 Compose 的服务名。
pub fn validate_container_name(name: &str) -> Result<(), ApiError> {
  let mut bytes = name.bytes();
  if name.len() <= 64
    && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
    && bytes.all(|b| {
      b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
    })
  {
    Ok(())
  } else {
    Err(ApiError::invalid(
      "子容器名须以字母或数字开头，最多 64 个字符，只能包含 ASCII 字母、数字、点、下划线或连字符",
    ))
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
