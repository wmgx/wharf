use super::*;

pub fn provider_error(e: ProviderError) -> ApiError {
  e.log("dns");
  let hint = match e.code {
    code::AUTH_FAILED => Some(
      "检查 Cloudflare token 权限：Zone → DNS → Edit，Zone → Zone → Read；Workers / Pages 还要 Account → Workers Scripts → Edit、Account → Cloudflare Pages → Edit、Zone → Workers Routes → Edit",
    ),
    code::PROVIDER_REJECTED => Some(
      "检查 token 是否完整复制、是否已过期或被删除；DNS 记录冲突时到 Cloudflare 面板确认",
    ),
    code::ZONE_NOT_FOUND => {
      Some("执行 wharf account discover <account> 重新发现 zone")
    }
    code::RATE_LIMITED
    | code::PROVIDER_UNAVAILABLE
    | code::TIMEOUT => Some("稍后重试"),
    _ => None,
  };
  let mut err = ApiError::new(
    ErrorCode::Provider,
    format!("{}（{}）", e.message, e.code),
  );
  if let Some(hint) = hint {
    err = err.with_hint(hint);
  }
  crate::external_status::failure(err, "Cloudflare")
}

pub fn dns_provider(
  account: &AccountRow,
) -> Result<Box<dyn DnsProvider>, ApiError> {
  let factory =
    wharf_providers::factory(&account.kind).ok_or_else(|| {
      ApiError::internal(format!("不支持的厂商类型 {}", account.kind))
    })?;
  (factory.build)(Credentials {
    name: account.name.clone(),
    token: account.token.clone(),
    zones: account.zones.clone(),
  })
  .map_err(provider_error)?
  .dns
  .ok_or_else(|| {
    ApiError::internal(format!("账号 {} 不支持 DNS", account.name))
  })
}

pub fn tunnel_provider(
  account: &AccountRow,
) -> Result<Box<dyn wharf_providers::TunnelProvider>, ApiError> {
  let factory =
    wharf_providers::factory(&account.kind).ok_or_else(|| {
      ApiError::internal(format!("不支持的厂商类型 {}", account.kind))
    })?;
  (factory.build)(Credentials {
    name: account.name.clone(),
    token: account.token.clone(),
    zones: account.zones.clone(),
  })
  .map_err(provider_error)?
  .tunnel
  .ok_or_else(|| {
    ApiError::invalid(format!("账号 {} 不支持隧道", account.name))
  })
}

pub fn edge_provider(
  account: &AccountRow,
) -> Result<Box<dyn wharf_providers::EdgeProvider>, ApiError> {
  let factory =
    wharf_providers::factory(&account.kind).ok_or_else(|| {
      ApiError::internal(format!("不支持的厂商类型 {}", account.kind))
    })?;
  (factory.build)(Credentials {
    name: account.name.clone(),
    token: account.token.clone(),
    zones: account.zones.clone(),
  })
  .map_err(provider_error)?
  .edge
  .ok_or_else(|| {
    ApiError::invalid(format!(
      "账号 {} 不支持 Workers / Pages",
      account.name
    ))
  })
}

/// 厂商调用的总超时（客户端自己也有单次请求超时）。
pub async fn with_timeout<T>(
  what: &str,
  fut: impl std::future::Future<Output = Result<T, ProviderError>>,
) -> Result<T, ApiError> {
  match tokio::time::timeout(Duration::from_secs(90), fut).await {
    Ok(result) => result.map_err(provider_error),
    Err(_) => Err(crate::external_status::failure(
      ApiError::new(
        ErrorCode::Timeout,
        format!("{what} 超过 90 秒没有完成"),
      ),
      "Cloudflare",
    )),
  }
}
