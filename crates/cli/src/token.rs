//! 访问令牌的管理命令。

use chrono::{DateTime, Local, NaiveDate, TimeDelta, TimeZone, Utc};
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  view::{
    CreatedToken, ExplainVerdict, Perm, TokenExplain, TokenSettings,
    TokenView,
  },
};

use crate::{
  TokenCmd,
  client::{CliResult, Client, seg},
  commands::out,
};

fn parse_non_empty_csv(
  flag: &str,
  raw: &str,
  clear_keyword: Option<&str>,
) -> Result<Vec<String>, ApiError> {
  let trimmed = raw.trim();
  if clear_keyword == Some(trimmed) {
    return Ok(vec![]);
  }
  let values: Vec<_> = trimmed.split(',').map(str::trim).collect();
  if values.iter().any(|value| value.is_empty()) {
    return Err(
      ApiError::invalid(format!("{flag} 不能为空或包含空项"))
        .with_hint(match clear_keyword {
          Some(kw) => format!(
            "填入逗号分隔的值；要清除限制请显式传 {flag} {kw}"
          ),
          None if flag == "--perms" => {
            "可选权限点：read、plan、apply、confirm、exec、admin"
              .into()
          }
          None => {
            format!("填入逗号分隔的值；如果不限制请不要传 {flag}")
          }
        }),
    );
  }
  Ok(values.into_iter().map(str::to_string).collect())
}

fn expiry(
  value: &str,
  allow_never: bool,
) -> Result<Option<DateTime<Utc>>, ApiError> {
  let value = value.trim();
  if allow_never && value == "never" {
    return Ok(None);
  }
  let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
    .ok()
    .and_then(|date| date.and_hms_opt(23, 59, 59))
    .and_then(|date| Local.from_local_datetime(&date).latest())
    .map(|date| date.to_utc());
  let relative = || {
    let delta = match value.as_bytes().last()? {
      b'm' | b'h' => {
        TimeDelta::from_std(crate::wait::parse_timeout(value).ok()?)
          .ok()?
      }
      b'd' => {
        TimeDelta::try_days(value.strip_suffix('d')?.parse().ok()?)?
      }
      _ => return None,
    };
    Utc::now().checked_add_signed(delta)
  };
  let time = date.or_else(relative).ok_or_else(|| {
    ApiError::invalid(format!("有效期 {value} 格式不对")).with_hint(
      if allow_never {
        "例如 30m、12h、7d、2026-12-31 或 never"
      } else {
        "例如 30m、12h、7d 或 2026-12-31"
      },
    )
  })?;
  if time.timestamp_millis() <= Utc::now().timestamp_millis() {
    return Err(ApiError::invalid("有效期必须晚于现在"));
  }
  Ok(Some(time))
}

fn expiry_label(left: TimeDelta) -> String {
  if left <= TimeDelta::zero() {
    "已过期".into()
  } else if left.num_days() > 0 {
    format!("剩 {} 天", left.num_days())
  } else if left.num_hours() > 0 {
    format!("剩 {} 小时", left.num_hours())
  } else {
    format!("剩 {} 分钟", left.num_minutes().max(1))
  }
}

pub async fn run(
  cmd: TokenCmd,
  url: Option<String>,
  token: Option<String>,
  j: bool,
) -> CliResult<()> {
  if matches!(
    &cmd,
    TokenCmd::Set {
      perms: None,
      expires: None,
      from: None,
      services: None,
      ..
    }
  ) {
    return Err(ApiError::invalid("没有要改的").into());
  }
  if let TokenCmd::Explain {
    path: Some(path), ..
  } = &cmd
    && !path.starts_with("/api/")
  {
    return Err(ApiError::invalid("--path 必须以 /api/ 开头").into());
  }
  let c = Client::new(url, token)?;
  match cmd {
    TokenCmd::Explain {
      name,
      service,
      from,
      method,
      path,
    } => {
      let query = [
        ("service", service),
        ("from", from),
        ("method", method),
        ("path", path),
      ]
      .into_iter()
      .filter_map(|(key, value)| {
        value.map(|value| format!("{key}={}", seg(&value)))
      })
      .collect::<Vec<_>>()
      .join("&");
      let mut endpoint =
        format!("/api/tokens/{}/explain", seg(&name));
      if !query.is_empty() {
        endpoint.push('?');
        endpoint.push_str(&query);
      }
      let response: TokenExplain = c.get(&endpoint).await?;
      out(j, &response, print_explanation);
    }
    TokenCmd::List => {
      let tokens: Vec<TokenView> = c.get("/api/tokens").await?;
      out(j, &tokens, |tokens| {
        println!("{:<14} {:<22} 限制", "名称", "权限");
        for token in tokens {
          let perms = token
            .perms
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>();
          let mut limits = vec![];
          if let Some(expires) = token.expires_at {
            limits.push(expiry_label(expires - Utc::now()));
          }
          if !token.allowed_from.is_empty() {
            limits.push(format!(
              "来源 {}",
              token.allowed_from.join(", ")
            ));
          }
          if !token.services.is_empty() {
            limits
              .push(format!("服务 {}", token.services.join(", ")));
          }
          println!(
            "{:<14} {:<22} {}",
            token.name,
            perms.join(","),
            if limits.is_empty() {
              "-".into()
            } else {
              limits.join(" · ")
            }
          );
        }
      });
    }
    TokenCmd::Create {
      name,
      perms,
      scope,
      expires,
      from,
      services,
    } => {
      let mut body = json!({
        "name": name,
        "expires_at": expires.as_deref().map(|v| expiry(v, false)).transpose()?.flatten(),
        "allowed_from": from.as_deref().map(|v| parse_non_empty_csv("--from", v, None)).transpose()?.unwrap_or_default(),
        "services": services.as_deref().map(|v| parse_non_empty_csv("--services", v, None)).transpose()?.unwrap_or_default(),
      });
      if let Some(perms) = perms {
        body["perms"] =
          json!(parse_non_empty_csv("--perms", &perms, None)?);
      } else {
        body["scope"] = json!(scope);
      }
      let created: CreatedToken =
        c.post("/api/tokens", &body).await?;
      out(j, &created, |v| {
        let perms =
          v.perms.iter().map(|p| p.as_str()).collect::<Vec<_>>();
        println!(
          "已创建 token {}（{}），只显示这一次：\n{}",
          v.name,
          perms.join(","),
          v.token
        );
      });
    }
    TokenCmd::Set {
      name,
      perms,
      expires,
      from,
      services,
      dry_run,
    } => {
      let from = from
        .as_deref()
        .map(|raw| parse_non_empty_csv("--from", raw, Some("any")))
        .transpose()?;
      let services = services
        .as_deref()
        .map(|raw| {
          parse_non_empty_csv("--services", raw, Some("all"))
        })
        .transpose()?;
      let perms = perms
        .as_deref()
        .map(|raw| parse_non_empty_csv("--perms", raw, None))
        .transpose()?;
      let tokens: Vec<TokenView> = c.get("/api/tokens").await?;
      let token = tokens
        .into_iter()
        .find(|token| token.name == name)
        .ok_or_else(|| {
          ApiError::not_found(format!("访问令牌 {name} 不存在"))
            .with_hint("执行 wharf token list")
        })?;
      let before = TokenSettings {
        perms: token.perms,
        expires_at: token.expires_at,
        allowed_from: token.allowed_from,
        services: token.services,
      };
      let mut after = before.clone();
      if let Some(perms) = perms {
        after.perms = perms
          .into_iter()
          .map(|p| {
            Perm::parse(&p).ok_or_else(|| {
              ApiError::invalid(format!("未知权限 {p}")).with_hint(
                "权限点：read、plan、apply、confirm、exec、admin",
              )
            })
          })
          .collect::<Result<_, _>>()?;
      }
      if let Some(expires) = expires {
        after.expires_at = expiry(&expires, true)?;
      }
      if let Some(from) = from {
        after.allowed_from = from;
      }
      if let Some(services) = services {
        after.services = services;
      }
      after.normalize()?;
      if dry_run {
        return crate::preview::show(
          j,
          &format!("token/{name}"),
          &json!(before),
          &json!(after),
        );
      }
      let value: Value = c
        .put(&format!("/api/tokens/{}", seg(&name)), &after)
        .await?;
      out(j, &value, |_| println!("已修改访问令牌 {name}"));
    }
    TokenCmd::Rm { name } => {
      let value: Value =
        c.delete(&format!("/api/tokens/{}", seg(&name))).await?;
      out(j, &value, |_| println!("已删除 token {name}"));
    }
  }
  Ok(())
}

fn print_explanation(result: &TokenExplain) {
  print!("令牌 {}", result.token);
  if let Some(service) = &result.service {
    print!(" · 服务 {service}");
  }
  if let Some(from) = &result.from {
    print!(" · 来源 {from}");
  }
  println!();
  let width = |s: &str| {
    s.chars()
      .map(|c| if c.is_ascii() { 1 } else { 2 })
      .sum::<usize>()
  };
  let request_width = result
    .items
    .iter()
    .map(|item| item.method.len() + 1 + width(&item.path))
    .max()
    .unwrap_or(0)
    .max(width("请求"));
  println!(
    "结果    操作                请求{:>pad$}  原因",
    "",
    pad = request_width - width("请求"),
  );
  for item in &result.items {
    let verdict = match item.verdict {
      ExplainVerdict::Allow => "放行",
      ExplainVerdict::Deny => "拦截",
      ExplainVerdict::Depends => "看情况",
    };
    let request = format!("{} {}", item.method, item.path);
    println!(
      "{verdict}{:>verdict_pad$}{op}{:>op_pad$}{request}{:>request_pad$}  {reason}",
      "",
      "",
      "",
      verdict_pad = 8 - width(verdict),
      op = item.op,
      op_pad = 20_usize.saturating_sub(width(&item.op)),
      request_pad = request_width - width(&request),
      reason = item.reason.as_deref().unwrap_or(""),
    );
  }
}

#[cfg(test)]
mod tests {
  use super::{TimeDelta, expiry_label};

  #[test]
  fn formats_time_left() {
    assert_eq!(expiry_label(TimeDelta::minutes(30)), "剩 30 分钟");
    assert_eq!(expiry_label(TimeDelta::hours(3)), "剩 3 小时");
    assert_eq!(expiry_label(TimeDelta::days(2)), "剩 2 天");
    assert_eq!(expiry_label(TimeDelta::seconds(-1)), "已过期");
  }
}

#[cfg(test)]
#[test]
fn cli_token_rejects_empty_services_from_and_perms() {
  for (flag, raw, clear) in [
    ("--services", "", None),
    ("--services", ",", Some("all")),
    ("--from", "  ", Some("any")),
    ("--perms", "", None),
  ] {
    assert_eq!(
      parse_non_empty_csv(flag, raw, clear).unwrap_err().code,
      wharf_api_types::ErrorCode::InvalidInput
    );
  }
  assert!(
    parse_non_empty_csv("--services", "all", Some("all"))
      .unwrap()
      .is_empty()
  );
}
