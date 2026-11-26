//! 访问令牌的管理命令。

use chrono::{DateTime, Local, NaiveDate, TimeDelta, TimeZone, Utc};
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  view::{CreatedToken, Perm, TokenSettings, TokenView},
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
  if clear_keyword.is_some_and(|kw| trimmed == kw) {
    return Ok(vec![]);
  }
  let mut items = Vec::new();
  for part in raw.split(',') {
    let item = part.trim();
    if item.is_empty() {
      let hint = if flag == "--perms" {
        "可选权限点：read、plan、apply、confirm、exec、admin".into()
      } else {
        match clear_keyword {
          Some(kw) => {
            format!(
              "填入逗号分隔的值；要清除限制请显式传 {flag} {kw}"
            )
          }
          None => {
            format!("填入逗号分隔的值；如果不限制请不要传 {flag}")
          }
        }
      };
      return Err(
        ApiError::invalid(format!("{flag} 不能为空或包含空项"))
          .with_hint(hint),
      );
    }
    items.push(item.to_string());
  }
  Ok(items)
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
  let c = Client::new(url, token)?;
  match cmd {
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
      let allowed_from = from
        .as_deref()
        .map(|v| parse_non_empty_csv("--from", v, None))
        .transpose()?
        .unwrap_or_default();
      let services = services
        .as_deref()
        .map(|v| parse_non_empty_csv("--services", v, None))
        .transpose()?
        .unwrap_or_default();
      let mut body = json!({
        "name": name,
        "expires_at": expires.as_deref().map(|v| expiry(v, false)).transpose()?.flatten(),
        "allowed_from": allowed_from,
        "services": services,
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
        after.perms = parse_non_empty_csv("--perms", &perms, None)?
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
        after.allowed_from =
          parse_non_empty_csv("--from", &from, Some("any"))?;
      }
      if let Some(services) = services {
        after.services =
          parse_non_empty_csv("--services", &services, Some("all"))?;
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

#[cfg(test)]
mod tests {
  use super::{TimeDelta, expiry_label, parse_non_empty_csv};
  use wharf_api_types::ErrorCode;

  #[test]
  fn formats_time_left() {
    assert_eq!(expiry_label(TimeDelta::minutes(30)), "剩 30 分钟");
    assert_eq!(expiry_label(TimeDelta::hours(3)), "剩 3 小时");
    assert_eq!(expiry_label(TimeDelta::days(2)), "剩 2 天");
    assert_eq!(expiry_label(TimeDelta::seconds(-1)), "已过期");
  }

  #[test]
  fn cli_token_rejects_empty_services_from_and_perms() {
    for (flag, raw, clear) in [
      ("--services", "", None),
      ("--services", ",", Some("all")),
      ("--from", "  ", Some("any")),
      ("--perms", "", None),
    ] {
      let err = parse_non_empty_csv(flag, raw, clear).unwrap_err();
      assert_eq!(err.code, ErrorCode::InvalidInput, "{flag}={raw:?}");
    }
    assert_eq!(
      parse_non_empty_csv("--services", "all", Some("all")).unwrap(),
      Vec::<String>::new()
    );
  }
}
