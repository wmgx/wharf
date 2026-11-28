//! CLI 可调整的控制面设置白名单。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, State},
};
use chrono::FixedOffset;
use rusqlite::Connection;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  view::{ConfigItemView, Perm},
};

use crate::{api::ApiResult, auth::Auth, db, state::AppState};

#[derive(Clone, Copy)]
enum Kind {
  Bool,
  Number(u16, u16, u16),
  Timezone,
  Url,
  Email,
  Server,
  Readonly,
}

struct Item(&'static str, Kind, &'static str);

static CONFIG_ITEMS: &[Item] = &[
  Item(
    "egress.api_via",
    Kind::Server,
    "控制面 API 使用的出口服务器",
  ),
  Item("oidc.email", Kind::Email, "OIDC 默认邮箱"),
  Item("alerts.include_logs", Kind::Bool, "告警附带日志"),
  Item(
    "alerts.digest_hour",
    Kind::Number(0, 23, 9),
    "每日告警汇总时刻",
  ),
  Item(
    "core.timezone",
    Kind::Timezone,
    "调度及日期解析使用的固定时区",
  ),
  Item("core.heartbeat_url", Kind::Url, "服务心跳报到基地址"),
  Item(
    "retention.audit_days",
    Kind::Number(7, 365, 90),
    "审计保留天数",
  ),
  Item(
    "retention.metrics_days",
    Kind::Number(7, 90, 14),
    "指标保留天数",
  ),
  Item(
    "retention.events_days",
    Kind::Number(14, 365, 90),
    "事件保留天数",
  ),
  Item(
    "retention.secret_keep_days",
    Kind::Number(0, 30, db::DEFAULT_SECRET_KEEP_DAYS),
    "轮换后的旧密钥保留天数",
  ),
  Item("core_backup.to", Kind::Readonly, "控制面备份服务器"),
];

fn item(key: &str) -> Result<&'static Item, ApiError> {
  CONFIG_ITEMS
    .iter()
    .find(|item| item.0 == key)
    .ok_or_else(|| {
      ApiError::not_found(format!("未知配置项 {key}"))
        .with_hint("运行 wharf config list 查看全部支持的配置项")
    })
}

fn view(
  c: &Connection,
  Item(key, kind, description): &Item,
) -> Result<ConfigItemView, ApiError> {
  let saved = db::setting(c, key)?;
  let (default_value, value_type) = match kind {
    Kind::Bool => (json!(false), "bool"),
    Kind::Number(_, _, default) => (json!(default), "integer"),
    Kind::Timezone => (json!("Asia/Shanghai"), "timezone"),
    Kind::Url => (Value::Null, "url"),
    Kind::Email => (Value::Null, "email"),
    Kind::Server | Kind::Readonly => (Value::Null, "server"),
  };
  let value = match (kind, saved.as_deref()) {
    (Kind::Bool, Some(value)) => json!(value == "1"),
    (Kind::Number(..), Some(value)) => value
      .parse::<u16>()
      .map_or_else(|_| default_value.clone(), |v| json!(v)),
    (_, Some(value)) => json!(value),
    (_, None) => default_value.clone(),
  };
  Ok(ConfigItemView {
    key: key.to_string(),
    value,
    default_value,
    value_type: value_type.into(),
    customized: saved.is_some(),
    readonly: matches!(kind, Kind::Readonly),
    description: description.to_string(),
  })
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<ConfigItemView>> {
  auth.require(Perm::Read)?;
  Ok(Json(
    s.db
      .call(|c| CONFIG_ITEMS.iter().map(|v| view(c, v)).collect())
      .await?,
  ))
}

pub async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(key): Path<String>,
) -> ApiResult<ConfigItemView> {
  auth.require(Perm::Read)?;
  let config = item(&key)?;
  Ok(Json(s.db.call(move |c| view(c, config)).await?))
}

pub async fn set(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(key): Path<String>,
  Json(value): Json<Value>,
) -> ApiResult<ConfigItemView> {
  auth.require(Perm::Admin)?;
  let config = item(&key)?;
  writable(config)?;
  let invalid = || ApiError::invalid(format!("{key} 的值格式不对"));
  let saved = match config.1 {
    Kind::Bool => match value
      .as_bool()
      .or_else(|| value.as_str()?.parse().ok())
    {
      Some(true) => Some("1".into()),
      Some(false) => None,
      None => {
        return Err(invalid().with_hint("使用 true 或 false").into());
      }
    },
    Kind::Number(min, max, _) => {
      let n = value
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| {
          ApiError::invalid(format!(
            "{key} 必须在 {min} 到 {max} 之间"
          ))
        })?;
      Some(n.to_string())
    }
    _ => {
      let text = value.as_str().ok_or_else(invalid)?.trim();
      match config.1 {
        Kind::Timezone => {
          parse_offset(text)?;
        }
        Kind::Url
          if !crate::caddy_validate::valid_public_url(text) =>
        {
          return Err(
            invalid()
              .with_hint("使用 http:// 或 https:// 开头的报到基地址")
              .into(),
          );
        }
        Kind::Email if !crate::oidc::email_ok(text) => {
          return Err(
            invalid().with_hint("例如 ops@example.test").into(),
          );
        }
        Kind::Server => {
          let snap = crate::snapshot::load_inner(&s.db).await?;
          crate::egress::route(text, &snap)?;
        }
        _ => {}
      }
      Some(text.to_string())
    }
  };
  save(&s, config, saved).await
}

pub async fn unset(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(key): Path<String>,
) -> ApiResult<ConfigItemView> {
  auth.require(Perm::Admin)?;
  let config = item(&key)?;
  writable(config)?;
  save(&s, config, None).await
}

fn writable(config: &Item) -> Result<(), ApiError> {
  if matches!(config.1, Kind::Readonly) {
    return Err(
      ApiError::invalid(
        "core_backup.to 不能直接通过 config set 修改",
      )
      .with_hint("请使用 wharf backup core --to <服务器>"),
    );
  }
  Ok(())
}

async fn save(
  s: &AppState,
  config: &'static Item,
  value: Option<String>,
) -> ApiResult<ConfigItemView> {
  let result = s
    .db
    .call(move |c| {
      db::set_setting(c, config.0, value.as_deref())?;
      view(c, config)
    })
    .await?;
  if config.0 == crate::egress::API_VIA {
    crate::snapshot::load(&s.db).await?;
  }
  Ok(Json(result))
}

fn parse_offset(value: &str) -> Result<FixedOffset, ApiError> {
  let hours = match value {
    "UTC" | "Europe/London" => 0,
    "Asia/Shanghai" | "Asia/Hong_Kong" | "Asia/Singapore"
    | "Asia/Taipei" => 8,
    "Asia/Tokyo" | "Asia/Seoul" => 9,
    "America/New_York" => -5,
    "America/Los_Angeles" => -8,
    _ => {
      let bytes = value.as_bytes();
      if let [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] = bytes
        && [h1, h2, m1, m2].iter().all(|b| b.is_ascii_digit())
      {
        let number = |a: u8, b: u8| {
          i32::from(a - b'0') * 10 + i32::from(b - b'0')
        };
        let minutes = number(*m1, *m2);
        let seconds = (number(*h1, *h2) * 60 + minutes) * 60;
        let seconds = if *sign == b'-' { -seconds } else { seconds };
        if minutes < 60 && (-12 * 3600..=14 * 3600).contains(&seconds)
        {
          return Ok(FixedOffset::east_opt(seconds).unwrap());
        }
      }
      return Err(
        ApiError::invalid("core.timezone 格式不对")
          .with_hint("例如 Asia/Shanghai、UTC 或 +08:00"),
      );
    }
  };
  Ok(FixedOffset::east_opt(hours * 3600).unwrap())
}

pub(crate) fn offset(
  c: &Connection,
) -> Result<FixedOffset, ApiError> {
  parse_offset(
    db::setting(c, "core.timezone")?
      .as_deref()
      .unwrap_or("Asia/Shanghai"),
  )
}

pub(crate) fn number(
  c: &Connection,
  key: &str,
) -> Result<u16, ApiError> {
  let Kind::Number(min, max, default) = item(key)?.1 else {
    return Err(ApiError::internal("不是数值配置项"));
  };
  Ok(
    db::setting(c, key)?
      .and_then(|v| v.parse().ok())
      .filter(|n| (min..=max).contains(n))
      .unwrap_or(default),
  )
}

#[tokio::test]
async fn configured_audit_retention_and_allowlist() {
  let db = db::Db::memory();
  db.call(|c| {
    let entry = item("retention.audit_days")?;
    db::set_setting(c, entry.0, Some("30"))?;
    assert_eq!(view(c, entry)?.value, json!(30));
    let now = db::now_ms();
    let old = now - 40 * 86_400_000;
    let insert = || c.execute(
      "INSERT INTO audit_log (at, kind, actor, method, path) VALUES (?1, 'api', 'fixture', 'GET', '/api/config')", [old],
    ).map_err(db::sql_err);
    let count = || c.query_row("SELECT count(*) FROM audit_log", [], |r| r.get::<_, i64>(0)).map_err(db::sql_err);
    insert()?;
    crate::audit::cleanup_rows(c, now)?;
    assert_eq!(count()?, 0);
    db::set_setting(c, entry.0, None)?;
    insert()?;
    crate::audit::cleanup_rows(c, now)?;
    assert_eq!(count()?, 1);
    assert!(matches!(item("gate.rt_key"), Err(e) if e.code == wharf_api_types::ErrorCode::NotFound));
    assert!(writable(item("core_backup.to")?).is_err());
    Ok(())
  }).await.unwrap();
}
