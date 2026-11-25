//! 组网策略、密钥到期和厂商凭据检查。只读厂商 API。
use std::{
  collections::BTreeMap,
  sync::{Arc, RwLock},
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError,
  external::{AclView, TailnetKey},
  view::{CheckStatus, DoctorCheck, Perm},
};
use wharf_providers::{
  http::Http,
  tailscale::{self, ReadError},
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::AccountRow,
  rules,
  snapshot::{self, Snapshot},
  state::AppState,
};

const POLICY_SCOPE: &str = "在 Tailscale 后台给这个 OAuth 客户端加 policy_file:read、devices:posture_attributes:read 和 devices:core:read；加完后不用重启 Wharf，可运行 wharf network acl --refresh。";
const OAUTH_SETUP: &str = "在 Tailscale 后台创建 OAuth 客户端，再运行 wharf secret set TAILSCALE_OAUTH，按 client_id:client_secret 输入。";
const DEVICE_SCOPE: &str =
  "在 Tailscale 后台给这个 OAuth 客户端加 devices:core:read。";
const CF_PERMISSIONS: &str = "在 Cloudflare 后台检查 Token 有效期和 Zone → Zone → Read、Zone → DNS → Edit，更新 Wharf 的厂商账号凭据。";
const CF_API: &str = "https://api.cloudflare.com/client/v4";
const ACL_TTL: Duration = Duration::from_secs(600);
type CachedAcl = ([u8; 32], Instant, AclView);
static ACL: tokio::sync::Mutex<Option<CachedAcl>> =
  tokio::sync::Mutex::const_new(None);
static KEYS: RwLock<BTreeMap<String, (String, TailnetKey)>> =
  RwLock::new(BTreeMap::new());

fn credential(snap: &Snapshot) -> Option<&str> {
  snap
    .secrets
    .get(crate::tailscale::OAUTH_SECRET)
    .map(String::as_str)
    .filter(|v| !v.is_empty())
}

fn acl_status(status: &str, hint: Option<&str>) -> AclView {
  AclView {
    status: status.into(),
    hint: hint.map(str::to_string),
    raw: None,
    groups: BTreeMap::new(),
    tag_owners: BTreeMap::new(),
    acls: 0,
    grants: 0,
    modified_at: None,
  }
}

fn policy_error(error: ReadError) -> AclView {
  if error.missing_scope() {
    acl_status(
      "OAuth 客户端缺少读取策略文件的权限",
      Some(POLICY_SCOPE),
    )
  } else {
    acl_status(&error.message(), None)
  }
}

fn devices_check(
  name: &str,
  result: Result<Value, ReadError>,
) -> DoctorCheck {
  match result {
    Ok(_) => item("设备", name, CheckStatus::Ok, "能列设备"),
    Err(e) if e.missing_scope() => item(
      "设备",
      name,
      CheckStatus::Bad,
      format!("OAuth 客户端缺少读取设备的权限。{DEVICE_SCOPE}"),
    ),
    Err(e) => item(
      "设备",
      name,
      if e.denied() {
        CheckStatus::Bad
      } else {
        CheckStatus::Warn
      },
      e.message(),
    ),
  }
}

fn policy_check(
  name: &str,
  result: Result<(String, Option<String>), ReadError>,
) -> DoctorCheck {
  match result {
    Ok(_) => item("策略", name, CheckStatus::Ok, "能读策略文件"),
    Err(e) => {
      let v = policy_error(e);
      let status = if v.hint.is_some() {
        CheckStatus::Skip
      } else {
        CheckStatus::Warn
      };
      let detail = match v.hint {
        Some(hint) => format!("{}。{hint}", v.status),
        None => v.status,
      };
      item("策略", name, status, detail)
    }
  }
}

// HuJSON 只增加注释和尾逗号。保留字符串中的斜线、逗号和转义。
fn parse_policy(raw: &str) -> serde_json::Result<Value> {
  let mut clean = Vec::with_capacity(raw.len());
  let mut input = raw.bytes().peekable();
  while let Some(c) = input.next() {
    match (c, input.peek().copied()) {
      (b'"', _) => {
        clean.push(c);
        while let Some(c) = input.next() {
          clean.push(c);
          if c == b'"' {
            break;
          }
          if c == b'\\' {
            clean.extend(input.next());
          }
        }
      }
      (b'/', Some(b'/')) => {
        for c in input.by_ref() {
          if c == b'\n' {
            break;
          }
        }
        clean.push(b' ');
      }
      (b'/', Some(b'*')) => {
        input.next();
        while let Some(c) = input.next() {
          if c == b'*' && input.peek() == Some(&b'/') {
            input.next();
            break;
          }
        }
        clean.push(b' ');
      }
      (b'}' | b']', _) => {
        if let Some(i) =
          clean.iter().rposition(|c| !c.is_ascii_whitespace())
          && clean[i] == b','
        {
          clean.truncate(i);
        }
        clean.push(c);
      }
      _ => clean.push(c),
    }
  }
  serde_json::from_slice(&clean)
}

async fn read_acl(token: &str) -> AclView {
  let (raw, modified_at) = match tailscale::policy(token).await {
    Ok(data) => data,
    Err(e) => return policy_error(e),
  };
  let Some(policy) = parse_policy(&raw).ok().filter(Value::is_object)
  else {
    return AclView {
      raw: Some(raw),
      modified_at,
      ..acl_status("策略文件无法解析", None)
    };
  };
  let entries =
    |key: &str| policy[key].as_array().map_or(0, Vec::len);
  let groups = |key: &str| {
    serde_json::from_value(policy[key].clone()).unwrap_or_default()
  };
  AclView {
    raw: Some(raw),
    groups: groups("groups"),
    tag_owners: groups("tagOwners"),
    acls: entries("acls"),
    grants: entries("grants"),
    modified_at,
    ..acl_status("正常", None)
  }
}

#[derive(Deserialize)]
pub struct AclQuery {
  #[serde(default)]
  refresh: bool,
}

pub async fn acl(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<AclQuery>,
) -> ApiResult<AclView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let Some(secret) = credential(&snap) else {
    return Ok(Json(acl_status(
      "没配 Tailscale OAuth 客户端",
      Some(OAUTH_SETUP),
    )));
  };
  let hash = Sha256::digest(secret.as_bytes()).into();
  let mut cache = ACL.lock().await;
  if !q.refresh
    && let Some((prev, at, value)) = cache.as_ref()
    && *prev == hash
    && at.elapsed() < ACL_TTL
  {
    return Ok(Json(value.clone()));
  }
  let value = match tailscale::access_token(secret).await {
    Ok(token) => read_acl(&token).await,
    Err(e) => acl_status(&e.message(), Some(OAUTH_SETUP)),
  };
  *cache = Some((hash, Instant::now(), value.clone()));
  Ok(Json(value))
}

pub fn key(name: &str, ip: Option<&str>) -> Option<TailnetKey> {
  let keys = KEYS.read().ok()?;
  let (recorded_ip, key) = keys.get(name)?;
  (ip.unwrap_or_default() == recorded_ip).then(|| key.clone())
}

fn days_left(key: &TailnetKey, now: DateTime<Utc>) -> Option<f64> {
  if key.never_expires {
    return Some(f64::MAX);
  }
  Some((key.expires? - now).num_seconds() as f64 / 86_400.0)
}

async fn record_keys(s: &AppState, snap: &Snapshot, devices: &Value) {
  let Some(devices) = devices["devices"].as_array() else {
    return;
  };
  let mut keys = BTreeMap::new();
  for name in snap.world.servers.keys() {
    let ip =
      crate::tailnet_probe::address(snap, name).unwrap_or_default();
    let hostname = snap
      .agent(name)
      .and_then(|a| a.report.as_ref())
      .map(|r| r.hostname.as_str());
    let candidates = devices
      .iter()
      .filter(|d| {
        !ip.is_empty()
          && d["addresses"].as_array().is_some_and(|addrs| {
            addrs.iter().any(|a| a.as_str() == Some(ip))
          })
      })
      .collect::<Vec<_>>();
    let device = match candidates.as_slice() {
      [d] => Some(*d),
      [] => {
        let mut matches = devices.iter().filter(|d| {
          d["hostname"].as_str().is_some_and(|host| {
            host == name || hostname == Some(host)
          })
        });
        let first = matches.next();
        first.filter(|_| matches.next().is_none())
      }
      _ => None,
    };
    if let Some(device) = device {
      let key = TailnetKey {
        expires: device["expires"]
          .as_str()
          .and_then(|v| v.parse().ok()),
        never_expires: device["keyExpiryDisabled"].as_bool()
          == Some(true),
      };
      let Some(days) = days_left(&key, Utc::now()) else {
        continue;
      };
      let detail = if key.never_expires {
        "组网密钥不过期".to_string()
      } else {
        format!(
          "{} UTC 到期，剩余 {:.1} 天。在 Tailscale 后台对这台机器续期或关闭到期",
          key.expires.unwrap_or_default().format("%Y-%m-%d %H:%M"),
          days.max(0.0)
        )
      };
      rules::observe(s, "tailnet.key_days", name, days, &detail)
        .await;
      keys.insert(name.clone(), (ip.to_string(), key));
    }
  }
  if let Ok(mut cache) = KEYS.write() {
    *cache = keys;
  }
}

pub async fn refresh_keys(s: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&s.db).await?;
  if let Some(secret) = credential(&snap)
    && let Ok(token) = tailscale::access_token(secret).await
    && let Ok(devices) = tailscale::devices(&token).await
  {
    record_keys(s, &snap, &devices).await;
  } else if credential(&snap).is_none()
    && let Ok(mut cache) = KEYS.write()
  {
    cache.clear();
  }
  Ok(())
}

fn item(
  layer: &str,
  subject: &str,
  status: CheckStatus,
  detail: impl Into<String>,
) -> DoctorCheck {
  DoctorCheck {
    layer: layer.into(),
    subject: subject.into(),
    status,
    detail: detail.into(),
    at: Utc::now(),
  }
}

async fn cf_get(
  http: &Http,
  token: &str,
  path: &str,
  query: &[(&str, &str)],
) -> Result<Value, CheckStatus> {
  let response = http
    .send(|c| {
      c.get(format!("{CF_API}{path}"))
        .bearer_auth(token)
        .query(query)
    })
    .await
    .map_err(|_| CheckStatus::Warn)?;
  if matches!(response.status().as_u16(), 400 | 401 | 403 | 404) {
    return Err(CheckStatus::Bad);
  }
  let value: Value = response
    .error_for_status()
    .map_err(|_| CheckStatus::Warn)?
    .json()
    .await
    .map_err(|_| CheckStatus::Warn)?;
  if value["success"] != true {
    return Err(CheckStatus::Warn);
  }
  Ok(value["result"].clone())
}

fn valid_id(id: &str) -> bool {
  id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

async fn cloudflare(account: &AccountRow) -> Vec<DoctorCheck> {
  let name = &format!("Cloudflare {}", account.name);
  let Ok(http) = Http::new(Duration::from_secs(10)) else {
    return vec![item(
      "令牌",
      name,
      CheckStatus::Warn,
      "Cloudflare API 查不到",
    )];
  };
  let mut zones = vec![];
  for zone in &account.zones {
    let result =
      cf_get(&http, &account.token, "/zones", &[("name", zone)])
        .await;
    zones.push((
      zone,
      result.and_then(|v| {
        v.as_array()
          .ok_or(CheckStatus::Warn)?
          .iter()
          .find(|z| z["name"].as_str() == Some(zone))
          .cloned()
          .ok_or(CheckStatus::Bad)
      }),
    ));
  }
  let mut token =
    cf_get(&http, &account.token, "/user/tokens/verify", &[]).await;
  if token == Err(CheckStatus::Bad) {
    let mut ids: std::collections::BTreeSet<_> = zones
      .iter()
      .filter_map(|(_, z)| {
        z.as_ref().ok()?.get("account")?["id"].as_str()
      })
      .filter(|id| valid_id(id))
      .map(str::to_string)
      .collect();
    if ids.is_empty()
      && let Ok(accounts) =
        cf_get(&http, &account.token, "/accounts", &[]).await
      && let Some(accounts) = accounts.as_array()
    {
      ids.extend(
        accounts
          .iter()
          .filter_map(|a| a["id"].as_str())
          .filter(|id| valid_id(id))
          .map(str::to_string),
      );
    }
    for id in ids {
      token = cf_get(
        &http,
        &account.token,
        &format!("/accounts/{id}/tokens/verify"),
        &[],
      )
      .await;
      if token.is_ok() {
        break;
      }
    }
  }
  let token_status = match token {
    Ok(v)
      if v["status"] == "active"
        && v["expires_on"]
          .as_str()
          .and_then(|date| date.parse::<DateTime<Utc>>().ok())
          .is_none_or(|at| at > Utc::now()) =>
    {
      CheckStatus::Ok
    }
    Ok(_) => CheckStatus::Bad,
    Err(status) => status,
  };
  let mut out = vec![item(
    "令牌",
    name,
    token_status,
    match token_status {
      CheckStatus::Ok => "Cloudflare 令牌有效".into(),
      CheckStatus::Bad => {
        format!("Cloudflare 令牌校验失败或已过期。{CF_PERMISSIONS}")
      }
      _ => "Cloudflare 令牌状态查不到".into(),
    },
  )];
  for (zone, data) in zones {
    let status = match data {
      Ok(data) => match data["id"].as_str().filter(|id| valid_id(id))
      {
        Some(id) => match cf_get(
          &http,
          &account.token,
          &format!("/zones/{id}/dns_records"),
          &[("per_page", "1")],
        )
        .await
        {
          Ok(v) if v.is_array() => CheckStatus::Ok,
          Ok(_) => CheckStatus::Warn,
          Err(status) => status,
        },
        None => CheckStatus::Warn,
      },
      Err(status) => status,
    };
    let detail = match status {
      CheckStatus::Ok => {
        format!("{zone} 能读 DNS 记录，编辑权限未确认")
      }
      CheckStatus::Bad => {
        format!("{zone} 缺少 Zone 或 DNS 读取权限。{CF_PERMISSIONS}")
      }
      _ => format!("{zone} 的 DNS 权限查不到"),
    };
    out.push(item("DNS", name, status, detail));
  }
  if let Some(hint) =
    crate::external_status::incident_hint("Cloudflare")
  {
    for check in &mut out {
      if matches!(check.status, CheckStatus::Bad | CheckStatus::Warn)
      {
        if !check.detail.ends_with('。') {
          check.detail.push('。');
        }
        check.detail.push_str(&hint);
      }
    }
  }
  out
}

async fn oauth(secret: Option<&str>) -> Vec<DoctorCheck> {
  let name = "Tailscale OAuth";
  let Some(secret) = secret else {
    return vec![item(
      "令牌",
      name,
      CheckStatus::Skip,
      format!("没配 Tailscale OAuth 客户端。{OAUTH_SETUP}"),
    )];
  };
  let token = match tailscale::access_token(secret).await {
    Ok(token) => token,
    Err(e) => {
      return vec![item(
        "令牌",
        name,
        if e.denied() {
          CheckStatus::Bad
        } else {
          CheckStatus::Warn
        },
        format!("{}。{OAUTH_SETUP}", e.message()),
      )];
    }
  };
  let mut out =
    vec![item("令牌", name, CheckStatus::Ok, "能换取访问令牌")];
  let (devices, policy) = tokio::join!(
    tailscale::devices(&token),
    tailscale::policy(&token)
  );
  out.push(devices_check(name, devices));
  out.push(policy_check(name, policy));
  out
}

pub async fn checks(
  s: &AppState,
) -> Result<Vec<DoctorCheck>, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let cf = futures_util::future::join_all(
    snap
      .accounts
      .iter()
      .filter(|a| a.kind == "cloudflare")
      .map(cloudflare),
  );
  let (cf, ts) = tokio::join!(cf, oauth(credential(&snap)));
  Ok(cf.into_iter().flatten().chain(ts).collect())
}

pub async fn refresh(s: &AppState) -> Result<(), ApiError> {
  let checks = checks(s).await?;
  record(s, &checks).await;
  Ok(())
}

/// 按检查结果更新“厂商账号不可用”告警：有失败就触发，全部通过就恢复。
pub async fn record(s: &AppState, checks: &[DoctorCheck]) {
  let mut grouped: BTreeMap<&str, Vec<&DoctorCheck>> =
    BTreeMap::new();
  for check in checks {
    grouped.entry(&check.subject).or_default().push(check);
  }
  for (name, checks) in grouped {
    let bad = checks
      .iter()
      .filter(|c| c.status == CheckStatus::Bad)
      .map(|c| c.detail.as_str())
      .collect::<Vec<_>>();
    if !bad.is_empty() {
      rules::observe(s, "vendor.invalid", name, 1.0, &bad.join("\n"))
        .await;
    } else if !checks.iter().any(|c| c.status == CheckStatus::Warn) {
      rules::observe(
        s,
        "vendor.invalid",
        name,
        0.0,
        "必需权限检查通过",
      )
      .await;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use chrono::TimeDelta;

  #[test]
  fn tailnet_key_days() {
    let now = Utc::now();
    for (days, never, fires) in
      [(13, false, true), (15, false, false), (13, true, false)]
    {
      let key = TailnetKey {
        expires: Some(now + TimeDelta::days(days)),
        never_expires: never,
      };
      assert_eq!(days_left(&key, now).unwrap() < 14.0, fires);
    }
  }

  #[test]
  fn hujson_comments_and_trailing_commas() {
    let raw = r#"{
      // comment
      "groups": {"group:test": ["a@example.com",],},
      /* comment */
      "grants": [{"src": ["https://example.com"],}],
    }"#;
    let value = parse_policy(raw).unwrap();
    assert_eq!(value["groups"]["group:test"][0], "a@example.com");
    assert_eq!(value["grants"][0]["src"][0], "https://example.com");
  }

  #[test]
  fn tailscale_404_treated_as_missing_scope() {
    for code in [
      reqwest::StatusCode::UNAUTHORIZED,
      reqwest::StatusCode::FORBIDDEN,
      reqwest::StatusCode::NOT_FOUND,
    ] {
      let acl = policy_error(ReadError::Http(code));
      assert_eq!(acl.status, "OAuth 客户端缺少读取策略文件的权限");
      assert_eq!(acl.hint.as_deref(), Some(POLICY_SCOPE));

      let policy =
        policy_check("Tailscale OAuth", Err(ReadError::Http(code)));
      assert_eq!(policy.status, CheckStatus::Skip);
      assert!(policy.detail.contains("缺少读取策略文件的权限"));
      assert!(policy.detail.contains(POLICY_SCOPE));

      let devices =
        devices_check("Tailscale OAuth", Err(ReadError::Http(code)));
      assert_eq!(devices.status, CheckStatus::Bad);
      assert!(devices.detail.contains("缺少读取设备的权限"));
      assert!(devices.detail.contains(DEVICE_SCOPE));
    }

    let acl_500 = policy_error(ReadError::Http(
      reqwest::StatusCode::INTERNAL_SERVER_ERROR,
    ));
    assert_eq!(acl_500.status, "Tailscale API 返回 HTTP 500");
    assert!(acl_500.hint.is_none());

    let policy_500 = policy_check(
      "Tailscale OAuth",
      Err(ReadError::Http(
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
      )),
    );
    assert_eq!(policy_500.status, CheckStatus::Warn);
    assert_eq!(policy_500.detail, "Tailscale API 返回 HTTP 500");

    let devices_down =
      devices_check("Tailscale OAuth", Err(ReadError::Unavailable));
    assert_eq!(devices_down.status, CheckStatus::Warn);
    assert_eq!(devices_down.detail, "Tailscale API 查不到");
  }
}
