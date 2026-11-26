//! 同步设备地址供内网来源判定使用。

use std::{
  collections::BTreeSet, net::IpAddr, sync::RwLock, time::Duration,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use wharf_providers::tailscale::{access_token, devices};

use crate::{
  auth::hash_token,
  db::{self, Db},
  source_trust::{is_cgnat_v4, is_tailscale_ula_v6},
  tailscale::OAUTH_SECRET,
};

const SETTING: &str = "tailscale.device_ips";
const INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Deserialize, Serialize)]
struct TailnetIps {
  client: String,
  cidrs: Vec<IpNet>,
}

static CACHE: RwLock<Option<TailnetIps>> = RwLock::new(None);

fn host_cidr(ip: IpAddr) -> Option<IpNet> {
  match ip {
    IpAddr::V4(v4) if is_cgnat_v4(v4) => Some(IpNet::from(ip)),
    IpAddr::V6(v6) if is_tailscale_ula_v6(v6) => {
      Some(IpNet::from(ip))
    }
    _ => None,
  }
}

fn client_id(credential: &str) -> Option<String> {
  let (id, secret) = credential.split_once(':')?;
  (!id.is_empty() && !secret.is_empty()).then(|| hash_token(id))
}

pub async fn init(db: &Db) {
  if let Ok(Some(json)) = db.call(|c| db::setting(c, SETTING)).await
    && let Ok(mut cache) = serde_json::from_str::<TailnetIps>(&json)
  {
    cache
      .cidrs
      .retain(|cidr| host_cidr(cidr.addr()) == Some(*cidr));
    cache.cidrs.sort();
    cache.cidrs.dedup();
    *CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
  }
}

pub fn cached_cidrs(credential: &str) -> Vec<IpNet> {
  let Some(client) = client_id(credential) else {
    return vec![];
  };
  CACHE
    .read()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .filter(|cache| cache.client == client)
    .map(|cache| cache.cidrs.clone())
    .unwrap_or_default()
}

async fn sync(db: &Db) -> Result<(), String> {
  let Some(credential) = db
    .call_credentials(|c, key| key.secret(c, OAUTH_SECRET))
    .await
    .map_err(|e| e.message)?
    .filter(|value| !value.is_empty())
  else {
    let had_cache = CACHE
      .write()
      .unwrap_or_else(|e| e.into_inner())
      .take()
      .is_some();
    if had_cache {
      db.call(|c| db::set_setting(c, SETTING, None))
        .await
        .map_err(|e| e.message)?;
      crate::snapshot::load(db).await.map_err(|e| e.message)?;
    }
    return Ok(());
  };
  let client = client_id(&credential)
    .ok_or("Tailscale 凭据格式应为 client_id:client_secret")?;
  let token =
    access_token(&credential).await.map_err(|e| e.message())?;
  let result = devices(&token).await.map_err(|e| e.message())?;
  let mut cidrs = BTreeSet::new();
  for device in result["devices"]
    .as_array()
    .ok_or("Tailscale 未返回设备列表")?
  {
    for addr in device["addresses"]
      .as_array()
      .ok_or("Tailscale 设备地址格式异常")?
    {
      let ip = addr
        .as_str()
        .and_then(|addr| addr.parse().ok())
        .ok_or("Tailscale 设备地址格式异常")?;
      cidrs.extend(host_cidr(ip));
    }
  }
  let cache = TailnetIps {
    client,
    cidrs: cidrs.into_iter().collect(),
  };
  if CACHE
    .read()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .is_some_and(|old| {
      old.client == cache.client && old.cidrs == cache.cidrs
    })
  {
    return Ok(());
  }
  let json = serde_json::to_string(&cache)
    .map_err(|_| "无法编码 Tailscale 设备地址")?;
  let accepted = db
    .call_credentials(move |c, key| {
      if key.secret(c, OAUTH_SECRET)?.as_deref()
        != Some(credential.as_str())
      {
        return Ok(false);
      }
      db::set_setting(c, SETTING, Some(&json))?;
      Ok(true)
    })
    .await
    .map_err(|e| e.message)?;
  if accepted {
    *CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
    crate::snapshot::load(db).await.map_err(|e| e.message)?;
  }
  Ok(())
}

pub fn spawn(db: Db) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(15)).await;
    loop {
      if let Err(error) = sync(&db).await {
        tracing::warn!("同步 Tailscale 设备地址失败：{error}");
      }
      tokio::time::sleep(INTERVAL).await;
    }
  });
}
