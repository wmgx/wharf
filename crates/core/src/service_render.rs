use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Path, State},
};
use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError,
  spec::Source,
  view::{Perm, ServiceRenderView},
};

use crate::{
  api::ApiResult,
  auth::Auth,
  render::{self, SecretMode},
  snapshot::{self, Snapshot},
  state::AppState,
};

mod export;
pub(crate) use export::get as export_compose;

pub async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ServiceRenderView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  let snap = snapshot::load_inner(&state.db).await?;
  preview(&snap, &name).map(Json).map_err(|mut error| {
    if let Some(row) = snap.world.services.get(&name) {
      let values = crate::log_redact::service_values(&row.spec);
      error.message =
        wharf_api_types::mask_values(&error.message, &values);
      error.hint = error
        .hint
        .map(|hint| wharf_api_types::mask_values(&hint, &values));
    }
    error.into()
  })
}

fn preview(
  snap: &Snapshot,
  name: &str,
) -> Result<ServiceRenderView, ApiError> {
  let mut world = snap.world.clone();
  let row = world
    .services
    .get_mut(name)
    .ok_or_else(|| crate::api::service_not_found(name))?;
  let extra = crate::log_redact::service_values(&row.spec);
  let keys: BTreeSet<_> = snap
    .render_values(&snap.world, name)
    .into_keys()
    .filter(|key| {
      snap
        .secret_restrictions
        .get(key)
        .is_none_or(|allowed| allowed.contains(name))
    })
    .collect();
  // 用普通标量占位，避免未加引号的星号被 YAML 当作别名。
  let mut marker = "WHARFPREVIEWMASK".to_string();
  let template = serde_json::to_string(&row.spec)
    .map_err(|_| ApiError::internal("无法读取服务模板"))?;
  while template.contains(&marker) {
    marker.push('X');
  }
  let mut replacements =
    BTreeMap::from([(marker.clone(), "***".to_string())]);
  let mut masks = BTreeMap::new();
  let mut missing = BTreeSet::new();
  let mut substitute = |text: &str| {
    render::rewrite_placeholders(text, true, |p| {
      if !keys.contains(p.name) {
        missing.insert(p.name.to_string());
        let id = format!("{marker}MISSING{}END", replacements.len());
        let prefix = match p.mode {
          SecretMode::Plain => "",
          SecretMode::B64 => "b64:",
          SecretMode::Json => "json:",
          SecretMode::Url => "url:",
          SecretMode::File => "FILE:",
        };
        replacements
          .insert(id.clone(), format!("[[{prefix}{}]]", p.name));
        return Ok(Some(id));
      }
      masks.insert(p.name.to_string(), marker.clone());
      Ok(Some(if p.mode == SecretMode::File {
        format!("[[FILE:{}]]", p.name)
      } else {
        marker.clone()
      }))
    })
  };
  let source = match &mut row.spec.source {
    Source::Compose { content, .. } => {
      if let Some(content) = content {
        *content = substitute(content)?;
      }
      "compose"
    }
    Source::Image(_) => "image",
    Source::Build(_) => "build",
  };
  for value in row.spec.env.values_mut() {
    *value = substitute(value)?;
  }
  for file in &mut row.spec.files {
    file.content = substitute(&file.content)?;
  }
  let init_cmd = row
    .spec
    .init_cmd
    .as_deref()
    .map(&mut substitute)
    .transpose()?;
  let mut warnings = missing
    .into_iter()
    .map(|key| {
      format!(
        "缺少密钥 {key}，部署前需先设置：wharf secret set {key}"
      )
    })
    .collect::<Vec<_>>();
  if row
    .spec
    .ports
    .iter()
    .any(|p| !row.host_ports.contains_key(&p.name))
  {
    warnings.push("有端口尚未分配宿主端口".into());
  }

  let net = snap.net(&world);
  let row = &world.services[name];
  let (compose, mounts) = render::service_compose(
    name,
    snapshot::runtime_spec(row)?.as_ref(),
    &row.host_ports,
    &net.bind_ips(&row.spec.server),
    Some(&masks),
  )?;
  let compose = crate::service_monitor::heartbeat::compose(
    &compose,
    &row.spec,
    net.heartbeat_url.as_deref(),
    false,
  )?;
  let compose = crate::refs::resolve(&compose, name, &world, &net)?;
  let compose = snapshot::with_files(
    &world,
    &net,
    name,
    &compose,
    mounts,
    Some(&masks),
    false,
  )?;

  let redact = |value: &str| {
    let value = wharf_api_types::mask_values(value, &extra);
    let mut value =
      wharf_api_types::mask_values(&value, &snap.log_values);
    for (from, to) in replacements.iter().rev() {
      value = value.replace(from, to);
    }
    value
  };
  let mut compose = render::parse_compose(&compose)?;
  mask_yaml(&mut compose, &redact);
  Ok(ServiceRenderView {
    service: name.into(),
    server: row.spec.server.clone(),
    source: source.into(),
    compose: serde_yaml_ng::to_string(&compose)
      .map_err(|_| ApiError::internal("无法输出 Compose 预览"))?,
    init_cmd: init_cmd
      .map(|cmd| redact(&crate::redact::redact_command(&cmd))),
    secrets_masked: masks.into_keys().collect(),
    warnings,
  })
}

fn mask_yaml(value: &mut Value, redact: &impl Fn(&str) -> String) {
  match value {
    Value::String(text) => *text = redact(text),
    Value::Sequence(items) => {
      items.iter_mut().for_each(|item| mask_yaml(item, redact))
    }
    Value::Mapping(items) => {
      for (mut key, mut value) in std::mem::take(items) {
        mask_yaml(&mut key, redact);
        mask_yaml(&mut value, redact);
        items.insert(key, value);
      }
    }
    Value::Tagged(tag) => mask_yaml(&mut tag.value, redact),
    Value::Number(n) if redact(&n.to_string()) != n.to_string() => {
      *value = Value::String("***".into())
    }
    _ => {}
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    db::{self, Write},
    host_access::tests::auth,
  };
  use serde_json::json;

  #[tokio::test]
  async fn service_render_expands_compose_merge_keys() {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      for (kind, name, spec) in [
        ("server", "s1", json!({})),
        ("service", "anchored", json!({"server":"s1", "source":{"compose":{
          "content":"x-base: &base { image: alpine, command: base }\nservices:\n  web:\n    <<: *base\n    command: local\n"}}})),
      ] {
        db::apply_write(c, &Write::Upsert {
          kind: kind.into(), name: name.into(), spec, meta: json!({}),
        })?;
      }
      Ok(())
    }).await.unwrap();
    let result = get(
      State(state),
      auth([Perm::Read], false),
      Path("anchored".into()),
    )
    .await
    .map_err(|error| error.0)
    .unwrap()
    .0;
    let doc: Value =
      serde_yaml_ng::from_str(&result.compose).unwrap();
    let web = &doc["services"]["web"];
    assert_eq!(web["image"].as_str(), Some("alpine"));
    assert_eq!(web["command"].as_str(), Some("local"));
    assert!(web.get("<<").is_none());
  }

  #[tokio::test]
  async fn service_render_masks_secret_files_and_scopes_access() {
    let state = crate::rules::tests::test_state();
    state.db.call_credentials(|c, key| {
      key.put_secret(c, "DB_PASS", "fixture-password", 0, true)?;
      key.put_secret(c, "TLS_KEY", "fixture-key", 0, true)?;
      for (kind, name, spec, meta) in [
        ("server", "s1", json!({"private_addr":{"ip":"100.64.0.1","network":"overlay"}}), json!({})),
        ("service", "app", json!({
          "server":"s1", "source":{"image":"alpine"},
          "env":{"DB_PASS":"[[b64:DB_PASS]]","KEY_PATH":"[[FILE:TLS_KEY]]","API_TOKEN":"fixture-inline","DB":"[[@db:port]]"},
          "files":[{"path":"/etc/app.conf","content":"missing=[[MISSING]]"}],
        }), json!({})),
        ("service", "db", json!({
          "server":"s1", "source":{"image":"alpine"}, "ports":[{"name":"db","container":5432}],
        }), json!({"host_ports":{"db":15432}})),
      ] {
        db::apply_write(c, &Write::Upsert { kind: kind.into(), name: name.into(), spec, meta })?;
      }
      Ok(())
    }).await.unwrap();
    let mut auth = auth([Perm::Read], false);
    auth.services = Some(["app".to_string()].into_iter().collect());
    let result = get(State(state.clone()), auth, Path("app".into()))
      .await
      .map_err(|error| error.0)
      .unwrap()
      .0;
    assert_eq!(result.secrets_masked, ["DB_PASS", "TLS_KEY"]);
    for text in [
      "/run/wharf-secrets/TLS_KEY",
      "15432",
      "/etc/app.conf",
      "[[MISSING]]",
      "***",
    ] {
      assert!(result.compose.contains(text), "{text}");
    }
    for text in [
      "fixture-password",
      "fixture-key",
      "fixture-inline",
      "[[@db:port]]",
    ] {
      assert!(!result.compose.contains(text), "{text}");
    }
    let mut auth =
      crate::host_access::tests::auth([Perm::Read], false);
    auth.services = Some(["app".to_string()].into_iter().collect());
    assert_eq!(
      get(State(state), auth, Path("db".into()))
        .await
        .unwrap_err()
        .0
        .code,
      wharf_api_types::ErrorCode::Forbidden
    );
  }
}
