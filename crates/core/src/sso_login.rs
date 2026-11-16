//! 按域名配置代登录，只有遮盖后的步骤摘要能返回接口。
use crate::{api::ApiResult, auth::Auth, snapshot, state::AppState};
use axum::{
  Json,
  extract::{Path, State},
};
use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HttpFetch, HttpFetchResult},
  spec::{
    Extract, LoginSpec, LoginStep, LoginWrite, SsoMode, SsoSpec,
  },
  view::{Perm, SsoStepResult, SsoTestResult},
};

type Values = BTreeMap<String, String>;
// 弱引用不保留已经完成的域名。
static LOCKS: LazyLock<
  Mutex<BTreeMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
> = LazyLock::new(Mutex::default);

pub struct Outcome {
  pub ok: bool,
  pub steps: Vec<SsoStepResult>,
  pub check: Option<SsoStepResult>,
  pub set_cookies: Vec<String>,
  pub vars: Values,
}

fn references(text: &str) -> Result<Vec<&str>, ApiError> {
  let mut rest = text;
  let mut names = Vec::new();
  while let Some((_, after)) = rest.split_once("{{") {
    let (name, next) = after
      .split_once("}}")
      .ok_or_else(|| ApiError::invalid("模板缺少 }}"))?;
    if name.is_empty() || name.contains(['{', '}']) {
      return Err(ApiError::invalid("模板名字无效"));
    }
    names.push(name);
    rest = next;
  }
  Ok(names)
}
pub fn render(
  text: &str,
  vars: &Values,
  secrets: &Values,
) -> Result<String, ApiError> {
  references(text)?;
  let mut result = String::new();
  let mut rest = text;
  while let Some((before, after)) = rest.split_once("{{") {
    let (name, next) = after.split_once("}}").unwrap();
    result.push_str(before);
    let value = if let Some(key) = name.strip_prefix("secret.") {
      secrets.get(key)
    } else {
      vars.get(name)
    }
    .ok_or_else(|| ApiError::invalid(format!("取不到 {name}")))?;
    result.push_str(value);
    rest = next;
  }
  result.push_str(rest);
  Ok(result)
}
fn strings(value: &serde_json::Value) -> Vec<&str> {
  match value {
    serde_json::Value::String(s) => vec![s],
    serde_json::Value::Array(a) => {
      a.iter().flat_map(strings).collect()
    }
    serde_json::Value::Object(o) => {
      o.values().flat_map(strings).collect()
    }
    _ => Vec::new(),
  }
}
pub fn secret_refs(login: &LoginSpec) -> BTreeSet<String> {
  strings(&serde_json::to_value(login).unwrap())
    .into_iter()
    .filter_map(|s| references(s).ok())
    .flatten()
    .filter_map(|s| s.strip_prefix("secret.").map(str::to_string))
    .collect()
}
pub fn validate(host: &str, sso: &SsoSpec) -> Result<(), ApiError> {
  let fail = |s: &str| ApiError::invalid(format!("域名 {host}：{s}"));
  if (sso.mode == SsoMode::Login) != sso.login.is_some() {
    return Err(fail(
      "只有 login 方式才能写登录步骤，login 方式必须有登录步骤",
    ));
  }
  let Some(login) = &sso.login else {
    return Ok(());
  };
  if !(1..=5).contains(&login.steps.len())
    || !(1..=8).contains(&login.write.len())
    || !(1..=720).contains(&login.ttl_hours)
  {
    return Err(fail(
      "登录步骤须为 1 到 5 步，写入须为 1 到 8 项，ttl_hours 须为 1 到 720",
    ));
  }
  let mut known = BTreeSet::new();
  for (i, step) in
    login.steps.iter().chain(login.check.iter()).enumerate()
  {
    if !step.path.starts_with('/')
      || step.path.starts_with("//")
      || !matches!(
        step.method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
      )
      || [
        step.form.is_some(),
        step.json.is_some(),
        step.body.is_some(),
      ]
      .into_iter()
      .filter(|v| *v)
      .count()
        > 1
    {
      return Err(fail("登录步骤的路径、方法或正文写得不对"));
    }
    if i == login.steps.len()
      && (step.method != "GET"
        || step.form.is_some()
        || step.json.is_some()
        || step.body.is_some()
        || !step.extract.is_empty())
    {
      return Err(fail("check 只支持 GET、path、expect 和 headers"));
    }
    let value = serde_json::to_value(step).unwrap();
    for text in strings(&value) {
      for name in references(text)? {
        if name.strip_prefix("secret.").is_none_or(|n| n.is_empty())
          && !known.contains(name)
        {
          return Err(fail(&format!(
            "第 {} 步用了 {name}，前面没有取过这个值",
            i + 1
          )));
        }
      }
    }
    for rule in &step.extract {
      let name = rule.name();
      if name.is_empty()
        || name == "secret"
        || !name.bytes().all(|b| {
          b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
        })
      {
        return Err(fail(
          "取值名字只允许小写字母、数字和 _，不能叫 secret",
        ));
      }
      known.insert(name.to_string());
    }
  }
  for write in &login.write {
    for text in strings(&serde_json::to_value(write).unwrap()) {
      for name in references(text)? {
        if name.strip_prefix("secret.").is_none_or(|n| n.is_empty())
          && !known.contains(name)
        {
          return Err(fail(&format!("写入用了未取过的值 {name}")));
        }
      }
    }
  }
  Ok(())
}

// 名字 -> (值, 原始 Set-Cookie)。不解释应用自己的 cookie 属性。
pub fn jar_update(
  jar: &mut BTreeMap<String, (String, String)>,
  headers: &[(String, String)],
) {
  for (_, raw) in headers
    .iter()
    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
  {
    if let Some((name, value)) =
      raw.split(';').next().unwrap_or("").split_once('=')
    {
      jar.insert(
        name.trim().into(),
        (value.trim().into(), raw.clone()),
      );
    }
  }
}
pub fn extract(
  rule: &Extract,
  headers: &[(String, String)],
  body: &str,
  jar: &BTreeMap<String, (String, String)>,
) -> Result<String, ApiError> {
  let value = match rule {
    Extract::Json { path, .. } => {
      serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|mut v| {
          for key in path.split('.') {
            v = if v.is_array() {
              v.get(key.parse::<usize>().ok()?)?
            } else {
              v.get(key)?
            }
            .clone();
          }
          match v {
            serde_json::Value::String(s) => Some(s),
            serde_json::Value::Number(_)
            | serde_json::Value::Bool(_) => Some(v.to_string()),
            _ => None,
          }
        })
    }
    Extract::Body { between, .. } => body
      .split_once(&between[0])
      .and_then(|(_, s)| s.split_once(&between[1]))
      .map(|(s, _)| s.to_string()),
    Extract::Header { header, .. } => headers
      .iter()
      .find(|(k, _)| k.eq_ignore_ascii_case(header))
      .map(|(_, v)| v.clone()),
    Extract::Cookie { cookie, .. } => {
      jar.get(cookie).map(|(v, _)| v.clone())
    }
  };
  value.ok_or_else(|| {
    ApiError::invalid(format!("取不到 {}", rule.name()))
  })
}
pub fn mask(text: &str, values: &[String]) -> String {
  let mut values: Vec<_> =
    values.iter().filter(|s| !s.is_empty()).collect();
  values.sort_by_key(|v| std::cmp::Reverse(v.len()));
  values
    .into_iter()
    .fold(text.to_string(), |s, v| s.replace(v, "***"))
}
fn render_json(
  value: &mut serde_json::Value,
  vars: &Values,
  secrets: &Values,
) -> Result<(), ApiError> {
  match value {
    serde_json::Value::String(s) => *s = render(s, vars, secrets)?,
    serde_json::Value::Array(a) => {
      for v in a {
        render_json(v, vars, secrets)?;
      }
    }
    serde_json::Value::Object(o) => {
      for v in o.values_mut() {
        render_json(v, vars, secrets)?;
      }
    }
    _ => {}
  }
  Ok(())
}
fn job(
  upstream: &str,
  step: &LoginStep,
  vars: &Values,
  secrets: &Values,
  jar: &BTreeMap<String, (String, String)>,
) -> Result<HttpFetch, ApiError> {
  let path = render(&step.path, vars, secrets)?;
  if !path.starts_with('/') || path.starts_with("//") {
    return Err(ApiError::invalid(
      "替换后的路径必须以 / 开头且不能以 // 开头",
    ));
  }
  let mut headers: Vec<(String, String)> = step
    .headers
    .iter()
    .map(|(k, v)| Ok((k.clone(), render(v, vars, secrets)?)))
    .collect::<Result<_, ApiError>>()?;
  let (body, content_type) = if let Some(form) = &step.form {
    (
      Some(
        form
          .iter()
          .map(|(k, v)| {
            Ok(format!(
              "{}={}",
              urlencoding::encode(k),
              urlencoding::encode(&render(v, vars, secrets)?)
            ))
          })
          .collect::<Result<Vec<_>, ApiError>>()?
          .join("&"),
      ),
      "application/x-www-form-urlencoded",
    )
  } else if let Some(json) = &step.json {
    let mut json = json.clone();
    render_json(&mut json, vars, secrets)?;
    (Some(json.to_string()), "application/json")
  } else {
    (
      step
        .body
        .as_ref()
        .map(|s| render(s, vars, secrets))
        .transpose()?,
      "text/plain",
    )
  };
  if body.is_some()
    && !headers
      .iter()
      .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
  {
    headers.push(("Content-Type".into(), content_type.into()));
  }
  if !jar.is_empty() {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
    headers.push((
      "Cookie".into(),
      jar
        .iter()
        .map(|(k, (v, _))| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "),
    ));
  }
  Ok(HttpFetch {
    url: format!("http://{upstream}{path}"),
    method: step.method.clone(),
    headers,
    body,
    timeout_secs: 15,
  })
}

async fn execute(
  state: &AppState,
  hostname: &str,
) -> Result<Outcome, ApiError> {
  let lock = {
    let mut locks = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    locks.retain(|_, v| v.strong_count() > 0);
    let lock = locks
      .get(hostname)
      .and_then(|v| v.upgrade())
      .unwrap_or_default();
    locks.insert(hostname.into(), Arc::downgrade(&lock));
    lock
  };
  let _guard = lock.lock().await;
  let snap = snapshot::load(&state.db).await?;
  let route = snap.world.routes.get(hostname).ok_or_else(|| {
    ApiError::not_found(format!("域名 {hostname} 不存在"))
  })?;
  let login = route
    .spec
    .sso
    .as_ref()
    .filter(|s| s.mode == SsoMode::Login)
    .and_then(|s| s.login.as_ref())
    .ok_or_else(|| ApiError::invalid("域名没有配置代登录"))?;
  if !snap.world.services.contains_key(&route.spec.service) {
    return Err(ApiError::invalid(format!(
      "域名 {hostname} 没有指向服务，不能代登录"
    )));
  }
  let gateway = snap
    .world
    .route_gateways(&route.spec)
    .first()
    .copied()
    .ok_or_else(|| ApiError::invalid("域名没有入口"))?;
  let server = &snap.world.gateways[gateway].spec.server;
  if !state.hub.is_online(server) {
    return Err(ApiError::new(
      ErrorCode::AgentOffline,
      format!("服务器 {server} 不在线"),
    ));
  }
  if crate::agent_upgrade::outdated(
    snap
      .agent(server)
      .and_then(|a| a.report.as_ref())
      .map(|r| r.build.as_str()),
  ) {
    return Err(ApiError::invalid(format!(
      "服务器 {server} 的 agent 版本太旧，升级后才能代登录"
    )));
  }
  let net = snap.net(&snap.world);
  let rendered =
    snapshot::gateway_render(&snap.world, &net, gateway)?;
  let upstream = &rendered
    .sites
    .iter()
    .find(|s| s.hostname == hostname)
    .ok_or_else(|| ApiError::invalid("域名没有上游"))?
    .upstream;
  let cancel = CancellationToken::new();
  let _cancel_on_drop = cancel.clone().drop_guard();
  let deadline =
    tokio::time::Instant::now() + Duration::from_secs(60);
  let mut outcome = Outcome {
    ok: true,
    steps: vec![],
    check: None,
    set_cookies: vec![],
    vars: Values::new(),
  };
  let mut jar = BTreeMap::new();
  let mut hidden: Vec<String> =
    snap.secrets.values().cloned().collect();
  for (i, step) in
    login.steps.iter().chain(login.check.iter()).enumerate()
  {
    let start = Instant::now();
    let is_check = i == login.steps.len();
    let mut summary = SsoStepResult {
      number: i + 1,
      method: step.method.clone(),
      path: step.path.clone(),
      status: None,
      ms: 0,
      extracted: BTreeMap::new(),
      error: None,
    };
    let mut response = HttpFetchResult::default();
    let result = async {
      let request =
        job(upstream, step, &outcome.vars, &snap.secrets, &jar)?;
      response = tokio::time::timeout_at(
        deadline,
        state.hub.call(
          server,
          AgentOp::HttpFetch(request),
          Duration::from_secs(15),
          None,
          &cancel,
        ),
      )
      .await
      .map_err(|_| {
        ApiError::new(ErrorCode::Timeout, "代登录超过 60 秒")
      })??;
      summary.status = response.status;
      jar_update(&mut jar, &response.headers);
      if let Some(e) = &response.error {
        return Err(ApiError::invalid(e));
      }
      for rule in &step.extract {
        // 先收集能取到的值，状态码失败的正文也必须遮盖它们。
        if let Ok(value) =
          extract(rule, &response.headers, &response.body, &jar)
        {
          outcome.vars.insert(rule.name().into(), value);
        }
      }
      if !response.status.is_some_and(|s| {
        step.expect.as_ref().map_or(
          if is_check {
            s == 200
          } else {
            (200..400).contains(&s)
          },
          |codes| codes.contains(&s),
        )
      }) {
        return Err(ApiError::invalid("应答状态码不符合预期"));
      }
      for rule in &step.extract {
        let value =
          extract(rule, &response.headers, &response.body, &jar)?;
        summary
          .extracted
          .insert(rule.name().into(), value.chars().count());
      }
      Ok::<_, ApiError>(())
    }
    .await;
    hidden.extend(outcome.vars.values().cloned());
    hidden.extend(jar.values().map(|(v, _)| v.clone()));
    summary.path = mask(&summary.path, &hidden);
    if let Err(error) = result {
      cancel.cancel();
      outcome.ok = false;
      let body = mask(&response.body, &hidden)
        .chars()
        .take(300)
        .collect::<String>();
      summary.error = Some(format!(
        "{}{}",
        mask(&error.message, &hidden),
        if body.is_empty() {
          String::new()
        } else {
          format!("：{body}")
        }
      ));
    }
    summary.ms = start.elapsed().as_millis() as u64;
    if is_check {
      outcome.check = Some(summary);
    } else {
      outcome.steps.push(summary);
    }
    if !outcome.ok {
      break;
    }
  }
  outcome.set_cookies =
    jar.into_values().map(|(_, raw)| raw).collect();
  Ok(outcome)
}

pub async fn record(
  state: &AppState,
  host: &str,
  ok: bool,
  error: Option<String>,
) -> Result<(), ApiError> {
  let host = host.to_string();
  let result = wharf_api_types::view::SsoLoginState {
    at: crate::db::now_ms(),
    ok,
    error,
  };
  state.db.call(move |c| {
    let value = serde_json::to_string(&result).map_err(|_| ApiError::internal("代登录结果格式不对"))?;
    let tx = c.unchecked_transaction().map_err(crate::db::sql_err)?;
    crate::db::set_setting(&tx, &format!("sso.login.{host}"), Some(&value))?;
    tx.execute("INSERT INTO audit_log (at,kind,actor,method,path,status,detail) VALUES (?1,'api','Wharf','sso',?2,?3,?4)", rusqlite::params![result.at, host, if ok {200} else {400}, result.error]).map_err(crate::db::sql_err)?;
    tx.commit().map_err(crate::db::sql_err)
  }).await
}
pub fn issues(
  snap: &snapshot::Snapshot,
) -> Vec<wharf_api_types::view::Issue> {
  use wharf_api_types::view::{
    Issue, IssueLevel, IssueSubject, SsoLoginState,
  };
  snap
    .world
    .routes
    .iter()
    .filter(|(_, r)| {
      r.spec
        .sso
        .as_ref()
        .is_some_and(|s| s.mode == SsoMode::Login)
    })
    .filter_map(|(host, _)| {
      let result: SsoLoginState =
        serde_json::from_str(snap.sso_login.get(host)?).ok()?;
      (!result.ok).then(|| Issue {
        code: "sso_login_failed".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "route".into(),
          name: host.clone(),
        }),
        title: format!("{host} 代登录失败"),
        hint: Some(format!(
          "{}；用 wharf sso test {host} 查看",
          result.error.as_deref().unwrap_or("登录失败")
        )),
      })
    })
    .collect()
}
pub async fn run(
  state: &AppState,
  hostname: &str,
) -> Result<Outcome, ApiError> {
  let outcome = execute(state, hostname).await;
  let (ok, error) = match &outcome {
    Ok(o) => (
      o.ok,
      o.steps.iter().chain(o.check.iter()).find_map(|step| {
        step
          .error
          .as_ref()
          .map(|e| format!("第 {} 步：{e}", step.number))
      }),
    ),
    Err(e) => (false, Some(e.message.clone())),
  };
  record(state, hostname, ok, error).await?;
  outcome
}

pub async fn test(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(hostname): Path<String>,
) -> ApiResult<SsoTestResult> {
  auth.require(Perm::Admin)?;
  let outcome = run(&state, &hostname).await?;
  let mut would_write = Vec::new();
  if outcome.ok {
    let snap = snapshot::load(&state.db).await?;
    let login = snap
      .world
      .routes
      .get(&hostname)
      .and_then(|r| r.spec.sso.as_ref())
      .and_then(|s| s.login.as_ref())
      .ok_or_else(|| ApiError::invalid("代登录配置已改变"))?;
    for write in &login.write {
      would_write.push(match write {
        LoginWrite::Cookies(_) => format!(
          "应用自己的 {} 个 cookie：{}",
          outcome.set_cookies.len(),
          outcome
            .set_cookies
            .iter()
            .filter_map(|s| s.split_once('=').map(|(n, _)| n))
            .collect::<Vec<_>>()
            .join("、")
        ),
        LoginWrite::Cookie { name, value, .. } => format!(
          "cookie {name}（{} 个字符）",
          render(value, &outcome.vars, &snap.secrets)?
            .chars()
            .count()
        ),
        LoginWrite::LocalStorage { key, value } => format!(
          "localStorage {key}（{} 个字符）",
          render(value, &outcome.vars, &snap.secrets)?
            .chars()
            .count()
        ),
        LoginWrite::SessionStorage { key, value } => format!(
          "sessionStorage {key}（{} 个字符）",
          render(value, &outcome.vars, &snap.secrets)?
            .chars()
            .count()
        ),
      });
    }
  }
  Ok(Json(SsoTestResult {
    ok: outcome.ok,
    steps: outcome.steps,
    check: outcome.check,
    would_write,
  }))
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn templates() {
    let vars = Values::from([("csrf".into(), "value".into())]);
    assert_eq!(
      render("a{{csrf}}", &vars, &Values::new()).unwrap(),
      "avalue"
    );
    assert!(render("{{missing}}", &vars, &Values::new()).is_err());
    assert_eq!(
      render(
        "{{secret.USER}}",
        &Values::new(),
        &Values::from([("USER".into(), "{{csrf}}".into())])
      )
      .unwrap(),
      "{{csrf}}"
    );
  }
  #[test]
  fn between() {
    let r = Extract::Body {
      name: "csrf".into(),
      between: ["a=".into(), ";".into()],
    };
    assert_eq!(
      extract(&r, &[], "a=abc;", &BTreeMap::new()).unwrap(),
      "abc"
    );
    assert!(extract(&r, &[], "missing", &BTreeMap::new()).is_err());
  }
  #[test]
  fn json_path() {
    let r = Extract::Json {
      name: "id".into(),
      path: "data.items.0.id".into(),
    };
    assert_eq!(
      extract(
        &r,
        &[],
        r#"{"data":{"items":[{"id":42}]}}"#,
        &BTreeMap::new()
      )
      .unwrap(),
      "42"
    );
  }
  #[test]
  fn cookies() {
    let mut jar = BTreeMap::new();
    jar_update(
      &mut jar,
      &[
        ("Set-Cookie".into(), "sid=old; Path=/".into()),
        ("set-cookie".into(), "sid=new; Secure".into()),
      ],
    );
    assert_eq!(jar["sid"], ("new".into(), "sid=new; Secure".into()));
  }
  #[test]
  fn masking() {
    let s = mask(
      "password=secret-value csrf=abc sid=long-secret-value",
      &[
        "secret-value".into(),
        "abc".into(),
        "long-secret-value".into(),
      ],
    );
    assert!(!s.contains("secret-value"));
    assert!(!s.contains("abc"));
  }
}
