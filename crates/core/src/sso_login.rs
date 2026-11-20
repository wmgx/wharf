//! 按域名配置代登录，测试接口只返回遮盖后的摘要和脚本日志。
use crate::{
  api::ApiResult, auth::Auth, render as config, snapshot,
  state::AppState, tasks,
};
use axum::{
  Json,
  extract::{Path, State},
};
use serde::Deserialize;
use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, HttpFetch, HttpFetchResult, TaskHow, TaskRunJob,
    TaskRunResult, sso_runner_name,
  },
  mask_values as mask,
  spec::{
    Extract, LoginScript, LoginSpec, LoginStep, LoginWrite, SsoMode,
    SsoSpec,
  },
  view::{Perm, SsoStepResult, SsoTestResult},
};

type Values = BTreeMap<String, String>;
type CookieJar = BTreeMap<String, (String, String)>;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const TEST_TIMEOUT: Duration = Duration::from_secs(13 * 60);
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
  pub script_storage: Storage,
  pub script_log: Option<String>,
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
  let mut value = serde_json::to_value(login).unwrap();
  value.as_object_mut().unwrap().remove("script");
  let mut names: BTreeSet<String> = strings(&value)
    .into_iter()
    .filter_map(|s| references(s).ok())
    .flatten()
    .filter_map(|s| s.strip_prefix("secret.").map(str::to_string))
    .collect();
  if let Some(script) = &login.script {
    names.extend(
      script
        .env
        .values()
        .filter_map(|value| env_refs(value).ok())
        .flatten()
        .map(str::to_string),
    );
  }
  names
}

fn env_refs(value: &str) -> Result<Vec<&str>, ApiError> {
  let mut rest = value;
  let mut names = Vec::new();
  while let Some((_, after)) = rest.split_once("[[") {
    let (name, next) = after
      .split_once("]]")
      .ok_or_else(|| ApiError::invalid("密钥引用缺少 ]]"))?;
    if name.is_empty()
      || !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
      return Err(ApiError::invalid("密钥引用的名称无效"));
    }
    names.push(name);
    rest = next;
  }
  Ok(names)
}
pub(crate) fn takeover_path(raw: &str) -> Option<String> {
  if !raw.starts_with('/')
    || raw.starts_with("//")
    || raw.contains('\\')
    || raw.chars().any(char::is_control)
  {
    return None;
  }
  let url =
    reqwest::Url::parse(&format!("https://example.test{raw}"))
      .ok()?;
  let path = urlencoding::decode(url.path()).ok()?;
  if path.starts_with("//")
    || path == "/_wharf"
    || path.starts_with("/_wharf/")
  {
    return None;
  }
  Some(path.into_owned())
}

pub(crate) fn takeover_matches(path: &str, paths: &[String]) -> bool {
  paths.iter().any(|prefix| {
    path == prefix
      || path
        .strip_prefix(prefix.trim_end_matches('/'))
        .is_some_and(|rest| rest.starts_with('/'))
  })
}

pub(crate) fn takeover_rd<'a>(
  login: &'a LoginSpec,
  raw: Option<&'a str>,
) -> &'a str {
  raw
    .filter(|rd| {
      takeover_path(rd).is_some_and(|path| {
        login
          .takeover
          .as_ref()
          .is_none_or(|t| !takeover_matches(&path, &t.paths))
      })
    })
    .or(login.entry.as_deref())
    .unwrap_or("/")
}

pub fn validate(host: &str, sso: &SsoSpec) -> Result<(), ApiError> {
  let fail = |s: &str| ApiError::invalid(format!("域名 {host}：{s}"));
  if (sso.mode == SsoMode::Login) != sso.login.is_some() {
    return Err(fail(
      "只有 login 方式才能写代登录配置，login 方式必须有配置",
    ));
  }
  crate::oidc::validate(host, sso)?;
  if sso.public
    && (!matches!(sso.mode, SsoMode::Login | SsoMode::Oidc)
      || sso.trust_internal
      || !sso.skip_paths.is_empty())
  {
    return Err(fail(
      "公开站点只能用 login 或 oidc 方式，也不需要排除路径和组网内免登录",
    ));
  }
  let Some(login) = &sso.login else {
    return Ok(());
  };
  let account_ref = |name: &str| -> Result<bool, ApiError> {
    if name.starts_with("account.") && !login.use_account {
      return Err(
        fail("代登录模板引用了应用账号")
          .with_hint("在登录配置里加 use_account: true"),
      );
    }
    Ok(matches!(name, "account.username" | "account.password"))
  };
  if login.entry.as_deref().is_some_and(|e| {
    !e.starts_with('/')
      || e.starts_with("//")
      || e.starts_with("/_wharf/")
      || e.contains(['\\', '\r', '\n'])
  }) {
    return Err(fail("entry 要写成站内路径，例如 /admin/"));
  }
  if let Some(t) = &login.takeover {
    if t.paths.is_empty()
      || t.paths.iter().any(|p| {
        p.contains(['?', '#']) || takeover_path(p).as_ref() != Some(p)
      })
    {
      return Err(fail(
        "takeover.paths 至少填一条站内登录路径，例如 /login",
      ));
    }
    let entry = login.entry.as_deref().unwrap_or("/");
    if takeover_path(entry)
      .is_none_or(|path| takeover_matches(&path, &t.paths))
    {
      return Err(fail("代登录完成后的 entry 不能指向接管的登录页"));
    }
    if t.native_minutes == 0 {
      return Err(fail("takeover.native_minutes 须大于 0"));
    }
  }
  if login.script.is_some() != login.steps.is_empty() {
    return Err(fail("steps 和 script 必须二选一"));
  }
  if !(1..=720).contains(&login.ttl_hours) {
    return Err(fail("ttl_hours 须为 1 到 720"));
  }
  if let Some(script) = &login.script {
    tasks::validate_script(
      script.runtime,
      &script.code,
      &script.deps,
      script.image.as_deref(),
    )
    .map_err(|e| fail(&e.message))?;
    if !(5..=120).contains(&script.timeout_secs) {
      return Err(fail("脚本 timeout_secs 须为 5 到 120"));
    }
    for (key, value) in &script.env {
      if key.starts_with("WHARF_") {
        return Err(
          fail("脚本环境变量不能以 WHARF_ 开头")
            .with_hint("WHARF_ 开头的环境变量由 Wharf 注入"),
        );
      }
      if key.is_empty() || key.contains(['=', '\n', '\r', '\0']) {
        return Err(fail("脚本环境变量名无效"));
      }
      if value.contains(['\n', '\r', '\0']) {
        return Err(fail("脚本环境变量的值含换行或空字符"));
      }
      env_refs(value).map_err(|e| fail(&e.message))?;
    }
  } else if login.steps.len() > 5
    || !(1..=8).contains(&login.write.len())
  {
    return Err(fail("登录步骤须为 1 到 5 步，写入须为 1 到 8 项"));
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
          && !account_ref(name)?
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
          && !account_ref(name)?
        {
          return Err(fail(&format!("写入用了未取过的值 {name}")));
        }
      }
    }
  }
  Ok(())
}

// 名字 -> (值, 原始 Set-Cookie)。不解释应用自己的 cookie 属性。
fn jar_update(jar: &mut CookieJar, headers: &[(String, String)]) {
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
fn extract(
  rule: &Extract,
  headers: &[(String, String)],
  body: &str,
  jar: &CookieJar,
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
  jar: &CookieJar,
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

pub fn cookie_header(
  name: &str,
  value: &str,
  http_only: bool,
) -> Result<String, ApiError> {
  if name.is_empty()
    || !name.bytes().all(|b| {
      b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    })
    || !value.bytes().all(|b| {
      matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
    })
  {
    return Err(ApiError::invalid("应用 cookie 格式不对"));
  }
  Ok(format!(
    "{name}={value}; Path=/; Secure{}",
    if http_only { "; HttpOnly" } else { "" }
  ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptResult {
  #[serde(default)]
  cookies: Vec<ScriptCookie>,
  #[serde(default)]
  local_storage: Values,
  #[serde(default)]
  session_storage: Values,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptCookie {
  name: String,
  value: String,
  #[serde(default = "default_http_only")]
  http_only: bool,
}

fn default_http_only() -> bool {
  true
}

type Storage = Vec<(bool, String, String)>;

fn parse_script_result(
  value: serde_json::Value,
) -> Result<(CookieJar, Storage), ApiError> {
  let result: ScriptResult = serde_json::from_value(value)
    .map_err(|_| ApiError::invalid("result.json 格式不对"))?;
  if result.cookies.is_empty()
    && result.local_storage.is_empty()
    && result.session_storage.is_empty()
  {
    return Err(ApiError::invalid(
      "result.json 没有要写入浏览器的内容",
    ));
  }
  if result.cookies.len() > 16
    || result.cookies.iter().any(|c| c.value.len() > 4096)
  {
    return Err(ApiError::invalid(
      "cookie 最多 16 个，单个值最多 4KB",
    ));
  }
  let bytes: usize = result
    .cookies
    .iter()
    .map(|c| c.name.len() + c.value.len())
    .chain(
      result
        .local_storage
        .iter()
        .chain(&result.session_storage)
        .map(|(k, v)| k.len() + v.len()),
    )
    .sum();
  if bytes > 32 * 1024 {
    return Err(ApiError::invalid("浏览器写入内容不能超过 32KB"));
  }
  let cookies = result
    .cookies
    .into_iter()
    .map(|cookie| {
      let header =
        cookie_header(&cookie.name, &cookie.value, cookie.http_only)?;
      Ok((cookie.name, (cookie.value, header)))
    })
    .collect::<Result<_, ApiError>>()?;
  let storage = result
    .local_storage
    .into_iter()
    .map(|(key, value)| (true, key, value))
    .chain(
      result
        .session_storage
        .into_iter()
        .map(|(key, value)| (false, key, value)),
    )
    .collect();
  Ok((cookies, storage))
}

pub fn missing_account(hostname: &str) -> ApiError {
  ApiError::invalid(format!(
    "域名 {hostname} 没有默认应用账号，代登录会失败"
  ))
  .with_hint(format!(
    "wharf sso account link <名称> {hostname} --default"
  ))
}

fn account_vars(
  snap: &snapshot::Snapshot,
  hostname: &str,
  use_account: bool,
) -> Result<Values, ApiError> {
  if !use_account {
    return Ok(Values::new());
  }
  let account = snap
    .app_account_defaults
    .get(hostname)
    .ok_or_else(|| missing_account(hostname))?;
  ["username", "password"]
    .into_iter()
    .map(|field| {
      let value = snap
        .service_values
        .get(&format!("account.{account}.{field}"))
        .ok_or_else(|| missing_account(hostname))?;
      Ok((format!("account.{field}"), value.clone()))
    })
    .collect()
}

fn script_env(
  script: &LoginScript,
  secrets: &Values,
  vars: &Values,
  hostname: &str,
  upstream: &str,
) -> Result<Values, ApiError> {
  let mut env: Values = script
    .env
    .iter()
    .map(|(key, value)| {
      Ok((key.clone(), config::substitute(value, Some(secrets))?))
    })
    .collect::<Result<_, ApiError>>()?;
  env.insert("WHARF_UPSTREAM".into(), format!("http://{upstream}"));
  env.insert("WHARF_HOST".into(), hostname.into());
  for (field, key) in [
    ("account.username", "WHARF_USERNAME"),
    ("account.password", "WHARF_PASSWORD"),
  ] {
    if let Some(value) = vars.get(field) {
      env.insert(key.into(), value.clone());
    }
  }
  Ok(env)
}

async fn run_script(
  state: &Arc<AppState>,
  server: &str,
  job: TaskRunJob,
  cancel: &CancellationToken,
) -> Result<TaskRunResult, ApiError> {
  let wait_for_deps = job.wait_for_deps;
  let (state, server, cancel) =
    (state.clone(), server.to_string(), cancel.clone());
  // 请求被浏览器丢弃时，仍要让 hub 读到取消信号并通知 agent。
  tokio::spawn(async move {
    state
      .hub
      .call(
        &server,
        AgentOp::TaskRun(job),
        if wait_for_deps {
          TEST_TIMEOUT
        } else {
          TOTAL_TIMEOUT
        },
        None,
        &cancel,
      )
      .await
  })
  .await
  .map_err(|_| ApiError::internal("代登录请求中断"))?
}

async fn execute(
  state: &Arc<AppState>,
  hostname: &str,
  wait_for_deps: bool,
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
  let _guard = if wait_for_deps {
    tokio::time::timeout(TEST_TIMEOUT, lock.lock())
      .await
      .map_err(|_| {
        ApiError::new(ErrorCode::Timeout, "等待上次代登录超时")
      })?
  } else {
    lock.try_lock().map_err(|_| {
      ApiError::new(ErrorCode::Conflict, "已有代登录在运行，稍后重试")
    })?
  };
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
  let vars = account_vars(&snap, hostname, login.use_account)?;
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
    return Err(
      ApiError::invalid(format!(
        "服务器 {server} 的 agent 版本太旧，升级后才能代登录"
      ))
      .with_hint("先运行 wharf upgrade"),
    );
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
  let mut deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
  let mut outcome = Outcome {
    ok: true,
    steps: vec![],
    check: None,
    set_cookies: vec![],
    vars,
    script_storage: vec![],
    script_log: None,
  };
  let mut jar = BTreeMap::new();
  let mut hidden: Vec<String> = snap
    .secrets
    .values()
    .chain(outcome.vars.values())
    .cloned()
    .collect();
  if let Some(script) = &login.script {
    let env = script_env(
      script,
      &snap.secrets,
      &outcome.vars,
      hostname,
      upstream,
    )?;
    let server_row = &snap.world.servers[server];
    let job = TaskRunJob {
      name: config::hash(hostname)[..32].to_string(),
      how: TaskHow::Script {
        image: script.image.clone().unwrap_or_else(|| {
          tasks::script_image(script.runtime).into()
        }),
        runtime: script.runtime,
        code: script.code.clone(),
        deps: script.deps.clone(),
        mirrors: server_row.settings.build_env.clone(),
        env,
      },
      input: None,
      network_host: true,
      out_dir: true,
      wait_for_deps,
      timeout_secs: script.timeout_secs,
      pull: snapshot::pull_policy(server_row),
    };
    let result = run_script(state, server, job, &cancel)
      .await
      .map_err(|mut e| {
        e.message = mask(&e.message, &hidden);
        e.hint = e.hint.map(|hint| mask(&hint, &hidden));
        e.suggest
          .iter_mut()
          .for_each(|command| *command = mask(command, &hidden));
        e
      })?;
    if wait_for_deps {
      deadline = tokio::time::Instant::now()
        + TOTAL_TIMEOUT
          .saturating_sub(Duration::from_millis(result.duration_ms));
    }
    let json = result
      .result
      .as_deref()
      .filter(|text| text.len() <= 64 * 1024)
      .and_then(|text| {
        serde_json::from_str::<serde_json::Value>(text).ok()
      });
    if let Some(json) = &json {
      hidden.extend(strings(json).into_iter().map(str::to_string));
    }
    outcome.script_log = Some(mask(&result.output, &hidden));
    let writes = if result.timed_out {
      Err(ApiError::invalid("代登录脚本超时"))
    } else if result.exit_code != Some(0) {
      Err(ApiError::invalid("代登录脚本退出失败"))
    } else {
      json
        .ok_or_else(|| ApiError::invalid("result.json 缺失或无效"))
        .and_then(parse_script_result)
    };
    outcome.ok = writes.is_ok();
    let error = match writes {
      Ok((cookies, storage)) => {
        outcome.set_cookies =
          cookies.values().map(|(_, raw)| raw.clone()).collect();
        jar = cookies;
        outcome.script_storage = storage;
        None
      }
      Err(e) => Some(e.message),
    };
    outcome.steps.push(SsoStepResult {
      number: 1,
      method: "SCRIPT".into(),
      path: "WHARF_OUT".into(),
      status: None,
      ms: result.duration_ms,
      extracted: BTreeMap::new(),
      error,
    });
    if !outcome.ok {
      return Ok(outcome);
    }
  }
  let script_steps = outcome.steps.len();
  for (i, step) in
    login.steps.iter().chain(login.check.iter()).enumerate()
  {
    let start = Instant::now();
    let is_check = i == login.steps.len();
    let mut summary = SsoStepResult {
      number: i + 1 + script_steps,
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
  if outcome.script_log.is_none() {
    outcome.set_cookies =
      jar.into_values().map(|(_, raw)| raw).collect();
  }
  Ok(outcome)
}

pub async fn cleanup(state: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let mut wanted: BTreeMap<
    &str,
    (BTreeSet<String>, BTreeSet<String>),
  > = BTreeMap::new();
  for (host, route) in &snap.world.routes {
    let Some(script) = route
      .spec
      .sso
      .as_ref()
      .and_then(|sso| sso.login.as_ref())
      .and_then(|login| login.script.as_ref())
    else {
      continue;
    };
    let image = script
      .image
      .as_deref()
      .unwrap_or_else(|| tasks::script_image(script.runtime));
    let Some(gateway) = snap.world.route_gateway(&route.spec) else {
      continue;
    };
    let Some(gateway) = snap.world.gateways.get(gateway) else {
      continue;
    };
    let (domains, runners) =
      wanted.entry(&gateway.spec.server).or_default();
    domains.insert(config::hash(host)[..32].into());
    runners.insert(sso_runner_name(script.runtime, image));
  }
  let cancel = CancellationToken::new();
  for server in snap.world.servers.keys() {
    if !state.hub.is_online(server)
      || crate::agent_upgrade::outdated(
        snap
          .agent(server)
          .and_then(|a| a.report.as_ref())
          .map(|r| r.build.as_str()),
      )
    {
      continue;
    }
    let (domains, runners) =
      wanted.remove(server.as_str()).unwrap_or_default();
    let result = state
      .hub
      .call::<serde_json::Value>(
        server,
        AgentOp::SsoCleanup {
          domains: domains.into_iter().collect(),
          runners: runners.into_iter().collect(),
        },
        Duration::from_secs(60),
        None,
        &cancel,
      )
      .await;
    if let Err(e) = result {
      tracing::warn!("清理服务器 {server} 上的代登录容器失败：{e}");
    }
  }
  Ok(())
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
  state: &Arc<AppState>,
  hostname: &str,
) -> Result<Outcome, ApiError> {
  run_with_deps(state, hostname, false).await
}

async fn run_with_deps(
  state: &Arc<AppState>,
  hostname: &str,
  wait_for_deps: bool,
) -> Result<Outcome, ApiError> {
  let outcome = execute(state, hostname, wait_for_deps).await;
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
  let outcome = tokio::time::timeout(
    TEST_TIMEOUT,
    run_with_deps(&state, &hostname, true),
  )
  .await
  .map_err(|_| {
    ApiError::new(ErrorCode::Timeout, "代登录测试超时")
  })??;
  let mut would_write = Vec::new();
  if outcome.ok {
    let snap = snapshot::load(&state.db).await?;
    let hidden: Vec<_> = snap
      .secrets
      .values()
      .chain(outcome.vars.values())
      .cloned()
      .collect();
    if outcome.script_log.is_some() {
      for raw in &outcome.set_cookies {
        if let Some((name, value)) =
          raw.split(';').next().and_then(|s| s.split_once('='))
        {
          would_write.push(format!(
            "cookie {}（{} 个字符）",
            mask(name, &hidden),
            value.chars().count()
          ));
        }
      }
      for (local, key, value) in &outcome.script_storage {
        let storage = if *local {
          "localStorage"
        } else {
          "sessionStorage"
        };
        would_write.push(format!(
          "{storage} {}（{} 个字符）",
          mask(key, &hidden),
          value.chars().count()
        ));
      }
    } else {
      let login = snap
        .world
        .routes
        .get(&hostname)
        .and_then(|r| r.spec.sso.as_ref())
        .and_then(|s| s.login.as_ref())
        .ok_or_else(|| ApiError::invalid("代登录配置已改变"))?;
      for write in &login.write {
        let summary = match write {
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
        };
        would_write.push(mask(&summary, &hidden));
      }
    }
  }
  Ok(Json(SsoTestResult {
    ok: outcome.ok,
    steps: outcome.steps,
    check: outcome.check,
    would_write,
    script_log: outcome.script_log,
  }))
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn script_env_includes_default_account() {
    let hostname = "app.example.com";
    let snap = snapshot::Snapshot {
      app_account_defaults: BTreeMap::from([(
        hostname.into(),
        "x".into(),
      )]),
      service_values: BTreeMap::from([
        ("account.x.username".into(), "fixture-user".into()),
        ("account.x.password".into(), "fixture-value".into()),
      ]),
      ..Default::default()
    };
    let script = serde_json::from_value(
      json!({ "runtime": "shell", "code": "true" }),
    )
    .unwrap();
    let vars = account_vars(&snap, hostname, true).unwrap();
    let env = script_env(
      &script,
      &snap.secrets,
      &vars,
      hostname,
      "127.0.0.1:80",
    )
    .unwrap();
    assert_eq!(env["WHARF_USERNAME"], "fixture-user");
    assert_eq!(env["WHARF_PASSWORD"], "fixture-value");
  }

  #[test]
  fn login_chooses_steps_or_script() {
    let steps = json!([{"path": "/login"}]);
    let script = json!({"runtime": "shell", "code": "exit 0"});
    let check = |login| {
      let sso = serde_json::from_value(json!({
        "mode": "login", "login": login
      }))
      .unwrap();
      validate("a.example.test", &sso)
    };
    assert!(
      check(json!({"steps": steps, "write": [{"cookies": "all"}]}))
        .is_ok()
    );
    assert!(check(json!({"script": script})).is_ok());
    assert!(
      check(json!({"steps": steps, "script": script})).is_err()
    );
    assert!(check(json!({})).is_err());
  }

  #[test]
  fn takeover_validates_paths_and_return_address() {
    let spec = |path| {
      serde_json::from_value::<SsoSpec>(json!({
        "mode": "login",
        "public": true,
        "login": {
          "script": {"runtime": "shell", "code": "true"},
          "entry": "/console",
          "takeover": {"paths": [path], "rd_param": "redirect_uri"}
        }
      }))
      .unwrap()
    };
    for bad in [
      "login",
      "//outside.example.test",
      "/_wharf/login",
      "/a/../_wharf/login",
    ] {
      assert!(validate("a.example.test", &spec(bad)).is_err());
    }
    let sso = spec("/login");
    assert!(validate("a.example.test", &sso).is_ok());
    let login = sso.login.as_ref().unwrap();
    for bad in [
      "https://outside.example.test/",
      "//outside.example.test/",
      "/\\outside.example.test/",
      "/login/",
    ] {
      assert_eq!(takeover_rd(login, Some(bad)), "/console");
    }
    assert_eq!(
      takeover_rd(login, Some("/details?q=1")),
      "/details?q=1"
    );
  }

  #[test]
  fn valid_script_result() {
    let (cookies, storage) = parse_script_result(json!({
      "cookies": [{"name": "session", "value": "abc"}],
      "local_storage": {"color": "green"},
      "session_storage": {"tab": "one"},
    }))
    .unwrap();
    assert_eq!(
      cookies["session"].1,
      "session=abc; Path=/; Secure; HttpOnly"
    );
    assert_eq!(
      storage,
      vec![
        (true, "color".into(), "green".into()),
        (false, "tab".into(), "one".into())
      ]
    );
  }

  #[test]
  fn invalid_script_result() {
    assert!(
      parse_script_result(json!({
        "cookies": [{"name": "session", "value": "invalid; Path=/"}],
      }))
      .is_err()
    );
  }

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
  fn public_only_with_login() {
    let sso = |mode: &str, entry: &str| -> SsoSpec {
      serde_json::from_value(serde_json::json!({"mode":mode,"public":true,"login":(mode=="login").then(||serde_json::json!({"steps":[{"path":"/login"}],"write":[{"cookies":"all"}],"entry":entry}))})).unwrap()
    };
    validate("a.example.test", &sso("login", "/admin/")).unwrap();
    assert!(validate("a.example.test", &sso("gate", "/")).is_err());
    assert!(
      validate("a.example.test", &sso("login", "//evil")).is_err()
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
