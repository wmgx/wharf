//! GitHub 私有仓库：借本机 gh 的登录，把 token 存成 Wharf 密钥，服务器拉代码时用。

use std::{process::Stdio, time::Duration};

use serde_json::json;
use wharf_api_types::{ApiError, view::SecretView};

use crate::client::{CliResult, Client, seg};

/// 保存 gh token 的密钥名。
pub const SECRET: &str = "GITHUB_TOKEN";

/// `https://github.com/owner/repo(.git)` → `owner/repo`，不是 GitHub 返回 `None`。
fn github_repo(url: &str) -> Option<String> {
  let rest = url.strip_prefix("https://github.com/")?;
  let rest = rest.trim_end_matches('/');
  let rest = rest.strip_suffix(".git").unwrap_or(rest);
  let (owner, repo) = rest.split_once('/')?;
  (!owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
    .then(|| format!("{owner}/{repo}"))
}

/// 执行 gh，15 秒超时。没装、没登录、失败都返回 `None`。
async fn gh(args: &[&str]) -> Option<String> {
  let child = tokio::process::Command::new("gh")
    .args(args)
    .stdin(Stdio::null())
    .stderr(Stdio::null())
    .kill_on_drop(true)
    .output();
  let out = tokio::time::timeout(Duration::from_secs(15), child)
    .await
    .ok()?
    .ok()?;
  let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
  (out.status.success() && !text.is_empty()).then_some(text)
}

/// 没指定密钥的 GitHub 来源沿用已有密钥，首次同步需要显式选择。
pub async fn private_token(
  c: &Client,
  repo: &str,
  sync: bool,
) -> CliResult<Option<String>> {
  let Some(slug) = github_repo(repo) else {
    if sync {
      return Err(
        ApiError::invalid("--sync-gh-token 只适用于 GitHub 仓库")
          .into(),
      );
    }
    return Ok(None);
  };
  if sync {
    refresh(c).await?;
    return Ok(Some(SECRET.into()));
  }
  let existing: Vec<SecretView> = c.get("/api/secrets").await?;
  if existing.iter().any(|entry| entry.name == SECRET) {
    eprintln!(
      "沿用控制面已有密钥 {SECRET}（如需用本机 gh 覆盖，加 --sync-gh-token）"
    );
    return Ok(Some(SECRET.into()));
  }
  let private =
    gh(&["api", &format!("repos/{slug}"), "--jq", ".private"]).await;
  if private.as_deref() == Some("true") {
    return Err(ApiError::invalid(format!("仓库 {slug} 是 GitHub 私有仓库，但控制面还没有密钥 {SECRET}"))
      .with_hint("先用 wharf secret set GITHUB_TOKEN 保存最小只读权限 PAT，或加 --sync-gh-token 用本机 gh 登录同步").into());
  }
  Ok(None)
}

/// 由显式选择同步本机 gh 凭据。
pub async fn refresh(c: &Client) -> CliResult<()> {
  let token = gh(&["auth", "token", "--hostname", "github.com"])
    .await
    .ok_or_else(|| {
      ApiError::invalid("本机 gh 没有可用的 GitHub 登录")
        .with_hint("执行 gh auth login 后重试")
    })?;
  if token.starts_with("ghu_") {
    eprintln!(
      "本机 gh 返回的短效 OAuth token（ghu_）约 8 小时后过期，长期构建建议使用细粒度只读 PAT"
    );
  }
  let _: SecretView = c
    .put(
      &format!("/api/secrets/{}", seg(SECRET)),
      &json!({ "value": token }),
    )
    .await?;
  eprintln!("已用本机 gh 的登录更新密钥 {SECRET}");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::github_repo;

  #[test]
  fn parses_github_urls() {
    assert_eq!(
      github_repo("https://github.com/o/r.git").as_deref(),
      Some("o/r")
    );
    assert_eq!(
      github_repo("https://github.com/o/r/").as_deref(),
      Some("o/r")
    );
    assert_eq!(github_repo("https://gitlab.com/o/r"), None);
    assert_eq!(github_repo("https://github.com/o"), None);
  }
}

#[tokio::test]
async fn github_token_is_reused_without_writing() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let endpoint = format!("http://{}", listener.local_addr().unwrap());
  let server = tokio::spawn(async move {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
      request.push(socket.read_u8().await.unwrap());
    }
    assert!(request.starts_with(b"GET /api/secrets "));
    let body = r#"[{"name":"GITHUB_TOKEN","updated_at":"2026-11-26T00:00:00Z","used_by":[]}]"#;
    let response = format!(
      "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
      body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
  });
  let client = Client::test_endpoint(endpoint);
  assert_eq!(
    private_token(&client, "https://github.com/o/priv", false)
      .await
      .unwrap()
      .as_deref(),
    Some(SECRET)
  );
  server.await.unwrap();
}
