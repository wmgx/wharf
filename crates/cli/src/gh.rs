//! GitHub 私有仓库：借本机 gh 的登录，把 token 存成 Wharf 密钥，服务器拉代码时用。

use std::{process::Stdio, time::Duration};

use serde_json::json;
use wharf_api_types::view::SecretView;

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

/// 没指定 token 密钥的 git 来源：是 GitHub 私有仓库且本机 gh 已登录时，
/// 把 gh 的 token 存进 [`SECRET`] 并返回密钥名。
pub async fn private_token(
  c: &Client,
  repo: &str,
) -> CliResult<Option<String>> {
  let Some(slug) = github_repo(repo) else {
    return Ok(None);
  };
  let private =
    gh(&["api", &format!("repos/{slug}"), "--jq", ".private"]).await;
  if private.as_deref() != Some("true") {
    return Ok(None);
  }
  Ok(refresh(c).await?.then(|| SECRET.to_string()))
}

/// 用本机 gh 的 token 更新 [`SECRET`]；gh 不可用时返回 `false`，不改密钥。
pub async fn refresh(c: &Client) -> CliResult<bool> {
  let Some(token) =
    gh(&["auth", "token", "--hostname", "github.com"]).await
  else {
    return Ok(false);
  };
  let _: SecretView = c
    .put(
      &format!("/api/secrets/{}", seg(SECRET)),
      &json!({ "value": token }),
    )
    .await?;
  eprintln!("已用本机 gh 的登录更新密钥 {SECRET}");
  Ok(true)
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
