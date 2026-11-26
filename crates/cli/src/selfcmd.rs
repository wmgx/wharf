//! CLI 自己：`whoami`、`self-update`、`commands --changes`。

use std::{path::PathBuf, time::Duration};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  client::{CliResult, Client},
  commands::out,
  view::cache_dir,
};

const MINE: &str = env!("WHARF_CLI_BUILD");
/// 控制面太旧、`/api/version` 里没有下载前缀时用。
const DEFAULT_RELEASES: &str =
  "https://github.com/wmgx/wharf/releases/download";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const SKILL_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn whoami(c: &Client, j: bool) -> CliResult<()> {
  let me: Value = c.get("/api/whoami").await?;
  let mut v = json!({
    "name": me["name"],
    "human": me["human"],
    "perms": me["perms"],
    "url": c.base(),
    "cli_build": MINE,
    "core_build": me["build"],
    "core_version": me["version"],
  });
  for key in ["expires_at", "allowed_from", "services"] {
    if let Some(value) = me.get(key) {
      v[key] = value.clone();
    }
  }
  out(j, &v, |v| {
    let perms: Vec<&str> = v["perms"]
      .as_array()
      .map(|a| a.iter().filter_map(Value::as_str).collect())
      .unwrap_or_default();
    println!(
      "{}（{}）",
      v["name"].as_str().unwrap_or("-"),
      if v["human"] == true {
        "页面登录"
      } else {
        "token"
      }
    );
    println!("权限：{}", perms.join("、"));
    if let Some(time) = v["expires_at"]
      .as_str()
      .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    {
      println!(
        "有效期：{}",
        time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M")
      );
    }
    for (key, label) in
      [("allowed_from", "来源"), ("services", "服务")]
    {
      let values = v[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
      if !values.is_empty() {
        println!("{label}：{}", values.join("、"));
      }
    }
    println!(
      "控制面：{}  构建 {}",
      c.base(),
      v["core_build"].as_str().unwrap_or("-")
    );
    println!("本机 CLI：构建 {MINE}");
  });
  Ok(())
}

fn platform() -> CliResult<(&'static str, &'static str)> {
  let os = match std::env::consts::OS {
    "macos" => "macos",
    "linux" => "linux",
    other => {
      return Err(
        ApiError::invalid(format!("不支持的系统：{other}")).into(),
      );
    }
  };
  let arch = match std::env::consts::ARCH {
    "x86_64" => "amd64",
    "aarch64" => "arm64",
    other => {
      return Err(
        ApiError::invalid(format!("不支持的架构：{other}")).into(),
      );
    }
  };
  Ok((os, arch))
}

/// 下载来的是不是可执行文件：ELF 或 Mach-O 开头。防止把出错页面装成 wharf。
fn executable(bytes: &[u8]) -> bool {
  const MAGICS: [&[u8]; 4] = [
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xfe\xed\xfa\xcf",
  ];
  MAGICS.iter().any(|m| bytes.starts_with(m))
}

async fn fetch_binary(url: &str) -> CliResult<Vec<u8>> {
  let failed = |reason: String| -> crate::client::CliError {
    ApiError::new(
      ErrorCode::Internal,
      format!("下载 {url} 失败：{reason}"),
    )
    .with_hint("这个构建的 CLI 可能还在 CI 里打包，过几分钟再试")
    .into()
  };
  let http = reqwest::Client::builder()
    .connect_timeout(Duration::from_secs(15))
    .timeout(DOWNLOAD_TIMEOUT)
    .build()
    .map_err(|e| failed(e.to_string()))?;
  let resp = http
    .get(url)
    .send()
    .await
    .map_err(|e| failed(e.without_url().to_string()))?;
  if !resp.status().is_success() {
    return Err(failed(format!("HTTP {}", resp.status().as_u16())));
  }
  let bytes = resp
    .bytes()
    .await
    .map_err(|e| failed(e.without_url().to_string()))?;
  if !executable(&bytes) {
    return Err(failed("下载到的不是可执行文件".into()));
  }
  Ok(bytes.to_vec())
}

/// 写到同目录的临时文件再改名，换到一半出错也不会留下坏的 wharf。
fn replace_exe(bytes: &[u8]) -> CliResult<PathBuf> {
  use std::os::unix::fs::PermissionsExt;
  let io =
    |what: &str, e: std::io::Error| -> crate::client::CliError {
      ApiError::internal(format!("{what}：{e}"))
        .with_hint("没有写权限时用 cli.sh 重新安装到自己的目录")
        .into()
    };
  let exe = std::env::current_exe()
    .and_then(|p| p.canonicalize())
    .map_err(|e| io("找不到本机 wharf 的位置", e))?;
  let dir = exe.parent().unwrap_or(std::path::Path::new("."));
  let tmp = dir.join(format!(".wharf.new.{}", std::process::id()));
  let result = std::fs::write(&tmp, bytes)
    .and_then(|()| {
      std::fs::set_permissions(
        &tmp,
        std::fs::Permissions::from_mode(0o755),
      )
    })
    .and_then(|()| std::fs::rename(&tmp, &exe));
  if let Err(e) = result {
    let _ = std::fs::remove_file(&tmp);
    return Err(io(&format!("替换 {} 失败", exe.display()), e));
  }
  Ok(exe)
}

/// 装过 Skill（`~/.agents/skills/wharf/SKILL.md`）才更新，没装不新装。
async fn update_skill(c: &Client) -> Option<String> {
  let path = PathBuf::from(std::env::var_os("HOME")?)
    .join(".agents/skills/wharf/SKILL.md");
  if !path.exists() {
    return None;
  }
  let mut text = Vec::new();
  let fetched = c
    .download("/skill.md", SKILL_TIMEOUT, |b| {
      text.extend_from_slice(b);
      Ok(())
    })
    .await;
  let tmp = path.with_extension("md.tmp");
  let saved = fetched.is_ok()
    && std::fs::write(&tmp, &text).is_ok()
    && std::fs::rename(&tmp, &path).is_ok();
  if !saved {
    let _ = std::fs::remove_file(&tmp);
    eprintln!("Skill 没更新成功，下次再试");
    return None;
  }
  Some(path.display().to_string())
}

/// 用新装的 wharf 比较命令变化，最多等 30 秒。
async fn new_changes(exe: &PathBuf) -> Value {
  let run = tokio::process::Command::new(exe)
    .args(["--json", "commands", "--changes"])
    .kill_on_drop(true)
    .output();
  match tokio::time::timeout(Duration::from_secs(30), run).await {
    Ok(Ok(o)) if o.status.success() => {
      serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
    }
    _ => Value::Null,
  }
}

pub async fn self_update(c: &Client, j: bool) -> CliResult<()> {
  let v: Value = c.get("/api/version").await?;
  let target = v["build"].as_str().unwrap_or_default().to_string();
  if target.is_empty() || target == "dev" {
    return Err(
      ApiError::invalid(
        "控制面是本地构建（dev），没有对应的 CLI 发布",
      )
      .with_hint("在仓库里 cargo install --path crates/cli")
      .into(),
    );
  }
  if target == MINE {
    let skill = update_skill(c).await;
    out(
      j,
      &json!({"updated": false, "build": MINE, "skill": skill}),
      |_| println!("本机 wharf 已经是构建 {MINE}，和控制面一致"),
    );
    return Ok(());
  }
  // 先记下旧版本的命令，新版本装好后据此列出变化。
  save_snapshot(&crate::describe::commands(&[]));
  let releases =
    v["cli_releases"].as_str().unwrap_or(DEFAULT_RELEASES);
  let (os, arch) = platform()?;
  let expected = required_sha256(&v, &target, os, arch)?;
  let url = format!("{releases}/build-{target}/wharf-{os}-{arch}");
  if !j {
    println!("下载 wharf 构建 {target}（{os}-{arch}）");
  }
  let bytes = fetch_binary(&url).await?;
  verify_sha256(&bytes, expected)?;
  let exe = replace_exe(&bytes)?;
  let skill = update_skill(c).await;
  let changes = new_changes(&exe).await;
  let result = json!({
    "updated": true,
    "from": MINE,
    "build": target,
    "path": exe.display().to_string(),
    "skill": skill,
    "changes": changes,
  });
  out(j, &result, |r| {
    println!("已换成构建 {target}：{}", exe.display());
    if let Some(s) = r["skill"].as_str() {
      println!("已更新 Skill：{s}");
    }
    print_changes(&r["changes"]);
  });
  Ok(())
}

// 命令变化

fn snapshot_dir() -> PathBuf {
  cache_dir().join("commands")
}

/// 存一份这个构建的命令清单。dev 构建每次都可能不一样，不存。
pub fn save_snapshot(commands: &Value) {
  let build = commands["build"].as_str().unwrap_or("dev");
  if build == "dev" {
    return;
  }
  let dir = snapshot_dir();
  let _ = std::fs::create_dir_all(&dir);
  let _ = std::fs::write(
    dir.join(format!("{build}.json")),
    commands.to_string(),
  );
}

/// 本机最近用过的另一个构建的命令清单。
fn previous_snapshot(current: &str) -> Option<Value> {
  let mut files: Vec<(std::time::SystemTime, PathBuf)> =
    std::fs::read_dir(snapshot_dir())
      .ok()?
      .filter_map(Result::ok)
      .map(|e| e.path())
      .filter(|p| {
        p.extension().is_some_and(|x| x == "json")
          && p.file_stem().is_some_and(|s| s != current)
      })
      .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p)))
      .collect();
  files.sort();
  let (_, path) = files.pop()?;
  serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn by_name<'a>(
  v: &'a Value,
  key: &str,
  field: &str,
) -> Vec<(&'a str, &'a Value)> {
  v[key]
    .as_array()
    .map(|a| {
      a.iter()
        .filter_map(|c| Some((c[field].as_str()?, c)))
        .collect()
    })
    .unwrap_or_default()
}

fn find<'a>(
  list: &[(&str, &'a Value)],
  name: &str,
) -> Option<&'a Value> {
  list.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// 两份命令清单的差异：新增、删除的命令，以及参数或说明变了的命令。
pub fn changes(old: &Value, new: &Value) -> Value {
  let old_cmds = by_name(old, "commands", "command");
  let new_cmds = by_name(new, "commands", "command");
  let added: Vec<&str> = new_cmds
    .iter()
    .filter(|(n, _)| find(&old_cmds, n).is_none())
    .map(|(n, _)| *n)
    .collect();
  let removed: Vec<&str> = old_cmds
    .iter()
    .filter(|(n, _)| find(&new_cmds, n).is_none())
    .map(|(n, _)| *n)
    .collect();
  let mut changed = Vec::new();
  for (name, nv) in &new_cmds {
    let Some(ov) = find(&old_cmds, name) else {
      continue;
    };
    if ov == *nv {
      continue;
    }
    let oa = by_name(ov, "args", "arg");
    let na = by_name(nv, "args", "arg");
    let args_added: Vec<&str> = na
      .iter()
      .filter(|(a, _)| find(&oa, a).is_none())
      .map(|(a, _)| *a)
      .collect();
    let args_removed: Vec<&str> = oa
      .iter()
      .filter(|(a, _)| find(&na, a).is_none())
      .map(|(a, _)| *a)
      .collect();
    let args_changed: Vec<&str> = na
      .iter()
      .filter(|(a, v)| find(&oa, a).is_some_and(|o| o != *v))
      .map(|(a, _)| *a)
      .collect();
    changed.push(json!({
      "command": name,
      "about_changed": ov["about"] != nv["about"] || ov["details"] != nv["details"],
      "args_added": args_added,
      "args_removed": args_removed,
      "args_changed": args_changed,
    }));
  }
  json!({
    "from": old["build"],
    "to": new["build"],
    "added": added,
    "removed": removed,
    "changed": changed,
  })
}

/// `wharf commands --changes`。
pub fn command_changes(j: bool) -> CliResult<()> {
  let now = crate::describe::commands(&[]);
  let v = match previous_snapshot(MINE) {
    Some(old) => changes(&old, &now),
    None => json!({
      "from": null,
      "to": MINE,
      "note": "本机没有旧版本的命令记录：用 wharf self-update 升级时会自动记下",
    }),
  };
  save_snapshot(&now);
  out(j, &v, print_changes);
  Ok(())
}

fn print_changes(v: &Value) {
  if v.is_null() {
    return;
  }
  if let Some(note) = v["note"].as_str() {
    println!("{note}");
    return;
  }
  let list = |k: &str| -> Vec<String> {
    v[k]
      .as_array()
      .map(|a| {
        a.iter()
          .map(|x| x.as_str().unwrap_or_default().to_string())
          .collect()
      })
      .unwrap_or_default()
  };
  let (added, removed) = (list("added"), list("removed"));
  let changed = v["changed"].as_array().cloned().unwrap_or_default();
  println!(
    "命令变化（构建 {} → {}）：",
    v["from"].as_str().unwrap_or("-"),
    v["to"].as_str().unwrap_or("-")
  );
  if added.is_empty() && removed.is_empty() && changed.is_empty() {
    println!("  没有变化");
  }
  for c in &added {
    println!("  + {c}");
  }
  for c in &removed {
    println!("  - {c}");
  }
  for c in &changed {
    let mut parts = Vec::new();
    let names = |k: &str| -> String {
      c[k]
        .as_array()
        .map(|a| {
          a.iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ")
        })
        .unwrap_or_default()
    };
    for (k, label) in [
      ("args_added", "新参数"),
      ("args_removed", "去掉"),
      ("args_changed", "改了"),
    ] {
      let n = names(k);
      if !n.is_empty() {
        parts.push(format!("{label} {n}"));
      }
    }
    if c["about_changed"] == true {
      parts.push("说明改了".into());
    }
    println!(
      "  ~ {}：{}",
      c["command"].as_str().unwrap_or_default(),
      parts.join("；")
    );
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  #[test]
  fn lists_command_changes() {
    let old = json!({"build": "a", "commands": [
      {"command": "wharf x", "args": [{"arg": "--a"}]},
      {"command": "wharf gone"},
    ]});
    let new = json!({"build": "b", "commands": [
      {"command": "wharf x", "args": [{"arg": "--a", "help": "改"}, {"arg": "--b"}]},
      {"command": "wharf new"},
    ]});
    let v = super::changes(&old, &new);
    assert_eq!(v["added"], json!(["wharf new"]));
    assert_eq!(v["removed"], json!(["wharf gone"]));
    assert_eq!(v["changed"][0]["args_added"], json!(["--b"]));
    assert_eq!(v["changed"][0]["args_changed"], json!(["--a"]));
  }

  #[test]
  fn rejects_non_executable() {
    assert!(super::executable(b"\x7fELF\x02\x01"));
    assert!(!super::executable(b"<html>Not Found"));
  }
}

fn required_sha256<'a>(
  version: &'a Value,
  target: &str,
  os: &str,
  arch: &str,
) -> CliResult<&'a str> {
  version["cli_sha256"][format!("{os}-{arch}")].as_str()
    .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .ok_or_else(|| ApiError::invalid(format!("控制面没有提供构建 {target}（{os}-{arch}）的 SHA-256 校验和，已取消自动更新"))
      .with_hint("先升级控制面到支持校验和的版本，或从 GitHub Releases 手动下载并核对 SHA256SUMS").into())
}

fn verify_sha256(bytes: &[u8], expected: &str) -> CliResult<()> {
  let actual = hex::encode(Sha256::digest(bytes));
  if actual != expected {
    return Err(ApiError::internal(format!("下载到的 wharf 校验和不匹配（期望 {expected}，实际 {actual}），已拒绝替换"))
      .with_hint("下载文件可能损坏或镜像源被篡改；检查 WHARF_CLI_RELEASES 后重试").into());
  }
  Ok(())
}

#[test]
fn update_requires_hash_and_rejects_tampered_executable() {
  assert!(
    required_sha256(&json!({}), "fixture", "linux", "amd64").is_err()
  );
  let original = b"\x7fELFfixture";
  let changed = b"\x7fELFfixturE";
  let hash = hex::encode(Sha256::digest(original));
  assert!(executable(changed));
  assert!(verify_sha256(original, &hash).is_ok());
  assert!(verify_sha256(changed, &hash).is_err());
}
