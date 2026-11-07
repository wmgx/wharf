//! 记下 CLI 的构建号：CI 传了 `WHARF_BUILD` 就用它，本地构建用 git 短提交号。
//! 连控制面时和它的构建号比对，不一致就提醒更新（旧 CLI 会吞掉新字段）。

fn main() {
  println!("cargo:rerun-if-env-changed=WHARF_BUILD");
  println!("cargo:rerun-if-changed=../../.git/HEAD");
  println!("cargo:rerun-if-changed=../../.git/refs/heads");
  let build = std::env::var("WHARF_BUILD").ok().or_else(|| {
    let out = std::process::Command::new("git")
      .args(["rev-parse", "--short=7", "HEAD"])
      .output()
      .ok()?;
    out.status.success().then(|| {
      String::from_utf8_lossy(&out.stdout).trim().to_string()
    })
  });
  println!(
    "cargo:rustc-env=WHARF_CLI_BUILD={}",
    build.unwrap_or_else(|| "dev".into())
  );
}
