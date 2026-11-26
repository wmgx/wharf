//! CLI 分发：`curl -fsSL <控制面>/cli.sh | sh -s -- <控制面>`。
//! 二进制由 CI 按构建号发布到 GitHub Release `build-<构建号>`，安装的版本和控制面一致。
//! 在终端里运行时，装完直接 `wharf login`（从 /dev/tty 读 token，token 不进命令行）；
//! 顺手把 `/skill.md` 装到 `~/.agents/skills/wharf`，本机有 `~/.claude` 时软链到 `~/.claude/skills/wharf`。

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
  extract::{ConnectInfo, Request, State},
  http::{StatusCode, header},
  response::{IntoResponse, Response},
};

const SHA256SUMS_PATH: &str = "/usr/local/share/wharf/cli-sha256sums";
const PLATFORMS: [&str; 4] =
  ["linux-amd64", "linux-arm64", "macos-amd64", "macos-arm64"];

pub fn parse_sha256sums(text: &str) -> BTreeMap<String, String> {
  text
    .lines()
    .filter_map(|line| {
      let mut fields = line.split_ascii_whitespace();
      let hash = fields.next()?;
      let platform = fields
        .next()?
        .trim_start_matches('*')
        .strip_prefix("wharf-")?;
      (fields.next().is_none()
        && PLATFORMS.contains(&platform)
        && hash.len() == 64
        && hash
          .bytes()
          .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
      .then(|| (platform.to_string(), hash.to_string()))
    })
    .collect()
}

pub fn sha256_map() -> BTreeMap<String, String> {
  let path = std::env::var_os("WHARF_CLI_SHA256SUMS_FILE")
    .unwrap_or_else(|| SHA256SUMS_PATH.into());
  parse_sha256sums(&std::fs::read_to_string(path).unwrap_or_default())
}

/// 公开仓库的 Release 地址；可以用 `WHARF_CLI_RELEASES` 换成镜像。
const RELEASES: &str =
  "https://github.com/wmgx/wharf/releases/download";

/// CLI 二进制的下载地址前缀，`<前缀>/build-<构建号>/wharf-<系统>-<架构>`。
pub fn releases() -> String {
  std::env::var("WHARF_CLI_RELEASES")
    .unwrap_or_else(|_| RELEASES.to_string())
}

/// `GET /skill.md`：给 AI 的 Skill，随控制面版本发布，不需要登录。
pub async fn skill() -> Response {
  (
    [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
    include_str!("../../../skill/SKILL.md"),
  )
    .into_response()
}

/// `GET /cli.sh`：不需要登录。
pub async fn script(
  State(s): State<Arc<crate::state::AppState>>,
  req: Request,
) -> Response {
  let local = req
    .extensions()
    .get::<ConnectInfo<SocketAddr>>()
    .is_some_and(|peer| {
      crate::source_trust::is_direct_local(peer.0.ip(), req.headers())
    });
  script_response(
    local,
    crate::source_trust::request_proto(&req),
    &hex::encode(s.key.verifying_key().to_bytes()),
    &sha256_map(),
  )
}

fn script_response(
  local: bool,
  proto: &str,
  core_key: &str,
  hashes: &BTreeMap<String, String>,
) -> Response {
  if proto != "https" && !local {
    return (StatusCode::BAD_REQUEST, "拒绝通过明文 HTTP 提供安装脚本；请经 HTTPS 访问控制面，或从 GitHub Releases 下载 wharf 并核对 SHA256SUMS").into_response();
  }
  let mut script = SCRIPT
    .replace("{build}", wharf_api_types::BUILD)
    .replace("{core_key}", core_key);
  for platform in PLATFORMS {
    script = script.replace(
      &format!("{{sha_{platform}}}"),
      hashes.get(platform).map_or("", String::as_str),
    );
  }
  let script = script
    .replace("{releases}", &releases().replace('\'', "'\"'\"'"));
  (
    [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
    script,
  )
    .into_response()
}

const SCRIPT: &str = r#"#!/bin/sh
# Wharf CLI 安装：curl -fsSL <控制面>/cli.sh | sh -s -- <控制面>
set -eu

# 整个脚本包在函数里：shell 先解析完再执行，管道传入时不会读到一半出错。
main() {
CORE_URL="${1:-}"
BUILD="{build}"
DEST="${WHARF_BIN_DIR:-$HOME/.local/bin}"

fail() { printf '\n失败：%s\n' "$1" >&2; exit 1; }

[ "$BUILD" != dev ] || fail "控制面是本地构建（dev），没有对应的 CLI 发布；在仓库里 cargo install --path crates/cli"

case "$(uname -s)" in
  Darwin) os=macos ;;
  Linux) os=linux ;;
  *) fail "不支持的系统：$(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "不支持的架构：$(uname -m)" ;;
esac

case "$os-$arch" in
  linux-amd64) EXPECTED="{sha_linux-amd64}" ;;
  linux-arm64) EXPECTED="{sha_linux-arm64}" ;;
  macos-amd64) EXPECTED="{sha_macos-amd64}" ;;
  macos-arm64) EXPECTED="{sha_macos-arm64}" ;;
esac
[ -n "$EXPECTED" ] || fail "缺少当前平台的 SHA-256 校验和，拒绝安装"

RELEASES='{releases}'
URL="$RELEASES/build-$BUILD/wharf-$os-$arch"
printf '==> 下载 wharf（构建 %s，%s-%s）\n' "$BUILD" "$os" "$arch"
mkdir -p "$DEST"
TMP="$(mktemp "$DEST/.wharf.tmp.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
curl -fL --connect-timeout 15 --max-time 300 -o "$TMP" "$URL" \
  || fail "下载失败：${URL}（这个构建的 CLI 可能还在 CI 里打包，过几分钟再试）"
if command -v sha256sum >/dev/null 2>&1; then
  SUM="$(sha256sum < "$TMP")"
elif command -v shasum >/dev/null 2>&1; then
  SUM="$(shasum -a 256 < "$TMP")"
else
  fail "缺少 sha256sum 或 shasum，无法校验安装包"
fi
[ "$EXPECTED" = "${SUM%% *}" ] || fail "校验和不匹配，已中止安装"
chmod +x "$TMP"
mv "$TMP" "$DEST/wharf"
trap - EXIT
printf '==> 已安装到 %s/wharf\n' "$DEST"

WHARF=wharf
case ":$PATH:" in
  *":$DEST:"*) ;;
  *)
    WHARF="$DEST/wharf"
    printf '\n%s 不在 PATH 里，按你用的 shell 执行一行（写进配置，新开终端生效）：\n' "$DEST"
    printf '  bash：echo '"'"'export PATH="%s:$PATH"'"'"' >> ~/.bashrc\n' "$DEST"
    printf '  zsh： echo '"'"'export PATH="%s:$PATH"'"'"' >> ~/.zshrc\n' "$DEST"
    printf '  fish：fish_add_path %s\n' "$DEST"
    ;;
esac

# Skill：正本放在 ~/.agents/skills/wharf（Codex 等读这里），其他 agent 的 skills 目录软链过去，
# 以后更新只换正本。只给本机已经装了的 agent 建链接。
CORE_AUTHORITY="${CORE_URL#http://}"
CORE_AUTHORITY="${CORE_AUTHORITY%%/*}"
SKILL_OK=0
case "$CORE_URL" in
  https://*) SKILL_OK=1 ;;
  http://*)
    case "$CORE_AUTHORITY" in
      *@*) ;;
      localhost | localhost:* | 127.0.0.1 | 127.0.0.1:* | \[::1\] | \[::1\]:*) SKILL_OK=1 ;;
    esac
    ;;
esac
if [ "$SKILL_OK" = 1 ]; then
  SKILL_DIR="$HOME/.agents/skills/wharf"
  mkdir -p "$SKILL_DIR"
  if curl -fsSL --proto "=http,https" --proto-redir "=https" --noproxy "localhost,127.0.0.1,::1" --connect-timeout 15 --max-time 60 -o "$SKILL_DIR/SKILL.md.tmp" "$CORE_URL/skill.md"; then
    mv "$SKILL_DIR/SKILL.md.tmp" "$SKILL_DIR/SKILL.md"
    printf '==> 已安装 Skill：%s/SKILL.md\n' "$SKILL_DIR"
    for AGENT_HOME in "$HOME/.claude"; do
      [ -d "$AGENT_HOME" ] || continue
      LINK="$AGENT_HOME/skills/wharf"
      mkdir -p "$AGENT_HOME/skills"
      # 旧版本装的是普通目录：只有 SKILL.md 时换成链接，有别的文件就不动。
      if [ -d "$LINK" ] && [ ! -L "$LINK" ]; then
        rm -f "$LINK/SKILL.md"
        rmdir "$LINK" 2>/dev/null || { printf '==> %s 里有其他文件，没有改成链接\n' "$LINK"; continue; }
      fi
      ln -sfn "$SKILL_DIR" "$LINK"
      printf '==> 已链接：%s -> %s\n' "$LINK" "$SKILL_DIR"
    done
  else
    rm -f "$SKILL_DIR/SKILL.md.tmp"
    printf '==> Skill 下载失败，跳过：%s/skill.md\n' "$CORE_URL"
  fi
elif [ -n "$CORE_URL" ]; then
  printf '==> 登录后用 wharf self-update 同步 Skill\n'
fi

LOGIN="$WHARF login --url ${CORE_URL:-<控制面地址>} --core-key {core_key}"
# 已经登录过（比如这次是更新）就不再登录。
if [ -n "$CORE_URL" ] && "$WHARF" status --json >/dev/null 2>&1; then
  printf '==> 已登录，完成\n'
  return 0
fi
# 有终端就直接登录；管道运行时标准输入是脚本本身，所以从 /dev/tty 读。
if [ -n "$CORE_URL" ] && { : </dev/tty; } 2>/dev/null; then
  printf '\n==> 登录：粘贴页面上新建的访问令牌\n'
  if "$WHARF" login --url "$CORE_URL" --core-key "{core_key}" </dev/tty; then
    "$WHARF" status || true
    return 0
  fi
  printf '\n登录没有完成，可以稍后重试：\n  %s\n' "$LOGIN"
  return 0
fi

printf '\n下一步（会提示输入 token，粘贴页面上新建的 token）：\n'
printf '  %s\n' "$LOGIN"
printf '  %s status\n' "$WHARF"
}

main "$@"
"#;

#[tokio::test]
async fn install_script_refuses_remote_plaintext() {
  let hash = "a".repeat(64);
  let hashes =
    parse_sha256sums(&format!("{hash}  wharf-linux-amd64"));
  assert_eq!(
    script_response(false, "http", "", &hashes).status(),
    StatusCode::BAD_REQUEST
  );
  for (local, proto) in [(true, "http"), (false, "https")] {
    let response = script_response(local, proto, "", &hashes);
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
      .await
      .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
      text.contains(&hash)
        && text.contains("sha256sum")
        && text.contains("mktemp \"$DEST/")
    );
  }
}
