//! CLI 分发：`curl -fsSL <控制面>/cli.sh | sh -s -- <控制面>`。
//! 二进制由 CI 按构建号发布到 GitHub Release `build-<构建号>`，安装的版本和控制面一致。
//! 脚本只给出下载地址和安装位置，不接触任何凭据；登录由用户执行 `wharf login`。

use axum::{
  http::header,
  response::{IntoResponse, Response},
};

/// 公开仓库的 Release 地址；可以用 `WHARF_CLI_RELEASES` 换成镜像。
const RELEASES: &str =
  "https://github.com/wmgx/wharf/releases/download";

/// `GET /cli.sh`：不需要登录。
pub async fn script() -> Response {
  let base = std::env::var("WHARF_CLI_RELEASES")
    .unwrap_or_else(|_| RELEASES.to_string());
  (
    [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
    SCRIPT
      .replace("{build}", wharf_api_types::BUILD)
      .replace("{releases}", &base),
  )
    .into_response()
}

const SCRIPT: &str = r#"#!/bin/sh
# Wharf CLI 安装：curl -fsSL <控制面>/cli.sh | sh -s -- <控制面>
set -eu
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

URL="{releases}/build-$BUILD/wharf-$os-$arch"
printf '==> 下载 wharf（构建 %s，%s-%s）\n' "$BUILD" "$os" "$arch"
mkdir -p "$DEST"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fL --connect-timeout 15 --max-time 300 -o "$TMP" "$URL" \
  || fail "下载失败：$URL（这个构建的 CLI 可能还在 CI 里打包，过几分钟再试）"
chmod +x "$TMP"
mv "$TMP" "$DEST/wharf"
trap - EXIT
printf '==> 已安装到 %s/wharf\n' "$DEST"

case ":$PATH:" in
  *":$DEST:"*) ;;
  *) printf '\n%s 不在 PATH 里，加到 shell 配置：\n  export PATH="%s:$PATH"\n' "$DEST" "$DEST" ;;
esac

printf '\n下一步：\n'
if [ -n "$CORE_URL" ]; then
  printf '  wharf login --url %s     # 粘贴页面上新建的 token\n' "$CORE_URL"
else
  printf '  wharf login --url <控制面地址>\n'
fi
printf '  wharf status\n'
"#;
