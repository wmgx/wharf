#!/usr/bin/env bash
# 发正式版本：scripts/release.sh 0.1.0
#
# 给 origin/main 的最新提交打标签 v<版本> 并推送，由 .github/workflows/release.yml 发布。
# 先改好 Cargo.toml 里的 version 并合进 main；这里检查版本号一致、main 上的 images 构建已经成功。
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:-}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "用法：$0 <版本>，例如 $0 0.1.0" >&2; exit 1; }
tag="v$version"

git fetch -q origin main --tags
sha=$(git rev-parse origin/main)
short=${sha::7}

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "标签 $tag 已经存在" >&2; exit 1
fi

cargo_version=$(git show "origin/main:Cargo.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
[ "$cargo_version" = "$version" ] || {
  echo "main 上 Cargo.toml 的版本是 $cargo_version，先改成 $version 并合进 main" >&2; exit 1
}

conclusion=$(gh run list --workflow images.yml --commit "$sha" --limit 1 --json conclusion --jq '.[0].conclusion // ""')
[ "$conclusion" = success ] || {
  echo "main 上 $short 的 images 构建还没成功（现在：${conclusion:-没有或还在跑}），等它通过再发版" >&2; exit 1
}

echo "发布 $tag（构建 $short）"
git tag -a "$tag" "$sha" -m "$tag"
git push -q origin "$tag"
echo "已推送标签，进度：gh run list --workflow release.yml --limit 1"
