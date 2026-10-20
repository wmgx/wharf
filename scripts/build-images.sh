#!/usr/bin/env bash
# 构建 wharf-core 和 wharf-agent 镜像。
#   TAG=dev CARGO_MIRROR=sparse+https://rsproxy.cn/index/ scripts/build-images.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=${TAG:-dev}
export DOCKER_BUILDKIT=1
args=(-f deploy/Dockerfile)
[ -n "${CARGO_MIRROR:-}" ] && args+=(--build-arg "CARGO_MIRROR=$CARGO_MIRROR")
for target in agent core; do
  echo "== 构建 wharf-$target:$TAG"
  docker build "${args[@]}" --target "$target" -t "wharf-$target:$TAG" .
done
