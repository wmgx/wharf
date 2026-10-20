#!/usr/bin/env bash
# 端到端验证：在一台有 Docker 的机器上起控制面和 agent，全程只用 wharf CLI 操作。
#
#   docker build -f deploy/Dockerfile --target core  -t wharf-core:dev .
#   docker build -f deploy/Dockerfile --target agent -t wharf-agent:dev .
#   scripts/e2e.sh
#
# 用到的东西都带 wharf-e2e 前缀，结束时清理。网关用 18080/18443，不占 80/443。
# token 只在变量里传递，不打印。
set -euo pipefail

CORE_IMAGE=${CORE_IMAGE:-wharf-core:dev}
AGENT_IMAGE=${AGENT_IMAGE:-wharf-agent:dev}
PORT=${PORT:-7700}
HTTPS_PORT=${HTTPS_PORT:-18443}
HOST=who.localhost
AGENT_DATA=/var/lib/wharf-e2e
CORE=wharf-e2e-core
AGENT=wharf-e2e-agent

step() { printf '\n== %s\n' "$*"; }
fail() { printf '\n!! 失败：%s\n' "$*"; exit 1; }

cleanup() {
  step "清理"
  docker rm -f "$CORE" "$AGENT" >/dev/null 2>&1 || true
  for p in whoami wharf-gw-edge; do
    docker ps -aq --filter "label=com.docker.compose.project=$p" | xargs -r docker rm -f >/dev/null
  done
  docker volume rm -f wharf-e2e-core >/dev/null 2>&1 || true
  docker run --rm -v /srv:/srv -v /var/lib:/hostlib debian:bookworm-slim \
    rm -rf /srv/wharf-gw-edge /srv/whoami /hostlib/wharf-e2e >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

step "启动控制面"
docker run -d --name "$CORE" --network host \
  -v wharf-e2e-core:/var/lib/wharf-core \
  -e WHARF_LISTEN=127.0.0.1:$PORT -e WHARF_AGENT_IMAGE="$AGENT_IMAGE" \
  "$CORE_IMAGE" >/dev/null
for _ in $(seq 30); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  sleep 1
done
TOKEN=$(docker exec "$CORE" cat /var/lib/wharf-core/admin.token)

# 在控制面容器里执行 wharf。
wharf() {
  docker exec -e WHARF_URL="http://127.0.0.1:$PORT" -e WHARF_TOKEN="$TOKEN" "$CORE" wharf "$@"
}
# 从 JSON 里取字段：jget '<python 表达式，d 是解析后的对象>'
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

step "登记服务器 e2e，用 server add 给出的 docker 命令加入"
JOIN=$(wharf server add e2e --json)
JOIN_TOKEN=$(echo "$JOIN" | jget 'd["join_token"]')
echo "$JOIN" | jget 'd["commands"]["docker"]' | grep -q "docker run" || fail "没有 docker 加入命令"
docker run -d --name "$AGENT" --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$AGENT_DATA:$AGENT_DATA" -v /srv:/srv \
  -e WHARF_DATA_DIR="$AGENT_DATA" \
  -e WHARF_CORE_URL="http://127.0.0.1:$PORT" -e WHARF_JOIN_TOKEN="$JOIN_TOKEN" \
  -e WHARF_PUBLIC_IP=127.0.0.1 \
  "$AGENT_IMAGE" >/dev/null
for _ in $(seq 30); do
  [ "$(wharf server show e2e --json | jget 'd["online"]')" = True ] && break
  sleep 1
done
[ "$(wharf server show e2e --json | jget 'd["online"]')" = True ] || { docker logs "$AGENT" | tail; fail "agent 没有上线"; }
echo "agent 已上线"

step "加入凭据只能用一次"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/agent/join" \
  -H 'content-type: application/json' \
  -d "{\"join_token\":\"$JOIN_TOKEN\",\"public_key\":\"$(printf '0%.0s' $(seq 64))\"}")
[ "$code" = 401 ] || fail "重复使用加入凭据返回 $code"

step "新建默认网关（caddy，${HTTPS_PORT} 端口）"
wharf gateway add edge --server e2e --default --http-port 18080 --https-port "$HTTPS_PORT" --apply

step "部署 whoami"
wharf service deploy whoami --image traefik/whoami --port http=80 --apply

step "加路由：没有 --confirm 时退出码是 2"
set +e
wharf route add "$HOST" --service whoami --apply >/dev/null 2>&1
code=$?
set -e
[ "$code" = 2 ] || fail "需要确认时退出码是 $code"
wharf route add "$HOST" --service whoami --apply --confirm "route/$HOST"

step "经过网关访问"
ok=
for _ in $(seq 20); do
  if curl -sk --resolve "$HOST:$HTTPS_PORT:127.0.0.1" "https://$HOST:$HTTPS_PORT/" | grep -q '^Hostname:'; then
    ok=1; break
  fi
  sleep 1
done
[ -n "$ok" ] || { wharf gateway logs edge --tail 30; fail "经网关访问 whoami 失败"; }
echo "https://$HOST:$HTTPS_PORT/ → whoami 正常"

step "服务端口不绑定 0.0.0.0"
docker ps --filter label=com.docker.compose.project=whoami --format '{{.Ports}}' | grep -q '0.0.0.0' \
  && fail "whoami 绑定了 0.0.0.0"
echo "只绑定了 127.0.0.1"

step "现实和配置一致时，plan 为空"
[ "$(wharf plan --json | jget 'len(d["items"])')" = 0 ] || { wharf plan; fail "plan 不为空"; }

step "制造漂移：停掉 whoami，plan 能发现并修复"
docker ps -q --filter label=com.docker.compose.project=whoami | xargs docker stop >/dev/null
wharf plan --json | jget '[i["reason"] for i in d["items"]]' | grep -q '漂移' || fail "没有发现漂移"
wharf plan --apply
[ "$(wharf plan --json | jget 'len(d["items"])')" = 0 ] || fail "修复后仍有差异"

step "过期计划：plan 之后改配置，旧计划 apply 退出码是 3"
OLD=$(wharf service deploy whoami --env A=1 --json | jget 'd["plan_id"]')
wharf service deploy whoami --env A=2 --apply >/dev/null
set +e
wharf apply "$OLD" >/dev/null 2>&1
code=$?
set -e
[ "$code" = 3 ] || fail "过期计划退出码是 $code"

step "status 和 export"
wharf status
wharf export | grep -q 'traefik/whoami' || fail "export 里没有 whoami"

step "删除路由、服务、网关"
wharf route rm "$HOST" --apply
wharf service rm whoami --apply --confirm service/whoami
wharf gateway rm edge --apply
[ -z "$(docker ps -aq --filter label=com.docker.compose.project=whoami)" ] || fail "whoami 容器还在"
[ -z "$(docker ps -aq --filter label=com.docker.compose.project=wharf-gw-edge)" ] || fail "网关容器还在"
[ "$(wharf plan --json | jget 'len(d["items"])')" = 0 ] || fail "删除后 plan 不为空"

step "全部通过"
