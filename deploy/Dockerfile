# 构建：docker build -f deploy/Dockerfile --target agent -t wharf-agent .
#       docker build -f deploy/Dockerfile --target core  -t wharf-core .
# 国内构建加 --build-arg CARGO_MIRROR=sparse+https://rsproxy.cn/index/
#            --build-arg NPM_REGISTRY=https://registry.npmmirror.com

# 页面：打包进 wharf-core 二进制。
FROM node:22-bookworm-slim AS web
ARG NPM_REGISTRY=
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi \
 && npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1.95-bookworm AS build
ARG CARGO_MIRROR=
# 构建号（短提交号），控制面用它判断 agent 是否要升级。
ARG WHARF_BUILD=
RUN if [ -n "$CARGO_MIRROR" ]; then \
      printf '[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "%s"\n' "$CARGO_MIRROR" > "$CARGO_HOME/config.toml"; \
    fi
WORKDIR /src
COPY . .
COPY --from=web /web/dist /src/web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -n "$WHARF_BUILD" ]; then export WHARF_BUILD; else unset WHARF_BUILD; fi \
 && cargo build --release --locked \
 && mkdir -p /out \
 && cp target/release/wharf-core target/release/wharf-agent target/release/wharf /out/

# docker CLI 和 compose 插件都是静态 Go 二进制，直接从官方镜像拿。
FROM docker:27-cli AS dockercli

# 只需要根证书，从构建镜像复制，不跑 apt（国内很慢）。
FROM debian:bookworm-slim AS base
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

FROM base AS agent
# rsync：迁移服务时在两台 agent 之间同步数据。
RUN apt-get update \
 && apt-get install -y --no-install-recommends rsync \
 && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
# buildx：构建来源的服务在 agent 上 docker build。
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY --from=build /out/wharf-agent /usr/local/bin/wharf-agent
ENV WHARF_DATA_DIR=/var/lib/wharf
ENTRYPOINT ["wharf-agent"]
CMD ["run"]

FROM base AS core
COPY --from=build /out/wharf-core /out/wharf /usr/local/bin/
ENV WHARF_DATA_DIR=/var/lib/wharf-core
EXPOSE 7700
ENTRYPOINT ["wharf-core"]
