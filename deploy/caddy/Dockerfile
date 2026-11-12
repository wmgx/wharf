# Wharf 网关镜像：官方 Caddy 加三个插件。改了这个文件就把 caddy-image.yml 里的 TAG 序号加一。
ARG CADDY_VERSION
FROM caddy:${CADDY_VERSION}-builder AS build
RUN xcaddy build \
    --with github.com/mholt/caddy-l4@eafc300ef23bcb2a28cc329a18e1e98bcd2b7cee \
    --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db \
    --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:${CADDY_VERSION}
COPY --from=build /usr/bin/caddy /usr/bin/caddy
