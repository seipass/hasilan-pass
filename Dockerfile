# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.92-bookworm
ARG NODE_IMAGE=node:24.18.0-bookworm-slim
ARG DEBIAN_IMAGE=debian:bookworm-20260623-slim
ARG CADDY_IMAGE=caddy:2.11.4-alpine
ARG ALPINE_IMAGE=alpine:3.23.4

FROM ${ALPINE_IMAGE} AS secret-init
COPY docker/init-secrets.sh /usr/local/bin/init-secrets
RUN chmod 0755 /usr/local/bin/init-secrets
ENTRYPOINT ["/bin/sh", "/usr/local/bin/init-secrets"]

FROM ${RUST_IMAGE} AS rust-builder
WORKDIR /src

RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.127 --locked

COPY . .
RUN cargo build --locked --release --package hasilan-server
RUN bash scripts/build-wasm.sh

FROM ${NODE_IMAGE} AS web-builder
WORKDIR /src

RUN corepack enable
RUN corepack prepare pnpm@10.28.2 --activate

COPY . .
COPY --from=rust-builder /src/web/src/generated ./web/src/generated
RUN pnpm install --frozen-lockfile --filter @hasilan/web-vault...
RUN pnpm --filter @hasilan/web-vault build

FROM ${DEBIAN_IMAGE} AS server

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 hasilan \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent hasilan

COPY --from=rust-builder /src/target/release/hasilan-server /usr/local/bin/hasilan-server
COPY docker/server-entrypoint.sh /usr/local/bin/server-entrypoint
RUN chmod 0755 /usr/local/bin/hasilan-server /usr/local/bin/server-entrypoint

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server-entrypoint"]

FROM ${CADDY_IMAGE} AS web

COPY docker/Caddyfile /etc/caddy/Caddyfile
COPY --from=web-builder /src/web/dist /srv
RUN addgroup -S -g 10002 caddy-runtime \
    && adduser -S -D -H -u 10002 -G caddy-runtime caddy-runtime \
    && chown -R 10002:10002 /config /data /srv

USER 10002:10002
EXPOSE 8080 80 443 443/udp
