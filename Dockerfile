# syntax=docker/dockerfile:1
#
# vulsweb: a single-file binary (burrito_ng) on a distroless base.
#
#   docker build -t vulsweb .
#   docker buildx build --platform linux/amd64,linux/arm64 -t vulsweb .
#
# Only the single-file binaries (dist/linux_amd64/vulsweb, ...):
#   docker buildx build --platform linux/amd64,linux/arm64 --target binary \
#     --output type=local,dest=dist .
#
# The builder always runs on the build machine's architecture; burrito_ng
# cross-builds the binary for TARGETARCH with a pre-compiled musl ERTS.

ARG MISE_VERSION=2026.10.25
ARG DEBIAN_VERSION=trixie-20261104-slim

# Runs on the build machine like the builder below (otherwise a multi-arch
# build copies the arm64 mise binary into the amd64 builder).
FROM --platform=$BUILDPLATFORM jdxcode/mise:${MISE_VERSION} AS mise

# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM debian:${DEBIAN_VERSION} AS build

# Toolchain build deps: Erlang (compiled by mise/kerl), Rust (rustup), bun.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip xz-utils \
      build-essential autoconf m4 libncurses-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY --from=mise /usr/local/bin/mise /usr/local/bin/mise
ENV MISE_DATA_DIR=/opt/mise \
    MISE_CACHE_DIR=/opt/mise/cache \
    PATH=/opt/mise/shims:$PATH \
    MIX_ENV=prod \
    LANG=C.UTF-8

WORKDIR /app

# Erlang, Elixir, bun and Rust exactly as pinned in mise.toml.
COPY mise.toml ./
RUN mise trust /app/mise.toml && mise install && mise reshim

RUN mix local.hex --force && mix local.rebar --force

# Hex deps (cached until mix.exs / mix.lock change).
COPY mix.exs mix.lock ./
RUN mix deps.get --only prod
COPY config/config.exs config/prod.exs config/
RUN mix deps.compile

# UI deps from npm via bun (cached until the lockfile changes).
COPY assets/package.json assets/bun.lock assets/bunfig.toml assets/
RUN cd assets && bun install --frozen-lockfile

COPY config config
COPY lib lib
COPY priv priv
COPY assets assets
RUN mix assets.deploy

# Release version (e.g. from the git tag); defaults to the one in mix.exs.
ARG VERSION=""
ENV VULSWEB_VERSION=${VERSION}

# TARGETARCH is amd64 or arm64, matching the burrito_ng target names in mix.exs.
ARG TARGETARCH
RUN BURRITO_NG_TARGET=linux_${TARGETARCH} mix release \
 && cp burrito_ng_out/vulsweb_linux_${TARGETARCH} /vulsweb

# ---------------------------------------------------------------------------
# Just the binary, for `docker buildx build --target binary --output ...`.
FROM scratch AS binary
COPY --from=build /vulsweb /vulsweb

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot

# The binary unpacks its payload (Erlang runtime + app) on first start, ~1s.
# With a read-only root filesystem mount an *exec* tmpfs on /tmp
# (docker: --tmpfs /tmp:exec, compose: tmpfs: ["/tmp:exec"]); docker mounts
# tmpfs noexec by default and the unpacked runtime must be executable.
ENV VULSWEB_INSTALL_DIR=/tmp/vulsweb \
    ERL_CRASH_DUMP=/tmp/erl_crash.dump \
    VULS_RESULTS_DIR=/vuls/results \
    BIND=0.0.0.0 \
    PORT=5111

# burrito_ng writes the binary as 0744; make it executable for any user.
COPY --from=build --chmod=0755 /vulsweb /vulsweb

# distroless :nonroot defaults to WORKDIR /home/nonroot (mode 0700, uid 65532).
# When run as root (to read vuls' 0600 results) with all capabilities dropped,
# root cannot even enter that directory and the VM fails to boot.
WORKDIR /

EXPOSE 5111
USER nonroot:nonroot
ENTRYPOINT ["/vulsweb"]
