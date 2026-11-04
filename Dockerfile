# --- Stage 1: Rust build ---
#
# FR-73 P1b — three layers instead of one, so a registry-backed cache is worth
# something on Actions (where every runner starts empty):
#
#   chef     the toolchain + cargo-chef, keyed by nothing that changes per commit
#   planner  the dependency recipe, keyed by the manifests
#   builder  `cargo chef cook` = every dependency (the mediasoup C++ worker
#            included) as ONE layer keyed by that recipe, then the real build
#            over ONLY the Rust sources
#
# Before this the stage was `COPY . .` then `cargo build`: any change anywhere —
# a UI file, a doc — invalidated the build layer and paid the full cold build
# (17 min 35 s measured on Actions, FR-69 AC4), and inside that layer rustup
# ALSO downloaded the toolchain `rust-toolchain.toml` pins, because the base
# image was a different minor. The base now matches the pin, so nothing is
# fetched at build time.
#
# ⚠️ `cook` must receive exactly the arguments the real build does (`-p`,
# `--no-default-features`, `--features`): a different feature set compiles the
# dependencies twice, which is slower than no cache — silently.
FROM rust:1.95-bookworm AS chef
RUN apt-get update && apt-get install -y libclang-dev cmake python3-pip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The pin comes first so `rustup` resolves the components the file lists
# (rustfmt is needed by the build) for the toolchain the build will run on.
COPY rust-toolchain.toml ./
RUN rustup show active-toolchain && rustup component add rustfmt
RUN cargo install cargo-chef --locked --version 0.1.78

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY agents agents
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# FR-69 P8 (D9/D13) — which pillars this image carries. `full` | `collab` |
# `remote` | `mesh` | `access`; every profile is the same server composed from
# fewer modules, and `/health` lists the ones it mounts. `SAAS=1` adds the
# hosted service's billing + newsletter module: the default HERE so the
# operator's manual prod build (no build args) keeps it; the self-host publish
# workflow passes `SAAS=0` and asserts the image does not mount it.
ARG PROFILE=full
ARG SAAS=1
COPY --from=planner /app/recipe.json recipe.json
# The `[patch.crates-io]` crates (`rtp`, `webrtc-ice`, `webrtc`) and the
# other path dependencies under crates/vendored are NOT part of the recipe —
# cargo-chef skeletonises workspace members, and a patch is resolved by
# cargo from its real manifest at cook time (the first dry run died with
# "failed to read /app/crates/vendored/rtp/Cargo.toml"). They ARE
# dependencies, so they belong in this layer: a change to a vendored crate
# invalidates the cook, which is the correct key.
COPY crates/vendored crates/vendored
# `derp-relay` rides along so the SAME image can run as the central
# coturn workers' `/stats` sidecar (stats follow-up): one image, two
# binaries, no second build+push pipeline. A few MB, and it keeps the
# stats producer byte-identical between the PoPs and the central fleet.
# Package-qualified features are what let one build line serve both
# packages: `derp-relay` has no features, so `--no-default-features` is
# inert for it, and `meshharbor-api/profile-…` names exactly the one crate
# that composes the modules.
#
# `cook --no-build` writes the skeleton (every workspace member reduced to
# its manifest + an empty source file) and stops. The build is then ours,
# because ONE member has to be real while the dependencies compile: the
# vendored `webrtc-ice` patch (a real crate, not a skeleton) depends on
# `crates/tcp-turn-conn`, and against the skeleton it fails with
# "cannot find `TcpTurnConn` in `tcp_turn_conn`" (the second dry run). So
# that member is overlaid with its real sources before the dependency build.
# Afterwards every member's artefacts are removed, which is what `cook`
# itself does after building: the real sources arrive by COPY with the
# build context's OLDER mtimes, and cargo would otherwise keep the skeleton's
# empty artefacts as "fresh" — a server whose main() is `{}`.
RUN cargo chef cook --no-build --release --recipe-path recipe.json -p meshharbor-api -p derp-relay --no-default-features \
      --features "meshharbor-api/profile-${PROFILE}$( [ "$SAAS" = "1" ] && printf ',meshharbor-api/saas' )"
COPY crates/tcp-turn-conn crates/tcp-turn-conn
RUN cargo build --release -p meshharbor-api -p derp-relay --no-default-features \
      --features "meshharbor-api/profile-${PROFILE}$( [ "$SAAS" = "1" ] && printf ',meshharbor-api/saas' )" \
 && cargo metadata --no-deps --format-version 1 \
      | python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))' \
      | xargs -n1 cargo clean --release -p
# Only what the server build reads: the manifests, the crates and the two
# terminal installers `crates/modules/fleet` embeds with `include_str!`.
# NOT `agents/`: the workspace manifest names those members, but nothing in
# them is compiled for these two packages, and the SKELETONS the cook wrote
# (manifests + empty sources) satisfy the workspace — copying the real agent
# sources here made every daemon-only merge recompile the server for five
# minutes (FR-73 P1c: the first "no-change" measurement was exactly that).
# The planner still sees the real `agents/` manifests, so an agent DEPENDENCY
# change still re-cooks. NOT `ui/`, `docs/`, `files/`, `config/` either: a
# change there must not touch a Rust layer.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY scripts/install.sh scripts/install.ps1 scripts/
RUN cargo build --release -p meshharbor-api -p derp-relay --no-default-features \
      --features "meshharbor-api/profile-${PROFILE}$( [ "$SAAS" = "1" ] && printf ',meshharbor-api/saas' )"

# --- Stage 2: Vue SPA build ---
FROM oven/bun:1 AS ui-builder
WORKDIR /app/ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui/ .
RUN bun run build

# --- Stage 3: Runtime (nginx + Rust binary) ---
FROM debian:trixie-slim AS runtime

# ── OCI image metadata (FR-24) ──────────────────────────────────────────────
# Renders on GHCR / Docker Hub listing pages and is what `docker inspect`
# reports. `licenses` is AGPL-3.0-only because THIS IMAGE is the control
# plane (meshharbor-api + derp-relay + the Vue bundle) — the MPL-2.0 half of
# the split ships as native agent binaries, never in this image. It must be
# updated in lockstep with LICENSE/LICENSING.md; a stale value here
# advertises the wrong terms to every registry that lists us.
ARG VERSION=dev
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="Roomler" \
      org.opencontainers.image.description="Remote desktop in a browser tab + WireGuard mesh VPN. Self-hosted, end-to-end encrypted." \
      org.opencontainers.image.url="https://roomler.ai" \
      org.opencontainers.image.source="https://github.com/gjovanov/roomler-ai" \
      org.opencontainers.image.documentation="https://roomler.ai/docs/" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="G ROX EOOD" \
      org.opencontainers.image.authors="legal@roomler.ai" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}"
RUN apt-get update && apt-get install -y ca-certificates nginx && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/meshharbor-api /usr/local/bin/
COPY --from=builder /app/target/release/derp-relay /usr/local/bin/
COPY --from=ui-builder /app/ui/dist /var/www/roomler-ai
COPY files/nginx-pod.conf /etc/nginx/conf.d/default.conf
# FR-91: the security headers live in one file that the pod nginx and the blog
# lane's server both include. Outside conf.d/ on purpose: nginx.conf includes
# conf.d/*.conf at http level, and this file belongs at server level only.
COPY files/security-headers.conf /etc/nginx/snippets/security-headers.conf
# The country database for the user analytics (#1896): DB-IP's "IP to Country
# Lite", CC BY 4.0. That licence permits exactly what this image does, which
# is to redistribute it publicly, given attribution: the observability
# dashboard links DB-IP, and the provenance note travels beside the file.
# `scripts/fetch-geoip.sh` stages it in files/geoip/ BEFORE `docker build`;
# both image workflows run it. Nothing here downloads, so a failed fetch can
# never fail the build or end up cached as an empty layer. Without the file
# (a source build that skipped the script) the analytics honestly report
# `country: unknown`, a supported state. NOT GeoLite2: MaxMind's EULA forbids
# handing its data to third parties, and a public image does exactly that.
# Details: files/geoip/README.md.
COPY files/geoip/ /usr/share/roomler/geoip/
# The image names its own database, so a deployment needs no setting for it.
# An env value overrides it (your own .mmdb, e.g. a licensed GeoIP2), and an
# EMPTY value turns country lookups off. ⚠️ An env var outranks the config
# files, so `geoip_mmdb` in config/local.toml cannot override this; use the
# variable.
ENV ROOMLER__STATS__GEOIP_MMDB=/usr/share/roomler/geoip/dbip-country-lite.mmdb
# FR-20 P5 - unit costs for the metered relay/SFU resources. The binary
# resolves `config/relay-costs.toml` relative to its CWD, which is `/` here.
# Same contract as the GeoIP directory above: absent is a supported state and
# renders "not priced", never a fabricated 0.00 (which would also imply 100%
# margin). `ROOMLER__RELAY_COSTS__*` overrides it without an image rebuild.
COPY config/ /config/
RUN rm -f /etc/nginx/sites-enabled/default
RUN printf '#!/bin/sh\nnginx\nexec meshharbor-api\n' > /entrypoint.sh && chmod +x /entrypoint.sh
EXPOSE 80
CMD ["/entrypoint.sh"]
