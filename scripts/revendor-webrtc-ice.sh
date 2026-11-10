#!/usr/bin/env bash
# P5 (consolidation invariant I5) — the vendored `crates/vendored/webrtc-ice`
# is pristine upstream + ONE canonical patch (`crates/vendored/webrtc-ice.patch`,
# the TURNS-over-TCP gather arm wired to the workspace `tcp-turn-conn` crate).
# This script makes that relationship mechanical:
#
#   scripts/revendor-webrtc-ice.sh [version]           rebuild the vendored tree
#                                                      from upstream + patch
#                                                      (use on a webrtc bump)
#   scripts/revendor-webrtc-ice.sh --check [version]   verify tree == upstream+patch
#                                                      (CI drift gate; no writes)
#   scripts/revendor-webrtc-ice.sh --regen [version]   regenerate the .patch from
#                                                      the CURRENT vendored tree
#                                                      (after editing the fork)
#
# Default version: 0.12.0 (the vendored release). After a rebuild, run
# `cargo check -p meshharbord` — the agent's WebRTC path is the fork's
# only remaining consumer.
set -euo pipefail

MODE="revendor"
case "${1:-}" in
--check | --regen)
    MODE="${1#--}"
    shift
    ;;
esac
VER="${1:-0.12.0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDORED="$ROOT/crates/vendored/webrtc-ice"
PATCH="$ROOT/crates/vendored/webrtc-ice.patch"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Fetch the pristine crates.io tarball (static CDN — the API download URL
# 403s UA-less curl). The tarball's publish metadata (.cargo_vcs_info.json,
# Cargo.toml.orig) is kept — the vendored tree carries it verbatim; the
# vendored tree's extra `.cargo-ok` (a cargo extract marker it was copied
# with) simply rides in the patch as a one-file addition.
#
# `--strip-trailing-cr` on every diff: a Windows autocrlf checkout hands us
# CRLF working-tree files while the tarball (and CI checkouts) are LF — the
# patch and the drift check compare CONTENT, not line endings.
mkdir -p "$TMP/upstream"
curl -sfL "https://static.crates.io/crates/webrtc-ice/webrtc-ice-$VER.crate" |
    tar xz -C "$TMP/upstream" --strip-components=1
# The tarball ships a Cargo.lock, but upstream's own .gitignore (also in the
# tarball) excludes it — so the TRACKED vendored tree can never carry one
# (and under [patch.crates-io] the workspace lockfile governs anyway).
# Strip it so tree == upstream+patch holds on a clean checkout.
rm -f "$TMP/upstream/Cargo.lock"

case "$MODE" in
regen)
    cp -r "$VENDORED" "$TMP/vendored"
    # diff exits 1 when differences exist — that's the point.
    (cd "$TMP" && diff -ruN --strip-trailing-cr upstream vendored >"$PATCH.tmp") || true
    mv "$PATCH.tmp" "$PATCH"
    echo "regenerated $(basename "$PATCH") ($(grep -c '^diff ' "$PATCH") file(s) differ)"
    ;;
check | revendor)
    cp -r "$TMP/upstream" "$TMP/rebuilt"
    (cd "$TMP/rebuilt" && patch -p1 --no-backup-if-mismatch -s <"$PATCH")
    if [ "$MODE" = "check" ]; then
        if diff -r --strip-trailing-cr "$TMP/rebuilt" "$VENDORED" >"$TMP/drift.txt" 2>&1; then
            echo "OK: vendored webrtc-ice == upstream $VER + $(basename "$PATCH")"
        else
            echo "DRIFT: vendored webrtc-ice != upstream $VER + patch:" >&2
            head -40 "$TMP/drift.txt" >&2
            echo "(edit the fork, then run: scripts/revendor-webrtc-ice.sh --regen)" >&2
            exit 1
        fi
    else
        rm -rf "$VENDORED"
        mv "$TMP/rebuilt" "$VENDORED"
        echo "revendored webrtc-ice $VER + patch into crates/vendored/webrtc-ice"
        echo "next: cargo check -p meshharbord"
    fi
    ;;
esac
