#!/usr/bin/env bash
# rc.283 (same invariant as I5 for webrtc-ice) — the vendored
# `crates/vendored/wintun-bindings` is pristine upstream + ONE canonical patch
# (`crates/vendored/wintun-bindings.patch`: the on-drop NetworkList
# Profiles/Signatures registry deletion removed, so an adapter drop no longer
# erases the meshharbor network's NLA identity / Private-profile categorization).
# This script makes that relationship mechanical:
#
#   scripts/revendor-wintun-bindings.sh [version]           rebuild the vendored tree
#                                                           from upstream + patch
#                                                           (use on a tun bump)
#   scripts/revendor-wintun-bindings.sh --check [version]   verify tree == upstream+patch
#                                                           (CI drift gate; no writes)
#   scripts/revendor-wintun-bindings.sh --regen [version]   regenerate the .patch from
#                                                           the CURRENT vendored tree
#                                                           (after editing the fork)
#
# Default version: 0.7.39 (the release `tun` 0.8.10 resolves). After a
# rebuild, run `cargo check -p meshharbor-tunnel-core --features overlay-l3`
# ON WINDOWS — the crate is windows-target-only, so a Linux CI build never
# compiles it; the drift gate below is content comparison and runs anywhere.
set -euo pipefail

MODE="revendor"
case "${1:-}" in
--check | --regen)
    MODE="${1#--}"
    shift
    ;;
esac
VER="${1:-0.7.39}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDORED="$ROOT/crates/vendored/wintun-bindings"
PATCH="$ROOT/crates/vendored/wintun-bindings.patch"
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
curl -sfL "https://static.crates.io/crates/wintun-bindings/wintun-bindings-$VER.crate" |
    tar xz -C "$TMP/upstream" --strip-components=1
# The tarball ships a Cargo.lock; under [patch.crates-io] the workspace
# lockfile governs, so the TRACKED vendored tree never carries one. Strip it
# so tree == upstream+patch holds on a clean checkout.
rm -f "$TMP/upstream/Cargo.lock"
# The tarball's SOURCES are CRLF (a Windows crate). The canonical patch is
# LF, and GNU patch on Linux matches hunk context line endings LITERALLY
# (msys patch strips CR, which is why a mismatch only bites in CI) —
# normalize the upstream TEXT files to LF before any diff/patch so hunk
# arithmetic is EOL-stable on every platform. `grep -I` skips the embedded
# wintun.dll driver binaries; the `--strip-trailing-cr` diffs bridge the
# (still-CRLF) tracked vendored tree.
grep -rIl "$(printf '\r')" "$TMP/upstream" | while IFS= read -r f; do
    sed -i 's/\r$//' "$f"
done

case "$MODE" in
regen)
    cp -r "$VENDORED" "$TMP/vendored"
    # Normalize the vendored COPY to LF too (an autocrlf checkout hands us
    # CRLF working-tree files), so the regenerated patch is pure LF end to
    # end — git stores it verbatim and Linux `patch` applies it verbatim.
    grep -rIl "$(printf '\r')" "$TMP/vendored" 2>/dev/null | while IFS= read -r f; do
        sed -i 's/\r$//' "$f"
    done
    # diff exits 1 when differences exist — that's the point.
    (cd "$TMP" && diff -ruN --strip-trailing-cr upstream vendored >"$PATCH.tmp") || true
    mv "$PATCH.tmp" "$PATCH"
    echo "regenerated $(basename "$PATCH") ($(grep -c '^diff ' "$PATCH") file(s) differ)"
    ;;
check | revendor)
    cp -r "$TMP/upstream" "$TMP/rebuilt"
    # CR-strip the patch at READ time: after an autocrlf checkout the
    # working-tree patch may be CRLF while the normalized upstream is LF —
    # GNU patch on Linux would then reject every hunk on line endings alone.
    sed 's/\r$//' "$PATCH" >"$TMP/patch.lf"
    (cd "$TMP/rebuilt" && patch -p1 --no-backup-if-mismatch -s <"$TMP/patch.lf")
    if [ "$MODE" = "check" ]; then
        if diff -r --strip-trailing-cr "$TMP/rebuilt" "$VENDORED" >"$TMP/drift.txt" 2>&1; then
            echo "OK: vendored wintun-bindings == upstream $VER + $(basename "$PATCH")"
        else
            echo "DRIFT: vendored wintun-bindings != upstream $VER + patch:" >&2
            head -40 "$TMP/drift.txt" >&2
            echo "(edit the fork, then run: scripts/revendor-wintun-bindings.sh --regen)" >&2
            exit 1
        fi
    else
        rm -rf "$VENDORED"
        mv "$TMP/rebuilt" "$VENDORED"
        echo "revendored wintun-bindings $VER + patch into crates/vendored/wintun-bindings"
        echo "next (Windows): cargo check -p meshharbor-tunnel-core --features overlay-l3"
    fi
    ;;
esac
