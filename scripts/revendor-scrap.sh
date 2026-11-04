#!/usr/bin/env bash
# Same invariant as I5 (webrtc-ice) and the wintun-bindings fork: the vendored
# `crates/vendored/scrap` is pristine upstream + ONE canonical patch
# (`crates/vendored/scrap.patch`), so the fork is auditable as a diff rather
# than as a tree nobody can tell apart from upstream.
#
# What the patch does: binds `IOSurfaceGetBytesPerRow` and exposes it as
# `Frame::bytes_per_row()`. Upstream binds only `IOSurfaceGetAllocSize` — the
# page-rounded TOTAL allocation — so a consumer has no way to learn the real
# row pitch and is forced to guess it as `len() / height`. That guess
# overshoots (and is usually not a multiple of 4), which shears every captured
# frame on macOS. Field-hit on a MacBook Pro, 2026-08-23.
#
# FR-85 P1d adds `Display::origin()` for DXGI and X11: where the captured
# display sits in screen coordinates, so a recording can place the mouse
# pointer in the frame. DXGI's first output need not be the primary monitor,
# and an X11 monitor is a rectangle of the root window.
#
# The quartz `Capturer`'s `Drop` releases the stream only after CoreGraphics
# reports `Stopped` (upstream left it as a TODO). `CGDisplayStreamStop` is
# asynchronous, and releasing on the next line let an already-queued frame
# delivery run against the freed stream: a SIGSEGV in SkyLight's
# `_CGYDisplayStreamFrameAvailable` after every session. Field-hit on a
# MacBook, 2026-10-15.
#
#   scripts/revendor-scrap.sh [version]           rebuild the vendored tree from
#                                                 upstream + patch (use on a bump)
#   scripts/revendor-scrap.sh --check [version]   verify tree == upstream+patch
#                                                 (CI drift gate; no writes)
#   scripts/revendor-scrap.sh --regen [version]   regenerate the .patch from the
#                                                 CURRENT vendored tree (after
#                                                 editing the fork)
#
# Default version: 0.5.0. The macOS arms compile only on a Mac, so after a
# rebuild run `cargo check -p meshharbord --features scrap-capture` ON macOS;
# the drift gate below is a content comparison and runs anywhere.
set -euo pipefail

MODE="revendor"
case "${1:-}" in
--check | --regen)
    MODE="${1#--}"
    shift
    ;;
esac
VER="${1:-0.5.0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDORED="$ROOT/crates/vendored/scrap"
PATCH="$ROOT/crates/vendored/scrap.patch"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Pristine crates.io tarball from the static CDN (the API download URL 403s a
# UA-less curl). Publish metadata (Cargo.toml.orig) rides along verbatim.
mkdir -p "$TMP/upstream"
curl -sfL "https://static.crates.io/crates/scrap/scrap-$VER.crate" |
    tar xz -C "$TMP/upstream" --strip-components=1
# Under [patch.crates-io] the workspace lockfile governs, so the tracked
# vendored tree never carries one.
rm -f "$TMP/upstream/Cargo.lock"

# `--strip-trailing-cr` on every diff, and LF-normalize both sides: this repo
# is developed on Windows, so an autocrlf checkout hands us CRLF working-tree
# files while the tarball is LF. The patch and the drift check compare
# CONTENT, not line endings.
# NOTE the `|| true`: scrap's tarball is pure LF, so grep matches nothing and
# exits 1 — which under `set -o pipefail` would abort the whole script. "No
# CRLF anywhere" is the expected case here, not a failure.
normalize_lf() {
    { grep -rIl "$(printf '\r')" "$1" 2>/dev/null || true; } | while IFS= read -r f; do
        [ -n "$f" ] && sed -i 's/\r$//' "$f"
    done
}
normalize_lf "$TMP/upstream"

case "$MODE" in
regen)
    cp -r "$VENDORED" "$TMP/vendored"
    normalize_lf "$TMP/vendored"
    # diff exits 1 when differences exist — that's the point.
    (cd "$TMP" && diff -ruN --strip-trailing-cr upstream vendored >"$PATCH.tmp") || true
    mv "$PATCH.tmp" "$PATCH"
    echo "regenerated $(basename "$PATCH") ($(grep -c '^diff ' "$PATCH") file(s) differ)"
    ;;
check | revendor)
    cp -r "$TMP/upstream" "$TMP/rebuilt"
    # CR-strip the patch at READ time: after an autocrlf checkout the
    # working-tree patch may be CRLF while the normalized upstream is LF, and
    # GNU patch on Linux matches hunk context line endings literally.
    sed 's/\r$//' "$PATCH" >"$TMP/patch.lf"
    (cd "$TMP/rebuilt" && patch -p1 --no-backup-if-mismatch -s <"$TMP/patch.lf")
    if [ "$MODE" = "check" ]; then
        if diff -r --strip-trailing-cr "$TMP/rebuilt" "$VENDORED" >"$TMP/drift.txt" 2>&1; then
            echo "OK: vendored scrap == upstream $VER + $(basename "$PATCH")"
        else
            echo "DRIFT: vendored scrap != upstream $VER + patch:" >&2
            head -40 "$TMP/drift.txt" >&2
            echo "(edit the fork, then run: scripts/revendor-scrap.sh --regen)" >&2
            exit 1
        fi
    else
        rm -rf "$VENDORED"
        mv "$TMP/rebuilt" "$VENDORED"
        echo "revendored scrap $VER + patch into crates/vendored/scrap"
        echo "next (macOS): cargo check -p meshharbord --features scrap-capture"
    fi
    ;;
esac
