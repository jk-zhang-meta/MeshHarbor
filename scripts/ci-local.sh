#!/usr/bin/env bash
# Run the Linux-runnable subset of CI's cargo gates, locally, with HONEST
# exit statuses.
#
# Why this exists (2026-08-23): a hand-rolled
# `cargo check --workspace --all-targets … | grep ': error'` reported CLEAN on
# a tree that did not compile, twice. Two separate reasons, and both are the
# kind you cannot fix by being careful:
#
#   1. The workspace includes the Tauri tray, whose `libdbus-sys` build script
#      PANICS when libdbus-1-dev is absent. cargo aborts before reaching the
#      crates you changed, a build-script panic is not a `path:line: error`
#      line, so the grep matches nothing — and the pipe throws away cargo's
#      exit status. You get silence and read it as success.
#   2. Several gates are FEATURE-GATED (`overlay-l3`, `overlay-netstack`,
#      `ssh-server`, `vp9-444`). A default `-p` check never compiles that code
#      at all, so a struct literal in a feature-gated test helper sails past
#      every local check and fails in CI.
#
# The rules this encodes: branch on the COMMAND'S EXIT STATUS, never on
# grepped output; and run the same feature combinations CI runs.
#
# Usage:  bash scripts/ci-local.sh [--quick]
#           --quick   skip the slower feature-gated lanes
#
# Prerequisites (matching CI's apt step):
#   sudo apt install -y libdbus-1-dev libglib2.0-dev libgtk-3-dev \
#       libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libwebkit2gtk-4.1-dev \
#       pkg-config
# Without libdbus-1-dev the workspace lanes fail for an ENVIRONMENTAL reason —
# this script says so explicitly rather than letting it look like your bug.
#
# NOT covered here, deliberately:
#   * `vp9-444` (needs libvpx + bindgen), macOS lanes, Windows lanes.
#   * `cargo test -p meshharbor-tests` — needs MongoDB + Redis. CI does not run
#     it either; see docs and CLAUDE.md for the WSL+docker recipe.
set -uo pipefail

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

# Per-CHECKOUT log dir. Parallel sessions each run this from their own
# worktree but share $TMPDIR, and a fixed path meant two runs redirected into
# the same files: one truncated the other mid-write, `grep` reported "binary
# file matches", and a lane that passes cleanly in isolation showed FAIL.
# A local check you cannot trust is worse than no local check — that is the
# whole reason this script exists — so the path is keyed to the checkout.
LOGDIR="${TMPDIR:-/tmp}/meshharbor-ci-local/$(basename "$(cd "$(dirname "$0")/.." && pwd)")-$$"
mkdir -p "$LOGDIR" 2>/dev/null || { LOGDIR="$HOME/.cache/meshharbor-ci-local-$$"; mkdir -p "$LOGDIR"; }

FAILED=()
run() {
  local name="$1"; shift
  printf '%-52s' "$name"
  if "$@" > "$LOGDIR/$name.log" 2>&1; then
    echo "OK"
  else
    echo "FAIL"
    FAILED+=("$name")
    # Show the first few real diagnostics, but the VERDICT above came from the
    # exit status — this output is for reading, not for deciding.
    grep -E "^error|error\[|panicked at" "$LOGDIR/$name.log" | head -4 | sed 's/^/    /'
    echo "    full log: $LOGDIR/$name.log"
  fi
}

echo "Running CI's Linux cargo gates (logs in $LOGDIR)"
echo

run "fmt"                cargo fmt --check --all
run "clippy-workspace"   cargo clippy --workspace -- -D warnings
# ci.yml runs this SECOND clippy pass because the workspace one above is
# deliberately not `--all-targets` and therefore never compiles `#[cfg(test)]`
# bodies. Mirrored here after a lint in a new unit test passed every local gate
# and then failed in CI (#707) — a local script that cannot catch what CI
# catches just sends you to CI to find out.
run "clippy-server-crates" \
  cargo clippy -p meshharbor-api -p meshharbor-services --all-targets -- -D warnings
run "test-api-lib"       cargo test -p meshharbor-api --lib
run "test-services-lib"  cargo test -p meshharbor-services --lib
run "check-tests-crate"  cargo check -p meshharbor-tests --all-targets

if [ "$QUICK" = "0" ]; then
  # The feature-gated lanes. These are the ones a default check never reaches,
  # and they are where the 2026-08-23 breakage actually lived.
  run "clippy-tunnel-overlay" \
    cargo clippy -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --all-targets -- -D warnings
  run "test-tunnel-overlay" \
    cargo test -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --lib -- --test-threads=1
  # `--all-targets`, matching CI. Without it the agent's TEST code is never
  # compiled here, and CI's agent lanes (the Rust lanes behind "Rust checks",
  # Windows overlay clippy, ffmpeg-encoder) all build with tests — so a struct literal in
  # `telemetry.rs`'s tests sailed past a green local gate and failed all three
  # (2026-08-25). "Compiled somewhere" is not "compiled everywhere CI does".
  run "clippy-agent-overlay" \
    cargo clippy -p meshharbord --features overlay-l3 --all-targets -- -D warnings
fi

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All gates passed."
  exit 0
fi
echo "FAILED: ${FAILED[*]}"
echo
echo "If clippy-workspace failed on libdbus-sys / glib, that is the missing apt"
echo "packages listed at the top of this script, not your change."
exit 1
