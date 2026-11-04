#!/bin/bash
# dev-xvfb.sh — run the agent's capture path against a virtual X framebuffer.
#
# Purpose: on hosts without a real desktop (WSL2 without WSLg, CI runners,
# containers) this spins up an Xvfb display, paints something recognisable
# on it, and then runs the scrap-capture smoke test against that display.
# Useful locally to confirm the capture→encode pipeline builds and captures
# frames before wiring the agent into a live session.
#
# Usage:
#   ./scripts/dev-xvfb.sh                # runs the capture smoke test
#   ./scripts/dev-xvfb.sh run            # runs `meshharbord run` (needs enrolled config)
#   ./scripts/dev-xvfb.sh shell          # leaves Xvfb up and drops you into a shell
#   ./scripts/dev-xvfb.sh <cmd> [args]   # runs <cmd> with DISPLAY set to the Xvfb
#
# Environment overrides:
#   XVFB_DISPLAY   display number (default :99)
#   XVFB_GEOMETRY  WxHxDEPTH (default 1280x720x24)
#   AGENT_FEATURES features to enable (default: scrap-capture,openh264-encoder,enigo-input)
#
# Requires (one-time):
#   sudo apt install -y libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev \
#                       xvfb xterm x11-utils

set -euo pipefail

XVFB_DISPLAY="${XVFB_DISPLAY:-:99}"
XVFB_GEOMETRY="${XVFB_GEOMETRY:-1280x720x24}"
AGENT_FEATURES="${AGENT_FEATURES:-scrap-capture,openh264-encoder,enigo-input}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Preflight ────────────────────────────────────────────────────────────
missing=()
for bin in Xvfb xterm xdpyinfo cargo; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
if (( ${#missing[@]} )); then
    echo "missing binaries: ${missing[*]}" >&2
    echo "install with: sudo apt install -y libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev xvfb xterm x11-utils" >&2
    exit 1
fi

if [[ -n "${DISPLAY:-}" && "${DISPLAY}" != "${XVFB_DISPLAY}" ]]; then
    echo "note: DISPLAY=$DISPLAY is already set; this script will override to $XVFB_DISPLAY" >&2
fi

# ── Start Xvfb (or reuse an existing display) + a painted xterm ─────────
pids=()
started_xvfb=0

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Check if the requested display is already answering. Happens when WSLg
# or a prior session has already bound the socket; reusing it is the
# sensible default and avoids noisy "server already running" errors.
export DISPLAY="$XVFB_DISPLAY"
if xdpyinfo >/dev/null 2>&1; then
    echo "display $XVFB_DISPLAY already up — reusing"
else
    # Guard against a stale lock left by a previous crashed Xvfb.
    rm -f "/tmp/.X${XVFB_DISPLAY#:}-lock" "/tmp/.X11-unix/X${XVFB_DISPLAY#:}" 2>/dev/null || true

    Xvfb "$XVFB_DISPLAY" -screen 0 "$XVFB_GEOMETRY" -nolisten tcp >/dev/null 2>&1 &
    pids+=($!)
    started_xvfb=1

    # Wait up to 5s for the server to answer queries.
    for _ in $(seq 1 50); do
        if xdpyinfo >/dev/null 2>&1; then break; fi
        sleep 0.1
    done
    if ! xdpyinfo >/dev/null 2>&1; then
        echo "Xvfb failed to start on $XVFB_DISPLAY" >&2
        exit 1
    fi
    echo "Xvfb up on $DISPLAY (${XVFB_GEOMETRY})"
fi

# Only paint a canvas if we started Xvfb ourselves — don't add junk
# windows to a user's live session they're reusing.
if (( started_xvfb )); then
    xterm -geometry 80x24+0+0 \
        -e "echo 'meshharbord dev-xvfb canvas'; sleep 1d" >/dev/null 2>&1 &
    pids+=($!)
    # Give the (WM-less) server a moment to map the window.
    sleep 0.3
fi

# ── Dispatch ─────────────────────────────────────────────────────────────
cd "$PROJECT_DIR"

if (( $# == 0 )); then
    echo "→ running capture smoke test (--features ${AGENT_FEATURES})"
    cargo test -p meshharbord --lib \
        --features "$AGENT_FEATURES" \
        capture:: -- --nocapture
    exit 0
fi

# Important: do NOT use `exec` here — it replaces this shell and the EXIT
# trap never fires, orphaning the Xvfb + xterm we started. Run in the
# foreground instead so `cleanup()` tears them down when the command exits.
case "$1" in
    run)
        echo "→ running meshharbord (--features ${AGENT_FEATURES})"
        cargo run -p meshharbord --features "$AGENT_FEATURES" -- run
        ;;
    shell)
        echo "→ dropping into a shell with DISPLAY=$DISPLAY (exit to tear down)"
        "${SHELL:-/bin/bash}"
        ;;
    *)
        echo "→ running: $*"
        "$@"
        ;;
esac
