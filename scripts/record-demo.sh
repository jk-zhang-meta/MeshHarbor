#!/usr/bin/env bash
# The README demo: real machines, one browser tab, each desktop full screen.
#
# Records against whatever server you point it at, usually production: for each
# device in MESHHARBOR_DEMO_DEVICES it opens the device's remote page with the
# sidebar collapsed, presses Connect, and enters the viewer's fullscreen. Then
# ui/e2e/video/cut-demo.ts cuts the take into the README MP4 and GIF.
#
# What you need before running:
#   - an account that can sign in, and the org (tenant) id the devices are in
#   - each device ONLINE. MESHHARBOR_DEMO_DEVICES finds it by display name, and
#     MESHHARBOR_DEMO_LABELS sets the name the video SHOWS: a display name says
#     whose machine it is, so give every device a neutral label
#   - bun, and ffmpeg on PATH (or in WSL)
#
# Usage:
#   ./scripts/record-demo.sh --login     once: sign in with the credentials below and
#                                        save the session to ~/.roomler-demo-state.json
#                                        (MESHHARBOR_DEMO_STATE); later takes need no password
#   MESHHARBOR_DEMO_USER=…  MESHHARBOR_DEMO_PASS=…  MESHHARBOR_DEMO_TENANT=<org id> \
#   MESHHARBOR_DEMO_DEVICES="office-mac,laptop-17,laptop-42" \
#   MESHHARBOR_DEMO_LABELS="MacBook|Windows laptop|Second laptop" \
#   MESHHARBOR_DEMO_CAPTIONS="A MacBook — in a browser tab|…|…" \
#   MESHHARBOR_DEMO_BLUR='[{"device":0,"phase":"full","rect":[136,46,400,394]}]' \
#   ./scripts/record-demo.sh
#
# MESHHARBOR_DEMO_BLUR (optional) blurs regions of a device's desktop, per layout:
# see cut-demo.ts. Measure the rectangles on the take's own frames.
#
# Optional scenes, each documented where it is defined in record-demo.spec.ts:
#   MESHHARBOR_DEMO_RECORD / MESHHARBOR_DEMO_RECORD_PROBE   the viewer's Record button, filmed
#   MESHHARBOR_DEMO_STEPS                                 scripted input on a remote app
#   MESHHARBOR_DEMO_NETWORK=1                             the dashboard's Network card
# MESHHARBOR_DEMO_LOCKCHECK (strongly advised): `roomler exec` selectors to check
# for a signed-in screen right before the take — see below.
# `bun ui/e2e/video/list-demo-devices.ts` lists, from the saved session, the
# orgs and device display names the account can film.
#
# Output, in the take folder (default ~/Videos/Roomler/demo/<date-time>):
#   frames/ + take.json    the raw take: every composited frame, and the marks
#   roomler-demo.mp4       1080p, for linking            → ./roomler-demo.mp4
#   demo-preview.gif       1280 px, auto-plays in README → docs/assets/demo-preview.gif
#   demo-preview-blog.gif  560 px, under the docs build's 3 MiB limit
#                                                        → ui/blog/assets/demo-preview.gif
#
# ⚠️ The screens are filmed AS THEY ARE, and a machine that is not yours to
# dress can say more than its name. Found on 2026-09-30:
#   - a managed laptop's lock screen printed its hostname, its addresses and
#     where it sits, on every frame (dropped until it was signed in);
#   - an unlocked Mac showed the operator's own dashboard, naming the whole
#     fleet (its window was minimized before the take), then a weather widget
#     naming a place and the host's "being viewed" banner naming the org (both
#     blurred);
#   - a laptop's system tray showed its corporate VPN client's icon (blurred:
#     a product name is a clue to whose network it is).
# A small region such as a tray icon is not text, so no OCR can confirm its
# blur: compare crops of the blurred and the unblurred cut, by eye, in both
# layouts and across the fullscreen switch.
# The take never visits the device list, the dashboard or the network pages,
# but only looking at the frames tells you what the DESKTOPS show. Watch the
# MP4 end to end before publishing either file.
#
# ⚠️ Write the captions from THIS take's frames. The path a machine takes is
# measured, not assumed: a laptop that went through a relay in one take went
# direct an hour later, once its VPN was off. The viewer's stats pills in the
# page frames say which.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
UI_DIR="$PROJECT_DIR/ui"

BASE_URL="${MESHHARBOR_DEMO_URL:-https://roomler.ai}"

# `--login` signs in once and saves the browser session to $STATE; every take
# after that starts from the session and never loads the password, so a take
# can be run by someone (or something) that must not handle it. The session
# lasts as long as the refresh token (30 days); then run --login again.
LOGIN=0
[ "${1:-}" = "--login" ] && LOGIN=1
STATE="${MESHHARBOR_DEMO_STATE:-$HOME/.roomler-demo-state.json}"

if [ $LOGIN -eq 1 ] || [ ! -f "$STATE" ]; then
  # Credentials may come from the environment or from a 0600 file, so a
  # re-record does not need them re-typed. The file is never echoed.
  for envfile in "${MESHHARBOR_DEMO_ENV:-}" "$HOME/.roomler-demo.env" ./.roomler-demo.env; do
    if [ -n "$envfile" ] && [ -f "$envfile" ]; then
      set -a; . "$envfile"; set +a
      echo "credentials: loaded from $envfile"
      break
    fi
  done
  : "${MESHHARBOR_DEMO_USER:?set MESHHARBOR_DEMO_USER, or put it in ~/.roomler-demo.env}"
  : "${MESHHARBOR_DEMO_PASS:?set MESHHARBOR_DEMO_PASS, or put it in ~/.roomler-demo.env}"
fi

if [ $LOGIN -eq 1 ]; then
  echo "=== Roomler demo: sign in once and save the session ==="
  cd "$UI_DIR" || exit 1
  E2E_BASE_URL="$BASE_URL" \
  E2E_USERNAME="$MESHHARBOR_DEMO_USER" \
  E2E_PASSWORD="$MESHHARBOR_DEMO_PASS" \
  E2E_SAVE_STATE=1 \
  E2E_STORAGE_STATE="$STATE" \
    bunx playwright test e2e/video/record-demo.spec.ts \
      --config=playwright.video.config.ts --reporter=list
  RC=$?
  if [ $RC -ne 0 ] || [ ! -f "$STATE" ]; then
    echo "ERROR: the sign-in did not finish (Playwright exited $RC) — read the log above."
    exit 1
  fi
  chmod 600 "$STATE" 2>/dev/null
  echo "Session saved to $STATE. Takes now run without the password."
  exit 0
fi

: "${MESHHARBOR_DEMO_TENANT:?set MESHHARBOR_DEMO_TENANT — the org id the devices are in}"
: "${MESHHARBOR_DEMO_DEVICES:?set MESHHARBOR_DEMO_DEVICES — display names, comma-separated, in filming order}"

# ⚠️ OUTSIDE ui/e2e/video/output: Playwright empties its outputDir at the start
# of every run, so a take kept there is lost to the next run of anything.
TAKE="${MESHHARBOR_DEMO_TAKE:-$HOME/Videos/Roomler/demo/$(date +%Y-%m-%d-%H%M%S)}"
mkdir -p "$TAKE"

echo "=== Roomler demo recording ==="
echo "server  : $BASE_URL"
echo "org     : $MESHHARBOR_DEMO_TENANT"
echo "devices : $MESHHARBOR_DEMO_DEVICES"
echo "take    : $TAKE"
echo ""

echo "[1/3] Checking the server answers…"
if ! curl -fsS -o /dev/null "$BASE_URL/health"; then
  echo "ERROR: $BASE_URL/health did not answer. Is the server up, and the URL right?"
  exit 1
fi

# ⚠️ Every screen signed in, checked right before THIS take. A locked screen takes typed text
# as a sign-in attempt (2026-10-06: a take that started after a Mac had locked typed a folder
# path into its password field), and a managed laptop's lock screen prints its name and
# addresses on every frame. MESHHARBOR_DEMO_LOCKCHECK lists `roomler exec` selectors, each with
# the OS that decides how to ask: "laptop-17:win,office-mac:mac". A screen that is locked, or a
# check that cannot answer, stops the take before anything is filmed. Selectors are machine
# names: pass them at run time, never write them down here.
if [ -n "${MESHHARBOR_DEMO_LOCKCHECK:-}" ]; then
  IFS=',' read -ra lockchecks <<< "$MESHHARBOR_DEMO_LOCKCHECK"
  for c in "${lockchecks[@]}"; do
    sel="${c%%:*}"
    os="${c##*:}"
    case "$os" in
      win)
        out=$(timeout 60 roomler exec "$sel" 'tasklist /FI "IMAGENAME eq LogonUI.exe" /NH' 2>&1)
        RC=$?
        # Decide on the process name and the INFO prefix alone: the "nothing found" sentence is
        # localized ("Es werden keine Aufgaben …" on a German laptop).
        if [ $RC -ne 0 ]; then
          echo "ERROR: could not check $sel (roomler exec exited $RC) — not filming."
          exit 1
        elif printf '%s' "$out" | grep -q 'LogonUI.exe'; then
          echo "ERROR: $sel is at its lock screen — sign it in first."
          exit 1
        elif ! printf '%s' "$out" | grep -q -E '^INFO'; then
          echo "ERROR: $sel answered something unexpected — not filming:"
          printf '%s\n' "$out" | head -3
          exit 1
        fi
        ;;
      mac)
        out=$(timeout 60 roomler exec "$sel" 'ioreg -n Root -d1 -a' 2>&1)
        RC=$?
        # Unlocked here = the lock key absent (or false) while the console session reports
        # LoginDone true.
        if [ $RC -ne 0 ]; then
          echo "ERROR: could not check $sel (roomler exec exited $RC) — not filming."
          exit 1
        elif printf '%s' "$out" | grep -A1 CGSSessionScreenIsLocked | grep -q '<true/>'; then
          echo "ERROR: $sel is locked — sign it in first."
          exit 1
        elif ! printf '%s' "$out" | grep -A1 kCGSessionLoginDoneKey | grep -q '<true/>'; then
          echo "ERROR: $sel has no signed-in console session — not filming."
          exit 1
        fi
        ;;
      *)
        echo "ERROR: MESHHARBOR_DEMO_LOCKCHECK entry '$c' needs :win or :mac."
        exit 1
        ;;
    esac
    echo "screen  : $sel signed in"
  done
fi

echo "[2/3] Recording…"
cd "$UI_DIR" || exit 1
if [ -f "$STATE" ]; then
  echo "session : $STATE (no password)"
  AUTH=(E2E_STORAGE_STATE="$STATE")
else
  AUTH=(E2E_USERNAME="$MESHHARBOR_DEMO_USER" E2E_PASSWORD="$MESHHARBOR_DEMO_PASS")
fi
# The spec refuses an unknown or offline device before it films anything.
env "${AUTH[@]}" \
E2E_BASE_URL="$BASE_URL" \
E2E_TENANT_ID="$MESHHARBOR_DEMO_TENANT" \
E2E_DEMO_DEVICES="$MESHHARBOR_DEMO_DEVICES" \
E2E_DEMO_LABELS="${MESHHARBOR_DEMO_LABELS:-}" \
E2E_DEMO_NETWORK="${MESHHARBOR_DEMO_NETWORK:-}" \
E2E_DEMO_RECORD="${MESHHARBOR_DEMO_RECORD:-}" \
E2E_DEMO_RECORD_PROBE="${MESHHARBOR_DEMO_RECORD_PROBE:-}" \
E2E_DEMO_STEPS="${MESHHARBOR_DEMO_STEPS:-}" \
E2E_DEMO_LOCKCHECK="${MESHHARBOR_DEMO_LOCKCHECK:-}" \
E2E_DEMO_OUT="$TAKE" \
  bunx playwright test e2e/video/record-demo.spec.ts \
    --config=playwright.video.config.ts --reporter=list
RC=$?
if [ $RC -ne 0 ] || [ ! -f "$TAKE/take.json" ]; then
  echo "ERROR: the take did not finish (Playwright exited $RC) — read the log above."
  exit 1
fi

echo "[3/3] Cutting…"
bun e2e/video/cut-demo.ts "$TAKE" "$TAKE" || exit 1

echo ""
echo "Next: WATCH $TAKE/roomler-demo.mp4 end to end (see the note at the top of"
echo "this script), then copy it to ./roomler-demo.mp4 and demo-preview.gif to"
echo "docs/assets/ and ui/blog/assets/."
