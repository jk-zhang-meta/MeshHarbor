#!/usr/bin/env bash
# FR-41 (#965) — dress a meshharbord virtual desktop so a demo recording has
# something worth filming, instead of two small windows on black.
#
# Run as root on the agent host, AFTER the daemon is up with
# MESHHARBORD_VIRTUAL_DESKTOP=1:
#
#   sudo bash scripts/demo-desktop.sh
#
# Four things this had to learn the hard way, all of them non-obvious:
#
# 1. ⚠️ WSLg exports WAYLAND_DISPLAY into every environment, and GTK PREFERS
#    Wayland when it sees it. So GTK apps started with DISPLAY=:<n> still tried
#    to talk to WSLg's compositor and died with
#    "libwnck ... no valid display found" — pointing at the wrong display
#    entirely. Unsetting WAYLAND_DISPLAY and pinning GDK_BACKEND=x11 is what
#    makes them land on the Xvfb the agent is actually capturing.
#
# 2. ⚠️ Do NOT swap the window manager under a live capture. `xfwm4 --replace`
#    against the Xvfb wedged the X server outright — xwd and xwininfo stopped
#    answering and the desktop had to be rebuilt. openbox (what the daemon
#    starts) is known to work with capture; dress around it.
#
# 3. ⚠️ xfce4-panel and xfdesktop want a session manager that does not exist
#    here ("Failed to connect to the session manager"), so they are not an
#    option. A wallpaper plus well-chosen windows gets most of the way.
#
# 4. ⚠️ The daemon picks the next FREE display each start, so it walks
#    (:100 -> :101 -> :102 ...) across restarts and leaves stale
#    /tmp/.X<n>-lock behind. Never hardcode the display — discover it.
set -u

# --- discover the display the daemon actually brought up --------------------
DPY="$(pgrep -a Xvfb | grep -oE ':[0-9]+' | head -1)"
[ -n "$DPY" ] || { echo "no Xvfb running — is MESHHARBORD_VIRTUAL_DESKTOP=1 set?"; exit 1; }
export DISPLAY="$DPY"
echo "display: $DISPLAY"

unset WAYLAND_DISPLAY            # see note 1
export GDK_BACKEND=x11
export QT_QPA_PLATFORM=xcb

timeout 10 xdpyinfo >/dev/null 2>&1 || { echo "X on $DISPLAY is not answering"; exit 1; }

# --- wallpaper --------------------------------------------------------------
WALL=/opt/meshharbor-demo/wall.png
mkdir -p /opt/meshharbor-demo
# Flat diagonal gradient in the product's teal. A radial vignette was tried and
# crushed it to near-black at capture bitrates — screen content is not a photo.
convert -size 1920x1080 gradient:#12463F-#0a2a26 -rotate 90 "$WALL"
timeout 10 feh --bg-scale "$WALL" && echo "wallpaper set"

# --- windows ----------------------------------------------------------------
# ⚠️ Reap apps left on a PREVIOUS display first. Because the daemon walks the
# display number (note 4), a plain `pgrep -x xterm` matches a window living on a
# dead :N and the launch is skipped — leaving an empty desktop that looks like
# the script worked. Staleness is per-display, so the only safe test is "did we
# start it on THIS one".
for app in xterm thunar pcmanfm; do
  for pid in $(pgrep -x "$app" 2>/dev/null); do
    tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q "^DISPLAY=$DISPLAY$" \
      || { kill "$pid" 2>/dev/null && echo "  reaped stale $app (pid $pid, other display)"; }
  done
done

# htop earns its place twice: it fills the frame with real system state, and its
# constant redraw proves to a viewer that the stream is live rather than a still.
if ! pgrep -x xterm >/dev/null; then
  # ⚠️ `-e htop` directly, NOT `-e bash -lc htop`. A login shell rewrites the
  # window title from its prompt, so the titlebar ends up reading
  # `root@<REAL-HOSTNAME>: /` — which then gets filmed. Running the target
  # binary with no shell in between leaves `-title` intact.
  setsid xterm -geometry 150x44+200+150 -fa 'DejaVu Sans Mono' -fs 13 \
    -bg '#08201d' -fg '#d8efe9' -title 'ubuntu-wsl' -e htop \
    </dev/null >/tmp/demo-xterm.log 2>&1 &
  disown
fi
if ! pgrep -x thunar >/dev/null; then
  setsid thunar /usr/share </dev/null >/tmp/demo-thunar.log 2>&1 &
  disown
fi
# pcmanfm is what forks the at-spi helper that wedges the systemd unit on stop
# (see FR-41's log); thunar is used instead and this clears any leftover.
pkill -x pcmanfm 2>/dev/null

sleep 4
echo "windows:"
timeout 10 xwininfo -root -children 2>/dev/null \
  | grep -E '^ +0x' | grep -viE 'has no name|1x1\+' | sed 's/^ */  /' | head -6
