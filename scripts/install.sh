#!/bin/sh
# roomler install.sh — terminal-driven install of the Roomler node stack
# (Linux + macOS), replicating the roomler-setup wizard's steps without a
# GUI: resolve via the roomler.ai proxy → download → sha256-verify →
# install → enroll → autostart.
#
# Usage (pipe from the API, or run a checked-out copy):
#
#   curl -fsSL https://www.itachi.fans/meshharbor/api/setup/install.sh | sh -s -- \
#       --role daemon --token <enrollment-jwt> [--server https://www.itachi.fans/meshharbor] \
#       [--name "$(hostname)"]
#
#   Roles:
#     daemon  — the roomlerd daemon ("be accessed"): Linux .deb / macOS .pkg,
#               enrolls with an AGENT enrollment token (Admin → Agents),
#               enables the packaged autostart (systemd user unit / LaunchAgent).
#     tunnel  — the roomler CLI only ("reach others"): enrolls with a TUNNEL
#               enrollment token (Admin → Tunnels).
#
#   --system          (daemon role, Linux only) install as a ROOT systemd
#                     SYSTEM service instead of the per-user unit. Pick this
#                     for a headless / server / WSL node: root is what lets
#                     the overlay bring up its TUN. It shows the person's
#                     GNOME or KDE desktop while it is on screen (FR-95/113).
#                     Config goes to /etc/roomler/config.toml. Both kinds
#                     update unattended: a system install's root daemon
#                     installs its own updates, and a per-user install gets a
#                     root update helper (roomler-update.timer + .path, FR-96)
#                     that installs them for it.
#
#   --download-only   resolve + download + verify, print what WOULD run, touch
#                     nothing else (safe on any box).
#   --no-enroll       install without enrolling (no token needed); prints the
#                     enroll command to run later.
#
# The desktop companion (roomler-desktop) rides IN the macOS .pkg. On Linux it
# is a SEPARATE .deb (FR-27), or .rpm on Fedora, the RHEL family and openSUSE
# (FR-93 P6d) — installed automatically when this box has a
# graphical session, since the companion is the device's consent PROMPT
# surface and a device set to "Prompt on host" without one cannot ask anybody.
#   --desktop / --no-desktop   force that decision either way.
#
# Conventions: POSIX sh (no bashisms), curl -fsSL, /tmp staging, sudo only
# where the target dir demands it. The enrollment token is single-use and is
# never echoed.

set -eu

# ⚠️ FR-50 — this line is REWRITTEN at serve time by the server that hands you
# this script (`crates/modules/fleet/src/setup_release.rs`), so a script fetched
# from a self-hosted Roomler enrols against THAT server and not the hosted one.
# A piped script cannot see the URL it was fetched from — there is no $0 and no
# filename — so the substitution has to happen on the server side. The literal
# below is the default for a checkout, and it is also what a server serves
# UNCHANGED when its own `app.frontend_url` is not a safe scheme://host[:port][/deployment-prefix].
# `--server` still overrides either.
#
# ⚠️ The API holds this exact text as a needle and a unit test asserts it
# appears exactly once, so editing it fails the build rather than silently
# disabling the substitution. Change both together.
SERVER="https://www.itachi.fans/meshharbor"
ROLE=""
TOKEN=""
CREDENTIALS_STDIN=0
NAME="$(hostname 2>/dev/null || echo roomler-device)"
DOWNLOAD_ONLY=0
# Explicit reviewed local-only daemon + CLI mode; never resolves latest assets.
LOCAL_PACKAGE=""
LOCAL_PACKAGE_SHA=""
LOCAL_CLI=""
LOCAL_CLI_SHA=""
LOCAL_MODE=0
LOCAL_PHASE=preflight
LOCAL_CLI_STATE=not-started
LOCAL_PACKAGE_STATE=not-started
LOCAL_ENROLL_STATE=not-started
LOCAL_STARTUP_STATE=not-started
LOCAL_MARKER_STATE=not-required
LOCAL_MARKER_TAG=""
SYSTEM=0
# Machine-global config for the --system (root) flow. The system unit starts
# at boot before any login, so a $HOME-derived path would be unreachable —
# and as root $HOME is /root, where the agent's appdirs resolver would look
# in the wrong tree entirely. Must match roomlerd.service's ROOMLERD_CONFIG.
SYSTEM_CONFIG="/etc/roomler/config.toml"
# macOS's privileged half has its OWN path, and it is NOT $SYSTEM_CONFIG above:
# com.roomler.daemon.plist passes it explicitly as `--config`, and the agent's
# root-aware config ladder is Linux-only. Reusing one variable for both would
# enroll into a file nothing reads.
# FR-46 P5a moved this off the retired name; the .pkg postinstall migrates an
# existing Mac and both gates it guards dual-read during the changeover.
MACOS_DAEMON_CONFIG="/etc/roomler/config.toml"
MACOS_DAEMON_MARKER="/etc/roomler/enable-daemon"
DAEMON_TOKEN=""
NO_ENROLL=0
# FR-27 — the Linux desktop companion. Empty = decide by probing for a
# graphical session; --desktop / --no-desktop force it either way.
DESKTOP=""
# FR-97 P6d — `--uninstall [--keep-config]` removes what this script, or a
# package, installed. It takes no --role, and refuses one.
UNINSTALL=0
KEEP_CONFIG=0

usage() {
    sed -n '2,32p' "$0" 2>/dev/null || true
    echo "usage: install.sh --role daemon|tunnel [--server URL] [--token JWT] [--name NAME]"
    echo "                  [--daemon-token JWT] [--system] [--download-only] [--no-enroll]"
    echo "                  [--desktop|--no-desktop]"
    echo "                  [--local-package PATH --local-package-sha256 HEX"
    echo "                   --local-cli PATH --local-cli-sha256 HEX] (daemon only; no downloads)"
    echo "       install.sh --uninstall [--keep-config]"
    echo
    echo "  --uninstall     Remove every Roomler part on this machine — the daemon, the"
    echo "                  companion, the tunnel CLI — however it was installed (this"
    echo "                  script, a package, the tarball). Each service is stopped through"
    echo "                  its manager first: its clean stop takes back the routes and the"
    echo "                  DNS steer it set. Then the programs, then the config, which"
    echo "                  holds the device's credential. --keep-config keeps the config."
    echo "                  Then remove the device in the dashboard: that revokes it."
    echo
    echo "  --desktop       Linux only. Force the roomler-desktop companion on or off."
    echo "                  Default: installed when a graphical session is detected. It is"
    echo "                  the device's on-screen consent prompt, so a host set to"
    echo "                  'Prompt on host' without it cannot ask anybody."
    echo
    echo "  --daemon-token  macOS only. Installs the privileged half as well (overlay/mesh)."
    echo "                  macOS needs TWO processes: a per-user LaunchAgent for screen"
    echo "                  capture and input (they only work inside a GUI login session)"
    echo "                  and a root LaunchDaemon for the overlay (creating a utun needs"
    echo "                  root). They cannot share one enrollment — the hub keys on"
    echo "                  agent_id and the second connection displaces the first — so"
    echo "                  this takes a SECOND single-use enrollment token and the Mac"
    echo "                  appears as two devices."
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --role) ROLE="$2"; shift 2 ;;
        --server) SERVER="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --credentials-stdin) CREDENTIALS_STDIN=1; shift ;;
        --name) NAME="$2"; shift 2 ;;
        --daemon-token) DAEMON_TOKEN="$2"; shift 2 ;;
        --system) SYSTEM=1; shift ;;
        --download-only) DOWNLOAD_ONLY=1; shift ;;
        --local-package) LOCAL_PACKAGE="$2"; shift 2 ;;
        --local-package-sha256) LOCAL_PACKAGE_SHA="$2"; shift 2 ;;
        --local-cli) LOCAL_CLI="$2"; shift 2 ;;
        --local-cli-sha256) LOCAL_CLI_SHA="$2"; shift 2 ;;
        --no-enroll) NO_ENROLL=1; shift ;;
        --desktop) DESKTOP=1; shift ;;
        --no-desktop) DESKTOP=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --keep-config) KEEP_CONFIG=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown flag: $1" >&2; usage ;;
    esac
done

if [ "$CREDENTIALS_STDIN" = 1 ]; then
    [ -z "$TOKEN" ] && [ -z "$DAEMON_TOKEN" ] && [ "$UNINSTALL" != 1 ] || {
        echo "error: protected credential input cannot be mixed with token arguments or uninstall" >&2; exit 1;
    }
    # Reset any inherited export attribute before receiving private values.
    unset TOKEN DAEMON_TOKEN
    TOKEN=""; DAEMON_TOKEN=""
    IFS= read -r TOKEN && IFS= read -r DAEMON_TOKEN || {
        echo "error: protected credential input is incomplete" >&2; exit 1;
    }
fi

if [ "$UNINSTALL" = 1 ]; then
    # It removes every Roomler part on this machine, so a --role would read as
    # "only this part" and remove more than was asked: refuse it, with the rest
    # of the install options.
    if [ -n "$ROLE" ] || [ -n "$TOKEN" ] || [ -n "$DAEMON_TOKEN" ] || [ "$SYSTEM" = 1 ] ||
        [ "$DOWNLOAD_ONLY" = 1 ] || [ "$NO_ENROLL" = 1 ] || [ -n "$DESKTOP" ] ||
        [ -n "$LOCAL_PACKAGE$LOCAL_PACKAGE_SHA$LOCAL_CLI$LOCAL_CLI_SHA" ]; then
        echo "error: --uninstall removes every Roomler part on this machine and takes no install options (only --keep-config)" >&2
        exit 1
    fi
else
    if [ "$KEEP_CONFIG" = 1 ]; then
        echo "error: --keep-config applies to --uninstall only" >&2
        exit 1
    fi
    case "$ROLE" in
        daemon|tunnel) ;;
        "") echo "error: --role daemon|tunnel is required" >&2; usage ;;
        *) echo "error: unknown role '$ROLE' (expected daemon|tunnel)" >&2; exit 1 ;;
    esac
fi

OS="$(uname -s)"
case "$OS" in
    Linux|Darwin) ;;
    *) echo "error: unsupported OS '$OS' — use install.ps1 on Windows" >&2; exit 1 ;;
esac

if [ "$SYSTEM" = 1 ] && { [ "$ROLE" != daemon ] || [ "$OS" != Linux ]; }; then
    echo "error: --system applies to '--role daemon' on Linux only (on macOS use --daemon-token for the privileged half; the tunnel role installs a CLI, not a service)" >&2
    exit 1
fi

if [ -n "$DAEMON_TOKEN" ] && { [ "$ROLE" != daemon ] || [ "$OS" != Darwin ]; }; then
    echo "error: --daemon-token applies to '--role daemon' on macOS only" >&2
    exit 1
fi

if [ -n "$LOCAL_PACKAGE$LOCAL_PACKAGE_SHA$LOCAL_CLI$LOCAL_CLI_SHA" ]; then
    [ "$ROLE" = daemon ] && [ -n "$LOCAL_PACKAGE" ] && [ -n "$LOCAL_PACKAGE_SHA" ] &&
        [ -n "$LOCAL_CLI" ] && [ -n "$LOCAL_CLI_SHA" ] || {
        echo "error: local daemon mode requires both artifacts and both SHA256 values" >&2; exit 1;
    }
    [ "$DESKTOP" != 1 ] || { echo "error: local mode never downloads a desktop companion" >&2; exit 1; }
    case "$LOCAL_PACKAGE" in /*) ;; *) echo "error: local daemon package path must be absolute" >&2; exit 1 ;; esac
    case "$OS/$LOCAL_PACKAGE" in
        Linux/*.deb|Darwin/*.pkg) ;;
        *) echo "error: local daemon package must be an absolute Linux .deb or macOS .pkg path" >&2; exit 1 ;;
    esac
    case "$LOCAL_CLI" in /*) ;; *) echo "error: local CLI path must be absolute" >&2; exit 1 ;; esac
    for local_file in "$LOCAL_PACKAGE" "$LOCAL_CLI"; do
        [ -f "$local_file" ] && [ -s "$local_file" ] && [ ! -L "$local_file" ] || {
            echo "error: local artifact must be a nonempty regular nonsymlink file" >&2; exit 1;
        }
    done
    for local_sha in "$LOCAL_PACKAGE_SHA" "$LOCAL_CLI_SHA"; do
        [ "${#local_sha}" = 64 ] || { echo "error: local SHA256 must be 64 lowercase hex characters" >&2; exit 1; }
        case "$local_sha" in *[!0-9a-f]*) echo "error: local SHA256 must be 64 lowercase hex characters" >&2; exit 1 ;; esac
    done
    LOCAL_MODE=1
fi

# ─── who is the desktop user? ───────────────────────────────────────────────
#
# On macOS the per-user half is a LaunchAgent in the console user's `gui/<uid>`
# domain, and its config comes from that user's HOME. So the enroll has to run
# AS that user — not as whoever invoked the script.
#
# This matters because running the whole one-liner under `sudo` is the natural
# thing to do (the script calls `sudo` internally for `installer`, so people
# reasonably front-load it), and it used to break the install silently:
# macOS sudoers carries `env_keep += "HOME"`, so the enroll wrote the config to
# the user's own path but owned root:wheel 0600 — and the uid-501 LaunchAgent
# then hit EACCES on every start, relaunched under KeepAlive, and logged to a
# file in /tmp nothing points at. With `sudo -i` it is worse but louder: the
# config lands in /var/root and the LaunchAgent's path simply does not exist.
# Either way the user sees "it didn't start as a service".
#
# `stat -f %Su /dev/console` is the same idiom the pkg postinstall uses to
# place the plist, so the two agree by construction.
CONSOLE_USER=""
CONSOLE_UID=""
# An uninstall must also work on a Mac nobody is signed in to (a headless
# Mac with only the root half): it reads the console user itself.
if [ "$OS" = Darwin ] && [ "$UNINSTALL" != 1 ]; then
    CONSOLE_USER="$(stat -f "%Su" /dev/console 2>/dev/null || echo "")"
    if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = root ]; then
        echo "error: no GUI session is logged in (console user is '${CONSOLE_USER:-unknown}')." >&2
        echo "       The macOS agent runs inside a login session — screen capture and input" >&2
        echo "       do not work from a LaunchDaemon. Log in on the Mac and re-run this." >&2
        exit 1
    fi
    CONSOLE_UID="$(id -u "$CONSOLE_USER")"
    if [ "$(id -u)" = 0 ]; then
        printf '==> %s\n' "running as root — the per-user half will be installed for '$CONSOLE_USER' (uid $CONSOLE_UID)"
    fi
fi

STAGE="$(mktemp -d /tmp/roomler-install.XXXXXX)"
finish_install() {
    local_exit=$1
    if [ "$LOCAL_MODE" = 1 ] && [ "$local_exit" != 0 ]; then
        # Only compensate a marker created by THIS attempt, never a preexisting
        # marker, config, package or service. Package managers can have partial
        # effects even on nonzero exit: this is NOT an OS rollback.
        if [ "$LOCAL_MARKER_STATE" = owned-created ]; then
            if sudo /bin/sh -c '[ -f "$1" ] && [ ! -L "$1" ] && printf "%s\n" "$2" | cmp -s - "$1" && rm -f "$1"' roomler-local-marker "$MACOS_DAEMON_MARKER" "$LOCAL_MARKER_TAG"; then
                LOCAL_MARKER_STATE=owned-marker-compensated
            else
                LOCAL_MARKER_STATE=marker-changed-or-retained-inspect
            fi
        fi
        (umask 077; printf 'phase=%s\ncli=%s\npackage=%s\nenrollment=%s\nstartup=%s\nmarker=%s\nos_rollback=false\nrecovery=inspect-native-package-and-service-state-no-blind-uninstall\n' \
            "$LOCAL_PHASE" "$LOCAL_CLI_STATE" "$LOCAL_PACKAGE_STATE" "$LOCAL_ENROLL_STATE" "$LOCAL_STARTUP_STATE" "$LOCAL_MARKER_STATE" > "$STAGE/local-state.txt")
        printf 'LOCAL_INSTALL_INCOMPLETE phase=%s cli=%s package=%s enrollment=%s startup=%s marker=%s os_rollback=false evidence=%s\n' \
            "$LOCAL_PHASE" "$LOCAL_CLI_STATE" "$LOCAL_PACKAGE_STATE" "$LOCAL_ENROLL_STATE" "$LOCAL_STARTUP_STATE" "$LOCAL_MARKER_STATE" "$STAGE" >&2
        # Verified nonsecret snapshots/state remain private for exact recovery.
        # No credentials are persisted; they arrived only over stdin.
    else
        rm -rf "$STAGE"
    fi
}
trap 'finish_install $?' EXIT

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

# Verify a file against a "sha256:<hex>" digest (GitHub asset format).
# Soft-skips when the digest is empty (older releases lack it).
verify_sha256() {
    file="$1"; digest="$2"
    [ -n "$digest" ] || { warn "no sha256 digest published for $(basename "$file") — skipping verification"; return 0; }
    want="$(printf '%s' "$digest" | sed 's/^sha256://')"
    if command -v sha256sum >/dev/null 2>&1; then
        got="$(sha256sum "$file" | awk '{print $1}')"
    else
        got="$(shasum -a 256 "$file" | awk '{print $1}')"
    fi
    if [ "$got" != "$want" ]; then
        echo "error: sha256 mismatch for $file (got $got, want $want)" >&2
        exit 1
    fi
    say "sha256 verified: $(basename "$file")"
}

# Extract "browser_download_url" / "digest" for the first asset whose name
# matches a suffix pattern, from the compact JSON our API emits. grep-based
# so the script has NO jq/python dependency; the serde output has no
# whitespace inside objects, which keeps this reliable.
asset_field_for() {
    json_file="$1"; name_pattern="$2"; field="$3"
    # Objects are comma-separated; split them onto lines first so one
    # grep can anchor name + field within a single asset object.
    tr '{' '\n' < "$json_file" \
        | grep '"name":"[^"]*'"$name_pattern"'"' \
        | grep -o '"'"$field"'":"[^"]*"' \
        | head -n 1 \
        | sed 's/^"'"$field"'":"//; s/"$//'
}

download() {
    url="$1"; out="$2"
    say "downloading $(basename "$out")"
    curl -fsSL -o "$out" "$url"
}

# ─── daemon role ────────────────────────────────────────────────────────────

# A tarball install up to 0.4.126 left these owned by the CI builder (uid
# 1001): the directories the archive carried, and the files it put in them.
# Put root back, PARENT BEFORE CHILD. Once a parent is root's, nothing below it
# can be swapped under this loop, and a symlink or a non-directory where a
# directory belongs stops the descent there.
# The mode the distribution's own package records for a path. Fedora ships
# /usr/bin and /usr/lib 0555, and an archive that rewrote them left 0755. With
# no package database, the repair only takes write away from group and others.
packaged_mode() {
    command -v rpm >/dev/null 2>&1 || return 0
    # ⚠️ For a path no package owns, `rpm -qf` prints "file … is not owned by
    # any package" on STDOUT and exits 1. Measured: without these two guards
    # the repair took "file" for a mode.
    rpm -qf "$1" >/dev/null 2>&1 || return 0
    rpm -qf --qf '[%{FILEMODES:octal} %{FILENAMES}\n]' "$1" 2>/dev/null \
        | awk -v p="$1" '$2 == p && $1 ~ /^[0-7]+$/ { print substr($1, length($1) - 3); exit }'
}

repair_tarball_owners() {
    skip=""
    # RETIRED-NAME-ANCHOR(4): usr/lib/roomler-agent is the binary's RPATH and
    # usr/share/doc/roomler-agent the payload's doc dir: what the tarball puts.
    for d in /usr /usr/bin /usr/lib /usr/lib/roomler-agent /usr/lib/systemd \
             /usr/lib/systemd/system /usr/lib/systemd/user /usr/share \
             /usr/share/doc /usr/share/doc/roomler-agent; do
        for s in $skip; do case "$d" in "$s"/*) continue 2 ;; esac; done
        if [ -L "$d" ] || { [ -e "$d" ] && [ ! -d "$d" ]; }; then
            warn "$d is not a plain directory; leaving it and everything below it"
            skip="$skip $d"
            continue
        fi
        [ -d "$d" ] || continue
        owner="$(stat -c %u:%g "$d")" || { skip="$skip $d"; continue; }
        [ "$owner" = "0:0" ] && continue
        mode="$(packaged_mode "$d")"
        warn "repairing $d: owned by $owner since an earlier tarball install; restoring root:root${mode:+, mode $mode}"
        if [ -n "$mode" ]; then
            sudo chown -h root:root "$d" && sudo chmod "$mode" "$d" || skip="$skip $d"
        else
            sudo chown -h root:root "$d" && sudo chmod go-w "$d" || skip="$skip $d"
        fi
    done
    # RETIRED-NAME-ANCHOR(3): the same two payload dirs, for the files in them.
    for f in /usr/bin/roomlerd /usr/bin/roomler /usr/lib/roomler-agent/* \
             /usr/lib/systemd/system/roomlerd.service /usr/lib/systemd/user/roomler.service \
             /usr/share/doc/roomler-agent/README.Debian; do
        { [ -f "$f" ] && [ ! -L "$f" ]; } || continue
        owner="$(stat -c %u:%g "$f")" || continue
        [ "$owner" = "0:0" ] && continue
        warn "repairing $f: owned by $owner; restoring root:root"
        sudo chown -h root:root "$f" && sudo chmod go-w "$f"
    done
}

# FR-96 — the update half of a per-user install. A per-user daemon runs as the
# user and cannot write /usr, so its updates come from a ROOT one-shot helper
# the package ships disabled: roomler-update.service, woken by
# roomler-update.timer (boot + every 6 h) and roomler-update.path (the file a
# pushed update touches). Enabled ONLY when this release's daemon steps aside
# for it (`update-helper --capabilities` lists `step-aside`): beside a daemon
# that still installs its own updates, two updaters would race. The words are
# pinned by `the_capabilities_are_the_words_install_sh_matches`.
# ⚠️ Every branch here ends in a construct that returns 0: under `set -e` a
# function whose last command fails would abort the whole install.
enable_update_helper() {
    if ! /usr/bin/roomlerd update-helper --capabilities 2>/dev/null | grep -qx 'step-aside'; then
        say "NOTE: this release's daemon cannot hand its updates to the root helper yet, and a per-user daemon cannot install them itself (writing /usr needs root). Re-run this script after the next release, or use --system."
        return 0
    fi
    say "enabling the root update helper (roomler-update.timer + .path — sudo): this daemon's updates install unattended, as root"
    sudo systemctl daemon-reload || true
    if sudo systemctl enable --now roomler-update.timer roomler-update.path; then
        if [ -e /etc/roomler/disable-auto-update ]; then
            say "NOTE: /etc/roomler/disable-auto-update is set: the helper honours it and installs nothing until it is removed"
        fi
    else
        warn "could not enable roomler-update.timer/.path; this daemon's updates stay manual"
    fi
}

# A system install's root daemon installs its own updates, so a helper left
# enabled by an earlier per-user install would race it: one updater per host.
disable_update_helper() {
    for u in roomler-update.timer roomler-update.path; do
        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            say "disabling $u: this system install's root daemon installs its own updates"
            sudo systemctl disable --now "$u" || warn "could not disable $u"
        fi
    done
}

# Whether the helper is on, by the daemon's own test: one of these enable links
# leads to a unit file (`UPDATE_HELPER_ENABLE_LINKS` in updater.rs; a unit test
# pins the list, so the two cannot disagree about who installs).
helper_on() {
    for l in /etc/systemd/system/paths.target.wants/roomler-update.path \
             /etc/systemd/system/timers.target.wants/roomler-update.timer \
             /run/systemd/system/paths.target.wants/roomler-update.path \
             /run/systemd/system/timers.target.wants/roomler-update.timer; do
        [ -e "$l" ] && return 0
    done
    return 1
}

# A re-run finds the per-user daemon already running: on its OLD image, under
# its old unit's sandbox, and with the answer it gave AT ITS START to who
# installs its updates (FR-96 P2a). It is restarted here only when it needs a
# restart and nothing else will give it one:
#   - the same version, and the helper was just turned on: only a restart
#     decides again, and FR-96 P2b does not restart onto the same version;
#   - another version, on a daemon older than P2b. A P2b daemon (it lists
#     `restart-on-replace`; the RUNNING image is asked, through /proc) restarts
#     onto a new version by itself once nothing it serves would be cut, and
#     decides again then.
# The same version with the same helper needs nothing, and a binary that does
# not answer `--version` is never restarted onto (P2b's own rule).
restart_old_user_daemon() {
    pid="$1"; helper_changed="$2"
    case "$pid" in ''|0) return 0 ;; esac
    installed="$(/usr/bin/roomlerd --version 2>/dev/null || true)"
    if [ -z "$installed" ]; then
        warn "/usr/bin/roomlerd --version did not answer; leaving the running daemon (pid $pid) as it is"
        return 0
    fi
    running="$("/proc/$pid/exe" --version 2>/dev/null || true)"
    if [ "$running" = "$installed" ]; then
        if [ "$helper_changed" = 0 ]; then
            say "the running daemon (pid $pid) already runs ${installed#roomlerd }: nothing to restart"
            return 0
        fi
        why="the root update helper was just turned on, and the daemon decides at its start who installs its updates"
    elif "/proc/$pid/exe" update-helper --capabilities 2>/dev/null | grep -qx 'restart-on-replace'; then
        say "the running daemon (pid $pid) restarts onto ${installed#roomlerd } by itself, once nothing it serves would be cut"
        return 0
    else
        rv="${running#roomlerd }"
        why="it runs ${rv:-an unknown version}, which cannot restart onto a new binary by itself"
    fi
    say "restarting the running daemon (pid $pid): $why (a remote or SSH session to this device drops for a few seconds)"
    systemctl --user restart roomler.service || warn "could not restart roomler.service; it runs the new binary from its next start"
}

install_daemon_linux() {
    if [ "$LOCAL_MODE" = 1 ]; then
        fmt=deb
        deb="$LOCAL_PACKAGE"
    else
    releases="$STAGE/releases.json"
    say "resolving latest agent release via $SERVER/api/agent/latest-release"
    curl -fsSL -o "$releases" "$SERVER/api/agent/latest-release"

    # Two axes, same rules as the agent's own updater
    # (docs/linux-self-update.md): the arch we are running, and a format this
    # host can actually install. A .deb needs dpkg/apt — on Fedora / RHEL /
    # SUSE / Arch it downloads and then fails — so those hosts take the
    # self-contained tarball.
    case "$(uname -m)" in
        x86_64|amd64)   arch=x86_64 ;;
        aarch64|arm64)  arch=aarch64 ;;
        *) echo "error: unsupported Linux architecture $(uname -m)" >&2; exit 1 ;;
    esac
    if command -v dpkg >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
        fmt=deb
    else
        fmt=tar.gz
    fi
    say "host: linux/$arch, installing the .$fmt"

    pattern="${arch}-unknown-linux-gnu\\.${fmt}"
    url="$(asset_field_for "$releases" "$pattern" browser_download_url)"
    digest="$(asset_field_for "$releases" "$pattern" digest)"
    if [ -z "$url" ] && [ "$fmt" = deb ]; then
        # A Debian host whose .deb is missing still installs via the tarball
        # rather than treating an absent artifact as a dead end.
        say "no .deb for ${arch} in this release — falling back to the tarball"
        fmt=tar.gz
        pattern="${arch}-unknown-linux-gnu\\.tar\\.gz"
        url="$(asset_field_for "$releases" "$pattern" browser_download_url)"
        digest="$(asset_field_for "$releases" "$pattern" digest)"
    fi
    [ -n "$url" ] || { echo "error: no linux/${arch} .${fmt} asset in the latest agent release" >&2; exit 1; }
    deb="$STAGE/roomlerd.${fmt}"
    download "$url" "$deb"
    verify_sha256 "$deb" "$digest"

    fi

    if [ "$DOWNLOAD_ONLY" = 1 ]; then
        if [ "$fmt" = deb ]; then
            say "download-only: would run: sudo dpkg -i $deb"
        else
            say "download-only: would run: sudo tar -xzf $deb --strip-components=1 -C /"
        fi
        if [ "$SYSTEM" = 1 ]; then
            say "download-only: would run: sudo roomlerd --config $SYSTEM_CONFIG enroll --server $SERVER --token <token> --name $NAME"
            say "download-only: would run: sudo systemctl disable --now roomler-update.timer roomler-update.path (only if a per-user install left them enabled)"
            say "download-only: would run: sudo systemctl enable --now roomlerd.service"
        else
            say "download-only: would run: roomlerd enroll --server $SERVER --token <token> --name $NAME"
            say "download-only: would run: sudo systemctl enable --now roomler-update.timer roomler-update.path (when the release's daemon lists step-aside)"
            say "download-only: would run: systemctl --user enable --now roomler.service"
        fi
        return 0
    fi

    if [ "$fmt" = deb ]; then
        say "installing the roomlerd daemon (.deb — sudo required)"
        if [ "$LOCAL_MODE" = 1 ]; then
            LOCAL_PHASE=package-install; LOCAL_PACKAGE_STATE=attempted
            sudo dpkg -i "$deb" # no package-manager download/fallback in local mode
            LOCAL_PACKAGE_STATE=command-succeeded
        else
            sudo dpkg -i "$deb" || sudo apt-get -f install -y
        fi
    else
        say "installing the roomlerd daemon (tarball — sudo required)"
        # --strip-components=1 drops the versioned prefix dir so the payload
# RETIRED-NAME-ANCHOR: usr/lib/roomler-agent is baked into the binary as an
# RPATH — the directory name cannot move without a relink.
        # lands at /usr/bin, /usr/lib/roomler-agent, /usr/lib/systemd/…
        # (identical to what the .deb installs). On a FIRST install there are
        # no operator-edited units to protect, so unpacking wholesale is fine;
        # the agent's own updater is the path that preserves them on upgrade.
        # ⚠️ --no-same-owner --no-overwrite-dir. GNU tar running as root
        # restores each entry's owner from the archive, and applies a
        # directory entry's metadata to a directory that already exists.
        # Tarballs up to 0.4.126 carried their directories with the CI
        # builder's uid (1001), so this one line made /usr, /usr/bin and
        # /usr/lib the property of whichever local account held that uid.
        sudo tar --no-same-owner --no-overwrite-dir -xzf "$deb" --strip-components=1 -C /
        sudo test -x /usr/bin/roomlerd || { echo "error: tarball did not install /usr/bin/roomlerd" >&2; exit 1; }
        repair_tarball_owners
    fi

    [ "$LOCAL_MODE" != 1 ] || check_local_cli_after_package
    enroll_daemon /usr/bin/roomlerd

    if [ "$SYSTEM" = 1 ]; then
        disable_update_helper
        say "enabling the systemd SYSTEM unit (root: self-update, the overlay TUN, and the desktop of the person on screen)"
        sudo systemctl daemon-reload || true
        if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=systemd-start; LOCAL_STARTUP_STATE=attempted; fi
        sudo systemctl enable --now roomlerd.service
        if [ "$LOCAL_MODE" = 1 ]; then
            sudo systemctl is-active --quiet roomlerd.service
            LOCAL_STARTUP_STATE=command-succeeded
        fi
        say "daemon status: $(sudo systemctl is-active roomlerd.service || true)"
        say "logs: sudo journalctl -u roomlerd.service -f"
    else
        # FR-96 — the helper FIRST: the daemon decides once, at its start,
        # whether it or the helper installs its updates.
        helper_before=0; helper_on && helper_before=1
        enable_update_helper
        helper_after=0; helper_on && helper_after=1
        helper_changed=0; [ "$helper_before" = "$helper_after" ] || helper_changed=1
        say "enabling the systemd user unit (autostart, this login session's user)"
        old_pid="$(systemctl --user show -p MainPID --value roomler.service 2>/dev/null || true)"
        systemctl --user daemon-reload || true
        systemctl --user enable --now roomler.service
        restart_old_user_daemon "$old_pid" "$helper_changed"
        say "daemon status: $(systemctl --user is-active roomler.service || true)"
        # `id -un`, not $USER: nothing sets USER in a container or a service,
        # and under `set -u` this last line then failed an install that had
        # worked (found by the FR-97 P6d cells).
        say "NOTE: on a headless host, run 'sudo loginctl enable-linger $(id -un)' so the user unit runs without an open session."
    fi
}

install_daemon_macos() {
    if [ "$LOCAL_MODE" = 1 ]; then
        pkg="$LOCAL_PACKAGE"
    else
    releases="$STAGE/releases.json"
    say "resolving latest agent release via $SERVER/api/agent/latest-release"
    curl -fsSL -o "$releases" "$SERVER/api/agent/latest-release"
    url="$(asset_field_for "$releases" 'aarch64-apple-darwin[^"]*\.pkg' browser_download_url)"
    digest="$(asset_field_for "$releases" 'aarch64-apple-darwin[^"]*\.pkg' digest)"
    [ -n "$url" ] || { echo "error: no macOS .pkg asset in the latest agent release" >&2; exit 1; }
    pkg="$STAGE/roomlerd.pkg"
    download "$url" "$pkg"
    verify_sha256 "$pkg" "$digest"

    fi

    # The .app kept its legacy internal name through the roomlerd rename —
# RETIRED-NAME-ANCHOR(5): the macOS .app bundle name is FROZEN (FR-21 D5) —
# it keys the host's Screen Recording and Accessibility TCC grants, which a
# rename would silently void, leaving a black screen with no error.
    # CFBundleExecutable is `roomler-agent`, and CI asserts it, because
    # renaming would change the binary's TCC identity and force every existing
    # Mac to re-grant Screen Recording and Accessibility. The old probe led
    # with `roomlerd`, which never exists, and relied on the fallback.
    daemon_bin="/Library/Roomler/roomlerd.app/Contents/MacOS/roomlerd"

    if [ "$DOWNLOAD_ONLY" = 1 ]; then
        say "download-only: would run: sudo installer -pkg $pkg -target /"
        say "download-only: would run: $daemon_bin enroll --server $SERVER --token <token> --name $NAME"
        [ -n "$DAEMON_TOKEN" ] && say "download-only: would also enroll the privileged half at $MACOS_DAEMON_CONFIG"
        return 0
    fi

    # The marker has to exist BEFORE the pkg runs: the postinstall reads it to
    # decide whether to install the root LaunchDaemon, and its ABSENCE actively
    # removes a previously-installed one. Nothing in the product ever created
    # this file, which is why the privileged half was unreachable through the
    # advertised one-liner despite shipping for months.
    if [ -n "$DAEMON_TOKEN" ]; then
        say "requesting the privileged half (root LaunchDaemon — the overlay needs root)"
        if [ "$LOCAL_MODE" = 1 ]; then
            LOCAL_PHASE=backend-marker
            if sudo test -e "$MACOS_DAEMON_MARKER"; then
                LOCAL_MARKER_STATE=preexisting-preserved
            else
                LOCAL_MARKER_TAG="roomler-local-$$-$(basename "$STAGE")"
                sudo mkdir -p "$(dirname "$MACOS_DAEMON_MARKER")"
                sudo /bin/sh -c 'umask 077; set -C; printf "%s\n" "$2" > "$1"' roomler-local-marker "$MACOS_DAEMON_MARKER" "$LOCAL_MARKER_TAG"
                LOCAL_MARKER_STATE=owned-created
            fi
        else
            sudo mkdir -p "$(dirname "$MACOS_DAEMON_MARKER")"
            sudo touch "$MACOS_DAEMON_MARKER"
        fi
    fi

    say "installing the roomler agent (.pkg — sudo required)"
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=package-install; LOCAL_PACKAGE_STATE=attempted; fi
    sudo installer -pkg "$pkg" -target /
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PACKAGE_STATE=command-succeeded; fi

    [ -x "$daemon_bin" ] || {
        echo "error: the package did not install $daemon_bin" >&2
        exit 1
    }

    [ "$LOCAL_MODE" != 1 ] || check_local_cli_after_package
    # ── the per-user half: capture + input, inside the GUI session ──
    enroll_daemon "$daemon_bin"

    # postinstall bootstrapped com.roomler.agent into the CONSOLE user's gui
    # domain, so kickstart it THERE. `gui/$(id -u)` was wrong under sudo — uid
    # 0 has no Aqua domain, the error went to /dev/null, and the warning that
    # replaced it ("will pick up the config at next login") was misleading.
    say "restarting the LaunchAgent so it picks up the enrollment"
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=launchagent-start; LOCAL_STARTUP_STATE=attempted; fi
    if ! launchctl kickstart -k "gui/$CONSOLE_UID/com.roomler.agent" 2>/dev/null; then
        [ "$LOCAL_MODE" != 1 ] || { echo "error: local LaunchAgent startup failed" >&2; exit 1; }
        warn "launchctl kickstart failed — the agent will pick up the config at next login"
    fi
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_STARTUP_STATE=user-command-succeeded; fi

    # ── the privileged half: overlay/mesh, as root, its own enrollment ──
    if [ -n "$DAEMON_TOKEN" ]; then
        install_macos_privileged_half "$daemon_bin"
    else
        say "NOTE: this Mac has the per-user half only — screen sharing works, the overlay"
        say "      mesh does not (creating a utun needs root). Pass --daemon-token <a second"
        say "      enrollment token> to add the privileged half."
    fi

    macos_permissions_notice
}

# The root half. A SEPARATE enrollment by construction: the hub keys sessions
# on agent_id, so two processes sharing one identity would fight over the
# control WS — the second connection displaces the first.
install_macos_privileged_half() {
    daemon_bin="$1"

    if [ ! -f /Library/LaunchDaemons/com.roomler.daemon.plist ]; then
        [ "$LOCAL_MODE" != 1 ] || { echo "error: local package omitted the privileged backend" >&2; exit 1; }
        warn "the package did not install the LaunchDaemon — skipping the privileged half"
        return 0
    fi

    if sudo test -f "$MACOS_DAEMON_CONFIG"; then
        say "privileged half already enrolled at $MACOS_DAEMON_CONFIG — leaving it alone"
    else
        # `--overlay` writes overlay_enabled with the rest of the enrolled
        # config. The overlay is the ONLY reason this half exists, and choosing
        # to install a root daemon IS the opt-in, so it would be perverse to
        # leave the operator hunting for a config key afterwards.
        # (`overlay_enabled` stays default-off everywhere else — unchanged.)
        say "enrolling the privileged half as '$NAME-daemon' (second single-use token, overlay on)"
        # The install trace rides the environment (see `install_trace`): a
        # root LaunchDaemon is the `system` scope.
        # shellcheck disable=SC2046
        if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=backend-enrollment; LOCAL_ENROLL_STATE=backend-attempted; fi
        sudo $(install_trace system) "$daemon_bin" --config "$MACOS_DAEMON_CONFIG" \
            enroll --server "$SERVER" --token "$DAEMON_TOKEN" --name "$NAME-daemon" --overlay
        if [ "$LOCAL_MODE" = 1 ]; then LOCAL_ENROLL_STATE=backend-command-succeeded; fi
    fi

    say "starting the privileged half"
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=launchdaemon-start; LOCAL_STARTUP_STATE=backend-attempted; fi
    if ! sudo launchctl kickstart -k system/com.roomler.daemon 2>/dev/null; then
        [ "$LOCAL_MODE" != 1 ] || { echo "error: local privileged backend startup failed" >&2; exit 1; }
        warn "launchctl kickstart failed for the daemon — it will start at next boot"
    fi
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_STARTUP_STATE=command-succeeded; fi
}

# macOS grants these two by hand, per binary, and never errors when they are
# missing: capture silently returns wallpaper-only frames and injected input is
# silently dropped. The agent logs both, but to a file under /tmp that nobody
# is told about — so say it here, where the person installing is still looking.
macos_permissions_notice() {
    say ""
    say "ONE MANUAL STEP REMAINS — macOS will not grant these without you:"
# RETIRED-NAME-ANCHOR(2): this is the string macOS SHOWS in the privacy pane;
# it comes from the frozen bundle, so it must match what the user will see.
    say "  System Settings → Privacy & Security → Screen Recording  → enable 'roomler-agent'"
    say "  System Settings → Privacy & Security → Accessibility     → enable 'roomler-agent'"
    say ""
    say "Without Screen Recording the remote screen is blank; without Accessibility the"
    say "remote keyboard and mouse do nothing. Neither reports an error. After granting:"
    say "  launchctl kickstart -k gui/$CONSOLE_UID/com.roomler.agent"
}

# FR-102 — the install trace: tell the server HOW this install happened, so
# the device row carries `install: {method: script-sh, scope: …}`. Through the
# ENVIRONMENT, never the `--install-method` flag: this script installs whatever
# release is current, and a daemon from before that flag existed refuses an
# argument it does not know — the enrollment would fail on every host until
# the next agent release. An older daemon simply ignores the variables. `env`
# carries the pair across `sudo`, which may strip `VAR=value` words from the
# command line depending on the sudoers policy.
install_trace() {
    echo "env ROOMLER_INSTALL_METHOD=script-sh ROOMLER_INSTALL_SCOPE=$1"
}

enroll_daemon() {
    daemon_bin="$1"
    # --system enrolls as root into the machine-global path the system unit
    # runs with; the per-user flow keeps the caller's own profile.
    if [ "$SYSTEM" = 1 ]; then
        enroll_sudo="sudo"
        enroll_bin="$daemon_bin --config $SYSTEM_CONFIG"
        enroll_trace="$(install_trace system)"
    elif [ "$OS" = Darwin ] && [ "$(id -u)" = 0 ]; then
        # See `as_console_user`: the LaunchAgent runs as the console user and
        # reads that user's config, so the enroll has to write it AS them.
        # Running it as root here is what silently broke the whole install.
        enroll_sudo="sudo -H -u $CONSOLE_USER"
        enroll_bin="$daemon_bin"
        enroll_trace="$(install_trace per-user)"
    else
        enroll_sudo=""
        enroll_bin="$daemon_bin"
        enroll_trace="$(install_trace per-user)"
    fi
    if [ "$NO_ENROLL" = 1 ] || [ -z "$TOKEN" ]; then
        [ "$NO_ENROLL" = 1 ] || warn "no --token given — skipping enrollment"
        say "enroll later with: $enroll_sudo $enroll_bin enroll --server $SERVER --token <agent-enrollment-jwt> --name \"$NAME\""
        return 0
    fi
    say "enrolling this machine as '$NAME' against $SERVER (token is single-use, never echoed)"
    # Unquoted on purpose: these are word lists we built ourselves (sudo,
    # env + two VAR=value words, binary + --config + path), none of which
    # contain whitespace.
    # shellcheck disable=SC2086
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_PHASE=enrollment; LOCAL_ENROLL_STATE=attempted; fi
    if [ "$LOCAL_MODE" = 1 ] && [ "$SYSTEM" = 1 ]; then
        $enroll_sudo $enroll_trace $enroll_bin enroll --server "$SERVER" --token "$TOKEN" --name "$NAME" --overlay
    else
        $enroll_sudo $enroll_trace $enroll_bin enroll --server "$SERVER" --token "$TOKEN" --name "$NAME"
    fi
    if [ "$LOCAL_MODE" = 1 ]; then LOCAL_ENROLL_STATE=user-command-succeeded; fi
}

# ─── tunnel role ────────────────────────────────────────────────────────────

install_tunnel_linux() {
    # FR-97 P7b — the build for this host's arch. The x86_64 names are the
    # proxy's first ones (`linux-x86_64`, `linux-deb`), kept as they were.
    # Before P7b every host got the x86_64 build: on aarch64, dpkg refused the
    # package for its architecture and the tarball's binary could not run.
    case "$(uname -m)" in
        x86_64|amd64)   tunnel_tar=linux-x86_64;  tunnel_deb=linux-deb ;;
        aarch64|arm64)  tunnel_tar=linux-aarch64; tunnel_deb=linux-deb-aarch64 ;;
        *) echo "error: unsupported Linux architecture $(uname -m)" >&2; exit 1 ;;
    esac
    # aarch64 builds start with the first tunnel release that has them; before
    # it the proxy answers 404, which on its own says nothing.
    if [ "$tunnel_tar" = linux-aarch64 ] &&
        ! curl -fs -o /dev/null "$SERVER/api/tunnel/installer/linux-aarch64/health?version=latest"; then
        echo "error: $SERVER serves no aarch64 build of the roomler CLI yet (its latest tunnel release has none)" >&2
        exit 1
    fi
    if command -v dpkg >/dev/null 2>&1; then
        deb="$STAGE/roomler-cli.deb"
        say "downloading the roomler CLI (.deb, $tunnel_deb) via the proxy"
        download "$SERVER/api/tunnel/installer/$tunnel_deb?version=latest" "$deb"
        if [ "$DOWNLOAD_ONLY" = 1 ]; then
            say "download-only: would run: sudo dpkg -i $deb (the tarball instead, if its dependencies cannot be met here)"
            return 0
        fi
        sudo dpkg -i "$deb" || sudo apt-get -f install -y
        # #2472 — a .deb whose dependencies this distro cannot meet is REMOVED
        # again by `apt-get -f`, and nothing is installed: tunnel-v0.3.0-rc.266
        # wants libssl3t64, which Debian 12 and Ubuntu 22.04 call libssl3. The
        # tarball needs only libssl.so.3, which both ship.
        if ! tunnel_cli_runs; then
            warn "the .deb did not install here (its dependencies cannot be met on this distro) — installing the tarball instead"
            tarball="$STAGE/roomler-cli.tar.gz"
            download "$SERVER/api/tunnel/installer/$tunnel_tar?version=latest" "$tarball"
            install_tunnel_tarball "$tarball"
        fi
    else
        tarball="$STAGE/roomler-cli.tar.gz"
        say "downloading the roomler CLI (tarball, $tunnel_tar) via the proxy"
        download "$SERVER/api/tunnel/installer/$tunnel_tar?version=latest" "$tarball"
        if [ "$DOWNLOAD_ONLY" = 1 ]; then
            say "download-only: would extract to /usr/local/bin"
            return 0
        fi
        install_tunnel_tarball "$tarball"
    fi
    require_tunnel_cli
    enroll_tunnel
}

install_tunnel_macos() {
    tarball="$STAGE/roomler-cli.tar.gz"
    say "downloading the roomler CLI (universal tarball) via the proxy"
    download "$SERVER/api/tunnel/installer/macos?version=latest" "$tarball"
    if [ "$DOWNLOAD_ONLY" = 1 ]; then
        say "download-only: would extract to /usr/local/bin"
        return 0
    fi
    install_tunnel_tarball "$tarball"
    require_tunnel_cli
    enroll_tunnel
}

# Does the installed CLI run here? `command -v` alone is not enough: a binary
# for another architecture, or one missing a library, is on PATH too.
tunnel_cli_runs() {
    cli="$(command -v roomler || true)"
    [ -n "$cli" ] && "$cli" --version >/dev/null 2>&1
}

# #2472 — never say "done" with nothing installed.
require_tunnel_cli() {
    if ! tunnel_cli_runs; then
        echo "error: the roomler CLI did not install: no working \`roomler\` on PATH" >&2
        exit 1
    fi
    say "installed: $(roomler --version 2>/dev/null | head -n 1)"
}

install_tunnel_tarball() {
    tarball="$1"
    xdir="$STAGE/tunnel"
    mkdir -p "$xdir"
    tar -xzf "$tarball" -C "$xdir"
    # Archives ship BOTH names since the P3d rename; prefer `roomler`.
    bin=""
# RETIRED-NAME-ANCHOR-BEGIN
# The tunnel CLI is installed on hosts that predate the rename, so the archive
# may carry either name and an existing `roomler-tunnel` on PATH must keep
# working. The symlink below is that compatibility promise, not a leftover.
    for name in roomler roomler-tunnel; do
        found="$(find "$xdir" -maxdepth 2 -type f -name "$name" | head -n 1)"
        [ -n "$found" ] && { bin="$found"; break; }
    done
    [ -n "$bin" ] || { echo "error: no roomler/roomler-tunnel binary in the archive" >&2; exit 1; }
    say "installing $(basename "$bin") to /usr/local/bin/roomler (sudo required)"
    sudo install -m 755 "$bin" /usr/local/bin/roomler
    # Legacy-name convenience symlink, matching the archives' compat alias.
    sudo ln -sf /usr/local/bin/roomler /usr/local/bin/roomler-tunnel
}

enroll_tunnel() {
    cli="$(command -v roomler || command -v roomler-tunnel || true)"
# RETIRED-NAME-ANCHOR-END
    [ -n "$cli" ] || cli=/usr/local/bin/roomler
    if [ "$NO_ENROLL" = 1 ] || [ -z "$TOKEN" ]; then
        [ "$NO_ENROLL" = 1 ] || warn "no --token given — skipping enrollment"
        say "enroll later with: $cli enroll --server $SERVER --token <tunnel-enrollment-jwt> --name \"$NAME\""
        return 0
    fi
    say "enrolling this tunnel client as '$NAME' against $SERVER (token is single-use, never echoed)"
    "$cli" enroll --server "$SERVER" --token "$TOKEN" --name "$NAME"
}

# FR-93 P6d — the tool that installs a local .rpm and resolves its
# dependencies from the distro's repositories; nothing when there is none.
desktop_rpm_tool() {
    for t in dnf zypper yum; do
        if command -v "$t" >/dev/null 2>&1; then
            echo "$t"
            return 0
        fi
    done
    return 1
}

# Install a downloaded companion package with this host's package manager.
desktop_install() {
    case "$1" in
        *.deb)
            # `apt-get -f install` pulls webkit2gtk / GTK / appindicator when
            # dpkg reports them missing, which on a fresh desktop it usually will.
            sudo dpkg -i "$1" || sudo apt-get -f install -y
            ;;
        *.rpm)
            # The package is ours and its sha256 is checked by the caller;
            # zypper alone refuses an unsigned local package without being told.
            case "$(desktop_rpm_tool)" in
                dnf) sudo dnf install -y "$1" ;;
                zypper) sudo zypper --non-interactive install --allow-unsigned-rpm "$1" ;;
                yum) sudo yum install -y "$1" ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

# FR-27 — the Linux desktop companion, from its OWN package: a .deb, or an
# .rpm on the hosts with no dpkg (FR-93 P6d).
#
# A SEPARATE package on purpose: the daemon .deb installs on headless nodes
# across the fleet, and folding webkit2gtk + GTK into it to ship a menu-bar app
# they cannot display would be a real regression for them.
#
# Installed by default when this box has a graphical session, because the
# companion IS the consent prompt surface — a device set to "Prompt on host"
# without one cannot ask anybody, and the operator only finds out when a
# session times out for no stated reason.
#
# Never fatal. A daemon with no companion is still a working daemon; it just
# has no on-screen way to answer a prompt, which this says out loud.
#
# Reads `arch` and `releases` from install_daemon_linux, which always runs
# first (the case dispatch below calls them in that order).
install_desktop_linux() {
    if [ "$DESKTOP" = 0 ]; then
        say "skipping the desktop companion (--no-desktop)"
        return 0
    fi
    if [ -z "$DESKTOP" ]; then
        # Probe, don't ask. A display or a login session is the honest signal
        # that someone could SEE a prompt on this box.
        if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ] &&
            ! { command -v loginctl >/dev/null 2>&1 &&
                loginctl list-sessions --no-legend 2>/dev/null | grep -q .; }; then
            say "no graphical session detected — skipping the desktop companion (--desktop forces it)"
            return 0
        fi
    fi
    # FR-93 P6d — a dpkg host takes the .deb; an RPM host (Fedora, the RHEL
    # family, openSUSE) the .rpm. Either way the host's own package manager
    # pulls webkit2gtk, GTK and the tray library from the distro's repositories.
    if command -v dpkg >/dev/null 2>&1; then
        desktop_ext=deb
    elif command -v rpm >/dev/null 2>&1 && desktop_rpm_tool >/dev/null; then
        desktop_ext=rpm
    else
        say "no dpkg and no dnf/zypper/yum here — the desktop companion ships as a .deb and an .rpm; skipping"
        return 0
    fi

    desktop_pattern="roomler-desktop-.*${arch}-unknown-linux-gnu\\.${desktop_ext}"
    desktop_url="$(asset_field_for "$releases" "$desktop_pattern" browser_download_url)"
    if [ -z "$desktop_url" ]; then
        say "no roomler-desktop .${desktop_ext} for ${arch} in this release — skipping the companion"
        return 0
    fi
    desktop_digest="$(asset_field_for "$releases" "$desktop_pattern" digest)"
    desktop_pkg="$STAGE/roomler-desktop.${desktop_ext}"
    download "$desktop_url" "$desktop_pkg"
    verify_sha256 "$desktop_pkg" "$desktop_digest"

    if [ "$DOWNLOAD_ONLY" = 1 ]; then
        if [ "$desktop_ext" = deb ]; then
            say "download-only: would run: sudo dpkg -i $desktop_pkg"
        else
            say "download-only: would run: sudo $(desktop_rpm_tool) install $desktop_pkg"
        fi
        return 0
    fi
    say "installing the roomler-desktop companion (.${desktop_ext} — sudo required)"
    if desktop_install "$desktop_pkg"; then
        # FR-84 D6 — the daemon (started above) watches for the companion and
        # opens it once, with the Welcome tour, in the logged-in graphical
        # session; the package's XDG entry starts it at every later login.
        say "desktop companion installed — the Roomler service opens it on this screen within a few"
        say "  seconds (the Welcome tour), or at the next login if nobody is signed in graphically."
    else
        warn "the desktop companion did not install; the daemon is unaffected."
        warn "  Without it this device has no on-screen consent prompt — use"
        warn "  'roomler consent --list' / '--approve', or set it to email/push consent."
    fi
}

# ─── uninstall (FR-97 P6d) ──────────────────────────────────────────────────
#
# `--uninstall` removes what any install path put on this machine: this
# script, the .deb, the tarball, the companion's .rpm, the .pkg, the tunnel
# CLI. Every step acts only on what is there, so it works on a partial
# install, on one made by hand, and when run twice. The Windows twin is
# `install.ps1 -Uninstall`.
#
# The ORDER is the design:
#   1. Every service stops THROUGH ITS MANAGER while its files are still on
#      disk. The stop is a SIGTERM, the daemon's clean stop: it takes back the
#      exit routes and the DNS steer it put in the host (FR-97 P0e), and an
#      ephemeral device unenrolls itself. Delete the files first and nothing
#      that would heal the host at its next boot is left installed. A daemon
#      no manager owns (started by hand, or an orphan) gets the same SIGTERM;
#      one that ignores it is reported, never SIGKILLed, which would skip the
#      very cleanup this order exists for. (The companion, a UI with nothing
#      to clean up, is killed if it outlives its SIGTERM.)
#   2. The packages, then what a tarball put down (only files no package
#      owns), then the login registrations of EVERY account: a LaunchAgent
#      left behind is respawned against a missing binary at every login.
#   3. Unless --keep-config, the config. It holds the device's credential,
#      and an uninstall that leaves a live token on disk is not one. Only the
#      trees of the account running this (the one behind sudo; on a Mac also
#      the console user) and root's; another account's are listed, not removed.
#   4. "done" only if every step held. Otherwise each failure is named, and
#      the exit status is 1.
#
# It cannot revoke the device. A permanent device may not remove itself from
# the server (only an ephemeral one may, in step 1), so the last line says how.

UNINSTALL_FAILED=""

# Recorded, never fatal: one part that will not go must not keep the rest on
# disk. The summary names every one.
uninstall_failed() {
    warn "$*"
    UNINSTALL_FAILED="$UNINSTALL_FAILED
  - $*"
}

# Root for one command: directly when this already is root (a container has
# no sudo), else through sudo.
as_root() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# Relay a privileged helper's report: every line said, every FAILED line
# recorded as a failure.
relay() {
    while IFS= read -r line; do
        case "$line" in
            '') ;;
            FAILED\ *) uninstall_failed "could not ${line#FAILED }" ;;
            *) say "$line" ;;
        esac
    done <<EOF
$1
EOF
}

# Run a small script as root, ONE privileged call for a whole list (a home
# this account cannot read is then no obstacle), and relay its report.
root_helper() {
    script="$1"; shift
    rc=0
    out="$(as_root sh -c "$script" sh "$@" 2>&1)" || rc=$?
    relay "$out"
    [ "$rc" = 0 ] || uninstall_failed "run a privileged step (exit $rc)"
}

# Remove each path given that exists: a file, a link or a whole directory.
# Every caller passes a fixed Roomler name, absolute or under a home.
remove_paths() {
    [ $# -gt 0 ] || return 0
    # shellcheck disable=SC2016 # the script expands as root, not here
    root_helper 'for p do
        if [ -L "$p" ] || [ -e "$p" ]; then
            if rm -rf -- "$p"; then echo "removed $p"; else echo "FAILED remove $p"; fi
        fi
    done' "$@"
}

# Every local account as "name home", root included. A macOS service account
# (`_name`) never holds an install.
local_accounts() {
    if [ "$OS" = Darwin ]; then
        dscl . -list /Users NFSHomeDirectory 2>/dev/null |
            awk 'NF == 2 && $1 !~ /^_/ { print $1, $2 }'
    else
        awk -F: '$6 ~ /^\/./ { print $1, $6 }' /etc/passwd 2>/dev/null
    fi
}

home_of() {
    if [ "$OS" = Darwin ]; then
        dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{ print $2; exit }'
    else
        getent passwd "$1" 2>/dev/null | cut -d: -f6
    fi
}

# The accounts whose own install this removes, config included: the caller,
# or the account behind sudo; on a Mac also the console user, who runs the
# per-user half. Root's trees go with the system's.
uninstall_accounts() {
    {
        if [ "$(id -u)" != 0 ]; then
            id -un
        elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
            echo "$SUDO_USER"
        fi
        if [ "$OS" = Darwin ]; then
            c="$(stat -f %Su /dev/console 2>/dev/null || true)"
            if [ -n "$c" ] && [ "$c" != root ]; then echo "$c"; fi
        fi
    } | awk '!seen[$0]++'
}

# One account's config and state trees: the daemon's (its companion's state
# lives in it too), the portal's restore token, the tunnel CLI's.
account_config_paths() {
    h="$1"
    case "$h" in ''|/) return 0 ;; esac
    if [ "$OS" = Darwin ]; then
        echo "$h/Library/Application Support/live.roomler.roomler"
        # RETIRED-NAME-ANCHOR(2): the tunnel CLI's config segment is still the
        # old name (roomler-cli config.rs), and a pre-rename daemon tree may
        # still hold an enrolled credential: skipping either leaves a live token.
        echo "$h/Library/Application Support/ai.roomler.roomler-tunnel"
        echo "$h/Library/Application Support/live.roomler.roomler-agent"
    else
        echo "$h/.config/roomler"
        echo "$h/.local/share/roomler"
        echo "$h/.local/state/roomler"
        # RETIRED-NAME-ANCHOR(3): as above — the tunnel CLI's current config
        # segment, then the two pre-rename daemon trees.
        echo "$h/.config/roomler-tunnel"
        echo "$h/.config/roomler-agent"
        echo "$h/.local/share/roomler-agent"
    fi
}

# Run `remove_paths` over newline-separated paths (a macOS path has a space).
remove_listed() {
    listed="$1"
    set --
    while IFS= read -r p; do
        if [ -n "$p" ]; then set -- "$@" "$p"; fi
    done <<EOF
$listed
EOF
    remove_paths "$@"
}

# The pids of every process with exactly this name. A minimal container has
# no procps, so read /proc there.
find_procs() {
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -x "$1" 2>/dev/null || true
    elif [ -d /proc ]; then
        for d in /proc/[0-9]*; do
            if [ "$(cat "$d/comm" 2>/dev/null || true)" = "$1" ]; then echo "${d#/proc/}"; fi
        done
    fi
}

describe_proc() {
    if command -v ps >/dev/null 2>&1; then
        ps -o user=,command= -p "$1" 2>/dev/null || true
    else
        tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true
    fi
}

# Wait up to $2 seconds for every process named $1 to be gone.
procs_gone_within() {
    n=0
    while [ -n "$(find_procs "$1")" ]; do
        n=$((n + 1))
        [ "$n" -ge "$2" ] && return 1
        sleep 1
    done
    return 0
}

# Step 1's sweep: what still runs once every manager has stopped its own.
# $2 is the grace a manager's own stop gets first: `launchctl bootout` returns
# while the job is still draining, where systemd's stop has already waited.
# Then the same SIGTERM. The daemon is never SIGKILLed: that would skip its
# cleanup, so a survivor is reported. The companion is a UI with nothing to
# clean up, so a straggler is killed, as the .pkg postinstall does.
stop_leftovers() {
    name="$1"; grace="$2"
    procs_gone_within "$name" "$grace" && return 0
    for pid in $(find_procs "$name"); do
        say "stopping $name pid $pid, which no service manager stopped: $(describe_proc "$pid")"
        as_root kill -TERM "$pid" 2>/dev/null || true
    done
    procs_gone_within "$name" 30 && return 0
    for pid in $(find_procs "$name"); do
        if [ "$name" = roomler-desktop ]; then
            warn "$name pid $pid outlived its SIGTERM by 30 s; killing it (a UI, nothing to clean up)"
            as_root kill -KILL "$pid" 2>/dev/null || true
        else
            uninstall_failed "stop $name pid $pid within 30 s of a SIGTERM: $(describe_proc "$pid")"
        fi
    done
    if [ "$name" = roomler-desktop ] && ! procs_gone_within "$name" 5; then
        uninstall_failed "stop $name: it outlived a SIGKILL"
    fi
}

# Step 3's honesty: the config another account still holds, listed.
report_other_config() {
    targets=" $(printf '%s\n' "$1" | tr '\n' ' ') "
    list=""
    while read -r name home; do
        [ "$name" = root ] && continue
        case "$targets" in *" $name "*) continue ;; esac
        list="$list
$(account_config_paths "$home")"
    done <<EOF
$(local_accounts)
EOF
    set --
    while IFS= read -r p; do
        if [ -n "$p" ]; then set -- "$@" "$p"; fi
    done <<EOF
$list
EOF
    [ $# -gt 0 ] || return 0
    # shellcheck disable=SC2016 # the script expands as root, not here
    left="$(as_root sh -c 'for p do if [ -e "$p" ]; then echo "  $p"; fi; done' sh "$@" 2>/dev/null || true)"
    if [ -n "$left" ]; then
        say "NOTE: other accounts' Roomler config is left in place (each holds that account's own device credential):"
        printf '%s\n' "$left"
        say "      Remove it as that account, or as root."
    fi
}

# ── Linux ──

# The per-user unit is in the account's own systemd, reachable on that
# account's bus: directly when this IS that account, else as root on
# /run/user/<uid>/bus, which exists while its manager runs.
user_systemctl() {
    u="$1"; shift
    uid="$(id -u "$u" 2>/dev/null)" || return 1
    if [ "$(id -u)" = "$uid" ]; then
        systemctl --user "$@"
    elif [ "$(id -u)" = 0 ] && [ -S "/run/user/$uid/bus" ]; then
        runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user "$@"
    else
        return 1
    fi
}

# Stop (and disable) one unit if this host has it. An absent unit, and a
# masked or disabled one that is not running, are left alone. "Running"
# includes `activating`: a unit waiting out its RestartSec starts again
# unless it is stopped.
stop_unit() {
    who="$1"; unit="$2"
    if [ "$who" = system ]; then
        st="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        state="$(systemctl show -p ActiveState --value "$unit" 2>/dev/null || true)"
    else
        st="$(user_systemctl "$who" is-enabled "$unit" 2>/dev/null || true)"
        state="$(user_systemctl "$who" show -p ActiveState --value "$unit" 2>/dev/null || true)"
    fi
    case "$st" in
        enabled*|linked*|alias|indirect) verb="disable --now" ;;
        *)
            case "$state" in
                active|activating|deactivating|reloading) verb=stop ;;
                *) return 0 ;;
            esac
            ;;
    esac
    label="$unit"; [ "$who" = system ] || label="$who's $unit"
    say "stopping $label"
    if [ "$who" = system ]; then
        # shellcheck disable=SC2086
        as_root systemctl $verb "$unit" >/dev/null 2>&1 || uninstall_failed "stop $label"
    else
        # shellcheck disable=SC2086
        user_systemctl "$who" $verb "$unit" >/dev/null 2>&1 || uninstall_failed "stop $label"
    fi
}

# Every account with a running user manager, as names. Root reaches each one;
# any other caller only its own.
accounts_with_a_user_manager() {
    if [ "$(id -u)" = 0 ]; then
        for d in /run/user/[0-9]*; do
            [ -S "$d/bus" ] || continue
            getent passwd "${d#/run/user/}" 2>/dev/null | cut -d: -f1
        done
    else
        id -un
    fi
}

uninstall_stop_linux() {
    if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
        say "no systemd running here: no service to stop through it"
        return 0
    fi
    # The update half first, so nothing begins an install under us; then let
    # a helper run already in flight finish, because killing it mid-install
    # would leave dpkg holding a half-installed package for step 2.
    stop_unit system roomler-update.timer
    stop_unit system roomler-update.path
    n=0
    while [ "$(systemctl show -p SubState --value roomler-update.service 2>/dev/null || true)" = start ]; do
        [ "$n" = 0 ] && say "waiting for roomler-update.service to finish: it is installing an update"
        n=$((n + 1))
        [ "$n" -ge 300 ] && { warn "roomler-update.service still runs after 300 s; stopping it"; break; }
        sleep 1
    done
    stop_unit system roomler-update.service
    stop_unit system roomlerd.service
    for acct in $(accounts_with_a_user_manager); do
        stop_unit "$acct" roomler.service
    done
}

remove_packages_linux() {
    if command -v dpkg-query >/dev/null 2>&1; then
        pkgs=""
        # Dependents first: the companion depends on the daemon. Then the
        # tunnel CLI.
        # RETIRED-NAME-ANCHOR: the last two are the packages the daemon's .deb
        # took over (Cargo.toml `replaces`); a host that had them keeps their
        # dpkg entries until they are removed by name.
        for p in roomler-desktop roomlerd roomler-cli roomler-tunnel roomler-agent; do
            # The status letter: i installed, c only its config left, n none.
            case "$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | cut -c2 || true)" in
                ''|n) ;;
                c) [ "$KEEP_CONFIG" = 1 ] || pkgs="$pkgs $p" ;;
                *) pkgs="$pkgs $p" ;;
            esac
        done
        if [ -n "$pkgs" ]; then
            mode=--purge
            [ "$KEEP_CONFIG" = 1 ] && mode=--remove
            say "removing the packages:$pkgs (dpkg $mode)"
            # shellcheck disable=SC2086
            as_root dpkg "$mode" $pkgs || uninstall_failed "remove the packages:$pkgs (dpkg $mode)"
        fi
    fi
    if command -v rpm >/dev/null 2>&1 && rpm -q roomler-desktop >/dev/null 2>&1; then
        say "removing the roomler-desktop package (rpm)"
        as_root rpm -e roomler-desktop || uninstall_failed "remove the roomler-desktop package (rpm -e)"
    fi
}

# What a tarball put down (scripts/stage-linux-tarball.sh, and the tunnel
# CLI's /usr/local/bin), where no package owns it: a path a package still owns
# is that package's to remove.
remove_tarball_linux() {
    set --
    # RETIRED-NAME-ANCHOR(5): the tarball's lib dir is the binary's RPATH and
    # its doc dir the payload's (as in repair_tarball_owners); roomler-tunnel
    # is the CLI's legacy-name symlink, which install_tunnel_tarball creates.
    for f in /usr/bin/roomlerd /usr/bin/roomler /usr/lib/roomler-agent \
             /usr/lib/systemd/system/roomlerd.service /usr/lib/systemd/user/roomler.service \
             /usr/lib/systemd/system/roomler-update.service /usr/lib/systemd/system/roomler-update.timer \
             /usr/lib/systemd/system/roomler-update.path /usr/share/doc/roomler-agent \
             /usr/local/bin/roomler /usr/local/bin/roomler-tunnel; do
        { [ -L "$f" ] || [ -e "$f" ]; } || continue
        owner=""
        if command -v dpkg >/dev/null 2>&1; then
            owner="$(dpkg -S "$f" 2>/dev/null | head -n 1 | cut -d: -f1 || true)"
        fi
        if [ -z "$owner" ] && command -v rpm >/dev/null 2>&1 && rpm -qf "$f" >/dev/null 2>&1; then
            owner="$(rpm -qf "$f" 2>/dev/null | head -n 1 || true)"
        fi
        if [ -n "$owner" ]; then
            warn "leaving $f: the package $owner owns it"
            continue
        fi
        set -- "$@" "$f"
    done
    remove_paths "$@"
}

# Login registrations, for every account: they name a program that is gone.
# The per-user unit's enable links (its WantedBy), and the companion's own
# autostart entry, only where it is ours (`X-Roomler-Managed`).
remove_registrations_linux() {
    links=""
    entries=""
    while read -r name home; do
        case "$home" in ''|/) continue ;; esac
        links="$links
$home/.config/systemd/user/default.target.wants/roomler.service
$home/.config/systemd/user/graphical-session.target.wants/roomler.service"
        entries="$entries
$home/.config/autostart/roomler-desktop.desktop"
    done <<EOF
$(local_accounts)
EOF
    remove_listed "$links"
    set --
    while IFS= read -r p; do
        if [ -n "$p" ]; then set -- "$@" "$p"; fi
    done <<EOF
$entries
EOF
    # shellcheck disable=SC2016 # the script expands as root, not here
    root_helper 'for p do
        if grep -qs "X-Roomler-Managed=true" "$p"; then
            if rm -f -- "$p"; then echo "removed $p"; else echo "FAILED remove $p"; fi
        fi
    done' "$@"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        as_root systemctl daemon-reload >/dev/null 2>&1 || true
        for acct in $(accounts_with_a_user_manager); do
            user_systemctl "$acct" daemon-reload >/dev/null 2>&1 || true
        done
    fi
}

uninstall_linux() {
    uninstall_stop_linux
    # No grace: every stop above has already waited for its unit.
    stop_leftovers roomlerd 0
    stop_leftovers roomler-desktop 0
    remove_packages_linux
    remove_tarball_linux
    remove_registrations_linux
    # The wake file the update helper watches (FR-96): runtime, never config.
    remove_paths /var/tmp/roomler-update-check
    if [ "$KEEP_CONFIG" = 1 ]; then
        say "keeping the config (--keep-config)"
        return 0
    fi
    accounts="$(uninstall_accounts)"
    list="$(for a in $accounts root; do account_config_paths "$(home_of "$a")"; done)"
    # The system config (/etc/roomler holds a system install's credential),
    # the system unit's environment file and an administrator's drop-ins.
    # RETIRED-NAME-ANCHOR: the pre-rename system config dir; a host that never
    # migrated holds its enrolled credential there.
    remove_paths /etc/roomler /etc/roomler-agent /etc/default/roomlerd \
        /etc/systemd/system/roomlerd.service.d
    remove_listed "$list"
    report_other_config "$accounts"
}

# ── macOS ──

uninstall_stop_macos() {
    # The update helper first, and never in the middle of an install: booting
    # it out kills its whole process group, `installer` included (the .pkg
    # postinstall's own warning).
    if as_root launchctl print system/com.roomler.update >/dev/null 2>&1; then
        n=0
        while as_root launchctl print system/com.roomler.update 2>/dev/null | grep -q 'state = running'; do
            [ "$n" = 0 ] && say "waiting for com.roomler.update to finish: it is installing an update"
            n=$((n + 1))
            [ "$n" -ge 300 ] && { warn "com.roomler.update still runs after 300 s; stopping it"; break; }
            sleep 1
        done
        say "stopping com.roomler.update"
        as_root launchctl bootout system/com.roomler.update 2>/dev/null ||
            uninstall_failed "stop com.roomler.update"
    fi
    # Every account's per-user half and companion: one per GUI login.
    uids="$(dscl . -list /Users UniqueID 2>/dev/null | awk '$1 !~ /^_/ && $2 >= 500 { print $2 }' || true)"
    # shellcheck disable=SC2016,SC2086 # the script expands as root; one uid per word
    root_helper 'for uid do
        for l in com.roomler.desktop com.roomler.agent; do
            if launchctl print "gui/$uid/$l" >/dev/null 2>&1; then
                if launchctl bootout "gui/$uid/$l" 2>/dev/null; then
                    echo "stopping gui/$uid/$l"
                else
                    echo "FAILED stop gui/$uid/$l"
                fi
            fi
        done
    done' $uids
    if as_root launchctl print system/com.roomler.daemon >/dev/null 2>&1; then
        say "stopping com.roomler.daemon (the root half)"
        as_root launchctl bootout system/com.roomler.daemon 2>/dev/null ||
            uninstall_failed "stop com.roomler.daemon"
    fi
}

uninstall_macos() {
    uninstall_stop_macos
    stop_leftovers roomlerd 20
    # A companion the person opened from Finder runs under LaunchServices,
    # which no bootout reaches.
    stop_leftovers roomler-desktop 20
    if [ "$KEEP_CONFIG" != 1 ]; then
        # The two grants, while the bundle that names them is still there to
        # resolve: a fresh install then asks again, instead of showing a toggle
        # that is on for a binary that is gone.
        for svc in ScreenCapture Accessibility; do
            as_root tccutil reset "$svc" com.roomler.agent >/dev/null 2>&1 ||
                warn "could not reset the $svc grant (tccutil reset $svc com.roomler.agent)"
        done
    fi
    agents=""
    while read -r name home; do
        case "$home" in ''|/) continue ;; esac
        agents="$agents
$home/Library/LaunchAgents/com.roomler.agent.plist
$home/Library/LaunchAgents/com.roomler.desktop.plist"
    done <<EOF
$(local_accounts)
EOF
    # /Library/LaunchAgents too: no .pkg places them there, but a plist left
    # there by hand loads for EVERY login, against a missing binary.
    # RETIRED-NAME-ANCHOR(6): the pre-rc.457 /Applications bundle the .pkg
    # postinstall also sweeps, and the CLI's legacy-name symlink that
    # install_tunnel_tarball creates.
    remove_paths /Library/LaunchDaemons/com.roomler.daemon.plist \
        /Library/LaunchDaemons/com.roomler.update.plist \
        /Library/LaunchAgents/com.roomler.agent.plist \
        /Library/LaunchAgents/com.roomler.desktop.plist /Library/Roomler \
        /Applications/Roomler.app /Applications/roomler-agent.app \
        /usr/local/bin/roomler /usr/local/bin/roomlerd /usr/local/bin/roomler-tunnel \
        /private/var/tmp/roomler-update-check /var/run/roomler
    remove_listed "$agents"
    for id in $(pkgutil --pkgs 2>/dev/null | grep '^com\.roomler\.' || true); do
        if as_root pkgutil --forget "$id" >/dev/null 2>&1; then
            say "forgot the package receipt $id"
        else
            uninstall_failed "forget the package receipt $id"
        fi
    done
    if [ "$KEEP_CONFIG" = 1 ]; then
        say "keeping the config (--keep-config)"
        return 0
    fi
    accounts="$(uninstall_accounts)"
    list="$(for a in $accounts root; do account_config_paths "$(home_of "$a")"; done)"
    # /etc/roomler holds the root half's credential; the logs follow it.
    # RETIRED-NAME-ANCHOR: the pre-rename system config and log dirs, which
    # the .pkg postinstall migrates but never deletes.
    remove_paths /etc/roomler /etc/roomler-agent /var/log/roomler /var/log/roomler-agent \
        /tmp/roomlerd.out.log /tmp/roomlerd.err.log \
        /tmp/roomler-desktop.out.log /tmp/roomler-desktop.err.log
    remove_listed "$list"
    report_other_config "$accounts"
}

uninstall_finish() {
    if [ -n "$UNINSTALL_FAILED" ]; then
        echo "error: the uninstall did not complete:$UNINSTALL_FAILED" >&2
        exit 1
    fi
    if [ "$KEEP_CONFIG" = 1 ]; then
        say "Roomler is removed from this machine; its config is kept."
    else
        say "Roomler is removed from this machine."
    fi
    say "Now remove the device in the dashboard (Devices → remove): that revokes its"
    say "  credential and releases its network address."
    if [ "$OS" = Darwin ]; then
        say "  A Mac that ran the root half is TWO devices there: remove both."
    fi
    say "done."
    exit 0
}

# ─── main ───────────────────────────────────────────────────────────────────

if [ "$UNINSTALL" = 1 ]; then
    say "roomler install.sh — uninstall os=$OS"
    case "$OS" in
        Linux) uninstall_linux ;;
        Darwin) uninstall_macos ;;
    esac
    uninstall_finish
fi

local_fresh_install_only() {
    for parent in /etc/roomler /etc/roomler-agent; do
        [ ! -d "$parent" ] || { [ -r "$parent" ] && [ -x "$parent" ]; } || {
            echo "error: existing daemon configuration scope is inaccessible; refusing local bootstrap" >&2; exit 1;
        }
    done
    for existing in /usr/local/bin/roomler /usr/local/bin/roomler-tunnel /usr/local/bin/roomlerd /etc/roomler/config.toml /etc/roomler-agent/config.toml /etc/default/roomlerd; do
        [ ! -e "$existing" ] && [ ! -L "$existing" ] || {
            echo "error: local bootstrap preserves existing Roomler state; reviewed migration required" >&2; exit 1;
        }
    done
    if [ "$OS" = Linux ]; then
        command -v dpkg-query >/dev/null 2>&1 || { echo "error: local .deb requires readable native package inventory" >&2; exit 1; }
        for package_name in roomlerd roomler-agent roomler-desktop roomler roomler-tunnel; do
            if dpkg-query -W "$package_name" >/dev/null 2>&1; then
                echo "error: existing Roomler package state requires reviewed migration" >&2; exit 1
            else
                inventory_exit=$?
                [ "$inventory_exit" = 1 ] || { echo "error: package inventory unavailable; refusing local bootstrap" >&2; exit 1; }
            fi
        done
        for unit in roomlerd.service roomler.service roomler-agent.service roomler-update.service roomler-update.timer roomler-update.path; do
            for base in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /usr/lib/systemd/user "${HOME}/.config/systemd/user"; do
                [ ! -e "$base/$unit" ] && [ ! -L "$base/$unit" ] || { echo "error: existing Roomler service state is preserved" >&2; exit 1; }
            done
        done
        for existing in /usr/bin/roomlerd /usr/bin/roomler /usr/bin/roomler-tunnel /usr/bin/roomler-agent /usr/bin/roomler-desktop /usr/lib/roomler-agent; do
            [ ! -e "$existing" ] && [ ! -L "$existing" ] || { echo "error: existing Linux daemon must be migrated explicitly" >&2; exit 1; }
        done
    else
        command -v pkgutil >/dev/null 2>&1 || { echo "error: native macOS package inventory is unavailable" >&2; exit 1; }
        registered_packages="$(pkgutil --pkgs 2>/dev/null)" || { echo "error: native macOS package inventory failed" >&2; exit 1; }
        [ "${#registered_packages}" -le 65536 ] || { echo "error: native package inventory exceeds bootstrap bound" >&2; exit 1; }
        if printf '%s\n' "$registered_packages" | grep -q '^com\.roomler\.'; then
            echo "error: existing macOS Roomler package requires reviewed migration" >&2; exit 1
        fi
        for existing in /Library/Roomler /Library/LaunchDaemons/com.roomler.daemon.plist /Library/LaunchDaemons/com.roomler.update.plist /Library/LaunchAgents/com.roomler.agent.plist /Library/LaunchAgents/com.roomler.desktop.plist; do
            [ ! -e "$existing" ] && [ ! -L "$existing" ] || { echo "error: existing macOS daemon must be migrated explicitly" >&2; exit 1; }
        done
        console_home="$(home_of "$CONSOLE_USER")"
        case "$console_home" in /*) ;; *) echo "error: cannot identify console-user configuration scope" >&2; exit 1 ;; esac
        for existing in "$console_home/Library/LaunchAgents/com.roomler.agent.plist" "$console_home/Library/LaunchAgents/com.roomler.desktop.plist"; do
            [ ! -e "$existing" ] && [ ! -L "$existing" ] || { echo "error: existing user LaunchAgent state is preserved" >&2; exit 1; }
        done
        account_config_paths "$console_home" | while IFS= read -r existing; do
            [ ! -e "$existing" ] && [ ! -L "$existing" ] || { echo "error: existing macOS enrollment is preserved" >&2; exit 1; }
        done
        [ ! -L "$MACOS_DAEMON_MARKER" ] || { echo "error: backend marker symlink is not owned by this bootstrap" >&2; exit 1; }
    fi
}

prepare_local_artifacts() {
    # Private snapshots close the verify/use race. Source changes cannot swap
    # the reviewed bytes between SHA verification and privileged installation.
    case "$OS" in Linux) local_suffix=deb ;; Darwin) local_suffix=pkg ;; esac
    cp "$LOCAL_PACKAGE" "$STAGE/local-daemon.$local_suffix"
    cp "$LOCAL_CLI" "$STAGE/local-roomler"
    LOCAL_PACKAGE="$STAGE/local-daemon.$local_suffix"
    LOCAL_CLI="$STAGE/local-roomler"
    verify_sha256 "$LOCAL_PACKAGE" "$LOCAL_PACKAGE_SHA"
    verify_sha256 "$LOCAL_CLI" "$LOCAL_CLI_SHA"
    LOCAL_PHASE=cli-preflight
    chmod 700 "$LOCAL_CLI"
    "$LOCAL_CLI" --version >/dev/null
    local_fresh_install_only
}

check_local_cli_after_package() {
    LOCAL_PHASE=cli-post-package-check
    verify_sha256 /usr/local/bin/roomler "$LOCAL_CLI_SHA"
    /usr/local/bin/roomler --version >/dev/null
}

install_local_cli() {
    if [ "$DOWNLOAD_ONLY" = 1 ]; then
        say "download-only: would run: sudo install -m 755 $LOCAL_CLI /usr/local/bin/roomler"
        return 0
    fi
    LOCAL_PHASE=cli-install; LOCAL_CLI_STATE=attempted
    sudo install -m 755 "$LOCAL_CLI" /usr/local/bin/roomler
    LOCAL_PHASE=cli-alias
    sudo ln -sf /usr/local/bin/roomler /usr/local/bin/roomler-tunnel
    LOCAL_PHASE=cli-installed-check
    /usr/local/bin/roomler --version >/dev/null
    LOCAL_CLI_STATE=ready
}

[ "$LOCAL_MODE" != 1 ] || prepare_local_artifacts

say "roomler install.sh — role=$ROLE os=$OS server=$SERVER"

case "$ROLE/$OS" in
    # FR-27 — the companion AFTER the daemon: it depends on `roomlerd` (the
    # .deb literally Depends on it), and it reuses the release listing the
    # daemon step already fetched.
    daemon/Linux)
        [ "$LOCAL_MODE" != 1 ] || install_local_cli
        install_daemon_linux
        [ "$LOCAL_MODE" = 1 ] || install_desktop_linux ;;
    daemon/Darwin)
        [ "$LOCAL_MODE" != 1 ] || install_local_cli
        install_daemon_macos ;;
    tunnel/Linux)  install_tunnel_linux ;;
    tunnel/Darwin) install_tunnel_macos ;;
esac

say "done."
