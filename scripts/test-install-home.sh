#!/bin/sh
# FR-123 P2 — exercise install.sh's home-directory install (an account without
# administrator rights) with the real functions, a fixture release tarball and
# a fixture HOME. Nothing privileged runs: sudo, systemctl and loginctl are
# stubs, and any sudo call fails the test.
set -eu
script=${1:-"$(dirname "$0")/install.sh"}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' 0 HUP INT TERM
mkdir -p "$fixture/home" "$fixture/bin" "$fixture/stage" "$fixture/rel/x/usr/bin" \
    "$fixture/rel/x/usr/lib/meshharbor"
awk '
  /^(asset_field_for|download|verify_sha256|restart_old_user_daemon|sign_in_with_link|sudo_usable|enable_linger_home|install_daemon_linux_home)\(\) \{/ { emit=1 }
  emit { print }
  emit && /^}/ { emit=0 }
' "$script" > "$fixture/functions.sh"
. "$fixture/functions.sh"

log="$fixture/calls.log"
: > "$log"
say() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
sudo() { echo "sudo $*" >> "$log"; echo "unexpected sudo: $*" >&2; return 1; }

# The release: a daemon that answers --version and records what it is asked.
cat > "$fixture/rel/x/usr/bin/meshharbord" <<EOF
#!/bin/sh
case "\$1" in
    --version) echo "meshharbord 9.9.9" ;;
    *) echo "meshharbord \$*" >> "$log" ;;
esac
EOF
printf '#!/bin/sh\necho mh\n' > "$fixture/rel/x/usr/bin/mh"
chmod 755 "$fixture/rel/x/usr/bin/meshharbord" "$fixture/rel/x/usr/bin/mh"
echo lib > "$fixture/rel/x/usr/lib/meshharbor/libvpx.so.7"
tar -czf "$fixture/release.tar.gz" -C "$fixture/rel" x
sha="$(sha256sum "$fixture/release.tar.gz" | awk '{print $1}')"
printf '{"assets":[{"name":"meshharbor-9.9.9-%s-unknown-linux-gnu.tar.gz","browser_download_url":"https://example.invalid/r.tar.gz","digest":"sha256:%s"}]}\n' \
    "$(uname -m | sed 's/amd64/x86_64/; s/arm64/aarch64/')" "$sha" > "$fixture/releases.json"

curl() {
    out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) url="$1"; shift ;; esac; done
    case "$url" in
        */api/agent/latest-release) cp "$fixture/releases.json" "$out" ;;
        *.tar.gz) cp "$fixture/release.tar.gz" "$out" ;;
        *) return 1 ;;
    esac
}
systemctl() { echo "systemctl $*" >> "$log"; case "$*" in *is-active*) echo active ;; *show*) echo 0 ;; esac; }
loginctl() {
    echo "loginctl $*" >> "$log"
    case "$*" in *show-user*) echo no ;; *enable-linger*) return 0 ;; esac
}

HOME="$fixture/home"; STAGE="$fixture/stage"; SERVER=https://example.invalid; NAME=fixture-host
TOKEN=""; NO_ENROLL=0; DOWNLOAD_ONLY=0
export HOME

# 1. No token: unpacked into ~/.local, signed in with a link, no sudo.
install_daemon_linux_home > "$fixture/out1.log"
[ -x "$HOME/.local/bin/meshharbord" ] || { echo "no ~/.local/bin/meshharbord" >&2; exit 1; }
[ -x "$HOME/.local/bin/mh" ] || { echo "no ~/.local/bin/mh" >&2; exit 1; }
[ -f "$HOME/.local/lib/meshharbor/libvpx.so.7" ] || { echo "no library in ~/.local/lib/meshharbor" >&2; exit 1; }
grep -q "meshharbord login --user --server https://example.invalid --name fixture-host" "$log" ||
    { echo "did not sign in with a link:"; cat "$log"; exit 1; } >&2
grep -q "loginctl --no-ask-password enable-linger" "$log" || { echo "did not ask for lingering" >&2; exit 1; }
if grep -q '^sudo ' "$log"; then echo "home install called sudo" >&2; exit 1; fi
if grep -q 'enroll --token' "$fixture/out1.log"; then echo "home install pointed at a token" >&2; exit 1; fi
ls -a "$HOME/.local/bin" | grep -q '\.new$' && { echo "a staging file was left behind" >&2; exit 1; }

# 2. A token: enroll, then the daemon writes and starts its own user unit.
: > "$log"; TOKEN=fixture-token
install_daemon_linux_home > "$fixture/out2.log"
grep -q "meshharbord enroll --server https://example.invalid --token fixture-token --name fixture-host" "$log" ||
    { echo "did not enroll with the token:"; cat "$log"; exit 1; } >&2
grep -q "meshharbord service install" "$log" || { echo "did not install the user unit" >&2; exit 1; }
if grep -q 'fixture-token' "$fixture/out2.log"; then echo "the token was echoed" >&2; exit 1; fi

# 3. Download-only touches nothing.
rm -rf "$HOME/.local"; : > "$log"; TOKEN=""; DOWNLOAD_ONLY=1
install_daemon_linux_home > "$fixture/out3.log"
[ ! -e "$HOME/.local/bin/meshharbord" ] || { echo "download-only installed something" >&2; exit 1; }
grep -q "would run: $HOME/.local/bin/meshharbord login --user" "$fixture/out3.log" ||
    { echo "download-only did not say what it would run" >&2; exit 1; }

# 4. sudo that needs a password, and no terminal: not usable.
sudo() { [ "$1" = -n ] && return 1; echo "sudo $*" >> "$log"; return 1; }
if (exec </dev/null; sudo_usable </dev/null) >/dev/null 2>&1 && ! ( : </dev/tty ) 2>/dev/null; then
    echo "sudo_usable said yes with no terminal and no passwordless sudo" >&2; exit 1
fi
sudo() { return 0; }
sudo_usable >/dev/null 2>&1 || { echo "passwordless sudo was not usable" >&2; exit 1; }

echo 'PASS: home install (link sign-in, token enroll, download-only, no sudo), sudo detection'
