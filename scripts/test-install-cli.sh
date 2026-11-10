#!/bin/sh
# Exercise the real installer functions without privilege or host installation.
set -eu
script=${1:-"$(dirname "$0")/install.sh"}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' 0 HUP INT TERM
mkdir -p "$fixture/payload" "$fixture/bin" "$fixture/stage" "$fixture/legacy"
awk '
  /^(tunnel_cli_runs|require_tunnel_cli|install_tunnel_tarball|enroll_tunnel|install_local_cli)\(\) \{/ { emit=1 }
  emit { print }
  emit && /^}/ { emit=0 }
' "$script" | sed "s|/usr/local/bin/mh|$fixture/bin/mh|g" > "$fixture/functions.sh"
. "$fixture/functions.sh"

say() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
sudo() {
    # Only this exact installation call is allowed, redirected into the fixture.
    if [ "$#" = 5 ] && [ "$1" = install ] && [ "$2" = -m ] &&
       [ "$3" = 755 ] && [ "$5" = "$fixture/bin/mh" ]; then
        command install -m 755 "$4" "$fixture/bin/mh"
    else
        echo "unexpected privileged command: $*" >&2
        return 1
    fi
}
printf '#!/bin/sh\nprintf "mh fixture 1.0\\n"\n' > "$fixture/payload/mh"
chmod 755 "$fixture/payload/mh"
tar -czf "$fixture/cli.tar.gz" -C "$fixture/payload" mh
STAGE="$fixture/stage"
PATH="$fixture/bin:$PATH"
export PATH
install_tunnel_tarball "$fixture/cli.tar.gz"
require_tunnel_cli
[ "$(mh --version)" = 'mh fixture 1.0' ]

# A stale alternate command must never be selected instead of mh.
cp "$fixture/payload/mh" "$fixture/bin/meshharbor"
NO_ENROLL=1 TOKEN= SERVER=https://example.invalid NAME=fixture
output=$(enroll_tunnel)
case "$output" in
    *"$fixture/bin/mh enroll"*) ;;
    *) echo "enrollment selected an alternate command: $output" >&2; exit 1 ;;
esac
LOCAL_CLI="$fixture/payload/mh" DOWNLOAD_ONLY=0
install_local_cli
[ "$LOCAL_CLI_STATE" = ready ]

# Archives with only the retired alternative are rejected.
cp "$fixture/payload/mh" "$fixture/legacy/meshharbor"
tar -czf "$fixture/legacy.tar.gz" -C "$fixture/legacy" meshharbor
if (STAGE="$fixture/negative"; mkdir -p "$STAGE"; install_tunnel_tarball "$fixture/legacy.tar.gz") > "$fixture/negative.log" 2>&1; then
    echo 'accepted an archive without mh' >&2
    exit 1
fi
echo 'PASS: mh archive, enrollment selection, local install, alternate rejection'
