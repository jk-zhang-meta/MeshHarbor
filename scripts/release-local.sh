#!/usr/bin/env bash
# release-local.sh -- publish a release into the server's own release
# directory (`releases.local_dir`, docs/self-hosted-releases.md). No CI and no
# GitHub: the server serves `<dir>/<tag>/<file>` from our own domain.
#
#   scripts/release-local.sh publish <release-dir> <tag> <artifact>...
#   scripts/release-local.sh verify  <release-dir> <tag>
#
# Every artifact gets a detached armored `.asc` from the release signing
# SUBKEY. The agents verify that `.asc` against the key compiled into them
# (crates/tunnel-core/src/pgp_verify.rs), so this script is the only place a
# release becomes installable. The secret key never lives in this repository:
#
#   MESHHARBOR_RELEASE_GNUPGHOME        GNUPGHOME holding the signing subkey
#   MESHHARBOR_RELEASE_PASSPHRASE_FILE  file with that key's passphrase
#
# Each signature is re-verified against the COMMITTED public key before
# anything becomes visible, and the tag directory appears by one rename of a
# hidden staging directory (the server's scan skips dot-entries), so a reader
# never sees a half-published release. A published tag is immutable.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PUBKEY="$ROOT/scripts/signing/gpg/meshharbor-release-pubkey.asc"
# The pinned signing subkey (pgp_verify::PINNED_RELEASE_SIGNING_KEY).
SUBKEY_FPR="${MESHHARBOR_RELEASE_SUBKEY:-A323047747FA652D8D74BB709482E0B7193780A1}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
valid_token() { [[ "$1" =~ ^[A-Za-z0-9._+-]{1,240}$ && "$1" != . && "$1" != .. && "$1" != .* ]]; }
valid_tag() { valid_token "$1" && [[ "$1" =~ ^(agent|tunnel|setup)-v[0-9] ]]; }

# Verify every artifact in $1 has an .asc made by the pinned subkey.
verify_dir() {
    local d=$1 kr n=0 f
    kr=$(mktemp -d)
    gpg --homedir "$kr" --batch --quiet --import "$PUBKEY" 2>/dev/null
    for f in "$d"/*; do
        [[ "$f" == *.asc ]] && continue
        [ -f "$f.asc" ] || { rm -rf "$kr"; die "missing signature: $(basename "$f").asc"; }
        if ! gpg --homedir "$kr" --batch --status-fd 1 --verify "$f.asc" "$f" 2>/dev/null \
            | grep -q "^\[GNUPG:\] VALIDSIG $SUBKEY_FPR "; then
            rm -rf "$kr"
            die "$(basename "$f").asc does not verify against the committed release key"
        fi
        n=$((n + 1))
    done
    rm -rf "$kr"
    [ "$n" -gt 0 ] || die "no artifacts in $d"
    echo "verified $n artifact(s) against $SUBKEY_FPR"
}

cmd_publish() {
    [ $# -ge 3 ] || die "usage: publish <release-dir> <tag> <artifact>..."
    local dir=$1 tag=$2
    shift 2
    valid_tag "$tag" || die "bad tag '$tag' (agent-v*/tunnel-v*/setup-v*)"
    [ -d "$dir" ] || die "release dir $dir does not exist"
    [ ! -e "$dir/$tag" ] || die "$dir/$tag exists -- a published release is immutable"
    : "${MESHHARBOR_RELEASE_GNUPGHOME:?set to the GNUPGHOME holding the release signing subkey}"
    : "${MESHHARBOR_RELEASE_PASSPHRASE_FILE:?set to the signing subkey passphrase file}"
    local version=${tag#*-v} stage="$dir/.staging-$tag-$$" a name
    mkdir -m 700 "$stage"
    trap 'rm -rf "$stage"' EXIT
    for a in "$@"; do
        name=$(basename -- "$a")
        valid_token "$name" && [[ "$name" != *.asc ]] || die "bad artifact name '$name'"
        [ -f "$a" ] && [ ! -L "$a" ] || die "not a regular file: $a"
        # The updater refuses an artifact that does not self-identify as the
        # release it was offered as (artifact_version.rs); catch the obvious
        # mismatch here instead of in the field.
        [[ "$name" == *"$version"* ]] || die "'$name' does not carry the tag's version $version"
        cp -- "$a" "$stage/$name"
        GNUPGHOME="$MESHHARBOR_RELEASE_GNUPGHOME" gpg --batch --yes --quiet \
            --pinentry-mode loopback --passphrase-file "$MESHHARBOR_RELEASE_PASSPHRASE_FILE" \
            --local-user "$SUBKEY_FPR!" --armor --detach-sign -o "$stage/$name.asc" "$stage/$name"
    done
    verify_dir "$stage"
    # The server may run as another uid (a container): world-readable, and
    # nothing writable by anyone but the publisher.
    chmod 755 "$stage"
    chmod 644 "$stage"/*
    mv -T "$stage" "$dir/$tag"
    trap - EXIT
    echo "published $tag: $(find "$dir/$tag" -maxdepth 1 -type f | wc -l) file(s); visible to agents within 30 s"
}

cmd_verify() {
    [ $# -eq 2 ] || die "usage: verify <release-dir> <tag>"
    valid_tag "$2" || die "bad tag '$2'"
    verify_dir "$1/$2"
}

case "${1:-}" in
    publish) shift; cmd_publish "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    *) die "usage: $0 publish <release-dir> <tag> <artifact>... | verify <release-dir> <tag>" ;;
esac
