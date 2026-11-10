#!/usr/bin/env bash
# RETIRED-NAME-ANCHOR-BEGIN
# Every retired name below names a PUBLISHED release asset. Their filenames are
# fixed by what is already on GitHub Releases (FR-21 D6), and these verify
# commands are meant to be pasted against a real downloaded artifact.
# 70-gpg-release-key.sh -- create the release signing key used to produce
# detached .asc signatures for published artifacts.
#
#   ./scripts/signing/70-gpg-release-key.sh create
#   ./scripts/signing/70-gpg-release-key.sh export --push
#   ./scripts/signing/70-gpg-release-key.sh verify <file> <file.asc>
#   ./scripts/signing/70-gpg-release-key.sh check
#
# Scope, honestly stated: signing a .deb this way does NOT make `dpkg -i`
# safer -- dpkg does not verify signatures at all, and apt verifies a
# repository InRelease file rather than per-package signatures. What a
# detached .asc buys is an integrity check a human or a script can run that
# does not depend on GitHub being honest, which is exactly the gap the
# existing .sha256 sidecars leave open (they are served by the same host
# they attest to, and nothing in the repo consumes them).
#
# A real signed apt repo is the thing that would make `apt install` safe;
# that is deliberately out of scope until an apt channel exists.
#
# Key shape: an ed25519 primary that CERTIFIES ONLY, plus an ed25519
# SIGNING SUBKEY. Only the subkey secret goes to CI, so a compromised
# runner cannot issue new identities or extend the key's life -- it can
# only sign, and the subkey can be revoked without burning the identity.

set -euo pipefail

REPO="${REPO:-jk-zhang-meta/MeshHarbor}"
OUTDIR="${OUTDIR:-$(cd "$(dirname "$0")" && pwd)/gpg}"
REAL_NAME="${GPG_REAL_NAME:-MeshHarbor Release Signing}"
REAL_EMAIL="${GPG_REAL_EMAIL:-releases@meshharbor.itachi.fans}"
EXPIRE="${GPG_EXPIRE:-2y}"

say()  { printf '==> %s\n' "$*"; }
ok()   { printf '    OK  %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*" >&2; }
die()  { printf '    ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. $2"; }

keyid_file="$OUTDIR/keyid.txt"

cmd_create() {
    need gpg 'Install GnuPG.'
    mkdir -p "$OUTDIR"; chmod 700 "$OUTDIR"

    if [ -f "$keyid_file" ]; then
        die "a key already exists ($(cat "$keyid_file")). Delete $OUTDIR to start over."
    fi

    local passphrase
    passphrase="$(gpg --gen-random --armor 1 24 | tr -d '\n')"
    printf '%s' "$passphrase" > "$OUTDIR/passphrase.txt"
    chmod 600 "$OUTDIR/passphrase.txt"

    say "Generating $REAL_NAME <$REAL_EMAIL>"
    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --quick-generate-key "$REAL_NAME <$REAL_EMAIL>" ed25519 cert "$EXPIRE"

    local fpr
    fpr="$(gpg --list-keys --with-colons "$REAL_EMAIL" | awk -F: '/^fpr:/ {print $10; exit}')"
    [ -n "$fpr" ] || die 'could not read the new key fingerprint.'
    printf '%s' "$fpr" > "$keyid_file"
    ok "primary (certify-only): $fpr"

    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --quick-add-key "$fpr" ed25519 sign "$EXPIRE"
    ok 'signing subkey added'

    # A revocation certificate is only useful if it exists BEFORE you need
    # it -- generate it now and store it away from the key.
    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --output "$OUTDIR/revocation.asc" --gen-revoke "$fpr" <<'EOF' >/dev/null 2>&1 || true
y
1

y
EOF
    [ -f "$OUTDIR/revocation.asc" ] && ok "revocation certificate: $OUTDIR/revocation.asc"

    cat <<EOF

$(say 'Generated')
    fingerprint: $fpr
    passphrase:  $OUTDIR/passphrase.txt

$(warn 'Move the PRIMARY secret key offline once you have exported the subkey:')
    gpg --export-secret-keys --armor $fpr > primary-OFFLINE.asc   # to a safe
    gpg --delete-secret-keys $fpr                                  # then remove locally
    gpg --import "$OUTDIR/signing-subkey.asc"                      # keep only the subkey

    Next: $0 export --push
EOF
}

cmd_export() {
    need gpg 'Install GnuPG.'
    local push=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --push) push=1; shift ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    [ -f "$keyid_file" ] || die "no key found. Run '$0 create' first."
    local fpr; fpr="$(cat "$keyid_file")"
    local passphrase; passphrase="$(cat "$OUTDIR/passphrase.txt")"

    # --export-secret-subkeys exports the subkey material with the primary
    # stubbed out. CI gets signing capability and nothing else.
    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --armor --export-secret-subkeys "$fpr" > "$OUTDIR/signing-subkey.asc"
    chmod 600 "$OUTDIR/signing-subkey.asc"
    ok "signing subkey (for CI): $OUTDIR/signing-subkey.asc"

    gpg --armor --export "$fpr" > "$OUTDIR/meshharbor-release-pubkey.asc"
    ok "public key (for users):  $OUTDIR/meshharbor-release-pubkey.asc"

    if [ "$push" -eq 1 ]; then
        need gh 'Install: https://cli.github.com/'
        say "Setting GPG secrets on $REPO"
        gh secret set GPG_PRIVATE_KEY --repo "$REPO" < "$OUTDIR/signing-subkey.asc"
        ok 'GPG_PRIVATE_KEY'
        gh secret set GPG_PASSPHRASE  --repo "$REPO" < "$OUTDIR/passphrase.txt"
        ok 'GPG_PASSPHRASE'
        printf '%s' "$fpr" | gh secret set GPG_KEY_ID --repo "$REPO"
        ok 'GPG_KEY_ID'
    else
        info ''
        info "gh secret set GPG_PRIVATE_KEY --repo $REPO < $OUTDIR/signing-subkey.asc"
        info "gh secret set GPG_PASSPHRASE  --repo $REPO < $OUTDIR/passphrase.txt"
        info "printf '%s' $fpr | gh secret set GPG_KEY_ID --repo $REPO"
    fi

    cat <<EOF

$(say 'Publish the public key so verification is possible')
    Commit $OUTDIR/meshharbor-release-pubkey.asc to the repo and serve it from
    the API the same way scripts/install.sh is served -- see
    crates/api/src/routes/setup_release.rs, which does:

        const INSTALL_SH: &str = include_str!("../../../../scripts/install.sh");

    Users then verify with:

        curl -fsSL https://meshharbor.itachi.fans/api/setup/meshharbor-release-pubkey.asc | gpg --import
        gpg --verify meshharbor-agent-<v>-x86_64-unknown-linux-gnu.deb.asc \\
                     meshharbor-agent-<v>-x86_64-unknown-linux-gnu.deb
EOF
}

cmd_verify() {
    need gpg 'Install GnuPG.'
    [ $# -eq 2 ] || die "usage: $0 verify <file> <file.asc>"
    gpg --verify "$2" "$1"
    ok 'signature valid'
}

cmd_check() {
    need gh 'Install: https://cli.github.com/'
    say "GPG secrets on $REPO"
    local have missing=0
    have="$(gh secret list --repo "$REPO" --json name --jq '.[].name' 2>/dev/null || true)"
    for n in GPG_PRIVATE_KEY GPG_PASSPHRASE GPG_KEY_ID; do
        if printf '%s\n' "$have" | grep -qx "$n"; then ok "$n"
        else printf '    MISSING  %s\n' "$n"; missing=$((missing + 1)); fi
    done
    [ "$missing" -eq 0 ] || { warn "$missing of 3 missing -- artifacts will publish without .asc signatures."; exit 1; }
}

case "${1:-}" in
    create) shift; cmd_create "$@" ;;
    export) shift; cmd_export "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    check)  shift; cmd_check  "$@" ;;
    *)
        sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
# RETIRED-NAME-ANCHOR-END
