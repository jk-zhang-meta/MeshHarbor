#!/usr/bin/env bash
# 60-apple-setup.sh -- produce the six Apple secrets that release-agent.yml's
# macOS job already expects, without ever touching Keychain Access.
#
# The signing + notarisation flow in .github/workflows/release-agent.yml is
# complete and correct; it has simply never had credentials. This script
# generates the keys and CSRs with openssl, assembles the .p12 bundles from
# the certificates Apple issues, and pushes everything to GitHub.
#
#   ./scripts/signing/60-apple-setup.sh csr
#       -> two private keys + two CSRs; upload the CSRs in the portal
#
#   ./scripts/signing/60-apple-setup.sh p12 \
#       --app-cer ~/Downloads/developerID_application.cer \
#       --installer-cer ~/Downloads/developerID_installer.cer
#       -> two .p12 bundles with the full Apple chain
#
#   ./scripts/signing/60-apple-setup.sh secrets \
#       --asc-key ~/Downloads/AuthKey_ABCD1234.p8 \
#       --key-id ABCD1234 --issuer-id 12345678-1234-1234-1234-1234567890ab
#       -> base64 + gh secret set x6
#
#   ./scripts/signing/60-apple-setup.sh check
#       -> report which of the six secrets are set on the repo
#
# Prerequisite the script cannot do for you: Apple Developer Program
# membership, 99 USD/yr. ORGANIZATION enrolment needs a D-U-N-S number
# (free from Dun & Bradstreet, but ALLOW 1-2 WEEKS) and puts the company
# name on the Developer ID. Individual enrolment is faster but stamps a
# personal name on every signature, which defeats the point of signing
# under a company identity on Windows. Start the D-U-N-S request on day 1.

set -euo pipefail

REPO="${REPO:-jk-zhang-meta/MeshHarbor}"
OUTDIR="${OUTDIR:-$(cd "$(dirname "$0")" && pwd)/apple}"
CERT_PASSWORD="${CERT_PASSWORD:-}"

say()  { printf '==> %s\n' "$*"; }
ok()   { printf '    OK  %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*" >&2; }
die()  { printf '    ERROR: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. $2"; }

# Apple's intermediate. Without it the .p12 carries a leaf with no path to
# the Apple root, and `codesign` fails at signing time with a misleading
# "unable to build chain" rather than anything about a missing intermediate.
APPLE_G2_URL='https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer'
APPLE_ROOT_URL='https://www.apple.com/appleca/AppleIncRootCertificate.cer'

gen_password() {
    if [ -n "$CERT_PASSWORD" ]; then printf '%s' "$CERT_PASSWORD"; return; fi
    openssl rand -base64 24 | tr -d '\n='
}

cmd_csr() {
    need openssl 'Install openssl.'
    mkdir -p "$OUTDIR"
    chmod 700 "$OUTDIR"

    # CN here is only the CSR's common name; the Developer ID certificate
    # Apple issues carries the TEAM name from the enrolment, so enrol the
    # company (G ROX LTD) rather than an individual if you want the macOS
    # publisher to match the Windows one.
    local subj_cn="${APPLE_CN:-G ROX LTD}"
    local subj_email="${APPLE_EMAIL:-goran.jovanov@gmail.com}"
    local country="${APPLE_COUNTRY:-BG}"

    for kind in application installer; do
        local key="$OUTDIR/developerID_${kind}.key"
        local csr="$OUTDIR/developerID_${kind}.csr"
        if [ -f "$key" ]; then
            info "reusing existing key $key"
        else
            openssl genrsa -out "$key" 2048 2>/dev/null
            chmod 600 "$key"
            ok "private key: $key"
        fi
        openssl req -new -key "$key" -out "$csr" \
            -subj "/emailAddress=${subj_email}/CN=${subj_cn}/C=${country}"
        ok "CSR: $csr"
    done

    cat <<EOF

$(say 'MANUAL STEP -- issue the certificates in the Apple Developer portal')
    https://developer.apple.com/account/resources/certificates/add

    Create TWO certificates, uploading the matching CSR for each:

      1. "Developer ID Application"  <- developerID_application.csr
         signs the Mach-O binaries, the .app bundle and the bundled dylibs

      2. "Developer ID Installer"    <- developerID_installer.csr
         signs the .pkg (productbuild --sign)

    Download both .cer files, then run:

      $0 p12 \\
          --app-cer ~/Downloads/developerID_application.cer \\
          --installer-cer ~/Downloads/developerID_installer.cer

$(say 'Also create an App Store Connect API key (for notarytool)')
    https://appstoreconnect.apple.com/access/integrations/api

    Team Keys -> generate a key with the "Developer" role.
    Note the KEY ID and the ISSUER ID, and download the .p8 ONCE
    (Apple will not let you download it again).
EOF
}

cmd_p12() {
    need openssl 'Install openssl.'
    need curl 'Install curl.'
    local app_cer='' inst_cer=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --app-cer)       app_cer="$2"; shift 2 ;;
            --installer-cer) inst_cer="$2"; shift 2 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    [ -n "$app_cer" ]  || die 'missing --app-cer'
    [ -n "$inst_cer" ] || die 'missing --installer-cer'
    [ -f "$app_cer" ]  || die "not found: $app_cer"
    [ -f "$inst_cer" ] || die "not found: $inst_cer"
    mkdir -p "$OUTDIR"

    say 'Fetching the Apple intermediate + root'
    curl -fsSL "$APPLE_G2_URL"   -o "$OUTDIR/DeveloperIDG2CA.cer"
    curl -fsSL "$APPLE_ROOT_URL" -o "$OUTDIR/AppleIncRootCertificate.cer"
    openssl x509 -inform DER -in "$OUTDIR/DeveloperIDG2CA.cer"          -out "$OUTDIR/chain.pem"
    openssl x509 -inform DER -in "$OUTDIR/AppleIncRootCertificate.cer" >> "$OUTDIR/chain.pem"
    ok 'chain.pem assembled'

    local password
    password="$(gen_password)"
    printf '%s' "$password" > "$OUTDIR/cert-password.txt"
    chmod 600 "$OUTDIR/cert-password.txt"

    build_one() {
        local kind="$1" cer="$2"
        local key="$OUTDIR/developerID_${kind}.key"
        [ -f "$key" ] || die "missing $key -- run '$0 csr' first (the key must pair with the CSR you uploaded)."
        # Apple hands back DER; openssl pkcs12 wants PEM.
        openssl x509 -inform DER -in "$cer" -out "$OUTDIR/developerID_${kind}.pem"
        openssl pkcs12 -export \
            -out "$OUTDIR/developerID_${kind}.p12" \
            -inkey "$key" \
            -in "$OUTDIR/developerID_${kind}.pem" \
            -certfile "$OUTDIR/chain.pem" \
            -passout "pass:${password}" \
            -legacy 2>/dev/null \
          || openssl pkcs12 -export \
            -out "$OUTDIR/developerID_${kind}.p12" \
            -inkey "$key" \
            -in "$OUTDIR/developerID_${kind}.pem" \
            -certfile "$OUTDIR/chain.pem" \
            -passout "pass:${password}"
        chmod 600 "$OUTDIR/developerID_${kind}.p12"
        local subject
        subject="$(openssl x509 -in "$OUTDIR/developerID_${kind}.pem" -noout -subject)"
        ok "developerID_${kind}.p12"
        info "  $subject"
    }

    say 'Building .p12 bundles'
    build_one application "$app_cer"
    build_one installer   "$inst_cer"

    cat <<EOF

    Password written to $OUTDIR/cert-password.txt
    (both .p12 files share it -- release-agent.yml passes one APPLE_CERT_PASSWORD
    to both 'security import' calls, so they MUST match.)

    Next:
      $0 secrets --asc-key <AuthKey_XXXX.p8> --key-id <KEYID> --issuer-id <ISSUERID>
EOF
}

cmd_secrets() {
    need gh 'Install: https://cli.github.com/'
    local asc_key='' key_id='' issuer_id=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --asc-key)   asc_key="$2";   shift 2 ;;
            --key-id)    key_id="$2";    shift 2 ;;
            --issuer-id) issuer_id="$2"; shift 2 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    [ -n "$asc_key" ]   || die 'missing --asc-key (the AuthKey_*.p8 from App Store Connect)'
    [ -n "$key_id" ]    || die 'missing --key-id'
    [ -n "$issuer_id" ] || die 'missing --issuer-id'
    [ -f "$asc_key" ]   || die "not found: $asc_key"

    local app_p12="$OUTDIR/developerID_application.p12"
    local inst_p12="$OUTDIR/developerID_installer.p12"
    local pw_file="$OUTDIR/cert-password.txt"
    for f in "$app_p12" "$inst_p12" "$pw_file"; do
        [ -f "$f" ] || die "missing $f -- run '$0 p12 ...' first."
    done

    # Single-line base64: `base64 -w0` is GNU-only, so fold manually.
    b64() { base64 < "$1" | tr -d '\n'; }

    say "Setting Apple secrets on $REPO"
    b64 "$app_p12"  | gh secret set APPLE_DEVELOPER_ID_APP_P12_BASE64       --repo "$REPO"
    ok  'APPLE_DEVELOPER_ID_APP_P12_BASE64'
    b64 "$inst_p12" | gh secret set APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64 --repo "$REPO"
    ok  'APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64'
    cat "$pw_file"  | gh secret set APPLE_CERT_PASSWORD                     --repo "$REPO"
    ok  'APPLE_CERT_PASSWORD'
    printf '%s' "$key_id"    | gh secret set APPLE_API_KEY_ID    --repo "$REPO"
    ok  'APPLE_API_KEY_ID'
    printf '%s' "$issuer_id" | gh secret set APPLE_API_ISSUER_ID --repo "$REPO"
    ok  'APPLE_API_ISSUER_ID'
    b64 "$asc_key"  | gh secret set APPLE_API_KEY_P8_BASE64 --repo "$REPO"
    ok  'APPLE_API_KEY_P8_BASE64'

    cat <<EOF

$(say 'All six set. Apple signing is all-or-nothing in CI:')
    a partially-configured run now FAILS rather than quietly producing a
    signed-but-unnotarised .pkg (which Gatekeeper rejects on any Mac that
    cannot reach Apple's notary service).

$(say 'Rehearse without publishing:')
    gh workflow run release-agent.yml --repo $REPO -f publish_release=false

    The acceptance check in the job log is:
      spctl -a -vvv -t install <pkg>   ->   source=Notarized Developer ID
EOF
}

cmd_check() {
    need gh 'Install: https://cli.github.com/'
    say "Apple secrets on $REPO"
    local names="APPLE_DEVELOPER_ID_APP_P12_BASE64 APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64 APPLE_CERT_PASSWORD APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8_BASE64"
    local have
    have="$(gh secret list --repo "$REPO" --json name --jq '.[].name' 2>/dev/null || true)"
    local missing=0
    for n in $names; do
        if printf '%s\n' "$have" | grep -qx "$n"; then ok "$n"
        else printf '    MISSING  %s\n' "$n"; missing=$((missing + 1)); fi
    done
    if [ "$missing" -gt 0 ]; then
        warn "$missing of 6 missing -- macOS artifacts will be unsigned and Gatekeeper-blocked."
        exit 1
    fi
    ok 'all six present'
}

case "${1:-}" in
    csr)     shift; cmd_csr "$@" ;;
    p12)     shift; cmd_p12 "$@" ;;
    secrets) shift; cmd_secrets "$@" ;;
    check)   shift; cmd_check "$@" ;;
    *)
        sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
