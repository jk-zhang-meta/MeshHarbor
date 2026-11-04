#!/usr/bin/env bash
# 90-verify-release.sh -- the macOS / Linux half of the release gate.
# Companion to 90-verify-release.ps1 (which does the Authenticode half).
#
#   ./scripts/signing/90-verify-release.sh --tag agent-v0.3.0-rc.361
#   ./scripts/signing/90-verify-release.sh --latest agent --keep
#
# Exits non-zero if anything that should be signed is not.
#
# On macOS this is the authoritative check: `spctl -a -t install` exercises
# the exact Gatekeeper path an end user hits, and it is the only test that
# distinguishes "signed" from "signed AND notarised". A .pkg can be
# correctly Developer-ID-signed and still be refused on every Mac in the
# world because notarisation never ran -- which is precisely the silent
# hole this repo's macOS job had.
#
# On Linux the Apple checks are skipped and only GPG + provenance run.

set -uo pipefail

REPO="${REPO:-jk-zhang-meta/MeshHarbor}"
TAG=''
LATEST=''
KEEP=0
WARN_ONLY=0

say()  { printf '==> %s\n' "$*"; }
ok()   { printf '      OK  %s\n' "$*"; }
bad()  { printf '      FAIL  %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*" >&2; }
die()  { printf '    ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. $2"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --tag)    TAG="$2"; shift 2 ;;
        --latest) LATEST="$2"; shift 2 ;;
        --repo)   REPO="$2"; shift 2 ;;
        --keep)   KEEP=1; shift ;;
        --warn-only) WARN_ONLY=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done

need gh 'Install: https://cli.github.com/'

if [ -z "$TAG" ]; then
    [ -n "$LATEST" ] || die 'pass --tag <tag> or --latest agent|setup|tunnel'
    TAG="$(gh release list --repo "$REPO" --limit 100 --json tagName --jq '.[].tagName' \
           | grep "^${LATEST}-v" | head -n1)"
    [ -n "$TAG" ] || die "no release found with prefix '${LATEST}-v' on $REPO"
    info "resolved --latest $LATEST -> $TAG"
fi

IS_MAC=0
[ "$(uname -s)" = 'Darwin' ] && IS_MAC=1
[ "$IS_MAC" -eq 1 ] || warn 'not macOS -- Gatekeeper checks (pkgutil/stapler/spctl) will be skipped.'

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/meshharbor-verify-XXXXXX")"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$STAGE"; }
trap cleanup EXIT

say "Downloading $TAG from $REPO"
gh release download "$TAG" --repo "$REPO" --dir "$STAGE" --clobber || die "could not download $TAG"

FAILURES=0
NOTES=''
note() { NOTES="${NOTES}
  - $*"; }
fail() { bad "$*"; FAILURES=$((FAILURES + 1)); }

for asset in "$STAGE"/*; do
    name="$(basename "$asset")"
    case "$name" in *.sha256|*.asc) continue ;; esac
    printf '\n'
    say "$name"

    case "$name" in
        *.pkg)
            if [ "$IS_MAC" -eq 1 ]; then
                if pkgutil --check-signature "$asset" >/dev/null 2>&1; then
                    signer="$(pkgutil --check-signature "$asset" 2>/dev/null | sed -n 's/^ *1\. //p' | head -n1)"
                    ok "pkg signature valid  (${signer:-unknown signer})"
                else
                    fail "pkg is NOT signed: $name"
                fi

                # A ticket can only be stapled to a bundle/.dmg/.pkg. Its
                # absence means Gatekeeper must reach Apple online, so an
                # offline or firewalled Mac fails closed.
                if xcrun stapler validate "$asset" >/dev/null 2>&1; then
                    ok 'notarisation ticket stapled'
                else
                    fail "no stapled notarisation ticket: $name"
                fi

                spctl_out="$(spctl -a -vvv -t install "$asset" 2>&1 || true)"
                if printf '%s' "$spctl_out" | grep -q 'source=Notarized Developer ID'; then
                    ok 'spctl: source=Notarized Developer ID'
                else
                    fail "spctl rejected $name: $(printf '%s' "$spctl_out" | head -n2 | tr '\n' ' ')"
                fi
            else
                note "$name needs a Mac for pkgutil/stapler/spctl"
            fi
            ;;
        *.tar.gz|*.tgz)
            work="$STAGE/untar-$name"
            mkdir -p "$work"
            tar xzf "$asset" -C "$work" 2>/dev/null || { warn "  could not extract $name"; note "extract failed: $name"; }
            if [ "$IS_MAC" -eq 1 ] && printf '%s' "$name" | grep -q 'apple-darwin'; then
                found_app=0
                while IFS= read -r app; do
                    found_app=1
                    if codesign --verify --strict --deep "$app" >/dev/null 2>&1; then
                        ok "codesign valid: $(basename "$app")"
                    else
                        fail "codesign INVALID: $(basename "$app") in $name"
                    fi
                    # The whole reason the wizard ships as a .app inside the
                    # tarball: a bare Mach-O cannot carry a stapled ticket,
                    # a bundle can, and the ticket survives tar round-trips.
                    if xcrun stapler validate "$app" >/dev/null 2>&1; then
                        ok "notarisation ticket stapled: $(basename "$app")"
                    else
                        fail "no stapled ticket inside $name (offline Macs will refuse it)"
                    fi
                done < <(find "$work" -maxdepth 3 -name '*.app' -type d 2>/dev/null)

                if [ "$found_app" -eq 0 ]; then
                    # Bare CLI binary: signed + notarised is achievable,
                    # stapled is not. Verify what can be verified.
                    while IFS= read -r bin; do
                        if codesign --verify --strict "$bin" >/dev/null 2>&1; then
                            ok "codesign valid: $(basename "$bin")"
                            if codesign -d --verbose=2 "$bin" 2>&1 | grep -q 'flags=.*runtime'; then
                                ok 'hardened runtime enabled'
                            else
                                fail "hardened runtime NOT enabled on $(basename "$bin") -- notarisation would reject it"
                            fi
                        else
                            fail "UNSIGNED Mach-O: $(basename "$bin") in $name"
                        fi
                    done < <(find "$work" -type f -perm -u+x 2>/dev/null | head -n5)
                    note "$name ships a bare binary: no stapled ticket possible, Gatekeeper needs an online check"
                fi
            else
                info '  not a macOS archive; nothing to codesign-verify'
            fi
            ;;
        *.deb)
            info '  .deb carries no embedded signature by design (dpkg does not verify)'
            ;;
        *.msi|*.exe|*.zip)
            note "$name needs Windows: pwsh scripts/signing/90-verify-release.ps1 -Tag $TAG"
            ;;
    esac

    if [ -f "$asset.asc" ]; then
        if command -v gpg >/dev/null 2>&1; then
            if gpg --verify "$asset.asc" "$asset" >/dev/null 2>&1; then ok 'detached GPG signature valid'
            else fail "GPG signature INVALID: $name"; fi
        else
            info '  .asc present but gpg is not installed'
        fi
    fi

    if gh attestation verify "$asset" --repo "$REPO" >/dev/null 2>&1; then
        ok 'build provenance attestation'
    else
        note "no build provenance attestation for $name"
    fi
done

printf '\n%s\n' '------------------------------------------------------------'
if [ -n "$NOTES" ]; then
    say 'Notes'
    printf '%s\n' "$NOTES"
fi

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
    printf 'RELEASE %s VERIFIED\n' "$TAG"
    exit 0
fi
printf 'RELEASE %s FAILED VERIFICATION (%d problem(s))\n' "$TAG" "$FAILURES"
[ "$KEEP" -eq 1 ] && info "artifacts kept at $STAGE"
[ "$WARN_ONLY" -eq 1 ] && exit 0
exit 1
