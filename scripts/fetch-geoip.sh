#!/usr/bin/env bash
#
# fetch-geoip.sh — stage the country database the server image carries (#1896).
#
#   scripts/fetch-geoip.sh              # into files/geoip/, which the Dockerfile COPYs
#   scripts/fetch-geoip.sh <dest-dir>
#
#   Run it BEFORE `docker build`. Both image workflows do (hosted-image.yml,
#   publish-selfhost-image.yml), and so must a build-host or source build that
#   wants countries in the user analytics.
#
# WHAT IT FETCHES
#   DB-IP's "IP to Country Lite" in MaxMind DB format: this month's release, or
#   last month's. DB-IP publishes a month on its 1st (06:27 UTC for 2026-09), so
#   for the first hours of every month the current name answers 404. Older
#   releases stay downloadable for a few months.
#     https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
#   It lands as dbip-country-lite.mmdb, the path the image's
#   MESHHARBOR__STATS__GEOIP_MMDB names, with dbip-country-lite.provenance.txt
#   beside it: the release, URL, SHA-256, licence and credit.
#
# WHY THIS DATABASE
#   The image is a PUBLIC package. DB-IP licenses its Lite databases under
#   CC BY 4.0, which permits redistributing them with attribution
#   (db-ip.com/db/download/ip-to-country-lite):
#     "You are free to use this IP to Country Lite database in your
#      application, provided you give attribution to DB-IP.com for the data.
#      In the case of a web application, you must include a link back to
#      DB-IP.com on pages that display or use results from the database."
#   The observability dashboard carries that link. MaxMind's GeoLite2 cannot go
#   into a public image: its EULA (§6) forbids disclosing GeoLite data to any
#   third party without MaxMind's prior written consent.
#
# WHAT IT CHECKS
#   The download comes over TLS from DB-IP's own host. Then: a valid gzip stream
#   (its CRC catches a truncated or corrupted transfer), a size between 1 MiB and
#   128 MiB (the 2026-10 release is 8.3 MB, an HTML error page is a few KB, and
#   anything city-sized is not the country database), and MaxMind DB metadata
#   that names the type DBIP-Country-Lite.
#   It does NOT pin a checksum. A pin would need a commit every month, and the
#   sums DB-IP lists come from the same origin as the file, so they prove no
#   more than the gzip CRC does. It RECORDS the SHA-256 of what it staged, in
#   the provenance file and in the log. The deep check belongs to the server:
#   the image smoke boots it and requires "geoip database loaded".
#
# A MISSING DATABASE IS A SUPPORTED STATE
#   Every failure here (DB-IP unreachable or stalled, a release not yet
#   published, a file that is not what it claims) stages NOTHING and exits 0
#   with a warning, within about five minutes at worst. A database an earlier
#   run staged is kept. Without one the image reports `country: unknown` and
#   `geoip: false`, as designed: a build must never fail because a third
#   party's download did.
#
# Exit 0 = staged, or warned and skipped. Exit 2 = usage error.
# Under GitHub Actions it also sets step outputs: present=true|false,
# release=YYYY-MM (or "kept"), sha256=<hex>.
#
# GEOIP_BASE_URL overrides https://download.db-ip.com/free (an https mirror,
# or a way to exercise the failure path).

set -u

NAME=dbip-country-lite
TYPE=DBIP-Country-Lite
BASE_URL="${GEOIP_BASE_URL:-https://download.db-ip.com/free}"
BASE_URL="${BASE_URL%/}"
MIN_BYTES=$((1024 * 1024))
MAX_BYTES=$((128 * 1024 * 1024))

DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/files/geoip}"
if [ ! -d "$DEST" ]; then
  echo "usage: $0 [<dest-dir>]   ('$DEST' is not a directory)" >&2
  exit 2
fi
DB="$DEST/$NAME.mmdb"
PROVENANCE="$DEST/$NAME.provenance.txt"

output() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1=$2" >> "$GITHUB_OUTPUT"; fi; }
warn() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::warning title=GeoIP database::$1"
  else
    echo "WARNING: $1" >&2
  fi
}
sha256() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }
bytes() { wc -c < "$1" | tr -d ' '; }

WORK="$(mktemp -d)" || {
  warn "cannot create a temporary directory, so no GeoIP database was staged"
  output present false
  exit 0
}
TMP_DB=""
trap 'rm -rf "$WORK"; [ -z "$TMP_DB" ] || rm -f "$TMP_DB"' EXIT

# This month, then last month, in UTC. From ONE `date` call (so a run that
# straddles midnight cannot mix two months), and by arithmetic rather than
# `date -d`, which BSD date does not have.
NOW="$(date -u +%Y-%m)"
Y=${NOW%-*}
M=$((10#${NOW#*-}))
if [ "$M" -eq 1 ]; then
  PREV=$(printf '%04d-12' $((Y - 1)))
else
  PREV=$(printf '%04d-%02d' "$Y" $((M - 1)))
fi

# fetch <YYYY-MM>: 0 with a verified database at $WORK/db, else 1 (and why).
#
# ⚠️ Every wait is bounded, because a download that HANGS must not fail the
# build either: the hosted job has a 60-minute timeout. One attempt may take
# 90 s, and no retry starts after 60 s, so each URL costs at most about two and
# a half minutes, and the script about five. (The release is 4 MB compressed;
# a runner fetches it in about a second.)
fetch() {
  local rel="$1" url="$BASE_URL/$NAME-$1.mmdb.gz" size
  rm -f "$WORK/db.gz" "$WORK/db"
  if ! curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 90 \
      --retry 2 --retry-delay 5 --retry-max-time 60 --max-filesize $((64 * 1024 * 1024)) \
      -o "$WORK/db.gz" "$url"; then
    echo "  $rel: download failed ($url)"
    return 1
  fi
  if ! gzip -t "$WORK/db.gz" 2>/dev/null; then
    echo "  $rel: not a valid gzip stream"
    return 1
  fi
  # Decompressed through `head -c`, so nothing can write more than the size
  # limit below to disk; anything that big is then refused by that limit.
  gzip -dc "$WORK/db.gz" 2>/dev/null | head -c $((MAX_BYTES + 1)) > "$WORK/db"
  size=$(bytes "$WORK/db")
  if [ "$size" -lt "$MIN_BYTES" ] || [ "$size" -gt "$MAX_BYTES" ]; then
    echo "  $rel: $size bytes, outside the range a country database can have"
    return 1
  fi
  # MaxMind DB metadata sits in the last 128 KiB, after the marker
  # \xAB\xCD\xEF"MaxMind.com"; `database_type` is a string inside it. Files,
  # not pipes: `grep -q` closing a pipe early can fail the pipeline.
  tail -c 131072 "$WORK/db" > "$WORK/meta"
  printf '\253\315\357MaxMind.com\n' > "$WORK/marker"
  if ! LC_ALL=C grep -a -q -F -f "$WORK/marker" "$WORK/meta"; then
    echo "  $rel: no MaxMind DB metadata, so not an .mmdb file"
    return 1
  fi
  if ! LC_ALL=C grep -a -q -F "$TYPE" "$WORK/meta"; then
    echo "  $rel: the metadata does not name the type $TYPE"
    return 1
  fi
  return 0
}

# stage <YYYY-MM>: move the verified database into $DEST and describe it.
# A temp file in the SAME directory, then a rename: a `docker build` reading
# $DEST never sees half a file.
# ⚠️ The chmod is load-bearing. `mktemp` creates the file 0600, `cp` into it
# and `mv` keep that, and Docker's COPY keeps the bits: the image would hold a
# root-only file that a container running as any other user cannot read, and
# every country would read `unknown`. (This script's first local run staged
# exactly that, a 0600 file; the image smokes run as root and would never have
# seen it, so they now read the file as uid 65534.)
stage() {
  local rel="$1" sum size
  TMP_DB="$(mktemp "$DEST/.$NAME.XXXXXX")" || return 1
  cp "$WORK/db" "$TMP_DB" || return 1
  chmod 0644 "$TMP_DB" || return 1
  mv -f "$TMP_DB" "$DB" || return 1
  TMP_DB=""
  sum=$(sha256 "$DB")
  size=$(bytes "$DB")
  {
    echo "DB-IP IP to Country Lite, release $rel (MaxMind DB format), unmodified."
    echo "source:  $BASE_URL/$NAME-$rel.mmdb.gz"
    echo "sha256:  $sum  ($NAME.mmdb, $size bytes)"
    echo "fetched: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "licence: Creative Commons Attribution 4.0 International (CC BY 4.0)"
    echo "         https://creativecommons.org/licenses/by/4.0/"
    echo "credit:  IP Geolocation by DB-IP, https://db-ip.com"
    echo "DB-IP provides the database as is, without warranties of any kind;"
    echo "the licence above carries the full disclaimer."
  } > "$PROVENANCE"
  echo "  staged $NAME.mmdb: release $rel, $size bytes, sha256 $sum"
  output present true
  output release "$rel"
  output sha256 "$sum"
}

echo "GeoIP: DB-IP IP to Country Lite -> $DB"
for rel in "$NOW" "$PREV"; do
  if fetch "$rel"; then
    if stage "$rel"; then
      exit 0
    fi
    echo "  $rel: verified, but could not be written to $DEST"
    break
  fi
done

if [ -s "$DB" ]; then
  warn "could not fetch a fresh DB-IP database, so the one already in $DEST is kept"
  output present true
  output release kept
  output sha256 "$(sha256 "$DB")"
  exit 0
fi
rm -f "$PROVENANCE"
warn "no GeoIP database staged: this image will report country 'unknown' (geoip: false). The build goes on; see files/geoip/README.md"
output present false
exit 0
