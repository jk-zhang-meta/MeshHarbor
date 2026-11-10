#!/usr/bin/env bash
# Apply (or check, or strip) SPDX headers across first-party source (FR-24).
#
#   scripts/apply-spdx.sh            apply headers, idempotently
#   scripts/apply-spdx.sh --check    exit 1 if any file is missing//wrong; write nothing
#   scripts/apply-spdx.sh --strip    remove headers this script added
#
# Idempotent by construction: a file whose first non-shebang line already names
# the right licence is left byte-identical. A file naming the WRONG licence is
# rewritten — that is the case that matters when a directory changes class.
#
# The classification lives in scripts/licence-classes.sh; this script only knows
# how to write a comment in each file type.

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/licence-classes.sh
source scripts/licence-classes.sh

MODE="apply"
case "${1:-}" in
  --check) MODE="check" ;;
  --strip) MODE="strip" ;;
  "")      ;;
  *)       echo "usage: $0 [--check|--strip]" >&2; exit 2 ;;
esac

applied=0 skipped=0 fixed=0 missing=0 unclassified=0

# comment_style <path> -> "line" | "block" | "" (unsupported)
comment_style() {
  case "$1" in
    *.rs|*.ts|*.js|*.mts|*.cts) printf 'line' ;;
    *.vue|*.html)               printf 'block' ;;
    *)                          printf '' ;;
  esac
}

header_for() {
  local licence="$1" style="$2"
  if [ "$style" = "block" ]; then
    printf '<!-- SPDX-License-Identifier: %s -->\n<!-- Copyright (C) %s %s -->\n' \
      "$licence" "$COPYRIGHT_YEAR" "$COPYRIGHT_HOLDER"
  else
    printf '// SPDX-License-Identifier: %s\n// Copyright (C) %s %s\n' \
      "$licence" "$COPYRIGHT_YEAR" "$COPYRIGHT_HOLDER"
  fi
}

# Files are listed by git, so untracked build output and anything in
# .gitignore can never be rewritten by accident.
while IFS= read -r file; do
  [ -f "$file" ] || continue

  style="$(comment_style "$file")"
  [ -n "$style" ] || continue

  if ! licence="$(licence_for "$file")"; then
    # ⚠️ Unclassified is an ERROR in --check, never a silent skip. A directory
    # RETIRED-NAME-ANCHOR: names the pre-FR-21 path on purpose — this comment
    # exists to record the rename that motivated the check.
    # RENAME is what makes this matter: FR-21 moved agents/meshharbor-agent ->
    # agents/meshharbord, and with a skip the whole daemon would have dropped out
    # of the sweep while the check still reported OK — files shipping with no
    # licence header at all, and nothing saying so.
    if [ "$MODE" = check ] && ! is_excluded "$file"; then
      echo "UNCLASSIFIED (add its directory to scripts/licence-classes.sh): $file"
      unclassified=$((unclassified + 1))
    fi
    continue
  fi

  existing="$(head -3 "$file" | grep -m1 -oE 'SPDX-License-Identifier: [A-Za-z0-9.\-]+' || true)"
  existing="${existing#SPDX-License-Identifier: }"

  if [ "$MODE" = "strip" ]; then
    [ -n "$existing" ] || continue
    # Drop the leading SPDX + Copyright lines this script writes.
    sed -i -E '1,3{/^(\/\/|<!--) SPDX-License-Identifier: /d; /^(\/\/|<!--) Copyright \(C\) /d}' "$file"
    applied=$((applied + 1))
    continue
  fi

  if [ "$existing" = "$licence" ]; then
    skipped=$((skipped + 1))
    continue
  fi

  if [ "$MODE" = "check" ]; then
    if [ -z "$existing" ]; then
      echo "missing SPDX ($licence): $file"
      missing=$((missing + 1))
    else
      echo "wrong SPDX (want $licence, found $existing): $file"
      fixed=$((fixed + 1))
    fi
    continue
  fi

  tmp="$file.spdx.tmp"

  if [ -n "$existing" ]; then
    # Wrong licence — replace the identifier in place, keep everything else.
    sed -E "1,3s|SPDX-License-Identifier: [A-Za-z0-9.\\-]+|SPDX-License-Identifier: $licence|" \
      "$file" > "$tmp"
    mv "$tmp" "$file"
    fixed=$((fixed + 1))
    continue
  fi

  # A shebang must stay on line 1, or the kernel resolves the wrong interpreter.
  first="$(head -1 "$file")"
  case "$first" in
    '#!'*)
      { printf '%s\n' "$first"; header_for "$licence" "$style"; tail -n +2 "$file"; } > "$tmp"
      ;;
    *)
      { header_for "$licence" "$style"; cat "$file"; } > "$tmp"
      ;;
  esac
  mv "$tmp" "$file"
  applied=$((applied + 1))
done < <(git ls-files)

case "$MODE" in
  check)
    if [ "$((missing + fixed + unclassified))" -gt 0 ]; then
      echo
      echo "FAIL: $missing missing an SPDX header, $fixed with the wrong licence, $unclassified unclassified."
      echo "Run: scripts/apply-spdx.sh"
      exit 1
    fi
    echo "OK: every classified source file carries the right SPDX header ($skipped checked)."
    ;;
  strip)  echo "stripped $applied header(s)." ;;
  apply)  echo "added $applied, corrected $fixed, already correct $skipped." ;;
esac
