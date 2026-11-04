#!/usr/bin/env bash
#
# anchor-range-audit.sh — no `file:N-M` anchor in the docs whose end comes before its start.
#
# WHY THIS EXISTS
#
#   The docs point into the code by line: `crates/localapi/src/lib.rs:2759`, a range
#   `agents/meshharbord/src/main.rs:4849-4856`, or a link `[…](../x.rs#L100-L120)`. Every
#   change that moves code moves those numbers, and they are re-shifted at merge time.
#   A shift that moves only the FIRST number of a range leaves `:2088-2087`, which points
#   at nothing a reader can follow, and no build, test or link checker notices: the file
#   exists and both numbers are in range. Measured on 2026-10-21: 31 such ranges on
#   master, across 13 docs, every one of them a half-shifted range.
#
#   An inverted range is always wrong, whatever the code says, so it needs no knowledge
#   of the code to catch. The ones already on master are pinned in
#   `scripts/anchor-range-baseline.txt`; anything NEW fails.
#
#   The baseline only shrinks. A pinned range that is gone (fixed, or its doc rewritten)
#   fails too, until its line is removed, so the file never keeps vouching for a range
#   that no longer exists, and a later re-inversion of the same text can't hide behind it.
#
# USAGE
#   bash scripts/anchor-range-audit.sh            # audit, exit non-zero on any fault
#   bash scripts/anchor-range-audit.sh --summary  # report only, always exit 0
#   bash scripts/anchor-range-audit.sh --list     # print every inverted range, baseline form
#
# ⚠️ Deliberately NO `set -o pipefail`: `grep` with no match exits 1, and "no match" is
#    the healthy answer here (fr-registry-audit.sh's note, learned the same way).

set -eu

cd "$(dirname "$0")/.."

BASELINE="scripts/anchor-range-baseline.txt"
MODE="${1:-}"

# A path with a code or doc extension, then `:N-M` or `#LN-LM` (`#LN-M` too).
EXT='rs|ts|tsx|vue|js|mjs|cjs|yml|yaml|sh|ps1|toml|py|json|html|css|go|swift|c|h|md'
PATTERN="[A-Za-z0-9_./-]+\\.(${EXT})(:|#L)[0-9]+-L?[0-9]+"

# Every inverted range as `doc<TAB>anchor`, one per occurrence, sorted.
current() {
  git ls-files -z '*.md' \
    | xargs -0 grep -HoE "$PATTERN" 2>/dev/null \
    | awk -F'\t' '{
        i = index($0, ":"); doc = substr($0, 1, i - 1); a = substr($0, i + 1)
        r = a; sub(/^.*(:|#L)/, "", r); split(r, n, "-"); s = n[1]; e = n[2]; sub(/^L/, "", e)
        if (e + 0 < s + 0) print doc "\t" a
      }' \
    | LC_ALL=C sort || true
}

pinned() {
  [ -f "$BASELINE" ] || return 0
  # `tr`: a Windows checkout may hand the baseline over with CRLF line ends.
  tr -d '\r' < "$BASELINE" | grep -vE '^[[:space:]]*(#|$)' | LC_ALL=C sort || true
}

if [ "$MODE" = "--list" ]; then
  current
  exit 0
fi

now="$(current)"
base="$(pinned)"

# Multiset differences: `comm` on sorted lists keeps duplicates paired one for one.
new="$(LC_ALL=C comm -23 <(printf '%s\n' "$now" | sed '/^$/d') <(printf '%s\n' "$base" | sed '/^$/d'))"
gone="$(LC_ALL=C comm -13 <(printf '%s\n' "$now" | sed '/^$/d') <(printf '%s\n' "$base" | sed '/^$/d'))"

faults=0
if [ -n "$new" ]; then
  echo "Inverted anchor ranges (the end comes before the start):"
  printf '%s\n' "$new" | while IFS="$(printf '\t')" read -r doc a; do
    line="$(grep -nF -- "$a" "$doc" | head -n 1 | cut -d: -f1)"
    echo "  ✗ ${doc}:${line:-?}  ${a}"
  done
  echo "  Point the range at the code it means: both ends, start ≤ end."
  faults=$((faults + $(printf '%s\n' "$new" | wc -l)))
fi
if [ -n "$gone" ]; then
  echo "Pinned in $BASELINE but no longer in the docs (fixed, or the doc changed):"
  printf '%s\n' "$gone" | while IFS="$(printf '\t')" read -r doc a; do
    echo "  ✗ ${doc}  ${a}"
  done
  echo "  Remove those lines from $BASELINE: the baseline only shrinks."
  faults=$((faults + $(printf '%s\n' "$gone" | wc -l)))
fi

total="$(printf '%s\n' "$now" | sed '/^$/d' | wc -l | tr -d ' ')"
pinned_n="$(printf '%s\n' "$base" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "anchor-range-audit: ${total} inverted range(s) in the docs, ${pinned_n} pinned, ${faults} fault(s)"

if [ "$faults" -gt 0 ] && [ "$MODE" != "--summary" ]; then
  exit 1
fi
exit 0
