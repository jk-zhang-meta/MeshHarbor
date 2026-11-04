#!/usr/bin/env bash
#
# fr-verification-debt.sh — an FR does not close on a merged PR.
#
# WHY THIS EXISTS
#
#   `CLAUDE.md` says it in three places and the FR workflow enforces it:
#   **CI green ≠ done.** An FR closes only when its acceptance criteria are
#   FIELD-VERIFIED, and since 2026-09-05 only when its docs exist too. The
#   acceptance criteria in `docs/fr/FR-*.md` are where that verification is
#   recorded — a ticked box is the claim that someone watched the thing work.
#
#   So a CLOSED issue whose spec still carries UNTICKED criteria is one of
#   exactly two things, and both matter:
#
#     1. the work WAS verified and nobody walked back to the checkboxes
#        -> the record is wrong, and the next reader cannot tell which
#     2. the work was NEVER verified and the issue closed on a green lane
#        -> precisely the lie this codebase is built to refuse
#
#   Nothing in this repository could tell those apart, or even notice. The
#   class was measured twice:
#
#     2026-09-01   8 closed FRs carrying 28 unticked criteria
#     2026-09-23  19 closed FRs carrying 74 unticked criteria
#
#   It did not decay. It more than doubled in three weeks, unobserved, while
#   `fr-registry-audit.sh` (the number-collision guard) was green throughout —
#   it audits a different axis entirely, the ledger row against the spec file.
#   This one audits the ISSUE against the spec.
#
#   ⚠️ Among the 74 is FR-73's AC9, the *docs* criterion. "Docs before close"
#      is a standing operator rule, and the one check that could have caught
#      its breach did not exist.
#
# WHY A SEPARATE SCRIPT FROM fr-registry-audit.sh
#
#   That one is hermetic: given a checkout it answers from the tree alone, with
#   no token and no network. It guards FR-number collisions between parallel
#   sessions, which has nothing to do with GitHub being reachable, and folding
#   a network call into it would let an API blip fail the collision guard.
#   This check cannot be hermetic — issue state lives on GitHub and nowhere
#   else — so it is its own script and its own CI job.
#
# THE BASELINE IS A PAIR, NOT A RATCHET
#
#   Borrowed from `name-audit.sh`, which learned it the hard way: a pure
#   "must not increase" ratchet happily passes a PR that pays off one FR's
#   debt and closes another FR with the same number of unticked criteria. The
#   total is unchanged and the guard says OK.
#
#   So each FR is pinned EXACTLY, in both directions:
#
#     count > pinned   -> new debt (criteria unticked, or an FR closed with them)
#     count < pinned   -> debt paid; lower the pin so the floor tracks the tree
#     pinned but open  -> stale entry; the FR reopened
#     pinned, no debt  -> stale entry
#     debt, not pinned -> new debt
#
#   Every entry in the baseline costs a reviewed line that SAYS WHY that FR
#   closed with criteria unticked. That is the whole point: the debt does not
#   become invisible, it becomes attributable. FR-29's entry, for instance,
#   records a criterion its own spec declares "NOT met — and not addressable
#   by P1" — honest, deliberate, and now written down where a guard can see it.
#
# A SECOND CHECK: THE DOCS CRITERION ITSELF
#
#   The operator's rule (PR #1401, 2026-09-05): closing an FR requires its docs,
#   and the docs step is "a phase row AND an acceptance criterion in every
#   spec". The check above can only enforce a criterion that EXISTS — it counts
#   boxes, so a spec that never wrote the docs criterion looks exactly like one
#   whose docs are done. FR-81 was the live case: all 8 criteria ticked, a clean
#   Result, reported as a close candidate — and no docs page, no docs/README.md
#   row, no docs criterion. Its AC8 says "documented in a skill", and that skill
#   is gitignored, so nothing public documents it at all.
#
#   Measured when this was written: 11 of 81 specs carry the criterion, and 37
#   of 41 open FRs lack it. But a rule binds from when it was made, so an FR is
#   BOUND by it if its issue OPENED, or it CLOSED, after the rule reached
#   master. Bound and lacking the criterion: exactly four — FR-74 and FR-81
#   (written after the rule), FR-7 and FR-66 (closed after it). Of the 9 specs
#   written since the rule, 7 carry it.
#
#   The 35 open FRs written BEFORE the rule are reported, not failed: each
#   becomes bound the day it closes, and a close without the criterion fails
#   then. Together the two checks make docs-before-close enforceable at all —
#   this one makes the docs criterion exist, the first makes it ticked.
#
#   ⚠️ Phase rows are NOT checked, although the rule names them. `autopilot`
#      measured 15+ distinct phase-table shapes and prose in place of a table,
#      and records that nothing may depend on parsing them.
#
# USAGE
#   bash scripts/fr-verification-debt.sh                   # CI guard; non-zero on drift
#   bash scripts/fr-verification-debt.sh --summary         # report only, always exit 0
#   bash scripts/fr-verification-debt.sh --update-baseline # after debt is paid or accepted
#
# ⚠️ Deliberately NO `set -o pipefail`, for the reason `fr-registry-audit.sh`
#    records: FR-46's audit died exactly there. `grep` with no match exits 1,
#    and under `pipefail` that killed the script AT THE MOMENT IT SUCCEEDED —
#    empty stdout, empty stderr, a clean tree indistinguishable from a crash.
#    Here "no matches" is the HEALTHY answer for most of these searches.

set -eu

# ⚠️ MEASURED, not precautionary. `docs/fr/README.md` is prose — em-dashes,
#    emoji, and at least one stray `0xA8` that is not valid UTF-8 on its own.
#    In a UTF-8 locale a `sed` `.*` STOPS at that byte rather than running to
#    end of line, so a substitution that looks like it consumed the row left
#    the tail behind and the captured issue number came back as `788<0xA8>`.
#    The lookup then silently missed and eight closed FRs were reported as
#    "issue could not be resolved" instead of as debt — a guard under-reporting
#    while looking healthy, which is the failure this file exists to prevent.
#    Under `LC_ALL=C` every tool treats the file as bytes and `.` matches any
#    of them. The parsers below additionally never match against the prose
#    columns at all, so neither defence relies on the other.
export LC_ALL=C

cd "$(dirname "$0")/.."

FR_DIR="docs/fr"
README="$FR_DIR/README.md"
BASELINE="scripts/fr-ac-debt-baseline.txt"

# The moment the docs-before-close rule reached master: PR #1401's mergedAt.
# ⚠️ NOT the calendar date "2026-09-05", and the difference is not pedantry.
#    FR-69 — the modular monolith — closed at 11:53Z that same day with no
#    reader-facing docs. That close is WHY the operator made the rule, and the
#    PR that stated it (#1401, 20:49Z) also delivered FR-69's owed docs. Keyed
#    on the date, this guard would have named as a breach the one FR the rule
#    was written about, whose docs landed in the very commit that introduced
#    it. A rule binds from when anyone could have read it.
# ISO-8601 UTC with a `Z`, the shape gh returns, so a plain string comparison
# orders these correctly.
RULE_AT="2026-09-05T20:49:42Z"

MODE=check
case "${1:-}" in
    --summary)         MODE=summary ;;
    --update-baseline) MODE=update ;;
    "")                ;;
    *) echo "fr-verification-debt: unknown argument '$1'" >&2; exit 2 ;;
esac

[ -f "$README" ] || { echo "fr-verification-debt: $README not found" >&2; exit 2; }

# ── refuse to scan nothing ───────────────────────────────────────────────────
# `name-audit.sh` carries this guard for a measured reason: a scan that finds
# no files reports a clean tree in exactly the same words as a healthy one.
# Numeric on the FR number, so every list below reads FR-6 … FR-66 … FR-7 as
# 6, 7, 66. ⚠️ No `-u` here: with a key, `sort -u` dedupes on the KEY, and two
# specs sharing a number would silently collapse into one — hiding exactly the
# collision `fr-registry-audit.sh` exists to report. Filenames are already unique.
specs=$(ls -1 "$FR_DIR" 2>/dev/null | grep -E '^FR-[0-9]+-[a-z0-9-]+\.md$' | sort -t- -k2,2n || true)
n_specs=$(printf '%s\n' "$specs" | grep -c . || true)
if [ "$n_specs" -eq 0 ]; then
    echo "FAIL  no FR specs found under $FR_DIR — refusing to report a clean tree." >&2
    exit 2
fi

# ── acceptance criteria, scoped to the section that holds them ───────────────
# Counting every checkbox in the file would sweep in phase tables and open
# decisions. The section is well defined: all 81 specs carry exactly one
# `##`-level heading whose text contains "acceptance criteria", in eight
# spellings ("## Acceptance criteria", "## 8. Acceptance criteria",
# "## Acceptance criteria (all field-verified)", …), and it runs to the next
# `##`. `###` sub-headings do NOT end it — several specs group criteria under
# them, and treating those as the end would silently undercount.
#
# The same pass answers the second question: does the section contain THE docs
# criterion? Two traps, both measured on these 81 specs:
#
#   ⚠️ Criteria are MULTI-LINE. FR-72's and FR-75's index-row commitment sits
#      on a continuation line, so reading only the checkbox line misses them.
#      Each criterion is joined with its indented continuation lines first.
#   ⚠️ Many FEATURE criteria mention a doc — "docs/self-hosting.md states it"
#      (FR-42), "no longer say amd64-only" (FR-57). Those are about the feature,
#      not about documenting it; a matcher on the word "docs" ANYWHERE counts
#      them.
#   ⚠️ …but the index row is not a complete signal either, and that was found
#      the day this shipped. FR-83's criterion — "Docs: `docs/meshharbor-ssh.md`
#      shows the ack in the grant sequence" — updates a doc that is ALREADY
#      indexed, so it has no reason to mention docs/README.md; nor does it name
#      the rule. The guard failed CI naming FR-83 as a breach of the rule it had
#      followed. A matcher calibrated on 81 specs met a legitimate 82nd phrasing.
#
#   So a criterion is the docs criterion when ANY of three holds:
#     1. its SUBJECT is the docs step — the first line, with the checkbox, the
#        bold/italic markers and an `ACn`/`Pn` id stripped, opens with the WORD
#        "docs" ("Docs updated…", "**Docs** —", "AC9 — Docs:"). A feature
#        criterion opens with something else, or with a `docs/` PATH whose
#        content it asserts — excluded by "docs" not followed by "/";
#     2. it commits to the docs/README.md index row (the rule's own words);
#     3. it names the rule outright (FR-23: its deliverable IS documentation).
#   Measured on the 82 specs: (1) adds exactly FR-83 to what (2)+(3) found, and
#   matches none of the feature criteria above.
#   `docs/fr/README.md` — the ledger — does not match (2): there "docs/" is
#   followed by "fr/".
#
# Prints "<ticked> <unticked> <has_docs_criterion 0|1>".
ac_scan() {
    awk '
        function chk(t) {
            if (tolower(t) ~ /docs\/readme\.md|docs[- ]before[- ]close|close[- ]requires[- ]docs/) docs = 1
        }
        function subject(l) {
            sub(/^[[:space:]]*-[[:space:]]*\[[^]]\][[:space:]]*/, "", l)
            gsub(/\*/, "", l)
            sub(/^(AC|P)[0-9]+[a-z]?[^A-Za-z`]*/, "", l)
            if (tolower(l) ~ /^docs?([^a-z\/]|$)/) docs = 1
        }
        /^## .*[Aa]cceptance [Cc]riteria/ { in_ac = 1; next }
        /^## /  { if (cur != "") chk(cur); cur = ""; in_ac = 0 }
        !in_ac  { next }
        /^[[:space:]]*-[[:space:]]*\[[xX]\][[:space:]]/         { ticked++ }
        /^[[:space:]]*-[[:space:]]*\[[^]xX]\][[:space:]]/ { untick++ }
        /^[[:space:]]*-[[:space:]]*\[[^]]\]/ { if (cur != "") chk(cur); cur = $0; subject($0); next }
        /^[[:space:]]+[^[:space:]]/ && cur != "" { cur = cur " " $0; next }
        { if (cur != "") chk(cur); cur = "" }
        END { if (cur != "") chk(cur); printf "%d %d %d\n", ticked + 0, untick + 0, docs + 0 }
    ' "$1"
}

# ── the ledger is the FR -> issue map ────────────────────────────────────────
# Authoritative and offline: the row that claims the number also carries the
# issue it tracks. Reading it here rather than re-deriving from issue titles
# means a spec whose ledger row is missing is already `fr-registry-audit.sh`'s
# fault to report, not silently a different FR's.
#   | [FR-52](FR-52-cross-org-remote-access.md) | [#1100](https://…) | … |
#
# Split on `|` and read the FR and issue out of columns 2 and 3 ONLY. Both are
# pure ASCII link syntax; the prose that carries the awkward bytes lives in
# columns 4 and 5 and is never matched against. A whole-line regex would have
# to cross that prose to reach the end, which is exactly what broke.
fr_to_issue=$(awk -F'|' '
    /^\| \[FR-[0-9]+\]/ {
        if (match($2, /FR-[0-9]+/) == 0) next
        f = substr($2, RSTART + 3, RLENGTH - 3)
        if (match($3, /#[0-9]+/) == 0) next          # e.g. a `#TBD` row
        print f, substr($3, RSTART + 1, RLENGTH - 1)
    }' "$README" || true)

issue_for() { printf '%s\n' "$fr_to_issue" | awk -v n="$1" '$1 == n { print $2; exit }'; }

# ── issue state, the one fact that is not in the tree ────────────────────────
# One call, not one per FR. `gh` infers the repo from the checkout's remote,
# which is what makes this work unchanged in a fork or a worktree.
if ! command -v gh >/dev/null 2>&1; then
    echo "FAIL  \`gh\` is not on PATH, and issue state is the whole question here." >&2
    echo "      This check cannot be answered from the tree. Install gh, or run" >&2
    echo "      scripts/fr-registry-audit.sh for the offline half." >&2
    exit 2
fi

issue_states=$(gh issue list --state all --limit 500 --search "FR- in:title" \
                  --json number,state,createdAt,closedAt \
                  --jq '.[] | "\(.number) \(.state) \(.createdAt) \(.closedAt // "-")"' 2>/dev/null || true)
if [ -z "$issue_states" ]; then
    echo "FAIL  gh returned no FR issues — refusing to report a clean tree." >&2
    echo "      Check authentication (GH_TOKEN) and network." >&2
    exit 2
fi

# "<number> <state> <createdAt> <closedAt|->" for one issue.
issue_row() { printf '%s\n' "$issue_states" | awk -v n="$1" '$1 == n { print; exit }'; }

# ── the baseline ─────────────────────────────────────────────────────────────
pinned_for() {
    [ -f "$BASELINE" ] || return 0
    sed -nE 's/^FR-([0-9]+)=([0-9]+).*/\1 \2/p' "$BASELINE" | awk -v n="$1" '$1 == n { print $2; exit }'
}

# A bound FR with no docs criterion is pinned as `nodocs FR-<n>  # reason`.
# A different line shape from the debt pins on purpose, so neither parser can
# read the other's lines — and `FR-7` must not match `nodocs FR-74`.
nodocs_pinned() {
    [ -f "$BASELINE" ] || return 1
    grep -qE "^nodocs[[:space:]]+FR-$1([^0-9]|\$)" "$BASELINE"
}

faults=0
faults_out=""
# Collected rather than echoed as they are found: the faults are the ANSWER and
# belong after the evidence, not interleaved with the walk that produces it.
fault() { faults_out="$faults_out
  ✗ $*"; faults=$((faults + 1)); }

# ── walk every spec once, classifying as we go ───────────────────────────────
debt_lines=""     # FR-n=count for --update-baseline
ready=""          # open, every criterion ticked, docs criterion present
ready_nodocs=""   # open, every criterion ticked — but there is no docs criterion
nodocs_lines=""   # bound by the docs rule, no docs criterion
predocs=""        # open, written before the rule, no docs criterion yet
unknown=""        # spec with no resolvable issue
n_debt=0
n_debt_criteria=0
n_nodocs=0

for f in $specs; do
    n=$(printf '%s\n' "$f" | sed -E 's/^FR-([0-9]+)-.*/\1/')
    read -r ticked untick has_docs <<EOF
$(ac_scan "$FR_DIR/$f")
EOF

    iss=$(issue_for "$n")
    if [ -z "$iss" ]; then
        unknown="$unknown FR-$n"
        continue
    fi
    row=$(issue_row "$iss")
    if [ -z "$row" ]; then
        unknown="$unknown FR-$n(#$iss)"
        continue
    fi
    read -r _ st created closed <<EOF
$row
EOF

    if [ "$st" = "CLOSED" ] && [ "$untick" -gt 0 ]; then
        n_debt=$((n_debt + 1))
        n_debt_criteria=$((n_debt_criteria + untick))
        debt_lines="$debt_lines
FR-$n=$untick"
        pin=$(pinned_for "$n")
        if [ -z "$pin" ]; then
            fault "FR-$n (#$iss) is CLOSED with $untick unticked acceptance criteria, and is not in $BASELINE — an FR closes on FIELD VERIFICATION, not on a merged PR. Tick them with evidence, or pin them with a reason."
        elif [ "$untick" -gt "$pin" ]; then
            fault "FR-$n (#$iss) now carries $untick unticked criteria, pinned at $pin — $((untick - pin)) new."
        elif [ "$untick" -lt "$pin" ]; then
            fault "FR-$n (#$iss) carries $untick unticked criteria, pinned at $pin — debt was paid; lower the pin (--update-baseline) so the floor keeps tracking the tree."
        fi
    fi

    # Bound by the docs rule? Opened after it (the author could have read it),
    # or closed after it (the close was made under it).
    bound=0
    if [[ "$created" > "$RULE_AT" ]]; then bound=1; fi
    if [ "$st" = "CLOSED" ] && [[ "$closed" > "$RULE_AT" ]]; then bound=1; fi

    if [ "$has_docs" -eq 0 ]; then
        if [ "$bound" -eq 1 ]; then
            n_nodocs=$((n_nodocs + 1))
            nodocs_lines="$nodocs_lines FR-$n"
            if ! nodocs_pinned "$n"; then
                if [ "$st" = "CLOSED" ]; then
                    fault "FR-$n (#$iss) CLOSED after the docs-before-close rule ($RULE_AT) and its spec has NO docs criterion — the rule makes one mandatory in every spec. Add it and document what the FR built, or pin 'nodocs FR-$n' with a reason."
                else
                    fault "FR-$n (#$iss) was opened after the docs-before-close rule ($RULE_AT) and its spec has NO docs criterion. Add one — \"Docs updated/created with diagrams, linked from docs/README.md\" — so that closing without docs is visible here."
                fi
            fi
        elif [ "$st" = "OPEN" ]; then
            predocs="$predocs FR-$n"
        fi
    fi

    # ⚠️ "Every box ticked" is NOT "closable" when no docs box exists: that was
    #    FR-81, reported here as a close candidate with nothing public to show
    #    for it. Only an FR that has the docs criterion — and has ticked it —
    #    is a candidate.
    if [ "$st" = "OPEN" ] && [ "$untick" -eq 0 ] && [ "$ticked" -gt 0 ]; then
        if [ "$has_docs" -eq 1 ]; then
            ready="$ready FR-$n(#$iss,$ticked)"
        else
            ready_nodocs="$ready_nodocs FR-$n(#$iss,$ticked)"
        fi
    fi
done

# ── stale pins ───────────────────────────────────────────────────────────────
# A pin that no longer describes the tree is the failure mode (3) that
# `name-audit.sh` found on master: a floor protects only at the value it was
# last written to, and nothing forces it to move with the tree.
if [ -f "$BASELINE" ]; then
    while read -r pn pv; do
        [ -z "${pn:-}" ] && continue
        case "$debt_lines" in
            *"FR-$pn="*) ;;
            *) fault "$BASELINE pins FR-$pn=$pv, but FR-$pn carries no unticked criteria on a closed issue any more — remove the entry (--update-baseline)." ;;
        esac
    done <<EOF
$(sed -nE 's/^FR-([0-9]+)=([0-9]+).*/\1 \2/p' "$BASELINE")
EOF

    # Same for the docs pins: one that no longer describes the tree is a floor
    # that has stopped tracking it. The spaces around both sides are what keep
    # `FR-7` from matching inside ` FR-74 `.
    for pn in $(sed -nE 's/^nodocs[[:space:]]+FR-([0-9]+).*/\1/p' "$BASELINE"); do
        case " $nodocs_lines " in
            *" FR-$pn "*) ;;
            *) fault "$BASELINE pins 'nodocs FR-$pn', but FR-$pn now carries a docs criterion (or is no longer bound by the rule) — remove the entry (--update-baseline)." ;;
        esac
    done
fi

# ── --update-baseline ────────────────────────────────────────────────────────
if [ "$MODE" = update ]; then
    debt_kv=$(printf '%s\n' "$debt_lines" | grep -E '^FR-[0-9]+=' || true)

    # First creation only: lay down a skeleton. Everything after this is edited
    # SURGICALLY, never regenerated.
    if [ ! -f "$BASELINE" ]; then
        {
            echo "# FR acceptance-criteria debt — update with scripts/fr-verification-debt.sh --update-baseline"
            echo "#"
            echo "# Every line is a CLOSED FR whose spec still carries unticked acceptance"
            echo "# criteria. An FR closes on field verification, so each of these is either a"
            echo "# record that was never updated or a verification that never happened, and"
            echo "# the entry must say WHICH. Counts are pinned exactly, both directions."
            echo "#"
            echo "# ⚠️ Adding a line here is not how an FR closes. It is how an ALREADY-closed"
            echo "#    FR's debt is made attributable instead of invisible."
        } > "$BASELINE"
    fi

    # ⚠️ SURGICAL, not a rewrite — and that distinction was paid for once already
    #    in this very file. The first version regenerated the whole baseline from
    #    a fixed header plus the current counts, carrying per-entry reasons
    #    across. It passed its own test: all 19 reasons survived. What it
    #    destroyed was everything BETWEEN the entries — the provenance block
    #    saying how the file was seeded, the warning that a `## Result` comment
    #    is evidence about the ISSUE and not about these criteria, and the A/B/C
    #    grouping that carries the actual finding. The most valuable prose in the
    #    file, deleted by the command whose whole purpose was to preserve it.
    #
    #    So: comments, blank lines, grouping and ordering are NEVER touched. An
    #    entry whose count is unchanged is emitted byte-for-byte, so the diff
    #    shows only what really moved.
    #
    # ⚠️ …and "byte-for-byte" includes the LINE ENDINGS, which the first version
    #    got wrong on this repo's own dev box. Git for Windows checks this file
    #    out CRLF (`core.autocrlf=true`), and MSYS awk STRIPS the CR on read and
    #    writes a bare LF — measured: `ab\r\n` reads as length 2, prints `ab\n`.
    #    So a no-op update rewrote all 76 lines. `git diff` normalises and showed
    #    nothing, which is exactly why the byte-identity test passed in the main
    #    clone (whose copy had never been re-checked-out) and why nobody would
    #    have seen it — until a raw `diff` in a fresh worktree flagged every line.
    #    Detected with `od`, not `grep $'\r'`: through a pipe on this box that
    #    reported a CR on every line of a file that had none.
    crlf=0
    if od -An -tx1 -v "$BASELINE" | tr ' ' '\n' | grep -q '^0d$'; then crlf=1; fi
    tmp="$BASELINE.tmp.$$"
    awk -v debt="$debt_kv" -v nodocs="$nodocs_lines" '
        BEGIN {
            n = split(debt, arr, "\n")
            for (i = 1; i <= n; i++)
                if (arr[i] != "") { split(arr[i], kv, "="); cur[kv[1]] = kv[2] }
            m = split(nodocs, nd, " ")
            for (i = 1; i <= m; i++) if (nd[i] != "") want[nd[i]] = 1
        }
        /^nodocs[[:space:]]+FR-[0-9]+/ {
            match($0, /FR-[0-9]+/); key = substr($0, RSTART, RLENGTH)
            if (!(key in want)) {
                printf "  - dropped nodocs %s (docs criterion present, or no longer bound)\n", key > "/dev/stderr"
                next
            }
            nseen[key] = 1
            print                                      # a boolean pin: never rewritten
            next
        }
        /^FR-[0-9]+=/ {
            key = $0; sub(/=.*/, "", key)
            if (!(key in cur)) {                       # debt paid, or FR reopened
                printf "  - dropped %s (no debt any more)\n", key > "/dev/stderr"
                next
            }
            seen[key] = 1
            v = $0; sub(/^FR-[0-9]+=/, "", v); sub(/[^0-9].*$/, "", v)
            if (v == cur[key]) { print; next }         # unchanged -> verbatim
            sub(/^FR-[0-9]+=[0-9]+/, key "=" cur[key])
            printf "  - repinned %s: %s -> %s\n", key, v, cur[key] > "/dev/stderr"
            print
            next
        }
        { print }
        END {
            for (k in cur)
                if (!(k in seen)) {
                    printf "%s=%s  # TODO: say why this FR closed with criteria unticked\n", k, cur[k]
                    printf "  - ADDED %s=%s — needs a reason before commit\n", k, cur[k] > "/dev/stderr"
                }
            for (k in want)
                if (!(k in nseen)) {
                    printf "nodocs %s  # TODO: say why this FR is bound by the docs rule and has no docs criterion\n", k
                    printf "  - ADDED nodocs %s — needs a reason before commit\n", k > "/dev/stderr"
                }
        }
    ' "$BASELINE" > "$tmp"

    # Put the file's own line endings back. Every line, whether it came from a
    # `print` or from one of the `printf`s above: those emit a bare LF whatever
    # ORS says. `sub(/\r$/, "")` first, because gawk on Linux does NOT strip the
    # CR on read, and a line that kept one would otherwise end up CR CR LF.
    if [ "$crlf" -eq 1 ]; then
        awk 'BEGIN { ORS = "\r\n" } { sub(/\r$/, ""); print }' "$tmp" > "$tmp.eol"
        mv "$tmp.eol" "$tmp"
    fi
    mv "$tmp" "$BASELINE"

    echo "$BASELINE updated in place — $n_debt FRs / $n_debt_criteria criteria, $n_nodocs nodocs pinned."
    echo "⚠️  Any line marked TODO records a count and nothing else. Say what it is."
    exit 0
fi

# ── report ───────────────────────────────────────────────────────────────────
echo "== closed FRs carrying unticked acceptance criteria =="
if [ "$n_debt" -eq 0 ]; then
    echo "  none"
else
    printf '%s\n' "$debt_lines" | grep -E '^FR-[0-9]+=' | sort -t- -k2 -n | sed 's/^/  /' || true
fi

echo
echo "== FRs bound by the docs-before-close rule, with no docs criterion =="
if [ -z "$nodocs_lines" ]; then
    echo "  none"
else
    for x in $nodocs_lines; do echo "  $x"; done
fi

echo
echo "== open FRs with every acceptance criterion ticked =="
if [ -z "$ready" ] && [ -z "$ready_nodocs" ]; then
    echo "  none"
else
    # Not a fault. Closing also needs, for many criteria, the operator's own
    # eyes — `autopilot` parks exactly here for that reason.
    for r in $ready; do echo "  · $r — candidate to close"; done
    for r in $ready_nodocs; do
        echo "  · $r — every box ticked, but NO docs criterion: not closable under the docs-before-close rule"
    done
fi

n_predocs=$(printf '%s\n' $predocs | grep -c . || true)
if [ "$n_predocs" -gt 0 ]; then
    echo
    echo "== open FRs written before the rule, with no docs criterion yet ($n_predocs) =="
    echo "  Not a fault. Each becomes one if it closes without adding the criterion:"
    echo $predocs | fold -s -w 74 | sed 's/^/    /'
fi

if [ -n "$unknown" ]; then
    echo
    echo "== specs whose issue could not be resolved =="
    for u in $unknown; do echo "  ? $u — no ledger row, or the issue is not an \`FR-\` title"; done
fi

if [ "$faults" -ne 0 ]; then
    echo
    echo "== faults =="
    printf '%s\n' "$faults_out" | grep -v '^$' || true
fi

echo
echo "specs: $n_specs   debt: $n_debt FRs / $n_debt_criteria criteria   nodocs: $n_nodocs bound, $n_predocs pre-rule   faults: $faults"

if [ "$faults" -ne 0 ] && [ "$MODE" = check ]; then
    echo
    echo "An FR closes when its acceptance criteria are FIELD-VERIFIED and its docs"
    echo "exist — not when its PR merges. Tick the criteria with linked evidence, add"
    echo "the docs criterion the rule requires, or pin the gap in $BASELINE"
    echo "with a line saying why."
    exit 1
fi
exit 0
