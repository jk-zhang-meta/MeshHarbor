#!/usr/bin/env bash
#
# name-audit.sh — FR-21's classifier and CI guard for retired product names.
#
#   docs/fr/FR-21-retire-obsolete-binary-names.md · issue #809
#
# WHAT IT IS FOR
#
#   The product renamed its binaries (`roomler-agent` -> `roomlerd`,
#   `roomler-agent-tray` -> `meshharbor-desktop`, `roomler-tunnel` -> `roomler`)
#   but ~1 765 references to the retired names survive across ~233 files.
#   Sweeping them blind is NOT safe: earlier slices (P3d A/B/C, P3e) left
#   deliberate DUAL-READ FALLBACKS so hosts enrolled under the old names keep
#   working, and every one of those looks exactly like an obsolete name.
#   Deleting one fails no build and no test — it strands part of the field at
#   the next update. The macOS `.app` bundle is the worst case: its name keys
#   the TCC grants, so renaming it silently drops Screen Recording and
#   Accessibility on every Mac.
#
#   So every occurrence must be in exactly one of two states:
#
#     * MIGRATED  — gone, replaced by the current name; or
#     * ANCHORED  — deliberately frozen, marked in-line with
#                   `RETIRED-NAME-ANCHOR`, carrying a reason.
#
#   "Occurrence nobody has looked at yet" is the state this script exists to
#   make impossible to keep.
#
# MARKING AN ANCHOR
#
#   Put the marker on or above the line, in whatever comment syntax the file
#   uses. It covers the marker line plus the next N lines (default 1):
#
#     // RETIRED-NAME-ANCHOR: pre-rename hosts still resolve this tree.
#     const OLD_APP: &str = "roomler-agent";
#
#     <!-- RETIRED-NAME-ANCHOR(12): the bundle name keys the macOS TCC grants;
#          renaming it drops Screen Recording + Accessibility fleet-wide. -->
#
#   A marker with no retired name under it is itself an error (`--check`
#   reports it), because a stale marker silently widens the exemption.
#
#   The COLON is part of the marker. `RETIRED-NAME-ANCHOR` written without one
#   is prose, not a marker — so a comment that merely talks ABOUT the scheme
#   cannot accidentally exempt the line beneath it.
#
# TWO CLASSES: ANCHOR (live) vs RECORD (history)          [FR-46, issue #1051]
#
#   FR-21 marked every deliberate occurrence with ONE marker, because under its
#   constraint — migrate or anchor, never disrupt the fleet — they all had the
#   same consequence: delete it and you strand a host. FR-46 lifts that
#   constraint (re-enrollment is authorised), and the population splits:
#
#     RETIRED-NAME-ANCHOR   LIVE compatibility. Code that RESOLVES, MATCHES or
#                           WRITES the retired name at runtime — appdirs trees,
#                           service and task names, log prefixes, env arms,
#                           asset pickers. This class is the work: it can and
#                           must reach zero.
#
#     RETIRED-NAME-RECORD   The HISTORICAL RECORD. Prose and fixtures that name
#                           the retired thing IN ORDER TO EXPLAIN IT — migration
#                           notes, field observations quoting what was actually
#                           measured, tests whose input is by definition a
#                           historical artifact. This class must NOT be renamed:
#                           doing so misreports history. It never reaches zero,
#                           and that is correct.
#
#   The distinction is about the SITE'S JOB, not about difficulty. A migration
#   note is RECORD; the code the note describes is ANCHOR. Reclassifying is
#   exactly as easy as fixing and looks identical in a diff, which is why
#   `records` is pinned EXACTLY in the baseline: the live count can never be
#   reduced by relabelling, and every new RECORD costs a reviewed baseline bump
#   that has to say what it is recording.
#
#   Both classes take the same forms — `RETIRED-NAME-RECORD:`,
#   `RETIRED-NAME-RECORD(N):`, and `RETIRED-NAME-RECORD-BEGIN` / `-END`.
# THE GUARD IS A PAIR, NOT A RATCHET
#
#   A pure "unclassified == 0" check would be red for the whole program, and a
#   pure ratchet ("the count must not increase") is worse than useless: it
#   happily passes a PR that DELETES an anchor and adds one comment — exactly
#   the failure this whole FR exists to prevent. So `--check` asserts BOTH:
#
#     1. unclassified <= baseline   — catches new occurrences being ADDED
#     2. anchors      >= baseline   — catches existing anchors being DELETED
#     3. anchors      <= baseline   — catches the FLOOR going stale
#
#   Together those are sound while the migration is in flight. `--check
#   --strict` replaces (1) with `unclassified == 0` and is what CI runs from
#   P5 onward.
#
#   (3) exists because a floor only protects at the value it was last written
#   to, and nothing was forcing it to move with the tree. On 2026-08-29 master
#   carried 110 anchors against a floor of 83: twenty-seven could have been
#   deleted with `--check` reporting OK, for weeks, silently. (2) and (3)
#   together mean the floor now tracks the tree exactly — raising it is the same
#   one-line `--update-baseline` that lowering it already required.
#
# USAGE
#
#   scripts/name-audit.sh                    # same as --report
#   scripts/name-audit.sh --report           # every occurrence, grouped by file
#   scripts/name-audit.sh --summary          # counts only
#   scripts/name-audit.sh --check            # CI guard (ratchet + anchor floor)
#   scripts/name-audit.sh --check --strict   # CI guard from P5 (must be zero)
#   scripts/name-audit.sh --update-baseline  # after a phase lands
#
set -euo pipefail

# `cd "$(git rev-parse …)"` on its own is not safe: if the rev-parse fails the
# substitution is empty, `cd ""` SUCCEEDS as a no-op, and the scan then runs in
# whatever directory the caller happened to be in — finding nothing and
# reporting `0 occurrences` as though the tree were clean. Observed for real:
# WSL git cannot resolve a worktree whose `.git` file holds a Windows gitdir
# path, and the scan silently returned 0 files.
#
# A guard that reports success after scanning nothing is the same defect this
# repo already documents for the integration lane ("a job that silently runs
# nothing is indistinguishable from a passing one"). Fail loudly instead.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$REPO_ROOT" ] || [ ! -d "$REPO_ROOT" ]; then
    echo "FAIL  cannot resolve the repository root — refusing to scan nothing." >&2
    echo "      \`git rev-parse --show-toplevel\` failed in: $(pwd)" >&2
    exit 2
fi
cd "$REPO_ROOT"

# Same reasoning one level down: an empty file list means the scan covered
# nothing, which must never be reportable as a clean tree.
if [ "$(git ls-files | wc -l)" -lt 2 ]; then
    echo "FAIL  the repository lists no tracked files — refusing to scan nothing." >&2
    exit 2
fi

BASELINE_FILE="scripts/name-audit-baseline.txt"

# The retired names, as extended-regex alternatives. `roomler-agent` also
# covers `roomler-agent-tray` and `roomler-agent-core`; `roomler-tunnel` also
# covers `roomler-tunnel-installer`. The CamelCase and spaced forms are the
# Windows service/task identifiers and the WiX DisplayName — user-visible
# surfaces that belong in the inventory, not just the snake/kebab code forms.
TOKENS='roomler-agent|roomler_agent|ROOMLER_AGENT_|RoomlerAgent|Roomler Agent|roomler-tunnel|roomler_tunnel|Roomler Tunnel|roomler-installer'

# Files excluded from the scan, each for a reason that is about the FILE'S JOB,
# not about it being inconvenient. This list must stay this short: a growing
# exclusion list is the hand-maintained path list the marker scheme exists to
# replace.
#
#   * this script          — it contains every token by construction
#   * the baseline         — it records counts, and may quote a token
#   * an FR spec whose SUBJECT is the retired names (FR-21 retired them,
#     FR-46 eradicates them) — such a spec cannot discuss its own topic
#     without naming it, and anchoring every mention would bury the prose.
#     This is a rule about the file's job, not a place to park work: a spec
#     that merely MENTIONS a retired name does not qualify.
is_excluded() {
    case "$1" in
        scripts/name-audit.sh) return 0 ;;
        "$BASELINE_FILE") return 0 ;;
        docs/fr/FR-21-*|docs/fr/FR-46-*) return 0 ;;
        *) return 1 ;;
    esac
}

# ── scan ────────────────────────────────────────────────────────────────────
#
# Walks each candidate file once, tracking anchor coverage, and emits one
# tab-separated record per interesting line:
#
#   <kind>\t<file>\t<lineno>\t<text>
#
# where kind is UNCLASSIFIED, ANCHORED, or STALEMARKER.
scan() {
    local files
    # Files with a retired name, UNION files carrying a marker.
    #
    # The union half closes a blind spot found the hard way (FR-46 P5b/P2b): a
    # file selected only by `git grep -l "$TOKENS"` drops OUT of the scan the
    # moment its LAST retired name is migrated — taking any marker it still
    # holds with it. The marker is then orphaned and structurally unreportable:
    # it covers nothing, widens no exemption today, and silently would if a
    # retired name ever reappeared under it. Seven of them accumulated across
    # six files in one phase before anyone noticed, and the audit could not
    # have said so.
    files=$(
        {
            git grep -I -l -E "$TOKENS" -- . || true
            git grep -I -l -E 'RETIRED-NAME-(ANCHOR|RECORD)' -- . || true
        } | sort -u
    )

    local f
    for f in $files; do
        is_excluded "$f" && continue
        TOKENS="$TOKENS" awk -v file="$f" '
            BEGIN { cover = 0; in_block = 0; span = 1; cover_kind = "ANCHORED"; region_kind = "ANCHORED" }
            {
                line = $0
                sub(/\r$/, "", line)
                bare = line
                sub(/^[ \t]*/, "", bare)

                has_token = (line ~ ENVIRON["TOKENS"])

                # A BEGIN/END pair covers a whole REGION. Line-counted spans are
                # too brittle for prose — a historical appendix is edited far more
                # often than it is renumbered — so a region that is frozen as a
                # body (an appendix recording what operators actually typed, a
                # legacy-cleanup module) says so explicitly at both ends.
                if (line ~ /RETIRED-NAME-(ANCHOR|RECORD)-BEGIN/) {
                    region_kind = (line ~ /RETIRED-NAME-RECORD-BEGIN/) ? "RECORD" : "ANCHORED"
                    in_region = 1
                    region_line = NR
                    region_used[NR] = 0
                    next
                }
                if (line ~ /RETIRED-NAME-(ANCHOR|RECORD)-END/) {
                    if (!in_region)
                        print "STALEMARKER\t" file "\t" NR "\tEND without a matching BEGIN"
                    else if (!region_used[region_line])
                        print "STALEMARKER\t" file "\t" region_line "\tBEGIN/END region holds no retired name"
                    in_region = 0
                    next
                }
                if (in_region) {
                    if (has_token) {
                        print region_kind "\t" file "\t" NR "\t" line
                        region_used[region_line] = 1
                    }
                    next
                }

                # The COLON is required, so that a line which merely MENTIONS the
                # marker in prose does not become one. Matching the bare token
                # anywhere meant a comment reading "...with no RETIRED-NAME-ANCHOR"
                # silently anchored the line beneath it and the audit went green —
                # found while writing a regression test whose own comment
                # exempted the regression. A silent exemption is the exact failure
                # this script exists to prevent, so it must not be reachable by
                # writing about the script.
                #
                # Safe by inspection, not by hope: all 146 span markers in the tree
                # use `RETIRED-NAME-ANCHOR:` or `RETIRED-NAME-ANCHOR(N):`, and the
                # BEGIN/END region markers are consumed above before this runs.
                is_marker = (line ~ /RETIRED-NAME-(ANCHOR|RECORD)(\([0-9]+\))?:/)
                # Which CLASS this marker declares. ANCHOR is live compatibility and
                # must reach zero; RECORD is the historical record and must not be
                # renamed at all. See docs/fr/FR-46.
                marker_kind = (line ~ /RETIRED-NAME-RECORD(\([0-9]+\))?:/) ? "RECORD" : "ANCHORED"
                # Comment syntaxes across the tree: Rust/TS //, shell/YAML/systemd #,
                # block-comment continuation *, /*, XML <!--, ini ;.
                is_comment = (bare ~ /^(\/\/|#|\*|\/\*|<!--|;)/)
                # An XML/HTML comment spans lines whose continuations start with
                # ordinary prose, so prefix-matching alone ends the block at the
                # first wrapped line and the marker stops short of the code it
                # explains. Track the open comment explicitly instead.
                if (in_xml_comment) {
                    is_comment = 1
                    if (line ~ /-->/) in_xml_comment = 0
                } else if (line ~ /<!--/ && line !~ /-->/) {
                    in_xml_comment = 1
                    is_comment = 1
                }

                if (is_marker) {
                    # A marker covers its whole (possibly multi-line) comment block plus
                    # the next `span` code lines, default 1. That is what a reader means
                    # by "this comment explains the line below it", and it stops at the
                    # first code line so the exemption cannot silently widen.
                    span = 1
                    if (match(line, /RETIRED-NAME-(ANCHOR|RECORD)\([0-9]+\)/)) {
                        n = substr(line, RSTART, RLENGTH)
                        gsub(/[^0-9]/, "", n)
                        span = n + 0
                    }
                    if (NR > cover) cover = NR
                    in_block = 1
                    marker_line[NR] = 1
                    marker_used[NR] = 0
                    last_marker = NR
                    cover_kind = marker_kind
                } else if (in_block) {
                    if (is_comment) {
                        cover = NR                       # still inside the comment block
                    } else {
                        cover = NR + span - 1            # first code line(s) under it
                        in_block = 0
                    }
                }

                if (has_token) {
                    if (NR <= cover) {
                        print cover_kind "\t" file "\t" NR "\t" line
                        if (last_marker) marker_used[last_marker] = 1
                    } else {
                        print "UNCLASSIFIED\t" file "\t" NR "\t" line
                    }
                }
            }
            END {
                for (m in marker_line)
                    if (!marker_used[m])
                        print "STALEMARKER\t" file "\t" m "\tmarker covers no retired name"
                # A BEGIN with no END silently swallows the REST OF THE FILE —
                # the widest possible exemption, and the one least likely to be
                # noticed, because everything it hides simply stops being
                # reported. Caught here rather than trusted to review.
                if (in_region)
                    print "STALEMARKER\t" file "\t" region_line "\tBEGIN with no matching END — it exempts the rest of the file"
            }
        ' "$f"
    done
}

# File and directory NAMES that still carry a retired name. Paths cannot carry
# an in-line marker, so they are counted and baselined separately.
scan_paths() {
    git ls-files | grep -E "$TOKENS" || true
}

read_baseline() {
    local key="$1" default="$2"
    if [ -f "$BASELINE_FILE" ]; then
        local v
        v=$(grep -E "^${key}=" "$BASELINE_FILE" | head -1 | cut -d= -f2 | tr -d ' \r') || true
        [ -n "${v:-}" ] && { echo "$v"; return; }
    fi
    echo "$default"
}

MODE=report
STRICT=0
for arg in "$@"; do
    case "$arg" in
        --report)          MODE=report ;;
        --summary)         MODE=summary ;;
        --check)           MODE=check ;;
        --update-baseline) MODE=update ;;
        --strict)          STRICT=1 ;;
        -h|--help)         sed -n "2,$(( $(grep -n '^set -euo pipefail' "$0" | head -1 | cut -d: -f1) - 1 ))p" "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

RESULTS=$(scan)
PATHS=$(scan_paths)

n_unclassified=$(printf '%s\n' "$RESULTS" | grep -c '^UNCLASSIFIED' || true)
n_anchored=$(printf '%s\n' "$RESULTS" | grep -c '^ANCHORED' || true)
n_records=$(printf '%s\n' "$RESULTS" | grep -c '^RECORD' || true)
n_stale=$(printf '%s\n' "$RESULTS" | grep -c '^STALEMARKER' || true)
n_paths=$(printf '%s\n' "$PATHS" | grep -c . || true)
n_files=$(printf '%s\n' "$RESULTS" | grep '^UNCLASSIFIED' | cut -f2 | sort -u | grep -c . || true)

case "$MODE" in
report)
    # ⚠ The `|| true` is load-bearing and reads like noise, so it invites deletion.
    # Under `set -euo pipefail` a `grep` that matches NOTHING exits 1 and takes the
    # whole script with it. That meant this audit died SILENTLY, printing no summary
    # at all, at exactly the moment the repo became FULLY CLASSIFIED -- the success
    # case was indistinguishable from a crash. It stayed latent for the entire
    # program because there was always one unclassified line left to keep grep happy.
    # Every sibling grep above already carries this guard; this one alone did not.
    #
    # Scoped as `{ ...; }` rather than trailing the pipeline: `a | b || true` binds to
    # the WHOLE pipeline and would mask a real awk failure downstream too.
    printf '%s\n' "$RESULTS" | { grep '^UNCLASSIFIED' || true; } | \
        awk -F'\t' '{ if ($2 != last) { print ""; print "── " $2; last = $2 } printf "  %6s  %s\n", $3, substr($4, 1, 120) }'
    if [ "$n_stale" -gt 0 ]; then
        echo; echo "── stale anchor markers (cover no retired name)"
        printf '%s\n' "$RESULTS" | grep '^STALEMARKER' | awk -F'\t' '{ printf "  %s:%s\n", $2, $3 }'
    fi
    if [ "$n_paths" -gt 0 ]; then
        echo; echo "── file/folder names still carrying a retired name"
        printf '%s\n' "$PATHS" | sed 's/^/  /'
    fi
    echo
    ;&
summary)
    echo "unclassified : $n_unclassified occurrences in $n_files files"
    echo "anchored     : $n_anchored (deliberately frozen, marked)"
    echo "record       : $n_records (historical record — must NOT be renamed; see docs/fr/FR-46)"
    echo "stale markers: $n_stale"
    echo "paths        : $n_paths file/folder names"
    ;;
update)
    {
        echo "# FR-21 name-audit baseline — regenerate with scripts/name-audit.sh --update-baseline"
        echo "# anchors is LIVE compatibility and must trend to 0 (FR-46); records is the"
        echo "# historical record and is pinned exactly. Both fail the guard if they move"
        echo "# without this file moving with them, in either direction."
        echo "unclassified=$n_unclassified"
        echo "anchors=$n_anchored"
        echo "records=$n_records"
        echo "paths=$n_paths"
    } > "$BASELINE_FILE"
    echo "baseline written: unclassified=$n_unclassified anchors=$n_anchored records=$n_records paths=$n_paths"
    ;;
check)
    rc=0
    # An anchor block inserted at the top of a script pushes the shebang off
    # line 1, where it stops being a shebang and becomes an ordinary comment.
    # That is not hypothetical: it shipped on this branch and broke the macOS
    # .pkg — `installer` failed at "Validating packages" because it could not
    # execute postinstall at all. Nothing else catches it; the file still
    # parses, still lints, and reads fine in review.
    displaced=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        head -c 2 "$f" 2>/dev/null | grep -q '^#!' && continue
        head -30 "$f" 2>/dev/null | grep -q '^#!/' || continue
        displaced="$displaced $f"
    done <<EOF
$(git ls-files 2>/dev/null)
EOF
    if [ -n "$displaced" ]; then
        echo "FAIL  a shebang is not on line 1:"
        for f in $displaced; do echo "        $f"; done
        echo "      A shebang only works as line 1. Put the anchor block BELOW it."
        rc=1
    fi

    # An anchor block dropped into the MIDDLE of a `//!`/`///` doc comment
    # splits two sentences at once -- the doc's and the anchor's own -- and
    # nothing catches it: the file still compiles, still passes `cargo fmt`,
    # and the audit still counts the anchor. It happened in
    # `meshharbor-setup-core/src/integration.rs`, where the module doc read
    # "...v1 just" and resumed five lines later at "ensures `roomler-tunnel`
    # is on PATH", while the anchor's own "(it leaves" ... "the old entry
    # stranded" was split around it. Leftover from converting `///` markers
    # to `//`: they were converted in place instead of being hoisted out.
    #
    # The tell is an anchor's prose resuming AFTER doc lines, before any code.
    # `#` is a comment only OUTSIDE Rust -- inside it starts an attribute
    # (`#[arg(long)]`), and treating those as prose flags every correctly
    # placed anchor (16 false positives when this check was first written).
    split_anchor=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in *.rs) hash_is_comment=0 ;; *) hash_is_comment=1 ;; esac
        if awk -v H="$hash_is_comment" '
              function isdoc(l) { return l ~ /^[[:space:]]*(\/\/!|\/\/\/)/ }
              function isprose(l) {
                  if (isdoc(l)) return 0
                  if (l ~ /^[[:space:]]*\/\//) return 1
                  if (H == "1" && l ~ /^[[:space:]]*#/) return 1
                  return 0
              }
              /RETIRED-NAME-(ANCHOR|RECORD)/ && !/RETIRED-NAME-(ANCHOR|RECORD)-END/ { st=1; sd=0; rs=0; next }
              st==1 {
                  if (isdoc($0))   { sd=1; next }
                  if (isprose($0)) { if (sd) rs=1; next }
                  if (rs) { found=1 }
                  st=0; next
              }
              END { exit(found ? 0 : 1) }
           ' "$f"; then
            split_anchor="$split_anchor $f"
        fi
    done <<EOF
$(git ls-files 2>/dev/null)
EOF
    if [ -n "$split_anchor" ]; then
        echo "FAIL  an anchor block is interleaved with a doc comment:"
        for f in $split_anchor; do echo "        $f"; done
        echo "      Hoist the whole anchor block ABOVE the doc comment (or below it),"
        echo "      never into the middle -- it silently splits both sentences."
        rc=1
    fi

    # An anchor placed inside a `\`-continued STRING LITERAL becomes part of the
    # STRING, not a comment. Rust's line continuation swallows the newline and
    # the leading whitespace, so the marker text is emitted by whatever that
    # string builds.
    #
    # Not hypothetical, and not cosmetic. `service.rs` generated the per-user
    # systemd unit and the macOS LaunchAgent plist from two such literals, and
    # an FR-21 anchor sat inside BOTH. The unit came out carrying
    # `// RETIRED-NAME-ANCHOR(2): renaming a lib renames its TRACING TARGET.`
    # as a directive line, and the plist came out with the same text between
    # `<key>EnvironmentVariables</key>` and its `<dict>` — which is invalid XML,
    # so launchctl cannot load the LaunchAgent at all.
    #
    # Nothing else catches it: the file compiles, `cargo fmt` is happy, and the
    # audit counts the anchor exactly as it would anywhere else.
    #
    # Detected by the one signal that is unambiguous — the PREVIOUS line ends in
    # a backslash. Tested with `substr` rather than a regex on purpose: `/\\$/`
    # silently fails to match here while `/\\\\$/` works, and this script has
    # been bitten by that class of escape often enough already.
    in_literal=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in *.rs) ;; *) continue ;; esac
        if awk '
              /RETIRED-NAME-(ANCHOR|RECORD)/ &&
              length(prev) > 0 && substr(prev, length(prev), 1) == "\\" { found = 1 }
              { prev = $0 }
              END { exit(found ? 0 : 1) }
           ' "$f"; then
            in_literal="$in_literal $f"
        fi
    done <<EOF
$(git ls-files 2>/dev/null)
EOF
    if [ -n "$in_literal" ]; then
        echo "FAIL  an anchor sits inside a \\-continued string literal:"
        for f in $in_literal; do echo "        $f"; done
        echo "      Rust's line continuation eats the newline, so the marker text is"
        echo "      EMITTED by whatever that string builds — a systemd unit, a plist."
        echo "      Move it above the format!/literal, never inside it."
        rc=1
    fi

    # `env::node_env` reads THREE prefixes so a retired spelling keeps working.
    # A test that pokes ONE of them directly is not hermetic: it clears one link
    # and an inherited value under another silently decides the assertion. That
    # was true of every env test in the agent (14 suffixes, 8 files) in both
    # directions -- some proved only the retired name, others only the current
    # one. `env::test_env` clears all three from the same PREFIXES list the
    # readers use, so this keeps them going through it.
    #
    # A site that genuinely needs both spellings live at once (proving which one
    # WINS) marks itself RAW-ENV-DELIBERATE on or just above the line.
    raw_env=$(grep -rnE '(set_var|remove_var)\("(ROOMLERD_|ROOMLER_NODE_|ROOMLER_AGENT_)' \
        --include=*.rs agents crates 2>/dev/null \
        | grep -v '^crates/tunnel-core/src/env.rs:' || true)
    unmarked=""
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        f=${hit%%:*}; rest=${hit#*:}; ln=${rest%%:*}
        case "$ln" in *[!0-9]*|"") continue ;; esac
        from=$((ln > 4 ? ln - 4 : 1))
        if ! sed -n "${from},${ln}p" "$f" 2>/dev/null | grep -q 'RAW-ENV-DELIBERATE'; then
            unmarked="$unmarked        $f:$ln
"
        fi
    done <<EOF
$raw_env
EOF
    if [ -n "$unmarked" ]; then
        echo "FAIL  raw node_env prefix in env manipulation (use env::test_env):"
        printf '%s' "$unmarked"
        echo "      test_env clears ALL prefixes; poking one leaves the test open to"
        echo "      an inherited value under another spelling deciding it."
        echo "      If both spellings must be live at once, mark the line RAW-ENV-DELIBERATE."
        rc=1
    fi

    base_unclassified=$(read_baseline unclassified 999999)
    base_anchors=$(read_baseline anchors 0)
    base_records=$(read_baseline records 0)
    base_paths=$(read_baseline paths 999999)

    if [ "$n_stale" -gt 0 ]; then
        echo "FAIL  $n_stale stale RETIRED-NAME-ANCHOR marker(s) cover no retired name."
        echo "      A marker with nothing under it silently widens the exemption."
        printf '%s\n' "$RESULTS" | grep '^STALEMARKER' | awk -F'\t' '{ printf "        %s:%s\n", $2, $3 }'
        rc=1
    fi

    if [ "$n_anchored" -lt "$base_anchors" ]; then
        echo "FAIL  anchors dropped $base_anchors -> $n_anchored."
        echo "      A deleted anchor strands pre-rename hosts and fails NO build and NO test."
        echo "      If an anchor is genuinely retired, lower it in $BASELINE_FILE in the same PR"
        echo "      and say in the PR body which field state no longer exists."
        rc=1
    fi

    # A floor only protects at the value it was last written to. Anchors were
    # added in later batches without regenerating the baseline, and on
    # 2026-08-29 master carried 110 anchors against a floor of 83 — meaning 27
    # could have been deleted with `--check` reporting OK. That is precisely the
    # failure the floor exists to prevent, and nothing surfaced it for weeks:
    # the guard was quieter than the tree it was guarding.
    #
    # So the floor must track the tree in BOTH directions. Raising it is a
    # one-line `--update-baseline` in the same PR that adds the anchor, which is
    # the same discipline already required for lowering it.
    if [ "$n_anchored" -gt "$base_anchors" ]; then
        echo "FAIL  anchors rose $base_anchors -> $n_anchored, so the floor is now STALE."
        echo "      It would not notice the next $(( n_anchored - base_anchors )) anchor(s) being deleted."
        echo "      Run: scripts/name-audit.sh --update-baseline   (and commit it in this PR)"
        rc=1
    fi

    # RECORD is pinned exactly, in BOTH directions, for the same reason anchors
    # are — but the failure it prevents is different and worse. An ANCHOR that
    # disappears strands a host; a RECORD that appears launders a live
    # compatibility site into permanence, because reclassifying is exactly as
    # easy as fixing and looks identical in a diff. Pinning it means every new
    # RECORD is a deliberate, reviewed act with a number attached, and the live
    # count can never be reduced by relabelling.
    if [ "$n_records" -ne "$base_records" ]; then
        if [ "$n_records" -gt "$base_records" ]; then
            echo "FAIL  records rose $base_records -> $n_records."
            echo "      A new RECORD says a site names the retired thing IN ORDER TO EXPLAIN IT"
            echo "      and can never be renamed. If it is live compatibility, it is an ANCHOR."
        else
            echo "FAIL  records dropped $base_records -> $n_records."
            echo "      Deleting a RECORD erases the account of what actually happened."
        fi
        echo "      Run: scripts/name-audit.sh --update-baseline   (and commit it in this PR,"
        echo "      saying in the PR body which record was added or retired, and why)."
        rc=1
    fi

    if [ "$STRICT" -eq 1 ]; then
        if [ "$n_unclassified" -ne 0 ]; then
            echo "FAIL  $n_unclassified unclassified occurrence(s); strict mode requires 0."
            rc=1
        fi
    elif [ "$n_unclassified" -gt "$base_unclassified" ]; then
        echo "FAIL  unclassified rose $base_unclassified -> $n_unclassified."
        echo "      Use the current name, or mark the site with RETIRED-NAME-ANCHOR and say why."
        rc=1
    fi

    if [ "$n_paths" -gt "$base_paths" ]; then
        echo "FAIL  retired-name paths rose $base_paths -> $n_paths."
        rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        echo "OK    unclassified=$n_unclassified (<= $base_unclassified)  anchors=$n_anchored (== $base_anchors)  records=$n_records (== $base_records)  paths=$n_paths (<= $base_paths)"
    fi
    exit "$rc"
    ;;
esac
