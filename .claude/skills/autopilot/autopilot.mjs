#!/usr/bin/env node
// autopilot — ingest FR state into cards, render the kanban board.
//
// Subcommands:
//   scan   [--repo <path>] [--docs <path>]   refresh cards from the ledger + specs + GitHub
//   board  [--docs <path>]                   regenerate BOARD.md from the cards
//   next   [--docs <path>] [--n 3]           print the next N cards by closest-to-done rank
//
// Why Node: this box has no python3 and no jq on the Git-Bash PATH (measured 2026-09-08).
// `gh --jq` covers GitHub reads; everything local is plain Node with zero dependencies.
//
// The cards are the run state. The GitHub issue and the FR spec remain authoritative for
// engineering truth — this never writes to either.

import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, basename } from 'node:path';

const COLUMNS = [
  ['admitted', 'Admitted'],
  ['judgement', 'Needs your judgement'],
  ['in_progress', 'In progress'],
  ['pr_open', 'PR open'],
  ['field', 'Field verification'],
  ['ready', 'Ready to close'],
];
const COLUMN_IDS = COLUMNS.map(([id]) => id);

const args = process.argv.slice(2);
const cmd = args[0];
const flag = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const REPO = flag('repo', 'C:/dev/jk-zhang-meta/MeshHarbor');
const DOCS = flag('docs', 'C:/dev/jk-zhang-meta/meshharbor-docs');
const STATE = join(DOCS, 'kanban', 'state');

// ---------------------------------------------------------------- ledger

// | [FR-52](FR-52-cross-org-remote-access.md) | [#1100](…/issues/1100) | Title | Status prose |
// The vacated `| ~~FR-3~~ | — | *vacated* … |` row must not match: it has no spec link.
//
// The issue cell is captured SEPARATELY from the row match on purpose. A row whose issue is
// `#TBD` or `—` is a claimed number with nothing published behind it, and dropping it
// silently is how a collision hides: the first run of this scanner found exactly that —
// a local branch holding `FR-80 | #TBD` for a spec master had already given to #1532.
// An unreadable row is REPORTED, never skipped.
const LEDGER_ROW = /^\|\s*\[FR-(\d+)\]\(([^)]+)\)\s*\|\s*([^|]*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$/;
const ISSUE_CELL = /\[#(\d+)\]/;

// ALWAYS read the ledger and the specs from origin/master, never the working tree. The
// ledger is the claim, and only master arbitrates it — a feature branch's copy is one
// session's opinion. Read from the tree instead and the queue changes shape depending on
// which branch the operator happens to be standing on: measured 2026-09-08, a branch
// holding `FR-80 | #TBD` hid master's real FR-80 (#1532) from the scan entirely.
function fromMaster(path) {
  try {
    return execFileSync('git', ['-C', REPO, 'show', `origin/master:${path}`], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

function readLedger() {
  const text = fromMaster('docs/fr/README.md')
    ?? readFileSync(join(REPO, 'docs', 'fr', 'README.md'), 'utf8');
  const rows = [], unclaimed = [];
  for (const line of text.split(/\r?\n/)) {
    const m = LEDGER_ROW.exec(line);
    if (!m) continue;
    const issueM = ISSUE_CELL.exec(m[3]);
    if (!issueM) {
      unclaimed.push({ fr: Number(m[1]), specFile: m[2], issueCell: m[3], title: m[4] });
      continue;
    }
    rows.push({
      fr: Number(m[1]),
      specFile: m[2],
      issue: Number(issueM[1]),
      title: m[4],
      ledgerStatus: m[5],
    });
  }
  return { rows, unclaimed };
}

// ---------------------------------------------------------------- spec parsing

function sectionBody(text, headingRe) {
  const lines = text.split(/\r?\n/);
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^##\s/.test(lines[i]) && headingRe.test(lines[i])) { start = i + 1; break; }
  }
  if (start < 0) return null;
  const out = [];
  for (let i = start; i < lines.length; i++) {
    if (/^##\s/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out;
}

// ACs are the spine: every one of the 79 specs uses `- [ ]` / `- [x]`, 73 have the heading,
// but only 13 use the bold `**ACn**` form — so the id is OPTIONAL and positional numbering
// is the fallback. Continuation lines (indented, or the trailing *( … )* evidence) are
// folded into the item they belong to.
//
// The mark is ANY one character, not just ` ` / `x`. The specs also use `- [~]` for "half
// met" — 11 criteria across 7 specs (2026-09-24) — and a pattern that knew only two marks
// skipped that line. That did two things at once. The criterion vanished from its card.
// And the lines under it, which are indented, were added to the criterion ABOVE it. So
// FR-79's docs criterion (AC7) carried half of AC8's field evidence, and its card read 6/8
// when the spec says 6 of 9.
// ⚠️ Only `x` means done. `~` is kept as `mark` and counted as open. A mark this parser
// has never seen is also open: a parser must never tick a box it cannot read.
const AC_ITEM = /^- \[(.)\]\s*(.*)$/;
// The whole bold span is the id, not just `ACn`. FR-70 splits criteria into halves —
// `**AC5 (attribution half)**`, `**AC6 (rate half)**` — and a regex demanding the bold
// END at the digit rejects those, dropping them to POSITIONAL ids that then collide with
// the spec's own later `**AC7**`. That produced a phantom "two criteria labelled AC7"
// warning against a spec that is perfectly correct: the duplicate was ours, not theirs.
// ⚠️ A parser that invents ids will eventually accuse a document of its own bug.
// Group 1 is the id (`AC5`); group 2 is anything else inside the bold span, which FR-70
// uses to split a criterion into halves — `**AC5 (attribution half)**`. The qualifier is
// kept in the TEXT, never folded into the id: the id has to stay stable and readable, and
// the text is what preserves a `verify` judgement across a reword.
const AC_BOLD_ID = /^\*\*(AC\s*\d+[a-z]?)([^*]*)\*\*\s*(?:—|-|:)?\s*/i;

// The criteria whose id the SPEC wrote (`**AC7**`), as opposed to a positional count. Kept
// out of the card JSON on purpose (a WeakSet, not a field): it matters only while a rescan
// carries judgements over, and persisting it would rewrite every card for no reader.
const NAMED = new WeakSet();

function parseAcs(text) {
  const body = sectionBody(text, /acceptance\s+criteri/i);
  if (!body) return [];
  const acs = [];
  const used = new Set();
  // Whether indented lines still belong to the last item. A non-indented line that is not
  // an item ends the item above it: continuation text that follows such a line is the
  // START of something the parser could not read, never the END of the previous criterion.
  let open = false;
  for (const raw of body) {
    const m = AC_ITEM.exec(raw);
    if (m) {
      let rest = m[2].trim();
      let id = null;
      const b = AC_BOLD_ID.exec(rest);
      if (b) {
        id = b[1].replace(/\s+/g, '');
        const qualifier = (b[2] || '').trim();
        rest = (qualifier ? qualifier + ' — ' : '') + rest.slice(b[0].length);
      }
      id = id || `AC${acs.length + 1}`;
      // A spec may legitimately number two criteria the same (FR-70's halves). Disambiguate
      // rather than warn: a collision here is the document's business, not a fault.
      if (used.has(id)) { let n = 2; while (used.has(`${id}#${n}`)) n++; id = `${id}#${n}`; }
      used.add(id);
      const ac = {
        id,
        text: rest,
        done: m[1].toLowerCase() === 'x',
        verify: 'unclassified', // agent | operator | unclassified — see Q10 in SKILL.md
      };
      // Only for a mark that is neither ` ` nor `x`, so the 600-odd ordinary criteria keep
      // their exact shape and a rescan does not rewrite every card on the board.
      if (!/[ xX]/.test(m[1])) ac.mark = m[1];
      if (b) NAMED.add(ac);
      acs.push(ac);
      open = true;
    } else if (open && /^\s+\S/.test(raw)) {
      acs[acs.length - 1].text += ' ' + raw.trim();
    } else if (/^\S/.test(raw)) {
      open = false;
    }
  }
  // Evidence parentheticals bloat the text; keep the claim, drop the log.
  for (const ac of acs) {
    ac.text = ac.text.replace(/\s*\*\([^)]*\)\*/g, '').replace(/\s+/g, ' ').trim();
  }
  return acs;
}

// Does the spec carry THE docs criterion that docs-before-close requires? This mirrors
// `ac_scan` in `scripts/fr-verification-debt.sh`, the guard that fails master when an FR
// closes without one. A criterion counts when ANY of its three rules holds:
//   1. its SUBJECT opens with the word "docs" (not a `docs/` path, which is a feature
//      criterion asserting some doc's content);
//   2. it commits to the `docs/README.md` index row;
//   3. it names the rule ("docs-before-close" / "close requires docs").
// ⚠️ Keep the two in step. If the guard's rules change, change this too: a board that
// disagrees with the guard parks a card as Ready to close that the close then turns red.
// That happened to FR-22 on 2026-09-25, and FR-24 was sitting in the same state.
// The one intended difference: a `- [~]` line starts a criterion here (#1614).
function hasDocsCriterion(text) {
  let inAc = false, cur = null, docs = false;
  const chk = (t) => {
    if (/docs\/readme\.md|docs[- ]before[- ]close|close[- ]requires[- ]docs/i.test(t)) docs = true;
  };
  const subject = (l) => {
    const s = l.replace(/^\s*-\s*\[.\]\s*/, '').replace(/\*/g, '')
      .replace(/^(AC|P)[0-9]+[a-z]?[^A-Za-z`]*/, '');
    if (/^docs?([^a-z/]|$)/i.test(s)) docs = true;
  };
  for (const l of text.split(/\r?\n/)) {
    if (/^## .*[Aa]cceptance [Cc]riteria/.test(l)) { inAc = true; continue; }
    if (/^## /.test(l)) { if (cur) chk(cur); cur = null; inAc = false; continue; }
    if (!inAc) continue;
    if (/^\s*-\s*\[.\]/.test(l)) { if (cur) chk(cur); cur = l; subject(l); continue; }
    if (/^\s+\S/.test(l) && cur) { cur += ' ' + l; continue; }
    if (cur) chk(cur);
    cur = null;
  }
  if (cur) chk(cur);
  return docs;
}

// Phases are BEST EFFORT and nothing depends on them: only 41 of 79 specs have the heading,
// the tables under it have 15+ distinct header shapes, and FR-70 has prose instead of a
// table. Match header cells by NAME, never by position; a spec we cannot parse gets [].
function parsePhases(text) {
  const body = sectionBody(text, /^##\s+Phases?\b/i);
  if (!body) return [];
  const rows = body.filter((l) => /^\s*\|/.test(l));
  if (rows.length < 3) return [];
  const cells = (l) => l.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
  const head = cells(rows[0]).map((h) => h.toLowerCase().replace(/[*`]/g, '').trim());
  // A short name matches EXACTLY. `startsWith('p')` read FR-6's `PR(s)` column as its
  // phase ids; only a word as long as `phase` is safe to match as a prefix.
  const idx = (names, not = -1) => head.findIndex((h, i) => i !== not
    && names.some((n) => h === n || (n.length > 3 && h.startsWith(n))));
  const iId = idx(['phase', 'p', '#', 'wave']);
  // `| # | Phase | Kill switch |` puts the description under `Phase`, and FR-68 and
  // FR-76 showed "P0 — " with nothing after it. So `phase` is a description column too,
  // but only as a FALLBACK, and never when it is already the id column. A table that
  // has a real `What` column keeps it: FR-59 has both.
  const iWhatNamed = idx(['what', 'scope', 'content', 'delivers', 'deliverable', 'change']);
  const iWhat = iWhatNamed >= 0 ? iWhatNamed : idx(['phase'], iId);
  const iStatus = idx(['status', 'outcome', 'state']);
  if (iId < 0) return [];
  const out = [];
  for (const row of rows.slice(2)) {
    const c = cells(row);
    if (!c[iId]) continue;
    const clean = (s) => (s || '').replace(/\*\*/g, '').trim();
    out.push({
      id: clean(c[iId]),
      what: clean(c[iWhat]).slice(0, 200),
      // `null` = the table has NO status column, so the state is unknown. That is not
      // the same as an empty cell, which does mean "not started". Seven specs' tables have
      // no status column. Reading their `''` as "not started" put "P0 — This spec + ledger
      // row + issue" on the board as FR-61's next step, on a card at 9/11.
      status: iStatus < 0 ? null : clean(c[iStatus]).slice(0, 300),
    });
  }
  return out;
}

// ---------------------------------------------------------------- GitHub

function gh(argv) {
  return execFileSync('gh', argv, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

function openIssues() {
  const raw = gh([
    'issue', 'list', '--repo', 'jk-zhang-meta/MeshHarbor',
    '--state', 'open', '--limit', '300',
    '--json', 'number,title,labels,updatedAt',
  ]);
  return JSON.parse(raw);
}

function openPrs() {
  const raw = gh([
    'pr', 'list', '--repo', 'jk-zhang-meta/MeshHarbor',
    '--state', 'open', '--limit', '100',
    '--json', 'number,title,headRefName,isDraft,updatedAt,files',
  ]);
  return JSON.parse(raw);
}

// Open PRs that EDIT this FR's spec, whatever their branch is called. Branch names miss a
// PR that works on several FRs at once. On 2026-09-24, #1598 (`fr-verification-debt`)
// was adding a criterion to FR-74's and FR-81's specs while the board showed both as
// Ready to close: an operator closing FR-81 then would have closed it one criterion short.
// ⚠️ gh returns at most 100 files per PR, so a PR larger than that can hide a spec edit.
function specEditors(prs, fr) {
  const re = new RegExp(`^docs/fr/FR-0*${fr}-`);
  return prs.filter((p) => (p.files || []).some((f) => re.test(f.path))).map((p) => p.number);
}

// ---------------------------------------------------------------- work in flight

// The autopilot TRACES work that is already under way; it never picks it up. A card whose
// FR has a live branch, a checked-out worktree or uncommitted changes is somebody's
// in-flight work, and a worker that started there would be racing a human over the same
// files. That is the #1144 shape — a merged, field-verified fix silently reverted, green
// CI, no conflict — and it is cheaper to observe than to recover from.
// Tunable with --fresh-days. Conservative by default: a false hands-off costs a card not
// being picked up, which the operator can see and override on the board; a false dispatch
// costs a collision with a human over the same files, which they may not see until merge.
const FRESH_DAYS = Number(flag('fresh-days', '14'));

function git(argv, cwd = REPO) {
  try {
    return execFileSync('git', ['-C', cwd, ...argv], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch { return ''; }
}

function branchIndex() {
  return git(['for-each-ref', '--format=%(refname:short)\t%(committerdate:unix)', 'refs/heads'])
    .split(/\r?\n/).filter(Boolean)
    .map((l) => { const [name, ts] = l.split('\t'); return { name, ts: Number(ts) }; });
}

function worktreeIndex() {
  const out = [], blocks = git(['worktree', 'list', '--porcelain']).split(/\n\n+/);
  for (const b of blocks) {
    const p = /^worktree (.+)$/m.exec(b);
    const br = /^branch refs\/heads\/(.+)$/m.exec(b);
    if (p) out.push({ path: p[1].trim(), branch: br ? br[1].trim() : null });
  }
  return out;
}

// Tracked files only: an untracked scratch file is not evidence that someone is mid-change.
const isDirty = (path) => git(['status', '--porcelain', '--untracked-files=no'], path).trim().length > 0;

// A branch whose PR MERGED is finished work that nobody deleted, not work in flight.
//
// Found on FR-43 (2026-09-24): its card sat hands-off on
// `fr43-p2d-installer-stops-reverting-delegation`, "touched 14d ago" — but that branch's
// PR (#1553) had merged on 2026-09-09. Age alone cannot tell "being worked on" from
// "done and left behind", and this box keeps branches for ever, so the age rule held
// back cards with no live work behind them at all.
//
// ⚠️ This repo SQUASH-merges, so `git merge-base --is-ancestor <branch> origin/master`
// would call every merged branch UNMERGED — its commits never reach master verbatim.
// GitHub's record of which PR merged, keyed by head branch, is the only authority.
// ⚠️ An UNCOMMITTED worktree still wins over a merged PR: someone may have reused a
// merged branch's checkout for new work, and that is exactly what must not be raced.
let MERGED_BRANCHES = null;
function mergedBranches() {
  if (MERGED_BRANCHES) return MERGED_BRANCHES;
  try {
    const raw = gh([
      'pr', 'list', '--repo', 'jk-zhang-meta/MeshHarbor',
      '--state', 'merged', '--limit', '1000', '--json', 'headRefName',
    ]);
    MERGED_BRANCHES = new Set(JSON.parse(raw).map((p) => p.headRefName));
  } catch {
    // Fail CLOSED toward safety: with no merged-set, fall back to the age rule rather
    // than treat every branch as finished and let a worker race a human.
    MERGED_BRANCHES = new Set();
  }
  return MERGED_BRANCHES;
}

function traceInFlight(card, fr, branches, worktrees, editors = []) {
  const re = new RegExp(`^fr-?0*${fr}(?![0-9])`, 'i');
  const now = Date.now() / 1000;
  const merged = mergedBranches();
  const found = [];
  for (const b of branches.filter((b) => re.test(b.name))) {
    const wt = worktrees.find((w) => w.branch === b.name);
    const ageDays = Math.round((now - b.ts) / 86400);
    found.push({
      branch: b.name,
      age_days: ageDays,
      worktree: wt ? wt.path : null,
      uncommitted: wt ? isDirty(wt.path) : false,
      merged: merged.has(b.name),
    });
  }
  card.run.in_flight = found;

  const live = found.some((f) => f.uncommitted || (!f.merged && f.age_days <= FRESH_DAYS));
  const fresh = found.find((x) => !x.merged && x.age_days <= FRESH_DAYS);
  const dirty = found.find((f) => f.uncommitted);
  const editing = editors.filter((n) => n !== card.run.adopted_pr);
  card.run.hands_off = Boolean(card.run.adopted_pr || live || editing.length);
  card.run.hands_off_reason = !card.run.hands_off ? null
    : card.run.adopted_pr ? `open PR #${card.run.adopted_pr}`
    : dirty ? `uncommitted changes in ${dirty.worktree}`
    : fresh ? `branch ${fresh.branch} touched ${fresh.age_days}d ago (no merged PR)`
    : `open PR ${editing.map((n) => '#' + n).join(', ')} edits this spec`;
  return card.run.hands_off;
}

// ---------------------------------------------------------------- reaping worktrees

// Remove a worktree once EVERY card that used it is closed — and nothing else, ever.
//
// Rail 6 says never delete a worktree this skill did not create, and 62 worktrees plus
// 1043 branches predate it. So a candidate must clear three independent gates, and each
// one alone would be too weak:
//   1. its basename matches the `ap-` prefix this skill names its own worktrees with;
//   2. at least one CARD records that path in `run.worktree` — proving we made it, rather
//      than inferring it from a name someone else could pick;
//   3. every issue referencing it (active cards AND archived ones) is closed — the user's
//      rule is "all FRs closed", and one worktree can serve several.
// Then `git worktree remove` runs WITHOUT `--force`, so git itself refuses on uncommitted
// changes. A refusal is reported, never overridden: the whole point is that the operator's
// work is not this skill's to discard.
function reapWorktrees(openIssueNumbers) {
  const archiveDir = join(DOCS, 'kanban', 'archive');
  const cards = [...allCards()];
  if (existsSync(archiveDir)) {
    for (const f of readdirSync(archiveDir).filter((x) => x.endsWith('.json'))) {
      cards.push(JSON.parse(readFileSync(join(archiveDir, f), 'utf8')));
    }
  }

  // path -> the issues that used it
  const byPath = new Map();
  for (const c of cards) {
    const p = c.run?.worktree;
    if (!p) continue;
    const key = p.replace(/\\/g, '/').replace(/\/+$/, '');
    if (!byPath.has(key)) byPath.set(key, new Set());
    byPath.get(key).add(c.issue);
  }
  if (!byPath.size) return;

  const live = new Set(worktreeIndex().map((w) => w.path.replace(/\\/g, '/').replace(/\/+$/, '')));

  for (const [path, issuesUsing] of byPath) {
    if (!live.has(path)) continue;                       // already gone
    if (!/^ap-/.test(path.split('/').pop() || '')) {
      console.warn(`  ⚠️  ${path} is referenced by a card but is not an \`ap-\` worktree — left alone`);
      continue;
    }
    const stillOpen = [...issuesUsing].filter((n) => openIssueNumbers.has(n));
    if (stillOpen.length) continue;                      // the user's rule: ALL of them closed

    const out = git(['worktree', 'remove', path]);       // no --force, deliberately
    if (live.has(path) && git(['worktree', 'list']).includes(path)) {
      console.warn(`  ⚠️  ${path}: every issue closed (${[...issuesUsing].map((n) => '#' + n).join(', ')}) but git refused to remove it`);
      console.warn('      — almost certainly uncommitted changes. Left in place on purpose; look before forcing.');
    } else {
      console.log(`  🧹 ${path} removed — every issue that used it is closed (${[...issuesUsing].map((n) => '#' + n).join(', ')})`);
    }
    void out;
  }
  git(['worktree', 'prune']);
}

// ---------------------------------------------------------------- cards

const cardPath = (id) => join(STATE, `${id}.json`);

function loadCard(id) {
  const p = cardPath(id);
  return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null;
}

function saveCard(card) {
  mkdirSync(STATE, { recursive: true });
  card.updated_at = new Date().toISOString();
  writeFileSync(cardPath(card.id), JSON.stringify(card, null, 2) + '\n', 'utf8');
}

function allCards() {
  if (!existsSync(STATE)) return [];
  return readdirSync(STATE)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(STATE, f), 'utf8')));
}

const freshRun = () => ({
  branch: null, worktree: null, pr: null, adopted_pr: null,
  attempts: 0, last_action: null, started_at: null, heartbeat: null,
  budget_halted: false, notes: [],
  in_flight: [], hands_off: false, hands_off_reason: null,
});

// ---------------------------------------------------------------- scan

function scan() {
  const { rows: ledger, unclaimed } = readLedger();
  const issues = openIssues();
  const prs = openPrs();
  const branches = branchIndex();
  const worktrees = worktreeIndex();
  const byNumber = new Map(issues.map((i) => [i.number, i]));

  let created = 0, updated = 0, skipped = 0;

  for (const row of ledger) {
    const issue = byNumber.get(row.issue);
    if (!issue) { skipped++; continue; } // closed issue — not our queue

    const id = `FR-${row.fr}`;
    const specRel = `docs/fr/${basename(row.specFile)}`;
    const specPath = join(REPO, specRel);
    const text = fromMaster(specRel) ?? (existsSync(specPath) ? readFileSync(specPath, 'utf8') : null);
    let acs = [], phases = [];
    if (text) { acs = parseAcs(text); phases = parsePhases(text); }

    const prev = loadCard(id);
    // A rescan must never silently un-classify an AC a human or a worker judged, and must
    // never resurrect a tick the spec has since cleared: the SPEC owns `done`, the CARD
    // owns `verify`.
    //
    // Match on TEXT first, and on the id only when the spec NAMED it. A positional id is a
    // count, and a count moves under every criterion added above it. This used to match
    // on id first, which is only right when ids are stable. On 2026-09-24 the parser
    // stopped dropping FR-56's `[~]` criterion, every positional id below it moved down
    // one, and an id-first match gave each judgement to the neighbour: an `operator`
    // verdict landed on a box already ticked, and the open box it was written about came
    // back `unclassified`.
    // ⚠️ The honest failure is `unclassified`, which the board counts and warns about. A
    // judgement on the WRONG criterion sends work to the wrong party and nothing shows it.
    // A positional id is still trustworthy when the COUNT did not change, and only then.
    // In that case nothing was inserted, so a criterion whose text grew (a note appended,
    // evidence added on the tick) keeps its verdict. The one exception is a previous
    // occupant that a text match has already claimed, because that criterion MOVED.
    if (prev) {
      const prevById = new Map(prev.acs.map((a) => [a.id, a]));
      const prevByText = new Map(prev.acs.map((a) => [a.text, a]));
      const stable = acs.length === prev.acs.length;
      const claimed = new Set();
      const matched = new Map();
      for (const ac of acs) {
        const old = prevByText.get(ac.text);
        if (old) { matched.set(ac, old); claimed.add(old); }
      }
      for (const ac of acs) {
        if (matched.has(ac) || !(NAMED.has(ac) || stable)) continue;
        const old = prevById.get(ac.id);
        if (old && !claimed.has(old)) { matched.set(ac, old); claimed.add(old); }
      }
      for (const [ac, old] of matched) {
        if (old.verify !== 'unclassified') ac.verify = old.verify;
      }
    }

    const card = {
      id,
      kind: 'fr',
      issue: row.issue,
      title: row.title,
      spec: `docs/fr/${basename(row.specFile)}`,
      column: prev?.column ?? 'admitted',
      blocked: prev?.blocked ?? null,
      priority: prev?.priority ?? null,
      acs,
      phases,
      // null = the spec could not be read, which says nothing either way.
      docs_criterion: text ? hasDocsCriterion(text) : null,
      ledger_status: row.ledgerStatus,
      issue_updated_at: issue.updatedAt,
      labels: issue.labels.map((l) => l.name),
      run: prev?.run ?? freshRun(),
      created_at: prev?.created_at ?? new Date().toISOString(),
    };

    // Adoption (Q8): an OPEN PR whose branch names this FR is adoptable — its diff is
    // reviewable and its intent is stated. A bare branch is NEVER adopted; that is the
    // #1144 shape (a merged, field-verified fix silently reverted, green CI, no conflict).
    //
    // ⚠️ An adoption is re-checked on EVERY scan. It used to be set once and never
    // cleared, so a PR that merged kept holding its card for ever — measured
    // 2026-09-24: three of seven "held by an open PR" cards cited MERGED PRs (#1556,
    // #1542, #1543). A merged PR is the end of that work, not a claim on the card.
    // Only the adoption-derived columns are unwound; a column a worker set on
    // purpose (`field`, say) is left where it is.
    const slug = `fr${row.fr}`;
    // The slug must not run on into ANOTHER digit: `fr6` must never claim
    // `fr65-ac2-tick`. This tested `/^fr\d/` against the remainder, which is never true
    // for a remainder like `5ac2tick` — so FR-6 adopted FR-65's PR (#1587).
    const ours = (p) => {
      const b = p.headRefName.toLowerCase().replace(/[^a-z0-9]/g, '');
      return b.startsWith(slug) && !/^\d/.test(b.slice(slug.length));
    };
    // Re-checked against BOTH conditions: still open, AND still this FR's. A stale
    // adoption can fail either one — #1556 merged (not open); #1587 is open but was
    // never FR-6's, so an openness-only check kept that false hold alive.
    const adopted = card.run.adopted_pr && prs.find((p) => p.number === card.run.adopted_pr);
    if (card.run.adopted_pr && (!adopted || !ours(adopted))) {
      card.run.notes.push(
        `PR #${card.run.adopted_pr} ${adopted ? 'belongs to another FR' : 'is no longer open'} — adoption cleared`,
      );
      card.run.adopted_pr = null;
      if (card.column === 'pr_open' || card.column === 'judgement') card.column = 'admitted';
    }
    const match = prs.find(ours);
    if (match && !card.run.adopted_pr) {
      card.run.adopted_pr = match.number;
      card.run.branch = match.headRefName;
      if (card.column === 'admitted') card.column = match.isDraft ? 'judgement' : 'pr_open';
      card.run.notes.push(
        `adoptable open PR #${match.number} (${match.headRefName})${match.isDraft ? ' — DRAFT, needs your call' : ''}`,
      );
    }

    // A worker parks its card at `pr_open` with its PR in `run.pr` and `started_at` still
    // set, and the reviewer merges later, when no worker is left to update the card. That
    // was the one-way door again, on the worker side: on 2026-09-25 five cards (FR-22, 27,
    // 45, 61, 79) sat in "PR open" citing MERGED PRs. `started_at` also exempts a card from
    // `place()`, so they could never re-derive. Once the worker's PR is merged or closed,
    // the run is over: clear the claim and let the column derive like any other card's.
    // ⚠️ `run.pr` is not always a number. FR-45's worker recorded the full URL.
    const workerPr = Number(String(card.run.pr ?? '').match(/(\d+)\s*$/)?.[1] || 0);
    if (workerPr && card.run.started_at) {
      let state = null;
      try {
        state = gh(['pr', 'view', String(workerPr), '--repo', 'jk-zhang-meta/MeshHarbor', '--json', 'state', '-q', '.state']).trim();
      } catch { /* unreadable: leave the claim alone rather than guess */ }
      if (state === 'MERGED' || state === 'CLOSED') {
        card.run.notes.push(`worker PR #${workerPr} ${state.toLowerCase()}: run ended, column re-derived`);
        card.run.started_at = null;
        if (card.column === 'pr_open' || card.column === 'in_progress') card.column = 'admitted';
      }
    }

    // Trace, never take over. A card with work in flight is reported and left alone.
    // ⚠️ Both directions. This only ever moved a card IN, so "In progress" was a one-way
    // door: when the traced work ended (its PR merged, its branch went stale), the card
    // stayed. On 2026-09-24, 24 of 39 cards sat there with no live work and no worker of
    // ours behind them, which is 24 cards an operator reading the board takes to be busy.
    // A card a worker of ours STARTED (`started_at`) is left alone: its column is that
    // worker's to set when it parks.
    const live = traceInFlight(card, row.fr, branches, worktrees, specEditors(prs, row.fr));
    if (live && card.column === 'admitted') {
      card.column = 'in_progress';
    } else if (!live && card.column === 'in_progress' && !card.run.started_at) {
      card.column = 'admitted';
    }

    saveCard(card);
    prev ? updated++ : created++;
  }

  console.log(`scan: ${created} created, ${updated} updated, ${skipped} ledger rows whose issue is closed`);

  // Two silent-drop classes, both reported loudly. A queue that quietly omits a row is
  // indistinguishable from one that has nothing to do — the same shape as a `cargo test`
  // filter matching no test.
  for (const u of unclaimed) {
    console.warn(`  ⚠️  FR-${u.fr} has no issue (${u.issueCell || 'empty'}) — ${u.specFile}`);
    console.warn('      A number claimed with nothing published behind it. Check master for a collision.');
  }
  // (There was a "two criteria share an id" warning here. It only ever fired on FR-70, and
  // the duplicate was this parser's own positional fallback colliding with the spec's real
  // AC7 — the document was correct throughout. Ids are now disambiguated at parse time, so
  // the check had nothing left to catch and every firing of it had been a false accusation.)
  // A card whose issue has been CLOSED must leave the board. Skipping the ledger row is not
  // enough — the card file already exists, so the board would keep rendering a finished FR
  // for ever, and "44 cards" would quietly stop meaning "44 things to do". Archived rather
  // than deleted: the run state is the only record of how the card was worked.
  const open = new Set(issues.map((i) => i.number));
  const archiveDir = join(DOCS, 'kanban', 'archive');
  for (const card of allCards()) {
    if (open.has(card.issue)) continue;
    mkdirSync(archiveDir, { recursive: true });
    card.column = 'closed';
    card.closed_at = new Date().toISOString();
    writeFileSync(join(archiveDir, `${card.id}.json`), JSON.stringify(card, null, 2) + '\n', 'utf8');
    rmSync(cardPath(card.id));
    console.log(`  ✓ ${card.id} (#${card.issue}) closed — card archived`);
  }

  // AFTER archiving, so a card closed in this very pass counts as closed here too.
  reapWorktrees(open);

  const carded = new Set(ledger.filter((r) => byNumber.has(r.issue)).map((r) => r.issue));
  for (const i of issues) {
    if (/^FR-\d+/.test(i.title) && !carded.has(i.number)) {
      console.warn(`  ⚠️  open FR issue #${i.number} has no ledger row — ${i.title.slice(0, 70)}`);
      console.warn('      The row IS the claim; a spec file alone is not. Nothing will work this issue.');
    }
  }
}

// ---------------------------------------------------------------- rank + render

// Closest-to-done first (Q15): the shortest path to a shorter backlog is finishing what is
// nearly finished. `priority` is the operator override and always wins.
function rank(cards) {
  return [...cards].sort((a, b) => {
    if ((b.priority ?? 0) !== (a.priority ?? 0)) return (b.priority ?? 0) - (a.priority ?? 0);
    const fa = fraction(a), fb = fraction(b);
    if (fb !== fa) return fb - fa;
    return remaining(a).length - remaining(b).length;
  });
}
const fraction = (c) => (c.acs.length ? c.acs.filter((a) => a.done).length / c.acs.length : 0);
const remaining = (c) => c.acs.filter((a) => !a.done);
const operatorOnly = (c) => remaining(c).filter((a) => a.verify === 'operator');
// A spec with no docs criterion owes one: closing the FR binds it to docs-before-close,
// and the verification-debt guard then fails master. Writing the doc and adding the
// criterion (marked as added retroactively) is agent work, so it counts here even though
// no checkbox exists yet.
const docsOwed = (c) => c.docs_criterion === false;
const DOCS_OWED = {
  id: 'DOCS',
  text: 'no docs criterion: closing would fail the FR verification-debt guard. Write the doc, add the criterion marked as added retroactively',
  done: false,
  verify: 'agent',
};
const agentLeft = (c) => [
  ...remaining(c).filter((a) => a.verify !== 'operator'),
  ...(docsOwed(c) ? [DOCS_OWED] : []),
];

function bar(f) {
  const n = Math.round(f * 10);
  return '█'.repeat(n) + '░'.repeat(10 - n);
}

function board() {
  const cards = allCards();
  if (!cards.length) { console.error('no cards — run `scan` first'); process.exit(1); }
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const L = [];

  L.push('# MeshHarbor autopilot board');
  L.push('');
  L.push(`_Generated ${stamp} by \`.claude/skills/autopilot\`. **Do not hand-edit** — every`);
  L.push('field comes from `kanban/state/*.json`, the FR specs and the GitHub issues, and a');
  L.push('hand edit is silently overwritten on the next run._');
  L.push('');

  // The payoff of Q10: one place that answers "what is waiting on ME?" across the backlog.
  const waiting = rank(cards.filter((c) => operatorOnly(c).length > 0 && agentLeft(c).length === 0));
  const draftCall = cards.filter((c) => c.column === 'judgement');
  L.push('## ⏳ Waiting on you');
  L.push('');
  if (!waiting.length && !draftCall.length) {
    L.push('_Nothing. Every open criterion is one an agent can reach._');
  } else {
    L.push('| card | issue | what only you can settle |');
    L.push('|---|---|---|');
    for (const c of waiting) {
      const items = operatorOnly(c).map((a) => `${a.id}: ${a.text}`).join('; ');
      L.push(`| **${c.id}** | [#${c.issue}](https://github.com/jk-zhang-meta/MeshHarbor/issues/${c.issue}) | ${trunc(items, 220)} |`);
    }
    for (const c of draftCall) {
      const why = c.run.notes.slice(-1)[0] || 'sorted here at admission';
      L.push(`| **${c.id}** | [#${c.issue}](https://github.com/jk-zhang-meta/MeshHarbor/issues/${c.issue}) | ${trunc(why, 220)} |`);
    }
  }
  L.push('');

  L.push('## Summary');
  L.push('');
  L.push('| column | cards |');
  L.push('|---|---|');
  for (const [id, label] of COLUMNS) {
    L.push(`| ${label} | ${cards.filter((c) => c.column === id).length} |`);
  }
  const unclassified = cards.reduce((n, c) => n + c.acs.filter((a) => a.verify === 'unclassified' && !a.done).length, 0);
  L.push(`| **total** | **${cards.length}** |`);
  L.push('');
  if (unclassified) {
    L.push(`> ⚠️ ${unclassified} open acceptance criteria are still \`unclassified\` — until a card's`);
    L.push('> criteria are split into agent-verifiable and operator-only, "Waiting on you" undercounts.');
    L.push('');
  }

  for (const [id, label] of COLUMNS) {
    const col = rank(cards.filter((c) => c.column === id));
    L.push(`## ${label} (${col.length})`);
    L.push('');
    if (!col.length) { L.push('_empty_'); L.push(''); continue; }
    L.push('| card | ACs | progress | phase / next | blocked |');
    L.push('|---|---|---|---|---|');
    for (const c of col) {
      const done = c.acs.filter((a) => a.done).length;
      const half = c.acs.filter((a) => !a.done && a.mark === '~').length;
      const op = operatorOnly(c).length;
      const title = `**[${c.id}](https://github.com/jk-zhang-meta/MeshHarbor/issues/${c.issue})** ${trunc(c.title, 60)}`;
      const marks = [half ? `${half} ◐` : '', op ? `${op} 👤` : '', docsOwed(c) ? '📘' : ''].filter(Boolean);
      const acCell = `${done}/${c.acs.length}${marks.length ? ` (${marks.join(', ')})` : ''}`;
      const next = c.run.hands_off ? `🔒 ${c.run.hands_off_reason}`
        : (c.run.last_action || nextPhase(c) || '—');
      L.push(`| ${title} | ${acCell} | \`${bar(fraction(c))}\` | ${trunc(next, 70)} | ${c.blocked ? '🚧 ' + trunc(c.blocked, 60) : ''} |`);
    }
    L.push('');
  }

  L.push('---');
  L.push('');
  L.push('**Legend** — `👤` an open criterion only the operator can settle · `◐` one the spec');
  L.push('marks half met (`- [~]`), counted as open until it reads `[x]` · `📘` the spec has no');
  L.push('docs criterion, so closing it would fail the verification-debt guard · `🚧` blocked ·');
  L.push('`🔒` work already in flight — **traced, never picked up**. A branch counts as live for');
  L.push(`${FRESH_DAYS} days after its last commit (\`--fresh-days\`); clear a card by hand if its`);
  L.push('branch is actually dead. ·');
  L.push('progress is ticked acceptance criteria, which is the spec\'s own measure, not a guess.');
  L.push('');
  L.push('An agent never closes an issue and never merges a PR. A card reaching **Ready to close**');
  L.push('means every agent-verifiable criterion is ticked *with linked field evidence* — CI green');
  L.push('is never evidence. The close is yours.');
  L.push('');

  mkdirSync(join(DOCS, 'kanban'), { recursive: true });
  writeFileSync(join(DOCS, 'kanban', 'BOARD.md'), L.join('\n'), 'utf8');
  console.log(`board: ${cards.length} cards -> ${join(DOCS, 'kanban', 'BOARD.md')}`);
}

// A phase with nothing left to BUILD, whether it shipped or was dropped. The acceptance
// criteria still carry the field work, so "implemented — field pending" is settled here.
// A P0 whose status is "this doc" / "this spec" is the spec itself, so it is settled too.
const SETTLED = /\b(?:shipped|closed|done|built|verified|completed?|implemented|merged|proven|resolved|retired|superseded)\b|\bnot planned\b|✅|^this\b/i;
// A NEGATED keyword says the opposite. FR-74's P5 reads "decided 2026-09-10, not built",
// and the bare keyword test settled it, hiding the one phase on that card still to build.
// Strip the negated phrase before testing. "not planned" is not in this list, so it
// still settles the phase: nothing left to build.
const NEGATED = /\b(?:not|never)\s+(?:yet\s+)?(?:shipped|closed|done|built|verified|completed?|implemented|merged|proven|resolved)\b/gi;
const settled = (status) => SETTLED.test((status || '').replace(NEGATED, ''));

function nextPhase(c) {
  // An unknown status (no status column) is never offered as the next step.
  const open = c.phases.find((p) => p.status !== null && !settled(p.status));
  return open ? `${open.id} — ${open.what}` : null;
}
const trunc = (s, n) => {
  s = (s || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
};

function next() {
  const n = Number(flag('n', '3'));
  // hands_off cards are somebody else's work in flight — traced, never dispatched. A BLOCKED
  // card, or one whose open criteria are all operator-only, gives an agent nothing to do. This
  // used to offer both anyway: FR-6, blocked on the operator's `cgu=1` decision, was the
  // second card `next` named on 2026-09-24.
  const pool = allCards().filter((c) => !c.run.hands_off && !c.blocked && agentLeft(c).length > 0
    && ['admitted', 'field'].includes(c.column));
  for (const c of rank(pool).slice(0, n)) {
    const left = agentLeft(c);
    console.log(`${c.id}  #${c.issue}  ${c.acs.filter(a=>a.done).length}/${c.acs.length} ACs  [${c.column}]  ${c.title}`);
    console.log(`    agent-reachable open criteria: ${left.length}${left.length ? ' — ' + left[0].id + ': ' + trunc(left[0].text, 90) : ''}`);
  }
}

// ---------------------------------------------------------------- classify

// Apply `{"FR-71": {"AC2": "agent"}}` maps onto the cards. Judgement comes from a reader
// (a human or a classifier agent); this only records it, and refuses anything that is not
// one of the two labels — an unknown value would read as "not yet judged" downstream and
// silently shrink the "Waiting on you" list.
function classify() {
  const dir = flag('from', null);
  if (!dir) { console.error('classify: --from <dir with classify-*.json> is required'); process.exit(2); }
  const files = readdirSync(dir).filter((f) => /^classify-.*\.json$/.test(f));
  if (!files.length) { console.error(`classify: no classify-*.json in ${dir}`); process.exit(1); }

  const merged = {};
  for (const f of files) {
    const obj = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    for (const [fr, acs] of Object.entries(obj)) {
      merged[fr] = { ...(merged[fr] || {}), ...acs };
    }
  }

  let applied = 0, unknownCard = [], unknownAc = [], badLabel = [];
  for (const [fr, acs] of Object.entries(merged)) {
    const card = loadCard(fr);
    if (!card) { unknownCard.push(fr); continue; }
    for (const [acId, label] of Object.entries(acs)) {
      if (label !== 'agent' && label !== 'operator') { badLabel.push(`${fr}/${acId}=${label}`); continue; }
      // EVERY match, not the first: a spec can label two criteria with the same id
      // (FR-70 has two `AC7`), and a `find` would leave the second silently unjudged —
      // which reads downstream as "not yet classified" forever.
      const hits = card.acs.filter((a) => a.id === acId);
      if (!hits.length) { unknownAc.push(`${fr}/${acId}`); continue; }
      for (const ac of hits) { ac.verify = label; applied++; }
    }
    saveCard(card);
  }

  console.log(`classify: ${applied} criteria labelled from ${files.length} file(s)`);
  if (unknownCard.length) console.warn(`  ⚠️  no such card: ${unknownCard.join(' ')}`);
  if (unknownAc.length) console.warn(`  ⚠️  no such criterion: ${unknownAc.join(' ')}`);
  if (badLabel.length) console.warn(`  ⚠️  not a label: ${badLabel.join(' ')}`);

  const left = allCards().reduce((n, c) => n + c.acs.filter((a) => a.verify === 'unclassified' && !a.done).length, 0);
  console.log(`  ${left} open criteria still unclassified`);
  place();
}

// A card whose remaining criteria are ALL operator-only has no agent work left in it —
// that is `ready`, and saying so is the point of the board. Derived, never sticky: it
// re-derives on every scan, and a card a worker has claimed is left alone.
// ⚠️ …unless it owes the docs criterion. "Every box ticked" is not closable when no box
// for the docs exists. The close would turn master's verification-debt guard red, as
// FR-22's did on 2026-09-25. So such a card is agent work, not the operator's to close.
function place() {
  let moved = 0;
  for (const card of allCards()) {
    if (card.run.started_at || card.run.hands_off || card.column === 'judgement') continue;
    const rem = remaining(card);
    const closable = rem.every((a) => a.verify === 'operator') && !docsOwed(card);
    const should = closable ? 'ready'
      : card.column === 'ready' ? 'admitted'
      : card.column;
    if (should !== card.column) { card.column = should; saveCard(card); moved++; }
  }
  if (moved) console.log(`  ${moved} card(s) re-placed by column derivation`);
}

switch (cmd) {
  case 'scan': scan(); place(); break;
  case 'board': board(); break;
  case 'next': next(); break;
  case 'classify': classify(); break;
  default:
    console.error('usage: autopilot.mjs <scan|board|next|classify --from <dir>> [--repo <p>] [--docs <p>] [--n N]');
    process.exit(2);
}
