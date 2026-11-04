---
name: sanitize-hostnames
description: Rewrite real machine names (corp asset tags, Windows default hostnames, personal computer names) to the product display names, across the working tree, the whole git history, and the GitHub issues/PRs/comments/releases. Use before publishing docs, after field notes land, or when a review turns up a real hostname in the repo.
---

# Sanitising machine names

Field notes are written in the heat of debugging, and a debugging session
writes down the name of the machine it is debugging. That name is a corp asset
tag, or a Windows default hostname, or someone's computer named after them.
On a **public** repo those are reconnaissance value: they map the fleet and say
which host runs what.

This skill rewrites them to the display names the product itself shows, so the
narratives stay readable — "the corp laptop over the VPN" is still a useful
sentence — while the tags themselves are gone.

## The map lives OUTSIDE the repo

`C:\dev\gjovanov\sanitize-map.txt`

That path is deliberate and non-negotiable: the map is the one place a real
name and its replacement sit **side by side**, so committing it would publish
exactly what the sweep exists to remove. Never commit it, never quote it in a
commit message, never paste it into an issue or a PR.

**Every file in this directory is written tag-free on purpose, prose included.**
A sweep walks the repo and does not exempt its own tooling. The first version of
this document named real tags in its explanations and the sweep rewrote them
into nonsense; the second time round the Python docstrings did it, and a history
rewrite turned *"a three-letter shorthand like `<tag>`"* into a sentence naming
an alias, and *"`<old-alias>` → `<new-alias>`"* into `X → X`.

So: describe the RULES, never the instances. Check this directory against the
map after any sweep —

```bash
python3 .claude/skills/sanitize-hostnames/sanitize.py \
    --map <map> --root .claude/skills/sanitize-hostnames --check   # want 0 / none
```

⚠️ Note what survived both times: the regexes. `\bCLK…` has no word boundary
before the letters (the preceding `b` of `\b` is a word character), so patterns
are accidentally immune while the comments beside them are not. The tool keeps
working and only its explanation rots — which is the failure mode that lasts,
because nothing fails.

### Map format

```
real-name = replacement      # one pair per line, '#' starts a comment
!keep goran                  # a spelling that must survive verbatim
```

Matching is **case-sensitive, whole-word, literal** — so list every casing that
actually occurs. `!keep` declares a spelling that must never be rewritten *and*
must never be reported as residue; it is matched case-sensitively, because its
whole reason to exist is a token whose uppercase form is a hostname and whose
lowercase form is a profile directory and an email local part.

## Running it

```bash
R=/mnt/c/dev/jk-zhang-meta/MeshHarbor; M=/mnt/c/dev/gjovanov/sanitize-map.txt
S=$R/.claude/skills/sanitize-hostnames

# 1. working tree
python3 $S/sanitize.py --map $M --root $R --apply     # or --check for CI

# 2. GitHub: issue + PR titles/bodies, comments, release notes
python3 $S/sanitize_github.py --map $M --apply        # or --check

# 2b. GitHub by SHAPE, which step 2 cannot do. sanitize_github.py is
#     map-driven, so it finds only names somebody already listed; nothing
#     otherwise scans PUBLISHED content for the *class*. Dump the bodies and
#     point check_shapes.py at them. (2026-09-06: 60k lines of issues, PRs,
#     comments and releases — clean.)
O=$(mktemp -d)
gh api --paginate '/repos/<owner>/<repo>/issues?state=all&per_page=100' \
  -q '.[] | "=== #\(.number) \(.title)\n\(.body // "")"'      > $O/issues.txt
gh api --paginate '/repos/<owner>/<repo>/issues/comments?per_page=100' \
  -q '.[] | "=== \(.id)\n\(.body // "")"'                     > $O/comments.txt
gh api --paginate '/repos/<owner>/<repo>/releases?per_page=100' \
  -q '.[] | "=== \(.tag_name)\n\(.body // "")"'               > $O/releases.txt
python3 $S/check_shapes.py --root $O; rm -rf $O

# 3. whole git history — see the warnings below before running this
python3 $S/sanitize.py --map $M --gen-filter-repo ~/sanitize/replace.txt
python3 $S/sanitize.py --map $M --gen-filename-callback ~/sanitize/filename-callback.py
git clone --mirror https://github.com/<owner>/<repo>.git ~/sanitize/repo.git
cd ~/sanitize/repo.git
git config --unset remote.origin.mirror    # from here a bare `git push` would MIRROR
git for-each-ref --format='%(objectname) %(refname)' > ../pre-refs.txt   # the leases
git for-each-ref --format="delete %(refname)" refs/pull | git update-ref --stdin
python3 ~/bin/git-filter-repo --sdr --no-fetch \
    --replace-text      ~/sanitize/replace.txt \
    --replace-message   ~/sanitize/replace.txt \
    --filename-callback ~/sanitize/filename-callback.py \
    --replace-refs delete-no-add --force
# then push each CHANGED head and tag with its own lease -- see "Pushing a rewrite"
```

### When step 2b reports a canary

Writing this guard up publishes its canaries: the write-up quotes the guard's own
output, and step 2b then scans that write-up. The hit is real, benign, and
recurs on every run — which is how a check earns the noise that gets it deleted.

**Do not silence it by allowlisting a value that is still in `CAUGHT`.** That
makes the canary vacuous, which is the one failure this whole directory exists
to prevent, and `selftest.sh` refuses it immediately (`MISSED:`, both casings).

Rotate instead, and move the retired value into **both** `ALLOW` and `IGNORED` —
the allowlist entry is the exemption, the `IGNORED` entry is what asserts the
exemption still works. Either alone rots: an entry with no assertion is an
unguarded hole, an assertion with no entry fails the selftest. Confirm-RED both
halves (break the entry ⇒ `FALSE POSITIVE`; plant the fresh value ⇒ it is named).

⚠️ Rotation costs one canary value per write-up, so it does not scale. If it
happens a second time, filter the dump at this boundary instead — the noise is
in published content, and paying for it out of a shared allowlist buys read-quiet
with a hole in the repo scan and CI too.

## Three layers, and only the first one is cheap

| layer | stops it at | enable |
|---|---|---|
| `.githooks/pre-commit` | the commit | `git config core.hooksPath .githooks` |
| CI job **No real machine names** | the merge | required status check on `master` |
| the sweep below | after publication | run it by hand |

Layer 3 has run four times now. Each run force-pushes ~1000 branches and ~700
tags with GitHub Actions disabled around it, and it still **cannot remove
anything from GitHub** — the pre-rewrite commits stay reachable by SHA through
`refs/pull/*` until GitHub Support runs GC. Treat every sweep as damage
control, and the hook as the actual fix.

⚠️ Measured on the fourth run (2026-10-21): what `refs/pull/*` keeps is the
unsanitised history of **every** earlier run, not just the latest. 66 of the
map's 76 keys were still in the object database, all reachable only through
pull refs, across 2358 pull requests. A rewrite that nobody follows up with a
Support GC has cleaned what people *browse*, and nothing that a fetch by SHA
can reach.

⚠️ **Set `core.hooksPath` in every clone.** It is per-clone config, so a fresh
clone has no hook until someone runs that line. Worktrees **share** that config
and the hook is tracked, so setting it once in the clone covers every worktree
made from it — but a worktree on a branch predating the hook still has no file,
which is the harmless `tool absent -- do not block` path.

## The other kind of name: WHO, not WHICH MACHINE

Everything above is about **content** — a hostname inside a file or a commit
message. A second surface leaks a name without touching content at all, and
this skill's guards are structurally blind to it:

| surface | what leaks | guarded by |
|---|---|---|
| a blob or a commit message | which machine | `check_shapes.py` + the sweep |
| a commit's author / committer | **who**, as an email address | `.githooks/check-identity.sh` |
| a GitHub issue, comment, review, release | **who**, as an account login | `.claude/hooks/gh-account-guard.sh` |

Rows 2 and 3 arrived on 2026-09-05, after an audit found a second GitHub
account — a corp one, whose *login alone* named an employer — had authored one
issue and three comments on this public repo, across three days spanning
eleven. It had authored no commits, and that was luck: nothing checked. In the
same history sat 520 commits carrying a corp mailbox as their author address.

Three things are worth carrying over from that:

- **A commit identity is metadata**, so it is in no blob and no message. The
  shape scan walks straight past it, and always would have.
- **`gh auth switch` is global.** It rewrites the active account in a shared
  config, for every process and every concurrent session. A second account
  signed in for unrelated work is one command away from authoring things, and
  `gh issue comment` prints a URL rather than an identity — so the mistake is
  invisible from inside the session making it. `scripts/gh-scoped-config.sh`
  builds a config directory the other account is not *in*, which is the
  difference between a rule that is checked and one that cannot be broken.
- **An ALLOWLIST, not a denylist**, and for the same reason the shape guard is
  shape-based: a denylist would have to write the unwanted addresses into a
  public file, publishing exactly what it exists to remove — and it only ever
  finds the mistakes someone already thought of. A denylist finds the
  identities you know about; an allowlist finds the class.

⚠️ **Neither is recoverable downstream**, which is why both are cheap only
here. A commit identity cannot be edited, only rewritten — renumbering every
SHA above it, and still leaving the old objects reachable through
`refs/pull/*`. An issue or comment author cannot be changed at all: the only
remedy is delete-and-recreate, which loses the thread and dangles every
reference to its number, including any already baked into a merged commit
subject.

⚠️ **One hole no local layer can close**: a merge made through the GitHub web
UI is committed *on GitHub*, from the email set on the **account**, after every
hook and PR check has already passed. Two things follow, and the second is the
one people get wrong:

1. **The fix is the account setting**, not a guard — GitHub Settings → Emails.
   Keep the address off the account, or turn on *Keep my email address private*
   so commits use the `users.noreply.github.com` form.
2. **A repository ruleset cannot help here.** `commit_author_email_pattern`
   would block it, but the whole metadata-rule family is organisation-and-paid-
   plan only: on this user-owned public repo the API refuses every one of
   `commit_author_email_pattern`, `committer_email_pattern`,
   `commit_message_pattern` and `branch_name_pattern` with HTTP 422 (measured
   2026-09-06, in `active` enforcement — `evaluate` is separately Enterprise-
   only). Do not plan around it.

What actually covers it is the **CI job's push-to-master run**: `on: push`
scans `github.event.before..github.sha`, so a merge commit with a foreign
identity turns master red within a minute. That is detection, not prevention —
the commit exists by then — but it is the difference between finding out in a
minute and finding out in an audit eleven days later, which is how this whole
entry started.

⚠️ Its fallback matters and was exercised on day one: after a force-push,
`github.event.before` names a commit that no longer exists, so the job falls
back to `<sha>~1..<sha>` rather than erroring or, worse, scanning nothing.

### The hook's exit-code contract — the hard-won part

`.githooks/pre-commit` blocks on **`EXIT_FOUND` (1) and nothing else**. Every
other status means *the guard did not answer*, and the hook says so and lets the
commit through, because the required CI check still refuses the merge.

| status | meaning | hook |
|---|---|---|
| `0` | clean | commit |
| `1` | names found | **REFUSE** |
| `2` | bad arguments — hook and guard drifted | warn, allow |
| `20` | guard raised, or a git call inside it failed | warn, allow |

⚠️ **This existed as one status until 2026-09-04, and it was worse than useless.**
`if ! out=$(run_guard)` collapsed every failure into "a real machine name",
so the hook told authors they had committed a hostname when it had merely
crashed. Measured twice that day, from two unrelated causes:

- a worktree whose `check_shapes.py` predated `--staged`, so argparse exited 2;
- **every** worktree on Windows, where `.git` is a file holding a Windows path
  WSL's git cannot follow — so `git` inside the WSL fallback exited 128 and the
  guard was inert in ~53 worktrees while working fine in the main clone. The
  hook now resolves the git dir natively and exports it across the boundary.

🔑 The rule this is an instance of, already written three times in this
directory: **a check whose result cannot distinguish "passed" from "never
answered" is not a check.** A guard that cries hostname when it means "I
crashed" is one somebody silences with `--no-verify`, and that removes the layer
permanently. `selftest.sh` asserts each status leads to its own outcome, and
asserts a **non-1** status specifically — "non-zero" would pass on the bug.

⚠️ The hook must be committed **mode 755**. Git skips a non-executable hook in
silence, which is layer 1 disarmed with nothing anywhere to say so; the selftest
checks this too.

## The seven things that go wrong

**0. The `--replace-text` rules file has NO COMMENT SYNTAX.** `get_replace_text()`
treats **every** line as a literal to match, and when a line carries no `==>`
the replacement defaults to `***REMOVED***`. So a line containing just `#` means
*replace every `#` in every blob*. Measured 2026-09-06 on a rules file whose
first four lines were ordinary explanation: **548,700 blob lines rewritten**,
`CLAUDE.md` stripped of all 53 of its headings, `.gitattributes` turned into
`***REMOVED***!/bin/sh`. The only tell during the run is a burst of
`is not a valid attribute name: .gitattributes:N` warnings, buried in the
progress spam.

Keep the `.txt` pure rules; put prose in a sibling file. Assert it before
running:

```bash
grep -c ''  replace.txt        # every line is a rule -- is that how many you meant?
grep -vc '==>' replace.txt     # want 0: a line without ==> uses the REMOVED default
```

⚠️ The `--mailmap` file is a *different* format (git's own) and **does** support
`#` comments. The two files sharing a directory and not a syntax is exactly the
trap.

**0b. A verification must not contaminate what it verifies.** To diff the
pre- and post-rewrite trees it is tempting to fetch the old master into the
rewritten mirror. That works, and it also re-imports every pre-rewrite commit:
`git log --all` then reports the addresses as still present, and — far worse —
`git push --mirror` would have **published `refs/orig/master`**, re-uploading in
one step the exact history the rewrite existed to remove. Do the comparison in a
third, throwaway repo, and assert before pushing that the mirror holds nothing
outside `refs/heads/*` and `refs/tags/*`.

**1. `--replace-text` does NOT touch commit messages.** It rewrites blob
contents only; commit and annotated-tag messages are a separate surface behind
`--replace-message`, and filter-repo says nothing at all when you omit it. The
first run of this sweep reported success, left every blob clean, and left 745
real names in the commit log — which on this repo is the *richer* of the two
surfaces, because the field-test narratives live in commit bodies. Always
verify against `git log --all --format=%B`, never the tree alone.

**2. `residual: none` is the only success condition, and CASE IS THE TRAP.**
The residual scan re-reads everything case-INSENSITIVELY. The first pass of the
2026-08-28 sweep listed only uppercase spellings, reported success, and left 60
real tags in the tree because half the prose was lowercase.

⚠️ That exact mistake was then **rebuilt one file over**: `check_shapes.py`
shipped with uppercase-only patterns, and on 2026-09-04 a field log wrote two
asset tags in lowercase — the guard printed `none found`, CI went green, and
the names reached a public repo and 15 GitHub items. Everything here matches
case-insensitively now, and `selftest.sh` carries every canary in both casings
so the regression cannot come back quietly. People write a hostname however it
came out of their terminal; a check that assumes a casing is not a check.

**3. Longest key first, or you orphan a prefix.** A `DESKTOP-`/`LAPTOP-`
qualified form has to be rewritten before its bare tag, or the qualifier is
left stranded on an already-rewritten name. `load_map` sorts by key length and
every consumer iterates that one list, so the rule cannot be applied in one
place and forgotten in another.

**4. Whole-word matching is what makes short keys safe** — and it has to be
*verified*, not assumed. Before mapping a 3-letter shorthand, dump every blob
in history and read the contexts:

```bash
git cat-file --batch-all-objects --batch-check='%(objecttype) %(objectname)' \
  | awk '$1=="blob"{print $2}' | git cat-file --batch \
  | grep -aoE '.{0,45}\b<KEY>\b.{0,35}' | sort -u
```

If any hit is a code identifier rather than prose, the key is not safe to map.

**5. `_` is part of a word, and a path is not content.** Two blind spots,
shared by every layer until 2026-10-21, when one corp laptop's name was found
in this repo's history in exactly these two forms after two whole-history
rewrites had "removed" it:

- **A tag glued to an identifier.** `\b` counts `_` as a word character, so
  `fn <tag>_layout()` has no boundary after the tag, and neither the shapes nor
  the map rules could see it. A key carrying a DIGIT (a generated tag) now
  ends at `_` as well, and rewrites to the identifier-safe form (`-` → `_`),
  so the rewritten history still compiles. A digit-free key keeps `\b` on
  purpose: rule 4 measured those as safe only under `\b`, and a three-letter
  key glued to `_` is ordinary code.
- **A tag in a file name.** Content scanning never reads a path, and
  `--replace-text` never rewrites one. The guard now scans every tracked path,
  binaries included (a screenshot named after a machine is the commonest
  case); the sweep's residual scan reports one; and a history rewrite needs
  `--filename-callback`, generated by `--gen-filename-callback`.

`selftest.sh` locks both, for the guard and the sweep alike. Its glued and path
canaries assert the exact `<file>:<line-or-name>  <token>` report line, because
the bare token is already in the output from the standalone plants, and a
grep for it alone would pass on the bug.

## Before rewriting history, know what it does and does not achieve

- **It does not remove anything from GitHub.** Old commits stay reachable by
  SHA through the `refs/pull/*` refs, effectively forever, unless GitHub
  Support runs GC on the repo. Drop those refs locally before filtering (you
  cannot push to them anyway) and treat the rewrite as cleaning what people
  *read*, not what a determined fetch can still reach.
- **Every SHA changes.** Clones elsewhere must re-clone or hard-reset; SHAs
  quoted in docs, issues and release notes dangle.
- **Back up first**: `git bundle create <path>.bundle --all` captures every ref
  in one file and restores with a plain `git clone`.
- Branches that exist only locally are not in a mirror clone and so are not
  rewritten. They keep the old content until deleted or rebuilt.

### Pushing a rewrite (the procedure the fourth run used)

That run froze pushes for 8 minutes: 5063 commits filtered in 2m15s, and 1730
refs pushed in ~2 min with 0 rejections. What made it short and safe:

- **Drop `refs/pull/*` BEFORE filtering.** Pull refs reach the old history of
  every PR. Keeping them tripled the commits and projected ~27 min, all of it
  spent on refs that cannot be pushed anyway. Record them first
  (`pre-refs.txt`): GitHub Support asks how many pull requests are affected.
- **Rules only for keys that occur.** A key that appears nowhere is a no-op
  rule that costs one regex pass over every blob. A case-insensitive
  *substring* search of the object database can only over-select, so cutting
  the map to those keys is safe. The run cut 76 keys to 11. Then verify
  against the **full** map afterwards.
- **`--sdr --no-fetch`.** With `remote.origin.mirror` unset, `--sdr` fetches
  `+refs/*:refs/*`, which brings every pull ref straight back.
- **Verify before pushing.** Check every key under both boundaries, and every
  shape, in blobs, commit messages, tag messages and paths. Ref counts, the
  commit count and the set of identities must be unchanged, and master's tree
  must be **identical**. Every tip tree that changed must differ only in paths
  that held a name.
- **Push each CHANGED ref with its own lease:**
  `git push --porcelain origin --force-with-lease=<ref>:<pre-rewrite-sha> <new>:<ref>`,
  in batches of ~100. A ref someone moved after the clone is *rejected and
  listed*, never clobbered. That replaces both `--mirror` (it would try to
  delete `refs/pull/*`) and a freeze nobody can enforce. Announce a short
  freeze to every active session anyway.
- **Actions OFF around the push, with a trap that turns it back on.** ~700
  release tags would each fire a signed release build onto the fleet's
  updater. ⚠️ The permissions GET right after the disabling PUT still read
  `enabled: true`. The run count before and after is the actual proof.
- **Then a fresh clone of the remote**, scanned the same way. That checks the
  surface, not the source.
- ⚠️ **Open PRs come out without CI on their new heads.** A synchronize event
  that fires while Actions is off is simply dropped. One that lands after the
  re-enable names the pre-rewrite base: `ci.yml`'s identity job now falls back
  for that case, but other jobs may not. Close and immediately reopen each
  affected PR to get a fresh event against the new base, and tell its owner
  first, because two re-triggers start two run sets.

## Adding a name

Find the replacement, do not invent one. In order of authority: the
`agents.display_name` column in the product database; then the alias table
recorded in the earlier privacy commit (`git log --grep='role-based aliases'`),
which is where the existing generic host aliases come from; then, only if
neither has it, the next free slot in the series already in use.
