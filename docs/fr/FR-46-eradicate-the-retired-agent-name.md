# FR-46 — Eradicate `roomler-agent` as a live name

**Issue**: [#1051](https://github.com/gjovanov/roomler-ai/issues/1051) · **Status**: P0 (spec) · **Predecessor**: [FR-21](FR-21-retire-obsolete-binary-names.md) (#809, DONE)

## Goal

Remove `roomler-agent` / `roomler-agent-tray` / `roomler-tunnel` from every surface a
shipping code path **reads, writes or matches** — including the surfaces FR-21 deliberately
froze. Fleet re-enrollment is authorised (operator, 2026-08-31), which is what makes the
frozen list negotiable.

## This is not FR-21 reopened

FR-21 was scoped **migrate-or-anchor with no fleet disruption**, and it succeeded: 1 849 → 0
unclassified occurrences, 13/13 criteria field-verified, deployed. Its anchors are not
leftovers — each is a site where renaming *was* the defect under that constraint.

FR-46 changes exactly one input: **disruption is now permitted**. Everything else — the
classifier, the guard, the anchor inventory — is FR-21's output, reused.

## Root finding: the anchor set is two populations, not one

FR-21 marked every deliberate occurrence with one marker, because under its constraint they
all had the same consequence (delete it → strand a host). Under FR-46's constraint they split
cleanly, and the split is what makes this program measurable:

| class | what it is | can it ever reach zero? |
|---|---|---|
| **LIVE** | code that resolves, matches or writes the retired name at runtime — appdirs trees, service/task names, log prefixes, env arms, asset pickers | **yes** — this is the program |
| **RECORD** | prose and fixtures that name the retired thing *in order to explain it* — migration notes, field logs quoting real output, FR specs, tests whose input is by definition a historical artifact | **no, and must not** — renaming these falsifies the record |

⚠️ `RECORD` is not an escape hatch for work someone does not want to do. A migration note is
`RECORD`; the code the note describes is `LIVE`. The guard must make the distinction
falsifiable, or the classification becomes a way to launder `LIVE` sites into permanence.

**P1a therefore splits the marker** (`RETIRED-NAME-ANCHOR` stays live, `RETIRED-NAME-RECORD`
is new) and guards them differently: `live` ratchets **down** and must reach 0; `record` is
pinned **exactly**, so a site cannot be quietly reclassified to dodge the live ratchet.

⚠️ **An anchor's own explanation can be swept, and nothing catches it.** The historical-appendix
region in `docs/remote-control.md` read *"rewriting `roomlerd` to `roomlerd` here would falsify
the record"* — it landed correct in `f3cc9240` and was mangled by FR-21's own `--strict` sweep
(`21004d78`), which rewrote the retired name inside the sentence that exists to say the name
must not be rewritten. **The audit is structurally blind to this**: it counts occurrences of
retired names, so a name wrongly REPLACED by the current one simply reads as progress — the
count went down. (Restoring it here moved `anchors` 745 → 746, which is the same signal
arriving far too late to help.) Swept the tree for the shape — exactly one instance, fixed
here. The lesson is the sanitize skill's own: *the tool keeps working and only its
explanation rots, which is the failure mode that lasts, because nothing fails.*

⚠️⚠️ **And the audit had a blind spot of exactly the same shape, now closed.** A file was
selected for scanning only by `git grep -l "$TOKENS"`, so it dropped OUT the moment its **last**
retired name was migrated — taking any marker it still held with it. The marker was then
orphaned and *structurally unreportable*: covering nothing, widening no exemption today, and
silently ready to widen one if a retired name ever reappeared under it. **Seven accumulated
across six files in a single phase** before anyone noticed, and the audit could not have said
so. `scan()` now selects the UNION of token-bearing and marker-bearing files, which found three
more immediately. Mutation-checked: an orphan in a token-free file reads `stale markers: 1` with
the union and `0` without.

## Root finding: the published-asset freeze is much narrower than FR-21 recorded

FR-21's D6 froze anchors on "already-published asset filenames are immutable and the updater
matches on them". The first half is true; **the second half is true on exactly one path**, and
that path already dual-matches. Measured against master:

| picker | matches on | prefix load-bearing? |
|---|---|---|
| Windows `pick_asset_for_windows` | `.msi` + `-permachine-` infix | **no** |
| macOS `pick_asset_for_unix` | `.pkg` | **no** |
| Linux ≥ 0.4.16 `is_daemon_asset` | `starts_with("roomler-agent")` OR `starts_with("roomlerd")` | **already dual** |
| Linux ≤ 0.4.15 | first `.deb` matching arch | **no** (order-dependent; fixed server-side) |
| server `order_assets_daemon_first` | `starts_with("meshharbor-desktop-")` | **no** — a companion *denylist*, not a daemon allowlist |
| `scripts/install.sh` | `<arch>-unknown-linux-gnu\.<fmt>` — a SUFFIX | **no** (relies on the same server ordering) |
| wizard `asset_resolver.rs` | nothing — `filename` is a plain `String` | **no**; its anchors are doc comments and test fixtures only |

⇒ **New releases can publish `roomlerd-<v>-…` without freezing any host**, including the
dormant pre-0.4.15 rows. The frozen surface is only the *already-published* files, which stop
being matched the moment nothing in the fleet is old enough to need them.

⚠️ Two things must move in the same PR as the rename or a guard goes stale silently:
`release-agent.yml`'s post-publish ordering check (`case "$first" in ""|roomler-agent-*)`) and
`is_daemon_asset`'s legacy arm, which becomes deletable only when no host below 0.4.16 is
being updated.

⚠️ `artifact_version.rs`'s fixtures (`meshharbor-agent.deb` / `.pkg` / `.tgz`) are anchored as
"PUBLISHED release asset" names and are **not** — no published asset has that spelling (real
ones carry a version), and the binding reads the MSI's own `ProductVersion`, using the filename
only to dispatch on extension. That anchor's reason is overstated; the fixtures are free.

## Root finding: the env prefix is a FLEET MIGRATION, not a cheap deletion

`MESHHARBOR_AGENT_*` is the largest single live class (~38 anchors) and the handover filed it
under "cheap classes". It is not. `env::node_env` reads three prefixes — `MESHHARBORD_`,
`MESHHARBOR_NODE_`, `MESHHARBOR_AGENT_` — and the anchor on that chain claims real hosts still set the
retired spelling in **operator-authored systemd drop-ins that a package upgrade never
rewrites**.

**Field-measured 2026-08-31 rather than trusted**: all three cluster hosts carry exactly four
`MESHHARBOR_AGENT_VIRTUAL_DESKTOP*` entries in `/etc/systemd/system/meshharbord.service.d/`. The
claim is current, not stale.

⇒ **Ordering is load-bearing.** Delete the arm before rewriting the hosts and the daemon starts
fine and silently ignores four settings per node — no error, no log line, just a headless
cluster node that quietly stops offering a virtual desktop. The migration must be
make-before-break: rewrite every host that sets the retired spelling, confirm, *then* delete
the arm.

⚠️ A host is only discoverable this way if someone goes and looks. There is no inventory of
operator-authored drop-ins, so "every host that sets it" is a claim that has to be re-measured
across the whole fleet — not just the hosts that happen to be in a runbook — before the arm
comes out.
## The three one-way doors

### D1 — macOS bundle identity (the only genuine blocker)

`meshharbor-agent.app` / `CFBundleExecutable` / `fans.itachi.meshharbor.agent` key the **TCC grants** for
Screen Recording and Accessibility. Renaming voids both on every Mac, with **no remote fix**.

⚠️ This is re-**consent**, not re-enrollment: a human must approve at each Mac. The operator's
authorisation covers fleet disruption; it does not conjure a person in front of a MacBook.
Ships **last**, staged one host, with FR-21's criterion re-used (Screen Recording +
Accessibility both granted in the agent log within ~30 s of start).


#### P5 readiness — what the macOS pass actually needs (scoped 2026-08-31)

Re-consent is authorised and the Mac is to hand, so P5 is no longer *blocked*. It is still
**last**, and this records why it must be one focused pass rather than an increment.

**Surface**: ~13 files. Three launchd plists, `packaging/macos/postinstall` (30 occurrences —
the riskiest single file), `updater.rs` (the root-helper update chain, FR-5), `install.sh`,
`installer-smoke.yml` (13), `release-agent.yml` (12), the shim, the desktop companion, and
`ci.yml`'s self-containment gate. Four distinct identities move together or not at all:

| identity | where | breaks if wrong |
|---|---|---|
| `.app` bundle name | plists, postinstall, workflows | **TCC grants void** — no capture, no input |
| `CFBundleExecutable` | the bundle + `ci.yml` assert | the daemon does not launch |
| `/Library/Roomler/<bundle>` + its symlink | postinstall | `.pkg` installs to a path nothing runs |
| `/etc/roomler-agent/config.toml` | `fans.itachi.meshharbor.daemon.plist` `--config` | **the daemon loses its enrolment** |

⚠️ The config path is the one sweep 3 found: on macOS the "legacy" appdirs path is the LIVE
one, passed explicitly as `--config`, so it does **not** move by itself when appdirs changes.
It cannot be migrated on-device either — the plist argument is explicit, so copying the config
to `/etc/roomler` changes nothing until a release ships a new plist.

**Why it cannot be iterated cheaply**: there is no macOS host in the build loop, macOS artifacts
are produced **only at tag time**, and each attempt therefore costs a tag plus a full build plus
an install. Two failure modes are already documented and both are silent-at-review:
a `postinstall` whose shebang was pushed off line 1 broke the `.pkg` at *"Validating packages"*,
and a bundle built on a runner with Homebrew baked `/opt/homebrew` paths into its dylibs and
**dyld killed the agent at launch on every end-user Mac**.

**Order for the pass**, once P2b and P4 are done:

1. Move all four identities in one commit; `ci.yml`'s self-containment and `CFBundleExecutable`
   asserts are the cheap gate that must fail first if the set is inconsistent.
2. Carry the config path as a **dual read** for exactly one release — old plist arg and new both
   resolving — so a host that takes the update out of order is not stranded.
3. Tag, build, install on the one Mac, re-approve Screen Recording + Accessibility by hand.
4. Acceptance is FR-21's: both grants present in the agent log within ~30 s of start, plus a
   remote-control session that actually paints and accepts input.
5. Only then the second Mac.


#### P5b — what moved, and what deliberately did not

Four things move **together**, because moving any subset installs cleanly and then fails at
runtime in a way that reads as something else entirely:

| | old | new |
|---|---|---|
| bundle | `/Library/Roomler/meshharbor-agent.app` | `/Library/Roomler/meshharbord.app` |
| `CFBundleExecutable` | `roomler-agent` | `roomlerd` |
| `CFBundleName` (what the Privacy panes DISPLAY) | `Roomler Agent` | `Roomler Daemon` |
| TCC usage strings | "Roomler Agent captures…" | "Roomler Daemon captures…" |

**`CFBundleIdentifier` stays `fans.itachi.meshharbor.agent`** — deliberately. It is not a retired name
(`roomler.agent`, not `roomler-agent`), it doubles as the launchd `Label`, and it is what TCC
attributes grants to. Changing it would widen the blast radius of a rename that already costs a
re-approval, for no eradication benefit.

⚠️ **The grants do not carry over.** The path changes, so macOS treats the renamed bundle as a
different app: Screen Recording and Accessibility must be approved again, and the stale
`Roomler Agent` entry should be removed by hand. The postinstall says so on the host when it
sweeps the old bundle, because the alternative is an operator discovering it from a black screen.

**The sweep is the part that is easy to forget.** A `.pkg` install is additive, so without it an
upgraded Mac keeps a second signed, launchable copy of the daemon — and it is the copy every
existing grant still points at, so the Privacy pane would offer two plausible entries with no way
to tell them apart. `installer-smoke` now seeds a fake pre-rename bundle, re-installs, and asserts
it is gone **and** that the current one survived — seeded rather than asserted on a fresh box,
where the old bundle never exists and the assertion would pass while proving nothing.

⚠️ **A blind spot in the audit, found here.** `enrollCommands.ts` was left holding an anchor that
covered nothing once its last retired name was renamed — and the guard could not report it,
because the file is only scanned when `git grep -l` finds a token in it. A file whose LAST retired
name goes away keeps its orphaned marker invisibly. Cleaned up by hand; it is the same shape as
the sweep that rewrote an anchor's own explanation, one level out.

### D2 — the updater chicken-and-egg

A frozen agent cannot receive its own fix. Precedent: publishing a second Linux `.deb` froze
every pre-0.4.16 agent, and the fix had to be **server-side** for exactly that reason. Rule for
every phase: *if this is wrong, can the fleet still take the next update?* If no, the
server-side escape hatch ships first.

### D3 — history is not reachable

Roughly three thousand commit messages and blobs carry the name. A `filter-repo` mirror
rewrite is possible but **every SHA changes** and old commits stay reachable through
`refs/pull/*` indefinitely. Out of scope — see the acceptance framing.

## Phases

| # | phase | kill switch | status |
|---|---|---|---|
| P0 | spec + issue + taxonomy decision | — | **this doc** |
| P1a | split the marker into ANCHOR (live) / `RETIRED-NAME-RECORD` (history); `records` pinned exactly so nothing can be laundered | revert the audit script | **shipped** |
| P1b | publish daemon assets as `roomlerd-*`; guard rewritten as a companion denylist | revert the workflow; published assets are immutable and additive | **✅ FIELD-PROVEN on 0.4.40** |
| P2a | env prefix: rewrite every host that sets the retired spelling (make-before-break) | both spellings kept; `.bak` / additive reg key | **swept with the P2b instrument** — 11 of 17 online peers measurable, 2 hits, both resolved; 6 unmeasurable (exec off / no CLI / other org) |
| P2b | env prefix: retire the read arm; a retired variable is now IGNORED **and reported**, never silently dropped | restore the arm | **shipped** |
| P2c | remaining cheap classes | per-item revert | `TermsView` ✅, logs ✅, **e2e image ✅**, **wizard PATH (Linux) ✅** — Windows install dir **investigated, not shipped**: its anchor's stated reason (frozen with the enrolled-config segment) is FALSE, the real blockers are a stale HKCU PATH entry + a layout decision, and there is no wizard host to field-prove it on |
| P3 | appdirs read-fallback | staged rollout + rollback build | **KEEP** — the migration it backstops is skipped whenever the desktop companion is up, so on a GUI host the fallback is the PRIMARY path, not a net |
| P4 | wire values — **step 1 of 3 shipped**: server accepts both ALPNs, client still offers legacy; SNI renamed outright (provably unread) | revert the constant | **step 1 done** (first shipped in agent-v0.4.45); step 2 = flip the client, step 3 = drop the legacy. ⛔ **Step 2 is BLOCKED, measured 2026-09-01**: the server's `agents.agent_version` shows 24 live rows at ≥0.4.45 and **9 below it**, two of them online right now on 0.4.43. Three of the nine are Windows agents that **cannot self-update at all** (pre-0.4 ProductVersion rule ⇒ every 0.4.x MSI refused) and need a manual reinstall — waiting will not clear them |
| P5a | macOS config + log paths off the retired name (no TCC risk) | dual-read gates; migration is dest-absent-only and never deletes | **✅ proven by the macOS pkg smoke** |
| P5b | macOS BUNDLE rename — `meshharbord.app` / `roomlerd` / CFBundleName `Roomler Daemon`; CFBundleIdentifier deliberately UNCHANGED | postinstall sweeps the old bundle; revert = one release | **✅ FIELD-VERIFIED on 0.4.41** |
| P6 | retire the machinery: `anchors=0`, guard flips to record-only | — | gated on fleet turnover, not effort — see the endgame table |


⚠️ **Check each anchor's stated reason before paying its price.** Two of them have now been
found false on inspection: `artifact_version.rs` calls its fixtures "PUBLISHED release asset"
names that no release ever carried, and `TermsView` called a section heading a "defined term in
the Terms" when the Terms define the word in the body and reference the heading nowhere. Both
were free. An anchor is a *claim*, and FR-21 wrote them under time pressure across ~1 849 sites.

## Acceptance criteria

- [ ] `name-audit.sh` reports **`anchors = 0`** — the counter is the LIVE class — and CI blocks on it
- [ ] no runtime path, service name, scheduled task, env var, log filename, wire value or
      bundle identity read or written by shipping code contains a retired name
- [ ] every remaining occurrence is `RECORD`-classified with a stated reason, and the record
      count is pinned exactly (a new one is a deliberate, reviewed act)
- [ ] a pre-rename host upgrades to the FR-46 build and keeps its enrolled identity **or** is
      re-enrolled by a documented, proven procedure — decided per class, recorded here
- [x] `roomlerd-*` assets are published and every picker in the fleet finds them — **FIELD-PROVEN 2026-08-31 on 0.4.40** (measured, not reasoned; see the log below)
- [x] macOS: Screen Recording + Accessibility granted in the agent log — **field-verified
      2026-09-01 on 0.4.41** after the operator re-approved (`macOS permissions: Screen
      Recording + Accessibility both granted`, user-session agent, fresh start)


## What `anchors = 0` actually costs — measured 2026-09-01 at 635

The criterion above says `anchors = 0`, and that number is still the right target. What was
not stated, and needed to be, is that **most of what remains is gated on the fleet turning
over, not on effort**. Classified by each anchor's own stated reason (137 carry one; the rest
are region markers):

| class | markers | removable by writing code? |
|---|---|---|
| appdirs / pre-rename trees | **24** | **yes — P3** |
| already-published release assets | 13 | no — the files exist; only the *matching* can stop |
| log filenames / tracing target | **10** | **yes — P2c** |
| sweeps that delete the old thing | 8 | no — a sweep must NAME what it removes |
| MSI installer identity (ARP, FileKey, ProductName) | 6 | renaming breaks upgrade detection — its own program |
| wire values (QUIC ALPN, WebRTC stream id) | **5** | **yes — P4, behind a dual-accept window** |
| env fallbacks / opt-out markers | 5 | only once no host can still have one |
| docker registry image | **2** | **yes — P2c** |

⇒ roughly **41 markers are work**, and the rest are waiting on a condition rather than on
someone doing something. None is permanently impossible: a sweep is deletable once no host can
have the thing it sweeps, a published-asset fixture becomes `RECORD` the moment no picker
matches it, and the installer identity is a major-upgrade decision rather than a rename.

⚠️ **This is a statement about sequencing, not a lowered bar.** The temptation at this point is
to redefine the criterion down to whatever is currently true; the honest version keeps
`anchors = 0` and says plainly that reaching it needs the pre-rename population to age out.
Every class above has a named condition, so "how would we know?" has an answer for each.

## Open decisions

| # | decision | owner | state |
|---|---|---|---|
| 1 | The dormant pre-0.4.15 rows: re-enroll or accept losing them? | operator | **ANSWERED 2026-08-31 — either is acceptable.** So the appdirs / service / task anchors (P3) are no longer gated on preserving them |
| 2 | macOS re-consent — a human at each Mac | operator | **ANSWERED 2026-08-31 — authorised.** P5 is unblocked, but stays LAST and staged one host: the grants cannot be re-approved remotely, so a wrong rename is a fleet-wide capture/input outage until someone visits |
| 3 | Does "complete" include git history (D3)? | operator | proposed: **no** |
| 4 | Is `roomlerd-*` the final published asset spelling? | — | proposed: **yes** |

## Out of scope

- Git history and already-published GitHub release files (D3) — unreachable, and framing the
  goal as behaviour rather than `git grep` is what keeps this FR honest.
- Forks and local clones.
- The `meshharbor-desktop` / `roomlerd` / `roomler` names themselves — those are the destination.

## Field-verification log

| date | build | what was proven |
|---|---|---|
| 2026-09-01 | ⛔ P4 | **P4 step 2 is NOT safe yet, and the cheap measurement said it was.** Step 1 (server accepts both ALPNs) first shipped in **agent-v0.4.45**, so flipping the client to offer only `roomlerd-quic-v1` requires every tunnel-participating node at ≥0.4.45 — a client offering only the new name to an older server gets a clean handshake failure, i.e. a silently dead carrier. The `roomler exec` sweep looked conclusive: **7 of 15 online peers measurable, every one at 0.4.45**. The server's own record says otherwise. `agents.agent_version` over live rows: **24 at ≥0.4.45, and 9 below it** — `0.4.43 ×3` (two of them **online right now**), plus `rc.483`, `rc.458`, `rc.434 ×2`, `rc.286` seen within the last fortnight and `rc.99` stale at 92 d. ⚠️ The exec sweep was not merely incomplete, it was **biased**: exec only reaches hosts where exec is enabled, and that correlates with being actively maintained — i.e. with being up to date. The subset it could measure was the subset least likely to be behind. ⚠️ A version histogram alone is also misleading, because `agent_version` is the LAST REPORTED value and a long-dead row keeps its number forever; the query has to bucket by `last_seen_at` before it means anything |
| 2026-09-01 | ⛔ fleet | **Three Windows devices cannot self-update and will never age out of P4's gate on their own.** `rc.99`, `rc.458` and `rc.483` carry a pre-0.4 `msi_product_version_for`, whose only rule was *every final is 65535*. Offered a 0.4.x MSI they compute `0.4.65535` as the expected ProductVersion, the artifact carries `0.4.46`, `verify_artifact_version` refuses, and the updater keeps the current version — by design, since that check exists to stop a substituted artifact. Confirmed from the current function's own comment (*"the old every-final-is-65535 rule would collapse ALL 0.4.x MSIs into one ProductVersion"*), not from recollection. ⇒ they need a manual reinstall; waiting cannot fix them. The three Linux stragglers are NOT in this class — pre-0.4.16 Linux pickers choose by ARCH rather than by name, so the P1b `roomlerd-*` rename does not strand them, and `order_assets_daemon_first` keeps the daemon ahead of the companion |
| 2026-09-01 | 🏁 audit | **`unclassified = 0` — the repo is fully classified for the first time.** `anchors=615, records=3, unclassified=0, stale=0, paths=0`. Every surviving occurrence of a retired name is now either a deliberately frozen ANCHOR or a historical RECORD; none is unaccounted for. That is P6's precondition met on the classification axis (P6 itself waits on `anchors=0`, which is fleet turnover, not effort) |
| 2026-09-01 | 🚨 audit | **The audit script died SILENTLY at the exact moment it succeeded, and the bug was mine.** `name-audit.sh` runs `printf … | grep '^UNCLASSIFIED' | awk …` in report mode. Under its own `set -euo pipefail`, a `grep` matching NOTHING exits 1, `pipefail` propagates it, and the script dies **before printing a single line of the summary** — no counts, no error, exit 1. Every sibling `grep` in the same block carries `|| true`; this one alone did not. ⚠️ It was **unfalsifiable for the entire program**: while even one unclassified occurrence existed the grep matched, so the bug could not fire — it armed itself the instant the last one was classified, turning the milestone into what looks exactly like a crash. I hit it by running the audit and getting exit 1 with empty stdout AND empty stderr. ⚠️ The guard is scoped `{ grep … || true; }`, not a trailing `|| true`: the latter binds to the whole pipeline and would mask a real `awk` failure as well. Mutation-checked both ways — a stray unmarked mention is reported (`1 occurrence in 1 file`, file named) and `--check` is proven to still fail on it, while the clean tree reports `OK unclassified=0 (<= 0) anchors=615 (== 615) records=3 (== 3) paths=0 (<= 0)` |
| 2026-09-01 | ⚠️ P2c | **An anchor's stated reason was false, and it described the wrong blocker.** The tunnel wizard's Windows install dir carried *"the tunnel CLI's enrolled-config segment; see agents/meshharbor-cli/src/config.rs. Frozen together."* Verified against the source: they are **independent call sites** — the credential resolves through `ProjectDirs::config_dir()`, the install dir through `data_local_dir()`, and nothing derives the config path from the binary's location — so renaming the install dir **cannot orphan an enrollment**. The config segment IS frozen, for its own reason, and keeps its own anchor. This mattered because the false reason made the item look blocked on a credential migration nobody would attempt casually. The REAL blockers are smaller and both real: (1) a pre-rename install strands a stale `HKCU\Environment\Path` entry, and **PATH order decides which `meshharbor.exe` wins**, so the rename needs a `remove_user_path_segment` beside it exactly as the Unix arm needed `retire_legacy_symlink`; (2) the retired name appears **twice** on that path — the ProjectDirs application segment and the leaf — so finishing it is a layout decision, not a string swap. ⚠️ Deliberately NOT shipped blind: there is no tunnel-only Windows wizard host in the fleet to field-prove a PATH-cleanup change on, and this program's bar is field-proof, not CI-green. The anchor now states the true constraint so the next attempt starts from it |
| 2026-09-01 | fleet, 0.4.43 | **P2a swept with the P2b instrument, and the instrument has a floor AND a ceiling.** `roomler status` now prints `retired env N SET and IGNORED` / `legacy env N READ through a retired name`, so P2a's completeness is measurable rather than remembered. Swept all 17 online peers: 11 measured, 2 hits, and 6 that could not be measured at all — 2 with exec off, 1 with no `roomler` on PATH, and 3 in the OTHER org, where exec is org-scoped and correctly refuses. **Both hits were resolved and neither was a lost setting.** ⚠️ Two false-reading modes found in the instrument itself, and they point opposite ways: (a) `legacy_env_uses` records actual READS, so a knob not yet read this boot is invisible — one host's registry held TWO middle-prefix vars while status reported ONE, i.e. the status line is a **lower bound, not an audit**; the registry/unit scan is the complete measurement. (b) the process env is a **start-time snapshot**, so a host whose registry was already migrated keeps REPORTING the retired spelling until the daemon restarts — a false positive that looks exactly like an unmigrated host. Read both together or read neither |
| 2026-09-01 | fleet | **The two P2a hits, resolved.** Host A reported `MESHHARBOR_AGENT_LOCAL_TURN` + `MESHHARBOR_AGENT_VP9_FPS` as SET-and-IGNORED, which reads like two silently dead settings. It was not: its registry already carried `MESHHARBORD_LOCAL_TURN=1` and `MESHHARBORD_VP9_FPS=60` with **identical values**, and the retired spellings survived only in the running process's inherited env — make-before-break working exactly as designed, visible only because the daemon has not restarted since. Host B was the real one: `MESHHARBOR_NODE_OVERLAY_VPN_BYPASS=0` and `MESHHARBOR_NODE_OVERLAY_UPLINK_IF=15` live on the MIDDLE prefix (honoured, not retired). Migrated make-before-break — add the current spelling, verify both present with equal values, remove the old, verify only the new remains, with a value-count control on the key each time. Precedence makes the window safe: `MESHHARBORD_` is tried first, so between the add and the delete both spellings resolve to the same value. Empty middle-prefix leftovers on host A cleared the same way after confirming they held no value |
| 2026-09-01 | ⚠️ method | **My own sweep classifier nearly produced a fifth vacuous zero.** Its "unmeasurable" branch grepped for `remote execution is disabled`; the daemon actually says `remote execution is **not enabled**`. Two hosts therefore fell through to the `NO OUTPUT` branch instead of `UNMEASURABLE` — the label was wrong, but the host was still excluded from `clean`, because the fallback was written as *"anything I cannot positively read is not clean"* rather than *"anything I cannot classify is fine"*. That default is the only reason a wrong string did not become a false all-clear. ⚠️ The rule this program keeps paying for: **make the un-classifiable case loud, because your matcher WILL be wrong about a string you did not read from the source** |
| 2026-09-01 | fleet, live | **The correction above, confirmed empirically rather than by reading.** Listed `C:\ProgramData\meshharbor-agent` on three Windows hosts at the same moment: one contains **`peer-connected.lock`** (the live marker, so the directory is in active use), one is **present but empty** (no peer connected in that second — precisely the transient state sweep 5 mistook for "leftover"), and one is **absent** because sweep 5 removed it and no marker has been written since. Three hosts, three states, one directory, all correct. ⇒ the removal was harmless and the directory returns on the next write; the *inference* was what needed retracting. Also measured `.6` once it came back and `exec_enabled` took effect: control 21 ProgramData entries, `ProgramData\meshharbor\roomler` as the CURRENT segment, and **no legacy appdirs tree under any user profile** (glob control = 1). ⚠️ Its first probe returned the `exec_enabled` refusal message, which `grep -c` counted as a one-line result — the positive control is what caught it, again |
| 2026-09-01 | ⚠️ P3 | **The appdirs fallback is not a safety net for a rare failure — on a desktop host it is the PRIMARY mechanism.** P3's plan rested on "`migrate_legacy_trees` runs before config resolution, so the read-fallback only fires when migration FAILED". That is true of the ordering and false about the frequency: `migrate_legacy_trees(companion_running)` **skips entirely** when the desktop companion is up — `"migration skipped: desktop companion is running (will retry next start)"` — and the daemon itself *respawns* that companion into the user session, where it survives daemon restarts. So on any host with a GUI the companion is running at nearly every daemon start and the migration is structurally deferred, possibly forever. Observed on this box's own service log, not inferred. ⇒ removing the read-fallback would strand precisely the hosts whose migration never gets to run, and the thing that was supposed to rescue them is the thing that never fires. **This is a better reason to defer P3's code change than the offline-device count was** — that argument shrinks as devices return; this one does not |
| 2026-09-01 | ⚠️ CORRECTION | **Sweep 5's Windows conclusion was reasoned wrongly, and the right answer is narrower.** It reported `C:\ProgramData\meshharbor-agent` as an "EMPTY leftover" on all six Windows hosts and removed it. The directory is not a leftover: `system_context::peer_presence::marker_path()` builds `%PROGRAMDATA%\roomler-agent\peer-connected.lock` and that is a **live path the daemon writes today**. It was empty at probe time because no peer-presence marker existed at that moment — a transient state read as a permanent one. The removal itself was harmless (`fs::create_dir_all(parent)` recreates it on the next write, and the directory will simply come back), but the inference was wrong and the conclusion "the appdirs dual-read is unnecessary on Windows" does **not** follow from it: what was measured is that no legacy *appdirs* tree exists, which is a different claim from no legacy *path*. ⚠️ The general lesson is the one this program keeps relearning in new clothes: **an empty directory is evidence about a moment, not about a lifetime.** The earlier probes failed by searching paths that could not exist; this one failed by finding a real path in a quiet second. Both produce a confident zero |
| 2026-09-01 | code | **P4 step 1 — the two wire values are not the same problem.** The QUIC **ALPN** genuinely cannot change in one release: it travels in the ClientHello, and a peer offering only the new name to a server that knows only the old one gets a clean handshake failure — a carrier that is simply dead while the ladder falls back to DERP and says nothing. So it is a three-step changeover and this is step 1: the SERVER offers `[roomlerd-quic-v1, roomler-tunnel-quic-v1]`, the CLIENT still offers only the legacy one. Step 2 flips the client, step 3 drops the legacy. ⚠️ The **SNI** is a different case and the anchor's own reason gave it away — *"the pin is by cert fingerprint so the name is not semantically load-bearing"*. Checked rather than trusted: `FingerprintVerifier::verify_server_cert` ignores `_server_name` outright and compares a SHA-256 pin, and the cert is generated per process, so a new SAN just yields a new fingerprint advertised over signalling like any other. Renamed in one release. The anchor's other half — *"changing it buys nothing"* — is exactly what FR-46 disputes: it buys a retired name off the wire |
| 2026-09-01 | test | **The dual-accept is proven, not reasoned.** `the_server_answers_both_the_new_and_the_legacy_alpn` runs a real loopback handshake for EACH offered name against the dual server, so step 2 is a flip rather than a leap. Mutation-checked: dropping `ALPN_LEGACY` from the server list fails it. ⚠️ Writing it also reproduced this program's own recurring defect — the block first landed INSIDE the neighbouring test's doc comment, splitting it, which `cargo clippy` caught as *"empty line after outer attribute"* where the audit's own interleaved-anchor guard would not have (it looks for markers, and this was a plain test) |
| 2026-09-01 | code + cluster | **P2c e2e image + wizard PATH — and a fifth anchor whose reason was false.** The `roomler-agent-e2e` anchor said renaming "requires a coordinated re-push; until then the standing e2e namespace pulls the existing name". It does not: `kubectl -n roomler-ai-e2e get statefulset` shows minio, mongodb, mailpit, redis and the app — **no `agent-e2e` at all**. The overlay under `scripts/e2e-k8s/overlay-template/` is a sanitised TEMPLATE with `<internal-registry>` placeholders, not what is deployed, so nothing pulls the image and the rename was free. Renamed to `roomlerd-e2e` across the runbook, the kustomization rewrite and the StatefulSet; both YAMLs still parse. The wizard's PATH anchor, by contrast, was **TRUE** — flipping the name "leaves the old entry stranded and changes the command an operator types" — so the Linux half is answered rather than overridden: the symlink is now `~/.local/bin/roomler` **and a pre-rename `roomler-tunnel` symlink is REMOVED**, so an operator ends with exactly one name on PATH instead of one working and one dangling. ⚠️ Only a SYMLINK is removed — this wizard has only ever created symlinks there, so a regular file of that name is someone else's. The WINDOWS half stays: the per-user install DIR is named by the extract step, not by this module |
| 2026-09-01 | code + fleet | **P2c logs — and a shipping bug an anchor comment had been causing.** The legacy `roomler-agent.log*` prefix left both READ paths (crash-sidecar tail, `rc:logs-fetch`) after measuring zero such files on any reachable host against a control of 5–30 current logs each; RETENTION still matches it, so a host that turns one up ages it out rather than leaking it forever. All four SHIPPED `RUST_LOG` specs dropped `roomler_agent=info,` — they already carried `roomlerd=info` beside it, and every measured host reads exactly that, so the change is a no-op by construction. ⚠️ **The find**: an FR-21 anchor sat INSIDE two `\`-continued string literals in `service.rs`, which generate the per-user systemd unit and the macOS LaunchAgent plist. Rust's line continuation swallows the newline, so the marker text was being EMITTED — the unit carried `// RETIRED-NAME-ANCHOR(2): …` as a directive line, and the plist carried it between `<key>EnvironmentVariables</key>` and its `<dict>`, which is **invalid XML, so launchctl cannot load that LaunchAgent at all**. Verified by compiling the exact literal shape, not by reading. Nothing caught it: the file compiles, `cargo fmt` is happy, and the audit counted the anchor normally. Fixed, and `--check` now has a guard for it — mutation-checked, and detected via `substr` rather than a regex because `/\$/` silently fails to match where `/\\$/` works |
| 2026-09-01 | fleet, live | **Sweep 5 — the P3 gap closed, and a leftover unit nobody was looking for.** Two findings. (1) All three Linux cluster hosts still carried `/etc/systemd/system/meshharbor-agent.service` **plus drop-ins** (`ice.conf` = `MESHHARBOR_AGENT_ICE_RELAY_TCP=0`, and a `u2-soak.conf`). Both are **disabled and inactive**, and neither variable is in any running daemon's environment — so inert, but one `systemctl enable roomler-agent` from muscle memory would have started a second daemon, which is the documented restart-storm shape. Backed up to `/root/fr46-legacy-unit-backup.tar.gz` and removed on all three; `roomlerd` still active and still resolving 4 VD entries afterwards. The P2a `.bak` drop-ins went too, now that 0.4.41 has proved the current spelling. (2) **P3's Windows gap is closed**: every Windows host carried `C:\ProgramData\meshharbor-agent`, and on all six it was **EMPTY** — the live config is `C:\ProgramData\meshharbor\roomler\config.toml`, i.e. the CURRENT segment. Removed (guarded: skip if non-empty). No per-user tree exists at all, and no legacy log files anywhere. ⇒ **the appdirs dual-read is unnecessary on every reachable host** — Linux, macOS (via P5a) and Windows alike |
| 2026-09-01 | method | ⚠️⚠️ **Three of those probes returned a vacuous ZERO before being positive-controlled, and the first two would have been reported as "all clean".** `roomler exec` in argv-direct form **eats backslashes** — `cmd /c echo C:\ProgramData` arrives as `C:ProgramData` — so every Windows path probe silently searched a path that cannot exist. `cmd`'s `dir` also does not expand a wildcard in an *intermediate* path component (`C:\Users\*\AppData\...` errors out), and a PowerShell `@(…).Count` returned `1` while the matching name listing returned nothing, i.e. the `-Command` string was being mangled and *neither* number meant anything. **The only form proven to work through ssh → bash → `roomler exec` → cmd is a single quoted `cmd /c "…"` argument**, and every negative result needs a positive control that must return something. See [[reference_roomler_exec_quoting_windows]] |
| 2026-09-01 | 0.4.41, MacBook | **P5b field-verified.** The renamed bundle installed by the auto-updater, the pre-rename `meshharbor-agent.app` was swept, and the user-session agent reports `macOS permissions: Screen Recording + Accessibility both granted` on a fresh start after the operator re-approved. ⚠️ The reading is authoritative, not a heuristic: it comes from `CGPreflightScreenCaptureAccess` / `AXIsProcessTrusted`, not the `CGDisplayStream` probe the code warns "opens successfully without the grant". 🔑 **Worth recording for the next rename**: the daemon ALSO reported both granted at 23:41, minutes after the rename and BEFORE any re-approval — which points at the grants having survived because `CFBundleIdentifier` and the signing identity were deliberately left alone. Stated as the likely mechanism rather than proven: the operator did re-approve, so both explanations fit the end state, and FR-21's D5 assumption ("the bundle NAME keys the grants") is at least too strong for a signed app |
| 2026-09-01 | — | **A second, smaller audit blind spot, recorded not fixed.** A span marker INSIDE a `BEGIN`/`END` region is never staleness-checked — the region consumes every line before the span logic runs — so four inner anchors in `postinstall` and `fans.itachi.meshharbor.agent.plist` went on claiming the bundle name was TCC-frozen for a whole phase after P5b renamed it. Removed by hand. Not worth a guard: inside a region an inner marker is decorative by construction, and no checker can verify a prose CLAIM — which is the actual failure here, and the third time this program has met it |
| 2026-09-01 | 0.4.41 fleet | **P2b unblocked by the telemetry it shipped with.** `NodeStatus.legacy_env_uses` landed in 0.4.41, so the question stopped being a manual sweep: of the devices reachable on that build, **none reads a `MESHHARBOR_AGENT_*` variable**. One reads `MESHHARBOR_NODE_OVERLAY_VPN_BYPASS` — the middle prefix, which is not a retired *name* and stays. The Windows host that carried two values now reports nothing, confirming the make-before-break took: `MESHHARBORD_*` wins at arm 1 and the legacy pair was inert, so it was deleted; the three cluster drop-ins likewise lost their legacy half after `systemctl show` proved 0 legacy / 4 current. ⚠️ **Four devices are still offline and were never measured**, which is why the arm was not simply deleted — see the phase note |
| 2026-08-31 | CI (`installer-smoke`, macOS) | **P5a proven by a real `.pkg` install, and it found a defect first.** The job installs the package on a macOS runner, so it exercises the migration rather than reasoning about it: the daemon marker is seeded at the LEGACY path, the install migrates it, and the test then asserts it arrived at `/etc/roomler` **and that the legacy directory is gone**. ⚠️ The first run **FAILED** — `helper job still loaded after opt-out` — against 11 consecutive passes on master, so it was a real regression, not a flake. Root cause was not the rename: postinstall decided whether to `bootout` the update helper from **one sample** of `launchctl print … state = running`, and the previous install re-cycles the helper, so the opt-out install lands ~1 s later and samples it mid-startup. P5a only shifted the timing by adding the migration to the top of the script. The consequence was real — an operator who set the opt-out marker had the plist removed but the **job left loaded "until next boot"**, i.e. a Mac told to stop self-updating keeps a live updater. Fixed by waiting up to 10 s for idle instead of deciding on one sample; the ancestor protection is unchanged (a genuine in-flight update stays busy far longer and still takes the announce path, which now says "still running after 10s" instead of asserting an ancestry it never checked). Re-run: **SUCCESS** |
| 2026-08-31 | **0.4.40** | **P1b FIELD-PROVEN — the fleet updated ACROSS the rename.** `agent-v0.4.38/39/40` all post-date the P1b merge and publish every daemon artifact as `roomlerd-<v>-…` (both `.deb` arches, both tarballs, both MSI flavours, the `.pkg`), with the companion correctly still `meshharbor-desktop-…` and the release titled `roomlerd 0.4.40`. Agents on **all three OSes** are running 0.4.40 — two Linux, one Windows, one macOS — and every one of them came from a **pre-rename** build, since 0.4.37 was the last release before the change. The mechanism is visible rather than inferred: a Linux host's journal reads `new release available — spawning installer and exiting current=0.4.37 latest=agent-v0.4.40 path=/tmp/roomlerd-update/roomlerd-0.4.40-x86_64-unknown-linux-gnu.deb`, i.e. the picker chose the RENAMED asset, and `installer .asc verified against the pinned release signing key asset=roomlerd-0.4.40-…deb` — so the GPG sidecar naming followed the rename too. That last line is the one worth noting: the pinned-key verify is **fail-closed**, so a sidecar whose name had not tracked the asset would have frozen every Linux and macOS update instead of failing loudly |
| 2026-08-31 | fleet, live | **Sweep 1 (systemd):** `MESHHARBOR_AGENT_VIRTUAL_DESKTOP*` is STILL SET on all three cluster hosts (4 entries each, operator-authored drop-in) — so the arm is load-bearing today and the handover's "cheap class" framing was wrong. Migrated all three make-before-break: both spellings, identical values, `.bak` kept, `systemctl show` resolves 8 of which 4 are `MESHHARBORD_`, daemons untouched and still `active` |
| 2026-08-31 | fleet, live | **Sweep 2 (whole fleet, via Fleet RPC):** probed all 12 online devices through `roomler exec`, whose child inherits the daemon's own environment — so this reads what the daemon ACTUALLY has, not what a config file claims. Found a **second, independent setter the systemd-only theory would have missed**: a Windows host carries `MESHHARBOR_AGENT_VP9_FPS=60` **machine-wide in HKLM**, not in any unit file. Migrated additively (`MESHHARBORD_VP9_FPS=60` added, legacy kept). ⚠️ **7 devices remain unverifiable** — 3 online with `exec_enabled` false (gate 4, which is exactly the gate a server cannot overrule) and 4 offline. So P2b stays blocked on evidence, not on effort |
| 2026-08-31 | fleet, live | **Sweep 3 (appdirs trees, gates P3):** on the reachable Unix devices the legacy tree is **already gone on Linux** — all three carry `/etc/roomler` + `/root/.config/roomler` and neither legacy path — so the appdirs dual-read costs Linux nothing to remove. **macOS is the opposite**: it has `/etc/roomler-agent` and **no** `/etc/roomler`, i.e. on that platform the "legacy" path is the *live* one the `fans.itachi.meshharbor.daemon.plist` passes as `--config`. So removing the appdirs fallback is NOT one change — it is free on Linux and a coordinated plist + config move on macOS, which belongs next to P5, not before it. ⚠️ The Windows per-user tree is **still unmeasured**: `roomler exec` runs as SYSTEM, whose `%APPDATA%` is the service profile, while enrollment writes the *enrolling user's* profile |
| 2026-08-31 | fleet, live | **Sweep 4 (the one that found the method was wrong).** Re-swept every online device after two more got `exec_enabled`. Three corrections to sweep 2, all of them mine: (1) a `tail -1` had hidden a SECOND var on the Windows host — `MESHHARBOR_AGENT_LOCAL_TURN=1` beside `VP9_FPS`; (2) the probe read the PROCESS environment, and **Windows drops empty variables**, so three more legacy entries sat in the registry invisible to it (`VIEWER_RATE_RECOVER`, `OVERLAY_VPN_BYPASS`, `OVERLAY_UPLINK_IF`) — the registry is the surface a FUTURE start reads, and it is the one that matters; (3) the dev box and its WSL sibling report `exec_enabled` false and did not need it — they are **this** machine, inspectable directly, and the box carried a third setter (`MESHHARBOR_AGENT_GPU_CLOCK_PIN`). Actions: `LOCAL_TURN` mirrored; the four inert entries DELETED (empty parses identically to absent for all of them, and `VIEWER_RATE_RECOVER` has **no reader in the tree at all**); the dead legacy install directory removed from the machine PATH (it did not exist on disk). Every other Windows host is clean at registry level, as are the Asahi and macOS hosts. ⇒ **only the 4 OFFLINE devices are now unmeasured** |
| 2026-08-31 | code read | **The instrumentation to answer P2b already exists and is write-only.** `env::note_legacy_use` emits a WARN — *"value read through a RETIRED variable name"* — the first time any legacy prefix is read. It has **no counter, no LocalAPI field and no consumer**, and it fires once near startup, so `roomler logs --grep` (a ≤64 KiB TAIL) cannot answer for a long-running daemon. Surfacing it as a counter in `peers --json` would turn P2b from a manual sweep into a fleet-wide read, the same shape the overlay-ACL rollout used with `rx_denied` |
