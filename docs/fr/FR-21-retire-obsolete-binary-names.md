# FR-21 — Retire the obsolete `roomler-agent` / `roomler-agent-tray` names

| | |
|---|---|
| **Issue** | [#809](https://github.com/gjovanov/roomler-ai/issues/809) |
| **Status** | **DONE 2026-08-30 — all 13 acceptance criteria field-verified**, on Linux, Windows and macOS; the last one (a pre-rename host keeping its enrolled identity across an upgrade) on a purpose-built throwaway Windows VM, §12. **DEPLOYED, re-measured 2026-08-31**: prod API 0.4.30, latest release 0.4.33, `agent-v0.4.15` an ancestor of both, and **14 of 14 ONLINE agents on 0.4.33**; the 7 rows still on pre-0.4.15 builds are all OFFLINE and dormant (§12). 1 849 → **0** unclassified, 743 anchored, guard BLOCKING on `--check --strict`. ⚠️ The issue was closed 2026-08-29 at a stated "11/11", which counted only the boxes ticked at that moment — this line said the same and was wrong in both directions. |
| **Opened** | 2026-08-28 |
| **Baseline** | master `fa364b12` (0.4.11) — every count and anchor below was measured against it |
| **Scope** | Windows · Linux · macOS — code, comments, docs, `CLAUDE.md`, file names, folder names, env vars |

---

## 1. Goal

**A reader — human or a fresh Claude session — must never meet a name the product no longer
uses.** Every occurrence of a retired name is, after this FR, in exactly one of two states:

1. **migrated** to the current name, or
2. **a compatibility anchor**: deliberately frozen, carrying a comment that says *why*, and
   listed in a machine-checked freeze list.

There is no third state. "Occurrence nobody has looked at yet" is the state this FR exists to
eliminate, and the CI guard in P0 is what stops it coming back.

The current names are the ones the product actually ships:

| retired | current | what it is |
|---|---|---|
| `roomler-agent` | **`roomlerd`** | the daemon on a controlled host |
| `roomler-agent-tray` | **`meshharbor-desktop`** | the desktop/tray companion |
| `roomler-tunnel` | **`roomler`** | the CLI |
| `roomler-installer`, `roomler-tunnel-installer` | **`meshharbor-setup`** | the unified wizard (legacy wizards deleted in P4c-2) |

---

## 2. Why this is an FR and not a `sed -i`

**The hard part is not renaming. It is knowing what must *not* be renamed.**

Four earlier slices — P3d A/B/C and P3e — already moved the *runtime identity* surfaces and
deliberately left **dual-read fallbacks** so hosts enrolled under the old names keep working.
Those fallbacks read as "obsolete name in the code" to any sweep, and a naive sweep deletes
them. Deleting one does not fail a build and does not fail CI; it strands whatever fraction of
the field is still on the old segment, silently, at the next update:

| anchor | file:line | what breaks if a sweep "fixes" it |
|---|---|---|
| `OLD_APP = "roomler-agent"` | `crates/agent-core/src/appdirs.rs:40` | a pre-rename host's enrolled `config.toml` is orphaned — the device drops off the mesh and re-enrolls as a stranger |
| `LEGACY_SERVICE_NAME = "RoomlerAgentService"` | `agents/meshharbord/src/win_service/mod.rs:72` | the takeover install cannot find the running service to retire; two services, or none |
| `LEGACY_TASK_NAME = "RoomlerAgent"` | `agents/meshharbord/src/service.rs:394` | the pre-rename scheduled task survives forever → two daemons |
| legacy log prefix `roomler-agent.log` | `crates/agent-core/src/logging.rs:245,312,440`; `agents/meshharbord/src/logs_fetch.rs:56` | `rc:logs-fetch` returns "no log file" on an upgraded host that has not rolled yet |
| `LEGACY_INSTALL_FOLDER_NAME = "roomler-agent"` | `agents/meshharbord/src/updater.rs:369` | the vacated install dir is never swept |
| `%h/.config/roomler-agent` in `ReadWritePaths` | `agents/meshharbord/packaging/linux/meshharbor.service:44` | systemd denies the daemon its own legacy tree mid-migration |
| **the macOS `.app` bundle** — see §5, D5 | `packaging/macos/fans.itachi.meshharbor.{agent,daemon}.plist`; `.github/workflows/ci.yml:393` | **TCC grants are voided** — every Mac silently loses Screen Recording + Accessibility until a human re-grants them |

So the deliverable is not a diff. It is **a classifier plus a guard**: an inventory that assigns
every occurrence to `migrate` / `freeze`, a CI job that fails on an unclassified occurrence, and
then the migration itself — done in that order, because without the guard the migration is
unverifiable and regresses on the next PR.

---

## 3. Measured inventory (master `fa364b12`)

```
roomler-agent               874 hits / 154 files
roomler_agent               201 hits /  40 files
roomler-agent-tray           21 hits /  15 files
roomler-tunnel              269 hits /  70 files
roomler_tunnel               22 hits /  14 files
MESHHARBOR_AGENT_*             407 hits /  69 files   (107 DISTINCT variables)
roomler-installer /
  roomler-tunnel-installer   14 hits /   5 files
                          ─────────────────────────
union                      1765 hits / 233 files
```

Concentration, for `roomler-agent` alone:

```
61  agents/meshharbord       13  docs                6  .github/workflows
11  crates/agent-core           8  scripts             5  crates/tunnel-core
 7  ui/src                      6  agents/meshharbor-tunnel
 4  agents/meshharbor-desktop   3  crates/tests        3  docs/fr
 3  crates/meshharbor-setup-core   3  agents/meshharbor-setup
```

`docs/` carries 121 hits across 17 files. `CLAUDE.md` carries the retired name on 17 lines —
including the **Commands** block a new session copy-pastes (`CLAUDE.md:85-92`):

```bash
cargo build -p roomler-agent --release --features full
./target/release/roomler-agent enroll --server <url> --token <jwt> --name <label>
./target/release/roomler-agent run
```

That block was **wrong** (fixed in P1): the emitted binary is `roomlerd`
(`agents/meshharbord/Cargo.toml:18`), so the documented `run` command does not exist at the
documented path. This is the cheapest possible demonstration that the residue costs something.

### Build-graph identity — **migrated in P2a**

Recorded as it stood at the baseline, with what it became. The `bin` rows were already
correct before this FR; everything else moved in P2a.

| where | was | is now |
|---|---|---|
| package | `roomler-agent` | **`roomlerd`** |
| lib | `roomler_agent` | **`roomlerd`** |
| bin | `roomlerd` | unchanged — was already right |
| package | `roomler-agent-tray` | **`meshharbor-desktop`** |
| bin | `meshharbor-desktop` | unchanged — was already right |
| package | `roomler-agent-core` | **`meshharbor-core`** — renamed again by FR-69 (2026-09-04) to **`meshharbor-node-core`**; `meshharbor-core` is now the SERVER core at `crates/core` |
| lib | `roomler_agent_core` | **`meshharbor_core`** — now **`meshharbor_node_core`** (FR-69) |
| directories | `agents/meshharbor-agent/`, `agents/meshharbor-agent-tray/` | **`agents/meshharbord/`, `agents/meshharbor-desktop/`** |
| Debian `Package:` | derived `roomler-agent` | **explicit `roomlerd`** + `provides`/`replaces` takeover |

The `[[bin]]` comments state the intent plainly, and are the reason this half was left:

> *P3d Slice B: the OUTPUT binary is `roomlerd` (daemon). The package (`roomler-agent`) + lib
> (`roomler_agent`) names are UNCHANGED — only the emitted exe filename moves.*

That was the right call **then** — it kept the slice revertible. It is now the largest single
source of residue: 154 files reference a package name whose product no longer exists.

---

## 4. Classification — the three classes

Every occurrence gets exactly one label. This table *is* the spec for the P0 classifier.

### Class A — **migrate** (no runtime effect; the bulk of the work)

Prose, comments, doc files, `CLAUDE.md`, workflow `-p <pkg>` selectors, cargo package/lib names,
directory names, test names. *≈ 1 400 of the 1 765 hits.*

### Class B — **migrate with a dual-read fallback** (live surface; the old value must keep working)

Anything a deployed host — or a deployed *operator runbook* — already depends on:

- the **107 `MESHHARBOR_AGENT_*` variables**. An operator-facing surface: only **4** are documented
  in `crates/agent-core/src/config_surface.rs`, so the other 103 exist solely in code and in
  people's shell history.
- residual on-disk paths not yet behind `appdirs` (§5).
- the HTTP `user_agent("roomler-agent/…")` sent by the updater
  (`agents/meshharbord/src/updater.rs:717,800,1002`). It is **recorded** into device/session
  telemetry at `crates/api/src/ws/handler.rs:69` — confirm nothing *dispatches* on it before
  changing it, because changing it also changes what historical rows mean.

### Class C — **freeze** (renaming *is* the defect)

The seven anchors in §2, plus already-published GitHub release asset names (immutable), plus the
legacy `meshharbor-agent.service` unit name referenced by the duplicate-unit cleanup
(`packaging/linux/meshharbord.service:61`).

Every Class-C site gets a one-line marker so the classifier finds it mechanically rather than
through a hand-maintained path list that drifts:

```rust
// RETIRED-NAME-ANCHOR: pre-rename hosts still resolve this tree; see docs/fr/FR-21.
const OLD_APP: &str = "roomler-agent";
```

---

## 5. Field evidence — a live defect the residue is already causing

**The RC console's "open staging folder" affordance points at a path that does not exist on a
fresh install.**

`ui/src/views/remote/RemoteControl.vue:1783` hardcodes:

```js
const STAGING_PATH = 'C:\\ProgramData\\meshharbor\\roomler-agent\\staging'
```

But `appdirs::machine_global_dir()` (`crates/agent-core/src/appdirs.rs:73-92`) resolves
`%PROGRAMDATA%\roomler\<segment>`, where `<segment>` is `NEW_APP = "roomler"` unless a pre-rename
tree is present:

```rust
let new = base.join(NEW_APP);   // C:\ProgramData\meshharbor\roomler
let old = base.join(OLD_APP);   // C:\ProgramData\meshharbor\roomler-agent
if !new.exists() && old.exists() { old } else { new }
```

So the hardcoded path is correct **only** on a perMachine host that still carries the legacy
tree, and wrong on every fresh perMachine install — where the real directory is
`C:\ProgramData\meshharbor\roomler\staging`.

And unlike the per-user trees, `migrate_legacy_trees` (`appdirs.rs:133-175`) walks the three
`ProjectDirs` paths **only** — it never touches the machine-global tree — so the split is
permanent, not transitional.

⚠️ **To confirm in the field before P4 lands** (see §12). The prediction is falsifiable and is
recorded as such.

This is the argument for the FR in one example: the residue is not cosmetic. A hardcoded copy of
a name that a resolver has since made *conditional* is a defect waiting for the resolver to take
the other branch.

---

## 6. Key design

**One classifier, one guard, then the migration in risk order.**

```
scripts/name-audit.sh          # classifier + CI guard: one script, two modes
  --report   → every occurrence, labelled A/B/C, grouped by file
  --check    → exit 1 on any occurrence that is neither migrated nor a marked anchor
```

`--check` is what CI runs. It is deliberately **not** a "count must not increase" ratchet: a
ratchet happily passes a PR that deletes one anchor and adds one comment. The guard asserts the
stronger property — *zero unclassified occurrences* — which is only reachable after P1–P4, so
the job ships **advisory (warn-only)** in P0 and flips to **blocking** at the end of P5. That
flip is itself an acceptance criterion, because an advisory guard nobody flips is a guard that
does nothing.

Migration order is by blast radius, smallest first, each phase independently revertible:

```
P0  classifier + advisory guard        → no product change at all
P1  prose (docs, CLAUDE.md, comments)  → no runtime change; revert = git revert
P2  build graph (packages, libs, dirs) → no ARTIFACT change (bins are already correct)
P3  env vars, dual-read                → old names keep working forever
P4  residual live paths + the §5 defect → resolver with fallback, never a hardcoded constant
P5  ratify the freeze list, flip the guard to blocking
P6  field verification on all three OSes
```

**P2's safety property is checkable, and must be checked.** Renaming a cargo *package* changes
no emitted artifact, because every `[[bin]]` name is already correct. The P2 PR therefore has to
show a byte-identical artifact-name listing before and after. If any release asset name moves,
P2 is wrong and stops.

---

## 7. Phases

| # | Phase | Deliverable | Kill switch |
|---|---|---|---|
| **P0** ✅ | Classifier + advisory guard | `scripts/name-audit.sh`; CI job `name-audit` in `ci.yml` with `continue-on-error: true`; `RETIRED-NAME-ANCHOR:` markers on every Class-C site | the job is advisory — it cannot fail a PR |
| **P1** ✅ | Everything FALSE today | the two clap program names; the `CLAUDE.md` Commands block; the copy-paste install steps in `docs/tunnel-install.md`; script/manifest comments | `git revert` — no runtime surface touched |
| **P1b** | The bulk prose sweep | the ~1 700 remaining prose hits, *after* P2 has moved what they describe; historical appendices keep the retired name behind a block anchor | `git revert` |
| **P2a** ✅ | Build-graph identity, agent side | packages `roomler-agent`→`roomlerd`, `roomler-agent-tray`→`meshharbor-desktop`, `roomler-agent-core`→`meshharbor-core`; libs `roomler_agent`→`roomlerd`, `roomler_agent_core`→`meshharbor_core`; dirs `agents/meshharbord`→`agents/meshharbord`, `agents/meshharbor-desktop`→`agents/meshharbor-desktop`; every `-p` selector in the workflows + `Dockerfile.agent-e2e` + `scripts/` | one atomic PR, `git revert`; gated on an **empty artifact-name diff** |
| **P2b** | Build-graph identity, CLI side | package `roomler-tunnel`→`meshharbor-cli`, lib `roomler_tunnel`→`meshharbor_cli`, dir `agents/meshharbor-tunnel`→`agents/meshharbor-cli`; `release-tunnel.yml` | same; separate PR so `release-tunnel.yml` moves in a reviewable diff |
| **P3** | Env-var namespace | 107 vars `MESHHARBOR_AGENT_<REST>` → **`MESHHARBORD_<REST>`** (D1), **dual-read**: new spelling wins, old spelling honoured and logged once at WARN | the old spelling never stops working; the WARN is the only new behaviour |
| **P4** | Residual live paths | fix the §5 staging defect by calling a resolver instead of a constant (expose `machine_global_dir()` over LocalAPI); sweep the remaining hardcoded `roomler-agent` paths | every path keeps a new-then-old fallback, exactly like `appdirs` |
| **P5** | Ratify + enforce | freeze list reviewed and justified in-tree; `name-audit --check` flips to **blocking**; a deliberately-red run proves it fails | revert the `continue-on-error` removal |
| **P6** | Field verification | the §9.4 matrix on Windows / Linux / macOS, fresh **and** upgrade-from-0.4.x, including a pre-rename host | n/a — verification, not a change |
| **P7** ✅ | Drive `unclassified` to zero, flip the guard to `--strict` | 12 reviewed batches; every occurrence migrated or anchored with a stated reason; `ci.yml` runs `--check --strict`; new guard: a shebang must stay on line 1 | revert the `--strict` word in `ci.yml` — the `--check` pair keeps working |

### 7a. Resequencing, measured during P1 — P1 was specced too large

The original plan put a ~1 400-hit "prose sweep" before the build-graph rename. **That is not
possible, and the measurement says so plainly.** Classifying the prose by whether it is *false
today*:

```
command forms (`roomler-agent run`, `roomler-tunnel enroll`)   26   <- FALSE today
path refs (`agents/meshharbord/...`)                         55   <- TRUE today
cargo -p refs (`cargo build -p meshharbord`)                 12   <- TRUE today
```

Almost all prose correctly describes the *current* build graph: the package really is called
`roomler-agent`, and the directory really is `agents/meshharbord/`. Rewriting it before P2
would replace accurate documentation with a description of a state that does not exist yet.

So P1 shrank to *everything that is false today*, and the bulk sweep moved to **P1b, after P2**
— where it is no longer judgement work but a mechanical follow-on from the rename it describes.
The dead end is worth recording: "sweep the docs first, it's the safe phase" is the intuitive
order and it is wrong, because in a rename the docs are only wrong *after* the code moves.

**What P1 actually found and fixed** — the most valuable single line in the FR so far:

```rust
-#[command(name = "roomlerd", version, about, long_about = None)]   // agents/meshharbord/src/main.rs:39
+#[command(name = "roomlerd",      version, about, long_about = None)]
-#[command(name = "meshharbor-cli", ...)]                                // agents/meshharbor-cli/src/cli.rs:60
+#[command(name = "roomler",        ...)]
```

Both binaries **misnamed themselves in every `--help`, usage line and argument error**. Nothing
tested it, because clap's program name is display-only. Verified by running the built binary,
not by reading the diff: `Usage: meshharbord.exe` where it previously said `meshharbor-agent.exe`.

### 7b. Two hazards found while executing, both blocking their phase

1. **P2a would silently rename the Debian package.** `[package.metadata.deb]` in
   `agents/meshharbord/Cargo.toml:550` sets no `name`, so cargo-deb derives `Package:` from the
   crate name — and `docs/installation.md:240` documents `apt remove roomler-agent`, confirming
   it. Renaming the crate therefore makes dpkg see a *different* package: the old one stays
   installed beside the new one, or the upgrade simply does not happen. **P2a must either pin
   `[package.metadata.deb] name = "roomlerd"` as an anchor, or ship
   `Provides`/`Conflicts`/`Replaces` so dpkg performs a real takeover** — and whichever is
   chosen has to be proven by an actual `apt upgrade` on a host installed from the previous
   release, not by inspection.
2. **Historical appendices must keep the retired name.** `docs/remote-control.md` §17–19 are
   explicitly historical (`## 19. Appendix — resilience cycle (0.1.50 → 0.1.54, historical)`),
   and passages like *"anyone who tried `roomler-agent service install` after 0.1.50–0.1.52 saw
   the error"* are records of what people actually typed. Rewriting them falsifies the record.
   P1b marks those regions with a block anchor instead — which needs a
   `RETIRED-NAME-ANCHOR-BEGIN`/`-END` pair, since a line-counted span is too brittle for prose.

---

## 8. Acceptance criteria

- [x] `scripts/name-audit.sh --check` exits 0 on master, and its report shows **0 unclassified
      occurrences** (down from 1 765).
- [x] Every remaining occurrence is a `RETIRED-NAME-ANCHOR:` site whose comment states why it is
      frozen; the anchor count is asserted by a unit test, so silently deleting one fails a test
      rather than a field host.
- [x] CI **fails** a PR that adds a new unclassified occurrence — proven by a deliberate red run
      linked from the issue, not by assertion.
- [x] `CLAUDE.md`'s Commands block names binaries that exist (`roomlerd`, `roomler`,
      `meshharbor-desktop`); copy-pasting any line works on a real host.
- [x] **P2 changed no artifact name** — checked against REAL published releases rather
      than a dispatch build, which is stronger: these are the files the fleet actually
      downloads. Asset name sets for `agent-v0.4.14` (pre-rename) and `agent-v0.4.23`,
      version-normalised: **25 names, zero removed, zero renamed**. The three additions
      (`meshharbor-desktop-*.deb` + `.asc` + `.sha256`) are FR-27's companion package, not
      this FR — and are the same asset that froze the pre-0.4.16 Linux fleet.
- [x] A host that sets only a retired spelling still works, and a retired read logs a
      deprecation **once per variable per start**. Reworded from "all 107 variables
      still work": `node_env` has no per-key logic, so enumerating 107 lookups through
      one generic function would have looked like evidence without being any. The
      property that carries information is that nothing BYPASSES the chain — enforced
      by `name-audit.sh --check`, which fails a raw `set_var`/`remove_var` on a node
      prefix outside `env.rs` unless the line is marked `RAW-ENV-DELIBERATE`.
- [x] The §5 staging path resolves correctly on **both** a fresh perMachine host and a pre-rename
      perMachine host — the SPA and `machine_global_dir()` now agree by construction.
- [x] `cargo test -p meshharbor-tests` green (floor: the current ~294 across 34 modules, 2 skips).
- [x] `cd ui && bun run test:unit` green, including the `enrollCommands` retired-name lock.
- [x] `cd ui && bun run e2e` — no new failures against `scripts/e2e-expected-failures.txt`.
      Run via the **nightly lane**, 2026-08-29 11:34Z on tag `v20260829-673a1686220f`:
      `OK (13 failed, 3 skipped, 154 passed)` — `OK` is the script's own verdict, meaning
      all 13 failures matched the 20-entry expected-failures list (the documented
      environmental set: conference specs, `rc-vp9-444`, email flows, the oauth-callback
      case). The lane's working tree carries the rename (`agents/meshharbord` present), so it
      is a post-rename run. ⚠️ It predates #895 / #924 / #941 — the audit script, anchor
      comments and one Linux-only X11 accessor, none of which touch the web UI or the
      server behaviour this suite exercises.
- [x] **macOS TCC grants survive the upgrade**: Screen Recording and Accessibility are *not*
      re-prompted, and remote control works with no human action.
- [x] A pre-rename host (legacy `%PROGRAMDATA%\roomler\roomler-agent` tree present) keeps its
      enrolled identity — same `agent_id`, same overlay address — across the upgrade.
      **Field-verified 2026-08-30 on a purpose-built throwaway Windows Server 2022 VM**
      (Hyper-V, clean install, no roomler trees). Full log in §12.
      ⚠️ The criterion names `%PROGRAMDATA%`, but on Windows the *identity* is resolved by
      `project_dirs()` (the PER-USER tree), not `machine_global_dir()` — `default_config_path()`
      has no Windows branch for the machine-global root, which carries `staging\`, crashes and
      `service-logs\` instead. Both trees were legacy in this test and both migrated, so the
      criterion holds as written; the wording is narrower than the code.
- [x] Field: post-roll `roomler exec` sweep across the fleet on all three OSes; every host reports
      the expected binary, service/unit/launchd label, config path and log path.

---

Evidence for the ticked boxes, and what the unticked ones are still waiting on
(recorded here so a reader does not have to reconstruct it):

| criterion | evidence |
|---|---|
| audit 0 unclassified | CI on `2568ecd1`: `OK unclassified=0 (<= 0) anchors=756 (>= 756) paths=0 (<= 0)`, job **Retired-name audit (FR-21): success** |
| CI fails a new occurrence | mutation-checked: appending one unanchored mention gives `FAIL 1 unclassified occurrence(s); strict mode requires 0` |
| Commands block names real binaries | every `-p`/`--bin` in the block resolved against `cargo metadata`: `meshharbor-api`, `roomlerd`, `roomler`, `roomler-shim`, `meshharbor-desktop`, `meshharbor-tests` all exist |
| integration tests | CI `integration-tests` on `2568ecd1`: **338 passed, 0 failed** (floor ~294) |
| ui unit tests | CI **Frontend checks** green, running `bun run test:unit` + `vue-tsc` |
| macOS TCC | P6 macOS row below — `Screen Recording + Accessibility both granted`, 30 s after the 0.4.15 release |
| field sweep, three OSes | P6 Linux / Windows / macOS rows below |
| e2e, no new failures | nightly lane `scripts/e2e-nightly.sh`, 2026-08-29 11:34Z on `v20260829-673a1686220f`: `OK (13 failed, 3 skipped, 154 passed)`. `OK` is the script's verdict that every failure matched `scripts/e2e-expected-failures.txt`. Post-rename tree. ⚠️ Predates #895/#924/#941, none of which touch the UI or server behaviour it exercises |
| pre-rename host keeps its identity | Throwaway Server 2022 VM: genuinely pre-rename agent `0.3.0-rc.83` (binary still named `meshharbor-agent.exe`) enrolled against prod → `agent_id 6a93ef77…6b90`, resolving `config_path=%APPDATA%\roomler\roomler-agent\config\config.toml` + `machine_global=C:\ProgramData\meshharbor\roomler-agent`. Its OWN auto-updater then fired (`new release available … current=0.3.0-rc.83 latest=agent-v0.4.27`) and upgraded it. 0.4.27 logged all four legacy-tree migrations, kept the same `agent_id`, and took overlay `100.65.4.35`. Stricter second pass: legacy-only state re-created against the CURRENT binary → migrated again, **same `agent_id`, same `100.65.4.35`**. Fleet view showed `fr21-prerename-vm 100.65.4.35` online. Device then deleted: `{"deleted":true,"overlay_released":true,"overlay_ip":"100.65.4.35"}` |
| no artifact name changed | `gh release view` asset lists for `agent-v0.4.14` vs `agent-v0.4.23`, version-normalised and diffed: nothing removed, nothing renamed. Real published artifacts, not a rehearsal build |
| nothing bypasses the env chain | `PREFIXES` is now the single list both readers and `env::test_env` use; all 44 env manipulations in the agent go through it, and `name-audit.sh --check` fails any new raw one. The deprecation warning is `legacy_use_is_new`, mutation-checked: disabling the dedupe fails `legacy_reads_warn_once_per_variable_and_current_reads_never_do` |
| §5 staging path, both host shapes | `appdirs::resolve_machine_global` split out of the `OnceLock`-cached `machine_global_dir()` and pinned by 4 tests (pre-rename only / fresh only / both present / neither). `files.rs` derives the staging dir as `machine_global_dir().join("staging")`, so this is the decision the criterion turns on. Mutation-checked: dropping the pre-rename branch fails `machine_global_keeps_a_pre_rename_tree` |

**Nothing open. 13 of 13 ticked**, the last one field-verified 2026-08-30 on a purpose-built
throwaway Windows Server 2022 VM (§12). Issue #809 was closed earlier at a stated "11/11",
which counted only the boxes ticked at that moment; the list is now genuinely complete.

Both pre-rename shapes were exercised in that run, on the same host:

- **§5 staging path on a PRE-RENAME host** — `C:\ProgramData\meshharbor\roomler-agent` was the live
  machine-global root under `rc.83` (`machine_global=` logged), and `0.4.27` migrated it to
  `…\roomler\roomler`. `staging\` derives from `machine_global_dir()`, so this is the branch the
  criterion turns on. Previously confirmed only on the fresh side (`CORPLAP-1`, twice).
- **A pre-rename host keeps its enrolled IDENTITY across an upgrade** — the property was already
  field-proven on **Linux** (mars/jupiter/zeus, real `roomler-agent` installs through
  `apt-get install`, node id + overlay IP unchanged). It is now proven on the **Windows** shape
  the box actually names, which is the input that selects the other branch of the resolver.

---

## 9. Test plan

### 9.1 Unit

- **Classifier**: table-driven over a fixture tree — an unmarked Class-C anchor must be reported;
  a marked one must not.
- **Anchor count**: asserted, so deleting an anchor fails a test.
- **Env dual-read (P3)**: old spelling alone → honoured; both set → new wins; neither → default.
- **Path resolver (P4)**: new-tree-present / old-tree-present / both / neither.

### 9.2 Integration (`crates/tests`)

- The suite drives the agent library **in-process**, so the P2 package rename is exercised by the
  whole `agent` + `remote_control` module set (`rc:*` round-trip) rather than by a compile check.
- **Add**: a `logs-fetch` case against a fixture dir containing *only* legacy
  `roomler-agent.log.*` files — the Class-C log anchor, locked by a test instead of a comment.

### 9.3 E2E (`ui/e2e`)

- The 24 existing specs stay at parity with `scripts/e2e-expected-failures.txt`.
- The RC console spec gains a check that the staging affordance resolves to the path the **agent
  reports**, not to a constant compiled into the SPA (§5).

### 9.4 Field matrix — the acceptance surface

| OS | install | what is verified |
|---|---|---|
| Windows | fresh perMachine MSI | service `Roomler`; `meshharbord.exe` + `meshharbor.exe` + `meshharbor-desktop.exe` present; config under `%PROGRAMDATA%\roomler\roomler`; staging affordance opens the real dir |
| Windows | fresh perUser MSI | scheduled task `Roomler`; `%APPDATA%` tree on the new segment |
| Windows | **upgrade from 0.4.x, pre-rename tree** | identity preserved; legacy service/task retired, not duplicated; legacy log files still fetchable |
| Linux | fresh `.deb` | `meshharbord.service` active; `/etc/roomler/config.toml`; `roomler peers` OK |
| Linux | **upgrade from 0.4.x** | no duplicate unit (the `SubState=auto-restart` storm class); enrolled identity preserved |
| macOS | fresh `.pkg` | LaunchAgent + opt-in LaunchDaemon load; capture and input work |
| macOS | **upgrade from 0.4.x** | **TCC grants survive** — the single highest-risk assertion in this FR |

Field verification runs through `roomler exec` after the roll, per the standing rule:
**CI green ≠ done.**

---

## 10. Decisions

**D1 — target namespace for the 107 env vars: `MESHHARBORD_*` or `MESHHARBOR_*`?**
**RESOLVED 2026-08-28 (operator): `MESHHARBORD_*`.** The precedent exists already
(`MESHHARBORD_CONFIG`, used by `packaging/linux/meshharbord.service:48`), and `MESHHARBOR_*` sits one
underscore from the **server's** `MESHHARBOR__` double-underscore config prefix —
`MESHHARBOR_OVERLAY_DEMOTE` beside `MESHHARBOR__OVERLAY__…` is a confusion this FR would be
*creating*, not removing.

The full mapping is therefore mechanical: `MESHHARBOR_AGENT_<REST>` → `MESHHARBORD_<REST>`, for all
107, with the old spelling honoured forever (D2).

**D2 — do the 107 vars move at all?** They are the largest Class-B block and the lowest
reader-value: almost none appear in docs. **RESOLVED: yes, but last (P3), dual-read, and the old
spelling is never removed** — the cost of keeping it is one match arm, and the alternative is
breaking shell history and runbooks nobody has an inventory of.

**D3 — what does `roomler-agent-core` become?** `roomlerd-core` reads as daemon-only, but the
crate exists **because** the desktop companion deps it *without* the daemon (P3e lever E).
**RESOLVED: `meshharbor-core`** (lib `meshharbor_core`) — it is the node's shared core, not the
daemon's. *Superseded 2026-09-04 by [FR-69](FR-69-modular-monolith.md): the crate is now
**`meshharbor-node-core`** (lib `meshharbor_node_core`) — the same reasoning, spelled out — because
FR-69 gives the name `meshharbor-core` to the server's core crate at `crates/core`. The
pre-FR-21 name stays retired; the directory stays `crates/agent-core`.*

**D4 — rename the directories, or only the package names?** Renaming `agents/meshharbord/`
costs `git log` legibility for the naive reader. **RESOLVED: rename, in a commit that changes
*only* paths** so `git log --follow` and `git blame` track cleanly — never mixed with content
edits.

**D5 — the macOS bundle.** Freeze, or migrate with a paired TCC re-grant campaign? Freezing
leaves `roomler-agent` visible at `/Library/Roomler/meshharbor-agent.app` and in both launchd labels
forever. That is ugly, and it is still right: the alternative asks every Mac user to re-grant
Screen Recording and Accessibility, and a missed re-grant is a device that looks enrolled and
cannot be controlled. **RESOLVED: freeze** — revisit only with an installer that can re-register
the bundle without a human. The lock already exists on both sides —
`ui/src/__tests__/utils/enrollCommands.spec.ts:129-147` and `.github/workflows/ci.yml:393`.

**D6 — `roomler-tunnel`.** 269 hits, and the enroll-command test already treats it as retired
(`enrollCommands.spec.ts:143`). **RESOLVED: fold in** — same sweep, same guard — but as its own
sub-phase **P2b**, landing after P2a (the agent-side packages), so each rename stays separately
revertible and `release-tunnel.yml` moves in a diff a reviewer can hold in their head.
Package `roomler-tunnel` → **`meshharbor-cli`** (lib `meshharbor_cli`): the emitted bin is already
`roomler`, and the command surface lives in the lib (`meshharbor_cli::cli`, P3e lever D), so
"cli" names what the crate now is — the tunnel client is one of the things it drives, not the
whole of it.

---

## 11. Out of scope

- **Published GitHub release assets.** Already-published names are immutable. The updater's
  pickers key on extension + arch + the `-permachine-` infix, **not** on the `roomler-agent-`
  prefix (`agents/meshharbord/src/updater.rs:414-484`) — verified, not assumed. This is why P2
  is low-risk and why no asset rename is forced.
- The `MESHHARBOR__` **server** config prefix — a different product surface, not a retired name.
- `meshharbor-setup`'s own naming, including the UAC lib-naming rule (`wizard_app` / `wizard_shared`
  dodge "install"/"setup"/"update"/"patch" deliberately).
- `derp-relay`, `tcp-turn-conn`, `tunnel-core`, `localapi` — current names.
- **Any behaviour change.** This FR moves names and adds a guard. If a phase needs a behaviour
  change to make a rename tractable, that is a separate FR.

---

## 12. Field-verification log

| date | what | result |
|---|---|---|
| 2026-08-31 | **Deployment status — is the rename actually IN THE FIELD?** Completeness on master is not the same question, so it was measured: prod API version, latest published agent release, and the per-device `agent_version` for every row in the fleet tenant. | **DEPLOYED.** Prod API **0.4.30**; latest release **0.4.33**; `agent-v0.4.15` (the rename release) is an ancestor of both. **14 of 14 ONLINE agents run 0.4.33** — nothing live is behind. The only FR-21-tagged commit on master not in `agent-v0.4.33` touches `CLAUDE.md` alone, so no functional rename work is awaiting a release or a deploy. ⚠️ **7 of 21 registered rows still carry pre-0.4.15 builds and every one of them is OFFLINE** (windows rc.99 ~89 d, windows rc.299 ~25 d, linux rc.286 ~9 d, linux rc.434 ~8 d, windows rc.458 ~5 d, windows rc.483 ~3 d, windows 0.4.13 ~1 d). Dormant device rows, not a stalled rollout — and the path they take on waking is the one field-verified the day before on the throwaway VM: the new binary migrates all four legacy trees and keeps the same `agent_id` and overlay address. The 0.4.13 row is the only one recent enough to expect back soon. ⚠️ Straggler detail is recorded by OS + version + staleness on purpose: the fleet API returns REAL machine names, which the repo may not carry. |
| 2026-08-30 | **THE LAST CRITERION — a genuine pre-rename Windows host, upgraded.** No such host exists in the fleet (all post-rename) and this dev box has a live enrollment, so one was BUILT: a throwaway Hyper-V VM, Windows Server 2022 Evaluation applied straight from the Microsoft ISO to a VHDX (`Expand-WindowsImage` + the GUEST image's own `bcdboot` — the host's Win11 `bcdboot` fails `193`), unattended via `Panther\unattend.xml`, driven entirely over PowerShell Direct. Clean host: no `roomler` trees at all. Installed the genuinely pre-rename **`0.3.0-rc.83`** (May build; binary still named `meshharbor-agent.exe`) and enrolled it against **production**. | **PASS, and by the product's own upgrade path.** rc.83 logged `config_path=%APPDATA%\roomler\roomler-agent\config\config.toml` and `machine_global=C:\ProgramData\meshharbor\roomler-agent` — both LEGACY — loaded `agent_id 6a93ef77…6b90` and sent `rc:agent.hello`. Its **own auto-updater** then fired (`new release available … current=0.3.0-rc.83 latest=agent-v0.4.27`) and installed 0.4.27, which logged all four legacy-tree migrations (`roomler-agent` → `roomler`, per-user config + data, LocalAppData data, ProgramData) and came up on the **same `agent_id`**, taking overlay **`100.65.4.35`**. Stricter second pass against the CURRENT binary: legacy-only state re-created (all three roots renamed back, no new tree anywhere) → migrated again, **same `agent_id`, same `100.65.4.35`**. Fleet view: `fr21-prerename-vm 100.65.4.35` online. Torn down after: device deleted (`{"deleted":true,"overlay_released":true,"overlay_ip":"100.65.4.35"}` — the lease returned to the pool, nothing burned), VM + 16 GB of artifacts removed, temporary host firewall rule removed. |
| 2026-08-28 | **Debian takeover, against real artifacts.** Built `.deb` from `release-agent.yml` run `33150602388`; published `agent-v0.4.11` `.deb` as the upgrade-from side. | **PASS.** `Package: roomlerd`, `Provides: roomler-agent`, `Replaces: roomler-tunnel, roomler-agent`. Upgrade via `dpkg -i` (the self-updater's *fallback*, the stricter path): **exit 0, zero overwrite conflicts**; `/usr/bin/roomlerd` + `/usr/bin/roomler` ownership transferred to `roomlerd`; unit present. Vestigial `ii roomler-agent` remains exactly as designed, and the one-time `--remove roomler-agent` sweep exits 0 with **all files surviving**. Asset filename unchanged (`roomler-agent-0.4.11-…deb`), so the "no artifact name moves" criterion holds. |
| 2026-08-29 | **P7 — `--strict` reached, and three real defects found on the way.** `unclassified` 1006 -> 0; 732 anchored sites, 0 stale markers. (1) `user_profile::active_user_config_path()` hardcoded the PRE-rename appdirs segment, so on every post-rename install the path could not exist and the caller's `exists()` filter silently dropped the user-config rung — indistinguishable from "no logged-in user", the documented `None` case. It survived because the test asserted `ends_with("\\roomler-agent\\config\\config.toml")`: the test pinned the bug. Now dual-segment, with a pure test on candidate ORDER; mutation-checked red/green. (2) An anchor block had been inserted ABOVE `#!/bin/bash` in the macOS `postinstall`, so `installer` could not execute it and EVERY `.pkg` install failed at `Validating packages`. Red on `installer-smoke` for nine commits, misread as the flakiness master shows on the same job — master fails LATER (`helper job still loaded after opt-out`, after a successful install). One job name, two failures. `--check` now fails any tracked file whose shebang is not line 1 — the anchor system's own failure mode, caught by nothing else. (3) Nine env keys were exercised in tests only through the RETIRED spelling, i.e. the third link of a three-link fallback; the spelling the code and docs use was covered by nothing, and `hw_auto_disabled_reads_env` cleared one name while reading a chain preferring the other. Plus a break this branch itself caused: the e2e image moved to `/etc/roomler` while its StatefulSet still mounted `/etc/roomler-agent`, and its data PVC mounted a directory the daemon never writes to. |
| 2026-08-28 | Full release lane under the renamed packages (dispatch). | **PASS** — both `.deb`s, `.msi`, `.pkg`, companion EXE all build. |
| 2026-08-28 | **P6 Linux, on three REAL hosts** — mars, jupiter, zeus, each with `roomler-agent 0.4.11-1` genuinely installed and the daemon running. `.deb` from run `33150602388`, moved to each host over the roomler mesh itself (`100.65.4.2` → node). Primary path `apt-get install ./…deb`, not the fallback. | **PASS.** `Replacing files in old package roomler-agent`, exit 0, no conflict, on all three. `/usr/bin/roomlerd`, `/usr/bin/roomler` and the bundled FFmpeg `.so`s transferred owner; `ldd` 0 not-found; node id + overlay ip UNCHANGED; service active on the new binary; `roomlerd --version` now `roomlerd 0.4.11` (production printed `roomler-agent 0.4.11`). |
| 2026-08-28 | **The RUST_LOG shim, forced onto the legacy spec** — a `.deb` upgrade replaces the packaged unit, so a plain upgrade tests the FILE, not the fallback. Drop-in pinned `RUST_LOG=roomler_agent=info,warn` on mars, then restart. | **PASS.** INFO 40 → 75: 35 new lines from the renamed lib under a spec naming ONLY the retired target. Without the shim it stays 40 and the daemon goes dark above `warn`. Drop-in removed; the operator's own `virtual-desktop.conf` untouched. |
| 2026-08-29 | **P6 Windows** — `CORPLAP-1`, a real corp Windows 11 host, carried onto `agent-v0.4.15` (the first release containing the rename) by the FLEET UPDATER, not by hand. Driven over Fleet RPC. | **PASS.** Service `Roomler` RUNNING from `"C:\Program Files\MeshHarbor\meshharbord.exe" service-run`; `roomlerd --version` -> `roomlerd 0.4.15`; the legacy `RoomlerAgentService` is **not installed** (`OpenService` 1060) — retired, not duplicated. |
| 2026-08-29 | **P6 macOS** — `MacBook-1`, Apple Silicon (Darwin 25.6 arm64), same updater-driven path. | **PASS, including the TCC assertion.** The bundle is still the frozen `/Library/Roomler/meshharbor-agent.app` (D5). The 0.4.15 process started `21:36:32Z` — 30 s after the release was published at `21:36:02Z` — and logged `macOS permissions: Screen Recording + Accessibility both granted` at `21:36:34Z`. The highest-risk claim in this FR, checked against a real Mac rather than reasoned about. |
| 2026-08-29 | **§5 confirmed a SECOND time, independently.** `%PROGRAMDATA%\roomler` on `CORPLAP-1` holds `roomler` and **no** `roomler-agent`. | **PASS.** The literal the viewer used to hardcode is wrong on that host too — two independent Windows hosts now, not one. |

⚠️ The isolated-dpkg-root row above used `--force-depends` + `--force-script-chrootless` and
exercised only `dpkg -i`. Its caveat — *"no real host has taken this upgrade"* — **no longer
holds**: the two rows beneath it are three real fleet hosts taking it through the `apt-get
install` primary path, with the daemon running and the old package genuinely installed. The two
tests are complementary rather than redundant — the isolated one covers the stricter `dpkg -i`
fallback, the fleet one covers the path the self-updater actually tries first.

⚠️ **The one-way-door risk is CLOSED, and it got field-tested by accident — which is better
than the test I designed.** P2a landed before the next release, so `agent-v0.4.15` shipped as
`roomlerd` and the fleet updater carried all three converted hosts across on its own. They did
not take the clean path either: each received a pre-rename `roomler-agent 0.4.13` in between, so
the sequence actually exercised was *converted → pre-rename release → post-rename release*. End
state on all three: `/usr/bin/roomlerd` and `/usr/bin/roomler` owned by `roomlerd`, running
process `/usr/bin/roomlerd`, version `roomlerd 0.4.15`, and `roomler-agent` surviving as a
file-less entry owning exactly the 11 vestigial paths the design predicted. A one-time
`apt-get remove roomler-agent` clears those and is safe because `replaces` transferred every
file — deliberately NOT run here, because that is a fleet action, not a test side effect.

⚠️ Not a regression, chased rather than assumed: jupiter/zeus sat on `relay:derp/tcp` from the
dev box after their restarts. From mars both were `direct 0 ms` throughout — only the long-haul
path to a home NAT degraded — and the `demote-follow` WARN (#746; its mitigation
`overlay_answer_while_followed` is unset on these hosts) occurred 171/158/81 times on the three
days BEFORE this change versus 39 today, restarts included. Take a second vantage before calling
a relay state a regression.

**To confirm before P4 lands** (§5): read the actual staging directory on a fresh perMachine
Windows host and on a pre-rename perMachine host. The prediction is that they differ
(`…\roomler\roomler\staging` vs `…\roomler\roomler-agent\staging`) and that the SPA affordance is
wrong on the first. If they do **not** differ, §5 is wrong and P4 is rescoped — record that here
either way, per the standing rule that a documented dead end is often the most valuable line in
the log.

---

## Related

- `CLAUDE.md` → *Install-size trim (P3e)*, *P3e Phase 2/3* — the slices that renamed the binaries
  and deliberately left the package names.
- [FR-7](FR-7-signed-releases.md) — release asset naming and the signing pipeline; P2 must not
  disturb the signed payload names.
- [FR-5](FR-5-macos-unattended-update-chain.md) — the macOS update chain that D5's TCC risk rides
  on.
