# FR-6: CI + release build-speed SLO — every lane ≤10 min warm, self-healing

**Status:** shipped + field-verified through 2026-08-26 (retroactive FR per the CLAUDE.md
standing rule — the program ran 2026-07-13 → 2026-08-26 across ~20 PRs). Tracking issue:
`FR-6` (#773) in gjovanov/roomler-ai/issues.

## Goal

A push to `master` (PR CI) and an `agent-v*` tag (release) must complete their gating
lanes in **≤10 minutes warm**, and the system must **self-heal**: no silent cold builds,
no cache state that a human has to notice and repair, and every degradation announcing
itself on the affected run's page. Baseline when the program started: releases took
**~60–69 min** (rc.176: 29m09s rebuilding FFmpeg from source per tag), PR CI drifted to
~30 min under mirror stalls.

## Root causes (field-evidenced, in the order they were peeled)

1. **FFmpeg/libvpx rebuilt from source per tag** — the vendored zips existed
   (`vendored-ffmpeg-8.1.2` release) but `build-windows` never consumed them.
2. **GitHub's 10 GB Actions-cache pool cannot host the release seeds** alongside the
   legitimately hot CI caches. Every scheme change only rotated the eviction victim:
   tag-ref saves are unrestorable by design; the env-hash key component flaps with the
   runner-image lottery (`0c34b334` vs `e76361e6`, same toolchain + lockfile, run
   30707448990); flat keys are immutable so refreshes silently skip-save; delete-based
   refreshes open absent-key races (rc.382 tagged inside one); LRU evicted a **verified**
   save 29 minutes later (rc.472, run 32892784757).
3. **Serial waste in the MSI job**: a debug-profile mismatched-feature link test (5m33s),
   tray/installer built serially (~9 min tail), `cargo-wix` compiled per tag.
4. **Non-cache axes**: Ubuntu-mirror apt stalls (25m47s in one step, run 32191779671),
   Windows-runner queue starvation during release bursts (70 min queue, rc.424), a CI
   step added without a lockfile change being permanently locked out of the immutable
   cache (`Run API unit tests`, +7 min/run), and a GUI smoke probe that hung forever the
   day the binary it launched stopped crashing (#659 → run 32738472108).

## Key design (as shipped, anchors verified 2026-08-27)

- **Seeds live on a rolling `seed-cache` RELEASE, not in the cache pool** —
  `.github/actions/seed-cache-restore/action.yml` + `seed-cache-save/action.yml`: two
  assets per family (`<fam>-cargo.tar.zst` + `<fam>-target.tar.zst`), `--clobber` is the
  keep-newest-1 retention, `--latest=false` (the fleet self-updater polls
  `/releases/latest`). No LRU, no budget, no reservations, repo-global (no ref scoping).
- **Reseed choreography** (`.github/workflows/release-agent.yml`): a `reseed` job
  dispatches an artifacts-only rehearsal after every successful tag; weekly cron +
  `seed-release-caches.yml` (paths: `rust-toolchain.toml`, `release-agent.yml`,
  `.github/actions/seed-cache-*/**`) re-seed on the events that reshape a seed.
  Rehearsals share a cancel-in-progress concurrency group; tag runs are never cancelled.
- **Nothing fails silently**: `seed-cache-save` verifies via the API that its assets
  exist and `::warning::`s the run page otherwise; `seed-cache-restore` warns on a cold
  TAG build; failed rehearsals file a GitHub issue (`seed-failure-alert` job); saves run
  under `if: always()` so a downstream failure still seeds.
- **Growth control**: accretion GC before the build (registry mtime sweep + all-or-nothing
  `target` drop over `SEED_TARGET_MAX_MB`, never file-level deletes under `target` —
  cargo fingerprints outlive outputs); `cache-janitor.yml` sweeps PR-ref/idle/tag-ref
  strays every 6 h.
- **PR CI** (`ci.yml`): Swatinem, keyed on the environment and the lockfile. A member
  crate's `Cargo.toml` edit or a third-party `Cargo.lock` change rotates a family's key,
  and the next run restores the previous generation as a prefix match. A version bump
  rotates nothing (wave 15). Since wave 16 a job's own changed or added steps rotate
  that job's key too: `.github/actions/cargo-cache-salt` writes a comment-only
  `.cargo/config.toml` holding a hash of the job's definition, which the lockfile part
  of the key covers, so the restore still falls back to the previous generation. apt
  packages are cached via `cache-apt-pkgs-action` (mirror out of the hot path). Since wave 14 the Rust work runs as **five parallel lanes**
  (`rust-lint`, `rust-unit`, `rust-agent`, `rust-recorder`, `rust-recorder-audio`),
  each with its own cache family and the same system packages from one composite
  (`.github/actions/ci-linux-system-deps`); an aggregate job keeps the name
  "Rust checks". Every Swatinem block that runs on PRs **saves only from master**
  (`save-if`), `CARGO_PROFILE_DEV_DEBUG=line-tables-only` shrinks compile time and cache
  size, a `concurrency` group cancels a PR's superseded run, and `cache-janitor.yml`
  deletes any cargo cache on a PR ref and keeps one generation per family on master,
  running after every master CI run as well as on its cron.
- **MSI job**: vendored FFmpeg/libvpx fetched from release assets (sha256-verified, exact
  legacy paths so baked `.pc` prefixes hold); FFmpeg link asserted inside `encoder-smoke`
  on the built EXE (the 5m33s cargo-test step is gone); tray/desktop companion in a
  parallel job; GUI smoke probes hard-bounded (background + `kill -9` after 5 s).

## Phase / wave table

| Wave | Date | Change | PR(s) |
|---|---|---|---|
| 1 | 07-13 | Vendored FFmpeg/libvpx consumption, release-profile link test, parallel companions, `save-if` on tag refs, Swatinem in ci.yml | #105→#108 (squash) |
| 2 | 07-23 | Smoke-side FFmpeg assert; weekly cron seed mode; toolchain-bump dispatcher | #161 |
| 3 | 07-30 | `cache-on-failure`; seed-failure-alert issue filer | #258 |
| 4 | 08-01 | Env-hash removed from keys; post-release reseed job; cache janitor | #266 |
| 5 | 08-15 | Lockfile-generation keys via local composites (rust-cache retired from the lane) | #488 |
| 6 | 08-19 | apt-package caching + 20-min CI timeout | #535 |
| 7–8 | 08-19/20 | Inline generation retirement; accretion GC (+ the #660-era fingerprint-safety hardening) | #537, #549 |
| 9 | 08-20 | Rehearsal concurrency (cancel-in-progress) | #556 |
| 10 | 08-21 | `wf-` hash in the CI cache key (a no-op, found in wave 15: rust-cache ignores `key` when `shared-key` is set) | #587 |
| 11 | 08-24 | Hard-bounded macOS GUI probe | #661 |
| 12 | 08-25 | Run-salted keys (reservation wedge) | #675, #677 |
| 13 | 08-26 | **Seeds → release assets** (+ shakeout: mktemp for tar paths, dispatcher watches composites, `contents: write` on the OIDC-narrowed Windows jobs) | #722, #725, #726, #728 |
| 14 | 09-27 | **PR CI regression**: the "Rust checks" monolith split into five parallel lanes + an aggregate; PR runs write no cargo caches (`save-if` in `ci.yml`, `integration-tests.yml`, `installer-smoke.yml`); `line-tables-only` debuginfo; PR-run `concurrency`; janitor sweeps PR-ref cargo caches and superseded master generations | #1743 |
| 15 | 09-28 | Actions-cache storage limit 10 → 20 GB (the operator, paid); the dead `key: wf-…` inputs removed, and the comments that relied on them corrected | #1772 |
| 16 | 09-29 | `cargo-cache-salt`: each of the 14 PR-facing Swatinem jobs (`ci.yml`, `integration-tests.yml`, `installer-smoke.yml`) salts its key with a hash of its own definition, so a new step's dependency builds reach the cache on the next master run (root cause 4, for real this time) | #1784 |
| 17 | 10-01 | The Actions budget set to $10 (the operator): above the free 10 GB the pool had been **read-only** since the 20 GB raise. And the profiles job's SFU build deps (cmake + libclang) come from the lanes' cached apt sets instead of a raw `apt-get` against the mirror | #1805 |
| 18 | 10-01 | The macOS desktop companion builds in a parallel job (`build-macos-companion`, its own seed family `agent-macos-companion`) instead of serially at the end of `build-macos`, which collects the binary where it used to build it | #1804 |
| 19 | 10-01 | The release Linux x86_64 job installs every package from one cached apt set (`release-linux-u2204-v1`, the master rehearsal saves it, tags restore it) instead of three raw `apt-get` steps against the mirror | #1806 |
| 20 | 10-06 | The Linux desktop companion builds in a parallel job (`build-linux-companion`, its own seed family `agent-linux-companion`, the SAME cached apt set as `build-linux`) instead of serially at the end of `build-linux`, the Linux twin of wave 18 | #1938 |
| 21 | 10-10 | The cache limit back to the **free 10 GB** (the paid tier went read-only when another repository spent the account's budget), and two cuts to master's working set: the plain recorder lane restores `recorder-audio`'s family (works, ~600 MB); a `cargo-cache-trim` step dropped the crate archives before each save (**a no-op**: rust-cache's own `cargo metadata` downloads them again before saving) | #1939 |
| 21b | 10-10 | The trim removed from all 14 jobs. The integration lane builds with `line-tables-only` instead of full debuginfo | #1944 |
| 22 | 10-11 | **Six cargo caches move to the free release-asset store** (`seed-cache` assets `ci-<family>-<os>-<arch>-*`, `.github/actions/ci-seed-restore` + `ci-seed-save`): integration, both installer smokes, and `ci.yml`'s macOS overlay check and two Windows lanes. The Actions cache keeps only the seven Linux lanes plus apt and bun | #1954 |
| 23a | 10-19 | The cargo-cache salt step removes every Rust toolchain but the pinned one before rust-cache computes its key (Linux). rust-cache hashes `rustc -vV` of **every installed toolchain**, so the runner image's own `stable` was in every key: a GitHub image rollout (1.99.0 → 1.99.1) gave each family two keys, and the janitor deleted each in turn as superseded | #2544 |
| 23b | 10-19 | Integration-suite dispatch inputs `threads`, `mongo_tmpfs` and `report_time` (libtest's per-test durations; the slowest tests, seconds per module and mongod's descriptor peaks go to the step summary) | #2544 |
| 23c | 10-19 | The release-asset cache key covers every manifest: profile and feature settings shape the dependency builds, and Cargo.lock records neither | #2544 |
| 23d | 10-19 | The crypto crates (Argon2, OPAQUE, the curve and AEAD crates) build at `opt-level = 3` in the dev and test profiles: the integration suite's test time −34% | #2544 |
| 24 | 10-20 | **The integration suite runs as three shards**, each on its own runner with its own mongod at 2 threads. Each shard lists the same binaries, sorts the (test, binary) pairs and runs every third with `--exact`; each must report every test it was handed. Only the first shard publishes the cargo cache | #2596 |
| 25 | 10-20 | **A merge burst queues one run, not one per commit**: `ci.yml`, `integration-tests.yml` and `installer-smoke.yml` group master's runs by branch, so GitHub keeps one running (never cancelled) and one waiting, and a newer push cancels the waiting one. PR pushes cancel their superseded run; a dispatch gets a group of its own | #2624 |

## Acceptance criteria

- [x] Release lane restores its seeds from a store with no LRU/budget/reservations
      (field: `restored from: seed-agent-windows-…-X64 assets (2.0G target)`, 2026-08-26)
- [x] All five lanes publish + restore asset pairs (10 assets live on `seed-cache`)
- [x] A failed/cancelled rehearsal cannot leave the lane silently cold (alert issue +
      run-page warnings, field-proven by #683 and the 403 warning that found #728)
- [x] PR CI warm ≤10 min with a hard cap — held at 4.9–7 min from #587, then
      **regressed** to 18–21 min warm and 35–45 min cold over 58 runs by 2026-09-27
      (the single "Rust checks" job had grown to ~35 serial steps, and PR-ref cache saves
      were evicting master's). Wave 14 restored it (field, run 36348497216 on #1745): the
      **whole CI in 6 min 21 s**, `Rust checks` critical path 5.8 min, every lane
      restoring master's cache with a full match; each lane has `timeout-minutes: 30`.
- [x] PR runs write no cargo caches, and master holds one generation per Swatinem
      family (wave 14; checked after a day of PR traffic). Field, 2026-09-28T21:26Z,
      25 h after the merge: 20 PR runs, and no `v0-rust-*` entry on any PR ref. None
      of the janitor's 22 sweeps in that window deleted one as `pr-cargo`, so none was
      ever written, not merely swept. Each of the 12 master families held exactly one
      generation; the janitor had retired 7 superseded ones
- [x] A changed or added CI step's dependency builds reach its job's cargo cache on the
      next master run, without a cold run (wave 16). Field: the first master run after
      the salt lands saves a new generation for every salted job from a prefix restore
      (`full match: false`, not `No cache found`), and a later edit to one job's steps
      rotates that job's key alone. Both halves, 2026-10-01: master CI re-run 36819352918
      (attempt 2) restored all 11 salted lanes from the pre-salt generation and saved
      each salted one, once the budget let writes through; then PR #1805, which edits only
      the profiles job, rotated `ci-profiles` alone (`…-767ec95a` against master's
      `…-4829dd40`, a prefix restore), while every other salted job restored master's key
      with a full match (run 36907082419)
- [x] No silent-save/skip path remains (verify-after-publish on every save)
- [x] **No cache write depends on the Actions budget** (waves 21–22): the limit is the free 10
      GB, master's working set fits it with room for a family's rotation (≤ ~8.5 GB
      steady), and master runs save with no "Cache reservation failed" warning. Field,
      2026-10-11: the pool settled at **7.48 GiB**, the seven Linux lanes (7,325 MiB) plus apt
      and bun, with no superseded or PR-ref entries. That leaves ~2.5 GiB for a rotation of
      the largest family (`ci-unit`, 2.1 GiB). Saves land with no budget warning, and the six
      moved families republished from master to the `seed-cache` release (log)
- [ ] **First normal-delta `agent-v*` tag post-migration lands ≤10 min end-to-end** —
      **not met.** agent-v0.4.115 (2026-10-01, run 36937794461, the first tag after
      waves 18 and 19, whose agent code is 0.4.114's) took **14.9 min**: Windows MSI
      13.9, macOS `.pkg` 10.4, Linux x86_64 9.9, aarch64 7.4. Over the 12 tags 0.4.102–
      0.4.115 the MSI job ran 9.2–14.9 min and is the steady long pole. Of its 13.9 min,
      586 s were the final single-crate compile of `roomlerd` under `codegen-units=1`, which
      took 349 s on 0.4.114 for the same code: runner speed, not work. The remaining
      levers are the operator's (see Open decisions)

## Open decisions / residual levers (all trade-offs, not waste)

- The warm Windows floor is the per-release rebuild of every path crate under the
  size-optimized `cgu=1` profile, plus Azure signing steps. **Measured 2026-10-01, now
  that macOS and Linux are off the critical path (waves 18–19):** normal-delta tags still
  exceed 10 min (agent-v0.4.115, 14.9 min). The MSI job is the pole (9.2–14.9 min across
  12 tags), and most of it is `roomlerd`'s own compile. Three levers were proposed:
  relax `cgu=1`, decouple the per-release version bump, or pay for 8-core runners. The
  2026-10-06 probe (log) narrowed them to one:
  - **Decoupling the version bump cannot help.** The path crates rebuild because the
    checkout gives every source file a newer mtime than the seed's dep-info, not because
    of the version. A rehearsal on the SAME commit as its seed rebuilt all 19 of them, and
    cargo's fingerprint log names the cause for each: `StaleItem(ChangedFile { stale:
    <source>, … })`, at an identical 0.4.116.
  - **Bigger runners cannot help on their own.** Under `cgu=1` the compile runs on one
    core, so extra cores sit idle. The runner is an AMD EPYC 7763 with **2 physical cores
    (4 threads)**, and Defender real-time scanning is already off (exclusions `C:\`,
    `D:\`), so that is not a lever either.
  - **`codegen-units` for `roomlerd` alone is the one real lever, and it buys ~2 min:**
    roomlerd's lib + bin took 355 → 244 s (`cgu=4`, −31%) on one runner and 496 → 358 s
    (−28%) on another; `cgu=16` was no better than 4, and `opt-level=2` at `cgu=1` saved
    nothing. Its size cost on the shipped binary is not yet measured. The bin (`main.rs`)
    alone takes 100–230 s after the lib, much of it plausibly the lib's generics
    monomorphized again, since release builds don't share generics across crates. Moving
    `main.rs` into the lib is the structural candidate, unmeasured. Runner variance is
    ±40% on identical work.
- Runner-pool queue time is outside repo control (observed 35–70 min during bursts);
  rehearsal concurrency caps our own contribution. A self-hosted Windows runner is the
  reserve option.
- **Resolved 2026-09-28: the cache pool was at capacity on master alone** (wave 14
  finding). With PR-ref saves gone, master's own families add up to ~11.6 GB: the five
  Rust lanes 5.6 GB (vs the single 4.1 GB `ci-linux` they replaced, since shared deps
  now sit in several families), `ci-integration` 1.1 GB, and the rest ~0.4–0.8 GB each.
  The pool read 10.2 GB right after seeding, and the first victims were the small,
  early-saved entries: Windows clippy, recording-ffmpeg, the apt sets. The expectation
  that LRU would keep the lanes warm (every PR restores them) and push the churn onto
  rarer jobs did not hold: over the next day the lanes themselves were evicted (lint
  overnight, unit at midday, agent and both recorder lanes in the evening), and each
  eviction cost the next PR a cold lane (log, 2026-09-28). The operator raised the
  repo's limit to **20 GB** (paid; `PUT repos/{repo}/actions/cache/storage-limit`
  answered 402 until the account had a payment method). ⚠️ The limit alone was not
  enough: with the Actions budget at its default, the pool above the free 10 GB was
  read-only from 09-28 21:37Z until the operator set a $10 budget on 10-01 (log).
  **Reversed 2026-10-10 by wave 21: back to the free 10 GB, and master's working set cut
  to fit it.** The budget (by then $20) is the ACCOUNT's, and the private `lgr` repository's
  hosted minutes exhausted it on 10-07 (6,667 weighted minutes on October 1–9 against
  2,000 included; macOS 57% of it). The pool went read-only again on 2026-10-09 ("Cache
  reservation failed: You have reached your configured budget"), so every lane restored
  an ever-older generation, though roomler-ai's own share of the bill was ~1 GB of
  storage. A paid tier that another repository can switch off is not a design. Wave 21
  took the two cuts this paragraph once held in reserve, and **only one of them works**.
  - The plain recorder lane restores `recorder-audio`'s family and keeps none of its own
    (~600 MB). `cargo tree` resolves the two TEST graphs to identical features for every
    shared crate. The lane's non-test `cargo build` still rebuilds tokio and ~25
    dependents, in a variant without dev-dependency features that the audio lane never
    builds. That cost was within master's range (log).
  - ⚠ **Dropping the crate archives cannot work, and wave 21b removed it.** Every family
    does hold the whole lockfile's archives (179 MB, 1,186 packages, ≈2.1 GB across 12),
    but rust-cache's post step runs `cargo metadata --all-features` before it saves, and
    cargo needs a crate's `.crate` file even when the source is already unpacked. It
    downloaded all 183 MB again, silently (rust-cache captures the output), and saved
    them. The family sizes did not move (log). The old line, "deduplicating it is not
    the lever", was right, for this reason rather than its size.
  - Wave 21b: the integration lane builds with line tables instead of FULL debuginfo,
    which its 1.1 GB family still carried. Its `RUST_BACKTRACE=1` keeps file:line.
  - **Wave 22, the operator's choice (2026-10-11): keep the free tier permanently, by moving
    caches out of the pool rather than paying for a bigger one.** The ten hot `ci.yml`
    families alone came to ~9.3 GiB, so moving only the three rarely-run families
    (integration, both installer smokes) would still have left the pool at its limit. Six
    jobs moved: those three plus `ci.yml`'s macOS overlay check and two Windows lanes.
    They restore from and publish to the `seed-cache` release, like the release seeds.
    `ci-seed-save` prunes local packages' units with their fingerprints and skips an
    unchanged cache, as rust-cache does. The pool keeps the seven Linux lanes plus apt and
    bun, ~7.6 GiB, which leaves room for a full rotation.
- **Resolved by wave 16 (merged 09-29, field-verified 10-01): a new CI step's dependency builds
  stayed out of the cache until the next key rotation** (wave 15 finding; root cause 4
  open again). The salt below shipped as `.github/actions/cargo-cache-salt`, hashing
  the calling job's own definition rather than the whole of `ci.yml`, so an edit to
  one job rotates that job alone. Wave 10 meant a `ci.yml`
  edit to rotate the key, but rust-cache ignores `key` when `shared-key` is set, so the
  key moves only with a member `Cargo.toml`, a third-party `Cargo.lock` change or the
  toolchain. Master saw such a change on 11 of the 30 days to 09-28, with one gap of
  17.3 days (09-08 → 09-25). A step added inside such a gap recompiles its new
  dependency builds on every run until the gap ends, as `Run API unit tests` did on
  08-21 (+7 min per run). Levers: bump `prefix-key` by hand (one cold master run per
  lane), or salt the lockfile part of the key. rust-cache hashes every
  `.cargo/config.toml` under the workspace byte for byte (`src/config.ts`, v2.9.2), so
  a CI step that writes a comment-only one outside any directory cargo runs from,
  holding a hash of `ci.yml`'s non-comment lines, would rotate the key on a real
  workflow change and still restore the previous generation as a prefix match. That
  relies on a rust-cache implementation detail; if it changes, the salt is ignored and
  the lane behaves as it does today.
- **Resolved 2026-10-01 by wave 19 (#1806): the release Linux x86_64 job installed from the mirror** (found by wave 18's
  rehearsal). Its two raw `apt-get` steps cost 18 min on 10-01 from 17:38Z, the window
  in which the same Azure mirror also stalled PR #1804's profiles job (on the pre-wave-17
  step). The mirror had stalled the profiles job on 09-30 15:47Z too, so this recurs. A
  tag built in such a window misses the 10-min goal on this job alone. Lever: the CI
  lanes' answer, `cache-apt-pkgs-action` sets that the master rehearsal saves and tag
  builds restore. Cost: a second package list to keep in step.
- **The integration suite after wave 23 (2026-10-19): ~18–21 min, above the 10-min goal.**
  Measured levers, from the field log:
  - Every third-party crate at opt-level 2 in dev/test (`[profile.dev.package."*"]`): test
    time 1,725 s against 2,488 s with wave 23d's crypto list. It costs one ~12-min cold
    rebuild of every dependency in every dev-profile lane, slower cold local builds, and
    deps that a debugger steps through optimized.
  - More threads need fewer open files in mongod, not just more CPU: each test creates and
    drops ~246 WiredTiger files, and 4 threads exhausted the 64,000-descriptor ceiling. The
    options are a higher ceiling (the leaked-database check catches a real leak either
    way), sharding the suite across runners (each with its own mongod, but each also takes
    one of the account's 20 concurrent job slots, which were full on 10-19), or a pool of
    pre-indexed test databases emptied between tests instead of dropped and re-created
    (removes the churn and ~1 s of setup per test, at the price of a harness change every
    module's tests ride on).
  - The 43 tests over 10 s (16% of test time) wait out real windows (an unanswered start, a
    silent device, a throttle). Shorter windows under test settings would cut most of it;
    those belong to the FR-90 and FR-52 owners.

## Out of scope

- The tag-race double-runs during release bursts (release-cutting process: `ls-remote`
  before tagging).
- CI-lane cache sizing owned by other programs (`ci-integration`, `ci-ffmpeg-encoder`…) —
  the pool is theirs now; the janitor governs it.

## Field-verification log

- 2026-07-14: rc.181/182/183 at ~21 min vs rc.180's 69 (wave 1).
- 2026-07-23: rc.210 9m08s / rc.211 8m25s (waves 2–4 steady state).
- 2026-08-16: `Cache hit for restore-key: …lock-f9806b32…` — prefix generations working.
- 2026-08-26: all 10 assets live; Linux warm-from-assets 5.5 min, macOS 6.1 min; Windows
  warm restore verified (2.0 G target), execution 18.3 min on a dozen-PR delta.
- Next: first normal-delta tag → check the run's warnings (none expected) and total time.
- 2026-09-27: **PR CI regression found.** Runs 36331413828 (20.1 min, warm) and
  36339984289 (36.8 min, cold) computed the SAME key
  `v0-rust-ci-linux-Linux-x64-2b670344-977c0b24`; the first restored it with a full
  match at 15:58, the second got `No cache found` at 18:15. The pool read 15.0 GB
  against its 10 GB limit, 13.1 GB of it on `refs/pull/*/merge`: two concurrent PRs
  had each saved ~9–10 GB across eight job caches, and LRU evicted master's. On the
  warm run, test execution was ~3.5 of the 20 minutes; the rest was `roomlerd` and
  friends compiled in ~12 feature configurations, one after another. Wave 14 plan and
  numbers: #773.
- 2026-09-27: **Wave 14 (#1743) cold numbers.** Its own PR runs are cold by
  construction, since every lane is a new cache family and the new
  `CARGO_PROFILE_DEV_DEBUG` moves the env hash (the edit to `ci.yml` itself rotates
  nothing; see 2026-09-28): the `Rust checks` critical
  path fell from 36.8 to ~17 min cold and the whole CI from 36.9 to 18.2 min (run
  36345672545). Cold runner variance is ~30%: identical lint steps took 316 s and
  426 s on two runners. The first master run after the merge seeded every lane
  (36346857140, 21.8 min cold), and the janitor fired from its new `workflow_run`
  trigger 2 s after it finished. The pool then held one generation per family, all
  on master. A wrong turn, recorded: the first layout put the integration type-check
  in the unit lane, where it re-checked ~800 dependencies from scratch (369 s against
  31 s beside the clippy whose check-mode artifacts it reuses).
- 2026-09-27: **Wave 14 warm result** (#1745, run 36348497216, the first PR after the
  seeding). **Whole CI 6 min 21 s** (was 20+ warm, 36.8 cold). Lanes: lint 5.8, unit
  3.4, agent 4.3, recorder 4.7, recorder + audio 3.8 min. Each restored master's cache
  with a full match. Also Windows recorder 6.0 (was 7.3), macOS 3.0 (was 4.6), profiles
  1.6 min. The PR wrote no `v0-rust-*` cache. The pool read 10.2 GB: see the capacity
  item under Open decisions.
- 2026-09-28: **Wave 14 over a day** (every CI run from the merge to 21:05Z: 20 PR
  runs, 19 on master; timings are first attempts). PR runs: whole CI ≤10 min in 18 of
  20, median 7.3 min; `Rust checks` median 5.7 min. Five PR runs had a lane restore
  nothing, getting `No cache found` on a key master had saved hours earlier: lint at
  05:44, unit at 12:55 and 13:06, agent and both recorder lanes at 20:04 and 20:18. The
  two over 10 min were the big lanes cold (lint 17.7 min, unit 15.0 min); the smaller
  lanes stayed under 10 even cold. Cause: master's own families (~11.6 GB) against the
  10 GB limit; the janitor measured the pool at 9.6–11.7 GB before its sweeps. No PR
  run wrote a cargo cache (acceptance criteria). One PR run's first attempt failed in
  `ffmpeg-encoder` on a flaky test and passed on re-run; unrelated to caching.
- 2026-09-28: **Limit 10 → 20 GB** at 21:04Z by the operator (paid), read back as
  `{"max_cache_size_gb":20}`. Pool at 21:26Z: 10.6 GB in 24 entries, every family
  present except `ci-integration`, which its next master run re-saves. Still owed: a
  day of PR runs with no `No cache found` on a key master saved.
- 2026-09-28: **Correction: wave 10's `wf-` key never worked** (#773). rust-cache
  reads `key` only when `shared-key` is unset (`src/config.ts`, v2.9.2, the release
  `@v2` resolves to), and every lane's log shows the key it computed with no trace of
  the `wf-…` input. Field: #1728, #1735 (+95 lines) and #1736 each edited `ci.yml` on
  09-27, and each master run then restored `v0-rust-ci-linux-…-977c0b24` with a full
  match and saved nothing. The lockfile hash is narrower than its name: rust-cache
  blanks member versions and skips the workspace's own `Cargo.lock` entries, so four
  version bumps (0.4.108 → 0.4.113) kept `ci-lint`'s key, while #1741 and #1752 (a
  dependency each in `crates/api/Cargo.toml`) and #1744 (a feature in
  `agents/meshharbord/Cargo.toml`) each rotated it. #587 added its `key` beside an
  existing `shared-key: ci-linux`, so it was dead from the first run. The likeliest end
  of the 08-21 lockout is #590, which changed a member manifest 42 min after #587
  merged (an eviction and re-save would also have refreshed the entry). A
  wrong turn, recorded: the first correction on #773 cited #1744 as the proof that a
  `ci.yml` edit rotates nothing, but #1744 also changed a manifest and its key did
  rotate. The dead inputs are removed (wave 15), and the gap they were meant to close
  is an open decision again.
- 2026-09-29: **Wave 16, the salt, before the field run.** Mechanism: the lint lane's
  own log lists `crates/vendored/wintun-bindings/.cargo/config.toml` under "Lockfiles
  considered", so a nested `.cargo/config.toml` is hashed; one written under
  `ci-cache-salt/` sits where cargo never runs from. A prefix restore stays warm:
  rust-cache's pre-clean on a partial match drops at most one week-old entry per
  directory (`rmExcept` returns inside its loop). The action's real `run:` script,
  executed under GitHub's `bash --noprofile --norc -eo pipefail` against edited copies
  of `ci.yml`: all 11 jobs get distinct salts; a comment, blank-line or
  trailing-space edit, a workflow-level `env:` edit, a new job and a CRLF checkout
  rotate nothing; an edited step in `rust-recorder` rotates only `rust-recorder`; a
  step appended to `rust-unit`, or to `profiles` (the last job, which runs to EOF),
  rotates only that job. An unknown job id warns and salts the whole file; a missing
  workflow file warns and writes nothing. A wrong turn, recorded: the first "appended
  step" check targeted `profiles`, inserted before the next job and so changed
  nothing, and read as a salt failure until the check was made to prove its edit
  applied. The awk also reads to EOF instead of `exit`ing at the next job, because an
  early exit can SIGPIPE the upstream `tr`, which `pipefail` turns into a failed step.
  macOS `macos-mesh-test.yml` (manual dispatch only) is not salted.
- 2026-09-29: **Correction: the 20 GB raise made the cache read-only.** It was
  "verified" by reading the limit back, the wrong check. The pool was 10.58 GB, above
  the free 10 GB, and with the account's Actions budget at its default every save from
  then on logged `Cache reservation failed: You have reached your configured budget,
  your cache is now read only to prevent additional charges.` as a warning, inside a
  job that stayed green. Last successful saves 09-28 19:43 and 20:17Z; limit raised
  21:04Z; first refusal 21:37Z; then 20 of 20 save attempts across 78 master runs
  refused, including all 13 salted jobs of wave 16's merge run. The newest cache entry
  on any ref stayed at 09-28 20:24Z and the janitor logged the same 10576 MB pool on
  every sweep. Cost: `integration-tests` ran cold every time, 22.3–24.8 min against
  13–19 min before (its family was missing and could not be re-saved). PR lanes kept
  restoring the pre-salt generation and stayed near-warm (whole CI median 6.8 min over
  19 PR runs, 09-29 19:00Z to 09-30 22:00Z).
- 2026-09-30: **A mirror stall in the profiles job** (wave 17). `Build profiles`, ~2 min,
  took 9.3, 10.3 and 10.6 min in three runs between 15:47 and 16:20Z. Its step "Build
  deps for the SFU worker (collab)" ran a raw `apt-get install` against
  `azure.archive.ubuntu.com`: 113 s for the 28.8 MB `libclang-18-dev`, then 300 s for
  the 5 kB `libclang-dev` (run 36739413410). The Rust lanes take the same packages from
  `cache-apt-pkgs-action` and were unaffected. Fix: the job uses the lanes' composite.
  Its cached sets carry everything that step installed (`cmake`, `cmake-data`,
  `libclang-18-dev`, `libclang-dev`, `libjsoncpp25`, `librhash0`); `python3-pip` ships
  with the runner image ("already the newest version"). The composite costs ~21 s in a
  lane, against ~14 s for the raw step on a good day.
- 2026-10-01: **Budget $10 (the operator); saves resume, and wave 16 in the field.**
  Re-ran master CI at `0c3a74ed0` (run 36819352918, attempt 2, 7.8 min): all 11 salted
  `ci.yml` jobs restored the pre-salt generation (`full match: false`, none cold) and
  SAVED their salted one, every key the one PR #1784's run had computed, the first
  writes since 09-28 20:24Z. installer-smoke's Windows job (run 36899658523) did the
  same. The janitor's `workflow_run` sweep then retired all 11 superseded generations,
  freeing 9.5 GB; the pool had peaked at 20.0 GB, both generations side by side.
  A dispatched `integration-tests` (run 36899638438, 21 min cold) saved `ci-integration`
  (1.1 GB), missing since 09-28, and installer-smoke's macOS job (13.7 min cold) saved
  its first `macos-pkg-smoke` entry. Pool afterwards: 12.9 GB in 24 entries.
  A detector note: rust-cache v2.9.2 logs a successful save only as `Sent N of N
  (100.0%)`; there is no "Cache saved" line to grep for.
- 2026-10-01: **Wave 16's second field half, and wave 17 under a live stall.** PR #1805
  edits only the profiles job. Its run (36907082419, whole CI 8.5 min) rotated
  `ci-profiles` alone (`…-767ec95a` against master's `…-4829dd40`, a prefix restore);
  the other ten salted jobs restored master's key with a full match. Its cached apt step
  took 21 s and the job 2.0 min, where PR #1804's run 50 min earlier, on the old raw
  step, had spent 455 s in apt during the mirror stall described below.
- 2026-10-01: **Wave 18, pre-merge rehearsal** (run 36900740850, on the branch,
  artifacts-only). `Build .pkg (macOS arm64)` took 10.6 min, against 12.2 on
  agent-v0.4.114. Agent 478 s, then it waited 1 s for the companion (finished at
  17:44:29, before the agent build did), downloaded it in 1 s and checked it in 0 s;
  staging, codesign and notarisation ran unchanged. A tag skips the 53 s seed save, so
  about 9.7 min there. The new `Build desktop companion (macOS arm64)` took 6.6 min cold
  (342 s build, no seed family yet) and saved its first seed. The same rehearsal also
  showed two slow jobs this wave does not touch:
  - `Build .deb (Linux x86_64)` took 35.5 min, 18 of them in raw `apt-get` against the
    Azure Ubuntu mirror ("Install system build deps" 594 s, the companion's deps 512 s,
    against about 22 s each on 09-28). Its aarch64 sibling (`ports.ubuntu.com`) installed
    in 27 s.
  - `Build .msi (Windows x86_64)` took 22.7 min, its agent compile 1085 s against 408 s
    on the tag, building against seeds three days old. The rehearsal saved fresh ones.
- 2026-10-01: **Wave 19, pre-merge rehearsal** (run 36934413598, on the branch). The
  cached-apt step missed, as a first run must, and cached 146 packages (180 MB) under its
  own key. Its install spent ~8.5 min in the mirror, still stalling at 22:20Z; the
  caching itself took 9 s. The verify step passed in 0 s on the real 22.04 runner: every
  pkg-config module, the loader, cmake/patchelf and libclang, with no fallback warning
  emitted. On master (rehearsal 36936407900) the set missed again, because a branch's
  caches are invisible to master. It installed in 40 s, the mirror having recovered, and
  saved on master at 22:40:57Z.
- 2026-10-01: **agent-v0.4.115, the field test of waves 18 and 19** (run 36937794461,
  tagged 22:54:13Z on `426150261`, published 23:08:48Z). 14.9 min end to end: MSI 13.9
  (the pole), `.pkg` 10.4 (12.2 on 0.4.114, median 12.3 over the last 12 tags), Linux
  x86_64 9.9, aarch64 7.4, the companions 3.3 (macOS) and 6.1 (Windows).
  - Release: 28 assets, names identical to 0.4.114's apart from the version, each
    artifact with its `.asc` and `.sha256`, and no intermediate leaked.
    `/api/agent/latest-release` served 0.4.115 with both daemon `.deb`s before the
    companion's.
  - Lockstep: `setup-v0.4.115` published at 23:26:27Z on the same commit, and
    `/api/setup/{windows,linux,macos}` all serve 0.4.115 filenames.
  - zeus (Linux x86_64, systemd-supervised, checked first): `self-update --check-only`
    verified the `.deb`'s `.asc` against the pinned release key, and the real update
    installed and verified itself (`SucceededVerified`). A CLI-run self-update leaves
    the live daemon on the deleted inode, as `dpkg -i` does, so a `systemd-run`
    scheduled restart moved it to 0.4.115. The server recorded it at once, and the
    overlay came back on DERP, then re-upgraded to direct 2.3 min later.
  - The operator's MacBook, read-only: the `.pkg`'s checksum matched; it is Developer ID
    signed and notarised (`spctl`: accepted, source=Notarized Developer ID). The
    companion inside it, built by the new parallel job, is an arm64 Mach-O whose `.app`
    passes `codesign --verify --deep --strict` (team 4TG7586MY5) and links only system
    libraries.
  - Fleet uptake at 23:25Z: 1 of 8 online devices on 0.4.115 (zeus, updated by hand);
    the rest follow their updaters (~4 h, the Mac's helper ~6 h). 0.4.115 changes nothing
    a device runs, so uptake proves the artifacts, not a behaviour.
- 2026-10-06: **wave 20 rehearsal** (run 37538752420, `publish_release=false` on the
  branch). Every job green. `build-linux-companion` built cold in 7.4 min ("no
  seed-agent-linux-companion-Linux-X64 seed yet"), published its family (447 MB target +
  70 MB cargo), and restored the same apt entry as `build-linux`
  (`cache-apt-pkgs_c4273460…`) with no fallback. `build-linux` took 9.1 min including a
  69 s seed save that tag builds skip, so about 8.0 min on a tag, against 10.8 on
  agent-v0.4.116 and 10.2 on the master rehearsal before it (37237655417).
- 2026-10-06: **the codegen probe** (branch `ci/fr6-cgu-probe`, never merged, run
  37539178203). It restored the release lane's Windows seed read-only and rebuilt
  `roomlerd` once per variant on one machine, two machines in opposite orders. lib + bin
  seconds:

  | Variant | Runner A | Runner B |
  |---|---|---|
  | `cgu=1` (as released) | 355 (repeat: 354) | 496 |
  | `cgu=4` | 244 | 358 |
  | `cgu=16` | 258 | 384 |
  | `cgu=1`, `opt-level=2` | 369 | 502 (repeat: 502) |

  The bin alone took 100–230 s after the lib. Build 1 also logged cargo's fingerprint
  reasons: every path crate was `StaleItem(ChangedFile)` (checkout mtime newer than the
  seed's dep-info) at the seed's own version, which retires "decouple the version bump" as
  a lever. Runner facts: AMD EPYC 7763, 2 cores / 4 threads, Defender real-time
  protection off with `C:\` and `D:\` excluded. The first attempt (run 37537408392) built
  green in 10m35s and then died on its own `grep`: GitHub runs `bash -e -o pipefail`, and
  `dtolnay/rust-toolchain` sets `CARGO_TERM_COLOR=always`, so an anchored grep over the
  log matched nothing.
- 2026-10-09/10: **the paid cache tier went read-only again; wave 21.**
  - The pool was read-only: master CI run 37904595751's lint lane restored a stale
    generation (`full match: false`), then `Cache reservation failed: You have reached your
    configured budget, your cache is now read only to prevent additional charges`. The pool
    held 11.48 GB in 16 entries against the 20 GB limit.
  - The budget went elsewhere. roomler-ai's minutes are free (public repository), and its
    storage was ~1 GB over the free tier. The private `lgr` repository's hosted jobs on
    October 1–9, from the jobs API (the run-timing API's `billable` field now reads 0 for
    every run, private ones included, so it measures nothing): Linux 1,895 min, Windows 491,
    macOS 379. That is 6,667 weighted minutes against 2,000 included, macOS 57% of them, and
    one Linux release job hung for 361 minutes. lgr's own fixes are lgr#125, which made macOS
    and Windows on-demand, and lgr#126 (a self-hosted runner, and a 90 min cap on the
    release build).
  - Same day: the limit went back to 10 GB (`PUT …/actions/cache/storage-limit
    max_cache_size_gb=10`, read back as `{"max_cache_size_gb":10}`).
  - The family sizes the cuts were planned from (MB): unit 2148, lint 1585, agent 846,
    macos-pkg-smoke 813, profiles 796, macos-overlay 760, windows-recorder 728,
    recording-ffmpeg 693, ffmpeg-encoder 651, recorder-audio 594, recorder 573,
    windows-clippy 417, plus apt and bun 333. The crate archives in master's lockfile total
    179 MB (1,186 packages), and every family holds them.
  - rust-cache's `cleanRegistry` (v2) keeps the extracted sources of `-sys` crates. A
    re-extraction would bump directory mtimes that their build scripts watch. So the trim
    deletes only the `.crate` files and keeps the directories, which that cleanup scans.
  - `cargo tree -p meshharbord -e normal,build,dev --target x86_64-unknown-linux-gnu`: the plain
    recorder graph and the `+audio` graph differ in roomlerd itself and 7 audio-only crates
    (alsa, alsa-sys, audiopus, audiopus_sys, cmake, cpal, dasp_sample), and in nothing else.
    ⚠ That comparison covered the TEST graphs only. On the PR (run 38081437008) the plain
    lane restored `v0-rust-ci-recorder-audio-…` and still compiled 40 crates against
    master's 15. The extra 25 (tokio, hyper, reqwest, quinn, openssl, webrtc-dtls, …) are
    the variant its non-test `cargo build -p meshharbord` needs: resolver v2 unifies no
    dev-dependency features there, and the audio lane never builds it. The lane took 273 s
    against 221–295 s over master's last six runs, off the CI critical path. The trim logged
    `dropped 183 MB of .crate archives`.
  - The 10 GB limit alone already made saves land again. Master run 38080443848 saved
    `ci-recorder-audio` (`Sent 623761050 of 623761050 (100.0%)`), most families had fresh
    entries from 19:24–19:54Z, and no budget warning appeared. But LRU evicted
    `ci-unit` and `ci-lint` at once: two families absent from the 10-09 measurement
    (`ci-integration` 1,124 MB and `installer-smoke-windows` 594 MB) make the full working
    set ~13.4 GB, not 10.9. By that arithmetic wave 21's cuts leave ~10.4 GB, still over
    the limit. The next cut is sized from the first master run's measured families, not
    from this estimate.
- 2026-10-10: **wave 21's crate-archive trim was a no-op** (found on its first master run,
  38083571444; removed by wave 21b):
  - Every lane logged `dropped 183 MB of .crate archives`, and no family got smaller. The
    unit lane restored 2,252,680,759 B and saved 2,252,534,802 B (146 KB apart). lint,
    macOS overlay and recorder-audio were all within 0.1% of their sizes before the trim.
  - A re-run of that unit job restored the post-trim archive (`full match: true`).
    Cargo downloaded nothing, and the trim again found 183 MB of archives. They were in
    the saved archive.
  - The mechanism, reproduced in WSL with a throwaway `CARGO_HOME`: build a crate,
    delete its `.crate` (its source stays unpacked), run `cargo metadata --all-features`,
    and it prints `Downloaded itoa v1.0.18`. Cargo opens the archive before it checks the
    unpacked source. rust-cache's post step runs exactly that call before it saves, with
    the output captured, so the deleted archives come back unseen. The trim also cost
    every job that hidden re-download.
- 2026-10-11: **wave 22 validated on its own PR (#1954)**. A temporary clause let the PR
  branch publish, so the PR could prove the whole cycle before merging; it was removed
  before merge.
  - Run 1 (cold): every one of the six found no `ci-*` asset, built cold, pruned and
    published.

    | Job | Cold | Target (MB, pruned → kept) | Published (cargo + target) |
    |---|---|---|---|
    | integration | 25.2 min | 6,302 → 3,464 | 191 + 856 MB |
    | installer-smoke-windows | 18.2 | 1,715 → 1,501 | 196 + 416 |
    | windows-recorder | 13.3 | 3,204 → 2,278 | 191 + 591 |
    | macos-pkg-smoke | 11.5 | 2,437 → 1,998 | 191 + 595 |
    | windows-clippy | 11.4 | 2,703 → 2,108 | 191 + 555 |
    | macos-overlay-check | 11.0 | 3,720 → 3,038 | 190 + 844 |

  - Run 2 (`gh run rerun`, same commit): all six restored `same key`, logged `cache
    up-to-date`, and published nothing. Warm times: integration 12.3 min, Windows MSI 10.2,
    Windows recorder 6.4, macOS pkg 6.1, Windows clippy 5.2, macOS overlay 7.3. The
    cargo-installed `cargo-wix` came back from the cache: the WiX step took 68 s
    (compiling it) on run 1 and 11 s on run 2.
  - The macOS overlay check's restore cap went 4,000 → 6,000 MB, since its fresh target is
    already 3,038 MB.
  - A dry run in WSL caught one bug before any of this: without `zstd`, `tar` left 0-byte
    archives, and the first draft uploaded them over the good cache. `ci-seed-save` now
    refuses a failed pack.
- 2026-10-11: **wave 22 on master** (`b928d563b`, #1954).
  - The first master runs (CI 38096524857, integration-tests 38096524893, installer-smoke
    38096524865) restored each of the six from the `seed-cache` release. Each saw the key
    change, since removing the validation clause changed each job's definition, and
    republished under master's key (`cache published: ci-…`). Times: macOS overlay 7.3 min,
    macOS pkg 8.5, Windows clippy 6.7, Windows recorder 8.2, Windows MSI 12.2, integration
    13.3. The jobs' annotations held only GitHub's Node.js 20 notice and a macOS capacity
    notice, no cache warning.
  - The six families' old Actions-cache entries were deleted by hand (8 entries,
    ~6.4 GiB), along with the orphaned plain-recorder family. One more
    `installer-smoke-windows` entry appeared at 00:00:31Z, written by the last run on the
    old workflow (38095828862, `a91171f26`, started before the merge), and was deleted.
  - Settled pool: **7.48 GiB in 12 entries**, against the free 10 GiB.
- 2026-10-19: **"the tests got slow": two causes, wave 23 (#2544).**
  - **CI lanes cold.** PR run 39288740822: lint 22.5 min, unit tests 19.2, profiles 10.1,
    each with `No cache found`. The jobs that missed ran on runner image 20261018.339.1 and
    the ones that hit on 20261012.334.1. rust-cache's "Rust Versions" listed two toolchains,
    1.95.0 (ours) and the image's own `stable`, 1.99.0 on the old image and 1.99.1 on the
    new, so each family had two keys (`…-6a930126-…`, `…-013f3a70-…`). Each miss built cold
    and saved, and the janitor then deleted the other image's key as superseded: `ci-lint`
    at 16:38, 17:23 and 17:58 UTC. With wave 23a, every Linux job on both images lists only
    1.95.0 and computes one env hash, `0e351699` (PR run 39305294563). The salt step costs
    1–2 s.
  - **The integration suite**, run 39288740923: the build was warm (2.4 min), and the suite
    was 30.6 min. Its 819 tests in one binary at `--test-threads=2` took 1,494 s. On master
    the suite step had grown from a mean of 19.5 min on 10-14 to 27–29 min on 10-17..10-19
    (max 35.7). With `report_time` (839 tests including the hive binaries):

    | arm (dispatch run) | threads | Mongo data | test time | median | mongod fd peak |
    |---|---|---|---|---|---|
    | A, as is (39305102217) | 2 | disk | 3,772 s | 3.88 s | 19.4 k |
    | B (39305113225) | 2 | tmpfs | 3,281 s | 3.34 s | 28.2 k |
    | C (39305123577) | 4 | disk | 6,481 s | 7.27 s | 32.8 k |
    | D (39305139703) | 4 | tmpfs | 4,823 s | 5.20 s | 31.4 k |
    | crypto opt-level 3 (39312440997) | 2 | disk | 2,488 s | 2.48 s | 22.4 k |
    | all deps opt-level 2 (39312466654) | 2 | disk | 1,725 s | 1.57 s | 35.2 k |
    | crypto, 4 threads (39312454242) | 4 | tmpfs | **mongod died** | | 63.8 k |

  - Password hashing was most of it. `health_check_returns_ok` took 1.1 s, a register 2.1 s
    and a register + login 2.5 s: one unoptimized `Argon2::default()` op cost 0.5–0.9 s, and
    `seed_tenant` (612 call sites) does four. 547 of the 839 tests took 2–5 s. Optimizing
    the crypto crates alone took the extauth KE1 throttle test from 23.1 s to 3.9.
  - Doubling the threads nearly doubled each test's time (arm C): the suite is CPU-bound on
    a 4-vCPU runner, so threads were not the lever until the crypto was optimized.
  - ⚠️ **More threads against ONE mongod hit its descriptor ceiling.** Every test creates
    and drops a database of ~246 WiredTiger files, and the dropped ones stay open until
    mongod reaps them. At 2 threads the curve is a sawtooth (22 k peaks, cleared every
    4–6 min); with fast tests at 4 threads it climbed ~10 k a minute to 63,769 of 64,000,
    and mongod aborted. Each later test then waited out the driver's 30 s, and the job
    hit its 75-min limit. Faster tests mean more churn, so the 2-thread margin shrinks too
    (35 k with every dependency optimized).
  - The PR's CI run waited 20–64 min in the queue before its jobs started. The account's
    20 concurrent jobs were full (experiment runs, other sessions' PRs, a release), so
    sharding the suite across runners costs queue slots as well as minutes.
  - Not shipped: all third-party crates at opt-level 2 (test time −54% against −34%). It
    costs a ~12-min cold rebuild of every dependency in every dev-profile lane, and slower
    cold local builds. That trade-off is the operator's (see Open decisions).
- 2026-10-20: **wave 24, the suite as three shards** (the operator's choice of the levers
  above). Dispatch run 39386817512 on the branch, with wave 23 in it:
  - **12.0 min wall-clock** (was ~30). The suite listed 874 tests (35 more than the night
    before). The shards were handed 292, 291 and 291, and each passed exactly what it was
    handed.

    | shard | job | build | suite | test time | mongod fd peak |
    |---|---|---|---|---|---|
    | 1/3 | 9.6 min | 2.5 | 5.3 | 613 s | 34.3 k |
    | 2/3 | 11.5 min | 3.7 | 6.4 | 741 s | 25.2 k |
    | 3/3 | 11.7 min | 3.3 | 6.6 | 756 s | 23.0 k |

  - Each build restored the integration cache under a changed key (wave 23 had not reached
    master yet), so it recompiled the crypto crates on top of the warm target. Once
    master republishes, a warm build is ~2–2.5 min and a shard ~10 min.
  - The partition was dry-run first with two fake libtest binaries (103 tests): union ==
    listing, no duplicates, the skipped test excluded, a module's tests spread 8/8/9.
- 2026-10-20, evening: **the shards on master, and the queue** (wave 25).
  - ⚠️ The forecast above was wrong. Of the six master runs since wave 24 (f0bf3a958
    through d6235e5ee), five took **11.7–15.3 min wall-clock**. Their shards ran 9.6–12.9
    min: builds 1.9–3.8 min, suites 5.4–8.2. The sixth took 24.8 min: its shards queued
    3–7 min, and one shard's build ran 10.1 min. The build does not drop to ~2 min,
    because the cache holds third-party crates only and every shard rebuilds the workspace
    crates. The lane stays above the 10-min goal; the levers left are in Open decisions.
  - The queue mattered more than any job. CI and integration runs were grouped per commit,
    and ten FR-116 squash-merges queued ten full CI runs (170 jobs) against the account's
    20 concurrent slots. A session cancelled its own superseded runs by hand, and #2596's
    own CI took 58 min, most of it waiting for slots. Wave 25 groups master's runs by
    branch, so a burst queues one run while the running one finishes.
