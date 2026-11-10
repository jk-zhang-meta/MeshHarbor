# FR-24 — Licensing split: AGPL control plane, MPL everything the customer runs

**Issue:** [#838](https://github.com/jk-zhang-meta/MeshHarbor/issues/838) · **Status:** P1–P4a shipped, P3-CLA + P4b open · **Owner:** @gjovanov

## Goal

Replace the single root MIT licence with a per-component split that makes
commercial **re-hosting** of the control plane unattractive, while leaving every
binary a customer installs on their own machines free of copyleft that
procurement will refuse. Keep the source fully auditable — that is the only
trust substitute an unknown vendor has when asking people to run a privileged
daemon.

**Explicit non-goal:** protecting the differentiated code from being copied. No
OSI licence does that, and §"What AGPL actually buys" measures exactly how
little this split protects. It is chosen with that measurement in hand, not in
spite of it.

## Field evidence

Measured against `origin/master`, not assumed from the README.

### The contributor-consent gate is a no-op

```
$ git log --format='%aN <%aE>' | sort | uniq -c | sort -rn
   1289 gjovanov <goran.jovanov@gmail.com>
   1251 Goran Jovanov <goran.jovanov@gmail.com>
```

One human, two identity strings, one address. **Sole copyright holder ⇒ no
consent campaign, no consent log, no rewrite-their-surviving-lines fallback.**
An earlier strategy brief treated this as a blocking gate with its own document
set; all of it is deleted.

> **Re-measured 2026-09-06, after the identity rewrite.** This table used to
> carry a third row — the same human under a corporate mailbox, on 528 commits
> made through the GitHub web UI while that address was the account's commit
> email. Those commits were rewritten to the address above
> (`git filter-repo --mailmap`), so the row is gone rather than edited away:
> the tally is a live command's output and now reproduces.
>
> The conclusion it supports is unchanged, and was never in doubt — every
> identity here was always the same person. What changed is that a public repo
> no longer names an employer in 528 commit objects. The guards that stop it
> recurring are `.githooks/check-identity.sh` and
> `.claude/hooks/gh-account-guard.sh`; see the *sanitize-hostnames* skill's
> "The other kind of name" section for why content scanning could never have
> caught this one.

The MIT grant on published history stays irrevocable, and `LICENSE-MIT` retains
it verbatim. Anyone may fork the pre-split tree under MIT forever. That is
stated in `LICENSING.md` rather than worked around.

A CLA is still worth having — **prospectively**, before the first external
contribution, because that is the moment dual licensing would otherwise become
impossible again.

### Crate classification, from the dependency graph

| Class | Crates | Rust LOC |
|---|---|---|
| **SERVER** | `api`, `services`, `db`, `config`, `derp-relay`, `tests` | 54 157 |
| **SERVER (web)** | `ui/src` | 53 717 |
| **SHARED** | `tunnel-core` 55 593 · `remote_control` 12 883 · `localapi` 3 012 · `tcp-turn-conn` 518 | **72 006** |
| **CLIENT** | `meshharbord` 89 737 · `meshharbor-core` · `meshharbor-cli` · `meshharbor-setup` · `meshharbor-setup-core` · `meshharbor-desktop` · `meshharbor-cli-shim` | 110 911 |
| **THIRD-PARTY** | `crates/vendored/*` | untouched |

SHARED is measured, not guessed: `crates/api/Cargo.toml` deps
`meshharbor-remote-control` and `meshharbor-tunnel-core` unconditionally, with
19 live `tunnel_core::` call sites in `crates/api/src`.

### What AGPL actually buys — the finding that shaped this FR

The originating brief justified the split by saying MIT lets a competitor "lift
the encoder cascade and the mesh carrier logic." **Both land on the permissive
side of its own proposal:**

| Named asset | Lives in | Class | Licence here |
|---|---|---|---|
| Mesh carrier cascade | `crates/tunnel-core/src/overlay/` | SHARED | **MPL-2.0** |
| Encoder cascade | `agents/meshharbord/src/encode/` | CLIENT | **MPL-2.0** |

**AGPL therefore covers ~37% of first-party code and 0% of the code the split
was argued for.** What it covers is routes, DAOs, Mongo models and the Vue app.

That is not a reason to abandon it — it is a reason to state the purpose
honestly. AGPL's only trigger is **network distribution to third parties**, i.e.
hosting, which is the one competitive threat copyleft can block. And its real
commercial value is that **AGPL + a sellable exception is a revenue mechanism**:
the buyer is a procurement department reacting to the letters, not an engineer
reading the dependency graph. The cascades are defended by field-validation
velocity ("CI green ≠ done"), not by a licence file.

### Decision on SHARED: MPL-2.0

Chosen with the trade-off measured, not by default.

- Keeps `meshharbord` free of AGPL. An AGPL agent on a customer endpoint is a
  procurement blocker and is exactly what pushes MSPs toward paid proprietary
  alternatives; that adoption cost outweighs the marginal protection.
- MPL's file-level copyleft still returns improvements to *existing* `overlay/`
  files — the realistic threat (adapting the cascade) more than a clean-room
  rewrite.
- OSI-approved and SPDX-known. Packagers and enterprise legal accept it without
  argument.
- **Accepts:** a competitor may take `tunnel-core` and `meshharbord` into a
  proprietary product, owing back only changes to our files.

Rejected, recorded so they are not re-litigated:

- **AGPL + linking exception on SHARED** — maximum protection, but custom
  licence text (lawyer cost) and non-standard licences spook packagers. Held in
  reserve; the one-file swap in `scripts/licence-classes.sh` makes it cheap.
- **Shrink the shared surface first** — give `tunnel-core` a `server` feature
  the way `remote_control` already has one, so `api` deps only the server half,
  then AGPL that half. Best end state, real refactor; deliberately not a
  precondition.
- **Apache-2.0 on SHARED** — zero reciprocity on any differentiated code.
- **BUSL-1.1 / FSL** — strongest protection, but not OSI-approved, and open
  source *is* the distribution channel. Rejected on strategy, not on legals.

### Third-party obligations surfaced by the audit

Both pre-existing; neither is caused by this FR.

1. ⚠️ **Windows statically links LGPL FFmpeg** (`x64-windows-static-md`,
   `vendor-ffmpeg-windows.yml`), triggering LGPL-2.1 **§6**'s relink
   requirement. Nothing discharged it. Linux/macOS use `--enable-shared` and are
   clean under §6(b). *Contrary to the brief's fear:* neither vendor workflow
   passes `--enable-gpl` or `--enable-nonfree` — both are `--disable-everything`
   plus an explicit encoder allowlist, and CI already fails on an x264/x265 lib.
   **There is no GPL contamination.**
2. ⚠️ **openh264 is compiled from source** (`features = ["source"]`), so Cisco's
   binary patent grant — which attaches to Cisco's own prebuilt module — does
   **not** apply. The code licence (BSD-2-Clause) is fine; AVC pool exposure is
   a business risk, recorded in `THIRD-PARTY-NOTICES.md`.

### Legal entity

Copyright is **G ROX EOOD**, matching the imprint, privacy policy, terms and
landing footer shipped by FR-23. ⚠️ Not `G ROX LTD`: that is the **Windows
code-signing certificate subject only**, a fourth rendering of the same entity
that FR-23 explicitly left in place because changing it needs a new Azure
identity validation (current one valid to 2028-11-21). Using LTD for copyright
would add a fifth inconsistency pointing away from the register.

## Key design

### One place to change the licence

`scripts/licence-classes.sh` holds the SPDX identifiers, the path
classification, the crate lists and the copyright holder. `apply-spdx.sh`,
`licensing.yml` and the manifest audit all source it. Swapping AGPL for
FSL/BUSL later is one line plus a licence text file.

### The check that stops the split rotting

`licensing.yml` runs three checks; the third is the load-bearing one:

1. every workspace member declares an explicit `license` matching its class —
   ⚠️ read from `[package]` only, because `[package.metadata.wix]` also has a
   `license` key meaning something entirely different (it false-positived once
   during implementation);
2. every classified source file carries the right SPDX header
   (`apply-spdx.sh --check`);
3. **no SERVER crate appears in any shipped agent binary's dependency graph.**

(1) and (2) catch a forgotten file. (3) catches the change that would actually
falsify `LICENSING.md`'s MSP paragraph — and nothing else would, because the
violating edge is a one-line `Cargo.toml` change that compiles fine. Uses
`-e normal` so a dev-dependency edge, which cannot reach a shipped binary, is
not a false positive that trains people to disable the check.

### LGPL §6

The FFmpeg builds already publish to a **permanent GitHub Release**
(`vendored-ffmpeg-8.1.2`) with SHA-256 sidecars — but binaries only. An Actions
artifact expires in 90 days and cannot carry a three-year offer, which is why
the release, not the artifact, is the anchor.

`lgpl-source-offer.yml` publishes the **corresponding source** — the upstream
tarball archived by us (an upstream tag can move), every change our builds make
to it, and the complete build recipe — to that same release, and then asserts
the asset actually resolves. ⚠️ A written offer pointing at a missing asset claims
compliance we do not have, so the verification step is part of the job, not a
nicety.

⚠️ **"Resolves" was not "complete", and for four weeks nothing noticed** (P4c).
The bundle shipped the upstream tarball and the recipe only. The recipe
*referenced* `.github/ffmpeg-patches/` (our FR-62 patch, since 2026-09-02) and
the vcpkg port's own 14 patches without carrying either. Meanwhile this page, the
bundle's README and `THIRD-PARTY-NOTICES.md` all said "we apply no patches", and
`docs/lgpl-relink.md` said the recipe applied them. The asset check was green
throughout, because it asked "is there a file" and never "is it the source we
built from". The fix answers that at both ends. The bundle ships both patch sets
and publishes what it was built from as `…inputs.txt`, and `release-agent.yml`
refuses to tag while that file disagrees with the release's own checkout.

## Phases

| P | Scope | Status |
|---|---|---|
| **P1** | Licence files, `LICENSING.md`, `COMMERCIAL.md`, README | ✅ shipped |
| **P2** | `license` on all 17 manifests, `ui/package.json`, 625 SPDX headers, `REUSE.toml` | ✅ shipped |
| **P3** | `CONTRIBUTING.md`, `SECURITY.md`, `security.txt`, `docs/CLA.md` (Apache-ICLA-derived), disabled `cla.yml` | ✅ shipped; ⚠️ CLA still needs legal review before the bot is enabled |
| **P4a** | `THIRD-PARTY-NOTICES.md` + written offer + `lgpl-source-offer.yml` | ✅ shipped; workflow needs its first dispatch (blocked until this merges — `workflow_dispatch` only resolves on the default branch) |
| **P4b** | Close the §6 relink gap | ✅ **resolved by publication** — see below; `docs/lgpl-relink.md` |
| **P4c** | The offer carries every change the builds make: our patches + the vcpkg port at the recipe's baseline, an `inputs.txt` asset, and a `release-agent.yml` gate against the checkout | ✅ republished complete 2026-09-24 (run 36062315391) and verified on the served asset; the release gate fails before and passes after |
| **P5** | *(optional)* `server` feature on `tunnel-core` so AGPL reaches further | not planned |
| **P6** | OCI image labels on the runtime stage + build-args in the deploy recipe | ✅ shipped |
| **P7** | The split's own guard covers FR-69's modules: the manifest check walks the workspace `members` (it globbed one level deep and saw 18 of 24), and the server crate list gains `meshharbor-mod-remote`/`-network` (the AGPL-in-agent graph check could not see them) | ✅ 2026-09-25, proven fail-first (field log) |
| **Docs** | [`docs/licensing.md`](../licensing.md) plus index rows for it and `lgpl-relink.md`. ✅ 2026-09-25, **added retroactively**: this FR opened before docs-before-close, and closing it binds it | ✅ |

### P4b — the relink gap was smaller than it looked

The first pass assumed §6 obliged us to ship **object files**, and recorded
two structural fixes (shared FFmpeg on Windows, or a per-release object
archive). Re-reading the clause closed it without either.

§6(a) asks for the "work that uses the Library" **"as object code and/or
source code"**. MeshHarbor's agent is MPL-2.0, every crate it links is in this
repository, and the Windows build is a public `cargo build` that finds FFmpeg
through `pkg-config` — so a recipient can modify FFmpeg, rebuild, point
`PKG_CONFIG_PATH` at their tree and relink, using nothing we have not already
published. **Being open source discharges the half we thought we owed.**

`docs/lgpl-relink.md` makes that exercisable rather than merely arguable:
the exact per-platform feature lists, the `.pc` layout the build requires, and
`encoder-smoke --codec hevc` as the check that the relinked binary really uses
the new library. ⚠️ It also states plainly that a relinked binary is unsigned
and our updater will refuse it — a security control, not a §6 restriction.

Shared-FFmpeg-on-Windows is therefore no longer a compliance item. It remains
available as a simplification, but it would **add** to the install (the Linux
minimal shared tree is ~2.5 MB of libraries, against a measured 0.29 MiB true
closure for the ten HW encoders when statically linked), so it is not obviously
a win and needs measuring on its own merits, not as a legal necessity.

## Acceptance criteria

- [x] Every first-party source file carries a correct SPDX header (625 files)
- [x] Every workspace member declares `license` explicitly
- [x] **No SERVER crate reaches any shipped agent binary**, asserted in CI across all five
- [x] The graph assertion is **falsifiable** — verified to trip when a crate that *is* in `meshharbord`'s graph is classified SERVER
- [x] `LICENSING.md` answers the seven practical questions, MSP paragraph included
- [x] `LICENSING.md` states the AGPL coverage limit plainly rather than letting a reader discover it from the dep graph
- [x] Pre-split MIT history retained and its permanence stated
- [x] `SECURITY.md` + `/.well-known/security.txt` published and present in the built bundle
- [x] FFmpeg build flags documented; openh264 grant gap and HEVC exposure recorded
- [x] `cargo check` green on both lanes; `ui` build + 858 unit tests green
- [x] `cargo deny check licenses` passes in CI — three real findings triaged (WTFPL `tun`, MIT-0 `dcv-color-primitives`, and our own AGPL members, fixed with `publish = false` + `private.ignore` rather than allowlisting AGPL)
- [x] `lgpl-source-offer.yml` dispatched; corresponding-source asset live *(2026-09-24, run 36062315391: the **complete** bundle, with upstream + `patches/` + `vcpkg-port-ffmpeg/` at the recipe's baseline + the recipe, verified on the served asset; the release gate failed against the live release before this dispatch and passes after it. ⚠️ The 2026-08-29 and 2026-09-07 dispatches were live but incomplete: see P4c and the field log.)*
- [x] CLA rewritten on the Apache ICLA 2.0 skeleton; `cla.yml` present but `if: false`
- [ ] CLA reviewed by a lawyer and the bot enabled *(the only thing still gating P3)*
- [x] OCI `licenses` label set on the runtime stage, landing WITH this FR — plus title/description/url/source/documentation/vendor, and `VERSION`/`GIT_SHA` build-args wired into the deploy recipe
- [x] LGPL §6 relink right is **exercisable and documented** (`docs/lgpl-relink.md`), not merely offered by mail
- [x] **Docs updated/created with diagrams, linked from `docs/README.md`**: [`docs/licensing.md`](../licensing.md) (the classification, the four CI checks and how each is shaped, the FFmpeg LGPL obligations with the corresponding-source release gate), plus a new Licensing section in `docs/README.md` indexing it and `lgpl-relink.md`. ⚠️ **Added retroactively (2026-09-25)**: FR-24 opened before the docs-before-close rule (#1401), and closing it binds it. The autopilot board had parked this card as Ready to close with no docs criterion, and the close would have failed the verification-debt guard, as FR-22's did that same day.

### Known friction, accepted deliberately

Once this is on master, **any PR that adds a source file fails `Licence split
integrity` until its author runs `scripts/apply-spdx.sh`**. That is intended —
a file shipping with no licence header is a real defect, and the failure names
the one command that fixes it — but it is new friction on every contributor,
so it is recorded rather than discovered.

⚠️ It also means **master itself can go red** when a PR merges that was opened
before this landed. `pull_request` CI checks out the branch MERGED WITH master,
so such a PR is caught before merge; a PR merged in the window between its last
CI run and this landing is not. The fix is the same one command.

## Open decisions

1. **P4b**: shared FFmpeg on Windows vs. per-release object archive. Needs the
   installer-size delta measured before choosing.
2. ~~Whether to pursue an HEVC pool licence~~ — **decided 2026-09-01: HEVC stays
   ON by default.** Only vendor *hardware* encoders ship, so we distribute no
   HEVC implementation and the licence sits with the silicon vendor — the
   position RustDesk and the wider field take. Recorded with its three
   load-bearing conditions in `THIRD-PARTY-NOTICES.md`; ⚠️ adding any SOFTWARE
   HEVC encoder would invalidate it.

## Out of scope

- SOC 2 / ISO 27001 / pentest procurement.
- Any change to the free or self-hosted feature set. Nothing is removed from the
  community edition — that would invert the strategy this FR serves.
- Pricing and entitlements (separate program; see FR-20 for the metering that
  has to land before any tier reshape).
- Repo positioning and metadata — description, topics, OCI labels, social card.
  Verified stale and cheap to fix, but a distinct piece of work.

## Field-verification log

| date | what | result |
|---|---|---|
| 2026-08-27 | Dependency-graph classification of all 17 members | SHARED = 4 crates / 72 006 LOC; `api` deps `tunnel-core` unconditionally |
| 2026-08-27 | `git log` contributor census | 1 human ⇒ consent gate deleted |
| 2026-08-27 | FFmpeg vendor workflows audited for GPL flags | no `--enable-gpl`/`--enable-nonfree`; x264/x265 already CI-blocked |
| 2026-08-27 | FFmpeg link mode per platform | Windows `static-md` ⇒ §6 open; Linux/macOS shared ⇒ clean |
| 2026-08-28 | SPDX sweep applied, then re-run | 625 added; second run 0 added / 625 already correct ⇒ **idempotent** |
| 2026-08-28 | AGPL-in-agent graph check, all 5 shipped binaries | `none` for each |
| 2026-08-28 | Same check with `remote_control` forced into SERVER_CRATES | **tripped** ⇒ assertion is falsifiable, not vacuous |
| 2026-08-28 | `cargo check` agent crates (native) / server crates (WSL) | both clean |
| 2026-08-28 | `ui`: `vue-tsc` + `vite build` + `vitest` | green; 858/858 |
| 2026-08-28 | `dist/.well-known/security.txt` after build | present |
| 2026-08-28 | First CI run of `licensing.yml` | manifest audit ✓ · SPDX check ✓ · **AGPL-in-agent graph check ✓** · `cargo deny` ✗ |
| 2026-08-28 | `cargo deny` failure triaged | two real findings: our own AGPL members were checked as "dependencies", and `tun` 0.8.10 is **WTFPL** (unvetted). The invented `ring` clarify never matched and was removed. |
| 2026-08-29 | Re-read LGPL-2.1 §6(a) against the actual build | "object code **and/or source code**" ⇒ open-sourcing the agent already discharges the half we thought needed an object archive; P4b closed without shipping one |
| 2026-08-29 | `gh workflow run lgpl-source-offer.yml --ref fr24-licensing-split` | **HTTP 404** — `workflow_dispatch` resolves only on the default branch; the first run has to wait for the merge |
<!-- RETIRED-NAME-ANCHOR(2): the row below RECORDS the rename, so it must name both sides. -->
| 2026-08-29 | Merged master (FR-21 renames + FR-25/26/28/29) into the branch | `agents/meshharbor-agent`→`meshharbord`, `meshharbor-tunnel`→`meshharbor-cli`, `meshharbor-agent-tray`→`meshharbor-desktop`, `meshharbor-agent-core`→`meshharbor-core`; classification and crate lists repointed |
| 2026-08-29 | **The rename exposed a hole in the sweep** | an unclassified path was a silent `continue`, so a renamed directory would have dropped the whole daemon out of the sweep while `--check` still reported OK. Unclassified is now a hard failure; it immediately caught 10 real files (`ui/*.ts`, `ui/index.html`, `ui/public/*`) that `ui/src` never covered ⇒ SERVER_PATHS broadened to `ui` |
| 2026-08-29 | Post-merge re-verification | SPDX 647/647 · manifest audit exit 0 · graph check `none` × 5 · fmt clean · agent crates check · ui build + **898/898** vitest |
| 2026-08-29 | First dispatch of `lgpl-source-offer.yml`, from master (run 33255539777) | asset live and the assert step green. ⚠️ It already lacked the vcpkg port's patches, which the Windows build applied from the start (found 2026-09-24) |
| 2026-09-07 | Re-dispatched for FFmpeg 9.0.1 (FR-77 P0, run 34141875484) | asset live and green. ⚠️ It now also lacked #1249's patch, which both the Windows and the Linux builds had applied since 2026-09-02 |
| 2026-09-24 | `tar t` of the **served** bundle | **zero patch files.** Upstream tarball + two workflow files + a README that said "we apply no patches", as did `THIRD-PARTY-NOTICES.md` and this spec. `docs/lgpl-relink.md` said the recipe applied them; it only referenced them |
| 2026-09-24 | The new `release-agent.yml` gate, run from its own YAML text against a stub | matching offer passes · tampered offer **fails** · missing asset **fails** |
| 2026-09-24 | The same gate against the **live** release, before republishing | **fails**: no `inputs.txt`. The fail-first half |
| 2026-09-24 | Offer workflow run from its YAML in WSL, with one patch and with none | both pass. The no-patch run caught two bugs before they shipped: `sha256sum` with no arguments hashing STDIN into the manifest, and an `ls` pipeline killing the step under `pipefail` |
| 2026-09-24 | Republished from the PR branch (run 36062315391); the served asset re-downloaded | `sha256sum -c` OK · `patches/` = the patch + manifest · `vcpkg-port-ffmpeg/` = 21 files at `2e6b9238` · `inputs.txt` = patch + baseline |
| 2026-09-24 | The same gate against the live release, after | **passes**: `FR-24 gate OK: the LGPL offer carries 1 patch(es) + vcpkg baseline 2e6b9238` |
| 2026-09-27 | FR-85 P4c changes the vendored FFmpeg's **configure options** (the software `h264` decoder and the `aac` encoder), which live in the recipe, not in a patch | a gap: the gate compared patches and the vcpkg baseline only, so it would have **passed** the next release against an offer whose recipe described the old build. Closed: `inputs.txt` records the sha256 of both recipe files and the gate compares them (`recipe/vendor-ffmpeg-windows.yml`, `recipe/vendor-ffmpeg-macos.yml`) |
| 2026-09-27 | The extended gate, its comparison replayed locally against the live `inputs.txt` and against one written the new way (hashes over LF text, as a CI checkout reads it) | live offer (patch + baseline, no recipe lines) **refused**, the fail-first half · new-format offer **passes**. The offer is re-dispatched from master after the FR-85 P4c merge, before the next tag |
