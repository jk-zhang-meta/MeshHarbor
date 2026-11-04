# FR-73: The prod image is built by GitHub Actions, served from GHCR, and promoted by a dispatch

**Status**: **CLOSED 2026-09-06** (#1389 — every acceptance criterion met and field-verified; reopens
on evidence) — P0 claim (#1390) · P1 the build lane (#1391, first cold run
13 min 37 s build / 15 min merge → tag) · P3 `promote` (#1393) · P4 retention (#1395) · the e2e
lane follows the deploy repo's registry (#1396) · **P2 rolled 20:07Z and field-verified** (pulls
3.3 s / 2.7 s per node, 20 s from the deploy-repo push to both pods, fleet unchanged) · **P1b
merged and AC2 measured** (Rust change 6 min 49 s, UI-only 1 min 04 s, no change 10 s — both
targets met) · P1c merged (#1406 — daemon-only merges stop recompiling the server) · the break-glass path
rehearsed · retention dry-run-verified · docs merged · the `promote` credential path verified
2026-09-06 (#1416: the job runs in the `release` environment that holds `DEPLOY_REPO_TOKEN` and
proves write access with a dry-run push) · **AC4 done 2026-09-06 12:14Z — the first real promote:
`hosted-20260906-5aa3c43` (0.4.74) rolled by dispatch, both pods 33 s later, merge → pods
8 min 51 s, fleet verified** · **every acceptance criterion met** ·
**Owner**: deploy / build ·
**Issue**: [#1389](https://github.com/gjovanov/roomler-ai/issues/1389) ·
**Related**: FR-6 (build-speed SLO — this lane inherits its ≤10 min warm target as an aspiration, not a gate), FR-69 (the publish workflow this one copies its smoke from), FR-37 (the e2e lane, which pins by image tag and gains a second registry to pin from)

## Goal

Move the hosted (prod) image's build and storage off the build host and onto GitHub:

- **build**: a merge to `master` that touches the server, the SPA or the image recipe produces
  `ghcr.io/gjovanov/roomler-ai:hosted-<YYYYMMDD>-<sha7>` with no human step, smoke-booted and
  attested before it is pushed;
- **registry**: the cluster pulls that image from GHCR — the same public package the self-host
  images already live in — instead of the registry container on the build host;
- **promote**: a `workflow_dispatch` bumps the deploy repo's tag, and ArgoCD rolls as it does
  today. Deliberately **not** continuous deployment (D5).

What it replaces: the deploy recipe in `CLAUDE.md` — ssh to the build host, `docker build`
(5–15 min warm, competing with every other project's builds and the registry on the same box),
`docker push` to `registry.roomler.ai`, `docker system prune`, then a hand-edited `newTag` in the
deploy repo. The build host stays the k8s utility worker and keeps its registry for the other
projects; roomler-ai's image simply stops depending on it being healthy or idle.

## Why now

- Every FR of the last month rolled prod at least once, each roll a manual recipe run on a shared
  host. The 2026-07-12 incident (`/` at 100 % from stale build images mid-deploy) is the shape of
  the risk: the build path shares a disk with the registry that serves the cluster.
- The self-host publish workflow (FR-69 P8, `publish-selfhost-image.yml`) already builds this
  exact Dockerfile on Actions, smoke-boots it, pushes it to GHCR and attests it. The hosted lane
  is that workflow with `SAAS=1`, a different tag family and a trigger — not new machinery.
- Measured on Actions: a cold `full` build is **17 min 35 s** (FR-69 AC4). The expected band with
  a working cache is 8–12 min for a Rust change and ~2 min for a UI-only change; the current
  Dockerfile cannot reach either (D6), which is why this FR has a Dockerfile phase.

## Key design — every decision with its alternatives

**D1 — Registry: GHCR.** Alternative: keep `registry.roomler.ai` and have Actions push to it
(it is internet-reachable with basic auth + an acme cert). Pros of the alternative: the cluster's
pull stays LAN-fast. Cons: the registry is still the build host's disk and uptime; a push
credential for it becomes a GitHub secret; it is a second channel next to the GHCR package the
self-host images already use. **Chosen: GHCR** — `GITHUB_TOKEN` suffices (no new secret),
provenance attestation comes for free, and the pull cost is bounded (D8).

**D2 — One package, two tag families.** The hosted image lands in the existing public package
`ghcr.io/gjovanov/roomler-ai` as `hosted-<date>-<sha7>` plus a moving `hosted` pointer.
Alternative: a second package `roomler-ai-hosted`. Pros of two: no self-hoster can pull the
wrong thing by accident. Cons: a second visibility setting, a second retention job, a second
attestation subject. **Chosen: one package** — the tag prefix is the separation; `latest` stays
reserved for the self-host `full` image (the self-host workflow's rule), and the hosted lane
**never** writes `latest`. The hosted image carries the `saas` module (Stripe webhook, newsletter);
it holds no secret (configuration is environment), so its being public changes nothing the AGPL
source does not already disclose — but `docs/self-hosting.md` says plainly that `hosted-*` tags
are not for self-hosters.

**D3 — Visibility: public, as it already is.** Verified 2026-09-05: `ghcr.io/gjovanov/roomler-ai`
answers an anonymous `tags/list` with 200 (tags `latest`, `v0.4.43`, `v0.4.45`, per-arch). A new
tag in a public package is public. Consequence: **the cluster needs no pull secret** for GHCR;
`regcred` stays on the Deployment (harmless, used by nothing) until the build-host registry is
retired for this image. Alternative: a private package with a fine-grained read-only PAT in a
`ghcr-pull` secret — rejected as a rotating credential that buys nothing for public code.

**D4 — Trigger: every push to `master` that can change the image, plus dispatch.** Paths:
`crates/**`, `ui/**`, `Dockerfile`, `files/**`, `config/**`, `Cargo.toml`, `Cargo.lock`, the
workflow itself. `concurrency: hosted-image` with `cancel-in-progress` so a burst of merges builds
only the newest. Alternative: dispatch-only. Pros of dispatch-only: no runner minutes on merges
nobody will roll. Cons: the image is not there when someone wants to roll, which is the wait this
FR exists to remove. **Chosen: on merge** — the repository is public, so standard runners cost
nothing; the cache is registry-backed (D6) so a build that nobody rolls still warms the next one.

**D5 — Deploy: build always, promote by dispatch — not continuous deployment.** A roll replaces a
pod, and every long-lived socket on it re-homes: agents reconnect, RC sessions drop, tunnels and
DERP re-register. `master` takes 10–20 merges on a busy day; rolling each of them is 10–20 fleet
reconnect waves, and each roll is field-verified by hand today. **Chosen:** the build job runs
on every merge; a separate `promote` dispatch (input: the hosted tag, default = the newest) bumps
`newTag` in the deploy repo. Flipping to CD later is one `if:` on the promote job. The bump needs
write access to the private deploy repo: a fine-grained PAT scoped to `roomler-ai-deploy`
(contents: write) stored as `DEPLOY_REPO_TOKEN` — the one operator-created secret in this FR.
Until it exists the promote job prints the exact bump it would have made, and the bump is done by
hand from any machine with the deploy repo (as today, minus the build).

**D6 — Cache: registry-backed BuildKit cache, and a Dockerfile that can use it.** The self-host
workflow uses `type=gha` (10 GB per repo, LRU) scoped per arch and profile; a lane that runs on
every merge would evict the self-host scopes. **Chosen:** `type=registry` at
`ghcr.io/gjovanov/roomler-ai:buildcache-hosted` with `mode=max` — no cap, survives runner
churn, public like the package. And the honest part: the Dockerfile today does `COPY . .` before
`cargo build`, so **any** source change invalidates the Rust layer and the cache buys nothing but
the base image; a UI-only edit rebuilds the whole server. P1b restructures the builder stage:
a `cargo chef` plan/cook pair so the dependency graph (including the mediasoup C++ worker) is a
cached layer keyed by `Cargo.lock`, and the Rust stage copies only the Rust sources (`Cargo.*`,
`crates/`, `agents/`, plus whatever `include_str!`/`build.rs` reach — audited in P1b) so a UI-only
change never touches it. Alternative: `RUN --mount=type=cache` for `target/` — rejected because
cache mounts are not exported by `cache-to` and a fresh runner starts empty every time.

**D7 — Tag scheme: `hosted-<YYYYMMDD>-<sha7>`.** From the git sha, not the image id the build-host
recipe used (`v<date>-<12 hex of the image id>`), so a running pod's tag names its commit.
`VERSION` stays `git describe --tags --always` (needs `fetch-depth: 0`) and `GIT_SHA` the full
sha, both into the OCI labels the Dockerfile already declares.

**D8 — What gets slower, measured, not guessed.** The pull: each of the two high-performance
workers pulls the changed layers over the site's uplink instead of the LAN (~100 MB compressed
for a new binary layer; seconds when only the SPA layer changed). `RollingUpdate` is
`maxSurge 0 / maxUnavailable 1`, so the pull happens one pod at a time and lengthens the roll
without touching availability. AC3 records the per-node pull time from the pod events; if it is
ever the long pole, a registry mirror on the build host (`registry.roomler.ai` as a pull-through
cache of GHCR) is the lever — it keeps the build off the host and only caches the pull.

**D9 — Retention on GHCR.** The build-host registry had `registry-retention.sh` (2 tags per repo,
weekly); GHCR has nothing until someone adds it. A weekly job deletes untagged versions and keeps
the newest N `hosted-*` tags (N = 20, about a fortnight of rolls), never touching `latest`,
`v*`, `*-<profile>` or `buildcache-*`. Alternative: leave it — GHCR storage for public packages is
free, but an unbounded tag list makes `hosted` un-navigable and the e2e lane's pin-by-tag noisy.

**D10 — The build host keeps the break-glass path.** The `CLAUDE.md` recipe survives as the
fallback for a GitHub outage, marked as such; the registry container stays for the other
projects. Nothing on the host is torn down by this FR.

## Phases

| Phase | What | PR | Kill switch | Status |
|---|---|---|---|---|
| P0 | This spec, the ledger row, the issue | [#1390](https://github.com/gjovanov/roomler-ai/pull/1390) | — | ✅ merged `5a9f357a1` |
| P1 | `.github/workflows/hosted-image.yml`: build on merge / dispatch, registry cache, smoke (`/health` = all six modules incl. `saas`, device route 401, SPA served), push `hosted-<date>-<sha7>` + `hosted`, attest, a summary with the measured build time | [#1391](https://github.com/gjovanov/roomler-ai/pull/1391) | `gh workflow disable hosted-image` | ✅ merged `5ef003087` — its merge was the cold run: 13 min 37 s build, 15 min 01 s merge → tag (field log) |
| P1b | Dockerfile: `cargo chef` dependency layer + Rust stage copies only Rust sources; base image matches the pinned toolchain; measured against P1's numbers (cold, warm-no-change, warm-Rust-change, warm-UI-only) | [#1392](https://github.com/gjovanov/roomler-ai/pull/1392) | revert the Dockerfile PR — the workflow is indifferent to the layering | ✅ merged `3d2f31b23` after three dry runs (field log); measured: Rust change 6 min 49 s, UI-only 1 min 04 s |
| P1c | The builder's final section keeps the agents' skeletons instead of copying `agents/` — a daemon-only merge no longer recompiles the server | [#1406](https://github.com/gjovanov/roomler-ai/pull/1406) | revert | ✅ merged `fb6f43ad7` after its dry run (33991818028); its own hosted build (a Dockerfile change, so the final layers rebuilt) 6 min 36 s |
| P2 | The cluster pulls from GHCR: deploy repo `newName: ghcr.io/gjovanov/roomler-ai`, `newTag: hosted-…`; one roll, field-verified from the fleet; per-node pull time recorded | deploy repo `2efae23` | revert `newName`/`newTag` — the build-host registry still holds the previous tag | ✅ **rolled 2026-09-05 20:07Z**, field-verified (field log): pulls 3.3 s / 2.7 s per node, push → both pods 20 s |
| P3 | `promote` dispatch: bump `newTag` in the deploy repo with `DEPLOY_REPO_TOKEN`; prints the bump when the secret is absent; refuses while `newName` is not GHCR | [#1393](https://github.com/gjovanov/roomler-ai/pull/1393), [#1416](https://github.com/gjovanov/roomler-ai/pull/1416) | remove the secret | ✅ merged; runs in the `release` environment; credential path verified 2026-09-06 (run 34030450507) |
| P4 | GHCR retention job ([#1395](https://github.com/gjovanov/roomler-ai/pull/1395), fixed by [#1399](https://github.com/gjovanov/roomler-ai/pull/1399) after the first dry run: GHCR stores attestations UNTAGGED, so only BuildKit cache manifests may be deleted); `CLAUDE.md` deploy section rewritten (Actions path first, build-host path as break-glass, [#1398](https://github.com/gjovanov/roomler-ai/pull/1398)); `docs/self-hosting.md` on the `hosted-*` family ([#1396](https://github.com/gjovanov/roomler-ai/pull/1396)); **docs with diagrams**: the pipeline section of `docs/deployment.md` (the rule of CLAUDE.md § FR workflow step 5) | | — | ✅ retention merged + dry-run-verified; docs merged |

## Acceptance criteria

- [x] **AC1** A merge to `master` touching the server or the SPA produces
      `ghcr.io/gjovanov/roomler-ai:hosted-<date>-<sha7>` with no human step; the smoke inside the
      workflow asserts `/health` mounts `chat conference fleet network remote saas`, the device
      route answers 401, and `/` serves the SPA — before the push. — The merge of #1391 produced
      `hosted-20260905-5ef0030` (run 33988344500): smoke healthy in ~20 s, modules asserted, device
      route 401, `/` 200, then the push. Every later merge touching the paths has built (a burst is
      cancelled down to the newest commit by the concurrency group — run 33989978860 was cancelled by
      the P1b merge, by design).
- [x] **AC2** Build time on Actions recorded for four cases — cold; warm with no source change;
      warm after a Rust change; warm after a UI-only change — before and after P1b. Targets after
      P1b: Rust change ≤ 12 min, UI-only ≤ 4 min (the estimate this FR was opened against). —
      Recorded in the field log ("AC2: the four build cases"): cold 13 min 37 s (`COPY . .`) and
      17 min 42 s (chef, first export); warm Rust change **6 min 49 s**; warm UI-only **1 min 04 s**;
      the no-change floor **10 s**. Both targets met.
- [x] **AC3** Both prod pods run a `hosted-*` image pulled from GHCR; the per-node pull time is
      read from the pod events and recorded; the roll is field-verified from the fleet exactly as
      every roll (online-agent count unchanged, an RC session, an overlay pair, a tunnel forward).
      — P2, 2026-09-05 20:07Z: pulls 3.3 s / 2.7 s per node, 20 s push → both pods, fleet checks in
      the field log.
- [x] **AC4** A `promote` dispatch bumps the deploy repo and ArgoCD rolls; elapsed merge → pods on
      the new image recorded against the 10–15 min estimate. — **Done 2026-09-06 12:14Z**
      (field log: "AC4: the first real promote"): `hosted-20260906-5aa3c43` promoted by dispatch,
      both pods on it 33 s later, merge → pods **8 min 51 s**, fleet verified. The credential path
      had been verified first
      (2026-09-06, run 34030450507): the operator's `DEPLOY_REPO_TOKEN` lives on the `release`
      environment, the job runs in it (#1416), cloned the private deploy repo, and the server
      accepted a dry-run push (the write proof), then stopped at "already at
      `hosted-20260905-5ef0030` — nothing to do". Ticks at the first real promote — a deploy
      decision — when the bump, the roll and the elapsed are read.
- [x] **AC5** `latest` on GHCR still resolves to the self-host `full` image after the hosted lane
      has run; the hosted lane has no code path that writes it. — After the first hosted push,
      `latest`'s digest (`e19b3c72…`) differs from `hosted`'s (`386a25b8…`); the workflow tags only
      the dated tag and `hosted`.
- [x] **AC6** The hosted image carries a provenance attestation and
      `org.opencontainers.image.revision` equal to the commit it was built from. — The workflow
      asserts the label before the smoke (`revision=5ef0030875e1…` on the first run) and attests
      after the push; the attestation is on GHCR as the untagged manifest behind the
      `sha256-f0628ac8…` index (which is why AC7's job had to learn not to delete untagged versions).
- [x] **AC7** Retention: `hosted-*` tags are pruned automatically to the newest N; `latest`, `v*`,
      `*-<profile>` and `buildcache-*` are never touched (asserted in the job). — `ghcr-retention.yml`
      (#1395); its first dry run (33989558475) listed 12 versions, 0 `hosted-*` beyond the newest 20,
      and 3 untagged — one of them the hosted image's provenance, because GHCR stores attestations
      untagged behind a `sha256-<subject>` index. #1399 narrows the untagged prune to BuildKit cache
      manifests (each candidate's manifest is read back by digest); the protected-tag assertion is
      unchanged. The fixed job's dry run (33990772888) keeps all three — their manifests report
      `config.mediaType = application/vnd.oci.empty.v1+json`, the OCI artifact shape attestations
      use — "untagged: 3, of which cache manifests: 0". **Run live once on 2026-09-06 12:33Z** (run
      34033536786), after a day of builds: 45 versions, 22 untagged of which 12 were BuildKit
      cache manifests — one per build's cache export — **all 12 deleted**, the 10 attestations
      kept, 0 `hosted-*` pruned (7 dated, below the 20 kept). Scheduled Mondays 05:00 UTC.
- [x] **AC8** The break-glass path is documented and was exercised once after the switch (a
      build-host build pushed to the old registry, not deployed). — 2026-09-05 20:20–20:30Z: master
      `70a279d` built on the build host in 9 min 38 s (warm), pushed to the build host's registry in
      9 s (digest acknowledged in the push log), tag `bg-20260905-70a279d`, not deployed; the local
      tag removed. `CLAUDE.md` keeps the recipe under "Break-glass" with the `newName` rule.
- [ ] **AC9** Docs updated or created with diagrams, linked from `docs/README.md` (the rule of
      `CLAUDE.md` § FR workflow step 5). — the pipeline section of `docs/deployment.md` (flowchart:
      merge → build/smoke/push → GHCR → promote → deploy repo → ArgoCD → cluster → fleet
      verification), the image section's three-layer build, `docs/README.md`'s row.

## Open decisions

- N for retention (20 proposed).
- Whether the `promote` job should also wait for `/health` on the public URL and post the roll
  to the FR issue of the change being rolled — nice, not required.
- Whether the e2e nightly's pin should move to `hosted-*` tags (it pins "the current prod tag" by
  reading the deploy repo, so it follows automatically; the doc just needs to say so).

## Out of scope

Continuous deployment (D5 keeps the human on the trigger); multi-arch hosted images (the cluster
is amd64); moving the deploy repo or ArgoCD; the agent releases (they have their own workflows);
retiring the build-host registry for the other projects; a registry mirror on the build host
(named in D8 as the lever if the pull ever matters).

## Field-verification log

### 2026-09-05 — P1: the first hosted build, cold, on the merge that created the lane

The merge of #1391 (`5ef0030`) triggered the workflow's first run (33988344500) — cold by
construction: no `buildcache-hosted` existed yet, and the Dockerfile was still the
`COPY . .` one.

| step | wall clock |
|---|---|
| Build (the Docker build, including the first export of every layer to the registry cache) | **13 min 37 s** (817 s) |
| labels check + smoke boot (healthy in ~20 s, all six modules incl. `saas`, device route 401, `/` 200) | 24 s |
| push `hosted-20260905-5ef0030` + move `hosted` | 11 s |
| attestation | 4 s |
| **merge push → tag on GHCR** | **15 min 01 s** (19:50:59Z → 20:06:00Z) |

Image 80.96 MB compressed; `org.opencontainers.image.revision` = the merged commit (the
workflow asserts it); `latest` untouched — its digest (`e19b3c72…`) differs from `hosted`'s
(`386a25b8…`), and the workflow has no path that writes it (AC5, AC6). The 13 min 37 s cold is
below the 17 min 35 s FR-69 measured for the same Dockerfile on the same runner class: a
runner-to-runner spread, not a change — the number to beat is the band, not one sample.

### 2026-09-05 — P1b, three dry runs before the layering was right (the wrong turns)

Validated end to end by dispatching the self-host publish workflow in dry-run mode against the
branch (any branch can be built that way; a new workflow file cannot be dispatched until it is
on master). Three failures, each a fact about cargo-chef worth keeping:

1. `failed to read /app/crates/vendored/rtp/Cargo.toml` — cargo-chef skeletonises workspace
   members; the `[patch.crates-io]` path crates are resolved by cargo from their real manifests
   at cook time. They are dependencies, so `crates/vendored` is copied into the cook layer.
2. `cannot find TcpTurnConn in tcp_turn_conn` — the vendored `webrtc-ice` patch (a real crate
   during the cook) depends on the workspace member `crates/tcp-turn-conn`, which the skeleton
   had reduced to an empty `lib.rs`. A non-member dependency that uses a member's types cannot be
   cooked with that member skeletonised.
3. The fix: `cargo chef cook --no-build` writes the skeleton and stops; that one member is
   overlaid with its real sources; the dependency build is ours; then every member's artefacts
   are removed (`cargo clean --release -p` over `cargo metadata --no-deps`) — which is what
   `cook` does itself after building, because the real sources arrive by `COPY` with the build
   context's OLDER mtimes and cargo would otherwise keep the skeleton's empty artefacts as
   fresh. The smoke would have caught a server whose `main()` is `{}`, but only after a
   twenty-minute build.

Also found on the way: the base image was `rust:1.88` while `rust-toolchain.toml` pins
**1.95.0**, so every build had been downloading and installing a second toolchain inside the
uncached build layer. The base now matches the pin.

### 2026-09-05 — P2: the cluster pulls from GHCR — one roll, field-verified

Between the running image (`89ea3128`, the FR-69 roll of 08:49Z) and `hosted-20260905-5ef0030`
master had only workspace-version bumps and agent-side FR-70/FR-71 features — the least
eventful roll available, which is what a registry switch wants. The deploy repo's prod overlay
was set to `newName: ghcr.io/gjovanov/roomler-ai`, `newTag: hosted-20260905-5ef0030` and pushed
at **20:07:38Z**. No pull secret was added (`regcred` stays on the Deployment, unused).

| | |
|---|---|
| pods on the new image | both — started 20:07:41Z and 20:07:58Z; `rollout status` complete inside the minute |
| pull, per node (pod events) | **3.3 s** and **2.7 s** for the whole 80.96 MB image — nothing of it was cached on the nodes, the registry had changed |
| public `/health` | 200 throughout; `version 0.4.70`, all six modules mounted and compiled |
| `/` | 200 (the SPA) |
| fleet RPC | `roomler exec` to the cluster's build host through the new pods answered (`uptime`) |
| remote desktop | a session to a cluster node from this controller: `[WS] received: connected`, connect attempt 1, **ttff 633 ms**, `rc:video-info` vp9 4:4:4 on **transport direct**, clock echoes every second |
| tunnels | this box's seven declared routes all `active` afterwards |
| overlay | online peers unchanged (14 with a live carrier after vs 13–14 before; every device that was online stayed online); the direct pair to the build host survived (39 ms); the WAN peers behind NAT were on `relay:derp/tcp` before and after — from this box today the `srflx` tier is ineligible (`why.tiers`), unrelated to the roll — and re-registered on the restarted pods' DERP within seconds |

**What got slower: nothing measurable.** D8 budgeted 10–60 s per node for the pull over the site
uplink; the nodes took three seconds. Deploy-repo push → both pods on the new image: **20 s**.
The build-host registry keeps the previous tag, so the kill switch (revert `newName`/`newTag`)
stays a one-line commit.

### 2026-09-05 — AC2: the four build cases, before and after the layering

Every number is the workflow's **Build** step (the Docker build, including the registry-cache
import and export) on a standard `ubuntu-latest` runner, one sample each:

| case | Dockerfile | build | what ran |
|---|---|---|---|
| cold — the merge that created the lane | `COPY . .` (P1) | **13 min 37 s** | everything; merge push → tag on GHCR 15 min 01 s |
| cold — the first build with the new layers | chef (P1b) | **17 min 42 s** | everything, plus the first export of the chef/planner/cook layers to the cache |
| warm — a daemon-only change (`agents/meshharbord`, #1400) | chef | 6 min 36 s | the cook layer hit; `COPY agents` missed, the server's workspace recompiled for 313 s although nothing it links had moved → **P1c** |
| warm — a Rust-only change (one line in `crates/api`) | chef | **6 min 49 s** | the cook layer hit; the workspace recompiled (325 s) — the honest cost of a server change |
| warm — a UI-only change, first attempt | chef | 6 min 45 s | contaminated: the cache manifest holds ONE build's layers, and the previous build was the Rust-only tree, so `crates/` missed |
| warm — a UI-only change, cache matching | chef | **1 min 04 s** | every Rust layer hit; only the bun build and the runtime assembly ran |
| warm — no change (the same tree twice) | chef | **10 s** | the floor: cache import + export and the runtime assembly |
| warm — a Dockerfile change (the P1c merge) | chef + P1c | 6 min 36 s | the builder's final layers changed, so the workspace recompiled once; the next daemon-only merge is the case P1c exists for |

Against the estimate this FR was opened with (8–12 min for a Rust change, ~2 min for a UI-only
change): a Rust change lands at **6 min 49 s**, a UI-only change at **1 min 04 s** — both inside
the band, the UI case well inside it. Two things the measurements taught:

- **A "warm, no change" run on a shared `master` is not one.** Between the chef build and the
  first warm dispatch another session's daemon fix merged; the dispatched ref was `master`, so
  the tree had moved. Pin the SHA (dispatch a branch) for any measurement that claims "no change".
- **The registry cache is one build's layer set, not a union.** `cache-to` replaces the
  `buildcache-hosted` manifest every run, so a build can only reuse the *previous* build's
  layers. On `master`'s linear history that is exactly right (consecutive merges share most
  layers); interleaving dispatches from unrelated trees makes the next build pay for whatever the
  last one changed — which is what the first UI-only attempt measured.

**P1c** (#1406) follows from the daemon-only row: the builder's final section no longer copies
`agents/` — the cook's skeletons satisfy the workspace, and nothing in the agent crates is
compiled for the two server packages — so a daemon-only merge, the commonest kind on this
`master`, no longer touches a server layer at all.

### 2026-09-06 — AC4: the first real promote, field-verified

The operator asked for the latest hosted tag to be promoted and the roll verified. The latest
was still building (the 0.4.74 version bump, #1422, merged 12:05:58Z — its hosted build ran
6 min 50 s and tagged `hosted-20260906-5aa3c43` at 12:13:46Z), so the promote waited for it and
rolled the actual newest master. Between the running image (0.4.70, 2026-09-05 19:50Z) and this
one: version bumps 0.4.71–0.4.74, the FR-72 MagicDNS fixes (daemon-side code that the server
links but never executes) and the P1b/P1c Dockerfile — a low-risk roll for a first promote.

| | |
|---|---|
| `gh workflow run promote.yml -f tag=hosted-20260906-5aa3c43` | dispatched 12:14:16Z (run 34032507275); the job resolved the tag, proved write access, bumped `newTag` and pushed |
| pods on the new image | 12:14:32Z and 12:14:49Z — **33 s from the dispatch to both pods** |
| pull, per node | 2.9 s and 2.2 s for the whole 81 MB image |
| **merge → pods on the new image** | **8 min 51 s** (12:05:58Z → 12:14:49Z: 7 min 48 s of it the build and tag, 33 s the roll) — against the 10–15 min estimate this FR opened with |
| public `/health` | 200 on every sample through and after the roll, `version 0.4.74`, all six modules; the promote job's own ten-minute watch: **0 of 60 probes were not 200** |
| fleet RPC | `roomler exec` to the cluster's build host answered through the new pods |
| remote desktop | a session to a cluster node from this controller: connect attempt 1, **ttff 713 ms**, VP9 4:4:4 over the data channel on transport direct, first frame 1600 × 900 |
| tunnels | this box's seven declared routes all `active` afterwards |
| overlay | online peers unchanged (13 before, 13 after: 5 direct + 7 DERP + 1 `upgrading` at +5 min — the DERP pairs re-registered on the restarted pods and one pair was climbing back to direct, the make-before-break the carrier ladder is built for); the 7 offline rows were offline before |

**AC4 met.** The lane's promise — a merge becomes a running pod without a human touching the
build host — held on its first real use: the only human step was the dispatch, and the roll
took 33 s. ⚠️ One thing the day's history rewrite taught about D7: the running image's tag named
`5ef0030`, a commit that no longer exists on master after the sanitiser rewrote the history, so
"a pod's tag names its commit" does not survive a rewrite. The OCI `revision` label still
records what was built; compare deployments by the workflow runs and the registry, never by a
`git log <old>..master`, which explodes into the whole history.
