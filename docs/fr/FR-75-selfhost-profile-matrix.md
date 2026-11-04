# FR-75: Self-host **profile** install & verify matrix — every profile does the job it advertises

**Issue:** [#1447](https://github.com/jk-zhang-meta/MeshHarbor/issues/1447) ·
**Status:** proposed 2026-09-06 ·
**Handover this came from:** `docs/handover/modular-monolith.md`

## Goal

Boot a throwaway VM per **self-host profile** (`full`, `collab`, `remote`, `mesh`, `access`),
install it the way a self-hoster does — `docker-compose.selfhost.yml` + `.env.selfhost` +
`MESHHARBOR_IMAGE=<tag>-<profile>` — and then **make the profile do the thing it claims**: chat and a
real two-party video call for `collab`, remote-desktop frames for `remote`, a real overlay
`peers`+`ping` between **two** agents for `mesh`, both for `access`, everything for `full`. Assert
positively that what a profile drops is **absent**. End with a repeatable skill.

## Evidence (why this exists)

FR-69 shipped the modular monolith and proved **composition**. Nothing proves **function**:

| what is verified today | where | what it does NOT establish |
|---|---|---|
| every profile **compiles**, and `cargo tree` asserts the absences (no `mediasoup` in remote/mesh/access, no `meshharbor-tunnel-core` in collab) with a positive control on `full` | `.github/workflows/ci.yml` (`profiles` job) | that any of them **runs** |
| a published image **is** the profile it claims (`/health .modules` == `WANT_<profile>`), and `/api/tenant/…/device` answers 401 where fleet is mounted and 404 where it is not | `.github/workflows/publish-selfhost-image.yml` | that a mounted module can carry **traffic** |
| the documented self-host steps work verbatim from a clean clone | `scripts/selfhost-smoke.sh` (FR-42) | one host, one profile, no pillar exercised |

**The precedent that should end the argument:** the 2026-08-26 mediasoup RTC-range incident had
*flawless signalling* — join, transports, producers and consumers all green — and **zero media**,
for weeks, on a subset of tenants, with nothing logged. `connect_transport` succeeding records only
that the client sent its DTLS parameters. A `/health` line saying `conference` would have been true
and useless. The claim a profile makes is a **product claim**, and only traffic settles it.

The second reason is FR-61's own yield: its most valuable output was not the green matrix, it was
the **35 field defects** found by installing the product the way users do — including two that no
unit or CI check could see (a Free-plan device cap that 403s enrollment *silently*, and per-user
overlay not being netstack-configured out of the box).

## The matrix (v1)

One cell per profile. Each asserts, in order: **install** → **the server IS the profile** → **the
pillar works** → **what it drops is absent**.

| # | profile | image | must WORK | must be ABSENT | VMs |
|---|---|---|---|---|---|
| 1 | `full` | `<tag>` | chat · 2-party call · remote desktop · overlay peers+ping | — (positive control for every absence probe) | server + 2 agents |
| 2 | `collab` | `<tag>-collab` | chat between two browser contexts · a real video call, media both ways | fleet · remote · network | server only |
| 3 | `remote` | `<tag>-remote` | agent enrols · remote-desktop frames decode and advance | chat · conference · network | server + 1 agent |
| 4 | `mesh` | `<tag>-mesh` | **two** agents see each other in `mh peers`; `mh ping` round-trips | chat · conference · remote | server + 2 agents |
| 5 | `access` | `<tag>-access` | remote desktop **and** mesh on one server | chat · conference | server + 2 agents |

⚠️ **Absence is asserted positively.** A probe answering 404 is the claim; the **same probe on
`full` answering 401** is the control. A grep that matches nothing is not evidence — that is the
FR-46 lesson, where an audit died silently at the moment it succeeded.

## Key design

### Per-cell flow

```
audit host capacity → boot server VM (COW off the docker golden)
  → clone the repo, cp .env.selfhost.example .env.selfhost, fill 4 secrets,
    MESHHARBOR_IMAGE=ghcr.io/jk-zhang-meta/meshharbor:<tag>[-<profile>]
  → docker compose … pull && up -d          ← the documented order; `up` alone BUILDS
  → wait /health
  → GATE 1  /health .modules == WANT_<profile> AND /api/capabilities agrees
  → GATE 2  five module probes: 404 where dropped, 401 where mounted
  → register owner + create org via the public API (no seeded account exists)
  → per profile:
       collab/full : Playwright INSIDE the VM, two contexts, chat + a real call
       remote/access/full : boot 1 agent VM, enrol, RD spec against 127.0.0.1
       mesh/access/full   : boot 2 agent VMs, enrol both, peers + ping both ways
  → teardown: destroy every VM in the cell; nothing to clean server-side —
    the server WAS the VM
```

**The whole cell is its own universe.** Unlike FR-61 this matrix never touches prod: no prod org,
no ephemeral enrollment key, no anchor node, no reaper. Enrollment tokens are minted on the VM's
own server through its own API, and the database dies with the VM. FR-61's **prod-isolation** rails
therefore do not apply; its **guest** rails (DNS/apt readiness, `curl|bash`, ephemeral shutdown)
all do.

### Where the browser runs, and why it is not negotiable

**Inside the server VM**, in a Playwright container on `--network host`, against
`http://localhost:8080`. Three independent reasons, each already paid for by the prod e2e lane
(which solved it the same way, with the `pwrunner` sidecar inside the app pod):

1. **RTP does not survive a port-forward.** A forward carries one TCP port and no media.
2. **A LAN URL is not a secure context** ⇒ `navigator.mediaDevices` is `undefined` ⇒ no
   `getUserMedia` ⇒ no call to measure.
3. **`MESHHARBOR__APP__FRONTEND_URL` must equal the browser's origin** — *a port is part of an
   Origin* — or the cookie-authenticated `/ws` upgrade is refused **403**
   (`crates/api/src/ws/handler.rs`), and every realtime check fails for that one reason.

⚠️ That origin check is on the **cookie path only** (`handler.rs`: a query token is a credential
the caller had to obtain, and native clients send no `Origin` at all). Agents connect
`role=agent&token=…`, so the agent VMs reach the server at `http://<server-ip>:8080` while
`FRONTEND_URL` stays `http://localhost:8080`. The two are not in conflict, and this is what makes
a one-VM browser and multi-VM agents coexist.

### Media ports — the choice, recorded

Keep the compose file's **default port-mapped form** (`40000-40031` UDP+TCP published,
`MESHHARBOR_ANNOUNCED_IP=127.0.0.1`), not `network_mode: host`. Reasons:

- it is what a self-hoster gets out of the box, so the cell measures the **documented** path;
- with the browser on the VM itself, `127.0.0.1` is exactly the case the doc says it works for;
- `network_mode: host` would break the meshharbor container's `mongo:27017` / `redis:6379` /
  `minio:9000` service-name resolution, since host networking leaves the compose network — a
  change with its own failure mode, adopted for no gain here.

A separate cell may later flip to host networking with a LAN `ANNOUNCED_IP`; out of scope for v1,
recorded so the choice is not re-litigated by accident.

### The two gates, and the probes

`GET /health` and `GET /api/capabilities` are both unauthenticated.
`capabilities` returns `{version, modules, compiled, switched_off}` where `modules` is what this
server **mounts** and `compiled` is what the build **linked**
(`crates/api/src/routes/capabilities.rs`).

| module | probe (unauthenticated GET) | mounted | dropped |
|---|---|---|---|
| `chat` | `/api/tenant/{tid}/room` | 401 | 404 |
| `conference` | `/api/tenant/{tid}/room/{rid}/call/participant` | 401 | 404 |
| `fleet` | `/api/tenant/{tid}/agent` | 401 | 404 |
| `remote` | `/api/turn/credentials` | 401 | 404 |
| `network` | `/api/tenant/{tid}/tunnel-client` | 401 | 404 |

Every path verified against `crates/tests/fixtures/composition.baseline.json`. Expected sets:
`full` = chat conference fleet network remote · `collab` = chat conference · `remote` = fleet
remote · `mesh` = fleet network · `access` = fleet network remote — the same table the publish
smoke asserts, so a disagreement between the two is itself a finding.

⚠️ A dropped module must answer **404, never 500**: 404 is "no such route", 500 would mean a route
mounted onto absent state.

### What each repo owns

| repo | contribution |
|---|---|
| `meshharbor` (public) | this spec + the ledger row; a `profile` e2e spec pair (`selfhost-collab.spec.ts` for chat+call, reusing `vmtest-remote.spec.ts` verbatim for RD) |
| `meshharbor-deploy` (private) | `profiletest/` — orchestrator, per-profile cell scripts, guest drivers, report |
| `k8s-cluster-multi` (private) | nothing new: FR-61's `vmtest-host` role and `vmtest-net` already provide libvirt, the network and the capacity audit |
| local, gitignored | the `profiletest` skill (P10) — it names fleet hosts |

**`profiletest/` is a sibling of `vmtest/`, not a lane inside it.** The cell shape genuinely
diverges — cells are per-profile rather than lane/method/type, a cell owns **several** VMs, and
there is no prod org to isolate — and folding it into `vmtest.sh`'s `default_cells` would make a
bare `vmtest.sh run` execute both matrices. It **sources `vmtest/lib.sh`** so the host abstraction,
guest SSH, `vm_ip`, the audit and the verdict shape are shared rather than copied. Decided once,
here, per the handover.

### The facts the design rests on (anchors verified against master, 2026-09-06)

- **Profiles** are Cargo feature aggregates in `crates/api/Cargo.toml`; `default = ["profile-full",
  "saas"]` is the hosted build, and no published `v*` image carries `saas`.
- **Compose**: `docker-compose.selfhost.yml` publishes `${MESHHARBOR_HTTP_PORT:-8080}:80` plus
  `40000-40031` UDP+TCP; `MESHHARBOR__APP__FRONTEND_URL` = `${MESHHARBOR_PUBLIC_URL:-http://localhost:8080}`;
  `MESHHARBOR__AUTH__AUTO_VERIFY` defaults **true**, so a registered account is usable with no SMTP.
- ⚠️ **`up -d` alone BUILDS** — Compose treats a service with a `build:` section as buildable, so a
  missing image is compiled from source instead of pulled. `pull` first, or the cell measures a
  20-minute build and calls it an install.
- ⚠️ **Mongo/MinIO passwords must be alphanumeric** — the Mongo one is interpolated into a
  connection URL, and `@ : / ? #` break it in a way that reads as an authentication failure.
- **No seeded account and no admin bootstrap**: the cell registers through the public API and
  creates the org as a second step, exactly as the docs say a human must.
- ⚠️ **A new org lands on the Free plan, which caps devices at 3** and then **403s** further
  enrollments silently (`crates/db/src/models/tenant.rs`). Two agents fit; a cell that ever needs
  more raises the plan on **that VM's** database.
- **`/api/setup/install.sh`** is served by the server under test (embedded at compile time), so the
  agent VMs install from the same box they enrol into.

### Safety rails

- **zeus only** by default — mars is the orchestrator, and **jupiter hosts the prod storage node**
  (refused unless `VMTEST_ALLOW_JUPITER=1`, announced window only).
- **Sequential cells**, one cell's VMs at a time; the FR-61 capacity audit (`vmtest-audit`) gates
  every cell and a shortfall is a refusal, not a shrink.
- **No prod contact of any kind.** The only external fetches are the GHCR image, the Ubuntu
  archive and GitHub release assets.
- **`--keep` for debugging**, and a teardown that runs from an `EXIT` trap so a crashed cell still
  destroys its VMs.

## Phases

| # | phase | kill switch / status |
|---|---|---|
| P0 | claim the FR (spec + ledger row, one commit) + issue | — |
| P1 | `profiletest/` skeleton on FR-61's host capability | run nothing; harness only |
| P2 | server golden: Ubuntu + docker + compose v2 preinstalled | `bake --lane server` |
| P3 | the two gates: `/health .modules`, `/api/capabilities`, the five probes | cheapest, runs first; a cell failing here boots no browser |
| P4 | `collab` — chat between two contexts + a real call, media both ways | `--profile collab` |
| P5 | `remote` — enrol an agent, reuse `vmtest-remote.spec.ts` | `--profile remote` |
| P6 | `mesh` — two agents, `peers` + `ping` both ways | `--profile mesh` |
| P7 | `access` — P5 + P6 on one server, chat/conference absent | `--profile access` |
| P8 | `full` — P4 + P5 + P6, and the absence control | `--profile full` |
| P9 | **run and tweak** — the largest phase | `expected-failures.txt` |
| P10 | the skill (local, gitignored) | — |
| P11 | report: matrix, evidence, fail-first record | — |

⚠️ **Expect the harness to be wrong more often than the product.** Across FR-61's re-runs, four
consecutive failing rounds were *all* harness faults — oracle blindness to a DataChannel transport,
a static desktop that is pixel-identical frame to frame, guest DNS/apt races, Playwright version
drift — and **zero** were product regressions. Confirm every apparent regression against a
screenshot or a log before reporting it as one.

## Acceptance criteria

- [x] **AC1** each of the five profiles installs on a clean VM by the documented self-host path —
      all five from published self-host images (`v0.4.81` + `v0.4.81-{collab,remote,mesh,access}`).
- [x] **AC2** `/api/capabilities` matches the profile exactly (`modules` == expected,
      `switched_off` empty) for all five, and agrees with `/health`.
- [x] **AC3** `collab`: two browsers exchange chat **and** complete a call with decoded, advancing
      frames on **both** sides.
- [x] **AC4** `remote`: a freshly enrolled agent streams decoded, advancing frames to a browser.
- [x] **AC5** `mesh`: two agents see each other in `peers` and `ping` round-trips both ways.
- [x] **AC6** `access`: AC4 **and** AC5 on one server, with chat/conference absent.
- [x] **AC7** `full`: AC3 + AC4 + AC5.
- [x] **AC8** every absence asserted positively, with the 401 control on `full`.
- [x] **AC9** teardown destroys every VM; a run is repeatable back-to-back.
- [x] **AC10** fail-first evidence recorded for at least one check per profile.
- [x] **AC11** the whole matrix runs from one command, documented in the skill.
- [x] **AC12** docs updated — a `docs/self-hosting.md` note on what the matrix proves, and a row in
      `docs/README.md` (the standing close-requires-docs rule).

## Open decisions

1. **Which image tag?** v1 pins `latest` + `latest-<profile>` (the published self-host family).
   Pinning a `v*` tag makes a run reproducible but stops it from catching a regression the day it
   publishes. Recorded either way in the run's report.
2. **Does `mesh` prove a tunnel or `mh ssh` too?** `peers`+`ping` is the hard gate for v1; a
   `mh ssh` probe is a cheap add once two agents are up, and is listed as a stretch check
   rather than an AC.
3. **A LAN-`ANNOUNCED_IP` cell** (browser off-box, host networking) is deliberately deferred — it
   tests the *operator's* network, not the profile.

## Out of scope

Windows/macOS **servers** (the self-host stack is Linux + docker); k8s deployment of profiles (the
prod overlay's job); the `saas`/billing add-on (hosted-only, never in a self-host image);
performance and scale (this is a *functional* matrix); upgrade/migration **between** profiles; and
`VITE_MODULES` bundle pruning (an optimisation — the runtime answer is the gate, FR-69 P9).

## Field-verification log

Every entry records what **failed first**, per the standing rule that a check which never failed
first has not been shown to work.

### 2026-09-06 — bring-up, `full` cell on zeus

Harness: `meshharbor-deploy/profiletest/` (sibling of `vmtest/`), server golden
`ubuntu-docker-noble.qcow2`, agents on FR-61's `ubuntu-gui-noble.qcow2`.

**Findings against the product / the docs**

| # | finding | evidence |
|---|---|---|
| 1 | **The four non-`full` profile images have never been published.** `ghcr.io/jk-zhang-meta/meshharbor:latest-collab` does not resolve, and no `-remote`/`-mesh`/`-access` tag exists on any tag family. `publish-selfhost-image.yml` is dispatch-only with `profile` defaulting to `full`, and has only ever been dispatched that way | first cell, at the cheapest gate, before a browser booted |
| 2 | **The one image that does exist predates the feature it is documented around.** `latest` = `v0.4.45` (2026-09-01); `/api/capabilities` + `/health .modules` landed 2026-09-04 (`4f8296fa7`, FR-69 P8). `merge-base --is-ancestor` says false. The workspace is at 0.4.76 — 31 versions ahead | `/health` → `{"status":"ok","version":"0.4.45"}` with no `.modules`; `/api/capabilities` → **404** |
| 3 | **Enrollment refuses plaintext off-loopback, and `docs/self-hosting.md` does not say so.** `normalize_server_url` upgrades `http://`→`https://` for any non-loopback host; loopback is exempt. So "Add your first machine" cannot work until the *later*, optional-looking "Putting it behind a real hostname" section has been done, and the error names nothing | `meshharbord enroll` → `POST https://…:8080/api/agent/enroll` → `SSL routines:ssl3_get_record:wrong version number` |

Findings 1 and 2 are reported, not fixed: publishing puts a public package under the operator's
account and is theirs to decide by the workflow's own design. The matrix therefore runs against a
**`hosted-*` tag** as a current-code stand-in, with `saas` expected *present* and every verdict
labelled so nobody mistakes it for a self-host image.

**Harness faults (the majority, as predicted)**

1. `curl -fsS … || echo '{}'` collapsed *"404, no such route"* into *"the field is missing"* — two
   causes with different fixes, one message. Read the **status**.
2. `--tag` was reverted in the child: `lib.sh` sources `~/profiletest/.env`, whose assignments are
   unconditional, so an exported `PT_TAG` is clobbered the moment `cell.sh` re-sources it. The run
   used `latest` **while looking perfectly healthy**. The tag now travels as an argument.
3. `install.sh` needs `--server` **even with `--no-enroll`** — it resolves the release through
   `$SERVER/api/agent/latest-release`, whose baked-in default named the agent's own loopback.
4. `$?` inside `if ! cmd; then … "$?" …; fi` is the **negation's** status, always 0 — a genuinely
   failed install reported `rc=0`. Same family as the standing "never branch on a piped exit
   status" rule.
5. `/api` is rate-limited **per client IP** (1 req/s, burst 60) and everything in a cell comes from
   `127.0.0.1`: the SPA logged `/api/capabilities unavailable … API error 429` and the call test
   timed out with nothing wrong on the server. The settings doc-comment already says the prod e2e
   overlay bumps this for exactly this reason.
6. `CI=1` makes `playwright.config` retry twice, so a **timeout** costs 3× — 18 minutes to prove
   the same 429 three times.
7. Tenant membership is not **room** membership: the `/ws` fan-out targets room members, so the
   peer saw nothing and the realtime assertion read as a broken socket.
8. **The daemon's two TLS stacks disagree.** Enrollment is reqwest/**native-tls (OpenSSL)**; the
   signalling WebSocket is tokio-tungstenite/**rustls**. A self-signed cert that is its own CA is
   accepted by the first and refused by the second
   (`invalid peer certificate: CaUsedAsEndEntity`) — so the agent enrolled perfectly, retried its
   socket forever, and the only visible verdict was *"no overlay self address within 120s"*, a
   symptom three layers below its cause. Fixed with a real CA → leaf chain; an overlay timeout now
   quotes the daemon's own last words.

**Green so far** (`hosted-20260906-5aa3c43`, version 0.4.74), reproduced across runs:

```
install       PASS  compose pull + up, documented path; /health and / both answer
capabilities  PASS  modules='chat conference fleet network remote saas', switched_off empty, /health agrees
saas          PASS  billing present, as a hosted-* image must be
probe/chat        PASS  401 (mounted)      probe/conference  PASS  401 (mounted)
probe/fleet       PASS  401 (mounted)      probe/remote      PASS  401 (mounted)
probe/network     PASS  401 (mounted)
register      PASS  owner registered + org created through the public API
tls           PASS  lab TLS front (CA → leaf, IP SAN)
collab        PASS  chat over /ws AND a 2-party call with advancing decoded frames on BOTH sides
agent1/install PASS  agent2/install PASS   (served install.sh, release resolved through the cell's own server)
agent1/enroll  PASS  agent2/enroll  PASS
```

`collab` is the headline: the first time a MeshHarbor call has been asserted end-to-end with a media
oracle that **can fail** — `conference-multi.spec.ts` swallows its tile assertion by design, which
is the same shape as the incident this FR cites.

### 2026-09-07 — all five cells, on the published images

Finding 1 was fixed at the operator's direction: `publish-selfhost-image.yml` was dispatched four
times against `master` (`tag=v0.4.76`, `also_latest=false`, `arm64=true`), and all four succeeded —
so `v0.4.76-collab`, `-remote`, `-mesh` and `-access` now exist as amd64+arm64 manifest lists.
`latest` was deliberately **not** moved.

| cell | image | result |
|---|---|---|
| `full` | `hosted-20260906-5aa3c43` (current-code stand-in) | **19 PASS / 0 FAIL** |
| `collab` | `v0.4.76-collab` | **10 PASS / 0 FAIL / 2 NA** |
| `remote` | `v0.4.76-remote` | 13 PASS / **1 FAIL** / 2 NA — see Finding 4 |
| `mesh` | `v0.4.76-mesh` | **18 PASS / 0 FAIL / 1 NA** |
| `access` | `v0.4.76-access` | **19 PASS / 0 FAIL** |

**85 checks, 79 PASS, 5 NA, 1 understood failure.** Teardown left no VM on zeus after any cell.

The absence half of AC8 landed here, and it is worth showing in full — the same five probes, three
different answers, each matching the profile's claim:

```
                chat   conference   fleet   remote   network
collab           401       401       404     404      404
remote           404       404       401     401      404
mesh             404       404       401     404      401
access           404       404       401     401      401
full             401       401       401     401      401     ← the control
```

⚠️ **`full` is still not proven from a self-host image.** `latest` remains `v0.4.45`, so the `full`
cell runs against a `hosted-*` tag, which is the same composition **plus** billing. One more
dispatch (`profile=full`, `tag=v0.4.76`) would close it.

⚠️ The published binaries report **`version=0.4.79`** under the tag `v0.4.76`: the workflow's `tag`
is an operator-chosen image label, while the version comes from `Cargo.toml` at build time, and
master moved between the decision and the build. Harmless, but a reader comparing the two will
notice.

**Finding 4 — the SPA fetches what the profile does not mount.** On `remote`, the devices page
fired `/tenant/{id}/tunnel-client` three times and `/tenant/{id}/overlay-node` once at a server
that correctly drops both: four 404s and four console errors per visit. The server was right; the
client was asking for doors it had already decided not to draw — `AgentsSection.vue` gated its
**template** on `caps.has('network')` but not its **data loads**. FR-69 P9's rule is that the SPA
gates on `/api/capabilities`, and that has to cover what it *fetches*, not only what it *renders*.
It is the same family as the P7b lesson in `docs/modular-monolith.md`, where every `remote` image
404'd its own devices page and a `/health`-only smoke could not see it.

Fixed in `8cd350ab2`. ⚠️ The fix lives in the **SPA bundle**, which is baked into the image, so
`v0.4.76-remote` still carries the old one and the check stays in `expected-failures.txt` — with
the fix named and the condition for deleting the entry — until the next self-host publish.

**One more harness fault**, found in the same run: `mesh-profile.spec.ts` demanded a *Tunnels* tile
and a *Network* nav group unconditionally, which fails on `remote` for doing exactly the right
thing. Three profiles mount no chat and the spec is meaningful on all of them; only the
network-owned surfaces are conditional. Fixed in `c3613debd`.

### 2026-09-07 (second half) — clean sweep on `v0.4.81`, both open items closed

```
2026-09-07T15:56:30Z PASS pass=80 fail=0 warn=0 na=5 total=85
image=ghcr.io/jk-zhang-meta/meshharbor:v0.4.81   run=20260907-141658
```

| cell | image | result |
|---|---|---|
| `collab` | `v0.4.81-collab` | 10 PASS / 0 FAIL / 2 NA |
| `remote` | `v0.4.81-remote` | 14 PASS / 0 FAIL / 2 NA |
| `mesh` | `v0.4.81-mesh` | 18 PASS / 0 FAIL / 1 NA |
| `access` | `v0.4.81-access` | 19 PASS / 0 FAIL |
| `full` | `v0.4.81` | 19 PASS / 0 FAIL |

No VM left on zeus; the five `NA`s are the by-design ones.

**Finding 2 closed.** `v0.4.81` was published with `also_latest=true`, so `latest` and `v0.4.81`
resolve to the same digest and the `full` cell no longer needs a `hosted-*` stand-in. The workspace
was bumped to `0.4.81` first, so every image reports the number on its own tag — the `v0.4.76`
family reported `0.4.79`, which was harmless but read as a discrepancy.

**Finding 4 closed — and the first fix was only HALF of it.** `8cd350ab2` gated `AgentsSection`'s
loads, which killed the `overlay-node` fetch and *two of the three* `tunnel-client` ones. The third
came from the org dashboard, which guarded it on **`showFleet`** — and `fleet` is a different
module, so a `remote` profile (fleet yes, network no) fired it anyway. A per-caller gate leaks the
moment one caller reaches for the wrong predicate; `05280ce91` (#1466) moves the guard **into the
two stores**, where there is no predicate for a caller to get wrong. `has()` is fail-open until the
server answers, so both guards are inert before first paint and in unit tests (1209 pass unchanged).

⚠️ The lesson worth keeping: **the partial fix passed review and read as complete.** Only running
the matrix against the published image showed it was not. That is the whole argument for this FR in
one paragraph.

**The absence matrix, from the final run** — five profiles, one probe set, each row matching that
profile's claim:

```
                chat   conference   fleet   remote   network
collab           401       401       404     404      404
remote           404       404       401     401      404
mesh             404       404       401     404      401
access           404       404       401     401      401
full             401       401       401     401      401     ← the control
```

`expected-failures.txt` is empty again and issue-filing is back on, so the next unexpected red
opens an issue by itself.
