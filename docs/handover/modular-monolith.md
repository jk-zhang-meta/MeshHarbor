# Handover — the self-host **profile** install & verify matrix

**For a fresh session.** Task: open an FR, build a harness that boots **throwaway VMs**,
installs **each self-host profile** (`full`, `collab`, `remote`, `mesh`, `access`) the way a
self-hoster does, and **proves the pillar each profile claims actually works** — chat + video
calls for `collab`, remote desktop for `remote`, the overlay mesh for `mesh`, both for
`access`. Then package it as a repeatable **skill**, run it, and report the results.

> Not to be confused with **`docs/modular-monolith.md`** — that is the FR-69 *design* (how the
> server is composed). This handover is about *proving the composition works* once installed.
> Model the FR spec on `docs/fr/FR-61-vmtest-matrix.md`, which did the same job for the agent
> install matrix and is the harness you will reuse.

---

## 1. Read these first, in this order

1. `docs/self-hosting.md` — **the install path under test**: the profile table (§"Choose a
   profile"), `.env.selfhost`, `docker-compose.selfhost.yml`, and the media-port note near the
   end (`network_mode: host` vs a `ports:` block).
2. `docs/modular-monolith.md` + `docs/fr/FR-69-modular-monolith.md` — what a profile *is*.
3. `docs/fr/FR-61-vmtest-matrix.md` — the VM harness, its cell/verdict shape, and its field log.
4. The **`vmtest` skill** (local, gitignored — it carries fleet specifics). It is the working
   system you are extending; read its *Traps* section before writing any code.
5. `CLAUDE.md` → "Functional Requirements (FR) workflow" — the claim rules (§P0 below).

---

## 2. What already EXISTS — do not rebuild it

Verified against master on 2026-09-06 (`file:line` anchors — re-check before relying on them):

| Thing | Where | What it already proves |
|---|---|---|
| The five profiles | `crates/api/Cargo.toml:30-36` — `profile-full = [chat, conference, fleet, remote, network]`, `collab = [chat, conference]`, `remote = [fleet, remote]`, `mesh = [fleet, network]`, `access = [fleet, remote, network]` | the composition exists as feature aggregates |
| Local profile checks | [local profile checks](../local-build.md#toolchain-and-checks) | every reduced profile **compiles**, and `cargo tree` asserts the **absences** (no `mediasoup` in remote/mesh/access, no `meshharbor-tunnel-core` in collab) with a positive control on `full` |
| Profile images | [local image recipe](../local-build.md#images-and-historical-recipes) | local packaging preserves `<tag>-<profile>` (bare `<tag>` for full), passes `PROFILE` as a build arg, and a **boot smoke** asserts the image *is* the profile it claims (`WANT_full='chat conference fleet network remote'`) |
| `GET /api/capabilities` | `crates/api/src/routes/capabilities.rs` | **unauthenticated**; returns `{version, modules, compiled, switched_off}`. `modules` = what this server mounts, `compiled` = what the build linked |
| Clean-clone install smoke | `scripts/selfhost-smoke.sh` (FR-42) | the documented self-host steps work **verbatim** from a clean clone — on one host, one profile |
| The VM harness | FR-61: `k8s-cluster-multi` playbook 15 (`vmtest-host`), goldens on zeus, `meshharbor-deploy/vmtest/` orchestrator | boots throwaway VMs, installs, enrolls, checks RD/overlay/desktop, tears down, reports |

## 3. The gap this FR closes

**Composition is proven; function is not.** Today a profile is verified by *what it links* and
*what string it advertises*. Nothing installs a profile the way a self-hoster does and then asks
it to do its job:

- a `collab` image is never asked to carry a **real video call**;
- a `mesh` image is never asked to carry a **real overlay ping between two agents**;
- an `access` image is never asked to do **both** while **refusing** chat;
- and no profile is ever installed on a **clean machine from the published image**.

That gap has a precedent that should end the argument: the 2026-08-26 mediasoup RTC-range
incident had *flawless signalling* — join, transports, producers, consumers all green — and
**zero media**, for weeks, on a subset of tenants, with nothing logged. A capabilities string
saying `conference` would have been true and useless. The claim a profile makes is a **product
claim**, and only traffic can settle it.

## 4. The matrix

One **cell per profile**. Each cell asserts, in order: the documented install works → the server
*is* the profile → the pillar **works** → what the profile drops is **absent**.

| profile | image | must WORK | must be ABSENT |
|---|---|---|---|
| `full` | `<tag>` | chat + 2-party call, remote desktop, overlay peers+ping | — |
| `collab` | `<tag>-collab` | chat + a real 2-party **video call** (media both ways) | fleet / remote-desktop / overlay endpoints |
| `remote` | `<tag>-remote` | agent enrolls + **remote desktop frames** | conference; overlay mesh |
| `mesh` | `<tag>-mesh` | **two agents** see each other in `mh peers`, `mh ping` round-trips; a tunnel or `mh ssh` succeeds | conference; remote desktop |
| `access` | `<tag>-access` | remote desktop **and** mesh, on one server | chat / conference |

⚠️ **Absence must be asserted positively** and with a **positive control** on `full` — a grep
that matches nothing is not evidence (the FR-46 lesson: an audit died silently at the moment it
succeeded). A dropped module should answer 404/501, never 500.

## 5. Per-cell topology — the part that will cost you time

A cell is **not** one VM. It is a **server VM** plus one or two **client VMs** on the same
`vmtest-net`:

```
server VM   docker + compose, .env.selfhost, MESHHARBOR_IMAGE=<tag>-<profile>
  ├─ collab      : 2 browser contexts   (no agent needed)
  ├─ remote      : 1 agent VM + browser
  ├─ mesh        : 2 agent VMs          (peer ↔ peer is the point; one agent proves nothing)
  ├─ access      : 1–2 agent VMs + browser
  └─ full        : all of the above
```

**A crucial simplification over FR-61:** this matrix **never touches prod**. Each self-hosted
server is its own universe with its own database, so there is no prod org, no ephemeral key from
prod, and no anchor node — agents enrol into *the VM's own server*, and the whole cell is
destroyed afterwards. (FR-61's prod-isolation rails do not apply; its **guest** rails do.)

⚠️ The self-hosted server's own tenant plan still applies: **Free caps devices at 3**
(`crates/db/src/models/tenant.rs`). Two agents fit; if a cell ever needs more, raise the plan on
that VM's database, not on prod.

## 6. Traps that WILL bite — every one already paid for

**Media / browser placement** (this is where the days go):

1. **RTP does not survive a port-forward.** A forward carries one TCP port and *no media*. The
   browser must have a real route to the address the server announces.
2. **A LAN URL is not a secure context** ⇒ `navigator.mediaDevices` is `undefined` ⇒ no
   `getUserMedia`, no call. Only `https://` or `http://127.0.0.1|localhost` qualify.
3. **`MESHHARBOR__APP__FRONTEND_URL` must EQUAL the browser's origin** — *a port is part of an
   Origin* — or the cookie-authenticated `/ws` upgrade is refused **403** and every realtime
   check fails for that one reason.
   ⇒ **Therefore: run the browser INSIDE the server VM against `http://127.0.0.1`.** That is
   exactly how the prod e2e lane solved it (the `pwrunner` sidecar inside the app pod), and for
   the same three reasons. Do not try to drive the call from mars.
4. The **RD frame oracle** is already correct — **reuse `ui/e2e/vmtest-remote.spec.ts`**, do not
   write a new one. It learned two lessons the hard way: RTP counters are **blind** to the
   VP9-4:4:4 DataChannel transport a SW-encode agent negotiates (`getStats` and the RTP stats ref
   both read 0 while the stream is perfect — #1297), and a **static desktop is pixel-identical**
   frame to frame, so a pixel-change proof fails a healthy stream (#1301). Prefer the viewer's
   own fps readout. **Before believing any RD "regression", open the failure screenshot.**

**Guest boot races** — reuse `vmtest/guest/linux-lane.sh`'s readiness block verbatim:

5. **DNS is not up when SSH is.** Resolve the server *and* `github.com` *and*
   `objects.githubusercontent.com` (installers fetch release assets from GitHub).
6. **`unattended-upgrades` holds the dpkg lock.** Waiting for the lock to be *free* is racy by
   construction — stop/disable the `apt-daily` timers and mask the service, then pass
   `-o DPkg::Lock::Timeout=300`.
7. **`curl … | bash` reports BASH's status** — a failed fetch reads as success. Fetch to a file,
   assert non-empty, then run.

**Harness hygiene:**

8. **Playwright version drift** kills every browser cell at once (`Executable doesn't exist at
   /ms-playwright/chromium_headless_shell-…`): `ui/package.json` pins a **caret** range, so
   `npm i` resolves past the image's baked browsers. Derive the version from the **image tag**.
9. **The mars `meshharbor` clone drifts** (history rewrites leave it thousands of commits
   diverged) — `git rev-list --left-right --count HEAD...origin/master`, reset before a run.
10. **A parallel session may be running vmtest** on the same host — check `tmux ls` *and*
    `virsh list`; identify a run dir by set-difference, never `ls -t | head -1`.
11. **An ephemeral agent unenrols itself on SIGTERM** — stop → enrol → **one** clean start;
    never `restart`.
12. **Media ports**: calls need the RTC range reachable. `docs/self-hosting.md` offers
    `network_mode: host` vs a `ports:` block — pick one deliberately and record which, because a
    call that signals perfectly and carries nothing is the exact failure this FR exists to catch.

## 7. Phases

- **P0 — claim the FR.** Add the spec `docs/fr/FR-N-<slug>.md` **and** the ledger row in
  `docs/fr/README.md` **in the same commit** (git arbitrates collisions; do *not* pick a number
  by scanning). The highest spec on 2026-09-06 was **FR-74**, so FR-75 is *likely* free — re-read
  the ledger at claim time and trust it, not this sentence. Then open the GitHub issue.
- **P1 — host capability.** Reuse FR-61's `vmtest-host`; add a `selfhost`/`profile` lane
  directory in `meshharbor-deploy/vmtest/` (or a sibling `profiletest/` if the cell shape
  diverges too far — decide once, in the spec).
- **P2 — server golden.** An Ubuntu golden with docker + compose preinstalled, so a cell measures
  *meshharbor's* install, not apt's.
- **P3 — the capabilities gate.** Cheapest, runs first: `GET /api/capabilities` must equal the
  profile's expected module set exactly (`modules` == expected, `switched_off` empty). A cell
  that fails here need not boot a browser.
- **P4 — `collab`**: chat between two browser contexts **and** a real call with media asserted on
  both sides.
- **P5 — `remote`**: enrol an agent against the VM's server, then the existing RD spec.
- **P6 — `mesh`**: two agents, `mh peers` + `mh ping` round-trip, plus a tunnel or
  `mh ssh` probe.
- **P7 — `access`**: P5 + P6 on one server, and chat/conference proven **absent**.
- **P8 — `full`**: P4 + P5 + P6.
- **P9 — RUN AND TWEAK.** The largest phase. Expect the *harness* to be wrong more often than the
  product: across FR-61's re-runs, four consecutive failures were all harness faults (oracle
  blindness, static-desktop liveness, guest DNS/apt races, Playwright drift) and **zero** were
  product regressions. Confirm every apparent regression against a screenshot or a log before
  reporting it as one.
- **P10 — the skill.** Mirror the `vmtest` skill: triggers, invocation, per-cell assertions,
  safety rails, and a Traps section carrying everything §6 lists plus whatever P9 teaches. Keep
  it **local/gitignored** if it names fleet hosts.
- **P11 — report.** Post a Result comment on the issue: the matrix table, the measured evidence,
  and the fail-first record (a check that never failed first has not been shown to work).

## 8. Acceptance criteria

- [ ] **AC1** each of the five profiles installs on a clean VM by the documented self-host path.
- [ ] **AC2** `/api/capabilities` matches the profile exactly — `modules` == expected set,
      `switched_off` empty — for all five.
- [ ] **AC3** `collab`: two browsers exchange chat **and** complete a call with decoded, advancing
      frames on **both** sides.
- [ ] **AC4** `remote`: a freshly enrolled agent streams decoded, advancing frames to a browser.
- [ ] **AC5** `mesh`: two agents see each other in `peers` and `ping` round-trips; a tunnel or
      `mh ssh` session succeeds.
- [ ] **AC6** `access`: AC4 **and** AC5 pass on one server, and chat/conference are absent.
- [ ] **AC7** `full`: AC3 + AC4 + AC5.
- [ ] **AC8** every absence is asserted positively, with a positive control on `full`.
- [ ] **AC9** teardown destroys every VM and leaves no residue; a run is repeatable back-to-back.
- [ ] **AC10** fail-first evidence recorded for at least one check per profile.
- [ ] **AC11** the whole matrix runs from one command, documented in the skill.

## 9. Out of scope (say so in the spec)

Windows/macOS **servers** (the self-host stack is Linux + docker); k8s deployment of profiles
(that is the prod overlay's job); the `saas`/billing add-on (hosted-only, never in a self-host
image); performance and scale (this is a *functional* matrix); and upgrade/migration between
profiles.

## 10. One last thing

FR-61's most valuable output was not the green matrix — it was the **35 field defects** the
harness found by installing the product the way users do. Expect the same here, and write the
failures down: a dead end recorded is often the most useful line in the log.
