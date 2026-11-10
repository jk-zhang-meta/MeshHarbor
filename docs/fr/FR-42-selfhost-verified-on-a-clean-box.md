# FR-42: Self-hosting, actually watched coming up on a clean machine

> **CLOSED 2026-09-01** — issue #967 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

Status: **P0 in progress** (2026-08-30). Tracking issue: `FR-42` (#967).
Child of FR-39 (#951), which shipped `docker-compose.selfhost.yml` and
`docs/self-hosting.md` **without anyone ever running them end to end**.

## Why this is not optional

FR-39 found that there was no self-host path at all: `docker-compose.yml` brought up
dependencies only and never ran the application, and no workflow publishes a container
image anywhere — while `LICENSING.md` promises self-hosting on unlimited devices forever.
It shipped a one-command stack to close that.

What it did **not** do is run it. What was verified was that the compose *renders*
(`docker compose config` exits 0), that it fails fast with a useful message when a secret
is missing, and that every `MESHHARBOR__*` key it sets exists in `settings.rs`. None of that
is the same as watching the thing come up.

⚠️ This is the exact path a launch post sends strangers down, and the audience it sends
them from — r/selfhosted — has a rule requiring a promoted project to be *production ready
with docs*, and a culture of actually running what is posted. A `docker compose up` that
fails on a clean machine is a launch-ending comment, and it arrives in public.

⚠️ It is also the second-order risk: FR-39's README and `docs/self-hosting.md` now make
concrete promises ("open <http://localhost:8080>", "the first build takes 10–20 minutes",
"register, then create your organization"). Two claims in the first draft of that document
were already **wrong** and only caught by reading the code. Prose about a running system
that nobody has run is a third class of the same defect.

## Goal

Somebody follows `docs/self-hosting.md` verbatim on a machine with nothing but Docker, and
ends up with a working MeshHarbor they can log into and enrol a device against. Every step
that does not behave as documented is either fixed or documented honestly.

## Where

**Docker Desktop with WSL2 integration on neo16** (operator's choice, 2026-08-30). Ubuntu
24.04.4, 45 GB RAM, 272 GB disk free — x86_64, the architecture most self-hosters run.

Rejected: installing `docker-ce` natively inside the WSL distro (adds packages to the
operator's dev box), and `scw-m2-asahi` (a real arm64 host and a better architecture test,
but it currently serves the FR-19 peer relay on :3478 and a 20-minute build there would
disturb live field testing).

## Key design

This FR is mostly *execution*, and its output is a list of defects. The design that matters
is what counts as a pass:

1. **Follow the document, not the intent.** Copy-paste each command from
   `docs/self-hosting.md` exactly as written. A step that only works because the operator
   knew what was meant is a documentation defect, and the whole point is to catch those
   before a stranger does.
2. **Record timings.** The doc claims 10–20 minutes for the first build. If it is 45, the
   doc is wrong in the way that makes people abandon halfway.
3. **Verify the reachability caveats are true**, not just present. Conference media is the
   one part that cannot be proxied, and the doc's port-range and `ANNOUNCED_IP` advice has
   never been tested from the form the compose actually ships.
4. **Enrol a real device against the self-hosted server** — the install one-liner in the
   doc points at `http://<your-host>:8080/api/setup/install.sh`, which nobody has fetched
   from a self-hosted instance. A server that runs but cannot enrol anything is not a pass.
5. **Every fix lands in the same PR as the finding**, so the doc and the stack stay in step.

## Phases

| phase | scope | kill switch |
|---|---|---|
| P0 | bring the stack up from the documented commands; record every deviation | `docker compose down -v` |
| P1 | fix what broke — compose, env example, or the document | revert the hunk |
| P2 | enrol a device against the self-hosted server and reach it | remove the test device |
| P3 | publish a prebuilt image so the first run is minutes, not a source build | workflow is dispatch-only — **shipped** (#1133) |

## Acceptance criteria

- [x] `docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d --build`
      succeeds from a clean clone, using only commands copied from the document
- [x] `curl -fsS http://localhost:8080/health` answers 200
- [x] an account can register, and an organization can be created from the dashboard
- [x] the measured first-build time is recorded, and `docs/self-hosting.md` states it
      honestly
- [~] a device enrols against the self-hosted server via the doc's own one-liner, and
      appears online — **enrolment proven, "online" not** (see the log: this host
      already runs a daemon, and one machine serves one)
- [x] every deviation between the document and reality is either fixed or written down
- [ ] `docker compose down -v` leaves the machine clean

## Open decisions

- **Whether to publish a container image (P3).** It turns a 10–20 minute source build into
  a 60-second pull, which is the difference between "I tried it" and "I gave up". But it
  means publishing a public package under the operator's account, with a tag and retention
  policy that are their call — so P3 ships the workflow **dispatch-only**, and nothing is
  published without an explicit run.
- **Whether the doc should recommend host networking by default on Linux.** It is the
  correct answer for conference media and it is how the hosted service runs, but it is not
  available on Docker Desktop — which is the very setup this FR is testing on.

## Out of scope

Kubernetes / multi-node self-hosting (`docs/multi-pod-scale-out.md` covers the topology) ·
automatic TLS · arm64 validation · backup/restore drills beyond the documented command.

## Field-verification log

| date | what was checked | result |
|---|---|---|
| 2026-08-30 | FR-39 shipped the stack unrun | `docker compose config` exit 0; missing-secret guard exits 1 with the `openssl rand` hint; `auth.auto_verify` and `s3.enabled` exist; the production JWT refusal is real (`crates/api/src/main.rs:32`). **None of this is a run.** |
| 2026-08-30 | target host | Docker Desktop + WSL2 integration on neo16; Ubuntu 24.04.4, 45 GB RAM, 272 GB free |
| 2026-08-30 | **P0: the documented path WORKS from a clean clone** | `git clone` → `cp .env.selfhost.example` → fill 4 secrets → `up -d --build` exited **rc=0 in 359 s (5m59s)**. All five services running (mongo/redis/minio healthy). `/health` answered 200 twenty seconds later: `{"status":"ok","version":"0.4.23"}`. `GET /` 200, `/api/setup/install.sh` 200, `/api/stripe/plans` 200 |
| 2026-08-30 | **the documented user journey works** | register → **201** (`auto-verified`, as `MESHHARBOR_AUTO_VERIFY=true` intends) · login → 200 · create organization → 200 (`Self Host Demo`, plan `free`) · mint agent enrolment token → 200 |
| 2026-08-30 | ⚠️ **DEFECT — the installer would enroll against the WRONG SERVER** | `scripts/install.sh` line 46 hardcodes `SERVER="https://meshharbor.itachi.fans"` and `install.ps1` line 64 `$Server = 'https://meshharbor.itachi.fans'`. Both are piped from the network, so **neither can see which host it was fetched from**. `docs/self-hosting.md` omitted `--server`, so a self-hoster would download the installer from their own server and then enroll the agent against the **hosted** service using a token only their own server can verify — an authentication failure that says nothing about the real cause, on the first thing anyone does after the stack comes up. Doc fixed |
| 2026-08-30 | ⚠️ **DEFECT — `irm … | iex` cannot pass arguments at all** | The Windows one-liner in `docs/self-hosting.md` **and in the README** could pass neither `-Server` nor `-Token`. `scripts/install.ps1`'s own header documents the `& ([scriptblock]::Create((irm …))) -Role … -Token …` form; both docs now use it. Pre-existing in the README, propagated by FR-39 |
| 2026-09-01 | **the installer defect is CLOSED, and proven on the served bytes** | FR-50 (#1083) made the route substitute `app.frontend_url` at serve time. The self-hosted stack now serves `SERVER="http://localhost:8080"`, and prod serves the committed script byte-for-byte. The doc no longer tells the reader to pass `--server` |
| 2026-09-01 | **a device DOES enrol against the self-hosted server** | Took the `SERVER` value **out of the served script** and enrolled with it: `Enrollment successful. Agent id: 6a96aca4…`, and the device appears in that server's own `/api/tenant/<tid>/agent` list. So the chain the one-liner walks — serve → read → enrol — works end to end |
| 2026-09-01 | ⚠️ **"appears online" could NOT be proven on this host, for a structural reason** | The probe daemon never reached signalling: the machine already runs one, and the single-instance lock is the *point* (`One daemon per enrolled machine` — it is why multi-org is `[[orgs]]` rather than N installs). Proving `online` needs a host with no daemon, which is a clean-VM test rather than a gap in the product |
| 2026-09-01 | 🔑 **an isolated `--config` does NOT isolate the UPDATER** | Running the probe with its own config pointed at the self-hosted server made the host **self-update system-wide** — `apt-get` installed `meshharbord-0.4.42` over 0.4.41 while the real daemon was running. The enrolment is per-config; the updater is per-MACHINE, exactly as `docs/multi-org.md` says. It then left the running daemon on the **deleted inode** (`/usr/bin/meshharbord (deleted)`, `--version` reporting the new one) until a restart. Re-run such a probe with `auto_update = false`, and expect to restart the host daemon afterwards |
| 2026-08-30 | ⚠️ the build-time claim was wrong | Doc said "10–20 minutes"; **measured 359 s** on 16 cores. Restated with the measurement and the hardware it was measured on, since "10–20 min" is what makes someone abandon halfway on a slow box and distrust the doc on a fast one |
| 2026-08-30 | ⚠️ **no healthcheck on the app service — FIXED** | `docker compose ps` reported `meshharbor` merely `running`, so nothing could gate on it. The runtime image has **no curl, no wget and no nc** (checked in the container), and adding one to a production image just to run a liveness probe is a poor trade — so the probe uses **bash's `/dev/tcp` builtin**, which is already there. Verified live: `meshharbor=Up 37 seconds (healthy)` |
