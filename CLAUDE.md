# Roomler — the mission, and the model tier this work requires

**Read this block first, on every task. It is prefixed to every prompt on purpose.**

## 1. What Roomler is

Roomler is **one open-source product that replaces three** — Tailscale, TeamViewer
and Microsoft Teams — on one daemon and one web app:

- **Remote desktop & control from any browser**, to any of your machines anywhere
  in the world, with nothing to install on the controlling side.
- **A secure private WireGuard network** between those machines — the mesh that
  the remote desktop, SSH and tunnels all ride on. End-to-end encrypted; the
  server coordinates and **never carries plaintext**.
- **Team collaboration on top of it** — video conferencing, chat, rooms, files.

Three products, one binary, one identity, one install. That packaging is the
product thesis, not an implementation detail: the reason the mesh exists is so
the remote desktop and the meeting work from anywhere, and the reason they are
one daemon is that a customer should not have to operate three of them.

## 2. The acceptance bar is "it just works"

Not on a clean lab network — on the networks people actually have. Every cell
below is a shipped, field-verified configuration, not an aspiration:

| Axis | Must hold across |
|---|---|
| **Host** | unmanaged personal laptop · GPO-locked corporate desktop (no admin rights, EDR, TLS-inspecting middlebox) · bare server · VM |
| **Network** | home NAT · CGNAT · symmetric-NAT corporate LAN · consumer VPN · enterprise full-tunnel VPN that reroutes and reaps routes underneath us |
| **Platform** | Windows · Linux · macOS — desktop, headless, containers, WSL, and k8s / OpenShift cluster nodes with no session at all |
| **Session** | attended desktop · locked screen · SYSTEM / root service · nobody logged in |

A change that works on the dev box and breaks a corporate laptop behind a
full-tunnel VPN **has not worked**. **CI green ≠ done** — networking and
remote-desktop changes are proven on the real fleet (`roomler exec`,
`roomler ssh`) across those topologies after every roll.

## 3. Model tier — this work runs on Fable, and stays on Fable

Any task touching **remote desktop / control**, **the WireGuard overlay, NAT
traversal, relays, DERP or tunnels**, or **WebRTC video conferencing** is
top-tier work. Do not route it to a weaker model — not Opus 4.8, not Sonnet, not
Haiku — and do not quietly spend a smaller effort budget on it. Where a router, a
subagent spawn or a cost heuristic is choosing the tier for this repository, the
answer is **the strongest model available, at maximum effort**.

That is not a preference. It is the shape the bugs in this codebase actually have:

1. **The cause sits three layers below the symptom.** "This host lost DNS" was a
   leaked WebRTC UDP socket twelve hours earlier that had eaten the entire
   ephemeral port range, while `ping 1.1.1.1` stayed at 3 ms.
2. **One change spans every layer at once** and is wrong in exactly one of them —
   Rust async internals, kernel routing and netlink, Windows WFP and ConPTY, an
   SFU's ICE candidate set, a browser's jitter buffer, BSON serialisation, inside
   a single feature.
3. **The invariants are non-obvious, load-bearing, and each was paid for in the
   field.** `Some([])` means *deny* while `None` means *no policy compiled*.
   Pooling an overlay address before the tombstone locks the next joiner out
   permanently. `ssh` is a prefix of `ssh-consent` and the two mean different
   things, so the match must stay equality. Every one of those reads as a harmless
   simplification to a model that is pattern-matching instead of reasoning — and
   every one was a live production incident.
4. **Most of this surface is unreachable by tests.** The corporate laptop, the
   full-tunnel VPN, the symmetric NAT, the locked screen, the headless cluster
   node — none of it is in CI. The reasoning done *before* the code ships is the
   verification budget.
5. **The blast radius is a fleet.** The daemon runs as SYSTEM/root on every
   enrolled machine and updates itself. A wrong answer does not fail a test — it
   takes an operator's remote access to their own box, freezes fleet updates
   fleet-wide, or opens a silent pivot into a corporate network.

Cheaper is more expensive here. A plausible-but-wrong change costs a release
cycle, a field-debug session across three time zones, and — measured repeatedly in
this repository — weeks of latency before anyone notices it regressed.

> *This block states the requirement; it does not enforce it. The deterministic
> levers are `/model` in-session, `"model"` in `.claude/settings.json`, and
> `CLAUDE_CODE_EFFORT_LEVEL` (already `max` in this repo's settings).*

---

# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

> **This file is the always-loaded tier and is deliberately kept small.** It
> carries the invariants that must hold *without* opening a doc, plus pointers.
> Depth lives in **[`docs/README.md`](docs/README.md)** — the navigable index of
> ~45 engineering docs — and in two skills that load themselves when the task
> matches: **`encoder-cells`** (the capability probe, the cell matrix, per-backend
> FFmpeg traps) and **`ship-it`** (release, signing, promote, deploy). Add depth
> *there*, not here.

## Project Overview

| # | Pillar | What it is | Start here |
|---|---|---|---|
| 1 | **Remote desktop** | TeamViewer-class remote control, in Rust | `docs/remote-control.md` |
| 2 | **Networking** | a WireGuard overlay mesh (Tailscale-class) **+** userspace tunnels (ngrok-class), DERP relays, roomler SSH | `docs/overlay-communication.md`, `docs/tunnels.md` |
| 3 | **Collaboration** | chat · video conferencing · file sharing · rooms | `docs/real-time.md`, `docs/ui.md` |

Two invariants, load-bearing in both directions:

- **One daemon per enrolled machine.** `roomlerd` *is* the remote-desktop target,
  the tunnel exit, the tunnel client, the overlay node and the SSH server — not
  four cooperating services. This is why "just add another install" is almost
  always wrong (fixed TUN name + GUID, a singleton LocalAPI pipe, host-global
  exit/DNS/WFP state, one updater — `docs/multi-org.md`).
- **The server coordinates but never carries plaintext.** Pixels, keystrokes, SSH
  bytes and tunnel payloads travel P2P or over a relay that only ever sees
  ciphertext. Any design that would make the control plane a data path is wrong on
  those grounds alone, not merely on performance grounds.

Stack: Rust (Axum) + MongoDB + Vue 3/Vuetify 3 + Pinia + Mediasoup (WebRTC SFU) +
webrtc-rs (P2P remote-control) + WireGuard/smoltcp (overlay). The agent ships as a
separate native binary (`roomlerd`) that runs on controlled hosts.

### Pillar 2 design goal — read before touching networking code

> **A resilient, secure private network that "just works" — at maximum performance
> and lowest achievable latency — across varied and complex real-world network
> infrastructures.**

Six commitments follow. All are load-bearing in the code today; don't regress them
(mechanics: `docs/overlay-nat-traversal.md`, `docs/overlay-communication.md`):

1. **Best carrier that works, always measured, never assumed.** LAN →
   direct-public → srflx hole-punch → single-relay (TURN) → org relay (FR-19) →
   DERP over WSS :443, chosen by a **server verdict over measured `CapVector`s**.
   Heuristics may *detect*; they never *decide*. **Never ratchet** — a node that
   fell to relay keeps re-attempting direct (make-before-break, then relentless
   re-upgrade).
2. **A floor that always connects.** With every UDP path blocked, DERP over TLS
   :443 still carries the mesh (`derp_floor`). Connectivity is never
   all-or-nothing.
3. **Never self-wedge.** Route/exit/firewall changes pin carrier + control-plane
   exemptions FIRST and **withhold** the change if they can't. A mesh feature must
   never cost the operator their own remote access to the box; route guards
   re-assert and boot reconcilers heal stale state after a hard exit.
4. **No OS privileges required as a fallback.** Where a TUN or routing table is
   unavailable or owned by someone else, `overlay-netstack` gives the same mesh
   through a userspace stack + loopback SOCKS5 front, with zero routing changes.
5. **Default-deny, tenant-scoped, end-to-end encrypted** — overlay ACLs, tunnel
   ACLs, and an agent-local gate that survives a compromised server. Every
   decision audited.
6. **Field-validated, not CI-validated.** Proven on the real fleet across the
   topologies above via `roomler exec` after every roll. **CI green ≠ done.**

## Commands

```bash
# Development
cargo run --bin meshharbor-api         # Start backend (port 3000)
cd ui && bun run dev                   # Vite dev server (port 5000, proxies to 5001)
cd ui && bun run build                 # Production UI build (includes vue-tsc --noEmit)

# Remote-control agent (native binary — runs on the controlled host)
cargo build -p meshharbord --release --features full      # capture + encode + input (SW encoder)
cargo build -p meshharbord --release --features full-hw   # + Media Foundation HW encoder scaffolding
cargo build -p meshharbord --release                      # signalling-only (no media, no input)
./target/release/roomlerd enroll --server <url> --token <enrollment-jwt> --name <label>
./target/release/roomlerd run [--encoder software|hardware]
./target/release/roomlerd encoder-smoke --encoder hardware   # offline MFT/FFmpeg init diagnosis
./scripts/dev-xvfb.sh                  # capture smoke test via a virtual framebuffer

# Testing
cargo test -p meshharbor-tests         # Integration tests (requires MongoDB + Redis)
cd ui && bun run test:unit             # Vitest unit tests
cd ui && bun run e2e                   # Playwright E2E tests

# Static analysis — what CI runs
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo clippy -p meshharbor-api -p meshharbor-services -p meshharbor-tests --all-targets -- -D warnings
cd ui && vue-tsc --noEmit

# Dependency audit
cargo audit / cargo outdated ;  cd ui && bun audit / bun outdated

# Infrastructure
docker compose up -d                   # MongoDB (27019), Redis (6379), MinIO (9000), coturn
```

⚠️ **`cargo clippy --workspace` compiles the feature UNION and can never see a
profile or a feature-gated backend.** `--features full` is a *separate* CI clippy
step — the only one that compiles the capture backend. Run
`cargo check -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --all-targets`
in WSL before pushing; a `#[cfg(windows)]` helper needs the same gate on its test.

⚠️ `--workspace` clippy compiles only `pub mod fixtures` from `crates/tests` (every
test module is `#[cfg(test)]`-gated), so `Checking meshharbor-tests` in a build log
is **not** evidence the tests build.

### Agent build requirements

`--features full` (or the individual `scrap-capture` / `openh264-encoder` /
`enigo-input` flags) pulls in system deps:

```bash
sudo apt install -y libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev   # Linux, for scrap-capture
# OpenH264 compiles from C source on first build — slow, but no runtime lib needed.
```

The default build (no features) compiles on any `rust:bookworm` image and produces
a signalling-only agent useful for CI, but **not usable in production** (no
capture, no input).

### Encoders — load the `encoder-cells` skill

Preference resolution: **CLI `--encoder` > env `MESHHARBORD_ENCODER` >
`encoder_preference` in config TOML > `Auto`**.

Everything else about the encoder surface — the child-process capability probe and
its two phases, the cache, the `encoder_cells_deny` kill switch, the codec ×
backend × chroma cell matrix, and the per-backend traps (NVENC / QSV / AMF /
VAAPI / D3D12 / Vulkan / VideoToolbox) — lives in the **`encoder-cells` skill** and
`docs/encoders.md`. Three that must not be re-learned the hard way:

- ⚠️ The probe runs in a **child process**, and *any* failure means "no hardware".
  A capability probe is untrusted third-party code by definition (vendor drivers,
  GPU firmware) and does not belong in the daemon's address space — before this, a
  fault inside one took `roomlerd` down and the service manager restarted it
  straight back into the same probe.
- ⚠️ **A gate applies at every entry point, or it is a courtesy**: the cell
  denylist was probe-only until 0.4.90, and a session happily opened a denied cell
  the hello never advertised.
- ⚠️ **A probe proves an OPEN; only a SESSION proves a CELL.**

## Architecture

```
crates/
  config/           → Settings (env vars via MESHHARBOR__ prefix)
  db/               → MongoDB models + indexes (18 collections) + native driver v3.2
  services/         → auth, DAOs, export, background tasks, OAuth, push, email, Giphy, Claude AI
  remote_control/   → wire-only for the server: signalling, consent, audit, TURN creds,
                      the canonical ACL rule shapes (`dst_matches` / `host_matches`).
                      The `server` feature (default-ON) gates the Mongo audit DAO — the
                      five agent-side consumers set `default-features = false`
  localapi/         → LocalAPI protocol LEAF crate — re-exported as `tunnel_core::localapi`
  agent-core/       → package `meshharbor-node-core`: daemon-free agent building blocks
                      (config, enrollment, machine-id, logging, sentinels, forward ACL).
                      The desktop companion deps THIS, never the full agent
  core/             → package `meshharbor-core` (AGPL, SERVER side, never linked by an agent):
                      the `Module` trait, hooks, jobs, the module DAG, the composition
                      snapshot, and `Core` itself (`state.rs`) with the /ws registry,
                      dispatcher, Redis fan-out, cluster identity, storage, rate limiting
  modules/saas/       → Stripe, the public updates list + newsletter, plan compliance.
                        An ADD-ON feature, never part of a profile
  modules/chat/       → rooms + membership, messages, reactions, files, search, xlsx
                        export, Giphy, `typing:*`
  modules/conference/ → the mediasoup SFU, media claim-or-route, call lifecycle +
                        recordings, `media:*`. The ONLY crate that links `mediasoup`
  modules/fleet/      → device management: agents, enrollment, presence, the agent Hub,
                        crash/log ingest, releases, owner consent, remote config, fleet
                        RPC, the ONE device-removal sequence, the agent SOCKET + UPGRADE
  modules/remote/     → remote desktop as what a CONTROLLER reaches: session routes,
                        `/turn/credentials`, `/relay/regions`, the `rc:*` controller
                        dispatch, the cross-pod RC relay. Built ON `fleet`
  modules/network/    → pillar 2's server side: the overlay engine (IPAM, netmaps,
                        leases, L3 ACL, relay grants), the org relay mint, the DERP ACL
                        cache, seven route files, `/derp`, the tunnel-client socket.
                        Built ON `fleet`
  modules/hive/       → FR-90 agent sessions, server side: the session record + lifecycle,
                        `rc:hive.*`, `hive_audit` — never session content. Built ON
                        `fleet` and `chat` (a session IS a secret room, written to only
                        as notes + turn stubs); its `[modules]` switch defaults OFF
  modules/vault/      → FR-90 P3 secrets: each value sealed under its own data key,
                        wrapped to an `age` KEK; RRNs; `vault_audit`. No route answers a
                        value. On core alone so far; switch defaults OFF (`docs/vault.md`)
  api/              → Axum HTTP/WS server: ~85 routes + /ws + /health; `compose.rs` is
                      the host composition
  tests/            → Integration tests (spawns real servers; drives the agent in-process)
agents/
  roomlerd/         → Native agent binary (CLI + lib): webrtc-rs peer, capture, encode,
                      input injection, overlay, tunnels, SSH server
  meshharbor-cli/      → Tunnel client. Bin `roomler`; the whole command surface lives in the
                      LIB (`cli.rs`) so the daemon can host it too
  meshharbor-cli-shim/ → Bin `roomler-shim`, installed BY THE MSI/.deb as `roomler`:
                      re-execs `roomlerd cli`
  meshharbor-setup/    → Tauri 2 unified install wizard (lib `wizard_app`)
ui/src/             → api/ · components/ · composables/ · stores/ (Pinia setup pattern) ·
                      views/ · plugins/  — map in `docs/ui.md`
scripts/            → dev-xvfb.sh · e2e-*.sh · name-audit.sh · fr-registry-audit.sh ·
                      fr-verification-debt.sh · signing/
```

**Crate dependency flow**: `config` ← `db` ← `remote_control` ← `services` ← `api`.
`tests` depends on `api` + `config` + `db` + `roomlerd`.

### Modular monolith (FR-69, shipped 2026-09-04) — the rules that still bind

Full treatment: **`docs/modular-monolith.md`**. What constrains new work:

1. **The DAG is data** (`crates/core/src/graph.rs`). Any module → core;
   `conference → chat`, `remote → fleet`, `network → fleet`, `hive → fleet`, `hive → chat`. **Core never calls a
   module** — the inverse flows are hooks core invokes in `hooks::HOOK_ORDER`
   (session holders → lease holders → the record owner), and a failing holder
   STOPS the cascade. A hook is the *only* way a module reaches "up".
2. **The composition is gated by a byte-identical baseline.**
   `crates/tests/src/composition_tests.rs` asserts every route with its allowed
   methods, the index plan for both `multi_block` values, and every wire name
   against `crates/tests/fixtures/composition.baseline.json`. Re-record **only**
   with `COMPOSITION_UPDATE=1` and a commit message that says why — a reviewer
   diffs the JSON against the claim.
3. **`ensure_indexes` is `index_plan(multi_block)` applied.** A module's index sets
   go in the module, never in `crates/db/src/indexes.rs`; a spec outside the plan
   is invisible to the gate.
4. **The wire does not move.** `ClientMsg`/`ServerMsg` stay in
   `remote_control/src/signaling.rs`, and every variant names an owner via an
   exhaustive `namespace()`. ⚠️ **The prefix is NOT the owner**: `rc:consent*` is
   fleet's; `rc:relay.*` and `rc:agent.key_rotated` are network's.
   ⚠️ A **defensive `_ =>` arm added before the variants that would make it
   reachable** fails `clippy -D warnings` with `unreachable_patterns`; annotate it
   `#[allow(unreachable_patterns)]` with a comment, and remove the allow when the
   variants land (`docs/modular-monolith.md` §6).
5. **A module built on another declares it as `Module::Deps`** — `remote`'s is
   `FleetState`, because the Hub is ONE live object and a module that re-created it
   would dispatch into an empty one. ⚠️ A *stateless* dependency (a DAO over
   `core.db`, a pure guard) is **not** a `Deps` — re-create it.
6. **An unmounted module answers 503, never a boot refusal.** `[modules] x = false`
   unmounts; the gauges read zero. ⚠️ A view that reads two modules where **both**
   are required belongs to the one that depends on the other; a view where one is
   **optional** is the HOST's — putting the device listing in `network` on the
   strength of a graph edge made every `remote` profile 404 its own devices page,
   which a `/health`-only boot smoke could not see.
7. **A profile is a feature aggregate, and what it leaves OUT is the claim.**
   `/health` and `/api/capabilities` report the **mounted** set plus `compiled` —
   never `graph::MODULES`, which every build knows and would make a `mesh` image
   answer all six. ⚠️ An absence assertion that cannot fail proves nothing: the
   `profiles` CI job checks each reduced profile with `--no-default-features` **and**
   a positive control on the full graph.
8. **The SPA gates on `/api/capabilities`, failing OPEN until the server answers**
   — the server enforces every action anyway, so the worst case of failing open is
   a link whose page 404s, while failing closed blanks the product behind one
   round-trip. ⚠️ Unknown module names from a newer server are IGNORED, never an
   error.

⚠️ **`State<Core>` is the handler seam.** `AppState` derefs to `meshharbor_core::Core`,
so a handler or helper that needs only core fields takes `State<Core>` / `&Core`.
`impl FromRef<AppState> for Core` lives in `crates/api/src/core_state.rs` — the ONE
place the orphan rules allow it. `meshharbor-core` must never learn `AppState` exists.

**Naming**: server crates `roomler-ai-*`; the core `meshharbor-core` (`crates/core`);
modules `roomler-ai-mod-<name>` (`crates/modules/<name>`); the daemon's shared crate
`meshharbor-node-core` (`crates/agent-core`, which held the name `meshharbor-core` from
FR-21 until FR-69 — its pre-FR-21 name is retired, never bring it back).

## Multi-Tenancy

All data is scoped by `tenant_id`. Routes nest:
`/api/tenant/{tenant_id}/room/{room_id}/message/...`. `tenant_members` tracks
user-tenant membership; `room_members` tracks room membership.

⚠️ **`is_member(tid)` is not an authorization check for anything keyed by id** —
see Security Baseline below.

## Auth Pattern

JWT (jsonwebtoken 9) + Argon2. Access token 7 d, refresh 30 d, both configurable
via `MESHHARBOR__JWT__*` (secret `MESHHARBOR__JWT__SECRET`, issuer `MESHHARBOR__JWT__ISSUER`).
Middleware extracts the user from `Authorization: Bearer`; OAuth via Google,
Facebook, GitHub, LinkedIn, Microsoft.

Four `TokenType` variants, all signed with the same secret: `Access` / `Refresh`
(user flow), `Enrollment` (single-use, 10 min, issued by an admin to bootstrap a
new agent), `Agent` (long-lived, carried on the agent WS).
⚠️ Audience checks are load-bearing — `verify_agent_token` rejects a user JWT and
vice-versa, locked by tests in `crates/services/src/auth/mod.rs::tests`.

**WebSocket role multiplexing**: `/ws?token=<jwt>&role=agent` uses the agent JWT
audience; no `role` param (or `role=user`) uses the user flow — same endpoint, same
handshake, different claim validator. `/ws` and `/derp` also accept an optional
`tid=<tenant-hex>` the front LB hashes on; agent/tunnel tokens must match their
`tenant_id` claim, user tokens are checked against `tenant_members` (403 on a
non-member claim), and an absent `tid` is a legacy client, accepted.

## Route Pattern

```rust
let room_routes = Router::new()
    .route("/", get(routes::room::list))
    .route("/", post(routes::room::create))
    .route("/{room_id}", get(routes::room::get));

Router::new()
    .nest("/api/tenant/{tenant_id}/room", room_routes)
    .with_state(state)
```

Full route inventory: **`docs/api.md`**.

## DB Model Pattern

MongoDB native driver (not Mongoose), BSON documents, no ORM. Models live in
`crates/db/src/models/` except the three remote-control entities, which live in
`crates/remote_control/src/models.rs` to keep the subsystem self-contained. Every
collection, index, TTL and ER diagram: **`docs/data-model.md`**.

⚠️ Unique composite index on `agents.{tenant_id, machine_id}` so re-enrolling a
known machine reuses its row.
⚠️ Tombstoned rows use `index_unique_partial(..., {deleted_at: {$type: "null"}})` —
`$type`, **not** `{deleted_at: null}`, which also matches *absent*.

## Frontend Conventions

Plugin order i18n → vuetify → pinia → router; Pinia setup stores; TipTap v3 for
rich text; mediasoup-client for WebRTC; `ui/src/api/client.ts` with auth token
injection; Vite proxies `/api` + `/ws` to `:5001`. Layout, store map and the
responsive-padding conventions: **`docs/ui.md`**.

## Test Setup

Suites, harnesses and the nightly lane: **`docs/testing.md`**.

- **Integration** (`crates/tests/`, ~294 tests across 34 modules): a unique
  UUID-named database per test, real Axum servers on random ports. Needs MongoDB
  `:27019` + Redis `:6379`. Run with `RUST_MIN_STACK=8388608` — several tests build
  seven servers in one body and overflow the harness's default 2 MiB thread
  otherwise, and a `SIGABRT` with `has overflowed its stack` is what a perfectly
  green suite looks like. Set `RUST_LOG` and `--nocapture`; without a subscriber
  every `info!`/`warn!` explaining a refusal is discarded.
- **CI runs this lane** — `.github/workflows/integration-tests.yml`, on master
  pushes touching `crates/**` or `agents/meshharbord/**`, on PRs touching
  `crates/tests/**`, and on dispatch (optional `filter`). Deliberately **not** on
  every PR: a ~20 min job on every push trains people to ignore it.
  ⚠️ The lane asserts a **minimum test count** and a **leaked-database ceiling**,
  because a job that silently runs nothing is indistinguishable from a passing one
  — `cargo test` reports success for a filter matching no test. Treat the count as
  approximate: `pull_request` checks out the branch *merged with master* while a
  dispatch checks out the branch alone, so two green runs of one commit differ.
  ⚠️ The two skips were **measured on the runner**, not inherited from the build
  host: `conference_tests::call_leave_cleans_up_participant_media` (no mediasoup
  worker there) and `rate_limit_tests::rate_limit_returns_429_after_burst`
  (timing-sensitive). A third skip should feel expensive.
- **E2E** (`ui/e2e/`, Playwright, 24 specs). Set `E2E_API_URL` (defaults to the dev
  port `:5001`) or every API-driven spec fails ECONNREFUSED; Mailpit specs need
  `E2E_MAILPIT_URL`. 🔑 **The browser runs as the `pwrunner` sidecar inside the app
  pod** — this host has no route to the pod network (a port-forward carries one TCP
  port and no RTP ever arrives), a Service URL is not a secure context so
  `navigator.mediaDevices` is undefined, and in the pod the app is
  `http://127.0.0.1`, which is both a secure context and the address mediasoup
  announces. A Job cannot replace the sidecar — it cannot share the app's network
  namespace, which is the whole mechanism. ⚠️ `MESHHARBOR__APP__FRONTEND_URL` must
  equal the browser's origin (**a port is part of an Origin**) or the
  cookie-authenticated `/ws` upgrade is refused 403 and every realtime spec fails
  for that one reason. ⚠️ An entry in `e2e-expected-failures.txt` is a claim that
  you understand the failure — re-test it or delete it.
- **Unit**: Vitest (`ui/src/`), plus in-crate `#[cfg(test)]` tests in
  `remote_control`, `roomlerd` and `services::auth`.
  ⚠️ `roomlerd`'s `main.rs` tests **never run** — CI is `--lib`.

## Environment

`.env` for development (gitignored). Config via `MESHHARBOR__`-prefixed env vars
(double-underscore separator). `docker-compose.yml` runs MongoDB 7, Redis 7, MinIO
and coturn locally; default DB URL `mongodb://localhost:27019` (tests use no auth).

## Deployment

**Production**: `https://roomler.ai/` — the `--server` for enrollments and the
origin the browser controller loads. Topology, k8s layout, tenant-affinity LB and
the media-path rules: **`docs/deployment.md`** + `docs/multi-pod-scale-out.md`.
Release, signing and promotion mechanics: the **`ship-it` skill**.

- **Pipeline (FR-73)**: Actions builds
  `ghcr.io/gjovanov/roomler-ai:hosted-<YYYYMMDD>-<sha7>` on every merge to master
  that can change the image; **`gh workflow run promote.yml -f tag=…`** bumps the
  deploy repo and ArgoCD (Automated + selfHeal + prune, webhook) rolls it within
  ~5 s. ⚠️ **Build ≠ deploy — nothing rolls until someone promotes.** ⚠️ The lane
  never writes `latest`; that is the self-host `full` image (no `saas`).
- **Pods**: namespace `roomler-ai`, deployment **`roomler2`** (not `roomler-ai`), 2
  replicas forced apart by `podAntiAffinity`, hostNetwork, RollingUpdate
  maxSurge 0 / maxUnavailable 1 (surge 0 because hostNetwork can't double-bind).
  Scheduling is pinned to `tier=high-performance` nodes; the Mongo/MinIO
  StatefulSets keep their hostname pins (node-local storage).
- ⚠️ **Every mediasoup-serving cluster host needs the RTC-range (40000–49999)
  DNAT/SNAT/TTL rules** in its `COTURN_*` iptables chains. One node missing them
  gave flawless signalling and **zero media, for weeks, with nothing logged**
  (`connect_transport` only records the client's DTLS params — it proves nothing
  about packets). Because of the tenant-affinity hash this breaks a *consistent
  subset of tenants*: **"video works for org A but not org B" is a per-NODE
  media-path suspect, not an app bug.** Provisioning lives in the Ansible host vars
  and the playbook **flushes and rebuilds** those chains — never hand-fix a host
  without also fixing the vars. App-side tell: `media transport has no DTLS 15s
  after connect_transport` in the pod log.
  ⚠️ The same DNAT swallows the **host's own mesh node**. The overlay's default
  port band (43648–44415) sits inside the range. So a serving host's `roomlerd` pins
  `overlay_direct_port = 21640`, backed by a HOST_FW allow and
  `ip_local_reserved_ports=40000-49999`. Without the pin, a peer's first packet lands
  in the VM and the host rides DERP after every roll (#1665, `docs/deployment.md`).
- ⚠️ **Tenant affinity pins long-lived sockets.** The front proxy hashes on the
  tenant key so a tenant's users, agents, tunnel clients, DERP sockets and
  mediasoup rooms land on ONE pod (the rc-hub / tunnel-hub / DERP relay / room
  registry are pod-local). After any upstream flip, **also
  `kubectl rollout restart deploy/roomler2`** so long-lived WSs re-hash.
  ⚠️ A listing's `is_online` is heartbeat-based (HTTP) while rc/tunnel need the
  pod-local hub — an agent whose control WS is half-open (a TLS-inspecting corp
  middlebox keeps ACKing keepalives after a pod roll killed the upstream leg) shows
  GREEN but is `agent_offline`; agents ≥rc.293 self-heal in ≤~2 min via a
  receive-liveness deadline.
- **After every roll, field-verify from the fleet** — pods on the new image,
  online-agent count, an RC session, an overlay pair, a tunnel forward. The
  workflow only proves the public `/health` kept answering. ⚠️ An exec sweep is a
  **biased sample** (it reaches only what is online) — query the server for the
  denominator.

## Functional Requirements (FR) workflow — STANDING RULE (operator, 2026-08-27)

Every substantial feature or multi-step program — a new capability, a performance
arc, a protocol change, anything bigger than a one-PR fix — gets a **Functional
Requirement** tracked in GitHub. **Creating the FR is a step of the PLAN**, not a
write-up filed afterwards. Registry and full protocol: **`docs/fr/README.md`**.

0. **Open the issue BEFORE you implement.** It is the only collision guard that
   actually works: a memory file is invisible to a parallel session, an open issue
   is not. Re-fetch master and list open FR issues before starting.
1. **Spec doc** `docs/fr/FR-N-<slug>.md`: goal, root-cause/field evidence, key
   design with `file:line` anchors verified against master, a phase/status table
   with each phase's kill switch, acceptance criteria as checkboxes, open
   decisions, out-of-scope, and a field-verification log.
   ⚠️ **Claim the number by adding your row to `docs/fr/README.md` in the same
   commit as the spec** — never by scanning the directory. Two sessions both read
   `max = N`, both write `FR-N+1`, and git merges them without a murmur because
   they touched *different* files (measured three times in one day, twice while a
   scan-and-re-verify rule was already in force). Editing one shared table makes
   git the arbiter instead: the loser's push is rejected as non-fast-forward.
   Enforced by `scripts/fr-registry-audit.sh` + CI.
   ⚠️ If one still slips through: **the LOWER issue number keeps `FR-N`, the HIGHER
   renumbers** — title, spec filename, ledger row and in-body references together,
   to the next free N, never into a vacated one. Issue ids are server-assigned and
   monotonic, so two sessions that never talk compute the same winner. Numbers
   already settled STAY settled.
2. **GitHub issue** `FR-N: <title>` with the spec link, and Goal / Key design /
   Acceptance criteria / Open decisions / Out of scope / Related.
3. **Comment as you ship** — a `## Step log` table appended as each PR merges, and
   a `## Result — field-verified on <version>` carrying the actual measurement.
   ⚠️ **CI green is not a result.** A field test must be shown to FAIL on the
   current deploy first, or its pass proves nothing — record both runs. Record the
   wrong turns too; a dead end documented is often the most valuable line in the log.
4. **Close** only when the acceptance criteria are field-verified; a regression
   reopens it with the evidence.
   ⚠️ **Tick the boxes in the same breath as the close** — the ticks *are* the
   record that the verification happened, and an unticked criterion on a closed
   issue cannot afterwards be told apart from one that was never verified.
   Measured: 8 closed FRs carrying 28 unticked criteria on 2026-09-01, **19
   carrying 74** three weeks later, entirely unobserved. Enforced by
   `scripts/fr-verification-debt.sh` + a daily lane — scheduled, not just
   push-triggered, because closing an issue leaves no trace in the repo at all.
   Pre-existing debt is pinned per-FR in `scripts/fr-ac-debt-baseline.txt`, each
   line saying *why* that FR closed without them.
5. **Docs before close** (operator, 2026-09-05): closing requires the docs that
   describe what it built to be updated or created, in the house style of the other
   `docs/*.md` — **mermaid diagrams**, tables, callouts, `file:line` anchors, and a
   row in `docs/README.md`'s index. It is a phase row *and* an acceptance criterion
   in every spec, ticked before the close.
   ⚠️ Enforced by the same `scripts/fr-verification-debt.sh`: a spec **bound** by
   this rule — its issue opened, or it closed, after the rule reached master
   (#1401, 2026-09-05T20:49Z) — must carry the docs criterion, recognised by its
   `docs/README.md` index-row commitment. Without it the ticked-box check cannot
   see the docs at all: FR-81 had every box ticked and nothing public documenting it.

## Post-Implementation Testing

Run the **most specific** command first; if a backend change also affects the
frontend, run both.

| Change type | Command |
|---|---|
| Backend (models, services, routes) | `cargo test -p meshharbor-tests` |
| Remote-control crate (signalling, wire format) | `cargo test -p meshharbor-remote-control --lib` |
| Agent library | `cargo test -p meshharbord --lib` |
| Agent with media / input backends | `cargo test -p meshharbord --lib --features full` |
| Agent capture, headless | `./scripts/dev-xvfb.sh` |
| Frontend | `cd ui && bun run build` |
| Frontend unit | `cd ui && bun run test:unit` |
| Full flow | `cd ui && bun run e2e` |

⚠️ The agent builds and unit-tests **natively on Windows**
(`cargo test -p meshharbord --lib`) — the WSL lane is not the only option.

## The three pillars — invariants, and where the detail lives

`docs/README.md` is the navigable index. This section holds only what must be true
without opening any of them.

### Remote desktop

Design: `docs/remote-control.md` · encoders: `docs/encoders.md` + the
`encoder-cells` skill · rate control: `docs/rate-control.md`.

One native agent per controlled host, the API as a **signalling-only** relay, the
browser as controller. All media + input flow over direct WebRTC P2P (TURN-relayed
if needed) — the server never sees raw pixels or keystrokes.

**Wire**: `rc:*` JSON over the existing `/ws`. `ClientMsg`/`ServerMsg` in
`crates/remote_control/src/signaling.rs`. ObjectIds are raw hex strings and
`Permissions` serialises pipe-separated (bitflags 2.x convention) — both locked by
tests.

**Agent capability verbs** (`AgentCaps.rpc`): the wire stays `Vec<String>` because
fleet agents span many releases and a typed wire format would strand them, but both
sides go through **`models::RpcCap`**. Adding a verb: variant → `wire()` arm (the
match is exhaustive, so the compiler makes you) → `ALL` entry (a test makes you).
⚠️ Unrecognised verbs are **IGNORED, never an error** — a newer agent may advertise
something this server has never heard of, and an additive list is only additive if
old readers skip what they don't know.
⚠️ **`ssh` is a PREFIX of `ssh-consent`** ("runs a server" vs "honours
`consent_mode`"), and `config` is a prefix of `config-report`. Matching must stay
**equality** — `starts_with`/`contains` would silently mark every ssh-capable agent
consent-capable, fleet-wide. Locked by `ssh_does_not_imply_ssh_consent`.
⚠️ The wire spellings are a compatibility surface: renaming one doesn't fail
loudly, it makes every deployed device look like it lacks the feature.

### Networking

Start at `docs/overlay-communication.md`. Sub-topics: `overlay-nat-traversal.md`,
`overlay-exit-nodes.md`, `overlay-wfp.md`, `multi-org.md`, `magicdns.md`,
`tunnels.md`, `tunnel-install.md`, `roomler-ssh.md`, `fleet-rpc.md`,
`remote-config.md`, `ephemeral-nodes.md`, `device-naming.md`,
`peer-relays.md`.

**Overlay address leases** (`docs/overlay-communication.md` §1) — the release order
is load-bearing: read peers while live → **CAS-tombstone** (winning the CAS is the
release *token*, so two concurrent removals can't pool one host twice) → pool the
host → fan `netmap_delta{removes}`.
⚠️ **Pooling before the tombstone** would hand the address out while the old row
still held it, and the unique index would lock that joiner out **permanently**.
This order only ever *leaks* a host.
⚠️ Rows are **tombstoned, not deleted**, and lookups are live-scoped ⇒ **removal is
final**: a re-enrolled machine gets a fresh lease, never the revived tombstone.
Evict = "force a new lease", **not** a ban.
⚠️ Client-side teardown is keyed by **pubkey**, never by IP.

**Overlay exit nodes** (`docs/overlay-exit-nodes.md`, default-OFF) — an admin
approval writes `is_exit_node` **and** adds `/0` to `approved_routes`; the route
list is the data-plane signal, not the flag alone. Core invariant = **never
self-wedge**: pin `/32`/`/128` carrier + control exemptions first, then install the
split-default, else WITHHOLD.
⚠️ An exit reroutes the host's own *inbound*-reply traffic, so it breaks
un-exempted SSH — and never run the exit field-test on a prod cluster node.

**Multi-org** (`docs/multi-org.md`) — ONE multi-tenant daemon, never N side-by-side
installs. The config's scalar identity stays the PRIMARY enrollment (rollback-safe);
secondaries live in `[[orgs]]` with their **own freshly-minted WG key** (never a
copy — cross-org pubkey correlation), and `rc:agent.update` is honoured only from
the primary.
⚠️ Every legacy tenant shares `100.64.0.0/10`, so tenant A's and tenant B's
`100.64.0.7` are the **same address**. Carved blocks are disjoint by construction
(uniquely-indexed `slot`, buddy-aligned starts — the index arbitrates concurrent
claims, no lock). Freed blocks are **quarantined, never re-issued**: a device that
missed the migration still believes it holds an address there.
⚠️ Joining a **secondary** org does not start its WS loop — the daemon must be
restarted. Signature: `last_seen_at == created_at` forever.

**Peer relays** (FR-19) — a tenant-owned `roomlerd` forwards **ciphertext** between
two nodes of the same tenant over UDP **3478** (the one port the symmetric-NAT corp
population was measured to reach; 41641 and the coturn band are dead for it). Four
default-deny gates, each owned by a different party, every decision audited in
`peer_relay_audit`.
⚠️ It is a third `RelayKind` behind the existing `RelayConn` seam, **not** a new
tier — `is_direct()` reads any new tier variant as DIRECT, silently.
⚠️ Serving **and** use are **primary-org only** — a UDP listener is host-global and
a secondary org's admin must not mint onto the device owner's listener.
⚠️ `static_endpoints` are public `ip:port` literals only, checked at the route
**and** at mint time — a server-pushed probe target is a port scanner run by every
device in the tenant as SYSTEM/root.
⚠️ Org relay engages on a **ladder climb, not the mode flip**: a pair on a healthy
DERP floor won't re-request until it churns.

**Roomler SSH** (`docs/roomler-ssh.md`) — SSH into any node by overlay address with
**no `sshd`, no bound port, no firewall rule**; packets are intercepted below the OS
by `SplitTun`. That is not an elegance choice: binding `overlay:22` fails
EADDRINUSE wherever sshd covers `0.0.0.0:22`, and a corp-managed laptop cannot have
sshd at all. Interception also leaves nothing for an EDR agent to terminate. Four
default-deny gates; `ssh_enabled` alone grants nothing (empty `ssh_authorized_keys`
= nobody).
⚠️ `-R` is **deliberately not implemented** — it would make the device bind a
listening socket, the one thing this design exists to avoid.
⚠️ `direct-tcpip` reads `forward_acl` **default-DENY, the opposite sense to the
tunnel path that shares the struct**: a tunnel flow was already authorized by the
server, but an SSH channel has no server in the path at all, so empty must mean
*nowhere* or every session is a silent open pivot.
⚠️ A key-list session with an unset `ssh_account_mode` authenticates and then runs
**nothing**, rather than quietly taking SYSTEM/root. An unparseable mode is a
refusal, never a fallback.
⚠️ **Session CONTENT is never recorded** — recording a terminal means shipping
whatever the operator typed (passwords into `sudo`, `mysql -p`) off the host, which
is the exact property this pillar exists to provide.
⚠️ `ssh_audit` is the server's own **decision** (authoritative); `ssh_activity` is a
**claim by a host that may be compromised**. Two collections on purpose; join on
`grant_id`. **An empty activity result is not evidence of inactivity** — the
device-owned `ssh_activity_log` defaults to off.

**Fleet RPC** (`docs/fleet-rpc.md`) — `roomler exec` over the agent's **existing
control WS**, deliberately not the overlay: the diagnostics this exists for are most
needed when the mesh is broken. Four independent default-deny gates, the last of
which (`exec_enabled` on the device) is the only refusal that survives a compromised
server.
⚠️ Who runs a command: **root under systemd**. On Windows, **SYSTEM in session 0
through the device's service once an administrator anchored it** (FR-94:
`roomlerd anchor create`, elevated); otherwise the process that holds the agent
socket, the console-session **worker**, which is the signed-in user on an attended
install and SYSTEM in SystemContext mode. ⚠️⚠️ On the SYSTEM path the service takes
**nothing but a request id** from the worker (the user's process): the command is
claimed from the server with the anchor's own credential, and the result goes back
to the server, never to a local pipe. Nothing the signed-in user can write may
decide what SYSTEM runs; `docs/fleet-rpc.md` § Privilege.
⚠️ A caller **awaits** this frame, so unlike `Goodbye`/`UpdateNow` it must gate on
`AgentCaps.rpc` containing `exec` (412 otherwise) — pushing to a pre-feature agent
would hang the caller until its deadline.
⚠️ `roomler exec` **re-splits argv**: Windows targets need ONE quoted argument, and
`;` never `&&`. On a host that restarts its own service it answers "no answer within
45 s" — the command ran.

**Remote configuration** (`docs/remote-config.md`) — the design constraint is **make
the device remotely configurable without making it server-configurable**.
Resolution: a device-owned `remote_config_enabled`, default OFF, **structurally
absent from `DesiredConfig`** (a test asserts it never appears in a serialised
request). Delivery is **reconcile-on-connect only**, so an offline device converges
by the same code path as an online one.
⚠️ **The device REPORTS BACK** — without it, *applied / applied-pending-restart /
refused-not-opted-in / refused-secondary-org / never-arrived* are ONE state on
screen, and each has a different fix. **Compare revisions, not just outcomes.**
⚠️ **Local edits are live too** (`adopt_local`) — making a server push live while
the owner's own edit waited for a restart inverts the very property gate 4 exists
for.
⚠️ **Remote configuration never restarts a daemon** — exiting an orphan `roomlerd
run` host takes it permanently offline. The one restart path is LOCAL (LocalAPI
`RestartDaemon`: "Apply now", `roomler restart`, FR-84 D3), and it refuses unless it
can PROVE a supervisor (`agents/meshharbord/src/supervision.rs`).

**Linux root daemons resolve `/etc/roomler/config.toml`** (rc.435,
`docs/installation.md`). ⚠️ `systemctl is-active` reads **inactive while such a host
is perfectly healthy** (the live daemon is an unmanaged orphan) — check
`pgrep -x roomlerd` and `roomler peers`, and never "restart to fix" on that basis.

**Declared tunnel routes** — `roomlerd` supervises forwards/SOCKS5 listeners
declared as `[[tunnel_routes]]` in its config, reconciled into hub flows on every
start (`docs/tunnel-install.md` §6).

⚠️ **A WebRTC peer MUST be `close()`d — dropping it frees NOTHING.** Its UDP sockets
are owned by tasks the ICE agent spawned, not by the struct, so an `Arc` drop leaves
every one of them live. This once consumed the entire ephemeral port range and
**took host DNS down** while `ping 1.1.1.1` stayed at 3 ms. That signature — names
unresolvable, IPs fine — is socket exhaustion, **not** a DNS-server problem. Full
note, with the diagnostic one-liner: `docs/tunnels.md`.

### Collaboration

`docs/real-time.md` (the WebSocket surfaces: user events, presence, mediasoup
signalling, DERP) · `docs/ui.md` (frontend map).

### Installation and packaging

`docs/installation.md` · `docs/code-signing.md` · the **`ship-it` skill**.

ONE unified wizard (`agents/meshharbor-setup`, Tauri 2) covers every role; backend
proxies under `/api/setup/*` and `/api/agent/installer/*` stream installer bytes
through `roomler.ai` (**not** `github.com`) so corporate ESET/Defender allow-lists
trust the download.

⚠️ **UAC lib-naming rule** — Windows UAC's "installer detection" heuristic
auto-elevates any EXE whose filename contains "install"/"setup"/"update"/"patch",
and cargo derives test-binary names from the **lib** crate, so wizard lib targets
must dodge those substrings (`wizard_app`, `wizard_shared`). The user-facing bin
keeps the marketing name; `[[bin]] test = false` keeps `cargo test -p meshharbor-setup`
off the UAC prompt.
<!-- RETIRED-NAME-ANCHOR(2): these two directories were DELETED under their
     retired names. A history line has to name what actually existed; an
     earlier path sweep rewrote one of them into agents/meshharbor-cli-installer,
     a directory git has never heard of. FR-21 D6. -->
⚠️ The legacy wizards `agents/meshharbor-installer` (rc.28) and
`agents/meshharbor-tunnel-installer` (rc.59) were retired in P4c-2. The tunnel CLI's
`self-update` is **kept** — it is the sole updater for tunnel-only hosts ("one
updater" is per-role; daemon hosts get `meshharbor.exe` refreshed by the MSI).

## Known Issues (OPEN only)

Fixed-and-shipped issues live in `git log` and the docs. Currently open:

- **[MEDIUM]** [2026-08-23] **User sessions are irrevocable** — no `token_epoch`
  check, no password-change route, no refresh rotation. `docs/security-baseline.md` §1.
- **[MEDIUM]** [2026-08-23] **The updater's manifest is unsigned** — version + url +
  hash are not attested as a unit. Publisher trust on the
  artifact itself is closed on all three platforms (`ship-it` skill §3), and so,
  since FR-97 P6a, is the downgrade the manifest allowed: every installable must state
  the claimed version inside its signed bytes (`docs/code-signing.md` §7b), so a
  hostile manifest can withhold an update but no longer swap in an older one. The
  tunnel CLI's `self-update` is key-pinned too since FR-97 P6b (tunnel-core's
  `pgp_verify`, every OS), from the first tunnel release that carries it.
- **[MEDIUM]** [2026-04-17, rewritten 2026-08-29 by **FR-27**, #854] Host consent now
  has a **`PromptSurface` chain** — native (`win`·`mac`·`x11`) → companion
  (`meshharbor-desktop` over LocalAPI) → notification (Linux, the desktop's own, with
  Approve/Deny: FR-93 P6f) → cli (`roomlerd consent`) → none, which reports
  `no_prompt_surface` instead of a silent deny, and the chosen surface is logged per
  prompt (before it, "the prompt didn't appear" was unattributable). ⚠️ On
  **Wayland** the native panel is the X11 one, through Xwayland: a per-user daemon
  shows it, with no guarantee of stacking above native windows (mutter offers no
  `wlr-layer-shell` at all; KWin offers `zwlr_layer_shell_v1`, but only to a native
  Wayland client, #2286), and a root daemon has no `DISPLAY` and falls through to the
  companion **by design, not by omission**. ⚠️ An agent-side prompt **timeout** must not come back as a bare
  `granted:false` — "nobody was at the machine" reaching the controller as "a human
  refused you"; the hub waits 5 s **longer** than the window it announces, because
  with equal timers its own fallback fired ~130 ms before the agent's reasoned
  verdict. ⚠️ A server directive must never override a device's
  `auto_grant_session=false` — `consent::strictest_of` makes the local setting a
  floor.
<!-- RETIRED-NAME-ANCHOR: the env-var spelling on the line below carries a
     retired product name deliberately — it is what the daemon actually reads,
     so renaming it would silently disable every virtual-desktop host. FR-27. -->
  ⚠️ A `MESHHARBOR_AGENT_VIRTUAL_DESKTOP=1` host is **not** a consent surface even
  though its X display connects: the only viewer of that Xvfb is a remote
  controller, so an unattended host reports `timeout` where the truth is
  `no_prompt_surface`, and an attended one lets viewer A approve viewer B.
  Still unverified: `prompt_owner`, `no_prompt_surface`, two concurrent viewers,
  `email`/`push`, and the macOS/X11 panels. Detail: `docs/fr/FR-27-*.md`.
- **[LOW]** [2026-08-03] Overlay ACL is feature-complete but **not field-proven
  under `enforce`**. ⚠️ `ingress_rules` is `Option`: `None` = no ACL compiled (fall
  back to the coarse scope), `Some([])` = **deny** — never collapse them. Rules ship
  ONLY under `enforce`, so `warn` can never cause a node to drop. Flip a tenant to
  `warn` first and read `rx_denied` before cutting over.
- **[LOW]** [2026-08-26] **`roomler self-update` verifies only the same-channel
  SHA-256 and fails OPEN when the manifest carries no digest** — the same hole the
  agent updater closed, in the binary that is the sole updater on tunnel-only hosts.
  Rated LOW after measuring the exposure: it has exactly one caller, the manual
  subcommand — no timer, no daemon-driven invocation. **Fixed on master by FR-97 P6b,
  open until a tunnel release ships it**: the CLI requires the artifact's `.asc`
  against the pinned key on every OS (`pgp_verify`, moved to `crates/tunnel-core`).
  ⚠️ It shares the PGP check, NOT `code_signature.rs`: WinTrust stays in `roomlerd`
  (tunnel-core is on `windows-sys` **0.61**, the agent on **0.59**), and no OS needed
  it, because Windows takes the same `.asc` check.
- **[LOW]** [2026-04-20] NVENC `ActivateObject` returns 0x8000FFFF on RTX 5090
  Blackwell for H.264/HEVC/AV1 MFTs regardless of adapter binding. The cascade routes
  around it; AV1 has no alternative and is filtered from advertised caps by the
  probe. Worth re-testing on newer drivers.
- **[LOW]** [2026-03-10] No git hooks for linting and no secret scanner
  (gitleaks/trufflehog) in CI.

## Security Baseline

Full treatment, with the reasoning behind every control:
**[`docs/security-baseline.md`](docs/security-baseline.md)**. Permission bits and
the managed-role reconcile: `docs/permissions.md`. The rules that bind new code:

- **`is_member(tid)` is NOT an authorization check for anything keyed by id.**
  Anyone can create a tenant for free, so a caller can always satisfy `is_member`
  for a tenant they own and then pass **another** tenant's `room_id`/`message_id`.
  Resolve the object **within** the tenant: `helpers::require_room_in_tenant` /
  `require_message_in_tenant`, so a foreign id 404s and leaks neither content nor
  existence. ⚠️ A handler keyed by `message_id` must use the **message** guard — the
  two ids are decoupled. ⚠️ Never re-fetch with a bare `find_by_id` after a
  tenant-scoped write.
- **A 403 is an answer, not an expired credential.** It never ends a session, on any
  method. The only 403 with a navigation is `not_a_member`, matched on a
  **server-sent code**, never a message-string sniff — chat's
  `Forbidden("Not a member of this room")` is the same shape and must not evict
  anyone from their org. ⚠️⚠️ An unclassified 403 does nothing but throw, so a
  newly-gated route is inert on the client by construction.
- **A system-managed role is reconciled, not frozen at its birthday** — one
  `role::MANAGED_ROLES` table, reconciled at boot under the startup lease.
  ⚠️⚠️ **Additive (`stored | definition`), never a replace** — a managed mask *is*
  editable, so overwriting would silently revoke an org's own grant.
  ⚠️⚠️ `EXEC_DEVICE`/`SSH_DEVICE` are in no row below the `ADMINISTRATOR` bypass:
  `DEFAULT_ADMIN |= EXEC_DEVICE` — a one-token edit that reads as tidying — would
  open exec-as-SYSTEM deployment-wide at the next boot, with no migration to review
  and no admin action to audit.
- **`users.email` holds an address only if that account PROVED it.** It is a UNIQUE
  index, so it is a *reservation*, not a contact field, and it is what
  account-linking keys off. An unverified provider assertion takes a `.invalid`
  placeholder; linking checks the **target** account is verified too; a proven
  identity **evicts** an unproven claim. ⚠️ Do not "simplify" this back to a
  one-sided `email_verified` check — that state left both the reservation and the
  unactivated-signup paths open. ⚠️ Microsoft is the only provider that is *always*
  unverified.
- **Agent tokens are status-checked on every use** via
  `crates/api/src/extractors/agent.rs::AuthAgent`. ⚠️ A lookup **failure is 500, not
  401** — a Mongo blip must not tell a healthy fleet its credentials were revoked,
  turning a database wobble into an enrollment storm. ⚠️ **Deletion wins over
  status**: an Online-looking tombstone still refuses.
- **A WG public key cannot be claimed by two live nodes in a network**
  (`wg_key_taken_by_other`, fail-CLOSED). Nothing proves possession of the private
  half, and the key is an *addressing* key — DERP authorizes registration against
  it, WireGuard keys peers by it.
- **Push endpoints are SSRF-validated at subscribe time** — the server POSTs to a
  browser-supplied URL from inside the cluster on every fan-out.
- **Uploads are sniffed, never trusted** (`crate::media_type::resolve`); the
  extension fallback structurally cannot produce `image/*` or `text/html`, which are
  exactly the types worth lying about.
- **The message-HTML allowlist is a security control** —
  `ui/src/composables/useMarkdown.ts` deliberately excludes `style`, and it is the
  ONLY XSS boundary for message content.
- **The CSP allowlist contains loopback origins on purpose** (`http://127.0.0.1:*`)
  — the RC viewer probes the local agent's loopback-TURN relay and clipboard bridge.
  ⚠️ When touching CSP, exercise the remote-control page, not just the main SPA.
- **Publishing identity is an allowlist at four layers.** This repo is **public**,
  and a commit's author email and a GitHub account login leak *who* rather than
  *what* — both invisible to the machine-name guards. ⚠️ `gh auth switch` is
  **global**; use `scripts/gh-scoped-config.sh`. ⚠️ Neither leak is recoverable
  downstream.
- **Prod refuses to boot on the default JWT secret**; session cookies carry `Secure`
  in production; CORS defaults to the frontend's own origin only; `tower_governor`
  caps 60 req/min per IP, and exec/SSH additionally have per-(caller, device)
  ceilings enforced **after** the identity gates so a refusal is attributable.
