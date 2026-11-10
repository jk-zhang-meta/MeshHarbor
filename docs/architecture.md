# Architecture

MeshHarbor is one Rust server, one Vue SPA, and a small fleet of native binaries that
turn every enrolled machine into a remote-desktop target, a tunnel exit, and an
overlay-mesh node. This page is the map; every subsystem has a deeper doc linked
along the way. (Counts stamped *as of 0.3.0-rc.381.*)

## System at a glance

```mermaid
flowchart TB
    subgraph clients["Clients"]
        SPA["Vue 3 SPA<br/>chat · calls · remote viewer<br/>admin · observability"]
        CLI["meshharbor CLI<br/>forward · socks5 · exec · ping"]
        DESK["meshharbor-desktop<br/>tray companion (Tauri)"]
    end

    subgraph server["meshharbor.itachi.fans — Axum API pod(s)"]
        NG["nginx<br/>SPA + /api + /ws + /derp proxy"]
        API["meshharbor-api<br/>REST + WebSocket + signalling"]
        SFU["mediasoup SFU<br/>(in-process workers)"]
        DERPD["/derp relay<br/>(pubkey-addressed WSS)"]
    end

    subgraph data["Data & infra"]
        MONGO[("MongoDB")]
        REDIS[("Redis<br/>pub/sub fan-out")]
        S3[("MinIO / S3<br/>files · recordings")]
        TURN["coturn<br/>TURN/STUN"]
        POP["derp-relay PoPs<br/>(standalone, DB-free)"]
    end

    subgraph fleet["Enrolled machines"]
        D1["meshharbord daemon<br/>capture · encode · input<br/>tunnel exit · overlay node"]
        D2["meshharbord daemon"]
    end

    SPA -->|REST /api| NG --> API
    SPA <-->|"/ws (user role)"| API
    SPA <-->|"WebRTC RTP"| SFU
    CLI <-->|"/ws (tunnel-client role)"| API
    DESK <-->|LocalAPI| D1
    D1 <-->|"/ws?role=agent (outbound WSS)"| API
    D2 <--> API
    API --- MONGO & REDIS & S3
    SPA <==>|"WebRTC P2P — remote desktop"| D1
    CLI <==>|"QUIC / WebRTC DC — tunnels"| D2
    D1 <-.->|"WireGuard overlay"| D2
    SPA & D1 & D2 -.->|fallback| TURN
    D1 & D2 -.->|"both UDP-blocked"| DERPD
    D1 & D2 -.-> POP
```

## Control plane vs three data planes

The server is a **coordination point, not a data path**. Each pillar has its own
data plane with its own transport and encryption; the server only ever brokers
sessions, enforces policy, and (for conferencing) mixes nothing — the SFU forwards
RTP without decoding it.

```mermaid
flowchart LR
    subgraph cp["Control plane — always through meshharbor.itachi.fans"]
        C1["auth · enrollment · consent<br/>ACL policy · signalling · audit"]
    end

    subgraph dp["Data planes"]
        P1["💬 Conference media<br/>browser ⇄ mediasoup SFU<br/>WebRTC RTP (DTLS-SRTP)"]
        P2["🖥️ Remote desktop<br/>browser ⇄ meshharbord, P2P<br/>WebRTC RTP + DataChannels"]
        P3["🌐 Overlay & tunnels<br/>node ⇄ node WireGuard<br/>tunnels over QUIC / WebRTC DC"]
    end

    C1 -.->|"session setup only"| P1 & P2 & P3
```

| Plane | Endpoints | Direct path | Fallback ladder | Server sees |
|---|---|---|---|---|
| Conference | browser ⇄ server SFU | always via SFU | — | encrypted RTP it routes (SFU model) |
| Remote desktop | browser ⇄ `meshharbord` | ICE P2P | host → STUN srflx → TURN (UDP → TCP/TLS :443) | signalling only; TURN relays ciphertext |
| Overlay mesh | `meshharbord`/CLI ⇄ peer | LAN → public → srflx hole-punch | TURN relay (QUIC-upgraded) → DERP over WSS :443 | netmaps + relay grants; WG ciphertext only |

Key invariants:

- **The server never sees pixels, keystrokes, clipboard, files, or overlay
  plaintext.** Remote-desktop media and input ride P2P WebRTC (E2E-encrypted);
  overlay packets are WireGuard-encrypted end to end; TURN and DERP forward bytes
  they cannot decrypt.
- **Everything is tenant-scoped.** Every route nests under
  `/api/tenant/{tenant_id}/…`, every collection carries `tenant_id`, and the six
  JWT audiences (below) cannot impersonate one another.
- **Agents dial out only.** A `meshharbord` daemon holds one outbound WSS control
  connection; no inbound port is ever required on an enrolled machine.

## Workspace map

One Cargo workspace builds the server and every native binary.
`config ← db ← remote_control ← services ← api` remains the server spine; the
agent stack layers on shared leaf crates so thin clients never link the world.

```mermaid
flowchart BT
    config["crates/config<br/>settings (MESHHARBOR__ env)"]
    db["crates/db<br/>Mongo models + indexes"]
    core["crates/core → meshharbor-core<br/>Core · module contract · composition snapshot"]
    saas["crates/modules/saas → meshharbor-mod-saas<br/>Stripe · newsletter · plan compliance (add-on)"]
    chat["crates/modules/chat → meshharbor-mod-chat<br/>rooms · messages · files · search · typing"]
    conference["crates/modules/conference → meshharbor-mod-conference<br/>mediasoup SFU · media:* · calls · recordings"]
    fleet["crates/modules/fleet → meshharbor-mod-fleet<br/>agents · enrollment · presence · Hub · consent · exec · releases"]
    remote["crates/modules/remote → meshharbor-mod-remote<br/>RC sessions · controller rc:* dispatch · cross-pod rc relay · TURN creds"]
    network["crates/modules/network → meshharbor-mod-network<br/>overlay engine · tunnels · peer relays · SSH · key rotation · DERP ACL"]
    rc["crates/remote_control<br/>signalling · consent · wire types¹ · ACL shapes"]
    services["crates/services<br/>DAOs · auth · billing · export"]
    api["crates/api<br/>Axum: core REST + /ws · composes the modules (/derp is network's)"]
    tests["crates/tests<br/>integration suite"]

    localapi["crates/localapi<br/>LocalAPI wire types + client"]
    agentcore["crates/agent-core<br/>config · enrollment · machine-id"]
    tunnelcore["crates/tunnel-core<br/>tunnels · transports · overlay (WG)"]
    tcpturn["crates/tcp-turn-conn<br/>TURNS/TCP adapter"]
    derprelay["crates/derp-relay<br/>standalone DERP PoP"]
    setupcore["crates/meshharbor-setup-core<br/>installer mechanics"]

    meshharbord["agents/meshharbord → meshharbord<br/>the daemon"]
    tunnel["agents/meshharbor-cli → meshharbor<br/>tunnel CLI (surface lives in its lib)"]
    shim["agents/meshharbor-cli-shim<br/>mh.exe on daemon hosts → re-execs meshharbord cli"]
    tray["agents/meshharbor-desktop → meshharbor-desktop"]
    setup["agents/meshharbor-setup<br/>install wizard (Tauri)"]

    db --> config
    core --> services
    saas --> core
    chat --> core
    conference --> core & chat
    fleet --> core & rc
    remote --> fleet & core & rc
    network --> fleet & core & rc & tunnelcore
    rc --> db
    services --> rc
    api --> services & core & saas & chat & conference & fleet & remote & network
    tests --> api & meshharbord & core

    tunnelcore --> localapi & tcpturn & rc
    agentcore --> config
    meshharbord --> tunnelcore & agentcore
    tunnel --> tunnelcore
    tray --> localapi & agentcore
    setup --> setupcore
    derprelay --> rc
```

¹ `remote_control`'s Mongo-backed part (the audit sink; the session Hub has been the
`fleet` module's since FR-69 P5a) sits behind a
default-on `server` cargo feature; agent-side consumers disable it, which keeps the
MongoDB driver out of every shipped native binary.

**Vendored forks** (workspace-excluded, wired via `[patch.crates-io]` — the *why*
is documented at the top of the root `Cargo.toml`):

| Fork | Reason |
|---|---|
| `crates/vendored/rtp` | H.265 payloader fix — upstream drops NALs after VPS/SPS/PPS aggregation, PLI-storming Chrome |
| `crates/vendored/webrtc-ice` | TURNS-over-TLS-over-TCP relay candidates (upstream closed NOT_PLANNED) — corp networks that block all UDP |
| `crates/vendored/webrtc` | exposes SCTP `a_rwnd` so native⇄native DataChannels advertise 8 MiB and stay link-bound at high BDP; `TrackLocalStaticSample::write_sample_after_gap` (#2284), which advances the RTP clock by the gap before a sample and stamps it with its own time, where upstream advances after it |
| `crates/vendored/wintun-bindings` | keeps the Windows NetworkList registry entry on drop |
| `crates/vendored/smoltcp` | the overlay netstack's TCP: the congestion window bounds bytes in flight (upstream it never did), and Reno is a NewReno-lite |

## Modular monolith — the shipped shape (FR-69)

The server is a **modular monolith** — the same process, the same container, the same wire —
composed from a small core and six module crates behind one `Module` contract, selected into
build **profiles** by Cargo features and discovered at run time through `GET /api/capabilities`.
[FR-69](fr/FR-69-modular-monolith.md) built it (P0–P9, closed 2026-09-05); the deep-dive with the
contract, the profiles, the wire ownership, the hooks and the composition gate is
**[modular-monolith.md](modular-monolith.md)**. The shape:

```mermaid
flowchart BT
    core["crates/core → meshharbor-core<br/>identity · tenancy · plans · notifications · storage<br/>/ws socket + fan-out · cluster · TURN creds · metering"]
    fleet["modules/fleet<br/>agents · enrollment · presence · Hub · consent · exec · releases"]
    chat["modules/chat<br/>rooms · messages · files · search · export"]
    conference["modules/conference<br/>mediasoup · media:* · recordings"]
    remote["modules/remote<br/>RC sessions · sdp/ice · rc relay"]
    network["modules/network<br/>overlay · tunnels · DERP · peer relays · SSH"]
    saas["modules/saas (add-on)<br/>Stripe · newsletter · plan compliance"]
    fleet --> core
    chat --> core
    saas --> core
    conference --> chat
    remote --> fleet
    network --> fleet
```

The rules that keep it a monolith rather than a pile of crates:

- **One contract.** Every module implements `meshharbor_core::Module` — routes, WebSocket
  namespaces, index specs, jobs, lifecycle hooks, capabilities — and the host composes the
  concrete types under `#[cfg(feature)]`. No dynamic loading, no runtime registry.
- **A DAG, not peers.** Any module may call core; `conference → chat`, `remote → fleet`,
  `network → fleet`, `hive → fleet`, `hive → chat`. Core never calls a module: the inverse flows (tenant
  archive, agent removal, member removal) are hooks that core invokes in a fixed order.
- **Core membership.** Something lives in core only if at least two modules need it **and** it is
  identity, tenancy or infrastructure. Everything else belongs to a module.
- **Profiles, not switches.** Cargo features select the pillars a build links (`full`, `collab`,
  `remote`, `mesh`, `access`; `saas` as an add-on the self-host images never carry). What a
  running server offers is discovered through `GET /api/capabilities`, so one UI build and one
  daemon work against any profile.
- **The wire and the documents do not move.** One `/ws` socket with an exhaustive
  `ClientMsg::namespace()` map; `/derp` unchanged; DAOs and indexes change owner, never shape.
- **Every move is checked.** A composition baseline — routes with their allowed methods, the
  index plan, the wire names — is asserted byte-identical after each module PR.

**Crate naming, as of FR-69.** Server-side crates are `meshharbor-*`; the server core is
**`meshharbor-core`** (`crates/core`, AGPL-3.0-only); module crates are `meshharbor-mod-<name>`.
The daemon's shared building blocks — config, enrollment, machine-id, logging — are
**`meshharbor-node-core`** (`crates/agent-core`, MPL-2.0), which held the name `meshharbor-core` from
FR-21 until FR-69. Its pre-FR-21 name is retired (FR-21); do not bring it back.

## The native stack on an enrolled machine

| Binary | Role |
|---|---|
| **`meshharbord`** | The daemon: WS signalling, per-session WebRTC peers, capture → encode → RTP/DC, input injection, clipboard/file/apps/audio channels, tunnel *target* and tunnel *client* sides, overlay node runtime, LocalAPI server, loopback TURN host, watchdog, self-updater, Windows SCM/SystemContext machinery |
| **`mh`** | The CLI. On tunnel-only hosts it is the full standalone binary; on daemon hosts the MSI/.deb installs a ~150 KB shim that re-execs `meshharbord cli` — one command surface (`meshharbor_cli::cli`), never version-skewed against the daemon |
| **`meshharbor-desktop`** | Tauri tray companion: node status, peers, tunnels, consent prompts — a thin LocalAPI client with zero transport crates |
| **`meshharbor-setup`** | The unified install wizard ([installation.md](installation.md)) |

The **LocalAPI** (named pipe `\\.\pipe\meshharbor` on Windows, `$XDG_RUNTIME_DIR/meshharbor.sock`
elsewhere) is the on-host control surface all three clients share — status, peers,
flows, routes, consent decisions. Protocol reference: [tunnels.md](tunnels.md).

A **system** daemon listens at `/var/run/meshharbor/meshharbor.sock`, and also at the legacy
per-user path, for CLIs that predate the split. On macOS a per-user half answers a socket
of its own. So two existing paths are not two daemons. When both exist, the CLI asks each
for its peer's PID, and adds "a second meshharbor daemon is running" only when two processes
answer (#2511). One process behind both is the system daemon's legacy bind, which every
root `mh status` used to report as a second daemon.

## Request flow & auth

```
Browser/CLI/daemon ──► nginx ──► Axum router
                                   ├─ per-IP governor (all /api)
                                   ├─ per-(IP, account) brute-force gate (login/register)
                                   ├─ JWT middleware (audience-checked)
                                   └─ handler ─► services (DAO) ─► MongoDB
                                              └─► Redis pub/sub ─► every pod ─► /ws clients
```

Six JWT audiences, all signed with the server secret, none interchangeable:
`Access` / `Refresh` (users), `Enrollment` (single-use, 10 min, mints an agent),
`Agent` (the daemon's long-lived credential), `TunnelEnrollment` / `TunnelClient`
(the CLI's pair). Verifiers reject cross-audience tokens; see
[api.md](api.md#authentication) for the token flows.

Real-time delivery: WebSocket sessions are pod-local; chat, presence, and
notifications fan out across pods via Redis pub/sub. Long-lived agent/tunnel/DERP
sockets are kept tenant-affine by the front load balancer (consistent hash on the
tenant id) so a tenant's controllers, agents, and mediasoup rooms co-locate on one
pod — the multi-pod design is settled in
[multi-pod-scale-out.md](multi-pod-scale-out.md).

## Frontend

Vue 3 + Vuetify 3 SPA (Vite, TypeScript, Pinia setup stores). The remote-desktop
viewer is the deepest component: WebCodecs decode workers, five render paths,
clipboard/file bridges — mapped in [ui.md](ui.md). Observability (mesh graph,
usage, relay stats) renders with d3. i18n is wired but ships English only today.

## Deployment shape

- **One Docker image** — `rust:1.88-bookworm` builds the API, `oven/bun` builds the
  SPA, `debian:trixie-slim` runs nginx + the binary ([deployment.md](deployment.md)).
- **Dev stack** — `docker compose up -d`: MongoDB (:27019), Redis, MinIO, coturn.
- **Native artifacts** — MSI / `.deb` / `.pkg` / tarballs built by tag-triggered
  GitHub workflows and served through the server's own installer proxies
  ([installation.md](installation.md)).
- **Relay infrastructure** — coturn for TURN; `crates/derp-relay` builds the
  standalone, DB-free regional DERP PoPs (Ed25519 ticket auth).

## Where to go deeper

| Topic | Doc |
|---|---|
| Remote-desktop design (protocol, consent, latency budget) | [remote-control.md](remote-control.md) |
| Encoder cascade & rate control | [encoders.md](encoders.md) |
| Overlay carriers, NAT traversal, DERP | [overlay-communication.md](overlay-communication.md), [overlay-nat-traversal.md](overlay-nat-traversal.md) |
| Tunnels, LocalAPI, CLI | [tunnels.md](tunnels.md) |
| Multi-org devices | [multi-org.md](multi-org.md) |
| HTTP + WS surface | [api.md](api.md), [real-time.md](real-time.md) |
| Data model | [data-model.md](data-model.md) |
