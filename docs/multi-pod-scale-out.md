# Multi-pod scale-out — the settled architecture

> Goal: **any client on any pod, any pod count** — correctness never depends
> on the front LB's tenant-affinity hashing; affinity is demoted to a
> placement *optimization*. Four pod-local in-memory subsystems become
> location-transparent: the **rc-hub** (remote-control sessions), the
> **tunnel-hub** (tunnel flows), the **DERP relay** (WG frame forwarding),
> and **mediasoup conferences** (rooms/routers/transports).
>
> Origin: the 2026-07-29 + 2026-08-02 S6 incidents (green badge,
> `agent not online`, "stalled" overlay, silent split-brain risk in
> conferences). Design pass 2026-08-02; staged rollout C-1..C-6 below.
> Pod-2 is parked (single-pod) until C-4 lands.

## Governing principles

1. **The entity's live connection is the source of truth; Redis is a
   directory, not a database.** Every record is re-derivable from a live
   socket/registry. Redis down ⇒ every path degrades to today's
   affinity-co-location behavior — never worse.
2. **Move endpoints, not state.** Everything that can redial (browsers,
   tunnel CLIs, agents, DERP sockets) converges by redialing through the
   LB. Server-side proxying exists ONLY where redial provably cannot work
   (media signaling — see below).
3. **No data plane on the bus.** Redis carries control frames only. rc
   media is P2P WebRTC, tunnel data is P2P QUIC/DC or coturn, mediasoup
   media reaches the owner pod directly via per-pod announced IPs, DERP
   converges by *rehoming* rather than forwarding.
4. **Fold, don't migrate.** On unresolvable conflict or owner death,
   in-memory islands fold (participants kicked with a rejoin signal) and
   rebuild via the normal join path. No live-state handoff anywhere.

## C-1 — identity, directory, bus (implemented)

### Pod identity (`crates/api/src/cluster/identity.rs`)

`pod_id` — stable across restarts: `MESHHARBOR__APP__POD_ID` override (tests
inject per-app values) → `MESHHARBOR__POD_HOST_IP` (hostNetwork ⇒ ≤1 API pod
per node, so the node IP IS the pod identity — the same key the LB
upstream list and `MESHHARBOR__MEDIASOUP__ANNOUNCED_IP_MAP` use) → hostname →
random dev id. `epoch` — a per-process random token: a restarted pod
re-subscribes to the same bus channel but must never be mistaken for the
process that owned the previous epoch's entities.

The pub/sub **origin** stamped on every envelope is `<pod_id>/<epoch>`
(replaces the old random per-process UUID; the self-echo guard and the
user-online SREM semantics are unchanged because the epoch differs per
process).

### Ownership directory (`crates/api/src/cluster/directory.rs`)

One Redis STRING per live entity, value = the canonical owner token
`"<pod_id>/<epoch>/<extra>/<since_ms>"` (`OwnerRecord::parse`). Key
builders live in ONE place per namespace:

| Key | Discipline | TTL / refresh | Since |
|---|---|---|---|
| `roomler:agent-online:<agent_id>` | **LWW** (newest live socket wins — mirrors the rc-hub's displacement rule) | 90 s / on received heartbeat + a 30 s pod sweep | A-1/C-1 |
| `roomler:own:tunnel:<session_id>` | LWW | 90 s / 30 s | C-3 |
| `roomler:own:derp:<net>:<pubkey>` | LWW (+ per-network set key) | 90 s / 30 s | C-5 |
| `roomler:own:media:<room_id>` | **NX mutex** — media rooms have no client-owned socket; two creations = silent split-brain, so creation itself is mutually exclusive | 30 s / 10 s | C-4 |
| `roomler:pod-alive:<pod_id>` | plain SET | 45 s / 15 s | C-1 (advisory only) |

Three shared operations (Lua where atomicity matters):
- **claim** — LWW: plain `SET … EX`; NX: `SET … NX EX` (loser learns the
  holder).
- **refresh-if-mine** — mine or absent ⇒ full re-`SET` (a wrongful delete
  or a Redis flap self-heals within one beat); **foreign ⇒ CONFLICT** —
  the caller folds its local copy, never overwrites.
- **release** — compare-and-delete on the full token (a bare GET+DEL races
  a fresh re-home; a stale release must no-op against a newer claim).

### Inter-pod bus (`crates/api/src/cluster/bus.rs`)

Each pod subscribes to `roomler:pod:<pod_id>` (stable — a restarted
process re-subscribes and NACKs requests for entities it doesn't hold,
actively pruning its predecessor epoch's stale records). Envelope:

```json
{"v":1, "origin":"<pod/epoch>", "kind":"req"|"rep", "class":"sys"|"rc"|"media"|"derp",
 "corr":"<id>", "reply_to":"<pod_id>", "conn":null, "body":{}}
```

- Request/reply with correlation ids; deadlines 2 s (5 s for
  router-creating media ops). **The RPC deadline is the ACTIVE failure
  detector**: expiry ⇒ owner presumed dead ⇒ compare-DEL the record acted
  on + subsystem fallback. Directory TTLs are the passive backstop;
  `pod-alive` is advisory (metrics/fast-fail), never the primary detector.
- Delivery: at-most-once, per-publisher FIFO (Redis pub/sub), no bus-level
  retries — every consumer path has a redial/retry fallback. Handlers are
  idempotent. Unknown class/entity ⇒ structured NACK.
- The pre-existing global channel `roomler:ws` keeps its contract
  (`{origin, user_ids|broadcast, message}`); C-4 adds an additive `conn`
  field for connection-addressed media events; consent/kick become
  idempotent broadcast control events in C-2.

Rejected: Redis Streams (durability for state that is re-derivable from
live sockets buys nothing), pod↔pod TCP/gRPC mesh (with DERP forwarding
rejected there is NO data plane crossing pods), keyspace notifications
(off by default, lossy).

## Per-subsystem routing (C-2, C-3, C-4, C-5)

- **rc (C-2)** — *client redial + idle-agent nudge*. On session-request
  hub-miss with a fresh foreign directory record: reply
  `rc:session.rehome{tid}`; the browser re-pins its WS
  (`setTenantAffinity` + a new `forceRedial` for the parked-socket case)
  and retries ONCE. After topology changes the *agent's* WS may sit on an
  old-hash pod: the owning pod closes it — **only when idle** (no active
  sessions, no tunnel sessions targeting it) — so its reconnect re-lands
  at the current hash. Sessions stay pod-local for life; **cross-pod
  session frame-relay is rejected permanently** (a `LiveSession` pins its
  `controller_tx` on the creating pod; relaying is a durable bidirectional
  proxy with new failure modes, for a signaling-only channel whose media
  is P2P). Consent + admin-kick become broadcast control events every pod
  applies to its local hub.
- **tunnel (C-3)** — same pattern: open-path miss ⇒
  `TunnelOpenReject{reason:"rehome"}` ⇒ the headless CLI redials itself
  (it owns its WS; tid from its JWT) + retry-once. No post-open relay:
  tunnel DATA is P2P/coturn and survives pod loss; the dropped
  agent→client WS bookkeeping gets a metric, not a proxy.
- **media signaling (C-4)** — *the ONE server-proxy*. Redial is wrong here
  (the room's owner is wherever `call/start` landed, not `hash(tid)`; one
  browser WS serves all the user's tenants). Viewer→owner commands ride an
  owner-RPC over the bus (a routing shim in every `media:*` handler +
  `call_leave`/`call_end`/recording routes); owner→viewer pushes ride the
  global channel with connection-id addressing (UUIDs are globally unique
  — no per-connection directory). The media data plane is unchanged:
  browsers already reach the owner pod's transports directly via its
  announced IP.
  **Claim-or-route replaces the split-brain get-or-create belt**
  (`ws/handler.rs` media:join): local room ⇒ serve; else GET the claim ⇒
  absent ⇒ Mongo `in_progress` check ⇒ `SET NX` (winner creates, loser
  routes); foreign owner ⇒ route; self-with-stale-epoch ⇒ release +
  re-claim (race-free owner-restart healing). Owner death: claim released
  by graceful shutdown (zero window on deploys) or ≤30 s TTL (crash) ⇒
  participants' ICE fails ⇒ UI rejoins ⇒ fresh claim on a live pod. Claim
  CONFLICT (possible only after a Redis outage window) ⇒ the claim-loser
  folds its island and pushes a rejoin. The old belt is retained SOLELY as
  the Redis-down fallback, logged + counted.
- **DERP (C-5)** — *registration-driven rehome, NO cross-pod frame
  forwarding*. A network is tenant-scoped and both ends carry the same
  tid, so under any consistent LB map the whole network converges to one
  pod; splits are stale-socket artifacts. On register, read the network's
  sibling records; the convergence target is the pod of the **newest**
  registration (`since_ms` max — the newest dial reflects the LB's
  *current* verdict; a "majority wins" rule would chase the parked past
  during a topology flip). Every other pod is asked (`derp.rehome` RPC)
  to close its `/derp` sockets for that network; the clients' reconnect
  re-lands converged. Ping-pong guard on the closing side: ≥60 s cooldown
  per (net, pubkey), 3 attempts per 10 min, then the split-evidence
  counter (`derp_rehome_stuck_total`). DERP scales by distributing
  NETWORKS across pods, never splitting one. (Frame forwarding rejected:
  it is the only mechanism that would put WG-rate bytes on the bus, buys
  correctness only for a transient window the rehome already bounds, and
  makes Redis a bandwidth SPOF. Revisit only if affinity is dropped or
  multi-region.)

## Mediasoup scale ladder

Stage (a) = C-4 (room-pinned signaling routing — N-pod conferencing is
correct with zero media-path changes). Stage (b) — **PipeTransport mesh**
(mediasoup 0.20 has all primitives: `create_pipe_transport`,
`pipe_producer_to_router`, manual cross-host param exchange = a
`media.pipe.*` req/rep on the bus): claim holder = home pod = sole
coordinator; satellite routers per pod, piped pairwise over node IPs
(SRTP on); pipe-all-producers with refcounts; satellite death folds the
satellite, home death folds the room. **Deferred behind a trigger
metric**: any room sustaining ≥12–15 active AV participants (≈450+
consumers vs the ~500/worker ceiling) or pod aggregate >60 % of
`num_workers × 500`, measured by the C-6 gauges. Below that, stage (b) is
pure risk with no benefit.

## Failure model

Detector precedence: (1) the entity's own socket death → drives redial;
(2) the RPC deadline → prunes records on demand; (3) directory TTL →
bounded passive staleness; (4) pod-alive → advisory only.

| Entity | Owner-pod death | Blast radius |
|---|---|---|
| Agent WS | socket breaks ⇒ agent redials; LWW re-register | that pod's rc sessions end (P2P media freezes → controller reconnect); listing stale ≤90 s |
| Tunnel session | **data plane survives outright** (P2P); new opens rehome | bookkeeping blip only |
| DERP peer | reconnect loop; LB re-hashes deterministically | seconds of WG loss; corp pairs re-handshake |
| Media room | claim gone (graceful: zero window; crash: ≤30 s TTL) ⇒ rejoin claims a live pod | one conference, ≤30 s gap on crash |

**Redis-down degradation (hard requirement)**: directory ops fail soft to
"no record" ⇒ rc/tunnel answer pod-local (= today), rehome/nudge
suppressed, media falls back to the S6 belt (logged
`media_belt_fallback_total`). On recovery, heartbeats re-assert every
record within one beat and the fold rule resolves any belt-era splits.

## Stages

| Stage | Content | Gate |
|---|---|---|
| **C-1** | `crates/api/src/cluster/{identity,directory,bus}.rs`, origin swap, A-1 agent keys canonicalized, directory heartbeat, two-pod tests | zero behavior change |
| C-2 | rc rehome + `forceRedial` + idle-agent nudge + consent/kick broadcast | |
| C-3 | tunnel rehome + CLI redial-retry + session ownership records | |
| C-4 | media claim-or-route + command shim + conn-addressed events + conflict fold | **THE un-park gate** |
| C-5 | DERP directory + rehome — convergence toward the NEWEST registration (cooldown + cap + `derp_rehome_stuck_total`) | |
| C-6 | shutdown sweep for all four classes (media/agents from C-4/A-1; + tunnel + derp records) + `cluster::metrics` counters (`rc_rehome`, `tunnel_rehome`, `agent_nudge`, `bus_deadline`, `media_fold`, `media_belt_fallback`, `derp_rehome_close`, `derp_rehome_stuck`, `split_evidence` — all `_total`) + per-pod media gauges (rooms/participants/consumers → the stage-(b) PipeTransport trigger) + `GET /api/cluster/status` (auth-gated) | un-park pod-2 once C-4..C-6 are deployed |

## Not building (scope honesty)

rc session frame-relay; DERP cross-pod frame forwarding / pod-TCP data
mesh; live mediasoup room migration (fold-and-rejoin only); PipeTransport
before the trigger fires; cross-pod piping for the (nonexistent) rc SFU
bridge; Redis Streams / gRPC / gossip / Redlock; a per-WS-connection
directory; viewer-WS redial for media; LB/readiness coupling.

## Ops notes

- `kubectl rollout restart` is **unreliable under ArgoCD selfHeal** (the
  restart annotation is drift and gets reverted mid-roll — observed
  replacing only one of two pods, twice, 2026-08-02). Restart via a
  git-driven image/annotation bump or `argocd app actions run`.
- Park/un-park runbook stays as documented in CLAUDE.md (S6 bullet);
  un-parking pod-2 is gated on C-4.
