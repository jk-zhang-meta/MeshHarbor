// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `/derp` — a pubkey-addressed WebSocket relay for the both-UDP-blocked
//! overlay carrier tier (NAT-traversal Phase D, DERP).
//!
//! # Why this exists
//!
//! The overlay carrier cascade (LAN-direct → public-direct → srflx-punch →
//! single-relay) covers every peer pair EXCEPT one: two nodes that are BOTH on
//! all-UDP-blocked networks (a strict corp firewall that permits only
//! TCP/TLS-443). Single-relay provably can't serve them — exactly one side must
//! be the raw-UDP dialer, and neither has UDP. DERP breaks the deadlock because
//! **both peers dial OUT** over TCP/TLS-443 to this rendezvous relay: no UDP, no
//! inbound-reachable allocation, no TURN permission model. It's Tailscale's
//! DERP, scoped to a single overlay network.
//!
//! # What the relay does
//!
//! It is a dumb, opaque, pubkey-keyed forwarder. A node opens ONE `/derp` WSS,
//! sends its 32-byte WireGuard public key as the first (registration) frame,
//! then exchanges binary data frames of the form `[dst_pubkey(32) || payload]`.
//! The relay rewrites the prefix to the SENDER's pubkey and delivers
//! `[src_pubkey(32) || payload]` to the destination — but ONLY to a peer
//! registered in the **same overlay network** (hard tenant/network isolation,
//! the same scope the netmap fan-out enforces). The payload is opaque WG
//! ciphertext; the relay never inspects or decrypts it — WireGuard is
//! end-to-end between the two nodes.
//!
//! # Security
//!
//! - **Auth**: the agent JWT, same audience as `/ws?role=agent`
//!   (`verify_agent_token`). The DB is authoritative for the agent's tenant, so
//!   a forged tenant claim can't widen scope.
//! - **Registration authz**: a node may only register a pubkey that matches its
//!   OWN `overlay_nodes.wg_public_key` — it can't claim a peer's key to
//!   intercept that peer's frames.
//! - **Network scoping**: a frame is delivered only to a pubkey registered in
//!   the sender's own network. The `(network_id, pubkey)` registry key makes a
//!   cross-network delivery structurally impossible.
//!
//! Placement (v1): on the `roomler2` API pods (hostNetwork, :443), behind the
//! dedicated `/derp` nginx `location`. The registry is in-memory on a
//! single-replica Recreate deployment, so a web deploy severs all DERP links
//! (they rebuild via the carrier `dead` latch) and it can't scale past one
//! replica — fine for the handful of corp pairs this tier serves.
use crate::NetworkState;
use crate::derp_acl::DerpAclCache;
use crate::overlay::{NodeIdentity, current_node};
use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use roomler_core::ws::upgrade::WsParams;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn};

// FR-69 P7a — the registry's key and map types moved to the network module
// with the overlay engine that addresses them; re-exported under their old
// names so every path in this crate reads as before.
pub use crate::derp_types::{DerpCancelRegistry, DerpKey, DerpPubKey, DerpRegistry};
/// Per-connection outbound queue depth. Bounded so a slow or hostile consumer
/// can't grow the relay's memory without bound; on overflow we DROP the frame
/// (WG/QUIC are loss-tolerant — a dropped carrier datagram just retransmits).
const DERP_SEND_QUEUE: usize = 256;
/// Max DERP frame = `[pubkey(32) || WG-carrier datagram]`. The carrier datagram
/// stays ≤ the overlay MTU (~1280–1420) + WG overhead; 2 KiB matches the relay
/// carrier's `MAX_DATAGRAM` with headroom for the 32-byte pubkey prefix and is
/// comfortably ≥ `mtu + WG_OVERHEAD + 32`.
const DERP_MAX_FRAME: usize = 2048;
/// Server→client keepalive Ping cadence on every `/derp` connection. Must sit
/// WELL inside the shortest idle timeout on the path — HAProxy fronts the
/// pods with `timeout client/server 300s` and NO `timeout tunnel`, so an
/// idle standby link dies at 300 s without this (field 2026-08-16: the
/// synchronized 21:55:37Z disconnect wave one idle window after post-roll
/// traffic settled). 30 s matches the control-WS keepalive convention and
/// gives 10× headroom.
const DERP_KEEPALIVE: Duration = Duration::from_secs(30);
/// Lifetime counters for the two forward-path drop classes. A missing dst is
/// byte-identical to peer-offline from the sender's side, so the count is the
/// ONLY server-side evidence of a one-way DERP pair (the split-brain class).
static DERP_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);
static DERP_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Per-(network, dst) pacing for the drop evidence lines — WG retries at
/// handshake rate (~every 5 s per pair), so an unpaced log would emit
/// hundreds of identical lines per dead pair per minute.
static MISS_LOG_AT: LazyLock<DashMap<DerpKey, Instant>> = LazyLock::new(DashMap::new);
static FULL_LOG_AT: LazyLock<DashMap<DerpKey, Instant>> = LazyLock::new(DashMap::new);
/// R4 — tunnel-leg shaping. The `quic-derp-v1` tunnel flavor multiplexes
/// QUIC over this relay, and unlike the WG floor traffic the plane was
/// sized for, a tunnel can be an elephant flow (a git clone). Per
/// (network, src) token bucket, applied ONLY to tunnel-class payloads
/// (non-WG/non-disco first bytes — the same classifier both mux ends use);
/// WG + disco frames are never shaped. ~3 Mbit/s sustained with a 1 MiB
/// burst: the leg is a last resort whose job is "usable", not "fast", and
/// a modest cap keeps the floor honest for every other tenant on the pod.
static DERP_TUNNEL_SHAPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static TUNNEL_SHAPE_LOG_AT: LazyLock<DashMap<DerpKey, Instant>> = LazyLock::new(DashMap::new);
static TUNNEL_BUCKETS: LazyLock<DashMap<DerpKey, std::sync::Mutex<(f64, Instant)>>> =
    LazyLock::new(DashMap::new);
const TUNNEL_RATE_BYTES_PER_SEC: f64 = 375_000.0; // ~3 Mbit/s sustained
const TUNNEL_BURST_BYTES: f64 = 1_048_576.0; // 1 MiB burst
/// FR-115 P4a — bulk frames dropped by the relay allowance (an org past its
/// plan's monthly relay, `crate::relay_allowance`), and their paced log.
static DERP_ALLOWANCE_SHAPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOWANCE_LOG_AT: LazyLock<DashMap<DerpKey, Instant>> = LazyLock::new(DashMap::new);
/// Debit `len` bytes from the (network, src) tunnel bucket; `false` = over
/// budget, drop the frame (QUIC retransmits under its congestion control,
/// which converges onto the sustained rate).
fn tunnel_budget_permits(network_id: ObjectId, src: &DerpPubKey, len: usize) -> bool {
    let entry = TUNNEL_BUCKETS
        .entry((network_id, *src))
        .or_insert_with(|| std::sync::Mutex::new((TUNNEL_BURST_BYTES, Instant::now())));
    let mut bucket = entry.lock().unwrap();
    let now = Instant::now();
    let refill = now.duration_since(bucket.1).as_secs_f64() * TUNNEL_RATE_BYTES_PER_SEC;
    bucket.0 = (bucket.0 + refill).min(TUNNEL_BURST_BYTES);
    bucket.1 = now;
    if bucket.0 >= len as f64 {
        bucket.0 -= len as f64;
        true
    } else {
        false
    }
}
// ── FR-20 collection point A — per-network relayed bytes ─────────────
//
// Accumulated lock-free on the forward path and drained by
// `spawn_derp_usage_flush` every `USAGE_FLUSH`. Keyed by NETWORK because that
// is what `forward_frame` holds; the flusher resolves network → tenant, which
// is a query it can afford and the hot path cannot.
static DERP_NETWORK_BYTES: LazyLock<DashMap<ObjectId, AtomicU64>> = LazyLock::new(DashMap::new);
const USAGE_FLUSH: Duration = Duration::from_secs(60);
/// Add `n` relayed bytes for `network_id`.
///
/// Steady state is a DashMap `get` (hash + shard read-lock) followed by one
/// relaxed atomic add — the lookup dominates, not the atomic. Measured by
/// `bench_add_network_bytes_cost` below; see FR-20 for the numbers and what
/// they mean against the fleet's real frame rate.
fn add_network_bytes(network_id: ObjectId, n: u64) {
    if let Some(c) = DERP_NETWORK_BYTES.get(&network_id) {
        c.fetch_add(n, Ordering::Relaxed);
        return;
    }
    // First frame for this network on this pod. `or_insert` races benignly —
    // whichever writer lands second adds onto the winner's counter.
    DERP_NETWORK_BYTES
        .entry(network_id)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(n, Ordering::Relaxed);
}
/// Take and zero every network's accumulated bytes.
///
/// `swap(0)` rather than remove-and-reinsert: a frame arriving mid-drain lands
/// on the live counter and is carried into the NEXT bucket instead of being
/// lost to a removed entry.
fn drain_network_bytes() -> Vec<(ObjectId, u64)> {
    DERP_NETWORK_BYTES
        .iter()
        .filter_map(|e| {
            let n = e.value().swap(0, Ordering::Relaxed);
            (n > 0).then(|| (*e.key(), n))
        })
        .collect()
}
/// FR-20 P1 — drain the per-network byte counters into `stats_usage` every
/// [`USAGE_FLUSH`].
///
/// Runs on both pods. Each writes only the bytes IT relayed, into the same
/// deterministic `_id`, and Mongo's `$inc` sums them — so no lease and no
/// leader election is needed for the ledger to be correct on a 2-pod
/// deployment.
pub fn spawn_derp_usage_flush(state: NetworkState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(USAGE_FLUSH);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if !state.settings.stats.enabled {
                continue;
            }
            let drained = drain_network_bytes();
            if drained.is_empty() {
                continue;
            }
            // ONE query for every network in this batch, not one per network:
            // the flusher runs while frames keep arriving, so its cost has to
            // stay flat in the number of active tenants.
            let ids: Vec<ObjectId> = drained.iter().map(|(id, _)| *id).collect();
            let mut tenant_of: std::collections::HashMap<ObjectId, ObjectId> =
                std::collections::HashMap::new();
            match state
                .overlay_networks
                .base
                .find_many(bson::doc! { "_id": { "$in": &ids } }, None)
                .await
            {
                Ok(rows) => {
                    for n in rows {
                        if let Some(nid) = n.id {
                            tenant_of.insert(nid, n.tenant_id);
                        }
                    }
                }
                Err(e) => {
                    // Drop this batch rather than retry: `$inc` is additive, so
                    // a retry that partially succeeded would double-bill. An
                    // under-reported minute is the cheaper error.
                    warn!(%e, batches = drained.len(), "fr-20: usage flush skipped (network lookup failed)");
                    continue;
                }
            }
            let now = bson::DateTime::now().timestamp_millis() / 1000;
            let (mut written, mut unattributed) = (0u64, 0u64);
            for (network_id, bytes) in drained {
                let Some(tenant_id) = tenant_of.get(&network_id).copied() else {
                    // The network row is gone (tenant deleted mid-bucket).
                    // Counted and logged, never guessed at — an unattributed
                    // byte must not become a wrongly-attributed one.
                    unattributed += bytes;
                    continue;
                };
                if let Err(e) = state
                    .stats
                    .add_usage(
                        tenant_id,
                        roomler_ai_services::dao::stats::Meter::DerpBytes,
                        now,
                        bytes as i64,
                    )
                    .await
                {
                    warn!(%tenant_id, %e, "fr-20: usage bucket write failed (bucket under-reports)");
                    continue;
                }
                written += bytes;
            }
            if unattributed > 0 {
                warn!(
                    unattributed_bytes = unattributed,
                    "fr-20: relayed bytes could not be attributed to a tenant"
                );
            }
            if written > 0 {
                tracing::debug!(derp_bytes = written, "fr-20: usage flushed");
            }
        }
    });
}
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);
/// First 8 hex chars of a pubkey — enough to correlate registration,
/// forward-drop, and client-side lines without dumping whole keys.
pub fn pk8(pk: &DerpPubKey) -> String {
    pk.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
/// `true` once per [`DROP_LOG_INTERVAL`] per key — books the emission slot.
fn drop_log_due(map: &DashMap<DerpKey, Instant>, key: DerpKey) -> bool {
    // Opportunistic sweep so dead pairs don't accrete on a long-lived pod.
    if map.len() > 4096 {
        map.retain(|_, at| at.elapsed() < DROP_LOG_INTERVAL);
    }
    let due = map
        .get(&key)
        .map(|at| at.elapsed() >= DROP_LOG_INTERVAL)
        .unwrap_or(true);
    if due {
        map.insert(key, Instant::now());
    }
    due
}
/// Minute-cadence census of this pod's DERP registry: per-network entry
/// counts, plus the two lifetime drop counters. One greppable line per pod
/// per minute while anything is registered (and one final line on the
/// transition to empty) — the ground truth the split-brain diagnosis
/// compares against clients' "connected + registered" claims.
pub fn spawn_registry_census(state: &NetworkState) {
    let reg = state.derp_registry.clone();
    let pod = state.pod.pod_id.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_summary = String::new();
        loop {
            tick.tick().await;
            let mut per_net: std::collections::BTreeMap<String, usize> = Default::default();
            for e in reg.iter() {
                *per_net.entry(e.key().0.to_hex()).or_default() += 1;
            }
            let summary = per_net
                .iter()
                .map(|(n, c)| format!("{n}={c}"))
                .collect::<Vec<_>>()
                .join(" ");
            // Quiet only while empty AND already reported empty.
            if summary.is_empty() && last_summary.is_empty() {
                continue;
            }
            info!(
                %pod,
                entries = reg.len(),
                networks = per_net.len(),
                %summary,
                derp_miss_total = DERP_MISS_TOTAL.load(Ordering::Relaxed),
                derp_full_total = DERP_FULL_TOTAL.load(Ordering::Relaxed),
                "derp registry census"
            );
            last_summary = summary;
        }
    });
}
/// `GET /derp?token=<agent-jwt>` — upgrade to the DERP relay WS. Agent-only,
/// same audience as `/ws?role=agent`.
pub async fn derp_upgrade(
    State(state): State<NetworkState>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // `WsParams::token` became optional when `/ws` learned to accept a browser
    // session cookie. DERP is agent-only — no cookie jar on this side, and a
    // browser must never be able to register as a relay node — so the token
    // stays REQUIRED here.
    let Some(token) = params.token.as_deref() else {
        return Response::builder()
            .status(401)
            .body("Unauthorized (derp)".into())
            .unwrap();
    };
    let claims = match state.auth.verify_agent_token(token) {
        Ok(c) => c,
        Err(_) => {
            return Response::builder()
                .status(401)
                .body("Unauthorized (derp)".into())
                .unwrap();
        }
    };
    // S6 — DERP relays are pod-local: two mesh peers only meet if their
    // /derp sockets land on the SAME pod, so the LB hashes on `tid` and
    // the server rejects a present-but-wrong claim.
    if let Some(t) = &params.tid
        && t != &claims.tenant_id
    {
        return Response::builder()
            .status(403)
            .body("tid does not match token tenant".into())
            .unwrap();
    }
    let agent_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid agent ID".into())
                .unwrap();
        }
    };
    let tenant_id = match ObjectId::parse_str(&claims.tenant_id) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid tenant ID".into())
                .unwrap();
        }
    };
    // The agent's row is the revocation list — an agent token is valid for a
    // year, so its signature says nothing about whether we still accept the
    // device. DELETION was already covered here by accident: the cascade
    // tombstones the overlay node, and `current_node` below is live-scoped, so
    // a deleted agent found no node. QUARANTINE was not — it leaves the node
    // row alone, so a quarantined device kept relaying through DERP.
    //
    // Checked BEFORE the upgrade: refusing the handshake is a clean signal,
    // whereas accepting and then dropping looks like a network fault to a
    // client that marks its mux "up" on send.
    //
    // ANY, not live (#1821): the tombstone is what this read is for — a
    // removed device is refused with its REASON in the log, and the `Err` arm
    // keeps meaning "the row could not be read", which is a different fault.
    match state
        .fleet
        .agents
        .find_any_in_tenant(tenant_id, agent_id)
        .await
    {
        Ok(agent) => {
            if let Some(reason) = roomler_ai_mod_fleet::auth_agent::refusal_reason(&agent) {
                info!(%agent_id, %tenant_id, reason, "derp: REFUSED before upgrade");
                return Response::builder()
                    .status(401)
                    .body("Unauthorized (derp)".into())
                    .unwrap();
            }
            // FR-103 — a token minted before the device was removed.
            if let Some(reason) = roomler_ai_mod_fleet::auth_agent::generation_refusal(
                claims.generation,
                agent.token_gen,
                state.fleet.settings.rc.token_generation_check,
            ) {
                info!(%agent_id, %tenant_id, reason, row_gen = agent.token_gen, "derp: REFUSED before upgrade");
                return Response::builder()
                    .status(401)
                    .body("Unauthorized (derp)".into())
                    .unwrap();
            }
        }
        Err(e) => {
            // Fail closed. This does NOT make DERP newly dependent on Mongo:
            // `handle_derp_socket` already resolves the overlay node through
            // `current_node`, which is `.ok().flatten()` — so a DB error was
            // already a refusal, just a later and quieter one. Moving it here
            // only changes WHERE the same refusal happens, and gives it a
            // reason in the log.
            info!(%agent_id, %tenant_id, %e, "derp: REFUSED — agent row unavailable");
            return Response::builder()
                .status(401)
                .body("Unauthorized (derp)".into())
                .unwrap();
        }
    }
    if state.settings.auth.account_approval.enabled {
        let gate = tokio::time::timeout(
            Duration::from_secs(3),
            roomler_ai_mod_fleet::auth_agent::accepted_agent(
                &state.fleet,
                &claims.sub,
                &claims.tenant_id,
                Some(claims.generation),
            ),
        )
        .await;
        if !matches!(gate, Ok(Ok(_))) {
            return Response::builder()
                .status(403)
                .body("Device owner admission required".into())
                .unwrap();
        }
    }
    ws.max_message_size(roomler_core::ws::upgrade::MAX_WS_MESSAGE_BYTES)
        .max_frame_size(roomler_core::ws::upgrade::MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_derp_socket(state, socket, agent_id))
}
/// Drive one DERP connection: resolve the agent's node, validate its
/// registration pubkey, add it to the registry, then pump frames until the
/// socket closes.
async fn handle_derp_socket(state: NetworkState, socket: WebSocket, agent_id: ObjectId) {
    // Resolve this agent's overlay node → its network + its stored pubkey.
    // Refusals log at INFO: the client marks its mux "up" after merely
    // SENDING the registration frame, so a silent server-side refusal is a
    // both-ends-look-healthy dark window (the split-brain class).
    let node = match current_node(&state, NodeIdentity::Agent(agent_id)).await {
        Some(n) => n,
        None => {
            info!(%agent_id, "derp: registration REFUSED — no overlay node for agent; closing");
            return;
        }
    };
    let network_id = node.network_id;
    let node_hex = node
        .id
        .map(|i| i.to_hex())
        .unwrap_or_else(|| "-".to_string());
    let (mut ws_tx, mut ws_rx) = socket.split();
    // First frame MUST be the 32-byte registration pubkey, and it MUST equal
    // this node's own `wg_public_key` — a node can only register ITS OWN key,
    // never a peer's (which would let it intercept that peer's frames).
    let self_pubkey: DerpPubKey = match ws_rx.next().await {
        Some(Ok(Message::Binary(b))) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b[..]);
            k
        }
        _ => {
            info!(%agent_id, node = %node_hex, "derp: registration REFUSED — bad or absent registration frame; closing");
            return;
        }
    };
    if BASE64.encode(self_pubkey) != node.wg_public_key {
        warn!(
            %agent_id, %network_id, node = %node_hex,
            got = %pk8(&self_pubkey),
            stored = %node.wg_public_key.chars().take(8).collect::<String>(),
            "derp: registration REFUSED — pubkey != node's wg_public_key (stale node row or key rotation race)"
        );
        return;
    }
    // Recheck after the registration frame: a client can delay that frame
    // past an account suspension which happened after the HTTP upgrade.
    let admission_check = || async {
        tokio::time::timeout(
            Duration::from_secs(3),
            roomler_ai_mod_fleet::auth_agent::accepted_agent(
                &state.fleet,
                &agent_id.to_hex(),
                &node.tenant_id.to_hex(),
                None,
            ),
        )
        .await
    };
    if state.settings.auth.account_approval.enabled && !matches!(admission_check().await, Ok(Ok(_)))
    {
        return;
    }
    let admission_watchdog = async {
        if !state.settings.auth.account_approval.enabled {
            std::future::pending::<()>().await;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if !matches!(admission_check().await, Ok(Ok(_))) {
                return;
            }
        }
    };
    tokio::pin!(admission_watchdog);
    let key: DerpKey = (network_id, self_pubkey);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(DERP_SEND_QUEUE);
    // Last-writer-wins on re-registration: a reconnect for the same pubkey
    // replaces the stale sender (corp middleboxes leave half-open TCP, so the
    // old entry would otherwise black-hole inbound frames). The old socket's
    // read loop keeps working as a SENDER until it notices its own close; only
    // inbound routing moves to the new connection.
    if state.derp_registry.insert(key, out_tx.clone()).is_some() {
        info!(
            %agent_id, %network_id, node = %node_hex, pk = %pk8(&self_pubkey),
            "derp: re-registration displaced a live socket (reconnect churn — old flow was still parked)"
        );
    }
    // C-5 — cancel handle (rehome close) + directory record + one
    // convergence sweep over this network's registrations.
    let cancel = Arc::new(tokio::sync::Notify::new());
    state.derp_cancels.insert(key, cancel.clone());
    super::derp_cluster::on_derp_register(&state, network_id, &self_pubkey, agent_id).await;
    info!(%agent_id, %network_id, node = %node_hex, pk = %pk8(&self_pubkey), "derp: node registered");
    // Write task: drain outbound frames → WS binary, interleaved with a
    // server-side keepalive Ping. A DERP link whose pairs are all parked on
    // better carriers goes COMPLETELY quiet (it exists as standby), and
    // neither side pinged — so the HAProxy hop in front of the pods
    // (timeout client/server 300 s, no `timeout tunnel`) reaped every idle
    // link 5 minutes after its last frame. Field 2026-08-16 21:55:37Z: a
    // synchronized disconnect wave across BOTH pods + networks exactly one
    // idle window after the post-roll rebuild traffic settled, then 1-4 min
    // re-register gaps during which every frame toward the absent peer hit
    // `derp_miss_total` — the rolling one-way-DERP windows task #15 chased
    // as a split-brain. Pinging from the SERVER fixes every fleet version
    // at once (tungstenite clients auto-pong, which also refreshes the
    // client→server direction through the proxy).
    let mut write = tokio::spawn(async move {
        let mut ping = tokio::time::interval(DERP_KEEPALIVE);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                frame = out_rx.recv() => match frame {
                    Some(frame) => {
                        if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if ws_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    });
    // Read loop: forward each data frame to its dst within THIS network.
    loop {
        tokio::select! {
            _ = &mut admission_watchdog => {
                info!(%agent_id, "derp: device account admission revoked");
                break;
            }
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Binary(frame))) => {
                    forward_frame(
                        &state.derp_registry,
                        &state.derp_acl,
                        network_id,
                        &self_pubkey,
                        &frame[..],
                    );
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                // Ignore text / ping / pong (axum auto-pongs).
                Some(Ok(_)) => {}
            },
            // If the write task ends (peer's socket died on the write side),
            // stop reading too.
            _ = &mut write => break,
            // C-5 — cluster rehome: this socket is parked on the wrong
            // pod; close it so the reconnect re-lands converged.
            _ = cancel.notified() => {
                info!(%agent_id, %network_id, "derp: closing for cluster rehome");
                break;
            }
        }
    }
    // Stop outbound IO before directory persistence can block cleanup.
    write.abort();
    // Deregister — but ONLY if we're still the registered sender. A newer
    // reconnect (last-writer-wins) may have replaced us; we must not evict it.
    let removal_was_ours = state
        .derp_registry
        .remove_if(&key, |_, tx| tx.same_channel(&out_tx))
        .is_some();
    super::derp_cluster::remove_cancel_if_ours(&state, &key, &cancel);
    if removal_was_ours {
        // C-5 — release the directory record (a displaced older socket
        // skips this: the record belongs to its replacement).
        super::derp_cluster::on_derp_teardown(&state, network_id, &self_pubkey).await;
    }
    write.abort();
    info!(%agent_id, %network_id, node = %node_hex, pk = %pk8(&self_pubkey), "derp: node disconnected");
}
/// Parse `[dst_pubkey(32) || payload]` sent by `src_pubkey`, and forward
/// `[src_pubkey(32) || payload]` to the destination — but ONLY to a peer
/// registered in the SAME `network_id` (hard scope). Silently drops on: a short
/// or oversized frame, an unknown dst (peer offline / not in this network), or a
/// full destination queue (the carrier is loss-tolerant).
///
/// **Overlay-ACL gated.** Beyond the `network_id` scope, a frame is dropped when
/// the tenant is ENFORCING and the ACL would not let `src_pubkey` see the
/// destination — otherwise a stale or modified client holding a denied peer's
/// key could relay straight around the netmap (an honest client never learns a
/// withheld key). The decision is a precomputed [`crate::derp_acl`] table read,
/// not a policy query: this is a synchronous per-datagram path. A missing table
/// permits the frame — see that module for the fail-open rationale.
fn forward_frame(
    registry: &DerpRegistry,
    acl: &DerpAclCache,
    network_id: ObjectId,
    src_pubkey: &DerpPubKey,
    frame: &[u8],
) {
    if frame.len() < 32 || frame.len() > DERP_MAX_FRAME {
        return;
    }
    let mut dst = [0u8; 32];
    dst.copy_from_slice(&frame[..32]);
    let payload = &frame[32..];
    // One lock-free lookup. Absent ⇒ fail open (no table built for this
    // network: ACL off, or not yet rebuilt after a restart).
    if let Some(table) = acl.get(&network_id)
        && !table.permits(src_pubkey, &dst)
    {
        // Rate-limited by the tenant's own churn, not per frame: a denied
        // pair retries on the WG handshake timer (~5 s), not per packet.
        info!(
            %network_id,
            src = %pk8(src_pubkey),
            dst = %pk8(&dst),
            "derp: dropped a frame the overlay ACL denies"
        );
        return;
    }
    // FR-115 P4a — the relay allowance. A network whose org is past its
    // plan's monthly relay has its BULK frames held to its rate; a WireGuard
    // handshake and disco always pass, so the floor still connects. While no
    // network is over, this is one relaxed atomic load.
    if let Some(rate) = crate::relay_allowance::rate_of(&network_id)
        && crate::relay_allowance::frame_is_bulk(payload)
        && !crate::relay_allowance::permits(network_id, frame.len(), rate)
    {
        let total = DERP_ALLOWANCE_SHAPED_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if drop_log_due(&ALLOWANCE_LOG_AT, (network_id, *src_pubkey)) {
            info!(
                %network_id,
                src = %pk8(src_pubkey),
                rate_bytes_per_sec = rate,
                derp_allowance_shaped_total = total,
                "derp: bulk frame dropped by the relay allowance (the org is past its plan's monthly relay)"
            );
        }
        return;
    }
    // R4 — shape tunnel-class payloads (see the bucket's doc); WG + disco
    // frames pass untouched.
    if !tunnel_core::transport::derp::payload_is_wg_or_disco(payload)
        && !tunnel_budget_permits(network_id, src_pubkey, frame.len())
    {
        let total = DERP_TUNNEL_SHAPED_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if drop_log_due(&TUNNEL_SHAPE_LOG_AT, (network_id, *src_pubkey)) {
            info!(
                %network_id,
                src = %pk8(src_pubkey),
                derp_tunnel_shaped_total = total,
                "derp: tunnel-leg frame dropped by the rate shaper (over ~3 Mbit/s sustained)"
            );
        }
        return;
    }
    // Clone the sender out of the shard guard so we don't hold the DashMap lock
    // across the (non-blocking) try_send.
    let sender = match registry.get(&(network_id, dst)) {
        Some(r) => r.clone(),
        None => {
            // dst offline or not registered on THIS pod. Indistinguishable
            // from peer-offline at the sender, so this paced line + counter
            // is the only server-side evidence of a one-way DERP pair.
            let total = DERP_MISS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
            if drop_log_due(&MISS_LOG_AT, (network_id, dst)) {
                info!(
                    %network_id,
                    src = %pk8(src_pubkey),
                    dst = %pk8(&dst),
                    derp_miss_total = total,
                    "derp: dropped a frame for an unregistered dst (peer offline, or registered on another pod/relay)"
                );
            }
            return;
        }
    };
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(src_pubkey);
    out.extend_from_slice(payload);
    let out_len = out.len() as u64;
    // Bounded, non-blocking: drop on overflow (loss-tolerant carrier).
    if sender.try_send(out).is_err() {
        let total = DERP_FULL_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if drop_log_due(&FULL_LOG_AT, (network_id, dst)) {
            warn!(
                %network_id,
                src = %pk8(src_pubkey),
                dst = %pk8(&dst),
                derp_full_total = total,
                "derp: dropped a frame on a full destination queue (slow or half-open consumer)"
            );
        }
    } else {
        // FR-19 — the pod actually relayed `out_len` bytes for this pair over
        // the control plane. Counted only on a SUCCESSFUL enqueue: a dropped
        // frame is not carried, so it must not inflate the offload baseline.
        roomler_core::cluster::metrics::DERP_BYTES_RELAYED_TOTAL
            .fetch_add(out_len, Ordering::Relaxed);
        // FR-20 collection point A — the same bytes, attributed per network so
        // they can become a per-tenant cost bucket.
        //
        // ⚠ Counted at the SAME point and on the same condition as the line
        // above, deliberately: we bill only for what we actually carried. A
        // frame dropped by the shaper, the ACL, or a full queue costs us
        // nothing and must not appear on anyone's ledger.
        //
        // ⚠ One `fetch_add` and nothing else. This is the relay latency path —
        // FR-18 exists because of queueing here — so there is no Mongo write,
        // no allocation and no lock held across an await. The flusher
        // (`spawn_derp_usage_flush`) does the I/O on its own timer.
        add_network_bytes(network_id, out_len);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// FR-115 P4a (AC7): over the relay allowance, a BULK frame past the
    /// bucket is dropped and billed nothing, while a WireGuard handshake on
    /// the same network still passes and is billed as carried. This is
    /// FR-20's rule, that only carried bytes are billed, applied to the new
    /// drop.
    #[test]
    fn the_allowance_holds_bulk_and_passes_the_handshake() {
        let _map = crate::relay_allowance::TEST_MAP_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let network = ObjectId::new();
        let (src, dst) = ([1u8; 32], [2u8; 32]);
        let registry: crate::derp_types::DerpRegistry = Arc::new(DashMap::new());
        let (tx, mut rx) = mpsc::channel(1024);
        registry.insert((network, dst), tx);
        let acl: DerpAclCache = Arc::new(DashMap::new());
        let frame = |head: [u8; 4], body: usize| {
            let mut f = dst.to_vec();
            f.extend_from_slice(&head);
            f.extend(std::iter::repeat_n(0u8, body));
            f
        };
        let bulk = frame([4, 0, 0, 0], 1200);
        let hello = frame([1, 0, 0, 0], 144);
        let billed = || {
            DERP_NETWORK_BYTES
                .get(&network)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0)
        };

        forward_frame(&registry, &acl, network, &src, &bulk);
        assert!(rx.try_recv().is_ok(), "inside the allowance, bulk passes");

        // Over, at 1 B/s: the bucket's 64 KiB minimum burst lets ~53 of
        // these through, and then holds.
        crate::relay_allowance::apply(std::collections::HashMap::from([(network, 1)]));
        let mut passed = 0;
        for _ in 0..200 {
            forward_frame(&registry, &acl, network, &src, &bulk);
            if rx.try_recv().is_ok() {
                passed += 1;
            }
        }
        assert!(
            (40..=60).contains(&passed),
            "the burst passes, then the bucket holds: {passed}"
        );
        let before = billed();
        forward_frame(&registry, &acl, network, &src, &bulk);
        assert!(rx.try_recv().is_err(), "past the bucket, bulk is dropped");
        assert_eq!(billed(), before, "a dropped frame is billed nothing");

        forward_frame(&registry, &acl, network, &src, &hello);
        assert!(rx.try_recv().is_ok(), "the handshake is never held back");
        assert_eq!(billed(), before + 32 + 148, "and it is billed as carried");
        crate::relay_allowance::apply(std::collections::HashMap::new());
    }
    /// FR-20 acceptance: *"measured DERP forward-path overhead is within noise
    /// of the pre-change baseline"*. `#[ignore]`d — it is a measurement, not a
    /// pass/fail assertion, and its numbers are machine-specific.
    ///
    /// ```text
    /// cargo test -p roomler-ai-api --lib bench_add_network_bytes_cost \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// Shape chosen deliberately: every thread hammers the SAME network id.
    /// That is both the realistic case (one busy tenant is one network) and the
    /// worst one — a single DashMap shard and a single cache line contended by
    /// every forwarding task. Spreading across ids would flatter the result.
    #[test]
    #[ignore]
    fn bench_add_network_bytes_cost() {
        use std::time::Instant;
        const ITERS: u64 = 2_000_000;
        let threads: usize = std::thread::available_parallelism()
            .map(|n| n.get().min(8))
            .unwrap_or(4);
        let net = ObjectId::new();
        // Warm the entry so we measure the steady-state `get` path rather than
        // the once-per-network `entry().or_insert_with()` branch.
        add_network_bytes(net, 0);
        let run = |label: &str, f: &(dyn Fn() + Sync)| {
            let t0 = Instant::now();
            std::thread::scope(|sc| {
                for _ in 0..threads {
                    sc.spawn(|| {
                        for _ in 0..ITERS {
                            f();
                        }
                    });
                }
            });
            let el = t0.elapsed();
            let ops = ITERS * threads as u64;
            let per = el.as_nanos() as f64 / ops as f64;
            println!("  {label:<26} {per:>7.2} ns/op   ({ops} ops on {threads} threads)");
            per
        };
        println!("add_network_bytes cost, {threads} threads on ONE network id:");
        // Floor: the atomic alone, with the lookup already done.
        let counter = AtomicU64::new(0);
        let floor = run("atomic add only", &|| {
            counter.fetch_add(1400, Ordering::Relaxed);
        });
        // The real hot path.
        let real = run("add_network_bytes", &|| add_network_bytes(net, 1400));
        println!(
            "  lookup overhead over the atomic: {:.2} ns/op",
            real - floor
        );
        // Grounding: the busiest minute this deployment has ever recorded was
        // 16.87 MB of DERP at ~1.4 KB/frame, i.e. ~200 frames/s fleet-wide.
        let frames_per_sec = 200.0;
        let core_pct = real * frames_per_sec / 1e9 * 100.0;
        println!("  at 200 frames/s (the busiest minute on record): {core_pct:.6}% of one core");
    }
    fn pk(byte: u8) -> DerpPubKey {
        [byte; 32]
    }
    fn frame(dst: &DerpPubKey, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(32 + payload.len());
        f.extend_from_slice(dst);
        f.extend_from_slice(payload);
        f
    }
    /// No table for any network — the fail-open posture, and the pre-ACL
    /// behaviour every test above asserts.
    fn no_acl() -> DerpAclCache {
        Arc::new(DashMap::new())
    }
    /// A cache holding one network's table.
    fn acl_with(net: ObjectId, table: crate::derp_acl::DerpAllowTable) -> DerpAclCache {
        let c: DerpAclCache = Arc::new(DashMap::new());
        c.insert(net, Arc::new(table));
        c
    }
    #[test]
    fn forwards_within_network_and_rewrites_src() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        // A → B with payload [1,2,3]; B should receive [A-pubkey || 1,2,3].
        forward_frame(&reg, &no_acl(), net, &a, &frame(&b, &[1, 2, 3]));
        let got = b_rx.try_recv().expect("B should receive the frame");
        assert_eq!(&got[..32], &a, "src prefix must be rewritten to the sender");
        assert_eq!(&got[32..], &[1, 2, 3]);
    }
    #[test]
    fn never_crosses_a_network_boundary() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let (net_a, net_b) = (ObjectId::new(), ObjectId::new());
        let (a, b) = (pk(0xAA), pk(0xBB));
        // Same pubkey B registered in BOTH networks with distinct channels.
        let (b_in_a_tx, mut b_in_a_rx) = mpsc::channel::<Vec<u8>>(8);
        let (b_in_b_tx, mut b_in_b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net_a, b), b_in_a_tx);
        reg.insert((net_b, b), b_in_b_tx);
        // A sends from net_a → only net_a's B receives; net_b's B never does.
        forward_frame(&reg, &no_acl(), net_a, &a, &frame(&b, &[9]));
        assert!(b_in_a_rx.try_recv().is_ok(), "same-network dst delivered");
        assert!(
            b_in_b_rx.try_recv().is_err(),
            "cross-network dst must NOT be delivered"
        );
    }
    #[test]
    fn unknown_dst_is_dropped_silently() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        // No registrations at all — forwarding must not panic.
        forward_frame(&reg, &no_acl(), net, &pk(0xAA), &frame(&pk(0xCC), &[1]));
    }
    /// The bypass this gate closes: both ends are registered in the same
    /// network and hold each other's pubkeys, but the ACL denies the pair.
    #[test]
    fn enforcing_acl_drops_a_denied_pair_even_though_both_are_registered() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        // Table enforces and lists no A→B pair.
        let acl = acl_with(net, crate::derp_acl::DerpAllowTable::for_test(true, &[]));
        forward_frame(&reg, &acl, net, &a, &frame(&b, &[1, 2, 3]));
        assert!(
            b_rx.try_recv().is_err(),
            "a pair the overlay ACL denies must not relay through DERP"
        );
        // Same registry, same frame — permitted once the pair is allowed.
        let acl = acl_with(
            net,
            crate::derp_acl::DerpAllowTable::for_test(true, &[(a, b)]),
        );
        forward_frame(&reg, &acl, net, &a, &frame(&b, &[1, 2, 3]));
        assert!(b_rx.try_recv().is_ok(), "an allowed pair must still relay");
    }
    /// `warn` must never drop — the evidence-first cutover, mirroring the
    /// netmap shaping and the node-side reverse-path filter.
    #[test]
    fn warn_mode_acl_delivers_even_an_unlisted_pair() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        let acl = acl_with(net, crate::derp_acl::DerpAllowTable::for_test(false, &[]));
        forward_frame(&reg, &acl, net, &a, &frame(&b, &[7]));
        assert!(b_rx.try_recv().is_ok(), "warn mode must not drop");
    }
    #[test]
    fn short_frame_without_full_pubkey_is_dropped() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (dst_tx, mut dst_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, pk(0xBB)), dst_tx);
        // 10 bytes < 32 → no dst pubkey → dropped, nothing delivered.
        forward_frame(&reg, &no_acl(), net, &pk(0xAA), &[0u8; 10]);
        assert!(dst_rx.try_recv().is_err());
    }
    // ── FR-20: the billing invariant ────────────────────────────────────
    //
    // The ledger must count EXACTLY the bytes this pod carried — no more, and
    // nothing at all for a frame it dropped. That is pinned per DROP PATH
    // rather than once on the happy path, because every `return` in
    // `forward_frame` is a branch where the bytes cost us nothing: an edit
    // that hoisted `add_network_bytes` above one of them would bill a tenant
    // for traffic that never left the pod, and no existing test would notice.
    //
    // ⚠️ Reads the one network's counter directly instead of calling
    // `drain_network_bytes()`: the drain takes EVERY network and zeroes it, so
    // using it here would steal the counters of tests running in parallel in
    // this same binary. A fresh `ObjectId` per test keeps each case isolated.
    fn billed(net: ObjectId) -> u64 {
        DERP_NETWORK_BYTES
            .get(&net)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    #[test]
    fn a_relayed_frame_bills_exactly_the_bytes_it_carried() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        forward_frame(&reg, &no_acl(), net, &a, &frame(&b, &[1, 2, 3]));
        assert!(b_rx.try_recv().is_ok(), "precondition: the frame relayed");
        // What goes on the wire is `src_pubkey || payload` — 32 + 3 — not the
        // inbound frame length. Billing the inbound length would double-count
        // the dst pubkey the pod strips off.
        assert_eq!(
            billed(net),
            35,
            "the ledger must bill the bytes actually sent (32 src + 3 payload)"
        );
    }
    #[test]
    fn two_relayed_frames_accumulate() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, _b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        forward_frame(&reg, &no_acl(), net, &a, &frame(&b, &[1, 2, 3]));
        forward_frame(&reg, &no_acl(), net, &a, &frame(&b, &[4, 5]));
        assert_eq!(billed(net), 35 + 34, "the bucket is additive across frames");
    }
    #[test]
    fn an_unregistered_dst_bills_nothing() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        // Nobody registered: the frame is dropped before it is ever built.
        forward_frame(
            &reg,
            &no_acl(),
            net,
            &pk(0xAA),
            &frame(&pk(0xBB), &[1, 2, 3]),
        );
        assert_eq!(
            billed(net),
            0,
            "a dropped frame costs nothing and bills nothing"
        );
    }
    #[test]
    fn a_cross_network_frame_bills_neither_network() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let (net_a, net_b) = (ObjectId::new(), ObjectId::new());
        let b = pk(0xBB);
        let (b_tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        // B exists, but only in net_b. A sends from net_a.
        reg.insert((net_b, b), b_tx);
        forward_frame(&reg, &no_acl(), net_a, &pk(0xAA), &frame(&b, &[1, 2, 3]));
        assert_eq!(billed(net_a), 0, "the sender's network carried nothing");
        assert_eq!(
            billed(net_b),
            0,
            "and the bystander network must not be billed"
        );
    }
    #[test]
    fn an_acl_denied_frame_bills_nothing() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        // Enforcing table that lists neither pair ⇒ the frame is refused.
        // ⚠️ `for_test(true, …)`, not `default()`: a default table is WARN mode,
        // which permits — so the precondition below would pass while billing
        // zero for the wrong reason. It caught exactly that when first written.
        let acl = acl_with(net, crate::derp_acl::DerpAllowTable::for_test(true, &[]));
        forward_frame(&reg, &acl, net, &a, &frame(&b, &[1, 2, 3]));
        assert!(b_rx.try_recv().is_err(), "precondition: the ACL dropped it");
        assert_eq!(
            billed(net),
            0,
            "policy-refused traffic never left the pod, so it must not be billed"
        );
    }
    #[test]
    fn a_frame_dropped_on_a_full_queue_bills_nothing() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        // Capacity 1, pre-filled ⇒ the next try_send fails.
        let (b_tx, _b_rx) = mpsc::channel::<Vec<u8>>(1);
        b_tx.try_send(vec![0u8; 4]).expect("prime the queue");
        reg.insert((net, b), b_tx);
        forward_frame(&reg, &no_acl(), net, &a, &frame(&b, &[1, 2, 3]));
        assert_eq!(
            billed(net),
            0,
            "a frame the pod could not enqueue was never carried — the slow-consumer \
             path must not become a bill"
        );
    }
    #[test]
    fn warn_mode_acl_delivers_and_therefore_bills() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, b), b_tx);
        // Warn mode lists no pair but permits anyway — the point of warn is to
        // gather evidence WITHOUT dropping. The bytes really do leave the pod,
        // so the mirror of the test above holds: they must be billed.
        let acl = acl_with(net, crate::derp_acl::DerpAllowTable::for_test(false, &[]));
        forward_frame(&reg, &acl, net, &a, &frame(&b, &[1, 2, 3]));
        assert!(b_rx.try_recv().is_ok(), "precondition: warn mode delivers");
        assert_eq!(
            billed(net),
            35,
            "traffic warn mode carried is traffic we paid for"
        );
    }
    #[test]
    fn a_malformed_frame_bills_nothing() {
        let reg: DerpRegistry = Arc::new(DashMap::new());
        let net = ObjectId::new();
        let (b_tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        reg.insert((net, pk(0xBB)), b_tx);
        // Under 32 bytes: no dst pubkey to parse.
        forward_frame(&reg, &no_acl(), net, &pk(0xAA), &[0u8; 10]);
        assert_eq!(billed(net), 0);
    }
}
