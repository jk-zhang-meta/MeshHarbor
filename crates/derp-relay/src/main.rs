// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `derp-relay` — the standalone regional DERP relay (one per relay PoP).
//!
//! A pubkey-addressed WebSocket forwarder for the overlay's both-UDP-blocked
//! carrier tier, functionally the API pods' `/derp` (see
//! `crates/api/src/ws/derp.rs`) minus everything a $5 PoP must not hold:
//!
//! - **No JWT secret.** Admission is an Ed25519 TICKET minted by the API
//!   (`remote_control::derp_ticket`); this binary holds only the PUBLIC key
//!   (`DERP_TICKET_PUBLIC_KEY`). A compromised PoP can forge nothing.
//! - **No Mongo.** The ticket carries the two facts the central relay reads
//!   from the DB: the node's overlay `network` (forwarding scope) and its
//!   `wg pubkey` (the only key it may register — checked against the first
//!   frame, so a stolen ticket can't intercept another node's traffic).
//! - **No cluster machinery.** One process per PoP; both ends of a pair are
//!   pushed the same regional URL by the API, so rendezvous is structural.
//!
//! The wire protocol is IDENTICAL to the central `/derp` (registration frame,
//! `[dst_pk(32)‖payload]` ≤ 2048 B, src-rewrite on delivery, drop-on-overflow)
//! — `DerpConn`/`DerpMux` on the agent work unchanged.
//!
//! Deployment: plain HTTP/WS on `DERP_BIND` (default `127.0.0.1:8443`); the
//! PoP's nginx terminates TLS for `derp-{region}.roomler.ai:443` and proxies
//! here (`scripts/relay-pop/`). `/healthz` serves the health cron.
//!
//! v1 scope note: the central relay additionally consults the overlay-ACL
//! DERP table (`ws/derp_acl.rs`) for ENFORCING tenants. Tickets don't carry
//! per-peer allow-lists yet, so a PoP enforces network scoping only; ACL
//! claims are the designed extension (the netmap already withholds denied
//! peers' keys from honest clients).

use axum::{
    Router,
    body::Bytes,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::Response,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::derp_frame::frame_is_bulk;
use meshharbor_remote_control::derp_ticket::{self, AllowanceSetClaims};
// Shared through remote_control so mint and verify can never version-drift.
use meshharbor_remote_control::derp_ticket::jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// 32-byte WireGuard public key — the addressing unit.
type DerpPubKey = [u8; 32];
/// Registry key: a pubkey is reachable only WITHIN its overlay network.
type DerpKey = (String, DerpPubKey);
type Registry = Arc<DashMap<DerpKey, mpsc::Sender<Vec<u8>>>>;

/// Same limits as the central relay (`api/src/ws/derp.rs`).
const DERP_SEND_QUEUE: usize = 256;
const DERP_MAX_FRAME: usize = 2048;

/// FR-20 B — bytes this PoP has relayed, per overlay network, since process
/// start. **Cumulative and never reset**: the API's poller diffs successive
/// `/stats` samples, exactly as it already does for the host `net_*_bytes`
/// counters.
///
/// ⚠ This binary stays **DB-free** — that is a design invariant, not an
/// oversight. It holds the ticket's public key and nothing else, so a PoP
/// cannot attribute a network to a tenant and must not try. It counts; the API
/// resolves and bills.
type NetworkBytes = Arc<DashMap<String, AtomicU64>>;

/// FR-115 P4a-2 — the smallest bucket: one second at the rate, but never
/// under this, so a burst of full-size frames can always start (as on the
/// API pods).
const MIN_BURST_BYTES: f64 = 64.0 * 1024.0;
/// The longest a pushed set is kept, whatever its `ttl` says.
const MAX_SET_TTL: Duration = Duration::from_secs(3600);
/// One drop line per network per this long.
const SHAPED_LOG_EVERY: Duration = Duration::from_secs(10);

/// FR-115 P4a-2 — the relay allowance on this PoP: the over-allowance set
/// the API pushes on its `/stats` poll (`POST`, signed with the ticket key,
/// `remote_control::derp_ticket::AllowanceSetClaims`), and the per-network
/// token buckets it drives. It mirrors the API pods' throttle
/// (`modules/network/src/relay_allowance.rs`): BULK frames only, by the same
/// classifier (`remote_control::derp_frame`), so a WireGuard handshake and
/// disco always pass and the floor still connects.
///
/// ⚠ Fail open, always. A set lapses `ttl` after it ARRIVED unless a newer
/// one replaces it, so a PoP the API stops reaching throttles nothing; and
/// the PoP holds no secret and no database — it is told which networks to
/// hold back, and verifies only that the API said so.
#[derive(Default)]
struct Allowance {
    set: RwLock<Option<PushedSet>>,
    /// The held set's size: while it is 0, the hot path is one relaxed load.
    len: AtomicUsize,
    buckets: DashMap<String, Mutex<(f64, Instant)>>,
    shaped_total: AtomicU64,
    /// network → when its last drop was logged.
    logged_at: DashMap<String, Instant>,
}

struct PushedSet {
    /// network hex → throttled rate (bytes/s).
    rates: HashMap<String, u64>,
    iat: u64,
    arrived: Instant,
    ttl: Duration,
}

impl PushedSet {
    fn live(&self) -> bool {
        self.arrived.elapsed() <= self.ttl
    }
}

impl Allowance {
    /// The throttled rate for `network`, while a live set names it.
    fn rate_of(&self, network: &str) -> Option<u64> {
        if self.len.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let held = self.set.read().unwrap_or_else(|p| p.into_inner());
        match held.as_ref() {
            Some(set) if set.live() => set.rates.get(network).copied(),
            _ => {
                // Lapsed: back to the one-load fast path. Safe under the read
                // lock, since `apply` stores a new size under the write lock.
                self.len.store(0, Ordering::Relaxed);
                None
            }
        }
    }

    /// Debit `len` bytes from the network's bucket at `rate` bytes/s; `false`
    /// means over the rate, and the frame is dropped, as the API pods drop
    /// it (WireGuard rides UDP semantics; TCP inside it backs off).
    fn permits(&self, network: &str, len: usize, rate: u64) -> bool {
        let rate = rate as f64;
        let burst = rate.max(MIN_BURST_BYTES);
        let entry = self
            .buckets
            .entry(network.to_string())
            .or_insert_with(|| Mutex::new((burst, Instant::now())));
        let mut bucket = entry.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        bucket.0 = (bucket.0 + now.duration_since(bucket.1).as_secs_f64() * rate).min(burst);
        bucket.1 = now;
        if bucket.0 >= len as f64 {
            bucket.0 -= len as f64;
            true
        } else {
            false
        }
    }

    /// Count a dropped frame, and log it at most once per network per
    /// [`SHAPED_LOG_EVERY`].
    fn shaped(&self, network: &str, rate: u64) {
        let total = self.shaped_total.fetch_add(1, Ordering::Relaxed) + 1;
        let now = Instant::now();
        let due = match self.logged_at.get(network) {
            Some(at) => now.duration_since(*at) >= SHAPED_LOG_EVERY,
            None => true,
        };
        if due {
            self.logged_at.insert(network.to_string(), now);
            info!(
                %network,
                rate_bytes_per_sec = rate,
                derp_allowance_shaped_total = total,
                "derp-relay: bulk frame dropped by the relay allowance (the org is past its plan's monthly relay)"
            );
        }
    }

    /// Hold a verified set. `false` (refused) when it is older than a set
    /// still held, so a captured set cannot be replayed over a newer one.
    fn apply(&self, claims: AllowanceSetClaims) -> bool {
        let mut held = self.set.write().unwrap_or_else(|p| p.into_inner());
        if let Some(cur) = held.as_ref()
            && cur.live()
            && claims.iat < cur.iat
        {
            return false;
        }
        let rates: HashMap<String, u64> = claims.set.into_iter().collect();
        let (entered, left) = match held.as_ref().filter(|s| s.live()) {
            Some(cur) => (
                rates.keys().filter(|k| !cur.rates.contains_key(*k)).count(),
                cur.rates.keys().filter(|k| !rates.contains_key(*k)).count(),
            ),
            None => (rates.len(), 0),
        };
        // A network that left the set drops its bucket; one that re-enters
        // later starts with a full burst.
        self.buckets.retain(|k, _| rates.contains_key(k));
        self.len.store(rates.len(), Ordering::Relaxed);
        if entered > 0 || left > 0 {
            info!(
                over = rates.len(),
                entered, left, "derp-relay: the throttled networks changed"
            );
        }
        *held = Some(PushedSet {
            rates,
            iat: claims.iat,
            arrived: Instant::now(),
            ttl: Duration::from_secs(claims.ttl).min(MAX_SET_TTL),
        });
        true
    }

    /// What `/stats` reports: the live set's size, its age, the drops.
    fn snapshot(&self) -> serde_json::Value {
        let held = self.set.read().unwrap_or_else(|p| p.into_inner());
        let live = held.as_ref().filter(|s| s.live());
        serde_json::json!({
            "networks": live.map_or(0, |s| s.rates.len()),
            "age_s": live.map(|s| s.arrived.elapsed().as_secs()),
            "shaped_total": self.shaped_total.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone)]
struct RelayState {
    registry: Registry,
    ticket_key: Arc<DecodingKey>,
    network_bytes: NetworkBytes,
    allowance: Arc<Allowance>,
}

#[derive(Deserialize)]
struct DerpParams {
    ticket: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let public_b64 = std::env::var("DERP_TICKET_PUBLIC_KEY")
        .expect("DERP_TICKET_PUBLIC_KEY (base64 raw 32-byte Ed25519 public key) is required");
    let ticket_key = derp_ticket::decoding_key_from_public_b64(&public_b64)
        .expect("DERP_TICKET_PUBLIC_KEY is not a valid Ed25519 public key");
    let bind = std::env::var("DERP_BIND").unwrap_or_else(|_| "127.0.0.1:8443".into());

    let state = RelayState {
        registry: Arc::new(DashMap::new()),
        ticket_key: Arc::new(ticket_key),
        network_bytes: Arc::new(DashMap::new()),
        allowance: Arc::new(Allowance::default()),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    info!(%bind, "derp-relay listening");
    axum::serve(listener, app).await.expect("serve");
}

fn router(state: RelayState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // FR-115 P4a-2 — the API's poll GETs the snapshot and POSTs the
        // over-allowance set, on the one path nginx already proxies.
        .route("/stats", get(stats).post(allowance_push))
        .route("/derp", get(derp_upgrade))
        .with_state(state)
}

/// `POST /stats` — FR-115 P4a-2: the API's over-allowance set, an EdDSA JWT
/// signed with the ticket key (`remote_control::derp_ticket::
/// verify_allowance_set`). 204 when held; 401 when it does not verify (a
/// foreign key, a ticket, expired); 409 when it is older than a set still
/// held. Whatever is refused changes nothing.
async fn allowance_push(State(state): State<RelayState>, body: Bytes) -> StatusCode {
    let Ok(token) = std::str::from_utf8(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let claims = match derp_ticket::verify_allowance_set(token.trim(), &state.ticket_key) {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "derp-relay: refused an allowance set");
            return StatusCode::UNAUTHORIZED;
        }
    };
    if state.allowance.apply(claims) {
        StatusCode::NO_CONTENT
    } else {
        debug!("derp-relay: an allowance set older than the one held; ignored");
        StatusCode::CONFLICT
    }
}

/// `GET /stats` — the PoP's load snapshot for the API's load-aware region
/// routing: system load/memory/uptime + per-interface traffic counters from
/// `/proc` (host-visible: the container runs host-network and /proc's
/// loadavg/meminfo/net are not namespaced away), live DERP registrations from
/// the in-process registry, and coturn's allocation gauges scraped from its
/// localhost prometheus listener (absent → `null`, never an error — a PoP
/// without the coturn exporter still reports its system half).
async fn stats(State(state): State<RelayState>) -> axum::Json<serde_json::Value> {
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut load_it = load.split_whitespace();
    let load1: f64 = load_it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load5: f64 = load_it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kb = |key: &str| -> u64 {
        meminfo
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };

    // Aggregate rx/tx across physical interfaces (skip lo). Monotonic
    // counters — the poller derives rates from successive samples.
    let netdev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in netdev.lines().skip(2) {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        if iface.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .map(|v| v.parse().unwrap_or(0))
            .collect();
        if f.len() >= 9 {
            rx = rx.saturating_add(f[0]);
            tx = tx.saturating_add(f[8]);
        }
    }

    let uptime_s: f64 = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0);

    axum::Json(serde_json::json!({
        "region": std::env::var("REGION").unwrap_or_default(),
        "cpus": cpus,
        "load1": load1,
        "load5": load5,
        "mem_total_kb": mem_kb("MemTotal:"),
        "mem_available_kb": mem_kb("MemAvailable:"),
        "net_rx_bytes": rx,
        "net_tx_bytes": tx,
        "uptime_s": uptime_s,
        "derp_registrations": state.registry.len(),
        // FR-20 B — cumulative relayed bytes per overlay network, since this
        // process started. The API poller diffs successive samples and resolves
        // network → tenant; this binary never learns which tenant is which.
        //
        // ⚠ A restart resets these to zero, so the poller's diff for that
        // interval goes NEGATIVE and is discarded — the bucket under-reports
        // rather than going wrong, the identical trade the host `net_*_bytes`
        // counters above already make. Do not "fix" it with a fabricated
        // carry-over; an invented byte on a cost ledger is worse than a
        // missing one.
        "per_network": state
            .network_bytes
            .iter()
            .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
            .collect::<std::collections::HashMap<String, u64>>(),
        "coturn": coturn_prometheus().await,
        // FR-115 P4a-2 — the relay allowance as this PoP holds it: how many
        // networks are throttled, how old the pushed set is, and the frames
        // dropped. `age_s` null = no live set (nothing is throttled).
        "allowance": state.allowance.snapshot(),
    }))
}

/// Scrape coturn's localhost prometheus listener (`prometheus` directive,
/// :9641 — firewalled to loopback by provision.sh) for the gauges the router
/// cares about. Minimal HTTP/1.0 over a raw socket — not worth an HTTP-client
/// dependency for one localhost endpoint. `null` on any failure.
async fn coturn_prometheus() -> serde_json::Value {
    let fetch = async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", 9641))
            .await
            .ok()?;
        s.write_all(b"GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .ok()?;
        let mut body = String::new();
        s.read_to_string(&mut body).await.ok()?;
        let gauge = |name: &str| -> f64 {
            body.lines()
                .filter(|l| l.starts_with(name) && !l.starts_with('#'))
                .filter_map(|l| l.split_whitespace().last()?.parse::<f64>().ok())
                .sum()
        };
        Some(serde_json::json!({
            // Live allocations = the direct "how busy is this TURN" signal.
            "allocations": gauge("turn_total_allocations"),
            "sessions": gauge("turn_total_sessions"),
        }))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(1), fetch).await {
        Ok(Some(v)) => v,
        _ => serde_json::Value::Null,
    }
}

/// `GET /derp?ticket=<eddsa-jwt>` — verify the ticket, then upgrade.
async fn derp_upgrade(
    State(state): State<RelayState>,
    Query(params): Query<DerpParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match derp_ticket::verify(&params.ticket, &state.ticket_key) {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "derp-relay: rejected ticket");
            return Response::builder()
                .status(401)
                .body("Unauthorized (derp ticket)".into())
                .unwrap();
        }
    };
    ws.on_upgrade(move |socket| handle_socket(state, socket, claims.net, claims.pk))
}

/// Drive one connection: validate the registration frame against the ticket's
/// pubkey, register, pump frames until close. Mirrors the central relay's
/// loop (last-writer-wins re-registration, identity-gated deregistration).
async fn handle_socket(state: RelayState, socket: WebSocket, network: String, ticket_pk: String) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // First frame MUST be the 32-byte registration pubkey and MUST equal the
    // ticket's `pk` — a node can only register the key its ticket names.
    let self_pubkey: DerpPubKey = match ws_rx.next().await {
        Some(Ok(Message::Binary(b))) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b[..]);
            k
        }
        _ => {
            debug!("derp-relay: bad or absent registration frame; closing");
            return;
        }
    };
    if BASE64.encode(self_pubkey) != ticket_pk {
        warn!("derp-relay: registration pubkey != ticket pk; refusing");
        return;
    }

    let key: DerpKey = (network.clone(), self_pubkey);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(DERP_SEND_QUEUE);
    // Last-writer-wins on re-registration (a reconnect replaces the stale
    // sender; the displaced socket keeps working as a SENDER until it closes).
    state.registry.insert(key.clone(), out_tx.clone());
    info!(%network, "derp-relay: node registered");

    let mut write = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    loop {
        tokio::select! {
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Binary(frame))) => {
                    forward_frame(
                        &state.registry,
                        &state.network_bytes,
                        &state.allowance,
                        &network,
                        &self_pubkey,
                        &frame[..],
                    );
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {} // text/ping/pong — axum auto-pongs
            },
            _ = &mut write => break,
        }
    }

    // Deregister only if we're still the registered sender (a newer
    // reconnect may have replaced us; we must not evict it).
    state
        .registry
        .remove_if(&key, |_, tx| tx.same_channel(&out_tx));
    write.abort();
    info!(%network, "derp-relay: node disconnected");
}

/// `[dst_pk(32)‖payload]` from `src` → `[src_pk(32)‖payload]` to dst, only
/// within `network`. Drops silently on short/oversized frames, unknown dst,
/// or a full destination queue (the carrier is loss-tolerant).
fn forward_frame(
    registry: &Registry,
    network_bytes: &NetworkBytes,
    allowance: &Allowance,
    network: &str,
    src_pubkey: &DerpPubKey,
    frame: &[u8],
) {
    if frame.len() < 32 || frame.len() > DERP_MAX_FRAME {
        return;
    }
    let mut dst = [0u8; 32];
    dst.copy_from_slice(&frame[..32]);
    let payload = &frame[32..];
    // FR-115 P4a-2 — the relay allowance, exactly as on the API pods: a
    // network whose org is past its plan's monthly relay has its BULK frames
    // held to its rate, and a WireGuard handshake and disco always pass. While
    // no set is held, this is one relaxed atomic load.
    if let Some(rate) = allowance.rate_of(network)
        && frame_is_bulk(payload)
        && !allowance.permits(network, frame.len(), rate)
    {
        allowance.shaped(network, rate);
        return;
    }
    let sender = match registry.get(&(network.to_string(), dst)) {
        Some(r) => r.clone(),
        None => return,
    };
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(src_pubkey);
    out.extend_from_slice(payload);
    let n = out.len() as u64;
    // FR-20 B — count only what we actually delivered. Same rule as the API
    // pod: a frame dropped on a full queue cost us nothing and must not appear
    // on any tenant's ledger. One atomic add; the PoP never touches a DB.
    if sender.try_send(out).is_ok() {
        if let Some(c) = network_bytes.get(network) {
            c.fetch_add(n, Ordering::Relaxed);
        } else {
            network_bytes
                .entry(network.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(n, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use meshharbor_remote_control::derp_ticket::DerpTicketSigner;
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    fn pk(byte: u8) -> DerpPubKey {
        [byte; 32]
    }

    fn test_signer() -> (DerpTicketSigner, DecodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = DerpTicketSigner::from_pkcs8_b64(&BASE64.encode(pkcs8.as_ref())).unwrap();
        let key = derp_ticket::decoding_key_from_public_b64(signer.public_key_b64()).unwrap();
        (signer, key)
    }

    async fn serve(key: DecodingKey) -> (std::net::SocketAddr, Registry) {
        let state = RelayState {
            registry: Arc::new(DashMap::new()),
            ticket_key: Arc::new(key),
            network_bytes: Arc::new(DashMap::new()),
            allowance: Arc::new(Allowance::default()),
        };
        let registry = state.registry.clone();
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, registry)
    }

    async fn connect(
        addr: std::net::SocketAddr,
        ticket: &str,
        reg_pk: DerpPubKey,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let url = format!("ws://{addr}/derp?ticket={ticket}");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws.send(WsMsg::Binary(reg_pk.to_vec().into()))
            .await
            .unwrap();
        ws
    }

    #[tokio::test]
    async fn forwards_within_network_and_rewrites_src() {
        let (signer, key) = test_signer();
        let (addr, _) = serve(key).await;
        let (a, b) = (pk(0xAA), pk(0xBB));
        let (ta, _) = signer.mint("net1", &BASE64.encode(a)).unwrap();
        let (tb, _) = signer.mint("net1", &BASE64.encode(b)).unwrap();
        let mut ws_a = connect(addr, &ta, a).await;
        let mut ws_b = connect(addr, &tb, b).await;
        // Registration is processed on the relay's read loop; give B's
        // registry insert a beat before A sends.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut frame = b.to_vec();
        frame.extend_from_slice(&[1, 2, 3]);
        ws_a.send(WsMsg::Binary(frame.into())).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), ws_b.next())
            .await
            .expect("B receives within 5s")
            .unwrap()
            .unwrap();
        let data = got.into_data();
        assert_eq!(&data[..32], &a, "src prefix rewritten to the sender");
        assert_eq!(&data[32..], &[1, 2, 3]);
    }

    #[tokio::test]
    async fn never_crosses_networks_and_rejects_bad_tickets() {
        let (signer, key) = test_signer();
        let (addr, _) = serve(key).await;
        let (a, b) = (pk(0x01), pk(0x02));
        let (ta, _) = signer.mint("net1", &BASE64.encode(a)).unwrap();
        // Same pubkey B, registered in ANOTHER network.
        let (tb, _) = signer.mint("net2", &BASE64.encode(b)).unwrap();
        let mut ws_a = connect(addr, &ta, a).await;
        let mut ws_b = connect(addr, &tb, b).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut frame = b.to_vec();
        frame.extend_from_slice(&[9]);
        ws_a.send(WsMsg::Binary(frame.into())).await.unwrap();
        // Cross-network: B must receive nothing.
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), ws_b.next()).await;
        assert!(r.is_err(), "cross-network frame must not be delivered");

        // A ticket signed by a FOREIGN key is refused at upgrade.
        let (foreign_signer, _) = test_signer();
        let (bad, _) = foreign_signer.mint("net1", &BASE64.encode(a)).unwrap();
        let url = format!("ws://{addr}/derp?ticket={bad}");
        assert!(
            tokio_tungstenite::connect_async(&url).await.is_err(),
            "foreign-signed ticket must 401"
        );
    }

    #[tokio::test]
    async fn stats_serves_system_snapshot() {
        let (_, key) = test_signer();
        let (addr, _) = serve(key).await;
        let body = reqwest_lite(addr, "/stats").await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("stats is JSON");
        // /proc-backed fields exist on Linux; on other CI hosts they parse to
        // zero — the shape is the contract either way.
        assert!(v["cpus"].as_u64().unwrap() >= 1);
        assert!(v["load1"].is_number());
        assert!(v["derp_registrations"].is_u64());
        // No coturn exporter in the test env → explicit null, not an error.
        assert!(v["coturn"].is_null());
    }

    /// Tiny HTTP/1.0 GET so the test needs no client dependency.
    async fn reqwest_lite(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.0\r\nHost: t\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        resp.split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn registration_pubkey_must_match_ticket() {
        let (signer, key) = test_signer();
        let (addr, registry) = serve(key).await;
        let (a, victim) = (pk(0x0A), pk(0x0B));
        // Ticket names A, but the socket tries to register VICTIM's key.
        let (ta, _) = signer.mint("net1", &BASE64.encode(a)).unwrap();
        let _ws = connect(addr, &ta, victim).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            registry.is_empty(),
            "mismatched registration must never enter the registry"
        );
    }

    // ── FR-115 P4a-2 — the relay allowance on a PoP ─────────────────────

    use meshharbor_remote_control::derp_ticket::jsonwebtoken::{
        self, Algorithm, EncodingKey, Header,
    };

    /// A signer plus the raw PKCS#8 key, to sign hand-made claims with.
    fn test_keys() -> (DerpTicketSigner, DecodingKey, EncodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = DerpTicketSigner::from_pkcs8_b64(&BASE64.encode(pkcs8.as_ref())).unwrap();
        let key = derp_ticket::decoding_key_from_public_b64(signer.public_key_b64()).unwrap();
        (signer, key, EncodingKey::from_ed_der(pkcs8.as_ref()))
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn claims(set: &[(&str, u64)], iat: u64, ttl: u64) -> AllowanceSetClaims {
        AllowanceSetClaims {
            aud: derp_ticket::ALLOWANCE_AUDIENCE.to_string(),
            iat,
            exp: iat + ttl,
            ttl,
            set: set.iter().map(|(n, r)| (n.to_string(), *r)).collect(),
        }
    }

    fn sign(enc: &EncodingKey, c: &AllowanceSetClaims) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), c, enc).unwrap()
    }

    /// Tiny HTTP/1.0 POST; the status code.
    async fn post_lite(addr: std::net::SocketAddr, path: &str, body: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: t\r\nContent-Type: application/jwt\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        resp.split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    /// Frames `ws` receives until it has been quiet for 400 ms.
    async fn drain(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> usize {
        let mut n = 0;
        while let Ok(Some(Ok(m))) =
            tokio::time::timeout(std::time::Duration::from_millis(400), ws.next()).await
        {
            if matches!(m, WsMsg::Binary(_)) {
                n += 1;
            }
        }
        n
    }

    /// A pushed set holds a listed network's BULK frames to its rate (here
    /// the 64 KiB minimum burst, at 1 kB/s), lets every WireGuard handshake
    /// through, and leaves a network it does not name alone.
    #[tokio::test]
    async fn a_pushed_set_holds_bulk_and_passes_the_handshake() {
        let (signer, key) = test_signer();
        let (addr, _) = serve(key).await;
        let (a, b, c, d) = (pk(0x31), pk(0x32), pk(0x33), pk(0x34));
        let mint = |net: &str, p: DerpPubKey| signer.mint(net, &BASE64.encode(p)).unwrap().0;
        let mut ws_a = connect(addr, &mint("net1", a), a).await;
        let mut ws_b = connect(addr, &mint("net1", b), b).await;
        let mut ws_c = connect(addr, &mint("net2", c), c).await;
        let mut ws_d = connect(addr, &mint("net2", d), d).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let token = signer
            .sign_allowance_set(
                std::collections::BTreeMap::from([("net1".to_string(), 1_000)]),
                90,
            )
            .unwrap();
        assert_eq!(post_lite(addr, "/stats", &token).await, 204);

        // 100 WireGuard data frames of 1436 bytes = 143,600 bytes: about 45
        // fit the 65,536-byte burst.
        let bulk = |dst: DerpPubKey| {
            let mut f = dst.to_vec();
            f.extend_from_slice(&[4, 0, 0, 0]);
            f.extend_from_slice(&[0xAB; 1400]);
            f
        };
        for _ in 0..100 {
            ws_a.send(WsMsg::Binary(bulk(b).into())).await.unwrap();
        }
        let got = drain(&mut ws_b).await;
        assert!(
            (30..60).contains(&got),
            "net1 is held to its burst: {got} of 100"
        );

        // Handshakes always pass, whatever the bucket holds.
        for _ in 0..20 {
            let mut f = b.to_vec();
            f.extend_from_slice(&[1, 0, 0, 0]);
            f.extend_from_slice(&[0xCD; 144]);
            ws_a.send(WsMsg::Binary(f.into())).await.unwrap();
        }
        assert_eq!(drain(&mut ws_b).await, 20, "every handshake passes");

        // A network the set does not name is not throttled at all.
        for _ in 0..100 {
            ws_c.send(WsMsg::Binary(bulk(d).into())).await.unwrap();
        }
        assert_eq!(drain(&mut ws_d).await, 100, "net2 is untouched");
    }

    /// Only a set the API signed is held: a foreign key and a ticket are
    /// 401, a set older than the one held is 409, and `/stats` says what
    /// is held.
    #[tokio::test]
    async fn only_the_apis_newest_set_is_held() {
        let (signer, key, enc) = test_keys();
        let (addr, _) = serve(key).await;
        let now = now_secs();

        let (foreign, _, _) = test_keys();
        let set = std::collections::BTreeMap::from([("net1".to_string(), 500_000)]);
        let alien = foreign.sign_allowance_set(set, 90).unwrap();
        assert_eq!(
            post_lite(addr, "/stats", &alien).await,
            401,
            "a foreign key"
        );
        let (ticket, _) = signer.mint("net1", &BASE64.encode(pk(1))).unwrap();
        assert_eq!(
            post_lite(addr, "/stats", &ticket).await,
            401,
            "a ticket is not a set"
        );

        let newer = sign(&enc, &claims(&[("net1", 500_000)], now, 90));
        assert_eq!(post_lite(addr, "/stats", &newer).await, 204);
        let older = sign(&enc, &claims(&[], now - 10, 90));
        assert_eq!(
            post_lite(addr, "/stats", &older).await,
            409,
            "an older set never replaces a newer one"
        );

        let v: serde_json::Value =
            serde_json::from_str(&reqwest_lite(addr, "/stats").await).unwrap();
        assert_eq!(v["allowance"]["networks"], 1, "{v}");
        assert!(v["allowance"]["age_s"].is_u64(), "{v}");
    }

    /// A held set lapses `ttl` after it arrived: nothing is throttled (fail
    /// open), and the hot path is back to one load.
    #[test]
    fn a_set_lapses_after_its_ttl() {
        let a = Allowance::default();
        assert!(a.apply(claims(&[("net1", 1_000)], now_secs(), 1)));
        assert_eq!(a.rate_of("net1"), Some(1_000));
        assert_eq!(a.rate_of("net2"), None);
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert_eq!(a.rate_of("net1"), None, "lapsed: nothing is throttled");
        assert_eq!(a.len.load(Ordering::Relaxed), 0);
        assert_eq!(a.snapshot()["networks"], 0);
        // Once the held set has lapsed, even an older one is taken.
        assert!(a.apply(claims(&[("net1", 2_000)], now_secs() - 5, 60)));
        assert_eq!(a.rate_of("net1"), Some(2_000));
    }
}
