// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-128 / FR-134 — this device as its zone's management entry, and the device side of asking one.
//!
//! An entry is a TCP listener on the gateway's entry port (default `18443`, configurable via
//! `management_entry_port`, or `0` to opt out). A non-gateway never binds the port: the listener
//! starts live when the centre sends a non-empty `rc:agent.management_entry` key and stops live
//! when the centre sends an empty key or the daemon shuts down. A connection that starts with
//! `MHE1 ` asks for an attestation: one line in, one line out (a token naming the address the
//! request came from, signed with the key the centre gave this gateway), then closed. Any other
//! connection is forwarded, unread, to this device's own centre (the host and port of its
//! `server_url`): the device inside runs TLS with the centre, so the entry sees ciphertext only,
//! and the destination never comes from a message.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use meshharbor_remote_control::management_entry as me;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};

/// Connections forwarded at once.
const MAX_CONNS: usize = 1024;
/// Connections at once from one source address.
const MAX_PER_SOURCE: usize = 32;
/// The upstream connect to the centre.
const UPSTREAM_CONNECT: Duration = Duration::from_secs(10);
/// A forwarded connection with no byte either way for this long is closed (the control
/// socket pings every 25 s).
const IDLE: Duration = Duration::from_secs(180);
/// A client must send its first byte within this.
const FIRST_BYTE: Duration = Duration::from_secs(10);

static PORT: AtomicU16 = AtomicU16::new(0);
/// `(this entry's agent id, key)`, from `rc:agent.management_entry`.
static KEY: RwLock<Option<(String, Vec<u8>)>> = RwLock::new(None);
/// Live listener stop signal (`Some(tx)` while a listener task is bound and accepting).
static STOP_TX: Mutex<Option<watch::Sender<bool>>> = Mutex::new(None);
/// Broadcasts `listening_port()` changes so the signaling heartbeat re-announces caps immediately.
static PORT_WATCH: OnceLock<watch::Sender<Option<u16>>> = OnceLock::new();
/// Wakes a primary control socket currently on last-resort direct when a fresh push brings a
/// reachable zone entry online.
static ENTRY_BACK_WAKE: OnceLock<tokio::sync::Notify> = OnceLock::new();

fn port_watch() -> &'static watch::Sender<Option<u16>> {
    PORT_WATCH.get_or_init(|| watch::channel(None).0)
}

/// Shared wake handle notified when an immediate background probe finds a reachable zone entry.
pub fn entry_back_notify() -> &'static tokio::sync::Notify {
    ENTRY_BACK_WAKE.get_or_init(tokio::sync::Notify::new)
}

/// Subscribe to live changes of [`listening_port`].
pub fn subscribe_port_changes() -> watch::Receiver<Option<u16>> {
    port_watch().subscribe()
}

/// The port the entry listens on, once bound.
pub fn listening_port() -> Option<u16> {
    match PORT.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p),
    }
}

/// The TCP port this device would bind if the centre designates it a zone gateway.
/// `None` if `MESHHARBORD_MANAGEMENT_ENTRIES=0`, `protected = true`, or `management_entry_port = 0`.
pub fn allowed_port(cfg: &meshharbor_node_core::config::AgentConfig) -> Option<u16> {
    if meshharbor_node_core::management_path::disabled() {
        return None;
    }
    cfg.management_entry_port_allowed()
}

/// The centre made this device an entry: the key it signs attestations with.
pub fn set_key(entry_id_hex: &str, key: Vec<u8>) {
    *KEY.write().unwrap_or_else(|e| e.into_inner()) = Some((entry_id_hex.to_string(), key));
}

fn key() -> Option<(String, Vec<u8>)> {
    KEY.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// FR-134 — called once at daemon startup. Does NOT bind a TCP listener: a non-gateway never
/// listens, and a zone gateway binds live when the centre delivers its entry key. Logs only when
/// the owner opted out or `protected` is active so operators can see why an entry will not bind.
pub fn maybe_note_startup(cfg: &meshharbor_node_core::config::AgentConfig) {
    if meshharbor_node_core::management_path::disabled() {
        info!("management entry: disabled by MESHHARBORD_MANAGEMENT_ENTRIES=0");
    } else if cfg.protected {
        info!("management entry: will not serve while this device is protected");
    } else if cfg.management_entry_port == Some(0) {
        info!("management entry: switched off by owner (management_entry_port = 0)");
    }
}

/// FR-134 — start (or refresh the key of) the live management entry listener when the centre
/// designates this device a zone gateway. Idempotent while already listening on the allowed port.
/// Returns the bound port, or `None` if refused or bind failed.
pub async fn ensure_started_with_key(
    cfg: &meshharbor_node_core::config::AgentConfig,
    new_key: Vec<u8>,
) -> Option<u16> {
    let Some(port) = allowed_port(cfg) else {
        stop();
        if cfg.protected {
            warn!("management entry: refused, this device is protected");
        } else if cfg.management_entry_port == Some(0) {
            info!("management entry: refused, switched off by owner (management_entry_port = 0)");
        }
        return None;
    };
    set_key(&cfg.agent_id, new_key);
    if listening_port() == Some(port) {
        return Some(port);
    }
    stop_listener_only();
    let Some((host, centre_port)) = centre_of(&cfg.server_url) else {
        warn!(server_url = %cfg.server_url, "management entry: no centre host in server_url, not started");
        return None;
    };
    let listener = match bind(port).await {
        Ok(l) => l,
        Err(e) => {
            warn!(port, %e, "management entry: bind failed, not started");
            return None;
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let (stop_tx, stop_rx) = watch::channel(false);
    *STOP_TX.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop_tx);
    PORT.store(bound_port, Ordering::Relaxed);
    let _ = port_watch().send(Some(bound_port));
    info!(
        port = bound_port,
        centre = %host,
        "management entry: listening; forwards only to this device's centre"
    );
    let upstream = tunnel_core::ctl_dns::hostport(&host, centre_port);
    tokio::spawn(serve(listener, upstream, stop_rx));
    Some(bound_port)
}

fn stop_listener_only() {
    if let Some(tx) = STOP_TX.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = tx.send(true);
    }
    if PORT.swap(0, Ordering::Relaxed) != 0 {
        let _ = port_watch().send(None);
    }
}

/// FR-134 — stop the management entry listener and drop its attestation key (e.g. when the
/// centre demotes this device from zone gateway or the daemon shuts down).
pub fn stop() {
    *KEY.write().unwrap_or_else(|e| e.into_inner()) = None;
    let was_listening = PORT.load(Ordering::Relaxed) != 0;
    stop_listener_only();
    if was_listening {
        info!("management entry: listener stopped");
    }
}

/// `[::]` (both families where the host allows), else `0.0.0.0`.
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    match TcpListener::bind(("::", port)).await {
        Ok(l) => Ok(l),
        Err(_) => TcpListener::bind(("0.0.0.0", port)).await,
    }
}

/// Host and port of the centre named by `server_url`.
fn centre_of(server_url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(server_url).ok()?;
    let host = u.host_str()?.trim_matches(['[', ']']).to_string();
    let port = u.port_or_known_default()?;
    Some((host, port))
}

/// An IPv4 client on a dual-stack socket arrives as `::ffff:a.b.c.d`; the centre compares
/// addresses in their plain form.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

struct SourceSlot {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = c.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                c.remove(&self.ip);
            }
        }
    }
}

async fn serve(listener: TcpListener, upstream: String, mut stop_rx: watch::Receiver<bool>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    let counts: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        if *stop_rx.borrow() {
            return;
        }
        let (stream, peer) = tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    return;
                }
                continue;
            }
            res = listener.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    debug!(%e, "management entry: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!(%peer, "management entry: at capacity, connection dropped");
            continue;
        };
        let ip = canonical(peer.ip());
        {
            let mut c = counts.lock().unwrap_or_else(|e| e.into_inner());
            let n = c.entry(ip).or_insert(0);
            if *n >= MAX_PER_SOURCE {
                debug!(%ip, "management entry: per-source limit, connection dropped");
                continue;
            }
            *n += 1;
        }
        let slot = SourceSlot {
            ip,
            counts: counts.clone(),
        };
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _slot = slot;
            handle(stream, ip, &upstream).await;
        });
    }
}

async fn handle(stream: TcpStream, ip: IpAddr, upstream: &str) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(FIRST_BYTE, stream.peek(&mut first)).await {
        Ok(Ok(1)) => {}
        _ => return,
    }
    if first[0] == me::PREFIX[0] {
        attest(stream, ip).await;
        return;
    }
    forward(stream, upstream).await;
}

/// Answer one attestation request.
async fn attest(stream: TcpStream, ip: IpAddr) {
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(r.take(me::MAX_LINE as u64));
    if tokio::time::timeout(FIRST_BYTE, reader.read_line(&mut line))
        .await
        .is_err()
    {
        return;
    }
    let answer = match (me::parse_request(&line), key()) {
        (None, _) => me::no_line("bad_request"),
        (Some(_), None) => me::no_line("not_an_entry_yet"),
        (Some(nonce), Some((entry_id, key))) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match me::sign(&key, &entry_id, ip, nonce, now) {
                Ok(token) => {
                    debug!(%ip, "management entry: attested");
                    me::ok_line(&token)
                }
                Err(_) => me::no_line("bad_request"),
            }
        }
    };
    let _ = w.write_all(answer.as_bytes()).await;
    let _ = w.shutdown().await;
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Copy the client's bytes to the centre and back, unread, until both sides finish or
/// nothing moves for [`IDLE`].
async fn forward(client: TcpStream, upstream: &str) {
    let mut centre = None;
    for addr in tunnel_core::ctl_dns::resolve(upstream).await {
        if let Ok(Ok(s)) = tokio::time::timeout(UPSTREAM_CONNECT, TcpStream::connect(addr)).await {
            centre = Some(s);
            break;
        }
    }
    let Some(centre) = centre else {
        tunnel_core::ctl_dns::distrust(upstream);
        debug!(%upstream, "management entry: centre unreachable, connection dropped");
        return;
    };
    let _ = centre.set_nodelay(true);
    splice(client, centre, IDLE).await;
}

async fn splice(a: TcpStream, b: TcpStream, idle: Duration) {
    let activity = AtomicU64::new(now_secs());
    let (ar, aw) = a.into_split();
    let (br, bw) = b.into_split();
    let both = async {
        let _ = tokio::join!(pump(ar, bw, &activity), pump(br, aw, &activity));
    };
    let watchdog = async {
        loop {
            tokio::time::sleep(Duration::from_secs(5).min(idle)).await;
            if now_secs().saturating_sub(activity.load(Ordering::Relaxed)) >= idle.as_secs() {
                break;
            }
        }
    };
    tokio::select! {
        _ = both => {}
        _ = watchdog => debug!("management entry: idle connection closed"),
    }
}

async fn pump<R, W>(mut r: R, mut w: W, activity: &AtomicU64) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        activity.store(now_secs(), Ordering::Relaxed);
    }
}

/// Why an attestation was not had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestFailure {
    /// The entry answered, and could not attest (no key yet, a bad request).
    Refused(String),
    /// The entry did not answer: it cannot carry the connection either.
    Unreachable(String),
}

impl std::fmt::Display for AttestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "refused: {r}"),
            Self::Unreachable(r) => write!(f, "unreachable: {r}"),
        }
    }
}

/// Device side: the first of this device's entries (the kept pushed path and the owner's own,
/// in dial order) that answers an attestation request. A refusal still answers: the entry can
/// carry the connection, as the dial itself would use it.
pub async fn first_reachable_entry(local: &[String], centre: &str) -> Option<SocketAddr> {
    use meshharbor_node_core::management_path as mp;
    let pushed = mp::state_path()
        .map(|p| mp::load(&p, centre))
        .unwrap_or_default();
    for c in mp::plan(&pushed, local, None).0 {
        if let mp::Candidate::Entry(entry) = c
            && !matches!(
                request_attestation(entry, Duration::from_secs(5)).await,
                Err(AttestFailure::Unreachable(_))
            )
        {
            return Some(entry);
        }
    }
    None
}

/// Device side: ask `entry` for an attestation of this device's address.
pub async fn request_attestation(
    entry: SocketAddr,
    timeout: Duration,
) -> Result<String, AttestFailure> {
    use AttestFailure::{Refused, Unreachable};
    let work = async {
        let mut s = TcpStream::connect(entry)
            .await
            .map_err(|e| Unreachable(e.to_string()))?;
        let nonce: String = {
            use rand::Rng;
            let mut rng = rand::rng();
            (0..32)
                .map(|_| char::from_digit(rng.random_range(0..16), 16).unwrap_or('0'))
                .collect()
        };
        s.write_all(me::request_line(&nonce).as_bytes())
            .await
            .map_err(|e| Unreachable(e.to_string()))?;
        let mut line = String::new();
        BufReader::new(s.take(me::MAX_LINE as u64))
            .read_line(&mut line)
            .await
            .map_err(|e| Unreachable(e.to_string()))?;
        me::parse_answer(&line).map(str::to_string).map_err(Refused)
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| Unreachable("timed out".to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_centre_is_the_server_urls_host_and_port() {
        assert_eq!(
            centre_of("https://centre.example/prefix"),
            Some(("centre.example".into(), 443))
        );
        assert_eq!(
            centre_of("http://127.0.0.1:5001"),
            Some(("127.0.0.1".into(), 5001))
        );
        assert_eq!(centre_of("not a url"), None);
    }

    /// An entry on loopback forwards a plain TCP exchange to its "centre" and answers an
    /// attestation request with a token the centre's key verifies, naming the caller.
    #[tokio::test]
    async fn a_dead_entry_is_passed_over_for_one_that_answers_even_with_a_refusal() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let alive = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive_addr = alive.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = alive.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            w.write_all(me::no_line("no_key").as_bytes()).await.unwrap();
        });
        let local = [dead_addr.to_string(), alive_addr.to_string()];
        assert_eq!(
            first_reachable_entry(&local, "127.0.0.1").await,
            Some(alive_addr)
        );
    }

    static GLOBAL_ENTRY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn an_entry_forwards_unread_and_attests_the_caller() {
        let _guard = GLOBAL_ENTRY_TEST_LOCK.lock().await;
        stop();
        // The "centre": echoes one line.
        let centre = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let centre_addr = centre.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = centre.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            w.write_all(format!("echo {line}").as_bytes())
                .await
                .unwrap();
        });
        let entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entry_addr = entry.local_addr().unwrap();
        let (_stop_tx, stop_rx) = watch::channel(false);
        tokio::spawn(serve(entry, centre_addr.to_string(), stop_rx));

        // Forwarded unread.
        let mut c = TcpStream::connect(entry_addr).await.unwrap();
        c.write_all(b"\x16hello\n").await.unwrap();
        let mut got = String::new();
        BufReader::new(&mut c).read_line(&mut got).await.unwrap();
        assert_eq!(got, "echo \x16hello\n");

        // No key yet: refused with a reason.
        assert_eq!(
            request_attestation(entry_addr, Duration::from_secs(5)).await,
            Err(AttestFailure::Refused("not_an_entry_yet".to_string()))
        );
        let k = me::derive_key(b"secret", "aa", 1);
        set_key("aa", k.clone());
        let token = request_attestation(entry_addr, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(me::entry_id(&token).unwrap(), "aa");
        let now = now_secs() as i64;
        let a = me::verify(&k, &token, now).unwrap();
        assert_eq!(a.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        stop();
    }

    #[tokio::test]
    async fn a_silent_forwarded_connection_is_closed_when_idle() {
        let centre = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_side = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_side.local_addr().unwrap();
        let c_addr = centre.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(a_addr).await.unwrap() });
        let (a, _) = a_side.accept().await.unwrap();
        let held = client.await.unwrap();
        let up = TcpStream::connect(c_addr).await.unwrap();
        let (_centre_side, _) = centre.accept().await.unwrap();
        let t0 = std::time::Instant::now();
        splice(a, up, Duration::from_secs(1)).await;
        assert!(t0.elapsed() < Duration::from_secs(10));
        drop(held);
    }

    #[tokio::test]
    async fn fr134_entry_starts_live_on_key_stops_without_restart_and_honours_opt_out() {
        let _guard = GLOBAL_ENTRY_TEST_LOCK.lock().await;
        stop();
        // Reserve a free port then release it so we can bind a predictable custom port.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.agent_id = "66f0000000000000000000aa".into();
        cfg.server_url = "https://centre.example.test".into();
        let key = me::derive_key(b"test-secret", &cfg.agent_id, 1);

        // Owner opt-out (`Some(0)`) refuses to start.
        cfg.management_entry_port = Some(0);
        assert_eq!(ensure_started_with_key(&cfg, key.clone()).await, None);
        assert_eq!(listening_port(), None);

        // Protected device refuses to start.
        cfg.management_entry_port = Some(port);
        cfg.protected = true;
        assert_eq!(ensure_started_with_key(&cfg, key.clone()).await, None);
        assert_eq!(listening_port(), None);

        // Allowed gateway starts live on receipt of key, attests callers, and stops cleanly.
        cfg.protected = false;
        let bound = ensure_started_with_key(&cfg, key.clone())
            .await
            .expect("live entry start");
        assert_eq!(bound, port);
        assert_eq!(listening_port(), Some(port));

        let addr: SocketAddr = format!("127.0.0.1:{bound}").parse().unwrap();
        let token = request_attestation(addr, Duration::from_secs(5))
            .await
            .expect("live entry attests");
        assert_eq!(me::entry_id(&token).unwrap(), cfg.agent_id);

        stop();
        assert_eq!(listening_port(), None);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            matches!(
                request_attestation(addr, Duration::from_secs(2)).await,
                Err(AttestFailure::Unreachable(_))
            ),
            "stopped management entry must release its TCP listener"
        );
    }
}
