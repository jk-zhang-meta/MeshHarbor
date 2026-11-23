// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-128 — this device as its zone's management entry, and the device side of asking one.
//!
//! An entry is a TCP listener on `management_entry_port`. A connection that starts with
//! `MHE1 ` asks for an attestation: one line in, one line out (a token naming the address the
//! request came from, signed with the key the centre gave this gateway), then closed. Any other
//! connection is forwarded, unread, to this device's own centre (the host and port of its
//! `server_url`): the device inside runs TLS with the centre, so the entry sees ciphertext only,
//! and the destination never comes from a message.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use meshharbor_remote_control::management_entry as me;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
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

/// The port the entry listens on, once bound.
pub fn listening_port() -> Option<u16> {
    match PORT.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p),
    }
}

/// The centre made this device an entry: the key it signs attestations with.
pub fn set_key(entry_id_hex: &str, key: Vec<u8>) {
    *KEY.write().unwrap_or_else(|e| e.into_inner()) = Some((entry_id_hex.to_string(), key));
}

fn key() -> Option<(String, Vec<u8>)> {
    KEY.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Start the entry when the owner set a port and the device is not protected. Returns at once;
/// the listener runs on its own task for the daemon's life.
pub async fn maybe_start(cfg: &meshharbor_node_core::config::AgentConfig) {
    let Some(port) = cfg.management_entry_port_allowed() else {
        if cfg.management_entry_port.is_some_and(|p| p != 0) && cfg.protected {
            warn!("management entry: refused, this device is protected");
        }
        return;
    };
    let Some((host, centre_port)) = centre_of(&cfg.server_url) else {
        warn!(server_url = %cfg.server_url, "management entry: no centre host in server_url, not started");
        return;
    };
    let listener = match bind(port).await {
        Ok(l) => l,
        Err(e) => {
            warn!(port, %e, "management entry: bind failed, not started");
            return;
        }
    };
    PORT.store(port, Ordering::Relaxed);
    info!(port, centre = %host, "management entry: listening; forwards only to this device's centre");
    let upstream = tunnel_core::ctl_dns::hostport(&host, centre_port);
    tokio::spawn(serve(listener, upstream));
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

async fn serve(listener: TcpListener, upstream: String) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    let counts: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                debug!(%e, "management entry: accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
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
pub async fn first_reachable_entry(local: &[String]) -> Option<SocketAddr> {
    use meshharbor_node_core::management_path as mp;
    let pushed = mp::state_path().map(|p| mp::load(&p)).unwrap_or_default();
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
        assert_eq!(first_reachable_entry(&local).await, Some(alive_addr));
    }

    #[tokio::test]
    async fn an_entry_forwards_unread_and_attests_the_caller() {
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
        tokio::spawn(serve(entry, centre_addr.to_string()));

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
}
