// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #20 slice 2a: the userspace backend for managed forwards
//! (v039 §6). A forward listens on ONE explicit address, admits only its
//! source CIDRs, and relays to its destination: TCP stream for stream, UDP
//! datagram for datagram (boundaries kept), masquerading (the destination
//! sees this node). It never touches routes, the firewall or the node's own
//! control connection.
//!
//! A forward whose destination is behind the overlay (`via_overlay`: a
//! node's overlay address, or a subnet a node routes) dials it through this
//! node's overlay: its userspace stack on a netstack node ([`OverlayDial`]),
//! the host's routes on a node with a TUN. TCP only; the server refuses UDP
//! into the overlay, and so does this end.
//!
//! A forward the server marks `nft` runs on the owned nftables table
//! instead (`managed_forward_nft`, Linux, root, primary enrollment only: the
//! table is host-wide); anywhere else it is reported failed, never relayed
//! in userspace with a different meaning.
//!
//! [`Forwarders::reconcile`] takes the whole desired set and is idempotent:
//! a forward already running at the same revision is left alone, a changed
//! revision is restarted, a forward no longer desired is stopped. Each
//! reconcile reports every forward's state, `listening` or `failed` with the
//! bind error, for the server's applied layer.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use roomler_ai_remote_control::net_inventory::L4;
use roomler_ai_remote_control::signaling::{
    ClientMsg, ForwardBackend, ManagedForwardAssignment, ManagedForwardStatusWire,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Concurrent TCP connections per forward.
pub const MAX_TCP_CONNS: usize = 256;
/// UDP client sessions per forward, and how long an idle one lives.
pub const MAX_UDP_SESSIONS: usize = 1024;
pub const UDP_IDLE: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub id: String,
    pub revision: u64,
    pub bind: SocketAddr,
    pub proto: L4,
    /// `(network, prefix length)`; the source must fall in one.
    pub sources: Vec<(IpAddr, u8)>,
    pub dest: SocketAddr,
    /// Dial `dest` through the overlay ([`OverlayDial`]).
    pub via_overlay: bool,
}

/// A byte stream a forward relays to.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// How a forward reaches a destination behind the overlay on a netstack
/// node: that org's userspace stack. A node with a TUN has none; its routes
/// already carry overlay addresses.
#[async_trait::async_trait]
pub trait OverlayDial: Send + Sync {
    async fn tcp(&self, dst: SocketAddr) -> std::io::Result<Box<dyn Io>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Listening,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub id: String,
    pub revision: u64,
    pub state: State,
}

/// Is `ip` inside `net/len`? IPv4-mapped IPv6 sources compare as IPv4.
pub fn in_cidr(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let len = u32::from(len.min(32));
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let len = u32::from(len.min(128));
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

fn admitted(a: &Assignment, ip: IpAddr) -> bool {
    a.sources.iter().any(|c| in_cidr(ip, *c))
}

struct Running {
    revision: u64,
    task: JoinHandle<()>,
}

#[derive(Default)]
pub struct Forwarders {
    running: HashMap<String, Running>,
    /// The last failure per forward, so a failed one is retried only when
    /// its revision changes, and reported every time.
    failed: HashMap<String, (u64, String)>,
    /// Listeners started over this value's life (tests check idempotence).
    starts: u64,
    /// The overlay dialer for `via_overlay` forwards, if this node has one.
    pub overlay: Option<Arc<dyn OverlayDial>>,
}

impl Forwarders {
    /// Forwards whose overlay destinations dial through `overlay`.
    pub fn with_overlay(overlay: Option<Arc<dyn OverlayDial>>) -> Self {
        Self {
            running: HashMap::new(),
            failed: HashMap::new(),
            starts: 0,
            overlay,
        }
    }

    /// Make the running set equal `want`; report every desired forward.
    pub async fn reconcile(&mut self, want: Vec<Assignment>) -> Vec<Status> {
        let keep: std::collections::HashSet<&str> = want.iter().map(|a| a.id.as_str()).collect();
        self.running.retain(|id, r| {
            let stay = keep.contains(id.as_str());
            if !stay {
                r.task.abort();
            }
            stay
        });
        self.failed.retain(|id, _| keep.contains(id.as_str()));
        let mut out = Vec::new();
        for a in want {
            if let Some(r) = self.running.get(&a.id) {
                if r.revision == a.revision && !r.task.is_finished() {
                    out.push(Status {
                        id: a.id,
                        revision: a.revision,
                        state: State::Listening,
                    });
                    continue;
                }
                r.task.abort();
            }
            if let Some((rev, why)) = self.failed.get(&a.id)
                && *rev == a.revision
            {
                out.push(Status {
                    id: a.id.clone(),
                    revision: a.revision,
                    state: State::Failed(why.clone()),
                });
                continue;
            }
            // A restart re-binds the same port: wait for the old task to let go.
            if let Some(old) = self.running.remove(&a.id) {
                let _ = old.task.await;
            }
            self.starts += 1;
            match start(a.clone(), self.overlay.clone()).await {
                Ok(task) => {
                    self.failed.remove(&a.id);
                    self.running.insert(
                        a.id.clone(),
                        Running {
                            revision: a.revision,
                            task,
                        },
                    );
                    out.push(Status {
                        id: a.id,
                        revision: a.revision,
                        state: State::Listening,
                    });
                }
                Err(e) => {
                    warn!(forward = %a.id, bind = %a.bind, %e, "managed forward: bind failed");
                    self.failed.insert(a.id.clone(), (a.revision, e.clone()));
                    out.push(Status {
                        id: a.id,
                        revision: a.revision,
                        state: State::Failed(e),
                    });
                }
            }
        }
        out
    }

    /// Stop everything (connection teardown).
    pub fn stop_all(&mut self) {
        for (_, r) in self.running.drain() {
            r.task.abort();
        }
    }
}

impl Drop for Forwarders {
    fn drop(&mut self) {
        self.stop_all();
    }
}

async fn start(
    a: Assignment,
    overlay: Option<Arc<dyn OverlayDial>>,
) -> Result<JoinHandle<()>, String> {
    match a.proto {
        L4::Tcp => {
            let l = TcpListener::bind(a.bind).await.map_err(|e| e.to_string())?;
            Ok(tokio::spawn(serve_tcp(a, l, overlay)))
        }
        L4::Udp if a.via_overlay => Err("UDP into the overlay is not supported".into()),
        L4::Udp => {
            let s = UdpSocket::bind(a.bind).await.map_err(|e| e.to_string())?;
            Ok(tokio::spawn(serve_udp(a, Arc::new(s))))
        }
    }
}

async fn dial(
    a: &Assignment,
    overlay: Option<&Arc<dyn OverlayDial>>,
) -> std::io::Result<Box<dyn Io>> {
    match overlay.filter(|_| a.via_overlay) {
        Some(d) => d.tcp(a.dest).await,
        None => Ok(Box::new(TcpStream::connect(a.dest).await?)),
    }
}

async fn serve_tcp(a: Assignment, l: TcpListener, overlay: Option<Arc<dyn OverlayDial>>) {
    let slots = Arc::new(Semaphore::new(MAX_TCP_CONNS));
    let a = Arc::new(a);
    loop {
        let Ok((mut client, peer)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        if !admitted(&a, peer.ip()) {
            debug!(forward = %a.id, %peer, "managed forward: source not admitted");
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!(forward = %a.id, "managed forward: connection cap reached");
            continue;
        };
        let (a, overlay) = (a.clone(), overlay.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(CONNECT_TIMEOUT, dial(&a, overlay.as_ref())).await {
                Ok(Ok(mut up)) => {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                }
                Ok(Err(e)) => debug!(forward = %a.id, %e, "managed forward: destination refused"),
                Err(_) => debug!(forward = %a.id, "managed forward: destination timed out"),
            }
        });
    }
}

async fn serve_udp(a: Assignment, sock: Arc<UdpSocket>) {
    let mut sessions: HashMap<SocketAddr, (Arc<UdpSocket>, Instant, JoinHandle<()>)> =
        HashMap::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if !admitted(&a, peer.ip()) {
            continue;
        }
        let now = Instant::now();
        sessions.retain(|_, (_, seen, task)| {
            let live = now.duration_since(*seen) < UDP_IDLE;
            if !live {
                task.abort();
            }
            live
        });
        if !sessions.contains_key(&peer) {
            if sessions.len() >= MAX_UDP_SESSIONS {
                continue;
            }
            let local: SocketAddr = if a.dest.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            let Ok(up) = UdpSocket::bind(local).await else {
                continue;
            };
            if up.connect(a.dest).await.is_err() {
                continue;
            }
            let up = Arc::new(up);
            let (back, reply_to, id) = (sock.clone(), peer, a.id.clone());
            let reader = up.clone();
            let task = tokio::spawn(async move {
                let mut b = vec![0u8; 65535];
                while let Ok(n) = reader.recv(&mut b).await {
                    if back.send_to(&b[..n], reply_to).await.is_err() {
                        debug!(forward = %id, "managed forward: reply undeliverable");
                        break;
                    }
                }
            });
            sessions.insert(peer, (up, now, task));
        }
        let entry = sessions.get_mut(&peer).expect("inserted above");
        entry.1 = now;
        let _ = entry.0.send(&buf[..n]).await;
    }
}

fn wire(s: Status) -> ManagedForwardStatusWire {
    match s.state {
        State::Listening => ManagedForwardStatusWire {
            id: s.id,
            revision: s.revision,
            listening: true,
            error: None,
        },
        State::Failed(e) => ManagedForwardStatusWire {
            id: s.id,
            revision: s.revision,
            listening: false,
            error: Some(e),
        },
    }
}

/// What the connection hands its runner.
pub enum Cmd {
    /// `rc:forward.set`: the whole desired set.
    Set(Vec<ManagedForwardAssignment>),
    /// `rc:forward.confirm`: keep that nft change.
    Confirm(u64),
}

/// This connection's forward runner: send it each `rc:forward.set`; it
/// reconciles and answers `rc:forward.status` on `outbound`. When the
/// connection ends its sender drops, the runner exits, and every forward
/// stops: a device the server can no longer reach (revoked, removed) keeps
/// no listener or nft rule it was given. `native` lets this connection run
/// the nft backend (the primary enrollment: the table is host-wide).
pub fn spawn_agent(
    outbound: mpsc::Sender<ClientMsg>,
    native: bool,
    overlay: Option<Arc<dyn OverlayDial>>,
) -> mpsc::Sender<Cmd> {
    let (tx, mut rx) = mpsc::channel::<Cmd>(4);
    tokio::spawn(async move {
        let mut forwarders = Forwarders::with_overlay(overlay);
        #[cfg(target_os = "linux")]
        let mut nft = (native && crate::managed_forward_nft::available())
            .then(crate::managed_forward_nft::NftBackend::system);
        #[cfg(not(target_os = "linux"))]
        let _ = native;
        // A table a crashed process left behind is not this connection's.
        #[cfg(target_os = "linux")]
        if let Some(b) = nft.as_mut()
            && let Err(e) = b.clear().await
        {
            warn!(%e, "managed forward: could not clear a stale nft table");
        }
        #[cfg(target_os = "linux")]
        let mut native_set: Vec<crate::managed_forward_nft::NatForward> = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            let cmd = tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(c) => c,
                    None => break,
                },
                _ = tick.tick() => {
                    #[cfg(target_os = "linux")]
                    if let Some(b) = nft.as_mut()
                        && b.expire().await
                    {
                        let statuses = native_set
                            .iter()
                            .map(|f| ManagedForwardStatusWire {
                                id: f.id.clone(),
                                revision: f.revision,
                                listening: false,
                                error: Some("rolled back: the server did not confirm the change in time".into()),
                            })
                            .collect();
                        native_set.clear();
                        let _ = outbound
                            .send(ClientMsg::ManagedForwardStatus { statuses, confirm: None })
                            .await;
                    }
                    continue;
                }
            };
            let set = match cmd {
                Cmd::Confirm(_generation) => {
                    #[cfg(target_os = "linux")]
                    if let Some(b) = nft.as_mut() {
                        b.confirm(_generation).await;
                    }
                    continue;
                }
                Cmd::Set(set) => set,
            };
            let (want, _native_want, mut statuses) = split(set);
            for s in forwarders.reconcile(want).await {
                statuses.push(wire(s));
            }
            let mut confirm = None;
            #[cfg(target_os = "linux")]
            if let Some(b) = nft.as_mut() {
                let set: Vec<_> = _native_want
                    .into_iter()
                    .map(|(a, preserve)| crate::managed_forward_nft::NatForward {
                        id: a.id,
                        revision: a.revision,
                        bind: a.bind,
                        proto: a.proto,
                        sources: a.sources,
                        dest: a.dest,
                        masquerade: !preserve,
                    })
                    .collect();
                let (st, g) = b.apply(&set).await;
                statuses.extend(st.into_iter().map(wire));
                confirm = g;
                native_set = set;
            } else {
                statuses.extend(_native_want.into_iter().map(|(a, _)| no_native(a)));
            }
            #[cfg(not(target_os = "linux"))]
            statuses.extend(_native_want.into_iter().map(|(a, _)| no_native(a)));
            if outbound
                .send(ClientMsg::ManagedForwardStatus { statuses, confirm })
                .await
                .is_err()
            {
                break;
            }
        }
        forwarders.stop_all();
        #[cfg(target_os = "linux")]
        if let Some(b) = nft.as_mut()
            && let Err(e) = b.clear().await
        {
            warn!(%e, "managed forward: could not remove the nft table at disconnect");
        }
    });
    tx
}

fn no_native(a: Assignment) -> ManagedForwardStatusWire {
    ManagedForwardStatusWire {
        id: a.id,
        revision: a.revision,
        listening: false,
        error: Some("no nft backend on this connection (Linux, root, primary enrollment)".into()),
    }
}

/// Split the wire set by backend: userspace forwards, nft forwards with
/// their preserve-source flag, and the entries that fail as sent (a
/// malformed one, or preserve-source asked of the userspace relay).
pub fn split(
    set: Vec<ManagedForwardAssignment>,
) -> (
    Vec<Assignment>,
    Vec<(Assignment, bool)>,
    Vec<ManagedForwardStatusWire>,
) {
    let mut native = Vec::new();
    let mut user = Vec::new();
    let mut bad = Vec::new();
    for w in set {
        match (w.backend, w.preserve_source) {
            (ForwardBackend::Nft, preserve) => {
                let (ok, b) = to_assignments(vec![w]);
                native.extend(ok.into_iter().map(|a| (a, preserve)));
                bad.extend(b);
            }
            (ForwardBackend::Userspace, true) => bad.push(ManagedForwardStatusWire {
                id: w.id,
                revision: w.revision,
                listening: false,
                error: Some(
                    "preserve_source needs the nft backend; not masqueraded instead".into(),
                ),
            }),
            (ForwardBackend::Userspace, false) => user.push(w),
        }
    }
    let (ok, b) = to_assignments(user);
    bad.extend(b);
    (ok, native, bad)
}

/// Parse the wire set; an entry that does not parse is reported failed,
/// never run with a guessed meaning.
pub fn to_assignments(
    set: Vec<ManagedForwardAssignment>,
) -> (Vec<Assignment>, Vec<ManagedForwardStatusWire>) {
    let (mut ok, mut bad) = (Vec::new(), Vec::new());
    for w in set {
        let bind = w
            .bind_addr
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, w.port));
        let dest = w
            .dest_addr
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, w.dest_port));
        let sources: Option<Vec<(IpAddr, u8)>> = w
            .sources
            .iter()
            .map(|s| {
                let (ip, len) = s.split_once('/').unwrap_or((s, ""));
                let ip: IpAddr = ip.parse().ok()?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let len = if len.is_empty() {
                    max
                } else {
                    len.parse().ok().filter(|l| *l <= max)?
                };
                Some((ip, len))
            })
            .collect();
        match (bind, dest, sources) {
            (Some(bind), Some(dest), Some(sources))
                if !sources.is_empty() && w.port != 0 && w.dest_port != 0 =>
            {
                ok.push(Assignment {
                    id: w.id,
                    revision: w.revision,
                    bind,
                    proto: w.proto,
                    sources,
                    dest,
                    via_overlay: w.via_overlay,
                });
            }
            _ => bad.push(ManagedForwardStatusWire {
                id: w.id,
                revision: w.revision,
                listening: false,
                error: Some("malformed assignment".into()),
            }),
        }
    }
    (ok, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn net(s: &str) -> (IpAddr, u8) {
        let (ip, len) = s.split_once('/').unwrap();
        (ip.parse().unwrap(), len.parse().unwrap())
    }

    async fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn tcp_echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn udp_echo() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, p)) = s.recv_from(&mut b).await {
                let _ = s.send_to(&b[..n], p).await;
            }
        });
        addr
    }

    fn assignment(
        id: &str,
        rev: u64,
        port: u16,
        proto: L4,
        sources: &[&str],
        dest: SocketAddr,
    ) -> Assignment {
        Assignment {
            id: id.into(),
            revision: rev,
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            proto,
            sources: sources.iter().map(|s| net(s)).collect(),
            dest,
            via_overlay: false,
        }
    }

    #[test]
    fn a_malformed_wire_entry_is_reported_failed_not_run() {
        let w = |bind: &str, srcs: &[&str]| ManagedForwardAssignment {
            id: "x".into(),
            revision: 3,
            bind_addr: bind.into(),
            port: 1000,
            proto: L4::Tcp,
            sources: srcs.iter().map(|s| s.to_string()).collect(),
            dest_addr: "127.0.0.1".into(),
            dest_port: 2000,
            backend: ForwardBackend::Userspace,
            preserve_source: false,
            via_overlay: false,
        };
        let (ok, bad) = to_assignments(vec![
            w("127.0.0.1", &["127.0.0.0/8"]),
            w("nope", &["127.0.0.0/8"]),
            w("127.0.0.1", &[]),
        ]);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].sources, vec![("127.0.0.0".parse().unwrap(), 8)]);
        assert_eq!(bad.len(), 2);
        assert!(bad.iter().all(|b| !b.listening && b.revision == 3));

        // By backend: preserve-source is never masqueraded in userspace.
        let mut nft = w("127.0.0.1", &["127.0.0.0/8"]);
        nft.backend = ForwardBackend::Nft;
        nft.preserve_source = true;
        let mut user_preserve = w("127.0.0.1", &["127.0.0.0/8"]);
        user_preserve.preserve_source = true;
        let (user, native, bad) = split(vec![w("127.0.0.1", &["127.0.0.0/8"]), nft, user_preserve]);
        assert_eq!(user.len(), 1);
        assert_eq!(native.len(), 1);
        assert!(native[0].1, "preserve flag kept");
        assert_eq!(bad.len(), 1);
        assert!(bad[0].error.as_deref().unwrap().contains("nft backend"));
    }

    #[test]
    fn cidr_membership_covers_both_families_and_mapped_v4() {
        assert!(in_cidr("10.1.2.3".parse().unwrap(), net("10.0.0.0/8")));
        assert!(!in_cidr("11.1.2.3".parse().unwrap(), net("10.0.0.0/8")));
        assert!(in_cidr(
            "::ffff:10.1.2.3".parse().unwrap(),
            net("10.0.0.0/8")
        ));
        assert!(in_cidr(
            "2001:db8::5".parse().unwrap(),
            net("2001:db8::/32")
        ));
        assert!(!in_cidr(
            "2001:db9::5".parse().unwrap(),
            net("2001:db8::/32")
        ));
        assert!(in_cidr("8.8.8.8".parse().unwrap(), net("0.0.0.0/0")));
        assert!(
            !in_cidr("10.0.0.1".parse().unwrap(), net("::/0")),
            "families never match across"
        );
    }

    #[tokio::test]
    async fn tcp_relays_admitted_sources_and_drops_others() {
        let echo = tcp_echo().await;
        let port = free_port().await;
        let mut f = Forwarders::default();
        let st = f
            .reconcile(vec![assignment(
                "t",
                1,
                port,
                L4::Tcp,
                &["127.0.0.0/8"],
                echo,
            )])
            .await;
        assert_eq!(st[0].state, State::Listening);
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 5];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");

        // Revision 2 admits only 10/8: loopback is now refused.
        let st = f
            .reconcile(vec![assignment(
                "t",
                2,
                port,
                L4::Tcp,
                &["10.0.0.0/8"],
                echo,
            )])
            .await;
        assert_eq!(st[0].state, State::Listening);
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _ = c.write_all(b"x").await;
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut b))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "a source outside the CIDRs is closed, not relayed");
    }

    /// A dialer that records where it was asked to go and connects to a
    /// local stand-in for the overlay destination.
    struct FakeOverlay {
        asked: std::sync::Mutex<Vec<SocketAddr>>,
        real: SocketAddr,
    }

    #[async_trait::async_trait]
    impl OverlayDial for FakeOverlay {
        async fn tcp(&self, dst: SocketAddr) -> std::io::Result<Box<dyn Io>> {
            self.asked.lock().unwrap().push(dst);
            Ok(Box::new(TcpStream::connect(self.real).await?))
        }
    }

    #[tokio::test]
    async fn an_overlay_destination_is_dialled_through_the_overlay() {
        let echo = tcp_echo().await;
        let port = free_port().await;
        let fake = Arc::new(FakeOverlay {
            asked: Default::default(),
            real: echo,
        });
        let mut f = Forwarders::with_overlay(Some(fake.clone()));
        let behind: SocketAddr = "100.64.0.7:5432".parse().unwrap();
        let mut a = assignment("o", 1, port, L4::Tcp, &["127.0.0.0/8"], behind);
        a.via_overlay = true;
        assert_eq!(
            f.reconcile(vec![a.clone()]).await[0].state,
            State::Listening
        );
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hi");
        assert_eq!(
            *fake.asked.lock().unwrap(),
            vec![behind],
            "dialled the overlay address"
        );

        // UDP into the overlay is refused here too, never relayed elsewhere.
        let mut u = assignment("u", 1, free_port().await, L4::Udp, &["127.0.0.0/8"], behind);
        u.via_overlay = true;
        let st = f.reconcile(vec![a, u]).await;
        assert!(
            matches!(&st[1].state, State::Failed(e) if e.contains("overlay")),
            "{st:?}"
        );
    }

    #[tokio::test]
    async fn udp_keeps_datagram_boundaries() {
        let echo = udp_echo().await;
        let port = free_port().await;
        let mut f = Forwarders::default();
        let st = f
            .reconcile(vec![assignment(
                "u",
                1,
                port,
                L4::Udp,
                &["127.0.0.0/8"],
                echo,
            )])
            .await;
        assert_eq!(st[0].state, State::Listening);
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.connect(("127.0.0.1", port)).await.unwrap();
        c.send(b"one").await.unwrap();
        c.send(b"second").await.unwrap();
        let mut b = [0u8; 64];
        let n1 = tokio::time::timeout(Duration::from_secs(2), c.recv(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n1], b"one");
        let n2 = tokio::time::timeout(Duration::from_secs(2), c.recv(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n2], b"second");
    }

    #[tokio::test]
    async fn reconcile_is_idempotent_reports_bind_failures_and_stops_removed_forwards() {
        let echo = tcp_echo().await;
        let port = free_port().await;
        let mut f = Forwarders::default();
        let a = assignment("t", 1, port, L4::Tcp, &["127.0.0.0/8"], echo);
        f.reconcile(vec![a.clone()]).await;
        f.reconcile(vec![a.clone()]).await;
        assert_eq!(f.starts, 1, "same revision: not restarted");

        // A port someone else holds fails, and says why.
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy = held.local_addr().unwrap().port();
        let st = f
            .reconcile(vec![
                a.clone(),
                assignment("b", 1, busy, L4::Tcp, &["127.0.0.0/8"], echo),
            ])
            .await;
        assert!(
            matches!(&st[1].state, State::Failed(e) if !e.is_empty()),
            "{st:?}"
        );

        // Removing a forward frees its port.
        f.reconcile(vec![]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            TcpListener::bind(("127.0.0.1", port)).await.is_ok(),
            "the listener is gone"
        );
    }
}
