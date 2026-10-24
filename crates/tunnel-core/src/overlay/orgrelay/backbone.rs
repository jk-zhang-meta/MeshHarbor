// SPDX-License-Identifier: MPL-2.0
//! Bounded two-leg org-relay bridge. This is NOT an automatic path planner.
//! Only an authorized control-plane caller may supply a grant; a second,
//! device-local opt-in and CIDR policy must permit the remote backbone leg.
//! WireGuard bytes stay opaque; each hop replaces only the Geneve VNI.
use super::{
    bind::BindSecret,
    client,
    wire::{HEADER_LEN, build_data, parse_data, vni_is_mintable},
};
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

/// Conservative experimental ceiling; callers must not select this path for
/// a WG datagram MTU above it. No TUN, system-route, or existing MTU changes.
pub const MAX_CIPHERTEXT: usize =
    roomler_ai_remote_control::models::peer_relay_limits::BACKBONE_MAX_CIPHERTEXT;
pub const MAX_BRIDGE_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_LOCAL_CIDRS: usize = 16;
const BIND_BUDGET: Duration = Duration::from_secs(5);

/// A local refusal independent of the center's approval. Empty/default is off.
#[derive(Default)]
pub struct LocalBackbonePolicy {
    pub enabled: bool,
    /// Explicit physical/private-underlay NIC, never selected from routing.
    pub interface: String,
    pub allowed_cidrs: Vec<IpNet>,
    /// Must include all overlay ranges to prevent recursive underlay routing.
    pub overlay_cidrs: Vec<IpNet>,
}
impl LocalBackbonePolicy {
    pub fn permits(&self, remote: SocketAddr) -> bool {
        cfg!(target_os = "linux")
            && self.enabled
            && valid_interface(&self.interface)
            && remote.port() != 0
            && unicast(remote.ip())
            && self.allowed_cidrs.len() <= MAX_LOCAL_CIDRS
            && self.overlay_cidrs.len() <= MAX_LOCAL_CIDRS
            && !self.overlay_cidrs.is_empty()
            && !self.overlay_cidrs.iter().any(|n| n.contains(&remote.ip()))
            && self.allowed_cidrs.iter().any(|n| {
                // A default route is not an explicit backbone allowlist.
                n.prefix_len() >= if n.addr().is_ipv4() { 8 } else { 32 }
                    && n.contains(&remote.ip())
            })
    }
}
/// Read only explicit native configuration. Missing or malformed CIDRs fail
/// closed, including an omitted overlay exclusion inventory.
#[cfg(not(target_os = "linux"))]
pub fn configured_local_policy() -> Option<LocalBackbonePolicy> {
    None
}

#[cfg(target_os = "linux")]
pub fn configured_local_policy() -> Option<LocalBackbonePolicy> {
    if !crate::env::flag("RELAY_BACKBONE_ENABLED", false) {
        return None;
    }
    let parse = |key: &str| -> Option<Vec<IpNet>> {
        let raw = crate::env::node_env(key)?;
        let parts = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > MAX_LOCAL_CIDRS {
            return None;
        }
        parts.into_iter().map(|s| s.parse::<IpNet>().ok()).collect()
    };
    let interface = crate::env::node_env("BACKBONE_INTERFACE")?;
    if !valid_interface(&interface) {
        return None;
    }
    // Probe only a local ephemeral socket: no datagram or route mutation.
    // Missing NIC or missing setsockopt privilege must not advertise readiness.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    pin_interface(&socket2::SockRef::from(&probe), &interface).ok()?;
    let allowed_cidrs = parse("BACKBONE_ALLOWED_CIDRS")?;
    let overlay_cidrs = parse("BACKBONE_OVERLAY_CIDRS")?;
    if allowed_cidrs
        .iter()
        .any(|n| n.prefix_len() < if n.addr().is_ipv4() { 8 } else { 32 })
    {
        return None;
    }
    Some(LocalBackbonePolicy {
        enabled: true,
        interface,
        allowed_cidrs,
        overlay_cidrs,
    })
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "lo"
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

#[cfg(target_os = "linux")]
fn pin_interface(socket: &socket2::SockRef<'_>, name: &str) -> io::Result<()> {
    if !valid_interface(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit backbone interface required",
        ));
    }
    socket.bind_device(Some(name.as_bytes()))?;
    if socket.device()?.as_deref() != Some(name.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backbone interface readback mismatch",
        ));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn pin_interface(_socket: &socket2::SockRef<'_>, _name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native backbone bridging currently requires Linux interface pinning",
    ))
}

pub fn path_enabled() -> bool {
    crate::env::flag("OVERLAY_BACKBONE_ENABLED", false)
}

fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

/// One server-issued, independently authorized relay session leg. The secret
/// is an existing org-relay bind capability, not an SSH or WG private key.
pub struct BridgeLeg {
    pub relay: SocketAddr,
    pub vni: u32,
    pub generation: u64,
    pub secret: BindSecret,
}
/// A trusted caller must derive this from an approved same-tenant graph. This
/// type itself does NOT authenticate a request or authorize a remote client.
pub struct AuthorizedBridgeGrant {
    pub source_relay_id: String,
    pub target_relay_id: String,
    pub local: BridgeLeg,
    pub remote: BridgeLeg,
    pub lifetime: Duration,
}

pub struct BridgeHandle {
    task: Option<JoinHandle<io::Result<()>>>,
    cancel: watch::Sender<bool>,
    local_addrs: [SocketAddr; 2],
}
impl BridgeHandle {
    pub fn local_addrs(&self) -> [SocketAddr; 2] {
        self.local_addrs
    }
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    /// Wait without detaching the task if the owning future is cancelled.
    pub async fn wait(&mut self) -> io::Result<()> {
        let result = match self.task.as_mut().unwrap().await {
            Ok(result) => result,
            Err(e) => Err(io::Error::other(e)),
        };
        self.task.take();
        result
    }
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.cancel.send_replace(true);
        match self.task.take().unwrap().await {
            Ok(result) => result,
            Err(e) => Err(io::Error::other(e)),
        }
    }
}
impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Bind exactly two authenticated sessions, then start the bridge. The local
/// leg MUST equal the daemon's actual listener (provided independently of the
/// grant); the remote leg additionally needs device-local CIDR approval.
/// No listener, registration, or permissive policy is created implicitly.
pub async fn start_authorized_bridge(
    grant: AuthorizedBridgeGrant,
    actual_local_listener: SocketAddr,
    policy: &LocalBackbonePolicy,
) -> io::Result<BridgeHandle> {
    if grant.source_relay_id.is_empty()
        || grant.target_relay_id.is_empty()
        || grant.source_relay_id == grant.target_relay_id
        || grant.local.relay != actual_local_listener
        || !actual_local_listener.ip().is_loopback()
        || !policy.permits(grant.remote.relay)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backbone grant/local policy refused",
        ));
    }
    bind_and_start(grant, Some(&policy.interface)).await
}

async fn bind_and_start(
    grant: AuthorizedBridgeGrant,
    interface: Option<&str>,
) -> io::Result<BridgeHandle> {
    let started = std::time::Instant::now();
    let lifetime = grant.lifetime.min(MAX_BRIDGE_LIFETIME);
    if grant.lifetime.is_zero()
        || grant.local.relay == grant.remote.relay
        || !vni_is_mintable(grant.local.vni)
        || !vni_is_mintable(grant.remote.vni)
        || grant.local.generation == 0
        || grant.remote.generation == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid two-leg backbone grant",
        ));
    }
    let bind_sock = |ip: IpAddr| async move {
        UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .await
            .map(Arc::new)
    };
    let left = bind_sock(grant.local.relay.ip()).await?;
    let right = bind_sock(grant.remote.relay.ip()).await?;
    // Only the private REMOTE leg is pinned. Pinning the local 127.0.0.1
    // leg to an underlay NIC would make our own listener unreachable.
    if let Some(interface) = interface {
        pin_interface(&socket2::SockRef::from(right.as_ref()), interface)?;
    }
    tokio::try_join!(
        bind_leg(&left, &grant.local),
        bind_leg(&right, &grant.remote)
    )?;
    let local_addrs = [left.local_addr()?, right.local_addr()?];
    let (cancel, mut cancelled) = watch::channel(false);
    let lifetime = lifetime.saturating_sub(started.elapsed());
    if lifetime.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "backbone grant expired during bind",
        ));
    }
    let task = tokio::spawn(async move {
        // No application queue: one bounded datagram per direction; awaiting
        // send propagates backpressure instead of retaining unbounded packets.
        tokio::select! {
            r = forward(&left, &grant.local, &right, &grant.remote) => r,
            r = forward(&right, &grant.remote, &left, &grant.local) => r,
            _ = tokio::time::sleep(lifetime) => Ok(()),
            _ = cancelled.changed() => Ok(()),
        }
    });
    Ok(BridgeHandle {
        task: Some(task),
        cancel,
        local_addrs,
    })
}

async fn bind_leg(sock: &UdpSocket, leg: &BridgeLeg) -> io::Result<()> {
    // Control-WS delivery to the two relays is independent. Retry a fresh
    // nonce inside one bounded budget when Serve has not arrived remotely.
    let started = std::time::Instant::now();
    loop {
        let left = BIND_BUDGET.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "backbone bind budget elapsed",
            ));
        }
        match client::bind(
            sock,
            leg.relay,
            leg.vni,
            leg.generation,
            &leg.secret,
            left.min(Duration::from_millis(1500)),
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) if e.is_no_answer() => continue,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    e.to_string(),
                ));
            }
        }
    }
}

async fn forward(
    input: &UdpSocket,
    from: &BridgeLeg,
    output: &UdpSocket,
    to: &BridgeLeg,
) -> io::Result<()> {
    // One extra byte detects oversized UDP without ever relaying a prefix.
    let mut bytes = [0u8; HEADER_LEN + MAX_CIPHERTEXT + 1];
    let mut dropped = 0u8;
    loop {
        let (n, source) = input.recv_from(&mut bytes).await?;
        let valid = if source == from.relay && n <= HEADER_LEN + MAX_CIPHERTEXT {
            parse_data(&bytes[..n]).filter(|(vni, _)| *vni == from.vni)
        } else {
            None
        };
        if let Some((_, payload)) = valid {
            output
                .send_to(&build_data(to.vni, payload), to.relay)
                .await?;
            dropped = 0;
        } else {
            dropped += 1;
            if dropped == 64 {
                tokio::task::yield_now().await;
                dropped = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::{
        bind::CookieKey,
        server::{RelayHandle, RelayServer, RelayStats},
        session::{Member, Session},
    };
    use std::time::Instant;
    #[test]
    #[cfg(target_os = "linux")]
    fn local_default_and_overlay_or_metadata_destinations_are_refused() {
        let remote: SocketAddr = "10.10.1.2:3478".parse().unwrap();
        assert!(!LocalBackbonePolicy::default().permits(remote));
        let mut p = LocalBackbonePolicy {
            enabled: true,
            interface: "eth-test".into(),
            allowed_cidrs: vec!["10.10.1.0/24".parse().unwrap()],
            overlay_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
        };
        assert!(p.permits(remote));
        for addr in [
            "10.10.2.2:3478",
            "169.254.169.254:80",
            "127.0.0.1:3478",
            "100.64.0.2:3478",
            "10.10.1.2:0",
        ] {
            assert!(!p.permits(addr.parse().unwrap()));
        }
        p.overlay_cidrs = vec!["10.10.1.0/24".parse().unwrap()];
        assert!(!p.permits(remote));
        p.overlay_cidrs.clear();
        assert!(!p.permits(remote));
    }
    struct TestRelay {
        addr: SocketAddr,
        stats: Arc<RelayStats>,
        _handle: RelayHandle,
        task: JoinHandle<()>,
    }
    impl Drop for TestRelay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn relay(vni: u32, secrets: [[u8; 32]; 2]) -> TestRelay {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) = RelayServer::new(CookieKey::from_bytes([7; 32]), stats.clone());
        let now = Instant::now();
        assert!(handle.install(Session {
            vni,
            generation: 1,
            members: [
                Member {
                    wg_public: [1; 32],
                    secret: BindSecret::from_bytes(secrets[0])
                },
                Member {
                    wg_public: [2; 32],
                    secret: BindSecret::from_bytes(secrets[1])
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(30),
            idle_deadline: now + Duration::from_secs(30),
            bind_deadline: now + Duration::from_secs(10)
        }));
        let task = tokio::spawn(server.serve(sock));
        TestRelay {
            addr,
            stats,
            _handle: handle,
            task,
        }
    }
    async fn end(relay: &TestRelay, vni: u32, secret: [u8; 32]) -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client::bind(
            &sock,
            relay.addr,
            vni,
            1,
            &BindSecret::from_bytes(secret),
            BIND_BUDGET,
        )
        .await
        .unwrap();
        sock
    }
    #[tokio::test]
    async fn two_real_relays_bridge_both_directions_preserving_opaque_datagrams_and_shutdown() {
        let a = relay(41, [[11; 32], [12; 32]]).await;
        let b = relay(83, [[21; 32], [22; 32]]).await;
        let left = end(&a, 41, [11; 32]).await;
        let right = end(&b, 83, [22; 32]).await;
        // Engine fixture binds real authenticated legs directly; production
        // wrapper's separate CIDR gate is tested above and never bypassed there.
        let h = bind_and_start(
            AuthorizedBridgeGrant {
                source_relay_id: "left".into(),
                target_relay_id: "right".into(),
                local: BridgeLeg {
                    relay: a.addr,
                    vni: 41,
                    generation: 1,
                    secret: BindSecret::from_bytes([12; 32]),
                },
                remote: BridgeLeg {
                    relay: b.addr,
                    vni: 83,
                    generation: 1,
                    secret: BindSecret::from_bytes([21; 32]),
                },
                lifetime: Duration::from_secs(30),
            },
            None,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while a.stats.snapshot().bound < 2 || b.stats.snapshot().bound < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut recv = [0u8; 2048];
        // Invalid peer and oversize data may not become truncated ciphertext.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let input = SocketAddr::new("127.0.0.1".parse().unwrap(), h.local_addrs()[0].port());
        stranger
            .send_to(&build_data(41, b"forged"), input)
            .await
            .unwrap();
        left.send_to(&build_data(41, &vec![9; MAX_CIPHERTEXT + 1]), a.addr)
            .await
            .unwrap();
        for len in [1, 85, 1312, MAX_CIPHERTEXT] {
            let payload: Vec<_> = (0..len).map(|n| (n % 251) as u8).collect();
            left.send_to(&build_data(41, &payload), a.addr)
                .await
                .unwrap();
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(2), right.recv_from(&mut recv))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, b.addr);
            let (vni, bytes) = parse_data(&recv[..n]).unwrap();
            assert_eq!(vni, 83);
            assert_eq!(bytes, payload);
            right
                .send_to(&build_data(83, &payload), b.addr)
                .await
                .unwrap();
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), left.recv_from(&mut recv))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(from, a.addr);
            let (vni, bytes) = parse_data(&recv[..n]).unwrap();
            assert_eq!(vni, 41);
            assert_eq!(bytes, payload);
        }
        let addrs = h.local_addrs();
        h.shutdown().await.unwrap();
        for addr in addrs {
            let rebound = UdpSocket::bind(addr).await.unwrap();
            assert_eq!(rebound.local_addr().unwrap(), addr);
        }
    }
    #[tokio::test]
    async fn unauthorized_bridge_refused_before_any_bind_or_task() {
        let grant = AuthorizedBridgeGrant {
            source_relay_id: "a".into(),
            target_relay_id: "b".into(),
            local: BridgeLeg {
                relay: "127.0.0.1:3478".parse().unwrap(),
                vni: 41,
                generation: 1,
                secret: BindSecret::from_bytes([1; 32]),
            },
            remote: BridgeLeg {
                relay: "10.0.0.1:3478".parse().unwrap(),
                vni: 83,
                generation: 1,
                secret: BindSecret::from_bytes([2; 32]),
            },
            lifetime: Duration::from_secs(30),
        };
        let err = start_authorized_bridge(
            grant,
            "127.0.0.1:3478".parse().unwrap(),
            &LocalBackbonePolicy::default(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
    #[test]
    fn interface_name_is_explicit_and_never_loopback_or_an_empty_unbind() {
        for name in ["", "lo", "bad/name", "x\0y", "0123456789012345"] {
            assert!(!valid_interface(name));
        }
        for name in ["eth0", "enp2s0", "private.42"] {
            assert!(valid_interface(name));
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_nic_fails_before_sending_any_bind_datagram() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let policy = LocalBackbonePolicy {
            enabled: true,
            interface: "mh-nonexistent".into(),
            allowed_cidrs: vec!["10.20.0.2/32".parse().unwrap()],
            overlay_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
        };
        let grant = AuthorizedBridgeGrant {
            source_relay_id: "a".into(),
            target_relay_id: "b".into(),
            local: BridgeLeg {
                relay: local,
                vni: 41,
                generation: 1,
                secret: BindSecret::from_bytes([1; 32]),
            },
            remote: BridgeLeg {
                relay: "10.20.0.2:3478".parse().unwrap(),
                vni: 83,
                generation: 1,
                secret: BindSecret::from_bytes([2; 32]),
            },
            lifetime: Duration::from_secs(30),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            start_authorized_bridge(grant, local, &policy),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        let mut bytes = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.recv_from(&mut bytes))
                .await
                .is_err(),
            "no local or private-leg bind may be sent after interface pin failure"
        );
    }
}
