// SPDX-License-Identifier: MPL-2.0
//! Bounded two-leg org-relay bridge. This is NOT an automatic path planner.
//! Only an authorized control-plane caller may supply a grant; a second,
//! device-local opt-in and CIDR policy must permit the remote backbone leg.
//! WireGuard bytes stay opaque; each hop replaces only the Geneve VNI.
//!
//! FR-125 P1 — the REMOTE leg keeps itself alive. A backbone edge may be any
//! UDP path the operator vouches for, including a one-way private line whose
//! NAT or stateful forwarder drops a quiet flow; a dormant pair can be silent
//! for minutes. So when nothing has come back on the remote leg for
//! [`KEEPALIVE_IDLE`], the bridge re-binds in band (a fresh nonce, the same
//! VNI and secret, exactly what a member carrier does, `client.rs`
//! § Re-binding). The outbound Bind refreshes the path's mapping; the relay's
//! Challenge proves the far relay still serves the session and re-learns a
//! remapped source; and a far relay that leaves [`KEEPALIVE_DEAD_ROUNDS`]
//! rounds unanswered ends the bridge, so the line is not a silent black hole.
//! Only this side ever sends first, which is all a one-way line allows.
//! Kill switch: `MESHHARBORD_RELAY_BACKBONE_KEEPALIVE=0` (the pre-FR-125
//! bind-once bridge).
//!
//! FR-125 P4 — a remote leg that fails (its bind, or its keeper) is news
//! about the LINK, not about this bridge: it goes out on [`link_failures`],
//! and the overlay runtime re-measures that relay at once, so the center
//! learns the link is down in seconds rather than at the next probe round.
//! Kill switch: `MESHHARBORD_RELAY_LINK_HEALTH=0`.
use super::{
    bind::{BindSecret, Nonce, tag1, tag2},
    client,
    wire::{ControlFrame, HEADER_LEN, build_data, parse_data, vni_is_mintable},
};
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, watch},
    task::JoinHandle,
};

/// Conservative experimental ceiling; callers must not select this path for
/// a WG datagram MTU above it. No TUN, system-route, or existing MTU changes.
pub const MAX_CIPHERTEXT: usize =
    meshharbor_remote_control::models::peer_relay_limits::BACKBONE_MAX_CIPHERTEXT;
pub const MAX_BRIDGE_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_LOCAL_CIDRS: usize = meshharbor_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES;
const BIND_BUDGET: Duration = Duration::from_secs(5);
/// FR-125 P1 — silence on the remote leg after which the bridge re-binds in
/// band. Well under the shortest UDP mapping timeout seen on NATs and Linux
/// conntrack (30 s for an unreplied flow).
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
/// An unanswered keepalive Bind is re-sent this often, [`KEEPALIVE_SENDS`]
/// times per round.
const KEEPALIVE_RETRY: Duration = Duration::from_secs(2);
const KEEPALIVE_SENDS: u32 = 3;
/// Whole rounds left unanswered before the far relay is declared gone and the
/// bridge ends: about `KEEPALIVE_IDLE + 3 × 3 × 2 s` ≈ 28 s after it stopped.
pub const KEEPALIVE_DEAD_ROUNDS: u32 = 3;

/// FR-125 P4 — the remote `ip:port` of every bridge whose remote leg failed
/// (bind or keeper). Process-wide: the bridge and the runtime that measures
/// relays are different components of one daemon.
static LINK_FAILURES: std::sync::OnceLock<broadcast::Sender<SocketAddr>> =
    std::sync::OnceLock::new();

fn link_failure_sender() -> &'static broadcast::Sender<SocketAddr> {
    LINK_FAILURES.get_or_init(|| broadcast::channel(16).0)
}

/// FR-125 P4 — subscribe to remote endpoints whose backbone leg just failed.
pub fn link_failures() -> broadcast::Receiver<SocketAddr> {
    link_failure_sender().subscribe()
}

fn report_link_failure(remote: SocketAddr) {
    if crate::env::flag("RELAY_LINK_HEALTH", true) {
        // No subscriber (no runtime yet) is not an error: nothing to tell.
        let _ = link_failure_sender().send(remote);
    }
}

/// The remote leg's keeper timings (FR-125 P1); tests shorten them.
#[derive(Clone, Copy, Debug)]
struct Keeper {
    idle: Duration,
    retry: Duration,
    sends: u32,
    dead_rounds: u32,
    tick: Duration,
}
impl Keeper {
    const PRODUCTION: Keeper = Keeper {
        idle: KEEPALIVE_IDLE,
        retry: KEEPALIVE_RETRY,
        sends: KEEPALIVE_SENDS,
        dead_rounds: KEEPALIVE_DEAD_ROUNDS,
        tick: Duration::from_secs(1),
    };
    fn from_env() -> Option<Keeper> {
        crate::env::flag("RELAY_BACKBONE_KEEPALIVE", true).then_some(Keeper::PRODUCTION)
    }
}

/// A local refusal independent of the center's approval. Empty/default is off.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
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

static SERVER_AUTHORIZED_BACKBONE: std::sync::OnceLock<
    std::sync::RwLock<Option<LocalBackbonePolicy>>,
> = std::sync::OnceLock::new();

fn server_authorized_slot() -> &'static std::sync::RwLock<Option<LocalBackbonePolicy>> {
    SERVER_AUTHORIZED_BACKBONE.get_or_init(|| std::sync::RwLock::new(None))
}

fn has_manual_backbone_env_override() -> bool {
    [
        "RELAY_BACKBONE_ENABLED",
        "BACKBONE_INTERFACE",
        "BACKBONE_ALLOWED_CIDRS",
        "BACKBONE_OVERLAY_CIDRS",
    ]
    .into_iter()
    .any(|k| crate::env::node_env(k).is_some())
}

#[cfg(target_os = "linux")]
fn default_overlay_exclusion_cidrs() -> Vec<IpNet> {
    vec![
        "100.64.0.0/10".parse().expect("valid IPv4 overlay CIDR"),
        "fd72:6f6f:6d6c::/48"
            .parse()
            .expect("valid IPv6 overlay CIDR"),
    ]
}

#[cfg(target_os = "linux")]
fn detect_egress_physical_interface(target: SocketAddr, overlay_cidrs: &[IpNet]) -> Option<String> {
    let bind_addr: SocketAddr = if target.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = std::net::UdpSocket::bind(bind_addr).ok()?;
    sock.connect(target).ok()?;
    let local_ip = sock.local_addr().ok()?.ip();
    if overlay_cidrs.iter().any(|n| n.contains(&local_ip)) {
        return None;
    }
    let ifaces = if_addrs::get_if_addrs().ok()?;
    // Collect any interface that carries an overlay address so we never pick an
    // overlay TUN interface even on a multi-address virtual adapter.
    let overlay_ifaces: std::collections::HashSet<String> = ifaces
        .iter()
        .filter(|i| overlay_cidrs.iter().any(|n| n.contains(&i.ip())))
        .map(|i| i.name.clone())
        .collect();
    for iface in ifaces {
        if iface.is_loopback()
            || !valid_interface(&iface.name)
            || iface.name.starts_with("mh")
            || iface.name.starts_with("tun")
            || iface.name.starts_with("utun")
            || overlay_ifaces.contains(&iface.name)
            || std::path::Path::new(&format!("/sys/class/net/{}/tun_flags", iface.name)).exists()
        {
            continue;
        }
        if iface.ip() == local_ip {
            let probe = std::net::UdpSocket::bind(bind_addr).ok()?;
            if pin_interface(&socket2::SockRef::from(&probe), &iface.name).is_ok() {
                return Some(iface.name);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn build_auto_local_policy_from_endpoints(endpoints: &[String]) -> Option<LocalBackbonePolicy> {
    if endpoints.is_empty() {
        return None;
    }
    let overlay_cidrs = default_overlay_exclusion_cidrs();
    let mut allowed_cidrs: Vec<IpNet> = Vec::new();
    let mut detected_iface: Option<String> = None;
    for raw in endpoints.iter().take(MAX_LOCAL_CIDRS) {
        let Ok(ep) = raw.parse::<SocketAddr>() else {
            continue;
        };
        if ep.port() == 0 || !unicast(ep.ip()) || overlay_cidrs.iter().any(|n| n.contains(&ep.ip()))
        {
            continue;
        }
        if detected_iface.is_none() {
            detected_iface = detect_egress_physical_interface(ep, &overlay_cidrs);
        }
        let host_net = match ep.ip() {
            IpAddr::V4(v4) => IpNet::from(ipnet::Ipv4Net::new(v4, 32).ok()?),
            IpAddr::V6(v6) => IpNet::from(ipnet::Ipv6Net::new(v6, 128).ok()?),
        };
        if !allowed_cidrs.contains(&host_net) {
            allowed_cidrs.push(host_net);
        }
    }
    let interface = detected_iface?;
    if allowed_cidrs.is_empty() {
        return None;
    }
    Some(LocalBackbonePolicy {
        enabled: true,
        interface,
        allowed_cidrs,
        overlay_cidrs,
    })
}

/// Update the server-authorized runtime backbone policy from `PeerRelayServe`.
/// Returns `true` when the effective [`configured_local_policy`] changed.
pub fn set_runtime_server_backbone_endpoints(serve: bool, endpoints: &[String]) -> bool {
    let before = configured_local_policy();
    #[cfg(target_os = "linux")]
    let next = if serve {
        build_auto_local_policy_from_endpoints(endpoints)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let next: Option<LocalBackbonePolicy> = {
        let _ = (serve, endpoints);
        None
    };
    *server_authorized_slot()
        .write()
        .unwrap_or_else(|e| e.into_inner()) = next;
    configured_local_policy() != before
}

/// Read explicit native configuration when any `RELAY_BACKBONE_*` / `BACKBONE_*`
/// override is set; otherwise fall back on Linux to the server-authorized
/// `PeerRelayServe` backbone endpoint policy. Missing or malformed manual
/// CIDRs still fail closed.
#[cfg(not(target_os = "linux"))]
pub fn configured_local_policy() -> Option<LocalBackbonePolicy> {
    None
}

#[cfg(target_os = "linux")]
pub fn configured_local_policy() -> Option<LocalBackbonePolicy> {
    if !has_manual_backbone_env_override() {
        return server_authorized_slot()
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
    }
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
pub(crate) fn pin_interface(socket: &socket2::SockRef<'_>, name: &str) -> io::Result<()> {
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
pub(crate) fn pin_interface(_socket: &socket2::SockRef<'_>, _name: &str) -> io::Result<()> {
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
    bind_and_start_with(grant, interface, Keeper::from_env()).await
}

async fn bind_and_start_with(
    grant: AuthorizedBridgeGrant,
    interface: Option<&str>,
    keeper: Option<Keeper>,
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
    tokio::try_join!(bind_leg(&left, &grant.local), async {
        bind_leg(&right, &grant.remote)
            .await
            .inspect_err(|_| report_link_failure(grant.remote.relay))
    })?;
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
            r = forward_remote(&right, &grant.remote, &left, &grant.local, keeper) => r,
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

/// The remote leg's direction (far relay → local relay), plus its keeper
/// (module docs, FR-125 P1). Without a keeper it is exactly [`forward`].
async fn forward_remote(
    input: &UdpSocket,
    from: &BridgeLeg,
    output: &UdpSocket,
    to: &BridgeLeg,
    keeper: Option<Keeper>,
) -> io::Result<()> {
    let Some(k) = keeper else {
        return forward(input, from, output, to).await;
    };
    let bind_frame = |nonce: &Nonce| {
        ControlFrame::Bind {
            nonce: *nonce,
            tag1: tag1(&from.secret, from.vni, from.generation, nonce),
        }
        .encode(from.vni)
    };
    let mut bytes = [0u8; HEADER_LEN + MAX_CIPHERTEXT + 1];
    let mut dropped = 0u8;
    // The bind that started the bridge was just answered.
    let mut last_heard = Instant::now();
    // The outstanding keepalive Bind: its nonce, when it last left, how often.
    let mut pending: Option<(Nonce, Instant, u32)> = None;
    let mut unanswered = 0u32;
    let mut tick = tokio::time::interval(k.tick);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            r = input.recv_from(&mut bytes) => {
                let (n, source) = r?;
                if source == from.relay && n <= HEADER_LEN + MAX_CIPHERTEXT {
                    if let Some((vni, payload)) = parse_data(&bytes[..n]) {
                        if vni == from.vni {
                            output.send_to(&build_data(to.vni, payload), to.relay).await?;
                            last_heard = Instant::now();
                            unanswered = 0;
                            dropped = 0;
                            continue;
                        }
                    } else if let Some((
                        vni,
                        ControlFrame::Challenge { nonce, cookie },
                    )) = ControlFrame::decode(&bytes[..n])
                    {
                        // Only the Challenge echoing OUR outstanding Bind.
                        if vni == from.vni && pending.is_some_and(|(p, _, _)| p == nonce) {
                            let answer = ControlFrame::Answer {
                                nonce,
                                cookie,
                                tag2: tag2(&from.secret, &cookie, &nonce),
                            }
                            .encode(from.vni);
                            input.send_to(&answer, from.relay).await?;
                            pending = None;
                            last_heard = Instant::now();
                            unanswered = 0;
                            continue;
                        }
                    }
                }
                dropped += 1;
                if dropped == 64 {
                    tokio::task::yield_now().await;
                    dropped = 0;
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                match pending {
                    None if now.duration_since(last_heard) >= k.idle => {
                        let nonce = client::fresh_nonce();
                        input.send_to(&bind_frame(&nonce), from.relay).await?;
                        pending = Some((nonce, now, 1));
                    }
                    Some((nonce, sent, n)) if now.duration_since(sent) >= k.retry => {
                        if n < k.sends {
                            input.send_to(&bind_frame(&nonce), from.relay).await?;
                            pending = Some((nonce, now, n + 1));
                        } else {
                            pending = None;
                            unanswered += 1;
                            if unanswered >= k.dead_rounds {
                                tracing::warn!(
                                    relay = %from.relay,
                                    rounds = unanswered,
                                    "org-relay backbone: the far relay stopped answering on the remote leg — ending the bridge"
                                );
                                report_link_failure(from.relay);
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "backbone remote leg unanswered",
                                ));
                            }
                        }
                    }
                    _ => {}
                }
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
    /// A UDP NAT as a line's stateful forwarder behaves (FR-125): packets from
    /// the inside leave through an outside socket; once the flow has been idle
    /// for `expire` the mapping is gone and the next packet leaves from a fresh
    /// port. Replies return to the newest inside source only.
    async fn line_nat(target: SocketAddr, expire: Duration) -> (SocketAddr, JoinHandle<()>) {
        let inside = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let entry = inside.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut outside: Option<UdpSocket> = None;
            let mut peer: Option<SocketAddr> = None;
            let mut last = Instant::now();
            let mut a = [0u8; 2048];
            let mut b = [0u8; 2048];
            loop {
                if outside.is_some() && last.elapsed() >= expire {
                    outside = None;
                }
                let out_recv = async {
                    match &outside {
                        Some(o) => o.recv_from(&mut b).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    r = inside.recv_from(&mut a) => {
                        let Ok((n, from)) = r else { return };
                        if outside.is_none() {
                            outside = Some(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        }
                        peer = Some(from);
                        last = Instant::now();
                        let _ = outside.as_ref().unwrap().send_to(&a[..n], target).await;
                    }
                    r = out_recv => {
                        let Ok((n, from)) = r else { return };
                        if from == target && let Some(p) = peer {
                            last = Instant::now();
                            let _ = inside.send_to(&b[..n], p).await;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
        });
        (entry, task)
    }
    fn fast_keeper() -> Keeper {
        Keeper {
            idle: Duration::from_millis(150),
            retry: Duration::from_millis(100),
            sends: 2,
            dead_rounds: 2,
            tick: Duration::from_millis(25),
        }
    }
    fn grant_through(a: &TestRelay, remote: SocketAddr) -> AuthorizedBridgeGrant {
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
                relay: remote,
                vni: 83,
                generation: 1,
                secret: BindSecret::from_bytes([21; 32]),
            },
            lifetime: Duration::from_secs(30),
        }
    }
    async fn round_trip(
        left: &UdpSocket,
        a: &TestRelay,
        right: &UdpSocket,
        b: &TestRelay,
        tag: u8,
    ) -> bool {
        let mut recv = [0u8; 2048];
        left.send_to(&build_data(41, &[tag; 64]), a.addr)
            .await
            .unwrap();
        let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_secs(1), right.recv_from(&mut recv)).await
        else {
            return false;
        };
        if parse_data(&recv[..n]) != Some((83, &[tag; 64][..])) {
            return false;
        }
        right
            .send_to(&build_data(83, &[tag; 64]), b.addr)
            .await
            .unwrap();
        matches!(
            tokio::time::timeout(Duration::from_secs(1), left.recv_from(&mut recv)).await,
            Ok(Ok((n, _))) if parse_data(&recv[..n]) == Some((41, &[tag; 64][..]))
        )
    }
    /// FR-125 P1 — a backbone edge over a line whose NAT drops a quiet flow
    /// (any stateful forwarder, one-way lines included) still carries the
    /// pair after a silence longer than the mapping lives: the bridge's
    /// keeper re-binds before it lapses. Without the keeper the next packet
    /// leaves from a fresh port, the far relay drops it as unbound, and the
    /// pair is a black hole.
    #[tokio::test]
    async fn a_quiet_bridge_over_an_expiring_nat_still_carries_the_pair() {
        let a = relay(41, [[11; 32], [12; 32]]).await;
        let b = relay(83, [[21; 32], [22; 32]]).await;
        let (entry, nat) = line_nat(b.addr, Duration::from_millis(400)).await;
        let left = end(&a, 41, [11; 32]).await;
        let right = end(&b, 83, [22; 32]).await;
        let h = bind_and_start_with(grant_through(&a, entry), None, Some(fast_keeper()))
            .await
            .unwrap();
        assert!(round_trip(&left, &a, &right, &b, 1).await, "fresh bridge");
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            round_trip(&left, &a, &right, &b, 2).await,
            "after a silence longer than the line's NAT mapping"
        );
        h.shutdown().await.unwrap();
        nat.abort();
    }
    /// FR-125 P1 — a far relay that stops answering ends the bridge instead
    /// of leaving it a silent black hole.
    #[tokio::test]
    async fn a_bridge_whose_far_relay_stops_answering_ends() {
        let a = relay(41, [[11; 32], [12; 32]]).await;
        let b = relay(83, [[21; 32], [22; 32]]).await;
        let far = b.addr;
        let _left = end(&a, 41, [11; 32]).await;
        let _right = end(&b, 83, [22; 32]).await;
        let mut failures = link_failures();
        let mut h = bind_and_start_with(grant_through(&a, far), None, Some(fast_keeper()))
            .await
            .unwrap();
        drop(b);
        let r = tokio::time::timeout(Duration::from_secs(3), h.wait())
            .await
            .expect("the bridge ends on its own");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        // FR-125 P4 — the dead leg is reported as the LINK to `far`.
        assert!(reported(&mut failures, far).await);
    }

    /// Drain `rx` (other tests share the process-wide channel) for `ep`.
    async fn reported(rx: &mut broadcast::Receiver<SocketAddr>, ep: SocketAddr) -> bool {
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match tokio::time::timeout_at(until, rx.recv()).await {
                Ok(Ok(got)) if got == ep => return true,
                Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return false,
            }
        }
    }

    /// FR-125 P4 — a remote leg whose bind is never answered (a line that
    /// lets nothing through) reports the link; a bridge that ends because it
    /// was told to reports nothing.
    #[tokio::test]
    async fn a_remote_bind_nobody_answers_reports_the_link_and_a_shutdown_does_not() {
        let a = relay(41, [[11; 32], [12; 32]]).await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = silent.local_addr().unwrap();
        let mut failures = link_failures();
        let _left = end(&a, 41, [11; 32]).await;
        let err = bind_and_start_with(grant_through(&a, dead), None, Some(fast_keeper()))
            .await
            .err()
            .expect("nothing answers the remote bind");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(reported(&mut failures, dead).await);

        let b = relay(83, [[21; 32], [22; 32]]).await;
        let _right = end(&b, 83, [22; 32]).await;
        let h = bind_and_start_with(grant_through(&a, b.addr), None, Some(fast_keeper()))
            .await
            .unwrap();
        h.shutdown().await.unwrap();
        assert!(!reported(&mut failures, b.addr).await);
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
