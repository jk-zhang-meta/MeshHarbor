// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! SOCKS5 **mesh** mode (`roomler socks5` with no `--agent`).
//!
//! One local SOCKS5 proxy that reaches the WHOLE tenant: each CONNECT names an
//! agent, and the mesh routes the flow to that agent. It reuses the proven
//! single-agent data plane VERBATIM — for each agent it lazily spawns a Phase-1
//! `socks5 --agent <id>` proxy on a loopback port and SOCKS-chains into it. No
//! change to the tunnel hot path; each per-agent proxy keeps its own
//! keepalive/auto-reconnect session.
//!
//! Address an agent by its **friendly name** (from the server roster) or its
//! **24-hex agent-id** as the SOCKS hostname
//! (`curl --socks5-hostname devbox:3389` or `<agent-id>:3389`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bson::oid::ObjectId;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::TunnelConfig;
use crate::forward::{self, TransportPref};
use crate::socks5;

/// Per-agent loopback proxy registry: agent-id → the `127.0.0.1` port its
/// Phase-1 SOCKS proxy listens on. Lazily populated on first CONNECT to an agent
/// and reused thereafter.
type ProxyPorts = Arc<Mutex<HashMap<ObjectId, u16>>>;

/// The tenant's routing table, fetched from the server: friendly-name →
/// agent-id (so a CONNECT can name an agent by label instead of its raw
/// 24-hex id), plus (Phase 2) advertised subnet CIDR → agent-id for
/// longest-prefix routing of LAN-IP targets.
#[derive(Default)]
struct RosterData {
    /// Lowercased friendly name → agent-id.
    names: HashMap<String, ObjectId>,
    /// Advertised route CIDR → agent-id (subnet-router). Not de-duplicated;
    /// [`RosterData::match_route`] does longest-prefix with a deterministic
    /// (lowest agent-id) tiebreak on equal-length overlaps.
    routes: Vec<(ipnet::IpNet, ObjectId)>,
}

impl RosterData {
    /// Longest-prefix-match `ip` against advertised routes; on equal prefix
    /// length, the lowest agent-id wins (deterministic across refreshes).
    fn match_route(&self, ip: std::net::IpAddr) -> Option<ObjectId> {
        self.routes
            .iter()
            .filter(|(net, _)| net.contains(&ip))
            .min_by_key(|(net, id)| (std::cmp::Reverse(net.prefix_len()), *id))
            .map(|(_, id)| *id)
    }
}

type Roster = Arc<Mutex<RosterData>>;

/// Where a resolved mesh target should be dialed. A NAME/id target reaches
/// the agent's OWN host (`127.0.0.1`); a SUBNET (LAN-IP) target reaches the
/// real IP, which the covering agent dials over its LAN.
struct MeshTarget {
    agent_id: ObjectId,
    /// The host string the covering agent dials — `"127.0.0.1"` for a
    /// name/id target, or the literal LAN IP for a subnet target.
    dial_host: String,
}

/// A live mesh UDP chain into a covering agent's per-agent proxy, keyed by the
/// app's ORIGINAL destination (name / id / LAN-IP). `dial_host` is what that
/// agent dials — its own `127.0.0.1` for a name/id target, or the real LAN IP
/// for a subnet route — so each datagram forwards correctly without
/// re-resolving; the reply pump reframes replies with the app's original DST.
#[derive(Clone)]
struct ChainEntry {
    sock: Arc<UdpSocket>,
    dial_host: String,
}

/// Cap on connecting to a freshly-spawned per-agent proxy (it must bind its
/// listener; its tunnel session establishes lazily on the first forwarded flow).
const PROXY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Run the mesh SOCKS5 proxy on `127.0.0.1:local`.
pub async fn run_mesh(cfg: TunnelConfig, local: u16, transport: TransportPref) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", local))
        .await
        .with_context(|| format!("binding 127.0.0.1:{local}"))?;
    info!(
        local = %listener.local_addr()?,
        ?transport,
        "roomler SOCKS5 mesh listening (address an agent by its name or 24-hex id as the SOCKS hostname)"
    );
    let ports: ProxyPorts = Arc::new(Mutex::new(HashMap::new()));

    // Agent roster (friendly-name → agent-id). Best-effort at startup — if it
    // fails (older server, transient), addressing by raw 24-hex agent-id still
    // works, and an unknown name triggers a lazy re-fetch below.
    let roster: Roster = Arc::new(Mutex::new(RosterData::default()));
    match fetch_roster(&cfg).await {
        Ok(r) => {
            info!(
                names = r.names.len(),
                routes = r.routes.len(),
                "mesh: fetched agent roster (name → agent-id + subnet routes)"
            );
            *roster.lock().await = r;
        }
        Err(e) => warn!(%e, "mesh: roster fetch failed; agent-id addressing still works"),
    }

    loop {
        let (mut tcp, peer_addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!(%e, "accept failed");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let cfg = cfg.clone();
        let ports = Arc::clone(&ports);
        let roster = Arc::clone(&roster);
        tokio::spawn(async move {
            // SOCKS server handshake → CONNECT target or UDP ASSOCIATE.
            let (host, port) = match socks5::accept_request(&mut tcp).await {
                Ok(socks5::Socks5Request::Connect { host, port }) => (host, port),
                Ok(socks5::Socks5Request::UdpAssociate) => {
                    // UDP ASSOCIATE routes per-datagram (each names an agent);
                    // hand off to the mesh UDP relay.
                    if let Err(e) = handle_associate_mesh(tcp, cfg, transport, ports, roster).await
                    {
                        warn!(%peer_addr, %e, "mesh UDP associate ended with error");
                    }
                    return;
                }
                Err(e) => {
                    warn!(%peer_addr, %e, "mesh socks handshake failed");
                    return;
                }
            };
            // Resolve the SOCKS hostname → a target: a 24-hex agent-id or a
            // friendly name (→ that agent's own 127.0.0.1), or a LAN-IP that
            // longest-prefix-matches an agent's advertised subnet route (→ the
            // covering agent dials the real IP).
            let Some(target) = resolve_target(&host, &cfg, &roster).await else {
                warn!(%peer_addr, host, "mesh: no target agent (unknown name/id, and no matching subnet route)");
                socks5::reply(&mut tcp, socks5::REP_GENERAL_FAILURE).await;
                return;
            };
            let agent_id = target.agent_id;
            let proxy_port = match get_or_spawn_proxy(agent_id, &cfg, transport, &ports).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(%peer_addr, %agent_id, %e, "mesh: agent proxy unavailable");
                    socks5::reply(&mut tcp, socks5::REP_GENERAL_FAILURE).await;
                    return;
                }
            };
            // Chain into the agent's loopback proxy. `dial_host` is `127.0.0.1`
            // for a name/id target (the agent's own host) or the real LAN IP
            // for a subnet target (the agent dials it over its LAN).
            let mut inner = match connect_proxy(proxy_port, &target.dial_host, port).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer_addr, %agent_id, %e, "mesh: chaining to agent proxy failed");
                    socks5::reply(&mut tcp, socks5::REP_GENERAL_FAILURE).await;
                    return;
                }
            };
            socks5::reply(&mut tcp, socks5::REP_SUCCESS).await;
            if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut inner).await {
                warn!(%peer_addr, %agent_id, %e, "mesh flow ended with error");
            }
        });
    }
}

/// Handle a SOCKS5 UDP ASSOCIATE on the mesh listener. Binds a local
/// relay socket, replies with its address, then relays each app datagram
/// to the agent named in the datagram's SOCKS-UDP header by SOCKS-UDP-
/// chaining into that agent's Phase-1 loopback proxy (which already does
/// UDP ASSOCIATE for a single agent). The target host names an agent
/// (name / 24-hex id); the agent dials `127.0.0.1:port` (its own host),
/// exactly like the mesh TCP path. Association lifetime = the SOCKS
/// control TCP connection (RFC 1928).
async fn handle_associate_mesh(
    mut tcp: TcpStream,
    cfg: TunnelConfig,
    transport: TransportPref,
    ports: ProxyPorts,
    roster: Roster,
) -> Result<()> {
    let relay = Arc::new(
        UdpSocket::bind(("127.0.0.1", 0))
            .await
            .context("bind mesh udp relay")?,
    );
    let relay_addr = relay.local_addr()?;
    socks5::reply_bound(&mut tcp, socks5::REP_SUCCESS, relay_addr).await;
    info!(%relay_addr, "mesh: UDP ASSOCIATE relay bound");

    // app-original-DST (name / id / LAN-IP) → the mesh-side UDP socket chained
    // to the covering agent's proxy relay, plus the host that agent dials.
    // Keyed by the app's TARGET — not by agent-id — so each chain's reply pump
    // reframes with exactly what the app addressed (v1.1: lets subnet LAN-IP
    // targets ride alongside name/id ones through the same covering agent).
    let chains: Arc<Mutex<HashMap<String, ChainEntry>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut app_src: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 64 * 1024 + 512];

    loop {
        tokio::select! {
            // App's TCP control conn closing ends the whole association.
            _ = drain_control(&mut tcp) => {
                debug!("mesh: UDP control connection closed; ending association");
                break;
            }
            recvd = relay.recv_from(&mut buf) => {
                let (n, from) = match recvd {
                    Ok(x) => x,
                    Err(e) => { warn!(%e, "mesh: udp relay recv_from failed"); continue; }
                };
                let src = *app_src.get_or_insert(from);
                if from != src {
                    debug!(%from, %src, "mesh: udp datagram from unexpected source — dropping");
                    continue;
                }
                let (name, port, off) = match socks5::parse_udp_datagram(&buf[..n]) {
                    Ok(x) => x,
                    Err(e) => { debug!(%e, "mesh: malformed socks udp datagram — dropping"); continue; }
                };
                // Chains are keyed by the app's original destination so each
                // reply is reframed with exactly what the app addressed.
                let existing = chains.lock().await.get(&name).cloned();
                let entry = match existing {
                    Some(e) => e,
                    None => {
                        // IP-aware resolution — the SAME longest-prefix route
                        // table the TCP path uses: a LAN-IP target picks the
                        // covering agent and `dial_host` is the real IP; a
                        // name/id target dials the agent's own 127.0.0.1.
                        let Some(target) = resolve_target(&name, &cfg, &roster).await else {
                            debug!(host = %name, "mesh: udp datagram for unknown target — dropping");
                            continue;
                        };
                        match open_udp_chain(
                            target.agent_id,
                            target.dial_host,
                            &cfg,
                            transport,
                            &ports,
                            &relay,
                            src,
                            &name,
                            &chains,
                        )
                        .await
                        {
                            Ok(e) => e,
                            Err(err) => {
                                warn!(host = %name, %err, "mesh: udp chain open failed");
                                continue;
                            }
                        }
                    }
                };
                // Forward to the proxy relay with the per-target dial host: the
                // agent's own `127.0.0.1` for a name/id target, or the real LAN
                // IP for a subnet route (so the covering agent dials the device).
                let framed = socks5::encode_udp_datagram(&entry.dial_host, port, &buf[off..n]);
                if let Err(e) = entry.sock.send(&framed).await {
                    debug!(host = %name, %e, "mesh: udp send to agent proxy failed");
                }
            }
        }
    }
    // Dropping `chains` drops the mesh-side sockets; each response task sees
    // its socket close and exits, dropping its held control-TCP → the proxy
    // tears the per-agent association down.
    Ok(())
}

/// Open a SOCKS-UDP chain into `agent_id`'s Phase-1 loopback proxy:
/// spawn/reuse the proxy, TCP-connect + UDP ASSOCIATE against it, and bind
/// a mesh-side UDP socket connected to the proxy's relay. Spawns a task
/// pumping the proxy's responses back to the app, re-framed with `name` — the
/// app's ORIGINAL DST (name / id / LAN-IP) — as source, so the app sees a
/// reply from what it addressed. `dial_host` is the host the covering agent
/// dials (its own `127.0.0.1` for name/id, or the real LAN IP for a subnet).
#[allow(clippy::too_many_arguments)]
async fn open_udp_chain(
    agent_id: ObjectId,
    dial_host: String,
    cfg: &TunnelConfig,
    transport: TransportPref,
    ports: &ProxyPorts,
    app_relay: &Arc<UdpSocket>,
    app_src: SocketAddr,
    name: &str,
    chains: &Arc<Mutex<HashMap<String, ChainEntry>>>,
) -> Result<ChainEntry> {
    let proxy_port = get_or_spawn_proxy(agent_id, cfg, transport, ports).await?;
    let mut control = connect_tcp(proxy_port).await?;
    let proxy_relay = socks5::client_udp_associate(&mut control).await?;
    let sock = Arc::new(
        UdpSocket::bind(("127.0.0.1", 0))
            .await
            .context("bind mesh->proxy udp")?,
    );
    sock.connect(proxy_relay)
        .await
        .context("connect to agent proxy relay")?;
    debug!(%agent_id, %proxy_relay, "mesh: udp chain to agent proxy open");

    let sock_rx = Arc::clone(&sock);
    let app_relay = Arc::clone(app_relay);
    // The app's original DST — reframe replies with it (a name → domain ATYP,
    // a LAN-IP → IPv4/IPv6 ATYP) and use it as the chain key on teardown.
    let pump_key = name.to_string();
    let chains_rx = Arc::clone(chains);
    tokio::spawn(async move {
        let _control = control; // hold the association open for its lifetime
        let mut buf = vec![0u8; 64 * 1024 + 512];
        while let Ok(n) = sock_rx.recv(&mut buf).await {
            // The proxy response header carries what the agent dialed
            // (`127.0.0.1` for name/id, the real IP for a subnet route); rewrite
            // the source to the app's original DST so the app accepts the reply.
            if let Ok((_h, port, off)) = socks5::parse_udp_datagram(&buf[..n]) {
                let reframed = socks5::encode_udp_datagram(&pump_key, port, &buf[off..n]);
                let _ = app_relay.send_to(&reframed, app_src).await;
            }
        }
        chains_rx.lock().await.remove(&pump_key);
    });

    let entry = ChainEntry {
        sock: Arc::clone(&sock),
        dial_host,
    };
    chains.lock().await.insert(name.to_string(), entry.clone());
    Ok(entry)
}

/// Read + discard the SOCKS control connection until EOF/error — its close
/// is the UDP association's teardown signal (RFC 1928).
async fn drain_control(tcp: &mut TcpStream) -> std::io::Result<()> {
    let mut b = [0u8; 256];
    loop {
        match tcp.read(&mut b).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Get the loopback port of `agent_id`'s Phase-1 SOCKS proxy, spawning it (a
/// persistent `run_socks5` task on a free loopback port) on first use.
async fn get_or_spawn_proxy(
    agent_id: ObjectId,
    cfg: &TunnelConfig,
    transport: TransportPref,
    ports: &ProxyPorts,
) -> Result<u16> {
    if let Some(p) = ports.lock().await.get(&agent_id).copied() {
        return Ok(p);
    }
    // Reserve a free loopback port, then hand it to a persistent per-agent proxy.
    // (Tiny bind→spawn race on loopback is acceptable; the connect below retries.)
    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .context("probe free loopback port")?;
    let port = probe.local_addr()?.port();
    drop(probe);

    let cfg = cfg.clone();
    let agent_hex = agent_id.to_hex();
    tokio::spawn(async move {
        // `run_socks5` reconnects internally (v1.1); it only returns on a fatal
        // setup error (e.g. a bad config), in which case this agent's proxy is
        // gone until re-requested.
        if let Err(e) = forward::run_socks5(cfg, &agent_hex, port, transport).await {
            warn!(%agent_hex, %e, "per-agent proxy exited");
        }
    });
    ports.lock().await.insert(agent_id, port);
    Ok(port)
}

/// TCP-connect to a per-agent loopback proxy, retrying briefly while the
/// freshly-spawned proxy binds its listener.
async fn connect_tcp(proxy_port: u16) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + PROXY_READY_TIMEOUT;
    loop {
        match TcpStream::connect(("127.0.0.1", proxy_port)).await {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e).context("connect to agent proxy"),
        }
    }
}

/// Connect to a per-agent loopback proxy and SOCKS-CONNECT to
/// `dial_host:dst_port`. `dial_host` is `127.0.0.1` for a name/id target
/// (the agent's own host) or a LAN IP for a subnet target (the agent dials
/// it directly). The host rides a domain-ATYP CONNECT either way — an IP
/// string round-trips fine — so no new socks5 surface is needed.
async fn connect_proxy(proxy_port: u16, dial_host: &str, dst_port: u16) -> Result<TcpStream> {
    let mut stream = connect_tcp(proxy_port).await?;
    socks5::client_connect(&mut stream, dial_host, dst_port).await?;
    Ok(stream)
}

/// One agent in the server's roster response.
#[derive(serde::Deserialize)]
struct AgentInfo {
    agent_id: String,
    name: String,
    /// Advertised subnet-router CIDRs. `#[serde(default)]` so an older
    /// server (no field) still deserializes.
    #[serde(default)]
    routes: Vec<String>,
}

/// Resolve a SOCKS-CONNECT hostname to a [`MeshTarget`], in strict order: a
/// raw 24-hex agent-id → that agent's own host (`127.0.0.1`); else a literal
/// IP → longest-prefix-match against advertised subnet routes → the covering
/// agent dials the real IP; else a friendly name → that agent's own host. A
/// literal IP NEVER falls through to name resolution, so an agent named like
/// an IP can't shadow the route table. Refreshes the roster once on an
/// IP-route miss or a name miss (picks up a newly-added route / renamed agent).
async fn resolve_target(host: &str, cfg: &TunnelConfig, roster: &Roster) -> Option<MeshTarget> {
    // 1. Raw agent-id.
    if let Ok(id) = ObjectId::parse_str(host) {
        return Some(MeshTarget {
            agent_id: id,
            dial_host: "127.0.0.1".to_string(),
        });
    }
    // 2. Literal IP → subnet route table (never falls through to name).
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if let Some(id) = roster.lock().await.match_route(ip) {
            return Some(MeshTarget {
                agent_id: id,
                dial_host: host.to_string(),
            });
        }
        // Route miss — refresh once (a new route may have been added).
        if let Ok(fresh) = fetch_roster(cfg).await {
            let id = fresh.match_route(ip);
            *roster.lock().await = fresh;
            return id.map(|agent_id| MeshTarget {
                agent_id,
                dial_host: host.to_string(),
            });
        }
        return None;
    }
    // 3. Friendly name.
    let key = host.to_ascii_lowercase();
    if let Some(id) = roster.lock().await.names.get(&key).copied() {
        return Some(MeshTarget {
            agent_id: id,
            dial_host: "127.0.0.1".to_string(),
        });
    }
    match fetch_roster(cfg).await {
        Ok(fresh) => {
            let id = fresh.names.get(&key).copied();
            *roster.lock().await = fresh;
            id.map(|agent_id| MeshTarget {
                agent_id,
                dial_host: "127.0.0.1".to_string(),
            })
        }
        Err(e) => {
            warn!(%e, "mesh: roster refresh failed");
            None
        }
    }
}

/// GET the tenant's agent roster (`/api/tunnel-client/agents`, TunnelClient
/// bearer auth) → a case-insensitive `name → agent-id` map plus the subnet
/// route table. The route table is built independently of the name filter so
/// an unnamed, route-only agent still routes. Unparseable CIDRs are skipped
/// with a warning; equal-length overlaps log a warning (tiebreak = lowest id).
async fn fetch_roster(cfg: &TunnelConfig) -> Result<RosterData> {
    let url = format!(
        "{}/api/tunnel-client/agents",
        cfg.server_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&cfg.tunnel_client_token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("roster fetch: HTTP {}", resp.status());
    }
    let agents: Vec<AgentInfo> = resp.json().await.context("parse roster json")?;
    let mut data = RosterData::default();
    for a in agents {
        let Ok(id) = ObjectId::parse_str(&a.agent_id) else {
            continue;
        };
        // Route table (independent of the name filter — a route-only agent
        // with an empty name still routes).
        for cidr in &a.routes {
            match cidr.parse::<ipnet::IpNet>() {
                Ok(net) => {
                    if let Some((_, other)) =
                        data.routes.iter().find(|(n, oid)| *n == net && *oid != id)
                    {
                        warn!(%cidr, agent_a = %other, agent_b = %id, "mesh: two agents advertise the same route — tiebreak is lowest agent-id");
                    }
                    data.routes.push((net, id));
                }
                Err(e) => warn!(%cidr, %e, "mesh: skipping unparseable advertised route"),
            }
        }
        if !a.name.is_empty() {
            data.names.insert(a.name.to_ascii_lowercase(), id);
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn match_route_longest_prefix_wins() {
        let broad = ObjectId::new();
        let specific = ObjectId::new();
        let r = RosterData {
            names: HashMap::new(),
            routes: vec![(net("10.0.0.0/8"), broad), (net("10.1.2.0/24"), specific)],
        };
        // Most-specific covering route wins.
        assert_eq!(r.match_route(ip("10.1.2.5")), Some(specific));
        // Only the broad route covers this.
        assert_eq!(r.match_route(ip("10.9.9.9")), Some(broad));
        // No route covers a public IP.
        assert_eq!(r.match_route(ip("8.8.8.8")), None);
    }

    #[test]
    fn match_route_equal_prefix_tiebreak_lowest_id_is_deterministic() {
        let a = ObjectId::parse_str("0000000000000000000000aa").unwrap();
        let b = ObjectId::parse_str("0000000000000000000000bb").unwrap();
        // Same /24 on two agents; lowest agent-id wins regardless of order.
        let r1 = RosterData {
            names: HashMap::new(),
            routes: vec![(net("192.168.0.0/24"), b), (net("192.168.0.0/24"), a)],
        };
        let r2 = RosterData {
            names: HashMap::new(),
            routes: vec![(net("192.168.0.0/24"), a), (net("192.168.0.0/24"), b)],
        };
        assert_eq!(r1.match_route(ip("192.168.0.5")), Some(a));
        assert_eq!(r2.match_route(ip("192.168.0.5")), Some(a));
    }
}
