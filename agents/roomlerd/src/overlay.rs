// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side overlay-network glue (Phase 3b).
//!
//! Bridges the agent's WS signaling loop to the shared
//! [`OverlayRuntime`](tunnel_core::overlay::runtime::OverlayRuntime): on
//! connect it spawns the runtime (relay mode) and returns the channel its
//! `ServerMsg::Overlay*` events flow into; the WS read loop forwards those
//! via [`intercept`].
//!
//! Two overlay surfaces, picked at runtime:
//! * **`overlay-l3`** — a real OS TUN (`SystemTun`). The agent runs privileged
//!   (service), so the device + routes come up directly. The default when no
//!   netstack port is set.
//! * **`overlay-netstack`** — a userspace smoltcp stack + a loopback SOCKS5
//!   front, the OS-free twin: on a locked-down host (full-tunnel VPN) the mesh
//!   is reachable with NO OS routing. Opt in with the env var
//!   `ROOMLERD_OVERLAY_NETSTACK_SOCKS=<port>`.
//!
//! Default-OFF regardless: `overlay_enabled` config **and** a build carrying
//! the relevant feature are both required to join the mesh.

use std::sync::Arc;

use roomler_ai_remote_control::signaling;
use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use tunnel_core::env::node_env;
use tunnel_core::localapi;
use tunnel_core::localapi::OverlayView;
use tunnel_core::overlay::WgKeypair;
use tunnel_core::overlay::runtime::{
    DerpMuxFactory, OverlayEvent, OverlayRuntime, RegionalDerpFactory, TunFactory,
};
#[cfg(feature = "overlay-l3")]
use tunnel_core::overlay::tun::SystemTun;
use tunnel_core::overlay::tun::TunIo;

use crate::config::AgentConfig;

/// Overlay MTU. 1280 (the IPv6 minimum) is safe under WireGuard + coturn
/// overhead on any path.
const OVERLAY_MTU: u16 = 1280;

/// rc.307 (B) — everything a spawned runtime's behavior was derived from.
/// A reconnect with an EQUAL fingerprint re-attaches the persistent runtime
/// (carriers survive); any difference spawns a fresh one (the old dies when
/// its last event-sender clone drops). Live-read env flags (MBB, DERP, tier
/// gates, …) are deliberately NOT here — `make_join` re-reads them on every
/// re-join, so they don't need a rebuild.
#[derive(Clone, PartialEq)]
struct RuntimeFingerprint {
    wg_public_key: String,
    netstack_port: Option<u16>,
    advertised_routes: Vec<String>,
    exit_node: Option<String>,
    tenant_id: String,
    server_url: String,
    /// The local LAN interface IP set (sorted). The config-derived fields
    /// above are process-immutable (config changes restart the daemon), so
    /// this is the ONE input that actually changes at runtime: after a
    /// network move the persistent runtime's per-interface sockets are bound
    /// to dead addresses and its punch socket STUNs from a corpse — a
    /// changed set forces the full rebuild a move needs. IP set only (not
    /// ifindexes): Windows renumbers ifindexes on adapter events without the
    /// addresses changing, and the sockets are bound to addresses.
    lan_ips: Vec<String>,
}

impl RuntimeFingerprint {
    /// R4 — do the fields that REQUIRE a runtime respawn all match?
    /// `lan_ips` is deliberately excluded: it is the one runtime-variable
    /// input, and a changed set is handled by an IN-PLACE direct-plane
    /// rebuild (`OverlayEvent::RebuildDirect`) instead of the old
    /// spawn-a-second-runtime path — which never told the first runtime,
    /// left both holding direct sockets, and made the new one walk the
    /// stable-port band, forfeiting the very 5-tuple stability rc.307/308
    /// exist to provide.
    fn same_shape(&self, other: &Self) -> bool {
        self.wg_public_key == other.wg_public_key
            && self.netstack_port == other.netstack_port
            && self.advertised_routes == other.advertised_routes
            && self.exit_node == other.exit_node
            && self.tenant_id == other.tenant_id
            && self.server_url == other.server_url
    }
}

struct RuntimeSlot {
    fingerprint: RuntimeFingerprint,
    evt_tx: mpsc::Sender<OverlayEvent>,
}

/// rc.307 (B) — the process-lifetime runtime slots. The overlay runtime used
/// to be scoped to ONE control-WS session (every server deploy / pod roll /
/// receive-liveness cycle tore down all carriers and rebuilt from empty —
/// which relay-locks a corp-VPN'd host whose firewall only grandfathers
/// established UDP flows). Now the first session spawns the runtime and
/// every later session RE-ATTACHES it (`OverlayEvent::Reattach`): the
/// runtime swaps its outbound sender, re-joins, and reconciles the reply
/// netmap against live state. The data plane (TUN, WG peers, carriers)
/// keeps flowing through the whole control-plane outage.
///
/// Multi-org P2c — keyed by TENANT: each org supervisor owns its own
/// persistent runtime, so org B's fresh spawn can never evict org A's
/// re-attach entry (a single slot would ping-pong and both orgs would
/// rebuild-from-empty on every reconnect — exactly the churn rc.307 killed).
static RUNTIME_SLOTS: std::sync::Mutex<std::collections::BTreeMap<String, RuntimeSlot>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// R4 — the per-tenant CENTRAL DERP mux, exposed to the tunnel plane for the
/// `quic-derp-v1` flavor. `Weak` so a mux that died with its runtime reads
/// as absent instead of leaking; the stored hex is the node's own pubkey
/// (the mux registered with it — one identity per tenant enrollment).
static DERP_TUNNEL_MUXES: std::sync::Mutex<
    std::collections::BTreeMap<
        String,
        (
            std::sync::Weak<tunnel_core::transport::derp::DerpMux>,
            String,
        ),
    >,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// R4 — the PRIMARY enrollment's tenant id, set once at daemon start. The
/// tunnel plane's derp flavor is primary-org-scoped (declared routes are;
/// the reconciler parks non-primary routes), and the flow supervisor has no
/// per-org context — this is its bridge to the right mux.
pub static PRIMARY_TENANT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn register_derp_tunnel_mux(tenant: &str, mux: &Arc<tunnel_core::transport::derp::DerpMux>) {
    DERP_TUNNEL_MUXES.lock().unwrap().insert(
        tenant.to_string(),
        (
            Arc::downgrade(mux),
            tunnel_core::transport::derp::pubkey_hex(&mux.self_pubkey()),
        ),
    );
}

/// R4 — the PRIMARY org's live DERP mux + identity as a tunnel handle, or
/// `None` when the overlay/derp is down or not yet started (callers fall
/// back to the classic transport ladder).
pub(crate) fn primary_derp_tunnel_handle() -> Option<tunnel_core::transport::derp::DerpTunnelHandle>
{
    derp_tunnel_handle(PRIMARY_TENANT_ID.get()?)
}

/// R4 — a specific tenant's live DERP mux + identity as a tunnel handle.
pub(crate) fn derp_tunnel_handle(
    tenant: &str,
) -> Option<tunnel_core::transport::derp::DerpTunnelHandle> {
    let slots = DERP_TUNNEL_MUXES.lock().unwrap();
    let (weak, hex) = slots.get(tenant)?;
    let mux = weak.upgrade()?;
    Some(tunnel_core::transport::derp::DerpTunnelHandle {
        mux,
        self_pubkey_hex: hex.clone(),
    })
}

/// Multi-org v2 — the ONE process-wide shared carrier plane every org's
/// engine attaches to when `overlay_shared_carrier` is on (one stable
/// direct-socket set for the whole daemon; receiver-index demux). Created on
/// first use, process-lifetime — the plane must outlive
/// any single org's session churn.
static SHARED_PLANE: std::sync::Mutex<
    Option<std::sync::Arc<tunnel_core::overlay::carrier_plane::CarrierPlane>>,
> = std::sync::Mutex::new(None);

/// The plane when the flag is on (`OVERLAY_SHARED_CARRIER` / config
/// `overlay_shared_carrier`, built-in default ON since rc.339 — explicit
/// `false` is the kill switch), else `None` — the runtime then binds
/// per-runtime sockets exactly as before.
fn shared_carrier_plane()
-> Option<std::sync::Arc<tunnel_core::overlay::carrier_plane::CarrierPlane>> {
    if !tunnel_core::env::flag("OVERLAY_SHARED_CARRIER", true) {
        return None;
    }
    let mut g = SHARED_PLANE.lock().unwrap_or_else(|e| e.into_inner());
    Some(
        g.get_or_insert_with(tunnel_core::overlay::carrier_plane::CarrierPlane::new)
            .clone(),
    )
}

/// If overlay is enabled, spawn the node runtime (relay mode) and return
/// the channel its control events arrive on. `None` when overlay is
/// disabled or the node has no persisted WG key (generated at startup in
/// `main`, so a missing one here means a misconfiguration).
pub async fn maybe_start(
    cfg: &AgentConfig,
    // FR-103 — this enrollment's LIVE token. The DERP dialer below outlives
    // the connection that built it (the runtime persists across reconnects),
    // so it reads this per dial rather than keeping a copy.
    token: crate::token_slot::TokenSlot,
    outbound: mpsc::Sender<ClientMsg>,
    peer_view: watch::Sender<OverlayView>,
    derp_ticket_slot: crate::relay_probe::DerpTicketSlot,
    // A2 — the session-services bundle the SSH server is built with. Threaded
    // explicitly (signaling::run already holds the broker) instead of the old
    // `consent::set_shared` process global.
    services: crate::ssh::SessionServices,
) -> Option<mpsc::Sender<OverlayEvent>> {
    if !cfg.overlay_enabled {
        // Drop THIS org's persistent-runtime slot entry: once the sessions'
        // event-sender clones are gone too, its channel closes and it tears
        // down cleanly. Other orgs' runtimes are untouched.
        RUNTIME_SLOTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&cfg.tenant_id);
        return None;
    }
    let Some(keypair) = cfg
        .overlay_wg_secret_key
        .as_deref()
        .and_then(WgKeypair::from_secret_base64)
    else {
        warn!("overlay enabled but no/invalid WG key persisted; not joining the mesh");
        return None;
    };

    // rc.307 (B) — re-attach the persistent runtime when nothing that shaped
    // it changed. Take the sender clone OUTSIDE the lock before awaiting.
    let fingerprint = RuntimeFingerprint {
        wg_public_key: keypair.public_base64(),
        netstack_port: netstack_socks_port(cfg),
        advertised_routes: cfg.effective_overlay_advertised_routes(),
        exit_node: cfg.overlay_exit_node.clone(),
        tenant_id: cfg.tenant_id.clone(),
        server_url: cfg.server_url.clone(),
        lan_ips: {
            let mut ips: Vec<String> = tunnel_core::overlay::direct::gather_lan_interfaces()
                .into_iter()
                .map(|(ip, _)| ip.to_string())
                .collect();
            ips.sort();
            ips
        },
    };
    let existing = {
        let slots = RUNTIME_SLOTS.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .get(&cfg.tenant_id)
            .filter(|s| s.fingerprint.same_shape(&fingerprint))
            .map(|s| {
                (
                    s.evt_tx.clone(),
                    s.fingerprint.lan_ips == fingerprint.lan_ips,
                )
            })
    };
    if let Some((evt_tx, lan_ips_same)) = existing {
        match evt_tx
            .send(OverlayEvent::Reattach {
                outbound: outbound.clone(),
            })
            .await
        {
            Ok(()) => {
                if lan_ips_same {
                    info!("overlay: re-attached the persistent node runtime (carriers intact)");
                } else {
                    // R4 — the LAN IP set moved while the runtime persisted:
                    // reattach (control plane) + rebuild the direct plane in
                    // place (data plane). Replaces the old fresh-spawn path,
                    // which raced the surviving runtime for the stable ports.
                    info!(
                        "overlay: re-attached the persistent runtime; LAN addresses changed — requesting a direct-plane rebuild"
                    );
                    let _ = evt_tx.send(OverlayEvent::RebuildDirect).await;
                    // Store the NEW set so the next reconnect compares
                    // against what the rebuild actually bound.
                    if let Some(s) = RUNTIME_SLOTS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_mut(&cfg.tenant_id)
                    {
                        s.fingerprint = fingerprint.clone();
                    }
                }
                return Some(evt_tx);
            }
            Err(_) => {
                // The runtime exited (self_ip change, TUN failure). Fall
                // through to a fresh spawn.
                info!("overlay: previous node runtime exited; starting fresh");
            }
        }
    }

    let (evt_tx, evt_rx) = mpsc::channel::<OverlayEvent>(64);

    // Pick the overlay surface: the userspace netstack (+ loopback SOCKS front)
    // when `ROOMLERD_OVERLAY_NETSTACK_SOCKS` names a port, else the OS TUN.
    // Either surface can be absent at build time; the helper warns + `None`s,
    // and `?` aborts the (mis)configured start.
    //
    // Multi-org P2c: with `overlay_multi_org` on, every `tun` org (primary
    // included) gets its OWN OS TUN adapter, keyed by its tenant id (below;
    // it replaced the shared-TUN mux W7c deleted). A secondary in `netstack`
    // mode (#2493, `derived_netstack`) takes its own stack and SOCKS front on
    // the port its `[[orgs]]` entry names instead: the flag is device-wide,
    // and it used to send such an org down the TUN path, where `for_org` had
    // already switched it off. The PRIMARY's env-key netstack still yields to
    // the flag, as before. The warning is about that env key, so a `tun`
    // secondary keeping the port it had in netstack mode stays quiet.
    let tun_factory: TunFactory = if cfg.overlay_multi_org && !cfg.derived_netstack {
        if !cfg.derived_org && netstack_socks_port(cfg).is_some() {
            warn!(
                "overlay: OVERLAY_NETSTACK_SOCKS is set but overlay_multi_org is on — \
                 the primary's netstack yields to that flag; using its own OS TUN instead"
            );
        }
        // Multi-org v2 — per-org adapters: each org gets its OWN device
        // (own address space, own route domain; one address per adapter, so
        // OS source selection is trivially correct). THE path since rc.339's
        // 4-host field soak; W7c (overlay v3) deleted the shared-TUN mux +
        // compensation stack it superseded after the ≥7-day fleet-zero
        // counter gate (mux_nat_rewrites / restores / skip_as_source_flips).
        per_org_systun_factory(cfg.tenant_id.clone(), !cfg.derived_org)?
    } else {
        match netstack_socks_port(cfg) {
            // Give the netstack SOCKS front a live mesh view so it can resolve
            // DOMAIN targets (peer name / MagicDNS FQDN → overlay IP). Same channel
            // the runtime publishes to below, so it's stable across reconnects.
            Some(port) => netstack_tun_factory(port, peer_view.subscribe(), &cfg.tenant_id)?,
            None => systun_tun_factory()?,
        }
    };
    // Roomler SSH — when this node opts in, splice a port-intercept shim over
    // whichever device we just chose, so `<overlay ip>:<ssh_port>` terminates in
    // the daemon. Deliberately applied AFTER the mode selection: it decorates
    // the OS-TUN, per-org and netstack factories identically, so SSH behaves the
    // same on a server, a multi-org host and a locked-down corp laptop.
    // No-op (and byte-for-byte the old path) unless `ssh_enabled` is on.
    let tun_factory = crate::ssh::maybe_intercept(tun_factory, cfg, services);
    // P5 exit-node client — resolve the coordination server's IPs NOW, while the
    // uplink is still clean (before any split-default is installed), so exit
    // routing can exempt them. Only when this node opts into an exit node.
    let exit_server_ips = if cfg.overlay_exit_node.is_some() {
        resolve_server_ips(&cfg.server_url).await
    } else {
        Vec::new()
    };

    // Phase D (DERP) — when enabled, provide a factory that opens the persistent
    // `/derp` WS. The runtime calls it lazily when THIS node is UDP-blocked
    // (its srflx gather found nothing) — and, Phase A (overlay v3), also
    // unconditionally when `overlay_derp_floor` is on (the always-on floor:
    // every floor-capable node stays registered so pairs can be floored at
    // birth). When called, it builds the demux, opens the WS (both peers dial
    // OUT over TCP/TLS-443), and returns the mux. Default-ON since rc.203.
    let derp_factory: Option<DerpMuxFactory> = if tunnel_core::overlay::direct::derp_enabled() {
        let ws_url = cfg.ws_url();
        let tenant = cfg.tenant_id.clone();
        let pubkey = keypair.public.to_bytes();
        Some(Box::new(move || {
            let (mux, outbound_rx) = tunnel_core::transport::derp::DerpMux::new(pubkey);
            crate::derp::spawn(&ws_url, token.clone(), &tenant, &mux, outbound_rx);
            // R4 — expose this tenant's central mux to the tunnel plane
            // (the quic-derp-v1 flavor multiplexes over it).
            register_derp_tunnel_mux(&tenant, &mux);
            info!("overlay derp: /derp carrier opened (UDP-blocked tier, or the always-on floor)");
            mux
        }))
    } else {
        None
    };

    // Multi-region DERP — the per-URL regional relay opener the force-DERP
    // handler consults when a push carries a `derp_url`. Reads the admission
    // ticket cached by the signaling loop; no ticket yet ⇒ `None` (the
    // coordinator degrades to the central mux; the WS owner spawned on a
    // later successful open reads the slot per attempt anyway).
    let regional_derp_factory: Option<RegionalDerpFactory> =
        if tunnel_core::overlay::direct::derp_enabled() {
            let tenant = cfg.tenant_id.clone();
            let pubkey = keypair.public.to_bytes();
            let slot = derp_ticket_slot.clone();
            Some(Box::new(move |url: &str| {
                let has_ticket = slot.lock().unwrap_or_else(|e| e.into_inner()).is_some();
                if !has_ticket {
                    warn!(%url, "overlay derp: regional relay pushed but no admission ticket yet");
                    return None;
                }
                let (mux, outbound_rx) = tunnel_core::transport::derp::DerpMux::new(pubkey);
                crate::derp::spawn_regional(url, slot.clone(), &tenant, &mux, outbound_rx);
                info!(%url, "overlay derp: regional /derp carrier opened");
                Some(mux)
            }))
        } else {
            None
        };

    let rt = OverlayRuntime::new_relay(keypair, outbound, tun_factory, OVERLAY_MTU)
        // FR-40 — the epoch persisted next to the key, bumped per rotation;
        // sent as `key_epoch` on the join.
        .with_key_epoch(cfg.overlay_wg_key_epoch)
        // Phase 1 — advertise this node's subnet routes (admin-gated server-side).
        // P5 — plus `0.0.0.0/0` when this node is configured as an exit node.
        .with_advertised_routes(cfg.effective_overlay_advertised_routes())
        // P5 — route THIS node's default egress through a chosen exit peer (with
        // carrier-endpoint exemptions), when `overlay_exit_node` is set.
        .with_exit_node(cfg.overlay_exit_node.clone(), exit_server_ips)
        // FR-97 P0c-3 — the netstack front, when that is the device chosen
        // above (under multi-org, only for a netstack secondary, #2493): an
        // exit then carries only what the front dials, and the host's DNS is
        // left alone.
        .with_netstack_socks(
            (!cfg.overlay_multi_org || cfg.derived_netstack)
                .then(|| netstack_socks_port(cfg))
                .flatten(),
        )
        // Phase D — LAZY `/derp`: the runtime opens the WS via this factory only
        // if the node is itself UDP-blocked (else no idle WS).
        .with_derp_mux_factory(derp_factory)
        // Multi-region DERP — per-URL regional relay opener (ticket-gated).
        .with_regional_derp_factory(regional_derp_factory)
        // Multi-org v2 — every org's engine shares ONE process-wide socket
        // set (receiver-index demux) instead of racing the port band.
        .with_carrier_plane(shared_carrier_plane())
        // Unification P1 — publish the live mesh view for the LocalAPI so
        // `roomler status` / `peers` see per-device connection types.
        .with_peer_view(peer_view)
        .with_org_primary(!cfg.derived_org)
        .with_relay_listener_readiness(crate::relay_server::readiness());
    // FIELD: endpoints are advertised lazily — the relay coordinator
    // trickles each relayed address post-allocation — so join carries none.
    tokio::spawn(rt.run(evt_rx, Vec::new()));
    info!("overlay: node runtime started (relay mode)");
    // rc.307 (B) — remember it for the next session's re-attach, under THIS
    // org's key. Replacing a fingerprint-mismatched entry drops the old
    // runtime's last stored sender clone; it tears down once the old
    // session's clones are gone too.
    RUNTIME_SLOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            cfg.tenant_id.clone(),
            RuntimeSlot {
                fingerprint,
                evt_tx: evt_tx.clone(),
            },
        );
    Some(evt_tx)
}

/// Resolve the coordination server's host (from `server_url`) to its current
/// IPs. Exit-node routing exempts these from the split-default, and they MUST be
/// resolved BEFORE any `0.0.0.0/1` is installed — once the default is captured,
/// DNS to a remote resolver may itself be swallowed. Best-effort + timeout-bound:
/// an empty result just means the runtime's exemption gate withholds default
/// routing (fail-safe — never a wedge). roomler.ai sits behind nginx/HAProxy and
/// may be multi-A, so every returned address is exempted.
async fn resolve_server_ips(server_url: &str) -> Vec<std::net::IpAddr> {
    use std::collections::HashSet;
    use std::net::IpAddr;

    // Host out of `scheme://host[:port][/path]` (server_url is never a v6 literal).
    let authority = server_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_url)
        .split('/')
        .next()
        .unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .trim();
    if host.is_empty() {
        return Vec::new();
    }
    // #2187 — through `ctl_dns`: the control WS resolves the server the same
    // way, so the exemption pins and the connection agree on the addresses, and
    // a name resolved before never waits on a dead resolver. A first lookup is
    // bounded at `ctl_dns::FIRST_LOOKUP_BOUND` (5 s, as before).
    let ips: Vec<IpAddr> =
        tunnel_core::ctl_dns::resolve(&tunnel_core::ctl_dns::hostport(host, 443))
            .await
            .into_iter()
            .map(|s| s.ip())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
    if ips.is_empty() {
        warn!(%host, "overlay exit-node: coordination-server DNS resolve failed; exit routing withholds until exemptions are known");
        return ips;
    }
    info!(
        %host,
        count = ips.len(),
        "overlay exit-node: resolved coordination-server IPs for carrier exemption"
    );
    ips
}

/// This org's loopback SOCKS5 port for **netstack mode**. `None` (the
/// default) selects OS-TUN mode; a zero value is treated as unset.
///
/// The PRIMARY reads `ROOMLERD_OVERLAY_NETSTACK_SOCKS`, exactly as
/// before. A SECONDARY gets whatever its `[[orgs]]` entry declares and
/// deliberately does NOT fall back to the env key: the port is one TCP
/// listener, so inheriting it would put two orgs on one front — the very
/// thing the per-org split exists to prevent.
fn netstack_socks_port(cfg: &AgentConfig) -> Option<u16> {
    cfg.netstack_socks_port
        .or_else(|| {
            // Only a primary config reaches the env: `for_org` always sets
            // the field explicitly (to the org's value, or None).
            (!cfg.derived_org)
                .then(|| node_env("OVERLAY_NETSTACK_SOCKS"))
                .flatten()
                .and_then(|v| v.trim().parse::<u16>().ok())
        })
        .filter(|p| *p != 0)
}

/// rc.280 — process-lifetime TUN cache. The runtime builds its device per WS
/// SESSION (first netmap) and drops it when `run()` returns, which used to
/// REMOVE the Wintun adapter on every reconnect (wintun's close-of-created
/// removes) and re-create it seconds later — the ifIndex/NLA churn multiplier
/// on top of the per-create random GUID (fixed in rc.279), and the source of
/// the rc.209 "device installation mutex" race between a dying session's
/// release and the next session's create. Caching the `Arc` here keeps the
/// device alive across sessions: a reconnect with the same `(ip, netmask,
/// mtu)` reuses it (metric pin, derived v6, WFP guard, Private profile all
/// still in place); a changed tuple (re-IP / re-enroll) drops the old device
/// first, then builds fresh. The static itself is never dropped, so even a
/// clean process exit leaves the adapter installed — the next process opens
/// it by name or re-forms the same identity via the rc.279 stable GUID.
#[cfg(feature = "overlay-l3")]
#[allow(clippy::type_complexity)]
static SYSTUN_CACHE: std::sync::Mutex<
    Option<(
        (std::net::Ipv4Addr, std::net::Ipv4Addr, u16),
        Arc<SystemTun>,
    )>,
> = std::sync::Mutex::new(None);

/// OS-TUN factory (`overlay-l3`). The agent is privileged, so the device +
/// routes come up directly in `SystemTun::up`. Kill-switch for the cache:
/// `overlay_tun_persist` / `ROOMLERD_OVERLAY_TUN_PERSIST`, default ON —
/// `0` restores the per-session create/remove cycle.
#[cfg(feature = "overlay-l3")]
fn systun_tun_factory() -> Option<TunFactory> {
    Some(Box::new(|ip, nm, mtu| {
        if !tunnel_core::env::flag("OVERLAY_TUN_PERSIST", true) {
            return SystemTun::up(ip, nm, mtu).map(|t| Arc::new(t) as Arc<dyn TunIo>);
        }
        let mut cache = SYSTUN_CACHE.lock().unwrap();
        if let Some((params, dev)) = cache.as_ref()
            && *params == (ip, nm, mtu)
            && dev.is_alive()
        {
            info!("overlay: reusing the process-lifetime TUN device (reconnect)");
            return Ok(dev.clone() as Arc<dyn TunIo>);
        }
        // Param change (re-IP) or dead device: release the old one BEFORE the
        // new create so the adapter's device-install lock frees up (the
        // rc.209 mutex retry inside `up` covers the release latency).
        *cache = None;
        let dev = Arc::new(SystemTun::up(ip, nm, mtu)?);
        *cache = Some(((ip, nm, mtu), dev.clone()));
        Ok(dev as Arc<dyn TunIo>)
    }))
}
#[cfg(not(feature = "overlay-l3"))]
fn systun_tun_factory() -> Option<TunFactory> {
    warn!(
        "overlay: OS-TUN mode requested but this build lacks `overlay-l3` \
         (set ROOMLERD_OVERLAY_NETSTACK_SOCKS for netstack mode); not joining"
    );
    None
}

/// Multi-org — release everything process-wide an org held: its per-org TUN
/// device claim, and the netstack surface if it owned that.
///
/// Called when an org's supervised loop ENDS for good (disabled, removed,
/// terminal error) — until now the address stayed up until the daemon
/// restarted (docs/multi-org.md §12). Harmless but untidy, and on a
/// long-lived multi-org host the litter accumulates.
///
/// No-op for anything the org never claimed (single-org daemons never
/// register), so it is safe to call unconditionally on teardown.
pub fn release_org(org_key: &str) {
    release_per_org_tun(org_key);
    release_netstack(org_key);
}

/// Hand this org's loopback SOCKS port back when its loop ends, so an org
/// configured onto the same port can take it on its next reconnect instead
/// of withholding forever.
#[cfg(feature = "overlay-netstack")]
fn release_netstack(org_key: &str) {
    let mut ports = SOCKS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ports) = ports.as_mut() {
        let freed: Vec<u16> = ports
            .iter()
            .filter(|(_, o)| o.as_str() == org_key)
            .map(|(p, _)| *p)
            .collect();
        for p in freed {
            ports.remove(&p);
            info!(org = %org_key, port = p,
                "overlay netstack: released the org's loopback SOCKS port");
        }
    }
}
#[cfg(not(feature = "overlay-netstack"))]
fn release_netstack(_org_key: &str) {}

/// Multi-org v2 — per-org TUN devices, keyed by tenant. Same process-lifetime
/// reuse contract as [`SYSTUN_CACHE`] (incl. the `overlay_tun_persist` kill
/// switch), one entry per org. Dropping an entry releases the process's
/// device handle; the ADAPTER persists by design (stable per-org GUID —
/// explicit org removal owns real deletion, never a loop end, so an ESET-y
/// host never sees device churn on reconnects).
#[cfg(feature = "overlay-l3")]
#[allow(clippy::type_complexity)]
static ORG_TUN_CACHE: std::sync::Mutex<
    Option<
        std::collections::BTreeMap<
            String,
            (
                (std::net::Ipv4Addr, std::net::Ipv4Addr, u16),
                Arc<SystemTun>,
            ),
        >,
    >,
> = std::sync::Mutex::new(None);

/// Multi-org v2 — a per-org adapter name that FITS the OS limit. Linux caps
/// interface names at `IFNAMSIZ-1` = 15 usable chars, and the base `IF_NAME`
/// differs per platform (`roomler` on Windows = 7, `roomler0` on Linux = 8),
/// so the naive `roomler0-<7hex>` (16) overflows on Linux and the kernel
/// rejects it — the secondary org's TUN never comes up. The tenant suffix is
/// truncated to whatever fits after `<IF_NAME>-`: Windows keeps 7 hex
/// (`roomler-6a712a5`), Linux keeps 6 (`roomler0-6a712a`). Deterministic per
/// (machine, org) — the suffix is a stable tenant-id prefix, and the FULL
/// tenant still drives the distinct per-org GUID, so a 6-hex-prefix clash
/// (negligible for a machine's handful of orgs) can't alias two devices.
fn per_org_ifname(if_name: &str, org_key: &str) -> String {
    const MAX_IFNAME: usize = 15; // IFNAMSIZ - 1 (Linux); Windows aliases allow more
    let max_suffix = MAX_IFNAME.saturating_sub(if_name.len() + 1);
    let short = &org_key[..org_key.len().min(max_suffix)];
    format!("{if_name}-{short}")
}

/// Multi-org v2 — the per-org twin of [`systun_tun_factory`]: this org gets
/// its OWN adapter with its own name, stable per-org GUID, and a derived-ULA
/// on-link NARROWED to its block (`96 + v4_plen`), so N adapters hold
/// nested-or-disjoint v6 prefixes and longest-prefix picks the right one.
///
/// Naming: the primary KEEPS the legacy `IF_NAME` (`roomler` / `roomler0`) +
/// GUID (no adapter churn on the mode flip); a secondary is
/// [`per_org_ifname`] (length-clamped for Linux IFNAMSIZ) with a stable
/// per-org GUID. The primary's on-link is narrowed too: its whole-/96 would
/// otherwise cover every sibling's embedded ULA range.
#[cfg(feature = "overlay-l3")]
fn per_org_systun_factory(org_key: String, is_primary: bool) -> Option<TunFactory> {
    use tunnel_core::overlay::tun::{IF_NAME, TunOptions, org_tun_guid};
    Some(Box::new(move |ip, nm, mtu| {
        let plen = u32::from(nm).count_ones() as u8;
        let mut opts = TunOptions::legacy(ip, nm, mtu);
        opts.v6_onlink_plen = 96 + plen;
        if !is_primary {
            opts.name = per_org_ifname(IF_NAME, &org_key);
            opts.guid = org_tun_guid(&org_key);
        }
        if !tunnel_core::env::flag("OVERLAY_TUN_PERSIST", true) {
            return SystemTun::up_with(opts).map(|t| Arc::new(t) as Arc<dyn TunIo>);
        }
        let mut cache = ORG_TUN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let map = cache.get_or_insert_with(Default::default);
        if let Some((params, dev)) = map.get(&org_key)
            && *params == (ip, nm, mtu)
            && dev.is_alive()
        {
            info!(org = %org_key, "overlay: reusing this org's process-lifetime TUN device (reconnect)");
            return Ok(dev.clone() as Arc<dyn TunIo>);
        }
        // Param change (re-IP) or dead device: release the old handle BEFORE
        // the new create (frees the adapter's device-install lock; the
        // rc.209 retry inside `up_with` covers the release latency).
        map.remove(&org_key);
        let dev = Arc::new(SystemTun::up_with(opts)?);
        map.insert(org_key.clone(), ((ip, nm, mtu), dev.clone()));
        info!(org = %org_key, primary = is_primary, "overlay: per-org TUN device up");
        Ok(dev as Arc<dyn TunIo>)
    }))
}
#[cfg(not(feature = "overlay-l3"))]
fn per_org_systun_factory(_org_key: String, _is_primary: bool) -> Option<TunFactory> {
    warn!("overlay: a per-org adapter requires an `overlay-l3` build; not joining");
    None
}

/// Drop an org's per-org device HANDLE when its loop ends for good. The
/// adapter itself persists (stable GUID re-binds it next start); explicit
/// org removal owns real deletion.
#[cfg(feature = "overlay-l3")]
fn release_per_org_tun(org_key: &str) {
    let mut cache = ORG_TUN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = cache.as_mut()
        && map.remove(org_key).is_some()
    {
        info!(org = %org_key, "overlay: released the org's per-org TUN handle (adapter persists)");
    }
}
#[cfg(not(feature = "overlay-l3"))]
fn release_per_org_tun(_org_key: &str) {}

/// Multi-org — one netstack handle channel PER ORG.
///
/// This used to be a single `OnceLock` channel, and that was the bug: the
/// SOCKS front and the `roomler ping` backend both read it, so a second org
/// publishing its stack did not join the mesh twice — it REPLACED the first
/// org's stack underneath a front that kept answering on the same port, and
/// a caller dialing for org A was silently routed by org B.
///
/// Keyed by org (the tenant id), so each org's front and pinger read their
/// OWN stack. Created on first use per org and reused across that org's
/// reconnects, which is what keeps the front alive between sessions.
#[cfg(feature = "overlay-netstack")]
#[allow(clippy::type_complexity)]
static NS_HANDLES: std::sync::Mutex<
    Option<
        std::collections::BTreeMap<
            String,
            watch::Sender<Option<tunnel_core::overlay::netstack::NetstackHandle>>,
        >,
    >,
> = std::sync::Mutex::new(None);

#[cfg(feature = "overlay-netstack")]
fn ns_handle_tx(
    org_key: &str,
) -> watch::Sender<Option<tunnel_core::overlay::netstack::NetstackHandle>> {
    let mut map = NS_HANDLES.lock().unwrap_or_else(|e| e.into_inner());
    map.get_or_insert_with(Default::default)
        .entry(org_key.to_string())
        .or_insert_with(|| watch::channel(None).0)
        .clone()
}

/// Which org holds each loopback SOCKS port.
///
/// The per-org split removes the shared-stack hazard but not this one: a
/// port is a single TCP listener, so two orgs configured onto the same one
/// still genuinely conflict. First org in binds it; a second withholds its
/// overlay with an actionable message rather than taking a front that
/// answers for someone else. Released when its owner's loop ends.
#[cfg(feature = "overlay-netstack")]
static SOCKS_PORTS: std::sync::Mutex<Option<std::collections::BTreeMap<u16, String>>> =
    std::sync::Mutex::new(None);

/// Claim `port` for `org_key`. `false` ⇒ another org already holds it.
/// Re-claiming by the owner is a no-op, which is what every reconnect does.
#[cfg(feature = "overlay-netstack")]
fn claim_socks_port(org_key: &str, port: u16) -> bool {
    let mut map = SOCKS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let map = map.get_or_insert_with(Default::default);
    match map.get(&port) {
        Some(cur) => cur == org_key,
        None => {
            map.insert(port, org_key.to_string());
            true
        }
    }
}

/// Netstack factory (`overlay-netstack`): each (re)connect builds a fresh
/// userspace stack for THIS org and publishes its handle to that org's
/// channel, so its loopback SOCKS front (bound once per port) outlives
/// reconnects without rebinding.
///
/// `None` when another org already holds `socks_port` — see
/// [`claim_socks_port`].
#[cfg(feature = "overlay-netstack")]
fn netstack_tun_factory(
    socks_port: u16,
    view_rx: watch::Receiver<OverlayView>,
    org_key: &str,
) -> Option<TunFactory> {
    use std::net::Ipv4Addr;
    use tunnel_core::overlay::netstack::Netstack;
    use tunnel_core::overlay::netstack_socks::serve_socks5;

    if !claim_socks_port(org_key, socks_port) {
        warn!(
            org = %org_key, port = socks_port,
            "overlay netstack: another organization already serves this loopback SOCKS \
             port. This org joins no mesh until it gets its own — set \
             `netstack_socks_port` on its [[orgs]] entry, or give both orgs an OS \
             TUN of their own with `overlay_multi_org`."
        );
        return None;
    }

    let handle_tx = ns_handle_tx(org_key);

    // Bind this org's front exactly once — a repeat call for the same port
    // is a reconnect, and the running front is already subscribed to the
    // org's channel.
    let bind_needed = {
        let mut bound = SOCKS_BOUND.lock().unwrap_or_else(|e| e.into_inner());
        bound
            .get_or_insert_with(Default::default)
            .insert(socks_port)
    };
    if bind_needed {
        let handle_rx = handle_tx.subscribe();
        let org = org_key.to_string();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).await {
                Ok(l) => {
                    info!(
                        port = socks_port, %org,
                        "overlay netstack: SOCKS5 front on 127.0.0.1"
                    );
                    serve_socks5(handle_rx, view_rx, l).await;
                }
                Err(e) => {
                    warn!(port = socks_port, %org, error = %e,
                        "overlay netstack: SOCKS bind failed")
                }
            }
        });
    }

    let org = org_key.to_string();
    Some(Box::new(move |ip, nm, mtu| {
        let ns = Netstack::start(ip, netmask_to_prefix(nm), mtu);
        let _ = handle_tx.send(Some(ns.handle.clone()));
        info!(%ip, socks_port, %org, "overlay netstack: userspace stack up (OS-free)");
        Ok(ns.tun as Arc<dyn TunIo>)
    }))
}

/// Ports whose SOCKS front task is already running.
#[cfg(feature = "overlay-netstack")]
static SOCKS_BOUND: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> =
    std::sync::Mutex::new(None);

/// The netstack ICMP backend for the `roomler ping` LocalAPI verb, watching the
/// shared handle channel. `None` unless this node is in netstack mode
/// (`ROOMLERD_OVERLAY_NETSTACK_SOCKS` set) — an OS-TUN node has no OS-free
/// ICMP path (the OS `ping` works there).
#[cfg(feature = "overlay-netstack")]
pub fn netstack_pinger(
    cfg: &AgentConfig,
) -> Option<Arc<dyn crate::localapi_state::NetstackPinger>> {
    use std::net::IpAddr;
    use std::time::Duration;
    use tunnel_core::overlay::netstack::NetstackHandle;

    // Only meaningful in netstack mode; `?` short-circuits to `None`
    // otherwise. Scoped to THIS config's org: `roomler ping` is a
    // process-wide verb, so it answers for the primary — a secondary's
    // stack is reachable through that org's own SOCKS front.
    netstack_socks_port(cfg)?;

    struct NsPinger {
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    #[async_trait::async_trait]
    impl crate::localapi_state::NetstackPinger for NsPinger {
        async fn ping(&self, dst: IpAddr, timeout: Duration) -> Result<Duration, String> {
            let handle = self
                .handle
                .borrow()
                .clone()
                .ok_or_else(|| "netstack not up yet (mesh not joined)".to_string())?;
            handle.ping(dst, timeout).await.map_err(|e| e.to_string())
        }
    }

    Some(Arc::new(NsPinger {
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}

/// MeshHarbor #20 FWD-02 — how a managed forward dials a destination behind
/// the overlay on a netstack node: this org's own stack. `None` unless this
/// node is in netstack mode: an OS-TUN node's routes carry overlay addresses.
#[cfg(feature = "overlay-netstack")]
pub fn managed_forward_dialer(
    cfg: &AgentConfig,
) -> Option<Arc<dyn crate::managed_forward::OverlayDial>> {
    use tunnel_core::overlay::netstack::NetstackHandle;

    netstack_socks_port(cfg)?;

    struct NsDial {
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    #[async_trait::async_trait]
    impl crate::managed_forward::OverlayDial for NsDial {
        async fn tcp(
            &self,
            dst: std::net::SocketAddr,
        ) -> std::io::Result<Box<dyn crate::managed_forward::Io>> {
            let handle =
                self.handle.borrow().clone().ok_or_else(|| {
                    std::io::Error::other("netstack not up yet (mesh not joined)")
                })?;
            Ok(Box::new(handle.connect(dst).await?))
        }
        async fn udp(
            &self,
            dst: std::net::SocketAddr,
        ) -> std::io::Result<Box<dyn crate::managed_forward::UdpSession>> {
            let handle =
                self.handle.borrow().clone().ok_or_else(|| {
                    std::io::Error::other("netstack not up yet (mesh not joined)")
                })?;
            let sock = handle.udp_bind().await?;
            Ok(Box::new(NsUdp {
                tx: sock.sender(),
                rx: tokio::sync::Mutex::new(sock),
                dst,
            }))
        }
    }

    /// A client's UDP session on the netstack: its own socket, talking to
    /// `dst` only (a datagram from anyone else is dropped).
    struct NsUdp {
        tx: tunnel_core::overlay::netstack::NsUdpSender,
        rx: tokio::sync::Mutex<tunnel_core::overlay::netstack::NsUdpSocket>,
        dst: std::net::SocketAddr,
    }
    #[async_trait::async_trait]
    impl crate::managed_forward::UdpSession for NsUdp {
        async fn send(&self, data: &[u8]) -> std::io::Result<()> {
            self.tx.send_to(data, self.dst).await
        }
        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut rx = self.rx.lock().await;
            loop {
                let (data, from) = rx.recv_from().await?;
                if from == self.dst {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok(n);
                }
            }
        }
    }

    Some(Arc::new(NsDial {
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}

#[cfg(not(feature = "overlay-netstack"))]
pub fn managed_forward_dialer(
    _cfg: &AgentConfig,
) -> Option<Arc<dyn crate::managed_forward::OverlayDial>> {
    None
}

/// FR-90 P3-8-2b — the netstack dialer for this daemon's own SSH client
/// ([`crate::ssh_client`]), watching the primary's handle channel, where
/// agent sessions run. `None` unless this node is in netstack mode: an
/// OS-TUN node dials through its routes ([`crate::ssh_client::OsDialer`]).
#[cfg(feature = "ssh-server")]
pub fn netstack_dialer(cfg: &AgentConfig) -> Option<Arc<dyn crate::ssh_client::OverlayDialer>> {
    use tunnel_core::overlay::netstack::NetstackHandle;

    netstack_socks_port(cfg)?;

    struct NsDialer {
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    #[async_trait::async_trait]
    impl crate::ssh_client::OverlayDialer for NsDialer {
        async fn dial(
            &self,
            address: &str,
            port: u16,
        ) -> Result<Box<dyn crate::ssh_client::Stream>, String> {
            let ip: std::net::IpAddr = address
                .parse()
                .map_err(|_| format!("{address} is not an overlay address"))?;
            let handle = self
                .handle
                .borrow()
                .clone()
                .ok_or_else(|| "netstack not up yet (mesh not joined)".to_string())?;
            let stream = handle
                .connect(std::net::SocketAddr::new(ip, port))
                .await
                .map_err(|e| format!("{address}:{port}: {e}"))?;
            Ok(Box::new(stream))
        }
    }

    Some(Arc::new(NsDialer {
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}
#[cfg(not(feature = "overlay-netstack"))]
fn netstack_tun_factory(
    _socks_port: u16,
    _view_rx: watch::Receiver<OverlayView>,
    _org_key: &str,
) -> Option<TunFactory> {
    warn!(
        "overlay: netstack mode requested (ROOMLERD_OVERLAY_NETSTACK_SOCKS set) \
         but this build lacks `overlay-netstack`; not joining"
    );
    None
}

/// IPv4 netmask → prefix length (count of leading one-bits).
#[cfg(feature = "overlay-netstack")]
pub(crate) fn netmask_to_prefix(nm: std::net::Ipv4Addr) -> u8 {
    u32::from(nm).count_ones() as u8
}

/// Forward an `rc:overlay.*` `ServerMsg` to the runtime. Returns the
/// message untouched if it isn't an overlay message, so the caller's
/// normal dispatch handles everything else.
pub fn intercept(
    evt_tx: &mpsc::Sender<OverlayEvent>,
    msg: ServerMsg,
    is_primary: bool,
) -> Option<ServerMsg> {
    let evt = match msg {
        ServerMsg::OverlayNetmap {
            self_ip,
            network,
            peers,
            org_relay_discovery,
            path_trial_v1,
            ..
        } => OverlayEvent::Netmap {
            self_ip,
            network,
            peers,
            org_relay_discovery,
            path_trial_v1,
        },
        ServerMsg::OverlayNetmapDelta {
            upserts, removes, ..
        } => OverlayEvent::NetmapDelta { upserts, removes },
        // FR-47 — the server could not complete our join and said why.
        //
        // Logged at ERROR and consumed here rather than forwarded as an
        // `OverlayEvent`: there is no runtime to tell, because the runtime is
        // exactly what never came up. Before this frame existed the same
        // situation produced NOTHING on this host — the daemon simply waited
        // on a netmap forever, which is indistinguishable from a slow server.
        //
        // Deliberately not retried here even when `is_retryable()`: the
        // signalling loop already reconnects on its own ladder, and a retry
        // at this layer would race it. The flag is carried for the operator
        // and for whoever adds a backoff decision later.
        ServerMsg::OverlayJoinRefused { reason, detail } => {
            tracing::error!(
                ?reason,
                %detail,
                retryable = reason.is_retryable(),
                "overlay: the server REFUSED our join — this node has no overlay \
                 address and will not appear in the mesh"
            );
            record_join_refusal(reason, &detail);
            return None;
        }
        ServerMsg::OverlayRelayGrant {
            ice_servers,
            peer_node_id,
            pair_key,
        } => OverlayEvent::RelayGrant {
            peer_node_id,
            ice_servers,
            pair_key,
        },
        // C4 stage 1 — pair-less creds for the standing warm allocation
        // (the reply to the runtime's own warm_relay_request).
        ServerMsg::OverlayWarmRelayGrant { ice_servers } => {
            OverlayEvent::WarmRelayGrant { ice_servers }
        }
        // P7 — server-pushed per-pair DERP escalation (corp TURN churn).
        ServerMsg::OverlayForceDerp {
            peer_node_id,
            ttl_ms,
            derp_url,
        } => OverlayEvent::ForceDerp {
            peer_node_id,
            ttl_ms,
            derp_url,
        },
        // FR-19 P4b — org-relay frames. PRIMARY org only: serving and use are
        // host-global, and a secondary org's WS must not be able to install a
        // session onto the device owner's listener — the `rc:agent.update`
        // trust line. The server refuses these for a secondary-org node
        // already; this is the device's own half of that rule.
        ServerMsg::OverlayPathTrialReturnPrepare { .. }
        | ServerMsg::OverlayPathTrialReturnCommit { .. }
        | ServerMsg::OverlayPathTrialReturnFinalize { .. }
        | ServerMsg::OverlayPathTrialReturnAbort { .. }
        | ServerMsg::OverlayPathTrialStart { .. }
        | ServerMsg::OverlayPathTrialCommit { .. }
        | ServerMsg::OverlayPathTrialFinalize { .. }
        | ServerMsg::OverlayPathTrialAbort { .. }
        | ServerMsg::OverlayOrgRelayCandidates { .. }
        | ServerMsg::OverlayRelaySession { .. }
        | ServerMsg::OverlayRelayBridgeServe { .. }
        | ServerMsg::OverlayRelayBridgeRevoke { .. }
        | ServerMsg::OverlayRelayServe { .. }
        | ServerMsg::OverlayRelayRevoke { .. }
            if !is_primary =>
        {
            warn!("overlay: org-relay frame on a secondary org's WS; dropped");
            return None;
        }
        trial @ (ServerMsg::OverlayPathTrialReturnPrepare { .. }
        | ServerMsg::OverlayPathTrialReturnCommit { .. }
        | ServerMsg::OverlayPathTrialReturnFinalize { .. }
        | ServerMsg::OverlayPathTrialReturnAbort { .. }
        | ServerMsg::OverlayPathTrialStart { .. }
        | ServerMsg::OverlayPathTrialCommit { .. }
        | ServerMsg::OverlayPathTrialFinalize { .. }
        | ServerMsg::OverlayPathTrialAbort { .. }) => OverlayEvent::PathTrial(trial),
        ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
        } => OverlayEvent::OrgRelayCandidates {
            peer_node_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
        },
        ServerMsg::OverlayRelaySession {
            vni,
            generation,
            peer_node_id,
            relay_node_id,
            relay_endpoints,
            bind_secret,
            bind_secs,
            max_lifetime_secs,
        } => OverlayEvent::OrgRelaySession {
            vni,
            generation,
            peer_node_id,
            relay_node_id,
            relay_endpoints,
            bind_secret,
            bind_secs,
            max_lifetime_secs,
        },
        // The RELAY's copy: install into this node's relay server, if it is
        // serving. Never reaches the member runtime.
        ServerMsg::OverlayRelayBridgeServe { bridge } => {
            crate::relay_server::install_bridge_from_wire(bridge);
            return None;
        }
        ServerMsg::OverlayRelayBridgeRevoke {
            trial_id,
            generation,
        } => {
            crate::relay_server::revoke_bridge_from_wire(trial_id, generation);
            return None;
        }
        ServerMsg::OverlayRelayServe {
            vni,
            generation,
            members,
            bind_secs,
            idle_secs,
            max_lifetime_secs,
        } => {
            crate::relay_server::install_from_wire(
                vni,
                generation,
                &members,
                bind_secs,
                idle_secs,
                max_lifetime_secs,
            );
            return None;
        }
        // A revoke reaches BOTH halves: the relay server drops the session if
        // it holds it, and the member runtime tears its carrier down.
        ServerMsg::OverlayRelayRevoke { vni } => {
            crate::relay_server::revoke_from_wire(vni);
            OverlayEvent::OrgRelayRevoke { vni }
        }
        other => return Some(other),
    };
    if evt_tx.try_send(evt).is_err() {
        warn!("overlay: event channel full/closed; dropping a netmap update");
    }
    None
}

/// The derived-port layout is split across two crates (agent-core computes,
/// tunnel-core binds) with NO direct dependency — this lock keeps the two
/// halves arithmetically consistent, or the sibling de-confliction silently
/// re-collides.
#[cfg(test)]
mod derived_port_layout_lock {
    #[test]
    fn agent_core_layout_matches_tunnel_core() {
        use roomler_node_core::config as c;
        use tunnel_core::overlay::direct as d;
        assert_eq!(c::DERIVED_PORT_BASE, u32::from(d::DEFAULT_DIRECT_PORT));
        assert_eq!(c::DERIVED_PORT_STRIDE, u32::from(d::DIRECT_PORT_BAND));
        // Every derived slot's WALK band must end before the public-dial
        // offset begins, and the highest base must clear the global cap.
        assert!(
            c::DERIVED_PORT_SLOTS * c::DERIVED_PORT_STRIDE <= u32::from(d::PUBLIC_DIAL_PORT_OFFSET),
            "a derived direct band would overlap another slot's public band"
        );
        // The band-2 jump must clear the WHOLE primary layout (direct
        // region + public region), or band-2 direct binds would land
        // inside primary public bands.
        assert!(
            u32::from(d::SECOND_BAND_OFFSET)
                >= u32::from(d::PUBLIC_DIAL_PORT_OFFSET)
                    + c::DERIVED_PORT_SLOTS * c::DERIVED_PORT_STRIDE,
            "band 2 would overlap the primary public region"
        );
        let max_base = c::DERIVED_PORT_BASE + (c::DERIVED_PORT_SLOTS - 1) * c::DERIVED_PORT_STRIDE;
        assert!(max_base <= u32::from(d::MAX_DIRECT_PORT_BASE));
    }
}

#[cfg(test)]
mod ifname_tests {
    use super::per_org_ifname;

    /// The per-org adapter name must never exceed Linux's 15-char IFNAMSIZ
    /// limit — the bug the fleet-host-2 canary caught: `roomler0-<7hex>` = 16.
    #[test]
    fn per_org_ifname_fits_ifnamsiz_on_every_platform() {
        let tenant = "6a712a572ceed780ac1ccbce";
        // Linux base "roomler0" (8): 15 - 9 = 6-hex suffix → 15 total.
        let linux = per_org_ifname("roomler0", tenant);
        assert_eq!(linux, "roomler0-6a712a");
        assert!(linux.len() <= 15, "linux name too long: {linux}");
        // Windows base "roomler" (7): 15 - 8 = 7-hex suffix → 15 total
        // (unchanged from the pre-fix Windows behavior, which already fit).
        let win = per_org_ifname("roomler", tenant);
        assert_eq!(win, "roomler-6a712a5");
        assert!(win.len() <= 15, "windows name too long: {win}");
        // A short org key never overflows and keeps its full suffix.
        assert_eq!(per_org_ifname("roomler0", "abc"), "roomler0-abc");
        // Distinct tenants that share a 6-hex prefix would clash on NAME —
        // acceptable (the full-tenant GUID still differs), and real fleet
        // tenants (grox 69a1…, jovanov 6a71…) don't even share the first char.
        assert_ne!(
            per_org_ifname("roomler0", "69a1dbbad2000f26adc875ce"),
            per_org_ifname("roomler0", "6a712a572ceed780ac1ccbce")
        );
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::RuntimeFingerprint;

    fn base() -> RuntimeFingerprint {
        RuntimeFingerprint {
            wg_public_key: "pk".into(),
            netstack_port: None,
            advertised_routes: vec!["10.0.0.0/24".into()],
            exit_node: None,
            tenant_id: "t1".into(),
            server_url: "https://roomler.ai".into(),
            lan_ips: vec!["192.168.68.5".into()],
        }
    }

    /// R4 — the respawn/rebuild split: a lan_ips-only difference is
    /// same-shape (⇒ reattach + in-place plane rebuild, never a second
    /// runtime), while any process-immutable field difference is not
    /// (⇒ the old fresh-spawn path).
    #[test]
    fn lan_ips_change_is_same_shape_immutable_fields_are_not() {
        let a = base();
        let mut roamed = base();
        roamed.lan_ips = vec!["10.20.30.40".into()];
        assert!(a.same_shape(&roamed), "a roam must not respawn the runtime");
        assert!(a != roamed, "but it is still a fingerprint difference");

        for mutate in [
            |f: &mut RuntimeFingerprint| f.wg_public_key = "other".into(),
            |f: &mut RuntimeFingerprint| f.netstack_port = Some(1080),
            |f: &mut RuntimeFingerprint| f.advertised_routes = vec![],
            |f: &mut RuntimeFingerprint| f.exit_node = Some("exit".into()),
            |f: &mut RuntimeFingerprint| f.tenant_id = "t2".into(),
            |f: &mut RuntimeFingerprint| f.server_url = "https://other".into(),
        ] {
            let mut m = base();
            mutate(&mut m);
            assert!(
                !a.same_shape(&m),
                "an immutable-field change must force a respawn"
            );
        }
    }
}

#[cfg(all(test, feature = "overlay-netstack"))]
mod netstack_claim_tests {
    use super::{claim_socks_port, ns_handle_tx, release_netstack};

    /// Each org gets its OWN netstack handle channel.
    ///
    /// This was one shared channel, and that was the bug: a second org
    /// publishing its stack did not join twice, it REPLACED the first org's
    /// under a SOCKS front that kept answering on the same port, so a caller
    /// dialing for org A was routed by org B.
    #[test]
    fn every_org_reads_its_own_stack() {
        let a = ns_handle_tx("org-a");
        let b = ns_handle_tx("org-b");
        assert!(
            !a.same_channel(&b),
            "two orgs must never share a stack handle"
        );
        assert!(
            a.same_channel(&ns_handle_tx("org-a")),
            "an org's channel survives its reconnects — the front stays subscribed"
        );
    }

    /// A loopback SOCKS port is one TCP listener, so it still has exactly
    /// one owner even though the stacks are now separate.
    #[test]
    fn a_socks_port_still_has_exactly_one_owner() {
        // Serialized in ONE test on purpose: the claim map is process-global,
        // so separate #[test] fns would race each other. Ports are unique to
        // this test for the same reason.
        assert!(claim_socks_port("org-a", 41080), "first org in binds it");
        assert!(
            claim_socks_port("org-a", 41080),
            "re-claim by the owner is a no-op — every reconnect does this"
        );
        assert!(
            !claim_socks_port("org-b", 41080),
            "a second org on the same port is refused, not served"
        );

        // Different ports are the whole point: both orgs get a mesh.
        assert!(
            claim_socks_port("org-b", 41081),
            "its own port is always available"
        );

        // Releasing frees only the leaver's ports.
        release_netstack("org-b");
        assert!(
            !claim_socks_port("org-c", 41080),
            "org-a still holds its own"
        );
        assert!(claim_socks_port("org-c", 41081), "org-b's is free again");

        release_netstack("org-a");
        release_netstack("org-c");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// FR-47 — the last join the server refused
// ───────────────────────────────────────────────────────────────────────────

/// The most recent [`ServerMsg::OverlayJoinRefused`], for `roomler status`.
///
/// A process-global rather than runtime state, and deliberately so: a refusal
/// means the overlay runtime never came up, so there is no runtime to hold it.
/// Same shape as the netcheck and netstate slots the status assembly already
/// reads for HOST-level facts.
static LAST_JOIN_REFUSAL: std::sync::Mutex<Option<localapi::JoinRefusalStatus>> =
    std::sync::Mutex::new(None);

/// Record a refusal. Last-writer-wins: the newest reason is the actionable one.
pub fn record_join_refusal(reason: signaling::OverlayJoinRefusal, detail: &str) {
    let status = localapi::JoinRefusalStatus {
        reason: serde_json::to_value(reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            // A tag that will not serialise is not worth losing the whole
            // report over — the detail string still carries the specifics.
            .unwrap_or_else(|| "unknown".to_string()),
        detail: detail.to_string(),
        at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        retryable: reason.is_retryable(),
    };
    if let Ok(mut slot) = LAST_JOIN_REFUSAL.lock() {
        *slot = Some(status);
    }
}

/// The last refusal, if this daemon has seen one.
pub fn last_join_refusal() -> Option<localapi::JoinRefusalStatus> {
    LAST_JOIN_REFUSAL.lock().ok().and_then(|s| s.clone())
}

#[cfg(test)]
mod org_relay_discovery_dispatch_tests {
    use super::*;
    #[tokio::test]
    async fn org_relay_discovery_old_netmap_capability_is_forwarded_as_false() {
        let (tx, mut rx) = mpsc::channel(2);
        let msg: ServerMsg = serde_json::from_value(serde_json::json!({
            "t":"rc:overlay.netmap", "self_ip":"100.64.0.1",
            "network":{"cidr":"100.64.0.0/10","mtu":1280}, "peers":[]
        }))
        .unwrap();
        assert!(intercept(&tx, msg, true).is_none());
        assert!(matches!(
            rx.try_recv(),
            Ok(OverlayEvent::Netmap {
                org_relay_discovery: false,
                ..
            })
        ));
    }
    #[tokio::test]
    async fn org_relay_discovery_signaling_candidates_reach_runtime_only_on_primary_org() {
        let (tx, mut rx) = mpsc::channel(4);
        let peer_node_id = bson::oid::ObjectId::new();
        let msg = || ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id,
            request_id: 17,
            candidates: vec![],
            ttl_secs: 0,
            next_cursor: None,
        };
        assert!(intercept(&tx, msg(), false).is_none());
        assert!(rx.try_recv().is_err());
        assert!(intercept(&tx, msg(), true).is_none());
        assert!(
            matches!(rx.try_recv(), Ok(OverlayEvent::OrgRelayCandidates {
            peer_node_id: id, request_id: 17, ttl_secs: 0, candidates, ..
        }) if id == peer_node_id && candidates.is_empty())
        );
        assert!(rx.try_recv().is_err()); // no serving/session/TURN action
    }
}
