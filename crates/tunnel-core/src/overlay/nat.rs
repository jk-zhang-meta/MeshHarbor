// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Phase 1 subnet-router forwarding + NAT.
//!
//! When a node advertises subnet routes, it must **forward** overlay→LAN traffic
//! and **masquerade** it so LAN hosts reply to the router itself (zero LAN-side
//! config — Tailscale's default). This module enables IP forwarding + NAT scoped
//! to the overlay CIDR at startup and reverts it on `Drop` (mirroring the WFP
//! guard's cleanup pattern).
//!
//! Best-effort: every command failure is logged, never fatal — a node that can't
//! set up NAT simply doesn't route (peers just can't reach its LAN). The agent
//! runs as a privileged service, so it has the rights.
//!
//! - **Linux:** `sysctl net.ipv4.ip_forward=1` + `iptables -t nat -A POSTROUTING
//!   -s <overlay-cidr> -j MASQUERADE`, plus `filter`/`FORWARD` ACCEPT rules for
//!   the overlay interface — container hosts (Docker/containerd, the k8s fleet)
//!   default the `FORWARD` chain policy to DROP, which silently swallows
//!   forwarded packets despite `ip_forward=1` (P5/A4).
//! - **Windows:** `Set-NetIPInterface -Forwarding Enabled` on the overlay NIC +
//!   **WinNAT** `New-NetNat -InternalIPInterfaceAddressPrefix <overlay-cidr>` —
//!   the modern, scriptable, no-reboot NAT engine (Win10 1607+/Server 2016+),
//!   the same one Docker/WSL2 use. Skipped when an overlapping `Get-NetNat`
//!   already exists (WinNAT rejects overlapping internal prefixes).
//! - **macOS (FR-97 P1b):** pf, in our own anchor under the stock
//!   `com.apple/*` wildcard, enabled with a `pfctl -E` reference token, and
//!   `net.inet.ip.forwarding` put back as found: see [`super::pf`].
//! - Other platforms: no-op.
//!
//! Only the *advertising* node needs this; clients of a subnet route need just
//! the route + router-table entry (no NAT).

#[allow(unused_imports)]
use tracing::{info, warn};

/// WinNAT instance name (Windows only).
#[cfg(target_os = "windows")]
const NAT_NAME: &str = "roomler-overlay";

/// RAII guard for the OS forwarding/NAT state. `Drop` reverts whatever `enable`
/// installed. A guard with `active == false` (nothing advertised, or setup
/// failed) is an inert no-op.
pub struct SubnetRouterGuard {
    /// Multi-org v2 — the overlay adapter these rules were scoped to (the
    /// `Drop` revert must name the SAME device the setup did).
    if_name: String,
    /// FR-47 P5e — EVERY block of the org's address space, not just the one
    /// this node is addressed in.
    ///
    /// A subnet router masquerades traffic *sourced from the overlay* out its
    /// uplink. Under multi-block a peer in block 1 reaching a LAN behind a
    /// router in block 0 is still overlay-sourced, and NATing only block 0
    /// would let its packets out un-masqueraded — the far side would reply to
    /// an address it cannot route to, and the flow would black-hole one way.
    ///
    /// One entry for every network that has not grown, which issues exactly
    /// the commands the single-CIDR version did.
    overlay_cidrs: Vec<String>,
    active: bool,
    /// FR-97 P0b-2b — the interfaces whose IPv4 forwarding this router relies
    /// on, as `setup` found them; `Drop` releases each, and the last holder of
    /// an interface we turned on switches it back off.
    #[cfg(target_os = "windows")]
    forwarding: Vec<super::host_ledger::FwdTarget>,
    /// FR-97 P1b — the pf serve `Drop` stops: our anchor, our pf references,
    /// and forwarding as found.
    #[cfg(target_os = "macos")]
    pf: Option<super::pf::Serve>,
}

/// FR-97 P0b-2b — this process's forwarding holds, shared by every router
/// guard (one per org): see [`super::host_ledger::ForwardingHolds`].
#[cfg(target_os = "windows")]
static FORWARDING: std::sync::Mutex<super::host_ledger::ForwardingHolds> =
    std::sync::Mutex::new(super::host_ledger::ForwardingHolds::new());

/// Enable forwarding + NAT for `overlay_cidr` when `advertised_routes` is
/// non-empty. Returns a guard that reverts on `Drop`. A no-op (inert guard) when
/// nothing is advertised or the platform is unsupported.
///
/// Multi-org v2 — `if_name` is the overlay adapter to scope the rules to
/// (formerly a module-level constant): per-org adapters must NAT/forward
/// THEIR device, not the historical singleton. Legacy callers pass the
/// device's own OS name, falling back to
/// [`tun::IF_NAME`](crate::overlay::tun::IF_NAME).
pub async fn enable(
    if_name: &str,
    overlay_cidrs: &[String],
    advertised_routes: &[String],
) -> SubnetRouterGuard {
    if advertised_routes.is_empty() {
        return SubnetRouterGuard {
            if_name: if_name.to_string(),
            overlay_cidrs: overlay_cidrs.to_vec(),
            active: false,
            #[cfg(target_os = "windows")]
            forwarding: Vec::new(),
            #[cfg(target_os = "macos")]
            pf: None,
        };
    }
    #[cfg(target_os = "windows")]
    let (fully_ok, forwarding) = setup(if_name, overlay_cidrs, advertised_routes).await;
    #[cfg(target_os = "macos")]
    let (fully_ok, pf) = super::pf::serve(if_name, overlay_cidrs).await;
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let fully_ok = setup(if_name, overlay_cidrs, advertised_routes).await;
    // Arm the guard on any platform where `setup` installs rules, so `Drop`
    // reverts even a PARTIALLY-applied ruleset (each `-D` / `Remove-NetNat` is
    // idempotent — reverting an absent rule is a harmless no-op). `fully_ok`
    // only drives the log level. Previously `active = setup()`, which leaked the
    // rules that DID apply whenever one of the (now multiple, P5/A4) commands
    // failed. macOS: armed whenever a serve exists to stop.
    #[cfg(target_os = "macos")]
    let active = pf.is_some();
    #[cfg(not(target_os = "macos"))]
    let active = cfg!(any(target_os = "linux", target_os = "windows"));
    if active && fully_ok {
        info!(%if_name, cidrs = ?overlay_cidrs, routes = ?advertised_routes,
            "overlay: subnet-router forwarding + NAT enabled");
    } else if active {
        warn!(%if_name, cidrs = ?overlay_cidrs,
            "overlay: subnet-router forwarding/NAT not fully enabled (see prior errors)");
    }
    SubnetRouterGuard {
        if_name: if_name.to_string(),
        overlay_cidrs: overlay_cidrs.to_vec(),
        active,
        #[cfg(target_os = "windows")]
        forwarding,
        #[cfg(target_os = "macos")]
        pf,
    }
}

/// FR-97 P0b — what a node offers its peers: every route it was configured
/// to advertise, or none, with the reason it cannot serve them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOffer {
    pub routes: Vec<String>,
    pub withheld: Option<String>,
}

/// FR-97 P0b — offer `/0` and subnet routes only where this host can forward
/// and NAT for the overlay.
///
/// [`enable`] runs after the join, because it needs the netmap's address
/// space, so a node used to offer whatever it was configured to and find out
/// afterwards whether it could serve it. Where it could not, an admin could
/// approve the offer and every client that took it black-holed: a Mac, which
/// has no NAT arm at all, and a Windows Home PC, which ships the `winnat`
/// service without its management class (#2077). This asks first, so such a
/// node advertises nothing and says why: in `meshharbor status`, and in its join.
///
/// `ROOMLERD_ROUTE_OFFER_UNPROBED=1` skips the probe and offers as before.
///
/// FR-97 P0c-3 — `netstack`: this node's device is the userspace netstack,
/// which offers nothing whatever the host's NAT could do ([`netstack_offer`]).
pub async fn gate_offer(advertised: Vec<String>, netstack: bool) -> RouteOffer {
    if let Some(offer) = netstack_offer(&advertised, netstack) {
        return offer;
    }
    // Through the node env chain like every other knob, so the config-backed
    // fallback and the older prefix are honoured too.
    let unprobed = crate::env::flag("ROUTE_OFFER_UNPROBED", false);
    gate_offer_with(advertised, unprobed, probe()).await
}

/// FR-97 P0c-3 — why a netstack node offers no route.
pub const NETSTACK_FORWARDS_NOTHING: &str =
    "this node runs the userspace netstack, which forwards nothing for its peers";

/// FR-97 P0c-3 — a netstack node terminates every packet addressed to it in
/// its own userspace stack and forwards none, so a `/0` or a subnet it
/// advertised would black-hole every peer that took it, however well the
/// host's own NAT works. A certainty rather than a probe, so
/// `ROUTE_OFFER_UNPROBED` does not lift it. `None` = not netstack, or nothing
/// to offer: the probe decides. Pure.
fn netstack_offer(advertised: &[String], netstack: bool) -> Option<RouteOffer> {
    (netstack && !advertised.is_empty()).then(|| RouteOffer {
        routes: Vec::new(),
        withheld: Some(NETSTACK_FORWARDS_NOTHING.to_string()),
    })
}

async fn gate_offer_with(
    advertised: Vec<String>,
    unprobed: bool,
    probe: impl std::future::Future<Output = Result<(), String>>,
) -> RouteOffer {
    if advertised.is_empty() || unprobed {
        return RouteOffer {
            routes: advertised,
            withheld: None,
        };
    }
    match probe.await {
        Ok(()) => RouteOffer {
            routes: advertised,
            withheld: None,
        },
        Err(why) => RouteOffer {
            routes: Vec::new(),
            withheld: Some(why),
        },
    }
}

/// Can this host forward and NAT for the overlay? `Err` says why not.
#[cfg(target_os = "linux")]
async fn probe() -> Result<(), String> {
    // `setup` writes its MASQUERADE and FORWARD rules with iptables, so a host
    // where iptables cannot use the nat table (no binary, not root, no
    // NET_ADMIN in a container) cannot serve. A per-user daemon is the common
    // case.
    probe_cmd(&["iptables", "-t", "nat", "-S", "POSTROUTING"])
        .await
        .map_err(|e| {
            format!(
                "iptables cannot use the nat table ({e}), so this host cannot forward or NAT \
                 for its peers"
            )
        })
}

/// Can this host forward and NAT for the overlay? `Err` says why not.
#[cfg(target_os = "windows")]
async fn probe() -> Result<(), String> {
    // `setup` creates a WinNAT instance. The class that manages WinNAT comes
    // with the Hyper-V feature, not with the edition: Windows Home cannot
    // install Hyper-V (`Invalid class`), and Pro or Enterprise without it
    // answer `Not found` too. FR-97 field, a Windows 11 Enterprise eval VM:
    // absent with Hyper-V and Containers off, still absent with Containers
    // on, present once Hyper-V was enabled.
    probe_cmd(&[
        "powershell",
        "-NoProfile",
        "-Command",
        "try { Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_NetNat \
         -ErrorAction Stop | Out-Null; exit 0 } \
         catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }",
    ])
    .await
    .map_err(|e| {
        format!(
            "WinNAT is not available ({e}): Windows provides it with the Hyper-V feature, \
             which Windows Home cannot install and Pro or Enterprise leave off by default, \
             so this device cannot be an exit node or a subnet router"
        )
    })
}

/// Can this Mac forward and NAT for the overlay? `Err` says why not: the
/// kill switch, a pf this daemon cannot drive (a per-user daemon), or a main
/// ruleset that does not evaluate `com.apple/*` (FR-97 P1b).
#[cfg(target_os = "macos")]
async fn probe() -> Result<(), String> {
    tokio::task::spawn_blocking(super::pf::probe)
        .await
        .unwrap_or_else(|e| Err(format!("the probe task failed: {e}")))
}

/// Can this host forward and NAT for the overlay? Not on this platform.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn probe() -> Result<(), String> {
    Err(
        "this platform has no NAT for the overlay, so it cannot be an exit node or a \
         subnet router"
            .into(),
    )
}

/// Run a probe off the reactor, hidden on Windows. `Err` carries the first
/// line of its stderr (bounded: it travels into the status and the join).
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn probe_cmd(args: &[&str]) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(&args[0]);
        cmd.args(&args[1..]);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        match cmd.output() {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stderr);
                let line = text.lines().map(str::trim).find(|l| !l.is_empty());
                Err(match line {
                    Some(l) => l.chars().take(200).collect(),
                    None => format!("{} exited with {}", args[0], o.status),
                })
            }
            Err(e) => Err(format!("{} could not start: {e}", args[0])),
        }
    })
    .await
    .unwrap_or_else(|e| Err(format!("the probe task failed: {e}")))
}

#[cfg(target_os = "linux")]
async fn setup(if_name: &str, overlay_cidrs: &[String], _advertised_routes: &[String]) -> bool {
    // Global forwarding (leave it on at teardown — another service may rely on
    // it; we only remove our own rules).
    let _ = run(vec![
        "sysctl".into(),
        "-w".into(),
        "net.ipv4.ip_forward=1".into(),
    ])
    .await;
    // NAT: masquerade overlay-sourced traffic out the host's uplink so the far
    // side replies to the router itself (zero peer-side config).
    //
    // FR-47 P5e — one rule per BLOCK. A single-block org issues exactly the one
    // command this used to, so the live subnet-router path is unchanged; a
    // grown org gets a rule for each of its ranges, because a peer in block 1
    // is just as overlay-sourced as one in block 0.
    let mut nat_ok = true;
    for cidr in overlay_cidrs {
        nat_ok &= run(vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "POSTROUTING".into(),
            "-s".into(),
            cidr.into(),
            "-j".into(),
            "MASQUERADE".into(),
        ])
        .await;
    }
    // filter/FORWARD ACCEPT (P5/A4): container hosts (Docker/containerd — the
    // k8s fleet buildhost/fleet-host-1/fleet-host-2) default the FORWARD chain policy to DROP, so
    // `ip_forward=1` + NAT alone silently drop forwarded packets. Explicitly
    // accept overlay→uplink and the established return path. Needed by BOTH
    // subnet-routers and exit nodes; the subnet-router path only ever "worked"
    // on LANs whose upstream router had a permissive FORWARD policy.
    let fwd_out_ok = run(vec![
        "iptables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-i".into(),
        if_name.into(),
        "-j".into(),
        "ACCEPT".into(),
    ])
    .await;
    let fwd_ret_ok = run(vec![
        "iptables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-o".into(),
        if_name.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ])
    .await;
    // P5/S3b — IPv6 exit egress (best-effort; independent of the v4 result so a
    // v4-only-uplink exit still reports v4 success). Clients keep v6 fail-closed
    // until this succeeds on the exit.
    setup_v6(if_name).await;
    nat_ok && fwd_out_ok && fwd_ret_ok
}

/// P5/S3b — enable IPv6 forwarding + MASQUERADE on an exit node (Linux). Best-
/// effort + logged independently of v4: a v4-only uplink (no v6, no `ip6tables`)
/// simply leaves v6 egress unavailable, and clients then stay v6-fail-closed.
#[cfg(target_os = "linux")]
async fn setup_v6(if_name: &str) {
    // Enable v6 forwarding. `accept_ra=2` so a host that forwards STILL accepts
    // Router Advertisements — otherwise `forwarding=1` downgrades RA acceptance
    // and a SLAAC/RA-configured uplink loses its OWN v6 default on the next RA,
    // killing the egress this NAT depends on (v4's `ip_forward` has no such
    // coupling). A static-v6 uplink is unaffected (no RA to lose). Leave both
    // sysctls on at teardown — another service may rely on them.
    let _ = run(vec![
        "sysctl".into(),
        "-w".into(),
        "net.ipv6.conf.all.forwarding=1".into(),
    ])
    .await;
    let _ = run(vec![
        "sysctl".into(),
        "-w".into(),
        "net.ipv6.conf.all.accept_ra=2".into(),
    ])
    .await;
    // MASQUERADE overlay-sourced v6 out the uplink. Source is the derived-v6
    // `/96` ([`OVERLAY_ULA_V6_CIDR`]) — exactly the on-link prefix, so it can't
    // over-broadly NAT a co-located non-overlay ULA (Docker/WSL2/other VPN).
    let nat6_ok = run(vec![
        "ip6tables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        "POSTROUTING".into(),
        "-s".into(),
        super::router::OVERLAY_ULA_V6_CIDR.into(),
        "-j".into(),
        "MASQUERADE".into(),
    ])
    .await;
    let fwd6_out_ok = run(vec![
        "ip6tables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-i".into(),
        if_name.into(),
        "-j".into(),
        "ACCEPT".into(),
    ])
    .await;
    let fwd6_ret_ok = run(vec![
        "ip6tables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-o".into(),
        if_name.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ])
    .await;
    if nat6_ok && fwd6_out_ok && fwd6_ret_ok {
        info!("overlay: exit-node IPv6 forwarding + NAT enabled");
    } else {
        info!(
            "overlay: IPv6 exit NAT not fully enabled (v4-only uplink / no ip6tables?) — \
             clients routing through this exit stay v6-fail-closed"
        );
    }
}

#[cfg(target_os = "windows")]
async fn setup(
    if_name: &str,
    overlay_cidrs: &[String],
    advertised_routes: &[String],
) -> (bool, Vec<super::host_ledger::FwdTarget>) {
    // P5/S3b — WinNAT (`New-NetNat`) has NO IPv6 API, so a Windows exit node
    // cannot NAT v6. Clients routing through a Windows exit stay v6-fail-closed
    // (their global v6 is encapsulated but dropped here — never leaked). v6 exit
    // egress is Linux's (ip6tables) and macOS's (pf NAT66, FR-97 P1b).
    info!(
        "overlay: IPv6 exit NAT unavailable on Windows (WinNAT is v4-only); v6 stays fail-closed"
    );
    // Forwarding on the overlay NIC **and on the EGRESS NIC for each advertised
    // route**.
    //
    // The previous version enabled only `roomler`, on the assumption that "the
    // LAN adapter's forwarding is normally already on". That is FALSE on
    // Windows: every interface ships `Forwarding: Disabled`, and Windows only
    // forwards a packet when forwarding is enabled on BOTH the ingress and the
    // egress interface. So the subnet router accepted overlay packets and then
    // silently dropped them — peers had the OS route installed and every TCP
    // connection still timed out.
    //
    // Field-diagnosed on winhost-a 2026-08-03: `roomler` Enabled, every other NIC
    // Disabled, `Get-NetNat` healthy — the subnet router had been dead for a
    // week while the agent logged "forwarding + NAT enabled".
    //
    // The egress NIC is DERIVED PER ROUTE via `Find-NetRoute` rather than
    // hardcoded to Ethernet/Wi-Fi: a corp route is very often carried by a VPN
    // adapter (Check Point / AnyConnect WAN miniports), which is exactly the
    // deployment a subnet router exists for. Only the interfaces that actually
    // carry an advertised route are touched — still far short of "enable every
    // interface".
    //
    // The script VERIFIES the resulting state and exits non-zero on failure,
    // because `run` can only observe the PowerShell process exit code and
    // `-ErrorAction SilentlyContinue` would otherwise report success for a
    // cmdlet that never applied.
    //
    // FR-97 P0b-2b — it also reports, per interface, the adapter GUID and the
    // forwarding state it FOUND (`FWD <guid> <ifIndex> <before>`), so the
    // revert can switch off exactly what this turned on (#2077, defect 2: it
    // used to leave every interface forwarding after the router stopped).
    let targets = advertised_routes
        .iter()
        .map(|c| format!("'{}'", c.trim().replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");
    // Multi-org v2 — the overlay NIC is the INSTANCE adapter, not the
    // historical `roomler` literal. Quote-sanitized like `targets` (the name
    // comes from our own constants/config, but a `'` must never break out).
    let alias = if_name.trim().replace('\'', "");
    let (fwd_ok, report) = run_capture(vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "$fail = 0; $idx = @(); \
             $o = Get-NetIPInterface -InterfaceAlias '{alias}' -AddressFamily IPv4 \
               -ErrorAction SilentlyContinue | Select-Object -First 1; \
             if ($o) {{ $idx += $o.ifIndex }} else {{ $fail = 1 }}; \
             foreach ($c in @({targets})) {{ \
               $ip = ($c -split '/')[0]; \
               $r = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | \
                 Select-Object -First 1; \
               if ($r) {{ $idx += $r.InterfaceIndex }} \
             }}; \
             foreach ($i in ($idx | Select-Object -Unique)) {{ \
               $before = (Get-NetIPInterface -ifIndex $i -AddressFamily IPv4 \
                 -ErrorAction SilentlyContinue | Select-Object -First 1).Forwarding; \
               $g = (Get-NetAdapter -InterfaceIndex $i -IncludeHidden \
                 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceGuid; \
               if (-not $g) {{ $g = '-' }}; \
               Set-NetIPInterface -ifIndex $i -AddressFamily IPv4 \
                 -Forwarding Enabled -ErrorAction SilentlyContinue; \
               if ((Get-NetIPInterface -ifIndex $i -AddressFamily IPv4 \
                 -ErrorAction SilentlyContinue | Select-Object -First 1).Forwarding \
                 -ne 'Enabled') {{ $fail = 1 }}; \
               Write-Output ('FWD ' + $g + ' ' + $i + ' ' + $before) \
             }}; \
             exit $fail"
        ),
    ])
    .await;
    // Hold every interface the script touched, whether or not it ended up
    // Enabled: a partial setup still needs its partial revert.
    let forwarding = super::host_ledger::parse_forwarding_report(&report);
    {
        let mut holds = FORWARDING.lock().unwrap_or_else(|e| e.into_inner());
        for t in &forwarding {
            holds.hold(t);
        }
        super::host_ledger::record_forwarding(holds.forwarding_guids());
    }
    if !fwd_ok {
        warn!(
            "overlay: could not enable IPv4 forwarding on the overlay NIC and/or an \
             advertised route's egress NIC — the subnet router will accept packets and \
             drop them. Check `Get-NetIPInterface | ft ifIndex,InterfaceAlias,Forwarding`."
        );
    }
    // Create the NAT only if no existing WinNAT covers this prefix (Docker
    // Desktop / WSL2 also use WinNAT and overlapping prefixes are rejected).
    //
    // FR-47 P5e — one WinNAT per BLOCK, because a WinNAT instance carries
    // exactly one internal prefix. The FIRST block keeps the historical
    // unsuffixed name, so a single-block org creates the identical instance it
    // always did (and an upgrade finds its own NAT rather than orphaning one);
    // later blocks are suffixed by index.
    let mut ok = true;
    let names = nat_names(overlay_cidrs.len());
    for (cidr, name) in overlay_cidrs.iter().zip(&names) {
        // FR-97 P0b-2b — `-ErrorAction Stop` and the message on stderr, so
        // `run` logs WHY WinNAT refused (an overlapping prefix from Docker
        // or WSL, a missing class) rather than a bare failure.
        ok &= run(vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!(
                "if (-not (Get-NetNat -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.InternalIPInterfaceAddressPrefix -eq '{cidr}' }})) {{ \
                 try {{ New-NetNat -Name {name} \
                   -InternalIPInterfaceAddressPrefix '{cidr}' -ErrorAction Stop | Out-Null }} \
                 catch {{ [Console]::Error.WriteLine('New-NetNat {name}: ' + \
                   $_.Exception.Message); exit 1 }} }}"
            ),
        ])
        .await;
    }
    // FR-97 P0b-2c — recorded, so the boot purge removes them after a crash.
    // Every name of ours, created now or found from an earlier run: only an
    // instance with OUR name is ever removed, never the one Docker or WSL
    // made for the same prefix.
    super::host_ledger::record_nat(&names);
    (ok, forwarding)
}

/// The WinNAT instance names for `blocks` overlay blocks: the historical
/// unsuffixed name first, later blocks suffixed by index (FR-47 P5e).
#[cfg(target_os = "windows")]
fn nat_names(blocks: usize) -> Vec<String> {
    (0..blocks.max(1))
        .map(|i| {
            if i == 0 {
                NAT_NAME.to_string()
            } else {
                format!("{NAT_NAME}-{i}")
            }
        })
        .collect()
}

/// FR-97 P0b-2c — the WinNAT half of [`super::host_ledger::purge`]: remove
/// the instances a router of ours left (by name, and only names like ours).
/// No-op off Windows, and for an empty list.
pub(crate) fn remove_nat_instances(names: &[String]) {
    #[cfg(target_os = "windows")]
    {
        let names: Vec<String> = names
            .iter()
            .filter(|n| super::host_ledger::is_nat_name(n))
            .map(|n| format!("'{n}'"))
            .collect();
        if names.is_empty() {
            return;
        }
        warn!(
            instances = ?names,
            "overlay: a router left its WinNAT instance (an exit that skipped its revert) — \
             removing it"
        );
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "foreach ($n in @({})) {{ Remove-NetNat -Name $n -Confirm:$false \
                     -ErrorAction SilentlyContinue }}",
                    names.join(",")
                ),
            ])
            .output();
    }
    #[cfg(not(target_os = "windows"))]
    let _ = names;
}

/// FR-97 P0b-2b — switch IPv4 forwarding back off on the given interfaces:
/// GUID identities through their adapter, `if:` ones by index. Synchronous,
/// because `Drop` and the boot purge both call it with no runtime. Also the
/// adapter bring-up's (P0b-2c), for an adapter that came up forwarding.
#[cfg(target_os = "windows")]
pub(crate) fn restore_forwarding(identities: &[String]) {
    let guids: Vec<String> = identities
        .iter()
        .filter_map(|id| id.strip_prefix("guid:"))
        .filter(|g| super::host_ledger::is_guid(g))
        .map(|g| format!("'{g}'"))
        .collect();
    let indexes: Vec<String> = identities
        .iter()
        .filter_map(|id| id.strip_prefix("if:"))
        .filter_map(|i| i.parse::<u32>().ok())
        .map(|i| i.to_string())
        .collect();
    if guids.is_empty() && indexes.is_empty() {
        return;
    }
    let script = format!(
        "foreach ($g in @({guids})) {{ \
           $a = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.InterfaceGuid -eq $g }} | Select-Object -First 1; \
           if ($a) {{ Set-NetIPInterface -ifIndex $a.ifIndex -AddressFamily IPv4 \
             -Forwarding Disabled -ErrorAction SilentlyContinue }} \
         }}; \
         foreach ($i in @({indexes})) {{ \
           Set-NetIPInterface -ifIndex $i -AddressFamily IPv4 -Forwarding Disabled \
             -ErrorAction SilentlyContinue \
         }}",
        guids = guids.join(","),
        indexes = indexes.join(","),
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output();
    info!(
        interfaces = identities.len(),
        "overlay: IPv4 forwarding switched back off where the router had turned it on"
    );
}

/// FR-97 P0b-2b — the forwarding half of [`super::host_ledger::purge`]:
/// switch forwarding back off on every adapter (by GUID) the ledger says a
/// run turned on and never released. No-op off Windows, and for an empty
/// list.
pub(crate) fn restore_forwarding_guids(guids: &[String]) {
    #[cfg(target_os = "windows")]
    {
        if guids.is_empty() {
            return;
        }
        let ids: Vec<String> = guids.iter().map(|g| format!("guid:{g}")).collect();
        warn!(
            adapters = ?guids,
            "overlay: a router left IPv4 forwarding on (an exit that skipped its revert) — \
             switching it back off"
        );
        restore_forwarding(&ids);
    }
    #[cfg(not(target_os = "windows"))]
    let _ = guids;
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn setup(_if_name: &str, _overlay_cidrs: &[String], _advertised_routes: &[String]) -> bool {
    false
}

impl Drop for SubnetRouterGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // FR-97 P1b — the anchor, the pf tokens, then forwarding as found.
        #[cfg(target_os = "macos")]
        if let Some(serve) = self.pf.take() {
            serve.stop();
        }
        // `Drop` can't await — revert synchronously via blocking `Command`.
        #[cfg(target_os = "linux")]
        {
            // FR-47 P5e — one `-D` per block, mirroring `setup`'s one `-A` per
            // block. Deleting a rule that is not there is a harmless no-op, so
            // a partially-applied ruleset still reverts cleanly.
            for cidr in &self.overlay_cidrs {
                let _ = std::process::Command::new("iptables")
                    .args([
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        cidr,
                        "-j",
                        "MASQUERADE",
                    ])
                    .output();
            }
            // Mirror the P5/A4 FORWARD ACCEPT rules from `setup`.
            let _ = std::process::Command::new("iptables")
                .args(["-D", "FORWARD", "-i", &self.if_name, "-j", "ACCEPT"])
                .output();
            let _ = std::process::Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-o",
                    &self.if_name,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .output();
            // P5/S3b — mirror the v6 rules from `setup_v6` (idempotent `-D`;
            // reverting an absent rule on a v4-only exit is a harmless no-op). The
            // forwarding/accept_ra sysctls are left on, like v4's `ip_forward`.
            let _ = std::process::Command::new("ip6tables")
                .args([
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    super::router::OVERLAY_ULA_V6_CIDR,
                    "-j",
                    "MASQUERADE",
                ])
                .output();
            let _ = std::process::Command::new("ip6tables")
                .args(["-D", "FORWARD", "-i", &self.if_name, "-j", "ACCEPT"])
                .output();
            let _ = std::process::Command::new("ip6tables")
                .args([
                    "-D",
                    "FORWARD",
                    "-o",
                    &self.if_name,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .output();
        }
        #[cfg(target_os = "windows")]
        {
            // FR-47 P5e — remove one instance per block, matching `setup`'s
            // naming (first unsuffixed, later ones `-1`, `-2`, …). Removing an
            // absent NAT is a no-op, so a partial setup still reverts.
            let names = nat_names(self.overlay_cidrs.len());
            for name in &names {
                let _ = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!(
                            "Remove-NetNat -Name {name} -Confirm:$false \
                             -ErrorAction SilentlyContinue"
                        ),
                    ])
                    .output();
            }
            // FR-97 P0b-2c — gone, so the boot purge has none to remove.
            super::host_ledger::forget_nat(&names);
            // FR-97 P0b-2b — then forwarding: this router's holds go, and the
            // last holder of an interface we turned on switches it back off
            // (#2077, defect 2). The ledger follows, so a crash after this
            // point has nothing left to restore.
            let restore: Vec<String> = {
                let mut holds = FORWARDING.lock().unwrap_or_else(|e| e.into_inner());
                let ids = self
                    .forwarding
                    .iter()
                    .filter(|t| holds.release(&t.identity))
                    .map(|t| t.identity.clone())
                    .collect();
                super::host_ledger::record_forwarding(holds.forwarding_guids());
                ids
            };
            restore_forwarding(&restore);
        }
        info!(
            if_name = %self.if_name,
            overlay_cidrs = ?self.overlay_cidrs,
            "overlay: subnet-router forwarding/NAT reverted"
        );
    }
}

/// Run an OS command off the async reactor (`std::process` in a blocking task —
/// avoids tokio's `process` feature). `true` on exit 0, else logs stderr.
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn run(args: Vec<String>) -> bool {
    tokio::task::spawn_blocking(move || {
        let prog = args[0].clone();
        match std::process::Command::new(&prog).args(&args[1..]).output() {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                warn!(%prog, stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "overlay: subnet-router command failed");
                false
            }
            Err(e) => {
                warn!(%prog, %e, "overlay: subnet-router command spawn failed");
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// FR-97 P0b-2b — [`run`], keeping stdout: `(exit 0, stdout)`. The forwarding
/// setup reports what it found on stdout, and a failed run still reports the
/// interfaces it touched, which the revert needs.
#[cfg(target_os = "windows")]
async fn run_capture(args: Vec<String>) -> (bool, String) {
    tokio::task::spawn_blocking(move || {
        let prog = args[0].clone();
        match std::process::Command::new(&prog).args(&args[1..]).output() {
            Ok(o) => {
                if !o.status.success() {
                    warn!(%prog, stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                        "overlay: subnet-router command failed");
                }
                (
                    o.status.success(),
                    String::from_utf8_lossy(&o.stdout).into_owned(),
                )
            }
            Err(e) => {
                warn!(%prog, %e, "overlay: subnet-router command spawn failed");
                (false, String::new())
            }
        }
    })
    .await
    .unwrap_or((false, String::new()))
}

#[cfg(test)]
mod offer_tests {
    use super::{NETSTACK_FORWARDS_NOTHING, RouteOffer, gate_offer_with, netstack_offer};

    /// FR-97 P0c-3 — a netstack node offers nothing it was configured to, and
    /// says why, before any probe; with nothing to offer it says nothing.
    #[test]
    fn a_netstack_node_offers_nothing_and_says_why() {
        assert_eq!(
            netstack_offer(&routes(&["0.0.0.0/0", "10.1.0.0/24"]), true),
            Some(RouteOffer {
                routes: Vec::new(),
                withheld: Some(NETSTACK_FORWARDS_NOTHING.to_string()),
            })
        );
        assert_eq!(netstack_offer(&[], true), None);
        assert_eq!(netstack_offer(&routes(&["0.0.0.0/0"]), false), None);
    }

    fn routes(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| s.to_string()).collect()
    }

    /// A probe that must never run: polling it fails the test.
    async fn never() -> Result<(), String> {
        panic!("probed a node that offers nothing, or with the probe switched off")
    }

    #[tokio::test]
    async fn a_host_that_can_serve_offers_everything_it_advertised() {
        let offer = gate_offer_with(routes(&["10.1.0.0/24", "0.0.0.0/0"]), false, async {
            Ok(())
        })
        .await;
        assert_eq!(
            offer,
            RouteOffer {
                routes: routes(&["10.1.0.0/24", "0.0.0.0/0"]),
                withheld: None
            }
        );
    }

    #[tokio::test]
    async fn a_host_that_cannot_serve_offers_nothing_and_says_why() {
        let offer = gate_offer_with(routes(&["0.0.0.0/0"]), false, async {
            Err("Invalid class".to_string())
        })
        .await;
        assert!(offer.routes.is_empty(), "nothing it cannot serve");
        assert_eq!(offer.withheld.as_deref(), Some("Invalid class"));
    }

    #[tokio::test]
    async fn nothing_to_offer_or_the_probe_switched_off_never_probes() {
        assert_eq!(
            gate_offer_with(Vec::new(), false, never()).await,
            RouteOffer {
                routes: Vec::new(),
                withheld: None
            }
        );
        assert_eq!(
            gate_offer_with(routes(&["0.0.0.0/0"]), true, never()).await,
            RouteOffer {
                routes: routes(&["0.0.0.0/0"]),
                withheld: None
            },
            "ROOMLERD_ROUTE_OFFER_UNPROBED=1 offers as before"
        );
    }

    /// The platform without a NAT arm says so, rather than offering a route
    /// nothing on the host would forward.
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    #[tokio::test]
    async fn a_platform_without_a_nat_arm_withholds() {
        assert!(super::probe().await.is_err());
    }
}
