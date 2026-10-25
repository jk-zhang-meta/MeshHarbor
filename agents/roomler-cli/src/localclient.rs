// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(2): this line EXISTS to explain the retired spelling, so it must
// contain it.
//! `roomler status | peers | flows` — the thin-client read verbs.
//!
//! These connect to the **local** daemon's LocalAPI (the ACL-gated named pipe /
//! unix socket the daemon binds — see `tunnel_core::localapi`) and render its
//! live node / peer / flow state. Purely a *client* of
//! [`tunnel_core::localapi::Client`]: no server, no token, no config — the OS
//! endpoint ACL is the trust boundary. This is the CLI half of the
//! unification's "thin clients over the LocalAPI" story; at the P3d rename
//! `roomler-tunnel <verb>` becomes `roomler <verb>`.
//!
//! Everything below the command handlers is a **pure** formatter (`now_ms` is
//! injected, never read from the clock) so the table rendering is unit-tested
//! with no live daemon.

use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use tunnel_core::localapi::{
    self, ConnectionType, DaemonMode, DeviceRowLite, FlowInfo, FlowKind, NodeStatus, PeerInfo,
    RouteInfo, RouteState, TierWhy,
};

use crate::names::{self, NamedPeer, Need, Resolution};

/// Em-dash for an absent / null field — matches the tray's `devices.js`
/// convention so the two surfaces read the same.
const DASH: &str = "—";

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// `roomler status` — the local node's own state (id, version, mode, overlay
/// IP, server connection). Renders [`NodeStatus`] ONLY: `status --json` is
/// exactly that struct, never a peers fan-out.
pub async fn status(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let status = client.status().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_status(&status);
        print_other_daemon_hint().await;
    }
    Ok(())
}

/// Say so when this host runs a SECOND daemon we did not answer for.
///
/// On macOS the two halves are separate processes on separate sockets, and the
/// unprivileged CLI always reaches the per-user one — which has no overlay. So
/// `status` prints `overlay ip —` and `peers` prints nothing, both perfectly
/// true of the process reached and both read as "the overlay is broken" when
/// the root half is meshed and healthy. Field-hit on a MacBook, 2026-08-24.
///
/// Only printed in human mode: `--json` output is parsed, and a stray line
/// would be a breaking change for anything consuming it.
async fn print_other_daemon_hint() {
    if let Some(other) = localapi::other_daemon_socket().await {
        eprintln!();
        eprintln!(
            "note: a second roomler daemon is running on this host ({}).",
            other.display()
        );
        eprintln!("      This is the per-user half; the overlay runs in the privileged one.");
        eprintln!("      Use `sudo roomler …` to ask that one instead.");
    }
}

/// `roomler logs` — surface the S2 `TailLog` verb on the CLI.
///
/// The verb and the daemon side already existed; without a command in front of
/// them the only way to read a remote agent's log was to guess its path through
/// a shell, and that path is genuinely hard: it depends on whether the process
/// carries a service role and, failing that, on which USER it runs as. A
/// Windows host therefore has three plausible `roomlerd.log*` files and two are
/// decoys — the SCM supervisor's (~30 lines/day, no overlay events) and the
/// updater's (a few KB, written only at update time). On 2026-08-07 that cost a
/// wrong "the agent's logging is dead" conclusion.
///
/// The daemon opened the file, so it is the only thing that reliably knows.
/// Composes with Fleet RPC: `roomler exec <host> -- roomler logs --grep ICE`.
/// The resolved path is always printed — remotely, that IS half the answer.
pub async fn logs(
    source: String,
    max_bytes: Option<u64>,
    grep: Option<String>,
    lines: Option<usize>,
    json: bool,
) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let (path, size, content) = client
        .tail_log(&source, max_bytes)
        .await
        .map_err(daemon_err)?;
    // Filter client-side: the daemon's verb is a byte-bounded tail, and
    // narrowing there would silently change what "the last N bytes" means.
    let body: String = match &grep {
        Some(g) => {
            let needle = g.to_lowercase();
            content
                .lines()
                .filter(|l| l.to_lowercase().contains(&needle))
                .collect::<Vec<_>>()
                .join("\n")
        }
        None => content,
    };
    // `-n` trims AFTER the grep, so `--grep X -n 20` reads as "the last 20
    // matching lines" — same order as a shell `grep X | tail -n 20`.
    let body: String = match lines {
        Some(n) => {
            let all: Vec<&str> = body.lines().collect();
            all[all.len().saturating_sub(n)..].join("\n")
        }
        None => body,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": path, "size": size, "content": body,
            }))?
        );
        return Ok(());
    }
    println!("{path}  ({size} bytes total)");
    if body.is_empty() {
        println!(
            "(no matching lines{})",
            grep.map(|g| format!(" for {g:?}")).unwrap_or_default()
        );
    } else {
        println!("{body}");
    }
    Ok(())
}

/// `roomler netcheck` — the measured capability vector (overlay v3 B4),
/// read from the daemon's status payload. What selection actually keys on,
/// plus how old the measurement is.
pub async fn netcheck(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let status = client.status().await.map_err(daemon_err)?;
    match status.netcheck {
        Some(nc) if json => println!("{}", serde_json::to_string_pretty(&nc)?),
        Some(nc) => {
            let band = match nc.relay_band_udp {
                Some(true) => "reachable",
                Some(false) => "BLOCKED",
                None => "unmeasured",
            };
            println!(
                "stun/udp:        {}",
                if nc.stun_udp { "ok" } else { "NO MAPPING" }
            );
            println!("relay band/udp:  {band}");
            println!(
                "derp floor ws:   {}",
                if nc.derp_ws_ok { "up" } else { "DOWN" }
            );
            println!(
                "nat:             {}",
                nc.nat.as_deref().unwrap_or("untyped")
            );
            println!("measured:        {}s ago (fresh < 3600s)", nc.age_s);
        }
        None if json => println!("null"),
        None => println!(
            "no measurement yet — the daemon probes ~45 s after start (older daemons never do)"
        ),
    }
    Ok(())
}

/// The flags of `roomler peers`.
#[derive(Debug, Clone, Default)]
pub struct PeersArgs {
    /// FR-49 — one enrollment label; `None` = every org.
    pub org: Option<String>,
    /// NAME shows each peer's dashboard display name (the device list joined
    /// in); `--json` gains a `display_name` per peer.
    pub display_name: bool,
    /// Positional filter: mesh names or display names, in output order.
    pub names: Vec<String>,
    pub json: bool,
}

/// `roomler peers` — every peer this node sees, with its live connection type.
///
/// FR-49 — `org` scopes the output to ONE enrollment. Not only ergonomics: on a
/// device in a customer org and a personal one this prints every org's node
/// names together, which makes it unusable on a shared screen or in a bug
/// report. And the orgs are fetched (not just the peers) so that an enrollment
/// with its overlay OFF can be SHOWN as such: it has no peers, so it used to
/// produce no section at all — indistinguishable from an org whose peers merely
/// happen to be offline.
///
/// Display names (`--display-name`, and a `NAME…` filter that may name a
/// device by either name) come from the device list, never from the netmap —
/// `docs/device-naming.md` — so they are a per-org JOIN done here, in the
/// client ([`names::name_peers`]). Without the list (an older daemon, a server
/// that did not answer) the column shows mesh names and one stderr line says
/// so; `--json` is the wire verbatim unless `--display-name` asked for more.
pub async fn peers(args: PeersArgs) -> Result<()> {
    let PeersArgs {
        org,
        display_name,
        names,
        json,
    } = args;
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let peers = client.peers().await.map_err(daemon_err)?;
    let peers: Vec<PeerInfo> = match &org {
        Some(want) => peers.into_iter().filter(|p| &p.org == want).collect(),
        None => peers,
    };
    // A second round trip on a local pipe, for the one thing the peer list
    // cannot say: which enrollments exist but contribute no peers, and why.
    // Human mode only — and BEFORE the name filter, so an unknown `--org` is
    // called that rather than "no peer named".
    let orgs = if json {
        Vec::new()
    } else {
        client
            .status()
            .await
            .map(|s| s.orgs)
            .unwrap_or_default()
            .into_iter()
            .filter(|o| org.as_deref().is_none_or(|w| o.label == w))
            .collect::<Vec<_>>()
    };
    if !json
        && let Some(want) = &org
        && orgs.is_empty()
        && peers.is_empty()
    {
        println!("No enrollment labelled {want:?} — see `roomlerd org ls`.");
        return Ok(());
    }
    // The device list of each org on screen, for the column and for the
    // filter alike — a filter argument may be a display name too.
    let rows_by_org = if (display_name || !names.is_empty()) && !peers.is_empty() {
        device_lists_for(&mut client, &peers).await
    } else {
        HashMap::new()
    };
    let named = names::name_peers(&peers, &rows_by_org);
    let named = if names.is_empty() {
        named
    } else {
        let (kept, unmatched) = names::filter_by_names(named, &names);
        for miss in &unmatched {
            eprintln!("warning: no peer named {miss:?}");
        }
        if kept.is_empty() {
            bail!("none of the given names matches a peer — `roomler peers` lists them");
        }
        kept
    };
    if json {
        println!("{}", peers_json(&named, display_name)?);
        return Ok(());
    }
    print_peers(&named, display_name, now_ms());
    // An org with no rows is only worth explaining when nothing was asked
    // for by name — a filter narrows the screen to what was named.
    if names.is_empty() {
        print_dark_orgs(&orgs, &peers);
    }
    print_other_daemon_hint().await;
    Ok(())
}

/// `peers --json`: the peer structs verbatim — and, under `--display-name`
/// only, a `display_name` on each (`null` when the device list knows none),
/// so a script that never asked sees the wire it always saw.
fn peers_json(named: &[NamedPeer<'_>], display_name: bool) -> Result<String> {
    if !display_name {
        let plain: Vec<&PeerInfo> = named.iter().map(|n| n.peer).collect();
        return Ok(serde_json::to_string_pretty(&plain)?);
    }
    let rows = named
        .iter()
        .map(|n| {
            let mut v = serde_json::to_value(n.peer)?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "display_name".to_string(),
                    n.display_name
                        .clone()
                        .map_or(serde_json::Value::Null, serde_json::Value::String),
                );
            }
            Ok(v)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::to_string_pretty(&rows)?)
}

/// The device list of every org the peer rows belong to, keyed as the rows
/// are stamped (`""` = a single-org daemon, whose rows are the primary's).
///
/// Best effort: an org whose list is unavailable is left out — its peers keep
/// their mesh names — and ONE line on stderr says so, with the cause, because
/// a column that silently fell back would read as "nobody set a display name".
async fn device_lists_for(
    client: &mut localapi::Client,
    peers: &[PeerInfo],
) -> HashMap<String, Vec<DeviceRowLite>> {
    let mut orgs: Vec<&str> = Vec::new();
    for p in peers {
        if !orgs.contains(&p.org.as_str()) {
            orgs.push(&p.org);
        }
    }
    let multi = orgs.len() > 1;
    let mut lists = HashMap::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut first_error = None;
    for org in orgs {
        match fetch_all_devices(client, org).await {
            Ok(rows) => {
                lists.insert(org.to_string(), rows);
            }
            Err(e) => {
                failed.push(if org.is_empty() { "primary" } else { org });
                first_error.get_or_insert(e);
            }
        }
    }
    if let Some(e) = first_error {
        let which = if multi {
            format!(" for {}", failed.join(", "))
        } else {
            String::new()
        };
        eprintln!(
            "warning: device list unavailable{which} — showing mesh names ({})",
            explain_directory_error(e)
        );
    }
    lists
}

/// Every page of `org`'s device list (`""` / `primary` = the primary
/// enrollment), at the server's page cap. The server's own `exec` resolver
/// reads at most 500 agents, so the page ceiling here is generous, not a
/// limit anyone meets.
async fn fetch_all_devices(
    client: &mut localapi::Client,
    org: &str,
) -> Result<Vec<DeviceRowLite>, localapi::DirectoryError> {
    const PER_PAGE: u64 = 100;
    const MAX_PAGES: u64 = 50;
    let mut all = Vec::new();
    let mut page = 1;
    loop {
        let query = localapi::DevicesQuery {
            page,
            per_page: PER_PAGE,
            ..Default::default()
        };
        let got = client.devices(org, &query).await?;
        let last = got.items.is_empty() || page >= got.total_pages || page >= MAX_PAGES;
        all.extend(got.items);
        if last {
            return Ok(all);
        }
        page += 1;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Device selectors — display names for `ping` / `exec` / `ssh`
// (`docs/device-naming.md`; the rule itself is `names::resolve_selector`)
// ────────────────────────────────────────────────────────────────────────────

/// The device list of the PRIMARY enrollment — the org these commands already
/// act in: the daemon's `ping` reads only the primary's mesh, and `exec` /
/// `ssh` ride the primary's control WS, so the server resolves their target
/// within that org. `None` when it cannot be had, for any reason — the
/// commands then behave exactly as before.
async fn primary_devices(client: &mut localapi::Client) -> Option<Vec<DeviceRowLite>> {
    match fetch_all_devices(client, "").await {
        Ok(rows) => Some(rows),
        Err(e) => {
            tracing::debug!(error = %e, "device list unavailable — the selector goes as typed");
            None
        }
    }
}

/// `exec` / `ssh`: the selector to SEND for what a person typed — as typed,
/// or the hex agent id of the one device whose display name it is. Refuses an
/// ambiguous display name; a command runs as SYSTEM/root on whatever it names.
pub async fn agent_selector(target: &str) -> Result<String> {
    if names::is_literal(target) {
        return Ok(target.to_string());
    }
    // A daemon that cannot be reached fails the command itself a moment
    // later, with the error that explains it — not here.
    let Ok(mut client) = localapi::connect().await else {
        return Ok(target.to_string());
    };
    let rows = primary_devices(&mut client).await;
    match names::resolve_selector(target, rows.as_deref(), Need::AgentId) {
        Resolution::AsTyped => Ok(target.to_string()),
        Resolution::Device(r) => Ok(r.id.clone()),
        Resolution::Ambiguous(c) => Err(names::ambiguity_error(target, &c)),
    }
}

/// `ping`: the target to SEND — as typed, or the overlay address of the one
/// device whose display name it is (the published IPv6 with `prefer_v6`).
async fn ping_target(
    client: &mut localapi::Client,
    target: &str,
    prefer_v6: bool,
) -> Result<String> {
    if names::is_literal(target) {
        return Ok(target.to_string());
    }
    let rows = primary_devices(client).await;
    match names::resolve_selector(target, rows.as_deref(), Need::OverlayIp) {
        Resolution::AsTyped => Ok(target.to_string()),
        Resolution::Device(r) => {
            // The derived v6 is published per peer by the overlay runtime,
            // not listed by the server — one more local read, only for `-6`.
            let peers = if prefer_v6 {
                client.peers().await.unwrap_or_default()
            } else {
                Vec::new()
            };
            Ok(names::ping_address(r, &peers, prefer_v6).unwrap_or_else(|| target.to_string()))
        }
        Resolution::Ambiguous(c) => Err(names::ambiguity_error(target, &c)),
    }
}

/// FR-49 — name the enrollments that contribute no peers BECAUSE they are not
/// on a mesh, which `print_peers` cannot do: it only ever sees peers, and an
/// overlay-off org has none.
///
/// ⚠️ Only for an org with **no rows at all**. An org that has peers is already
/// visible, and an org whose overlay is on but whose peers are all offline is a
/// different state that must keep looking different.
///
/// The selection is [`dark_orgs`] so it can be locked by a test: the whole
/// point is which orgs are and are not in it, and getting that wrong rebuilds
/// the ambiguity this exists to remove.
fn print_dark_orgs(orgs: &[tunnel_core::localapi::OrgStatus], peers: &[PeerInfo]) {
    let dark = dark_orgs(orgs, peers);
    if dark.is_empty() {
        return;
    }
    for o in dark {
        println!();
        println!("  ── org: {} ──", o.label);
        println!(
            "  (overlay OFF — this enrollment is not on a mesh, so it has no peers. \
             It is not \"no peers online\".)"
        );
        println!(
            "  join it with: roomlerd org overlay {} netstack   (then restart the daemon)",
            o.label
        );
    }
}

/// FR-84 D5b — the flags of `roomler devices`.
#[derive(Debug, Clone, Default)]
pub struct DevicesArgs {
    /// An enrollment label (`primary` or an `[[orgs]]` label); `None` = the
    /// primary.
    pub org: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub desc: bool,
    pub page: u64,
    pub per_page: u64,
    pub json: bool,
}

/// `roomler devices` — FR-84 D5b: the devices this device's private network
/// lets it see, itself included, as the SERVER lists them (display names,
/// OS, version, presence, MagicDNS), with this node's live carrier merged in
/// from `peers`.
///
/// Different from `roomler peers` on purpose: `peers` is what the overlay
/// engine currently holds (the netmap's names, carriers, RTTs); this is the
/// org's own record of the same set, asked by the daemon with the org's agent
/// token. Search, sort and paging run on the server. `--json` is the page
/// verbatim, without the merge.
pub async fn devices(args: DevicesArgs) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let query = localapi::DevicesQuery {
        page: args.page,
        per_page: args.per_page,
        q: args.q.clone(),
        sort: args.sort.clone(),
        dir: args.desc.then(|| "desc".to_string()),
    };
    let org = args.org.clone().unwrap_or_default();
    let page = client
        .devices(&org, &query)
        .await
        .map_err(explain_directory_error)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&page)?);
        return Ok(());
    }
    // The live carrier column, best effort: the list is still worth printing
    // when the peer read fails.
    let peers = client.peers().await.unwrap_or_default();
    let peers = peers_of_org(peers, &page.org);
    let searched = args.q.as_deref().is_some_and(|q| !q.trim().is_empty());
    print_devices(&page, &peers, searched);
    Ok(())
}

/// A peer list scoped to one enrollment. A single-org daemon stamps no `org`
/// on its peers, and those are the primary's.
fn peers_of_org(peers: Vec<PeerInfo>, org: &str) -> Vec<PeerInfo> {
    let primary = org.is_empty() || org == "primary";
    peers
        .into_iter()
        .filter(|p| p.org == org || (p.org.is_empty() && primary))
        .collect()
}

/// A [`localapi::DirectoryError`] as the one line an operator acts on.
fn explain_directory_error(e: localapi::DirectoryError) -> anyhow::Error {
    match e.code() {
        "daemon_unreachable" => anyhow!("roomler daemon not running (is the service started?)"),
        "unsupported_daemon" => anyhow!(
            "the roomler daemon on this machine predates `roomler devices` — update it \
             (`roomler peers` lists what its mesh carries)"
        ),
        "unsupported_server" => anyhow!(
            "this device's server predates the device list (HTTP 404) — update the server; \
             `roomler peers` lists what this device's mesh carries"
        ),
        "unknown_org" | "org_disabled" | "unsupported" => anyhow!("{}", upstream_message(&e)),
        code => match e.status() {
            Some(s) => anyhow!(
                "the server did not give the list ({code}, HTTP {s}): {}",
                upstream_message(&e)
            ),
            None => anyhow!(
                "the server did not give the list ({code}): {}",
                upstream_message(&e)
            ),
        },
    }
}

fn upstream_message(e: &localapi::DirectoryError) -> String {
    match e {
        localapi::DirectoryError::Upstream { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

/// `roomler why <peer>` — F: explain, for ONE pair, why it rides the carrier
/// it rides.
///
/// Everything printed here was already being computed by the selector on every
/// sweep and was readable nowhere. On 2026-08-26 answering "why is this Mac on
/// relay when it is on the same Wi-Fi?" needed a `tcpdump` on one host and log
/// archaeology on the other; worse, the decisive record — the demote-follow —
/// carries only `peer=<node id>`, so an earlier search by overlay IP returned
/// nothing and produced a confident WRONG answer. This command exists so that
/// question costs one command on either end.
pub async fn why(peer: &str, json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let peers = client.peers().await.map_err(daemon_err)?;
    let needle = peer.to_ascii_lowercase();
    // Match on name, overlay IP or node id, and accept a unique prefix of the
    // name — an operator reads the name out of `peers` and should not have to
    // retype `macbook-1-local-daemon` exactly.
    let matches: Vec<_> = peers
        .iter()
        .filter(|p| {
            p.node_id.eq_ignore_ascii_case(&needle)
                || p.overlay_ip.as_deref() == Some(peer)
                || p.overlay_ip6.as_deref() == Some(peer)
                || p.name.to_ascii_lowercase().contains(&needle)
        })
        .collect();
    let p = match matches.as_slice() {
        [one] => *one,
        [] => {
            anyhow::bail!(
                "no peer matches {peer:?} — `roomler peers` lists them by name, overlay IP and node id"
            )
        }
        many => {
            // Name alone is NOT a disambiguator on this fleet: one physical
            // host enrolled in two orgs appears once per org under the SAME
            // name with different overlay IPs, so "matches 2 peers: mars,
            // mars" is true and useless. Print what the caller can retype.
            let rows: Vec<String> = many
                .iter()
                .map(|p| {
                    let ip = p.overlay_ip.as_deref().unwrap_or("no-ip");
                    match p.org.as_str() {
                        "" => format!("{} ({ip})", p.name),
                        org => format!("{} ({ip}, org {org})", p.name),
                    }
                })
                .collect();
            anyhow::bail!(
                "{peer:?} matches {} peers — pass one of: {}",
                many.len(),
                rows.join(" | ")
            )
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(p)?);
        return Ok(());
    }
    print_why(p);
    print_other_daemon_hint().await;
    Ok(())
}

fn print_why(p: &PeerInfo) {
    let ip = p.overlay_ip.as_deref().unwrap_or("—");
    println!("{}  {}", p.name, ip);
    let carried = match (&p.connection, p.relay_kind.as_deref()) {
        (ConnectionType::Direct, _) => "direct".to_string(),
        (ConnectionType::Relay, Some(k)) => format!("relay:{k}"),
        (c, _) => format!("{c:?}").to_ascii_lowercase(),
    };
    let via = p
        .debug
        .as_ref()
        .and_then(|d| d.dst.as_deref())
        .map(|d| format!(" via {d}"))
        .unwrap_or_default();
    println!("  carrier   {carried}{via}");
    if let Some(d) = &p.debug {
        println!(
            "  tier      {}   handshake {}   tx {} / rx {}   last heard {}s ago",
            d.tier,
            if d.hs_done { "done" } else { "NOT DONE" },
            d.tx,
            d.rx,
            d.last_rx_age_s
        );
        // A one-way carrier is the single most misread state in the field: the
        // CONN column looks healthy while nothing arrives.
        if d.tx > 0 && d.rx == 0 {
            println!("            ^ ONE-WAY: we are sending and receiving nothing");
        }
    }
    // A — what the prober actually measured, printed next to the decision.
    // A clean path the selector will not use is the single most useful thing
    // this command can show, and it is only visible if the two sit together.
    if !p.probes.is_empty() {
        println!();
        println!("  MEASURED PATH          LOSS    RTT     p95     max");
        for pr in &p.probes {
            let pct = |v: Option<f64>| {
                v.map(|v| format!("{:.0}%", v * 100.0))
                    .unwrap_or_else(|| "—".into())
            };
            let ms = |v: Option<f64>| v.map(|v| format!("{v:.0}ms")).unwrap_or_else(|| "—".into());
            println!(
                "  {:<22} {:>5}  {:>6}  {:>6}  {:>6}",
                pr.dst,
                pct(pr.loss),
                ms(pr.rtt_ms),
                ms(pr.rtt_p95_ms),
                ms(pr.rtt_max_ms)
            );
        }
        // An unmeasured path must never read as a bad one.
        if p.probes.iter().all(|pr| pr.loss.is_none()) {
            println!("  (— = not enough rounds yet to judge, NOT a bad path)");
        }
    }
    let Some(w) = &p.why else {
        println!("  (this daemon predates `why` — upgrade it to see the path decision)");
        return;
    };
    println!();
    println!("  TIER      ELIGIBLE  SCORE   = BASE  + Q      - PENALTY   WHY NOT");
    for t in &w.tiers {
        println!("{}", why_tier_row(t));
    }
    if w.tiers.iter().any(|t| t.available == Some(false)) {
        println!("  (— = no dialable candidate for that tier: nothing to try, whatever its score)");
    }
    println!();
    // The hold-downs, spelled out. Each of these is a legitimate reason the
    // pair is NOT on the tier its raw scores would pick, and each has a
    // different fix, so naming them is the whole point of the command.
    if let Some(s) = w.relayed_instead_s {
        println!(
            "  HELD DOWN {s}s more: the peer is relaying to us over /derp while we hold\n\
             \x20           another carrier, so we follow it rather than fight it (strike {}).\n\
             \x20           Every direct tier is ineligible regardless of its own health.\n\
             \x20           If the peer can reach us directly, the fix is at the PEER.",
            w.relayed_instead_strikes
        );
    } else if w.relayed_instead_strikes > 0 {
        println!(
            "  {} recent demote-follow(s), window expired — the two ends have been\n\
             \x20           disagreeing about this path.",
            w.relayed_instead_strikes
        );
    }
    if let Some(s) = w.forced_derp_s {
        // Deliberately spelled out. The pin selects which RELAY FLAVOUR this
        // pair uses; it does NOT hold the pair off a direct tier —
        // `PathMonitor` keeps it as an annotation and direct decisions ignore
        // it entirely. Read live on 2026-08-26 against a pair that was
        // DIRECT at the time with 1311 s still on the pin, and the first
        // wording ("forced this pair onto /derp") invited exactly the
        // misreading this whole command exists to prevent: blaming a visible
        // knob for a landing it did not cause.
        println!(
            "  PINNED    {s}s more: the server pins this pair's RELAY flavour to /derp.\n\
             \x20           This does NOT hold the pair off a direct tier — if it is on\n\
             \x20           relay, look above for the reason, not here."
        );
    }
    if w.tiers
        .iter()
        .any(|t| t.blocked_by.as_deref() == Some("lan-captured"))
    {
        // FR-33 P2 — a fact about THIS host, not the path: spelled out so the
        // operator goes to the VPN profile, not to path tuning.
        println!(
            "  CAPTURED  this host's own LAN prefix is routed through another adapter (a\n\
             \x20           VPN client's split-prefix capture), so a LAN dial cannot work and\n\
             \x20           is not attempted — `roomler status` names the adapter. The fix is\n\
             \x20           in the VPN profile (local-LAN access / split-exclude), not here."
        );
    }
    if let Some(t) = &w.probing {
        println!("  PROBING   a direct upgrade on {t} is in flight right now.");
    }
    if w.relayed_instead_s.is_none()
        && w.forced_derp_s.is_none()
        && w.tiers.iter().all(|t| t.eligible)
    {
        println!("  No hold-down is active: every tier is eligible.");
    }
}

/// One row of the `why` TIER table. #2089 — a tier with no dialable
/// candidate reads `—`, not `yes`, and WHY NOT says so: an untried tier has
/// no penalty, so "eligible" alone made a NATed peer's `public` row look like
/// the best tier the selector was ignoring, when it was never on the ballot.
fn why_tier_row(t: &TierWhy) -> String {
    let unavailable = t.available == Some(false);
    let eligible = if unavailable {
        "—"
    } else if t.eligible {
        "yes"
    } else {
        "no"
    };
    let why_not = match (unavailable, t.blocked_by.as_deref()) {
        (true, Some(b)) => format!("no candidate, {b}"),
        (true, None) => "no candidate".to_string(),
        (false, b) => b.unwrap_or("").to_string(),
    };
    format!(
        "  {:<9} {:<9} {:>6.1} = {:>5.0} {:>+7.1} {:>10.1}   {}",
        t.tier, eligible, t.score, t.base, t.q, t.penalty, why_not
    )
}

/// `roomler flows` — active forwards / SOCKS5 listeners + throughput. Empty on
/// today's agent daemon until the tunnel data plane folds in (P3b).
pub async fn flows(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let flows = client.flows().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&flows)?);
    } else {
        print_flows(&flows);
    }
    Ok(())
}

/// `roomler rename <name>` — persist a new device name through the running
/// daemon (it writes its OWN config, so this works unelevated even when the
/// daemon is a SYSTEM service). Announced on the next server reconnect. An old
/// daemon that predates the verb reports a clean error.
pub async fn rename(name: &str) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let effective = client.set_device_name(name).await.map_err(daemon_err)?;
    println!("device renamed to \u{201c}{effective}\u{201d} — announced on the next reconnect");
    Ok(())
}

/// `roomler ping <target> [-6] [--timeout-ms N]` — ICMP-ping an overlay peer (by
/// name or IP) over the userspace netstack: the OS-free reachability probe for a
/// locked-down host with no OS route to the mesh. Meaningful on a netstack node;
/// other daemons reply "not supported". The daemon's own error (unknown peer /
/// timeout / not-a-netstack-node) is surfaced verbatim — only a *connect* failure
/// maps through [`daemon_err`].
///
/// A dashboard display name is translated here to the device's overlay
/// address ([`ping_target`]); the output line keeps what was TYPED.
pub async fn ping(target: &str, timeout_ms: u64, prefer_v6: bool, json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let send = ping_target(&mut client, target, prefer_v6).await?;
    let (overlay_ip, rtt_ms) = client
        .ping(&send, timeout_ms, prefer_v6)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "target": target, "overlay_ip": overlay_ip, "rtt_ms": rtt_ms })
        );
    } else {
        println!("{target} ({overlay_ip}): {rtt_ms:.1} ms");
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Fleet RPC — `roomler exec` / `roomler diag`
// ────────────────────────────────────────────────────────────────────────────

/// One remote command's result, in the shape the printers want.
struct RemoteRun {
    node: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    truncated: bool,
    duration_ms: u64,
    error: Option<String>,
}

/// Ask the local daemon to run `command` on `node` and wait for the answer.
async fn run_remote(node: &str, shell: &str, command: &str, timeout_ms: u64) -> Result<RemoteRun> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let req = localapi::Request::ExecRemote {
        node: node.to_string(),
        shell: shell.to_string(),
        command: command.to_string(),
        timeout_ms,
    };
    match client.request(&req).await.map_err(|e| anyhow!("{e}"))? {
        localapi::Response::ExecResult {
            node,
            exit_code,
            stdout,
            stderr,
            truncated,
            duration_ms,
            error,
            ..
        } => Ok(RemoteRun {
            node,
            exit_code,
            stdout,
            stderr,
            truncated,
            duration_ms,
            error,
        }),
        localapi::Response::Error { message } => Err(anyhow!("{message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

/// Resolve a roomler device NAME to its overlay address (P6c).
///
/// Case-insensitive, matching the server's `resolve_exec_target`, because
/// device names are display strings and nobody types `CORPLAP-3`.
/// `Ok(None)` = no such peer — the caller must report that rather than dial
/// something arbitrary.
///
/// The name may also arrive QUALIFIED, in the two spellings a user is steered
/// toward (#1573): `corplap-3.roomler`, which the `Host *.roomler` recipe in
/// `roomler proxy --help` hands over as `%h` — until this, the documented
/// setup failed for every host — and the MagicDNS name,
/// `corplap-3.<magic domain>`. [`mesh_label`] says why no other suffix is
/// stripped.
pub async fn resolve_overlay_ip(name: &str) -> Result<Option<String>> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let peers = client.peers().await.map_err(daemon_err)?;
    let find = |label: &str| {
        peers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(label))
            .map(|p| p.overlay_ip.clone())
    };
    // The name as given first, so everything that resolved before still
    // resolves to the same peer.
    if let Some(ip) = find(name) {
        return Ok(ip);
    }
    if !name.contains('.') {
        return Ok(None);
    }
    // Only a qualified name pays for the second round-trip. A daemon that
    // cannot say (MagicDNS off for the tenant, or older than the field) still
    // gets `.roomler`.
    let magic = client
        .status()
        .await
        .ok()
        .and_then(|s| s.dns)
        .map(|d| d.magic_domain);
    Ok(mesh_label(name, magic.as_deref()).and_then(find).flatten())
}

/// The device label inside a qualified mesh name, or `None` when `name`
/// carries no suffix this resolver owns.
///
/// Owned: the tenant's MagicDNS domain (when the daemon reports one) and
/// `.roomler`, both case-insensitive, with an absolute name's trailing dot
/// ignored.
///
/// ⚠️ Deliberately NOT "everything after the first dot". A `ProxyCommand`
/// scoped wider than `Host *.roomler` would then turn `github.com` into a
/// lookup for a device named `github` and hand the user's `git` to it. A mesh
/// lookup must fail on a name it does not own, never find a different
/// destination — the same rule that keeps the OS resolver away from mesh
/// names.
fn mesh_label<'a>(name: &'a str, magic_domain: Option<&str>) -> Option<&'a str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let magic = magic_domain
        .map(|d| d.trim_matches('.'))
        .filter(|d| !d.is_empty());
    magic
        .into_iter()
        .chain(["roomler"])
        .find_map(|domain| strip_domain(name, domain))
}

/// `name` minus a trailing `.<domain>`, compared case-insensitively. `None`
/// when it does not end that way, or when nothing would be left.
fn strip_domain<'a>(name: &'a str, domain: &str) -> Option<&'a str> {
    let cut = name.len().checked_sub(domain.len() + 1)?;
    // `get`, not indexing: in a non-ASCII name the byte offset can fall
    // inside a character, and that is a non-match, not a panic.
    let (label, tail) = (name.get(..cut)?, name.get(cut..)?);
    let rest = tail.strip_prefix('.')?;
    (!label.is_empty() && rest.eq_ignore_ascii_case(domain)).then_some(label)
}

/// What the server answered about an SSH session request.
pub struct SshGrant {
    pub address: Option<String>,
    pub port: Option<u16>,
    /// The target's SSH host public key. `None` = the device cannot prove
    /// itself; the caller must refuse rather than connect unverified.
    pub host_pubkey: Option<String>,
    pub error: Option<String>,
}

/// Ask the local daemon for a single-use SSH grant on `node`.
///
/// `public_key` is the caller's ephemeral session key — the daemon relays it
/// and never sees the private half.
pub async fn ssh_session(node: &str, public_key: &str, session_secs: u64) -> Result<SshGrant> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let req = localapi::Request::SshSession {
        node: node.to_string(),
        public_key: public_key.to_string(),
        session_secs,
    };
    match client.request(&req).await.map_err(|e| anyhow!("{e}"))? {
        localapi::Response::SshSession {
            address,
            port,
            host_pubkey,
            error,
            ..
        } => Ok(SshGrant {
            address,
            port,
            host_pubkey,
            error,
        }),
        localapi::Response::Error { message } => Err(anyhow!("{message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

/// `roomler exec <device> -- <command…>`
///
/// Exit status mirrors the remote command's, so this composes in a script:
/// a refused or failed command is a non-zero exit here too, never a silent 0.
///
/// `device` may be a dashboard display name: [`agent_selector`] turns it into
/// the hex agent id before the request leaves, and refuses one two devices
/// share. The server still resolves and gates whatever is sent.
pub async fn exec(
    device: &str,
    shell: &str,
    command: &str,
    timeout_ms: u64,
    json: bool,
) -> Result<()> {
    let node = agent_selector(device).await?;
    let mut run = run_remote(&node, shell, command, timeout_ms).await?;
    // The daemon echoes the selector it was sent. Show the one that was
    // TYPED — identical whenever nothing was translated, and the name the
    // person recognises when a display name was.
    run.node = device.to_string();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "node": run.node,
                "exit_code": run.exit_code,
                "stdout": run.stdout,
                "stderr": run.stderr,
                "truncated": run.truncated,
                "duration_ms": run.duration_ms,
                "error": run.error,
            })
        );
    } else {
        print!("{}", run.stdout);
        if !run.stderr.is_empty() {
            eprint!("{}", run.stderr);
        }
        if run.truncated {
            eprintln!("[output truncated at the device's limit]");
        }
        if let Some(e) = &run.error {
            eprintln!("{}: {e}", run.node);
        }
    }
    // `error` set = never ran (a gate said no, offline, timed out). 1 is the
    // conventional "didn't work"; a real exit code passes straight through.
    match (run.error.is_some(), run.exit_code) {
        (true, _) => std::process::exit(1),
        (false, Some(0)) | (false, None) => Ok(()),
        (false, Some(code)) => std::process::exit(code),
    }
}

/// A named section of a diagnostic bundle.
struct BundleSection {
    title: &'static str,
    command: &'static str,
}

/// The Windows evidence set for "why is this pair not direct?".
///
/// Everything here is READ-ONLY — a bundle must be safe to run on a
/// production host without a second thought.
const WINDOWS_BUNDLE: &[BundleSection] = &[
    BundleSection {
        title: "adapters",
        command: "Get-NetAdapter | Sort-Object ifIndex | Format-Table -Auto ifIndex,Name,Status,LinkSpeed,InterfaceDescription | Out-String -Width 200",
    },
    BundleSection {
        title: "addresses",
        command: "Get-NetIPAddress -AddressFamily IPv4 | Format-Table -Auto ifIndex,IPAddress,PrefixLength,InterfaceAlias | Out-String -Width 200",
    },
    BundleSection {
        title: "routes (lowest metric first)",
        command: "Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 25 | Format-Table -Auto DestinationPrefix,NextHop,RouteMetric,ifIndex | Out-String -Width 200",
    },
    BundleSection {
        title: "firewall profiles",
        command: "Get-NetFirewallProfile | Format-Table -Auto Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Out-String -Width 200",
    },
    BundleSection {
        title: "firewall rules mentioning roomler",
        command: "Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*oomler*' } | Format-Table -Auto DisplayName,Enabled,Direction,Action,Profile | Out-String -Width 200",
    },
    BundleSection {
        title: "udp dynamic port range",
        command: "netsh int ipv4 show dynamicport udp",
    },
    BundleSection {
        title: "udp excluded port ranges (Hyper-V/WSL reservations)",
        command: "netsh int ipv4 show excludedportrange protocol=udp",
    },
    BundleSection {
        title: "overlay peers",
        command: "& \"$env:ProgramFiles\\Roomler\\roomler.exe\" peers 2>&1 | Out-String -Width 200",
    },
    BundleSection {
        title: "node status",
        command: "& \"$env:ProgramFiles\\Roomler\\roomler.exe\" status 2>&1 | Out-String -Width 200",
    },
];

/// The Linux/macOS evidence set. Same questions, different tools; also
/// strictly read-only.
const UNIX_BUNDLE: &[BundleSection] = &[
    BundleSection {
        title: "addresses",
        command: "ip -br addr 2>/dev/null || ifconfig",
    },
    BundleSection {
        title: "routes",
        command: "ip route 2>/dev/null || netstat -rn",
    },
    BundleSection {
        title: "routes (v6)",
        command: "ip -6 route 2>/dev/null || true",
    },
    BundleSection {
        title: "firewall",
        command: "(nft list ruleset 2>/dev/null | head -40) || (iptables -S 2>/dev/null | head -40) || echo 'no nft/iptables visible'",
    },
    BundleSection {
        title: "overlay peers",
        command: "roomler peers 2>&1 || /usr/bin/roomler peers 2>&1",
    },
    BundleSection {
        title: "node status",
        command: "roomler status 2>&1 || /usr/bin/roomler status 2>&1",
    },
    BundleSection {
        title: "recent overlay log lines",
        command: "journalctl -u roomler -n 400 --no-pager 2>/dev/null | grep -iE 'overlay|carrier|relay' | tail -30 || echo 'no journal access'",
    },
];

/// Marker the bundle prints between sections, so one exec can carry the whole
/// set and the client can split it apart. Chosen to be something no diagnostic
/// output produces on its own.
const SECTION_MARK: &str = "===ROOMLER-DIAG-SECTION===";

/// Detect the target's family with ONE cheap round trip.
///
/// `echo $env:OS` is valid in both shells and disambiguates them: PowerShell
/// expands `$env:OS` to `Windows_NT`, while bash sees an unset `$env` followed
/// by the literal `:OS`. Cheaper and more reliable than trying to run `uname`
/// under PowerShell, and it needs no OS field on the wire.
async fn detect_windows(node: &str, label: &str) -> Result<bool> {
    let run = run_remote(node, "", "echo $env:OS", 15_000).await?;
    if let Some(e) = run.error {
        return Err(anyhow!("{label}: {e}"));
    }
    Ok(run.stdout.contains("Windows_NT"))
}

/// `roomler diag host|pair` — run the canned bundle on each device and print
/// the sections.
///
/// The bundle lives HERE, in the CLI, not in the agent: a new probe is then a
/// CLI release rather than a fleet-wide agent rollout, which is the whole
/// reason this shipped as free-form exec first.
pub async fn diag_bundle(devices: &[String], json: bool) -> Result<()> {
    let mut all = Vec::new();
    for device in devices {
        // Same selector rule as `exec`: a display name becomes the hex id
        // once, and both execs below address that.
        let node = agent_selector(device).await?;
        let is_windows = detect_windows(&node, device).await?;
        let sections = if is_windows {
            WINDOWS_BUNDLE
        } else {
            UNIX_BUNDLE
        };
        // One exec per host, not one per section: the round trips dominate,
        // and a single command keeps the whole bundle atomic in time — two
        // halves of a route table captured 5 s apart can disagree.
        let script = sections
            .iter()
            .map(|s| {
                if is_windows {
                    format!("Write-Output '{SECTION_MARK}{}'; {}", s.title, s.command)
                } else {
                    format!("echo '{SECTION_MARK}{}'; {}", s.title, s.command)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let run = run_remote(&node, "", &script, 120_000).await?;
        all.push((device.clone(), run));
    }

    if json {
        let payload: Vec<serde_json::Value> = all
            .iter()
            .map(|(device, run)| {
                serde_json::json!({
                    "device": device,
                    "error": run.error,
                    "duration_ms": run.duration_ms,
                    "truncated": run.truncated,
                    "sections": split_sections(&run.stdout),
                })
            })
            .collect();
        println!("{}", serde_json::json!(payload));
        return Ok(());
    }

    for (device, run) in &all {
        println!("\n╔══ {device} ══════════════════════════════════════════");
        if let Some(e) = &run.error {
            println!("║ FAILED: {e}");
            continue;
        }
        for (title, body) in split_sections(&run.stdout) {
            println!("║\n║ ── {title} ──");
            for line in body.lines() {
                println!("║ {line}");
            }
        }
        if run.truncated {
            println!("║ [output truncated at the device's limit]");
        }
        if !run.stderr.is_empty() {
            println!("║\n║ ── stderr ──");
            for line in run.stderr.lines() {
                println!("║ {line}");
            }
        }
    }
    println!();
    Ok(())
}

/// Split a bundle's combined output back into `(title, body)` pairs on the
/// section marker. Pure — unit-tested without a daemon.
fn split_sections(out: &str) -> Vec<(String, String)> {
    let mut sections = Vec::new();
    let mut title: Option<String> = None;
    let mut body = String::new();
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix(SECTION_MARK) {
            if let Some(t) = title.take() {
                sections.push((t, std::mem::take(&mut body)));
            }
            title = Some(rest.to_string());
            continue;
        }
        if title.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(t) = title {
        sections.push((t, body));
    }
    sections
}

/// `roomler forward --daemon --agent <node> --local L --remote R` — ask the
/// LOCAL daemon to open + supervise a static forward over its OWN agent WS
/// (identity model b: no separate tunnel-client token — the pipe/socket ACL is
/// the trust boundary). Returns as soon as the daemon registers the flow; the
/// flow runs IN the daemon and survives this CLI's exit. `roomler flows` shows
/// it; `roomler kill <id>` stops it. A daemon-side error (bad node/remote, port
/// in use) surfaces verbatim; only a *connect* failure maps through [`daemon_err`].
pub async fn create_forward(
    node: &str,
    local: u16,
    remote: &str,
    transport: &str,
    start_transport: &str,
) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let id = client
        .create_forward(node, local, remote, transport, start_transport)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    println!("forward created: {id}");
    println!(
        "  127.0.0.1:{local} → {remote}  via node {}",
        short_id(node)
    );
    println!("  roomler flows          # show it");
    println!("  roomler kill {id}      # stop it");
    Ok(())
}

/// `roomler socks5 --daemon --agent <node> --local L` — ask the LOCAL daemon to
/// open + supervise a SOCKS5 listener (userspace mode; per-connection target)
/// toward `node`. Same lifecycle as [`create_forward`].
pub async fn create_socks5(node: &str, local: u16, transport: &str) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let id = client
        .create_socks5(node, local, transport)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    println!("socks5 listener created: {id}");
    println!(
        "  127.0.0.1:{local} → node {} (per-connection target)",
        short_id(node)
    );
    println!("  roomler flows          # show it");
    println!("  roomler kill {id}      # stop it");
    Ok(())
}

/// `roomler kill <flow-id>` — stop + deregister a daemon flow. Reports whether
/// the id matched.
pub async fn kill(id: &str) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    if client.kill_flow(id).await.map_err(daemon_err)? {
        println!("killed flow {id}");
    } else {
        println!("no active flow with id {id}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Declared routes (P6)
// ---------------------------------------------------------------------------

/// `roomler route add …` — declare a daemon-supervised route. `remote`
/// present ⇒ static forward; absent ⇒ SOCKS5 listener. The daemon
/// persists it (config `[[tunnel_routes]]`) and reconciles it into a live
/// flow; it comes back on every daemon start until `route rm`.
pub async fn route_add(
    id: String,
    node: &str,
    local: u16,
    remote: Option<String>,
    transport: &str,
    enabled: bool,
) -> Result<()> {
    let kind = if remote.is_some() {
        FlowKind::Forward
    } else {
        FlowKind::Socks5
    };
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let eff = client
        .route_add(localapi::RouteDescriptor {
            id,
            kind,
            node: node.to_string(),
            local,
            remote,
            transport: transport.to_string(),
            enabled,
            org: None,
        })
        .await
        .map_err(|e| anyhow!("{e}"))?;
    println!("route declared: {}", eff.id);
    match &eff.remote {
        Some(r) => println!(
            "  127.0.0.1:{} → {r}  via node {}",
            eff.local,
            short_id(node)
        ),
        None => println!(
            "  socks5 127.0.0.1:{} → node {} (per-connection target)",
            eff.local,
            short_id(node)
        ),
    }
    if !eff.enabled {
        println!("  declared DISABLED — `roomler route enable {}`", eff.id);
    }
    println!("  roomler route ls            # live state");
    println!("  roomler route rm {}   # remove", eff.id);
    Ok(())
}

/// `roomler route rm <id>` — remove a declared route (kills its live flow,
/// deletes it from the daemon config).
pub async fn route_rm(id: &str) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    if client.route_remove(id).await.map_err(|e| anyhow!("{e}"))? {
        println!("removed route {id}");
    } else {
        println!("no declared route with id {id}");
    }
    Ok(())
}

/// `roomler route ls` — declared routes + live state.
pub async fn route_ls(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let routes = client.route_list().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&routes)?);
    } else {
        print_routes(&routes);
    }
    Ok(())
}

/// What `roomler route edit` may change. Every field is optional; the
/// route's other settings (enabled state, org) are carried over unchanged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RouteEdit {
    pub id: String,
    pub agent: Option<String>,
    pub local: Option<u16>,
    pub remote: Option<String>,
    pub socks5: bool,
    pub transport: Option<&'static str>,
}

/// Apply an edit to the descriptor `route ls` returned. Pure, so the
/// field-by-field carry-over is testable without a daemon.
pub fn apply_route_edit(
    mut route: localapi::RouteDescriptor,
    edit: &RouteEdit,
) -> Result<localapi::RouteDescriptor> {
    if edit.agent.is_none()
        && edit.local.is_none()
        && edit.remote.is_none()
        && !edit.socks5
        && edit.transport.is_none()
    {
        bail!(
            "nothing to change — pass at least one of --agent, --local, --remote, --socks5, --transport"
        );
    }
    if let Some(agent) = &edit.agent {
        route.node = agent.clone();
    }
    if let Some(local) = edit.local {
        route.local = local;
    }
    if edit.socks5 {
        route.kind = FlowKind::Socks5;
        route.remote = None;
    } else if let Some(remote) = &edit.remote {
        route.kind = FlowKind::Forward;
        route.remote = Some(remote.clone());
    }
    if let Some(transport) = edit.transport {
        route.transport = transport.to_string();
    }
    Ok(route)
}

/// `roomler route edit <id> …` — replace a declared route in ONE step (the
/// FR-84 `RouteUpdate` verb). The daemon validates the result exactly like
/// an add and refuses it without touching the running route.
pub async fn route_edit(edit: RouteEdit) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let routes = client.route_list().await.map_err(daemon_err)?;
    let Some(current) = routes.into_iter().find(|r| r.route.id == edit.id) else {
        bail!("no declared route with id {}", edit.id);
    };
    let wanted = apply_route_edit(current.route, &edit)?;
    let eff = client.route_update(wanted).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown variant") {
            anyhow!("the roomler daemon predates `route edit` — update it, then retry")
        } else {
            anyhow!("{msg}")
        }
    })?;
    println!("route replaced: {}", eff.id);
    match &eff.remote {
        Some(r) => println!(
            "  127.0.0.1:{} → {r}  via node {}",
            eff.local,
            short_id(&eff.node)
        ),
        None => println!(
            "  socks5 127.0.0.1:{} → node {} (per-connection target)",
            eff.local,
            short_id(&eff.node)
        ),
    }
    if !eff.enabled {
        println!("  declared DISABLED — `roomler route enable {}`", eff.id);
    }
    println!("  roomler route ls            # live state");
    Ok(())
}

/// `roomler route enable|disable <id>`.
pub async fn route_set_enabled(id: &str, enabled: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    if client
        .route_set_enabled(id, enabled)
        .await
        .map_err(|e| anyhow!("{e}"))?
    {
        println!(
            "route {id} {}",
            if enabled { "enabled" } else { "disabled" }
        );
    } else {
        println!("no declared route with id {id}");
    }
    Ok(())
}

/// `roomler config ls` — the S2 editable config surface: key, current
/// value, type, and whether a change applies live or on restart. The
/// daemon reads its own config file, so pending not-yet-restarted edits
/// show. FR-84 D2: the daemon lists the surface grouped, in display order,
/// and names each entry's group, so the human table prints a header when
/// the group changes; an older daemon sends no group and the table stays
/// flat. `--json` is the entries verbatim (fields added, none changed).
pub async fn config_ls(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let entries = client.config_entries().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    let key_w = entries
        .iter()
        .map(|e| e.key.len())
        .max()
        .unwrap_or(3)
        .max(3);
    println!("{:key_w$}  {:9}  {:8}  VALUE", "KEY", "TYPE", "APPLIES");
    let mut last_group: Option<&str> = None;
    for e in &entries {
        if !e.group_label.is_empty() && last_group != Some(e.group_label.as_str()) {
            println!("\n[{}]", e.group_label);
            last_group = Some(e.group_label.as_str());
        }
        let value = match &e.value {
            Some(v) if !v.is_empty() => v.clone(),
            _ => "(default)".to_string(),
        };
        let applies = if e.restart_required {
            "restart"
        } else {
            "live"
        };
        println!("{:key_w$}  {:9}  {:8}  {value}", e.key, e.kind, applies);
    }
    println!(
        "\n`restart` keys take effect on the next daemon restart, `live` keys at once — \
         `roomler config set <key> <value>`"
    );
    Ok(())
}

/// `roomler config set <key> <value>` / `config clear <key>` — the
/// daemon validates per key + persists; the echoed entry confirms the
/// stored value. Validation errors come back verbatim.
pub async fn config_set(key: &str, value: Option<&str>) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let entry = client
        .config_set(key, value)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    match &entry.value {
        Some(v) if !v.is_empty() => println!("{} = {v}", entry.key),
        _ => println!("{} cleared (built-in default applies)", entry.key),
    }
    // The daemon says per key whether the change is LIVE (the gate-4 flags
    // it re-seeds from the file it just wrote, docs/remote-config.md §7b) or
    // waits for a restart — FR-84 D2 moved that truth into the surface, so
    // this no longer keeps its own list of the live keys. Telling an operator
    // to restart a live key would be wrong in the direction that matters:
    // they would believe a refusal they just made is not in force yet, and
    // either restart a healthy daemon for nothing or assume they are still
    // exposed.
    if entry.restart_required {
        println!("takes effect on the next daemon restart (apply it now: `roomler restart`)");
    } else {
        println!("in effect now — no restart needed");
    }
    Ok(())
}

/// How long `roomler restart` waits for the relaunched daemon to answer.
const RESTART_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// `roomler restart` — FR-84 D3. Ask the daemon to restart itself through its
/// supervisor; the daemon decides, and a refusal exits non-zero with its
/// reason. Then wait for the NEW daemon (a different pid) to answer, running
/// `roomlerd service start` along the way when the answer says the relaunch
/// is ours (`restart_by: caller` — the Windows Scheduled Task).
///
/// ⚠️ Through Fleet RPC (`roomler exec <host> -- roomler restart`) the daemon
/// relaying the command is the one restarting, so the caller sees "no answer"
/// even though it ran; `roomler exec <host> -- roomler status` afterwards
/// shows the new pid and version.
pub async fn restart(
    reason: &str,
    no_wait: bool,
    daemon_exe: Option<std::path::PathBuf>,
) -> Result<()> {
    let reason = if reason.trim().is_empty() {
        "roomler restart"
    } else {
        reason
    };
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let answer = client.restart_daemon(reason).await.map_err(daemon_err)?;
    drop(client);
    let (supervisor, restart_by, exit_code, leaving, restart_within_s) = match answer {
        localapi::RestartAnswer::Accepted {
            supervisor,
            restart_by,
            exit_code,
            leaving,
            restart_within_s,
        } => (supervisor, restart_by, exit_code, leaving, restart_within_s),
        localapi::RestartAnswer::Refused(why) => bail!("the daemon refused to restart: {why}"),
        localapi::RestartAnswer::Unsupported(_) => bail!(
            "this daemon predates `roomler restart` — restart it through its service manager \
             (Windows: the Roomler service or scheduled task; Linux: systemctl; macOS: launchctl)"
        ),
    };
    let caller_starts = restart_by == "caller";
    println!(
        "restarting: pid {} exits with code {exit_code}; {}",
        leaving
            .pid
            .map_or_else(|| "?".to_string(), |p| p.to_string()),
        if caller_starts {
            format!("this command starts it again ({supervisor})")
        } else {
            format!("{supervisor} relaunches it")
        }
    );
    if no_wait {
        return Ok(());
    }
    // #1684 — wait as long as the supervisor says the relaunch can take (systemd
    // reports `TimeoutStopSec + RestartSec`), never less than the historic
    // floor. A SIGTERM-deaf process in the unit's cgroup can push a stop out to
    // 90 s + `RestartSec`, well past the fixed 60 s that made the verdict lie.
    let wait = localapi::restart_wait(restart_within_s, RESTART_WAIT);
    if wait > RESTART_WAIT {
        println!(
            "(the service manager may take up to {} s to stop and relaunch; waiting that long)",
            wait.as_secs()
        );
    }
    let started = std::time::Instant::now();
    let start = || {
        let exe = daemon_exe.clone();
        async move { start_daemon_service(exe).await }
    };
    match localapi::wait_for_restart(leaving, caller_starts, start, wait).await {
        Ok(pid) => {
            println!(
                "back: pid {} after {:.1} s",
                pid.map_or_else(|| "?".to_string(), |p| p.to_string()),
                started.elapsed().as_secs_f64()
            );
            Ok(())
        }
        Err(why) => bail!("{why} — check the service manager"),
    }
}

/// `roomlerd service start`, the caller half of a restart under the Windows
/// Scheduled Task. The daemon it starts is spawned by the scheduler, never as
/// a child of this process.
async fn start_daemon_service(exe: Option<std::path::PathBuf>) -> Result<(), String> {
    let exe = exe.ok_or_else(|| "roomlerd was not found next to this command".to_string())?;
    let run = tokio::process::Command::new(&exe)
        .args(["service", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(20), run).await {
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(out)) => Err(format!(
            "`{} service start` failed ({}): {}",
            exe.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("running `{} service start`: {e}", exe.display())),
        Err(_) => Err(format!(
            "`{} service start` did not finish within 20 s",
            exe.display()
        )),
    }
}

// ---------------------------------------------------------------------------
// FR-85 — screen recording
// ---------------------------------------------------------------------------

/// A recording's length: `m:ss`, or `h:mm:ss` past the hour.
fn fmt_duration_ms(ms: u64) -> String {
    let s = ms / 1000;
    let (h, m, s) = (s / 3600, (s / 60) % 60, s % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// Which audio a recording carries, as a suffix: `""`, `", computer audio"`,
/// `", microphone"` or `", computer audio + microphone"`.
fn fmt_audio(system: bool, microphone: bool) -> &'static str {
    match (system, microphone) {
        (false, false) => "",
        (true, false) => ", computer audio",
        (false, true) => ", microphone",
        (true, true) => ", computer audio + microphone",
    }
}

/// How the last recording ended, in one line (`None` = nothing has ended).
fn fmt_recording_end(last: &localapi::RecordingEnded) -> String {
    let what = match &last.path {
        Some(p) => format!(
            "saved {p} — {}, {}",
            fmt_duration_ms(last.duration_ms),
            human_bytes(last.bytes)
        ),
        None => "no file was written".to_string(),
    };
    let mut line = if last.reason == "requested" {
        what
    } else {
        format!("{what} (ended: {})", last.reason)
    };
    if let Some(d) = &last.detail {
        line.push_str(&format!("\n  {d}"));
    }
    line
}

/// `roomler record start` — record this device's screen until `record stop`.
/// Answers once the recorder is encoding, naming the file and the encoder.
pub async fn record_start(
    fps: Option<u32>,
    encoder: Option<String>,
    max_minutes: Option<u32>,
    system_audio: bool,
    microphone: bool,
    json: bool,
) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let st = client
        .record_start(localapi::RecordStartOpts {
            fps,
            encoder,
            max_minutes,
            system_audio,
            microphone,
        })
        .await
        .map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&st)?);
        return Ok(());
    }
    println!("recording to {}", st.path.as_deref().unwrap_or(DASH));
    println!(
        "  {}x{} @ {} fps, {}{}",
        st.width,
        st.height,
        st.fps,
        st.encoder.as_deref().unwrap_or(DASH),
        fmt_audio(st.system_audio, st.microphone)
    );
    if let Some(reason) = &st.folder_reason {
        println!("  folder: {reason}");
    }
    println!("stop with `roomler record stop`");
    Ok(())
}

/// `roomler record stop` — answers once the file is final.
pub async fn record_stop(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let st = client.record_stop().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&st)?);
        return Ok(());
    }
    match (&st.last, st.active) {
        (_, true) => println!("still finalizing — check `roomler record status`"),
        (Some(last), false) => println!("{}", fmt_recording_end(last)),
        (None, false) => println!("nothing was recording"),
    }
    Ok(())
}

/// `roomler record status` — is a recording running, and how the last ended.
pub async fn record_status(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let st = client.record_status().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&st)?);
        return Ok(());
    }
    if st.active {
        println!(
            "recording — {}, {}, {} frames, {}{}",
            fmt_duration_ms(st.duration_ms),
            human_bytes(st.bytes),
            st.frames,
            st.encoder.as_deref().unwrap_or(DASH),
            fmt_audio(st.system_audio, st.microphone)
        );
        println!("  {}", st.path.as_deref().unwrap_or(DASH));
    } else {
        println!("not recording");
    }
    if let Some(last) = &st.last {
        println!("last: {}", fmt_recording_end(last));
    }
    Ok(())
}

/// `roomler keep-busy status` — FR-92.
pub async fn keep_busy_status(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let s = client.keep_busy_status().await.map_err(daemon_err)?;
    print_keep_busy(&s, json)
}

/// FR-92 P10 — what `roomler keep-busy on` asks for (the LocalAPI's type).
pub type KeepBusyStart = localapi::KeepBusyStartOpts;

/// `roomler keep-busy on` — FR-92 P10. Only the person at this computer may:
/// the daemon refuses root, services and `roomler exec`, and checks every
/// value with the viewer's own parser.
pub async fn keep_busy_on(opts: KeepBusyStart, json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let s = client.keep_busy_on(opts).await.map_err(daemon_err)?;
    print_keep_busy(&s, json)?;
    if !s.on && !json && s.reason.is_none() {
        println!("(the start is being applied — `roomler keep-busy status` will show it)");
    }
    Ok(())
}

/// `roomler keep-busy off` — FR-92. Stopping is always allowed here.
pub async fn keep_busy_off(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let s = client.keep_busy_off().await.map_err(daemon_err)?;
    print_keep_busy(&s, json)?;
    if s.on && !json {
        println!("(the stop is being applied — `roomler keep-busy status` will show it)");
    }
    Ok(())
}

fn print_keep_busy(s: &localapi::KeepBusyInfo, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(s)?);
        return Ok(());
    }
    println!("{}", keep_busy_line(s));
    if let Some(by) = &s.set_by
        && s.on
    {
        println!("  turned on by {by}");
    }
    Ok(())
}

/// One line for `roomler keep-busy status`. The agent's own sentence for
/// the reason, never a CLI paraphrase.
pub(crate) fn keep_busy_line(s: &localapi::KeepBusyInfo) -> String {
    let sentence = s.sentence.as_deref();
    if !s.on {
        return match (s.reason.as_deref(), sentence) {
            (Some("stopped_by_controller"), _) | (None, _) => "keep busy: off".into(),
            (_, Some(t)) => format!("keep busy: off — {t}"),
            _ => "keep busy: off".into(),
        };
    }
    let mut line = format!("keep busy: {} ({})", s.phase, s.pattern);
    if let Some(t) = sentence {
        line.push_str(" — ");
        line.push_str(t);
    }
    if let Some(ms) = s.resumes_in_ms
        && s.phase == "paused"
    {
        line.push_str(&format!(
            " Resumes in {} s if nothing else happens.",
            ms.div_ceil(1000)
        ));
    }
    line
}

/// `roomler record ls` — the recordings folder, why it is that one, and what
/// is in it (newest first).
pub async fn recordings_ls(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let l = client.recordings_list().await.map_err(daemon_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&l)?);
        return Ok(());
    }
    println!("folder: {}", l.dir);
    if let Some(reason) = &l.folder_reason {
        println!("  ({reason})");
    }
    if l.items.is_empty() {
        println!("no recordings yet");
        return Ok(());
    }
    let name_w = l
        .items
        .iter()
        .map(|i| i.name.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:name_w$}  {:>8}  {:>10}  {:8}  ENDED",
        "NAME", "LENGTH", "SIZE", "ORIGIN"
    );
    for i in &l.items {
        let origin = match &i.controller {
            Some(c) => format!("{} ({c})", i.origin),
            None => i.origin.clone(),
        };
        println!(
            "{:name_w$}  {:>8}  {:>10}  {:8}  {}",
            i.name,
            fmt_duration_ms(i.duration_ms),
            human_bytes(i.bytes),
            origin,
            i.stop_reason.as_deref().unwrap_or(DASH)
        );
    }
    Ok(())
}

/// `roomler record rm <name>` — delete one recording and its sidecar.
pub async fn recording_rm(name: &str) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    client.recording_delete(name).await.map_err(daemon_err)?;
    println!("deleted {name}");
    Ok(())
}

/// FR-52 gate 4 — `roomler rc password set`.
///
/// The password is read here, handed to the daemon over the local pipe, and
/// registered THERE: this process never derives, stores or transmits anything
/// derived from it, and the daemon persists only an OPAQUE record that is not
/// password-equivalent. Nothing about it reaches the server — that is the whole
/// property gate 4 provides, and the reason there is no dashboard equivalent.
///
/// ⚠️ `--stdin` reads exactly one line and strips only the terminator. Trimming
/// surrounding whitespace would store a password the operator did not choose,
/// and they would discover it at the worst possible moment: locked out of the
/// machine they are trying to reach.
fn read_new_password(from_stdin: bool) -> Result<String> {
    if from_stdin {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading the password from stdin")?;
        // Only the terminator, and CRLF as well as LF — a password piped from a
        // file written on Windows would otherwise carry a stray `\r` that
        // nothing on screen shows.
        let pw = line.strip_suffix('\n').unwrap_or(&line);
        let pw = pw.strip_suffix('\r').unwrap_or(pw);
        if pw.is_empty() {
            bail!("no password on stdin");
        }
        return Ok(pw.to_string());
    }
    // Interactive: twice, never echoed. The confirmation is not politeness — a
    // typo in an UNATTENDED password is undiscoverable until someone outside the
    // org tries to use it and fails, by which time nobody suspects the typo.
    let first = rpassword::prompt_password("New external-access password: ")
        .context("reading the password")?;
    let again = rpassword::prompt_password("Repeat it: ").context("reading the confirmation")?;
    if first != again {
        bail!("the two entries differ — nothing was changed");
    }
    Ok(first)
}

/// `roomler rc password set [--stdin]`.
pub async fn rc_password_set(from_stdin: bool) -> Result<()> {
    // Connect FIRST, before asking for a password: on a host with no daemon
    // this fails in one clean line instead of making someone type a password
    // twice and only then telling them there was nothing to send it to.
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let password = read_new_password(from_stdin)?;
    let state = client
        .external_password_set(&password)
        .await
        .map_err(external_verb_err)?;
    println!("external-access password set for this device");
    print_password_next_steps(&state);
    Ok(())
}

/// `roomler rc password clear`.
pub async fn rc_password_clear() -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let state = client
        .external_password_clear()
        .await
        .map_err(external_verb_err)?;
    println!("external-access password cleared — nobody outside this organization can connect");
    if state.enabled {
        println!(
            "note: external_access_enabled is still true; it admits nobody without a password"
        );
    }
    Ok(())
}

/// `roomler rc password status [--json]`.
pub async fn rc_password_status(json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let state = client
        .external_password_status()
        .await
        .map_err(external_verb_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }
    println!(
        "build support     {}",
        if state.supported {
            "yes"
        } else {
            "NO — this build cannot hold a password"
        }
    );
    println!(
        "password          {}",
        if state.password_set { "set" } else { "not set" }
    );
    println!(
        "external access   {}",
        if state.enabled { "on" } else { "off" }
    );
    if let Some(mode) = &state.consent_mode {
        println!("consent mode      {mode}");
    }
    if let Some(perms) = &state.max_permissions {
        println!("local ceiling     {perms}");
    }
    print_password_next_steps(&state);
    Ok(())
}

/// Turn a LocalAPI refusal on an FR-52 verb into something an operator can act on.
///
/// ⚠️ Measured against the live 0.4.99 service, which predates these verbs: a
/// daemon that does not know them cannot *refuse* them, it cannot **parse** the
/// request at all, so what comes back is serde's
/// `unknown variant \`external_password_status\`, expected one of` followed by
/// all twenty-two verb names it does know. That is what the operator sees, and it
/// says nothing about the one thing they can do. Version skew is normal here: on
/// tunnel-only hosts the CLI self-updates independently of any daemon, and a
/// locally built `roomler` against an installed service is exactly this case.
///
/// ⚠️ The hint is **additive and the raw error is kept**. Matching a foreign
/// library's message text is brittle — the same reason a Windows error string is
/// never branched on — so if serde rewords this, the outcome must degrade to
/// "slightly noisier", never to "a real failure is hidden behind a wrong guess".
fn external_verb_err(e: std::io::Error) -> anyhow::Error {
    let raw = e.to_string();
    if raw.contains("unknown variant") {
        return anyhow!(
            "this daemon does not know the external-access verbs, so it is older than this \
             CLI — update the daemon (`roomler status` shows its version).\n  raw: {raw}"
        );
    }
    anyhow!("{raw}")
}

/// Name the gate that is still shut, one line, most-blocking first.
///
/// ⚠️ This says nothing about the ORG side. Gates 1 and 2 — the organization's
/// switch and its per-device approval — live on the server and this device
/// cannot see them, so a device reporting every local gate open is still not a
/// device an outsider can reach. Printing "ready" here would be a claim this
/// process has no way to check.
fn print_password_next_steps(state: &localapi::ExternalPasswordState) {
    if !state.supported {
        println!("  → install a build with external-access support to hold a password");
        return;
    }
    if !state.password_set {
        println!("  → `roomler rc password set` to set one");
    }
    if !state.enabled {
        println!("  → `roomler config set external_access_enabled true` to open gate 3");
    }
    if state.password_set && state.enabled {
        println!("  → this device is ready; an admin must also approve it for external access");
    }
}

/// Map a LocalAPI connect/IO error to a user-facing one. A missing daemon is an
/// *expected* state, so `NotFound` collapses to a single clean line with **no**
/// `.source()` chain (the raw "The system cannot find the file specified" /
/// ENOENT must never surface, and `main` prints just this one line). Everything
/// else keeps its context. Both branches are returned BEFORE any stdout write,
/// so `--json | jq` on a dead daemon fails cleanly with empty stdout.
pub(crate) fn daemon_err(e: io::Error) -> anyhow::Error {
    if e.kind() == io::ErrorKind::NotFound {
        anyhow!("roomler daemon not running (is the service started?)")
    } else {
        anyhow!("talking to the roomler daemon: {e}")
    }
}

/// Wall-clock ms since epoch, for the (pure) `fmt_last_seen`. Only the command
/// handlers call this; the formatters take `now_ms` as an argument.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Pure formatters (no I/O, no clock — deterministically testable)
// ---------------------------------------------------------------------------

/// ● up / ○ down — used for both the node's `connected` and a peer's `online`.
fn up_glyph(up: bool) -> char {
    if up { '●' } else { '○' }
}

/// The Tailscale-style connection-type word shown per peer.
fn connection_label(c: ConnectionType) -> &'static str {
    match c {
        ConnectionType::Direct => "direct",
        ConnectionType::Relay => "relay",
        ConnectionType::Tunnel => "tunnel",
        ConnectionType::Blocked => "blocked",
        ConnectionType::Offline => "offline",
    }
}

/// `relay` qualified with WHICH relay and HOW it is reached —
/// `relay:turn/udp`, `relay:derp/tcp`, or plain `relay` when the daemon is
/// older than the fields (they are `#[serde(default)]`).
///
/// A bare `relay` could not distinguish a ~50 ms coturn/UDP hop from a
/// ~175 ms DERP/TCP one, nor a healthy PoP from a DEAD one: on 2026-08-12 a
/// coturn worker was down for 90 minutes while agents crash-looped and this
/// column said only "relay". Non-relay rows are unchanged.
fn relay_qualified_label(p: &PeerInfo) -> String {
    let base = connection_label(p.connection);
    if !matches!(p.connection, ConnectionType::Relay) {
        return base.to_string();
    }
    match (p.relay_kind.as_deref(), p.relay_transport.as_deref()) {
        (Some(k), Some(t)) => format!("{base}:{k}/{t}"),
        (Some(k), None) => format!("{base}:{k}"),
        _ => base.to_string(),
    }
}

/// Render an optional `Display` value, falling back to the em-dash.
fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => DASH.to_string(),
    }
}

/// First 12 chars of a node/flow id + ellipsis (full id stays in `--json`).
fn short_id(id: &str) -> String {
    if id.chars().count() > 12 {
        let s: String = id.chars().take(12).collect();
        format!("{s}…")
    } else {
        id.to_string()
    }
}

/// 1024-step human bytes (`B`/`KiB`/`MiB`/`GiB`/`TiB`) for the flows table. The
/// raw `u64` still goes out untouched under `--json`.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// Relative age of `last_seen_ms` (epoch-ms) against `now_ms` — "12s ago" /
/// "3m ago" / "5h ago" / "2d ago". `now_ms` is injected so the formatter stays
/// pure. `None` → em-dash. A clock behind the timestamp clamps to "0s ago"
/// rather than underflowing.
fn fmt_last_seen(last_seen_ms: Option<u64>, now_ms: u64) -> String {
    let Some(ts) = last_seen_ms else {
        return DASH.to_string();
    };
    let secs = now_ms.saturating_sub(ts) / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// The NAME a peer row shows by default: its mesh name — or, for a peer that
/// arrived without one (seen in the field), its short node id rather than a
/// blank cell, so the row still identifies it.
fn peer_mesh_name(p: &PeerInfo) -> String {
    if p.name.is_empty() {
        short_id(&p.node_id)
    } else {
        p.name.clone()
    }
}

/// The NAME a peer row shows: under `display`, its dashboard display name
/// when the device list knows one; else [`peer_mesh_name`].
fn peer_label(n: &NamedPeer<'_>, display: bool) -> String {
    match (&n.display_name, display) {
        (Some(d), true) => d.clone(),
        _ => peer_mesh_name(n.peer),
    }
}

/// Cut a label to `width` with an ellipsis — only when asked (`cut`): the
/// default table never truncated a mesh name and must not start.
fn fit_label(label: &str, width: usize, cut: bool) -> String {
    if cut && label.chars().count() > width {
        label
            .chars()
            .take(width.saturating_sub(1))
            .collect::<String>()
            + "…"
    } else {
        label.to_string()
    }
}

/// One `peers` table row: `<glyph> NAME OVERLAY-IP CONN RTT LAST-SEEN`, the
/// NAME being the mesh name in its fixed 20-column cell — the default row,
/// kept as the shape the tests pin (`print_peers` reaches it through
/// [`fmt_peer_row_as`] with the same label and width).
#[cfg(test)]
fn fmt_peer_row(p: &PeerInfo, now_ms: u64) -> String {
    fmt_peer_row_as(p, &peer_mesh_name(p), PEER_NAME_W, now_ms)
}

/// The NAME column's width when nothing widens it — the table's shape since
/// the first `roomler peers`, which the diag bundle and older readers parse.
const PEER_NAME_W: usize = 20;

/// One `peers` table row with `name` in a NAME cell `name_w` wide.
fn fmt_peer_row_as(p: &PeerInfo, name: &str, name_w: usize, now_ms: u64) -> String {
    let rtt = match p.rtt_ms {
        Some(ms) => format!("{ms} ms"),
        None => DASH.to_string(),
    };
    // rc.275 honesty — a carrier the health sweep judged SILENTLY ONE-WAY
    // renders as `stalled`, not as a healthy-looking `direct`/`relay` (the
    // dishonest label cost a multi-session field hunt on winhost-a: every tier
    // "installed", zero completed handshakes, 100 % ping loss — and the table
    // still said direct). Takes precedence over `upgrading`; the tier itself
    // stays visible in `peers --json` (`connection` + `stalled`).
    // P8-cosmetics — a relay peer with a make-before-break direct probe in
    // flight renders as `upgrading`: a snapshot taken mid-transition reads as
    // what it is instead of contradicting the latency the user just measured.
    let conn =
        if p.stalled && matches!(p.connection, ConnectionType::Direct | ConnectionType::Relay) {
            "stalled".to_string()
        } else if p.upgrading && matches!(p.connection, ConnectionType::Relay) {
            "upgrading".to_string()
        } else {
            relay_qualified_label(p)
        };
    format!(
        "{} {:<name_w$} {:<16} {:<26} {:<15} {:>7} {}",
        up_glyph(p.online),
        name,
        opt(p.overlay_ip.as_deref()),
        opt(p.overlay_ip6.as_deref()),
        conn,
        rtt,
        fmt_last_seen(p.last_seen_ms, now_ms),
    )
}

/// One `flows` table row. `TARGET/NODE` shows the static forward's `target`, or
/// the reachable `node` for a SOCKS5 listener (whose target is per-connection).
fn fmt_flow_row(f: &FlowInfo) -> String {
    let kind = match f.kind {
        FlowKind::Forward => "forward",
        FlowKind::Socks5 => "socks5",
    };
    let target_or_node = f
        .target
        .as_deref()
        .or(f.node.as_deref())
        .unwrap_or(DASH)
        .to_string();
    format!(
        "{:<12} {:<8} {:<21} {:<24} {:<10} {:>6} {:>10} {:>10}",
        short_id(&f.id),
        kind,
        f.local_addr,
        target_or_node,
        f.transport,
        f.active_flows,
        human_bytes(f.bytes_in),
        human_bytes(f.bytes_out),
    )
}

/// The `mode` line. `mode` names the kind of node; `privileged` names the
/// account it runs as. Before the daemon reported the account, this line read
/// "service (SYSTEM)" for every full node, per-user ones included. An older
/// daemon reports no account, so the line names none.
fn mode_label(mode: DaemonMode, privileged: Option<bool>) -> &'static str {
    match (mode, privileged) {
        (DaemonMode::Service, Some(true)) if cfg!(windows) => "service (SYSTEM)",
        (DaemonMode::Service, Some(true)) => "service (root)",
        (DaemonMode::Service, Some(false)) => "service (per-user)",
        (DaemonMode::Service, None) => "service",
        (DaemonMode::User, _) => "user",
    }
}

fn print_status(s: &NodeStatus) {
    let mode = mode_label(s.mode, s.privileged);
    println!("{} {}", up_glyph(s.connected), s.name);
    println!("  node id     {}", short_id(&s.node_id));
    println!("  version     {}", s.version);
    println!("  mode        {mode}");
    // FR-51 — only when true: a permanent device's output stays byte-stable.
    if s.ephemeral {
        println!("  ephemeral   yes — removes itself after inactivity, or on clean stop");
    }
    println!("  tenant      {}", opt(s.tenant_id.as_deref()));
    println!("  overlay ip  {}", opt(s.overlay_ip.as_deref()));
    println!("  overlay ip6 {}", opt(s.overlay_ip6.as_deref()));
    println!(
        "  server      {}",
        if s.connected {
            "connected"
        } else {
            "disconnected"
        }
    );
    // FR-103 — the primary enrollment's credential. Printed only when the
    // daemon reports it, so an older daemon's output is unchanged.
    if let Some(exp) = s
        .orgs
        .iter()
        .find(|o| o.primary)
        .and_then(|o| o.token_expires_at)
    {
        println!("  credential  {}", credential_expiry(exp, unix_now()));
    }
    print_orgs(&s.orgs);
    // P5/S4 — exit-node routing (only when this node is configured as a client).
    // S3b — when active, also report whether global IPv6 rides the exit or is
    // fail-closed (Windows exit / no v6 uplink). S4b — and whether DNS is steered
    // through the exit (NOT steered = a DNS leak the operator should see).
    if let Some(ex) = &s.exit_node {
        println!("  exit node   {} ({})", ex.selector, exit_node_state(ex));
    }
    // FR-97 P0b — this node was configured to offer `/0` or subnet routes and
    // offers none, because the host cannot forward or NAT for its peers.
    if let Some(why) = &s.route_offer_withheld {
        println!("  routes      offer withheld — {why}");
    }
    // FR-97 P3i — said only when the host's firewall limits what a mesh peer
    // reaches here, so an open host's output is unchanged.
    if let Some(line) = s.host_firewall.as_ref().and_then(host_firewall_line) {
        println!("  host fw     {line}");
    }
    // S2 — MagicDNS status (only when the tenant has a magic domain and the
    // overlay published it). "resolver down" / "OS steer failed" are the two
    // states worth an operator's eye.
    if let Some(dns) = &s.dns {
        // FR-97 P3h — a steer the host's own resolver never asks is not
        // "active", so it is named, and why on the line below.
        let bypassed = dns
            .os_steer_bypassed
            .as_deref()
            .filter(|_| dns.resolver_bound && dns.os_steer_active);
        let health = if !dns.resolver_bound {
            "resolver DOWN"
        } else if !dns.os_steer_active {
            "resolver up, OS steer FAILED"
        } else if bypassed.is_some() {
            "steered but BYPASSED"
        } else {
            "active"
        };
        let aaaa = if dns.answer_aaaa {
            "AAAA on"
        } else {
            "AAAA off"
        };
        println!(
            "  magicdns    {} ({health}, {aaaa}, upstream {})",
            dns.magic_domain, dns.upstream
        );
        if let Some(why) = bypassed {
            println!("              ⚠️ {why}: this host's own lookups never reach the steer");
        }
    }

    // FR-33 — a captured LAN prefix is the other single most useful answer to
    // "why is this LAN pair on relay?": the peer's handshakes arrive, ours
    // leave through the VPN. Absent field = a daemon without the probe, and
    // then NOTHING is printed (an old daemon must not read as "clear").
    // Probe switched OFF by the operator = say so: there is no verdict, and
    // `why` / the RC pill cannot name a capture until it is back on.
    if s.lan_capture_probe == Some(false) {
        println!(
            "  lan         probe OFF (overlay_lan_capture_probe=false) — no capture verdict; `why` and the RC pill cannot name a VPN capture until it is re-enabled"
        );
    } else if let Some(caps) = &s.lan_captures {
        if caps.is_empty() {
            println!("  lan         clear (own prefixes route on-link)");
        }
        for c in caps {
            let via = match &c.via_name {
                Some(n) => format!("\"{n}\""),
                None => format!("ifref {}", c.via),
            };
            println!(
                "  lan         CAPTURED — {} leaves via {via} (owned by {}); direct on the LAN is impossible while it does",
                c.prefix, c.owner
            );
        }
    }
    // FR-47 — the server refused this node's overlay join. Printed even when
    // the node is connected NOW: "we were refused, and here is why" is the
    // only trace left once the daemon log has rotated, and `connected` above
    // already reports the current state so this cannot be read as it.
    //
    // Absent field = a daemon predating it, and then nothing is printed —
    // silence must never be mistaken for "never refused" on an old build.
    if let Some(r) = &s.join_refusal {
        let ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 - r.at_unix)
            .unwrap_or(0)
            .max(0);
        let when = if ago < 90 {
            format!("{ago}s ago")
        } else if ago < 5400 {
            format!("{}m ago", ago / 60)
        } else {
            format!("{}h ago", ago / 3600)
        };
        let hint = if r.retryable {
            "transient — a retry may succeed"
        } else {
            "retrying will not help; an operator has to act"
        };
        println!("  join        REFUSED {when} — {} ({hint})", r.reason);
        if !r.detail.is_empty() {
            println!("              {}", r.detail);
        }
    }
    // NAT-traversal — the srflx line exists because an empty srflx tier is the
    // single most useful answer to "why is every peer on relay?", and it used
    // to be invisible: both failure paths logged at debug! only.
    if let Some(srflx) = &s.srflx {
        if srflx.candidates.is_empty() {
            let why = srflx.error.as_deref().unwrap_or("no public candidate");
            println!("  srflx       NONE — cannot hole-punch ({why})");
        } else {
            let nat = srflx.nat.as_deref().unwrap_or("unknown NAT");
            let via = srflx
                .stun_server
                .as_deref()
                .map(|s| format!(" via {s}"))
                .unwrap_or_default();
            // R2 — say WHICH path owns the mapping: a public-dial rescue means
            // every LAN vantage was dead and punches ride the VPN-tunnel path.
            let vantage = if srflx.via_public_dial {
                ", public-dial vantage"
            } else {
                ""
            };
            // §6 item 5 — a gateway port mapping is the first candidate.
            let mapped = srflx
                .portmap
                .as_deref()
                .map(|p| format!(", gateway {p}"))
                .unwrap_or_default();
            println!(
                "  srflx       {} ({nat}{via}{vantage}{mapped})",
                srflx.candidates.join(", ")
            );
        }
    }

    // #32 — inbound `/derp` frames that reached no consumer. Printed ONLY when
    // non-zero: on a healthy node both are 0 and a permanent zero line is noise,
    // but after a network transition `unrouted` is the first thing to read — it
    // means a peer is relaying to us that we have not followed onto DERP, which
    // is exactly the 2026-08-25 case that could not be diagnosed because these
    // counters existed and were readable nowhere.
    if let Some((unrouted, backpressure)) = s.derp_inbound_drops
        && (unrouted > 0 || backpressure > 0)
    {
        println!(
            "  derp drops  unrouted={unrouted} backpressure={backpressure} \n             (cumulative — DIFF two readings, never judge the absolute)"
        );
    }

    // FR-68 — route-guard evidence. Printed only when something actually
    // happened, like every other counter line here. The pair worth reading is
    // evicted vs spared: on a healthy multi-org host `spared` climbs while
    // `evicted` stays flat. `evicted` climbing steadily is a route war — we
    // delete, a competitor re-adds, neither side holds the FIB.
    if let Some((evicted, spared, waves, revalidations)) = s.route_guard
        && (evicted > 0 || spared > 0 || waves > 0 || revalidations > 0)
    {
        // #1282 — attribute the waves when the daemon reports it. ⚠️ `tick` is
        // NOT just the blind 2 s fallback: an event inside the 3 s quiet window
        // pulls the tick forward and the tick counts that wave, so a guard
        // whose own writes re-arm it reads as tick ≫ event. `pulled` (newer
        // daemons) is that share: pulled ≈ tick is a self-feeding guard, and
        // `tick − pulled` is the real heartbeat. `other` is any wave neither
        // call site claimed — a third caller nobody attributed.
        let arms = match s.route_wave_arms {
            Some((tick, event)) => {
                let other = waves.saturating_sub(tick + event);
                let tail = if other > 0 {
                    format!(" other={other}")
                } else {
                    String::new()
                };
                let pulled = match s.route_wave_pulls {
                    Some(p) => format!(" pulled={p}"),
                    None => String::new(),
                };
                format!(" [tick={tick}{pulled} event={event}{tail}]")
            }
            None => String::new(),
        };
        // #1328 — the stand-down count. Shown only when non-zero, so a healthy
        // host's line is unchanged and a yielding host names itself. It sits
        // next to `evicted` on purpose: yields up while evicted goes flat is
        // the fight being bounded; BOTH climbing means the cooldown is too
        // short for whatever is competing here.
        let yields = match s.route_yields {
            Some(y) if y > 0 => format!(" yielded={y}"),
            _ => String::new(),
        };
        println!(
            "  route guard evicted={evicted} spared={spared} waves={waves}{arms} revalidations={revalidations}{yields} \n             (cumulative — DIFF two readings, never judge the absolute)"
        );
    }

    // C4 stage 1 — the warm TURN/UDP allocation. The line the Monday-morning
    // VPN check reads: "live" with a fresh probe while srflx is NONE means
    // the relay flow was grandfathered across the VPN connect.
    if let Some(w) = &s.warm_relay {
        match w.state.as_str() {
            "live" => {
                let probe = match w.last_probe_ok_s {
                    Some(a) => format!("probe ok {a}s ago"),
                    None => "probe pending".to_string(),
                };
                let expiry = match w.cred_expiry_in_s {
                    Some(e) => format!(", creds {e}s left"),
                    None => String::new(),
                };
                // C4 stage 2 — say which transport the leg rides: `tls`
                // is the strict-corp flavor that survives a VPN capture.
                let flavor = w
                    .flavor
                    .as_deref()
                    .map(|f| format!("{f}, "))
                    .unwrap_or_default();
                println!(
                    "  warm relay  {} ({flavor}age {}s, {probe}{expiry})",
                    w.relayed.as_deref().unwrap_or("?"),
                    w.age_s.unwrap_or(0)
                );
            }
            other => {
                let why = w.detail.as_deref().unwrap_or("not yet established");
                println!("  warm relay  {other} ({why})");
            }
        }
    }

    // FR-19 — the org-relay probe responder. Absent means this node is not
    // serving; it never means "serving but idle", which is why `answered` is
    // printed even when zero.
    if let Some(r) = &s.org_relay {
        // `bound` is not `reachable`: a DNAT can eat the port upstream of the
        // socket (measured on mars). `answered > 0` is the only line here that
        // is evidence someone actually got through.
        let reach = if r.answered > 0 {
            "reachable (probes answered)"
        } else {
            "bound — NOT yet proven reachable"
        };
        println!("  org relay   {} — {reach}", r.listening);
        println!(
            "              answered={} refused: shape={} not-probe={} rate={}",
            r.answered, r.refused_not_shaped, r.refused_not_probe, r.refused_rate_limited
        );
    }

    // PR-B1 — per-bound-direct-socket receive liveness: a socket with rx=0 /
    // a growing last_rx age while its endpoint is advertised is a dead reader
    // (the 2026-08-10 wedge: bound, advertised, Recv-Q pegged, never read).
    for ds in &s.direct_socks {
        let last = match ds.last_rx_age_s {
            Some(a) => format!("{a}s ago"),
            None => "never".into(),
        };
        println!(
            "  direct sock {}  rx={} last_rx={last}",
            ds.local, ds.rx_pkts
        );
    }
    if let Some(w) = s.direct_bind_walks
        && w > 0
    {
        println!(
            "  bind walks  {w} (stable direct port unavailable — squatter or in-process \
             bind collision)"
        );
    }
    if let Some(r) = s.roam_adoptions
        && r > 0
    {
        println!("  roam adopts {r} (peer endpoints adopted via WG-style roaming)");
    }
    // FR-46 — only printed when NON-EMPTY. An empty list is the common case and
    // says almost nothing (a knob read lazily is absent until it is read), so
    // printing "legacy env: none" every time would read as an all-clear it has
    // not earned. A hit, by contrast, is authoritative: this daemon really is
    // running on a retired variable name.
    if let Some(uses) = s.legacy_env_uses.as_ref()
        && !uses.is_empty()
    {
        println!(
            "  legacy env  {} READ through a retired name: {}",
            uses.len(),
            uses.join(", ")
        );
    }
    // FR-46 P2b — a retired variable is SET but not read. Printed even though
    // it changes nothing, because that is exactly the problem: the daemon runs
    // fine while the host is configured for a spelling nothing honours, so the
    // only way anyone finds out is if something says so.
    //
    // A sibling of the block above, NOT nested inside it: after P2b nothing
    // reads a retired prefix, so `legacy_env_uses` is empty on exactly the
    // hosts this line exists for, and nesting would make it dead code.
    if let Some(present) = s.retired_env_present.as_ref()
        && !present.is_empty()
    {
        println!(
            "  retired env {} SET and IGNORED: {} (rename to ROOMLERD_*)",
            present.len(),
            present.join(", ")
        );
    }
}

/// FR-103 — an agent token's expiry as `roomler status` says it: relative,
/// because "in 172 days" is the fact an operator acts on and needs no
/// calendar. A device renews its own token well before this, so an expiry
/// that keeps approaching is the thing to notice.
fn credential_expiry(expires_at: i64, now_unix: i64) -> String {
    const DAY: i64 = 86_400;
    let plural = |n: i64| if n == 1 { "" } else { "s" };
    if expires_at > now_unix {
        let days = (expires_at - now_unix) / DAY;
        if days == 0 {
            "expires within a day".to_string()
        } else {
            format!("expires in {days} day{}", plural(days))
        }
    } else {
        // The server renews a token up to 90 days past its expiry
        // (`RENEWAL_GRACE_SECS`); past that, only a re-enrollment helps.
        let days = (now_unix - expires_at) / DAY;
        let next = if days < 90 {
            format!("renewable for {} more day{}", 90 - days, plural(90 - days))
        } else {
            "re-enroll this device".to_string()
        };
        format!("EXPIRED {days} day{} ago ({next})", plural(days))
    }
}

/// P5/S4 — the state half of `roomler status`'s exit-node line. While active
/// it says whether global IPv6 rides the exit or is fail-closed (S3b), and
/// whether DNS is steered through it, since NOT steered is a DNS leak the
/// operator should see (S4b).
///
/// FR-97 P0c-3 — a netstack node (`socks5_port`) installs no OS routes, so
/// its exit carries only what the SOCKS5 front dials. Saying "active, v6 on"
/// there told the operator that every app on the host left through the exit,
/// when none did (field, 2026-10-17).
fn exit_node_state(ex: &tunnel_core::localapi::ExitNodeStatus) -> String {
    if !ex.active {
        return format!(
            "withheld — {}",
            ex.withheld_reason.as_deref().unwrap_or("not ready")
        );
    }
    if let Some(port) = ex.socks5_port {
        return format!(
            "active for SOCKS5 clients of 127.0.0.1:{port} only — IPv4 destinations; \
             nothing else on this host uses it"
        );
    }
    let v6 = if ex.v6_active {
        "v6 on"
    } else {
        "v6 fail-closed"
    };
    let dns = if ex.dns_steered {
        "DNS steered"
    } else {
        "DNS NOT steered"
    };
    format!("active, {v6}, {dns}")
}

/// FR-97 P3i — the `host fw` line: what the host's own firewall lets a mesh
/// peer reach on this node's overlay address, or `None` when it admits
/// everything there. Carriers are not in it: they pass a host firewall
/// through conntrack (FR-97 §8). A service the line does not name is refused.
fn host_firewall_line(fw: &tunnel_core::localapi::HostFirewallStatus) -> Option<String> {
    if fw.admits_all {
        return None;
    }
    let reach = if fw.admits.is_empty() {
        "mesh peers reach nothing here".to_string()
    } else {
        format!("mesh peers reach only {} here", fw.admits.join(", "))
    };
    Some(match fw.zone.as_deref() {
        Some(zone) if fw.zone_is_default => format!(
            "{} has {} in no zone, so the default zone {zone} applies: {reach}",
            fw.kind, fw.interface
        ),
        Some(zone) => format!("{} has {} in zone {zone}: {reach}", fw.kind, fw.interface),
        None => format!("{} limits incoming on {}: {reach}", fw.kind, fw.interface),
    })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// FR-49 — the per-enrollment block in `roomler status`.
///
/// `NodeStatus.orgs` has been on the wire since multi-org P1 and was rendered
/// by NOTHING but `--json`, so on a device in two orgs the human output said
/// nothing about the second at all. Skipped entirely for a single-org daemon,
/// keeping that output byte-identical.
fn print_orgs(orgs: &[tunnel_core::localapi::OrgStatus]) {
    if orgs.len() < 2 {
        return;
    }
    println!("  enrollments");
    for o in orgs {
        let conn = if !o.enabled {
            "disabled"
        } else if o.connected {
            "connected"
        } else {
            "disconnected"
        };
        // ⚠️ Empty is "this daemon does not report it", NOT "off" — those are
        // opposite claims and an older daemon must not be made to assert the
        // one it never made.
        let overlay = match o.overlay_mode.as_str() {
            "" => "overlay ?".to_string(),
            "off" => "overlay OFF".to_string(),
            m => format!("overlay {m}"),
        };
        let primary = if o.primary { " (primary)" } else { "" };
        println!("    {:<14} {conn}, {overlay}{primary}", o.label);
        if let Some(err) = &o.terminal_error {
            println!("                   stopped: {err}");
        }
        if let Some(exp) = o.token_expires_at {
            println!(
                "                   credential {}",
                credential_expiry(exp, unix_now())
            );
        }
    }
    // The line that closes the gap this FR is about: enabled + connected +
    // no mesh looks exactly like healthy, and the operator has to be told.
    let dark: Vec<&str> = orgs
        .iter()
        .filter(|o| o.enabled && o.overlay_mode == "off")
        .map(|o| o.label.as_str())
        .collect();
    if !dark.is_empty() {
        println!(
            "                   ⚠️ enrolled but NOT on the mesh: {} \
             (`roomlerd org overlay <label> netstack`)",
            dark.join(", ")
        );
    }
}

/// The orgs `print_dark_orgs` names: enabled, overlay explicitly `off`, and
/// contributing no peer rows.
///
/// ⚠️ Four exclusions, each load-bearing:
/// - an org with peers is already visible, so naming it would be noise;
/// - an org whose overlay is ON but whose peers are all offline is a DIFFERENT
///   state and must keep looking different — that is the distinction the whole
///   FR is about;
/// - a DISABLED org has no signalling loop either, so "not on a mesh" is not
///   the interesting thing about it;
/// - an EMPTY `overlay_mode` means the daemon does not report one, which is not
///   a claim that the overlay is off (absent ≠ off).
fn dark_orgs<'a>(
    orgs: &'a [tunnel_core::localapi::OrgStatus],
    peers: &[PeerInfo],
) -> Vec<&'a tunnel_core::localapi::OrgStatus> {
    orgs.iter()
        .filter(|o| o.enabled && o.overlay_mode == "off")
        .filter(|o| !peers.iter().any(|p| p.org == o.label))
        .collect()
}

/// The `peers` table. Under `display` the NAME column is each peer's
/// dashboard display name (its mesh name when it has none), widened to fit
/// and cut at 34 like the `devices` table; otherwise it is the mesh name in
/// its fixed cell — byte for byte the table it has always been.
fn print_peers(named: &[NamedPeer<'_>], display: bool, now_ms: u64) {
    let labels: Vec<String> = named.iter().map(|n| peer_label(n, display)).collect();
    let name_w = if display {
        labels
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0)
            .clamp(PEER_NAME_W, 34)
    } else {
        PEER_NAME_W
    };
    println!(
        "  {:<name_w$} {:<16} {:<26} {:<15} {:>7} LAST SEEN",
        "NAME", "OVERLAY IP", "OVERLAY IP6", "CONN", "RTT"
    );
    if named.is_empty() {
        println!("(no peers)");
        return;
    }
    let rows: Vec<(&NamedPeer<'_>, &str)> = named
        .iter()
        .zip(labels.iter().map(String::as_str))
        .collect();
    let grouped = group_by_org(&rows, |(n, _)| n.peer.org.as_str());
    for (i, (org, group)) in grouped.into_iter().enumerate() {
        if let Some(org) = org {
            if i > 0 {
                println!();
            }
            println!("  ── org: {org} ──");
        }
        for (n, label) in group {
            let cell = fit_label(label, name_w, display);
            println!("{}", fmt_peer_row_as(n.peer, &cell, name_w, now_ms));
        }
    }
}

/// FR-84 D5b — the `devices` table, one row per listed device, then the page
/// footer and (when the list is short for a reason) why.
fn print_devices(page: &localapi::DevicesPage, peers: &[PeerInfo], searched: bool) {
    let name_w = page
        .items
        .iter()
        .map(|r| device_name(r).chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 34);
    println!(
        "  {:<name_w$} {:<8} {:<9} {:<8} {:<15} {:<30} CONN",
        "NAME", "OS", "VERSION", "STATUS", "OVERLAY IP", "DNS"
    );
    if page.items.is_empty() {
        println!("(no devices)");
    }
    for r in &page.items {
        println!("{}", fmt_device_row(r, peer_for_row(r, peers), name_w));
    }
    let noun = if page.total == 1 { "device" } else { "devices" };
    println!();
    println!(
        "page {} of {} · {} {noun} · overlay {} · acl {}{}",
        page.page.max(1),
        page.total_pages.max(1),
        page.total,
        if page.overlay.is_empty() {
            DASH
        } else {
            &page.overlay
        },
        if page.acl_mode.is_empty() {
            DASH
        } else {
            &page.acl_mode
        },
        if page.org.is_empty() || page.org == "primary" {
            String::new()
        } else {
            format!(" · org {}", page.org)
        },
    );
    if let Some(hint) = devices_hint(page, searched) {
        println!("{hint}");
    }
}

/// The name a person reads: the admin's display name, else the machine name,
/// and a marker on the row that is this device.
fn device_name(r: &localapi::DeviceRowLite) -> String {
    let base = r
        .display_name
        .as_deref()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or(&r.name);
    let base = if base.is_empty() {
        short_id(&r.id)
    } else {
        base.to_string()
    };
    if r.is_self {
        format!("{base} (this device)")
    } else {
        base
    }
}

/// The local peer behind a listed device: by overlay node id, else by the
/// backing agent id — the one join rule, shared with the display-name
/// lookups ([`names::peer_for_device`]).
fn peer_for_row<'a>(r: &localapi::DeviceRowLite, peers: &'a [PeerInfo]) -> Option<&'a PeerInfo> {
    names::peer_for_device(r, peers)
}

/// One `devices` table row — pure, so the column rules are unit-tested.
fn fmt_device_row(r: &localapi::DeviceRowLite, peer: Option<&PeerInfo>, name_w: usize) -> String {
    let glyph = match r.presence.as_str() {
        "online" => '●',
        "stale" => '◐',
        _ => '○',
    };
    let mut name = device_name(r);
    if name.chars().count() > name_w {
        name = name
            .chars()
            .take(name_w.saturating_sub(1))
            .collect::<String>()
            + "…";
    }
    let dns = r
        .magic_dns_fqdn
        .as_deref()
        .or(r.magic_dns_name.as_deref())
        .unwrap_or(DASH);
    let conn = if r.is_self {
        "self".to_string()
    } else {
        match peer {
            Some(p) => {
                let base = if p.stalled
                    && matches!(p.connection, ConnectionType::Direct | ConnectionType::Relay)
                {
                    "stalled".to_string()
                } else {
                    relay_qualified_label(p)
                };
                match p.rtt_ms {
                    Some(ms) => format!("{base} · {ms} ms"),
                    None => base,
                }
            }
            None => DASH.to_string(),
        }
    };
    let or_dash = |s: &str| {
        if s.is_empty() {
            DASH.to_string()
        } else {
            s.to_string()
        }
    };
    format!(
        "{glyph} {name:<name_w$} {:<8} {:<9} {:<8} {:<15} {:<30} {conn}",
        or_dash(&r.os),
        or_dash(&r.version),
        or_dash(&r.presence),
        opt(r.overlay_ip.as_deref()),
        dns,
    )
}

/// Why a list is short, when the envelope says so — a device off the private
/// network lists only itself, which must not read as "the org is empty". A
/// search that matched one row says nothing about the ACL, so `searched`
/// silences that hint.
fn devices_hint(page: &localapi::DevicesPage, searched: bool) -> Option<&'static str> {
    match page.overlay.as_str() {
        "no_node" => Some(
            "this device is not on the private network (overlay off), so it lists only \
             itself — `roomler config set overlay_enabled true` and restart the service",
        ),
        "no_network" => {
            Some("the organization has no private network yet — only this device is listed")
        }
        "unavailable" => {
            Some("the server has no private-network module — only this device is listed")
        }
        "ok" if page.acl_mode == "enforce" && page.total <= 1 && !searched => Some(
            "the organization's access rules (ACL enforce) let this device see no other devices",
        ),
        _ => None,
    }
}

/// Multi-org — group peers by org in FIRST-APPEARANCE order (the daemon emits
/// the primary's mesh first, then each secondary). `None` as the group key
/// means "print no header": that is the single-org case, where every row has
/// an empty `org` and the output must stay byte-identical to the flat table
/// older CLIs — and the diag bundle, which shells out to `roomler peers` —
/// already expect. Rows with no org alongside labelled ones (mixed daemon
/// shapes) are kept in a trailing `(unlabelled)` group rather than dropped.
#[cfg(test)]
fn group_peers_by_org(peers: &[PeerInfo]) -> Vec<(Option<&str>, Vec<&PeerInfo>)> {
    group_by_org(peers, |p| p.org.as_str())
}

/// [`group_peers_by_org`] over any row type that knows its org — the table
/// prints `(peer, label)` pairs under `--display-name`.
fn group_by_org<T>(
    items: &[T],
    org_of: impl for<'b> Fn(&'b T) -> &'b str,
) -> Vec<(Option<&str>, Vec<&T>)> {
    let mut order: Vec<&str> = Vec::new();
    for it in items {
        let org = org_of(it);
        if !org.is_empty() && !order.contains(&org) {
            order.push(org);
        }
    }
    if order.is_empty() {
        return vec![(None, items.iter().collect())];
    }
    let mut out: Vec<(Option<&str>, Vec<&T>)> = order
        .into_iter()
        .map(|org| {
            (
                Some(org),
                items.iter().filter(|it| org_of(it) == org).collect(),
            )
        })
        .collect();
    let orphans: Vec<&T> = items.iter().filter(|it| org_of(it).is_empty()).collect();
    if !orphans.is_empty() {
        out.push((Some("(unlabelled)"), orphans));
    }
    out
}

fn print_flows(flows: &[FlowInfo]) {
    if flows.is_empty() {
        println!("No active flows.");
        return;
    }
    println!(
        "{:<12} {:<8} {:<21} {:<24} {:<10} {:>6} {:>10} {:>10}",
        "ID", "KIND", "LOCAL", "TARGET/NODE", "TRANSPORT", "ACTIVE", "IN", "OUT"
    );
    for f in flows {
        println!("{}", fmt_flow_row(f));
    }
}

fn print_routes(routes: &[RouteInfo]) {
    if routes.is_empty() {
        println!("No declared routes. Declare one with `roomler route add`.");
        return;
    }
    println!(
        "{:<14} {:<8} {:<10} {:>6} {:<24} {:<10} STATE",
        "ID", "KIND", "NODE", "LOCAL", "REMOTE", "TRANSPORT"
    );
    for r in routes {
        println!("{}", fmt_route_row(r));
    }
}

/// One `route ls` table row — pure for unit tests.
fn fmt_route_row(r: &RouteInfo) -> String {
    let d = &r.route;
    let kind = match d.kind {
        FlowKind::Forward => "forward",
        FlowKind::Socks5 => "socks5",
    };
    let transport = if d.transport.is_empty() {
        "auto"
    } else {
        &d.transport
    };
    format!(
        "{:<14} {:<8} {:<10} {:>6} {:<24} {:<10} {}",
        d.id,
        kind,
        short_id(&d.node),
        d.local,
        d.remote.as_deref().unwrap_or(DASH),
        transport,
        route_state_word(&r.state),
    )
}

/// Compact human word for a route's live state. `backoff`/`failed` carry
/// their detail — that's what the operator acts on.
///
/// #1685 — `active` is a bound, serving listener and nothing less. A flow
/// that exists but does not serve carries its `flow_id`: on `pending` its
/// first session attempt is in flight (`connecting`); on `backoff` the tunnel
/// session toward the node is what keeps failing (`retrying …`), as opposed
/// to a `backoff` without one, where the local port could not be bound.
fn route_state_word(s: &RouteState) -> String {
    match s {
        RouteState::Disabled => "disabled".into(),
        RouteState::Pending { flow_id: None } => "pending".into(),
        RouteState::Pending { flow_id: Some(f) } => format!("connecting ({f})"),
        RouteState::Active { flow_id } => format!("active ({flow_id})"),
        RouteState::Backoff {
            next_retry_secs,
            last_error,
            flow_id: Some(f),
            attempts,
        } => {
            let next = if *next_retry_secs > 0 {
                format!(", next in {next_retry_secs}s")
            } else {
                String::new()
            };
            format!("retrying ({f}, attempt {attempts}{next}): {last_error}")
        }
        RouteState::Backoff {
            next_retry_secs,
            last_error,
            flow_id: None,
            ..
        } => format!("backoff {next_retry_secs}s: {last_error}"),
        RouteState::Failed { reason } => format!("FAILED: {reason} (route enable to retry)"),
        // A newer daemon's state word — shown, never an error.
        RouteState::Unknown => "unknown (a newer daemon — update this CLI)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier_row(tier: &str, eligible: bool, available: Option<bool>) -> TierWhy {
        TierWhy {
            tier: tier.into(),
            eligible,
            blocked_by: (!eligible).then(|| "penalty".to_string()),
            available,
            base: 330.0,
            q: 0.0,
            penalty: 0.0,
            score: 330.0,
            fails: 0,
        }
    }

    /// #2089 — the row that misled on 2026-10-11: `public` behind NAT is
    /// unpenalised (eligible) but has nothing to dial. It must not read `yes`.
    #[test]
    fn why_row_says_no_candidate_instead_of_yes() {
        let row = why_tier_row(&tier_row("public", true, Some(false)));
        assert!(row.contains("no candidate"), "{row}");
        assert!(!row.contains(" yes "), "{row}");
        // Both facts at once: no candidate AND a penalty.
        let both = why_tier_row(&tier_row("srflx", false, Some(false)));
        assert!(both.contains("no candidate, penalty"), "{both}");
    }

    /// An available tier, and a daemon that predates the field, render
    /// exactly as before.
    #[test]
    fn why_row_is_unchanged_when_available_or_unknown() {
        for available in [Some(true), None] {
            let row = why_tier_row(&tier_row("public", true, available));
            assert_eq!(
                row, "  public    yes        330.0 =   330    +0.0        0.0   ",
                "{available:?}"
            );
            assert!(why_tier_row(&tier_row("lan", false, available)).ends_with("   penalty"));
        }
    }

    /// FR-93's lab saw a per-user Fedora daemon print "service (SYSTEM)". The
    /// label follows the account the daemon reports, and an older daemon,
    /// which reports none, gets no guess.
    #[test]
    fn the_mode_line_names_the_account_the_daemon_reported() {
        assert_eq!(
            mode_label(DaemonMode::Service, Some(false)),
            "service (per-user)"
        );
        assert_eq!(mode_label(DaemonMode::Service, None), "service");
        let privileged = if cfg!(windows) {
            "service (SYSTEM)"
        } else {
            "service (root)"
        };
        assert_eq!(mode_label(DaemonMode::Service, Some(true)), privileged);
        assert_eq!(mode_label(DaemonMode::User, Some(false)), "user");
    }

    /// FR-92 — the line uses the agent's own sentence and never a paraphrase;
    /// a plain stop from the viewer reads as a plain "off".
    #[test]
    fn keep_busy_line_reads_the_agents_words() {
        let mut s = localapi::KeepBusyInfo {
            available: true,
            on: true,
            phase: "paused".into(),
            reason: Some("user_active".into()),
            sentence: Some("Paused: someone is using this computer.".into()),
            resumes_in_ms: Some(22_100),
            pattern: "heart".into(),
            ..Default::default()
        };
        assert_eq!(
            keep_busy_line(&s),
            "keep busy: paused (heart) — Paused: someone is using this computer. Resumes in 23 s if nothing else happens."
        );
        s.on = false;
        s.reason = Some("stopped_locally".into());
        s.sentence = Some("Turned off at this computer.".into());
        assert_eq!(
            keep_busy_line(&s),
            "keep busy: off — Turned off at this computer."
        );
        s.reason = Some("stopped_by_controller".into());
        assert_eq!(keep_busy_line(&s), "keep busy: off");
    }

    /// FR-52 — an older daemon gets a line it can act on, and the raw error
    /// survives underneath it.
    ///
    /// The second assertion is the one that matters. The hint is triggered by
    /// matching serde's message text, which is a foreign library's wording, so
    /// the failure mode to design against is not "the hint stops appearing" —
    /// it is "a real error was swallowed by a confident wrong guess". Keeping
    /// the raw string and passing everything else through untouched is what
    /// makes a serde rewording cost noise instead of a misdiagnosis.
    #[test]
    fn an_older_daemon_gets_an_actionable_hint_and_keeps_the_raw_error() {
        // The real message, measured against the live 0.4.99 SYSTEM service.
        let raw = "localapi error: bad request: unknown variant \
                   `external_password_status`, expected one of `status`, `peers`";
        let mapped = external_verb_err(io::Error::other(raw)).to_string();
        assert!(
            mapped.contains("older than this CLI"),
            "no actionable line: {mapped}"
        );
        assert!(
            mapped.contains(raw),
            "the raw error must survive — the hint is additive: {mapped}"
        );

        // Anything else passes through UNCHANGED.
        let other = "loading config: permission denied";
        assert_eq!(
            external_verb_err(io::Error::other(other)).to_string(),
            other,
            "an unrelated failure must not be relabelled as a version problem"
        );
    }

    fn peer(name: &str, org: &str) -> PeerInfo {
        PeerInfo {
            node_id: name.into(),
            name: name.into(),
            org: org.into(),
            overlay_ip: None,
            overlay_ip6: None,
            online: true,
            connection: ConnectionType::Direct,
            upgrading: false,
            stalled: false,
            rtt_ms: None,
            last_seen_ms: None,
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        }
    }

    /// A relayed peer must say WHICH relay and HOW — a bare `relay` hid a dead
    /// coturn PoP for 90 minutes on 2026-08-12, and makes a ~50 ms UDP hop
    /// indistinguishable from a ~175 ms DERP/TCP one.
    #[test]
    fn relay_rows_name_the_relay_kind_and_transport() {
        let mut p = peer("fleet-host-2", "");
        p.connection = ConnectionType::Relay;

        p.relay_kind = Some("turn".into());
        p.relay_transport = Some("udp".into());
        assert_eq!(relay_qualified_label(&p), "relay:turn/udp");

        p.relay_kind = Some("derp".into());
        p.relay_transport = Some("tcp".into());
        assert_eq!(relay_qualified_label(&p), "relay:derp/tcp");

        // Older daemon: the fields are `#[serde(default)]`, so the row must
        // degrade to the historical word rather than render "relay:".
        p.relay_kind = None;
        p.relay_transport = None;
        assert_eq!(relay_qualified_label(&p), "relay");

        // A DIRECT peer never carries a relay qualifier, even if stale fields
        // linger in the payload.
        let mut d = peer("buildhost", "");
        d.relay_kind = Some("turn".into());
        d.relay_transport = Some("udp".into());
        assert_eq!(relay_qualified_label(&d), "direct");
    }

    fn org(label: &str, overlay_mode: &str, enabled: bool) -> tunnel_core::localapi::OrgStatus {
        tunnel_core::localapi::OrgStatus {
            label: label.into(),
            server_url: "https://example.invalid".into(),
            tenant_id: None,
            agent_id: None,
            primary: false,
            enabled,
            connected: true,
            terminal_error: None,
            updates_ignored: 0,
            overlay_mode: overlay_mode.into(),
            token_expires_at: None,
        }
    }

    /// FR-49 — an org with no mesh and an org with no peers must not render
    /// identically. Before this, an overlay-off org produced no section at all
    /// in `roomler peers`, which is exactly what an org whose peers happen to
    /// be offline produces.
    /// FR-97 P0c-3 — a netstack node's exit line says the exit carries only its
    /// SOCKS5 front, never "v6 on" or a DNS clause about a host it does not
    /// route; an OS-TUN node's line, and the withheld one, read as before.
    #[test]
    fn a_netstack_exit_says_it_carries_only_the_socks_front() {
        let os_tun = tunnel_core::localapi::ExitNodeStatus {
            selector: "exit".into(),
            active: true,
            withheld_reason: None,
            v6_active: true,
            dns_steered: false,
            socks5_port: None,
        };
        assert_eq!(exit_node_state(&os_tun), "active, v6 on, DNS NOT steered");
        let netstack = tunnel_core::localapi::ExitNodeStatus {
            socks5_port: Some(1080),
            ..os_tun.clone()
        };
        let line = exit_node_state(&netstack);
        assert!(
            line.starts_with("active for SOCKS5 clients of 127.0.0.1:1080 only"),
            "{line}"
        );
        assert!(!line.contains("v6") && !line.contains("DNS"), "{line}");
        let withheld = tunnel_core::localapi::ExitNodeStatus {
            active: false,
            withheld_reason: Some("exit node has no live carrier yet".into()),
            ..netstack
        };
        assert_eq!(
            exit_node_state(&withheld),
            "withheld — exit node has no live carrier yet"
        );
    }

    /// FR-97 P3i — the `host fw` line names what governs the adapter and what
    /// it admits, and says nothing when the firewall admits everything there.
    #[test]
    fn the_host_firewall_line_says_what_a_mesh_peer_reaches() {
        let public = tunnel_core::localapi::HostFirewallStatus {
            kind: "firewalld".into(),
            interface: "roomler0".into(),
            zone: Some("public".into()),
            zone_is_default: true,
            admits_all: false,
            admits: vec!["dhcpv6-client".into(), "ssh".into()],
        };
        assert_eq!(
            host_firewall_line(&public).as_deref(),
            Some(
                "firewalld has roomler0 in no zone, so the default zone public applies: \
                 mesh peers reach only dhcpv6-client, ssh here"
            )
        );
        let work = tunnel_core::localapi::HostFirewallStatus {
            zone: Some("work".into()),
            zone_is_default: false,
            admits: Vec::new(),
            ..public.clone()
        };
        assert_eq!(
            host_firewall_line(&work).as_deref(),
            Some("firewalld has roomler0 in zone work: mesh peers reach nothing here")
        );
        let ufw = tunnel_core::localapi::HostFirewallStatus {
            kind: "ufw".into(),
            zone: None,
            zone_is_default: false,
            admits: vec!["22/tcp".into()],
            ..public.clone()
        };
        assert_eq!(
            host_firewall_line(&ufw).as_deref(),
            Some("ufw limits incoming on roomler0: mesh peers reach only 22/tcp here")
        );
        let trusted = tunnel_core::localapi::HostFirewallStatus {
            admits_all: true,
            ..public
        };
        assert_eq!(host_firewall_line(&trusted), None);
    }

    /// FR-103 — the credential line is relative, and an expired token says
    /// so loudly, with the grace the server still gives it.
    #[test]
    fn a_credential_expiry_reads_in_days() {
        let day = 86_400;
        assert_eq!(credential_expiry(172 * day + 5, 0), "expires in 172 days");
        assert_eq!(credential_expiry(day, 0), "expires in 1 day");
        assert_eq!(credential_expiry(60, 0), "expires within a day");
        assert_eq!(
            credential_expiry(0, 3 * day),
            "EXPIRED 3 days ago (renewable for 87 more days)"
        );
        assert_eq!(
            credential_expiry(0, 90 * day),
            "EXPIRED 90 days ago (re-enroll this device)"
        );
    }

    #[test]
    fn only_an_enabled_overlay_off_org_with_no_peers_is_dark() {
        let orgs = vec![
            org("dark", "off", true),        // ← the case this exists for
            org("meshed-idle", "tun", true), // overlay ON, no peers yet: NOT dark
            org("disabled", "off", false),   // no signalling loop either
            org("unreported", "", true),     // older daemon: absent is not "off"
            org("has-peers", "off", true),   // already visible in the table
        ];
        let peers = vec![peer("node-a", "has-peers")];
        let dark: Vec<&str> = dark_orgs(&orgs, &peers)
            .into_iter()
            .map(|o| o.label.as_str())
            .collect();
        assert_eq!(dark, vec!["dark"]);
    }

    /// The single-org case must stay byte-identical: nothing to say, so
    /// nothing is said.
    #[test]
    fn a_single_org_daemon_has_no_dark_orgs_and_no_enrollment_block() {
        assert!(dark_orgs(&[], &[]).is_empty());
        assert!(dark_orgs(&[org("solo", "tun", true)], &[]).is_empty());
    }

    /// Single-org (every row unlabelled) must render as ONE unheaded group —
    /// byte-identical to the pre-multi-org flat table that older CLIs and the
    /// diag bundle parse. Multi-org groups in first-appearance order.
    #[test]
    fn peers_group_by_org_first_appearance_and_single_org_is_flat() {
        // Single-org: one group, no header.
        let flat = vec![peer("a", ""), peer("b", "")];
        let g = group_peers_by_org(&flat);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].0, None, "single-org must print no org header");
        assert_eq!(g[0].1.len(), 2);

        // Multi-org: primary first (as the daemon emits), then secondaries,
        // each group holding only its own rows.
        let multi = vec![
            peer("p1", "primary"),
            peer("j1", "jovanov"),
            peer("p2", "primary"),
        ];
        let g = group_peers_by_org(&multi);
        assert_eq!(
            g.iter().map(|(o, _)| o.unwrap()).collect::<Vec<_>>(),
            vec!["primary", "jovanov"]
        );
        assert_eq!(g[0].1.len(), 2);
        assert_eq!(g[1].1.len(), 1);
        assert_eq!(g[1].1[0].name, "j1");

        // Mixed shapes: unlabelled rows are kept, not dropped.
        let mixed = vec![peer("x", "primary"), peer("y", "")];
        let g = group_peers_by_org(&mixed);
        assert_eq!(g.len(), 2);
        assert_eq!(g[1].0, Some("(unlabelled)"));
        assert_eq!(g[1].1[0].name, "y");
    }

    #[test]
    fn route_rows_render_each_state() {
        fn info(state: RouteState) -> RouteInfo {
            RouteInfo {
                route: tunnel_core::localapi::RouteDescriptor {
                    id: "pg-buildhost".into(),
                    kind: FlowKind::Forward,
                    node: "aabbccddeeff001122334455".into(),
                    local: 15432,
                    remote: Some("db:5432".into()),
                    transport: String::new(),
                    enabled: true,
                    org: None,
                },
                state,
            }
        }
        let active = fmt_route_row(&info(RouteState::Active {
            flow_id: "fl-3".into(),
        }));
        assert!(active.contains("pg-buildhost"), "got {active}");
        assert!(active.contains("forward"));
        assert!(active.contains("db:5432"));
        assert!(active.contains("auto"), "empty transport renders auto");
        assert!(active.contains("active (fl-3)"));

        // Flow creation is what fails (the port is taken): no flow id.
        let backoff = fmt_route_row(&info(RouteState::Backoff {
            next_retry_secs: 12,
            last_error: "port 15432 in use".into(),
            flow_id: None,
            attempts: 1,
        }));
        assert!(backoff.contains("backoff 12s: port 15432 in use"));

        let failed = fmt_route_row(&info(RouteState::Failed {
            reason: "revoked".into(),
        }));
        assert!(failed.contains("FAILED: revoked"));

        // A socks5 route has no remote — the column shows the dash.
        let mut socks = info(RouteState::Pending { flow_id: None });
        socks.route.kind = FlowKind::Socks5;
        socks.route.remote = None;
        let row = fmt_route_row(&socks);
        assert!(row.contains("socks5"));
        assert!(row.contains(DASH));
        assert!(row.contains("pending"));

        // #1685 — a flow that exists but does not serve is never `active`.
        let connecting = fmt_route_row(&info(RouteState::Pending {
            flow_id: Some("fl-2".into()),
        }));
        assert!(connecting.contains("connecting (fl-2)"), "got {connecting}");
        assert!(!connecting.contains("active"));
        let retrying = fmt_route_row(&info(RouteState::Backoff {
            next_retry_secs: 4,
            last_error: "server error during tunnel.open: agent_unavailable: agent is offline"
                .into(),
            flow_id: Some("fl-2".into()),
            attempts: 3,
        }));
        assert!(
            retrying.contains(
                "retrying (fl-2, attempt 3, next in 4s): server error during tunnel.open: \
                 agent_unavailable: agent is offline"
            ),
            "got {retrying}"
        );
        assert!(!retrying.contains("active"));
        // An attempt in flight has no countdown.
        let in_flight = fmt_route_row(&info(RouteState::Backoff {
            next_retry_secs: 0,
            last_error: "waiting for DC pool to open: deadline has elapsed".into(),
            flow_id: Some("fl-2".into()),
            attempts: 1,
        }));
        assert!(
            in_flight.contains("retrying (fl-2, attempt 1): waiting for DC pool"),
            "got {in_flight}"
        );
        // A state word from a newer daemon renders, it does not error.
        let unknown = fmt_route_row(&info(RouteState::Unknown));
        assert!(unknown.contains("unknown"), "got {unknown}");
    }

    #[test]
    fn human_bytes_steps() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn recording_lengths_and_endings_read_plainly() {
        assert_eq!(fmt_audio(false, false), "");
        assert_eq!(fmt_audio(true, true), ", computer audio + microphone");
        assert_eq!(fmt_duration_ms(0), "0:00");
        assert_eq!(fmt_duration_ms(61_999), "1:01");
        assert_eq!(fmt_duration_ms(3_600_000 + 62_000), "1:01:02");
        let mut last = localapi::RecordingEnded {
            reason: "requested".into(),
            path: Some("C:\\r.mp4".into()),
            bytes: 1024 * 1024,
            duration_ms: 90_000,
            detail: None,
        };
        assert_eq!(fmt_recording_end(&last), "saved C:\\r.mp4 — 1:30, 1.0 MiB");
        // Anything but a plain stop says why it ended.
        last.reason = "disk_low".into();
        assert!(fmt_recording_end(&last).ends_with("(ended: disk_low)"));
        let never = localapi::RecordingEnded {
            reason: "encoder_unavailable".into(),
            detail: Some("no GPU".into()),
            ..Default::default()
        };
        assert_eq!(
            fmt_recording_end(&never),
            "no file was written (ended: encoder_unavailable)\n  no GPU"
        );
    }

    #[test]
    fn last_seen_relative_and_dash() {
        let now = 1_700_000_000_000u64; // realistic epoch-ms (well past 2 days)
        assert_eq!(fmt_last_seen(None, now), "—");
        assert_eq!(fmt_last_seen(Some(now), now), "0s ago");
        assert_eq!(fmt_last_seen(Some(now - 5_000), now), "5s ago");
        assert_eq!(fmt_last_seen(Some(now - 120_000), now), "2m ago");
        assert_eq!(fmt_last_seen(Some(now - 7_200_000), now), "2h ago");
        assert_eq!(fmt_last_seen(Some(now - 172_800_000), now), "2d ago");
        // Clock behind the reported timestamp clamps to 0, not an underflow panic.
        assert_eq!(fmt_last_seen(Some(now + 5_000), now), "0s ago");
    }

    #[test]
    fn peer_row_fields_and_dash_for_nulls() {
        let now = 1_000_000u64;
        let online = PeerInfo {
            node_id: "n2".into(),
            name: "winhost-a".into(),
            org: String::new(),
            overlay_ip: Some("100.64.0.1".into()),
            overlay_ip6: Some("fd72:6f6f:6d6c::6440:1".into()),
            online: true,
            connection: ConnectionType::Tunnel,
            upgrading: false,
            stalled: false,
            rtt_ms: Some(52),
            last_seen_ms: Some(now - 3_000),
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        };
        let row = fmt_peer_row(&online, now);
        assert!(row.starts_with('●'));
        assert!(row.contains("winhost-a"));
        assert!(row.contains("100.64.0.1"));
        assert!(row.contains("fd72:6f6f:6d6c::6440:1"));
        assert!(row.contains("tunnel"));
        assert!(row.contains("52 ms"));
        assert!(row.contains("3s ago"));

        let offline = PeerInfo {
            node_id: "n3".into(),
            name: "home".into(),
            org: String::new(),
            overlay_ip: None,
            overlay_ip6: None,
            online: false,
            connection: ConnectionType::Offline,
            upgrading: false,
            stalled: false,
            rtt_ms: None,
            last_seen_ms: None,
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        };
        let row = fmt_peer_row(&offline, now);
        assert!(row.starts_with('○'));
        assert!(row.contains('—')); // null overlay_ip + rtt + last_seen
        assert!(row.contains("offline"));
    }

    #[test]
    fn peer_row_empty_name_shows_short_id() {
        let now = 1_000_000u64;
        let p = PeerInfo {
            node_id: "0123456789abcdef0123".into(),
            name: String::new(),
            org: String::new(),
            overlay_ip: Some("100.64.0.7".into()),
            overlay_ip6: None,
            online: true,
            connection: ConnectionType::Direct,
            upgrading: false,
            stalled: false,
            rtt_ms: None,
            last_seen_ms: None,
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        };
        let row = fmt_peer_row(&p, now);
        assert!(row.contains("0123456789ab…"), "row was: {row}");
        assert!(row.contains("100.64.0.7"));
    }

    /// rc.275 honesty — a silently-one-way carrier renders `stalled`, never a
    /// healthy-looking tier label; it also beats `upgrading`. A stalled
    /// TUNNEL/OFFLINE peer keeps its own label (the flag describes overlay
    /// carriers only).
    #[test]
    fn peer_row_stalled_beats_tier_and_upgrading() {
        let now = 1_000_000u64;
        let mut p = PeerInfo {
            node_id: "n4".into(),
            name: "winhost-a".into(),
            org: String::new(),
            overlay_ip: Some("100.64.0.1".into()),
            overlay_ip6: None,
            online: true,
            connection: ConnectionType::Direct,
            upgrading: false,
            stalled: true,
            rtt_ms: None,
            last_seen_ms: Some(now - 4_000),
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        };
        assert!(fmt_peer_row(&p, now).contains("stalled"));
        p.connection = ConnectionType::Relay;
        p.upgrading = true;
        let row = fmt_peer_row(&p, now);
        assert!(row.contains("stalled"), "stalled beats upgrading: {row}");
        assert!(!row.contains("upgrading"));
        // Not an overlay carrier ⇒ the flag is ignored.
        p.connection = ConnectionType::Tunnel;
        assert!(fmt_peer_row(&p, now).contains("tunnel"));
        p.stalled = false;
        p.connection = ConnectionType::Relay;
        assert!(fmt_peer_row(&p, now).contains("upgrading"));
    }

    #[test]
    fn flow_row_target_then_node_fallback() {
        let fwd = FlowInfo {
            id: "0123456789abcdef0123".into(),
            kind: FlowKind::Forward,
            local_addr: "127.0.0.1:5432".into(),
            target: Some("10.0.0.5:5432".into()),
            node: Some("winhost-a".into()),
            transport: "quic-v1".into(),
            active_flows: 2,
            bytes_in: 4096,
            bytes_out: 1024 * 1024,
        };
        let row = fmt_flow_row(&fwd);
        assert!(row.contains("0123456789ab…")); // short id
        assert!(row.contains("forward"));
        assert!(row.contains("127.0.0.1:5432"));
        assert!(row.contains("10.0.0.5:5432")); // target wins over node
        assert!(row.contains("4.0 KiB"));
        assert!(row.contains("1.0 MiB"));

        let socks = FlowInfo {
            id: "f2".into(),
            kind: FlowKind::Socks5,
            local_addr: "127.0.0.1:1080".into(),
            target: None,
            node: Some("winhost-a".into()),
            transport: "quic-v1".into(),
            active_flows: 0,
            bytes_in: 0,
            bytes_out: 0,
        };
        let row = fmt_flow_row(&socks);
        assert!(row.contains("socks5"));
        assert!(row.contains("winhost-a")); // node fallback when target is None
    }

    #[test]
    fn labels_glyphs_and_short_id() {
        assert_eq!(connection_label(ConnectionType::Direct), "direct");
        assert_eq!(connection_label(ConnectionType::Relay), "relay");
        assert_eq!(connection_label(ConnectionType::Blocked), "blocked");
        assert_eq!(up_glyph(true), '●');
        assert_eq!(up_glyph(false), '○');
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id("0123456789abcdef0123"), "0123456789ab…");
        assert_eq!(opt::<&str>(None), "—");
        assert_eq!(opt(Some("x")), "x");
    }

    // ─── Fleet-RPC diag bundle ───────────────────────────────────────

    #[test]
    fn splits_a_bundle_into_sections() {
        let out = format!(
            "{SECTION_MARK}adapters\neth0 UP\nwlan0 DOWN\n{SECTION_MARK}routes\ndefault via 1.1.1.1\n"
        );
        let sections = split_sections(&out);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].0, "adapters");
        assert_eq!(sections[0].1, "eth0 UP\nwlan0 DOWN\n");
        assert_eq!(sections[1].0, "routes");
        assert_eq!(sections[1].1, "default via 1.1.1.1\n");
    }

    #[test]
    fn preamble_before_the_first_marker_is_dropped() {
        // PowerShell profiles and shell rc files love printing banners. They
        // belong to no section, and attributing them to the first one would
        // quietly corrupt the evidence.
        let out = format!("Windows PowerShell\nCopyright (c)\n{SECTION_MARK}routes\n0.0.0.0/0\n");
        let sections = split_sections(&out);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].0, "routes");
        assert_eq!(sections[0].1, "0.0.0.0/0\n");
    }

    #[test]
    fn an_empty_section_still_appears() {
        // "the firewall has no roomler rules" is a FINDING, not a missing
        // section — dropping it would read as "we didn't check".
        let out =
            format!("{SECTION_MARK}firewall rules mentioning roomler\n{SECTION_MARK}routes\nx\n");
        let sections = split_sections(&out);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].0, "firewall rules mentioning roomler");
        assert_eq!(sections[0].1, "");
    }

    #[test]
    fn output_with_no_markers_yields_nothing() {
        assert!(split_sections("just some output\n").is_empty());
        assert!(split_sections("").is_empty());
    }

    #[test]
    fn bundles_are_read_only() {
        // A bundle must be safe to run unthinkingly on a production node —
        // three of the fleet's Linux hosts are live k8s cluster members.
        // This is a coarse guard, not a sandbox, but it catches the obvious
        // slip of pasting a mutating command into the evidence set.
        const FORBIDDEN: &[&str] = &[
            "Stop-Service",
            "Restart-Service",
            "Set-Net",
            "New-Net",
            "Remove-",
            "systemctl stop",
            "systemctl restart",
            "pkill",
            "kill -",
            "reboot",
            "shutdown",
            " rm ",
            "iptables -A",
            "iptables -I",
            "nft add",
        ];
        for section in WINDOWS_BUNDLE.iter().chain(UNIX_BUNDLE.iter()) {
            for bad in FORBIDDEN {
                assert!(
                    !section.command.contains(bad),
                    "bundle section {:?} contains a mutating command {bad:?}",
                    section.title
                );
            }
        }
    }

    #[test]
    fn the_recipe_suffix_and_the_magicdns_name_both_yield_the_label() {
        // #1573: `Host *.roomler` guarantees `%h` arrives WITH the suffix, so
        // a proxy that looked the name up verbatim failed for every host.
        let magic = Some("grox.roomler.ai");
        assert_eq!(mesh_label("zeus.roomler", magic), Some("zeus"));
        assert_eq!(mesh_label("zeus.roomler", None), Some("zeus"));
        assert_eq!(mesh_label("zeus.grox.roomler.ai", magic), Some("zeus"));
        // Absolute form, and any casing a user or a config file produces.
        assert_eq!(mesh_label("zeus.grox.roomler.ai.", magic), Some("zeus"));
        assert_eq!(mesh_label("CORPLAP-3.ROOMLER", None), Some("CORPLAP-3"));
        assert_eq!(mesh_label("zeus.Grox.Roomler.AI", magic), Some("zeus"));
        // A domain reported with dots around it is the same domain.
        assert_eq!(
            mesh_label("zeus.grox.roomler.ai", Some(".grox.roomler.ai.")),
            Some("zeus")
        );
    }

    #[test]
    fn a_suffix_the_mesh_does_not_own_is_never_stripped() {
        // The failure this prevents: a ProxyCommand scoped wider than
        // `*.roomler` turning `github.com` into a lookup for a device named
        // `github` and handing the user's git to it.
        let magic = Some("grox.roomler.ai");
        assert_eq!(mesh_label("github.com", magic), None);
        assert_eq!(mesh_label("zeus.example.roomler.ai", magic), None);
        // Without the daemon's word for it, a MagicDNS name is not guessed at.
        assert_eq!(mesh_label("zeus.grox.roomler.ai", None), None);
        // A suffix that merely ENDS the same way is not the suffix.
        assert_eq!(mesh_label("zeusroomler", None), None);
        assert_eq!(mesh_label("zeus.xroomler", None), None);
    }

    #[test]
    fn nothing_left_after_the_suffix_is_no_label() {
        assert_eq!(mesh_label(".roomler", None), None);
        assert_eq!(mesh_label("roomler", None), None);
        assert_eq!(mesh_label("grox.roomler.ai", Some("grox.roomler.ai")), None);
        assert_eq!(mesh_label("", None), None);
        // An empty domain must not turn every dotted name into a match.
        assert_eq!(mesh_label("zeus.local", Some("")), None);
        assert_eq!(mesh_label("zeus.local", Some(".")), None);
    }

    #[test]
    fn a_non_ascii_name_is_a_non_match_not_a_panic() {
        // The cut is a BYTE offset; in the last two it lands inside a
        // character (`ž` is two bytes, `€` three).
        assert_eq!(mesh_label("ž.roomler", None), Some("ž"));
        assert_eq!(mesh_label("a.žroomler", None), None);
        assert_eq!(mesh_label("€€€€", None), None);
    }
}

#[cfg(test)]
mod route_edit_tests {
    use super::{RouteEdit, apply_route_edit};
    use tunnel_core::localapi::{FlowKind, RouteDescriptor};

    fn declared() -> RouteDescriptor {
        RouteDescriptor {
            id: "pg".into(),
            kind: FlowKind::Forward,
            node: "aabbccddeeff001122334455".into(),
            local: 15432,
            remote: Some("db:5432".into()),
            transport: "auto".into(),
            enabled: false,
            org: Some("acme".into()),
        }
    }

    /// FR-84 — `route edit` sends the WHOLE descriptor back, so everything
    /// the flags did not name must ride along unchanged: the enabled state
    /// (a disabled route stays disabled) and the org label in particular.
    #[test]
    fn edit_changes_only_what_was_named() {
        let edited = apply_route_edit(
            declared(),
            &RouteEdit {
                id: "pg".into(),
                local: Some(25432),
                ..RouteEdit::default()
            },
        )
        .unwrap();
        assert_eq!(edited.local, 25432);
        assert_eq!(edited.remote.as_deref(), Some("db:5432"));
        assert_eq!(edited.node, "aabbccddeeff001122334455");
        assert!(!edited.enabled, "the enabled state is carried over");
        assert_eq!(
            edited.org.as_deref(),
            Some("acme"),
            "the org label is carried over"
        );
        assert_eq!(edited.id, "pg");
    }

    #[test]
    fn socks5_drops_the_remote_and_remote_makes_a_forward() {
        let socks = apply_route_edit(
            declared(),
            &RouteEdit {
                id: "pg".into(),
                socks5: true,
                ..RouteEdit::default()
            },
        )
        .unwrap();
        assert_eq!(socks.kind, FlowKind::Socks5);
        assert_eq!(socks.remote, None);

        let mut was_socks = declared();
        was_socks.kind = FlowKind::Socks5;
        was_socks.remote = None;
        let fwd = apply_route_edit(
            was_socks,
            &RouteEdit {
                id: "pg".into(),
                remote: Some("web:80".into()),
                transport: Some("quic"),
                ..RouteEdit::default()
            },
        )
        .unwrap();
        assert_eq!(fwd.kind, FlowKind::Forward);
        assert_eq!(fwd.remote.as_deref(), Some("web:80"));
        assert_eq!(fwd.transport, "quic");
    }

    #[test]
    fn an_edit_that_names_nothing_is_refused() {
        let err = apply_route_edit(
            declared(),
            &RouteEdit {
                id: "pg".into(),
                ..RouteEdit::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("nothing to change"), "{err}");
    }
}

#[cfg(test)]
mod devices_tests {
    use super::*;

    fn row(name: &str) -> localapi::DeviceRowLite {
        localapi::DeviceRowLite {
            kind: "agent".into(),
            id: "0123456789abcdef01234567".into(),
            name: name.into(),
            os: "linux".into(),
            version: "0.4.103".into(),
            presence: "online".into(),
            is_online: true,
            overlay_ip: Some("100.64.0.3".into()),
            overlay_node_id: Some("76543210fedcba9876543210".into()),
            magic_dns_name: Some(name.into()),
            ..Default::default()
        }
    }

    fn peer(node: &str, agent: Option<&str>, conn: ConnectionType, rtt: Option<u32>) -> PeerInfo {
        let mut p: PeerInfo = serde_json::from_str(
            r#"{"node_id":"x","name":"x","online":true,"connection":"direct"}"#,
        )
        .unwrap();
        p.node_id = node.into();
        p.agent_id = agent.map(str::to_string);
        p.connection = conn;
        p.rtt_ms = rtt;
        p
    }

    /// The NAME column is the admin's display name when there is one, and
    /// this device says so.
    #[test]
    fn names_prefer_the_display_name_and_mark_this_device() {
        let mut r = row("bravo-box");
        assert_eq!(device_name(&r), "bravo-box");
        r.display_name = Some("Kilo".into());
        assert_eq!(device_name(&r), "Kilo");
        r.display_name = Some("   ".into());
        assert_eq!(device_name(&r), "bravo-box", "a blank label is no label");
        r.is_self = true;
        assert_eq!(device_name(&r), "bravo-box (this device)");
    }

    /// CONN comes from THIS node's live peer view, joined by overlay node id
    /// and, failing that, by the backing agent id; a device the engine holds
    /// no carrier for shows a dash, never a guessed state.
    #[test]
    fn conn_is_the_local_carrier_joined_by_node_then_agent() {
        let r = row("kilo");
        let by_node = [peer(
            "76543210fedcba9876543210",
            None,
            ConnectionType::Direct,
            Some(4),
        )];
        let line = fmt_device_row(&r, peer_for_row(&r, &by_node), 12);
        assert!(line.ends_with("direct · 4 ms"), "{line}");

        let by_agent = [peer(
            "other-node",
            Some("0123456789abcdef01234567"),
            ConnectionType::Relay,
            None,
        )];
        let line = fmt_device_row(&r, peer_for_row(&r, &by_agent), 12);
        assert!(line.ends_with("relay"), "{line}");

        let line = fmt_device_row(&r, peer_for_row(&r, &[]), 12);
        assert!(line.ends_with(DASH), "{line}");

        let mut me = row("me");
        me.is_self = true;
        assert!(fmt_device_row(&me, None, 20).ends_with("self"));
    }

    /// A single-org daemon stamps no org on its peers — those are the
    /// primary's; a multi-org daemon's other orgs are filtered out.
    #[test]
    fn peers_are_scoped_to_the_listed_org() {
        let mut a = peer("n1", None, ConnectionType::Direct, None);
        let mut b = peer("n2", None, ConnectionType::Direct, None);
        let c = peer("n3", None, ConnectionType::Direct, None);
        a.org = "primary".into();
        b.org = "acme".into();
        let all = vec![a, b, c];
        let prim: Vec<String> = peers_of_org(all.clone(), "primary")
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        assert_eq!(prim, ["n1", "n3"]);
        let acme: Vec<String> = peers_of_org(all, "acme")
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        assert_eq!(acme, ["n2"]);
    }

    /// A short list says why — and a search that matched one row does not
    /// get blamed on the ACL.
    #[test]
    fn a_short_list_explains_itself() {
        let mut page = localapi::DevicesPage {
            total: 1,
            overlay: "no_node".into(),
            acl_mode: "off".into(),
            ..Default::default()
        };
        assert!(devices_hint(&page, false).unwrap().contains("overlay off"));
        page.overlay = "ok".into();
        page.acl_mode = "enforce".into();
        assert!(devices_hint(&page, false).unwrap().contains("ACL enforce"));
        assert_eq!(devices_hint(&page, true), None);
        page.total = 5;
        assert_eq!(devices_hint(&page, false), None);
    }

    /// Each cause reads as the thing to do about it.
    #[test]
    fn directory_errors_read_as_actions() {
        let up = |code: &str, status: Option<u16>| localapi::DirectoryError::Upstream {
            code: code.into(),
            message: "m".into(),
            status,
        };
        let msg = explain_directory_error(localapi::DirectoryError::UnsupportedDaemon {
            message: "unknown variant".into(),
        })
        .to_string();
        assert!(msg.contains("predates `roomler devices`"), "{msg}");
        let msg = explain_directory_error(up("unsupported_server", Some(404))).to_string();
        assert!(msg.contains("update the server"), "{msg}");
        let msg = explain_directory_error(up("unauthorized", Some(401))).to_string();
        assert!(msg.contains("unauthorized, HTTP 401"), "{msg}");
        let msg = explain_directory_error(localapi::DirectoryError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "x",
        )))
        .to_string();
        assert!(msg.contains("not running"), "{msg}");
    }
}

#[cfg(test)]
mod display_name_tests {
    use super::*;

    fn peer(node: &str, name: &str) -> PeerInfo {
        let mut p: PeerInfo = serde_json::from_str(
            r#"{"node_id":"x","name":"x","online":true,"connection":"direct","overlay_ip":"100.64.0.5"}"#,
        )
        .unwrap();
        p.node_id = node.into();
        p.name = name.into();
        p
    }

    /// Without `--display-name` a row is byte-identical to the row it has
    /// always been — the mesh name in its fixed cell, never cut — and with it
    /// the label is the display name, cut only past the widened cell.
    #[test]
    fn default_rows_are_unchanged_and_display_labels_widen_and_cut() {
        let now = 1_000u64;
        let p = peer("node-laptop", "laptop");
        let n = NamedPeer {
            peer: &p,
            display_name: Some("Travel Laptop".into()),
        };
        assert_eq!(
            fmt_peer_row_as(&p, &peer_label(&n, false), PEER_NAME_W, now),
            fmt_peer_row(&p, now),
            "the flag off is today's row"
        );
        assert_eq!(peer_label(&n, false), "laptop");
        assert_eq!(peer_label(&n, true), "Travel Laptop");
        let unnamed = NamedPeer {
            peer: &p,
            display_name: None,
        };
        assert_eq!(
            peer_label(&unnamed, true),
            "laptop",
            "no display name: the mesh name"
        );

        // A peer with no mesh name shows its short node id either way.
        let blank = peer("0123456789abcdef0123", "");
        let b = NamedPeer {
            peer: &blank,
            display_name: None,
        };
        assert_eq!(peer_label(&b, true), "0123456789ab…");

        let long = "a-mesh-name-longer-than-twenty-chars";
        assert_eq!(
            fit_label(long, PEER_NAME_W, false),
            long,
            "never cut by default"
        );
        let cut = fit_label(&"x".repeat(40), 34, true);
        assert_eq!(cut.chars().count(), 34);
        assert!(cut.ends_with('…'));
        assert_eq!(fit_label("short", 34, true), "short");

        // The widened row really is wider: the OVERLAY IP column moves.
        let wide = fmt_peer_row_as(&p, "Travel Laptop", 30, now);
        let narrow = fmt_peer_row_as(&p, "Travel Laptop", PEER_NAME_W, now);
        assert_eq!(
            wide.find("100.64.0.5").unwrap(),
            narrow.find("100.64.0.5").unwrap() + 10
        );
    }

    /// `--json` is the wire verbatim; `--display-name --json` adds exactly one
    /// field per peer, `null` when the device list knows none.
    #[test]
    fn json_adds_display_name_only_when_asked() {
        let a = peer("n1", "laptop");
        let b = peer("n2", "home-server");
        let named = vec![
            NamedPeer {
                peer: &a,
                display_name: Some("Travel Laptop".into()),
            },
            NamedPeer {
                peer: &b,
                display_name: None,
            },
        ];
        let plain: serde_json::Value =
            serde_json::from_str(&peers_json(&named, false).unwrap()).unwrap();
        assert_eq!(
            plain,
            serde_json::to_value([&a, &b]).unwrap(),
            "without the flag the JSON is the PeerInfo wire, nothing added"
        );
        let with: serde_json::Value =
            serde_json::from_str(&peers_json(&named, true).unwrap()).unwrap();
        assert_eq!(with[0]["display_name"], "Travel Laptop");
        assert!(with[1]["display_name"].is_null());
        assert_eq!(with[0]["name"], "laptop", "the mesh name stays alongside");
        assert_eq!(with.as_array().unwrap().len(), 2);
    }
}
