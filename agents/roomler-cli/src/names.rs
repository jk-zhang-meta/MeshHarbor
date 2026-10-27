// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Display names on the command line — the join between what the overlay
//! engine calls a peer and what an admin called it in the dashboard, and the
//! rule for reading a device selector a person typed.
//!
//! Three facts shape this module, all about where a name lives:
//!
//! * The NAME `meshharbor peers` prints is [`PeerInfo::name`]: the MagicDNS label
//!   the netmap carries, derived from the fleet name. The dashboard's
//!   `display_name` deliberately never enters the netmap
//!   (`docs/device-naming.md`), so the only place a CLI can learn it is the
//!   device list the daemon fetches for this device (`roomler devices`, FR-84
//!   D5b). Everything here is a JOIN of those two lists; nothing on the wire
//!   changes.
//! * `exec` / `ssh` targets are resolved by the SERVER (hex id, then the fleet
//!   name exact, then case-insensitive — `resolve_exec_target`) and `ping`
//!   targets by the DAEMON (a literal address, then the mesh label —
//!   `resolve_overlay`). Neither knows display names. This module translates a
//!   display name into something they do know — the hex agent id, or an
//!   overlay address — and ONLY when nothing they already resolve would have
//!   matched: a selector that works today must keep meaning the same device,
//!   so a display name can never shadow a fleet name, a label, an id or an
//!   address.
//! * A command sent to the wrong device runs as SYSTEM/root there. Two devices
//!   carrying the same display name is therefore a REFUSAL, never a guess.
//!
//! Every function is pure — slices in, verdicts out — so the precedence is
//! locked by unit tests with no daemon.

use std::collections::HashMap;
use std::net::IpAddr;

use tunnel_core::localapi::{DeviceRowLite, PeerInfo};

/// The admin's display name of a listed device, when it has one worth
/// showing — a blank label is no label.
pub fn display_name_of(row: &DeviceRowLite) -> Option<&str> {
    row.display_name
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
}

/// The listed device behind a peer: by overlay node id, else by the backing
/// agent id. The same two keys as [`peer_for_device`], read the other way.
pub fn row_for_peer<'a>(p: &PeerInfo, rows: &'a [DeviceRowLite]) -> Option<&'a DeviceRowLite> {
    if !p.node_id.is_empty()
        && let Some(r) = rows
            .iter()
            .find(|r| r.overlay_node_id.as_deref() == Some(p.node_id.as_str()))
    {
        return Some(r);
    }
    let agent = p.agent_id.as_deref().filter(|a| !a.is_empty())?;
    rows.iter().find(|r| r.kind == "agent" && r.id == agent)
}

/// The local peer behind a listed device: by overlay node id, else by the
/// backing agent id. `roomler devices` fills its CONN column with this.
pub fn peer_for_device<'a>(r: &DeviceRowLite, peers: &'a [PeerInfo]) -> Option<&'a PeerInfo> {
    if let Some(node) = r.overlay_node_id.as_deref()
        && !node.is_empty()
        && let Some(p) = peers.iter().find(|p| p.node_id == node)
    {
        return Some(p);
    }
    if r.kind == "agent" && !r.id.is_empty() {
        return peers
            .iter()
            .find(|p| p.agent_id.as_deref() == Some(r.id.as_str()));
    }
    None
}

/// A peer together with the dashboard display name the device list knows for
/// it, if any.
#[derive(Debug, Clone)]
pub struct NamedPeer<'a> {
    pub peer: &'a PeerInfo,
    pub display_name: Option<String>,
}

impl NamedPeer<'_> {
    /// Whether `wanted` names this peer — its mesh name or its display name,
    /// case-insensitively. An empty mesh name (seen in the field) names
    /// nothing rather than matching an empty argument.
    fn is_named(&self, wanted: &str) -> bool {
        (!self.peer.name.is_empty() && eq_ci(&self.peer.name, wanted))
            || self
                .display_name
                .as_deref()
                .is_some_and(|d| eq_ci(d, wanted))
    }
}

/// Pair every peer with its display name, looked up in the device list of ITS
/// org — `rows_by_org` is keyed the way the peer rows are stamped (`""` for a
/// single-org daemon, else the enrollment label), and an org whose list was
/// unavailable is simply absent, leaving its peers unnamed.
pub fn name_peers<'a>(
    peers: &'a [PeerInfo],
    rows_by_org: &HashMap<String, Vec<DeviceRowLite>>,
) -> Vec<NamedPeer<'a>> {
    peers
        .iter()
        .map(|p| NamedPeer {
            peer: p,
            display_name: rows_by_org
                .get(&p.org)
                .and_then(|rows| row_for_peer(p, rows))
                .and_then(display_name_of)
                .map(str::to_string),
        })
        .collect()
}

/// `meshharbor peers NAME…` — keep the peers whose mesh name OR display name is
/// one of `wanted` (case-insensitive), **in the order of the arguments**:
/// every peer the first argument names (in list order — the same host can
/// appear once per shared org), then the next argument's. A peer two
/// arguments name appears once, under the first; an argument repeated is
/// counted once. Returns the kept rows and the arguments that named nothing.
pub fn filter_by_names<'a>(
    named: Vec<NamedPeer<'a>>,
    wanted: &[String],
) -> (Vec<NamedPeer<'a>>, Vec<String>) {
    let mut taken = vec![false; named.len()];
    let mut kept = Vec::new();
    let mut unmatched = Vec::new();
    for (i, w) in wanted.iter().enumerate() {
        if wanted[..i].iter().any(|earlier| eq_ci(earlier, w)) {
            continue;
        }
        let mut hit = false;
        for (j, n) in named.iter().enumerate() {
            if !n.is_named(w) {
                continue;
            }
            // A row an earlier argument already placed still counts as this
            // argument's match — it is shown, just not twice.
            hit = true;
            if !taken[j] {
                taken[j] = true;
                kept.push(n.clone());
            }
        }
        if !hit {
            unmatched.push(w.clone());
        }
    }
    (kept, unmatched)
}

/// What a resolved selector has to yield.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// `exec` / `ssh`: the hex agent id the server resolves — agents only; a
    /// tunnel client cannot run a command or serve a shell.
    AgentId,
    /// `ping`: a device with an overlay address.
    OverlayIp,
}

/// The verdict on a typed selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// Send the selector exactly as typed — a literal address, a hex id, a
    /// name the server or daemon resolves itself, or a display name nobody
    /// carries. Today's behaviour, including today's error.
    AsTyped,
    /// Exactly one eligible device carries that display name, and nothing the
    /// server or daemon resolves matches it.
    Device(&'a DeviceRowLite),
    /// Several eligible devices carry that display name. Refuse; never pick.
    Ambiguous(Vec<&'a DeviceRowLite>),
}

/// A selector that is already an answer: a literal IP (either family) or a
/// 24-hex ObjectId. Neither can be a display name worth translating, and a
/// caller may skip fetching the device list for one.
pub fn is_literal(target: &str) -> bool {
    target.parse::<IpAddr>().is_ok()
        || (target.len() == 24 && target.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Resolve `target` against the device list, by the precedence
/// `docs/device-naming.md` documents:
///
/// 1. a literal address or hex id → as typed;
/// 2. a listed device's fleet name, MagicDNS label or FQDN (case-insensitive,
///    whole or by first label, the way the daemon's resolver reads a dotted
///    name) → as typed — the server / daemon resolves it today and must keep
///    resolving it to the same device;
/// 3. an exact `display_name` match among the devices `need` can use: one →
///    that device, several → ambiguous;
/// 4. else a case-insensitive `display_name` match: one → that device, several
///    → ambiguous, none → as typed.
///
/// `rows == None` is "no device list" and resolves everything as typed.
pub fn resolve_selector<'a>(
    target: &str,
    rows: Option<&'a [DeviceRowLite]>,
    need: Need,
) -> Resolution<'a> {
    let Some(rows) = rows else {
        return Resolution::AsTyped;
    };
    if target.is_empty() || is_literal(target) {
        return Resolution::AsTyped;
    }
    if rows.iter().any(|r| is_resolvable_name(target, r)) {
        return Resolution::AsTyped;
    }
    let pick = |same: &dyn Fn(&str) -> bool| -> Vec<&'a DeviceRowLite> {
        rows.iter()
            .filter(|r| eligible(r, need))
            .filter(|r| display_name_of(r).is_some_and(same))
            .collect()
    };
    let exact = pick(&|d| d == target);
    match exact.len() {
        1 => return Resolution::Device(exact[0]),
        n if n > 1 => return Resolution::Ambiguous(exact),
        _ => {}
    }
    let folded = pick(&|d| eq_ci(d, target));
    match folded.len() {
        0 => Resolution::AsTyped,
        1 => Resolution::Device(folded[0]),
        _ => Resolution::Ambiguous(folded),
    }
}

/// The address `meshharbor ping` sends for a display-name-resolved device: its
/// overlay IPv4, or with `prefer_v6` the derived IPv6 the local peer view
/// publishes for it — falling back to the v4 when no v6 is published, exactly
/// as the daemon does for a name. `None` when the device has no address.
pub fn ping_address(row: &DeviceRowLite, peers: &[PeerInfo], prefer_v6: bool) -> Option<String> {
    let v4 = row.overlay_ip.as_deref().filter(|ip| !ip.is_empty())?;
    if prefer_v6 && let Some(v6) = peer_for_device(row, peers).and_then(|p| p.overlay_ip6.clone()) {
        return Some(v6);
    }
    Some(v4.to_string())
}

/// The refusal for an ambiguous display name: what was typed, how many carry
/// it, and what to type instead — never a choice made for the caller.
pub fn ambiguity_error(target: &str, rows: &[&DeviceRowLite]) -> anyhow::Error {
    let candidates: Vec<String> = rows
        .iter()
        .map(|r| {
            let name = if r.name.is_empty() {
                "unnamed"
            } else {
                &r.name
            };
            match r.overlay_ip.as_deref().filter(|ip| !ip.is_empty()) {
                Some(ip) => format!("{name} ({}, {ip})", r.id),
                None => format!("{name} ({})", r.id),
            }
        })
        .collect();
    anyhow::anyhow!(
        "{target:?} is the display name of {} devices, and this command will not guess \
         which — use the device name or hex id instead: {}",
        rows.len(),
        candidates.join(" | ")
    )
}

/// Whether the server or the daemon would resolve `target` to `row` on its
/// own: its fleet name, its MagicDNS label or its FQDN, case-insensitively,
/// against the whole selector or its first label (a dotted `ping` target is
/// read by its first label by the daemon). Generous on purpose — a false
/// `true` only means "send as typed", which is today's behaviour, while a
/// false `false` would let a display name shadow a real name.
fn is_resolvable_name(target: &str, row: &DeviceRowLite) -> bool {
    let bare = target
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or(target);
    std::iter::once(row.name.as_str())
        .chain(row.magic_dns_name.as_deref())
        .chain(row.magic_dns_fqdn.as_deref())
        .filter(|k| !k.is_empty())
        .any(|k| eq_ci(k, target) || eq_ci(k, bare))
}

/// Whether `need` can be answered with `row` at all.
fn eligible(row: &DeviceRowLite, need: Need) -> bool {
    match need {
        Need::AgentId => row.kind == "agent" && !row.id.is_empty(),
        Need::OverlayIp => row.overlay_ip.as_deref().is_some_and(|ip| !ip.is_empty()),
    }
}

/// Case-insensitive equality with Unicode folding — display names are free
/// text an admin typed, not ASCII identifiers.
fn eq_ci(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_core::localapi::ConnectionType;

    fn peer(node: &str, name: &str, org: &str) -> PeerInfo {
        let mut p: PeerInfo = serde_json::from_str(
            r#"{"node_id":"x","name":"x","online":true,"connection":"direct"}"#,
        )
        .unwrap();
        p.node_id = node.into();
        p.name = name.into();
        p.org = org.into();
        p.connection = ConnectionType::Direct;
        p
    }

    fn row(id: &str, name: &str, display: Option<&str>) -> DeviceRowLite {
        DeviceRowLite {
            kind: "agent".into(),
            id: id.into(),
            name: name.into(),
            display_name: display.map(str::to_string),
            os: "linux".into(),
            presence: "online".into(),
            is_online: true,
            overlay_ip: Some(format!("100.64.0.{}", id.len())),
            overlay_node_id: Some(format!("node-{name}")),
            magic_dns_name: Some(name.into()),
            ..Default::default()
        }
    }

    const LAPTOP: &str = "aaaaaaaaaaaaaaaaaaaaaaa1";
    const HOME_SERVER: &str = "aaaaaaaaaaaaaaaaaaaaaaa2";
    const BUILD_BOX: &str = "aaaaaaaaaaaaaaaaaaaaaaa3";
    const OFFICE_PC: &str = "aaaaaaaaaaaaaaaaaaaaaaa4";

    fn fleet() -> Vec<DeviceRowLite> {
        vec![
            row(LAPTOP, "laptop", Some("Travel Laptop")),
            row(HOME_SERVER, "home-server", None),
            row(BUILD_BOX, "build-box", Some("   ")),
            row(OFFICE_PC, "office-pc", Some("Office PC")),
        ]
    }

    // ── the join ───────────────────────────────────────────────────────────

    /// The NAME column reads the display name through the same two join keys
    /// `roomler devices` uses the other way round — node id first, then the
    /// backing agent id — and a blank label is no label.
    #[test]
    fn peers_are_named_by_node_id_then_agent_id_and_blank_labels_are_none() {
        let rows = fleet();
        let by_node = peer("node-laptop", "laptop", "");
        assert_eq!(
            row_for_peer(&by_node, &rows).map(|r| r.id.as_str()),
            Some(LAPTOP)
        );

        let mut by_agent = peer("unknown-node", "laptop", "");
        by_agent.agent_id = Some(LAPTOP.into());
        assert_eq!(
            row_for_peer(&by_agent, &rows).map(|r| r.id.as_str()),
            Some(LAPTOP)
        );

        let stranger = peer("no-such-node", "stranger", "");
        assert!(row_for_peer(&stranger, &rows).is_none());

        let mut by_org = HashMap::new();
        by_org.insert(String::new(), rows);
        let peers = vec![
            peer("node-laptop", "laptop", ""),
            peer("node-home-server", "home-server", ""),
            peer("node-build-box", "build-box", ""),
        ];
        let named = name_peers(&peers, &by_org);
        assert_eq!(named[0].display_name.as_deref(), Some("Travel Laptop"));
        assert_eq!(named[1].display_name, None, "no display name set");
        assert_eq!(named[2].display_name, None, "a blank label is no label");
    }

    /// Each org section is joined against ITS OWN device list — the same node
    /// id never crosses orgs, and an org whose list failed leaves its peers
    /// on their mesh names rather than borrowing another org's labels.
    #[test]
    fn the_join_is_per_org_and_a_missing_list_leaves_mesh_names() {
        let mut by_org = HashMap::new();
        by_org.insert("primary".to_string(), fleet());
        // The secondary's list never arrived.
        let peers = vec![
            peer("node-laptop", "laptop", "primary"),
            peer("node-laptop", "laptop", "acme"),
        ];
        let named = name_peers(&peers, &by_org);
        assert_eq!(named[0].display_name.as_deref(), Some("Travel Laptop"));
        assert_eq!(named[1].display_name, None);
    }

    // ── the filter ─────────────────────────────────────────────────────────

    #[test]
    fn filter_keeps_argument_order_matches_either_name_case_insensitively() {
        let mut by_org = HashMap::new();
        by_org.insert(String::new(), fleet());
        let peers = vec![
            peer("node-laptop", "laptop", ""),
            peer("node-home-server", "home-server", ""),
            peer("node-office-pc", "office-pc", ""),
        ];
        let named = name_peers(&peers, &by_org);

        // Display name, then mesh name — rows come out in ARGUMENT order, not
        // list order, and both spellings fold case.
        let (kept, unmatched) = filter_by_names(
            named.clone(),
            &["office pc".to_string(), "LAPTOP".to_string()],
        );
        let names: Vec<&str> = kept.iter().map(|n| n.peer.name.as_str()).collect();
        assert_eq!(names, ["office-pc", "laptop"]);
        assert!(unmatched.is_empty());

        // An argument nobody carries is reported, the rest still match; a peer
        // named twice (mesh name AND display name) appears once, under the
        // first argument; a repeated argument is not a second miss.
        let (kept, unmatched) = filter_by_names(
            named,
            &[
                "Travel Laptop".to_string(),
                "ghost".to_string(),
                "laptop".to_string(),
                "GHOST".to_string(),
            ],
        );
        let names: Vec<&str> = kept.iter().map(|n| n.peer.name.as_str()).collect();
        assert_eq!(names, ["laptop"]);
        assert_eq!(unmatched, ["ghost"]);
    }

    /// Without a device list the filter still works on mesh names — and a
    /// display name then matches nothing, which the caller reports.
    #[test]
    fn filter_without_a_device_list_matches_mesh_names_only() {
        let peers = vec![peer("node-laptop", "laptop", "")];
        let named = name_peers(&peers, &HashMap::new());
        let (kept, unmatched) =
            filter_by_names(named, &["laptop".to_string(), "Travel Laptop".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(unmatched, ["Travel Laptop"]);

        // Nothing matched at all: the caller exits non-zero on an empty keep.
        let peers = vec![peer("node-laptop", "laptop", "")];
        let named = name_peers(&peers, &HashMap::new());
        let (kept, unmatched) = filter_by_names(named, &["nobody".to_string()]);
        assert!(kept.is_empty());
        assert_eq!(unmatched, ["nobody"]);
    }

    /// The same host enrolled in two orgs appears once per org under the same
    /// mesh name; one argument keeps BOTH rows (the org header tells them
    /// apart), rather than silently dropping one.
    #[test]
    fn filter_keeps_every_peer_an_argument_names_across_orgs() {
        let peers = vec![
            peer("n1", "laptop", "primary"),
            peer("n2", "home-server", "primary"),
            peer("n3", "laptop", "acme"),
        ];
        let named = name_peers(&peers, &HashMap::new());
        let (kept, _) = filter_by_names(named, &["laptop".to_string()]);
        let orgs: Vec<&str> = kept.iter().map(|n| n.peer.org.as_str()).collect();
        assert_eq!(orgs, ["primary", "acme"]);
    }

    // ── the selector ───────────────────────────────────────────────────────

    #[test]
    fn literals_are_never_translated_even_when_a_display_name_collides() {
        let mut rows = fleet();
        // An admin who labels a device with another device's id or address is
        // not asking for every command typed with that id to be rerouted.
        rows[0].display_name = Some(HOME_SERVER.into());
        rows[1].display_name = Some("100.64.0.9".into());
        for literal in [HOME_SERVER, "100.64.0.9", "fd72:6f6f:6d6c::6440:9"] {
            assert_eq!(
                resolve_selector(literal, Some(&rows), Need::AgentId),
                Resolution::AsTyped,
                "{literal}"
            );
            assert_eq!(
                resolve_selector(literal, Some(&rows), Need::OverlayIp),
                Resolution::AsTyped,
                "{literal}"
            );
        }
        assert!(is_literal("AAAAAAAAAAAAAAAAAAAAAAA1"));
        assert!(
            !is_literal("aaaaaaaaaaaaaaaaaaaaaaa"),
            "23 hex digits is a name"
        );
        assert!(!is_literal("laptop"));
    }

    /// The load-bearing rule: a fleet name or MagicDNS label the server /
    /// daemon resolves today wins over ANY display name, in any case, so the
    /// selector keeps meaning the device it meant yesterday.
    #[test]
    fn a_real_name_or_label_beats_a_display_name_and_goes_as_typed() {
        let mut rows = fleet();
        // Device A's display name is device B's fleet name.
        rows[3].display_name = Some("home-server".into());
        for typed in ["home-server", "HOME-SERVER", "Home-Server"] {
            assert_eq!(
                resolve_selector(typed, Some(&rows), Need::AgentId),
                Resolution::AsTyped,
                "{typed}: the server resolves this name itself"
            );
            assert_eq!(
                resolve_selector(typed, Some(&rows), Need::OverlayIp),
                Resolution::AsTyped,
                "{typed}: the daemon resolves this label itself"
            );
        }
        // Qualified spellings of a label — the daemon reads the first label;
        // the FQDN is the label too.
        rows[1].magic_dns_fqdn = Some("home-server.acme.roomler.net".into());
        for typed in [
            "home-server.acme.roomler.net",
            "HOME-SERVER.acme.roomler.net.",
            "home-server.roomler",
        ] {
            assert_eq!(
                resolve_selector(typed, Some(&rows), Need::OverlayIp),
                Resolution::AsTyped,
                "{typed}"
            );
        }
    }

    #[test]
    fn a_unique_display_name_resolves_and_exact_beats_case_insensitive() {
        let mut rows = fleet();
        assert_eq!(
            resolve_selector("Office PC", Some(&rows), Need::AgentId),
            Resolution::Device(&rows[3])
        );
        assert_eq!(
            resolve_selector("office pc", Some(&rows), Need::OverlayIp),
            Resolution::Device(&rows[3]),
            "a lone case-insensitive match resolves"
        );
        // Two devices differ only by case: the exact spelling picks one, the
        // other spelling picks the other, and a third spelling is ambiguous.
        rows[1].display_name = Some("office pc".into());
        assert_eq!(
            resolve_selector("Office PC", Some(&rows), Need::AgentId),
            Resolution::Device(&rows[3])
        );
        assert_eq!(
            resolve_selector("office pc", Some(&rows), Need::AgentId),
            Resolution::Device(&rows[1])
        );
        assert_eq!(
            resolve_selector("OFFICE PC", Some(&rows), Need::AgentId),
            Resolution::Ambiguous(vec![&rows[1], &rows[3]])
        );
    }

    #[test]
    fn a_shared_display_name_is_refused_and_the_refusal_names_the_candidates() {
        let mut rows = fleet();
        rows[0].display_name = Some("Office PC".into());
        let verdict = resolve_selector("Office PC", Some(&rows), Need::AgentId);
        let Resolution::Ambiguous(c) = verdict else {
            panic!("expected a refusal, got {verdict:?}");
        };
        assert_eq!(c.len(), 2);
        let msg = ambiguity_error("Office PC", &c).to_string();
        assert!(msg.contains(LAPTOP) && msg.contains(OFFICE_PC), "{msg}");
        assert!(msg.contains("laptop") && msg.contains("office-pc"), "{msg}");
        assert!(msg.contains("will not guess"), "{msg}");
    }

    /// Eligibility is applied BEFORE uniqueness: a tunnel client sharing a
    /// label with an agent cannot run a command, so it is not a second
    /// candidate for `exec` — but it IS one for `ping` when it has an address.
    #[test]
    fn only_devices_the_command_can_use_count_as_candidates() {
        let mut rows = fleet();
        rows[1].kind = "tunnel_client".into();
        rows[1].display_name = Some("Office PC".into());
        assert_eq!(
            resolve_selector("Office PC", Some(&rows), Need::AgentId),
            Resolution::Device(&rows[3])
        );
        assert!(matches!(
            resolve_selector("Office PC", Some(&rows), Need::OverlayIp),
            Resolution::Ambiguous(_)
        ));
        // A device with no overlay address cannot be pinged by display name.
        rows[1].kind = "agent".into();
        rows[1].display_name = Some("Dark Box".into());
        rows[1].overlay_ip = None;
        assert_eq!(
            resolve_selector("Dark Box", Some(&rows), Need::OverlayIp),
            Resolution::AsTyped
        );
        assert_eq!(
            resolve_selector("Dark Box", Some(&rows), Need::AgentId),
            Resolution::Device(&rows[1])
        );
    }

    #[test]
    fn no_list_or_no_match_goes_as_typed() {
        assert_eq!(
            resolve_selector("Office PC", None, Need::AgentId),
            Resolution::AsTyped,
            "no device list: behave exactly as today"
        );
        let rows = fleet();
        assert_eq!(
            resolve_selector("nobody", Some(&rows), Need::AgentId),
            Resolution::AsTyped,
            "unknown: the server's own error appears"
        );
        assert_eq!(
            resolve_selector("", Some(&rows), Need::AgentId),
            Resolution::AsTyped
        );
        assert_eq!(
            resolve_selector("Office PC", Some(&[]), Need::OverlayIp),
            Resolution::AsTyped
        );
    }

    /// `-6` sends the derived IPv6 the local peer view publishes for the
    /// device, found by the same join; without one the v4 goes, as the
    /// daemon itself falls back for a name.
    #[test]
    fn ping_address_is_v4_or_the_published_v6() {
        let rows = fleet();
        let office = &rows[3];
        let mut p = peer("node-office-pc", "office-pc", "");
        p.overlay_ip6 = Some("fd72:6f6f:6d6c::6440:18".into());
        assert_eq!(
            ping_address(office, &[p.clone()], false).as_deref(),
            office.overlay_ip.as_deref()
        );
        assert_eq!(
            ping_address(office, &[p.clone()], true).as_deref(),
            Some("fd72:6f6f:6d6c::6440:18")
        );
        p.overlay_ip6 = None;
        assert_eq!(
            ping_address(office, &[p], true).as_deref(),
            office.overlay_ip.as_deref(),
            "no published v6: the v4 goes"
        );
        assert_eq!(
            ping_address(office, &[], true).as_deref(),
            office.overlay_ip.as_deref(),
            "peer not in the local view: the v4 goes"
        );
        let mut dark = rows[1].clone();
        dark.overlay_ip = None;
        assert_eq!(ping_address(&dark, &[], false), None);
    }
}
