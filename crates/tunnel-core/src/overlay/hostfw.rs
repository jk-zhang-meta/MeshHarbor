// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3i — what the host's own firewall lets a mesh peer reach on this
//! node's overlay address.
//!
//! Measured (FR-97 §8, 2026-10-17): carriers pass a host firewall. A
//! hole-punched path (a Fedora host, firewalld's `FedoraServer` zone) and a
//! LAN-direct one (`tier=Lan`, firewalld's `public` zone) both ride conntrack,
//! because both ends probe. But the overlay adapter sits in no zone, so the
//! firewall's default zone governs it, as ufw's default incoming policy does,
//! and a service listening on the overlay address is refused unless the
//! firewall admits it. Putting the adapter in `trusted` opened exactly the
//! mesh and left the LAN as the zone said.
//!
//! The daemon does not change the firewall. It belongs to the host's owner,
//! and trusting the adapter would open every service on the host to every
//! peer the overlay ACL admits. Instead it says what governs the adapter, so a
//! refusal in `meshharbor status` has a cause. Roomler's own services do not need
//! it: roomler SSH is intercepted below the OS, and exec, remote control and
//! tunnels ride the daemon's own connections.
//!
//! The parsers are pure and tested on every OS. Only [`probe`] runs commands,
//! and only on Linux.

// Off Linux only the tests read the parsers.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::localapi::HostFirewallStatus;

/// The parts of firewalld's `--info-zone` output that decide what a peer
/// reaches.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ZoneInfo {
    pub(crate) target: String,
    pub(crate) services: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) protocols: Vec<String>,
    /// Rich rules can admit more than the lists say; they are counted, not
    /// interpreted.
    pub(crate) rich_rules: usize,
}

/// Parse `firewall-cmd --info-zone=<zone>`. `None` when there is no
/// `target:` line, which every zone prints. Pure.
pub(crate) fn parse_info_zone(text: &str) -> Option<ZoneInfo> {
    let mut zone = ZoneInfo::default();
    let mut has_target = false;
    let mut in_rich_rules = false;
    for line in text.lines() {
        let line = line.trim();
        // Rich rules follow their key one per line, and may hold colons.
        if in_rich_rules && line.starts_with("rule ") {
            zone.rich_rules += 1;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        in_rich_rules = false;
        let words = || value.split_whitespace().map(str::to_string).collect();
        match key.trim() {
            "target" => {
                zone.target = value.trim().to_string();
                has_target = true;
            }
            "services" => zone.services = words(),
            "ports" => zone.ports = words(),
            "protocols" => zone.protocols = words(),
            "rich rules" => {
                in_rich_rules = true;
                if value.trim().starts_with("rule ") {
                    zone.rich_rules += 1;
                }
            }
            _ => {}
        }
    }
    has_target.then_some(zone)
}

/// What a firewalld zone means for the adapter. A zone whose target is
/// `ACCEPT` (`trusted`) admits everything; any other target (`default`,
/// `%%REJECT%%`, `DROP`) admits only its services, ports and protocols. Pure.
pub(crate) fn firewalld_status(
    interface: &str,
    zone: &str,
    zone_is_default: bool,
    info: &ZoneInfo,
) -> HostFirewallStatus {
    HostFirewallStatus {
        kind: "firewalld".into(),
        interface: interface.into(),
        zone: Some(zone.into()),
        zone_is_default,
        admits_all: info.target.eq_ignore_ascii_case("ACCEPT"),
        admits: info
            .services
            .iter()
            .chain(&info.ports)
            .chain(&info.protocols)
            .cloned()
            .chain((info.rich_rules > 0).then(|| match info.rich_rules {
                1 => "1 rich rule".to_string(),
                n => format!("{n} rich rules"),
            }))
            .collect(),
    }
}

/// One ufw ALLOW (or LIMIT) rule for incoming traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UfwAllow {
    /// What it admits: `22/tcp`, `8080`, or `Anywhere`.
    pub(crate) to: String,
    /// The interface it is written for; `None` = every interface.
    pub(crate) on: Option<String>,
    /// The source it is limited to; `None` = `Anywhere`.
    pub(crate) from: Option<String>,
}

/// `ufw status verbose`, active: the default incoming policy (`deny`,
/// `reject` or `allow`) and its incoming ALLOW rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UfwInfo {
    pub(crate) incoming: String,
    pub(crate) allows: Vec<UfwAllow>,
}

/// Parse `ufw status verbose`. `None` while ufw is inactive. Pure.
pub(crate) fn parse_ufw_status(text: &str) -> Option<UfwInfo> {
    let mut lines = text.lines().map(str::trim);
    if !lines.any(|l| l.eq_ignore_ascii_case("Status: active")) {
        return None;
    }
    let mut incoming = String::new();
    let mut allows = Vec::new();
    let mut in_table = false;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("Default:") {
            // "deny (incoming), allow (outgoing), deny (routed)"
            incoming = rest
                .split(',')
                .find(|p| p.contains("(incoming)"))
                .map(|p| p.replace("(incoming)", "").trim().to_string())
                .unwrap_or_default();
        } else if line.starts_with("--") {
            in_table = true;
        } else if in_table && !line.is_empty() {
            // Columns are separated by runs of spaces: To, Action, From.
            let cols: Vec<&str> = line
                .split("  ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            let (Some(to), Some(action)) = (cols.first(), cols.get(1)) else {
                continue;
            };
            let action = action.to_ascii_uppercase();
            let allows_in = (action.starts_with("ALLOW") || action.starts_with("LIMIT"))
                && !action.contains("OUT")
                && !action.contains("FWD");
            if !allows_in {
                continue;
            }
            let to = to.replace("(v6)", "");
            let (to, on) = match to.split_once(" on ") {
                Some((t, iface)) => (t.trim().to_string(), Some(iface.trim().to_string())),
                None => (to.trim().to_string(), None),
            };
            let from = cols
                .get(2)
                .map(|f| f.replace("(v6)", "").trim().to_string())
                .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("Anywhere"));
            let rule = UfwAllow { to, on, from };
            if !allows.contains(&rule) {
                allows.push(rule);
            }
        }
    }
    Some(UfwInfo { incoming, allows })
}

/// What ufw means for the adapter: its rules for every interface, plus those
/// written for this one. An unrestricted `Anywhere` rule for the adapter
/// (`ufw allow in on roomler0`) admits everything, as an `allow` default
/// does. Pure.
pub(crate) fn ufw_status(interface: &str, info: &UfwInfo) -> HostFirewallStatus {
    let mut admits_all = info.incoming.eq_ignore_ascii_case("allow");
    let mut admits: Vec<String> = Vec::new();
    for rule in &info.allows {
        // A rule written for another adapter does not reach this one.
        if rule.on.as_deref().is_some_and(|i| i != interface) {
            continue;
        }
        if rule.to.eq_ignore_ascii_case("Anywhere") && rule.from.is_none() {
            admits_all = true;
        }
        let entry = match &rule.from {
            Some(from) => format!("{} from {from}", rule.to),
            None => rule.to.clone(),
        };
        if !admits.contains(&entry) {
            admits.push(entry);
        }
    }
    HostFirewallStatus {
        kind: "ufw".into(),
        interface: interface.into(),
        zone: None,
        zone_is_default: false,
        admits_all,
        admits,
    }
}

/// What the host's firewall lets a mesh peer reach on `interface`, or `None`
/// when neither firewalld nor ufw is active here (or this process may not
/// ask). firewalld first, as a host runs one or the other.
#[cfg(target_os = "linux")]
pub async fn probe(interface: &str) -> Option<HostFirewallStatus> {
    match probe_firewalld(interface).await {
        Some(status) => Some(status),
        None => probe_ufw(interface).await,
    }
}

/// Off Linux there is nothing to ask yet: macOS's Application Firewall
/// passes forwarded traffic (FR-97 §8) and filters per application, and
/// Windows has its own Defender rule (`winfw`).
#[cfg(not(target_os = "linux"))]
pub async fn probe(_interface: &str) -> Option<HostFirewallStatus> {
    None
}

#[cfg(target_os = "linux")]
async fn probe_firewalld(interface: &str) -> Option<HostFirewallStatus> {
    let (ok, state) = capture(&["firewall-cmd", "--state"]).await;
    if !ok || state.trim() != "running" {
        return None;
    }
    // `no zone` (exit 2) means the default zone governs the adapter.
    let (ok, zone) = capture(&[
        "firewall-cmd",
        &format!("--get-zone-of-interface={interface}"),
    ])
    .await;
    let (zone, zone_is_default) = if ok && !zone.trim().is_empty() {
        (zone.trim().to_string(), false)
    } else {
        let (ok, default) = capture(&["firewall-cmd", "--get-default-zone"]).await;
        if !ok || default.trim().is_empty() {
            return None;
        }
        (default.trim().to_string(), true)
    };
    let (ok, info) = capture(&["firewall-cmd", &format!("--info-zone={zone}")]).await;
    if !ok {
        return None;
    }
    let info = parse_info_zone(&info)?;
    Some(firewalld_status(interface, &zone, zone_is_default, &info))
}

#[cfg(target_os = "linux")]
async fn probe_ufw(interface: &str) -> Option<HostFirewallStatus> {
    // Needs root: a per-user daemon gets "You need to be root" and reports
    // nothing, rather than a guess.
    let (ok, out) = capture(&["ufw", "status", "verbose"]).await;
    if !ok {
        return None;
    }
    let info = parse_ufw_status(&out)?;
    Some(ufw_status(interface, &info))
}

/// Run a read-only firewall query: `(exit 0, stdout)`. A missing binary, a
/// failure or a hang past five seconds reads as `(false, "")`.
#[cfg(target_os = "linux")]
async fn capture(args: &[&str]) -> (bool, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let run = tokio::task::spawn_blocking(move || {
        match std::process::Command::new(&args[0])
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .output()
        {
            Ok(o) => (
                o.status.success(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
            ),
            Err(_) => (false, String::new()),
        }
    });
    match tokio::time::timeout(std::time::Duration::from_secs(5), run).await {
        Ok(Ok(result)) => result,
        _ => (false, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// firewalld 1.1.1's own output (a throwaway container, 2026-10-17).
    const PUBLIC: &str = "public\n  target: default\n  icmp-block-inversion: no\n  interfaces: \n  sources: \n  services: dhcpv6-client ssh\n  ports: \n  protocols: \n  forward: yes\n  masquerade: no\n  forward-ports: \n  source-ports: \n  icmp-blocks: \n  rich rules: \n";
    const TRUSTED: &str = "trusted (active)\n  target: ACCEPT\n  icmp-block-inversion: no\n  interfaces: roomler0\n  sources: \n  services: \n  ports: \n  protocols: \n  forward: yes\n  masquerade: no\n";

    #[test]
    fn a_default_zone_admits_only_its_services() {
        let info = parse_info_zone(PUBLIC).unwrap();
        assert_eq!(info.target, "default");
        assert_eq!(info.services, ["dhcpv6-client", "ssh"]);
        assert!(info.ports.is_empty());
        let s = firewalld_status("roomler0", "public", true, &info);
        assert_eq!(s.kind, "firewalld");
        assert_eq!(s.zone.as_deref(), Some("public"));
        assert!(s.zone_is_default);
        assert!(!s.admits_all);
        assert_eq!(s.admits, ["dhcpv6-client", "ssh"]);
    }

    #[test]
    fn a_trusted_zone_admits_everything() {
        let info = parse_info_zone(TRUSTED).unwrap();
        let s = firewalld_status("roomler0", "trusted", false, &info);
        assert!(s.admits_all);
        assert!(!s.zone_is_default);
        assert!(s.admits.is_empty());
    }

    #[test]
    fn a_zone_with_ports_and_protocols_lists_them() {
        let text = "work\n  target: %%REJECT%%\n  services: ssh\n  ports: 8080/tcp 5353/udp\n  protocols: icmp\n";
        let s = firewalld_status("roomler0", "work", false, &parse_info_zone(text).unwrap());
        assert!(!s.admits_all);
        assert_eq!(s.admits, ["ssh", "8080/tcp", "5353/udp", "icmp"]);
    }

    #[test]
    fn output_with_no_target_is_no_zone() {
        assert_eq!(parse_info_zone(""), None);
        assert_eq!(parse_info_zone("Error: INVALID_ZONE: nope\n"), None);
    }

    /// ufw 0.36.1's own output (a throwaway container, 2026-10-17).
    const UFW_ACTIVE: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere                  \n8080/tcp on roomler0       ALLOW IN    Anywhere                  \n9000/tcp on eth0           ALLOW IN    Anywhere                  \n53                         DENY IN     Anywhere                  \n22/tcp (v6)                ALLOW IN    Anywhere (v6)             \n8080/tcp (v6) on roomler0  ALLOW IN    Anywhere (v6)             \n";

    #[test]
    fn ufw_admits_its_rules_for_every_interface_and_for_ours() {
        let info = parse_ufw_status(UFW_ACTIVE).unwrap();
        assert_eq!(info.incoming, "deny");
        let s = ufw_status("roomler0", &info);
        assert_eq!(s.kind, "ufw");
        assert!(!s.admits_all);
        // Not eth0's rule, not the DENY, and each v6 twin once.
        assert_eq!(s.admits, ["22/tcp", "8080/tcp"]);
        // Another adapter does not get roomler0's rule.
        assert_eq!(ufw_status("roomler1", &info).admits, ["22/tcp"]);
    }

    #[test]
    fn an_inactive_ufw_says_nothing_and_allow_by_default_admits_all() {
        assert_eq!(parse_ufw_status("Status: inactive\n"), None);
        let allow =
            "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n";
        assert!(ufw_status("roomler0", &parse_ufw_status(allow).unwrap()).admits_all);
    }

    /// `ufw allow in on roomler0` is how a ufw host opens the mesh, and it
    /// must read as open; a rule limited to a source keeps its source.
    #[test]
    fn ufw_open_on_the_adapter_admits_all_and_a_source_stays_attached() {
        let text = "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n\nTo                         Action      From\n--                         ------      ----\nAnywhere on roomler0       ALLOW IN    Anywhere                  \n5432/tcp                   ALLOW IN    10.0.0.0/8                \n";
        let info = parse_ufw_status(text).unwrap();
        let ours = ufw_status("roomler0", &info);
        assert!(ours.admits_all);
        assert_eq!(ours.admits, ["Anywhere", "5432/tcp from 10.0.0.0/8"]);
        let other = ufw_status("roomler1", &info);
        assert!(!other.admits_all);
        assert_eq!(other.admits, ["5432/tcp from 10.0.0.0/8"]);
    }

    #[test]
    fn rich_rules_are_counted_not_interpreted() {
        let text = "public\n  target: default\n  services: ssh\n  rich rules: \n\trule family=\"ipv4\" source address=\"100.64.0.0/10\" accept\n\trule family=\"ipv6\" source address=\"fd72::/16\" port port=\"8080\" protocol=\"tcp\" accept\n";
        let info = parse_info_zone(text).unwrap();
        assert_eq!(info.rich_rules, 2);
        assert_eq!(info.services, ["ssh"]);
        let s = firewalld_status("roomler0", "public", true, &info);
        assert_eq!(s.admits, ["ssh", "2 rich rules"]);
    }
}
