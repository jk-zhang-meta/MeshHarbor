// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #19 (v039 §4): the read-only network inventory a node reports.
//!
//! Interfaces, routes, policy rules, listeners, forwarding flags and
//! firewall/NAT state, as bounded and normalized facts: no command lines,
//! environment, keys, payloads or raw conntrack. The node reports what it
//! READ; nothing here is a desired state, and a reported rule is never
//! evidence that a remote peer can use it.
//!
//! Every section says how complete it is. `complete` means every item the
//! node saw is in `items`; a capped section is `partial` with the real
//! `total`, and [`NetInventory::validate`] rejects a `complete` section whose
//! count disagrees, so a truncated snapshot can never pass for a whole one.
//!
//! A large snapshot travels in up to [`MAX_PAGES`] pages of one `seq`
//! ([`NetInventory::split`] / [`NetInventory::merge`]): page 0 carries the
//! section states, totals and flags, and every page carries a run of items.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_PAGES: u16 = 16;
pub const MAX_ITEMS_PER_PAGE: usize = 1024;
pub const MAX_INTERFACES: usize = 256;
pub const MAX_ADDRS_PER_INTERFACE: usize = 64;
pub const MAX_ROUTES: usize = 4096;
pub const MAX_RULES: usize = 512;
pub const MAX_LISTENERS: usize = 2048;
pub const MAX_FIREWALL_CHAINS: usize = 512;
pub const MAX_FIREWALL_RULES: usize = 4096;
/// Any single string field (names, selectors, match summaries).
pub const MAX_STR: usize = 160;
pub const MAX_BOOT_ID: usize = 64;

/// How much of a section the node could read.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SectionState {
    /// Every item seen is in `items`.
    #[default]
    Complete,
    /// Capped or partly unreadable: `total` is what was seen.
    Partial,
    /// This platform or backend has no such facility.
    Unsupported,
    /// The facility exists but the node may not read it.
    Denied,
    /// Reading failed (see `note`).
    Error,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
// `items` defaults to empty, which needs no `T: Default` (serde would add it).
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Section<T> {
    pub state: SectionState,
    /// Items the node saw; more than `items.len()` only when `partial`.
    pub total: u32,
    #[serde(default)]
    pub items: Vec<T>,
    /// A short reason for a state other than `complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// An empty, complete section (not `T: Default`, which a derive would need).
impl<T> Default for Section<T> {
    fn default() -> Self {
        Section {
            state: SectionState::Complete,
            total: 0,
            items: Vec::new(),
            note: None,
        }
    }
}

impl<T> Section<T> {
    /// A section of `items` capped at `cap`: `partial` past it.
    pub fn capped(mut items: Vec<T>, cap: usize) -> Self {
        let total = items.len();
        items.truncate(cap);
        Section {
            state: if total > cap {
                SectionState::Partial
            } else {
                SectionState::Complete
            },
            total: total as u32,
            items,
            note: (total > cap).then(|| format!("capped at {cap}")),
        }
    }

    /// An empty section in a non-complete `state`.
    pub fn absent(state: SectionState, note: impl Into<String>) -> Self {
        let mut note: String = note.into();
        truncate_str(&mut note, MAX_STR);
        Section {
            state,
            total: 0,
            items: Vec::new(),
            note: Some(note),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V4,
    V6,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum L4 {
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    /// Link kind when the kernel names one (`wireguard`, `tun`, `bridge`,
    /// `veth`, `vlan`, ...); `None` for a plain device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Assigned addresses as `ip/prefix`.
    #[serde(default)]
    pub addrs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub family: Family,
    /// Table name (`main`, `local`) or number.
    pub table: String,
    /// `ip/prefix`, or `default`.
    pub dst: String,
    /// `unicast`, `local`, `blackhole`, `unreachable`, `prohibit`, ...
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub family: Family,
    pub priority: u32,
    /// The match, e.g. `from 10.0.0.0/8 iif eth0 fwmark 0x1` (`all` = none).
    pub selector: String,
    /// What a match does, e.g. `lookup main`, `blackhole`.
    pub action: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub proto: L4,
    pub addr: String,
    pub port: u16,
    /// The owning process's short name when the node may see it (never its
    /// command line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

/// Who manages a firewall object, so a foreign rule stays identifiable and
/// read-only rather than flattened into something MeshHarbor may edit.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallOwner {
    Meshharbor,
    Docker,
    Firewalld,
    Fail2ban,
    Libvirt,
    Kubernetes,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FirewallChain {
    /// `nftables` (iptables-nft rules appear here too) or `iptables-legacy`.
    pub backend: String,
    pub family: String,
    pub table: String,
    pub name: String,
    /// Base chains only: the hook, type, priority and default policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub owner: FirewallOwner,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FirewallRule {
    pub backend: String,
    pub family: String,
    pub table: String,
    pub chain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<u64>,
    /// A bounded summary of the rule's matches (`iifname eth0 tcp dport 443`).
    pub matches: String,
    /// `accept`, `drop`, `reject`, `jump X`, `goto X`, `return`, `dnat`,
    /// `snat`, `masquerade`, `redirect`, `none` (counter only) or `other`.
    pub verdict: String,
    /// A NAT rule's rewrite target (`10.0.0.5:80`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub owner: FirewallOwner,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Forwarding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetInventory {
    /// `linux`, `windows`, `macos`.
    pub os: String,
    /// Which network namespaces were read: `host_only` until the collector
    /// enters others. Container and other namespaces are NOT covered then.
    pub namespaces: String,
    #[serde(default)]
    pub forwarding: Forwarding,
    #[serde(default)]
    pub interfaces: Section<Interface>,
    #[serde(default)]
    pub routes: Section<Route>,
    #[serde(default)]
    pub rules: Section<Rule>,
    #[serde(default)]
    pub listeners: Section<Listener>,
    #[serde(default)]
    pub firewall_chains: Section<FirewallChain>,
    #[serde(default)]
    pub firewall_rules: Section<FirewallRule>,
}

/// Cut `s` to at most `max` bytes on a char boundary.
pub fn truncate_str(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
}

fn check_str(what: &str, s: &str) -> Result<(), String> {
    if s.len() > MAX_STR {
        return Err(format!("{what}: longer than {MAX_STR} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{what}: control character"));
    }
    Ok(())
}

fn check_opt(what: &str, s: &Option<String>) -> Result<(), String> {
    s.as_deref().map_or(Ok(()), |s| check_str(what, s))
}

fn check_cidr(what: &str, s: &str) -> Result<(), String> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, ""));
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("{what}: not an address: {s:?}"))?;
    if !prefix.is_empty() {
        let p: u8 = prefix
            .parse()
            .map_err(|_| format!("{what}: bad prefix: {s:?}"))?;
        if p > if ip.is_ipv4() { 32 } else { 128 } {
            return Err(format!("{what}: prefix out of range: {s:?}"));
        }
    }
    Ok(())
}

fn check_section<T>(
    what: &str,
    s: &Section<T>,
    cap: usize,
    item: impl Fn(&T) -> Result<(), String>,
) -> Result<(), String> {
    if s.items.len() > cap {
        return Err(format!("{what}: {} items, cap {cap}", s.items.len()));
    }
    if (s.total as usize) < s.items.len() {
        return Err(format!(
            "{what}: total {} below its {} items",
            s.total,
            s.items.len()
        ));
    }
    if s.state == SectionState::Complete && s.total as usize != s.items.len() {
        return Err(format!(
            "{what}: complete but {} of {} items",
            s.items.len(),
            s.total
        ));
    }
    if matches!(
        s.state,
        SectionState::Unsupported | SectionState::Denied | SectionState::Error
    ) && !s.items.is_empty()
    {
        return Err(format!("{what}: {:?} with items", s.state));
    }
    check_opt(what, &s.note)?;
    s.items.iter().try_for_each(item)
}

fn check_interface(i: &Interface) -> Result<(), String> {
    check_str("interface name", &i.name)?;
    check_opt("interface kind", &i.kind)?;
    if i.addrs.len() > MAX_ADDRS_PER_INTERFACE {
        return Err(format!("interface {}: too many addresses", i.name));
    }
    i.addrs
        .iter()
        .try_for_each(|a| check_cidr("interface address", a))
}

fn check_route(r: &Route) -> Result<(), String> {
    check_str("route table", &r.table)?;
    check_str("route kind", &r.kind)?;
    if r.dst != "default" {
        check_cidr("route dst", &r.dst)?;
    }
    if let Some(g) = &r.gateway {
        check_cidr("route gateway", g)?;
    }
    check_opt("route dev", &r.dev)?;
    check_opt("route protocol", &r.protocol)
}

fn check_rule(r: &Rule) -> Result<(), String> {
    check_str("rule selector", &r.selector)?;
    check_str("rule action", &r.action)
}

fn check_listener(l: &Listener) -> Result<(), String> {
    l.addr
        .parse::<IpAddr>()
        .map_err(|_| format!("listener: not an address: {:?}", l.addr))?;
    check_opt("listener process", &l.process)
}

fn check_chain(c: &FirewallChain) -> Result<(), String> {
    for (w, s) in [
        ("backend", &c.backend),
        ("family", &c.family),
        ("table", &c.table),
        ("chain", &c.name),
    ] {
        check_str(w, s)?;
    }
    check_opt("hook", &c.hook)?;
    check_opt("chain type", &c.chain_type)?;
    check_opt("policy", &c.policy)
}

fn check_fw_rule(r: &FirewallRule) -> Result<(), String> {
    for (w, s) in [
        ("backend", &r.backend),
        ("family", &r.family),
        ("table", &r.table),
        ("chain", &r.chain),
        ("matches", &r.matches),
        ("verdict", &r.verdict),
    ] {
        check_str(w, s)?;
    }
    check_opt("target", &r.target)
}

/// Drop the items `check` refuses, marking the section `partial`.
fn retain_valid<T>(s: &mut Section<T>, check: fn(&T) -> Result<(), String>) {
    let before = s.items.len();
    s.items.retain(|i| check(i).is_ok());
    let dropped = before - s.items.len();
    if dropped > 0 {
        if s.state == SectionState::Complete {
            s.state = SectionState::Partial;
        }
        s.note = Some(format!("{dropped} unreadable items dropped"));
    }
}

impl NetInventory {
    /// The bounds and normal forms every accepted snapshot holds. The server
    /// rejects a snapshot that breaks one rather than trim it, so a node bug
    /// cannot become a silently partial picture.
    pub fn validate(&self) -> Result<(), String> {
        check_str("os", &self.os)?;
        check_str("namespaces", &self.namespaces)?;
        check_section(
            "interfaces",
            &self.interfaces,
            MAX_INTERFACES,
            check_interface,
        )?;
        check_section("routes", &self.routes, MAX_ROUTES, check_route)?;
        check_section("rules", &self.rules, MAX_RULES, check_rule)?;
        check_section("listeners", &self.listeners, MAX_LISTENERS, check_listener)?;
        check_section(
            "firewall_chains",
            &self.firewall_chains,
            MAX_FIREWALL_CHAINS,
            check_chain,
        )?;
        check_section(
            "firewall_rules",
            &self.firewall_rules,
            MAX_FIREWALL_RULES,
            check_fw_rule,
        )
    }

    /// The node's side of [`Self::validate`]: drop each item it would
    /// refuse (an address the kernel printed in a form we do not parse, an
    /// overlong name) and mark that section `partial`, so one odd entry
    /// costs that entry, not the whole snapshot.
    pub fn sanitize(&mut self) {
        truncate_str(&mut self.os, MAX_STR);
        truncate_str(&mut self.namespaces, MAX_STR);
        retain_valid(&mut self.interfaces, check_interface);
        retain_valid(&mut self.routes, check_route);
        retain_valid(&mut self.rules, check_rule);
        retain_valid(&mut self.listeners, check_listener);
        retain_valid(&mut self.firewall_chains, check_chain);
        retain_valid(&mut self.firewall_rules, check_fw_rule);
    }

    fn item_count(&self) -> usize {
        self.interfaces.items.len()
            + self.routes.items.len()
            + self.rules.items.len()
            + self.listeners.items.len()
            + self.firewall_chains.items.len()
            + self.firewall_rules.items.len()
    }

    /// Pages of at most `per_page` items each, in section order; page 0 keeps
    /// the states, totals and flags, later pages only items. At least one
    /// page, at most [`MAX_PAGES`]: a snapshot that would need more is cut
    /// to fit and its cut sections marked `partial`.
    pub fn split(mut self, per_page: usize) -> Vec<NetInventory> {
        let per_page = per_page.clamp(1, MAX_ITEMS_PER_PAGE);
        let budget = per_page * MAX_PAGES as usize;
        if self.item_count() > budget {
            let mut left = budget;
            fn fit<T>(s: &mut Section<T>, left: &mut usize) {
                if s.items.len() > *left {
                    s.items.truncate(*left);
                    s.state = SectionState::Partial;
                    s.note = Some("cut to fit the page budget".into());
                }
                *left -= s.items.len();
            }
            fit(&mut self.interfaces, &mut left);
            fit(&mut self.routes, &mut left);
            fit(&mut self.rules, &mut left);
            fit(&mut self.listeners, &mut left);
            fit(&mut self.firewall_chains, &mut left);
            fit(&mut self.firewall_rules, &mut left);
        }
        let mut pages = Vec::new();
        let mut head = NetInventory {
            os: self.os.clone(),
            namespaces: self.namespaces.clone(),
            forwarding: self.forwarding.clone(),
            interfaces: self.interfaces.clone_meta(),
            routes: self.routes.clone_meta(),
            rules: self.rules.clone_meta(),
            listeners: self.listeners.clone_meta(),
            firewall_chains: self.firewall_chains.clone_meta(),
            firewall_rules: self.firewall_rules.clone_meta(),
        };
        let mut room = per_page;
        macro_rules! drain {
            ($field:ident) => {
                for item in std::mem::take(&mut self.$field.items) {
                    if room == 0 {
                        pages.push(std::mem::take(&mut head));
                        room = per_page;
                    }
                    head.$field.items.push(item);
                    room -= 1;
                }
            };
        }
        drain!(interfaces);
        drain!(routes);
        drain!(rules);
        drain!(listeners);
        drain!(firewall_chains);
        drain!(firewall_rules);
        pages.push(head);
        pages
    }

    /// Reassemble [`Self::split`]'s pages, in page order. `Err` when a page
    /// carries more than [`MAX_ITEMS_PER_PAGE`] items or there are too many
    /// pages; the result still has to pass [`Self::validate`].
    pub fn merge(pages: Vec<NetInventory>) -> Result<NetInventory, String> {
        if pages.is_empty() || pages.len() > MAX_PAGES as usize {
            return Err(format!("{} pages", pages.len()));
        }
        let mut pages = pages.into_iter();
        let mut whole = pages.next().expect("non-empty");
        if whole.item_count() > MAX_ITEMS_PER_PAGE {
            return Err("page 0: too many items".into());
        }
        for (i, page) in pages.enumerate() {
            if page.item_count() > MAX_ITEMS_PER_PAGE {
                return Err(format!("page {}: too many items", i + 1));
            }
            whole.interfaces.items.extend(page.interfaces.items);
            whole.routes.items.extend(page.routes.items);
            whole.rules.items.extend(page.rules.items);
            whole.listeners.items.extend(page.listeners.items);
            whole
                .firewall_chains
                .items
                .extend(page.firewall_chains.items);
            whole.firewall_rules.items.extend(page.firewall_rules.items);
        }
        Ok(whole)
    }
}

impl<T> Section<T> {
    fn clone_meta(&self) -> Section<T> {
        Section {
            state: self.state,
            total: self.total,
            items: Vec::new(),
            note: self.note.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dst: &str) -> Route {
        Route {
            family: Family::V4,
            table: "main".into(),
            dst: dst.into(),
            kind: "unicast".into(),
            gateway: None,
            dev: Some("eth0".into()),
            protocol: None,
            metric: None,
        }
    }

    fn sample(routes: usize) -> NetInventory {
        NetInventory {
            os: "linux".into(),
            namespaces: "host_only".into(),
            forwarding: Forwarding {
                ipv4: Some(true),
                ipv6: Some(false),
            },
            interfaces: Section::capped(
                vec![Interface {
                    name: "eth0".into(),
                    index: 2,
                    kind: None,
                    up: true,
                    mtu: Some(1500),
                    addrs: vec!["192.0.2.10/24".into(), "2001:db8::10/64".into()],
                }],
                MAX_INTERFACES,
            ),
            routes: Section::capped(
                (0..routes)
                    .map(|i| route(&format!("10.{}.{}.0/24", i / 256, i % 256)))
                    .collect(),
                MAX_ROUTES,
            ),
            listeners: Section::absent(SectionState::Denied, "no CAP_NET_ADMIN"),
            ..Default::default()
        }
    }

    #[test]
    fn a_capped_section_is_partial_with_its_real_total() {
        let s = Section::capped(vec![1, 2, 3, 4, 5], 3);
        assert_eq!(
            (s.state, s.total, s.items.len()),
            (SectionState::Partial, 5, 3)
        );
        let s = Section::capped(vec![1, 2], 3);
        assert_eq!((s.state, s.total), (SectionState::Complete, 2));
    }

    #[test]
    fn a_truncated_section_cannot_claim_to_be_complete() {
        let mut inv = sample(10);
        assert!(inv.validate().is_ok());
        inv.routes.items.pop();
        assert!(inv.validate().unwrap_err().contains("complete but 9 of 10"));
        inv.routes.state = SectionState::Partial;
        assert!(inv.validate().is_ok());
        inv.routes.total = 3;
        assert!(inv.validate().is_err(), "a total below the items");
    }

    #[test]
    fn validation_rejects_oversize_odd_and_malformed_fields() {
        let mut inv = sample(1);
        inv.routes.items[0].dst = "10.0.0.0/33".into();
        assert!(inv.validate().is_err());
        let mut inv = sample(1);
        inv.routes.items[0].dev = Some("x".repeat(MAX_STR + 1));
        assert!(inv.validate().is_err());
        let mut inv = sample(1);
        inv.interfaces.items[0].name = "eth\n0".into();
        assert!(inv.validate().is_err(), "control characters");
        let mut inv = sample(1);
        inv.listeners = Section::capped(
            vec![Listener {
                proto: L4::Tcp,
                addr: "localhost".into(),
                port: 22,
                process: None,
            }],
            10,
        );
        assert!(inv.validate().is_err(), "an address, not a name");
        let mut inv = sample(1);
        inv.listeners.items.push(Listener {
            proto: L4::Udp,
            addr: "::".into(),
            port: 53,
            process: None,
        });
        assert!(inv.validate().is_err(), "a denied section has no items");
        let mut inv = sample(1);
        inv.routes.items[0].dst = "default".into();
        assert!(inv.validate().is_ok());
    }

    #[test]
    fn sanitize_drops_only_the_bad_items_and_says_so() {
        let mut inv = sample(3);
        inv.routes.items[1].dst = "weird-form".into();
        assert!(inv.validate().is_err());
        inv.sanitize();
        assert_eq!(
            (inv.routes.state, inv.routes.total, inv.routes.items.len()),
            (SectionState::Partial, 3, 2)
        );
        assert!(inv.routes.note.as_deref().unwrap().contains("1 unreadable"));
        assert!(inv.validate().is_ok());
    }

    #[test]
    fn split_and_merge_round_trip_and_page_zero_carries_the_meta() {
        let inv = sample(2500);
        let pages = inv.clone().split(1000);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].routes.total, 2500);
        assert_eq!(pages[2].routes.total, 0, "later pages carry only items");
        assert!(pages.iter().all(|p| p.item_count() <= 1000));
        assert_eq!(NetInventory::merge(pages).unwrap(), inv);
    }

    #[test]
    fn split_cuts_a_snapshot_past_the_page_budget_to_partial() {
        let pages = sample(4000).split(100);
        assert_eq!(pages.len(), MAX_PAGES as usize);
        let whole = NetInventory::merge(pages).unwrap();
        assert_eq!(whole.routes.state, SectionState::Partial);
        assert_eq!(whole.routes.total, 4000);
        assert_eq!(whole.item_count(), 100 * MAX_PAGES as usize);
        assert!(whole.validate().is_ok());
    }

    #[test]
    fn merge_rejects_too_many_pages_or_items() {
        let pages: Vec<_> = (0..MAX_PAGES + 1)
            .map(|_| NetInventory::default())
            .collect();
        assert!(NetInventory::merge(pages).is_err());
        let mut big = sample(0);
        big.routes = Section::capped(
            (0..MAX_ITEMS_PER_PAGE + 1)
                .map(|_| route("10.0.0.0/8"))
                .collect(),
            MAX_ROUTES,
        );
        assert!(NetInventory::merge(vec![big]).is_err());
    }

    #[test]
    fn the_wire_form_is_stable_snake_case() {
        let v = serde_json::to_value(sample(1)).unwrap();
        assert_eq!(v["listeners"]["state"], "denied");
        assert_eq!(v["routes"]["items"][0]["family"], "v4");
        let back: NetInventory = serde_json::from_value(v).unwrap();
        assert_eq!(back, sample(1));
    }
}
