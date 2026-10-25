// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #19 (v039 §4): read this host's network state and report it,
//! read-only, as `rc:agent.net_inventory` ([`NetInventory`]).
//!
//! Linux reads `ip -j` (interfaces, routes, policy rules), `/proc/net`
//! (listeners, with the owning process's short name when visible),
//! `/proc/sys` (forwarding) and `nft -j list ruleset`; iptables-legacy
//! rules, which nft cannot show, are counted and marked, not parsed. Other
//! platforms report every section `unsupported` until they get native
//! adapters. Only the host network namespace is read.
//!
//! Nothing is uploaded that the topology does not need: no command lines,
//! environment, rule comments, keys or payloads, and every section is
//! capped ([`Section::capped`]) and sanitized before it leaves.
//!
//! A multi-org device reports nothing: the host's inventory would show
//! every org its other enrollments' overlay interfaces and routes.

use std::time::Duration;

use roomler_ai_remote_control::net_inventory::{NetInventory, Section, SectionState};
use roomler_ai_remote_control::signaling::ClientMsg;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// The first report waits this long after the connection opens (past the
/// hello burst); then one every [`REPORT_EVERY`], inside the server's
/// 15-minute freshness window with two to spare.
pub const FIRST_AFTER: Duration = Duration::from_secs(30);
pub const REPORT_EVERY: Duration = Duration::from_secs(5 * 60);
const PER_PAGE: usize = 512;

/// Report this connection's inventory until the connection ends (its
/// outbound queue closes). `None` when this device must not report.
pub fn spawn_reporter(
    outbound: mpsc::Sender<ClientMsg>,
    primary: bool,
    secondary_orgs: usize,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    if !primary || secondary_orgs > 0 {
        info!(
            secondary_orgs,
            "net inventory: not reported (multi-org device)"
        );
        return None;
    }
    Some(tokio::spawn(report(outbound)))
}

/// `NET_INVENTORY=0` (or the config key `net_inventory = false`) turns it off.
fn enabled() -> bool {
    !matches!(
        tunnel_core::env::node_env("NET_INVENTORY")
            .as_deref()
            .map(str::trim),
        Some("0" | "false" | "off")
    )
}

async fn report(outbound: mpsc::Sender<ClientMsg>) {
    let boot_id = format!("{:032x}", rand::random::<u128>());
    let mut seq = 0u64;
    tokio::time::sleep(FIRST_AFTER).await;
    loop {
        seq += 1;
        let observed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let mut inv = collect().await;
        inv.sanitize();
        let pages = inv.split(PER_PAGE);
        let n = pages.len() as u16;
        debug!(seq, pages = n, "net inventory: reporting");
        for (i, page) in pages.into_iter().enumerate() {
            let msg = ClientMsg::NetInventory {
                boot_id: boot_id.clone(),
                seq,
                page: i as u16,
                pages: n,
                observed_at_ms,
                inventory: Box::new(page),
            };
            if outbound.send(msg).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(REPORT_EVERY).await;
    }
}

pub async fn collect() -> NetInventory {
    #[cfg(target_os = "linux")]
    {
        linux::collect().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let none = || "no adapter for this platform yet";
        NetInventory {
            os: std::env::consts::OS.into(),
            namespaces: "host_only".into(),
            interfaces: Section::absent(SectionState::Unsupported, none()),
            routes: Section::absent(SectionState::Unsupported, none()),
            rules: Section::absent(SectionState::Unsupported, none()),
            listeners: Section::absent(SectionState::Unsupported, none()),
            firewall_chains: Section::absent(SectionState::Unsupported, none()),
            firewall_rules: Section::absent(SectionState::Unsupported, none()),
            ..Default::default()
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use roomler_ai_remote_control::net_inventory::{
        Family, FirewallChain, FirewallOwner, FirewallRule, Forwarding, Interface, L4, Listener,
        MAX_FIREWALL_CHAINS, MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_LISTENERS, MAX_ROUTES,
        MAX_RULES, MAX_STR, Route, Rule, truncate_str,
    };
    use serde_json::Value;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const CMD_TIMEOUT: Duration = Duration::from_secs(5);
    const CMD_MAX_OUTPUT: usize = 16 * 1024 * 1024;

    pub(super) enum CmdError {
        Missing,
        Denied(String),
        Failed(String),
    }

    impl CmdError {
        fn section<T>(&self, what: &str) -> Section<T> {
            match self {
                CmdError::Missing => {
                    Section::absent(SectionState::Unsupported, format!("{what} not installed"))
                }
                CmdError::Denied(e) => Section::absent(SectionState::Denied, e.clone()),
                CmdError::Failed(e) => Section::absent(SectionState::Error, e.clone()),
            }
        }
    }

    /// `cmd` from `PATH`, else from the sbin directories a service's `PATH`
    /// often lacks (`nft`, `iptables-legacy-save` live there).
    fn resolve(cmd: &str) -> std::path::PathBuf {
        let on_path = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()));
        if !on_path {
            for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
                let p = std::path::Path::new(dir).join(cmd);
                if p.is_file() {
                    return p;
                }
            }
        }
        cmd.into()
    }

    /// Run a read-only command with a deadline and an output cap.
    pub(super) async fn run(cmd: &str, args: &[&str]) -> Result<String, CmdError> {
        let child = tokio::process::Command::new(resolve(cmd))
            .args(args)
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        let out = match tokio::time::timeout(CMD_TIMEOUT, child).await {
            Err(_) => return Err(CmdError::Failed(format!("{cmd}: timed out"))),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CmdError::Missing);
            }
            Ok(Err(e)) => return Err(CmdError::Failed(format!("{cmd}: {e}"))),
            Ok(Ok(o)) => o,
        };
        if !out.status.success() {
            let mut err = String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            truncate_str(&mut err, 120);
            let denied =
                err.contains("ermission denied") || err.contains("Operation not permitted");
            return Err(if denied {
                CmdError::Denied(err)
            } else {
                CmdError::Failed(err)
            });
        }
        if out.stdout.len() > CMD_MAX_OUTPUT {
            return Err(CmdError::Failed(format!(
                "{cmd}: output past {CMD_MAX_OUTPUT} bytes"
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn s(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    pub(super) async fn collect() -> NetInventory {
        let (firewall_chains, firewall_rules) = firewall().await;
        NetInventory {
            os: "linux".into(),
            namespaces: "host_only".into(),
            forwarding: forwarding(),
            interfaces: match run("ip", &["-j", "-d", "addr", "show"]).await {
                Ok(out) => Section::capped(parse_interfaces(&out), MAX_INTERFACES),
                Err(e) => e.section("ip"),
            },
            routes: both_families(&["route", "show", "table", "all"], parse_routes, MAX_ROUTES)
                .await,
            rules: both_families(&["rule", "show"], parse_rules, MAX_RULES).await,
            listeners: Section::capped(listeners(), MAX_LISTENERS),
            firewall_chains,
            firewall_rules,
        }
    }

    async fn both_families<T>(
        args: &[&str],
        parse: fn(&str, Family) -> Vec<T>,
        cap: usize,
    ) -> Section<T> {
        let mut items = Vec::new();
        for (flag, fam) in [("-4", Family::V4), ("-6", Family::V6)] {
            let mut a = vec!["-j", flag];
            a.extend_from_slice(args);
            match run("ip", &a).await {
                Ok(out) => items.extend(parse(&out, fam)),
                Err(e) => return e.section("ip"),
            }
        }
        Section::capped(items, cap)
    }

    fn forwarding() -> Forwarding {
        let flag = |p: &str| std::fs::read_to_string(p).ok().map(|v| v.trim() == "1");
        Forwarding {
            ipv4: flag("/proc/sys/net/ipv4/ip_forward"),
            ipv6: flag("/proc/sys/net/ipv6/conf/all/forwarding"),
        }
    }

    pub(super) fn parse_interfaces(json: &str) -> Vec<Interface> {
        let Ok(Value::Array(links)) = serde_json::from_str::<Value>(json) else {
            return Vec::new();
        };
        links
            .iter()
            .filter_map(|l| {
                let name = l["ifname"].as_str()?.to_string();
                let up = l["flags"]
                    .as_array()
                    .is_some_and(|f| f.iter().any(|x| x == "UP"));
                let addrs = l["addr_info"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| {
                                Some(format!(
                                    "{}/{}",
                                    x["local"].as_str()?,
                                    x["prefixlen"].as_u64()?
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(Interface {
                    name,
                    index: l["ifindex"].as_u64().unwrap_or(0) as u32,
                    kind: l["linkinfo"]["info_kind"].as_str().map(str::to_string),
                    up,
                    mtu: l["mtu"].as_u64().map(|m| m as u32),
                    addrs,
                })
            })
            .collect()
    }

    pub(super) fn parse_routes(json: &str, family: Family) -> Vec<Route> {
        let Ok(Value::Array(rs)) = serde_json::from_str::<Value>(json) else {
            return Vec::new();
        };
        rs.iter()
            .filter_map(|r| {
                Some(Route {
                    family,
                    table: r.get("table").and_then(s).unwrap_or_else(|| "main".into()),
                    dst: r.get("dst").and_then(s)?,
                    kind: r
                        .get("type")
                        .and_then(s)
                        .unwrap_or_else(|| "unicast".into()),
                    gateway: r.get("gateway").and_then(s),
                    dev: r.get("dev").and_then(s),
                    protocol: r.get("protocol").and_then(s),
                    metric: r.get("metric").and_then(Value::as_u64).map(|m| m as u32),
                })
            })
            .collect()
    }

    pub(super) fn parse_rules(json: &str, family: Family) -> Vec<Rule> {
        let Ok(Value::Array(rs)) = serde_json::from_str::<Value>(json) else {
            return Vec::new();
        };
        rs.iter()
            .map(|r| {
                let mut sel = Vec::new();
                if r.get("not").is_some() {
                    sel.push("not".to_string());
                }
                for (key, len, word) in [("src", "srclen", "from"), ("dst", "dstlen", "to")] {
                    if let Some(a) = r.get(key).and_then(s).filter(|a| a != "all") {
                        let l = r.get(len).and_then(Value::as_u64);
                        sel.push(match l {
                            Some(l) => format!("{word} {a}/{l}"),
                            None => format!("{word} {a}"),
                        });
                    }
                }
                for key in [
                    "iif", "oif", "fwmark", "ipproto", "sport", "dport", "uidrange", "l3mdev",
                ] {
                    if let Some(v) = r.get(key).and_then(s) {
                        sel.push(format!("{key} {v}"));
                    }
                }
                let action = if let Some(t) = r.get("table").and_then(s) {
                    format!("lookup {t}")
                } else if let Some(g) = r.get("goto").and_then(s) {
                    format!("goto {g}")
                } else {
                    r.get("action")
                        .and_then(s)
                        .unwrap_or_else(|| "other".into())
                };
                let mut selector = if sel.is_empty() {
                    "all".into()
                } else {
                    sel.join(" ")
                };
                truncate_str(&mut selector, MAX_STR);
                Rule {
                    family,
                    priority: r["priority"].as_u64().unwrap_or(0) as u32,
                    selector,
                    action,
                }
            })
            .collect()
    }

    /// A `/proc/net/{tcp,udp}{,6}` hex address (`0100007F:0035`).
    pub(super) fn proc_addr(hex: &str) -> Option<(IpAddr, u16)> {
        let (a, p) = hex.split_once(':')?;
        let port = u16::from_str_radix(p, 16).ok()?;
        let ip = match a.len() {
            8 => IpAddr::V4(Ipv4Addr::from(
                u32::from_str_radix(a, 16).ok()?.to_le_bytes(),
            )),
            32 => {
                let mut b = [0u8; 16];
                for i in 0..4 {
                    let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                    b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return None,
        };
        Some((ip, port))
    }

    /// `(proto, addr, port, inode)` of listening TCP and bound, unconnected
    /// UDP sockets in one `/proc/net` table.
    pub(super) fn parse_proc_net(text: &str, proto: L4) -> Vec<(L4, IpAddr, u16, u64)> {
        let want = match proto {
            L4::Tcp => "0A", // LISTEN
            L4::Udp => "07", // unconnected
        };
        text.lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() < 10 || f[3] != want {
                    return None;
                }
                let (ip, port) = proc_addr(f[1])?;
                Some((proto, ip, port, f[9].parse().ok()?))
            })
            .collect()
    }

    /// socket inode -> owning process's `comm`, read within a time budget.
    fn socket_owners() -> HashMap<u64, String> {
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);
        let mut owners = HashMap::new();
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return owners;
        };
        for p in procs.flatten().take(8192) {
            if std::time::Instant::now() > deadline {
                break;
            }
            let name = p.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|n| n.bytes().all(|c| c.is_ascii_digit()))
            else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            let mut comm: Option<String> = None;
            for fd in fds.flatten().take(4096) {
                let Ok(link) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                let Some(inode) = link
                    .to_str()
                    .and_then(|l| l.strip_prefix("socket:["))
                    .and_then(|l| l.strip_suffix(']'))
                    .and_then(|l| l.parse::<u64>().ok())
                else {
                    continue;
                };
                let c = comm.get_or_insert_with(|| {
                    let mut c = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    truncate_str(&mut c, 32);
                    c
                });
                owners.entry(inode).or_insert_with(|| c.clone());
            }
        }
        owners
    }

    fn listeners() -> Vec<Listener> {
        let mut socks = Vec::new();
        for (file, proto) in [
            ("tcp", L4::Tcp),
            ("tcp6", L4::Tcp),
            ("udp", L4::Udp),
            ("udp6", L4::Udp),
        ] {
            if let Ok(t) = std::fs::read_to_string(format!("/proc/net/{file}")) {
                socks.extend(parse_proc_net(&t, proto));
            }
        }
        let owners = socket_owners();
        let mut seen = std::collections::HashSet::new();
        socks
            .into_iter()
            .filter(|(p, ip, port, _)| seen.insert((*p as u8, *ip, *port)))
            .map(|(proto, ip, port, inode)| Listener {
                proto,
                addr: ip.to_string(),
                port,
                process: owners.get(&inode).cloned().filter(|c| !c.is_empty()),
            })
            .collect()
    }

    fn owner(table: &str, chain: &str) -> FirewallOwner {
        let t = table.to_ascii_lowercase();
        if t.starts_with("meshharbor") || t.starts_with("roomler") {
            FirewallOwner::Meshharbor
        } else if t == "firewalld" {
            FirewallOwner::Firewalld
        } else if chain.starts_with("DOCKER") {
            FirewallOwner::Docker
        } else if chain.starts_with("f2b-") || t == "f2b-table" {
            FirewallOwner::Fail2ban
        } else if chain.starts_with("LIBVIRT") || t.starts_with("libvirt") {
            FirewallOwner::Libvirt
        } else if chain.starts_with("KUBE-")
            || chain.starts_with("cali-")
            || chain.starts_with("CILIUM")
        {
            FirewallOwner::Kubernetes
        } else {
            FirewallOwner::Unknown
        }
    }

    /// An nft JSON expression operand, compactly.
    fn operand(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(a) => format!(
                "{{{}}}",
                a.iter().map(operand).collect::<Vec<_>>().join(",")
            ),
            Value::Object(o) => {
                if let Some(p) = o.get("payload") {
                    format!(
                        "{} {}",
                        p["protocol"].as_str().unwrap_or("?"),
                        p["field"].as_str().unwrap_or("?")
                    )
                } else if let Some(m) = o.get("meta") {
                    m["key"].as_str().unwrap_or("meta").to_string()
                } else if let Some(c) = o.get("ct") {
                    format!("ct {}", c["key"].as_str().unwrap_or("?"))
                } else if let Some(p) = o.get("prefix") {
                    format!("{}/{}", p["addr"].as_str().unwrap_or("?"), p["len"])
                } else if let Some(r) = o.get("range") {
                    r.as_array()
                        .map(|r| r.iter().map(operand).collect::<Vec<_>>().join("-"))
                        .unwrap_or_default()
                } else if let Some(s) = o.get("set") {
                    operand(s)
                } else {
                    o.keys().next().cloned().unwrap_or_else(|| "?".into())
                }
            }
            Value::Null => "null".into(),
        }
    }

    /// One nft rule's matches, verdict, NAT target and counters.
    pub(super) fn summarize_rule(
        expr: &[Value],
    ) -> (String, String, Option<String>, Option<u64>, Option<u64>) {
        let (mut matches, mut verdict, mut target, mut packets, mut bytes) =
            (Vec::new(), None, None, None, None);
        for e in expr {
            let Some((k, v)) = e.as_object().and_then(|o| o.iter().next()) else {
                continue;
            };
            match k.as_str() {
                "match" => {
                    let (l, r) = (operand(&v["left"]), operand(&v["right"]));
                    matches.push(match v["op"].as_str() {
                        Some("==") | Some("in") | None => format!("{l} {r}"),
                        Some(op) => format!("{l} {op} {r}"),
                    });
                }
                "counter" => {
                    packets = v["packets"].as_u64();
                    bytes = v["bytes"].as_u64();
                }
                "accept" | "drop" | "return" | "masquerade" | "reject" | "queue" => {
                    verdict = Some(k.clone())
                }
                "jump" | "goto" => {
                    verdict = Some(format!("{k} {}", v["target"].as_str().unwrap_or("?")))
                }
                "dnat" | "snat" | "redirect" => {
                    verdict = Some(k.clone());
                    let addr = v.get("addr").map(operand).unwrap_or_default();
                    let port = v.get("port").map(operand);
                    target = Some(match port {
                        Some(p) => format!("{addr}:{p}"),
                        None => addr,
                    });
                }
                "log" | "limit" | "mangle" | "notrack" => matches.push(k.clone()),
                _ => {}
            }
        }
        let mut m = matches.join(" ");
        truncate_str(&mut m, MAX_STR);
        if let Some(t) = target.as_mut() {
            truncate_str(t, MAX_STR);
        }
        let verdict = verdict.unwrap_or_else(|| {
            if packets.is_some() {
                "none".into()
            } else {
                "other".into()
            }
        });
        (m, verdict, target, packets, bytes)
    }

    pub(super) fn parse_nft(json: &str) -> (Vec<FirewallChain>, Vec<FirewallRule>) {
        let mut chains = Vec::new();
        let mut rules = Vec::new();
        let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
        for item in v["nftables"].as_array().into_iter().flatten() {
            if let Some(c) = item.get("chain") {
                let (table, name) = (
                    c["table"].as_str().unwrap_or("").to_string(),
                    c["name"].as_str().unwrap_or("").to_string(),
                );
                chains.push(FirewallChain {
                    backend: "nftables".into(),
                    family: c["family"].as_str().unwrap_or("").into(),
                    owner: owner(&table, &name),
                    hook: c["hook"].as_str().map(str::to_string),
                    chain_type: c["type"].as_str().map(str::to_string),
                    priority: c["prio"].as_i64().map(|p| p as i32),
                    policy: c["policy"].as_str().map(str::to_string),
                    table,
                    name,
                });
            } else if let Some(r) = item.get("rule") {
                let (table, chain) = (
                    r["table"].as_str().unwrap_or("").to_string(),
                    r["chain"].as_str().unwrap_or("").to_string(),
                );
                let (matches, verdict, target, packets, bytes) =
                    summarize_rule(r["expr"].as_array().map(Vec::as_slice).unwrap_or(&[]));
                rules.push(FirewallRule {
                    backend: "nftables".into(),
                    family: r["family"].as_str().unwrap_or("").into(),
                    owner: owner(&table, &chain),
                    handle: r["handle"].as_u64(),
                    matches,
                    verdict,
                    target,
                    packets,
                    bytes,
                    table,
                    chain,
                });
            }
        }
        (chains, rules)
    }

    async fn firewall() -> (Section<FirewallChain>, Section<FirewallRule>) {
        let (mut chains, mut rules) = match run("nft", &["-j", "list", "ruleset"]).await {
            Ok(out) => {
                let (c, r) = parse_nft(&out);
                (
                    Section::capped(c, MAX_FIREWALL_CHAINS),
                    Section::capped(r, MAX_FIREWALL_RULES),
                )
            }
            Err(e) => (e.section("nft"), e.section("nft")),
        };
        // Rules in the legacy (non-nft) iptables backend are invisible to
        // nft: count them so the section never reads as the whole picture.
        let mut legacy = 0usize;
        for cmd in ["iptables-legacy-save", "ip6tables-legacy-save"] {
            if let Ok(out) = run(cmd, &[]).await {
                legacy += out.lines().filter(|l| l.starts_with("-A ")).count();
            }
        }
        if legacy > 0 {
            for (state, note) in [
                (&mut chains.state, &mut chains.note),
                (&mut rules.state, &mut rules.note),
            ] {
                if *state == SectionState::Complete {
                    *state = SectionState::Partial;
                }
                *note = Some(format!(
                    "{legacy} iptables-legacy rules present, not parsed"
                ));
            }
            rules.total = rules.total.max(rules.items.len() as u32) + legacy as u32;
        }
        (chains, rules)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::*;
    use roomler_ai_remote_control::net_inventory::{Family, L4};
    use serde_json::json;

    #[test]
    fn proc_net_addresses_decode_both_families() {
        assert_eq!(
            proc_addr("0100007F:0035").unwrap(),
            ("127.0.0.1".parse().unwrap(), 53)
        );
        assert_eq!(
            proc_addr("00000000000000000000000001000000:1F90").unwrap(),
            ("::1".parse().unwrap(), 8080)
        );
        assert!(proc_addr("zz:1").is_none());
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0\n\
   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0 100 0 0 10 0\n";
        let l = parse_proc_net(tcp, L4::Tcp);
        assert_eq!(l.len(), 1, "only the LISTEN row");
        assert_eq!(
            (l[0].1.to_string(), l[0].2, l[0].3),
            ("0.0.0.0".into(), 22, 12345)
        );
    }

    #[test]
    fn iproute_json_normalizes_into_interfaces_routes_and_rules() {
        let addr = json!([{"ifindex":3,"ifname":"wg0","flags":["POINTOPOINT","UP"],"mtu":1420,
            "linkinfo":{"info_kind":"wireguard"},"addr_info":[{"family":"inet","local":"100.64.0.2","prefixlen":32}]}]);
        let i = parse_interfaces(&addr.to_string());
        assert_eq!(
            (i[0].name.as_str(), i[0].kind.as_deref(), i[0].up),
            ("wg0", Some("wireguard"), true)
        );
        assert_eq!(i[0].addrs, vec!["100.64.0.2/32".to_string()]);
        let routes = json!([{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100},
            {"type":"local","dst":"192.0.2.10","table":"local","dev":"eth0"}]);
        let r = parse_routes(&routes.to_string(), Family::V4);
        assert_eq!(
            (
                r[0].table.as_str(),
                r[0].kind.as_str(),
                r[0].gateway.as_deref()
            ),
            ("main", "unicast", Some("192.0.2.1"))
        );
        assert_eq!(
            (r[1].table.as_str(), r[1].kind.as_str()),
            ("local", "local")
        );
        let rules = json!([{"priority":0,"src":"all","table":"local"},
            {"priority":5208,"src":"10.0.0.0","srclen":8,"iif":"eth0","fwmark":"0x1","table":"52"},
            {"priority":9000,"not":null,"src":"all","action":"blackhole"}]);
        let r = parse_rules(&rules.to_string(), Family::V4);
        assert_eq!(
            (r[0].selector.as_str(), r[0].action.as_str()),
            ("all", "lookup local")
        );
        assert_eq!(r[1].selector, "from 10.0.0.0/8 iif eth0 fwmark 0x1");
        assert_eq!(
            (r[2].selector.as_str(), r[2].action.as_str()),
            ("not", "blackhole")
        );
    }

    #[test]
    fn nft_json_yields_chains_rules_nat_targets_and_owners() {
        let nft = json!({"nftables":[
            {"metainfo":{"json_schema_version":1}},
            {"table":{"family":"ip","name":"nat","handle":1}},
            {"chain":{"family":"ip","table":"nat","name":"PREROUTING","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
            {"chain":{"family":"ip","table":"nat","name":"DOCKER","handle":2}},
            {"rule":{"family":"ip","table":"nat","chain":"DOCKER","handle":7,"comment":"secret-ish note","expr":[
                {"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"docker0"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},
                {"counter":{"packets":3,"bytes":180}},
                {"dnat":{"addr":"172.17.0.2","port":80}}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,"expr":[
                {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":["established","related"]}},
                {"accept":null}]}}
        ]});
        let (chains, rules) = parse_nft(&nft.to_string());
        assert_eq!(chains.len(), 2);
        assert_eq!(
            (
                chains[0].hook.as_deref(),
                chains[0].priority,
                chains[0].policy.as_deref()
            ),
            (Some("prerouting"), Some(-100), Some("accept"))
        );
        assert_eq!(
            chains[1].owner,
            roomler_ai_remote_control::net_inventory::FirewallOwner::Docker
        );
        assert_eq!(rules[0].matches, "iifname != docker0 tcp dport 8080");
        assert_eq!(
            (rules[0].verdict.as_str(), rules[0].target.as_deref()),
            ("dnat", Some("172.17.0.2:80"))
        );
        assert_eq!((rules[0].packets, rules[0].bytes), (Some(3), Some(180)));
        assert!(
            !serde_json::to_string(&rules)
                .unwrap()
                .contains("secret-ish"),
            "comments never leave"
        );
        assert_eq!(
            (rules[1].matches.as_str(), rules[1].verdict.as_str()),
            ("ct state {established,related}", "accept")
        );
    }

    /// OBS-01 on a real host: collect, sanitize, and the result passes the
    /// server's validation. Prints the section states and counts.
    #[tokio::test]
    #[ignore = "reads this host's live network state; run with --ignored --nocapture"]
    async fn live_collect_validates() {
        let mut inv = super::collect().await;
        inv.sanitize();
        inv.validate()
            .expect("a collected snapshot passes the server's checks");
        let line = |name: &str,
                    state: roomler_ai_remote_control::net_inventory::SectionState,
                    total: u32,
                    n: usize,
                    note: &Option<String>| {
            eprintln!("OBSERVED {name}: {state:?} total={total} reported={n} note={note:?}");
        };
        line(
            "interfaces",
            inv.interfaces.state,
            inv.interfaces.total,
            inv.interfaces.items.len(),
            &inv.interfaces.note,
        );
        line(
            "routes",
            inv.routes.state,
            inv.routes.total,
            inv.routes.items.len(),
            &inv.routes.note,
        );
        line(
            "rules",
            inv.rules.state,
            inv.rules.total,
            inv.rules.items.len(),
            &inv.rules.note,
        );
        line(
            "listeners",
            inv.listeners.state,
            inv.listeners.total,
            inv.listeners.items.len(),
            &inv.listeners.note,
        );
        line(
            "firewall_chains",
            inv.firewall_chains.state,
            inv.firewall_chains.total,
            inv.firewall_chains.items.len(),
            &inv.firewall_chains.note,
        );
        line(
            "firewall_rules",
            inv.firewall_rules.state,
            inv.firewall_rules.total,
            inv.firewall_rules.items.len(),
            &inv.firewall_rules.note,
        );
        let bytes = serde_json::to_vec(&inv).unwrap().len();
        eprintln!(
            "OBSERVED forwarding={:?} json_bytes={bytes} pages={}",
            inv.forwarding,
            inv.clone().split(512).len()
        );
        assert!(!inv.interfaces.items.is_empty() && !inv.routes.items.is_empty());
    }
}
