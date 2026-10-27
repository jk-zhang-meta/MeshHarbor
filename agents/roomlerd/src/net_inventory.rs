// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #19 (v039 §4): read this host's network state and report it,
//! read-only, as `rc:agent.net_inventory` ([`NetInventory`]).
//!
//! Linux reads `ip -j` (interfaces, routes, policy rules), `/proc/net`
//! (listeners, with the owning process's short name when visible),
//! `/proc/sys` (forwarding) and `nft -j list ruleset`; iptables-legacy
//! rules, which nft cannot show, are counted and marked, not parsed. Windows
//! reads its interfaces, routes and listeners from the IP Helper API; its
//! policy rules and firewall, and every section elsewhere, report
//! `unsupported` until they get a native adapter. Only the host network namespace is read.
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
        #[cfg(target_os = "windows")]
        let listeners = match tokio::task::spawn_blocking(windows::listeners).await {
            Ok(Some(l)) => {
                Section::capped(l, roomler_ai_remote_control::net_inventory::MAX_LISTENERS)
            }
            _ => Section::absent(
                SectionState::Error,
                "the IP Helper socket tables could not be read",
            ),
        };
        #[cfg(target_os = "windows")]
        let (interfaces, routes) = {
            use roomler_ai_remote_control::net_inventory::{MAX_INTERFACES, MAX_ROUTES};
            fn unreadable<T>(what: &str) -> Section<T> {
                Section::absent(SectionState::Error, format!("{what} could not be read"))
            }
            match tokio::task::spawn_blocking(windows::interfaces).await {
                Ok(Some((ifs, links))) => {
                    let routes =
                        match tokio::task::spawn_blocking(move || windows::routes(&links)).await {
                            Ok(Some(r)) => Section::capped(r, MAX_ROUTES),
                            _ => unreadable("the forwarding table"),
                        };
                    (Section::capped(ifs, MAX_INTERFACES), routes)
                }
                _ => (
                    unreadable("the adapter list"),
                    unreadable("the forwarding table"),
                ),
            }
        };
        #[cfg(not(target_os = "windows"))]
        let (interfaces, routes, listeners) = (
            Section::absent(SectionState::Unsupported, none()),
            Section::absent(SectionState::Unsupported, none()),
            Section::absent(SectionState::Unsupported, none()),
        );
        NetInventory {
            os: std::env::consts::OS.into(),
            namespaces: "host_only".into(),
            interfaces,
            routes,
            rules: Section::absent(SectionState::Unsupported, none()),
            listeners,
            firewall_chains: Section::absent(SectionState::Unsupported, none()),
            firewall_rules: Section::absent(SectionState::Unsupported, none()),
            ..Default::default()
        }
    }
}

/// MeshHarbor v039 OS-01 — Windows reports what it can read: its adapters
/// with their addresses (`GetAdaptersAddresses`), its IPv4/IPv6 forwarding
/// table (`GetIpForwardTable2`), and its listening TCP and bound UDP sockets
/// with each owner's image name (`GetExtended{Tcp,Udp}Table`, the read the
/// tunnel's port-holder check uses). Policy rules, firewall chains and rules
/// stay `unsupported` until each has an adapter, so nothing claims parity.
#[cfg(target_os = "windows")]
mod windows {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use roomler_ai_remote_control::net_inventory::{
        Family, Interface, L4, Listener, MAX_ADDRS_PER_INTERFACE, MAX_INTERFACES, MAX_ROUTES,
        MAX_STR, Route, truncate_str,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
        UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock as ws;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    /// One table read into u32-aligned storage (every row field is a u32 or
    /// a byte array). `None` when the table cannot be read.
    fn table(udp: bool, af: u32) -> Option<Vec<u32>> {
        let mut size = 0u32;
        // The table grows between the size it reports and the read: asked
        // again with the room it then says it needs.
        for _ in 0..4 {
            let mut buf = vec![0u32; (size as usize).div_ceil(4) + 1];
            let mut len = (buf.len() * 4) as u32;
            // SAFETY: `buf` holds `len` bytes, aligned for the rows' fields.
            let rc = unsafe {
                if udp {
                    GetExtendedUdpTable(
                        buf.as_mut_ptr().cast(),
                        &mut len,
                        0,
                        af,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                } else {
                    GetExtendedTcpTable(
                        buf.as_mut_ptr().cast(),
                        &mut len,
                        0,
                        af,
                        TCP_TABLE_OWNER_PID_LISTENER,
                        0,
                    )
                }
            };
            if rc == ERROR_INSUFFICIENT_BUFFER {
                size = len;
                continue;
            }
            return (rc == 0).then_some(buf);
        }
        None
    }

    /// The rows of a table read by [`table`]: `dwNumEntries`, then that many
    /// rows, bounded by the room the buffer has.
    fn rows<R>(buf: &[u32]) -> &[R] {
        let room = (buf.len() - 1) * 4 / std::mem::size_of::<R>();
        let n = (buf[0] as usize).min(room);
        // SAFETY: the API wrote `dwNumEntries` rows after the count, and `n`
        // never exceeds what `buf` holds.
        unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<R>(), n) }
    }

    /// A port as a row holds it: network order, in the low word.
    fn port(raw: u32) -> u16 {
        u16::from_be((raw & 0xffff) as u16)
    }

    /// The image file name (`sshd.exe`) of a process, when this account may
    /// query it; never its path or command line.
    fn image(pid: u32) -> Option<String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };
        if pid == 0 || pid == 4 {
            return Some("System".into());
        }
        // SAFETY: a plain open by pid; the handle is closed below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: a live handle and a buffer of `len` UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        } != 0;
        // SAFETY: the handle OpenProcess gave us, closed once.
        unsafe { CloseHandle(h) };
        if !ok {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let mut name = path.rsplit(['\\', '/']).next()?.to_string();
        truncate_str(&mut name, 64);
        (!name.is_empty()).then_some(name)
    }

    /// Every listening TCP and bound UDP socket, v4 and v6. `None` when no
    /// table could be read at all.
    pub(super) fn listeners() -> Option<Vec<Listener>> {
        let mut found: Vec<(L4, String, u16, u32)> = Vec::new();
        let mut read_any = false;
        for (udp, proto) in [(false, L4::Tcp), (true, L4::Udp)] {
            if let Some(buf) = table(udp, AF_INET) {
                read_any = true;
                if udp {
                    for r in rows::<MIB_UDPROW_OWNER_PID>(&buf) {
                        let ip = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
                        found.push((proto, ip.to_string(), port(r.dwLocalPort), r.dwOwningPid));
                    }
                } else {
                    for r in rows::<MIB_TCPROW_OWNER_PID>(&buf) {
                        let ip = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
                        found.push((proto, ip.to_string(), port(r.dwLocalPort), r.dwOwningPid));
                    }
                }
            }
            if let Some(buf) = table(udp, AF_INET6) {
                read_any = true;
                if udp {
                    for r in rows::<MIB_UDP6ROW_OWNER_PID>(&buf) {
                        let ip = Ipv6Addr::from(r.ucLocalAddr);
                        found.push((proto, ip.to_string(), port(r.dwLocalPort), r.dwOwningPid));
                    }
                } else {
                    for r in rows::<MIB_TCP6ROW_OWNER_PID>(&buf) {
                        let ip = Ipv6Addr::from(r.ucLocalAddr);
                        found.push((proto, ip.to_string(), port(r.dwLocalPort), r.dwOwningPid));
                    }
                }
            }
        }
        if !read_any {
            return None;
        }
        let mut names: HashMap<u32, Option<String>> = HashMap::new();
        let mut out: Vec<Listener> = found
            .into_iter()
            .map(|(proto, addr, port, pid)| Listener {
                proto,
                addr,
                port,
                process: names.entry(pid).or_insert_with(|| image(pid)).clone(),
            })
            .collect();
        out.sort_by(|a, b| (a.port, &a.addr).cmp(&(b.port, &b.addr)));
        out.dedup_by(|a, b| a.proto == b.proto && a.addr == b.addr && a.port == b.port);
        Some(out)
    }

    /// The address a `SOCKADDR` holds; `None` for a null pointer or another
    /// family.
    ///
    /// # Safety
    /// `sa` is null or points at a live socket address of its family's size.
    unsafe fn ip_of(sa: *const ws::SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // SAFETY: the caller's contract; the family field leads every layout.
        match unsafe { (*sa).sa_family } {
            ws::AF_INET => {
                // SAFETY: an AF_INET address is a SOCKADDR_IN.
                let v4 = unsafe { &*sa.cast::<ws::SOCKADDR_IN>() };
                // SAFETY: every member of the IN_ADDR union is the address.
                Some(IpAddr::from(
                    unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes(),
                ))
            }
            ws::AF_INET6 => {
                // SAFETY: an AF_INET6 address is a SOCKADDR_IN6.
                let v6 = unsafe { &*sa.cast::<ws::SOCKADDR_IN6>() };
                // SAFETY: every member of the IN6_ADDR union is the address.
                Some(IpAddr::from(unsafe { v6.sin6_addr.u.Byte }))
            }
            _ => None,
        }
    }

    fn ip_of_inet(a: &ws::SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: a SOCKADDR_INET is a v4 or v6 address led by its family.
        unsafe { ip_of(std::ptr::from_ref(a).cast()) }
    }

    /// A NUL-terminated UTF-16 string, as a bounded, printable `String`.
    fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        // SAFETY: the API hands out NUL-terminated strings; bounded anyway.
        while n < 1024 && unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        // SAFETY: `n` units were just read.
        let mut s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) });
        s.retain(|c| !c.is_control());
        truncate_str(&mut s, MAX_STR);
        s
    }

    /// The link kind, in the words the Linux adapter uses where one fits.
    fn kind_of(if_type: u32, description: &str) -> Option<String> {
        let k = match if_type {
            6 => return None,
            24 => "loopback",
            71 => "wifi",
            23 => "ppp",
            131 => "tunnel",
            53 if description.contains("WireGuard") => "wireguard",
            53 if description.contains("Wintun") => "tun",
            53 => "virtual",
            t => return Some(format!("iftype-{t}")),
        };
        Some(k.into())
    }

    /// What the route table needs from an adapter: its name, whether it is
    /// up, and its interface metrics (v4, v6), which Windows adds to a
    /// route's own metric.
    pub(super) struct Link {
        pub name: String,
        pub up: bool,
        pub metric: (u32, u32),
    }

    /// Every adapter with its addresses (`ip/prefix`), and the [`Link`] of
    /// each by index. `None` when the adapter list cannot be read.
    pub(super) fn interfaces() -> Option<(Vec<Interface>, HashMap<u32, Link>)> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // u64 storage: the list's structs are 8-aligned.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let mut len = (buf.len() * 8) as u32;
            // SAFETY: `buf` holds `len` bytes, aligned for the list.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(ws::AF_UNSPEC),
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if rc == ERROR_BUFFER_OVERFLOW {
                size = len;
                continue;
            }
            if rc != 0 {
                return None;
            }
            let mut out = Vec::new();
            let mut links = HashMap::new();
            let mut a = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !a.is_null() && out.len() < MAX_INTERFACES {
                // SAFETY: a node of the list the API wrote into `buf`.
                let ad = unsafe { &*a };
                // SAFETY: both union members carry the index in this layout.
                let v4_index = unsafe { ad.Anonymous1.Anonymous.IfIndex };
                let mut addrs = Vec::new();
                let mut u = ad.FirstUnicastAddress;
                while !u.is_null() && addrs.len() < MAX_ADDRS_PER_INTERFACE {
                    // SAFETY: a node of the adapter's unicast list.
                    let ua = unsafe { &*u };
                    // SAFETY: the API's own socket address for this entry.
                    if let Some(ip) = unsafe { ip_of(ua.Address.lpSockaddr) } {
                        addrs.push(format!("{ip}/{}", ua.OnLinkPrefixLength));
                    }
                    u = ua.Next;
                }
                let name = wide(ad.FriendlyName);
                let up = ad.OperStatus == IfOperStatusUp;
                for index in [v4_index, ad.Ipv6IfIndex] {
                    if index != 0 {
                        links.insert(
                            index,
                            Link {
                                name: name.clone(),
                                up,
                                metric: (ad.Ipv4Metric, ad.Ipv6Metric),
                            },
                        );
                    }
                }
                out.push(Interface {
                    name,
                    index: if v4_index != 0 {
                        v4_index
                    } else {
                        ad.Ipv6IfIndex
                    },
                    kind: kind_of(ad.IfType, &wide(ad.Description)),
                    up,
                    mtu: (ad.Mtu != u32::MAX).then_some(ad.Mtu),
                    addrs,
                });
                a = ad.Next;
            }
            return Some((out, links));
        }
        None
    }

    fn protocol_name(p: i32) -> String {
        match p {
            1 => "other".into(),
            2 => "local".into(),
            3 => "netmgmt".into(),
            4 => "icmp".into(),
            10002 => "autostatic".into(),
            10006 | 10007 => "static".into(),
            p => p.to_string(),
        }
    }

    /// The active IPv4 and IPv6 routes, as `route print` lists them: a route
    /// on an adapter that is down is left out, and the metric is the
    /// effective one (the route's plus its interface's). `None` when the
    /// table cannot be read.
    pub(super) fn routes(links: &HashMap<u32, Link>) -> Option<Vec<Route>> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
        };
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: a valid out-pointer; the table is freed below.
        let rc = unsafe { GetIpForwardTable2(ws::AF_UNSPEC, &mut table) };
        if rc != 0 || table.is_null() {
            return None;
        }
        // SAFETY: the API wrote `NumEntries` rows into the table it returned.
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let out = rows
            .iter()
            .take(MAX_ROUTES)
            .filter_map(|r| {
                let link = links.get(&r.InterfaceIndex).filter(|l| l.up)?;
                let dst = ip_of_inet(&r.DestinationPrefix.Prefix)?;
                let len = r.DestinationPrefix.PrefixLength;
                let if_metric = if dst.is_ipv4() {
                    link.metric.0
                } else {
                    link.metric.1
                };
                Some(Route {
                    family: if dst.is_ipv4() {
                        Family::V4
                    } else {
                        Family::V6
                    },
                    table: "main".into(),
                    dst: if len == 0 {
                        "default".into()
                    } else {
                        format!("{dst}/{len}")
                    },
                    kind: if r.Loopback != 0 { "local" } else { "unicast" }.into(),
                    gateway: ip_of_inet(&r.NextHop)
                        .filter(|g| !g.is_unspecified())
                        .map(|g| g.to_string()),
                    dev: Some(link.name.clone()),
                    protocol: Some(protocol_name(r.Protocol)),
                    metric: Some(r.Metric.saturating_add(if_metric)),
                })
            })
            .collect();
        // SAFETY: the table GetIpForwardTable2 allocated, freed once.
        unsafe { FreeMibTable(table.cast_const().cast()) };
        Some(out)
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

/// OS-01: on a real Windows host the inventory is read, not stubbed, and
/// passes the same bounds the server applies (`--nocapture` prints it).
#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use roomler_ai_remote_control::net_inventory::SectionState;

    #[tokio::test]
    async fn the_windows_inventory_is_read_and_validates() {
        let inv = super::collect().await;
        inv.validate().expect("the server would accept it");
        for (what, state) in [
            ("interfaces", inv.interfaces.state),
            ("routes", inv.routes.state),
            ("listeners", inv.listeners.state),
        ] {
            assert!(
                matches!(state, SectionState::Complete | SectionState::Partial),
                "{what}: {state:?}"
            );
        }
        let lo = inv
            .interfaces
            .items
            .iter()
            .find(|i| i.kind.as_deref() == Some("loopback"))
            .expect("the loopback pseudo-interface");
        assert!(lo.addrs.iter().any(|a| a == "127.0.0.1/8"), "{lo:?}");
        assert!(
            inv.routes.items.iter().any(|r| r.dst == "127.0.0.0/8"),
            "the loopback route"
        );
        assert_eq!(inv.rules.state, SectionState::Unsupported);
        for i in &inv.interfaces.items {
            println!(
                "if {} #{} {:?} up={} mtu={:?} {:?}",
                i.name, i.index, i.kind, i.up, i.mtu, i.addrs
            );
        }
        for r in inv.routes.items.iter().filter(|r| r.kind == "unicast") {
            println!(
                "rt {} via {:?} dev {:?} {:?} metric {:?}",
                r.dst, r.gateway, r.dev, r.protocol, r.metric
            );
        }
    }
}
