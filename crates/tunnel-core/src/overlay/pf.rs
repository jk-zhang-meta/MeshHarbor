// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P1b — a Mac serves as an exit node or subnet router through pf.
//!
//! The macOS twin of the Linux iptables arm in [`super::nat`]: kernel NAT for
//! the overlay, its rules in our OWN anchor under the stock `com.apple/*`
//! wildcard, so `/etc/pf.conf` is never edited.
//!
//! Field-verified before any of this was written (FR-97 §8, 2026-10-16/17):
//! - a fresh macOS boot loads `/etc/pf.conf` and leaves pf disabled, and that
//!   main ruleset carries `nat-anchor "com.apple/*"` and `anchor "com.apple/*"`:
//!   rules in a sub-anchor of ours were evaluated once pf was enabled;
//! - `pfctl -E` enables pf and returns a reference token, and `pfctl -X <token>`
//!   releases it: pf went back to Disabled, as found. Never `pfctl -d`, which
//!   switches pf off under every other user of it (Internet Sharing, a VPN);
//! - `nat on <if> … -> (<if>)` follows the interface's address, but for `inet6`
//!   it round-robins over EVERY address, link-local included, so a v6 rule
//!   names a stable address instead (a global one first);
//! - a Mac whose primary service has no IPv6 has no UNSCOPED v6 default
//!   (every one is ifscoped), and a forwarded packet then has no route: v6 is
//!   served only where an unscoped default exists.
//!
//! And after it, beside Internet Sharing (driven through vmnet's shared mode, the
//! NAT behind a Mac's VMs) and other users of pf (§8, 2026-10-17):
//! - a token's value is a hash of its kernel allocation's address, and a freed
//!   one comes straight back: after another program's `pfctl -d` freed every
//!   reference, the next `pfctl -E` got our old value 20 times out of 20. So a
//!   reference is released only while `pfctl -s References` still lists it
//!   with the pid of the `pfctl` that took it ([`still_ours`]);
//! - Internet Sharing holds its own reference (through `pfd`) and keeps its
//!   rules in `com.apple.internet-sharing`, so our stop leaves its NAT running;
//!   but when its last share stops it switches forwarding OFF, a serving exit's
//!   included, so the re-assert switches it back on;
//! - the InternetSharing process outlives its last share (by 40 s to a minute
//!   here), so "Internet Sharing is NATing" is read from its anchor's rules, not
//!   from the process.
//!
//! The anchor holds one `nat` per egress interface (Linux's MASQUERADE has no
//! `-o` either), never onto another VPN's utun, and a `pass` for the overlay
//! adapter. Forwarding (`net.inet.ip.forwarding`, and the v6 one when v6 is
//! served) is turned on and put back as found, unless Internet Sharing is
//! NATing: it needs forwarding too, and AC5 says it keeps working.
//!
//! A crash skips every `Drop`, so each serve is recorded in the host ledger
//! (anchor, references, what forwarding was) and [`purge`] undoes it at boot
//! and after every exit of the daemon.

#[allow(unused_imports)]
use tracing::{info, warn};

#[cfg(any(target_os = "macos", test))]
use std::net::Ipv6Addr;

/// Our anchors live under the stock wildcard `/etc/pf.conf` already evaluates.
#[cfg(any(target_os = "macos", test))]
pub(crate) const ANCHOR_PREFIX: &str = "com.apple/roomler-";

/// Our anchor for the overlay adapter `if_name`: one per org's adapter.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn anchor_for(if_name: &str) -> String {
    format!("{ANCHOR_PREFIX}{if_name}")
}

/// Strict, because a name read back from the ledger goes into `pfctl -a`:
/// ours and nothing else, `com.apple/roomler-utun<1-3 digits>`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn is_our_anchor(s: &str) -> bool {
    s.strip_prefix(ANCHOR_PREFIX)
        .and_then(|ifn| ifn.strip_prefix("utun"))
        .is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.chars().all(|c| c.is_ascii_digit()))
}

/// An interface name as pf takes it: lowercase letters, then digits (`en0`,
/// `utun4`, `bridge100`). Anything else never reaches a rule.
#[cfg(any(target_os = "macos", test))]
fn is_ifname(s: &str) -> bool {
    let digits = s.trim_start_matches(|c: char| c.is_ascii_lowercase());
    s.len() <= 15
        && !digits.is_empty()
        && digits.len() < s.len()
        && digits.chars().all(|c| c.is_ascii_digit())
}

/// A tunnel or loopback: never an egress for overlay traffic.
#[cfg(any(target_os = "macos", test))]
fn is_tunnel(s: &str) -> bool {
    ["utun", "ipsec", "ppp", "gif", "stf", "lo"]
        .iter()
        .any(|p| s.starts_with(p))
}

/// The interfaces overlay traffic leaves through and is NATed on: every
/// Ethernet-class (`en*`) one with an IPv4 address, plus the default route's
/// when it is not a tunnel. Never another VPN's utun: NAT onto it would hand
/// every peer a path into whatever that VPN reaches. Sorted, so the same
/// interfaces always render the same anchor.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn egress(with_v4: &[String], default_if: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = with_v4
        .iter()
        .filter(|n| n.starts_with("en") && is_ifname(n))
        .cloned()
        .collect();
    if let Some(d) = default_if
        && is_ifname(d)
        && !is_tunnel(d)
    {
        out.push(d.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The address a v6 `nat` on an interface takes, from `ifconfig <if>`: a
/// stable global one, else a stable ULA; never link-local or temporary. Not
/// `(if)`: for `inet6` pf round-robins over every address, link-local
/// included (field, FR-97 §8, 2026-10-16).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn nat66_source(ifconfig: &str) -> Option<Ipv6Addr> {
    let stable: Vec<Ipv6Addr> = ifconfig
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("inet6 ")?;
            if [
                "temporary",
                "deprecated",
                "detached",
                "tentative",
                "duplicated",
            ]
            .iter()
            .any(|f| rest.contains(f))
            {
                return None;
            }
            let a: Ipv6Addr = rest
                .split_whitespace()
                .next()?
                .split('%')
                .next()?
                .parse()
                .ok()?;
            let link_local = a.segments()[0] & 0xffc0 == 0xfe80;
            (!link_local && !a.is_loopback() && !a.is_unspecified() && !a.is_multicast())
                .then_some(a)
        })
        .collect();
    let ula = |a: &Ipv6Addr| a.segments()[0] & 0xfe00 == 0xfc00;
    // A global address first; a ULA only where the uplink has nothing else
    // (a network that NATs v6 upstream, as the FR-97 v6 cell's does).
    stable
        .iter()
        .find(|a| !ula(a))
        .or_else(|| stable.first())
        .copied()
}

/// Whether `netstat -rn -f inet6` holds an UNSCOPED default. A Mac whose
/// primary service has no v6 has only ifscoped ones (flags with `I`), and a
/// forwarded v6 packet then has no route (field, FR-97 §8, 2026-10-16).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn has_unscoped_v6_default(netstat: &str) -> bool {
    netstat.lines().any(|l| {
        let mut f = l.split_whitespace();
        f.next() == Some("default") && f.nth(1).is_some_and(|flags| !flags.contains('I'))
    })
}

/// The reference token `pfctl -E` prints: `Token : 13889181449326457865`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_token(output: &str) -> Option<u64> {
    output.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("token") {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

/// One row of `pfctl -s References`: a reference that keeps pf enabled.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StarterRef {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) token: u64,
}

/// `pfctl -s References` as macOS prints it (field, FR-97 §8):
///
/// ```text
/// TOKENS:
/// PID      Process Name                 TOKEN                    TIMESTAMP
/// 674      pfctl                        5506544203745733392      0 days 00:00:00
/// ```
///
/// or `No pf starter references held`. `None` for anything else, a row that
/// does not parse included, so a caller can tell "none held" from "could not
/// read them". A row starts with its pid; any other line is one of pfctl's
/// notices (`No ALTQ support in kernel`), which follow the table once its
/// stderr is joined after its stdout. A process name may hold spaces; the
/// timestamp is the last three fields.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_references(output: &str) -> Option<Vec<StarterRef>> {
    let mut rows = Vec::new();
    let mut header = false;
    for l in output.lines().map(str::trim) {
        if l.starts_with("No pf starter references held") {
            return Some(Vec::new());
        }
        if l.starts_with("PID") && l.contains("TOKEN") {
            header = true;
            continue;
        }
        if !header || !l.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        let n = f.len();
        if n < 6 || !f[n - 1].contains(':') || !f[n - 2].starts_with("day") {
            return None;
        }
        let (Ok(pid), Ok(token)) = (f[0].parse(), f[n - 4].parse()) else {
            return None;
        };
        rows.push(StarterRef {
            pid,
            name: f[1..n - 4].join(" "),
            token,
        });
    }
    header.then_some(rows)
}

/// Whether the reference we took as `token` is still ours. The kernel derives
/// a token's value from its allocation's address and hands a freed one
/// straight back: after another program's `pfctl -d` freed every reference,
/// the next `pfctl -E` got our old value 20 times out of 20 (field, FR-97 §8).
/// Release by value alone, and our stop would drop THAT program's reference,
/// and pf with it if it was the last. So a token is ours only while the kernel
/// lists it with the pid of the `pfctl -E` that took it. One recorded without a
/// pid (a ledger a 0.4.141 daemon wrote) is accepted only from a `pfctl`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn still_ours(token: u64, pid: Option<u32>, listed: &[StarterRef]) -> bool {
    listed.iter().any(|r| {
        r.token == token
            && match pid {
                Some(p) => r.pid == p,
                None => r.name == "pfctl",
            }
    })
}

/// The anchor's text: per egress interface a `nat` for the overlay's IPv4
/// blocks, and one for its v6 ULA where v6 is served and the interface has a
/// stable address (a global one first, else a ULA); then a `pass` for the
/// overlay adapter. Translation rules first, as pf requires. Inputs that would
/// not parse as what they claim to be never reach a rule.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn render(
    overlay_if: &str,
    egress: &[(String, Option<Ipv6Addr>)],
    overlay_v4: &[String],
    serve_v6: bool,
) -> String {
    let blocks: Vec<String> = overlay_v4
        .iter()
        .filter_map(|c| c.parse::<ipnet::Ipv4Net>().ok())
        .map(|n| n.to_string())
        .collect();
    let mut out = String::new();
    if is_ifname(overlay_if) && !blocks.is_empty() {
        let from = if blocks.len() == 1 {
            blocks[0].clone()
        } else {
            format!("{{ {} }}", blocks.join(", "))
        };
        for (name, v6) in egress.iter().filter(|(n, _)| is_ifname(n)) {
            out.push_str(&format!(
                "nat on {name} inet from {from} to any -> ({name})\n"
            ));
            if serve_v6 && let Some(a) = v6 {
                out.push_str(&format!(
                    "nat on {name} inet6 from {} to any -> {a}\n",
                    super::router::OVERLAY_ULA_V6_CIDR
                ));
            }
        }
        out.push_str(&format!("pass quick on {overlay_if} all keep state\n"));
    }
    out
}

/// The macOS side effects: probe, serve, stop, re-assert, purge.
#[cfg(target_os = "macos")]
mod host {
    use super::{
        Ipv6Addr, StarterRef, anchor_for, egress, has_unscoped_v6_default, is_ifname,
        is_our_anchor, nat66_source, parse_references, parse_token, render, still_ours,
    };
    use crate::overlay::host_ledger::{PfRecord, PfToken};
    use std::sync::{Arc, Mutex};
    use tracing::{info, warn};

    const PFCTL: &str = "/sbin/pfctl";
    const FWD4: &str = "net.inet.ip.forwarding";
    const FWD6: &str = "net.inet6.ip6.forwarding";
    /// Internet Sharing's rules live here and in the anchors below it.
    const IS_ANCHOR: &str = "com.apple.internet-sharing";
    /// How often a serving Mac re-checks its anchor, its pf reference and
    /// forwarding: another program's `pfctl -F all` or `-d`, Internet Sharing
    /// switching forwarding off as its last share stops, or an interface that
    /// came or went.
    const REASSERT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Run `pfctl`, `stdin` piped in; `(exit 0, stdout + stderr)`. pfctl
    /// prints its token and most notices on stderr.
    fn pfctl(args: &[&str], stdin: Option<&str>) -> (bool, String) {
        let (ok, out, _) = pfctl_as(args, stdin);
        (ok, out)
    }

    /// [`pfctl`], and the pid it ran as: what `pfctl -s References` lists
    /// beside a token that `pfctl -E` took.
    fn pfctl_as(args: &[&str], stdin: Option<&str>) -> (bool, String, u32) {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let child = Command::new(PFCTL)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let Ok(mut child) = child else {
            return (false, format!("{PFCTL} could not start"), 0);
        };
        let pid = child.id();
        if let (Some(text), Some(mut w)) = (stdin, child.stdin.take()) {
            let _ = w.write_all(text.as_bytes());
        }
        match child.wait_with_output() {
            Ok(o) => {
                let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                (o.status.success(), s, pid)
            }
            Err(e) => (false, e.to_string(), pid),
        }
    }

    fn run(prog: &str, args: &[&str]) -> Option<String> {
        let o = std::process::Command::new(prog).args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }

    fn sysctl_on(name: &str) -> Option<bool> {
        run("/usr/sbin/sysctl", &["-n", name]).map(|v| v.trim() != "0")
    }

    fn sysctl_set(name: &str, on: bool) -> bool {
        let kv = format!("{name}={}", if on { 1 } else { 0 });
        run("/usr/sbin/sysctl", &["-w", &kv]).is_some()
    }

    /// Whether Internet Sharing is NATing now: the share System Settings turns
    /// on, or vmnet's shared mode, the NAT behind every VM on a Mac in NAT
    /// mode. Either turns forwarding on for itself, and switching it off under
    /// it would cut whatever it serves. Its rules live in [`IS_ANCHOR`] and the
    /// anchors below it. The InternetSharing process says nothing: it outlives
    /// the last share by 40 s to a minute (field, FR-97 §8, 2026-10-17).
    fn internet_sharing_nats() -> bool {
        pf_enabled()
            && pfctl(&["-v", "-s", "Anchors"], None)
                .1
                .lines()
                .map(str::trim)
                .filter(|a| {
                    *a == IS_ANCHOR
                        || a.strip_prefix(IS_ANCHOR)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                .any(|a| {
                    pfctl(&["-a", a, "-s", "nat"], None)
                        .1
                        .lines()
                        .any(|l| l.trim_start().starts_with("nat on "))
                })
    }

    fn pf_enabled() -> bool {
        pfctl(&["-s", "info"], None)
            .1
            .lines()
            .any(|l| l.starts_with("Status: Enabled"))
    }

    /// Interfaces with an IPv4 address that are up and, where `ifconfig`
    /// reports one, `status: active`.
    fn interfaces_with_v4() -> Vec<(String, String)> {
        let Some(list) = run("/sbin/ifconfig", &["-l"]) else {
            return Vec::new();
        };
        list.split_whitespace()
            .filter(|n| is_ifname(n))
            .filter_map(|n| {
                let text = run("/sbin/ifconfig", &[n])?;
                let has_v4 = text.lines().any(|l| l.trim_start().starts_with("inet "));
                let inactive = text.lines().any(|l| l.trim() == "status: inactive");
                (has_v4 && !inactive).then(|| (n.to_string(), text))
            })
            .collect()
    }

    fn default_if() -> Option<String> {
        run("/sbin/route", &["-n", "get", "default"])?
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("interface:")
                    .map(|s| s.trim().to_string())
            })
    }

    fn unscoped_v6_default() -> bool {
        run("/usr/sbin/netstat", &["-rn", "-f", "inet6"])
            .is_some_and(|t| has_unscoped_v6_default(&t))
    }

    /// The egress interfaces with the v6 address each would NAT to.
    fn current_egress() -> Vec<(String, Option<Ipv6Addr>)> {
        let found = interfaces_with_v4();
        let names: Vec<String> = found.iter().map(|(n, _)| n.clone()).collect();
        egress(&names, default_if().as_deref())
            .into_iter()
            .map(|n| {
                let v6 = found
                    .iter()
                    .find(|(m, _)| *m == n)
                    .and_then(|(_, text)| nat66_source(text));
                (n, v6)
            })
            .collect()
    }

    fn load(anchor: &str, rules: &str) -> Result<(), String> {
        let (ok, out) = pfctl(&["-a", anchor, "-f", "-"], Some(rules));
        if ok { Ok(()) } else { Err(first_line(&out)) }
    }

    fn flush(anchor: &str) {
        let _ = pfctl(&["-a", anchor, "-F", "all"], None);
    }

    /// `pfctl -E`: a reference of our own on pf, enabling pf if it was off.
    fn take() -> Option<PfToken> {
        let (_, out, pid) = pfctl_as(&["-E"], None);
        parse_token(&out).map(|token| PfToken { token, pid })
    }

    fn release(token: u64) {
        let _ = pfctl(&["-X", &token.to_string()], None);
    }

    /// The references pf holds; `None` if they could not be read.
    fn references() -> Option<Vec<StarterRef>> {
        parse_references(&pfctl(&["-s", "References"], None).1)
    }

    /// Release those of `ours` that pf still lists as ours ([`still_ours`]),
    /// and nothing else. If the list cannot be read, release none: a
    /// reference left held only keeps pf enabled, while one released in error
    /// can switch pf off under whoever enabled it.
    fn release_ours(ours: &[(u64, Option<u32>)]) {
        if ours.is_empty() {
            return;
        }
        let Some(listed) = references() else {
            warn!(
                "overlay: could not read pf's references (pfctl -s References) — keeping ours rather than risk releasing another program's"
            );
            return;
        };
        for &(token, pid) in ours {
            if still_ours(token, pid, &listed) {
                release(token);
            } else {
                info!(
                    token,
                    ?pid,
                    "overlay: a pf reference of ours is gone (another program's pfctl -d freed it) — not releasing a value pf may have handed to someone else"
                );
            }
        }
    }

    fn first_line(s: &str) -> String {
        s.lines()
            .map(str::trim)
            .find(|l| {
                !l.is_empty()
                    && !l.contains("ALTQ")
                    && !l.starts_with("Use of -f")
                    && !l.starts_with("present in the main")
                    && !l.starts_with("See /etc")
            })
            .unwrap_or("pfctl failed")
            .chars()
            .take(200)
            .collect()
    }

    /// Can this Mac serve? `Err` says why not, for the offer and `meshharbor status`.
    pub(crate) fn probe() -> Result<(), String> {
        if !crate::env::flag("PF_NAT", true) {
            return Err(
                "the macOS pf NAT is switched off (ROOMLERD_PF_NAT=0), so this Mac \
                        cannot be an exit node or a subnet router"
                    .into(),
            );
        }
        let (ok, out) = pfctl(&["-s", "nat"], None);
        if !ok {
            return Err(format!(
                "pf is not usable here ({}): serving needs the root daemon",
                first_line(&out)
            ));
        }
        if !out.contains("nat-anchor \"com.apple/*\"") {
            return Err(
                "pf's main ruleset does not evaluate the com.apple/* anchors, and this \
                        Mac does not edit /etc/pf.conf, so it cannot NAT for its peers"
                    .into(),
            );
        }
        Ok(())
    }

    /// FR-97 P1b — this process's hold on forwarding: two orgs' routers share
    /// it, and only the last to stop puts it back. The FIRST holder's reading
    /// decides whether it was ours to turn on.
    struct Fwd {
        v4_holders: usize,
        v4_restore: bool,
        v6_holders: usize,
        v6_restore: bool,
    }
    static FWD: Mutex<Fwd> = Mutex::new(Fwd {
        v4_holders: 0,
        v4_restore: false,
        v6_holders: 0,
        v6_restore: false,
    });

    /// One served adapter. `stop` (from the guard's `Drop`) takes it all back.
    pub(crate) struct Serve {
        anchor: String,
        v6: bool,
        live: Arc<Mutex<Live>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    /// What the re-assert task and `stop` share. Every pfctl call of either
    /// happens under this lock, and `stopped` ends the task's work: aborting a
    /// task does not stop a blocking closure already running, which would
    /// otherwise load the anchor again, or take a token, after `stop`.
    struct Live {
        overlay_if: String,
        v4: Vec<String>,
        rules: String,
        tokens: Vec<PfToken>,
        stopped: bool,
    }

    fn record(anchor: &str, live: &Live, v4_restore: bool, v6_restore: bool) {
        crate::overlay::host_ledger::record_pf(PfRecord {
            anchor: anchor.to_string(),
            tokens: live.tokens.iter().map(|t| t.token).collect(),
            refs: live.tokens.clone(),
            v4_was_off: v4_restore,
            v6_was_off: v6_restore,
        });
    }

    /// Serve the overlay adapter `overlay_if` for the IPv4 blocks `v4`.
    /// `(fully ok, the serve to stop later)`; `None` only when nothing at all
    /// could be set up.
    pub(crate) async fn serve(overlay_if: &str, v4: &[String]) -> (bool, Option<Serve>) {
        let overlay_if = overlay_if.to_string();
        let v4 = v4.to_vec();
        let started = tokio::task::spawn_blocking(move || {
            let anchor = anchor_for(&overlay_if);
            let serve_v6 = unscoped_v6_default();
            let (v4_restore, v6_restore) = {
                let mut f = FWD.lock().unwrap_or_else(|e| e.into_inner());
                if f.v4_holders == 0 {
                    f.v4_restore = sysctl_on(FWD4) == Some(false);
                }
                f.v4_holders += 1;
                if serve_v6 {
                    if f.v6_holders == 0 {
                        f.v6_restore = sysctl_on(FWD6) == Some(false);
                    }
                    f.v6_holders += 1;
                }
                (f.v4_restore, serve_v6 && f.v6_restore)
            };
            let mut ok = sysctl_set(FWD4, true);
            if serve_v6 {
                ok &= sysctl_set(FWD6, true);
            } else {
                info!("overlay: pf exit — no unscoped IPv6 default route here, so IPv6 is not served (clients stay v6 fail-closed)");
            }
            let rules = render(&overlay_if, &current_egress(), &v4, serve_v6);
            if let Err(e) = load(&anchor, &rules) {
                warn!(%anchor, err = %e, "overlay: pf anchor load failed");
                ok = false;
            }
            let mut live = Live {
                overlay_if,
                v4,
                rules,
                tokens: Vec::new(),
                stopped: false,
            };
            match take() {
                Some(t) => live.tokens.push(t),
                None => {
                    warn!("overlay: pfctl -E returned no token; pf may not be enabled");
                    ok = false;
                }
            }
            record(&anchor, &live, v4_restore, v6_restore);
            info!(%anchor, rules = %live.rules.trim().replace('\n', " | "), "overlay: pf NAT for the overlay loaded");
            (ok, anchor, serve_v6, live)
        })
        .await;
        let Ok((ok, anchor, serve_v6, live)) = started else {
            return (false, None);
        };
        let live = Arc::new(Mutex::new(live));
        let task = tokio::spawn(reassert(anchor.clone(), serve_v6, live.clone()));
        (
            ok,
            Some(Serve {
                anchor,
                v6: serve_v6,
                live,
                task: Some(task),
            }),
        )
    }

    /// Keep the serve as served, every [`REASSERT`]. See [`reassert_once`].
    async fn reassert(anchor: String, v6: bool, live: Arc<Mutex<Live>>) {
        loop {
            tokio::time::sleep(REASSERT).await;
            let anchor = anchor.clone();
            let live = live.clone();
            let _ = tokio::task::spawn_blocking(move || reassert_once(&anchor, v6, &live)).await;
        }
    }

    /// One re-assert. Another program may flush all rules, disable pf, or
    /// switch forwarding off (Internet Sharing does, as its last share stops,
    /// under a serving exit too: field, FR-97 §8, 2026-10-17); an interface
    /// may come or go (a re-render follows the new set). Logs only what it
    /// changes.
    fn reassert_once(anchor: &str, v6: bool, live: &Mutex<Live>) {
        let mut l = live.lock().unwrap_or_else(|e| e.into_inner());
        if l.stopped {
            return;
        }
        let rules = render(&l.overlay_if, &current_egress(), &l.v4, v6);
        let present = pfctl(&["-a", anchor, "-s", "nat"], None)
            .1
            .contains("nat on ");
        if rules != l.rules || !present {
            match load(anchor, &rules) {
                Ok(()) => {
                    info!(%anchor, flushed = !present, rules = %rules.trim().replace('\n', " | "), "overlay: pf anchor re-asserted")
                }
                Err(e) => warn!(%anchor, err = %e, "overlay: pf anchor re-assert failed"),
            }
            l.rules = rules;
        }
        // Our reference. Another program's `pfctl -d` frees every one, ours
        // with it, and pf may hand our value to whoever takes the next: keep
        // only what pf still lists as ours, and always hold one.
        let mut changed = false;
        let was_disabled = !pf_enabled();
        if was_disabled {
            changed |= !l.tokens.is_empty();
            l.tokens.clear();
        } else if let Some(listed) = references() {
            let before = l.tokens.len();
            l.tokens
                .retain(|t| still_ours(t.token, Some(t.pid), &listed));
            changed |= l.tokens.len() != before;
        }
        if l.tokens.is_empty() {
            match take() {
                Some(t) => {
                    l.tokens.push(t);
                    changed = true;
                    if was_disabled {
                        warn!("overlay: pf was disabled under a serving exit — enabled it again");
                    } else {
                        warn!(
                            "overlay: another program dropped our pf reference (its pfctl -d) — took a new one"
                        );
                    }
                }
                None => warn!("overlay: pfctl -E returned no token; pf may not stay enabled"),
            }
        }
        // Forwarding. Whoever switched it off wanted it off, so from now on
        // our stop puts it back off too.
        let mut f = FWD.lock().unwrap_or_else(|e| e.into_inner());
        if sysctl_on(FWD4) == Some(false) && sysctl_set(FWD4, true) {
            warn!(
                "overlay: IPv4 forwarding was switched off under a serving exit — switched it back on"
            );
            f.v4_restore = true;
            changed = true;
        }
        if v6 && sysctl_on(FWD6) == Some(false) && sysctl_set(FWD6, true) {
            warn!(
                "overlay: IPv6 forwarding was switched off under a serving exit — switched it back on"
            );
            f.v6_restore = true;
            changed = true;
        }
        if changed {
            record(anchor, &l, f.v4_restore, v6 && f.v6_restore);
        }
    }

    impl Serve {
        /// Run one re-assert now, as the task does every [`REASSERT`].
        #[cfg(test)]
        pub(crate) fn reassert_now(&self) {
            reassert_once(&self.anchor, self.v6, &self.live);
        }

        /// Our recorded references now carry the value `token`, their pid
        /// kept: the state pf leaves whenever it hands our freed value to
        /// another program, made certain for a test.
        #[cfg(test)]
        pub(crate) fn pretend_ours_is(&self, token: u64) {
            let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
            for t in &mut l.tokens {
                t.token = token;
            }
        }

        /// Flush the anchor, release the references that are still ours
        /// (never `pfctl -d`), and put forwarding back as found once the last
        /// holder stops.
        pub(crate) fn stop(mut self) {
            if let Some(t) = self.task.take() {
                t.abort();
            }
            // Under the lock: waits out a re-assert already running, and no
            // later one does anything.
            let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
            l.stopped = true;
            flush(&self.anchor);
            let ours: Vec<(u64, Option<u32>)> = std::mem::take(&mut l.tokens)
                .into_iter()
                .map(|t| (t.token, Some(t.pid)))
                .collect();
            release_ours(&ours);
            drop(l);
            let sharing = internet_sharing_nats();
            let mut f = FWD.lock().unwrap_or_else(|e| e.into_inner());
            f.v4_holders = f.v4_holders.saturating_sub(1);
            if f.v4_holders == 0 && f.v4_restore && !sharing {
                sysctl_set(FWD4, false);
            }
            if self.v6 {
                f.v6_holders = f.v6_holders.saturating_sub(1);
                if f.v6_holders == 0 && f.v6_restore && !sharing {
                    sysctl_set(FWD6, false);
                }
            }
            crate::overlay::host_ledger::forget_pf(&self.anchor);
            info!(anchor = %self.anchor, internet_sharing = sharing, "overlay: pf NAT for the overlay reverted");
        }
    }

    /// The boot / after-exit purge: what a crashed serve left.
    pub(crate) fn purge(records: &[PfRecord]) {
        let ours: Vec<&PfRecord> = records
            .iter()
            .filter(|r| is_our_anchor(&r.anchor))
            .collect();
        if ours.is_empty() {
            return;
        }
        let mut held: Vec<(u64, Option<u32>)> = Vec::new();
        for r in &ours {
            flush(&r.anchor);
            held.extend(r.refs.iter().map(|t| (t.token, Some(t.pid))));
            // A ledger a 0.4.141 daemon wrote has token values only.
            held.extend(
                r.tokens
                    .iter()
                    .filter(|v| !r.refs.iter().any(|t| t.token == **v))
                    .map(|v| (*v, None)),
            );
        }
        release_ours(&held);
        let sharing = internet_sharing_nats();
        if !sharing {
            if ours.iter().any(|r| r.v4_was_off) && sysctl_on(FWD4) == Some(true) {
                sysctl_set(FWD4, false);
            }
            if ours.iter().any(|r| r.v6_was_off) && sysctl_on(FWD6) == Some(true) {
                sysctl_set(FWD6, false);
            }
        }
        warn!(
            anchors = ?ours.iter().map(|r| r.anchor.as_str()).collect::<Vec<_>>(),
            internet_sharing = sharing,
            "overlay: a pf exit left its anchor (an exit that skipped its revert) — flushed it, released its pf reference and put forwarding back"
        );
    }
}

#[cfg(target_os = "macos")]
pub(crate) use host::{Serve, probe, serve};

/// The pf half of [`super::host_ledger::purge`]. No-op off macOS.
pub(crate) fn purge(records: &[super::host_ledger::PfRecord]) {
    #[cfg(target_os = "macos")]
    host::purge(records);
    #[cfg(not(target_os = "macos"))]
    let _ = records;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_anchor_is_one_level_under_the_stock_wildcard_and_nothing_else() {
        assert_eq!(anchor_for("utun4"), "com.apple/roomler-utun4");
        assert!(is_our_anchor("com.apple/roomler-utun4"));
        assert!(is_our_anchor("com.apple/roomler-utun123"));
        for bad in [
            "com.apple/roomler-utun",
            "com.apple/roomler-utun1234",
            "com.apple/roomler-en0",
            "com.apple/internet-sharing",
            "com.apple/roomler-utun4; pfctl -d",
            "com.apple/*",
            "roomler-utun4",
        ] {
            assert!(!is_our_anchor(bad), "{bad}");
        }
    }

    #[test]
    fn egress_is_every_ethernet_class_interface_plus_a_non_tunnel_default() {
        let up = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            egress(
                &up(&["en0", "en7", "lo0", "utun4", "bridge100"]),
                Some("en0")
            ),
            vec!["en0", "en7"]
        );
        // a default that is not `en*` but is real joins
        assert_eq!(
            egress(&up(&["en0"]), Some("bridge0")),
            vec!["bridge0", "en0"]
        );
        // never another VPN's tunnel, even as the default
        assert_eq!(egress(&up(&["en0"]), Some("utun3")), vec!["en0"]);
        assert_eq!(egress(&up(&["en0"]), Some("ppp0")), vec!["en0"]);
        // junk never reaches a rule
        assert_eq!(
            egress(&up(&["en0;x", "EN1", "en"]), Some("en0 ")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_v6_nat_target_is_stable_global_first_never_link_local_or_temporary() {
        let ifc = "en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                   \tinet6 fe80::1448:e811:8eee:e167%en7 prefixlen 64 secured scopeid 0x20\n\
                   \tinet6 fd00:ac4::2 prefixlen 64\n\
                   \tinet6 2001:db8:51b:fb6b:1c2a:3b4c:5d6e:7f80 prefixlen 64 autoconf temporary\n\
                   \tinet6 2001:db8:51b:fb6b:aaaa:bbbb:cccc:dddd prefixlen 64 autoconf secured\n\
                   \tinet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15\n";
        // the global wins over a ULA listed before it; the temporary never counts
        assert_eq!(
            nat66_source(ifc),
            Some("2001:db8:51b:fb6b:aaaa:bbbb:cccc:dddd".parse().unwrap())
        );
        // a ULA where the uplink has nothing else (v6 NATed upstream)
        assert_eq!(
            nat66_source("\tinet6 fe80::1%en0 prefixlen 64\n\tinet6 fd00:ac4::2 prefixlen 64\n"),
            Some("fd00:ac4::2".parse().unwrap())
        );
        // link-local alone, or no v6 at all: nothing to NAT to
        assert_eq!(
            nat66_source("\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0x4\n"),
            None
        );
        assert_eq!(
            nat66_source("\tinet 192.168.8.106 netmask 0xffffff00\n"),
            None
        );
    }

    #[test]
    fn only_an_unscoped_v6_default_serves_v6() {
        // the field Mac: Wi-Fi primary without v6, the iPhone's v6 default ifscoped
        let scoped = "Routing tables\n\nInternet6:\nDestination        Gateway                        Flags         Netif Expire\n\
                      default            fe80::%utun1                   UGcIg         utun1\n\
                      default            fe80::30e0:4fff:fe04:ac64%en7  UGcIg           en7\n";
        assert!(!has_unscoped_v6_default(scoped));
        let unscoped = "Internet6:\nDestination        Gateway                        Flags         Netif Expire\n\
                        default            fe80::1%en0                    UGc             en0\n";
        assert!(has_unscoped_v6_default(unscoped));
        assert!(!has_unscoped_v6_default(""));
    }

    #[test]
    fn the_token_pfctl_e_prints_is_read_back() {
        assert_eq!(
            parse_token("pf enabled\nToken : 13889181449326457865\n"),
            Some(13889181449326457865)
        );
        assert_eq!(
            parse_token("No ALTQ support in kernel\nToken : 7\n"),
            Some(7)
        );
        assert_eq!(parse_token("pfctl: /dev/pf: Permission denied\n"), None);
    }

    /// `pfctl -s References` as a macOS VM printed it (FR-97 §8, 2026-10-17):
    /// our `pfctl -E` and Internet Sharing's `pfd`.
    const REFS: &str = "No ALTQ support in kernel\n\
                        ALTQ related functions disabled\n\
                        TOKENS:\n\
                        PID      Process Name                 TOKEN                    TIMESTAMP\n\
                        751      pfctl                        5506544203745733392      0 days 00:00:00\n\
                        672      pfd                          15547325524921387773     0 days 00:00:07\n";

    #[test]
    fn pf_references_are_read_with_the_pid_and_name_that_took_each() {
        let refs = parse_references(REFS).expect("the listing parses");
        assert_eq!(
            refs,
            vec![
                StarterRef {
                    pid: 751,
                    name: "pfctl".into(),
                    token: 5506544203745733392
                },
                StarterRef {
                    pid: 672,
                    name: "pfd".into(),
                    token: 15547325524921387773
                },
            ]
        );
        assert_eq!(
            parse_references(
                "No ALTQ support in kernel\nALTQ related functions disabled\nNo pf starter references held\n"
            ),
            Some(vec![])
        );
        // As the daemon reads it: stdout (the table), THEN stderr (the
        // notices). Read as notices, not as rows that fail to parse: the first
        // cut returned None here, so a stop kept our reference and pf stayed
        // on (CI's macOS kernel test, 2026-10-17).
        let joined = "TOKENS:\n\
                      PID      Process Name                 TOKEN                    TIMESTAMP\n\
                      751      pfctl                        5506544203745733392      0 days 00:00:00\n\
                      No ALTQ support in kernel\n\
                      ALTQ related functions disabled\n";
        assert_eq!(
            parse_references(joined).map(|r| r.len()),
            Some(1),
            "the notices after the table are not rows"
        );
        assert_eq!(
            parse_references(
                "No pf starter references held\nNo ALTQ support in kernel\nALTQ related functions disabled\n"
            ),
            Some(vec![])
        );
        // A name with a space, and a token held for days.
        let r = parse_references(
            "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n\
             901      Some VPN Helper              42                       3 days 04:05:06\n",
        )
        .expect("parses");
        assert_eq!(
            (r[0].pid, r[0].name.as_str(), r[0].token),
            (901, "Some VPN Helper", 42)
        );
        // Anything else is "could not read them", never "none held".
        for unknown in [
            "",
            "pfctl: /dev/pf: Permission denied\n",
            "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n\
             751      pfctl                        notanumber               0 days 00:00:00\n",
            "TOKENS:\nPID      Process Name                 TOKEN\n751      pfctl     7\n",
        ] {
            assert_eq!(parse_references(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn a_reference_is_ours_only_while_pf_lists_it_with_our_pid() {
        let refs = parse_references(REFS).unwrap();
        assert!(still_ours(5506544203745733392, Some(751), &refs));
        // The value came back to another program after its `pfctl -d`: the
        // same token, another pid. Releasing it would drop THEIR reference.
        assert!(!still_ours(5506544203745733392, Some(750), &refs));
        assert!(!still_ours(15547325524921387773, Some(751), &refs));
        // Freed and not handed out again.
        assert!(!still_ours(7, Some(751), &refs));
        assert!(!still_ours(7, None, &refs));
        // A 0.4.141 ledger's value has no pid: only a `pfctl`'s is ours.
        assert!(still_ours(5506544203745733392, None, &refs));
        assert!(!still_ours(15547325524921387773, None, &refs));
        assert!(!still_ours(5506544203745733392, Some(751), &[]));
    }

    #[test]
    fn the_anchor_nats_every_egress_and_passes_the_overlay_adapter() {
        let v6: Ipv6Addr = "2001:db8:51b:fb6b:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let eg = vec![("en0".to_string(), None), ("en7".to_string(), Some(v6))];
        let one = render("utun4", &eg, &["100.65.20.0/24".into()], true);
        assert_eq!(
            one,
            "nat on en0 inet from 100.65.20.0/24 to any -> (en0)\n\
             nat on en7 inet from 100.65.20.0/24 to any -> (en7)\n\
             nat on en7 inet6 from fd72:6f6f:6d6c::/96 to any -> 2001:db8:51b:fb6b:aaaa:bbbb:cccc:dddd\n\
             pass quick on utun4 all keep state\n"
        );
        // v6 not served: no inet6 rule even where an address exists
        assert!(!render("utun4", &eg, &["100.65.20.0/24".into()], false).contains("inet6"));
        // a grown org: every block (FR-47 P5e)
        assert!(
            render(
                "utun4",
                &eg[..1],
                &["100.65.20.0/24".into(), "100.65.21.0/24".into()],
                false
            )
            .starts_with(
                "nat on en0 inet from { 100.65.20.0/24, 100.65.21.0/24 } to any -> (en0)\n"
            )
        );
    }

    #[test]
    fn nothing_that_does_not_parse_reaches_a_rule() {
        let eg = vec![("en0".to_string(), None)];
        assert_eq!(
            render(
                "utun4",
                &eg,
                &["100.65.20.0/24 to any -> (en0)\npass all".into()],
                false
            ),
            ""
        );
        assert_eq!(
            render("utun4;x", &eg, &["100.65.20.0/24".into()], false),
            ""
        );
        assert_eq!(
            render(
                "utun4",
                &[("en0 inet".to_string(), None)],
                &["100.65.20.0/24".into()],
                false
            ),
            "pass quick on utun4 all keep state\n"
        );
    }
}

/// FR-97 P1b — on a real Mac, as root: CI's `macos_kernel_tests` step runs
/// these under `sudo` with `ROOMLER_TUN_KERNEL_TEST=1`.
#[cfg(all(test, target_os = "macos"))]
mod macos_kernel_tests {
    /// `Enabled` or `Disabled`: the word alone. The line around it changes
    /// with a toggle (`Disabled for 0 days 00:00:00` once pf has been on),
    /// which CI's first run compared and failed on with pf correctly off.
    fn pf_status() -> String {
        let o = std::process::Command::new("/sbin/pfctl")
            .args(["-s", "info"])
            .output()
            .expect("pfctl");
        let s = String::from_utf8_lossy(&o.stdout).into_owned();
        s.lines()
            .find(|l| l.starts_with("Status:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("")
            .to_string()
    }

    fn anchor_nat(anchor: &str) -> String {
        let o = std::process::Command::new("/sbin/pfctl")
            .args(["-a", anchor, "-s", "nat"])
            .output()
            .expect("pfctl");
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn fwd4() -> String {
        let o = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .expect("sysctl");
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    #[tokio::test]
    async fn a_served_anchor_nats_and_pf_and_forwarding_are_left_as_found() {
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").is_err() {
            return;
        }
        super::probe().expect("this runner's pf evaluates com.apple/* (the stock pf.conf)");
        let (status0, fwd0) = (pf_status(), fwd4());
        let anchor = super::anchor_for("utun199");
        let (ok, serve) = super::serve("utun199", &["100.64.0.0/10".to_string()]).await;
        let serve = serve.expect("a serve to stop");
        assert!(ok, "the serve set up fully");
        assert_eq!(pf_status(), "Enabled", "pf enabled by our token");
        assert!(
            anchor_nat(&anchor).contains("nat on "),
            "our anchor holds its nat: {}",
            anchor_nat(&anchor)
        );
        assert_eq!(fwd4(), "1", "forwarding on while serving");
        // Read as the daemon reads it (stdout, then stderr).
        let listed = pfctl(&["-s", "References"]);
        eprintln!("pf references while serving:\n{listed}");
        let refs = super::parse_references(&listed).expect("pf's references parse");
        assert_eq!(
            refs.iter().filter(|r| r.name == "pfctl").count(),
            1,
            "one reference of ours: {refs:?}"
        );
        serve.stop();
        assert_eq!(anchor_nat(&anchor).trim(), "", "our anchor is empty again");
        assert_eq!(pf_status(), status0, "pf back as found");
        assert_eq!(fwd4(), fwd0, "forwarding back as found");
    }

    /// `pfctl` as "another program" would run it; stdout + stderr.
    fn pfctl(args: &[&str]) -> String {
        let o = std::process::Command::new("/sbin/pfctl")
            .args(args)
            .output()
            .expect("pfctl");
        let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&o.stderr));
        s
    }

    fn set_fwd4(on: bool) {
        let kv = if on {
            "net.inet.ip.forwarding=1"
        } else {
            "net.inet.ip.forwarding=0"
        };
        let _ = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-w", kv])
            .output();
    }

    /// These two play "another program" with `pfctl -d`, which frees every
    /// reference on the box: only where nothing else holds pf.
    fn pf_idle() -> bool {
        let idle = pf_status() == "Disabled";
        if !idle {
            eprintln!("pf is in use on this runner; skipping a test that runs pfctl -d");
        }
        idle
    }

    /// Another program's `pfctl -d` frees our reference, and its next
    /// `pfctl -E` may get our old value back (20 times out of 20 on a macOS
    /// VM, FR-97 §8). Our stop must leave THAT reference alone, and pf on.
    #[tokio::test]
    async fn another_programs_reference_with_our_old_value_is_never_released() {
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").is_err() || !pf_idle() {
            return;
        }
        let (status0, fwd0) = (pf_status(), fwd4());
        let (_, serve) = super::serve("utun198", &["100.64.0.0/10".to_string()]).await;
        let serve = serve.expect("a serve to stop");
        let ours = super::parse_references(&pfctl(&["-s", "References"])).expect("listed");
        pfctl(&["-d"]);
        let theirs = super::parse_token(&pfctl(&["-E"])).expect("their token");
        eprintln!(
            "their pfctl -E got our old value back: {}",
            ours.iter().any(|r| r.token == theirs)
        );
        // Whether or not the kernel recycled it this time, make the collision
        // certain: our record holds their value, our pid. Released by value,
        // as #2362 did, their reference goes and pf with it.
        serve.pretend_ours_is(theirs);
        serve.stop();
        assert_eq!(pf_status(), "Enabled", "their reference still holds pf on");
        pfctl(&["-X", &theirs.to_string()]);
        assert_eq!(pf_status(), status0, "pf back as found once they let go");
        assert_eq!(fwd4(), fwd0, "forwarding back as found");
    }

    /// Internet Sharing switches forwarding off as its last share stops, a
    /// serving exit's included (FR-97 §8), and another program may run
    /// `pfctl -d`. One re-assert puts both back with ONE reference of ours;
    /// the stop then leaves forwarding off, as the program that switched it
    /// off wanted it.
    #[tokio::test]
    async fn forwarding_and_pf_switched_off_under_a_serve_come_back() {
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").is_err() || !pf_idle() {
            return;
        }
        let (status0, fwd0) = (pf_status(), fwd4());
        let anchor = super::anchor_for("utun197");
        let (_, serve) = super::serve("utun197", &["100.64.0.0/10".to_string()]).await;
        let serve = serve.expect("a serve to stop");
        set_fwd4(false);
        pfctl(&["-d"]);
        serve.reassert_now();
        assert_eq!(fwd4(), "1", "forwarding switched back on");
        assert_eq!(pf_status(), "Enabled", "pf enabled again");
        assert!(
            anchor_nat(&anchor).contains("nat on "),
            "our anchor still NATs"
        );
        let refs = super::parse_references(&pfctl(&["-s", "References"])).expect("listed");
        assert_eq!(
            refs.iter().filter(|r| r.name == "pfctl").count(),
            1,
            "exactly one reference of ours: {refs:?}"
        );
        serve.stop();
        assert_eq!(pf_status(), status0, "pf back as found");
        assert_eq!(
            fwd4(),
            "0",
            "forwarding left off, as whoever switched it off left it"
        );
        set_fwd4(fwd0 == "1");
    }
}
