// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD

//! FR-72 P6 — the last rung of the MagicDNS ladder.
//!
//! The preferred path is the OS split-DNS steer (`dns::configure_os`): dynamic,
//! whole-zone, nothing written to disk. On some managed hosts it cannot work at
//! all — a corporate DNS-enforcement layer intercepts the machine's own DNS
//! egress and refuses queries to any non-approved resolver, **including the
//! host's own overlay address**. Field-measured: the same resolver, at the same
//! moment, answers a peer correctly and refuses its own host with `REFUSED`
//! (RA=0, which our resolver never emits — `dns.rs` always sets RA=1).
//!
//! The hosts file is not on the DNS path at all, which is exactly why it
//! survives that. This module owns a **delimited block** in it, so the file's
//! other lines — a corporate VPN's, an operator's — are preserved byte for byte.
//!
//! ⚠️ **FQDNs only, never bare labels.** Writing `mars` into a corporate
//! machine's hosts file would shadow a real internal host; only
//! `mars.<magic domain>` is ever written.
//!
//! ⚠️ **A stale entry is the hazard**, not the write. Overlay addresses are
//! recycled, so a line left behind by a hard exit can silently send traffic to
//! a different machine — the same class of bug as pooling an overlay address
//! before its tombstone. The block is therefore cleared when the ladder climbs
//! back to DNS, cleared on runtime teardown, and cleared at runtime start
//! before anything else (the boot reconciler: whatever a previous process left
//! is not trusted, it is removed and re-derived).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Markers delimiting the block this module owns. Anything between them is
/// ours to rewrite; anything outside is never touched.
const BEGIN: &str = "# BEGIN meshharbor magicdns (managed — edits here are overwritten)";
const END: &str = "# END meshharbor magicdns";

/// One name's addresses. `v6` is `None` when AAAA answers are switched off.
pub type Entry = (String, Ipv4Addr, Option<Ipv6Addr>);

/// The OS hosts file.
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Render the managed block for `entries` (already sorted by the caller).
fn render(entries: &[Entry], nl: &str) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push_str(nl);
    for (name, v4, v6) in entries {
        out.push_str(&format!("{v4} {name}{nl}"));
        if let Some(v6) = v6 {
            out.push_str(&format!("{v6} {name}{nl}"));
        }
    }
    out.push_str(END);
    out
}

/// Strip our block from `content`, returning the remainder. A file with no
/// block comes back unchanged; an unterminated block (a previous process killed
/// mid-write) is dropped to the end, which is the safe reading — a half-written
/// block must never be left behind as live entries.
fn strip_block(content: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in content.lines() {
        let t = line.trim();
        if t == BEGIN {
            inside = true;
            continue;
        }
        if t == END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    out.join("\n")
}

/// Replace the managed block with `entries`; an empty slice removes it.
///
/// Returns `Ok(true)` when the file was actually rewritten — the caller uses
/// that to keep a periodic reconcile from touching a system file every tick.
pub fn write_block(entries: &[Entry]) -> io::Result<bool> {
    let path = hosts_path();
    // A missing hosts file is not an error to us: treat it as empty and create
    // it. (It is always present on Windows, and effectively always on Unix.)
    let original = std::fs::read_to_string(&path).unwrap_or_default();

    // Match the file's own line endings rather than the platform's: a Windows
    // hosts file is CRLF, but an operator's editor may have left LF, and
    // rewriting the whole file in the other convention would show up as a
    // wholesale diff in any tool watching it.
    let nl = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let body = strip_block(&original);
    let body = body.trim_end_matches(['\r', '\n']).to_string();

    let mut next = if nl == "\r\n" {
        body.replace('\n', "\r\n")
    } else {
        body
    };
    if !entries.is_empty() {
        if !next.is_empty() {
            next.push_str(nl);
        }
        next.push_str(&render(entries, nl));
    }
    if !next.is_empty() {
        next.push_str(nl);
    }

    if next == original {
        return Ok(false);
    }
    write_atomic(&path, &next)?;
    Ok(true)
}

/// Remove the managed block entirely.
pub fn clear_block() -> io::Result<bool> {
    write_block(&[])
}

/// Write via a sibling temp file + rename, so a crash mid-write cannot leave
/// the system's hosts file truncated.
///
/// ⚠️ Falls back to a direct write when the rename fails: on Windows an AV or
/// backup agent can hold a transient handle on `etc\hosts`, and refusing to
/// write at all would mean the fallback silently stops working on exactly the
/// managed hosts it exists for. The direct write is the lesser risk — the file
/// is small and written in one call.
fn write_atomic(path: &std::path::Path, content: &str) -> io::Result<()> {
    let tmp = path.with_extension("meshharbor-tmp");
    match std::fs::write(&tmp, content).and_then(|()| std::fs::rename(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            tracing::debug!(%e, "magicdns hosts: atomic replace failed, writing in place");
            std::fs::write(path, content)
        }
    }
}

/// How often the ladder re-tests the DNS rung. Cheap (one `getaddrinfo`), and
/// the interval is the worst-case lag before a host whose DNS came back climbs
/// off the hosts file.
const PROBE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// A `getaddrinfo` that has not answered in this long is a failure. Generous:
/// on an enforced-DNS host the query is refused fast, but a corporate resolver
/// under load can be slow, and a false "DNS is broken" would write the fallback
/// on a host that does not need it.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The MagicDNS resolution ladder: prefer the OS DNS steer, fall back to the
/// hosts file, and **climb back** as soon as DNS works again.
///
/// The rung is chosen by measurement, never assumed — the same rule the carrier
/// cascade follows. The measurement is [`dns::PROBE_LABEL`], a name only our own
/// resolver answers, resolved through the OS: it succeeds exactly when the OS
/// steer reaches us.
pub struct Ladder {
    enabled: bool,
    magic_domain: String,
    /// Is our block currently in the file?
    active: bool,
    next_probe: std::time::Instant,
}

impl Ladder {
    /// `enabled` is the kill switch (`MESHHARBORD_MAGICDNS_HOSTS`).
    ///
    /// ⚠️ Construction CLEARS any existing block — the boot reconciler. A block
    /// left by a previous process describes a netmap we have not verified, and
    /// overlay addresses are recycled, so it is removed and re-derived rather
    /// than trusted.
    pub fn new(magic_domain: String, enabled: bool) -> Self {
        match clear_block() {
            Ok(true) => tracing::info!("magicdns hosts: cleared a block left by a previous run"),
            Ok(false) => {}
            Err(e) => tracing::warn!(%e, "magicdns hosts: could not clear a stale block"),
        }
        Self {
            enabled,
            magic_domain,
            active: false,
            next_probe: std::time::Instant::now(),
        }
    }

    /// Does the OS resolve a name only our resolver can answer?
    async fn dns_reaches_us(&self) -> bool {
        let host = format!("{}.{}:0", super::dns::PROBE_LABEL, self.magic_domain);
        match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host(host)).await {
            Ok(Ok(mut addrs)) => addrs.next().is_some(),
            _ => false,
        }
    }

    /// Called from the runtime's periodic tick.
    pub async fn tick(&mut self, names: &super::dns::NameMap, answer_aaaa: bool) {
        if !self.enabled {
            self.deactivate("switch off");
            return;
        }
        if std::time::Instant::now() < self.next_probe {
            // Between probes, keep an ACTIVE block in step with the netmap —
            // a peer that joined or changed address must not be missing from it.
            if self.active {
                self.write(names, answer_aaaa);
            }
            return;
        }
        self.next_probe = std::time::Instant::now() + PROBE_EVERY;

        if self.dns_reaches_us().await {
            // Never ratchet: DNS works, so give the file back.
            self.deactivate("the OS DNS path reaches the resolver again");
        } else {
            if !self.active {
                tracing::warn!(
                    domain = %self.magic_domain,
                    "magicdns: the OS DNS path does not reach our resolver — \
                     falling back to hosts-file entries"
                );
            }
            self.active = true;
            self.write(names, answer_aaaa);
        }
    }

    fn write(&mut self, names: &super::dns::NameMap, answer_aaaa: bool) {
        // `try_read` on purpose: the map is written by the netmap path, and a
        // periodic reconcile must never block it. A skipped tick costs at most
        // one interval.
        let Ok(map) = names.try_read() else { return };
        let mut entries: Vec<Entry> = map
            .iter()
            .map(|(label, v4)| {
                let name = format!("{label}.{}", self.magic_domain);
                let v6 = answer_aaaa.then(|| super::router::derive_overlay_v6(*v4));
                (name, *v4, v6)
            })
            .collect();
        drop(map);
        // Deterministic order, so an unchanged netmap never rewrites the file.
        entries.sort();
        match write_block(&entries) {
            Ok(true) => tracing::info!(
                count = entries.len(),
                "magicdns hosts: wrote the managed block"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(%e, "magicdns hosts: write failed"),
        }
    }

    fn deactivate(&mut self, why: &str) {
        if !self.active {
            return;
        }
        self.active = false;
        match clear_block() {
            Ok(_) => tracing::info!(%why, "magicdns hosts: removed the managed block"),
            Err(e) => tracing::warn!(%e, %why, "magicdns hosts: could not remove the block"),
        }
    }

    /// Runtime teardown. ⚠️ Must run on every exit path: a block that outlives
    /// the daemon points names at addresses nothing is serving, and a recycled
    /// overlay address makes that actively wrong rather than merely dead.
    pub fn shutdown(&mut self) {
        self.deactivate("runtime shutting down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, v4: [u8; 4]) -> Entry {
        (name.into(), Ipv4Addr::from(v4), None)
    }

    #[test]
    fn foreign_lines_survive_and_the_block_round_trips() {
        let foreign = "127.0.0.1 localhost\n10.0.0.5 corp-fileserver\n";
        let with = format!(
            "{foreign}{}\n",
            render(&[e("mars.myorg.example", [100, 65, 4, 14])], "\n")
        );
        // Stripping ours leaves theirs untouched, byte for byte.
        assert_eq!(
            strip_block(&with).trim_end_matches('\n'),
            foreign.trim_end_matches('\n')
        );
    }

    #[test]
    fn an_unterminated_block_is_dropped_not_kept() {
        // A process killed mid-write leaves BEGIN with no END. Those lines must
        // NOT survive as live entries: a stale overlay address silently routes
        // to whatever machine holds it now.
        let broken = format!("127.0.0.1 localhost\n{BEGIN}\n100.65.4.14 mars.myorg.example\n");
        let left = strip_block(&broken);
        assert!(
            !left.contains("mars.myorg.example"),
            "a half-written block must be discarded, not adopted"
        );
        assert!(left.contains("localhost"), "foreign lines still survive");
    }

    #[test]
    fn only_fqdns_are_rendered() {
        // ⚠️ A bare label would shadow a real corporate host of the same name.
        let out = render(&[e("mars.myorg.example", [100, 65, 4, 14])], "\n");
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split_whitespace().nth(1).unwrap();
            assert!(name.contains('.'), "{name} is not an FQDN");
        }
    }

    #[test]
    fn v6_is_emitted_beside_v4_when_present() {
        let entries: Vec<Entry> = vec![(
            "mars.myorg.example".into(),
            Ipv4Addr::new(100, 65, 4, 14),
            Some("fd72:6f6f:6d6c::6441:40e".parse().unwrap()),
        )];
        let out = render(&entries, "\n");
        assert!(out.contains("100.65.4.14 mars.myorg.example"));
        assert!(out.contains("fd72:6f6f:6d6c::6441:40e mars.myorg.example"));
    }
}
