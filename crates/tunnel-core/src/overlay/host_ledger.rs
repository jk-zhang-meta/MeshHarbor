// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P0b-2b — host state this daemon changes that must not outlive it.
//!
//! A subnet router or exit node on Windows turns IPv4 forwarding on, on the
//! overlay adapter and on the egress adapter of every route it serves:
//! Windows ships every interface `Forwarding: Disabled` and forwards a packet
//! only when both ends have it enabled. The revert used to run `Remove-NetNat`
//! alone, so a device that stopped serving kept routing between its adapters
//! for as long as it ran (#2077, defect 2). An unclean exit (a crash, `kill`,
//! a watchdog or self-update `process::exit`) skips every `Drop`, so the
//! revert must also be reachable from the context-free boot purge.
//!
//! Two parts:
//! - [`ForwardingHolds`]: the in-process record, refcounted per interface.
//!   Two orgs' routers can share one egress adapter, and the first to stop
//!   must not switch forwarding off under the other. The FIRST holder's
//!   observation decides whether the interface is ours to restore: a later
//!   holder sees `Enabled` because we enabled it.
//! - [`HostLedger`]: the same facts persisted, in one place per machine
//!   (`store`), so the boot purge can restore what a crashed run turned on.
//!   Only stable identities are written (an adapter GUID): an ifIndex can
//!   name a different interface after a reboot.
//!
//! FR-97 P0e (N13) — the exit client's carrier-endpoint pins live here too.
//! A pin is a host route through the PHYSICAL uplink, so it does not die with
//! the TUN the way the `/1`s do, and no shutdown path tore exit routing down:
//! field, a tart Mac on 0.4.134, a clean stop left the coordination server's
//! `/32` in the table. Harmless on the same network; after the next network
//! change it points at a next hop that no longer answers, the restarted
//! daemon's control WebSocket cannot reach the server, and the overlay
//! runtime that would re-pin never starts. Every pin is recorded when it is
//! made and forgotten when it is removed, and [`purge`] removes what is left
//! at boot (before the overlay runs) and after every exit of the daemon.

#[cfg(any(windows, test))]
use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One interface whose forwarding a router asked for, as the setup script
/// reported it. `identity` is `guid:{…}` when the adapter has a GUID, else
/// `if:<ifIndex>`; only the first form is persisted.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FwdTarget {
    pub(crate) identity: String,
    pub(crate) if_index: u32,
    /// The interface had forwarding OFF before this setup turned it on.
    pub(crate) was_disabled: bool,
}

/// An adapter GUID exactly as `Get-NetAdapter` prints it: `{8-4-4-4-12}` in
/// hex. Strict, because the value is put back into a PowerShell command, and
/// the ledger it comes from is read back at boot.
pub fn is_guid(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return false;
    };
    let groups: Vec<&str> = inner.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Parse the setup script's `FWD <guid|-> <ifIndex> <Enabled|Disabled>` lines.
/// Anything else on stdout is ignored, so the script may print diagnostics.
#[cfg(any(windows, test))]
pub(crate) fn parse_forwarding_report(out: &str) -> Vec<FwdTarget> {
    out.lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            if cols.next()? != "FWD" {
                return None;
            }
            let guid = cols.next()?;
            let if_index: u32 = cols.next()?.parse().ok()?;
            let before = cols.next()?;
            let identity = if is_guid(guid) {
                format!("guid:{guid}")
            } else {
                format!("if:{if_index}")
            };
            Some(FwdTarget {
                identity,
                if_index,
                was_disabled: before.eq_ignore_ascii_case("Disabled"),
            })
        })
        .collect()
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hold {
    /// Forwarding was off before the first holder turned it on.
    restore: bool,
    holders: usize,
}

/// FR-97 P0b-2b — who holds forwarding on which interface, this process.
#[cfg(any(windows, test))]
#[derive(Debug, Default)]
pub(crate) struct ForwardingHolds {
    by_identity: BTreeMap<String, Hold>,
}

#[cfg(any(windows, test))]
impl ForwardingHolds {
    /// For the process-wide `static` in `nat.rs`, the one Windows caller.
    #[cfg(windows)]
    pub(crate) const fn new() -> Self {
        Self {
            by_identity: BTreeMap::new(),
        }
    }

    /// A router now relies on forwarding on `t`'s interface.
    pub(crate) fn hold(&mut self, t: &FwdTarget) {
        self.by_identity
            .entry(t.identity.clone())
            .and_modify(|h| h.holders += 1)
            .or_insert(Hold {
                restore: t.was_disabled,
                holders: 1,
            });
    }

    /// A router no longer relies on it. `true` when this was the last holder
    /// and forwarding was off before we turned it on: switch it back off.
    pub(crate) fn release(&mut self, identity: &str) -> bool {
        let Some(h) = self.by_identity.get_mut(identity) else {
            return false;
        };
        h.holders = h.holders.saturating_sub(1);
        if h.holders > 0 {
            return false;
        }
        let restore = h.restore;
        self.by_identity.remove(identity);
        restore
    }

    /// The persisted half: the GUID-identified interfaces we turned on and
    /// still hold. An `if:` identity is not written: after a reboot that
    /// index can belong to a different interface.
    pub(crate) fn forwarding_guids(&self) -> Vec<String> {
        self.by_identity
            .iter()
            .filter(|(id, h)| h.restore && id.starts_with("guid:"))
            .map(|(id, _)| id.trim_start_matches("guid:").to_string())
            .collect()
    }
}

/// FR-97 P0e — one exit-client pin as its OS arm installed it: a host route
/// for `ip` through `gateway` on `interface` (Linux `dev`, Windows ifIndex,
/// macOS netif). `gateway` is kept as the OS tool takes it, so a macOS
/// link-local next hop keeps its `%zone`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    pub ip: std::net::IpAddr,
    pub gateway: String,
    pub interface: String,
    /// Linux: the pin carries `onlink`, as its default route did.
    #[serde(default)]
    pub onlink: bool,
}

/// FR-97 P1b — one pf serve on a Mac: our anchor, every reference token we took
/// with `pfctl -E`, and whether forwarding was off before we turned it on. The
/// purge flushes the anchor, releases the references that are still ours (pf
/// goes back to disabled if nothing else holds it), and puts forwarding back
/// unless Internet Sharing runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfRecord {
    pub anchor: String,
    /// The token values alone: all a 0.4.141 daemon reads, after a rollback.
    #[serde(default)]
    pub tokens: Vec<u64>,
    /// The same references, each with the pid of the `pfctl` that took it.
    #[serde(default)]
    pub refs: Vec<PfToken>,
    #[serde(default)]
    pub v4_was_off: bool,
    #[serde(default)]
    pub v6_was_off: bool,
}

/// FR-97 P1b — a pf reference a serve took: the `pfctl -E` token, and the pid
/// of that `pfctl`, which `pfctl -s References` lists beside it. A value alone
/// does not identify a reference. The kernel hands a freed token's value
/// straight back to the next taker (field, FR-97 §8), so after another
/// program's `pfctl -d` that program can hold OUR old value, and only the pid
/// tells the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfToken {
    pub token: u64,
    pub pid: u32,
}

/// What this daemon changed on the host and has not yet undone; persisted,
/// what the boot purge must undo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLedger {
    /// FR-97 P0b-2b — Windows adapter GUIDs (`{…}`) whose IPv4 forwarding
    /// this daemon turned on and had not yet turned off.
    #[serde(default)]
    pub forwarding: Vec<String>,
    /// FR-97 P0e — exit-client pins this daemon installed and had not yet
    /// removed. One per address.
    #[serde(default)]
    pub pins: Vec<PinRecord>,
    /// FR-97 P0b-2c — the WinNAT instances a Windows router created and had
    /// not yet removed, by name ([`is_nat_name`]). A crash used to leave one
    /// behind (field, both 0.4.134 and the P0b-2b candidate), and on client
    /// Windows it can stand in the way of Docker's or WSL's own NAT.
    #[serde(default)]
    pub nat: Vec<String>,
    /// FR-97 P1b — the pf serves a Mac router or exit set up and had not yet
    /// taken back out, one per overlay adapter.
    #[serde(default)]
    pub pf: Vec<PfRecord>,
}

impl HostLedger {
    pub fn is_empty(&self) -> bool {
        self.forwarding.is_empty()
            && self.pins.is_empty()
            && self.nat.is_empty()
            && self.pf.is_empty()
    }

    /// Record `pin`, replacing any earlier record for the same address.
    #[cfg(any(feature = "overlay-l3", test))]
    pub(crate) fn upsert_pin(&mut self, pin: PinRecord) {
        self.pins.retain(|p| p.ip != pin.ip);
        self.pins.push(pin);
    }

    #[cfg(any(feature = "overlay-l3", test))]
    pub(crate) fn remove_pin(&mut self, ip: std::net::IpAddr) {
        self.pins.retain(|p| p.ip != ip);
    }
}

/// This process's ledger, the one writer of the persisted one. Both halves go
/// through it, so the forwarding records and the pin records never overwrite
/// each other.
static LEDGER: Mutex<HostLedger> = Mutex::new(HostLedger {
    forwarding: Vec::new(),
    pins: Vec::new(),
    nat: Vec::new(),
    pf: Vec::new(),
});

/// FR-97 P0b-2c — a WinNAT instance name a router of ours creates:
/// `roomler-overlay`, or `roomler-overlay-<n>` for a later block. Strict,
/// because the name goes back into a PowerShell command, and only an
/// instance named like ours is ever removed.
pub fn is_nat_name(s: &str) -> bool {
    match s.strip_prefix("roomler-overlay") {
        Some("") => true,
        Some(rest) => rest.strip_prefix('-').is_some_and(|n| {
            !n.is_empty() && n.len() <= 3 && n.chars().all(|c| c.is_ascii_digit())
        }),
        None => false,
    }
}

/// FR-97 P0b-2c — a router's WinNAT instances are in.
#[cfg(windows)]
pub(crate) fn record_nat(names: &[String]) {
    with_ledger(|l| {
        for n in names {
            if is_nat_name(n) && !l.nat.contains(n) {
                l.nat.push(n.clone());
            }
        }
    });
}

/// FR-97 P0b-2c — a router's WinNAT instances are out.
#[cfg(windows)]
pub(crate) fn forget_nat(names: &[String]) {
    with_ledger(|l| l.nat.retain(|n| !names.contains(n)));
}

/// FR-97 P1b — a pf serve is in (or took another token): record it before
/// anything can kill the daemon. One record per anchor.
#[cfg(target_os = "macos")]
pub(crate) fn record_pf(r: PfRecord) {
    with_ledger(|l| {
        l.pf.retain(|p| p.anchor != r.anchor);
        l.pf.push(r);
    });
}

/// FR-97 P1b — a pf serve is out.
#[cfg(target_os = "macos")]
pub(crate) fn forget_pf(anchor: &str) {
    with_ledger(|l| l.pf.retain(|p| p.anchor != anchor));
}

#[cfg(any(windows, target_os = "macos", feature = "overlay-l3"))]
fn with_ledger(f: impl FnOnce(&mut HostLedger)) {
    let mut ledger = LEDGER.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut ledger);
    ledger.store();
}

/// FR-97 P0b-2b — the forwarding half now held (replaces the earlier list).
#[cfg(windows)]
pub(crate) fn record_forwarding(guids: Vec<String>) {
    with_ledger(|l| l.forwarding = guids);
}

/// FR-97 P0e — a pin is in: record it before anything can kill the daemon.
#[cfg(feature = "overlay-l3")]
pub(crate) fn record_pin(pin: PinRecord) {
    with_ledger(|l| l.upsert_pin(pin));
}

/// FR-97 P0e — a pin is out.
#[cfg(feature = "overlay-l3")]
pub(crate) fn forget_pin(ip: std::net::IpAddr) {
    with_ledger(|l| l.remove_pin(ip));
}

/// FR-97 P0e (N12) — how this process installed its pin for `ip`, if it holds
/// one: the route to remove, even after the uplink it went through moved.
#[cfg(all(
    feature = "overlay-l3",
    any(target_os = "linux", target_os = "windows")
))]
pub(crate) fn pin_record(ip: std::net::IpAddr) -> Option<PinRecord> {
    LEDGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pins
        .iter()
        .find(|p| p.ip == ip)
        .cloned()
}

/// FR-97 P0b-2b / P0e — undo what the persisted ledger records, then clear
/// it: the WinNAT instances and the forwarding a Windows router left, and
/// every exit-client pin. Run at boot, before the overlay can install
/// anything, and after every exit of the daemon (`roomlerd::purge_exit_routes`).
/// Context-free and synchronous; a no-op when the ledger is empty. Each OS arm
/// checks that a route still looks like our pin before it removes it.
pub fn purge() {
    let on_disk = HostLedger::load();
    if on_disk.is_empty() {
        return;
    }
    super::nat::remove_nat_instances(&on_disk.nat);
    super::nat::restore_forwarding_guids(&on_disk.forwarding);
    super::pf::purge(&on_disk.pf);
    #[cfg(feature = "overlay-l3")]
    super::tun::purge_pins(&on_disk.pins);
    *LEDGER.lock().unwrap_or_else(|e| e.into_inner()) = HostLedger::default();
    HostLedger::default().store();
}

impl HostLedger {
    /// Read the ledger; an absent or unreadable one is empty.
    pub fn load() -> Self {
        store::read()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write the ledger; an empty ledger is removed. Best-effort: a daemon
    /// that cannot write it (not root, a read-only system) keeps working, and
    /// only loses the crash-time undo.
    pub fn store(&self) {
        if self.is_empty() {
            store::remove();
            return;
        }
        if let Ok(body) = serde_json::to_string(self) {
            store::write(&body);
        }
    }
}

/// Where the ledger lives: one place per machine, because one daemon per
/// machine owns this state (`docs/multi-org.md`) and the boot purge runs
/// before any config is read. The daemon acts on what it says as SYSTEM or
/// root, so only that identity may be able to write it.
///
/// On Windows that is the registry, `HKLM\SOFTWARE\Roomler\Overlay`, never a
/// file under `%ProgramData%`: any account may create a file there, and the
/// SYSTEM daemon acts on what the ledger says at boot. A standard user who
/// planted one would choose which adapter SYSTEM switches forwarding off on.
/// Only SYSTEM and Administrators may write below `HKLM\SOFTWARE`.
#[cfg(windows)]
mod store {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegGetValueW, RegSetValueExW,
    };

    const SUBKEY: &str = r"SOFTWARE\Roomler\Overlay";
    const VALUE: &str = "HostLedger";
    /// A ledger is a few GUIDs and pins; anything near this is not one.
    const MAX_BYTES: u32 = 256 * 1024;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn read() -> Option<Vec<u8>> {
        let (key, value) = (wide(SUBKEY), wide(VALUE));
        let mut len: u32 = 0;
        // SAFETY: NUL-terminated names that outlive the call; a null buffer
        // asks only for the size, in bytes.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS || len == 0 || len > MAX_BYTES {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: `buf` holds `len` bytes; RegGetValueW NUL-terminates a
        // REG_SZ it returns, and fails with ERROR_MORE_DATA if the value grew.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let chars = (len as usize / 2).min(buf.len());
        let text: Vec<u16> = buf[..chars]
            .iter()
            .copied()
            .take_while(|&c| c != 0)
            .collect();
        Some(String::from_utf16_lossy(&text).into_bytes())
    }

    pub(super) fn write(body: &str) {
        let key = wide(SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated subkey; `hkey` is a valid out-pointer and
        // is closed below. No class, default security (inherited from
        // HKLM\SOFTWARE), no disposition wanted.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS || hkey.is_null() {
            return;
        }
        let data = wide(body);
        let value = wide(VALUE);
        // SAFETY: a live key opened for KEY_SET_VALUE; `data` is the REG_SZ
        // with its NUL, sized in bytes.
        unsafe {
            RegSetValueExW(
                hkey,
                value.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            );
            RegCloseKey(hkey);
        }
    }

    pub(super) fn remove() {
        let (key, value) = (wide(SUBKEY), wide(VALUE));
        // SAFETY: NUL-terminated names that outlive the call. A missing key
        // or value is the normal case and is ignored.
        unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr()) };
    }
}

/// On Linux and macOS, a file in a directory only root may create:
/// `/var/lib/meshharbor` or `/var/db/roomler`. It is believed only while both
/// the directory and the file are root's and nobody else may write them (a
/// directory someone loosened, or a symlink, is not this daemon's record).
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod store {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::{Path, PathBuf};

    #[cfg(target_os = "linux")]
    const DIR: &str = "/var/lib/meshharbor";
    #[cfg(target_os = "macos")]
    const DIR: &str = "/var/db/roomler";
    const FILE: &str = "overlay-host-ledger.json";
    /// A ledger is a few pins; anything near this is not one.
    const MAX_BYTES: u64 = 256 * 1024;

    fn path() -> PathBuf {
        Path::new(DIR).join(FILE)
    }

    /// Root's, and writable by nobody else.
    pub(super) fn root_private(uid: u32, mode: u32) -> bool {
        uid == 0 && mode & 0o022 == 0
    }

    pub(super) fn read() -> Option<Vec<u8>> {
        let dir = std::fs::symlink_metadata(DIR).ok()?;
        if !dir.is_dir() || !root_private(dir.uid(), dir.mode()) {
            return None;
        }
        // Only root can swap the file in that directory, so a check by
        // name holds for the read that follows it.
        let file = std::fs::symlink_metadata(path()).ok()?;
        if !file.is_file() || !root_private(file.uid(), file.mode()) || file.len() > MAX_BYTES {
            return None;
        }
        std::fs::read(path()).ok()
    }

    pub(super) fn write(body: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(DIR);
        // A fresh 0600 file whatever the umask, so `read` believes it.
        let tmp = Path::new(DIR).join(format!("{FILE}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(body.as_bytes()));
        if written.is_ok() {
            let _ = std::fs::rename(&tmp, path());
        }
    }

    pub(super) fn remove() {
        let _ = std::fs::remove_file(path());
    }
}

/// Nothing on this OS writes the ledger.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod store {
    pub(super) fn read() -> Option<Vec<u8>> {
        None
    }
    pub(super) fn write(_body: &str) {}
    pub(super) fn remove() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID_A: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
    const GUID_B: &str = "{11111111-2222-3333-4444-555555555555}";

    #[test]
    fn the_report_names_each_interface_and_its_state_before() {
        let out = format!(
            "noise from PowerShell\nFWD {GUID_A} 12 Disabled\nFWD - 31 Enabled\nFWD {GUID_B} x Disabled\nFWD\n"
        );
        let got = parse_forwarding_report(&out);
        assert_eq!(
            got,
            vec![
                FwdTarget {
                    identity: format!("guid:{GUID_A}"),
                    if_index: 12,
                    was_disabled: true,
                },
                FwdTarget {
                    identity: "if:31".into(),
                    if_index: 31,
                    was_disabled: false,
                },
            ],
            "a malformed index or a short line is skipped"
        );
    }

    fn target(guid: &str, before: &str) -> FwdTarget {
        parse_forwarding_report(&format!("FWD {guid} 7 {before}"))
            .pop()
            .unwrap()
    }

    /// The defect: forwarding stayed on after the router stopped. Restored
    /// only by the LAST holder, and only where we had turned it on.
    #[test]
    fn forwarding_we_turned_on_is_restored_by_the_last_holder() {
        let mut holds = ForwardingHolds::default();
        // Org A turns it on; org B, sharing the egress adapter, then sees it
        // Enabled. That must not erase A's observation.
        holds.hold(&target(GUID_A, "Disabled"));
        holds.hold(&target(GUID_A, "Enabled"));
        let id = format!("guid:{GUID_A}");
        assert!(!holds.release(&id), "B still routes: not yet");
        assert!(holds.release(&id), "the last holder restores");
        assert!(!holds.release(&id), "and only once");
    }

    #[test]
    fn forwarding_that_was_already_on_is_left_on() {
        let mut holds = ForwardingHolds::default();
        holds.hold(&target(GUID_A, "Enabled"));
        assert!(
            !holds.release(&format!("guid:{GUID_A}")),
            "someone else's setting, never ours to turn off"
        );
    }

    /// Only stable identities reach the disk, and only those we must restore.
    #[test]
    fn the_ledger_holds_only_guids_we_turned_on() {
        let mut holds = ForwardingHolds::default();
        holds.hold(&target(GUID_A, "Disabled"));
        holds.hold(&target(GUID_B, "Enabled"));
        holds.hold(&parse_forwarding_report("FWD - 9 Disabled").pop().unwrap());
        assert_eq!(holds.forwarding_guids(), vec![GUID_A.to_string()]);
        holds.release(&format!("guid:{GUID_A}"));
        assert!(holds.forwarding_guids().is_empty());
    }

    #[test]
    fn only_a_well_formed_guid_is_a_guid() {
        assert!(is_guid(GUID_A));
        for bad in [
            "",
            "-",
            "{}",
            "4D36E972-E325-11CE-BFC1-08002BE10318",
            "{4D36E972-E325-11CE-BFC1-08002BE1031}",
            "{4D36E972-E325-11CE-BFC1-08002BE1031Z}",
            "{4D36E972-E325-11CE-BFC1'; Stop-Computer; '}",
        ] {
            assert!(!is_guid(bad), "{bad}");
        }
        // A malformed GUID falls back to the ifIndex, which is never persisted.
        let t = parse_forwarding_report("FWD {not-a-guid} 5 Disabled")
            .pop()
            .unwrap();
        assert_eq!(t.identity, "if:5");
    }

    fn pin(ip: &str, gw: &str) -> PinRecord {
        PinRecord {
            ip: ip.parse().unwrap(),
            gateway: gw.into(),
            interface: "en0".into(),
            onlink: false,
        }
    }

    #[test]
    fn the_ledger_round_trips_and_tolerates_a_missing_field() {
        let l = HostLedger {
            forwarding: vec![GUID_A.into()],
            pins: vec![
                pin("94.130.141.98", "192.168.64.1"),
                pin("2a01:4f8::1", "fe80::1%en0"),
            ],
            nat: vec!["roomler-overlay".into()],
            pf: vec![PfRecord {
                anchor: "com.apple/roomler-utun4".into(),
                tokens: vec![13889181449326457865],
                refs: vec![PfToken {
                    token: 13889181449326457865,
                    pid: 674,
                }],
                v4_was_off: true,
                v6_was_off: false,
            }],
        };
        let back: HostLedger = serde_json::from_slice(&serde_json::to_vec(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        let empty: HostLedger = serde_json::from_str("{}").unwrap();
        assert!(empty.is_empty());
        // A ledger written by P0b-2b, before pins, NAT names and pf existed,
        // still reads.
        let old: HostLedger =
            serde_json::from_str(&format!("{{\"forwarding\":[\"{GUID_A}\"]}}")).unwrap();
        assert_eq!(old.forwarding, vec![GUID_A.to_string()]);
        assert!(old.pins.is_empty() && old.nat.is_empty() && old.pf.is_empty());
        // A NAT name alone keeps the ledger (and its purge) alive.
        let nat_only = HostLedger {
            nat: vec!["roomler-overlay".into()],
            ..HostLedger::default()
        };
        assert!(!nat_only.is_empty());
        // FR-97 P1b — so does a pf serve, and one written with only its anchor
        // reads with no tokens and forwarding left alone.
        let pf_only = HostLedger {
            pf: l.pf.clone(),
            ..HostLedger::default()
        };
        assert!(!pf_only.is_empty());
        let bare: HostLedger =
            serde_json::from_str("{\"pf\":[{\"anchor\":\"com.apple/roomler-utun4\"}]}").unwrap();
        assert_eq!(bare.pf[0].tokens, Vec::<u64>::new());
        assert!(!bare.pf[0].v4_was_off && !bare.pf[0].v6_was_off);
        // One a 0.4.141 daemon wrote: token values, no pids.
        let v141: HostLedger = serde_json::from_str(
            "{\"pf\":[{\"anchor\":\"com.apple/roomler-utun4\",\"tokens\":[7],\"v4_was_off\":true,\"v6_was_off\":false}]}",
        )
        .unwrap();
        assert_eq!(v141.pf[0].tokens, vec![7]);
        assert!(v141.pf[0].refs.is_empty());
        // And a 0.4.141 daemon, after a rollback, still finds the values it
        // knows in what this one writes.
        let written = serde_json::to_value(&l).unwrap();
        assert_eq!(
            written["pf"][0]["tokens"],
            serde_json::json!([13889181449326457865u64])
        );
    }

    /// FR-97 P0b-2c — only an instance named like ours is ever removed, and
    /// the name goes back into PowerShell, so the check is strict.
    #[test]
    fn only_our_nat_names_are_nat_names() {
        for good in ["roomler-overlay", "roomler-overlay-1", "roomler-overlay-12"] {
            assert!(is_nat_name(good), "{good}");
        }
        for bad in [
            "",
            "roomler",
            "roomler-overlay-",
            "roomler-overlay-a",
            "roomler-overlay-1;Remove-Item",
            "roomler-overlay-1234",
            "DockerNAT",
            "roomler-overlay2",
            "x-roomler-overlay",
        ] {
            assert!(!is_nat_name(bad), "{bad:?}");
        }
    }

    /// FR-97 P0e — one record per address: a re-pin through a new uplink
    /// replaces the old record, so the purge targets the route that exists.
    #[test]
    fn a_pin_is_recorded_once_per_address_and_forgotten() {
        let mut l = HostLedger::default();
        l.upsert_pin(pin("94.130.141.98", "192.168.64.1"));
        l.upsert_pin(pin("5.9.157.226", "192.168.64.1"));
        l.upsert_pin(pin("94.130.141.98", "10.0.0.1"));
        assert_eq!(l.pins.len(), 2);
        assert!(
            l.pins
                .iter()
                .any(|p| p.ip.to_string() == "94.130.141.98" && p.gateway == "10.0.0.1"),
            "the newer record wins: {:?}",
            l.pins
        );
        l.remove_pin("94.130.141.98".parse().unwrap());
        assert_eq!(l.pins.len(), 1);
        assert!(!l.is_empty());
        l.remove_pin("5.9.157.226".parse().unwrap());
        assert!(l.is_empty(), "an empty ledger is removed on store");
    }

    /// Root acts on the ledger at boot, so it is believed only from a
    /// directory and a file that are root's and nobody else may write.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn only_a_root_private_ledger_is_believed() {
        use super::store::root_private;
        assert!(
            root_private(0, 0o040755),
            "the directory as write() makes it"
        );
        assert!(root_private(0, 0o100600), "the file as write() makes it");
        assert!(!root_private(0, 0o040775), "group-writable");
        assert!(!root_private(0, 0o041777), "world-writable, even sticky");
        assert!(!root_private(0, 0o100666), "a file made under umask 0");
        assert!(!root_private(1000, 0o100600), "another account's file");
    }
}
