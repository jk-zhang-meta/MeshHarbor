// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! RC/RDP Phase B — read-only local RDP capability & certificate fingerprint
//! probe for `AgentCaps::{rdp_available, rdp_cert_sha256}`.
//!
//! ## Contract
//!
//! 1. **Strictly read-only**: never modifies registry keys, services, firewall
//!    rules, or certificate stores.
//! 2. **Windows Home SKU guard**: Windows Home (`PRODUCT_CORE*`,
//!    `PRODUCT_HOME_*`, `PRODUCT_STARTER*`, or `VER_SUITE_PERSONAL`) ships no
//!    built-in RDP server (`TermService`); [`is_windows_home_sku`] forces
//!    `available = false` and `cert_sha256 = None` even if a third-party process
//!    happens to bind port 3389.
//! 3. **Non-loopback TCP 3389 listener check**: reports `available = true` only
//!    when a local TCP listener on port `3389` is bound to a wildcard
//!    (`0.0.0.0` / `::`) or non-loopback address (`GetExtendedTcpTable` on
//!    Windows, `/proc/net/tcp` + `/proc/net/tcp6` on Linux). Loopback-only
//!    listeners (`127.0.0.0/8`, `::1`, `::ffff:127.0.0.0/104` — such as
//!    `mh rdp`'s local `127.77.x.y:3389` forwarder) are excluded.
//! 4. **Read-only TLS certificate selection**:
//!    - On Windows, reads `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
//!      value `SSLCertificateSHA1Hash` in read-only mode. When present, looks
//!      up the certificate with that exact SHA-1 thumbprint across
//!      `LocalMachine\Remote Desktop` and `LocalMachine\My` and reports its
//!      SHA-256 fingerprint. When absent, reports the SHA-256 fingerprint only
//!      if `LocalMachine\Remote Desktop` contains **exactly one** certificate
//!      and that certificate is currently within its validity period
//!      (`CertVerifyTimeValidity == 0`); otherwise reports `None`.
//!    - On Linux, reads `/etc/xrdp/cert.pem` if accessible.

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Local RDP port checked by the read-only listener probe.
pub const RDP_PORT: u16 = 3389;

/// How long [`current`] caches a probe snapshot so heartbeat ticks do not
/// re-read OS tables more than once per heartbeat window.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// `OSVERSIONINFOEXW::wSuiteMask` bit set on Windows Home editions.
pub const VER_SUITE_PERSONAL: u16 = 0x0200;

/// `GetProductInfo` SKU constants for Windows Home / Starter editions that
/// ship without an RDP server.
pub const PRODUCT_HOME_BASIC: u32 = 0x0000_0002;
pub const PRODUCT_HOME_PREMIUM: u32 = 0x0000_0003;
pub const PRODUCT_HOME_BASIC_N: u32 = 0x0000_0005;
pub const PRODUCT_STARTER: u32 = 0x0000_000B;
pub const PRODUCT_HOME_PREMIUM_N: u32 = 0x0000_001A;
pub const PRODUCT_STARTER_N: u32 = 0x0000_002F;
pub const PRODUCT_STARTER_E: u32 = 0x0000_0042;
pub const PRODUCT_HOME_BASIC_E: u32 = 0x0000_0043;
pub const PRODUCT_HOME_PREMIUM_E: u32 = 0x0000_0044;
pub const PRODUCT_CORE_N: u32 = 0x0000_0062;
pub const PRODUCT_CORE_COUNTRYSPECIFIC: u32 = 0x0000_0063;
pub const PRODUCT_CORE_SINGLELANGUAGE: u32 = 0x0000_0064;
pub const PRODUCT_CORE: u32 = 0x0000_0065;

/// Read-only snapshot of the host's local RDP capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpCapsSnapshot {
    pub available: bool,
    pub cert_sha256: Option<String>,
}

/// Candidate certificate metadata read from a Windows certificate store, used by
/// the pure selection rule [`select_rdp_cert_sha256`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertCandidate {
    pub sha1: [u8; 20],
    pub sha256: String,
    pub time_valid: bool,
}

/// Read-only state of `HKLM\...\RDP-Tcp\SSLCertificateSHA1Hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpRegistryCertHash {
    /// The registry value does not exist (or is empty).
    Absent,
    /// The registry value holds a 20-byte SHA-1 certificate thumbprint.
    Sha1([u8; 20]),
    /// The registry value exists but is not a valid 20-byte SHA-1 thumbprint.
    Malformed,
}

static CACHE: Mutex<Option<(Instant, RdpCapsSnapshot)>> = Mutex::new(None);

/// Return the current host's [`RdpCapsSnapshot`], cached for [`CACHE_TTL`].
pub fn current() -> RdpCapsSnapshot {
    let now = Instant::now();
    if let Ok(guard) = CACHE.lock()
        && let Some((at, ref snap)) = *guard
        && now.saturating_duration_since(at) < CACHE_TTL
    {
        return snap.clone();
    }
    let snap = probe_now();
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((now, snap.clone()));
    }
    snap
}

/// Pure SKU predicate: returns `true` when `product_type` (from `GetProductInfo`)
/// or `suite_mask` (from `RtlGetVersion`) identifies a Windows Home / Starter
/// edition that has no built-in RDP server.
pub fn is_windows_home_sku(product_type: u32, suite_mask: u16) -> bool {
    if (suite_mask & VER_SUITE_PERSONAL) != 0 {
        return true;
    }
    matches!(
        product_type,
        PRODUCT_CORE
            | PRODUCT_CORE_N
            | PRODUCT_CORE_COUNTRYSPECIFIC
            | PRODUCT_CORE_SINGLELANGUAGE
            | PRODUCT_HOME_BASIC
            | PRODUCT_HOME_BASIC_N
            | PRODUCT_HOME_BASIC_E
            | PRODUCT_HOME_PREMIUM
            | PRODUCT_HOME_PREMIUM_N
            | PRODUCT_HOME_PREMIUM_E
            | PRODUCT_STARTER
            | PRODUCT_STARTER_N
            | PRODUCT_STARTER_E
    )
}

/// Pure address filter: returns `true` when `ip` is a wildcard (`0.0.0.0`,
/// `::`) or non-loopback address. Excludes `127.0.0.0/8`, `::1`, and
/// IPv4-mapped loopback `::ffff:127.0.0.0/104` (such as `mh rdp`'s local
/// `127.77.x.y:3389` tunnel listener).
pub fn is_usable_rdp_listener_ip(ip: IpAddr) -> bool {
    !ip.is_loopback() && !ip.to_canonical().is_loopback()
}

/// Pure socket-address predicate: returns `true` when `addr` listens on
/// [`RDP_PORT`] (`3389`) and [`is_usable_rdp_listener_ip`] accepts its IP.
pub fn is_usable_rdp_listener_addr(addr: SocketAddr) -> bool {
    addr.port() == RDP_PORT && is_usable_rdp_listener_ip(addr.ip())
}

/// Pure certificate selection rule for Windows RDP (`16:10` §3(b)):
/// - When `reg_hash` is [`RdpRegistryCertHash::Sha1`], searches
///   `remote_desktop_certs` and then `my_certs` for a certificate with that
///   exact SHA-1 thumbprint and returns its SHA-256 fingerprint.
/// - When `reg_hash` is [`RdpRegistryCertHash::Absent`], returns the SHA-256
///   fingerprint only if `remote_desktop_certs` has **exactly one** certificate
///   and `time_valid` is `true`.
/// - In all other cases (malformed registry hash, hash not found, 0 or >1
///   certificates in `Remote Desktop`, or an expired sole certificate), returns
///   `None`.
pub fn select_rdp_cert_sha256(
    reg_hash: &RdpRegistryCertHash,
    remote_desktop_certs: &[CertCandidate],
    my_certs: &[CertCandidate],
) -> Option<String> {
    match reg_hash {
        RdpRegistryCertHash::Sha1(target) => remote_desktop_certs
            .iter()
            .chain(my_certs.iter())
            .find(|c| &c.sha1 == target)
            .map(|c| c.sha256.clone()),
        RdpRegistryCertHash::Malformed => None,
        RdpRegistryCertHash::Absent => {
            if remote_desktop_certs.len() == 1 && remote_desktop_certs[0].time_valid {
                Some(remote_desktop_certs[0].sha256.clone())
            } else {
                None
            }
        }
    }
}

/// Format the SHA-256 digest of a DER-encoded X.509 certificate as lowercase
/// colon-separated hex (`aa:bb:…`, 95 chars).
pub fn format_cert_sha256_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 3 - 1);
    for (i, byte) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Extract the first `-----BEGIN CERTIFICATE-----` PEM block from `pem` and
/// return its lowercase colon-separated SHA-256 DER fingerprint.
pub fn cert_sha256_from_pem(pem: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;
    let b64: String = rest[..end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if b64.is_empty() {
        return None;
    }
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if der.is_empty() {
        return None;
    }
    Some(format_cert_sha256_der(&der))
}

/// Parse the hex IP column from Linux `/proc/net/tcp` (8 hex chars, host-endian
/// `u32`) or `/proc/net/tcp6` (32 hex chars, four host-endian `u32` words).
fn parse_proc_net_hex_ip(addr_hex: &str) -> Option<IpAddr> {
    match addr_hex.len() {
        8 => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Pure parser for Linux `/proc/net/tcp` and `/proc/net/tcp6`: returns `true`
/// when any row is in state `0A` (`TCP_LISTEN`) on local port `port` AND its
/// local address is wildcard or non-loopback ([`is_usable_rdp_listener_ip`]).
pub fn parse_proc_net_tcp_has_listener(content: &str, port: u16) -> bool {
    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _slot = cols.next();
        let Some(local) = cols.next() else { continue };
        let Some(_rem) = cols.next() else { continue };
        let Some(state) = cols.next() else { continue };
        if !state.eq_ignore_ascii_case("0A") {
            continue;
        }
        let Some((addr_hex, port_hex)) = local.rsplit_once(':') else {
            continue;
        };
        if u16::from_str_radix(port_hex, 16).ok() != Some(port) {
            continue;
        }
        let Some(ip) = parse_proc_net_hex_ip(addr_hex) else {
            continue;
        };
        if is_usable_rdp_listener_ip(ip) {
            return true;
        }
    }
    false
}

fn probe_now() -> RdpCapsSnapshot {
    #[cfg(target_os = "windows")]
    {
        if windows_is_home_edition() {
            return RdpCapsSnapshot {
                available: false,
                cert_sha256: None,
            };
        }
        let available = port_listening_windows(RDP_PORT);
        let cert_sha256 = if available {
            read_windows_rdp_cert_sha256()
        } else {
            None
        };
        RdpCapsSnapshot {
            available,
            cert_sha256,
        }
    }
    #[cfg(target_os = "linux")]
    {
        let available = port_listening_linux(RDP_PORT);
        let cert_sha256 = if available {
            std::fs::read_to_string("/etc/xrdp/cert.pem")
                .ok()
                .and_then(|pem| cert_sha256_from_pem(&pem))
        } else {
            None
        };
        RdpCapsSnapshot {
            available,
            cert_sha256,
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        RdpCapsSnapshot {
            available: false,
            cert_sha256: None,
        }
    }
}

#[cfg(target_os = "linux")]
fn port_listening_linux(port: u16) -> bool {
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path)
            && parse_proc_net_tcp_has_listener(&content, port)
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn windows_is_home_edition() -> bool {
    use windows_sys::Win32::System::SystemInformation::{GetProductInfo, OSVERSIONINFOEXW};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOEXW) -> i32;
    }

    // SAFETY: zero-initialized `OSVERSIONINFOEXW` with `dwOSVersionInfoSize` set.
    let mut os_info: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
    let status = unsafe { RtlGetVersion(&mut os_info) };
    if status != 0 {
        return false;
    }
    let mut product_type = 0u32;
    // SAFETY: pure read of SKU code for the running OS version.
    let ok = unsafe {
        GetProductInfo(
            os_info.dwMajorVersion,
            os_info.dwMinorVersion,
            os_info.wServicePackMajor as u32,
            os_info.wServicePackMinor as u32,
            &mut product_type,
        )
    };
    let sku = if ok != 0 { product_type } else { 0 };
    is_windows_home_sku(sku, os_info.wSuiteMask)
}

#[cfg(target_os = "windows")]
fn port_listening_windows(port: u16) -> bool {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    fn table(af: u32) -> Option<Vec<u32>> {
        let mut size = 0u32;
        // SAFETY: size query with null buffer and valid out-pointer.
        let rc = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 1];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: `buf` is u32-aligned and holds `len` bytes.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                af,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        (rc == 0).then_some(buf)
    }

    let port_of = |raw: u32| u16::from_be((raw & 0xffff) as u16);

    if let Some(buf) = table(AF_INET) {
        let n = buf[0] as usize;
        // SAFETY: `dwNumEntries` followed by `n` `MIB_TCPROW_OWNER_PID` rows.
        let rows = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<MIB_TCPROW_OWNER_PID>(), n)
        };
        if rows.iter().any(|r| {
            port_of(r.dwLocalPort) == port
                && is_usable_rdp_listener_ip(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    r.dwLocalAddr,
                ))))
        }) {
            return true;
        }
    }
    if let Some(buf) = table(AF_INET6) {
        let n = buf[0] as usize;
        // SAFETY: `dwNumEntries` followed by `n` `MIB_TCP6ROW_OWNER_PID` rows.
        let rows = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<MIB_TCP6ROW_OWNER_PID>(), n)
        };
        if rows.iter().any(|r| {
            port_of(r.dwLocalPort) == port
                && is_usable_rdp_listener_ip(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)))
        }) {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn read_rdp_tcp_registry_cert_sha1() -> RdpRegistryCertHash {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };

    let subkey: Vec<u16> =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\0"
            .encode_utf16()
            .collect();
    let value_name: Vec<u16> = "SSLCertificateSHA1Hash\0".encode_utf16().collect();

    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: read-only open of HKLM\...\RDP-Tcp.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if rc != ERROR_SUCCESS || hkey.is_null() {
        return RdpRegistryCertHash::Absent;
    }

    let mut reg_type = 0u32;
    let mut buf = [0u8; 64];
    let mut cb = buf.len() as u32;
    // SAFETY: `hkey` is open for `KEY_READ`, `buf` holds `cb` bytes.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut reg_type,
            buf.as_mut_ptr(),
            &mut cb,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if rc != ERROR_SUCCESS || cb == 0 {
        return RdpRegistryCertHash::Absent;
    }
    if reg_type == REG_BINARY && cb == 20 {
        let mut sha1 = [0u8; 20];
        sha1.copy_from_slice(&buf[..20]);
        if sha1 == [0u8; 20] {
            return RdpRegistryCertHash::Absent;
        }
        return RdpRegistryCertHash::Sha1(sha1);
    }
    RdpRegistryCertHash::Malformed
}

#[cfg(target_os = "windows")]
fn read_windows_store_cert_candidates(store_label: &str) -> Vec<CertCandidate> {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_HASH_PROP_ID, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
        CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
        CERT_SYSTEM_STORE_LOCATION_SHIFT, CertCloseStore, CertEnumCertificatesInStore,
        CertGetCertificateContextProperty, CertOpenStore, CertVerifyTimeValidity,
    };

    const CERT_SYSTEM_STORE_LOCAL_MACHINE: u32 =
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

    let mut store_name: Vec<u16> = store_label.encode_utf16().collect();
    store_name.push(0);

    // SAFETY: read-only open of an existing LocalMachine system certificate store.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_READONLY_FLAG,
            store_name.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut prev: *const CERT_CONTEXT = std::ptr::null();
    loop {
        // SAFETY: `CertEnumCertificatesInStore` frees `prev` automatically when
        // advancing to the next certificate context, and returns null at the end.
        let ctx = unsafe { CertEnumCertificatesInStore(store, prev) };
        if ctx.is_null() {
            break;
        }
        prev = ctx;

        let der = unsafe {
            let c = &*ctx;
            if !c.pbCertEncoded.is_null() && c.cbCertEncoded > 0 {
                Some(std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec())
            } else {
                None
            }
        };
        let mut sha1 = [0u8; 20];
        let mut sha1_len = sha1.len() as u32;
        let has_sha1 = unsafe {
            CertGetCertificateContextProperty(
                ctx,
                CERT_HASH_PROP_ID,
                sha1.as_mut_ptr().cast(),
                &mut sha1_len,
            ) != 0
                && sha1_len == 20
        };
        let time_valid = unsafe {
            let c = &*ctx;
            !c.pCertInfo.is_null() && CertVerifyTimeValidity(std::ptr::null(), c.pCertInfo) == 0
        };
        if let Some(der_bytes) = der
            && has_sha1
        {
            out.push(CertCandidate {
                sha1,
                sha256: format_cert_sha256_der(&der_bytes),
                time_valid,
            });
        }
    }

    unsafe {
        CertCloseStore(store, 0);
    }
    out
}

#[cfg(target_os = "windows")]
fn read_windows_rdp_cert_sha256() -> Option<String> {
    let reg_hash = read_rdp_tcp_registry_cert_sha1();
    let remote_desktop_certs = read_windows_store_cert_candidates("Remote Desktop");
    let my_certs = match reg_hash {
        RdpRegistryCertHash::Sha1(_) => read_windows_store_cert_candidates("My"),
        _ => Vec::new(),
    };
    select_rdp_cert_sha256(&reg_hash, &remote_desktop_certs, &my_certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_home_sku_detection_covers_core_and_personal_suite() {
        assert!(is_windows_home_sku(PRODUCT_CORE, 0));
        assert!(is_windows_home_sku(PRODUCT_CORE_N, 0));
        assert!(is_windows_home_sku(PRODUCT_CORE_COUNTRYSPECIFIC, 0));
        assert!(is_windows_home_sku(PRODUCT_CORE_SINGLELANGUAGE, 0));
        assert!(is_windows_home_sku(PRODUCT_HOME_BASIC, 0));
        assert!(is_windows_home_sku(PRODUCT_HOME_PREMIUM, 0));
        assert!(is_windows_home_sku(PRODUCT_STARTER, 0));
        // Even if product_type is unknown/0, VER_SUITE_PERSONAL marks Windows Home.
        assert!(is_windows_home_sku(0, VER_SUITE_PERSONAL));

        // Windows Pro (0x30) and Enterprise (0x04) without VER_SUITE_PERSONAL are NOT Home.
        assert!(!is_windows_home_sku(0x0000_0030, 0));
        assert!(!is_windows_home_sku(0x0000_0004, 0));
    }

    #[test]
    fn usable_rdp_listener_address_excludes_loopback_and_accepts_wildcard_or_lan() {
        assert!(!is_usable_rdp_listener_addr(
            "127.77.0.1:3389".parse().unwrap()
        ));
        assert!(!is_usable_rdp_listener_addr(
            "127.0.0.1:3389".parse().unwrap()
        ));
        assert!(is_usable_rdp_listener_addr("0.0.0.0:3389".parse().unwrap()));
        assert!(is_usable_rdp_listener_addr("[::]:3389".parse().unwrap()));
        assert!(!is_usable_rdp_listener_addr("[::1]:3389".parse().unwrap()));
        assert!(!is_usable_rdp_listener_addr(
            "[::ffff:127.77.0.1]:3389".parse().unwrap()
        ));
    }

    #[test]
    fn proc_net_tcp_listener_parser_excludes_loopback_and_matches_wildcard_listen() {
        fn v4_hex(ip: Ipv4Addr) -> String {
            format!("{:08X}", u32::from_ne_bytes(ip.octets()))
        }
        fn v6_hex(ip: Ipv6Addr) -> String {
            let b = ip.octets();
            let mut s = String::with_capacity(32);
            for i in 0..4 {
                let w = u32::from_ne_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
                s.push_str(&format!("{w:08X}"));
            }
            s
        }

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

        // 1. Only 127.77.0.1:3389 (`mh rdp` local forwarder) -> false
        let only_loopback_v4 = format!(
            "{header}   0: {}:0D3D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n",
            v4_hex(Ipv4Addr::new(127, 77, 0, 1))
        );
        assert!(!parse_proc_net_tcp_has_listener(&only_loopback_v4, 3389));

        // 2. 0.0.0.0:3389 -> true
        let wildcard_v4 = format!(
            "{header}   0: {}:0D3D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n",
            v4_hex(Ipv4Addr::UNSPECIFIED)
        );
        assert!(parse_proc_net_tcp_has_listener(&wildcard_v4, 3389));

        // 3. [::]:3389 -> true
        let wildcard_v6 = format!(
            "{header}   0: {}:0D3D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n",
            v6_hex(Ipv6Addr::UNSPECIFIED)
        );
        assert!(parse_proc_net_tcp_has_listener(&wildcard_v6, 3389));

        // 4. [::1]:3389 -> false
        let loopback_v6 = format!(
            "{header}   0: {}:0D3D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n",
            v6_hex(Ipv6Addr::LOCALHOST)
        );
        assert!(!parse_proc_net_tcp_has_listener(&loopback_v6, 3389));
    }

    #[test]
    fn cert_selection_rule_requires_reg_match_or_single_valid_remote_desktop_cert() {
        let cert_a = CertCandidate {
            sha1: [0x11; 20],
            sha256: "aa:11".to_string(),
            time_valid: true,
        };
        let cert_b = CertCandidate {
            sha1: [0x22; 20],
            sha256: "bb:22".to_string(),
            time_valid: true,
        };
        let cert_expired = CertCandidate {
            sha1: [0x33; 20],
            sha256: "cc:33".to_string(),
            time_valid: false,
        };

        // Multiple certs in Remote Desktop + no registry value -> None.
        assert_eq!(
            select_rdp_cert_sha256(
                &RdpRegistryCertHash::Absent,
                &[cert_a.clone(), cert_b.clone()],
                &[]
            ),
            None
        );

        // Single cert in Remote Desktop, expired + no registry value -> None.
        assert_eq!(
            select_rdp_cert_sha256(&RdpRegistryCertHash::Absent, &[cert_expired], &[]),
            None
        );

        // Single valid cert in Remote Desktop + no registry value -> Some(sha256).
        assert_eq!(
            select_rdp_cert_sha256(
                &RdpRegistryCertHash::Absent,
                std::slice::from_ref(&cert_a),
                &[]
            ),
            Some("aa:11".to_string())
        );

        // Registry SHA-1 present: selects matching cert from Remote Desktop or My even when multiple exist.
        assert_eq!(
            select_rdp_cert_sha256(
                &RdpRegistryCertHash::Sha1([0x22; 20]),
                &[cert_a.clone(), cert_b.clone()],
                &[]
            ),
            Some("bb:22".to_string())
        );
        assert_eq!(
            select_rdp_cert_sha256(
                &RdpRegistryCertHash::Sha1([0x22; 20]),
                std::slice::from_ref(&cert_a),
                std::slice::from_ref(&cert_b),
            ),
            Some("bb:22".to_string())
        );

        // Registry SHA-1 present but not found in either store -> None (never falls back).
        assert_eq!(
            select_rdp_cert_sha256(
                &RdpRegistryCertHash::Sha1([0x99; 20]),
                std::slice::from_ref(&cert_a),
                &[]
            ),
            None
        );
    }

    #[test]
    fn cert_sha256_formatting_and_pem_extraction_match_expected_digest() {
        let der = b"meshharbor-rdp-cert-der-test-bytes";
        let fp = format_cert_sha256_der(der);
        assert_eq!(fp.len(), 95);
        assert_eq!(fp.chars().filter(|&c| c == ':').count(), 31);
        assert!(
            fp.chars()
                .all(|c| c == ':' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64
        );
        assert_eq!(cert_sha256_from_pem(&pem).as_deref(), Some(fp.as_str()));
        assert_eq!(cert_sha256_from_pem("not a pem"), None);
    }
}
