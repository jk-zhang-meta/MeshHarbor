// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor §6 item 5 — UPnP IGD UDP port mapping, the fallback after PCP
//! and NAT-PMP. Most mainland ISP gateways speak only this.
//!
//! The steps: SSDP discovery (an `M-SEARCH` for `InternetGatewayDevice:1`
//! and `:2`, to the gateway itself and to the multicast group), then the
//! device description over HTTP for a `WANIPConnection` or `WANPPPConnection`
//! control URL, then SOAP `GetExternalIPAddress`, `AddPortMapping` and
//! `DeletePortMapping`. HTTP is a minimal HTTP/1.1 client, because builds are
//! offline with no HTTP or XML crate in tunnel-core. The description is read
//! with tag scanning, which is enough for the leaf elements used here.
//!
//! Rails:
//! * only the default gateway is trusted: the SSDP reply must come from it,
//!   and the description and control URLs must point at it, so another LAN
//!   device cannot steer the mapping or make this node fetch elsewhere;
//! * the external address must be public and is checked BEFORE a mapping is
//!   added;
//! * a router that only grants permanent leases (error 725) is asked again
//!   with lease 0, and the caller still refreshes on its own schedule. An
//!   external port taken by another client (718) moves to a random port;
//! * every HTTP exchange is bounded in time ([`HTTP_TIMEOUT`]) and size
//!   ([`MAX_HTTP`]).

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use super::{Mapping, Proto};
use crate::overlay::direct::is_public_v4;

pub(super) const SSDP_PORT: u16 = 1900;
const SSDP_MULTICAST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), SSDP_PORT);
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];
/// In preference order.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HTTP: usize = 64 * 1024;
const ERR_CONFLICT: u16 = 718;
const ERR_ONLY_PERMANENT: u16 = 725;

/// Where SSDP asks: the gateway's `ip:1900`, plus the multicast group in
/// production (a test's fake IGD listens on loopback only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ssdp {
    pub(super) to: SocketAddrV4,
    pub(super) multicast: bool,
}

/// A discovered WAN connection service: its control endpoint on the
/// gateway and its service type (the SOAP namespace).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Ctl {
    at: SocketAddrV4,
    path: String,
    service: String,
}

/// Map `internal_port` (bound on `local`) through the gateway's IGD. `prev`
/// refreshes a UPnP mapping (its control URL and external port reused).
pub(super) async fn map(
    ssdp: Ssdp,
    local: Ipv4Addr,
    internal_port: u16,
    prev: Option<&Mapping>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    let gw = *ssdp.to.ip();
    let (_, client) = super::gateway_socket(SocketAddrV4::new(gw, SSDP_PORT), local).await?;
    let ctl = match prev.and_then(|p| p.upnp.clone()) {
        Some(c) => c,
        None => discover(ssdp, local, wait).await?,
    };
    let ip: Ipv4Addr = tag(&soap(&ctl, "GetExternalIPAddress", "").await.ok()?, "NewExternalIPAddress")?
        .parse()
        .ok()?;
    if !is_public_v4(ip) {
        debug!(%ip, "portmap: the IGD's external address is not public (a second NAT?); not mapping");
        return None;
    }
    let mut ext_port = prev.map_or(internal_port, |p| p.external.port());
    let mut lease = lifetime;
    for _ in 0..3 {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext_port}</NewExternalPort>\
             <NewProtocol>UDP</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>meshharbor</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>"
        );
        match soap(&ctl, "AddPortMapping", &args).await {
            Ok(_) => {
                return Some(Mapping {
                    proto: Proto::Upnp,
                    internal_port,
                    external: SocketAddrV4::new(ip, ext_port),
                    // A permanent lease is still refreshed on our schedule.
                    lifetime: Duration::from_secs(lifetime.into()),
                    nonce: [0; 12],
                    upnp: Some(ctl),
                });
            }
            Err(ERR_ONLY_PERMANENT) if lease != 0 => lease = 0,
            Err(ERR_CONFLICT) => ext_port = 1024 + rand::random::<u16>() % (u16::MAX - 1024),
            Err(code) => {
                debug!(code, "portmap: the IGD refused AddPortMapping");
                return None;
            }
        }
    }
    None
}

/// Release a UPnP mapping (best effort).
pub(super) async fn unmap(m: &Mapping) -> bool {
    let Some(ctl) = &m.upnp else {
        return false;
    };
    let args = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>",
        m.external.port()
    );
    soap(ctl, "DeletePortMapping", &args).await.is_ok()
}

async fn discover(ssdp: Ssdp, local: Ipv4Addr, wait: Duration) -> Option<Ctl> {
    let gw = *ssdp.to.ip();
    let sock = UdpSocket::bind(SocketAddrV4::new(local, 0)).await.ok()?;
    for st in SEARCH_TARGETS {
        let req = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
        );
        let _ = sock.send_to(req.as_bytes(), ssdp.to).await;
        if ssdp.multicast {
            let _ = sock.send_to(req.as_bytes(), SSDP_MULTICAST).await;
        }
    }
    let location = tokio::time::timeout(wait, async {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.ok()?;
            if from.ip() != IpAddr::V4(gw) {
                continue;
            }
            let reply = String::from_utf8_lossy(&buf[..n]);
            if let Some(url) = header(&reply, "location").and_then(parse_url)
                && *url.0.ip() == gw
            {
                return Some(url);
            }
        }
    })
    .await
    .ok()??;
    let (status, body) = http(location.0, get_request(&location).as_bytes()).await?;
    if status != 200 {
        return None;
    }
    let (service, control) = find_service(&body)?;
    let (at, path) = resolve(&location, control)?;
    if *at.ip() != gw {
        debug!(%at, "portmap: the IGD's control URL is not on the gateway; ignoring it");
        return None;
    }
    Some(Ctl {
        at,
        path,
        service: service.to_string(),
    })
}

/// One SOAP action. `Err` carries the UPnP `errorCode` (0 = none readable or
/// no answer).
async fn soap(ctl: &Ctl, action: &str, args: &str) -> Result<String, u16> {
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{svc}\">{args}</u:{action}></s:Body></s:Envelope>\r\n",
        svc = ctl.service
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {at}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{svc}#{action}\"\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = ctl.path,
        at = ctl.at,
        svc = ctl.service,
        len = body.len()
    );
    match http(ctl.at, req.as_bytes()).await {
        Some((200, b)) => Ok(b),
        Some((_, b)) => Err(tag(&b, "errorCode").and_then(|c| c.parse().ok()).unwrap_or(0)),
        None => Err(0),
    }
}

fn get_request((at, path): &(SocketAddrV4, String)) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {at}\r\nConnection: close\r\n\r\n")
}

/// One HTTP/1.1 exchange: status and body, read to the end of the body
/// (`Content-Length`, or EOF), de-chunked when chunked.
async fn http(to: SocketAddrV4, req: &[u8]) -> Option<(u16, String)> {
    tokio::time::timeout(HTTP_TIMEOUT, async {
        let mut s = TcpStream::connect(to).await.ok()?;
        s.write_all(req).await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > MAX_HTTP {
                return None;
            }
            if response_complete(&buf) {
                break;
            }
        }
        parse_response(&buf)
    })
    .await
    .ok()?
}

/// A router that ignores `Connection: close` keeps the socket open; stop
/// once `Content-Length` bytes of body are in.
fn response_complete(buf: &[u8]) -> bool {
    let Some(h) = find(buf, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..h]);
    header(&head, "content-length")
        .and_then(|l| l.parse::<usize>().ok())
        .is_some_and(|len| buf.len() >= h + 4 + len)
}

fn parse_response(buf: &[u8]) -> Option<(u16, String)> {
    let h = find(buf, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..h]);
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    let mut body = buf[h + 4..].to_vec();
    if header(&head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        body = dechunk(&body)?;
    } else if let Some(len) = header(&head, "content-length").and_then(|l| l.parse::<usize>().ok()) {
        body.truncate(len);
    }
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find(b, b"\r\n")?;
        let size_txt = std::str::from_utf8(&b[..eol]).ok()?;
        let size = usize::from_str_radix(size_txt.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        let start = eol + 2;
        out.extend_from_slice(b.get(start..start + size)?);
        b = b.get(start + size + 2..)?;
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A header's value, matched case-insensitively.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// `http://a.b.c.d[:port]/path` → (`a.b.c.d:port`, `/path`). Only IPv4
/// literal hosts: a gateway's URLs name its own address.
fn parse_url(u: &str) -> Option<(SocketAddrV4, String)> {
    let rest = u.get(..7).filter(|p| p.eq_ignore_ascii_case("http://")).map(|_| &u[7..])?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (hostport, 80),
    };
    Some((SocketAddrV4::new(host.parse().ok()?, port), path))
}

/// Resolve a control URL against the description's location: absolute,
/// host-relative (`/ctl`) or path-relative (`ctl`).
fn resolve((at, base): &(SocketAddrV4, String), control: &str) -> Option<(SocketAddrV4, String)> {
    if control.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://")) {
        return parse_url(control);
    }
    if control.starts_with('/') {
        return Some((*at, control.to_string()));
    }
    let dir = &base[..base.rfind('/').map_or(0, |i| i + 1)];
    Some((*at, format!("{}{control}", if dir.is_empty() { "/" } else { dir })))
}

/// The preferred WAN connection service in a device description, and its
/// control URL.
fn find_service(xml: &str) -> Option<(&'static str, &str)> {
    let blocks: Vec<&str> = xml.split("<service>").skip(1).collect();
    SERVICES.iter().find_map(|want| {
        blocks.iter().find_map(|b| {
            (tag(b, "serviceType")? == *want).then_some(())?;
            Some((*want, tag(b, "controlURL")?))
        })
    })
}

/// The text of the first `<name>` or `<prefix:name>` leaf element.
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = xml[from..].find(name) {
        let s = from + i;
        let e = s + name.len();
        from = e;
        let Some(lt) = xml[..s].rfind('<') else {
            continue;
        };
        let prefix = &xml[lt + 1..s];
        let opening = !prefix.starts_with('/')
            && (prefix.is_empty() || (prefix.ends_with(':') && prefix.bytes().all(|c| c.is_ascii_alphanumeric() || c == b':')));
        if !opening || !matches!(xml.as_bytes().get(e), Some(b'>') | Some(b' ')) {
            continue;
        }
        let start = e + xml[e..].find('>')? + 1;
        let end = start + xml[start..].find("</")?;
        return Some(xml[start..end].trim());
    }
    None
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    pub(in crate::overlay::portmap) const EXTERNAL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    /// How the fake IGD answers `AddPortMapping`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(in crate::overlay::portmap) enum Igd {
        Grants,
        /// Error 725 unless the lease is 0.
        PermanentOnly,
        /// Error 718 for the internal port asked as the external one.
        Conflict,
        /// The description's control URL points off the gateway.
        ForeignControl,
    }

    const DESC: &str = "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
        <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
        <controlURL>/ctl/L3F</controlURL></service></serviceList><deviceList><device>\
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>CONTROL</controlURL>\
        </service></serviceList></device></deviceList></device></root>";

    /// A fake IGD on loopback: an SSDP responder and an HTTP server. Returns
    /// the SSDP target and every HTTP request it served.
    pub(in crate::overlay::portmap) async fn igd(kind: Igd) -> (Ssdp, Arc<Mutex<Vec<String>>>) {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_at = http.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = http.accept().await {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                loop {
                    let k = s.read(&mut buf[n..]).await.unwrap_or(0);
                    n += k;
                    if k == 0 || response_complete(&buf[..n]) || (n >= 4 && buf[..n].ends_with(b"\r\n\r\n") && buf.starts_with(b"GET")) {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                log.lock().unwrap().push(req.clone());
                let control = if kind == Igd::ForeignControl { "http://127.0.0.2:1/ctl/IPConn" } else { "/ctl/IPConn" };
                let (status, body) = if req.starts_with("GET /rootDesc.xml") {
                    (200, DESC.replace("CONTROL", control))
                } else if req.contains("#GetExternalIPAddress") {
                    (200, format!("<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>{EXTERNAL}</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"))
                } else if req.contains("#AddPortMapping") {
                    let internal = tag(&req, "NewInternalPort").unwrap_or("").to_string();
                    let external = tag(&req, "NewExternalPort").unwrap_or("").to_string();
                    let refuse = match kind {
                        Igd::PermanentOnly if tag(&req, "NewLeaseDuration") != Some("0") => Some(ERR_ONLY_PERMANENT),
                        Igd::Conflict if internal == external => Some(ERR_CONFLICT),
                        _ => None,
                    };
                    match refuse {
                        Some(code) => (500, format!("<s:Envelope><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>")),
                        None => (200, String::from("<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>")),
                    }
                } else if req.contains("#DeletePortMapping") {
                    (200, String::from("<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>"))
                } else {
                    (404, String::new())
                };
                let resp = format!("HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        let ssdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(to) = ssdp.local_addr().unwrap() else { unreachable!() };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, from)) = ssdp.recv_from(&mut buf).await {
                if buf[..n].starts_with(b"M-SEARCH") {
                    let reply = format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {}\r\nLOCATION: http://{http_at}/rootDesc.xml\r\n\r\n", SEARCH_TARGETS[0]);
                    let _ = ssdp.send_to(reply.as_bytes(), from).await;
                }
            }
        });
        (Ssdp { to, multicast: false }, seen)
    }

    const WAIT: Duration = Duration::from_millis(400);

    fn adds(seen: &Mutex<Vec<String>>) -> Vec<String> {
        seen.lock().unwrap().iter().filter(|r| r.contains("#AddPortMapping")).cloned().collect()
    }

    #[tokio::test]
    async fn an_igd_maps_the_port_at_its_external_address() {
        let (ssdp, seen) = igd(Igd::Grants).await;
        let m = map(ssdp, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.expect("mapped");
        assert_eq!((m.proto, m.external), (Proto::Upnp, SocketAddrV4::new(EXTERNAL, 43648)));
        let add = adds(&seen).pop().unwrap();
        assert!(add.contains("SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""), "{add}");
        assert_eq!(tag(&add, "NewInternalClient"), Some("127.0.0.1"));
        assert_eq!(tag(&add, "NewProtocol"), Some("UDP"));
        assert_eq!(tag(&add, "NewLeaseDuration"), Some("7200"));
        assert!(add.starts_with("POST /ctl/IPConn "), "the WAN service's control URL, not Layer3Forwarding's");
        assert!(unmap(&m).await);
        assert!(seen.lock().unwrap().last().unwrap().contains("#DeletePortMapping"));
    }

    #[tokio::test]
    async fn a_permanent_only_igd_is_asked_again_with_lease_zero() {
        let (ssdp, seen) = igd(Igd::PermanentOnly).await;
        let m = map(ssdp, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.expect("mapped");
        assert_eq!(m.lifetime, Duration::from_secs(7200), "still refreshed on our schedule");
        let leases: Vec<String> = adds(&seen).iter().filter_map(|r| tag(r, "NewLeaseDuration").map(str::to_string)).collect();
        assert_eq!(leases, ["7200", "0"]);
    }

    #[tokio::test]
    async fn a_taken_external_port_moves_to_another() {
        let (ssdp, _) = igd(Igd::Conflict).await;
        let m = map(ssdp, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.expect("mapped");
        assert_ne!(m.external.port(), 43648);
        assert!(m.external.port() >= 1024);
    }

    #[tokio::test]
    async fn a_refresh_reuses_the_control_url_and_external_port() {
        let (ssdp, seen) = igd(Igd::Conflict).await;
        let first = map(ssdp, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.unwrap();
        let n = seen.lock().unwrap().len();
        let again = map(ssdp, Ipv4Addr::LOCALHOST, 43648, Some(&first), 7200, WAIT).await.unwrap();
        assert_eq!(again.external, first.external);
        let seen = seen.lock().unwrap();
        assert!(!seen[n..].iter().any(|r| r.starts_with("GET")), "no rediscovery");
    }

    #[tokio::test]
    async fn a_control_url_off_the_gateway_is_refused() {
        let (ssdp, seen) = igd(Igd::ForeignControl).await;
        assert!(map(ssdp, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.is_none());
        assert!(adds(&seen).is_empty());
    }

    #[tokio::test]
    async fn no_igd_costs_one_wait() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(to) = sock.local_addr().unwrap() else { unreachable!() };
        let t = std::time::Instant::now();
        assert!(map(Ssdp { to, multicast: false }, Ipv4Addr::LOCALHOST, 43648, None, 7200, WAIT).await.is_none());
        assert!(t.elapsed() < WAIT + Duration::from_millis(200), "took {:?}", t.elapsed());
    }

    #[test]
    fn the_parsers_handle_real_router_shapes() {
        assert_eq!(tag("<m:NewExternalIPAddress>1.2.3.4</m:NewExternalIPAddress>", "NewExternalIPAddress"), Some("1.2.3.4"));
        assert_eq!(tag("<errorCode >718</errorCode>", "errorCode"), Some("718"));
        assert_eq!(tag("<NewExternalIPAddressX>no</NewExternalIPAddressX>", "NewExternalIPAddress"), None);
        assert_eq!(dechunk(b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n").unwrap(), b"hello world");
        let loc = parse_url("HTTP://192.168.1.1:5000/desc/root.xml").unwrap();
        assert_eq!(loc, (SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 5000), "/desc/root.xml".into()));
        assert_eq!(resolve(&loc, "ctl/IPConn").unwrap().1, "/desc/ctl/IPConn");
        assert_eq!(resolve(&loc, "/upnp/control").unwrap().1, "/upnp/control");
        assert_eq!(resolve(&loc, "http://192.168.1.1:49152/c").unwrap().0.port(), 49152);
        assert_eq!(parse_url("http://router.lan/x"), None, "only IPv4 literal hosts");
        assert_eq!(header("HTTP/1.1 200 OK\r\nLocation: http://a\r\n", "LOCATION"), Some("http://a"));
    }
}
