// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Linux TUN segmentation and receive offload: the TUN half of the batched
//! data plane ([`super::udp_batch`] is the UDP half).
//!
//! Without offload every overlay TCP segment costs one TUN `read` on the
//! sender, one TUN `write` on the receiver, and one trip through the
//! receiving kernel's IP/TCP stack. Opened with `IFF_VNET_HDR` and given
//! `TUNSETOFFLOAD`, the device behaves like a virtio NIC: the kernel hands us
//! TCP super-packets of up to 64 KiB (TSO), each behind a `virtio_net_hdr`,
//! and takes super-packets back (GRO), so both kernels do their per-packet
//! work once per run instead of once per segment. Userspace does what the NIC
//! would: split on read, coalesce on write, finish partial checksums. The
//! rules are wireguard-go's (`tun/offload_linux.go`, what Tailscale ships),
//! tightened to the kernel's own where they differ: CWR is cleared after the
//! first segment (`tcp_gso_segment`), and a run never spans a change of TCP
//! window or of an IPv6 flow label (`tcp_gro_receive`, `ipv6_gro_receive`).
//!
//! Everything except the Linux device glue ([`VnetIo`]) is packet arithmetic,
//! unit-tested on every platform.

use std::collections::HashMap;

/// `sizeof(struct virtio_net_hdr)`: the TUN default, never changed.
pub(crate) const VNET_HDR_LEN: usize = 10;
/// One TUN read: the header plus the largest packet a 16-bit IP length allows.
#[cfg_attr(
    not(all(target_os = "linux", feature = "overlay-l3")),
    allow(dead_code)
)]
pub(crate) const READ_BUF_LEN: usize = VNET_HDR_LEN + 65535;
/// The largest packet [`Gro`] builds: IPv4's total length is 16 bits.
const MAX_COALESCED: usize = 65535;

const F_NEEDS_CSUM: u8 = 1;
const GSO_NONE: u8 = 0;
const GSO_TCPV4: u8 = 1;
const GSO_TCPV6: u8 = 4;
const GSO_UDP_L4: u8 = 5;
/// Set only for a device that asked for `TUN_F_TSO_ECN`, which [`VnetIo`]
/// never does; masked off so it cannot fail a split. Segments keep CWR on the
/// first one only, which is all the flag asks for.
const GSO_ECN: u8 = 0x80;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_CWR: u8 = 0x80;

/// `struct virtio_net_hdr`. A TUN device uses the legacy layout: native
/// endian, unless `TUNSETVNETLE`/`TUNSETVNETBE` was called (it never is).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VnetHdr {
    pub(crate) flags: u8,
    pub(crate) gso_type: u8,
    pub(crate) hdr_len: u16,
    pub(crate) gso_size: u16,
    pub(crate) csum_start: u16,
    pub(crate) csum_offset: u16,
}

impl VnetHdr {
    pub(crate) fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..VNET_HDR_LEN)?;
        let u = |i: usize| u16::from_ne_bytes([b[i], b[i + 1]]);
        Some(Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: u(2),
            gso_size: u(4),
            csum_start: u(6),
            csum_offset: u(8),
        })
    }

    pub(crate) fn encode(&self) -> [u8; VNET_HDR_LEN] {
        let mut b = [0u8; VNET_HDR_LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        b
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn put16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_be_bytes());
}

fn put32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_be_bytes());
}

/// Ones'-complement addition in a u64 lane (end-around carry).
fn add(a: u64, b: u64) -> u64 {
    let (s, carry) = a.overflowing_add(b);
    s + u64::from(carry)
}

/// Ones'-complement sum of `data` as big-endian 16-bit words (an odd final
/// byte padded with zero), added to `acc`, not yet folded. Eight bytes per
/// step is exact: 2^16 − 1 divides 2^64 − 1. A part summed separately must
/// start at an even offset of the region it belongs to.
fn sum(data: &[u8], mut acc: u64) -> u64 {
    let mut words = data.chunks_exact(8);
    for w in &mut words {
        acc = add(
            acc,
            u64::from_be_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]),
        );
    }
    let rest = words.remainder();
    if !rest.is_empty() {
        let mut tail = [0u8; 8];
        tail[..rest.len()].copy_from_slice(rest);
        acc = add(acc, u64::from_be_bytes(tail));
    }
    acc
}

fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc >> 16) + (acc & 0xffff);
    }
    acc as u16
}

/// The value for a checksum field over a sum: its complement, with zero sent
/// as 0xFFFF. That is `skb_checksum_help`'s rule; UDP needs it (zero means
/// "no checksum" there) and for TCP the two spellings are the same number.
fn finish(acc: u64) -> u16 {
    match !fold(acc) {
        0 => 0xffff,
        c => c,
    }
}

/// The transport pseudo-header sum (RFC 793, RFC 8200 §8.1): both addresses,
/// the protocol, and the transport length.
fn pseudo(proto: u8, pkt: &[u8], v6: bool, len: usize) -> u64 {
    let addrs = if v6 { &pkt[8..40] } else { &pkt[12..20] };
    add(add(sum(addrs, 0), u64::from(proto)), len as u64)
}

fn ipv4_header_checksum(hdr: &mut [u8]) {
    hdr[10] = 0;
    hdr[11] = 0;
    let c = !fold(sum(hdr, 0));
    put16(&mut hdr[10..], c);
}

/// Whether a whole TCP segment's checksum verifies.
fn tcp_checksum_ok(p: &[u8], iph: usize, v6: bool) -> bool {
    fold(sum(&p[iph..], pseudo(PROTO_TCP, p, v6, p.len() - iph))) == 0xffff
}

/// Why a TUN read was dropped instead of split. The kernel only produces
/// well-formed super-packets, so each is a bug or a kernel feature this module
/// does not know; the reader drops the packet and reads on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SplitError {
    /// Shorter than its virtio-net header.
    Short,
    /// A GSO type this module does not split, or one that contradicts the IP
    /// version.
    GsoType,
    /// Offsets or lengths that do not fit the packet.
    Malformed,
}

/// Turn one TUN read (`buf`: the virtio-net header, then one packet, possibly
/// a TSO/USO super-packet) into the IP packets it carries, appended to `out`
/// in order. Each segment gets its own IP length, IPv4 ID and header checksum,
/// TCP sequence number or UDP length, and a complete transport checksum. FIN
/// and PSH stay on the last TCP segment only and CWR on the first only, as
/// the kernel segments. `buf` is scratch: a partial checksum is finished in
/// place.
pub(crate) fn split_read(buf: &mut [u8], out: &mut Vec<Vec<u8>>) -> Result<(), SplitError> {
    let hdr = VnetHdr::decode(buf).ok_or(SplitError::Short)?;
    let pkt = &mut buf[VNET_HDR_LEN..];
    let gso = hdr.gso_type & !GSO_ECN;
    if gso == GSO_NONE {
        if hdr.flags & F_NEEDS_CSUM != 0 {
            finish_partial(pkt, hdr.csum_start.into(), hdr.csum_offset.into())?;
        }
        out.push(pkt.to_vec());
        return Ok(());
    }
    let pkt = &*pkt;
    let v6 = match (pkt.first().map(|b| b >> 4), gso) {
        (Some(4), GSO_TCPV4 | GSO_UDP_L4) => false,
        (Some(6), GSO_TCPV6 | GSO_UDP_L4) => true,
        _ => return Err(SplitError::GsoType),
    };
    let tcp = gso != GSO_UDP_L4;
    let (proto, csum_field) = if tcp { (PROTO_TCP, 16) } else { (PROTO_UDP, 6) };
    let iph = usize::from(hdr.csum_start);
    if iph + 8 > pkt.len() || usize::from(hdr.csum_offset) != csum_field || hdr.gso_size == 0 {
        return Err(SplitError::Malformed);
    }
    // The header length is recomputed rather than trusted: on the FORWARD
    // path the kernel can report the whole first packet as `hdr_len`.
    let hdrs = if tcp {
        let doff = usize::from(*pkt.get(iph + 12).ok_or(SplitError::Malformed)? >> 4) * 4;
        if !(20..=60).contains(&doff) {
            return Err(SplitError::Malformed);
        }
        iph + doff
    } else {
        iph + 8
    };
    let ip_ok = if v6 {
        iph >= 40 && (iph > 40 || pkt[6] == proto)
    } else {
        iph >= 20 && iph == usize::from(pkt[0] & 0x0f) * 4 && pkt[9] == proto
    };
    if !ip_ok || hdrs > pkt.len() {
        return Err(SplitError::Malformed);
    }
    let gso_size = usize::from(hdr.gso_size);
    let first_seq = if tcp { be32(&pkt[iph + 4..]) } else { 0 };
    let first_id = if v6 { 0 } else { be16(&pkt[4..]) };
    let (mut at, mut i) = (hdrs, 0u16);
    while at < pkt.len() {
        let end = (at + gso_size).min(pkt.len());
        let len = hdrs + (end - at);
        let mut seg = Vec::with_capacity(len);
        seg.extend_from_slice(&pkt[..hdrs]);
        seg.extend_from_slice(&pkt[at..end]);
        if v6 {
            put16(&mut seg[4..], (len - 40) as u16);
        } else {
            put16(&mut seg[2..], len as u16);
            put16(&mut seg[4..], first_id.wrapping_add(i));
            ipv4_header_checksum(&mut seg[..iph]);
        }
        if tcp {
            put32(
                &mut seg[iph + 4..],
                first_seq.wrapping_add((at - hdrs) as u32),
            );
            let flags = &mut seg[iph + 13];
            if end != pkt.len() {
                *flags &= !(TCP_FIN | TCP_PSH);
            }
            if i != 0 {
                *flags &= !TCP_CWR;
            }
        } else {
            put16(&mut seg[iph + 4..], (len - iph) as u16);
        }
        let c = iph + csum_field;
        seg[c] = 0;
        seg[c + 1] = 0;
        let seed = pseudo(proto, &seg, v6, len - iph);
        let check = finish(sum(&seg[iph..], seed));
        put16(&mut seg[c..], check);
        out.push(seg);
        at = end;
        i = i.wrapping_add(1);
    }
    Ok(())
}

/// Complete a `CHECKSUM_PARTIAL` packet in place: the field at
/// `start + offset` holds the pseudo-header sum, and everything from `start`
/// on folds into it.
fn finish_partial(pkt: &mut [u8], start: usize, offset: usize) -> Result<(), SplitError> {
    let at = start + offset;
    if at + 2 > pkt.len() {
        return Err(SplitError::Malformed);
    }
    let seed = u64::from(be16(&pkt[at..]));
    pkt[at] = 0;
    pkt[at + 1] = 0;
    let check = finish(sum(&pkt[start..], seed));
    put16(&mut pkt[at..], check);
    Ok(())
}

/// One output of [`Gro::coalesce`]: a packet to write behind `hdr`.
#[derive(Debug)]
pub(crate) struct GroPacket {
    pub(crate) hdr: VnetHdr,
    pub(crate) pkt: Vec<u8>,
}

/// TCP receive coalescing for one burst of decrypted inbound packets. Kept
/// across bursts only to reuse its allocations.
#[derive(Default)]
pub(crate) struct Gro {
    flows: HashMap<FlowKey, Vec<usize>>,
    runs: Vec<Run>,
}

/// Segments that may share a run: same addresses, ports and ACK number.
/// Varying ACKs are separate flows, as in the kernel.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct FlowKey {
    v6: bool,
    src: [u8; 16],
    dst: [u8; 16],
    ports: [u8; 4],
    ack: u32,
}

/// A run being built: its head's output slot and what a joining segment must
/// match.
struct Run {
    out: usize,
    v6: bool,
    iph: usize,
    tcph: usize,
    /// Payload size of the run's segments; only the last may be shorter.
    gso_size: usize,
    /// Sequence number of the run's first payload byte.
    seq: u32,
    merged: usize,
    /// A PSH segment ended the run.
    psh: bool,
}

/// A coalescing candidate: an unfragmented TCP segment with payload, no IPv4
/// options or IPv6 extension headers, and only ACK (or ACK+PSH) set.
struct TcpSeg {
    v6: bool,
    iph: usize,
    tcph: usize,
    payload: usize,
    seq: u32,
    psh: bool,
}

impl TcpSeg {
    fn parse(p: &[u8]) -> Option<Self> {
        let (v6, iph) = match p.first()? >> 4 {
            4 if p.len() >= 40 && p[0] & 0x0f == 5 && p[9] == PROTO_TCP => {
                let whole = usize::from(be16(&p[2..])) == p.len();
                (whole && p[6] & 0x3f == 0 && p[7] == 0).then_some((false, 20))?
            }
            6 if p.len() >= 60 && p[6] == PROTO_TCP => {
                (usize::from(be16(&p[4..])) == p.len() - 40).then_some((true, 40))?
            }
            _ => return None,
        };
        let tcph = usize::from(p[iph + 12] >> 4) * 4;
        if !(20..=60).contains(&tcph) || p.len() < iph + tcph {
            return None;
        }
        let flags = p[iph + 13];
        if flags != TCP_ACK && flags != TCP_ACK | TCP_PSH {
            return None;
        }
        let payload = p.len() - iph - tcph;
        (payload > 0).then_some(Self {
            v6,
            iph,
            tcph,
            payload,
            seq: be32(&p[iph + 4..]),
            psh: flags & TCP_PSH != 0,
        })
    }

    fn key(&self, p: &[u8]) -> FlowKey {
        let (mut src, mut dst) = ([0u8; 16], [0u8; 16]);
        if self.v6 {
            src.copy_from_slice(&p[8..24]);
            dst.copy_from_slice(&p[24..40]);
        } else {
            src[..4].copy_from_slice(&p[12..16]);
            dst[..4].copy_from_slice(&p[16..20]);
        }
        let t = &p[self.iph..];
        FlowKey {
            v6: self.v6,
            src,
            dst,
            ports: [t[0], t[1], t[2], t[3]],
            ack: be32(&t[8..]),
        }
    }
}

enum Fit {
    Append,
    Prepend,
}

/// Whether `pkt` continues (`Append`) or precedes (`Prepend`) `run`: equal IP
/// fields that may not change within a run, equal TCP options and window,
/// adjacent sequence numbers, every segment `gso_size` long except the last,
/// and PSH on the last segment only.
fn fits(run: &Run, head: &[u8], pkt: &[u8], seg: &TcpSeg) -> Option<Fit> {
    if seg.v6 != run.v6 || seg.tcph != run.tcph || !ip_fields_match(head, pkt, run.v6) {
        return None;
    }
    let (h, p) = (&head[run.iph..], &pkt[seg.iph..]);
    if h[12] != p[12] || h[14..16] != p[14..16] || h[20..run.tcph] != p[20..seg.tcph] {
        return None;
    }
    let run_payload = head.len() - run.iph - run.tcph;
    if seg.seq == run.seq.wrapping_add(run_payload as u32) {
        let open =
            !run.psh && run_payload.is_multiple_of(run.gso_size) && seg.payload <= run.gso_size;
        open.then_some(Fit::Append)
    } else if seg.seq.wrapping_add(seg.payload as u32) == run.seq {
        let lead = !seg.psh
            && seg.payload >= run.gso_size
            && (seg.payload == run.gso_size || run.merged == 0);
        lead.then_some(Fit::Prepend)
    } else {
        None
    }
}

fn ip_fields_match(a: &[u8], b: &[u8], v6: bool) -> bool {
    if v6 {
        // Version, traffic class and flow label; hop limit.
        a[..4] == b[..4] && a[7] == b[7]
    } else {
        // ToS; the reserved, DF and MF bits; TTL.
        a[1] == b[1] && a[6] >> 5 == b[6] >> 5 && a[8] == b[8]
    }
}

impl Gro {
    /// Coalesce a burst of inbound IP packets (arrival order) into what to
    /// write to the device, appended to `out`; drains `pkts`. A TCP segment
    /// that continues a run of its flow joins the run's head, and each run is
    /// written as one GSO super-packet in its head's place; everything else is
    /// written as it came. Every segment's checksum is verified before it
    /// joins, because the kernel trusts the run's (`CHECKSUM_PARTIAL`); one
    /// that fails is written alone for the kernel to drop.
    pub(crate) fn coalesce(&mut self, pkts: &mut Vec<Vec<u8>>, out: &mut Vec<GroPacket>) {
        self.flows.clear();
        self.runs.clear();
        for pkt in pkts.drain(..) {
            self.push(pkt, out);
        }
        for run in &self.runs {
            if run.merged > 0 {
                finalize(&mut out[run.out], run);
            }
        }
    }

    fn push(&mut self, pkt: Vec<u8>, out: &mut Vec<GroPacket>) {
        let Some(seg) = TcpSeg::parse(&pkt) else {
            out.push(GroPacket {
                hdr: VnetHdr::default(),
                pkt,
            });
            return;
        };
        let flow = self.flows.entry(seg.key(&pkt)).or_default();
        // Newest first: in-order arrival extends the latest run.
        for k in (0..flow.len()).rev() {
            let run = &self.runs[flow[k]];
            let head = &out[run.out].pkt;
            let Some(fit) = fits(run, head, &pkt, &seg) else {
                continue;
            };
            if head.len() + seg.payload > MAX_COALESCED {
                continue;
            }
            if run.merged == 0 && !tcp_checksum_ok(head, run.iph, run.v6) {
                // The head stays written alone and leaves the table.
                flow.remove(k);
                continue;
            }
            if !tcp_checksum_ok(&pkt, seg.iph, seg.v6) {
                out.push(GroPacket {
                    hdr: VnetHdr::default(),
                    pkt,
                });
                return;
            }
            let run = &mut self.runs[flow[k]];
            let slot = run.out;
            merge(run, &mut out[slot].pkt, pkt, &seg, fit);
            return;
        }
        flow.push(self.runs.len());
        self.runs.push(Run {
            out: out.len(),
            v6: seg.v6,
            iph: seg.iph,
            tcph: seg.tcph,
            gso_size: seg.payload,
            seq: seg.seq,
            merged: 0,
            psh: seg.psh,
        });
        out.push(GroPacket {
            hdr: VnetHdr::default(),
            pkt,
        });
    }
}

fn merge(run: &mut Run, head: &mut Vec<u8>, pkt: Vec<u8>, seg: &TcpSeg, fit: Fit) {
    match fit {
        Fit::Append => {
            if run.merged == 0 {
                head.reserve_exact(MAX_COALESCED.saturating_sub(head.len()));
            }
            head.extend_from_slice(&pkt[seg.iph + seg.tcph..]);
            if seg.psh {
                head[run.iph + 13] |= TCP_PSH;
                run.psh = true;
            }
        }
        Fit::Prepend => {
            let mut lead = pkt;
            lead.reserve_exact(MAX_COALESCED.saturating_sub(lead.len()));
            lead.extend_from_slice(&head[run.iph + run.tcph..]);
            if run.psh {
                lead[seg.iph + 13] |= TCP_PSH;
            }
            *head = lead;
            run.seq = seg.seq;
            run.gso_size = seg.payload;
        }
    }
    run.merged += 1;
}

/// Make a coalesced run's head a GSO super-packet: its IP length (and IPv4
/// header checksum) cover the run, the TCP checksum field holds the
/// pseudo-header sum, and the header describes `CHECKSUM_PARTIAL` TCP GSO.
fn finalize(o: &mut GroPacket, run: &Run) {
    let len = o.pkt.len();
    let iph = run.iph;
    if run.v6 {
        put16(&mut o.pkt[4..], (len - 40) as u16);
    } else {
        put16(&mut o.pkt[2..], len as u16);
        ipv4_header_checksum(&mut o.pkt[..iph]);
    }
    let seed = fold(pseudo(PROTO_TCP, &o.pkt, run.v6, len - iph));
    put16(&mut o.pkt[iph + 16..], seed);
    o.hdr = VnetHdr {
        flags: F_NEEDS_CSUM,
        gso_type: if run.v6 { GSO_TCPV6 } else { GSO_TCPV4 },
        hdr_len: (iph + run.tcph) as u16,
        gso_size: run.gso_size as u16,
        csum_start: iph as u16,
        csum_offset: 16,
    };
}

#[cfg(all(target_os = "linux", feature = "overlay-l3"))]
pub use linux::OffloadStats;
#[cfg(all(target_os = "linux", feature = "overlay-l3"))]
pub(crate) use linux::VnetIo;

#[cfg(all(target_os = "linux", feature = "overlay-l3"))]
mod linux {
    use std::collections::VecDeque;
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

    use tokio::sync::Mutex;

    use super::{GSO_NONE, Gro, GroPacket, READ_BUF_LEN, VNET_HDR_LEN, VnetHdr, split_read};

    /// What a vnet-header device's offload has done so far: device calls
    /// against the packets that crossed them (their ratio is the offload's
    /// whole effect), and which offloads are live.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OffloadStats {
        pub tso: bool,
        pub uso: bool,
        pub gro: bool,
        pub reads: u64,
        pub read_packets: u64,
        pub writes: u64,
        pub write_packets: u64,
    }

    /// A vnet-header TUN device's framing and offload state. One reader task
    /// and one writer task use it, so its locks are uncontended; they exist to
    /// make `&self` access sound.
    pub(crate) struct VnetIo {
        /// `TUNSETOFFLOAD` accepted checksum + TSO: the kernel may hand us TCP
        /// super-packets, and takes coalesced ones back.
        tso: bool,
        /// ... and UDP segmentation (opt-in, `ROOMLERD_OVERLAY_TUN_USO`).
        uso: bool,
        /// Cleared for the device's life the first time the kernel refuses a
        /// coalesced write; runs are then written segment by segment.
        gro: AtomicBool,
        rd: Mutex<Reader>,
        wr: Mutex<Writer>,
        reads: AtomicU64,
        read_packets: AtomicU64,
        writes: AtomicU64,
        write_packets: AtomicU64,
    }

    struct Reader {
        buf: Box<[u8]>,
        segs: Vec<Vec<u8>>,
        pending: VecDeque<Vec<u8>>,
    }

    #[derive(Default)]
    struct Writer {
        gro: Gro,
        out: Vec<GroPacket>,
    }

    impl VnetIo {
        /// Ask the kernel for checksum + TSO offload on `fd`, a device opened
        /// with `IFF_VNET_HDR` (TSO since Linux 2.6; USO, Linux 6.2, only
        /// when `want_uso`). A refusal leaves plain vnet framing, which still
        /// works: every packet then crosses alone behind an empty header.
        pub(crate) fn new(fd: RawFd, want_uso: bool) -> Self {
            let tcp = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
            let udp = libc::TUN_F_USO4 | libc::TUN_F_USO6;
            // SAFETY: TUNSETOFFLOAD takes its flags by value on a TUN fd.
            let set = |f: libc::c_uint| unsafe {
                libc::ioctl(fd, libc::TUNSETOFFLOAD, libc::c_ulong::from(f)) == 0
            };
            let uso = want_uso && set(tcp | udp);
            let tso = uso || set(tcp);
            tracing::info!(tso, uso, "overlay: TUN offload (virtio-net header)");
            Self {
                tso,
                uso,
                gro: AtomicBool::new(tso),
                rd: Mutex::new(Reader {
                    buf: vec![0u8; READ_BUF_LEN].into_boxed_slice(),
                    segs: Vec::new(),
                    pending: VecDeque::new(),
                }),
                wr: Mutex::new(Writer::default()),
                reads: AtomicU64::new(0),
                read_packets: AtomicU64::new(0),
                writes: AtomicU64::new(0),
                write_packets: AtomicU64::new(0),
            }
        }

        pub(crate) fn stats(&self) -> OffloadStats {
            OffloadStats {
                tso: self.tso,
                uso: self.uso,
                gro: self.gro.load(Relaxed),
                reads: self.reads.load(Relaxed),
                read_packets: self.read_packets.load(Relaxed),
                writes: self.writes.load(Relaxed),
                write_packets: self.write_packets.load(Relaxed),
            }
        }

        /// Read until at least one IP packet is queued: a super-packet that
        /// does not split is dropped and the next one read; only a device
        /// error ends the wait.
        async fn fill(&self, rd: &mut Reader, dev: &tun::AsyncDevice) -> io::Result<()> {
            while rd.pending.is_empty() {
                let n = dev.recv(&mut rd.buf).await?;
                self.reads.fetch_add(1, Relaxed);
                match split_read(&mut rd.buf[..n], &mut rd.segs) {
                    Ok(()) => {
                        self.read_packets.fetch_add(rd.segs.len() as u64, Relaxed);
                        rd.pending.extend(rd.segs.drain(..));
                    }
                    Err(e) => {
                        rd.segs.clear();
                        tracing::debug!(
                            ?e,
                            len = n,
                            "overlay: dropped a TUN read that does not split"
                        );
                    }
                }
            }
            Ok(())
        }

        /// Every IP packet of the next device read (all segments of one
        /// super-packet), appended to `out`.
        pub(crate) async fn read(
            &self,
            dev: &tun::AsyncDevice,
            out: &mut Vec<Vec<u8>>,
        ) -> io::Result<()> {
            let mut rd = self.rd.lock().await;
            self.fill(&mut rd, dev).await?;
            out.extend(rd.pending.drain(..));
            Ok(())
        }

        /// One IP packet: the next queued segment, or the first of a new read.
        pub(crate) async fn read_one(&self, dev: &tun::AsyncDevice) -> io::Result<Vec<u8>> {
            let mut rd = self.rd.lock().await;
            self.fill(&mut rd, dev).await?;
            Ok(rd
                .pending
                .pop_front()
                .expect("fill queues at least one packet"))
        }

        /// Write a burst in order, draining `pkts`: TCP runs coalesced into
        /// super-packets while the kernel takes them, everything behind a
        /// virtio-net header.
        pub(crate) async fn write(
            &self,
            dev: &tun::AsyncDevice,
            pkts: &mut Vec<Vec<u8>>,
        ) -> io::Result<()> {
            let mut wr = self.wr.lock().await;
            let Writer { gro, out } = &mut *wr;
            self.write_packets.fetch_add(pkts.len() as u64, Relaxed);
            if self.gro.load(Relaxed) {
                gro.coalesce(pkts, out);
            } else {
                out.extend(pkts.drain(..).map(|pkt| GroPacket {
                    hdr: VnetHdr::default(),
                    pkt,
                }));
            }
            for p in out.drain(..) {
                self.write_gso(dev, &p).await?;
            }
            Ok(())
        }

        /// Write one plain IP packet.
        pub(crate) async fn write_one(&self, dev: &tun::AsyncDevice, pkt: &[u8]) -> io::Result<()> {
            self.write_packets.fetch_add(1, Relaxed);
            self.writes.fetch_add(1, Relaxed);
            write_with_hdr(dev, &[0; VNET_HDR_LEN], pkt).await
        }

        /// Write one output of the coalescer. A super-packet the kernel
        /// refuses (EINVAL) turns coalescing off for this device and is
        /// delivered as its segments instead, so a kernel that disagrees with
        /// a run costs speed, never packets.
        async fn write_gso(&self, dev: &tun::AsyncDevice, p: &GroPacket) -> io::Result<()> {
            self.writes.fetch_add(1, Relaxed);
            let hdr = p.hdr.encode();
            match write_with_hdr(dev, &hdr, &p.pkt).await {
                Err(e) if p.hdr.gso_type != GSO_NONE && e.raw_os_error() == Some(libc::EINVAL) => {
                    if self.gro.swap(false, Relaxed) {
                        tracing::warn!(
                            %e,
                            "overlay: the kernel refused a coalesced TUN write; writing segments individually"
                        );
                    }
                    let mut buf = Vec::with_capacity(VNET_HDR_LEN + p.pkt.len());
                    buf.extend_from_slice(&hdr);
                    buf.extend_from_slice(&p.pkt);
                    let mut segs = Vec::new();
                    if split_read(&mut buf, &mut segs).is_err() {
                        return Ok(());
                    }
                    for s in segs {
                        self.writes.fetch_add(1, Relaxed);
                        write_with_hdr(dev, &[0; VNET_HDR_LEN], &s).await?;
                    }
                    Ok(())
                }
                r => r,
            }
        }
    }

    /// One device write of `hdr` then `pkt`, without joining them: `writev`
    /// straight on the fd, and the readiness-aware `send` only when the
    /// device queue is full (rare: a TUN write is consumed whole or fails).
    async fn write_with_hdr(
        dev: &tun::AsyncDevice,
        hdr: &[u8; VNET_HDR_LEN],
        pkt: &[u8],
    ) -> io::Result<()> {
        let iov = [io::IoSlice::new(hdr), io::IoSlice::new(pkt)];
        // SAFETY: `IoSlice` is ABI-compatible with `iovec`, and both slices
        // outlive the call.
        let n = unsafe { libc::writev(dev.as_raw_fd(), iov.as_ptr().cast(), 2) };
        if n >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(e);
        }
        let mut joined = Vec::with_capacity(VNET_HDR_LEN + pkt.len());
        joined.extend_from_slice(hdr);
        joined.extend_from_slice(pkt);
        dev.send(&joined).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 the slow way, 16 bits at a time: the reference `sum` is
    /// checked against.
    fn naive(data: &[u8]) -> u16 {
        let mut acc: u32 = 0;
        for c in data.chunks(2) {
            let w = (u32::from(c[0]) << 8) | u32::from(*c.get(1).unwrap_or(&0));
            acc += w;
            acc = (acc & 0xffff) + (acc >> 16);
        }
        acc as u16
    }

    /// Deterministic bytes, no RNG crate needed.
    fn bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    const A4: [u8; 4] = [100, 64, 0, 1];
    const B4: [u8; 4] = [100, 64, 0, 2];

    fn v6_addr(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[1] = 0x7a;
        a[15] = last;
        a
    }

    /// A TCP segment with valid checksums (12 bytes of timestamp-like options).
    fn tcp(v6: bool, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (iph, tcph) = (if v6 { 40 } else { 20 }, 32);
        let len = iph + tcph + payload.len();
        let mut p = vec![0u8; len];
        if v6 {
            p[0] = 0x60;
            put16(&mut p[4..], (len - 40) as u16);
            p[6] = PROTO_TCP;
            p[7] = 64;
            p[8..24].copy_from_slice(&v6_addr(1));
            p[24..40].copy_from_slice(&v6_addr(2));
        } else {
            p[0] = 0x45;
            put16(&mut p[2..], len as u16);
            put16(&mut p[4..], 0x1234);
            p[6] = 0x40; // DF
            p[8] = 64;
            p[9] = PROTO_TCP;
            p[12..16].copy_from_slice(&A4);
            p[16..20].copy_from_slice(&B4);
            ipv4_header_checksum(&mut p[..20]);
        }
        let t = &mut p[iph..];
        put16(&mut t[0..], 40000);
        put16(&mut t[2..], 5201);
        put32(&mut t[4..], seq);
        put32(&mut t[8..], ack);
        t[12] = ((tcph / 4) as u8) << 4;
        t[13] = flags;
        put16(&mut t[14..], 512);
        t[20..32].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9]);
        t[tcph..].copy_from_slice(payload);
        let seed = pseudo(PROTO_TCP, &p, v6, len - iph);
        let c = finish(sum(&p[iph..], seed));
        put16(&mut p[iph + 16..], c);
        p
    }

    fn udp(v6: bool, payload: &[u8]) -> Vec<u8> {
        let iph = if v6 { 40 } else { 20 };
        let len = iph + 8 + payload.len();
        let mut p = vec![0u8; len];
        if v6 {
            p[0] = 0x60;
            put16(&mut p[4..], (len - 40) as u16);
            p[6] = PROTO_UDP;
            p[7] = 64;
            p[8..24].copy_from_slice(&v6_addr(1));
            p[24..40].copy_from_slice(&v6_addr(2));
        } else {
            p[0] = 0x45;
            put16(&mut p[2..], len as u16);
            p[8] = 64;
            p[9] = PROTO_UDP;
            p[12..16].copy_from_slice(&A4);
            p[16..20].copy_from_slice(&B4);
            ipv4_header_checksum(&mut p[..20]);
        }
        put16(&mut p[iph..], 4433);
        put16(&mut p[iph + 2..], 443);
        put16(&mut p[iph + 4..], (len - iph) as u16);
        p[iph + 8..].copy_from_slice(payload);
        let seed = pseudo(PROTO_UDP, &p, v6, len - iph);
        let c = finish(sum(&p[iph..], seed));
        put16(&mut p[iph + 6..], c);
        p
    }

    fn transport_ok(p: &[u8], v6: bool) -> bool {
        let iph = if v6 { 40 } else { usize::from(p[0] & 0x0f) * 4 };
        let proto = if v6 { p[6] } else { p[9] };
        fold(sum(&p[iph..], pseudo(proto, p, v6, p.len() - iph))) == 0xffff
    }

    fn ipv4_ok(p: &[u8]) -> bool {
        fold(sum(&p[..20], 0)) == 0xffff
    }

    /// What the kernel hands a TSO/USO device: one header over `total`
    /// payload bytes, the transport checksum field holding only the
    /// pseudo-header sum (`CHECKSUM_PARTIAL`).
    fn super_packet(v6: bool, tcp_seg: bool, payload: &[u8], gso: u16, flags: u8) -> Vec<u8> {
        let mut p = if tcp_seg {
            tcp(v6, 1000, 77, flags, payload)
        } else {
            udp(v6, payload)
        };
        let iph = if v6 { 40 } else { 20 };
        let (hl, field, proto) = if tcp_seg {
            (iph + 32, 16, PROTO_TCP)
        } else {
            (iph + 8, 6, PROTO_UDP)
        };
        let partial = fold(pseudo(proto, &p, v6, p.len() - iph));
        put16(&mut p[iph + field..], partial);
        let hdr = VnetHdr {
            flags: F_NEEDS_CSUM,
            gso_type: match (tcp_seg, v6) {
                (true, false) => GSO_TCPV4,
                (true, true) => GSO_TCPV6,
                _ => GSO_UDP_L4,
            },
            hdr_len: hl as u16,
            gso_size: gso,
            csum_start: iph as u16,
            csum_offset: field as u16,
        };
        let mut buf = hdr.encode().to_vec();
        buf.extend_from_slice(&p);
        buf
    }

    #[test]
    fn sum_matches_rfc1071_reference_for_every_length_and_alignment() {
        for len in 0..80 {
            let data = bytes(len, len as u32);
            assert_eq!(fold(sum(&data, 0)), naive(&data), "len {len}");
        }
        let big = bytes(65535, 7);
        assert_eq!(fold(sum(&big, 0)), naive(&big));
        // A region summed in even-offset parts equals the whole.
        let (a, b) = big.split_at(1234);
        assert_eq!(fold(sum(b, sum(a, 0))), naive(&big));
    }

    #[test]
    fn vnet_header_round_trips() {
        let h = VnetHdr {
            flags: 1,
            gso_type: GSO_TCPV6,
            hdr_len: 72,
            gso_size: 1208,
            csum_start: 40,
            csum_offset: 16,
        };
        assert_eq!(VnetHdr::decode(&h.encode()), Some(h));
        assert_eq!(VnetHdr::decode(&[0u8; 9]), None);
    }

    #[test]
    fn plain_reads_pass_through_and_partial_checksums_are_finished() {
        let pkt = tcp(false, 1, 2, TCP_ACK, b"hello");
        let mut buf = VnetHdr::default().encode().to_vec();
        buf.extend_from_slice(&pkt);
        let mut out = Vec::new();
        split_read(&mut buf, &mut out).unwrap();
        assert_eq!(out, vec![pkt.clone()]);

        for (v6, is_tcp) in [(false, true), (true, true), (false, false), (true, false)] {
            let full = if is_tcp {
                tcp(v6, 9, 9, TCP_ACK | TCP_PSH, &bytes(333, 3))
            } else {
                udp(v6, &bytes(333, 3))
            };
            let mut p = full.clone();
            let iph = if v6 { 40 } else { 20 };
            let field = if is_tcp { 16 } else { 6 };
            let proto = if is_tcp { PROTO_TCP } else { PROTO_UDP };
            let partial = fold(pseudo(proto, &p, v6, p.len() - iph));
            put16(&mut p[iph + field..], partial);
            let hdr = VnetHdr {
                flags: F_NEEDS_CSUM,
                csum_start: iph as u16,
                csum_offset: field as u16,
                ..VnetHdr::default()
            };
            let mut buf = hdr.encode().to_vec();
            buf.extend_from_slice(&p);
            let mut out = Vec::new();
            split_read(&mut buf, &mut out).unwrap();
            assert_eq!(out, vec![full], "v6={v6} tcp={is_tcp}");
        }
    }

    #[test]
    fn tso_reads_split_like_the_kernel_segments() {
        for v6 in [false, true] {
            let payload = bytes(10_000, 11);
            let flags = TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR;
            let mut buf = super_packet(v6, true, &payload, 1208, flags);
            let mut out = Vec::new();
            split_read(&mut buf, &mut out).unwrap();
            assert_eq!(out.len(), 10_000usize.div_ceil(1208), "v6={v6}");
            let iph = if v6 { 40 } else { 20 };
            let mut joined = Vec::new();
            for (i, s) in out.iter().enumerate() {
                let last = i == out.len() - 1;
                assert!(transport_ok(s, v6), "segment {i} checksum, v6={v6}");
                if v6 {
                    assert_eq!(usize::from(be16(&s[4..])), s.len() - 40);
                } else {
                    assert!(ipv4_ok(s), "segment {i} header checksum");
                    assert_eq!(usize::from(be16(&s[2..])), s.len());
                    assert_eq!(be16(&s[4..]), 0x1234u16.wrapping_add(i as u16));
                }
                assert_eq!(be32(&s[iph + 4..]), 1000 + 1208 * i as u32);
                let f = s[iph + 13];
                assert_eq!(f & (TCP_FIN | TCP_PSH) != 0, last, "FIN/PSH only last");
                assert_eq!(f & TCP_CWR != 0, i == 0, "CWR only first");
                assert_eq!(f & TCP_ACK, TCP_ACK);
                assert_eq!(
                    s.len(),
                    iph + 32 + if last { 10_000 - 1208 * i } else { 1208 }
                );
                joined.extend_from_slice(&s[iph + 32..]);
            }
            assert_eq!(joined, payload);
        }
    }

    #[test]
    fn uso_reads_split_into_datagrams() {
        for v6 in [false, true] {
            let payload = bytes(3000, 5);
            let mut buf = super_packet(v6, false, &payload, 1200, 0);
            let mut out = Vec::new();
            split_read(&mut buf, &mut out).unwrap();
            assert_eq!(out.len(), 3);
            let iph = if v6 { 40 } else { 20 };
            for (i, s) in out.iter().enumerate() {
                assert!(transport_ok(s, v6));
                assert_eq!(usize::from(be16(&s[iph + 4..])), s.len() - iph);
                let body = &payload[i * 1200..(i * 1200 + 1200).min(3000)];
                assert_eq!(&s[iph + 8..], body);
            }
        }
    }

    #[test]
    fn malformed_reads_are_refused_without_panicking() {
        let mut out = Vec::new();
        assert_eq!(split_read(&mut [0u8; 4], &mut out), Err(SplitError::Short));
        // TCPV6 on an IPv4 packet; an unknown GSO type.
        let mut buf = super_packet(false, true, &bytes(3000, 1), 1208, TCP_ACK);
        buf[1] = GSO_TCPV6;
        assert_eq!(split_read(&mut buf, &mut out), Err(SplitError::GsoType));
        buf[1] = 3;
        assert_eq!(split_read(&mut buf, &mut out), Err(SplitError::GsoType));
        // Zero gso_size; a checksum offset that is not TCP's.
        let mut buf = super_packet(false, true, &bytes(3000, 1), 0, TCP_ACK);
        assert_eq!(split_read(&mut buf, &mut out), Err(SplitError::Malformed));
        let mut buf = super_packet(false, true, &bytes(3000, 1), 1208, TCP_ACK);
        buf[8] = 6;
        assert_eq!(split_read(&mut buf, &mut out), Err(SplitError::Malformed));
        assert!(out.is_empty());
        // Truncations and garbage anywhere in the header never panic.
        let good = super_packet(true, true, &bytes(3000, 2), 1208, TCP_ACK);
        for cut in 0..good.len() {
            let _ = split_read(&mut good[..cut].to_vec(), &mut out);
        }
        for i in 0..80 {
            for v in [0u8, 0x0f, 0x5f, 0xff] {
                let mut b = good.clone();
                b[i] = v;
                let _ = split_read(&mut b, &mut out);
            }
        }
    }

    /// Split a run the way the receiving kernel would, to check what GRO built.
    fn resplit(o: &GroPacket) -> Vec<Vec<u8>> {
        let mut buf = o.hdr.encode().to_vec();
        buf.extend_from_slice(&o.pkt);
        let mut out = Vec::new();
        split_read(&mut buf, &mut out).unwrap();
        out
    }

    fn coalesce(pkts: Vec<Vec<u8>>) -> Vec<GroPacket> {
        let (mut pkts, mut out) = (pkts, Vec::new());
        Gro::default().coalesce(&mut pkts, &mut out);
        assert!(pkts.is_empty());
        out
    }

    fn segments(v6: bool, n: usize, size: usize, seq0: u32) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                tcp(
                    v6,
                    seq0 + (i * size) as u32,
                    5,
                    TCP_ACK,
                    &bytes(size, i as u32),
                )
            })
            .collect()
    }

    #[test]
    fn in_order_segments_coalesce_into_one_super_packet_and_split_back() {
        for v6 in [false, true] {
            let mut segs = segments(v6, 20, 1208, 7);
            let last = segs.len() - 1;
            let iph = if v6 { 40 } else { 20 };
            // A shorter PSH segment ends the run.
            segs[last] = tcp(
                v6,
                7 + 1208 * last as u32,
                5,
                TCP_ACK | TCP_PSH,
                &bytes(100, 99),
            );
            let out = coalesce(segs.clone());
            assert_eq!(out.len(), 1, "v6={v6}");
            let h = out[0].hdr;
            assert_eq!(h.flags, F_NEEDS_CSUM);
            assert_eq!(h.gso_type, if v6 { GSO_TCPV6 } else { GSO_TCPV4 });
            assert_eq!(usize::from(h.gso_size), 1208);
            assert_eq!(usize::from(h.hdr_len), iph + 32);
            assert_eq!(out[0].pkt[iph + 13], TCP_ACK | TCP_PSH);
            if !v6 {
                assert!(ipv4_ok(&out[0].pkt));
            }
            // What the receiving kernel re-segments is what was sent.
            let back = resplit(&out[0]);
            assert_eq!(back.len(), segs.len());
            for (a, b) in back.iter().zip(&segs) {
                assert_eq!(a[iph..], b[iph..], "TCP header + payload");
                if v6 {
                    assert_eq!(a, b);
                }
            }
        }
    }

    #[test]
    fn non_tcp_and_unmergeable_packets_pass_through_in_order() {
        let u = udp(false, &bytes(500, 1));
        let syn = tcp(false, 1, 0, 0x02, &[]);
        let pure_ack = tcp(false, 1, 1, TCP_ACK, &[]);
        let out = coalesce(vec![u.clone(), syn.clone(), pure_ack.clone()]);
        assert_eq!(out.len(), 3);
        for (o, p) in out.iter().zip([u, syn, pure_ack]) {
            assert_eq!(o.hdr, VnetHdr::default());
            assert_eq!(o.pkt, p);
        }
    }

    #[test]
    fn flows_interleaved_coalesce_separately_and_keep_head_order() {
        let a = segments(false, 4, 1000, 0);
        let mut b = segments(false, 4, 1000, 50_000);
        for p in &mut b {
            // A second flow: another source port.
            put16(&mut p[20..], 40001);
            p[36] = 0;
            p[37] = 0;
            let seed = pseudo(PROTO_TCP, p, false, p.len() - 20);
            let c = finish(sum(&p[20..], seed));
            put16(&mut p[36..], c);
        }
        let mixed: Vec<_> = a
            .iter()
            .zip(&b)
            .flat_map(|(x, y)| [x.clone(), y.clone()])
            .collect();
        let out = coalesce(mixed);
        assert_eq!(out.len(), 2);
        assert_eq!(be16(&out[0].pkt[20..]), 40000);
        assert_eq!(be16(&out[1].pkt[20..]), 40001);
        assert_eq!(resplit(&out[0]).len(), 4);
        assert_eq!(resplit(&out[1]).len(), 4);
    }

    /// Segments per output: what the receiving kernel would see.
    fn run_lengths(out: &[GroPacket]) -> Vec<usize> {
        out.iter()
            .map(|o| {
                if o.hdr.gso_type == GSO_NONE {
                    1
                } else {
                    resplit(o).len()
                }
            })
            .collect()
    }

    /// Re-seal an IPv4 TCP segment after a test edits it.
    fn reseal(p: &mut [u8]) {
        ipv4_header_checksum(&mut p[..20]);
        p[36] = 0;
        p[37] = 0;
        let seed = pseudo(PROTO_TCP, p, false, p.len() - 20);
        let c = finish(sum(&p[20..], seed));
        put16(&mut p[36..], c);
    }

    #[test]
    fn a_field_that_must_not_change_within_a_run_splits_it() {
        let control = coalesce(segments(false, 3, 1000, 0));
        assert_eq!(run_lengths(&control), vec![3]);
        // Edited on the middle segment: it cannot join the first, and the
        // third, no longer adjacent to the first's run, cannot either.
        type Edit = (&'static str, fn(&mut Vec<u8>));
        let edits: [Edit; 7] = [
            ("window", |p| put16(&mut p[34..], 1024)),
            ("ttl", |p| p[8] = 63),
            ("tos", |p| p[1] = 0x10),
            ("df", |p| p[6] = 0),
            ("option", |p| p[51] = 8),
            ("ack", |p| put32(&mut p[28..], 6)),
            ("sequence gap", |p| put32(&mut p[24..], 1500)),
        ];
        for (what, edit) in edits {
            let mut segs = segments(false, 3, 1000, 0);
            edit(&mut segs[1]);
            reseal(&mut segs[1]);
            assert_eq!(run_lengths(&coalesce(segs)), vec![1, 1, 1], "{what}");
        }
    }

    #[test]
    fn a_short_segment_or_psh_closes_the_run() {
        let mut segs = segments(false, 5, 1000, 0);
        segs[2] = tcp(false, 2000, 5, TCP_ACK, &bytes(10, 2)); // short: run ends after it
        segs[3] = tcp(false, 2010, 5, TCP_ACK, &bytes(1000, 3));
        segs[4] = tcp(false, 3010, 5, TCP_ACK, &bytes(1000, 4));
        let out = coalesce(segs);
        assert_eq!(out.len(), 2);
        assert_eq!(resplit(&out[0]).len(), 3);
        assert_eq!(resplit(&out[1]).len(), 2);
    }

    #[test]
    fn a_segment_that_arrives_early_is_prepended() {
        let segs = segments(true, 3, 1000, 0);
        let out = coalesce(vec![segs[1].clone(), segs[0].clone(), segs[2].clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(resplit(&out[0]), segs);
    }

    #[test]
    fn bad_checksums_are_never_coalesced() {
        let mut segs = segments(false, 4, 1000, 0);
        segs[2][60] ^= 0xff;
        let out = coalesce(segs.clone());
        assert_eq!(out.len(), 3);
        assert_eq!(resplit(&out[0]).len(), 2);
        assert_eq!(out[1].pkt, segs[2]);
        assert_eq!(out[1].hdr, VnetHdr::default());
        // A corrupt head is written alone and its run starts afresh.
        let mut segs = segments(false, 3, 1000, 0);
        segs[0][60] ^= 0xff;
        let out = coalesce(segs.clone());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].pkt, segs[0]);
        assert_eq!(resplit(&out[1]).len(), 2);
    }

    #[test]
    fn runs_stop_at_the_ip_length_limit() {
        let segs = segments(false, 120, 1208, 0);
        let out = coalesce(segs);
        assert!(out.len() >= 3);
        let mut total = 0;
        for o in &out {
            assert!(o.pkt.len() <= MAX_COALESCED);
            total += resplit(o).len();
        }
        assert_eq!(total, 120);
    }
}

#[cfg(all(test, target_os = "linux", feature = "overlay-l3"))]
mod tun_bench {
    //! End-to-end throughput over two REAL TUN devices in two network
    //! namespaces: kernel TCP → TUN → reader → pump → WireGuard → UDP over a
    //! veth → carrier plane → inbound writer → TUN → kernel TCP, every byte
    //! verified on arrival. The reader/pump/writer glue mirrors
    //! `OverlayRuntime::run`'s. Needs a kernel with TUN and CAP_NET_ADMIN +
    //! CAP_SYS_ADMIN over a fresh network namespace (`unshare -Urn`, `lo` up);
    //! `--ignored`. Env: MH_BENCH_SECS (10), MH_BENCH_STREAMS (1);
    //! `ROOMLERD_OVERLAY_TUN_OFFLOAD=0` measures the plain device.
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use crate::overlay::WgKeypair;
    use crate::overlay::carrier_plane::CarrierPlane;
    use crate::overlay::tun::{SystemTun, TunIo, TunOptions};
    use crate::overlay::wg::WgDevice;

    const PORT: u16 = 5201;
    const IP_A: Ipv4Addr = Ipv4Addr::new(100, 64, 43, 1);
    const IP_B: Ipv4Addr = Ipv4Addr::new(100, 64, 43, 2);

    fn ip(args: &str) {
        let st = std::process::Command::new("ip")
            .args(args.split_whitespace())
            .status()
            .expect("run ip");
        assert!(st.success(), "ip {args}");
    }

    fn up_tun(name: &str, ip: Ipv4Addr) -> Arc<SystemTun> {
        let mask = Ipv4Addr::new(255, 192, 0, 0);
        let opts = TunOptions {
            name: name.into(),
            ..TunOptions::legacy(ip, mask, 1280)
        };
        Arc::new(SystemTun::up_with(opts).expect("TUN up (needs /dev/net/tun and CAP_NET_ADMIN)"))
    }

    fn process_cpu_secs() -> f64 {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
        let tail = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
        let f: Vec<&str> = tail.split_whitespace().collect();
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        (ticks(11) + ticks(12)) / 100.0
    }

    /// The runtime's data plane for one node: TUN reader → pump →
    /// `send_ip_batch`, and decrypted inbound → bursts → `write_packets`.
    fn data_plane(
        t: Arc<SystemTun>,
        dev: &WgDevice,
        inbound: mpsc::Receiver<Vec<u8>>,
    ) -> [JoinHandle<()>; 3] {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
        let rt = t.clone();
        let reader = tokio::spawn(async move {
            let mut pkts = Vec::new();
            while rt.read_packets(&mut pkts).await.is_ok() {
                for p in pkts.drain(..) {
                    if tx.send(p).await.is_err() {
                        return;
                    }
                }
            }
        });
        let sender = dev.sender();
        let pump = tokio::spawn(async move {
            let mut burst = Vec::with_capacity(64);
            while let Some(p) = rx.recv().await {
                burst.push(p);
                while burst.len() < 64
                    && let Ok(p) = rx.try_recv()
                {
                    burst.push(p);
                }
                sender.send_ip_batch(&burst).await;
                burst.clear();
            }
        });
        let writer = tokio::spawn(async move {
            let mut rx = inbound;
            let mut burst = Vec::with_capacity(128);
            while let Some(p) = rx.recv().await {
                burst.push(p);
                while burst.len() < 128
                    && let Ok(p) = rx.try_recv()
                {
                    burst.push(p);
                }
                if t.write_packets(&mut burst).await.is_err() {
                    return;
                }
            }
        });
        [reader, pump, writer]
    }

    /// Checks a stream of little-endian u64 words counting up from zero.
    #[derive(Default)]
    struct Verify {
        word: u64,
        part: [u8; 8],
        have: usize,
        bytes: u64,
        bad: bool,
    }

    impl Verify {
        fn feed(&mut self, mut data: &[u8]) {
            self.bytes += data.len() as u64;
            if self.have > 0 {
                let take = (8 - self.have).min(data.len());
                self.part[self.have..self.have + take].copy_from_slice(&data[..take]);
                self.have += take;
                data = &data[take..];
                if self.have < 8 {
                    return;
                }
                self.check(u64::from_le_bytes(self.part));
                self.have = 0;
            }
            let mut words = data.chunks_exact(8);
            for w in &mut words {
                self.check(u64::from_le_bytes([
                    w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
                ]));
            }
            let rest = words.remainder();
            self.part[..rest.len()].copy_from_slice(rest);
            self.have = rest.len();
        }

        fn check(&mut self, w: u64) {
            self.bad |= w != self.word;
            self.word += 1;
        }
    }

    async fn sink(mut s: tokio::net::TcpStream) -> (u64, bool) {
        let mut buf = vec![0u8; 256 * 1024];
        let mut v = Verify::default();
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 {
                break;
            }
            v.feed(&buf[..n]);
        }
        (v.bytes, !v.bad && v.have == 0)
    }

    async fn source(deadline: Instant) {
        let mut s = tokio::net::TcpStream::connect((IP_B, PORT))
            .await
            .expect("connect over the overlay");
        let mut buf = vec![0u8; 256 * 1024];
        let mut word = 0u64;
        while Instant::now() < deadline {
            for c in buf.chunks_exact_mut(8) {
                c.copy_from_slice(&word.to_le_bytes());
                word += 1;
            }
            s.write_all(&buf).await.expect("write over the overlay");
        }
        let _ = s.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn bench_tun_e2e_tcp_throughput() {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let secs: u64 = env("MH_BENCH_SECS", "10").parse().unwrap();
        let streams: usize = env("MH_BENCH_STREAMS", "1").parse().unwrap();

        // Side B lives on its own thread in a second network namespace;
        // whatever it creates (TUN, sockets) stays there.
        ip("link add mhta type veth peer name mhtb");
        let (tid_tx, tid_rx) = std::sync::mpsc::channel::<i32>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (b_tx, b_rx) = std::sync::mpsc::channel();
        let handle = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            // SAFETY: CLONE_NEWNET moves only this thread.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "unshare(CLONE_NEWNET)"
            );
            // SAFETY: gettid has no preconditions.
            tid_tx
                .send(unsafe { libc::syscall(libc::SYS_gettid) } as i32)
                .unwrap();
            go_rx.recv().unwrap();
            ip("link set lo up");
            ip("addr add 10.254.43.2/30 dev mhtb");
            ip("link set mhtb up");
            let _rt = handle.enter();
            let t = up_tun("mhtun-b", IP_B);
            let udp = std::net::UdpSocket::bind("10.254.43.2:0").unwrap();
            let lst = std::net::TcpListener::bind((IP_B, PORT)).unwrap();
            b_tx.send((t, udp, lst)).unwrap();
        });
        let tid = tid_rx.recv().unwrap();
        ip(&format!("link set mhtb netns {tid}"));
        go_tx.send(()).unwrap();
        ip("addr add 10.254.43.1/30 dev mhta");
        ip("link set mhta up");
        let tun_a = up_tun("mhtun-a", IP_A);
        let udp_a = std::net::UdpSocket::bind("10.254.43.1:0").unwrap();
        let (tun_b, udp_b, lst_b) = b_rx.recv().unwrap();

        let tokio_udp = |s: std::net::UdpSocket| {
            s.set_nonblocking(true).unwrap();
            let s = Arc::new(tokio::net::UdpSocket::from_std(s).unwrap());
            crate::overlay::sockbuf::tune_carrier(&s, "bench");
            s
        };
        let (sock_a, sock_b) = (tokio_udp(udp_a), tokio_udp(udp_b));
        let (addr_a, addr_b): (SocketAddr, SocketAddr) =
            (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        let (kp_a, kp_b) = (WgKeypair::generate(), WgKeypair::generate());
        let (plane_a, plane_b) = (CarrierPlane::new(), CarrierPlane::new());
        plane_a.adopt_socket(sock_a.clone());
        plane_b.adopt_socket(sock_b.clone());
        let (mut a, mut rx_a) = WgDevice::new(kp_a.secret.clone());
        a.set_plane(plane_a.attach(a.plane_hooks()));
        let (mut b, mut rx_b) = WgDevice::new(kp_b.secret.clone());
        b.set_plane(plane_b.attach(b.plane_hooks()));
        b.add_direct_peer(sock_b.clone(), kp_a.public.to_bytes(), IP_A, addr_a, false)
            .await;
        a.add_direct_peer(sock_a.clone(), kp_b.public.to_bytes(), IP_B, addr_b, true)
            .await;

        // Complete the handshake both ways before TCP's first SYN needs it.
        let probe = |src: Ipv4Addr, dst: Ipv4Addr| {
            let mut p = vec![0u8; 28];
            p[0] = 0x45;
            p[3] = 28;
            p[8] = 64;
            p[9] = 17;
            p[12..16].copy_from_slice(&src.octets());
            p[16..20].copy_from_slice(&dst.octets());
            p
        };
        for (dev, rx, pkt) in [
            (&a, &mut rx_b, probe(IP_A, IP_B)),
            (&b, &mut rx_a, probe(IP_B, IP_A)),
        ] {
            let mut ok = false;
            for _ in 0..100 {
                dev.send_ip_packet(&pkt).await;
                if let Ok(Some(_)) = timeout(Duration::from_millis(50), rx.recv()).await {
                    ok = true;
                    break;
                }
            }
            assert!(ok, "WireGuard handshake over the veth");
        }
        let _plane_tasks = (
            data_plane(tun_a.clone(), &a, rx_a),
            data_plane(tun_b.clone(), &b, rx_b),
        );

        let listener = tokio::net::TcpListener::from_std({
            lst_b.set_nonblocking(true).unwrap();
            lst_b
        })
        .unwrap();
        let server = tokio::spawn(async move {
            let mut sinks = Vec::new();
            for _ in 0..streams {
                let (s, _) = listener.accept().await.unwrap();
                sinks.push(tokio::spawn(sink(s)));
            }
            let (mut bytes, mut ok) = (0u64, true);
            for s in sinks {
                let (n, good) = s.await.unwrap();
                bytes += n;
                ok &= good;
            }
            (bytes, ok)
        });
        let (cpu0, t0) = (process_cpu_secs(), Instant::now());
        let deadline = t0 + Duration::from_secs(secs);
        let sources: Vec<_> = (0..streams)
            .map(|_| tokio::spawn(source(deadline)))
            .collect();
        for s in sources {
            s.await.unwrap();
        }
        let (bytes, ok) = server.await.unwrap();
        let wall = t0.elapsed().as_secs_f64();
        let cpu = process_cpu_secs() - cpu0;
        let gbit = bytes as f64 * 8.0 / 1e9;
        let (sa, sb) = (tun_a.offload_stats(), tun_b.offload_stats());
        println!(
            "BENCH tun-e2e offload={} streams={streams} secs={wall:.2} bytes={bytes} goodput_mbps={:.1} \
             cpu={cpu:.2}s cpu_per_gbit={:.3}s verified={ok} a={sa:?} b={sb:?}",
            if sa.is_some() { "on" } else { "off" },
            gbit * 1e3 / wall,
            cpu / gbit.max(1e-9),
        );
        assert!(ok, "every byte must arrive intact and in order");
        assert!(bytes > 0);
        drop((a, b));
    }
}
