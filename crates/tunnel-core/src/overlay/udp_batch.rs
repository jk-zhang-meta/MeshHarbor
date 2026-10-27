// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Batched UDP I/O for the WG data plane — FR-110's "next lever".
//!
//! One syscall per datagram was the remaining per-packet cost once FR-110
//! removed the receive drops. On Linux this module reads up to
//! [`RECV_BATCH`] messages per `recvmmsg`, with UDP GRO coalescing runs of
//! equal-size datagrams from one source, and sends a run of equal-size WG
//! data datagrams to one destination as ONE `sendmsg` with UDP GSO. Both go
//! through `quinn-udp`, the socket layer quinn already ships in this tree.
//!
//! Elsewhere, and whenever the kernel refuses an offload (quinn-udp then
//! disables it process-wide), callers keep one syscall per datagram.

#[cfg(target_os = "linux")]
pub(crate) use linux::*;

/// Largest run [`send_segments`] accepts in one call (Linux: 64 segments).
#[cfg(not(target_os = "linux"))]
pub(crate) fn max_send_segments() -> usize {
    1
}

/// No GSO here: [`max_send_segments`] is 1, so no caller ever hands this a
/// run; it exists so the batched send path compiles off Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) async fn send_segments(
    _sock: &tokio::net::UdpSocket,
    _dst: std::net::SocketAddr,
    _buf: &[u8],
    _seg: usize,
) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::sync::OnceLock;

    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    /// Messages per `recvmmsg`.
    pub(crate) const RECV_BATCH: usize = 32;
    /// Bytes per receive buffer: one GRO message holds up to 64 KiB.
    const RECV_BUF: usize = 64 * 1024;

    /// A socket's batched reader. Owns its buffers; one per recv loop.
    pub(crate) struct BatchRecv {
        state: quinn_udp::UdpSocketState,
        bufs: Vec<Box<[u8]>>,
        metas: Vec<quinn_udp::RecvMeta>,
    }

    impl BatchRecv {
        /// Enable GRO on `sock`. quinn-udp also switches the socket to
        /// `IP_PMTUDISC_PROBE` (DF on every datagram); the carrier's existing
        /// fragmentation behaviour is restored so this changes no path's
        /// reachability — only how datagrams are read.
        pub(crate) fn new(sock: &UdpSocket) -> io::Result<Self> {
            let saved = MtuDiscover::save(sock);
            let state = quinn_udp::UdpSocketState::new(sock.into())?;
            saved.restore(sock);
            Ok(Self {
                state,
                bufs: (0..RECV_BATCH).map(|_| vec![0u8; RECV_BUF].into_boxed_slice()).collect(),
                metas: vec![quinn_udp::RecvMeta::default(); RECV_BATCH],
            })
        }

        /// Wait for and read up to [`RECV_BATCH`] messages; returns how many.
        /// Errors about an earlier datagram are read past, as `udp_recv` does.
        pub(crate) async fn recv(&mut self, sock: &UdpSocket) -> io::Result<usize> {
            loop {
                sock.readable().await?;
                let Self { state, bufs, metas } = self;
                let mut iov: Vec<IoSliceMut<'_>> =
                    bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                match sock.try_io(Interest::READABLE, || state.recv(sock.into(), &mut iov, metas)) {
                    Ok(n) => return Ok(n),
                    Err(e) if super::super::udp_recv::recv_error_is_transient(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        /// Message `i`'s source and datagrams. GRO joins equal-size datagrams
        /// from one source; `stride` is that size (the whole length without GRO).
        pub(crate) fn datagrams(&mut self, i: usize) -> (SocketAddr, std::slice::ChunksMut<'_, u8>) {
            let m = &self.metas[i];
            (m.addr, self.bufs[i][..m.len].chunks_mut(m.stride.max(1)))
        }
    }

    /// Capability state for sends. The flags quinn-udp keeps are about the
    /// kernel (GSO support, a refused cmsg), not one socket, and sending sets
    /// no socket option, so one state serves every carrier socket.
    fn send_state() -> Option<&'static quinn_udp::UdpSocketState> {
        static STATE: OnceLock<Option<quinn_udp::UdpSocketState>> = OnceLock::new();
        STATE
            .get_or_init(|| {
                let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
                quinn_udp::UdpSocketState::new((&probe).into()).ok()
            })
            .as_ref()
    }

    /// Largest run [`send_segments`] accepts in one call; 1 = no GSO.
    pub(crate) fn max_send_segments() -> usize {
        send_state().map_or(1, |s| s.max_gso_segments())
    }

    /// Send `buf` — consecutive datagrams of `seg` bytes, the last possibly
    /// shorter — to `dst` as one GSO `sendmsg`. On `Err` nothing is known to
    /// have been sent and the caller resends datagram by datagram (an EIO or
    /// EINVAL here also turns GSO off for the process).
    pub(crate) async fn send_segments(
        sock: &UdpSocket,
        dst: SocketAddr,
        buf: &[u8],
        seg: usize,
    ) -> io::Result<()> {
        let state = send_state().ok_or_else(|| io::Error::other("no batched send state"))?;
        let transmit = quinn_udp::Transmit {
            destination: dst,
            ecn: None,
            contents: buf,
            segment_size: Some(seg),
            src_ip: None,
        };
        loop {
            sock.writable().await?;
            match sock.try_io(Interest::WRITABLE, || state.send(sock.into(), &transmit)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                r => return r,
            }
        }
    }

    /// The socket's `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` values.
    struct MtuDiscover {
        v4: Option<libc::c_int>,
        v6: Option<libc::c_int>,
    }

    impl MtuDiscover {
        fn save(sock: &UdpSocket) -> Self {
            let fd = sock.as_raw_fd();
            Self {
                v4: get_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
                v6: get_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
            }
        }

        fn restore(self, sock: &UdpSocket) {
            let fd = sock.as_raw_fd();
            if let Some(v) = self.v4 {
                set_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, v);
            }
            if let Some(v) = self.v6 {
                set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, v);
            }
        }
    }

    fn get_int(fd: libc::c_int, level: libc::c_int, name: libc::c_int) -> Option<libc::c_int> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v`/`len` are valid for writes of one c_int.
        let rc = unsafe { libc::getsockopt(fd, level, name, (&raw mut v).cast(), &mut len) };
        (rc == 0).then_some(v)
    }

    fn set_int(fd: libc::c_int, level: libc::c_int, name: libc::c_int, v: libc::c_int) {
        // SAFETY: `v` is a valid c_int for the duration of the call.
        let _ = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const v).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// GRO reading keeps every datagram intact and in order, the GSO send
        /// is one call for a whole run, and the socket's DF policy is unchanged.
        #[tokio::test]
        async fn gso_run_arrives_as_individual_datagrams_and_df_policy_is_kept() {
            let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let before = get_int(rx.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER);
            let mut batch = BatchRecv::new(&rx).unwrap();
            assert_eq!(get_int(rx.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER), before);

            let seg = 1312;
            let count = max_send_segments().min(20);
            let mut run = Vec::new();
            for i in 0..count {
                run.extend(std::iter::repeat_n(i as u8, if i + 1 == count { 700 } else { seg }));
            }
            send_segments(&tx, rx.local_addr().unwrap(), &run, seg).await.unwrap();

            let mut got: Vec<Vec<u8>> = Vec::new();
            while got.len() < count {
                let n = tokio::time::timeout(std::time::Duration::from_secs(5), batch.recv(&rx))
                    .await
                    .expect("datagrams arrive")
                    .unwrap();
                for i in 0..n {
                    let (src, dgs) = batch.datagrams(i);
                    assert_eq!(src, tx.local_addr().unwrap());
                    got.extend(dgs.map(|d| d.to_vec()));
                }
            }
            assert_eq!(got.len(), count);
            for (i, d) in got.iter().enumerate() {
                assert_eq!(d.len(), if i + 1 == count { 700 } else { seg }, "datagram {i}");
                assert!(d.iter().all(|&b| b == i as u8), "datagram {i} content/order");
            }
        }
    }
}
