// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Bounded, single-peer datagram seam for a future authorized mesh carrier.
//!
//! This adapter does NOT discover, authenticate, register or select peers. The
//! caller must authorize the underlying transport and pin its remote endpoint
//! before construction. It carries opaque WireGuard ciphertext without changing
//! WireGuard identity, TUN, DNS, system routes or existing transport defaults.
//! No EasyTier engine or automatic route/quality switching is installed here.
//! The underlying transport must honor datagram boundaries and cancellation.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::{Semaphore, watch};

use super::relay::{RelayConn, RelayTransport};

/// UDP's maximum IPv4 payload; the adapter never allocates above this plus one.
pub const MAX_FABRIC_DATAGRAM: usize = 65_507;

/// A caller-authorized, endpoint-pinned connection implementing the existing
/// [`RelayConn`] seam. At most one send and one receive can be in flight; excess
/// callers receive `WouldBlock`, not an unbounded pending queue. A timed-out send
/// is not retried: delivery may already have happened in the underlying transport.
pub struct FabricRelayConn {
    inner: Arc<dyn RelayConn>,
    peer: SocketAddr,
    max_datagram: usize,
    send_timeout: Duration,
    send_slot: Semaphore,
    recv_slot: Semaphore,
    closed: watch::Sender<bool>,
    dropped_datagrams: AtomicU64,
}

impl FabricRelayConn {
    pub fn new(
        inner: Arc<dyn RelayConn>,
        peer: SocketAddr,
        max_datagram: usize,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fabric peer",
            ));
        }
        if !(1..=MAX_FABRIC_DATAGRAM).contains(&max_datagram) || send_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fabric limits",
            ));
        }
        let (closed, _) = watch::channel(false);
        Ok(Self {
            inner,
            peer,
            max_datagram,
            send_timeout,
            send_slot: Semaphore::new(1),
            recv_slot: Semaphore::new(1),
            closed,
            dropped_datagrams: AtomicU64::new(0),
        })
    }

    /// Permanently cancel this adapter's pending I/O. The shared underlying
    /// transport is not closed, so unrelated peers using it are not disturbed.
    pub fn close(&self) {
        self.closed.send_replace(true);
    }

    /// Number of invalid-source or oversize datagrams discarded internally.
    /// Per-packet refusals must not become terminal errors in RelayConn consumers.
    pub fn dropped_datagrams(&self) -> u64 {
        self.dropped_datagrams.load(Ordering::Relaxed)
    }

    fn open(&self) -> io::Result<watch::Receiver<bool>> {
        let rx = self.closed.subscribe();
        let is_closed = *rx.borrow();
        if is_closed {
            Err(closed_error())
        } else {
            Ok(rx)
        }
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "fabric adapter closed")
}

#[async_trait]
impl RelayConn for FabricRelayConn {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        let mut closed = self.open()?;
        if dst != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fabric peer mismatch",
            ));
        }
        if buf.len() > self.max_datagram {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fabric datagram too large",
            ));
        }
        let _slot = self.send_slot.try_acquire().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "fabric send already in flight")
        })?;
        tokio::select! {
            biased;
            _ = closed.changed() => Err(closed_error()),
            result = tokio::time::timeout(self.send_timeout, self.inner.send_to(buf, dst)) => {
                let count = result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fabric send deadline"))??;
                if count != buf.len() {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "partial fabric datagram"));
                }
                Ok(count)
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut closed = self.open()?;
        let _slot = self.recv_slot.try_acquire().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "fabric receive already in flight",
            )
        })?;
        // The sentinel byte detects oversize before copying anything to callers;
        // a small caller buffer must never turn truncation into a successful WG
        // datagram. The allocation and outstanding operations are strictly bounded.
        let mut packet = vec![0u8; self.max_datagram + 1];
        let mut rejected_in_batch = 0;
        loop {
            let (count, src) = tokio::select! {
                biased;
                _ = closed.changed() => return Err(closed_error()),
                result = self.inner.recv_from(&mut packet) => result?,
            };
            if src != self.peer || count > self.max_datagram || count > buf.len() {
                self.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                rejected_in_batch += 1;
                // Invalid datagrams are packet drops, not connection failures:
                // RelayUdpSocket's fill task terminates on any recv error.
                // Bound uninterrupted work even for an always-ready transport.
                if rejected_in_batch == 16 {
                    tokio::task::yield_now().await;
                    rejected_in_batch = 0;
                }
                continue;
            }
            buf[..count].copy_from_slice(&packet[..count]);
            return Ok((count, src));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let _ = self.open()?;
        self.inner.local_addr()
    }

    fn relay_transport(&self) -> RelayTransport {
        self.inner.relay_transport()
    }

    fn relay_server(&self) -> Option<String> {
        self.inner.relay_server()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::relay::UdpRelayConn;
    use tokio::{net::UdpSocket, time::timeout};

    async fn pair(max: usize) -> (Arc<FabricRelayConn>, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let adapter = FabricRelayConn::new(
            Arc::new(UdpRelayConn(a)),
            b.local_addr().unwrap(),
            max,
            Duration::from_secs(1),
        )
        .unwrap();
        (Arc::new(adapter), b)
    }

    // Observe each rejection before submitting the next phase. UDP delivery
    // ordering across different sender sockets is not an application guarantee.
    async fn wait_for_drops(adapter: &FabricRelayConn, expected: u64) {
        timeout(Duration::from_secs(1), async {
            while adapter.dropped_datagrams() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expected invalid datagram was not consumed");
        assert_eq!(adapter.dropped_datagrams(), expected);
    }

    #[tokio::test]
    async fn fabric_loopback_preserves_opaque_datagrams_and_endpoints() {
        let (adapter, peer) = pair(2048).await;
        let local = adapter.local_addr().unwrap();
        let remote = peer.local_addr().unwrap();
        // Binary/zero bytes, two distinct datagrams, no stream concatenation.
        let packets: [&[u8]; 2] = [&[4, 0, 0, 0, 255, 128, 0], &[9, 8, 0, 7]];
        let mut buf = [0u8; 2048];
        for packet in packets {
            assert_eq!(adapter.send_to(packet, remote).await.unwrap(), packet.len());
            let (n, src) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(src, local);
            assert_eq!(&buf[..n], packet);
            peer.send_to(packet, local).await.unwrap();
            let (n, src) = timeout(Duration::from_secs(1), adapter.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(src, remote);
            assert_eq!(&buf[..n], packet);
        }
        println!("FABRIC roundtrip=2 boundaries=preserved source=exact opaque=unchanged");
    }

    #[tokio::test]
    async fn fabric_rejects_other_peer_and_oversize_without_truncation() {
        let (adapter, peer) = pair(8).await;
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = adapter.local_addr().unwrap();
        let remote = peer.local_addr().unwrap();
        assert_eq!(
            adapter
                .send_to(b"a", stranger.local_addr().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            adapter.send_to(&[0; 9], remote).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let receiver = adapter.clone();
        let pending = tokio::spawn(async move {
            let mut buf = [0x55; 16];
            let (n, src) = receiver.recv_from(&mut buf).await.unwrap();
            (buf, n, src)
        });
        stranger.send_to(b"bad", local).await.unwrap();
        wait_for_drops(&adapter, 1).await;
        peer.send_to(&[1; 9], local).await.unwrap();
        wait_for_drops(&adapter, 2).await;
        peer.send_to(b"ok", local).await.unwrap();
        let (buf, n, src) = timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(src, remote);
        assert_eq!(&buf[..n], b"ok");
        assert_eq!(&buf[n..], &[0x55; 14]);
        let receiver = adapter.clone();
        let pending = tokio::spawn(async move {
            let mut buf = [0x55; 4];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            (buf, n)
        });
        peer.send_to(&[2; 8], local).await.unwrap();
        wait_for_drops(&adapter, 3).await;
        peer.send_to(b"yes", local).await.unwrap();
        let (buf, n) = timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"yes");
        assert_eq!(buf[n], 0x55);
    }

    #[tokio::test]
    async fn fabric_native_relay_socket_survives_rejected_datagrams() {
        use crate::transport::relay::RelayUdpSocket;
        use quinn::{AsyncUdpSocket, udp::RecvMeta};
        use std::{future::poll_fn, io::IoSliceMut, task::Poll};
        let (adapter, peer) = pair(8).await;
        let local = adapter.local_addr().unwrap();
        let remote = peer.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = RelayUdpSocket::new(adapter.clone()).unwrap();
        stranger.send_to(b"bad", local).await.unwrap();
        wait_for_drops(&adapter, 1).await;
        peer.send_to(&[0; 9], local).await.unwrap();
        wait_for_drops(&adapter, 2).await;
        peer.send_to(b"valid", local).await.unwrap();
        let mut buf = [0u8; 32];
        let (n, source) = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut buf)];
                let mut meta = [RecvMeta::default()];
                match socket.poll_recv(cx, &mut bufs, &mut meta) {
                    Poll::Ready(Ok(_)) => Poll::Ready((meta[0].len, meta[0].addr)),
                    Poll::Ready(Err(error)) => panic!("native receive pump ended: {error}"),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(&buf[..n], b"valid");
        assert_eq!(source, remote);
        assert_eq!(adapter.dropped_datagrams(), 2);
        adapter.close();
    }

    #[tokio::test]
    async fn fabric_receive_backpressure_and_close_cancel_pending_io() {
        let (adapter, peer) = pair(64).await;
        // Hold exactly the permit a pending receive holds: competing callers
        // must fail immediately rather than accumulate in a queue.
        let slot = adapter.recv_slot.try_acquire().unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            adapter.recv_from(&mut buf).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(slot);
        let task_adapter = adapter.clone();
        let pending = tokio::spawn(async move {
            task_adapter
                .recv_from(&mut [0u8; 64])
                .await
                .unwrap_err()
                .kind()
        });
        while adapter.recv_slot.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        adapter.close();
        assert_eq!(
            timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            adapter
                .send_to(b"x", peer.local_addr().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            adapter.local_addr().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    struct StalledSend;
    #[async_trait]
    impl RelayConn for StalledSend {
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            std::future::pending().await
        }
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
    }

    #[tokio::test]
    async fn fabric_send_is_bounded_and_releases_slot_after_timeout() {
        let peer = "127.0.0.1:2".parse().unwrap();
        let adapter =
            FabricRelayConn::new(Arc::new(StalledSend), peer, 64, Duration::from_millis(10))
                .unwrap();
        let slot = adapter.send_slot.try_acquire().unwrap();
        assert_eq!(
            adapter.send_to(b"x", peer).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(slot);
        assert_eq!(
            adapter.send_to(b"x", peer).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(adapter.send_slot.available_permits(), 1);
    }

    #[tokio::test]
    async fn fabric_close_cancels_inflight_send() {
        let peer = "127.0.0.1:2".parse().unwrap();
        let adapter = Arc::new(
            FabricRelayConn::new(Arc::new(StalledSend), peer, 64, Duration::from_secs(60)).unwrap(),
        );
        let task_adapter = adapter.clone();
        let pending =
            tokio::spawn(async move { task_adapter.send_to(b"x", peer).await.unwrap_err().kind() });
        while adapter.send_slot.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        adapter.close();
        assert_eq!(
            timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(adapter.send_slot.available_permits(), 1);
    }

    #[tokio::test]
    async fn fabric_invalid_limits_are_refused() {
        let peer = "127.0.0.1:2".parse().unwrap();
        for size in [0, MAX_FABRIC_DATAGRAM + 1] {
            assert!(
                FabricRelayConn::new(Arc::new(StalledSend), peer, size, Duration::from_secs(1))
                    .is_err()
            );
        }
        assert!(FabricRelayConn::new(Arc::new(StalledSend), peer, 64, Duration::ZERO).is_err());
        assert!(
            FabricRelayConn::new(
                Arc::new(StalledSend),
                "0.0.0.0:0".parse().unwrap(),
                64,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
