// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Multi-region relay probing — the client half of `rc:relay.regions`.
//!
//! The server pushes the region probe-target list (capability-gated on the
//! hello's `supports_relay_regions`); this module times a STUN Binding
//! round-trip against each region's coturn and reports the table back via
//! `rc:relay.probe_report`. The SERVER derives `relay_home` (with hysteresis)
//! — the agent never picks its own region, so both ends of any pair always
//! agree on whose home applies.
//!
//! Kill switch: `MESHHARBORD_RELAY_PROBE` (default ON; config-surface key
//! `relay_probe`). Probing runs at connection start (on the first push), on
//! every region-set `rev` change, and every ~20 min ±20 % jitter.

use meshharbor_remote_control::signaling::{ClientMsg, RelayRegionInfo, RelayRegionRtt};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::debug;

/// `MESHHARBORD_RELAY_PROBE` — default ON.
pub fn probing_enabled() -> bool {
    tunnel_core::env::flag("RELAY_PROBE", true)
}

/// The last region list pushed on this connection (with its `rev`), shared
/// between the dispatch arm (immediate probe on change) and the periodic
/// re-prober.
pub type RegionSlot = Arc<Mutex<Option<(Vec<RelayRegionInfo>, u64)>>>;

/// Multi-region DERP: the per-connection admission-ticket cache
/// (`(ticket, exp_unix)`), filled by the signaling loop's
/// `ServerMsg::DerpTicket` arm and read by the regional relay dialer per
/// connect attempt. Lives here (not in `derp.rs`) because that module is
/// overlay-feature-gated while the signaling arms that fill this are not.
pub type DerpTicketSlot = Arc<Mutex<Option<(String, u64)>>>;

/// STUN samples per region; the reported RTT is their median.
const SAMPLES: usize = 3;
/// Per-sample wait — a PoP farther than this is never the right home anyway.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);
const SAMPLE_SPACING: Duration = Duration::from_millis(80);
/// Re-probe cadence (±20 % jitter so a fleet never probes in lockstep).
const REPROBE_BASE: Duration = Duration::from_secs(20 * 60);

/// Probe every region and push the report through the connection's outbound
/// channel. Spawned — never blocks the signaling loop.
pub async fn probe_and_report(regions: Vec<RelayRegionInfo>, outbound: mpsc::Sender<ClientMsg>) {
    let results = probe_regions(&regions).await;
    debug!(
        results = ?results
            .iter()
            .map(|r| format!("{}={:?}", r.region, r.rtt_ms))
            .collect::<Vec<_>>(),
        "relay probe complete"
    );
    if outbound
        .send(ClientMsg::RelayProbeReport { results })
        .await
        .is_err()
    {
        debug!("relay probe: connection gone before the report could be sent");
    }
}

/// One pass over the region list (sequential — a handful of PoPs at 3 samples
/// each finishes in seconds and never bursts the uplink).
pub async fn probe_regions(regions: &[RelayRegionInfo]) -> Vec<RelayRegionRtt> {
    let mut out = Vec::with_capacity(regions.len());
    for r in regions {
        out.push(RelayRegionRtt {
            region: r.id.clone(),
            rtt_ms: probe_one(&r.stun).await,
        });
    }
    out
}

/// Median timed STUN Binding RTT against `host:port`; `None` when resolution
/// fails or every sample times out (full-UDP-block — the server then leaves
/// the home unset and this node rides the default region, which is correct:
/// its traffic goes over TURNS-443/DERP anyway).
async fn probe_one(target: &str) -> Option<u32> {
    let addr = tokio::net::lookup_host(target)
        .await
        .ok()?
        .find(|a| a.is_ipv4())?;
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    let mut samples: Vec<u32> = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let txn: [u8; 12] = rand::random();
        let req = tunnel_core::transport::stun::encode_binding_request(txn);
        let t0 = Instant::now();
        if sock.send_to(&req, addr).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 256];
        if let Ok(Ok((n, from))) =
            tokio::time::timeout(SAMPLE_TIMEOUT, sock.recv_from(&mut buf)).await
        {
            // Binding SUCCESS (0x0101) + magic cookie + OUR txn id. A stray
            // datagram or a late reply to a previous txn is simply not a
            // sample.
            if from == addr
                && n >= 20
                && buf[0] == 0x01
                && buf[1] == 0x01
                && buf[4..8] == [0x21, 0x12, 0xA4, 0x42]
                && buf[8..20] == txn
            {
                samples.push(t0.elapsed().as_millis().min(u128::from(u32::MAX)) as u32);
            }
        }
        if i + 1 < SAMPLES {
            tokio::time::sleep(SAMPLE_SPACING).await;
        }
    }
    samples.sort_unstable();
    samples.get(samples.len() / 2).copied()
}

/// Per-connection periodic re-probe driver. Exits when the connection's
/// outbound channel closes (so reconnects never accumulate probers).
pub async fn periodic_reprobe(slot: RegionSlot, outbound: mpsc::Sender<ClientMsg>) {
    loop {
        let jitter = 0.8 + rand::random::<f64>() * 0.4;
        tokio::time::sleep(REPROBE_BASE.mul_f64(jitter)).await;
        if outbound.is_closed() {
            return;
        }
        let regions = {
            let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|(r, _)| r.clone())
        };
        let Some(regions) = regions else { continue };
        probe_and_report(regions, outbound.clone()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal STUN responder: reflects Binding SUCCESS with the request's
    /// txn id (header-only, zero attributes — `probe_one` validates only the
    /// header).
    async fn fake_stun_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if n < 20 {
                    continue;
                }
                let mut resp = [0u8; 20];
                resp[0] = 0x01;
                resp[1] = 0x01; // Binding SUCCESS, length 0
                resp[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
                resp[8..20].copy_from_slice(&buf[8..20]);
                let _ = sock.send_to(&resp, from).await;
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn probe_one_measures_against_a_responder_and_nones_a_dead_port() {
        let (addr, handle) = fake_stun_server().await;
        let rtt = probe_one(&addr.to_string()).await;
        assert!(rtt.is_some(), "loopback responder must yield a sample");
        assert!(rtt.unwrap() < 2000);
        handle.abort();

        // A port nobody answers on: all samples time out → None. Use the
        // now-closed responder port (nothing listens).
        // (2 s/sample × 3 — acceptable for a unit test.)
        let dead = probe_one(&addr.to_string()).await;
        assert_eq!(dead, None);
    }

    #[tokio::test]
    async fn probe_regions_reports_every_region() {
        let (addr, handle) = fake_stun_server().await;
        let regions = vec![
            RelayRegionInfo {
                id: "up".into(),
                stun: addr.to_string(),
                derp_url: None,
                relay_band: None,
            },
            RelayRegionInfo {
                id: "bogus".into(),
                stun: "this-host-does-not-exist.invalid:3478".into(),
                derp_url: None,
                relay_band: None,
            },
        ];
        let table = probe_regions(&regions).await;
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].region, "up");
        assert!(table[0].rtt_ms.is_some());
        assert_eq!(table[1].rtt_ms, None, "unresolvable host is None");
        handle.abort();
    }
}
