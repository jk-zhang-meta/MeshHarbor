// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #5 — this node's RTT to every org relay it may bind to, measured
//! before any session exists.
//!
//! The center ranks a pair's candidate relays by the sum of both members' RTT
//! (`plan_mint_candidates_reusing`), but it used to learn an RTT only from a
//! bind to a relay it had already minted for the member, so a pair's first
//! session went to an unmeasured relay. The full netmap now names the relays
//! this node may use (`OverlayNetworkInfo::relay_probe_targets`); this task
//! measures each and the runtime reports the results as ordinary
//! `rc:overlay.relay_probe` rows.
//!
//! #5 step B: a backbone-ready relay is also offered the LINES it may carry a
//! pair over (`backbone_probe_targets`: the exit relay at the edge's private
//! endpoint). Those are probed only on the backbone interface, from a socket
//! pinned to it, and only where the local backbone policy permits the
//! endpoint; with no such policy they are not probed at all, so a line is
//! never measured over the public path.
//!
//! A probe is the relay's unauthenticated echo ([`build_probe`], answered byte
//! for byte by the relay's responder), so it needs no session, secret or VNI,
//! and it cannot amplify. [`SAMPLES`] per endpoint stays inside the
//! responder's per-source budget (4 per 2 s).

use std::net::SocketAddr;
use std::time::Duration;

use bson::oid::ObjectId;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};

use super::wire::{PROBE_TOKEN_LEN, build_probe, parse_probe};

/// How often every target is measured again: well inside the center's
/// 600-s `PROBE_TTL_SECS`, so a fresh RTT is always on file.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(240);
/// Echoes sent per endpoint; the minimum RTT is reported.
pub const SAMPLES: usize = 3;
/// How long one echo is waited for.
pub const SAMPLE_WAIT: Duration = Duration::from_millis(1500);
/// The VNI the probe frames carry. Any value answers; a probe is not a session.
const PROBE_VNI: u32 = 1;

/// One relay the netmap offered, with its endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub relay_node_id: ObjectId,
    pub endpoints: Vec<SocketAddr>,
    /// The backbone interface a line is probed on; `None` = the default route.
    pub via: Option<String>,
}

/// One endpoint's measurement: `None` when no echo came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub relay_node_id: ObjectId,
    pub endpoint: SocketAddr,
    pub rtt: Option<Duration>,
}

/// The netmap's targets as this module takes them; an endpoint that does not
/// parse is dropped. The lines (`backbone`) are kept only where `policy`, the
/// device's own backbone opt-in, permits the endpoint, and carry its
/// interface.
pub fn targets_from_wire(
    relays: &[roomler_ai_remote_control::signaling::RelayProbeTargetWire],
    backbone: &[roomler_ai_remote_control::signaling::RelayProbeTargetWire],
    policy: Option<&super::backbone::LocalBackbonePolicy>,
) -> Vec<Target> {
    let parse = |t: &roomler_ai_remote_control::signaling::RelayProbeTargetWire| {
        t.endpoints
            .iter()
            .filter_map(|e| e.parse().ok())
            .collect::<Vec<SocketAddr>>()
    };
    let own = relays.iter().map(|t| Target {
        relay_node_id: t.relay_node_id,
        endpoints: parse(t),
        via: None,
    });
    let lines = policy.into_iter().flat_map(|p| {
        backbone.iter().map(move |t| Target {
            relay_node_id: t.relay_node_id,
            endpoints: parse(t).into_iter().filter(|e| p.permits(*e)).collect(),
            via: Some(p.interface.clone()),
        })
    });
    own.chain(lines)
        .filter(|t| !t.endpoints.is_empty())
        .collect()
}

/// The minimum echo RTT to `endpoint` over [`SAMPLES`] probes, on a socket of
/// its own (so concurrent endpoints never share a responder budget), pinned
/// to interface `via` when given.
pub async fn probe_rtt(endpoint: SocketAddr, via: Option<&str>) -> Option<Duration> {
    let bind: SocketAddr = if endpoint.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = match via {
        None => UdpSocket::bind(bind).await.ok()?,
        Some(interface) => {
            let std = std::net::UdpSocket::bind(bind).ok()?;
            super::backbone::pin_interface(&socket2::SockRef::from(&std), interface).ok()?;
            std.set_nonblocking(true).ok()?;
            UdpSocket::from_std(std).ok()?
        }
    };
    let mut best: Option<Duration> = None;
    let mut buf = [0u8; 256];
    for _ in 0..SAMPLES {
        let token: [u8; PROBE_TOKEN_LEN] = rand::random();
        let sent = Instant::now();
        if sock
            .send_to(&build_probe(PROBE_VNI, &token), endpoint)
            .await
            .is_err()
        {
            return best;
        }
        let deadline = sent + SAMPLE_WAIT;
        // Only this echo counts: another source, or a late echo of an earlier
        // sample, is skipped rather than timed.
        while let Ok(Ok((n, from))) = timeout(
            deadline.saturating_duration_since(Instant::now()),
            sock.recv_from(&mut buf),
        )
        .await
        {
            if from == endpoint && parse_probe(&buf[..n]).is_some_and(|(_, t)| t == token) {
                let rtt = sent.elapsed();
                best = Some(best.map_or(rtt, |b| b.min(rtt)));
                break;
            }
        }
    }
    best
}

/// Measure every endpoint of every target, concurrently.
pub async fn probe_all(targets: &[Target]) -> Vec<Outcome> {
    let jobs = targets.iter().flat_map(|t| {
        t.endpoints.iter().map(move |&endpoint| async move {
            Outcome {
                relay_node_id: t.relay_node_id,
                endpoint,
                rtt: probe_rtt(endpoint, t.via.as_deref()).await,
            }
        })
    });
    futures::future::join_all(jobs).await
}

/// Probe the current targets now, whenever they change, and every
/// [`PROBE_INTERVAL`]; hand each round to `results`. Ends when the runtime
/// drops either channel.
pub fn spawn(
    mut targets: watch::Receiver<Vec<Target>>,
    results: mpsc::Sender<Vec<Outcome>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let now: Vec<Target> = targets.borrow_and_update().clone();
            if !now.is_empty() {
                let round = probe_all(&now).await;
                if results.send(round).await.is_err() {
                    return;
                }
            }
            tokio::select! {
                changed = targets.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::bind::CookieKey;
    use crate::overlay::orgrelay::server::{RelayServer, RelayStats};
    use std::sync::Arc;

    #[tokio::test]
    async fn a_relay_answers_a_probe_and_a_silent_endpoint_does_not() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let (server, _handle) = RelayServer::new(
            CookieKey::from_bytes([1; 32]),
            Arc::new(RelayStats::default()),
        );
        tokio::spawn(server.serve(relay_sock));
        // A bound socket nobody reads: the probe goes nowhere.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_ep = silent.local_addr().unwrap();

        let id = ObjectId::new();
        let out = probe_all(&[Target {
            relay_node_id: id,
            endpoints: vec![relay, silent_ep],
            via: None,
        }])
        .await;
        assert_eq!(out.len(), 2);
        let rtt = out.iter().find(|o| o.endpoint == relay).unwrap().rtt;
        assert!(
            rtt.is_some_and(|r| r < SAMPLE_WAIT),
            "the relay echoes: {rtt:?}"
        );
        assert_eq!(
            out.iter().find(|o| o.endpoint == silent_ep).unwrap().rtt,
            None
        );
    }

    #[tokio::test]
    async fn the_task_measures_new_targets_at_once() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let (server, _handle) = RelayServer::new(
            CookieKey::from_bytes([2; 32]),
            Arc::new(RelayStats::default()),
        );
        tokio::spawn(server.serve(relay_sock));

        let (tx, rx) = watch::channel(Vec::new());
        let (res_tx, mut res_rx) = mpsc::channel(4);
        let task = spawn(rx, res_tx);
        let id = ObjectId::new();
        tx.send_replace(vec![Target {
            relay_node_id: id,
            endpoints: vec![relay],
            via: None,
        }]);
        let round = timeout(Duration::from_secs(5), res_rx.recv())
            .await
            .expect("a round within 5 s")
            .unwrap();
        assert_eq!(round.len(), 1);
        assert_eq!(round[0].relay_node_id, id);
        assert!(round[0].rtt.is_some());
        drop(tx);
        timeout(Duration::from_secs(2), task)
            .await
            .expect("the task ends with its runtime")
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_line_is_probed_only_where_the_backbone_policy_permits_it() {
        use roomler_ai_remote_control::signaling::RelayProbeTargetWire;
        let (relay, exit) = (ObjectId::new(), ObjectId::new());
        let own = [RelayProbeTargetWire {
            relay_node_id: relay,
            endpoints: vec!["203.0.113.7:3478".into()],
        }];
        let lines = [RelayProbeTargetWire {
            relay_node_id: exit,
            endpoints: vec!["10.42.2.114:3478".into(), "192.0.2.9:3478".into()],
        }];
        // No local opt-in: a line is never measured, least of all over the
        // public path.
        let none = targets_from_wire(&own, &lines, None);
        assert_eq!(none.len(), 1);
        assert_eq!(
            (none[0].relay_node_id, none[0].via.as_deref()),
            (relay, None)
        );

        let policy = super::super::backbone::LocalBackbonePolicy {
            enabled: true,
            interface: "eth1".into(),
            allowed_cidrs: vec!["10.42.0.0/16".parse().unwrap()],
            overlay_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
        };
        let with = targets_from_wire(&own, &lines, Some(&policy));
        assert_eq!(with.len(), 2);
        let line = with.iter().find(|t| t.relay_node_id == exit).unwrap();
        assert_eq!(
            line.via.as_deref(),
            Some("eth1"),
            "pinned to the backbone NIC"
        );
        assert_eq!(
            line.endpoints,
            vec!["10.42.2.114:3478".parse::<SocketAddr>().unwrap()],
            "an endpoint outside the allowed CIDRs is dropped"
        );
    }
}
