// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1740 — a closed ICE agent must leave nothing running behind it.
//!
//! Every remote-control session owns one agent of the vendored `webrtc-ice`,
//! and the agent owns every UDP socket its candidates hold. Two doors let one
//! outlive its session, each keeping the agent (and so every socket) alive
//! for the life of the daemon:
//!
//! 1. the resolution of a browser's `<uuid>.local` host candidate. Upstream
//!    asks once a second until someone answers, and a browser off this LAN
//!    never does ([`crate::mdns_resolve`] hands on the names the OS resolver
//!    could not answer). Field 2026-09-27: +17 UDP sockets and +2 mDNS
//!    queries/s per ended session, cumulative.
//! 2. a candidate whose gathering finishes after the close (a late STUN or
//!    TURN answer), which upstream started and kept.
//!
//! Both tests are black-box: each counts the tasks alive on a runtime of its
//! own, so what they measure is exactly what a closed agent leaves behind.

use std::sync::Arc;
use std::time::Duration;

use webrtc::ice::agent::Agent;
use webrtc::ice::agent::agent_config::AgentConfig;
use webrtc::ice::candidate::candidate_base::unmarshal_candidate;
use webrtc::ice::candidate::{Candidate, CandidateType};
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::url::Url;
use webrtc::stun::message::{BINDING_SUCCESS, Message, Setter};
use webrtc::stun::xoraddr::XorMappedAddress;

/// A host candidate as Chrome sends it when it hides its LAN address.
const MDNS_HOST: &str = "candidate:842163049 1 udp 2113937151 \
     4e8b9a2c-1f3d-4c5e-9a7b-2d6f8e0c1a3b.local 54321 typ host generation 0";

/// How long a closed agent's tasks get to finish. Everything they wait on is
/// local and already signalled, so this is slack, not a timing assumption.
const SETTLE: Duration = Duration::from_secs(3);

/// A runtime of the test's own: its task count is the agent's alone.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

fn alive() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Waits for the runtime to come back down to `baseline` tasks; returns the
/// count it ended on.
async fn settle_to(baseline: usize) -> usize {
    let deadline = tokio::time::Instant::now() + SETTLE;
    loop {
        let now = alive();
        if now <= baseline || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn an_unanswered_mdns_resolution_ends_with_the_agent() {
    runtime().block_on(async {
        let baseline = alive();
        let agent = Agent::new(AgentConfig {
            multicast_dns_mode: MulticastDnsMode::QueryOnly,
            network_types: vec![NetworkType::Udp4],
            ..Default::default()
        })
        .await
        .expect("ice agent");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let idle = alive();

        let remote: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(MDNS_HOST).expect("candidate"));
        agent.add_remote_candidate(&remote).expect("add");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resolving = alive();
        if resolving == idle {
            // No mDNS socket here (the bind or every multicast join was
            // refused), so webrtc-ice started no resolution and there is
            // nothing to end. Linux CI must exercise the path: a failure there.
            #[cfg(target_os = "linux")]
            panic!("webrtc-ice started no mDNS resolution: this test measured nothing");
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("SKIP: no mDNS socket on this host, the resolution was never started");
                return;
            }
        }
        assert_eq!(
            resolving,
            idle + 1,
            "one resolution for the one unanswered name"
        );

        agent.close().await.expect("close");
        drop(agent);
        assert_eq!(
            settle_to(baseline).await,
            baseline,
            "a closed agent left a task behind: the mDNS resolution outlived it, \
             holding the agent and every socket it owned"
        );
    });
}

#[test]
fn a_candidate_gathered_after_close_does_not_outlive_the_agent() {
    runtime().block_on(async {
        // A STUN server that answers only when told to: after the close.
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("stun socket");
        let stun_addr = stun.local_addr().expect("stun addr");
        let baseline = alive();

        let agent = Agent::new(AgentConfig {
            urls: vec![Url::parse_url(&format!("stun:{stun_addr}")).expect("url")],
            candidate_types: vec![CandidateType::ServerReflexive],
            network_types: vec![NetworkType::Udp4],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        })
        .await
        .expect("ice agent");
        agent.on_candidate(Box::new(|_| Box::pin(async {})));
        agent.gather_candidates().expect("gather");

        // The gather now waits on our answer.
        let mut buf = [0u8; 1500];
        let (n, from) = tokio::time::timeout(Duration::from_secs(3), stun.recv_from(&mut buf))
            .await
            .expect("the gather sent no binding request")
            .expect("recv");

        agent.close().await.expect("close");

        // Answer now: the gather finishes against a closed agent.
        let mut request = Message::new();
        request.raw = buf[..n].to_vec();
        request.decode().expect("binding request");
        let mut answer = Message::new();
        let setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: from.ip(),
                port: from.port(),
            }),
        ];
        answer.build(&setters).expect("binding success");
        stun.send_to(&answer.raw, from).await.expect("answer");

        drop(agent);
        assert_eq!(
            settle_to(baseline).await,
            baseline,
            "a closed agent left a task behind: the candidate gathered after the \
             close kept its receive loop, holding the agent and every socket it owned"
        );
    });
}
