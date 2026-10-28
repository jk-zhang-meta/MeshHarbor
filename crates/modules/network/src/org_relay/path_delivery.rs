// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Construct relay and local-bridge messages for an ordered relay session.
//! This checks structural consistency, not authorization or reservation.

use super::{LineLeg, OrgRelaySession};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use roomler_ai_remote_control::{
    models::{NodeRef, peer_relay_limits as limits},
    signaling::{RelayBridgeWire, RelayMemberWire, ServerMsg},
};
use std::{collections::HashSet, time::Instant};

pub(super) struct Delivery {
    /// All relay sessions must be installed before any bridge is started.
    pub relays: Vec<(NodeRef, ServerMsg)>,
    /// Each bridge runs on its preceding relay and joins its successor.
    pub bridges: Vec<(NodeRef, ServerMsg)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DeliveryError {
    InvalidIdentity,
    DuplicateRelay,
    InvalidVni,
    InvalidSecret,
    DuplicateSecret,
    InvalidEndpoint,
    DuplicateBridge,
    Expired,
}

fn valid_vni(vni: u32) -> bool {
    vni > 0 && vni <= limits::VNI_MAX && vni != limits::STUN_COOKIE_VNI
}

/// Validate the complete shape before returning any control messages. The
/// caller must independently reauthorize each member, relay, edge and reserve
/// resources atomically; this is not an authorization or a send operation.
pub(super) fn build(s: &OrgRelaySession, now: Instant) -> Result<Delivery, DeliveryError> {
    let remaining = s
        .expires_at
        .saturating_duration_since(now)
        .as_secs()
        .min(u64::from(limits::MAX_LIFETIME_SECS)) as u32;
    if remaining == 0 || s.bind_by <= now {
        return Err(DeliveryError::Expired);
    }
    if s.members[0].party.node_id == s.members[1].party.node_id
        || s.members[0].party.node_ref == s.members[1].party.node_ref
        || s.members.iter().any(|m| {
            BASE64
                .decode(&m.wg_public_key)
                .map_or(true, |b| b.len() != 32)
        })
    {
        return Err(DeliveryError::InvalidIdentity);
    }
    let mut seen_nodes = HashSet::new();
    let mut seen_agents = HashSet::new();
    let mut seen_bridges = HashSet::new();
    let mut seen_secrets = HashSet::new();
    let mut check_secret = |secret: &str| -> Result<(), DeliveryError> {
        let bytes: [u8; 32] = BASE64
            .decode(secret)
            .map_err(|_| DeliveryError::InvalidSecret)?
            .try_into()
            .map_err(|_| DeliveryError::InvalidSecret)?;
        if !seen_secrets.insert(bytes) {
            return Err(DeliveryError::DuplicateSecret);
        }
        Ok(())
    };
    for member in &s.members {
        check_secret(&member.bind_secret)?;
    }
    let check_relay = |node_id,
                       node_ref: &NodeRef,
                       agent_id,
                       vni,
                       generation,
                       endpoints: &[String],
                       seen_nodes: &mut HashSet<ObjectId>,
                       seen_agents: &mut HashSet<ObjectId>| {
        if !matches!(node_ref, NodeRef::Agent { agent_id: actual } if *actual == agent_id)
            || s.members
                .iter()
                .any(|m| m.party.node_id == node_id || &m.party.node_ref == node_ref)
        {
            return Err(DeliveryError::InvalidIdentity);
        }
        if !seen_nodes.insert(node_id) || !seen_agents.insert(agent_id) {
            return Err(DeliveryError::DuplicateRelay);
        }
        if !valid_vni(vni) || generation == 0 {
            return Err(DeliveryError::InvalidVni);
        }
        if endpoints.is_empty() {
            return Err(DeliveryError::InvalidEndpoint);
        }
        Ok(())
    };
    check_relay(
        s.relay.node_id,
        &s.relay.node_ref,
        s.relay_agent_id,
        s.vni,
        s.generation,
        &s.endpoints,
        &mut seen_nodes,
        &mut seen_agents,
    )?;
    for hop in &s.hops {
        check_relay(
            hop.relay.node_id,
            &hop.relay.node_ref,
            hop.relay_agent_id,
            hop.vni,
            hop.generation,
            &hop.endpoints,
            &mut seen_nodes,
            &mut seen_agents,
        )?;
        if !crate::routes::peer_relay::valid_backbone_endpoint(&hop.private_endpoint) {
            return Err(DeliveryError::InvalidEndpoint);
        }
        if !seen_bridges.insert(hop.bridge_id) {
            return Err(DeliveryError::DuplicateBridge);
        }
        check_secret(&hop.bridge_secrets[0])?;
        check_secret(&hop.bridge_secrets[1])?;
    }

    let mut relays = Vec::with_capacity(s.hops.len().saturating_add(1));
    let mut bridges = Vec::with_capacity(s.hops.len());
    for i in 0..=s.hops.len() {
        let (node, vni, generation) = if i == 0 {
            (&s.relay.node_ref, s.vni, s.generation)
        } else {
            let prev = &s.hops[i - 1];
            (&prev.relay.node_ref, prev.vni, prev.generation)
        };
        let left = if i == 0 {
            &s.members[0].bind_secret
        } else {
            &s.hops[i - 1].bridge_secrets[1]
        };
        let right = if i == s.hops.len() {
            &s.members[1].bind_secret
        } else {
            &s.hops[i].bridge_secrets[0]
        };
        let members = [left, right]
            .into_iter()
            .enumerate()
            .map(|(j, secret)| RelayMemberWire {
                wg_public_key: s.members[j].wg_public_key.clone(),
                bind_secret: secret.clone(),
            })
            .collect();
        relays.push((
            node.clone(),
            ServerMsg::OverlayRelayServe {
                vni,
                generation,
                members,
                bind_secs: limits::BIND_SECS,
                idle_secs: limits::IDLE_SECS,
                max_lifetime_secs: remaining,
            },
        ));
    }
    for (i, hop) in s.hops.iter().enumerate() {
        let (source, source_agent, local_vni, local_generation) = if i == 0 {
            (&s.relay.node_ref, s.relay_agent_id, s.vni, s.generation)
        } else {
            let prev: &LineLeg = &s.hops[i - 1];
            (
                &prev.relay.node_ref,
                prev.relay_agent_id,
                prev.vni,
                prev.generation,
            )
        };
        bridges.push((
            source.clone(),
            ServerMsg::OverlayRelayBridgeServe {
                bridge: RelayBridgeWire {
                    trial_id: hop.bridge_id,
                    generation: local_generation,
                    source_agent_id: source_agent,
                    target_agent_id: hop.relay_agent_id,
                    local_vni,
                    local_generation,
                    local_bind_secret: hop.bridge_secrets[0].clone(),
                    remote_endpoint: hop.private_endpoint.clone(),
                    remote_vni: hop.vni,
                    remote_generation: hop.generation,
                    remote_bind_secret: hop.bridge_secrets[1].clone(),
                    max_lifetime_secs: remaining,
                },
            },
        ));
    }
    Ok(Delivery { relays, bridges })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org_relay::{SessionMember, SessionParty};
    use std::time::Duration;

    fn secret(n: u64) -> String {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        BASE64.encode(bytes)
    }
    fn agent() -> (SessionParty, ObjectId) {
        let id = ObjectId::new();
        (
            SessionParty {
                node_id: ObjectId::new(),
                node_ref: NodeRef::Agent { agent_id: id },
            },
            id,
        )
    }
    fn fixture(count: usize) -> OrgRelaySession {
        assert!(count >= 1);
        let (relay, relay_agent_id) = agent();
        let members = [1u64, 2].map(|n| {
            let (party, _) = agent();
            SessionMember {
                party,
                wg_public_key: secret(1000 + n),
                bind_secret: secret(n),
            }
        });
        let hops = (1..count)
            .map(|i| {
                let (relay, relay_agent_id) = agent();
                LineLeg {
                    relay,
                    relay_agent_id,
                    vni: i as u32 + 1,
                    generation: i as u64 + 10,
                    endpoints: vec!["8.8.8.8:3478".into()],
                    private_endpoint: "10.0.0.1:3478".into(),
                    requires_cross_border_approval: false,
                    bridge_id: ObjectId::new(),
                    bridge_secrets: [secret(2 * i as u64 + 1), secret(2 * i as u64 + 2)],
                }
            })
            .collect();
        OrgRelaySession {
            tenant_id: ObjectId::new(),
            pair_key: "test".into(),
            vni: 1,
            generation: 9,
            relay,
            relay_agent_id,
            implicit: false,
            members,
            endpoints: vec!["8.8.8.8:3478".into()],
            expires_at: Instant::now() + Duration::from_secs(300),
            bind_by: Instant::now() + Duration::from_secs(30),
            hops,
        }
    }

    #[test]
    fn builds_one_two_three_and_many_relay_slots_and_bridges_in_order() {
        for n in [1, 2, 3, 16, 80] {
            let s = fixture(n);
            let d = build(&s, Instant::now()).unwrap();
            assert_eq!(d.relays.len(), n);
            assert_eq!(d.bridges.len(), n - 1);
            for (i, (dest, msg)) in d.relays.iter().enumerate() {
                let (expected_node, expected_vni, expected_gen) = if i == 0 {
                    (&s.relay.node_ref, s.vni, s.generation)
                } else {
                    let h = &s.hops[i - 1];
                    (&h.relay.node_ref, h.vni, h.generation)
                };
                assert_eq!(dest, expected_node);
                let ServerMsg::OverlayRelayServe {
                    vni,
                    generation,
                    members,
                    ..
                } = msg
                else {
                    panic!("expected serve")
                };
                assert_eq!((*vni, *generation), (expected_vni, expected_gen));
                assert_eq!(members.len(), 2);
                assert_eq!(members[0].wg_public_key, s.members[0].wg_public_key);
                assert_eq!(members[1].wg_public_key, s.members[1].wg_public_key);
                let left = if i == 0 {
                    &s.members[0].bind_secret
                } else {
                    &s.hops[i - 1].bridge_secrets[1]
                };
                let right = if i == n - 1 {
                    &s.members[1].bind_secret
                } else {
                    &s.hops[i].bridge_secrets[0]
                };
                assert_eq!(
                    (&members[0].bind_secret, &members[1].bind_secret),
                    (left, right)
                );
            }
            for (i, (dest, msg)) in d.bridges.iter().enumerate() {
                let h = &s.hops[i];
                let (source, agent, vni, generation) = if i == 0 {
                    (&s.relay.node_ref, s.relay_agent_id, s.vni, s.generation)
                } else {
                    let previous = &s.hops[i - 1];
                    (
                        &previous.relay.node_ref,
                        previous.relay_agent_id,
                        previous.vni,
                        previous.generation,
                    )
                };
                assert_eq!(dest, source);
                let ServerMsg::OverlayRelayBridgeServe { bridge } = msg else {
                    panic!("expected bridge")
                };
                assert_eq!(
                    (bridge.source_agent_id, bridge.target_agent_id),
                    (agent, h.relay_agent_id)
                );
                assert_eq!(
                    (bridge.local_vni, bridge.local_generation, bridge.generation),
                    (vni, generation, generation)
                );
                assert_eq!(
                    (bridge.remote_vni, bridge.remote_generation, bridge.trial_id),
                    (h.vni, h.generation, h.bridge_id)
                );
                assert_eq!(
                    (&bridge.local_bind_secret, &bridge.remote_bind_secret),
                    (&h.bridge_secrets[0], &h.bridge_secrets[1])
                );
                assert_eq!(bridge.remote_endpoint, h.private_endpoint);
            }
        }
    }

    #[test]
    fn rejects_invalid_complete_shape_before_returning_any_messages() {
        let now = Instant::now();
        let s = fixture(3);
        let mut bad = s.clone();
        bad.hops[1].relay.node_id = bad.relay.node_id;
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::DuplicateRelay)
        ));
        let mut bad = s.clone();
        bad.hops[0].relay.node_ref = bad.relay.node_ref.clone();
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::InvalidIdentity)
        ));
        let mut bad = s.clone();
        bad.hops[0].vni = limits::STUN_COOKIE_VNI;
        assert!(matches!(build(&bad, now), Err(DeliveryError::InvalidVni)));
        let mut bad = s.clone();
        bad.hops[0].private_endpoint = "127.0.0.1:3478".into();
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::InvalidEndpoint)
        ));
        let mut bad = s.clone();
        bad.hops[1].bridge_id = bad.hops[0].bridge_id;
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::DuplicateBridge)
        ));
        let mut bad = s.clone();
        bad.hops[0].bridge_secrets[0] = bad.members[0].bind_secret.clone();
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::DuplicateSecret)
        ));
        let mut bad = s.clone();
        bad.members[0].bind_secret = "invalid".into();
        assert!(matches!(
            build(&bad, now),
            Err(DeliveryError::InvalidSecret)
        ));
        let mut bad = s.clone();
        bad.bind_by = now;
        assert!(matches!(build(&bad, now), Err(DeliveryError::Expired)));
        let mut bad = s;
        bad.expires_at = now;
        assert!(matches!(build(&bad, now), Err(DeliveryError::Expired)));
    }
}
