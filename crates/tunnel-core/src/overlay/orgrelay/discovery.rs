// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Bounded discovery METADATA only. No sockets, secrets, sessions, or carrier decisions.
use crate::overlay::runtime::ControlTx;
use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{
    ClientMsg, NetmapPeer, OrgRelayCandidateWire, OrgRelayDiscoveryCursorWire,
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAX_PAIRS: usize = 64;
const MAX_TTL: Duration = Duration::from_secs(30);
const GLOBAL_GAP: Duration = Duration::from_secs(11); // <=6/min, whole runtime
const FAILURE_COOLDOWN: Duration = Duration::from_secs(120);
const PAIR_GAP: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct Discovery {
    pairs: HashMap<ObjectId, Pair>,
    next_request: Option<Instant>,
    serial: u64,
    // Fair traversal survives bounded-cache eviction and metadata invalidation.
    cursor: Option<ObjectId>,
}
#[derive(Clone, PartialEq, Eq)]
struct PathKey(ObjectId, Option<ObjectId>, Vec<String>);
fn path_key(c: &OrgRelayCandidateWire) -> PathKey {
    PathKey(c.relay_node_id, c.exit_relay_node_id, c.endpoints.clone())
}
struct Pair {
    identity: (String, String),
    asked: Instant,
    pending: Option<(u64, Instant)>,
    cached: Option<(Instant, Vec<OrgRelayCandidateWire>)>,
    attempted: Option<PathKey>,
    failed: Vec<(PathKey, Instant)>,
    page_cursor: Option<OrgRelayDiscoveryCursorWire>,
    page_after: Option<OrgRelayDiscoveryCursorWire>,
}
fn eligible(p: &NetmapPeer) -> bool {
    p.reachable && p.supports_org_relay && crate::overlay::decode_public(&p.wg_public_key).is_some()
}
fn identity(p: &NetmapPeer) -> (String, String) {
    (p.wg_public_key.clone(), p.overlay_ip.clone())
}
impl Discovery {
    pub(crate) fn candidate_for(
        &self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        peer: ObjectId,
        now: Instant,
    ) -> Option<OrgRelayCandidateWire> {
        let current = peers.get(&peer)?;
        let pair = self.pairs.get(&peer)?;
        if !eligible(current) || identity(current) != pair.identity {
            return None;
        }
        let (until, candidates) = pair.cached.as_ref()?;
        if now >= *until {
            return None;
        }
        if pair.page_cursor.is_some()
            && let Some(page_after) = pair.page_after
        {
            // Discovery display order is a preference, not attempt fairness.
            // Continue after the ACTUAL queued attempt. Moving only by the last
            // returned page can permanently starve paths under short cooldowns.
            let key = pair.attempted.as_ref().map_or(
                (page_after.relay_node_id, page_after.exit_relay_node_id),
                |k| (k.0, k.1),
            );
            return candidates
                .iter()
                .filter(|c| {
                    !pair.failed.iter().any(|(k, at)| {
                        *k == path_key(c) && now.saturating_duration_since(*at) < FAILURE_COOLDOWN
                    })
                })
                .min_by_key(|c| {
                    let k = (c.relay_node_id, c.exit_relay_node_id);
                    (k <= key, k)
                })
                .cloned();
        }
        let after = pair
            .attempted
            .as_ref()
            .and_then(|key| candidates.iter().position(|c| path_key(c) == *key))
            .map_or(0, |i| (i + 1) % candidates.len());
        (0..candidates.len())
            .map(|n| &candidates[(after + n) % candidates.len()])
            .find(|c| {
                !pair.failed.iter().any(|(key, at)| {
                    *key == path_key(c) && now.saturating_duration_since(*at) < FAILURE_COOLDOWN
                })
            })
            .cloned()
    }
    /// Advance only after a real bounded request entered ControlTx. Successful
    /// relay use suppresses further trials; failed/denied attempts cannot keep
    /// choosing the first hint forever. This is coverage, not a quality score.
    pub(crate) fn note_attempt(
        &mut self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        peer: ObjectId,
        candidate: &OrgRelayCandidateWire,
        now: Instant,
    ) {
        let Some(current) = peers.get(&peer) else {
            return;
        };
        let Some(pair) = self.pairs.get_mut(&peer) else {
            return;
        };
        if !eligible(current) || identity(current) != pair.identity {
            return;
        }
        if pair.cached.as_ref().is_some_and(|(until, cs)| {
            now < *until && cs.iter().any(|c| path_key(c) == path_key(candidate))
        }) {
            pair.attempted = Some(path_key(candidate));
        }
    }
    /// Only the local requester's exact correlated precommit failure feeds this
    /// bounded cooldown. A removed/rekeyed identity never poisons its successor.
    pub(crate) fn note_failure(
        &mut self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        peer: ObjectId,
        expected: &(String, String),
        candidate: &OrgRelayCandidateWire,
        now: Instant,
    ) {
        let Some(current) = peers.get(&peer) else {
            return;
        };
        let Some(pair) = self.pairs.get_mut(&peer) else {
            return;
        };
        if !eligible(current) || identity(current) != *expected || pair.identity != *expected {
            return;
        }
        pair.failed.retain(|(k, at)| {
            *k != path_key(candidate) && now.saturating_duration_since(*at) < FAILURE_COOLDOWN
        });
        if pair.failed.len() >= 3 {
            pair.failed.remove(0);
        }
        pair.failed.push((path_key(candidate), now));
    }
    /// Keep rate-limit memory, but discard all evidence and pending correlations.
    /// Used on reattach/netmap edits/revocation, including a remove+re-add in one delta.
    pub(crate) fn invalidate(&mut self) {
        for p in self.pairs.values_mut() {
            p.pending = None;
            p.cached = None;
            p.page_cursor = None;
            p.page_after = None;
        }
    }
    /// Every delta invalidates authorization hints and pending correlations.
    /// Preserve only non-authorizing traversal progress for the same eligible
    /// key/IP; an explicit remove+re-add must not inherit its old position.
    pub(crate) fn reconcile_delta(
        &mut self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        removed: &[ObjectId],
    ) {
        self.pairs.retain(|id, pair| {
            !removed.contains(id)
                && peers
                    .get(id)
                    .is_some_and(|peer| eligible(peer) && identity(peer) == pair.identity)
        });
        for pair in self.pairs.values_mut() {
            pair.pending = None;
            pair.cached = None;
        }
    }
    fn prune(&mut self, peers: &HashMap<ObjectId, NetmapPeer>, now: Instant) {
        self.pairs.retain(|id, p| {
            peers
                .get(id)
                .is_some_and(|n| eligible(n) && identity(n) == p.identity)
        });
        for p in self.pairs.values_mut() {
            if p.pending.is_some_and(|(_, until)| now >= until) {
                p.pending = None;
            }
            if p.cached.as_ref().is_some_and(|(until, _)| now >= *until) {
                p.cached = None;
            }
        }
    }
    /// Called by the real runtime tick; independent of the incumbent P2P/DERP tier.
    /// A full/closed control queue cannot stall the data/control loop indefinitely.
    pub(crate) async fn request(
        &mut self,
        enabled: bool,
        server_supported: bool,
        peers: &HashMap<ObjectId, NetmapPeer>,
        out: &ControlTx,
        now: Instant,
    ) {
        self.prune(peers, now);
        if !enabled || !server_supported {
            self.invalidate();
            return;
        }
        if self.next_request.is_some_and(|next| now < next) {
            return;
        }
        let choice = peers
            .iter()
            .filter(|(_, p)| eligible(p))
            .filter(|(id, _)| {
                self.pairs
                    .get(*id)
                    .is_none_or(|p| now.saturating_duration_since(p.asked) >= PAIR_GAP)
            })
            // Prefer the next eligible ID after the last attempt; wrap once.
            // Cache absence is NOT priority: eviction must never starve high IDs.
            .min_by_key(|(id, _)| (self.cursor.is_some_and(|cursor| **id <= cursor), **id))
            .map(|(id, p)| (*id, identity(p)));
        let Some((id, identity)) = choice else {
            return;
        };
        // Bound state without starving large netmaps: evict least recently requested.
        if !self.pairs.contains_key(&id) && self.pairs.len() >= MAX_PAIRS {
            if let Some(oldest) = self
                .pairs
                .iter()
                .min_by_key(|(id, p)| (p.asked, **id))
                .map(|(id, _)| *id)
            {
                self.pairs.remove(&oldest);
            }
        }
        // No wrap means an ancient response can never collide with a new request.
        let Some(request_id) = self.serial.checked_add(1) else {
            return;
        };
        self.serial = request_id;
        self.cursor = Some(id);
        self.next_request = Some(now + GLOBAL_GAP);
        let history = self
            .pairs
            .get(&id)
            .filter(|p| p.identity == identity)
            .map(|p| (p.attempted.clone(), p.failed.clone(), p.page_cursor))
            .unwrap_or_default();
        let page_after = history.2.map(|cursor| {
            history
                .0
                .as_ref()
                .map_or(cursor, |k| OrgRelayDiscoveryCursorWire {
                    relay_node_id: k.0,
                    exit_relay_node_id: k.1,
                })
        });
        self.pairs.insert(
            id,
            Pair {
                identity,
                asked: now,
                pending: Some((request_id, now + MAX_TTL)),
                cached: None,
                attempted: history.0,
                failed: history.1,
                page_cursor: history.2,
                page_after,
            },
        );
        let sent = tokio::time::timeout(
            Duration::from_millis(10),
            out.send(ClientMsg::OverlayOrgRelayDiscover {
                peer_node_id: id,
                request_id,
                cursor: page_after,
            }),
        )
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            self.pairs.get_mut(&id).unwrap().pending = None;
        }
    }
    /// Only an outstanding, unexpired request for the current key/IP may populate metadata.
    /// Returned count is diagnostic, not path eligibility or an authorization grant.
    #[cfg(test)]
    pub(crate) fn receive(
        &mut self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        peer: ObjectId,
        request_id: u64,
        candidates: Vec<OrgRelayCandidateWire>,
        ttl_secs: u32,
        now: Instant,
    ) -> usize {
        self.receive_page(peers, peer, request_id, candidates, ttl_secs, None, now)
    }
    pub(crate) fn receive_page(
        &mut self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        peer: ObjectId,
        request_id: u64,
        candidates: Vec<OrgRelayCandidateWire>,
        ttl_secs: u32,
        next_cursor: Option<OrgRelayDiscoveryCursorWire>,
        now: Instant,
    ) -> usize {
        self.prune(peers, now);
        let Some(p) = self.pairs.get_mut(&peer) else {
            return 0;
        };
        let Some((expected, deadline)) = p.pending else {
            return 0;
        };
        if request_id != expected || now >= deadline {
            return 0;
        }
        p.pending = None;
        p.cached = None;
        p.page_cursor = None;
        if ttl_secs == 0 || candidates.is_empty() {
            return 0;
        }
        // Reject oversize/malformed payloads rather than silently treating partial data as trusted.
        if next_cursor.is_some_and(|next| {
            !candidates.iter().any(|c| {
                c.relay_node_id == next.relay_node_id
                    && c.exit_relay_node_id == next.exit_relay_node_id
            })
        }) || candidates.len() > 3
            || candidates.iter().enumerate().any(|(index, c)| {
                c.exit_relay_node_id == Some(c.relay_node_id)
                    || candidates[..index].iter().any(|p| {
                        p.relay_node_id == c.relay_node_id
                            && p.exit_relay_node_id == c.exit_relay_node_id
                    })
                    || c.endpoints.is_empty()
                    || c.endpoints.len() > 4
                    || c.endpoints.iter().any(|e| {
                        e.len() > 80
                            || e.parse::<std::net::SocketAddr>().is_err()
                            || e.parse::<std::net::SocketAddr>()
                                .is_ok_and(|s| s.port() == 0)
                    })
            })
        {
            return 0;
        }
        let expires = (now + Duration::from_secs(u64::from(ttl_secs)).min(MAX_TTL)).min(deadline);
        let count = candidates.len();
        p.cached = Some((expires, candidates));
        p.page_cursor = next_cursor;
        if next_cursor.is_none() {
            p.page_after = None;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::WgKeypair;
    fn peer() -> NetmapPeer {
        serde_json::from_value(serde_json::json!({"node_id":ObjectId::new().to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":WgKeypair::generate().public_base64(),"reachable":true,"supports_org_relay":true})).unwrap()
    }
    fn candidate() -> OrgRelayCandidateWire {
        OrgRelayCandidateWire {
            exit_relay_node_id: None,
            relay_node_id: ObjectId::new(),
            endpoints: vec!["8.8.8.8:3478".into()],
        }
    }
    async fn asked(
        d: &mut Discovery,
        peers: &HashMap<ObjectId, NetmapPeer>,
        now: Instant,
    ) -> (ObjectId, u64) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        d.request(true, true, peers, &ControlTx::new(tx), now).await;
        match rx.try_recv().unwrap() {
            ClientMsg::OverlayOrgRelayDiscover {
                peer_node_id,
                request_id,
                ..
            } => (peer_node_id, request_id),
            other => panic!("unexpected side effect {other:?}"),
        }
    }
    #[tokio::test]
    async fn org_relay_discovery_real_request_call_is_opt_in_metadata_only_and_rate_bounded() {
        let p = peer();
        let peers = HashMap::from([(p.node_id, p)]);
        let mut d = Discovery::default();
        let now = Instant::now();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let out = ControlTx::new(tx);
        d.request(false, true, &peers, &out, now).await;
        assert!(rx.try_recv().is_err());
        d.request(true, true, &peers, &out, now).await;
        assert!(matches!(
            rx.try_recv(),
            Ok(ClientMsg::OverlayOrgRelayDiscover { .. })
        ));
        d.request(true, true, &peers, &out, now + Duration::from_secs(11))
            .await;
        assert!(rx.try_recv().is_err());
        d.request(true, true, &peers, &out, now + PAIR_GAP).await;
        assert!(matches!(
            rx.try_recv(),
            Ok(ClientMsg::OverlayOrgRelayDiscover { .. })
        ));
        assert!(rx.try_recv().is_err()); // no relay_request/session/TURN side effects
    }
    #[tokio::test]
    async fn org_relay_multi_onehop_failed_first_keeps_alternates_and_cache_bounds() {
        let p = peer();
        let id = p.node_id;
        let peers = HashMap::from([(id, p.clone())]);
        let now = Instant::now();
        let paths: Vec<_> = (0..3).map(|_| candidate()).collect();
        let mut d = Discovery::default();
        let (_, r) = asked(&mut d, &peers, now).await;
        assert_eq!(d.receive(&peers, id, r, paths.clone(), 30, now), 3);
        assert!(path_key(&d.candidate_for(&peers, id, now).unwrap()) == path_key(&paths[0]));
        for c in &paths {
            assert!(path_key(&d.candidate_for(&peers, id, now).unwrap()) == path_key(c));
            d.note_attempt(&peers, id, c, now);
            d.note_failure(&peers, id, &identity(&p), c, now);
        }
        assert!(
            d.candidate_for(&peers, id, now).is_none(),
            "no forced relay when all failed"
        );
        assert_eq!(d.pairs[&id].cached.as_ref().unwrap().1.len(), 3);
        assert!(d.candidate_for(&peers, id, now + MAX_TTL).is_none());
    }

    #[tokio::test]
    async fn org_relay_multi_onehop_rejects_duplicate_overlimit_empty_and_malformed_hints() {
        let p = peer();
        let id = p.node_id;
        let peers = HashMap::from([(id, p)]);
        let now = Instant::now();
        let c = candidate();
        let mut no_endpoints = candidate();
        no_endpoints.endpoints.clear();
        let mut too_many_endpoints = candidate();
        too_many_endpoints.endpoints = vec!["8.8.8.8:3478".into(); 5];
        let mut zero_port = candidate();
        zero_port.endpoints = vec!["8.8.8.8:0".into()];
        let mut malformed = candidate();
        malformed.endpoints = vec!["not-a-socket-address".into()];
        let mut self_exit = candidate();
        self_exit.exit_relay_node_id = Some(self_exit.relay_node_id);
        for paths in [
            vec![],
            vec![c.clone(), c],
            (0..4).map(|_| candidate()).collect(),
            vec![candidate(), no_endpoints],
            vec![candidate(), too_many_endpoints],
            vec![candidate(), zero_port],
            vec![candidate(), malformed],
            vec![candidate(), self_exit],
        ] {
            let mut d = Discovery::default();
            let (_, r) = asked(&mut d, &peers, now).await;
            assert_eq!(d.receive(&peers, id, r, paths, 30, now), 0);
            assert!(d.pairs[&id].cached.is_none());
            assert!(d.candidate_for(&peers, id, now).is_none());
        }
    }

    #[tokio::test]
    async fn org_relay_discovery_response_cache_requires_request_id_and_expires_without_extension()
    {
        let p = peer();
        let peers = HashMap::from([(p.node_id, p)]);
        let mut d = Discovery::default();
        let now = Instant::now();
        let (id, r) = asked(&mut d, &peers, now).await;
        assert_eq!(d.receive(&peers, id, r + 1, vec![candidate()], 30, now), 0);
        assert_eq!(
            d.receive(
                &peers,
                id,
                r,
                vec![candidate()],
                u32::MAX,
                now + Duration::from_secs(20)
            ),
            1
        );
        assert_eq!(d.pairs[&id].cached.as_ref().unwrap().0, now + MAX_TTL);
        d.prune(&peers, now + MAX_TTL);
        assert!(d.pairs[&id].cached.is_none());
        assert_eq!(
            d.receive(&peers, id, r, vec![candidate()], 30, now + MAX_TTL),
            0
        );
    }
    #[tokio::test]
    async fn org_relay_discovery_removal_rekey_revocation_and_empty_reply_discard_metadata() {
        let p = peer();
        let id = p.node_id;
        let mut peers = HashMap::from([(id, p)]);
        let mut d = Discovery::default();
        let now = Instant::now();
        let (_, r) = asked(&mut d, &peers, now).await;
        d.invalidate();
        assert_eq!(d.receive(&peers, id, r, vec![candidate()], 30, now), 0);
        let (_, r) = asked(&mut d, &peers, now + PAIR_GAP).await;
        peers.get_mut(&id).unwrap().wg_public_key = WgKeypair::generate().public_base64();
        assert_eq!(
            d.receive(&peers, id, r, vec![candidate()], 30, now + PAIR_GAP),
            0
        );
        let (_, r) = asked(&mut d, &peers, now + PAIR_GAP * 2).await;
        assert_eq!(d.receive(&peers, id, r, vec![], 0, now + PAIR_GAP * 2), 0);
        assert!(d.pairs[&id].cached.is_none());
        peers.clear();
        d.prune(&peers, now + PAIR_GAP * 2);
        assert!(d.pairs.is_empty());
    }
    #[tokio::test]
    async fn org_relay_discovery_cache_and_unanswered_requests_are_bounded() {
        let peers: HashMap<_, _> = (0..100)
            .map(|_| {
                let p = peer();
                (p.node_id, p)
            })
            .collect();
        let now = Instant::now();
        let mut d = Discovery::default();
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let (id, _) = asked(&mut d, &peers, now + GLOBAL_GAP * i).await;
            assert!(
                seen.insert(id),
                "round robin revisited an ID before covering the netmap"
            );
            assert!(d.pairs.len() <= MAX_PAIRS);
        }
        assert_eq!(
            seen.len(),
            peers.len(),
            "100 requests must cover all 100 peers despite a 64-pair cache"
        );
        assert!(peers.keys().all(|id| seen.contains(id)));
        assert!(d.pairs.values().filter(|p| p.pending.is_some()).count() <= 3);
    }
    #[tokio::test]
    async fn org_relay_discovery_legacy_full_netmap_does_not_request() {
        use roomler_ai_remote_control::signaling::ServerMsg;
        let msg: ServerMsg = serde_json::from_value(serde_json::json!({
            "t":"rc:overlay.netmap", "self_ip":"100.64.0.1",
            "network":{"cidr":"100.64.0.0/10","mtu":1280}, "peers":[]
        }))
        .unwrap();
        let ServerMsg::OverlayNetmap {
            org_relay_discovery,
            ..
        } = msg
        else {
            panic!("wrong variant")
        };
        assert!(!org_relay_discovery);
        let p = peer();
        let peers = HashMap::from([(p.node_id, p)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut d = Discovery::default();
        d.request(
            true,
            org_relay_discovery,
            &peers,
            &ControlTx::new(tx),
            Instant::now(),
        )
        .await;
        assert!(rx.try_recv().is_err());
        assert!(d.pairs.is_empty());
    }

    #[tokio::test]
    async fn org_relay_discovery_capability_reset_on_reattach_stops_requests_and_old_replies() {
        let p = peer();
        let peers = HashMap::from([(p.node_id, p)]);
        let now = Instant::now();
        let mut d = Discovery::default();
        let (id, request_id) = asked(&mut d, &peers, now).await;
        // The runtime Reattach arm performs exactly these two actions before rejoining.
        d.invalidate();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        d.request(true, false, &peers, &ControlTx::new(tx), now + PAIR_GAP)
            .await;
        assert!(rx.try_recv().is_err());
        assert_eq!(
            d.receive(&peers, id, request_id, vec![candidate()], 30, now),
            0
        );
    }
}

#[cfg(test)]
mod candidate_coverage_tests {
    use super::*;
    use crate::overlay::WgKeypair;
    #[tokio::test]
    async fn path_trial_three_candidate_coverage_failed_first_refresh_and_identity_fence() {
        let key = WgKeypair::generate();
        let id = ObjectId::new();
        let now = Instant::now();
        let p:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":id.to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":key.public_base64(),"reachable":true,"supports_org_relay":true})).unwrap();
        let mut peers = HashMap::from([(id, p.clone())]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let tx = ControlTx::new(tx);
        let mut d = Discovery::default();
        let ingress = ObjectId::new();
        let paths: Vec<_> = [Some(ObjectId::new()), Some(ObjectId::new()), None]
            .into_iter()
            .map(|exit| OrgRelayCandidateWire {
                relay_node_id: ingress,
                exit_relay_node_id: exit,
                endpoints: vec!["8.8.8.8:3478".into()],
            })
            .collect();
        d.request(true, true, &peers, &tx, now).await;
        let ClientMsg::OverlayOrgRelayDiscover { request_id, .. } = rx.recv().await.unwrap() else {
            panic!("real discovery request")
        };
        assert_eq!(d.receive(&peers, id, request_id, paths.clone(), 30, now), 3);
        let first = d.candidate_for(&peers, id, now).unwrap();
        assert!(path_key(&first) == path_key(&paths[0]));
        // Looking does not consume another peer's turn or a failed queue write.
        assert!(path_key(&d.candidate_for(&peers, id, now).unwrap()) == path_key(&first));
        d.note_attempt(&peers, id, &first, now);
        d.note_failure(&peers, id, &identity(&p), &first, now);
        let second = d.candidate_for(&peers, id, now).unwrap();
        assert!(path_key(&second) == path_key(&paths[1]));
        d.note_attempt(&peers, id, &second, now);
        let third = d.candidate_for(&peers, id, now).unwrap();
        assert!(path_key(&third) == path_key(&paths[2]));
        d.note_attempt(&peers, id, &third, now);
        assert!(
            path_key(&d.candidate_for(&peers, id, now).unwrap()) == path_key(&paths[1]),
            "failed first stays cooled while both alternate paths remain selectable"
        );
        // A genuinely new metadata fetch keeps the coverage cursor/failure but
        // does not extend an old cache's lifetime or create permission.
        let fresh = now + Duration::from_secs(61);
        d.request(true, true, &peers, &tx, fresh).await;
        let ClientMsg::OverlayOrgRelayDiscover { request_id, .. } = rx.recv().await.unwrap() else {
            panic!("refresh")
        };
        assert_eq!(
            d.receive(&peers, id, request_id, paths.clone(), 30, fresh),
            3
        );
        assert!(path_key(&d.candidate_for(&peers, id, fresh).unwrap()) == path_key(&paths[1]));
        for c in &paths {
            d.note_failure(&peers, id, &identity(&p), c, fresh);
        }
        assert!(
            d.candidate_for(&peers, id, fresh).is_none(),
            "all failed means retain P2P, not force a relay"
        );
        peers.get_mut(&id).unwrap().wg_public_key = WgKeypair::generate().public_base64();
        d.note_failure(&peers, id, &identity(&p), &paths[0], fresh);
        assert!(d.candidate_for(&peers, id, fresh).is_none());
        d.prune(&peers, fresh);
        assert!(
            !d.pairs.contains_key(&id),
            "rekey removes old cursor and negative evidence"
        );
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use crate::overlay::WgKeypair;
    #[tokio::test]
    async fn discovery_cursor_survives_ttl_but_not_identity_reset_or_bad_reply() {
        let peer:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":ObjectId::new().to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":WgKeypair::generate().public_base64(),"reachable":true,"supports_org_relay":true})).unwrap();
        let id = peer.node_id;
        let mut peers = HashMap::from([(id, peer)]);
        let candidate = OrgRelayCandidateWire {
            relay_node_id: ObjectId::new(),
            exit_relay_node_id: None,
            endpoints: vec!["8.8.8.8:3478".into()],
        };
        let cursor = OrgRelayDiscoveryCursorWire {
            relay_node_id: candidate.relay_node_id,
            exit_relay_node_id: None,
        };
        let mut d = Discovery::default();
        let now = Instant::now();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let out = ControlTx::new(tx);
        d.request(true, true, &peers, &out, now).await;
        let ClientMsg::OverlayOrgRelayDiscover {
            request_id,
            cursor: c,
            ..
        } = rx.recv().await.unwrap()
        else {
            panic!()
        };
        assert!(c.is_none());
        assert_eq!(
            d.receive_page(
                &peers,
                id,
                request_id + 1,
                vec![candidate.clone()],
                30,
                Some(cursor),
                now
            ),
            0
        );
        assert_eq!(
            d.receive_page(
                &peers,
                id,
                request_id,
                vec![candidate.clone()],
                30,
                Some(cursor),
                now
            ),
            1
        );
        d.request(true, true, &peers, &out, now + Duration::from_secs(59))
            .await;
        assert!(rx.try_recv().is_err());
        d.request(true, true, &peers, &out, now + Duration::from_secs(60))
            .await;
        let ClientMsg::OverlayOrgRelayDiscover {
            request_id,
            cursor: c,
            ..
        } = rx.recv().await.unwrap()
        else {
            panic!()
        };
        assert_eq!(c, Some(cursor));
        // A cursor not present in its own page is malformed, not a grant/position update.
        let bad = OrgRelayDiscoveryCursorWire {
            relay_node_id: ObjectId::new(),
            exit_relay_node_id: None,
        };
        assert_eq!(
            d.receive_page(
                &peers,
                id,
                request_id,
                vec![candidate.clone()],
                30,
                Some(bad),
                now + Duration::from_secs(60)
            ),
            0
        );
        assert!(d.pairs[&id].page_cursor.is_none());
        d.request(true, true, &peers, &out, now + Duration::from_secs(120))
            .await;
        let ClientMsg::OverlayOrgRelayDiscover {
            request_id,
            cursor: c,
            ..
        } = rx.recv().await.unwrap()
        else {
            panic!()
        };
        assert!(c.is_none());
        d.receive_page(
            &peers,
            id,
            request_id,
            vec![candidate.clone()],
            30,
            Some(cursor),
            now + Duration::from_secs(120),
        );
        d.invalidate();
        assert!(d.pairs[&id].page_cursor.is_none());
        peers.get_mut(&id).unwrap().wg_public_key = WgKeypair::generate().public_base64();
        d.request(true, true, &peers, &out, now + Duration::from_secs(180))
            .await;
        let ClientMsg::OverlayOrgRelayDiscover { cursor: c, .. } = rx.recv().await.unwrap() else {
            panic!()
        };
        assert!(c.is_none());
    }
}

#[cfg(test)]
mod traversal_attempt_tests {
    use super::*;
    use crate::overlay::WgKeypair;
    fn hint(n: u8) -> OrgRelayCandidateWire {
        OrgRelayCandidateWire {
            relay_node_id: ObjectId::from_bytes([n; 12]),
            exit_relay_node_id: None,
            endpoints: vec!["8.8.8.8:3478".into()],
        }
    }
    fn response_page(
        all: &[OrgRelayCandidateWire],
        cursor: Option<OrgRelayDiscoveryCursorWire>,
    ) -> (Vec<OrgRelayCandidateWire>, OrgRelayDiscoveryCursorWire) {
        let mut selected = if let Some(cursor) = cursor {
            let key = (cursor.relay_node_id, cursor.exit_relay_node_id);
            let mut ring = all.to_vec();
            ring.sort_by_key(|c| {
                let k = (c.relay_node_id, c.exit_relay_node_id);
                (k <= key, k)
            });
            ring.truncate(3);
            ring
        } else {
            all[..3].to_vec()
        };
        let last = if cursor.is_none() {
            selected
                .iter()
                .max_by_key(|c| (c.relay_node_id, c.exit_relay_node_id))
                .unwrap()
        } else {
            selected.last().unwrap()
        };
        let next = OrgRelayDiscoveryCursorWire {
            relay_node_id: last.relay_node_id,
            exit_relay_node_id: last.exit_relay_node_id,
        };
        selected.sort_by_key(|c| all.iter().position(|p| p == c).unwrap());
        (selected, next)
    }
    #[tokio::test]
    async fn discovery_cursor_actual_attempt_coverage_prevents_hidden_healthy_path_starvation() {
        // This exact planner order indefinitely hid healthy key2 with metadata
        // cursor alone despite covering it repeatedly. Exercise the REAL cache,
        // outbound requests, candidate selection, attempted and failure APIs.
        let all: Vec<_> = [3, 1, 5, 4, 2].into_iter().map(hint).collect();
        let healthy = hint(2);
        let peer:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":ObjectId::new().to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":WgKeypair::generate().public_base64(),"reachable":true,"supports_org_relay":true})).unwrap();
        let id = peer.node_id;
        let peers = HashMap::from([(id, peer)]);
        let ident = identity(&peers[&id]);
        let mut d = Discovery::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let out = ControlTx::new(tx);
        let start = Instant::now();
        let mut selected = Vec::new();
        for step in 0..6 {
            let now = start + Duration::from_secs(step * 60);
            d.request(true, true, &peers, &out, now).await;
            let ClientMsg::OverlayOrgRelayDiscover {
                request_id, cursor, ..
            } = rx.recv().await.unwrap()
            else {
                panic!()
            };
            if let Some(previous) = selected.last() {
                assert_eq!(
                    cursor.map(|c| c.relay_node_id),
                    Some(*previous),
                    "advance by actual successful enqueue, not page end"
                );
            }
            let (page, next) = response_page(&all, cursor);
            assert_eq!(
                d.receive_page(&peers, id, request_id, page, 30, Some(next), now),
                3
            );
            let candidate = d.candidate_for(&peers, id, now).unwrap();
            if selected.is_empty() {
                assert_eq!(candidate, all[0], "initial preferred candidate unchanged");
            }
            // Represent a successfully queued trial exactly as production does.
            d.note_attempt(&peers, id, &candidate, now);
            selected.push(candidate.relay_node_id);
            if candidate == healthy {
                break;
            }
            d.note_failure(&peers, id, &ident, &candidate, now + Duration::from_secs(5));
        }
        assert!(
            selected.contains(&healthy.relay_node_id),
            "normally paced traversal must actually attempt healthy formerly-hidden key2"
        );
        assert!(selected.len() <= 5);
    }
    #[tokio::test]
    async fn discovery_cursor_actual_attempt_coverage_all_five_relay_preferences() {
        fn permute(prefix: Vec<u8>, remaining: Vec<u8>, out: &mut Vec<Vec<u8>>) {
            if remaining.is_empty() {
                out.push(prefix);
                return;
            }
            for i in 0..remaining.len() {
                let mut p = prefix.clone();
                p.push(remaining[i]);
                let mut r = remaining.clone();
                r.remove(i);
                permute(p, r, out);
            }
        }
        let mut orders = Vec::new();
        permute(vec![], vec![1, 2, 3, 4, 5], &mut orders);
        assert_eq!(orders.len(), 120);
        let peer:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":ObjectId::new().to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":WgKeypair::generate().public_base64(),"reachable":true,"supports_org_relay":true})).unwrap();
        let id = peer.node_id;
        let peers = HashMap::from([(id, peer)]);
        let ident = identity(&peers[&id]);
        for order in orders {
            for healthy in 1..=5 {
                let all: Vec<_> = order.iter().copied().map(hint).collect();
                let wanted = hint(healthy);
                let mut d = Discovery::default();
                let (tx, mut rx) = tokio::sync::mpsc::channel(4);
                let out = ControlTx::new(tx);
                let start = Instant::now();
                let mut found = false;
                for step in 0..5 {
                    let now = start + Duration::from_secs(step * 60);
                    d.request(true, true, &peers, &out, now).await;
                    let ClientMsg::OverlayOrgRelayDiscover {
                        request_id, cursor, ..
                    } = rx.recv().await.unwrap()
                    else {
                        panic!()
                    };
                    let (page, next) = response_page(&all, cursor);
                    assert_eq!(
                        d.receive_page(&peers, id, request_id, page, 30, Some(next), now),
                        3
                    );
                    let candidate = d.candidate_for(&peers, id, now).unwrap();
                    d.note_attempt(&peers, id, &candidate, now);
                    if candidate == wanted {
                        found = true;
                        break;
                    }
                    d.note_failure(&peers, id, &ident, &candidate, now + Duration::from_secs(5));
                }
                assert!(
                    found,
                    "planner={order:?} healthy={healthy} must be attempted in five paced cycles"
                );
            }
        }
    }
}

#[cfg(test)]
mod delta_progress_tests {
    use super::*;
    use crate::overlay::WgKeypair;

    fn fixture() -> (
        ObjectId,
        HashMap<ObjectId, NetmapPeer>,
        Vec<OrgRelayCandidateWire>,
    ) {
        let id = ObjectId::new();
        let peer: NetmapPeer = serde_json::from_value(serde_json::json!({
            "node_id":id.to_hex(), "overlay_ip":"100.64.0.2",
            "wg_public_key":WgKeypair::generate().public_base64(),
            "reachable":true, "supports_org_relay":true
        }))
        .unwrap();
        let paths = [1u8, 3, 5, 4, 2]
            .into_iter()
            .map(|n| OrgRelayCandidateWire {
                relay_node_id: ObjectId::from_bytes([n; 12]),
                exit_relay_node_id: None,
                endpoints: vec![format!("8.8.8.{n}:3478")],
            })
            .collect();
        (id, HashMap::from([(id, peer)]), paths)
    }

    async fn request(
        d: &mut Discovery,
        peers: &HashMap<ObjectId, NetmapPeer>,
        now: Instant,
    ) -> (u64, Option<OrgRelayDiscoveryCursorWire>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        d.request(true, true, peers, &ControlTx::new(tx), now).await;
        let ClientMsg::OverlayOrgRelayDiscover {
            request_id, cursor, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("expected actual queued metadata request")
        };
        (request_id, cursor)
    }

    async fn seed(
        d: &mut Discovery,
        id: ObjectId,
        peers: &HashMap<ObjectId, NetmapPeer>,
        paths: &[OrgRelayCandidateWire],
        now: Instant,
    ) -> u64 {
        let (request_id, cursor) = request(d, peers, now).await;
        assert!(cursor.is_none());
        assert_eq!(
            d.receive_page(
                peers,
                id,
                request_id,
                paths[..3].to_vec(),
                30,
                Some(OrgRelayDiscoveryCursorWire {
                    relay_node_id: paths[2].relay_node_id,
                    exit_relay_node_id: None,
                }),
                now
            ),
            3
        );
        let chosen = d.candidate_for(peers, id, now).unwrap();
        assert_eq!(chosen.relay_node_id, paths[0].relay_node_id);
        d.note_attempt(peers, id, &chosen, now);
        d.note_failure(peers, id, &identity(&peers[&id]), &chosen, now);
        request_id
    }

    #[tokio::test]
    async fn discovery_delta_preserves_position_but_requires_fresh_hidden_relay_metadata() {
        let (id, peers, paths) = fixture();
        let now = Instant::now();
        let mut d = Discovery::default();
        let old_request = seed(&mut d, id, &peers, &paths, now).await;
        // A redundant peer update or another peer's removal is still a new
        // authorization snapshot. Cached endpoints must stop being usable.
        d.reconcile_delta(&peers, &[ObjectId::new()]);
        assert!(d.candidate_for(&peers, id, now).is_none());
        assert_eq!(
            d.receive_page(&peers, id, old_request, paths[..3].to_vec(), 30, None, now),
            0,
            "old reply cannot restore metadata after a delta"
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        d.request(
            true,
            true,
            &peers,
            &ControlTx::new(tx),
            now + Duration::from_secs(59),
        )
        .await;
        assert!(
            rx.try_recv().is_err(),
            "delta must retain the original request pacing"
        );
        let (fresh_request, cursor) = request(&mut d, &peers, now + PAIR_GAP).await;
        assert_eq!(
            cursor,
            Some(OrgRelayDiscoveryCursorWire {
                relay_node_id: paths[0].relay_node_id,
                exit_relay_node_id: None,
            }),
            "ordinary updates must not restart the preferred top-three page forever"
        );
        assert!(d.candidate_for(&peers, id, now + PAIR_GAP).is_none());
        // A fresh server-authorized successor page exposes previously hidden 2.
        let successor_page = vec![paths[1].clone(), paths[3].clone(), paths[4].clone()];
        assert_eq!(
            d.receive_page(
                &peers,
                id,
                fresh_request,
                successor_page,
                30,
                Some(OrgRelayDiscoveryCursorWire {
                    relay_node_id: paths[3].relay_node_id,
                    exit_relay_node_id: None,
                }),
                now + PAIR_GAP
            ),
            3
        );
        assert_eq!(
            d.candidate_for(&peers, id, now + PAIR_GAP)
                .unwrap()
                .relay_node_id,
            paths[4].relay_node_id
        );
    }

    #[tokio::test]
    async fn discovery_delta_cancels_pending_reply_without_extending_its_deadline() {
        let (id, peers, paths) = fixture();
        let now = Instant::now();
        let mut d = Discovery::default();
        let (request_id, _) = request(&mut d, &peers, now).await;
        d.reconcile_delta(&peers, &[]);
        assert!(d.pairs[&id].pending.is_none());
        assert!(d.pairs[&id].cached.is_none());
        assert_eq!(d.pairs[&id].asked, now);
        assert_eq!(
            d.receive_page(
                &peers,
                id,
                request_id,
                paths[..3].to_vec(),
                30,
                None,
                now + Duration::from_secs(1)
            ),
            0
        );
    }

    #[tokio::test]
    async fn discovery_delta_discards_removed_readded_rekeyed_readdressed_and_ineligible_pairs() {
        for change in 0..6 {
            let (id, mut peers, paths) = fixture();
            let now = Instant::now();
            let mut d = Discovery::default();
            let old_request = seed(&mut d, id, &peers, &paths, now).await;
            let mut removed = Vec::new();
            match change {
                0 => {
                    peers.remove(&id);
                }
                1 => {
                    removed.push(id);
                } // remove+upsert of the same key and IP
                2 => {
                    peers.get_mut(&id).unwrap().wg_public_key =
                        WgKeypair::generate().public_base64();
                }
                3 => {
                    peers.get_mut(&id).unwrap().overlay_ip = "100.64.0.3".into();
                }
                4 => {
                    peers.get_mut(&id).unwrap().reachable = false;
                }
                5 => {
                    peers.get_mut(&id).unwrap().supports_org_relay = false;
                }
                _ => unreachable!(),
            }
            d.reconcile_delta(&peers, &removed);
            assert!(
                !d.pairs.contains_key(&id),
                "stale position/history survived identity change {change}"
            );
            assert!(d.candidate_for(&peers, id, now).is_none());
            assert_eq!(
                d.receive_page(&peers, id, old_request, paths[..3].to_vec(), 30, None, now),
                0
            );
            if peers.get(&id).is_some_and(eligible) {
                let (_, cursor) = request(&mut d, &peers, now + PAIR_GAP).await;
                assert!(cursor.is_none(), "new identity must start fresh");
            }
        }
    }

    #[tokio::test]
    async fn discovery_full_invalidation_still_discards_negotiated_progress() {
        let (id, peers, paths) = fixture();
        let now = Instant::now();
        let mut d = Discovery::default();
        let old_request = seed(&mut d, id, &peers, &paths, now).await;
        // Reattach/full netmap/revoke keep the conservative existing contract.
        d.invalidate();
        assert!(d.pairs[&id].page_cursor.is_none());
        assert!(d.pairs[&id].page_after.is_none());
        assert!(d.pairs[&id].cached.is_none());
        assert_eq!(
            d.receive_page(&peers, id, old_request, paths[..3].to_vec(), 30, None, now),
            0
        );
        let (_, cursor) = request(&mut d, &peers, now + PAIR_GAP).await;
        assert!(cursor.is_none());
    }
}
