// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P3c — the org-relay MINT: the server's decision to route one pair of
//! nodes through a third, tenant-owned node (`docs/fr/FR-19-peer-relays.md`
//! §1–§7).
//!
//! The server decides and pushes; it never carries a byte. A mint is three
//! frames — `rc:overlay.relay_serve` to the relay with both members' secrets,
//! `rc:overlay.relay_session` to each member with its own — and then the
//! server's involvement ends: the members bind at the relay over a path the
//! server is not on. That is why every refusal is enumerated
//! ([`PeerRelayDenyReason`]) and written to `peer_relay_audit`: the asker never
//! gets a synchronous answer, so the row IS the answer.
//!
//! ## Gates, in order
//!
//! 1. `peer_relay_mode` — `off` ⇒ nothing: no rows, no reads past the cached
//!    mode; `warn` ⇒ decide and audit exactly as `on` would, push nothing;
//!    `on` ⇒ mint.
//! 2. Both ends advertised `supports_org_relay` and joined from their PRIMARY
//!    org. An absent flag is treated as "not primary": fail closed.
//! 3. The overlay ACL grants EACH member the relay node — an affirmative
//!    capability evaluated regardless of `acl_mode` (§4, decision "taken"),
//!    read through [`try_load_acl`] so an unreadable policy set is a refusal
//!    with its own reason and never a grant.
//! 4. A relay candidate: approved (`peer_relay_policy.serve`), advertising
//!    `relay-server` on its last hello, online on this pod, joined from its
//!    primary org, with at least one public endpoint, under its session cap.
//! 5. The per-(requester, relay) mint ceiling — after the identity gates, so
//!    a refusal is attributable.
//!
//! ## What is pod-local, and why that is right
//!
//! Sessions, VNI cursors, the generation clock, join extras and probe reports
//! live in this process. Tenant affinity puts a tenant's nodes — requester,
//! peer, relay — on ONE pod (`CLAUDE.md`, S6), so the mint and every party's
//! WS share a process, exactly as `relay_pair_churn` does. After a pod restart
//! the relay's own table is the truth: its sessions run out their
//! `max_lifetime`, the members re-request, and a fresh mint issues a fresh VNI.
//! Bounding that window is what `MAX_LIFETIME_SECS` is for.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{DateTime, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_remote_control::{
    models::{
        Agent, NodeRef, OverlayNode, PeerRelayAuditAction, PeerRelayAuditEvent,
        PeerRelayDenyReason, PeerRelayMode, RpcCap, peer_relay_limits as limits,
    },
    signaling::{
        OrgRelayCandidateWire, OrgRelayDiscoveryCursorWire, RelayMemberWire, RelayPathWire,
        RelayProbeTargetWire, RelayRevokeScopeWire, ServerMsg,
    },
};
use rand::RngCore;
use tracing::{debug, info, warn};
use tunnel_core::policy::{OverlayPeerRef, OverlaySource, evaluate_overlay};

use crate::NetworkState;
use crate::overlay::{
    NodeIdentity, PolicyLoad, current_node, pair_key, send_to_node, send_to_node_ref, try_load_acl,
    try_overlay_source_of,
};
use meshharbor_core::business_authority::{AuthenticatedDevice, BusinessZone};
use meshharbor_core::net::is_global_unicast;

// Search over the currently authorized relay graph.
#[allow(dead_code)]
mod path_search;
// Construct directed edges from approved relay policies.
#[allow(dead_code)]
mod path_graph;
// Resumable enumeration is staged until discovery carries its checkpoint.
#[allow(dead_code)]
mod path_discovery;
mod path_discovery_page;
// Build a live authorization snapshot for path selection.
#[allow(dead_code)]
mod path_candidate;
// Rank paths from a common authorized snapshot.
#[allow(dead_code)]
mod path_select;
// Structural message construction is shared by the existing two-relay mint
// and the staged N-hop workflow; authorization and reservation stay outside.
mod path_delivery;
mod path_mint;
// Staged exact-path authorization; it does not reserve or send a trial.
#[allow(dead_code)]
mod path_trial_plan;
// Staged atomic admission primitive; existing mint/trial owners are not yet coordinated.
#[allow(dead_code)]
mod path_reservation;
mod session_zone;
mod trial;
/// Test-only adapter for exercising the staged candidate builder against a
/// real isolated server fixture. It returns metadata, never grants sessions.
#[cfg(feature = "path-planner-test-support")]
pub mod candidate_test_support {
    use super::*;
    /// Opaque snapshot from the real staged trial path authorization.
    pub struct TrialPathSnapshot(path_trial_plan::TrialPathPlan);

    impl TrialPathSnapshot {
        pub fn edges(&self) -> Vec<(ObjectId, ObjectId, String, bool)> {
            self.0
                .edges
                .iter()
                .map(|edge| {
                    (
                        edge.source,
                        edge.target,
                        edge.endpoint.clone(),
                        edge.requires_cross_border_approval,
                    )
                })
                .collect()
        }
        pub fn locally_current(&self, state: &NetworkState) -> bool {
            self.0.locally_current(state)
        }
    }

    pub async fn plan_trial_path_fixture(
        state: &NetworkState,
        requester: ObjectId,
        peer: ObjectId,
        nodes: Vec<ObjectId>,
        requester_at_exit: bool,
    ) -> Result<TrialPathSnapshot, PeerRelayDenyReason> {
        let path = meshharbor_remote_control::signaling::RelayPathWire::new(nodes)
            .map_err(|_| PeerRelayDenyReason::RequesterUnsupported)?;
        let a = state
            .overlay_nodes
            .base
            .find_by_id(requester)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let b = state
            .overlay_nodes
            .base
            .find_by_id(peer)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        path_trial_plan::plan(state, &a, &b, &path, requester_at_exit)
            .await
            .map(TrialPathSnapshot)
    }

    pub async fn reauthorize_trial_path_fixture(
        state: &NetworkState,
        requester: ObjectId,
        peer: ObjectId,
        expected: &TrialPathSnapshot,
    ) -> Result<TrialPathSnapshot, PeerRelayDenyReason> {
        let a = state
            .overlay_nodes
            .base
            .find_by_id(requester)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let b = state
            .overlay_nodes
            .base
            .find_by_id(peer)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        path_trial_plan::reauthorize(state, &a, &b, &expected.0)
            .await
            .map(TrialPathSnapshot)
    }
    /// Insert a fixture-owned session without sending grants; integration
    /// tests use it only to exercise the server's revocation entry point.
    pub fn insert_session_fixture(state: &NetworkState, session: OrgRelaySession) -> bool {
        match state.org_relay.sessions.entry(session.pair_key.clone()) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(session);
                true
            }
            dashmap::mapref::entry::Entry::Occupied(_) => false,
        }
    }
    /// Make one member key in a fixture-owned active session stale.
    pub fn invalidate_session_member_key_fixture(state: &NetworkState, pair: &str) -> bool {
        let Some(mut session) = state.org_relay.sessions.get_mut(pair) else {
            return false;
        };
        session.members[0].wg_public_key.push_str("-stale");
        true
    }
    /// Populate a test fixture through the same offer/report checks as the
    /// normal probe receiver. Only compiled for integration tests.
    pub fn record_member_probe_fixture(
        state: &NetworkState,
        member: ObjectId,
        reports: &[(ObjectId, String, bool, Option<u32>)],
    ) -> bool {
        let targets: Vec<_> = reports
            .iter()
            .map(|(relay, endpoint, _, _)| RelayProbeTargetWire {
                relay_node_id: *relay,
                endpoints: vec![endpoint.clone()],
            })
            .collect();
        state.org_relay.offer_probes(member, &targets);
        reports.iter().all(|(relay, endpoint, reachable, rtt)| {
            state
                .org_relay
                .record_probe(member, *relay, endpoint.clone(), *reachable, *rtt)
        })
    }
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use tokio::sync::oneshot;
    #[derive(Clone, Copy)]
    pub enum TrialCrossingAuditFault {
        Error,
        Timeout,
    }
    fn trial_crossing_audit_faults() -> &'static Mutex<HashMap<String, TrialCrossingAuditFault>> {
        static FAULTS: OnceLock<Mutex<HashMap<String, TrialCrossingAuditFault>>> = OnceLock::new();
        FAULTS.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Inject one audit failure or a pending write for an isolated trial pair.
    pub fn fail_next_trial_crossing_audit(pair: String, fault: TrialCrossingAuditFault) {
        assert!(
            trial_crossing_audit_faults()
                .lock()
                .unwrap()
                .insert(pair, fault)
                .is_none()
        );
    }
    pub(super) fn take_trial_crossing_audit_fault(pair: &str) -> Option<TrialCrossingAuditFault> {
        trial_crossing_audit_faults().lock().unwrap().remove(pair)
    }
    /// Exposes only the fixture's currently reserved trial slots.
    pub fn trial_slots_on_relay(state: &NetworkState, relay: ObjectId) -> usize {
        state
            .org_relay
            .trials
            .sessions_on_relay(relay, Instant::now())
    }
    /// Fixture-only phase and member progress; no state is changed.
    pub fn trial_member_progress(
        state: &NetworkState,
        id: ObjectId,
        node: ObjectId,
    ) -> Option<(u8, bool)> {
        super::trial::member_progress_fixture(state, id, node)
    }
    /// Insert a fixture-owned N-hop trial without emitting any grants. Used
    /// only to drive live zone changes and exact revoke frames in tests.
    pub fn insert_nhop_zone_trial_fixture(
        state: &NetworkState,
        session: OrgRelaySession,
        relay_zones: Vec<BusinessZone>,
        member_zones: Option<[BusinessZone; 2]>,
    ) -> ObjectId {
        super::trial::insert_trial_fixture(state, session, relay_zones, member_zones)
    }
    struct TrialZonePause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn trial_zone_pauses() -> &'static Mutex<HashMap<ObjectId, TrialZonePause>> {
        static PAUSES: OnceLock<Mutex<HashMap<ObjectId, TrialZonePause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause a fixture after reading the changed zones but before removal.
    pub fn pause_trial_zone_revoke(
        trial: ObjectId,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            trial_zone_pauses()
                .lock()
                .unwrap()
                .insert(
                    trial,
                    TrialZonePause {
                        reached: reached_tx,
                        resume: resume_rx,
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_trial_zone_revoke_if_armed(trial: ObjectId) {
        let pause = trial_zone_pauses().lock().unwrap().remove(&trial);
        if let Some(TrialZonePause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    fn trial_zone_read_failures() -> &'static Mutex<std::collections::HashSet<ObjectId>> {
        static FAILURES: OnceLock<Mutex<std::collections::HashSet<ObjectId>>> = OnceLock::new();
        FAILURES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    /// Simulate a transient zone-evidence read failure for one trial.
    pub fn fail_next_trial_zone_read(trial: ObjectId) {
        assert!(trial_zone_read_failures().lock().unwrap().insert(trial));
    }
    pub(super) fn take_trial_zone_read_failure(trial: ObjectId) -> bool {
        trial_zone_read_failures().lock().unwrap().remove(&trial)
    }
    fn trial_zone_read_stalls() -> &'static Mutex<std::collections::HashSet<ObjectId>> {
        static STALLS: OnceLock<Mutex<std::collections::HashSet<ObjectId>>> = OnceLock::new();
        STALLS.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    pub fn stall_next_trial_zone_read(trial: ObjectId) {
        assert!(trial_zone_read_stalls().lock().unwrap().insert(trial));
    }
    pub(super) fn take_trial_zone_read_stall(trial: ObjectId) -> bool {
        trial_zone_read_stalls().lock().unwrap().remove(&trial)
    }
    pub fn trial_exists_fixture(state: &NetworkState, id: ObjectId) -> bool {
        super::trial::trial_exists_fixture(state, id)
    }
    /// Exercise the same sequential party slices used by one worker batch.
    pub async fn run_two_trial_slices_fixture(
        state: &NetworkState,
        first: ObjectId,
        second: ObjectId,
    ) -> (bool, bool) {
        let a = !matches!(
            super::trial::recheck_trial_zone_slice(state, first, "fixture").await,
            super::trial::TrialZoneSlice::Complete
        );
        let b = !matches!(
            super::trial::recheck_trial_zone_slice(state, second, "fixture").await,
            super::trial::TrialZoneSlice::Complete
        );
        (a, b)
    }
    pub async fn run_one_trial_slice_fixture(state: &NetworkState, id: ObjectId) -> bool {
        !matches!(
            super::trial::recheck_trial_zone_slice(state, id, "fixture").await,
            super::trial::TrialZoneSlice::Complete
        )
    }
    fn trial_member_zone_read_failures() -> &'static Mutex<std::collections::HashSet<ObjectId>> {
        static FAILURES: OnceLock<Mutex<std::collections::HashSet<ObjectId>>> = OnceLock::new();
        FAILURES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    pub fn fail_next_trial_member_zone_read(trial: ObjectId) {
        assert!(
            trial_member_zone_read_failures()
                .lock()
                .unwrap()
                .insert(trial)
        );
    }
    pub(super) fn take_trial_member_zone_read_failure(trial: ObjectId) -> bool {
        trial_member_zone_read_failures()
            .lock()
            .unwrap()
            .remove(&trial)
    }
    fn line_audit_failures() -> &'static Mutex<std::collections::HashSet<String>> {
        static FAILURES: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
        FAILURES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    /// Simulate a two-relay line audit error for one fixture pair.
    pub fn fail_next_line_audit_fixture(pair: String) {
        assert!(line_audit_failures().lock().unwrap().insert(pair));
    }
    pub(super) fn take_line_audit_failure(pair: &str) -> bool {
        line_audit_failures().lock().unwrap().remove(pair)
    }
    fn nhop_audit_failures() -> &'static Mutex<std::collections::HashSet<String>> {
        static FAILURES: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
        FAILURES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    /// Simulate a crossing-audit error for one fixture pair, exactly once.
    pub fn fail_next_nhop_audit_fixture(pair: String) {
        assert!(nhop_audit_failures().lock().unwrap().insert(pair));
    }
    pub(super) fn take_nhop_audit_failure(pair: &str) -> bool {
        nhop_audit_failures().lock().unwrap().remove(pair)
    }
    /// Populate backbone measurements via the same offer/report gates.
    pub fn record_backbone_probe_fixture(
        state: &NetworkState,
        source: ObjectId,
        reports: &[(ObjectId, String, bool, Option<u32>)],
    ) -> bool {
        let targets: Vec<_> = reports
            .iter()
            .map(|(relay, endpoint, _, _)| RelayProbeTargetWire {
                relay_node_id: *relay,
                endpoints: vec![endpoint.clone()],
            })
            .collect();
        state.org_relay.offer_backbone_probes(source, &targets);
        reports.iter().all(|(relay, endpoint, reachable, rtt)| {
            state
                .org_relay
                .record_probe(source, *relay, endpoint.clone(), *reachable, *rtt)
        })
    }
    struct NhopPreclaimPause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn nhop_preclaim_pauses() -> &'static Mutex<HashMap<String, NhopPreclaimPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, NhopPreclaimPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn pause_nhop_preclaim_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            nhop_preclaim_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    NhopPreclaimPause {
                        reached: reached_tx,
                        resume: resume_rx
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_nhop_preclaim_if_armed(pair: &str) {
        let pause = nhop_preclaim_pauses().lock().unwrap().remove(pair);
        if let Some(NhopPreclaimPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    struct NhopPartialPause {
        reached: oneshot::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    }
    fn nhop_partial_pauses() -> &'static Mutex<HashMap<String, NhopPartialPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, NhopPartialPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Bounded test-only pause immediately before the first send under the delivery guard.
    pub fn pause_nhop_before_first_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        assert!(
            nhop_partial_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    NhopPartialPause {
                        reached: reached_tx,
                        resume: resume_rx
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) fn pause_nhop_before_first_if_armed(pair: &str) {
        let pause = nhop_partial_pauses().lock().unwrap().remove(pair);
        if let Some(NhopPartialPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.recv_timeout(Duration::from_secs(5));
        }
    }
    fn nhop_reauth_failures() -> &'static Mutex<std::collections::HashSet<String>> {
        static FAILURES: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
        FAILURES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
    }
    /// Simulate one transient reauthorization read failure for a fixture pair.
    pub fn fail_next_nhop_reauth_fixture(pair: String) {
        assert!(nhop_reauth_failures().lock().unwrap().insert(pair));
    }
    pub(super) fn take_nhop_reauth_failure(pair: &str) -> bool {
        nhop_reauth_failures().lock().unwrap().remove(pair)
    }
    struct NhopRepushPause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn nhop_repush_pauses() -> &'static Mutex<HashMap<String, NhopRepushPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, NhopRepushPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause after reauthorization and before its guarded re-push.
    pub fn pause_nhop_repush_fixture(pair: String) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            nhop_repush_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    NhopRepushPause {
                        reached: reached_tx,
                        resume: resume_rx
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_nhop_repush_if_armed(pair: &str) {
        let pause = nhop_repush_pauses().lock().unwrap().remove(pair);
        if let Some(NhopRepushPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    fn session_zone_pauses() -> &'static Mutex<HashMap<String, NhopRepushPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, NhopRepushPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause after region reads and immediately before their final decision.
    pub fn pause_session_zone_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            session_zone_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    NhopRepushPause {
                        reached: reached_tx,
                        resume: resume_rx
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_session_zone_if_armed(pair: &str) {
        let pause = session_zone_pauses().lock().unwrap().remove(pair);
        if let Some(NhopRepushPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    struct LinePreclaimPause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn line_preclaim_pauses() -> &'static Mutex<HashMap<String, LinePreclaimPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, LinePreclaimPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause an established line just before its shared session claim.
    pub fn pause_line_preclaim_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            line_preclaim_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    LinePreclaimPause {
                        reached: reached_tx,
                        resume: resume_rx,
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_line_preclaim_if_armed(pair: &str) {
        let pause = line_preclaim_pauses().lock().unwrap().remove(pair);
        if let Some(LinePreclaimPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    struct CrossDiscoveryPause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn cross_discovery_pauses() -> &'static Mutex<HashMap<String, CrossDiscoveryPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, CrossDiscoveryPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause after constructing a cross-zone page, before its final fence.
    pub fn pause_cross_discovery_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            cross_discovery_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    CrossDiscoveryPause {
                        reached: reached_tx,
                        resume: resume_rx,
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_cross_discovery_if_armed(pair: &str) {
        let pause = cross_discovery_pauses().lock().unwrap().remove(pair);
        if let Some(CrossDiscoveryPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    struct NhopDeliveryPause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn nhop_delivery_pauses() -> &'static Mutex<HashMap<String, NhopDeliveryPause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, NhopDeliveryPause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause one fixture pair after claim but before any delivery.
    pub fn pause_nhop_delivery_fixture(
        pair: String,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            nhop_delivery_pauses()
                .lock()
                .unwrap()
                .insert(
                    pair,
                    NhopDeliveryPause {
                        reached: reached_tx,
                        resume: resume_rx
                    }
                )
                .is_none()
        );
        (reached_rx, resume_tx)
    }
    pub(super) async fn pause_nhop_delivery_if_armed(pair: &str) {
        let pause = nhop_delivery_pauses().lock().unwrap().remove(pair);
        if let Some(NhopDeliveryPause { reached, resume }) = pause {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    struct ProbePause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
        finished: oneshot::Sender<bool>,
    }
    fn pauses() -> &'static Mutex<HashMap<ObjectId, ProbePause>> {
        static PAUSES: OnceLock<Mutex<HashMap<ObjectId, ProbePause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Pause one selected identity after node lookup to force the actual
    /// displaced-connection race in an isolated integration fixture.
    pub fn pause_next_probe(
        identity: ObjectId,
    ) -> (
        oneshot::Receiver<()>,
        oneshot::Sender<()>,
        oneshot::Receiver<bool>,
    ) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let old = pauses().lock().unwrap().insert(
            identity,
            ProbePause {
                reached: reached_tx,
                resume: resume_rx,
                finished: finished_tx,
            },
        );
        assert!(old.is_none(), "duplicate probe pause fixture");
        (reached_rx, resume_tx, finished_rx)
    }
    pub(super) async fn pause_probe(identity: ObjectId) -> Option<oneshot::Sender<bool>> {
        let entry = pauses().lock().unwrap().remove(&identity);
        let ProbePause {
            reached,
            resume,
            finished,
        } = entry?;
        let _ = reached.send(());
        let _ = resume.await;
        Some(finished)
    }
    struct TunnelLeavePause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    fn tunnel_leave_pauses() -> &'static Mutex<HashMap<String, TunnelLeavePause>> {
        static PAUSES: OnceLock<Mutex<HashMap<String, TunnelLeavePause>>> = OnceLock::new();
        PAUSES.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn pause_tunnel_leave(connection_id: &str) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (tx, rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        assert!(
            tunnel_leave_pauses()
                .lock()
                .unwrap()
                .insert(
                    connection_id.to_owned(),
                    TunnelLeavePause {
                        reached: tx,
                        resume: resume_rx,
                    }
                )
                .is_none()
        );
        (rx, resume_tx)
    }
    pub(crate) async fn pause_tunnel_leave_if_armed(connection_id: &str) {
        let entry = tunnel_leave_pauses().lock().unwrap().remove(connection_id);
        if let Some(TunnelLeavePause { reached, resume }) = entry {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
    fn tunnel_bind_observers() -> &'static Mutex<HashMap<ObjectId, oneshot::Sender<()>>> {
        static OBSERVERS: OnceLock<Mutex<HashMap<ObjectId, oneshot::Sender<()>>>> = OnceLock::new();
        OBSERVERS.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn observe_tunnel_bind_attempt(identity: ObjectId) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        assert!(
            tunnel_bind_observers()
                .lock()
                .unwrap()
                .insert(identity, tx)
                .is_none()
        );
        rx
    }
    pub(crate) fn tunnel_bind_attempt(identity: ObjectId) {
        if let Some(tx) = tunnel_bind_observers().lock().unwrap().remove(&identity) {
            let _ = tx.send(());
        }
    }
    fn tunnel_bound_observers() -> &'static Mutex<HashMap<ObjectId, oneshot::Sender<()>>> {
        static OBSERVERS: OnceLock<Mutex<HashMap<ObjectId, oneshot::Sender<()>>>> = OnceLock::new();
        OBSERVERS.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn observe_tunnel_bound(identity: ObjectId) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        assert!(
            tunnel_bound_observers()
                .lock()
                .unwrap()
                .insert(identity, tx)
                .is_none()
        );
        rx
    }
    pub(crate) fn tunnel_bound(identity: ObjectId) {
        if let Some(tx) = tunnel_bound_observers().lock().unwrap().remove(&identity) {
            let _ = tx.send(());
        }
    }
    fn tunnel_cleanup_observers() -> &'static Mutex<HashMap<String, oneshot::Sender<()>>> {
        static OBSERVERS: OnceLock<Mutex<HashMap<String, oneshot::Sender<()>>>> = OnceLock::new();
        OBSERVERS.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn observe_tunnel_cleanup(connection_id: &str) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        assert!(
            tunnel_cleanup_observers()
                .lock()
                .unwrap()
                .insert(connection_id.to_owned(), tx)
                .is_none()
        );
        rx
    }
    pub(crate) fn tunnel_cleanup_done(connection_id: &str) {
        if let Some(tx) = tunnel_cleanup_observers()
            .lock()
            .unwrap()
            .remove(connection_id)
        {
            let _ = tx.send(());
        }
    }
    pub fn current_connection_id(state: &NetworkState, identity: ObjectId) -> Option<String> {
        state.org_relay.live_conn(identity)
    }
    /// Read back only fixture probe RTTs; no production route exposes this.
    pub fn probe_rtts(
        state: &NetworkState,
        reporter: ObjectId,
        relay: ObjectId,
    ) -> Vec<Option<u32>> {
        state
            .org_relay
            .probes
            .get(&(reporter, relay))
            .map(|records| records.iter().map(|record| record.rtt_ms).collect())
            .unwrap_or_default()
    }
    /// Exercise the real zone-recheck logic with fixture-owned session data.
    pub async fn line_zones_fit_fixture(state: &NetworkState, session: &OrgRelaySession) -> bool {
        line_zones_fit(state, session).await
    }
    pub async fn recheck_zones_fixture(state: &NetworkState, agent: ObjectId) {
        recheck_zones(state, agent, "fixture-zone-recheck").await;
    }
    pub fn schedule_trial_zone_retry_fixture(state: &NetworkState, id: ObjectId) {
        schedule_trial_zone_retry(state, std::collections::HashSet::from([id]));
    }
    pub fn trial_zone_retry_state_fixture(state: &NetworkState) -> (bool, bool) {
        let retry = state.org_relay.trial_zone_retry.lock().unwrap();
        (retry.running, retry.rescan)
    }
    /// Test the real full-path reauthorization with an already-held fixture.
    pub async fn reauthorize_nhop_fixture(
        state: &NetworkState,
        requester: ObjectId,
        peer: ObjectId,
        session: &OrgRelaySession,
    ) -> bool {
        let Ok(a) = state.overlay_nodes.base.find_by_id(requester).await else {
            return false;
        };
        let Ok(b) = state.overlay_nodes.base.find_by_id(peer).await else {
            return false;
        };
        path_mint::reauthorize(state, &a, &b, session).await.is_ok()
    }
    pub fn remove_session_fixture(state: &NetworkState, pair: &str) -> bool {
        state.org_relay.sessions.remove(pair).is_some()
    }
    /// Build only relay/bridge control frames from a fixture-owned session.
    /// No authorization, resource reservation, or messages are performed.
    pub fn delivery_frames_for_fixture(
        session: &OrgRelaySession,
    ) -> Result<Vec<(NodeRef, ServerMsg)>, String> {
        let delivery =
            path_delivery::build(session, Instant::now()).map_err(|e| format!("{e:?}"))?;
        Ok(delivery
            .relays
            .into_iter()
            .chain(delivery.bridges)
            .collect())
    }
    /// Read only: distinguish a missing current observation from GEO-04.
    pub async fn zone_snapshot_for_fixture(
        state: &NetworkState,
        id: ObjectId,
    ) -> Result<serde_json::Value, String> {
        let node = state
            .overlay_nodes
            .base
            .find_by_id(id)
            .await
            .map_err(|e| e.to_string())?;
        let observed = observed_zone(state, node.tenant_id, &node.node_ref)
            .await
            .map(|(zone, _)| format!("{zone:?}"));
        let zone = node_zone(state, &node)
            .await
            .map(|zone| format!("{zone:?}"));
        Ok(
            serde_json::json!({"node":id.to_hex(),"observed":observed,"zone":zone,
            "relay_withdrawn":state.org_relay.join_extras(id).relay_withdrawn,
            "srflx":node.srflx_endpoints,"lan":node.lan_endpoints}),
        )
    }

    pub fn last_mint_for_fixture(
        state: &NetworkState,
        a: ObjectId,
        b: ObjectId,
    ) -> Option<serde_json::Value> {
        state.org_relay.last_mint_audit.get(&pair_key(a,b)).map(|entry| {
            serde_json::json!({"denied":format!("{:?}",entry.0.0),"warn_only":entry.0.1,
                "age_ms":entry.1.elapsed().as_millis(),"eligibility_epoch":state.org_relay.eligibility_generation()})
        })
    }

    pub async fn select_path(
        state: &NetworkState,
        requester: ObjectId,
        peer: ObjectId,
        for_trial: bool,
    ) -> Result<Option<(Vec<ObjectId>, bool)>, PeerRelayDenyReason> {
        let a = state
            .overlay_nodes
            .base
            .find_by_id(requester)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let b = state
            .overlay_nodes
            .base
            .find_by_id(peer)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let prepared = path_candidate::prepare(state, &a, &b, for_trial).await?;
        let selected = path_select::select(state, prepared)?;
        Ok(selected.map(|s| {
            (
                s.path
                    .path
                    .relays
                    .iter()
                    .map(|&i| s.prepared.graph.relays[i].agent_id)
                    .collect(),
                s.path.flipped,
            )
        }))
    }
    pub async fn prepare_edges(
        state: &NetworkState,
        requester: ObjectId,
        peer: ObjectId,
        for_trial: bool,
    ) -> Result<Vec<(ObjectId, ObjectId, String, bool)>, PeerRelayDenyReason> {
        let a = state
            .overlay_nodes
            .base
            .find_by_id(requester)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let b = state
            .overlay_nodes
            .base
            .find_by_id(peer)
            .await
            .map_err(|_| PeerRelayDenyReason::PolicyUnreadable)?;
        let prepared = path_candidate::prepare(state, &a, &b, for_trial).await?;
        Ok(prepared
            .graph
            .edges
            .iter()
            .map(|edge| {
                (
                    prepared.graph.relays[edge.from].agent_id,
                    prepared.graph.relays[edge.to].agent_id,
                    edge.endpoint.clone(),
                    edge.cross_border,
                )
            })
            .collect())
    }
}

pub use trial::{
    PathTrialReturnUpdate, PathTrialUpdate, request as path_trial_request,
    return_update as path_trial_return_update, update as path_trial_update,
};

/// How long a cached `peer_relay_mode` read stands. The org switch route
/// invalidates on write (same pod, by tenant affinity), so this only bounds
/// the window after an out-of-band edit.
const MODE_CACHE_TTL: Duration = Duration::from_secs(30);
/// Reports per (reporter, relay) kept; older ones fall off.
const PROBES_PER_KEY: usize = 8;

/// The first wait before a loss-pinned relay may serve its pair again as the
/// pair's only relay ([`OrgRelayState::loss_pin_sole_retry_due`]).
pub const LOSS_PIN_SOLE_RETRY: Duration = Duration::from_secs(120);
/// A pin set again within this long of the last one is a further strike.
const LOSS_PIN_STRIKE_WINDOW: Duration = Duration::from_secs(1200);
/// How long a relay whose session for a pair never bound is ranked last
/// for that pair ([`OrgRelayState::demote_unbound`]).
pub const UNBOUND_DEMOTE: Duration = Duration::from_secs(180);
/// Bound on the per-(pair, relay) marks kept in memory.
const MAX_PAIR_RELAY_MARKS: usize = 8192;

/// A per-pair loss pin on one relay ([`OrgRelayState::mark_lossy`]).
#[derive(Clone, Copy, Debug)]
struct LossPin {
    until: Instant,
    pinned_at: Instant,
    strikes: u32,
}

/// What a join tells the mint that the persisted row does not carry.
#[derive(Clone, Copy, Default)]
pub struct JoinExtras {
    /// `Some(true)` = joined from the device's primary org. `None` = the
    /// build did not say; treated as NOT primary everywhere it matters.
    pub org_primary: Option<bool>,
    /// The node's org-relay listening port, when it serves.
    pub relay_port: Option<u16>,
    /// Explicit loss after advertising a listener. Kept across further empty
    /// joins, while legacy clients which never supplied a port retain fallback.
    pub relay_withdrawn: bool,
    pub supports_org_relay_multi_candidate: bool,
    pub supports_org_relay_discovery_cursor: bool,
    pub supports_path_trial_v1: bool,
    pub supports_path_backbone_v1: bool,
    pub relay_backbone_ready: bool,
    /// MeshHarbor #21 — rides a cross-zone peer over its line alone.
    pub supports_backbone_only_v1: bool,
}

#[derive(Clone)]
pub struct SessionParty {
    pub node_id: ObjectId,
    pub node_ref: NodeRef,
}

#[derive(Clone)]
pub struct SessionMember {
    pub party: SessionParty,
    pub wg_public_key: String,
    /// base64 of the 32-byte bind secret. Kept so an idempotent re-request
    /// re-pushes the SAME session instead of minting a second one.
    pub bind_secret: String,
}

#[derive(Clone)]
pub struct OrgRelaySession {
    pub tenant_id: ObjectId,
    pub pair_key: String,
    pub vni: u32,
    pub generation: u64,
    pub relay: SessionParty,
    /// The relay's backing agent — the device an audit row is ABOUT.
    pub relay_agent_id: ObjectId,
    /// MeshHarbor `auto`: granted by the relay's central Server role and one
    /// shared business zone, not by an overlay policy. It rests on the three
    /// live connections that zone was observed on, so it ends with any of
    /// them, with the role and with `auto`; a policy edit neither grants nor
    /// revokes it.
    pub implicit: bool,
    pub members: [SessionMember; 2],
    pub endpoints: Vec<String>,
    pub expires_at: Instant,
    /// The relay drops every Bind for a session not fully bound by its bind
    /// deadline (`BIND_SECS` after the install), and later reaps it. Past
    /// this instant a re-push can no longer bind, so a fallback re-request
    /// mints a fresh session instead (`maybe_mint_fallback`).
    pub bind_by: Instant,
    /// Ordered relay sessions after the ingress. Each entry also describes
    /// the bridge on the preceding relay to this relay's session.
    pub hops: Vec<LineLeg>,
}

/// The exit half of a cross-border line session (`mint_line`).
#[derive(Clone)]
pub struct LineLeg {
    pub relay: SessionParty,
    pub relay_agent_id: ObjectId,
    pub vni: u32,
    pub generation: u64,
    /// The exit relay's public endpoints, for `members[1]`.
    pub endpoints: Vec<String>,
    /// The exit relay's address on the private line (the approved edge's).
    pub private_endpoint: String,
    /// Whether this particular edge requires explicit cross-border approval.
    /// Callers must treat unknown zone relationships as requiring approval.
    pub requires_cross_border_approval: bool,
    /// Keys the ingress relay's bridge (`rc:overlay.relay_bridge_*`).
    pub bridge_id: ObjectId,
    /// The bridge's bind secrets: `members[1]`'s slot on the ingress session
    /// and `members[0]`'s on the exit session. No member ever holds them.
    pub bridge_secrets: [String; 2],
}

/// What one member binds: its relay, VNI and endpoints.
struct MemberLeg<'a> {
    relay_node_id: ObjectId,
    vni: u32,
    generation: u64,
    endpoints: &'a [String],
}

impl OrgRelaySession {
    fn member_index(&self, node_id: ObjectId) -> Option<usize> {
        self.members.iter().position(|m| m.party.node_id == node_id)
    }
    fn involves(&self, node_id: ObjectId) -> bool {
        self.relay.node_id == node_id
            || self.member_index(node_id).is_some()
            || self.hops.iter().any(|l| l.relay.node_id == node_id)
    }
    fn involves_agent(&self, agent_id: ObjectId) -> bool {
        self.involves_device(
            meshharbor_core::business_authority::DeviceKind::Agent,
            agent_id,
        )
    }

    pub(crate) fn involves_device(
        &self,
        kind: meshharbor_core::business_authority::DeviceKind,
        device_id: ObjectId,
    ) -> bool {
        let is = |n: &NodeRef| match (kind, n) {
            (
                meshharbor_core::business_authority::DeviceKind::Agent,
                NodeRef::Agent { agent_id },
            ) => *agent_id == device_id,
            (
                meshharbor_core::business_authority::DeviceKind::TunnelClient,
                NodeRef::TunnelClient { tunnel_client_id },
            ) => *tunnel_client_id == device_id,
            _ => false,
        };
        is(&self.relay.node_ref)
            || self.members.iter().any(|m| is(&m.party.node_ref))
            || self.hops.iter().any(|l| is(&l.relay.node_ref))
    }

    fn involves_identity(&self, identity_id: ObjectId) -> bool {
        self.involves_device(
            meshharbor_core::business_authority::DeviceKind::Agent,
            identity_id,
        ) || self.involves_device(
            meshharbor_core::business_authority::DeviceKind::TunnelClient,
            identity_id,
        )
    }
    /// Whether `agent_id` relays this session (either leg of a line).
    fn relayed_by_agent(&self, agent_id: ObjectId) -> bool {
        self.relay_agent_id == agent_id || self.hops.iter().any(|l| l.relay_agent_id == agent_id)
    }
    /// All relay nodes, in path order.
    fn relay_nodes(&self) -> impl Iterator<Item = ObjectId> + '_ {
        std::iter::once(self.relay.node_id).chain(self.hops.iter().map(|l| l.relay.node_id))
    }
    /// The VNIs held on `relay_node_id`.
    fn vnis_on(&self, relay_node_id: ObjectId) -> impl Iterator<Item = u32> + '_ {
        (self.relay.node_id == relay_node_id)
            .then_some(self.vni)
            .into_iter()
            .chain(
                self.hops
                    .iter()
                    .filter(move |l| l.relay.node_id == relay_node_id)
                    .map(|l| l.vni),
            )
    }
    /// For legacy cross-border lines, require every edge from `source` to
    /// remain explicitly approved as cross-border with the same endpoint.
    fn has_removed_line_edge(
        &self,
        source: ObjectId,
        approved: &[meshharbor_remote_control::models::PeerRelayBackboneEdge],
    ) -> bool {
        self.hops.iter().enumerate().any(|(i, hop)| {
            let predecessor = if i == 0 {
                self.relay_agent_id
            } else {
                self.hops[i - 1].relay_agent_id
            };
            predecessor == source
                && !approved.iter().any(|edge| {
                    (!hop.requires_cross_border_approval || edge.cross_border)
                        && edge.endpoint == hop.private_endpoint
                        && ObjectId::parse_str(&edge.relay_agent_id).ok()
                            == Some(hop.relay_agent_id)
                })
        })
    }

    /// Revocations for the relay sessions after ingress and their source bridges.
    fn hop_revocations(&self) -> Vec<(NodeRef, ServerMsg)> {
        let mut messages = Vec::with_capacity(self.hops.len().saturating_mul(2));
        for (i, hop) in self.hops.iter().enumerate() {
            let (source, generation) = if i == 0 {
                (&self.relay.node_ref, self.generation)
            } else {
                (
                    &self.hops[i - 1].relay.node_ref,
                    self.hops[i - 1].generation,
                )
            };
            messages.push((
                hop.relay.node_ref.clone(),
                ServerMsg::OverlayRelayRevoke {
                    vni: hop.vni,
                    scope: RelayRevokeScopeWire {
                        relay_node_id: hop.relay.node_id,
                        generation: hop.generation,
                        peer_node_id: None,
                    },
                },
            ));
            messages.push((
                source.clone(),
                ServerMsg::OverlayRelayBridgeRevoke {
                    trial_id: hop.bridge_id,
                    generation,
                },
            ));
        }
        messages
    }

    /// What member `i` binds: on a line, `members[1]` binds the exit leg.
    fn member_leg(&self, i: usize) -> MemberLeg<'_> {
        match self.hops.last() {
            Some(l) if i == 1 => MemberLeg {
                relay_node_id: l.relay.node_id,
                vni: l.vni,
                generation: l.generation,
                endpoints: &l.endpoints,
            },
            _ => MemberLeg {
                relay_node_id: self.relay.node_id,
                vni: self.vni,
                generation: self.generation,
                endpoints: &self.endpoints,
            },
        }
    }
}

#[derive(Clone)]
pub struct ProbeRecord {
    pub endpoint: String,
    pub reachable: bool,
    pub rtt_ms: Option<u32>,
    pub at: Instant,
}

/// One member's measured standing toward one relay, for ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeVerdict {
    /// A fresh report says at least one endpoint answered.
    Reachable(u32),
    /// Every fresh report says no.
    Unreachable,
    /// Never measured, or only stale reports.
    Unknown,
}

#[derive(Default)]
pub struct OrgRelayState {
    // Serializes nonblocking N-hop delivery with synchronous revocation so a
    // stale grant cannot be queued after its revoke on this control process.
    delivery_guard: std::sync::Mutex<()>,
    /// One process-wide worker rechecks each live trial at most once per pass.
    trial_zone_retry: std::sync::Mutex<TrialZoneRetry>,
    trial_zone_cursors:
        std::sync::Mutex<std::collections::HashMap<ObjectId, trial::TrialZoneCursor>>,
    trial_zone_inflight: std::sync::Mutex<std::collections::HashSet<ObjectId>>,
    trial_zone_io_permits: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>>,
    trial_zone_io_budget: std::sync::Mutex<TrialZoneIoBudget>,
    sessions: DashMap<String, OrgRelaySession>,
    next_vni: DashMap<ObjectId, u32>,
    /// The server-wide logical clock the reference design calls `LamportID`:
    /// monotonic across every (pair, relay), so it is monotonic per one too.
    lamport: AtomicU64,
    join_extras: DashMap<ObjectId, JoinExtras>,
    /// Current overlay join start, used to reject pre-rejoin path probes.
    probe_join_at: DashMap<ObjectId, Instant>,
    /// Staged path ranking rejects measurements predating endpoint or policy changes.
    probe_endpoint_at: DashMap<ObjectId, Instant>,
    probe_policy_at: DashMap<ObjectId, Instant>,
    probes: DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>,
    /// MeshHarbor #5 — the (relay, endpoint)s each member's last full netmap
    /// offered it to probe ([`probe_targets`]). Replaced on every join.
    probe_offers: DashMap<ObjectId, Vec<(ObjectId, String)>>,
    /// MeshHarbor #5 step B — a relay's RTT to another relay over their
    /// private line, keyed (ingress relay node, exit relay node): measured by
    /// the ingress relay on its backbone interface, never the public path.
    backbone_probes: DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>,
    /// The (exit relay, private endpoint)s each relay's last full netmap
    /// offered it to measure ([`backbone_probe_targets`]).
    backbone_offers: DashMap<ObjectId, Vec<(ObjectId, String)>>,
    mode_cache: DashMap<ObjectId, (PeerRelayMode, Instant)>,
    /// MeshHarbor `auto` and #21: each agent's (`hello` binds, `closing`
    /// unbinds) and each tunnel client's (its WS binds and unbinds) live
    /// connection on this pod, whose opening observation is its zone
    /// evidence. Keyed by the device's ObjectId, unique across both kinds.
    live_conns: DashMap<ObjectId, LiveConnection>,
    trials: trial::PathTrials,
    /// (pair key, relay node) a member measured lossy: the planner skips
    /// that relay for that pair while the pair has another relay, until the
    /// pin ends (see [`Self::mark_lossy`], [`Self::loss_pin_sole_retry_due`]).
    lossy: DashMap<(String, ObjectId), LossPin>,
    /// (pair key, relay node) whose last session for the pair outlived its
    /// bind window while a member was still asking for a link: ranked last
    /// for that pair until when (see [`Self::demote_unbound`]).
    unbound: DashMap<(String, ObjectId), Instant>,
    /// Each pair's last mint row (its refusal, if any, and whether `warn`),
    /// and when it was written: a repeat of it is not written again within
    /// [`REPEAT_REFUSAL_AUDIT_GAP`] (see [`audit_mint`]).
    last_mint_audit: DashMap<String, ((Option<PeerRelayDenyReason>, bool), Instant)>,
    // Conservative generation for membership/policy decisions spanning async IO.
    eligibility_epoch: AtomicU64,
}

struct LiveConnection {
    id: String,
    /// Taken while the map entry is locked, after any previous report finishes.
    bound_at: Instant,
}

impl OrgRelayState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn invalidate_eligibility(&self) {
        self.eligibility_epoch.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn eligibility_generation(&self) -> u64 {
        self.eligibility_epoch.load(Ordering::Acquire)
    }

    /// Bind `agent_id`'s live connection; returns the one it displaced.
    pub fn bind_live_conn(&self, agent_id: ObjectId, conn_id: &str) -> Option<String> {
        self.invalidate_eligibility();
        let previous = match self.live_conns.entry(agent_id) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let old = entry.insert(LiveConnection {
                    id: conn_id.to_owned(),
                    bound_at: Instant::now(),
                });
                Some(old.id)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(LiveConnection {
                    id: conn_id.to_owned(),
                    bound_at: Instant::now(),
                });
                None
            }
        };
        self.invalidate_eligibility();
        previous.filter(|old| old != conn_id)
    }

    /// Unbind only while the binding still names `conn_id`: a displaced
    /// connection's late teardown must not unbind its replacement.
    pub fn unbind_live_conn(&self, agent_id: ObjectId, conn_id: &str) -> bool {
        let gone = self
            .live_conns
            .remove_if(&agent_id, |_, bound| bound.id == conn_id)
            .is_some();
        if gone {
            self.invalidate_eligibility();
        }
        gone
    }

    pub(crate) fn live_conn(&self, agent_id: ObjectId) -> Option<String> {
        self.live_conns.get(&agent_id).map(|c| c.id.clone())
    }

    /// Keep the ownership guard until the report has been recorded. A newly
    /// bound connection cannot overtake an accepted report's timestamp, and a
    /// displaced socket cannot inject reports after replacement.
    fn record_probe_from_connection(
        &self,
        owner: (ObjectId, &str),
        reporter: ObjectId,
        relay: ObjectId,
        endpoint: String,
        reachable: bool,
        rtt_ms: Option<u32>,
    ) -> bool {
        let Some(current) = self.live_conns.get(&owner.0) else {
            return false;
        };
        if current.id != owner.1 {
            return false;
        }
        let accepted = self.record_probe(reporter, relay, endpoint, reachable, rtt_ms);
        drop(current);
        accepted
    }

    pub(crate) fn note_probe_endpoint_change(&self, node_id: ObjectId) {
        self.probe_endpoint_at.insert(node_id, Instant::now());
        self.invalidate_eligibility();
    }

    pub(crate) fn note_probe_policy_change(&self, agent_id: ObjectId) {
        self.probe_policy_at.insert(agent_id, Instant::now());
        self.invalidate_eligibility();
    }

    /// Test hook: read the recorded policy-change timestamp for `agent_id`.
    /// Integration-test only (`path-planner-test-support`); never compiled in production builds.
    #[cfg(feature = "path-planner-test-support")]
    #[doc(hidden)]
    pub fn has_probe_policy_change(&self, agent_id: ObjectId) -> bool {
        self.probe_policy_at.contains_key(&agent_id)
    }

    /// Test hook: check whether `tenant_id` is currently cached in `mode_cache`.
    /// Integration-test only (`path-planner-test-support`); never compiled in production builds.
    #[cfg(feature = "path-planner-test-support")]
    #[doc(hidden)]
    pub fn has_cached_mode(&self, tenant_id: ObjectId) -> bool {
        self.mode_cache.contains_key(&tenant_id)
    }

    /// Test hook: seed `mode_cache` for `tenant_id` without creating an
    /// `OverlayNetwork` row in Mongo. Integration-test only (`path-planner-test-support`).
    #[cfg(feature = "path-planner-test-support")]
    #[doc(hidden)]
    pub fn prime_cached_mode_for_test(&self, tenant_id: ObjectId) {
        self.mode_cache
            .insert(tenant_id, (PeerRelayMode::Auto, Instant::now()));
    }

    /// A join is usable as measurement provenance only when it belongs to the
    /// connection currently owning this identity. Hold the ownership guard
    /// across the synchronous state update so a replacement cannot interleave.
    pub(crate) fn note_join_from_connection(
        &self,
        identity: ObjectId,
        connection_id: &str,
        node_id: ObjectId,
        extras: JoinExtras,
    ) -> Option<bool> {
        let owner = self.live_conns.get(&identity)?;
        if owner.id != connection_id {
            return None;
        }
        let changed = self.note_join(node_id, extras);
        drop(owner);
        Some(changed)
    }

    /// Record what a join said beyond the row. Overwrites on every rejoin so a
    /// build that stops advertising a port, or an org that stops being
    /// primary, is not remembered as it was.
    pub fn note_join(&self, node_id: ObjectId, mut extras: JoinExtras) -> bool {
        self.probe_join_at.insert(node_id, Instant::now());
        self.invalidate_eligibility();
        let mut entry = self.join_extras.entry(node_id).or_default();
        let previous = *entry;
        let changed_listener =
            previous.relay_port.is_some() && previous.relay_port != extras.relay_port;
        extras.relay_withdrawn = extras.relay_port.is_none()
            && (previous.relay_port.is_some() || previous.relay_withdrawn);
        *entry = extras;
        changed_listener
    }

    pub fn forget_node(&self, node_id: ObjectId) {
        self.invalidate_eligibility();
        self.join_extras.remove(&node_id);
        self.probe_join_at.remove(&node_id);
        self.probe_endpoint_at.remove(&node_id);
        self.probes.retain(|(reporter, _), _| *reporter != node_id);
    }

    pub fn join_extras(&self, node_id: ObjectId) -> JoinExtras {
        self.join_extras
            .get(&node_id)
            .map(|e| *e)
            .unwrap_or_default()
    }

    pub fn invalidate_mode(&self, tenant_id: ObjectId) {
        self.invalidate_eligibility();
        self.mode_cache.remove(&tenant_id);
    }

    /// The live session for a pair, if any. Expired sessions are reaped on
    /// the way out so a stale entry can never be re-pushed.
    pub fn active_session(&self, pair_key: &str) -> Option<OrgRelaySession> {
        loop {
            let s = self.sessions.get(pair_key).map(|e| e.value().clone())?;
            let now = Instant::now();
            if s.expires_at > now {
                return Some(s);
            }
            // A replacement can arrive after the read. Only remove the value
            // currently in the map if it is still expired; otherwise retry.
            if self.remove_expired_session(pair_key, now) {
                return None;
            }
        }
    }

    fn remove_expired_session(&self, pair_key: &str, now: Instant) -> bool {
        self.sessions
            .remove_if(pair_key, |_, current| current.expires_at <= now)
            .is_some()
    }

    /// Test hook: as if `pair_key`'s session had outlived its bind window.
    #[doc(hidden)]
    pub fn age_past_bind_window(&self, pair_key: &str) {
        if let Some(mut s) = self.sessions.get_mut(pair_key) {
            s.bind_by = Instant::now() - Duration::from_secs(1);
        }
    }

    /// A member measured `relay_node_id` lossy for the pair `pair_key`: the
    /// planner skips that relay for that pair until `until`, so the pair
    /// moves to another relay in its zone, and to DERP only when none is
    /// left. Other pairs keep the relay.
    ///
    /// A pin set again within [`LOSS_PIN_STRIKE_WINDOW`] of the previous one
    /// counts a strike: a relay that keeps losing the pair's packets earns a
    /// longer wait before it is retried as the pair's only relay.
    pub fn mark_lossy(&self, pair_key: &str, relay_node_id: ObjectId, until: Instant) {
        let now = Instant::now();
        if self.lossy.len() >= MAX_PAIR_RELAY_MARKS {
            self.lossy.retain(|_, pin| pin.until > now);
        }
        let key = (pair_key.to_string(), relay_node_id);
        let strikes = self
            .lossy
            .get(&key)
            .filter(|prev| now.saturating_duration_since(prev.pinned_at) < LOSS_PIN_STRIKE_WINDOW)
            .map_or(1, |prev| prev.strikes.saturating_add(1));
        self.lossy.insert(
            key,
            LossPin {
                until,
                pinned_at: now,
                strikes,
            },
        );
    }

    pub fn is_lossy(&self, pair_key: &str, relay_node_id: ObjectId, now: Instant) -> bool {
        let key = (pair_key.to_string(), relay_node_id);
        match self.lossy.get(&key).map(|p| p.until) {
            Some(until) if until > now => true,
            Some(_) => {
                self.lossy.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Whether a loss-pinned relay may be offered again to its pair as the
    /// pair's ONLY relay (field, 2026-11-11: the pair's other relay froze
    /// two minutes into a 10-minute pin and the pair sat on DERP for the
    /// rest of it, the pinned relay healthy). The first strike waits
    /// [`LOSS_PIN_SOLE_RETRY`], each further strike twice as long, never
    /// past the pin itself. The pin still keeps the relay out while any
    /// other relay can take the pair, and a retried relay that loses the
    /// pair's packets again is re-pinned with a strike.
    pub fn loss_pin_sole_retry_due(
        &self,
        pair_key: &str,
        relay_node_id: ObjectId,
        now: Instant,
    ) -> bool {
        let key = (pair_key.to_string(), relay_node_id);
        let Some(pin) = self.lossy.get(&key).map(|p| *p) else {
            return true;
        };
        if pin.until <= now {
            return true;
        }
        let shift = pin.strikes.saturating_sub(1).min(16);
        let wait = LOSS_PIN_SOLE_RETRY
            .saturating_mul(1u32 << shift)
            .min(pin.until.saturating_duration_since(pin.pinned_at));
        now.saturating_duration_since(pin.pinned_at) >= wait
    }

    /// Test hook: as if `pair_key`'s loss pin on `relay_node_id` was set
    /// `by` earlier (it ends `by` earlier too).
    #[doc(hidden)]
    pub fn age_loss_pin(&self, pair_key: &str, relay_node_id: ObjectId, by: Duration) {
        if let Some(mut pin) = self.lossy.get_mut(&(pair_key.to_string(), relay_node_id))
            && let (Some(at), Some(until)) =
                (pin.pinned_at.checked_sub(by), pin.until.checked_sub(by))
        {
            pin.pinned_at = at;
            pin.until = until;
        }
    }

    /// A pair's session on `relay_node_id` passed its bind window while a
    /// member still asked for a link: whatever the probes say, that relay
    /// did not carry this pair. It is ranked last for the pair until
    /// `until` — never excluded, so it still serves a pair it is the only
    /// relay for, and one member can only demote it for its own pair.
    pub fn demote_unbound(&self, pair_key: &str, relay_node_id: ObjectId, until: Instant) {
        let now = Instant::now();
        if self.unbound.len() >= MAX_PAIR_RELAY_MARKS {
            self.unbound.retain(|_, u| *u > now);
        }
        self.unbound
            .insert((pair_key.to_string(), relay_node_id), until);
    }

    pub fn is_unbound_demoted(
        &self,
        pair_key: &str,
        relay_node_id: ObjectId,
        now: Instant,
    ) -> bool {
        let key = (pair_key.to_string(), relay_node_id);
        match self.unbound.get(&key).map(|u| *u) {
            Some(until) if until > now => true,
            Some(_) => {
                self.unbound.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn sessions_on_relay(&self, relay_node_id: ObjectId) -> usize {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter(|e| e.relay_nodes().any(|r| r == relay_node_id) && e.expires_at > now)
            .count()
            + self.trials.sessions_on_relay(relay_node_id, now)
    }

    /// Next free 24-bit VNI on a relay — globally unique PER RELAY NODE, never
    /// per tenant (§2: the Geneve header has no tenant field, so a shared
    /// node's demux key must be unambiguous across tenants). Skips 0 and the
    /// STUN magic cookie (which the relay never mints, so a STUN packet can
    /// never alias a session), and any VNI a live session on that relay
    /// still holds.
    fn alloc_vni(&self, relay_node_id: ObjectId) -> Option<u32> {
        let reserved = self.trials.vnis_on_relay(relay_node_id);
        self.alloc_vni_with_reserved(relay_node_id, &reserved)
    }

    fn alloc_vni_with_reserved(&self, relay_node_id: ObjectId, reserved: &[u32]) -> Option<u32> {
        let mut in_use: Vec<u32> = self
            .sessions
            .iter()
            .flat_map(|e| e.vnis_on(relay_node_id).collect::<Vec<_>>())
            .collect();
        in_use.extend_from_slice(reserved);
        let mut cursor = self.next_vni.entry(relay_node_id).or_insert(1);
        // At most `MAX_SESSIONS_PER_RELAY` live VNIs plus the two reserved
        // values can stand in the way; bound the walk accordingly.
        for _ in 0..(limits::MAX_SESSIONS_PER_RELAY + 4) {
            let candidate = *cursor;
            *cursor = if candidate >= limits::VNI_MAX {
                1
            } else {
                candidate + 1
            };
            if candidate == 0 || candidate == limits::STUN_COOKIE_VNI {
                continue;
            }
            if in_use.contains(&candidate) {
                continue;
            }
            return Some(candidate);
        }
        None
    }

    /// Remember what a member's netmap offered it to probe (#5).
    pub(crate) fn offer_probes(&self, member: ObjectId, targets: &[RelayProbeTargetWire]) {
        let offers = targets
            .iter()
            .flat_map(|t| t.endpoints.iter().map(|e| (t.relay_node_id, e.clone())))
            .collect();
        self.probe_offers.insert(member, offers);
    }

    /// Remember which lines a relay's netmap offered it to measure (#5 B).
    pub(crate) fn offer_backbone_probes(&self, relay: ObjectId, targets: &[RelayProbeTargetWire]) {
        let offers = targets
            .iter()
            .flat_map(|t| t.endpoints.iter().map(|e| (t.relay_node_id, e.clone())))
            .collect();
        self.backbone_offers.insert(relay, offers);
    }

    /// Accept a reachability report ONLY about a relay + endpoint the server
    /// minted for that node or offered it to probe ([`probe_targets`]): a
    /// device cannot inject claims about arbitrary targets. A report about a
    /// line the node was offered ([`backbone_probe_targets`]) is filed apart:
    /// it is that line's RTT, not the node's own path to the relay.
    pub fn record_probe(
        &self,
        reporter: ObjectId,
        relay_node_id: ObjectId,
        endpoint: String,
        reachable: bool,
        rtt_ms: Option<u32>,
    ) -> bool {
        let minted_for_it = self.sessions.iter().any(|e| {
            e.member_index(reporter).is_some_and(|i| {
                let leg = e.member_leg(i);
                leg.relay_node_id == relay_node_id && leg.endpoints.contains(&endpoint)
            })
        });
        let offered = |offers: &DashMap<ObjectId, Vec<(ObjectId, String)>>| {
            offers
                .get(&reporter)
                .is_some_and(|o| o.iter().any(|(r, e)| *r == relay_node_id && *e == endpoint))
        };
        let line = offered(&self.backbone_offers);
        let own = minted_for_it || offered(&self.probe_offers);
        let record = ProbeRecord {
            endpoint,
            reachable,
            rtt_ms,
            at: Instant::now(),
        };
        let push = |map: &DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>| {
            let mut v = map.entry((reporter, relay_node_id)).or_default();
            v.push(record.clone());
            if v.len() > PROBES_PER_KEY {
                let excess = v.len() - PROBES_PER_KEY;
                v.drain(..excess);
            }
        };
        if line {
            push(&self.backbone_probes);
        }
        if own {
            push(&self.probes);
        }
        line || own
    }

    fn probe_verdict(
        &self,
        reporter: ObjectId,
        relay_node_id: ObjectId,
        now: Instant,
    ) -> ProbeVerdict {
        verdict_of(&self.probes, reporter, relay_node_id, now)
    }

    /// The line from relay `ingress` to relay `exit`, as `ingress` measured it.
    fn backbone_verdict(&self, ingress: ObjectId, exit: ObjectId, now: Instant) -> ProbeVerdict {
        verdict_of(&self.backbone_probes, ingress, exit, now)
    }
}

fn verdict_of(
    map: &DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>,
    reporter: ObjectId,
    relay_node_id: ObjectId,
    now: Instant,
) -> ProbeVerdict {
    let Some(v) = map.get(&(reporter, relay_node_id)) else {
        return ProbeVerdict::Unknown;
    };
    let ttl = Duration::from_secs(limits::PROBE_TTL_SECS);
    let fresh: Vec<&ProbeRecord> = v
        .iter()
        .filter(|p| now.duration_since(p.at) < ttl)
        .collect();
    // Records are kept in arrival order. Per ENDPOINT, the newest decides: a
    // failure measured after a success is that endpoint's state now, however
    // good it was earlier in the window (field, 2026-11-11: a frozen relay
    // was re-minted twice on 10-minute-old successes after both members had
    // measured it unreachable). The relay is reachable when any endpoint's
    // newest record is, at the best RTT any such endpoint measured since its
    // own last failure; per endpoint, so a relay with one dead address and
    // one live one does not flip with the order a round's reports arrive in.
    if fresh.is_empty() {
        return ProbeVerdict::Unknown;
    }
    let mut best: Option<u32> = None;
    let mut endpoints: Vec<&str> = Vec::new();
    for p in &fresh {
        if !endpoints.contains(&p.endpoint.as_str()) {
            endpoints.push(p.endpoint.as_str());
        }
    }
    for ep in endpoints {
        let of_ep: Vec<&&ProbeRecord> = fresh.iter().filter(|p| p.endpoint == ep).collect();
        if !of_ep.last().is_some_and(|p| p.reachable) {
            continue;
        }
        let since = of_ep
            .iter()
            .rposition(|p| !p.reachable)
            .map_or(0, |i| i + 1);
        let rtt = of_ep[since..]
            .iter()
            .map(|p| p.rtt_ms.unwrap_or(0))
            .min()
            .unwrap_or(0);
        best = Some(best.map_or(rtt, |b| b.min(rtt)));
    }
    match best {
        Some(rtt) => ProbeVerdict::Reachable(rtt),
        None => ProbeVerdict::Unreachable,
    }
}

/// A staged path can only use measurements made against its current approved
/// endpoints. A successful report without an RTT is unknown, not 0 ms.
fn scoped_probe_verdict(
    map: &DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>,
    reporter: ObjectId,
    relay: ObjectId,
    endpoints: &[String],
    not_before: Option<Instant>,
    now: Instant,
) -> ProbeVerdict {
    let Some(not_before) = not_before else {
        return ProbeVerdict::Unknown;
    };
    let Some(records) = map.get(&(reporter, relay)) else {
        return ProbeVerdict::Unknown;
    };
    let ttl = Duration::from_secs(limits::PROBE_TTL_SECS);
    let mut measured: Option<u32> = None;
    let mut missing_rtt = false;
    let mut failed = false;
    for record in records.iter().filter(|r| {
        endpoints.contains(&r.endpoint)
            && r.at >= not_before
            && now
                .checked_duration_since(r.at)
                .is_some_and(|age| age < ttl)
    }) {
        match (record.reachable, record.rtt_ms) {
            (true, Some(ms)) => measured = Some(measured.map_or(ms, |old| old.min(ms))),
            (true, None) => missing_rtt = true,
            (false, _) => failed = true,
        }
    }
    if let Some(rtt) = measured {
        ProbeVerdict::Reachable(rtt)
    } else if missing_rtt {
        ProbeVerdict::Unknown
    } else if failed {
        ProbeVerdict::Unreachable
    } else {
        ProbeVerdict::Unknown
    }
}

/// The tenant's peer-relay posture, cached briefly. A read failure is `Off`:
/// the wrong answer here costs one un-minted relay session (the pair stays
/// on TURN/DERP), while the wrong answer in the other direction would mint
/// against a posture nobody set.
pub async fn peer_relay_mode(state: &NetworkState, tenant_id: ObjectId) -> PeerRelayMode {
    let now = Instant::now();
    if let Some(e) = state.org_relay.mode_cache.get(&tenant_id)
        && now.duration_since(e.1) < MODE_CACHE_TTL
    {
        return e.0;
    }
    let mode = match state.overlay_networks.get_or_create(tenant_id).await {
        Ok(n) => n.peer_relay_mode,
        Err(e) => {
            warn!(%tenant_id, %e, "org-relay: network read failed; treating peer_relay_mode as off");
            return PeerRelayMode::Off;
        }
    };
    state.org_relay.mode_cache.insert(tenant_id, (mode, now));
    mode
}

/// A relay chosen for a pair, with everything the frames need.
#[derive(Clone)]
struct Plan {
    relay: OverlayNode,
    relay_agent_id: ObjectId,
    endpoints: Vec<String>,
    backbone_edges: Vec<meshharbor_remote_control::models::PeerRelayBackboneEdge>,
    /// Granted by role and zone (`auto`), not by an overlay policy.
    implicit: bool,
}

/// The relay's dialable `ip:port`s: its own public addresses (srflx first —
/// the mapping its NAT actually exposes — then a public NIC, then the relay
/// trickle bucket), each paired with the relay-server port, then the admin's
/// static endpoints. `Err` = a static endpoint failed the SSRF rule, which
/// refuses the mint outright rather than quietly dropping the entry: the
/// admin wrote it, and a mint that silently ignores policy is worse than one
/// that says why it did not happen.
fn relay_endpoints(
    node: &OverlayNode,
    port: u16,
    static_endpoints: &[String],
) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for cand in node
        .srflx_endpoints
        .iter()
        .chain(node.lan_endpoints.iter())
        .chain(node.endpoints.iter())
    {
        if let Ok(sa) = cand.parse::<SocketAddr>()
            && is_global_unicast(&sa.ip())
        {
            push(SocketAddr::new(sa.ip(), port).to_string());
        }
    }
    for s in static_endpoints {
        let sa: SocketAddr = s.parse().map_err(|_| ())?;
        if !is_global_unicast(&sa.ip()) {
            return Err(());
        }
        push(sa.to_string());
    }
    Ok(out)
}

/// Is `s` a public `ip:port` literal? The approval route's validator — a
/// name is refused too, because a name can resolve to something else by the
/// time the mint re-checks it.
pub fn valid_static_endpoint(s: &str) -> bool {
    s.parse::<SocketAddr>()
        .map(|sa| sa.port() != 0 && is_global_unicast(&sa.ip()))
        .unwrap_or(false)
}

/// The business zone `agent`'s live connection on this pod was observed in
/// when it opened. `None` (no live connection here, or no zone) refuses.
pub(crate) fn agent_zone(state: &NetworkState, agent: &Agent) -> Option<BusinessZone> {
    let conn = state.org_relay.live_conn(agent.id?)?;
    let device = AuthenticatedDevice::from_agent(agent).ok()?;
    meshharbor_core::business_authority::connection_zone(&state.core, &device, &conn)
}

/// The business zone of the device behind an overlay node: its live
/// connection's opening observation on this pod. `None` (no live connection
/// here, or no zone) refuses wherever a zone gates anything — the auto relay
/// gate here, and the #21 isolation in netmap shaping.
///
/// GEO-04 — a zone the node's own advertised public addresses contradict is
/// no zone ([`addresses_agree`]).
pub(crate) async fn node_zone(state: &NetworkState, node: &OverlayNode) -> Option<BusinessZone> {
    let (zone, _) = observed_zone(state, node.tenant_id, &node.node_ref).await?;
    addresses_agree(state, node, zone).then_some(zone)
}

/// [`node_zone`] for a session party, known by its tenant and reference.
pub(crate) async fn party_zone(
    state: &NetworkState,
    tenant_id: ObjectId,
    node_ref: &NodeRef,
) -> Option<BusinessZone> {
    let (zone, machine_id) = observed_zone(state, tenant_id, node_ref).await?;
    match state
        .overlay_nodes
        .find_live_by_tenant_and_machine(tenant_id, &machine_id)
        .await
    {
        Ok(Some(node)) => addresses_agree(state, &node, zone).then_some(zone),
        // Not in the overlay: it advertised nothing to contradict the zone.
        _ => Some(zone),
    }
}

/// Fallback zone for a [`meshharbor_remote_control::models::TunnelClient`] on a
/// stateless HTTP request when no live `/ws?role=tunnel-client` connection is
/// open on this pod. Uses the request's [`meshharbor_core::client_ip::ConnectionOrigin`]
/// without writing to `live_conns` or `business_zones`, and still applies
/// [`addresses_agree`] if a live overlay node row exists for the client's machine.
/// Fails closed (`None`) if reading the overlay node row from storage fails.
pub(crate) async fn tunnel_client_request_zone(
    state: &NetworkState,
    client: &meshharbor_remote_control::models::TunnelClient,
    origin: &meshharbor_core::client_ip::ConnectionOrigin,
) -> Option<BusinessZone> {
    let zone = meshharbor_core::business_authority::origin_zone(&state.core, origin)?;
    let lookup = state
        .overlay_nodes
        .find_live_by_tenant_and_machine(client.tenant_id, &client.machine_id)
        .await;
    resolve_request_zone_with_overlay_lookup(
        client.tenant_id,
        &client.machine_id,
        zone,
        lookup,
        |node, z| addresses_agree(state, node, z),
    )
}

fn resolve_request_zone_with_overlay_lookup<T, E: std::fmt::Display>(
    tenant_id: ObjectId,
    machine_id: &str,
    zone: BusinessZone,
    lookup: Result<Option<T>, E>,
    agree: impl FnOnce(&T, BusinessZone) -> bool,
) -> Option<BusinessZone> {
    match lookup {
        Ok(Some(node)) => agree(&node, zone).then_some(zone),
        Ok(None) => Some(zone),
        Err(e) => {
            warn!(
                %tenant_id,
                machine_id,
                %e,
                "business isolation: overlay node lookup failed during tunnel-client request zone check; refusing"
            );
            None
        }
    }
}

/// The zone a device's live connection was observed in, and its machine id.
async fn observed_zone(
    state: &NetworkState,
    tenant_id: ObjectId,
    node_ref: &NodeRef,
) -> Option<(BusinessZone, String)> {
    match node_ref {
        NodeRef::Agent { agent_id } => {
            let agent = state
                .fleet
                .agents
                .find_live_in_tenant(tenant_id, *agent_id)
                .await
                .ok()?;
            Some((agent_zone(state, &agent)?, agent.machine_id))
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            let client = state
                .tunnel_clients
                .find_live_in_tenant(tenant_id, *tunnel_client_id)
                .await
                .ok()?;
            let conn = state.org_relay.live_conn(*tunnel_client_id)?;
            let device = AuthenticatedDevice::from_tunnel_client(&client).ok()?;
            let zone =
                meshharbor_core::business_authority::connection_zone(&state.core, &device, &conn)?;
            Some((zone, client.machine_id))
        }
    }
}

/// How often one node's conflicting addresses are logged.
const CONFLICT_LOG_GAP: Duration = Duration::from_secs(600);
static CONFLICT_LOGGED: std::sync::LazyLock<DashMap<ObjectId, Instant>> =
    std::sync::LazyLock::new(DashMap::new);

/// GEO-04 — whether every public address `node` advertised for its data
/// plane (its STUN-observed srflx candidates and its NIC's global addresses,
/// IPv4 and IPv6) geolocates to `zone` or to nothing known. A control
/// connection observed in one zone while the node's traffic leaves from the
/// other (a proxied control path, or a dual-stack host whose IPv6 exits
/// elsewhere) is conflicting evidence, and conflicting evidence is no zone.
fn addresses_agree(state: &NetworkState, node: &OverlayNode, zone: BusinessZone) -> bool {
    let conflict = node
        .srflx_endpoints
        .iter()
        .chain(&node.lan_endpoints)
        .filter_map(|e| e.parse::<SocketAddr>().ok())
        .map(|sa| sa.ip())
        .filter(is_global_unicast)
        .find(|ip| {
            meshharbor_core::business_authority::address_zone(&state.core, *ip)
                .is_some_and(|z| z != zone)
        });
    let Some(ip) = conflict else {
        return true;
    };
    if let Some(id) = node.id {
        let now = Instant::now();
        let quiet = CONFLICT_LOGGED
            .get(&id)
            .is_some_and(|t| now.duration_since(*t) < CONFLICT_LOG_GAP);
        if !quiet {
            CONFLICT_LOGGED.insert(id, now);
            warn!(node = %id, ?zone, %ip,
                "business isolation: the node's control connection and an address it advertised are in different zones; it has no zone");
        }
    }
    false
}

/// At most this many relays are offered to one member to probe.
const MAX_PROBE_TARGETS: usize = 16;

/// MeshHarbor #5 — the relays `member` may bind to, offered in its full
/// netmap so it measures its RTT to each before any session exists; the mint
/// then ranks a pair's relays by both members' RTT from the very first
/// session (until now it knew RTT only to relays it had minted for a member).
///
/// The member's half of [`plan_mint_candidates_reusing`]'s gates: the relay
/// serves, is online and primary, the member is granted it (explicitly, or
/// implicitly under `auto` inside the member's zone), and under `enforce` it
/// is in the member's zone. A pair's gates are re-checked at mint time; this
/// only decides which endpoints the member may learn and measure.
pub(crate) async fn probe_targets(
    state: &NetworkState,
    member: &OverlayNode,
    preloaded_lines: Option<&crate::business_isolation::Lines>,
) -> Vec<RelayProbeTargetWire> {
    let targets = probe_targets_inner(state, member, preloaded_lines).await;
    if let Some(id) = member.id {
        state.org_relay.offer_probes(id, &targets);
    }
    targets
}

async fn probe_targets_inner(
    state: &NetworkState,
    member: &OverlayNode,
    preloaded_lines: Option<&crate::business_isolation::Lines>,
) -> Vec<RelayProbeTargetWire> {
    use crate::business_isolation::{self as iso, Mode};
    let tenant_id = member.tenant_id;
    let Some(member_id) = member.id else {
        return Vec::new();
    };
    if !member.supports_org_relay
        || state.org_relay.join_extras(member_id).org_primary != Some(true)
    {
        return Vec::new();
    }
    let mode = peer_relay_mode(state, tenant_id).await;
    if !matches!(mode, PeerRelayMode::On | PeerRelayMode::Auto) {
        return Vec::new();
    }
    // Every read fails closed: nothing offered.
    let Ok(acl) = try_load_acl(state, tenant_id, PolicyLoad::Always).await else {
        return Vec::new();
    };
    let Ok(src) = try_overlay_source_of(state, member).await else {
        return Vec::new();
    };
    let Ok(mut relays) = state.fleet.agents.list_relay_approved(tenant_id).await else {
        return Vec::new();
    };
    let mut servers: Vec<ObjectId> = Vec::new();
    if mode == PeerRelayMode::Auto
        && let Ok(agents) =
            meshharbor_core::business_authority::current_server_agents(&state.core, tenant_id).await
    {
        for agent in agents {
            let Some(id) = agent.id else { continue };
            servers.push(id);
            if !relays.iter().any(|r| r.id == Some(id)) {
                relays.push(agent);
            }
        }
    }
    let iso_mode = iso::mode(state);
    let owned_topo;
    let topo = match preloaded_lines {
        Some(l) => l,
        None => {
            owned_topo = iso::lines(state, iso_mode, tenant_id).await;
            &owned_topo
        }
    };
    if iso_mode == Mode::Enforce && topo.roles_read_failed {
        return Vec::new();
    }
    if !topo.node_role_known(member) {
        if iso_mode == Mode::Enforce && topo.unknown_role == Mode::Enforce {
            return Vec::new();
        }
        if topo.unknown_role != Mode::Off {
            let unknown_devices = vec![iso::Lines::node_label(member)];
            iso::log_unknown_role_with_peers(tenant_id, "probe_targets", &unknown_devices);
        }
    }
    let member_zone = if iso_mode != Mode::Off || !servers.is_empty() {
        node_zone(state, member).await
    } else {
        None
    };
    let mut out = Vec::new();
    for agent in relays {
        if out.len() >= MAX_PROBE_TARGETS {
            break;
        }
        let Some(agent_id) = agent.id else { continue };
        let relay_ref = NodeRef::Agent { agent_id };
        if !topo.ref_role_known(&relay_ref) {
            if iso_mode == Mode::Enforce && topo.unknown_role == Mode::Enforce {
                continue;
            }
            if topo.unknown_role != Mode::Off {
                let unknown_devices = vec![iso::Lines::ref_label(&relay_ref)];
                iso::log_unknown_role_with_peers(
                    tenant_id,
                    "probe_targets_relay",
                    &unknown_devices,
                );
            }
        }
        if !agent.capabilities.has_rpc(RpcCap::RelayServer)
            || !state.fleet.rc_hub.is_agent_online(agent_id)
        {
            continue;
        }
        let Ok(Some(node)) = state
            .overlay_nodes
            .find_live_by_tenant_and_machine(tenant_id, &agent.machine_id)
            .await
        else {
            continue;
        };
        if !node.is_key_authorized_at(bson::DateTime::now()) {
            continue;
        }
        let Some(relay_id) = node.id else { continue };
        if relay_id == member_id {
            continue;
        }
        let extras = state.org_relay.join_extras(relay_id);
        if extras.org_primary != Some(true) || extras.relay_withdrawn {
            continue;
        }
        let relay_routes = node.effective_routes();
        let relay_ref = OverlayPeerRef {
            node_id: relay_id,
            overlay_ip: &node.overlay_ip,
            approved_routes: &relay_routes,
        };
        let relay_zone = agent_zone(state, &agent).filter(|z| addresses_agree(state, &node, *z));
        let granted = agent.peer_relay_policy.serve
            && evaluate_overlay(&acl.policies, &src, relay_ref).visible;
        let implicit = !granted
            && servers.contains(&agent_id)
            && relay_zone.is_some()
            && relay_zone == member_zone;
        if !granted && !implicit {
            continue;
        }
        if iso_mode == Mode::Enforce && (member_zone.is_none() || relay_zone != member_zone) {
            continue;
        }
        let port = extras.relay_port.unwrap_or(limits::DEFAULT_RELAY_PORT);
        let Ok(endpoints) = relay_endpoints(&node, port, &agent.peer_relay_policy.static_endpoints)
        else {
            continue;
        };
        if endpoints.is_empty() {
            continue;
        }
        out.push(RelayProbeTargetWire {
            relay_node_id: relay_id,
            endpoints: endpoints.into_iter().take(4).collect(),
        });
    }
    out
}

/// MeshHarbor #5 step B — the lines `relay` may carry a pair over, offered in
/// its full netmap so it measures each one's RTT on its backbone interface:
/// every approved backbone edge (at most [`MAX_PROBE_TARGETS`]) whose target
/// relay is approved and live here, at the edge's private endpoint. A relay
/// that is not backbone-ready gets none. Only what is offered here is
/// accepted back as a line's RTT ([`OrgRelayState::record_probe`]).
pub(crate) async fn backbone_probe_targets(
    state: &NetworkState,
    relay: &OverlayNode,
    preloaded_lines: Option<&crate::business_isolation::Lines>,
) -> Vec<RelayProbeTargetWire> {
    let targets = backbone_probe_targets_inner(state, relay, preloaded_lines).await;
    if let Some(id) = relay.id {
        state.org_relay.offer_backbone_probes(id, &targets);
    }
    targets
}

async fn backbone_probe_targets_inner(
    state: &NetworkState,
    relay: &OverlayNode,
    preloaded_lines: Option<&crate::business_isolation::Lines>,
) -> Vec<RelayProbeTargetWire> {
    let Some(relay_id) = relay.id else {
        return Vec::new();
    };
    if !state.org_relay.join_extras(relay_id).relay_backbone_ready {
        return Vec::new();
    }
    let iso_mode = crate::business_isolation::mode(state);
    let owned_topo;
    let topo = match preloaded_lines {
        Some(l) => l,
        None => {
            owned_topo = crate::business_isolation::lines(state, iso_mode, relay.tenant_id).await;
            &owned_topo
        }
    };
    if iso_mode == crate::business_isolation::Mode::Enforce && topo.roles_read_failed {
        return Vec::new();
    }
    if !topo.node_role_known(relay) {
        if iso_mode == crate::business_isolation::Mode::Enforce
            && topo.unknown_role == crate::business_isolation::Mode::Enforce
        {
            return Vec::new();
        }
        if topo.unknown_role != crate::business_isolation::Mode::Off {
            let unknown_devices = vec![crate::business_isolation::Lines::node_label(relay)];
            crate::business_isolation::log_unknown_role_with_peers(
                relay.tenant_id,
                "backbone_probe_targets",
                &unknown_devices,
            );
        }
    }
    let Ok(relays) = state
        .fleet
        .agents
        .list_relay_approved(relay.tenant_id)
        .await
    else {
        return Vec::new();
    };
    let Some(own) = relays.iter().find(|a| a.machine_id == relay.machine_id) else {
        return Vec::new();
    };
    let Ok(network) = state.overlay_networks.get_or_create(relay.tenant_id).await else {
        return Vec::new();
    };
    let mut out: Vec<RelayProbeTargetWire> = Vec::new();
    for edge in own
        .peer_relay_policy
        .approved_backbone_edges
        .iter()
        .take(meshharbor_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES)
    {
        if out.len() >= MAX_PROBE_TARGETS {
            break;
        }
        if !crate::routes::peer_relay::valid_backbone_endpoint(&edge.endpoint)
            || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                &edge.endpoint,
                &network.cidr,
            )
        {
            continue;
        }
        let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else {
            continue;
        };
        let Some(exit) = relays.iter().find(|a| a.id == Some(target)) else {
            continue;
        };
        let Ok(Some(exit_node)) = state
            .overlay_nodes
            .find_live_by_tenant_and_machine(relay.tenant_id, &exit.machine_id)
            .await
        else {
            continue;
        };
        if !exit_node.is_key_authorized_at(bson::DateTime::now()) {
            continue;
        }
        let Some(exit_id) = exit_node.id else {
            continue;
        };
        if !topo.node_role_known(&exit_node) {
            if iso_mode == crate::business_isolation::Mode::Enforce
                && topo.unknown_role == crate::business_isolation::Mode::Enforce
            {
                continue;
            }
            if topo.unknown_role != crate::business_isolation::Mode::Off {
                let unknown_devices =
                    vec![crate::business_isolation::Lines::node_label(&exit_node)];
                crate::business_isolation::log_unknown_role_with_peers(
                    relay.tenant_id,
                    "backbone_probe_targets_exit",
                    &unknown_devices,
                );
            }
        }
        if exit_id == relay_id || out.iter().any(|t| t.relay_node_id == exit_id) {
            continue;
        }
        out.push(RelayProbeTargetWire {
            relay_node_id: exit_id,
            endpoints: vec![edge.endpoint.clone()],
        });
    }
    out
}

/// Which zone a plan's relays must be in under #21 isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ZoneScope {
    /// The zone the pair shares (the rule).
    Pair,
    /// One side of a cross-border line: relays in this zone, explicit
    /// grants only (an implicit `auto` grant rests on one shared zone).
    Side(BusinessZone),
}

/// Shared candidate authorization (gates 2–4). Discovery only returns metadata;
/// the mint caller additionally applies gate 5 and audits its verdict.
async fn plan_mint(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Result<Plan, PeerRelayDenyReason> {
    plan_mint_candidates(state, requester, peer)
        .await?
        .into_iter()
        .next()
        .ok_or(PeerRelayDenyReason::NoRelay)
}

async fn plan_mint_candidates(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Result<Vec<Plan>, PeerRelayDenyReason> {
    plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Pair).await
}

/// The relay the planner would mint the pair on now, if any; a relay marked
/// lossy for the pair is not among the candidates.
pub(crate) async fn next_relay(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Option<ObjectId> {
    plan_mint_candidates(state, requester, peer)
        .await
        .ok()?
        .into_iter()
        .next()?
        .relay
        .id
}

// A per-preparation cap, shared across Side scopes. This is not a
// cross-request rate limiter and does not contain network addresses.
#[derive(Default)]
struct TrialUnknownZoneDiagnostics {
    logged: std::collections::HashSet<ObjectId>,
    suppressed: bool,
}
impl TrialUnknownZoneDiagnostics {
    fn filtered(&mut self, agent_id: ObjectId) {
        if self.logged.contains(&agent_id) {
            return;
        }
        if self.logged.len() < 16 {
            self.logged.insert(agent_id);
            warn!(relay_agent_id = %agent_id,
                reason = "zone_evidence_unavailable",
                "path trial candidate filtered: relay zone is unavailable");
        } else if !self.suppressed {
            self.suppressed = true;
            warn!("path trial: additional unknown-zone candidate diagnostics suppressed");
        }
    }
}

async fn plan_mint_candidates_reusing(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    reuse: Option<&OrgRelaySession>,
    scope: ZoneScope,
) -> Result<Vec<Plan>, PeerRelayDenyReason> {
    plan_mint_candidates_with_trial_diagnostics(state, requester, peer, reuse, scope, None).await
}

async fn plan_mint_candidates_with_trial_diagnostics(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    reuse: Option<&OrgRelaySession>,
    scope: ZoneScope,
    mut diagnostic: Option<&mut TrialUnknownZoneDiagnostics>,
) -> Result<Vec<Plan>, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let tenant_id = requester.tenant_id;
    if peer.tenant_id != tenant_id {
        return Err(D::CrossTenant);
    }
    let now_dt = bson::DateTime::now();
    if !requester.is_key_authorized_at(now_dt) {
        return Err(D::RequesterUnsupported);
    }
    if !peer.is_key_authorized_at(now_dt) {
        return Err(D::PeerUnsupported);
    }
    if !requester.supports_org_relay {
        return Err(D::RequesterUnsupported);
    }
    if !peer.supports_org_relay {
        return Err(D::PeerUnsupported);
    }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return Err(D::RequesterUnsupported);
    };
    if state.org_relay.join_extras(req_id).org_primary != Some(true)
        || state.org_relay.join_extras(peer_id).org_primary != Some(true)
    {
        return Err(D::SecondaryOrg);
    }
    // #21 — the pair must share one zone, and every candidate relay must be
    // in it (below): no grant, explicit or implicit, carries a pair across
    // the mainland line. Under `warn` both are only logged.
    use crate::business_isolation::{self as iso, Mode};
    let iso_mode = iso::mode(state);
    let unknown_role_mode = iso::unknown_role_mode(state);
    let approved_roles = if iso_mode == Mode::Enforce || unknown_role_mode != Mode::Off {
        match meshharbor_core::business_authority::current_approved_roles(&state.core, tenant_id)
            .await
        {
            Ok(roles) => (unknown_role_mode != Mode::Off).then_some(roles),
            Err(e) if iso_mode == Mode::Enforce => {
                warn!(%tenant_id, %e, "org-relay: approved device roles unreadable; refusing");
                return Err(D::PolicyUnreadable);
            }
            Err(_) => None,
        }
    } else {
        None
    };
    if let Some(roles) = approved_roles.as_ref() {
        let req_known = roles.contains_key(&iso::Lines::ref_identity(&requester.node_ref));
        let peer_known = roles.contains_key(&iso::Lines::ref_identity(&peer.node_ref));
        if !req_known || !peer_known {
            let mut unknown_devices = Vec::new();
            if !req_known {
                unknown_devices.push(iso::Lines::node_label(requester));
            }
            if !peer_known {
                unknown_devices.push(iso::Lines::node_label(peer));
            }
            if iso_mode == Mode::Enforce && unknown_role_mode == Mode::Enforce {
                warn!(
                    %tenant_id,
                    requester = %req_id,
                    peer = %peer_id,
                    ?unknown_devices,
                    "org-relay: refusing: unknown_role"
                );
                return Err(D::ZoneDenied);
            }
            iso::log_unknown_role_with_peers(tenant_id, "org_relay_pair", &unknown_devices);
        }
    }
    // Servers meet by their topology link instead; a linked pair may ride a
    // relay in either server's zone.
    let iso_zones: Vec<BusinessZone> = match (iso_mode, scope) {
        (Mode::Off, _) => Vec::new(),
        (_, ZoneScope::Side(z)) => vec![z],
        _ => iso::pair_permit(state, iso_mode, requester, peer)
            .await
            .relay_zones(),
    };
    if iso_mode != Mode::Off && iso_zones.is_empty() {
        if iso_mode == Mode::Enforce {
            warn!(%tenant_id, requester = %req_id, peer = %peer_id, "org-relay: pair not in one business zone; refusing");
            return Err(D::ZoneDenied);
        }
        info!(%tenant_id, requester = %req_id, peer = %peer_id, "org-relay [isolation warn]: would refuse a pair not in one business zone");
    }

    // Gate 2's inputs — every read fails CLOSED, each with the reason that
    // distinguishes "the rules said no" from "the rules could not be read".
    let acl = try_load_acl(state, tenant_id, PolicyLoad::Always)
        .await
        .map_err(|e| {
            warn!(%tenant_id, %e, "org-relay: policies unreadable; refusing");
            D::PolicyUnreadable
        })?;
    let req_src = try_overlay_source_of(state, requester).await.map_err(|e| {
        warn!(%tenant_id, node = %req_id, %e, "org-relay: requester identity unreadable; refusing");
        D::PolicyUnreadable
    })?;
    let peer_src = try_overlay_source_of(state, peer).await.map_err(|e| {
        warn!(%tenant_id, node = %peer_id, %e, "org-relay: peer identity unreadable; refusing");
        D::PolicyUnreadable
    })?;
    let mut relays = state
        .fleet
        .agents
        .list_relay_approved(tenant_id)
        .await
        .map_err(|e| {
            warn!(%tenant_id, %e, "org-relay: approved-relay list unreadable; refusing");
            D::PolicyUnreadable
        })?;
    // MeshHarbor `auto`: a device whose central Server role is current is a
    // candidate without gate 3, and stands in for gate 2 only inside one
    // business zone (below). An unreadable role list can only withhold an
    // implicit grant, never widen one.
    let mut servers: Vec<ObjectId> = Vec::new();
    let mut servers_unreadable = false;
    if peer_relay_mode(state, tenant_id).await == PeerRelayMode::Auto {
        match meshharbor_core::business_authority::current_server_agents(&state.core, tenant_id)
            .await
        {
            Ok(agents) => {
                for agent in agents {
                    let Some(id) = agent.id else { continue };
                    servers.push(id);
                    if !relays.iter().any(|r| r.id == Some(id)) {
                        relays.push(agent);
                    }
                }
            }
            Err(e) => {
                warn!(%tenant_id, %e, "org-relay: server roles unreadable; no implicit grant");
                servers_unreadable = true;
            }
        }
    }
    // The zone both members share, read once and only when an implicit grant
    // is in play: `Some(None)` = they share none.
    let mut member_zone: Option<Option<BusinessZone>> = None;

    let now = Instant::now();
    let pk = pair_key(req_id, peer_id);
    let mut candidates: Vec<Plan> = Vec::new();
    let mut loss_pinned_plans: Vec<Plan> = Vec::new();
    let mut acl_denied = 0usize;
    let mut zone_denied = 0usize;
    let mut bad_static = false;
    for agent in relays {
        let Some(agent_id) = agent.id else { continue };
        if let Some(roles) = approved_roles.as_ref()
            && !roles.contains_key(&(
                meshharbor_core::business_authority::DeviceKind::Agent,
                agent_id,
            ))
        {
            if iso_mode == Mode::Enforce && unknown_role_mode == Mode::Enforce {
                zone_denied += 1;
                continue;
            }
            let unknown_devices = vec![format!("agent:{agent_id}:{}", agent.name)];
            iso::log_unknown_role_with_peers(tenant_id, "org_relay_candidate", &unknown_devices);
        }
        // Gate 4 as the device last advertised it, and liveness on this pod.
        if !agent.capabilities.has_rpc(RpcCap::RelayServer)
            || !state.fleet.rc_hub.is_agent_online(agent_id)
        {
            continue;
        }
        let Ok(Some(node)) = state
            .overlay_nodes
            .find_live_by_tenant_and_machine(tenant_id, &agent.machine_id)
            .await
        else {
            continue;
        };
        if !node.is_key_authorized_at(bson::DateTime::now()) {
            continue;
        }
        let Some(relay_id) = node.id else { continue };
        if relay_id == req_id || relay_id == peer_id {
            continue;
        }
        // A relay a member measured lossy for this pair sits out its pin
        // while the pair has another relay to go to. Past its sole-retry
        // wait it is held aside rather than dropped, and offered only if no
        // other relay is left (else the pair sat on DERP for the whole pin).
        let loss_pinned = state.org_relay.is_lossy(&pk, relay_id, now);
        if loss_pinned && !state.org_relay.loss_pin_sole_retry_due(&pk, relay_id, now) {
            continue;
        }
        let extras = state.org_relay.join_extras(relay_id);
        // Serving is primary-only: a UDP listener is host-global.
        if extras.org_primary != Some(true) || extras.relay_withdrawn {
            continue;
        }
        if state.org_relay.sessions_on_relay(relay_id) >= limits::MAX_SESSIONS_PER_RELAY
            && !reuse.is_some_and(|session| session.relay_nodes().any(|node| node == relay_id))
        {
            continue;
        }
        // Gate 2 — BOTH members must be granted this relay; each binds to it.
        // FR-97 P0b — granted from the routes the relay OFFERS.
        let relay_routes = node.effective_routes();
        let relay_ref = OverlayPeerRef {
            node_id: relay_id,
            overlay_ip: &node.overlay_ip,
            approved_routes: &relay_routes,
        };
        let granted = agent.peer_relay_policy.serve
            && evaluate_overlay(&acl.policies, &req_src, relay_ref).visible
            && evaluate_overlay(&acl.policies, &peer_src, relay_ref).visible;
        // `auto`: requester, peer and relay all observed in ONE zone on their
        // live connections; unknown anywhere refuses (hard isolation).
        // GEO-04 — a relay is judged like any node: its own addresses can
        // contradict its connection's zone.
        let relay_zone = agent_zone(state, &agent).filter(|z| addresses_agree(state, &node, *z));
        let implicit = !granted
            && scope == ZoneScope::Pair
            && servers.contains(&agent_id)
            && {
                if member_zone.is_none() {
                    let a = node_zone(state, requester).await;
                    let b = node_zone(state, peer).await;
                    member_zone = Some(a.filter(|_| a == b));
                }
                debug!(%tenant_id, relay = %relay_id, ?relay_zone, ?member_zone, "org-relay: implicit grant zones");
                relay_zone.is_some() && member_zone == Some(relay_zone)
            };
        if !granted && !implicit {
            if agent.peer_relay_policy.serve {
                acl_denied += 1;
            } else {
                zone_denied += 1;
            }
            continue;
        }
        if iso_mode != Mode::Off && !relay_zone.is_some_and(|z| iso_zones.contains(&z)) {
            if iso_mode == Mode::Enforce {
                if granted
                    && relay_zone.is_none()
                    && node.tenant_id == tenant_id
                    && node.network_id == requester.network_id
                    && matches!(&node.node_ref, NodeRef::Agent { agent_id: owner } if *owner == agent_id)
                    && let Some(diagnostic) = diagnostic.as_deref_mut()
                {
                    diagnostic.filtered(agent_id);
                }
                zone_denied += 1;
                continue;
            }
            info!(%tenant_id, relay = %relay_id, "org-relay [isolation warn]: would skip a relay outside the pair's zone");
        }
        let port = extras.relay_port.unwrap_or(limits::DEFAULT_RELAY_PORT);
        let endpoints =
            match relay_endpoints(&node, port, &agent.peer_relay_policy.static_endpoints) {
                Ok(e) => e,
                Err(()) => {
                    bad_static = true;
                    continue;
                }
            };
        if endpoints.is_empty() {
            debug!(%tenant_id, relay = %relay_id, "org-relay: candidate has no public endpoint; skipped");
            continue;
        }
        let plan = Plan {
            relay: node,
            relay_agent_id: agent_id,
            endpoints,
            backbone_edges: agent.peer_relay_policy.approved_backbone_edges,
            implicit,
        };
        if loss_pinned {
            loss_pinned_plans.push(plan);
        } else {
            candidates.push(plan);
        }
    }
    if candidates.is_empty() && !loss_pinned_plans.is_empty() {
        info!(%tenant_id, %pk, relays = loss_pinned_plans.len(),
            "org-relay: only loss-pinned relays are left for the pair; retrying them before DERP");
        candidates = loss_pinned_plans;
    }
    if candidates.is_empty() {
        return Err(if bad_static {
            D::NonRoutableEndpoint
        } else if acl_denied > 0 {
            D::AclDenied
        } else if zone_denied > 0 {
            D::ZoneDenied
        } else if servers_unreadable {
            D::PolicyUnreadable
        } else {
            D::NoRelay
        });
    }

    // Rank by [`mint_class`], then RTT. Nothing is excluded: a stale negative
    // must not starve the only relay.
    candidates.sort_by_key(|c| {
        let relay_id = c.relay.id.unwrap_or_default();
        let (class, rtt) = rank_key(state, req_id, peer_id, relay_id, now);
        let class = mint_class(
            class,
            state.org_relay.is_unbound_demoted(&pk, relay_id, now),
        );
        (class, rtt, state.org_relay.sessions_on_relay(relay_id))
    });
    Ok(candidates)
}

/// A candidate relay's class for a pair's mint, best first: `0` both members
/// measured it reachable; `1` unmeasured; `2` its last session for this pair
/// never bound ([`UNBOUND_DEMOTE`]); `3` a member's newest measurement says
/// it cannot reach it (`measured` is [`rank_key`]'s class).
///
/// A relay a member measures unreachable NOW is tried after one that only
/// failed this pair a moment ago: the demotion is a guess about a relay
/// nobody saw fail, the measurement is not. The two used to share the last
/// class, and its tie went to the unreachable relay, because an unreachable
/// leg adds no RTT. A pair whose first relay had recovered inside the
/// demotion window was then re-minted onto its second relay while that one
/// was frozen (item 6: two failures less than `UNBOUND_DEMOTE` apart).
fn mint_class(measured: u8, unbound_demoted: bool) -> u8 {
    match (measured, unbound_demoted) {
        (2.., _) => 3,
        (_, true) => 2,
        (class, false) => class,
    }
}

/// A relay's rank for the pair `a`–`b`: its class (0 both measured it
/// reachable, 1 unmeasured, 2 someone measured it unreachable) and the
/// members' summed RTT.
fn rank_key(
    state: &NetworkState,
    a: ObjectId,
    b: ObjectId,
    relay_id: ObjectId,
    now: Instant,
) -> (u8, u32) {
    rank_legs([
        state.org_relay.probe_verdict(a, relay_id, now),
        state.org_relay.probe_verdict(b, relay_id, now),
    ])
}

/// Rank any number of measured legs using the worst reachability class,
/// followed by the sum of known RTTs. Unknown/unreachable legs add no RTT,
/// matching the existing one- and two-relay ranking policy.
fn rank_legs(legs: impl IntoIterator<Item = ProbeVerdict>) -> (u8, u32) {
    legs.into_iter()
        .fold((0, 0u32), |(class, rtt), leg| match leg {
            ProbeVerdict::Reachable(ms) => (class, rtt.saturating_add(ms)),
            ProbeVerdict::Unknown => (class.max(1), rtt),
            ProbeVerdict::Unreachable => (2, rtt),
        })
}

/// Whether `best` beats `current` by enough to move a live pair: both
/// members measured `best` reachable, and `current` unreachable, or both
/// measured it too and `best` is at least 20% and 10 ms faster. An unmeasured
/// `current` stays: half a round of reports is not a comparison.
fn clearly_better(best: (u8, u32), current: (u8, u32)) -> bool {
    best.0 == 0
        && (current.0 == 2
            || (current.0 == 0
                && u64::from(best.1) * 5 < u64::from(current.1) * 4
                && current.1 - best.1 >= 10))
}

/// MeshHarbor #5 — a pair minted before its members' probes landed (a member
/// that needs a relay right after its join asks before its first round is
/// back) went to an unmeasured relay. When a member's measurements arrive,
/// each of its pairs still inside the session's bind window moves to the
/// relay the planner now ranks [`clearly_better`]. A bound session is never
/// moved: past the bind window, choosing is the next mint's business.
async fn rerank_young(state: &NetworkState, reporter: &OverlayNode) {
    let Some(reporter_id) = reporter.id else {
        return;
    };
    let now = Instant::now();
    let young: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|e| e.hops.is_empty() && now < e.bind_by && e.member_index(reporter_id).is_some())
        .map(|e| e.value().clone())
        .collect();
    for session in young {
        let Some(peer_id) = session
            .members
            .iter()
            .map(|m| m.party.node_id)
            .find(|id| *id != reporter_id)
        else {
            continue;
        };
        let peer = match state.overlay_nodes.base.find_by_id(peer_id).await {
            Ok(p)
                if p.tenant_id == reporter.tenant_id
                    && p.deleted_at.is_none()
                    && p.is_key_authorized_at(bson::DateTime::now()) =>
            {
                p
            }
            _ => continue,
        };
        let Some(best) = next_relay(state, reporter, &peer).await else {
            continue;
        };
        let current_relay = session.relay.node_id;
        let (to, from) = (
            rank_key(state, reporter_id, peer_id, best, now),
            rank_key(state, reporter_id, peer_id, current_relay, now),
        );
        if best == current_relay || !clearly_better(to, from) {
            continue;
        }
        info!(pair = %session.pair_key, from_relay = %current_relay, ?from, to_relay = %best, ?to,
            "org-relay: the members' first measurements rank another relay clearly faster; moving the young pair");
        revoke_where(state, "org_relay_rerank", |s| {
            s.pair_key == session.pair_key
                && s.vni == session.vni
                && s.generation == session.generation
        })
        .await;
        maybe_mint(state, reporter, &peer).await;
    }
}

pub fn revoke_backbone_node_sync(
    state: &NetworkState,
    tenant: ObjectId,
    node: ObjectId,
    member_withdrawn: bool,
    ingress_withdrawn: bool,
) -> Vec<PeerRelayAuditEvent> {
    trial::revoke_backbone_node(state, tenant, node, member_withdrawn, ingress_withdrawn)
}

/// #21 — `node` stopped riding line-only peers, or (as an ingress relay)
/// stopped being backbone-ready: the lines it takes part in end.
pub fn revoke_line_node_sync(
    state: &NetworkState,
    tenant: ObjectId,
    node: ObjectId,
) -> Vec<PeerRelayAuditEvent> {
    revoke_matching_sync(state, "backbone_capability_withdrawn", |s| {
        s.tenant_id == tenant && !s.hops.is_empty() && s.involves(node)
    })
}

/// `source`'s approved edges changed: end affected lines and trials when an
/// edge disappears or loses an approval required by that particular edge.
pub fn revoke_removed_backbone_edges_sync(
    state: &NetworkState,
    tenant: ObjectId,
    source: ObjectId,
    approved: &[meshharbor_remote_control::models::PeerRelayBackboneEdge],
) -> Vec<PeerRelayAuditEvent> {
    let mut events = trial::revoke_removed_backbone_edges(state, tenant, source, approved);
    events.extend(revoke_matching_sync(state, "backbone_edge_revoked", |s| {
        s.tenant_id == tenant && s.has_removed_line_edge(source, approved)
    }));
    events
}

/// The audit `reason` of a mint planned over a cross-border line (#21).
pub const CROSS_BORDER_REASON: &str = "cross_border_line";

/// The zone pairs the tenant's approved cross-border lines connect: an
/// approved relay with a `cross_border` edge to another approved relay, both
/// live here with a known zone, and the zones different.
pub(crate) async fn cross_border_lines(
    state: &NetworkState,
    tenant_id: ObjectId,
) -> Vec<(BusinessZone, BusinessZone)> {
    cross_border_lines_with_roles(state, tenant_id, None).await
}

pub(crate) type PreloadedRoles<'a> = (
    &'a std::collections::HashSet<(meshharbor_core::business_authority::DeviceKind, ObjectId)>,
    crate::business_isolation::Mode,
    bool,
);

pub(crate) async fn cross_border_lines_with_roles(
    state: &NetworkState,
    tenant_id: ObjectId,
    preloaded_roles: Option<PreloadedRoles<'_>>,
) -> Vec<(BusinessZone, BusinessZone)> {
    let Ok(relays) = state.fleet.agents.list_relay_approved(tenant_id).await else {
        return Vec::new();
    };
    let owned_roles: std::collections::HashSet<(
        meshharbor_core::business_authority::DeviceKind,
        ObjectId,
    )>;
    let (approved_roles, unknown_role_mode, roles_read_failed) = match preloaded_roles {
        Some((set, mode, failed)) => {
            if crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce {
                (
                    (mode != crate::business_isolation::Mode::Off).then_some(set),
                    mode,
                    failed,
                )
            } else {
                (None, mode, false)
            }
        }
        None => {
            let mode = crate::business_isolation::unknown_role_mode(state);
            if crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce
                && mode != crate::business_isolation::Mode::Off
            {
                match meshharbor_core::business_authority::current_approved_roles(
                    &state.core,
                    tenant_id,
                )
                .await
                {
                    Ok(map) => {
                        owned_roles = map.into_keys().collect();
                        (Some(&owned_roles), mode, false)
                    }
                    Err(_) => {
                        owned_roles = std::collections::HashSet::new();
                        (Some(&owned_roles), mode, true)
                    }
                }
            } else {
                (None, mode, false)
            }
        }
    };
    if roles_read_failed
        && crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce
    {
        return Vec::new();
    }
    let mut unknown_relays = Vec::new();
    let role_ok = |agent_id: ObjectId, unknown: &mut Vec<String>| -> bool {
        let Some(approved) = approved_roles else {
            return true;
        };
        if roles_read_failed && unknown_role_mode != crate::business_isolation::Mode::Enforce {
            return true;
        }
        if approved.contains(&(
            meshharbor_core::business_authority::DeviceKind::Agent,
            agent_id,
        )) {
            true
        } else {
            let label = format!("agent:{agent_id}");
            if !unknown.contains(&label) {
                unknown.push(label);
            }
            unknown_role_mode != crate::business_isolation::Mode::Enforce
        }
    };
    let mut out = Vec::new();
    for r in &relays {
        let Some(r_id) = r.id else { continue };
        if !role_ok(r_id, &mut unknown_relays) {
            continue;
        }
        let mut edges = r
            .peer_relay_policy
            .approved_backbone_edges
            .iter()
            .filter(|e| e.cross_border)
            .peekable();
        if edges.peek().is_none() {
            continue;
        }
        let Some(from) = agent_zone(state, r) else {
            continue;
        };
        for e in edges {
            let Ok(t) = ObjectId::parse_str(&e.relay_agent_id) else {
                continue;
            };
            if !role_ok(t, &mut unknown_relays) {
                continue;
            }
            let Some(to) = relays
                .iter()
                .find(|x| x.id == Some(t))
                .and_then(|x| agent_zone(state, x))
            else {
                continue;
            };
            if from != to && !out.contains(&(from, to)) {
                out.push((from, to));
            }
        }
    }
    if unknown_role_mode == crate::business_isolation::Mode::Warn && !unknown_relays.is_empty() {
        crate::business_isolation::log_unknown_role_with_peers(
            tenant_id,
            "cross_border_lines",
            &unknown_relays,
        );
    }
    out
}

/// The two zones of a pair that only a cross-border line may carry: both
/// known, different, and the rule enforced. `None` means the ordinary rule
/// applies (one zone, or `warn`/`off`, which refuse nothing).
async fn cross_border_zones(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Option<(BusinessZone, BusinessZone)> {
    use crate::business_isolation as iso;
    let mode = iso::mode(state);
    if mode != iso::Mode::Enforce {
        return None;
    }
    let (za, zb) = (
        iso::zone_of(state, mode, requester).await?,
        iso::zone_of(state, mode, peer).await?,
    );
    (za != zb).then_some((za, zb))
}

/// A cross-border line for a pair (#21 rule 2): an approved relay in one
/// member's zone with an approved `cross_border` edge to an approved relay in
/// the other's, each explicitly granted to both members. The edge's source
/// holds the bridge, so whichever
/// member asked, the member in the source's zone binds there.
struct LinePlan {
    ingress: Plan,
    exit: Plan,
    private_endpoint: String,
    /// The member in the ingress relay's zone is the peer, not the requester.
    flipped: bool,
}

async fn plan_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    (za, zb): (BusinessZone, BusinessZone),
) -> Result<LinePlan, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let (Some(a), Some(b)) = (requester.id, peer.id) else {
        return Err(D::RequesterUnsupported);
    };
    // The exception applies only where a line connects the two zones, toward
    // members that both ride line-only peers (rule 4: a line to a member
    // that cannot would be a session nobody binds). Anywhere else the zone
    // rule's own refusal stands.
    let connected = cross_border_lines(state, requester.tenant_id)
        .await
        .iter()
        .any(|&line| line == (za, zb) || line == (zb, za));
    if !connected
        || !state.org_relay.join_extras(a).supports_backbone_only_v1
        || !state.org_relay.join_extras(b).supports_backbone_only_v1
    {
        return Err(D::ZoneDenied);
    }
    let network = state
        .overlay_networks
        .get_or_create(requester.tenant_id)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    if network.mtu > limits::BACKBONE_MAX_OVERLAY_MTU {
        return Err(D::ZoneDenied);
    }
    let side_a =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(za)).await;
    let side_b =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(zb)).await;
    // #5 step B: every usable line, ranked by the path a packet rides.
    let mut found: Vec<LinePlan> = Vec::new();
    for (ingresses, exits, flipped) in [(&side_a, &side_b, false), (&side_b, &side_a, true)] {
        let (Ok(ingresses), Ok(exits)) = (ingresses, exits) else {
            continue;
        };
        for ingress in ingresses {
            let Some(ingress_id) = ingress.relay.id else {
                continue;
            };
            if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                continue;
            }
            for edge in ingress
                .backbone_edges
                .iter()
                .take(meshharbor_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES)
                .filter(|e| e.cross_border)
            {
                if !crate::routes::peer_relay::valid_backbone_endpoint(&edge.endpoint)
                    || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                        &edge.endpoint,
                        &network.cidr,
                    )
                {
                    continue;
                }
                let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else {
                    continue;
                };
                if let Some(exit) = exits.iter().find(|p| p.relay_agent_id == target) {
                    found.push(LinePlan {
                        ingress: ingress.clone(),
                        exit: exit.clone(),
                        private_endpoint: edge.endpoint.clone(),
                        flipped,
                    });
                }
            }
        }
    }
    let now = Instant::now();
    if let Some(best) = found
        .into_iter()
        .enumerate()
        .min_by_key(|(i, plan)| (line_rank_key(state, a, b, plan, now), *i))
        .map(|(_, plan)| plan)
    {
        return Ok(best);
    }
    // A side's own refusal names its gate; two usable sides with no line
    // between them are what the zone rule refuses.
    match (side_a, side_b) {
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Err(D::ZoneDenied),
    }
}

/// A line's rank for the pair `requester`–`peer` (#5 step B), over the three
/// legs a packet rides: the member in the ingress relay's zone to that relay,
/// the line itself (as the ingress relay measured it on its backbone
/// interface), and the exit relay to the other member. Class 0 when all three
/// were measured reachable, 1 when one is unmeasured, 2 when one was measured
/// unreachable (last, not excluded: a stale negative must not strand a pair
/// whose only line it is); then the summed RTT, then both relays' load.
fn line_rank_key(
    state: &NetworkState,
    requester: ObjectId,
    peer: ObjectId,
    plan: &LinePlan,
    now: Instant,
) -> (u8, u32, usize) {
    let (Some(ingress), Some(exit)) = (plan.ingress.relay.id, plan.exit.relay.id) else {
        return (2, u32::MAX, usize::MAX);
    };
    let (near, far) = if plan.flipped {
        (peer, requester)
    } else {
        (requester, peer)
    };
    let o = &state.org_relay;
    let legs = [
        o.probe_verdict(near, ingress, now),
        o.backbone_verdict(ingress, exit, now),
        o.probe_verdict(far, exit, now),
    ];
    let (class, rtt) = rank_legs(legs);
    (
        class,
        rtt,
        o.sessions_on_relay(ingress) + o.sessions_on_relay(exit),
    )
}

/// `relay_request` / fallback for a pair only a line may carry: re-push the
/// live line to the asker while it can still bind, else mint one (or audit
/// the refusal). A member asks only while it has no working carrier, so a
/// line past its bind window is revoked and minted afresh, as a fallback
/// does for a one-hop session.
async fn maybe_mint_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    zones: (BusinessZone, BusinessZone),
    warn_only: bool,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let pk = pair_key(req_id, peer_id);
    if !warn_only && let Some(s) = state.org_relay.active_session(&pk) {
        if s.member_index(req_id).is_none() {
            return;
        }
        let zones_fit = if s.hops.is_empty() {
            false
        } else {
            match session_zone::check(state, &s).await {
                session_zone::Decision::Uncertain { .. } => return,
                session_zone::Decision::Fits => true,
                session_zone::Decision::Invalid => false,
            }
        };
        if zones_fit && Instant::now() + BIND_REUSE_MARGIN < s.bind_by {
            match path_mint::repush(state, requester, peer, &s).await {
                path_mint::RepushOutcome::Sent | path_mint::RepushOutcome::Unavailable => return,
                path_mint::RepushOutcome::Denied => {}
            }
        }
        revoke_where(state, "org-line-rebind", |c| {
            c.pair_key == pk && c.vni == s.vni && c.generation == s.generation
        })
        .await;
    }
    let mut charged_relay = None;
    match path_mint::mint(state, requester, peer, warn_only, false, &mut charged_relay).await {
        Ok(true) => return,
        Ok(false) => {}
        Err(reason) => {
            // A failed long path is not evidence that a freshly authorized
            // established two-relay line is unusable.
            debug!(%tenant_id, requester = %req_id, peer = %peer_id, ?reason,
                "org-relay: multi-hop attempt failed; replanning the two-relay line");
        }
    }
    let line_epoch = state.org_relay.eligibility_generation();
    match plan_line(state, requester, peer, zones).await {
        Ok(plan) => {
            mint_line(
                state,
                requester,
                peer,
                plan,
                warn_only,
                line_epoch,
                charged_relay,
            )
            .await
        }
        Err(reason) => {
            info!(%tenant_id, requester = %req_id, peer = %peer_id, ?reason, warn_only,
                "org-relay: cross-border line refused");
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                warn_only,
                Some(reason),
            )
            .await;
        }
    }
}

/// Mint a cross-border line (#21): the ingress relay serves `members[0]` and
/// the bridge, the exit relay serves the bridge and `members[1]`, and the
/// ingress relay's bridge joins the two sessions over the private line. Each
/// member is pushed only its own relay and rides it as an ordinary org-relay
/// session; WireGuard stays end to end, the relays see ciphertext. Both legs
/// are audited `cross_border_line` (rule 5).
async fn mint_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    plan: LinePlan,
    warn_only: bool,
    plan_epoch: u64,
    charged_relay: Option<ObjectId>,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let pk = pair_key(req_id, peer_id);
    let (Some(ingress_id), Some(exit_id)) = (plan.ingress.relay.id, plan.exit.relay.id) else {
        return;
    };
    let refuse = |reason| {
        audit_mint(
            state,
            tenant_id,
            req_id,
            peer_id,
            None,
            None,
            warn_only,
            Some(reason),
        )
    };
    if !warn_only
        && charged_relay != Some(ingress_id)
        && !state
            .relay_rate_limiter
            .check(req_id, ingress_id, limits::MINT_RATE_LIMIT_PER_MINUTE)
    {
        refuse(PeerRelayDenyReason::RateLimited).await;
        return;
    }
    // Warn uses tentative values only for its audit; a real mint allocates
    // under the shared claim lock below. The placeholder is never sent.
    let (vni, exit_vni) = if warn_only {
        let (Some(vni), Some(exit_vni)) = (
            state.org_relay.alloc_vni(ingress_id),
            state.org_relay.alloc_vni(exit_id),
        ) else {
            refuse(PeerRelayDenyReason::NoRelay).await;
            return;
        };
        (vni, exit_vni)
    } else {
        (1, 1)
    };
    let (m0, m1) = if plan.flipped {
        (peer, requester)
    } else {
        (requester, peer)
    };
    let member = |n: &OverlayNode| SessionMember {
        party: SessionParty {
            node_id: n.id.unwrap_or_default(),
            node_ref: n.node_ref.clone(),
        },
        wg_public_key: n.wg_public_key.clone(),
        bind_secret: random_secret(),
    };
    let now = Instant::now();
    let generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let exit_generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let mut session = OrgRelaySession {
        tenant_id,
        pair_key: pk.clone(),
        vni,
        generation,
        relay: SessionParty {
            node_id: ingress_id,
            node_ref: plan.ingress.relay.node_ref.clone(),
        },
        relay_agent_id: plan.ingress.relay_agent_id,
        implicit: false,
        members: [member(m0), member(m1)],
        endpoints: plan.ingress.endpoints.clone(),
        expires_at: now + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
        bind_by: now + Duration::from_secs(u64::from(limits::BIND_SECS)),
        hops: vec![LineLeg {
            relay: SessionParty {
                node_id: exit_id,
                node_ref: plan.exit.relay.node_ref.clone(),
            },
            relay_agent_id: plan.exit.relay_agent_id,
            vni: exit_vni,
            generation: exit_generation,
            endpoints: plan.exit.endpoints.clone(),
            private_endpoint: plan.private_endpoint.clone(),
            requires_cross_border_approval: true,
            bridge_id: ObjectId::new(),
            bridge_secrets: [random_secret(), random_secret()],
        }],
    };
    // This established entry point handles precisely one bridge; longer paths
    // use path_mint and must not enter this two-relay message flow.
    if session.hops.len() != 1 {
        return;
    }
    match path_delivery::build(&session, Instant::now()) {
        Ok(_) => {}
        Err(error) => {
            warn!(?error, "org-relay: invalid line delivery shape");
            refuse(PeerRelayDenyReason::PolicyUnreadable).await;
            return;
        }
    };
    if warn_only {
        let _ = audit_line(state, &session, true).await;
        info!(%tenant_id, requester = %req_id, peer = %peer_id, ingress = %ingress_id,
            exit = %exit_id, "org-relay [warn]: would mint a cross-border line; pushing nothing");
        return;
    }
    #[cfg(feature = "path-planner-test-support")]
    candidate_test_support::pause_line_preclaim_if_armed(&pk).await;
    // Share the trial admission lock so no other local claim can take the
    // same remaining capacity between the check and this session's insert.
    // Note: `plan_epoch` is checked inside the `claim_mint` closure so that if
    // a concurrent N-hop trial won the pair while we were paused, `claim_mint`
    // still returns `MintClaim::Existing` and runs `reauthorize_concurrent_winner`.
    let mut delivery = None;
    let mut epoch_stale = false;
    let current = match trial::claim_mint(&state.org_relay, &mut session, |allocated| {
        if plan_epoch != state.org_relay.eligibility_generation() {
            epoch_stale = true;
            return false;
        }
        delivery = path_delivery::build(allocated, Instant::now()).ok();
        delivery.is_some()
    }) {
        trial::MintClaim::Existing(existing) => Some(existing),
        trial::MintClaim::Inserted => None,
        trial::MintClaim::Full => {
            refuse(PeerRelayDenyReason::NoRelay).await;
            return;
        }
        trial::MintClaim::Rejected => {
            if !epoch_stale {
                refuse(PeerRelayDenyReason::PolicyUnreadable).await;
            }
            return;
        }
    };
    if let Some(current) = current {
        if !current.hops.is_empty() {
            reauthorize_concurrent_winner(state, requester, peer, &current).await;
            return;
        }
        if let Some(i) = current.member_index(req_id) {
            push_member(state, &current, i).await;
        }
        return;
    }
    let Some(delivery) = delivery else { return };
    let (vni, exit_vni) = (session.vni, session.hops[0].vni);
    if !audit_line(state, &session, false).await {
        // A concurrent retry could have received the just-claimed session;
        // revoke it before refusing rather than leave any unrecorded path.
        revoke_where(state, "cross_border_audit_failed", |current| {
            current.pair_key == pk
                && current.vni == session.vni
                && current.generation == session.generation
        })
        .await;
        refuse(PeerRelayDenyReason::PolicyUnreadable).await;
        return;
    }
    if !state.org_relay.active_session(&pk).is_some_and(|current| {
        current.vni == session.vni && current.generation == session.generation
    }) {
        return;
    }
    info!(%tenant_id, requester = %req_id, peer = %peer_id, ingress = %ingress_id, vni,
        exit = %exit_id, exit_vni, line = %session.hops[0].private_endpoint,
        "org-relay: a cross-border pair rides its approved line");
    // Send every relay control message before bridge control messages.
    // Delivery is asynchronous; bridges retry until both sides are ready.
    // Member grants remain last.
    for (target, message) in delivery.relays.into_iter().chain(delivery.bridges) {
        send_to_node_ref(state, &target, message).await;
    }
    push_member(state, &session, 0).await;
    push_member(state, &session, 1).await;
}

/// Rule 5: one `mint` row per leg of a line, each naming its relay and VNI,
/// with reason `cross_border_line`.
async fn audit_line(state: &NetworkState, s: &OrgRelaySession, warn_only: bool) -> bool {
    if s.hops.is_empty() {
        return false;
    }
    #[cfg(feature = "path-planner-test-support")]
    if candidate_test_support::take_line_audit_failure(&s.pair_key) {
        return false;
    }
    let relays = std::iter::once((s.relay_agent_id, s.relay.node_id, s.vni)).chain(
        s.hops
            .iter()
            .map(|hop| (hop.relay_agent_id, hop.relay.node_id, hop.vni)),
    );
    for (agent_id, relay_node_id, vni) in relays {
        let event = PeerRelayAuditEvent {
            id: None,
            tenant_id: s.tenant_id,
            action: PeerRelayAuditAction::Mint,
            agent_id: Some(agent_id),
            user_id: None,
            requester_node_id: Some(s.members[0].party.node_id),
            peer_node_id: Some(s.members[1].party.node_id),
            relay_node_id: Some(relay_node_id),
            serve: None,
            vni: Some(vni),
            warn_only,
            at: DateTime::now(),
            denied: None,
            reason: Some(CROSS_BORDER_REASON.into()),
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), state.peer_relay_audit.record(event))
                .await,
            Ok(Ok(_))
        ) {
            warn!("org-relay: cross-border audit write failed or timed out");
            return false;
        }
    }
    true
}

/// Cross-border hints are metadata only. The cursor page is rebuilt from
/// fresh side-authorized plans and keeps only a bounded page while scanning.
async fn cross_border_hints(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    overlay_cidr: &str,
    cursor: Option<OrgRelayDiscoveryCursorWire>,
) -> (
    Vec<OrgRelayCandidateWire>,
    Option<OrgRelayDiscoveryCursorWire>,
) {
    let Some((za, zb)) = cross_border_zones(state, requester, peer).await else {
        return (Vec::new(), None);
    };
    let Ok(ingresses) =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(za)).await
    else {
        return (Vec::new(), None);
    };
    let Ok(exits) =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(zb)).await
    else {
        return (Vec::new(), None);
    };
    let hints = ingresses
        .iter()
        .filter_map(|ingress| {
            let ingress_id = ingress.relay.id?;
            state
                .org_relay
                .join_extras(ingress_id)
                .relay_backbone_ready
                .then_some((ingress_id, ingress))
        })
        .flat_map(|(ingress_id, ingress)| {
            let exits = &exits;
            ingress
                .backbone_edges
                .iter()
                .take(8)
                .filter_map(move |edge| {
                    if !edge.cross_border
                        || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                            &edge.endpoint,
                            overlay_cidr,
                        )
                    {
                        return None;
                    }
                    let target = ObjectId::parse_str(&edge.relay_agent_id).ok()?;
                    let exit = exits.iter().find(|p| p.relay_agent_id == target)?;
                    Some(OrgRelayCandidateWire {
                        path: RelayPathWire::new(vec![ingress_id, exit.relay.id?]).ok()?,
                        requester_at_exit: false,
                        endpoints: ingress.endpoints.iter().take(4).cloned().collect(),
                    })
                })
        });
    if let Some(cursor) = cursor {
        discovery_page(hints, cursor)
    } else {
        (hints.take(2).collect(), None)
    }
}

fn discovery_key(c: &OrgRelayCandidateWire) -> OrgRelayDiscoveryCursorWire {
    c.cursor()
}
fn discovery_cursor(c: &OrgRelayCandidateWire) -> OrgRelayDiscoveryCursorWire {
    c.cursor()
}
/// At most six hints retained while scanning the already-authorized planner.
/// Ring order provides coverage; output order remains planner preference order.
fn discovery_page(
    hints: impl Iterator<Item = OrgRelayCandidateWire>,
    cursor: OrgRelayDiscoveryCursorWire,
) -> (
    Vec<OrgRelayCandidateWire>,
    Option<OrgRelayDiscoveryCursorWire>,
) {
    let key = cursor;
    let mut first = Vec::new();
    let mut after = Vec::new();
    for (rank, hint) in hints.enumerate() {
        let k = discovery_key(&hint);
        fn keep(
            window: &mut Vec<(usize, OrgRelayCandidateWire)>,
            rank: usize,
            hint: OrgRelayCandidateWire,
        ) {
            if window
                .iter()
                .any(|(_, c)| discovery_key(c) == discovery_key(&hint))
            {
                return;
            }
            window.push((rank, hint));
            window.sort_by_key(|(_, c)| discovery_key(c));
            window.truncate(3);
        }
        keep(&mut first, rank, hint.clone());
        if k > key {
            keep(&mut after, rank, hint);
        }
    }
    for entry in first {
        if after.len() == 3 {
            break;
        }
        if !after
            .iter()
            .any(|(_, c)| discovery_key(c) == discovery_key(&entry.1))
        {
            after.push(entry);
        }
    }
    // Last traversed, NOT maximum key: a page may wrap through the origin.
    let next = after.last().map(|(_, c)| discovery_cursor(c));
    after.sort_by_key(|(rank, _)| *rank);
    (after.into_iter().map(|(_, c)| c).collect(), next)
}

/// Return a short-lived selection hint using the SAME candidate authorization
/// as session minting. No VNI, secret, session, TURN allocation, or peer push.
/// The caller already bounded requests and checked the pair's visibility.
pub async fn discover(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    request_id: u64,
    cursor: Option<OrgRelayDiscoveryCursorWire>,
    scan: Option<meshharbor_remote_control::signaling::OrgRelayDiscoveryScanWire>,
) {
    let Some(peer_id) = peer.id else { return };
    let mut candidates = Vec::new();
    let extras = requester
        .id
        .map(|id| state.org_relay.join_extras(id))
        .unwrap_or_default();
    let traversal =
        extras.supports_org_relay_multi_candidate && extras.supports_org_relay_discovery_cursor;
    use meshharbor_remote_control::signaling::OrgRelayDiscoveryScanWire as Scan;
    if traversal
        && let Some(Scan::Progress {
            scan_next: true,
            checkpoint,
            after,
        }) = scan.as_ref()
    {
        let (candidates, progress) =
            path_discovery_page::page(state, requester, peer, checkpoint.as_ref(), after.as_ref())
                .await;
        send_to_node(
            state,
            requester,
            ServerMsg::OverlayOrgRelayCandidates {
                peer_node_id: peer_id,
                request_id,
                candidates,
                ttl_secs: 30,
                next_cursor: None,
                scan: Some(progress),
            },
        )
        .await;
        return;
    }
    let mut next_cursor = None;
    let mut backbone_cidr = None;
    let enabled = matches!(
        peer_relay_mode(state, requester.tenant_id).await,
        PeerRelayMode::On | PeerRelayMode::Auto
    );
    if enabled {
        let path_caps = requester
            .id
            .is_some_and(|id| state.org_relay.join_extras(id).supports_path_backbone_v1)
            && state
                .org_relay
                .join_extras(peer_id)
                .supports_path_backbone_v1;
        let path_network = if path_caps {
            state
                .overlay_networks
                .get_or_create(requester.tenant_id)
                .await
                .ok()
                .filter(|n| n.mtu <= limits::BACKBONE_MAX_OVERLAY_MTU)
        } else {
            None
        };
        if let Some(path_network) = path_network.as_ref() {
            // A cross-border pair gets only its line's hints.
            candidates.extend(
                cross_border_hints(state, requester, peer, &path_network.cidr, None)
                    .await
                    .0,
            );
        }
        if let Some(path_network) = path_network {
            backbone_cidr = Some(path_network.cidr.clone());
            if let Ok(plans) = plan_mint_candidates(state, requester, peer).await {
                // Ordering is only a discovery hint, NEVER a path-quality
                // decision. A bilateral same-metric trial must prove the full
                // path including the private backbone before application use.
                'sources: for ingress in &plans {
                    let Some(ingress_id) = ingress.relay.id else {
                        continue;
                    };
                    if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                        continue;
                    }
                    for edge in ingress.backbone_edges.iter().take(8) {
                        if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                            &edge.endpoint,
                            &path_network.cidr,
                        ) {
                            continue;
                        }
                        let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else {
                            continue;
                        };
                        let Some(exit) = plans
                            .iter()
                            .find(|p| p.relay_agent_id == target && p.relay.id != Some(ingress_id))
                        else {
                            continue;
                        };
                        let Some(path) = exit
                            .relay
                            .id
                            .and_then(|id| RelayPathWire::new(vec![ingress_id, id]).ok())
                        else {
                            continue;
                        };
                        candidates.push(OrgRelayCandidateWire {
                            path,
                            requester_at_exit: false,
                            endpoints: ingress.endpoints.iter().take(4).cloned().collect(),
                        });
                        if candidates.len() >= 2 {
                            break 'sources;
                        }
                    }
                }
            }
        }
        if requester.id.is_some_and(|id| {
            state
                .org_relay
                .join_extras(id)
                .supports_org_relay_multi_candidate
        }) {
            // Metadata only: preserve the existing authorized ordering, and
            // fill unused slots after the original (at most two) backbone
            // hints. Failure/cooldown and trials remain client-owned; discovery
            // never establishes or promotes a path. Old clients retain their
            // exact single-one-hop response because they reject this shape.
            if let Ok(plans) = plan_mint_candidates(state, requester, peer).await {
                for plan in plans {
                    if candidates.len() >= 3 {
                        break;
                    }
                    let Some(relay_node_id) = plan.relay.id else {
                        continue;
                    };
                    if candidates
                        .iter()
                        .any(|c| c.path.relay_node_ids() == [relay_node_id] && !c.requester_at_exit)
                    {
                        continue;
                    }
                    candidates.push(OrgRelayCandidateWire {
                        path: RelayPathWire::new(vec![relay_node_id]).expect("one relay"),
                        requester_at_exit: false,
                        endpoints: plan.endpoints.into_iter().take(4).collect(),
                    });
                }
            }
        } else if let Ok(plan) = plan_mint(state, requester, peer).await
            && let Some(relay_node_id) = plan.relay.id
        {
            candidates.push(OrgRelayCandidateWire {
                path: RelayPathWire::new(vec![relay_node_id]).expect("one relay"),
                requester_at_exit: false,
                endpoints: plan.endpoints.into_iter().take(4).collect(),
            });
        }
    }
    if traversal && enabled {
        if let Some(cursor) = cursor {
            if let Some(zones) = cross_border_zones(state, requester, peer).await {
                // A cross-zone pair has no Pair-scope single-relay plan. Build
                // each page from newly authorized Side-scope lines instead.
                let epoch = state.org_relay.eligibility_generation();
                let current_caps = requester
                    .id
                    .is_some_and(|id| state.org_relay.join_extras(id).supports_path_backbone_v1)
                    && state
                        .org_relay
                        .join_extras(peer_id)
                        .supports_path_backbone_v1;
                let current_network = if current_caps {
                    state
                        .overlay_networks
                        .get_or_create(requester.tenant_id)
                        .await
                        .ok()
                        .filter(|n| n.mtu <= limits::BACKBONE_MAX_OVERLAY_MTU)
                } else {
                    None
                };
                if let Some(network) = current_network {
                    (candidates, next_cursor) =
                        cross_border_hints(state, requester, peer, &network.cidr, Some(cursor))
                            .await;
                } else {
                    candidates.clear();
                }
                #[cfg(feature = "path-planner-test-support")]
                if let Some(requester_id) = requester.id {
                    candidate_test_support::pause_cross_discovery_if_armed(&pair_key(
                        requester_id,
                        peer_id,
                    ))
                    .await;
                }
                let current_zones = cross_border_zones(state, requester, peer).await;
                let current_mode = peer_relay_mode(state, requester.tenant_id).await;
                if current_zones != Some(zones)
                    || !matches!(current_mode, PeerRelayMode::On | PeerRelayMode::Auto)
                    || epoch != state.org_relay.eligibility_generation()
                {
                    candidates.clear();
                    next_cursor = None;
                }
            } else {
                // Existing two-hop scope is unchanged: only the original at-most-two
                // backbone hints participate. All one-hop plans are freshly filtered.
                match plan_mint_candidates(state, requester, peer).await {
                    Ok(plans) => {
                        // Never carry a backbone hint across the await into this
                        // fresh page snapshot: approval, ACL or approved edges may
                        // have changed. Rebuild only the existing <=2 hint scope.
                        let mut backbone = Vec::new();
                        let current_path_caps = requester.id.is_some_and(|id| {
                            state.org_relay.join_extras(id).supports_path_backbone_v1
                        }) && state
                            .org_relay
                            .join_extras(peer_id)
                            .supports_path_backbone_v1;
                        if let Some(cidr) = backbone_cidr.as_deref().filter(|_| current_path_caps) {
                            'sources: for ingress in &plans {
                                let Some(ingress_id) = ingress.relay.id else {
                                    continue;
                                };
                                if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                                    continue;
                                }
                                for edge in ingress.backbone_edges.iter().take(8) {
                                    if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                                        &edge.endpoint,
                                        cidr,
                                    ) {
                                        continue;
                                    }
                                    let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id)
                                    else {
                                        continue;
                                    };
                                    let Some(exit) = plans.iter().find(|p| {
                                        p.relay_agent_id == target && p.relay.id != Some(ingress_id)
                                    }) else {
                                        continue;
                                    };
                                    let Some(path) = exit.relay.id.and_then(|id| {
                                        RelayPathWire::new(vec![ingress_id, id]).ok()
                                    }) else {
                                        continue;
                                    };
                                    let hint = OrgRelayCandidateWire {
                                        path,
                                        requester_at_exit: false,
                                        endpoints: ingress
                                            .endpoints
                                            .iter()
                                            .take(4)
                                            .cloned()
                                            .collect(),
                                    };
                                    if !backbone
                                        .iter()
                                        .any(|c| discovery_key(c) == discovery_key(&hint))
                                    {
                                        backbone.push(hint);
                                    }
                                    if backbone.len() == 2 {
                                        break 'sources;
                                    }
                                }
                            }
                        }
                        let onehop = plans.into_iter().filter_map(|p| {
                            p.relay.id.map(|id| OrgRelayCandidateWire {
                                path: RelayPathWire::new(vec![id]).expect("one relay"),
                                requester_at_exit: false,
                                endpoints: p.endpoints.into_iter().take(4).collect(),
                            })
                        });
                        (candidates, next_cursor) =
                            discovery_page(backbone.into_iter().chain(onehop), cursor);
                    }
                    Err(_) => candidates.clear(), // no stale-page fallback on authorization failure
                }
            }
        } else {
            // Preserve the original preferred first page, including backbone reservation.
            next_cursor = candidates
                .iter()
                .max_by_key(|c| discovery_key(c))
                .map(discovery_cursor);
        }
    }
    let scan_caps = extras.supports_path_trial_v1
        && extras.supports_path_backbone_v1
        && state.org_relay.join_extras(peer_id).supports_path_trial_v1
        && state
            .org_relay
            .join_extras(peer_id)
            .supports_path_backbone_v1;
    let scan = if traversal
        && scan_caps
        && peer_relay_mode(state, requester.tenant_id).await == PeerRelayMode::On
    {
        Some(match scan {
            Some(Scan::Progress {
                checkpoint, after, ..
            }) => Scan::Progress {
                scan_next: true,
                checkpoint,
                after,
            },
            _ => Scan::Progress {
                scan_next: true,
                checkpoint: None,
                after: None,
            },
        })
    } else {
        None
    };
    let ttl_secs = if candidates.is_empty() && scan.is_none() {
        0
    } else {
        30
    };
    send_to_node(
        state,
        requester,
        ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id: peer_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
            scan,
        },
    )
    .await;
}

fn random_secret() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    BASE64.encode(b)
}

/// The entry point, called from `handle_overlay_relay_request` after its own
/// cross-tenant and ACL-enforce checks. Never blocks the TURN grant: the
/// client cascade (P4) picks Org over Turn/Derp when a session arrives.
async fn reauthorize_concurrent_winner(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    current: &OrgRelaySession,
) {
    if path_mint::repush(state, requester, peer, current).await == path_mint::RepushOutcome::Denied
    {
        revoke_where(state, "nhop_reauthorization_failed", |entry| {
            entry.pair_key == current.pair_key
                && entry.vni == current.vni
                && entry.generation == current.generation
        })
        .await;
    }
}

pub async fn maybe_mint(state: &NetworkState, requester: &OverlayNode, peer: &OverlayNode) {
    let tenant_id = requester.tenant_id;
    let mode = peer_relay_mode(state, tenant_id).await;
    if mode == PeerRelayMode::Off {
        // Gate 1 — zero rows, zero further reads.
        return;
    }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let warn_only = mode == PeerRelayMode::Warn;
    let pk = pair_key(req_id, peer_id);
    // A pair pinned to DERP (TURN churn, or a lossy ORG carrier) rides DERP
    // whatever is minted, so a session now would never bind.
    if crate::overlay::org_fallback_forced_derp(state, &pk) {
        return;
    }
    // #21 — a pair in two zones rides a cross-border line or nothing.
    if let Some(zones) = cross_border_zones(state, requester, peer).await {
        maybe_mint_line(state, requester, peer, zones, warn_only).await;
        return;
    }

    // Idempotent per pair: a live session is re-pushed to the ASKER only —
    // the peer and the relay already hold it. Not audited: nothing was
    // decided, and a retrying client must not fill the log.
    if !warn_only && let Some(s) = state.org_relay.active_session(&pk) {
        if !s.hops.is_empty() {
            match path_mint::repush(state, requester, peer, &s).await {
                path_mint::RepushOutcome::Sent | path_mint::RepushOutcome::Unavailable => return,
                path_mint::RepushOutcome::Denied => {}
            }
            revoke_where(state, "nhop_reauthorization_failed", |current| {
                current.pair_key == pk && current.vni == s.vni && current.generation == s.generation
            })
            .await;
        } else {
            let keys_current = [(req_id, requester), (peer_id, peer)]
                .iter()
                .all(|(id, node)| {
                    s.member_index(*id).is_some_and(|i| {
                        s.members[i].wg_public_key == node.wg_public_key
                            && s.members[i].party.node_ref == node.node_ref
                    })
                });
            if !keys_current {
                revoke_where(state, "member_key_rotated", |current| {
                    current.pair_key == pk
                        && current.vni == s.vni
                        && current.generation == s.generation
                })
                .await;
            } else {
                if !s.hops.is_empty()
                    || crate::business_isolation::mode(state)
                        == crate::business_isolation::Mode::Enforce
                {
                    match session_zone::check(state, &s).await {
                        session_zone::Decision::Uncertain { .. } => return,
                        session_zone::Decision::Fits => {}
                        session_zone::Decision::Invalid => {
                            revoke_where(state, "session_region_changed", |current| {
                                current.pair_key == pk
                                    && current.vni == s.vni
                                    && current.generation == s.generation
                            })
                            .await;
                            return;
                        }
                    }
                }
                if let Some(i) = s.member_index(req_id) {
                    push_member(state, &s, i).await;
                    debug!(%tenant_id, %pk, vni = s.vni, "org-relay: re-pushed the live session to a re-requesting member");
                }
                return;
            }
        }
    }

    let mut charged_relay = None;
    match path_mint::mint(state, requester, peer, warn_only, true, &mut charged_relay).await {
        Ok(true) => return,
        Ok(false) => {}
        Err(reason) => {
            debug!(%tenant_id, %pk, ?reason, "org-relay: multi-hop attempt failed; replan")
        }
    }

    // An implicit plan rests on live connections, so it mints under the
    // eligibility fence, whose claim also spends its rate budget (once).
    let epoch = state.org_relay.eligibility_generation();
    let verdict = plan_mint(state, requester, peer).await.and_then(|plan| {
        let relay_id = plan.relay.id.unwrap_or_default();
        // Gate 5 belongs to minting, not metadata discovery. Preserve its
        // existing requester->relay ceiling and audited refusal behavior.
        if plan.implicit
            || charged_relay == Some(relay_id)
            || state
                .relay_rate_limiter
                .check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE)
        {
            Ok(plan)
        } else {
            Err(PeerRelayDenyReason::RateLimited)
        }
    });
    let plan = match verdict {
        Ok(plan) => plan,
        Err(reason) => {
            info!(%tenant_id, requester = %req_id, peer = %peer_id, ?reason, warn_only, "org-relay: mint refused");
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                warn_only,
                Some(reason),
            )
            .await;
            return;
        }
    };
    let fence = plan.implicit.then_some(epoch);
    mint_plan(
        state,
        requester,
        peer,
        plan,
        warn_only,
        epoch,
        fence,
        charged_relay,
    )
    .await;
}

/// Time a re-pushed session needs to bind before the relay's bind deadline:
/// the member's bind sends and the push latency.
const BIND_REUSE_MARGIN: Duration = Duration::from_secs(8);

/// A fallback query reauthorizes cached leases, and never allocates TURN.
/// In particular a stale but unexpired relay lease cannot suppress reselection.
pub async fn maybe_mint_fallback(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) {
    let tenant_id = requester.tenant_id;
    let mode = peer_relay_mode(state, tenant_id).await;
    if mode == PeerRelayMode::Off {
        return;
    }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let pk = pair_key(req_id, peer_id);
    if crate::overlay::org_fallback_forced_derp(state, &pk) {
        return;
    }
    if let Some(zones) = cross_border_zones(state, requester, peer).await {
        maybe_mint_line(state, requester, peer, zones, mode == PeerRelayMode::Warn).await;
        return;
    }
    let mut cached = state.org_relay.active_session(&pk);
    if mode != PeerRelayMode::Warn && cached.as_ref().is_some_and(|s| !s.hops.is_empty()) {
        let session = cached.take().expect("checked above");
        match path_mint::repush(state, requester, peer, &session).await {
            path_mint::RepushOutcome::Sent | path_mint::RepushOutcome::Unavailable => return,
            path_mint::RepushOutcome::Denied => {}
        }
        revoke_where(state, "nhop_reauthorization_failed", |current| {
            current.pair_key == pk
                && current.vni == session.vni
                && current.generation == session.generation
        })
        .await;
    }
    if let Some(session) = cached.as_ref()
        && (!session.hops.is_empty()
            || crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce)
    {
        match session_zone::check(state, session).await {
            session_zone::Decision::Uncertain { .. } => return,
            session_zone::Decision::Fits => {}
            session_zone::Decision::Invalid => {
                revoke_where(state, "session_region_changed", |current| {
                    current.pair_key == pk
                        && current.vni == session.vni
                        && current.generation == session.generation
                })
                .await;
                cached = None;
            }
        }
    }
    let epoch = state.org_relay.eligibility_generation();
    let verdict =
        plan_mint_candidates_reusing(state, requester, peer, cached.as_ref(), ZoneScope::Pair)
            .await;
    if epoch != state.org_relay.eligibility_generation()
        || crate::overlay::org_fallback_forced_derp(state, &pk)
    {
        return;
    }
    if let Some(session) = cached {
        let authorized = verdict.as_ref().is_ok_and(|plans| {
            plans.iter().any(|plan| {
                plan.relay.id == Some(session.relay.node_id)
                    && plan.relay_agent_id == session.relay_agent_id
                    && plan.relay.node_ref == session.relay.node_ref
                    && plan.endpoints == session.endpoints
                    && plan.implicit == session.implicit
                    && [(req_id, requester), (peer_id, peer)]
                        .iter()
                        .all(|(id, node)| {
                            session.member_index(*id).is_some_and(|i| {
                                session.members[i].wg_public_key == node.wg_public_key
                                    && session.members[i].party.node_ref == node.node_ref
                            })
                        })
            })
        });
        // A member asks again only while it has no working org link. Within
        // the bind window the same session can still bind, so re-push it;
        // past it the relay drops its Binds (an unbound session dies at its
        // bind deadline), and re-pushing it stranded the pair until some
        // other event revoked it (field, 2026-10-25: 6 and 26 minutes).
        let bindable = Instant::now() + BIND_REUSE_MARGIN < session.bind_by;
        if authorized && bindable && mode != PeerRelayMode::Warn {
            if let Some(i) = session.member_index(req_id) {
                push_member(state, &session, i).await;
            }
            return;
        }
        if authorized && !bindable && mode != PeerRelayMode::Warn {
            // The member is asking again, so this session never gave it a
            // link (one-way or dead carrier): rank its relay last for the
            // pair, so the re-mint below tries another one first.
            if session.hops.is_empty() {
                state.org_relay.demote_unbound(
                    &pk,
                    session.relay.node_id,
                    Instant::now() + UNBOUND_DEMOTE,
                );
            }
            revoke_where(state, "org-fallback-bind-window-passed", |current| {
                current.pair_key == pk
                    && current.vni == session.vni
                    && current.generation == session.generation
            })
            .await;
        }
        if !authorized {
            revoke_where(state, "org-fallback-reauthorization", |current| {
                current.pair_key == pk
                    && current.vni == session.vni
                    && current.generation == session.generation
            })
            .await;
        }
    }
    if crate::overlay::org_fallback_forced_derp(state, &pk) {
        return;
    }
    let mut charged_relay = None;
    match path_mint::mint(
        state,
        requester,
        peer,
        mode == PeerRelayMode::Warn,
        true,
        &mut charged_relay,
    )
    .await
    {
        Ok(true) => return,
        Ok(false) => {}
        Err(reason) => {
            debug!(%tenant_id, %pk, ?reason, "org-relay: fallback multi-hop attempt failed; replan")
        }
    }
    // Multi-hop selection awaits fresh reads and may observe policy changes.
    let epoch = state.org_relay.eligibility_generation();
    let verdict = plan_mint_candidates(state, requester, peer).await;
    if epoch != state.org_relay.eligibility_generation()
        || crate::overlay::org_fallback_forced_derp(state, &pk)
    {
        return;
    }
    let verdict =
        verdict.and_then(|plans| plans.into_iter().next().ok_or(PeerRelayDenyReason::NoRelay));
    match verdict {
        Ok(plan) => {
            mint_plan(
                state,
                requester,
                peer,
                plan,
                mode == PeerRelayMode::Warn,
                epoch,
                Some(epoch),
                charged_relay,
            )
            .await
        }
        Err(reason) => {
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                mode == PeerRelayMode::Warn,
                Some(reason),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn mint_plan(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    plan: Plan,
    warn_only: bool,
    plan_epoch: u64,
    fallback_epoch: Option<u64>,
    charged_relay: Option<ObjectId>,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let pk = pair_key(req_id, peer_id);
    let relay_id = plan.relay.id.unwrap_or_default();
    let vni = if warn_only {
        let Some(vni) = state.org_relay.alloc_vni(relay_id) else {
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                Some((plan.relay_agent_id, relay_id)),
                None,
                true,
                Some(PeerRelayDenyReason::NoRelay),
            )
            .await;
            return;
        };
        vni
    } else {
        1
    }; // Placeholder is replaced under the claim lock before use.
    let generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let mut session = OrgRelaySession {
        tenant_id,
        pair_key: pk.clone(),
        vni,
        generation,
        relay: SessionParty {
            node_id: relay_id,
            node_ref: plan.relay.node_ref.clone(),
        },
        relay_agent_id: plan.relay_agent_id,
        implicit: plan.implicit,
        members: [
            SessionMember {
                party: SessionParty {
                    node_id: req_id,
                    node_ref: requester.node_ref.clone(),
                },
                wg_public_key: requester.wg_public_key.clone(),
                bind_secret: random_secret(),
            },
            SessionMember {
                party: SessionParty {
                    node_id: peer_id,
                    node_ref: peer.node_ref.clone(),
                },
                wg_public_key: peer.wg_public_key.clone(),
                bind_secret: random_secret(),
            },
        ],
        endpoints: plan.endpoints.clone(),
        expires_at: Instant::now() + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
        bind_by: Instant::now() + Duration::from_secs(u64::from(limits::BIND_SECS)),
        hops: Vec::new(),
    };
    // Warn never claims capacity; actual mints audit only after winning.
    if warn_only {
        if fallback_epoch.is_some()
            && !state
                .relay_rate_limiter
                .check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE)
        {
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                warn_only,
                Some(PeerRelayDenyReason::RateLimited),
            )
            .await;
            return;
        }
        audit_mint(
            state,
            tenant_id,
            req_id,
            peer_id,
            Some((plan.relay_agent_id, relay_id)),
            Some(vni),
            warn_only,
            None,
        )
        .await;
    }
    if warn_only {
        info!(%tenant_id, requester = %req_id, peer = %peer_id, relay = %relay_id, vni, "org-relay [warn]: would mint; pushing nothing");
        return;
    }
    if let Some(epoch) = fallback_epoch
        && (epoch != state.org_relay.eligibility_generation()
            || crate::overlay::org_fallback_forced_derp(state, &pk))
    {
        return;
    }
    let mut refusal = None;
    let claim = trial::claim_mint(&state.org_relay, &mut session, |_| {
        if plan_epoch != state.org_relay.eligibility_generation() {
            return false;
        }
        if let Some(epoch) = fallback_epoch {
            if epoch != state.org_relay.eligibility_generation()
                || crate::overlay::org_fallback_forced_derp(state, &pk)
            {
                return false;
            }
            if charged_relay != Some(relay_id)
                && !state.relay_rate_limiter.check(
                    req_id,
                    relay_id,
                    limits::MINT_RATE_LIMIT_PER_MINUTE,
                )
            {
                refusal = Some(PeerRelayDenyReason::RateLimited);
                return false;
            }
        }
        true
    });
    match claim {
        trial::MintClaim::Existing(current) => {
            if !current.hops.is_empty() {
                reauthorize_concurrent_winner(state, requester, peer, &current).await;
                return;
            }
            // Fallback must reauthorize this exact winner; ordinary mint has
            // the same reuse semantics as maybe_mint's existing-session path.
            let authorized = fallback_epoch.is_none()
                || (current.relay.node_id == relay_id
                    && current.relay.node_ref == plan.relay.node_ref
                    && current.endpoints == plan.endpoints
                    && current.implicit == plan.implicit
                    && [(req_id, requester), (peer_id, peer)]
                        .iter()
                        .all(|(id, node)| {
                            current.member_index(*id).is_some_and(|i| {
                                current.members[i].wg_public_key == node.wg_public_key
                                    && current.members[i].party.node_ref == node.node_ref
                            })
                        })
                    && fallback_epoch == Some(state.org_relay.eligibility_generation())
                    && !crate::overlay::org_fallback_forced_derp(state, &pk));
            if authorized && let Some(i) = current.member_index(req_id) {
                push_member(state, &current, i).await;
            }
            return;
        }
        trial::MintClaim::Full => {
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                false,
                Some(PeerRelayDenyReason::NoRelay),
            )
            .await;
            return;
        }
        trial::MintClaim::Rejected => {
            if let Some(reason) = refusal {
                audit_mint(
                    state,
                    tenant_id,
                    req_id,
                    peer_id,
                    None,
                    None,
                    false,
                    Some(reason),
                )
                .await;
            }
            return;
        }
        trial::MintClaim::Inserted => {}
    }
    let vni = session.vni;
    if fallback_epoch.is_none() {
        audit_mint(
            state,
            tenant_id,
            req_id,
            peer_id,
            Some((plan.relay_agent_id, relay_id)),
            Some(vni),
            false,
            None,
        )
        .await;
        if !state.org_relay.active_session(&pk).is_some_and(|current| {
            current.vni == session.vni && current.generation == session.generation
        }) {
            return;
        }
    }
    info!(%tenant_id, requester = %req_id, peer = %peer_id, relay = %relay_id, vni, generation,
        endpoints = ?session.endpoints, "org-relay: minted");

    // The relay FIRST, so it can verify the binds by the time the members
    // arrive; then each member with its own secret.
    send_to_node(
        state,
        &plan.relay,
        ServerMsg::OverlayRelayServe {
            vni,
            generation,
            members: session
                .members
                .iter()
                .map(|m| RelayMemberWire {
                    wg_public_key: m.wg_public_key.clone(),
                    bind_secret: m.bind_secret.clone(),
                })
                .collect(),
            bind_secs: limits::BIND_SECS,
            idle_secs: limits::IDLE_SECS,
            max_lifetime_secs: limits::MAX_LIFETIME_SECS,
        },
    )
    .await;
    push_member(state, &session, 0).await;
    push_member(state, &session, 1).await;
    if fallback_epoch.is_some() {
        audit_mint(
            state,
            tenant_id,
            req_id,
            peer_id,
            Some((plan.relay_agent_id, relay_id)),
            Some(vni),
            false,
            None,
        )
        .await;
    }
}

/// `rc:overlay.relay_session` to member `i`, naming the OTHER member as its
/// peer and carrying only its own secret and its own relay (on a line, each
/// member's is in its own zone).
fn member_message(s: &OrgRelaySession, i: usize) -> Option<ServerMsg> {
    let remaining = s
        .expires_at
        .saturating_duration_since(Instant::now())
        .as_secs()
        .min(u64::from(limits::MAX_LIFETIME_SECS)) as u32;
    if remaining == 0 {
        return None;
    }
    let me = &s.members[i];
    let other = &s.members[1 - i];
    let leg = s.member_leg(i);
    Some(ServerMsg::OverlayRelaySession {
        vni: leg.vni,
        generation: leg.generation,
        peer_node_id: other.party.node_id,
        relay_node_id: leg.relay_node_id,
        relay_endpoints: leg.endpoints.to_vec(),
        bind_secret: me.bind_secret.clone(),
        bind_secs: limits::BIND_SECS,
        max_lifetime_secs: remaining,
    })
}

async fn push_member(state: &NetworkState, s: &OrgRelaySession, i: usize) {
    if let Some(message) = member_message(s, i) {
        send_to_node_ref(state, &s.members[i].party.node_ref, message).await;
    }
}

/// How long consecutive identical refusals of one pair collapse into the
/// first row (field, 2026-10-26: a member on DERP asks for an ORG fallback
/// every 60 s, and a pair no relay may carry wrote a `zone_denied` row each
/// time). Any other decision for the pair is written and starts afresh.
const REPEAT_REFUSAL_AUDIT_GAP: Duration = Duration::from_secs(600);

#[allow(clippy::too_many_arguments)]
async fn audit_mint(
    state: &NetworkState,
    tenant_id: ObjectId,
    requester: ObjectId,
    peer: ObjectId,
    relay: Option<(ObjectId, ObjectId)>,
    vni: Option<u32>,
    warn_only: bool,
    denied: Option<PeerRelayDenyReason>,
) {
    let now = Instant::now();
    let kind = (denied, warn_only);
    let repeat = state
        .org_relay
        .last_mint_audit
        .get(&pair_key(requester, peer))
        .is_some_and(|e| {
            denied.is_some() && e.0 == kind && now.duration_since(e.1) < REPEAT_REFUSAL_AUDIT_GAP
        });
    if repeat {
        return;
    }
    let audits = &state.org_relay.last_mint_audit;
    if audits.len() >= 4096 {
        audits.retain(|_, e| now.duration_since(e.1) < REPEAT_REFUSAL_AUDIT_GAP);
    }
    audits.insert(pair_key(requester, peer), (kind, now));
    let event = PeerRelayAuditEvent {
        id: None,
        tenant_id,
        action: PeerRelayAuditAction::Mint,
        agent_id: relay.map(|r| r.0),
        user_id: None,
        requester_node_id: Some(requester),
        peer_node_id: Some(peer),
        relay_node_id: relay.map(|r| r.1),
        serve: None,
        vni,
        warn_only,
        at: DateTime::now(),
        denied,
        reason: None,
    };
    if let Err(e) = state.peer_relay_audit.record(event).await {
        warn!(%e, "org-relay: audit write failed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation — a push, never an expiry (§7)
// ─────────────────────────────────────────────────────────────────────────────

/// Tear down every live session `pred` selects: `rc:overlay.relay_revoke` to
/// the relay and both members, the record dropped, one audit row per session
/// naming the trigger. Returns how many were revoked.
/// Send control messages without DB access or awaited channel capacity. A
/// failed push is not an acknowledgment; the authoritative state is already
/// removed and the normal reconnect/receiver liveness paths remain in force.
fn push_control(state: &NetworkState, node: &NodeRef, msg: ServerMsg) -> bool {
    match node {
        NodeRef::Agent { agent_id } => state.fleet.rc_hub.send_to_agent(*agent_id, msg).is_ok(),
        NodeRef::TunnelClient { tunnel_client_id } => state
            .overlay_nodes_by_id
            .get(tunnel_client_id)
            .is_some_and(|tx| tx.try_send(msg).is_ok()),
    }
}

fn revoke_matching_sync(
    state: &NetworkState,
    reason: &str,
    pred: impl Fn(&OrgRelaySession) -> bool,
) -> Vec<PeerRelayAuditEvent> {
    // Do not let N-hop grants overtake these nonblocking revocations.
    let _delivery = state
        .org_relay
        .delivery_guard
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Even zero current sessions must invalidate an in-flight authorization.
    state.org_relay.invalidate_eligibility();
    let victims: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|entry| pred(entry.value()))
        .map(|entry| entry.value().clone())
        .collect();
    let mut events = Vec::new();
    for session in victims {
        // Do not remove a newer generation which replaced the selected row.
        if state
            .org_relay
            .sessions
            .remove_if(&session.pair_key, |_, current| {
                current.vni == session.vni && current.generation == session.generation
            })
            .is_none()
        {
            continue;
        }
        let revoke = |vni, relay_node_id, generation, peer_node_id| ServerMsg::OverlayRelayRevoke {
            vni,
            scope: RelayRevokeScopeWire {
                relay_node_id,
                generation,
                peer_node_id,
            },
        };
        push_control(
            state,
            &session.relay.node_ref,
            revoke(session.vni, session.relay.node_id, session.generation, None),
        );
        for (i, member) in session.members.iter().enumerate() {
            let leg = session.member_leg(i);
            push_control(
                state,
                &member.party.node_ref,
                revoke(
                    leg.vni,
                    leg.relay_node_id,
                    leg.generation,
                    Some(session.members[1 - i].party.node_id),
                ),
            );
        }
        for (recipient, message) in session.hop_revocations() {
            push_control(state, &recipient, message);
        }
        events.push(PeerRelayAuditEvent {
            id: None,
            tenant_id: session.tenant_id,
            action: PeerRelayAuditAction::Revoke,
            agent_id: Some(session.relay_agent_id),
            user_id: None,
            requester_node_id: Some(session.members[0].party.node_id),
            peer_node_id: Some(session.members[1].party.node_id),
            relay_node_id: Some(session.relay.node_id),
            serve: None,
            vni: Some(session.vni),
            warn_only: false,
            at: DateTime::now(),
            denied: None,
            reason: Some(reason.to_string()),
        });
    }
    events.extend(state.org_relay.trials.revoke_where(state, reason, &pred));
    events
}

/// Admission revocation: no current_node lookup, storage operation or await
/// precedes terminating every session in which this authenticated agent acts.
/// The caller owns bounded persistence of the returned audit events.
pub fn revoke_agent_sync(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    reason: &str,
) -> Vec<PeerRelayAuditEvent> {
    revoke_matching_sync(state, reason, |session| {
        session.tenant_id == tenant_id && session.involves_agent(agent_id)
    })
}

pub async fn revoke_where(
    state: &NetworkState,
    reason: &str,
    pred: impl Fn(&OrgRelaySession) -> bool,
) -> usize {
    // Complete ALL removals and notifications before the first audit IO.
    let events = revoke_matching_sync(state, reason, pred);
    let count = events.len();
    for event in events {
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), state.peer_relay_audit.record(event))
                .await,
            Ok(Ok(_))
        ) {
            warn!("org-relay: revoke audit failed or timed out after control revocation");
        }
    }
    count
}

/// Trigger 1 — the org switched peer relays off.
pub async fn revoke_tenant(state: &NetworkState, tenant_id: ObjectId, reason: &str) -> usize {
    revoke_where(state, reason, |s| s.tenant_id == tenant_id).await
}

/// Trigger 3 — a relay's approval was cleared (either leg of a line).
pub async fn revoke_relay_agent(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    reason: &str,
) -> usize {
    revoke_where(state, reason, |s| {
        s.tenant_id == tenant_id && s.relayed_by_agent(agent_id)
    })
    .await
}

/// How long a cross-border line outlives one party's closed or displaced
/// control connection. A line carries its traffic without the control plane,
/// so a reconnect inside the grace, or a center restart, keeps it; once the
/// grace has passed the parties' zones are read again ([`line_zones_fit`]).
pub const LINE_RECONNECT_GRACE: Duration = Duration::from_secs(20);

/// MeshHarbor `auto` and #21: an implicit session and a cross-border line
/// rest on the zone each party's live connection was observed in. That
/// connection closing or being displaced ends an implicit session at once,
/// and a line after [`LINE_RECONNECT_GRACE`] unless every party is connected
/// again in a zone that still fits it (field, 2026-10-26: revoking at once
/// tore a line down on one relay only while a restarting center closed its
/// connections, and the members kept the dead half).
pub async fn connection_ended(state: &NetworkState, agent_id: ObjectId, reason: &'static str) {
    revoke_where(state, reason, |s| s.implicit && s.involves_agent(agent_id)).await;
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(LINE_RECONNECT_GRACE).await;
        recheck_zones(&state, agent_id, reason).await;
    });
}

/// MeshHarbor GEO-05 — end `agent_id`'s sessions whose parties' zones no
/// longer fit them: a device that roamed into the other zone reconnects, and
/// its rejoin calls this once its new observation is in (and
/// [`connection_ended`] once more after [`LINE_RECONNECT_GRACE`]). Lines
/// always; every other session only under #21 `enforce`, where it was minted
/// on one shared zone (under `warn` the refusal is logged).
pub async fn recheck_zones(state: &NetworkState, agent_id: ObjectId, reason: &str) -> bool {
    use crate::business_isolation::{self as iso, Mode};
    state.org_relay.invalidate_eligibility();
    let mode = iso::mode(state);
    let sessions: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|e| e.involves_identity(agent_id) && (!e.hops.is_empty() || mode != Mode::Off))
        .map(|e| e.value().clone())
        .collect();
    let mut all_certain = true;
    for s in sessions {
        match session_zone::check(state, &s).await {
            session_zone::Decision::Fits => continue,
            session_zone::Decision::Uncertain { retryable } => {
                if retryable {
                    all_certain = false;
                }
                continue;
            }
            session_zone::Decision::Invalid => {}
        }
        if s.hops.is_empty() && mode != Mode::Enforce {
            info!(pair = %s.pair_key, vni = s.vni, reason,
                "org-relay [isolation warn]: would end a session whose parties no longer share one zone");
            continue;
        }
        revoke_where(state, reason, |c| {
            c.pair_key == s.pair_key && c.vni == s.vni && c.generation == s.generation
        })
        .await;
    }
    recheck_trial_zones(state, agent_id, reason).await;
    all_certain
}

/// Backbone trials need the same live relay-zone evidence in every isolation
/// mode. A changing eligibility epoch defers the decision instead of revoking
/// from a mixed snapshot; retry is deduplicated per affected relay.
pub(crate) async fn recheck_trial_zones(state: &NetworkState, agent_id: ObjectId, reason: &str) {
    let ids = trial::trial_ids_for_identity(state, agent_id);
    if !ids.is_empty() {
        schedule_trial_zone_retry(state, ids);
    }
    let ids = trial::recheck_relay_zones(state, agent_id, reason).await;
    if !ids.is_empty() {
        schedule_trial_zone_retry(state, ids);
    }
}

#[derive(Default)]
struct TrialZoneRetry {
    running: bool,
    generation: u64,
    pending: std::collections::VecDeque<ObjectId>,
    queued: std::collections::HashSet<ObjectId>,
    rescan: bool,
}

/// At most 16 party-read starts per one-second fixed window, independent of
/// the semaphore limiting concurrent reads. Each party performs at most two
/// sequential DAO lookups. A rejected read is uncertainty, not invalidity.
#[derive(Default)]
struct TrialZoneIoBudget {
    window: Option<Instant>,
    starts: u32,
}

impl TrialZoneIoBudget {
    fn admit(&mut self, now: Instant) -> bool {
        if self
            .window
            .is_none_or(|start| now.saturating_duration_since(start) >= Duration::from_secs(1))
        {
            self.window = Some(now);
            self.starts = 0;
        }
        if self.starts >= 16 {
            return false;
        }
        self.starts += 1;
        true
    }
}

impl TrialZoneRetry {
    fn enqueue(&mut self, id: ObjectId) {
        if self.queued.contains(&id) {
            return;
        }
        if self.pending.len() >= trial::MAX_TRIALS {
            self.rescan = true;
            return;
        }
        self.queued.insert(id);
        self.pending.push_back(id);
    }

    fn request(&mut self, ids: impl IntoIterator<Item = ObjectId>) -> Option<u64> {
        for id in ids {
            self.enqueue(id);
        }
        if self.pending.is_empty() && !self.rescan {
            return None;
        }
        if self.running {
            None
        } else {
            self.running = true;
            self.generation = self.generation.wrapping_add(1);
            Some(self.generation)
        }
    }

    fn finish_pass(
        &mut self,
        generation: u64,
        retry: impl IntoIterator<Item = ObjectId>,
        deferred: bool,
    ) -> bool {
        if !self.running || self.generation != generation {
            return false;
        }
        for id in retry {
            self.enqueue(id);
        }
        if self.rescan || !self.pending.is_empty() || deferred {
            true
        } else {
            self.running = false;
            false
        }
    }

    fn abnormal_exit(&mut self, generation: u64) -> bool {
        if !self.running || self.generation != generation {
            return false;
        }
        self.running = false;
        // Any in-flight IDs may have been removed from the queue.
        self.rescan = true;
        true
    }
}

struct TrialZoneWorkerGuard {
    state: NetworkState,
    generation: u64,
    started: bool,
    completed: bool,
}

impl Drop for TrialZoneWorkerGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let owns_worker = self
            .state
            .org_relay
            .trial_zone_retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abnormal_exit(self.generation);
        // A polled worker that panicked or was cancelled restarts via the
        // normal delayed scheduler. A never-polled task can be dropped during
        // runtime shutdown; do not recursively spawn during shutdown.
        if owns_worker && self.started && tokio::runtime::Handle::try_current().is_ok() {
            schedule_trial_zone_retry(&self.state, std::collections::HashSet::new());
        }
    }
}

fn schedule_trial_zone_retry(state: &NetworkState, ids: std::collections::HashSet<ObjectId>) {
    let generation = state
        .org_relay
        .trial_zone_retry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .request(ids);
    let Some(generation) = generation else { return };
    let state = state.clone();
    let guard = TrialZoneWorkerGuard {
        state: state.clone(),
        generation,
        started: false,
        completed: false,
    };
    tokio::spawn(async move {
        // Capture the whole Drop guard, rather than separate Copy fields.
        let mut guard = guard;
        guard.started = true;
        let mut deferred = std::collections::HashSet::<ObjectId>::new();
        let mut retry_at = tokio::time::Instant::now();
        loop {
            // Productive continuation is rate-bounded, while completed
            // uncertain scans back off independently for five seconds.
            let idle = {
                let q = state
                    .org_relay
                    .trial_zone_retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                q.pending.is_empty() && !q.rescan && !deferred.is_empty()
            };
            if idle {
                tokio::time::sleep_until(retry_at).await;
            } else {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            if !deferred.is_empty() && tokio::time::Instant::now() >= retry_at {
                let mut q = state
                    .org_relay
                    .trial_zone_retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                for id in deferred.drain() {
                    q.enqueue(id);
                }
            }
            trial::prune_trial_zone_cursors(&state);
            trial::refill_zone_retry_if_needed(&state, generation);
            let batch = {
                let mut retry = state
                    .org_relay
                    .trial_zone_retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !retry.running || retry.generation != generation {
                    guard.completed = true;
                    return;
                }
                let mut batch = std::collections::HashSet::new();
                for _ in 0..4 {
                    let Some(id) = retry.pending.pop_front() else {
                        break;
                    };
                    retry.queued.remove(&id);
                    deferred.remove(&id);
                    batch.insert(id);
                }
                batch
            };
            let mut pending = std::collections::HashSet::new();
            for id in batch {
                match trial::recheck_trial_zone_slice(&state, id, "zone_retry").await {
                    trial::TrialZoneSlice::Complete => {}
                    trial::TrialZoneSlice::Continue => {
                        pending.insert(id);
                    }
                    trial::TrialZoneSlice::Retry => {
                        if deferred.is_empty() {
                            retry_at = tokio::time::Instant::now() + Duration::from_secs(5);
                        }
                        if deferred.len() < trial::MAX_TRIALS || deferred.contains(&id) {
                            deferred.insert(id);
                        } else {
                            state
                                .org_relay
                                .trial_zone_retry
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .rescan = true;
                        }
                    }
                }
            }
            let again = state
                .org_relay
                .trial_zone_retry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .finish_pass(generation, pending, !deferred.is_empty());
            if !again {
                guard.completed = true;
                break;
            }
        }
    });
}

/// A fixture's boolean answer is true only for a fully known valid line.
/// Production rechecks distinguish uncertainty from confirmed invalidity.
#[cfg(feature = "path-planner-test-support")]
async fn line_zones_fit(state: &NetworkState, s: &OrgRelaySession) -> bool {
    !s.hops.is_empty() && session_zone::check(state, s).await == session_zone::Decision::Fits
}

/// Trigger 4 — a party (member or relay) was removed from the overlay.
pub async fn revoke_node(state: &NetworkState, node_id: ObjectId, reason: &str) -> usize {
    state.org_relay.forget_node(node_id);
    revoke_where(state, reason, |s| s.involves(node_id)).await
}

/// Trigger 2 — the tenant's policies changed: re-run gate 2 for every live
/// session and revoke the pairs no longer granted their relay.
///
/// A read failure here does NOTHING, deliberately. Refusing a NEW mint on a
/// blip costs one session; tearing down every LIVE session on a blip is the
/// "spurious deny takes the mesh down" failure `load_acl` fails open to avoid.
pub async fn reconcile_acl(state: &NetworkState, tenant_id: ObjectId) -> bool {
    state.org_relay.invalidate_eligibility();
    let mut ok = true;
    match state.overlay_networks.find_for_tenant(tenant_id).await {
        Ok(Some(net)) => {
            if net.peer_relay_mode == PeerRelayMode::Off {
                let _ = revoke_tenant(state, tenant_id, "mode_off").await;
                return true;
            }
            if net.peer_relay_mode != PeerRelayMode::Auto {
                let _ = revoke_where(state, "mode_not_auto", |s| {
                    s.tenant_id == tenant_id && s.implicit
                })
                .await;
            }
        }
        Ok(None) => return true,
        Err(_) => {
            ok = false;
        }
    }
    let approved_relays: Option<
        std::collections::HashMap<
            ObjectId,
            Vec<meshharbor_remote_control::models::PeerRelayBackboneEdge>,
        >,
    > = match state.fleet.agents.list_relay_approved(tenant_id).await {
        Ok(agents) => Some(
            agents
                .into_iter()
                .filter_map(|a| {
                    let id = a.id?;
                    Some((id, a.peer_relay_policy.approved_backbone_edges))
                })
                .collect(),
        ),
        Err(_) => {
            ok = false;
            None
        }
    };
    if let Some(ref approved) = approved_relays {
        for (source_id, edges) in approved {
            let _ = revoke_removed_backbone_edges_sync(state, tenant_id, *source_id, edges);
        }
    }
    let server_agents: Option<std::collections::HashSet<ObjectId>> =
        match meshharbor_core::business_authority::current_server_agents(&state.core, tenant_id)
            .await
        {
            Ok(agents) => Some(agents.into_iter().filter_map(|a| a.id).collect()),
            Err(_) => {
                ok = false;
                None
            }
        };
    let acl = match try_load_acl(state, tenant_id, PolicyLoad::Always).await {
        Ok(a) => a,
        Err(e) => {
            warn!(%tenant_id, %e, "org-relay: policies unreadable during reconcile; leaving sessions as they are");
            return false;
        }
    };
    let mut live: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|e| e.tenant_id == tenant_id)
        .map(|e| e.value().clone())
        .collect();
    live.extend(state.org_relay.trials.sessions_for_tenant(tenant_id));
    for s in live {
        // Granted by role and zone, not by a policy: an edit cannot touch it,
        // unless the server role itself was revoked on another pod.
        if s.implicit {
            if let Some(ref servers) = server_agents
                && !servers.contains(&s.relay_agent_id)
            {
                let pk = s.pair_key.clone();
                revoke_where(state, "role_revoked", |x| x.pair_key == pk && x.implicit).await;
            }
            continue;
        }
        if let Some(ref approved) = approved_relays
            && !approved.contains_key(&s.relay_agent_id)
        {
            let pk = s.pair_key.clone();
            revoke_where(state, "policy_revoked", |x| x.pair_key == pk && !x.implicit).await;
            continue;
        }
        // Both members must still be granted every relay of the session (a
        // line's two, as its planner requires).
        let mut granted = true;
        let mut policy_revoked = false;
        'relays: for relay_id in s.relay_nodes() {
            let relay = match state.overlay_nodes.base.find_by_id(relay_id).await {
                Ok(r) => r,
                Err(meshharbor_services::dao::base::DaoError::NotFound) => {
                    granted = false;
                    break 'relays;
                }
                Err(_) => {
                    ok = false;
                    continue;
                }
            };
            if let NodeRef::Agent { agent_id } = relay.node_ref
                && let Some(ref approved) = approved_relays
                && !approved.contains_key(&agent_id)
            {
                policy_revoked = true;
                break 'relays;
            }
            // FR-97 P0b — granted from the routes the relay OFFERS.
            let relay_routes = relay.effective_routes();
            let relay_ref = OverlayPeerRef {
                node_id: relay_id,
                overlay_ip: &relay.overlay_ip,
                approved_routes: &relay_routes,
            };
            for m in &s.members {
                let node = match state.overlay_nodes.base.find_by_id(m.party.node_id).await {
                    Ok(n) => n,
                    Err(meshharbor_services::dao::base::DaoError::NotFound) => {
                        granted = false;
                        break 'relays;
                    }
                    Err(_) => {
                        ok = false;
                        continue;
                    }
                };
                let src: OverlaySource = match try_overlay_source_of(state, &node).await {
                    Ok(src) => src,
                    Err(_) => {
                        ok = false;
                        continue; // unreadable identity: not evidence of revocation
                    }
                };
                if !evaluate_overlay(&acl.policies, &src, relay_ref).visible {
                    granted = false;
                    break 'relays;
                }
            }
        }
        if policy_revoked {
            let pk = s.pair_key.clone();
            revoke_where(state, "policy_revoked", |x| x.pair_key == pk && !x.implicit).await;
        } else if !granted {
            let pk = s.pair_key.clone();
            revoke_where(state, "acl_revoked", |x| x.pair_key == pk).await;
        }
    }
    ok
}

/// `rc:overlay.relay_probe` — a member's own measurement toward a relay the
/// server minted for it. Accepted only for (relay, endpoint) pairs that
/// appear in one of its sessions.
pub async fn handle_relay_probe(
    state: &NetworkState,
    ident: NodeIdentity,
    connection_id: &str,
    relay_node_id: ObjectId,
    endpoint: String,
    reachable: bool,
    rtt_ms: Option<u32>,
) {
    let Some(node) = current_node(state, ident).await else {
        return;
    };
    let Some(node_id) = node.id else { return };
    if node.node_ref != ident.node_ref() {
        return;
    }
    let identity_id = ident.connection_key();
    #[cfg(feature = "path-planner-test-support")]
    let finished = candidate_test_support::pause_probe(identity_id).await;
    let accepted = state.org_relay.record_probe_from_connection(
        (identity_id, connection_id),
        node_id,
        relay_node_id,
        endpoint.clone(),
        reachable,
        rtt_ms,
    );
    #[cfg(feature = "path-planner-test-support")]
    if let Some(finished) = finished {
        let _ = finished.send(accepted);
    }
    debug!(reporter = %node_id, relay = %relay_node_id, %endpoint, reachable, ?rtt_ms, accepted,
        "org-relay: reachability report");
    if accepted {
        rerank_young(state, &node).await;
    }
}

/// The live session a member's loss report names: the reporter's own pair
/// with `peer`, under the VNI it rides. `None` for anything else (a stale
/// VNI, a session it is not a member of), and the report is dropped.
pub(crate) fn reported_session(
    state: &NetworkState,
    reporter: ObjectId,
    peer: ObjectId,
    vni: u32,
) -> Option<OrgRelaySession> {
    let s = state.org_relay.active_session(&pair_key(reporter, peer))?;
    let i = s.member_index(reporter)?;
    (s.member_leg(i).vni == vni).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Item 6 — a relay a member measures unreachable now ranks behind one
    /// that was only demoted for the pair, so two failures inside the
    /// demotion window send the pair back to the recovered relay instead of
    /// re-minting it onto the frozen one.
    #[test]
    fn an_unreachable_relay_ranks_behind_one_that_was_only_demoted() {
        // Unchanged: reachable, then unmeasured, then a demoted relay.
        assert!(mint_class(0, false) < mint_class(1, false));
        assert!(mint_class(1, false) < mint_class(0, true));
        assert!(mint_class(1, false) < mint_class(1, true));
        // The fix: measured unreachable is last, demoted or not ...
        assert!(mint_class(0, true) < mint_class(2, false));
        assert!(mint_class(1, true) < mint_class(2, false));
        assert_eq!(mint_class(2, true), mint_class(2, false));
        // ... so the recovered-but-demoted relay beats the frozen one that
        // has just been demoted too.
        assert!(mint_class(0, true) < mint_class(2, true));
    }

    #[test]
    fn trial_zone_party_read_budget_bounds_starts_per_window() {
        let mut budget = TrialZoneIoBudget::default();
        let now = Instant::now();
        for _ in 0..16 {
            assert!(budget.admit(now));
        }
        assert!(!budget.admit(now));
        assert!(budget.admit(now + Duration::from_secs(1)));
    }

    #[test]
    fn trial_zone_semaphore_limits_concurrent_party_reads() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let guards: Vec<_> = (0..4)
            .map(|_| sem.clone().try_acquire_owned().unwrap())
            .collect();
        assert!(sem.clone().try_acquire_owned().is_err());
        drop(guards);
        assert!(sem.try_acquire_owned().is_ok());
    }

    #[test]
    fn zone_retry_coalesces_requests_and_does_not_lose_a_wakeup() {
        use std::sync::{Arc, Barrier, Mutex};
        for _ in 0..32 {
            let queue = Arc::new(Mutex::new(TrialZoneRetry::default()));
            let id = ObjectId::new();
            let generation = queue.lock().unwrap().request([id]).unwrap();
            assert!(queue.lock().unwrap().request([id]).is_none());
            {
                let mut q = queue.lock().unwrap();
                assert_eq!(q.pending.pop_front(), Some(id));
                q.queued.remove(&id);
            }
            let barrier = Arc::new(Barrier::new(3));
            let q = queue.clone();
            let b = barrier.clone();
            let finish = std::thread::spawn(move || {
                b.wait();
                q.lock().unwrap().finish_pass(generation, [], false)
            });
            let q = queue.clone();
            let b = barrier.clone();
            let request = std::thread::spawn(move || {
                b.wait();
                q.lock().unwrap().request([id])
            });
            barrier.wait();
            let kept_running = finish.join().unwrap();
            let started_again = request.join().unwrap().is_some();
            assert!(kept_running || started_again);
            assert!(queue.lock().unwrap().running);
        }
    }

    #[test]
    fn abnormal_zone_worker_exit_remains_retryable() {
        let mut retry = TrialZoneRetry::default();
        let generation = retry.request([ObjectId::new()]).unwrap();
        assert!(retry.abnormal_exit(generation));
        assert!(!retry.running && retry.rescan);
        assert!(retry.request([]).is_some());
        assert!(retry.running && retry.rescan);
    }

    #[test]
    fn old_zone_worker_exit_cannot_clobber_new_generation() {
        let mut retry = TrialZoneRetry::default();
        let id = ObjectId::new();
        let old = retry.request([id]).unwrap();
        retry.pending.clear();
        retry.queued.clear();
        assert!(!retry.finish_pass(old, [], false));
        let new = retry.request([id]).unwrap();
        assert_ne!(old, new);
        assert!(!retry.abnormal_exit(old));
        assert!(retry.running && retry.queued.contains(&id));
        assert_eq!(retry.generation, new);
    }

    #[test]
    fn zone_retry_queue_deduplicates_and_overflow_requests_a_rescan() {
        let mut retry = TrialZoneRetry::default();
        let first = ObjectId::new();
        retry.enqueue(first);
        retry.enqueue(first);
        assert_eq!(retry.pending.len(), 1);
        for _ in 1..=trial::MAX_TRIALS {
            retry.enqueue(ObjectId::new());
        }
        assert_eq!(retry.pending.len(), trial::MAX_TRIALS);
        assert!(retry.rescan);
    }

    #[test]
    fn zone_retry_unfinished_trial_goes_behind_other_pending_trials() {
        let mut retry = TrialZoneRetry::default();
        let slow = ObjectId::new();
        let other = ObjectId::new();
        retry.enqueue(slow);
        retry.enqueue(other);
        assert_eq!(retry.pending.pop_front(), Some(slow));
        retry.queued.remove(&slow);
        retry.enqueue(slow);
        assert_eq!(retry.pending.pop_front(), Some(other));
        assert_eq!(retry.pending.pop_front(), Some(slow));
    }

    #[test]
    fn zone_retry_keeps_worker_alive_for_deferred_uncertainty() {
        let mut retry = TrialZoneRetry::default();
        let id = ObjectId::new();
        let generation = retry.request([id]).unwrap();
        retry.pending.clear();
        retry.queued.clear();
        assert!(retry.finish_pass(generation, [], true));
        assert!(retry.running);
        assert!(!retry.finish_pass(generation, [], false));
        assert!(!retry.running);
    }

    fn node_with(srflx: &[&str], lan: &[&str], endpoints: &[&str]) -> OverlayNode {
        let mut n: OverlayNode = serde_json::from_value(serde_json::json!({
            "tenant_id": ObjectId::new(),
            "node_ref": { "kind": "agent", "id": ObjectId::new() },
            "network_id": ObjectId::new(),
            "machine_id": "m",
            "name": "n",
            "overlay_ip": "100.64.0.9",
            "wg_public_key": "k",
            "status": "online",
            "last_seen_at": DateTime::now(),
            "created_at": DateTime::now(),
            "updated_at": DateTime::now(),
        }))
        .expect("a minimal node row deserialises");
        n.srflx_endpoints = srflx.iter().map(|s| s.to_string()).collect();
        n.lan_endpoints = lan.iter().map(|s| s.to_string()).collect();
        n.endpoints = endpoints.iter().map(|s| s.to_string()).collect();
        n
    }

    /// Public addresses are re-paired with the relay port, private ones are
    /// dropped, and a static entry keeps its own port.
    #[test]
    fn relay_endpoints_pairs_public_addresses_with_the_relay_port() {
        let n = node_with(
            &["62.210.194.66:41641"],
            &["192.168.1.7:41641", "62.210.194.66:41641"],
            &["10.10.10.11:12000"],
        );
        let out = relay_endpoints(&n, 3478, &["8.8.8.8:5000".to_string()]).unwrap();
        assert_eq!(out, vec!["62.210.194.66:3478", "8.8.8.8:5000"]);
    }

    /// A static endpoint that fails the SSRF rule refuses the whole plan —
    /// the metadata service, RFC1918, the overlay range, a name.
    #[test]
    fn a_non_routable_static_endpoint_is_an_error_not_a_skip() {
        let n = node_with(&["62.210.194.66:41641"], &[], &[]);
        for bad in [
            "169.254.169.254:80",
            "10.0.0.5:3478",
            "100.64.0.1:3478",
            "127.0.0.1:3478",
            "relay.example.com:3478",
        ] {
            assert!(
                relay_endpoints(&n, 3478, &[bad.to_string()]).is_err(),
                "{bad} must refuse"
            );
            assert!(!valid_static_endpoint(bad), "{bad} must not validate");
        }
        assert!(valid_static_endpoint("62.210.194.66:3478"));
        assert!(!valid_static_endpoint("62.210.194.66:0"));
    }

    /// A reaper holding an old observation must not delete a replacement.
    /// Simulate the exact read/replace/remove interleaving; the two threads
    /// synchronize so this test does not depend on scheduler timing.
    #[test]
    fn expired_observation_never_reaps_a_replacement_session() {
        use std::sync::{Arc, mpsc};
        let st = Arc::new(OrgRelayState::new());
        let relay = ObjectId::new();
        let party = |id| SessionParty {
            node_id: id,
            node_ref: NodeRef::Agent { agent_id: id },
        };
        let member = |id| SessionMember {
            party: party(id),
            wg_public_key: "k".into(),
            bind_secret: "s".into(),
        };
        let now = Instant::now();
        let old = OrgRelaySession {
            tenant_id: ObjectId::new(),
            pair_key: "pair".into(),
            vni: 21,
            generation: 10,
            relay: party(relay),
            relay_agent_id: relay,
            implicit: false,
            members: [member(ObjectId::new()), member(ObjectId::new())],
            endpoints: vec!["relay".into()],
            expires_at: now - Duration::from_secs(1),
            bind_by: now,
            hops: Vec::new(),
        };
        let mut replacement = old.clone();
        replacement.vni = 22;
        replacement.generation = 11;
        replacement.expires_at = now + Duration::from_secs(60);
        st.sessions.insert("pair".into(), old);
        let (read_tx, read_rx) = mpsc::channel();
        let (replace_tx, replace_rx) = mpsc::channel();
        let worker_st = Arc::clone(&st);
        let worker = std::thread::spawn(move || {
            let observed = worker_st.sessions.get("pair").unwrap().value().clone();
            assert!(observed.expires_at <= now);
            read_tx.send(()).unwrap();
            replace_rx.recv().unwrap();
            assert!(!worker_st.remove_expired_session("pair", now));
        });
        read_rx.recv().unwrap();
        st.sessions.insert("pair".into(), replacement);
        replace_tx.send(()).unwrap();
        worker.join().unwrap();
        let current = st.active_session("pair").unwrap();
        assert_eq!((current.vni, current.generation), (22, 11));
        assert_eq!(st.sessions_on_relay(relay), 1);
        st.next_vni.insert(relay, 22);
        assert_ne!(st.alloc_vni(relay), Some(22));
        assert_eq!(st.active_session("missing").map(|s| s.generation), None);
        st.sessions.get_mut("pair").unwrap().expires_at = now - Duration::from_secs(1);
        assert!(st.active_session("pair").is_none());
        assert_eq!(st.sessions_on_relay(relay), 0);
    }

    /// VNIs are per relay, never 0 or the STUN cookie, and never one a live
    /// session on that relay still holds.
    #[test]
    fn vni_allocation_skips_reserved_and_in_use_values() {
        let st = OrgRelayState::new();
        let relay = ObjectId::new();
        // Park the cursor just below the STUN cookie and check it is skipped.
        st.next_vni.insert(relay, limits::STUN_COOKIE_VNI - 1);
        assert_eq!(st.alloc_vni(relay), Some(limits::STUN_COOKIE_VNI - 1));
        assert_eq!(st.alloc_vni(relay), Some(limits::STUN_COOKIE_VNI + 1));
        // Wrap at the 24-bit ceiling, skipping 0.
        st.next_vni.insert(relay, limits::VNI_MAX);
        assert_eq!(st.alloc_vni(relay), Some(limits::VNI_MAX));
        assert_eq!(st.alloc_vni(relay), Some(1));
        // Another relay has its own space.
        assert_eq!(st.alloc_vni(ObjectId::new()), Some(1));
    }

    #[test]
    fn path_rank_uses_worst_class_and_saturating_known_rtt_for_any_length() {
        use ProbeVerdict::{Reachable as R, Unknown as U, Unreachable as X};
        assert_eq!(rank_legs([R(5), R(9)]), (0, 14));
        assert_eq!(rank_legs([R(5), U, R(7), U, R(9)]), (1, 21));
        assert_eq!(rank_legs([R(5), X, U, R(9)]), (2, 14));
        assert_eq!(rank_legs([R(u32::MAX), R(1)]), (0, u32::MAX));
        // A later unknown edge can equalize earlier classes, so a search may
        // not discard the lower-RTT unknown prefix using one Dijkstra label.
        assert!(rank_legs([R(100), U]) > rank_legs([U, U]));
    }

    #[test]
    fn multi_relay_session_tracks_every_leg_and_revokes_every_bridge() {
        let ids: Vec<_> = (0..5).map(|_| ObjectId::new()).collect();
        let party = |id| SessionParty {
            node_id: id,
            node_ref: NodeRef::Agent { agent_id: id },
        };
        let member = |id| SessionMember {
            party: party(id),
            wg_public_key: "k".into(),
            bind_secret: "s".into(),
        };
        let hops: Vec<_> = (1..=3)
            .map(|i| LineLeg {
                relay: party(ids[i]),
                relay_agent_id: ids[i],
                vni: 10 + i as u32,
                generation: 100 + i as u64,
                endpoints: vec![format!("relay{i}")],
                private_endpoint: format!("10.0.0.{i}:1234"),
                requires_cross_border_approval: true,
                bridge_id: ObjectId::new(),
                bridge_secrets: ["a".into(), "b".into()],
            })
            .collect();
        let session = OrgRelaySession {
            tenant_id: ObjectId::new(),
            pair_key: "test".into(),
            vni: 10,
            generation: 100,
            relay: party(ids[0]),
            relay_agent_id: ids[0],
            implicit: false,
            members: [member(ids[4]), member(ObjectId::new())],
            endpoints: vec!["ingress".into()],
            expires_at: Instant::now(),
            bind_by: Instant::now(),
            hops,
        };
        assert_eq!(session.relay_nodes().collect::<Vec<_>>(), ids[..4]);
        for (i, id) in ids[..4].iter().enumerate() {
            assert!(session.involves(*id));
            assert!(session.involves_agent(*id));
            assert!(session.relayed_by_agent(*id));
            assert_eq!(
                session.vnis_on(*id).collect::<Vec<_>>(),
                vec![10 + i as u32]
            );
        }
        assert_eq!(session.member_leg(0).relay_node_id, ids[0]);
        assert_eq!(session.member_leg(1).relay_node_id, ids[3]);
        assert_eq!(session.member_leg(1).vni, 13);
        let edge = |i: usize| meshharbor_remote_control::models::PeerRelayBackboneEdge {
            relay_agent_id: ids[i + 1].to_hex(),
            endpoint: session.hops[i].private_endpoint.clone(),
            cross_border: true,
        };
        assert!(!session.has_removed_line_edge(ids[1], &[edge(1)]));
        assert!(session.has_removed_line_edge(ids[1], &[]));
        let mut changed = edge(1);
        changed.endpoint = "10.0.0.99:1234".into();
        assert!(session.has_removed_line_edge(ids[1], &[changed.clone()]));
        let mut no_crossing = edge(1);
        no_crossing.cross_border = false;
        assert!(session.has_removed_line_edge(ids[1], &[no_crossing.clone()]));
        let mut mixed = session.clone();
        mixed.hops[1].requires_cross_border_approval = false;
        assert!(!mixed.has_removed_line_edge(ids[1], &[no_crossing]));
        assert!(
            !mixed.has_removed_line_edge(ids[1], &[edge(1)]),
            "additional approval is allowed"
        );
        assert!(
            mixed.has_removed_line_edge(ids[1], &[]),
            "ordinary edge removal revokes too"
        );
        assert!(
            mixed.has_removed_line_edge(ids[1], &[changed]),
            "ordinary edge endpoint must still match"
        );
        assert!(
            mixed.has_removed_line_edge(
                ids[0],
                &[meshharbor_remote_control::models::PeerRelayBackboneEdge {
                    relay_agent_id: ids[1].to_hex(),
                    endpoint: mixed.hops[0].private_endpoint.clone(),
                    cross_border: false,
                }]
            ),
            "a different cross-border edge retains its own requirement"
        );
        assert!(!session.has_removed_line_edge(ObjectId::new(), &[]));
        let messages = session.hop_revocations();
        assert_eq!(messages.len(), 6);
        for i in 0..3 {
            assert_eq!(
                messages[2 * i].0,
                NodeRef::Agent {
                    agent_id: ids[i + 1]
                }
            );
            assert!(
                matches!(&messages[2*i].1, ServerMsg::OverlayRelayRevoke { vni, scope }
                    if *vni == 11 + i as u32 && scope.generation == session.hops[i].generation
                        && scope.relay_node_id == session.hops[i].relay.node_id
                        && scope.peer_node_id.is_none())
            );
            assert_eq!(messages[2 * i + 1].0, NodeRef::Agent { agent_id: ids[i] });
            assert!(
                matches!(messages[2*i+1].1, ServerMsg::OverlayRelayBridgeRevoke { trial_id, generation }
                if trial_id == session.hops[i].bridge_id && generation == 100 + i as u64)
            );
        }
    }

    /// A report is accepted only about a relay + endpoint the server minted
    /// for that node.
    #[test]
    fn probes_are_accepted_only_for_minted_targets() {
        let st = OrgRelayState::new();
        let (a, b, relay) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let party = |id| SessionParty {
            node_id: id,
            node_ref: NodeRef::Agent { agent_id: id },
        };
        st.sessions.insert(
            "pk".into(),
            OrgRelaySession {
                tenant_id: ObjectId::new(),
                pair_key: "pk".into(),
                vni: 7,
                generation: 1,
                relay: party(relay),
                relay_agent_id: relay,
                implicit: false,
                members: [
                    SessionMember {
                        party: party(a),
                        wg_public_key: "a".into(),
                        bind_secret: "s".into(),
                    },
                    SessionMember {
                        party: party(b),
                        wg_public_key: "b".into(),
                        bind_secret: "t".into(),
                    },
                ],
                endpoints: vec!["8.8.8.8:3478".into()],
                expires_at: Instant::now() + Duration::from_secs(60),
                bind_by: Instant::now() + Duration::from_secs(30),
                hops: Vec::new(),
            },
        );
        assert!(st.record_probe(a, relay, "8.8.8.8:3478".into(), true, Some(12)));
        assert!(
            !st.record_probe(a, relay, "8.8.4.4:3478".into(), true, None),
            "an endpoint never minted"
        );
        assert!(
            !st.record_probe(ObjectId::new(), relay, "8.8.8.8:3478".into(), true, None),
            "a stranger"
        );
        assert_eq!(
            st.probe_verdict(a, relay, Instant::now()),
            ProbeVerdict::Reachable(12)
        );
        assert_eq!(
            st.probe_verdict(b, relay, Instant::now()),
            ProbeVerdict::Unknown
        );
        assert!(st.record_probe(b, relay, "8.8.8.8:3478".into(), false, None));
        assert_eq!(
            st.probe_verdict(b, relay, Instant::now()),
            ProbeVerdict::Unreachable
        );
    }

    #[test]
    fn the_newest_probe_decides_and_rtt_counts_only_since_the_last_failure() {
        let map = DashMap::new();
        let (reporter, relay) = (ObjectId::new(), ObjectId::new());
        let now = Instant::now();
        let rec = |reachable, rtt_ms| ProbeRecord {
            endpoint: "8.8.8.8:3478".into(),
            reachable,
            rtt_ms,
            at: now,
        };
        map.insert(
            (reporter, relay),
            vec![rec(true, Some(5)), rec(false, None)],
        );
        assert_eq!(
            verdict_of(&map, reporter, relay, now),
            ProbeVerdict::Unreachable,
            "a failure measured after a success is the relay's state now"
        );
        map.get_mut(&(reporter, relay))
            .unwrap()
            .push(rec(true, Some(40)));
        assert_eq!(
            verdict_of(&map, reporter, relay, now),
            ProbeVerdict::Reachable(40),
            "an RTT measured before the failure no longer counts"
        );
        map.get_mut(&(reporter, relay))
            .unwrap()
            .push(rec(true, Some(30)));
        assert_eq!(
            verdict_of(&map, reporter, relay, now),
            ProbeVerdict::Reachable(30)
        );
        let stale = now + Duration::from_secs(limits::PROBE_TTL_SECS);
        assert_eq!(
            verdict_of(&map, reporter, relay, stale),
            ProbeVerdict::Unknown
        );
    }

    #[test]
    fn a_relay_with_one_live_endpoint_stays_reachable_whatever_the_report_order() {
        let map = DashMap::new();
        let (reporter, relay) = (ObjectId::new(), ObjectId::new());
        let now = Instant::now();
        let rec = |endpoint: &str, reachable, rtt_ms| ProbeRecord {
            endpoint: endpoint.into(),
            reachable,
            rtt_ms,
            at: now,
        };
        map.insert(
            (reporter, relay),
            vec![
                rec("8.8.8.8:3478", true, Some(9)),
                rec("8.8.4.4:3478", false, None),
            ],
        );
        assert_eq!(
            verdict_of(&map, reporter, relay, now),
            ProbeVerdict::Reachable(9),
            "the dead endpoint's newer report does not hide the live one"
        );
        map.get_mut(&(reporter, relay))
            .unwrap()
            .push(rec("8.8.8.8:3478", false, None));
        assert_eq!(
            verdict_of(&map, reporter, relay, now),
            ProbeVerdict::Unreachable,
            "every endpoint's newest report failed"
        );
    }

    #[test]
    fn a_loss_pin_offers_its_relay_as_the_only_one_after_a_growing_wait() {
        let st = OrgRelayState::new();
        let relay = ObjectId::new();
        st.mark_lossy("pk", relay, Instant::now() + Duration::from_secs(600));
        assert!(st.is_lossy("pk", relay, Instant::now()));
        assert!(!st.loss_pin_sole_retry_due("pk", relay, Instant::now()));
        st.age_loss_pin("pk", relay, LOSS_PIN_SOLE_RETRY);
        assert!(
            st.loss_pin_sole_retry_due("pk", relay, Instant::now()),
            "first strike: due after LOSS_PIN_SOLE_RETRY"
        );
        assert!(
            st.is_lossy("pk", relay, Instant::now()),
            "and still pinned while another relay can take the pair"
        );
        // Pinned again inside the strike window: the wait doubles.
        st.mark_lossy("pk", relay, Instant::now() + Duration::from_secs(600));
        st.age_loss_pin("pk", relay, LOSS_PIN_SOLE_RETRY);
        assert!(!st.loss_pin_sole_retry_due("pk", relay, Instant::now()));
        st.age_loss_pin("pk", relay, LOSS_PIN_SOLE_RETRY);
        assert!(st.loss_pin_sole_retry_due("pk", relay, Instant::now()));
        // However many strikes, the wait never outlasts the pin.
        for _ in 0..8 {
            st.mark_lossy("pk", relay, Instant::now() + Duration::from_secs(300));
        }
        st.age_loss_pin("pk", relay, Duration::from_secs(299));
        assert!(!st.loss_pin_sole_retry_due("pk", relay, Instant::now()));
        st.age_loss_pin("pk", relay, Duration::from_secs(1));
        assert!(st.loss_pin_sole_retry_due("pk", relay, Instant::now()));
        assert!(!st.is_lossy("pk", relay, Instant::now()));
        // Another pair is not touched.
        assert!(!st.is_lossy("other", relay, Instant::now()));
        assert!(st.loss_pin_sole_retry_due("other", relay, Instant::now()));
    }

    #[test]
    fn an_unbound_demotion_is_scoped_to_its_pair_and_ends() {
        let st = OrgRelayState::new();
        let relay = ObjectId::new();
        let now = Instant::now();
        st.demote_unbound("pk", relay, now + Duration::from_secs(5));
        assert!(st.is_unbound_demoted("pk", relay, now));
        assert!(!st.is_unbound_demoted("other", relay, now));
        assert!(!st.is_unbound_demoted("pk", relay, now + Duration::from_secs(5)));
        assert!(
            !st.is_unbound_demoted("pk", relay, now),
            "an expired mark is gone"
        );
    }

    #[test]
    fn scoped_probe_uses_only_current_endpoint_and_never_invents_zero_rtt() {
        let map = DashMap::new();
        let reporter = ObjectId::new();
        let relay = ObjectId::new();
        let now = Instant::now();
        let active = vec!["10.0.0.2:3478".to_string()];
        let record = |endpoint: &str, reachable, rtt_ms, at| ProbeRecord {
            endpoint: endpoint.into(),
            reachable,
            rtt_ms,
            at,
        };
        map.insert(
            (reporter, relay),
            vec![
                record("10.0.0.1:3478", true, Some(1), now),
                record("10.0.0.2:3478", false, None, now),
                record("10.0.0.2:3478", true, None, now),
            ],
        );
        assert_eq!(
            scoped_probe_verdict(&map, reporter, relay, &active, Some(now), now),
            ProbeVerdict::Unknown
        );
        map.get_mut(&(reporter, relay))
            .unwrap()
            .push(record("10.0.0.2:3478", true, Some(34), now));
        assert_eq!(
            scoped_probe_verdict(&map, reporter, relay, &active, Some(now), now),
            ProbeVerdict::Reachable(34)
        );
        let stale = now + Duration::from_secs(limits::PROBE_TTL_SECS);
        assert_eq!(
            scoped_probe_verdict(&map, reporter, relay, &active, Some(now), stale),
            ProbeVerdict::Unknown
        );
        assert_eq!(
            scoped_probe_verdict(&map, reporter, relay, &[], Some(now), now),
            ProbeVerdict::Unknown
        );
        assert_eq!(
            scoped_probe_verdict(&map, reporter, relay, &active, None, now),
            ProbeVerdict::Unknown
        );
        assert_eq!(
            scoped_probe_verdict(
                &map,
                reporter,
                relay,
                &active,
                Some(now + Duration::from_nanos(1)),
                now
            ),
            ProbeVerdict::Unknown
        );
    }

    #[test]
    fn displaced_connection_cannot_record_a_late_probe() {
        let state = OrgRelayState::new();
        let identity = ObjectId::new();
        let reporter = ObjectId::new();
        let relay = ObjectId::new();
        let endpoint = "8.8.8.8:3478".to_string();
        state.offer_probes(
            reporter,
            &[RelayProbeTargetWire {
                relay_node_id: relay,
                endpoints: vec![endpoint.clone()],
            }],
        );
        assert!(state.bind_live_conn(identity, "old").is_none());
        assert!(state.record_probe_from_connection(
            (identity, "old"),
            reporter,
            relay,
            endpoint.clone(),
            true,
            Some(4)
        ));
        let first = state.live_conns.get(&identity).unwrap().bound_at;
        assert_eq!(
            state.bind_live_conn(identity, "new"),
            Some("old".to_string())
        );
        assert!(
            state
                .note_join_from_connection(identity, "old", reporter, JoinExtras::default())
                .is_none()
        );
        assert!(
            state
                .note_join_from_connection(identity, "new", reporter, JoinExtras::default())
                .is_some()
        );
        let second = state.live_conns.get(&identity).unwrap().bound_at;
        assert!(second >= first);
        assert!(!state.record_probe_from_connection(
            (identity, "old"),
            reporter,
            relay,
            endpoint.clone(),
            true,
            Some(1)
        ));
        assert_eq!(state.probes.get(&(reporter, relay)).unwrap().len(), 1);
        assert!(!state.unbind_live_conn(identity, "old"));
        assert!(state.record_probe_from_connection(
            (identity, "new"),
            reporter,
            relay,
            endpoint.clone(),
            true,
            Some(7)
        ));
        assert!(state.unbind_live_conn(identity, "new"));
        assert!(!state.record_probe_from_connection(
            (identity, "new"),
            reporter,
            relay,
            endpoint,
            true,
            Some(1)
        ));
    }

    #[test]
    fn multi_candidate_capability_is_replaced_not_latched_on_rejoin() {
        let state = OrgRelayState::new();
        let node = ObjectId::new();
        state.note_join(
            node,
            JoinExtras {
                supports_org_relay_multi_candidate: true,
                ..Default::default()
            },
        );
        assert!(state.join_extras(node).supports_org_relay_multi_candidate);
        state.note_join(node, JoinExtras::default());
        assert!(!state.join_extras(node).supports_org_relay_multi_candidate);
    }

    #[test]
    fn a_young_pair_moves_only_for_a_clear_measured_win() {
        assert!(clearly_better((0, 48), (0, 91)), "measured, 47% faster");
        assert!(
            clearly_better((0, 300), (2, 0)),
            "the current relay was measured unreachable"
        );
        assert!(
            !clearly_better((0, 48), (1, 0)),
            "half a round is not a comparison"
        );
        assert!(!clearly_better((0, 85), (0, 91)), "under 20%");
        assert!(!clearly_better((0, 4), (0, 12)), "under 10 ms");
        assert!(
            !clearly_better((1, 0), (0, 91)),
            "the target is not measured by both"
        );
    }

    #[test]
    fn listener_withdrawal_stays_withdrawn_but_legacy_missing_port_is_supported() {
        let state = OrgRelayState::new();
        let node = ObjectId::new();
        let extras = |port| JoinExtras {
            org_primary: Some(true),
            relay_port: port,
            relay_withdrawn: false,
            supports_org_relay_multi_candidate: false,
            supports_org_relay_discovery_cursor: false,
            supports_path_trial_v1: false,
            supports_path_backbone_v1: false,
            relay_backbone_ready: false,
            supports_backbone_only_v1: false,
        };
        assert!(!state.note_join(node, extras(None)));
        assert!(
            !state.join_extras(node).relay_withdrawn,
            "legacy missing port still uses default"
        );
        assert!(!state.note_join(node, extras(Some(3478))));
        assert!(state.note_join(node, extras(None)));
        assert!(state.join_extras(node).relay_withdrawn);
        assert!(!state.note_join(node, extras(None)));
        assert!(
            state.join_extras(node).relay_withdrawn,
            "empty repeated join cannot resurrect listener"
        );
        assert!(!state.note_join(node, extras(Some(3479))));
        assert!(!state.join_extras(node).relay_withdrawn);
        assert!(
            state.note_join(node, extras(Some(3480))),
            "port replacement retires old sessions"
        );
    }
}

#[cfg(test)]
mod discovery_traversal_tests {
    use super::*;
    fn hint(n: u8) -> OrgRelayCandidateWire {
        OrgRelayCandidateWire {
            path: RelayPathWire::new(vec![ObjectId::from_bytes([n; 12])]).unwrap(),
            requester_at_exit: false,
            endpoints: vec!["8.8.8.8:3478".into()],
        }
    }
    #[test]
    fn discovery_traversal_five_relays_preserves_preference_and_wraps() {
        let all: Vec<_> = [5, 2, 4, 1, 3].into_iter().map(hint).collect();
        // Initial response is the original planner preference, not lowest IDs.
        let preferred = all[..3].to_vec();
        let mut cursor = preferred
            .iter()
            .max_by_key(|c| discovery_key(c))
            .map(discovery_cursor)
            .unwrap();
        let mut seen: std::collections::HashSet<_> = preferred.iter().map(discovery_key).collect();
        for _ in 0..2 {
            let (page, next) = discovery_page(all.clone().into_iter(), cursor);
            assert_eq!(page.len(), 3);
            assert_eq!(
                page.iter()
                    .map(discovery_key)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                3
            );
            // Every page presents hints in original planner preference order.
            assert!(
                page.windows(2)
                    .all(|p| all.iter().position(|c| c == &p[0])
                        < all.iter().position(|c| c == &p[1]))
            );
            seen.extend(page.iter().map(discovery_key));
            cursor = next.unwrap();
        }
        assert_eq!(seen.len(), 5);
        // Wrapped cursor is the last canonical traversal entry, not max or last displayed.
        let (page, next) = discovery_page(all.into_iter(), discovery_cursor(&hint(4)));
        assert_eq!(next.unwrap(), discovery_cursor(&hint(2)));
        assert_eq!(
            page.iter()
                .map(|c| c.requester_relay_node_id())
                .collect::<Vec<_>>(),
            vec![
                hint(5).requester_relay_node_id(),
                hint(2).requester_relay_node_id(),
                hint(1).requester_relay_node_id()
            ]
        );
    }
    #[test]
    fn discovery_traversal_dynamic_set_unknown_cursor_empty_and_duplicate_bounds() {
        let cursor = discovery_cursor(&hint(3));
        let mut all = vec![hint(1), hint(2), hint(4), hint(5)]; // revoked 3 absent
        all.push(hint(6)); // newly joined relay, no leaf address input
        let mut next = cursor.clone();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let (page, c) = discovery_page(all.clone().into_iter().chain(all.clone()), next);
            assert!(
                page.len() <= 3
                    && page
                        .iter()
                        .all(|c| c.requester_relay_node_id() != hint(3).requester_relay_node_id())
            );
            assert_eq!(
                page.iter()
                    .map(discovery_key)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                page.len()
            );
            seen.extend(page.iter().map(discovery_key));
            next = c.unwrap();
        }
        assert_eq!(seen.len(), 5);
        let (page, next) = discovery_page(std::iter::empty(), cursor);
        assert!(page.is_empty() && next.is_none());
        let (page, _) = discovery_page(vec![hint(1)].into_iter(), discovery_cursor(&hint(99)));
        assert_eq!(page, vec![hint(1)]);
    }

    #[test]
    fn tunnel_client_request_zone_fails_closed_on_overlay_lookup_error_and_checks_agreement() {
        let tid = ObjectId::new();
        // Ok(None): no overlay node row -> permits the request origin's zone.
        assert_eq!(
            resolve_request_zone_with_overlay_lookup::<(), &str>(
                tid,
                "tc-machine",
                BusinessZone::Mainland,
                Ok(None),
                |_, _| unreachable!("agree not called when Ok(None)"),
            ),
            Some(BusinessZone::Mainland)
        );
        // Ok(Some(node)) with agreeing advertised addresses -> permits the zone.
        assert_eq!(
            resolve_request_zone_with_overlay_lookup::<&str, &str>(
                tid,
                "tc-machine",
                BusinessZone::Mainland,
                Ok(Some("node-row")),
                |node, z| *node == "node-row" && z == BusinessZone::Mainland,
            ),
            Some(BusinessZone::Mainland)
        );
        // Ok(Some(node)) with conflicting advertised addresses -> withdraws zone (None).
        assert_eq!(
            resolve_request_zone_with_overlay_lookup::<&str, &str>(
                tid,
                "tc-machine",
                BusinessZone::Mainland,
                Ok(Some("node-row")),
                |_, _| false,
            ),
            None
        );
        // Err(e): database lookup failure -> fails closed (None).
        assert_eq!(
            resolve_request_zone_with_overlay_lookup::<(), &str>(
                tid,
                "tc-machine",
                BusinessZone::NonMainland,
                Err("simulated overlay_nodes storage error"),
                |_, _| true,
            ),
            None
        );
    }
}
