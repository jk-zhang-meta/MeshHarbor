use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use stun::agent::*;
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use tokio::time::{Duration, Instant};

use crate::agent::agent_internal::*;
use crate::candidate::*;
use crate::control::*;
use crate::priority::*;
use crate::use_candidate::*;

/// Roomler patch (follow-renomination v2, 2026-07-28): how long the currently
/// selected pair may go without ANY inbound before a renomination onto an
/// overlay-remote pair is accepted as a failover. Live pairs see STUN consent
/// checks and media continuously, so 3 s of silence means the pair is dying.
const FOLLOW_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3);

/// Whether the controlled/controlling agent should switch its selected pair
/// to a newly (re)nominated one.
///
/// rc.260 (follow everything) died in the field: Chrome nominates a
/// half-blackholed mongrel pair early — its remote is the controller's
/// overlay-TUN host candidate, whose reverse leg routes into the TUN with a
/// physical source — and following it killed SCTP ~4 s into every session.
/// rc.262 (never follow) survives but pins media to the first-nominated
/// overlay pair even when a clean real-path srflx pair sits validated and
/// idle (field 2026-07-28: video on an 89 ms churn relay while the 11 ms
/// srflx pair carried nothing; TeamViewer on the same host was smooth).
///
/// v2 follows only when it cannot be the poison case; v2.1 (rc.268) adds the
/// UPWARD-ONLY gate after field thrash:
/// - the new pair's REMOTE parses to a real-path (non-overlay-range) IP AND
///   the new pair's priority is STRICTLY greater than the current one —
///   upgrading onto srflx/public pairs is safe, but equal-priority siblings
///   are not a migration. Field (rc.267, WINHOST-C): the agent gathers
///   one srflx candidate per STUN server (7 sockets, equal priority); Chrome
///   aggressively nominated each in turn and v2 followed every one — 7
///   selection switches in one second, each changing the sending socket
///   (fresh NAT flow) — visible as 1–2 s delivery gaps. Strict `>` makes
///   sibling nominations no-ops while host→srflx still migrates; or
/// - the currently selected pair is STALE (no inbound for
///   [`FOLLOW_STALE_AFTER`]) — any nominated pair beats riding a dead one,
///   equal/lower priority included.
///
/// Unparseable remotes (mDNS names) are conservatively treated as
/// overlay-possible. Env overrides: `ROOMLER_ICE_FOLLOW_RENOMINATION=0`
/// never follows (rc.262 semantics), `=1` always follows (rc.260 semantics).
fn selected_pair_inbound_age(pair: &CandidatePair, use_pair_proof: bool) -> Duration {
    let authenticated = if use_pair_proof {
        pair.authenticated_age()
    } else {
        None
    };
    authenticated.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(pair.remote.last_received())
            .unwrap_or_default()
    })
}
fn same_pair(a: &CandidatePair, b: &CandidatePair) -> bool {
    a.local.equal(&*b.local) && a.remote.equal(&*b.remote)
}
fn direct_real_path(pair: &CandidatePair) -> bool {
    [&pair.local, &pair.remote].iter().all(|candidate| {
        candidate.candidate_type() != CandidateType::Relay
            && candidate
                .address()
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| !crate::agent::agent_gather::is_roomler_overlay_ip(&ip))
    })
}
fn should_follow_renomination(
    new_pair: &CandidatePair,
    current: &CandidatePair,
    use_pair_proof: bool,
) -> bool {
    let new_remote_is_real_path = new_pair
        .remote
        .address()
        .parse::<std::net::IpAddr>()
        .map(|ip| !crate::agent::agent_gather::is_roomler_overlay_ip(&ip))
        .unwrap_or(false);
    let current_stale = selected_pair_inbound_age(current, use_pair_proof) > FOLLOW_STALE_AFTER;
    follow_renomination_policy(
        std::env::var("ROOMLER_ICE_FOLLOW_RENOMINATION")
            .ok()
            .as_deref(),
        new_remote_is_real_path,
        new_pair.priority() > current.priority(),
        current_stale,
    )
}

/// Pure decision core of [`should_follow_renomination`] — unit-tested.
fn follow_renomination_policy(
    env: Option<&str>,
    new_remote_is_real_path: bool,
    new_prio_higher: bool,
    current_stale: bool,
) -> bool {
    match env {
        Some("0") => false,
        Some("1") => true,
        _ => (new_remote_is_real_path && new_prio_higher) || current_stale,
    }
}

/// Roomler patch (warm standby, 2026-07-28): cadence for pinging validated
/// pairs that are NOT the selected one. Upstream keepalives only the selected
/// pair, so every other validated pair's NAT mapping expires minutes after it
/// goes idle (field, WINHOST-C: the agent's srflx mapping died within
/// ~4–13 min of media settling on the overlay-host pair — killing the exact
/// real-path fallback needed when the overlay carrier stalls). A controlled
/// binding request never carries USE-CANDIDATE, so a warm ping can't change
/// anyone's selection; the peer's success response refreshes the far-side
/// mapping too.
const WARM_STANDBY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

impl AgentInternal {
    /// Maintain only pairs from this ICE generation's checklist. Pacing is
    /// pair-owned (local sockets/remotes can be shared), capped at four per tick.
    /// Authenticated replies, not a successful send or candidate RX, grant proof.
    fn migration_terminal(&self) -> bool {
        *self.closed.borrow()
            || matches!(
                crate::state::ConnectionState::from(self.connection_state.load(Ordering::SeqCst)),
                crate::state::ConnectionState::Failed | crate::state::ConnectionState::Closed
            )
    }
    async fn refresh_selected_consent(&self) {
        if self.migration_terminal() || self.keepalive_interval.is_zero() {
            return;
        }
        if let Some(selected) = self.agent_conn.get_selected_pair() {
            if selected.probe_due(self.keepalive_interval) {
                self.ping_candidate(&selected.local, &selected.remote).await;
            }
        }
    }
    async fn warm_standby_pairs(&self) {
        self.refresh_standby_pairs(WARM_STANDBY_INTERVAL, false, false)
            .await;
    }
    async fn refresh_standby_pairs(
        &self,
        interval: Duration,
        direct_only: bool,
        check_unvalidated: bool,
    ) {
        if self.migration_terminal()
            || std::env::var("ROOMLER_ICE_WARM_STANDBY").as_deref() == Ok("0")
        {
            return;
        }
        let selected = self.agent_conn.get_selected_pair();
        let standby: Vec<_> = {
            let checklist = self.agent_conn.checklist.lock().await;
            checklist
                .iter()
                .filter(|p| {
                    let state = p.state.load(Ordering::SeqCst);
                    state == CandidatePairState::Succeeded as u8
                        || (check_unvalidated
                            && (state == CandidatePairState::Waiting as u8
                                || state == CandidatePairState::InProgress as u8))
                })
                .filter(|p| selected.as_ref().is_none_or(|s| !same_pair(p, s)))
                .filter(|p| {
                    !direct_only
                        || (direct_real_path(p)
                            && selected
                                .as_ref()
                                .is_some_and(|s| p.priority() > s.priority()))
                })
                .filter(|p| p.probe_due(interval))
                .take(4)
                .cloned()
                .collect()
        };
        for pair in standby {
            if self.migration_terminal() {
                break;
            }
            let state = pair.state.load(Ordering::SeqCst);
            if state == CandidatePairState::Waiting as u8
                || state == CandidatePairState::InProgress as u8
            {
                // Late trickled / unfinished pairs were never Succeeded, so
                // warm-only refresh cannot discover them after fast direct
                // nomination. Reuse the existing initial-check request budget,
                // with the same >max boundary, and never revive Failed pairs.
                if pair.binding_request_count.load(Ordering::SeqCst) > self.max_binding_requests {
                    pair.state
                        .store(CandidatePairState::Failed as u8, Ordering::SeqCst);
                    continue;
                }
                pair.state
                    .store(CandidatePairState::InProgress as u8, Ordering::SeqCst);
                pair.binding_request_count.fetch_add(1, Ordering::SeqCst);
            } else if state != CandidatePairState::Succeeded as u8 {
                continue;
            }
            // Sending only starts a check. Authenticated MI/live-TX/exact-local
            // success and the unchanged nomination ACK gates still own switch.
            self.ping_candidate(&pair.local, &pair.remote).await;
        }
    }
    async fn maintain_controlling_path(&self) {
        if self.migration_terminal()
            || self.keepalive_interval.is_zero()
            || !self.is_controlling.load(Ordering::SeqCst)
        {
            return;
        }
        let Some(current) = self.agent_conn.get_selected_pair() else {
            return;
        };
        self.refresh_selected_consent().await;
        let stale = !self.disconnected_timeout.is_zero()
            && selected_pair_inbound_age(&current, true) > self.disconnected_timeout;
        let on_relay = current.local.candidate_type() == CandidateType::Relay
            || current.remote.candidate_type() == CandidateType::Relay;
        // One standby batch per tick, at most four pairs. Loss refresh is
        // active; healthy relays specifically keep higher-priority P2P warm.
        if stale {
            self.refresh_standby_pairs(Duration::from_secs(2), false, true)
                .await;
        } else if on_relay {
            self.refresh_standby_pairs(Duration::from_secs(2), true, true)
                .await;
        } else {
            self.warm_standby_pairs().await;
        }
        let candidate = {
            let checklist = self.agent_conn.checklist.lock().await;
            checklist
                .iter()
                .filter(|p| !same_pair(p, &current))
                .filter(|p| {
                    p.state.load(Ordering::SeqCst) == CandidatePairState::Succeeded as u8
                        && p.authenticated_fresh()
                })
                .filter(|p| {
                    stale
                        || (on_relay
                            && direct_real_path(p)
                            && p.priority() > current.priority()
                            && p.recovery_ready(Duration::from_secs(4)))
                })
                .max_by_key(|p| p.priority())
                .cloned()
        };
        let Some(candidate) = candidate else {
            return;
        };
        let mut nominated = self.nominated_pair.lock().await;
        if self.migration_terminal()
            || !self.is_controlling.load(Ordering::SeqCst)
            || !self
                .agent_conn
                .get_selected_pair()
                .is_some_and(|p| Arc::ptr_eq(&p, &current))
            || !candidate.authenticated_fresh()
        {
            return;
        }
        // Revalidate liveness after the async probe/locks, not a stale boolean.
        let still_stale = !self.disconnected_timeout.is_zero()
            && selected_pair_inbound_age(&current, true) > self.disconnected_timeout;
        if !still_stale
            && !(on_relay
                && direct_real_path(&candidate)
                && candidate.priority() > current.priority()
                && candidate.recovery_ready(Duration::from_secs(4)))
        {
            return;
        }
        *nominated = Some(candidate);
        drop(nominated);
        // Old selected sender stays installed until the authenticated USE reply.
        self.nominate_pair().await;
    }
}

#[cfg(test)]
mod follow_renomination_tests {
    use super::follow_renomination_policy;

    #[test]
    fn v2_1_policy_matrix() {
        // args: (env, new_remote_is_real_path, new_prio_higher, current_stale)
        // Default: real-path remotes followed ONLY upward (strictly higher
        // pair priority); overlay remotes only as failover off a stale pair.
        assert!(follow_renomination_policy(None, true, true, false)); // host→srflx upgrade
        assert!(!follow_renomination_policy(None, true, false, false)); // equal-prio sibling: NO thrash
        assert!(!follow_renomination_policy(None, false, true, false)); // overlay remote, healthy current
        assert!(follow_renomination_policy(None, false, false, true)); // stale failover, any pair
        assert!(follow_renomination_policy(None, true, false, true)); // stale failover, sibling ok
                                                                      // Env pins: 0 = never (rc.262), 1 = always (rc.260).
        assert!(!follow_renomination_policy(Some("0"), true, true, true));
        assert!(follow_renomination_policy(Some("1"), false, false, false));
        // Garbage env falls back to the v2.1 rule.
        assert!(follow_renomination_policy(Some("x"), true, true, false));
        assert!(!follow_renomination_policy(Some("x"), true, false, false));
    }
}

#[async_trait]
trait ControllingSelector {
    async fn start(&self);
    async fn contact_candidates(&self);
    async fn ping_candidate(
        &self,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    );
    async fn handle_success_response(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
        remote_addr: SocketAddr,
    );
    async fn handle_binding_request(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    );
}

#[async_trait]
trait ControlledSelector {
    async fn start(&self);
    async fn contact_candidates(&self);
    async fn ping_candidate(
        &self,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    );
    async fn handle_success_response(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
        remote_addr: SocketAddr,
    );
    async fn handle_binding_request(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    );
}

impl AgentInternal {
    fn is_nominatable(&self, c: &Arc<dyn Candidate + Send + Sync>) -> bool {
        let start_time = *self.start_time.lock();
        match c.candidate_type() {
            CandidateType::Host => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.host_acceptance_min_wait.as_nanos()
            }
            CandidateType::ServerReflexive => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.srflx_acceptance_min_wait.as_nanos()
            }
            CandidateType::PeerReflexive => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.prflx_acceptance_min_wait.as_nanos()
            }
            CandidateType::Relay => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.relay_acceptance_min_wait.as_nanos()
            }
            CandidateType::Unspecified => {
                log::error!(
                    "is_nominatable invalid candidate type {}",
                    c.candidate_type()
                );
                false
            }
        }
    }

    async fn nominate_pair(&self) {
        let result = {
            let nominated_pair = self.nominated_pair.lock().await;
            if let Some(pair) = &*nominated_pair {
                // The controlling agent MUST include the USE-CANDIDATE attribute in
                // order to nominate a candidate pair (Section 8.1.1).  The controlled
                // agent MUST NOT include the USE-CANDIDATE attribute in a Binding
                // request.

                let (msg, result) = {
                    let ufrag_pwd = self.ufrag_pwd.lock().await;
                    let username =
                        ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
                    let mut msg = Message::new();
                    let result = msg.build(&[
                        Box::new(BINDING_REQUEST),
                        Box::new(TransactionId::new()),
                        Box::new(Username::new(ATTR_USERNAME, username)),
                        Box::<UseCandidateAttr>::default(),
                        Box::new(AttrControlling(self.tie_breaker.load(Ordering::SeqCst))),
                        Box::new(PriorityAttr(pair.local.priority())),
                        Box::new(MessageIntegrity::new_short_term_integrity(
                            ufrag_pwd.remote_pwd.clone(),
                        )),
                        Box::new(FINGERPRINT),
                    ]);
                    (msg, result)
                };

                if let Err(err) = result {
                    // Roomler vendor patch (2026-05-18 a third field-test host log-flood
                    // fix): downgrade per-attempt STUN build failures
                    // to DEBUG so they don't drown the rolling log,
                    // and prefix with a target so they're greppable.
                    // Per-candidate-pair build failures are not
                    // session-fatal — ICE keeps trying other pairs.
                    log::debug!(target: "webrtc_ice::nominate_pair", "STUN message build failed: {}", err);
                    None
                } else {
                    log::trace!(
                        "ping STUN (nominate candidate pair from {} to {}",
                        pair.local,
                        pair.remote
                    );
                    let local = pair.local.clone();
                    let remote = pair.remote.clone();
                    Some((msg, local, remote))
                }
            } else {
                None
            }
        };

        if let Some((msg, local, remote)) = result {
            self.send_binding_request(&msg, &local, &remote).await;
        }
    }

    pub(crate) async fn start(&self) {
        if self.is_controlling.load(Ordering::SeqCst) {
            ControllingSelector::start(self).await;
        } else {
            ControlledSelector::start(self).await;
        }
    }

    pub(crate) async fn contact_candidates(&self) {
        if self.is_controlling.load(Ordering::SeqCst) {
            ControllingSelector::contact_candidates(self).await;
        } else {
            ControlledSelector::contact_candidates(self).await;
        }
    }

    pub(crate) async fn ping_candidate(
        &self,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        if self.is_controlling.load(Ordering::SeqCst) {
            ControllingSelector::ping_candidate(self, local, remote).await;
        } else {
            ControlledSelector::ping_candidate(self, local, remote).await;
        }
    }

    pub(crate) async fn handle_success_response(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
        remote_addr: SocketAddr,
    ) {
        if self.is_controlling.load(Ordering::SeqCst) {
            ControllingSelector::handle_success_response(self, m, local, remote, remote_addr).await;
        } else {
            ControlledSelector::handle_success_response(self, m, local, remote, remote_addr).await;
        }
    }

    pub(crate) async fn handle_binding_request(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        if self.is_controlling.load(Ordering::SeqCst) {
            ControllingSelector::handle_binding_request(self, m, local, remote).await;
        } else {
            ControlledSelector::handle_binding_request(self, m, local, remote).await;
        }
    }
}

#[async_trait]
impl ControllingSelector for AgentInternal {
    async fn start(&self) {
        {
            let mut nominated_pair = self.nominated_pair.lock().await;
            *nominated_pair = None;
        }
        *self.start_time.lock() = Instant::now();
    }

    async fn contact_candidates(&self) {
        if self.migration_terminal() {
            return;
        }
        // A lite selector should not contact candidates
        if self.lite.load(Ordering::SeqCst) {
            // This only happens if both peers are lite. See RFC 8445 S6.1.1 and S6.2
            log::trace!("now falling back to full agent");
        }

        let nominated_pair_is_some = {
            let nominated_pair = self.nominated_pair.lock().await;
            nominated_pair.is_some()
        };

        if self.agent_conn.get_selected_pair().is_some() {
            if self.validate_selected_pair().await {
                log::trace!("[{}]: checking keepalive", self.get_name());
                self.maintain_controlling_path().await;
            }
        } else if nominated_pair_is_some {
            self.nominate_pair().await;
        } else {
            let has_nominated_pair =
                if let Some(p) = self.agent_conn.get_best_valid_candidate_pair().await {
                    self.is_nominatable(&p.local) && self.is_nominatable(&p.remote)
                } else {
                    false
                };

            if has_nominated_pair {
                if let Some(p) = self.agent_conn.get_best_valid_candidate_pair().await {
                    log::trace!(
                        "Nominatable pair found, nominating ({}, {})",
                        p.local.to_string(),
                        p.remote.to_string()
                    );
                    p.nominated.store(true, Ordering::SeqCst);
                    {
                        let mut nominated_pair = self.nominated_pair.lock().await;
                        *nominated_pair = Some(p);
                    }
                }

                self.nominate_pair().await;
            } else {
                self.ping_all_candidates().await;
            }
        }
    }

    async fn ping_candidate(
        &self,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        let (msg, result) = {
            let ufrag_pwd = self.ufrag_pwd.lock().await;
            let username = ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlling(self.tie_breaker.load(Ordering::SeqCst))),
                Box::new(PriorityAttr(local.priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    ufrag_pwd.remote_pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            // Roomler vendor patch (2026-05-18 a third field-test host log-flood fix):
            // see nominate_pair above; per-candidate STUN build
            // failures are not session-fatal.
            log::debug!(target: "webrtc_ice::ping_candidate", "STUN message build failed: {}", err);
        } else {
            self.send_binding_request(&msg, local, remote).await;
        }
    }

    async fn handle_success_response(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
        remote_addr: SocketAddr,
    ) {
        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id).await {
            let transaction_addr = pending_request.destination;
            let bound_local = match &pending_request.local_candidate_id {
                Some(id) if *id != local.id() => return,
                Some(_) => true,
                None => false,
            };

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                log::debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote);
                return;
            }

            log::trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote,
                local
            );
            let selected_pair_is_none = self.agent_conn.get_selected_pair().is_none();

            if let Some(p) = self.find_pair(local, remote).await {
                if bound_local {
                    p.note_authenticated_success();
                }
                p.state
                    .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
                log::trace!(
                    "Found valid candidate pair: {}, p.state: {}, isUseCandidate: {}, {}",
                    p,
                    p.state.load(Ordering::SeqCst),
                    pending_request.is_use_candidate,
                    selected_pair_is_none
                );
                // Roomler patch (follow renomination): mirror of the
                // handle_binding_request policy — when the USE-CANDIDATE
                // arrived before this pair's own check completed, the
                // triggered check's success must also honour the controlling
                // agent's latest nomination, not only a cold start.
                // Default-OFF (2026-07-27 field): following renominations let Chrome
                // steer the agent onto a half-blackholed pair (browser-TUN-host ×
                // agent-srflx validates one-way through the home-NAT masquerade;
                // the reverse direction routes into the TUN with a physical
                // source) — SCTP died ~4 s in, every session. Opt-in via
                // ROOMLER_ICE_FOLLOW_RENOMINATION=1 until the follow policy
                // validates pair liveness both ways.
                // v2 (2026-07-28): policy in should_follow_renomination() —
                // real-path remotes always, overlay remotes only off a stale
                // pair. Env: 0=never (rc.262), 1=always (rc.260).
                let follow_renomination = {
                    let selected = self.agent_conn.get_selected_pair();
                    selected.as_ref().is_some_and(|s| {
                        should_follow_renomination(&p, s, !self.keepalive_interval.is_zero())
                    })
                };
                let already_selected = {
                    let selected = self.agent_conn.get_selected_pair();
                    selected
                        .as_ref()
                        .is_some_and(|s| s.local.equal(&*p.local) && s.remote.equal(&*p.remote))
                };
                if pending_request.is_use_candidate
                    && (selected_pair_is_none || (follow_renomination && !already_selected))
                {
                    self.set_selected_pair(Some(Arc::clone(&p))).await;
                }
            } else {
                // This shouldn't happen
                log::error!("Success response from invalid candidate pair");
            }
        } else {
            log::warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote,
                m.transaction_id
            );
        }
    }

    async fn handle_binding_request(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        self.send_binding_success(m, local, remote).await;
        log::trace!("controllingSelector: sendBindingSuccess");

        if let Some(p) = self.find_pair(local, remote).await {
            let nominated_pair_is_none = {
                let nominated_pair = self.nominated_pair.lock().await;
                nominated_pair.is_none()
            };

            log::trace!(
                "controllingSelector: after findPair {}, p.state: {}, {}",
                p,
                p.state.load(Ordering::SeqCst),
                nominated_pair_is_none,
                //self.agent_conn.get_selected_pair().await.is_none() //, {}
            );
            if p.state.load(Ordering::SeqCst) == CandidatePairState::Succeeded as u8
                && nominated_pair_is_none
                && self.agent_conn.get_selected_pair().is_none()
            {
                if let Some(best_pair) = self.agent_conn.get_best_available_candidate_pair().await {
                    log::trace!(
                        "controllingSelector: getBestAvailableCandidatePair {}",
                        best_pair
                    );
                    if best_pair == p
                        && self.is_nominatable(&p.local)
                        && self.is_nominatable(&p.remote)
                    {
                        log::trace!("The candidate ({}, {}) is the best candidate available, marking it as nominated",
                            p.local, p.remote);
                        {
                            let mut nominated_pair = self.nominated_pair.lock().await;
                            *nominated_pair = Some(p);
                        }
                        self.nominate_pair().await;
                    }
                } else {
                    log::trace!("No best pair available");
                }
            }
        } else {
            log::trace!("controllingSelector: addPair");
            self.add_pair(local.clone(), remote.clone()).await;
        }
    }
}

#[async_trait]
impl ControlledSelector for AgentInternal {
    async fn start(&self) {}

    async fn contact_candidates(&self) {
        if self.migration_terminal() {
            return;
        }
        // A lite selector should not contact candidates
        if self.lite.load(Ordering::SeqCst) {
            self.validate_selected_pair().await;
        } else if self.agent_conn.get_selected_pair().is_some() {
            if self.validate_selected_pair().await {
                log::trace!("[{}]: checking keepalive", self.get_name());
                self.refresh_selected_consent().await;
                self.warm_standby_pairs().await;
            }
        } else {
            self.ping_all_candidates().await;
        }
    }

    async fn ping_candidate(
        &self,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        let (msg, result) = {
            let ufrag_pwd = self.ufrag_pwd.lock().await;
            let username = ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlled(self.tie_breaker.load(Ordering::SeqCst))),
                Box::new(PriorityAttr(local.priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    ufrag_pwd.remote_pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            // Roomler vendor patch (2026-05-18 a third field-test host log-flood fix):
            // see nominate_pair above; per-candidate STUN build
            // failures are not session-fatal.
            log::debug!(target: "webrtc_ice::ping_candidate", "STUN message build failed: {}", err);
        } else {
            self.send_binding_request(&msg, local, remote).await;
        }
    }

    async fn handle_success_response(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
        remote_addr: SocketAddr,
    ) {
        // https://tools.ietf.org/html/rfc8445#section-7.3.1.5
        // If the controlled agent does not accept the request from the
        // controlling agent, the controlled agent MUST reject the nomination
        // request with an appropriate error code response (e.g., 400)
        // [RFC5389].

        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id).await {
            let transaction_addr = pending_request.destination;
            let bound_local = match &pending_request.local_candidate_id {
                Some(id) if *id != local.id() => return,
                Some(_) => true,
                None => false,
            };

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                log::debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote);
                return;
            }

            log::trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote,
                local
            );

            if let Some(p) = self.find_pair(local, remote).await {
                if bound_local {
                    p.note_authenticated_success();
                }
                p.state
                    .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
                log::trace!("Found valid candidate pair: {}", p);
            } else {
                // This shouldn't happen
                log::error!("Success response from invalid candidate pair");
            }
        } else {
            log::warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote,
                m.transaction_id
            );
        }
    }

    async fn handle_binding_request(
        &self,
        m: &Message,
        local: &Arc<dyn Candidate + Send + Sync>,
        remote: &Arc<dyn Candidate + Send + Sync>,
    ) {
        if self.find_pair(local, remote).await.is_none() {
            self.add_pair(local.clone(), remote.clone()).await;
        }

        if let Some(p) = self.find_pair(local, remote).await {
            let use_candidate = m.contains(ATTR_USE_CANDIDATE);
            if use_candidate {
                // https://tools.ietf.org/html/rfc8445#section-7.3.1.5

                if p.state.load(Ordering::SeqCst) == CandidatePairState::Succeeded as u8 {
                    let changing = self
                        .agent_conn
                        .get_selected_pair()
                        .is_some_and(|selected| !same_pair(&p, &selected));
                    if changing && !p.authenticated_fresh() {
                        self.ping_candidate(local, remote).await;
                        return;
                    }
                    // If the state of this pair is Succeeded, it means that the check
                    // previously sent by this pair produced a successful response and
                    // generated a valid pair (Section 7.2.5.3.2).  The agent sets the
                    // nominated flag value of the valid pair to true.
                    //
                    // Roomler patch (follow renomination): upstream only set the
                    // selected pair when NONE was set, pinning the controlled
                    // agent to the FIRST nominated pair for the connection's
                    // lifetime. Browsers renominate deliberately when they
                    // switch transports (ICE renomination semantics) — e.g.
                    // Chrome moving off a deprioritized overlay-TUN host pair
                    // onto the real-path srflx pair. Follow the controlling
                    // agent's most recent nomination so both directions ride
                    // the pair it chose; without this the browser switches its
                    // send path while the agent keeps streaming media over the
                    // stale pair (field 2026-07-27, DEVBOX→WINHOST-C: video pinned
                    // to the overlay pair through carrier churn while the
                    // nominated srflx pair sat idle).
                    // Default-OFF (2026-07-27 field): following renominations let
                    // Chrome steer the agent onto a half-blackholed pair
                    // (browser-TUN-host × agent-srflx validates one-way through
                    // the home-NAT masquerade; the reverse direction routes into
                    // the TUN with a physical source) — SCTP died ~4 s in, every
                    // session. Opt-in via ROOMLER_ICE_FOLLOW_RENOMINATION=1 until
                    // the follow policy validates pair liveness both ways.
                    // v2 (2026-07-28): see should_follow_renomination().
                    let follow_renomination = {
                        let selected = self.agent_conn.get_selected_pair();
                        selected.as_ref().is_some_and(|s| {
                            should_follow_renomination(&p, s, !self.keepalive_interval.is_zero())
                        })
                    };
                    let already_selected = {
                        let selected = self.agent_conn.get_selected_pair();
                        selected
                            .as_ref()
                            .is_some_and(|s| s.local.equal(&*p.local) && s.remote.equal(&*p.remote))
                    };
                    if self.agent_conn.get_selected_pair().is_none()
                        || (follow_renomination && !already_selected)
                    {
                        self.set_selected_pair(Some(Arc::clone(&p))).await;
                    }
                    self.send_binding_success(m, local, remote).await;
                } else {
                    // If the received Binding request triggered a new check to be
                    // enqueued in the triggered-check queue (Section 7.3.1.4), once the
                    // check is sent and if it generates a successful response, and
                    // generates a valid pair, the agent sets the nominated flag of the
                    // pair to true.  If the request fails (Section 7.2.5.2), the agent
                    // MUST remove the candidate pair from the valid list, set the
                    // candidate pair state to Failed, and set the checklist state to
                    // Failed.
                    self.ping_candidate(local, remote).await;
                }
            } else {
                self.send_binding_success(m, local, remote).await;
                self.ping_candidate(local, remote).await;
            }
        }
    }
}

#[cfg(test)]
mod same_session_failover_tests {
    use super::*;
    use crate::agent::{Agent, AgentConfig, BindingRequest};
    use crate::candidate::candidate_base::{CandidateBase, CandidateBaseConfig};
    use crate::candidate::candidate_host::CandidateHostConfig;
    use crate::candidate::candidate_relay::CandidateRelayConfig;
    use crate::error::Result;
    use crate::mdns::MulticastDnsMode;
    use crate::state::ConnectionState;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        agent: Agent,
        direct: Arc<CandidatePair>,
        backup: Arc<CandidatePair>,
    }
    async fn fixture(direct_age: Duration) -> Result<Fixture> {
        fixture_with_keepalive(direct_age, None).await
    }
    async fn fixture_with_keepalive(
        direct_age: Duration,
        keepalive_interval: Option<Duration>,
    ) -> Result<Fixture> {
        // No gather/connect loop, sockets, public address, mDNS or WAN probes.
        let agent = Agent::new(AgentConfig {
            is_controlling: true,
            keepalive_interval,
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        })
        .await?;
        let local: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "127.0.0.1".into(),
                    port: 15001,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?,
        );
        let old_remote: Arc<CandidateBase> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "127.0.0.2".into(),
                    port: 15002,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?,
        );
        old_remote.set_last_received(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .saturating_sub(direct_age),
        );
        let direct = Arc::new(CandidatePair::new(local.clone(), old_remote, true));
        direct
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        let backup_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateRelayConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "127.0.0.3".into(),
                    port: 15003,
                    component: 1,
                    ..Default::default()
                },
                rel_addr: "127.0.0.3".into(),
                rel_port: 15003,
                ..Default::default()
            }
            .new_candidate_relay()?,
        );
        let backup = Arc::new(CandidatePair::new(local, backup_remote, true));
        // A previously-succeeded pair alone MUST NOT be proof of current health.
        backup
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        agent
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .extend([direct.clone(), backup.clone()]);
        {
            let mut remotes = agent.internal.remote_candidates.lock().await;
            remotes
                .entry(backup.local.network_type())
                .or_default()
                .extend([direct.remote.clone(), backup.remote.clone()]);
        }
        {
            let mut credentials = agent.internal.ufrag_pwd.lock().await;
            credentials.remote_ufrag = "remote-fragment".into();
            credentials.remote_pwd = "remote-password-with-sufficient-entropy".into();
        }
        agent.internal.set_selected_pair(Some(direct.clone())).await;
        *agent.internal.nominated_pair.lock().await = Some(direct.clone());
        Ok(Fixture {
            agent,
            direct,
            backup,
        })
    }
    async fn authenticated_response(f: &Fixture, transaction: TransactionId) -> Result<()> {
        let password = f.agent.internal.ufrag_pwd.lock().await.remote_pwd.clone();
        let mut response = Message::new();
        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(transaction),
            Box::new(MessageIntegrity::new_short_term_integrity(password)),
            Box::new(FINGERPRINT),
        ])?;
        f.agent
            .internal
            .handle_inbound(&mut response, &f.backup.local, f.backup.remote.addr())
            .await;
        Ok(())
    }
    async fn prove_backup(f: &Fixture) -> Result<()> {
        // Use the production sender to bind the nonce to its exact local
        // candidate; only socket I/O is absent in this focused state test.
        f.agent
            .internal
            .ping_candidate(&f.backup.local, &f.backup.remote)
            .await;
        let transaction = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .find(|request| {
                !request.is_use_candidate && request.destination == f.backup.remote.addr()
            })
            .expect("production connectivity probe recorded a pending transaction")
            .transaction_id;
        authenticated_response(f, transaction).await
    }
    async fn backup_nomination(f: &Fixture) -> Option<BindingRequest> {
        f.agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .find(|p| p.is_use_candidate && p.destination == f.backup.remote.addr())
            .cloned()
    }
    async fn cold_backup_probe_count(f: &Fixture) -> usize {
        f.agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .filter(|p| !p.is_use_candidate && p.destination == f.backup.remote.addr())
            .count()
    }
    #[tokio::test]
    async fn ice_same_session_cold_standby_waiting_and_inprogress_are_checked_before_nomination(
    ) -> Result<()> {
        for state in [CandidatePairState::Waiting, CandidatePairState::InProgress] {
            let f = fixture(Duration::from_secs(6)).await?;
            f.backup.state.store(state as u8, Ordering::SeqCst);
            assert!(!f.backup.authenticated_fresh());
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            assert_eq!(cold_backup_probe_count(&f).await, 1,
                "a current-generation unfinished backup must be actively checked after selected loss");
            assert_eq!(
                f.backup.state.load(Ordering::SeqCst),
                CandidatePairState::InProgress as u8
            );
            assert_eq!(f.backup.binding_request_count.load(Ordering::SeqCst), 1);
            assert!(
                backup_nomination(&f).await.is_none(),
                "a send is not pair proof"
            );
            assert!(Arc::ptr_eq(
                &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
                &f.direct
            ));
            // Repeated scheduler ticks do not bypass the pair-owned 2s budget.
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            assert_eq!(cold_backup_probe_count(&f).await, 1);
            assert_eq!(f.backup.binding_request_count.load(Ordering::SeqCst), 1);
            let tx = f
                .agent
                .internal
                .pending_binding_requests
                .lock()
                .await
                .iter()
                .find(|p| !p.is_use_candidate && p.destination == f.backup.remote.addr())
                .unwrap()
                .transaction_id;
            authenticated_response(&f, tx).await?;
            assert!(f.backup.authenticated_fresh());
            assert_eq!(
                f.backup.state.load(Ordering::SeqCst),
                CandidatePairState::Succeeded as u8
            );
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            let nomination = backup_nomination(&f)
                .await
                .expect("only authenticated fresh backup may be nominated");
            assert!(Arc::ptr_eq(
                &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
                &f.direct
            ));
            authenticated_response(&f, nomination.transaction_id).await?;
            assert!(Arc::ptr_eq(
                &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
                &f.backup
            ));
            f.agent.close().await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_cold_standby_healthy_direct_is_not_downgraded() -> Result<()> {
        let f = fixture(Duration::ZERO).await?;
        f.backup
            .state
            .store(CandidatePairState::Waiting as u8, Ordering::SeqCst);
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert_eq!(cold_backup_probe_count(&f).await, 0);
        assert_eq!(f.backup.binding_request_count.load(Ordering::SeqCst), 0);
        assert!(backup_nomination(&f).await.is_none());
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_cold_standby_failed_or_exhausted_is_not_resurrected() -> Result<()> {
        for failed in [false, true] {
            let f = fixture(Duration::from_secs(6)).await?;
            f.backup.state.store(
                if failed {
                    CandidatePairState::Failed
                } else {
                    CandidatePairState::InProgress
                } as u8,
                Ordering::SeqCst,
            );
            f.backup
                .binding_request_count
                .store(f.agent.internal.max_binding_requests + 1, Ordering::SeqCst);
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            assert_eq!(cold_backup_probe_count(&f).await, 0);
            assert!(!f.backup.authenticated_fresh());
            assert!(backup_nomination(&f).await.is_none());
            assert!(Arc::ptr_eq(
                &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
                &f.direct
            ));
            f.agent.close().await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_cold_standby_batch_is_capped_at_four() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        f.backup
            .state
            .store(CandidatePairState::Waiting as u8, Ordering::SeqCst);
        for port in 15100..15107 {
            let remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
                CandidateRelayConfig {
                    base_config: CandidateBaseConfig {
                        network: "udp".into(),
                        address: "127.0.0.6".into(),
                        port,
                        component: 1,
                        ..Default::default()
                    },
                    rel_addr: "127.0.0.6".into(),
                    rel_port: port,
                    ..Default::default()
                }
                .new_candidate_relay()?,
            );
            f.agent
                .internal
                .add_pair(f.direct.local.clone(), remote)
                .await;
        }
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let count = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .filter(|p| !p.is_use_candidate && p.destination != f.direct.remote.addr())
            .count();
        assert_eq!(
            count, 4,
            "mixed unfinished standby work stays at most four checks per tick"
        );
        assert!(backup_nomination(&f).await.is_none());
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.direct
        ));
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_stale_direct_nominates_authenticated_fresh_relay() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        prove_backup(&f).await?;
        let same_conn = f.agent.internal.agent_conn.clone();
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let nomination = backup_nomination(&f).await;
        assert!(nomination.is_some(),"stale selected direct must actively nominate the fresh authenticated backup in this same ICE generation");
        // No optimistic data-plane switch before the nomination response.
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.direct
        ));
        authenticated_response(&f, nomination.unwrap().transaction_id).await?;
        assert!(Arc::ptr_eq(&same_conn, &f.agent.internal.agent_conn));
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.backup
        ));
        assert_eq!(
            f.agent.internal.connection_state.load(Ordering::SeqCst),
            ConnectionState::Connected as u8
        );
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_healthy_direct_not_replaced_by_relay() -> Result<()> {
        let f = fixture(Duration::from_secs(0)).await?;
        prove_backup(&f).await?;
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.direct
        ));
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_unsolicited_success_not_fresh_backup_proof() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        // Correct integrity but no matching live transaction: candidate-level
        // last_received can move; pair authorization/freshness MUST NOT.
        authenticated_response(&f, TransactionId::new()).await?;
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_expired_success_not_fresh_backup_proof() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        let transaction = TransactionId::new();
        f.agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .push(BindingRequest {
                timestamp: Instant::now() - Duration::from_secs(5),
                transaction_id: transaction,
                destination: f.backup.remote.addr(),
                is_use_candidate: false,
                ..Default::default()
            });
        authenticated_response(&f, transaction).await?;
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        f.agent.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn ice_same_session_shared_remote_does_not_mask_selected_loss() -> Result<()> {
        let original = fixture(Duration::from_secs(6)).await?;
        // The active pair and the relay-local backup share the SAME remote.
        // Candidate-level last_received therefore cannot describe either path.
        let relay_local: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateRelayConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "127.0.0.4".into(),
                    port: 15004,
                    component: 1,
                    ..Default::default()
                },
                rel_addr: "127.0.0.4".into(),
                rel_port: 15004,
                ..Default::default()
            }
            .new_candidate_relay()?,
        );
        let backup = Arc::new(CandidatePair::new(
            relay_local,
            original.direct.remote.clone(),
            true,
        ));
        backup
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        original
            .agent
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .push(backup.clone());
        original.direct.proof.lock().authenticated_at =
            Some(Instant::now() - Duration::from_secs(6));
        let f = Fixture {
            agent: original.agent,
            direct: original.direct,
            backup,
        };
        prove_backup(&f).await?;
        assert!(
            SystemTime::now()
                .duration_since(f.direct.remote.last_received())
                .unwrap()
                < Duration::from_secs(1)
        );
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(
            backup_nomination(&f).await.is_some(),
            "shared remote traffic must not mask loss of the selected pair"
        );
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_stale_pair_proof_not_refreshed_by_candidate_rx() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        prove_backup(&f).await?;
        f.backup.proof.lock().authenticated_at = Some(Instant::now() - Duration::from_secs(7));
        f.backup.remote.seen(false);
        // The valid proof's request was just issued. Expiring only its auth
        // timestamp must NOT bypass the independent two-second probe budget.
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        let before = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .filter(|p| !p.is_use_candidate && p.destination == f.backup.remote.addr())
            .count();
        assert_eq!(
            before, 0,
            "no duplicate standby probe before the pair pacing deadline"
        );
        // Now advance the fixture's probe clock as well: a genuinely due,
        // expired backup must be refreshed actively, without any nomination.
        f.backup.proof.lock().probed_at = Some(Instant::now() - Duration::from_secs(3));
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        let after = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .filter(|p| !p.is_use_candidate && p.destination == f.backup.remote.addr())
            .count();
        assert_eq!(
            after, 1,
            "loss must actively refresh expired backup proof once due"
        );
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let repeated = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .filter(|p| !p.is_use_candidate && p.destination == f.backup.remote.addr())
            .count();
        assert_eq!(
            repeated, 1,
            "immediate subsequent ticks must not flood standby probes"
        );
        assert!(backup_nomination(&f).await.is_none());
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_matching_tx_wrong_local_candidate_is_not_proof() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        f.agent
            .internal
            .ping_candidate(&f.backup.local, &f.backup.remote)
            .await;
        let transaction = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .find(|p| p.destination == f.backup.remote.addr())
            .unwrap()
            .transaction_id;
        let other_local: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "127.0.0.5".into(),
                    port: 15005,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?,
        );
        let other = Arc::new(CandidatePair::new(
            other_local.clone(),
            f.backup.remote.clone(),
            true,
        ));
        other
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        f.agent
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .push(other.clone());
        let password = f.agent.internal.ufrag_pwd.lock().await.remote_pwd.clone();
        let mut response = Message::new();
        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(transaction),
            Box::new(MessageIntegrity::new_short_term_integrity(password)),
            Box::new(FINGERPRINT),
        ])?;
        f.agent
            .internal
            .handle_inbound(&mut response, &other_local, f.backup.remote.addr())
            .await;
        assert!(!other.authenticated_fresh());
        assert!(!f.backup.authenticated_fresh());
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_controlled_role_never_originates_nomination() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        prove_backup(&f).await?;
        f.agent
            .internal
            .is_controlling
            .store(false, Ordering::SeqCst);
        f.agent.internal.contact_candidates().await;
        assert!(backup_nomination(&f).await.is_none());
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_terminal_or_closed_never_revives() -> Result<()> {
        for closed in [false, true] {
            let f = fixture(Duration::from_secs(6)).await?;
            prove_backup(&f).await?;
            if closed {
                f.agent.internal.closed.send_replace(true);
            } else {
                f.agent
                    .internal
                    .connection_state
                    .store(ConnectionState::Failed as u8, Ordering::SeqCst);
            }
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            assert!(backup_nomination(&f).await.is_none());
            // Test-only restoration lets Agent::close clean its event tasks.
            if closed {
                f.agent.internal.closed.send_replace(false);
            }
            f.agent.close().await?;
        }
        Ok(())
    }
    async fn recovery_fixture(successes: u8, span: Duration) -> Result<Fixture> {
        let old = fixture(Duration::from_secs(0)).await?;
        prove_backup(&old).await?;
        old.agent
            .internal
            .set_selected_pair(Some(old.backup.clone()))
            .await;
        *old.agent.internal.nominated_pair.lock().await = Some(old.backup.clone());
        {
            let mut proof = old.direct.proof.lock();
            proof.authenticated_at = Some(Instant::now());
            proof.streak_start = Some(Instant::now() - span);
            proof.successes = successes;
        }
        Ok(Fixture {
            agent: old.agent,
            direct: old.backup,
            backup: old.direct,
        })
    }
    #[tokio::test]
    async fn ice_same_session_recovery_requires_fresh_stable_direct_then_ack() -> Result<()> {
        let f = recovery_fixture(3, Duration::from_secs(5)).await?;
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let nomination = backup_nomination(&f)
            .await
            .expect("stable fresh higher-priority direct may be renominated from relay");
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.direct
        ));
        authenticated_response(&f, nomination.transaction_id).await?;
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.backup
        ));
        f.agent.close().await?;
        Ok(())
    }
    #[tokio::test]
    async fn ice_same_session_recovery_cannot_use_short_or_expired_streak() -> Result<()> {
        for expired in [false, true] {
            let f = recovery_fixture(
                3,
                if expired {
                    Duration::from_secs(10)
                } else {
                    Duration::from_secs(1)
                },
            )
            .await?;
            if expired {
                f.backup.proof.lock().authenticated_at =
                    Some(Instant::now() - Duration::from_secs(7));
            }
            ControllingSelector::contact_candidates(&*f.agent.internal).await;
            assert!(backup_nomination(&f).await.is_none());
            f.agent.close().await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn ice_same_session_explicit_zero_keepalive_preserves_legacy_liveness() -> Result<()> {
        let f =
            fixture_with_keepalive(Duration::from_secs(0), Some(Duration::from_secs(0))).await?;
        prove_backup(&f).await?;
        f.direct.proof.lock().authenticated_at = Some(Instant::now() - Duration::from_secs(40));
        f.direct.remote.seen(false);
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(backup_nomination(&f).await.is_none());
        assert_eq!(
            f.agent.internal.connection_state.load(Ordering::SeqCst),
            ConnectionState::Connected as u8
        );
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.direct
        ));
        f.agent.close().await?;
        Ok(())
    }

    async fn nomination_request(f: &Fixture, transaction: TransactionId) -> Result<Message> {
        let credentials = f.agent.internal.ufrag_pwd.lock().await;
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(transaction),
            Box::new(Username::new(
                ATTR_USERNAME,
                credentials.remote_ufrag.clone() + ":" + &credentials.local_ufrag,
            )),
            Box::<UseCandidateAttr>::default(),
            Box::new(AttrControlling(
                f.agent.internal.tie_breaker.load(Ordering::SeqCst),
            )),
            Box::new(PriorityAttr(f.backup.local.priority())),
            Box::new(MessageIntegrity::new_short_term_integrity(
                credentials.remote_pwd.clone(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        Ok(msg)
    }
    #[tokio::test]
    async fn ice_same_session_bilateral_stale_reverse_proof_refresh_then_retry_commits(
    ) -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        prove_backup(&f).await?;
        let controlled = Agent::new(AgentConfig {
            is_controlling: false,
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        })
        .await?;
        {
            let origin = f.agent.internal.ufrag_pwd.lock().await;
            let mut target = controlled.internal.ufrag_pwd.lock().await;
            target.local_ufrag = origin.remote_ufrag.clone();
            target.local_pwd = origin.remote_pwd.clone();
            target.remote_ufrag = origin.local_ufrag.clone();
            target.remote_pwd = origin.local_pwd.clone();
        }
        let direct = Arc::new(CandidatePair::new(
            f.direct.remote.clone(),
            f.direct.local.clone(),
            false,
        ));
        direct
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        direct.proof.lock().authenticated_at = Some(Instant::now() - Duration::from_secs(6));
        let backup = Arc::new(CandidatePair::new(
            f.backup.remote.clone(),
            f.backup.local.clone(),
            false,
        ));
        backup
            .state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        controlled
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .extend([direct.clone(), backup.clone()]);
        controlled
            .internal
            .remote_candidates
            .lock()
            .await
            .entry(backup.local.network_type())
            .or_default()
            .push(backup.remote.clone());
        controlled
            .internal
            .set_selected_pair(Some(direct.clone()))
            .await;
        let origin_conn = f.agent.internal.agent_conn.clone();
        let target_conn = controlled.internal.agent_conn.clone();
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let first = backup_nomination(&f)
            .await
            .expect("origin issues a live same-generation nomination");
        let mut request = nomination_request(&f, first.transaction_id).await?;
        controlled
            .internal
            .handle_inbound(&mut request, &backup.local, backup.remote.addr())
            .await;
        assert!(
            Arc::ptr_eq(
                &controlled.internal.agent_conn.get_selected_pair().unwrap(),
                &direct
            ),
            "no fresh reverse proof: target must retain old selected path"
        );
        let reverse = controlled
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .find(|p| !p.is_use_candidate && p.destination == backup.remote.addr())
            .cloned()
            .expect("target triggers bounded reverse connectivity check before acknowledgement");
        let password = controlled
            .internal
            .ufrag_pwd
            .lock()
            .await
            .remote_pwd
            .clone();
        let mut reply = Message::new();
        reply.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(reverse.transaction_id),
            Box::new(MessageIntegrity::new_short_term_integrity(password)),
            Box::new(FINGERPRINT),
        ])?;
        controlled
            .internal
            .handle_inbound(&mut reply, &backup.local, backup.remote.addr())
            .await;
        assert!(backup.authenticated_fresh());
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        let second = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .rev()
            .find(|p| p.is_use_candidate && p.destination == f.backup.remote.addr())
            .cloned()
            .expect("origin retries nomination without a new SDP/ICE generation");
        assert_ne!(first.transaction_id, second.transaction_id);
        let mut retried = nomination_request(&f, second.transaction_id).await?;
        controlled
            .internal
            .handle_inbound(&mut retried, &backup.local, backup.remote.addr())
            .await;
        assert!(Arc::ptr_eq(
            &controlled.internal.agent_conn.get_selected_pair().unwrap(),
            &backup
        ));
        authenticated_response(&f, second.transaction_id).await?;
        assert!(Arc::ptr_eq(
            &f.agent.internal.agent_conn.get_selected_pair().unwrap(),
            &f.backup
        ));
        assert!(Arc::ptr_eq(&origin_conn, &f.agent.internal.agent_conn));
        assert!(Arc::ptr_eq(&target_conn, &controlled.internal.agent_conn));
        assert!(!controlled.internal.is_controlling.load(Ordering::SeqCst));
        assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));
        controlled.close().await?;
        f.agent.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn ice_same_session_restart_cannot_reuse_old_generation_proof_or_reply() -> Result<()> {
        let f = fixture(Duration::from_secs(6)).await?;
        prove_backup(&f).await?;
        f.agent
            .internal
            .ping_candidate(&f.backup.local, &f.backup.remote)
            .await;
        let transaction = f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .iter()
            .find(|p| p.destination == f.backup.remote.addr())
            .unwrap()
            .transaction_id;
        let old_password = f.agent.internal.ufrag_pwd.lock().await.remote_pwd.clone();
        let mut old_reply = Message::new();
        old_reply.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(transaction),
            Box::new(MessageIntegrity::new_short_term_integrity(old_password)),
            Box::new(FINGERPRINT),
        ])?;
        f.agent
            .restart(
                "fresh-generation".into(),
                "fresh-generation-password-with-sufficient-entropy".into(),
            )
            .await?;
        f.agent
            .internal
            .handle_inbound(&mut old_reply, &f.backup.local, f.backup.remote.addr())
            .await;
        ControllingSelector::contact_candidates(&*f.agent.internal).await;
        assert!(f.agent.internal.agent_conn.get_selected_pair().is_none());
        assert!(f
            .agent
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .is_empty());
        assert!(f
            .agent
            .internal
            .pending_binding_requests
            .lock()
            .await
            .is_empty());
        f.agent.close().await?;
        Ok(())
    }
}
