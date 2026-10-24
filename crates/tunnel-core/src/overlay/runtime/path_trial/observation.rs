//! Read-only projection of Engine-owned accepted phases. Never routing input.
use super::*;
use crate::localapi::{
    PathTrialEvent, PathTrialInfo, PathTrialPhase, PathTrialResetDiagnostics, PathTrialResetReason,
    PathTrialSample, PathTrialStatus, PathTrialTransition,
};
use std::collections::VecDeque;
const HISTORY: usize = 32;
const HISTORY_TTL: Duration = Duration::from_secs(30);
pub(super) type Phases = HashMap<ObjectId, (ObjectId, PathTrialPhase, Option<ObjectId>)>;
pub(super) struct Observation {
    runtime_id: u64,
    epoch: u64,
    serial: u64,
    reset_diagnostics: PathTrialResetDiagnostics,
    history: VecDeque<(Instant, PathTrialTransition)>,
}
impl Observation {
    pub(super) fn new() -> Self {
        Self {
            runtime_id: rand::random(),
            epoch: rand::random(),
            serial: 0,
            reset_diagnostics: PathTrialResetDiagnostics::default(),
            history: VecDeque::new(),
        }
    }
    pub(super) fn reset(&mut self, reason: PathTrialResetReason) {
        let owner = self.runtime_id;
        let diagnostics = self.reset_diagnostics.clone();
        *self = Self::new();
        self.runtime_id = owner;
        self.reset_diagnostics = diagnostics;
        use PathTrialResetReason as R;
        let counter = match reason {
            R::Reattach => &mut self.reset_diagnostics.reattach,
            R::FullNetmap => &mut self.reset_diagnostics.full_netmap,
            R::NetmapDelta => &mut self.reset_diagnostics.netmap_delta,
            R::HandleLocalDisabled => &mut self.reset_diagnostics.handle_local_disabled,
            R::HandleServerUnsupported => &mut self.reset_diagnostics.handle_server_unsupported,
            R::HandleNonPrimary => &mut self.reset_diagnostics.handle_non_primary,
            R::TickLocalDisabled => &mut self.reset_diagnostics.tick_local_disabled,
            R::TickServerUnsupported => &mut self.reset_diagnostics.tick_server_unsupported,
            R::TickNonPrimary => &mut self.reset_diagnostics.tick_non_primary,
        };
        *counter = counter.saturating_add(1);
        self.reset_diagnostics.last_reason = Some(reason);
    }
    pub(super) fn record(&mut self, before: Phases, after: Phases, event: PathTrialEvent) {
        let mut ids: Vec<_> = before.keys().chain(after.keys()).copied().collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let from = before.get(&id);
            let to = after.get(&id);
            if from == to {
                continue;
            }
            let peer = to.or(from).unwrap().0;
            self.serial = self.serial.saturating_add(1);
            if self.history.len() == HISTORY {
                self.history.pop_front();
            }
            self.history.push_back((
                Instant::now(),
                PathTrialTransition {
                    sequence: self.serial,
                    trial_id: id.to_hex(),
                    peer_node_id: peer.to_hex(),
                    from: from.map(|p| p.1),
                    to: to.map(|p| p.1),
                    event: accepted_event(event, from.map(|p| p.1), to.map(|p| p.1)),
                    return_id: to
                        .and_then(|p| p.2)
                        .or_else(|| from.and_then(|p| p.2))
                        .map(|id| id.to_hex()),
                    age_ms: 0,
                },
            ));
        }
    }
}
// A rejected control can cause safe cleanup. Never label that as acceptance
// of the rejected message (e.g. invalid Commit -> trial removal).
fn accepted_event(
    event: PathTrialEvent,
    from: Option<PathTrialPhase>,
    to: Option<PathTrialPhase>,
) -> PathTrialEvent {
    use PathTrialEvent as E;
    use PathTrialPhase as P;
    let accepted = match event {
        E::Start => from.is_none() && to == Some(P::Binding),
        E::Commit => to == Some(P::Committed),
        E::Finalize => to == Some(P::Finalized),
        E::Abort => to.is_none(),
        E::ReturnPrepare => to == Some(P::ReturnPreparing),
        E::ReturnCommit => to == Some(P::Returned),
        E::ReturnFinalize => from == Some(P::Returned) && to.is_none(),
        E::ReturnAbort => to == Some(P::Finalized),
        E::Tick | E::Cleanup => true,
    };
    if accepted { event } else { E::Cleanup }
}
fn phase(p: Phase) -> PathTrialPhase {
    match p {
        Phase::Binding => PathTrialPhase::Binding,
        Phase::Measuring => PathTrialPhase::Measuring,
        Phase::Ready => PathTrialPhase::Ready,
        Phase::Committed => PathTrialPhase::Committed,
        Phase::Finalized => PathTrialPhase::Finalized,
        Phase::ReturnPreparing => PathTrialPhase::ReturnPreparing,
        Phase::ReturnReady => PathTrialPhase::ReturnReady,
        Phase::Returned => PathTrialPhase::Returned,
    }
}
pub(super) fn event(m: &ServerMsg) -> PathTrialEvent {
    match m {
        ServerMsg::OverlayPathTrialStart { .. } => PathTrialEvent::Start,
        ServerMsg::OverlayPathTrialCommit { .. } => PathTrialEvent::Commit,
        ServerMsg::OverlayPathTrialFinalize { .. } => PathTrialEvent::Finalize,
        ServerMsg::OverlayPathTrialAbort { .. } => PathTrialEvent::Abort,
        ServerMsg::OverlayPathTrialReturnPrepare { .. } => PathTrialEvent::ReturnPrepare,
        ServerMsg::OverlayPathTrialReturnCommit { .. } => PathTrialEvent::ReturnCommit,
        ServerMsg::OverlayPathTrialReturnFinalize { .. } => PathTrialEvent::ReturnFinalize,
        ServerMsg::OverlayPathTrialReturnAbort { .. } => PathTrialEvent::ReturnAbort,
        _ => PathTrialEvent::Tick,
    }
}
fn millis(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}
fn rtt_ns(v: Option<f64>) -> Option<u64> {
    v.filter(|n| n.is_finite() && *n >= 0.0)
        .map(|n| (n * 1_000_000.0).round().min(u64::MAX as f64) as u64)
}
fn median(samples: impl Iterator<Item = Option<f64>>) -> Option<u64> {
    let mut v: Vec<_> = samples
        .flatten()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .collect();
    v.sort_by(f64::total_cmp);
    (!v.is_empty()).then(|| v[v.len() / 2].round().min(u64::MAX as f64) as u64)
}
impl Engine {
    pub(in crate::overlay::runtime) fn observation_runtime_id(&self) -> u64 {
        self.observation.runtime_id
    }
    pub(in crate::overlay::runtime) fn reset_observation(&mut self, reason: PathTrialResetReason) {
        self.observation.reset(reason);
    }
    pub(super) fn observation_phases(&self) -> Phases {
        self.trials
            .iter()
            .map(|(id, t)| (*id, (t.peer_id, phase(t.phase), t.return_id)))
            .collect()
    }
    pub(in crate::overlay::runtime) fn observation(
        &self,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &HashMap<ObjectId, Installed>,
        live: bool,
    ) -> Option<PathTrialStatus> {
        if !live {
            return None;
        }
        let now = Instant::now();
        let mut active: Vec<_> = self
            .trials
            .iter()
            .filter(|(_, t)| Self::current(t, peers, installed))
            .map(|(id, t)| PathTrialInfo {
                trial_id: id.to_hex(),
                peer_node_id: t.peer_id.to_hex(),
                phase: phase(t.phase),
                return_id: t.return_id.map(|id| id.to_hex()),
                samples: t
                    .measurements
                    .windows
                    .iter()
                    .take(9)
                    .map(|w| PathTrialSample {
                        direct_rtt_ns: rtt_ns(w.0),
                        candidate_rtt_ns: rtt_ns(w.1),
                        age_ms: millis(now.saturating_duration_since(w.2)),
                    })
                    .collect(),
                age_ms: millis(now.saturating_duration_since(t.started)),
                windows: t.measurements.windows.len().min(9) as u8,
                direct_success: t
                    .measurements
                    .windows
                    .iter()
                    .filter(|w| w.0.is_some())
                    .count()
                    .min(9) as u8,
                candidate_success: t
                    .measurements
                    .windows
                    .iter()
                    .filter(|w| w.1.is_some())
                    .count()
                    .min(9) as u8,
                direct_median_ms: median(t.measurements.windows.iter().map(|w| w.0)),
                candidate_median_ms: median(t.measurements.windows.iter().map(|w| w.1)),
                newest_sample_age_ms: t
                    .measurements
                    .windows
                    .last()
                    .map(|w| millis(now.saturating_duration_since(w.2))),
            })
            .collect();
        active.sort_by(|a, b| a.trial_id.cmp(&b.trial_id));
        active.truncate(MAX_TRIALS);
        let transitions = self
            .observation
            .history
            .iter()
            .filter(|(at, _)| now.saturating_duration_since(*at) < HISTORY_TTL)
            .map(|(at, t)| {
                let mut t = t.clone();
                t.age_ms = millis(now.saturating_duration_since(*at));
                t
            })
            .collect();
        Some(PathTrialStatus {
            reset_diagnostics: Some(self.observation.reset_diagnostics.clone()),
            runtime_id: self.observation.runtime_id,
            epoch: self.observation.epoch,
            observed_at_ms: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| millis(d))
                .unwrap_or(0),
            history_ttl_ms: millis(HISTORY_TTL),
            active,
            transitions,
        })
    }
}
/// On cancellation/exit, stale watch data can never look like a live runtime.
pub(crate) struct ViewGuard {
    tx: Option<watch::Sender<crate::localapi::OverlayView>>,
    runtime_id: u64,
}
pub(crate) fn clear_view(
    tx: &Option<watch::Sender<crate::localapi::OverlayView>>,
    runtime_id: u64,
) {
    if let Some(tx) = tx {
        tx.send_if_modified(|v| {
            if v.path_trials
                .as_ref()
                .is_some_and(|s| s.runtime_id == runtime_id)
            {
                v.path_trials = None;
                true
            } else {
                false
            }
        });
    }
}
/// Update only this bounded field on the existing watch; no whole-peer rebuild
/// or additional wakeups in the default-off/foreign-runtime case.
pub(in crate::overlay::runtime) fn publish_view(
    tx: &Option<watch::Sender<crate::localapi::OverlayView>>,
    engine: &Engine,
    peers: &HashMap<ObjectId, NetmapPeer>,
    installed: &HashMap<ObjectId, Installed>,
    live: bool,
) {
    if !live {
        clear_view(tx, engine.observation_runtime_id());
        return;
    }
    if let Some(tx) = tx {
        let snapshot = engine.observation(peers, installed, true);
        tx.send_if_modified(|v| {
            if v.path_trials
                .as_ref()
                .is_some_and(|s| s.runtime_id != engine.observation_runtime_id())
            {
                return false;
            }
            v.path_trials = snapshot;
            true
        });
    }
}

impl ViewGuard {
    pub(crate) fn new(
        tx: Option<watch::Sender<crate::localapi::OverlayView>>,
        runtime_id: u64,
    ) -> Self {
        Self { tx, runtime_id }
    }
}
impl Drop for ViewGuard {
    fn drop(&mut self) {
        clear_view(&self.tx, self.runtime_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_trial_observation_ring_is_bounded_and_rejected_control_is_cleanup() {
        let mut o = Observation::new();
        let id = ObjectId::new();
        let peer = ObjectId::new();
        for _ in 0..20 {
            o.record(
                Phases::new(),
                Phases::from([(id, (peer, PathTrialPhase::Binding, None))]),
                PathTrialEvent::Start,
            );
            o.record(
                Phases::from([(id, (peer, PathTrialPhase::Binding, None))]),
                Phases::new(),
                PathTrialEvent::Commit,
            );
        }
        assert_eq!(o.history.len(), 32);
        assert_eq!(o.serial, 40);
        assert_eq!(o.history.back().unwrap().1.event, PathTrialEvent::Cleanup);
        let before = o.serial;
        o.record(Phases::new(), Phases::new(), PathTrialEvent::Finalize);
        assert_eq!(o.serial, before);
        let old = o.epoch;
        o.reset(PathTrialResetReason::FullNetmap);
        assert_ne!(o.epoch, old);
        assert!(o.history.is_empty());
    }
    #[test]
    fn path_trial_observation_guard_clears_stale_watch_on_drop() {
        let (tx, rx) = watch::channel(crate::localapi::OverlayView::default());
        tx.send_modify(|v| {
            v.path_trials = Some(PathTrialStatus {
                reset_diagnostics: None,
                runtime_id: 1,
                epoch: 1,
                observed_at_ms: 1,
                history_ttl_ms: 30000,
                active: vec![],
                transitions: vec![],
            })
        });
        drop(ViewGuard::new(Some(tx), 1));
        assert!(rx.borrow().path_trials.is_none());
    }
    #[test]
    fn path_trial_observation_old_guard_cannot_clear_new_runtime() {
        let (tx, rx) = watch::channel(crate::localapi::OverlayView::default());
        let guard = ViewGuard::new(Some(tx.clone()), 1);
        tx.send_modify(|v| {
            v.path_trials = Some(PathTrialStatus {
                reset_diagnostics: None,
                runtime_id: 2,
                epoch: 3,
                observed_at_ms: 4,
                history_ttl_ms: 30000,
                active: vec![],
                transitions: vec![],
            })
        });
        drop(guard);
        assert_eq!(rx.borrow().path_trials.as_ref().unwrap().runtime_id, 2);
        let mut observation = Observation::new();
        let id = observation.runtime_id;
        observation.reset(PathTrialResetReason::FullNetmap);
        assert_eq!(observation.runtime_id, id);
    }
    #[test]
    fn path_trial_observation_publish_is_bounded_own_field_only_and_default_off_quiet() {
        let (tx, mut rx) = watch::channel(crate::localapi::OverlayView::default());
        let engine = Engine::new();
        let peers = HashMap::new();
        let installed = HashMap::new();
        rx.borrow_and_update();
        publish_view(&Some(tx.clone()), &engine, &peers, &installed, false);
        assert!(!rx.has_changed().unwrap());
        publish_view(&Some(tx.clone()), &engine, &peers, &installed, true);
        assert_eq!(
            rx.borrow().path_trials.as_ref().unwrap().runtime_id,
            engine.observation_runtime_id()
        );
        tx.send_modify(|v| {
            v.self_ip = Some("unrelated-view-field".into());
            v.path_trials.as_mut().unwrap().runtime_id =
                engine.observation_runtime_id().wrapping_add(1);
        });
        rx.borrow_and_update();
        publish_view(&Some(tx.clone()), &engine, &peers, &installed, true);
        assert!(!rx.has_changed().unwrap());
        publish_view(&Some(tx.clone()), &engine, &peers, &installed, false);
        assert!(!rx.has_changed().unwrap());
        assert_eq!(rx.borrow().self_ip.as_deref(), Some("unrelated-view-field"));
    }
}

#[cfg(test)]
mod reset_cause_tests {
    use super::*;
    #[test]
    fn path_trial_reset_causes_accumulate_across_epochs_and_new_engine_is_zero() {
        use PathTrialResetReason as R;
        let mut engine = Engine::new();
        let owner = engine.observation_runtime_id();
        for reason in [
            R::Reattach,
            R::FullNetmap,
            R::NetmapDelta,
            R::HandleLocalDisabled,
            R::HandleServerUnsupported,
            R::HandleNonPrimary,
            R::TickLocalDisabled,
            R::TickServerUnsupported,
            R::TickNonPrimary,
        ] {
            engine.reset_observation(reason);
            assert_eq!(engine.observation_runtime_id(), owner);
            assert!(engine.observation.history.is_empty());
            assert_eq!(engine.observation.serial, 0);
        }
        let d = engine
            .observation(&HashMap::new(), &HashMap::new(), true)
            .unwrap()
            .reset_diagnostics
            .unwrap();
        assert_eq!(
            d,
            PathTrialResetDiagnostics {
                reattach: 1,
                full_netmap: 1,
                netmap_delta: 1,
                handle_local_disabled: 1,
                handle_server_unsupported: 1,
                handle_non_primary: 1,
                tick_local_disabled: 1,
                tick_server_unsupported: 1,
                tick_non_primary: 1,
                last_reason: Some(R::TickNonPrimary),
            }
        );
        assert!(
            engine
                .observation(&HashMap::new(), &HashMap::new(), false)
                .is_none()
        );
        let fresh = Engine::new();
        assert_eq!(
            fresh.observation.reset_diagnostics,
            PathTrialResetDiagnostics::default()
        );
    }
    #[test]
    fn path_trial_reset_cause_counters_saturate_and_projection_is_read_only() {
        let mut engine = Engine::new();
        engine.observation.reset_diagnostics.netmap_delta = u64::MAX;
        engine.reset_observation(PathTrialResetReason::NetmapDelta);
        assert_eq!(engine.observation.reset_diagnostics.netmap_delta, u64::MAX);
        let before = engine
            .observation(&HashMap::new(), &HashMap::new(), true)
            .unwrap();
        let after = engine
            .observation(&HashMap::new(), &HashMap::new(), true)
            .unwrap();
        assert_eq!(before.reset_diagnostics, after.reset_diagnostics);
        assert_eq!(before.epoch, after.epoch);
        assert_eq!(
            before.reset_diagnostics.unwrap().last_reason,
            Some(PathTrialResetReason::NetmapDelta)
        );
    }
}
