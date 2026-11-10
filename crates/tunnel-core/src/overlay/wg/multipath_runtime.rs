// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! B8's ownership transaction and existing-runtime control-loop integration.

use super::*;

pub(crate) enum MultipathFailure {
    Unavailable,
    Pending,
    Promoted(super::super::relay_link::RelayKind),
}

impl WgDevice {
    pub(crate) fn multipath_enabled(&self) -> bool {
        self.multipath_mode != super::super::multipath::MultipathMode::Off
    }

    pub(crate) fn retains_multipath_carrier(&self, key: &[u8; 32]) -> bool {
        self.peers.get(key).is_some_and(|p| p.retained.is_some())
    }

    /// Default Off delegates to the original synchronous promotion unchanged.
    /// Enabled mode retires the old receiver BEFORE attaching that transport
    /// to the promoted peer's one Tunn. No relay receiver is read twice.
    pub(crate) async fn promote_direct_probe_multipath(
        &mut self,
        key: &[u8; 32],
        kind: Option<super::super::relay_link::RelayKind>,
    ) -> bool {
        // A direct probe can latch while the peer's ORG link is still an
        // unproven upgrade candidate: a restarted peer re-binds its org
        // session and proves direct within milliseconds. The plain path
        // cancels that candidate and leaves the pair with no standby leg
        // for as long as direct stays healthy. Keep its carrier instead;
        // B8's own leg proof still gates every use of it.
        if self.multipath_enabled()
            && self.probes.contains_key(key)
            && !self.path_trials.values().any(|t| &t.public_key == key)
            && self
                .org_upgrades
                .get(key)
                .is_some_and(|u| !u.candidate.carrier.is_dead())
            && self.peers.get(key).is_some_and(|p| !p.carrier.is_direct())
        {
            let mut upgrade = self.org_upgrades.remove(key).expect("checked candidate");
            if let Some(pq) = upgrade.candidate.stats.pq.get() {
                pq.clear_candidate(&upgrade.candidate.stats);
            }
            self.unregister_plane_route(&upgrade.candidate);
            let carrier = upgrade.candidate.carrier.clone();
            // The candidate's receiver must be gone before the leg spawns
            // its own: no relay receiver is read twice.
            for task in &upgrade.candidate.tasks {
                task.abort();
            }
            for task in upgrade.candidate.tasks.drain(..) {
                let _ = task.await;
            }
            drop(upgrade);
            self.sync_peer_on_demand_hold(key);
            if !self.promote_direct_probe(key) {
                return false;
            }
            let peer = self.peers.get_mut(key).expect("promoted peer");
            peer.retained = Some(RetainedMultipathCarrier {
                carrier,
                kind: super::super::relay_link::RelayKind::Org,
                attached: false,
                was_ready: false,
                failure_at: None,
                exhausted_in: None,
            });
            info!(event="multipath_standby_adopted", peer_key=%hex::encode(key), source="org_candidate",
                "overlay: unproven org-relay candidate kept as the B8 standby leg of the promoted direct peer");
            return true;
        }
        if !self.multipath_enabled()
            || kind.is_none()
            || self.path_trials.values().any(|t| &t.public_key == key)
            || self.org_upgrades.contains_key(key)
            || self.peers.get(key).is_none_or(|p| p.carrier.is_direct())
        {
            return self.promote_direct_probe(key);
        }
        if !self.probes.contains_key(key) {
            return false;
        }
        let mut old = self.peers.remove(key).expect("checked incumbent");
        let carrier = old.carrier.clone();
        if !self.promote_direct_probe(key) {
            self.peers.insert(*key, old);
            return false;
        }
        for task in &old.tasks {
            task.abort();
        }
        for task in old.tasks.drain(..) {
            let _ = task.await;
        }
        self.unregister_direct(&old).await;
        drop(old);
        let peer = self.peers.get_mut(key).expect("promoted peer");
        peer.retained = Some(RetainedMultipathCarrier {
            carrier,
            kind: kind.expect("checked kind"),
            attached: false,
            was_ready: false,
            failure_at: None,
            exhausted_in: None,
        });
        true
    }

    /// A healthy direct peer that lost its relay incumbent before direct
    /// latched has no standby leg. A later ORG session for it may supply one.
    /// A DERP standby is replaced too: an end that promoted direct while its
    /// incumbent was still the DERP floor kept DERP, while the other end of
    /// the same pair kept the ORG link it already had. Mismatched standby
    /// transports can never prove a shared-session leg (B8 lifecycle R4:
    /// both restart cases), and the server pushes one ORG session to both
    /// ends, so preferring ORG makes both ends converge.
    pub(crate) fn wants_multipath_standby(&self, key: &[u8; 32]) -> bool {
        self.multipath_enabled()
            && !self.probes.contains_key(key)
            && !self.org_upgrades.contains_key(key)
            && !self.path_trials.values().any(|t| &t.public_key == key)
            && self.peers.get(key).is_some_and(|p| {
                p.carrier.is_direct()
                    && !p.carrier.is_dead()
                    && p.retained
                        .as_ref()
                        .is_none_or(|r| r.kind == super::super::relay_link::RelayKind::Derp)
                    && p.stats.mp_control.get().is_some_and(|c| !c.retired())
            })
    }

    /// Keep `carrier` as `key`'s unattached standby leg. It carries nothing
    /// until B8 proves the current shared session over it.
    pub(crate) fn adopt_multipath_standby(
        &mut self,
        key: &[u8; 32],
        carrier: Arc<Carrier>,
        kind: super::super::relay_link::RelayKind,
    ) -> bool {
        if !self.wants_multipath_standby(key) || carrier.is_dead() {
            return false;
        }
        let replaced_derp = self.retains_multipath_carrier(key);
        if replaced_derp {
            // Its leg (and receive task) goes before the new carrier's leg can attach.
            self.drop_retained_multipath(key);
        }
        self.peers.get_mut(key).expect("checked peer").retained = Some(RetainedMultipathCarrier {
            carrier,
            kind,
            attached: false,
            was_ready: false,
            failure_at: None,
            exhausted_in: None,
        });
        info!(event="multipath_standby_adopted", peer_key=%hex::encode(key), source="late_relay", ?kind, replaced_derp,
            "overlay: relay carrier adopted as the B8 standby leg of a direct peer");
        true
    }

    fn drop_retained_multipath(&mut self, key: &[u8; 32]) {
        let Some(peer) = self.peers.get_mut(key) else {
            return;
        };
        peer.multipath.remove_secondary_leg(1);
        *peer
            .stats
            .mp_secondary
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = std::sync::Weak::new();
        peer.retained = None;
    }

    /// Called by the existing scout tick; no new timer or retry scheduler.
    /// Returns allocations the runtime coordinator should forget.
    pub(crate) async fn poll_multipath(
        &mut self,
        org_allowed: &std::collections::HashSet<[u8; 32]>,
    ) -> Vec<([u8; 32], Option<super::super::relay_link::RelayKind>)> {
        if !self.multipath_enabled() {
            return Vec::new();
        }
        let keys: Vec<_> = self.peers.keys().copied().collect();
        let mut released = Vec::new();
        for key in keys {
            let Some(peer) = self.peers.get(&key) else {
                continue;
            };
            let Some(control) = peer.stats.mp_control.get().cloned() else {
                continue;
            };
            if peer.stats.on_demand.is_dormant_or_waking()
                || peer.stats.pq_guard_active.load(Ordering::Acquire)
                || self.path_trials.values().any(|t| t.public_key == key)
                || self.org_upgrades.contains_key(&key)
            {
                continue;
            }
            let now = Instant::now();
            if control.holding() {
                let before = control.hold_snapshot();
                control.expire_hold(now);
                let after = control.hold_snapshot();
                if after.expired > before.expired {
                    warn!(event="multipath_hold_expired", peer_key=%hex::encode(key), expired=after.expired,
                        packets=after.packets, bytes=after.bytes, global_bytes=after.global_bytes,
                        "overlay: expired bounded multipath recovery queue");
                }
            }
            let generation = control.binding().map_or(0, |b| b.session_generation);
            let exhausted = control.exhausted(now) && !control.recovery_allowed();
            let mut first_exhaustion = false;
            let remove = peer.retained.as_ref().is_some_and(|r| {
                r.carrier.is_dead()
                    || r.kind == super::super::relay_link::RelayKind::Org
                        && !org_allowed.contains(&key)
                    || control.retired()
                    || exhausted
                        && match r.exhausted_in {
                            // Ran out in an earlier session and again in a newer one.
                            Some(first) => generation > first,
                            None => {
                                first_exhaustion = true;
                                false
                            }
                        }
            });
            if remove {
                self.drop_retained_multipath(&key);
                released.push((key, None));
            } else if first_exhaustion
                && let Some(r) = self.peers.get_mut(&key).and_then(|p| p.retained.as_mut())
            {
                r.exhausted_in = Some(generation);
                info!(event="multipath_standby_kept_after_exhaustion", peer_key=%hex::encode(key), kind=?r.kind, session_generation=generation,
                    "overlay: B8 negotiation ran out in this session; standby kept until a newer session also runs out");
            }
            let Some(peer) = self.peers.get(&key) else {
                continue;
            };
            let (tunn, primary, stats, mp) = (
                peer.tunn.clone(),
                peer.carrier.clone(),
                peer.stats.clone(),
                peer.multipath.clone(),
            );
            if primary.is_direct()
                && !primary.is_dead()
                && let Some(offer) = control.offer(now)
                && let Some(binding) = control.binding()
                && self.sender().same_owner(&key, &tunn, &primary, false)
                && control.binding() == Some(binding)
            {
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), primary.send_disco(&offer))
                        .await;
            }
            let attach = self
                .peers
                .get(&key)
                .and_then(|p| p.retained.as_ref())
                .filter(|r| !r.attached && control.peer_on(Instant::now()))
                .map(|r| r.carrier.clone());
            if let Some(carrier) = attach {
                *stats.mp_secondary.lock().unwrap_or_else(|e| e.into_inner()) =
                    Arc::downgrade(&carrier);
                mp.set_config(super::super::multipath::MultipathConfig::new(
                    control.mode(),
                ));
                if self.add_multipath_leg_with_health(&key, 1, carrier, 10, 1, false) {
                    self.peers
                        .get_mut(&key)
                        .expect("owned peer")
                        .retained
                        .as_mut()
                        .expect("retained")
                        .attached = true;
                } else {
                    self.drop_retained_multipath(&key);
                    released.push((key, None));
                }
            }
            if let Some(carrier) = self
                .peers
                .get(&key)
                .and_then(|p| p.retained.as_ref())
                .filter(|r| r.attached && control.should_validate_secondary(Instant::now()))
                .map(|r| r.carrier.clone())
            {
                let binding = control.binding();
                let wire = {
                    let mut t = tunn.lock().await;
                    if !t.has_current_session() || control.binding() != binding {
                        None
                    } else {
                        let mut buf = vec![0; WG_BUF];
                        match t.encapsulate(&[], &mut buf) {
                            TunnResult::WriteToNetwork(out)
                                if out.len() == 32 && out[..4] == [4, 0, 0, 0] =>
                            {
                                Some(out.to_vec())
                            }
                            _ => None,
                        }
                    }
                };
                if let Some(wire) = wire
                    && self.sender().owns_multipath_carrier(&key, &tunn, &carrier)
                    && control.binding() == binding
                    && !stats.on_demand.is_dormant_or_waking()
                    && tokio::time::timeout(
                        Duration::from_millis(100),
                        send_wg_recorded(&carrier, &stats, &wire),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok())
                    && control.binding() == binding
                    && self.sender().owns_multipath_carrier(&key, &tunn, &carrier)
                    && let Some(challenge) = control.challenge(&wire, Instant::now())
                {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(100),
                        carrier.send_disco(&challenge),
                    )
                    .await;
                }
            }
            let ready = control.ready(Instant::now());
            mp.set_leg_healthy(1, ready);
            if let Some(retained) = self.peers.get_mut(&key).and_then(|p| p.retained.as_mut()) {
                if ready && !retained.was_ready {
                    info!(event="multipath_validated", peer_key=%hex::encode(key), mode=?control.mode(),
                        session_generation=control.binding().map(|b| b.session_generation),
                        "overlay: current shared-session secondary validated");
                }
                // Readiness on the previous poll: every new session's proof
                // (rekey, peer restart) is reported, not only the first.
                retained.was_ready = ready;
            }
            // A healthy restarted primary may answer the fallback INIT within
            // this same PokeArm. Release only on current-session roundtrip.
            if control.holding()
                && (control.current_primary_roundtrip(Instant::now())
                    || control
                        .primary_answer_age(Instant::now())
                        .is_some_and(|age| age < Duration::from_secs(2)))
            {
                self.drain_multipath_hold(&key).await;
            }
            if self
                .peers
                .get(&key)
                .and_then(|p| p.retained.as_ref())
                .is_some_and(|r| r.failure_at.is_some())
                && let MultipathFailure::Promoted(kind) = self
                    .multipath_primary_failed(&key, org_allowed.contains(&key))
                    .await
            {
                released.push((key, Some(kind)));
            }
        }
        released
    }

    /// Health inputs are strictly primary-leg observations. Total traffic is
    /// still exposed by peer_traffic for the API and accounting.
    pub(crate) fn peer_primary_traffic(&self, key: &[u8; 32]) -> Option<(u64, u64)> {
        let p = self.peers.get(key)?;
        Some((
            p.stats.tx.load(Ordering::Relaxed),
            if p.stats.mp_control.get().is_some() {
                p.stats.mp_primary_rx.load(Ordering::Relaxed)
            } else {
                p.stats.rx.load(Ordering::Relaxed)
            },
        ))
    }

    /// First attempt is a session-preserving Type-4 proof. This is called
    /// exactly where the existing runtime arms PokeArm; it owns no deadline.
    pub(crate) fn request_carrier_revalidation(&self, key: &[u8; 32]) -> bool {
        let Some(p) = self.peers.get(key) else {
            return false;
        };
        let Some(control) = p
            .stats
            .mp_control
            .get()
            .cloned()
            .filter(|c| c.peer_on(Instant::now()))
        else {
            return self.poke_handshake(key);
        };
        if !p.carrier.is_direct() {
            return self.poke_handshake(key);
        }
        if p.stats.on_demand.is_dormant_or_waking()
            || p.stats.pq_guard_active.load(Ordering::Acquire)
        {
            return false;
        }
        control.clear_primary_probe();
        let (key, tunn, carrier, stats, sender) = (
            *key,
            p.tunn.clone(),
            p.carrier.clone(),
            p.stats.clone(),
            self.sender(),
        );
        tokio::spawn(async move {
            let binding = control.binding();
            let wire = {
                let mut t = tunn.lock().await;
                let mut buf = vec![0; WG_BUF];
                if !t.has_current_session() || control.binding() != binding {
                    None
                } else {
                    match t.encapsulate(&[], &mut buf) {
                        TunnResult::WriteToNetwork(out)
                            if out.len() == 32 && out[..4] == [4, 0, 0, 0] =>
                        {
                            Some(out.to_vec())
                        }
                        _ => None,
                    }
                }
            };
            if !sender.same_owner(&key, &tunn, &carrier, false)
                || control.retired()
                || stats.on_demand.is_dormant_or_waking()
                || stats.pq_guard_active.load(Ordering::Acquire)
            {
                return;
            }
            if let Some(wire) = wire
                && control.binding() == binding
                && let Some(challenge) = control.primary_challenge(&wire, Instant::now())
            {
                let _ = tokio::time::timeout(Duration::from_millis(100), async {
                    send_wg_recorded(&carrier, &stats, &wire).await?;
                    carrier.send_disco(&challenge).await
                })
                .await;
            } else {
                // Session disappeared before the no-rekey transaction could
                // arm. Use the original handshake without changing PokeArm.
                let out = {
                    let mut t = tunn.lock().await;
                    let mut buf = vec![0; WG_BUF];
                    match t.format_handshake_initiation(&mut buf, true) {
                        TunnResult::WriteToNetwork(out) => Some(out.to_vec()),
                        _ => None,
                    }
                };
                if let Some(out) = out
                    && sender.same_owner(&key, &tunn, &carrier, false)
                    && !control.retired()
                {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(100),
                        send_wg_recorded(&carrier, &stats, &out),
                    )
                    .await;
                }
            }
        });
        true
    }

    /// The existing business sampler already retries legacy INITs. B8's
    /// first-cycle fallback is consumed by peer_initiator_hs_answered, once.
    pub(crate) fn retap_carrier_revalidation(&self, key: &[u8; 32]) -> bool {
        if self.peers.get(key).is_some_and(|p| {
            p.stats
                .mp_control
                .get()
                .is_some_and(|c| c.peer_on(Instant::now()))
        }) {
            false
        } else {
            self.poke_handshake(key)
        }
    }

    /// Only called after carrier_tick has convicted the primary, or while
    /// completing that exact latched verdict. No independent quality policy.
    pub(crate) async fn multipath_primary_failed(
        &mut self,
        key: &[u8; 32],
        org_allowed: bool,
    ) -> MultipathFailure {
        let Some(p) = self.peers.get(key) else {
            return MultipathFailure::Unavailable;
        };
        let Some(control) = p.stats.mp_control.get().cloned() else {
            return MultipathFailure::Unavailable;
        };
        let Some(r) = p.retained.as_ref() else {
            return MultipathFailure::Unavailable;
        };
        if r.kind == super::super::relay_link::RelayKind::Org && !org_allowed {
            self.drop_retained_multipath(key);
            return MultipathFailure::Unavailable;
        }
        if !r.attached
            || r.carrier.is_dead()
            || p.stats.on_demand.is_dormant_or_waking()
            || p.stats.pq_guard_active.load(Ordering::Acquire)
            || !control.recovery_allowed()
        {
            return MultipathFailure::Unavailable;
        }
        let now = Instant::now();
        if control.ready(now) || control.recovery_ready(now) {
            return self
                .commit_multipath_primary(key)
                .await
                .map_or(MultipathFailure::Unavailable, MultipathFailure::Promoted);
        }
        if let Some(at) = r.failure_at {
            if now.saturating_duration_since(at) < Duration::from_secs(2) {
                return MultipathFailure::Pending;
            }
            self.drop_retained_multipath(key);
            return MultipathFailure::Unavailable;
        }
        let (tunn, carrier, stats) = (p.tunn.clone(), r.carrier.clone(), p.stats.clone());
        control.begin_hold(now);
        self.peers
            .get_mut(key)
            .unwrap()
            .retained
            .as_mut()
            .unwrap()
            .failure_at = Some(now);
        let out = {
            let mut t = tunn.lock().await;
            let mut buf = vec![0; WG_BUF];
            match t.format_handshake_initiation(&mut buf, true) {
                TunnResult::WriteToNetwork(out) => Some(out.to_vec()),
                _ => None,
            }
        };
        if let Some(out) = out
            && self.sender().owns_multipath_carrier(key, &tunn, &carrier)
            && !control.retired()
        {
            let _ = tokio::time::timeout(
                Duration::from_millis(100),
                send_wg_recorded(&carrier, &stats, &out),
            )
            .await;
        }
        MultipathFailure::Pending
    }

    async fn commit_multipath_primary(
        &mut self,
        key: &[u8; 32],
    ) -> Option<super::super::relay_link::RelayKind> {
        // Receiver on candidate continues throughout. Retire and await ONLY
        // the old primary timer, then move the candidate's existing receiver.
        let p = self.peers.get_mut(key)?;
        let control = p.stats.mp_control.get()?.clone();
        for task in &p.tasks {
            task.abort();
        }
        let tasks = std::mem::take(&mut p.tasks);
        for task in tasks {
            let _ = task.await;
        }
        let tunn = self.peers.get(key)?.tunn.clone();
        let _tunn_guard = tunn.lock().await;
        let p = self.peers.get(key)?;
        let retained = p.retained.as_ref()?;
        if retained.carrier.is_dead()
            || control.retired()
            || !(control.ready(Instant::now()) || control.recovery_ready(Instant::now()))
        {
            // Keep one timer if proof expired during receiver retirement.
            let p = self.peers.get_mut(key)?;
            p.tasks.push(Self::spawn_carrier_timer(
                p.tunn.clone(),
                p.carrier.clone(),
                p.stats.clone(),
                p.multipath.clone(),
            ));
            return None;
        }
        let kind = retained.kind;
        let mut leg = p.multipath.take_secondary_leg(1)?;
        self.unregister_direct(p).await;
        {
            let mut mirror = self.send.0.write().unwrap();
            let p = self
                .peers
                .get_mut(key)
                .expect("exclusive runtime peer owner");
            p.carrier = leg.carrier.clone();
            p.tasks = leg.take_tasks();
            p.direct_src = None;
            p.plane_idx = None;
            p.direct_index = None;
            *p.stats.mp_primary.lock().unwrap_or_else(|e| e.into_inner()) =
                Arc::downgrade(&p.carrier);
            *p.stats
                .mp_secondary
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = std::sync::Weak::new();
            p.stats.mp_primary_leg.store(1, Ordering::Release);
            p.stats.mp_primary_rx.store(0, Ordering::Relaxed);
            p.stats.mp_primary_rx_any.store(0, Ordering::Relaxed);
            p.stats.mp_primary_hs_response.store(0, Ordering::Relaxed);
            p.stats.derp_role.store(
                kind == super::super::relay_link::RelayKind::Derp,
                Ordering::Relaxed,
            );
            p.stats.org_role.store(
                kind == super::super::relay_link::RelayKind::Org,
                Ordering::Relaxed,
            );
            p.multipath.clear_crypto_observations();
            control.role_changed();
            if let Some(pq) = p.stats.pq.get() {
                pq.set_carrier(&p.carrier);
            }
            p.retained = None;
            p.tasks.push(Self::spawn_carrier_timer(
                p.tunn.clone(),
                p.carrier.clone(),
                p.stats.clone(),
                p.multipath.clone(),
            ));
            Self::send_install_locked(
                &mut mirror,
                *key,
                p.overlay_ip,
                p.tunn.clone(),
                p.carrier.clone(),
                p.stats.clone(),
                p.multipath.clone(),
            );
        }
        drop(_tunn_guard);
        self.drain_multipath_hold(key).await;
        info!(event="multipath_primary_promoted", peer_key=%hex::encode(key), ?kind, "overlay: authenticated secondary committed at existing primary failure verdict");
        Some(kind)
    }

    async fn drain_multipath_hold(&self, key: &[u8; 32]) {
        let Some(peer) = self.send.0.read().unwrap().peers.get(key).cloned() else {
            return;
        };
        let Some(control) = peer.stats.mp_control.get() else {
            return;
        };
        let Some(binding) = control.binding() else {
            return;
        };
        if peer.stats.pq_guard_active.load(Ordering::Acquire)
            || peer.stats.on_demand.is_dormant_or_waking()
        {
            return;
        }
        // Keep global/per-peer reservations while the packet is in flight.
        for _ in 0..64 {
            let Some(packet) = control.pop_held_at(Instant::now()) else {
                control.finish_hold();
                break;
            };
            if !self
                .sender()
                .same_owner(key, &peer.tunn, &peer.carrier, false)
                || control.retired()
            {
                break;
            }
            if !peer
                .send_inner(packet.bytes(), SendAuthorization::Held(binding))
                .await
            {
                control.requeue_held(packet);
                break;
            }
            drop(packet);
        }
        control.finish_hold();
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::multipath::MultipathMode;
    use super::super::super::relay_link::RelayKind;
    use super::*;
    use crate::overlay::WgKeypair;
    use crate::transport::relay::UdpRelayConn;

    const A: Ipv4Addr = Ipv4Addr::new(100, 100, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(100, 100, 0, 2);

    fn packet(value: u8) -> Vec<u8> {
        let mut p = vec![0; 21];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&21u16.to_be_bytes());
        p[8] = 64;
        p[9] = 253;
        p[12..16].copy_from_slice(&A.octets());
        p[16..20].copy_from_slice(&B.octets());
        p[20] = value;
        p
    }

    async fn connected(dev: &WgDevice, key: &[u8; 32]) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dev.is_connected(key).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real WG session");
    }

    async fn pair(
        am: MultipathMode,
        bm: MultipathMode,
    ) -> (WgDevice, WgDevice, mpsc::Receiver<Vec<u8>>, StaticSecret) {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        let (mut da, _) = WgDevice::new(a.secret);
        let (mut db, rx) = WgDevice::new(b.secret.clone());
        da.multipath_mode = am;
        db.multipath_mode = bm;
        da.set_on_demand_config(super::super::super::on_demand::OnDemandConfig::disabled());
        db.set_on_demand_config(super::super::super::on_demand::OnDemandConfig::disabled());
        db.add_peer(da.public.to_bytes(), A, Carrier::direct(sb, aa), false);
        da.add_peer(db.public.to_bytes(), B, Carrier::direct(sa, ab), true);
        connected(&da, &db.public.to_bytes()).await;
        (da, db, rx, b.secret)
    }

    async fn retain_pair(da: &mut WgDevice, db: &mut WgDevice) {
        let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        da.peers.get_mut(&db.public.to_bytes()).unwrap().retained =
            Some(RetainedMultipathCarrier {
                carrier: Carrier::relay(Arc::new(UdpRelayConn(sa)), ab),
                kind: RelayKind::Turn,
                attached: false,
                was_ready: false,
                failure_at: None,
                exhausted_in: None,
            });
        db.peers.get_mut(&da.public.to_bytes()).unwrap().retained =
            Some(RetainedMultipathCarrier {
                carrier: Carrier::relay(Arc::new(UdpRelayConn(sb)), aa),
                kind: RelayKind::Turn,
                attached: false,
                was_ready: false,
                failure_at: None,
                exhausted_in: None,
            });
    }

    async fn negotiated(da: &mut WgDevice, db: &mut WgDevice, secondary: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                let ca = da.peers[&db.public.to_bytes()]
                    .stats
                    .mp_control
                    .get()
                    .unwrap();
                let cb = db.peers[&da.public.to_bytes()]
                    .stats
                    .mp_control
                    .get()
                    .unwrap();
                let now = Instant::now();
                if if secondary {
                    ca.ready(now) && cb.ready(now)
                } else {
                    ca.peer_on(now) && cb.peer_on(now)
                } {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real authenticated runtime negotiation");
    }

    #[tokio::test]
    async fn runtime_off_peer_never_attaches_secondary_in_either_business_mode() {
        for mode in [MultipathMode::Redundant, MultipathMode::Aggregate] {
            let (mut da, mut db, mut rx, _) = pair(mode, MultipathMode::Off).await;
            retain_pair(&mut da, &mut db).await;
            let kb = db.public.to_bytes();
            let ka = da.public.to_bytes();
            for _ in 0..3 {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(db.peers[&ka].stats.mp_control.get().is_none());
            assert!(!da.peers[&kb].retained.as_ref().unwrap().attached);
            assert!(
                !da.peers[&kb]
                    .stats
                    .mp_control
                    .get()
                    .unwrap()
                    .peer_on(Instant::now())
            );
            let wire = packet(1);
            assert!(da.send_to_peer(&kb, &wire).await);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                wire
            );
            assert_eq!(da.peer_multipath_snapshot(&kb).unwrap().legs.len(), 1);
            assert!(matches!(
                da.multipath_primary_failed(&kb, true).await,
                MultipathFailure::Unavailable
            ));
        }
    }

    #[tokio::test]
    async fn runtime_retap_unconfirmed_or_off_peer_sends_real_legacy_init() {
        for remote in [MultipathMode::Off, MultipathMode::Redundant] {
            let (da, _db, _rx, _) = pair(MultipathMode::Redundant, remote).await;
            let key = *da.peers.keys().next().unwrap();
            let stats = da.peers[&key].stats.clone();
            assert!(!stats.mp_control.get().unwrap().peer_on(Instant::now()));
            stats.hs_response_at.store(0, Ordering::Release);
            assert!(da.retap_carrier_revalidation(&key));
            tokio::time::timeout(Duration::from_secs(2), async {
                while stats.hs_response_at.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("production retap INIT must receive a real authenticated WG response");
        }
        let (mut da, mut db, _, _) = pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        negotiated(&mut da, &mut db, false).await;
        assert!(!da.retap_carrier_revalidation(&db.public.to_bytes()));
    }

    /// An ordinary UDP transport with bounded control-frame delay/drop. It
    /// never changes a packet, sender address, or authenticated protocol state.
    struct PqGate {
        socket: UdpSocket,
        drop_init: AtomicBool,
        block_confirm: AtomicBool,
        confirm: std::sync::Mutex<Option<(Vec<u8>, SocketAddr)>>,
        business: AtomicU64,
    }

    impl PqGate {
        async fn new() -> Arc<Self> {
            Arc::new(Self {
                socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                drop_init: AtomicBool::new(true),
                block_confirm: AtomicBool::new(false),
                confirm: std::sync::Mutex::new(None),
                business: AtomicU64::new(0),
            })
        }

        async fn release_confirm(&self) {
            self.block_confirm.store(false, Ordering::Release);
            let (bytes, dst) = self.confirm.lock().unwrap().take().unwrap();
            self.socket.send_to(&bytes, dst).await.unwrap();
        }
    }

    #[async_trait::async_trait]
    impl crate::transport::relay::RelayConn for PqGate {
        async fn send_to(&self, bytes: &[u8], dst: SocketAddr) -> io::Result<usize> {
            if bytes.starts_with(super::super::super::pq_psk::MAGIC) {
                // Existing wire kinds: INIT=1, CONFIRM=4, FRAG=6.
                if self.drop_init.load(Ordering::Acquire)
                    && (bytes[8] == 1 || bytes[8] == 6 && bytes[9] == 1)
                {
                    return Ok(bytes.len());
                }
                if bytes[8] == 4 && self.block_confirm.load(Ordering::Acquire) {
                    *self.confirm.lock().unwrap() = Some((bytes.to_vec(), dst));
                    return Ok(bytes.len());
                }
            }
            if bytes.len() > 32 && bytes[..4] == [4, 0, 0, 0] {
                self.business.fetch_add(1, Ordering::Relaxed);
            }
            self.socket.send_to(bytes, dst).await
        }
        async fn recv_from(&self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.socket.recv_from(bytes).await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }
    }

    #[tokio::test]
    async fn runtime_secondary_pq_confirm_drops_nonempty_b7_batch_during_b8_hold() {
        use super::super::super::on_demand::OnDemandConfig;
        use super::super::super::pq_psk::{PqPeerStatus, PqPskConfig, PqPskMode};

        let (a, b) = loop {
            let a = WgKeypair::generate();
            let b = WgKeypair::generate();
            // B wins existing simultaneous-PQ-initiation glare; A receives
            // the actual CONFIRM and owns the nonempty B7 pending queue.
            if a.public.as_bytes() > b.public.as_bytes() {
                break (a, b);
            }
        };
        let sa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        let (mut da, _) = WgDevice::new(a.secret);
        let (mut db, mut rx) = WgDevice::new(b.secret);
        let ka = da.public.to_bytes();
        let kb = db.public.to_bytes();
        for dev in [&mut da, &mut db] {
            dev.multipath_mode = MultipathMode::Redundant;
            dev.set_pq_psk_config(PqPskConfig {
                mode: PqPskMode::Optional,
                ..PqPskConfig::default()
            });
            dev.set_on_demand_config(OnDemandConfig::enabled(Duration::from_secs(60)));
        }
        // Defer automatic initial work until the controlled transports own
        // the PQ exchanges. Classical Optional WG still uses real direct UDP.
        db.add_peer(ka, A, Carrier::direct(sb, aa), false);
        da.add_peer(kb, B, Carrier::direct(sa, ab), true);
        let ga = PqGate::new().await;
        let gb = PqGate::new().await;
        let ca = Carrier::relay(ga.clone(), gb.local_addr().unwrap());
        let cb = Carrier::relay(gb.clone(), ga.local_addr().unwrap());
        let pqa = da.peers[&kb].stats.pq.get().unwrap().clone();
        let pqb = db.peers[&ka].stats.pq.get().unwrap().clone();
        pqa.set_carrier(&ca);
        pqb.set_carrier(&cb);
        for (dev, key, carrier) in [(&mut da, kb, ca), (&mut db, ka, cb)] {
            dev.peers.get_mut(&key).unwrap().retained = Some(RetainedMultipathCarrier {
                carrier,
                kind: RelayKind::Turn,
                attached: false,
                was_ready: false,
                failure_at: None,
                exhausted_in: None,
            });
            dev.set_on_demand_config(OnDemandConfig::disabled());
            let p = &dev.peers[&key];
            // Consume the same deferred-config synchronization as the sole
            // carrier timer before issuing the first test-owned WG INIT.
            p.stats
                .on_demand
                .sync_tunn_if_needed_under_lock(&mut *p.tunn.lock().await);
        }
        assert!(da.poke_handshake(&kb));
        connected(&da, &kb).await;
        negotiated(&mut da, &mut db, true).await;
        assert_eq!(pqa.snapshot().await.current_epoch, 0);
        assert!(da.send_to_peer(&kb, &packet(70)).await);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            packet(70)
        );
        for value in [77, 78, 79] {
            assert!(pqa.buffer_outbound_if_negotiating(&packet(value)).await);
        }
        gb.block_confirm.store(true, Ordering::Release);
        gb.drop_init.store(false, Ordering::Release);
        assert!(pqb.start_or_rotate().await);
        tokio::time::timeout(Duration::from_secs(2), async {
            while gb.confirm.lock().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real ML-KEM response must produce a valid delayed CONFIRM");

        let stats = da.peers[&kb].stats.clone();
        let tunn = da.peers[&kb].tunn.clone();
        let control = stats.mp_control.get().unwrap().clone();
        pqa.reinstall_tunn_psk(Some([9; 32]), true, false, Vec::new(), None)
            .await;
        assert!(!tunn.lock().await.has_current_session());
        assert!(control.holding() && !control.ready(Instant::now()));
        assert!(da.send_to_peer(&kb, &packet(80)).await);
        assert_eq!(control.hold_snapshot().packets, 1);
        ga.business.store(0, Ordering::Relaxed);
        gb.release_confirm().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !matches!(
                pqa.snapshot().await.status,
                PqPeerStatus::Established { .. }
            ) || !matches!(
                pqb.snapshot().await.status,
                PqPeerStatus::Established { .. }
            ) || !tunn.lock().await.has_current_session()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("secondary receiver must verify CONFIRM, install PSK and complete real WG");
        assert_eq!(pqa.pending_multipath_drops(), 3);
        assert_eq!(ga.business.load(Ordering::Relaxed), 0);
        assert_eq!(control.hold_snapshot().packets, 1);
        assert!(control.holding() && !control.ready(Instant::now()));
        assert!(rx.try_recv().is_err());

        // B7 drops must not leak later from Tunn's native queue. Only the
        // separately held IP may leave after actual primary authentication.
        pqa.set_carrier(&da.peers[&kb].carrier);
        pqb.set_carrier(&db.peers[&ka].carrier);
        assert!(da.poke_handshake(&kb));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                da.poll_multipath(&Default::default()).await;
                if !control.holding() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("existing primary recovery authorizes B8 FIFO release");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            packet(80)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err()
        );
        assert!(Arc::ptr_eq(&tunn, &da.peers[&kb].tunn));
        assert!(Arc::ptr_eq(&pqa, da.peers[&kb].stats.pq.get().unwrap()));
    }

    #[tokio::test]
    async fn runtime_initial_pq_pending_without_b8_session_uses_current_primary() {
        use super::super::super::on_demand::OnDemandConfig;
        use super::super::super::pq_psk::{PqPskConfig, PqPskMode};

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        let (mut da, _) = WgDevice::new(a.secret);
        let (mut db, mut rx) = WgDevice::new(b.secret);
        let ka = da.public.to_bytes();
        let kb = db.public.to_bytes();
        for dev in [&mut da, &mut db] {
            dev.multipath_mode = MultipathMode::Redundant;
            dev.set_on_demand_config(OnDemandConfig::disabled());
            dev.set_pq_psk_config(PqPskConfig {
                mode: PqPskMode::Required,
                ..PqPskConfig::default()
            });
        }
        db.add_peer(ka, A, Carrier::direct(sb, aa), false);
        da.add_peer(kb, B, Carrier::direct(sa, ab), true);
        let stats = da.peers[&kb].stats.clone();
        let pq = stats.pq.get().unwrap();
        assert_eq!(stats.multipath_pending_binding(), Some(None));
        assert!(pq.buffer_outbound_if_negotiating(&packet(81)).await);
        connected(&da, &kb).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            packet(81)
        );
        assert_eq!(pq.pending_multipath_drops(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "the authorized initial pending IP is delivered exactly once"
        );
        assert_eq!(da.peer_multipath_snapshot(&kb).unwrap().legs.len(), 1);
    }

    #[derive(Default)]
    struct BlockingPrimary {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl crate::transport::relay::RelayConn for BlockingPrimary {
        async fn send_to(&self, bytes: &[u8], _: SocketAddr) -> io::Result<usize> {
            if bytes.len() > 32 && bytes[..4] == [4, 0, 0, 0] {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(bytes.len())
        }
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
    }

    #[tokio::test]
    async fn runtime_role_invalidated_during_primary_await_never_sends_secondary_business() {
        for withdraw_owner in [false, true] {
            let (mut da, mut db, mut rx, _) =
                pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
            retain_pair(&mut da, &mut db).await;
            negotiated(&mut da, &mut db, true).await;
            let kb = db.public.to_bytes();
            let block = Arc::new(BlockingPrimary::default());
            // Only the transport is substituted: use the actual production
            // WgSender -> encapsulate -> select targets -> awaited dispatch path,
            // the real negotiated Control and the real authenticated secondary.
            let carrier = Carrier::relay(block.clone(), "127.0.0.1:2".parse().unwrap());
            let p = da.peers.get_mut(&kb).unwrap();
            p.carrier = carrier.clone();
            *p.stats.mp_primary.lock().unwrap() = Arc::downgrade(&carrier);
            let (ip, tunn, stats, mp) = (
                p.overlay_ip,
                p.tunn.clone(),
                p.stats.clone(),
                p.multipath.clone(),
            );
            da.send_install(kb, ip, tunn, carrier, stats.clone(), mp);
            let before = da.peer_multipath_snapshot(&kb).unwrap().legs[1].tx_packets;
            let sender = da.sender();
            let sending = tokio::spawn(async move { sender.send_to_peer(&kb, &packet(42)).await });
            tokio::time::timeout(Duration::from_secs(1), block.entered.notified())
                .await
                .unwrap();
            if withdraw_owner {
                // Keep Peer alive to exercise the real uninstall-before-async-
                // cleanup interval, rather than relying on Peer::drop retirement.
                da.send_uninstall(&kb);
            } else {
                stats.mp_control.get().unwrap().role_changed();
            }
            block.release.notify_one();
            assert!(
                sending.await.unwrap(),
                "first transport's completed send is still reported"
            );
            assert_eq!(
                da.peer_multipath_snapshot(&kb).unwrap().legs[1].tx_packets,
                before
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), rx.recv())
                    .await
                    .is_err(),
                "real remote secondary must receive zero business packets"
            );
        }
    }

    #[tokio::test]
    async fn runtime_hold_drain_never_reauthorizes_remaining_fifo_after_binding_change() {
        for reset_session in [false, true] {
            let (mut da, mut db, _, _) =
                pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
            negotiated(&mut da, &mut db, false).await;
            let kb = db.public.to_bytes();
            let block = Arc::new(BlockingPrimary::default());
            let carrier = Carrier::relay(block.clone(), "127.0.0.1:2".parse().unwrap());
            let p = da.peers.get_mut(&kb).unwrap();
            p.carrier = carrier.clone();
            *p.stats.mp_primary.lock().unwrap() = Arc::downgrade(&carrier);
            let (ip, tunn, stats, mp) = (
                p.overlay_ip,
                p.tunn.clone(),
                p.stats.clone(),
                p.multipath.clone(),
            );
            let reset_tunn = tunn.clone();
            da.send_install(kb, ip, tunn, carrier, stats.clone(), mp);
            let control = stats.mp_control.get().unwrap().clone();
            control.begin_hold(Instant::now());
            for v in [80, 81] {
                assert!(da.send_to_peer(&kb, &packet(v)).await);
            }
            let draining = tokio::spawn(async move {
                da.drain_multipath_hold(&kb).await;
                da
            });
            tokio::time::timeout(Duration::from_secs(1), block.entered.notified())
                .await
                .unwrap();
            // Changed role invalidates entry authorization while the first
            // packet is in flight. It cannot authorize the second packet.
            if reset_session {
                let mut tunn = reset_tunn.lock().await;
                tunn.reset_sessions_preserving_replay_and_psk();
                stats.multipath_session_reset();
            } else {
                control.role_changed();
            }
            block.release.notify_one();
            let _da = tokio::time::timeout(Duration::from_secs(1), draining)
                .await
                .unwrap()
                .unwrap();
            let snapshot = control.hold_snapshot();
            assert!(control.holding());
            assert_eq!(snapshot.packets, 1);
            assert_eq!(snapshot.bytes, packet(81).len());
            let held = control.pop_held_at(Instant::now()).unwrap();
            assert_eq!(held.bytes(), packet(81));
            assert_eq!(
                control.hold_snapshot().packets,
                1,
                "in-flight reservation retained"
            );
            drop(held);
            assert!(control.finish_hold());
        }
    }

    #[tokio::test]
    async fn runtime_probation_replay_and_previous_session_empty_frames_never_make_leg_healthy() {
        let (mut da, mut db, _, _) = pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        negotiated(&mut da, &mut db, false).await;
        retain_pair(&mut da, &mut db).await;
        let ka = da.public.to_bytes();
        let kb = db.public.to_bytes();
        let candidate_a = da.peers[&kb].retained.as_ref().unwrap().carrier.clone();
        let candidate_b = db.peers[&ka].retained.as_ref().unwrap().carrier.clone();
        let stats_b = db.peers[&ka].stats.clone();
        *stats_b.mp_secondary.lock().unwrap() = Arc::downgrade(&candidate_b);
        assert!(db.add_multipath_leg_with_health(&ka, 1, candidate_b, 10, 1, false));
        let mut frames = Vec::new();
        {
            let mut tunn = da.peers[&kb].tunn.lock().await;
            let mut buf = vec![0; WG_BUF];
            for _ in 0..2 {
                if let TunnResult::WriteToNetwork(out) = tunn.encapsulate(&[], &mut buf) {
                    frames.push(out.to_vec());
                }
            }
        }
        assert_eq!(frames.len(), 2);
        candidate_a.send(&frames[0]).await.unwrap();
        candidate_a.send(&frames[0]).await.unwrap(); // replay alone is no proof roundtrip
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!stats_b.mp_control.get().unwrap().ready(Instant::now()));
        assert!(!db.peer_multipath_snapshot(&ka).unwrap().legs[1].healthy);
        let old = stats_b.mp_control.get().unwrap().binding().unwrap();
        assert!(da.poke_handshake(&kb));
        tokio::time::timeout(Duration::from_secs(2), async {
            while stats_b.mp_control.get().unwrap().binding() == Some(old) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let current = stats_b.mp_control.get().unwrap().binding();
        let primary_rx = stats_b.mp_primary_rx_any.load(Ordering::Relaxed);
        // This is fresh (unused counter), AEAD-valid in boringtun's retained
        // previous session; it cannot roll B8's active transcript backwards.
        candidate_a.send(&frames[1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(stats_b.mp_control.get().unwrap().binding(), current);
        assert_eq!(
            stats_b.mp_primary_rx_any.load(Ordering::Relaxed),
            primary_rx
        );
        assert!(!stats_b.mp_control.get().unwrap().ready(Instant::now()));
        assert!(!db.peer_multipath_snapshot(&ka).unwrap().legs[1].healthy);
    }

    #[tokio::test]
    async fn runtime_authenticated_secondary_survives_primary_loss_and_transfers_same_tunn() {
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let ka = da.public.to_bytes();
        let tunn = da.peers[&kb].tunn.clone();
        let pq = da.peers[&kb].stats.pq.get().unwrap().clone();
        let binding = da.peers[&kb]
            .stats
            .mp_control
            .get()
            .unwrap()
            .binding()
            .unwrap();
        let baseline = db.peer_primary_traffic(&ka).unwrap().1;
        let hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        da.peers[&kb]
            .carrier
            .set_direct_dst(hole.local_addr().unwrap());
        for value in 0..3 {
            let p = packet(value);
            assert!(da.send_to_peer(&kb, &p).await);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                p
            );
        }
        assert_eq!(
            db.peer_primary_traffic(&ka).unwrap().1,
            baseline,
            "secondary data cannot certify primary health"
        );
        assert!(matches!(
            da.multipath_primary_failed(&kb, true).await,
            MultipathFailure::Promoted(RelayKind::Turn)
        ));
        assert!(Arc::ptr_eq(&tunn, &da.peers[&kb].tunn));
        assert!(Arc::ptr_eq(&pq, da.peers[&kb].stats.pq.get().unwrap()));
        assert!(!da.peers[&kb].carrier.is_direct());
        assert_eq!(
            da.peers[&kb].tasks.len(),
            2,
            "one transferred receiver, one timer"
        );
        let new_binding = da.peers[&kb]
            .stats
            .mp_control
            .get()
            .unwrap()
            .binding()
            .unwrap();
        assert_eq!(binding.session_generation, new_binding.session_generation);
        assert_ne!(binding.role_generation, new_binding.role_generation);
        let p = packet(9);
        assert!(da.send_to_peer(&kb, &p).await);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            p
        );
        da.remove_peer(&kb).await;
        assert!(!da.sender().0.read().unwrap().peers.contains_key(&kb));
    }

    #[tokio::test]
    async fn runtime_healthy_primary_peer_restart_answers_fallback_in_original_arm() {
        let (mut da, mut db, _, secret_b) =
            pair(MultipathMode::Redundant, MultipathMode::Aggregate).await;
        negotiated(&mut da, &mut db, false).await;
        let ka = da.public.to_bytes();
        let kb = db.public.to_bytes();
        let primary = da.peers[&kb].carrier.clone();
        let tunn = da.peers[&kb].tunn.clone();
        let pq = da.peers[&kb].stats.pq.get().unwrap().clone();
        let binding = da.peers[&kb]
            .stats
            .mp_control
            .get()
            .unwrap()
            .binding()
            .unwrap();
        let carrier_b = db.peers[&ka].carrier.clone();
        db.remove_peer(&ka).await;
        drop(db);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (mut restarted, mut rx) = WgDevice::new(secret_b);
        restarted.multipath_mode = MultipathMode::Aggregate;
        restarted.set_on_demand_config(super::super::super::on_demand::OnDemandConfig::disabled());
        restarted.add_peer(ka, A, carrier_b, false);
        let arm = Instant::now();
        assert!(da.request_carrier_revalidation(&kb));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!da.peer_initiator_hs_answered(&kb, arm));
        tokio::time::sleep(super::super::super::lifecycle::BUSINESS_POKE_RETAP_AFTER).await;
        // This consumes the first-cycle fallback once; it does not replace arm.
        assert!(!da.peer_initiator_hs_answered(&kb, arm));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !da.peer_initiator_hs_answered(&kb, arm) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("healthy restarted primary answers ordinary INIT");
        assert!(Arc::ptr_eq(&primary, &da.peers[&kb].carrier));
        assert!(Arc::ptr_eq(&tunn, &da.peers[&kb].tunn));
        assert!(Arc::ptr_eq(&pq, da.peers[&kb].stats.pq.get().unwrap()));
        let next = da.peers[&kb]
            .stats
            .mp_control
            .get()
            .unwrap()
            .binding()
            .unwrap();
        assert_ne!(binding.session_generation, next.session_generation);
        assert!(
            !da.peers[&kb]
                .stats
                .mp_control
                .get()
                .unwrap()
                .ready(Instant::now())
        );
        let p = packet(7);
        assert!(da.send_to_peer(&kb, &p).await);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            p
        );
    }

    #[tokio::test]
    async fn runtime_real_pq_guard_reset_invalidates_proof_and_preserves_held_fifo() {
        if std::env::var_os("MH_PQ_FIFO_ISOLATED").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let out = std::process::Command::new(exe)
                .env("MH_PQ_FIFO_ISOLATED", "1")
                .args([
                    "--exact",
                    "overlay::wg::multipath_runtime::tests::runtime_real_pq_guard_reset_invalidates_proof_and_preserves_held_fifo",
                    "--nocapture",
                ])
                .output()
                .expect("spawn isolated pq guard reset fifo test");
            assert!(
                out.status.success(),
                "isolated runtime_real_pq_guard_reset_invalidates_proof_and_preserves_held_fifo failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let tunn = da.peers[&kb].tunn.clone();
        let stats = da.peers[&kb].stats.clone();
        let pq = stats.pq.get().unwrap().clone();
        let control = stats.mp_control.get().unwrap().clone();
        let original = control.binding();
        // Exercise the real B7 installation method. An ordinary in-place
        // PSK update preserves live WG sessions and must preserve B8 binding.
        pq.reinstall_tunn_psk(Some([7; 32]), false, false, Vec::new(), None)
            .await;
        assert_eq!(control.binding(), original);
        assert!(control.ready(Instant::now()));
        pq.reinstall_tunn_psk(Some([9; 32]), true, false, Vec::new(), None)
            .await;
        assert!(!tunn.lock().await.has_current_session());
        assert!(control.binding().is_none());
        assert!(!control.ready(Instant::now()));
        assert!(control.recovery_allowed());
        assert!(control.holding());
        assert!(!da.peer_multipath_snapshot(&kb).unwrap().legs[1].healthy);
        for v in [55, 56] {
            assert!(da.send_to_peer(&kb, &packet(v)).await);
        }
        assert_eq!(control.hold_snapshot().packets, 2);
        assert!(rx.try_recv().is_err());
        // The real classical-downgrade reset must retain this same bounded
        // FIFO, then release it only after a new authenticated primary RTT.
        pq.reinstall_tunn_psk(None, false, true, Vec::new(), None)
            .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                da.poll_multipath(&Default::default()).await;
                if !control.holding() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("current primary recovery drains original FIFO");
        for v in [55, 56] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                packet(v)
            );
        }
        assert!(Arc::ptr_eq(&tunn, &da.peers[&kb].tunn));
        assert!(Arc::ptr_eq(&pq, da.peers[&kb].stats.pq.get().unwrap()));
        assert_eq!(control.hold_snapshot().packets, 0);
    }

    #[tokio::test]
    async fn runtime_b6_dormant_is_silent_and_wake_preserves_b8_fifo() {
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let ka = da.public.to_bytes();
        let kb = db.public.to_bytes();
        let cfg =
            super::super::super::on_demand::OnDemandConfig::enabled(Duration::from_millis(300))
                .with_defer_initial_handshake(false);
        da.set_on_demand_config(cfg);
        db.set_on_demand_config(cfg);
        tokio::time::timeout(Duration::from_secs(3), async {
            while da.peer_is_dormant(&kb) != Some(true) || db.peer_is_dormant(&ka) != Some(true) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let a = da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets;
        let b = db.peer_on_demand_snapshot(&ka).unwrap().wire_tx_packets;
        for _ in 0..5 {
            da.poll_multipath(&Default::default()).await;
            db.poll_multipath(&Default::default()).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets, a);
        assert_eq!(db.peer_on_demand_snapshot(&ka).unwrap().wire_tx_packets, b);
        for v in [70, 71] {
            assert!(da.send_to_peer(&kb, &packet(v)).await);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while da.peers[&kb].stats.mp_control.get().unwrap().holding() {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("existing B6 handshake wakes and authorizes same-primary FIFO");
        for v in [70, 71] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                packet(v)
            );
        }
    }

    fn batch(n: u8) -> Vec<Vec<u8>> {
        (0..n).map(packet).collect()
    }

    /// B8 throughput fix (handoff 222): a controlled batch takes ONE locked
    /// decision pass and per-leg grouped emission, yet every mode still
    /// delivers each packet exactly once and in order on a real negotiated
    /// two-leg session.
    #[tokio::test]
    async fn runtime_controlled_batch_delivers_every_packet_once_in_order_in_every_mode() {
        for mode in [
            MultipathMode::ActiveStandby,
            MultipathMode::Redundant,
            MultipathMode::Aggregate,
        ] {
            let (mut da, mut db, mut rx, _) = pair(mode, mode).await;
            retain_pair(&mut da, &mut db).await;
            negotiated(&mut da, &mut db, true).await;
            let kb = db.public.to_bytes();
            assert!(da.peers[&kb].stats.mp_control.get().is_some());
            let burst = batch(64);
            assert_eq!(da.send_ip_batch(&burst).await, 64, "{mode:?}");
            for (i, want) in burst.iter().enumerate() {
                let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap_or_else(|_| panic!("{mode:?}: packet {i} lost"))
                    .unwrap();
                assert_eq!(&got, want, "{mode:?}: packet {i} reordered or altered");
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(200), rx.recv())
                    .await
                    .is_err(),
                "{mode:?}: a packet was delivered twice"
            );
        }
    }

    /// While B8 holds for recovery, a batch is queued behind the hold exactly
    /// as N single sends would be: counted as sent, nothing reaches the wire.
    #[tokio::test]
    async fn runtime_controlled_batch_during_hold_queues_every_packet_and_sends_none() {
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::ActiveStandby, MultipathMode::ActiveStandby).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let control = da.peers[&kb].stats.mp_control.get().unwrap().clone();
        control.begin_hold(Instant::now());
        assert!(control.holding());
        let before = control.hold_snapshot().packets;
        assert_eq!(da.send_ip_batch(&batch(3)).await, 3);
        assert_eq!(control.hold_snapshot().packets, before + 3);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err()
        );
    }

    fn udp_relay(sock: UdpSocket, dst: SocketAddr) -> Arc<Carrier> {
        Carrier::relay(Arc::new(UdpRelayConn(sock)), dst)
    }

    /// Lifecycle (peer restart): the relay incumbent is gone and direct is
    /// healthy. A later relay carrier is adopted once, unattached, and B8
    /// proves the current shared session over it before it carries anything.
    #[tokio::test]
    async fn runtime_late_standby_is_adopted_once_and_validates_on_a_direct_peer() {
        let (mut off_a, _off_b, _, _) = pair(MultipathMode::Off, MultipathMode::Off).await;
        let off_key = *off_a.peers.keys().next().unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            !off_a.wants_multipath_standby(&off_key),
            "default Off never wants a standby"
        );
        assert!(!off_a.adopt_multipath_standby(
            &off_key,
            udp_relay(s, "127.0.0.1:9".parse().unwrap()),
            RelayKind::Org
        ));

        let (mut da, mut db, _, _) =
            pair(MultipathMode::ActiveStandby, MultipathMode::ActiveStandby).await;
        let (ka, kb) = (da.public.to_bytes(), db.public.to_bytes());
        let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        assert!(da.wants_multipath_standby(&kb));
        let ca = udp_relay(sa, ab);
        assert!(da.adopt_multipath_standby(&kb, ca.clone(), RelayKind::Turn));
        assert!(!da.wants_multipath_standby(&kb), "one standby leg per peer");
        let spare = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(!da.adopt_multipath_standby(&kb, udp_relay(spare, ab), RelayKind::Turn));
        assert!(Arc::ptr_eq(
            &da.peers[&kb].retained.as_ref().unwrap().carrier,
            &ca
        ));
        assert!(!da.peers[&kb].retained.as_ref().unwrap().attached);
        assert!(db.adopt_multipath_standby(&ka, udp_relay(sb, aa), RelayKind::Turn));
        assert!(
            da.peers[&kb].carrier.is_direct(),
            "adoption never touches the primary"
        );
        negotiated(&mut da, &mut db, true).await;
        assert!(da.peers[&kb].retained.as_ref().unwrap().attached);
        assert!(da.peers[&kb].carrier.is_direct());
    }

    /// R4: one end kept the DERP floor as its standby (direct latched first),
    /// the other end the ORG link. A late ORG carrier replaces DERP so both
    /// ends converge; an ORG standby is never replaced.
    #[tokio::test]
    async fn late_org_carrier_replaces_a_derp_standby_but_never_an_org_one() {
        let (mut da, _db, _, _) =
            pair(MultipathMode::ActiveStandby, MultipathMode::ActiveStandby).await;
        let kb = *da.peers.keys().next().unwrap();
        let sock = |_: ()| async { UdpSocket::bind("127.0.0.1:0").await.unwrap() };
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let derp = udp_relay(sock(()).await, dst);
        assert!(da.adopt_multipath_standby(&kb, derp.clone(), RelayKind::Derp));
        assert!(
            da.wants_multipath_standby(&kb),
            "a DERP standby still wants ORG"
        );
        let org = udp_relay(sock(()).await, dst);
        assert!(da.adopt_multipath_standby(&kb, org.clone(), RelayKind::Org));
        let r = da.peers[&kb].retained.as_ref().unwrap();
        assert!(Arc::ptr_eq(&r.carrier, &org) && r.kind == RelayKind::Org && !r.attached);
        assert!(!da.wants_multipath_standby(&kb), "an ORG standby is final");
        assert!(!da.adopt_multipath_standby(&kb, udp_relay(sock(()).await, dst), RelayKind::Org));
        assert!(da.peers[&kb].carrier.is_direct());
    }

    /// Readiness is tracked per poll, so a proof reset (rekey, restart) and
    /// the next proof are each reported, not only the first one ever.
    #[tokio::test]
    async fn runtime_validated_readiness_rearms_after_a_proof_reset() {
        let (mut da, mut db, _, _) = pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        let kb = db.public.to_bytes();
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        da.poll_multipath(&Default::default()).await;
        assert!(da.peers[&kb].retained.as_ref().unwrap().was_ready);
        da.peers[&kb].stats.mp_control.get().unwrap().role_changed();
        da.poll_multipath(&Default::default()).await;
        assert!(!da.peers[&kb].retained.as_ref().unwrap().was_ready);
        negotiated(&mut da, &mut db, true).await;
        da.poll_multipath(&Default::default()).await;
        assert!(da.peers[&kb].retained.as_ref().unwrap().was_ready);
    }

    /// Lifecycle (peer restart): direct latches while the ORG link is still an
    /// unproven upgrade candidate. B8 keeps that carrier as the standby leg;
    /// default Off keeps the original cancel-and-promote path unchanged.
    #[tokio::test(flavor = "multi_thread")]
    async fn promotion_keeps_an_unproven_org_candidate_as_the_standby_leg() {
        for mode in [MultipathMode::ActiveStandby, MultipathMode::Off] {
            let kp = WgKeypair::generate();
            let peer = WgKeypair::generate();
            let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
            dev.multipath_mode = mode;
            dev.set_on_demand_config(super::super::super::on_demand::OnDemandConfig::disabled());
            let pk = peer.public.to_bytes();
            let floor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            dev.add_peer(
                pk,
                B,
                udp_relay(floor, "127.0.0.1:9".parse().unwrap()),
                false,
            );
            let org_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let org = udp_relay(org_sock, "127.0.0.1:9".parse().unwrap());
            assert!(dev.start_org_upgrade(pk, B, org.clone()).await);
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            dev.ensure_direct_demux(sock.clone());
            dev.start_direct_probe(sock, pk, B, "127.0.0.1:9".parse().unwrap(), true)
                .await;
            dev.test_latch_probe_handshake_done(&pk);
            assert!(
                dev.promote_direct_probe_multipath(&pk, Some(RelayKind::Derp))
                    .await
            );
            assert!(dev.peers[&pk].carrier.is_direct());
            assert!(
                !dev.org_upgrades.contains_key(&pk),
                "the candidate never outlives promotion"
            );
            match mode {
                MultipathMode::Off => assert!(dev.peers[&pk].retained.is_none()),
                _ => {
                    let r = dev.peers[&pk].retained.as_ref().expect("standby leg kept");
                    assert!(Arc::ptr_eq(&r.carrier, &org));
                    assert_eq!(r.kind, RelayKind::Org);
                    assert!(!r.attached && !r.was_ready);
                    assert!(!org.is_dead());
                }
            }
        }
    }

    /// B7 x org upgrade: the org-relay candidate shares the incumbent's PQ
    /// handle (one PSK lineage per peer), every rotation reaches the candidate
    /// Tunn, and promotion/cancellation move or clear exactly that binding.
    #[tokio::test(flavor = "multi_thread")]
    async fn org_candidate_shares_the_incumbent_pq_handle_and_receives_rotations() {
        use super::super::super::pq_psk::{PqPskConfig, PqPskMode};
        let kp = WgKeypair::generate();
        let peer = WgKeypair::generate();
        let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
        dev.set_pq_psk_config(PqPskConfig {
            mode: PqPskMode::Required,
            configured_psk: Some([0x42; 32]),
            ..PqPskConfig::default()
        });
        dev.set_on_demand_config(super::super::super::on_demand::OnDemandConfig::disabled());
        let pk = peer.public.to_bytes();
        let floor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        dev.add_peer(
            pk,
            B,
            udp_relay(floor, "127.0.0.1:9".parse().unwrap()),
            false,
        );
        let incumbent = dev.peers[&pk].stats.pq.get().cloned().expect("pq handle");
        for round in 0..2 {
            let org_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            assert!(
                dev.start_org_upgrade(pk, B, udp_relay(org_sock, "127.0.0.1:9".parse().unwrap()))
                    .await
            );
            let cand = &dev.org_upgrades[&pk].candidate;
            assert!(
                Arc::ptr_eq(cand.stats.pq.get().unwrap(), &incumbent),
                "one PSK lineage per peer"
            );
            let rotated = [0x50 + round as u8; 32];
            incumbent
                .reinstall_tunn_psk(Some(rotated), false, false, Vec::new(), None)
                .await;
            let cand = &dev.org_upgrades[&pk].candidate;
            assert_eq!(
                cand.tunn.lock().await.preshared_key(),
                Some(rotated),
                "rotation reaches the candidate"
            );
            assert_eq!(
                dev.peers[&pk].tunn.lock().await.preshared_key(),
                Some(rotated)
            );
            let stats = cand.stats.clone();
            if round == 0 {
                dev.cancel_org_upgrade(&pk);
                assert!(
                    !incumbent.promote_candidate_to_primary(&stats),
                    "cancel cleared the binding"
                );
            } else {
                assert!(incumbent.promote_candidate_to_primary(&stats));
                assert!(
                    !incumbent.promote_candidate_to_primary(&stats),
                    "promoted exactly once"
                );
                dev.cancel_org_upgrade(&pk);
            }
        }
    }

    #[tokio::test]
    async fn first_session_exhaustion_keeps_the_standby_until_a_newer_session_exhausts_too() {
        // B8 on one end only: every offer goes unanswered, as it does when crossed
        // bring-up handshakes leave the ends on different sessions.
        let (mut da, mut db, _rx, _) = pair(MultipathMode::Redundant, MultipathMode::Off).await;
        retain_pair(&mut da, &mut db).await;
        let kb = db.public.to_bytes();
        let control = da.peers[&kb].stats.mp_control.get().unwrap().clone();
        let first = control.binding().unwrap().session_generation;
        let drive = |deadline: Instant| async move {
            assert!(Instant::now() < deadline, "negotiation never ran out");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !control.exhausted(Instant::now()) {
            da.poll_multipath(&Default::default()).await;
            db.poll_multipath(&Default::default()).await;
            drive(deadline).await;
        }
        for _ in 0..3 {
            assert!(da.poll_multipath(&Default::default()).await.is_empty());
        }
        assert!(
            da.retains_multipath_carrier(&kb),
            "one session's exhaustion must not release the standby leg"
        );
        assert!(da.poke_handshake(&kb));
        let deadline = Instant::now() + Duration::from_secs(15);
        while control.binding().unwrap().session_generation <= first {
            da.poll_multipath(&Default::default()).await;
            db.poll_multipath(&Default::default()).await;
            drive(deadline).await;
        }
        assert!(
            da.retains_multipath_carrier(&kb),
            "a newer session restarts negotiation before any release"
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut released = Vec::new();
        while da.retains_multipath_carrier(&kb) {
            released.extend(da.poll_multipath(&Default::default()).await);
            db.poll_multipath(&Default::default()).await;
            drive(deadline).await;
        }
        assert_eq!(released, vec![(kb, None)]);
    }

    #[tokio::test]
    async fn a_packet_an_expired_hold_refuses_without_a_session_still_starts_a_handshake() {
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let (tunn, stats) = {
            let p = &da.peers[&kb];
            (p.tunn.clone(), p.stats.clone())
        };
        {
            let mut t = tunn.lock().await;
            t.reset_sessions_preserving_replay_and_psk();
            stats.multipath_session_reset();
        }
        let control = stats.mp_control.get().unwrap().clone();
        assert!(control.holding());
        control.expire_hold_now();
        let before = da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets;
        assert!(
            !da.send_to_peer(&kb, &packet(91)).await,
            "an expired hold refuses the packet"
        );
        assert!(
            da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets > before,
            "a refused packet with no session must still emit a handshake initiation"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !tunn.lock().await.has_current_session() {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the initiation re-established a session");
        drop(rx.try_recv());
    }

    #[tokio::test]
    async fn dormant_entry_leaves_no_hold_and_the_next_packet_initiates() {
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let (tunn, stats) = {
            let p = &da.peers[&kb];
            (p.tunn.clone(), p.stats.clone())
        };
        {
            // What the B6 timer does on Dormant entry.
            let mut t = tunn.lock().await;
            t.reset_sessions_preserving_replay_and_psk();
            stats.multipath_idle_reset();
        }
        let control = stats.mp_control.get().unwrap().clone();
        assert!(!control.holding(), "Dormant entry arms no recovery hold");
        assert!(control.binding().is_none());
        let before = da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets;
        assert!(da.send_to_peer(&kb, &packet(92)).await);
        assert!(
            da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets > before,
            "the first packet after Dormant must emit a handshake initiation"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !tunn.lock().await.has_current_session() {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the initiation re-established a session");
        drop(rx.try_recv());
    }

    #[tokio::test]
    async fn a_held_packet_without_a_session_starts_a_handshake_even_when_not_just_woken() {
        // B8 proved a secondary, then the session was cleared the way B6 Dormant
        // entry clears it; the peer is Active again without a wake (B6 off here).
        let (mut da, mut db, mut rx, _) =
            pair(MultipathMode::Redundant, MultipathMode::Redundant).await;
        retain_pair(&mut da, &mut db).await;
        negotiated(&mut da, &mut db, true).await;
        let kb = db.public.to_bytes();
        let (tunn, stats) = {
            let p = &da.peers[&kb];
            (p.tunn.clone(), p.stats.clone())
        };
        {
            let mut t = tunn.lock().await;
            t.reset_sessions_preserving_replay_and_psk();
            stats.multipath_session_reset();
        }
        let control = stats.mp_control.get().unwrap().clone();
        assert!(control.holding() && control.recovery_allowed());
        let before = da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets;
        assert!(da.send_to_peer(&kb, &packet(90)).await);
        assert!(control.hold_snapshot().packets >= 1, "the packet is held");
        assert!(
            da.peer_on_demand_snapshot(&kb).unwrap().wire_tx_packets > before,
            "a held packet with no session must emit a handshake initiation"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !tunn.lock().await.has_current_session() {
                da.poll_multipath(&Default::default()).await;
                db.poll_multipath(&Default::default()).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the initiation re-established a session");
        drop(rx.try_recv());
    }
}
