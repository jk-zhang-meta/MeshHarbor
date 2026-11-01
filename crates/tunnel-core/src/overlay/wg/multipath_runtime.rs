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
        });
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
            let remove = peer.retained.as_ref().is_some_and(|r| {
                r.carrier.is_dead()
                    || r.kind == super::super::relay_link::RelayKind::Org
                        && !org_allowed.contains(&key)
                    || control.exhausted(now) && !control.recovery_allowed()
            });
            if remove {
                self.drop_retained_multipath(&key);
                released.push((key, None));
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
                    info!(event="multipath_validated", peer_key=%hex::encode(key), mode=?control.mode(), "overlay: current shared-session secondary validated");
                }
                retained.was_ready |= ready;
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
        if self
            .peers
            .get(key)
            .is_some_and(|p| p.stats.mp_control.get().is_some())
        {
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
            if !peer.send_inner(packet.bytes(), true).await {
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
            });
        db.peers.get_mut(&da.public.to_bytes()).unwrap().retained =
            Some(RetainedMultipathCarrier {
                carrier: Carrier::relay(Arc::new(UdpRelayConn(sb)), aa),
                kind: RelayKind::Turn,
                attached: false,
                was_ready: false,
                failure_at: None,
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
}
