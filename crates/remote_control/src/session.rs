// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Per-session state machine.
//!
//! Each `RemoteSession` has a lightweight in-memory state object held by the
//! `Hub` while the session is non-terminal. The MongoDB `RemoteSession`
//! document is the durable record; this struct is the live cache.

use bson::{DateTime, oid::ObjectId};
use std::collections::HashMap;
use tokio::sync::mpsc;

use crate::consent::ConsentSlot;
use crate::error::{Error, Result};
use crate::models::{ConsentMode, EndReason, SessionPhase, SessionStats};
use crate::permissions::Permissions;
use crate::signaling::{LocalRelayDescriptor, ServerMsg};

/// Channel used to push messages to a connected client (agent or controller).
/// The WS layer owns the receiving half and forwards to the socket.
pub type ClientTx = mpsc::Sender<ServerMsg>;

pub struct LiveSession {
    pub id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    permissions: Permissions,
    device_share_scope: Option<DeviceShareSessionScope>,
    share_watch_started: bool,
    shared_lease_epoch: Option<String>,
    pub phase: SessionPhase,
    pub created_at: DateTime,
    pub started_at: Option<DateTime>,
    pub stats: SessionStats,

    /// One-shot consent slot, taken when the agent replies.
    pub consent_slot: Option<ConsentSlot>,

    /// FR-27 — the consent mode this session was created under.
    ///
    /// Needed at DELIVERY time, not just at request time: under
    /// `prompt_then_email` a host-side timeout must NOT resolve the slot,
    /// because the owner's emailed link is still live and is the whole point of
    /// the mode. Without the mode here, `deliver_consent` cannot tell that case
    /// from an ordinary attended timeout, and would end the session the moment
    /// the on-host modal closed.
    pub consent_mode: ConsentMode,

    /// Watchers (view-only). user_id → tx
    pub watchers: HashMap<ObjectId, ClientTx>,

    /// The active controller's tx. None if disconnected.
    pub controller_tx: Option<ClientTx>,

    /// Loopback-TURN corp-relay (Phase 2). Set from the controller's
    /// `rc:session.request` when its browser discovered a local-agent TURN; the
    /// Hub reads it back in `forward_offer` to append `turn:{overlay_ip}:{port}`
    /// to the REMOTE agent's ICE servers. `None` for every session that didn't
    /// forward one (the default). See [`LocalRelayDescriptor`].
    pub local_relay: Option<LocalRelayDescriptor>,

    /// #1882 — the device's `AccessPolicy.rc_overlay`, resolved at session
    /// create. `forward_offer` hands the agent the overlay `local_relay` TURN
    /// only when this is `true`: with the overlay off, an overlay relay is a
    /// candidate the agent would only discard.
    pub rc_overlay: bool,

    /// Multi-region relay: the region FROZEN at session create (load-aware
    /// pick over the agent's home + RTT-ordered prefs). Frozen so all three
    /// per-session issuance pushes (Ready / SdpOffer / SdpAnswer) carry the
    /// SAME region even if the agent's home or a busy flag flips mid-setup —
    /// a split would put the two ICE ends on different PoPs. `None` = the
    /// default region.
    pub relay_region: Option<String>,

    /// Whether the controller's SDP offer ever arrived. Read by the
    /// post-consent negotiating reaper: consent granted + `Ready` pushed but
    /// no offer within the window means the controller never heard back
    /// (its socket died, or its reply raced a teardown) — the session would
    /// otherwise sit in `Negotiating` forever while the browser shows
    /// "awaiting consent" (2026-08-05 winhost-a incident).
    pub offer_seen: bool,

    /// The exact `ServerMsg::Request` pushed to the agent at create, kept
    /// while consent is pending. An agent whose control WS flaps between
    /// the Request and its `rc:consent` reply loses the exchange entirely;
    /// `register_agent` re-pushes this on the agent's fresh connection so
    /// the consent flow completes instead of timing out.
    pub pending_request: Option<ServerMsg>,

    /// FR-85 P3 — why `Permissions::RECORD` was stripped from this grant, when
    /// it was asked for and refused (`device_cannot_record`,
    /// `controller_not_allowed`, `device_not_opted_in`). Kept so a DUPLICATE
    /// request coalesced onto this
    /// session (#1045) is answered with the same reason: the effective grant
    /// it repeats lacks RECORD, and a bare `None` would read as "never asked".
    pub record_refused: Option<&'static str>,

    /// FR-99 — why `Permissions::PRIVACY` was stripped from this grant
    /// (`device_cannot_curtain`, `break_glass`, `device_not_opted_in`). Kept
    /// for a coalesced duplicate request, exactly as [`Self::record_refused`].
    pub privacy_refused: Option<&'static str>,

    /// FR-101 P2 — the session features the policy took out of this grant,
    /// feature → reason (`files` → `org_policy_off`). Kept for a coalesced
    /// duplicate request, exactly as [`Self::record_refused`]. Empty = none.
    pub features_refused: std::collections::BTreeMap<&'static str, &'static str>,

    /// FR-101 P4b — the org's maximum session length, armed as a timer when
    /// the session goes live and TAKEN then, so a renegotiation cannot arm a
    /// second. `None` = no limit (or already armed).
    pub max_duration: Option<std::time::Duration>,

    /// FR-101 P4b-2 — the idle limit the viewer was told (`SessionCreated.
    /// idle_secs`): set only when the device keeps it. Kept for a coalesced
    /// duplicate request, exactly as [`Self::record_refused`].
    pub idle_secs: Option<u32>,
}

impl LiveSession {
    pub fn shared_lease_epoch(&self) -> Option<&str> {
        self.shared_lease_epoch.as_deref()
    }
    pub fn set_shared_lease_epoch(&mut self, epoch: String) -> Result<()> {
        if self.device_share_scope.is_none()
            || self
                .shared_lease_epoch
                .as_ref()
                .is_some_and(|e| e != &epoch)
        {
            return Err(Error::PermissionDenied("immutable shared lease epoch"));
        }
        self.shared_lease_epoch = Some(epoch);
        Ok(())
    }
    pub fn permissions(&self) -> Permissions {
        self.permissions
    }
    /// Every future permission update must cross this ceiling; the field is private.
    pub fn set_permissions(&mut self, permissions: Permissions) {
        self.permissions = self
            .device_share_scope
            .map_or(permissions, |s| permissions & s.ceiling);
    }
    pub fn device_share_scope(&self) -> Option<DeviceShareSessionScope> {
        self.device_share_scope
    }
    pub fn bind_device_share(&mut self, scope: DeviceShareSessionScope) -> Result<()> {
        if self.device_share_scope.is_some_and(|old| old != scope) {
            return Err(Error::PermissionDenied(
                "session already has another share scope",
            ));
        }
        self.device_share_scope = Some(scope);
        self.set_permissions(self.permissions);
        Ok(())
    }
    pub fn claim_share_watch(&mut self, grant_id: ObjectId) -> bool {
        if self.share_watch_started
            || self
                .device_share_scope
                .is_none_or(|s| s.grant_id != grant_id)
        {
            return false;
        }
        self.share_watch_started = true;
        true
    }
    pub fn new(
        id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        controller_user_id: ObjectId,
        permissions: Permissions,
        controller_tx: ClientTx,
    ) -> (Self, crate::consent::ConsentWaiter) {
        let (slot, waiter) = ConsentSlot::new();
        let s = Self {
            id,
            agent_id,
            tenant_id,
            controller_user_id,
            permissions,
            device_share_scope: None,
            share_watch_started: false,
            shared_lease_epoch: None,
            phase: SessionPhase::Pending,
            created_at: DateTime::now(),
            started_at: None,
            stats: SessionStats::default(),
            consent_slot: Some(slot),
            // `create_session` overwrites this with the resolved directive.
            // The attended default is the safe one to be wrong in.
            consent_mode: ConsentMode::Prompt,
            watchers: HashMap::new(),
            controller_tx: Some(controller_tx),
            local_relay: None,
            rc_overlay: false,
            relay_region: None,
            offer_seen: false,
            pending_request: None,
            record_refused: None,
            privacy_refused: None,
            features_refused: Default::default(),
            max_duration: None,
            idle_secs: None,
        };
        (s, waiter)
    }

    /// Transition guard: only certain transitions are legal.
    pub fn transition(&mut self, to: SessionPhase) -> Result<()> {
        use SessionPhase::*;
        let ok = matches!(
            (self.phase, to),
            (Pending, AwaitingConsent)
                | (AwaitingConsent, Negotiating)
                | (AwaitingConsent, Closed)
                | (Negotiating, Active)
                | (Negotiating, Closed)
                | (Active, Closed)
                | (Pending, Closed)
        );
        if !ok {
            return Err(Error::BadPhase(self.id.to_hex(), phase_name(self.phase)));
        }
        self.phase = to;
        if to == SessionPhase::Active {
            self.started_at = Some(DateTime::now());
        }
        Ok(())
    }

    pub fn is_terminal(&self) -> bool {
        self.phase == SessionPhase::Closed
    }

    /// Admit the controller's SDP offer: only in `Negotiating`, and only once.
    ///
    /// An offer is the controller's reply to `rc:ready`, which goes out when
    /// consent is GRANTED (`AwaitingConsent → Negotiating`), and the agent
    /// builds a peer from whatever offer reaches it. So this is where consent
    /// is enforced for the media path: an offer admitted in `AwaitingConsent`
    /// streamed the screen while the host's prompt was still up, and a second
    /// offer rebuilt the agent's peer after its per-session grant had been
    /// consumed by the first — under the DEFAULT grant, so a view-only session
    /// came back with input and clipboard. Every controller the server ships
    /// sends exactly one offer, on `rc:ready`.
    pub fn admit_offer(&mut self) -> Result<()> {
        if self.phase != SessionPhase::Negotiating {
            return Err(Error::BadPhase(self.id.to_hex(), phase_name(self.phase)));
        }
        if self.offer_seen {
            return Err(Error::BadPhase(self.id.to_hex(), "offer_already_forwarded"));
        }
        self.offer_seen = true;
        Ok(())
    }
}

fn phase_name(p: SessionPhase) -> &'static str {
    match p {
        SessionPhase::Pending => "pending",
        SessionPhase::AwaitingConsent => "awaiting_consent",
        SessionPhase::Negotiating => "negotiating",
        SessionPhase::Active => "active",
        SessionPhase::Closed => "closed",
    }
}

/// Why a session ended (used by the Hub to write final Mongo state).
#[derive(Debug, Clone)]
pub struct CloseRecord {
    pub session_id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub reason: EndReason,
    pub stats: SessionStats,
    pub ended_at: DateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> LiveSession {
        let (tx, _rx) = mpsc::channel(8);
        let (s, _) = LiveSession::new(
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            Permissions::default(),
            tx,
        );
        s
    }

    #[test]
    fn legal_path() {
        let mut s = fixture();
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.transition(SessionPhase::Closed).unwrap();
        assert!(s.is_terminal());
    }

    #[test]
    fn cannot_skip_phases() {
        let mut s = fixture();
        assert!(s.transition(SessionPhase::Active).is_err());
    }

    #[test]
    fn closed_is_dead_end() {
        let mut s = fixture();
        s.transition(SessionPhase::Closed).unwrap();
        assert!(s.transition(SessionPhase::Active).is_err());
    }

    #[test]
    fn an_offer_is_admitted_only_after_consent_and_only_once() {
        let mut s = fixture();
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        assert!(s.admit_offer().is_err(), "before consent");
        assert!(
            !s.offer_seen,
            "a refused offer does not stand the reaper down"
        );
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        assert!(s.admit_offer().is_err(), "a second offer");
        s.transition(SessionPhase::Active).unwrap();
        assert!(s.admit_offer().is_err(), "a re-offer on a live session");
    }
}

/// Immutable identity and service ceiling of a shared-device session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceShareSessionScope {
    pub grant_id: ObjectId,
    pub ceiling: Permissions,
}
#[cfg(test)]
mod device_share_scope_tests {
    use super::*;
    #[test]
    fn device_share_ceiling_blocks_immediate_permission_elevation_and_scope_rebinding() {
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        let (mut s, _waiter) = LiveSession::new(
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            Permissions::VIEW,
            tx,
        );
        let scope = DeviceShareSessionScope {
            grant_id: ObjectId::new(),
            ceiling: Permissions::VIEW,
        };
        s.bind_device_share(scope).unwrap();
        s.set_permissions(Permissions::all());
        assert_eq!(s.permissions(), Permissions::VIEW);
        assert!(
            s.bind_device_share(DeviceShareSessionScope {
                grant_id: ObjectId::new(),
                ceiling: Permissions::all()
            })
            .is_err()
        );
        assert_eq!(s.device_share_scope(), Some(scope));
        assert!(s.claim_share_watch(scope.grant_id));
        assert!(!s.claim_share_watch(scope.grant_id));
    }
}
