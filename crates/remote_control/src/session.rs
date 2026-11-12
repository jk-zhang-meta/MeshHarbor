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
use crate::signaling::{FileChildDirection, LocalRelayDescriptor, ServerMsg};

/// Channel used to push messages to a connected client (agent or controller).
/// The WS layer owns the receiving half and forwards to the socket.
pub type ClientTx = mpsc::Sender<ServerMsg>;

/// Maximum concurrent download file-child reservations/connections per parent session.
pub const MAX_DOWNLOAD_FILE_CHILDREN: usize = 4;

/// Maximum concurrent upload file-child reservations/connections per parent session.
pub const MAX_UPLOAD_FILE_CHILDREN: usize = 8;

#[derive(PartialEq, Eq)]
enum FileChildState {
    Reserved,
    Active,
}

struct FileChild {
    transfer_id: String,
    direction: FileChildDirection,
    state: FileChildState,
}

/// Monotonic policy revision snapshot bound to a parent session's file-child
/// capability (`tenant.security_revision()` and `agent.access_policy_revision()`).
/// Both revisions must be strictly positive (`> 0`). Any mismatch, `None`, or
/// policy tightening irreversibly revokes file-child capability on the parent
/// session until a fresh parent session is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileChildPolicySnapshot {
    pub tenant_security_rev: i64,
    pub agent_access_policy_rev: i64,
}

impl FileChildPolicySnapshot {
    pub fn new(
        tenant_security_rev: Option<i64>,
        agent_access_policy_rev: Option<i64>,
    ) -> Option<Self> {
        let tenant_security_rev = tenant_security_rev.filter(|&r| r > 0)?;
        let agent_access_policy_rev = agent_access_policy_rev.filter(|&r| r > 0)?;
        Some(Self {
            tenant_security_rev,
            agent_access_policy_rev,
        })
    }
}

/// Server-internal creation context, never a wire DTO. `local_pdp` is a
/// privileged constructor for a caller that already verified a local user
/// and completed the actual session PDP. Absence of a scope does not grant it.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct FileChildControllerScope {
    local_pdp: bool,
    consent_mode: ConsentMode,
    external_attempt: Option<String>,
    override_applied: bool,
}

impl FileChildControllerScope {
    pub fn unknown(
        consent_mode: ConsentMode,
        external_attempt: Option<String>,
        override_applied: bool,
    ) -> Self {
        Self {
            local_pdp: false,
            consent_mode,
            external_attempt,
            override_applied,
        }
    }

    pub fn local_pdp(consent_mode: ConsentMode) -> Self {
        Self {
            local_pdp: matches!(consent_mode, ConsentMode::Auto | ConsentMode::Prompt),
            consent_mode,
            external_attempt: None,
            override_applied: false,
        }
    }
}

pub struct LiveSession {
    pub id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    permissions: Permissions,
    file_children_opted_in: bool,
    file_children_enabled: bool,
    file_child_upload_opted_in: bool,
    file_child_upload_enabled: bool,
    file_children_revoked: bool,
    file_child_revoke_pending_ack: bool,
    file_child_policy_snapshot: Option<FileChildPolicySnapshot>,
    file_child_watch_started: bool,
    // Frozen by construction, before Hub publication. No late consent or
    // capability update can upgrade an Unknown creation to local-PDP.
    file_child_controller_scope: FileChildControllerScope,
    // Reservations and admissions share four slots. Completion removes only
    // the exact active binding; transport close and authorization are not wired
    // to this bookkeeping yet, so production callers must remain disabled.
    file_children: HashMap<ObjectId, FileChild>,
    device_share_scope: Option<DeviceShareSessionScope>,
    share_watch_started: bool,
    shared_lease_epoch: Option<String>,
    // MeshHarbor — the share account a shared session's file operations run
    // as on the device, frozen with the lease (`SharedSessionLease::account`).
    shared_files_account: Option<String>,
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
    /// The share account this shared session's file operations run as.
    pub fn shared_files_account(&self) -> Option<&str> {
        self.shared_files_account.as_deref()
    }
    /// Freeze the share account into the session, once, before publication:
    /// only a share-bound session carries one, and a second, different value
    /// is refused, as a second lease epoch is.
    pub fn set_shared_files_account(&mut self, account: Option<String>) -> Result<()> {
        let Some(account) = account else {
            return Ok(());
        };
        if self.device_share_scope.is_none()
            || self
                .shared_files_account
                .as_ref()
                .is_some_and(|a| a != &account)
        {
            return Err(Error::PermissionDenied("immutable shared files account"));
        }
        self.shared_files_account = Some(account);
        Ok(())
    }
    pub fn permissions(&self) -> Permissions {
        self.permissions
    }
    /// Every future permission update must cross this ceiling; the field is private.
    /// Losing effective FILES invalidates child bookkeeping and negotiation.
    /// Callers must separately stop owned transports: clearing records is not
    /// evidence that a live connection has closed.
    pub fn set_permissions(&mut self, permissions: Permissions) {
        self.permissions = self
            .device_share_scope
            .map_or(permissions, |s| permissions & s.ceiling);
        if !self.permissions.contains(Permissions::FILES) {
            self.file_children_enabled = false;
            self.file_child_upload_enabled = false;
            self.file_children.clear();
        }
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
            file_children_opted_in: false,
            file_children_enabled: false,
            file_child_upload_opted_in: false,
            file_child_upload_enabled: false,
            file_children_revoked: false,
            file_child_revoke_pending_ack: false,
            file_child_policy_snapshot: None,
            file_child_watch_started: false,
            file_child_controller_scope: FileChildControllerScope::unknown(
                ConsentMode::Prompt,
                None,
                false,
            ),
            file_children: HashMap::new(),
            device_share_scope: None,
            share_watch_started: false,
            shared_lease_epoch: None,
            shared_files_account: None,
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

    /// The compatibility constructor above always remains Unknown. This
    /// server-only constructor consumes the trusted creator's frozen scope;
    /// it cannot modify an already published/coalesced session.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_controller_scope(
        id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        controller_user_id: ObjectId,
        permissions: Permissions,
        controller_tx: ClientTx,
        scope: FileChildControllerScope,
    ) -> (Self, crate::consent::ConsentWaiter) {
        let (mut session, waiter) = Self::new(
            id,
            agent_id,
            tenant_id,
            controller_user_id,
            permissions,
            controller_tx,
        );
        session.file_child_controller_scope = scope;
        (session, waiter)
    }

    #[doc(hidden)]
    pub fn matches_file_child_controller_scope(&self, scope: &FileChildControllerScope) -> bool {
        &self.file_child_controller_scope == scope
    }

    fn require_file_child_controller_source(&self) -> Result<()> {
        if !self.file_child_controller_scope.local_pdp || self.device_share_scope.is_some() {
            return Err(Error::PermissionDenied(
                "file child controller source unavailable",
            ));
        }
        Ok(())
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

    /// Explicit child capability gate; ordinary session creation leaves it off.
    /// This is not proof verification or permission to enable a production path.
    /// Disabling invalidates all child bookkeeping; callers must separately
    /// cancel the actual transports before considering them closed.
    /// Enabling without an active FILES grant cannot pre-arm future access.
    /// Once irreversibly revoked by a policy tightening or revision mismatch,
    /// child capability cannot be re-enabled on this parent session.
    pub fn set_file_children_opted_in(&mut self, opted_in: bool) {
        self.set_file_children_opted_in_for(FileChildDirection::Download, opted_in);
    }

    pub fn set_file_children_opted_in_for(
        &mut self,
        direction: FileChildDirection,
        opted_in: bool,
    ) {
        let allowed = opted_in && !self.file_children_revoked;
        match direction {
            FileChildDirection::Download => self.file_children_opted_in = allowed,
            FileChildDirection::Upload => self.file_child_upload_opted_in = allowed,
        }
    }

    pub fn is_file_children_opted_in(&self) -> bool {
        self.is_file_children_opted_in_for(FileChildDirection::Download)
    }

    pub fn is_file_children_opted_in_for(&self, direction: FileChildDirection) -> bool {
        !self.file_children_revoked
            && match direction {
                FileChildDirection::Download => self.file_children_opted_in,
                FileChildDirection::Upload => self.file_child_upload_opted_in,
            }
    }

    pub fn is_file_children_enabled(&self) -> bool {
        self.is_file_children_enabled_for(FileChildDirection::Download)
    }

    pub fn is_file_children_enabled_for(&self, direction: FileChildDirection) -> bool {
        !self.file_children_revoked
            && match direction {
                FileChildDirection::Download => self.file_children_enabled,
                FileChildDirection::Upload => self.file_child_upload_enabled,
            }
    }

    pub fn set_file_children_enabled(&mut self, enabled: bool) {
        self.set_file_children_enabled_for(FileChildDirection::Download, enabled);
    }

    pub fn set_file_children_enabled_for(&mut self, direction: FileChildDirection, enabled: bool) {
        if enabled && !self.file_children_revoked {
            self.set_file_children_opted_in_for(direction, true);
        }
        let next = enabled
            && !self.file_children_revoked
            && self.phase == SessionPhase::Active
            && self.permissions().contains(Permissions::FILES);
        match direction {
            FileChildDirection::Download => self.file_children_enabled = next,
            FileChildDirection::Upload => self.file_child_upload_enabled = next,
        }
        if !next {
            self.file_children.retain(|_, c| c.direction != direction);
            if self.file_children.is_empty() {
                self.file_child_watch_started = false;
            }
        }
    }

    pub fn is_any_file_children_opted_in_or_enabled(&self) -> bool {
        !self.file_children_revoked
            && (self.file_children_opted_in
                || self.file_children_enabled
                || self.file_child_upload_opted_in
                || self.file_child_upload_enabled)
    }

    pub fn is_file_children_revoked(&self) -> bool {
        self.file_children_revoked
    }

    pub fn is_file_child_revoke_pending_ack(&self) -> bool {
        self.file_child_revoke_pending_ack
    }

    pub fn file_child_policy_snapshot(&self) -> Option<FileChildPolicySnapshot> {
        self.file_child_policy_snapshot
    }

    /// Irreversibly revoke all file child capability (`download` and `upload`)
    /// on this parent session. Returns `true` when this call transitions the
    /// session into the revoked state (so the caller can push
    /// `rc:file.child.revoke` and arm the 5s fail-closed ACK timer once).
    pub fn revoke_file_children_irreversibly(&mut self) -> bool {
        let first_revocation = !self.file_children_revoked;
        self.file_children_revoked = true;
        self.file_children_opted_in = false;
        self.file_children_enabled = false;
        self.file_child_upload_opted_in = false;
        self.file_child_upload_enabled = false;
        self.file_child_watch_started = false;
        self.file_children.clear();
        if first_revocation {
            self.file_child_revoke_pending_ack = true;
        }
        first_revocation
    }

    /// Mark the agent's `rc:file.child.revoke_ack` as received.
    pub fn ack_file_child_revocation(&mut self) -> bool {
        let was_pending = self.file_child_revoke_pending_ack;
        self.file_child_revoke_pending_ack = false;
        was_pending
    }

    /// Seed the initial policy revision snapshot captured by the local-PDP
    /// `rc:session.request` gate while the parent session is still in
    /// `AwaitingConsent`. Does not enable child transports (which still
    /// requires `SessionPhase::Active` + `admit_file_child_policy_snapshot` on
    /// `rc:file.child.reserve`), and any policy revision change between
    /// `rc:session.request` and the first `rc:file.child.reserve` will mismatch
    /// this seeded snapshot and irreversibly revoke child capability.
    pub fn seed_file_child_policy_snapshot(&mut self, snapshot: FileChildPolicySnapshot) {
        if self.require_file_child_controller_source().is_ok()
            && !self.file_children_revoked
            && self.file_child_policy_snapshot.is_none()
            && self.permissions().contains(Permissions::FILES)
        {
            self.file_child_policy_snapshot = Some(snapshot);
        }
    }

    /// Bind the initial policy revision snapshot on first child admission or
    /// verify that a subsequent child reserve/offer still sees the exact same
    /// monotonic snapshot (`tenant.security_revision()` and
    /// `agent.access_policy_revision()`). Any `None` or revision change
    /// irreversibly revokes child capability for the rest of this parent session.
    pub fn verify_or_bind_file_child_policy_snapshot(
        &mut self,
        current: Option<FileChildPolicySnapshot>,
    ) -> Result<()> {
        self.require_file_child_controller_source()?;
        if self.file_children_revoked {
            return Err(Error::PermissionDenied(
                "file child transports revoked for this session",
            ));
        }
        if self.phase != SessionPhase::Active || !self.permissions().contains(Permissions::FILES) {
            self.revoke_file_children_irreversibly();
            return Err(Error::PermissionDenied(
                "file child parent session is not active with FILES permission",
            ));
        }
        let Some(snapshot) = current else {
            self.revoke_file_children_irreversibly();
            return Err(Error::PermissionDenied(
                "file child policy revision unavailable",
            ));
        };
        match self.file_child_policy_snapshot {
            None => {
                self.file_child_policy_snapshot = Some(snapshot);
                Ok(())
            }
            Some(bound) if bound == snapshot => Ok(()),
            Some(_) => {
                self.revoke_file_children_irreversibly();
                Err(Error::PermissionDenied(
                    "file child policy revision changed",
                ))
            }
        }
    }

    /// Whether this parent session currently holds any `Reserved` or `Active`
    /// download-only file child slot.
    pub fn has_file_children(&self) -> bool {
        !self.file_children.is_empty()
    }

    /// Claim the single background policy-revision watcher task for this parent
    /// session after a `FileChildPolicySnapshot` has been bound.
    pub fn claim_file_child_watch(&mut self) -> bool {
        if self.file_child_watch_started
            || self.file_children_revoked
            || self.file_child_policy_snapshot.is_none()
        {
            return false;
        }
        self.file_child_watch_started = true;
        true
    }

    /// Release the background policy-revision watcher claim when no `Reserved`
    /// or `Active` file-child slots remain on this parent session, so the
    /// watcher exits when idle and restarts on the next `reserve`.
    pub fn release_file_child_watch_if_idle(&mut self) -> bool {
        if self.file_children.is_empty() {
            self.file_child_watch_started = false;
            return true;
        }
        false
    }

    /// Check whether `(child_id, transfer_id)` is currently an active child
    /// slot on an unrevoked, active FILES parent session.
    pub fn has_active_file_child(&self, child_id: ObjectId, transfer_id: &str) -> bool {
        !self.file_children_revoked
            && self.phase == SessionPhase::Active
            && self.permissions().contains(Permissions::FILES)
            && self.file_children.get(&child_id).is_some_and(|c| {
                c.transfer_id == transfer_id
                    && c.state == FileChildState::Active
                    && self.is_file_children_enabled_for(c.direction)
            })
    }

    /// Reserve a server-chosen child ID for this parent's download transfer.
    /// For direction-parameterized reservations (`download` or `upload`), see
    /// [`Self::reserve_file_child_for_direction`].
    pub fn reserve_file_child(&mut self, transfer_id: &str) -> Result<ObjectId> {
        self.reserve_file_child_for_direction(transfer_id, FileChildDirection::Download)
    }

    /// Reserve a server-chosen child ID for this parent's transfer in
    /// `direction`. Reserved and active children are bounded per direction
    /// (`MAX_DOWNLOAD_FILE_CHILDREN` = 4 for download, `MAX_UPLOAD_FILE_CHILDREN` = 8
    /// for upload) across the parent session.
    pub fn reserve_file_child_for_direction(
        &mut self,
        transfer_id: &str,
        direction: FileChildDirection,
    ) -> Result<ObjectId> {
        use ring::rand::{SecureRandom, SystemRandom};

        self.require_file_child_controller_source()?;

        if self.file_children_revoked {
            return Err(Error::PermissionDenied(
                "file child transports revoked for this session",
            ));
        }
        if !self.is_file_children_enabled_for(direction) {
            return Err(Error::PermissionDenied(
                "file child transports are disabled",
            ));
        }
        if self.phase != SessionPhase::Active {
            return Err(Error::BadPhase(self.id.to_hex(), phase_name(self.phase)));
        }
        if !self.permissions().contains(Permissions::FILES) {
            return Err(Error::PermissionDenied("FILES permission is not granted"));
        }
        if transfer_id.is_empty()
            || transfer_id.len() > 128
            || transfer_id.chars().any(char::is_control)
        {
            return Err(Error::BadMessage("invalid file transfer ID"));
        }
        let max_children = match direction {
            FileChildDirection::Download => MAX_DOWNLOAD_FILE_CHILDREN,
            FileChildDirection::Upload => MAX_UPLOAD_FILE_CHILDREN,
        };
        let direction_count = self
            .file_children
            .values()
            .filter(|c| c.direction == direction)
            .count();
        if direction_count >= max_children {
            return Err(Error::PermissionDenied(
                "file child connection limit reached",
            ));
        }
        let mut bytes = [0u8; 12];
        SystemRandom::new().fill(&mut bytes).map_err(|_| {
            Error::PermissionDenied("file child reservation randomness unavailable")
        })?;
        let child_id = ObjectId::from_bytes(bytes);
        if self.file_children.contains_key(&child_id) {
            return Err(Error::PermissionDenied("file child reservation collision"));
        }
        self.file_children.insert(
            child_id,
            FileChild {
                transfer_id: transfer_id.to_string(),
                direction,
                state: FileChildState::Reserved,
            },
        );
        Ok(child_id)
    }

    /// Download child transports have separate admission from the ordinary
    /// remote-control offer. Only an explicitly enabled, active FILES parent
    /// passes this gate. Only a matching server reservation may become Active,
    /// once. Reserved and active children share four slots, including distinct
    /// children of the same transfer.
    pub fn admit_file_child(&mut self, child_id: ObjectId, transfer_id: &str) -> Result<()> {
        self.admit_file_child_for_direction(child_id, transfer_id, FileChildDirection::Download)
    }

    pub fn admit_file_child_for_direction(
        &mut self,
        child_id: ObjectId,
        transfer_id: &str,
        direction: FileChildDirection,
    ) -> Result<()> {
        self.reserved_file_child_for_direction_mut(child_id, transfer_id, direction)?
            .state = FileChildState::Active;
        Ok(())
    }

    fn reserved_file_child_for_direction_mut(
        &mut self,
        child_id: ObjectId,
        transfer_id: &str,
        direction: FileChildDirection,
    ) -> Result<&mut FileChild> {
        self.require_file_child_controller_source()?;
        if self.file_children_revoked {
            return Err(Error::PermissionDenied(
                "file child transports revoked for this session",
            ));
        }
        if !self.is_file_children_enabled_for(direction) {
            return Err(Error::PermissionDenied(
                "file child transports are disabled",
            ));
        }
        if self.phase != SessionPhase::Active {
            return Err(Error::BadPhase(self.id.to_hex(), phase_name(self.phase)));
        }
        if !self.permissions().contains(Permissions::FILES) {
            return Err(Error::PermissionDenied("FILES permission is not granted"));
        }
        let child = self
            .file_children
            .get_mut(&child_id)
            .ok_or(Error::PermissionDenied("file child has no reservation"))?;
        if child.transfer_id != transfer_id {
            return Err(Error::PermissionDenied("file child transfer mismatch"));
        }
        if child.direction != direction {
            return Err(Error::PermissionDenied("file child direction mismatch"));
        }
        if child.state != FileChildState::Reserved {
            return Err(Error::PermissionDenied("file child ID already admitted"));
        }
        Ok(child)
    }

    /// The caller holds the parent lock. `enqueue` must return Err only if
    /// nothing was queued (the Hub uses exactly one bounded try_send).
    /// Validate before calling it, then commit using this same child borrow:
    /// a successful enqueue has no second fallible admission/lookup afterward.
    pub fn enqueue_file_child_offer<F>(
        &mut self,
        child_id: ObjectId,
        transfer_id: &str,
        enqueue: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        self.enqueue_file_child_offer_for_direction(
            child_id,
            transfer_id,
            FileChildDirection::Download,
            enqueue,
        )
    }

    pub fn enqueue_file_child_offer_for_direction<F>(
        &mut self,
        child_id: ObjectId,
        transfer_id: &str,
        direction: FileChildDirection,
        enqueue: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let child = self.reserved_file_child_for_direction_mut(child_id, transfer_id, direction)?;
        match enqueue() {
            Ok(()) => {
                child.state = FileChildState::Active;
                Ok(())
            }
            Err(error) => {
                // Still the exact Reserved entry validated above: no await or
                // externally writable child state exists during this callback.
                self.file_children.remove(&child_id);
                Err(error)
            }
        }
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn file_child_local_pdp_for_tests(&self) -> bool {
        self.require_file_child_controller_source().is_ok()
    }

    /// Roll back only the exact Reserved binding when its reply cannot be
    /// delivered. Never release an Active child or a different transfer. The
    /// caller holds the parent state lock across allocation, send and rollback.
    pub fn cancel_file_child_reservation(
        &mut self,
        child_id: ObjectId,
        transfer_id: &str,
    ) -> Result<()> {
        let child = self
            .file_children
            .get(&child_id)
            .ok_or(Error::PermissionDenied("file child has no reservation"))?;
        if child.transfer_id != transfer_id || child.state != FileChildState::Reserved {
            return Err(Error::PermissionDenied("file child reservation mismatch"));
        }
        self.file_children.remove(&child_id);
        Ok(())
    }

    /// Read-only admission inspection for this crate and downstream tests.
    /// `Some(false)` is Reserved, `Some(true)` is Active; neither proves that
    /// an agent received a message or that any transport exists.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn file_child_active_for_tests(
        &self,
        child_id: ObjectId,
        transfer_id: &str,
    ) -> Option<bool> {
        self.file_children
            .get(&child_id)
            .filter(|child| child.transfer_id == transfer_id)
            .map(|child| child.state == FileChildState::Active)
    }

    /// Release only the exact active binding, after the caller has closed its
    /// transport. This neither closes a connection nor authenticates a caller.
    /// The old offer then has no reservation to consume; no tombstones grow
    /// with the parent's lifetime. Fresh random IDs still have a theoretical
    /// collision risk and must not be advertised as mathematically unique.
    pub fn complete_file_child(&mut self, child_id: ObjectId, transfer_id: &str) -> Result<()> {
        let child = self
            .file_children
            .get(&child_id)
            .ok_or(Error::PermissionDenied("file child has no reservation"))?;
        if child.transfer_id != transfer_id {
            return Err(Error::PermissionDenied("file child transfer mismatch"));
        }
        if child.state != FileChildState::Active {
            return Err(Error::PermissionDenied("file child is not active"));
        }
        self.file_children.remove(&child_id);
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
        let (s, _) = LiveSession::new_with_controller_scope(
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            Permissions::default(),
            tx,
            FileChildControllerScope::local_pdp(ConsentMode::Prompt),
        );
        s
    }

    #[test]
    fn file_child_unknown_and_remote_consent_sources_cannot_inherit_capability() {
        for scope in [
            FileChildControllerScope::unknown(ConsentMode::Prompt, None, false),
            FileChildControllerScope::unknown(
                ConsentMode::Prompt,
                Some("synthetic-attempt".into()),
                false,
            ),
            FileChildControllerScope::unknown(ConsentMode::Auto, None, true),
            FileChildControllerScope::local_pdp(ConsentMode::Email),
            FileChildControllerScope::local_pdp(ConsentMode::Push),
            FileChildControllerScope::local_pdp(ConsentMode::PromptThenEmail),
        ] {
            let (tx, _rx) = mpsc::channel(8);
            let (mut session, _waiter) = LiveSession::new_with_controller_scope(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                Permissions::VIEW | Permissions::FILES,
                tx,
                scope,
            );
            session.phase = SessionPhase::Active;
            session.set_file_children_enabled(true);
            assert!(!session.file_child_local_pdp_for_tests());
            assert!(session.reserve_file_child("download").is_err());
        }
        let (tx, _rx) = mpsc::channel(8);
        let (mut legacy, _waiter) = LiveSession::new(
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            Permissions::VIEW | Permissions::FILES,
            tx,
        );
        legacy.phase = SessionPhase::Active;
        legacy.set_file_children_enabled(true);
        assert!(legacy.reserve_file_child("legacy").is_err());
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
    fn file_child_download_is_denied_by_default_even_for_active_files_session() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();

        assert!(s.permissions().contains(Permissions::FILES));
        assert!(matches!(
            s.admit_file_child(ObjectId::new(), "download-test"),
            Err(Error::PermissionDenied(_))
        ));
        assert_eq!(s.phase, SessionPhase::Active);
        assert!(s.offer_seen, "the authorized ordinary offer remains intact");
    }

    #[test]
    fn explicitly_enabled_active_files_session_admits_a_download_child() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let child = s.reserve_file_child("download-test").unwrap();
        assert!(
            s.admit_file_child(child, "download-test").is_ok(),
            "explicit child capability on an active FILES parent must admit its first child"
        );
        assert_eq!(s.phase, SessionPhase::Active);
        assert!(
            s.offer_seen,
            "child admission must preserve the ordinary offer"
        );
    }

    #[test]
    fn file_child_id_cannot_be_readmitted_even_for_another_transfer() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);
        let child = s.reserve_file_child("download-test").unwrap();
        s.admit_file_child(child, "download-test").unwrap();

        for transfer in ["download-test", "another-transfer"] {
            assert!(
                s.admit_file_child(child, transfer).is_err(),
                "an admitted child ID must not be replayed or rebound to another transfer"
            );
        }
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn one_download_transfer_admits_four_active_children_but_not_a_fifth() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        for _ in 0..4 {
            let child = s.reserve_file_child("download-test").unwrap();
            s.admit_file_child(child, "download-test")
                .expect("four distinct child transports may stripe the same download");
        }
        // None has closed: the budget is for simultaneously active children,
        // not a lifetime limit on files downloaded through the parent session.
        assert!(
            s.reserve_file_child("download-test").is_err(),
            "a fifth simultaneous child must not exceed the active connection budget"
        );
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn file_child_reservations_issue_distinct_server_ids_within_the_parent_budget() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let mut children = Vec::new();
        for _ in 0..4 {
            let child = s
                .reserve_file_child("download-test")
                .expect("an authorized parent must issue a child reservation");
            assert!(
                !children.contains(&child),
                "simultaneous reservations must have distinct server-issued IDs"
            );
            children.push(child);
        }
        assert!(
            s.reserve_file_child("another-transfer").is_err(),
            "reservations share the parent's four-child connection budget"
        );
        assert_eq!(s.phase, SessionPhase::Active);
        // Distinct IDs here are an observable contract, not a statistical
        // claim of randomness or proof that future collisions are impossible.
    }

    #[test]
    fn file_child_admission_requires_and_consumes_a_matching_reservation() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        assert!(
            s.admit_file_child(ObjectId::new(), "download-test")
                .is_err(),
            "a client-chosen child ID must not bypass reservation"
        );
        let child = s.reserve_file_child("download-test").unwrap();
        assert!(
            s.admit_file_child(child, "another-transfer").is_err(),
            "a reservation must not be rebound to another file"
        );
        s.admit_file_child(child, "download-test")
            .expect("a rejected mismatch must leave the matching reservation usable");
        assert!(
            s.admit_file_child(child, "download-test").is_err(),
            "the matching reservation may be admitted only once"
        );
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn completed_file_child_releases_a_slot_without_readmitting_the_old_id() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let mut children = Vec::new();
        for _ in 0..4 {
            let child = s.reserve_file_child("download-test").unwrap();
            s.admit_file_child(child, "download-test").unwrap();
            children.push(child);
        }
        let completed = children[0];
        s.complete_file_child(completed, "download-test")
            .expect("a matching completion must release its active child slot");
        let replacement = s
            .reserve_file_child("another-transfer")
            .expect("a completed child must leave room for another download");
        assert_ne!(replacement, completed);
        s.admit_file_child(replacement, "another-transfer").unwrap();
        assert!(
            s.admit_file_child(completed, "download-test").is_err(),
            "a completed child's old offer must have no reservation to consume"
        );
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn invalid_file_child_completion_cannot_release_active_or_reserved_budget() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let mut children = Vec::new();
        for _ in 0..4 {
            let child = s.reserve_file_child("download-test").unwrap();
            s.admit_file_child(child, "download-test").unwrap();
            children.push(child);
        }
        assert!(
            s.complete_file_child(children[0], "wrong-transfer")
                .is_err()
        );
        assert!(
            s.reserve_file_child("overflow-transfer").is_err(),
            "a completion with the wrong transfer must not release an active slot"
        );
        let unknown = ObjectId::new();
        assert!(!children.contains(&unknown));
        assert!(s.complete_file_child(unknown, "download-test").is_err());
        assert!(
            s.reserve_file_child("overflow-transfer").is_err(),
            "an unknown completion must not release another child's slot"
        );

        // Replace one legitimately completed child with a reservation, keeping
        // the same full four-slot budget without admitting that reservation.
        s.complete_file_child(children[0], "download-test").unwrap();
        let reserved = s.reserve_file_child("pending-transfer").unwrap();
        assert!(s.complete_file_child(reserved, "pending-transfer").is_err());
        assert!(
            s.reserve_file_child("overflow-transfer").is_err(),
            "an unadmitted reservation must not be released as a completed connection"
        );
        s.admit_file_child(reserved, "pending-transfer")
            .expect("a refused completion must leave the reservation intact");
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn cancelling_a_reservation_releases_only_the_matching_reserved_slot() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);
        let active = s.reserve_file_child("active").unwrap();
        s.admit_file_child(active, "active").unwrap();
        let reserved = s.reserve_file_child("reserved").unwrap();
        let retained = s.reserve_file_child("retained").unwrap();
        s.reserve_file_child("fourth").unwrap();

        assert!(
            s.cancel_file_child_reservation(active, "active").is_err(),
            "reservation cancellation must never free an Active child"
        );
        assert!(
            s.cancel_file_child_reservation(reserved, "wrong-transfer")
                .is_err()
        );
        assert!(
            s.cancel_file_child_reservation(ObjectId::new(), "reserved")
                .is_err()
        );
        assert!(
            s.reserve_file_child("overflow-after-refusals").is_err(),
            "failed cancellation must not change the four-slot budget"
        );

        let cancelled = s.cancel_file_child_reservation(reserved, "reserved");
        assert!(
            cancelled.is_ok(),
            "matching Reserved cancellation must release exactly its slot: {cancelled:?}"
        );
        assert!(s.admit_file_child(reserved, "reserved").is_err());
        assert!(s.complete_file_child(reserved, "reserved").is_err());
        s.reserve_file_child("replacement").unwrap();
        assert!(s.reserve_file_child("fifth").is_err());
        s.complete_file_child(active, "active").unwrap();
        s.admit_file_child(retained, "retained").unwrap();
        assert!(
            s.cancel_file_child_reservation(retained, "retained")
                .is_err()
        );
    }

    #[test]
    fn revoking_files_invalidates_children_and_requires_fresh_capability_negotiation() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);
        let active = s.reserve_file_child("active-before-revoke").unwrap();
        s.admit_file_child(active, "active-before-revoke").unwrap();
        let reserved = s.reserve_file_child("reserved-before-revoke").unwrap();

        s.set_permissions(Permissions::VIEW);
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        assert!(
            s.reserve_file_child("after-restore").is_err(),
            "restoring FILES must not silently restore the old child capability"
        );

        s.set_file_children_enabled(true);
        for (child, transfer) in [
            (active, "active-before-revoke"),
            (reserved, "reserved-before-revoke"),
        ] {
            assert!(
                s.admit_file_child(child, transfer).is_err(),
                "renegotiation must not revive a pre-revocation reservation or offer"
            );
            assert!(
                s.complete_file_child(child, transfer).is_err(),
                "a pre-revocation transfer must have no remaining active record"
            );
        }
        let fresh = s.reserve_file_child("after-renegotiation").unwrap();
        s.admit_file_child(fresh, "after-renegotiation").unwrap();
        assert_eq!(s.phase, SessionPhase::Active);
        // This proves session bookkeeping only, not cancellation of a live
        // transport, which requires a separate integration oracle.
    }

    #[test]
    fn disabling_file_children_invalidates_slots_before_explicit_reenable() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);
        let active = s.reserve_file_child("active-before-disable").unwrap();
        s.admit_file_child(active, "active-before-disable").unwrap();
        let reserved = s.reserve_file_child("reserved-before-disable").unwrap();

        s.set_file_children_enabled(false);
        s.set_file_children_enabled(true);
        for (child, transfer) in [
            (active, "active-before-disable"),
            (reserved, "reserved-before-disable"),
        ] {
            assert!(
                s.admit_file_child(child, transfer).is_err(),
                "reenabling must not resurrect a disabled child reservation"
            );
            assert!(
                s.complete_file_child(child, transfer).is_err(),
                "reenabling must not retain a disabled active child record"
            );
        }
        for _ in 0..4 {
            s.reserve_file_child("after-renegotiation")
                .expect("explicit renegotiation must have the full fresh four-slot budget");
        }
        assert_eq!(s.phase, SessionPhase::Active);
        assert!(s.permissions().contains(Permissions::FILES));
        // Session bookkeeping only: no live transport is created or closed.
    }

    #[test]
    fn file_child_capability_cannot_be_prearmed_without_effective_files_permission() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        assert!(!s.permissions().contains(Permissions::FILES));

        s.set_file_children_enabled(true);
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        assert!(
            s.reserve_file_child("after-files-grant").is_err(),
            "a capability requested without FILES must not silently activate after authorization"
        );

        s.set_file_children_enabled(true);
        s.reserve_file_child("after-explicit-negotiation")
            .expect("an authorized parent may explicitly negotiate a fresh child capability");
        assert_eq!(s.phase, SessionPhase::Active);
    }

    #[test]
    fn policy_revision_mismatch_irreversibly_revokes_file_child_capability_for_session_lifetime() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let initial_snapshot = FileChildPolicySnapshot::new(Some(3), Some(5)).unwrap();
        s.verify_or_bind_file_child_policy_snapshot(Some(initial_snapshot))
            .expect("initial positive policy revisions must bind cleanly");
        assert_eq!(s.file_child_policy_snapshot(), Some(initial_snapshot));

        let child = s.reserve_file_child("before-aba").unwrap();
        s.admit_file_child(child, "before-aba").unwrap();
        assert!(s.has_active_file_child(child, "before-aba"));

        // Simulate On -> Ask -> On ABA where tenant security_rev advances from 3 to 5:
        let aba_snapshot = FileChildPolicySnapshot::new(Some(5), Some(5));
        assert!(
            s.verify_or_bind_file_child_policy_snapshot(aba_snapshot)
                .is_err(),
            "revision advancement must invalidate the bound child snapshot"
        );
        assert!(s.is_file_children_revoked());
        assert!(s.is_file_child_revoke_pending_ack());
        assert!(!s.has_active_file_child(child, "before-aba"));

        // Even if the caller tries to re-enable or revert to the old snapshot,
        // the parent session's child capability stays irreversibly revoked.
        s.set_file_children_enabled(true);
        assert!(s.reserve_file_child("after-revoke").is_err());
        assert!(
            s.verify_or_bind_file_child_policy_snapshot(Some(initial_snapshot))
                .is_err()
        );
        assert!(s.ack_file_child_revocation());
        assert!(!s.is_file_child_revoke_pending_ack());
        assert_eq!(
            s.phase,
            SessionPhase::Active,
            "parent RC session remains active once revocation is acknowledged"
        );
    }

    #[test]
    fn missing_or_nonpositive_policy_revisions_fail_closed_and_revoke() {
        for (t_rev, a_rev) in [
            (None, Some(1)),
            (Some(1), None),
            (Some(0), Some(1)),
            (Some(1), Some(-1)),
        ] {
            assert!(FileChildPolicySnapshot::new(t_rev, a_rev).is_none());
        }
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        assert!(s.verify_or_bind_file_child_policy_snapshot(None).is_err());
        assert!(s.is_file_children_revoked());
        assert!(s.reserve_file_child("denied").is_err());
    }

    #[test]
    fn file_child_watch_exits_when_idle_and_reclaims_on_next_reserve() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled(true);

        let snap = FileChildPolicySnapshot::new(Some(2), Some(3)).unwrap();
        s.verify_or_bind_file_child_policy_snapshot(Some(snap))
            .unwrap();
        assert!(s.claim_file_child_watch());
        assert!(!s.claim_file_child_watch());

        let child1 = s.reserve_file_child("batch-1").unwrap();
        s.admit_file_child(child1, "batch-1").unwrap();
        assert!(s.has_file_children());
        assert!(
            !s.release_file_child_watch_if_idle(),
            "watcher must remain claimed while a child slot is Reserved or Active"
        );

        s.complete_file_child(child1, "batch-1").unwrap();
        assert!(!s.has_file_children());
        assert!(
            s.release_file_child_watch_if_idle(),
            "watcher must release once no Reserved/Active children remain"
        );
        // Bound snapshot remains pinned across idle periods; next reserve re-claims the watcher.
        assert_eq!(s.file_child_policy_snapshot(), Some(snap));
        s.verify_or_bind_file_child_policy_snapshot(Some(snap))
            .unwrap();
        assert!(
            s.claim_file_child_watch(),
            "next reserve after idle release must re-claim the watcher"
        );
    }

    #[test]
    fn seed_file_child_policy_snapshot_in_awaiting_consent_preserves_session_and_detects_drift() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();

        let snap1 = FileChildPolicySnapshot::new(Some(1), Some(1)).unwrap();
        s.seed_file_child_policy_snapshot(snap1);
        assert!(
            !s.is_file_children_revoked(),
            "seeding the initial snapshot during AwaitingConsent must not revoke child capability"
        );
        assert_eq!(s.file_child_policy_snapshot(), Some(snap1));

        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();

        // Matching snapshot once Active succeeds and allows enabling child slots.
        s.verify_or_bind_file_child_policy_snapshot(Some(snap1))
            .unwrap();
        s.set_file_children_enabled(true);
        let child = s.reserve_file_child("after-consent").unwrap();
        s.admit_file_child(child, "after-consent").unwrap();

        // Policy drift while AwaitingConsent is caught on the first Active check.
        let mut s2 = fixture();
        s2.set_permissions(Permissions::VIEW | Permissions::FILES);
        s2.transition(SessionPhase::AwaitingConsent).unwrap();
        s2.seed_file_child_policy_snapshot(snap1);
        s2.transition(SessionPhase::Negotiating).unwrap();
        s2.admit_offer().unwrap();
        s2.transition(SessionPhase::Active).unwrap();

        let snap2 = FileChildPolicySnapshot::new(Some(2), Some(1)).unwrap();
        assert!(
            s2.verify_or_bind_file_child_policy_snapshot(Some(snap2))
                .is_err()
        );
        assert!(s2.is_file_children_revoked());
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

    #[test]
    fn file_child_upload_is_denied_by_default_and_isolated_from_download_capability() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();

        // Both directions are OFF by default.
        assert!(
            s.reserve_file_child_for_direction("dl-0", FileChildDirection::Download)
                .is_err()
        );
        assert!(
            s.reserve_file_child_for_direction("up-0", FileChildDirection::Upload)
                .is_err()
        );

        // Enabling download ONLY does not enable upload.
        s.set_file_children_enabled_for(FileChildDirection::Download, true);
        let dl_child = s
            .reserve_file_child_for_direction("dl-1", FileChildDirection::Download)
            .expect("download enabled");
        assert!(
            s.reserve_file_child_for_direction("up-1", FileChildDirection::Upload)
                .is_err(),
            "upload must remain disabled when only download is enabled"
        );
        assert!(
            s.admit_file_child_for_direction(dl_child, "dl-1", FileChildDirection::Upload)
                .is_err(),
            "a download reservation must not be admitted as upload"
        );
        s.admit_file_child_for_direction(dl_child, "dl-1", FileChildDirection::Download)
            .unwrap();

        // Enable upload alongside download.
        s.set_file_children_enabled_for(FileChildDirection::Upload, true);
        let up_child = s
            .reserve_file_child_for_direction("up-1", FileChildDirection::Upload)
            .expect("upload enabled");
        assert!(
            s.admit_file_child_for_direction(up_child, "up-1", FileChildDirection::Download)
                .is_err(),
            "an upload reservation must not be admitted as download"
        );
        s.admit_file_child_for_direction(up_child, "up-1", FileChildDirection::Upload)
            .unwrap();
        assert!(s.has_active_file_child(dl_child, "dl-1"));
        assert!(s.has_active_file_child(up_child, "up-1"));

        // Disabling upload drops ONLY upload children; download child stays active.
        s.set_file_children_enabled_for(FileChildDirection::Upload, false);
        assert!(
            s.has_active_file_child(dl_child, "dl-1"),
            "disabling upload must not drop active download children"
        );
        assert!(
            !s.has_active_file_child(up_child, "up-1"),
            "disabling upload must drop active upload children"
        );
        assert!(
            s.reserve_file_child_for_direction("up-2", FileChildDirection::Upload)
                .is_err()
        );
        let dl_child_2 = s
            .reserve_file_child_for_direction("dl-2", FileChildDirection::Download)
            .expect("download still works after upload is disabled");
        s.admit_file_child_for_direction(dl_child_2, "dl-2", FileChildDirection::Download)
            .unwrap();
    }

    #[test]
    fn file_child_direction_limits_enforce_8_upload_and_4_download_independently() {
        let mut s = fixture();
        s.set_permissions(Permissions::VIEW | Permissions::FILES);
        s.transition(SessionPhase::AwaitingConsent).unwrap();
        s.transition(SessionPhase::Negotiating).unwrap();
        s.admit_offer().unwrap();
        s.transition(SessionPhase::Active).unwrap();
        s.set_file_children_enabled_for(FileChildDirection::Download, true);
        s.set_file_children_enabled_for(FileChildDirection::Upload, true);

        // Reserve and admit 8 upload children (up to MAX_UPLOAD_FILE_CHILDREN = 8).
        let mut up_children = Vec::new();
        for i in 0..MAX_UPLOAD_FILE_CHILDREN {
            let tid = format!("up-{i}");
            let cid = s
                .reserve_file_child_for_direction(&tid, FileChildDirection::Upload)
                .unwrap_or_else(|e| panic!("upload child {i} should succeed: {e:?}"));
            s.admit_file_child_for_direction(cid, &tid, FileChildDirection::Upload)
                .unwrap();
            up_children.push((cid, tid));
        }
        assert_eq!(up_children.len(), 8);

        // 9th upload child must be rejected with "file child connection limit reached".
        let ninth_up = s.reserve_file_child_for_direction("up-8", FileChildDirection::Upload);
        assert!(
            matches!(
                ninth_up,
                Err(Error::PermissionDenied(
                    "file child connection limit reached"
                ))
            ),
            "9th upload child must be rejected: {ninth_up:?}"
        );

        // Simultaneously reserve and admit 4 download children (MAX_DOWNLOAD_FILE_CHILDREN = 4)
        // while all 8 upload children are active.
        let mut dl_children = Vec::new();
        for i in 0..MAX_DOWNLOAD_FILE_CHILDREN {
            let tid = format!("dl-{i}");
            let cid = s
                .reserve_file_child_for_direction(&tid, FileChildDirection::Download)
                .unwrap_or_else(|e| {
                    panic!("download child {i} should succeed alongside 8 uploads: {e:?}")
                });
            s.admit_file_child_for_direction(cid, &tid, FileChildDirection::Download)
                .unwrap();
            dl_children.push((cid, tid));
        }
        assert_eq!(dl_children.len(), 4);

        // 5th download child must be rejected with "file child connection limit reached".
        let fifth_dl = s.reserve_file_child_for_direction("dl-4", FileChildDirection::Download);
        assert!(
            matches!(
                fifth_dl,
                Err(Error::PermissionDenied(
                    "file child connection limit reached"
                ))
            ),
            "5th download child must be rejected: {fifth_dl:?}"
        );

        // All 8 upload and 4 download children remain simultaneously active.
        for (cid, tid) in &up_children {
            assert!(s.has_active_file_child(*cid, tid));
        }
        for (cid, tid) in &dl_children {
            assert!(s.has_active_file_child(*cid, tid));
        }

        // Completing 1 download child does NOT allow a 9th upload child, but DOES allow a 4th download replacement.
        s.complete_file_child(dl_children[0].0, &dl_children[0].1)
            .unwrap();
        assert!(
            s.reserve_file_child_for_direction("up-still-full", FileChildDirection::Upload)
                .is_err()
        );
        let dl_replacement = s
            .reserve_file_child_for_direction("dl-repl", FileChildDirection::Download)
            .expect("completing 1 download slot frees 1 download slot");
        s.admit_file_child_for_direction(dl_replacement, "dl-repl", FileChildDirection::Download)
            .unwrap();
        assert!(
            s.reserve_file_child_for_direction("dl-overflow", FileChildDirection::Download)
                .is_err()
        );

        // Completing 1 upload child frees 1 upload slot while download remains at 4/4.
        s.complete_file_child(up_children[0].0, &up_children[0].1)
            .unwrap();
        let up_replacement = s
            .reserve_file_child_for_direction("up-repl", FileChildDirection::Upload)
            .expect("completing 1 upload slot frees 1 upload slot");
        s.admit_file_child_for_direction(up_replacement, "up-repl", FileChildDirection::Upload)
            .unwrap();
        assert!(
            s.reserve_file_child_for_direction("up-overflow", FileChildDirection::Upload)
                .is_err()
        );
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
