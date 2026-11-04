// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-3c — revocation: the vault takes a lease back, and tells the device
//! (`rc:vault.revoke`, one word from [`RevokeReason`]).
//!
//! | Why | Found by | Told |
//! |---|---|---|
//! | the session ended, or a stop was ordered | the device's pod, at its sweep | at that sweep |
//! | the session moved (another fence, another device) | the device's pod, at its sweep | at that sweep |
//! | the field has a newer version | the value's write | at once on the device's pod, else at that pod's sweep |
//! | the secret was disabled, or deleted | the change | at once on the device's pod, else at that pod's sweep |
//! | the device's vault key changed (its daemon restarted) | its next hello | at that hello |
//! | the device is being removed | `agent_removed`, before its row and socket go | at once |
//! | the organization is no longer served, or (P3-9-1) a person's lease and the vault no longer lends to its people | the device's pod, at its sweep or hello | at that sweep |
//! | P3-9-1 — a person's lease, and the device's row names another owner, or its owner is no longer a member | the device's pod, at its sweep or hello | at that sweep |
//!
//! A person's lease (`roomler connect`, [`crate::connect`]) names no
//! session: it stands on its owner instead, and on everything else a
//! session's lease stands on.
//!
//! Each pod looks after the devices CONNECTED TO IT: it holds their
//! connections (the lease socket's lifecycle) and sweeps those holding live
//! leases every `vault.revoke_sweep_secs`. Nothing crosses pods: a change
//! made on another pod is written to the lease's row at once, and the
//! device's own pod tells it at its next sweep.
//!
//! ⚠️ Hive must never call the vault (`vault → hive` in the graph), and a
//! session ends or moves on many paths (its device's report, a stop, a
//! purge, a promote, a teleport, a fork, its device's removal). So a session
//! is not followed: each sweep reads it again and asks whether every lease
//! still stands.
//!
//! ⚠️ No acknowledgement: every hello is told again of each revoked lease that
//! has not expired, so a frame lost to a pod roll or an offline device costs
//! a repeat, never a lease that outlives its revocation by more than its
//! TTL.
//!
//! ⚠️ A lease's expiry is its own revocation: an expired lease is never told,
//! and never revoked.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use bson::{DateTime, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_mod_hive::model::{AgentSession, SessionStatus};
use meshharbor_remote_control::{
    models::{Agent, RpcCap},
    signaling::ServerMsg,
    vault::{RevokeReason, lease_limits},
};
use meshharbor_services::dao::base::DaoError;
use meshharbor_core::{FleetLifecycle, ReleasedLease};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::VaultState;
use crate::lease::leasable;
use crate::model::{VaultAuditEvent, VaultLease, VaultSecret};
use crate::policy;

/// How often a pod checks its devices' leases when `vault.revoke_sweep_secs`
/// is 0 or absent.
pub const DEFAULT_SWEEP_SECS: u64 = 10;

/// The connection a device holds on THIS pod.
struct Link {
    conn_id: String,
    tx: mpsc::WeakSender<ServerMsg>,
    /// Whether the device's row advertises `vault` and holds a key: only
    /// then is it told, since an older build cannot read the frame. Learned
    /// when a lease is released to it or its leases are checked.
    capable: bool,
    /// The leases this connection has been told of. A hello starts empty, so
    /// each revoked lease not yet expired is told again.
    told: HashSet<ObjectId>,
}

/// What this pod knows for revocation: its devices' connections, and which
/// of them hold live leases.
#[derive(Default)]
pub struct Revoker {
    links: DashMap<ObjectId, Link>,
    /// The devices a sweep checks, each with a generation that a release
    /// raises: a sweep that found nothing live forgets a device only if no
    /// lease was released to it meanwhile.
    holders: DashMap<ObjectId, u64>,
}

impl Revoker {
    /// A device's connection on this pod, from its hello. A newer one
    /// replaces an older.
    pub fn link(&self, device: ObjectId, conn_id: &str, tx: mpsc::WeakSender<ServerMsg>) {
        self.links.insert(
            device,
            Link {
                conn_id: conn_id.to_string(),
                tx,
                capable: false,
                told: HashSet::new(),
            },
        );
    }

    /// The connection went: forget it, unless a newer one took its place.
    /// Its leases are checked again at the device's next hello, wherever it
    /// lands.
    pub fn unlink(&self, device: ObjectId, conn_id: &str) {
        if self
            .links
            .remove_if(&device, |_, l| l.conn_id == conn_id)
            .is_some()
        {
            self.holders.remove(&device);
        }
    }

    /// A lease was released on this pod to `device`, over a connection whose
    /// row advertised `vault` and held a key.
    pub fn hold(&self, device: ObjectId) {
        if let Some(mut l) = self.links.get_mut(&device) {
            l.capable = true;
        }
        *self.holders.entry(device).or_insert(0) += 1;
    }

    /// A device a check found holding a live lease: swept from now on.
    /// Unlike [`Self::hold`], says nothing of whether its row is capable.
    fn hold_checked(&self, device: ObjectId) {
        self.holders.entry(device).or_insert(0);
    }

    fn generation(&self, device: ObjectId) -> Option<u64> {
        self.holders.get(&device).map(|g| *g)
    }

    /// Forget a holder that a sweep found holding nothing live — unless a
    /// lease was released to it since the sweep read its generation.
    fn release_if_unchanged(&self, device: ObjectId, seen: u64) {
        self.holders.remove_if(&device, |_, g| *g == seen);
    }

    fn set_capable(&self, device: ObjectId, capable: bool) {
        if let Some(mut l) = self.links.get_mut(&device) {
            l.capable = capable;
        }
    }

    /// Tell the device's connection on this pod of the leases it has not
    /// been told of. Never waits: a full outbound queue leaves the rest for
    /// the next sweep.
    fn tell(&self, device: ObjectId, reason: &str, ids: &[ObjectId]) {
        let Some(mut link) = self.links.get_mut(&device) else {
            return;
        };
        if !link.capable {
            return;
        }
        let fresh: Vec<ObjectId> = ids
            .iter()
            .filter(|id| !link.told.contains(id))
            .copied()
            .collect();
        if fresh.is_empty() {
            return;
        }
        let Some(tx) = link.tx.upgrade() else {
            return;
        };
        for chunk in fresh.chunks(lease_limits::MAX_REVOKE_IDS) {
            let frame = ServerMsg::VaultRevoke {
                lease_ids: chunk.iter().map(|id| id.to_hex()).collect(),
                reason: reason.to_string(),
            };
            if tx.try_send(frame).is_err() {
                debug!(%device, "vault: a revocation waits for the next sweep — the connection's queue is full");
                return;
            }
            link.told.extend(chunk.iter().copied());
        }
    }
}

/// The session a lease names, as its record stands.
#[derive(Debug, Clone, Copy)]
pub struct SessionStanding {
    pub status: SessionStatus,
    pub fence: i64,
    pub device: ObjectId,
}

/// The secret a lease names, as its row stands.
#[derive(Debug, Clone, Copy)]
pub struct SecretStanding {
    pub deleted: bool,
    pub disabled: bool,
    /// Whether what the lease released has a newer version: its field's, or
    /// (P3-6b) for a bundle, any of the issuer's fields.
    pub changed: bool,
}

/// P3-9-1 — the owner a person's lease stands on, as the device's row and
/// the organization's members hold them now.
#[derive(Debug, Clone, Copy)]
pub struct OwnerStanding {
    /// The owner the device's row names.
    pub id: ObjectId,
    /// Whether they are a member of the organization.
    pub member: bool,
}

/// What a lease is checked against, read by the caller; `None` = gone.
#[derive(Debug, Clone, Copy)]
pub struct Standing<'a> {
    /// The vault serves the organization, and (P3-9-1) for a person's lease
    /// lends to its people.
    pub served: bool,
    /// The device row's vault key.
    pub device_key: Option<&'a str>,
    /// A session's lease: its session.
    pub session: Option<SessionStanding>,
    /// P3-9-1 — a person's lease: its owner.
    pub owner: Option<OwnerStanding>,
    pub secret: Option<SecretStanding>,
}

impl<'a> Standing<'a> {
    fn of(
        lease: &VaultLease,
        served: bool,
        device: Option<&'a Agent>,
        session: Option<&AgentSession>,
        owner: Option<OwnerStanding>,
        secret: Option<&VaultSecret>,
    ) -> Self {
        Self {
            served,
            device_key: device.map(|a| a.vault_key.as_str()),
            session: session.map(|s| SessionStanding {
                status: s.status,
                fence: s.fence,
                device: s.location.device_id,
            }),
            owner,
            secret: secret.map(|s| SecretStanding {
                deleted: s.deleted_at.is_some(),
                disabled: s.disabled,
                changed: changed(lease, s),
            }),
        }
    }
}

/// Whether what `lease` released has a newer version in `secret`: its
/// field's, or (P3-6b) for a bundle, any of the issuer's fields. Pure.
pub fn changed(lease: &VaultLease, secret: &VaultSecret) -> bool {
    match &lease.bundle {
        Some(bundle) => crate::dynamic::bundle_changed(
            bundle,
            crate::dynamic::provider_of(secret),
            &secret.fields,
        ),
        None => secret.fields.get(&lease.field).map(|f| f.current) != Some(lease.n),
    }
}

/// Why a live lease must go, or `None` while it stands. Pure.
pub fn verdict(lease: &VaultLease, s: &Standing<'_>) -> Option<RevokeReason> {
    if !s.served {
        return Some(RevokeReason::NotServed);
    }
    let Some(key) = s.device_key else {
        return Some(RevokeReason::DeviceRemoved);
    };
    if key != lease.sealed_to {
        return Some(RevokeReason::KeyChanged);
    }
    if lease.session_id.is_some() {
        let Some(session) = s.session.filter(|x| leasable(x.status)) else {
            return Some(RevokeReason::SessionEnded);
        };
        if session.fence != lease.fence || session.device != lease.device_id {
            return Some(RevokeReason::SessionMoved);
        }
    } else {
        // P3-9-1 — a person's lease: decided for the owner the device's row
        // named, who must still be the one it names, and still a member.
        let Some(owner) = s.owner.filter(|o| o.id == lease.owner_id) else {
            return Some(RevokeReason::OwnerChanged);
        };
        if !owner.member {
            return Some(RevokeReason::OwnerNotMember);
        }
    }
    let Some(secret) = s.secret.filter(|x| !x.deleted) else {
        return Some(RevokeReason::SecretDeleted);
    };
    if secret.disabled {
        return Some(RevokeReason::SecretDisabled);
    }
    if secret.changed {
        return Some(RevokeReason::ValueChanged);
    }
    None
}

/// One revocation, recorded. Best effort: the lease's row already says it
/// is revoked, and that row is what every check reads.
async fn record(state: &VaultState, lease: &VaultLease, why: RevokeReason) {
    let Some(id) = lease.id else { return };
    let event = VaultAuditEvent {
        id: None,
        tenant_id: lease.tenant_id,
        principal: "vault".into(),
        user_id: lease.owner_id,
        // P3-9-1 — the action the lease was decided under: a lease with no
        // session is a person's.
        action: match lease.session_id {
            Some(_) => policy::ACTION_USE,
            None => policy::ACTION_CONNECT,
        }
        .into(),
        op: "revoke".into(),
        decision: "revoke".into(),
        reason: why.wire().into(),
        secret_id: Some(lease.secret_id),
        rrn: None,
        field: Some(lease.field.clone()),
        n: Some(lease.n),
        target: Some(format!("lease:{}", id.to_hex())),
        session_id: lease.session_id,
        device_id: Some(lease.device_id),
        request: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(&event).await {
        warn!(lease = %id, %e, "vault: a revocation was not recorded");
    }
}

/// Take one lease back for `why`: `true` when this call did (the
/// compare-and-set it won), and then it is recorded.
async fn take_back(
    state: &VaultState,
    lease: &VaultLease,
    why: RevokeReason,
    at: DateTime,
) -> bool {
    let Some(id) = lease.id else { return false };
    match state.leases.revoke(id, why.wire(), at).await {
        Ok(true) => {
            record(state, lease, why).await;
            true
        }
        Ok(false) => false,
        Err(e) => {
            warn!(lease = %id, %e, "vault: a lease was not taken back — the next check tries again");
            false
        }
    }
}

/// Check one device's leases: take back each live one that no longer
/// stands, tell its connection on this pod of every revoked one it has not
/// been told of, and answer whether a live one remains.
pub async fn check_device(state: &VaultState, device: ObjectId) -> Result<bool, DaoError> {
    let now = DateTime::now();
    let mut leases = state.leases.unexpired_for_device(device, now).await?;
    let Some(tenant) = leases.first().map(|l| l.tenant_id) else {
        return Ok(false);
    };
    let row = match state.agents.find_live_in_tenant(tenant, device).await {
        Ok(a) => Some(a),
        Err(DaoError::NotFound) => None,
        Err(e) => return Err(e),
    };
    let capable = row
        .as_ref()
        .is_some_and(|a| a.capabilities.has_rpc(RpcCap::Vault) && !a.vault_key.is_empty());
    state.revoker.set_capable(device, capable);
    let served = state.scope.serves(tenant);
    // P3-9-1 — and a person's lease, only while the vault lends to the
    // organization's people.
    let people_served = served && state.people.serves(tenant);
    let mut sessions: HashMap<ObjectId, Option<AgentSession>> = HashMap::new();
    let mut secrets: HashMap<ObjectId, Option<VaultSecret>> = HashMap::new();
    // P3-9-1 — the owner a person's lease stands on, read once per check and
    // only when one is live.
    let mut owner: Option<Option<OwnerStanding>> = None;
    let mut live = false;
    for lease in leases.iter_mut().filter(|l| l.revoked_at.is_none()) {
        let session = match lease.session_id {
            Some(sid) => {
                if let Entry::Vacant(slot) = sessions.entry(sid) {
                    slot.insert(match state.sessions.find_in_tenant(tenant, sid).await {
                        Ok(s) => Some(s),
                        Err(DaoError::NotFound) => None,
                        Err(e) => return Err(e),
                    });
                }
                sessions[&sid].as_ref()
            }
            None => None,
        };
        let standing_owner = match (lease.session_id, owner) {
            (Some(_), _) => None,
            (None, Some(known)) => known,
            (None, None) => {
                let known = match row.as_ref() {
                    Some(a) => Some(OwnerStanding {
                        id: a.owner_user_id,
                        member: state.tenants.is_member(tenant, a.owner_user_id).await?,
                    }),
                    None => None,
                };
                owner = Some(known);
                known
            }
        };
        if let Entry::Vacant(slot) = secrets.entry(lease.secret_id) {
            slot.insert(state.secrets.find_any(tenant, lease.secret_id).await?);
        }
        let standing = Standing::of(
            lease,
            if lease.session_id.is_some() {
                served
            } else {
                people_served
            },
            row.as_ref(),
            session,
            standing_owner,
            secrets[&lease.secret_id].as_ref(),
        );
        let why = verdict(lease, &standing);
        match why {
            None => live = true,
            Some(why) => {
                take_back(state, lease, why, now).await;
                // Revoked now, whoever's write landed; told under the word
                // this check found.
                lease.revoked_at = Some(now);
                lease.revoked_why = Some(why.wire().to_string());
            }
        }
    }
    let mut by_reason: BTreeMap<&str, Vec<ObjectId>> = BTreeMap::new();
    for lease in &leases {
        if let (Some(id), Some(_)) = (lease.id, lease.revoked_at) {
            let why = lease.revoked_why.as_deref().unwrap_or("revoked");
            by_reason.entry(why).or_default().push(id);
        }
    }
    for (why, ids) in by_reason {
        state.revoker.tell(device, why, &ids);
    }
    Ok(live)
}

/// At a device's hello on this pod: check its leases, so its connection is
/// told of what it missed, and look after it while a live one remains.
pub async fn reconcile(state: VaultState, device: ObjectId) {
    match check_device(&state, device).await {
        Ok(true) => state.revoker.hold_checked(device),
        Ok(false) => {}
        Err(e) => {
            warn!(%device, %e, "vault: a device's leases were not checked at its hello — the next sweep does");
            state.revoker.hold_checked(device);
        }
    }
}

/// One pass over the devices on this pod that hold live leases.
pub async fn sweep_once(state: &VaultState) {
    let devices: Vec<ObjectId> = state.revoker.holders.iter().map(|e| *e.key()).collect();
    for device in devices {
        let Some(seen) = state.revoker.generation(device) else {
            continue;
        };
        match check_device(state, device).await {
            Ok(true) => {}
            Ok(false) => state.revoker.release_if_unchanged(device, seen),
            Err(e) => {
                warn!(%device, %e, "vault: a device's leases were not checked — the next sweep tries again")
            }
        }
    }
}

/// Every `period`, sweep this pod's devices. The first pass is a period
/// out: a booting pod has no leases released yet, and a hello reconciles
/// its own device.
pub fn spawn_sweeper(state: VaultState, period: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            sweep_once(&state).await;
        }
    });
}

/// A change to a secret: take back its live leases — one field's, when
/// given, and of that field only the versions before `newer_than` — and
/// tell the devices on this pod at once. A device on another pod is told
/// at that pod's next sweep, which finds the lease revoked.
pub async fn secret_changed(
    state: &VaultState,
    secret_id: ObjectId,
    field: Option<&str>,
    newer_than: Option<i64>,
    why: RevokeReason,
) {
    let now = DateTime::now();
    let leases = match state.leases.live_for_secret(secret_id, field, now).await {
        Ok(l) => l,
        Err(e) => {
            warn!(secret = %secret_id, %e, "vault: a changed secret's leases were not read — each device's next check takes them back");
            return;
        }
    };
    let mut by_device: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for lease in &leases {
        if newer_than.is_some_and(|n| lease.n >= n) {
            continue;
        }
        if take_back(state, lease, why, now).await
            && let Some(id) = lease.id
        {
            by_device.entry(lease.device_id).or_default().push(id);
        }
    }
    for (device, ids) in by_device {
        state.revoker.tell(device, why.wire(), &ids);
    }
}

/// The device is going: take back every live lease it holds, and tell it
/// while its socket is still there.
pub async fn device_removed(
    state: &VaultState,
    tenant: ObjectId,
    device: ObjectId,
) -> Result<(), DaoError> {
    let now = DateTime::now();
    let leases = state.leases.unexpired_for_device(device, now).await?;
    let mut ids = Vec::new();
    for lease in &leases {
        let Some(id) = lease.id else { continue };
        if lease.revoked_at.is_none() {
            take_back(state, lease, RevokeReason::DeviceRemoved, now).await;
        }
        ids.push(id);
    }
    if ids.is_empty() {
        return Ok(());
    }
    // Its row is still there (the hook runs before it goes): told only if it
    // can read the frame.
    if let Ok(row) = state.agents.find_live_in_tenant(tenant, device).await {
        state.revoker.set_capable(
            device,
            row.capabilities.has_rpc(RpcCap::Vault) && !row.vault_key.is_empty(),
        );
    }
    state
        .revoker
        .tell(device, RevokeReason::DeviceRemoved.wire(), &ids);
    Ok(())
}

/// The vault's place in fleet's removal cascade, after hive's in
/// `HOOK_ORDER`: a removed device's sessions have ended, and its leases go
/// next, while its row and socket are still there to tell it.
pub struct VaultFleetHooks {
    pub state: VaultState,
}

#[async_trait]
impl FleetLifecycle for VaultFleetHooks {
    /// ⚠️ A failure is logged, never the cascade's refusal: a device being
    /// removed — possibly a compromised one — must not stay because the
    /// vault could not write. What it holds expires within
    /// [`lease_limits::MAX_TTL_SECS`] whatever happens here.
    async fn agent_removed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        _machine_id: &str,
        _reason: &str,
    ) -> anyhow::Result<Option<ReleasedLease>> {
        if let Err(e) = device_removed(&self.state, tenant_id, agent_id).await {
            warn!(device = %agent_id, %e, "vault: a removed device's leases were not taken back — they expire on their own");
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> VaultLease {
        VaultLease {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            secret_id: ObjectId::new(),
            field: "value".into(),
            n: 3,
            bundle: None,
            session_id: Some(ObjectId::new()),
            fence: 2,
            device_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            sealed_to: "KEY".into(),
            mode: "env".into(),
            audience: String::new(),
            issued_at: DateTime::now(),
            expires_at: DateTime::now(),
            revoked_at: None,
            revoked_why: None,
        }
    }

    fn standing(l: &VaultLease) -> Standing<'static> {
        Standing {
            served: true,
            device_key: Some("KEY"),
            session: Some(SessionStanding {
                status: SessionStatus::Running,
                fence: l.fence,
                device: l.device_id,
            }),
            owner: None,
            secret: Some(SecretStanding {
                deleted: false,
                disabled: false,
                changed: false,
            }),
        }
    }

    /// Each way a lease stops standing has its own word.
    #[test]
    fn a_lease_stands_until_one_of_its_conditions_goes() {
        let l = lease();
        let ok = standing(&l);
        assert_eq!(verdict(&l, &ok), None);
        let session = ok.session.unwrap();
        let secret = ok.secret.unwrap();
        let cases = [
            (
                Standing {
                    served: false,
                    ..ok
                },
                RevokeReason::NotServed,
            ),
            (
                Standing {
                    device_key: None,
                    ..ok
                },
                RevokeReason::DeviceRemoved,
            ),
            (
                Standing {
                    device_key: Some("ANOTHER"),
                    ..ok
                },
                RevokeReason::KeyChanged,
            ),
            (
                Standing {
                    session: None,
                    ..ok
                },
                RevokeReason::SessionEnded,
            ),
            (
                Standing {
                    session: Some(SessionStanding {
                        fence: l.fence + 1,
                        ..session
                    }),
                    ..ok
                },
                RevokeReason::SessionMoved,
            ),
            (
                Standing {
                    session: Some(SessionStanding {
                        device: ObjectId::new(),
                        ..session
                    }),
                    ..ok
                },
                RevokeReason::SessionMoved,
            ),
            (Standing { secret: None, ..ok }, RevokeReason::SecretDeleted),
            (
                Standing {
                    secret: Some(SecretStanding {
                        deleted: true,
                        ..secret
                    }),
                    ..ok
                },
                RevokeReason::SecretDeleted,
            ),
            (
                Standing {
                    secret: Some(SecretStanding {
                        disabled: true,
                        ..secret
                    }),
                    ..ok
                },
                RevokeReason::SecretDisabled,
            ),
            (
                Standing {
                    secret: Some(SecretStanding {
                        changed: true,
                        ..secret
                    }),
                    ..ok
                },
                RevokeReason::ValueChanged,
            ),
        ];
        for (s, want) in cases {
            assert_eq!(verdict(&l, &s), Some(want), "{s:?}");
        }
    }

    /// A session is leased from its start until a stop is ordered, and its
    /// leases go with it.
    #[test]
    fn a_session_past_a_stop_takes_its_leases_with_it() {
        let l = lease();
        let ok = standing(&l);
        for (status, stands) in [
            (SessionStatus::Starting, true),
            (SessionStatus::Idle, true),
            (SessionStatus::Running, true),
            (SessionStatus::AwaitingApproval, true),
            (SessionStatus::Stopping, false),
            (SessionStatus::Ended, false),
            (SessionStatus::Refused, false),
            (SessionStatus::Lost, false),
        ] {
            let s = Standing {
                session: Some(SessionStanding {
                    status,
                    ..ok.session.unwrap()
                }),
                ..ok
            };
            let want = (!stands).then_some(RevokeReason::SessionEnded);
            assert_eq!(verdict(&l, &s), want, "{status:?}");
        }
    }

    /// P3-9-1 — a person's lease names no session and stands on its owner:
    /// the one the device's row names, still a member. No session is read
    /// for it, and a session's lease never reads an owner.
    #[test]
    fn a_persons_lease_stands_on_its_owner() {
        let l = VaultLease {
            session_id: None,
            fence: 0,
            mode: "proxy".into(),
            ..lease()
        };
        let owner = OwnerStanding {
            id: l.owner_id,
            member: true,
        };
        let ok = Standing {
            session: None,
            owner: Some(owner),
            ..standing(&l)
        };
        assert_eq!(verdict(&l, &ok), None);
        for (s, want) in [
            (
                Standing {
                    owner: Some(OwnerStanding {
                        id: ObjectId::new(),
                        ..owner
                    }),
                    ..ok
                },
                RevokeReason::OwnerChanged,
            ),
            (Standing { owner: None, ..ok }, RevokeReason::OwnerChanged),
            (
                Standing {
                    owner: Some(OwnerStanding {
                        member: false,
                        ..owner
                    }),
                    ..ok
                },
                RevokeReason::OwnerNotMember,
            ),
            (
                Standing {
                    served: false,
                    ..ok
                },
                RevokeReason::NotServed,
            ),
            (
                Standing {
                    device_key: Some("ANOTHER"),
                    ..ok
                },
                RevokeReason::KeyChanged,
            ),
            (
                Standing {
                    secret: Some(SecretStanding {
                        changed: true,
                        ..ok.secret.unwrap()
                    }),
                    ..ok
                },
                RevokeReason::ValueChanged,
            ),
        ] {
            assert_eq!(verdict(&l, &s), Some(want), "{s:?}");
        }
        // A session's lease is a session's whatever an owner reads.
        let session_lease = lease();
        let moved_owner = Standing {
            owner: Some(OwnerStanding {
                id: ObjectId::new(),
                member: false,
            }),
            ..standing(&session_lease)
        };
        assert_eq!(verdict(&session_lease, &moved_owner), None);
    }

    /// A device's connection is forgotten only by itself: the close of a
    /// displaced one leaves the connection that replaced it, and its holding.
    #[test]
    fn a_displaced_connection_does_not_unlink_its_successor() {
        let r = Revoker::default();
        let device = ObjectId::new();
        let (tx, _rx) = mpsc::channel(4);
        r.link(device, "old", tx.downgrade());
        r.link(device, "new", tx.downgrade());
        r.hold(device);
        r.unlink(device, "old");
        assert!(r.links.contains_key(&device));
        assert!(r.holders.contains_key(&device));
        r.unlink(device, "new");
        assert!(!r.links.contains_key(&device));
        assert!(!r.holders.contains_key(&device));
    }

    /// A sweep forgets a holder it found holding nothing live only if no
    /// lease was released to it meanwhile.
    #[test]
    fn a_release_during_a_sweep_keeps_the_device_swept() {
        let r = Revoker::default();
        let device = ObjectId::new();
        r.hold(device);
        let seen = r.generation(device).unwrap();
        r.hold(device);
        r.release_if_unchanged(device, seen);
        assert!(r.holders.contains_key(&device), "released to meanwhile");
        let seen = r.generation(device).unwrap();
        r.release_if_unchanged(device, seen);
        assert!(!r.holders.contains_key(&device));
    }

    /// A connection is told of each lease once, at most MAX_REVOKE_IDS a
    /// frame, and only when its row can read the frame.
    #[test]
    fn a_connection_is_told_once_in_bounded_frames_and_only_if_capable() {
        let r = Revoker::default();
        let device = ObjectId::new();
        let (tx, mut rx) = mpsc::channel(16);
        r.link(device, "c", tx.downgrade());
        let ids: Vec<ObjectId> = (0..lease_limits::MAX_REVOKE_IDS + 1)
            .map(|_| ObjectId::new())
            .collect();
        r.tell(device, "session_ended", &ids);
        assert!(rx.try_recv().is_err(), "not yet known to read the frame");
        r.set_capable(device, true);
        r.tell(device, "session_ended", &ids);
        let mut told = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            match frame {
                ServerMsg::VaultRevoke { lease_ids, reason } => {
                    assert_eq!(reason, "session_ended");
                    assert!(lease_ids.len() <= lease_limits::MAX_REVOKE_IDS);
                    told.extend(lease_ids);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(told.len(), ids.len());
        r.tell(device, "session_ended", &ids);
        assert!(rx.try_recv().is_err(), "told once");
    }
}
