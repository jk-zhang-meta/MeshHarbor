// SPDX-License-Identifier: AGPL-3.0-only
//! Private server-side facts for business-policy issuance. These records are
//! deliberately NOT fields of public Agent/TunnelClient documents or wire DTOs.
//! A captured origin, role approval and GeoIP lookup are observations, not a
//! signed grant. Runtime consumers must additionally verify the current live
//! authenticated connection, revocation/generation and complete actual path.

use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_remote_control::models::{Agent, AgentStatus, TunnelClient};
use mongodb::options::ReturnDocument;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, Core,
    client_ip::ConnectionOrigin,
    extractors::auth::AuthUser,
    user_analytics::{GeoIpDatasetIdentity, GeoIpSecurityLookup},
};

pub const ROLE_APPROVALS_COLLECTION: &str = "business_device_roles";
pub const OBSERVATIONS_COLLECTION: &str = "business_connection_observations";
pub const OBSERVATION_TTL_MILLIS: i64 = 60_000;
/// DB-IP Country Lite is released monthly. A database older than this is not
/// security evidence: zones fail closed until the image is rebuilt.
pub const MAX_GEOIP_DATASET_AGE_SECS: u64 = 120 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Agent,
    TunnelClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceUseRole {
    Unknown,
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessZone {
    Mainland,
    NonMainland,
}

/// Storage identity only. Deserializing it does not authenticate a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub kind: DeviceKind,
    pub tenant_id: ObjectId,
    pub device_id: ObjectId,
    pub machine_id: String,
    pub token_generation: u32,
}

/// Constructed from the current registered row after the socket owner validates
/// its credential/current admission. Private fields prevent direct wire derive.
/// Central-owner approval routes may also wrap a freshly loaded target row;
/// that establishes a target identity, never proof that it is connected.
#[derive(Debug, Clone)]
pub struct AuthenticatedDevice {
    identity: DeviceIdentity,
}

impl AuthenticatedDevice {
    pub fn from_agent(agent: &Agent) -> Result<Self, ApiError> {
        if agent.deleted_at.is_some() {
            return Err(ApiError::Conflict(
                "Device identity no longer current".into(),
            ));
        }
        Self::new(
            DeviceKind::Agent,
            agent.tenant_id,
            agent.id,
            &agent.machine_id,
            agent.token_gen,
        )
    }

    pub fn from_tunnel_client(client: &TunnelClient) -> Result<Self, ApiError> {
        if client.deleted_at.is_some() {
            return Err(ApiError::Conflict(
                "Device identity no longer current".into(),
            ));
        }
        Self::new(
            DeviceKind::TunnelClient,
            client.tenant_id,
            client.id,
            &client.machine_id,
            client.token_gen,
        )
    }

    fn new(
        kind: DeviceKind,
        tenant_id: ObjectId,
        device_id: Option<ObjectId>,
        machine_id: &str,
        token_generation: u32,
    ) -> Result<Self, ApiError> {
        let device_id =
            device_id.ok_or_else(|| ApiError::Conflict("Device identity missing".into()))?;
        if machine_id.is_empty()
            || machine_id.len() > 256
            || machine_id.chars().any(char::is_control)
        {
            return Err(ApiError::Conflict("Device machine identity invalid".into()));
        }
        Ok(Self {
            identity: DeviceIdentity {
                kind,
                tenant_id,
                device_id,
                machine_id: machine_id.into(),
                token_generation,
            },
        })
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            match self.identity.kind {
                DeviceKind::Agent => "agent",
                DeviceKind::TunnelClient => "tunnel_client",
            },
            self.identity.tenant_id,
            self.identity.device_id
        )
    }
}

/// Private central-owner record, never inferred from tags, OS, NodeRef::Agent
/// or a node's relay setting. Unknown is an explicit revocation/default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleApproval {
    #[serde(rename = "_id")]
    pub id: String,
    pub identity: DeviceIdentity,
    pub role: DeviceUseRole,
    pub approved_by: ObjectId,
    pub approved_at: DateTime,
    pub revision: i64,
    pub reason: String,
    pub revoked: bool,
}

impl RoleApproval {
    fn current_for(
        &self,
        device: &AuthenticatedDevice,
        owner: Option<ObjectId>,
        now: DateTime,
    ) -> bool {
        self.id == device.key()
            && self.identity == device.identity
            && owner == Some(self.approved_by)
            && self.approved_at <= now
            && self.revision > 0
            && !self.revoked
            && self.role != DeviceUseRole::Unknown
    }
}

/// Raw private persisted observation. No secrets, credential, XFF string, raw
/// headers or client-provided country/role are stored. No Serialize conversion
/// from this record into authority-bearing BusinessReachability inputs exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionObservation {
    #[serde(rename = "_id")]
    pub id: String,
    pub identity: DeviceIdentity,
    pub connection_id: String,
    pub captured_at: DateTime,
    pub recorded_at: DateTime,
    pub expires_at: DateTime,
    pub closed_at: Option<DateTime>,
    pub transport_peer_ip: Option<String>,
    pub client_ip: Option<String>,
    pub origin_source: String,
    pub country_code: Option<String>,
    pub zone: Option<BusinessZone>,
    pub dataset: Option<GeoIpDatasetIdentity>,
    pub role_at_capture: DeviceUseRole,
    pub role_revision_at_capture: Option<i64>,
}

impl ConnectionObservation {
    pub fn is_current_for(
        &self,
        device: &AuthenticatedDevice,
        connection_id: &str,
        now: DateTime,
    ) -> bool {
        let client = self
            .client_ip
            .as_deref()
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
        let peer = self
            .transport_peer_ip
            .as_deref()
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
        let coherent_source = match self.origin_source.as_str() {
            "socket_peer" => client.is_some() && client == peer,
            "trusted_proxy_chain" => client.is_some() && peer.is_some(),
            _ => false,
        };
        self.identity == device.identity
            && self.connection_id == connection_id
            && self.id == observation_key(device, connection_id)
            && self.closed_at.is_none()
            && self.captured_at <= now
            && self.recorded_at >= self.captured_at
            && self.recorded_at <= now
            && self.expires_at > now
            && self.expires_at.timestamp_millis()
                <= self
                    .captured_at
                    .timestamp_millis()
                    .saturating_add(OBSERVATION_TTL_MILLIS)
            && coherent_source
    }
}

/// The zone each live connection was observed in when it opened, keyed like
/// its observation row and held by THIS process. The row itself is deleted
/// 60 s after capture (TTL index on `expires_at`), while what it observed
/// stays true for the connection's life: a transport connection cannot change
/// its source address. Written only after the row is persisted, and dropped
/// when that connection's observation is closed.
#[derive(Clone, Default)]
pub struct LiveZones {
    map: std::sync::Arc<dashmap::DashMap<String, (DeviceIdentity, BusinessZone)>>,
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl LiveZones {
    fn get(&self, key: &str, device: &AuthenticatedDevice) -> Option<BusinessZone> {
        self.map
            .get(key)
            .filter(|e| e.0 == device.identity)
            .map(|e| e.1)
    }

    fn insert(&self, key: String, value: (DeviceIdentity, BusinessZone)) {
        self.map.insert(key, value);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    fn remove(&self, key: &str) {
        if self.map.remove(key).is_some() {
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Private operator surface only; never return this through ordinary/shared
/// device JSON. "Current" describes a bounded source observation, not access.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorityView {
    pub identity: DeviceIdentity,
    pub role_approval: Option<RoleApproval>,
    pub effective_role: DeviceUseRole,
    pub last_observation: Option<ConnectionObservation>,
    /// Newest still-open observation that is current right now, if any.
    pub current_observation: Option<ConnectionObservation>,
    pub observation_is_current: bool,
}

fn storage_error(_: mongodb::error::Error) -> ApiError {
    // Do not include private source addresses/documents in user-visible errors.
    ApiError::ServiceUnavailable("Business authority storage unavailable".into())
}

fn current_owner(core: &Core) -> Result<Option<ObjectId>, ApiError> {
    crate::admission::owner_id(&core.settings.auth.account_approval)
}

fn require_role_approver(
    policy: &meshharbor_config::AccountApprovalSettings,
    actor: ObjectId,
) -> Result<(), ApiError> {
    if crate::admission::owner_id(policy)? == Some(actor) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "Central approval owner required".into(),
        ))
    }
}

/// Re-reads the registration immediately before a write. `require_active`
/// additionally demands a non-quarantined device whose owner is still
/// admitted: quarantine and de-admission do not bump the token generation, so
/// identity equality alone would let such a device mint current evidence.
/// Revocation and diagnostics pass `false` so they keep working on those rows.
async fn verify_current_device(
    core: &Core,
    device: &AuthenticatedDevice,
    require_active: bool,
) -> Result<(), ApiError> {
    let filter = doc! { "_id": device.identity.device_id, "tenant_id": device.identity.tenant_id, "deleted_at": bson::Bson::Null };
    let actual = match device.identity.kind {
        DeviceKind::Agent => core
            .db
            .collection::<Agent>(Agent::COLLECTION)
            .find_one(filter)
            .await
            .map_err(storage_error)?
            .map(|row| {
                Ok::<_, ApiError>((
                    AuthenticatedDevice::from_agent(&row)?,
                    row.status,
                    row.owner_user_id,
                ))
            })
            .transpose()?,
        DeviceKind::TunnelClient => core
            .db
            .collection::<TunnelClient>(TunnelClient::COLLECTION)
            .find_one(filter)
            .await
            .map_err(storage_error)?
            .map(|row| {
                Ok::<_, ApiError>((
                    AuthenticatedDevice::from_tunnel_client(&row)?,
                    row.status,
                    row.owner_user_id,
                ))
            })
            .transpose()?,
    };
    let Some((_, status, owner)) = actual.filter(|(row, _, _)| row.identity == device.identity)
    else {
        return Err(ApiError::Conflict(
            "Device identity changed; reload current registration".into(),
        ));
    };
    if require_active {
        if matches!(status, AgentStatus::Quarantined) {
            return Err(ApiError::Conflict("Device is quarantined".into()));
        }
        crate::admission::authorize_user_id(core, owner, None).await?;
    }
    Ok(())
}

fn effective_role(
    approval: Option<&RoleApproval>,
    device: &AuthenticatedDevice,
    owner: Option<ObjectId>,
    now: DateTime,
) -> DeviceUseRole {
    approval
        .filter(|a| a.current_for(device, owner, now))
        .map(|a| a.role)
        .unwrap_or(DeviceUseRole::Unknown)
}

fn observation_key(device: &AuthenticatedDevice, connection_id: &str) -> String {
    format!("{}:{}", device.key(), connection_id)
}

fn valid_connection_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_:.".contains(&v))
}

/// Metadata is a database-defined version, not a content signature. A future,
/// empty or stale build identity cannot support the security classification.
fn dataset_current(geo: &GeoIpSecurityLookup, now_secs: u64) -> bool {
    geo.dataset.as_ref().is_some_and(|d| {
        !d.database_type.is_empty()
            && d.build_epoch > 0
            && d.build_epoch <= now_secs
            && now_secs - d.build_epoch <= MAX_GEOIP_DATASET_AGE_SECS
    })
}

/// GEO-04 — the zone one address geolocates to, under the observation's
/// dataset rule (a stale or future dataset answers nothing). For evidence that
/// CONFLICTS with a connection's zone only: an address a device advertised is
/// its own claim, so it may withdraw a zone but never grant one.
pub fn address_zone(core: &Core, ip: std::net::IpAddr) -> Option<BusinessZone> {
    let geo = core.geoip.security_lookup(ip);
    let now_secs = DateTime::now().timestamp_millis().max(0) as u64 / 1000;
    if !dataset_current(&geo, now_secs) {
        return None;
    }
    known_zone(geo.country_code.as_deref())
}

/// Classify a single request's [`ConnectionOrigin`] into a [`BusinessZone`]
/// using the same source-currency and GeoIP dataset rules as a persistent
/// connection observation, without persisting an observation or mutating
/// [`LiveZones`].
pub fn origin_zone(core: &Core, origin: &ConnectionOrigin) -> Option<BusinessZone> {
    let now = DateTime::now();
    let captured = origin.captured_at();
    let expiry = captured
        .timestamp_millis()
        .checked_add(OBSERVATION_TTL_MILLIS)
        .filter(|_| captured <= now)
        .map(DateTime::from_millis)
        .unwrap_or(now);
    if !(captured <= now && now < expiry) {
        return None;
    }
    address_zone(core, origin.client_ip()?)
}

fn known_zone(code: Option<&str>) -> Option<BusinessZone> {
    match code {
        Some("CN") => Some(BusinessZone::Mainland),
        Some(v)
            if v.len() == 2
                && v.bytes().all(|b| b.is_ascii_uppercase())
                && !matches!(v, "XX" | "ZZ" | "EU" | "AP") =>
        {
            Some(BusinessZone::NonMainland)
        }
        _ => None,
    }
}

fn observation(
    device: &AuthenticatedDevice,
    origin: &ConnectionOrigin,
    connection_id: &str,
    geo: GeoIpSecurityLookup,
    approval: Option<&RoleApproval>,
    owner: Option<ObjectId>,
    now: DateTime,
) -> Result<ConnectionObservation, ApiError> {
    if !valid_connection_id(connection_id) {
        return Err(ApiError::BadRequest(
            "Invalid server connection identity".into(),
        ));
    }
    let captured = origin.captured_at();
    let expiry = captured
        .timestamp_millis()
        .checked_add(OBSERVATION_TTL_MILLIS)
        .filter(|_| captured <= now)
        .map(DateTime::from_millis)
        .unwrap_or(now);
    let source_current = captured <= now && now < expiry && origin.client_ip().is_some();
    // Metadata is a database-defined version, not a content signature. A future,
    // empty or stale build identity cannot support the security classification.
    let now_secs = now.timestamp_millis().max(0) as u64 / 1000;
    let country_code = if source_current && dataset_current(&geo, now_secs) {
        geo.country_code
    } else {
        None
    };
    let zone = known_zone(country_code.as_deref());
    let role = effective_role(approval, device, owner, now);
    Ok(ConnectionObservation {
        id: observation_key(device, connection_id),
        identity: device.identity.clone(),
        connection_id: connection_id.into(),
        captured_at: captured,
        recorded_at: now,
        expires_at: if source_current { expiry } else { now },
        closed_at: None,
        transport_peer_ip: origin.transport_peer().map(|ip| ip.to_string()),
        client_ip: if source_current {
            origin.client_ip().map(|ip| ip.to_string())
        } else {
            None
        },
        origin_source: origin.source().as_str().into(),
        country_code,
        zone,
        dataset: geo.dataset,
        role_at_capture: role,
        role_revision_at_capture: if role == DeviceUseRole::Unknown {
            None
        } else {
            approval.map(|a| a.revision)
        },
    })
}

/// Persist a one-shot fact after credential/current-admission validation, never
/// from a heartbeat's self-reported fields. A duplicate connection cannot replace
/// or refresh the original source evidence. Errors must not close management WS.
pub async fn record_connection_observation(
    core: &Core,
    device: &AuthenticatedDevice,
    origin: &ConnectionOrigin,
    connection_id: &str,
) -> Result<ConnectionObservation, ApiError> {
    verify_current_device(core, device, true).await?;
    let approval = core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one(doc! { "_id": device.key() })
        .await
        .map_err(storage_error)?;
    let geo = origin
        .client_ip()
        .map(|ip| core.geoip.security_lookup(ip))
        .unwrap_or(GeoIpSecurityLookup {
            dataset: None,
            country_code: None,
        });
    let row = observation(
        device,
        origin,
        connection_id,
        geo,
        approval.as_ref(),
        current_owner(core)?,
        DateTime::now(),
    )?;
    core.db
        .collection::<ConnectionObservation>(OBSERVATIONS_COLLECTION)
        .insert_one(&row)
        .await
        .map_err(storage_error)?;
    if let Some(zone) = row
        .zone
        .filter(|_| row.is_current_for(device, connection_id, DateTime::now()))
    {
        core.business_zones
            .insert(row.id.clone(), (device.identity.clone(), zone));
    }
    Ok(row)
}

/// The business zone `connection_id` was observed in when it opened, while
/// that connection's observation is open on THIS process. The caller must
/// hold `connection_id` as the device's live connection. `None` (unknown)
/// refuses wherever a zone gates anything.
pub fn connection_zone(
    core: &Core,
    device: &AuthenticatedDevice,
    connection_id: &str,
) -> Option<BusinessZone> {
    core.business_zones
        .get(&observation_key(device, connection_id), device)
}

/// A connection's observation recorder, run beside (not before) the socket's
/// management loop so slow storage can never delay hello/registration.
pub struct ObservationTask(tokio::task::JoinHandle<Option<AuthenticatedDevice>>);

impl ObservationTask {
    pub fn spawn(
        record: impl std::future::Future<Output = Option<AuthenticatedDevice>> + Send + 'static,
    ) -> Self {
        Self(tokio::spawn(record))
    }

    /// Wait briefly for the recorder so its insert cannot land after the close,
    /// then close exactly this connection. A recorder still running after the
    /// bound is aborted; at worst one open row remains until its 60 s expiry.
    pub async fn finish(mut self, core: &Core, connection_id: &str) {
        let wait = std::time::Duration::from_secs(2);
        match tokio::time::timeout(wait, &mut self.0).await {
            Ok(Ok(Some(device))) => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    close_connection_observation(core, &device, connection_id),
                )
                .await;
            }
            Ok(_) => {}
            Err(_) => self.0.abort(),
        }
    }
}

/// Close exactly this old/new connection identity; never upsert, overwrite a
/// different session, or extend source expiry. Mongo's TTL index is registered
/// by the network owner; validity does not rely on timely TTL deletion.
pub async fn close_connection_observation(
    core: &Core,
    device: &AuthenticatedDevice,
    connection_id: &str,
) -> Result<(), ApiError> {
    if !valid_connection_id(connection_id) {
        return Err(ApiError::BadRequest(
            "Invalid server connection identity".into(),
        ));
    }
    core.business_zones
        .remove(&observation_key(device, connection_id));
    let identity = bson::to_bson(&device.identity)
        .map_err(|_| ApiError::Internal("Device identity serialization failed".into()))?;
    let now = DateTime::now();
    core.db.collection::<ConnectionObservation>(OBSERVATIONS_COLLECTION)
        .update_one(doc! { "_id": observation_key(device, connection_id), "identity": identity, "connection_id": connection_id },
            doc! { "$set": { "closed_at": now }, "$min": { "expires_at": now } })
        .await.map_err(storage_error)?;
    Ok(())
}

/// Central account-approval owner only, not tenant manager, tag owner or a
/// self-reported agent capability. Both current actor admission and target row
/// identity are rechecked here even when the HTTP route already guarded them.
pub async fn approve_device_role(
    core: &Core,
    auth: &AuthUser,
    device: &AuthenticatedDevice,
    role: DeviceUseRole,
    reason: &str,
) -> Result<RoleApproval, ApiError> {
    require_role_approver(&core.settings.auth.account_approval, auth.user_id)?;
    crate::admission::authorize_user_id(core, auth.user_id, Some(auth.claims.approval_revision))
        .await?;
    // Granting needs an active device; revoking must work on any current row.
    verify_current_device(core, device, role != DeviceUseRole::Unknown).await?;
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "A bounded approval/revocation reason is required".into(),
        ));
    }
    let identity = bson::to_bson(&device.identity)
        .map_err(|_| ApiError::Internal("Device identity serialization failed".into()))?;
    let role_value = bson::to_bson(&role)
        .map_err(|_| ApiError::Internal("Device role serialization failed".into()))?;
    core.db.collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one_and_update(doc! { "_id": device.key() }, doc! {
            "$set": { "identity": identity, "role": role_value, "approved_by": auth.user_id,
                "approved_at": DateTime::now(), "reason": reason, "revoked": role == DeviceUseRole::Unknown },
            "$inc": { "revision": 1_i64 }
        }).upsert(true).return_document(ReturnDocument::After).await.map_err(storage_error)?
        .ok_or_else(|| ApiError::ServiceUnavailable("Role approval was not confirmed".into()))
}

/// Agents of `tenant_id` whose central-owner Server role is current right now,
/// each re-checked against its live registration (identity and token
/// generation, quarantine, the owner's admission), never the stored row alone.
/// One direction only: serving as a relay never makes a device a Server.
static TEST_FAIL_ROLE_READ_TENANTS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashSet<ObjectId>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashSet::new()));

/// Test hook to simulate transient storage failure in `current_approved_roles`
/// and `current_server_agents` for a specific `tenant_id`.
pub fn set_test_force_role_read_fail(tenant_id: ObjectId, fail: bool) {
    let mut guard = TEST_FAIL_ROLE_READ_TENANTS
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if fail {
        guard.insert(tenant_id);
    } else {
        guard.remove(&tenant_id);
    }
}

fn check_test_role_read_fail(tenant_id: ObjectId) -> Result<(), ApiError> {
    if TEST_FAIL_ROLE_READ_TENANTS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&tenant_id)
    {
        return Err(ApiError::ServiceUnavailable(
            "Simulated role approval storage failure".into(),
        ));
    }
    Ok(())
}

async fn admitted_owner_set(
    core: &Core,
    owner_ids: &[ObjectId],
) -> Result<Option<std::collections::HashSet<ObjectId>>, ApiError> {
    if !core.settings.auth.account_approval.enabled {
        return Ok(None);
    }
    if owner_ids.is_empty() {
        return Ok(Some(std::collections::HashSet::new()));
    }
    let users: Vec<meshharbor_db::models::User> =
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            core.db
                .collection::<meshharbor_db::models::User>(meshharbor_db::models::User::COLLECTION)
                .find(doc! { "_id": { "$in": owner_ids } })
                .await
                .map_err(storage_error)?
                .try_collect()
                .await
                .map_err(storage_error)
        })
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Account admission lookup timed out".into()))??;
    let mut admitted = std::collections::HashSet::with_capacity(users.len());
    for user in users {
        if let Some(uid) = user.id
            && crate::admission::require_user(core, &user, None).is_ok()
        {
            admitted.insert(uid);
        }
    }
    Ok(Some(admitted))
}

pub async fn current_server_agents(
    core: &Core,
    tenant_id: ObjectId,
) -> Result<Vec<Agent>, ApiError> {
    check_test_role_read_fail(tenant_id)?;
    let Some(owner) = current_owner(core)? else {
        return Ok(Vec::new());
    };
    let approvals: Vec<RoleApproval> = core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find(doc! {
            "identity.kind": "agent", "identity.tenant_id": tenant_id,
            "role": "server", "revoked": false, "approved_by": owner
        })
        .await
        .map_err(storage_error)?
        .try_collect()
        .await
        .map_err(storage_error)?;
    if approvals.is_empty() {
        return Ok(Vec::new());
    }
    let agent_ids: Vec<ObjectId> = approvals.iter().map(|a| a.identity.device_id).collect();
    let agents: Vec<Agent> = core
        .db
        .collection::<Agent>(Agent::COLLECTION)
        .find(doc! {
            "_id": { "$in": &agent_ids },
            "tenant_id": tenant_id,
            "deleted_at": bson::Bson::Null,
        })
        .await
        .map_err(storage_error)?
        .try_collect()
        .await
        .map_err(storage_error)?;
    let mut agent_map: std::collections::HashMap<ObjectId, Agent> = agents
        .into_iter()
        .filter_map(|a| Some((a.id?, a)))
        .collect();
    let mut owner_ids: Vec<ObjectId> = agent_map.values().map(|a| a.owner_user_id).collect();
    owner_ids.sort_unstable();
    owner_ids.dedup();
    let admitted = admitted_owner_set(core, &owner_ids).await?;
    let now = DateTime::now();
    let mut out = Vec::new();
    for approval in approvals {
        let Some(agent) = agent_map.remove(&approval.identity.device_id) else {
            continue;
        };
        let Ok(device) = AuthenticatedDevice::from_agent(&agent) else {
            continue;
        };
        if effective_role(Some(&approval), &device, Some(owner), now) != DeviceUseRole::Server
            || matches!(agent.status, AgentStatus::Quarantined)
            || admitted
                .as_ref()
                .is_some_and(|set| !set.contains(&agent.owner_user_id))
        {
            continue;
        }
        out.push(agent);
    }
    Ok(out)
}

/// Every device (`Agent` or `TunnelClient`) in `tenant_id` whose current
/// effective role is approved (`Client` or `Server`), re-checked against its
/// live registration (`machine_id`, `token_generation`, `deleted_at`, agent
/// quarantine, and the device owner's admission) using batch `$in` queries.
pub async fn current_approved_roles(
    core: &Core,
    tenant_id: ObjectId,
) -> Result<std::collections::HashMap<(DeviceKind, ObjectId), DeviceUseRole>, ApiError> {
    check_test_role_read_fail(tenant_id)?;
    let Some(owner) = current_owner(core)? else {
        return Ok(std::collections::HashMap::new());
    };
    let approvals: Vec<RoleApproval> = core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find(doc! {
            "identity.tenant_id": tenant_id,
            "role": { "$in": ["client", "server"] },
            "revoked": false,
            "approved_by": owner,
        })
        .await
        .map_err(storage_error)?
        .try_collect()
        .await
        .map_err(storage_error)?;
    if approvals.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let mut agent_ids = Vec::new();
    let mut client_ids = Vec::new();
    for a in &approvals {
        match a.identity.kind {
            DeviceKind::Agent => agent_ids.push(a.identity.device_id),
            DeviceKind::TunnelClient => client_ids.push(a.identity.device_id),
        }
    }
    let agents: std::collections::HashMap<ObjectId, Agent> = if agent_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        let rows: Vec<Agent> = core
            .db
            .collection::<Agent>(Agent::COLLECTION)
            .find(doc! {
                "_id": { "$in": &agent_ids },
                "tenant_id": tenant_id,
                "deleted_at": bson::Bson::Null,
            })
            .await
            .map_err(storage_error)?
            .try_collect()
            .await
            .map_err(storage_error)?;
        rows.into_iter().filter_map(|a| Some((a.id?, a))).collect()
    };
    let clients: std::collections::HashMap<ObjectId, TunnelClient> = if client_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        let rows: Vec<TunnelClient> = core
            .db
            .collection::<TunnelClient>(TunnelClient::COLLECTION)
            .find(doc! {
                "_id": { "$in": &client_ids },
                "tenant_id": tenant_id,
                "deleted_at": bson::Bson::Null,
            })
            .await
            .map_err(storage_error)?
            .try_collect()
            .await
            .map_err(storage_error)?;
        rows.into_iter().filter_map(|c| Some((c.id?, c))).collect()
    };
    let mut owner_ids: Vec<ObjectId> = agents
        .values()
        .map(|a| a.owner_user_id)
        .chain(clients.values().map(|c| c.owner_user_id))
        .collect();
    owner_ids.sort_unstable();
    owner_ids.dedup();
    let admitted = admitted_owner_set(core, &owner_ids).await?;
    let now = DateTime::now();
    let mut out = std::collections::HashMap::with_capacity(approvals.len());
    for approval in approvals {
        let device_id = approval.identity.device_id;
        let (device, owner_user_id) = match approval.identity.kind {
            DeviceKind::Agent => {
                let Some(agent) = agents.get(&device_id) else {
                    continue;
                };
                if matches!(agent.status, AgentStatus::Quarantined) {
                    continue;
                }
                let Ok(device) = AuthenticatedDevice::from_agent(agent) else {
                    continue;
                };
                (device, agent.owner_user_id)
            }
            DeviceKind::TunnelClient => {
                let Some(client) = clients.get(&device_id) else {
                    continue;
                };
                if matches!(client.status, AgentStatus::Quarantined) {
                    continue;
                }
                let Ok(device) = AuthenticatedDevice::from_tunnel_client(client) else {
                    continue;
                };
                (device, client.owner_user_id)
            }
        };
        let role = effective_role(Some(&approval), &device, Some(owner), now);
        if role != approval.role
            || role == DeviceUseRole::Unknown
            || admitted
                .as_ref()
                .is_some_and(|set| !set.contains(&owner_user_id))
        {
            continue;
        }
        out.insert((approval.identity.kind, device_id), role);
    }
    Ok(out)
}

/// Target-scoped live role evidence for either an `Agent` or a `TunnelClient`.
/// Unlike `trial_server_evidence`'s legacy `Client` short-circuit, this verifies
/// the live device row, token/machine generation, quarantine, and owner
/// admission for both `Client` and `Server` roles so `business_unknown_role = enforce`
/// never admits a stale or revoked device role.
pub async fn trial_device_role_evidence(
    core: &Core,
    tenant_id: ObjectId,
    kind: DeviceKind,
    device_id: ObjectId,
) -> TrialServerEvidence {
    use TrialServerEvidence as E;
    if check_test_role_read_fail(tenant_id).is_err() {
        return E::Unknown;
    }
    let owner = match current_owner(core) {
        Ok(Some(owner)) => owner,
        Ok(None) => return E::ApprovalDisabled,
        Err(_) => return E::Unknown,
    };
    let key = format!(
        "{}:{tenant_id}:{device_id}",
        match kind {
            DeviceKind::Agent => "agent",
            DeviceKind::TunnelClient => "tunnel_client",
        }
    );
    let approval = match core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one(doc! { "_id": key })
        .await
    {
        Ok(Some(approval)) => approval,
        Ok(None) => return E::MissingApproval,
        Err(_) => return E::Unknown,
    };
    if approval.identity.kind != kind
        || approval.identity.tenant_id != tenant_id
        || approval.identity.device_id != device_id
    {
        return E::Unknown;
    }
    if approval.revoked || approval.role == DeviceUseRole::Unknown || approval.approved_by != owner
    {
        return E::ObservedInactive;
    }
    let (device, owner_user_id) = match kind {
        DeviceKind::Agent => {
            let agent = match core
                .db
                .collection::<Agent>(Agent::COLLECTION)
                .find_one(doc! {
                    "_id": device_id,
                    "tenant_id": tenant_id,
                    "deleted_at": bson::Bson::Null,
                })
                .await
            {
                Ok(Some(agent)) => agent,
                Ok(None) => return E::ObservedInactive,
                Err(_) => return E::Unknown,
            };
            if matches!(agent.status, AgentStatus::Quarantined) {
                return E::ObservedInactive;
            }
            let Ok(device) = AuthenticatedDevice::from_agent(&agent) else {
                return E::ObservedInactive;
            };
            (device, agent.owner_user_id)
        }
        DeviceKind::TunnelClient => {
            let client = match core
                .db
                .collection::<TunnelClient>(TunnelClient::COLLECTION)
                .find_one(doc! {
                    "_id": device_id,
                    "tenant_id": tenant_id,
                    "deleted_at": bson::Bson::Null,
                })
                .await
            {
                Ok(Some(client)) => client,
                Ok(None) => return E::ObservedInactive,
                Err(_) => return E::Unknown,
            };
            if matches!(client.status, AgentStatus::Quarantined) {
                return E::ObservedInactive;
            }
            let Ok(device) = AuthenticatedDevice::from_tunnel_client(&client) else {
                return E::ObservedInactive;
            };
            (device, client.owner_user_id)
        }
    };
    let role = effective_role(Some(&approval), &device, Some(owner), DateTime::now());
    if role != approval.role || role == DeviceUseRole::Unknown {
        return E::ObservedInactive;
    }
    match crate::admission::authorize_user_id(core, owner_user_id, None).await {
        Ok(()) => match role {
            DeviceUseRole::Server => E::ObservedServer,
            DeviceUseRole::Client => E::ObservedClient,
            DeviceUseRole::Unknown => E::ObservedInactive,
        },
        Err(ApiError::NotFound(_) | ApiError::Forbidden(_) | ApiError::Unauthorized(_)) => {
            E::ObservedInactive
        }
        Err(_) => E::Unknown,
    }
}

/// Target-scoped observations for admitting a *new* trial. None of these
/// values authenticates the current socket or fences a subsequent policy
/// change: only a shared authority revision can make them durable evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialServerEvidence {
    ObservedServer,
    ObservedClient,
    ObservedInactive,
    MissingApproval,
    ApprovalDisabled,
    Unknown,
}

/// Unlike `current_server_agents`, an unreadable owner for the target cannot
/// be silently omitted from a server list. Other tenants/devices do not block.
pub async fn trial_server_evidence(
    core: &Core,
    tenant_id: ObjectId,
    agent_id: ObjectId,
) -> TrialServerEvidence {
    use TrialServerEvidence as E;
    if check_test_role_read_fail(tenant_id).is_err() {
        return E::Unknown;
    }
    let owner = match current_owner(core) {
        Ok(Some(owner)) => owner,
        Ok(None) => return E::ApprovalDisabled,
        Err(_) => return E::Unknown,
    };
    let key = format!("agent:{tenant_id}:{agent_id}");
    let approval = match core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one(doc! { "_id": key })
        .await
    {
        Ok(Some(approval)) => approval,
        Ok(None) => return E::MissingApproval,
        Err(_) => return E::Unknown,
    };
    if approval.identity.kind != DeviceKind::Agent
        || approval.identity.tenant_id != tenant_id
        || approval.identity.device_id != agent_id
    {
        return E::Unknown;
    }
    // Match the existing server-list short circuit: approvals that cannot be
    // current Server approvals take the ordinary zone/ACL path, not a new
    // blanket denial. These are observations, not socket-role proof.
    if approval.revoked || approval.role == DeviceUseRole::Unknown || approval.approved_by != owner
    {
        return E::ObservedInactive;
    }
    if approval.role == DeviceUseRole::Client {
        return E::ObservedClient;
    }
    let agent = match core
        .db
        .collection::<Agent>(Agent::COLLECTION)
        .find_one(doc! { "_id": agent_id, "tenant_id": tenant_id, "deleted_at": bson::Bson::Null })
        .await
    {
        Ok(Some(agent)) => agent,
        Ok(None) => return E::ObservedInactive,
        Err(_) => return E::Unknown,
    };
    let device = match AuthenticatedDevice::from_agent(&agent) {
        Ok(device) => device,
        Err(_) => return E::ObservedInactive,
    };
    if effective_role(Some(&approval), &device, Some(owner), DateTime::now())
        != DeviceUseRole::Server
        || matches!(agent.status, AgentStatus::Quarantined)
    {
        return E::ObservedInactive;
    }
    match crate::admission::authorize_user_id(core, agent.owner_user_id, None).await {
        Ok(()) => E::ObservedServer,
        // The legacy role list excludes these confirmed admission outcomes.
        Err(ApiError::NotFound(_) | ApiError::Forbidden(_) | ApiError::Unauthorized(_)) => {
            E::ObservedInactive
        }
        // Includes storage, deserialization and timeout; not non-server proof.
        Err(_) => E::Unknown,
    }
}

/// Private operator diagnostics. The caller must enforce the central-owner gate
/// before serializing this view. This does not mint or return business grants.
pub async fn get_device_authority(
    core: &Core,
    device: &AuthenticatedDevice,
) -> Result<DeviceAuthorityView, ApiError> {
    verify_current_device(core, device, false).await?;
    let role_approval = core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one(doc! { "_id": device.key() })
        .await
        .map_err(storage_error)?;
    let identity = bson::to_bson(&device.identity)
        .map_err(|_| ApiError::Internal("Device identity serialization failed".into()))?;
    let observations = core
        .db
        .collection::<ConnectionObservation>(OBSERVATIONS_COLLECTION);
    let last_observation = observations
        .find_one(doc! { "identity": identity.clone() })
        .sort(doc! { "captured_at": -1 })
        .await
        .map_err(storage_error)?;
    // A newer closed row must not hide an older connection that is still open.
    let now = DateTime::now();
    let current_observation = observations
        .find_one(doc! { "identity": identity, "closed_at": bson::Bson::Null })
        .sort(doc! { "captured_at": -1 })
        .await
        .map_err(storage_error)?
        .filter(|o| o.is_current_for(device, &o.connection_id, now));
    Ok(DeviceAuthorityView {
        identity: device.identity.clone(),
        effective_role: effective_role(role_approval.as_ref(), device, current_owner(core)?, now),
        role_approval,
        last_observation,
        observation_is_current: current_observation.is_some(),
        current_observation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn device(kind: DeviceKind) -> AuthenticatedDevice {
        AuthenticatedDevice::new(
            kind,
            ObjectId::new(),
            Some(ObjectId::new()),
            "machine-fixture",
            7,
        )
        .unwrap()
    }
    fn origin() -> ConnectionOrigin {
        ConnectionOrigin::capture(
            &HeaderMap::new(),
            Some("198.51.100.9:443".parse().unwrap()),
            &[],
            0,
        )
    }
    fn geo(code: Option<&str>) -> GeoIpSecurityLookup {
        GeoIpSecurityLookup {
            country_code: code.map(str::to_string),
            dataset: Some(GeoIpDatasetIdentity {
                database_type: "fixture-country".into(),
                build_epoch: (DateTime::now().timestamp_millis() / 1000 - 86_400) as u64,
                ip_version: 4,
            }),
        }
    }
    fn approval(
        device: &AuthenticatedDevice,
        owner: ObjectId,
        role: DeviceUseRole,
        now: DateTime,
    ) -> RoleApproval {
        RoleApproval {
            id: device.key(),
            identity: device.identity.clone(),
            role,
            approved_by: owner,
            approved_at: now,
            revision: 1,
            reason: "fixture".into(),
            revoked: false,
        }
    }

    #[test]
    fn missing_roles_never_make_agents_servers_or_clients_overseas() {
        for kind in [DeviceKind::Agent, DeviceKind::TunnelClient] {
            let d = device(kind);
            let o = origin();
            let row = observation(
                &d,
                &o,
                "connection-a",
                geo(None),
                None,
                None,
                o.captured_at(),
            )
            .unwrap();
            assert_eq!(row.role_at_capture, DeviceUseRole::Unknown);
            assert_eq!(row.zone, None);
            assert_eq!(row.country_code, None);
        }
    }

    #[test]
    fn only_explicit_enabled_central_owner_can_approve_or_revoke_roles() {
        use meshharbor_config::AccountApprovalSettings;
        let owner = ObjectId::new();
        let configured = AccountApprovalSettings {
            enabled: true,
            owner_user_id: Some(owner.to_hex()),
        };
        assert!(require_role_approver(&configured, owner).is_ok());
        assert!(require_role_approver(&configured, ObjectId::new()).is_err());
        assert!(require_role_approver(&AccountApprovalSettings::default(), owner).is_err());
        assert!(
            require_role_approver(
                &AccountApprovalSettings {
                    enabled: false,
                    owner_user_id: Some(owner.to_hex())
                },
                owner
            )
            .is_err()
        );
        assert!(
            require_role_approver(
                &AccountApprovalSettings {
                    enabled: true,
                    owner_user_id: Some("not-an-objectid".into())
                },
                owner
            )
            .is_err()
        );
    }

    #[test]
    fn country_classification_is_binary_but_unknown_is_not_non_mainland() {
        assert_eq!(known_zone(Some("CN")), Some(BusinessZone::Mainland));
        for code in ["US", "HK", "MO", "TW", "GB"] {
            assert_eq!(known_zone(Some(code)), Some(BusinessZone::NonMainland));
        }
        for code in [
            None,
            Some(""),
            Some("unknown"),
            Some("ZZ"),
            Some("XX"),
            Some("EU"),
            Some("AP"),
            Some("cn"),
            Some(" CN"),
        ] {
            assert_eq!(known_zone(code), None);
        }
    }

    #[test]
    fn role_approval_binds_owner_machine_generation_and_current_time() {
        let d = device(DeviceKind::Agent);
        let owner = ObjectId::new();
        let now = DateTime::now();
        let a = approval(&d, owner, DeviceUseRole::Server, now);
        assert_eq!(
            effective_role(Some(&a), &d, Some(owner), now),
            DeviceUseRole::Server
        );
        assert_eq!(
            effective_role(Some(&a), &d, None, now),
            DeviceUseRole::Unknown
        );
        assert_eq!(
            effective_role(Some(&a), &d, Some(ObjectId::new()), now),
            DeviceUseRole::Unknown
        );
        let mut changed = d.clone();
        changed.identity.machine_id = "different".into();
        assert_eq!(
            effective_role(Some(&a), &changed, Some(owner), now),
            DeviceUseRole::Unknown
        );
        changed = d.clone();
        changed.identity.token_generation += 1;
        assert_eq!(
            effective_role(Some(&a), &changed, Some(owner), now),
            DeviceUseRole::Unknown
        );
        let mut revoked = a.clone();
        revoked.revoked = true;
        assert_eq!(
            effective_role(Some(&revoked), &d, Some(owner), now),
            DeviceUseRole::Unknown
        );
        let mut future = a.clone();
        future.approved_at = DateTime::from_millis(now.timestamp_millis() + 1);
        assert_eq!(
            effective_role(Some(&future), &d, Some(owner), now),
            DeviceUseRole::Unknown
        );
    }

    #[test]
    fn observations_keep_exact_connection_and_do_not_restamp_stale_capture() {
        let d = device(DeviceKind::Agent);
        let o = origin();
        let now = o.captured_at();
        let row = observation(&d, &o, "connection-a", geo(Some("CN")), None, None, now).unwrap();
        assert_eq!(row.identity, d.identity);
        assert_eq!(row.client_ip.as_deref(), Some("198.51.100.9"));
        assert!(row.is_current_for(&d, "connection-a", now));
        assert!(!row.is_current_for(&d, "connection-b", now));
        assert_eq!(row.zone, Some(BusinessZone::Mainland));
        let later = DateTime::from_millis(now.timestamp_millis() + OBSERVATION_TTL_MILLIS + 1);
        let expired =
            observation(&d, &o, "connection-a", geo(Some("CN")), None, None, later).unwrap();
        assert_eq!(expired.client_ip, None);
        assert_eq!(expired.zone, None);
        assert!(!expired.is_current_for(&d, "connection-a", later));
    }

    #[test]
    fn unknown_source_and_missing_or_future_dataset_never_yield_a_zone() {
        let d = device(DeviceKind::TunnelClient);
        let missing = ConnectionOrigin::capture(&HeaderMap::new(), None, &[], 0);
        let row = observation(
            &d,
            &missing,
            "c",
            geo(Some("CN")),
            None,
            None,
            missing.captured_at(),
        )
        .unwrap();
        assert_eq!(row.client_ip, None);
        assert_eq!(row.zone, None);
        let o = origin();
        let no_db = GeoIpSecurityLookup {
            dataset: None,
            country_code: Some("CN".into()),
        };
        assert_eq!(
            observation(&d, &o, "c", no_db, None, None, o.captured_at())
                .unwrap()
                .zone,
            None
        );
        let mut future = geo(Some("CN"));
        future.dataset.as_mut().unwrap().build_epoch = u64::MAX;
        assert_eq!(
            observation(&d, &o, "c", future, None, None, o.captured_at())
                .unwrap()
                .zone,
            None
        );
        let mut stale = geo(Some("CN"));
        stale.dataset.as_mut().unwrap().build_epoch -= MAX_GEOIP_DATASET_AGE_SECS;
        assert_eq!(
            observation(&d, &o, "c", stale, None, None, o.captured_at())
                .unwrap()
                .zone,
            None,
            "a database older than the bound is not security evidence"
        );
        assert_eq!(
            observation(&d, &o, "c", geo(Some("CN")), None, None, o.captured_at())
                .unwrap()
                .zone,
            Some(BusinessZone::Mainland)
        );
    }

    #[test]
    fn private_records_use_distinct_subjects_and_no_credential_fields() {
        let mut d = device(DeviceKind::Agent);
        let first = d.key();
        d.identity.kind = DeviceKind::TunnelClient;
        assert_ne!(first, d.key());
        let o = origin();
        let row = observation(&d, &o, "c", geo(Some("US")), None, None, o.captured_at()).unwrap();
        let doc = bson::to_document(&row).unwrap();
        for forbidden in [
            "token",
            "credential",
            "headers",
            "xff",
            "agent_token",
            "password",
        ] {
            assert!(!doc.contains_key(forbidden));
        }
        let restored: ConnectionObservation = bson::from_document(doc).unwrap();
        assert_eq!(restored.identity, d.identity);
        assert_eq!(restored.zone, Some(BusinessZone::NonMainland));
    }

    #[test]
    fn malformed_stored_observation_is_not_current_authority() {
        let d = device(DeviceKind::Agent);
        let o = origin();
        let now = o.captured_at();
        let row = observation(&d, &o, "c", geo(Some("CN")), None, None, now).unwrap();
        assert!(row.is_current_for(&d, "c", now));
        let mut invalid = row.clone();
        invalid.client_ip = Some("not-an-address".into());
        assert!(!invalid.is_current_for(&d, "c", now));
        invalid = row.clone();
        invalid.transport_peer_ip = Some("198.51.100.10".into());
        assert!(!invalid.is_current_for(&d, "c", now));
        invalid = row.clone();
        invalid.origin_source = "unknown".into();
        assert!(!invalid.is_current_for(&d, "c", now));
        invalid = row.clone();
        invalid.recorded_at = DateTime::from_millis(now.timestamp_millis() + 1);
        assert!(!invalid.is_current_for(&d, "c", now));
        invalid = row.clone();
        invalid.closed_at = Some(now);
        assert!(!invalid.is_current_for(&d, "c", now));
    }

    #[test]
    fn invalid_identity_or_connection_id_is_not_an_observation() {
        assert!(
            AuthenticatedDevice::new(DeviceKind::Agent, ObjectId::new(), None, "machine", 0)
                .is_err()
        );
        assert!(
            AuthenticatedDevice::new(
                DeviceKind::Agent,
                ObjectId::new(),
                Some(ObjectId::new()),
                "",
                0
            )
            .is_err()
        );
        let d = device(DeviceKind::Agent);
        let o = origin();
        for id in ["", "credential\nleak", "bad/id"] {
            assert!(observation(&d, &o, id, geo(Some("CN")), None, None, o.captured_at()).is_err());
        }
    }
}
