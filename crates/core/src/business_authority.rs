// SPDX-License-Identifier: AGPL-3.0-only
//! Private server-side facts for business-policy issuance. These records are
//! deliberately NOT fields of public Agent/TunnelClient documents or wire DTOs.
//! A captured origin, role approval and GeoIP lookup are observations, not a
//! signed grant. Runtime consumers must additionally verify the current live
//! authenticated connection, revocation/generation and complete actual path.

use bson::{DateTime, doc, oid::ObjectId};
use mongodb::options::ReturnDocument;
use roomler_ai_remote_control::models::{Agent, TunnelClient};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Private operator surface only; never return this through ordinary/shared
/// device JSON. "Current" describes a bounded source observation, not access.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorityView {
    pub identity: DeviceIdentity,
    pub role_approval: Option<RoleApproval>,
    pub effective_role: DeviceUseRole,
    pub last_observation: Option<ConnectionObservation>,
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
    policy: &roomler_ai_config::AccountApprovalSettings,
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

async fn verify_current_device(core: &Core, device: &AuthenticatedDevice) -> Result<(), ApiError> {
    let filter = doc! { "_id": device.identity.device_id, "tenant_id": device.identity.tenant_id, "deleted_at": bson::Bson::Null };
    let actual = match device.identity.kind {
        DeviceKind::Agent => core
            .db
            .collection::<Agent>(Agent::COLLECTION)
            .find_one(filter)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(AuthenticatedDevice::from_agent)
            .transpose()?,
        DeviceKind::TunnelClient => core
            .db
            .collection::<TunnelClient>(TunnelClient::COLLECTION)
            .find_one(filter)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(AuthenticatedDevice::from_tunnel_client)
            .transpose()?,
    };
    if actual
        .as_ref()
        .is_none_or(|row| row.identity != device.identity)
    {
        return Err(ApiError::Conflict(
            "Device identity changed; reload current registration".into(),
        ));
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
    // Metadata is a database-defined version, not a content signature. A future
    // or empty build identity cannot support the security classification.
    let dataset_current = geo.dataset.as_ref().is_some_and(|d| {
        !d.database_type.is_empty()
            && d.build_epoch > 0
            && d.build_epoch <= (now.timestamp_millis().max(0) as u64 / 1000)
    });
    let country_code = if source_current && dataset_current {
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
    verify_current_device(core, device).await?;
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
    Ok(row)
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
    verify_current_device(core, device).await?;
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

/// Private operator diagnostics. The caller must enforce the central-owner gate
/// before serializing this view. This does not mint or return business grants.
pub async fn get_device_authority(
    core: &Core,
    device: &AuthenticatedDevice,
) -> Result<DeviceAuthorityView, ApiError> {
    verify_current_device(core, device).await?;
    let role_approval = core
        .db
        .collection::<RoleApproval>(ROLE_APPROVALS_COLLECTION)
        .find_one(doc! { "_id": device.key() })
        .await
        .map_err(storage_error)?;
    let identity = bson::to_bson(&device.identity)
        .map_err(|_| ApiError::Internal("Device identity serialization failed".into()))?;
    let last_observation = core
        .db
        .collection::<ConnectionObservation>(OBSERVATIONS_COLLECTION)
        .find_one(doc! { "identity": identity })
        .sort(doc! { "captured_at": -1 })
        .await
        .map_err(storage_error)?;
    let now = DateTime::now();
    let observation_is_current = last_observation
        .as_ref()
        .is_some_and(|o| o.is_current_for(device, &o.connection_id, now));
    Ok(DeviceAuthorityView {
        identity: device.identity.clone(),
        effective_role: effective_role(role_approval.as_ref(), device, current_owner(core)?, now),
        role_approval,
        last_observation,
        observation_is_current,
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
                build_epoch: 1,
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
        use roomler_ai_config::AccountApprovalSettings;
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
