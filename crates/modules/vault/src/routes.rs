// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The vault's routes in P3-1: an administrator's view of the store.
//!
//! | Route | Does | Needs the KEK |
//! |---|---|---|
//! | `GET …/vault` | the vault's state: the KEK's, and how much it holds | no |
//! | `GET …/vault/secret` | the live secrets, by path (`?prefix=` a folder) | no |
//! | `POST …/vault/secret` | declare one: its path, kind and rules — no value | no |
//! | `GET …/vault/secret/{id}` | one secret and its versions' metadata | no |
//! | `PATCH …/vault/secret/{id}` | change its rules (never its path or kind); a disable takes its leases back (P3-3c) | no |
//! | `DELETE …/vault/secret/{id}` | tombstone it and destroy every version; its leases taken back (P3-3c) | no |
//! | `PUT …/vault/secret/{id}/value` | write a field's next version, sealed; the field's older leases taken back (P3-3c) | **yes** |
//! | `POST …/vault/verify` | open every version, answer which do not | **yes** |
//! | `GET …/vault/audit` | the decisions, newest first | no |
//!
//! ⚠️ **No route answers a value.** A value goes in through `PUT …/value`
//! and comes out of no route at all in P3-1: a session's use is P3-3's
//! lease, and a person's `secret:read` is a later step with its own gate.
//!
//! The one policy in P3-1: an organization's `ADMINISTRATOR` may do anything
//! to its vault, and no one else anything. Every `secret:*` and
//! `vault:verify` decision is recorded in `vault_audit`, allow and deny — an
//! allow BEFORE it is acted on, so a decision that cannot be recorded is not
//! acted on. Membership comes first: someone outside an organization learns
//! nothing, not even whether the vault serves it. P3-2 puts Cedar where
//! [`decide`] is, behind the same audit.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, Document, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::parse_tid};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::vault::{RevokeReason, providers};
use meshharbor_services::dao::base::DaoError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{error, warn};
use zeroize::Zeroize;

use crate::VaultState;
use crate::crypto::{Binding, KekState};
use crate::dao::{MAX_VERIFY, VersionMeta, is_path_taken};
use crate::model::{
    FieldState, KIND_DYNAMIC, KIND_STATIC, KIND_STRUCTURED, KINDS, VaultAuditEvent, VaultSecret,
    VaultVersion, binary,
};
use crate::rrn::{STATIC_FIELD, check_field, check_path, check_tag, secret_rrn};

/// What a member of an organization the vault does not serve is told, on
/// every route.
pub const NOT_SERVED: &str = "the vault is not available to this organization";

/// The largest value, in bytes.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
/// A field keeps its last this many versions; older ones are destroyed.
pub const KEEP_VERSIONS: i64 = 10;
/// The most fields a structured secret holds.
pub const MAX_FIELDS: usize = 32;
/// The most entries in each of audiences, exec_allow and tags.
pub const MAX_LIST_ENTRIES: usize = 32;
/// The longest audience or `exec_allow` entry.
pub const MAX_ENTRY_LEN: usize = 255;
/// The longest description.
pub const MAX_DESCRIPTION_LEN: usize = 1024;
/// The longest rotation period, in days.
pub const MAX_ROTATION_DAYS: u32 = 3650;
/// The most failures a verify lists (it counts them all).
pub const MAX_VERIFY_FAILURES: usize = 100;

// ─── the gate ───────────────────────────────────────────────────────────────

/// The organization a route names, once the caller is shown to be in it
/// and the vault serves it.
pub(crate) async fn member_tenant(
    state: &VaultState,
    tenant_id: &str,
    auth: &AuthUser,
) -> Result<ObjectId, ApiError> {
    let tid = parse_tid(tenant_id)?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    if !state.scope.serves(tid) {
        return Err(ApiError::NotFound(NOT_SERVED.into()));
    }
    Ok(tid)
}

/// What was asked, as the audit records it.
pub(crate) struct Ask {
    action: &'static str,
    op: &'static str,
    secret_id: Option<ObjectId>,
    rrn: Option<String>,
    field: Option<String>,
    n: Option<i64>,
    /// P3-2 — a role or a policy the decision is about.
    target: Option<String>,
}

impl Ask {
    pub(crate) fn new(action: &'static str, op: &'static str) -> Self {
        Self {
            action,
            op,
            secret_id: None,
            rrn: None,
            field: None,
            n: None,
            target: None,
        }
    }

    fn secret(mut self, id: Option<ObjectId>) -> Self {
        self.secret_id = id;
        self
    }

    /// P3-2 — `role:<name>` or `policy:<id>`.
    pub(crate) fn target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    fn event(&self, tid: ObjectId, auth: &AuthUser, allow: bool) -> VaultAuditEvent {
        VaultAuditEvent {
            id: None,
            tenant_id: tid,
            principal: "user".into(),
            user_id: auth.user_id,
            action: self.action.into(),
            op: self.op.into(),
            decision: if allow { "allow" } else { "deny" }.into(),
            reason: if allow {
                "administrator"
            } else {
                "not_administrator"
            }
            .into(),
            secret_id: self.secret_id,
            rrn: self.rrn.clone(),
            field: self.field.clone(),
            n: self.n,
            target: self.target.clone(),
            session_id: None,
            device_id: None,
            request: None,
            at: DateTime::now(),
        }
    }
}

/// P3-1's one policy: the organization's administrators, and no one else.
/// A refusal is recorded (best effort: the caller is refused whatever the
/// database says) and answered 403.
pub(crate) async fn decide(
    state: &VaultState,
    tid: ObjectId,
    auth: &AuthUser,
    ask: &Ask,
) -> Result<(), ApiError> {
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if permissions::has(perms, permissions::ADMINISTRATOR) {
        return Ok(());
    }
    if let Err(e) = state.audit.record(&ask.event(tid, auth, false)).await {
        warn!(%e, "vault: a refusal could not be recorded");
    }
    Err(ApiError::Forbidden(
        "only the organization's administrators reach its vault".into(),
    ))
}

/// Record an allow, before acting on it. ⚠️ Fails CLOSED: an allow the
/// vault cannot record is answered 500 and not acted on.
pub(crate) async fn record_allow(
    state: &VaultState,
    tid: ObjectId,
    auth: &AuthUser,
    ask: &Ask,
) -> Result<(), ApiError> {
    state
        .audit
        .record(&ask.event(tid, auth, true))
        .await
        .map(|_| ())
        .map_err(|e| {
            error!(%e, "vault: a decision could not be recorded — not acted on");
            ApiError::Internal("the vault could not record its decision".into())
        })
}

/// The KEK, or the 503 that says why there is none.
fn kek_or_503(state: &VaultState) -> Result<std::sync::Arc<crate::crypto::Kek>, ApiError> {
    match &state.kek {
        KekState::Ready(k) => Ok(k.clone()),
        KekState::Missing => Err(ApiError::ServiceUnavailable(
            "the vault has no key-encryption key (vault.kek / vault.kek_file)".into(),
        )),
        KekState::Invalid(why) => Err(ApiError::ServiceUnavailable(format!(
            "the vault's key-encryption key is unusable: {why}"
        ))),
    }
}

/// The organization's slug, for its RRNs.
pub(crate) async fn org_slug(state: &VaultState, tid: ObjectId) -> Result<String, ApiError> {
    Ok(state.tenants.base.find_by_id(tid).await?.slug)
}

pub(crate) fn parse_secret_id(raw: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest("Invalid secret id".into()))
}

/// A live secret of the organization, or the 404 every other id gets.
pub(crate) async fn live_secret(
    state: &VaultState,
    tid: ObjectId,
    id: ObjectId,
) -> Result<VaultSecret, ApiError> {
    match state.secrets.get_live(tid, id).await {
        Ok(s) => Ok(s),
        Err(DaoError::NotFound) => Err(ApiError::NotFound("no such secret".into())),
        Err(e) => Err(e.into()),
    }
}

// ─── views: metadata only ───────────────────────────────────────────────────

pub(crate) fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

/// A secret as an answer shows it: its name and rules, never a value.
#[derive(Serialize, Debug)]
pub struct SecretView {
    pub id: String,
    pub rrn: String,
    pub path: String,
    pub kind: String,
    /// P3-6b — a dynamic secret's provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub description: String,
    /// The fields that hold a value, and which version is current.
    pub fields: Vec<FieldView>,
    pub audiences: Vec<String>,
    pub exec_allow: Vec<String>,
    pub tags: Vec<String>,
    pub owner_id: String,
    pub rotation_days: Option<u32>,
    pub disabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Debug)]
pub struct FieldView {
    pub name: String,
    pub current: i64,
    pub updated_at: Option<String>,
}

impl SecretView {
    fn of(s: &VaultSecret, slug: &str) -> Self {
        Self {
            id: s.id.map(|i| i.to_hex()).unwrap_or_default(),
            rrn: secret_rrn(slug, &s.path),
            path: s.path.clone(),
            kind: s.kind.clone(),
            provider: s.provider.clone(),
            description: s.description.clone(),
            fields: s
                .fields
                .iter()
                .filter(|(_, f)| f.current > 0)
                .map(|(name, f): (&String, &FieldState)| FieldView {
                    name: name.clone(),
                    current: f.current,
                    updated_at: f.updated_at.map(rfc3339),
                })
                .collect(),
            audiences: s.audiences.clone(),
            exec_allow: s.exec_allow.clone(),
            tags: s.tags.clone(),
            owner_id: s.owner_id.to_hex(),
            rotation_days: s.rotation_days,
            disabled: s.disabled,
            created_by: s.created_by.to_hex(),
            created_at: rfc3339(s.created_at),
            updated_at: rfc3339(s.updated_at),
        }
    }
}

/// A version as an answer shows it: its number, its KEK, who wrote it.
#[derive(Serialize, Debug)]
pub struct VersionView {
    pub field: String,
    pub n: i64,
    pub current: bool,
    pub kek: String,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl VersionView {
    fn of(v: &VersionMeta, s: &VaultSecret) -> Self {
        Self {
            current: s.fields.get(&v.field).is_some_and(|f| f.current == v.n),
            field: v.field.clone(),
            n: v.n,
            kek: v.kek.clone(),
            created_by: v.created_by.to_hex(),
            created_at: rfc3339(v.created_at),
            expires_at: v.expires_at.map(rfc3339),
        }
    }
}

// ─── request checks ─────────────────────────────────────────────────────────

pub(crate) fn check_description(d: &str) -> Result<(), ApiError> {
    if d.len() > MAX_DESCRIPTION_LEN {
        return Err(ApiError::BadRequest(format!(
            "description is longer than {MAX_DESCRIPTION_LEN} bytes"
        )));
    }
    if d.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(ApiError::BadRequest(
            "description holds a control character".into(),
        ));
    }
    Ok(())
}

/// Audiences and `exec_allow`: a bounded list of distinct entries, each a
/// run of visible characters. P3-5 is where an audience's grammar is held
/// to; P3-1 refuses only what no grammar will ever take.
fn check_entries(what: &str, entries: &[String]) -> Result<(), ApiError> {
    if entries.len() > MAX_LIST_ENTRIES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_LIST_ENTRIES} {what}"
        )));
    }
    for (i, e) in entries.iter().enumerate() {
        if e.is_empty() || e.len() > MAX_ENTRY_LEN {
            return Err(ApiError::BadRequest(format!(
                "each of {what} must be 1 to {MAX_ENTRY_LEN} bytes"
            )));
        }
        if e.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ApiError::BadRequest(format!(
                "{what} entry {e:?} holds a space or a control character"
            )));
        }
        if entries[..i].contains(e) {
            return Err(ApiError::BadRequest(format!(
                "{what} entry {e:?} is listed twice"
            )));
        }
    }
    Ok(())
}

/// P3-4c — `exec_allow` names programs by their BARE name
/// ([`program_name_ok`](meshharbor_remote_control::vault::program_name_ok)):
/// the device resolves the name among the system's own directories and hands
/// a value to nothing else, so a path could only ever allow nothing. It is
/// refused here rather than kept to do nothing.
fn check_programs(entries: &[String]) -> Result<(), ApiError> {
    check_entries("exec_allow", entries)?;
    if let Some(e) = entries
        .iter()
        .find(|e| !meshharbor_remote_control::vault::program_name_ok(e))
    {
        return Err(ApiError::BadRequest(format!(
            "exec_allow entry {e:?} is not a program's bare name (letters, digits, `.`, `_`, \
             `+` or `-`, at most {} characters, not starting with `.` or `-`)",
            meshharbor_remote_control::vault::lease_limits::MAX_PROGRAM_LEN
        )));
    }
    Ok(())
}

fn check_tags(tags: &[String]) -> Result<(), ApiError> {
    if tags.len() > MAX_LIST_ENTRIES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_LIST_ENTRIES} tags"
        )));
    }
    for (i, t) in tags.iter().enumerate() {
        check_tag(t).map_err(ApiError::BadRequest)?;
        if tags[..i].contains(t) {
            return Err(ApiError::BadRequest(format!("tag {t:?} is listed twice")));
        }
    }
    Ok(())
}

fn check_rotation(days: u32) -> Result<(), ApiError> {
    if days == 0 || days > MAX_ROTATION_DAYS {
        return Err(ApiError::BadRequest(format!(
            "rotation_days must be 1 to {MAX_ROTATION_DAYS}"
        )));
    }
    Ok(())
}

/// An owner must be a member of the organization.
pub(crate) async fn check_owner(
    state: &VaultState,
    tid: ObjectId,
    raw: &str,
) -> Result<ObjectId, ApiError> {
    let owner =
        ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest("Invalid owner_id".into()))?;
    if !state.tenants.is_member(tid, owner).await? {
        return Err(ApiError::BadRequest(
            "the owner must be a member of the organization".into(),
        ));
    }
    Ok(owner)
}

// ─── routes ─────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/vault` — whether the vault can seal (the
/// KEK's state and the recipient it wraps to; never the key), and how much
/// it holds. `other_kek` counts the versions wrapped to another KEK: a
/// non-zero count after a key change is every value that key held, gone
/// unreadable.
pub async fn status(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if !permissions::has(perms, permissions::ADMINISTRATOR) {
        return Err(ApiError::Forbidden(
            "only the organization's administrators reach its vault".into(),
        ));
    }
    let kek = match &state.kek {
        KekState::Ready(k) => json!({ "state": "ready", "recipient": k.recipient() }),
        KekState::Missing => json!({ "state": "missing" }),
        KekState::Invalid(why) => json!({ "state": "invalid", "reason": why }),
    };
    let other_kek = match state.kek.ready() {
        Some(k) => Some(state.versions.count_other_kek(tid, k.recipient()).await?),
        None => None,
    };
    Ok(Json(json!({
        "enabled": true,
        "kek": kek,
        "secrets": state.secrets.count_live(tid).await?,
        "versions": state.versions.count(tid).await?,
        "other_kek": other_kek,
    })))
}

#[derive(Deserialize, Debug, Default)]
pub struct ListQuery {
    /// A folder: `staging/` lists what is under it.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// `GET /api/tenant/{tenant_id}/vault/secret` — the live secrets, by path.
pub async fn list(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<SecretView>>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("secret:list", "list");
    decide(&state, tid, &auth, &ask).await?;
    record_allow(&state, tid, &auth, &ask).await?;
    let slug = org_slug(&state, tid).await?;
    let secrets = state.secrets.list_live(tid, q.prefix.as_deref()).await?;
    Ok(Json(
        secrets.iter().map(|s| SecretView::of(s, &slug)).collect(),
    ))
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CreateSecret {
    pub path: String,
    pub kind: String,
    /// P3-6b — a dynamic secret's provider, and only a dynamic secret's.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub exec_allow: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub rotation_days: Option<u32>,
    #[serde(default)]
    pub disabled: bool,
    /// Defaults to the caller.
    #[serde(default)]
    pub owner_id: Option<String>,
}

/// `POST /api/tenant/{tenant_id}/vault/secret` — declare a secret: its
/// path, kind and rules. It holds no value until `PUT …/value`; ⚠️ a
/// `value` here is an unknown field, refused, so a value has one way in.
pub async fn create(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateSecret>,
) -> Result<(axum::http::StatusCode, Json<SecretView>), ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let mut ask = Ask::new("secret:write", "create");
    decide(&state, tid, &auth, &ask).await?;

    let path = check_path(&body.path).map_err(ApiError::BadRequest)?;
    if !KINDS.contains(&body.kind.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "kind must be one of {}",
            KINDS.join(", ")
        )));
    }
    check_description(&body.description)?;
    check_entries("audiences", &body.audiences)?;
    // P3-6b — a dynamic secret names a provider this build knows, and one
    // audience; no other kind names a provider at all.
    let provider = match (body.kind.as_str(), &body.provider) {
        (KIND_DYNAMIC, Some(p)) => {
            let Some(p) = providers::named(p) else {
                return Err(ApiError::BadRequest(format!(
                    "provider must be one of {}",
                    providers::ALL
                        .iter()
                        .map(|p| p.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            crate::dynamic::check_audiences(&body.audiences).map_err(ApiError::BadRequest)?;
            Some(p.name.to_string())
        }
        (KIND_DYNAMIC, None) => {
            return Err(ApiError::BadRequest(
                "a dynamic secret names its provider".into(),
            ));
        }
        (_, Some(_)) => {
            return Err(ApiError::BadRequest(
                "only a dynamic secret names a provider".into(),
            ));
        }
        (_, None) => None,
    };
    check_programs(&body.exec_allow)?;
    check_tags(&body.tags)?;
    if let Some(d) = body.rotation_days {
        check_rotation(d)?;
    }
    let owner_id = match &body.owner_id {
        Some(raw) => check_owner(&state, tid, raw).await?,
        None => auth.user_id,
    };

    let slug = org_slug(&state, tid).await?;
    ask.rrn = Some(secret_rrn(&slug, path));
    record_allow(&state, tid, &auth, &ask).await?;
    let now = DateTime::now();
    let mut secret = VaultSecret {
        id: None,
        tenant_id: tid,
        path: path.to_string(),
        kind: body.kind.clone(),
        provider,
        description: body.description.clone(),
        fields: Default::default(),
        audiences: body.audiences.clone(),
        exec_allow: body.exec_allow.clone(),
        tags: body.tags.clone(),
        owner_id,
        rotation_days: body.rotation_days,
        disabled: body.disabled,
        created_by: auth.user_id,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    };
    match state.secrets.create(&secret).await {
        Ok(id) => secret.id = Some(id),
        Err(e) if is_path_taken(&e) => {
            return Err(ApiError::Conflict(format!(
                "a secret already lives at {path}"
            )));
        }
        Err(e) => return Err(e.into()),
    }
    Ok((
        axum::http::StatusCode::CREATED,
        Json(SecretView::of(&secret, &slug)),
    ))
}

/// `GET /api/tenant/{tenant_id}/vault/secret/{secret_id}` — one secret and
/// its versions' metadata (number, KEK, author, expiry): never their bytes,
/// which the read does not even load.
pub async fn describe(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, secret_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let mut ask = Ask::new("secret:list", "describe").secret(ObjectId::parse_str(&secret_id).ok());
    decide(&state, tid, &auth, &ask).await?;
    let id = parse_secret_id(&secret_id)?;
    let secret = live_secret(&state, tid, id).await?;
    let slug = org_slug(&state, tid).await?;
    ask.rrn = Some(secret_rrn(&slug, &secret.path));
    record_allow(&state, tid, &auth, &ask).await?;
    let versions: Vec<VersionView> = state
        .versions
        .list_meta(id)
        .await?
        .iter()
        .map(|v| VersionView::of(v, &secret))
        .collect();
    let mut out = serde_json::to_value(SecretView::of(&secret, &slug))
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    out["versions"] =
        serde_json::to_value(versions).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(out))
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct PatchSecret {
    pub description: Option<String>,
    pub audiences: Option<Vec<String>>,
    pub exec_allow: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    /// `0` clears it.
    pub rotation_days: Option<u32>,
    pub disabled: Option<bool>,
    pub owner_id: Option<String>,
}

/// `PATCH /api/tenant/{tenant_id}/vault/secret/{secret_id}` — change a
/// secret's rules. Its path and kind never change (unknown fields here):
/// a policy names a secret by its RRN, and a rename would silently re-point
/// every policy that names it.
pub async fn update(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, secret_id)): Path<(String, String)>,
    Json(body): Json<PatchSecret>,
) -> Result<Json<SecretView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let mut ask = Ask::new("secret:write", "update").secret(ObjectId::parse_str(&secret_id).ok());
    decide(&state, tid, &auth, &ask).await?;
    let id = parse_secret_id(&secret_id)?;

    let mut set = Document::new();
    if let Some(d) = &body.description {
        check_description(d)?;
        set.insert("description", d.clone());
    }
    if let Some(a) = &body.audiences {
        check_entries("audiences", a)?;
        set.insert("audiences", a.clone());
    }
    if let Some(x) = &body.exec_allow {
        check_programs(x)?;
        set.insert("exec_allow", x.clone());
    }
    if let Some(t) = &body.tags {
        check_tags(t)?;
        set.insert("tags", t.clone());
    }
    if let Some(d) = body.rotation_days {
        if d == 0 {
            set.insert("rotation_days", bson::Bson::Null);
        } else {
            check_rotation(d)?;
            set.insert("rotation_days", i64::from(d));
        }
    }
    if let Some(d) = body.disabled {
        set.insert("disabled", d);
    }
    if let Some(raw) = &body.owner_id {
        set.insert("owner_id", check_owner(&state, tid, raw).await?);
    }
    if set.is_empty() {
        return Err(ApiError::BadRequest("nothing to change".into()));
    }

    let secret = live_secret(&state, tid, id).await?;
    // P3-6b — a dynamic secret keeps its one audience.
    if secret.kind == KIND_DYNAMIC
        && let Some(a) = &body.audiences
    {
        crate::dynamic::check_audiences(a).map_err(ApiError::BadRequest)?;
    }
    let slug = org_slug(&state, tid).await?;
    ask.rrn = Some(secret_rrn(&slug, &secret.path));
    record_allow(&state, tid, &auth, &ask).await?;
    if !state.secrets.update_live(tid, id, set).await? {
        return Err(ApiError::NotFound("no such secret".into()));
    }
    // P3-3c — disabled: what it has released is taken back.
    if body.disabled == Some(true) {
        crate::revoke::secret_changed(&state, id, None, None, RevokeReason::SecretDisabled).await;
    }
    let secret = live_secret(&state, tid, id).await?;
    Ok(Json(SecretView::of(&secret, &slug)))
}

/// `DELETE /api/tenant/{tenant_id}/vault/secret/{secret_id}` — tombstone
/// the secret, then destroy every version of it. There is no undo: the
/// values are gone, and the path is free for a new secret, which gets a new
/// id. The tombstone is a compare-and-set, so of two deletes one acts.
pub async fn delete(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, secret_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let mut ask = Ask::new("secret:delete", "delete").secret(ObjectId::parse_str(&secret_id).ok());
    decide(&state, tid, &auth, &ask).await?;
    let id = parse_secret_id(&secret_id)?;
    let secret = live_secret(&state, tid, id).await?;
    let slug = org_slug(&state, tid).await?;
    ask.rrn = Some(secret_rrn(&slug, &secret.path));
    record_allow(&state, tid, &auth, &ask).await?;
    if !state.secrets.tombstone(tid, id).await? {
        return Err(ApiError::NotFound("no such secret".into()));
    }
    // P3-3c — what it has released is taken back.
    crate::revoke::secret_changed(&state, id, None, None, RevokeReason::SecretDeleted).await;
    // The tombstone first: a version delete that fails after it leaves
    // ciphertext no route reaches — a leak to sweep, never a secret back.
    let destroyed = state.versions.delete_for_secret(id).await?;
    Ok(Json(
        json!({ "deleted": true, "versions_destroyed": destroyed }),
    ))
}

/// ⚠️ `Debug` by hand: a `?body` in a log line must never print the value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutValue {
    /// `value` for a static secret (the default); a field name for a
    /// structured one.
    #[serde(default)]
    pub field: Option<String>,
    pub value: String,
    /// RFC 3339; in the future. Honoured by the first step that USES a
    /// value (P3-3's leases never hand out an expired version).
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for PutValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutValue")
            .field("field", &self.field)
            .field("value", &format_args!("<{} bytes>", self.value.len()))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// `PUT /api/tenant/{tenant_id}/vault/secret/{secret_id}/value` — write a
/// field's next version, sealed under a fresh data key wrapped to the KEK.
/// Answers the version's number, never the value. A field keeps its last
/// [`KEEP_VERSIONS`]; older ones are destroyed.
pub async fn put_value(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, secret_id)): Path<(String, String)>,
    Json(mut body): Json<PutValue>,
) -> Result<Json<Value>, ApiError> {
    let result = put_value_inner(&state, &auth, &tenant_id, &secret_id, &body).await;
    // The request's copy of the value, zeroed whatever happened. (What the
    // JSON parser and the socket buffered is out of reach: best effort.)
    body.value.zeroize();
    result
}

async fn put_value_inner(
    state: &VaultState,
    auth: &AuthUser,
    tenant_id: &str,
    secret_id: &str,
    body: &PutValue,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(state, tenant_id, auth).await?;
    let mut ask = Ask::new("secret:write", "value").secret(ObjectId::parse_str(secret_id).ok());
    decide(state, tid, auth, &ask).await?;
    let id = parse_secret_id(secret_id)?;
    let secret = live_secret(state, tid, id).await?;

    let field = body.field.as_deref().unwrap_or(STATIC_FIELD);
    let field = check_field(field).map_err(ApiError::BadRequest)?;
    match secret.kind.as_str() {
        KIND_STATIC if field != STATIC_FIELD => {
            return Err(ApiError::BadRequest(format!(
                "a static secret has one field, {STATIC_FIELD}"
            )));
        }
        KIND_STATIC => {}
        KIND_STRUCTURED => {
            if !secret.fields.contains_key(field) && secret.fields.len() >= MAX_FIELDS {
                return Err(ApiError::BadRequest(format!(
                    "a structured secret holds at most {MAX_FIELDS} fields"
                )));
            }
        }
        // P3-6b — the issuer's fields, as its provider names them.
        KIND_DYNAMIC => match crate::dynamic::provider_of(&secret) {
            Some(p) => {
                crate::dynamic::check_issuer_field(p, field).map_err(ApiError::BadRequest)?
            }
            None => {
                return Err(ApiError::BadRequest(format!(
                    "this server cannot write a secret of provider {}",
                    secret.provider.as_deref().unwrap_or("")
                )));
            }
        },
        other => {
            return Err(ApiError::BadRequest(format!(
                "this server cannot write a secret of kind {other}"
            )));
        }
    }
    if body.value.is_empty() || body.value.len() > MAX_VALUE_LEN {
        return Err(ApiError::BadRequest(format!(
            "value must be 1 to {MAX_VALUE_LEN} bytes"
        )));
    }
    let expires_at = match &body.expires_at {
        Some(raw) => {
            let t = DateTime::parse_rfc3339_str(raw)
                .map_err(|_| ApiError::BadRequest("expires_at must be an RFC 3339 time".into()))?;
            if t <= DateTime::now() {
                return Err(ApiError::BadRequest("expires_at is in the past".into()));
            }
            Some(t)
        }
        None => None,
    };
    let kek = kek_or_503(state)?;

    // The number first (an `$inc`: a write that fails later leaves a gap,
    // never a reused number), so the allow names the version it allows.
    let Some(n) = state.secrets.next_version(tid, id, field).await? else {
        return Err(ApiError::NotFound("no such secret".into()));
    };
    let slug = org_slug(state, tid).await?;
    ask.rrn = Some(secret_rrn(&slug, &secret.path));
    ask.field = Some(field.to_string());
    ask.n = Some(n);
    record_allow(state, tid, auth, &ask).await?;

    let at = Binding {
        tenant_id: tid,
        secret_id: id,
        field,
        n,
    };
    let sealed = kek.seal(&at, body.value.as_bytes()).map_err(|e| {
        error!(?e, "vault: sealing a value failed");
        ApiError::Internal("the vault could not seal the value".into())
    })?;
    let now = DateTime::now();
    let version = VaultVersion {
        id: None,
        tenant_id: tid,
        secret_id: id,
        field: field.to_string(),
        n,
        ciphertext: binary(sealed.ciphertext),
        nonce: binary(sealed.nonce),
        dek_wrapped: binary(sealed.dek_wrapped),
        kek: sealed.kek,
        created_by: auth.user_id,
        created_at: now,
        expires_at,
    };
    let version_id = state.versions.insert(&version).await?;
    if !state.secrets.mark_current(tid, id, field, n).await? {
        // Deleted while this was written: the version goes too, rather than
        // outliving its secret.
        if let Err(e) = state.versions.delete_one(version_id).await {
            warn!(%e, "vault: a version written as its secret was deleted could not be removed");
        }
        return Err(ApiError::NotFound("no such secret".into()));
    }
    // P3-3c — the field's leases of older versions are taken back; (P3-6b)
    // a dynamic secret's, every lease of it, since each bundle carried every
    // field.
    if secret.kind == KIND_DYNAMIC {
        crate::revoke::secret_changed(state, id, None, None, RevokeReason::ValueChanged).await;
    } else {
        crate::revoke::secret_changed(state, id, Some(field), Some(n), RevokeReason::ValueChanged)
            .await;
    }
    if n > KEEP_VERSIONS
        && let Err(e) = state.versions.prune(id, field, n - KEEP_VERSIONS + 1).await
    {
        warn!(%e, "vault: older versions could not be pruned");
    }
    Ok(Json(json!({
        "field": field,
        "n": n,
        "created_at": rfc3339(now),
        "expires_at": expires_at.map(rfc3339),
    })))
}

/// One version that did not open, in a verify's answer.
#[derive(Serialize, Debug)]
pub struct VerifyFailure {
    pub secret_id: String,
    pub field: String,
    pub n: i64,
    /// `other_kek` | `dek_unreadable` | `tampered`.
    pub reason: &'static str,
}

/// `POST /api/tenant/{tenant_id}/vault/verify` — open every version the
/// organization holds (at most [`MAX_VERIFY`]) with this server's KEK, and
/// answer which do not open and why. Never a value: each is zeroed as soon
/// as it has opened. What a KEK change or a restore must show before it is
/// trusted.
pub async fn verify(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("vault:verify", "verify");
    decide(&state, tid, &auth, &ask).await?;
    let kek = kek_or_503(&state)?;
    record_allow(&state, tid, &auth, &ask).await?;
    let versions = state.versions.scan(tid).await?;
    let total = versions.len();
    // Opening is CPU work (an X25519 agreement per version): off the
    // request's executor thread.
    let (ok, failed, failures) = tokio::task::spawn_blocking(move || {
        let mut ok = 0usize;
        let mut failed = 0usize;
        let mut failures = Vec::new();
        for v in &versions {
            let at = Binding {
                tenant_id: v.tenant_id,
                secret_id: v.secret_id,
                field: &v.field,
                n: v.n,
            };
            match kek.open(
                &at,
                &v.ciphertext.bytes,
                &v.nonce.bytes,
                &v.dek_wrapped.bytes,
                &v.kek,
            ) {
                Ok(_plaintext) => ok += 1, // zeroed on drop, here
                Err(e) => {
                    failed += 1;
                    if failures.len() < MAX_VERIFY_FAILURES {
                        failures.push(VerifyFailure {
                            secret_id: v.secret_id.to_hex(),
                            field: v.field.clone(),
                            n: v.n,
                            reason: e.as_str(),
                        });
                    }
                }
            }
        }
        (ok, failed, failures)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("verify did not finish: {e}")))?;
    Ok(Json(json!({
        "versions": total,
        "ok": ok,
        "failed": failed,
        "failures": failures,
        "truncated": total as i64 >= MAX_VERIFY,
    })))
}

#[derive(Deserialize, Debug, Default)]
pub struct AuditQuery {
    /// RFC 3339: the page before this time.
    #[serde(default)]
    pub before: Option<String>,
    /// 1 to 200; 50 by default.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/tenant/{tenant_id}/vault/audit` — the organization's vault
/// decisions, newest first.
pub async fn audit(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if !permissions::has(perms, permissions::ADMINISTRATOR) {
        return Err(ApiError::Forbidden(
            "only the organization's administrators reach its vault".into(),
        ));
    }
    let before = match &q.before {
        Some(raw) => Some(
            DateTime::parse_rfc3339_str(raw)
                .map_err(|_| ApiError::BadRequest("before must be an RFC 3339 time".into()))?,
        ),
        None => None,
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows = state.audit.recent(tid, before, limit).await?;
    Ok(Json(
        rows.iter()
            .map(|e| {
                json!({
                    "id": e.id.map(|i| i.to_hex()),
                    "at": rfc3339(e.at),
                    "principal": e.principal,
                    "user_id": e.user_id.to_hex(),
                    "action": e.action,
                    "op": e.op,
                    "decision": e.decision,
                    "reason": e.reason,
                    "secret_id": e.secret_id.map(|i| i.to_hex()),
                    "rrn": e.rrn,
                    "field": e.field,
                    "n": e.n,
                    "target": e.target,
                })
            })
            .collect(),
    ))
}

#[derive(Deserialize, Debug, Default)]
pub struct ActivityQuery {
    /// RFC 3339: the page before this time.
    #[serde(default)]
    pub before: Option<String>,
    /// 1 to 200; 50 by default.
    #[serde(default)]
    pub limit: Option<i64>,
    /// One session's reports.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The reports naming one lease: where a use joins its decision.
    #[serde(default)]
    pub lease_id: Option<String>,
}

/// FR-90 P3-4d — `GET /api/tenant/{tenant_id}/vault/activity`: what the
/// organization's devices REPORT doing with their leases, newest first.
/// Claims, never decisions: `…/vault/audit` holds those. An empty answer is
/// not evidence of disuse, since a device reports only while its own
/// `vault_activity_log` is on.
pub async fn activity(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<ActivityQuery>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if !permissions::has(perms, permissions::ADMINISTRATOR) {
        return Err(ApiError::Forbidden(
            "only the organization's administrators reach its vault".into(),
        ));
    }
    let id = |raw: &Option<String>, what: &str| -> Result<Option<ObjectId>, ApiError> {
        raw.as_deref()
            .map(|s| {
                ObjectId::parse_str(s)
                    .map_err(|_| ApiError::BadRequest(format!("{what} is not an id")))
            })
            .transpose()
    };
    let session_id = id(&q.session_id, "session_id")?;
    let lease_id = id(&q.lease_id, "lease_id")?;
    let before = match &q.before {
        Some(raw) => Some(
            DateTime::parse_rfc3339_str(raw)
                .map_err(|_| ApiError::BadRequest("before must be an RFC 3339 time".into()))?,
        ),
        None => None,
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows = state
        .activity
        .recent(tid, session_id, lease_id, before, limit)
        .await?;
    Ok(Json(
        rows.iter()
            .map(|a| {
                json!({
                    "id": a.id.map(|i| i.to_hex()),
                    "at": rfc3339(a.at),
                    "device_id": a.device_id.to_hex(),
                    "session_id": a.session_id.to_hex(),
                    "fence": a.fence,
                    "kind": a.kind,
                    "lease_ids": a.lease_ids.iter().map(|l| l.to_hex()).collect::<Vec<_>>(),
                    "target": a.target,
                    "exit_code": a.exit_code,
                    "timed_out": a.timed_out,
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_never_prints() {
        // Made at run time: a literal here reads as a leaked credential to a
        // secret scanner.
        let probe = format!("probe-{}", ObjectId::new().to_hex());
        let body: PutValue = serde_json::from_value(json!({
            "field": "dsn",
            "value": probe,
        }))
        .unwrap();
        let shown = format!("{body:?} {body:#?}");
        assert!(!shown.contains(&probe), "{shown}");
        assert!(
            shown.contains("dsn") && shown.contains(&format!("<{} bytes>", probe.len())),
            "{shown}"
        );
    }

    #[test]
    fn a_value_has_one_way_in() {
        // A `value` on the create body is an unknown field, refused, not
        // dropped: a client that thinks it set one learns it did not.
        let create = serde_json::from_value::<CreateSecret>(json!({
            "path": "db", "kind": "static", "value": "hunter2",
        }));
        assert!(create.is_err());
        let patch = serde_json::from_value::<PatchSecret>(json!({ "value": "hunter2" }));
        assert!(patch.is_err());
        for renamed in [json!({ "path": "other" }), json!({ "kind": "structured" })] {
            assert!(serde_json::from_value::<PatchSecret>(renamed).is_err());
        }
    }
}
