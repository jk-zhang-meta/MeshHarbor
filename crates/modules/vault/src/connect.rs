// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-9-1 — a PERSON's use of a secret, through an endpoint their device
//! serves them (`meshharbor connect`; `docs/fr/FR-90-hive-agent-sessions.md`
//! §3e, "P3-9, `meshharbor connect`, as designed"): the vault's answer to
//! `rc:vault.connect`.
//!
//! The device asks over its own control connection, in the queue its
//! sessions' leases share, one frame per field its endpoint needs, and the
//! vault answers each as it answers a session's lease: the field sealed to
//! the device's vault key (`rc:vault.leased`), or one word
//! (`rc:vault.refused`, [`LeaseRefusal`]).
//!
//! | Check, in order | Refused as | Recorded |
//! |---|---|---|
//! | the request within its bounds: its id, the secret, the field, an upstream | `bad_request` | no |
//! | the vault serves the organization (`vault.tenants`) and lends to its people (`vault.people`) | `not_served` | no |
//! | the device takes leases: its hello advertised `vault` and carried a key | `unsupported` | no |
//! | within the device's per-minute ceiling for its owner | `busy` | no |
//! | its owner, as the device's ROW names them, a member of the organization | `denied` | yes, as `owner_not_member` |
//! | the secret, by path or by this organization's RRN, live | `no_secret` | yes |
//! | not disabled | `disabled` | yes |
//! | its field holding a value | `no_value` | yes |
//! | a usable KEK | `unavailable` | yes |
//! | Cedar's `secret:connect`, for the owner in the roles they hold | `denied` | yes, with the request |
//! | where it denied: whether someone's yes would lift it (decision 24) | `approval_unavailable` | yes, with the request |
//! | its version not past the `expires_at` its writer gave | `no_value` | yes |
//! | opened, and sealed to the device's key | `unavailable` | yes |
//! | the allow recorded and the lease written | `undecided` | — |
//!
//! ⚠️ The principal is the device's OWNER as its row names them, never as a
//! frame says: the frame names nobody (decision 23). A device asks for what
//! its owner may, and for nobody else.
//!
//! ⚠️ Not a session's path. A person's request shares nothing with
//! [`crate::lease::identify`], which believes every field it is given
//! against a session's record, and its lease names no session: its
//! revocation stands on the owner instead ([`crate::revoke`]).
//!
//! ⚠️ Nobody approves a person's request in P3-9 (decision 24): it has no
//! session room to post a card into. Where a policy would allow it only with
//! someone's yes, it is refused `approval_unavailable` rather than
//! `denied`, so the person knows asking someone could help once a person's
//! card has a home. The question is put to Cedar with an approver who holds
//! every role the organization has and is not the person; a policy that
//! names one approver by id is answered `denied`.
//!
//! ⚠️ The allow is recorded and the lease written BEFORE the sealed value is
//! sent, as for a session: a lease the vault could not record is never
//! released.
//!
//! ⚠️ The ceiling is checked before anything is recorded, and nothing is
//! recorded before the device is identified: a device's flood must not
//! become audit rows.

use bson::{DateTime, oid::ObjectId};
use meshharbor_remote_control::{
    models::{Agent, RpcCap},
    vault::{LeaseRefusal, lease_limits},
};
use meshharbor_services::dao::base::DaoError;
use tracing::warn;

use crate::VaultState;
use crate::crypto;
use crate::lease::{Conn, Leased, Record, open_one, os_name, path_of, reason_of};
use crate::model::{VaultLease, VaultSecret};
use crate::policy::{self, Approver, Ask, DeviceFacts, SecretFacts};
use crate::policy_routes::{decide_for_org, groups_of_member, org_groups};
use crate::rrn;

/// The one mode a person's lease is in: the device holds the value, and
/// serves an endpoint that signs in with it. Never a value handed to the
/// person (`raw`, the design's `meshharbor vault get`, is not this verb).
pub const CONNECT_MODE: &str = "proxy";

/// One `rc:vault.connect`, as it arrived.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub req_id: String,
    pub secret: String,
    pub field: String,
    pub audience: String,
    pub ttl_secs: u32,
}

/// Whether the request is within its bounds: an id an answer can name, a
/// secret, a field, and the upstream its endpoint signs in to — always one,
/// since an endpoint signs in somewhere.
fn within_bounds(req: &ConnectRequest) -> bool {
    let printable = |s: &str| !s.chars().any(char::is_control);
    !req.req_id.is_empty()
        && req.req_id.len() <= lease_limits::MAX_REQ_ID_LEN
        && printable(&req.req_id)
        && !req.secret.is_empty()
        && req.secret.len() <= lease_limits::MAX_SECRET_LEN
        && req.field.len() <= lease_limits::MAX_FIELD_LEN
        && !req.audience.is_empty()
        && req.audience.len() <= lease_limits::MAX_AUDIENCE_LEN
        && printable(&req.audience)
}

/// Decide one request for the device's owner, and release the field when it
/// is allowed.
pub async fn connect(
    state: &VaultState,
    conn: Conn,
    req: &ConnectRequest,
) -> Result<Leased, LeaseRefusal> {
    if !within_bounds(req) {
        return Err(LeaseRefusal::BadRequest);
    }
    let tid = conn.tenant_id;
    if !state.scope.serves(tid) || !state.people.serves(tid) {
        return Err(LeaseRefusal::NotServed);
    }
    let agent = match state.agents.find_live_in_tenant(tid, conn.device_id).await {
        Ok(a) => a,
        Err(DaoError::NotFound) => return Err(LeaseRefusal::Unsupported),
        Err(e) => {
            warn!(device = %conn.device_id, %e, "vault: a person's request's device was not read");
            return Err(LeaseRefusal::Unavailable);
        }
    };
    if !agent.capabilities.has_rpc(RpcCap::Vault) || agent.vault_key.is_empty() {
        return Err(LeaseRefusal::Unsupported);
    }
    // The principal, from the ROW.
    let owner = agent.owner_user_id;
    if !state
        .person_limiter
        .check(owner, conn.device_id, lease_limits::CONNECT_PER_MINUTE)
    {
        return Err(LeaseRefusal::Busy);
    }
    let mut rec = Record {
        state,
        conn,
        session_id: None,
        owner,
        asked: &req.secret,
        secret: None,
        action: policy::ACTION_CONNECT,
        op: "connect",
        approval: None,
        grant: None,
        ticket: None,
    };
    // A device can outlive its owner's place in the organization: a person
    // removed from it is nobody's principal here, whatever a policy says.
    match state.tenants.is_member(tid, owner).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(rec.refuse(LeaseRefusal::Denied, "owner_not_member").await);
        }
        Err(e) => {
            warn!(device = %conn.device_id, %e, "vault: a person's membership was not read");
            return Err(rec.refuse(LeaseRefusal::Unavailable, "owner_unread").await);
        }
    }
    decide_and_release(state, &mut rec, &agent, req).await
}

/// From the owner on: the secret, the decision, the value.
async fn decide_and_release(
    state: &VaultState,
    rec: &mut Record<'_>,
    agent: &Agent,
    req: &ConnectRequest,
) -> Result<Leased, LeaseRefusal> {
    let tid = rec.conn.tenant_id;
    let Ok(slug) = crate::routes::org_slug(state, tid).await else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "org_unread").await);
    };
    let secret: VaultSecret = match path_of(&req.secret, &slug) {
        None => {
            let why = LeaseRefusal::NoSecret;
            return Err(rec.refuse(why, why.wire()).await);
        }
        Some(path) => match state.secrets.find_live_by_path(tid, &path).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                let why = LeaseRefusal::NoSecret;
                return Err(rec.refuse(why, why.wire()).await);
            }
            Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "secret_unread").await),
        },
    };
    let Some(secret_id) = secret.id else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "secret_unread").await);
    };
    // One field at a time, a dynamic secret's included: its fields are its
    // issuer's, which a guardrail keeps from any person
    // (`guardrail:connect-never-dynamic`).
    let field = if req.field.is_empty() {
        rrn::STATIC_FIELD
    } else {
        req.field.as_str()
    };
    let n = secret
        .fields
        .get(field)
        .map(|f| f.current)
        .filter(|n| *n > 0);
    rec.secret = Some((
        secret_id,
        rrn::secret_rrn(&slug, &secret.path),
        field.to_string(),
        n,
    ));
    if secret.disabled {
        let why = LeaseRefusal::Disabled;
        return Err(rec.refuse(why, why.wire()).await);
    }
    let Some(n) = n else {
        let why = LeaseRefusal::NoValue;
        return Err(rec.refuse(why, why.wire()).await);
    };
    let Some(kek) = state.kek.ready() else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "no_kek").await);
    };
    let device = match DeviceFacts::new(os_name(agent.os), &agent.tags, agent.owner_user_id) {
        Ok(d) => d,
        Err(why) => {
            return Err(rec
                .refuse(LeaseRefusal::Denied, &format!("device: {why}"))
                .await);
        }
    };
    let groups = match groups_of_member(state, tid, rec.owner).await {
        Ok(g) => g,
        Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "owner_unread").await),
    };
    let ttl = req
        .ttl_secs
        .clamp(lease_limits::MIN_TTL_SECS, lease_limits::MAX_TTL_SECS);
    let ask = Ask::ConnectSecret {
        user: rec.owner,
        groups,
        secret: SecretFacts {
            prefix: rrn::secret_rrn(&slug, ""),
            path: secret.path.clone(),
            kind: secret.kind.clone(),
            tags: secret.tags.clone(),
            exec_allow: secret.exec_allow.clone(),
            audiences: secret.audiences.clone(),
        },
        audience: req.audience.clone(),
        ttl_s: i64::from(ttl),
        device,
        approver: None,
    };
    let verdict = decide_for_org(state, tid, &ask).await;
    let reason = reason_of(&verdict);
    if !verdict.allow {
        // Decision 24 — a yes nobody can give is said, not waited for.
        let (why, recorded) = if approvable(state, tid, &ask).await {
            let why = LeaseRefusal::ApprovalUnavailable;
            (why, why.wire().to_string())
        } else {
            (LeaseRefusal::Denied, reason)
        };
        if let Err(e) = rec.decided(false, &recorded, &ask, None).await {
            warn!(device = %rec.conn.device_id, %e, "vault: a person's deny was not recorded");
        }
        return Err(why);
    }

    // Allowed: open the value and seal it for the device, BEFORE the allow is
    // recorded, so a recorded allow is one that was ready to release.
    let (value, until) = open_one(state, rec, kek, secret_id, field, n).await?;
    let sealed = match crypto::seal_for_device(&agent.vault_key, &value) {
        Ok(s) => s,
        Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "seal").await),
    };
    drop(value);
    let lease_id = ObjectId::new();
    if let Err(e) = rec.decided(true, &reason, &ask, Some(lease_id)).await {
        warn!(device = %rec.conn.device_id, %e, "vault: a person's allow was not recorded — not released");
        return Err(LeaseRefusal::Undecided);
    }
    let issued_at = DateTime::now();
    let mut expires_at =
        DateTime::from_millis(issued_at.timestamp_millis() + i64::from(ttl) * 1000);
    // No lease outlives its version.
    if let Some(until) = until
        && until < expires_at
    {
        expires_at = until;
    }
    let row = VaultLease {
        id: Some(lease_id),
        tenant_id: tid,
        secret_id,
        field: field.to_string(),
        n,
        bundle: None,
        session_id: None,
        fence: 0,
        device_id: rec.conn.device_id,
        owner_id: rec.owner,
        sealed_to: agent.vault_key.clone(),
        mode: CONNECT_MODE.to_string(),
        audience: req.audience.clone(),
        issued_at,
        expires_at,
        revoked_at: None,
        revoked_why: None,
    };
    if let Err(e) = state.leases.insert(&row).await {
        warn!(device = %rec.conn.device_id, %e, "vault: a person's lease was not written — not released");
        return Err(LeaseRefusal::Undecided);
    }
    Ok(Leased {
        lease_id,
        n,
        sealed,
        expires_at,
        provider: None,
    })
}

/// Decision 24 — whether someone's yes would lift Cedar's deny of `ask`:
/// decided again with an approver who holds every role the organization has
/// and is not the person. Nothing read, nothing lifted: a refusal either way.
async fn approvable(state: &VaultState, tid: ObjectId, ask: &Ask) -> bool {
    let Ok(groups) = org_groups(state, tid).await else {
        return false;
    };
    decide_for_org(state, tid, &with_any_approver(ask, groups))
        .await
        .allow
}

/// `ask`, with an approver who is nobody in particular, in `groups`.
fn with_any_approver(ask: &Ask, groups: Vec<String>) -> Ask {
    let mut probe = ask.clone();
    if let Ask::ConnectSecret { approver, .. } = &mut probe {
        *approver = Some(Approver {
            id: ObjectId::new(),
            groups,
        });
    }
    probe
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{decide, policy_set};

    fn req() -> ConnectRequest {
        ConnectRequest {
            req_id: "c1".into(),
            secret: "db/main".into(),
            field: "password".into(),
            audience: "db.internal:5432".into(),
            ttl_secs: 300,
        }
    }

    /// A request names itself, a secret and the upstream its endpoint signs
    /// in to; anything else is refused before the device is read.
    #[test]
    fn a_request_is_held_to_its_bounds() {
        assert!(within_bounds(&req()));
        assert!(within_bounds(&ConnectRequest {
            field: String::new(),
            ..req()
        }));
        for bad in [
            ConnectRequest {
                req_id: String::new(),
                ..req()
            },
            ConnectRequest {
                req_id: "a\nb".into(),
                ..req()
            },
            ConnectRequest {
                req_id: "r".repeat(lease_limits::MAX_REQ_ID_LEN + 1),
                ..req()
            },
            ConnectRequest {
                secret: String::new(),
                ..req()
            },
            ConnectRequest {
                secret: "s".repeat(lease_limits::MAX_SECRET_LEN + 1),
                ..req()
            },
            ConnectRequest {
                field: "f".repeat(lease_limits::MAX_FIELD_LEN + 1),
                ..req()
            },
            ConnectRequest {
                audience: String::new(),
                ..req()
            },
            ConnectRequest {
                audience: "db\u{0}".into(),
                ..req()
            },
            ConnectRequest {
                audience: "a".repeat(lease_limits::MAX_AUDIENCE_LEN + 1),
                ..req()
            },
        ] {
            assert!(!within_bounds(&bad), "{bad:?}");
        }
    }

    fn connect_ask(groups: &[&str]) -> Ask {
        let owner = ObjectId::new();
        Ask::ConnectSecret {
            user: owner,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            secret: SecretFacts {
                prefix: "rrn:grox:secret:".into(),
                path: "db/main".into(),
                kind: "structured".into(),
                tags: Vec::new(),
                exec_allow: Vec::new(),
                audiences: vec!["db.internal:5432".into()],
            },
            audience: "db.internal:5432".into(),
            ttl_s: 300,
            device: DeviceFacts::new("linux", &[], owner).unwrap(),
            approver: None,
        }
    }

    /// Decision 24 — the question the vault puts to Cedar: the same request,
    /// with an approver in every role who is not the person. A policy that
    /// asks for a yes is lifted by it, one that asks for nothing more is not,
    /// and a policy that refuses a person's own yes still holds.
    #[test]
    fn a_yes_is_asked_of_an_approver_in_every_role_who_is_not_the_person() {
        let roles = vec!["admin".to_string(), "member".to_string()];
        let set = policy_set([(
            "policy:0".to_string(),
            r#"permit (principal in MeshHarbor::Group::"member",
                action == MeshHarbor::Action::"secret:connect", resource)
               when { context has approval
                      && context.approval.approver in MeshHarbor::Group::"admin"
                      && context.approval.approver != principal };"#,
        )])
        .unwrap();
        let ask = connect_ask(&["member"]);
        assert!(!decide(&set, &ask).allow, "no yes was given");
        let probe = with_any_approver(&ask, roles.clone());
        assert!(decide(&set, &probe).allow, "an admin's yes would lift it");
        let (Ask::ConnectSecret { user, .. }, Ask::ConnectSecret { approver, .. }) = (&ask, &probe)
        else {
            unreachable!()
        };
        let approver = approver.as_ref().unwrap();
        assert_ne!(approver.id, *user, "nobody approves their own use");
        assert_eq!(approver.groups, roles);
        // A policy that names one approver by id is not lifted by just any.
        let named = policy_set([(
            "policy:0".to_string(),
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource)
               when { context has approval
                      && context.approval.approver == MeshHarbor::User::"65f0000000000000000000a1" };"#,
        )])
        .unwrap();
        assert!(!decide(&named, &probe).allow);
    }
}
