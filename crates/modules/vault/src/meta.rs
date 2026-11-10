// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-4b — what a session may know of the vault's secrets: their names and
//! rules, never a value. A session's tools list (`rc:vault.list`) and
//! describe (`rc:vault.describe`) over its device's control connection.
//!
//! | Check, in order | Refused as | Recorded |
//! |---|---|---|
//! | the request within its bounds | `bad_request` | no |
//! | believed as a lease is ([`lease::identify`]): served, the device takes leases, the session's record on THIS device, at its fence, live, within its per-minute ceiling | a lease's words | as a lease's |
//! | holding a vault role | `no_role` | yes |
//! | describe: the secret, by path or this organization's RRN, live | `no_secret` | yes |
//! | Cedar's `secret:list`, the device's facts from its ROW | describe: `denied`; a listing leaves it out | describe: yes, with the request; a listing: one row a call |
//! | the decision recorded before it is answered | `undecided` | — |
//!
//! ⚠️ Listing is its own permission (`secret:list`): a role allowed to use a
//! secret lists nothing until a policy lets it list, and listing uses nothing.
//!
//! ⚠️ A listing answers only what the role may list, at most
//! [`lease_limits::MAX_LISTED`], and says `more` when the bound left some
//! out. It never says which were refused, nor how many.

use meshharbor_mod_hive::model::AgentSession;
use meshharbor_remote_control::models::Agent;
use meshharbor_remote_control::vault::{LeaseRefusal, VaultSecretMeta, lease_limits};
use tracing::warn;

use crate::VaultState;
use crate::lease::{self, Conn, DescribeRequest, ListRequest, Record};
use crate::model::VaultSecret;
use crate::policy::{self, Ask, DeviceFacts, SecretFacts, SessionFacts};
use crate::policy_routes::{decide_for_org, org_set};
use crate::rrn;

fn printable(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

fn req_id_ok(req_id: &str) -> bool {
    !req_id.is_empty() && req_id.len() <= lease_limits::MAX_REQ_ID_LEN && printable(req_id)
}

/// What a session is told of a secret: never a value, a version's number,
/// or who wrote it.
pub fn meta_of(secret: &VaultSecret, slug: &str) -> VaultSecretMeta {
    // P3-6b — a dynamic secret's fields are its issuer's, which no session
    // names: it is told the minted credential's instead.
    let dynamic =
        crate::dynamic::provider_of(secret).filter(|_| secret.kind == crate::model::KIND_DYNAMIC);
    VaultSecretMeta {
        rrn: rrn::secret_rrn(slug, &secret.path),
        path: secret.path.clone(),
        kind: secret.kind.clone(),
        provider: dynamic.map(|p| p.name.to_string()),
        description: secret.description.clone(),
        fields: match dynamic {
            Some(p) => p.minted.iter().map(|f| (*f).to_string()).collect(),
            None if secret.kind == crate::model::KIND_DYNAMIC => Vec::new(),
            None => secret
                .fields
                .iter()
                .filter(|(_, f)| f.current > 0)
                .map(|(name, _)| name.clone())
                .collect(),
        },
        audiences: secret.audiences.clone(),
        exec_allow: secret.exec_allow.clone(),
        tags: secret.tags.clone(),
        disabled: secret.disabled,
    }
}

/// The session in its role, and the device from its ROW: what every
/// `secret:list` decision of one request is made with.
async fn facts(
    rec: &Record<'_>,
    session: &AgentSession,
    agent: &Agent,
) -> Result<(SessionFacts, DeviceFacts), LeaseRefusal> {
    let Some(role) = session.vault_role.clone() else {
        let why = LeaseRefusal::NoRole;
        return Err(rec.refuse(why, why.wire()).await);
    };
    let device = match DeviceFacts::new(lease::os_name(agent.os), &agent.tags, agent.owner_user_id)
    {
        Ok(d) => d,
        Err(why) => {
            return Err(rec
                .refuse(LeaseRefusal::Denied, &format!("device: {why}"))
                .await);
        }
    };
    Ok((
        SessionFacts {
            id: rec.session_id.map(|s| s.to_hex()).unwrap_or_default(),
            owner: session.owner_id,
            role: Some(role),
            playbook: None,
        },
        device,
    ))
}

fn secret_facts(secret: &VaultSecret, slug: &str) -> SecretFacts {
    SecretFacts {
        prefix: rrn::secret_rrn(slug, ""),
        path: secret.path.clone(),
        kind: secret.kind.clone(),
        tags: secret.tags.clone(),
        exec_allow: secret.exec_allow.clone(),
        audiences: secret.audiences.clone(),
    }
}

/// `rc:vault.list`: what the session's role may list, under `prefix`.
pub async fn list(
    state: &VaultState,
    conn: Conn,
    req: &ListRequest,
) -> Result<(Vec<VaultSecretMeta>, bool), LeaseRefusal> {
    if !req_id_ok(&req.req_id)
        || req.prefix.len() > lease_limits::MAX_SECRET_LEN
        || !printable(&req.prefix)
    {
        return Err(LeaseRefusal::BadRequest);
    }
    let asked = if req.prefix.is_empty() {
        "*"
    } else {
        req.prefix.as_str()
    };
    let (agent, session, rec) = lease::identify(
        state,
        conn,
        req.session_id,
        req.fence,
        asked,
        policy::ACTION_LIST,
        "list",
    )
    .await?;
    let (session_facts, device) = facts(&rec, &session, &agent).await?;
    let tid = conn.tenant_id;
    let Ok(slug) = crate::routes::org_slug(state, tid).await else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "org_unread").await);
    };
    let prefix = (!req.prefix.is_empty()).then_some(req.prefix.as_str());
    let Ok(secrets) = state.secrets.list_live(tid, prefix).await else {
        return Err(rec
            .refuse(LeaseRefusal::Unavailable, "secrets_unread")
            .await);
    };
    // The set once, every secret decided against it.
    let set = match org_set(state, tid).await {
        Ok((set, _)) => set,
        Err(why) => return Err(rec.refuse(LeaseRefusal::Unavailable, &why).await),
    };
    // The store's own bound cut the listing short.
    let mut more = i64::try_from(secrets.len()).unwrap_or(i64::MAX) >= crate::dao::MAX_LIST;
    let mut listed = Vec::new();
    for s in &secrets {
        let ask = Ask::ListSecret {
            session: session_facts.clone(),
            secret: secret_facts(s, &slug),
            device: device.clone(),
        };
        if policy::decide(&set, &ask).allow {
            if listed.len() == lease_limits::MAX_LISTED {
                more = true;
                break;
            }
            listed.push(meta_of(s, &slug));
        }
    }
    // One row a call, before the answer: an aggregate, not a decision a
    // replay could decide again.
    let reason = format!("listed {} of {}", listed.len(), secrets.len());
    if let Err(e) = state
        .audit
        .record(&rec.event(true, &reason, None, None))
        .await
    {
        warn!(session = %req.session_id, %e, "vault: a listing was not recorded — not answered");
        return Err(LeaseRefusal::Undecided);
    }
    Ok((listed, more))
}

/// `rc:vault.describe`: one secret's metadata, when the session's role may
/// list it.
pub async fn describe(
    state: &VaultState,
    conn: Conn,
    req: &DescribeRequest,
) -> Result<VaultSecretMeta, LeaseRefusal> {
    if !req_id_ok(&req.req_id)
        || req.secret.is_empty()
        || req.secret.len() > lease_limits::MAX_SECRET_LEN
        || !printable(&req.secret)
    {
        return Err(LeaseRefusal::BadRequest);
    }
    let (agent, session, mut rec) = lease::identify(
        state,
        conn,
        req.session_id,
        req.fence,
        &req.secret,
        policy::ACTION_LIST,
        "describe",
    )
    .await?;
    let (session_facts, device) = facts(&rec, &session, &agent).await?;
    let tid = conn.tenant_id;
    let Ok(slug) = crate::routes::org_slug(state, tid).await else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "org_unread").await);
    };
    let Some(path) = lease::path_of(&req.secret, &slug) else {
        let why = LeaseRefusal::NoSecret;
        return Err(rec.refuse(why, why.wire()).await);
    };
    let secret = match state.secrets.find_live_by_path(tid, &path).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            let why = LeaseRefusal::NoSecret;
            return Err(rec.refuse(why, why.wire()).await);
        }
        Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "secret_unread").await),
    };
    let Some(secret_id) = secret.id else {
        return Err(rec.refuse(LeaseRefusal::Unavailable, "secret_unread").await);
    };
    rec.secret = Some((
        secret_id,
        rrn::secret_rrn(&slug, &secret.path),
        String::new(),
        None,
    ));
    let ask = Ask::ListSecret {
        session: session_facts,
        secret: secret_facts(&secret, &slug),
        device,
    };
    let verdict = decide_for_org(state, tid, &ask).await;
    let reason = lease::reason_of(&verdict);
    if !verdict.allow {
        if let Err(e) = rec.decided(false, &reason, &ask, None).await {
            warn!(session = %req.session_id, %e, "vault: a describe's deny was not recorded");
        }
        return Err(LeaseRefusal::Denied);
    }
    if let Err(e) = rec.decided(true, &reason, &ask, None).await {
        warn!(session = %req.session_id, %e, "vault: a describe's allow was not recorded — not answered");
        return Err(LeaseRefusal::Undecided);
    }
    Ok(meta_of(&secret, &slug))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FieldState;
    use bson::{DateTime, oid::ObjectId};

    /// What a session is told of a secret holds no value and no person: the
    /// fields that hold one, by name, and the rules.
    #[test]
    fn a_secrets_metadata_names_its_fields_and_rules_only() {
        let now = DateTime::now();
        let field = |current: i64| FieldState {
            seq: current,
            current,
            updated_at: Some(now),
        };
        let secret = VaultSecret {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            path: "db/main".into(),
            kind: "structured".into(),
            provider: None,
            description: "the main database".into(),
            fields: [
                ("password".to_string(), field(3)),
                ("username".to_string(), field(1)),
                ("unwritten".to_string(), field(0)),
            ]
            .into_iter()
            .collect(),
            audiences: vec!["db.internal".into()],
            exec_allow: vec!["psql".into()],
            tags: vec!["staging".into()],
            owner_id: ObjectId::new(),
            rotation_days: None,
            disabled: false,
            created_by: ObjectId::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let meta = meta_of(&secret, "grox");
        assert_eq!(meta.rrn, "rrn:grox:secret:db/main");
        assert_eq!(
            meta.fields,
            ["password", "username"],
            "a field with no value is not one"
        );
        assert_eq!(meta.exec_allow, ["psql"]);
        let wire = serde_json::to_string(&meta).unwrap();
        for absent in [
            "owner",
            "created_by",
            "\"seq\"",
            "current",
            "disabled",
            "provider",
        ] {
            assert!(!wire.contains(absent), "{absent} in {wire}");
        }
    }

    /// P3-6b — a session is told a dynamic secret's provider and the fields
    /// it may name, the minted credential's, and never its issuer's.
    #[test]
    fn a_dynamic_secrets_metadata_names_what_it_mints() {
        let now = DateTime::now();
        let field = |current| crate::model::FieldState {
            seq: current,
            current,
            updated_at: Some(now),
        };
        let mut secret = VaultSecret {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            path: "db/dyn".into(),
            kind: crate::model::KIND_DYNAMIC.into(),
            provider: Some("postgres".into()),
            description: String::new(),
            fields: [
                ("admin_user".to_string(), field(1)),
                ("admin_password".to_string(), field(2)),
                ("database".to_string(), field(1)),
            ]
            .into_iter()
            .collect(),
            audiences: vec!["db.internal:5432".into()],
            exec_allow: Vec::new(),
            tags: Vec::new(),
            owner_id: ObjectId::new(),
            rotation_days: None,
            disabled: false,
            created_by: ObjectId::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let meta = meta_of(&secret, "grox");
        assert_eq!(meta.provider.as_deref(), Some("postgres"));
        assert_eq!(
            meta.fields,
            ["user", "password", "host", "port", "database"]
        );
        let wire = serde_json::to_string(&meta).unwrap();
        assert!(!wire.contains("admin_"), "{wire}");
        // P3-6d-1b — a MySQL issuer's secret names the same credential.
        secret.provider = Some("mysql".into());
        let meta = meta_of(&secret, "grox");
        assert_eq!(meta.provider.as_deref(), Some("mysql"));
        assert_eq!(
            meta.fields,
            ["user", "password", "host", "port", "database"]
        );
        // A provider this build cannot name: nothing to name at all.
        secret.provider = Some("from_a_newer_build".into());
        let meta = meta_of(&secret, "grox");
        assert_eq!((meta.provider, meta.fields), (None, Vec::<String>::new()));
    }
}
