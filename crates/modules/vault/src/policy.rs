// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Cedar (FR-90 P3-2, `docs/meshharbor-hive-design.md` §8.4): the vault's
//! schema, the guardrails it seeds, how a policy is checked before it is
//! stored, and the one function that decides.
//!
//! | Piece | Rule |
//! |---|---|
//! | the schema | [`SCHEMA_SRC`]; every stored policy is validated against it, strictly |
//! | default | deny: nothing is allowed that no policy permits |
//! | `forbid` | beats every `permit`, as an explicit deny does in IAM |
//! | guardrails | [`GUARDRAILS`]: code, not rows, so no organization can lose one; they are in every organization's set from its first decision |
//! | a set that fails to build | is an error, and the caller DENIES: a `forbid` that did not parse must never vanish quietly |
//! | a policy that can never apply | refused when it is written (P3-2c): Cedar reports one only as a warning, and a `forbid` like that would forbid nothing |
//!
//! ⚠️ A policy can only name its own organization: a `Secret` or
//! `SecretFolder` literal must carry the organization's RRN prefix, a `Role`
//! one of the organization's roles, a `Group` one of its meshharbor roles, a
//! `User` one of its members (that last checked by the route, which can ask
//! the database). A `Session` is never named: sessions come and go, and a
//! policy for one would outlive it.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use bson::oid::ObjectId;
use cedar_policy::{
    ActionConstraint, Authorizer, Context, Decision, Effect, Entities, EntityUid, Policy, PolicyId,
    PolicySet, Request, Schema, ValidationMode, ValidationWarning, Validator,
};
use serde_json::{Value, json};

use crate::rrn::check_path;

/// The vault's Cedar schema.
pub const SCHEMA_SRC: &str = include_str!("policy.cedarschema");

static SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    Schema::from_cedarschema_str(SCHEMA_SRC)
        .map(|(schema, _warnings)| schema)
        .expect("the vault's Cedar schema parses — a unit test holds it")
});

/// The parsed schema.
pub fn schema() -> &'static Schema {
    &SCHEMA
}

/// The Cedar namespace every vault entity lives in.
pub const NS: &str = "MeshHarbor";

/// The actions a policy may name, as the wire and the audit spell them.
pub const ACTIONS: &[&str] = &[
    ACTION_ASSUME,
    ACTION_USE,
    ACTION_LIST,
    ACTION_NET_SOCKS,
    ACTION_NET_FORWARD,
    ACTION_SSH_RUN,
    ACTION_CONNECT,
];
pub const ACTION_ASSUME: &str = "role:assume";
pub const ACTION_USE: &str = "secret:use";
/// P3-4b — a session listing or describing a secret.
pub const ACTION_LIST: &str = "secret:list";
/// P3-7 — a session opening a SOCKS5 listener whose flows exit through a
/// device (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-7, a session's own
/// egress, as designed").
pub const ACTION_NET_SOCKS: &str = "net:socks";
/// P3-7 — a session opening a forward to one destination through a device.
pub const ACTION_NET_FORWARD: &str = "net:forward";
/// P3-8 — a session running one command on another device over MeshHarbor SSH
/// (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-8, `ssh_run`, as
/// designed").
pub const ACTION_SSH_RUN: &str = "ssh:run";
/// P3-9-1 — a PERSON using a secret through an endpoint their device serves
/// them (`mh connect`; `docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-9,
/// `mh connect`, as designed"). Its principal is a `User`, the device's
/// owner: `secret:use` is a session's alone, so no policy written for
/// sessions admits a person.
pub const ACTION_CONNECT: &str = "secret:connect";

/// P3-9-1 — the actions only a permit that NAMES them in its scope admits
/// ([`decide`]). A policy whose scope names no action
/// (`permit (principal in MeshHarbor::Group::"admin", action, resource)`)
/// admits every action Cedar knows, so one written before a person's action
/// existed would admit a person the day it did, without a line of it
/// changing. A `forbid` binds whatever its scope, as it always did.
pub const NAMED_ONLY: &[&str] = &[ACTION_CONNECT];

/// The modes a session may ask a secret in (design §8.5). `raw` is not one:
/// it is a person's `secret:read`, never a session's use.
pub const MODES: &[&str] = &[
    "identity",
    "proxy",
    "placeholder",
    "short-lived",
    "file",
    "env",
    "exec",
];

/// The operating systems a device context may name — the spellings the agent
/// rows store (`OsKind`, snake case). Anything else is refused, never
/// lowercased into a match: a guard that assumes a casing is no guard.
pub const OSES: &[&str] = &["linux", "macos", "windows"];

/// A guardrail the vault seeds into every organization's set.
#[derive(Debug, Clone, Copy)]
pub struct Guardrail {
    /// The policy id it is decided under (`guardrail:<name>`).
    pub id: &'static str,
    /// Why it is there, for the listing.
    pub why: &'static str,
    pub text: &'static str,
}

/// The guardrails (design §8.4; decision 17). Organization-independent text:
/// no slug is spliced into Cedar, so no organization's name can change what
/// they say.
pub const GUARDRAILS: &[Guardrail] = &[
    Guardrail {
        id: "guardrail:windows-proxy-only",
        why: "Windows has no Claude Code sandbox, so a session there gets a secret only through \
              a proxy that authenticates for it (AC13; decision 17)",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when { context.device.os == "windows" && context.mode != "proxy" };"#,
    },
    Guardrail {
        id: "guardrail:prod-never-materializes",
        why: "a production value never lands in a file, an environment or a command line: a \
              secret tagged `prod`, or under the folder `prod/`, is used in no materializing mode",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when {
  (resource.tags.contains("prod") || resource.path == "prod" || resource.path like "prod/*") &&
  ["file", "env", "exec"].contains(context.mode)
};"#,
    },
    // P3-4c — the confused deputy's guard (design §8.5): a handle smuggled
    // into any other command resolves to nothing. The device sends the
    // program's bare name as the audience, and runs only that program.
    Guardrail {
        id: "guardrail:exec-only-allowed-programs",
        why: "in `exec` mode a value is handed only to a program its secret names in \
              `exec_allow`, by bare name: a handle smuggled into any other command is refused",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when { context.mode == "exec" && !(resource.exec_allow.contains(context.audience)) };"#,
    },
    // P3-5a — the proxy's confused deputy: the daemon authenticates with the
    // value to whatever upstream the session names, so the upstream must be
    // one the secret names. Exactly, as `exec_allow` matches a program.
    Guardrail {
        id: "guardrail:proxy-only-named-audiences",
        why: "in `proxy` mode a value is presented only to an upstream its secret names in \
              `audiences`, exactly: a session pointing a proxy anywhere else is refused",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when { context.mode == "proxy" && !(resource.audiences.contains(context.audience)) };"#,
    },
    // P3-6b — a dynamic secret's fields are its issuer's: the account that
    // mints, the App's key. In any other mode a lease would release one of
    // them to the session as a stored value, which no policy that permits a
    // mode for "a secret" ever meant.
    Guardrail {
        id: "guardrail:dynamic-only-short-lived",
        why: "a dynamic secret's fields are its issuer's, used only in `short-lived` to mint a \
              credential: no other mode hands one to a session",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when { resource.kind == "dynamic" && context.mode != "short-lived" };"#,
    },
    // P3-6b — and the other way about: `short-lived` releases a bundle to
    // mint with, which a stored value is not.
    Guardrail {
        id: "guardrail:short-lived-only-dynamic",
        why: "`short-lived` mints a credential with a dynamic secret's issuer: no other kind of \
              secret is leased in it",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
when { context.mode == "short-lived" && resource.kind != "dynamic" };"#,
    },
    // P3-9-1 — each guardrail above names `secret:use`, so none binds a
    // person's own action by itself. A person's endpoint is always a proxy:
    // the twin of `proxy-only-named-audiences` holds it to the upstreams its
    // secret names, exactly.
    Guardrail {
        id: "guardrail:connect-only-named-audiences",
        why: "a person's endpoint (`mh connect`) signs in only to an upstream its secret \
              names in `audiences`, exactly: an endpoint pointed anywhere else is refused",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:connect", resource)
when { !(resource.audiences.contains(context.audience)) };"#,
    },
    // P3-9-1 — the twin of `dynamic-only-short-lived`: a dynamic secret's
    // fields are its issuer's, and a person's short-lived credential is not
    // in P3-9, so no person's endpoint signs in with one.
    Guardrail {
        id: "guardrail:connect-never-dynamic",
        why: "a dynamic secret's fields are its issuer's, the account that mints: no person's \
              endpoint signs in with one",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:connect", resource)
when { resource.kind == "dynamic" };"#,
    },
    // P3-9-1 — decision 24: no person reaches a production secret through
    // an endpoint, as the design's §8.6 asks a second approver for a
    // person's read of one, and P3-9 has no approver for a person.
    Guardrail {
        id: "guardrail:connect-never-prod",
        why: "no person reaches a production secret through `mh connect` (decision 24): a \
              secret tagged `prod`, or under the folder `prod/`",
        text: r#"forbid (principal, action == MeshHarbor::Action::"secret:connect", resource)
when { resource.tags.contains("prod") || resource.path == "prod" || resource.path like "prod/*" };"#,
    },
];

/// What a policy may name of its organization.
#[derive(Debug, Clone, Default)]
pub struct OrgNames {
    /// The organization's RRN prefix for secrets: `rrn:{slug}:secret:`.
    pub secret_prefix: String,
    /// The organization's vault roles.
    pub roles: BTreeSet<String>,
    /// The organization's meshharbor role names (the `Group`s).
    pub groups: BTreeSet<String>,
}

/// A policy that passed every check: what to store and what it names.
#[derive(Debug, Clone)]
pub struct CheckedPolicy {
    /// `permit` | `forbid`.
    pub effect: &'static str,
    /// The `User` ids it names, for the route to check against membership.
    pub users: BTreeSet<ObjectId>,
    /// P3-7 — the `Node` ids it names, for the route to check against the
    /// organization's devices.
    pub nodes: BTreeSet<ObjectId>,
}

/// Check one policy before it is stored: exactly one static Cedar policy,
/// valid against the schema in strict mode, naming only its organization.
pub fn check_policy(text: &str, names: &OrgNames) -> Result<CheckedPolicy, String> {
    if text.trim().is_empty() {
        return Err("the policy is empty".into());
    }
    if text.len() > MAX_POLICY_LEN {
        return Err(format!("a policy is at most {MAX_POLICY_LEN} bytes"));
    }
    let policy = Policy::parse(None, text).map_err(|e| format!("not a Cedar policy: {e}"))?;
    let mut set = PolicySet::new();
    set.add(policy.clone())
        .map_err(|e| format!("not a policy: {e}"))?;
    let result = Validator::new(schema().clone()).validate(&set, ValidationMode::Strict);
    if !result.validation_passed() {
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        return Err(format!(
            "the policy does not fit the vault's schema: {}",
            errors.join("; ")
        ));
    }
    // P3-2c — a policy that can never apply is refused, never kept. Cedar
    // reports one only as a warning: a condition that is always false, or a
    // scope no action applies to (a `Node` named where `secret:use` takes a
    // `Secret`). Kept, it decides nothing, and a `forbid` like that forbids
    // nothing its writer meant it to. Cedar reports the scope's shape as
    // impossible too; its own warning is the one that says why.
    let never: Vec<String> = result
        .validation_warnings()
        .filter(|w| {
            matches!(
                w,
                ValidationWarning::ImpossiblePolicy(_)
                    | ValidationWarning::InvalidActionApplication(_)
            )
        })
        .map(|w| w.to_string())
        .collect();
    if !never.is_empty() {
        return Err(format!("the policy can never apply: {}", never.join("; ")));
    }
    let est = policy
        .to_json()
        .map_err(|e| format!("the policy cannot be read back: {e}"))?;
    let mut refs = Vec::new();
    entity_refs(&est, &mut refs);
    let mut users = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    for (ty, id) in refs {
        match ty.strip_prefix("MeshHarbor::").unwrap_or(&ty) {
            "Secret" | "SecretFolder" => {
                let Some(path) = id.strip_prefix(&names.secret_prefix) else {
                    return Err(format!(
                        "{ty}::{id:?} is not this organization's: its RRN must begin {:?}",
                        names.secret_prefix
                    ));
                };
                check_path(path).map_err(|why| format!("{ty}::{id:?}: {why}"))?;
            }
            "Role" => {
                if !names.roles.contains(&id) {
                    return Err(format!(
                        "Role::{id:?} is not one of this organization's vault roles"
                    ));
                }
            }
            "Group" => {
                if !names.groups.contains(&id) {
                    return Err(format!(
                        "Group::{id:?} is not one of this organization's roles"
                    ));
                }
            }
            "User" => {
                let user = ObjectId::parse_str(&id)
                    .map_err(|_| format!("User::{id:?} is not a user id"))?;
                users.insert(user);
            }
            // P3-7 — an exit named by its device's id; most policies name
            // exits by their tags instead.
            "Node" => {
                let node = ObjectId::parse_str(&id)
                    .map_err(|_| format!("Node::{id:?} is not a device id"))?;
                nodes.insert(node);
            }
            "Session" => {
                return Err(
                    "a policy never names one session: name the role sessions assume".into(),
                );
            }
            "Action" => {}
            other => return Err(format!("{other} is not a vault entity type")),
        }
    }
    Ok(CheckedPolicy {
        effect: match policy.effect() {
            cedar_policy::Effect::Permit => "permit",
            cedar_policy::Effect::Forbid => "forbid",
        },
        users,
        nodes,
    })
}

/// The longest policy, in bytes.
pub const MAX_POLICY_LEN: usize = 16 * 1024;

/// Every entity a policy's JSON form names, as `(type, id)`. Entity
/// references are the objects with exactly a string `type` and a string
/// `id`; a record literal's fields are expressions, never bare strings, so
/// one cannot pass for a reference.
fn entity_refs(v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            if m.len() == 2
                && let (Some(Value::String(ty)), Some(Value::String(id))) =
                    (m.get("type"), m.get("id"))
            {
                out.push((ty.clone(), id.clone()));
                return;
            }
            for child in m.values() {
                entity_refs(child, out);
            }
        }
        Value::Array(a) => {
            for child in a {
                entity_refs(child, out);
            }
        }
        _ => {}
    }
}

/// Whether a stored policy names `Role::"<role>"` — read from the parsed
/// policy, so no spacing or escape in the text can hide it. A text that no
/// longer parses counts as naming it: the answer guards a deletion.
pub fn names_role(text: &str, role: &str) -> bool {
    let Ok(policy) = Policy::parse(None, text) else {
        return true;
    };
    let Ok(est) = policy.to_json() else {
        return true;
    };
    let mut refs = Vec::new();
    entity_refs(&est, &mut refs);
    refs.iter()
        .any(|(ty, id)| ty == &format!("{NS}::Role") && id == role)
}

/// The policy id a stored policy is decided under.
pub fn stored_id(id: ObjectId) -> String {
    format!("policy:{}", id.to_hex())
}

/// The organization's whole set: the guardrails, then its own policies.
/// ⚠️ A policy that does not parse is an ERROR for the whole set, never a
/// policy skipped: the one skipped could be a `forbid`.
pub fn policy_set<'a>(
    stored: impl IntoIterator<Item = (String, &'a str)>,
) -> Result<PolicySet, String> {
    let mut set = PolicySet::new();
    for g in GUARDRAILS {
        let p = Policy::parse(Some(PolicyId::new(g.id)), g.text)
            .map_err(|e| format!("guardrail {} does not parse: {e}", g.id))?;
        set.add(p).map_err(|e| format!("guardrail {}: {e}", g.id))?;
    }
    for (id, text) in stored {
        let p = Policy::parse(Some(PolicyId::new(id.clone())), text)
            .map_err(|e| format!("stored policy {id} does not parse: {e}"))?;
        set.add(p).map_err(|e| format!("stored policy {id}: {e}"))?;
    }
    Ok(set)
}

/// A device's facts, as a request's context carries them.
#[derive(Debug, Clone)]
pub struct DeviceFacts {
    /// One of [`OSES`].
    pub os: String,
    /// Lowercased by [`DeviceFacts::new`].
    pub tags: Vec<String>,
    pub owner: ObjectId,
}

impl DeviceFacts {
    /// `os` must be one of [`OSES`] exactly; tags are lowercased, because a
    /// device's tags are free-form and a policy compares by equality.
    pub fn new(os: &str, tags: &[String], owner: ObjectId) -> Result<Self, String> {
        if !OSES.contains(&os) {
            return Err(format!("os must be one of {}", OSES.join(", ")));
        }
        Ok(Self {
            os: os.to_string(),
            tags: tags.iter().map(|t| t.trim().to_lowercase()).collect(),
            owner,
        })
    }

    fn json(&self) -> Value {
        json!({ "os": self.os, "tags": self.tags, "owner": user_ref(self.owner) })
    }
}

/// P3-7 — a device a session's flow exits through, as its ROW holds it,
/// never as a request says.
#[derive(Debug, Clone)]
pub struct NodeFacts {
    pub id: ObjectId,
    /// One of [`OSES`].
    pub os: String,
    /// Lowercased by [`NodeFacts::new`].
    pub tags: Vec<String>,
    pub owner: ObjectId,
}

impl NodeFacts {
    /// As [`DeviceFacts::new`], for the device named `id`.
    pub fn new(id: ObjectId, os: &str, tags: &[String], owner: ObjectId) -> Result<Self, String> {
        let d = DeviceFacts::new(os, tags, owner)?;
        Ok(Self {
            id,
            os: d.os,
            tags: d.tags,
            owner: d.owner,
        })
    }

    /// Its uid, and its entity.
    fn entity(&self) -> (Value, Value) {
        let node_uid = uid("Node", &self.id.to_hex());
        let entity = json!({
            "uid": node_uid,
            "attrs": { "os": self.os, "tags": self.tags, "owner": user_ref(self.owner) },
            "parents": [],
        });
        (node_uid, entity)
    }
}

/// A secret, as a request names it.
#[derive(Debug, Clone)]
pub struct SecretFacts {
    /// `rrn:{slug}:secret:`.
    pub prefix: String,
    pub path: String,
    pub kind: String,
    pub tags: Vec<String>,
    /// P3-4c — the programs a value may be handed to in `exec` mode, by bare
    /// name. Empty: no program at all.
    pub exec_allow: Vec<String>,
    /// P3-5a — where a value may be presented: in `proxy` mode, the upstream
    /// the daemon authenticates to. Empty: nowhere.
    pub audiences: Vec<String>,
}

/// A session, as a `secret:use` names it.
#[derive(Debug, Clone)]
pub struct SessionFacts {
    pub id: String,
    pub owner: ObjectId,
    /// The role it assumed; none means no policy can name it, so nothing is
    /// allowed it.
    pub role: Option<String>,
    pub playbook: Option<String>,
}

/// P3-4e — the person who said yes to an approval card, as a policy reads
/// them: `context.approval.approver`, in a `Group` per meshharbor role they
/// hold, so `approver in MeshHarbor::Group::"admin"` holds for an admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    pub id: ObjectId,
    pub groups: Vec<String>,
}

/// One request to decide.
#[derive(Debug, Clone)]
pub enum Ask {
    /// `role:assume`: may `user` (in `groups`) assume `role` on `device`?
    AssumeRole {
        user: ObjectId,
        groups: Vec<String>,
        role: String,
        device: DeviceFacts,
    },
    /// `secret:use`: may `session` use `secret` in `mode`?
    UseSecret {
        session: SessionFacts,
        secret: SecretFacts,
        mode: String,
        audience: String,
        ttl_s: i64,
        device: DeviceFacts,
        approver: Option<Approver>,
    },
    /// P3-4b — `secret:list`: may `session` list or describe `secret`?
    ListSecret {
        session: SessionFacts,
        secret: SecretFacts,
        device: DeviceFacts,
    },
    /// P3-7 — `net:socks`: may `session`, on `device`, open a SOCKS5
    /// listener whose flows exit through `node`?
    NetSocks {
        session: SessionFacts,
        node: NodeFacts,
        device: DeviceFacts,
    },
    /// P3-7 — `net:forward`: may `session`, on `device`, open a forward to
    /// `host:port` through `node`?
    NetForward {
        session: SessionFacts,
        node: NodeFacts,
        host: String,
        port: u16,
        device: DeviceFacts,
    },
    /// P3-8 — `ssh:run`: may `session`, on `device`, run one command on
    /// `node` over MeshHarbor SSH, as `account` (the account `node`'s SSH policy
    /// maps, as an `SshAccountMode` word)?
    SshRun {
        session: SessionFacts,
        node: NodeFacts,
        account: String,
        device: DeviceFacts,
    },
    /// P3-9-1 — `secret:connect`: may `user` (in `groups`), the owner of
    /// `device` as its row names them, use `secret` through an endpoint the
    /// device serves them, toward `audience`, for `ttl_s`?
    ///
    /// `approver` is never given in a real decision (decision 24): a person's
    /// request has nobody to say yes. It is how the vault asks whether a yes
    /// WOULD lift a deny, to refuse `approval_unavailable` rather than
    /// `denied`.
    ConnectSecret {
        user: ObjectId,
        groups: Vec<String>,
        secret: SecretFacts,
        audience: String,
        ttl_s: i64,
        device: DeviceFacts,
        approver: Option<Approver>,
    },
}

fn uid(ty: &str, id: &str) -> Value {
    json!({ "type": format!("{NS}::{ty}"), "id": id })
}

fn user_ref(id: ObjectId) -> Value {
    json!({ "__entity": uid("User", &id.to_hex()) })
}

/// A person and each group they are in, as entities: the user, then every
/// group once.
fn user_in_groups(user: ObjectId, groups: &[String]) -> Vec<Value> {
    let groups: BTreeSet<&str> = groups.iter().map(String::as_str).collect();
    let mut entities = vec![json!({
        "uid": uid("User", &user.to_hex()),
        "attrs": {},
        "parents": groups.iter().map(|g| uid("Group", g)).collect::<Vec<_>>(),
    })];
    for g in groups {
        entities.push(json!({ "uid": uid("Group", g), "attrs": {}, "parents": [] }));
    }
    entities
}

fn parse_uid(v: &Value) -> Result<EntityUid, String> {
    EntityUid::from_json(v.clone()).map_err(|e| format!("an entity id: {e}"))
}

/// Every element a string, or `None`.
fn strings(a: &bson::Array) -> Option<Vec<String>> {
    a.iter().map(|b| b.as_str().map(String::from)).collect()
}

/// The session, in the role it assumed, and the secret, in its folders: the
/// principal, the resource and the entities a `secret:*` request is decided
/// over.
fn session_and_secret(session: &SessionFacts, secret: &SecretFacts) -> (Value, Value, Vec<Value>) {
    let (session_uid, mut entities) = session_entities(session);
    let (secret_uid, secret) = secret_entities(secret);
    entities.extend(secret);
    (session_uid, secret_uid, entities)
}

/// The secret, in its folders: its uid, and the entities, itself and every
/// folder above it.
fn secret_entities(secret: &SecretFacts) -> (Value, Vec<Value>) {
    let mut entities = Vec::new();
    let chain = folders(&secret.path);
    let secret_uid = uid("Secret", &format!("{}{}", secret.prefix, secret.path));
    entities.push(json!({
        "uid": secret_uid,
        "attrs": {
            "path": secret.path,
            "kind": secret.kind,
            "tags": secret.tags,
            "exec_allow": secret.exec_allow,
            "audiences": secret.audiences,
        },
        "parents": chain.first()
            .map(|f| vec![uid("SecretFolder", &format!("{}{f}", secret.prefix))])
            .unwrap_or_default(),
    }));
    for (i, f) in chain.iter().enumerate() {
        let parents: Vec<Value> = chain
            .get(i + 1)
            .map(|up| vec![uid("SecretFolder", &format!("{}{up}", secret.prefix))])
            .unwrap_or_default();
        entities.push(json!({
            "uid": uid("SecretFolder", &format!("{}{f}", secret.prefix)),
            "attrs": {},
            "parents": parents,
        }));
    }
    (secret_uid, entities)
}

/// The session, in the role it assumed: its uid, and the entities, itself and
/// its role.
fn session_entities(session: &SessionFacts) -> (Value, Vec<Value>) {
    let session_uid = uid("Session", &session.id);
    let mut attrs = json!({ "owner": user_ref(session.owner) });
    if let Some(p) = &session.playbook {
        attrs["playbook"] = json!(p);
    }
    let parents: Vec<Value> = session.role.iter().map(|r| uid("Role", r)).collect();
    let mut entities = vec![json!({ "uid": session_uid, "attrs": attrs, "parents": parents })];
    if let Some(r) = &session.role {
        entities.push(json!({ "uid": uid("Role", r), "attrs": {}, "parents": [] }));
    }
    (session_uid, entities)
}

/// The folders above a path, innermost first: `a/b/c` → `a/b`, `a`.
fn folders(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = path;
    while let Some(i) = rest.rfind('/') {
        rest = &rest[..i];
        out.push(rest);
    }
    out
}

impl Ask {
    /// The action's name.
    pub fn action(&self) -> &'static str {
        match self {
            Self::AssumeRole { .. } => ACTION_ASSUME,
            Self::UseSecret { .. } => ACTION_USE,
            Self::ListSecret { .. } => ACTION_LIST,
            Self::NetSocks { .. } => ACTION_NET_SOCKS,
            Self::NetForward { .. } => ACTION_NET_FORWARD,
            Self::SshRun { .. } => ACTION_SSH_RUN,
            Self::ConnectSecret { .. } => ACTION_CONNECT,
        }
    }

    /// P3-2b — the request as `vault_audit` keeps it, so a replay decides
    /// exactly what was decided: the groups, the device's facts, the mode,
    /// as they were then.
    pub fn to_doc(&self) -> bson::Document {
        let device = |d: &DeviceFacts| {
            bson::doc! { "os": &d.os, "tags": &d.tags, "owner": d.owner }
        };
        let session_doc = |s: &SessionFacts| {
            bson::doc! {
                "id": &s.id,
                "owner": s.owner,
                "role": s.role.clone(),
                "playbook": s.playbook.clone(),
            }
        };
        let secret_doc = |r: &SecretFacts| {
            bson::doc! {
                "prefix": &r.prefix,
                "path": &r.path,
                "kind": &r.kind,
                "tags": &r.tags,
                "exec_allow": &r.exec_allow,
                "audiences": &r.audiences,
            }
        };
        let node_doc = |n: &NodeFacts| {
            bson::doc! { "id": n.id, "os": &n.os, "tags": &n.tags, "owner": n.owner }
        };
        match self {
            Self::AssumeRole {
                user,
                groups,
                role,
                device: d,
            } => bson::doc! {
                "action": ACTION_ASSUME,
                "user": *user,
                "groups": groups,
                "role": role,
                "device": device(d),
            },
            Self::UseSecret {
                session,
                secret,
                mode,
                audience,
                ttl_s,
                device: d,
                approver,
            } => {
                let mut doc = bson::doc! {
                    "action": ACTION_USE,
                    "session": session_doc(session),
                    "secret": secret_doc(secret),
                    "mode": mode,
                    "audience": audience,
                    "ttl_s": *ttl_s,
                    "device": device(d),
                };
                if let Some(a) = approver {
                    doc.insert("approver", a.id);
                    doc.insert("approver_groups", a.groups.clone());
                }
                doc
            }
            Self::ListSecret {
                session,
                secret,
                device: d,
            } => bson::doc! {
                "action": ACTION_LIST,
                "session": session_doc(session),
                "secret": secret_doc(secret),
                "device": device(d),
            },
            Self::NetSocks {
                session,
                node,
                device: d,
            } => bson::doc! {
                "action": ACTION_NET_SOCKS,
                "session": session_doc(session),
                "node": node_doc(node),
                "device": device(d),
            },
            Self::NetForward {
                session,
                node,
                host,
                port,
                device: d,
            } => bson::doc! {
                "action": ACTION_NET_FORWARD,
                "session": session_doc(session),
                "node": node_doc(node),
                "host": host,
                "port": i32::from(*port),
                "device": device(d),
            },
            Self::SshRun {
                session,
                node,
                account,
                device: d,
            } => bson::doc! {
                "action": ACTION_SSH_RUN,
                "session": session_doc(session),
                "node": node_doc(node),
                "account": account,
                "device": device(d),
            },
            Self::ConnectSecret {
                user,
                groups,
                secret,
                audience,
                ttl_s,
                device: d,
                approver,
            } => {
                let mut doc = bson::doc! {
                    "action": ACTION_CONNECT,
                    "user": *user,
                    "groups": groups,
                    "secret": secret_doc(secret),
                    "audience": audience,
                    "ttl_s": *ttl_s,
                    "device": device(d),
                };
                if let Some(a) = approver {
                    doc.insert("approver", a.id);
                    doc.insert("approver_groups", a.groups.clone());
                }
                doc
            }
        }
    }

    /// The inverse of [`Self::to_doc`]; `None` for a row no replay can read
    /// (a later version's shape, or a damaged one).
    pub fn from_doc(doc: &bson::Document) -> Option<Self> {
        let device = |d: &bson::Document| -> Option<DeviceFacts> {
            Some(DeviceFacts {
                os: d.get_str("os").ok()?.to_string(),
                tags: strings(d.get_array("tags").ok()?)?,
                owner: d.get_object_id("owner").ok()?,
            })
        };
        let session = |s: &bson::Document| -> Option<SessionFacts> {
            Some(SessionFacts {
                id: s.get_str("id").ok()?.to_string(),
                owner: s.get_object_id("owner").ok()?,
                role: s.get_str("role").ok().map(String::from),
                playbook: s.get_str("playbook").ok().map(String::from),
            })
        };
        let secret = |r: &bson::Document| -> Option<SecretFacts> {
            Some(SecretFacts {
                prefix: r.get_str("prefix").ok()?.to_string(),
                path: r.get_str("path").ok()?.to_string(),
                kind: r.get_str("kind").ok()?.to_string(),
                tags: strings(r.get_array("tags").ok()?)?,
                // P3-4c — a request recorded before the field existed named
                // no program: decided again, its exec is refused.
                exec_allow: match r.get_array("exec_allow") {
                    Ok(a) => strings(a)?,
                    Err(_) => Vec::new(),
                },
                // P3-5a — likewise no audience: decided again, its proxy use
                // is refused.
                audiences: match r.get_array("audiences") {
                    Ok(a) => strings(a)?,
                    Err(_) => Vec::new(),
                },
            })
        };
        let node = |n: &bson::Document| -> Option<NodeFacts> {
            Some(NodeFacts {
                id: n.get_object_id("id").ok()?,
                os: n.get_str("os").ok()?.to_string(),
                tags: strings(n.get_array("tags").ok()?)?,
                owner: n.get_object_id("owner").ok()?,
            })
        };
        let approver = match doc.get_object_id("approver") {
            Ok(id) => Some(Approver {
                id,
                // P3-4e — a request recorded before the groups were named
                // had none, and was decided without them.
                groups: match doc.get_array("approver_groups") {
                    Ok(a) => strings(a)?,
                    Err(_) => Vec::new(),
                },
            }),
            Err(_) => None,
        };
        match doc.get_str("action").ok()? {
            ACTION_ASSUME => Some(Self::AssumeRole {
                user: doc.get_object_id("user").ok()?,
                groups: strings(doc.get_array("groups").ok()?)?,
                role: doc.get_str("role").ok()?.to_string(),
                device: device(doc.get_document("device").ok()?)?,
            }),
            ACTION_USE => Some(Self::UseSecret {
                session: session(doc.get_document("session").ok()?)?,
                secret: secret(doc.get_document("secret").ok()?)?,
                mode: doc.get_str("mode").ok()?.to_string(),
                audience: doc.get_str("audience").ok()?.to_string(),
                ttl_s: doc.get_i64("ttl_s").ok()?,
                device: device(doc.get_document("device").ok()?)?,
                approver,
            }),
            ACTION_LIST => Some(Self::ListSecret {
                session: session(doc.get_document("session").ok()?)?,
                secret: secret(doc.get_document("secret").ok()?)?,
                device: device(doc.get_document("device").ok()?)?,
            }),
            ACTION_NET_SOCKS => Some(Self::NetSocks {
                session: session(doc.get_document("session").ok()?)?,
                node: node(doc.get_document("node").ok()?)?,
                device: device(doc.get_document("device").ok()?)?,
            }),
            ACTION_NET_FORWARD => Some(Self::NetForward {
                session: session(doc.get_document("session").ok()?)?,
                node: node(doc.get_document("node").ok()?)?,
                host: doc.get_str("host").ok()?.to_string(),
                port: u16::try_from(doc.get_i32("port").ok()?).ok()?,
                device: device(doc.get_document("device").ok()?)?,
            }),
            ACTION_SSH_RUN => Some(Self::SshRun {
                session: session(doc.get_document("session").ok()?)?,
                node: node(doc.get_document("node").ok()?)?,
                account: doc.get_str("account").ok()?.to_string(),
                device: device(doc.get_document("device").ok()?)?,
            }),
            ACTION_CONNECT => Some(Self::ConnectSecret {
                user: doc.get_object_id("user").ok()?,
                groups: strings(doc.get_array("groups").ok()?)?,
                secret: secret(doc.get_document("secret").ok()?)?,
                audience: doc.get_str("audience").ok()?.to_string(),
                ttl_s: doc.get_i64("ttl_s").ok()?,
                device: device(doc.get_document("device").ok()?)?,
                approver,
            }),
            _ => None,
        }
    }

    /// The Cedar request, and the entities it is decided over, both checked
    /// against the schema.
    pub fn build(&self) -> Result<(Request, Entities), String> {
        let action = parse_uid(&uid("Action", self.action()))?;
        let (principal, resource, entities, context) = match self {
            Self::AssumeRole {
                user,
                groups,
                role,
                device,
            } => {
                let user_uid = uid("User", &user.to_hex());
                let role_uid = uid("Role", role);
                let mut entities = user_in_groups(*user, groups);
                entities.push(json!({ "uid": role_uid, "attrs": {}, "parents": [] }));
                (
                    user_uid,
                    role_uid,
                    entities,
                    json!({ "device": device.json() }),
                )
            }
            Self::UseSecret {
                session,
                secret,
                mode,
                audience,
                ttl_s,
                device,
                approver,
            } => {
                let (session_uid, secret_uid, mut entities) = session_and_secret(session, secret);
                let mut context = json!({
                    "mode": mode,
                    "audience": audience,
                    "ttl_s": ttl_s,
                    "device": device.json(),
                });
                if let Some(a) = approver {
                    context["approval"] = json!({ "approver": user_ref(a.id) });
                    // P3-4e — in the groups they hold, or a policy that names
                    // an approver's group could never hold.
                    entities.extend(user_in_groups(a.id, &a.groups));
                }
                (session_uid, secret_uid, entities, context)
            }
            Self::ListSecret {
                session,
                secret,
                device,
            } => {
                let (session_uid, secret_uid, entities) = session_and_secret(session, secret);
                (
                    session_uid,
                    secret_uid,
                    entities,
                    json!({ "device": device.json() }),
                )
            }
            Self::NetSocks {
                session,
                node,
                device,
            } => {
                let (session_uid, mut entities) = session_entities(session);
                let (node_uid, node_entity) = node.entity();
                entities.push(node_entity);
                (
                    session_uid,
                    node_uid,
                    entities,
                    json!({ "device": device.json() }),
                )
            }
            Self::NetForward {
                session,
                node,
                host,
                port,
                device,
            } => {
                let (session_uid, mut entities) = session_entities(session);
                let (node_uid, node_entity) = node.entity();
                entities.push(node_entity);
                (
                    session_uid,
                    node_uid,
                    entities,
                    json!({ "device": device.json(), "host": host, "port": port }),
                )
            }
            Self::SshRun {
                session,
                node,
                account,
                device,
            } => {
                let (session_uid, mut entities) = session_entities(session);
                let (node_uid, node_entity) = node.entity();
                entities.push(node_entity);
                (
                    session_uid,
                    node_uid,
                    entities,
                    json!({ "device": device.json(), "account": account }),
                )
            }
            Self::ConnectSecret {
                user,
                groups,
                secret,
                audience,
                ttl_s,
                device,
                approver,
            } => {
                let (secret_uid, mut entities) = secret_entities(secret);
                entities.extend(user_in_groups(*user, groups));
                let mut context = json!({
                    "audience": audience,
                    "ttl_s": ttl_s,
                    "device": device.json(),
                });
                if let Some(a) = approver {
                    context["approval"] = json!({ "approver": user_ref(a.id) });
                    // In the groups they hold, as for `secret:use`. A group
                    // both name, or the person as their own approver, is the
                    // same entity twice, which Cedar takes when the copies
                    // are identical.
                    entities.extend(user_in_groups(a.id, &a.groups));
                }
                (uid("User", &user.to_hex()), secret_uid, entities, context)
            }
        };
        let principal = parse_uid(&principal)?;
        let resource = parse_uid(&resource)?;
        let context = Context::from_json_value(context, Some((schema(), &action)))
            .map_err(|e| format!("the request's context: {e}"))?;
        let request = Request::new(principal, action, resource, context, Some(schema()))
            .map_err(|e| format!("the request: {e}"))?;
        let entities = Entities::from_json_value(Value::Array(entities), Some(schema()))
            .map_err(|e| format!("the request's entities: {e}"))?;
        Ok((request, entities))
    }
}

/// A decision, and what made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    /// The policies that determined it: the permits that allowed it, or the
    /// forbids that denied it. Empty for a default deny.
    pub determining: Vec<String>,
    /// Policies that erred while evaluating (they count as not applying).
    pub errors: Vec<String>,
}

impl Verdict {
    /// Deny, for a reason outside Cedar (a set that did not build, a request
    /// that did not fit the schema).
    pub fn deny(why: impl Into<String>) -> Self {
        Self {
            allow: false,
            determining: Vec::new(),
            errors: vec![why.into()],
        }
    }
}

/// Decide `ask` against `set`. Anything that keeps a request from being
/// decided is a DENY, with why.
///
/// ⚠️ P3-9-1 — an action in [`NAMED_ONLY`] is decided over the set without
/// the permits whose scope names no action: only a permit written for it
/// admits it.
pub fn decide(set: &PolicySet, ask: &Ask) -> Verdict {
    let (request, entities) = match ask.build() {
        Ok(built) => built,
        Err(why) => return Verdict::deny(why),
    };
    let narrowed;
    let set = if NAMED_ONLY.contains(&ask.action()) {
        narrowed = match named_only(set, ask.action()) {
            Ok(s) => s,
            Err(why) => return Verdict::deny(why),
        };
        &narrowed
    } else {
        set
    };
    let response = Authorizer::new().is_authorized(&request, set, &entities);
    let mut determining: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|id| id.to_string())
        .collect();
    determining.sort();
    Verdict {
        allow: response.decision() == Decision::Allow,
        determining,
        errors: response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect(),
    }
}

/// P3-9-1 — `set` without the permits whose scope does not name `action`:
/// every `forbid`, and every permit that names it (`action ==` it, or
/// `action in [...]` with it).
fn named_only(set: &PolicySet, action: &str) -> Result<PolicySet, String> {
    let action = parse_uid(&uid("Action", action))?;
    let mut out = PolicySet::new();
    for p in set.policies() {
        let names = match p.action_constraint() {
            ActionConstraint::Any => false,
            ActionConstraint::Eq(a) => a == action,
            ActionConstraint::In(actions) => actions.contains(&action),
        };
        if names || p.effect() == Effect::Forbid {
            out.add(p.clone())
                .map_err(|e| format!("policy {}: {e}", p.id()))?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "rrn:grox:secret:";

    fn names() -> OrgNames {
        OrgNames {
            secret_prefix: ORG.into(),
            roles: ["dev", "deployer"].into_iter().map(String::from).collect(),
            groups: ["admin", "member"].into_iter().map(String::from).collect(),
        }
    }

    fn device(os: &str, tags: &[&str]) -> DeviceFacts {
        let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
        DeviceFacts::new(os, &tags, ObjectId::new()).unwrap()
    }

    fn use_secret(role: Option<&str>, path: &str, tags: &[&str], mode: &str, os: &str) -> Ask {
        Ask::UseSecret {
            session: SessionFacts {
                id: ObjectId::new().to_hex(),
                owner: ObjectId::new(),
                role: role.map(String::from),
                playbook: None,
            },
            // P3-4c — a program the secret names, so an `exec` here meets
            // every guardrail but the one a test is about; P3-5a — and an
            // audience, likewise for a `proxy`.
            secret: SecretFacts {
                prefix: ORG.into(),
                path: path.into(),
                kind: "static".into(),
                tags: tags.iter().map(|t| t.to_string()).collect(),
                exec_allow: vec!["psql".into()],
                audiences: vec!["psql".into()],
            },
            mode: mode.into(),
            audience: "psql".into(),
            ttl_s: 900,
            device: device(os, &[]),
            approver: None,
        }
    }

    fn list_secret(role: Option<&str>, path: &str, os: &str) -> Ask {
        Ask::ListSecret {
            session: SessionFacts {
                id: ObjectId::new().to_hex(),
                owner: ObjectId::new(),
                role: role.map(String::from),
                playbook: None,
            },
            secret: SecretFacts {
                prefix: ORG.into(),
                path: path.into(),
                kind: "static".into(),
                tags: Vec::new(),
                exec_allow: Vec::new(),
                audiences: Vec::new(),
            },
            device: device(os, &[]),
        }
    }

    const DEV_LISTS_STAGING: &str = r#"permit (principal in MeshHarbor::Role::"dev",
        action == MeshHarbor::Action::"secret:list",
        resource in MeshHarbor::SecretFolder::"rrn:grox:secret:staging");"#;

    fn set_with(policies: &[&str]) -> PolicySet {
        policy_set(
            policies
                .iter()
                .enumerate()
                .map(|(i, t)| (format!("policy:{i}"), *t)),
        )
        .unwrap()
    }

    const DEV_STAGING: &str = r#"permit (principal in MeshHarbor::Role::"dev",
        action == MeshHarbor::Action::"secret:use",
        resource in MeshHarbor::SecretFolder::"rrn:grox:secret:staging");"#;

    #[test]
    fn the_schema_and_every_guardrail_hold() {
        let _ = schema();
        let set = policy_set(std::iter::empty()).unwrap();
        assert_eq!(set.policies().count(), GUARDRAILS.len());
        // Each guardrail is valid against the schema, as any stored policy
        // must be.
        let mut only = PolicySet::new();
        for g in GUARDRAILS {
            only.add(Policy::parse(Some(PolicyId::new(g.id)), g.text).unwrap())
                .unwrap();
        }
        let r = Validator::new(schema().clone()).validate(&only, ValidationMode::Strict);
        assert!(
            r.validation_passed(),
            "{:?}",
            r.validation_errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn nothing_is_allowed_that_no_policy_permits() {
        let set = policy_set(std::iter::empty()).unwrap();
        let v = decide(
            &set,
            &use_secret(Some("dev"), "staging/db", &[], "proxy", "linux"),
        );
        assert!(!v.allow && v.determining.is_empty(), "{v:?}");
    }

    #[test]
    fn a_permit_allows_inside_its_folder_only() {
        let set = set_with(&[DEV_STAGING]);
        let ok = decide(
            &set,
            &use_secret(Some("dev"), "staging/db/main", &[], "proxy", "linux"),
        );
        assert!(ok.allow, "{ok:?}");
        assert_eq!(ok.determining, ["policy:0"]);
        for ask in [
            use_secret(Some("dev"), "prod/db", &[], "proxy", "linux"),
            use_secret(Some("deployer"), "staging/db", &[], "proxy", "linux"),
            use_secret(None, "staging/db", &[], "proxy", "linux"),
            // A sibling whose name merely starts the same is not inside.
            use_secret(Some("dev"), "staging2/db", &[], "proxy", "linux"),
        ] {
            assert!(!decide(&set, &ask).allow, "{ask:?}");
        }
    }

    #[test]
    fn windows_gets_a_secret_through_a_proxy_only() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        assert!(
            decide(
                &set,
                &use_secret(Some("dev"), "staging/db", &[], "proxy", "windows")
            )
            .allow
        );
        for mode in [
            "file",
            "env",
            "exec",
            "short-lived",
            "identity",
            "placeholder",
        ] {
            // P3-6b — `short-lived` with the one kind it is for, so only
            // the guardrail this test is about decides.
            let ask = use_secret(Some("dev"), "staging/db", &[], mode, "windows");
            let ask = if mode == "short-lived" {
                of_kind(ask, "dynamic")
            } else {
                ask
            };
            let v = decide(&set, &ask);
            assert!(!v.allow, "{mode}: {v:?}");
            assert_eq!(v.determining, ["guardrail:windows-proxy-only"], "{mode}");
        }
        // Linux and macOS are not held to it.
        for os in ["linux", "macos"] {
            assert!(decide(&set, &use_secret(Some("dev"), "staging/db", &[], "env", os)).allow);
        }
    }

    /// The same ask, of another kind of secret.
    fn of_kind(mut ask: Ask, kind: &str) -> Ask {
        if let Ask::UseSecret { secret, .. } = &mut ask {
            secret.kind = kind.into();
        }
        ask
    }

    /// P3-6b — a dynamic secret's issuer is used to mint, in `short-lived`,
    /// and in no other mode: whatever a policy permits.
    #[test]
    fn a_dynamic_secret_is_used_short_lived_alone() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        for os in ["linux", "macos"] {
            let ask = of_kind(
                use_secret(Some("dev"), "db/dyn", &[], "short-lived", os),
                "dynamic",
            );
            assert!(decide(&set, &ask).allow, "{os}");
        }
        for mode in ["proxy", "file", "env", "exec", "identity", "placeholder"] {
            let ask = of_kind(
                use_secret(Some("dev"), "db/dyn", &[], mode, "linux"),
                "dynamic",
            );
            let v = decide(&set, &ask);
            assert!(!v.allow, "{mode}: {v:?}");
            assert_eq!(
                v.determining,
                ["guardrail:dynamic-only-short-lived"],
                "{mode}"
            );
        }
    }

    /// P3-6b — and `short-lived` leases nothing a dynamic secret is not.
    #[test]
    fn short_lived_uses_a_dynamic_secret_alone() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        for kind in ["static", "structured", "template", ""] {
            let ask = of_kind(
                use_secret(Some("dev"), "db/x", &[], "short-lived", "linux"),
                kind,
            );
            let v = decide(&set, &ask);
            assert!(!v.allow, "{kind:?}: {v:?}");
            assert_eq!(
                v.determining,
                ["guardrail:short-lived-only-dynamic"],
                "{kind:?}"
            );
        }
    }

    /// P3-6b — prod's guardrail keeps a STORED value from materializing; a
    /// credential minted for minutes is what it pushes toward.
    #[test]
    fn a_prod_credential_is_minted_short_lived() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        for (path, tags) in [("prod/db", &[][..]), ("svc/db", &["prod"][..])] {
            let ask = of_kind(
                use_secret(Some("ops"), path, tags, "short-lived", "linux"),
                "dynamic",
            );
            assert!(decide(&set, &ask).allow, "{path} {tags:?}");
        }
    }

    #[test]
    fn a_prod_value_never_materializes() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        for (path, tags) in [
            ("prod", &[][..]),
            ("prod/db", &[][..]),
            ("svc/db", &["prod"][..]),
        ] {
            for mode in ["file", "env", "exec"] {
                let v = decide(&set, &use_secret(Some("ops"), path, tags, mode, "linux"));
                assert!(!v.allow, "{path} {tags:?} {mode}");
                assert_eq!(v.determining, ["guardrail:prod-never-materializes"]);
            }
            assert!(decide(&set, &use_secret(Some("ops"), path, tags, "proxy", "linux")).allow);
        }
        // `production/…` is not `prod/…`.
        assert!(
            decide(
                &set,
                &use_secret(Some("ops"), "production/db", &[], "env", "linux")
            )
            .allow
        );
    }

    /// P3-4c — `exec` hands a value only to a program its secret names, by
    /// bare name; every other mode is not held to the list.
    #[test]
    fn exec_reaches_only_a_program_its_secret_names() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        let with = |audience: &str, allow: &[&str], mode: &str| {
            let mut ask = use_secret(Some("dev"), "staging/db", &[], mode, "linux");
            if let Ask::UseSecret {
                secret,
                audience: a,
                ..
            } = &mut ask
            {
                *a = audience.into();
                secret.exec_allow = allow.iter().map(|p| p.to_string()).collect();
            }
            ask
        };
        let ok = decide(&set, &with("psql", &["psql", "kubectl"], "exec"));
        assert!(ok.allow && ok.errors.is_empty(), "{ok:?}");
        for (audience, allow) in [
            ("curl", &["psql"][..]),
            ("/usr/bin/psql", &["psql"][..]),
            ("psql", &[][..]),
            ("", &["psql"][..]),
        ] {
            let v = decide(&set, &with(audience, allow, "exec"));
            assert!(!v.allow, "{audience:?} {allow:?}: {v:?}");
            assert_eq!(
                v.determining,
                ["guardrail:exec-only-allowed-programs"],
                "{audience:?}"
            );
        }
        // P3-5a — `proxy` is held by a guardrail of its own, to the
        // secret's audiences.
        for mode in ["env", "file"] {
            assert!(decide(&set, &with("curl", &[], mode)).allow, "{mode}");
        }
    }

    /// P3-5a — a proxy presents a value only to an upstream its secret
    /// names, exactly as written; no mode that presents nothing to an
    /// upstream is held to the audiences.
    #[test]
    fn a_proxy_reaches_only_an_audience_its_secret_names() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let set = set_with(&[any]);
        let with = |audience: &str, audiences: &[&str], mode: &str| {
            let mut ask = use_secret(Some("dev"), "staging/db", &[], mode, "linux");
            if let Ask::UseSecret {
                secret,
                audience: a,
                ..
            } = &mut ask
            {
                *a = audience.into();
                secret.audiences = audiences.iter().map(|p| p.to_string()).collect();
            }
            ask
        };
        let ok = decide(
            &set,
            &with(
                "db.internal:5432",
                &["db.internal:5432", "replica:5432"],
                "proxy",
            ),
        );
        assert!(ok.allow && ok.errors.is_empty(), "{ok:?}");
        for (audience, audiences) in [
            ("evil.example:5432", &["db.internal:5432"][..]),
            // Another port is another upstream.
            ("db.internal:6432", &["db.internal:5432"][..]),
            ("db.internal", &["db.internal:5432"][..]),
            // Exactly as the secret writes it.
            ("DB.internal:5432", &["db.internal:5432"][..]),
            // A secret that names none is presented nowhere.
            ("db.internal:5432", &[][..]),
            ("", &["db.internal:5432"][..]),
        ] {
            let v = decide(&set, &with(audience, audiences, "proxy"));
            assert!(!v.allow, "{audience:?} {audiences:?}: {v:?}");
            assert_eq!(
                v.determining,
                ["guardrail:proxy-only-named-audiences"],
                "{audience:?}"
            );
        }
        for mode in ["env", "file"] {
            assert!(decide(&set, &with("anywhere", &[], mode)).allow, "{mode}");
        }
    }

    /// P3-5a — a request recorded before `audiences` existed reads back
    /// naming none, so decided again its proxy use is refused.
    #[test]
    fn a_request_recorded_without_audiences_reads_back_naming_none() {
        let ask = use_secret(Some("dev"), "staging/db", &[], "proxy", "linux");
        let mut doc = ask.to_doc();
        doc.get_document_mut("secret")
            .unwrap()
            .remove("audiences")
            .expect("written today");
        let back = Ask::from_doc(&doc).expect("still reads");
        let Ask::UseSecret { secret, .. } = &back else {
            panic!("{back:?}")
        };
        assert!(secret.audiences.is_empty());
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let v = decide(&set_with(&[any]), &back);
        assert_eq!(v.determining, ["guardrail:proxy-only-named-audiences"]);
    }

    /// P3-4c — a request recorded before `exec_allow` existed reads back
    /// naming no program, so decided again its exec is refused.
    #[test]
    fn a_request_recorded_without_exec_allow_reads_back_naming_no_program() {
        let ask = use_secret(Some("dev"), "staging/db", &[], "exec", "linux");
        let mut doc = ask.to_doc();
        doc.get_document_mut("secret")
            .unwrap()
            .remove("exec_allow")
            .expect("written today");
        let back = Ask::from_doc(&doc).expect("still reads");
        let Ask::UseSecret { secret, .. } = &back else {
            panic!("{back:?}")
        };
        assert!(secret.exec_allow.is_empty());
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let v = decide(&set_with(&[any]), &back);
        assert_eq!(v.determining, ["guardrail:exec-only-allowed-programs"]);
    }

    #[test]
    fn a_forbid_beats_every_permit() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#;
        let no_dev = r#"forbid (principal in MeshHarbor::Role::"dev", action, resource);"#;
        let set = set_with(&[any, no_dev]);
        let v = decide(
            &set,
            &use_secret(Some("dev"), "staging/db", &[], "proxy", "linux"),
        );
        assert!(!v.allow);
        assert_eq!(v.determining, ["policy:1"]);
    }

    #[test]
    fn role_assume_reads_the_device() {
        let p = r#"permit (principal in MeshHarbor::Group::"member",
            action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev")
            when { context.device.owner == principal || context.device.tags.contains("build") };"#;
        let set = set_with(&[p]);
        let me = ObjectId::new();
        let ask = |groups: &[&str], role: &str, owner: ObjectId, tags: &[&str]| Ask::AssumeRole {
            user: me,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            role: role.into(),
            device: DeviceFacts::new(
                "linux",
                &tags.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
                owner,
            )
            .unwrap(),
        };
        assert!(
            decide(&set, &ask(&["member"], "dev", me, &[])).allow,
            "own device"
        );
        assert!(
            decide(&set, &ask(&["member"], "dev", ObjectId::new(), &["Build"])).allow,
            "a build box — the device's tag lowercased"
        );
        assert!(!decide(&set, &ask(&["member"], "dev", ObjectId::new(), &[])).allow);
        assert!(
            !decide(&set, &ask(&["guest"], "dev", me, &[])).allow,
            "not a member"
        );
        assert!(!decide(&set, &ask(&["member"], "deployer", me, &[])).allow);
    }

    #[test]
    fn an_approval_can_be_required() {
        let p = r#"permit (principal in MeshHarbor::Role::"deployer",
            action == MeshHarbor::Action::"secret:use", resource)
            when { context.ttl_s <= 900 && context has approval };"#;
        let set = set_with(&[p]);
        let mut ask = use_secret(Some("deployer"), "deploy/key", &[], "proxy", "linux");
        assert!(!decide(&set, &ask).allow, "no approval");
        if let Ask::UseSecret { approver, .. } = &mut ask {
            *approver = Some(Approver {
                id: ObjectId::new(),
                groups: Vec::new(),
            });
        }
        assert!(decide(&set, &ask).allow);
        if let Ask::UseSecret { ttl_s, .. } = &mut ask {
            *ttl_s = 3600;
        }
        assert!(!decide(&set, &ask).allow, "too long");
    }

    /// P3-4e — a policy may say WHO approves: the approver is read in the
    /// groups they hold, as a person assuming a role is. One person's yes
    /// is not another's, and a person in no named group allows nothing.
    #[test]
    fn a_policy_may_name_whose_approval_counts() {
        let p = r#"permit (principal in MeshHarbor::Role::"deployer",
            action == MeshHarbor::Action::"secret:use", resource)
            when { context has approval && context.approval.approver in MeshHarbor::Group::"admin" };"#;
        let set = set_with(&[p]);
        let mut ask = use_secret(Some("deployer"), "deploy/key", &[], "proxy", "linux");
        let approved_by = |ask: &mut Ask, groups: &[&str]| {
            if let Ask::UseSecret { approver, .. } = ask {
                *approver = Some(Approver {
                    id: ObjectId::new(),
                    groups: groups.iter().map(|g| g.to_string()).collect(),
                });
            }
        };
        assert!(!decide(&set, &ask).allow, "no approval");
        approved_by(&mut ask, &["member"]);
        assert!(!decide(&set, &ask).allow, "a member's yes");
        approved_by(&mut ask, &[]);
        assert!(!decide(&set, &ask).allow, "a yes from no group");
        // A group named twice is one group, never an entity Cedar refuses.
        approved_by(&mut ask, &["member", "admin", "admin"]);
        let v = decide(&set, &ask);
        assert!(v.allow && v.errors.is_empty(), "an admin's yes: {v:?}");
    }

    /// P3-4e — four eyes: a policy may refuse a session's owner as the
    /// approver of their own session's use, and take anyone else's yes.
    #[test]
    fn a_policy_may_refuse_an_owners_yes_to_their_own_session() {
        let p = r#"permit (principal in MeshHarbor::Role::"deployer",
            action == MeshHarbor::Action::"secret:use", resource)
            when { context has approval };"#;
        let f = r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource)
            when { context has approval && context.approval.approver == principal.owner };"#;
        let set = set_with(&[p, f]);
        let mut ask = use_secret(Some("deployer"), "deploy/key", &[], "proxy", "linux");
        let Ask::UseSecret { session, .. } = &ask else {
            unreachable!()
        };
        let owner = session.owner;
        let approved_by = |ask: &mut Ask, id: ObjectId| {
            if let Ask::UseSecret { approver, .. } = ask {
                *approver = Some(Approver {
                    id,
                    groups: vec!["admin".into()],
                });
            }
        };
        approved_by(&mut ask, owner);
        let v = decide(&set, &ask);
        assert!(!v.allow, "the owner's own yes: {v:?}");
        assert_eq!(v.determining, ["policy:1"], "the forbid decided it");
        approved_by(&mut ask, ObjectId::new());
        assert!(decide(&set, &ask).allow, "another's yes");
    }

    #[test]
    fn a_policy_is_checked_before_it_is_kept() {
        let n = names();
        assert_eq!(check_policy(DEV_STAGING, &n).unwrap().effect, "permit");
        let refused = [
            ("", "empty"),
            ("permit (principal, action, resource)", "not a Cedar policy"),
            (
                "permit (principal, action, resource); permit (principal, action, resource);",
                "not a Cedar policy",
            ),
            (
                r#"permit (principal, action == MeshHarbor::Action::"secret:read", resource);"#,
                "schema",
            ),
            (
                r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource) when { context.nope == 1 };"#,
                "schema",
            ),
            (
                r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:other:secret:prod");"#,
                "not this organization",
            ),
            (
                r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:grox:secret:Prod");"#,
                "segment",
            ),
            (
                r#"permit (principal in MeshHarbor::Role::"admin2", action, resource);"#,
                "vault roles",
            ),
            (
                r#"permit (principal in MeshHarbor::Group::"ghosts", action, resource);"#,
                "roles",
            ),
            (
                r#"permit (principal == MeshHarbor::Session::"abc", action, resource);"#,
                "one session",
            ),
            (
                r#"permit (principal == MeshHarbor::User::"not-an-id", action, resource);"#,
                "user id",
            ),
            (
                r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource) when { resource in MeshHarbor::SecretFolder::"rrn:other:secret:x" };"#,
                "not this organization",
            ),
        ];
        for (text, why) in refused {
            let e = check_policy(text, &n).expect_err(text);
            assert!(e.contains(why), "{text}\n→ {e}");
        }
        let u = ObjectId::new();
        let named = format!(
            r#"forbid (principal == MeshHarbor::User::"{}", action, resource);"#,
            u.to_hex()
        );
        let c = check_policy(&named, &n).unwrap();
        assert_eq!(
            (c.effect, c.users.iter().copied().collect::<Vec<_>>()),
            ("forbid", vec![u])
        );
    }

    #[test]
    fn a_set_that_does_not_build_is_an_error_not_a_skip() {
        let r = policy_set([(
            "policy:1".to_string(),
            "forbid (principal, action, resource",
        )]);
        assert!(r.is_err());
    }

    #[test]
    fn a_device_context_takes_the_rows_spellings_only() {
        assert!(DeviceFacts::new("Windows", &[], ObjectId::new()).is_err());
        assert!(DeviceFacts::new("win32", &[], ObjectId::new()).is_err());
        let d = DeviceFacts::new("macos", &[" Build ".into()], ObjectId::new()).unwrap();
        assert_eq!(d.tags, ["build"]);
    }

    #[test]
    fn folders_are_every_prefix_innermost_first() {
        assert_eq!(folders("a/b/c"), ["a/b", "a"]);
        assert!(folders("a").is_empty());
    }

    /// P3-4b — listing is its own permission: a role allowed to use a secret
    /// lists nothing until a policy lets it list, and listing uses nothing.
    #[test]
    fn a_list_permit_is_its_own_and_neither_implies_the_other() {
        let uses = set_with(&[DEV_STAGING]);
        assert!(
            !decide(&uses, &list_secret(Some("dev"), "staging/db", "linux")).allow,
            "a use permit lists nothing"
        );
        let lists = set_with(&[DEV_LISTS_STAGING]);
        let ok = decide(
            &lists,
            &list_secret(Some("dev"), "staging/db/main", "linux"),
        );
        assert!(ok.allow, "{ok:?}");
        assert_eq!(ok.determining, ["policy:0"]);
        for ask in [
            list_secret(Some("dev"), "prod/db", "linux"),
            list_secret(Some("deployer"), "staging/db", "linux"),
            list_secret(None, "staging/db", "linux"),
            use_secret(Some("dev"), "staging/db", &[], "proxy", "linux"),
        ] {
            assert!(!decide(&lists, &ask).allow, "{ask:?}");
        }
    }

    /// P3-4b — the guardrails are about using a value: neither stops a
    /// listing, on Windows or of a production secret.
    #[test]
    fn no_guardrail_stops_a_listing() {
        let any = r#"permit (principal, action == MeshHarbor::Action::"secret:list", resource);"#;
        let set = set_with(&[any]);
        for ask in [
            list_secret(Some("dev"), "staging/db", "windows"),
            list_secret(Some("dev"), "prod/db", "linux"),
        ] {
            let v = decide(&set, &ask);
            assert!(v.allow && v.errors.is_empty(), "{ask:?} {v:?}");
        }
    }

    #[test]
    fn a_recorded_request_reads_back_as_it_was_decided() {
        // P3-2b — a replay decides exactly what was decided: every fact the
        // request held survives the audit row's round trip.
        let assume = Ask::AssumeRole {
            user: ObjectId::new(),
            groups: vec!["member".into(), "ops".into()],
            role: "dev".into(),
            device: device("windows", &["Build"]),
        };
        let mut used = use_secret(Some("deployer"), "prod/db", &["prod"], "proxy", "macos");
        if let Ask::UseSecret {
            approver, session, ..
        } = &mut used
        {
            *approver = Some(Approver {
                id: ObjectId::new(),
                groups: vec!["admin".into(), "ops".into()],
            });
            session.playbook = Some("deploy-prod".into());
        }
        let listed = list_secret(Some("dev"), "staging/db", "windows");
        for ask in [
            assume,
            used,
            use_secret(None, "x", &[], "env", "linux"),
            listed,
        ] {
            let back = Ask::from_doc(&ask.to_doc()).expect("reads back");
            assert_eq!(format!("{back:?}"), format!("{ask:?}"));
            // And decides alike.
            let set = set_with(&[r#"permit (principal, action, resource);"#]);
            assert_eq!(decide(&set, &back), decide(&set, &ask));
        }
        // A row of another shape is unreadable, never a guess.
        assert!(Ask::from_doc(&bson::doc! { "action": "secret:read" }).is_none());
        assert!(Ask::from_doc(&bson::doc! { "action": "role:assume", "user": "x" }).is_none());
    }

    /// P3-4e — an approver recorded before their groups were reads back in
    /// none, as it was decided then; groups that are not names make the row
    /// one no replay can read.
    #[test]
    fn an_approver_recorded_without_groups_reads_back_in_none() {
        let id = ObjectId::new();
        let mut ask = use_secret(Some("deployer"), "deploy/key", &[], "proxy", "linux");
        if let Ask::UseSecret { approver, .. } = &mut ask {
            *approver = Some(Approver {
                id,
                groups: vec!["admin".into()],
            });
        }
        let mut doc = ask.to_doc();
        doc.remove("approver_groups");
        match Ask::from_doc(&doc) {
            Some(Ask::UseSecret {
                approver: Some(a), ..
            }) => assert_eq!(
                a,
                Approver {
                    id,
                    groups: Vec::new()
                }
            ),
            other => panic!("{other:?}"),
        }
        doc.insert("approver_groups", vec![bson::Bson::Int32(1)]);
        assert!(Ask::from_doc(&doc).is_none());
    }

    fn session(role: Option<&str>) -> SessionFacts {
        SessionFacts {
            id: ObjectId::new().to_hex(),
            owner: ObjectId::new(),
            role: role.map(String::from),
            playbook: None,
        }
    }

    fn node(tags: &[&str]) -> NodeFacts {
        let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
        NodeFacts::new(ObjectId::new(), "linux", &tags, ObjectId::new()).unwrap()
    }

    fn net_socks(role: Option<&str>, tags: &[&str]) -> Ask {
        Ask::NetSocks {
            session: session(role),
            node: node(tags),
            device: device("macos", &[]),
        }
    }

    fn net_forward(role: Option<&str>, tags: &[&str], host: &str, port: u16) -> Ask {
        Ask::NetForward {
            session: session(role),
            node: node(tags),
            host: host.into(),
            port,
            device: device("linux", &[]),
        }
    }

    const DEV_SOCKS_THROUGH_OFFICE: &str = r#"permit (principal in MeshHarbor::Role::"dev",
        action == MeshHarbor::Action::"net:socks",
        resource) when { resource.tags.contains("office") };"#;

    /// P3-7 — a session's role is permitted SOCKS through an exit by the
    /// exit's tags, and nothing else follows: another exit, another role, no
    /// role, or a forward is each denied.
    #[test]
    fn a_role_may_open_socks_through_the_exits_a_policy_names() {
        let set = set_with(&[DEV_SOCKS_THROUGH_OFFICE]);
        assert!(
            decide(&set, &net_socks(Some("dev"), &["Office"])).allow,
            "tags are lowercased"
        );
        for (ask, why) in [
            (net_socks(Some("dev"), &["lab"]), "another exit"),
            (net_socks(Some("deployer"), &["office"]), "another role"),
            (net_socks(None, &["office"]), "no role"),
            (
                net_forward(Some("dev"), &["office"], "db.internal", 5432),
                "a forward is not a SOCKS listener",
            ),
        ] {
            assert!(!decide(&set, &ask).allow, "{why}");
        }
    }

    /// P3-7 — a forward is decided toward its destination, which a policy
    /// reads from the context.
    #[test]
    fn a_forward_is_decided_toward_its_destination() {
        let set = set_with(&[r#"permit (principal in MeshHarbor::Role::"dev",
            action == MeshHarbor::Action::"net:forward",
            resource) when { context.port == 5432 && context.host like "*.internal" };"#]);
        assert!(decide(&set, &net_forward(Some("dev"), &[], "db.internal", 5432)).allow);
        for (host, port) in [("db.internal", 22), ("db.example.com", 5432)] {
            assert!(
                !decide(&set, &net_forward(Some("dev"), &[], host, port)).allow,
                "{host}:{port}"
            );
        }
        assert!(
            !decide(&set, &net_socks(Some("dev"), &[])).allow,
            "a forward's permit opens no SOCKS listener"
        );
    }

    /// P3-7 — a net request reads back from its record exactly, and decides
    /// alike; a port past `u16` makes the row unreadable.
    #[test]
    fn a_net_request_reads_back_from_its_record() {
        for ask in [
            net_socks(Some("dev"), &["office"]),
            net_forward(Some("dev"), &["office"], "db.internal", 5432),
        ] {
            let back = Ask::from_doc(&ask.to_doc()).expect("reads back");
            assert_eq!(format!("{back:?}"), format!("{ask:?}"));
            let set = set_with(&[DEV_SOCKS_THROUGH_OFFICE]);
            assert_eq!(decide(&set, &back), decide(&set, &ask));
        }
        let mut doc = net_forward(Some("dev"), &[], "db.internal", 5432).to_doc();
        doc.insert("port", 70_000_i32);
        assert!(Ask::from_doc(&doc).is_none());
    }

    /// P3-7 — a policy may name an exit by its device's id, which the route
    /// then checks is this organization's; an id that is no device id is
    /// refused.
    #[test]
    fn a_policy_names_an_exit_by_its_device_id() {
        let id = ObjectId::new();
        let checked = check_policy(
            &format!(
                r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"net:socks",
                resource == MeshHarbor::Node::"{}");"#,
                id.to_hex()
            ),
            &names(),
        )
        .unwrap();
        assert_eq!(checked.nodes, [id].into_iter().collect());
        let not_an_id = check_policy(
            r#"permit (principal, action == MeshHarbor::Action::"net:socks", resource == MeshHarbor::Node::"office");"#,
            &names(),
        );
        assert!(not_an_id.unwrap_err().contains("is not a device id"));
    }

    /// P3-2c — a policy that can never apply is refused, a `forbid` above
    /// all: kept, it would forbid nothing its writer meant it to. Cedar
    /// reports both shapes only as warnings, a scope no action applies to and
    /// a condition that is always false.
    #[test]
    fn a_policy_that_can_never_apply_is_refused() {
        let node = ObjectId::new().to_hex();
        // Cedar's own words for each shape, which the refusal carries.
        let no_action = "unable to find an applicable action";
        let always_false = "policy is impossible";
        for (text, why, cedar) in [
            (
                format!(
                    r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource == MeshHarbor::Node::"{node}");"#
                ),
                "a Node where secret:use takes a Secret",
                no_action,
            ),
            (
                r#"forbid (principal, action == MeshHarbor::Action::"net:socks", resource is MeshHarbor::Secret);"#
                    .to_string(),
                "a Secret where net:socks takes a Node",
                no_action,
            ),
            (
                r#"forbid (principal, action == MeshHarbor::Action::"net:socks", resource) when { false };"#
                    .to_string(),
                "a condition that is always false",
                always_false,
            ),
        ] {
            let refused = check_policy(&text, &names()).expect_err(why);
            assert!(refused.contains("can never apply"), "{why}: {refused}");
            assert!(refused.contains(cedar), "{why}: {refused}");
        }
        // What can apply is kept, a forbid as a permit.
        for text in [
            format!(
                r#"forbid (principal, action == MeshHarbor::Action::"net:socks", resource == MeshHarbor::Node::"{node}");"#
            ),
            r#"forbid (principal, action == MeshHarbor::Action::"net:forward", resource) when { context.port == 22 };"#
                .to_string(),
        ] {
            check_policy(&text, &names()).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
    }

    fn ssh_run(role: Option<&str>, tags: &[&str], account: &str) -> Ask {
        Ask::SshRun {
            session: session(role),
            node: node(tags),
            account: account.into(),
            device: device("linux", &[]),
        }
    }

    const DEV_RUNS_ON_BUILD: &str = r#"permit (principal in MeshHarbor::Role::"dev",
        action == MeshHarbor::Action::"ssh:run",
        resource) when { resource.tags.contains("build") };"#;

    /// P3-8 — a session's role is permitted a command on a node by the
    /// node's tags, and nothing else follows: another node, another role, no
    /// role, or egress through the same node; nor does egress imply a
    /// command.
    #[test]
    fn a_role_may_run_a_command_on_the_nodes_a_policy_names() {
        let set = set_with(&[DEV_RUNS_ON_BUILD]);
        assert!(
            decide(&set, &ssh_run(Some("dev"), &["Build"], "console_user")).allow,
            "tags are lowercased"
        );
        for (ask, why) in [
            (
                ssh_run(Some("dev"), &["lab"], "console_user"),
                "another node",
            ),
            (
                ssh_run(Some("deployer"), &["build"], "console_user"),
                "another role",
            ),
            (ssh_run(None, &["build"], "console_user"), "no role"),
            (
                net_socks(Some("dev"), &["build"]),
                "a command is not a SOCKS listener",
            ),
        ] {
            assert!(!decide(&set, &ask).allow, "{why}");
        }
        let socks = set_with(&[DEV_SOCKS_THROUGH_OFFICE]);
        assert!(
            !decide(&socks, &ssh_run(Some("dev"), &["office"], "console_user")).allow,
            "egress through a node runs nothing on it"
        );
    }

    /// P3-8 — the account the node maps is in the context, so a guardrail
    /// can forbid a session the daemon's (SYSTEM or root) whatever permits
    /// it: a `forbid` beats every `permit`.
    #[test]
    fn a_guardrail_may_forbid_a_session_the_daemons_account() {
        let set = set_with(&[
            DEV_RUNS_ON_BUILD,
            r#"forbid (principal, action == MeshHarbor::Action::"ssh:run", resource)
                when { context.account == "daemon" };"#,
        ]);
        assert!(decide(&set, &ssh_run(Some("dev"), &["build"], "console_user")).allow);
        assert!(decide(&set, &ssh_run(Some("dev"), &["build"], "named")).allow);
        let as_daemon = decide(&set, &ssh_run(Some("dev"), &["build"], "daemon"));
        assert!(!as_daemon.allow, "the daemon's account is forbidden");
        assert_eq!(as_daemon.determining.len(), 1, "{as_daemon:?}");
    }

    /// P3-8 — an SSH request reads back from its record exactly, its account
    /// included, and decides alike; a row without its account is unreadable.
    #[test]
    fn an_ssh_request_reads_back_from_its_record() {
        let ask = ssh_run(Some("dev"), &["build"], "daemon");
        let back = Ask::from_doc(&ask.to_doc()).expect("reads back");
        assert_eq!(format!("{back:?}"), format!("{ask:?}"));
        let set = set_with(&[DEV_RUNS_ON_BUILD]);
        assert_eq!(decide(&set, &back), decide(&set, &ask));
        let mut doc = ask.to_doc();
        doc.remove("account");
        assert!(Ask::from_doc(&doc).is_none());
    }

    /// P3-8 — `ssh:run` takes a Node, as `net:*` does: a policy naming a
    /// Secret for it can never apply, and the guardrail on the daemon's
    /// account is kept.
    #[test]
    fn an_ssh_policy_is_checked_as_a_net_one_is() {
        let refused = check_policy(
            r#"forbid (principal, action == MeshHarbor::Action::"ssh:run", resource is MeshHarbor::Secret);"#,
            &names(),
        )
        .expect_err("a Secret where ssh:run takes a Node");
        assert!(refused.contains("can never apply"), "{refused}");
        for text in [
            r#"forbid (principal, action == MeshHarbor::Action::"ssh:run", resource) when { context.account == "daemon" };"#
                .to_string(),
            format!(
                r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"ssh:run", resource == MeshHarbor::Node::"{}");"#,
                ObjectId::new().to_hex()
            ),
        ] {
            check_policy(&text, &names()).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
    }

    /// P3-9-1 — a person, `user` in `groups`, the owner of a Linux device,
    /// connecting to `path` toward `audience`; the secret names
    /// `db.internal:5432` as its one upstream.
    fn connect(groups: &[&str], path: &str, tags: &[&str], audience: &str) -> Ask {
        let user = ObjectId::new();
        Ask::ConnectSecret {
            user,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            secret: SecretFacts {
                prefix: ORG.into(),
                path: path.into(),
                kind: "structured".into(),
                tags: tags.iter().map(|t| t.to_string()).collect(),
                exec_allow: Vec::new(),
                audiences: vec!["db.internal:5432".into()],
            },
            audience: audience.into(),
            ttl_s: 600,
            device: DeviceFacts::new("linux", &[], user).unwrap(),
            approver: None,
        }
    }

    const MEMBERS_CONNECT_TO_DB: &str = r#"permit (principal in MeshHarbor::Group::"member",
        action == MeshHarbor::Action::"secret:connect",
        resource in MeshHarbor::SecretFolder::"rrn:grox:secret:db");"#;

    /// P3-9-1 — only a permit that names `secret:connect` admits a person: one
    /// written for sessions does not, and neither does one whose scope names
    /// no action, however wide. A `forbid` that names no action still binds.
    #[test]
    fn a_person_is_admitted_only_by_a_permit_that_names_their_action() {
        let asked = connect(&["member"], "db/orders", &[], "db.internal:5432");
        let ok = decide(&set_with(&[MEMBERS_CONNECT_TO_DB]), &asked);
        assert!(ok.allow && ok.errors.is_empty(), "{ok:?}");
        assert_eq!(ok.determining, ["policy:0"]);
        for wide in [
            r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#,
            r#"permit (principal, action, resource);"#,
            r#"permit (principal in MeshHarbor::Group::"member", action, resource);"#,
        ] {
            let v = decide(&set_with(&[wide]), &asked);
            assert!(!v.allow, "{wide}: {v:?}");
            assert!(
                v.determining.is_empty() && v.errors.is_empty(),
                "{wide}: {v:?}"
            );
        }
        // Named in a list, it counts.
        let listed = r#"permit (principal in MeshHarbor::Group::"member",
            action in [MeshHarbor::Action::"secret:use", MeshHarbor::Action::"secret:connect"],
            resource);"#;
        assert!(decide(&set_with(&[listed]), &asked).allow);
        // A forbid whose scope names no action binds a person too.
        let v = decide(
            &set_with(&[
                MEMBERS_CONNECT_TO_DB,
                r#"forbid (principal, action, resource) when { resource.path == "db/orders" };"#,
            ]),
            &asked,
        );
        assert!(!v.allow);
        assert_eq!(v.determining, ["policy:1"]);
        // And the narrowing is the person's alone: a session is admitted by
        // an action-less permit as it always was.
        let session_ask = use_secret(Some("dev"), "db/orders", &[], "env", "linux");
        assert!(
            decide(
                &set_with(&[r#"permit (principal, action, resource);"#]),
                &session_ask
            )
            .allow
        );
    }

    /// P3-9-1 — a person's endpoint signs in only to an upstream its secret
    /// names, exactly, never with a dynamic secret's field, and never to a
    /// production secret (decision 24): whatever a policy permits, and
    /// whatever someone's yes would say.
    #[test]
    fn a_persons_endpoint_is_held_by_its_own_guardrails() {
        let any =
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource);"#;
        let set = set_with(&[any]);
        assert!(decide(&set, &connect(&[], "db/orders", &[], "db.internal:5432")).allow);
        let with_yes = |mut ask: Ask| {
            if let Ask::ConnectSecret { approver, .. } = &mut ask {
                *approver = Some(Approver {
                    id: ObjectId::new(),
                    groups: vec!["admin".into()],
                });
            }
            ask
        };
        let dynamic = || {
            let mut ask = connect(&[], "db/dyn", &[], "db.internal:5432");
            if let Ask::ConnectSecret { secret, .. } = &mut ask {
                secret.kind = "dynamic".into();
            }
            ask
        };
        for (ask, guardrail) in [
            (
                connect(&[], "db/orders", &[], "evil.example:5432"),
                "guardrail:connect-only-named-audiences",
            ),
            (
                connect(&[], "db/orders", &[], "DB.internal:5432"),
                "guardrail:connect-only-named-audiences",
            ),
            (
                connect(&[], "db/orders", &[], ""),
                "guardrail:connect-only-named-audiences",
            ),
            (dynamic(), "guardrail:connect-never-dynamic"),
            (
                connect(&[], "prod", &[], "db.internal:5432"),
                "guardrail:connect-never-prod",
            ),
            (
                connect(&[], "prod/db", &[], "db.internal:5432"),
                "guardrail:connect-never-prod",
            ),
            (
                connect(&[], "svc/db", &["prod"], "db.internal:5432"),
                "guardrail:connect-never-prod",
            ),
        ] {
            for ask in [ask.clone(), with_yes(ask)] {
                let v = decide(&set, &ask);
                assert!(!v.allow, "{ask:?}: {v:?}");
                assert_eq!(v.determining, [guardrail], "{ask:?}");
            }
        }
        // A sibling whose name merely starts the same is no prod path.
        assert!(
            decide(
                &set,
                &connect(&[], "production/db", &[], "db.internal:5432")
            )
            .allow
        );
    }

    /// P3-9-1 — a person's request in a policy's terms: `principal` is the
    /// person, in their groups; `context.device.owner` is the same person,
    /// and `context.approval` exists only when a yes was given. A person and
    /// an approver who share a group, or one person as both, decide without
    /// an error: each shared entity is the same both times.
    #[test]
    fn a_persons_request_reads_as_a_policy_names_it() {
        let set = set_with(&[
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource)
            when { principal == context.device.owner && context has approval
                   && context.approval.approver in MeshHarbor::Group::"admin"
                   && context.approval.approver != principal };"#,
        ]);
        let mut ask = connect(&["member", "admin"], "db/orders", &[], "db.internal:5432");
        let v = decide(&set, &ask);
        assert!(!v.allow && v.errors.is_empty(), "no yes was given: {v:?}");
        if let Ask::ConnectSecret { approver, .. } = &mut ask {
            *approver = Some(Approver {
                id: ObjectId::new(),
                groups: vec!["admin".into(), "member".into()],
            });
        }
        let v = decide(&set, &ask);
        assert!(v.allow && v.errors.is_empty(), "{v:?}");
        // Their own yes is no yes.
        if let Ask::ConnectSecret {
            approver: Some(a),
            user,
            ..
        } = &mut ask
        {
            a.id = *user;
        }
        let v = decide(&set, &ask);
        assert!(!v.allow && v.errors.is_empty(), "{v:?}");
    }

    /// P3-9-1 — a person's request reads back from its record exactly, its
    /// groups and an approver included, and decides alike; a row without its
    /// person is unreadable.
    #[test]
    fn a_persons_request_reads_back_from_its_record() {
        let mut ask = connect(&["member", "ops"], "db/orders", &["pg"], "db.internal:5432");
        for approver in [
            None,
            Some(Approver {
                id: ObjectId::new(),
                groups: vec!["admin".into()],
            }),
        ] {
            if let Ask::ConnectSecret { approver: a, .. } = &mut ask {
                *a = approver;
            }
            let back = Ask::from_doc(&ask.to_doc()).expect("reads back");
            assert_eq!(format!("{back:?}"), format!("{ask:?}"));
            let set = set_with(&[MEMBERS_CONNECT_TO_DB]);
            assert_eq!(decide(&set, &back), decide(&set, &ask));
        }
        let mut doc = ask.to_doc();
        doc.remove("user");
        assert!(Ask::from_doc(&doc).is_none());
    }

    /// P3-9-1 — `secret:connect` takes a person: a policy that names a role
    /// for it, which only a session assumes, can never apply and is refused;
    /// one that names a group, a member, or the device's owner is kept.
    #[test]
    fn a_connect_policy_names_people_never_sessions() {
        let refused = check_policy(
            r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:connect", resource);"#,
            &names(),
        )
        .expect_err("a role where secret:connect takes a person");
        assert!(refused.contains("can never apply"), "{refused}");
        for text in [
            MEMBERS_CONNECT_TO_DB.to_string(),
            format!(
                r#"permit (principal == MeshHarbor::User::"{}", action == MeshHarbor::Action::"secret:connect", resource);"#,
                ObjectId::new().to_hex()
            ),
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource) when { principal == context.device.owner && context.ttl_s <= 300 };"#.to_string(),
        ] {
            check_policy(&text, &names()).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
    }
}
