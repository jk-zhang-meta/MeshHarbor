// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-3b — leases: a value released to one agent session, sealed to the vault
//! key of the daemon that runs it.
//!
//! A session's device asks over its own control connection
//! (`rc:vault.lease`), and the vault answers on that connection: the value as
//! a sealed box for the key the device's hello carried (`rc:vault.leased`),
//! or one word (`rc:vault.refused`, [`LeaseRefusal`]).
//!
//! | Check, in order | Refused as | Recorded |
//! |---|---|---|
//! | the request within its bounds, in a mode that releases a stored value | `bad_request` | no |
//! | the vault serves the organization | `not_served` | no |
//! | the device takes leases: its hello advertised `vault` and carried a key | `unsupported` | no |
//! | a session of the organization whose record places it on THIS device | `not_located` | no |
//! | at the record's fence | `stale_fence` | yes |
//! | live | `ended` | yes |
//! | within the session's per-minute ceiling | `busy` | no |
//! | holding a vault role | `no_role` | yes |
//! | the secret, by path or by this organization's RRN, live | `no_secret` | yes |
//! | not disabled | `disabled` | yes |
//! | its field holding a value | `no_value` | yes |
//! | a usable KEK | `unavailable` | yes |
//! | Cedar's `secret:use` | `denied` | yes, with the request |
//! | P3-4e — where it denied: a driver's yes that lifts it ([`crate::approval`]), else a card that waits for one | `awaiting_approval` · `denied` | yes, with the request |
//! | its version not past the `expires_at` its writer gave (P3-3c) | `no_value` | yes |
//! | opened, and sealed to the device's key | `unavailable` | yes |
//! | P3-4e — a yes that allowed it spent (compare-and-set) | `denied` | yes |
//! | the allow recorded and the lease written | `undecided` | — |
//!
//! A lease ends at its TTL or at its version's `expires_at`, whichever comes
//! first (P3-3c), and earlier when the vault takes it back ([`crate::revoke`]).
//!
//! ⚠️ A request is believed only from the device the session's RECORD places
//! it on, at the record's fence — hive's identity rule for its own frames. A
//! device cannot lease for a session it does not run, and a run that lost its
//! session to a move cannot lease for it any more.
//!
//! ⚠️ What a policy reads of the device comes from its ROW, never from the
//! request.
//!
//! ⚠️ The allow is recorded and the lease written BEFORE the sealed value is
//! sent: a lease the vault could not record is never released.
//!
//! ⚠️ Until the session is identified, a refusal is logged, not recorded:
//! there is no session to name yet, and a device's flood of them must not
//! become audit rows.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine;
use bson::{DateTime, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_core::{AgentCtx, AgentMsgHandler, AgentSocketLifecycle};
use meshharbor_mod_hive::model::{AgentSession, SessionStatus};
use meshharbor_remote_control::{
    models::{Agent, OsKind, RpcCap},
    signaling::{ClientMsg, ServerMsg},
    vault::{LeaseRefusal, VaultActivityKind, lease_limits, program_name_ok, providers::Provider},
};
use meshharbor_services::dao::base::DaoError;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::VaultState;
use crate::approval::{self, Next};
use crate::crypto::{self, Binding};
use crate::dao::ApprovalKey;
use crate::dynamic;
use crate::model::{KIND_DYNAMIC, VaultActivity, VaultAuditEvent, VaultLease, VaultSecret};
use crate::policy::{self, Ask, DeviceFacts, SecretFacts, SessionFacts, Verdict};
use crate::policy_routes::decide_for_org;
use crate::revoke;
use crate::rrn;

/// The modes a lease may be asked in: those that hand the daemon a STORED
/// value, and (P3-6b) `short-lived`, which hands it a dynamic secret's
/// issuer to mint a credential with. `identity` releases nothing (the
/// session authenticates as itself), and `placeholder` is P3b's: a lease in
/// either would release a value the policy that permits the mode never
/// meant to. Which kind each mode leases is the guardrails' to decide
/// (`dynamic-only-short-lived`, `short-lived-only-dynamic`).
pub const LEASE_MODES: &[&str] = &["proxy", "file", "env", "exec", "short-lived"];

/// One `rc:vault.lease`, as it arrived.
#[derive(Debug, Clone)]
pub struct LeaseRequest {
    pub req_id: String,
    pub session_id: ObjectId,
    pub fence: u64,
    pub secret: String,
    pub field: String,
    pub mode: String,
    pub audience: String,
    pub ttl_secs: u32,
}

/// P3-4b — one `rc:vault.list`, as it arrived.
#[derive(Debug, Clone)]
pub struct ListRequest {
    pub req_id: String,
    pub session_id: ObjectId,
    pub fence: u64,
    pub prefix: String,
}

/// P3-4b — one `rc:vault.describe`, as it arrived.
#[derive(Debug, Clone)]
pub struct DescribeRequest {
    pub req_id: String,
    pub session_id: ObjectId,
    pub fence: u64,
    pub secret: String,
}

/// P3-4d — one `rc:vault.activity`, as it arrived: a device's claim of a
/// use, answered with nothing.
#[derive(Debug, Clone)]
pub struct ActivityReport {
    pub session_id: ObjectId,
    pub fence: u64,
    pub kind: String,
    pub lease_ids: Vec<String>,
    pub target: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// What a session's device asked of the vault, queued in the order it came.
#[derive(Debug, Clone)]
pub enum Request {
    Lease(LeaseRequest),
    List(ListRequest),
    Describe(DescribeRequest),
    /// P3-4d — in the same queue, so a flood of reports is dropped at its
    /// bound like a flood of requests, and answered with nothing.
    Activity(ActivityReport),
    /// P3-7-1b — a session's own egress ([`crate::net`]), answered in order
    /// with the leases.
    Net(crate::net::NetRequest),
    /// P3-8-1a — a session's command on another device ([`crate::ssh`]),
    /// answered in order with the leases.
    Ssh(crate::ssh::SshRequest),
    /// P3-9-1 — a person's use, through an endpoint the device serves them
    /// ([`crate::connect`]): in the same queue, so it waits its turn behind
    /// the device's sessions and a flood of it is answered `busy`.
    Connect(crate::connect::ConnectRequest),
}

impl Request {
    /// The id an answer names; none for a report, which gets no answer.
    fn req_id(&self) -> Option<&str> {
        match self {
            Self::Lease(r) => Some(&r.req_id),
            Self::List(r) => Some(&r.req_id),
            Self::Describe(r) => Some(&r.req_id),
            Self::Activity(_) => None,
            Self::Net(r) => Some(&r.req_id),
            Self::Ssh(r) => Some(&r.req_id),
            Self::Connect(r) => Some(&r.req_id),
        }
    }
}

/// P3-4e — a lease's refusal: the word, and with `awaiting_approval` the
/// approval its card waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub why: LeaseRefusal,
    pub approval: Option<ObjectId>,
}

impl From<LeaseRefusal> for Refused {
    fn from(why: LeaseRefusal) -> Self {
        Self {
            why,
            approval: None,
        }
    }
}

/// What a granted lease answers with.
#[derive(Debug)]
pub struct Leased {
    pub lease_id: ObjectId,
    pub n: i64,
    pub sealed: Vec<u8>,
    pub expires_at: DateTime,
    /// P3-6b — a dynamic secret's provider: `sealed` is then its bundle.
    pub provider: Option<&'static str>,
}

/// The connection a request arrived on: whose device, in which organization.
#[derive(Debug, Clone, Copy)]
pub struct Conn {
    pub tenant_id: ObjectId,
    pub device_id: ObjectId,
}

/// The vault's half of the agent socket: one queue per connection, answered
/// in order by one task, so a slow decision never holds the socket's read
/// loop and a flood is answered `busy` instead of queued.
pub struct LeaseSocket {
    state: VaultState,
    conns: DashMap<String, mpsc::Sender<Request>>,
}

impl LeaseSocket {
    pub fn new(state: VaultState) -> Self {
        Self {
            state,
            conns: DashMap::new(),
        }
    }
}

#[async_trait]
impl AgentMsgHandler for LeaseSocket {
    async fn handle(&self, ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg> {
        let req = match msg {
            ClientMsg::VaultLease {
                req_id,
                session_id,
                fence,
                secret,
                field,
                mode,
                audience,
                ttl_secs,
            } => Request::Lease(LeaseRequest {
                req_id,
                session_id,
                fence,
                secret,
                field,
                mode,
                audience,
                ttl_secs,
            }),
            ClientMsg::VaultList {
                req_id,
                session_id,
                fence,
                prefix,
            } => Request::List(ListRequest {
                req_id,
                session_id,
                fence,
                prefix,
            }),
            ClientMsg::VaultDescribe {
                req_id,
                session_id,
                fence,
                secret,
            } => Request::Describe(DescribeRequest {
                req_id,
                session_id,
                fence,
                secret,
            }),
            ClientMsg::VaultActivity {
                session_id,
                fence,
                kind,
                lease_ids,
                target,
                exit_code,
                timed_out,
            } => Request::Activity(ActivityReport {
                session_id,
                fence,
                kind,
                lease_ids,
                target,
                exit_code,
                timed_out,
            }),
            ClientMsg::VaultNet {
                req_id,
                session_id,
                fence,
                exit,
                kind,
                host,
                port,
                ttl_secs,
            } => Request::Net(crate::net::NetRequest {
                req_id,
                session_id,
                fence,
                exit,
                kind,
                host,
                port,
                ttl_secs,
            }),
            ClientMsg::VaultSsh {
                req_id,
                session_id,
                fence,
                target,
                ttl_secs,
            } => Request::Ssh(crate::ssh::SshRequest {
                req_id,
                session_id,
                fence,
                target,
                ttl_secs,
            }),
            ClientMsg::VaultConnect {
                req_id,
                secret,
                field,
                audience,
                ttl_secs,
            } => Request::Connect(crate::connect::ConnectRequest {
                req_id,
                secret,
                field,
                audience,
                ttl_secs,
            }),
            other => return Some(other),
        };
        let queued = match self.conns.get(&ctx.conn_id).map(|q| q.value().clone()) {
            Some(queue) => queue.try_send(req).map_err(|e| match e {
                TrySendError::Full(r) | TrySendError::Closed(r) => r,
            }),
            None => Err(req),
        };
        if let Err(req) = queued {
            debug!(device = %ctx.agent_id, "vault: a request found its connection's queue full");
            // A report gets no answer, not even this one: it is dropped.
            if let Some(req_id) = req.req_id() {
                let _ = ctx.tx.try_send(refusal(req_id, LeaseRefusal::Busy));
            }
        }
        None
    }
}

#[async_trait]
impl AgentSocketLifecycle for LeaseSocket {
    async fn hello(&self, ctx: &AgentCtx) {
        let (tx, rx) = mpsc::channel(lease_limits::QUEUE_PER_CONNECTION);
        self.conns.insert(ctx.conn_id.clone(), tx);
        let conn = Conn {
            tenant_id: ctx.tenant_id,
            device_id: ctx.agent_id,
        };
        // Held weakly: a closed or displaced connection's channel is not
        // kept open by the task that answers it.
        tokio::spawn(answer_in_order(
            self.state.clone(),
            conn,
            rx,
            ctx.tx.downgrade(),
        ));
        // P3-3c — the connection a revocation is told on, and what this
        // device missed while it was away.
        self.state
            .revoker
            .link(ctx.agent_id, &ctx.conn_id, ctx.tx.downgrade());
        tokio::spawn(revoke::reconcile(self.state.clone(), ctx.agent_id));
    }

    /// Dropping the sender ends the answering task once its queue is empty.
    async fn closing(&self, ctx: &AgentCtx) {
        self.conns.remove(&ctx.conn_id);
    }

    /// P3-3c — this pod stops looking after the device, unless a newer
    /// connection of it already took over.
    async fn closed(&self, ctx: &AgentCtx, _removal_was_ours: bool) {
        self.state.revoker.unlink(ctx.agent_id, &ctx.conn_id);
    }
}

/// Answer one connection's requests, in the order they came, until it goes.
async fn answer_in_order(
    state: VaultState,
    conn: Conn,
    mut rx: mpsc::Receiver<Request>,
    tx: mpsc::WeakSender<ServerMsg>,
) {
    while let Some(req) = rx.recv().await {
        let answer = match &req {
            Request::Lease(r) => match lease(&state, conn, r).await {
                Ok(l) => {
                    // P3-3c — swept from now on, while the lease is live.
                    state.revoker.hold(conn.device_id);
                    ServerMsg::VaultLeased {
                        req_id: r.req_id.clone(),
                        lease_id: l.lease_id.to_hex(),
                        n: l.n,
                        sealed: base64::engine::general_purpose::STANDARD.encode(&l.sealed),
                        expires_at_ms: l.expires_at.timestamp_millis(),
                        provider: l.provider.map(String::from),
                    }
                }
                Err(refused) => ServerMsg::VaultRefused {
                    req_id: clip(&r.req_id, lease_limits::MAX_REQ_ID_LEN),
                    reason: refused.why.wire().into(),
                    approval_id: refused.approval.map(|a| a.to_hex()),
                },
            },
            // P3-4b — metadata, never a value.
            Request::List(r) => match crate::meta::list(&state, conn, r).await {
                Ok((secrets, more)) => ServerMsg::VaultListed {
                    req_id: r.req_id.clone(),
                    secrets,
                    more,
                },
                Err(why) => refusal(&r.req_id, why),
            },
            Request::Describe(r) => match crate::meta::describe(&state, conn, r).await {
                Ok(secret) => ServerMsg::VaultDescribed {
                    req_id: r.req_id.clone(),
                    secret,
                },
                Err(why) => refusal(&r.req_id, why),
            },
            // P3-4d — kept or dropped, and answered with nothing.
            Request::Activity(r) => {
                activity(&state, conn, r).await;
                continue;
            }
            // P3-7-1b — a grant, never a value.
            Request::Net(r) => match crate::net::grant(&state, conn, r).await {
                Ok(g) => {
                    let (host, port) = g.dst.unwrap_or_default();
                    ServerMsg::VaultNetGranted {
                        req_id: r.req_id.clone(),
                        grant_id: g.grant_id.to_hex(),
                        grant: g.grant,
                        expires_at_ms: g.expires_at.timestamp_millis(),
                        host,
                        port,
                    }
                }
                Err(why) => refusal(&r.req_id, why),
            },
            // P3-8-1a — a ticket, never a key.
            Request::Ssh(r) => match crate::ssh::ticket(&state, conn, r).await {
                Ok(t) => ServerMsg::VaultSshGranted {
                    req_id: r.req_id.clone(),
                    ticket_id: t.ticket_id.to_hex(),
                    ticket: t.ticket,
                    expires_at_ms: t.expires_at.timestamp_millis(),
                    os: t.os,
                    account: t.account.wire().to_string(),
                },
                Err(why) => refusal(&r.req_id, why),
            },
            // P3-9-1 — a person's lease, answered as a session's is: the
            // device opens it with the same key, and its revocation reaches
            // it the same way.
            Request::Connect(r) => match crate::connect::connect(&state, conn, r).await {
                Ok(l) => {
                    state.revoker.hold(conn.device_id);
                    ServerMsg::VaultLeased {
                        req_id: r.req_id.clone(),
                        lease_id: l.lease_id.to_hex(),
                        n: l.n,
                        sealed: base64::engine::general_purpose::STANDARD.encode(&l.sealed),
                        expires_at_ms: l.expires_at.timestamp_millis(),
                        provider: None,
                    }
                }
                Err(why) => refusal(&r.req_id, why),
            },
        };
        let Some(tx) = tx.upgrade() else { break };
        if tx.send(answer).await.is_err() {
            break;
        }
    }
}

fn refusal(req_id: &str, why: LeaseRefusal) -> ServerMsg {
    ServerMsg::VaultRefused {
        req_id: clip(req_id, lease_limits::MAX_REQ_ID_LEN),
        reason: why.wire().into(),
        approval_id: None,
    }
}

/// P3-4d — keep a device's report of a use when every lease it names was
/// released to this device, for this session, in the use's mode and toward
/// its target (P3-6b-2b: or in `short-lived`, which serves any use); drop it
/// otherwise, at debug. A report is a claim, and a claim about a lease this
/// device was never released is no claim at all.
async fn activity(state: &VaultState, conn: Conn, r: &ActivityReport) {
    let dropped = |why: &str| {
        debug!(device = %conn.device_id, session = %r.session_id, why, "vault: an activity report dropped");
    };
    if !state.scope.serves(conn.tenant_id) {
        return dropped("the organization is not served");
    }
    let Some(kind) = VaultActivityKind::from_wire(&r.kind) else {
        return dropped("a kind this server cannot name");
    };
    if r.lease_ids.is_empty()
        || r.lease_ids.len() > lease_limits::MAX_ACTIVITY_LEASES
        || !program_name_ok(&r.target)
    {
        return dropped("out of bounds");
    }
    let Some(mut ids) = r
        .lease_ids
        .iter()
        .map(|id| ObjectId::parse_str(id).ok())
        .collect::<Option<Vec<ObjectId>>>()
    else {
        return dropped("a lease id that is not one");
    };
    ids.sort();
    ids.dedup();
    if !state.activity_limiter.check(
        r.session_id,
        conn.device_id,
        lease_limits::ACTIVITY_PER_MINUTE,
    ) {
        return dropped("past the rate");
    }
    match state
        .leases
        .all_released_for(
            &ids,
            conn.tenant_id,
            conn.device_id,
            r.session_id,
            kind.mode(),
            &r.target,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return dropped("a lease not released to this device for this use"),
        Err(e) => {
            warn!(device = %conn.device_id, %e, "vault: an activity report could not be checked");
            return;
        }
    }
    let exec = kind == VaultActivityKind::Exec;
    let row = VaultActivity {
        id: None,
        tenant_id: conn.tenant_id,
        device_id: conn.device_id,
        session_id: r.session_id,
        fence: i64::try_from(r.fence).unwrap_or(i64::MAX),
        kind: kind.wire().into(),
        lease_ids: ids,
        target: r.target.clone(),
        // What only a command has: never kept for a file.
        exit_code: r.exit_code.filter(|_| exec),
        timed_out: exec && r.timed_out,
        at: DateTime::now(),
    };
    if let Err(e) = state.activity.insert(&row).await {
        warn!(device = %conn.device_id, %e, "vault: an activity report was not kept");
    }
}

/// At most `max` bytes of `s`, cut on a character boundary.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Whether a request is within its bounds, in a mode that leases.
fn within_bounds(req: &LeaseRequest) -> bool {
    let printable = |s: &str| !s.chars().any(char::is_control);
    !req.req_id.is_empty()
        && req.req_id.len() <= lease_limits::MAX_REQ_ID_LEN
        && printable(&req.req_id)
        && !req.secret.is_empty()
        && req.secret.len() <= lease_limits::MAX_SECRET_LEN
        && req.field.len() <= lease_limits::MAX_FIELD_LEN
        && req.audience.len() <= lease_limits::MAX_AUDIENCE_LEN
        && printable(&req.audience)
        && LEASE_MODES.contains(&req.mode.as_str())
}

/// The statuses a session is leased in: from its start until a stop is
/// ordered. P3-3c revokes a lease once its session is past them.
pub(crate) fn leasable(status: SessionStatus) -> bool {
    matches!(
        status,
        SessionStatus::Starting
            | SessionStatus::Idle
            | SessionStatus::Running
            | SessionStatus::AwaitingApproval
    )
}

/// The path a request names: a path as is, or an RRN of THIS organization.
/// `None` for anything else, another organization's RRN included — which a
/// device is told is no secret, never that it is someone else's.
pub(crate) fn path_of(asked: &str, slug: &str) -> Option<String> {
    let path = match asked.strip_prefix("rrn:") {
        Some(_) => asked.strip_prefix(&format!("rrn:{slug}:secret:"))?,
        None => asked,
    };
    rrn::check_path(path).ok().map(str::to_string)
}

/// The spelling the device's row stores, which policies compare.
pub(crate) fn os_name(os: OsKind) -> &'static str {
    match os {
        OsKind::Linux => "linux",
        OsKind::Macos => "macos",
        OsKind::Windows => "windows",
    }
}

/// The `secret:use` request a lease is decided as — and P3-4e's answer to
/// an approval, decided again with the person as the approver: the session
/// in the role it assumed, the secret as its row holds it, and the device's
/// facts from ITS row.
pub(crate) fn use_ask(
    slug: &str,
    session: &AgentSession,
    secret: &VaultSecret,
    device: DeviceFacts,
    mode: &str,
    audience: &str,
    ttl_s: i64,
) -> Ask {
    Ask::UseSecret {
        session: SessionFacts {
            id: session.id.map(|i| i.to_hex()).unwrap_or_default(),
            owner: session.owner_id,
            role: session.vault_role.clone(),
            playbook: None,
        },
        secret: SecretFacts {
            prefix: format!("rrn:{slug}:secret:"),
            path: secret.path.clone(),
            kind: secret.kind.clone(),
            tags: secret.tags.clone(),
            exec_allow: secret.exec_allow.clone(),
            audiences: secret.audiences.clone(),
        },
        mode: mode.to_string(),
        audience: audience.to_string(),
        ttl_s,
        device,
        approver: None,
    }
}

/// The reason a Cedar decision is recorded with.
pub(crate) fn reason_of(verdict: &Verdict) -> String {
    if !verdict.determining.is_empty() {
        verdict.determining.join(",")
    } else if !verdict.errors.is_empty() {
        format!("undecided: {}", verdict.errors.join("; "))
    } else {
        "default_deny".to_string()
    }
}

/// What every row about one request names.
pub(crate) struct Record<'a> {
    pub(crate) state: &'a VaultState,
    pub(crate) conn: Conn,
    /// The session asking; P3-9-1 — none for a person's request
    /// ([`crate::connect`]), whose rows name the device's owner as a `user`.
    pub(crate) session_id: Option<ObjectId>,
    pub(crate) owner: ObjectId,
    pub(crate) asked: &'a str,
    /// Once resolved: the secret, its RRN, the field, and the version.
    pub(crate) secret: Option<(ObjectId, String, String, Option<i64>)>,
    /// The action as a policy names it (`secret:use`, P3-4b's
    /// `secret:list`, P3-9-1's `secret:connect`), and what exactly: `lease`
    /// · `list` · `describe` · `connect`.
    pub(crate) action: &'static str,
    pub(crate) op: &'static str,
    /// P3-4e — the approval a deny waits on or stands on, which its row
    /// names as the target.
    pub(crate) approval: Option<ObjectId>,
    /// P3-7-1b — the grant an allow gave, which its row names as the target.
    pub(crate) grant: Option<ObjectId>,
    /// P3-8-1a — the ticket an allow gave, which its row names as the target.
    pub(crate) ticket: Option<ObjectId>,
}

impl Record<'_> {
    /// Who asked, as the audit names a principal: a session, or (P3-9-1) a
    /// person, the device's owner.
    fn principal(&self) -> &'static str {
        match self.session_id {
            Some(_) => "session",
            None => "user",
        }
    }

    pub(crate) fn event(
        &self,
        allow: bool,
        reason: &str,
        request: Option<&Ask>,
        lease: Option<ObjectId>,
    ) -> VaultAuditEvent {
        let (secret_id, rrn, field, n) = match &self.secret {
            Some((id, rrn, field, n)) => (
                Some(*id),
                Some(rrn.clone()),
                Some(field.clone()).filter(|f| !f.is_empty()),
                *n,
            ),
            None => (None, None, None, None),
        };
        let target = match (lease, self.grant, self.ticket, &self.secret) {
            (Some(id), _, _, _) => Some(format!("lease:{}", id.to_hex())),
            (None, Some(id), _, _) => Some(format!("grant:{}", id.to_hex())),
            (None, None, Some(id), _) => Some(format!("ticket:{}", id.to_hex())),
            (None, None, None, None) => Some(format!("asked:{}", self.asked)),
            (None, None, None, Some(_)) => {
                self.approval.map(|id| format!("approval:{}", id.to_hex()))
            }
        };
        VaultAuditEvent {
            id: None,
            tenant_id: self.conn.tenant_id,
            principal: self.principal().into(),
            user_id: self.owner,
            action: self.action.into(),
            op: self.op.into(),
            decision: if allow { "allow" } else { "deny" }.into(),
            reason: reason.into(),
            secret_id,
            rrn,
            field,
            n,
            target,
            session_id: self.session_id,
            device_id: Some(self.conn.device_id),
            request: request.map(Ask::to_doc),
            at: DateTime::now(),
        }
    }

    /// Refuse, recording why on a best-effort basis: the device is refused
    /// whatever the database says.
    pub(crate) async fn refuse(&self, why: LeaseRefusal, reason: &str) -> LeaseRefusal {
        if let Err(e) = self
            .state
            .audit
            .record(&self.event(false, reason, None, None))
            .await
        {
            warn!(session = ?self.session_id, device = %self.conn.device_id, %e, "vault: a lease refusal was not recorded");
        }
        why
    }

    /// Record a Cedar decision. An allow that is not recorded is not acted
    /// on, so the error is the caller's to answer.
    pub(crate) async fn decided(
        &self,
        allow: bool,
        reason: &str,
        ask: &Ask,
        lease: Option<ObjectId>,
    ) -> Result<(), DaoError> {
        self.state
            .audit
            .record(&self.event(allow, reason, Some(ask), lease))
            .await
            .map(|_| ())
    }
}

/// Decide one request, and release the value when it is allowed.
pub async fn lease(state: &VaultState, conn: Conn, req: &LeaseRequest) -> Result<Leased, Refused> {
    if !within_bounds(req) {
        return Err(LeaseRefusal::BadRequest.into());
    }
    let (agent, session, mut rec) = identify(
        state,
        conn,
        req.session_id,
        req.fence,
        &req.secret,
        policy::ACTION_USE,
        "lease",
    )
    .await?;
    decide_and_release(state, &mut rec, &agent, &session, req)
        .await
        .map_err(|why| Refused {
            why,
            // P3-4e — only `awaiting_approval` names the approval.
            approval: rec
                .approval
                .filter(|_| why == LeaseRefusal::AwaitingApproval),
        })
}

/// What every request is believed on, whatever it asks: the vault serves the
/// organization, the device takes leases (its hello advertised `vault` and
/// carried a key), and the session's record places it on THIS device, at
/// this fence, live, within its per-minute ceiling. Answers the device's row,
/// the session's record, and the record later refusals are kept in. P3-4b's
/// listing and describing are believed exactly as a lease is.
pub(crate) async fn identify<'a>(
    state: &'a VaultState,
    conn: Conn,
    session_id: ObjectId,
    fence: u64,
    asked: &'a str,
    action: &'static str,
    op: &'static str,
) -> Result<(Agent, AgentSession, Record<'a>), LeaseRefusal> {
    if !state.scope.serves(conn.tenant_id) {
        return Err(LeaseRefusal::NotServed);
    }
    let agent = match state
        .agents
        .find_live_in_tenant(conn.tenant_id, conn.device_id)
        .await
    {
        Ok(a) => a,
        Err(DaoError::NotFound) => return Err(LeaseRefusal::Unsupported),
        Err(e) => {
            warn!(device = %conn.device_id, %e, "vault: a request's device was not read");
            return Err(LeaseRefusal::Unavailable);
        }
    };
    if !agent.capabilities.has_rpc(RpcCap::Vault) || agent.vault_key.is_empty() {
        return Err(LeaseRefusal::Unsupported);
    }
    let session = match state
        .sessions
        .find_in_tenant(conn.tenant_id, session_id)
        .await
    {
        Ok(s) if s.location.device_id == conn.device_id => s,
        Ok(_) | Err(DaoError::NotFound) => {
            warn!(
                device = %conn.device_id, session = %session_id, op,
                "vault: a request for a session this device does not run"
            );
            return Err(LeaseRefusal::NotLocated);
        }
        Err(e) => {
            warn!(session = %session_id, %e, "vault: a request's session was not read");
            return Err(LeaseRefusal::Unavailable);
        }
    };
    let rec = Record {
        state,
        conn,
        session_id: Some(session_id),
        owner: session.owner_id,
        asked,
        secret: None,
        action,
        op,
        approval: None,
        grant: None,
        ticket: None,
    };
    if u64::try_from(session.fence).ok() != Some(fence) {
        let why = LeaseRefusal::StaleFence;
        return Err(rec.refuse(why, why.wire()).await);
    }
    if !leasable(session.status) {
        let why = LeaseRefusal::Ended;
        return Err(rec.refuse(why, why.wire()).await);
    }
    if !state
        .lease_limiter
        .check(session_id, conn.device_id, lease_limits::RATE_PER_MINUTE)
    {
        return Err(LeaseRefusal::Busy);
    }
    Ok((agent, session, rec))
}

/// From the role on: the secret, the decision, the value.
async fn decide_and_release(
    state: &VaultState,
    rec: &mut Record<'_>,
    agent: &meshharbor_remote_control::models::Agent,
    session: &AgentSession,
    req: &LeaseRequest,
) -> Result<Leased, LeaseRefusal> {
    let tid = rec.conn.tenant_id;
    if session.vault_role.is_none() {
        let why = LeaseRefusal::NoRole;
        return Err(rec.refuse(why, why.wire()).await);
    }
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
    // P3-6b — a dynamic secret is leased as a whole: its issuer's fields in
    // one bundle. Every other secret, one field at a time.
    let dynamic = secret.kind == KIND_DYNAMIC;
    let field = if dynamic || !req.field.is_empty() {
        req.field.as_str()
    } else {
        rrn::STATIC_FIELD
    };
    let n = if dynamic {
        None
    } else {
        secret
            .fields
            .get(field)
            .map(|f| f.current)
            .filter(|n| *n > 0)
    };
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
    let leasing = if dynamic {
        bundle_for(state, rec, &secret, &req.field).await?
    } else {
        let Some(n) = n else {
            let why = LeaseRefusal::NoValue;
            return Err(rec.refuse(why, why.wire()).await);
        };
        Leasing::Field { field, n }
    };
    // What the lease is recorded as: a bundle names no field, and no version.
    let (field, n, audience) = match &leasing {
        Leasing::Field { field, n } => (*field, *n, req.audience.as_str()),
        Leasing::Bundle { audience, .. } => ("", 0, *audience),
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
    let ttl = req
        .ttl_secs
        .clamp(lease_limits::MIN_TTL_SECS, lease_limits::MAX_TTL_SECS);
    let mut ask = use_ask(
        &slug,
        session,
        &secret,
        device,
        &req.mode,
        audience,
        i64::from(ttl),
    );
    let mut verdict = decide_for_org(state, tid, &ask).await;
    // P3-4e — a deny a person's yes may lift.
    let mut approved = None;
    if !verdict.allow {
        let key = ApprovalKey {
            tenant_id: tid,
            session_id: req.session_id,
            fence: session.fence,
            device_id: rec.conn.device_id,
            secret_id,
            field,
            mode: &req.mode,
            audience,
        };
        let rrn = rrn::secret_rrn(&slug, &secret.path);
        match approval::after_deny(state, session, &key, &rrn, i64::from(ttl), &ask).await {
            Ok(Next::Deny) => {}
            Ok(Next::Use {
                approval_id,
                approver,
            }) => {
                if let Ask::UseSecret { approver: a, .. } = &mut ask {
                    *a = Some(approver);
                }
                verdict = decide_for_org(state, tid, &ask).await;
                if verdict.allow {
                    approved = Some(approval_id);
                }
            }
            Ok(Next::Awaiting(id)) => {
                rec.approval = Some(id);
                let why = LeaseRefusal::AwaitingApproval;
                if let Err(e) = rec.decided(false, why.wire(), &ask, None).await {
                    warn!(session = %req.session_id, %e, "vault: a lease awaiting approval was not recorded");
                }
                return Err(why);
            }
            Ok(Next::Refused(id)) => {
                rec.approval = Some(id);
                if let Err(e) = rec.decided(false, "approval_denied", &ask, None).await {
                    warn!(session = %req.session_id, %e, "vault: a lease's deny was not recorded");
                }
                return Err(LeaseRefusal::Denied);
            }
            Err(why) => return Err(rec.refuse(LeaseRefusal::Unavailable, why).await),
        }
    }
    let reason = reason_of(&verdict);
    if !verdict.allow {
        if let Err(e) = rec.decided(false, &reason, &ask, None).await {
            warn!(session = %req.session_id, %e, "vault: a lease's deny was not recorded");
        }
        return Err(LeaseRefusal::Denied);
    }

    // Allowed: open the value and seal it for the device, BEFORE the allow is
    // recorded, so a recorded allow is one that was ready to release.
    let (sealed, until) = match &leasing {
        Leasing::Field { field, n } => {
            let (value, until) = open_one(state, rec, kek, secret_id, field, *n).await?;
            match crypto::seal_for_device(&agent.vault_key, &value) {
                Ok(s) => (s, until),
                Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "seal").await),
            }
            // `value` is zeroed here, when it drops.
        }
        // P3-6b — every issuer field the bundle carries, each at its version,
        // sealed together: the lease ends no later than the first of them.
        Leasing::Bundle {
            versions, audience, ..
        } => {
            let mut opened = Vec::with_capacity(versions.len());
            let mut until: Option<DateTime> = None;
            for (f, n) in versions {
                let (value, ends) = open_one(state, rec, kek, secret_id, f, *n).await?;
                until = match (until, ends) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                opened.push((f.as_str(), value));
            }
            let pairs: Vec<(&str, &[u8])> =
                opened.iter().map(|(f, v)| (*f, v.as_slice())).collect();
            let bundle = match dynamic::bundle_json(audience, &pairs) {
                Ok(b) => b,
                Err(why) => return Err(rec.refuse(LeaseRefusal::Unavailable, why).await),
            };
            match crypto::seal_for_device(&agent.vault_key, &bundle) {
                Ok(s) => (s, until),
                Err(_) => return Err(rec.refuse(LeaseRefusal::Unavailable, "seal").await),
            }
            // The values and the bundle are zeroed here, when they drop.
        }
    };

    let lease_id = ObjectId::new();
    // P3-4e — the yes is spent BEFORE the allow is recorded: winning the
    // compare-and-set is its one use, so a lost race releases nothing, and a
    // failure after it only wastes a yes.
    if let Some(approval_id) = approved {
        rec.approval = Some(approval_id);
        match state
            .approvals
            .spend(approval_id, lease_id, DateTime::now())
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(rec.refuse(LeaseRefusal::Denied, "approval_spent").await),
            Err(_) => {
                return Err(rec
                    .refuse(LeaseRefusal::Unavailable, "approval_unread")
                    .await);
            }
        }
    }
    if let Err(e) = rec.decided(true, &reason, &ask, Some(lease_id)).await {
        warn!(session = %req.session_id, %e, "vault: a lease's allow was not recorded — not released");
        return Err(LeaseRefusal::Undecided);
    }
    let issued_at = DateTime::now();
    let mut expires_at =
        DateTime::from_millis(issued_at.timestamp_millis() + i64::from(ttl) * 1000);
    // P3-3c — and no lease outlives its version: a policy that read the
    // asked TTL allowed at least this much.
    if let Some(until) = until
        && until < expires_at
    {
        expires_at = until;
    }
    let (bundle, provider) = match leasing {
        Leasing::Field { .. } => (None, None),
        Leasing::Bundle {
            provider, versions, ..
        } => (Some(versions), Some(provider.name)),
    };
    let row = VaultLease {
        id: Some(lease_id),
        tenant_id: tid,
        secret_id,
        field: field.to_string(),
        n,
        bundle,
        session_id: Some(req.session_id),
        fence: session.fence,
        device_id: rec.conn.device_id,
        owner_id: session.owner_id,
        sealed_to: agent.vault_key.clone(),
        mode: req.mode.clone(),
        audience: audience.to_string(),
        issued_at,
        expires_at,
        revoked_at: None,
        revoked_why: None,
    };
    if let Err(e) = state.leases.insert(&row).await {
        warn!(session = %req.session_id, %e, "vault: a lease was not written — not released");
        return Err(LeaseRefusal::Undecided);
    }
    if let Some(approval_id) = approved {
        approval::spent(state, session, approval_id).await;
    }
    Ok(Leased {
        lease_id,
        n,
        sealed,
        expires_at,
        provider,
    })
}

/// What a lease releases.
enum Leasing<'a> {
    /// One field of a stored secret, at its current version.
    Field { field: &'a str, n: i64 },
    /// P3-6b — a dynamic secret as a whole: its issuer's fields, each at the
    /// version leased, for the device to mint toward `audience`.
    Bundle {
        provider: &'static Provider,
        versions: BTreeMap<String, i64>,
        audience: &'a str,
    },
}

/// P3-6b — a dynamic secret's lease, before any policy reads it: the secret
/// as a whole, since a field named is no session's to have; a provider this
/// build knows and the vault serves; the one audience it mints toward; and
/// every field no mint can do without.
async fn bundle_for<'a>(
    state: &VaultState,
    rec: &Record<'_>,
    secret: &'a VaultSecret,
    asked_field: &str,
) -> Result<Leasing<'a>, LeaseRefusal> {
    if !asked_field.is_empty() {
        return Err(rec
            .refuse(LeaseRefusal::NoValue, "dynamic_names_no_field")
            .await);
    }
    let Some(provider) = dynamic::provider_of(secret) else {
        return Err(rec.refuse(LeaseRefusal::NoValue, "provider_unknown").await);
    };
    if !state.providers.serves(provider) {
        return Err(rec
            .refuse(LeaseRefusal::NotServed, "provider_not_served")
            .await);
    }
    let [audience] = secret.audiences.as_slice() else {
        return Err(rec.refuse(LeaseRefusal::NoValue, "audience_not_one").await);
    };
    let versions = dynamic::bundle_of(provider, &secret.fields);
    if let Some(missing) = dynamic::missing_required(provider, &versions) {
        let reason = format!("issuer_lacks_{missing}");
        return Err(rec.refuse(LeaseRefusal::NoValue, &reason).await);
    }
    Ok(Leasing::Bundle {
        provider,
        versions,
        audience,
    })
}

/// One stored version, opened for a lease, and the `expires_at` its writer
/// gave it. A version past that is never released (P3-3c: P3-1 promised it of
/// the first step to use a value, and P3-3b did not keep the promise).
pub(crate) async fn open_one(
    state: &VaultState,
    rec: &Record<'_>,
    kek: &crypto::Kek,
    secret_id: ObjectId,
    field: &str,
    n: i64,
) -> Result<(Zeroizing<Vec<u8>>, Option<DateTime>), LeaseRefusal> {
    let version = match state.versions.get(secret_id, field, n).await {
        Ok(Some(v)) => v,
        Ok(None) => return Err(rec.refuse(LeaseRefusal::NoValue, "version_gone").await),
        Err(_) => {
            return Err(rec
                .refuse(LeaseRefusal::Unavailable, "version_unread")
                .await);
        }
    };
    if version.expires_at.is_some_and(|t| t <= DateTime::now()) {
        return Err(rec.refuse(LeaseRefusal::NoValue, "version_expired").await);
    }
    let at = Binding {
        tenant_id: rec.conn.tenant_id,
        secret_id,
        field,
        n,
    };
    match kek.open(
        &at,
        &version.ciphertext.bytes,
        &version.nonce.bytes,
        &version.dek_wrapped.bytes,
        &version.kek,
    ) {
        Ok(value) => Ok((value, version.expires_at)),
        Err(e) => {
            let reason = format!("open: {}", e.as_str());
            Err(rec.refuse(LeaseRefusal::Unavailable, &reason).await)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> LeaseRequest {
        LeaseRequest {
            req_id: "r1".into(),
            session_id: ObjectId::new(),
            fence: 1,
            secret: "db/main".into(),
            field: String::new(),
            mode: "env".into(),
            audience: String::new(),
            ttl_secs: 300,
        }
    }

    #[test]
    fn a_request_is_held_to_its_bounds_and_to_a_mode_that_leases() {
        assert!(within_bounds(&req()));
        for mode in LEASE_MODES {
            assert!(within_bounds(&LeaseRequest {
                mode: (*mode).into(),
                ..req()
            }));
        }
        // Modes a policy may name that release no value to a daemon.
        for mode in ["identity", "placeholder", "raw", "shortlived", ""] {
            assert!(
                !within_bounds(&LeaseRequest {
                    mode: mode.into(),
                    ..req()
                }),
                "{mode:?}"
            );
        }
        for bad in [
            LeaseRequest {
                req_id: String::new(),
                ..req()
            },
            LeaseRequest {
                req_id: "x".repeat(lease_limits::MAX_REQ_ID_LEN + 1),
                ..req()
            },
            LeaseRequest {
                req_id: "a\nb".into(),
                ..req()
            },
            LeaseRequest {
                secret: String::new(),
                ..req()
            },
            LeaseRequest {
                secret: "s".repeat(lease_limits::MAX_SECRET_LEN + 1),
                ..req()
            },
            LeaseRequest {
                field: "f".repeat(lease_limits::MAX_FIELD_LEN + 1),
                ..req()
            },
            LeaseRequest {
                audience: "a\u{0}".into(),
                ..req()
            },
        ] {
            assert!(!within_bounds(&bad), "{bad:?}");
        }
    }

    #[test]
    fn a_secret_is_named_by_path_or_by_this_organizations_rrn() {
        assert_eq!(path_of("db/main", "grox").as_deref(), Some("db/main"));
        assert_eq!(
            path_of("rrn:grox:secret:db/main", "grox").as_deref(),
            Some("db/main")
        );
        // Another organization's RRN is no secret here — not "someone
        // else's".
        assert_eq!(path_of("rrn:other:secret:db/main", "grox"), None);
        assert_eq!(path_of("rrn:grox:role:db/main", "grox"), None);
        // A path the vault would never store.
        assert_eq!(path_of("DB/Main", "grox"), None);
        assert_eq!(path_of("../db", "grox"), None);
    }

    #[test]
    fn only_a_session_short_of_a_stop_is_leased() {
        for s in [
            SessionStatus::Starting,
            SessionStatus::Idle,
            SessionStatus::Running,
            SessionStatus::AwaitingApproval,
        ] {
            assert!(leasable(s), "{s:?}");
        }
        for s in [
            SessionStatus::Stopping,
            SessionStatus::Ended,
            SessionStatus::Refused,
            SessionStatus::Lost,
        ] {
            assert!(!leasable(s), "{s:?}");
        }
    }

    #[test]
    fn a_long_request_id_is_echoed_clipped_on_a_character_boundary() {
        let long = "é".repeat(lease_limits::MAX_REQ_ID_LEN);
        let clipped = clip(&long, lease_limits::MAX_REQ_ID_LEN);
        assert!(clipped.len() <= lease_limits::MAX_REQ_ID_LEN);
        assert!(long.starts_with(&clipped));
        assert_eq!(clip("short", 64), "short");
    }
}
