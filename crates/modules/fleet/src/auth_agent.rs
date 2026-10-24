// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The one place an agent JWT turns into an authorization decision.
//!
//! ## Why this exists
//!
//! An agent token lives for a **year**. Verifying its signature proves only
//! that we minted it — not that the device it names is still one we accept.
//!
//! The `/ws?role=agent` upgrade has always loaded the row and refused a deleted
//! or quarantined agent. The HTTP ingest routes did not: `agent_log::ingest_agent`
//! and `agent_crash::ingest` verified the token, parsed the ids straight out of
//! the claims, and wrote. So **deleting or quarantining a device did not stop it
//! writing** — for up to a year, with no revocation short of rotating the JWT
//! secret for the entire fleet. Sessions here are stateless, so the row IS the
//! revocation list; a path that never reads it has no revocation at all.
//!
//! ## Why an extractor rather than a helper call
//!
//! A helper is a step a handler can forget, and the two that forgot it are the
//! evidence. As an extractor the check is not a step at all: the only way to
//! obtain an authenticated `agent_id`/`tenant_id` is to have passed it. A new
//! agent-authed route gets the check by writing its signature.
//!
//! The WS paths (`ws::handler`, `ws::derp`) cannot use an extractor — their
//! token arrives in a query parameter on an upgrade — so they share the
//! *decision* instead, via [`refusal_reason`]. That function is the single
//! definition of "this agent may still act"; nothing should re-spell it.

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{Agent, AgentStatus};

use axum::extract::FromRef;

use roomler_core::ApiError;

use crate::FleetState;

/// An agent that authenticated with its own JWT **and** still has a row we
/// accept. Carries the row so a handler that needs it does not re-read.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthAgent {
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub agent: Agent,
}

/// The single definition of "this agent may still act". `Some(reason)` refuses.
///
/// Shared with the WS paths so there is exactly one answer to the question.
/// Deliberately matches what `/ws?role=agent` has always enforced — deleted or
/// quarantined — rather than quietly widening the policy. (`AgentStatus::Unenrolled`
/// is not included: it is only ever written to `overlay_nodes`, never to an
/// agent row. Widening this is a policy change and should be argued on its own.)
pub fn refusal_reason(agent: &Agent) -> Option<&'static str> {
    refusal_reason_parts(agent.deleted_at.is_some(), agent.status)
}

/// The rule itself, over just the two fields it reads.
///
/// Split out ONLY so the tests can drive it: `Agent` has no constructor, and a
/// struct literal in a test breaks every time the model gains a field — the
/// failure mode this repo has already been bitten by. Do not "simplify" this
/// back into one function; the seam is what keeps the rule tested.
fn refusal_reason_parts(deleted: bool, status: AgentStatus) -> Option<&'static str> {
    if deleted {
        // Deletion wins over status: the cascade tombstones the row without
        // necessarily rewriting `status`, so an Online-looking tombstone must
        // still refuse.
        Some("agent has been deleted")
    } else if matches!(status, AgentStatus::Quarantined) {
        Some("agent is quarantined")
    } else {
        None
    }
}

/// FR-103: the single definition of "this token predates the device's
/// removal". `Some(reason)` refuses. A removal bumps the row's `token_gen`
/// (`AgentDao::soft_delete`, `TunnelClientDao::soft_delete`), and enrollment
/// and renewal mint at the current value, so a token whose `gen` is not the
/// row's was minted before a removal. Shared with the socket, DERP and the
/// tunnel-client paths, as [`refusal_reason`] is.
///
/// Every row that was never removed is at 0, and so is every pre-FR-103 token
/// (no `gen` claim), so before any removal this refuses nothing. `enforced`
/// is `rc.token_generation_check`, the kill switch.
///
/// Callers check [`refusal_reason`] FIRST, so a removed device still hears
/// that it was deleted (its typed goodbye) rather than this.
pub fn generation_refusal(claims_gen: u32, row_gen: u32, enforced: bool) -> Option<&'static str> {
    (enforced && claims_gen != row_gen)
        .then_some("this credential was issued before the device was removed; re-enroll it")
}

/// The bearer token from an `Authorization` header, or `None` if it is
/// missing, empty or a different scheme.
///
/// Agent tokens travel in this header only — never a cookie. An agent is not a
/// browser, and accepting a cookie here would widen the surface for no caller.
///
/// Moved here (with its tests) from the duplicate `extract_bearer` that both
/// `agent_log` and `agent_crash` carried. The scheme match is case-insensitive
/// per RFC 7235 §2.1, which is slightly wider than the `Bearer `/`bearer `
/// pair the originals accepted and strictly more correct.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = raw.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// The decision itself, over the request headers — what the extractor below
/// runs, callable by a router whose state cannot `FromRef` a `FleetState`.
///
/// FR-84 D5a split this out of the extractor for the HOST's `/api/agent/self/*`
/// routes: their state is `AppState`, on which the fleet module is an
/// `Option` (a switched-off module is unmounted, never a boot refusal), so
/// the `FleetState: FromRef<S>` bound above can't be met there. The host
/// wraps this in its own extractor and answers 503 for the `None`; the rules
/// are these, once: bearer only, audience-checked, status-checked on every
/// use, deletion wins over status, a lookup FAILURE is 500 not 401.
pub async fn authenticate(
    fleet: &FleetState,
    headers: &axum::http::HeaderMap,
) -> Result<AuthAgent, ApiError> {
    let token = bearer_token(headers)
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    // Audience-checked: `verify_agent_token` rejects a user JWT, and FR-94's
    // service credential.
    let claims = fleet
        .auth
        .verify_agent_token(token)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;

    let (agent_id, tenant_id, agent) = accepted_agent(
        fleet,
        &claims.sub,
        &claims.tenant_id,
        Some(claims.generation),
    )
    .await?;
    Ok(AuthAgent {
        agent_id,
        tenant_id,
        agent,
    })
}

/// FR-103: [`authenticate`] for `POST /api/agent/self/renew` ONLY. The token
/// may be up to `RENEWAL_GRACE_SECS` past its `exp`
/// (`AuthService::verify_agent_token_for_renewal`), so a device that slept
/// through its anniversary can buy a fresh one. Everything else is the same
/// decision: audience, the row (deleted or quarantined refuses), and the
/// generation. An expired token therefore renews only for a device that is
/// still one we accept.
pub async fn authenticate_for_renewal(
    fleet: &FleetState,
    headers: &axum::http::HeaderMap,
) -> Result<AuthAgent, ApiError> {
    let token = bearer_token(headers)
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;
    let claims = fleet
        .auth
        .verify_agent_token_for_renewal(token)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;
    let (agent_id, tenant_id, agent) = accepted_agent(
        fleet,
        &claims.sub,
        &claims.tenant_id,
        Some(claims.generation),
    )
    .await?;
    Ok(AuthAgent {
        agent_id,
        tenant_id,
        agent,
    })
}

/// FR-94 — a Windows device's SYSTEM service, authenticated with its OWN
/// credential (`TokenType::AgentService`, minted by `POST /api/agent/anchor`)
/// and still a device we accept. The agent token never passes here, and this
/// credential never passes [`AuthAgent`]. On an attended install the agent
/// token sits in the signed-in user's writable config, and nothing that user
/// can write may decide what SYSTEM runs (FR-94 §4).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthAgentService {
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub agent: Agent,
}

/// [`authenticate`]'s twin for the service credential: the same bearer rule,
/// the same row check, a different audience, and one more rule: the
/// credential must name the device's CURRENT anchor.
pub async fn authenticate_service(
    fleet: &FleetState,
    headers: &axum::http::HeaderMap,
) -> Result<AuthAgentService, ApiError> {
    let token = bearer_token(headers)
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;
    let claims = fleet
        .auth
        .verify_agent_service_token(token)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;
    // No generation: a removal ends this credential through its anchor
    // (#2133, `soft_delete` clears `exec_anchor`), checked just below.
    let (agent_id, tenant_id, agent) =
        accepted_agent(fleet, &claims.sub, &claims.tenant_id, None).await?;
    if !anchor_is_current(&agent, &claims.anchor_id) {
        tracing::info!(%agent_id, %tenant_id, "refusing service-authed request: anchor superseded");
        // 401: this credential is dead for good, and the service must hear
        // "re-anchor", not "try again".
        return Err(ApiError::Unauthorized(
            "this device's SYSTEM service was re-anchored or un-anchored; anchor it again".into(),
        ));
    }
    Ok(AuthAgentService {
        agent_id,
        tenant_id,
        agent,
    })
}

/// A service credential is live only while it names the device's current
/// anchor. Re-anchoring writes a new id, so every credential an earlier
/// anchor minted dies with it: one live SYSTEM service per device, and an
/// administrator can revoke one without removing the device. An empty id
/// (a row from before the field) matches nothing.
fn anchor_is_current(agent: &Agent, anchor_id: &str) -> bool {
    anchor_matches(
        agent.exec_anchor.as_ref().map(|a| a.anchor_id.as_str()),
        anchor_id,
    )
}

/// The rule over just the two ids, split out for the tests the same way
/// [`refusal_reason_parts`] is.
fn anchor_matches(current: Option<&str>, presented: &str) -> bool {
    current.is_some_and(|c| !c.is_empty() && c == presented)
}

/// The row check both credentials share: the ids in the claims, the row
/// they name, [`refusal_reason`], and for an agent token (`gen` is `Some`)
/// [`generation_refusal`]. One definition of "this device may still act",
/// whichever credential is asking.
pub async fn accepted_agent(
    fleet: &FleetState,
    sub: &str,
    tenant: &str,
    generation: Option<u32>,
) -> Result<(ObjectId, ObjectId, Agent), ApiError> {
    let agent_id = ObjectId::parse_str(sub)
        .map_err(|_| ApiError::Unauthorized("invalid agent_id in claims".to_string()))?;
    let tenant_id = ObjectId::parse_str(tenant)
        .map_err(|_| ApiError::Unauthorized("invalid tenant_id in claims".to_string()))?;

    // The row is the revocation list. A lookup FAILURE is a 500, not a
    // 401: a Mongo blip must not tell a healthy fleet its credentials were
    // revoked, which would turn a database wobble into an enrollment storm.
    //
    // `NotFound` is the one exception, and FR-51 is what made it real: a
    // REAPED ephemeral row is hard-deleted, so "no row" is Mongo's
    // AUTHORITATIVE answer, not a wobble — pre-FR-51 a gone device always
    // still had a tombstone and took the 401 below. Mapping NotFound to
    // 500 would have a reaped-but-still-running device retrying forever
    // against what reads as server trouble, instead of hearing that its
    // credential is dead (and the agent's self-unenroll deliberately
    // treats 401 as "already gone").
    //
    // ANY, not live (#1821): this reader's job IS the tombstone. A removed
    // device must take the `refusal_reason` branch below and hear "deleted",
    // and the `NotFound` arm must keep meaning what the paragraph above says
    // — a REAPED row — so the log can tell the two apart.
    let agent = fleet
        .agents
        .find_any_in_tenant(tenant_id, agent_id)
        .await
        .map_err(|e| match e {
            roomler_ai_services::dao::base::DaoError::NotFound => {
                tracing::info!(%agent_id, %tenant_id, "refusing agent-authed request: row gone");
                ApiError::Unauthorized("no such device".to_string())
            }
            other => ApiError::Internal(format!("agent lookup: {other}")),
        })?;

    if let Some(reason) = refusal_reason(&agent) {
        tracing::info!(%agent_id, %tenant_id, reason, "refusing agent-authed request");
        // 401, not 403: the credential itself is no longer accepted, and
        // that is what the device needs to hear.
        return Err(ApiError::Unauthorized(reason.to_string()));
    }

    // FR-103 — after the row check, so a removed device hears "deleted".
    if let Some(reason) = generation.and_then(|g| {
        generation_refusal(g, agent.token_gen, fleet.settings.rc.token_generation_check)
    }) {
        tracing::info!(
            %agent_id, %tenant_id, reason, row_gen = agent.token_gen,
            "refusing agent-authed request: token predates the device's removal"
        );
        return Err(ApiError::Unauthorized(reason.to_string()));
    }

    roomler_core::admission::authorize_user_id(&fleet.core, agent.owner_user_id, None).await?;

    Ok((agent_id, tenant_id, agent))
}

impl<S> FromRequestParts<S> for AuthAgentService
where
    FleetState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let fleet = FleetState::from_ref(state);
        authenticate_service(&fleet, &parts.headers).await
    }
}

impl<S> FromRequestParts<S> for AuthAgent
where
    FleetState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = FleetState::from_ref(state);
        authenticate(&app_state, &parts.headers).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    // ── bearer parsing (ported from the duplicate `extract_bearer` that
    //    `agent_log` and `agent_crash` each carried before this extractor) ──

    #[test]
    fn bearer_returns_the_token_after_the_scheme() {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer abc.def.ghi"),
        );
        assert_eq!(bearer_token(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for raw in ["bearer xyz", "BEARER xyz", "BeArEr xyz"] {
            let mut h = HeaderMap::new();
            h.insert(AUTHORIZATION, HeaderValue::from_str(raw).unwrap());
            assert_eq!(bearer_token(&h), Some("xyz"), "{raw}");
        }
    }

    #[test]
    fn bearer_returns_none_on_missing_header() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    /// FR-94 — a service credential is live only for the device's current
    /// anchor. No anchor, another anchor, and an empty id on both sides
    /// (a row from before the field) all refuse.
    #[test]
    fn only_the_current_anchor_is_accepted() {
        assert!(anchor_matches(Some("a1"), "a1"));
        assert!(!anchor_matches(Some("a2"), "a1"), "re-anchored");
        assert!(!anchor_matches(None, "a1"), "un-anchored");
        assert!(!anchor_matches(Some(""), ""), "an empty id matches nothing");
    }

    /// FR-103: a token from before the device's removal is refused. Before
    /// any removal everything is at 0 and passes, a pre-FR-103 token
    /// included. The kill switch passes everything.
    #[test]
    fn only_a_token_of_the_rows_generation_is_accepted() {
        assert_eq!(generation_refusal(0, 0, true), None, "never removed");
        assert_eq!(generation_refusal(1, 1, true), None, "minted after it");
        assert!(
            generation_refusal(0, 1, true).is_some(),
            "minted before the removal"
        );
        assert!(
            generation_refusal(2, 1, true).is_some(),
            "a generation the row never had"
        );
        assert_eq!(generation_refusal(0, 1, false), None, "the kill switch");
    }

    #[test]
    fn bearer_returns_none_on_empty_token() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer    "));
        assert_eq!(bearer_token(&h), None);
    }

    #[test]
    fn bearer_returns_none_on_a_different_scheme() {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        assert_eq!(bearer_token(&h), None);
    }

    // ── the revocation rule ──

    #[test]
    fn a_live_agent_is_allowed() {
        assert!(refusal_reason_parts(false, AgentStatus::Online).is_none());
        assert!(refusal_reason_parts(false, AgentStatus::Offline).is_none());
        // Never written to an agent row today, but it is not a refusal reason
        // and must not silently become one.
        assert!(refusal_reason_parts(false, AgentStatus::Unenrolled).is_none());
    }

    #[test]
    fn a_quarantined_agent_is_refused() {
        assert_eq!(
            refusal_reason_parts(false, AgentStatus::Quarantined),
            Some("agent is quarantined")
        );
    }

    #[test]
    fn a_deleted_agent_is_refused_whatever_its_status_says() {
        for status in [
            AgentStatus::Online,
            AgentStatus::Offline,
            AgentStatus::Quarantined,
            AgentStatus::Unenrolled,
        ] {
            assert_eq!(
                refusal_reason_parts(true, status),
                Some("agent has been deleted"),
                "a tombstoned row must refuse regardless of {status:?}"
            );
        }
    }
}
