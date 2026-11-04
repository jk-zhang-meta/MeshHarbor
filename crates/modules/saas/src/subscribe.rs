// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-39 — PUBLIC subscribe / confirm / unsubscribe.
//!
//! No auth extractor anywhere in this module. For `confirm` and `unsubscribe`
//! the unguessable token IS the capability, the same shape as
//! `routes::consent`. For `subscribe` there is no capability at all — it is an
//! open form — which is why two properties below are load-bearing rather than
//! polish:
//!
//! 1. **Every outcome answers 202.** New address, address already on the list,
//!    address that unsubscribed last year: indistinguishable. A response that
//!    told them apart would be a membership oracle, and the addresses on this
//!    list are overwhelmingly also `users.email` values — a field that is a
//!    unique index *and* the key OAuth account-linking resolves against.
//! 2. **Resends are on a cooldown** (`SubscriberDao`). An open form that mails
//!    whoever is named in the body is a mail bomb pointed at that person,
//!    posted from our own domain.
//!
//! A third follows from the first and is easy to undo by accident: the
//! confirmation mail is **sent from a detached task**, so the response time does
//! not depend on whether one was sent. Awaiting it inline would leak the same
//! membership fact through latency that the status code refuses to leak
//! directly.

use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use meshharbor_db::models::IssueStatus;
use meshharbor_services::dao::subscriber::SubscribeOutcome;
use serde::Deserialize;
use tracing::{info, warn};

use meshharbor_core::ApiError;

use crate::SaasState;

/// Upper bound on a stored address. RFC 5321 caps a path at 256 octets; this is
/// a storage guard, not a validator — the confirmation mail is the validator.
const MAX_EMAIL_LEN: usize = 254;
/// `source` is caller-supplied and ends up in operator-facing exports, so it is
/// clamped and character-restricted rather than trusted.
const MAX_SOURCE_LEN: usize = 32;

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub email: String,
    /// Where the form was — `landing`, `docs`, a campaign tag. Optional.
    #[serde(default)]
    pub source: Option<String>,
}

/// Cheap sanity, deliberately not a full RFC 5322 grammar.
///
/// The purpose is to keep obvious junk out of the collection, not to decide
/// deliverability — only delivery decides deliverability, and every regex that
/// tries ends up rejecting somebody's legitimate address. Anything that passes
/// here still has to survive a confirmation click before it is mailable.
fn looks_like_an_address(email: &str) -> bool {
    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return false;
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    // A dot may not lead or trail EITHER side. Checking only the domain looks
    // right and is not: `.leading@example.com` has a clean domain and an
    // invalid local part, so it would sail through.
    let edges_are_clean = |s: &str| !s.starts_with('.') && !s.ends_with('.') && !s.is_empty();

    edges_are_clean(local)
        && edges_are_clean(domain)
        && domain.contains('.')
        && !email.contains("..")
}

fn clean_source(raw: Option<String>) -> String {
    raw.map(|s| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(MAX_SOURCE_LEN)
            .collect::<String>()
    })
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "unknown".to_string())
}

/// `POST /api/subscribe`
///
/// Always 202. See the module note — the uniform response is the control, not
/// an accident of error handling.
pub async fn subscribe(
    State(state): State<SaasState>,
    Json(body): Json<SubscribeRequest>,
) -> impl IntoResponse {
    let email = meshharbor_db::models::Subscriber::normalize_email(&body.email);
    let source = clean_source(body.source);

    if !looks_like_an_address(&email) {
        // Still 202. A 400 here would separate "malformed" from "accepted",
        // which is a weaker oracle than membership but is still one, and the
        // client has no use for the distinction.
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "ok": true })),
        );
    }

    match state.subscribers.subscribe(&email, &source).await {
        Ok((outcome, token)) => {
            if let Some(token) = token {
                // Detached on purpose, and this is part of the same control as
                // the uniform 202 rather than a throughput optimisation.
                // Awaiting the send here would make the response time depend on
                // the outcome — a fresh address pays for an SMTP round trip, an
                // address already on the list returns immediately — which is a
                // timing oracle for exactly the membership the status code is
                // careful not to reveal. Detaching makes both paths do the same
                // work before answering.
                let state = state.clone();
                let email = email.clone();
                tokio::spawn(async move {
                    send_confirmation(&state, &email, &token).await;
                });
            }
            info!(source = %source, outcome = ?outcome, "subscribe request handled");
            if outcome == SubscribeOutcome::AlreadyConfirmed {
                // Logged, never returned — the caller must not learn this.
                info!("subscribe: address already confirmed; no mail sent");
            }
        }
        Err(e) => {
            // Swallowed on purpose. A storage failure must not turn into a
            // different status code than success, or the shape of the failure
            // becomes the oracle the uniform 202 exists to remove.
            warn!("subscribe failed for a request: {e:?}");
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "ok": true })),
    )
}

async fn send_confirmation(state: &SaasState, email: &str, token: &str) {
    let Some(mailer) = state.email.as_ref() else {
        // Not an error. A self-hosted instance with no SMTP configured still
        // collects addresses; the row simply stays unconfirmed until a mailer
        // exists. Losing the address instead would be the worse failure.
        warn!("subscribe: no mailer configured — stored unconfirmed, no mail sent");
        return;
    };
    let base = state.settings.app.frontend_url.trim_end_matches('/');
    // The link goes to a PAGE whose button POSTs the token — never to a
    // confirming GET. Field-proven necessity (FR-58 P6): Gmail's link scanner
    // followed the old GET and confirmed the very first real subscriber
    // before any human clicked. Same shape as the consent mail, which linked
    // to a page "so an email prefetcher can't auto-approve via a GET".
    let link = format!("{base}/newsletter/confirm/{token}");
    let html = format!(
        "<p>Please confirm you want product updates about MeshHarbor.</p>\
         <p><a href=\"{link}\">Confirm my address</a></p>\
         <p style=\"color:#666;font-size:13px\">If you did not ask for this, ignore this \
         message — nothing is sent to an address that never confirms, and the link \
         stops working once the confirmation is used.</p>"
    );
    if let Err(e) = mailer
        .send(email, "Confirm your MeshHarbor updates", &html)
        .await
    {
        warn!("subscribe: confirmation mail failed to send: {e:?}");
    }
}

/// `GET /api/subscribe/confirm/{token}` — a pure redirect to the confirm
/// PAGE. ⚠️ It must never confirm: mailbox link scanners follow GETs, and on
/// FR-58's very first field subscriber Gmail's scanner burned the single-use
/// token before any human clicked. The GET keeps working for links already in
/// old emails (they now cost one extra, deliberate click); the DB is not even
/// read here, so a prefetcher achieves nothing.
pub async fn confirm_redirect(
    State(state): State<SaasState>,
    Path(token): Path<String>,
) -> Redirect {
    let base = state.settings.app.frontend_url.trim_end_matches('/');
    Redirect::to(&format!("{base}/newsletter/confirm/{token}"))
}

/// `POST /api/subscribe/confirm/{token}` — the deliberate click. Called by
/// the confirm page's button; answers JSON so the page can render the
/// outcome in place. Token-as-capability, single-use (the DAO clears it) —
/// `{"confirmed": false}` for an unknown or already-used token is a statement
/// to the token HOLDER, not a membership oracle.
pub async fn confirm(
    State(state): State<SaasState>,
    Path(token): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.subscribers.confirm(&token).await.unwrap_or(false);
    info!(ok, "subscribe confirm (deliberate POST) handled");
    Json(serde_json::json!({ "confirmed": ok }))
}

/// FR-102 P5 — the issue an unsubscribe link came in: its `i=<slug>`, kept
/// only when it names an issue that was sent (a draft never mailed anyone;
/// a garbage value names nothing). Parsed leniently from the raw query: a
/// malformed query must never turn an unsubscribe into a 400.
async fn via_issue(state: &SaasState, raw_query: Option<&str>) -> Option<String> {
    let slug = url::form_urlencoded::parse(raw_query?.as_bytes())
        .find(|(k, _)| k == "i")
        .map(|(_, v)| v.into_owned())?;
    if !crate::newsletter::valid_slug(&slug) {
        return None;
    }
    match state.newsletter_issues.get_by_slug(&slug).await {
        Ok(Some(issue)) if issue.status != IssueStatus::Draft => Some(issue.slug),
        _ => None,
    }
}

/// `GET /api/subscribe/unsubscribe/{token}`
///
/// No confirmation step and no session: a one-click unsubscribe that asks the
/// person to log in first is not a working unsubscribe. Idempotent, because
/// mail clients prefetch links. FR-102 P5: the link's `i=<slug>` records
/// which issue it came in (`subscribers.unsubscribed_via`).
pub async fn unsubscribe(
    State(state): State<SaasState>,
    Path(token): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Redirect, ApiError> {
    let via = via_issue(&state, query.as_deref()).await;
    let ok = state
        .subscribers
        .unsubscribe(&token, via.as_deref())
        .await
        .unwrap_or(false);
    Ok(Redirect::to(&outcome_page(
        &state,
        "unsubscribed",
        if ok { "ok" } else { "invalid" },
    )))
}

/// `POST /api/subscribe/unsubscribe/{token}` — the RFC 8058 one-click target
/// (`List-Unsubscribe-Post: List-Unsubscribe=One-Click`), so Gmail/Yahoo can
/// unsubscribe a recipient from their own UI (FR-58).
///
/// Three properties are the contract, not conveniences:
/// - **Plain 200 for every outcome.** Providers want a 2xx and follow no
///   redirects; and a distinguishable miss would be a token-space oracle the
///   GET above already refuses to be.
/// - **The form body is discarded unread.** Providers POST
///   `List-Unsubscribe=One-Click` as a urlencoded body; an extractor that
///   415s on an unexpected content-type would break exactly the callers this
///   route exists for. The token in the path is the whole input.
/// - Idempotent, same as the GET — the DAO stamp is a no-op on repeat.
pub async fn unsubscribe_oneclick(
    State(state): State<SaasState>,
    Path(token): Path<String>,
    RawQuery(query): RawQuery,
) -> StatusCode {
    // The List-Unsubscribe header carries the same link, `i=` included.
    let via = via_issue(&state, query.as_deref()).await;
    let ok = state
        .subscribers
        .unsubscribe(&token, via.as_deref())
        .await
        .unwrap_or(false);
    info!(
        ok,
        via_issue = via.is_some(),
        "one-click unsubscribe handled"
    );
    StatusCode::OK
}

/// Where a confirm/unsubscribe link lands a human: the public SPA outcome
/// pages (`/newsletter/confirmed` / `/newsletter/unsubscribed`).
///
/// ⚠️ This used to be `{base}/?subscribe=…`, and no human ever saw the
/// outcome: `/` is auth-gated in the SPA router and its guard exact-matches
/// `fullPath === '/'`, so a logged-out confirmer bounced to `/login` and a
/// signed-in one rendered the dashboard — the landing handler for the query
/// was dead code (FR-58 field evidence 2).
fn outcome_page(state: &SaasState, page: &str, status: &str) -> String {
    let base = state.settings.app.frontend_url.trim_end_matches('/');
    format!("{base}/newsletter/{page}?status={status}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_addresses_are_accepted() {
        for ok in [
            "a@b.co",
            "first.last+tag@example.co.uk",
            "x_y-z@sub.domain.example",
        ] {
            assert!(looks_like_an_address(ok), "should accept {ok}");
        }
    }

    #[test]
    fn obvious_junk_is_rejected() {
        for bad in [
            "",
            "no-at-sign",
            "@nolocal.com",
            "nodomain@",
            "no@dot",
            "spa ce@example.com",
            "dots@exa..mple.com",
            ".leading@example.com",
            "trailing@example.com.",
        ] {
            assert!(!looks_like_an_address(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn an_over_long_address_is_rejected() {
        let long = format!("{}@example.com", "a".repeat(MAX_EMAIL_LEN));
        assert!(!looks_like_an_address(&long));
    }

    /// The `source` field lands in operator-facing exports, so it must not be
    /// able to carry markup, separators or newlines out of a public form.
    #[test]
    fn source_is_clamped_and_stripped() {
        assert_eq!(clean_source(None), "unknown");
        assert_eq!(clean_source(Some(String::new())), "unknown");
        assert_eq!(clean_source(Some("landing".into())), "landing");
        assert_eq!(
            clean_source(Some("<script>alert(1)</script>".into())),
            "scriptalert1script"
        );
        assert_eq!(clean_source(Some("a,b\nc\td".into())), "abcd");
        assert_eq!(
            clean_source(Some("x".repeat(100))),
            "x".repeat(MAX_SOURCE_LEN)
        );
    }

    /// Normalisation is what makes the unique index mean anything — two casings
    /// of one address must not become two rows, because the second could never
    /// be reached by the first one's unsubscribe link.
    #[test]
    fn addresses_normalize_to_one_row() {
        use meshharbor_db::models::Subscriber;
        assert_eq!(
            Subscriber::normalize_email("  Person@Example.COM  "),
            "person@example.com"
        );
    }
}
