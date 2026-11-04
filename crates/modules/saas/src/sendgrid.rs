// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P5 (D6) — SendGrid's signed Event Webhook, and the startup check
//! of SendGrid's own open/click tracking.
//!
//! `POST /api/sendgrid/webhook` records what happened to a newsletter
//! message AFTER SendGrid accepted it — `delivered`, `bounce`, `dropped`,
//! `spamreport` — on that message's ledger row (`newsletter_sends.delivery`),
//! and suppresses the address on a hard bounce or a spam report, so the next
//! issue's fan-out never mails it.
//!
//! # Verified before it is parsed
//!
//! SendGrid signs `timestamp || body` with ECDSA over P-256 and SHA-256, and
//! sends the base64 DER signature and the timestamp in two headers. The key
//! is `newsletter.event_webhook_public_key` (the key SendGrid shows). The
//! order is the control: no key configured → the empty 404 of an absent
//! path, for everything; a missing header, a stale timestamp or a signature
//! that does not verify → 401, **and the body has not been parsed** — a
//! forged request never reaches the JSON parser, let alone the database.
//! Only then is the body read as JSON. Recording is idempotent (every time
//! is a `$min`), so a replayed signed batch — or SendGrid's own retry —
//! writes nothing new; the timestamp window (25 h back, 5 min ahead) covers
//! SendGrid's 24 h of retries.
//!
//! # Four events, and never a reader's
//!
//! Only `delivered`, `bounce`, `dropped` and `spamreport` are recorded.
//! `open` and `click` are ignored even when SendGrid sends them (and the
//! newsletter switches both off per message anyway, `SendOptions::
//! no_tracking`): the footer promises nothing in the email is per-reader
//! except the unsubscribe link, and the server keeps nothing per reader
//! either.
//!
//! # Matched by the issue, never by a per-recipient token
//!
//! The fan-out tags each message with ONE SendGrid custom arg,
//! [`ISSUE_ARG`] = the issue's slug — the same for every recipient. An event
//! carries it back with the recipient's address, and the pair names exactly
//! one ledger row (the subscriber by its unique address, then the row by the
//! unique `(issue_id, subscriber_id)`). An event without the arg is not a
//! newsletter message (activation mail, an invite) and is ignored.
//!
//! Addresses are never logged — a batch is logged as counts.

use std::collections::HashMap;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bson::{DateTime, oid::ObjectId};
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use meshharbor_services::dao::{base::DaoError, newsletter_send::DeliveryEvent};
/// The key and the signature check live beside the Stripe one, in the
/// services crate, so the host's views agree with this route on whether a
/// configured key is usable.
pub use meshharbor_services::sendgrid::EventVerifier;
use meshharbor_core::Core;

use crate::SaasState;

/// The base64 DER ECDSA signature of `timestamp || body`.
pub const SIGNATURE_HEADER: &str = "x-twilio-email-event-webhook-signature";
/// Unix seconds, as a decimal string — signed together with the body.
pub const TIMESTAMP_HEADER: &str = "x-twilio-email-event-webhook-timestamp";
/// The SendGrid custom arg every newsletter message carries: the issue's
/// slug, the same for every recipient.
pub const ISSUE_ARG: &str = "nl_issue";
/// SendGrid posts a batch every 30 s or at 768 KB, whichever comes first.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// A ceiling on the events one batch may carry — far above what 768 KB
/// holds; a bound, not a page.
pub const MAX_EVENTS: usize = 10_000;
/// How old a signed timestamp may be: SendGrid retries for 24 hours.
pub const MAX_SIGNATURE_AGE_SECS: i64 = 25 * 60 * 60;
/// How far ahead of our clock a signed timestamp may be.
pub const MAX_SIGNATURE_SKEW_SECS: i64 = 5 * 60;

/// The configured verifier, or `None` (webhook off). A key that does not
/// parse is logged and treated as absent — the route then refuses
/// everything, which is the safe reading of a broken key.
pub fn verifier_from_settings(raw: &str) -> Option<EventVerifier> {
    if raw.trim().is_empty() {
        info!(
            "SendGrid Event Webhook off: no MESHHARBOR__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY — \
             newsletter delivery reads \"not measured\""
        );
        return None;
    }
    match EventVerifier::from_config(raw) {
        Ok(v) => {
            info!("SendGrid Event Webhook on: signed events are verified and recorded");
            Some(v)
        }
        Err(e) => {
            warn!(
                error = %e,
                "MESHHARBOR__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY is not usable — the SendGrid \
                 webhook refuses every request until it is fixed"
            );
            None
        }
    }
}

/// Whether a signed timestamp is inside the window.
pub fn timestamp_fresh(raw: &str, now_secs: i64) -> bool {
    let Ok(t) = raw.trim().parse::<i64>() else {
        return false;
    };
    let age = now_secs - t;
    (-MAX_SIGNATURE_SKEW_SECS..=MAX_SIGNATURE_AGE_SECS).contains(&age)
}

/// One event the webhook records: the issue, the address and what happened.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEvent {
    pub issue: String,
    pub email: String,
    pub event: DeliveryEvent,
}

/// An event's own time (SendGrid's `timestamp`, Unix seconds), when it is a
/// plausible one; otherwise the time it was received.
fn event_time(v: Option<&Value>, now: DateTime) -> DateTime {
    const FLOOR_SECS: i64 = 1_577_836_800; // 2020-01-01
    let ahead = now.timestamp_millis() / 1000 + 86_400;
    match v.and_then(Value::as_i64) {
        Some(t) if (FLOOR_SECS..=ahead).contains(&t) => DateTime::from_millis(t * 1000),
        _ => now,
    }
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One raw SendGrid event → what to record, or `None`: an event kind other
/// than the four (`processed`, `deferred`, `open`, `click`, `unsubscribe`…),
/// a message that is not a newsletter's (no [`ISSUE_ARG`]), or a shape that
/// names no row.
pub fn parse_event(v: &Value, now: DateTime) -> Option<ParsedEvent> {
    let kind = v.get("event")?.as_str()?;
    let issue = v.get(ISSUE_ARG)?.as_str()?;
    if !valid_slug(issue) {
        return None;
    }
    let email = v.get("email")?.as_str()?.trim();
    if email.is_empty() || email.len() > 254 || !email.contains('@') {
        return None;
    }
    let at = event_time(v.get("timestamp"), now);
    let reason = v.get("reason").and_then(Value::as_str).map(str::to_string);
    let event = match kind {
        "delivered" => DeliveryEvent::Delivered { at },
        // SendGrid's bounce `type`: `bounce` is a hard bounce; `blocked`
        // (or anything else) is the receiving server refusing this one
        // message, which must not cost the address its subscription.
        "bounce" => DeliveryEvent::Bounced {
            at,
            hard: v.get("type").and_then(Value::as_str) == Some("bounce"),
            reason,
        },
        "dropped" => DeliveryEvent::Dropped { at, reason },
        "spamreport" => DeliveryEvent::SpamReport { at },
        _ => return None,
    };
    Some(ParsedEvent {
        issue: issue.to_string(),
        email: email.to_string(),
        event,
    })
}

/// What one batch did — counts only, never an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Recorded {
    pub events: usize,
    /// Written on a ledger row (a replay counts again; it changes nothing).
    pub recorded: usize,
    /// Not one of the four, or not a newsletter message.
    pub ignored: usize,
    /// A newsletter event naming no ledger row (an unknown issue or address).
    pub unmatched: usize,
    /// Addresses this batch suppressed (a hard bounce or a spam report).
    pub suppressed: usize,
}

/// Record a verified batch. Lookups are cached per batch (one issue, many
/// recipients is the normal shape). A database error stops the batch and is
/// returned, so the route answers 503 and SendGrid retries — safe, since
/// every write is idempotent.
pub async fn record_events(
    state: &SaasState,
    events: &[Value],
    now: DateTime,
) -> Result<Recorded, DaoError> {
    let mut out = Recorded {
        events: events.len(),
        ..Recorded::default()
    };
    let mut issues: HashMap<String, Option<ObjectId>> = HashMap::new();
    let mut subscribers: HashMap<String, Option<ObjectId>> = HashMap::new();
    for raw in events {
        let Some(p) = parse_event(raw, now) else {
            out.ignored += 1;
            continue;
        };
        let issue_id = match issues.get(&p.issue) {
            Some(id) => *id,
            None => {
                let id = state
                    .newsletter_issues
                    .get_by_slug(&p.issue)
                    .await?
                    .and_then(|i| i.id);
                issues.insert(p.issue.clone(), id);
                id
            }
        };
        let key = meshharbor_db::models::Subscriber::normalize_email(&p.email);
        let subscriber_id = match subscribers.get(&key) {
            Some(id) => *id,
            None => {
                let id = state.subscribers.id_by_email(&key).await?;
                subscribers.insert(key, id);
                id
            }
        };
        let (Some(issue_id), Some(subscriber_id)) = (issue_id, subscriber_id) else {
            out.unmatched += 1;
            continue;
        };
        if !state
            .newsletter_sends
            .record_delivery(issue_id, subscriber_id, &p.event)
            .await?
        {
            out.unmatched += 1;
            continue;
        }
        out.recorded += 1;
        if let Some(reason) = p.event.suppresses()
            && state
                .subscribers
                .suppress(subscriber_id, reason, p.event.at())
                .await?
        {
            out.suppressed += 1;
        }
    }
    Ok(out)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "invalid signature").into_response()
}

/// `POST /api/sendgrid/webhook` — see the module docs for the order of the
/// checks; the body is parsed only after its signature verified.
pub async fn webhook(State(state): State<SaasState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(verifier) = state.sendgrid_events.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (Some(signature), Some(timestamp)) = (
        header(&headers, SIGNATURE_HEADER),
        header(&headers, TIMESTAMP_HEADER),
    ) else {
        warn!("sendgrid webhook: refused, no signature headers");
        return unauthorized();
    };
    let now = DateTime::now();
    if !timestamp_fresh(timestamp, now.timestamp_millis() / 1000) {
        warn!("sendgrid webhook: refused, the signed timestamp is outside the window");
        return unauthorized();
    }
    if !verifier.verify(timestamp, &body, signature) {
        warn!(
            bytes = body.len(),
            "sendgrid webhook: refused, the signature does not verify"
        );
        return unauthorized();
    }
    // Verified — only now is the body read as JSON.
    let events = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Array(events)) => events,
        _ => {
            warn!("sendgrid webhook: a signed body that is not a JSON array");
            return (StatusCode::BAD_REQUEST, "expected a JSON array of events").into_response();
        }
    };
    if events.len() > MAX_EVENTS {
        warn!(
            events = events.len(),
            "sendgrid webhook: more events than one batch may carry"
        );
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    match record_events(&state, &events, now).await {
        Ok(r) => {
            info!(
                events = r.events,
                recorded = r.recorded,
                ignored = r.ignored,
                unmatched = r.unmatched,
                suppressed = r.suppressed,
                "sendgrid webhook: batch recorded"
            );
            (StatusCode::OK, Json(r)).into_response()
        }
        Err(e) => {
            warn!(%e, "sendgrid webhook: the batch could not be recorded — SendGrid will retry");
            (StatusCode::SERVICE_UNAVAILABLE, "try again").into_response()
        }
    }
}

/// FR-102 P5 (D6) — at startup, read SendGrid's ACCOUNT-level open and
/// click tracking and say so loudly if either is on. Best-effort: spawned,
/// bounded, never blocks the boot; nothing to check without a SendGrid key.
/// The newsletter turns tracking off per message regardless — this is the
/// check that the account itself does not track (every other mail would be,
/// and anyone reading SendGrid's numbers would be reading per-reader data).
pub fn spawn_tracking_check(core: &Core) {
    let Some(mailer) = core.email.clone() else {
        return;
    };
    if !mailer.is_sendgrid() {
        return;
    }
    tokio::spawn(async move {
        match mailer.tracking_settings().await {
            Some(Ok(r)) if r.open || r.click => warn!(
                open_tracking = r.open,
                click_tracking = r.click,
                "SendGrid account-level open/click tracking is ON (FR-102 D6: never). The \
                 newsletter switches both off per message, but every other mail is tracked — \
                 turn them off in SendGrid → Settings → Tracking"
            ),
            Some(Ok(_)) => info!("SendGrid open and click tracking are off (FR-102 D6)"),
            Some(Err(e)) => warn!(
                error = %e,
                "could not read SendGrid's tracking settings — open/click tracking is NOT \
                 verified off (the API key needs the tracking_settings.read scope)"
            ),
            None => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A key that does not parse turns the webhook off rather than on.
    #[test]
    fn an_unusable_key_turns_the_webhook_off() {
        assert!(verifier_from_settings("").is_none());
        assert!(verifier_from_settings("not a key").is_none());
    }

    #[test]
    fn the_signed_timestamp_window_is_25h_back_and_5_min_ahead() {
        let now = 1_760_515_200;
        assert!(timestamp_fresh(&now.to_string(), now));
        assert!(timestamp_fresh(&(now - 24 * 3600).to_string(), now));
        assert!(!timestamp_fresh(&(now - 26 * 3600).to_string(), now));
        assert!(timestamp_fresh(&(now + 240).to_string(), now));
        assert!(!timestamp_fresh(&(now + 600).to_string(), now));
        assert!(!timestamp_fresh("soon", now));
        assert!(!timestamp_fresh("", now));
    }

    fn now() -> DateTime {
        DateTime::parse_rfc3339_str("2026-10-15T12:00:00Z").unwrap()
    }

    /// D6 — the four kinds, mapped; opens, clicks and every other kind
    /// recorded as nothing; a message without the issue arg is not ours.
    #[test]
    fn only_the_four_events_of_a_newsletter_message_are_recorded() {
        let ev = |kind: &str| {
            json!({
                "event": kind, "email": "Reader@Example.com", "nl_issue": "oct-notes",
                "timestamp": 1_760_515_200, "sg_event_id": "x", "reason": "550 no such user",
                "type": "bounce",
            })
        };
        let at = DateTime::from_millis(1_760_515_200_000);
        assert_eq!(
            parse_event(&ev("delivered"), now()).unwrap().event,
            DeliveryEvent::Delivered { at }
        );
        let p = parse_event(&ev("bounce"), now()).unwrap();
        assert_eq!(p.issue, "oct-notes");
        assert_eq!(p.email, "Reader@Example.com");
        assert_eq!(
            p.event,
            DeliveryEvent::Bounced {
                at,
                hard: true,
                reason: Some("550 no such user".into())
            }
        );
        assert!(matches!(
            parse_event(&ev("dropped"), now()).unwrap().event,
            DeliveryEvent::Dropped { .. }
        ));
        assert_eq!(
            parse_event(&ev("spamreport"), now()).unwrap().event,
            DeliveryEvent::SpamReport { at }
        );
        for never in [
            "open",
            "click",
            "processed",
            "deferred",
            "unsubscribe",
            "group_unsubscribe",
            "group_resubscribe",
            "",
        ] {
            assert_eq!(parse_event(&ev(never), now()), None, "{never}");
        }
        // Not a newsletter message: no issue arg, or one that is no slug.
        let mut transactional = ev("bounce");
        transactional.as_object_mut().unwrap().remove("nl_issue");
        assert_eq!(parse_event(&transactional, now()), None);
        let mut forged = ev("delivered");
        forged["nl_issue"] = json!("../../etc");
        assert_eq!(parse_event(&forged, now()), None);
        let mut no_address = ev("delivered");
        no_address["email"] = json!("");
        assert_eq!(parse_event(&no_address, now()), None);
    }

    /// A bounce is hard only when SendGrid says `type: bounce`; a block (or
    /// a bounce of no stated type) never costs an address its subscription.
    #[test]
    fn only_a_bounce_of_type_bounce_is_hard() {
        let bounce = |ty: Option<&str>| {
            let mut v = json!({ "event": "bounce", "email": "a@x.io", "nl_issue": "oct" });
            if let Some(t) = ty {
                v["type"] = json!(t);
            }
            match parse_event(&v, now()).unwrap().event {
                DeliveryEvent::Bounced { hard, .. } => hard,
                other => panic!("{other:?}"),
            }
        };
        assert!(bounce(Some("bounce")));
        assert!(!bounce(Some("blocked")));
        assert!(!bounce(Some("expired")));
        assert!(!bounce(None));
    }

    /// An implausible event time is replaced by the receipt time, never
    /// stored as 1970 or the far future.
    #[test]
    fn an_implausible_event_time_is_the_receipt_time() {
        let at = |ts: Value| {
            let v = json!({ "event": "delivered", "email": "a@x.io", "nl_issue": "oct", "timestamp": ts });
            parse_event(&v, now()).unwrap().event.at()
        };
        assert_eq!(at(json!(0)), now());
        assert_eq!(at(json!(9_999_999_999_i64)), now());
        assert_eq!(at(json!("1760515200")), now());
        assert_eq!(
            at(json!(1_760_515_200)),
            DateTime::from_millis(1_760_515_200_000)
        );
    }
}
