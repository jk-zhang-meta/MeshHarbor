// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-58 — the newsletter fan-out. One task per claimed send, spawned by the
//! send route on the pod that won the issue-level CAS.
//!
//! Deliberately NOT `TaskService` (tenant-scoped, no retry/recovery, and its
//! progress record would duplicate the ledger — which IS the progress record)
//! and NOT Redis `try_claim` (skip-a-cycle semantics; a send must not skip).
//! Coordination is Mongo CAS + the `newsletter_sends` unique index, so it
//! survives a Redis outage and a resume can land on either pod.
//!
//! ⚠️ A rolling deploy kills this task silently (bare `tokio::spawn`, no
//! drain). That is accepted and documented: status then shows `sending` with
//! a stale heartbeat, and recovery is the operator re-POSTing send (the
//! stale-claim arm of the CAS). Don't deploy mid-send.

use std::sync::Arc;
use std::time::Duration;

use bson::DateTime;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use meshharbor_db::models::{NewsletterIssue, Subscriber};
use meshharbor_services::newsletter::render_issue_html;

use crate::SaasState;
use crate::newsletter::{compose, link_tags, newsletter_from, unsubscribe_url};

/// A ledger row still `claimed` after this long is STALE — the crash-window
/// residue the status surface reports and `retry_stale` may re-attempt.
/// Defined beside the ledger DAO since FR-102 P5 (the host's newsletter view
/// reads it too); re-exported so the path stays.
pub use meshharbor_services::dao::newsletter_send::STALE_ROW_SECS;
/// An issue claim older than this may be re-claimed by a resume POST. Kept
/// well above the heartbeat interval so a live fan-out is never usurped.
pub const ISSUE_CLAIM_STALE_SECS: i64 = 10 * 60;

const SEND_CONCURRENCY: usize = 4;
/// ⚠️ Load-bearing, not polish: the SendGrid `reqwest::Client::new()` has NO
/// default timeout, so one hung connection would wedge a semaphore slot — and
/// eventually the whole fan-out — behind a live heartbeat masking it.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);

pub fn stale_cutoff() -> DateTime {
    meshharbor_services::dao::newsletter_send::stale_cutoff_at(DateTime::now())
}

/// The fan-out. Pre-renders once, then per recipient: claim (unique index
/// arbitrates) → re-check consent → substitute → send with a hard timeout →
/// mark. Finishes by stamping `completed` + the counts snapshot.
pub async fn run_send(state: SaasState, issue: NewsletterIssue, retry_stale: bool) {
    let slug = issue.slug.clone();
    let issue_id = issue.id.expect("a stored issue has an id");
    let Some(mailer) = state.email.clone() else {
        // The route refuses before claiming; this is the defensive twin.
        warn!(%slug, "run_send started with no mailer — leaving the claim to go stale");
        return;
    };

    let mut subscribers = match state.subscribers.mailable().await {
        Ok(v) => v,
        Err(e) => {
            // Leave the issue `sending`; the heartbeat stops with us and the
            // stale claim makes a re-POST the recovery path.
            warn!(%slug, error = ?e, "run_send could not load the recipient snapshot");
            return;
        }
    };
    // FR-102 P5 — a test issue goes only to its audience: the confirmed
    // subscribers among the addresses fixed with the draft (so a resume can
    // never widen it to the list). Logged as a count, never the addresses.
    if let Some(audience) = &issue.audience {
        subscribers.retain(|s| audience.contains(&s.email));
        info!(%slug, audience = audience.len(), recipients = subscribers.len(), "test issue: the send is restricted to its audience");
    }

    // FR-102 P5 — the issue's link tags (D5), rendered in ONCE so they are
    // the same bytes for every recipient, and stamped on the issue with the
    // fact that every message names it for the Event Webhook (D6).
    let tags = link_tags(&state, &slug);
    if let Err(e) = state
        .newsletter_issues
        .stamp_send_tags(
            &slug,
            tags.as_ref().map(|t| t.campaign.as_str()),
            state.sendgrid_events.is_some(),
        )
        .await
    {
        warn!(%slug, error = ?e, "could not stamp the issue's tags — its visits may read unmeasured");
    }
    let rendered = render_issue_html(&issue, tags.as_ref());
    let from = newsletter_from(&state);
    let subject = issue.subject.clone();

    // The claim stays visibly alive while we work; scoped to our pod id.
    let hb = {
        let issues = state.newsletter_issues.clone();
        let pod = state.pod.pod_id.clone();
        let slug = slug.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_EVERY);
            tick.tick().await; // the immediate first tick — the claim is fresh
            loop {
                tick.tick().await;
                if let Err(e) = issues.heartbeat(&slug, &pod).await {
                    warn!(%slug, error = ?e, "send heartbeat failed");
                }
            }
        })
    };

    // Phase A — explicitly requested retries of stale rows. Per-row CAS, so a
    // second resuming pod can't double-attempt one recipient; the re-fetch
    // honors a withdrawal that happened while the row sat stuck.
    let mut work: Vec<(bson::oid::ObjectId, Subscriber)> = Vec::new();
    if retry_stale {
        match state
            .newsletter_sends
            .stale_rows(issue_id, stale_cutoff())
            .await
        {
            Ok(rows) => {
                for row in rows {
                    let row_id = row.id.expect("a stored ledger row has an id");
                    match state.newsletter_sends.reclaim(row_id, stale_cutoff()).await {
                        Ok(true) => {
                            match state.subscribers.base.find_by_id(row.subscriber_id).await {
                                Ok(sub) => work.push((row_id, sub)),
                                Err(_) => {
                                    // The subscriber row is unreadable — treat as
                                    // withdrawn rather than guessing.
                                    let _ = state.newsletter_sends.mark_suppressed(row_id).await;
                                }
                            }
                        }
                        Ok(false) => {} // someone else owns the retry
                        Err(e) => warn!(%slug, error = ?e, "stale-row reclaim failed"),
                    }
                }
            }
            Err(e) => warn!(%slug, error = ?e, "could not list stale rows"),
        }
    }

    // Phase B — the snapshot. Claim-first; a duplicate claim means an earlier
    // pass already dispositioned the recipient (that is the resume working).
    for sub in subscribers {
        let sub_id = sub.id.expect("a stored subscriber has an id");
        match state
            .newsletter_sends
            .try_claim(issue_id, sub_id, &sub.email)
            .await
        {
            Ok(Some(row_id)) => work.push((row_id, sub)),
            Ok(None) => {}
            Err(e) => warn!(%slug, error = ?e, "ledger claim failed; recipient skipped this pass"),
        }
    }

    let sem = Arc::new(Semaphore::new(SEND_CONCURRENCY));
    let mut handles = Vec::with_capacity(work.len());
    for (row_id, sub) in work {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let state = state.clone();
        let mailer = mailer.clone();
        let rendered = rendered.clone();
        let subject = subject.clone();
        let from = from.clone();
        let slug = slug.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;

            // The consent re-check: honored between snapshot and send. FR-102
            // P5 — an address SendGrid reported as a hard bounce or a spam
            // report is suppressed: its row reads `suppressed`, nothing is
            // sent, until the address consents afresh.
            let fresh = state.subscribers.base.find_by_id(sub.id.unwrap()).await;
            let withdrawn = match &fresh {
                Ok(f) => f.unsubscribed_at.is_some() || !f.confirmed || f.suppressed_at.is_some(),
                Err(_) => true, // unreadable ⇒ do not mail
            };
            if withdrawn {
                let _ = state.newsletter_sends.mark_suppressed(row_id).await;
                return;
            }

            let unsub = unsubscribe_url(&state, &sub.unsubscribe_token, Some(&slug));
            let (html, opts) = compose(&rendered, &unsub, Some(&slug), from);
            let outcome = tokio::time::timeout(
                SEND_TIMEOUT,
                mailer.send_ext(&sub.email, &subject, &html, &opts),
            )
            .await;
            let mark = match outcome {
                Ok(Ok(())) => state.newsletter_sends.mark_sent(row_id).await,
                Ok(Err(e)) => {
                    state
                        .newsletter_sends
                        .mark_failed(row_id, &format!("{e:#}"))
                        .await
                }
                Err(_) => {
                    state
                        .newsletter_sends
                        .mark_failed(row_id, "send timed out after 30s")
                        .await
                }
            };
            if let Err(e) = mark {
                warn!(error = ?e, "ledger mark failed — the row will read as stale");
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    hb.abort();

    match state
        .newsletter_sends
        .counts(issue_id, stale_cutoff())
        .await
    {
        Ok(counts) => {
            if let Err(e) = state.newsletter_issues.complete(&slug, counts).await {
                warn!(%slug, error = ?e, "could not stamp completion");
            } else {
                info!(
                    %slug,
                    total = counts.total,
                    sent = counts.sent,
                    failed = counts.failed,
                    suppressed = counts.suppressed,
                    stale = counts.stale,
                    "newsletter fan-out completed"
                );
            }
        }
        Err(e) => warn!(%slug, error = ?e, "could not compute completion counts"),
    }
}

#[cfg(test)]
mod tests {
    use bson::DateTime;
    use meshharbor_db::models::{IssueStatus, NewsletterIssue};
    use meshharbor_services::newsletter::{LinkTags, render_issue_html, site_hosts};

    use crate::newsletter::{compose, unsubscribe_link};

    const FRONTEND: &str = "https://meshharbor.itachi.fans";

    fn issue() -> NewsletterIssue {
        NewsletterIssue {
            id: None,
            slug: "october-notes".into(),
            subject: "Three products, one daemon".into(),
            preheader: "Why one agent per machine is the whole point.".into(),
            body_md: "## The story\n\nRead [the docs](https://meshharbor.itachi.fans/docs/install), \
                      [the post](https://meshharbor.itachi.fans/blog/one-daemon#why), the \
                      [source](https://github.com/jk-zhang-meta/MeshHarbor) and \
                      <https://www.meshharbor.itachi.fans/pricing>.\n\n![a diagram](https://meshharbor.itachi.fans/newsletter-img/d.png)\n"
                .into(),
            hero_url: Some("https://meshharbor.itachi.fans/newsletter-img/october-notes-v1.png".into()),
            hero_alt: Some("One daemon".into()),
            cta_text: Some("Try MeshHarbor".into()),
            cta_url: Some("https://meshharbor.itachi.fans/register".into()),
            audience: None,
            status: IssueStatus::Sending,
            claimed_by: None,
            claimed_at: None,
            counts: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            sent_at: None,
            campaign: None,
            delivery_events: false,
        }
    }

    /// Every `href="…"` and `src="…"` value, in document order.
    fn links(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        for attr in ["href=\"", "src=\""] {
            let mut rest = html;
            while let Some(i) = rest.find(attr) {
                rest = &rest[i + attr.len()..];
                let end = rest.find('"').expect("an attribute closes");
                out.push(format!("{attr}{}", &rest[..end]));
                rest = &rest[end..];
            }
        }
        out
    }

    /// AC15 (the footer's promise, as a test) — two recipients of one issue
    /// get byte-identical messages except for the unsubscribe link: every
    /// other link (the body's, the call to action, the footer's, the
    /// images) is the same bytes, the per-issue tags included; the headers
    /// differ only in the List-Unsubscribe link; the custom arg the Event
    /// Webhook matches by is the issue, the same for both.
    #[test]
    fn every_link_but_the_unsubscribe_link_is_byte_identical_for_two_recipients() {
        let issue = issue();
        let tags = LinkTags::for_issue(&issue.slug, site_hosts(FRONTEND));
        // Rendered ONCE, exactly as `run_send` does.
        let rendered = render_issue_html(&issue, Some(&tags));
        let unsub_a = unsubscribe_link(FRONTEND, &"a".repeat(48), Some(&issue.slug));
        let unsub_b = unsubscribe_link(FRONTEND, &"b".repeat(48), Some(&issue.slug));
        let (html_a, opts_a) = compose(&rendered, &unsub_a, Some(&issue.slug), None);
        let (html_b, opts_b) = compose(&rendered, &unsub_b, Some(&issue.slug), None);

        let (la, lb) = (links(&html_a), links(&html_b));
        assert_eq!(la.len(), lb.len());
        assert!(la.len() >= 8, "the fixture has links to compare: {la:?}");
        let differing: Vec<(&String, &String)> =
            la.iter().zip(&lb).filter(|(a, b)| a != b).collect();
        assert_eq!(
            differing.len(),
            1,
            "exactly one link differs between two recipients: {differing:?}"
        );
        assert_eq!(differing[0].0, &format!("href=\"{unsub_a}"));
        assert_eq!(differing[0].1, &format!("href=\"{unsub_b}"));
        // The unsubscribe link names the issue, the same for both.
        assert!(unsub_a.ends_with("?i=october-notes") && unsub_b.ends_with("?i=october-notes"));

        // The links to this site carry the issue's tags; the rest do not.
        let tagged = "utm_source=newsletter&amp;utm_medium=email&amp;utm_campaign=nl-october-notes";
        for l in &la {
            let ours = l.contains("://meshharbor.itachi.fans/")
                || l.contains("://www.meshharbor.itachi.fans/");
            let is_link = l.starts_with("href=");
            let is_unsub = l.contains("/api/subscribe/unsubscribe/");
            if is_link && ours && !is_unsub {
                assert!(l.contains(tagged), "untagged: {l}");
            } else {
                assert!(!l.contains("utm_"), "tagged where it must not be: {l}");
            }
        }

        // The whole body: with each recipient's unsubscribe link taken out,
        // the two messages are the same bytes.
        assert_eq!(
            html_a.replace(&unsub_a, "UNSUBSCRIBE"),
            html_b.replace(&unsub_b, "UNSUBSCRIBE")
        );
        // No per-recipient thing hides in the options either.
        assert_eq!(opts_a.custom_args, opts_b.custom_args);
        assert_eq!(
            opts_a.custom_args,
            vec![("nl_issue".to_string(), "october-notes".to_string())]
        );
        assert!(opts_a.no_tracking && opts_b.no_tracking);
        let other = |o: &meshharbor_services::email::SendOptions, unsub: &str| {
            o.headers
                .iter()
                .map(|(k, v)| (k.clone(), v.replace(unsub, "UNSUBSCRIBE")))
                .collect::<Vec<_>>()
        };
        assert_eq!(other(&opts_a, &unsub_a), other(&opts_b, &unsub_b));
    }

    /// With the tags switched off (`newsletter.link_tags = false`), links
    /// are exactly as written — and still identical for every recipient.
    #[test]
    fn untagged_links_are_as_written() {
        let issue = issue();
        let rendered = render_issue_html(&issue, None);
        let (html, _) = compose(
            &rendered,
            &unsubscribe_link(FRONTEND, "tok", Some(&issue.slug)),
            Some(&issue.slug),
            None,
        );
        assert!(!html.contains("utm_"));
        assert!(html.contains("href=\"https://meshharbor.itachi.fans/register\""));
    }

    /// A test-send carries no custom arg: it has no ledger row, so an event
    /// about it must never land on a real recipient's.
    #[test]
    fn a_test_send_names_no_issue_for_the_webhook() {
        let (_, opts) = compose("x %%UNSUBSCRIBE_URL%%", "https://u", None, None);
        assert!(opts.custom_args.is_empty());
        assert!(opts.no_tracking, "tracking is off for a test-send too");
    }
}
