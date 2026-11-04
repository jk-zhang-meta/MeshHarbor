// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-58 — the newsletter sending program's admin surface (issues CRUD,
//! preview, test-send; the fan-out itself is P3).
//!
//! Every handler's first line is `require_platform_admin` — the existing
//! ObjectId allowlist, answering **404** on missing authority (never 403: the
//! allowlist is itself the thing being hidden, and a hidden surface beats an
//! acknowledged one — the client's old "any 403 ⇒ log out" rule was a second
//! reason and is gone, FR-82). `platform_admins` unset ⇒ this entire surface 404s;
//! that inherent gate is the kill switch, and a second config flag guarding
//! the same door would just be a second switch to forget.
//!
//! The preview IS the sent artifact: it serves the exact bytes
//! `render_issue_html` produces (with a sample unsubscribe URL substituted),
//! because the fan-out pre-renders once and substitutes per recipient.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use bson::DateTime;
use serde::{Deserialize, Serialize};

use meshharbor_db::models::{IssueCounts, IssueStatus, NewsletterIssue};
use meshharbor_services::email::SendOptions;
use meshharbor_services::newsletter::{
    LinkTags, clean_header_text, render_issue_html, site_hosts, substitute_recipient,
};

use meshharbor_core::guards::require_platform_admin;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::SaasState;

/// Storage guard for the markdown body. An issue is an email, not a book.
const MAX_BODY_MD_BYTES: usize = 256 * 1024;
/// FR-102 P5 — the most addresses a test issue's audience may name.
pub const MAX_TEST_AUDIENCE: usize = 20;

// ── Wire shapes ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IssueBody {
    pub subject: String,
    pub preheader: String,
    pub body_md: String,
    #[serde(default)]
    pub hero_url: Option<String>,
    #[serde(default)]
    pub hero_alt: Option<String>,
    #[serde(default)]
    pub cta_text: Option<String>,
    #[serde(default)]
    pub cta_url: Option<String>,
    /// FR-102 P5 — a TEST issue's audience (at most [`MAX_TEST_AUDIENCE`]
    /// addresses): the send then goes only to the confirmed subscribers
    /// among them. Fixed with the draft, so no resume can widen it.
    #[serde(default)]
    pub audience: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateIssue {
    pub slug: String,
    #[serde(flatten)]
    pub body: IssueBody,
}

/// Read model. Plain strings and numbers only — a raw `bson::DateTime`
/// serialises as `{"$date":…}`, a truthy object that renders as
/// `[object Object]` (the FR-12 wire-leak lesson).
#[derive(Debug, Serialize)]
pub struct IssueView {
    pub slug: String,
    pub subject: String,
    pub preheader: String,
    pub body_md: String,
    pub hero_url: Option<String>,
    pub hero_alt: Option<String>,
    pub cta_text: Option<String>,
    pub cta_url: Option<String>,
    /// FR-102 P5 — a test issue's audience; absent for a list issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    pub status: IssueStatus,
    pub created_at: String,
    pub updated_at: String,
    pub sent_at: Option<String>,
    pub counts: Option<IssueCounts>,
}

#[derive(Debug, Serialize)]
pub struct IssueListItem {
    pub slug: String,
    pub subject: String,
    pub status: IssueStatus,
    pub created_at: String,
    pub sent_at: Option<String>,
    pub counts: Option<IssueCounts>,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

fn view(i: NewsletterIssue) -> IssueView {
    IssueView {
        slug: i.slug,
        subject: i.subject,
        preheader: i.preheader,
        body_md: i.body_md,
        hero_url: i.hero_url,
        hero_alt: i.hero_alt,
        cta_text: i.cta_text,
        cta_url: i.cta_url,
        audience: i.audience,
        status: i.status,
        created_at: rfc3339(i.created_at),
        updated_at: rfc3339(i.updated_at),
        sent_at: i.sent_at.map(rfc3339),
        counts: i.counts,
    }
}

// ── Validation ──────────────────────────────────────────────────────────

pub(crate) fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Absolute http(s), no quote/angle/space/control — these land in `src`/`href`
/// attributes, and the escaping downstream is belt, not license.
fn valid_http_url(s: &str) -> bool {
    (s.starts_with("https://") || s.starts_with("http://"))
        && s.len() <= 512
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>')
}

struct CleanIssueBody {
    subject: String,
    preheader: String,
    body_md: String,
    hero_url: Option<String>,
    hero_alt: Option<String>,
    cta_text: Option<String>,
    cta_url: Option<String>,
    audience: Option<Vec<String>>,
}

/// FR-102 P5 — a test audience, normalised (the subscriber store's own
/// spelling), de-duplicated and bounded: 1 to [`MAX_TEST_AUDIENCE`]
/// plausible addresses, or a refusal — never a silently empty list, which
/// would read as "no restriction".
fn clean_audience(raw: Option<Vec<String>>) -> Result<Option<Vec<String>>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for a in &raw {
        let a = meshharbor_db::models::Subscriber::normalize_email(a);
        if a.is_empty() || a.len() > 254 || !a.contains('@') || a.chars().any(char::is_whitespace) {
            return Err(ApiError::Validation(
                "audience must list plausible addresses".into(),
            ));
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() || out.len() > MAX_TEST_AUDIENCE {
        return Err(ApiError::Validation(format!(
            "a test audience names 1 to {MAX_TEST_AUDIENCE} addresses"
        )));
    }
    Ok(Some(out))
}

fn clean_issue_body(b: IssueBody) -> Result<CleanIssueBody, ApiError> {
    // ⚠️ Control chars stripped here because a `\r\n` in a subject is SMTP
    // header injection on the lettre backend — this is a security bound, not
    // tidiness.
    let subject = clean_header_text(&b.subject, 200);
    let preheader = clean_header_text(&b.preheader, 300);
    if subject.is_empty() {
        return Err(ApiError::Validation("subject must not be empty".into()));
    }
    if b.body_md.len() > MAX_BODY_MD_BYTES {
        return Err(ApiError::Validation(format!(
            "body_md exceeds {MAX_BODY_MD_BYTES} bytes"
        )));
    }
    for url in [&b.hero_url, &b.cta_url].into_iter().flatten() {
        if !valid_http_url(url) {
            return Err(ApiError::Validation(format!(
                "not an absolute http(s) URL: {url:?}"
            )));
        }
    }
    if b.cta_text.is_some() != b.cta_url.is_some() {
        return Err(ApiError::Validation(
            "cta_text and cta_url come together or not at all".into(),
        ));
    }
    Ok(CleanIssueBody {
        subject,
        preheader,
        body_md: b.body_md,
        hero_url: b.hero_url,
        hero_alt: b.hero_alt.map(|s| clean_header_text(&s, 200)),
        cta_text: b.cta_text.map(|s| clean_header_text(&s, 64)),
        cta_url: b.cta_url,
        audience: clean_audience(b.audience)?,
    })
}

// ── The newsletter From + one-click headers (shared with the P3 fan-out) ──

/// The newsletter From mailbox: `newsletter.from_*` with per-field fallback to
/// the transactional `email.from_*`. `None` = no override at all (both unset).
pub(crate) fn newsletter_from(state: &SaasState) -> Option<(String, String)> {
    let nl = &state.settings.newsletter;
    let em = &state.settings.email;
    match (nl.from_email.clone(), nl.from_name.clone()) {
        (None, None) => None,
        (e, n) => Some((
            e.unwrap_or_else(|| em.from_email.clone()),
            n.unwrap_or_else(|| em.from_name.clone()),
        )),
    }
}

/// RFC 8058: both headers, or providers show no one-click button.
pub(crate) fn unsubscribe_headers(unsubscribe_url: &str) -> Vec<(String, String)> {
    vec![
        ("List-Unsubscribe".into(), format!("<{unsubscribe_url}>")),
        (
            "List-Unsubscribe-Post".into(),
            "List-Unsubscribe=One-Click".into(),
        ),
    ]
}

pub(crate) fn unsubscribe_url(state: &SaasState, token: &str, issue: Option<&str>) -> String {
    unsubscribe_link(&state.settings.app.frontend_url, token, issue)
}

/// The unsubscribe link: the recipient's own token (the one per-recipient
/// thing in the email) and, FR-102 P5, `i=<slug>` — the issue it came in,
/// the same for every recipient of that issue — so the click can be
/// counted against the issue (`subscribers.unsubscribed_via`).
pub(crate) fn unsubscribe_link(frontend_url: &str, token: &str, issue: Option<&str>) -> String {
    let base = frontend_url.trim_end_matches('/');
    match issue {
        // Slugs are `[a-z0-9-]`, so the value needs no encoding.
        Some(slug) => format!("{base}/api/subscribe/unsubscribe/{token}?i={slug}"),
        None => format!("{base}/api/subscribe/unsubscribe/{token}"),
    }
}

/// FR-102 P5 (D5) — the tags an issue's links carry, or `None` with
/// `newsletter.link_tags` off. The same for the preview, the test-send and
/// the fan-out, so the preview stays THE sent artifact.
pub(crate) fn link_tags(state: &SaasState, slug: &str) -> Option<LinkTags> {
    state
        .settings
        .newsletter
        .link_tags
        .then(|| LinkTags::for_issue(slug, site_hosts(&state.settings.app.frontend_url)))
}

/// What one recipient's message is: the issue rendered ONCE (with its
/// tags), this recipient's unsubscribe link substituted — the only
/// per-recipient part (AC15) — and the send options: the one-click
/// headers (the same link), the newsletter From, tracking switched off
/// (D6), and, for a real send, the issue as the SendGrid custom arg the
/// Event Webhook matches events by (the same for every recipient).
pub(crate) fn compose(
    rendered: &str,
    unsubscribe: &str,
    issue_arg: Option<&str>,
    from: Option<(String, String)>,
) -> (String, SendOptions) {
    let html = substitute_recipient(rendered, unsubscribe);
    let opts = SendOptions {
        headers: unsubscribe_headers(unsubscribe),
        from,
        custom_args: issue_arg
            .map(|slug| vec![(crate::sendgrid::ISSUE_ARG.to_string(), slug.to_string())])
            .unwrap_or_default(),
        no_tracking: true,
    };
    (html, opts)
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `POST /api/admin/newsletter/issues`
pub async fn create(
    State(state): State<SaasState>,
    auth: AuthUser,
    Json(body): Json<CreateIssue>,
) -> Result<impl IntoResponse, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !valid_slug(&body.slug) {
        return Err(ApiError::Validation(
            "slug must be [a-z0-9-], at most 64 chars".into(),
        ));
    }
    let clean = clean_issue_body(body.body)?;
    let issue = NewsletterIssue {
        id: None,
        slug: body.slug,
        subject: clean.subject,
        preheader: clean.preheader,
        body_md: clean.body_md,
        hero_url: clean.hero_url,
        hero_alt: clean.hero_alt,
        cta_text: clean.cta_text,
        cta_url: clean.cta_url,
        audience: clean.audience,
        status: IssueStatus::Draft,
        claimed_by: None,
        claimed_at: None,
        counts: None,
        created_at: DateTime::now(),
        updated_at: DateTime::now(),
        sent_at: None,
        // Stamped by the fan-out when it starts (FR-102 P5).
        campaign: None,
        delivery_events: false,
    };
    // Two concurrent creates on one slug: the unique index arbitrates and the
    // loser's DuplicateKey maps to 409.
    state.newsletter_issues.create(&issue).await?;
    Ok((StatusCode::CREATED, Json(view(issue))))
}

/// `PUT /api/admin/newsletter/issues/{slug}` — drafts only.
pub async fn update(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
    Json(body): Json<IssueBody>,
) -> Result<Json<IssueView>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let clean = clean_issue_body(body)?;
    let mut set = bson::doc! {
        "subject": &clean.subject,
        "preheader": &clean.preheader,
        "body_md": &clean.body_md,
    };
    // Optional fields are SET or UNSET explicitly — a hand-built doc that
    // skips the None arm would silently keep a hero the operator removed.
    let mut unset = bson::Document::new();
    for (key, value) in [
        ("hero_url", &clean.hero_url),
        ("hero_alt", &clean.hero_alt),
        ("cta_text", &clean.cta_text),
        ("cta_url", &clean.cta_url),
    ] {
        match value {
            Some(v) => {
                set.insert(key, v);
            }
            None => {
                unset.insert(key, "");
            }
        }
    }
    // FR-102 P5 — the test audience, the same explicit set-or-unset.
    match &clean.audience {
        Some(a) => {
            set.insert("audience", a.clone());
        }
        None => {
            unset.insert("audience", "");
        }
    }
    let matched = if unset.is_empty() {
        state.newsletter_issues.update_draft(&slug, set).await?
    } else {
        // update_draft only $sets; do the combined form here.
        set.insert("updated_at", DateTime::now());
        state
            .newsletter_issues
            .base
            .update_one(
                bson::doc! { "slug": &slug, "status": "draft" },
                bson::doc! { "$set": set, "$unset": unset },
            )
            .await?
    };
    if !matched {
        // Absent vs no-longer-a-draft have different fixes; say which.
        return match state.newsletter_issues.get_by_slug(&slug).await? {
            None => Err(ApiError::NotFound("no such issue".into())),
            Some(_) => Err(ApiError::Conflict(
                "issue is no longer a draft and cannot be edited".into(),
            )),
        };
    }
    let issue = state
        .newsletter_issues
        .get_by_slug(&slug)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such issue".into()))?;
    Ok(Json(view(issue)))
}

/// `GET /api/admin/newsletter/issues`
pub async fn list(
    State(state): State<SaasState>,
    auth: AuthUser,
) -> Result<Json<Vec<IssueListItem>>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let items = state
        .newsletter_issues
        .list()
        .await?
        .into_iter()
        .map(|i| IssueListItem {
            slug: i.slug,
            subject: i.subject,
            status: i.status,
            created_at: rfc3339(i.created_at),
            sent_at: i.sent_at.map(rfc3339),
            counts: i.counts,
        })
        .collect();
    Ok(Json(items))
}

/// `GET /api/admin/newsletter/issues/{slug}`
pub async fn get_one(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
) -> Result<Json<IssueView>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let issue = state
        .newsletter_issues
        .get_by_slug(&slug)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such issue".into()))?;
    Ok(Json(view(issue)))
}

/// `GET /api/admin/newsletter/issues/{slug}/preview` — the exact send-path
/// bytes, with a sample unsubscribe URL substituted.
pub async fn preview(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_platform_admin(&state, &auth)?;
    let issue = state
        .newsletter_issues
        .get_by_slug(&slug)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such issue".into()))?;
    let tags = link_tags(&state, &issue.slug);
    let html = substitute_recipient(
        &render_issue_html(&issue, tags.as_ref()),
        &unsubscribe_url(&state, "preview-sample-token", Some(&issue.slug)),
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().expect("static header"),
    );
    // Belt: the body is renderer-emitted only, but this response renders in
    // the admin's authenticated browser origin — sandbox it anyway.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "sandbox".parse().expect("static header"),
    );
    Ok((headers, html))
}

#[derive(Debug, Deserialize)]
pub struct TestSend {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct TestSendResult {
    pub sent: bool,
    pub to: String,
}

/// `POST /api/admin/newsletter/issues/{slug}/test-send` — render + send to ONE
/// address with the real headers and a sample token. No ledger, no status
/// change; failures are propagated honestly (this caller is an operator, not
/// an oracle-sensitive public form).
pub async fn test_send(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
    Json(body): Json<TestSend>,
) -> Result<Json<TestSendResult>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let issue = state
        .newsletter_issues
        .get_by_slug(&slug)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such issue".into()))?;

    let Some(mailer) = state.email.clone() else {
        return Err(ApiError::BadRequest(
            "no mailer configured — set MESHHARBOR__EMAIL__API_KEY or SMTP host/port".into(),
        ));
    };
    let to = body.email.trim().to_string();
    if !to.contains('@') || to.len() > 254 {
        return Err(ApiError::Validation("not a plausible address".into()));
    }

    // The real send's bytes and options — except the custom arg the Event
    // Webhook matches by: a test-send has no ledger row, so its events must
    // not land on a real recipient's.
    let tags = link_tags(&state, &issue.slug);
    let unsub = unsubscribe_url(&state, "test-send-sample-token", Some(&issue.slug));
    let (html, opts) = compose(
        &render_issue_html(&issue, tags.as_ref()),
        &unsub,
        None,
        newsletter_from(&state),
    );
    mailer
        .send_ext(&to, &issue.subject, &html, &opts)
        .await
        .map_err(|e| ApiError::Internal(format!("test-send failed: {e:#}")))?;
    Ok(Json(TestSendResult { sent: true, to }))
}

// ── P3: the fan-out ─────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct SendRequest {
    /// Re-attempt ledger rows stuck `claimed` past the staleness cutoff — an
    /// explicit operator decision, never automatic: a stuck row is "maybe
    /// delivered", and auto-retry converts that into "maybe delivered twice".
    #[serde(default)]
    pub retry_stale: bool,
}

#[derive(Debug, Serialize)]
pub struct SendAccepted {
    pub slug: String,
    pub status: IssueStatus,
    pub claimed_by: String,
}

/// `POST /api/admin/newsletter/issues/{slug}/send` — claim and fan out.
/// Re-POSTing is the RESUME path: the CAS re-claims a `sending` issue whose
/// claim went stale (dead pod), and the ledger makes the re-run idempotent.
pub async fn send(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
    body: Option<Json<SendRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    require_platform_admin(&state, &auth)?;
    let req = body.map(|Json(b)| b).unwrap_or_default();

    // Refuse BEFORE claiming: ledgering an entire list into `failed` on a
    // misconfigured pod would be strictly worse than refusing loudly.
    if state.email.is_none() {
        return Err(ApiError::BadRequest(
            "no mailer configured — set MESHHARBOR__EMAIL__API_KEY or SMTP host/port".into(),
        ));
    }

    let claimed = state
        .newsletter_issues
        .claim_for_send(
            &slug,
            &state.pod.pod_id,
            crate::newsletter_send::ISSUE_CLAIM_STALE_SECS,
        )
        .await?;

    match claimed {
        Some(issue) => {
            let accepted = SendAccepted {
                slug: issue.slug.clone(),
                status: issue.status,
                claimed_by: state.pod.pod_id.clone(),
            };
            tokio::spawn(crate::newsletter_send::run_send(
                state.clone(),
                issue,
                req.retry_stale,
            ));
            Ok((StatusCode::ACCEPTED, Json(accepted)))
        }
        None => match state.newsletter_issues.get_by_slug(&slug).await? {
            None => Err(ApiError::NotFound("no such issue".into())),
            Some(i) => match i.status {
                IssueStatus::Completed => Err(ApiError::Conflict(
                    "issue already completed — one issue, one send; counts carry the truth".into(),
                )),
                IssueStatus::Sending => Err(ApiError::Conflict(format!(
                    "already sending on pod {} since {} — a live claim is never usurped; \
                     re-POST after it goes stale to resume",
                    i.claimed_by.as_deref().unwrap_or("?"),
                    i.claimed_at.map(rfc3339).unwrap_or_default(),
                ))),
                IssueStatus::Draft => Err(ApiError::Conflict(
                    "claim raced another caller — try again".into(),
                )),
            },
        },
    }
}

#[derive(Debug, Serialize)]
pub struct FailedRow {
    pub email: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueStatusView {
    pub slug: String,
    pub status: IssueStatus,
    /// Live from the ledger while sending; the stored snapshot once
    /// completed. `sent` means "accepted by the mail backend", not delivered.
    pub counts: IssueCounts,
    /// Rows stuck `claimed` — these recipients MAY or MAY NOT have received
    /// the issue (crash between backend accept and our mark). Capped sample.
    pub stale_addresses: Vec<String>,
    /// Capped sample of failures with their backend errors.
    pub failed_sample: Vec<FailedRow>,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<String>,
    pub sent_at: Option<String>,
}

/// `GET /api/admin/newsletter/issues/{slug}/status`
pub async fn status(
    State(state): State<SaasState>,
    auth: AuthUser,
    Path(slug): Path<String>,
) -> Result<Json<IssueStatusView>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let issue = state
        .newsletter_issues
        .get_by_slug(&slug)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such issue".into()))?;
    let issue_id = issue.id.expect("a stored issue has an id");
    let cutoff = crate::newsletter_send::stale_cutoff();

    let counts = match (issue.status, issue.counts) {
        (IssueStatus::Completed, Some(stored)) => stored,
        _ => state.newsletter_sends.counts(issue_id, cutoff).await?,
    };
    let stale_addresses = state
        .newsletter_sends
        .stale_rows(issue_id, cutoff)
        .await?
        .into_iter()
        .take(20)
        .map(|r| r.email)
        .collect();
    let failed_sample = state
        .newsletter_sends
        .failed_sample(issue_id, 20)
        .await?
        .into_iter()
        .map(|r| FailedRow {
            email: r.email,
            error: r.error,
        })
        .collect();

    Ok(Json(IssueStatusView {
        slug: issue.slug,
        status: issue.status,
        counts,
        stale_addresses,
        failed_sample,
        claimed_by: issue.claimed_by,
        claimed_at: issue.claimed_at.map(rfc3339),
        sent_at: issue.sent_at.map(rfc3339),
    }))
}

// ── P4: the signed-in surface (user-scoped, NOT admin) ──────────────────
//
// `subscribers` stays the ONLY membership store — this is a different DOOR
// into it, not a second list. Ownership of the address is the account's
// email verification, so subscribing here is pre-confirmed: no confirmation
// mail, and no oracle concern (the caller asks about their own address).

#[derive(Debug, Serialize)]
pub struct NewsletterPref {
    pub subscribed: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetNewsletterPref {
    pub subscribed: bool,
}

/// `GET /api/user/newsletter`
pub async fn user_get(
    State(state): State<SaasState>,
    auth: AuthUser,
) -> Result<Json<NewsletterPref>, ApiError> {
    // The user row, not the JWT claim — the row is what activation verified.
    let user = state.users.base.find_by_id(auth.user_id).await?;
    let subscribed = state.subscribers.is_subscribed(&user.email).await?;
    Ok(Json(NewsletterPref { subscribed }))
}

/// `PUT /api/user/newsletter` `{subscribed}`
pub async fn user_set(
    State(state): State<SaasState>,
    auth: AuthUser,
    Json(body): Json<SetNewsletterPref>,
) -> Result<Json<NewsletterPref>, ApiError> {
    let user = state.users.base.find_by_id(auth.user_id).await?;
    if body.subscribed && !user.is_verified {
        // Pre-confirmed subscription rides on PROVEN ownership; an unverified
        // account hasn't proven it, and the public double-opt-in form is the
        // right door for them.
        return Err(ApiError::Validation(
            "verify your account email first — or use the subscribe form, which sends a confirmation link".into(),
        ));
    }
    let subscribed = state
        .subscribers
        .set_account_subscription(&user.email, body.subscribed)
        .await?;
    Ok(Json(NewsletterPref { subscribed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-102 P5 — a test audience is normalised to the store's spelling,
    /// de-duplicated, and bounded; an empty or oversized list is refused
    /// rather than read as "no restriction".
    #[test]
    fn a_test_audience_is_normalised_and_bounded() {
        assert_eq!(clean_audience(None).unwrap(), None);
        assert_eq!(
            clean_audience(Some(vec![
                " Me@Example.COM ".into(),
                "me@example.com".into(),
                "bounce@example.net".into(),
            ]))
            .unwrap(),
            Some(vec![
                "me@example.com".to_string(),
                "bounce@example.net".to_string()
            ])
        );
        assert!(clean_audience(Some(vec![])).is_err());
        assert!(clean_audience(Some(vec!["not an address".into()])).is_err());
        assert!(clean_audience(Some(vec!["".into()])).is_err());
        let many: Vec<String> = (0..=MAX_TEST_AUDIENCE)
            .map(|i| format!("a{i}@example.com"))
            .collect();
        assert!(clean_audience(Some(many)).is_err());
    }

    /// The unsubscribe link names the issue only when there is one.
    #[test]
    fn the_unsubscribe_link_names_the_issue() {
        assert_eq!(
            unsubscribe_link("https://meshharbor.itachi.fans/", "tok", Some("oct")),
            "https://meshharbor.itachi.fans/api/subscribe/unsubscribe/tok?i=oct"
        );
        assert_eq!(
            unsubscribe_link("https://meshharbor.itachi.fans", "tok", None),
            "https://meshharbor.itachi.fans/api/subscribe/unsubscribe/tok"
        );
    }
}
