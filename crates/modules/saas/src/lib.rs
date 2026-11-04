// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `saas` — the hosted-product layer, as a module (FR-69 P2).
//!
//! Stripe billing (plans, checkout, the customer portal, the webhook), the
//! public updates list and the newsletter sending program (FR-39 / FR-58),
//! the platform-admin plan-compliance view (FR-32), and FR-102's purestat
//! puller (P6, [`purestat_pull`] — the web plane frozen daily into the core
//! `growth_daily` collection, through the core DAO) and the promotion
//! pipeline's ingest routes (P8, [`growth_ingest`] — posts and metric
//! snapshots into the core `growth_posts` / `growth_post_snapshots`,
//! behind a hashed ingest key), the newsletter's delivery side (P5,
//! [`sendgrid`] — SendGrid's signed Event Webhook onto the send ledger, the
//! per-issue link tags and unsubscribes), and billed revenue (P4 — the six
//! Stripe billing kinds into `billing_events`, and the operator's one-off
//! backfill of Stripe's paid invoices), and P7's GitHub puller
//! ([`github_pull`] — the repository's public counters as daily cumulative
//! snapshots, its traffic with a token). Everything here
//! exists because roomler.ai is a hosted product; a self-hosted deployment
//! runs without it, which is why it is an **add-on feature** on the host
//! rather than part of any profile.
//!
//! It is also the first module crate, chosen for that reason: it is the
//! smallest, and it exercises the whole [`Module`] contract at the lowest
//! risk — `unlimited_routes` for the Stripe webhook (signature-authenticated
//! and deliberately outside the per-IP governor), `indexes` for its
//! collections, a runtime switch (`[modules] saas = false`) that unmounts it
//! on a live pod.
//!
//! # Shape
//!
//! [`SaasState`] is the module's state: a [`Core`] plus the three DAOs it
//! owns. It derefs to `Core`, so handlers read `state.settings`,
//! `state.email`, `state.tenants` exactly as they did on the host's
//! `AppState`; `impl FromRef<SaasState> for Core` lets a handler that needs
//! only the core take `State<Core>`, and lets `meshharbor-core`'s extractors
//! (`AuthUser`, `TenantId`) serve this router unchanged.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRef},
    routing::{get, post, put},
};
use meshharbor_config::Settings;
use meshharbor_db::indexes::{
    IndexSet, index, index_unique, index_unique_partial, index_unique_sparse,
};
use meshharbor_services::dao::{
    newsletter_issue::NewsletterIssueDao, newsletter_send::NewsletterSendDao,
    subscriber::SubscriberDao,
};
use meshharbor_core::{Capabilities, Core, Module, TenantCtx};

pub mod bing_pull;
pub mod capped;
pub mod content_pull;
pub mod github_pull;
pub mod growth_ingest;
pub mod newsletter;
pub mod newsletter_send;
pub mod plan_compliance;
pub mod pull_schedule;
pub mod purestat_pull;
pub mod search_console;
pub mod search_pull;
pub mod sendgrid;
pub mod stripe;
pub mod subscribe;

/// The module's state: the core plus the DAOs of the three newsletter-side
/// collections it owns (`billing_events`, its fourth, is written through
/// the services crate's `BillingEventDao` from the Stripe webhook).
#[derive(Clone)]
pub struct SaasState {
    pub core: Core,
    /// FR-39 — the public updates list. Not a user store: no password, no
    /// tenant, no session.
    pub subscribers: Arc<SubscriberDao>,
    /// FR-58 — newsletter issues (platform-admin surface).
    pub newsletter_issues: Arc<NewsletterIssueDao>,
    /// FR-58 — the per-recipient delivery ledger; its unique index is the
    /// send program's at-most-once invariant.
    pub newsletter_sends: Arc<NewsletterSendDao>,
    /// FR-102 P5 — SendGrid's Event Webhook key, parsed once; `None` turns
    /// the webhook off (every request is the empty 404).
    pub sendgrid_events: Option<Arc<sendgrid::EventVerifier>>,
}

impl std::ops::Deref for SaasState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<SaasState> for Core {
    fn from_ref(state: &SaasState) -> Self {
        state.core.clone()
    }
}

impl Module for SaasState {
    const ID: &'static str = "saas";

    type Deps = ();

    async fn init(core: Core, settings: &Settings, _deps: ()) -> anyhow::Result<Self> {
        let db = &core.db;
        // FR-102 P6 — the daily purestat puller (hosted-only: this module).
        // Spawns nothing without `growth.enabled` and a purestat key; one
        // pod per tick through a Redis claim, like the fleet and network
        // modules' sweepers spawned from their own init.
        purestat_pull::spawn_puller(core.clone());
        // FR-102 P7 — the daily GitHub puller: the repository's public
        // counters as cumulative snapshots (no credential), and its traffic
        // with the optional token. Nothing without `growth.enabled` and a
        // repository; one pod per tick through its own Redis claim.
        github_pull::spawn_puller(core.clone());
        // FR-102 P7 — search: Google Search Console per final day (with a
        // service-account key), the blog's feed and each post's URL
        // Inspection verdict (the feed needs nothing; the verdicts the same
        // key), and Bing Webmaster at Bing's own grain (with an API key).
        // Each says once why it pulls nothing, and claims its own tick.
        search_pull::spawn_puller(core.clone());
        content_pull::spawn_puller(core.clone());
        bing_pull::spawn_puller(core.clone());
        // FR-102 P5 (D6) — SendGrid's account-level open/click tracking,
        // read once and warned about loudly if on. Spawned, bounded, never
        // blocks the boot; nothing without a SendGrid key.
        sendgrid::spawn_tracking_check(&core);
        // FR-115 P2 — keep each subscription's quantity equal to its org's
        // seats (every 15 minutes, one pod per tick). Nothing without a
        // Stripe key, or with `stripe.seat_sync` off.
        stripe::spawn_seat_sync(core.clone());
        let sendgrid_events =
            sendgrid::verifier_from_settings(&settings.newsletter.event_webhook_public_key)
                .map(Arc::new);
        Ok(Self {
            subscribers: Arc::new(SubscriberDao::new(db)),
            newsletter_issues: Arc::new(NewsletterIssueDao::new(db)),
            newsletter_sends: Arc::new(NewsletterSendDao::new(db)),
            sendgrid_events,
            core,
        })
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.saas
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        // Plan-independent: billing and the newsletter are platform features,
        // not something a tenant's plan switches on or off.
        Capabilities::enabled(Self::ID)
    }

    /// Everything under `/api`, inside the governor. Paths are the ones the
    /// host mounted before P2, unchanged — the composition baseline is the
    /// check.
    fn routes(&self) -> Router {
        // Stripe: plan listing + checkout + customer portal. The webhook is
        // in `unlimited_routes` (see there).
        let stripe = Router::new()
            .route("/plans", get(stripe::get_plans))
            .route("/checkout", post(stripe::create_checkout))
            .route("/portal", post(stripe::create_portal))
            // FR-115 — a plan change on a live subscription (never a second
            // checkout), and the billing page's view of the org.
            .route("/change-plan", post(stripe::change_plan))
            .route("/summary", get(stripe::summary));

        // FR-58 — the newsletter sending program's admin surface. Platform-
        // admin gated, 404 on miss; `platform_admins` unset ⇒ the whole
        // family 404s.
        let admin_newsletter = Router::new()
            .route("/issues", post(newsletter::create).get(newsletter::list))
            .route(
                "/issues/{slug}",
                put(newsletter::update).get(newsletter::get_one),
            )
            .route("/issues/{slug}/preview", get(newsletter::preview))
            .route("/issues/{slug}/test-send", post(newsletter::test_send))
            .route("/issues/{slug}/send", post(newsletter::send))
            .route("/issues/{slug}/status", get(newsletter::status));

        // FR-102 P8 — the promotion pipeline's pushes (D11), opened by an
        // INGEST key and nothing else (D12). The gate runs first, before the
        // body is read: a missing, wrong or revoked key — and
        // `growth.enabled = false` — is the empty 404 of a path that does
        // not exist, never 401/403 (AC18).
        let growth_ingest_routes = Router::new()
            .route(
                "/admin/growth/ingest/posts",
                post(growth_ingest::ingest_post),
            )
            .route(
                "/admin/growth/ingest/snapshots",
                post(growth_ingest::ingest_snapshot),
            )
            .route_layer(DefaultBodyLimit::max(growth_ingest::MAX_BODY_BYTES))
            .route_layer(axum::middleware::from_fn_with_state(
                self.clone(),
                growth_ingest::require_ingest_key,
            ));

        Router::new()
            .merge(growth_ingest_routes)
            // FR-102 P4 — the operator's one-off read of Stripe's paid
            // invoices into `billing_events` (platform admins; 404 otherwise
            // and when `growth.enabled = false`). Reads Stripe, never writes.
            .route("/admin/growth/billing/backfill", post(stripe::backfill))
            .nest("/stripe", stripe)
            .nest("/admin/newsletter", admin_newsletter)
            // FR-32 P1c — "who would break if enforcement were turned on?".
            // Platform-admin only (404 on miss, like the rest of /admin).
            .route(
                "/admin/plan-compliance",
                get(plan_compliance::admin_plan_compliance),
            )
            // FR-58 P4 — the signed-in newsletter toggle. A different door
            // into `subscribers`, not a second list. A static segment, so it
            // wins over the host's `/user/{user_id}` capture.
            .route(
                "/user/newsletter",
                get(newsletter::user_get).put(newsletter::user_set),
            )
            // FR-39 — the public updates list. No auth extractor: `subscribe`
            // is an open form, and for the other two the unguessable token IS
            // the capability. ⚠️ `subscribe` answers 202 for every outcome,
            // including failure — the uniform response is a membership-oracle
            // control, not error handling.
            .route("/subscribe", post(subscribe::subscribe))
            // FR-58 follow-up: the GET is a pure redirect to the confirm PAGE —
            // Gmail's link scanner burned the first field subscriber's
            // single-use token via the old confirming GET. The POST is the
            // deliberate click.
            .route(
                "/subscribe/confirm/{token}",
                get(subscribe::confirm_redirect).post(subscribe::confirm),
            )
            // FR-58: the POST leg is the RFC 8058 one-click target — same
            // path, same token capability, plain 200 (providers follow no
            // redirects).
            .route(
                "/subscribe/unsubscribe/{token}",
                get(subscribe::unsubscribe).post(subscribe::unsubscribe_oneclick),
            )
            .with_state(self.clone())
    }

    /// S5 — the Stripe webhook, OUTSIDE the governor: it is signature-
    /// authenticated, and retry bursts from Stripe's fixed IPs would trip the
    /// per-IP limiter and mark the endpoint failing on their dashboard.
    ///
    /// FR-102 P5 — SendGrid's Event Webhook, for the same reasons: signed
    /// (ECDSA, verified before the body is parsed), and SendGrid posts a
    /// batch every 30 s from a handful of addresses. Its own body bound (a
    /// batch is at most 768 KB).
    fn unlimited_routes(&self) -> Router {
        Router::new()
            .route("/api/stripe/webhook", post(stripe::webhook))
            .route(
                "/api/sendgrid/webhook",
                post(sendgrid::webhook)
                    .route_layer(DefaultBodyLimit::max(sendgrid::MAX_BODY_BYTES)),
            )
            .with_state(self.clone())
    }

    /// The collections this module owns. The first three's specs are the
    /// ones the db crate's plan held before P2, unchanged; FR-102 P4 adds
    /// `billing_events`.
    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            // Subscribers (FR-39).
            IndexSet {
                collection: "subscribers",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "email": 1 }),
                    index_unique(bson::doc! { "unsubscribe_token": 1 }),
                    index(bson::doc! { "confirm_token": 1 }),
                    index(bson::doc! { "created_at": -1 }),
                ],
            },
            // Newsletter issues (FR-58). `slug` is unique because create is
            // explicit (a typo'd slug on update must 404, never upsert a
            // second issue), and the unique index is what arbitrates two
            // concurrent creates.
            IndexSet {
                collection: "newsletter_issues",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "slug": 1 }),
                    index(bson::doc! { "created_at": -1 }),
                ],
            },
            // Newsletter delivery ledger (FR-58). 🔑 The unique pair IS the
            // send program's at-most-once invariant: rows are claimed
            // (inserted) before the send attempt, so a resume — or even two
            // pods fanning out concurrently — resolves each recipient to
            // exactly one winner.
            IndexSet {
                collection: "newsletter_sends",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "issue_id": 1, "subscriber_id": 1 }),
                    index(bson::doc! { "issue_id": 1, "status": 1 }),
                ],
            },
            // FR-102 P4 — what Stripe billed. A webhook row is unique by its
            // event (`event_id`; sparse — a backfilled row has none), a paid
            // invoice by `(kind, stripe_id)` across the webhook and the
            // backfill; read per org over time and by kind over time.
            IndexSet {
                collection: "billing_events",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique_sparse(bson::doc! { "event_id": 1 }),
                    index_unique_partial(
                        bson::doc! { "kind": 1, "stripe_id": 1 },
                        bson::doc! { "kind": "invoice_paid" },
                    ),
                    index(bson::doc! { "tenant_id": 1, "ts": 1 }),
                    index(bson::doc! { "kind": 1, "ts": 1 }),
                ],
            },
            // FR-102 P7 — the blog's posts as the content puller read them
            // from the feed, `_id` the post's path, with Google's URL
            // Inspection verdict. Read newest first by the Content table.
            // No TTL: our own content, no person (spec §3p).
            IndexSet {
                collection: meshharbor_services::dao::growth_content::GROWTH_CONTENT,
                pre_ops: Vec::new(),
                indexes: vec![index(bson::doc! { "published_at": -1 })],
            },
        ]
    }
}
