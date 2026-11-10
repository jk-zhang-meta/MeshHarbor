// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 — growth observability, the host's side (spec §3o).
//!
//! Everything under `/api/admin/growth/*` is a view over core (users,
//! tenants, the exclusion list) and whichever modules are mounted (fleet's
//! agents, remote's sessions, conference's calls, saas's subscribers) — a
//! composition view, which is the host's to hold, next to `/admin/stats`.
//! Same gate as its siblings: 404 to anyone who is not a platform admin,
//! and 404 for everyone when `growth.enabled = false` (the kill switch).
//!
//! * [`exclusions`] — P1c: the explicit exclusion list and the implicit one
//!   it folds into (`meshharbor_core::growth::ExclusionSet`).
//! * [`digest`] — P1d: the daily digest's sections, the once-only claim,
//!   the delivery and the scheduler; [`purestat`] its one read of the web
//!   plane (in `meshharbor-services` since P6, re-exported here); [`render`]
//!   its email bodies; [`routes`] its four routes.
//! * [`value`] — P2: the four value-event definitions every view shares.
//! * [`org_daily`] — P2: `growth_org_daily`, the nightly fold and the
//!   bounded backfill.
//! * [`funnel`], [`cohorts`], [`orgs`] — P2: the account funnel with time
//!   to value, the weekly cohorts with the north star (WAO), the org list
//!   and one org's timeline.
//! * [`campaigns`] — P6: the Campaigns table, purestat's web plane queried
//!   live for the range beside the funnel's account plane, joined by the
//!   normalised campaign key. (The daily purestat PULL is the `saas`
//!   module's — it talks to the outside world for the hosted business.)
//! * [`revenue`] — P4: billed revenue from `billing_events` (the `saas`
//!   module's Stripe webhook and backfill) — billed MRR, the monthly
//!   movements (frozen once closed), trial → paid, by channel — beside the
//!   list-price estimate, the cost to serve (margin) and the plan-limit
//!   collisions.
//! * [`channels`], [`keys`] — P8: the Channels table (each platform's own
//!   reach as the promotion pipeline pushed it, then what each post's key
//!   brought, and spend) and the machine keys that open the `saas` module's
//!   ingest routes.
//! * [`newsletter`] — P5: the list over time and the per-issue table
//!   (delivery from SendGrid's signed Event Webhook, unsubscribes through
//!   the issue's own link, visits and sign-ups by the issue's campaign key).
//!   The webhook itself is the `saas` module's.
//! * [`read_key`] — P10: the read key (D12) — a layer on this router and
//!   the [`read_key::GrowthAuth`] extractor every GET view names: a live
//!   key opens a GET of a data route, and everything else it meets is the
//!   empty 404.
//! * [`weekly`] — P10: the weekly roll-up — the past ISO week's totals,
//!   funnel, cohort lines and tables, computed, stored and mailed once
//!   through the digest's own claim, in `growth_weekly`.
//! * [`alerts`] — P10: the alert rules, their hourly evaluation, the
//!   `growth_alerts` rows and the once-a-day mail.
//! * [`quality`] — P9a: remote-desktop quality per day and agent version,
//!   frozen nightly into `growth_quality_daily` from `remote_sessions`,
//!   `agent_logs` (FR-22's time to first frame, before its 7-day horizon),
//!   `agent_crashes` and `stats_machine_1d`; the Quality view and the
//!   re-freeze route. Server only — no remote-control code path changes.

pub mod alerts;
pub mod campaigns;
pub mod channels;
pub mod cohorts;
pub mod content;
pub mod digest;
pub mod exclusions;
pub mod funnel;
pub mod github;
pub mod keys;
pub mod newsletter;
pub mod org_daily;
pub mod orgs;
pub mod quality;
pub mod read_key;
pub mod render;
pub mod revenue;
pub mod routes;
pub mod search;
pub mod value;
pub mod weekly;

/// The purestat v1 client lives in `meshharbor-services` since P6 — below
/// the host AND the `saas` module, whose daily puller uses it too.
/// Re-exported so `growth::purestat::…` keeps naming it.
pub use meshharbor_services::purestat;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// The one error type of the growth surface: the digest's, which every
/// later phase reuses rather than minting a twin.
pub use digest::DigestError as GrowthError;

/// The `/api/admin/growth` router, mounted by `build_router`.
///
/// P10 — [`read_key::read_key_gate`] is a layer on every route here: a
/// request carrying a growth key is answered by the key's rule (a live
/// read key opens a GET of a data route; anything else is the empty 404)
/// before any handler runs, and a request without one reaches the
/// handlers' session gate as before.
pub fn admin_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/exclusions",
            get(exclusions::get_exclusions).put(exclusions::put_exclusions),
        )
        // P1d — the digest: a stored day, the list, a recompute (mails only
        // with `send=true` and never a `sent` day), and a live preview that
        // stores and mails nothing (`include_internal=true` = raw totals).
        .route("/digest", get(routes::get_digest))
        .route("/digests", get(routes::list_digests))
        .route("/digest/run", post(routes::run_digest))
        .route("/digest/preview", get(routes::preview_digest))
        // P2 — the account funnel (with time to value), the weekly cohorts
        // (with WAO), the org list, one org's timeline, and the bounded
        // backfill of `growth_org_daily`.
        .route("/funnel", get(funnel::get_funnel))
        .route("/cohorts", get(cohorts::get_cohorts))
        .route("/orgs", get(orgs::list_orgs))
        .route("/org/{tenant_id}/timeline", get(orgs::org_timeline))
        .route("/org-daily/backfill", post(org_daily::backfill_route))
        // P6 — the Campaigns table: per normalised key, purestat's web
        // plane (live, for the exact range) beside the account funnel.
        .route("/campaigns", get(campaigns::get_campaigns))
        // P7 — the Content table: per blog post, the web plane over the
        // range (purestat, live), Google's final days from the `saas`
        // pullers, the URL Inspection verdict, and the sign-ups that
        // landed on it.
        .route("/content", get(content::get_content))
        // P4 — billed revenue, the monthly movements, margin and the
        // plan-limit collisions. (The Stripe backfill that fills it is the
        // `saas` module's `/admin/growth/billing/backfill`.)
        .route("/revenue", get(revenue::get_revenue))
        // P8 — the Channels table (each platform's own reach, then what the
        // posts' keys brought, and spend) and the growth machine keys (D12:
        // only a hash stored; an `ingest` key opens the `saas` module's
        // `/admin/growth/ingest/*` routes and nothing else).
        .route("/channels", get(channels::get_channels))
        .route("/keys", get(keys::list_keys).post(keys::mint_key))
        .route("/keys/{key_id}", delete(keys::revoke_key))
        // P5 — the newsletter: the list over time and the per-issue table.
        .route("/newsletter", get(newsletter::get_newsletter))
        // P10 — the weekly roll-up: a stored week (the latest when `week`
        // is omitted), the list, and a recompute through the same claim
        // the scheduler uses (mails only with `send=true`, never a `sent`
        // week).
        .route("/weekly", get(weekly::get_weekly))
        .route("/weeklies", get(weekly::list_weeklies))
        .route("/weekly/run", post(weekly::run_weekly))
        // P10 — alerts: the open and recent rows, and an evaluation of
        // every rule now (what the hourly job does), for a field check.
        .route("/alerts", get(alerts::get_alerts))
        .route("/alerts/evaluate", post(alerts::evaluate_route))
        // P9a — remote-desktop quality over a closed range of frozen days
        // (per agent version, the day series), and a re-freeze of a closed
        // range with the current exclusion set.
        .route("/quality", get(quality::get_quality))
        .route("/quality/backfill", post(quality::backfill_route))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            read_key::read_key_gate,
        ))
}

/// Whether a module is mounted on this pod — the gate every growth read of
/// a module's collection passes, so an absent module reads as "cannot
/// see", never as "none".
pub(crate) fn mounted(state: &AppState, id: &str) -> bool {
    state.modules.mounted().contains(&id)
}

/// The gate every growth handler passes first: a platform admin, on a
/// server whose growth surface is on. Both failures are 404 — the surface
/// is what is being hidden.
pub(crate) fn require_growth_admin(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    crate::routes::stats::require_platform_admin(state, auth)?;
    if !state.settings.growth.enabled {
        return Err(ApiError::NotFound("Not found".to_string()));
    }
    Ok(())
}
