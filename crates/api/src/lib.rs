// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
pub mod cluster;
pub mod compose;
pub mod core_state;
pub mod extractors;
pub mod growth;
pub mod logging;
pub mod middleware;
pub mod routes;
pub mod stall_watchdog;
pub mod state;
pub mod stats_rollup;
pub mod ws;

// FR-69 P1b/P1d — these moved into `roomler-core` unchanged (they hold or
// serve `Core`'s fields, or are the request-side primitives a module's
// handlers need: the error type, the session cookie helpers, the origin
// policy); re-exported so every `crate::…` path in this crate reads as before.
pub use roomler_core::{cookies, error, origin, rate_limit, relay_load, storage, user_analytics};

use axum::{
    Router,
    routing::{delete, get, post, put},
};
use middleware::{
    auth_rate_limit::{AuthRateLimitState, AuthRateLimiter},
    client_ip::TrustedProxyIpKeyExtractor,
};
use state::AppState;
use std::sync::Arc;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

fn build_cors_layer(origins: &[String], frontend_url: &str) -> CorsLayer {
    // The allow-list is computed by `origin::origin_policy`, which the `/ws`
    // upgrade also consults before honouring a session COOKIE. Sharing the
    // answer is the point: two hand-rolled copies of "an origin we trust"
    // would drift, and the copy that drifts loose is an authenticated socket
    // for somebody else's page.
    //
    // Tightened default (2026-07-28, closes the "Any-origin fallback"
    // Known Issue): with no cors_origins configured, allow only the
    // frontend's own origin instead of every origin. Same-origin app
    // traffic never needed CORS; native clients (agent, tunnel CLI,
    // desktop) don't enforce it — so nothing legitimate relied on Any.
    let policy = crate::origin::origin_policy(origins, frontend_url);

    // Explicit "*" = the operator deliberately chose permissive mode.
    let allowed_strs = match policy {
        crate::origin::OriginPolicy::AnyOrigin => {
            tracing::warn!("CORS is configured fully permissive (cors_origins contains \"*\")");
            return CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);
        }
        crate::origin::OriginPolicy::Only(list) => list,
    };

    let allowed: Vec<axum::http::HeaderValue> =
        allowed_strs.iter().filter_map(|o| o.parse().ok()).collect();
    if allowed.is_empty() {
        // Nothing parseable — fail open rather than brick every browser
        // client, but say so loudly.
        tracing::warn!("CORS origin list resolved empty; falling back to permissive");
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
    }
    // NOTE: with allow_credentials(true), tower-http (0.6+) rejects
    // wildcard methods/headers at request time — the old
    // `.allow_methods(Any)` here is why the two cors_tests sat in the
    // known-failing baseline. Enumerate instead.
    use axum::http::{Method, header};
    CorsLayer::new()
        .allow_origin(allowed)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_credentials(true)
}

pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(
        &state.settings.app.cors_origins,
        &state.settings.app.frontend_url,
    );

    // Capacity limiting for `/api`, keyed on the client address.
    //
    // `per_millisecond` (like `per_second`) takes the interval that
    // replenishes ONE token, not a rate — so the req/s setting is converted
    // by `rate_limit_period_ms` rather than passed straight through. Feeding
    // a rate into `per_second` is what made prod 10x stricter instead of 10x
    // looser on 2026-07-28.
    //
    // The key comes from `TrustedProxyIpKeyExtractor`, not `SmartIpKeyExtractor`:
    // the latter believes a client-supplied `X-Forwarded-For`, which is a
    // one-header bypass of the whole limiter.
    let governor_conf = GovernorConfigBuilder::default()
        .per_millisecond(state.settings.app.rate_limit_period_ms())
        .burst_size(state.settings.app.rate_limit_burst)
        .key_extractor(TrustedProxyIpKeyExtractor {
            trusted_hops: state.settings.app.rate_limit_trusted_hops,
        })
        .finish()
        .expect("rate limit period is clamped non-zero, so the config is valid");
    let governor_layer = GovernorLayer {
        config: governor_conf.into(),
    };

    // Brute-force gate for the credential endpoints, keyed on
    // (client address, account) so it can be strict without locking out
    // everyone sharing an address.
    let auth_rate_limit_state = AuthRateLimitState {
        limiter: Arc::new(AuthRateLimiter::new(
            state.settings.app.auth_rate_limit_period_ms(),
            state.settings.app.auth_rate_limit_burst,
        )),
        trusted_hops: state.settings.app.rate_limit_trusted_hops,
    };

    // Password endpoints — the ones actually worth guessing at — carry the
    // per-(address, account) brute-force gate on top of the general limiter.
    //
    // `/refresh` is deliberately NOT here: a refresh token is a signed,
    // high-entropy secret rather than something guessable, so the gate would
    // buy nothing, and refreshes carry no account field to key on. Every
    // refresh from one address would share a single bucket, which turns a
    // token-expiry stampede in a shared office into a self-inflicted outage.
    let credential_routes = Router::new()
        .route("/register", post(routes::auth::register))
        .route("/login", post(routes::auth::login))
        .route("/native/share-ssh/login", post(routes::auth::native_share_ssh_login))
        .route("/approval/status", post(routes::account_approval::status))
        .layer(axum::middleware::from_fn_with_state(
            auth_rate_limit_state,
            middleware::auth_rate_limit::auth_rate_limit,
        ));

    // Auth routes (no tenant prefix)
    let auth_routes = Router::new()
        .route("/approval/access", get(routes::account_approval::access))
        .route("/approval", get(routes::account_approval::list))
        .route(
            "/approval/{user_id}",
            post(routes::account_approval::review),
        )
        .route("/logout", post(routes::auth::logout))
        .route("/refresh", post(routes::auth::refresh))
        .route("/activate", post(routes::auth::activate))
        .route("/me", get(routes::auth::me))
        .route("/me", put(routes::auth::me))
        .merge(credential_routes);

    // Tenant routes
    let tenant_routes = Router::new()
        .route("/", get(routes::tenant::list))
        .route("/", post(routes::tenant::create))
        .route("/{tenant_id}", get(routes::tenant::get))
        // Owner-only. Archiving revokes every device's enrollment and
        // releases the org's mesh — see `routes::tenant::archive`.
        .route("/{tenant_id}/archive", post(routes::tenant::archive))
        .route("/{tenant_id}/unarchive", post(routes::tenant::unarchive));

    // Member routes (under tenant)
    let member_routes = Router::new()
        .route(
            "/",
            get(routes::user::list_members).post(routes::invite::add_member),
        )
        .route("/me", get(routes::user::my_membership))
        // FR-10 — matchit gives the static `/me` above precedence over this
        // parameterised segment.
        .route("/{user_id}", delete(routes::user::remove_member));

    // Room CRUD, messages, reactions, files, search, the xlsx export and
    // Giphy are the `chat` module's (FR-69 P3); the call lifecycle and the
    // recording routes under the same `/room` prefix are `conference`'s (P4).

    // Background task routes (under tenant)
    let task_routes = Router::new()
        .route("/", get(routes::background_task::list))
        .route("/{task_id}", get(routes::background_task::get))
        .route(
            "/{task_id}/download",
            get(routes::background_task::download),
        );

    // Export routes (under tenant). The xlsx `/conversation` export is the
    // `chat` module's; this PDF one is the host's integration route, mounted
    // under the same prefix.
    let export_routes = Router::new().route(
        "/conversation-pdf",
        post(routes::integration::export_conversation_pdf),
    );

    // Public invite routes (no auth required for info, auth required for accept)
    let public_invite_routes = Router::new()
        .route("/{code}", get(routes::invite::get_invite_info))
        .route("/{code}/accept", post(routes::invite::accept_invite));

    // Role routes (under tenant)
    let role_routes = Router::new()
        .route("/", get(routes::role::list))
        .route("/", post(routes::role::create))
        .route("/{role_id}", put(routes::role::update))
        .route("/{role_id}", delete(routes::role::delete))
        .route("/{role_id}/assign/{user_id}", post(routes::role::assign))
        .route(
            "/{role_id}/assign/{user_id}",
            delete(routes::role::unassign),
        );

    // Tenant-scoped invite routes
    let tenant_invite_routes = Router::new()
        .route("/", get(routes::invite::list_invites))
        .route("/", post(routes::invite::create_invite))
        .route("/batch", post(routes::invite::batch_create_invite))
        .route("/{invite_id}", delete(routes::invite::revoke_invite));

    // OAuth routes (no auth required)
    let oauth_routes = Router::new()
        .route("/{provider}", get(routes::oauth::oauth_redirect))
        .route("/callback/{provider}", get(routes::oauth::oauth_callback));

    // Stripe routes are the `saas` module's (FR-69 P2), including the
    // webhook, which that module mounts un-governed at the root.

    // Push notification routes (user-scoped, no tenant prefix)
    let push_routes = Router::new()
        .route("/config", get(routes::push::config))
        .route("/subscribe", post(routes::push::subscribe))
        .route("/unsubscribe", post(routes::push::unsubscribe));

    // Notification routes (user-scoped, no tenant prefix)
    let notification_routes = Router::new()
        .route("/", get(routes::notification::list))
        .route("/unread", get(routes::notification::unread))
        .route("/unread-count", get(routes::notification::unread_count))
        .route(
            "/{notification_id}/read",
            put(routes::notification::mark_read),
        )
        .route("/read-all", post(routes::notification::mark_all_read));

    // User profile routes
    let user_routes = Router::new()
        .route("/me", put(routes::user::update_profile))
        // P4 — `/user/unread-summary` is the `chat` module's (it counts
        // messages); a static segment, it still wins over the capture.
        // FR-12 P3 — likewise static, likewise above the capture.
        .route("/tutorial", put(routes::user::update_tutorial))
        // FR-58 P4 — `/user/newsletter` (the signed-in toggle) is mounted by
        // the `saas` module; a static segment, it still wins over the capture.
        .route("/{user_id}", get(routes::user::get_profile));

    // rc.58 — browser console log batch ingest. User-authed (the
    // controller user's JWT). The body MUST include an explicit
    // `tenant_id` field since the user JWT doesn't pin a tenant; the
    // route handler verifies membership before persisting.
    // The per-device network sub-routes under the fleet module's `/agent`
    // prefix (`overlay-key/rotate`, `ssh`, `ssh-policy`, `peer-relay-policy`)
    // are the `network` module's (FR-69 P7a), merged in by
    // `state.modules.mount` below — as is the rest of pillar 2's HTTP
    // surface: tunnel clients + policies, overlay nodes / ACL / MagicDNS /
    // blocks, peer relays, SSH audit + activity + settings, the public
    // `/tunnel-client/*` enrollment pair and the two `/admin/overlay-*`
    // platform operations.

    // `/tenant/{tenant_id}/session/*`, `/turn/credentials` and
    // `/relay/regions` are the `remote` module's (FR-69 P6), merged in by
    // `state.modules.mount` below.

    // Stats PR-3 — observability queries. The /admin family is gated by
    // the platform_admins ObjectId allowlist (404 on miss); the tenant
    // family gates in-handler (member for overview, MANAGE_AGENTS for
    // the queryable series — also 404, so a polled panel degrades to
    // empty rather than erroring; see stats.rs for why it is not the
    // "the client logs out on 403" reason this used to give, FR-82).
    let admin_stats_routes = Router::new()
        .route("/relay/current", get(routes::stats::admin_relay_current))
        .route("/relay/history", get(routes::stats::admin_relay_history))
        .route("/orgs", get(routes::stats::admin_orgs))
        // FR-20 P5 - per-org metered cost + margin inputs. Platform
        // admin only, and it reports "not priced"/"not monitored"
        // rather than zero for anything it has not measured.
        .route("/cost", get(routes::cost::admin_cost))
        .route("/users", get(routes::stats::admin_users))
        .route("/machines", get(routes::stats::admin_machines))
        .route("/calls", get(routes::stats::admin_calls))
        // FR-88 P1a — sign-ups by campaign and how many activated (a device
        // enrolled within 7 days). Counts only; `activated` is null without
        // the fleet module.
        .route("/attribution", get(routes::attribution::admin_attribution))
        // Wave 3 — per-user usage. `/usage/{uid}` spans every org, which is
        // what makes "in which org did this happen" answerable.
        .route("/usage", get(routes::usage::admin_usage))
        .route("/usage/{user_id}", get(routes::usage::admin_usage_detail));
    // FR-58 — the newsletter admin surface (`/admin/newsletter/*`) is
    // mounted by the `saas` module (FR-69 P2).
    let tenant_stats_routes = Router::new()
        .route("/overview", get(routes::stats::tenant_overview))
        .route("/mesh", get(routes::stats::tenant_mesh))
        .route("/machines", get(routes::stats::tenant_machines))
        .route("/calls", get(routes::stats::tenant_calls))
        .route("/tunnels", get(routes::stats::tenant_tunnels))
        // FR-20 P6 - the org's OWN metered consumption, in units rather
        // than money: these are our costs, not their bill, and the point of
        // the surface is that a high relayed share is something their own
        // network team can act on. Membership only; failures 404.
        .route("/resources", get(routes::cost::tenant_resources))
        // `/usage` needs MANAGE_AGENTS (everyone's activity); `/usage/{uid}`
        // is self-service for your OWN row, MANAGE_AGENTS for anyone else's.
        .route("/usage", get(routes::usage::tenant_usage))
        .route("/usage/{user_id}", get(routes::usage::tenant_usage_detail));

    // Compose API
    let api = Router::new()
        // FR-69 — what this server is composed of; the module list one UI
        // build and one daemon read before offering a pillar.
        .route("/capabilities", get(routes::capabilities::get))
        // C-6 — per-pod cluster status (identity, counters, gauges).
        .route("/cluster/status", get(routes::cluster::status))
        .nest("/auth", auth_routes)
        .nest("/user", user_routes)
        .nest("/oauth", oauth_routes)
        .nest("/invite", public_invite_routes)
        .nest("/push", push_routes)
        .nest("/notification", notification_routes)
        .nest("/admin/stats", admin_stats_routes)
        // FR-102 — growth observability: the exclusion list (P1c) and, from
        // P1d, the daily digest. A composition view over core and whichever
        // modules are mounted, so the host's, next to `/admin/stats`; the
        // same platform-admin gate, plus `growth.enabled`.
        .nest("/admin/growth", growth::admin_routes(&state))
        // `/stripe/*`, `/admin/newsletter/*`, `/admin/plan-compliance`,
        // `/user/newsletter` and `/subscribe*` are the `saas` module's
        // (FR-69 P2), merged in by `state.modules.mount` below.
        // Wave 2 — the SPA's route-change beacon (authenticated, paths
        // normalised server-side). User-scoped, not tenant-scoped: a
        // user navigates across orgs within one session.
        .route("/stats/pageview", post(routes::stats::page_view))
        .nest("/tenant", tenant_routes)
        .nest("/tenant/{tenant_id}/member", member_routes)
        .nest("/tenant/{tenant_id}/role", role_routes)
        .nest("/tenant/{tenant_id}/invite", tenant_invite_routes)
        .nest("/tenant/{tenant_id}/task", task_routes)
        .nest("/tenant/{tenant_id}/export", export_routes)
        // `/tenant/{tenant_id}/device` — the listing that joins agents with
        // tunnel clients and overlay nodes — is the `network` module's (FR-69
        // P7b: it depends on fleet, which the graph allows; the host may not).
        .nest("/tenant/{tenant_id}/stats", tenant_stats_routes);

    // FR-69 — the unified device listing is the host's composition view:
    // fleet's agents (required) joined with network's tunnel clients and
    // overlay nodes (optional). Mounted wherever `fleet` is compiled in, so
    // a `remote` profile keeps its devices page; the handler answers 503
    // when the module is switched off at runtime.
    #[cfg(feature = "fleet")]
    let api = api.nest(
        "/tenant/{tenant_id}/device",
        Router::new().route("/", get(routes::device::list_devices)),
    );

    // User-only personal directory: actual ownership + nonpending membership,
    // never a tenant-wide/platform-admin device inventory.
    #[cfg(feature = "fleet")]
    let api = if state.modules.fleet.is_some() {
        api.route("/account/devices", get(routes::account_devices::list))
            .route("/account/devices/summary", get(routes::account_devices::summary))
    } else { api };

    // Explicit account-to-single-device shares never create tenant membership.
    #[cfg(feature = "fleet")]
    let api = if state.modules.fleet.is_some() {
        api.nest(
            "/device-shares",
            Router::new()
                .route(
                    "/",
                    get(routes::device_share::list).post(routes::device_share::create),
                )
                .route("/{share_id}/revoke", post(routes::device_share::revoke))
                .route("/{share_id}/check", post(routes::device_share::check)),
        )
    } else {
        api
    };

    // FR-84 D5a — a device's OWN view of its org, agent-token authenticated:
    // the devices its overlay netmap already carries (plus itself) and the
    // mesh graph over the same set, for the desktop companion. The same
    // composition (fleet required, network optional) and the same owner as
    // the listing above. Plain routes rather than a nest: the fleet module
    // already serves `/agent/self/unenroll` under its own `/agent` nest.
    #[cfg(feature = "fleet")]
    let api = api
        .route("/agent/self/devices", get(routes::agent_self::devices))
        .route("/agent/self/mesh", get(routes::agent_self::mesh));

    // Health check. `/health` stays a cheap process-alive 200 (liveness /
    // startup probes — must NOT flap on dependency blips or k8s restarts the
    // pod during a Redis outage); `/health/ready` checks the dependencies
    // (readiness probe + operators).
    let health = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check));

    // FR-69 — the module crates' governed routes join the host's under
    // `/api` (`crates/api/src/compose.rs`).
    let api = state.modules.mount(api);

    // Apply rate limiting only to API routes (not health/ws which need unrestricted access)
    let rate_limited_api = Router::new().nest("/api", api).layer(governor_layer);

    // FR-69 — the module crates' ungoverned routes join at the root: the
    // Stripe webhook (S5) is signature-authed, and retry bursts from Stripe's
    // fixed IPs would trip the per-IP limiter and mark the endpoint failing
    // on their dashboard.
    let root = state
        .modules
        .mount_unlimited(Router::new().merge(rate_limited_api).merge(health));
    // FR-69 P7b — a module's own upgrade endpoints join the root too: `/derp`
    // is the network module's, mounted at the path it has always had.
    let root = state.modules.mount_upgrades(root);

    root.route("/ws", get(ws::handler::ws_upgrade))
        // Security — never let a bearer-carrying query string into the logs:
        // `/ws?token=<jwt>&role=agent` and `/derp?token=<jwt>` authenticate
        // via the query (WS clients can't set headers), and TraceLayer's
        // default span records the FULL uri at DEBUG — pod logs held live
        // long-lived agent JWTs (field 2026-08-18, task #15). Queries that
        // carry no token stay logged verbatim (pagination etc. is useful).
        .layer(TraceLayer::new_for_http().make_span_with(
            |req: &axum::http::Request<axum::body::Body>| {
                let uri = req.uri();
                let shown = match uri.query() {
                    Some(q) if q.contains("token") => {
                        format!("{}?<token redacted>", uri.path())
                    }
                    _ => uri.to_string(),
                };
                tracing::debug_span!("request", method = %req.method(), uri = %shown)
            },
        ))
        .layer(cors)
        .with_state(state)
}

async fn health_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        // FR-69 P8 — the modules THIS binary mounts, which is what a profile
        // boot smoke asserts. `compiled` is the set the build linked
        // (`compose::EXTRACTED`); the two differ only by `[modules]`
        // switches. ⚠️ Not `graph::MODULES` — that is the DAG every build
        // knows about, and a `mesh` image answering all six would be exactly
        // the lie the smoke exists to catch.
        "modules": state.modules.mounted(),
        "compiled": compose::EXTRACTED,
    }))
}

/// Readiness: 200 only when Mongo answers a ping, the Redis publisher
/// round-trips a PING, and the pub/sub subscriber currently holds a live
/// subscription. 503 otherwise, with per-check detail in the body. A pod
/// that booted without Redis (`redis_pubsub: None`) reports not-ready —
/// cross-instance delivery is silently broken in that state and the old
/// static 200 hid it.
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use std::time::Duration;

    let mongo_ok = tokio::time::timeout(
        Duration::from_secs(2),
        state.db.run_command(bson::doc! { "ping": 1 }),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    let (redis_ok, subscriber_ok) = match &state.redis_pubsub {
        Some(pubsub) => {
            let ok = tokio::time::timeout(Duration::from_secs(2), pubsub.ping())
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            (
                ok,
                state
                    .redis_sub_alive
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
        }
        None => (false, false),
    };

    let ready = mongo_ok && redis_ok && subscriber_ok;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(serde_json::json!({
            "status": if ready { "ready" } else { "not_ready" },
            "checks": {
                "mongo": mongo_ok,
                "redis": redis_ok,
                "redis_subscriber": subscriber_ok,
            },
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}
