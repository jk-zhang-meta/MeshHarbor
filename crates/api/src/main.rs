// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use meshharbor_api::{build_router, state, state::AppState};
use meshharbor_config::{DEFAULT_FRONTEND_URL, Settings};
use meshharbor_db::{connect, indexes::ensure_indexes};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file (silently ignore if missing)
    dotenvy::dotenv().ok();

    // Initialize tracing.
    //
    // #1731 — through a non-blocking, lossy writer (`logging::nonblocking`):
    // a log call enqueues and returns, and one thread owns stdout. Writing
    // stdout synchronously under its process-wide lock let a log pipe that
    // stopped draining freeze every tokio worker at once (two, under the pod's
    // CPU limit), so `/health` died with the log. Now an overflow drops lines,
    // counted and reported below. The guard lives as long as `main`.
    let (log_writer, _log_guard) = meshharbor_api::logging::nonblocking(std::io::stdout());
    let dropped_log_lines = log_writer.error_counter();
    tracing_subscriber::registry()
        // ⚠️ The bare `warn` at the front is load-bearing, and it is the whole
        // point of this list's shape. Without it an `EnvFilter` built only from
        // `target=level` directives is an ALLOWLIST: a crate nobody named is
        // silent at every level, with nothing anywhere saying so.
        //
        // That is not hypothetical. FR-69 moved the pillars out of
        // `meshharbor_api` into `meshharbor-mod-*` + `meshharbor-core`, and this
        // default was not moved with them — so in prod, where `RUST_LOG` is
        // unset (checked: absent from the deployment env AND the
        // `meshharbor2-config` configmap, `printenv RUST_LOG` in the pod says
        // UNSET), **425 of the server's 522 log statements were dropped**:
        // the whole overlay engine, the DERP cluster, the ephemeral reaper,
        // the org-relay mint, the agent socket, fleet RPC, the Hub. Measured
        // 2026-09-07: zero `meshharbor_mod_network` lines in three hours while
        // `meshharbor_api` and `tower_http` logged normally, on a pod that was
        // demonstrably reaping devices at the time.
        //
        // It surfaced because a reap left no trace: the reaper's own comment
        // calls its line "the record that this removal happened and why", and
        // that record was going nowhere. A `warn` floor makes the next
        // omission merely quiet instead of invisible.
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                concat!(
                    "warn",
                    ",meshharbor_api=debug",
                    ",meshharbor_services=debug",
                    ",meshharbor_db=debug",
                    ",meshharbor_core=debug",
                    ",meshharbor_mod_fleet=debug",
                    ",meshharbor_mod_network=debug",
                    ",meshharbor_mod_remote=debug",
                    ",meshharbor_mod_chat=debug",
                    ",meshharbor_mod_conference=debug",
                    ",meshharbor_mod_saas=debug",
                    ",meshharbor_remote_control=debug",
                    ",tunnel_core=debug",
                    ",tower_http=debug",
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(log_writer))
        .init();
    meshharbor_api::logging::report_dropped_lines(dropped_log_lines);

    // Load config
    let settings = Settings::load()?;

    // #1731 — the stall watchdog: armed before anything that could stall, and
    // it never writes through stdout, the prime suspect. Unset = on in
    // production only.
    let stall_watchdog = settings
        .diag
        .stall_watchdog
        .unwrap_or(settings.app.environment == "production");
    if stall_watchdog {
        let dump_dir = std::path::PathBuf::from(&settings.diag.stall_dump_dir);
        let threshold = std::time::Duration::from_secs(settings.diag.stall_threshold_secs.max(2));
        match meshharbor_api::stall_watchdog::start(
            &tokio::runtime::Handle::current(),
            meshharbor_api::stall_watchdog::Config {
                threshold,
                dump_dir: dump_dir.clone(),
                echo_stderr: true,
            },
        ) {
            Ok(_running) => info!(
                dump_dir = %dump_dir.display(),
                threshold_secs = threshold.as_secs(),
                "stall watchdog armed (#1731)"
            ),
            Err(e) => warn!(error = %e, "stall watchdog did not start (#1731)"),
        }
        // Then whatever a stalled predecessor left behind: a stall normally
        // ends in a liveness kill, so this container is the first place its
        // dump can be reported. From a thread of its own and only after the
        // arming, so a log pipe that is still wedged can neither hold the boot
        // nor leave this process unwatched.
        let _ = std::thread::Builder::new()
            .name("stall-report".into())
            .spawn(move || {
                meshharbor_api::stall_watchdog::report_previous_dumps(&dump_dir);
            });
    }

    // The built-in JWT secret ("change-me-in-production") lets anyone forge
    // tokens. In development that's a loud warning; with
    // `app.environment=production` (prod configmap sets
    // MESHHARBOR__APP__ENVIRONMENT=production) it's a REFUSAL to boot — a
    // production deployment on the default secret is strictly worse than
    // downtime.
    if settings.jwt.secret == "change-me-in-production" {
        if settings.app.environment == "production" {
            anyhow::bail!(
                "Refusing to start: app.environment=production but the JWT secret \
                 is still the built-in default — set MESHHARBOR__JWT__SECRET."
            );
        }
        error!(
            "JWT secret is the built-in default \"change-me-in-production\" — \
             set MESHHARBOR__JWT__SECRET before exposing this server."
        );
    }

    // A RETIRED secret still verifies, so it forges exactly as well as the
    // current one. Rotating away from the default while leaving it in
    // `previous_secrets` would look like a fix and change nothing — the
    // guard above has to cover both lists or it only covers the easy half.
    if settings
        .jwt
        .previous_secrets
        .split(',')
        .map(str::trim)
        .any(|s| s == "change-me-in-production")
    {
        if settings.app.environment == "production" {
            anyhow::bail!(
                "Refusing to start: app.environment=production but the built-in default \
                 secret is listed in MESHHARBOR__JWT__PREVIOUS_SECRETS — tokens signed with \
                 it are still accepted, so this is not a rotation."
            );
        }
        error!(
            "The built-in default secret is listed in MESHHARBOR__JWT__PREVIOUS_SECRETS — \
             tokens signed with it are still accepted."
        );
    }

    // FR-50 P3 - `app.frontend_url` left at the built-in development default
    // on a production deployment.
    //
    // It was always load-bearing (OAuth returns, invitation and activation
    // links, the CORS origin policy), but FR-50 gave it a failure mode that
    // points away from itself: the route serving `install.{sh,ps1}` substitutes
    // this value, so a self-hoster who never set it downloads the installer
    // from their own server and then watches the agent enrol against
    // `http://localhost:5000`. Nothing in that error names `frontend_url`.
    //
    // A warning, not a refusal. A wrong `frontend_url` degrades links; it does
    // not compromise anything, and refusing to boot over it would take a live
    // deployment offline for a config value that looks cosmetic - which is not
    // the trade the JWT-secret refusals above are making.
    if settings.app.environment == "production" && settings.app.frontend_url == DEFAULT_FRONTEND_URL
    {
        error!(
            frontend_url = %settings.app.frontend_url,
            "app.environment=production but app.frontend_url is still the built-in \
             development default. OAuth returns, invitation and activation links, the \
             CORS origin policy and the SERVER baked into /api/setup/install.{{sh,ps1}} \
             all resolve from it - set MESHHARBOR__APP__FRONTEND_URL to this deployment's \
             public URL."
        );
    }

    // Stripe half-configuration is a silent checkout-killer: with a secret
    // key but empty price ids, every valid-plan checkout errors (prod hit
    // exactly this — empty MESHHARBOR__STRIPE__PRICE_PRO/BUSINESS in the
    // configmap). Loud at startup; the checkout path also refuses cleanly
    // (StripeError::PriceNotConfigured).
    if !settings.stripe.secret_key.is_empty()
        && (settings.stripe.price_pro.is_empty() || settings.stripe.price_business.is_empty())
    {
        error!(
            "Stripe secret key is set but price_pro/price_business is empty — \
             checkout WILL fail; set MESHHARBOR__STRIPE__PRICE_PRO and \
             MESHHARBOR__STRIPE__PRICE_BUSINESS."
        );
    }

    info!(
        "Starting MeshHarbor2 API on {}:{}",
        settings.app.host, settings.app.port
    );
    info!(
        listen_ip = %settings.mediasoup.listen_ip,
        announced_ip = %settings.mediasoup.announced_ip,
        rtc_ports = %format!("{}-{}", settings.mediasoup.rtc_min_port, settings.mediasoup.rtc_max_port),
        turn_url = ?settings.turn.url,
        force_relay = ?settings.turn.force_relay,
        "Mediasoup/TURN config"
    );

    // Connect to MongoDB
    let db = connect(&settings).await?;

    // Ensure indexes
    ensure_indexes(&db, settings.overlay.multi_block_enabled).await?;

    // Build app state (async: spawns mediasoup workers)
    let app_state = AppState::new(db.clone(), settings.clone()).await?;
    // FR-69 — the module crates' index sets, after the core plan above. The
    // `[modules]` switches decide which crates initialised; a switched-off
    // module contributes nothing here either.
    meshharbor_db::indexes::apply_index_sets(&db, &app_state.modules.index_sets()).await?;

    // S6 — leader-gate the startup maintenance below. With two pods, a
    // restarting pod must NOT reset `in_progress` calls that are live on
    // the OTHER pod's mediasoup. A short Mongo lease elects exactly one
    // maintenance runner per window: the filtered upsert succeeds for one
    // pod (fresh insert, or expired-lease takeover) and fails with a
    // duplicate-key / zero-match for everyone else. A skipped reset is
    // healed by the media:join get-or-create belt in ws/handler.rs.
    let startup_leader = {
        let locks = db.collection::<bson::Document>("locks");
        let now = bson::DateTime::now();
        let lease_until = bson::DateTime::from_millis(now.timestamp_millis() + 120_000);
        match locks
            .update_one(
                bson::doc! { "_id": "startup_maintenance", "expires_at": { "$lt": now } },
                bson::doc! { "$set": { "expires_at": lease_until } },
            )
            .upsert(true)
            .await
        {
            Ok(r) => r.modified_count > 0 || r.upserted_id.is_some(),
            // Concurrent upsert loser (E11000 on _id) or Mongo hiccup —
            // either way, someone else owns maintenance this window.
            Err(_) => false,
        }
    };
    if !startup_leader {
        info!(
            "Startup maintenance lease held elsewhere — skipping stale-call reset + thread migration"
        );
    }

    // FR-69 P4 — the modules' startup jobs under the same lease: the
    // stale-call reset (no call can be active at server startup) is
    // conference's leader-gated job now. A failing job is logged, not fatal —
    // exactly what the inline block did with its `.ok()`.
    app_state.modules.run_startup_jobs(startup_leader).await;

    // FR-82 — bring every system-managed role up to its definition.
    //
    // A managed role's mask was written once, at tenant creation, and never
    // again: adding a permission bit reached only orgs created afterwards.
    // Measured on the hosted deployment before this landed — 63 of 72 orgs
    // carried `admin = 0x7ffff7`, i.e. no MANAGE_AGENTS, no REMOTE_CONTROL
    // and neither audit view — every fleet feature shipped since those orgs
    // were created, invisible to their own admins. Additive
    // (`stored | definition`), grouped, and a no-op on every boot after the
    // first.
    //
    // Logged at INFO with the arithmetic, never silently: this GRANTS
    // permissions across every tenant on the deployment, so the one run that
    // does something has to be readable in `kubectl logs` afterwards.
    if startup_leader {
        if !settings.auth.reconcile_managed_roles {
            // Say so out loud. Off, a role stays frozen at the mask it was
            // seeded with, and the symptom (an admin who cannot see the
            // fleet) looks nothing like a config switch.
            warn!(
                "managed-role reconcile is OFF (auth.reconcile_managed_roles=false) — \
                 roles seeded before a permission bit existed will not gain it"
            );
        } else {
            match app_state.tenants.reconcile_managed_roles().await {
                Ok(groups) => {
                    let changed: Vec<_> = groups.iter().filter(|g| g.gained() != 0).collect();
                    if changed.is_empty() {
                        info!(
                            groups = groups.len(),
                            "managed roles already match their definitions"
                        );
                    } else {
                        for g in &changed {
                            info!(
                                role = %g.name,
                                rows = g.rows,
                                stored = format!("{:#x}", g.stored),
                                gained = format!("{:#x}", g.gained()),
                                granted = ?meshharbor_db::models::role::permissions::names(g.gained()),
                                "managed role reconciled to its definition"
                            );
                        }
                    }
                }
                // Not fatal, exactly like the maintenance below it: a
                // deployment that cannot reconcile its roles is one with
                // stale permissions, not one that should refuse to serve.
                Err(e) => warn!(error = %e, "managed-role reconcile failed"),
            }
        }
    }

    // Fix thread metadata for existing thread roots with null metadata
    // (bug: MongoDB $inc fails on null subdocuments, so reply_count was never set)
    if startup_leader {
        let msgs_coll = db.collection::<bson::Document>("messages");
        // Count replies per thread parent and rebuild metadata
        use futures::TryStreamExt;
        let pipeline = vec![
            bson::doc! { "$match": { "thread_id": { "$ne": null } } },
            bson::doc! { "$group": {
                "_id": "$thread_id",
                "reply_count": { "$sum": 1 },
                "last_reply_at": { "$max": "$created_at" },
                "last_reply_user_id": { "$last": "$author_id" },
                "participant_ids": { "$addToSet": "$author_id" },
            }},
        ];
        if let Ok(mut cursor) = msgs_coll.aggregate(pipeline).await {
            let mut fixed = 0u64;
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(parent_id), Some(count)) = (
                    doc.get_object_id("_id").ok(),
                    doc.get_i32("reply_count").ok(),
                ) {
                    let update = bson::doc! {
                        "$set": {
                            "is_thread_root": true,
                            "thread_metadata": {
                                "reply_count": count,
                                "last_reply_at": doc.get("last_reply_at"),
                                "last_reply_user_id": doc.get("last_reply_user_id"),
                                "participant_ids": doc.get("participant_ids"),
                            },
                        },
                    };
                    if msgs_coll
                        .update_one(bson::doc! { "_id": parent_id }, update)
                        .await
                        .is_ok()
                    {
                        fixed += 1;
                    }
                }
            }
            if fixed > 0 {
                info!(
                    "Rebuilt thread metadata for {} thread parent messages",
                    fixed
                );
            }
        }
    }

    // One-off migration: a pre-S0 pod wrote uploads to the (ephemeral) local
    // dir; when the S3 backend is enabled, sweep whatever survived up to S3
    // so those file records resolve again. No-op on the local backend.
    {
        let storage = app_state.storage.clone();
        tokio::spawn(async move { storage.migrate_local_to_s3().await });
    }

    // Build router
    let shutdown_state = app_state.clone();
    let app = build_router(app_state);

    // Start server
    let addr = format!("{}:{}", settings.app.host, settings.app.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);

    // Phase A-1 — graceful shutdown: on SIGTERM/CTRL-C run the presence
    // cleanup FIRST (mark this pod's agents Offline + release their Redis
    // claims — a killed pod must not strand green-but-dead rows), then let
    // axum stop accepting. axum's graceful drain waits for in-flight
    // connections INDEFINITELY (surviving browser WSs would pin the
    // process until SIGKILL), so the whole serve future is raced against
    // a short post-signal drain window. No pre-close draining: the front
    // nginx targets host IPs (readiness is invisible to it) and
    // maxSurge=0 means every drained second is downtime for this node.
    let (cleanup_done_tx, cleanup_done_rx) = tokio::sync::oneshot::channel::<()>();
    // `with_connect_info` so the rate limiter has a peer address to fall back
    // on when `X-Forwarded-For` is absent or too short to trust (a request
    // that did not come through our proxy chain).
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        info!("shutdown signal received — running presence cleanup");
        state::shutdown_cleanup(&shutdown_state).await;
        let _ = cleanup_done_tx.send(());
    });
    tokio::select! {
        r = serve => { r?; }
        _ = async {
            let _ = cleanup_done_rx.await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        } => {
            info!("shutdown drain window elapsed; exiting");
        }
    }

    Ok(())
}

/// Resolve on SIGTERM (k8s pod stop; unix only) or CTRL-C (everywhere).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                error!(%e, "SIGTERM handler install failed; CTRL-C only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
