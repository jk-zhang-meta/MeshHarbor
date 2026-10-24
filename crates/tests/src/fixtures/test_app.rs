// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use mongodb::{Client, Database, options::ClientOptions};
use roomler_ai_api::{build_router, state::AppState};
use roomler_ai_config::Settings;
use roomler_ai_db::indexes::ensure_indexes;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// A running test application with its own MongoDB database.
pub struct TestApp {
    pub addr: SocketAddr,
    pub base_url: String,
    pub db: Database,
    pub settings: Settings,
    pub client: reqwest::Client,
    /// The server's own state — lets tests drive in-process surfaces the
    /// HTTP API doesn't expose (rc-hub introspection, `shutdown_cleanup`).
    pub state: AppState,
}

/// Install a tracing subscriber ONCE per test binary, only when `RUST_LOG`
/// is set.
///
/// Without this the harness has no subscriber at all, so every `info!` and
/// `warn!` the server emits is discarded — and several of those lines exist
/// precisely to explain a refusal. `/derp` registration is the worst case: it
/// refuses with `info!` and returns, so the symptom is a directory record that
/// silently never appears, and `RUST_LOG=info` does nothing to help you (it
/// cost a long diagnosis in #612). Failures like that are meant to be readable.
///
/// Opt-in rather than always-on: the suite is chatty and most runs don't want
/// it. `with_test_writer` routes through the harness capture, so output shows
/// up under `--nocapture` and stays attached to the failing test otherwise.
/// Keep each `TestApp`'s connection pool tiny.
///
/// Every test builds its OWN `Client` against its OWN database, and the
/// driver's default pool is 10 connections — so a full suite run can ask one
/// mongod for a couple of thousand sockets, each of which is a file
/// descriptor on the server.
///
/// ⚠️ This fixed NOTHING, and the measurement says so. I read `conn1333` in
/// the crash log as "too many connections" and capped the pool; the next run
/// failed identically. Sampling mongod during a run (CI run 32767662554)
/// settled it — connections are FLAT while files explode:
///
/// ```text
///   19:30:34  fds=51    wt_files=14    conns=5   leaked_dbs=0
///   19:30:50  fds=5192  wt_files=5166  conns=11  leaked_dbs=21
/// ```
///
/// 5 166 files for 21 databases is ~246 WiredTiger files per database (one
/// per collection AND per index), so `fds ≈ 26 + 246 × databases` and the
/// 64 000 `nofile` ceiling arrives at ~260 databases — mid-suite. The cause
/// is the teardown that never ran; see `impl Drop for TestApp`.
///
/// The cap stays because it is genuinely free: a test needs ~1 connection at
/// a time, so 2 is generous. It is not a fix for anything.
fn cap_pool(opts: &mut ClientOptions) {
    opts.max_pool_size = Some(2);
    opts.min_pool_size = Some(0);
}

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var("RUST_LOG").is_ok() {
            // `try_init` because a global default may already exist; a second
            // install must never abort a test run.
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
        }
    });
}

impl TestApp {
    /// Spawn a new test server connected to the test MongoDB.
    ///
    /// Requires a running MongoDB at localhost:27019.
    /// Set ROOMLER__DATABASE__URL env var to override the connection string.
    /// Each test gets a unique database name for isolation.
    pub async fn spawn() -> Self {
        init_tracing();
        let db_name = format!("roomler_ai_test_{}", uuid::Uuid::new_v4().simple());

        let mut settings = Settings::load().unwrap_or_else(|_| {
            // Fallback to minimal settings for tests
            test_settings()
        });
        // Allow env var override for database URL
        if let Ok(url) = std::env::var("ROOMLER__DATABASE__URL") {
            settings.database.url = url;
        }
        settings.database.name = db_name.clone();

        let mut client_options = ClientOptions::parse(&settings.database.url)
            .await
            .expect("Failed to parse MongoDB URL");
        cap_pool(&mut client_options);
        let mongo_client =
            Client::with_options(client_options).expect("Failed to create MongoDB client");
        let db = mongo_client.database(&db_name);

        ensure_indexes(&db, settings.overlay.multi_block_enabled)
            .await
            .expect("Failed to create indexes");

        // FR-69 P4 — boxed: the server-construction future (every module init,
        // the mediasoup worker pool) is the largest state machine in the crate,
        // and a test that builds several servers in one body carried it inline
        // on the test thread (2 MiB) until `peer_relay_mint_tests` overflowed.
        let app_state = Box::pin(AppState::new(db.clone(), settings.clone()))
            .await
            .expect("Failed to create AppState");
        // FR-69 — the module crates' index sets, after the core plan (the
        // same two steps `main.rs` runs).
        roomler_ai_db::indexes::apply_index_sets(&db, &app_state.modules.index_sets())
            .await
            .expect("Failed to create module indexes");
        let state = app_state.clone();
        let app = build_router(app_state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            addr,
            base_url,
            db,
            settings,
            client,
            state,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Phase A-1 — model TWO pods: two servers over ONE database (and the
    /// one shared Redis at :6379), each with its own pod-local in-memory
    /// state (rc-hub, room manager, …). The second app shortens nothing;
    /// pass a `mutator` applied to BOTH apps' settings for e.g. short
    /// liveness deadlines.
    pub async fn spawn_pair(mutator: fn(&mut Settings)) -> (Self, Self) {
        init_tracing();
        let shared_db = format!("roomler_ai_test_{}", uuid::Uuid::new_v4().simple());
        let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let (db1, pod1) = (shared_db.clone(), format!("testpod1-{run}"));
        let app1 = Self::spawn_with_settings(move |s| {
            s.database.name = db1.clone();
            // C-1: distinct stable pod identities per in-process app (env
            // vars are process-global, so identity must ride Settings).
            s.app.pod_id = Some(pod1.clone());
            mutator(s);
        })
        .await;
        let (db2, pod2) = (shared_db.clone(), format!("testpod2-{run}"));
        let app2 = Self::spawn_with_settings(move |s| {
            s.database.name = db2.clone();
            s.app.pod_id = Some(pod2.clone());
            mutator(s);
        })
        .await;
        (app1, app2)
    }

    /// Spawn a test server with customized settings.
    ///
    /// The `mutator` closure receives a `&mut Settings` after defaults are applied,
    /// allowing tests to tweak specific fields (e.g., TURN config).
    pub async fn spawn_with_settings(mutator: impl FnOnce(&mut Settings)) -> Self {
        init_tracing();
        let db_name = format!("roomler_ai_test_{}", uuid::Uuid::new_v4().simple());

        let mut settings = Settings::load().unwrap_or_else(|_| test_settings());
        if let Ok(url) = std::env::var("ROOMLER__DATABASE__URL") {
            settings.database.url = url;
        }
        settings.database.name = db_name.clone();

        // Apply caller's customizations
        mutator(&mut settings);

        let mut client_options = ClientOptions::parse(&settings.database.url)
            .await
            .expect("Failed to parse MongoDB URL");
        cap_pool(&mut client_options);
        let mongo_client =
            Client::with_options(client_options).expect("Failed to create MongoDB client");
        // Phase A-1: honor a mutator-overridden db name — `spawn_pair`
        // models two pods by pointing two TestApps at ONE database (+ the
        // already-shared Redis). Pre-A-1 this line used the local
        // `db_name`, silently ignoring the override.
        let db = mongo_client.database(&settings.database.name);

        ensure_indexes(&db, settings.overlay.multi_block_enabled)
            .await
            .expect("Failed to create indexes");

        // FR-69 P4 — boxed: the server-construction future (every module init,
        // the mediasoup worker pool) is the largest state machine in the crate,
        // and a test that builds several servers in one body carried it inline
        // on the test thread (2 MiB) until `peer_relay_mint_tests` overflowed.
        let app_state = Box::pin(AppState::new(db.clone(), settings.clone()))
            .await
            .expect("Failed to create AppState");
        // FR-69 — the module crates' index sets, after the core plan (the
        // same two steps `main.rs` runs).
        roomler_ai_db::indexes::apply_index_sets(&db, &app_state.modules.index_sets())
            .await
            .expect("Failed to create module indexes");
        let state = app_state.clone();
        let app = build_router(app_state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            addr,
            base_url,
            db,
            settings,
            client,
            state,
        }
    }

    /// Spawn a test server with OAuth providers configured (fake client IDs).
    /// Uses a no-redirect reqwest client so we can inspect the 302/307 Location header.
    pub async fn spawn_with_oauth() -> Self {
        init_tracing();
        let db_name = format!("roomler_ai_test_{}", uuid::Uuid::new_v4().simple());

        let mut settings = Settings::load().unwrap_or_else(|_| test_settings());
        if let Ok(url) = std::env::var("ROOMLER__DATABASE__URL") {
            settings.database.url = url;
        }
        settings.database.name = db_name.clone();

        // Configure fake OAuth provider credentials
        settings.oauth.base_url = "http://localhost:5001".to_string();
        settings.oauth.google.client_id = "test-google-id".to_string();
        settings.oauth.google.client_secret = "test-google-secret".to_string();
        settings.oauth.facebook.client_id = "test-facebook-id".to_string();
        settings.oauth.facebook.client_secret = "test-facebook-secret".to_string();
        settings.oauth.github.client_id = "test-github-id".to_string();
        settings.oauth.github.client_secret = "test-github-secret".to_string();
        settings.oauth.linkedin.client_id = "test-linkedin-id".to_string();
        settings.oauth.linkedin.client_secret = "test-linkedin-secret".to_string();
        settings.oauth.microsoft.client_id = "test-microsoft-id".to_string();
        settings.oauth.microsoft.client_secret = "test-microsoft-secret".to_string();

        let mut client_options = ClientOptions::parse(&settings.database.url)
            .await
            .expect("Failed to parse MongoDB URL");
        cap_pool(&mut client_options);
        let mongo_client =
            Client::with_options(client_options).expect("Failed to create MongoDB client");
        let db = mongo_client.database(&db_name);

        ensure_indexes(&db, settings.overlay.multi_block_enabled)
            .await
            .expect("Failed to create indexes");

        // FR-69 P4 — boxed: the server-construction future (every module init,
        // the mediasoup worker pool) is the largest state machine in the crate,
        // and a test that builds several servers in one body carried it inline
        // on the test thread (2 MiB) until `peer_relay_mint_tests` overflowed.
        let app_state = Box::pin(AppState::new(db.clone(), settings.clone()))
            .await
            .expect("Failed to create AppState");
        // FR-69 — the module crates' index sets, after the core plan (the
        // same two steps `main.rs` runs).
        roomler_ai_db::indexes::apply_index_sets(&db, &app_state.modules.index_sets())
            .await
            .expect("Failed to create module indexes");
        let state = app_state.clone();
        let app = build_router(app_state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let base_url = format!("http://{}", addr);
        // No-redirect client for OAuth redirect tests
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client");

        Self {
            addr,
            base_url,
            db,
            settings,
            client,
            state,
        }
    }
}

impl TestApp {
    /// Activate a user by email (bypass email verification for tests).
    pub async fn activate_user(&self, email: &str) {
        use bson::doc;
        self.db
            .collection::<bson::Document>("users")
            .update_one(
                doc! { "email": email },
                doc! { "$set": { "is_verified": true } },
            )
            .await
            .expect("Failed to activate user");
    }
}

impl Drop for TestApp {
    /// Drop this test's database — **synchronously**.
    ///
    /// This used to be a detached `tokio::spawn`, which **never ran**. Every
    /// test here is a plain `#[tokio::test]` (all 291 of them), so the body is
    /// driven by `block_on` on a current-thread runtime; this `Drop` fires as
    /// that body completes, queues a task, and `block_on` returns on the very
    /// next step. The runtime is then dropped with the task still queued and
    /// never polled — so *every* test database survived its test. Same shape
    /// as #602: a dropped `JoinHandle` detaches, and detached is not "later",
    /// it is "never" once the runtime goes.
    ///
    /// Measured cost of the leak (CI run 32767662554): 29 tests → 29 databases
    /// → ~246 WiredTiger files each. A full suite crossed mongod's 64 000
    /// descriptor ceiling around the 260th database, hit `EMFILE`, and aborted
    /// on fatal assertion 50853 — which surfaced as dozens of unrelated-looking
    /// tests failing on `Connection refused`.
    ///
    /// ⚠️ The new client is **not** redundant with `self.db`, and reusing the
    /// existing one deadlocks. We block this thread on `join()`, so the test's
    /// runtime stops driving its IO driver — and `self.db`'s sockets are
    /// registered with exactly that driver, so their readiness would never be
    /// delivered. The cleanup must own every part of its own I/O.
    fn drop(&mut self) {
        let uri = self.settings.database.url.clone();
        let name = self.db.name().to_string();
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async {
                // ⚠️ Bound the wait. If mongod is already gone — which is
                // exactly the state this teardown exists to prevent — the
                // driver's 30 s default server selection would be spent once
                // PER TEST, and ~290 of those turn a diagnosable failure into
                // a job that hits its wall-clock limit having reported
                // nothing. Three seconds is generous for a local socket.
                let Ok(mut opts) = ClientOptions::parse(&uri).await else {
                    return;
                };
                opts.server_selection_timeout = Some(std::time::Duration::from_secs(3));
                opts.connect_timeout = Some(std::time::Duration::from_secs(3));
                opts.max_pool_size = Some(1);
                if let Ok(client) = Client::with_options(opts) {
                    let _ = client.database(&name).drop().await;
                }
            });
        })
        .join();
    }
}

fn test_settings() -> Settings {
    Settings {
        app: roomler_ai_config::AppSettings {
            rate_limit_per_sec: 1,
            rate_limit_burst: 60,
            // Tests talk to the server directly, so no proxy prepends a
            // hop — trust the peer address, not any client-sent header.
            rate_limit_trusted_hops: 0,
            business_trusted_proxy_cidrs: vec![],
            auth_rate_limit_per_min: 10,
            auth_rate_limit_burst: 20,
            host: "127.0.0.1".to_string(),
            port: 0,
            static_dir: None,
            cors_origins: vec![],
            frontend_url: "http://localhost:5173".to_string(),
            environment: "development".to_string(),
            pod_id: None,
        },
        database: roomler_ai_config::DatabaseSettings {
            url: "mongodb://localhost:27019".to_string(),
            name: "roomler_ai_test".to_string(),
            max_pool_size: Some(5),
            min_pool_size: Some(1),
        },
        jwt: roomler_ai_config::JwtSettings {
            secret: "test-secret-key-for-jwt-signing-minimum-32-chars".to_string(),
            previous_secrets: String::new(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 604800,
            issuer: "roomler-ai".to_string(),
        },
        redis: roomler_ai_config::RedisSettings {
            url: "redis://127.0.0.1:6379".to_string(),
        },
        s3: roomler_ai_config::S3Settings {
            // Tests run on the local-disk backend — the file_tests suite
            // must pass without a MinIO container.
            enabled: false,
            endpoint: "http://localhost:9000".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
            bucket: "roomler-ai-test".to_string(),
            region: "us-east-1".to_string(),
        },
        mediasoup: roomler_ai_config::MediasoupSettings {
            num_workers: 1,
            listen_ip: "0.0.0.0".to_string(),
            announced_ip: "127.0.0.1".to_string(),
            announced_ip_map: None,
            rtc_min_port: 40000,
            rtc_max_port: 40100,
        },
        turn: roomler_ai_config::TurnSettings {
            worker_urls: None,
            url: None,
            username: None,
            password: None,
            shared_secret: None,
            force_relay: None,
            ttl_secs: None,
        },
        relay: roomler_ai_config::RelaySettings::default(),
        releases: roomler_ai_config::ReleasesSettings::default(),
        // Stats collection ON (the prod default) so collector-path tests
        // exercise the real write path; platform_admins is set per-test
        // via `spawn_with_settings`.
        stats: roomler_ai_config::StatsSettings::default(),
        // FR-102 — the growth routes on, the digest OFF (the shipped
        // default); a digest test drives the job directly.
        growth: roomler_ai_config::GrowthSettings::default(),
        // FR-20 P5 - no prices configured, which is what a test deployment
        // (and any deployment without the toml) actually looks like. Every
        // cost therefore reads "not priced" rather than 0.00.
        relay_costs: roomler_ai_config::RelayCosts::default(),
        modules: roomler_ai_config::ModulesSettings::default(),
        // FR-90 P1g — every organization, as a deployment without `[hive]`.
        hive: roomler_ai_config::HiveSettings::default(),
        // FR-90 P3-1 — every organization and no KEK, as a deployment
        // without `[vault]`; a vault test makes its own KEK.
        vault: roomler_ai_config::VaultSettings::default(),
        // #1731 — inert here: the stall watchdog is armed by the binary's
        // `main`, which these in-process servers never run.
        diag: roomler_ai_config::DiagSettings::default(),
        // FR-115 P5 — the meeting cap ON, as a deployment without
        // `[meetings]`; the tests drive its sweep by hand.
        meetings: roomler_ai_config::MeetingsSettings::default(),
        // FR-115 P4a — the relay allowance OFF, as a deployment without
        // `[relay_allowance]`; its tests switch it on and drive the job by hand.
        relay_allowance: roomler_ai_config::RelayAllowanceSettings::default(),
        // P2b — blocks OFF by default, exactly like a fresh deployment. The
        // renumber tests carve explicitly; the block-carve test flips the
        // flag via `spawn_with_settings`.
        overlay: roomler_ai_config::OverlaySettings::default(),
        oauth: roomler_ai_config::OAuthSettings {
            base_url: "http://localhost:5001".to_string(),
            google: roomler_ai_config::OAuthProviderSettings {
                client_id: String::new(),
                client_secret: String::new(),
            },
            facebook: roomler_ai_config::OAuthProviderSettings {
                client_id: String::new(),
                client_secret: String::new(),
            },
            github: roomler_ai_config::OAuthProviderSettings {
                client_id: String::new(),
                client_secret: String::new(),
            },
            linkedin: roomler_ai_config::OAuthProviderSettings {
                client_id: String::new(),
                client_secret: String::new(),
            },
            microsoft: roomler_ai_config::OAuthProviderSettings {
                client_id: String::new(),
                client_secret: String::new(),
            },
        },
        stripe: roomler_ai_config::StripeSettings {
            secret_key: String::new(),
            webhook_secret: String::new(),
            price_pro: String::new(),
            price_business: String::new(),
            // FR-115 — annual off, real Stripe, and the seat sync as the
            // config default has it (on); a test that needs a fake Stripe
            // or annual prices sets them.
            seat_sync: true,
            ..Default::default()
        },
        giphy: roomler_ai_config::GiphySettings {
            api_key: String::new(),
        },
        email: roomler_ai_config::EmailSettings {
            api_key: String::new(),
            from_email: "test@roomler.ai".to_string(),
            from_name: "Roomler Test".to_string(),
            activation_token_ttl_minutes: 5,
            smtp_host: None,
            smtp_port: None,
        },
        newsletter: Default::default(),
        push: roomler_ai_config::PushSettings {
            vapid_public_key: String::new(),
            vapid_private_key: String::new(),
            contact: "mailto:test@roomler.ai".to_string(),
        },
        auth: roomler_ai_config::AuthSettings::default(),
        // Prod-shaped liveness (90 s — an in-process agent heartbeats every
        // 30 s, so existing tests never trip it). The reap test shortens it
        // via `spawn_with_settings`.
        rc: roomler_ai_config::RcSettings::default(),
    }
}
