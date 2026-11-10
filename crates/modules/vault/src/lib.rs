// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `vault` — IAM for secrets, the server side (FR-90 P3,
//! `docs/meshharbor-hive-design.md` §8, `docs/vault.md`).
//!
//! ⚠️ **Managed custody.** This module holds the key-encryption key and can
//! decrypt every secret it stores, so a compromised server can read them
//! all. That is the v1 model, said first and plainly; customer-managed keys
//! and sovereign custody are P7.
//!
//! P3-1 builds the store: secrets and their versions, each version sealed
//! under its own data key wrapped to an `age` KEK ([`crypto`]), named by
//! RRNs ([`rrn`]), every decision recorded in `vault_audit` — and an
//! administrator's metadata routes ([`routes`]), none of which answers a
//! value. Roles and Cedar policies (P3-2), a device's leases (P3-3) and the
//! session's tools (P3-4) are built on it. A device's own report of using a
//! lease (P3-4d) is kept apart, in `vault_activity`: a claim, never one of
//! the vault's decisions. A policy may ask for a person's yes before a value
//! is released (P3-4e, [`approval`]): a card in the session's room, answered
//! by one of its drivers. A session's own egress is the vault's to decide
//! too (P3-7-1b, [`net`]): a grant, signed under its own audience, that the
//! network module checks without calling the vault. So is a session's command
//! on another device over MeshHarbor SSH (P3-8-1a, [`ssh`]): a ticket, likewise
//! under its own audience, never naming the device the session runs on.
//! And from P3-9-1 a PERSON's use, through an endpoint their device serves
//! them (`mh connect`, [`connect`]): decided by Cedar's own
//! `secret:connect` for the device's owner as its row names them, and lent
//! only to the organizations `vault.people` lists.
//!
//! The module's switch defaults OFF (`[modules] vault`), and a
//! `vault.tenants` list both switches it on and limits it to the
//! organizations listed — the form a hosted server uses, as `hive.tenants`
//! is for Hive. Clearing the list is the kill switch.

use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{delete, get, post, put},
};
use meshharbor_config::Settings;
use meshharbor_core::{AgentSocketHooks, Capabilities, Core, Hooks, Module, TenantCtx};
use meshharbor_db::indexes::{IndexSet, index, index_ttl, index_unique, index_unique_partial};

pub mod approval;
pub mod connect;
pub mod crypto;
pub mod dao;
pub mod dynamic;
pub mod gate;
pub mod lease;
pub mod meta;
pub mod model;
pub mod net;
pub mod policy;
pub mod policy_routes;
pub mod revoke;
pub mod routes;
pub mod rrn;
pub mod scope;
pub mod ssh;

/// The module's state: the core, and what the vault owns.
#[derive(Clone)]
pub struct VaultState {
    pub core: Core,
    pub secrets: Arc<dao::VaultSecretDao>,
    pub versions: Arc<dao::VaultVersionDao>,
    pub audit: Arc<dao::VaultAuditDao>,
    /// P3-2 — the roles sessions assume, and the policies over them.
    pub roles: Arc<dao::VaultRoleDao>,
    pub policies: Arc<dao::VaultPolicyDao>,
    /// P3-3b — what was released to which session.
    pub leases: Arc<dao::VaultLeaseDao>,
    /// P3-3b — a lease is believed from the session record's device at its
    /// fence (hive's DAO, re-created: it is stateless), and sealed to the key
    /// on that device's row.
    pub sessions: Arc<meshharbor_mod_hive::dao::AgentSessionDao>,
    pub agents: Arc<meshharbor_services::dao::agent::AgentDao>,
    /// P3-3b — each session's lease requests per minute on its device.
    pub lease_limiter: Arc<meshharbor_core::rate_limit::RateLimiter>,
    /// P3-3c — this pod's devices' connections, and which hold live leases.
    pub revoker: Arc<revoke::Revoker>,
    /// P3-4d — what devices report doing with their leases, and each
    /// session's reports per minute on its device.
    pub activity: Arc<dao::VaultActivityDao>,
    pub activity_limiter: Arc<meshharbor_core::rate_limit::RateLimiter>,
    /// P3-4e — the approvals policies asked for, and their answers.
    pub approvals: Arc<dao::VaultApprovalDao>,
    /// The organizations the vault serves (`vault.tenants`).
    pub scope: Arc<scope::TenantScope>,
    /// P3-9-1 — the organizations whose people it lends to (`vault.people`,
    /// opt-in: empty is none).
    pub people: Arc<scope::TenantScope>,
    /// P3-9-1 — each device's requests per minute for its owner.
    pub person_limiter: Arc<meshharbor_core::rate_limit::RateLimiter>,
    /// P3-6b — the providers a dynamic secret is leased for
    /// (`vault.providers`).
    pub providers: Arc<dynamic::ProviderScope>,
    /// The KEK, or why there is none: read once at boot.
    pub kek: crypto::KekState,
}

impl std::ops::Deref for VaultState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<VaultState> for Core {
    fn from_ref(state: &VaultState) -> Self {
        state.core.clone()
    }
}

impl Module for VaultState {
    const ID: &'static str = "vault";

    /// No module STATE: hive's session reads go through its stateless DAO
    /// (the graph's `vault → hive` edge, FR-69 rule 5), and an answer to a
    /// device goes back on the connection it came from. P3-3c's revocations
    /// too: each pod tells the devices connected to it, on the connections
    /// its lease socket holds, so `fleet`'s Hub is not needed.
    type Deps = ();

    async fn init(core: Core, settings: &Settings, _deps: ()) -> anyhow::Result<Self> {
        let db = &core.db;
        let scope = scope::TenantScope::parse(&settings.vault.tenants);
        scope.log();
        let people = scope::TenantScope::parse_opt_in(&settings.vault.people);
        people.log_people();
        let providers = dynamic::ProviderScope::parse(&settings.vault.providers);
        providers.log();
        // Never a boot refusal: a missing or unusable KEK leaves the
        // metadata routes working and answers 503 where the key is needed.
        let kek = crypto::KekState::load(&settings.vault);
        kek.log();
        let state = Self {
            secrets: Arc::new(dao::VaultSecretDao::new(db)),
            versions: Arc::new(dao::VaultVersionDao::new(db)),
            audit: Arc::new(dao::VaultAuditDao::new(db)),
            roles: Arc::new(dao::VaultRoleDao::new(db)),
            policies: Arc::new(dao::VaultPolicyDao::new(db)),
            leases: Arc::new(dao::VaultLeaseDao::new(db)),
            sessions: Arc::new(meshharbor_mod_hive::dao::AgentSessionDao::new(db)),
            agents: Arc::new(meshharbor_services::dao::agent::AgentDao::new(db)),
            lease_limiter: Arc::new(meshharbor_core::rate_limit::RateLimiter::new()),
            revoker: Arc::new(revoke::Revoker::default()),
            activity: Arc::new(dao::VaultActivityDao::new(db)),
            activity_limiter: Arc::new(meshharbor_core::rate_limit::RateLimiter::new()),
            approvals: Arc::new(dao::VaultApprovalDao::new(db)),
            scope: Arc::new(scope),
            people: Arc::new(people),
            person_limiter: Arc::new(meshharbor_core::rate_limit::RateLimiter::new()),
            providers: Arc::new(providers),
            kek,
            core,
        };
        // P3-3c — every pod sweeps the leases of the devices connected to it.
        let sweep = match settings.vault.revoke_sweep_secs {
            0 => revoke::DEFAULT_SWEEP_SECS,
            secs => secs,
        };
        revoke::spawn_sweeper(state.clone(), std::time::Duration::from_secs(sweep));
        // P3-3b — the agent socket is fleet's; a device's `rc:vault.lease`
        // is dispatched here by `ClientMsg::namespace()`, and each
        // connection gets its own lease queue at its hello.
        let socket = Arc::new(lease::LeaseSocket::new(state.clone()));
        state.core.agent_socket.register(
            Self::ID,
            AgentSocketHooks {
                handler: Some(socket.clone()),
                lifecycle: Some(socket),
            },
        );
        Ok(state)
    }

    /// The module switch, or a `vault.tenants` list.
    fn enabled(settings: &Settings) -> bool {
        settings.vault_on()
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    fn routes(&self) -> Router {
        let secret = Router::new()
            .route("/", get(routes::list).post(routes::create))
            .route(
                "/{secret_id}",
                get(routes::describe)
                    .patch(routes::update)
                    .delete(routes::delete),
            )
            .route("/{secret_id}/value", put(routes::put_value));
        // P3-2 — roles, policies, and what a request would be decided.
        let role = Router::new()
            .route(
                "/",
                get(policy_routes::list_roles).post(policy_routes::create_role),
            )
            .route("/{name}", delete(policy_routes::delete_role));
        let policy = Router::new()
            .route(
                "/",
                get(policy_routes::list_policies).post(policy_routes::create_policy),
            )
            .route(
                "/{policy_id}",
                get(policy_routes::get_policy)
                    .put(policy_routes::replace_policy)
                    .delete(policy_routes::delete_policy),
            );
        Router::new()
            .route("/tenant/{tenant_id}/vault", get(routes::status))
            .route("/tenant/{tenant_id}/vault/verify", post(routes::verify))
            .route("/tenant/{tenant_id}/vault/audit", get(routes::audit))
            // P3-4d — what devices report doing with their leases.
            .route("/tenant/{tenant_id}/vault/activity", get(routes::activity))
            // P3-4e — an approval a policy asked for, and a driver's answer.
            .route(
                "/tenant/{tenant_id}/vault/approval/{approval_id}",
                get(approval::get).post(approval::answer),
            )
            .route(
                "/tenant/{tenant_id}/vault/schema",
                get(policy_routes::schema),
            )
            .route(
                "/tenant/{tenant_id}/vault/simulate",
                post(policy_routes::simulate),
            )
            // P3-2b — a change replayed against the recorded decisions.
            .route(
                "/tenant/{tenant_id}/vault/simulate/replay",
                post(policy_routes::replay),
            )
            .nest("/tenant/{tenant_id}/vault/secret", secret)
            .nest("/tenant/{tenant_id}/vault/role", role)
            .nest("/tenant/{tenant_id}/vault/policy", policy)
            .with_state(self.clone())
    }

    /// P3-2b — the gate hive asks, through core, before a session takes a
    /// role or moves with one ([`gate::VaultGate`]). P3-3c — a removed
    /// device's leases, taken back after hive has ended its sessions and
    /// before fleet removes it ([`revoke::VaultFleetHooks`]).
    fn hooks(&self) -> Hooks {
        Hooks {
            session: Some(Arc::new(gate::VaultGate {
                state: self.clone(),
            })),
            fleet: Some(Arc::new(revoke::VaultFleetHooks {
                state: self.clone(),
            })),
            ..Default::default()
        }
    }

    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            IndexSet {
                collection: model::VaultSecret::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    // One live secret per path in an organization; a
                    // tombstone frees its path. `$type: "null"`: a live row
                    // stores an explicit null.
                    index_unique_partial(
                        bson::doc! { "tenant_id": 1, "path": 1 },
                        bson::doc! { "deleted_at": { "$type": "null" } },
                    ),
                    // The listing: live rows, by path.
                    index(bson::doc! { "tenant_id": 1, "deleted_at": 1, "path": 1 }),
                ],
            },
            IndexSet {
                collection: model::VaultVersion::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    // One row per (secret, field, number): the counter hands
                    // numbers out, the index holds it to that.
                    index_unique(bson::doc! { "secret_id": 1, "field": 1, "n": 1 }),
                    // An organization's versions: the counts, a verify's
                    // scan, those wrapped to another KEK.
                    index(bson::doc! { "tenant_id": 1, "kek": 1 }),
                ],
            },
            // The server's decisions — 90-day retention, like the exec, SSH
            // and Hive audits.
            IndexSet {
                collection: model::VaultAuditEvent::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "secret_id": 1, "at": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // P3-2 — one live role, and one live policy, per name in an
            // organization; a tombstone frees its name.
            IndexSet {
                collection: model::VaultRole::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_unique_partial(
                    bson::doc! { "tenant_id": 1, "name": 1 },
                    bson::doc! { "deleted_at": { "$type": "null" } },
                )],
            },
            IndexSet {
                collection: model::VaultPolicy::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique_partial(
                        bson::doc! { "tenant_id": 1, "name": 1 },
                        bson::doc! { "deleted_at": { "$type": "null" } },
                    ),
                    // The organization's set, oldest first.
                    index(bson::doc! { "tenant_id": 1, "deleted_at": 1, "created_at": 1 }),
                ],
            },
            // P3-3b — leases: a session's, for its revocation (P3-3c); gone a
            // week after they expire, while the audit keeps the decision for
            // 90 days.
            IndexSet {
                collection: model::VaultLease::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "session_id": 1 }),
                    index_ttl(bson::doc! { "expires_at": 1 }, 7 * 24 * 60 * 60),
                    // P3-3c — a device's unexpired leases (its pod's sweep,
                    // its hello), and a changed secret's.
                    index(bson::doc! { "device_id": 1, "expires_at": 1 }),
                    index(bson::doc! { "secret_id": 1, "expires_at": 1 }),
                ],
            },
            // P3-4d — what devices report doing with their leases: claims,
            // kept 90 days like the decisions they are kept apart from. The
            // organization's newest, one session's, and those naming a lease.
            IndexSet {
                collection: model::VaultActivity::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "session_id": 1, "at": -1 }),
                    index(bson::doc! { "lease_ids": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // P3-4e — approvals: one pending card per request (the index
            // arbitrates two asks at once); a request's own, newest first;
            // kept 90 days, like the decisions they lifted.
            IndexSet {
                collection: model::VaultApproval::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique_partial(
                        bson::doc! {
                            "session_id": 1, "fence": 1, "device_id": 1, "secret_id": 1,
                            "field": 1, "mode": 1, "audience": 1,
                        },
                        bson::doc! { "status": "pending" },
                    ),
                    index(bson::doc! { "session_id": 1, "secret_id": 1, "requested_at": -1 }),
                    index_ttl(bson::doc! { "requested_at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
        ]
    }
}
