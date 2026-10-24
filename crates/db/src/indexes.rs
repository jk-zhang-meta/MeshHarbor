// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use mongodb::{Database, IndexModel, options::IndexOptions};
use serde::Serialize;
use tracing::info;

/// A pre-creation operation on a collection — applied before that
/// collection's indexes are created, in plan order.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IndexOp {
    /// `dropIndex`, tolerating both "index not found" (27) and "collection not
    /// found" (26); anything else is an error.
    DropIndexIfPresent {
        index: &'static str,
        /// Logged when applied — the one line a reader of the boot log needs.
        why: &'static str,
    },
}

/// One collection's index set.
#[derive(Debug, Clone, Serialize)]
pub struct IndexSet {
    pub collection: &'static str,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_ops: Vec<IndexOp>,
    pub indexes: Vec<IndexModel>,
}

/// Every index the app relies on, as data, in the order they are applied.
///
/// FR-69: this is what the composition baseline records and what
/// [`ensure_indexes`] applies — the two cannot drift, because the second is
/// defined in terms of the first. Modules contribute their own sets from P1
/// on; until then this one plan holds them all.
#[derive(Debug, Clone, Serialize)]
pub struct IndexPlan {
    pub multi_block: bool,
    pub sets: Vec<IndexSet>,
}

fn set(collection: &'static str, indexes: Vec<IndexModel>) -> IndexSet {
    IndexSet {
        collection,
        pre_ops: Vec::new(),
        indexes,
    }
}

/// Create every index the app relies on — [`index_plan`], applied in order.
///
/// `multi_block` (FR-47 P5c) selects between two mutually exclusive schemas
/// for `overlay_blocks`:
///
/// * `false` — the partial-unique index on `network_id` is created, enforcing
///   **one assigned block per network**. This is the shipped default and the
///   pre-P5c behaviour.
/// * `true` — that index is **dropped** if present and never created, because
///   it *is* the invariant multi-block removes.
///
/// ⚠️ Passing `true` is a one-way door in practice. Once a network holds two
/// assigned blocks, going back to `false` cannot recreate the index — Mongo
/// refuses it on the duplicate `network_id` — and the boot would fail loudly
/// rather than silently run without the guard. That is the intended failure:
/// a uniqueness guard that quietly gives up is worse than one that stops you.
pub async fn ensure_indexes(db: &Database, multi_block: bool) -> Result<(), mongodb::error::Error> {
    apply_index_sets(db, &index_plan(multi_block).sets).await?;
    info!("All indexes ensured");
    Ok(())
}

/// Apply index sets in order: each set's pre-ops, then its indexes.
///
/// FR-69 — the host calls this a second time with the module crates' sets
/// (`roomler_core::Module::indexes`), after the core plan above.
pub async fn apply_index_sets(
    db: &Database,
    sets: &[IndexSet],
) -> Result<(), mongodb::error::Error> {
    for entry in sets {
        for op in &entry.pre_ops {
            apply_op(db, entry.collection, op).await?;
        }
        create_indexes(db, entry.collection, entry.indexes.clone()).await?;
    }
    Ok(())
}

async fn apply_op(
    db: &Database,
    collection: &str,
    op: &IndexOp,
) -> Result<(), mongodb::error::Error> {
    match op {
        IndexOp::DropIndexIfPresent { index, why } => {
            // Two "nothing to drop" outcomes, and BOTH are normal — tolerating
            // only one of them is a bug this cost a test run to find:
            //
            //   * IndexNotFound (27)     — the collection exists without the
            //     index (a deployment that already ran with the op applied).
            //   * NamespaceNotFound (26) — the collection does not exist AT
            //     ALL, which is every fresh database, including every test
            //     database.
            //
            // 26 is the one that is easy to miss, because it never happens on
            // the deployment you are looking at while developing.
            if let Err(e) = db
                .collection::<bson::Document>(collection)
                .drop_index(*index)
                .await
                && !matches!(
                    &*e.kind,
                    mongodb::error::ErrorKind::Command(c) if c.code == 27 || c.code == 26
                )
            {
                return Err(e);
            }
            info!("{collection}: {why}");
            Ok(())
        }
    }
}

/// The plan: every collection's index set, in application order.
pub fn index_plan(multi_block: bool) -> IndexPlan {
    let mut sets: Vec<IndexSet> = Vec::new();

    // Tenants
    sets.push(set(
        "tenants",
        vec![
            index_unique(bson::doc! { "slug": 1 }),
            index(bson::doc! { "owner_id": 1 }),
        ],
    ));

    // Users
    sets.push(set(
        "users",
        vec![
            index_unique(bson::doc! { "email": 1 }),
            index_unique(bson::doc! { "username": 1 }),
            index_text(bson::doc! { "display_name": "text", "username": "text" }),
            // FR-88 P1a — the activation view reads sign-ups by creation
            // window (`UserDao::signups_between`: a range on `created_at`,
            // sorted by it). Users are core, so the index is the core plan's.
            index(bson::doc! { "created_at": 1 }),
        ],
    ));

    // Explicit device-share ledger. Expiry is checked synchronously; do not TTL-delete audit history.
    sets.push(set(
        "device_share_grants",
        vec![
            index(bson::doc! {"recipient_user_id":1,"device_id":1,"revoked_at":1,"expires_at":1}),
            index(bson::doc! {"owner_user_id":1,"created_at":-1,"_id":-1}),
            index(bson::doc! {"recipient_user_id":1,"created_at":-1,"_id":-1}),
        ],
    ));

    // Tenant Members
    sets.push(set(
        "tenant_members",
        vec![
            index_unique(bson::doc! { "tenant_id": 1, "user_id": 1 }),
            index(bson::doc! { "user_id": 1 }),
        ],
    ));

    // Roles
    sets.push(set(
        "roles",
        vec![
            index_unique(bson::doc! { "tenant_id": 1, "name": 1 }),
            index(bson::doc! { "tenant_id": 1, "position": 1 }),
        ],
    ));

    // FR-69 P3 — `rooms`, `room_members`, `messages`, `reactions`, `files`
    // and `custom_emojis` are the `chat` module's: their sets live in
    // `roomler_ai_mod_chat::ChatState::indexes`.

    // FR-69 P4 — `recordings` and `call_sessions` are the `conference`
    // module's: their sets live in `roomler_ai_mod_conference::ConferenceState::indexes`.

    // Invites
    sets.push(set(
        "invites",
        vec![
            index_unique(bson::doc! { "code": 1 }),
            index(bson::doc! { "tenant_id": 1, "status": 1 }),
        ],
    ));

    // Consent requests (Phase 4 — owner email/push consent). Unique capability
    // token; lookup by session; TTL-swept at `expires_at` (expireAfterSeconds=0
    // ⇒ the doc's own date is the expiry).
    // FR-69 P5a — `consent_requests` is the `fleet` module's
    // (`roomler_ai_mod_fleet::FleetState::indexes`).

    // Background Tasks
    sets.push(set(
        "background_tasks",
        vec![
            index(bson::doc! { "tenant_id": 1, "user_id": 1, "status": 1 }),
            index_ttl(bson::doc! { "expires_at": 1 }, 0),
        ],
    ));

    // S5 — Stripe webhook idempotency ledger: `_id` = the Stripe event
    // id (natural unique key), rows expire after 30 days (Stripe stops
    // retrying long before that).
    sets.push(set(
        "stripe_events",
        vec![index_ttl(
            bson::doc! { "processed_at": 1 },
            30 * 24 * 60 * 60,
        )],
    ));

    // Notifications
    sets.push(set(
        "notifications",
        vec![
            index(bson::doc! { "user_id": 1, "is_read": 1, "created_at": -1 }),
            index(bson::doc! { "tenant_id": 1, "user_id": 1 }),
        ],
    ));

    // FR-69 P2 — `subscribers`, `newsletter_issues` and `newsletter_sends`
    // are the `saas` module's: their sets live in
    // `roomler_ai_mod_saas::SaasState::indexes` and the host applies them
    // after this plan.

    // Activation Codes
    sets.push(set(
        "activation_codes",
        vec![
            index(bson::doc! { "user_id": 1 }),
            // TTL: auto-expire when valid_to passes
            index_ttl(bson::doc! { "valid_to": 1 }, 0),
        ],
    ));

    // FR-69 P5a — `agents`, `agent_crashes`, `enrollment_keys`,
    // `enrollment_key_uses`, `exec_audit`, `config_audit` and `agent_logs` are
    // the `fleet` module's: their sets live in
    // `roomler_ai_mod_fleet::FleetState::indexes`.
    // FR-69 P6 — `remote_sessions` (both sets) and `remote_audit` are the
    // `remote` module's: `roomler_ai_mod_remote::RemoteState::indexes`.

    // Remote-control agent crash reports — 90-day TTL on
    // `reported_at` (server clock). Compound index drives the admin
    // UI query: "last N crashes for this agent in this tenant",
    // sorted by client-supplied `crashed_at_unix` desc. See
    // `roomler_ai_remote_control::models::AgentCrashRecord` for the
    // shape (defined by the crash-report plan).

    // FR-69 P7a — `tunnel_clients`, `overlay_networks`, `overlay_blocks` (both
    // `multi_block` plans), `overlay_nodes`, `tunnel_policies`, `tunnel_audit`
    // (both sets), `key_rotation_audit`, `peer_relay_audit`, `ssh_audit` and
    // `ssh_activity` are the `network` module's: their sets live in
    // `roomler_ai_mod_network::NetworkState::indexes_for`.

    // Single-use token ledger (`_id` = the token's jti, so uniqueness is the
    // primary key and a claim is one insert). Rows expire an hour after use —
    // past every 10-minute enrollment token's lifetime, so a replay always
    // finds its record, while the ledger stays bounded.
    sets.push(set(
        "used_tokens",
        vec![index_ttl(bson::doc! { "used_at": 1 }, 60 * 60)],
    ));

    // FR-51 P2 — reusable ephemeral enrollment keys. `jti` is the value the
    // atomic use-claim is keyed by; unique GLOBALLY (jtis are uuid4, and a
    // cross-tenant collision would let one org's claim decrement another's
    // ceiling). No TTL: a dead key is a record until pruning is decided
    // explicitly (P4).

    // Fleet-RPC audit log — 90-day retention, same posture as remote_audit /
    // tunnel_audit. Every exec ATTEMPT lands here, allowed or denied, so the
    // (tenant_id, at) index backs the org-wide "what ran on my fleet?" view
    // and (agent_id, at) backs the per-device console history. The
    // (tenant_id, user_id, at) entry answers "what did this person run?" —
    // the question an incident review actually starts from.

    // Centralized log batches (rc.58). 7-day TTL on `created_at` so
    // operators have a one-week diagnostic window. The compound
    // tenant+agent+created_at index drives the admin UI query "last N
    // batches for this agent". The text index on `lines.msg` powers
    // full-text search in the admin UI; without it a tenant with 10k
    // batches/day would hit a collection scan on every search.

    // ── Observability / analytics (stats PR-1) ────────────────────────────
    // Sample collections use deterministic string `_id`s ("{key}:{bucket}")
    // so every writer is an idempotent upsert — that, not a lease, is what
    // makes the 2-pod deployment race-free. Raw samples are short-TTL; the
    // rollup task compacts them into _1h (90 d) and _1d (730 d).

    // Relay-PoP samples, one per region per 30 s poll tick (both pods write
    // the same bucket id). `{region, ts}` backs the history queries.
    sets.push(set(
        "stats_relay",
        vec![
            index(bson::doc! { "region": 1, "ts": 1 }),
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // FR-20 — the cost ledger. One bucket per (tenant, meter, minute), with a
    // deterministic `_id` so both pods `$inc` the same document.
    //
    // ⚠ 7-day raw retention like its siblings: the durable record is the
    // rollup (`_1h` 90 d, `_1d` 730 d), and billing reads those. Raw minute
    // buckets exist to be compacted, not to be the ledger of record.
    sets.push(set(
        "stats_usage",
        vec![
            index(bson::doc! { "tenant_id": 1, "meter": 1, "ts": 1 }),
            // ⚠ No separate `{ts: 1}` index: the TTL index below already IS
            // one, and declaring both is an IndexOptionsConflict (same key
            // pattern, different options) as well as a wasted WiredTiger file
            // per test database. The siblings above deliberately don't either.
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // Per-agent minute buckets from the heartbeat handler (the agent's
    // owning pod is the single writer).
    sets.push(set(
        "stats_machine",
        vec![
            index(bson::doc! { "tenant_id": 1, "ts": 1 }),
            index(bson::doc! { "tenant_id": 1, "agent_id": 1, "ts": 1 }),
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // Wave 2 — platform user analytics. Neither collection stores an IP
    // or a raw User-Agent: the address is resolved to a country at
    // connect time and dropped, and page paths are normalised before
    // insert. 90-day retention, which is plenty for usage trends and
    // short enough that stale behavioural data doesn't accumulate.
    sets.push(set(
        "ws_sessions",
        vec![
            index(bson::doc! { "started_at": -1 }),
            index(bson::doc! { "tenant_id": 1, "started_at": -1 }),
            index(bson::doc! { "user_id": 1, "started_at": -1 }),
            // The close path updates by _id + open-ness; this keeps the
            // "still open" scan (and the orphan sweep) cheap.
            index(bson::doc! { "ended_at": 1 }),
            index_ttl(bson::doc! { "started_at": 1 }, 90 * 24 * 60 * 60),
        ],
    ));
    sets.push(set(
        "page_views",
        vec![
            index(bson::doc! { "ts": -1 }),
            index(bson::doc! { "tenant_id": 1, "ts": -1 }),
            index(bson::doc! { "path": 1, "ts": -1 }),
            index_ttl(bson::doc! { "ts": 1 }, 90 * 24 * 60 * 60),
        ],
    ));

    // Wave 2 — per-agent overlay mesh snapshots (one row per agent,
    // replaced each heartbeat). TTL reaps the rows of agents that stop
    // reporting, so a decommissioned device leaves the graph on its own.
    sets.push(set(
        "stats_mesh",
        vec![
            index(bson::doc! { "tenant_id": 1, "ts": -1 }),
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // Presence transition ledger (online|stale|offline), appended after the
    // `agents.last_presence` CAS — exactly-once across pods by construction.
    // Long TTL: transitions are rare and the 1-year uptime strips need them.
    sets.push(set(
        "stats_events",
        vec![
            index(bson::doc! { "tenant_id": 1, "agent_id": 1, "ts": 1 }),
            index_ttl(bson::doc! { "ts": 1 }, 730 * 24 * 60 * 60),
        ],
    ));

    // Per-conference-instance sample buckets from the mediasoup sampler
    // (owner pod of the room is the single writer).
    sets.push(set(
        "stats_call",
        vec![
            index(bson::doc! { "tenant_id": 1, "ts": 1 }),
            index(bson::doc! { "tenant_id": 1, "room_id": 1, "ts": 1 }),
            index(bson::doc! { "call_id": 1, "ts": 1 }),
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // Wave 3 — the same sampler's PER-PARTICIPANT rows, backing per-user
    // usage accounting. `user_id` leads its own index because the platform
    // view queries one user ACROSS orgs, where a tenant-first index can't
    // help.
    sets.push(set(
        "stats_call_user",
        vec![
            index(bson::doc! { "tenant_id": 1, "ts": 1 }),
            index(bson::doc! { "tenant_id": 1, "user_id": 1, "ts": 1 }),
            index(bson::doc! { "user_id": 1, "ts": 1 }),
            index_ttl(bson::doc! { "ts": 1 }, 7 * 24 * 60 * 60),
        ],
    ));

    // Wave 3 — the per-user usage reads' (user, time) indexes on
    // `remote_sessions` and `tunnel_audit` are the `remote` (P6) and
    // `network` (P7a) modules' now.

    // ── Growth observability (FR-102) ─────────────────────────────────────
    // Core-level like `stats_*` (spec §3o): written by the host's growth
    // routes and jobs, read by every growth number.

    // P1c — the platform admin's explicit exclusion list: one row per
    // `(kind, id)`, so the same org cannot be listed twice with two reasons.
    // The implicit exclusions (platform admins and the orgs they own) have
    // no row — `roomler_core::growth::ExclusionSet` folds both in.
    sets.push(set(
        "growth_exclusions",
        vec![index_unique(bson::doc! { "kind": 1, "id": 1 })],
    ));

    // P1d — one digest per closed UTC day, `_id` the day: the unique `_id`
    // is the once-only claim (the insert decides which pod computes and
    // sends). Kept 25 months (spec §3l) from the day it was computed; a row
    // that never computed (a claim that died) has no `computed_at` and is
    // re-claimed by the job, not reaped.
    sets.push(set(
        "growth_digests",
        vec![index_ttl(
            bson::doc! { "computed_at": 1 },
            25 * 30 * 24 * 60 * 60,
        )],
    ));

    // P2 — one row per org per UTC day with any activity, `_id` =
    // `"{tenant}:{yyyy-mm-dd}"` (spec §3d). Read per org (the timeline, the
    // first/last value day) and per day range (the funnel, cohorts, WAO —
    // `day` is `YYYY-MM-DD`, which sorts as a date). Kept 25 months from the
    // day itself; it outlives the 90-day audit rows it was computed from.
    // `GrowthDao::purge_tenant` takes an org's rows with it, but no org
    // hard-delete path exists yet, so the TTL is what bounds it for now.
    sets.push(set(
        "growth_org_daily",
        vec![
            index(bson::doc! { "tenant_id": 1, "day": 1 }),
            index(bson::doc! { "day": 1 }),
            index_ttl(bson::doc! { "day_start": 1 }, 25 * 30 * 24 * 60 * 60),
        ],
    ));

    // P3 — the frozen daily totals: one row per `(source, metric, dims, day)`
    // with `_id` the four joined (the upsert's own key). The digest reads one
    // `(source, metric)` over a day range, which is this index. No TTL
    // (spec §3o: kept indefinitely — they carry no person).
    sets.push(set(
        "growth_daily",
        vec![index(bson::doc! { "source": 1, "metric": 1, "day": 1 })],
    ));

    // P6 — one pull-status row per `(source, UTC day)` a puller attempted,
    // `_id = "<source>:<day>"` (the upsert's own key): whether the day was
    // pulled, when, and what the newest attempt met. It is how a reader of
    // `growth_daily` tells "not pulled" (no row) or "failed" from a pulled
    // zero. Read per source over a day range. No TTL, like the rows it
    // describes.
    sets.push(set(
        "growth_pulls",
        vec![index(bson::doc! { "source": 1, "day": 1 })],
    ));

    // P8 — machine keys for the growth surface (D12): only a hash and a
    // display prefix, never the key. The hash is what a request is looked
    // up by, so it is unique (two keys colliding is a 2^-192 event, and the
    // index makes it a refused insert rather than an ambiguous lookup).
    sets.push(set(
        "growth_keys",
        vec![
            index_unique(bson::doc! { "hash": 1 }),
            index(bson::doc! { "kind": 1, "created_at": -1 }),
        ],
    ));

    // P8 — social reach as the promotion pipeline pushes it: a post is
    // `(platform, platform_id)` and a snapshot `(platform, platform_id,
    // snapshot)`. The unique pairs ARE the idempotency (AC18: a snapshot
    // pushed twice is stored once); the views read posts by publish time.
    // No TTL — aggregates about our own content, no person (spec §3p).
    sets.push(set(
        "growth_posts",
        vec![
            index_unique(bson::doc! { "platform": 1, "platform_id": 1 }),
            index(bson::doc! { "published_at": 1 }),
        ],
    ));
    sets.push(set(
        "growth_post_snapshots",
        vec![index_unique(
            bson::doc! { "platform": 1, "platform_id": 1, "snapshot": 1 },
        )],
    ));

    // P10 — the weekly roll-ups: one row per closed ISO week, `_id =
    // "YYYY-Www"`, the daily digest's claim and statuses in a collection of
    // their own, and the same 25-month TTL from the compute.
    sets.push(set(
        "growth_weekly",
        vec![index_ttl(
            bson::doc! { "computed_at": 1 },
            25 * 30 * 24 * 60 * 60,
        )],
    ));

    // P10 — alerts: at most ONE open row per `(rule, key)`. The partial
    // unique index is the fire's arbiter across pods (a second pod's insert
    // is a duplicate key, read back as "already open", never a second
    // alert); `$type: "null"` so only an explicit null — an open row —
    // takes part, and a cleared row never blocks the next fire. Kept 90
    // days from `fired_at` (spec §3o).
    sets.push(set(
        "growth_alerts",
        vec![
            index_unique_partial(
                bson::doc! { "rule": 1, "key": 1 },
                bson::doc! { "cleared_at": { "$type": "null" } },
            ),
            index_ttl(bson::doc! { "fired_at": 1 }, 90 * 24 * 60 * 60),
        ],
    ));

    // P9a — remote-desktop quality per UTC day, scope and agent version,
    // `_id = "{day}:{scope}:{version}"`, frozen nightly by the host: the one
    // place FR-22's time to first frame survives the 7-day `agent_logs`
    // TTL. Read per scope over a day range (the Quality view, the digest,
    // the weekly roll-up). No TTL — aggregates about the product, no org
    // and no person (spec §3o), like `growth_daily`.
    sets.push(set(
        "growth_quality_daily",
        vec![index(bson::doc! { "scope": 1, "day": 1 })],
    ));

    // Hourly rollups (90 d) and daily rollups (730 d). The rollup task
    // whole-bucket-replaces via $merge on _id, so these are also upserts.
    for (coll, ttl_days) in [
        ("stats_usage_1h", 90u64),
        ("stats_relay_1h", 90),
        ("stats_machine_1h", 90),
        ("stats_call_1h", 90),
        ("stats_call_user_1h", 90),
        ("stats_usage_1d", 730),
        ("stats_relay_1d", 730),
        ("stats_machine_1d", 730),
        ("stats_call_1d", 730),
        ("stats_call_user_1d", 730),
    ] {
        let mut idx = vec![index_ttl(bson::doc! { "ts": 1 }, ttl_days * 24 * 60 * 60)];
        if coll.starts_with("stats_relay") {
            idx.push(index(bson::doc! { "region": 1, "ts": 1 }));
        } else {
            idx.push(index(bson::doc! { "tenant_id": 1, "ts": 1 }));
        }
        // The rolled-up usage tiers are read per USER as well as per org
        // (the platform view asks "this user, across every org").
        if coll.starts_with("stats_call_user") {
            idx.push(index(bson::doc! { "user_id": 1, "ts": 1 }));
        }
        sets.push(set(coll, idx));
    }

    IndexPlan { multi_block, sets }
}

pub fn index(keys: bson::Document) -> IndexModel {
    IndexModel::builder().keys(keys).build()
}

pub fn index_unique(keys: bson::Document) -> IndexModel {
    IndexModel::builder()
        .keys(keys)
        .options(IndexOptions::builder().unique(true).build())
        .build()
}

pub fn index_ttl(keys: bson::Document, expire_after_secs: u64) -> IndexModel {
    IndexModel::builder()
        .keys(keys)
        .options(
            IndexOptions::builder()
                .expire_after(std::time::Duration::from_secs(expire_after_secs))
                .build(),
        )
        .build()
}

pub fn index_text(keys: bson::Document) -> IndexModel {
    IndexModel::builder().keys(keys).build()
}

pub fn index_unique_sparse(keys: bson::Document) -> IndexModel {
    IndexModel::builder()
        .keys(keys)
        .options(IndexOptions::builder().unique(true).sparse(true).build())
        .build()
}

/// Unique index scoped by a partial filter — uniqueness is enforced only for
/// documents matching `filter` (e.g. non-empty `name`, so pre-Phase-0 rows with
/// an empty name don't collide).
pub fn index_unique_partial(keys: bson::Document, filter: bson::Document) -> IndexModel {
    IndexModel::builder()
        .keys(keys)
        .options(
            IndexOptions::builder()
                .unique(true)
                .partial_filter_expression(filter)
                .build(),
        )
        .build()
}

async fn create_indexes(
    db: &Database,
    collection: &str,
    indexes: Vec<IndexModel>,
) -> Result<(), mongodb::error::Error> {
    let coll = db.collection::<bson::Document>(collection);
    match coll.create_indexes(indexes.clone()).await {
        Ok(_) => {
            info!(collection, "Indexes created");
            Ok(())
        }
        Err(e) => {
            // IndexOptionsConflict (85) or IndexKeySpecsConflict (86): an existing
            // index has the same name but different options (e.g. adding TTL to an
            // existing index). Drop all indexes and recreate.
            if let mongodb::error::ErrorKind::Command(ref cmd_err) = *e.kind
                && (cmd_err.code == 85 || cmd_err.code == 86)
            {
                tracing::warn!(
                    collection,
                    "Index conflict detected, dropping conflicting indexes and retrying"
                );
                // Drop all non-_id indexes and recreate
                coll.drop_indexes().await?;
                coll.create_indexes(indexes).await?;
                info!(collection, "Indexes recreated after conflict resolution");
                return Ok(());
            }
            Err(e)
        }
    }
}
