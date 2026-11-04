// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 — the growth collections that are core-level (spec §3o): written
//! by the host's growth jobs and routes, read by every growth number.
//!
//! * [`GROWTH_EXCLUSIONS`] — the platform admin's explicit exclusion list
//!   (P1c): `{kind: tenant|user, id, reason, by, at}`, unique on
//!   `(kind, id)`. The implicit exclusions (every platform admin and the
//!   orgs they own) need no row; `meshharbor_core::growth::ExclusionSet` folds
//!   both into one set.
//! * [`GROWTH_ORG_DAILY`] — one row per org per UTC day with any activity
//!   (P2, spec §3d): `_id = "{tenant}:{yyyy-mm-dd}"`, the counters and the
//!   `value` flag. Written whole by the host's nightly job
//!   (`crates/api/src/growth/org_daily.rs`), read by the funnel, the
//!   cohorts and the org views. It exists because four of its sources
//!   expire at 90 days and retention needs a year: a row here outlives
//!   the audit rows it was computed from. Bounded by a 25-month TTL;
//!   [`GrowthDao::purge_tenant`] is the one call an org deletion must make
//!   to take an org's rows with it, though no org hard-delete path exists
//!   yet (orgs are only archived, reversibly), so until one does the TTL
//!   is what bounds the collection.
//!
//! * [`GROWTH_DAILY`] — the frozen daily totals (P3 onward): one row per
//!   `(source, metric, dims, day)`, `_id` the four joined, `value` the
//!   count. Written by whichever module owns the fact
//!   ([`GrowthDao::bump_daily`] — fleet's fetch counters; and since P6
//!   [`GrowthDao::replace_daily`] — the `saas` module's purestat puller),
//!   read by the digest. A row carries dimensions and a number, never a
//!   person, a User-Agent or an address.
//! * [`GROWTH_PULLS`] (P6) — one row per `(source, UTC day)` a puller
//!   attempted: whether the day was pulled, when, and the last error. It is
//!   what lets a reader of `growth_daily` tell a day that was **not pulled**
//!   (no row), or whose pull **failed**, from a pulled day with no rows — a
//!   zero (spec principle 4: null ≠ 0).
//!
//! Stateless over `core.db`, so a caller re-creates it (`GrowthDao::new`)
//! rather than threading a handle through `Core` (FR-69 rule 5).

use std::collections::{BTreeMap, HashMap};

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};

use super::base::DaoResult;

pub const GROWTH_EXCLUSIONS: &str = "growth_exclusions";
pub const GROWTH_ORG_DAILY: &str = "growth_org_daily";
/// The frozen daily totals (spec §3o): written by P3's install trace and
/// read by the digest; a tenant purge also takes an org's `dims.tenant`
/// rows from here.
pub const GROWTH_DAILY: &str = "growth_daily";

/// P3 — the install trace's `(source, metric)`: written by the `fleet`
/// module's fetch counters, read by the host's digest. Named here, in the
/// crate both can see, because `fleet` is an optional dependency of the host
/// and the digest must read the rows whether or not that module is compiled.
pub const INSTALL_SOURCE: &str = "install";
pub const INSTALL_FETCH_METRIC: &str = "fetch";
/// P3c — the `client` dimension of a fetch from one of the operator's
/// internal networks (`growth.internal_networks`), counted here INSTEAD of
/// under its client class: the digest leaves these rows out of the fetch
/// table and reports their sum on its own line.
pub const INSTALL_INTERNAL_CLIENT: &str = "internal";
/// P3b — the wizard's opt-in diagnostics frozen per day: `dims {step,
/// outcome, os}`, the value the number of DISTINCT runs that ended `step`
/// with `outcome` on `os` that day (a retry re-passing a step is one run).
/// Written by the host's nightly freeze from `setup_diagnostics`, whose rows
/// expire at 90 days; these do not.
pub const INSTALL_WIZARD_STEP_METRIC: &str = "wizard_step";

/// P4 — a plan-limit collision (`meshharbor_core::quota`), counted per UTC day
/// with `dims {tenant, limit}` beside the FR-32 warn line: the upgrade-intent
/// signal. Named here, below its writers (every module that gates a limit)
/// and its readers (the host's revenue view and digest).
pub const QUOTA_SOURCE: &str = "quota";
pub const QUOTA_COLLISION_METRIC: &str = "collision";
/// P4 — the monthly billed-revenue totals frozen from `billing_events`
/// (`meshharbor_services::billing::freeze_month`): one row per metric per
/// currency, `day` the month's first day, `dims {currency, period: month}`.
/// No tenant: an org deleted later does not rewrite last year's MRR.
pub const BILLING_SOURCE: &str = "billing";
/// P4 — the `growth_pulls` source of the operator's Stripe backfill: one
/// `ok` row per day it ran (`rows` = invoices recorded), so a reader can tell
/// "billed since the webhook was wired" from "billed, history included".
pub const BILLING_BACKFILL_SOURCE: &str = "billing_backfill";

/// P6 — one pull-status row per `(source, day)` a puller attempted.
pub const GROWTH_PULLS: &str = "growth_pulls";
/// P6 — the purestat puller's `source`, in `growth_daily` and `growth_pulls`.
/// Named here, below both its writer (`saas`) and its readers (the host).
pub const PURESTAT_SOURCE: &str = "purestat";
/// P6 — a pulled day older than this many days is FROZEN: never pulled
/// again and never rewritten. Within it, every run re-pulls the day, so a
/// late event (a visit still open at midnight, a buffered batch) lands.
pub const PURESTAT_FREEZE_DAYS: i64 = 7;
/// P7 — the `saas` GitHub puller's public counters: one CUMULATIVE snapshot
/// per closed UTC day (`dims.by` `repo` · `release` · `flavour`), differenced
/// into daily deltas by the reader. A day with no `ok` pull has no snapshot,
/// and every delta across it is null — never split, never 0.
pub const GITHUB_SOURCE: &str = "github";
/// P7 — the repository's traffic, read with the optional token: views and
/// clones per day from GitHub's 14-day series (`by: traffic`), and the
/// referrers' 14-day ranking as read after a day closed (`by: referrer`).
pub const GITHUB_TRAFFIC_SOURCE: &str = "github_traffic";
/// P7 — Google Search Console, per FINAL day (a Pacific-time day, as
/// Google dates it): `dims.by` `site` · `page` · `query` · `page_query`,
/// metrics `clicks`, `impressions` and `position_x100` (the position
/// weighted by impressions, ×100 — averaged over any set of rows as
/// `Σ position_x100 / Σ impressions / 100`).
pub const SEARCH_CONSOLE_SOURCE: &str = "search_console";
/// P7 — Bing Webmaster's daily site totals (`by: site`, `clicks`
/// `impressions`), and the source of its cycle's `growth_pulls` row.
pub const BING_SOURCE: &str = "bing";
/// P7 — Bing's weekly buckets per query and per page, at Bing's own grain,
/// stored under the bucket's date.
pub const BING_WEEKLY_SOURCE: &str = "bing_weekly";
/// P7 — the blog feed's read (`saas::content_pull`): one `growth_pulls` row
/// per UTC day; the posts themselves live in `growth_content`.
pub const CONTENT_SOURCE: &str = "content";
/// P7 — a day's URL Inspection of the blog's posts (`saas::content_pull`):
/// one `growth_pulls` row per UTC day.
pub const URL_INSPECTION_SOURCE: &str = "url_inspection";

/// The most org-days one read loads — far above this deployment's volume
/// (every org active every day for 25 months is ~10 rows a day); a bound,
/// not a page.
pub const MAX_ORG_DAY_ROWS: i64 = 500_000;

/// One `growth_daily` row as stored. `dims` is a flat map of short
/// strings; `day` is the UTC day `YYYY-MM-DD`, a string so a range read is a
/// plain string comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrowthDaily {
    #[serde(rename = "_id")]
    pub id: String,
    pub day: String,
    pub source: String,
    pub metric: String,
    #[serde(default)]
    pub dims: BTreeMap<String, String>,
    #[serde(default)]
    pub value: i64,
}

/// The `_id` of a daily row: `<source>:<metric>:<k=v,k=v>:<day>`, the
/// dimensions in key order so two writers of the same fact share one row.
///
/// P3's dimension values are short enum spellings (a client class, an asset
/// name, an OS); P6's purestat rows carry campaign keys and paths, which are
/// client-chosen text. Every part is therefore escaped (`%`, `,`, `=` and
/// `:` percent-encoded), so no value can forge another row's id —
/// `campaign=a,content=b` and `campaign=a%2Ccontent%3Db` stay two rows. A
/// spelling without those four characters is unchanged, which keeps every
/// P3 id as it was.
pub fn daily_id(source: &str, metric: &str, dims: &BTreeMap<String, String>, day: &str) -> String {
    let dims: Vec<String> = dims
        .iter()
        .map(|(k, v)| format!("{}={}", id_part(k), id_part(v)))
        .collect();
    format!(
        "{}:{}:{}:{}",
        id_part(source),
        id_part(metric),
        dims.join(","),
        id_part(day)
    )
}

/// One part of a daily `_id`, with the separators percent-encoded.
fn id_part(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(['%', ',', '=', ':']) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            ',' => out.push_str("%2C"),
            '=' => out.push_str("%3D"),
            ':' => out.push_str("%3A"),
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// A row for `(source, metric, dims, day)`, its `_id` derived.
pub fn daily_row(
    source: &str,
    metric: &str,
    dims: BTreeMap<String, String>,
    day: &str,
    value: i64,
) -> GrowthDaily {
    GrowthDaily {
        id: daily_id(source, metric, &dims, day),
        day: day.to_string(),
        source: source.to_string(),
        metric: metric.to_string(),
        dims,
        value,
    }
}

/// P6 — whether a `(source, day)` was pulled. `ok` once a pull of the day
/// succeeded (its rows ARE the day's rows); `failed` while none has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullStatus {
    Ok,
    Failed,
}

impl PullStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PullStatus::Ok => "ok",
            PullStatus::Failed => "failed",
        }
    }
}

/// P6 — one `growth_pulls` row: the state of one `(source, UTC day)`.
///
/// A later attempt that fails does NOT turn an `ok` day `failed`: the rows
/// of the last good pull are still the day's rows, so the status stays `ok`
/// and `error` carries what the newest attempt met.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrowthPull {
    /// `"<source>:<day>"`.
    #[serde(rename = "_id")]
    pub id: String,
    pub source: String,
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    pub status: PullStatus,
    /// The last pull that succeeded.
    #[serde(default)]
    pub pulled_at: Option<DateTime>,
    /// The newest attempt, successful or not.
    pub attempted_at: DateTime,
    #[serde(default)]
    pub attempts: u32,
    /// The `growth_daily` rows the last successful pull left for the day.
    #[serde(default)]
    pub rows: u32,
    /// What the newest attempt met; `None` when it succeeded.
    #[serde(default)]
    pub error: Option<String>,
    /// A goal the source did not define at the last successful pull — its
    /// conversions are not measured for the day (the rest is).
    #[serde(default)]
    pub missing_goal: Option<String>,
    /// The last successful pull hit the client's page bound: the day holds
    /// the busiest rows only.
    #[serde(default)]
    pub truncated: bool,
}

impl GrowthPull {
    pub fn id_of(source: &str, day: &str) -> String {
        format!("{source}:{day}")
    }
}

/// What a successful pull of one day left, for [`GrowthDao::record_pull_ok`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PulledDay<'a> {
    pub rows: u32,
    pub missing_goal: Option<&'a str>,
    pub truncated: bool,
}

/// What [`GrowthDao::replace_daily`] did to one day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ReplaceCounts {
    /// Rows written (new, or a changed value).
    pub written: u64,
    /// Rows already holding the pulled value.
    pub unchanged: u64,
    /// Rows of the day's metrics the pull no longer carries.
    pub pruned: u64,
}

/// One org's activity on one UTC day (spec §3d). Every counter is what
/// happened THAT day: sessions and calls are counted on the day they
/// started, minutes are each session's overlap with the day (a session
/// spanning midnight is split), and `value` says whether any of the four
/// value events happened — a remote-desktop session that reached Active
/// and lasted ≥ 30 s, a call with ≥ 2 participants, a tunnel flow, an SSH
/// session — with `value_kinds` naming which.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrgDay {
    /// `"{tenant hex}:{YYYY-MM-DD}"` — the idempotent upsert key.
    #[serde(rename = "_id")]
    pub id: String,
    pub tenant_id: ObjectId,
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    /// The day's 00:00 UTC: the TTL anchor and the range key.
    pub day_start: DateTime,
    /// Remote-desktop sessions that reached Active and started that day.
    pub rc_sessions: i64,
    /// Minutes of remote-desktop sessions overlapping the day, to 0.1.
    pub rc_session_minutes: f64,
    /// Distinct controllers of the sessions that started that day.
    pub rc_controllers: i64,
    /// Calls that started that day.
    pub calls: i64,
    /// Participant-minutes of the calls that started that day.
    pub call_participant_minutes: f64,
    /// Tunnel flows accepted that day (`tunnel_audit.kind = tcp_accept`).
    pub tunnel_flows: i64,
    /// SSH grants issued that day (`ssh_audit` rows without `denied`).
    pub ssh_sessions: i64,
    /// Remote commands that ran that day (`exec_audit` rows without `denied`).
    pub exec_runs: i64,
    /// Distinct devices seen online that day (presence transitions, or a
    /// daily machine rollup with online minutes).
    pub devices_online: i64,
    /// Distinct members who opened a session or controlled a device that day.
    pub members_active: i64,
    /// A value event happened that day.
    pub value: bool,
    /// Which value events: `rc` · `call` · `tunnel` · `ssh`, sorted.
    #[serde(default)]
    pub value_kinds: Vec<String>,
    pub computed_at: DateTime,
}

impl OrgDay {
    /// The row id: `"{tenant hex}:{day}"`.
    pub fn id_of(tenant_id: &ObjectId, day: &str) -> String {
        format!("{}:{day}", tenant_id.to_hex())
    }
}

/// What a tenant purge removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PurgedCounts {
    pub org_days: u64,
    pub daily: u64,
    /// P4 — the org's `billing_events` rows (`meshharbor_core::growth::purge_tenant`
    /// takes them; this DAO does not know the `saas` collection).
    pub billing_events: u64,
}

/// What an exclusion row names. The stored spelling is the snake_case
/// variant; a wire value outside the two is a 400 at the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    Tenant,
    User,
}

impl ExclusionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ExclusionKind::Tenant => "tenant",
            ExclusionKind::User => "user",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "tenant" => Some(ExclusionKind::Tenant),
            "user" => Some(ExclusionKind::User),
            _ => None,
        }
    }
}

/// One explicit exclusion, as stored. `by` is the platform admin who wrote
/// the list (an id, never an address); `at` when.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrowthExclusion {
    pub kind: ExclusionKind,
    pub id: ObjectId,
    pub reason: String,
    pub by: ObjectId,
    pub at: DateTime,
}

pub struct GrowthDao {
    db: Database,
}

impl GrowthDao {
    pub fn new(db: &Database) -> Self {
        Self { db: db.clone() }
    }

    fn exclusions(&self) -> Collection<GrowthExclusion> {
        self.db.collection::<GrowthExclusion>(GROWTH_EXCLUSIONS)
    }

    /// Add `by` to the `(source, metric, dims, day)` counter, creating the
    /// row on first sight. One upsert, atomic per row, so N pods counting
    /// the same fact never lose an increment to each other.
    pub async fn bump_daily(
        &self,
        day: &str,
        source: &str,
        metric: &str,
        dims: &BTreeMap<String, String>,
        by: i64,
    ) -> DaoResult<()> {
        let id = daily_id(source, metric, dims, day);
        let dims_doc: Document = dims
            .iter()
            .map(|(k, v)| (k.clone(), bson::Bson::String(v.clone())))
            .collect();
        self.db
            .collection::<Document>(GROWTH_DAILY)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$inc": { "value": by },
                    "$setOnInsert": {
                        "day": day,
                        "source": source,
                        "metric": metric,
                        "dims": dims_doc,
                    },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    /// Every row of one `(source, metric)` with `from <= day <= to`
    /// (inclusive, `YYYY-MM-DD` strings).
    ///
    /// Lenient per row: a row that does not have this shape (a hand-written
    /// one, an older writer's) is skipped with a warning and costs its own
    /// count, never the whole digest — one bad row must not take the daily
    /// mail down.
    pub async fn read_daily(
        &self,
        source: &str,
        metric: &str,
        from: &str,
        to: &str,
    ) -> DaoResult<Vec<GrowthDaily>> {
        let docs: Vec<Document> = self
            .db
            .collection::<Document>(GROWTH_DAILY)
            .find(doc! {
                "source": source,
                "metric": metric,
                "day": { "$gte": from, "$lte": to },
            })
            .await?
            .try_collect()
            .await?;
        let mut rows = Vec::with_capacity(docs.len());
        for d in docs {
            match bson::from_document::<GrowthDaily>(d) {
                Ok(row) => rows.push(row),
                Err(e) => tracing::warn!(
                    source, metric, error = %e,
                    "growth_daily: skipping a row that does not have the daily shape"
                ),
            }
        }
        Ok(rows)
    }

    /// P6 — make one `(source, day)` hold exactly `rows` for the given
    /// `metrics`: a row whose value changed (or that is new) is written with
    /// `$set` — idempotent, unlike [`Self::bump_daily`]'s `$inc`, so a day
    /// pulled twice holds one copy of each fact — an unchanged row is left
    /// alone, and a row of those metrics the pull no longer carries is
    /// deleted. Write-then-prune, never delete-then-insert, so a reader
    /// never meets an empty day between the two. A metric outside `metrics`
    /// is not touched at all (a pull that could not measure goals keeps the
    /// goal rows an earlier pull measured).
    pub async fn replace_daily(
        &self,
        source: &str,
        day: &str,
        metrics: &[&str],
        rows: &[GrowthDaily],
    ) -> DaoResult<ReplaceCounts> {
        let coll = self.db.collection::<Document>(GROWTH_DAILY);
        let existing: Vec<Document> = coll
            .find(doc! { "source": source, "day": day, "metric": { "$in": metrics } })
            .projection(doc! { "value": 1 })
            .await?
            .try_collect()
            .await?;
        let had: HashMap<String, i64> = existing
            .iter()
            .filter_map(|d| {
                let id = d.get_str("_id").ok()?.to_string();
                let v = match d.get("value") {
                    Some(Bson::Int64(v)) => *v,
                    Some(Bson::Int32(v)) => i64::from(*v),
                    Some(Bson::Double(v)) => *v as i64,
                    _ => i64::MIN,
                };
                Some((id, v))
            })
            .collect();
        let mut counts = ReplaceCounts::default();
        let mut keep: Vec<&str> = Vec::with_capacity(rows.len());
        for row in rows {
            debug_assert!(
                row.source == source && row.day == day && metrics.contains(&row.metric.as_str()),
                "a row written under the wrong (source, day, metric)"
            );
            keep.push(&row.id);
            if had.get(&row.id) == Some(&row.value) {
                counts.unchanged += 1;
                continue;
            }
            let dims_doc: Document = row
                .dims
                .iter()
                .map(|(k, v)| (k.clone(), Bson::String(v.clone())))
                .collect();
            coll.update_one(
                doc! { "_id": &row.id },
                doc! { "$set": {
                    "day": &row.day,
                    "source": &row.source,
                    "metric": &row.metric,
                    "dims": dims_doc,
                    "value": row.value,
                } },
            )
            .upsert(true)
            .await?;
            counts.written += 1;
        }
        counts.pruned = coll
            .delete_many(doc! {
                "source": source,
                "day": day,
                "metric": { "$in": metrics },
                "_id": { "$nin": keep },
            })
            .await?
            .deleted_count;
        Ok(counts)
    }

    /// P6 — every row of a `(source, day)` range whose `dims.by` is `by`
    /// (`site`, `campaign`, `path`), any metric. Lenient per row, like
    /// [`Self::read_daily`].
    pub async fn read_daily_by(
        &self,
        source: &str,
        by: &str,
        from: &str,
        to: &str,
    ) -> DaoResult<Vec<GrowthDaily>> {
        let docs: Vec<Document> = self
            .db
            .collection::<Document>(GROWTH_DAILY)
            .find(doc! {
                "source": source,
                "day": { "$gte": from, "$lte": to },
                "dims.by": by,
            })
            .await?
            .try_collect()
            .await?;
        Ok(docs
            .into_iter()
            .filter_map(|d| bson::from_document::<GrowthDaily>(d).ok())
            .collect())
    }

    // ── growth_pulls (P6) ────────────────────────────────────────────────

    /// A pull of `(source, day)` succeeded and left `rows` rows: the day is
    /// `ok` from now on, whatever an earlier attempt met.
    pub async fn record_pull_ok(
        &self,
        source: &str,
        day: &str,
        pulled: PulledDay<'_>,
        now: DateTime,
    ) -> DaoResult<()> {
        let PulledDay {
            rows,
            missing_goal,
            truncated,
        } = pulled;
        self.db
            .collection::<Document>(GROWTH_PULLS)
            .update_one(
                doc! { "_id": GrowthPull::id_of(source, day) },
                doc! {
                    "$set": {
                        "source": source,
                        "day": day,
                        "status": PullStatus::Ok.as_str(),
                        "pulled_at": now,
                        "attempted_at": now,
                        "rows": i64::from(rows),
                        "error": Bson::Null,
                        "missing_goal": missing_goal.map(Bson::from).unwrap_or(Bson::Null),
                        "truncated": truncated,
                    },
                    "$inc": { "attempts": 1_i64 },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    /// An attempt at `(source, day)` failed with `error` (a short reason,
    /// never a credential). A day that was already pulled stays `ok` — its
    /// rows are the last good pull's — and only records the error; a day
    /// never pulled is `failed`. One pipeline update, so the "stays ok" is
    /// decided by the stored row itself, not by a read beforehand.
    pub async fn record_pull_failed(
        &self,
        source: &str,
        day: &str,
        error: &str,
        now: DateTime,
    ) -> DaoResult<()> {
        let error: String = error.chars().take(200).collect();
        self.db
            .collection::<Document>(GROWTH_PULLS)
            .update_one(
                doc! { "_id": GrowthPull::id_of(source, day) },
                vec![doc! { "$set": {
                    "source": source,
                    "day": day,
                    "status": { "$cond": [
                        { "$eq": ["$status", PullStatus::Ok.as_str()] },
                        PullStatus::Ok.as_str(),
                        PullStatus::Failed.as_str(),
                    ] },
                    "attempted_at": now,
                    "attempts": { "$add": [{ "$ifNull": ["$attempts", 0_i64] }, 1_i64] },
                    "rows": { "$ifNull": ["$rows", 0_i64] },
                    // `$literal`: inside a pipeline a string that starts
                    // with `$` would be read as a field path.
                    "error": { "$literal": error },
                } }],
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    /// The pull rows of `source` for `from <= day <= to`, oldest first.
    pub async fn pulls_between(
        &self,
        source: &str,
        from: &str,
        to: &str,
    ) -> DaoResult<Vec<GrowthPull>> {
        let docs: Vec<Document> = self
            .db
            .collection::<Document>(GROWTH_PULLS)
            .find(doc! { "source": source, "day": { "$gte": from, "$lte": to } })
            .sort(doc! { "day": 1 })
            .await?
            .try_collect()
            .await?;
        let mut out = Vec::with_capacity(docs.len());
        for d in docs {
            match bson::from_document::<GrowthPull>(d) {
                Ok(p) => out.push(p),
                Err(e) => {
                    tracing::warn!(source, error = %e, "growth_pulls: skipping an unreadable row")
                }
            }
        }
        Ok(out)
    }

    /// Every explicit row, tenants first, then by id — a stable order for
    /// the admin view and for a test that compares lists.
    pub async fn list_exclusions(&self) -> DaoResult<Vec<GrowthExclusion>> {
        let mut rows: Vec<GrowthExclusion> =
            self.exclusions().find(doc! {}).await?.try_collect().await?;
        rows.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
        Ok(rows)
    }

    /// Replace the explicit list wholesale. Not transactional — two admins
    /// saving at once end with one of their lists, which is what "replace"
    /// means — and the unique `(kind, id)` index refuses a duplicate the
    /// caller failed to fold.
    pub async fn replace_exclusions(&self, rows: &[GrowthExclusion]) -> DaoResult<()> {
        self.db
            .collection::<Document>(GROWTH_EXCLUSIONS)
            .delete_many(doc! {})
            .await?;
        if !rows.is_empty() {
            self.exclusions().insert_many(rows).await?;
        }
        Ok(())
    }

    // ── growth_org_daily (P2) ────────────────────────────────────────────

    fn org_days(&self) -> Collection<OrgDay> {
        self.db.collection::<OrgDay>(GROWTH_ORG_DAILY)
    }

    fn org_day_docs(&self) -> Collection<Document> {
        self.db.collection::<Document>(GROWTH_ORG_DAILY)
    }

    /// Write one day's rows: each row replaced on its `_id` (an upsert), then
    /// every row of that day whose org is NOT in `rows` deleted — an org
    /// whose activity vanished on a recompute (its sessions were removed)
    /// must not keep yesterday's row. Replace-then-prune rather than
    /// delete-then-insert, so a reader never meets an empty day between the
    /// two. Returns the rows written.
    pub async fn replace_day(&self, day: &str, rows: &[OrgDay]) -> DaoResult<u64> {
        let coll = self.org_days();
        let mut ids: Vec<String> = Vec::with_capacity(rows.len());
        for row in rows {
            debug_assert_eq!(row.day, day, "a row written under the wrong day");
            coll.replace_one(doc! { "_id": &row.id }, row)
                .upsert(true)
                .await?;
            ids.push(row.id.clone());
        }
        self.org_day_docs()
            .delete_many(doc! { "day": day, "_id": { "$nin": ids } })
            .await?;
        Ok(rows.len() as u64)
    }

    /// The rows of `[from_day, to_day]` (inclusive, `YYYY-MM-DD`), for the
    /// given orgs (every org when `None`) minus `excluded`; only the value
    /// days when `value_only`. Oldest first, bounded by
    /// [`MAX_ORG_DAY_ROWS`].
    pub async fn org_days_between(
        &self,
        tenants: Option<&[ObjectId]>,
        excluded: &[ObjectId],
        from_day: &str,
        to_day: &str,
        value_only: bool,
    ) -> DaoResult<Vec<OrgDay>> {
        let mut filter = doc! { "day": { "$gte": from_day, "$lte": to_day } };
        match tenants {
            Some(ids) => {
                filter.insert("tenant_id", doc! { "$in": ids, "$nin": excluded });
            }
            None => {
                filter.insert("tenant_id", doc! { "$nin": excluded });
            }
        }
        if value_only {
            filter.insert("value", true);
        }
        let rows: Vec<OrgDay> = self
            .org_days()
            .find(filter)
            .sort(doc! { "day": 1, "tenant_id": 1 })
            .limit(MAX_ORG_DAY_ROWS)
            .await?
            .try_collect()
            .await?;
        Ok(rows)
    }

    /// Each org's FIRST value day and the kinds of that day — the funnel's
    /// first-value step and the timeline's milestone.
    pub async fn first_value_days(
        &self,
        tenants: &[ObjectId],
    ) -> DaoResult<HashMap<ObjectId, (String, Vec<String>)>> {
        if tenants.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<Document> = self
            .org_day_docs()
            .aggregate(vec![
                doc! { "$match": { "tenant_id": { "$in": tenants }, "value": true } },
                doc! { "$sort": { "tenant_id": 1, "day": 1 } },
                doc! { "$group": {
                    "_id": "$tenant_id",
                    "day": { "$first": "$day" },
                    "kinds": { "$first": "$value_kinds" },
                } },
            ])
            .await?
            .try_collect()
            .await?;
        Ok(rows
            .iter()
            .filter_map(|d| {
                let tenant = d.get_object_id("_id").ok()?;
                let day = d.get_str("day").ok()?.to_string();
                let kinds = d
                    .get_array("kinds")
                    .map(|a| {
                        a.iter()
                            .filter_map(|k| k.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                Some((tenant, (day, kinds)))
            })
            .collect())
    }

    /// Each org's LAST value day, over every org not excluded.
    pub async fn last_value_days(
        &self,
        excluded: &[ObjectId],
    ) -> DaoResult<HashMap<ObjectId, String>> {
        let rows: Vec<Document> = self
            .org_day_docs()
            .aggregate(vec![
                doc! { "$match": { "tenant_id": { "$nin": excluded }, "value": true } },
                doc! { "$group": { "_id": "$tenant_id", "day": { "$max": "$day" } } },
            ])
            .await?
            .try_collect()
            .await?;
        Ok(rows
            .iter()
            .filter_map(|d| {
                Some((
                    d.get_object_id("_id").ok()?,
                    d.get_str("day").ok()?.to_string(),
                ))
            })
            .collect())
    }

    /// The first and last day with any row — the horizon the views can see.
    pub async fn day_bounds(&self) -> DaoResult<Option<(String, String)>> {
        let first = self
            .org_day_docs()
            .find_one(doc! {})
            .projection(doc! { "day": 1 })
            .sort(doc! { "day": 1 })
            .await?;
        let Some(first) = first else {
            return Ok(None);
        };
        let last = self
            .org_day_docs()
            .find_one(doc! {})
            .projection(doc! { "day": 1 })
            .sort(doc! { "day": -1 })
            .await?;
        let day = |d: &Document| d.get_str("day").map(str::to_string).ok();
        Ok(match (day(&first), last.as_ref().and_then(day)) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        })
    }

    /// Everything the growth collections hold about one org: its
    /// `growth_org_daily` rows, and the `growth_daily` rows whose `dims`
    /// carry the tenant (spec principle 7 — rows never outlive their
    /// owner). This is the one call an org deletion must make for growth;
    /// no org hard-delete path exists yet (orgs are only archived,
    /// reversibly), so for now it has no production caller and the 25-month
    /// TTL is what bounds `growth_org_daily`. Idempotent; a second call
    /// deletes nothing.
    pub async fn purge_tenant(&self, tenant_id: ObjectId) -> DaoResult<PurgedCounts> {
        let org_days = self
            .org_day_docs()
            .delete_many(doc! { "tenant_id": tenant_id })
            .await?
            .deleted_count;
        // The frozen totals key the tenant as its hex id (the dims are
        // strings); an ObjectId is accepted too so a writer that stores
        // the id itself is purged just the same.
        let daily = self
            .db
            .collection::<Document>(GROWTH_DAILY)
            .delete_many(doc! { "$or": [
                { "dims.tenant": tenant_id.to_hex() },
                { "dims.tenant": Bson::ObjectId(tenant_id) },
            ] })
            .await?
            .deleted_count;
        Ok(PurgedCounts {
            org_days,
            daily,
            billing_events: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored spelling is a persisted key and a wire value: renaming a
    /// variant would make every existing row unreadable.
    #[test]
    fn kind_spellings_are_locked() {
        assert_eq!(ExclusionKind::Tenant.as_str(), "tenant");
        assert_eq!(ExclusionKind::User.as_str(), "user");
        assert_eq!(ExclusionKind::parse("tenant"), Some(ExclusionKind::Tenant));
        assert_eq!(ExclusionKind::parse("user"), Some(ExclusionKind::User));
        assert_eq!(ExclusionKind::parse("org"), None);
        assert_eq!(ExclusionKind::parse("Tenant"), None);
        assert_eq!(
            serde_json::to_string(&ExclusionKind::Tenant).unwrap(),
            "\"tenant\""
        );
    }

    /// The row round-trips through BSON as a struct — the insert path
    /// serialises it, so a field added later travels without a hand-built
    /// `doc!{}` to forget it in.
    #[test]
    fn a_row_round_trips_through_bson() {
        let row = GrowthExclusion {
            kind: ExclusionKind::User,
            id: ObjectId::new(),
            reason: "test account".into(),
            by: ObjectId::new(),
            at: DateTime::now(),
        };
        let doc = bson::to_document(&row).unwrap();
        assert_eq!(doc.get_str("kind").unwrap(), "user");
        let back: GrowthExclusion = bson::from_document(doc).unwrap();
        assert_eq!(back.kind, row.kind);
        assert_eq!(back.id, row.id);
        assert_eq!(back.reason, row.reason);
    }

    /// The daily row's `_id` is the fact itself, dimensions in key order:
    /// two writers that disagree only on insertion order share one row.
    #[test]
    fn the_daily_id_is_canonical_over_dimension_order() {
        let mut a = BTreeMap::new();
        a.insert("os".to_string(), "windows".to_string());
        a.insert("asset".to_string(), "install.ps1".to_string());
        a.insert("client".to_string(), "script-ps1".to_string());
        let mut b = BTreeMap::new();
        b.insert("client".to_string(), "script-ps1".to_string());
        b.insert("asset".to_string(), "install.ps1".to_string());
        b.insert("os".to_string(), "windows".to_string());
        assert_eq!(
            daily_id("install", "fetch", &a, "2026-10-14"),
            "install:fetch:asset=install.ps1,client=script-ps1,os=windows:2026-10-14"
        );
        assert_eq!(
            daily_id("install", "fetch", &a, "2026-10-14"),
            daily_id("install", "fetch", &b, "2026-10-14")
        );
        assert_eq!(
            daily_id("x", "y", &BTreeMap::new(), "2026-01-01"),
            "x:y::2026-01-01"
        );
    }

    /// P6 — a client-chosen value cannot forge another row's id: the four
    /// separators are escaped, so two different dimension sets never share
    /// an `_id`; a value without them (every P3 spelling) is unchanged.
    #[test]
    fn a_daily_id_escapes_what_could_forge_another_rows_id() {
        let dims = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let a = dims(&[("campaign", "a"), ("content", "b")]);
        let forged = dims(&[("campaign", "a,content=b")]);
        assert_ne!(
            daily_id("purestat", "visitors", &a, "2026-10-13"),
            daily_id("purestat", "visitors", &forged, "2026-10-13")
        );
        assert_eq!(
            daily_id("purestat", "visitors", &forged, "2026-10-13"),
            "purestat:visitors:campaign=a%2Ccontent%3Db:2026-10-13"
        );
        assert_eq!(
            daily_id(
                "purestat",
                "visitors",
                &dims(&[("path", "/a:b%")]),
                "2026-10-13"
            ),
            "purestat:visitors:path=/a%3Ab%25:2026-10-13"
        );
        // P3's ids are what they were.
        let p3 = dims(&[
            ("asset", "installer-permachine"),
            ("client", "wizard"),
            ("os", "windows"),
        ]);
        assert_eq!(
            daily_id("install", "fetch", &p3, "2026-10-14"),
            "install:fetch:asset=installer-permachine,client=wizard,os=windows:2026-10-14"
        );
        let row = daily_row(
            "purestat",
            "goal.signup",
            dims(&[("by", "site")]),
            "2026-10-13",
            3,
        );
        assert_eq!(row.id, "purestat:goal.signup:by=site:2026-10-13");
        assert_eq!((row.value, row.day.as_str()), (3, "2026-10-13"));
    }

    /// P6 — a pull row round-trips, and one written by the failure path
    /// alone (no `pulled_at`, no `missing_goal`) still reads.
    #[test]
    fn a_pull_row_round_trips_and_a_failed_one_reads_without_its_optional_fields() {
        let row = GrowthPull {
            id: GrowthPull::id_of(PURESTAT_SOURCE, "2026-10-13"),
            source: PURESTAT_SOURCE.into(),
            day: "2026-10-13".into(),
            status: PullStatus::Ok,
            pulled_at: Some(DateTime::now()),
            attempted_at: DateTime::now(),
            attempts: 2,
            rows: 17,
            error: None,
            missing_goal: Some("signup".into()),
            truncated: false,
        };
        assert_eq!(row.id, "purestat:2026-10-13");
        let doc = bson::to_document(&row).unwrap();
        assert_eq!(doc.get_str("status").unwrap(), "ok");
        let back: GrowthPull = bson::from_document(doc).unwrap();
        assert_eq!(back, row);
        let failed: GrowthPull = bson::from_document(doc! {
            "_id": "purestat:2026-10-12", "source": "purestat", "day": "2026-10-12",
            "status": "failed", "attempted_at": DateTime::now(), "attempts": 1_i64,
            "rows": 0_i64, "error": "purestat unreachable: unauthorized (401)",
        })
        .unwrap();
        assert_eq!(failed.status, PullStatus::Failed);
        assert_eq!(failed.pulled_at, None);
        assert_eq!(failed.missing_goal, None);
        assert!(!failed.truncated);
        assert_eq!(failed.attempts, 1);
        assert_eq!(PullStatus::Failed.as_str(), "failed");
    }

    /// P2 — an org-day round-trips as a struct with the composite `_id`,
    /// and a row from before `value_kinds` existed still reads.
    #[test]
    fn an_org_day_round_trips_with_its_composite_id() {
        let tenant = ObjectId::new();
        let row = OrgDay {
            id: OrgDay::id_of(&tenant, "2026-10-01"),
            tenant_id: tenant,
            day: "2026-10-01".into(),
            day_start: DateTime::parse_rfc3339_str("2026-10-01T00:00:00Z").unwrap(),
            rc_sessions: 2,
            rc_session_minutes: 60.2,
            rc_controllers: 1,
            calls: 1,
            call_participant_minutes: 10.0,
            tunnel_flows: 3,
            ssh_sessions: 1,
            exec_runs: 0,
            devices_online: 2,
            members_active: 2,
            value: true,
            value_kinds: vec!["rc".into(), "tunnel".into()],
            computed_at: DateTime::now(),
        };
        assert_eq!(row.id, format!("{}:2026-10-01", tenant.to_hex()));
        let mut doc = bson::to_document(&row).unwrap();
        assert_eq!(doc.get_str("_id").unwrap(), row.id);
        let back: OrgDay = bson::from_document(doc.clone()).unwrap();
        assert_eq!(back, row);
        doc.remove("value_kinds");
        let older: OrgDay = bson::from_document(doc).unwrap();
        assert!(older.value_kinds.is_empty());
        assert!(older.value);
    }
}
