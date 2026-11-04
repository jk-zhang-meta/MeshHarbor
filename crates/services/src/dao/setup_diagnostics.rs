// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P3b — `setup_diagnostics`: one row per step boundary a wizard run
//! reported, **only when the person ticked the box** (spec §3e item 5, D4).
//! Owned by the `fleet` module (§3o), which carries its index set and the
//! one route that writes here; the host's digest and its nightly freeze
//! read it.
//!
//! A row is the validated wire record
//! ([`meshharbor_remote_control::setup_diagnostics::SetupDiagnostic`]) plus
//! the server's clock: `{run, step, outcome, elapsed_ms, error_code, os,
//! wizard_version, ts}`. Nothing about the request is kept — the handler
//! never sees an address or a User-Agent — and `run` is a random id the
//! wizard mints per launch, which joins the rows of one run to each other
//! and, through `agents.install.run`, to the device that run enrolled.
//!
//! Kept 90 days by the TTL on `ts` (spec §3p); the daily counts the host
//! freezes into `growth_daily` outlive the rows. A run can write at most
//! [`MAX_ROWS_PER_RUN`] rows, so a wizard stuck in a retry loop — or anyone
//! replaying a captured body — cannot grow the collection without bound.

use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_remote_control::setup_diagnostics::SetupDiagnostic;
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};

use super::base::DaoResult;

pub const SETUP_DIAGNOSTICS: &str = "setup_diagnostics";

/// How long a row is kept, from `ts` (spec §3p: 90 days).
pub const SETUP_DIAGNOSTICS_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// The most rows one `run` may hold. A run passes at most fourteen
/// boundaries; a retry re-passes the pipeline's, so a few attempts fit and
/// a loop does not. Counted before the insert, so with N pods racing the
/// true ceiling is `MAX_ROWS_PER_RUN + N − 1` — a bound, not an exact
/// quota, which is all it is for.
pub const MAX_ROWS_PER_RUN: u64 = 48;

/// The most rows one read returns (the digest's 28-day window). Far above
/// today's volume; a read that hits it is logged by the caller.
pub const MAX_READ_ROWS: i64 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetupDiagnosticRow {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub run: String,
    pub step: String,
    pub outcome: String,
    pub elapsed_ms: i64,
    /// `null` on a step that did not fail — present, so the shape is one.
    pub error_code: Option<String>,
    pub os: String,
    pub wizard_version: String,
    /// The server's clock at the write, never the wizard's.
    pub ts: DateTime,
}

/// What [`SetupDiagnosticsDao::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Stored,
    /// The run already holds [`MAX_ROWS_PER_RUN`] rows; nothing was written.
    RunCapped,
}

pub struct SetupDiagnosticsDao {
    collection: Collection<SetupDiagnosticRow>,
    raw: Collection<Document>,
}

impl SetupDiagnosticsDao {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection(SETUP_DIAGNOSTICS),
            raw: db.collection(SETUP_DIAGNOSTICS),
        }
    }

    /// Store one validated record under the server's clock, unless its run
    /// is already at the cap. The caller has run
    /// [`SetupDiagnostic::validate`]; this writes exactly the record's
    /// fields plus `ts`, nothing derived from the request.
    pub async fn record(&self, d: &SetupDiagnostic, ts: DateTime) -> DaoResult<Recorded> {
        if self.count_for_run(&d.run).await? >= MAX_ROWS_PER_RUN {
            return Ok(Recorded::RunCapped);
        }
        let row = SetupDiagnosticRow {
            id: ObjectId::new(),
            run: d.run.clone(),
            step: d.step.clone(),
            outcome: d.outcome.clone(),
            elapsed_ms: i64::try_from(d.elapsed_ms).unwrap_or(i64::MAX),
            error_code: d.error_code.clone(),
            os: d.os.clone(),
            wizard_version: d.wizard_version.clone(),
            ts,
        };
        self.collection.insert_one(&row).await?;
        Ok(Recorded::Stored)
    }

    /// Rows one run has written so far (the `run` index).
    pub async fn count_for_run(&self, run: &str) -> DaoResult<u64> {
        Ok(self
            .raw
            .count_documents(doc! { "run": run })
            .limit(MAX_ROWS_PER_RUN + 1)
            .await?)
    }

    /// Every row with `from <= ts < to`, oldest first, at most
    /// [`MAX_READ_ROWS`]. Lenient per row: one that does not have this shape
    /// is skipped with a warning and costs its own count, never the digest.
    pub async fn rows_between(
        &self,
        from: DateTime,
        to: DateTime,
    ) -> DaoResult<Vec<SetupDiagnosticRow>> {
        let docs: Vec<Document> = self
            .raw
            .find(doc! { "ts": { "$gte": from, "$lt": to } })
            .sort(doc! { "ts": 1 })
            .limit(MAX_READ_ROWS)
            .await?
            .try_collect()
            .await?;
        let mut rows = Vec::with_capacity(docs.len());
        for d in docs {
            match bson::from_document::<SetupDiagnosticRow>(d) {
                Ok(row) => rows.push(row),
                Err(e) => tracing::warn!(
                    error = %e,
                    "setup_diagnostics: skipping a row that does not have the diagnostic shape"
                ),
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored row is the wire record plus `ts` — eight fields under
    /// `_id`, `error_code` present as `null` — and nothing about a request.
    #[test]
    fn a_row_is_the_record_plus_the_clock_and_round_trips() {
        let row = SetupDiagnosticRow {
            id: ObjectId::new(),
            run: "a".repeat(32),
            step: "enroll".into(),
            outcome: "ok".into(),
            elapsed_ms: 812,
            error_code: None,
            os: "linux".into(),
            wizard_version: "0.4.138".into(),
            ts: DateTime::now(),
        };
        let doc = bson::to_document(&row).unwrap();
        let mut keys: Vec<&str> = doc.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "_id",
                "elapsed_ms",
                "error_code",
                "os",
                "outcome",
                "run",
                "step",
                "ts",
                "wizard_version"
            ]
        );
        assert_eq!(doc.get("error_code"), Some(&bson::Bson::Null));
        let back: SetupDiagnosticRow = bson::from_document(doc).unwrap();
        assert_eq!(back, row);
    }
}
