// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1c — `GET` / `PUT /api/admin/growth/exclusions`: the list of
//! orgs and people no growth number counts.
//!
//! The GET answers the whole set — the explicit rows AND the implicit ones
//! (every platform admin, every org an excluded user owns), each marked, so
//! the admin sees exactly what the numbers leave out. The PUT replaces the
//! explicit list; it cannot touch the implicit one, which is the allowlist's
//! and the ownership graph's to decide.
//!
//! Ids are hex strings on the wire and ObjectIds in the store; `by` is the
//! writing admin's id, never an address. A reason is required and bounded:
//! it ends up in an operator-facing table.

use axum::{Json, extract::State};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::growth::{ExclusionSet, IMPLICIT_OWNED_BY_EXCLUDED, IMPLICIT_PLATFORM_ADMIN};
use meshharbor_services::dao::growth::{ExclusionKind, GrowthDao, GrowthExclusion};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// The longest reason the list keeps.
pub const MAX_REASON_LEN: usize = 200;
/// The most explicit rows one list may hold — a ceiling, not a page size.
pub const MAX_EXCLUSIONS: usize = 1_000;

#[derive(Debug, Serialize, PartialEq)]
pub struct ExclusionRow {
    pub kind: &'static str,
    pub id: String,
    pub reason: String,
    /// `true` for a row no one wrote: a platform admin, or an org one owns.
    pub implicit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ExclusionCounts {
    pub users: usize,
    pub tenants: usize,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ExclusionsResponse {
    pub enabled: bool,
    pub exclusions: Vec<ExclusionRow>,
    pub counts: ExclusionCounts,
}

impl ExclusionsResponse {
    pub fn of(set: &ExclusionSet) -> Self {
        let mut rows: Vec<ExclusionRow> = Vec::new();
        for id in &set.implicit_users {
            rows.push(ExclusionRow {
                kind: ExclusionKind::User.as_str(),
                id: id.to_hex(),
                reason: IMPLICIT_PLATFORM_ADMIN.to_string(),
                implicit: true,
                by: None,
                at: None,
            });
        }
        for id in &set.implicit_tenants {
            rows.push(ExclusionRow {
                kind: ExclusionKind::Tenant.as_str(),
                id: id.to_hex(),
                reason: IMPLICIT_OWNED_BY_EXCLUDED.to_string(),
                implicit: true,
                by: None,
                at: None,
            });
        }
        for row in &set.explicit {
            rows.push(ExclusionRow {
                kind: row.kind.as_str(),
                id: row.id.to_hex(),
                reason: row.reason.clone(),
                implicit: false,
                by: Some(row.by.to_hex()),
                at: Some(row.at.try_to_rfc3339_string().unwrap_or_default()),
            });
        }
        let (users, tenants) = set.counts();
        Self {
            enabled: true,
            exclusions: rows,
            counts: ExclusionCounts { users, tenants },
        }
    }
}

/// `GET /api/admin/growth/exclusions`
pub async fn get_exclusions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ExclusionsResponse>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let set = ExclusionSet::load(&state.core).await?;
    Ok(Json(ExclusionsResponse::of(&set)))
}

#[derive(Debug, Deserialize)]
pub struct PutRow {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct PutBody {
    pub exclusions: Vec<PutRow>,
}

/// `PUT /api/admin/growth/exclusions` — replace the explicit list. Answers
/// the same shape as the GET, so a client renders what it saved.
pub async fn put_exclusions(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<PutBody>,
) -> Result<Json<ExclusionsResponse>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let rows = validate_rows(body.exclusions, auth.user_id, DateTime::now())?;
    GrowthDao::new(&state.db).replace_exclusions(&rows).await?;
    let set = ExclusionSet::load(&state.core).await?;
    Ok(Json(ExclusionsResponse::of(&set)))
}

/// The PUT's contract, pure so it is testable without a server: a known
/// kind, a 24-hex id, a non-empty reason of at most [`MAX_REASON_LEN`]
/// printable characters (trimmed), at most [`MAX_EXCLUSIONS`] rows, and
/// duplicates folded (the first reason wins) rather than refused — a client
/// that re-sends a row it already showed is not wrong.
pub fn validate_rows(
    rows: Vec<PutRow>,
    by: ObjectId,
    at: DateTime,
) -> Result<Vec<GrowthExclusion>, ApiError> {
    if rows.len() > MAX_EXCLUSIONS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_EXCLUSIONS} exclusions"
        )));
    }
    let mut out: Vec<GrowthExclusion> = Vec::with_capacity(rows.len());
    for (i, row) in rows.into_iter().enumerate() {
        let kind = ExclusionKind::parse(row.kind.trim()).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "exclusions[{i}].kind must be tenant or user, got {:?}",
                row.kind
            ))
        })?;
        let id = ObjectId::parse_str(row.id.trim()).map_err(|_| {
            ApiError::BadRequest(format!(
                "exclusions[{i}].id must be a 24-hex ObjectId, got {:?}",
                row.id
            ))
        })?;
        let reason = row.reason.trim();
        if reason.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "exclusions[{i}].reason is required"
            )));
        }
        if reason.chars().count() > MAX_REASON_LEN {
            return Err(ApiError::BadRequest(format!(
                "exclusions[{i}].reason is longer than {MAX_REASON_LEN} characters"
            )));
        }
        if reason.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(format!(
                "exclusions[{i}].reason must be printable text"
            )));
        }
        if out.iter().any(|r| r.kind == kind && r.id == id) {
            continue;
        }
        out.push(GrowthExclusion {
            kind,
            id,
            reason: reason.to_string(),
            by,
            at,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: &str, id: &str, reason: &str) -> PutRow {
        PutRow {
            kind: kind.into(),
            id: id.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn valid_rows_are_kept_trimmed_and_deduplicated() {
        let by = ObjectId::new();
        let a = ObjectId::new();
        let b = ObjectId::new();
        let rows = validate_rows(
            vec![
                row("tenant", &a.to_hex(), "  test org  "),
                row(" user ", &format!(" {} ", b.to_hex()), "field tester"),
                // The same org again, another reason: folded, first wins.
                row("tenant", &a.to_hex(), "duplicate"),
                // The same id as a USER is a different exclusion.
                row("user", &a.to_hex(), "same id, other kind"),
            ],
            by,
            DateTime::now(),
        )
        .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind, ExclusionKind::Tenant);
        assert_eq!(rows[0].id, a);
        assert_eq!(rows[0].reason, "test org");
        assert_eq!(rows[0].by, by);
        assert_eq!(rows[1].kind, ExclusionKind::User);
        assert_eq!(rows[1].id, b);
        assert_eq!(rows[2].kind, ExclusionKind::User);
        assert_eq!(rows[2].id, a);
        assert!(
            validate_rows(vec![], by, DateTime::now())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_bad_kind_id_or_reason_is_a_400_naming_the_row() {
        let by = ObjectId::new();
        let ok = ObjectId::new().to_hex();
        let bad: Vec<(PutRow, &str)> = vec![
            (row("org", &ok, "x"), "kind"),
            (row("tenant", "not-hex", "x"), "id"),
            (row("tenant", "", "x"), "id"),
            (row("tenant", &ok, "   "), "reason is required"),
            (
                row("tenant", &ok, &"r".repeat(MAX_REASON_LEN + 1)),
                "longer",
            ),
            (row("tenant", &ok, "line\nbreak"), "printable"),
        ];
        for (r, needle) in bad {
            let err = validate_rows(vec![r], by, DateTime::now()).unwrap_err();
            assert!(
                matches!(&err, ApiError::BadRequest(m) if m.contains("exclusions[0]") && m.contains(needle)),
                "{err}"
            );
        }
        // Exactly the ceiling is fine; non-ASCII printable text is fine.
        let exact = "é".repeat(MAX_REASON_LEN);
        assert!(validate_rows(vec![row("user", &ok, &exact)], by, DateTime::now()).is_ok());
        let too_many: Vec<PutRow> = (0..=MAX_EXCLUSIONS)
            .map(|_| row("user", &ObjectId::new().to_hex(), "x"))
            .collect();
        assert!(validate_rows(too_many, by, DateTime::now()).is_err());
    }

    #[test]
    fn the_response_marks_implicit_rows_and_carries_no_address() {
        let admin = ObjectId::new();
        let org = ObjectId::new();
        let explicit_org = ObjectId::new();
        let set = ExclusionSet {
            users: [admin].into_iter().collect(),
            tenants: [org, explicit_org].into_iter().collect(),
            explicit: vec![GrowthExclusion {
                kind: ExclusionKind::Tenant,
                id: explicit_org,
                reason: "test org".into(),
                by: admin,
                at: DateTime::now(),
            }],
            implicit_users: vec![admin],
            implicit_tenants: vec![org],
        };
        let r = ExclusionsResponse::of(&set);
        assert_eq!(
            r.counts,
            ExclusionCounts {
                users: 1,
                tenants: 2
            }
        );
        assert_eq!(r.exclusions.len(), 3);
        assert!(r.exclusions[0].implicit && r.exclusions[0].kind == "user");
        assert_eq!(r.exclusions[0].reason, IMPLICIT_PLATFORM_ADMIN);
        assert!(r.exclusions[1].implicit && r.exclusions[1].kind == "tenant");
        assert_eq!(r.exclusions[1].reason, IMPLICIT_OWNED_BY_EXCLUDED);
        assert!(!r.exclusions[2].implicit);
        assert_eq!(r.exclusions[2].by.as_deref(), Some(admin.to_hex().as_str()));
        assert!(r.exclusions[2].at.as_deref().unwrap().ends_with('Z'));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains('@'));
        assert!(!json.contains("$date"), "dates are strings: {json}");
    }
}
