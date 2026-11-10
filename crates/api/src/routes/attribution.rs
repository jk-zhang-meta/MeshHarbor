// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-88 P1a — `GET /api/admin/stats/attribution?since=&until=`: what the
//! promotion brought, as COUNTS.
//!
//! Sign-ups in a window, grouped by where they said they came from
//! (`source`, `medium`, `campaign`, `self_reported`), and how many of them
//! ACTIVATED — the person's org enrolled at least one device within
//! [`ACTIVATION_WINDOW_DAYS`] of the account's creation. Never a user list:
//! the projection the query reads has no name or address in it, and the
//! payload has no per-user row.
//!
//! A sign-up whose window has not closed yet and that has no device so far
//! is PENDING, not "not activated": it is reported separately (`pending`),
//! and `settled` (= `signups − pending`) is the denominator an activation
//! rate must use — a rate over all sign-ups would read yesterday's sign-ups
//! as failures. Activation is final: an activated sign-up inside its window
//! counts as activated, not pending.
//!
//! ⚠️ Every bucket `key` is client-chosen text — sanitised to at most 64
//! printable ASCII characters, but chosen by whoever built the link. An admin
//! UI renders it as TEXT, never as markup (`v-html`).
//!
//! It is the HOST's view, like the device listing: users are core, agents
//! are the `fleet` module's. Without `fleet` — not compiled, or switched off
//! — every `activated` is `null`, never `0`: "we cannot see devices" and "no
//! one enrolled one" are different answers and the dashboard must not
//! flatten them. Same gate as its siblings: 404 to anyone who is not a
//! platform admin.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_services::dao::user::{MAX_SIGNUP_ROWS, SignupRow};
use serde::{Deserialize, Serialize};

use crate::{
    error::ApiError,
    extractors::auth::AuthUser,
    routes::stats::{disabled_payload, require_platform_admin},
    state::AppState,
};

/// A sign-up counts as activated when its org enrolls a device within this
/// many days of the account's `created_at` (FR-88 §3c).
pub const ACTIVATION_WINDOW_DAYS: i64 = 7;
/// The default `since` when the query names none.
const DEFAULT_WINDOW_DAYS: i64 = 30;
/// Buckets kept per dimension, most sign-ups first. A campaign list longer
/// than this is a tagging problem, not a dashboard one.
const MAX_BUCKETS: usize = 100;

#[derive(Debug, Deserialize)]
pub struct AttributionQuery {
    /// Inclusive. RFC 3339 (`2026-09-01T00:00:00Z`), a date (`2026-09-01`,
    /// midnight UTC) or unix seconds. Default: 30 days before `until`.
    #[serde(default)]
    pub since: Option<String>,
    /// Exclusive. Same forms. Default: now.
    #[serde(default)]
    pub until: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Bucket {
    /// The value sign-ups were grouped on; `null` is the sign-ups that
    /// recorded nothing for this dimension. Client-chosen text: render as
    /// text.
    pub key: Option<String>,
    pub signups: u64,
    /// Sign-ups whose org enrolled a device within the window. `null` when
    /// the server cannot see devices (no `fleet`).
    pub activated: Option<u64>,
    /// Sign-ups with no device so far whose window has not closed. Not a
    /// failure: leave them out of any activation denominator. `null` with
    /// `activated`.
    pub pending: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct AttributionReport {
    pub enabled: bool,
    pub since: String,
    pub until: String,
    pub activation_window_days: i64,
    /// True when the window held more sign-ups than one query loads
    /// (`MAX_SIGNUP_ROWS`); the counts then cover the oldest rows only.
    pub truncated: bool,
    pub signups: u64,
    /// Sign-ups that recorded ANY attribution field.
    pub attributed: u64,
    /// See [`Bucket::activated`].
    pub activated: Option<u64>,
    /// See [`Bucket::pending`].
    pub pending: Option<u64>,
    /// `signups − pending`: the sign-ups whose outcome is known (activated,
    /// or the window closed without a device). The denominator for an
    /// activation rate — `activated / settled`, never `activated / signups`.
    /// `null` with `activated`.
    pub settled: Option<u64>,
    pub by_source: Vec<Bucket>,
    pub by_medium: Vec<Bucket>,
    pub by_campaign: Vec<Bucket>,
    pub by_self_reported: Vec<Bucket>,
}

/// GET /api/admin/stats/attribution?since=&until=
pub async fn admin_attribution(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<AttributionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let until = match q.until.as_deref() {
        Some(s) => parse_instant(s, "until")?,
        None => DateTime::now(),
    };
    let since = match q.since.as_deref() {
        Some(s) => parse_instant(s, "since")?,
        None => DateTime::from_millis(until.timestamp_millis() - DEFAULT_WINDOW_DAYS * 86_400_000),
    };
    if since >= until {
        return Err(ApiError::BadRequest("since must be before until".into()));
    }

    let rows = state.users.signups_between(since, until).await?;
    let truncated = rows.len() as i64 >= MAX_SIGNUP_ROWS;
    let user_ids: Vec<ObjectId> = rows.iter().map(|r| r.id).collect();
    let memberships = state.tenants.memberships_for_users(&user_ids).await?;
    let tenant_ids: Vec<ObjectId> = memberships
        .iter()
        .map(|(_, tid)| *tid)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let enrollments = fleet_enrollments(&state, &tenant_ids).await?;

    let report = tally(
        &rows,
        &memberships,
        enrollments.as_deref(),
        since,
        until,
        DateTime::now(),
        truncated,
    );
    Ok(Json(serde_json::to_value(report).map_err(|e| {
        ApiError::Internal(format!("attribution report did not serialise: {e}"))
    })?))
}

/// `(tenant_id, enrolled_at)` for every device in `tenant_ids` — the one
/// place this handler reaches past core. `Some` only when the server can
/// see devices: `modules.fleet` is `None` when the operator switched the
/// module off, and the whole field is absent when the build never linked it.
/// Both read as "cannot see", never as "none".
#[cfg(feature = "fleet")]
async fn fleet_enrollments(
    state: &AppState,
    tenant_ids: &[ObjectId],
) -> Result<Option<Vec<(ObjectId, DateTime)>>, ApiError> {
    match state.modules.fleet.as_ref() {
        Some(fleet) => Ok(Some(
            fleet.agents.enrollments_for_tenants(tenant_ids).await?,
        )),
        None => Ok(None),
    }
}

#[cfg(not(feature = "fleet"))]
async fn fleet_enrollments(
    _state: &AppState,
    _tenant_ids: &[ObjectId],
) -> Result<Option<Vec<(ObjectId, DateTime)>>, ApiError> {
    Ok(None)
}

/// RFC 3339, `YYYY-MM-DD` (midnight UTC) or unix seconds; anything else is
/// a 400 naming the parameter. Shared with the growth funnel (FR-102 P2),
/// whose window is the same three forms.
pub(crate) fn parse_instant(raw: &str, param: &str) -> Result<DateTime, ApiError> {
    let raw = raw.trim();
    let bad = || {
        ApiError::BadRequest(format!(
            "{param} must be RFC 3339, YYYY-MM-DD or unix seconds, got {raw:?}"
        ))
    };
    if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
        let secs: i64 = raw.parse().map_err(|_| bad())?;
        return secs
            .checked_mul(1000)
            .map(DateTime::from_millis)
            .ok_or_else(bad);
    }
    if raw.len() == 10 && raw.as_bytes()[4] == b'-' && raw.as_bytes()[7] == b'-' {
        return DateTime::parse_rfc3339_str(format!("{raw}T00:00:00Z")).map_err(|_| bad());
    }
    DateTime::parse_rfc3339_str(raw).map_err(|_| bad())
}

/// What one sign-up amounts to, once devices are visible.
#[derive(Clone, Copy, PartialEq)]
enum Fate {
    /// A device within the window. Final.
    Activated,
    /// No device yet, window still open at `now`.
    Pending,
    /// The window closed without a device.
    Cold,
}

/// The join and the counting, pure so it is testable without a database.
///
/// `enrollments` is `Some` only when the server can see devices; each entry
/// is `(tenant_id, enrolled_at)`. A sign-up is activated when any org it is
/// a member of enrolled a device in
/// `[created_at, created_at + ACTIVATION_WINDOW_DAYS]`. Devices enrolled
/// BEFORE the account existed do not count — joining an org that already had
/// a fleet is not this sign-up's activation. `now` decides whether a sign-up
/// without a device is still pending or cold.
pub(crate) fn tally(
    rows: &[SignupRow],
    memberships: &[(ObjectId, ObjectId)],
    enrollments: Option<&[(ObjectId, DateTime)]>,
    since: DateTime,
    until: DateTime,
    now: DateTime,
    truncated: bool,
) -> AttributionReport {
    let mut tenants_of: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for (uid, tid) in memberships {
        tenants_of.entry(*uid).or_default().push(*tid);
    }
    let enrolled_at: Option<HashMap<ObjectId, Vec<i64>>> = enrollments.map(|list| {
        let mut m: HashMap<ObjectId, Vec<i64>> = HashMap::new();
        for (tid, at) in list {
            m.entry(*tid).or_default().push(at.timestamp_millis());
        }
        m
    });
    let window_ms = ACTIVATION_WINDOW_DAYS * 86_400_000;
    let now_ms = now.timestamp_millis();

    let fate_of = |row: &SignupRow| -> Option<Fate> {
        let enrolled_at = enrolled_at.as_ref()?;
        let start = row.created_at.timestamp_millis();
        let end = start + window_ms;
        let hit = tenants_of
            .get(&row.id)
            .into_iter()
            .flatten()
            .filter_map(|tid| enrolled_at.get(tid))
            .flatten()
            .any(|at| (start..=end).contains(at));
        Some(if hit {
            Fate::Activated
        } else if now_ms <= end {
            Fate::Pending
        } else {
            Fate::Cold
        })
    };

    #[derive(Default)]
    struct Tallies {
        signups: u64,
        activated: u64,
        pending: u64,
    }
    impl Tallies {
        fn add(&mut self, fate: Option<Fate>) {
            self.signups += 1;
            match fate {
                Some(Fate::Activated) => self.activated += 1,
                Some(Fate::Pending) => self.pending += 1,
                Some(Fate::Cold) | None => {}
            }
        }
    }
    // BTreeMap so equal counts render in a stable order.
    let mut by: [BTreeMap<Option<String>, Tallies>; 4] = Default::default();
    let mut total = Tallies::default();
    let mut attributed = 0u64;

    for row in rows {
        let fate = fate_of(row);
        total.add(fate);
        let attr = row.signup_attribution.as_ref();
        if attr.is_some_and(|a| !a.is_empty()) {
            attributed += 1;
        }
        let keys = [
            attr.and_then(|a| a.source.clone()),
            attr.and_then(|a| a.medium.clone()),
            attr.and_then(|a| a.campaign.clone()),
            attr.and_then(|a| a.self_reported.clone()),
        ];
        for (dim, key) in keys.into_iter().enumerate() {
            by[dim].entry(key).or_default().add(fate);
        }
    }

    let can_see = enrolled_at.is_some();
    let render = |m: BTreeMap<Option<String>, Tallies>| -> Vec<Bucket> {
        let mut out: Vec<Bucket> = m
            .into_iter()
            .map(|(key, t)| Bucket {
                key,
                signups: t.signups,
                activated: can_see.then_some(t.activated),
                pending: can_see.then_some(t.pending),
            })
            .collect();
        out.sort_by(|a, b| b.signups.cmp(&a.signups).then_with(|| a.key.cmp(&b.key)));
        out.truncate(MAX_BUCKETS);
        out
    };
    let [source, medium, campaign, self_reported] = by;

    AttributionReport {
        enabled: true,
        since: since.try_to_rfc3339_string().unwrap_or_default(),
        until: until.try_to_rfc3339_string().unwrap_or_default(),
        activation_window_days: ACTIVATION_WINDOW_DAYS,
        truncated,
        signups: total.signups,
        attributed,
        activated: can_see.then_some(total.activated),
        pending: can_see.then_some(total.pending),
        settled: can_see.then_some(total.signups - total.pending),
        by_source: render(source),
        by_medium: render(medium),
        by_campaign: render(campaign),
        by_self_reported: render(self_reported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_db::models::SignupAttribution;

    const DAY: i64 = 86_400_000;

    fn row(
        id: ObjectId,
        created_ms: i64,
        source: Option<&str>,
        campaign: Option<&str>,
    ) -> SignupRow {
        SignupRow {
            id,
            created_at: DateTime::from_millis(created_ms),
            signup_attribution: source.or(campaign).map(|_| SignupAttribution {
                source: source.map(str::to_string),
                campaign: campaign.map(str::to_string),
                ..Default::default()
            }),
        }
    }

    fn bucket<'a>(buckets: &'a [Bucket], key: Option<&str>) -> &'a Bucket {
        buckets
            .iter()
            .find(|b| b.key.as_deref() == key)
            .unwrap_or_else(|| panic!("no bucket {key:?} in {buckets:?}"))
    }

    const T0: i64 = 1_700_000_000_000;

    /// `tally` with the window `[T0, T0 + 10 d)` and `now` far enough out
    /// that every sign-up's activation window has closed.
    fn settled_tally(
        rows: &[SignupRow],
        memberships: &[(ObjectId, ObjectId)],
        enrollments: Option<&[(ObjectId, DateTime)]>,
    ) -> AttributionReport {
        tally(
            rows,
            memberships,
            enrollments,
            DateTime::from_millis(T0),
            DateTime::from_millis(T0 + 10 * DAY),
            DateTime::from_millis(T0 + 30 * DAY),
            false,
        )
    }

    /// Three sign-ups, two orgs, one device enrolled in time, one too late,
    /// one before the account existed.
    #[test]
    fn activation_is_a_device_within_seven_days_of_the_account() {
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let (org_a, org_c) = (ObjectId::new(), ObjectId::new());
        let rows = vec![
            row(a, T0, Some("youtube"), Some("c1")),
            row(b, T0 + DAY, Some("youtube"), None),
            row(c, T0 + 2 * DAY, None, None),
        ];
        let memberships = vec![(a, org_a), (c, org_c)];
        let enrollments = vec![
            // a's org: one device on day 3 — inside the window.
            (org_a, DateTime::from_millis(T0 + 3 * DAY)),
            // c's org: a device from BEFORE c signed up, and one on day 8 —
            // neither counts.
            (org_c, DateTime::from_millis(T0)),
            (org_c, DateTime::from_millis(T0 + 2 * DAY + 8 * DAY)),
        ];
        let r = settled_tally(&rows, &memberships, Some(&enrollments));
        assert_eq!(r.signups, 3);
        assert_eq!(r.attributed, 2);
        assert_eq!(r.activated, Some(1));
        assert_eq!(r.pending, Some(0), "every window has closed");
        assert_eq!(r.settled, Some(3));
        let yt = bucket(&r.by_source, Some("youtube"));
        assert_eq!((yt.signups, yt.activated), (2, Some(1)));
        let none = bucket(&r.by_source, None);
        assert_eq!((none.signups, none.activated), (1, Some(0)));
        let c1 = bucket(&r.by_campaign, Some("c1"));
        assert_eq!((c1.signups, c1.activated), (1, Some(1)));
        assert_eq!(bucket(&r.by_campaign, None).signups, 2);
        // Most sign-ups first.
        assert_eq!(r.by_source[0].key.as_deref(), Some("youtube"));
        assert!(!r.truncated);
    }

    /// L2 of the P1a review: a sign-up whose window is still open and has no
    /// device is PENDING, not a failure, and stays out of `settled`. One that
    /// activated inside its open window is activated, not pending.
    #[test]
    fn an_open_window_without_a_device_is_pending_not_cold() {
        let (fresh, fresh_active, old) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let org = ObjectId::new();
        let now = T0 + 20 * DAY;
        let rows = vec![
            // Signed up yesterday, no device yet: pending.
            row(fresh, now - DAY, Some("youtube"), None),
            // Signed up yesterday, device today: activated, window still open.
            row(fresh_active, now - DAY, Some("youtube"), None),
            // Signed up three weeks ago, never a device: cold.
            row(old, T0, Some("tiktok"), None),
        ];
        let enrollments = vec![(org, DateTime::from_millis(now))];
        let r = tally(
            &rows,
            &[(fresh_active, org)],
            Some(&enrollments),
            DateTime::from_millis(T0),
            DateTime::from_millis(now),
            DateTime::from_millis(now),
            false,
        );
        assert_eq!(r.signups, 3);
        assert_eq!(r.activated, Some(1));
        assert_eq!(r.pending, Some(1));
        assert_eq!(r.settled, Some(2), "signups − pending");
        let yt = bucket(&r.by_source, Some("youtube"));
        assert_eq!(
            (yt.signups, yt.activated, yt.pending),
            (2, Some(1), Some(1))
        );
        let tt = bucket(&r.by_source, Some("tiktok"));
        assert_eq!(
            (tt.signups, tt.activated, tt.pending),
            (1, Some(0), Some(0))
        );

        // The pending edge: `now` exactly at the window's end is still open.
        let edge = vec![row(fresh, now - 7 * DAY, Some("x"), None)];
        let at_end = tally(
            &edge,
            &[],
            Some(&[]),
            DateTime::from_millis(T0),
            DateTime::from_millis(now),
            DateTime::from_millis(now),
            false,
        );
        assert_eq!(at_end.pending, Some(1));
        let past_end = tally(
            &edge,
            &[],
            Some(&[]),
            DateTime::from_millis(T0),
            DateTime::from_millis(now),
            DateTime::from_millis(now + 1),
            false,
        );
        assert_eq!(past_end.pending, Some(0));
        assert_eq!(past_end.settled, Some(1));
    }

    /// The boundary is inclusive at both ends of the window.
    #[test]
    fn the_window_edges_are_inclusive() {
        let a = ObjectId::new();
        let org = ObjectId::new();
        let rows = vec![row(a, T0, Some("x"), None)];
        let at_edge = vec![(org, DateTime::from_millis(T0 + 7 * DAY))];
        let r = settled_tally(&rows, &[(a, org)], Some(&at_edge));
        assert_eq!(r.activated, Some(1));
        let past_edge = vec![(org, DateTime::from_millis(T0 + 7 * DAY + 1))];
        let r = settled_tally(&rows, &[(a, org)], Some(&past_edge));
        assert_eq!(r.activated, Some(0));
    }

    /// Without `fleet` the answer is "cannot see", never "nobody did" — for
    /// `activated`, `pending` and `settled` alike.
    #[test]
    fn without_fleet_every_activated_is_null_never_zero() {
        let a = ObjectId::new();
        let rows = vec![row(a, T0, Some("tiktok"), None)];
        let r = settled_tally(&rows, &[], None);
        assert_eq!(r.signups, 1);
        assert_eq!((r.activated, r.pending, r.settled), (None, None, None));
        let tt = bucket(&r.by_source, Some("tiktok"));
        assert_eq!((tt.activated, tt.pending), (None, None));
        assert_eq!(bucket(&r.by_medium, None).activated, None);
        // ...and WITH fleet but no devices at all it is a real zero.
        let r = settled_tally(&rows, &[], Some(&[]));
        assert_eq!(
            (r.activated, r.pending, r.settled),
            (Some(0), Some(0), Some(1))
        );
        assert_eq!(bucket(&r.by_source, Some("tiktok")).activated, Some(0));
    }

    #[test]
    fn the_report_never_carries_a_user() {
        let a = ObjectId::new();
        let rows = vec![row(a, T0, Some("youtube"), Some("c1"))];
        let r = settled_tally(&rows, &[], Some(&[]));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&a.to_hex()), "a user id leaked: {json}");
        for key in ["email", "username", "user_id", "users"] {
            assert!(!json.contains(key), "{key} in {json}");
        }
    }

    #[test]
    fn instants_parse_in_three_forms_and_nothing_else() {
        assert_eq!(
            parse_instant("2026-09-01", "since")
                .unwrap()
                .timestamp_millis(),
            DateTime::parse_rfc3339_str("2026-09-01T00:00:00Z")
                .unwrap()
                .timestamp_millis()
        );
        assert_eq!(
            parse_instant(" 2026-09-01T12:30:00Z ", "since")
                .unwrap()
                .timestamp_millis(),
            DateTime::parse_rfc3339_str("2026-09-01T12:30:00Z")
                .unwrap()
                .timestamp_millis()
        );
        assert_eq!(
            parse_instant("1700000000", "since")
                .unwrap()
                .timestamp_millis(),
            1_700_000_000_000
        );
        for bad in [
            "",
            "yesterday",
            "2026-13-01",
            "2026-09-01T",
            "-5",
            "99999999999999999999",
        ] {
            let err = parse_instant(bad, "until").unwrap_err();
            assert!(
                matches!(err, ApiError::BadRequest(ref m) if m.contains("until")),
                "{bad:?}: {err}"
            );
        }
    }
}
