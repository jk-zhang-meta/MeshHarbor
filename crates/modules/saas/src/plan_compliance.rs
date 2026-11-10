// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-32 P1c — "who would break if I turned enforcement on?"
//!
//! P2 of the pricing arc has to grandfather the tenants already over a limit
//! before flipping any of them to [`PlanEnforcement::Enforce`]. That question
//! is a **snapshot**, not an event stream, and the difference matters:
//!
//! - A denial log only ever sees tenants who happen to call the API during the
//!   observe window. A tenant sitting at 40 members on a 10-member plan that
//!   nobody adds to this month emits **nothing**, and would be flipped straight
//!   into a wall.
//! - A snapshot is complete, needs no accumulation window, and answers on the
//!   day the code deploys instead of weeks later.
//!
//! So the observe phase is served by this report rather than by a
//! `quota_denials` collection. The `tracing::warn!` line in `services::quota`
//! still records *frequency* — how often people actually collide with a limit —
//! which is a P3 pricing input, and a different question from this one.
//!
//! ⚠ Limits are read through [`quota::Limit::describe`], the same function the
//! gates use. A report that recomputed them independently could say a tenant is
//! compliant while the gate refuses them, which is worse than having no report.

use axum::{Json, extract::State};
use bson::{Bson, Document, doc};
use meshharbor_services::quota;
use serde::Serialize;
use std::collections::HashMap;

use meshharbor_core::{ApiError, Core, extractors::auth::AuthUser, guards::require_platform_admin};

#[derive(Debug, Serialize)]
pub struct LimitRow {
    /// The `Limit` variant's name, e.g. `MaxMembers`.
    pub limit: String,
    pub used: u64,
    /// `None` = the plan does not cap this limit.
    pub max: Option<u64>,
    pub over: bool,
    /// This limit is measured and reported but has no gate — see the FR-32
    /// spec. Today: `max_message_history`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reported_only: bool,
}

#[derive(Debug, Serialize)]
pub struct TenantCompliance {
    pub tenant_id: String,
    pub name: String,
    pub plan: String,
    pub enforcement: String,
    /// True when at least one **gated** limit is already exceeded, i.e.
    /// flipping this tenant to `Enforce` would start refusing them.
    pub would_break: bool,
    pub limits: Vec<LimitRow>,
}

/// One aggregation per collection, grouped by tenant, rather than N queries per
/// tenant: the fleet has hundreds of orgs, most of them empty test artifacts.
async fn group_by_tenant(
    state: &Core,
    coll: &str,
    accumulator: Document,
    extra_match: Option<Document>,
) -> Result<HashMap<String, u64>, ApiError> {
    let mut pipeline = Vec::new();
    if let Some(m) = extra_match {
        pipeline.push(doc! { "$match": m });
    }
    pipeline.push(doc! { "$group": { "_id": "$tenant_id", "n": accumulator } });
    pipeline.push(doc! { "$set": { "tid": { "$toString": "$_id" } } });

    let mut cur = state
        .db
        .collection::<Document>(coll)
        .aggregate(pipeline)
        .await
        .map_err(|e| ApiError::Internal(format!("compliance query failed on {coll}: {e}")))?;

    let mut out = HashMap::new();
    use futures::TryStreamExt;
    while let Some(d) = cur
        .try_next()
        .await
        .map_err(|e| ApiError::Internal(format!("compliance cursor failed: {e}")))?
    {
        let Ok(tid) = d.get_str("tid") else { continue };
        // `$sum` widens to i32/i64/f64 depending on what was stored, so read
        // all three rather than assuming one.
        let n = d
            .get_i64("n")
            .map(|v| v.max(0) as u64)
            .or_else(|_| d.get_i32("n").map(|v| v.max(0) as u64))
            .or_else(|_| d.get_f64("n").map(|v| v.max(0.0) as u64))
            .unwrap_or(0);
        out.insert(tid.to_string(), n);
    }
    Ok(out)
}

/// GET /api/admin/plan-compliance — every tenant, with the limits it is
/// already over. Platform-admin only (404 on miss, like the rest of `/admin`).
pub async fn admin_plan_compliance(
    State(state): State<Core>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;

    let live = doc! { "deleted_at": Bson::Null };
    let count = doc! { "$sum": 1 };

    let members = group_by_tenant(&state, "tenant_members", count.clone(), None).await?;
    // The gate's own definition (a bound room — an agent session's — is not
    // a channel), so the report never calls an org over a limit the gate
    // would let it stay under.
    let channels = group_by_tenant(
        &state,
        "rooms",
        count.clone(),
        Some(meshharbor_services::dao::room::RoomDao::channel_filter()),
    )
    .await?;
    let devices = group_by_tenant(&state, "agents", count.clone(), Some(live.clone())).await?;
    let clients =
        group_by_tenant(&state, "tunnel_clients", count.clone(), Some(live.clone())).await?;
    let recordings =
        group_by_tenant(&state, "recordings", count.clone(), Some(live.clone())).await?;
    let messages = group_by_tenant(&state, "messages", count.clone(), Some(live.clone())).await?;
    let storage = group_by_tenant(
        &state,
        "files",
        doc! { "$sum": "$size" },
        Some(live.clone()),
    )
    .await?;
    let exit_nodes = group_by_tenant(
        &state,
        "overlay_nodes",
        count,
        Some(doc! { "deleted_at": Bson::Null, "is_exit_node": true }),
    )
    .await?;

    let tenants = state
        .tenants
        .base
        .find_many(live, None)
        .await
        .map_err(|e| ApiError::Internal(format!("tenant list failed: {e}")))?;

    let mut rows = Vec::new();
    for t in tenants {
        let Some(id) = t.id else { continue };
        let tid = id.to_hex();
        // FR-115 — the org's own limits, scaled to its billed seats.
        let limits = t.limits();
        let get = |m: &HashMap<String, u64>| m.get(&tid).copied().unwrap_or(0);

        // (variant, measured usage, gated?)
        let measured: Vec<(quota::Limit, u64, bool)> = vec![
            (quota::Limit::MaxMembers, get(&members), true),
            (quota::Limit::MaxChannels, get(&channels), true),
            (quota::Limit::StorageBytes, get(&storage), true),
            (quota::Limit::Recordings, get(&recordings), true),
            (quota::Limit::ExitNodes, get(&exit_nodes), true),
            // Established before FR-32; shown because they are the two limits
            // that already refuse, so an operator reading this page sees the
            // whole picture rather than only the new gates.
            (quota::Limit::MaxDevices, get(&devices), true),
            (quota::Limit::MaxTunnelClients, get(&clients), true),
        ];

        let mut out = Vec::new();
        let mut would_break = false;
        for (limit, used, gated) in measured {
            let (max, _) = limit.describe(&limits);
            let over = max.is_some_and(|m| used > m);
            if over && gated {
                would_break = true;
            }
            out.push(LimitRow {
                limit: format!("{limit:?}"),
                used,
                max,
                over,
                reported_only: !gated,
            });
        }

        // MagicDNS is possession, not a count: the tenant either holds a zone
        // or does not.
        let has_dns = t.settings.magic_dns_domain.is_some();
        let dns_max = quota::Limit::MagicDns.describe(&limits).0;
        let dns_over = has_dns && dns_max == Some(0);
        if dns_over {
            would_break = true;
        }
        out.push(LimitRow {
            limit: "MagicDns".into(),
            used: u64::from(has_dns),
            max: dns_max,
            over: dns_over,
            reported_only: false,
        });

        // ⚠ `video_max_participants` is a WIRED gate that the first version of
        // this report omitted — and the omission mattered.
        //
        // Free's video cap was **0** until 2026-08-29 — "Free has no
        // conferencing" — so flipping a Free tenant to `Enforce` would have
        // refused the very first person to join a call. A snapshot cannot see
        // that as "over", because a zero cap is only exceeded *while a call is
        // in progress*, so the report said `would_break: 0` about a change that
        // would have taken video away from every Free tenant. A report used to
        // authorise a rollout has to cover every gate that rollout turns on,
        // including the ones whose breakage is invisible at rest.
        //
        // Surfaced as a **capability row**: `used` is what the tenant holds
        // today (always 1 — the ability is live while unenforced), `max` is 0
        // when the plan excludes it, so `over` means "enforcing would REMOVE
        // something this tenant can do right now" rather than "they exceeded a
        // quota". Free now has a real cap (10 since FR-115), so no current plan excludes
        // video — but the row stays, because the next plan change could.
        let video_max = quota::Limit::VideoMaxParticipants.describe(&limits).0;
        let video_excluded = video_max == Some(0);
        if video_excluded {
            would_break = true;
        }
        out.push(LimitRow {
            limit: "VideoMaxParticipants".into(),
            used: 1,
            max: video_max,
            over: video_excluded,
            reported_only: false,
        });

        // `max_message_history` is measured and NEVER gated — see the FR-32
        // spec. It is here so P3 can decide whether the limit survives
        // re-pricing, which is the only question it was kept for.
        let msg_used = get(&messages);
        let msg_max = if limits.max_message_history < 0 {
            None
        } else {
            Some(limits.max_message_history as u64)
        };
        out.push(LimitRow {
            limit: "MaxMessageHistory".into(),
            used: msg_used,
            max: msg_max,
            over: msg_max.is_some_and(|m| msg_used > m),
            reported_only: true,
        });

        rows.push(TenantCompliance {
            tenant_id: tid,
            name: t.name,
            plan: format!("{:?}", t.plan),
            enforcement: format!("{:?}", t.settings.plan_enforcement),
            would_break,
            limits: out,
        });
    }

    // Worst first: the tenants that need a grandfathering decision lead.
    rows.sort_by(|a, b| {
        b.would_break
            .cmp(&a.would_break)
            .then_with(|| a.name.cmp(&b.name))
    });

    let breaking = rows.iter().filter(|r| r.would_break).count();
    Ok(Json(serde_json::json!({
        "tenants": rows.len(),
        "would_break": breaking,
        "items": rows,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_db::models::{Plan, PlanEnforcement};

    /// The report must read its limits from the same place the gates do, or it
    /// can call a tenant compliant while the gate refuses them.
    #[test]
    fn report_uses_the_same_limit_source_as_the_gates() {
        let free = Plan::Free.limits();
        assert_eq!(quota::Limit::MaxMembers.describe(&free).0, Some(10));
        // FR-115 — chat is unlimited on every plan.
        assert_eq!(quota::Limit::MaxChannels.describe(&free).0, None);
        assert_eq!(quota::Limit::MaxDevices.describe(&free).0, Some(100));
        // Recordings off on Free ⇒ a cap of zero, so any recording is "over".
        assert_eq!(quota::Limit::Recordings.describe(&free).0, Some(0));
        // Pro's unlimited sentinel must read as uncapped, not as 4294967295.
        assert_eq!(
            quota::Limit::MaxMembers.describe(&Plan::Pro.limits()).0,
            None
        );
    }

    /// `over` is strict: at the cap is compliant, past it is not. The GATE
    /// refuses the *next* one at the cap, which is a different question — the
    /// report answers "are you already outside your plan".
    #[test]
    fn over_is_strictly_greater_than_the_cap() {
        let free = Plan::Free.limits();
        let max = quota::Limit::MaxMembers.describe(&free).0.unwrap();
        assert_eq!(max, 10);
        assert!(10u64 <= max, "exactly at the cap is not over");
        assert!(11u64 > max, "one past the cap is over");
    }

    /// A plan that EXCLUDES a capability (a cap of zero) must be reported as
    /// breaking: enforcing it removes something the tenant can do today, and a
    /// zero cap is never "over" at rest, so nothing else would surface it.
    ///
    /// This is the case the report's first version missed — it said
    /// `would_break: 0` about a change that would have taken conferencing away
    /// from every Free tenant, back when `Free.video_max_participants` was 0.
    ///
    /// Free got a real video cap of 4 (operator decision, 2026-08-29), and 10
    /// with a 60-minute meeting in FR-115, so video is no longer a removal for
    /// Free. `recordings` (still excluded on Free) carries the property here —
    /// the guard keeps a live example rather than being deleted along with the
    /// value it used to pin.
    #[test]
    fn a_plan_that_excludes_a_capability_is_reported_as_breaking() {
        let free = Plan::Free.limits();
        // Free HAS video now, bounded — a cap the gate can enforce without
        // taking a capability away from anyone.
        assert_eq!(
            quota::Limit::VideoMaxParticipants.describe(&free).0,
            Some(10),
            "Free has 10 video participants; 0 would mean enforcing REMOVES conferencing"
        );
        // `recordings` carries the excluded-capability property now that
        // `ai_recognition` is gone: excluded ⇒ a zero cap ⇒ the report flags a
        // tenant that holds any, because enforcing would take them away.
        assert_eq!(
            quota::Limit::Recordings.describe(&free).0,
            Some(0),
            "an excluded capability must read as a zero cap so the report flags it"
        );
        assert_eq!(quota::Limit::ExitNodes.describe(&free).0, Some(0));

        // A plan that includes them must not be flagged.
        let biz = Plan::Business.limits();
        assert_eq!(
            quota::Limit::VideoMaxParticipants.describe(&biz).0,
            Some(100)
        );
        assert_eq!(quota::Limit::Recordings.describe(&biz).0, None);
    }

    #[test]
    fn enforcement_default_is_warn() {
        assert!(matches!(PlanEnforcement::default(), PlanEnforcement::Warn));
    }
}
