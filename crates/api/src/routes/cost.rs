// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-20 P5 — what the metered resources cost, per org.
//!
//! Reads the `stats_usage*` ledger built in P1/P2/P4, prices it from
//! `config/relay-costs.toml`, and hands `/observability` the per-org cost and
//! margin inputs. It computes nothing it has not measured.
//!
//! # Three things this module refuses to fabricate
//!
//! 1. **A cost with no price.** Every unit cost is `Option`; unset yields
//!    `null`, which the UI renders as *not priced*. A defaulted 0.00 would
//!    read as "this org is free to serve" and imply 100 % margin.
//! 2. **A zero for an uncollected meter.** `turn_bytes` is written only by
//!    FR-115 P4b's collector (`relay_allowance.turn_attribution`, off by
//!    default), and only for the cluster's coturn until P4b-2 brings the PoPs
//!    in, so it reports `monitored: false` until both are. *No traffic* and
//!    *not measured* are different facts and must never share a cell.
//! 3. **A relayed fraction with no reporters.** An empty denominator yields
//!    `null`, not `0`, which would otherwise read as a flawless mesh.
//!
//! # `mrr_cents` is a list-price ESTIMATE, not billed revenue
//!
//! What a customer is actually charged lives in Stripe; `BillingInfo` stores
//! only ids and a status, no amount. So MRR here is
//! `Plan::price_monthly_cents` x seats, and it ignores discounts, annual
//! terms, trials and proration. `subscription_status` rides along precisely so
//! a reader can see that a `canceled` or `trialing` org's MRR is notional.
//! Margin inherits every one of those caveats.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{Bson, doc};
use std::collections::HashMap;

use super::stats::{
    RangeQuery, agg, disabled_payload, floor_dt, parse_tid, range_spec, require_platform_admin,
    require_tenant_stats, tier_coll,
};
use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};
use bson::oid::ObjectId;
use meshharbor_config::RelayCosts;
use meshharbor_db::models::tenant::Plan;
use meshharbor_services::relay_allowance;

/// Meters this deployment actually collects. A meter absent from this list is
/// reported `monitored: false` rather than `0` — see the module docs.
///
/// `turn_bytes` is deliberately NOT here: until FR-115 P4b's collector covers
/// every coturn (the cluster's and the PoPs'), a total would be partial.
const MONITORED: &[&str] = &["derp_bytes", "sfu_participant_seconds"];

/// Cost of `total` units of `meter`, or `None` when that meter has no price
/// configured. The conversion to a billable unit lives here so the ledger can
/// keep storing raw, additive counts.
fn cost_of(meter: &str, total: f64, c: &RelayCosts) -> Option<f64> {
    match meter {
        "derp_bytes" => c.derp_gb.map(|p| total / 1e9 * p),
        "turn_bytes" => c.turn_gb.map(|p| total / 1e9 * p),
        "sfu_participant_seconds" => c.sfu_participant_hour.map(|p| total / 3600.0 * p),
        _ => None,
    }
}

/// The list-price MRR ESTIMATE for one org: `Plan::price_monthly_cents` ×
/// seats. The one formula — the cost view and FR-102's digest both read
/// it, so neither can drift into "billed" by accident. It ignores
/// discounts, annual terms, trials and proration (see the module docs).
///
/// FR-115 — until then checkout billed ONE unit per org whatever its size,
/// so this × seats figure overstated every multi-member org; checkout now
/// bills one unit per seat and the two agree. An annual subscription costs
/// ten months for twelve, so for it this is an upper bound — the billed
/// figure (`growth::revenue`, from invoices) is the one that knows.
pub(crate) fn mrr_estimate_cents(plan: &Plan, seats: f64) -> f64 {
    f64::from(plan.price_monthly_cents()) * seats
}

fn f64_of(v: &serde_json::Value, k: &str) -> f64 {
    v.get(k).and_then(serde_json::Value::as_f64).unwrap_or(0.0)
}

fn str_of(v: &serde_json::Value, k: &str) -> String {
    v.get(k)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Per-tenant (hex id) meter totals over a window.
type UsagePerOrg = HashMap<String, HashMap<String, f64>>;

/// The ledger, summed per (tenant, meter) over `window` seconds: per org,
/// and per meter across the fleet.
async fn usage_per_org(
    state: &Core,
    window: i64,
    tier: super::stats::Tier,
) -> Result<(UsagePerOrg, HashMap<String, f64>), ApiError> {
    let usage = agg(
        state,
        &tier_coll("stats_usage", tier),
        vec![
            doc! { "$match": { "ts": { "$gte": floor_dt(window) } } },
            doc! { "$group": {
                "_id": { "t": "$tenant_id", "m": "$meter" },
                "total": { "$sum": "$value" },
            }},
            doc! { "$set": { "tenant_id": { "$toString": "$_id.t" }, "meter": "$_id.m" } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let mut per_org: UsagePerOrg = HashMap::new();
    let mut fleet: HashMap<String, f64> = HashMap::new();
    for u in &usage {
        let meter = str_of(u, "meter");
        let total = f64_of(u, "total");
        *per_org
            .entry(str_of(u, "tenant_id"))
            .or_default()
            .entry(meter.clone())
            .or_insert(0.0) += total;
        *fleet.entry(meter).or_insert(0.0) += total;
    }
    Ok((per_org, fleet))
}

/// One org's priced cost over the window: the sum over the MONITORED
/// meters that carry a price, `None` when none of them does (never a 0.00
/// that would read as "free to serve").
fn org_cost(mine: Option<&HashMap<String, f64>>, costs: &RelayCosts) -> Option<f64> {
    let mut total = 0.0;
    let mut any_priced = false;
    for m in MONITORED {
        let used = mine.and_then(|h| h.get(*m)).copied().unwrap_or(0.0);
        if let Some(c) = cost_of(m, used, costs) {
            total += c;
            any_priced = true;
        }
    }
    any_priced.then_some(total)
}

/// FR-102 P4 — each org's priced cost over `range` (`24h|7d|30d|1y`), for
/// the revenue view's margin: the same ledger and the same prices as
/// [`admin_cost`], so the two cannot disagree on what an org cost.
pub(crate) struct OrgCosts {
    /// `relay_costs.currency` — the unit the costs are in (major units).
    pub currency: Option<String>,
    /// Whether any monitored meter carries a price.
    pub priced: bool,
    /// Tenant (hex) → its priced cost; an org with no ledger rows is absent
    /// (`0.0` when priced — a monitored meter's zero is a measurement).
    pub per_org: HashMap<String, f64>,
}

impl OrgCosts {
    /// One org's cost: `None` when nothing is priced.
    pub fn of(&self, tenant_hex: &str) -> Option<f64> {
        self.priced
            .then(|| self.per_org.get(tenant_hex).copied().unwrap_or(0.0))
    }
}

pub(crate) async fn org_costs(state: &Core, range: &str) -> Result<OrgCosts, ApiError> {
    let (window, tier) = range_spec(Some(range))?;
    let costs = &state.settings.relay_costs;
    let (per_org, _) = usage_per_org(state, window, tier).await?;
    Ok(OrgCosts {
        currency: costs.currency.clone(),
        priced: costs.derp_gb.is_some() || costs.sfu_participant_hour.is_some(),
        per_org: per_org
            .iter()
            .filter_map(|(t, mine)| Some((t.clone(), org_cost(Some(mine), costs)?)))
            .collect(),
    })
}

/// `GET /api/admin/stats/cost?range=24h|7d|30d|1y` — per-org metered cost,
/// list-price MRR, and the fleet carrier mix.
pub async fn admin_cost(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let (window, tier) = range_spec(q.range.as_deref())?;
    let costs = &state.settings.relay_costs;

    // ── the ledger, summed per (tenant, meter) over the range ──────────────
    let (per_org, fleet) = usage_per_org(&state, window, tier).await?;

    let tenants = agg(
        &state,
        "tenants",
        vec![
            doc! { "$match": { "deleted_at": Bson::Null } },
            doc! { "$set": { "id": { "$toString": "$_id" } } },
            doc! { "$project": {
                "_id": 0, "id": 1, "name": 1, "slug": 1, "plan": 1,
                "subscription_status": "$billing.status",
            }},
            doc! { "$limit": 500 },
        ],
    )
    .await?;
    let members = agg(
        &state,
        "tenant_members",
        vec![
            doc! { "$group": { "_id": "$tenant_id", "seats": { "$sum": 1 } } },
            doc! { "$set": { "tenant_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;

    // ── assemble per org ──────────────────────────────────────────────────
    let mut seats: HashMap<String, f64> = HashMap::new();
    for m in &members {
        seats.insert(str_of(m, "tenant_id"), f64_of(m, "seats"));
    }

    let mut orgs: Vec<serde_json::Value> = Vec::new();
    for t in &tenants {
        let id = str_of(t, "id");
        let mine = per_org.get(&id);
        // An org with no ledger rows is included with explicit zeros: for a
        // MONITORED meter, zero is a measurement ("relayed nothing"), which is
        // exactly the fact an operator wants to see.
        let mut meters = serde_json::Map::new();
        for m in MONITORED {
            let total = mine.and_then(|h| h.get(*m)).copied().unwrap_or(0.0);
            meters.insert(
                (*m).to_string(),
                serde_json::json!({ "total": total, "cost": cost_of(m, total, costs) }),
            );
        }
        let plan: Plan =
            serde_json::from_value(t.get("plan").cloned().unwrap_or(serde_json::Value::Null))
                .unwrap_or(Plan::Free);
        let seats_n = seats.get(&id).copied().unwrap_or(0.0);
        let mrr_cents = mrr_estimate_cents(&plan, seats_n);
        // Cost is measured over `range` while MRR is monthly, so subtracting
        // them here would be wrong for every range but 30d. The margin is left
        // to the caller, which knows what it asked for — and `window_secs`
        // travels in the payload so it can normalise.
        orgs.push(serde_json::json!({
            "tenant_id": id,
            "name": t.get("name").cloned().unwrap_or(serde_json::Value::Null),
            "slug": t.get("slug").cloned().unwrap_or(serde_json::Value::Null),
            "plan": t.get("plan").cloned().unwrap_or(serde_json::Value::Null),
            "subscription_status": t.get("subscription_status").cloned()
                .unwrap_or(serde_json::Value::Null),
            "seats": seats_n,
            "mrr_cents": mrr_cents,
            "meters": meters,
            // `null`, not 0, when nothing this org used carries a price.
            "cost": org_cost(mine, costs),
        }));
    }

    // ── fleet carrier mix: the NAT-traversal alarm ────────────────────────
    //
    // Deliberately NOT a byte fraction. Direct bytes are measured nowhere —
    // that is the property the whole FR rests on — so a byte-level "relayed
    // fraction" is not computable, and inventing one would be exactly the
    // class of confident-looking wrong number this design exists to avoid.
    // This counts CONNECTIONS by carrier, which agents already report, and it
    // reads the raw tier over the last hour because it is a *now* signal.
    //
    // ⚠ Agent-reported, so it is a claim by the fleet, not a server
    // measurement. Good enough to raise an alarm; it must never price a bill.
    //
    // ⚠ It is also a SNAPSHOT of carriers, not a count of failures.
    // `overlay_derp_floor` is on by default and floors fresh pairs at birth,
    // so a pair that is merely young is indistinguishable from one that
    // could not go direct. Prod 2026-08-31 read 43.7%, with 3,800 of the
    // 3,917 relayed links on DERP. The UI therefore says "currently on a
    // relay" and points the reader at the trend, not the absolute.
    let mix = agg(
        &state,
        "stats_machine",
        vec![
            doc! { "$match": { "ts": { "$gte": floor_dt(3_600) } } },
            doc! { "$group": {
                "_id": Bson::Null,
                "direct": { "$sum": "$sys.transports.direct" },
                "relay":  { "$sum": "$sys.transports.relay" },
                "derp":   { "$sum": "$sys.transports.derp" },
            }},
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let carrier_mix = mix.first().map(|m| {
        let (d, r, p) = (f64_of(m, "direct"), f64_of(m, "relay"), f64_of(m, "derp"));
        let denom = d + r + p;
        serde_json::json!({
            "direct": d, "relay": r, "derp": p,
            // No reporters ⇒ `null`. A 0.0 here would read as a flawless mesh.
            "relayed_fraction": if denom > 0.0 { Some((r + p) / denom) } else { None },
            "basis": "connections",
            "window": "1h",
        })
    });

    let fleet_meters: serde_json::Map<String, serde_json::Value> = MONITORED
        .iter()
        .map(|m| {
            let total = fleet.get(*m).copied().unwrap_or(0.0);
            (
                (*m).to_string(),
                serde_json::json!({
                    "total": total,
                    "cost": cost_of(m, total, costs),
                    "monitored": true,
                }),
            )
        })
        // Everything the ledger CAN carry but this deployment does not
        // collect, reported honestly rather than omitted or zeroed.
        .chain(std::iter::once((
            "turn_bytes".to_string(),
            serde_json::json!({
                "total": serde_json::Value::Null,
                "cost": serde_json::Value::Null,
                "monitored": false,
                "why": "coturn 4.17.2 emits no user label, so relayed bytes \
                        cannot be attributed to a tenant (FR-20 P3)",
            }),
        )))
        .collect();

    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": q.range.unwrap_or_else(|| "24h".into()),
        "window_secs": window,
        "currency": costs.currency,
        "priced": costs.derp_gb.is_some() || costs.sfu_participant_hour.is_some(),
        "unit_costs": {
            "derp_gb": costs.derp_gb,
            "turn_gb": costs.turn_gb,
            "sfu_participant_hour": costs.sfu_participant_hour,
        },
        "meters": fleet_meters,
        "orgs": orgs,
        "carrier_mix": carrier_mix,
    })))
}

/// `GET /api/tenant/{tenant_id}/stats/resources?range=…` — an org's own
/// metered consumption.
///
/// # Deliberately reports UNITS, not money
///
/// The platform surface renders currency because the operator is reading their
/// own cost. This one does not, and the omission is the design:
///
/// * These are **our costs**, not the org's bill. Showing "your traffic cost
///   €0.03" invites a dispute about a number that appears on no invoice, and
///   there are no quotas yet for it to mean anything against.
/// * The point of this surface is **actionable**: a high relayed share means
///   *that org's network is blocking direct paths*, which their own IT can
///   fix. That is a networking finding, and pricing it obscures it.
///
/// When quotas land, the unit figures here are already the ones a quota would
/// be denominated in.
///
/// # Membership, and 404 on failure
///
/// `require_tenant_stats(.., need_manage = false)`: every member may see what
/// their own org consumed. Failures are 404 rather than 403 so a polled panel
/// degrades to empty instead of erroring on every tick.
///
/// ⚠️ Not, as this once said, "because the web client wipes tokens on 403" —
/// it does not any more (FR-82).
pub async fn tenant_resources(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, false).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let (window, tier) = range_spec(q.range.as_deref())?;

    let usage = agg(
        &state,
        &tier_coll("stats_usage", tier),
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$gte": floor_dt(window) } } },
            doc! { "$group": { "_id": "$meter", "total": { "$sum": "$value" } } },
            doc! { "$set": { "meter": "$_id" } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let mut totals: HashMap<String, f64> = HashMap::new();
    for u in &usage {
        totals.insert(str_of(u, "meter"), f64_of(u, "total"));
    }
    let meters: serde_json::Map<String, serde_json::Value> = MONITORED
        .iter()
        .map(|m| {
            (
                (*m).to_string(),
                // A monitored meter with no rows is a real measurement — this
                // org relayed nothing — so zero is the honest value here, in
                // contrast to `turn_bytes` below which nobody counted.
                serde_json::json!({
                    "total": totals.get(*m).copied().unwrap_or(0.0),
                    "monitored": true,
                }),
            )
        })
        .chain(std::iter::once((
            "turn_bytes".to_string(),
            serde_json::json!({ "total": serde_json::Value::Null, "monitored": false }),
        )))
        .collect();

    // Storage is a live sum of what the org is holding right now, not a
    // rate over the range — so it is deliberately not range-scoped, and the
    // payload names it `at` rather than folding it in with the meters.
    let storage = agg(
        &state,
        "files",
        vec![
            doc! { "$match": { "tenant_id": tid, "deleted_at": Bson::Null } },
            doc! { "$group": {
                "_id": Bson::Null,
                "bytes": { "$sum": "$size" },
                "files": { "$sum": 1 },
            }},
            doc! { "$unset": "_id" },
        ],
    )
    .await?;

    // This org's own carrier mix — the actionable half. Same caveats as the
    // platform view: CONNECTIONS not bytes (direct bytes are measured
    // nowhere), agent-reported, and `null` when nothing reported rather than
    // a 0 that would read as a perfect mesh.
    let mix = agg(
        &state,
        "stats_machine",
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$gte": floor_dt(3_600) } } },
            doc! { "$group": {
                "_id": Bson::Null,
                "direct": { "$sum": "$sys.transports.direct" },
                "relay":  { "$sum": "$sys.transports.relay" },
                "derp":   { "$sum": "$sys.transports.derp" },
            }},
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let carrier_mix = mix.first().map(|m| {
        let (d, r, p) = (f64_of(m, "direct"), f64_of(m, "relay"), f64_of(m, "derp"));
        let denom = d + r + p;
        serde_json::json!({
            "direct": d, "relay": r, "derp": p,
            "relayed_fraction": if denom > 0.0 { Some((r + p) / denom) } else { None },
            "basis": "connections",
            "window": "1h",
        })
    });

    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": q.range.unwrap_or_else(|| "24h".into()),
        "window_secs": window,
        "meters": meters,
        "storage": storage.first().cloned(),
        "carrier_mix": carrier_mix,
        // FR-115 P4a — the relay allowance, the first quota this slot holds.
        // `null` where plans are not sold, so the UI renders the slot dark
        // instead of pretending an unlimited plan is a satisfied one.
        "quota": relay_quota(&state, tid).await,
    })))
}

/// FR-115 P4a — the org's relay allowance this month, as the throttle reads
/// it (`meshharbor_services::relay_allowance`, the same functions): the bytes
/// relayed through DERP since the first of the month (UTC) against the
/// plan's allowance for its seats. In units, never money (FR-20).
///
/// `null` where plans are not sold (self-hosting has no allowance) and on
/// any error: the panel that polls this degrades, it never fails over it.
async fn relay_quota(state: &Core, tid: ObjectId) -> serde_json::Value {
    if !state.plans_sold {
        return serde_json::Value::Null;
    }
    let now = bson::DateTime::now();
    let (tenant, used) = match (
        state.tenants.base.find_by_id(tid).await,
        state.stats.relay_month_to_date(Some(tid), now).await,
    ) {
        (Ok(t), Ok(used)) => (t, used.get(&tid).copied().unwrap_or(0)),
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(%tid, %e, "relay quota: not computed");
            return serde_json::Value::Null;
        }
    };
    let s = &state.settings.relay_allowance;
    let seats = tenant.billed_seats();
    let allowance = relay_allowance::allowance_bytes(&tenant.plan, seats);
    let over = relay_allowance::rate_for(&tenant.plan, seats, used, s).is_some();
    let iso = |d: bson::DateTime| d.try_to_rfc3339_string().unwrap_or_default();
    serde_json::json!({
        "relay": {
            "month_start": iso(relay_allowance::month_start(now)),
            "resets_at": iso(relay_allowance::next_month_start(now)),
            "used_bytes": used,
            // `null` = the plan has no allowance (unlimited).
            "allowance_bytes": allowance,
            // The rate past the allowance; it is slowed, never cut off.
            "rate_kbps": allowance.map(|_| relay_allowance::rate_kbps(&tenant.plan, s)),
            // `relay_allowance.enabled`: the throttle is on for this
            // deployment. Off, the allowance is shown and not applied.
            "enforced": s.enabled,
            // Recomputed here; the throttle's own job runs every five
            // minutes, so the two agree within one job period.
            "throttled": s.enabled && over,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priced() -> RelayCosts {
        RelayCosts {
            currency: Some("EUR".into()),
            derp_gb: Some(0.010),
            turn_gb: Some(0.010),
            sfu_participant_hour: Some(0.0040),
        }
    }

    /// The whole point of `Option`: an unpriced meter must not become 0.00.
    /// A zero cost renders as "free to serve" and implies 100 % margin, which
    /// is a worse error than a visibly missing number.
    #[test]
    fn an_unpriced_meter_yields_none_not_zero() {
        let empty = RelayCosts::default();
        assert_eq!(cost_of("derp_bytes", 5e9, &empty), None);
        assert_eq!(cost_of("sfu_participant_seconds", 7200.0, &empty), None);
        // ...and with a price it is a real number, so the `None`s above are a
        // property of the config rather than of the function.
        assert!(cost_of("derp_bytes", 5e9, &priced()).is_some());
    }

    /// Guards the unit conversions, the easiest thing here to get wrong by a
    /// factor of 1000 (GB vs GiB) or 60 (minutes vs hours).
    #[test]
    fn units_convert_at_the_documented_scale() {
        // 5 GB at 0.010/GB = 0.05
        let c = cost_of("derp_bytes", 5e9, &priced()).unwrap();
        assert!((c - 0.05).abs() < 1e-9, "{c}");
        // 2 participant-hours at 0.0040/h = 0.008
        let c = cost_of("sfu_participant_seconds", 7200.0, &priced()).unwrap();
        assert!((c - 0.008).abs() < 1e-9, "{c}");
    }

    /// `turn_bytes` must never appear as monitored: it has a price and an enum
    /// variant but no writer, and reporting `0` would assert that coturn
    /// relayed nothing when the truth is that nobody counted.
    #[test]
    fn turn_bytes_is_not_a_monitored_meter() {
        assert!(!MONITORED.contains(&"turn_bytes"));
        assert!(MONITORED.contains(&"derp_bytes"));
        assert!(MONITORED.contains(&"sfu_participant_seconds"));
    }

    /// An unknown meter is unpriced rather than silently free — if a meter is
    /// added to the ledger and not to `cost_of`, the surface must say so.
    #[test]
    fn an_unknown_meter_is_never_priced() {
        assert_eq!(cost_of("something_new", 1e12, &priced()), None);
    }

    /// FR-102 P4 — an org's cost, as the margin reads it: `None` with no
    /// price (never a 0.00 that reads as "free to serve"), a measured 0.0
    /// for a priced org that used nothing, and the monitored meters summed.
    #[test]
    fn an_org_cost_is_none_unpriced_and_a_sum_when_priced() {
        let used: HashMap<String, f64> = HashMap::from([
            ("derp_bytes".to_string(), 5e9),
            ("sfu_participant_seconds".to_string(), 7200.0),
            // Not monitored: never priced into the org's cost.
            ("turn_bytes".to_string(), 9e12),
        ]);
        assert_eq!(org_cost(Some(&used), &RelayCosts::default()), None);
        let c = org_cost(Some(&used), &priced()).unwrap();
        assert!((c - 0.058).abs() < 1e-9, "{c}");
        assert_eq!(org_cost(None, &priced()), Some(0.0));

        let costs = OrgCosts {
            currency: Some("EUR".into()),
            priced: true,
            per_org: HashMap::from([("a".to_string(), 1.5)]),
        };
        assert_eq!(costs.of("a"), Some(1.5));
        assert_eq!(costs.of("b"), Some(0.0), "priced, no ledger rows: a zero");
        let unpriced = OrgCosts {
            priced: false,
            ..costs
        };
        assert_eq!(unpriced.of("a"), None);
    }
}
