// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P5 — `GET /api/admin/growth/newsletter`: the list over time and
//! the per-issue table (spec §3h).
//!
//! * **The list over time** — new, confirmed, unsubscribed and suppressed
//!   per UTC day, by `source`, from timestamps `subscribers` already keeps,
//!   and the list's size now. A subscriber carries no account id, so the
//!   exclusion set cannot apply to the list (a platform admin's own address
//!   on it counts); a re-subscription restarts a row's history (the
//!   subscribe path re-stamps `created_at`), so a day's numbers are what the
//!   rows say today.
//! * **The per-issue table** — for each issue sent in the range:
//!   recipients and accepted from the send ledger; delivered, bounced,
//!   complaints from SendGrid's signed Event Webhook (`saas`,
//!   `newsletter_sends.delivery`); unsubscribed via the issue's own link
//!   (`subscribers.unsubscribed_via`); visits by the issue's campaign key
//!   from purestat, live, for the range; sign-ups whose attribution carries
//!   that key — the funnel's own read, exclusions applied.
//! * **Measured, not measured and zero are three cells.** Delivery is
//!   `not_measured` when this server does not verify the webhook, or the
//!   issue was sent before delivery events were recorded; visits when the
//!   issue's links carried no tags, or purestat cannot be asked. Never 0.
//! * **Nothing per reader.** Every number is a count over an issue; no
//!   address leaves this view (the ledger's `email` is never read here).
//!
//! The collections are the `saas` module's: without it mounted the whole
//! view is `not_measured: "saas module not mounted"`.

use std::collections::{BTreeMap, HashMap};

use axum::{
    Json,
    extract::{Query as AxumQuery, State},
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_core::{
    campaign::{CampaignKey, KeyDepth},
    growth::ExclusionSet,
};
use meshharbor_services::{
    dao::{
        growth_digest::ExcludedCounts,
        newsletter_send::{DeliveryCounts, NewsletterSendDao, stale_cutoff_at},
    },
    newsletter::{ISSUE_UTM_MEDIUM, ISSUE_UTM_SOURCE},
    purestat::{Filter, Query},
};
use serde::{Deserialize, Serialize};

use super::{
    campaigns::{GOALS, Rate, WEB_METRICS, WebCells, day_range_ms, web_by_key, web_client},
    digest::{
        DigestError, Measured, NotMeasured, SMALL_N, aggregate, day_str, dt_ms, find_docs, i64_of,
        parse_day, str_of, utc_date_of,
    },
    funnel, mounted,
    read_key::GrowthAuth,
};
use crate::{error::ApiError, state::AppState};

/// The default range: the 90 closed days ending yesterday (an issue is
/// never more than monthly).
pub const DEFAULT_RANGE_DAYS: i64 = 90;
/// The most issues one answer lists — newest first.
pub const MAX_ISSUES: i64 = 50;
const DAY_MS: i64 = 86_400_000;

/// Why an issue's delivery is not measured.
pub const WEBHOOK_OFF: &str = "the SendGrid Event Webhook is not verified on this server \
     (no usable MESHHARBOR__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY)";
pub const SENT_UNRECORDED: &str =
    "sent before delivery events were recorded (or while the webhook key was unset)";
pub const UNTAGGED: &str = "the issue's links carried no campaign tags";

/// Whether this server verifies SendGrid's Event Webhook — a key is set AND
/// usable; the same test the `saas` route's own key parse applies, so "no
/// event arrived" (a measured zero) is never shown where no event CAN.
pub fn webhook_on(state: &AppState) -> bool {
    meshharbor_services::sendgrid::webhook_key_usable(
        &state.settings.newsletter.event_webhook_public_key,
    )
}

#[derive(Debug, Deserialize)]
pub struct NewsletterQuery {
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// One UTC day of the list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListDay {
    pub day: String,
    pub new: i64,
    pub confirmed: i64,
    pub unsubscribed: i64,
    pub suppressed: i64,
}

/// The list as it stands now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSize {
    /// Confirmed, not withdrawn, not suppressed — who the next issue mails.
    pub mailable: i64,
    /// Never confirmed.
    pub pending: i64,
    pub unsubscribed: i64,
    /// Confirmed but suppressed (a hard bounce or a spam report).
    pub suppressed: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTotals {
    pub new: i64,
    pub confirmed: i64,
    pub unsubscribed: i64,
    /// Of `unsubscribed`, those that came through an issue's own link.
    pub unsubscribed_via_issue: i64,
    pub suppressed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSource {
    pub source: String,
    pub new: i64,
    pub confirmed: i64,
    pub unsubscribed: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListReport {
    pub size: ListSize,
    pub totals: ListTotals,
    pub days: Vec<ListDay>,
    pub by_source: Vec<ListSource>,
}

/// The send ledger's disposition of an issue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCounts {
    /// Ledger rows: every subscriber the fan-out claimed.
    pub recipients: i64,
    /// Accepted by the mail backend (a SendGrid 202) — not delivered.
    pub accepted: i64,
    pub failed: i64,
    /// Withdrawn, unconfirmed or suppressed when their turn came.
    pub suppressed: i64,
    /// Stuck `claimed`: may or may not have been sent.
    pub stale: i64,
}

/// An issue's rates, each with its n; `value` only from n = 30.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IssueRates {
    /// delivered ÷ accepted.
    pub delivered: Option<Rate>,
    /// hard bounces ÷ accepted.
    pub hard_bounce: Option<Rate>,
    /// spam reports ÷ delivered.
    pub complaint: Option<Rate>,
    /// unsubscribed via the issue ÷ delivered (accepted while delivery is
    /// not measured).
    pub unsubscribe: Rate,
    /// sign-ups ÷ visitors.
    pub signup_per_visitor: Option<Rate>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IssueReport {
    pub slug: String,
    pub subject: String,
    /// `sending` · `completed`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    /// The `utm_campaign` its links carried; `None` = untagged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    /// A TEST issue: the size of the audience it was restricted to (never
    /// the addresses); absent for an issue sent to the list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_audience: Option<u32>,
    pub ledger: LedgerCounts,
    pub delivery: Measured<DeliveryCounts>,
    /// Subscribers whose current unsubscription came through this issue's
    /// link.
    pub unsubscribed_via: i64,
    /// purestat, by the issue's campaign key, over the range.
    pub web: Measured<WebCells>,
    /// Sign-ups in the range whose attribution carries the issue's key,
    /// exclusions applied.
    pub signups: u64,
    pub rates: IssueRates,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NewsletterReport {
    pub enabled: bool,
    pub since: String,
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub n_floor: i64,
    /// Whether this server verifies SendGrid's Event Webhook now.
    pub webhook_configured: bool,
    /// Whether new issues' links carry the per-issue tags.
    pub link_tags: bool,
    /// Why there is nothing at all (the `saas` module not mounted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<NotMeasured>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<ListReport>,
    pub issues: Vec<IssueReport>,
    /// More issues in the range than [`MAX_ISSUES`]: the newest only.
    pub issues_truncated: bool,
    /// Why every issue's web cell is `not_measured`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_not_measured: Option<NotMeasured>,
    pub web_truncated: bool,
    pub account_truncated: bool,
}

/// The range: UTC days, both inclusive; `until` defaults to yesterday and
/// never passes today; `since` defaults to [`DEFAULT_RANGE_DAYS`] back;
/// at most `campaigns::MAX_RANGE_DAYS` (purestat's own bound).
pub fn range(
    since: Option<&str>,
    until: Option<&str>,
    today: NaiveDate,
) -> Result<(NaiveDate, NaiveDate), String> {
    let until_day = match until {
        Some(s) => parse_day(s)?,
        None => today.pred_opt().ok_or("no yesterday")?,
    };
    let since_day = match since {
        Some(s) => parse_day(s)?,
        None => until_day - chrono::Duration::days(DEFAULT_RANGE_DAYS - 1),
    };
    super::campaigns::range(Some(&day_str(since_day)), Some(&day_str(until_day)), today)
}

/// The key an issue's links carry, normalised as a sign-up's would be.
pub fn issue_key(campaign: &str) -> Option<CampaignKey> {
    CampaignKey::normalized(
        Some(ISSUE_UTM_SOURCE),
        Some(ISSUE_UTM_MEDIUM),
        Some(campaign),
        None,
    )
    .map(|k| k.at_depth(KeyDepth::Campaign))
}

/// The list over `[start, end)`: per day, by source, and its size now.
pub async fn read_list(
    state: &AppState,
    since: NaiveDate,
    until: NaiveDate,
) -> Result<ListReport, DigestError> {
    let (start_ms, end_ms) = day_range_ms(since, until);
    let between = doc! {
        "$gte": DateTime::from_millis(start_ms),
        "$lt": DateTime::from_millis(end_ms),
    };
    let rows = find_docs(
        state,
        "subscribers",
        doc! { "$or": [
            { "created_at": between.clone() },
            { "confirmed_at": between.clone() },
            { "unsubscribed_at": between.clone() },
            { "suppressed_at": between },
        ] },
        doc! {
            "source": 1, "created_at": 1, "confirmed_at": 1, "unsubscribed_at": 1,
            "unsubscribed_via": 1, "suppressed_at": 1,
        },
    )
    .await?;
    let n_days = ((end_ms - start_ms) / DAY_MS) as usize;
    let mut days: Vec<ListDay> = (0..n_days)
        .map(|i| ListDay {
            day: day_str(utc_date_of(DateTime::from_millis(
                start_ms + i as i64 * DAY_MS,
            ))),
            ..ListDay::default()
        })
        .collect();
    let slot = |t: i64| -> Option<usize> {
        (start_ms..end_ms)
            .contains(&t)
            .then(|| ((t - start_ms) / DAY_MS) as usize)
    };
    let mut totals = ListTotals::default();
    let mut by_source: BTreeMap<String, ListSource> = BTreeMap::new();
    for d in &rows {
        let source = str_of(d, "source").unwrap_or_else(|| "(none)".into());
        let src = by_source
            .entry(source.clone())
            .or_insert_with(|| ListSource {
                source,
                new: 0,
                confirmed: 0,
                unsubscribed: 0,
            });
        if let Some(i) = dt_ms(d, "created_at").and_then(slot) {
            days[i].new += 1;
            totals.new += 1;
            src.new += 1;
        }
        if let Some(i) = dt_ms(d, "confirmed_at").and_then(slot) {
            days[i].confirmed += 1;
            totals.confirmed += 1;
            src.confirmed += 1;
        }
        if let Some(i) = dt_ms(d, "unsubscribed_at").and_then(slot) {
            days[i].unsubscribed += 1;
            totals.unsubscribed += 1;
            src.unsubscribed += 1;
            if str_of(d, "unsubscribed_via").is_some() {
                totals.unsubscribed_via_issue += 1;
            }
        }
        if let Some(i) = dt_ms(d, "suppressed_at").and_then(slot) {
            days[i].suppressed += 1;
            totals.suppressed += 1;
        }
    }
    let mut by_source: Vec<ListSource> = by_source
        .into_values()
        .filter(|r| r.new + r.confirmed + r.unsubscribed > 0)
        .collect();
    by_source.sort_by(|a, b| b.new.cmp(&a.new).then_with(|| a.source.cmp(&b.source)));
    let coll = state.db.collection::<Document>("subscribers");
    let count = |filter: Document| {
        let coll = coll.clone();
        async move { coll.count_documents(filter).await.map(|n| n as i64) }
    };
    let size = ListSize {
        mailable: count(doc! { "confirmed": true, "unsubscribed_at": Bson::Null, "suppressed_at": Bson::Null }).await?,
        pending: count(doc! { "confirmed": false, "unsubscribed_at": Bson::Null }).await?,
        unsubscribed: count(doc! { "unsubscribed_at": { "$ne": Bson::Null } }).await?,
        suppressed: count(doc! { "confirmed": true, "unsubscribed_at": Bson::Null, "suppressed_at": { "$ne": Bson::Null } }).await?,
    };
    Ok(ListReport {
        size,
        totals,
        days,
        by_source,
    })
}

/// One issue as stored, the fields this view reads.
#[derive(Debug, Clone)]
pub struct IssueFacts {
    pub id: ObjectId,
    pub slug: String,
    pub subject: String,
    pub status: String,
    pub sent_at_ms: Option<i64>,
    pub campaign: Option<String>,
    pub delivery_events: bool,
    /// A test issue's audience size (the addresses are never read here).
    pub test_audience: Option<u32>,
    /// The counts stamped at completion; `None` while sending.
    pub counts: Option<LedgerCounts>,
}

/// One stored issue row, read; `None` without an id or a slug.
pub fn issue_facts_of(d: &Document) -> Option<IssueFacts> {
    let counts = d.get_document("counts").ok().map(|c| LedgerCounts {
        recipients: i64_of(c, "total"),
        accepted: i64_of(c, "sent"),
        failed: i64_of(c, "failed"),
        suppressed: i64_of(c, "suppressed"),
        stale: i64_of(c, "stale"),
    });
    Some(IssueFacts {
        id: d.get_object_id("_id").ok()?,
        slug: str_of(d, "slug")?,
        subject: str_of(d, "subject").unwrap_or_default(),
        status: str_of(d, "status").unwrap_or_default(),
        sent_at_ms: dt_ms(d, "sent_at"),
        campaign: str_of(d, "campaign").filter(|c| !c.is_empty()),
        delivery_events: d.get_bool("delivery_events").unwrap_or(false),
        test_audience: d.get_array("audience").ok().map(|a| a.len() as u32),
        counts: if str_of(d, "status").as_deref() == Some("completed") {
            counts
        } else {
            None
        },
    })
}

/// The issues sent in `[start, end)`, plus any still sending — newest
/// first, at most `limit` (the bool says whether it cut).
pub async fn read_issues(
    state: &AppState,
    start_ms: i64,
    end_ms: i64,
    limit: i64,
) -> Result<(Vec<IssueFacts>, bool), DigestError> {
    let docs: Vec<Document> = {
        use futures::TryStreamExt;
        state
            .db
            .collection::<Document>("newsletter_issues")
            .find(doc! { "$or": [
                { "status": "completed", "sent_at": {
                    "$gte": DateTime::from_millis(start_ms),
                    "$lt": DateTime::from_millis(end_ms),
                } },
                { "status": "sending" },
            ] })
            .projection(doc! {
                "slug": 1, "subject": 1, "status": 1, "sent_at": 1, "counts": 1,
                "campaign": 1, "delivery_events": 1, "claimed_at": 1, "audience": 1,
            })
            .sort(doc! { "sent_at": -1, "claimed_at": -1 })
            .limit(limit + 1)
            .await?
            .try_collect()
            .await?
    };
    let truncated = docs.len() as i64 > limit;
    Ok((
        docs.iter()
            .take(limit as usize)
            .filter_map(issue_facts_of)
            .collect(),
        truncated,
    ))
}

/// Each issue's ledger counts: the stamped ones once completed, live while
/// sending.
pub async fn ledger_counts(
    state: &AppState,
    issues: &[IssueFacts],
    now: DateTime,
) -> Result<HashMap<ObjectId, LedgerCounts>, DigestError> {
    let dao = NewsletterSendDao::new(&state.db);
    let mut out = HashMap::new();
    for i in issues {
        let counts = match i.counts {
            Some(c) => c,
            None => {
                let live = dao.counts(i.id, stale_cutoff_at(now)).await?;
                LedgerCounts {
                    recipients: live.total,
                    accepted: live.sent,
                    failed: live.failed,
                    suppressed: live.suppressed,
                    stale: live.stale,
                }
            }
        };
        out.insert(i.id, counts);
    }
    Ok(out)
}

/// Each listed slug's count of subscribers whose current unsubscription
/// came through that issue's link.
pub async fn unsubscribed_via(
    state: &AppState,
    slugs: &[String],
) -> Result<HashMap<String, i64>, DigestError> {
    if slugs.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = aggregate(
        state,
        "subscribers",
        vec![
            doc! { "$match": { "unsubscribed_via": { "$in": slugs } } },
            doc! { "$group": { "_id": "$unsubscribed_via", "n": { "$sum": 1 } } },
        ],
    )
    .await?;
    Ok(rows
        .iter()
        .filter_map(|d| Some((str_of(d, "_id")?, i64_of(d, "n"))))
        .collect())
}

/// An issue's delivery cell: the counts, or why there are none.
pub fn delivery_cell(
    webhook_configured: bool,
    issue: &IssueFacts,
    counts: Option<DeliveryCounts>,
) -> Measured<DeliveryCounts> {
    if !webhook_configured {
        Measured::NotMeasured(NotMeasured::now(WEBHOOK_OFF))
    } else if !issue.delivery_events {
        Measured::NotMeasured(NotMeasured::now(SENT_UNRECORDED))
    } else {
        Measured::Value(counts.unwrap_or_default())
    }
}

/// An issue's rates.
pub fn rates(
    ledger: &LedgerCounts,
    delivery: &Measured<DeliveryCounts>,
    via: i64,
    web: &Measured<WebCells>,
    signups: u64,
) -> IssueRates {
    let d = delivery.value();
    IssueRates {
        delivered: d.map(|d| Rate::of(d.delivered, ledger.accepted)),
        hard_bounce: d.map(|d| Rate::of(d.hard_bounced, ledger.accepted)),
        complaint: d.map(|d| Rate::of(d.complaints, d.delivered)),
        unsubscribe: Rate::of(via, d.map(|d| d.delivered).unwrap_or(ledger.accepted)),
        signup_per_visitor: web.value().map(|w| Rate::of(signups as i64, w.visitors)),
    }
}

/// `GET /api/admin/growth/newsletter?since&until&include_internal`
pub async fn get_newsletter(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    AxumQuery(q): AxumQuery<NewsletterQuery>,
) -> Result<Json<NewsletterReport>, ApiError> {
    let now = DateTime::now();
    let today = utc_date_of(now);
    let (since, until) =
        range(q.since.as_deref(), q.until.as_deref(), today).map_err(ApiError::BadRequest)?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, q.include_internal, now).await?,
    ))
}

/// The report for the closed days `[since, until]` (inclusive) at `now` —
/// what the route answers, and what P10's weekly roll-up stores for its
/// week.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: NaiveDate,
    until: NaiveDate,
    include_internal: bool,
    now: DateTime,
) -> Result<NewsletterReport, ApiError> {
    let (users, tenants) = set.counts();
    let webhook_configured = webhook_on(state);
    let mut report = NewsletterReport {
        enabled: true,
        since: day_str(since),
        until: day_str(until),
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        n_floor: SMALL_N,
        webhook_configured,
        link_tags: state.settings.newsletter.link_tags,
        not_measured: None,
        list: None,
        issues: Vec::new(),
        issues_truncated: false,
        web_not_measured: None,
        web_truncated: false,
        account_truncated: false,
    };
    if !mounted(state, "saas") {
        report.not_measured = Some(NotMeasured::now("saas module not mounted"));
        return Ok(report);
    }

    report.list = Some(read_list(state, since, until).await?);
    let (start_ms, end_ms) = day_range_ms(since, until);
    let (issues, truncated) = read_issues(state, start_ms, end_ms, MAX_ISSUES).await?;
    report.issues_truncated = truncated;
    if issues.is_empty() {
        return Ok(report);
    }

    let ids: Vec<ObjectId> = issues.iter().map(|i| i.id).collect();
    let slugs: Vec<String> = issues.iter().map(|i| i.slug.clone()).collect();
    let ledgers = ledger_counts(state, &issues, now).await?;
    let delivery = NewsletterSendDao::new(&state.db)
        .delivery_counts(&ids)
        .await?;
    let via = unsubscribed_via(state, &slugs).await?;

    // The account plane: the funnel's own read of the range's sign-ups,
    // grouped by the normalised key at the campaign depth.
    let read = funnel::read(
        state,
        set,
        DateTime::from_millis(start_ms),
        DateTime::from_millis(end_ms),
    )
    .await?;
    report.account_truncated = read.truncated;
    let facts = read.facts(now.timestamp_millis());
    let account = super::campaigns::account_by_key(&facts, KeyDepth::Campaign);

    // The web plane: ONE purestat breakdown of the newsletter's own
    // traffic, by campaign, over the range.
    let web = match web_client(state) {
        Err(n) => Err(n),
        Ok(client) => {
            let (from, to) = (day_str(since), day_str(until));
            let query = Query::range(
                &from,
                &to,
                KeyDepth::Campaign.utm_dimensions(),
                &WEB_METRICS,
                &GOALS,
            )
            .filter(Filter::is("utm_source", ISSUE_UTM_SOURCE));
            match client.query_or_without_goals(&query).await {
                Ok((paged, missing)) => {
                    report.web_truncated = paged.truncated;
                    let conversions = missing.map(|goal| {
                        NotMeasured::now(format!("{goal} is not defined on the purestat site"))
                    });
                    Ok((
                        web_by_key(&paged.rows, KeyDepth::Campaign, &conversions),
                        conversions,
                    ))
                }
                Err(e) => Err(NotMeasured::now(e.to_string())),
            }
        }
    };
    report.web_not_measured = web.as_ref().err().cloned();

    for i in &issues {
        let ledger = ledgers.get(&i.id).copied().unwrap_or_default();
        let delivery = delivery_cell(webhook_configured, i, delivery.get(&i.id).copied());
        let unsubscribed_via = via.get(&i.slug).copied().unwrap_or(0);
        let key = i.campaign.as_deref().and_then(issue_key);
        let web_cell = match (&key, &web) {
            (None, _) => Measured::NotMeasured(NotMeasured::now(UNTAGGED)),
            (Some(_), Err(n)) => Measured::NotMeasured(n.clone()),
            (Some(k), Ok((by_key, conversions))) => Measured::Value(
                by_key
                    .get(k)
                    .cloned()
                    .unwrap_or_else(|| WebCells::zero(conversions.is_none(), conversions)),
            ),
        };
        let signups = key
            .as_ref()
            .and_then(|k| account.get(&Some(k.clone())))
            .map(|g| g.signups)
            .unwrap_or(0);
        report.issues.push(IssueReport {
            rates: rates(&ledger, &delivery, unsubscribed_via, &web_cell, signups),
            slug: i.slug.clone(),
            subject: i.subject.clone(),
            status: i.status.clone(),
            sent_at: i
                .sent_at_ms
                .and_then(|t| DateTime::from_millis(t).try_to_rfc3339_string().ok()),
            campaign: i.campaign.clone(),
            test_audience: i.test_audience,
            ledger,
            delivery,
            unsubscribed_via,
            web: web_cell,
            signups,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(delivery_events: bool, campaign: Option<&str>) -> IssueFacts {
        IssueFacts {
            id: ObjectId::new(),
            slug: "october-notes".into(),
            subject: "s".into(),
            status: "completed".into(),
            sent_at_ms: Some(0),
            campaign: campaign.map(str::to_string),
            delivery_events,
            test_audience: None,
            counts: None,
        }
    }

    /// The key an issue's links carry is the one a sign-up through them is
    /// stored under — the link's spelling, normalised at ingress.
    #[test]
    fn an_issues_key_is_the_one_its_signups_are_stored_under() {
        let campaign = meshharbor_services::newsletter::issue_campaign("october-notes");
        let k = issue_key(&campaign).unwrap();
        assert_eq!(k.source, "newsletter");
        assert_eq!(k.medium.as_deref(), Some("email"));
        assert_eq!(k.campaign.as_deref(), Some("nl-october-notes"));
        assert_eq!(k.content, None);
        // A sign-up that came through the link, as ingress stores it.
        let stored = meshharbor_core::attribution::sanitize(
            meshharbor_core::attribution::AttributionInput {
                source: Some("newsletter".into()),
                medium: Some("email".into()),
                campaign: Some(campaign.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        let from_signup = CampaignKey::normalized(
            stored.source.as_deref(),
            stored.medium.as_deref(),
            stored.campaign.as_deref(),
            stored.content.as_deref(),
        )
        .unwrap()
        .at_depth(KeyDepth::Campaign);
        assert_eq!(from_signup, k);
    }

    /// A 64-character slug: the campaign the link carries is cut where a
    /// sign-up's would be, so the two still meet.
    #[test]
    fn a_long_slugs_campaign_still_meets_its_signups() {
        let campaign = meshharbor_services::newsletter::issue_campaign(&"a".repeat(64));
        let stored = meshharbor_core::attribution::clean_value(&campaign).unwrap();
        assert_eq!(stored, campaign, "ingress keeps the link's campaign whole");
    }

    /// Three cells: not verified → not measured; an issue sent without
    /// recorded events → not measured; otherwise a value, zero included.
    #[test]
    fn delivery_is_never_a_zero_it_could_not_see() {
        let counts = DeliveryCounts {
            delivered: 3,
            ..Default::default()
        };
        assert_eq!(
            delivery_cell(false, &issue(true, None), Some(counts)),
            Measured::NotMeasured(NotMeasured::now(WEBHOOK_OFF))
        );
        assert_eq!(
            delivery_cell(true, &issue(false, None), None),
            Measured::NotMeasured(NotMeasured::now(SENT_UNRECORDED))
        );
        assert_eq!(
            delivery_cell(true, &issue(true, None), None),
            Measured::Value(DeliveryCounts::default()),
            "recorded, and no event arrived: a measured zero"
        );
        assert_eq!(
            delivery_cell(true, &issue(true, None), Some(counts)),
            Measured::Value(counts)
        );
    }

    /// Every rate carries its n; a value only from n = 30.
    #[test]
    fn rates_carry_their_n_and_a_value_only_from_thirty() {
        let ledger = LedgerCounts {
            recipients: 40,
            accepted: 40,
            ..Default::default()
        };
        let delivery = Measured::Value(DeliveryCounts {
            delivered: 38,
            bounced: 2,
            hard_bounced: 1,
            dropped: 0,
            complaints: 1,
        });
        let web = Measured::Value(WebCells::zero(true, &None));
        let r = rates(&ledger, &delivery, 2, &web, 0);
        assert_eq!(r.delivered.unwrap().n, 40);
        assert_eq!(r.delivered.unwrap().value, Some(0.95));
        assert_eq!(r.hard_bounce.unwrap().value, Some(0.025));
        assert_eq!(r.complaint.unwrap().n, 38);
        assert_eq!(
            r.unsubscribe.n, 38,
            "unsubscribes are per delivered message"
        );
        assert_eq!(r.signup_per_visitor.unwrap().n, 0);
        assert_eq!(r.signup_per_visitor.unwrap().value, None);
        // Delivery not measured: no delivery rate, and the unsubscribe rate
        // rests on the accepted count instead.
        let small = LedgerCounts {
            accepted: 5,
            ..Default::default()
        };
        let none: Measured<DeliveryCounts> = Measured::NotMeasured(NotMeasured::now(WEBHOOK_OFF));
        let r = rates(
            &small,
            &none,
            1,
            &Measured::NotMeasured(NotMeasured::now("x")),
            0,
        );
        assert!(r.delivered.is_none() && r.hard_bounce.is_none() && r.complaint.is_none());
        assert_eq!(r.unsubscribe.n, 5);
        assert_eq!(r.unsubscribe.value, None, "n < 30: counts only");
        assert!(r.signup_per_visitor.is_none());
    }

    #[test]
    fn the_range_defaults_to_ninety_closed_days() {
        let today = parse_day("2026-10-15").unwrap();
        let (s, u) = range(None, None, today).unwrap();
        assert_eq!(day_str(u), "2026-10-14");
        assert_eq!((u - s).num_days() + 1, DEFAULT_RANGE_DAYS);
        assert!(range(Some("2026-10-10"), Some("2026-10-01"), today).is_err());
        assert!(range(None, Some("2026-10-16"), today).is_err());
        assert!(
            range(Some("2024-01-01"), None, today).is_err(),
            "over a year"
        );
    }
}
