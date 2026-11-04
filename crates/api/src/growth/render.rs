// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1d — the digest's email bodies, HTML and plain text, rendered
//! from the STORED sections (never from a second query: what was mailed is
//! what `GET …/digest` answers).
//!
//! Both bodies come from one intermediate model ([`Block`]) so the two can
//! not disagree; the HTML writer escapes every string (org names, UTM
//! values and referrer hosts are client-chosen text). The rules the text
//! follows:
//!
//! * every count sits beside its 7- and 28-day context (`fig`);
//! * a rate is shown only when its denominator reaches `SMALL_N`
//!   ([`pct_if_enough`]) — below it, counts only;
//! * a `not_measured` section reads "not measured — arrives with Pn" (or
//!   the reason), never 0;
//! * the footer says how many users and orgs were excluded, and that the
//!   digest carries no personal addresses.

use meshharbor_services::{
    dao::{growth_alert::GrowthAlert, growth_digest::DigestDoc, growth_quality::Pooled},
    newsletter::escape_html,
};

use super::{
    campaigns::{Rate, WebCells},
    digest::{
        AlertRow, AlertsSection, CampaignGoals, DistFigure, DistSummary, Figure, FigureF, Measured,
        NotMeasured, RateFigure, SMALL_N, Sections,
    },
    funnel::StepCounts,
    quality::{QualityReport, VersionQuality},
    weekly::{WeekFigure, WeeklyHeadline, WeeklySections},
};

/// `Roomler daily digest — YYYY-MM-DD`.
pub fn subject(day: &str) -> String {
    format!("Roomler daily digest — {day}")
}

/// P10 — `Roomler weekly roll-up — 2026-W41 (2026-10-05 → 2026-10-11)`.
pub fn weekly_subject(h: &WeeklyHeadline) -> String {
    format!(
        "Roomler weekly roll-up — {} ({} → {})",
        h.week, h.since, h.until
    )
}

/// P10 — `Roomler growth alert — spike: signups`.
pub fn alert_subject(a: &GrowthAlert) -> String {
    format!("Roomler growth alert — {}: {}", a.rule, a.key)
}

/// `num / den` as a percentage, only once `den` reaches [`SMALL_N`].
pub fn pct_if_enough(num: i64, den: i64) -> Option<f64> {
    (den >= SMALL_N).then(|| (num as f64 / den as f64 * 1000.0).round() / 10.0)
}

/// The render model.
#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    Heading(String),
    /// `label: value`
    Line(String, String),
    /// A table: headers, then rows of cells.
    Table(Vec<String>, Vec<Vec<String>>),
    Note(String),
}

pub fn fig(f: &Figure) -> String {
    format!("{} (7d {} · 28d {})", f.day, f.d7, f.d28)
}

pub fn figf(f: &FigureF) -> String {
    format!("{:.1} (7d {:.1} · 28d {:.1})", f.day, f.d7, f.d28)
}

/// P9a — milliseconds as a reader reads them: `820 ms`, `2.7 s`, `12.3 min`,
/// `1.5 h`.
pub fn ms_label(ms: i64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1} min", ms as f64 / 60_000.0)
    } else {
        format!("{:.1} h", ms as f64 / 3_600_000.0)
    }
}

fn opt_unit(v: Option<i64>, unit: &dyn Fn(i64) -> String) -> String {
    v.map(unit).unwrap_or_else(|| "—".into())
}

/// P9a — `p50 2.7 s · p90 6.1 s (n 94)`, or `no sample`.
pub fn dist_summary_label(d: &DistSummary, unit: &dyn Fn(i64) -> String) -> String {
    if d.n == 0 {
        return "no sample".into();
    }
    format!(
        "p50 {} · p90 {} (n {})",
        opt_unit(d.p50, unit),
        opt_unit(d.p90, unit),
        d.n
    )
}

/// P9a — the day's distribution, then the windows'.
pub fn dist_fig(d: &DistFigure, unit: &dyn Fn(i64) -> String) -> String {
    format!(
        "{} · 7d {} · 28d {}",
        dist_summary_label(&d.day, unit),
        dist_summary_label(&d.d7, unit),
        dist_summary_label(&d.d28, unit)
    )
}

/// P9a — a pooled distribution, `≈` when estimated from the daily
/// histograms rather than one day's exact values.
pub fn pooled_label(p: &Pooled, unit: &dyn Fn(i64) -> String) -> String {
    if p.n == 0 {
        return "no sample".into();
    }
    format!(
        "{}p50 {} · p90 {} (n {})",
        if p.exact { "" } else { "≈ " },
        opt_unit(p.p50, unit),
        opt_unit(p.p90, unit),
        p.n
    )
}

/// P9a — a rate per window; `n < 30` where the floor was not reached.
pub fn rate_fig(r: &RateFigure, unit: &dyn Fn(f64) -> String) -> String {
    let one = |v: Option<f64>| v.map(unit).unwrap_or_else(|| format!("— (n < {SMALL_N})"));
    format!("{} · 7d {} · 28d {}", one(r.day), one(r.d7), one(r.d28))
}

/// A share as `93.3 %`.
fn share(v: f64) -> String {
    format!("{:.1} %", v * 100.0)
}

fn opt_count(v: Option<i64>) -> String {
    v.map(|c| c.to_string())
        .unwrap_or_else(|| "not measured".into())
}

pub fn not_measured(n: &NotMeasured) -> String {
    match &n.arrives_with {
        Some(p) => format!("not measured — arrives with {p} ({})", n.not_measured),
        None => format!("not measured — {}", n.not_measured),
    }
}

fn measured<T>(m: &Measured<T>, show: impl FnOnce(&T) -> String) -> String {
    match m {
        Measured::Value(v) => show(v),
        Measured::NotMeasured(n) => not_measured(n),
    }
}

fn opt(s: &Option<String>) -> String {
    s.clone().unwrap_or_else(|| "—".to_string())
}

fn money(cents: f64) -> String {
    format!("{:.2}", cents / 100.0)
}

/// The sections as blocks, in the order the operator reads them.
pub fn blocks(doc: &DigestDoc, s: &Sections) -> Vec<Block> {
    use Block::*;
    let mut out = Vec::new();

    out.push(Heading("Headline".into()));
    out.push(Line("Sign-ups".into(), fig(&s.headline.signups)));
    out.push(Line("Orgs created".into(), fig(&s.headline.orgs_created)));
    out.push(Line(
        "Devices enrolled".into(),
        measured(&s.headline.devices_enrolled, fig),
    ));
    out.push(Line(
        "Active orgs".into(),
        measured(&s.headline.active_orgs, |a| {
            format!(
                "{} (7d {} · 28d {}) — basis: {}",
                a.day,
                a.d7,
                a.d28,
                a.basis.join(" + ")
            )
        }),
    ));
    out.push(Line(
        "Coverage".into(),
        measured(&s.headline.coverage, |c| {
            let ratio = match c.ratio {
                Some(r) => format!(", {:.2}", r),
                None => format!(" (no ratio below n = {})", c.n_floor),
            };
            format!(
                "{} purestat sign-up goals vs {} server sign-ups{ratio}",
                c.purestat_signup_goals, c.server_signups
            )
        }),
    ));

    out.push(Heading("Sign-ups".into()));
    out.push(Line("Total".into(), fig(&s.signups.total)));
    out.push(Line("With attribution".into(), fig(&s.signups.attributed)));
    if !s.signups.by_provider.is_empty() {
        out.push(Table(
            vec!["Provider".into(), "Sign-ups".into()],
            s.signups
                .by_provider
                .iter()
                .map(|k| vec![k.key.clone(), k.count.to_string()])
                .collect(),
        ));
    }
    if !s.signups.by_source.is_empty() {
        out.push(Table(
            vec!["Source".into(), "Sign-ups".into()],
            s.signups
                .by_source
                .iter()
                .map(|k| vec![k.key.clone(), k.count.to_string()])
                .collect(),
        ));
    }
    match &s.signups.rows {
        Some(rows) if !rows.is_empty() => out.push(Table(
            vec![
                "Provider".into(),
                "Source".into(),
                "Medium".into(),
                "Campaign".into(),
                "Content".into(),
                "Landing".into(),
                "Referrer".into(),
                "Self-reported".into(),
            ],
            rows.iter()
                .map(|r| {
                    vec![
                        r.provider.clone(),
                        opt(&r.source),
                        opt(&r.medium),
                        opt(&r.campaign),
                        opt(&r.content),
                        opt(&r.landing_path),
                        opt(&r.referrer_host),
                        opt(&r.self_reported),
                    ]
                })
                .collect(),
        )),
        Some(_) => {}
        None => out.push(Note(
            "More than the listed ceiling of sign-ups — aggregated by source above.".into(),
        )),
    }

    out.push(Heading("Orgs and devices".into()));
    out.push(Line(
        "Orgs created".into(),
        fig(&s.orgs_devices.orgs_created),
    ));
    out.push(Line(
        "Devices enrolled".into(),
        measured(&s.orgs_devices.devices_enrolled, fig),
    ));
    out.push(Line(
        "Orgs enrolling their first device".into(),
        measured(&s.orgs_devices.orgs_first_device, fig),
    ));
    match &s.orgs_devices.devices_by_os {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec!["OS".into(), "Enrolled".into()],
            rows.iter()
                .map(|k| vec![k.key.clone(), k.count.to_string()])
                .collect(),
        )),
        Measured::Value(_) => {}
        Measured::NotMeasured(n) => out.push(Line("By OS".into(), not_measured(n))),
    }
    match &s.orgs_devices.by_install_method {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec!["Install method".into(), "Enrolled".into()],
            rows.iter()
                .map(|k| vec![k.key.clone(), k.count.to_string()])
                .collect(),
        )),
        Measured::Value(_) => {}
        Measured::NotMeasured(n) => out.push(Line("By install method".into(), not_measured(n))),
    }

    out.push(Heading("Install".into()));
    match &s.install.tokens {
        Measured::Value(t) => {
            out.push(Line("Enrollment tokens issued".into(), fig(&t.issued)));
            out.push(Line("… of which redeemed".into(), fig(&t.redeemed)));
            if let Some(p) = pct_if_enough(t.redeemed.d28, t.issued.d28) {
                out.push(Line("Redeemed share (28d)".into(), format!("{p:.1} %")));
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Enrollment tokens".into(), not_measured(n))),
    }
    match &s.install.enrollments_by_method {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec![
                "Method".into(),
                "OS".into(),
                "Enrolled (day · 7d · 28d)".into(),
            ],
            rows.iter()
                .map(|r| {
                    vec![
                        r.method.clone(),
                        r.os.clone(),
                        format!(
                            "{} · {} · {}",
                            r.enrolled.day, r.enrolled.d7, r.enrolled.d28
                        ),
                    ]
                })
                .collect(),
        )),
        Measured::Value(_) => out.push(Note("No device enrolled in the last 28 days.".into())),
        Measured::NotMeasured(n) => out.push(Line("Enrollments by method".into(), not_measured(n))),
    }
    match &s.install.fetches {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec![
                "Asset".into(),
                "Client".into(),
                "OS".into(),
                "Fetches (day · 7d · 28d)".into(),
            ],
            rows.iter()
                .map(|r| {
                    vec![
                        r.asset.clone(),
                        r.client.clone(),
                        r.os.clone(),
                        format!("{} · {} · {}", r.fetches.day, r.fetches.d7, r.fetches.d28),
                    ]
                })
                .collect(),
        )),
        Measured::Value(_) => out.push(Note(
            "No installer or script fetched in the last 28 days.".into(),
        )),
        Measured::NotMeasured(n) => out.push(Line("Fetches".into(), not_measured(n))),
    }
    // P3c — the lab's own fetches, left out of the table above and counted
    // here, so nothing vanishes silently.
    match &s.install.internal_fetches {
        Measured::Value(f) => out.push(Line(
            "Fetches from internal networks (not in the table)".into(),
            fig(f),
        )),
        Measured::NotMeasured(n) => out.push(Line(
            "Fetches from internal networks".into(),
            not_measured(n),
        )),
    }
    out.push(Note(
        "Fetches are counted by client class from the User-Agent (wizard, script-sh, script-ps1, \
         browser, other) and never include the daemon's own update checks; a fetch from one of \
         the configured internal networks is counted as internal instead of its class; a fetch \
         is a lower bound on intent, not an install."
            .into(),
    ));
    // P3b — the wizard's opt-in diagnostics: opted-in runs only, labelled
    // with their n; a share only once the n clears the floor.
    match &s.install.wizard_steps {
        Measured::Value(ws) => {
            out.push(Line("Wizard runs (opted in)".into(), fig(&ws.runs)));
            if let Some(share) = ws.done_share_28d {
                out.push(Line(
                    "… of which reached done (28d)".into(),
                    format!("{:.1} %", share * 100.0),
                ));
            }
            if ws.steps.is_empty() {
                out.push(Note("No opted-in wizard run in the last 28 days.".into()));
            } else {
                out.push(Table(
                    vec![
                        "Step".into(),
                        "Runs reaching it (day · 7d · 28d)".into(),
                        "ok".into(),
                        "failed".into(),
                        "cancelled".into(),
                    ],
                    ws.steps
                        .iter()
                        .map(|r| {
                            vec![
                                r.step.clone(),
                                format!("{} · {} · {}", r.reached.day, r.reached.d7, r.reached.d28),
                                r.ok.d28.to_string(),
                                r.failed.d28.to_string(),
                                r.cancelled.d28.to_string(),
                            ]
                        })
                        .collect(),
                ));
            }
            if !ws.errors.is_empty() {
                out.push(Table(
                    vec![
                        "Step".into(),
                        "Error code".into(),
                        "Runs (day · 7d · 28d)".into(),
                    ],
                    ws.errors
                        .iter()
                        .map(|r| {
                            vec![
                                r.step.clone(),
                                r.error_code.clone(),
                                format!(
                                    "{} · {} · {}",
                                    r.failures.day, r.failures.d7, r.failures.d28
                                ),
                            ]
                        })
                        .collect(),
                ));
            }
            out.push(Note(format!(
                "Wizard steps come only from runs whose operator ticked the diagnostics box; \
                 they say nothing about the runs that did not. Outcomes are distinct runs in \
                 the 28-day window; a share is shown only from {} runs.",
                ws.n_floor
            )));
        }
        Measured::NotMeasured(n) => out.push(Line("Wizard steps".into(), not_measured(n))),
    }

    out.push(Heading("Usage".into()));
    out.push(Line(
        "Remote-desktop sessions".into(),
        measured(&s.usage.remote, |r| fig(&r.sessions_started)),
    ));
    out.push(Line(
        "Remote-desktop minutes".into(),
        measured(&s.usage.remote, |r| figf(&r.session_minutes)),
    ));
    out.push(Line(
        "Calls".into(),
        measured(&s.usage.calls, |c| fig(&c.calls)),
    ));
    out.push(Line(
        "Participant-minutes".into(),
        measured(&s.usage.calls, |c| figf(&c.participant_minutes)),
    ));
    out.push(Line(
        "Active orgs".into(),
        measured(&s.usage.active_orgs, |a| {
            format!("{} (7d {} · 28d {})", a.day, a.d7, a.d28)
        }),
    ));
    match &s.usage.top_orgs {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec!["Org".into(), "Minutes".into(), "Sessions".into()],
            rows.iter()
                .map(|o| {
                    vec![
                        o.name.clone(),
                        format!("{:.1}", o.minutes),
                        o.sessions.to_string(),
                    ]
                })
                .collect(),
        )),
        Measured::Value(_) => out.push(Note("No remote-desktop minutes that day.".into())),
        Measured::NotMeasured(n) => out.push(Line("Top orgs".into(), not_measured(n))),
    }

    out.push(Heading("Website".into()));
    match &s.website {
        Measured::Value(w) => {
            out.push(Line("Visitors".into(), fig(&w.visitors)));
            out.push(Line("Visits".into(), fig(&w.visits)));
            out.push(Line("Pageviews".into(), fig(&w.pageviews)));
            if !w.channels.is_empty() {
                out.push(Table(
                    vec!["Channel".into(), "Visitors".into()],
                    w.channels
                        .iter()
                        .map(|k| vec![k.key.clone(), k.count.to_string()])
                        .collect(),
                ));
            }
            if !w.top_referrers.is_empty() {
                out.push(Table(
                    vec!["Referrer".into(), "Channel".into(), "Visitors".into()],
                    w.top_referrers
                        .iter()
                        .map(|r| vec![r.host.clone(), r.channel.clone(), r.visitors.to_string()])
                        .collect(),
                ));
            }
            if !w.top_paths.is_empty() {
                out.push(Table(
                    vec!["Path".into(), "Visitors".into(), "Pageviews".into()],
                    w.top_paths
                        .iter()
                        .map(|p| {
                            vec![
                                p.path.clone(),
                                p.visitors.to_string(),
                                p.pageviews.to_string(),
                            ]
                        })
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Note(not_measured(n))),
    }

    out.push(Heading("Blog".into()));
    match &s.blog {
        Measured::Value(b) => {
            if b.posts.is_empty() {
                out.push(Note("No blog post was viewed that day.".into()));
            } else {
                out.push(Table(
                    vec![
                        "Post".into(),
                        "Visitors".into(),
                        "Pageviews".into(),
                        "Reads".into(),
                        "Median read (s)".into(),
                    ],
                    b.posts
                        .iter()
                        .map(|p| {
                            vec![
                                p.path.clone(),
                                p.visitors.to_string(),
                                p.pageviews.to_string(),
                                p.reads.map(|r| r.to_string()).unwrap_or_else(|| "—".into()),
                                p.median_read_s
                                    .map(|r| format!("{r:.0}"))
                                    .unwrap_or_else(|| "—".into()),
                            ]
                        })
                        .collect(),
                ));
            }
            if !b.top_sources.is_empty() {
                out.push(Table(
                    vec!["Blog source".into(), "Visitors".into()],
                    b.top_sources
                        .iter()
                        .map(|k| vec![k.key.clone(), k.count.to_string()])
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Note(not_measured(n))),
    }

    out.push(Heading("Campaigns".into()));
    match &s.campaigns {
        Measured::Value(c) if c.rows.is_empty() => out.push(Note(
            "No campaign traffic or campaign sign-up that day.".into(),
        )),
        Measured::Value(c) => {
            // P2 — a goal the site does not define: the visitors are real,
            // the conversion columns are not measured, and the note says
            // which goal (never a 0).
            if let Some(n) = &c.conversions {
                out.push(Note(format!("Goal conversions: {}", not_measured(n))));
            }
            let goal = |m: &Measured<CampaignGoals>, pick: fn(&CampaignGoals) -> i64| match m {
                Measured::Value(g) => pick(g).to_string(),
                Measured::NotMeasured(_) => "—".to_string(),
            };
            out.push(Table(
                vec![
                    "Source".into(),
                    "Medium".into(),
                    "Campaign".into(),
                    "Visitors".into(),
                    "Pageviews".into(),
                    "Goal: signup".into(),
                    "Goal: subscribe".into(),
                    "Goal: install-copy".into(),
                    "Goal: github".into(),
                    "Server sign-ups".into(),
                ],
                c.rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.source.clone(),
                            r.medium.clone(),
                            r.campaign.clone(),
                            r.visitors.to_string(),
                            r.pageviews.to_string(),
                            goal(&r.goals, |g| g.signup),
                            goal(&r.goals, |g| g.subscribe),
                            goal(&r.goals, |g| g.install_copy),
                            goal(&r.goals, |g| g.github_outbound),
                            r.signups.to_string(),
                        ]
                    })
                    .collect(),
            ));
        }
        Measured::NotMeasured(n) => out.push(Note(not_measured(n))),
    }

    out.push(Heading("Newsletter".into()));
    match &s.newsletter {
        Measured::Value(n) => {
            out.push(Line("New subscribers".into(), fig(&n.new)));
            out.push(Line("Confirmed".into(), fig(&n.confirmed)));
            out.push(Line("Unsubscribed".into(), fig(&n.unsubscribed)));
            if let Some(v) = &n.unsubscribed_via_issue {
                out.push(Line("… through an issue's link".into(), fig(v)));
            }
            if let Some(p) = pct_if_enough(n.confirmed.d28, n.new.d28) {
                out.push(Line("Confirm rate (28d)".into(), format!("{p:.1} %")));
            }
            if !n.by_source.is_empty() {
                out.push(Table(
                    vec![
                        "Source".into(),
                        "New".into(),
                        "Confirmed".into(),
                        "Unsubscribed".into(),
                    ],
                    n.by_source
                        .iter()
                        .map(|r| {
                            vec![
                                r.source.clone(),
                                r.new.to_string(),
                                r.confirmed.to_string(),
                                r.unsubscribed.to_string(),
                            ]
                        })
                        .collect(),
                ));
            }
            if n.issues.is_empty() {
                out.push(Note("No issue was sent that day.".into()));
            } else {
                out.push(Table(
                    vec![
                        "Issue".into(),
                        "Subject".into(),
                        "Sent at".into(),
                        "Recipients".into(),
                        "Accepted".into(),
                        "Failed".into(),
                        "Suppressed".into(),
                        "Stale".into(),
                        "Delivered".into(),
                        "Bounced (hard)".into(),
                        "Complaints".into(),
                        "Unsubscribed via".into(),
                    ],
                    n.issues
                        .iter()
                        .map(|i| {
                            let (delivered, bounced, complaints) = match &i.delivery {
                                Measured::Value(d) => (
                                    d.delivered.to_string(),
                                    format!("{} ({})", d.bounced, d.hard_bounced),
                                    d.complaints.to_string(),
                                ),
                                Measured::NotMeasured(_) => {
                                    let nm = "not measured".to_string();
                                    (nm.clone(), nm.clone(), nm)
                                }
                            };
                            vec![
                                i.slug.clone(),
                                i.subject.clone(),
                                i.sent_at.clone(),
                                i.counts.total.to_string(),
                                i.counts.sent.to_string(),
                                i.counts.failed.to_string(),
                                i.counts.suppressed.to_string(),
                                i.counts.stale.to_string(),
                                delivered,
                                bounced,
                                complaints,
                                i.unsubscribed_via
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "—".into()),
                            ]
                        })
                        .collect(),
                ));
                // Why a delivery cell reads "not measured" (one line per
                // distinct reason, never a 0).
                let mut reasons: Vec<String> = n
                    .issues
                    .iter()
                    .filter_map(|i| match &i.delivery {
                        Measured::NotMeasured(nm) => Some(not_measured(nm)),
                        Measured::Value(_) => None,
                    })
                    .collect();
                reasons.sort();
                reasons.dedup();
                for r in reasons {
                    out.push(Note(format!("Delivery {r}")));
                }
            }
            match &n.delivery {
                Measured::Value(d) => {
                    out.push(Line("Delivered".into(), fig(&d.delivered)));
                    out.push(Line(
                        "Bounced".into(),
                        format!("{} — hard: {}", fig(&d.bounced), fig(&d.hard_bounced)),
                    ));
                    out.push(Line("Dropped".into(), fig(&d.dropped)));
                    out.push(Line("Spam reports".into(), fig(&d.complaints)));
                    out.push(Line("Addresses suppressed".into(), fig(&d.suppressed)));
                }
                Measured::NotMeasured(nm) => {
                    out.push(Line("Delivery".into(), not_measured(nm)));
                }
            }
        }
        Measured::NotMeasured(n) => out.push(Note(not_measured(n))),
    }

    out.push(Heading("Revenue".into()));
    if s.revenue.orgs_by_plan_status.is_empty() {
        out.push(Note("No orgs.".into()));
    } else {
        out.push(Table(
            vec!["Plan".into(), "Subscription".into(), "Orgs".into()],
            s.revenue
                .orgs_by_plan_status
                .iter()
                .map(|r| vec![r.plan.clone(), r.status.clone(), r.orgs.to_string()])
                .collect(),
        ));
    }
    out.push(Line(
        "MRR (ESTIMATE)".into(),
        format!("{} — {}", money(s.revenue.mrr.cents), s.revenue.mrr.basis),
    ));
    // P4 — what Stripe billed, beside (never instead of) the estimate.
    match &s.revenue.billed {
        Measured::Value(b) => {
            if !b.backfilled {
                out.push(Note(format!(
                    "Billed figures cover what Stripe's webhook delivered since {}; \
                     the backfill of Stripe's history has not run.",
                    opt(&b.record_since)
                )));
            }
            if b.mrr.is_empty() {
                out.push(Line("Billed MRR".into(), "0 — no paying org".into()));
            }
            for m in &b.mrr {
                out.push(Line(
                    format!("Billed MRR ({})", m.currency.to_uppercase()),
                    format!(
                        "{} — {} paying org{}",
                        money(m.mrr_cents as f64),
                        m.paying_orgs,
                        if m.paying_orgs == 1 { "" } else { "s" }
                    ),
                ));
            }
            out.push(Line("Invoices paid".into(), fig(&b.invoices_paid)));
            for c in &b.billed {
                out.push(Line(
                    format!("Billed ({})", c.currency.to_uppercase()),
                    format!(
                        "{} (7d {} · 28d {})",
                        money(c.cents.day as f64),
                        money(c.cents.d7 as f64),
                        money(c.cents.d28 as f64)
                    ),
                ));
            }
            out.push(Line("Failed payments".into(), fig(&b.payment_failures)));
            out.push(Line("First payments".into(), fig(&b.new_paying_orgs)));
            out.push(Line("Cancellations".into(), fig(&b.cancellations)));
            out.push(Line("Trials started".into(), fig(&b.trials_started)));
        }
        Measured::NotMeasured(n) => out.push(Line("Billed".into(), not_measured(n))),
    }
    if let Some(u) = &s.revenue.upgrade_intent {
        out.push(Line("Plan-limit collisions".into(), fig(&u.collisions)));
        out.push(Line("… orgs that hit a limit".into(), fig(&u.orgs)));
        if !u.top.is_empty() {
            out.push(Table(
                vec!["Org".into(), "Limit".into(), "Collisions (28d)".into()],
                u.top
                    .iter()
                    .map(|c| vec![c.name.clone(), c.limit.clone(), c.count.to_string()])
                    .collect(),
            ));
        }
    }

    out.push(Heading("Quality".into()));
    match &s.quality.remote {
        Measured::Value(q) => {
            // P9a — the sessions requested, by what became of them.
            out.push(Line("Sessions requested".into(), fig(&q.requested)));
            out.push(Line(
                "… reached Active".into(),
                format!(
                    "{} — share {}",
                    fig(&q.reached_active),
                    rate_fig(&q.reached_share, &share)
                ),
            ));
            out.push(Line("… never reached Active".into(), fig(&q.not_reached)));
            out.push(Line("Sessions ended".into(), fig(&q.ended)));
            out.push(Line("Hang-ups".into(), fig(&q.hangups)));
            out.push(Line("Refusals".into(), fig(&q.refusals)));
            out.push(Line("Failures".into(), fig(&q.failures)));
            if let Some(p) = pct_if_enough(q.failures.d28, q.ended.d28) {
                out.push(Line("Failure share (28d)".into(), format!("{p:.1} %")));
            }
            if !q.by_end_reason.is_empty() {
                out.push(Table(
                    vec!["End reason".into(), "Class".into(), "Sessions".into()],
                    q.by_end_reason
                        .iter()
                        .map(|r| vec![r.reason.clone(), r.class.clone(), r.count.to_string()])
                        .collect(),
                ));
            }
            out.push(Line(
                "Session duration (Active, ended)".into(),
                dist_fig(&q.duration_ms, &ms_label),
            ));
            out.push(Line(
                "Peak frame rate".into(),
                dist_fig(&q.peak_fps, &|v| format!("{v} fps")),
            ));
            out.push(Line(
                "Average RTT".into(),
                dist_fig(&q.avg_rtt_ms, &ms_label),
            ));
        }
        Measured::NotMeasured(n) => out.push(Line("Remote sessions".into(), not_measured(n))),
    }
    // P9a — FR-22's time to first frame, from the frozen daily rows.
    match &s.quality.ttff {
        Measured::Value(t) => {
            let ms = |v: Option<i64>| opt_unit(v, &ms_label);
            out.push(Line(
                "Time to first frame (foreground, first attempts)".into(),
                format!(
                    "p50 {} · p90 {} (n {}) · 7d ≈ p50 {} · p90 {} (n {}, {} days) · 28d ≈ p50 {} · p90 {} (n {}, {} days)",
                    ms(t.p50_ms.day),
                    ms(t.p90_ms.day),
                    t.n.day,
                    ms(t.p50_ms.d7),
                    ms(t.p90_ms.d7),
                    t.n.d7,
                    t.days_measured.d7,
                    ms(t.p50_ms.d28),
                    ms(t.p90_ms.d28),
                    t.n.d28,
                    t.days_measured.d28,
                ),
            ));
            out.push(Line(
                "… records set aside".into(),
                format!(
                    "hidden tab {} · later attempts {}",
                    fig(&t.hidden),
                    fig(&t.later_attempts)
                ),
            ));
        }
        Measured::NotMeasured(n) => out.push(Line("Time to first frame".into(), not_measured(n))),
    }
    match &s.quality.crashes {
        Measured::Value(c) => {
            out.push(Line("Agent crashes".into(), fig(&c.total)));
            out.push(Line(
                "Device-days (devices online)".into(),
                fig(&c.device_days),
            ));
            out.push(Line(
                "Crashes per 100 device-days".into(),
                rate_fig(&c.per_100_device_days, &|v| format!("{v:.2}")),
            ));
            if !c.by_agent_version.is_empty() {
                out.push(Table(
                    vec!["Agent version".into(), "Crashes".into()],
                    c.by_agent_version
                        .iter()
                        .map(|k| vec![k.key.clone(), k.count.to_string()])
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Agent crashes".into(), not_measured(n))),
    }
    // P9a — the day by agent version, from the frozen rows.
    match &s.quality.by_agent_version {
        Measured::Value(rows) if !rows.is_empty() => out.push(Table(
            vec![
                "Agent version".into(),
                "Requested".into(),
                "Active".into(),
                "Never active".into(),
                "Failures".into(),
                "TTFF p50 · p90 (n)".into(),
                "Crashes".into(),
                "Device-days".into(),
            ],
            rows.iter()
                .map(|r| {
                    vec![
                        r.agent_version.clone(),
                        r.requested.to_string(),
                        r.reached_active.to_string(),
                        r.not_reached.to_string(),
                        r.failures.to_string(),
                        match r.ttff_n {
                            Some(n) if n > 0 => format!(
                                "{} · {} ({n})",
                                opt_unit(r.ttff_p50_ms, &ms_label),
                                opt_unit(r.ttff_p90_ms, &ms_label)
                            ),
                            Some(_) => "no sample".into(),
                            None => "not measured".into(),
                        },
                        opt_count(r.crashes),
                        opt_count(r.device_days),
                    ]
                })
                .collect(),
        )),
        Measured::Value(_) => out.push(Note(
            "No session, crash or online device on record for the day, by version.".into(),
        )),
        Measured::NotMeasured(n) => out.push(Line("By agent version".into(), not_measured(n))),
    }
    // P9b — what people answered the post-session prompt.
    match &s.quality.ratings {
        Measured::Value(r) => {
            out.push(Line("Session ratings: thumbs up".into(), fig(&r.up)));
            out.push(Line("Session ratings: thumbs down".into(), fig(&r.down)));
            out.push(Line(
                "… share up (28d)".into(),
                r.up_share_28d
                    .map(share)
                    .unwrap_or_else(|| format!("— (n < {SMALL_N} answers)")),
            ));
            if !r.reasons_28d.is_empty() {
                out.push(Table(
                    vec!["Reason (28d)".into(), "Times ticked".into()],
                    r.reasons_28d
                        .iter()
                        .map(|k| vec![k.key.clone(), k.count.to_string()])
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Session ratings".into(), not_measured(n))),
    }
    out.push(Note(
        "Time to first frame is FR-22's browser record (a foreground tab, a first attempt, no \
         drop), frozen nightly from agent_logs before its 7-day horizon; the 7- and 28-day \
         values are estimates from the daily histograms. A device's version is read from its \
         own logs of the day, else from its device row. A rate appears only from 30. Ratings \
         are what people answered the viewer's prompt after a session of 30 s or more — at most \
         once a day each, a thumb and reason chips, never text."
            .into(),
    ));

    out.push(Heading("Social reach".into()));
    match &s.social {
        Measured::Value(soc) => {
            if !soc.posts_by_platform.is_empty() {
                out.push(Table(
                    vec!["Platform".into(), "Posts published".into()],
                    soc.posts_by_platform
                        .iter()
                        .map(|p| vec![p.platform.clone(), fig(&p.posts)])
                        .collect(),
                ));
            }
            if !soc.snapshots.is_empty() {
                out.push(Table(
                    vec![
                        "Platform".into(),
                        "Campaign".into(),
                        "Age".into(),
                        "The platform's own numbers".into(),
                    ],
                    soc.snapshots
                        .iter()
                        .map(|sn| {
                            vec![
                                sn.platform.clone(),
                                sn.campaign
                                    .clone()
                                    .unwrap_or_else(|| sn.platform_id.clone()),
                                sn.snapshot.clone(),
                                sn.metrics
                                    .iter()
                                    .take(4)
                                    .map(|(k, v)| format!("{k} {v}"))
                                    .collect::<Vec<_>>()
                                    .join(" · "),
                            ]
                        })
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Social reach".into(), not_measured(n))),
    }

    github_blocks(&mut out, &s.github);

    search_blocks(&mut out, &s.search);

    alert_blocks(&mut out, &s.alerts, "the day");

    out.push(Note(format!(
        "Excluded from every number above: {} users and {} orgs (platform admins, the orgs they own, \
         and the explicit exclusion list). This digest carries no personal addresses, names or IPs. \
         Day {} (UTC), attempt {}.",
        doc.excluded.users, doc.excluded.tenants, doc.day, doc.attempts
    )));
    out
}

/// P7 — a search row as table cells: the key, clicks, impressions, and the
/// position only where the reader gave one (from 30 impressions).
fn search_cells(r: &super::search::SearchRow) -> Vec<String> {
    vec![
        r.key.clone(),
        r.cell.clicks.to_string(),
        r.cell.impressions.to_string(),
        r.cell
            .position
            .map(|p| format!("{p:.1}"))
            .unwrap_or_else(|| "—".into()),
    ]
}

/// P7 — the Search section: Google over its final days, Bing at its own
/// grain. Shared by the daily digest and the weekly roll-up.
pub(crate) fn search_blocks(out: &mut Vec<Block>, s: &Measured<super::search::SearchSection>) {
    use Block::*;
    out.push(Heading("Search".into()));
    let s = match s {
        Measured::Value(s) => s,
        Measured::NotMeasured(n) => {
            out.push(Line("Search".into(), not_measured(n)));
            return;
        }
    };
    match &s.google {
        Measured::Value(g) => {
            out.push(Line(
                "Google, final through".into(),
                format!("{} (Search Console's own day)", g.through),
            ));
            out.push(Line("Clicks".into(), fig_over(&g.clicks, &g.days)));
            out.push(Line(
                "Impressions".into(),
                fig_over(&g.impressions, &g.days),
            ));
            out.push(Line("Days pulled".into(), fig(&g.days)));
            if let (Some(ctr), Some(pos)) = (g.d28.ctr, g.d28.position) {
                out.push(Line(
                    "CTR · average position (28d)".into(),
                    format!("{:.1} % · {pos:.1}", ctr * 100.0),
                ));
            }
            for (title, rows) in [
                ("Top queries (7d)", &g.top_queries_7d),
                ("Top pages (7d)", &g.top_pages_7d),
            ] {
                if !rows.is_empty() {
                    out.push(Table(
                        vec![
                            title.into(),
                            "Clicks".into(),
                            "Impressions".into(),
                            "Position".into(),
                        ],
                        rows.iter().map(search_cells).collect(),
                    ));
                }
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Google".into(), not_measured(n))),
    }
    match &s.bing {
        Measured::Value(b) => {
            out.push(Line(
                "Bing, daily through".into(),
                format!(
                    "{} (Bing's own day; read by the pull for {})",
                    b.through, b.pulled
                ),
            ));
            out.push(Line("Bing clicks".into(), fig(&b.clicks)));
            out.push(Line("Bing impressions".into(), fig(&b.impressions)));
            if let Some(week) = &b.week {
                for (title, rows) in [
                    (
                        format!("Bing queries, its week of {week}"),
                        &b.top_queries_week,
                    ),
                    (format!("Bing pages, its week of {week}"), &b.top_pages_week),
                ] {
                    if !rows.is_empty() {
                        out.push(Table(
                            vec![
                                title,
                                "Clicks".into(),
                                "Impressions".into(),
                                "Position".into(),
                            ],
                            rows.iter().map(search_cells).collect(),
                        ));
                    }
                }
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Bing".into(), not_measured(n))),
    }
    out.push(Note(
        "Google's numbers are its final days only — Search Console settles two or three days \
         behind — on its own (Pacific) dates; a position is weighted by impressions, and a CTR \
         or a position appears only from 30 impressions. Bing's queries and pages come in Bing's \
         weekly buckets and are never relabelled as 7 days."
            .into(),
    ));
}

/// P7 — a change as text: signed, or `—` when a snapshot it needs is
/// missing (never a 0 for "not measured").
fn delta_str(d: Option<i64>) -> String {
    match d {
        Some(n) if n > 0 => format!("+{n}"),
        Some(n) => n.to_string(),
        None => "—".into(),
    }
}

fn deltas(d: &super::github::Delta) -> String {
    format!(
        "day {} · 7d {} · 28d {}",
        delta_str(d.day),
        delta_str(d.d7),
        delta_str(d.d28)
    )
}

/// P7 — a traffic figure per window over the days pulled: `—` for a window
/// with no measured day, never a 0 it did not count.
pub fn fig_over(f: &Figure, measured_days: &Figure) -> String {
    let cell = |n: i64, days: i64| {
        if days == 0 {
            "—".to_string()
        } else {
            n.to_string()
        }
    };
    format!(
        "{} (7d {} · 28d {})",
        cell(f.day, measured_days.day),
        cell(f.d7, measured_days.d7),
        cell(f.d28, measured_days.d28)
    )
}

/// P7 — the repository: counters at their snapshot with the changes, the
/// week's downloads by release and flavour, and the traffic with its
/// measured days. Shared by the daily digest and the weekly roll-up.
pub(crate) fn github_blocks(out: &mut Vec<Block>, g: &super::github::GithubSection) {
    use Block::*;
    out.push(Heading("GitHub".into()));
    match &g.counters {
        Measured::Value(c) => {
            out.push(Line(
                "Snapshot".into(),
                format!("{} at the close of {} (UTC)", c.repo, c.at),
            ));
            let lower = if c.downloads_truncated {
                ", a lower bound: the release listing hit the page bound"
            } else {
                ""
            };
            for (label, now, d) in [
                ("Stars".to_string(), c.stars, &c.stars_delta),
                ("Forks".to_string(), c.forks, &c.forks_delta),
                ("Watchers".to_string(), c.watchers, &c.watchers_delta),
                (
                    format!("Release downloads (all time{lower})"),
                    c.downloads,
                    &c.downloads_delta,
                ),
                (
                    format!("Helper-release downloads (CI's vendored builds{lower})"),
                    c.helper_downloads,
                    &c.helper_downloads_delta,
                ),
            ] {
                out.push(Line(label, format!("{now} ({})", deltas(d))));
            }
            for (title, list) in [
                ("Downloads in 7 days, by release", &c.top_releases_7d),
                ("Downloads in 7 days, by flavour", &c.top_flavours_7d),
            ] {
                match list {
                    Measured::Value(rows) if !rows.is_empty() => out.push(Table(
                        vec![title.into(), "Downloads".into()],
                        rows.iter()
                            .map(|k| vec![k.key.clone(), k.count.to_string()])
                            .collect(),
                    )),
                    Measured::Value(_) => out.push(Line(title.into(), "none".into())),
                    Measured::NotMeasured(n) => out.push(Line(title.into(), not_measured(n))),
                }
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Counters".into(), not_measured(n))),
    }
    match &g.traffic {
        Measured::Value(t) => {
            out.push(Line("Views".into(), fig_over(&t.views, &t.measured_days)));
            out.push(Line(
                "Clones (mostly CI's checkouts, not people)".into(),
                fig_over(&t.clones, &t.measured_days),
            ));
            out.push(Line("Days measured".into(), fig(&t.measured_days)));
            if let Some(as_of) = &t.referrers_as_of
                && !t.referrers.is_empty()
            {
                out.push(Table(
                    vec![
                        format!("Referrers (GitHub's 14 days, read after {as_of})"),
                        "Views".into(),
                        "Uniques".into(),
                    ],
                    t.referrers
                        .iter()
                        .map(|r| {
                            vec![
                                r.referrer.clone(),
                                r.views.to_string(),
                                r.uniques.to_string(),
                            ]
                        })
                        .collect(),
                ));
            }
        }
        Measured::NotMeasured(n) => out.push(Line("Traffic".into(), not_measured(n))),
    }
    out.push(Note(
        "A change is the difference of two daily snapshots; — means a snapshot it needs is \
         missing, or a traffic window with no day pulled. GitHub counts every download of a \
         release asset, the fleet's self-updates included: downloads are distribution, not \
         installs. Release downloads are the product's (the daemon, the wizard, the tunnel CLI), \
         without the signature and checksum files fetched beside each package; the vendored \
         builds our own CI downloads are counted apart. A release whose total went down (an asset \
         re-uploaded) counts nothing that day."
            .into(),
    ));
}

/// P10 — one alert row as a table line: rule, key, fired, cleared, and
/// its detail as `k v` pairs.
fn alert_cells(a: &AlertRow) -> Vec<String> {
    vec![
        a.rule.clone(),
        a.key.clone(),
        a.fired_at.clone(),
        a.cleared_at.clone().unwrap_or_else(|| "open".into()),
        a.detail
            .iter()
            .map(|(k, v)| format!("{k} {}", bson_text(v)))
            .collect::<Vec<_>>()
            .join(" · "),
    ]
}

/// A detail value as text (days, numbers, names — never a person).
fn bson_text(v: &bson::Bson) -> String {
    match v {
        bson::Bson::String(s) => s.clone(),
        bson::Bson::Document(d) => d
            .iter()
            .map(|(k, v)| format!("{k}={}", bson_text(v)))
            .collect::<Vec<_>>()
            .join(","),
        bson::Bson::Array(a) => a.iter().map(bson_text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// P10 — the alerts section of a digest or a roll-up.
fn alert_blocks(out: &mut Vec<Block>, alerts: &Measured<AlertsSection>, window: &str) {
    use Block::*;
    out.push(Heading("Alerts".into()));
    match alerts {
        Measured::NotMeasured(n) => out.push(Line("Alerts".into(), not_measured(n))),
        Measured::Value(a) => {
            out.push(Line("Open now".into(), a.open.len().to_string()));
            out.push(Line(
                format!("Fired during {window}"),
                a.fired.len().to_string(),
            ));
            out.push(Line(
                format!("Cleared during {window}"),
                a.cleared.len().to_string(),
            ));
            let rows: Vec<&AlertRow> = a
                .open
                .iter()
                .chain(a.fired.iter().filter(|f| {
                    !a.open
                        .iter()
                        .any(|o| o.fired_at == f.fired_at && o.rule == f.rule && o.key == f.key)
                }))
                .chain(a.cleared.iter().filter(|c| {
                    !a.fired
                        .iter()
                        .any(|f| f.fired_at == c.fired_at && f.rule == c.rule && f.key == c.key)
                }))
                .collect();
            if !rows.is_empty() {
                out.push(Table(
                    vec![
                        "Rule".into(),
                        "Key".into(),
                        "Fired".into(),
                        "Cleared".into(),
                        "Detail".into(),
                    ],
                    rows.iter().map(|a| alert_cells(a)).collect(),
                ));
            }
        }
    }
}

/// P10 — a week figure: the week, the week before, the four-week mean.
pub fn wfig(f: &WeekFigure) -> String {
    match f.w4_avg {
        Some(avg) => format!("{} (prev {} · 4w avg {:.1})", f.week, f.prev_week, avg),
        None => format!("{} (prev {})", f.week, f.prev_week),
    }
}

/// A step's count, pending, settled, and its rate only at n ≥ 30.
fn step(s: &StepCounts) -> String {
    match pct_if_enough(s.count as i64, s.settled as i64) {
        Some(p) => format!(
            "{} ({p:.1} % of {} settled · {} pending)",
            s.count, s.settled, s.pending
        ),
        None => format!(
            "{} ({} settled, n < {SMALL_N} · {} pending)",
            s.count, s.settled, s.pending
        ),
    }
}

fn opt_step(s: &Option<StepCounts>, missing: &str) -> String {
    match s {
        Some(s) => step(s),
        None => format!("not measured — {missing}"),
    }
}

fn rate(r: &Option<Rate>) -> String {
    match r {
        Some(Rate { value: Some(v), n }) => format!("{:.1} % (n {n})", v * 100.0),
        Some(Rate { value: None, n }) => format!("n {n} < {SMALL_N}"),
        None => "—".into(),
    }
}

fn web(w: &Measured<WebCells>) -> String {
    match w {
        Measured::Value(c) => format!(
            "{} visitors · {} visits · {} pageviews · {} reads",
            c.visitors, c.visits, c.pageviews, c.reads
        ),
        Measured::NotMeasured(n) => not_measured(n),
    }
}

/// P10 — the weekly roll-up as blocks, in the order the operator reads
/// them: the headline against its baselines, the funnel, the cohort
/// lines, the tables, the alerts.
pub fn weekly_blocks(doc: &DigestDoc, s: &WeeklySections) -> Vec<Block> {
    use Block::*;
    let mut out = Vec::new();
    let h = &s.headline;

    out.push(Heading("Headline".into()));
    out.push(Line("Sign-ups".into(), wfig(&h.signups)));
    out.push(Line("Orgs created".into(), wfig(&h.orgs_created)));
    out.push(Line(
        "Devices enrolled".into(),
        measured(&h.devices_enrolled, wfig),
    ));
    out.push(Line(
        "Weekly active orgs (north star)".into(),
        measured(&h.active_orgs, wfig),
    ));
    match &h.website {
        Measured::Value(w) => {
            out.push(Line("Website visitors".into(), wfig(&w.visitors)));
            out.push(Line("Website visits".into(), wfig(&w.visits)));
            out.push(Line("Website pageviews".into(), wfig(&w.pageviews)));
            out.push(Line("Website reads".into(), wfig(&w.reads)));
        }
        Measured::NotMeasured(n) => out.push(Line("Website".into(), not_measured(n))),
    }

    out.push(Heading("The account funnel — the week's sign-ups".into()));
    let f = &s.funnel;
    out.push(Line("Sign-ups".into(), f.steps.signup.to_string()));
    out.push(Line(
        format!("Org created (≤ {} d)", f.windows.org_days),
        step(&f.steps.org_created),
    ));
    out.push(Line(
        format!("Activated (device ≤ {} d)", f.windows.activation_days),
        opt_step(
            &f.steps.activated,
            f.not_measured
                .get("activated")
                .map(String::as_str)
                .unwrap_or("not mounted"),
        ),
    ));
    out.push(Line(
        format!("First value (≤ {} d)", f.windows.value_days),
        opt_step(
            &f.steps.first_value,
            f.not_measured
                .get("first_value")
                .map(String::as_str)
                .unwrap_or("not mounted"),
        ),
    ));
    // P4 — paid as of now, no window; `None` where billing is not on
    // record (the funnel names why).
    out.push(Line(
        "Paid (so far)".into(),
        opt_step(
            &f.steps.paid,
            f.not_measured
                .get("paid")
                .map(String::as_str)
                .unwrap_or("billing not on record"),
        ),
    ));
    if let Some(p) = &f.time_to_value.first_device {
        out.push(Line(
            "Sign-up → first device".into(),
            match p.median_h {
                Some(m) => format!("median {m:.1} h (n {})", p.n),
                None => format!("n {}", p.n),
            },
        ));
    }
    if !f.buckets.is_empty() {
        out.push(Table(
            vec![
                "Source".into(),
                "Sign-ups".into(),
                "Org created".into(),
                "Activated".into(),
                "First value".into(),
            ],
            f.buckets
                .iter()
                .map(|b| {
                    vec![
                        b.key.clone().unwrap_or_else(|| "(none)".into()),
                        b.signups.to_string(),
                        b.org_created.count.to_string(),
                        b.activated
                            .as_ref()
                            .map(|s| s.count.to_string())
                            .unwrap_or_else(|| "—".into()),
                        b.first_value
                            .as_ref()
                            .map(|s| s.count.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ]
                })
                .collect(),
        ));
    }

    out.push(Heading("Cohorts — weekly active orgs".into()));
    match (&s.cohorts.wao, &s.cohorts.not_measured) {
        (Some(wao), _) => out.push(Table(
            vec!["Week".into(), "Active orgs".into(), "".into()],
            wao.iter()
                .map(|w| {
                    vec![
                        w.week.clone(),
                        w.active_orgs.to_string(),
                        if w.partial {
                            "partial".into()
                        } else {
                            String::new()
                        },
                    ]
                })
                .collect(),
        )),
        (None, reason) => out.push(Line(
            "Weekly active orgs".into(),
            format!(
                "not measured — {}",
                reason.clone().unwrap_or_else(|| "no value module".into())
            ),
        )),
    }
    if let Some(rows) = &s.cohorts.cohorts {
        let cell = |r: &super::cohorts::CohortRow, k: usize| {
            r.active
                .get(k)
                .copied()
                .flatten()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into())
        };
        out.push(Table(
            vec![
                "Cohort".into(),
                "Orgs".into(),
                "W1".into(),
                "W4".into(),
                "W12".into(),
            ],
            rows.iter()
                .map(|r| {
                    vec![
                        r.week.clone(),
                        r.size.to_string(),
                        cell(r, 1),
                        cell(r, 4),
                        cell(r, 12),
                    ]
                })
                .collect(),
        ));
    }

    out.push(Heading("Campaigns by source — the week".into()));
    let c = &s.campaigns;
    out.push(Line(
        "Website (the week, unique)".into(),
        web(&c.totals.web),
    ));
    out.push(Line(
        "Sign-ups (with a campaign key)".into(),
        format!("{} ({})", c.totals.signups, c.totals.keyed_signups),
    ));
    out.push(Line(
        "Coverage".into(),
        match &c.totals.coverage {
            Measured::Value(cov) => match cov.ratio {
                Some(r) => format!(
                    "{:.1} % ({} goals ÷ {} sign-ups)",
                    r * 100.0,
                    cov.purestat_signup_goals,
                    cov.server_signups
                ),
                None => format!(
                    "{} goals ÷ {} sign-ups (n < {})",
                    cov.purestat_signup_goals, cov.server_signups, cov.n_floor
                ),
            },
            Measured::NotMeasured(n) => not_measured(n),
        },
    ));
    if !c.rows.is_empty() {
        out.push(Table(
            vec![
                "Source".into(),
                "Visitors".into(),
                "Reads".into(),
                "Sign-up goals".into(),
                "Sign-ups".into(),
                "Activated".into(),
                "Sign-up / visitor".into(),
            ],
            c.rows
                .iter()
                .map(|r| {
                    let (visitors, reads, goals) = match &r.web {
                        Measured::Value(w) => (
                            w.visitors.to_string(),
                            w.reads.to_string(),
                            match &w.goals {
                                Measured::Value(g) => g.signup.to_string(),
                                Measured::NotMeasured(_) => "not measured".into(),
                            },
                        ),
                        Measured::NotMeasured(_) => (
                            "not measured".into(),
                            "not measured".into(),
                            "not measured".into(),
                        ),
                    };
                    vec![
                        r.key.source.clone(),
                        visitors,
                        reads,
                        goals,
                        r.signups.to_string(),
                        r.activated
                            .as_ref()
                            .map(|s| s.count.to_string())
                            .unwrap_or_else(|| "—".into()),
                        rate(&r.rates.signup_per_visitor),
                    ]
                })
                .collect(),
        ));
    }

    out.push(Heading("Channels — posts published in the week".into()));
    let with_posts: Vec<_> = s
        .channels
        .platforms
        .iter()
        .filter(|p| !p.posts.is_empty())
        .collect();
    if with_posts.is_empty() {
        out.push(Line("Posts".into(), "none pushed for the week".into()));
    } else {
        out.push(Table(
            vec![
                "Platform".into(),
                "Posts".into(),
                "Reach (latest age)".into(),
                "Web".into(),
                "Sign-ups".into(),
            ],
            with_posts
                .iter()
                .map(|p| match &p.summary {
                    Measured::Value(sm) => vec![
                        p.platform.clone(),
                        sm.posts.to_string(),
                        match &sm.reach {
                            Measured::Value(at) => at
                                .last()
                                .map(|r| {
                                    format!(
                                        "{}: {}",
                                        r.snapshot,
                                        r.metrics
                                            .iter()
                                            .take(3)
                                            .map(|(k, v)| format!("{k} {v}"))
                                            .collect::<Vec<_>>()
                                            .join(" · ")
                                    )
                                })
                                .unwrap_or_else(|| "—".into()),
                            Measured::NotMeasured(n) => not_measured(n),
                        },
                        web(&sm.web),
                        sm.signups.to_string(),
                    ],
                    Measured::NotMeasured(n) => vec![
                        p.platform.clone(),
                        p.posts.len().to_string(),
                        not_measured(n),
                        String::new(),
                        String::new(),
                    ],
                })
                .collect(),
        ));
    }

    out.push(Heading("Newsletter — the week".into()));
    let n = &s.newsletter;
    match (&n.not_measured, &n.list) {
        (Some(reason), _) => out.push(Line("Newsletter".into(), not_measured(reason))),
        (None, Some(list)) => {
            out.push(Line(
                "New · confirmed · unsubscribed".into(),
                format!(
                    "{} · {} · {} (via an issue's link {})",
                    list.totals.new,
                    list.totals.confirmed,
                    list.totals.unsubscribed,
                    list.totals.unsubscribed_via_issue
                ),
            ));
            out.push(Line(
                "List now".into(),
                format!(
                    "{} mailable · {} pending · {} unsubscribed · {} suppressed",
                    list.size.mailable,
                    list.size.pending,
                    list.size.unsubscribed,
                    list.size.suppressed
                ),
            ));
        }
        (None, None) => out.push(Line("Newsletter".into(), "no list read".into())),
    }
    if !n.issues.is_empty() {
        out.push(Table(
            vec![
                "Issue".into(),
                "Sent".into(),
                "Accepted".into(),
                "Delivered".into(),
                "Bounced".into(),
                "Unsubscribed via".into(),
                "Visitors".into(),
                "Sign-ups".into(),
            ],
            n.issues
                .iter()
                .map(|i| {
                    let (delivered, bounced) = match &i.delivery {
                        Measured::Value(d) => (d.delivered.to_string(), d.bounced.to_string()),
                        Measured::NotMeasured(_) => ("not measured".into(), "not measured".into()),
                    };
                    vec![
                        i.slug.clone(),
                        i.sent_at.clone().unwrap_or_else(|| "—".into()),
                        i.ledger.accepted.to_string(),
                        delivered,
                        bounced,
                        i.unsubscribed_via.to_string(),
                        match &i.web {
                            Measured::Value(w) => w.visitors.to_string(),
                            Measured::NotMeasured(_) => "not measured".into(),
                        },
                        i.signups.to_string(),
                    ]
                })
                .collect(),
        ));
    }

    quality_blocks(&mut out, &s.quality);

    // P7 — the repository at Sunday's snapshot: its 7-day changes are the
    // week's; search over the windows ending on Sunday's newest final day.
    github_blocks(&mut out, &s.github);
    search_blocks(&mut out, &s.search);

    alert_blocks(&mut out, &s.alerts, "the week");

    out.push(Note(format!(
        "Excluded from every number above: {} users and {} orgs (platform admins, the orgs they own, \
         and the explicit exclusion list). This roll-up carries no personal addresses, names or IPs. \
         Week {} ({} → {}, UTC), attempt {}.",
        doc.excluded.users, doc.excluded.tenants, h.week, h.since, h.until, doc.attempts
    )));
    out
}

/// P9a — one version's (or every version's) lines of a quality report.
fn version_lines(out: &mut Vec<Block>, v: &VersionQuality) {
    use Block::*;
    match &v.sessions {
        Some(s) => {
            out.push(Line("Sessions requested".into(), s.requested.to_string()));
            out.push(Line(
                "… reached Active".into(),
                format!(
                    "{} ({})",
                    s.reached_active,
                    s.reached_share
                        .map(share)
                        .unwrap_or_else(|| format!("n < {SMALL_N}"))
                ),
            ));
            out.push(Line(
                "… never reached Active".into(),
                s.not_reached.to_string(),
            ));
            out.push(Line(
                "… pending at the freeze".into(),
                s.pending.to_string(),
            ));
            if !s.by_end_reason.is_empty() {
                out.push(Table(
                    vec![
                        "Reached Active".into(),
                        "End reason".into(),
                        "Sessions".into(),
                    ],
                    s.by_end_reason
                        .iter()
                        .map(|c| {
                            vec![
                                if c.reached_active { "yes" } else { "no" }.into(),
                                c.reason.clone(),
                                c.count.to_string(),
                            ]
                        })
                        .collect(),
                ));
            }
            out.push(Line(
                "Session duration (Active, ended)".into(),
                pooled_label(&s.duration_ms, &ms_label),
            ));
            out.push(Line(
                "Peak frame rate".into(),
                pooled_label(&s.peak_fps, &|v| format!("{v} fps")),
            ));
            out.push(Line(
                "Average RTT".into(),
                pooled_label(&s.avg_rtt_ms, &ms_label),
            ));
            // P9c — the Active sessions by the carrier they rode: recorded,
            // never chosen; a session with none is `unknown`, never direct.
            if !s.by_carrier.is_empty() {
                out.push(Table(
                    vec![
                        "Carrier".into(),
                        "Active".into(),
                        "Duration".into(),
                        "Avg RTT".into(),
                    ],
                    s.by_carrier
                        .iter()
                        .map(|c| {
                            vec![
                                c.carrier.clone(),
                                c.reached_active.to_string(),
                                pooled_label(&c.duration_ms, &ms_label),
                                pooled_label(&c.avg_rtt_ms, &ms_label),
                            ]
                        })
                        .collect(),
                ));
            }
        }
        None => out.push(Line(
            "Sessions".into(),
            "not measured — remote module not mounted".into(),
        )),
    }
    match &v.ttff {
        Some(t) => out.push(Line(
            "Time to first frame (foreground, first attempts)".into(),
            format!(
                "{}p50 {} · p90 {} (n {}, {} days measured) · set aside: hidden tab {} · later attempts {}",
                if t.exact { "" } else { "≈ " },
                opt_unit(t.p50_ms, &ms_label),
                opt_unit(t.p90_ms, &ms_label),
                t.n,
                t.days_measured,
                t.hidden,
                t.later_attempts
            ),
        )),
        None => out.push(Line(
            "Time to first frame".into(),
            "not measured — no frozen day with its connect records still complete".into(),
        )),
    }
    out.push(Line("Agent crashes".into(), opt_count(v.crashes)));
    out.push(Line(
        "Device-days (devices online)".into(),
        opt_count(v.device_days),
    ));
    out.push(Line(
        "Crashes per 100 device-days".into(),
        v.crashes_per_100_device_days
            .map(|r| format!("{r:.2}"))
            .unwrap_or_else(|| format!("— (n < {SMALL_N} device-days)")),
    ));
}

/// P9a — the weekly roll-up's quality section: the Quality view's own
/// report for Mon–Sun, from the frozen daily rows.
fn quality_blocks(out: &mut Vec<Block>, q: &QualityReport) {
    use Block::*;
    out.push(Heading("Remote-desktop quality — the week".into()));
    if let Some(n) = &q.not_measured {
        out.push(Line("Quality".into(), not_measured(n)));
        return;
    }
    out.push(Line(
        "Frozen days".into(),
        format!("{} of {}", q.frozen_days, q.days),
    ));
    if let Some(t) = &q.totals {
        version_lines(out, t);
    }
    if !q.by_agent_version.is_empty() {
        out.push(Table(
            vec![
                "Agent version".into(),
                "Requested".into(),
                "Active".into(),
                "Never active".into(),
                "TTFF p50 · p90 (n)".into(),
                "Crashes".into(),
                "Device-days".into(),
                "Per 100 device-days".into(),
            ],
            q.by_agent_version
                .iter()
                .map(|v| {
                    let s = v.sessions.as_ref();
                    vec![
                        v.agent_version.clone(),
                        s.map(|s| s.requested.to_string()).unwrap_or_default(),
                        s.map(|s| s.reached_active.to_string()).unwrap_or_default(),
                        s.map(|s| s.not_reached.to_string()).unwrap_or_default(),
                        match &v.ttff {
                            Some(t) if t.n > 0 => format!(
                                "{}{} · {} ({})",
                                if t.exact { "" } else { "≈ " },
                                opt_unit(t.p50_ms, &ms_label),
                                opt_unit(t.p90_ms, &ms_label),
                                t.n
                            ),
                            Some(_) => "no sample".into(),
                            None => "not measured".into(),
                        },
                        opt_count(v.crashes),
                        opt_count(v.device_days),
                        v.crashes_per_100_device_days
                            .map(|r| format!("{r:.2}"))
                            .unwrap_or_else(|| "—".into()),
                    ]
                })
                .collect(),
        ));
    }
    out.push(Note(
        "Time to first frame is FR-22's browser record (a foreground tab, a first attempt, no \
         drop), frozen nightly from agent_logs before its 7-day horizon; a value marked ≈ is \
         estimated from the daily histograms. A device's version is read from its own logs of \
         the day, else from its device row. A rate appears only from 30."
            .into(),
    ));
}

/// P10 — an alert's mail: the rule, the key, the detail, and how many
/// alerts are open.
pub fn alert_mail(a: &GrowthAlert, open_now: usize) -> (String, String, String) {
    use Block::*;
    let fired = a.fired_at.try_to_rfc3339_string().unwrap_or_default();
    let mut blocks = vec![
        Heading(format!("{}: {}", a.rule, a.key)),
        Line("Fired at".into(), fired.clone()),
    ];
    for (k, v) in &a.detail {
        blocks.push(Line(k.clone(), bson_text(v)));
    }
    blocks.push(Note(format!(
        "{open_now} alert(s) open now. This alert is mailed at most once per rule and key per day; \
         it clears on its own when the condition goes away. See /observability/growth."
    )));
    let title = alert_subject(a);
    (
        title.clone(),
        html_document(&title, "", &blocks),
        text_document(&title, "", &blocks),
    )
}

/// The HTML body. Every string escaped; inline styles only (mail clients).
pub fn render_html(doc: &DigestDoc, s: &Sections) -> String {
    html_document(
        &format!("Roomler daily digest — {}", doc.day),
        &format!(
            "Every count is the day, then the trailing 7 and 28 days. Rates appear only above n = {SMALL_N}."
        ),
        &blocks(doc, s),
    )
}

/// The plain-text body: the same blocks, as text.
pub fn render_text(doc: &DigestDoc, s: &Sections) -> String {
    text_document(
        &format!("Roomler daily digest — {}", doc.day),
        &format!(
            "Every count is the day, then the trailing 7 and 28 days. Rates appear only above n = {SMALL_N}."
        ),
        &blocks(doc, s),
    )
}

/// P10 — the weekly roll-up's HTML body.
pub fn render_weekly_html(doc: &DigestDoc, s: &WeeklySections) -> String {
    html_document(
        &weekly_subject(&s.headline),
        &format!(
            "Every count is the week, then the week before and the mean of the four before it. \
             Rates appear only above n = {SMALL_N}."
        ),
        &weekly_blocks(doc, s),
    )
}

/// P10 — the weekly roll-up's plain-text body.
pub fn render_weekly_text(doc: &DigestDoc, s: &WeeklySections) -> String {
    text_document(
        &weekly_subject(&s.headline),
        &format!(
            "Every count is the week, then the week before and the mean of the four before it. \
             Rates appear only above n = {SMALL_N}."
        ),
        &weekly_blocks(doc, s),
    )
}

/// The HTML document writer every mail shares. Every string escaped;
/// inline styles only (mail clients).
fn html_document(title: &str, intro: &str, blocks: &[Block]) -> String {
    let mut html = String::with_capacity(16 * 1024);
    html.push_str(
        "<div style=\"font-family: sans-serif; max-width: 860px; margin: 0 auto; color: #222;\">",
    );
    html.push_str(&format!(
        "<h2 style=\"margin-bottom: 4px;\">{}</h2>",
        escape_html(title)
    ));
    if !intro.is_empty() {
        html.push_str(&format!(
            "<p style=\"color: #666; margin-top: 0;\">{}</p>",
            escape_html(intro)
        ));
    }
    for b in blocks {
        match b {
            Block::Heading(h) => html.push_str(&format!(
                "<h3 style=\"margin: 20px 0 6px; border-bottom: 1px solid #ddd;\">{}</h3>",
                escape_html(h)
            )),
            Block::Line(k, v) => html.push_str(&format!(
                "<div style=\"margin: 2px 0;\"><strong>{}</strong>: {}</div>",
                escape_html(k),
                escape_html(v)
            )),
            Block::Table(headers, rows) => {
                html.push_str(
                    "<table style=\"border-collapse: collapse; margin: 6px 0; font-size: 13px;\"><thead><tr>",
                );
                for h in headers {
                    html.push_str(&format!(
                        "<th style=\"text-align: left; padding: 2px 8px; border-bottom: 1px solid #999;\">{}</th>",
                        escape_html(h)
                    ));
                }
                html.push_str("</tr></thead><tbody>");
                for row in rows {
                    html.push_str("<tr>");
                    for cell in row {
                        html.push_str(&format!(
                            "<td style=\"padding: 2px 8px; border-bottom: 1px solid #eee;\">{}</td>",
                            escape_html(cell)
                        ));
                    }
                    html.push_str("</tr>");
                }
                html.push_str("</tbody></table>");
            }
            Block::Note(n) => html.push_str(&format!(
                "<p style=\"color: #666; font-size: 13px;\">{}</p>",
                escape_html(n)
            )),
        }
    }
    html.push_str(
        "<p style=\"color: #999; font-size: 12px; margin-top: 24px;\">— Roomler growth</p></div>",
    );
    html
}

/// The plain-text writer every mail shares: the same blocks, as text.
fn text_document(title: &str, intro: &str, blocks: &[Block]) -> String {
    let mut text = String::with_capacity(8 * 1024);
    text.push_str(title);
    text.push('\n');
    if !intro.is_empty() {
        text.push_str(intro);
        text.push('\n');
    }
    for b in blocks {
        match b {
            Block::Heading(h) => text.push_str(&format!("\n== {h} ==\n")),
            Block::Line(k, v) => text.push_str(&format!("{k}: {v}\n")),
            Block::Table(headers, rows) => {
                text.push_str(&format!("  {}\n", headers.join(" | ")));
                for row in rows {
                    text.push_str(&format!("  {}\n", row.join(" | ")));
                }
            }
            Block::Note(n) => text.push_str(&format!("{n}\n")),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::growth::digest::{
        ActiveOrgs, FetchRow, Headline, Install, KeyCount, MethodRow, MrrEstimate, OrgsDevices,
        Quality, Revenue, SignupRow, Signups, Social, SocialPlatform, SocialSnapshot, Tokens,
        TopOrg, Usage, WizardErrorRow, WizardStepRow, WizardSteps,
    };
    use meshharbor_services::dao::growth_digest::{DigestStatus, ExcludedCounts};

    /// A minimal day with one of everything the renderer branches on, and a
    /// planted org name that reads as markup.
    fn sample() -> (DigestDoc, Sections) {
        let f = |day, d7, d28| Figure { day, d7, d28 };
        let doc = DigestDoc {
            day: "2026-10-13".into(),
            status: DigestStatus::Stored,
            version: 1,
            claimed_at: bson::DateTime::now(),
            computed_at: None,
            sent_at: None,
            attempts: 1,
            error: None,
            recipients: 2,
            excluded: ExcludedCounts {
                users: 1,
                tenants: 3,
            },
            sections: None,
        };
        let s = Sections {
            headline: Headline {
                signups: f(2, 9, 31),
                orgs_created: f(1, 4, 12),
                devices_enrolled: Measured::Value(f(3, 7, 20)),
                active_orgs: Measured::Value(ActiveOrgs {
                    day: 2,
                    d7: 5,
                    d28: 9,
                    basis: vec!["remote".into(), "conference".into()],
                }),
                coverage: Measured::NotMeasured(NotMeasured::now("purestat key not configured")),
            },
            signups: Signups {
                total: f(2, 9, 31),
                attributed: f(1, 3, 10),
                by_provider: vec![KeyCount {
                    key: "email".into(),
                    count: 2,
                }],
                by_source: vec![KeyCount {
                    key: "youtube".into(),
                    count: 1,
                }],
                rows: Some(vec![SignupRow {
                    provider: "email".into(),
                    source: Some("youtube".into()),
                    medium: Some("video".into()),
                    campaign: Some("<b>c1</b>".into()),
                    content: None,
                    landing_path: None,
                    referrer_host: None,
                    self_reported: None,
                }]),
            },
            orgs_devices: OrgsDevices {
                orgs_created: f(1, 4, 12),
                devices_enrolled: Measured::Value(f(3, 7, 20)),
                devices_by_os: Measured::Value(vec![KeyCount {
                    key: "linux".into(),
                    count: 3,
                }]),
                orgs_first_device: Measured::Value(f(1, 2, 5)),
                by_install_method: Measured::Value(vec![KeyCount {
                    key: "script-sh".into(),
                    count: 3,
                }]),
            },
            usage: Usage {
                remote: Measured::unmounted("remote"),
                calls: Measured::unmounted("conference"),
                active_orgs: Measured::unmounted("remote and conference"),
                top_orgs: Measured::Value(vec![TopOrg {
                    tenant_id: "x".into(),
                    name: "<script>alert(1)</script> Org".into(),
                    minutes: 12.5,
                    sessions: 2,
                }]),
            },
            website: Measured::NotMeasured(NotMeasured::now("purestat key not configured")),
            blog: Measured::NotMeasured(NotMeasured::now("purestat key not configured")),
            campaigns: Measured::NotMeasured(NotMeasured::now("purestat key not configured")),
            newsletter: Measured::unmounted("saas"),
            revenue: Revenue {
                orgs_by_plan_status: vec![],
                mrr: MrrEstimate {
                    cents: 1600.0,
                    estimate: true,
                    basis: "list price × seats".into(),
                },
                billed: Measured::unmounted("saas"),
                upgrade_intent: None,
            },
            quality: Quality {
                remote: Measured::unmounted("remote"),
                crashes: Measured::unmounted("fleet"),
                ttff: Measured::unmounted("fleet"),
                by_agent_version: Measured::unmounted("fleet"),
                ratings: Measured::unmounted("remote"),
            },
            install: Install {
                fetches: Measured::Value(vec![FetchRow {
                    asset: "install.sh".into(),
                    client: "script-sh".into(),
                    os: "unknown".into(),
                    fetches: f(4, 10, 30),
                }]),
                internal_fetches: Measured::Value(f(6, 20, 50)),
                tokens: Measured::Value(Tokens {
                    issued: f(3, 12, 40),
                    redeemed: f(2, 9, 30),
                }),
                enrollments_by_method: Measured::Value(vec![MethodRow {
                    method: "script-sh".into(),
                    os: "linux".into(),
                    enrolled: f(3, 7, 20),
                }]),
                // P3b — opted-in runs below the floor: counts only, no share.
                wizard_steps: Measured::Value(WizardSteps {
                    runs: f(1, 3, 9),
                    n_floor: SMALL_N,
                    done_share_28d: None,
                    steps: vec![
                        WizardStepRow {
                            step: "welcome".into(),
                            reached: f(1, 3, 9),
                            ok: f(1, 3, 9),
                            failed: f(0, 0, 0),
                            cancelled: f(0, 0, 0),
                        },
                        WizardStepRow {
                            step: "msi".into(),
                            reached: f(1, 3, 7),
                            ok: f(1, 2, 5),
                            failed: f(0, 1, 2),
                            cancelled: f(0, 0, 0),
                        },
                    ],
                    errors: vec![WizardErrorRow {
                        step: "msi".into(),
                        error_code: "msi_user_cancel".into(),
                        failures: f(0, 1, 2),
                    }],
                }),
            },
            social: Measured::Value(Social {
                posts_by_platform: vec![SocialPlatform {
                    platform: "linkedin".into(),
                    posts: f(1, 2, 5),
                }],
                snapshots: vec![SocialSnapshot {
                    platform: "linkedin".into(),
                    platform_id: "urn:li:share:7".into(),
                    snapshot: "T+7d".into(),
                    campaign: Some("<i>c7</i>".into()),
                    metrics: [
                        ("clicks".to_string(), 80.0),
                        ("impressions".to_string(), 3000.0),
                    ]
                    .into_iter()
                    .collect(),
                }],
            }),
            github: crate::growth::github::GithubSection {
                counters: Measured::Value(crate::growth::github::GithubCounters {
                    repo: "gjovanov/roomler-ai".into(),
                    at: "2026-10-12".into(),
                    stars: 130,
                    forks: 11,
                    watchers: 4,
                    downloads: 9_000,
                    helper_downloads: 8_000,
                    downloads_truncated: false,
                    helper_downloads_delta: crate::growth::github::Delta {
                        day: Some(100),
                        d7: None,
                        d28: None,
                    },
                    stars_delta: crate::growth::github::Delta {
                        day: Some(2),
                        d7: Some(9),
                        d28: None,
                    },
                    forks_delta: crate::growth::github::Delta::default(),
                    watchers_delta: crate::growth::github::Delta::default(),
                    downloads_delta: crate::growth::github::Delta {
                        day: Some(40),
                        d7: Some(300),
                        d28: None,
                    },
                    top_releases_7d: Measured::Value(vec![KeyCount {
                        key: "agent-v0.4.140".into(),
                        count: 250,
                    }]),
                    top_flavours_7d: Measured::NotMeasured(NotMeasured::now(
                        "no snapshot for 2026-10-05 to difference against",
                    )),
                }),
                traffic: Measured::NotMeasured(NotMeasured::now(
                    "no GitHub token configured (ROOMLER__GROWTH__GITHUB_TOKEN)",
                )),
            },
            search: Measured::Value(crate::growth::search::SearchSection {
                google: Measured::Value(crate::growth::search::GoogleReport {
                    through: "2026-10-10".into(),
                    clicks: f(3, 20, 70),
                    impressions: f(150, 900, 4000),
                    d28: crate::growth::search::SearchCell {
                        clicks: 70,
                        impressions: 4000,
                        ctr: Some(0.02),
                        position: Some(8.4),
                    },
                    days: f(1, 7, 28),
                    top_queries_7d: vec![crate::growth::search::SearchRow {
                        key: "self-hosted teamviewer alternative".into(),
                        cell: crate::growth::search::SearchCell {
                            clicks: 6,
                            impressions: 12,
                            ctr: None,
                            position: None,
                        },
                    }],
                    top_pages_7d: vec![],
                }),
                bing: Measured::NotMeasured(NotMeasured::now(
                    "no Bing Webmaster API key configured (ROOMLER__GROWTH__BING_API_KEY)",
                )),
            }),
            alerts: Measured::Value(AlertsSection {
                fired: vec![AlertRow {
                    rule: "spike".into(),
                    key: "signups".into(),
                    fired_at: "2026-10-13T09:00:00Z".into(),
                    cleared_at: None,
                    detail: bson::doc! { "day": "2026-10-12", "value": 9_i64, "baseline_mean": 1.07 },
                }],
                cleared: vec![],
                open: vec![AlertRow {
                    rule: "spike".into(),
                    key: "signups".into(),
                    fired_at: "2026-10-13T09:00:00Z".into(),
                    cleared_at: None,
                    detail: bson::doc! { "day": "2026-10-12", "value": 9_i64, "baseline_mean": 1.07 },
                }],
            }),
        };
        (doc, s)
    }

    /// P7 — traffic over its measured days: a window with no day pulled is
    /// "—", never a 0 nobody counted; clones say whose they mostly are; a
    /// truncated listing says its downloads are a lower bound.
    #[test]
    fn github_traffic_and_a_truncated_listing_read_honestly() {
        use crate::growth::github::{Delta, GithubCounters, GithubSection, GithubTraffic};
        let counters = GithubCounters {
            repo: "o/r".into(),
            at: "2026-10-16".into(),
            stars: 1,
            forks: 0,
            watchers: 0,
            downloads: 50,
            helper_downloads: 0,
            downloads_truncated: true,
            stars_delta: Delta::default(),
            forks_delta: Delta::default(),
            watchers_delta: Delta::default(),
            downloads_delta: Delta::default(),
            helper_downloads_delta: Delta::default(),
            top_releases_7d: Measured::Value(vec![]),
            top_flavours_7d: Measured::Value(vec![]),
        };
        let traffic = GithubTraffic {
            views: Figure {
                day: 0,
                d7: 12,
                d28: 40,
            },
            views_uniques: Figure::default(),
            clones: Figure {
                day: 0,
                d7: 3358,
                d28: 9000,
            },
            clones_uniques: Figure::default(),
            measured_days: Figure {
                day: 0,
                d7: 6,
                d28: 20,
            },
            referrers: vec![],
            referrers_as_of: None,
        };
        let mut out = Vec::new();
        github_blocks(
            &mut out,
            &GithubSection {
                counters: Measured::Value(counters),
                traffic: Measured::Value(traffic),
            },
        );
        let text = text_document("t", "i", &out);
        assert!(text.contains("Views: — (7d 12 · 28d 40)"), "{text}");
        assert!(
            text.contains("Clones (mostly CI's checkouts, not people): — (7d 3358 · 28d 9000)"),
            "{text}"
        );
        assert!(
            text.contains(
                "Release downloads (all time, a lower bound: the release listing hit the page bound): 50"
            ),
            "{text}"
        );
    }

    /// P7 — the Search block: a Google window with no final day pulled reads
    /// "—", never 0; Bing says which pull its numbers come from.
    #[test]
    fn search_reads_unpulled_windows_as_a_dash_and_names_bings_pull() {
        use crate::growth::search::{BingReport, GoogleReport, SearchCell, SearchSection};
        let f = |day: i64, d7: i64, d28: i64| Figure { day, d7, d28 };
        let s = Measured::Value(SearchSection {
            google: Measured::Value(GoogleReport {
                through: "2026-10-10".into(),
                clicks: f(0, 4, 9),
                impressions: f(0, 80, 300),
                d28: SearchCell::default(),
                days: f(0, 3, 20),
                top_queries_7d: vec![],
                top_pages_7d: vec![],
            }),
            bing: Measured::Value(BingReport {
                through: "2026-10-12".into(),
                pulled: "2026-10-13".into(),
                clicks: f(1, 2, 5),
                impressions: f(10, 40, 90),
                week: None,
                top_queries_week: vec![],
                top_pages_week: vec![],
            }),
        });
        let mut out = Vec::new();
        search_blocks(&mut out, &s);
        let text = text_document("t", "i", &out);
        assert!(text.contains("Clicks: — (7d 4 · 28d 9)"), "{text}");
        assert!(
            text.contains(
                "Bing, daily through: 2026-10-12 (Bing's own day; read by the pull for 2026-10-13)"
            ),
            "{text}"
        );
    }

    /// Below n = 30 there is no percentage; at 30 there is.
    #[test]
    fn rates_need_thirty() {
        assert_eq!(pct_if_enough(5, 10), None);
        assert_eq!(pct_if_enough(29, 29), None);
        assert_eq!(pct_if_enough(15, 30), Some(50.0));
        assert_eq!(pct_if_enough(1, 300), Some(0.3));
        assert_eq!(pct_if_enough(0, 0), None);
    }

    #[test]
    /// P5 — the newsletter's delivery renders as numbers where SendGrid's
    /// webhook measured it, and as "not measured" (never 0) where it did
    /// not; an issue's cells say which.
    fn newsletter_delivery_renders_measured_and_not_measured_apart() {
        use super::super::digest::{
            DeliveryFigures, IssueCountsOut, IssueDelivery, IssueRow, Newsletter,
        };
        let (doc, mut s) = sample();
        let f = |day, d7, d28| Figure { day, d7, d28 };
        let issue = |slug: &str, delivery| IssueRow {
            slug: slug.into(),
            subject: format!("Issue {slug}"),
            sent_at: "2026-10-13T08:00:00Z".into(),
            counts: IssueCountsOut {
                total: 4,
                sent: 4,
                ..Default::default()
            },
            delivery,
            unsubscribed_via: Some(1),
            campaign: Some(format!("nl-{slug}")),
        };
        s.newsletter = Measured::Value(Newsletter {
            new: f(1, 2, 3),
            confirmed: f(1, 1, 1),
            unsubscribed: f(1, 1, 2),
            unsubscribed_via_issue: Some(f(1, 1, 1)),
            by_source: Vec::new(),
            issues: vec![
                issue(
                    "oct",
                    Measured::Value(IssueDelivery {
                        delivered: 3,
                        bounced: 1,
                        hard_bounced: 1,
                        dropped: 0,
                        complaints: 0,
                    }),
                ),
                issue(
                    "old",
                    Measured::NotMeasured(NotMeasured::now(
                        "sent before delivery events were recorded",
                    )),
                ),
            ],
            delivery: Measured::Value(DeliveryFigures {
                delivered: f(3, 3, 9),
                bounced: f(1, 1, 2),
                hard_bounced: f(1, 1, 1),
                dropped: f(0, 0, 0),
                complaints: f(0, 0, 1),
                suppressed: f(1, 1, 2),
            }),
        });
        let text = render_text(&doc, &s);
        assert!(text.contains("Delivered: 3 (7d 3 · 28d 9)"), "{text}");
        assert!(text.contains("Bounced: 1 (7d 1 · 28d 2) — hard: 1 (7d 1 · 28d 1)"));
        assert!(text.contains("Addresses suppressed: 1 (7d 1 · 28d 2)"));
        assert!(text.contains("… through an issue's link: 1 (7d 1 · 28d 1)"));
        assert!(text.contains("| 3 | 1 (1) | 0 | 1"), "{text}");
        assert!(text.contains("not measured | not measured | not measured | 1"));
        assert!(text.contains("Delivery not measured — sent before delivery events were recorded"));
        // Without the webhook, the window's delivery is a reason, not a 0.
        if let Measured::Value(n) = &mut s.newsletter {
            n.delivery = Measured::NotMeasured(NotMeasured::now("no webhook key"));
        }
        let text = render_text(&doc, &s);
        assert!(text.contains("Delivery: not measured — no webhook key"));
        assert!(!text.contains("Delivered: "));
    }

    #[test]
    fn not_measured_reads_as_such_never_as_zero() {
        let (doc, s) = sample();
        let text = render_text(&doc, &s);
        assert!(text.contains("Website"));
        assert!(text.contains("not measured — purestat key not configured"));
        assert!(text.contains("not measured — remote module not mounted"));
        // P3b — the wizard's opt-in runs render as counts labelled with
        // their n (9 in 28 days, under the floor of 30), the step table
        // with the outcomes as distinct runs, the failure by code, and the
        // note that says whose runs these are; no share below the floor.
        assert!(text.contains("Wizard runs (opted in): 1 (7d 3 · 28d 9)"));
        assert!(text.contains("msi"));
        assert!(text.contains("msi_user_cancel"));
        assert!(text.contains("ticked the diagnostics box"));
        assert!(text.contains("a share is shown only from 30 runs"));
        assert!(!text.contains("reached done (28d)"));
        // P3 — the install trace renders as numbers, with the ratio only
        // once its n clears the floor (40 issued ≥ 30).
        assert!(text.contains("Enrollment tokens issued: 3 (7d 12 · 28d 40)"));
        assert!(text.contains("Redeemed share (28d): 75.0 %"));
        assert!(text.contains("script-sh | linux | 3 · 7 · 20"));
        assert!(text.contains("install.sh | script-sh | unknown | 4 · 10 · 30"));
        assert!(text.contains("never include the daemon's own update checks"));
        // P3c — the lab's fetches on their own line, beside the table.
        assert!(
            text.contains("Fetches from internal networks (not in the table): 6 (7d 20 · 28d 50)"),
            "{text}"
        );
        assert!(text.contains("counted as internal instead of its class"));
        assert!(text.contains("Remote-desktop minutes: not measured"));
        // The figure carries its context, and the footer its exclusions.
        assert!(text.contains("Sign-ups: 2 (7d 9 · 28d 31)"));
        assert!(text.contains("Excluded from every number above: 1 users and 3 orgs"));
        assert!(text.contains("no personal addresses"));
        assert!(text.contains("MRR (ESTIMATE): 16.00"));
        // P8 — social reach: posts per platform, and the day's snapshots in
        // the platform's own metric names.
        assert!(text.contains("== Social reach =="));
        // P7 — the repository: the counters at their snapshot with signed
        // changes, a missing end as "—" (never 0), the week by release, a
        // list that cannot be differenced yet and traffic without a token
        // as not measured, and the note that downloads are not installs.
        assert!(text.contains("== GitHub =="), "{text}");
        assert!(text.contains("gjovanov/roomler-ai at the close of 2026-10-12 (UTC)"));
        assert!(
            text.contains("Stars: 130 (day +2 · 7d +9 · 28d —)"),
            "{text}"
        );
        assert!(text.contains("Forks: 11 (day — · 7d — · 28d —)"));
        assert!(text.contains("Release downloads (all time): 9000 (day +40 · 7d +300 · 28d —)"));
        assert!(text.contains("agent-v0.4.140 | 250"));
        assert!(text.contains("no snapshot for 2026-10-05 to difference against"));
        assert!(text.contains("Traffic: not measured"), "{text}");
        assert!(text.contains("downloads are distribution, not installs"));
        assert!(text.contains(
            "Helper-release downloads (CI's vendored builds): 8000 (day +100 · 7d — · 28d —)"
        ));
        // P7 — search: Google's final days with the day it is final
        // through, the rates only where the reader gave them (28 days, from
        // 30 impressions), a query below the floor with no position, and
        // Bing saying why it is absent.
        assert!(text.contains("== Search =="), "{text}");
        assert!(text.contains("Google, final through: 2026-10-10 (Search Console's own day)"));
        assert!(text.contains("Clicks: 3 (7d 20 · 28d 70)"));
        assert!(
            text.contains("CTR · average position (28d): 2.0 % · 8.4"),
            "{text}"
        );
        assert!(text.contains("self-hosted teamviewer alternative | 6 | 12 | —"));
        assert!(text.contains("Bing: not measured — no Bing Webmaster API key configured"));
        assert!(text.contains("never relabelled as 7 days"));
        assert!(!text.contains("Not yet measured"));
        assert!(text.contains("linkedin | 1 (7d 2 · 28d 5)"), "{text}");
        assert!(
            text.contains("T+7d | clicks 80 · impressions 3000"),
            "{text}"
        );
        // P7 is built: no section of this day still waits for it.
        assert!(!text.contains("arrives with P7"), "{text}");
        assert_eq!(subject("2026-10-13"), "Roomler daily digest — 2026-10-13");
        // P10 — the day's alerts: the open row listed once (it fired that
        // day too), with its detail as text.
        assert!(text.contains("== Alerts =="), "{text}");
        assert!(text.contains("Open now: 1\nFired during the day: 1\nCleared during the day: 0"));
        assert_eq!(
            text.matches("spike | signups | 2026-10-13T09:00:00Z | open |")
                .count(),
            1
        );
        assert!(text.contains("day 2026-10-12 · value 9 · baseline_mean 1.07"));
        // Off: a reason, never a count.
        let (doc, mut s) = sample();
        s.alerts = Measured::NotMeasured(NotMeasured::now("alerts are off on this server"));
        let text = render_text(&doc, &s);
        assert!(text.contains("Alerts: not measured — alerts are off on this server"));
        assert!(!text.contains("Open now"));
    }

    /// P10 — the weekly roll-up: the headline against its baselines, every
    /// rate with its n, a not-measured cell as a reason, and no address.
    #[test]
    fn the_weekly_roll_up_renders_its_baselines_and_keeps_every_n() {
        use super::super::quality::QualityReport;
        use super::super::{
            campaigns::{CampaignsReport, PullSummary, Totals},
            channels::ChannelsReport,
            cohorts::{CohortsReport, OrgDailyCoverage, WaoWeek},
            digest::Coverage,
            funnel::{FunnelReport, Steps, TimeToValue, Windows},
            newsletter::NewsletterReport,
            weekly::{WebWeek, WeekFigure, WeeklyHeadline, WeeklySections},
        };
        let (mut doc, _) = sample();
        doc.day = "2026-W41".into();
        let wf = |week, prev_week, w4| WeekFigure {
            week,
            prev_week,
            w4_avg: w4,
        };
        let excluded = doc.excluded;
        let s = WeeklySections {
            headline: WeeklyHeadline {
                week: "2026-W41".into(),
                since: "2026-10-05".into(),
                until: "2026-10-11".into(),
                signups: wf(12, 9, Some(5.0)),
                orgs_created: wf(3, 1, Some(1.5)),
                devices_enrolled: Measured::unmounted("fleet"),
                active_orgs: Measured::Value(wf(7, 6, None)),
                website: Measured::Value(WebWeek {
                    visitors: wf(300, 280, None),
                    visits: wf(400, 350, None),
                    pageviews: wf(900, 800, None),
                    reads: wf(120, 100, None),
                }),
            },
            funnel: FunnelReport {
                enabled: true,
                since: "2026-10-05T00:00:00Z".into(),
                until: "2026-10-12T00:00:00Z".into(),
                include_internal: false,
                excluded,
                windows: Windows {
                    org_days: 7,
                    activation_days: 7,
                    value_days: 14,
                },
                truncated: false,
                value_basis: vec!["remote".into()],
                not_measured: Default::default(),
                steps: Steps {
                    signup: 12,
                    org_created: StepCounts {
                        count: 6,
                        pending: 2,
                        settled: 10,
                    },
                    activated: Some(StepCounts {
                        count: 20,
                        pending: 0,
                        settled: 40,
                    }),
                    first_value: None,
                    paid: None,
                },
                time_to_value: TimeToValue {
                    first_device: None,
                    first_value: None,
                },
                by: None,
                buckets: vec![],
            },
            cohorts: CohortsReport {
                enabled: true,
                unit: "week".into(),
                since: "2026-07-20".into(),
                include_internal: false,
                excluded,
                weeks_since: 12,
                highlight: [1, 4, 12],
                value_basis: vec!["remote".into()],
                not_measured: None,
                cohorts: Some(vec![]),
                wao: Some(vec![WaoWeek {
                    week: "2026-W41".into(),
                    start: "2026-10-05".into(),
                    active_orgs: 7,
                    partial: false,
                }]),
                org_daily: OrgDailyCoverage::default(),
            },
            campaigns: CampaignsReport {
                enabled: true,
                since: "2026-10-05".into(),
                until: "2026-10-11".into(),
                by: meshharbor_core::campaign::KeyDepth::Source,
                include_internal: false,
                excluded,
                windows: Windows {
                    org_days: 7,
                    activation_days: 7,
                    value_days: 14,
                },
                n_floor: SMALL_N,
                web_not_measured: Some(NotMeasured::now("purestat key not configured")),
                conversions: None,
                web_truncated: false,
                account_truncated: false,
                rows_truncated: false,
                value_basis: vec![],
                not_measured: Default::default(),
                totals: Totals {
                    web: Measured::NotMeasured(NotMeasured::now("purestat key not configured")),
                    signups: 12,
                    keyed_signups: 4,
                    coverage: Measured::Value(Coverage {
                        purestat_signup_goals: 2,
                        server_signups: 12,
                        ratio: None,
                        n_floor: SMALL_N,
                    }),
                },
                rows: vec![],
                pulls: PullSummary {
                    source: "purestat".into(),
                    days: 7,
                    pulled: 0,
                    failed: 0,
                    not_pulled: 7,
                    freeze_days: 7,
                    last_pulled_at: None,
                    last_error: None,
                    not_measured: None,
                },
            },
            channels: ChannelsReport {
                enabled: true,
                since: "2026-10-05".into(),
                until: "2026-10-11".into(),
                include_internal: false,
                excluded,
                n_floor: SMALL_N,
                ingest_mounted: true,
                web_not_measured: None,
                conversions: None,
                web_truncated: false,
                account_truncated: false,
                posts_truncated: false,
                value_basis: vec![],
                not_measured: Default::default(),
                platforms: vec![],
            },
            newsletter: NewsletterReport {
                enabled: true,
                since: "2026-10-05".into(),
                until: "2026-10-11".into(),
                include_internal: false,
                excluded,
                n_floor: SMALL_N,
                webhook_configured: false,
                link_tags: true,
                not_measured: Some(NotMeasured::now("saas module not mounted")),
                list: None,
                issues: vec![],
                issues_truncated: false,
                web_not_measured: None,
                web_truncated: false,
                account_truncated: false,
            },
            alerts: Measured::Value(AlertsSection {
                fired: vec![],
                cleared: vec![],
                open: vec![],
            }),
            quality: QualityReport {
                enabled: true,
                since: "2026-10-05".into(),
                until: "2026-10-11".into(),
                include_internal: false,
                excluded,
                n_floor: SMALL_N,
                days: 7,
                frozen_days: 0,
                ttff_horizon_days: 7,
                not_measured: Some(NotMeasured::now("no frozen day in the range")),
                totals: None,
                by_agent_version: vec![],
                series: vec![],
            },
            github: crate::growth::github::GithubSection::before_p7(),
            search: Measured::NotMeasured(NotMeasured::later(
                "clicks, impressions, top queries and pages",
                "P7",
            )),
        };
        let text = render_weekly_text(&doc, &s);
        // P7 — the section renders even when nothing is measured yet.
        assert!(text.contains("== GitHub =="), "{text}");
        assert!(text.contains("Counters: not measured — arrives with P7"));
        assert!(
            text.contains("Roomler weekly roll-up — 2026-W41 (2026-10-05 → 2026-10-11)"),
            "{text}"
        );
        // P9a — a week with nothing frozen is a reason, never zeros.
        assert!(
            text.contains("Quality: not measured — no frozen day in the range"),
            "{text}"
        );
        assert!(!text.contains("Sessions requested"));
        assert!(text.contains("Sign-ups: 12 (prev 9 · 4w avg 5.0)"));
        assert!(text.contains("Orgs created: 3 (prev 1 · 4w avg 1.5)"));
        assert!(text.contains("Devices enrolled: not measured — fleet module not mounted"));
        assert!(text.contains("Weekly active orgs (north star): 7 (prev 6)"));
        assert!(text.contains("Website visitors: 300 (prev 280)"));
        // Rates: below n = 30 counts only; at 40 settled a percentage.
        assert!(
            text.contains("Org created (≤ 7 d): 6 (10 settled, n < 30 · 2 pending)"),
            "{text}"
        );
        assert!(text.contains("Activated (device ≤ 7 d): 20 (50.0 % of 40 settled · 0 pending)"));
        assert!(text.contains("First value (≤ 14 d): not measured — not mounted"));
        assert!(
            text.contains("Website (the week, unique): not measured — purestat key not configured")
        );
        assert!(text.contains("Coverage: 2 goals ÷ 12 sign-ups (n < 30)"));
        assert!(text.contains("2026-W41 | 7 |"));
        assert!(text.contains("Newsletter: not measured — saas module not mounted"));
        assert!(text.contains("Open now: 0"));
        assert!(text.contains("Week 2026-W41 (2026-10-05 → 2026-10-11, UTC), attempt 1."));
        assert!(!text.contains('@'));
        let html = render_weekly_html(&doc, &s);
        assert!(
            html.contains("<h2 style=\"margin-bottom: 4px;\">Roomler weekly roll-up — 2026-W41")
        );
        assert!(html.contains("4w avg 5.0"));
        assert!(!html.contains('@'));
    }

    /// P10 — an alert's mail names the rule and the key, carries the
    /// detail as text, and says how many are open.
    #[test]
    fn an_alert_mail_carries_the_rule_the_key_and_the_detail() {
        let a = GrowthAlert {
            id: bson::oid::ObjectId::new(),
            rule: "spike".into(),
            key: "signups".into(),
            fired_at: bson::DateTime::parse_rfc3339_str("2026-10-15T09:00:00Z").unwrap(),
            cleared_at: None,
            detail: bson::doc! { "day": "2026-10-14", "value": 9_i64, "baseline_mean": 1.07, "<b>x</b>": "<i>y</i>" },
            mailed_on: None,
        };
        let (subject, html, text) = alert_mail(&a, 2);
        assert_eq!(subject, "Roomler growth alert — spike: signups");
        assert!(
            text.contains("== spike: signups ==\nFired at: 2026-10-15T09:00:00Z\n"),
            "{text}"
        );
        assert!(text.contains("day: 2026-10-14\nvalue: 9\nbaseline_mean: 1.07\n"));
        assert!(text.contains("2 alert(s) open now"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;") && !html.contains("<i>y</i>"));
        assert!(!text.contains('@') && !html.contains('@'));
    }

    #[test]
    fn html_escapes_every_client_chosen_string() {
        let (doc, s) = sample();
        let html = render_html(&doc, &s);
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; Org"));
        assert!(html.contains("&lt;b&gt;c1&lt;/b&gt;"));
        assert!(
            html.contains("&lt;i&gt;c7&lt;/i&gt;"),
            "a pushed campaign is text"
        );
        assert!(html.contains("<h3"));
        assert!(!html.contains('@'), "no address anywhere in a digest");
    }

    /// P4 — billed revenue renders beside the list-price estimate (which
    /// keeps its label), per currency; without `saas` it is a reason, never
    /// a 0; the collisions name the org and the limit.
    #[test]
    fn billed_revenue_renders_beside_the_estimate() {
        use crate::growth::digest::{
            BilledFigures, CollisionOrg, CurrencyBilled, CurrencyMrr, UpgradeIntent,
        };
        let (doc, mut s) = sample();
        let f = |day, d7, d28| Figure { day, d7, d28 };
        let text = render_text(&doc, &s);
        assert!(text.contains("Billed: not measured — saas module not mounted"));
        assert!(!text.contains("Plan-limit collisions"), "absent before P4");

        s.revenue.billed = Measured::Value(BilledFigures {
            record_since: Some("2026-10-01".into()),
            backfilled: false,
            mrr: vec![CurrencyMrr {
                currency: "eur".into(),
                mrr_cents: 1920,
                paying_orgs: 1,
            }],
            invoices_paid: f(1, 1, 2),
            billed: vec![CurrencyBilled {
                currency: "eur".into(),
                cents: f(1920, 1920, 2400),
            }],
            payment_failures: f(0, 0, 1),
            new_paying_orgs: f(1, 1, 1),
            cancellations: f(0, 0, 0),
            trials_started: f(0, 1, 1),
        });
        s.revenue.upgrade_intent = Some(UpgradeIntent {
            collisions: f(3, 5, 9),
            orgs: f(1, 2, 2),
            top: vec![CollisionOrg {
                tenant_id: "x".into(),
                name: "<b>Acme</b>".into(),
                limit: "max_members".into(),
                count: 7,
            }],
        });
        let text = render_text(&doc, &s);
        assert!(
            text.contains(
                "delivered since 2026-10-01; the backfill of Stripe's history has not run"
            ),
            "{text}"
        );
        assert!(text.contains("MRR (ESTIMATE): 16.00"), "the estimate stays");
        assert!(
            text.contains("Billed MRR (EUR): 19.20 — 1 paying org"),
            "{text}"
        );
        assert!(text.contains("Invoices paid: 1 (7d 1 · 28d 2)"));
        assert!(text.contains("Billed (EUR): 19.20 (7d 19.20 · 28d 24.00)"));
        assert!(text.contains("Failed payments: 0 (7d 0 · 28d 1)"));
        assert!(text.contains("Plan-limit collisions: 3 (7d 5 · 28d 9)"));
        assert!(text.contains("<b>Acme</b> | max_members | 7"));
        let html = render_html(&doc, &s);
        assert!(
            html.contains("&lt;b&gt;Acme&lt;/b&gt;"),
            "an org name is text"
        );
    }
}
