// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1d — the purestat v1 query client (`POST {purestat_url}/api/v1/query`).
//!
//! The anonymous plane's one read. It lives here, below both the host and
//! the `saas` module (P6): the host's digest and Campaigns view query it
//! live, and `saas`'s daily puller freezes its breakdowns into
//! `growth_daily` — one client, one set of rules, for every caller. The
//! contract is purestat PS1's (`gjovanov/purestat#13`, live as v0.1.8):
//!
//! ```text
//! POST /api/v1/query          X-API-Key: <key>
//! {"date_from":"YYYY-MM-DD","date_to":"YYYY-MM-DD","dimensions":[..0..4],
//!  "metrics":[..],"goals":[..],"filters":[{"dimension","operator","value"}],
//!  "limit":100,"offset":0}
//! 200 {"rows":[{"dimensions":{..},"metrics":{..},"goals":{..}}],
//!      "meta":{"site_domain","hostnames","date_from","date_to","limit","offset","has_more"}}
//! 400 {"error":".."} · 401 {"error":"unauthorized"} · 500 {"error":"internal"}
//! ```
//!
//! Three rules, each paid for elsewhere in this tree:
//!
//! * **An explicit timeout** ([`DEFAULT_TIMEOUT`]). A client with none once
//!   held a send loop on a hung upstream; this one runs inside the digest
//!   job, and a hung purestat must cost the web sections, not the day.
//! * **The key is never logged** and never part of an error: every
//!   [`PurestatError`] is a short reason the digest stores as
//!   `not_measured: "purestat unreachable: <reason>"`.
//! * **Paging is bounded** ([`MAX_PAGES`]): `has_more` is followed, but a
//!   breakdown that will not fit in a thousand rows is a reporting problem,
//!   not something a nightly job should page through forever.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};

/// Per-request ceiling. Well above purestat's measured answer time and
/// well below anything a nightly job should wait for.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// Rows per page — the contract's `limit`.
pub const PAGE_LIMIT: u32 = 100;
/// Pages followed per query before giving up (10 × 100 rows).
pub const MAX_PAGES: u32 = 10;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Filter {
    pub dimension: String,
    pub operator: String,
    pub value: String,
}

impl Filter {
    pub fn starts_with(dimension: &str, value: &str) -> Self {
        Self {
            dimension: dimension.into(),
            operator: "starts_with".into(),
            value: value.into(),
        }
    }

    /// An exact match. ⚠️ purestat compares literally and case-sensitively,
    /// so a filter on a UTM value matches the spelling the link carried, not
    /// the taxonomy's — a caller that joins by the normalised key breaks
    /// down by the dimension and normalises the rows instead.
    pub fn is(dimension: &str, value: &str) -> Self {
        Self {
            dimension: dimension.into(),
            operator: "is".into(),
            value: value.into(),
        }
    }
}

/// One query, as the body on the wire. `limit` / `offset` are the client's
/// to set while paging; a caller fills the rest.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Query {
    pub date_from: String,
    pub date_to: String,
    pub dimensions: Vec<String>,
    pub metrics: Vec<String>,
    pub goals: Vec<String>,
    pub filters: Vec<Filter>,
    pub limit: u32,
    pub offset: u32,
}

impl Query {
    /// A one-day query with the given breakdown and no filters.
    pub fn day(day: &str, dimensions: &[&str], metrics: &[&str], goals: &[&str]) -> Self {
        Self::range(day, day, dimensions, metrics, goals)
    }

    pub fn range(
        from: &str,
        to: &str,
        dimensions: &[&str],
        metrics: &[&str],
        goals: &[&str],
    ) -> Self {
        Self {
            date_from: from.into(),
            date_to: to.into(),
            dimensions: dimensions.iter().map(|s| s.to_string()).collect(),
            metrics: metrics.iter().map(|s| s.to_string()).collect(),
            goals: goals.iter().map(|s| s.to_string()).collect(),
            filters: Vec::new(),
            limit: PAGE_LIMIT,
            offset: 0,
        }
    }

    pub fn filter(mut self, f: Filter) -> Self {
        self.filters.push(f);
        self
    }
}

/// One row of a breakdown. Dimension values arrive as strings (or null
/// when the visit had none); metrics as numbers, null where the metric is
/// not defined for that breakdown (`visits` on a non-session dimension,
/// `median_read_s` with no reads).
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Row {
    #[serde(default)]
    pub dimensions: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub metrics: BTreeMap<String, Option<f64>>,
    #[serde(default)]
    pub goals: BTreeMap<String, Option<f64>>,
}

impl Row {
    /// A dimension's value, `None` when absent or null.
    pub fn dim(&self, name: &str) -> Option<&str> {
        self.dimensions.get(name).and_then(|v| v.as_deref())
    }

    /// A metric as an integer count; absent or null reads as 0 — a count
    /// the server did not report for this row is a count of nothing in it.
    pub fn count(&self, name: &str) -> i64 {
        self.metrics
            .get(name)
            .copied()
            .flatten()
            .map(|v| v.round() as i64)
            .unwrap_or(0)
    }

    /// A metric as-is, `None` when absent or null (`median_read_s`).
    pub fn metric(&self, name: &str) -> Option<f64> {
        self.metrics.get(name).copied().flatten()
    }

    /// A goal's conversions; absent or null reads as 0.
    pub fn goal(&self, name: &str) -> i64 {
        self.goals
            .get(name)
            .copied()
            .flatten()
            .map(|v| v.round() as i64)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Meta {
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Response {
    #[serde(default)]
    pub rows: Vec<Row>,
    #[serde(default)]
    pub meta: Meta,
}

/// Every page of one query, and whether [`MAX_PAGES`] cut it short.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Paged {
    pub rows: Vec<Row>,
    pub truncated: bool,
}

/// Why a query gave no rows. `Display` is the short reason the digest
/// stores; none of them carries the key or the body.
#[derive(Debug, Clone, PartialEq)]
pub enum PurestatError {
    /// No key configured — the caller should not have asked.
    NotConfigured,
    /// 401: the key is wrong or revoked.
    Unauthorized,
    /// Any other non-2xx, with the server's `error` text (bounded).
    Status(u16, String),
    /// The request did not complete within the timeout.
    Timeout,
    /// Could not connect, or the connection broke.
    Transport(String),
    /// 2xx with a body that is not the contract.
    Decode(String),
}

impl std::fmt::Display for PurestatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "purestat key not configured"),
            Self::Unauthorized => write!(f, "purestat unreachable: unauthorized (401)"),
            Self::Status(code, msg) => write!(f, "purestat unreachable: HTTP {code} {msg}"),
            Self::Timeout => write!(f, "purestat unreachable: timed out"),
            Self::Transport(e) => write!(f, "purestat unreachable: {e}"),
            Self::Decode(e) => write!(f, "purestat unreachable: unreadable answer ({e})"),
        }
    }
}

impl PurestatError {
    /// Whether a later query in the same run could succeed. A wrong key
    /// or an unreachable host will not fix itself between two queries of
    /// one digest, so the run stops asking after the first of these.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::NotConfigured | Self::Unauthorized | Self::Timeout | Self::Transport(_)
        )
    }
}

/// The goal a purestat 400 names as undefined (`unknown goal: "signup"`),
/// when that is what the error is. A site with no goal definitions is a
/// configuration gap on the web plane, not an outage: a caller retries the
/// breakdown without goals (its visitors are still real) and says which
/// conversions are not measured.
pub fn unknown_goal(e: &PurestatError) -> Option<String> {
    let PurestatError::Status(400, msg) = e else {
        return None;
    };
    let lower = msg.to_ascii_lowercase();
    let idx = lower.find("unknown goal")?;
    let rest = &msg[idx + "unknown goal".len()..];
    let quoted = rest
        .split('"')
        .nth(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(quoted.unwrap_or_else(|| {
        let bare = rest.trim_start_matches(':').trim();
        if bare.is_empty() {
            "the goal".to_string()
        } else {
            bare.to_string()
        }
    }))
}

#[derive(Clone)]
pub struct PurestatClient {
    endpoint: String,
    key: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for PurestatClient {
    /// No key, ever.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PurestatClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl PurestatClient {
    /// `None` when no key is configured — the web sections then read "not
    /// measured" without a request being made.
    pub fn new(base_url: &str, api_key: &str) -> Option<Self> {
        Self::with_timeout(base_url, api_key, DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(base_url: &str, api_key: &str, timeout: Duration) -> Option<Self> {
        let key = api_key.trim();
        if key.is_empty() {
            return None;
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .build()
            .ok()?;
        Some(Self {
            endpoint: format!("{}/api/v1/query", base_url.trim_end_matches('/')),
            key: key.to_string(),
            http,
        })
    }

    /// Run one query, following `has_more` up to [`MAX_PAGES`]. The rows of
    /// every page, in order.
    pub async fn query(&self, query: &Query) -> Result<Vec<Row>, PurestatError> {
        Ok(self.query_paged(query).await?.rows)
    }

    /// [`Self::query_paged`], retried ONCE without goals when the server
    /// answers that a goal is not defined (a 400 naming it): the breakdown's
    /// visitors are still real, and the missing goal comes back beside them
    /// so the caller can say which conversions are not measured.
    pub async fn query_or_without_goals(
        &self,
        query: &Query,
    ) -> Result<(Paged, Option<String>), PurestatError> {
        match self.query_paged(query).await {
            Ok(paged) => Ok((paged, None)),
            Err(e) => match unknown_goal(&e) {
                Some(goal) if !query.goals.is_empty() => {
                    let mut without = query.clone();
                    without.goals.clear();
                    Ok((self.query_paged(&without).await?, Some(goal)))
                }
                _ => Err(e),
            },
        }
    }

    /// [`Self::query`], saying whether the page bound cut the answer short:
    /// `truncated` is true when the last page followed still had `has_more`.
    /// A view that shows the rows says so rather than presenting a partial
    /// breakdown as the whole one.
    pub async fn query_paged(&self, query: &Query) -> Result<Paged, PurestatError> {
        let mut rows = Vec::new();
        let mut page = query.clone();
        page.limit = PAGE_LIMIT;
        page.offset = 0;
        let mut truncated = false;
        for i in 0..MAX_PAGES {
            let resp = self.one_page(&page).await?;
            let n = resp.rows.len() as u32;
            rows.extend(resp.rows);
            if !resp.meta.has_more || n == 0 {
                break;
            }
            if i + 1 == MAX_PAGES {
                truncated = true;
                break;
            }
            page.offset += n;
        }
        Ok(Paged { rows, truncated })
    }

    async fn one_page(&self, query: &Query) -> Result<Response, PurestatError> {
        let sent = self
            .http
            .post(&self.endpoint)
            .header("X-API-Key", &self.key)
            .json(query)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    PurestatError::Timeout
                } else {
                    // reqwest's Display can echo the URL; the key is a
                    // header and never part of it.
                    PurestatError::Transport(short(&e.without_url().to_string()))
                }
            })?;
        let status = sent.status();
        if status.as_u16() == 401 {
            return Err(PurestatError::Unauthorized);
        }
        if !status.is_success() {
            let text = sent.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or(text);
            return Err(PurestatError::Status(status.as_u16(), short(&msg)));
        }
        sent.json::<Response>()
            .await
            .map_err(|e| PurestatError::Decode(short(&e.without_url().to_string())))
    }
}

/// Bound a server-supplied string before it lands in a stored reason.
fn short(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    s.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_is_the_contracts_shape() {
        let q = Query::day(
            "2026-10-13",
            &["utm_source", "utm_medium"],
            &["visitors"],
            &["signup"],
        )
        .filter(Filter::starts_with("path", "/blog/"));
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "date_from": "2026-10-13",
                "date_to": "2026-10-13",
                "dimensions": ["utm_source", "utm_medium"],
                "metrics": ["visitors"],
                "goals": ["signup"],
                "filters": [{"dimension": "path", "operator": "starts_with", "value": "/blog/"}],
                "limit": 100,
                "offset": 0,
            })
        );
    }

    #[test]
    fn an_exact_filter_is_the_contracts_is_operator() {
        let q = Query::range("2026-10-01", "2026-10-13", &[], &["visitors"], &[])
            .filter(Filter::is("utm_source", "linkedin"));
        assert_eq!(
            serde_json::to_value(&q).unwrap()["filters"],
            serde_json::json!([{"dimension": "utm_source", "operator": "is", "value": "linkedin"}])
        );
    }

    #[test]
    fn rows_read_nulls_as_absent_and_counts_as_zero() {
        let r: Response = serde_json::from_str(
            r#"{"rows":[{"dimensions":{"utm_source":"linkedin","utm_medium":null},
                "metrics":{"visitors":52,"pageviews":265.0,"visits":null,"median_read_s":null},
                "goals":{"signup":1}}],
                "meta":{"site_domain":"meshharbor.itachi.fans","hostnames":["meshharbor.itachi.fans"],"date_from":"2026-10-13",
                "date_to":"2026-10-13","limit":100,"offset":0,"has_more":false}}"#,
        )
        .unwrap();
        let row = &r.rows[0];
        assert_eq!(row.dim("utm_source"), Some("linkedin"));
        assert_eq!(row.dim("utm_medium"), None);
        assert_eq!(row.dim("absent"), None);
        assert_eq!(row.count("visitors"), 52);
        assert_eq!(row.count("pageviews"), 265);
        assert_eq!(row.count("visits"), 0);
        assert_eq!(row.metric("visits"), None);
        assert_eq!(row.metric("median_read_s"), None);
        assert_eq!(row.goal("signup"), 1);
        assert_eq!(row.goal("subscribe"), 0);
        assert!(!r.meta.has_more);
    }

    #[test]
    fn no_key_means_no_client_and_no_request() {
        assert!(PurestatClient::new("https://purestat.ai", "").is_none());
        assert!(PurestatClient::new("https://purestat.ai", "   ").is_none());
        let c = PurestatClient::new("https://purestat.ai/", "k").unwrap();
        assert_eq!(c.endpoint, "https://purestat.ai/api/v1/query");
        assert!(!format!("{c:?}").contains('k'), "the key is never printed");
    }

    #[test]
    fn errors_read_as_short_reasons_without_the_key() {
        assert_eq!(
            PurestatError::Unauthorized.to_string(),
            "purestat unreachable: unauthorized (401)"
        );
        assert_eq!(
            PurestatError::NotConfigured.to_string(),
            "purestat key not configured"
        );
        assert!(PurestatError::Timeout.is_fatal());
        assert!(!PurestatError::Status(400, "bad dimension".into()).is_fatal());
        assert_eq!(short("a\nb\tc"), "abc");
        assert_eq!(short(&"x".repeat(500)).len(), 120);
    }
}
