// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-88 P1a — sign-up attribution, server side.
//!
//! A visitor lands on the site with `utm_*` on the URL; the site's own links
//! carry those keys into the register view, and the register view sends them
//! here — nothing is ever written to the visitor's device (the whole point of
//! §3a of the spec). This module is the ONE place a client's claim about where
//! a sign-up came from is turned into what `users.signup_attribution` stores:
//!
//! * [`AttributionInput`] — the shape a client may send, on the register body
//!   (`attribution: {…}`) or as `utm_*` query keys on `GET /api/oauth/{p}`.
//!   Deliberately lenient: unknown keys are ignored, a value that is not a
//!   string is ignored, a body that is not an object is an empty input. A
//!   malformed attribution never fails a registration.
//! * [`sanitize`] — the contract the frontend relies on: every value trimmed,
//!   printable ASCII only, clamped to [`MAX_ATTRIBUTION_VALUE_LEN`]; the
//!   referrer must look like a bare host and the landing path must start
//!   with `/`, or the value is dropped. An input with nothing left is `None`,
//!   never an empty subdocument.
//! * [`park_for_oauth`] / [`take_for_oauth`] — the Redis parking spot that
//!   carries the values across an OAuth round trip, keyed by the CSRF state
//!   `oauth_redirect` already mints, with the `oauth_state` cookie's TTL. No
//!   new cookie. ⚠️ Nothing here may influence the CSRF check: a missing or
//!   expired key is "no attribution", never a failed login, which is why
//!   [`take_for_oauth`] cannot fail — every error is `None`. ⚠️ Nothing here
//!   may slow the sign-in either: before FR-88 the OAuth path made no Redis
//!   call at all, and `redis`'s connection manager has no response timeout,
//!   so a reachable-but-hung Redis would hold every redirect and callback.
//!   Both calls run under [`OAUTH_STORE_BUDGET`]; past it the attribution is
//!   dropped and the sign-in goes on. The store is a trait
//!   ([`OauthAttributionStore`]) so that budget is tested against a store
//!   that never answers, with no Redis in the loop.
//!
//! The values are never logged at `info` (they are, in the end, a user's own
//! answer to "how did you hear about us"), and they are never returned by a
//! user-facing endpoint — `routes::auth::UserResponse::of` is the seam that
//! keeps that true.

use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};

use bson::DateTime;
use roomler_ai_db::models::{MAX_ATTRIBUTION_VALUE_LEN, SignupAttribution};
use serde::{Deserialize, Deserializer};
use tracing::debug;

use crate::ws::redis_pubsub::RedisPubSub;

/// What a client may claim. Every field optional; see the module docs for
/// how leniently it is read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AttributionInput {
    pub source: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub content: Option<String>,
    pub term: Option<String>,
    pub referrer_host: Option<String>,
    pub landing_path: Option<String>,
    pub self_reported: Option<String>,
}

impl AttributionInput {
    /// The `utm_*` spellings the OAuth redirect accepts as query keys, paired
    /// with the field each lands in. `referrer_host`, `landing_path` and
    /// `self_reported` have no `utm_` form and keep their own names.
    const QUERY_KEYS: [(&'static str, &'static str); 8] = [
        ("utm_source", "source"),
        ("utm_medium", "medium"),
        ("utm_campaign", "campaign"),
        ("utm_content", "content"),
        ("utm_term", "term"),
        ("referrer_host", "referrer_host"),
        ("landing_path", "landing_path"),
        ("self_reported", "self_reported"),
    ];

    /// From the query string of `GET /api/oauth/{provider}` — the eight keys
    /// by their `utm_*` names; everything else in the map is ignored.
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        let mut out = Self::default();
        for (query_key, field) in Self::QUERY_KEYS {
            if let Some(v) = query.get(query_key) {
                out.set(field, v);
            }
        }
        out
    }

    /// From a JSON value — the `attribution` object on the register body.
    /// Anything that is not an object reads as empty; inside an object only
    /// string values for the eight known keys are taken.
    pub fn from_value(value: &serde_json::Value) -> Self {
        let mut out = Self::default();
        if let Some(obj) = value.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    out.set(k, s);
                }
            }
        }
        out
    }

    fn set(&mut self, field: &str, value: &str) {
        let slot = match field {
            "source" => &mut self.source,
            "medium" => &mut self.medium,
            "campaign" => &mut self.campaign,
            "content" => &mut self.content,
            "term" => &mut self.term,
            "referrer_host" => &mut self.referrer_host,
            "landing_path" => &mut self.landing_path,
            "self_reported" => &mut self.self_reported,
            _ => return,
        };
        *slot = Some(value.to_string());
    }
}

/// Lenient on purpose: the register body is `Json<RegisterRequest>`, and a
/// derived `Deserialize` here would turn `attribution: "youtube"` — or a
/// number where a string belongs — into a 422 for the whole registration.
/// The attribution is a courtesy the sign-up carries, not a field it may fail
/// on, so it is read as a free-form JSON value and picked apart.
impl<'de> Deserialize<'de> for AttributionInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(Self::from_value(&value))
    }
}

/// The contract, applied. `None` when nothing survives.
///
/// Order per value: trim → reject anything outside printable ASCII → clamp
/// to [`MAX_ATTRIBUTION_VALUE_LEN`] → drop if empty. Then the two shaped
/// fields get their own rule: a referrer keeps only a bare host (lower-cased,
/// an optional `:port`), a landing path keeps only the path part and must
/// start with a single `/`.
///
/// FR-102 P1b — `source` and `medium` then go through the campaign
/// taxonomy (`campaign::normalize_source` / `normalize_medium`): lowercase,
/// then the aliases (`YouTub` → `youtube`, `Twitter` → `x`), so the stored
/// key is the one the reports and purestat group by. An unknown value is
/// kept verbatim (lowercased), never dropped — it is reported under `other`.
pub fn sanitize(input: AttributionInput) -> Option<SignupAttribution> {
    let attr = SignupAttribution {
        source: input
            .source
            .as_deref()
            .and_then(clean_value)
            .map(|v| crate::campaign::normalize_source(&v)),
        medium: input
            .medium
            .as_deref()
            .and_then(clean_value)
            .map(|v| crate::campaign::normalize_medium(&v)),
        campaign: input.campaign.as_deref().and_then(clean_value),
        content: input.content.as_deref().and_then(clean_value),
        term: input.term.as_deref().and_then(clean_value),
        referrer_host: input.referrer_host.as_deref().and_then(clean_host),
        landing_path: input.landing_path.as_deref().and_then(clean_path),
        self_reported: input.self_reported.as_deref().and_then(clean_value),
        captured_at: None,
    };
    if attr.is_empty() {
        return None;
    }
    Some(SignupAttribution {
        captured_at: Some(DateTime::now()),
        ..attr
    })
}

fn is_printable_ascii(c: char) -> bool {
    (' '..='~').contains(&c)
}

/// Trim, reject non-printable / non-ASCII, clamp, drop empty.
///
/// A value with a character outside printable ASCII is DROPPED rather than
/// stripped: stripping `vidéo` to `vido` manufactures a campaign key that
/// looks right and matches nothing the operator ever wrote. The keys are the
/// operator's own slugs; anything else is not worth guessing at.
///
/// FR-102 P6 — public because the campaign key the web plane's rows join by
/// (`campaign::CampaignKey::normalized`) must be cleaned exactly as a
/// sign-up's was at ingress, or a key purestat saw would never meet the
/// sign-up that carried it.
pub fn clean_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.chars().all(is_printable_ascii) {
        return None;
    }
    // ASCII, so a char boundary is a byte boundary and the clamp cannot
    // split a character. Re-trim: the cut may end on a space.
    let clamped = trimmed
        .get(..MAX_ATTRIBUTION_VALUE_LEN)
        .unwrap_or(trimmed)
        .trim_end();
    (!clamped.is_empty()).then(|| clamped.to_string())
}

/// A bare host: labels of `[a-z0-9-]` joined by `.`, an optional numeric
/// port, nothing else. A scheme, a path, a query, credentials or whitespace
/// mean the client sent a URL where a host belongs — dropped, not repaired,
/// because `document.referrer`'s hostname is the one thing the frontend was
/// asked for and a full URL is what it must not send.
fn clean_host(raw: &str) -> Option<String> {
    let value = clean_value(raw)?.to_ascii_lowercase();
    let (host, port) = match value.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (value.as_str(), None),
    };
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.is_empty() || !host.split('.').all(label_ok) {
        return None;
    }
    Some(value)
}

/// A path: must start with exactly one `/` (a `//` prefix is a
/// protocol-relative URL, not a path), keeps nothing from `?` or `#` on (the
/// query would only duplicate the UTM keys the other fields already hold),
/// and refuses a backslash, which some URL parsers read as `/`.
fn clean_path(raw: &str) -> Option<String> {
    let value = clean_value(raw)?;
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return None;
    }
    let end = value.find(['?', '#']).unwrap_or(value.len());
    let path = value[..end].trim_end();
    (!path.is_empty()).then(|| path.to_string())
}

// ── The OAuth parking spot ──────────────────────────────────────────────

/// The `oauth_state` cookie's `Max-Age`, and therefore the key's TTL: an
/// attribution outliving the CSRF state it is keyed by could never be
/// claimed anyway.
pub const OAUTH_PARK_TTL_SECS: u64 = 600;

/// `roomler:oauth_attr:<csrf_state>` — the `roomler:` namespace every other
/// key this server writes lives in. The state is a server-minted UUID, so
/// the key cannot be guessed or chosen by a client.
pub fn oauth_park_key(csrf_state: &str) -> String {
    format!("roomler:oauth_attr:{csrf_state}")
}

/// How long either parking-spot call may take before it is abandoned.
///
/// Redis is in-cluster and answers in well under a millisecond, so this is
/// two orders of magnitude of headroom — and a ceiling on what a hung Redis
/// can cost a sign-in, which before FR-88 never touched Redis at all. The
/// attribution is a courtesy the sign-in carries; it is never worth a wait.
pub const OAUTH_STORE_BUDGET: Duration = Duration::from_millis(250);

/// The future a store operation returns.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The parking spot's two operations, behind a trait so the budget above is
/// tested against a store that never answers. Errors are strings: the only
/// thing a caller does with one is log it at `debug`.
pub trait OauthAttributionStore: Send + Sync {
    /// `SET key bytes EX ttl_secs`.
    fn park(
        &self,
        key: String,
        bytes: Vec<u8>,
        ttl_secs: u64,
    ) -> StoreFuture<'_, Result<(), String>>;
    /// Read-and-delete, atomically: a callback that is replayed or raced
    /// must not collect the value twice.
    fn take(&self, key: String) -> StoreFuture<'_, Result<Option<Vec<u8>>, String>>;
}

impl OauthAttributionStore for RedisPubSub {
    fn park(
        &self,
        key: String,
        bytes: Vec<u8>,
        ttl_secs: u64,
    ) -> StoreFuture<'_, Result<(), String>> {
        let mut conn = self.connection();
        Box::pin(async move {
            redis::cmd("SET")
                .arg(key)
                .arg(bytes)
                .arg("EX")
                .arg(ttl_secs)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// One `MULTI GET DEL EXEC` — not `GETDEL`, which needs Redis 6.2.
    fn take(&self, key: String) -> StoreFuture<'_, Result<Option<Vec<u8>>, String>> {
        let mut conn = self.connection();
        Box::pin(async move {
            let (value, _deleted): (Option<Vec<u8>>, i64) = redis::pipe()
                .atomic()
                .cmd("GET")
                .arg(&key)
                .cmd("DEL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|e| e.to_string())?;
            Ok(value)
        })
    }
}

/// Why a park did not happen. The caller logs it at `debug` and sends the
/// redirect regardless.
#[derive(Debug, PartialEq)]
pub enum ParkError {
    Serialise(String),
    Store(String),
    /// The store did not answer within [`OAUTH_STORE_BUDGET`].
    TimedOut,
}

impl std::fmt::Display for ParkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialise(e) => write!(f, "attribution did not serialise: {e}"),
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::TimedOut => write!(
                f,
                "store did not answer within {} ms",
                OAUTH_STORE_BUDGET.as_millis()
            ),
        }
    }
}

/// Park a sanitised attribution under the CSRF state for the callback to
/// collect. Stored as BSON bytes (`captured_at` round-trips natively) with
/// the cookie's TTL, under [`OAUTH_STORE_BUDGET`]. Errors are the caller's
/// to log and ignore — the redirect must go out regardless.
pub async fn park_for_oauth(
    store: &dyn OauthAttributionStore,
    csrf_state: &str,
    attribution: &SignupAttribution,
) -> Result<(), ParkError> {
    let bytes = bson::to_vec(attribution).map_err(|e| ParkError::Serialise(e.to_string()))?;
    let parked = store.park(oauth_park_key(csrf_state), bytes, OAUTH_PARK_TTL_SECS);
    match tokio::time::timeout(OAUTH_STORE_BUDGET, parked).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ParkError::Store(e)),
        Err(_elapsed) => Err(ParkError::TimedOut),
    }
}

/// Read-and-delete the parked attribution for a CSRF state, under
/// [`OAUTH_STORE_BUDGET`].
///
/// Cannot fail by construction: a missing key, an expired key, a store
/// error, a store that does not answer in time and an unreadable value are
/// all `None`. The login that follows must not depend on this in any way.
pub async fn take_for_oauth(
    store: &dyn OauthAttributionStore,
    csrf_state: &str,
) -> Option<SignupAttribution> {
    let taken = store.take(oauth_park_key(csrf_state));
    let bytes = match tokio::time::timeout(OAUTH_STORE_BUDGET, taken).await {
        Ok(Ok(value)) => value?,
        Ok(Err(e)) => {
            debug!(%e, "parked oauth attribution could not be read; ignored");
            return None;
        }
        Err(_elapsed) => {
            debug!(
                budget_ms = OAUTH_STORE_BUDGET.as_millis() as u64,
                "the attribution store did not answer in time; signing in without it"
            );
            return None;
        }
    };
    match bson::from_slice::<SignupAttribution>(&bytes) {
        Ok(attr) if !attr.is_empty() => Some(attr),
        Ok(_) => None,
        Err(e) => {
            debug!(%e, "parked oauth attribution was unreadable; ignored");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomler_ai_db::models::{NotificationPrefs, Presence, TutorialState, User, UserStatusInfo};
    use serde_json::json;

    fn input(v: serde_json::Value) -> AttributionInput {
        AttributionInput::from_value(&v)
    }

    #[test]
    fn values_are_trimmed_and_kept_when_printable_ascii() {
        let got = sanitize(input(json!({
            "source": "  youtube ",
            "medium": "video",
            "campaign": "fr88-test",
            "content": "short-1",
            "term": "remote desktop",
            "self_reported": "tiktok",
        })))
        .expect("something survived");
        assert_eq!(got.source.as_deref(), Some("youtube"));
        assert_eq!(got.medium.as_deref(), Some("video"));
        assert_eq!(got.campaign.as_deref(), Some("fr88-test"));
        assert_eq!(got.content.as_deref(), Some("short-1"));
        assert_eq!(got.term.as_deref(), Some("remote desktop"));
        assert_eq!(got.self_reported.as_deref(), Some("tiktok"));
        assert!(got.captured_at.is_some(), "stamped when something survived");
    }

    /// The planted over-long value: 100 characters in, exactly 64 out.
    #[test]
    fn an_over_long_value_is_clamped_to_the_ceiling() {
        let planted: String = (0..100)
            .map(|i| char::from(b'a' + (i % 26) as u8))
            .collect();
        assert_eq!(planted.len(), 100);
        let got = sanitize(input(json!({ "campaign": planted }))).unwrap();
        let campaign = got.campaign.unwrap();
        assert_eq!(campaign.len(), MAX_ATTRIBUTION_VALUE_LEN);
        assert_eq!(campaign, planted[..MAX_ATTRIBUTION_VALUE_LEN]);
    }

    /// A clamp that lands on a space must not leave a trailing one.
    #[test]
    fn a_clamp_that_cuts_on_whitespace_re_trims() {
        let mut planted = "x".repeat(MAX_ATTRIBUTION_VALUE_LEN - 1);
        planted.push_str("   tail");
        let got = sanitize(input(json!({ "term": planted }))).unwrap();
        assert_eq!(got.term.unwrap(), "x".repeat(MAX_ATTRIBUTION_VALUE_LEN - 1));
    }

    #[test]
    fn non_ascii_and_control_characters_drop_the_value() {
        for bad in ["vidéo", "a\tb", "a\u{7f}b", "new\nline", "日本"] {
            assert_eq!(
                sanitize(input(json!({ "source": bad }))),
                None,
                "{bad:?} must be dropped, not stripped"
            );
        }
    }

    #[test]
    fn a_javascript_landing_path_is_dropped() {
        assert_eq!(
            sanitize(input(json!({ "landing_path": "javascript:alert(1)" }))),
            None
        );
        assert_eq!(
            sanitize(input(json!({ "landing_path": "https://roomler.ai/" }))),
            None
        );
        // Protocol-relative and backslash forms are not paths either.
        assert_eq!(
            sanitize(input(json!({ "landing_path": "//evil.example/x" }))),
            None
        );
        assert_eq!(
            sanitize(input(json!({ "landing_path": "/\\evil.example" }))),
            None
        );
    }

    #[test]
    fn a_landing_path_keeps_only_the_path() {
        let got = sanitize(input(json!({
            "landing_path": " /blog/x/?utm_source=youtube#top "
        })))
        .unwrap();
        assert_eq!(got.landing_path.as_deref(), Some("/blog/x/"));
        let root = sanitize(input(json!({ "landing_path": "/?utm_source=yt" }))).unwrap();
        assert_eq!(root.landing_path.as_deref(), Some("/"));
    }

    #[test]
    fn a_referrer_must_be_a_bare_host() {
        for bad in [
            "https://youtube.com/watch",
            "youtube.com/x",
            "you tube.com",
            "user@youtube.com",
            "youtube.com?x=1",
            "youtube.com:",
            "youtube.com:abc",
            "-bad.example",
            "bad-.example",
            "a..b",
            ".",
        ] {
            assert_eq!(
                sanitize(input(json!({ "referrer_host": bad }))),
                None,
                "{bad:?} is not a host"
            );
        }
        let ok = sanitize(input(json!({ "referrer_host": " www.YouTube.com " }))).unwrap();
        assert_eq!(ok.referrer_host.as_deref(), Some("www.youtube.com"));
        let dev = sanitize(input(json!({ "referrer_host": "localhost:5000" }))).unwrap();
        assert_eq!(dev.referrer_host.as_deref(), Some("localhost:5000"));
        let punycode = sanitize(input(json!({ "referrer_host": "xn--80ak6aa92e.com" }))).unwrap();
        assert_eq!(
            punycode.referrer_host.as_deref(),
            Some("xn--80ak6aa92e.com")
        );
    }

    #[test]
    fn unknown_keys_and_non_string_values_are_ignored() {
        let got = sanitize(input(json!({
            "source": "tiktok",
            "bogus": "x",
            "medium": 5,
            "campaign": null,
            "content": ["a"],
        })))
        .unwrap();
        assert_eq!(got.source.as_deref(), Some("tiktok"));
        assert_eq!(got.medium, None);
        assert_eq!(got.campaign, None);
        assert_eq!(got.content, None);
    }

    /// FR-102 AC5 — the taxonomy is applied at ingress: the field's
    /// `YouTub` and `Video` store as `youtube` / `video`, an alias stores as
    /// its canonical, and an unknown source is stored verbatim (lowercased)
    /// rather than dropped. Only `source` and `medium` are normalised: a
    /// campaign slug is the operator's own and is kept as sent.
    #[test]
    fn source_and_medium_are_normalised_through_the_taxonomy() {
        let got = sanitize(input(json!({
            "source": "YouTub",
            "medium": "Video",
            "campaign": "20261019-Slug",
            "content": "Desc-Top",
        })))
        .unwrap();
        assert_eq!(got.source.as_deref(), Some("youtube"));
        assert_eq!(got.medium.as_deref(), Some("video"));
        assert_eq!(got.campaign.as_deref(), Some("20261019-Slug"));
        assert_eq!(got.content.as_deref(), Some("Desc-Top"));

        let alias = sanitize(input(json!({ "source": " Twitter ", "medium": "POST" }))).unwrap();
        assert_eq!(alias.source.as_deref(), Some("x"));
        assert_eq!(alias.medium.as_deref(), Some("post"));

        let unknown = sanitize(input(json!({ "source": "Mastodon" }))).unwrap();
        assert_eq!(unknown.source.as_deref(), Some("mastodon"));

        // The OAuth query path goes through the same function.
        let q: HashMap<String, String> = [("utm_source", "YouTub"), ("utm_medium", "Video")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let via_query = sanitize(AttributionInput::from_query(&q)).unwrap();
        assert_eq!(via_query.source.as_deref(), Some("youtube"));
        assert_eq!(via_query.medium.as_deref(), Some("video"));
    }

    #[test]
    fn nothing_left_means_none_not_an_empty_document() {
        assert_eq!(sanitize(input(json!({}))), None);
        assert_eq!(sanitize(input(json!({ "source": "   " }))), None);
        assert_eq!(sanitize(input(json!({ "bogus": "x" }))), None);
        assert_eq!(sanitize(input(json!("youtube"))), None);
        assert_eq!(sanitize(input(json!(42))), None);
        assert_eq!(sanitize(AttributionInput::default()), None);
    }

    /// The register body reads the field through serde — the lenient impl,
    /// not a derived one, so a wrong-typed value cannot 422 a sign-up.
    #[test]
    fn the_body_field_deserialises_leniently() {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            attribution: Option<AttributionInput>,
        }
        let ok: Body = serde_json::from_str(r#"{"attribution":{"source":"yt","x":1}}"#).unwrap();
        assert_eq!(ok.attribution.unwrap().source.as_deref(), Some("yt"));
        let string: Body = serde_json::from_str(r#"{"attribution":"youtube"}"#).unwrap();
        assert_eq!(string.attribution, Some(AttributionInput::default()));
        let number: Body = serde_json::from_str(r#"{"attribution":7}"#).unwrap();
        assert_eq!(number.attribution, Some(AttributionInput::default()));
        let absent: Body = serde_json::from_str(r#"{}"#).unwrap();
        assert!(absent.attribution.is_none());
        let null: Body = serde_json::from_str(r#"{"attribution":null}"#).unwrap();
        assert!(null.attribution.is_none());
    }

    #[test]
    fn utm_query_keys_map_to_their_fields() {
        let q: HashMap<String, String> = [
            ("utm_source", "youtube"),
            ("utm_medium", "video"),
            ("utm_campaign", "c1"),
            ("utm_content", "short"),
            ("utm_term", "rdp"),
            ("referrer_host", "youtube.com"),
            ("landing_path", "/blog/x/"),
            ("self_reported", "friend"),
            // The un-prefixed spellings are the BODY's, not the query's.
            ("source", "ignored"),
            ("bogus", "ignored"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let got = sanitize(AttributionInput::from_query(&q)).unwrap();
        assert_eq!(got.source.as_deref(), Some("youtube"));
        assert_eq!(got.medium.as_deref(), Some("video"));
        assert_eq!(got.campaign.as_deref(), Some("c1"));
        assert_eq!(got.content.as_deref(), Some("short"));
        assert_eq!(got.term.as_deref(), Some("rdp"));
        assert_eq!(got.referrer_host.as_deref(), Some("youtube.com"));
        assert_eq!(got.landing_path.as_deref(), Some("/blog/x/"));
        assert_eq!(got.self_reported.as_deref(), Some("friend"));
        assert_eq!(
            sanitize(AttributionInput::from_query(&HashMap::new())),
            None
        );
    }

    fn a_user(attribution: Option<SignupAttribution>) -> User {
        let now = DateTime::now();
        User {
            id: None,
            email: "round@trip.test".into(),
            unverified_email: None,
            username: "roundtrip".into(),
            display_name: "Round Trip".into(),
            avatar: None,
            bio: None,
            password_hash: None,
            status: UserStatusInfo::default(),
            presence: Presence::Offline,
            locale: "en-US".into(),
            timezone: "UTC".into(),
            is_verified: false,
            account_approval: roomler_ai_db::models::AccountApproval::pending(),
            is_mfa_enabled: false,
            last_active_at: None,
            oauth_providers: Vec::new(),
            notification_preferences: NotificationPrefs::default(),
            tutorial: TutorialState::default(),
            signup_attribution: attribution,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// The insert path serialises the STRUCT (`BaseDao::insert_one` on a
    /// typed collection), so this is the round trip that path takes. A
    /// hand-built `doc!{}` would drop the field silently — which is exactly
    /// why the spec asks for this test.
    #[test]
    fn signup_attribution_round_trips_through_bson() {
        let attr = sanitize(input(json!({
            "source": "youtube",
            "campaign": "c1",
            "landing_path": "/blog/x/",
        })))
        .unwrap();
        let doc = bson::to_document(&a_user(Some(attr.clone()))).unwrap();
        let sub = doc
            .get_document("signup_attribution")
            .expect("the subdocument is written");
        assert_eq!(sub.get_str("source").unwrap(), "youtube");
        assert_eq!(sub.get_str("campaign").unwrap(), "c1");
        assert_eq!(sub.get_str("landing_path").unwrap(), "/blog/x/");
        assert!(sub.get("medium").is_none(), "absent values are not written");
        assert!(sub.get_datetime("captured_at").is_ok());

        let back: User = bson::from_document(doc).unwrap();
        assert_eq!(back.signup_attribution, Some(attr));
    }

    #[test]
    fn no_attribution_writes_no_key_and_a_legacy_row_reads_none() {
        let doc = bson::to_document(&a_user(None)).unwrap();
        assert!(
            doc.get("signup_attribution").is_none(),
            "skip_serializing_if keeps the key off the row"
        );
        // A row written before FR-88 has no key at all.
        let mut legacy = doc.clone();
        legacy.remove("signup_attribution");
        let back: User = bson::from_document(legacy).unwrap();
        assert_eq!(back.signup_attribution, None);
    }

    /// What the parking spot stores and reads back — the same bytes the
    /// Redis round trip carries, minus Redis.
    #[test]
    fn the_parked_bytes_round_trip() {
        let attr = sanitize(input(json!({ "source": "tiktok", "medium": "profile" }))).unwrap();
        let bytes = bson::to_vec(&attr).unwrap();
        let back: SignupAttribution = bson::from_slice(&bytes).unwrap();
        assert_eq!(back, attr);
        assert_eq!(
            oauth_park_key("11111111-2222-3333-4444-555555555555"),
            "roomler:oauth_attr:11111111-2222-3333-4444-555555555555"
        );
    }

    /// An in-memory store: the seam's contract without Redis.
    #[derive(Default)]
    struct Memory {
        parked: std::sync::Mutex<HashMap<String, (Vec<u8>, u64)>>,
    }

    impl OauthAttributionStore for Memory {
        fn park(
            &self,
            key: String,
            bytes: Vec<u8>,
            ttl_secs: u64,
        ) -> StoreFuture<'_, Result<(), String>> {
            self.parked.lock().unwrap().insert(key, (bytes, ttl_secs));
            Box::pin(async { Ok(()) })
        }
        fn take(&self, key: String) -> StoreFuture<'_, Result<Option<Vec<u8>>, String>> {
            let value = self.parked.lock().unwrap().remove(&key).map(|(b, _)| b);
            Box::pin(async move { Ok(value) })
        }
    }

    /// A reachable-but-hung store: every call is a future that never
    /// completes, which is what a wedged Redis looks like to a client with
    /// no response timeout.
    struct Hung;

    impl OauthAttributionStore for Hung {
        fn park(&self, _: String, _: Vec<u8>, _: u64) -> StoreFuture<'_, Result<(), String>> {
            Box::pin(std::future::pending())
        }
        fn take(&self, _: String) -> StoreFuture<'_, Result<Option<Vec<u8>>, String>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn parking_is_keyed_by_state_with_the_cookie_ttl_and_collected_once() {
        let store = Memory::default();
        let attr = sanitize(input(json!({ "source": "youtube", "campaign": "c1" }))).unwrap();
        park_for_oauth(&store, "state-a", &attr).await.unwrap();
        assert_eq!(
            store
                .parked
                .lock()
                .unwrap()
                .get(&oauth_park_key("state-a"))
                .map(|(_, ttl)| *ttl),
            Some(OAUTH_PARK_TTL_SECS)
        );
        assert_eq!(
            take_for_oauth(&store, "state-b").await,
            None,
            "another state"
        );
        assert_eq!(take_for_oauth(&store, "state-a").await, Some(attr));
        assert_eq!(
            take_for_oauth(&store, "state-a").await,
            None,
            "read-and-delete"
        );
        // An unreadable value is dropped, never an error.
        store
            .parked
            .lock()
            .unwrap()
            .insert(oauth_park_key("state-c"), (vec![1, 2, 3], 1));
        assert_eq!(take_for_oauth(&store, "state-c").await, None);
    }

    /// M1 of the P1a review: a store that never answers costs the
    /// attribution — each call gives up at the budget — and nothing else. The
    /// callers treat `Err`/`None` as "no attribution" and go on with the
    /// redirect and the sign-in.
    #[tokio::test]
    async fn a_store_that_never_answers_costs_the_attribution_not_the_sign_in() {
        let attr = sanitize(input(json!({ "source": "youtube" }))).unwrap();
        let t0 = std::time::Instant::now();
        assert_eq!(
            park_for_oauth(&Hung, "state", &attr).await,
            Err(ParkError::TimedOut)
        );
        let after_park = t0.elapsed();
        assert!(
            after_park >= OAUTH_STORE_BUDGET && after_park < Duration::from_secs(3),
            "the park gave up at the budget, not later: {after_park:?}"
        );
        assert_eq!(take_for_oauth(&Hung, "state").await, None);
        let total = t0.elapsed();
        assert!(
            total >= 2 * OAUTH_STORE_BUDGET && total < Duration::from_secs(6),
            "the take gave up at the budget too: {total:?}"
        );
        assert!(
            ParkError::TimedOut.to_string().contains("250 ms"),
            "the log line names the budget"
        );
    }
}
