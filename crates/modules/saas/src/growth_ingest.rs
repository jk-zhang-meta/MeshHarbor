// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P8 — the promotion pipeline's ingest routes (spec §3j, D11, D12):
//!
//! * `POST /api/admin/growth/ingest/posts` —
//!   `{platform, platform_id, account, format, url, published_at,
//!   utm_source, utm_medium?, utm_campaign, utm_content?, cost_cents?}`;
//! * `POST /api/admin/growth/ingest/snapshots` —
//!   `{platform, platform_id, snapshot: "T+1d"|"T+7d"|"T+28d", taken_at,
//!   metrics: {raw name: number}}`.
//!
//! **Push, not pull** (D11): the collector runs where its credentials live
//! and needs nothing to be reachable. It authenticates with an INGEST key
//! (`Authorization: Bearer rgi_…`, minted by a platform admin at
//! `/api/admin/growth/keys`, stored hashed) that opens these two routes and
//! nothing else.
//!
//! The rules, each one AC18's or principle 7's:
//!
//! * **A missing, malformed, unknown or revoked key is a 404** — the empty
//!   404 of a path that does not exist, decided in a gate before the body is
//!   read, so the routes cannot be told from absent ones. `growth.enabled =
//!   false` answers the same. Never 401 / 403.
//! * **No post text, ever.** The pipeline sends ids, URLs, numbers and the
//!   campaign key; a body with a field that looks like a caption, a body, a
//!   title or any other copy is refused whole (`post_text_refused`), and an
//!   unknown field is refused too (`unknown_field`) — the shape is closed.
//! * **An unknown platform is refused** (`unknown_platform`); the platforms
//!   are the taxonomy's (`campaign::PLATFORMS`).
//! * **Idempotent**: a post is `(platform, platform_id)` — a re-push updates
//!   it; a snapshot is `(platform, platform_id, snapshot)` — written ONCE.
//! * **Bounded everywhere**: a 16 KiB body, every string's length and
//!   alphabet, at most 50 metrics, numbers only and finite.
//!
//! The campaign key goes through `CampaignKey::normalized` — the cleaning a
//! sign-up gets at ingress — so a post meets its visits and its sign-ups on
//! one spelling.

use std::collections::BTreeMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::campaign::{CampaignKey, normalize_platform};
use meshharbor_services::dao::{
    growth_key::{GrowthKeyDao, GrowthKeyKind},
    growth_social::{GrowthSocialDao, NewPost, PostKey, PostSnapshot, SNAPSHOTS, Upserted},
};
use serde::Serialize;
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::SaasState;

/// The largest body either route reads.
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// The most metrics one snapshot carries.
pub const MAX_METRICS: usize = 50;
/// The largest cost a post may declare (100,000.00 in the account currency).
pub const MAX_COST_CENTS: i64 = 10_000_000;
/// The largest metric value accepted (beyond any real count).
pub const MAX_METRIC_ABS: f64 = 1e15;

/// The fields a post push may carry — exactly these.
pub const POST_FIELDS: [&str; 11] = [
    "platform",
    "platform_id",
    "account",
    "format",
    "url",
    "published_at",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "cost_cents",
];
/// The fields a snapshot push may carry — exactly these.
pub const SNAPSHOT_FIELDS: [&str; 5] =
    ["platform", "platform_id", "snapshot", "taken_at", "metrics"];

/// Word parts that mark a field as post TEXT — refused by name, whatever
/// its value, before anything else is looked at.
const TEXT_WORDS: &[&str] = &[
    "caption",
    "captions",
    "body",
    "text",
    "texts",
    "title",
    "titles",
    "description",
    "desc",
    "message",
    "msg",
    "content",
    "copy",
    "transcript",
    "subtitle",
    "subtitles",
    "summary",
    "headline",
    "comment",
    "comments",
    "hashtag",
    "hashtags",
    "alt",
    "html",
    "markdown",
    "excerpt",
    "snippet",
    "quote",
];

/// A refused push: a stable `code` for the pipeline and a short message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub error: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(error: &'static str, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        (StatusCode::UNPROCESSABLE_ENTITY, Json(self)).into_response()
    }
}

/// The words of a field name: split at non-alphanumerics and at a lower →
/// upper case step, lowercased (`postText` → `post`, `text`).
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether a field NAME looks like it carries post text.
pub fn looks_like_text_field(name: &str) -> bool {
    words(name).iter().any(|w| TEXT_WORDS.contains(&w.as_str()))
}

/// The body as an object whose every field is one of `allowed` — a field
/// that looks like text is `post_text_refused`, any other stranger
/// `unknown_field`.
fn closed_object<'a>(v: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, Refusal> {
    let obj = v
        .as_object()
        .ok_or_else(|| Refusal::new("not_an_object", "the body must be a JSON object"))?;
    // Text first: a body carrying copy is refused for THAT, whatever else
    // is wrong with it.
    if let Some(k) = obj
        .keys()
        .find(|k| !allowed.contains(&k.as_str()) && looks_like_text_field(k))
    {
        return Err(Refusal::new(
            "post_text_refused",
            format!(
                "`{}` looks like post text; the ingest stores ids, urls, numbers and the campaign key, never content",
                bounded(k)
            ),
        ));
    }
    if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(Refusal::new(
            "unknown_field",
            format!("`{}` is not a field of this push", bounded(k)),
        ));
    }
    Ok(obj)
}

/// A client-chosen string, cut for an error message.
fn bounded(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(40).collect()
}

fn string_field<'a>(
    obj: &'a Map<String, Value>,
    name: &str,
    required: bool,
) -> Result<Option<&'a str>, Refusal> {
    match obj.get(name) {
        None | Some(Value::Null) if !required => Ok(None),
        None | Some(Value::Null) => Err(Refusal::new(
            "missing_field",
            format!("`{name}` is required"),
        )),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(Refusal::new(
            "invalid_field",
            format!("`{name}` must be a string"),
        )),
    }
}

/// A short token: `max` characters at most, every one from `allowed`.
fn token(
    raw: &str,
    name: &str,
    max: usize,
    allowed: impl Fn(char) -> bool,
    error: &'static str,
) -> Result<String, Refusal> {
    let s = raw.trim();
    if s.is_empty() || s.chars().count() > max || !s.chars().all(allowed) {
        return Err(Refusal::new(
            error,
            format!("`{name}` must be 1–{max} characters of its alphabet"),
        ));
    }
    Ok(s.to_string())
}

fn platform_of(obj: &Map<String, Value>) -> Result<&'static str, Refusal> {
    let raw = string_field(obj, "platform", true)?.unwrap_or_default();
    normalize_platform(raw).ok_or_else(|| {
        Refusal::new(
            "unknown_platform",
            format!(
                "`{}` is not one of {}",
                bounded(raw),
                meshharbor_core::campaign::PLATFORMS.join(", ")
            ),
        )
    })
}

fn platform_id_of(obj: &Map<String, Value>) -> Result<String, Refusal> {
    token(
        string_field(obj, "platform_id", true)?.unwrap_or_default(),
        "platform_id",
        128,
        |c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.'),
        "invalid_platform_id",
    )
}

/// An instant within bounds: RFC 3339, not before 2020, not more than
/// `ahead_ms` past `now`.
fn instant_of(
    obj: &Map<String, Value>,
    name: &str,
    now: DateTime,
    ahead_ms: i64,
    error: &'static str,
) -> Result<DateTime, Refusal> {
    let raw = string_field(obj, name, true)?.unwrap_or_default();
    let t = DateTime::parse_rfc3339_str(raw.trim())
        .map_err(|_| Refusal::new(error, format!("`{name}` must be an RFC 3339 instant")))?;
    let floor = DateTime::parse_rfc3339_str("2020-01-01T00:00:00Z").expect("a fixed instant");
    if t < floor || t.timestamp_millis() > now.timestamp_millis() + ahead_ms {
        return Err(Refusal::new(
            error,
            format!("`{name}` is outside 2020 … now"),
        ));
    }
    Ok(t)
}

/// A validated post push.
pub fn validate_post(v: &Value, now: DateTime) -> Result<NewPost, Refusal> {
    let obj = closed_object(v, &POST_FIELDS)?;
    let platform = platform_of(obj)?;
    let platform_id = platform_id_of(obj)?;
    let account = token(
        string_field(obj, "account", true)?.unwrap_or_default(),
        "account",
        64,
        |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'),
        "invalid_account",
    )?;
    let format = token(
        string_field(obj, "format", true)?.unwrap_or_default(),
        "format",
        32,
        |c| c.is_ascii_alphanumeric() || c == '-',
        "invalid_format",
    )?
    .to_ascii_lowercase();
    let url_raw = string_field(obj, "url", true)?.unwrap_or_default().trim();
    let url_ok = url_raw.len() <= 512
        && (url_raw.starts_with("https://") || url_raw.starts_with("http://"))
        && !url_raw.chars().any(|c| c.is_control() || c.is_whitespace())
        && reqwest::Url::parse(url_raw).is_ok_and(|u| u.host_str().is_some_and(|h| !h.is_empty()));
    if !url_ok {
        return Err(Refusal::new(
            "invalid_url",
            "`url` must be an http(s) URL of at most 512 characters",
        ));
    }
    let published_at = instant_of(obj, "published_at", now, 86_400_000, "invalid_published_at")?;
    let source = string_field(obj, "utm_source", true)?;
    let campaign = string_field(obj, "utm_campaign", true)?;
    let medium = string_field(obj, "utm_medium", false)?;
    let content = string_field(obj, "utm_content", false)?;
    let key = CampaignKey::normalized(source, medium, campaign, content)
        .filter(|k| k.campaign.is_some())
        .ok_or_else(|| {
            Refusal::new(
                "invalid_key",
                "`utm_source` and `utm_campaign` must be printable ASCII of at most 64 characters",
            )
        })?;
    let cost_cents = match obj.get("cost_cents") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(c) if (0..=MAX_COST_CENTS).contains(&c) => Some(c),
            _ => {
                return Err(Refusal::new(
                    "invalid_cost",
                    format!("`cost_cents` must be a whole number from 0 to {MAX_COST_CENTS}"),
                ));
            }
        },
        Some(_) => {
            return Err(Refusal::new(
                "invalid_cost",
                "`cost_cents` must be a whole number",
            ));
        }
    };
    Ok(NewPost {
        platform: platform.to_string(),
        platform_id,
        account,
        format,
        url: url_raw.to_string(),
        published_at,
        key: PostKey {
            source: key.source,
            medium: key.medium,
            campaign: key.campaign,
            content: key.content,
        },
        cost_cents,
    })
}

/// A validated snapshot push (`received_at` is the caller's `now`).
pub fn validate_snapshot(v: &Value, now: DateTime) -> Result<PostSnapshot, Refusal> {
    let obj = closed_object(v, &SNAPSHOT_FIELDS)?;
    let platform = platform_of(obj)?;
    let platform_id = platform_id_of(obj)?;
    let raw = string_field(obj, "snapshot", true)?.unwrap_or_default();
    let snapshot = SNAPSHOTS
        .iter()
        .copied()
        .find(|s| *s == raw.trim())
        .ok_or_else(|| {
            Refusal::new(
                "unknown_snapshot",
                format!("`snapshot` must be one of {}", SNAPSHOTS.join(", ")),
            )
        })?;
    let taken_at = instant_of(obj, "taken_at", now, 3_600_000, "invalid_taken_at")?;
    let metrics_obj = match obj.get("metrics") {
        Some(Value::Object(m)) => m,
        _ => {
            return Err(Refusal::new(
                "invalid_metrics",
                "`metrics` must be an object of raw metric names to numbers",
            ));
        }
    };
    if metrics_obj.is_empty() || metrics_obj.len() > MAX_METRICS {
        return Err(Refusal::new(
            "invalid_metrics",
            format!("`metrics` must hold 1–{MAX_METRICS} entries"),
        ));
    }
    let mut metrics = BTreeMap::new();
    for (name, value) in metrics_obj {
        let name_ok = !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
        if !name_ok {
            return Err(Refusal::new(
                "invalid_metrics",
                format!(
                    "metric name `{}` must be 1–64 characters of [A-Za-z0-9_.:-]",
                    bounded(name)
                ),
            ));
        }
        let Some(v) = value
            .as_f64()
            .filter(|v| v.is_finite() && v.abs() <= MAX_METRIC_ABS)
        else {
            return Err(Refusal::new(
                "metric_not_numeric",
                format!("metric `{}` must be a finite number", bounded(name)),
            ));
        };
        metrics.insert(name.clone(), v);
    }
    Ok(PostSnapshot {
        id: None,
        platform: platform.to_string(),
        platform_id,
        snapshot: snapshot.to_string(),
        taken_at,
        metrics,
        received_at: now,
    })
}

// ── The gate ─────────────────────────────────────────────────────────────

/// Which key opened a request, for the use log (never the key).
#[derive(Debug, Clone)]
pub struct IngestKey {
    pub id: ObjectId,
    pub prefix: String,
}

/// The empty 404 of a path that does not exist — what every refusal of the
/// gate looks like, so a wrong key cannot tell the routes exist.
fn absent() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// The ingest key gate, before the body is read: `growth.enabled` and a
/// live ingest key, or the empty 404. A database error is a 503 — a Mongo
/// blip must not tell the pipeline its key was revoked.
pub async fn require_ingest_key(
    State(state): State<SaasState>,
    mut req: Request,
    next: Next,
) -> Response {
    if !state.settings.growth.enabled {
        return absent();
    }
    let Some(raw) = bearer(req.headers()) else {
        return absent();
    };
    let dao = GrowthKeyDao::new(&state.db);
    match dao.find_live(GrowthKeyKind::Ingest, raw).await {
        Ok(Some(key)) => {
            if let Err(e) = dao.touch(key.id, DateTime::now()).await {
                warn!(key = %key.prefix, %e, "growth ingest: could not record the key's use");
            }
            req.extensions_mut().insert(IngestKey {
                id: key.id,
                prefix: key.prefix,
            });
            next.run(req).await
        }
        Ok(None) => absent(),
        Err(e) => {
            warn!(%e, "growth ingest: key lookup failed");
            (StatusCode::SERVICE_UNAVAILABLE, "try again").into_response()
        }
    }
}

// ── The routes ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Stored {
    pub status: Upserted,
    pub platform: String,
    pub platform_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
}

/// The body as JSON, or `None` — answered by [`invalid_json`].
fn parse_body(body: &Bytes) -> Option<Value> {
    serde_json::from_slice::<Value>(body).ok()
}

/// 400: the body is not JSON at all (a key-holder's malformed push).
fn invalid_json() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(Refusal::new("invalid_json", "the body is not JSON")),
    )
        .into_response()
}

fn stored_status(s: Upserted) -> StatusCode {
    if s == Upserted::Created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    }
}

/// `POST /api/admin/growth/ingest/posts`
pub async fn ingest_post(
    State(state): State<SaasState>,
    axum::Extension(key): axum::Extension<IngestKey>,
    body: Bytes,
) -> Response {
    let Some(v) = parse_body(&body) else {
        return invalid_json();
    };
    let now = DateTime::now();
    let post = match validate_post(&v, now) {
        Ok(p) => p,
        Err(refusal) => {
            info!(key = %key.prefix, error = refusal.error, "growth ingest: post refused");
            return refusal.into_response();
        }
    };
    match GrowthSocialDao::new(&state.db)
        .upsert_post(&post, now)
        .await
    {
        Ok(status) => {
            info!(
                key = %key.prefix, platform = %post.platform, platform_id = %post.platform_id,
                status = ?status, "growth ingest: post"
            );
            (
                stored_status(status),
                Json(Stored {
                    status,
                    platform: post.platform,
                    platform_id: post.platform_id,
                    snapshot: None,
                }),
            )
                .into_response()
        }
        Err(e) => meshharbor_core::error::ApiError::from(e).into_response(),
    }
}

/// `POST /api/admin/growth/ingest/snapshots`
pub async fn ingest_snapshot(
    State(state): State<SaasState>,
    axum::Extension(key): axum::Extension<IngestKey>,
    body: Bytes,
) -> Response {
    let Some(v) = parse_body(&body) else {
        return invalid_json();
    };
    let now = DateTime::now();
    let snap = match validate_snapshot(&v, now) {
        Ok(s) => s,
        Err(refusal) => {
            info!(key = %key.prefix, error = refusal.error, "growth ingest: snapshot refused");
            return refusal.into_response();
        }
    };
    let dao = GrowthSocialDao::new(&state.db);
    match dao.post_exists(&snap.platform, &snap.platform_id).await {
        Ok(true) => {}
        Ok(false) => {
            return Refusal::new("unknown_post", "push the post before its snapshots")
                .into_response();
        }
        Err(e) => return meshharbor_core::error::ApiError::from(e).into_response(),
    }
    match dao.insert_snapshot_once(&snap).await {
        Ok(status) => {
            info!(
                key = %key.prefix, platform = %snap.platform, platform_id = %snap.platform_id,
                snapshot = %snap.snapshot, status = ?status, "growth ingest: snapshot"
            );
            (
                stored_status(status),
                Json(Stored {
                    status,
                    platform: snap.platform,
                    platform_id: snap.platform_id,
                    snapshot: Some(snap.snapshot),
                }),
            )
                .into_response()
        }
        Err(e) => meshharbor_core::error::ApiError::from(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime {
        DateTime::parse_rfc3339_str("2026-10-20T12:00:00Z").unwrap()
    }

    fn post() -> Value {
        json!({
            "platform": "LinkedIn",
            "platform_id": "urn:li:share:7123",
            "account": "meshharbor",
            "format": "Post",
            "url": "https://www.linkedin.com/feed/update/urn:li:share:7123/",
            "published_at": "2026-10-19T09:00:00Z",
            "utm_source": "LinkedIn",
            "utm_medium": "post",
            "utm_campaign": "20261019-SSH",
            "cost_cents": 500,
        })
    }

    fn with(mut v: Value, k: &str, x: Value) -> Value {
        v[k] = x;
        v
    }

    fn without(mut v: Value, k: &str) -> Value {
        v.as_object_mut().unwrap().remove(k);
        v
    }

    fn code(r: Result<impl std::fmt::Debug, Refusal>) -> &'static str {
        r.expect_err("refused").error
    }

    #[test]
    fn a_post_validates_and_normalises() {
        let p = validate_post(&post(), now()).unwrap();
        assert_eq!(p.platform, "linkedin");
        assert_eq!(p.format, "post");
        assert_eq!(p.key.source, "linkedin");
        assert_eq!(p.key.campaign.as_deref(), Some("20261019-ssh"));
        assert_eq!(p.key.content, None);
        assert_eq!(p.cost_cents, Some(500));
        // Optional fields may be absent or null.
        let p = validate_post(
            &with(without(post(), "cost_cents"), "utm_content", Value::Null),
            now(),
        )
        .unwrap();
        assert_eq!(p.cost_cents, None);
        // `Twitter` is `x`.
        assert_eq!(
            validate_post(&with(post(), "platform", json!("Twitter")), now())
                .unwrap()
                .platform,
            "x"
        );
    }

    /// AC18 — an unknown platform is refused, by name.
    #[test]
    fn an_unknown_platform_is_refused() {
        for p in ["mastodon", "reddit", "", "linkedin.com"] {
            assert_eq!(
                code(validate_post(&with(post(), "platform", json!(p)), now())),
                "unknown_platform",
                "{p}"
            );
        }
        assert_eq!(
            code(validate_post(&with(post(), "platform", json!(5)), now())),
            "invalid_field"
        );
    }

    /// AC18 — any field that looks like post text refuses the whole push,
    /// whatever its value; an unknown field that does not look like text is
    /// refused too (the shape is closed).
    #[test]
    fn a_body_carrying_post_text_is_refused() {
        for field in [
            "caption",
            "text",
            "title",
            "body",
            "description",
            "postText",
            "post_body",
            "Caption",
            "message",
            "content",
            "alt_text",
            "hashtags",
        ] {
            assert_eq!(
                code(validate_post(
                    &with(post(), field, json!("Hello world")),
                    now()
                )),
                "post_text_refused",
                "{field}"
            );
            assert_eq!(
                code(validate_post(&with(post(), field, Value::Null), now())),
                "post_text_refused",
                "{field} = null"
            );
        }
        let snap = json!({ "platform": "youtube", "platform_id": "abc", "snapshot": "T+1d",
            "taken_at": "2026-10-20T10:00:00Z", "metrics": { "views": 1 }, "title": "x" });
        assert_eq!(code(validate_snapshot(&snap, now())), "post_text_refused");
        // utm_content is a key field, not text.
        assert!(validate_post(&with(post(), "utm_content", json!("desc-top")), now()).is_ok());
        assert_eq!(
            code(validate_post(
                &with(post(), "thumbnail_url", json!("https://x")),
                now()
            )),
            "unknown_field"
        );
        assert!(looks_like_text_field("captionText"));
        assert!(!looks_like_text_field("platform_id"));
        assert!(!looks_like_text_field("cost_cents"));
    }

    #[test]
    fn every_field_is_bounded() {
        let long = "a".repeat(129);
        assert_eq!(
            code(validate_post(
                &with(post(), "platform_id", json!(long)),
                now()
            )),
            "invalid_platform_id"
        );
        assert_eq!(
            code(validate_post(
                &with(post(), "platform_id", json!("a b")),
                now()
            )),
            "invalid_platform_id"
        );
        assert_eq!(
            code(validate_post(
                &with(post(), "account", json!("MeshHarbor")),
                now()
            )),
            "invalid_account"
        );
        for url in [
            "javascript:alert(1)",
            "ftp://x.example",
            "https://",
            "https://a b.example",
            "",
        ] {
            assert_eq!(
                code(validate_post(&with(post(), "url", json!(url)), now())),
                "invalid_url",
                "{url}"
            );
        }
        let long_url = format!("https://x.example/{}", "a".repeat(512));
        assert_eq!(
            code(validate_post(&with(post(), "url", json!(long_url)), now())),
            "invalid_url"
        );
        for t in [
            "2019-12-31T23:59:59Z",
            "2026-10-21T13:00:00Z",
            "yesterday",
            "2026-10-19",
        ] {
            assert_eq!(
                code(validate_post(
                    &with(post(), "published_at", json!(t)),
                    now()
                )),
                "invalid_published_at",
                "{t}"
            );
        }
        for c in [json!(-1), json!(10_000_001), json!(1.5), json!("500")] {
            assert_eq!(
                code(validate_post(&with(post(), "cost_cents", c.clone()), now())),
                "invalid_cost",
                "{c}"
            );
        }
        assert_eq!(
            code(validate_post(&without(post(), "utm_campaign"), now())),
            "missing_field"
        );
        assert_eq!(
            code(validate_post(
                &with(post(), "utm_source", json!("yöutube")),
                now()
            )),
            "invalid_key"
        );
        assert_eq!(code(validate_post(&json!([1, 2]), now())), "not_an_object");
    }

    #[test]
    fn a_snapshot_keeps_raw_metric_names_numbers_only() {
        let snap = json!({ "platform": "yt", "platform_id": "dQw4w9WgXcQ", "snapshot": "T+7d",
            "taken_at": "2026-10-20T10:00:00Z",
            "metrics": { "views": 120, "averageViewPercentage": 41.5, "public_metrics.impression_count": 9 } });
        let s = validate_snapshot(&snap, now()).unwrap();
        assert_eq!(s.platform, "youtube");
        assert_eq!(s.snapshot, "T+7d");
        assert_eq!(s.metrics["averageViewPercentage"], 41.5);
        assert_eq!(s.metrics["public_metrics.impression_count"], 9.0);
        assert_eq!(s.received_at, now());
        let bad = |k: &str, x: Value| code(validate_snapshot(&with(snap.clone(), k, x), now()));
        assert_eq!(bad("snapshot", json!("T+2d")), "unknown_snapshot");
        assert_eq!(bad("snapshot", json!("t+1d")), "unknown_snapshot");
        assert_eq!(bad("metrics", json!({})), "invalid_metrics");
        assert_eq!(bad("metrics", json!([1])), "invalid_metrics");
        assert_eq!(
            bad("metrics", json!({ "views": "120" })),
            "metric_not_numeric"
        );
        assert_eq!(
            bad("metrics", json!({ "views": null })),
            "metric_not_numeric"
        );
        assert_eq!(
            bad("metrics", json!({ "views": 1e16 })),
            "metric_not_numeric"
        );
        assert_eq!(bad("metrics", json!({ "a b": 1 })), "invalid_metrics");
        assert_eq!(
            bad("taken_at", json!("2026-10-20T14:00:00Z")),
            "invalid_taken_at"
        );
        let many: Map<String, Value> = (0..=MAX_METRICS)
            .map(|i| (format!("m{i}"), json!(i)))
            .collect();
        assert_eq!(bad("metrics", Value::Object(many)), "invalid_metrics");
    }

    #[test]
    fn words_split_at_separators_and_case_steps() {
        assert_eq!(words("postText"), vec!["post", "text"]);
        assert_eq!(words("post_body-html"), vec!["post", "body", "html"]);
        assert_eq!(words("ALT"), vec!["alt"]);
        assert_eq!(words("utm_content"), vec!["utm", "content"]);
        assert_eq!(words("v2Title"), vec!["v2", "title"]);
    }
}
