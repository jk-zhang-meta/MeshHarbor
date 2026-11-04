// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the Google Search Console client (spec §3k): a service
//! account's access token, Search Analytics and URL Inspection.
//!
//! * **The credential** is a service account's JSON key
//!   (`MESHHARBOR__GROWTH__SEARCH_CONSOLE_KEY`, from a Secret). The token is the
//!   OAuth 2.0 JWT-bearer grant: an RS256 assertion `{iss: client_email,
//!   scope: webmasters.readonly, aud: token_uri, iat, exp ≤ iat + 1 h}`
//!   posted to the key's `token_uri`, and the access token cached until a
//!   minute before it expires. `webmasters.readonly` covers both Search
//!   Analytics and URL Inspection.
//! * **The key is never logged** and never part of an error: every
//!   [`ScError`] is a short reason a pull row can store.
//! * **Explicit timeouts**, as every outside call here has.
//! * Search Console's days are **Pacific-time days** (America/Los_Angeles),
//!   not UTC: a stored `day` is Google's own date.
//! * Google's answer is read leniently where Google is lenient: `rows` is
//!   absent on an empty answer, and `ctr` / `position` have been seen as the
//!   string `"NaN"`.

use std::{sync::Arc, time::Duration};

use bson::DateTime;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Deserializer, Serialize};

/// Read-only Search Console: Search Analytics and URL Inspection.
pub const SCOPE: &str = "https://www.googleapis.com/auth/webmasters.readonly";
/// Where a key without `token_uri` gets its token.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// The JWT-bearer grant type.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Per-request ceiling.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// Rows per page — the API's maximum.
pub const ROW_LIMIT: u32 = 25_000;
/// Pages followed per breakdown before the answer is called truncated
/// (the API keeps at most 50,000 rows a day per search type anyway).
pub const MAX_PAGES: u32 = 4;
/// A token is renewed this long before it expires.
const TOKEN_MARGIN_MS: i64 = 60_000;
/// The largest answer read: a page of 25,000 rows is a few MB.
pub const MAX_BODY_BYTES: usize = 32 << 20;

/// Why a call gave nothing. `Display` is the short reason a pull row
/// stores; none carries the key, a token or a body.
#[derive(Debug, Clone, PartialEq)]
pub enum ScError {
    /// The configured key is not a usable service-account key.
    BadKey(String),
    /// The token endpoint refused the assertion (`invalid_grant`, …).
    Token(String),
    /// 401 from the API: the token is not accepted.
    Unauthorized,
    /// 403: the service account is not a user of the property — or, for
    /// URL Inspection, not one with enough permission.
    Forbidden(String),
    /// 429 or a quota 403.
    Quota(String),
    Status(u16, String),
    Timeout,
    Transport(String),
    Decode(String),
}

impl std::fmt::Display for ScError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey(m) => write!(f, "search console key unusable: {m}"),
            Self::Token(m) => write!(f, "search console unreachable: token refused ({m})"),
            Self::Unauthorized => write!(f, "search console unreachable: unauthorized (401)"),
            Self::Forbidden(m) => write!(f, "search console unreachable: forbidden (403) {m}"),
            Self::Quota(m) => write!(f, "search console unreachable: quota exceeded {m}"),
            Self::Status(c, m) => write!(f, "search console unreachable: HTTP {c} {m}"),
            Self::Timeout => write!(f, "search console unreachable: timed out"),
            Self::Transport(e) => write!(f, "search console unreachable: {e}"),
            Self::Decode(e) => write!(f, "search console unreachable: unreadable answer ({e})"),
        }
    }
}

impl ScError {
    /// Whether a later call in the same run could succeed.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::Status(..) | Self::Decode(_))
    }
}

/// Bound a server-supplied string before it lands in a stored reason.
fn short(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(160).collect()
}

/// The service-account key file's fields this client reads (Google's own
/// names); everything else in the file is ignored.
#[derive(Deserialize)]
struct KeyFile {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// One Search Analytics request (`searchAnalytics.query`'s body).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScQuery {
    pub start_date: String,
    pub end_date: String,
    pub dimensions: Vec<String>,
    #[serde(rename = "type")]
    pub search_type: String,
    pub data_state: String,
    pub row_limit: u32,
    pub start_row: u32,
}

impl ScQuery {
    /// Web search, one breakdown, `[from, to]` (Google's own dates).
    pub fn new(from: &str, to: &str, dimensions: &[&str], data_state: &str) -> Self {
        Self {
            start_date: from.to_string(),
            end_date: to.to_string(),
            dimensions: dimensions.iter().map(|d| d.to_string()).collect(),
            search_type: "web".into(),
            data_state: data_state.into(),
            row_limit: ROW_LIMIT,
            start_row: 0,
        }
    }
}

/// A number Google may send as a number, as an exponent, or as `"NaN"`.
fn lenient_f64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(match v {
        serde_json::Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        serde_json::Value::String(s) => s.parse::<f64>().ok().filter(|f| f.is_finite()),
        _ => None,
    })
}

/// One row of a breakdown, in the order of the request's `dimensions`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ScRow {
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default, deserialize_with = "lenient_f64")]
    pub clicks: Option<f64>,
    #[serde(default, deserialize_with = "lenient_f64")]
    pub impressions: Option<f64>,
    #[serde(default, deserialize_with = "lenient_f64")]
    pub position: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ScMeta {
    /// The first date whose data is not final yet; present only for a
    /// `dataState: all` query grouped by `date` whose range reaches it.
    #[serde(
        default,
        rename = "firstIncompleteDate",
        alias = "first_incomplete_date"
    )]
    pub first_incomplete_date: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ScResponse {
    /// Absent on an empty answer — the same as `[]`.
    #[serde(default)]
    pub rows: Vec<ScRow>,
    #[serde(default)]
    pub metadata: Option<ScMeta>,
}

/// URL Inspection's index status, as Google spells it.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IndexStatus {
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub coverage_state: Option<String>,
    #[serde(default)]
    pub indexing_state: Option<String>,
    #[serde(default)]
    pub page_fetch_state: Option<String>,
    #[serde(default)]
    pub robots_txt_state: Option<String>,
    /// RFC 3339; absent when the URL was never crawled.
    #[serde(default)]
    pub last_crawl_time: Option<String>,
    #[serde(default)]
    pub google_canonical: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectResult {
    #[serde(default)]
    index_status_result: Option<IndexStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectResponse {
    #[serde(default)]
    inspection_result: Option<InspectResult>,
}

#[derive(Clone)]
pub struct ScClient {
    site: String,
    api_base: String,
    token_uri: String,
    client_email: String,
    key_id: Option<String>,
    key: EncodingKey,
    alg: Algorithm,
    http: reqwest::Client,
    token: Arc<tokio::sync::Mutex<Option<(String, i64)>>>,
}

impl std::fmt::Debug for ScClient {
    /// No key and no token, ever.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScClient")
            .field("site", &self.site)
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

impl ScClient {
    /// This server's client: `None` without a key (nothing is ever asked),
    /// `Some(Err)` when the key is set but unusable — the pullers say so
    /// once and ask nothing.
    pub fn from_settings(g: &meshharbor_config::GrowthSettings) -> Option<Result<Self, ScError>> {
        if !g.search_console_configured() {
            return None;
        }
        Some(Self::from_key_json(
            &g.search_console_site,
            &g.search_console_api_url,
            &g.search_console_key,
        ))
    }

    /// The client a service-account key JSON describes; RS256, as Google
    /// requires. `BadKey` names what is wrong without echoing the key.
    pub fn from_key_json(site: &str, api_base: &str, key_json: &str) -> Result<Self, ScError> {
        let k: KeyFile = serde_json::from_str(key_json.trim())
            .map_err(|_| ScError::BadKey("not a service-account key JSON".into()))?;
        if k.kind.as_deref().is_some_and(|t| t != "service_account") {
            return Err(ScError::BadKey(
                "the key's type is not service_account".into(),
            ));
        }
        if k.client_email.trim().is_empty() {
            return Err(ScError::BadKey("the key has no client_email".into()));
        }
        let key = EncodingKey::from_rsa_pem(k.private_key.as_bytes())
            .map_err(|_| ScError::BadKey("the private_key is not an RSA PEM key".into()))?;
        Ok(Self::with_signer(
            site,
            api_base,
            k.token_uri.as_deref().unwrap_or(DEFAULT_TOKEN_URI),
            &k.client_email,
            k.private_key_id,
            key,
            Algorithm::RS256,
        ))
    }

    /// The client with an explicit signer — what a test uses with HS256
    /// and a fake token endpoint; production always comes through
    /// [`Self::from_key_json`].
    pub fn with_signer(
        site: &str,
        api_base: &str,
        token_uri: &str,
        client_email: &str,
        key_id: Option<String>,
        key: EncodingKey,
        alg: Algorithm,
    ) -> Self {
        Self {
            site: site.trim().to_string(),
            api_base: api_base.trim_end_matches('/').to_string(),
            token_uri: token_uri.to_string(),
            client_email: client_email.trim().to_string(),
            key_id,
            key,
            alg,
            http: http_client(TIMEOUT),
            token: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// The same client with another per-request ceiling — a test's way to
    /// reach a timeout without waiting [`TIMEOUT`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = http_client(timeout);
        self
    }

    pub fn site(&self) -> &str {
        &self.site
    }

    /// The signed assertion for `now` (seconds since the epoch).
    pub fn assertion(&self, now_s: i64) -> Result<String, ScError> {
        let mut header = Header::new(self.alg);
        header.kid = self.key_id.clone();
        jsonwebtoken::encode(
            &header,
            &Claims {
                iss: &self.client_email,
                scope: SCOPE,
                aud: &self.token_uri,
                iat: now_s,
                exp: now_s + 3600,
            },
            &self.key,
        )
        .map_err(|_| ScError::BadKey("the assertion could not be signed".into()))
    }

    /// A cached access token, renewed a minute before it expires.
    async fn access_token(&self) -> Result<String, ScError> {
        let mut slot = self.token.lock().await;
        let now_ms = DateTime::now().timestamp_millis();
        if let Some((t, exp)) = slot.as_ref()
            && *exp - TOKEN_MARGIN_MS > now_ms
        {
            return Ok(t.clone());
        }
        let assertion = self.assertion(now_ms / 1000)?;
        let sent = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", GRANT_TYPE),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(transport)?;
        let status = sent.status().as_u16();
        let body = read(sent).await?;
        if !(200..300).contains(&status) {
            let why = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(short))
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(ScError::Token(why));
        }
        let t: TokenResponse =
            serde_json::from_slice(&body).map_err(|e| ScError::Decode(short(&e.to_string())))?;
        let exp = now_ms + t.expires_in.unwrap_or(3600) * 1000;
        *slot = Some((t.access_token.clone(), exp));
        Ok(t.access_token)
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        url: String,
        body: &impl Serialize,
    ) -> Result<T, ScError> {
        let token = self.access_token().await?;
        let sent = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(transport)?;
        let status = sent.status().as_u16();
        let body = read(sent).await?;
        if !(200..300).contains(&status) {
            let msg = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.pointer("/error/message")
                        .and_then(|m| m.as_str())
                        .map(short)
                })
                .unwrap_or_default();
            return Err(match status {
                401 => ScError::Unauthorized,
                429 => ScError::Quota(msg),
                403 if msg.to_ascii_lowercase().contains("quota") => ScError::Quota(msg),
                403 => ScError::Forbidden(msg),
                _ => ScError::Status(status, msg),
            });
        }
        serde_json::from_slice::<T>(&body).map_err(|e| ScError::Decode(short(&e.to_string())))
    }

    /// The property's path segment: `sc-domain:meshharbor.itachi.fans` →
    /// `sc-domain%3Ameshharbor.itachi.fans` (every reserved character encoded).
    fn site_segment(&self) -> String {
        url::form_urlencoded::byte_serialize(self.site.as_bytes()).collect()
    }

    /// One page of a Search Analytics breakdown.
    pub async fn query(&self, q: &ScQuery) -> Result<ScResponse, ScError> {
        let url = format!(
            "{}/webmasters/v3/sites/{}/searchAnalytics/query",
            self.api_base,
            self.site_segment()
        );
        self.post(url, q).await
    }

    /// Every page of a breakdown, and whether [`MAX_PAGES`] cut it short.
    pub async fn query_all(&self, q: &ScQuery) -> Result<(ScResponse, bool), ScError> {
        let mut page = q.clone();
        page.row_limit = ROW_LIMIT;
        page.start_row = 0;
        let mut out = ScResponse::default();
        for i in 0..MAX_PAGES {
            let r = self.query(&page).await?;
            let n = r.rows.len() as u32;
            out.rows.extend(r.rows);
            if out.metadata.is_none() {
                out.metadata = r.metadata;
            }
            if n < ROW_LIMIT {
                return Ok((out, false));
            }
            if i + 1 == MAX_PAGES {
                return Ok((out, true));
            }
            page.start_row += n;
        }
        Ok((out, false))
    }

    /// URL Inspection's index status of one URL of the property.
    pub async fn inspect(&self, url: &str) -> Result<IndexStatus, ScError> {
        let body = serde_json::json!({ "inspectionUrl": url, "siteUrl": self.site });
        let r: InspectResponse = self
            .post(
                format!("{}/v1/urlInspection/index:inspect", self.api_base),
                &body,
            )
            .await?;
        Ok(r.inspection_result
            .and_then(|i| i.index_status_result)
            .unwrap_or_default())
    }
}

fn transport(e: reqwest::Error) -> ScError {
    if e.is_timeout() {
        ScError::Timeout
    } else {
        ScError::Transport(short(&e.without_url().to_string()))
    }
}

fn http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .build()
        .expect("a reqwest client with a timeout builds")
}

/// A body, capped at [`MAX_BODY_BYTES`].
async fn read(resp: reqwest::Response) -> Result<Vec<u8>, ScError> {
    crate::capped::read_capped(resp, MAX_BODY_BYTES)
        .await
        .map_err(|e| match e {
            crate::capped::BodyError::Timeout => ScError::Timeout,
            other => ScError::Transport(short(&other.to_string())),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs_client(site: &str) -> ScClient {
        ScClient::with_signer(
            site,
            "https://searchconsole.googleapis.com/",
            "https://oauth2.example.test/token",
            "reader@proj.iam.gserviceaccount.com",
            Some("kid-1".into()),
            EncodingKey::from_secret(b"test-secret"),
            Algorithm::HS256,
        )
    }

    /// The body is `searchAnalytics.query`'s, in Google's spelling.
    #[test]
    fn the_query_body_is_the_apis_shape() {
        let q = ScQuery::new("2026-10-10", "2026-10-12", &["page", "query"], "final");
        assert_eq!(
            serde_json::to_value(&q).unwrap(),
            serde_json::json!({
                "startDate": "2026-10-10", "endDate": "2026-10-12",
                "dimensions": ["page", "query"], "type": "web",
                "dataState": "final", "rowLimit": 25000, "startRow": 0,
            })
        );
    }

    /// Google's answer read leniently: no `rows` key is no rows, `NaN`
    /// positions are absent, exponents are numbers, the metadata camelCase.
    #[test]
    fn the_answer_is_read_as_google_writes_it() {
        let empty: ScResponse =
            serde_json::from_str(r#"{"responseAggregationType":"byProperty"}"#).unwrap();
        assert!(empty.rows.is_empty());
        let r: ScResponse = serde_json::from_str(
            r#"{"rows":[
                {"keys":["2026-10-12"],"clicks":3,"impressions":1.7090884E2,"ctr":"NaN","position":"NaN"},
                {"keys":["2026-10-13"],"clicks":0,"impressions":10,"ctr":0,"position":7.25}],
              "responseAggregationType":"byProperty",
              "metadata":{"firstIncompleteDate":"2026-10-14"}}"#,
        )
        .unwrap();
        assert_eq!(r.rows[0].impressions, Some(170.90884));
        assert_eq!(r.rows[0].position, None, "NaN is not a position");
        assert_eq!(r.rows[1].position, Some(7.25));
        assert_eq!(
            r.metadata.unwrap().first_incomplete_date.as_deref(),
            Some("2026-10-14")
        );
    }

    #[test]
    fn an_inspection_reads_the_index_status() {
        let r: InspectResponse = serde_json::from_str(
            r#"{"inspectionResult":{"inspectionResultLink":"https://search.google.com/x",
                "indexStatusResult":{"verdict":"PASS","coverageState":"Submitted and indexed",
                "robotsTxtState":"ALLOWED","indexingState":"INDEXING_ALLOWED",
                "lastCrawlTime":"2026-10-12T08:00:00Z","pageFetchState":"SUCCESSFUL",
                "googleCanonical":"https://meshharbor.itachi.fans/blog/x/","crawledAs":"MOBILE"}}}"#,
        )
        .unwrap();
        let s = r.inspection_result.unwrap().index_status_result.unwrap();
        assert_eq!(s.verdict.as_deref(), Some("PASS"));
        assert_eq!(s.coverage_state.as_deref(), Some("Submitted and indexed"));
        assert_eq!(s.last_crawl_time.as_deref(), Some("2026-10-12T08:00:00Z"));
    }

    /// The assertion is the JWT-bearer grant's: the service account, the
    /// read-only scope, the token endpoint as audience, an hour at most.
    #[test]
    fn the_assertion_carries_the_grants_claims() {
        let c = hs_client("sc-domain:meshharbor.itachi.fans");
        let jwt = c.assertion(1_760_000_000).unwrap();
        let mut v = jsonwebtoken::Validation::new(Algorithm::HS256);
        v.set_audience(&["https://oauth2.example.test/token"]);
        v.validate_exp = false;
        let data = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            &v,
        )
        .unwrap();
        assert_eq!(data.header.kid.as_deref(), Some("kid-1"));
        let claims = data.claims;
        assert_eq!(claims["iss"], "reader@proj.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["iat"], 1_760_000_000_i64);
        assert_eq!(claims["exp"], 1_760_003_600_i64);
    }

    /// The production path end to end: a service-account key JSON with a
    /// PKCS#8 RSA key — the form Google issues — parses, and its assertion
    /// is RS256, carries the key's id, and verifies against the public half
    /// with the grant's claims. The key is made here, so no private key
    /// lives in the repository.
    #[test]
    fn a_pkcs8_service_account_key_signs_rs256() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"), "PKCS#8");
        let public = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_json = serde_json::json!({
            "type": "service_account",
            "project_id": "meshharbor-test",
            "private_key_id": "a1b2c3",
            "private_key": pem.as_str(),
            "client_email": "growth-reader@meshharbor-test.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string();
        let c = ScClient::from_key_json("sc-domain:meshharbor.itachi.fans", "https://x", &key_json)
            .unwrap();
        let now = DateTime::now().timestamp_millis() / 1000;
        let jwt = c.assertion(now).unwrap();
        let mut v = jsonwebtoken::Validation::new(Algorithm::RS256);
        v.set_audience(&["https://oauth2.googleapis.com/token"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &jsonwebtoken::DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            &v,
        )
        .unwrap();
        assert_eq!(data.header.alg, Algorithm::RS256);
        assert_eq!(data.header.kid.as_deref(), Some("a1b2c3"));
        assert_eq!(
            data.claims["iss"],
            "growth-reader@meshharbor-test.iam.gserviceaccount.com"
        );
        assert_eq!(data.claims["scope"], SCOPE);
        assert_eq!(data.claims["exp"], now + 3600);
        // The check is not vacuous: the same token with its signature's first
        // character changed fails it.
        let (head, sig) = jwt.rsplit_once('.').unwrap();
        let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
        let forged = format!("{head}.{flipped}{}", &sig[1..]);
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(
                &forged,
                &jsonwebtoken::DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
                &v,
            )
            .is_err()
        );
    }

    #[test]
    fn the_property_is_one_encoded_path_segment() {
        assert_eq!(
            hs_client("sc-domain:meshharbor.itachi.fans").site_segment(),
            "sc-domain%3Ameshharbor.itachi.fans"
        );
        assert_eq!(
            hs_client("https://meshharbor.itachi.fans/").site_segment(),
            "https%3A%2F%2Fmeshharbor.itachi.fans%2F"
        );
    }

    /// An unusable key is named without being echoed; the client never
    /// prints a key or a token.
    #[test]
    fn a_bad_key_says_what_is_wrong_and_echoes_nothing() {
        let secretish = "not json but a secret-looking value 12345";
        let e = ScClient::from_key_json("sc-domain:x", "https://x", secretish).unwrap_err();
        assert!(!e.to_string().contains("12345"), "{e}");
        let wrong_type = r#"{"type":"authorized_user","client_email":"a@b","private_key":"x"}"#;
        assert!(matches!(
            ScClient::from_key_json("sc-domain:x", "https://x", wrong_type),
            Err(ScError::BadKey(_))
        ));
        let not_rsa = r#"{"type":"service_account","client_email":"a@b","private_key":"-----BEGIN NOTHING-----"}"#;
        let e = ScClient::from_key_json("sc-domain:x", "https://x", not_rsa).unwrap_err();
        assert_eq!(
            e.to_string(),
            "search console key unusable: the private_key is not an RSA PEM key"
        );
        assert!(e.is_fatal());
        assert!(!ScError::Status(500, "x".into()).is_fatal());
        let shown = format!("{:?}", hs_client("sc-domain:x"));
        assert!(!shown.contains("test-secret"), "{shown}");
        // No key configured: no client, nothing asked.
        assert!(ScClient::from_settings(&meshharbor_config::GrowthSettings::default()).is_none());
    }
}
