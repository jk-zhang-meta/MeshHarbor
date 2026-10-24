// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The single GitHub-releases cache behind every release-serving route,
//! plus `POST /api/releases/refresh` — the cache-bust the release
//! workflows call the moment a tag is published.
//!
//! ## Why one cache
//!
//! `agent_release`, `tunnel_release` and `setup_release` each used to own
//! a private copy of the same cache holding the same
//! `Vec<AgentRelease>` fetched from the same URL; they differ only in the
//! tag prefix they filter on *after* the fetch
//! (`agent_release::filter_component_releases`). Three copies meant three
//! times the upstream traffic against GitHub's 60-req/h unauthenticated
//! quota for no benefit. One cache at `per_page=100` (the page depth
//! `setup_release` already needed — `agent-v*` ships several times a day,
//! so a 30-deep page loses the rarely-tagged families within days) serves
//! all three.
//!
//! ## Why a refresh endpoint
//!
//! The cache is per-pod and in-process. With N pods a freshly published
//! release is invisible for up to one TTL on each pod *independently*, so
//! the answer a client gets depends on which pod the load balancer picked
//! — and `roomlerd self-update` reads exactly this data
//! (`updater.rs::DEFAULT_PROXY_URL`). Field repro 2026-08-04:
//! `agent-v0.3.0-rc.305` published 21:14 UTC; at 21:33 the endpoint still
//! answered `rc.304` on 4/4 samples because both pods had warmed their
//! caches at 21:05.
//!
//! `POST /api/releases/refresh` force-refetches on the receiving pod and
//! then fans the same request out to every other live pod over the C-1
//! control bus, so one HTTP call busts the whole cluster. The TTL remains
//! as the backstop for a refresh that never lands.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use roomler_core::ApiError;

use crate::{FleetState, agent_release::AgentRelease};

/// GitHub repo slug. A fork can override here without touching agents.
pub(crate) const RELEASES_REPO: &str = "jk-zhang-meta/roomler-ai";

/// GitHub page size — the API max. See the module docs: the shallow
/// 30-deep page the agent/tunnel caches used loses the rarely-tagged
/// `setup-v*` / `tunnel-v*` families behind a day or two of `agent-v*`.
///
/// ⚠️ 100 only delays that. A family that ships less often than 100 of the
/// others falls off this page too, and with it every route that serves it:
/// `tunnel-v0.3.0-rc.266` (2026-07-28) fell behind 100 newer releases by
/// 09-07, and every tunnel-client install then 404'd for six weeks, unnoticed
/// (#2468). So the page is never the whole story: [`fetch_releases`] recovers
/// each family the page lacks, by tag, at any depth.
const RELEASES_PER_PAGE: usize = 100;

/// The release families the routes serve, by tag prefix
/// (`agent_release::filter_component_releases`).
const FAMILIES: [&str; 3] = ["agent-v", "tunnel-v", "setup-v"];

/// A family's tag ordered by its version: `release_ord` on what follows the
/// prefix. `release_ord` alone strips only `agent-`, so it reads every
/// `tunnel-v*` and `setup-v*` tag as unparseable, and a `max_by_key` over
/// those picks by list position, not by version.
fn family_ord(tag: &str, prefix: &str) -> Option<(u64, u64, u64, u64)> {
    crate::agent::release_ord(tag.strip_prefix(prefix)?)
}

/// Upstream fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// `expect_tag` retry budget. GitHub's releases *list* endpoint trails
/// release creation by a few seconds, so the workflow step can easily
/// beat it by a hair.
const EXPECT_TAG_ATTEMPTS: u32 = 5;
const EXPECT_TAG_BACKOFF: Duration = Duration::from_secs(2);

/// Bus deadline for a peer refresh. Far above the 2 s `RPC_DEADLINE`
/// because the peer does a GitHub round-trip (with retries) inline.
const PEER_REFRESH_DEADLINE: Duration = Duration::from_secs(45);

/// C-1 bus request class for the cross-pod fan-out. Registered in
/// `state.rs` next to `rc.agent_nudge`.
pub const BUS_CLASS_REFRESH: &str = "sys.releases.refresh";

struct CacheEntry {
    fetched_at: Instant,
    payload: Vec<AgentRelease>,
}

/// The one releases cache. Lives on `FleetState` behind an `Arc` so
/// cloning the state is cheap; `RwLock` so concurrent reads don't
/// serialise through a mutex.
pub struct ReleasesCache {
    inner: RwLock<Option<CacheEntry>>,
}

impl ReleasesCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(None),
        })
    }

    /// TTL-respecting read. Fast path returns the cached payload without
    /// touching GitHub; on a cold/expired cache we refetch, and if that
    /// fails we serve the stale payload rather than break every client
    /// on one upstream blip.
    pub async fn get(&self, ttl: Duration) -> Result<Vec<AgentRelease>, ApiError> {
        {
            let g = self.inner.read().await;
            if let Some(entry) = g.as_ref()
                && entry.fetched_at.elapsed() < ttl
            {
                return Ok(entry.payload.clone());
            }
        }
        match fetch_releases().await {
            Ok(releases) => {
                self.store(releases.clone()).await;
                Ok(releases)
            }
            Err(e) => {
                tracing::warn!(error = %e, "GitHub releases fetch failed; serving stale cache if any");
                let g = self.inner.read().await;
                if let Some(entry) = g.as_ref() {
                    return Ok(entry.payload.clone());
                }
                Err(ApiError::Internal(format!(
                    "upstream releases fetch failed and no cache: {e}"
                )))
            }
        }
    }

    /// Refetch ignoring the TTL. When `expect_tag` is given, retry until
    /// that tag shows up upstream (or the budget runs out) — that is what
    /// makes the release-workflow call meaningful rather than advisory.
    /// Every successful fetch is stored even if `expect_tag` is still
    /// missing: the payload is strictly fresher than what we held.
    pub async fn force_refresh(&self, pod_id: &str, expect_tag: Option<&str>) -> PodRefresh {
        let mut last_err: Option<String> = None;
        for attempt in 1..=EXPECT_TAG_ATTEMPTS {
            match fetch_releases().await {
                Ok(mut releases) => {
                    let mut satisfied = expect_tag
                        .is_none_or(|tag| releases.iter().any(|r| !r.draft && r.tag_name == tag));
                    // GitHub's LIST endpoint lags its by-tag endpoint after
                    // API incidents (field 2026-08-17: `/releases` returned
                    // `[]` for 45+ min while `/releases/tags/agent-v0.3.0-
                    // rc.400` and `/releases/latest` served the published
                    // release — the whole fleet's update path stalled on an
                    // index that nothing we run depends on). When the caller
                    // NAMED the tag it expects, fetch it directly and merge
                    // it into the payload — the cache then serves it and the
                    // roll proceeds.
                    if !satisfied && let Some(tag) = expect_tag {
                        match fetch_release_by_tag(tag).await {
                            Ok(r) if !r.draft => {
                                tracing::info!(
                                    %tag,
                                    "releases refresh: list endpoint lagging — recovered the expected tag via the by-tag endpoint"
                                );
                                releases.retain(|x| x.tag_name != r.tag_name);
                                releases.insert(0, r);
                                satisfied = true;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                tracing::debug!(%tag, %e, "releases refresh: by-tag fallback failed too");
                            }
                        }
                    }
                    let newest = NewestTags::from_releases(&releases);
                    self.store(releases).await;
                    if satisfied {
                        return PodRefresh {
                            pod_id: pod_id.to_string(),
                            ok: true,
                            attempts: attempt,
                            newest,
                            error: None,
                        };
                    }
                    last_err = Some(format!(
                        "{} not visible upstream yet",
                        expect_tag.unwrap_or("<none>")
                    ));
                }
                Err(e) => last_err = Some(e.to_string()),
            }
            if attempt < EXPECT_TAG_ATTEMPTS {
                tokio::time::sleep(EXPECT_TAG_BACKOFF).await;
            }
        }
        let newest = {
            let g = self.inner.read().await;
            g.as_ref()
                .map(|e| NewestTags::from_releases(&e.payload))
                .unwrap_or_default()
        };
        PodRefresh {
            pod_id: pod_id.to_string(),
            ok: false,
            attempts: EXPECT_TAG_ATTEMPTS,
            newest,
            error: last_err,
        }
    }

    async fn store(&self, payload: Vec<AgentRelease>) {
        let mut g = self.inner.write().await;
        *g = Some(CacheEntry {
            fetched_at: Instant::now(),
            payload,
        });
    }
}

/// TTL-respecting read against the state's cache — the entry point every
/// `latest-release` / installer handler uses.
pub async fn cached(state: &FleetState) -> Result<Vec<AgentRelease>, ApiError> {
    state
        .releases_cache
        .get(Duration::from_secs(state.settings.releases.cache_ttl_secs))
        .await
}

/// One release by exact tag — GitHub's by-tag endpoint stays consistent
/// through the list-index lag its `/releases` endpoint exhibits after API
/// incidents (see the fallback in [`ReleasesCache::force_refresh`]).
async fn fetch_release_by_tag(tag: &str) -> anyhow::Result<AgentRelease> {
    let url = format!("https://api.github.com/repos/{RELEASES_REPO}/releases/tags/{tag}");
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomler-ai-api/", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .build()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("GitHub returned {}", resp.status());
    }
    Ok(resp.json::<AgentRelease>().await?)
}

/// The newest page of releases, plus the newest release of every family the
/// page no longer reaches (#2468). Two extra calls per missing family, and
/// only while one is missing: a new release of any family lands on the page
/// the moment it is published.
async fn fetch_releases() -> anyhow::Result<Vec<AgentRelease>> {
    let mut releases = fetch_release_page().await?;
    for prefix in missing_families(&releases) {
        match fetch_newest_of_family(prefix).await {
            Ok(Some(r)) => {
                tracing::info!(
                    %prefix,
                    tag = %r.tag_name,
                    "releases: recovered a family the first page no longer reaches"
                );
                releases.push(r);
            }
            Ok(None) => {
                tracing::debug!(%prefix, "releases: no published release in this family");
            }
            Err(e) => tracing::warn!(
                %prefix,
                error = %format!("{e:#}"),
                "releases: the first page lacks this family, and recovering it failed"
            ),
        }
    }
    Ok(releases)
}

/// The families with no published (non-draft) release in `releases`.
fn missing_families(releases: &[AgentRelease]) -> Vec<&'static str> {
    FAMILIES
        .into_iter()
        .filter(|p| {
            !releases
                .iter()
                .any(|r| !r.draft && r.tag_name.starts_with(p))
        })
        .collect()
}

/// The newest published release of one family, by its tags: GitHub's
/// `matching-refs` lists every tag with the prefix in one unpaginated call,
/// and the release is then fetched by tag. A tag with no release, or only a
/// draft, falls through to the next newest (three at most).
async fn fetch_newest_of_family(prefix: &str) -> anyhow::Result<Option<AgentRelease>> {
    let tags = fetch_tags_with_prefix(prefix).await?;
    let mut last_err = None;
    for tag in newest_first(&tags, prefix).into_iter().take(3) {
        match fetch_release_by_tag(&tag).await {
            Ok(r) if !r.draft => return Ok(Some(r)),
            Ok(_) => {}
            Err(e) => last_err = Some(e.context(format!("release {tag}"))),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// One family's tags, newest version first; a tag no version can be read
/// from is dropped. Never GitHub's order, which is lexicographic: there
/// `tunnel-v0.3.0-rc.84` sorts after `tunnel-v0.3.0-rc.266`.
fn newest_first(tags: &[String], prefix: &str) -> Vec<String> {
    let mut ordered: Vec<_> = tags
        .iter()
        .filter_map(|t| family_ord(t, prefix).map(|o| (o, t)))
        .collect();
    ordered.sort_by_key(|(o, _)| std::cmp::Reverse(*o));
    ordered.into_iter().map(|(_, t)| t.clone()).collect()
}

/// Every tag starting with `prefix`, without the `refs/tags/` part.
async fn fetch_tags_with_prefix(prefix: &str) -> anyhow::Result<Vec<String>> {
    #[derive(Deserialize)]
    struct GitRef {
        #[serde(rename = "ref")]
        name: String,
    }
    let url =
        format!("https://api.github.com/repos/{RELEASES_REPO}/git/matching-refs/tags/{prefix}");
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomler-ai-api/", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .build()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("GitHub returned {}", resp.status());
    }
    let refs: Vec<GitRef> = resp.json().await?;
    Ok(refs
        .into_iter()
        .filter_map(|r| r.name.strip_prefix("refs/tags/").map(str::to_string))
        .collect())
}

/// Page 1 of the repo's releases, newest first.
async fn fetch_release_page() -> anyhow::Result<Vec<AgentRelease>> {
    let url = format!(
        "https://api.github.com/repos/{RELEASES_REPO}/releases?per_page={RELEASES_PER_PAGE}"
    );
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomler-ai-api/", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .build()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("GitHub returned {}", resp.status());
    }
    Ok(resp.json::<Vec<AgentRelease>>().await?)
}

// ─── refresh endpoint ────────────────────────────────────────────────────────

/// Newest non-draft tag per release family, for the refresh report. This
/// is the field an operator actually reads to answer "did the cluster
/// pick the release up".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewestTags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
}

impl NewestTags {
    /// Highest VERSION per prefix — deliberately not "GitHub's first match",
    /// which is what this used to do. GitHub's REST `/releases` orders by tag
    /// name lexicographically, so `agent-v0.4.10` sorts below `agent-v0.4.2`
    /// and the first match stops being the newest as soon as a patch number
    /// reaches two digits (measured 2026-08-27). This report is how an
    /// operator confirms a cache bust actually took, so it reporting a stale
    /// tag would send them looking for the wrong bug.
    ///
    /// ⚠️ Ordered by [`family_ord`]: `release_ord` reads no `tunnel-v*` or
    /// `setup-v*` tag, and over all-`None` keys `max_by_key` took whichever of
    /// the family's releases came LAST in list order, until #2468.
    pub fn from_releases(releases: &[AgentRelease]) -> Self {
        let newest = |prefix: &str| {
            releases
                .iter()
                .filter(|r| !r.draft && r.tag_name.starts_with(prefix))
                .max_by_key(|r| family_ord(&r.tag_name, prefix))
                .map(|r| r.tag_name.clone())
        };
        Self {
            agent: newest("agent-v"),
            tunnel: newest("tunnel-v"),
            setup: newest("setup-v"),
        }
    }
}

/// One pod's refresh outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodRefresh {
    pub pod_id: String,
    pub ok: bool,
    /// Upstream fetches performed (>1 means `expect_tag` needed retries).
    pub attempts: u32,
    pub newest: NewestTags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshQuery {
    /// Tag the caller just published, e.g. `agent-v0.3.0-rc.305`. When
    /// set, a pod only reports `ok` once it can actually see that tag.
    pub expect_tag: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefreshReport {
    /// True only when this pod AND every live peer confirmed. The release
    /// workflows key their warning annotation off this.
    pub all_ok: bool,
    pub local: PodRefresh,
    pub peers: Vec<PodRefresh>,
}

/// `POST /api/releases/refresh?expect_tag=<tag>` — bust the releases
/// cache on every pod. Bearer-authenticated with a shared secret; the
/// data served is public, but an open endpoint would let anyone burn
/// GitHub's 60-req/h unauthenticated quota for the whole cluster.
pub async fn refresh(
    State(state): State<FleetState>,
    Query(params): Query<RefreshQuery>,
    headers: HeaderMap,
) -> Result<Json<RefreshReport>, ApiError> {
    authorize(&state, &headers)?;
    let expect = params.expect_tag.as_deref();

    let local = state
        .releases_cache
        .force_refresh(&state.pod.pod_id, expect)
        .await;
    let peers = refresh_peers(&state, expect).await;

    let all_ok = local.ok && peers.iter().all(|p| p.ok);
    tracing::info!(
        all_ok,
        expect_tag = expect.unwrap_or("<none>"),
        peers = peers.len(),
        newest_agent = local.newest.agent.as_deref().unwrap_or("<none>"),
        "releases cache refresh"
    );
    Ok(Json(RefreshReport {
        all_ok,
        local,
        peers,
    }))
}

/// Fan the refresh out to every live pod but ourselves, concurrently.
/// Fail-soft: no bus / no directory (single-pod or dev) just means no
/// peers, and a peer that misses its deadline is reported as
/// `ok: false` rather than failing the whole call.
async fn refresh_peers(state: &FleetState, expect_tag: Option<&str>) -> Vec<PodRefresh> {
    let (Some(bus), Some(dir)) = (&state.cluster_bus, &state.cluster_directory) else {
        return Vec::new();
    };
    // Same enumeration the C-6 status snapshot uses (`cluster::metrics`).
    let peer_ids: Vec<String> = dir
        .scan_keys("roomler:pod-alive:*")
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|k| k.rsplit(':').next().map(str::to_string))
        .filter(|id| *id != state.pod.pod_id)
        .collect();

    let body = serde_json::json!({ "expect_tag": expect_tag });
    futures::future::join_all(peer_ids.into_iter().map(|pod_id| {
        let bus = bus.clone();
        let body = body.clone();
        async move {
            match bus
                .request_with_deadline(&pod_id, BUS_CLASS_REFRESH, body, PEER_REFRESH_DEADLINE)
                .await
            {
                Ok(v) => serde_json::from_value::<PodRefresh>(v).unwrap_or_else(|e| PodRefresh {
                    pod_id: pod_id.clone(),
                    ok: false,
                    attempts: 0,
                    newest: NewestTags::default(),
                    error: Some(format!("undecodable peer reply: {e}")),
                }),
                Err(e) => PodRefresh {
                    pod_id,
                    ok: false,
                    attempts: 0,
                    newest: NewestTags::default(),
                    error: Some(e.to_string()),
                },
            }
        }
    }))
    .await
}

/// Bearer check against `releases.refresh_token`. An unset token
/// disables the endpoint outright (503) — deliberately no permissive
/// default, per the `change-me-in-production` lesson.
fn authorize(state: &FleetState, headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = state
        .settings
        .releases
        .refresh_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "releases refresh endpoint disabled (ROOMLER__RELEASES__REFRESH_TOKEN unset)"
                    .to_string(),
            )
        })?;
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if tokens_match(presented, configured) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("invalid refresh token".to_string()))
    }
}

/// Compare SHA-256 digests rather than the raw strings: an attacker
/// timing the comparison learns about digests they can't invert, not
/// about a shared secret's prefix. `sha2` is already an api dependency,
/// so this needs no new crate.
fn tokens_match(presented: &str, configured: &str) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(presented.as_bytes()) == Sha256::digest(configured.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_release::AgentRelease;

    fn release(tag: &str, draft: bool) -> AgentRelease {
        AgentRelease {
            tag_name: tag.to_string(),
            draft,
            prerelease: false,
            published_at: None,
            assets: Vec::new(),
        }
    }

    #[test]
    fn newest_tags_picks_first_non_draft_per_family() {
        // Newest-first, mixed families + an unrelated helper release —
        // exactly the shape the raw repo list has.
        let releases = vec![
            release("vendored-ffmpeg-8.1.2", false),
            release("agent-v0.3.0-rc.305", false),
            release("agent-v0.3.0-rc.304", false),
            release("setup-v0.3.0-rc.197", false),
            release("tunnel-v0.3.0-rc.167", false),
        ];
        let n = NewestTags::from_releases(&releases);
        assert_eq!(n.agent.as_deref(), Some("agent-v0.3.0-rc.305"));
        assert_eq!(n.tunnel.as_deref(), Some("tunnel-v0.3.0-rc.167"));
        assert_eq!(n.setup.as_deref(), Some("setup-v0.3.0-rc.197"));
    }

    #[test]
    fn newest_tags_skips_drafts_and_reports_missing_families() {
        let releases = vec![
            release("agent-v0.3.0-rc.306", true),
            release("agent-v0.3.0-rc.305", false),
        ];
        let n = NewestTags::from_releases(&releases);
        assert_eq!(n.agent.as_deref(), Some("agent-v0.3.0-rc.305"));
        assert!(n.tunnel.is_none());
        assert!(n.setup.is_none());
    }

    #[test]
    fn newest_tags_orders_tunnel_and_setup_by_version_not_list_position() {
        // #2468 — `release_ord` reads no `tunnel-v*`/`setup-v*` tag, so the
        // report took the family's last release in list order. GitHub's order
        // is by name, where `rc.84` sorts after `rc.266`.
        let releases = vec![
            release("tunnel-v0.3.0-rc.266", false),
            release("tunnel-v0.3.0-rc.84", false),
            release("setup-v0.4.143", false),
            release("setup-v0.4.99", false),
            release("agent-v0.4.143", false),
            release("agent-v0.4.99", false),
        ];
        let n = NewestTags::from_releases(&releases);
        assert_eq!(n.tunnel.as_deref(), Some("tunnel-v0.3.0-rc.266"));
        assert_eq!(n.setup.as_deref(), Some("setup-v0.4.143"));
        assert_eq!(n.agent.as_deref(), Some("agent-v0.4.143"));
    }

    #[test]
    fn a_family_the_page_lacks_is_missing_and_a_draft_does_not_count() {
        // The shape page 1 had on 2026-10-18: agent and setup releases, and
        // no tunnel release in reach (#2468). A draft is not a release.
        let page = vec![
            release("agent-v0.4.143", false),
            release("setup-v0.4.143", false),
            release("tunnel-v0.4.144", true),
        ];
        assert_eq!(missing_families(&page), vec!["tunnel-v"]);
        let whole = vec![
            release("agent-v0.4.143", false),
            release("setup-v0.4.143", false),
            release("tunnel-v0.3.0-rc.266", false),
        ];
        assert!(missing_families(&whole).is_empty());
        assert_eq!(missing_families(&[]), FAMILIES.to_vec());
    }

    #[test]
    fn a_family_s_tags_are_tried_newest_version_first() {
        let tags: Vec<String> = [
            "tunnel-v0.3.0-rc.69",
            "tunnel-v0.3.0-rc.266",
            "tunnel-v0.3.0-rc.84",
            "tunnel-v0.3.0",
            "tunnel-vnext",
            "agent-v0.4.1",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            newest_first(&tags, "tunnel-v"),
            vec![
                "tunnel-v0.3.0",
                "tunnel-v0.3.0-rc.266",
                "tunnel-v0.3.0-rc.84",
                "tunnel-v0.3.0-rc.69",
            ]
        );
    }

    /// The real repo, over the network: every family the routes serve comes
    /// back, however deep its newest release sits. Not in CI (GitHub's
    /// unauthenticated quota); run it after touching the fetch:
    /// `cargo test -p roomler-ai-mod-fleet --lib releases -- --ignored`.
    #[tokio::test]
    #[ignore = "network: the real GitHub API"]
    async fn the_real_repo_serves_every_family() {
        let releases = fetch_releases().await.expect("fetch");
        let n = NewestTags::from_releases(&releases);
        assert!(n.agent.is_some(), "agent: {n:?}");
        assert!(n.setup.is_some(), "setup: {n:?}");
        assert!(n.tunnel.is_some(), "tunnel: {n:?}");
        eprintln!("newest: {n:?} ({} releases)", releases.len());
    }

    #[test]
    fn tokens_match_only_on_exact_secret() {
        assert!(tokens_match("s3cret", "s3cret"));
        assert!(!tokens_match("s3cre", "s3cret"));
        assert!(!tokens_match("", "s3cret"));
        assert!(!tokens_match("s3cretX", "s3cret"));
    }

    #[tokio::test]
    async fn cache_serves_within_ttl_without_refetching() {
        // A populated cache read inside its TTL must not touch the
        // network — the whole point of the fast path. A zero-length TTL
        // would fall through to a real fetch, so this also locks that
        // `get` honours the TTL argument rather than a const.
        let cache = ReleasesCache::new();
        cache
            .store(vec![release("agent-v0.3.0-rc.305", false)])
            .await;
        let out = cache.get(Duration::from_secs(900)).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tag_name, "agent-v0.3.0-rc.305");
    }

    #[test]
    fn pod_refresh_survives_a_bus_roundtrip() {
        // The peer reply crosses the bus as `serde_json::Value`; a shape
        // drift here would silently degrade every peer to "undecodable".
        let r = PodRefresh {
            pod_id: "10.10.20.11".to_string(),
            ok: true,
            attempts: 2,
            newest: NewestTags {
                agent: Some("agent-v0.3.0-rc.305".to_string()),
                tunnel: None,
                setup: None,
            },
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        let back: PodRefresh = serde_json::from_value(v).unwrap();
        assert_eq!(back.pod_id, "10.10.20.11");
        assert!(back.ok);
        assert_eq!(back.attempts, 2);
        assert_eq!(back.newest.agent.as_deref(), Some("agent-v0.3.0-rc.305"));
        assert!(back.error.is_none());
    }
}
