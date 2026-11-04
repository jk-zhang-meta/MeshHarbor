// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the content puller (spec §3k): the blog's posts, read from
//! the site's own Atom feed once a day into `growth_content`, and — with a
//! Search Console credential — each post's index status from URL
//! Inspection.
//!
//! * **The feed is the list.** The blog is built by the docs generator
//!   (`ui/docs/build.ts`, `theme/xml.ts`) and published by the blog lane;
//!   its `/blog/feed.xml` carries every post with its permanent URL, its
//!   title and its `published` time — what the Content table needs and what
//!   no server record holds. A post that leaves the feed keeps its row,
//!   `in_feed: false`.
//! * **Only a feed moves the list.** A 404, a redirect, a non-https URL, or
//!   a 200 that is not an Atom feed (an SPA's index page served for any
//!   path; a half-deployed site) is a FAILED read, recorded with its reason:
//!   nothing is marked out of the feed on the strength of an answer that
//!   was never the feed. A feed whose entries all fail to parse is a failed
//!   read too. Only `https` entry links are read — the Content table renders
//!   them as links. No redirect is followed, and the body is capped at
//!   [`MAX_FEED_BYTES`].
//! * **URL Inspection** asks Google about each post in the feed, within its
//!   quota of 2,000 a day per property ([`MAX_INSPECTIONS`] here). A post's
//!   failed inspection keeps its last good verdict (and the time it was
//!   read) and records the error and the attempt's time. A timeout is that
//!   post's failure, unless [`MAX_TIMEOUTS_IN_A_ROW`] come in a row; a fatal
//!   error (the key, the token, a 403 — a service account that is only a
//!   *Restricted* user is refused here while Search Analytics answers it)
//!   stops the run, is recorded on EVERY post the run still owed, and on the
//!   day's pull row. A post inspected successfully in this cycle is not
//!   asked again when a later tick retries the day.
//! * Once per cycle each, marked by `growth_pulls` rows `content:<day>` and
//!   `url_inspection:<day>` (the UTC day of the read).

use bson::DateTime;
use meshharbor_services::dao::{
    base::DaoResult,
    growth::{GrowthDao, PulledDay},
    growth_content::{FeedPost, GrowthContentDao, Inspection},
};
use meshharbor_core::Core;
use serde::Serialize;
use tracing::warn;

use crate::{
    pull_schedule::{self, day_str},
    search_console::{ScClient, ScError},
};

/// The `growth_pulls` sources of a feed read and of a day's URL inspections,
/// spelled in the core DAO so the host's alert rules read the same rows.
pub use meshharbor_services::dao::growth::{
    CONTENT_SOURCE, URL_INSPECTION_SOURCE as INSPECTION_SOURCE,
};
pub const CYCLE_HOUR_UTC: u32 = 2;
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
pub const FIRST_TICK_DELAY_SECS: u64 = 8 * 60;
/// Posts read from one feed, at most.
pub const MAX_POSTS: usize = 500;
/// Inspections per day, at most — far inside Google's 2,000.
pub const MAX_INSPECTIONS: usize = 200;
/// A stored title is cut to this many characters; a path or URL to
/// [`MAX_URL_LEN`].
pub const MAX_TITLE_LEN: usize = 200;
pub const MAX_URL_LEN: usize = 300;
pub const FEED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// The largest feed read: the site's was 116 KB on 2026-10-17.
pub const MAX_FEED_BYTES: usize = 8 << 20;
/// Inspection timeouts in a row that stop the run: one slow URL is that
/// post's failure, a run of them is Google being down.
pub const MAX_TIMEOUTS_IN_A_ROW: u32 = 3;

/// The text between `<tag>` and `</tag>` in `block`, the first one.
fn between<'a>(block: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = block.find(open)? + open.len();
    let end = block[start..].find(close)? + start;
    Some(&block[start..end])
}

/// XML's five entities and numeric references.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(semi) = tail.find(';').filter(|n| *n <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..semi];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn bounded(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect()
}

/// Pure: whether `xml` is an Atom feed — its root element is `feed` in the
/// Atom namespace. An HTML page, a JSON error, an empty body are not.
pub fn is_atom_feed(xml: &str) -> bool {
    // Skip the prolog: a BOM, whitespace, processing instructions
    // (`<?xml …?>`, a stylesheet) and comments. The first element must be
    // the feed itself.
    let mut rest = xml.trim_start_matches('\u{feff}');
    loop {
        rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix("<?") {
            let Some(e) = r.find("?>") else {
                return false;
            };
            rest = &r[e + 2..];
        } else if let Some(r) = rest.strip_prefix("<!--") {
            let Some(e) = r.find("-->") else {
                return false;
            };
            rest = &r[e + 3..];
        } else {
            break;
        }
    }
    let Some(tag) = rest.strip_prefix("<feed") else {
        return false;
    };
    let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
    tag.starts_with(|c: char| c.is_ascii_whitespace())
        && tag.contains("http://www.w3.org/2005/Atom")
}

/// Pure: the posts of an Atom feed as our generator writes it
/// (`ui/docs/theme/xml.ts`): each `<entry>`'s alternate link, title and
/// `published` / `updated` times. An entry whose link is not an `https`
/// URL under `/blog/`, or without a `published` time, is skipped; at most
/// [`MAX_POSTS`].
pub fn parse_feed(xml: &str) -> Vec<FeedPost> {
    let mut out = Vec::new();
    for chunk in xml.split("<entry>").skip(1) {
        if out.len() >= MAX_POSTS {
            break;
        }
        let entry = chunk.split("</entry>").next().unwrap_or("");
        let Some(href) = entry
            .find("<link")
            .and_then(|i| between(&entry[i..], "href=\"", "\""))
            .map(unescape)
        else {
            continue;
        };
        let Ok(url) = url::Url::parse(href.trim()) else {
            continue;
        };
        // The Content table renders the URL as a link: https, nothing else.
        if url.scheme() != "https" || url.host_str().is_none() {
            continue;
        }
        let path = url.path().to_string();
        if !path.starts_with("/blog/") || path == "/blog/" || path.len() > MAX_URL_LEN {
            continue;
        }
        let Some(published) = between(entry, "<published>", "</published>")
            .and_then(|t| DateTime::parse_rfc3339_str(t.trim()).ok())
        else {
            continue;
        };
        let updated = between(entry, "<updated>", "</updated>")
            .and_then(|t| DateTime::parse_rfc3339_str(t.trim()).ok());
        let title = between(entry, "<title>", "</title>")
            .map(|t| bounded(&unescape(t), MAX_TITLE_LEN))
            .unwrap_or_default();
        out.push(FeedPost {
            path,
            url: bounded(url.as_str(), MAX_URL_LEN),
            title,
            published_at: published,
            updated_at: updated,
        });
    }
    out
}

/// The feed's URL: the setting, else `{frontend_url}/blog/feed.xml`.
pub fn feed_url(core: &Core) -> String {
    let g = core.settings.growth.blog_feed_url.trim();
    if !g.is_empty() {
        return g.to_string();
    }
    format!(
        "{}/blog/feed.xml",
        core.settings.app.frontend_url.trim_end_matches('/')
    )
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContentReport {
    pub feed_due: bool,
    pub posts: u64,
    pub left_feed: u64,
    pub inspection_due: bool,
    /// Posts in the feed already inspected successfully this cycle — a
    /// retried day does not ask Google about them again.
    pub already_inspected: u32,
    pub inspected: u32,
    pub inspection_failed: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether the feed may be read from `url`: `https`, or plain `http` to a
/// loopback address (a test's fake site).
pub fn feed_url_allowed(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url.trim()) else {
        return false;
    };
    match (u.scheme(), u.host()) {
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Ipv6(ip))) => ip.is_loopback(),
        ("http", Some(url::Host::Domain(d))) => d.eq_ignore_ascii_case("localhost"),
        _ => false,
    }
}

/// The posts of one read of the feed, or why there are none to trust.
/// Only an Atom feed is a list: a 404, a redirect, a non-https URL, an
/// answer that is not a feed, or a feed none of whose entries parse is an
/// error, so the caller never marks posts out of the feed on its strength.
async fn read_feed(url: &str) -> Result<Vec<FeedPost>, String> {
    if !feed_url_allowed(url) {
        return Err(
            "feed refused: its URL is not https (MESHHARBOR__GROWTH__BLOG_FEED_URL)".to_string(),
        );
    }
    let http = reqwest::Client::builder()
        .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
        .timeout(FEED_TIMEOUT)
        // A redirect is the site moving its feed: said, never followed.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("feed unreachable: {}", e.without_url()))?;
    let status = resp.status().as_u16();
    if (300..400).contains(&status) {
        return Err(format!(
            "feed unreachable: HTTP {status}, a redirect, not followed (point MESHHARBOR__GROWTH__BLOG_FEED_URL at its target)"
        ));
    }
    if status == 404 {
        return Err("feed not found (404)".to_string());
    }
    if !(200..300).contains(&status) {
        return Err(format!("feed unreachable: HTTP {status}"));
    }
    let body = crate::capped::read_capped(resp, MAX_FEED_BYTES)
        .await
        .map_err(|e| format!("feed unreadable: {e}"))?;
    let text = String::from_utf8_lossy(&body);
    if !is_atom_feed(&text) {
        return Err("feed unreadable: the answer is not an Atom feed".to_string());
    }
    let posts = parse_feed(&text);
    let entries = text.matches("<entry>").count();
    if posts.is_empty() && entries > 0 {
        return Err(format!(
            "feed unreadable: none of its {entries} entries parsed"
        ));
    }
    Ok(posts)
}

fn inspection_of(status: crate::search_console::IndexStatus, now: DateTime) -> Inspection {
    Inspection {
        verdict: status.verdict,
        coverage_state: status.coverage_state,
        indexing_state: status.indexing_state,
        page_fetch_state: status.page_fetch_state,
        robots_txt_state: status.robots_txt_state,
        last_crawl_time: status
            .last_crawl_time
            .as_deref()
            .and_then(|t| DateTime::parse_rfc3339_str(t).ok()),
        google_canonical: status.google_canonical,
        inspected_at: Some(now),
        attempted_at: Some(now),
        error: None,
    }
}

/// One run at `now`: the feed once per cycle, then the inspections once
/// per cycle when a Search Console client is given.
pub async fn run_once(
    core: &Core,
    feed: &str,
    sc: Option<&ScClient>,
    now: DateTime,
) -> DaoResult<ContentReport> {
    let dao = GrowthDao::new(&core.db);
    let content = GrowthContentDao::new(&core.db);
    let mut report = ContentReport::default();
    let today = day_str(pull_schedule::date_of(now));
    let due = |pulls: &[meshharbor_services::dao::growth::GrowthPull]| {
        now.timestamp_millis() >= pull_schedule::cycle_start_ms(now, CYCLE_HOUR_UTC)
            && pulls
                .first()
                .is_none_or(|p| p.status != meshharbor_services::dao::growth::PullStatus::Ok)
    };

    if due(&dao.pulls_between(CONTENT_SOURCE, &today, &today).await?) {
        report.feed_due = true;
        match read_feed(feed).await {
            Ok(posts) => {
                let (n, left) = content.sync_feed(&posts, now).await?;
                report.posts = n;
                report.left_feed = left;
                dao.record_pull_ok(
                    CONTENT_SOURCE,
                    &today,
                    PulledDay {
                        rows: n as u32,
                        missing_goal: None,
                        truncated: posts.len() >= MAX_POSTS,
                    },
                    now,
                )
                .await?;
            }
            Err(reason) => {
                dao.record_pull_failed(CONTENT_SOURCE, &today, &reason, now)
                    .await?;
                report.error = Some(reason);
            }
        }
    }

    let Some(sc) = sc else {
        return Ok(report);
    };
    if !due(&dao.pulls_between(INSPECTION_SOURCE, &today, &today).await?) {
        return Ok(report);
    }
    report.inspection_due = true;
    // A post inspected successfully in this cycle is not asked again when a
    // later tick retries the day: a recurring failure must not re-inspect
    // from the top every hour.
    let cycle_start = pull_schedule::cycle_start_ms(now, CYCLE_HOUR_UTC);
    let (done, owed): (Vec<_>, Vec<_>) = content
        .list()
        .await?
        .into_iter()
        .filter(|p| p.in_feed)
        .partition(|p| {
            p.inspection
                .as_ref()
                .and_then(|i| i.inspected_at)
                .is_some_and(|t| t.timestamp_millis() >= cycle_start)
        });
    report.already_inspected = done.len() as u32;
    let truncated = owed.len() > MAX_INSPECTIONS;
    let owed: Vec<_> = owed.into_iter().take(MAX_INSPECTIONS).collect();
    let mut fatal: Option<ScError> = None;
    let mut timeouts = 0u32;
    for (i, p) in owed.iter().enumerate() {
        let e = match sc.inspect(&p.url).await {
            Ok(status) => {
                timeouts = 0;
                content
                    .set_inspection(&p.path, &inspection_of(status, now))
                    .await?;
                report.inspected += 1;
                continue;
            }
            Err(e) => e,
        };
        report.inspection_failed += 1;
        content
            .set_inspection(&p.path, &Inspection::failed(now, e.to_string()))
            .await?;
        // One slow URL is that post's failure; a run of them is Google down.
        let stop = if e == ScError::Timeout {
            timeouts += 1;
            timeouts >= MAX_TIMEOUTS_IN_A_ROW
        } else {
            timeouts = 0;
            e.is_fatal()
        };
        if stop {
            // The reason is every remaining post's, not the first's: a
            // Restricted account's 403 answers them all the same.
            for rest in &owed[i + 1..] {
                content
                    .set_inspection(&rest.path, &Inspection::failed(now, e.to_string()))
                    .await?;
                report.inspection_failed += 1;
            }
            fatal = Some(e);
            break;
        }
    }
    match fatal {
        Some(e) => {
            let reason = if e == ScError::Timeout {
                format!("{e} ({MAX_TIMEOUTS_IN_A_ROW} inspections in a row)")
            } else {
                e.to_string()
            };
            warn!(%reason, "url inspection stopped");
            dao.record_pull_failed(INSPECTION_SOURCE, &today, &reason, now)
                .await?;
            report.error.get_or_insert(reason);
        }
        None => {
            dao.record_pull_ok(
                INSPECTION_SOURCE,
                &today,
                PulledDay {
                    rows: report.inspected + report.already_inspected,
                    missing_goal: None,
                    truncated,
                },
                now,
            )
            .await?;
        }
    }
    Ok(report)
}

/// The scheduler: hourly, one pod (the Redis claim), with `growth.enabled`
/// — the feed is the site's own, so it is read without any credential; the
/// inspections only with a usable Search Console key.
pub fn spawn_puller(core: Core) {
    if !core.settings.growth.enabled {
        return;
    }
    let sc = match ScClient::from_settings(&core.settings.growth) {
        Some(Ok(c)) => Some(c),
        // `search_pull::spawn_puller` says why, once.
        Some(Err(_)) | None => None,
    };
    let feed = feed_url(&core);
    tracing::info!(feed = %feed, inspection = sc.is_some(), "growth content puller starting");
    pull_schedule::spawn_hourly(
        core,
        "growth-content-pull",
        FIRST_TICK_DELAY_SECS,
        LOOP_INTERVAL_SECS,
        move |core| {
            let sc = sc.clone();
            let feed = feed.clone();
            async move {
                match run_once(&core, &feed, sc.as_ref(), DateTime::now()).await {
                    Ok(r) if r.feed_due || r.inspection_due => tracing::info!(
                        posts = r.posts,
                        left_feed = r.left_feed,
                        inspected = r.inspected,
                        inspection_failed = r.inspection_failed,
                        error = r.error.as_deref().unwrap_or(""),
                        "growth content pull"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(%e, "growth content pull failed"),
                }
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The feed exactly as `ui/docs/theme/xml.ts` writes it.
    const FEED: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <id>https://roomler.ai/blog/</id>
  <title>MeshHarbor blog</title>
  <link rel="self" type="application/atom+xml" href="https://roomler.ai/blog/feed.xml"/>
  <updated>2026-10-13T14:49:49Z</updated>
  <entry>
    <id>https://roomler.ai/blog/self-hosted-teamviewer-alternative/</id>
    <title>A self-hosted TeamViewer alternative &amp; why &lt;it&gt; matters</title>
    <link rel="alternate" type="text/html" href="https://roomler.ai/blog/self-hosted-teamviewer-alternative/"/>
    <published>2026-09-25T22:45:13Z</published>
    <updated>2026-10-01T08:00:00Z</updated>
    <author><name>Goran</name></author>
    <summary>One &#8212; two</summary>
    <content type="html">&lt;title&gt;not the title&lt;/title&gt;&lt;p&gt;Body&lt;/p&gt;</content>
  </entry>
  <entry>
    <id>https://roomler.ai/blog/ssh-without-port-forwarding/</id>
    <title>SSH without port forwarding</title>
    <link rel="alternate" type="text/html" href="https://roomler.ai/blog/ssh-without-port-forwarding/"/>
    <published>2026-10-19T06:00:00+02:00</published>
    <updated>2026-10-19T06:00:00+02:00</updated>
    <author><name>Goran</name></author>
  </entry>
  <entry>
    <id>https://roomler.ai/docs/x/</id>
    <title>Not a post</title>
    <link rel="alternate" type="text/html" href="https://roomler.ai/docs/x/"/>
    <published>2026-10-01T00:00:00Z</published>
  </entry>
  <entry>
    <title>No date</title>
    <link rel="alternate" type="text/html" href="https://roomler.ai/blog/undated/"/>
  </entry>
  <entry>
    <title>Plain http</title>
    <link rel="alternate" type="text/html" href="http://roomler.ai/blog/plain/"/>
    <published>2026-10-02T00:00:00Z</published>
  </entry>
  <entry>
    <title>Script</title>
    <link rel="alternate" type="text/html" href="javascript:alert(1)//blog/x/"/>
    <published>2026-10-03T00:00:00Z</published>
  </entry>
</feed>
"#;

    #[test]
    fn the_feed_reads_each_posts_path_title_and_times() {
        let posts = parse_feed(FEED);
        assert_eq!(posts.len(), 2, "{posts:?}");
        let a = &posts[0];
        assert_eq!(a.path, "/blog/self-hosted-teamviewer-alternative/");
        assert_eq!(
            a.url,
            "https://roomler.ai/blog/self-hosted-teamviewer-alternative/"
        );
        assert_eq!(
            a.title,
            "A self-hosted TeamViewer alternative & why <it> matters"
        );
        assert_eq!(
            a.published_at,
            DateTime::parse_rfc3339_str("2026-09-25T22:45:13Z").unwrap()
        );
        assert_eq!(
            a.updated_at,
            Some(DateTime::parse_rfc3339_str("2026-10-01T08:00:00Z").unwrap())
        );
        // An offset is honoured: 06:00+02:00 is 04:00Z.
        assert_eq!(
            posts[1].published_at,
            DateTime::parse_rfc3339_str("2026-10-19T04:00:00Z").unwrap()
        );
        // Not a feed at all: nothing, never a panic.
        assert!(parse_feed("<html>nope</html>").is_empty());
        assert!(parse_feed("<entry><link href=\"").is_empty());
        assert!(
            posts.iter().all(|p| p.url.starts_with("https://")),
            "an http or javascript: link is never read: {posts:?}"
        );
    }

    /// Only an Atom feed is a list: an HTML page (an SPA's index served for
    /// any path), a JSON error or nothing at all is not, whatever it holds.
    #[test]
    fn only_an_atom_feed_is_a_feed() {
        assert!(is_atom_feed(FEED));
        assert!(is_atom_feed(
            "\u{feff}<!-- built --><feed xmlns=\"http://www.w3.org/2005/Atom\"></feed>"
        ));
        for not_a_feed in [
            "",
            "<!DOCTYPE html><html><body><feed xmlns=\"http://www.w3.org/2005/Atom\">",
            "<?xml version=\"1.0\"?><rss version=\"2.0\"></rss>",
            "<feeds xmlns=\"http://www.w3.org/2005/Atom\"></feeds>",
            "<feed></feed>",
            "{\"error\":\"not found\"}",
        ] {
            assert!(!is_atom_feed(not_a_feed), "{not_a_feed:?}");
        }
    }

    /// The feed is read over https; plain http only from a loopback test
    /// site.
    #[test]
    fn the_feed_url_must_be_https() {
        assert!(feed_url_allowed("https://roomler.ai/blog/feed.xml"));
        assert!(feed_url_allowed("http://127.0.0.1:5000/blog/feed.xml"));
        assert!(feed_url_allowed("http://localhost/blog/feed.xml"));
        assert!(feed_url_allowed("http://[::1]:8080/blog/feed.xml"));
        for bad in [
            "http://roomler.ai/blog/feed.xml",
            "ftp://roomler.ai/feed.xml",
            "file:///etc/passwd",
            "not a url",
            "",
        ] {
            assert!(!feed_url_allowed(bad), "{bad:?}");
        }
    }

    #[test]
    fn entities_unescape_and_junk_stays_literal() {
        assert_eq!(
            unescape("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"),
            "a & b <c> \"d\" 'e'"
        );
        assert_eq!(unescape("&#8212;&#x2014;"), "——");
        assert_eq!(unescape("AT&T & co; &bogus; &"), "AT&T & co; &bogus; &");
    }
}
