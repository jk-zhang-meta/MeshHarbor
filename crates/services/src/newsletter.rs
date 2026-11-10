// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-58 — newsletter rendering: markdown → the branded email HTML.
//!
//! Three properties are the contract, not implementation detail:
//!
//! 1. **Raw HTML never survives.** `render_markdown` filters
//!    `Event::Html`/`Event::InlineHtml` before `push_html`, so the only HTML
//!    in a rendered body is renderer-emitted. A pasted export cannot smuggle
//!    tags, tracking pixels or foreign styling into the wrapper — and the
//!    email pipeline has no other sanitizer, so this filter is the boundary.
//! 2. **Pre-render once, substitute per recipient.** The wrapper carries
//!    [`UNSUB_PLACEHOLDER`]; the fan-out substitutes each recipient's
//!    unsubscribe URL. Every recipient therefore receives byte-identical
//!    content except their link — which is what makes the admin preview THE
//!    sent artifact rather than a sibling of it.
//! 3. **Operator strings are escaped.** Subject/preheader/CTA/alt pass
//!    [`escape_html`] before entering the wrapper, and header-bound strings
//!    pass [`clean_header_text`] at the route (a `\r\n` in a subject is SMTP
//!    header injection on the lettre backend).
//! 4. **FR-102 P5 (D5) — the issue's tags are the issue's, not the
//!    reader's.** [`LinkTags`] adds `utm_source=newsletter&utm_medium=email&
//!    utm_campaign=nl-<slug>` to every link to this site at RENDER time,
//!    before property 2's substitution — so the tags are, by construction,
//!    byte-identical for every recipient, and the footer's promise ("the
//!    only per-recipient thing in this email is your unsubscribe link")
//!    stays literally true. Links elsewhere are left exactly as written: a
//!    third party learns nothing, and a signed URL is not broken.

use std::collections::HashSet;

use meshharbor_db::models::NewsletterIssue;
use pulldown_cmark::{Event, Options, Parser, Tag, html};

/// Sentinel the wrapper embeds where a recipient's unsubscribe URL belongs.
/// Chosen to survive both markdown rendering and HTML escaping unchanged; an
/// operator who literally types it into a body gets it substituted, which is
/// harmless (admin-only surface).
pub const UNSUB_PLACEHOLDER: &str = "%%UNSUBSCRIBE_URL%%";

/// FR-102 P5 (D5) — the `utm_source` every issue's links carry (the
/// taxonomy's `newsletter`, `crates/core/src/campaign.rs`).
pub const ISSUE_UTM_SOURCE: &str = "newsletter";
/// FR-102 P5 (D5) — the `utm_medium` (the taxonomy's `email`).
pub const ISSUE_UTM_MEDIUM: &str = "email";
/// FR-102 P5 (D5) — an issue's `utm_campaign` is this prefix and its slug.
pub const ISSUE_CAMPAIGN_PREFIX: &str = "nl-";
/// The hosted site's own hosts, tagged whatever `app.frontend_url` says
/// (the footer links to `https://meshharbor.itachi.fans`).
pub const HOSTED_SITE_HOSTS: [&str; 2] = ["meshharbor.itachi.fans", "www.meshharbor.itachi.fans"];

/// `nl-<slug>`, cut to the longest value a sign-up's attribution keeps
/// (`MAX_ATTRIBUTION_VALUE_LEN`, the clamp ingress applies): a longer
/// campaign would be cut at sign-up and never meet the issue it came from,
/// so it is cut the same way here first. The one spelling both the links
/// and every per-issue lookup use.
pub fn issue_campaign(slug: &str) -> String {
    format!("{ISSUE_CAMPAIGN_PREFIX}{slug}")
        .chars()
        .take(meshharbor_db::models::MAX_ATTRIBUTION_VALUE_LEN)
        .collect()
}

/// The hosts whose links an issue tags: `frontend_url`'s host and
/// [`HOSTED_SITE_HOSTS`], lowercased.
pub fn site_hosts(frontend_url: &str) -> Vec<String> {
    let mut hosts: Vec<String> = HOSTED_SITE_HOSTS.iter().map(|h| h.to_string()).collect();
    if let Some(h) = url::Url::parse(frontend_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        && !hosts.contains(&h)
    {
        hosts.push(h);
    }
    hosts
}

/// FR-102 P5 (D5) — one issue's link tags: the same three parameters on
/// every link to this site, for every recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTags {
    /// `nl-<slug>` ([`issue_campaign`]).
    pub campaign: String,
    /// Lowercased hosts whose links are tagged.
    pub hosts: Vec<String>,
}

impl LinkTags {
    pub fn for_issue(slug: &str, hosts: Vec<String>) -> Self {
        Self {
            campaign: issue_campaign(slug),
            hosts: hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        }
    }

    /// `raw` with the issue's tags when it is an http(s) link to one of
    /// [`Self::hosts`]; otherwise exactly `raw`. A parameter the link
    /// already carries is the operator's and is kept — only the missing
    /// ones are added, after the existing query and before any fragment.
    pub fn tag(&self, raw: &str) -> String {
        let Ok(mut url) = url::Url::parse(raw) else {
            return raw.to_string();
        };
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return raw.to_string();
        }
        let ours = url
            .host_str()
            .is_some_and(|h| self.hosts.iter().any(|o| o.eq_ignore_ascii_case(h)));
        if !ours {
            return raw.to_string();
        }
        let present: HashSet<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        let missing: Vec<(&str, &str)> = [
            ("utm_source", ISSUE_UTM_SOURCE),
            ("utm_medium", ISSUE_UTM_MEDIUM),
            ("utm_campaign", self.campaign.as_str()),
        ]
        .into_iter()
        .filter(|(k, _)| !present.contains(*k))
        .collect();
        if missing.is_empty() {
            return raw.to_string();
        }
        url.query_pairs_mut().extend_pairs(missing);
        url.to_string()
    }
}

/// Minimal, complete HTML escaping for text landing in the wrapper.
/// (First in the tree — the transactional templates interpolate unescaped,
/// which FR-58's operator-authored fields must not.)
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Single-line header/metadata hygiene: strips ALL control characters
/// (CR/LF included — SMTP header injection), trims, and caps at `max_chars`
/// on a char boundary. Truncation over rejection: these are operator-supplied
/// fields on the operator's own issue.
pub fn clean_header_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Markdown → HTML with raw-HTML events dropped structurally (property 1).
pub fn render_markdown(md: &str) -> String {
    render_markdown_tagged(md, None)
}

/// [`render_markdown`], with every link's destination passed through the
/// issue's [`LinkTags`] (property 4). Images are not links and keep their
/// source as written.
pub fn render_markdown_tagged(md: &str, tags: Option<&LinkTags>) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(md, opts)
        .filter(|e| !matches!(e, Event::Html(_) | Event::InlineHtml(_)))
        .map(|e| match (e, tags) {
            (
                Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }),
                Some(tags),
            ) => Event::Start(Tag::Link {
                link_type,
                dest_url: tags.tag(&dest_url).into(),
                title,
                id,
            }),
            (e, _) => e,
        });
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

/// Inline-style pass over renderer output. Mail clients strip `<style>`
/// blocks, so the tags the renderer emits get their styles injected here.
/// ⚠️ Safe ONLY because the input is `render_markdown` output — every tag
/// below is renderer-emitted with a known shape; never run this over
/// arbitrary HTML.
fn style_rendered_html(body: &str) -> String {
    body
        // `<pre><code…` first, so the inner code block doesn't take the
        // inline-code style afterwards (`<code>` with no attrs won't match it
        // once this inserted `style=`).
        .replace(
            "<pre><code",
            "<pre style=\"background:#1a1a2e;color:#e0f2f1;padding:14px 16px;border-radius:8px;overflow-x:auto;font-size:14px;line-height:1.5;\"><code style=\"font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;\"",
        )
        .replace(
            "<code>",
            "<code style=\"font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:rgba(0,150,136,0.10);padding:1px 5px;border-radius:4px;font-size:14px;\">",
        )
        .replace("<a href=", "<a style=\"color:#00796B;\" href=")
        .replace(
            "<h2>",
            "<h2 style=\"margin:24px 0 12px;font-size:21px;line-height:1.3;color:#1a1a2e;\">",
        )
        .replace(
            "<h3>",
            "<h3 style=\"margin:20px 0 10px;font-size:17px;line-height:1.3;color:#1a1a2e;\">",
        )
        .replace(
            "<blockquote>",
            "<blockquote style=\"margin:16px 0;padding:8px 16px;border-left:3px solid #009688;background:rgba(0,150,136,0.06);border-radius:4px;color:#1a1a2e;\">",
        )
        .replace(
            "<table>",
            "<table style=\"border-collapse:collapse;margin:16px 0;width:100%;\">",
        )
        .replace(
            "<th>",
            "<th style=\"border:1px solid rgba(0,150,136,0.25);padding:6px 10px;text-align:left;background:rgba(0,150,136,0.08);\">",
        )
        .replace(
            "<td>",
            "<td style=\"border:1px solid rgba(0,150,136,0.25);padding:6px 10px;\">",
        )
        .replace(
            "<hr />",
            "<hr style=\"border:none;border-top:1px solid rgba(0,150,136,0.25);margin:24px 0;\" />",
        )
}

const FONT_STACK: &str = "system-ui,-apple-system,'Segoe UI',Roboto,sans-serif";

/// The branded 600 px light-only wrapper (MeshHarbor Field Notes). Returns the
/// COMPLETE email HTML with [`UNSUB_PLACEHOLDER`] where the recipient's
/// unsubscribe URL belongs — the exact bytes a recipient receives, which is
/// also exactly what the admin preview serves.
///
/// `tags` (FR-102 P5, property 4) tags every link to this site — the
/// body's, the call to action and the footer's — and never the unsubscribe
/// link, which is substituted per recipient afterwards. `None` renders the
/// links as written (`newsletter.link_tags = false`).
pub fn render_issue_html(issue: &NewsletterIssue, tags: Option<&LinkTags>) -> String {
    let tag = |url: &str| match tags {
        Some(t) => t.tag(url),
        None => url.to_string(),
    };
    let subject = escape_html(&issue.subject);
    let preheader = escape_html(&issue.preheader);
    let body = style_rendered_html(&render_markdown_tagged(&issue.body_md, tags));
    let home = escape_html(&tag("https://meshharbor.itachi.fans"));

    let hero = match (&issue.hero_url, &issue.hero_alt) {
        (Some(url), alt) => format!(
            "<img src=\"{}\" width=\"600\" alt=\"{}\" style=\"width:100%;height:auto;display:block;\" />",
            escape_html(url),
            escape_html(alt.as_deref().unwrap_or("")),
        ),
        (None, _) => String::new(),
    };

    let cta = match (&issue.cta_text, &issue.cta_url) {
        (Some(text), Some(url)) => format!(
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin:28px auto 4px;\"><tr>\
             <td style=\"background:#009688;border-radius:6px;\">\
             <a href=\"{}\" style=\"display:inline-block;padding:12px 28px;color:#ffffff;font-family:{};font-size:16px;font-weight:600;text-decoration:none;\">{}</a>\
             </td></tr></table>",
            escape_html(&tag(url)),
            FONT_STACK,
            escape_html(text),
        ),
        _ => String::new(),
    };

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\
         <meta name=\"color-scheme\" content=\"light only\" />\n\
         <title>{subject}</title>\n</head>\n\
         <body style=\"margin:0;padding:0;background:#f5f7fa;\">\n\
         <div style=\"display:none;max-height:0;overflow:hidden;mso-hide:all;\">{preheader}</div>\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#f5f7fa;\"><tr>\
         <td align=\"center\" style=\"padding:24px 12px;\">\n\
         <table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:600px;max-width:100%;\">\n\
         <tr><td style=\"padding:0 8px 14px;font-family:{font};font-size:18px;font-weight:700;color:#1a1a2e;\">\
         MeshHarbor <span style=\"color:#009688;\">Field Notes</span></td></tr>\n\
         <tr><td style=\"background:#ffffff;border:1px solid rgba(0,150,136,0.18);border-radius:12px;overflow:hidden;\">\n\
         {hero}\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>\
         <td style=\"padding:28px 32px;font-family:{font};font-size:16px;line-height:1.6;color:#1a1a2e;\">\n\
         <h1 style=\"margin:0 0 16px;font-size:26px;line-height:1.25;color:#1a1a2e;\">{subject}</h1>\n\
         {body}\n{cta}\n\
         </td></tr></table>\n\
         </td></tr>\n\
         <tr><td style=\"padding:20px 8px 0;font-family:{font};font-size:12.5px;line-height:1.7;color:#5b6570;text-align:center;\">\n\
         You subscribed at meshharbor.itachi.fans. Product updates only, never more than monthly.<br />\n\
         No tracking pixels — the only per-recipient thing in this email is your unsubscribe link.<br />\n\
         <a href=\"{unsub}\" style=\"color:#00796B;\">Unsubscribe</a>&nbsp;&middot;&nbsp;<a href=\"{home}\" style=\"color:#00796B;\">meshharbor.itachi.fans</a><br />\n\
         MeshHarbor &middot; G ROX LTD, Pazardzhik, Bulgaria\n\
         </td></tr>\n\
         </table>\n</td></tr></table>\n</body>\n</html>\n",
        subject = subject,
        preheader = preheader,
        font = FONT_STACK,
        hero = hero,
        body = body,
        cta = cta,
        unsub = UNSUB_PLACEHOLDER,
        home = home,
    )
}

/// Per-recipient substitution (property 2). Hex tokens need no escaping; the
/// URL is ours, built server-side.
pub fn substitute_recipient(rendered: &str, unsubscribe_url: &str) -> String {
    rendered.replace(UNSUB_PLACEHOLDER, unsubscribe_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::DateTime;
    use meshharbor_db::models::IssueStatus;

    fn issue(body_md: &str) -> NewsletterIssue {
        NewsletterIssue {
            id: None,
            slug: "test-issue".into(),
            subject: "A <subject> & so".into(),
            preheader: "Preview line".into(),
            body_md: body_md.into(),
            hero_url: Some("https://meshharbor.itachi.fans/newsletter-img/test-v1.png".into()),
            hero_alt: Some("An \"alt\" text".into()),
            cta_text: Some("Try it".into()),
            cta_url: Some("https://meshharbor.itachi.fans/".into()),
            audience: None,
            status: IssueStatus::Draft,
            claimed_by: None,
            claimed_at: None,
            counts: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            sent_at: None,
            campaign: None,
            delivery_events: false,
        }
    }

    fn tags() -> LinkTags {
        LinkTags::for_issue(
            "october-notes",
            site_hosts("https://meshharbor.itachi.fans"),
        )
    }

    const TAGGED: &str = "utm_source=newsletter&utm_medium=email&utm_campaign=nl-october-notes";

    /// D5 — a link to this site gains the issue's three tags; a link
    /// anywhere else, a `mailto:`, a relative path and anything unparsable
    /// are left byte-for-byte as written.
    #[test]
    fn only_links_to_this_site_are_tagged_and_the_rest_are_untouched() {
        let t = tags();
        assert_eq!(
            t.tag("https://meshharbor.itachi.fans/docs/install"),
            format!("https://meshharbor.itachi.fans/docs/install?{TAGGED}")
        );
        assert_eq!(
            t.tag("https://www.meshharbor.itachi.fans/blog/x#part-2"),
            format!("https://www.meshharbor.itachi.fans/blog/x?{TAGGED}#part-2"),
            "the fragment stays last"
        );
        assert_eq!(
            t.tag("https://meshharbor.itachi.fans/pricing?plan=pro"),
            format!("https://meshharbor.itachi.fans/pricing?plan=pro&{TAGGED}"),
            "the existing query is kept, the tags appended"
        );
        assert_eq!(
            t.tag("https://meshharbor.itachi.fans"),
            format!("https://meshharbor.itachi.fans/?{TAGGED}")
        );
        for untouched in [
            "https://github.com/jk-zhang-meta/MeshHarbor",
            "https://meshharbor.itachi.fans.evil.example/x",
            "https://evil.example/?u=https://meshharbor.itachi.fans/",
            "https://user@meshharbor.itachi.fans/x",
            "mailto:hello@meshharbor.itachi.fans",
            "/relative/path",
            "not a url",
            "ftp://meshharbor.itachi.fans/file",
        ] {
            assert_eq!(t.tag(untouched), untouched, "{untouched}");
        }
    }

    /// A tag the operator wrote is the operator's: only the missing ones
    /// are added, and a fully tagged link is left alone.
    #[test]
    fn an_operators_own_tag_is_kept() {
        let t = tags();
        assert_eq!(
            t.tag("https://meshharbor.itachi.fans/x?utm_campaign=custom"),
            "https://meshharbor.itachi.fans/x?utm_campaign=custom&utm_source=newsletter&utm_medium=email"
        );
        let full = "https://meshharbor.itachi.fans/x?utm_source=a&utm_medium=b&utm_campaign=c";
        assert_eq!(t.tag(full), full);
    }

    /// The campaign is cut where a sign-up's attribution would cut it, so
    /// the two always meet.
    #[test]
    fn the_campaign_is_nl_and_the_slug_cut_like_a_signups() {
        assert_eq!(issue_campaign("october-notes"), "nl-october-notes");
        let long = "a".repeat(64);
        let c = issue_campaign(&long);
        assert_eq!(c.len(), meshharbor_db::models::MAX_ATTRIBUTION_VALUE_LEN);
        assert!(c.starts_with("nl-aaa"));
    }

    #[test]
    fn the_site_hosts_are_the_hosted_pair_and_the_frontend() {
        assert_eq!(
            site_hosts("https://meshharbor.itachi.fans"),
            vec![
                "meshharbor.itachi.fans".to_string(),
                "www.meshharbor.itachi.fans".to_string()
            ]
        );
        assert_eq!(
            site_hosts("http://Localhost:5173/"),
            vec![
                "meshharbor.itachi.fans".to_string(),
                "www.meshharbor.itachi.fans".to_string(),
                "localhost".to_string()
            ]
        );
        assert_eq!(site_hosts("not a url").len(), 2);
    }

    /// Every link in a rendered issue — the body's, the call to action and
    /// the footer's — carries the tags, except the unsubscribe placeholder
    /// (substituted per recipient later) and the hero image (not a link).
    #[test]
    fn a_tagged_issue_tags_body_cta_and_footer_and_nothing_else() {
        let i = issue(
            "See [the docs](https://meshharbor.itachi.fans/docs), [GitHub](https://github.com/jk-zhang-meta/MeshHarbor) \
             and <https://meshharbor.itachi.fans/blog/x>.",
        );
        let html = render_issue_html(&i, Some(&tags()));
        let amp = TAGGED.replace('&', "&amp;");
        assert!(
            html.contains(&format!(
                "href=\"https://meshharbor.itachi.fans/docs?{amp}\""
            )),
            "{html}"
        );
        assert!(html.contains(&format!(
            "href=\"https://meshharbor.itachi.fans/blog/x?{amp}\""
        )));
        assert!(
            html.contains("href=\"https://github.com/jk-zhang-meta/MeshHarbor\""),
            "third-party links are untouched"
        );
        assert!(
            html.contains(&format!(
                "href=\"https://meshharbor.itachi.fans/?{amp}\" style=\"display:inline-block"
            )),
            "the call to action is tagged"
        );
        assert!(
            html.contains(&format!(
                "href=\"https://meshharbor.itachi.fans/?{amp}\" style=\"color:#00796B;\">meshharbor.itachi.fans</a>"
            )),
            "the footer's link is tagged"
        );
        assert!(html.contains(&format!("href=\"{UNSUB_PLACEHOLDER}\"")));
        assert!(
            html.contains("src=\"https://meshharbor.itachi.fans/newsletter-img/test-v1.png\""),
            "the hero image is not a link and is not tagged"
        );
        // Untagged, every link is as written.
        let plain = render_issue_html(&i, None);
        assert!(!plain.contains("utm_"), "{plain}");
    }

    #[test]
    fn raw_html_is_dropped_structurally() {
        let out = render_markdown(
            "hello <b onmouseover=\"x()\">bold</b>\n\n<script>alert(1)</script>\n\n<img src=x onerror=steal()>\n\nworld",
        );
        assert!(
            !out.contains("<script"),
            "block HTML must be dropped: {out}"
        );
        assert!(!out.contains("<b"), "inline HTML must be dropped: {out}");
        assert!(
            !out.contains("onerror"),
            "attributes must be dropped: {out}"
        );
        assert!(out.contains("hello"), "the text around it survives: {out}");
        assert!(out.contains("world"));
    }

    #[test]
    fn markdown_basics_render() {
        let out = render_markdown(
            "## Heading\n\n- one\n- two\n\n[link](https://example.com)\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n~~gone~~\n\n`code` and\n\n```\nblock\n```\n",
        );
        assert!(out.contains("<h2>"), "{out}");
        assert!(out.contains("<li>one</li>"), "{out}");
        assert!(out.contains("<a href=\"https://example.com\""), "{out}");
        assert!(out.contains("<table>"), "{out}");
        assert!(out.contains("<del>gone</del>"), "{out}");
        assert!(out.contains("<code>code</code>"), "{out}");
        assert!(out.contains("<pre><code>block"), "{out}");
    }

    #[test]
    fn escape_html_covers_the_five() {
        assert_eq!(
            escape_html("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn clean_header_text_strips_controls_and_caps() {
        assert_eq!(
            clean_header_text("  Subject\r\nBcc: evil@x\ttail  ", 200),
            "SubjectBcc: evil@xtail"
        );
        assert_eq!(clean_header_text("abcdef", 3), "abc");
    }

    #[test]
    fn wrapper_escapes_operator_strings_and_carries_the_contract() {
        let html = render_issue_html(
            &issue("Body **text** with a [link](https://example.com)."),
            None,
        );
        // Subject escaped, twice (title + h1) — never raw.
        assert!(!html.contains("A <subject>"), "raw subject leaked");
        assert!(html.contains("A &lt;subject&gt; &amp; so"));
        // The per-recipient placeholder is present for the fan-out.
        assert!(html.contains(UNSUB_PLACEHOLDER));
        // Hero + alt escaped; CTA present.
        assert!(html.contains("newsletter-img/test-v1.png"));
        assert!(html.contains("An &quot;alt&quot; text"));
        assert!(html.contains(">Try it</a>"));
        // Rendered links get the inline brand style (mail clients strip
        // <style> blocks, so this is the only styling path).
        assert!(html.contains("<a style=\"color:#00796B;\" href=\"https://example.com\""));
        // The footer promises, verbatim enough to notice drift.
        assert!(html.contains("No tracking pixels"));
        assert!(html.contains("never more than monthly"));
        assert!(html.contains("G ROX LTD"));
        // Light-only — the wrapper commits to one look.
        assert!(html.contains("color-scheme"));
    }

    #[test]
    fn wrapper_omits_hero_and_cta_when_absent() {
        let mut i = issue("plain");
        i.hero_url = None;
        i.cta_text = None;
        i.cta_url = None;
        let html = render_issue_html(&i, None);
        assert!(!html.contains("<img"));
        assert!(!html.contains("Try it"));
    }

    #[test]
    fn substitution_replaces_every_occurrence() {
        let html = render_issue_html(&issue("body"), None);
        let out = substitute_recipient(
            &html,
            "https://meshharbor.itachi.fans/api/subscribe/unsubscribe/abc",
        );
        assert!(!out.contains(UNSUB_PLACEHOLDER));
        assert!(out.contains("unsubscribe/abc"));
    }
}
