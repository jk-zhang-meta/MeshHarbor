// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1b — the campaign key: one taxonomy, checked at both ends.
//!
//! The anonymous plane (purestat) and the account plane (meshharbor) meet only
//! at the campaign key `(source, medium, campaign, content)` and at counts
//! (spec §3a). A join by key is only a join when both ends spell the key the
//! same way — and the field found `youtub`, `YouTube` and an empty medium in
//! one month of real links (spec §2a). This module is the ONE table:
//!
//! * [`SOURCES`] / [`MEDIUMS`] — the canonical values the link linter checks
//!   against and the reports group by;
//! * [`normalize_source`] / [`normalize_medium`] — what the server applies at
//!   ingress (`attribution::sanitize`): trim, lowercase, then the aliases;
//! * [`source_group`] / [`medium_group`] — the canonical value, or `other`.
//!   ⚠️ An unknown value is **kept verbatim** (lowercased) and only
//!   *reported* under `other`, never dropped: a new channel must show up in
//!   the numbers before it has a name in this table, or the table decides
//!   what can be measured.
//! * [`channel_for_referrer_host`] — the organic channels, from a bare
//!   referrer host (spec §3b): search, AI assistants, social, community,
//!   code, self (`meshharbor.itachi.fans` is navigation, never a source), direct.
//!
//! * [`CampaignKey`] / [`KeyDepth`] (P6) — the key itself, normalised the
//!   way a sign-up's was at ingress, so a row of purestat's breakdown and a
//!   sign-up meet on the same spelling; and how deep a breakdown goes
//!   (`source` → `medium` → `campaign` → `content`).
//!
//! The private promotion pipeline's link linter checks against a pinned copy
//! of the same table; a change here is a change there.

use serde::{Deserialize, Serialize};

/// `utm_source`: the platform, never the account. `instagram` is retired
/// and kept for history.
pub const SOURCES: [&str; 14] = [
    "youtube",
    "tiktok",
    "x",
    "linkedin",
    "facebook",
    "reddit",
    "hn",
    "devto",
    "hashnode",
    "medium",
    "github",
    "newsletter",
    "blog",
    "instagram",
];

/// `utm_medium`: the format.
pub const MEDIUMS: [&str; 8] = [
    "video",
    "post",
    "carousel",
    "comment",
    "community",
    "bio",
    "article",
    "email",
];

/// The group every value outside the table reports under.
pub const OTHER: &str = "other";

/// The spellings seen in the wild, mapped to the canonical value. Applied
/// AFTER lowercasing, so the left side is lowercase.
const SOURCE_ALIASES: &[(&str, &str)] = &[
    ("twitter", "x"),
    ("fb", "facebook"),
    ("yt", "youtube"),
    ("youtub", "youtube"),
    ("li", "linkedin"),
    ("ig", "instagram"),
];

/// Trim, lowercase, then the aliases. Never empties a non-empty value and
/// never invents one: an unknown source comes back as itself, lowercased.
pub fn normalize_source(raw: &str) -> String {
    let value = raw.trim().to_lowercase();
    match SOURCE_ALIASES.iter().find(|(alias, _)| *alias == value) {
        Some((_, canonical)) => (*canonical).to_string(),
        None => value,
    }
}

/// Trim and lowercase. The mediums have no aliases worth encoding yet; an
/// unknown one is kept as itself.
pub fn normalize_medium(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// The canonical source a (normalised) value belongs to, or [`OTHER`].
pub fn source_group(normalised: &str) -> &'static str {
    SOURCES
        .iter()
        .copied()
        .find(|s| *s == normalised)
        .unwrap_or(OTHER)
}

/// The canonical medium a (normalised) value belongs to, or [`OTHER`].
pub fn medium_group(normalised: &str) -> &'static str {
    MEDIUMS
        .iter()
        .copied()
        .find(|m| *m == normalised)
        .unwrap_or(OTHER)
}

/// P8 — the social platforms the promotion pipeline pushes posts and metric
/// snapshots for (spec §3j), in report order. `instagram` is retired and
/// kept for history, as it is among the [`SOURCES`].
pub const PLATFORMS: [&str; 6] = [
    "youtube",
    "x",
    "linkedin",
    "facebook",
    "tiktok",
    "instagram",
];

/// The platforms no longer posted to: their history stays readable, and the
/// Channels view lists them only when they have data.
pub const RETIRED_PLATFORMS: [&str; 1] = ["instagram"];

/// A platform name as the pipeline spells it, through the source aliases
/// (`Twitter` → `x`, `yt` → `youtube`); `None` unless it is one of
/// [`PLATFORMS`] — an unknown platform is refused at ingest, never stored
/// under a name nothing reads.
pub fn normalize_platform(raw: &str) -> Option<&'static str> {
    let v = normalize_source(raw);
    PLATFORMS.iter().copied().find(|p| *p == v)
}

/// Whether a (normalised) platform is retired.
pub fn platform_retired(platform: &str) -> bool {
    RETIRED_PLATFORMS.contains(&platform)
}

/// `utm_campaign`: trimmed and lowercased. The taxonomy's ids are
/// `yyyymmdd-slug`, lowercase by construction, so a capital letter is a
/// typo of the same post, not a different one.
pub fn normalize_campaign(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// `utm_content`: trimmed and lowercased (`[a-z0-9-]` by the taxonomy).
pub fn normalize_content(raw: &str) -> String {
    raw.trim().to_lowercase()
}

// ── The key (P6) ─────────────────────────────────────────────────────────

/// How deep a breakdown by the campaign key goes: each level is the one
/// above plus one more UTM field. A row at a depth is purestat's breakdown
/// by exactly those dimensions, so its unique visitors are purestat's own
/// number for that key — never a sum of the finer rows below it, which
/// would count a visitor once per row they appear in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDepth {
    Source,
    Medium,
    Campaign,
    Content,
}

/// The four UTM dimensions of the key, in key order (purestat's names).
pub const UTM_DIMENSIONS: [&str; 4] = ["utm_source", "utm_medium", "utm_campaign", "utm_content"];

impl KeyDepth {
    pub const ALL: [KeyDepth; 4] = [
        KeyDepth::Source,
        KeyDepth::Medium,
        KeyDepth::Campaign,
        KeyDepth::Content,
    ];

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "source" => Some(KeyDepth::Source),
            "medium" => Some(KeyDepth::Medium),
            "campaign" => Some(KeyDepth::Campaign),
            "content" => Some(KeyDepth::Content),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            KeyDepth::Source => "source",
            KeyDepth::Medium => "medium",
            KeyDepth::Campaign => "campaign",
            KeyDepth::Content => "content",
        }
    }

    /// How many of the four fields the key keeps at this depth.
    pub fn fields(self) -> usize {
        match self {
            KeyDepth::Source => 1,
            KeyDepth::Medium => 2,
            KeyDepth::Campaign => 3,
            KeyDepth::Content => 4,
        }
    }

    /// purestat's dimensions for a breakdown at this depth, in key order.
    pub fn utm_dimensions(self) -> &'static [&'static str] {
        &UTM_DIMENSIONS[..self.fields()]
    }
}

/// The campaign key `(source, medium, campaign, content)` both planes are
/// joined by (spec §3a) — the ONE spelling a purestat row and a sign-up meet
/// on. [`CampaignKey::normalized`] applies exactly what ingress applies to a
/// sign-up (`attribution::sanitize`): each value trimmed, refused unless
/// printable ASCII, clamped to 64; the source and medium then through the
/// taxonomy (`YouTub` → `youtube`), the campaign and content lowercased. A
/// key without a source is no key: the visit or sign-up is organic.
///
/// ⚠️ Every field is client-chosen text (anyone can craft a link): a
/// reader renders it as TEXT, never as markup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CampaignKey {
    pub source: String,
    #[serde(default)]
    pub medium: Option<String>,
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

impl CampaignKey {
    /// The normalised key of four raw values; `None` when no source
    /// survives the cleaning. A field that does not survive is `None` too —
    /// the same field a sign-up with that value would have stored as absent.
    pub fn normalized(
        source: Option<&str>,
        medium: Option<&str>,
        campaign: Option<&str>,
        content: Option<&str>,
    ) -> Option<Self> {
        let clean = |v: Option<&str>| v.and_then(crate::attribution::clean_value);
        let source = clean(source).map(|v| normalize_source(&v))?;
        Some(Self {
            source,
            medium: clean(medium).map(|v| normalize_medium(&v)),
            campaign: clean(campaign).map(|v| normalize_campaign(&v)),
            content: clean(content).map(|v| normalize_content(&v)),
        })
    }

    /// The key cut to a depth: the fields below it are `None`, so every key
    /// that agrees down to the depth folds into one.
    pub fn at_depth(&self, depth: KeyDepth) -> Self {
        let n = depth.fields();
        Self {
            source: self.source.clone(),
            medium: if n >= 2 { self.medium.clone() } else { None },
            campaign: if n >= 3 { self.campaign.clone() } else { None },
            content: if n >= 4 { self.content.clone() } else { None },
        }
    }

    /// The taxonomy's group of the source: canonical, or [`OTHER`].
    pub fn group(&self) -> &'static str {
        source_group(&self.source)
    }
}

/// Where a visit came from, by its referrer host (spec §3b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Search,
    AiAssistant,
    Social,
    Community,
    Code,
    /// `meshharbor.itachi.fans` itself: navigation, never a source.
    #[serde(rename = "self")]
    SelfSite,
    /// No referrer at all.
    Direct,
    Other,
}

impl Channel {
    /// The wire / report spelling (the serde one).
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Search => "search",
            Channel::AiAssistant => "ai_assistant",
            Channel::Social => "social",
            Channel::Community => "community",
            Channel::Code => "code",
            Channel::SelfSite => "self",
            Channel::Direct => "direct",
            Channel::Other => "other",
        }
    }

    /// Every channel, in report order.
    pub const ALL: [Channel; 8] = [
        Channel::Search,
        Channel::AiAssistant,
        Channel::Social,
        Channel::Community,
        Channel::Code,
        Channel::SelfSite,
        Channel::Direct,
        Channel::Other,
    ];
}

/// Hosts matched by suffix (`host == domain` or `host` ends with
/// `.domain`), first match wins — so `gemini.google.com` sits ABOVE the
/// `google` label rule below, and `l.facebook.com` needs no row of its own.
const HOST_SUFFIXES: &[(&str, Channel)] = &[
    // AI assistants
    ("chatgpt.com", Channel::AiAssistant),
    ("chat.openai.com", Channel::AiAssistant),
    ("perplexity.ai", Channel::AiAssistant),
    ("gemini.google.com", Channel::AiAssistant),
    ("copilot.microsoft.com", Channel::AiAssistant),
    ("claude.ai", Channel::AiAssistant),
    // Search (the `google.*` / `yandex.*` families are a label rule below)
    ("bing.com", Channel::Search),
    ("duckduckgo.com", Channel::Search),
    ("ecosia.org", Channel::Search),
    // Social
    ("t.co", Channel::Social),
    ("x.com", Channel::Social),
    ("twitter.com", Channel::Social),
    ("linkedin.com", Channel::Social),
    ("lnkd.in", Channel::Social),
    ("facebook.com", Channel::Social),
    ("youtube.com", Channel::Social),
    ("youtu.be", Channel::Social),
    ("tiktok.com", Channel::Social),
    ("reddit.com", Channel::Social),
    ("instagram.com", Channel::Social),
    // Community
    ("news.ycombinator.com", Channel::Community),
    ("lobste.rs", Channel::Community),
    ("dev.to", Channel::Community),
    ("hashnode.com", Channel::Community),
    ("medium.com", Channel::Community),
    // Code
    ("github.com", Channel::Code),
    // Self
    ("meshharbor.itachi.fans", Channel::SelfSite),
];

/// Search engines whose registrable label is followed by any country TLD
/// (`google.com`, `www.google.co.uk`, `yandex.ru`).
const SEARCH_LABELS: &[&str] = &["google", "yandex"];

/// The organic channel of a referrer host. `None` (no referrer recorded) is
/// [`Channel::Direct`]; a host nothing here recognises is
/// [`Channel::Other`]. The host is read as `attribution::clean_host` stores
/// it — lowercase, optionally `:port` — but a raw `Host`-style value with
/// upper case or a trailing dot is tolerated.
pub fn channel_for_referrer_host(host: Option<&str>) -> Channel {
    let Some(raw) = host else {
        return Channel::Direct;
    };
    let host = raw.trim().to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.');
    if host.is_empty() {
        return Channel::Direct;
    }
    for (domain, channel) in HOST_SUFFIXES {
        if host == *domain || host.ends_with(&format!(".{domain}")) {
            return *channel;
        }
    }
    // `google.*`: a `google` label that is not the last one (so `google.com`,
    // `www.google.de`, `google.co.uk`), never a host that merely contains
    // the word (`googleusercontent.com`, `notgoogle.com`).
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2
        && labels[..labels.len() - 1]
            .iter()
            .any(|l| SEARCH_LABELS.contains(l))
    {
        return Channel::Search;
    }
    Channel::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC5's two halves: the aliases and the case, and an unknown value kept
    /// as itself rather than dropped or guessed at.
    #[test]
    fn sources_normalise_through_case_and_aliases() {
        assert_eq!(normalize_source("YouTub"), "youtube");
        assert_eq!(normalize_source(" yt "), "youtube");
        assert_eq!(normalize_source("YouTube"), "youtube");
        assert_eq!(normalize_source("Twitter"), "x");
        assert_eq!(normalize_source("FB"), "facebook");
        assert_eq!(normalize_source("li"), "linkedin");
        assert_eq!(normalize_source("IG"), "instagram");
        // Unknown: verbatim, lowercased — never dropped.
        assert_eq!(normalize_source("Mastodon"), "mastodon");
        assert_eq!(normalize_source("check"), "check");
        // A canonical value is a fixed point.
        for s in SOURCES {
            assert_eq!(normalize_source(s), s);
            assert_eq!(normalize_source(&s.to_uppercase()), s);
        }
    }

    #[test]
    fn mediums_normalise_through_case() {
        assert_eq!(normalize_medium("Video"), "video");
        assert_eq!(normalize_medium(" POST "), "post");
        assert_eq!(normalize_medium("reel"), "reel");
        for m in MEDIUMS {
            assert_eq!(normalize_medium(m), m);
            assert_eq!(normalize_medium(&m.to_uppercase()), m);
        }
    }

    /// The whole table, both directions: every canonical value groups to
    /// itself, every alias groups to its canonical, and anything else is
    /// `other`.
    #[test]
    fn the_table_is_exhaustive_and_unknowns_group_under_other() {
        for s in SOURCES {
            assert_eq!(source_group(s), s);
        }
        for (alias, canonical) in SOURCE_ALIASES {
            assert!(
                SOURCES.contains(canonical),
                "alias {alias} points outside the table: {canonical}"
            );
            assert_eq!(source_group(&normalize_source(alias)), *canonical);
        }
        for m in MEDIUMS {
            assert_eq!(medium_group(m), m);
        }
        assert_eq!(source_group("mastodon"), OTHER);
        assert_eq!(source_group(""), OTHER);
        assert_eq!(medium_group("reel"), OTHER);
        // The table has no duplicates (a duplicate would make `source_group`
        // depend on order).
        let mut sorted: Vec<&str> = SOURCES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SOURCES.len());
        let mut sorted: Vec<&str> = MEDIUMS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), MEDIUMS.len());
        // An alias must not shadow a canonical value.
        for (alias, _) in SOURCE_ALIASES {
            assert!(
                !SOURCES.contains(alias),
                "{alias} is both an alias and canonical"
            );
        }
    }

    /// The spec's §3b table, host by host, plus the subdomain and port forms
    /// the referrer actually arrives in.
    #[test]
    fn referrer_hosts_map_to_their_channel() {
        use Channel::*;
        let cases: &[(&str, Channel)] = &[
            // search
            ("google.com", Search),
            ("www.google.com", Search),
            ("www.google.co.uk", Search),
            ("google.de", Search),
            ("bing.com", Search),
            ("www.bing.com", Search),
            ("duckduckgo.com", Search),
            ("ecosia.org", Search),
            ("yandex.ru", Search),
            ("www.yandex.com", Search),
            // AI assistants
            ("chatgpt.com", AiAssistant),
            ("chat.openai.com", AiAssistant),
            ("perplexity.ai", AiAssistant),
            ("www.perplexity.ai", AiAssistant),
            ("gemini.google.com", AiAssistant),
            ("copilot.microsoft.com", AiAssistant),
            ("claude.ai", AiAssistant),
            // social
            ("t.co", Social),
            ("x.com", Social),
            ("twitter.com", Social),
            ("linkedin.com", Social),
            ("www.linkedin.com", Social),
            ("lnkd.in", Social),
            ("facebook.com", Social),
            ("l.facebook.com", Social),
            ("m.facebook.com", Social),
            ("youtube.com", Social),
            ("www.youtube.com", Social),
            ("m.youtube.com", Social),
            ("youtu.be", Social),
            ("tiktok.com", Social),
            ("www.tiktok.com", Social),
            ("reddit.com", Social),
            ("old.reddit.com", Social),
            ("out.reddit.com", Social),
            ("instagram.com", Social),
            // community
            ("news.ycombinator.com", Community),
            ("lobste.rs", Community),
            ("dev.to", Community),
            ("hashnode.com", Community),
            ("medium.com", Community),
            // code
            ("github.com", Code),
            // self
            ("meshharbor.itachi.fans", SelfSite),
            ("www.meshharbor.itachi.fans", SelfSite),
            // other
            ("example.com", Other),
            ("localhost", Other),
            ("localhost:5000", Other),
            ("googleusercontent.com", Other),
            ("notgoogle.com", Other),
            ("google", Other),
            ("meshharbor.itachi.fans.evil.example", Other),
        ];
        for (host, expected) in cases {
            assert_eq!(channel_for_referrer_host(Some(host)), *expected, "{host}");
        }
        // The forms a raw referrer can arrive in.
        assert_eq!(
            channel_for_referrer_host(Some("WWW.YouTube.com:443")),
            Social
        );
        assert_eq!(channel_for_referrer_host(Some("github.com.")), Code);
        // No referrer is direct, not other.
        assert_eq!(channel_for_referrer_host(None), Direct);
        assert_eq!(channel_for_referrer_host(Some("")), Direct);
        assert_eq!(channel_for_referrer_host(Some("   ")), Direct);
    }

    /// P6 — the key both planes join by: the taxonomy for source and
    /// medium, lowercase for campaign and content, and the ingress cleaning
    /// (a value that would not survive a sign-up's sanitising is absent).
    #[test]
    fn the_key_normalises_like_a_sign_up_at_ingress() {
        let k = CampaignKey::normalized(
            Some(" YouTub "),
            Some("Video"),
            Some(" 20261019-SSH-Slug "),
            Some("Desc-Top"),
        )
        .unwrap();
        assert_eq!(
            k,
            CampaignKey {
                source: "youtube".into(),
                medium: Some("video".into()),
                campaign: Some("20261019-ssh-slug".into()),
                content: Some("desc-top".into()),
            }
        );
        assert_eq!(k.group(), "youtube");
        // No source, or one the cleaning refuses: no key at all.
        assert_eq!(
            CampaignKey::normalized(None, Some("post"), None, None),
            None
        );
        assert_eq!(CampaignKey::normalized(Some("   "), None, None, None), None);
        assert_eq!(
            CampaignKey::normalized(Some("yöutube"), None, None, None),
            None
        );
        // A field the cleaning refuses is absent, as a sign-up stores it.
        let k = CampaignKey::normalized(Some("Mastodon"), Some("vidéo"), Some(""), None).unwrap();
        assert_eq!(k.group(), OTHER);
        assert_eq!(
            (
                k.source.as_str(),
                k.medium.as_deref(),
                k.campaign.as_deref()
            ),
            ("mastodon", None, None)
        );
        // Clamped to the attribution ceiling, as at ingress.
        let long = "c".repeat(200);
        let k = CampaignKey::normalized(Some("x"), None, Some(&long), None).unwrap();
        assert_eq!(k.campaign.unwrap().len(), 64);
    }

    /// The same raw link, through the sign-up's sanitising on one side and
    /// the key's normalisation on the other, is ONE key — the join's whole
    /// premise.
    #[test]
    fn a_stored_sign_up_and_a_raw_purestat_row_meet_on_one_key() {
        let raw = ("YouTub", "Video", "20261019-Slug", "Desc-Top");
        let stored = crate::attribution::sanitize(crate::attribution::AttributionInput {
            source: Some(raw.0.into()),
            medium: Some(raw.1.into()),
            campaign: Some(raw.2.into()),
            content: Some(raw.3.into()),
            ..Default::default()
        })
        .unwrap();
        let from_signup = CampaignKey::normalized(
            stored.source.as_deref(),
            stored.medium.as_deref(),
            stored.campaign.as_deref(),
            stored.content.as_deref(),
        );
        let from_purestat =
            CampaignKey::normalized(Some(raw.0), Some(raw.1), Some(raw.2), Some(raw.3));
        assert!(from_signup.is_some());
        assert_eq!(from_signup, from_purestat);
    }

    /// P8 — the pipeline's platform names, through the aliases; anything
    /// else is refused (`None`), and every platform is a source of the
    /// taxonomy (a post's link carries it as `utm_source`).
    #[test]
    fn platforms_normalise_through_the_aliases_and_nothing_else_passes() {
        assert_eq!(normalize_platform("Twitter"), Some("x"));
        assert_eq!(normalize_platform(" YT "), Some("youtube"));
        assert_eq!(normalize_platform("LinkedIn"), Some("linkedin"));
        assert_eq!(normalize_platform("fb"), Some("facebook"));
        assert_eq!(normalize_platform("TikTok"), Some("tiktok"));
        assert_eq!(normalize_platform("ig"), Some("instagram"));
        for unknown in ["mastodon", "reddit", "newsletter", "", "x.com"] {
            assert_eq!(normalize_platform(unknown), None, "{unknown}");
        }
        for p in PLATFORMS {
            assert_eq!(normalize_platform(p), Some(p));
            assert!(SOURCES.contains(&p), "{p} is not a taxonomy source");
        }
        assert!(platform_retired("instagram"));
        assert!(!platform_retired("youtube"));
    }

    #[test]
    fn a_depth_cuts_the_key_and_names_its_dimensions() {
        let k =
            CampaignKey::normalized(Some("linkedin"), Some("post"), Some("c1"), Some("a")).unwrap();
        assert_eq!(k.at_depth(KeyDepth::Content), k);
        let c = k.at_depth(KeyDepth::Campaign);
        assert_eq!(
            (c.campaign.as_deref(), c.content.as_deref()),
            (Some("c1"), None)
        );
        let m = k.at_depth(KeyDepth::Medium);
        assert_eq!(
            (m.medium.as_deref(), m.campaign.as_deref()),
            (Some("post"), None)
        );
        let s = k.at_depth(KeyDepth::Source);
        assert_eq!((s.source.as_str(), s.medium.as_deref()), ("linkedin", None));
        assert_eq!(KeyDepth::Source.utm_dimensions(), &["utm_source"]);
        assert_eq!(
            KeyDepth::Content.utm_dimensions(),
            &["utm_source", "utm_medium", "utm_campaign", "utm_content"]
        );
        for d in KeyDepth::ALL {
            assert_eq!(KeyDepth::parse(d.as_str()), Some(d));
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{}\"", d.as_str())
            );
        }
        assert_eq!(KeyDepth::parse("channel"), None);
        // On the wire an absent field is an explicit null.
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::json!({"source": "linkedin", "medium": null, "campaign": null, "content": null})
        );
    }

    #[test]
    fn channel_spellings_are_the_wire_names() {
        for c in Channel::ALL {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()));
        }
        assert_eq!(Channel::SelfSite.as_str(), "self");
        assert_eq!(Channel::AiAssistant.as_str(), "ai_assistant");
    }
}
