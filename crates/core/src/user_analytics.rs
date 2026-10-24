// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Platform user analytics (wave 2): who is connected, for how long,
//! from what browser, and from where.
//!
//! **Privacy shape, decided up front.** The raw client IP is used ONCE,
//! at connect time, to resolve a country — and then dropped. Nothing
//! here stores an address, and page paths are normalised (`/tenant/:id`)
//! so no room, message or tenant identifier ends up in an analytics
//! row. What remains is deliberately coarse: user, org, duration,
//! browser family, platform, country, page.
//!
//! Country resolution is OPTIONAL and pluggable — point
//! `ROOMLER__STATS__GEOIP_MMDB` at a MaxMind-format country database
//! (DB-IP, GeoLite2) and it resolves; leave it unset, or set it empty, and
//! every session records `unknown`. The server image names DB-IP's
//! CC BY 4.0 "IP to Country Lite" by default (#1896, `files/geoip/README.md`);
//! no dataset is vendored into the repo, and an absent database yields an
//! honest "we don't know" rather than a guess.

use std::net::IpAddr;

use bson::{DateTime, doc, oid::ObjectId};

/// Browser family + OS platform, the only two things we take from a
/// User-Agent. Hand-rolled: pulling a UA-parsing crate (and its
/// regex database) for two coarse labels is not a trade worth making,
/// and the match order below is the whole subtlety — every Chromium
/// browser also says "Chrome", and everything says "Mozilla".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaInfo {
    pub browser: &'static str,
    pub platform: &'static str,
}

pub fn parse_ua(ua: &str) -> UaInfo {
    let u = ua.to_ascii_lowercase();
    // Order matters: the more specific brand must win over the engine
    // it embeds (Edge/Opera/Brave all carry "chrome").
    let browser = if u.contains("edg/") || u.contains("edga/") || u.contains("edgios/") {
        "Edge"
    } else if u.contains("opr/") || u.contains("opera") {
        "Opera"
    } else if u.contains("brave") {
        "Brave"
    } else if u.contains("vivaldi") {
        "Vivaldi"
    } else if u.contains("firefox") || u.contains("fxios") {
        "Firefox"
    } else if u.contains("chrome") || u.contains("crios") || u.contains("chromium") {
        "Chrome"
    } else if u.contains("safari") {
        // Only after every Chromium brand is excluded: they all claim
        // "safari" for legacy reasons.
        "Safari"
    } else if u.contains("electron") || u.contains("tauri") || u.contains("roomler") {
        "Desktop app"
    } else if u.is_empty() {
        "unknown"
    } else {
        "Other"
    };

    let platform = if u.contains("android") {
        "Android"
    } else if u.contains("iphone") || u.contains("ipad") || u.contains("ios") {
        "iOS"
    } else if u.contains("windows") {
        "Windows"
    } else if u.contains("mac os") || u.contains("macintosh") {
        "macOS"
    } else if u.contains("cros") {
        "ChromeOS"
    } else if u.contains("linux") || u.contains("x11") {
        "Linux"
    } else {
        "unknown"
    };

    UaInfo { browser, platform }
}

/// Country lookup backed by an optional MaxMind-format database.
///
/// Held as `Option`: with no database configured every call answers
/// `None`, which surfaces as `unknown` — never a fabricated country.
pub struct GeoIp {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

/// The loaded reader's own version metadata, not an IP label or a guessed
/// filename. This is NOT a content hash or a cryptographic attestation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeoIpDatasetIdentity {
    pub database_type: String,
    pub build_epoch: u64,
    pub ip_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpSecurityLookup {
    pub dataset: Option<GeoIpDatasetIdentity>,
    pub country_code: Option<String>,
}

impl GeoIp {
    /// Open the database named by `stats.geoip_mmdb`. A missing or
    /// unreadable file is logged and degrades to "no geo", because
    /// analytics must never keep the server from starting.
    ///
    /// An EMPTY value is an explicit "off", not a broken path. The image
    /// names a database by default (#1896), so an operator who wants no
    /// country lookup at all sets the variable to `""`. That must not log a
    /// warning on every boot.
    pub fn open(path: Option<&str>) -> Self {
        let path = path.map(str::trim).filter(|p| !p.is_empty());
        let reader = path.and_then(|p| match maxminddb::Reader::open_readfile(p) {
            Ok(r) => {
                // WHICH database and HOW OLD: a country database goes stale
                // month by month, and the dashboard's credit depends on whose
                // data it is. The image's CI smoke greps this line.
                tracing::info!(
                    path = %p,
                    database = %r.metadata.database_type,
                    built = %built_on(r.metadata.build_epoch),
                    "geoip database loaded"
                );
                Some(r)
            }
            Err(e) => {
                tracing::warn!(path = %p, %e, "geoip database unusable — countries will read 'unknown'");
                None
            }
        });
        Self { reader }
    }

    pub fn enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// The loaded database's own `database_type` (`DBIP-Country-Lite`,
    /// `GeoLite2-Country`, …), or `None` with no database. The dashboard
    /// keys its attribution on this, so a deployment that supplies its own
    /// database is never credited to someone else's.
    pub fn database(&self) -> Option<&str> {
        self.reader
            .as_ref()
            .map(|r| r.metadata.database_type.as_str())
    }

    /// ISO country code for an address, or `None` when unresolvable —
    /// an address the database doesn't cover is a normal outcome, not an
    /// error worth logging on every connection.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let r = self.reader.as_ref()?;
        let looked: maxminddb::geoip2::Country = r.lookup(ip).ok()?;
        looked.country?.iso_code.map(str::to_string)
    }

    /// Security producers use the same loaded reader regardless of whether
    /// optional analytics collection is enabled. Missing data stays unknown.
    pub fn security_lookup(&self, ip: IpAddr) -> GeoIpSecurityLookup {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
            ip => ip,
        };
        let dataset = self.reader.as_ref().map(|r| GeoIpDatasetIdentity {
            database_type: r.metadata.database_type.clone(),
            build_epoch: r.metadata.build_epoch,
            ip_version: r.metadata.ip_version,
        });
        GeoIpSecurityLookup {
            // A loopback/private proxy is not a geographically located client.
            // Do not let an unusually broad database turn a missing trusted
            // proxy configuration into a fabricated non-mainland observation.
            country_code: if private_or_local_source(ip) {
                None
            } else {
                self.country(ip)
            },
            dataset,
        }
    }
}

/// Only explicit private/local source categories are excluded here. This is not
/// a hand-maintained "all global Internet addresses" classifier: other special
/// addresses still require an actual country result from the loaded database.
fn private_or_local_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let a = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_broadcast()
                || a[0] == 0
                || a[0] >= 240
                || (a[0] == 100 && (64..128).contains(&a[1]))
        }
        IpAddr::V6(v) => {
            let first = v.segments()[0];
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
        }
    }
}

/// The database's `build_epoch` as a calendar date, for the load log.
fn built_on(epoch: u64) -> String {
    let date = i64::try_from(epoch)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|ms| DateTime::from_millis(ms).try_to_rfc3339_string().ok());
    match date {
        Some(d) => d.get(..10).unwrap_or(&d).to_string(),
        None => format!("epoch {epoch}"),
    }
}

/// Collapse a SPA path to its route shape: every id-looking segment
/// becomes `:id`, so analytics rows can be grouped by page without
/// carrying tenant/room/message identifiers around.
pub fn normalize_path(path: &str) -> String {
    let cleaned = path.split(['?', '#']).next().unwrap_or(path);
    let mut out = String::with_capacity(cleaned.len());
    for seg in cleaned.split('/') {
        if seg.is_empty() {
            continue;
        }
        out.push('/');
        if is_id_like(seg) {
            out.push_str(":id");
        } else {
            out.push_str(&seg.to_ascii_lowercase());
        }
    }
    if out.is_empty() { "/".to_string() } else { out }
}

fn is_id_like(seg: &str) -> bool {
    // 24-hex ObjectId, a UUID, or any long digit run.
    let hex24 = seg.len() == 24 && seg.chars().all(|c| c.is_ascii_hexdigit());
    let uuid = seg.len() == 36 && seg.matches('-').count() == 4;
    let numeric = seg.len() > 6 && seg.chars().all(|c| c.is_ascii_digit());
    hex24 || uuid || numeric
}

/// Open a WS session row and return its id (for the close update).
#[allow(clippy::too_many_arguments)]
pub async fn open_session(
    state: &crate::Core,
    user_id: ObjectId,
    tenant_id: Option<ObjectId>,
    ua: &str,
    ip: Option<IpAddr>,
) -> Option<ObjectId> {
    if !state.settings.stats.enabled {
        return None;
    }
    let info = parse_ua(ua);
    // The IP is resolved and DROPPED here — it is never written.
    let country = ip
        .and_then(|ip| state.geoip.country(ip))
        .unwrap_or_else(|| "unknown".to_string());
    let id = ObjectId::new();
    let doc = doc! {
        "_id": id,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "started_at": DateTime::now(),
        "ended_at": bson::Bson::Null,
        "browser": info.browser,
        "platform": info.platform,
        "country": country,
        "pod": state.pod.pod_id.clone(),
    };
    match state
        .db
        .collection::<bson::Document>(WS_SESSIONS)
        .insert_one(doc)
        .await
    {
        Ok(_) => Some(id),
        Err(e) => {
            tracing::debug!(%e, "ws session open persist failed");
            None
        }
    }
}

/// Close a WS session row, stamping its duration.
pub async fn close_session(state: &crate::Core, id: ObjectId) {
    let now = DateTime::now();
    let update = vec![doc! { "$set": {
        "ended_at": bson::Bson::DateTime(now),
        "duration_s": { "$divide": [
            { "$subtract": [ bson::Bson::DateTime(now), "$started_at" ] },
            1000,
        ]},
    }}];
    if let Err(e) = state
        .db
        .collection::<bson::Document>(WS_SESSIONS)
        .update_one(doc! { "_id": id, "ended_at": bson::Bson::Null }, update)
        .await
    {
        tracing::debug!(%e, "ws session close persist failed");
    }
}

pub const WS_SESSIONS: &str = "ws_sessions";
pub const PAGE_VIEWS: &str = "page_views";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_brand_beats_the_engine_it_embeds() {
        // Every Chromium browser also says "Chrome", and all of them say
        // "Safari" — the specific brand has to win.
        let edge = parse_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        );
        assert_eq!(edge.browser, "Edge");
        assert_eq!(edge.platform, "Windows");

        let chrome = parse_ua(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/126.0.0.0 Safari/537.36",
        );
        assert_eq!(chrome.browser, "Chrome");
        assert_eq!(chrome.platform, "Linux");

        let safari = parse_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        );
        assert_eq!(safari.browser, "Safari");
        assert_eq!(safari.platform, "macOS");

        let ff = parse_ua("Mozilla/5.0 (Windows NT 10.0; rv:127.0) Gecko/20100101 Firefox/127.0");
        assert_eq!(ff.browser, "Firefox");

        let ios = parse_ua(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) CriOS/126.0 Mobile/15E148 Safari/604.1",
        );
        assert_eq!(ios.browser, "Chrome");
        assert_eq!(ios.platform, "iOS");
    }

    #[test]
    fn unknown_ua_is_labelled_not_guessed() {
        assert_eq!(parse_ua("").browser, "unknown");
        assert_eq!(parse_ua("").platform, "unknown");
        assert_eq!(parse_ua("curl/8.4.0").browser, "Other");
    }

    #[test]
    fn paths_lose_every_identifier() {
        assert_eq!(
            normalize_path("/tenant/69a1dbbad2000f26adc875ce/room/69a1dbc8d2000f26adc875d5"),
            "/tenant/:id/room/:id"
        );
        assert_eq!(
            normalize_path("/tenant/69a1dbbad2000f26adc875ce"),
            "/tenant/:id"
        );
        assert_eq!(normalize_path("/observability"), "/observability");
        assert_eq!(normalize_path("/"), "/");
        // Query strings and fragments carry ids too — dropped whole.
        assert_eq!(normalize_path("/rooms?tab=all#x"), "/rooms");
        // UUIDs and long digit runs are ids as well.
        assert_eq!(
            normalize_path("/x/123e4567-e89b-12d3-a456-426614174000"),
            "/x/:id"
        );
        assert_eq!(normalize_path("/invite/1234567890"), "/invite/:id");
        // Short numerics are NOT ids — they're usually route params like
        // a page number, and collapsing them would erase real routes.
        assert_eq!(normalize_path("/page/42"), "/page/42");
    }

    #[test]
    fn geoip_without_a_database_answers_unknown_not_a_guess() {
        let g = GeoIp::open(None);
        assert!(!g.enabled());
        assert_eq!(g.country("8.8.8.8".parse().unwrap()), None);
        // No database ⇒ nobody to credit on the dashboard.
        assert_eq!(g.database(), None);
        assert_eq!(
            g.security_lookup("8.8.8.8".parse().unwrap()),
            GeoIpSecurityLookup {
                dataset: None,
                country_code: None
            }
        );
        // A configured-but-missing file degrades the same way.
        let g = GeoIp::open(Some("/nonexistent/GeoLite2-Country.mmdb"));
        assert!(!g.enabled());
        // An empty value is how an operator turns off the image's default
        // database (#1896): off, not a path to try.
        for off in ["", "   "] {
            let g = GeoIp::open(Some(off));
            assert!(!g.enabled());
            assert_eq!(g.database(), None);
        }
    }

    /// A two-record MaxMind DB (format 2.0), built byte by byte: one IPv4
    /// search-tree node sends 0.0.0.0/1 to `{country: {iso_code: "US"}}` and
    /// 128.0.0.0/1 to `{country: {iso_code: "DE"}}`. Small enough to read in
    /// full, and real enough that the reader the server uses opens it and
    /// decodes the same record shape DB-IP and GeoLite2 ship.
    fn tiny_country_mmdb(database_type: &str) -> Vec<u8> {
        // Data-section encodings (sizes stay < 29, so one control byte).
        fn text(out: &mut Vec<u8>, v: &str) {
            out.push(0x40 | v.len() as u8); // utf8_string
            out.extend_from_slice(v.as_bytes());
        }
        fn map(out: &mut Vec<u8>, entries: u8) {
            out.push(0xE0 | entries);
        }
        fn uint16(out: &mut Vec<u8>, v: u16) {
            out.push(0xA2);
            out.extend_from_slice(&v.to_be_bytes());
        }
        fn uint32(out: &mut Vec<u8>, v: u32) {
            out.push(0xC4);
            out.extend_from_slice(&v.to_be_bytes());
        }
        fn uint64(out: &mut Vec<u8>, v: u64) {
            out.extend_from_slice(&[0x08, 9 - 7]); // extended type 9, 8 bytes
            out.extend_from_slice(&v.to_be_bytes());
        }
        fn country(code: &str) -> Vec<u8> {
            let mut d = Vec::new();
            map(&mut d, 1);
            text(&mut d, "country");
            map(&mut d, 1);
            text(&mut d, "iso_code");
            text(&mut d, code);
            d
        }

        let (us, de) = (country("US"), country("DE"));
        let node_count: u32 = 1;
        // A record above `node_count` points into the data section, at
        // `record - node_count - 16` (the 16 is the zeroed separator).
        let to_us = node_count + 16;
        let to_de = to_us + us.len() as u32;
        let mut db = Vec::new();
        db.extend_from_slice(&to_us.to_be_bytes()[1..]); // 24-bit records
        db.extend_from_slice(&to_de.to_be_bytes()[1..]);
        db.extend_from_slice(&[0; 16]);
        db.extend_from_slice(&us);
        db.extend_from_slice(&de);
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        map(&mut db, 9);
        text(&mut db, "binary_format_major_version");
        uint16(&mut db, 2);
        text(&mut db, "binary_format_minor_version");
        uint16(&mut db, 0);
        text(&mut db, "build_epoch");
        uint64(&mut db, 1_790_812_800); // 2026-10-01T00:00:00Z
        text(&mut db, "database_type");
        text(&mut db, database_type);
        text(&mut db, "description");
        map(&mut db, 1);
        text(&mut db, "en");
        text(&mut db, "test fixture");
        text(&mut db, "ip_version");
        uint16(&mut db, 4);
        text(&mut db, "languages");
        db.extend_from_slice(&[0x01, 11 - 7]); // extended type 11 (array), 1 entry
        text(&mut db, "en");
        text(&mut db, "node_count");
        uint32(&mut db, node_count);
        text(&mut db, "record_size");
        uint16(&mut db, 24);
        db
    }

    #[test]
    fn geoip_resolves_countries_and_names_its_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dbip-country-lite.mmdb");
        std::fs::write(&path, tiny_country_mmdb("DBIP-Country-Lite")).unwrap();

        let g = GeoIp::open(path.to_str());
        assert!(g.enabled(), "a valid database must load");
        // What the dashboard credits: the database's own type, not a guess
        // from the file name.
        assert_eq!(g.database(), Some("DBIP-Country-Lite"));
        let security = g.security_lookup("8.8.8.8".parse().unwrap());
        assert_eq!(security.country_code.as_deref(), Some("US"));
        assert_eq!(
            security.dataset.as_ref().unwrap().database_type,
            "DBIP-Country-Lite"
        );
        assert_eq!(security.dataset.as_ref().unwrap().ip_version, 4);
        assert!(security.dataset.as_ref().unwrap().build_epoch > 0);
        for source in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert_eq!(
                g.security_lookup(source.parse().unwrap()).country_code,
                None,
                "{source}"
            );
        }
        assert_eq!(
            g.security_lookup("::ffff:8.8.8.8".parse().unwrap())
                .country_code
                .as_deref(),
            Some("US")
        );
        // `country.iso_code` is the field the analytics stores. A reader that
        // looked anywhere else (`registered_country`, which DB-IP's Lite
        // database does not carry) would answer `None` for every address,
        // with `geoip: true` on the dashboard.
        assert_eq!(g.country("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(
            g.country("193.0.6.139".parse().unwrap()).as_deref(),
            Some("DE")
        );
    }

    #[test]
    fn geoip_build_date_reads_as_a_date() {
        assert_eq!(built_on(1_790_812_800), "2026-10-01");
        assert_eq!(built_on(0), "1970-01-01");
        // Out of `DateTime`'s range: still logged, never a panic.
        assert_eq!(built_on(u64::MAX), format!("epoch {}", u64::MAX));
    }
}
