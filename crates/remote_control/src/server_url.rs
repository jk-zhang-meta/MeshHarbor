// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P1b — how an agent or the CLI reaches its server: over TLS.
//!
//! Enrollment promoted `http://` to `https://` (the enrollment token must
//! travel over TLS), but a `server_url` that reached a config another way, an
//! enrollment from before the rule or a hand edit, was dialled as written:
//! `ws://` for the control socket, and plain HTTP for the token renewal, the
//! updater and the uploads, with the device's credential on every request.
//! This is the one rule for every place a URL to the server is read:
//! `http://` becomes `https://`, and `ws://` becomes `wss://`.
//!
//! Two exemptions:
//! - **Loopback.** It has no off-host path to defend, and dev, test and CI
//!   servers run plaintext there (the integration `TestApp` binds
//!   `http://127.0.0.1`).
//! - **`allow_plaintext`.** A lab whose server serves no TLS says so on the
//!   device, in its own config. Never from the server: a compromised server
//!   must not be able to talk a device down to plaintext.
//!
//! On the production server a plaintext URL never connected anyway: port 80
//! answers every `/ws` with a 301, which a WebSocket client does not follow.
//! So there the rule only ever brings such a device back.

/// What [`secure`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secured {
    /// The URL to use.
    pub url: String,
    /// It was plaintext, and was promoted to TLS.
    pub promoted: bool,
}

/// The URL to reach the server at: `http://` becomes `https://` and `ws://`
/// becomes `wss://`, unless the host is loopback or `allow_plaintext` is set.
/// A promoted URL comes back cleaned (as below) and with `//`; anything else,
/// TLS already, a bare host or a malformed input, comes back as it came, for
/// the caller's own parser to judge.
///
/// The URL is read the way the HTTP client that dials it reads it (the WHATWG
/// rules of the `url` crate under `reqwest`), because a guard stricter than
/// its dialler is a guard with a hole: C0 controls and spaces at either end
/// are dropped and a tab or newline anywhere is ignored; the scheme is matched
/// in any case (`HTTP://` is plaintext too); and the slashes after `http:` may
/// be `\`, more or fewer, or none at all (`http:meshharbor.itachi.fans` is dialled as
/// `http://meshharbor.itachi.fans/`).
pub fn secure(raw: &str, allow_plaintext: bool) -> Secured {
    let unchanged = || Secured {
        url: raw.to_string(),
        promoted: false,
    };
    let cleaned: String = raw
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let Some((scheme, rest)) = cleaned.split_once(':') else {
        return unchanged();
    };
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" => "https",
        "ws" => "wss",
        _ => return unchanged(),
    };
    let rest = rest.trim_start_matches(['/', '\\']);
    if allow_plaintext || is_loopback_authority(rest) {
        return unchanged();
    }
    Secured {
        url: format!("{tls}://{rest}"),
        promoted: true,
    }
}

/// Whether `after_scheme` (`[userinfo@]host[:port][/path]`) names a loopback
/// host: `localhost`, `127.0.0.0/8` or `::1`. The host is found as the dialler
/// finds it: the authority ends at the first `/`, `\`, `?` or `#`, and the
/// host follows its last `@` (`http://localhost:80@evil.example` dials
/// `evil.example`, and `http://evil.example#@127.0.0.1` dials it too). Strict
/// on purpose: `localhost.example` or `127.0.0.1.example` are names like any
/// other, and a spelling this does not read as loopback (`0x7f.1`, `%6c…`) is
/// not exempt, so every doubt falls on the side of TLS.
pub fn is_loopback_authority(after_scheme: &str) -> bool {
    let authority = after_scheme
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host_port.strip_prefix('[') {
        // `[::1]:8080` → `::1`
        Some(inner) => inner.split(']').next().unwrap_or_default(),
        // An unbracketed host ends at its first `:`; what follows is the port.
        None => host_port.split(':').next().unwrap_or_default(),
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(raw: &str) -> (String, bool) {
        let r = secure(raw, false);
        (r.url, r.promoted)
    }

    /// AC3's two halves, and the same for a WebSocket URL: a remote plaintext
    /// URL is promoted; loopback stays as it is.
    #[test]
    fn plaintext_to_a_remote_host_is_promoted() {
        assert_eq!(
            s("http://meshharbor.itachi.fans"),
            ("https://meshharbor.itachi.fans".into(), true)
        );
        assert_eq!(
            s("http://meshharbor.itachi.fans/"),
            ("https://meshharbor.itachi.fans/".into(), true)
        );
        assert_eq!(
            s("ws://meshharbor.itachi.fans/ws"),
            ("wss://meshharbor.itachi.fans/ws".into(), true)
        );
        assert_eq!(
            s("http://10.0.0.5:3000"),
            ("https://10.0.0.5:3000".into(), true),
            "a private address is still off-host"
        );
        assert_eq!(
            s("http://[2001:db8::1]:8080"),
            ("https://[2001:db8::1]:8080".into(), true)
        );
    }

    #[test]
    fn loopback_stays_plaintext() {
        for raw in LOOPBACK {
            assert_eq!(s(raw), (raw.to_string(), false), "{raw}");
        }
    }

    const LOOPBACK: &[&str] = &[
        "http://127.0.0.1",
        "http://127.0.0.1:41003",
        "http://127.5.5.5",
        "http://localhost:5001/",
        "http://LOCALHOST",
        "http://[::1]:8080",
        "ws://127.0.0.1:3000/ws",
        "http://user@127.0.0.1",
        "http://127.0.0.1?x=1",
        "http://localhost#top",
    ];

    /// Plaintext to a host that is not loopback, spelled every way the
    /// dialler accepts: any case, stray whitespace, the slashes as `\`, fewer
    /// or none, and a `localhost` or `127.0.0.1` that is really userinfo, a
    /// fragment, a path or a query, or that only looks like loopback (`0127`
    /// is octal to the dialler: `87.0.0.1`).
    const OFF_HOST: &[&str] = &[
        "http://meshharbor.itachi.fans",
        "HTTP://meshharbor.itachi.fans",
        "Ws://meshharbor.itachi.fans/ws",
        " http://meshharbor.itachi.fans \n",
        "ht\ttp://meshharbor.itachi.fans",
        "http:meshharbor.itachi.fans",
        "http:/meshharbor.itachi.fans",
        "http:\\\\meshharbor.itachi.fans",
        "http:///meshharbor.itachi.fans",
        "WS:meshharbor.itachi.fans/ws",
        "http://10.0.0.5:3000",
        "http://[2001:db8::1]:8080",
        "http://localhost:80@evil.example",
        "http://127.0.0.1@evil.example",
        "http://evil.example#@127.0.0.1",
        "http://evil.example/@127.0.0.1",
        "http://evil.example\\@127.0.0.1",
        "http://evil.example?@127.0.0.1",
        "http://localhost.example",
        "http://127.0.0.1.example",
        "http://0127.0.0.1",
    ];

    fn the_dialler_reads_loopback(u: &url::Url) -> bool {
        match u.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
    }

    /// The guard reads a URL as the client that dials it does (the `url`
    /// crate under `reqwest`), so no spelling gets past it: every plaintext
    /// URL the dialler would send off-host is promoted, to one the dialler
    /// reads as TLS to the same host, port and path; and what it leaves alone
    /// the dialler reads as loopback. A loopback spelled in a form the guard
    /// does not read (hex, a bare number, percent-escapes) is promoted: the
    /// doubt falls on the side of TLS.
    #[test]
    fn the_guard_reads_a_url_as_its_dialler_does() {
        for raw in OFF_HOST {
            let dialled = url::Url::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert!(
                matches!(dialled.scheme(), "http" | "ws") && !the_dialler_reads_loopback(&dialled),
                "{raw:?} is not plaintext off-host to the dialler: {dialled}"
            );
            let secured = secure(raw, false);
            assert!(secured.promoted, "{raw:?} was left plaintext");
            let now = url::Url::parse(&secured.url)
                .unwrap_or_else(|e| panic!("{raw:?} became {:?}: {e}", secured.url));
            assert!(
                matches!(now.scheme(), "https" | "wss"),
                "{raw:?} became {now}"
            );
            assert_eq!(
                (now.host(), now.port(), now.path()),
                (dialled.host(), dialled.port(), dialled.path()),
                "{raw:?} became {now}, the dialler read {dialled}"
            );
        }
        for raw in LOOPBACK {
            let dialled = url::Url::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert!(the_dialler_reads_loopback(&dialled), "{raw:?}: {dialled}");
        }
        for raw in ["http://0x7f.1", "http://2130706433", "http://%6c%6fcalhost"] {
            let dialled = url::Url::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert!(the_dialler_reads_loopback(&dialled), "{raw:?}: {dialled}");
            assert!(secure(raw, false).promoted, "{raw:?}");
        }
    }

    /// The lab's escape keeps plaintext; TLS, a bare host and other schemes
    /// come back untouched.
    #[test]
    fn the_escape_and_everything_else_are_left_alone() {
        assert_eq!(
            secure("http://lab.local:3000", true),
            Secured {
                url: "http://lab.local:3000".into(),
                promoted: false
            }
        );
        for raw in [
            "https://meshharbor.itachi.fans",
            "wss://meshharbor.itachi.fans/ws",
            "meshharbor.itachi.fans",
            "ftp://x",
            "",
        ] {
            assert_eq!(s(raw), (raw.to_string(), false), "{raw}");
        }
    }
}
