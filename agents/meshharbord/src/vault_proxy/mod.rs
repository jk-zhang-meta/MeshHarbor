// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5 — the vault's proxies: an endpoint the daemon serves that
//! authenticates upstream with a leased value, so the session, its model and
//! its transcript never hold the value (`docs/fr/FR-90-hive-agent-sessions.md`
//! §3e, "P3-5, `proxy` mode, as designed").
//!
//! | Module | What |
//! |---|---|
//! | [`scram`] | SCRAM-SHA-256, the client's half: a proof of the password, never the password |
//! | [`tls`] | TLS to an upstream, always verified: the system's roots, and a CA the secret holds |
//! | [`pg`] | one Postgres session: the client let in by the endpoint, the upstream by SCRAM |
//! | [`mongo`] | one MongoDB session: the same, by SCRAM in `saslStart` and `saslContinue` (P3-5c-1) |
//! | [`http`] | one HTTP client connection: each request sent on to one upstream origin, the secret's credential in `Authorization` (P3-5d-1) |
//! | [`ssh_agent`] | one SSH agent connection: the secret's key, signing a sign-in to one of the secret's hosts and nothing else (P3-5f-1) |
//! | [`pg_mint`] | a Postgres user minted for one lease by a dynamic secret's issuer, and taken back (P3-6b-2a) |
//! | [`mysql_mint`] | a MySQL user minted for one lease, ended by an event, and taken back (P3-6d-1a) |
//! | [`k8s_mint`] | a Kubernetes service account's token minted for one lease, bound to a Secret its revocation deletes (P3-6f-1) |
//! | [`minter`] | the minter a dynamic secret's provider names, which the lease client calls (P3-6d-1b) |
//!
//! P3-5b-1 builds these, P3-5c-1 the MongoDB engine, P3-5d-1 the HTTP one
//! and P3-5f-1 the SSH agent; the endpoint (`hive::vault_connect`) serves
//! them, one session per connection. The minter's caller is the daemon's
//! lease client (`crate::vault`, P3-6b-2b).

// P3-6d-1 — a dynamic secret's bundle, as every minter opens it.
pub(crate) mod bundle;
pub(crate) mod http;
// P3-6f-1 — a Kubernetes service account's token minted per lease, bound to a
// Secret its revocation deletes; since P3-6f-2 the minter's caller reaches it.
pub(crate) mod k8s_mint;
// P3-6d-1b — the minter by provider, the lease client's one door to them.
pub(crate) mod minter;
pub(crate) mod mongo;
// P3-6d-1 — MySQL's client protocol, as a dynamic secret's issuer speaks it,
// and a MySQL user minted per lease.
pub(crate) mod mysql;
pub(crate) mod mysql_mint;
pub(crate) mod pg;
// P3-6b-2 — a Postgres user minted per lease, by a dynamic secret's issuer.
pub(crate) mod pg_mint;
pub(crate) mod scram;
// P3-6d-1 — SHA-256 crypt, the form a MySQL account keeps its password in.
pub(crate) mod sha_crypt;
pub(crate) mod ssh_agent;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod tls;

/// `host:port`, as an audience names an upstream: a host name (`_` allowed:
/// a Compose service may carry one), an IPv4 address
/// or a bracketed IPv6 one, then a port written plainly (no sign, no leading
/// zero). Answers the host, unbracketed, and the port.
///
/// P3-6b-2b moved it here from `hive::vault_connect`: the lease client mints
/// toward a dynamic secret's audience, and it is built wherever the `vault`
/// feature is, while `hive` is built only on a `hive_host`.
pub(crate) fn upstream_of(raw: &str) -> Result<(String, u16), String> {
    use meshharbor_remote_control::vault::lease_limits::MAX_AUDIENCE_LEN;
    let bad = || {
        format!(
            "upstream must be host:port, as the secret's audiences name it (such as \
             db.internal:5432, or [fd00::5]:5432): got {raw:?}"
        )
    };
    if raw.len() > MAX_AUDIENCE_LEN {
        return Err(bad());
    }
    let (host, port) = raw.rsplit_once(':').ok_or_else(bad)?;
    // Digits only, and no leading zero: one spelling per port, so the
    // audience the vault matches is the port dialled.
    let plain =
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !port.starts_with('0');
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| plain && *p != 0)
        .ok_or_else(bad)?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => {
            v6.parse::<std::net::Ipv6Addr>().map_err(|_| bad())?;
            v6
        }
        None => {
            let name_ok = !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !host.starts_with(['.', '-']);
            if !name_ok {
                return Err(bad());
            }
            host
        }
    };
    Ok((host.to_string(), port))
}

/// P3-5d-2 — an origin, as an audience names an HTTP upstream:
/// `https://<host>[:<port>]`, TLS always, with no path, query, user or
/// fragment, and the port written only where it is not 443, so an origin
/// has one spelling. A database's audience is `host:port`, a different
/// string, so a secret named for one never opens the other. Answers the
/// host, unbracketed, and the port.
///
/// P3-6f-1 moved it here from `hive::vault_connect`, as P3-6b-2b moved
/// [`upstream_of`]: a Kubernetes issuer's minter reads its audience with it,
/// wherever the `vault` feature is built.
pub(crate) fn origin_of(raw: &str) -> Result<(String, u16), String> {
    use meshharbor_remote_control::vault::lease_limits::MAX_AUDIENCE_LEN;
    let bad = || {
        format!(
            "upstream must be an origin, https://host or https://host:port, as the secret's \
             audiences name it (such as https://github.com): got {raw:?}"
        )
    };
    if raw.len() > MAX_AUDIENCE_LEN {
        return Err(bad());
    }
    let authority = raw.strip_prefix("https://").ok_or_else(bad)?;
    if authority.contains(['/', '?', '#', '@']) {
        return Err(bad());
    }
    // A name with no colon, or a bracketed IPv6 address, names no port.
    let ported = authority.contains(':') && !authority.ends_with(']');
    let (host, port) = if ported {
        upstream_of(authority)
    } else {
        upstream_of(&format!("{authority}:443"))
    }
    .map_err(|_| bad())?;
    if ported && port == 443 {
        let plain = authority.strip_suffix(":443").unwrap_or(authority);
        return Err(format!(
            "upstream names port 443, which an origin leaves out: write https://{plain}"
        ));
    }
    Ok((host, port))
}
