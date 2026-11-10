// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The minter by provider: each provider this build mints for reaches its
//! own minter, and any other is refused.

use serde_json::json;

use super::super::testing::made;
use super::*;

/// A bundle any of the minters reads: an issuer, its database, and a CA made
/// for the test.
fn bundle() -> Vec<u8> {
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .unwrap()
        .cert
        .pem();
    let word = made();
    serde_json::to_vec(&json!({
        "audience": "db.internal:3306",
        "fields": {
            "admin_user": "issuer",
            "admin_password": word,
            "database": "orders",
            "ca": ca,
        },
    }))
    .unwrap()
}

/// Each provider in `MINTS` is one the wire names, and is read by its own
/// minter; a bundle that does not parse is refused in that minter's words.
#[test]
fn each_provider_this_build_mints_for_reaches_its_own_minter() {
    for p in MINTS {
        assert!(providers::named(p).is_some(), "{p}");
        assert_eq!(
            Issuer::from_bundle(p, b"not a bundle").err().as_deref(),
            Some("the bundle does not parse"),
            "{p}"
        );
    }
    let b = bundle();
    assert!(matches!(
        Issuer::from_bundle(providers::POSTGRES.name, &b),
        Ok(Issuer::Postgres(_))
    ));
    assert!(matches!(
        Issuer::from_bundle(providers::MYSQL.name, &b),
        Ok(Issuer::Mysql(_))
    ));
    // P3-6f-2 — a Kubernetes issuer's bundle names an origin, and its
    // minter reads it; a database's bundle is no issuer of it.
    let k8s = serde_json::to_vec(&json!({
        "audience": "https://kubernetes.internal:6443",
        "fields": {
            "namespace": "hive-tokens",
            "service_account": "session-runner",
            "admin_token": made(),
        },
    }))
    .unwrap();
    assert!(matches!(
        Issuer::from_bundle(providers::KUBERNETES.name, &k8s),
        Ok(Issuer::Kubernetes(_))
    ));
    assert!(Issuer::from_bundle(providers::KUBERNETES.name, &b).is_err());
    assert!(Issuer::from_bundle(providers::POSTGRES.name, &k8s).is_err());
}

/// P3-6f-2 — the TTL a token is asked for is what is left of its lease, in
/// whole seconds, at least one and never past the longest lease, whatever
/// the two clocks say.
#[test]
fn a_tokens_ttl_is_what_is_left_of_its_lease() {
    let now = 1_767_225_600_000;
    assert_eq!(ttl_secs(now + 60_000, now), 60);
    assert_eq!(ttl_secs(now + 60_999, now), 60, "rounded down");
    assert_eq!(ttl_secs(now + 500, now), 1, "at least a second");
    assert_eq!(ttl_secs(now - 60_000, now), 1, "an end already past");
    assert_eq!(
        ttl_secs(now + 86_400_000, now),
        MAX_TTL_SECS,
        "never past the longest lease"
    );
    assert_eq!(ttl_secs(i64::MAX, i64::MIN), MAX_TTL_SECS);
}

/// A provider this build mints nothing for, however it is spelled, is
/// refused before its bundle is read.
#[test]
fn any_other_provider_is_refused() {
    let b = bundle();
    for p in ["github_app", "Postgres", "MYSQL", "", "from_a_newer_build"] {
        assert_eq!(
            Issuer::from_bundle(p, &b).err(),
            Some(format!("this build mints nothing for {p:?}")),
            "{p}"
        );
    }
}

/// The lease's end, as Postgres's `VALID UNTIL` takes it.
#[test]
fn the_lease_end_is_a_time_postgres_takes() {
    assert_eq!(rfc3339(1_767_225_600_000).unwrap(), "2026-01-01T00:00:00Z");
}
