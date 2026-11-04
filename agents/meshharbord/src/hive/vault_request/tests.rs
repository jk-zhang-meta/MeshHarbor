// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `vault_request`'s checks.

use serde_json::json;

use super::*;

#[test]
fn a_request_names_a_secret_a_mode_a_use_takes_and_its_audience() {
    let req =
        parse(&json!({"handle": "db/main#password", "mode": "exec", "audience": "psql"})).unwrap();
    assert_eq!(
        req,
        AheadRequest {
            handle: Handle {
                secret: "db/main".into(),
                field: "password".into(),
            },
            mode: "exec",
            audience: "psql".into(),
            ttl: DEFAULT_TTL,
        }
    );
    let file = parse(
        &json!({"handle": "k8s/prod", "mode": "file", "audience": "kubeconfig", "ttl_s": 900}),
    )
    .unwrap();
    assert_eq!((file.mode, file.ttl), ("file", 900));
    // P3-5b-2 — `proxy`, toward the upstream `vault_connect` will name.
    let proxy = parse(
        &json!({"handle": "db/main#password", "mode": "proxy", "audience": "db.internal:5432"}),
    )
    .unwrap();
    assert_eq!(
        (proxy.mode, proxy.audience.as_str()),
        ("proxy", "db.internal:5432")
    );
    // P3-5d-2 — or toward an HTTP upstream's origin.
    let http = parse(
        &json!({"handle": "git/bot#token", "mode": "proxy", "audience": "https://github.com"}),
    )
    .unwrap();
    assert_eq!(http.audience, "https://github.com");
    // P3-5f-2 — or toward an SSH host.
    let ssh = parse(
        &json!({"handle": "ssh/deploy#key", "mode": "proxy", "audience": "ssh://git@github.com"}),
    )
    .unwrap();
    assert_eq!(ssh.audience, "ssh://git@github.com");
}

#[test]
fn a_request_no_use_could_take_is_refused() {
    for bad in [
        json!({"mode": "exec", "audience": "psql"}),
        json!({"handle": "", "mode": "exec", "audience": "psql"}),
        // A proxy's audience is an upstream, host:port; a bare name is not.
        json!({"handle": "db/main", "mode": "proxy", "audience": "psql"}),
        // P3-5d-2 — an origin, as vault_connect names one: no path, no 443.
        json!({"handle": "git/bot", "mode": "proxy", "audience": "https://github.com/"}),
        json!({"handle": "git/bot", "mode": "proxy", "audience": "https://github.com:443"}),
        json!({"handle": "git/bot", "mode": "proxy", "audience": "http://github.com"}),
        // P3-5f-2 — an ssh host, as vault_connect names one: no path, no 22.
        json!({"handle": "ssh/deploy", "mode": "proxy", "audience": "ssh://github.com/org/repo"}),
        json!({"handle": "ssh/deploy", "mode": "proxy", "audience": "ssh://git@github.com:22"}),
        json!({"handle": "db/main", "mode": "exec", "audience": "db.internal:5432"}),
        json!({"handle": "db/main", "mode": "env", "audience": "psql"}),
        json!({"handle": "db/main", "audience": "psql"}),
        json!({"handle": "db/main", "mode": "exec"}),
        json!({"handle": "db/main", "mode": "exec", "audience": "/usr/bin/psql"}),
        json!({"handle": "db/main", "mode": "file", "audience": "../kubeconfig"}),
        json!({"handle": "db/main", "mode": "file", "audience": ".env"}),
        json!({"handle": "db/main", "mode": "exec", "audience": "-rf"}),
        json!({"handle": "db/main", "mode": "exec", "audience": "psql", "ttl_s": 29}),
        json!({"handle": "db/main", "mode": "exec", "audience": "psql", "ttl_s": 901}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}
