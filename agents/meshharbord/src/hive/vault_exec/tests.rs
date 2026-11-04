// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `vault_exec`'s checks, its program resolution and its scrub.

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;

#[test]
fn a_call_is_parsed_into_its_program_values_and_timeout() {
    let req = parse(&json!({
        "argv": ["psql", "-c", "select 1"],
        "env": {"PGPASSWORD": "db/main#password", "TOKEN": "rrn:grox:secret:api/key"},
        "timeout_s": 20,
    }))
    .unwrap();
    assert_eq!(req.argv, ["psql", "-c", "select 1"]);
    assert_eq!(req.timeout, Duration::from_secs(20));
    assert_eq!(
        req.env,
        [
            (
                "PGPASSWORD".to_string(),
                Handle {
                    secret: "db/main".into(),
                    field: "password".into()
                }
            ),
            (
                "TOKEN".to_string(),
                Handle {
                    secret: "rrn:grox:secret:api/key".into(),
                    field: String::new()
                }
            ),
        ]
    );
    let default = parse(&json!({"argv": ["psql"], "env": {"A": "db/main"}})).unwrap();
    assert_eq!(default.timeout, DEFAULT_TIMEOUT);
}

#[test]
fn a_call_that_could_steer_what_runs_is_refused() {
    let many: serde_json::Map<String, Value> = (0..=MAX_ENV)
        .map(|i| (format!("V{i}"), json!("db/main")))
        .collect();
    for bad in [
        json!({"argv": [], "env": {"A": "db/main"}}),
        json!({"argv": ["/usr/bin/psql"], "env": {"A": "db/main"}}),
        json!({"argv": ["./psql"], "env": {"A": "db/main"}}),
        json!({"argv": ["psql", 1], "env": {"A": "db/main"}}),
        json!({"argv": ["psql", "a\u{0}b"], "env": {"A": "db/main"}}),
        json!({"argv": ["psql"]}),
        json!({"argv": ["psql"], "env": {}}),
        json!({"argv": ["psql"], "env": many}),
        json!({"argv": ["psql"], "env": {"a": "db/main"}}),
        json!({"argv": ["psql"], "env": {"1A": "db/main"}}),
        json!({"argv": ["psql"], "env": {"LD_PRELOAD": "db/main"}}),
        json!({"argv": ["psql"], "env": {"DYLD_INSERT_LIBRARIES": "db/main"}}),
        json!({"argv": ["psql"], "env": {"BASH_ENV": "db/main"}}),
        json!({"argv": ["psql"], "env": {"A": ""}}),
        json!({"argv": ["psql"], "env": {"A": 7}}),
        json!({"argv": ["psql"], "env": {"A": "db/main"}, "timeout_s": 301}),
        json!({"argv": ["psql"], "env": {"A": "db/main"}, "timeout_s": "5"}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

/// A file in `dir` named `name`, with `mode`.
fn program(dir: &std::path::Path, name: &str, mode: u32) {
    let path = dir.join(name);
    std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn a_program_is_found_only_where_nobody_else_can_change_it() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let dirs = [
        first.path().to_str().unwrap(),
        second.path().to_str().unwrap(),
    ];
    program(second.path(), "tool", 0o755);
    assert_eq!(
        resolve("tool", &dirs).unwrap(),
        second.path().join("tool"),
        "the first directory that has it"
    );
    // Not executable: skipped, and the next directory is looked in.
    program(first.path(), "tool", 0o644);
    assert_eq!(resolve("tool", &dirs).unwrap(), second.path().join("tool"));
    // Writable by group or other: refused outright, never skipped past.
    program(first.path(), "tool", 0o775);
    assert!(
        resolve("tool", &dirs)
            .unwrap_err()
            .contains("written by others")
    );
    program(first.path(), "tool", 0o757);
    assert!(
        resolve("tool", &dirs)
            .unwrap_err()
            .contains("written by others")
    );
    assert!(
        resolve("nowhere", &dirs)
            .unwrap_err()
            .contains("was not found")
    );
    // The system's own copy of a shell is there, root's.
    assert!(resolve("sh", &SYSTEM_DIRS).is_ok());
}

fn values(pairs: &[(&str, &[u8])]) -> Vec<(String, Zeroizing<Vec<u8>>)> {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), Zeroizing::new(v.to_vec())))
        .collect()
}

#[test]
fn every_value_is_scrubbed_the_longest_first() {
    let v = values(&[("SHORT", b"abcd1234"), ("LONG", b"xxabcd1234yy")]);
    let out = scrub(b"a=xxabcd1234yy b=abcd1234 c=abcd1234", &v);
    assert_eq!(out, b"a=[vault:LONG] b=[vault:SHORT] c=[vault:SHORT]");
}

#[test]
fn a_value_too_short_to_mask_is_left_and_the_redactor_still_runs() {
    let v = values(&[("PIN", b"123")]);
    // A bearer token made here, never written down: a literal one is what a
    // secret scanner rightly flags.
    let token: String = (b'a'..=b'z').map(char::from).take(20).collect();
    let line = format!("pin=123 Authorization: Bearer {token}");
    let out = scrub(line.as_bytes(), &v);
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("pin=123 "), "{out}");
    assert!(!out.contains(&token), "{out}");
}
