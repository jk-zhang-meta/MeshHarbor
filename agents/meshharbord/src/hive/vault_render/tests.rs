// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `vault_render`'s template, its checks, its directory and its file.

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;

fn handle(secret: &str, field: &str) -> Handle {
    Handle {
        secret: secret.into(),
        field: field.into(),
    }
}

#[test]
fn a_template_is_split_into_its_text_and_its_secrets() {
    let (pieces, handles) = parse_template(
        "host: {{ db/main#host }}\npass: {{db/main#password}}\nagain: {{ db/main#host }}",
    )
    .unwrap();
    assert_eq!(
        handles,
        [handle("db/main", "host"), handle("db/main", "password")],
        "each secret once, in the order it first appears"
    );
    assert_eq!(
        pieces,
        [
            Piece::Text("host: ".into()),
            Piece::Value(0),
            Piece::Text("\npass: ".into()),
            Piece::Value(1),
            Piece::Text("\nagain: ".into()),
            Piece::Value(0),
        ]
    );
    let req = parse(&json!({"template": "{{ api/key }}", "dest": "token"})).unwrap();
    assert_eq!(req.ttl, DEFAULT_TTL);
    assert_eq!(req.dest, "token");
}

#[test]
fn a_call_that_could_not_render_safely_is_refused() {
    let nine: String = (0..=MAX_HANDLES)
        .map(|i| format!("{{{{ s/{i} }}}}"))
        .collect();
    for bad in [
        json!({"template": "no secret here", "dest": "a"}),
        json!({"template": "x {{ db/main", "dest": "a"}),
        // Unclosed after a good placeholder: refused for the brace alone.
        json!({"template": "{{ db/main }} then {{ db/other", "dest": "a"}),
        json!({"template": "{{ }}", "dest": "a"}),
        json!({"template": nine, "dest": "a"}),
        json!({"template": "a\u{0}{{ db/main }}", "dest": "a"}),
        json!({"template": "x".repeat(MAX_TEMPLATE + 1), "dest": "a"}),
        json!({"template": "{{ db/main }}"}),
        json!({"template": "{{ db/main }}", "dest": "../etc/passwd"}),
        json!({"template": "{{ db/main }}", "dest": "sub/file"}),
        json!({"template": "{{ db/main }}", "dest": ".hidden"}),
        json!({"template": "{{ db/main }}", "dest": "-rf"}),
        json!({"template": "{{ db/main }}", "dest": "a", "ttl_s": 10}),
        json!({"template": "{{ db/main }}", "dest": "a", "ttl_s": 901}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn the_rendered_file_is_the_template_with_its_values() {
    let (pieces, _) = parse_template("u={{ a }}\np={{ b }}\nu again={{ a }}\n").unwrap();
    let values = [
        Zeroizing::new(b"alice".to_vec()),
        Zeroizing::new(b"pw-1".to_vec()),
    ];
    let out = render(&pieces, &values).unwrap();
    assert_eq!(&out[..], b"u=alice\np=pw-1\nu again=alice\n");
    assert_eq!(
        out.capacity(),
        out.len(),
        "sized once: no regrowth left a copy behind"
    );
}

#[test]
fn the_secrets_directory_is_the_daemons_and_lists_nothing() {
    let run = tempfile::tempdir().unwrap();
    let dir = secrets_dir(run.path()).unwrap();
    assert_eq!(dir, run.path().join(SECRETS_DIR));
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o711);
    // Again: found, and held to its mode.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    secrets_dir(run.path()).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o711);

    // A link or a file in its place is refused, never followed.
    let linked = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), linked.path().join(SECRETS_DIR)).unwrap();
    assert!(secrets_dir(linked.path()).is_err());
    let filed = tempfile::tempdir().unwrap();
    std::fs::write(filed.path().join(SECRETS_DIR), b"x").unwrap();
    assert!(secrets_dir(filed.path()).is_err());
}

#[test]
fn the_file_is_written_whole_and_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "db.env", b"first", None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // Written again: replaced whole, and no temporary is left behind.
    write_file(dir.path(), "db.env", b"second", None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["db.env"]);
}
