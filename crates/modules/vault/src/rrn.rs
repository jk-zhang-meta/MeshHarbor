// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! RRNs — the vault's names (`docs/meshharbor-hive-design.md` §8.1):
//! `rrn:{org}:{type}:{path}`, the ARN's shape.
//!
//! The organization's slug is part of the name, so a reference to another
//! organization's secret cannot be written down, let alone allowed. A
//! secret is stored by its organization and PATH; its RRN is rendered from
//! the organization's slug when it is shown, never stored, so the name and
//! the row cannot disagree.
//!
//! ⚠️ One spelling per name. A path is lowercase by rule, not folded: two
//! paths that differ only in case would be one name to a person and two to
//! an index, and a guard that compares one spelling is no guard for the
//! other.

/// The longest path.
pub const MAX_PATH_LEN: usize = 256;
/// The longest segment of a path.
pub const MAX_SEGMENT_LEN: usize = 64;
/// The longest field name.
pub const MAX_FIELD_LEN: usize = 64;

/// The one field of a `static` secret.
pub const STATIC_FIELD: &str = "value";

/// A secret's path, checked: one or more segments joined by `/`, each
/// starting with `[a-z0-9]` and going on in `[a-z0-9._-]` — so no empty
/// segment, no `.` or `..`, no `:` (the RRN's separator), nothing a person
/// would read two ways.
pub fn check_path(raw: &str) -> Result<&str, String> {
    if raw.is_empty() {
        return Err("path must not be empty".into());
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(format!("path is longer than {MAX_PATH_LEN} bytes"));
    }
    for segment in raw.split('/') {
        check_word(segment, MAX_SEGMENT_LEN, b"._-").map_err(|why| {
            format!(
                "path segment {segment:?} {why} (lowercase segments of a-z 0-9 . _ -, \
                 starting with a letter or a digit, joined by /)"
            )
        })?;
    }
    Ok(raw)
}

/// A field name, checked: `[a-z0-9]` then `[a-z0-9_-]`. No `.` and no `$`:
/// a field name is a key in the stored document (`fields.<name>`), and
/// either would make it a path or an operator to the database.
pub fn check_field(raw: &str) -> Result<&str, String> {
    check_word(raw, MAX_FIELD_LEN, b"_-").map_err(|why| {
        format!("field {raw:?} {why} (a-z 0-9 _ -, starting with a letter or a digit)")
    })?;
    Ok(raw)
}

/// A tag on a secret: one path segment's rule (`[a-z0-9][a-z0-9._-]*`, at
/// most [`MAX_SEGMENT_LEN`]). A policy matches tags by equality, so they
/// get one spelling too.
pub fn check_tag(raw: &str) -> Result<&str, String> {
    check_word(raw, MAX_SEGMENT_LEN, b"._-").map_err(|why| {
        format!("tag {raw:?} {why} (a-z 0-9 . _ -, starting with a letter or a digit)")
    })?;
    Ok(raw)
}

fn check_word(word: &str, max: usize, more: &[u8]) -> Result<(), &'static str> {
    let bytes = word.as_bytes();
    let Some(first) = bytes.first() else {
        return Err("is empty");
    };
    if bytes.len() > max {
        return Err("is too long");
    }
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err("must start with a lowercase letter or a digit");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || more.contains(b))
    {
        return Err("holds a character outside the allowed set");
    }
    Ok(())
}

/// A secret's RRN: `rrn:{org slug}:secret:{path}`.
pub fn secret_rrn(org_slug: &str, path: &str) -> String {
    format!("rrn:{org_slug}:secret:{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_lowercase_segments() {
        for ok in [
            "db",
            "staging/db",
            "prod/k8s/deployer",
            "tmpl/prod-kubeconfig",
            "a.b_c-d/0",
            "9lives",
        ] {
            assert_eq!(check_path(ok), Ok(ok), "{ok}");
        }
        for bad in [
            "",
            "/db",
            "db/",
            "staging//db",
            "Staging/db",
            "staging/DB",
            "./db",
            "../db",
            "staging/../prod",
            ".hidden",
            "-dash",
            "has space",
            "rrn:grox:secret:db",
            "tab\tdb",
            "nul\0db",
            "ünïcode",
            "db$",
        ] {
            assert!(check_path(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_path_and_its_segments_have_a_length() {
        let long_segment = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert!(check_path(&long_segment).is_err());
        assert!(check_path(&"a".repeat(MAX_SEGMENT_LEN)).is_ok());
        let long_path = vec!["a".repeat(MAX_SEGMENT_LEN); 5].join("/");
        assert!(long_path.len() > MAX_PATH_LEN);
        assert!(check_path(&long_path).is_err());
    }

    #[test]
    fn a_field_name_is_never_a_database_path_or_operator() {
        for ok in ["value", "password", "user_name", "tls-cert", "0"] {
            assert_eq!(check_field(ok), Ok(ok), "{ok}");
        }
        for bad in [
            "",
            "a.b",
            "$set",
            "pass word",
            "Password",
            "_x",
            "-x",
            "x/y",
            "x:y",
        ] {
            assert!(check_field(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(check_field(&"f".repeat(MAX_FIELD_LEN + 1)).is_err());
    }

    #[test]
    fn a_tag_is_one_lowercase_word() {
        for ok in ["build", "prod", "eu-west.1"] {
            assert_eq!(check_tag(ok), Ok(ok), "{ok}");
        }
        for bad in ["", "Build", "a/b", "has space", ".x"] {
            assert!(check_tag(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_rrn_names_the_organization() {
        assert_eq!(
            secret_rrn("grox", "staging/db"),
            "rrn:grox:secret:staging/db"
        );
    }

    #[test]
    fn a_refusal_says_what_was_refused() {
        let why = check_path("Staging/db").unwrap_err();
        assert!(why.contains("\"Staging\""), "{why}");
    }
}
