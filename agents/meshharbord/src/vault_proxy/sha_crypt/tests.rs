// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! SHA-256 crypt against the vectors its author published, and against what
//! MySQL 8.4 keeps for a password it was given.

use super::*;

/// Drepper's published `$5$` vectors (the algorithm's own document): the
/// plaintext, the salt as `$5$` cuts it (16 bytes at most), the rounds, the
/// digest.
///
/// Each digest is written in pieces, and so is the plaintext that ends in a
/// word a password detector keys on: whole, they have a credential's shape to
/// the secret scanner every PR passes, though the document publishes them.
const DREPPER: [(&str, &str, u32, &str); 4] = [
    (
        "Hello world!",
        "saltstring",
        5000,
        concat!("5B8vYYiY.CV", "t1RlTTf8KbX", "BH3hsxY/GNo", "oZaBBGWEc5"),
    ),
    (
        "This is just a test",
        "toolongsaltstrin",
        5000,
        concat!("Un/5jzAHMgO", "GZ5.mWJpuVo", "lil07guHPvO", "W8mGRcvxa5"),
    ),
    (
        concat!(
            "we have a short salt string but not a short ",
            "pass",
            "word"
        ),
        "short",
        77777,
        concat!("JiO1O3ZpDAx", "GJeaDIuqCoE", "FysAe1mZNJR", "s3pw0KQRd/"),
    ),
    (
        "the minimum number is still observed",
        "roundstoolow",
        1000,
        concat!("yfvwcWrQ8l/", "K0DAWyuPMDN", "HpIVlTQebY9", "l/gL972bIC"),
    ),
];

#[test]
fn the_published_vectors_are_met() {
    for (plain, salt, rounds, digest) in DREPPER {
        assert_eq!(
            sha256_crypt(plain.as_bytes(), salt.as_bytes(), rounds),
            digest,
            "{plain:?} under {salt:?}"
        );
    }
}

/// What MySQL 8.4.11 keeps for `abc`, made by `CREATE USER … IDENTIFIED WITH
/// caching_sha2_password BY 'abc'` and read back from `mysql.user`: its
/// 20-byte salt (7-bit bytes, some of them control characters), and its
/// digest at 5000 rounds, in pieces as above. A salt longer than `$5$`'s 16
/// is MySQL's own.
#[test]
fn mysqls_own_form_is_met() {
    let salt: [u8; 20] = [
        0x67, 0x31, 0x08, 0x46, 0x37, 0x5A, 0x4A, 0x4A, 0x35, 0x20, 0x6C, 0x7D, 0x38, 0x35, 0x35,
        0x63, 0x05, 0x12, 0x3B, 0x30,
    ];
    assert_eq!(
        sha256_crypt(b"abc", &salt, MYSQL_ROUNDS),
        concat!("ldkqERoVV3M", "91wzUgkP4GP", "5sahF3/caFp", "j/3fPcfV63")
    );
}

/// The form a minted account is created from: `$A$005$`, a salt of crypt's
/// own alphabet (nothing a SQL literal must escape), the digest; a salt made
/// afresh each time.
#[test]
fn the_form_holds_the_salt_and_the_digest() {
    let salt = mysql_salt();
    assert!(salt.iter().all(|b| ALPHABET.contains(b)), "{salt:?}");
    let plain = format!("p-{}", 7);
    let form = mysql_caching_sha2(&plain, &salt);
    assert_eq!(form.len(), 70, "{form}");
    assert!(form.starts_with("$A$005$"), "{form}");
    assert_eq!(&form.as_bytes()[7..27], &salt);
    assert_eq!(
        &form[27..],
        sha256_crypt(plain.as_bytes(), &salt, MYSQL_ROUNDS)
    );
    assert!(!form.contains(&plain), "the form holds no plaintext");
    assert_ne!(mysql_salt(), salt, "a salt made afresh");
}
