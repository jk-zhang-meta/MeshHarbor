// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6d-1 — SHA-256 crypt, Ulrich Drepper's public-domain algorithm,
//! and the form MySQL's `caching_sha2_password` keeps a password in:
//! `$A$005$`, a 20-byte salt, and this digest of the password at 5000 rounds.
//! A minted MySQL account is created from that form, so the password itself
//! never reaches the database (`docs/fr/FR-90-hive-agent-sessions.md` §3e,
//! "P3-6d, MySQL, SQL Server and Redis users, as designed").
//!
//! Drepper's `$5$` cuts a salt to 16 bytes and MySQL's to 20; the caller
//! gives the salt already cut, and the digest is the same algorithm either
//! way.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// crypt's own base64 alphabet.
const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The rounds MySQL's `caching_sha2_password` uses by default
/// (`caching_sha2_password_digest_rounds`), written `005` in its form.
pub(crate) const MYSQL_ROUNDS: u32 = 5000;

/// The length of the salt in MySQL's form.
pub(crate) const MYSQL_SALT_LEN: usize = 20;

/// The digest of `key` under `salt` after `rounds`, in crypt's base64: 43
/// characters. `salt` is used whole.
pub(crate) fn sha256_crypt(key: &[u8], salt: &[u8], rounds: u32) -> String {
    let b = Sha256::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();
    let mut a = Sha256::new();
    a.update(key);
    a.update(salt);
    let mut left = key.len();
    while left > 32 {
        a.update(b);
        left -= 32;
    }
    a.update(&b[..left]);
    // The key's length in binary, from its lowest bit: B for a 1, the key
    // for a 0.
    let mut bits = key.len();
    while bits > 0 {
        if bits & 1 == 1 {
            a.update(b);
        } else {
            a.update(key);
        }
        bits >>= 1;
    }
    let mut a = a.finalize();
    let mut dp = Sha256::new();
    for _ in 0..key.len() {
        dp.update(key);
    }
    let dp = Zeroizing::new(dp.finalize());
    let p: Zeroizing<Vec<u8>> = Zeroizing::new((0..key.len()).map(|i| dp[i % 32]).collect());
    let mut ds = Sha256::new();
    for _ in 0..16 + usize::from(a[0]) {
        ds.update(salt);
    }
    let ds = ds.finalize();
    let s: Vec<u8> = (0..salt.len()).map(|i| ds[i % 32]).collect();
    for round in 0..rounds {
        let mut c = Sha256::new();
        if round & 1 == 1 {
            c.update(p.as_slice());
        } else {
            c.update(a);
        }
        if round % 3 != 0 {
            c.update(&s);
        }
        if round % 7 != 0 {
            c.update(p.as_slice());
        }
        if round & 1 == 1 {
            c.update(a);
        } else {
            c.update(p.as_slice());
        }
        a = c.finalize();
    }
    encode(&a)
}

/// The 32-byte digest in crypt's base64, in the byte order SHA-256 crypt
/// fixes.
fn encode(d: &[u8]) -> String {
    let mut out = String::with_capacity(43);
    let mut put = |b2: u8, b1: u8, b0: u8, n: usize| {
        let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
        for _ in 0..n {
            out.push(char::from(ALPHABET[(w & 0x3f) as usize]));
            w >>= 6;
        }
    };
    for (x, y, z) in [
        (0, 10, 20),
        (21, 1, 11),
        (12, 22, 2),
        (3, 13, 23),
        (24, 4, 14),
        (15, 25, 5),
        (6, 16, 26),
        (27, 7, 17),
        (18, 28, 8),
        (9, 19, 29),
    ] {
        put(d[x], d[y], d[z], 4);
    }
    put(0, d[31], d[30], 3);
    out
}

/// A salt for MySQL's form, from crypt's own alphabet: 20 characters, so
/// the form holds no byte a SQL literal must escape.
pub(crate) fn mysql_salt() -> [u8; MYSQL_SALT_LEN] {
    let mut salt = [0u8; MYSQL_SALT_LEN];
    for b in &mut salt {
        *b = ALPHABET[usize::from(rand::random::<u8>() & 0x3f)];
    }
    salt
}

/// MySQL's `caching_sha2_password` form of `password` under `salt`:
/// `$A$005$<salt><digest>`, 70 characters.
pub(crate) fn mysql_caching_sha2(password: &str, salt: &[u8; MYSQL_SALT_LEN]) -> String {
    let digest = sha256_crypt(password.as_bytes(), salt, MYSQL_ROUNDS);
    let mut form = String::with_capacity(70);
    form.push_str("$A$005$");
    // The salt is crypt's alphabet, which is ASCII.
    form.extend(salt.iter().map(|b| char::from(*b)));
    form.push_str(&digest);
    form
}

#[cfg(test)]
mod tests;
