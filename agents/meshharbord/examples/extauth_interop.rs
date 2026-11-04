// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-52 — the DEVICE half of a cross-implementation OPAQUE login, driven over
//! stdin/stdout so a real browser-side client can log into it.
//!
//! This exists because the one decision in FR-52 that is expensive to get wrong
//! is whether a browser can log into a device at all. The ciphersuite, the KSF
//! parameters and the message encoding are all compatibility surfaces: once a
//! device stores a record, changing any of them is a forced password reset on
//! every device in the field. A Rust-to-Rust test cannot catch a mismatch with
//! the browser library, because both halves share whatever this crate got wrong.
//!
//! It registers a password exactly as `roomler rc password set` does
//! ([`set_password`]), then answers ONE login:
//!
//! ```text
//!   stdin : KE1 (base64url, no padding)      stdout: KE2
//!   stdin : KE3                              stdout: OK <sha256(session key)> | FAIL <reason>
//! ```
//!
//! The encoding is `@serenity-kit/opaque`'s (base64url, no padding), so its
//! output is fed in unmodified. Only a HASH of the session key is printed —
//! equal hashes on both sides prove the keys agree without printing either.
//!
//! Run (the password comes from the environment, never argv):
//!
//! ```text
//! cargo build -p meshharbord --features external-access --example extauth_interop
//! EXTAUTH_PW=… <js client that spawns target/debug/examples/extauth_interop>
//! ```

use std::io::{BufRead as _, Write as _};

use base64::Engine as _;
use meshharbord::external_access::{login_finish, login_start, set_password};
use sha2::Digest as _;

fn b64url() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn main() {
    let password = std::env::var("EXTAUTH_PW").expect("EXTAUTH_PW must hold the password");
    let (cred, _) = set_password(None, &password).expect("registration");

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut out = std::io::stdout();

    let ke1 = b64url()
        .decode(lines.next().expect("KE1 line").expect("stdin").trim())
        .expect("KE1 is base64url");
    let (ke2, pending) = match login_start(&cred, &ke1) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "FAIL start: {e}").unwrap();
            return;
        }
    };
    writeln!(out, "{}", b64url().encode(ke2)).unwrap();
    out.flush().unwrap();

    let ke3 = match lines.next() {
        Some(Ok(line)) => b64url().decode(line.trim()).expect("KE3 is base64url"),
        // The client abandoned the login — which is exactly what a client does
        // when KE2 told it the password was wrong.
        _ => {
            writeln!(out, "FAIL abandoned: no KE3").unwrap();
            return;
        }
    };
    match login_finish(pending, &ke3) {
        Ok(key) => {
            let digest = sha2::Sha256::digest(key.expose());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "OK {hex}").unwrap();
        }
        Err(e) => writeln!(out, "FAIL finish: {e}").unwrap(),
    }
}
