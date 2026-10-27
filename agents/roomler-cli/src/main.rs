// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler` — the standalone tunnel-client CLI binary.
//!
//! The command surface itself lives in `roomler_cli::cli` (the LIB), not
//! here, so that `meshharbord cli` can dispatch into the exact same code on
//! daemon hosts instead of the MSI shipping a second full copy of it. See
//! `cli.rs` for the surface and P3e lever D for the why.
//!
//! This binary is what tunnel-ONLY hosts install (release-tunnel.yml); daemon
//! hosts get a small `roomler` shim that re-execs `meshharbord cli` instead.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    roomler_cli::cli::run().await
}
