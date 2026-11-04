// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Roomler-agent MSI UpgradeCode constants.
//!
//! Mirror the values in the WiX sources at
//! `agents/meshharbord/wix/main.wxs` (per-user) and
//! `agents/meshharbord/wix-perMachine/main.wxs` (per-machine). The
//! parity tests below `include_str!` both `.wxs` files and assert the
//! Rust constants match — if anyone ever edits an UpgradeCode without
//! updating the constant here (or vice versa), `cargo test --lib`
//! fails loudly.

/// UpgradeCode for the per-user MSI flavour.
pub const PERUSER_UPGRADE_CODE: &str = "1F2D7B1C-8B2F-4D2E-B1A3-6B1E2C7E4D91";

/// UpgradeCode for the per-machine MSI flavour.
pub const PERMACHINE_UPGRADE_CODE: &str = "2A8E9C2D-3F1A-5E3F-C2B4-7C2F3D8F5E02";

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the `UpgradeCode='<guid>'` attribute out of a WiX source.
    /// Returns the GUID without braces, in the case the WiX source
    /// uses (we don't normalise — the constants must match byte-for-byte).
    fn extract_upgrade_code(wix: &str) -> &str {
        let needle = "UpgradeCode='";
        let start = wix
            .find(needle)
            .expect("UpgradeCode attribute missing from WiX source");
        let after = &wix[start + needle.len()..];
        let end = after
            .find('\'')
            .expect("unterminated UpgradeCode attribute in WiX source");
        &after[..end]
    }

    #[test]
    fn peruser_constant_matches_wix() {
        let wix = include_str!("../../wix/main.wxs");
        assert_eq!(extract_upgrade_code(wix), PERUSER_UPGRADE_CODE);
    }

    #[test]
    fn permachine_constant_matches_wix() {
        let wix = include_str!("../../wix-perMachine/main.wxs");
        assert_eq!(extract_upgrade_code(wix), PERMACHINE_UPGRADE_CODE);
    }
}
