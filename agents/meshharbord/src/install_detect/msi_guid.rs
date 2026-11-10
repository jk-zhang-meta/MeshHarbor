// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows Installer "packed" / "compressed" GUID encoder.
//!
//! Windows Installer stores `UpgradeCode`-to-`ProductCode` mappings
//! under registry keys whose names are NOT the canonical-form GUID
//! but a packed 32-hex-char form, derived as follows from a GUID
//! `{XXXXXXXX-YYYY-ZZZZ-AABB-CCDDEEFFGGHH}`:
//!
//! 1. **Segment 1** (8 hex chars / 4 bytes): char-reverse the segment.
//!    Equivalent to nibble-swapping each byte AND byte-reversing the
//!    segment. Mirrors `Data1` being a little-endian 32-bit integer.
//! 2. **Segment 2** (4 chars / 2 bytes): char-reverse. Mirrors
//!    `Data2` as LE u16.
//! 3. **Segment 3** (4 chars / 2 bytes): char-reverse. Mirrors
//!    `Data3` as LE u16.
//! 4. **Segment 4** (4 chars / 2 bytes): nibble-swap each byte
//!    (each pair of hex chars `XY` → `YX`). No byte-reverse. Mirrors
//!    `Data4[0..2]` as byte array (network order).
//! 5. **Segment 5** (12 chars / 6 bytes): nibble-swap each byte.
//!    Mirrors `Data4[2..8]`.
//!
//! Cross-references: `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\`
//! (per-machine) and `HKCU\Software\Microsoft\Installer\UpgradeCodes\`
//! (per-user). The value names under those keys are the packed-form
//! `ProductCode`s sharing that `UpgradeCode`.

use std::fmt;

/// Errors from [`pack_msi_guid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsiGuidError {
    /// After stripping braces and hyphens, the input was not exactly
    /// 32 hex characters long.
    BadLength(usize),
    /// A non-hex character appeared at the given (post-strip) index.
    NonHex(usize, char),
}

impl fmt::Display for MsiGuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsiGuidError::BadLength(n) => {
                write!(
                    f,
                    "expected 32 hex digits after stripping braces and hyphens, got {n}"
                )
            }
            MsiGuidError::NonHex(i, c) => {
                write!(f, "non-hex character at index {i}: {c:?}")
            }
        }
    }
}

impl std::error::Error for MsiGuidError {}

/// Pack a GUID (with or without braces, any case) into the 32-hex
/// form Windows Installer stores under `…\Installer\UpgradeCodes\`.
/// Output is always uppercase to match the convention SCM uses.
pub fn pack_msi_guid(guid: &str) -> Result<String, MsiGuidError> {
    // Strip braces (at most one of each, at the ends) and all
    // hyphens. Preserve original-index information for error
    // reporting on non-hex chars.
    let trimmed = guid.trim();
    let trimmed = trimmed
        .strip_prefix('{')
        .unwrap_or(trimmed)
        .strip_suffix('}')
        .unwrap_or(trimmed);

    let mut hex = String::with_capacity(32);
    for ch in trimmed.chars() {
        if ch == '-' {
            continue;
        }
        let idx = hex.len();
        if !ch.is_ascii_hexdigit() {
            return Err(MsiGuidError::NonHex(idx, ch));
        }
        hex.push(ch.to_ascii_uppercase());
    }

    if hex.len() != 32 {
        return Err(MsiGuidError::BadLength(hex.len()));
    }

    let bytes = hex.as_bytes();
    let mut out = String::with_capacity(32);

    // Segment 1: chars 0..8 reversed.
    for i in (0..8).rev() {
        out.push(bytes[i] as char);
    }
    // Segment 2: chars 8..12 reversed.
    for i in (8..12).rev() {
        out.push(bytes[i] as char);
    }
    // Segment 3: chars 12..16 reversed.
    for i in (12..16).rev() {
        out.push(bytes[i] as char);
    }
    // Segment 4: chars 16..20, nibble-swap each byte
    // (each 2-char pair becomes [hi=lo, lo=hi]).
    for i in (16..20).step_by(2) {
        out.push(bytes[i + 1] as char);
        out.push(bytes[i] as char);
    }
    // Segment 5: chars 20..32, nibble-swap each byte.
    for i in (20..32).step_by(2) {
        out.push(bytes[i + 1] as char);
        out.push(bytes[i] as char);
    }

    Ok(out)
}

/// Unpack a 32-hex packed-form GUID back to canonical
/// `{XXXXXXXX-YYYY-ZZZZ-AABB-CCDDEEFFGGHH}` brace form.
///
/// Both pack and unpack are involutions (char-reverse + nibble-swap
/// are their own inverses), so the inner transformation is identical.
/// This function just adds the braces and hyphens back.
pub fn unpack_msi_guid(packed: &str) -> Result<String, MsiGuidError> {
    let trimmed = packed.trim();
    let mut hex = String::with_capacity(32);
    for ch in trimmed.chars() {
        let idx = hex.len();
        if !ch.is_ascii_hexdigit() {
            return Err(MsiGuidError::NonHex(idx, ch));
        }
        hex.push(ch.to_ascii_uppercase());
    }
    if hex.len() != 32 {
        return Err(MsiGuidError::BadLength(hex.len()));
    }
    let bytes = hex.as_bytes();
    let mut out = String::with_capacity(38);
    out.push('{');
    for i in (0..8).rev() {
        out.push(bytes[i] as char);
    }
    out.push('-');
    for i in (8..12).rev() {
        out.push(bytes[i] as char);
    }
    out.push('-');
    for i in (12..16).rev() {
        out.push(bytes[i] as char);
    }
    out.push('-');
    for i in (16..20).step_by(2) {
        out.push(bytes[i + 1] as char);
        out.push(bytes[i] as char);
    }
    out.push('-');
    for i in (20..32).step_by(2) {
        out.push(bytes[i + 1] as char);
        out.push(bytes[i] as char);
    }
    out.push('}');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_detect::{PERMACHINE_UPGRADE_CODE, PERUSER_UPGRADE_CODE};

    #[test]
    fn all_zeros_round_trips_to_zeros() {
        let packed = pack_msi_guid("{00000000-0000-0000-0000-000000000000}").unwrap();
        assert_eq!(packed, "00000000000000000000000000000000");
    }

    #[test]
    fn all_fs_round_trips_to_fs() {
        let packed = pack_msi_guid("{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}").unwrap();
        assert_eq!(packed, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    }

    #[test]
    fn synthetic_ordered_guid_packs_per_algorithm() {
        // {12345678-1234-5678-9ABC-DEF012345678}
        // Seg1 char-reversed:  87654321
        // Seg2 char-reversed:  4321
        // Seg3 char-reversed:  8765
        // Seg4 nibble-swap:    9A→A9, BC→CB → A9CB
        // Seg5 nibble-swap:    DE→ED, F0→0F, 12→21, 34→43, 56→65, 78→87
        //                      → ED0F21436587
        assert_eq!(
            pack_msi_guid("{12345678-1234-5678-9ABC-DEF012345678}").unwrap(),
            "8765432143218765A9CBED0F21436587"
        );
    }

    #[test]
    fn peruser_upgrade_code_packs() {
        // 1F2D7B1C-8B2F-4D2E-B1A3-6B1E2C7E4D91
        // Seg1 chars: 1F2D7B1C → reverse → C1B7D2F1
        // Seg2 chars: 8B2F     → reverse → F2B8
        // Seg3 chars: 4D2E     → reverse → E2D4
        // Seg4 chars: B1A3 → nibble-swap each byte: B1→1B, A3→3A → 1B3A
        // Seg5 chars: 6B1E2C7E4D91 → nibble-swap: B6E1C2E7D419
        assert_eq!(
            pack_msi_guid(PERUSER_UPGRADE_CODE).unwrap(),
            "C1B7D2F1F2B8E2D41B3AB6E1C2E7D419"
        );
    }

    #[test]
    fn permachine_upgrade_code_packs() {
        // 2A8E9C2D-3F1A-5E3F-C2B4-7C2F3D8F5E02
        // Seg1: 2A8E9C2D → reverse → D2C9E8A2
        // Seg2: 3F1A     → reverse → A1F3
        // Seg3: 5E3F     → reverse → F3E5
        // Seg4: C2B4 → nibble-swap: 2C, 4B → 2C4B
        // Seg5: 7C2F3D8F5E02 → nibble-swap: C7F2D3F8E520
        assert_eq!(
            pack_msi_guid(PERMACHINE_UPGRADE_CODE).unwrap(),
            "D2C9E8A2A1F3F3E52C4BC7F2D3F8E520"
        );
    }

    #[test]
    fn lowercase_input_normalised_to_uppercase() {
        let packed = pack_msi_guid("{1f2d7b1c-8b2f-4d2e-b1a3-6b1e2c7e4d91}").unwrap();
        assert_eq!(packed, "C1B7D2F1F2B8E2D41B3AB6E1C2E7D419");
    }

    #[test]
    fn mixed_case_input_normalised() {
        let packed = pack_msi_guid("1F2d7B1c-8b2F-4D2e-B1a3-6B1e2C7E4d91").unwrap();
        assert_eq!(packed, "C1B7D2F1F2B8E2D41B3AB6E1C2E7D419");
    }

    #[test]
    fn no_braces_accepted() {
        let packed = pack_msi_guid("12345678-1234-5678-9ABC-DEF012345678").unwrap();
        assert_eq!(packed, "8765432143218765A9CBED0F21436587");
    }

    #[test]
    fn rejects_too_short() {
        let err = pack_msi_guid("{12345678-1234-5678-9ABC-DEF01234567}").unwrap_err();
        assert!(matches!(err, MsiGuidError::BadLength(31)));
    }

    #[test]
    fn rejects_too_long() {
        let err = pack_msi_guid("{12345678-1234-5678-9ABC-DEF0123456789}").unwrap_err();
        assert!(matches!(err, MsiGuidError::BadLength(33)));
    }

    #[test]
    fn rejects_non_hex() {
        let err = pack_msi_guid("{12345678-1234-5678-9ABZ-DEF012345678}").unwrap_err();
        match err {
            MsiGuidError::NonHex(_, ch) => assert_eq!(ch, 'Z'),
            other => panic!("expected NonHex, got {other:?}"),
        }
    }

    #[test]
    fn pack_then_unpack_round_trips() {
        for input in [PERUSER_UPGRADE_CODE, PERMACHINE_UPGRADE_CODE] {
            let packed = pack_msi_guid(input).unwrap();
            let unpacked = unpack_msi_guid(&packed).unwrap();
            // Compare case-insensitively because input may be mixed case
            // but unpack always produces uppercase.
            assert_eq!(
                unpacked.to_ascii_uppercase(),
                format!("{{{}}}", input.to_ascii_uppercase())
            );
        }
    }

    #[test]
    fn unpack_then_pack_round_trips() {
        let packed_in = "C1B7D2F1F2B8E2D41B3AB6E1C2E7D419";
        let canonical = unpack_msi_guid(packed_in).unwrap();
        let repacked = pack_msi_guid(&canonical).unwrap();
        assert_eq!(repacked, packed_in);
    }

    #[test]
    fn packed_output_is_always_32_hex_chars() {
        // Sanity property: any valid GUID input always packs to
        // exactly 32 uppercase hex chars.
        let inputs = [
            "{00000000-0000-0000-0000-000000000000}",
            "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
            "{12345678-1234-5678-9ABC-DEF012345678}",
            PERUSER_UPGRADE_CODE,
            PERMACHINE_UPGRADE_CODE,
        ];
        for input in inputs {
            let packed = pack_msi_guid(input).unwrap();
            assert_eq!(packed.len(), 32, "input {input}");
            assert!(
                packed
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && c.is_uppercase() || c.is_ascii_digit()),
                "input {input} produced {packed}"
            );
        }
    }
}
