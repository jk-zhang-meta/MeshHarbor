// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-40 — the overlay-key mint behind `rc:agent.key_rotate`
//! (`docs/fr/FR-40-overlay-key-rotation.md`).
//!
//! Compiled in EVERY feature set, with the overlay split INSIDE: a build with
//! no overlay surface answers `None` (there is no key to rotate) instead of
//! making the caller carry a `#[cfg]` of its own. That is not tidiness — a
//! `#[cfg]`-split handler arm left `ConnectError::KeyRotated` unconstructed
//! in the default build, and rustc 1.95's deathness pass ICEd on the dead
//! variant there. One code path in the handler, the split here.
//!
//! The secret half never leaves this process: it goes from here to
//! `RemoteConfigServices::rotate_overlay_key` (disk) and into the signaling
//! loop's own config snapshot (memory). Only the public half is reported.

/// Mint a fresh WireGuard identity: `(secret_base64, public_base64)`.
/// `None` when this build has no overlay surface.
pub fn mint_wg_identity() -> Option<(String, String)> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let kp = tunnel_core::overlay::WgKeypair::generate();
        Some((kp.secret_base64(), kp.public_base64()))
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        None
    }
}

/// The public half of a persisted secret (for the report's `old_public_key`).
/// `None` when the secret does not parse — or in a build with no overlay.
pub fn wg_public_of(secret_base64: &str) -> Option<String> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        tunnel_core::overlay::WgKeypair::from_secret_base64(secret_base64)
            .map(|k| k.public_base64())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = secret_base64;
        None
    }
}

#[cfg(all(test, any(feature = "overlay-l3", feature = "overlay-netstack")))]
mod tests {
    use super::*;

    #[test]
    fn a_mint_is_fresh_and_its_public_half_derives_from_its_secret() {
        let (s1, p1) = mint_wg_identity().expect("overlay build mints");
        let (s2, p2) = mint_wg_identity().expect("overlay build mints");
        assert_ne!(s1, s2, "two mints are two identities");
        assert_ne!(p1, p2);
        assert_eq!(wg_public_of(&s1).as_deref(), Some(p1.as_str()));
        assert_eq!(wg_public_of(&s2).as_deref(), Some(p2.as_str()));
        assert_eq!(wg_public_of("not a key"), None);
        // 32 bytes, base64 — the shape the netmap distributes.
        assert_eq!(p1.len(), 44);
    }
}
