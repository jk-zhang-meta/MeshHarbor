// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Pinned-key verification of the release `.asc` sidecars.
//!
//! Windows updates are anchored by Authenticode + a signer-name check
//! (`code_signature::verify_publisher`). The `.deb` and `.pkg` had no
//! equivalent: their SHA256 arrives in the SAME manifest, from the SAME
//! origin, as the download URL — a transport check, not a tamper anchor —
//! so anything able to serve the manifest could serve matching "proof".
//! Every release since rc.458 ships detached GPG signatures, but a key
//! fetched from the release is that same-channel failure again. This
//! module is the missing half: the release signing key is **compiled into
//! the binary**, and the updater refuses a Linux/macOS artifact whose
//! `.asc` does not verify against it.
//!
//! It lives in `tunnel-core` since FR-97 P6b, so the tunnel CLI's
//! `meshharbor self-update` refuses its own artifacts the same way, on every
//! OS. The agent re-exports it as `meshharbord::pgp_verify`.
//!
//! Scope is deliberately narrow — this is NOT an OpenPGP implementation.
//! It verifies exactly the shape our CI emits (`gpg --armor --detach-sign`
//! with an ed25519 key): one v4 signature packet, class 0x00 (binary
//! document), algorithm 22 (EdDSA), SHA-256 or SHA-512. Anything else is
//! refused with a message naming what was found. The actual cryptography
//! is `ring`'s ed25519 (already in this workspace's graph — the tunnel
//! stack is ring-only by invariant) plus `sha2`; the code here only
//! parses RFC 4880 framing and builds the v4 hash trailer.
//!
//! ⚠️ Key rotation therefore requires a RELEASE (the pin is a constant).
//! That is the point of pinning, and the same property Windows has: the
//! `EXPECTED_PUBLISHER` name is compiled in too. Rotate by shipping a
//! release signed by BOTH keys' overlap window: publish releases signed by
//! the old key that CONTAIN the new pin, then switch CI's signing key once
//! the fleet has updated past the pivot.

use anyhow::{Context, Result, bail};

/// The ed25519 public point of the release SIGNING subkey, pinned.
///
/// Key: `MeshHarbor Release Signing <releases@roomler.ai>`
/// Subkey fingerprint: `5DB8221F546288DE780C10D3A2C53E5FE6FA485A` (key id
/// `A2C53E5FE6FA485A`), certified by the offline primary
/// `D654B016256FD92A81634A0E2AD1E9F025973A7F`.
///
/// The canonical armored key lives at
/// `scripts/signing/gpg/meshharbor-release-pubkey.asc` and is republished as
/// a release asset; `pinned_key_matches_committed_pubkey` re-derives this
/// constant from that file so the two can never drift silently.
pub const PINNED_RELEASE_SIGNING_KEY: [u8; 32] = [
    0xc2, 0x7e, 0x10, 0x54, 0xd2, 0x42, 0x57, 0xdc, 0x8d, 0x66, 0x00, 0x50, 0x15, 0xf0, 0xdb, 0x31,
    0x9b, 0x7a, 0xf4, 0x47, 0xa0, 0x38, 0x77, 0x3c, 0xc0, 0x11, 0xff, 0xfa, 0x8b, 0xa6, 0xd9, 0xfa,
];

/// Verify `artifact` against the armored detached signature `asc`, using
/// the pinned release key. The error is the refusal reason, ready for the
/// updater's fail-closed path.
pub fn verify_release_artifact(artifact: &[u8], asc: &str) -> Result<()> {
    verify_detached(artifact, asc, &PINNED_RELEASE_SIGNING_KEY)
}

/// Strip the ASCII armor (RFC 4880 §6.2) and return the binary payload.
/// The CRC-24 line is verified when present — it catches truncation and
/// copy-paste damage with a better message than "bad signature".
fn dearmor(asc: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let mut in_body = false;
    let mut seen_begin = false;
    let mut b64 = String::new();
    let mut crc_line: Option<String> = None;
    for line in asc.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("-----BEGIN PGP ") {
            seen_begin = true;
            continue;
        }
        if line.starts_with("-----END PGP ") {
            break;
        }
        if !seen_begin {
            continue;
        }
        if !in_body {
            // Armor headers run until the first empty line. A body with no
            // headers starts immediately, so a base64-looking line before
            // any empty line is the body too.
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if line.contains(": ") {
                continue; // Version:, Comment:, …
            }
            in_body = true;
        }
        if let Some(crc) = line.strip_prefix('=') {
            crc_line = Some(crc.to_string());
            continue;
        }
        b64.push_str(line);
    }
    if !seen_begin {
        bail!("not an ASCII-armored PGP block (no BEGIN line)");
    }
    let data = STANDARD
        .decode(b64.as_bytes())
        .context("armor body is not valid base64")?;
    if let Some(crc) = crc_line {
        let want = STANDARD
            .decode(crc.as_bytes())
            .context("armor CRC line is not valid base64")?;
        let got = crc24(&data);
        if want.len() != 3 || want != got {
            bail!("armor CRC-24 mismatch — the signature file is corrupt or truncated");
        }
    }
    Ok(data)
}

/// CRC-24 as specified in RFC 4880 §6.1.
fn crc24(data: &[u8]) -> Vec<u8> {
    const INIT: u32 = 0x00B7_04CE;
    const POLY: u32 = 0x0186_4CFB;
    let mut crc = INIT;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= POLY;
            }
        }
    }
    vec![(crc >> 16) as u8, (crc >> 8) as u8, crc as u8]
}

/// The pieces of a v4 signature packet the verification needs.
struct SigPacket {
    hash_algo: u8,
    /// The hashed-subpackets region VERBATIM (its bytes are part of the
    /// signed data — reserialising would break the signature).
    hashed_subpackets: Vec<u8>,
    /// High 16 bits of the expected digest — a cheap pre-check that turns
    /// "bad signature" into "wrong digest" when the artifact was swapped.
    left16: [u8; 2],
    /// The ed25519 signature, R ‖ S, each MPI left-padded to 32 bytes.
    signature: [u8; 64],
}

/// Parse the single signature packet our CI emits. Multi-packet input is
/// refused: a detached signature file with trailing packets is not ours.
fn parse_signature_packet(data: &[u8]) -> Result<SigPacket> {
    let mut r = Reader(data);

    // Packet header. gpg emits old-format tag 2 here; accept old format
    // with 1/2/4-byte lengths and new format with 1/2/5-byte lengths.
    let ctb = r.u8().context("empty signature data")?;
    if ctb & 0x80 == 0 {
        bail!("not an OpenPGP packet (bad CTB 0x{ctb:02x})");
    }
    let (tag, body_len) = if ctb & 0x40 == 0 {
        // Old format: tag in bits 5..2, length type in bits 1..0.
        let tag = (ctb >> 2) & 0x0f;
        let len = match ctb & 0x03 {
            0 => r.u8()? as usize,
            1 => r.u16()? as usize,
            2 => r.u32()? as usize,
            _ => bail!("indeterminate-length packet is not a detached signature"),
        };
        (tag, len)
    } else {
        // New format: tag in bits 5..0, then a variable-length length.
        let tag = ctb & 0x3f;
        let first = r.u8()?;
        let len = match first {
            0..=191 => first as usize,
            192..=223 => {
                let second = r.u8()?;
                (((first as usize) - 192) << 8) + second as usize + 192
            }
            255 => r.u32()? as usize,
            _ => bail!("partial-length packet is not a detached signature"),
        };
        (tag, len)
    };
    if tag != 2 {
        bail!("expected a signature packet (tag 2), found tag {tag}");
    }
    let body = r.take(body_len).context("signature packet truncated")?;
    if !r.0.is_empty() {
        bail!(
            "trailing data after the signature packet ({} bytes) — not a plain detached signature",
            r.0.len()
        );
    }
    let mut b = Reader(body);

    let version = b.u8()?;
    if version != 4 {
        bail!("unsupported signature version {version} (our releases sign v4)");
    }
    let sig_class = b.u8()?;
    if sig_class != 0x00 {
        bail!("unsupported signature class 0x{sig_class:02x} (expected 0x00, binary document)");
    }
    let pk_algo = b.u8()?;
    if pk_algo != 22 {
        bail!("unsupported public-key algorithm {pk_algo} (expected 22, EdDSA/ed25519)");
    }
    let hash_algo = b.u8()?;
    if hash_algo != 8 && hash_algo != 10 {
        bail!("unsupported hash algorithm {hash_algo} (expected SHA-256 or SHA-512)");
    }
    let hashed_len = b.u16()? as usize;
    let hashed_subpackets = b
        .take(hashed_len)
        .context("hashed subpackets truncated")?
        .to_vec();
    let unhashed_len = b.u16()? as usize;
    let _ = b
        .take(unhashed_len)
        .context("unhashed subpackets truncated")?;
    let left16 = [b.u8()?, b.u8()?];

    // Two MPIs (R, S), each ≤ 32 bytes for ed25519, left-padded to 32.
    let mut signature = [0u8; 64];
    for half in 0..2 {
        let bits = b.u16()? as usize;
        let bytes = bits.div_ceil(8);
        if bytes > 32 {
            bail!("signature MPI is {bytes} bytes — not an ed25519 scalar");
        }
        let mpi = b.take(bytes).context("signature MPI truncated")?;
        signature[half * 32 + (32 - bytes)..half * 32 + 32].copy_from_slice(mpi);
    }

    Ok(SigPacket {
        hash_algo,
        hashed_subpackets,
        left16,
        signature,
    })
}

/// Verify `artifact` against an armored detached signature with an explicit
/// key — the pin-free core, so tests can use a throwaway fixture key.
fn verify_detached(artifact: &[u8], asc: &str, pubkey: &[u8; 32]) -> Result<()> {
    let packet = dearmor(asc)?;
    let sig = parse_signature_packet(&packet)?;

    // RFC 4880 §5.2.4 — the digest covers the artifact, then the signature
    // packet's own v4 prefix through the hashed subpackets, then a final
    // trailer of 0x04 0xFF and the byte count of that prefix.
    let hashed_len = sig.hashed_subpackets.len();
    let mut trailer = Vec::with_capacity(6 + hashed_len + 6);
    trailer.push(0x04); // version
    trailer.push(0x00); // class: binary document
    trailer.push(22); // pk algo: EdDSA
    trailer.push(sig.hash_algo);
    trailer.extend_from_slice(&(hashed_len as u16).to_be_bytes());
    trailer.extend_from_slice(&sig.hashed_subpackets);
    let prefix_len = trailer.len() as u32;
    trailer.extend_from_slice(&[0x04, 0xFF]);
    trailer.extend_from_slice(&prefix_len.to_be_bytes());

    let digest: Vec<u8> = match sig.hash_algo {
        8 => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(artifact);
            h.update(&trailer);
            h.finalize().to_vec()
        }
        10 => {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::new();
            h.update(artifact);
            h.update(&trailer);
            h.finalize().to_vec()
        }
        other => bail!("unsupported hash algorithm {other}"),
    };

    if digest[..2] != sig.left16 {
        bail!(
            "digest prefix mismatch (expected {:02x}{:02x}, computed {:02x}{:02x}) — \
             the signature is for DIFFERENT bytes than this artifact",
            sig.left16[0],
            sig.left16[1],
            digest[0],
            digest[1]
        );
    }

    // OpenPGP EdDSA signs the HASH VALUE (the ed25519 message input is the
    // digest itself, not the raw artifact).
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey)
        .verify(&digest, &sig.signature)
        .map_err(|_| {
            anyhow::anyhow!(
                "ed25519 signature verification FAILED against the pinned release key — \
                 this artifact was not signed by MeshHarbor Release Signing"
            )
        })
}

/// Tiny cursor over a byte slice; every read is bounds-checked so a
/// truncated or hostile `.asc` degrades to an error, never a panic.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self.0.split_first().context("unexpected end of packet")?;
        self.0 = rest;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!(
                "unexpected end of packet (wanted {n} bytes, have {})",
                self.0.len()
            );
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway ed25519 key + a message it signed, generated once with
    /// gpg 2.4.8 in an isolated GNUPGHOME (2026-08-26). The key exists
    /// nowhere else; these bytes are test vectors, not secrets.
    const FIXTURE_MSG: &[u8] = b"meshharbor pgp_verify fixture message v1\n";
    const FIXTURE_KEY: [u8; 32] = [
        0xeb, 0x45, 0x29, 0xff, 0x24, 0xe9, 0xf6, 0xb7, 0x21, 0x20, 0x7a, 0x34, 0x08, 0x01, 0xa2,
        0x6b, 0xf7, 0x0f, 0xe4, 0x2d, 0xc4, 0xdf, 0x3e, 0xd3, 0xc3, 0x19, 0x5d, 0xc1, 0xcc, 0xbe,
        0xce, 0x4e,
    ];
    const FIXTURE_ASC: &str = "-----BEGIN PGP SIGNATURE-----\n\n\
iHUEABYKAB0WIQR+gSR1LCoEVCK5rt+0sI1x14/rFgUCao7qAAAKCRC0sI1x14/r\n\
Fib9AQC7rcJIbBRX9OLFsijHeAtLA78lEFbZECl0rBM3Ui3ECAEAzAZhKfTmb0nJ\n\
hV/0cAHGFizJ3Gl+qz5YZ4IEbnnXtgs=\n\
=wJg0\n\
-----END PGP SIGNATURE-----\n";

    #[test]
    fn fixture_signature_verifies() {
        verify_detached(FIXTURE_MSG, FIXTURE_ASC, &FIXTURE_KEY)
            .expect("the fixture must verify against its own key");
    }

    #[test]
    fn tampered_artifact_is_refused() {
        let mut msg = FIXTURE_MSG.to_vec();
        msg[0] ^= 0x01;
        let err = verify_detached(&msg, FIXTURE_ASC, &FIXTURE_KEY)
            .expect_err("a flipped artifact byte must fail");
        // The left16 pre-check catches it with the sharper message.
        assert!(err.to_string().contains("digest prefix mismatch"), "{err}");
    }

    #[test]
    fn tampered_signature_is_refused() {
        // Flip one bit inside the base64 body (the CRC then also disagrees —
        // corruption must be caught no matter which check sees it first).
        let tampered = FIXTURE_ASC.replace("Fib9AQC7", "Fib9AQC8");
        verify_detached(FIXTURE_MSG, &tampered, &FIXTURE_KEY)
            .expect_err("a tampered signature body must fail");
    }

    #[test]
    fn wrong_key_is_refused() {
        let err = verify_detached(FIXTURE_MSG, FIXTURE_ASC, &PINNED_RELEASE_SIGNING_KEY)
            .expect_err("the fixture must NOT verify against the release key");
        assert!(err.to_string().contains("FAILED"), "{err}");
    }

    #[test]
    fn garbage_inputs_error_cleanly() {
        assert!(verify_detached(b"x", "not armor at all", &FIXTURE_KEY).is_err());
        assert!(
            verify_detached(
                b"x",
                "-----BEGIN PGP SIGNATURE-----\n\naGVsbG8=\n-----END PGP SIGNATURE-----\n",
                &FIXTURE_KEY
            )
            .is_err()
        );
        // Truncated mid-packet: valid armor, short body.
        assert!(
            verify_detached(
                b"x",
                "-----BEGIN PGP SIGNATURE-----\n\niHU=\n-----END PGP SIGNATURE-----\n",
                &FIXTURE_KEY
            )
            .is_err()
        );
    }

    /// The pin and the committed pubkey file must agree. This walks just
    /// enough of the key's packet framing (test-only — runtime never parses
    /// keys) to reach the SIGNING SUBKEY's ed25519 point: primary key
    /// packet (tag 6), user id (13), certification sig (2), subkey (14).
    #[test]
    fn pinned_key_matches_committed_pubkey() {
        let armored = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/signing/gpg/meshharbor-release-pubkey.asc"
        ));
        let data = dearmor(armored).expect("committed pubkey must dearmor");
        let mut r = Reader(&data);
        let mut subkey_point: Option<[u8; 32]> = None;
        while !r.0.is_empty() {
            let ctb = r.u8().unwrap();
            assert_ne!(ctb & 0x80, 0, "bad CTB in committed key");
            let (tag, len) = if ctb & 0x40 == 0 {
                let tag = (ctb >> 2) & 0x0f;
                let len = match ctb & 0x03 {
                    0 => r.u8().unwrap() as usize,
                    1 => r.u16().unwrap() as usize,
                    _ => panic!("unexpected length type in committed key"),
                };
                (tag, len)
            } else {
                let tag = ctb & 0x3f;
                let first = r.u8().unwrap();
                let len = match first {
                    0..=191 => first as usize,
                    192..=223 => (((first as usize) - 192) << 8) + r.u8().unwrap() as usize + 192,
                    255 => r.u32().unwrap() as usize,
                    _ => panic!("unexpected new-format length"),
                };
                (tag, len)
            };
            let body = r.take(len).unwrap();
            if tag == 14 {
                // v4, created(4), algo 22, oid-len, oid, MPI bitlen(2), 0x40, point.
                assert_eq!(body[0], 4, "subkey version");
                assert_eq!(body[5], 22, "subkey algo must be EdDSA");
                let oid_len = body[6] as usize;
                let mpi_start = 7 + oid_len + 2;
                assert_eq!(body[mpi_start], 0x40, "expected compressed-point prefix");
                let mut point = [0u8; 32];
                point.copy_from_slice(&body[mpi_start + 1..mpi_start + 33]);
                subkey_point = Some(point);
            }
        }
        let point = subkey_point.expect("committed key must contain a signing subkey");
        assert_eq!(
            point, PINNED_RELEASE_SIGNING_KEY,
            "the pinned constant no longer matches scripts/signing/gpg/meshharbor-release-pubkey.asc — \
             if the key was rotated on purpose, update the pin AND read the rotation note in the \
             module docs; a silent mismatch would freeze every Linux/macOS update"
        );
    }

    // RETIRED-NAME-ANCHOR(8): names a PUBLISHED release asset. Filenames are fixed by
    // what is already on GitHub Releases (FR-21 D6).
    /// Verifies a REAL published artifact against the real pin. `#[ignore]`
    /// because it needs release files this repo does not carry:
    ///
    /// ```text
    /// gh release download agent-v0.3.0-rc.475 --repo gjovanov/roomler-ai \
    ///   --pattern 'meshharbor-agent-*aarch64-apple-darwin.pkg*' --dir /tmp/rel
    /// MESHHARBOR_TEST_ARTIFACT=/tmp/rel/meshharbor-agent-0.3.0-rc.475-aarch64-apple-darwin.pkg \
    ///   cargo test -p meshharbor-tunnel-core --lib -- --ignored real_published_asc
    /// ```
    #[test]
    #[ignore = "needs a published release artifact; see the doc comment"]
    fn real_published_asc_verifies_and_a_flipped_byte_fails() {
        let artifact = std::env::var("MESHHARBOR_TEST_ARTIFACT")
            .expect("set MESHHARBOR_TEST_ARTIFACT to a downloaded release artifact");
        let bytes = std::fs::read(&artifact).expect("reading the artifact");
        let asc = std::fs::read_to_string(format!("{artifact}.asc"))
            .expect("reading the .asc next to the artifact");

        verify_release_artifact(&bytes, &asc)
            .expect("a genuine release artifact must verify against the pin");

        let mut flipped = bytes;
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x01;
        verify_release_artifact(&flipped, &asc)
            .expect_err("a flipped byte in the middle must be refused");
    }
}
