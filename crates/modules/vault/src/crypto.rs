// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Envelope encryption (`docs/roomler-hive-design.md` §8.2).
//!
//! Every version of every field gets a data key of its own (a DEK, 32
//! random bytes). The value is sealed under it with XChaCha20-Poly1305, and
//! the DEK is wrapped to the key-encryption key (the KEK): an `age` X25519
//! identity, so a wrapped DEK is an ordinary `age` file and an `age-keygen`
//! file is the KEK.
//!
//! | Stored with a version | What it is |
//! |---|---|
//! | `ciphertext` | the value, XChaCha20-Poly1305 under the DEK |
//! | `nonce` | 24 random bytes, one per version |
//! | `dek_wrapped` | the DEK, `age`-encrypted to the KEK |
//! | `kek` | the KEK's recipient (`age1…`): public, so a rotation can tell which key unwraps a version |
//!
//! ⚠️ The seal is bound to the version's PLACE — organization, secret,
//! field and number — as associated data ([`Binding`]). Whoever can write
//! the database can move a ciphertext from one secret to another; with the
//! binding, the moved value fails to open instead of answering for the
//! secret it was moved into. The KEK is not in the binding: a rotation
//! re-wraps the DEKs and never touches a value.
//!
//! The KEK is the vault's own key. Nothing here derives from the JWT secret
//! or the DERP ticket key, and no KEK material is ever logged or answered:
//! every reason a KEK is refused is a fixed sentence.

use std::sync::Arc;

use bson::oid::ObjectId;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use meshharbor_config::VaultSettings;
use zeroize::Zeroizing;

/// The length of a data key.
pub const DEK_LEN: usize = 32;
/// The length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;

/// Where a version lives: what its seal is bound to.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub tenant_id: ObjectId,
    pub secret_id: ObjectId,
    /// A checked field name ([`crate::rrn::check_field`]): no NUL in it, so
    /// the encoding below cannot be read two ways.
    pub field: &'a str,
    pub n: i64,
}

impl Binding<'_> {
    /// The associated data: a version tag, then the place, NUL-separated.
    /// The ids are fixed-width hex and the field holds no NUL, so no two
    /// places encode alike.
    fn aad(&self) -> Vec<u8> {
        format!(
            "roomler-vault/v1\0{}\0{}\0{}\0{}",
            self.tenant_id.to_hex(),
            self.secret_id.to_hex(),
            self.field,
            self.n
        )
        .into_bytes()
    }
}

/// A sealed value, as a version stores it.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub dek_wrapped: Vec<u8>,
    /// The recipient the DEK was wrapped to.
    pub kek: String,
}

/// Why a seal failed. Neither is expected: both mean the cipher or `age`
/// refused a well-formed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    Encrypt,
    Wrap,
}

/// Why a stored version did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Its DEK was wrapped to a KEK this server does not hold.
    OtherKek,
    /// Its DEK names this server's KEK and does not open under it: the
    /// wrapped key was altered.
    DekUnreadable,
    /// The value failed authentication: altered, or moved from another
    /// place.
    Tampered,
}

impl OpenError {
    /// The word an answer and the audit use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OtherKek => "other_kek",
            Self::DekUnreadable => "dek_unreadable",
            Self::Tampered => "tampered",
        }
    }
}

/// The key-encryption key: one `age` X25519 identity.
pub struct Kek {
    identity: age::x25519::Identity,
    recipient: age::x25519::Recipient,
    /// `recipient` as `age1…`, kept with every version it wraps.
    recipient_str: String,
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The recipient is public; the identity never prints.
        f.debug_struct("Kek")
            .field("recipient", &self.recipient_str)
            .finish_non_exhaustive()
    }
}

impl Kek {
    /// One identity, as `age-keygen` writes it (`AGE-SECRET-KEY-1…`).
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let s = s.trim();
        if s.starts_with("age1") {
            return Err(
                "that is an age recipient (a public key): the KEK is the identity, \
                        AGE-SECRET-KEY-1…",
            );
        }
        let identity: age::x25519::Identity = s
            .parse()
            .map_err(|_| "not an age X25519 identity (AGE-SECRET-KEY-1…)")?;
        let recipient = identity.to_public();
        Ok(Self {
            recipient_str: recipient.to_string(),
            identity,
            recipient,
        })
    }

    /// The text of an identity file, or of a setting holding one: blank
    /// lines and `#` comments skipped, exactly one identity left.
    pub fn parse_file_text(text: &str) -> Result<Self, &'static str> {
        let mut keys = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let Some(first) = keys.next() else {
            return Err("holds no age identity");
        };
        if keys.next().is_some() {
            return Err(
                "holds more than one line besides comments: the vault takes ONE \
                        identity (a KEK rotation is not built yet)",
            );
        }
        Self::parse(first)
    }

    /// The recipient every new version's DEK is wrapped to.
    pub fn recipient(&self) -> &str {
        &self.recipient_str
    }

    /// Seal `value` for the version at `at`, under a fresh DEK.
    pub fn seal(&self, at: &Binding<'_>, value: &[u8]) -> Result<Sealed, SealError> {
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());
        let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_slice()));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = at.aad();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Encrypt)?;
        let dek_wrapped =
            age::encrypt(&self.recipient, dek.as_slice()).map_err(|_| SealError::Wrap)?;
        Ok(Sealed {
            ciphertext,
            nonce: nonce.to_vec(),
            dek_wrapped,
            kek: self.recipient_str.clone(),
        })
    }

    /// Open a stored version at `at`. The plaintext is zeroed when the
    /// caller drops it.
    pub fn open(
        &self,
        at: &Binding<'_>,
        ciphertext: &[u8],
        nonce: &[u8],
        dek_wrapped: &[u8],
        kek: &str,
    ) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        if kek != self.recipient_str {
            return Err(OpenError::OtherKek);
        }
        let dek = Zeroizing::new(
            age::decrypt(&self.identity, dek_wrapped).map_err(|_| OpenError::DekUnreadable)?,
        );
        if dek.len() != DEK_LEN {
            return Err(OpenError::DekUnreadable);
        }
        if nonce.len() != NONCE_LEN {
            return Err(OpenError::Tampered);
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_slice()));
        let aad = at.aad();
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| OpenError::Tampered)
    }
}

/// The KEK as the settings give it. Never a boot refusal: without a usable
/// KEK the vault still mounts, its metadata reads and writes work, and
/// every route that needs the key answers 503 saying why.
#[derive(Debug, Clone)]
pub enum KekState {
    Ready(Arc<Kek>),
    /// Neither `vault.kek` nor `vault.kek_file` is set.
    Missing,
    /// Set, and unusable — a fixed sentence, never the key.
    Invalid(&'static str),
}

impl KekState {
    /// `vault.kek` (the identity, or an identity file's text) or
    /// `vault.kek_file` (its path); both set is refused rather than
    /// guessed, since the two may disagree.
    pub fn load(settings: &VaultSettings) -> Self {
        let inline = settings.kek.trim();
        let path = settings.kek_file.trim();
        match (inline.is_empty(), path.is_empty()) {
            (true, true) => Self::Missing,
            (false, false) => Self::Invalid("both vault.kek and vault.kek_file are set"),
            (false, true) => match Kek::parse_file_text(inline) {
                Ok(k) => Self::Ready(Arc::new(k)),
                Err(why) => Self::Invalid(why),
            },
            (true, false) => match std::fs::read_to_string(path) {
                Ok(text) => match Kek::parse_file_text(&text) {
                    Ok(k) => Self::Ready(Arc::new(k)),
                    Err(why) => Self::Invalid(why),
                },
                Err(_) => Self::Invalid("vault.kek_file cannot be read"),
            },
        }
    }

    /// The KEK, when there is a usable one.
    pub fn ready(&self) -> Option<&Arc<Kek>> {
        match self {
            Self::Ready(k) => Some(k),
            _ => None,
        }
    }

    /// Said once at boot: whether the vault can seal, and which recipient it
    /// wraps to. Never the identity.
    pub fn log(&self) {
        match self {
            Self::Ready(k) => {
                tracing::info!(recipient = k.recipient(), "vault: KEK loaded")
            }
            Self::Missing => tracing::warn!(
                "vault: no KEK (vault.kek / vault.kek_file) — secrets can be declared, \
                 and every route that needs the key answers 503"
            ),
            Self::Invalid(why) => tracing::error!(
                reason = why,
                "vault: the KEK is unusable — every route that needs it answers 503"
            ),
        }
    }
}

/// P3-3b — why a value could not be sealed to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSealError {
    /// The key is not 32 bytes in canonical standard base64.
    BadKey,
    /// The sealed box was refused (not expected for a well-formed key).
    Seal,
}

/// P3-3b — `value` as a libsodium sealed box (`crypto_box_seal`: an
/// ephemeral X25519 key, XSalsa20-Poly1305) for the device key `key_b64`
/// (`agents.vault_key`), which only the daemon holding its secret half
/// opens. A fresh ephemeral key per box, so two leases of one value never
/// look alike on the wire.
pub fn seal_for_device(key_b64: &str, value: &[u8]) -> Result<Vec<u8>, DeviceSealError> {
    use base64::Engine;
    if !meshharbor_remote_control::signaling::vault_key_is_well_formed(key_b64) {
        return Err(DeviceSealError::BadKey);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| DeviceSealError::BadKey)?;
    let key = crypto_box::PublicKey::from_slice(&bytes).map_err(|_| DeviceSealError::BadKey)?;
    key.seal(&mut crypto_box::aead::OsRng, value)
        .map_err(|_| DeviceSealError::Seal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn fresh_identity() -> String {
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret()
            .to_string()
    }

    fn kek() -> Kek {
        Kek::parse(&fresh_identity()).unwrap()
    }

    fn at(field: &str, n: i64) -> (ObjectId, ObjectId, String, i64) {
        (ObjectId::new(), ObjectId::new(), field.to_string(), n)
    }

    fn binding(p: &(ObjectId, ObjectId, String, i64)) -> Binding<'_> {
        Binding {
            tenant_id: p.0,
            secret_id: p.1,
            field: &p.2,
            n: p.3,
        }
    }

    fn open(k: &Kek, b: &Binding<'_>, s: &Sealed) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        k.open(b, &s.ciphertext, &s.nonce, &s.dek_wrapped, &s.kek)
    }

    #[test]
    fn a_sealed_value_opens_at_its_place() {
        let k = kek();
        let p = at("password", 3);
        let s = k.seal(&binding(&p), b"hunter2").unwrap();
        assert_eq!(open(&k, &binding(&p), &s).unwrap().as_slice(), b"hunter2");
        assert_eq!(s.kek, k.recipient());
        assert!(s.kek.starts_with("age1"), "{}", s.kek);
        assert_eq!(s.nonce.len(), NONCE_LEN);
        // The plaintext is nowhere in what is stored.
        for stored in [&s.ciphertext, &s.dek_wrapped] {
            assert!(!stored.windows(7).any(|w| w == b"hunter2"));
        }
    }

    #[test]
    fn every_version_has_its_own_data_key_and_nonce() {
        let k = kek();
        let p = at("value", 1);
        let a = k.seal(&binding(&p), b"same").unwrap();
        let b = k.seal(&binding(&p), b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.dek_wrapped, b.dek_wrapped);
    }

    #[test]
    fn a_value_moved_to_another_place_does_not_open() {
        let k = kek();
        let p = at("password", 2);
        let s = k.seal(&binding(&p), b"hunter2").unwrap();
        let moved = [
            (ObjectId::new(), p.1, p.2.clone(), p.3), // another organization
            (p.0, ObjectId::new(), p.2.clone(), p.3), // another secret
            (p.0, p.1, "username".to_string(), p.3),  // another field
            (p.0, p.1, p.2.clone(), p.3 + 1),         // another version
        ];
        for m in &moved {
            assert_eq!(
                open(&k, &binding(m), &s).unwrap_err(),
                OpenError::Tampered,
                "{m:?}"
            );
        }
    }

    #[test]
    fn an_altered_version_does_not_open() {
        let k = kek();
        let p = at("value", 1);
        let s = k.seal(&binding(&p), b"hunter2").unwrap();

        let mut ct = s.clone();
        ct.ciphertext[0] ^= 1;
        assert_eq!(
            open(&k, &binding(&p), &ct).unwrap_err(),
            OpenError::Tampered
        );

        let mut nonce = s.clone();
        nonce.nonce[0] ^= 1;
        assert_eq!(
            open(&k, &binding(&p), &nonce).unwrap_err(),
            OpenError::Tampered
        );
        nonce.nonce.pop();
        assert_eq!(
            open(&k, &binding(&p), &nonce).unwrap_err(),
            OpenError::Tampered
        );

        let mut dek = s.clone();
        let last = dek.dek_wrapped.len() - 1;
        dek.dek_wrapped[last] ^= 1;
        assert_eq!(
            open(&k, &binding(&p), &dek).unwrap_err(),
            OpenError::DekUnreadable
        );
    }

    #[test]
    fn two_versions_swapped_whole_do_not_open() {
        // Ciphertext, nonce and wrapped key moved together, as one row's
        // payload into another row: the binding still refuses it.
        let k = kek();
        let one = at("value", 1);
        let two = (one.0, one.1, one.2.clone(), 2);
        let s1 = k.seal(&binding(&one), b"first").unwrap();
        assert_eq!(
            open(&k, &binding(&two), &s1).unwrap_err(),
            OpenError::Tampered
        );
    }

    #[test]
    fn another_kek_opens_nothing() {
        let k = kek();
        let other = kek();
        let p = at("value", 1);
        let s = k.seal(&binding(&p), b"hunter2").unwrap();
        // Named as another key's: refused before anything is tried.
        assert_eq!(
            open(&other, &binding(&p), &s).unwrap_err(),
            OpenError::OtherKek
        );
        // Re-labelled as the other key's: its identity still opens nothing.
        let relabelled = Sealed {
            kek: other.recipient().to_string(),
            ..s
        };
        assert_eq!(
            open(&other, &binding(&p), &relabelled).unwrap_err(),
            OpenError::DekUnreadable
        );
    }

    #[test]
    fn a_wrapped_data_key_is_an_ordinary_age_file() {
        // What makes `age -d -i kek.txt` a recovery path: the stock decrypt
        // of `dek_wrapped` is the data key, and it opens the value.
        let secret = fresh_identity();
        let k = Kek::parse(&secret).unwrap();
        let p = at("value", 1);
        let s = k.seal(&binding(&p), b"hunter2").unwrap();
        let identity: age::x25519::Identity = secret.parse().unwrap();
        let dek = age::decrypt(&identity, &s.dek_wrapped).unwrap();
        assert_eq!(dek.len(), DEK_LEN);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&dek));
        let value = cipher
            .decrypt(
                XNonce::from_slice(&s.nonce),
                Payload {
                    msg: &s.ciphertext,
                    aad: &binding(&p).aad(),
                },
            )
            .unwrap();
        assert_eq!(value, b"hunter2");
    }

    #[test]
    fn the_binding_encodes_each_place_once() {
        let t = ObjectId::parse_str("65f0000000000000000000a1").unwrap();
        let s = ObjectId::parse_str("65f0000000000000000000b2").unwrap();
        let b = Binding {
            tenant_id: t,
            secret_id: s,
            field: "value",
            n: 12,
        };
        assert_eq!(
            b.aad(),
            b"roomler-vault/v1\x0065f0000000000000000000a1\x0065f0000000000000000000b2\x00value\x0012"
        );
    }

    #[test]
    fn an_identity_file_holds_exactly_one_identity() {
        let secret = fresh_identity();
        let file =
            format!("# created: 2026-10-17T00:00:00Z\n# public key: age1example\n{secret}\n\n");
        let k = Kek::parse_file_text(&file).unwrap();
        assert_eq!(k.recipient(), Kek::parse(&secret).unwrap().recipient());

        assert_eq!(
            Kek::parse_file_text("# only a comment\n\n").unwrap_err(),
            "holds no age identity"
        );
        let two = format!("{secret}\n{}\n", fresh_identity());
        assert!(
            Kek::parse_file_text(&two)
                .unwrap_err()
                .contains("ONE identity")
        );
    }

    #[test]
    fn what_is_not_an_identity_is_refused_without_echoing_it() {
        let recipient = kek().recipient().to_string();
        let why = Kek::parse(&recipient).unwrap_err();
        assert!(why.contains("recipient"), "{why}");
        assert!(!why.contains(&recipient));

        let garbage = "AGE-SECRET-KEY-1NOTAKEY";
        let why = Kek::parse(garbage).unwrap_err();
        assert!(!why.contains(garbage), "{why}");
    }

    #[test]
    fn the_settings_decide_the_kek_state() {
        let secret = fresh_identity();
        let s = |kek: &str, kek_file: &str| VaultSettings {
            kek: kek.into(),
            kek_file: kek_file.into(),
            ..Default::default()
        };
        assert!(matches!(KekState::load(&s("", "")), KekState::Missing));
        assert!(KekState::load(&s(&secret, "")).ready().is_some());
        assert!(matches!(
            KekState::load(&s(&secret, "/etc/roomler/kek.txt")),
            KekState::Invalid(_)
        ));
        assert!(matches!(
            KekState::load(&s("", "/nonexistent/roomler-vault-kek.txt")),
            KekState::Invalid("vault.kek_file cannot be read")
        ));

        let dir = std::env::temp_dir().join(format!("roomler-vault-kek-{}", ObjectId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("kek.txt");
        std::fs::write(&file, format!("# public key: x\n{secret}\n")).unwrap();
        let state = KekState::load(&s("", file.to_str().unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            state.ready().unwrap().recipient(),
            Kek::parse(&secret).unwrap().recipient()
        );
    }

    #[test]
    fn a_kek_never_prints_its_identity() {
        let secret = fresh_identity();
        let k = Kek::parse(&secret).unwrap();
        let shown = format!(
            "{k:?} {:?}",
            KekState::Ready(Arc::new(Kek::parse(&secret).unwrap()))
        );
        assert!(!shown.contains(&secret), "{shown}");
        assert!(!shown.to_uppercase().contains("AGE-SECRET-KEY"), "{shown}");
        assert!(shown.contains(k.recipient()), "{shown}");
    }

    /// P3-3b — a value sealed for a device opens with that device's secret
    /// half and no other; every box is new; a key that is not one is
    /// refused before anything is sealed. The device's key is made here, as
    /// the daemon makes it (`roomlerd`'s `vault.rs`).
    #[test]
    fn a_value_sealed_for_a_device_opens_only_there() {
        use base64::Engine;
        let rng = &mut crypto_box::aead::OsRng;
        let device = crypto_box::SecretKey::generate(rng);
        let published =
            base64::engine::general_purpose::STANDARD.encode(device.public_key().as_bytes());

        let a = seal_for_device(&published, b"leased-canary").unwrap();
        let b = seal_for_device(&published, b"leased-canary").unwrap();
        assert_ne!(a, b, "a fresh ephemeral key per box");
        assert_eq!(device.unseal(&a).unwrap(), b"leased-canary");
        assert_eq!(device.unseal(&b).unwrap(), b"leased-canary");

        let other = crypto_box::SecretKey::generate(rng);
        assert!(other.unseal(&a).is_err(), "another device opens nothing");

        for bad in [
            String::new(),
            "not-a-key".to_string(),
            base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            // Bytes whose encoding needs `+` and `/`: in the URL-safe
            // alphabet they are `-` and `_`, never a standard spelling.
            base64::engine::general_purpose::URL_SAFE.encode([0xfbu8; 32]),
        ] {
            assert_eq!(
                seal_for_device(&bad, b"x"),
                Err(DeviceSealError::BadKey),
                "{bad:?}"
            );
        }
    }
}
