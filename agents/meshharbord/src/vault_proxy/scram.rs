// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5b — SCRAM-SHA-256 (RFC 5802, RFC 7677), the client's half: how
//! a vault proxy proves to an upstream that it holds a password without ever
//! sending it, and checks that the upstream held it too.
//!
//! ⚠️ The password never crosses the wire in any form a server could replay
//! elsewhere: the client sends a proof bound to this exchange's two nonces,
//! and trusts the session only once the server's own signature checks. A
//! server that cannot sign never had the password, and is refused.
//!
//! P3-5b-3 — channel binding (RFC 5802 §6, RFC 5929): inside TLS whose
//! certificate it verified, the exchange already runs with an upstream the
//! system trusts for that name. Binding (`p=tls-server-end-point`) adds the
//! certificate the client saw to what the proof covers, so a TLS terminator
//! the system also trusts (an inspection proxy whose CA is in the OS store)
//! cannot relay the exchange: the upstream compares the binding with its own
//! certificate and refuses. Where the upstream offers no `-PLUS`, the client
//! says it could have bound (`y`), and an upstream that does support binding
//! refuses that as a downgrade.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The most PBKDF2 iterations an upstream may ask for: past it, an exchange
/// is a way to make the daemon burn CPU. (Postgres and MongoDB default to
/// 4096 and 15000.)
pub(crate) const MAX_ITERATIONS: u32 = 10_000_000;

/// P3-5b-3 — how an exchange binds to the TLS channel it runs in. No
/// authorization identity in any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Binding {
    /// `n`: the client does not bind. Said where the upstream's certificate
    /// defines no binding data (RFC 5929 leaves it undefined).
    No,
    /// `y`: the client could bind, but the upstream offered no `-PLUS`. An
    /// upstream that does support binding refuses this, as a downgrade.
    Unoffered,
    /// `p=tls-server-end-point`: bound to this hash of the certificate the
    /// client verified ([`super::tls::server_end_point`]).
    ServerEndPoint(Vec<u8>),
}

impl Binding {
    /// The GS2 header (RFC 5802 §7).
    pub(crate) fn gs2_header(&self) -> &'static str {
        match self {
            Self::No => "n,,",
            Self::Unoffered => "y,,",
            Self::ServerEndPoint(_) => "p=tls-server-end-point,,",
        }
    }

    /// What `c=` carries, before base64: the GS2 header, then the binding's
    /// data where the client binds.
    fn cbind_input(&self) -> Vec<u8> {
        let mut input = self.gs2_header().as_bytes().to_vec();
        if let Self::ServerEndPoint(data) = self {
            input.extend(data);
        }
        input
    }
}

/// One exchange, from the client's first message to the server's signature.
pub(crate) struct ScramClient {
    /// SASLprepped (RFC 4013), as both ends derive the key from it.
    password: Zeroizing<String>,
    /// P3-5b-3 — the channel binding the exchange carries.
    binding: Binding,
    client_nonce: String,
    client_first_bare: String,
    /// Set by [`Self::client_final`]: what the server must sign with.
    server_signature: Option<[u8; 32]>,
}

impl ScramClient {
    /// Begin an exchange that does not bind, for `user` (Postgres sends
    /// none: it takes the user from its startup message) and `password`,
    /// with a fresh random nonce. Err for a password SASLprep refuses.
    #[cfg(test)]
    pub(crate) fn new(user: &str, password: &str) -> Result<Self, String> {
        Self::bound(user, password, Binding::No)
    }

    /// P3-5b-3 — begin an exchange carrying `binding`.
    pub(crate) fn bound(user: &str, password: &str, binding: Binding) -> Result<Self, String> {
        Self::with_nonce(
            user,
            password,
            binding,
            &B64.encode(rand::random::<[u8; 18]>()),
        )
    }

    fn with_nonce(
        user: &str,
        password: &str,
        binding: Binding,
        nonce: &str,
    ) -> Result<Self, String> {
        let password = stringprep::saslprep(password)
            .map_err(|_| "the password is not one SCRAM can use (SASLprep refused it)")?;
        let client_first_bare = format!("n={},r={nonce}", escape(user));
        Ok(Self {
            password: Zeroizing::new(password.into_owned()),
            binding,
            client_nonce: nonce.to_string(),
            client_first_bare,
            server_signature: None,
        })
    }

    /// `client-first-message`.
    pub(crate) fn client_first(&self) -> String {
        format!("{}{}", self.binding.gs2_header(), self.client_first_bare)
    }

    /// Read the `server-first-message` and answer the `client-final-message`,
    /// with the proof. Err for a server whose nonce is not this exchange's,
    /// whose salt does not decode, or whose iteration count is out of
    /// bounds.
    pub(crate) fn client_final(&mut self, server_first: &str) -> Result<String, String> {
        let mut nonce = None;
        let mut salt = None;
        let mut iterations = None;
        for attr in server_first.split(',') {
            match attr.split_once('=') {
                Some(("r", v)) => nonce = Some(v),
                Some(("s", v)) => salt = Some(v),
                Some(("i", v)) => iterations = Some(v),
                // A mandatory extension this client does not know (RFC
                // 5802 §5.1): refused, as the RFC requires.
                Some(("m", _)) => return Err("the server asked for a SCRAM extension".into()),
                _ => {}
            }
        }
        let nonce = nonce.ok_or("the server's first message has no nonce")?;
        if !nonce.starts_with(&self.client_nonce) || nonce.len() <= self.client_nonce.len() {
            return Err("the server's nonce is not this exchange's".into());
        }
        let salt = B64
            .decode(salt.ok_or("the server's first message has no salt")?)
            .map_err(|_| "the server's salt does not decode")?;
        let iterations: u32 = iterations
            .ok_or("the server's first message has no iteration count")?
            .parse()
            .map_err(|_| "the server's iteration count is not a number")?;
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(format!(
                "the server asked for {iterations} iterations (at most {MAX_ITERATIONS})"
            ));
        }

        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(self.password.as_bytes(), &salt, iterations, salted.as_mut());
        let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
        let stored_key: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
        // The binding is part of what the proof covers: a relay that
        // terminated the TLS cannot make it match the upstream's own.
        let without_proof = format!("c={},r={nonce}", B64.encode(self.binding.cbind_input()));
        let auth_message = format!("{},{server_first},{without_proof}", self.client_first_bare);
        let signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for (p, (k, s)) in proof
            .iter_mut()
            .zip(client_key.iter().zip(signature.iter()))
        {
            *p = k ^ s;
        }
        let server_key = Zeroizing::new(hmac(salted.as_ref(), b"Server Key"));
        self.server_signature = Some(hmac(server_key.as_ref(), auth_message.as_bytes()));
        Ok(format!("{without_proof},p={}", B64.encode(proof)))
    }

    /// Check the `server-final-message`: Ok only for the signature only a
    /// server that holds the password could make. An `e=` is the server's
    /// own refusal, said in its words.
    pub(crate) fn verify_server_final(&self, server_final: &str) -> Result<(), String> {
        let expected = self
            .server_signature
            .ok_or("the server's final message came before its first")?;
        for attr in server_final.split(',') {
            match attr.split_once('=') {
                Some(("e", why)) => return Err(format!("the server refused: {why}")),
                Some(("v", sig)) => {
                    let sig = B64
                        .decode(sig)
                        .map_err(|_| "the server's signature does not decode")?;
                    // Compared in constant time: an exchange that leaks
                    // nothing is simpler to reason about than one that leaks
                    // little.
                    let same = sig.len() == expected.len()
                        && sig
                            .iter()
                            .zip(expected.iter())
                            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                            == 0;
                    return if same {
                        Ok(())
                    } else {
                        Err("the server's signature is wrong: it does not hold the password".into())
                    };
                }
                _ => {}
            }
        }
        Err("the server's final message has no signature".into())
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// A SCRAM `saslname`: `=` and `,` escaped (RFC 5802 §5.1).
fn escape(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}

/// P3-6b-2 — the iterations a minted password's verifier is made with:
/// Postgres's own default (`scram_iterations`).
pub(crate) const VERIFIER_ITERATIONS: u32 = 4096;

/// P3-6b-2 — the SCRAM-SHA-256 verifier Postgres stores for `password`:
/// `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, its own
/// `pg_authid` form. `CREATE ROLE … PASSWORD` is given this rather than the
/// password, which so never reaches the database, nor a statement log there.
/// The password is SASLprepped as a client's sign-in prepares it, so the
/// keys are those a sign-in derives.
pub(crate) fn verifier(password: &str, salt: &[u8], iterations: u32) -> Result<String, String> {
    if salt.is_empty() || iterations == 0 || iterations > MAX_ITERATIONS {
        return Err("a verifier needs a salt and a sane iteration count".into());
    }
    let password = stringprep::saslprep(password)
        .map_err(|_| "the password is not one SCRAM can use (SASLprep refused it)")?;
    let mut salted = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, salted.as_mut());
    let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
    let stored_key: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
    let server_key = hmac(salted.as_ref(), b"Server Key");
    Ok(format!(
        "SCRAM-SHA-256${iterations}:{}${}:{}",
        B64.encode(salt),
        B64.encode(stored_key),
        B64.encode(server_key)
    ))
}

/// The server's half, for the proxies' tests: what an upstream checks and
/// answers, from the same RFC.
#[cfg(test)]
pub(crate) mod server {
    use super::*;

    /// One server-side exchange for `password`, with `salt` and
    /// `iterations`; P3-5b-3: with `binds`, the binding data of its own TLS
    /// channel, it supports channel binding as Postgres does.
    pub(crate) struct ScramServer {
        /// What a server keeps: never the password, nor the salted one
        /// (RFC 5802 §3).
        stored_key: [u8; 32],
        server_key: [u8; 32],
        salt: Vec<u8>,
        iterations: u32,
        nonce: String,
        binds: Option<Vec<u8>>,
        /// The client's GS2 header, and the refusal it earns, if any.
        gs2: String,
        refusal: Option<String>,
        client_first_bare: String,
        server_first: String,
    }

    impl ScramServer {
        pub(crate) fn new(password: &str, salt: &[u8], iterations: u32, nonce: &str) -> Self {
            let password = stringprep::saslprep(password).unwrap();
            let mut salted = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);
            let client_key = hmac(&salted, b"Client Key");
            Self {
                stored_key: Sha256::digest(client_key).into(),
                server_key: hmac(&salted, b"Server Key"),
                salt: salt.to_vec(),
                iterations,
                nonce: nonce.to_string(),
                binds: None,
                gs2: String::new(),
                refusal: None,
                client_first_bare: String::new(),
                server_first: String::new(),
            }
        }

        /// P3-6b-2 — a server that knows the user by the verifier it stores
        /// (`SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`), as
        /// Postgres knows a role whose password it was given hashed.
        pub(crate) fn from_verifier(verifier: &str, nonce: &str) -> Result<Self, String> {
            let rest = verifier
                .strip_prefix("SCRAM-SHA-256$")
                .ok_or("not a SCRAM-SHA-256 verifier")?;
            let (params, keys) = rest.split_once('$').ok_or("no keys")?;
            let (iterations, salt) = params.split_once(':').ok_or("no salt")?;
            let (stored, server) = keys.split_once(':').ok_or("no server key")?;
            let key = |s: &str| -> Result<[u8; 32], String> {
                B64.decode(s)
                    .map_err(|_| "a key does not decode".to_string())?
                    .try_into()
                    .map_err(|_| "a key is not 32 bytes".to_string())
            };
            Ok(Self {
                stored_key: key(stored)?,
                server_key: key(server)?,
                salt: B64.decode(salt).map_err(|_| "the salt does not decode")?,
                iterations: iterations
                    .parse()
                    .map_err(|_| "the iterations are not a number")?,
                nonce: nonce.to_string(),
                binds: None,
                gs2: String::new(),
                refusal: None,
                client_first_bare: String::new(),
                server_first: String::new(),
            })
        }

        /// A server whose TLS channel has this binding data.
        pub(crate) fn binding(mut self, data: Vec<u8>) -> Self {
            self.binds = Some(data);
            self
        }

        /// The GS2 header the client sent.
        pub(crate) fn gs2(&self) -> &str {
            &self.gs2
        }

        /// The `server-first-message` for a `client-first-message`. A
        /// header this server cannot honour is refused at the final message,
        /// as Postgres refuses it.
        pub(crate) fn server_first(&mut self, client_first: &str) -> String {
            let header_end = client_first
                .match_indices(',')
                .nth(1)
                .map(|(i, _)| i + 1)
                .expect("a GS2 header");
            let (gs2, bare) = client_first.split_at(header_end);
            self.gs2 = gs2.to_string();
            self.refusal = match (gs2, &self.binds) {
                ("n,,", _) => None,
                ("y,,", Some(_)) => Some("e=server-does-support-channel-binding".into()),
                ("y,,", None) => None,
                ("p=tls-server-end-point,,", None) => {
                    Some("e=server-does-not-support-channel-binding".into())
                }
                ("p=tls-server-end-point,,", Some(_)) => None,
                _ => Some("e=unsupported-channel-binding-type".into()),
            };
            let client_nonce = bare.split(',').find_map(|a| a.strip_prefix("r=")).unwrap();
            self.client_first_bare = bare.to_string();
            self.server_first = format!(
                "r={client_nonce}{},s={},i={}",
                self.nonce,
                B64.encode(&self.salt),
                self.iterations
            );
            self.server_first.clone()
        }

        /// The `server-final-message` for a `client-final-message`: its
        /// signature when the proof checks, `e=invalid-proof` when it does
        /// not.
        pub(crate) fn server_final(&self, client_final: &str) -> Result<String, String> {
            if let Some(refusal) = &self.refusal {
                return Err(refusal.clone());
            }
            let (without_proof, proof) = client_final.rsplit_once(",p=").unwrap();
            // The binding the client sent must be this channel's.
            let mut expected = self.gs2.as_bytes().to_vec();
            if self.gs2.starts_with("p=") {
                expected.extend(self.binds.as_deref().unwrap_or_default());
            }
            let sent = without_proof
                .split(',')
                .find_map(|a| a.strip_prefix("c="))
                .unwrap();
            if B64.decode(sent).ok().as_deref() != Some(expected.as_slice()) {
                return Err("e=channel-bindings-dont-match".into());
            }
            let auth_message = format!(
                "{},{},{without_proof}",
                self.client_first_bare, self.server_first
            );
            let signature = hmac(&self.stored_key, auth_message.as_bytes());
            let proof = B64.decode(proof).unwrap();
            let recovered: Vec<u8> = proof
                .iter()
                .zip(signature.iter())
                .map(|(p, s)| p ^ s)
                .collect();
            if Sha256::digest(&recovered).as_slice() != self.stored_key {
                return Err("e=invalid-proof".into());
            }
            Ok(format!(
                "v={}",
                B64.encode(hmac(&self.server_key, auth_message.as_bytes()))
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::made;
    use super::server::ScramServer;
    use super::*;

    /// RFC 7677 §3's exchange, byte for byte: the proof the client sends and
    /// the signature it accepts.
    #[test]
    fn the_rfc_7677_exchange_comes_out_byte_for_byte() {
        let mut c =
            ScramClient::with_nonce("user", "pencil", Binding::No, "rOprNGfwEbeRWgbNEkqO").unwrap();
        assert_eq!(c.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                            s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert_eq!(
            c.client_final(server_first).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        c.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
    }

    /// Against the test server: a matching password is let in both ways; a
    /// wrong one is refused by the server, and a server that does not hold
    /// the password is refused by the client.
    #[test]
    fn only_the_same_password_on_both_sides_completes() {
        let exchange = |client_pw: &str, server_pw: &str| {
            let mut c = ScramClient::new("", client_pw).unwrap();
            let mut s = ScramServer::new(server_pw, b"salt-for-a-test", 4096, "srvnonce");
            let first = s.server_first(&c.client_first());
            let fin = c.client_final(&first).unwrap();
            s.server_final(&fin).map(|v| c.verify_server_final(&v))
        };
        assert_eq!(exchange("same", "same"), Ok(Ok(())));
        assert_eq!(
            exchange("mine", "theirs"),
            Err("e=invalid-proof".into()),
            "the server refuses a wrong proof"
        );
        // A server that answers without the password: its signature cannot
        // check.
        let mut c = ScramClient::new("", "real").unwrap();
        let mut s = ScramServer::new("forged", b"salt", 4096, "n");
        let first = s.server_first(&c.client_first());
        c.client_final(&first).unwrap();
        let forged = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        assert!(c.verify_server_final(forged).is_err());
        assert_eq!(
            c.verify_server_final("e=other-error"),
            Err("the server refused: other-error".into())
        );
    }

    /// A server first message is checked before any work is done for it.
    #[test]
    fn a_server_first_message_is_held_to_this_exchange_and_its_bounds() {
        let mut c = ScramClient::with_nonce("", "pw", Binding::No, "abc").unwrap();
        for bad in [
            // Another exchange's nonce, or the client's echoed alone.
            "r=xyzdef,s=c2FsdA==,i=4096",
            "r=abc,s=c2FsdA==,i=4096",
            "s=c2FsdA==,i=4096",
            "r=abcdef,s=***,i=4096",
            "r=abcdef,i=4096",
            "r=abcdef,s=c2FsdA==",
            "r=abcdef,s=c2FsdA==,i=0",
            "r=abcdef,s=c2FsdA==,i=10000001",
            "r=abcdef,s=c2FsdA==,i=many",
            "m=ext,r=abcdef,s=c2FsdA==,i=4096",
        ] {
            assert!(c.client_final(bad).is_err(), "{bad}");
        }
        assert!(c.client_final("r=abcdef,s=c2FsdA==,i=4096").is_ok());
        assert!(
            ScramClient::new("", "pw")
                .unwrap()
                .verify_server_final("v=AAAA")
                .is_err(),
            "a final message before a first"
        );
    }

    /// The user is a `saslname` (RFC 5802 §5.1), and the password SASLprepped
    /// (RFC 4013) as the server derives it: a non-ASCII space is a space.
    #[test]
    fn names_are_escaped_and_passwords_saslprepped() {
        let c = ScramClient::with_nonce("a=b,c", "pw", Binding::No, "n").unwrap();
        assert_eq!(c.client_first(), "n,,n=a=3Db=2Cc,r=n");
        let exchange = |client_pw: &str, server_pw: &str| {
            let mut c = ScramClient::new("", client_pw).unwrap();
            let mut s = ScramServer::new(server_pw, b"salt", 4096, "srv");
            let first = s.server_first(&c.client_first());
            let fin = c.client_final(&first).unwrap();
            s.server_final(&fin).is_ok()
        };
        assert!(exchange("a\u{00A0}b", "a b"), "a no-break space is a space");
        assert!(
            ScramClient::new("", "bad\u{0007}").is_err(),
            "a control character is refused"
        );
    }

    /// P3-5b-3 — each binding against servers with and without binding
    /// support: a bound exchange completes only where the client's binding
    /// data is the server's own channel's; `y` completes only where the
    /// server cannot bind; `n` completes everywhere.
    #[test]
    fn a_binding_completes_only_on_the_channel_it_names() {
        let ours = b"the hash of the certificate the client saw".to_vec();
        let exchange = |binding: Binding, server_binds: Option<Vec<u8>>| {
            let mut c = ScramClient::bound("", "same", binding).unwrap();
            let mut s = ScramServer::new("same", b"salt", 4096, "srv");
            if let Some(data) = server_binds {
                s = s.binding(data);
            }
            let first = s.server_first(&c.client_first());
            let fin = c.client_final(&first).unwrap();
            assert!(fin.starts_with("c="), "the binding opens the final message");
            s.server_final(&fin).map(|v| c.verify_server_final(&v))
        };
        let bound = || Binding::ServerEndPoint(ours.clone());
        assert_eq!(exchange(bound(), Some(ours.clone())), Ok(Ok(())));
        assert_eq!(
            exchange(bound(), Some(b"a relay's certificate".to_vec())),
            Err("e=channel-bindings-dont-match".into()),
            "a binding to another channel: what a TLS-terminating relay would be"
        );
        assert_eq!(
            exchange(bound(), None),
            Err("e=server-does-not-support-channel-binding".into())
        );
        assert_eq!(
            exchange(Binding::Unoffered, Some(ours.clone())),
            Err("e=server-does-support-channel-binding".into()),
            "y to a server that binds: a downgrade"
        );
        assert_eq!(exchange(Binding::Unoffered, None), Ok(Ok(())));
        assert_eq!(exchange(Binding::No, Some(ours.clone())), Ok(Ok(())));
        assert_eq!(exchange(Binding::No, None), Ok(Ok(())));
        let headers = [Binding::No, Binding::Unoffered, bound()].map(|b| b.gs2_header());
        assert_eq!(headers, ["n,,", "y,,", "p=tls-server-end-point,,"]);
    }

    /// P3-6b-2 — a verifier is what Postgres stores, its keys derived as
    /// RFC 5802 derives them, here checked by another implementation
    /// (`ring`'s), not this module's own.
    #[test]
    fn a_verifier_holds_the_keys_a_server_keeps() {
        let password = made();
        let salt: [u8; 16] = rand::random();
        let v = verifier(&password, &salt, VERIFIER_ITERATIONS).unwrap();

        let mut salted = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(VERIFIER_ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut salted,
        );
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &salted);
        let client_key = ring::hmac::sign(&key, b"Client Key");
        let stored_key = ring::digest::digest(&ring::digest::SHA256, client_key.as_ref());
        let server_key = ring::hmac::sign(&key, b"Server Key");
        assert_eq!(
            v,
            format!(
                "SCRAM-SHA-256$4096:{}${}:{}",
                B64.encode(salt),
                B64.encode(stored_key.as_ref()),
                B64.encode(server_key.as_ref())
            )
        );
        assert!(!v.contains(&password), "the verifier holds no password");
        assert!(verifier(&password, &[], VERIFIER_ITERATIONS).is_err());
        assert!(verifier(&password, &salt, 0).is_err());
    }

    /// P3-6b-2 — and a server that knows the user by the verifier alone lets
    /// the password's holder in, and no one else.
    #[test]
    fn a_sign_in_checks_against_the_verifier_alone() {
        let password = made();
        let v = verifier(&password, &rand::random::<[u8; 16]>(), VERIFIER_ITERATIONS).unwrap();
        let sign_in = |with: &str| {
            let mut s = server::ScramServer::from_verifier(&v, "srvnonce").unwrap();
            let mut c = ScramClient::new("", with).unwrap();
            let first = s.server_first(&c.client_first());
            let fin = c.client_final(&first).unwrap();
            s.server_final(&fin).map(|v| c.verify_server_final(&v))
        };
        assert_eq!(sign_in(&password), Ok(Ok(())));
        assert_eq!(
            sign_in(&format!("{password}x")),
            Err("e=invalid-proof".into())
        );
    }
}
