// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-52 gate 4 — the device's half of the cross-org access password.
//!
//! This is the module that makes the whole feature honest. Everything else in
//! FR-52 is policy the server can see and change; this is the one gate the
//! server cannot pass, cannot read and cannot forge, because the secret behind
//! it never leaves the machine and is never in a form the server could replay.
//!
//! # Why an aPAKE and not a hash
//!
//! The obvious build — the browser POSTs the password, the server compares a
//! stored hash — moves the gate into the server. A compromised control plane
//! then opens any device in the fleet and a database dump is a fleet-wide
//! credential dump. Every neighbouring subsystem (`exec_enabled`,
//! `ssh_enabled`, `remote_config_enabled`) is built so the device holds the
//! last refusal, and an outsider has no tenant membership behind them, so here
//! the password IS the whole authorization.
//!
//! The next design — the device stores `Argon2(password)` and the client sends
//! `HMAC(that, nonce)` — is much better and still wrong in two ways that
//! matter: the device would hold a **password-equivalent** secret, and the
//! relaying server would hold an **offline cracking oracle** (guess, derive,
//! HMAC over the nonce it chose, compare with the tag it saw). Against a
//! human-chosen password that is a real break, by exactly the party this
//! design exists to exclude.
//!
//! OPAQUE removes both. The device stores a registration record that is not
//! password-equivalent; a network observer — our own server, which relays
//! every byte — learns nothing it can attack offline; and the client
//! **authenticates the device** as well, so a compromised server cannot
//! impersonate the machine to harvest the operator's password.
//!
//! # What is stored, and why two values
//!
//! [`AgentConfig::external_access_setup`] (the `ServerSetup`) and
//! [`AgentConfig::external_access_verifier`] (the `ServerRegistration`).
//! OPAQUE needs both for every login, and neither is useful without the other.
//! They are written only by `rc password set`, and are deliberately absent
//! from the config *surface*: `config get` would print a credential and
//! `config set` would let anyone able to write the file choose the password,
//! which is the property gate 4 exists to deny.
//!
//! ⚠️ **The KSF is Argon2id, and that is load-bearing.** It is what makes a
//! STOLEN record expensive to attack offline. With `ksf::Identity` — the
//! choice opaque-ke's own doc example uses "only to ensure that the tests
//! execute quickly" — the record would be worth roughly what the password is,
//! and the "not password-equivalent" claim above would be false.
//!
//! # Registration runs entirely on this device
//!
//! OPAQUE registration is a client/server exchange, but the device plays both
//! halves: it is holding the password at that moment. Nothing crosses a
//! network, which is why the password can never be pushed from the dashboard —
//! a password typed into a web form has already crossed the server, and that
//! is the one thing this module exists to prevent. The dashboard may show
//! *set / not set* and may CLEAR; it can never set.

use base64::Engine as _;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, Ristretto255, ServerRegistration,
    ServerSetup, TripleDh,
};
// ⚠️ NOT the workspace `rand`. opaque-ke is on rand 0.8 / rand_core 0.6 while
// the workspace is on 0.9, and the two `RngCore` traits are different types —
// the workspace `OsRng` fails to satisfy opaque-ke's bounds with an error that
// mentions `rand_core` only in a trailing note. See the Cargo.toml comment.
use rand_opaque::rngs::OsRng;

/// The ciphersuite, fixed for the life of the wire.
///
/// ⚠️ Every value in it is a compatibility surface: a device's stored record
/// is only readable by the same suite that wrote it, so changing any of these
/// invalidates every password already set in the field. A change here is a
/// forced re-set on every device, not a refactor.
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    /// ⚠️ NOT `ksf::Identity` (see the module docs — this is what stands
    /// between a stolen config file and the password in it), and NOT a bare
    /// `argon2::Argon2` either: see [`PinnedArgon2`].
    type Ksf = PinnedArgon2;
}

/// Argon2id memory cost, in KiB — 2^16, i.e. 64 MiB.
pub const KSF_MEMORY_KIB: u32 = 1 << 16;
/// Argon2id passes.
pub const KSF_ITERATIONS: u32 = 3;
/// Argon2id lanes.
pub const KSF_PARALLELISM: u32 = 4;

/// The key-stretching function, with its parameters PINNED rather than taken
/// from a crate default.
///
/// In OPAQUE the KSF runs on the **client** — at registration (where this
/// device plays the client) and at every login (where the outsider's browser
/// does). Both must use byte-identical parameters or the login cannot verify:
/// the browser derives a different key, the envelope does not open, and the
/// right password is refused. So the parameters are a wire-compatibility
/// surface, and changing them after a record is stored is a forced password
/// reset on that device.
///
/// ⚠️ **What this replaced, and why it had to go.** `type Ksf =
/// argon2::Argon2<'static>` used `Argon2::default()` — 19 MiB, 2 passes,
/// 1 lane — because opaque-ke falls back to `CS::Ksf::default()` whenever a
/// caller passes no KSF. The browser library (`@serenity-kit/opaque`, which is
/// opaque-ke itself compiled to WASM) defaults to 64 MiB, 3 passes, 4 lanes.
/// Measured before this change: the real browser client, typing the CORRECT
/// password, could not log into a device this crate had registered ("KE2 did
/// not verify"). Every browser login would have failed, and the first place
/// anyone would have seen it was P4's connect page.
///
/// Making the TYPE's `Default` the pinned instance, rather than passing pinned
/// parameters at call sites, is the point: opaque-ke reaches for `Default`
/// whenever a caller omits the KSF, so a call site that forgot could not fall
/// back to anything else.
///
/// The values are the browser library's DEFAULT ("memory-constrained", RFC
/// 9106 §4's recommendation for memory-constrained environments), so the
/// connect page can call it with no key-stretching option at all — one fewer
/// place for the two sides to drift. ~1 s on a laptop's browser per login.
pub struct PinnedArgon2(opaque_ke::argon2::Argon2<'static>);

impl Default for PinnedArgon2 {
    fn default() -> Self {
        use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
        // Valid by construction; `the_pinned_ksf_matches_an_independent_argon2id`
        // builds this first and would fail before any record could be written.
        let params = Params::new(KSF_MEMORY_KIB, KSF_ITERATIONS, KSF_PARALLELISM, None)
            .expect("the pinned Argon2id parameters are valid");
        Self(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl opaque_ke::ksf::Ksf for PinnedArgon2 {
    /// Byte-for-byte opaque-ke's own `impl Ksf for Argon2` — and
    /// `@serenity-kit/opaque`'s `CustomKsf` — so the only thing this type
    /// changes is WHICH instance runs: a zero salt of `RECOMMENDED_SALT_LEN`
    /// (OPAQUE salts through the OPRF, not here) and an output as long as the
    /// input.
    fn hash<L: opaque_ke::generic_array::ArrayLength<u8>>(
        &self,
        input: opaque_ke::generic_array::GenericArray<u8, L>,
    ) -> Result<opaque_ke::generic_array::GenericArray<u8, L>, opaque_ke::errors::InternalError>
    {
        let mut output = opaque_ke::generic_array::GenericArray::default();
        self.0
            .hash_password_into(
                &input,
                &[0; opaque_ke::argon2::RECOMMENDED_SALT_LEN],
                &mut output,
            )
            .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
        Ok(output)
    }
}

/// What `rc password set` persists. Both halves or neither: a config carrying
/// one without the other cannot authenticate anyone, and is the shape a
/// half-completed write would leave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// base64 `ServerSetup`
    pub setup: String,
    /// base64 `ServerRegistration`
    pub verifier: String,
}

/// Anything that can go wrong turning a password into a stored credential.
///
/// Deliberately does NOT carry the password, an OPAQUE internal, or any part
/// of either — an error type is the most likely thing to end up in a log line.
#[derive(Debug)]
pub enum Error {
    /// The password was empty. Refused rather than registered, because an
    /// empty password that "works" is a device with no gate 4 at all.
    EmptyPassword,
    /// Shorter than [`MIN_PASSWORD_CHARS`]. Separate from `EmptyPassword`
    /// because the two need different words on screen: one is a mistake, the
    /// other is a choice the operator has to revise.
    TooShort,
    /// The OPAQUE protocol refused. The cause is not surfaced on purpose.
    Protocol,
    /// A stored value is not valid base64, or not a value this suite wrote.
    Corrupt,
    /// A login message from the other side did not deserialize. Distinct from
    /// `LoginRejected`: this is a broken or hostile client, not a wrong
    /// password, and the two want different lines in an audit log.
    Malformed,
    /// KE3 did not verify — the client did not prove it knows the password.
    LoginRejected,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EmptyPassword => "the external-access password must not be empty",
            // The number is inlined rather than formatted because `Display` on
            // an error with no arguments is `write_str`-able, and a `format!`
            // here would allocate on every refusal path.
            Self::TooShort => {
                "the external-access password must be at least 12 characters — it is the whole \
                 authorization for controlling this machine, and the connect code in front of it \
                 is dictated aloud, not secret"
            }
            Self::Protocol => "could not derive the external-access credential",
            Self::Corrupt => {
                "the stored external-access credential is unreadable — set the password again"
            }
            Self::Malformed => "a login message could not be read",
            Self::LoginRejected => "the login did not verify",
        })
    }
}

impl std::error::Error for Error {}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The OPAQUE identity a record is bound to.
///
/// Fixed rather than the device id: the record lives in this device's own
/// config and is never shared, so there is nothing for an identity to
/// disambiguate — and binding to a device id would invalidate every stored
/// password the first time a device is re-enrolled and gets a new one.
const IDENTITY: &[u8] = b"roomler-external-access";

/// First-time registration with a freshly minted setup — **a test shorthand**,
/// private on purpose.
///
/// [`set_password`] is the single production entry point, because it is where
/// [`MIN_PASSWORD_CHARS`] is enforced. A second public way to mint a credential
/// would make that floor a courtesy instead of a gate — precisely the shape the
/// encoder cell denylist had before 0.4.90, where the check lived on the probe
/// and a session cheerfully opened a cell the probe had denied. This shorthand
/// delegates, so every test goes through the real gate too.
#[cfg(test)]
fn register(password: &str) -> Result<Credential, Error> {
    set_password(None, password).map(|(cred, _)| cred)
}

/// The shortest password this device will accept.
///
/// Not a style preference. After the three gates in front of it, this password
/// is the *entire* authorization for remote control of the machine — and unlike
/// every other credential in the product there is no username to guess first:
/// the connect code that names the device is dictated over the phone and is not
/// a secret. OPAQUE makes an attacker pay a round trip to the device for every
/// guess, but "pay a round trip" is only a defence if the guess space is large,
/// so the floor is where the entropy has to come from.
///
/// ⚠️ Raising this later cannot retroactively strengthen a password already
/// set in the field — that needs a forced re-set — so the number is easier to
/// get right now than to correct.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Where the `ServerSetup` behind a newly stored credential came from. The
/// caller logs it: `Replaced` means this set REPAIRED a device whose stored
/// record could not be read, which is worth a line in the log because the
/// failure it fixes is otherwise invisible until someone tries to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupOrigin {
    /// A password *change* — the device's existing OPAQUE identity was kept.
    Reused,
    /// First password on this device.
    Minted,
    /// A setup was stored but did not parse; a fresh one replaced it.
    Replaced,
}

/// Set — or change — the device's password, keeping the device's OPAQUE
/// identity stable across a change.
///
/// `stored_setup` is the base64 `external_access_setup` already in this
/// device's config, if any. When it is present and parses, the new record is
/// registered against it, so changing a password does **not** rotate the
/// device's long-term OPAQUE keypair. That keypair is per-DEVICE
/// infrastructure, not per-password: a stable one is what a client can pin,
/// and rotating it on every change would mean a password change and a device
/// re-identification were indistinguishable to anyone watching.
///
/// ⚠️ A stored setup that does **not** parse falls back to minting a fresh one
/// rather than failing. `rc password set` is precisely the command an operator
/// reaches for when the stored record is broken, and refusing it there would
/// leave the device with no route back except hand-editing the config as
/// SYSTEM — the state this returns `Replaced` for.
pub fn set_password(
    stored_setup: Option<&str>,
    password: &str,
) -> Result<(Credential, SetupOrigin), Error> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(if password.is_empty() {
            Error::EmptyPassword
        } else {
            Error::TooShort
        });
    }
    let mut rng = OsRng;
    let (setup, origin) = match stored_setup {
        None => (ServerSetup::<Suite>::new(&mut rng), SetupOrigin::Minted),
        Some(encoded) => match b64()
            .decode(encoded)
            .ok()
            .and_then(|bytes| ServerSetup::<Suite>::deserialize(&bytes).ok())
        {
            Some(existing) => (existing, SetupOrigin::Reused),
            None => (ServerSetup::<Suite>::new(&mut rng), SetupOrigin::Replaced),
        },
    };
    let verifier = register_with(&setup, password, &mut rng)?;
    Ok((
        Credential {
            setup: b64().encode(setup.serialize()),
            verifier: b64().encode(verifier.serialize()),
        },
        origin,
    ))
}

/// Re-register a password against an EXISTING `ServerSetup`.
///
/// Split out because a password *change* must keep the setup: it is
/// long-lived per device, and minting a fresh one on every change would be a
/// silent extra way for the two stored halves to stop matching.
fn register_with(
    setup: &ServerSetup<Suite>,
    password: &str,
    rng: &mut OsRng,
) -> Result<ServerRegistration<Suite>, Error> {
    let pw = password.as_bytes();
    let client_start = ClientRegistration::<Suite>::start(rng, pw).map_err(|_| Error::Protocol)?;
    let server_start = ServerRegistration::<Suite>::start(setup, client_start.message, IDENTITY)
        .map_err(|_| Error::Protocol)?;
    let client_finish = client_start
        .state
        .finish(
            rng,
            pw,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| Error::Protocol)?;
    Ok(ServerRegistration::<Suite>::finish(client_finish.message))
}

/// Read a stored credential back into the OPAQUE types a login needs.
///
/// ⚠️ `Corrupt` and "no password set" are different answers and the caller
/// must keep them apart: the first is a device whose owner needs to set the
/// password again, the second is a device that never had one. Collapsing them
/// would tell an operator to redo work they never did.
pub fn parse(cred: &Credential) -> Result<(ServerSetup<Suite>, ServerRegistration<Suite>), Error> {
    let setup_bytes = b64().decode(&cred.setup).map_err(|_| Error::Corrupt)?;
    let verifier_bytes = b64().decode(&cred.verifier).map_err(|_| Error::Corrupt)?;
    let setup = ServerSetup::<Suite>::deserialize(&setup_bytes).map_err(|_| Error::Corrupt)?;
    let verifier =
        ServerRegistration::<Suite>::deserialize(&verifier_bytes).map_err(|_| Error::Corrupt)?;
    Ok((setup, verifier))
}

// ---------------------------------------------------------------------------
// FR-52 P3 — the device's half of an OPAQUE LOGIN.
//
// Two pure steps, no state tables and no gates: KE1 → KE2, then KE3 → a
// session key. Who may start a login, how often, and what a verified login is
// good for are the caller's business; these functions only speak the
// protocol, so they can be proven against a real browser client in isolation.
// ---------------------------------------------------------------------------

/// The device's state between answering KE1 and receiving KE3.
///
/// Deliberately opaque and not `Clone`: a pending login is consumed by
/// [`login_finish`], so the type makes "finish the same login twice"
/// unrepresentable rather than merely unlikely.
pub struct PendingLogin(opaque_ke::ServerLogin<Suite>);

/// The 64-byte key both sides hold after a verified login.
///
/// ⚠️ `Debug` is redacted, for the reason `localapi::Secret` is: this is the
/// value everything after the login is authenticated under, and the most likely
/// way it leaves the process is a well-meant `tracing::debug!(?grant)`.
pub struct SessionKey(Vec<u8>);

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(***)")
    }
}

impl SessionKey {
    /// Borrow the key. Every call site is a place to ask where it can end up.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// KE1 → KE2: answer a client's login request against this device's record.
///
/// ⚠️ **The caller must count this call as a guess, not wait for KE3.** In
/// OPAQUE the *client* learns whether its password is right when it opens KE2 —
/// before it ever sends KE3. A caller that throttled only failed KE3s would give
/// an attacker unlimited free guesses: send KE1, check KE2 locally, never send
/// KE3, and the device never sees a failure at all.
///
/// Cheap on this side by design: the key stretching (Argon2id) runs on the
/// CLIENT at login. The device does one OPRF evaluation and the 3DH, so a flood
/// of KE1s costs the attacker a round trip each and the device almost nothing.
pub fn login_start(cred: &Credential, ke1: &[u8]) -> Result<(Vec<u8>, PendingLogin), Error> {
    let (setup, record) = parse(cred)?;
    let request =
        opaque_ke::CredentialRequest::<Suite>::deserialize(ke1).map_err(|_| Error::Malformed)?;
    let mut rng = OsRng;
    let started = opaque_ke::ServerLogin::<Suite>::start(
        &mut rng,
        &setup,
        Some(record),
        request,
        IDENTITY,
        // No context and default identifiers, matching the browser client
        // (`@serenity-kit/opaque` passes `None` for both). The principal is
        // bound AFTER the login, by deriving the application key from the
        // session key — see the P3 section of the FR-52 spec.
        opaque_ke::ServerLoginParameters::default(),
    )
    .map_err(|_| Error::Protocol)?;
    Ok((
        started.message.serialize().to_vec(),
        PendingLogin(started.state),
    ))
}

/// KE3 → the session key, or a refusal.
///
/// A wrong password surfaces HERE as [`Error::LoginRejected`] — but only for a
/// client honest enough to send its KE3. See [`login_start`] for why that is
/// not where guesses may be counted.
pub fn login_finish(pending: PendingLogin, ke3: &[u8]) -> Result<SessionKey, Error> {
    let finalization = opaque_ke::CredentialFinalization::<Suite>::deserialize(ke3)
        .map_err(|_| Error::Malformed)?;
    let finished = pending
        .0
        .finish(finalization, opaque_ke::ServerLoginParameters::default())
        .map_err(|_| Error::LoginRejected)?;
    Ok(SessionKey(finished.session_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{ClientLogin, ClientLoginFinishParameters};

    /// Test passwords are BUILT, never written as literals.
    ///
    /// ⚠️ Not cosmetic: a secret scanner cannot tell a KDF input in a unit
    /// test from a leaked credential, and this file failed GitGuardian on a
    /// literal the moment it was pushed. Nothing here needs to LOOK like a
    /// password — what the tests exercise is that two inputs differ.
    fn pw(tag: &str) -> String {
        format!("fr52-not-a-credential-{tag}")
    }

    /// Drive a full OPAQUE login against a record this module registered.
    ///
    /// This is the point of the test module. Registration on its own is
    /// unfalsifiable — it always produces *something* — and the wire that
    /// would exercise it is FR-52 P3. Running the login here proves the stored
    /// pair is actually usable, and proves it now rather than after a protocol
    /// change has quietly made every fielded password unreadable.
    fn login(cred: &Credential, password: &str) -> Result<(), ()> {
        // The DEVICE half goes through `login_start` / `login_finish` — the
        // functions that ship — not through opaque-ke directly. A helper that
        // drove the protocol itself would keep every test below green no
        // matter what the shipping path did (P2c deleted a test for exactly
        // that). The CLIENT half is raw opaque-ke, standing in for the browser.
        let mut rng = OsRng;
        let c1 = ClientLogin::<Suite>::start(&mut rng, password.as_bytes()).map_err(|_| ())?;
        let (ke2, pending) = login_start(cred, &c1.message.serialize()).map_err(|_| ())?;
        let c2 = c1
            .state
            .finish(
                &mut rng,
                password.as_bytes(),
                opaque_ke::CredentialResponse::<Suite>::deserialize(&ke2).map_err(|_| ())?,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| ())?;
        let key = login_finish(pending, &c2.message.serialize()).map_err(|_| ())?;
        // Both sides derived a session key, and they AGREE. That agreement is
        // the thing P4 binds the DTLS fingerprint to; without it a "verified"
        // password would still leave the server free to substitute its own
        // peer, and the whole aPAKE would buy less than it looks like.
        assert_eq!(
            c2.session_key.as_slice(),
            key.expose(),
            "client and device derived different session keys"
        );
        Ok(())
    }

    #[test]
    fn a_registered_password_authenticates() {
        let cred = register(&pw("alpha")).expect("registration");
        login(&cred, &pw("alpha")).expect("the right password must authenticate");
    }

    /// The half that makes the test above mean anything. A round trip that
    /// only ever tries the right password passes on an implementation that
    /// accepts everything.
    #[test]
    fn a_wrong_password_does_not() {
        let cred = register(&pw("alpha")).unwrap();
        assert!(
            login(&cred, &(pw("alpha") + "x")).is_err(),
            "a one-character-off password authenticated — gate 4 is not a gate"
        );
        assert!(login(&cred, "").is_err());
    }

    /// Two devices setting the SAME password must not produce the same record:
    /// the setup is per-device, so a record lifted from one config cannot be
    /// dropped into another, and two devices are not correlatable by their
    /// stored verifier.
    #[test]
    fn the_same_password_registers_differently_on_two_devices() {
        let a = register(&pw("shared")).unwrap();
        let b = register(&pw("shared")).unwrap();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.setup, b.setup);
        // And a record is bound to ITS OWN setup: crossing them must fail.
        let crossed = Credential {
            setup: a.setup.clone(),
            verifier: b.verifier.clone(),
        };
        assert!(
            login(&crossed, &pw("shared")).is_err(),
            "a verifier authenticated against another device's setup"
        );
    }

    /// An empty password is REFUSED, not registered. A device whose password
    /// is "" has no gate 4 while looking exactly like one that does.
    #[test]
    fn an_empty_password_is_refused() {
        assert!(matches!(register(""), Err(Error::EmptyPassword)));
    }

    /// Unreadable is its own answer, distinct from absent. An operator told
    /// "set it again" for a device that never had one is being sent to redo
    /// work they never did.
    #[test]
    fn a_corrupt_credential_says_so_rather_than_panicking() {
        let cred = Credential {
            setup: "not base64!!".into(),
            verifier: "also not".into(),
        };
        assert!(matches!(parse(&cred), Err(Error::Corrupt)));

        let good = register(&pw("corrupt")).unwrap();
        let truncated = Credential {
            setup: good.setup[..good.setup.len() / 2].to_string(),
            verifier: good.verifier.clone(),
        };
        assert!(matches!(parse(&truncated), Err(Error::Corrupt)));
    }

    /// ⚠️ The error type is the most likely thing to reach a log line, so it
    /// must not carry the password or anything derived from it.
    #[test]
    fn errors_never_quote_the_password() {
        let marker = "fr52-marker-not-a-credential";
        let e = register("").unwrap_err();
        assert!(!format!("{e}").contains(marker));
        assert!(!format!("{e:?}").contains(marker));
        let bad = Credential {
            setup: marker.into(),
            verifier: marker.into(),
        };
        let e = parse(&bad).unwrap_err();
        assert!(!format!("{e}").contains(marker));
        assert!(!format!("{e:?}").contains(marker));
    }

    /// A password CHANGE keeps the device's OPAQUE identity and retires the old
    /// password.
    ///
    /// Both halves matter. Keeping the setup is what makes the device's
    /// long-term keypair per-device rather than per-password; retiring the old
    /// password is what makes it a change rather than an addition. A bug that
    /// reused the whole *credential* instead of just the setup would leave the
    /// old password working, which is the failure an operator would least
    /// expect and least likely notice.
    ///
    /// ⚠️ This REPLACED a P2b test that asserted the same property by calling
    /// `register_with` directly and assembling the changed `Credential` by hand.
    /// That test exercised the mechanism and never the caller, so it stayed
    /// green no matter what `set_password` did — including minting a fresh setup
    /// on every change, the exact bug it was named for. The property has to be
    /// asserted through the entry point that ships.
    #[test]
    fn a_password_change_keeps_the_identity_and_retires_the_old_password() {
        let (first, origin) = set_password(None, &pw("before")).unwrap();
        assert_eq!(origin, SetupOrigin::Minted);

        let (second, origin) = set_password(Some(&first.setup), &pw("after")).unwrap();
        assert_eq!(origin, SetupOrigin::Reused);
        assert_eq!(
            first.setup, second.setup,
            "a password change must not rotate the device's OPAQUE keypair"
        );
        assert_ne!(
            first.verifier, second.verifier,
            "the record must change with the password"
        );

        assert!(
            login(&second, &pw("after")).is_ok(),
            "the new password works"
        );
        assert!(
            login(&second, &pw("before")).is_err(),
            "the OLD password must stop working"
        );
    }

    /// A stored setup that cannot be read is REPLACED, not a refusal.
    ///
    /// `rc password set` is the command an operator reaches for when the record
    /// is broken. Failing here would leave them with no route back except
    /// hand-editing the config as SYSTEM, and the resulting credential must be
    /// fully usable — a `Replaced` that produced an unloggable-into record
    /// would turn one broken state into another.
    #[test]
    fn a_corrupt_stored_setup_is_replaced_rather_than_refused() {
        let (cred, origin) = set_password(Some("!!! not base64 !!!"), &pw("repair")).unwrap();
        assert_eq!(origin, SetupOrigin::Replaced);
        assert!(login(&cred, &pw("repair")).is_ok());

        // Valid base64 that is not a ServerSetup this suite wrote takes the same
        // path — the decode succeeding is not the same as the value being ours.
        let (cred, origin) = set_password(Some(&b64().encode([7u8; 8])), &pw("repair2")).unwrap();
        assert_eq!(origin, SetupOrigin::Replaced);
        assert!(login(&cred, &pw("repair2")).is_ok());
    }

    /// The length floor holds at its exact boundary, and counts CHARACTERS.
    ///
    /// ⚠️ The chars-vs-bytes half is the one worth a test: with `len()` the
    /// 6-character accented password below is 12 BYTES and would sail through,
    /// giving an operator who chose a non-ASCII password half the floor everyone
    /// else gets — and silently, since nothing on screen distinguishes them.
    #[test]
    fn the_password_floor_is_exact_and_counts_characters() {
        assert_eq!(MIN_PASSWORD_CHARS, 12, "the boundary cases below assume 12");

        let short = "a".repeat(MIN_PASSWORD_CHARS - 1);
        assert!(matches!(set_password(None, &short), Err(Error::TooShort)));

        let exact = "a".repeat(MIN_PASSWORD_CHARS);
        assert!(set_password(None, &exact).is_ok(), "the floor is inclusive");

        // 6 chars, 12 bytes.
        let multibyte = "é".repeat(6);
        assert_eq!(multibyte.len(), 12, "the byte length matches the floor");
        assert_eq!(multibyte.chars().count(), 6);
        assert!(
            matches!(set_password(None, &multibyte), Err(Error::TooShort)),
            "the floor must count characters, not bytes"
        );

        // Empty stays its own answer — a mistake, not a choice to revise.
        assert!(matches!(set_password(None, ""), Err(Error::EmptyPassword)));
    }

    /// The refusal names the real minimum.
    ///
    /// The number is inlined in `Display` (an argument-free `Display` is
    /// `write_str`-able), so this test is what keeps the two from drifting —
    /// the failure mode being an operator told "at least 12" by a build that
    /// wants 16.
    #[test]
    fn the_too_short_message_states_the_actual_minimum() {
        let msg = format!("{}", Error::TooShort);
        assert!(
            msg.contains(&MIN_PASSWORD_CHARS.to_string()),
            "the refusal must name MIN_PASSWORD_CHARS ({MIN_PASSWORD_CHARS}), got: {msg}"
        );
    }

    /// FR-52 P3a — the KSF reproduces a vector from an INDEPENDENT Argon2id.
    ///
    /// The expected bytes were computed by OpenSSL's Argon2 (Node 24,
    /// `crypto.argon2Sync("argon2id", { message: 00..3f, nonce: 16 × 00,
    /// memory: 65536, passes: 3, parallelism: 4, tagLength: 64 })`), not by
    /// this crate. One assertion therefore pins the algorithm, the version, all
    /// three costs, the salt convention and the output length — every value the
    /// browser client must share with this device for a login to verify.
    ///
    /// ⚠️ A golden value computed by the code under test would only prove the
    /// code agrees with itself; this one would fail if the argon2 crate, the
    /// pinned constants, or opaque-ke's salt convention moved.
    #[test]
    fn the_pinned_ksf_matches_an_independent_argon2id() {
        use opaque_ke::generic_array::{GenericArray, typenum::U64};
        use opaque_ke::ksf::Ksf as _;

        let input: GenericArray<u8, U64> = GenericArray::from_exact_iter(0u8..64).unwrap();
        let out = PinnedArgon2::default().hash(input).expect("the KSF runs");
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "763c05e205e6d06f9d49921578c5fc314590d8016bd8ccc98049f3da265fad5d\
             4a27e85aaac6ac1de7cf2aeda7b8c767de0ff4e5db3ff8421d9bb3e8effb279b",
            "the KSF no longer matches the browser client's Argon2id — every \
             stored record and every login in the field depends on these bytes"
        );
    }

    /// FR-52 P3 — a wrong password is decided at KE2, so the DEVICE never sees
    /// a failure.
    ///
    /// This is the property the device's throttling is built on, asserted here
    /// so it cannot be forgotten by whoever writes that throttle: the device
    /// answers KE1 (one guess served), and the client learns it was wrong while
    /// opening KE2 — before a KE3 exists to send. A guessing client simply
    /// stops there. Measured with the real browser library too (FR-52 field
    /// log, 2026-09-24): wrong password ⇒ "KE2 did not verify", and the device
    /// saw only an abandoned login.
    ///
    /// ⚠️ Consequence: guesses must be counted when KE1 is ANSWERED. A throttle
    /// that counted failed KE3s would count nothing.
    #[test]
    fn a_wrong_password_is_decided_at_ke2_so_the_device_never_sees_a_failure() {
        let cred = register(&pw("right")).unwrap();
        let mut rng = OsRng;
        let c1 = ClientLogin::<Suite>::start(&mut rng, pw("wrong").as_bytes()).unwrap();

        // The device answers — it cannot know the guess is wrong yet.
        let (ke2, _pending) =
            login_start(&cred, &c1.message.serialize()).expect("the device answers KE1");

        // ...and the client learns the answer from KE2 alone.
        let opened = c1.state.finish(
            &mut rng,
            pw("wrong").as_bytes(),
            opaque_ke::CredentialResponse::<Suite>::deserialize(&ke2).unwrap(),
            ClientLoginFinishParameters::default(),
        );
        assert!(
            opened.is_err(),
            "a wrong password must fail CLIENT-side at KE2 — if this ever passes, the \
             throttling rationale in `login_start` no longer holds and must be revisited"
        );
        // `_pending` is dropped unfinished: the device has no failure to count.
    }

    /// A message that is not an OPAQUE message is `Malformed`, at either step —
    /// never `LoginRejected`, which would record a broken client as a wrong
    /// password in the audit log.
    #[test]
    fn garbage_is_malformed_not_a_wrong_password() {
        let cred = register(&pw("malformed")).unwrap();
        assert!(matches!(
            login_start(&cred, b"not a KE1"),
            Err(Error::Malformed)
        ));

        let mut rng = OsRng;
        let c1 = ClientLogin::<Suite>::start(&mut rng, pw("malformed").as_bytes()).unwrap();
        let (_, pending) = login_start(&cred, &c1.message.serialize()).unwrap();
        assert!(matches!(
            login_finish(pending, b"not a KE3"),
            Err(Error::Malformed)
        ));
    }

    /// The session key does not print itself — the same guard `Secret` has, for
    /// the value everything after a login is authenticated under.
    #[test]
    fn a_session_key_never_prints_itself() {
        let key = SessionKey(vec![0xAB; 64]);
        let printed = format!("{key:?}");
        assert!(!printed.to_lowercase().contains("ab"), "{printed}");
        assert!(
            !printed.contains("171"),
            "not even as decimal bytes: {printed}"
        );
    }
}
