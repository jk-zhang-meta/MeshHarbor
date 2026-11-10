// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5f-1 — the SSH agent: what it lists, binds and signs, asked as
//! OpenSSH's `ssh` asks it, with every key made for the test (by `ring`, and
//! where the system has it, by `ssh-keygen`; and listed by `ssh-add`).

use std::time::Duration;

use base64::Engine as _;
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{self as sig, KeyPair as _, RsaKeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::vault_proxy::testing::{KeyFile, armor, made, present, strings};

const WAIT: Duration = Duration::from_secs(10);
const HANDLE: &str = "git/deploy";

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

fn b64(raw: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// What a PEM block holds, whatever its label: its lines between the two
/// armor lines, decoded.
fn unarmor(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// The secret scalar in `ring`'s PKCS#8 for an ECDSA key: ring writes the
/// ECPrivateKey (RFC 5915) after a fixed template, its version 1 and then
/// the scalar as an OCTET STRING.
fn scalar_of(pkcs8: &[u8], len: usize) -> Vec<u8> {
    let marker = [0x02, 0x01, 0x01, 0x04, u8::try_from(len).unwrap()];
    let at = pkcs8.windows(5).position(|w| w == marker).unwrap() + 5;
    pkcs8[at..at + len].to_vec()
}

/// A key the vault might hold, made for the test: the secret's `key`, its
/// public half as SSH writes it, and how to check a signature by it.
struct UserKey {
    pem: String,
    public: Vec<u8>,
    key_type: &'static str,
    point: Vec<u8>,
    curve: Option<Curve>,
}

impl UserKey {
    fn parts_ed25519() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let seed = random::<32>();
        let pk = Ed25519KeyPair::from_seed_unchecked(&seed)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let secret = [&seed[..], &pk[..]].concat();
        let public = strings(&[b"ssh-ed25519", &pk]);
        let private = strings(&[b"ssh-ed25519", &pk, &secret]);
        (public, private, pk)
    }

    fn ed25519() -> Self {
        let (public, private, pk) = Self::parts_ed25519();
        Self {
            pem: KeyFile::new(public.clone(), private).pem(),
            public,
            key_type: "ssh-ed25519",
            point: pk,
            curve: None,
        }
    }

    fn ecdsa(curve: Curve) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(curve.signing(), &rng).unwrap();
        let point = EcdsaKeyPair::from_pkcs8(curve.signing(), pkcs8.as_ref(), &rng)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let scalar = scalar_of(pkcs8.as_ref(), curve.scalar_len());
        let public = strings(&[curve.key_type().as_bytes(), curve.name(), &point]);
        let mut private = public.clone();
        put_mpint(&mut private, &scalar);
        Self {
            pem: KeyFile::new(public.clone(), private).pem(),
            public,
            key_type: curve.key_type(),
            point,
            curve: Some(curve),
        }
    }

    /// Whether `answer` is a `SIGN_RESPONSE` holding this key's signature
    /// on `data`: the signature checked by `ring` itself.
    fn signed(&self, answer: &[u8], data: &[u8]) -> bool {
        let mut r = Reader::new(answer);
        if r.u8() != Some(SIGN_RESPONSE) {
            return false;
        }
        let Some(signature) = r.string() else {
            return false;
        };
        let mut s = Reader::new(signature);
        let (Some(algorithm), Some(blob)) = (s.string(), s.string()) else {
            return false;
        };
        if r.end().is_none() || s.end().is_none() || algorithm != self.key_type.as_bytes() {
            return false;
        }
        match self.curve {
            None => sig::UnparsedPublicKey::new(&sig::ED25519, &self.point)
                .verify(data, blob)
                .is_ok(),
            Some(curve) => {
                let mut halves = Reader::new(blob);
                let (r, s) = (halves.mpint().unwrap(), halves.mpint().unwrap());
                let mut fixed_rs = fixed(r, curve.scalar_len()).unwrap();
                fixed_rs.extend(fixed(s, curve.scalar_len()).unwrap());
                sig::UnparsedPublicKey::new(curve.verifying(), &self.point)
                    .verify(data, &fixed_rs)
                    .is_ok()
            }
        }
    }
}

/// An SSH host, made for the test: its key, and its signature over a
/// session identifier, as its key exchange sends one.
enum Host {
    Ed25519(Ed25519KeyPair),
    Ecdsa(EcdsaKeyPair, Curve),
}

impl Host {
    fn ed25519() -> Self {
        Self::Ed25519(Ed25519KeyPair::from_seed_unchecked(&random::<32>()).unwrap())
    }

    fn ecdsa(curve: Curve) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(curve.signing(), &rng).unwrap();
        Self::Ecdsa(
            EcdsaKeyPair::from_pkcs8(curve.signing(), pkcs8.as_ref(), &rng).unwrap(),
            curve,
        )
    }

    fn key_type(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ssh-ed25519",
            Self::Ecdsa(_, curve) => curve.key_type(),
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(pair) => strings(&[b"ssh-ed25519", pair.public_key().as_ref()]),
            Self::Ecdsa(pair, curve) => strings(&[
                curve.key_type().as_bytes(),
                curve.name(),
                pair.public_key().as_ref(),
            ]),
        }
    }

    /// The key as `host_keys` names it.
    fn line(&self) -> String {
        format!("{} {}", self.key_type(), b64(&self.key()))
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(pair) => strings(&[b"ssh-ed25519", pair.sign(data).as_ref()]),
            Self::Ecdsa(pair, curve) => {
                let fixed_rs = pair.sign(&SystemRandom::new(), data).unwrap();
                let (r, s) = fixed_rs.as_ref().split_at(curve.scalar_len());
                let mut halves = Vec::new();
                put_mpint(&mut halves, r);
                put_mpint(&mut halves, s);
                strings(&[curve.key_type().as_bytes(), &halves])
            }
        }
    }
}

/// `session-bind@openssh.com`, field by field.
fn bind_message(host_key: &[u8], session_id: &[u8], signature: &[u8], forwarding: u8) -> Vec<u8> {
    let mut m = vec![EXTENSION];
    put_string(&mut m, SESSION_BIND);
    put_string(&mut m, host_key);
    put_string(&mut m, session_id);
    put_string(&mut m, signature);
    m.push(forwarding);
    m
}

/// A binding as `ssh` sends one, right after its key exchange with `host`.
fn binding(host: &Host, session_id: &[u8]) -> Vec<u8> {
    bind_message(&host.key(), session_id, &host.sign(session_id), 0)
}

fn sign_request(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = vec![SIGN_REQUEST];
    put_string(&mut m, key);
    put_string(&mut m, data);
    put_u32(&mut m, 0);
    m
}

/// A sign-in's data, as `ssh` asks for its signature (RFC 4252 §7), each
/// field one a test may make wrong.
#[derive(Clone, Copy)]
struct SignInData<'a> {
    session_id: &'a [u8],
    user: &'a str,
    service: &'a str,
    method: &'a str,
    signature_follows: u8,
    algorithm: &'a str,
    key: &'a [u8],
    host_key: Option<&'a [u8]>,
    after: &'a [u8],
}

impl SignInData<'_> {
    fn bytes(&self) -> Vec<u8> {
        let mut d = Vec::new();
        put_string(&mut d, self.session_id);
        d.push(USERAUTH_REQUEST);
        put_string(&mut d, self.user.as_bytes());
        put_string(&mut d, self.service.as_bytes());
        put_string(&mut d, self.method.as_bytes());
        d.push(self.signature_follows);
        put_string(&mut d, self.algorithm.as_bytes());
        put_string(&mut d, self.key);
        if let Some(host_key) = self.host_key {
            put_string(&mut d, host_key);
        }
        d.extend_from_slice(self.after);
        d
    }
}

/// The sign-in `ssh` asks for, as `git`, with `key`, in `session_id`.
fn sign_in<'a>(session_id: &'a [u8], key: &'a UserKey) -> SignInData<'a> {
    SignInData {
        session_id,
        user: "git",
        service: "ssh-connection",
        method: "publickey",
        signature_follows: 1,
        algorithm: key.key_type,
        key: &key.public,
        host_key: None,
        after: &[],
    }
}

fn agent(key: &UserKey, hosts: &[&Host], user: Option<&str>) -> Agent {
    let lines: Vec<String> = hosts.iter().map(|h| h.line()).collect();
    Agent::new(&key.pem, &lines.join("\n"), HANDLE, user).unwrap()
}

/// A client on one connection to an agent served for the test.
struct Client {
    io: DuplexStream,
    served: tokio::task::JoinHandle<Result<(), String>>,
}

impl Client {
    fn new(agent: Agent) -> Self {
        let (io, theirs) = tokio::io::duplex(1 << 20);
        let served = tokio::spawn(async move { serve(theirs, &agent).await });
        Self { io, served }
    }

    async fn ask(&mut self, message: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        put_string(&mut framed, message);
        self.io.write_all(&framed).await.unwrap();
        let mut len = [0u8; 4];
        tokio::time::timeout(WAIT, self.io.read_exact(&mut len))
            .await
            .expect("an answer within 10 s")
            .unwrap();
        let mut answer = vec![0u8; u32::from_be_bytes(len) as usize];
        self.io.read_exact(&mut answer).await.unwrap();
        answer
    }

    /// The keys the agent lists, each with its comment.
    async fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        let answer = self.ask(&[REQUEST_IDENTITIES]).await;
        let mut r = Reader::new(&answer);
        assert_eq!(r.u8(), Some(IDENTITIES_ANSWER));
        let keys = (0..r.u32().unwrap())
            .map(|_| {
                let key = r.string().unwrap().to_vec();
                (
                    key,
                    String::from_utf8(r.string().unwrap().to_vec()).unwrap(),
                )
            })
            .collect();
        assert!(r.end().is_some());
        keys
    }
}

/// P3-5f-1 — the agent lists its one key, under the handle's name.
#[tokio::test]
async fn the_key_is_listed_under_the_handle() {
    let key = UserKey::ed25519();
    let mut c = Client::new(agent(&key, &[&Host::ed25519()], None));
    assert_eq!(
        c.identities().await,
        [(key.public.clone(), HANDLE.to_string())]
    );
}

/// P3-5f-1 — a sign-in to a host the secret names is signed, on a connection
/// bound to it: each key type the agent signs with, to a host of each type
/// it checks by `ring` alone, in both of OpenSSH's sign-in methods.
#[tokio::test]
async fn a_sign_in_to_a_host_the_secret_names_is_signed() {
    for key in [
        UserKey::ed25519(),
        UserKey::ecdsa(Curve::P256),
        UserKey::ecdsa(Curve::P384),
    ] {
        for host in [
            Host::ed25519(),
            Host::ecdsa(Curve::P256),
            Host::ecdsa(Curve::P384),
        ] {
            let what = format!("a {} key, to a {} host", key.key_type, host.key_type());
            let mut c = Client::new(agent(&key, &[&Host::ed25519(), &host], None));
            let session_id = random::<32>();
            assert_eq!(
                c.ask(&binding(&host, &session_id)).await,
                [SUCCESS],
                "{what}"
            );
            assert_eq!(c.identities().await.len(), 1, "{what}");
            let data = sign_in(&session_id, &key).bytes();
            let answer = c.ask(&sign_request(&key.public, &data)).await;
            assert!(key.signed(&answer, &data), "{what}: {answer:?}");
            // OpenSSH's own sign-in names the bound host's key too.
            let host_key = host.key();
            let hostbound = SignInData {
                method: HOSTBOUND,
                host_key: Some(&host_key),
                ..sign_in(&session_id, &key)
            }
            .bytes();
            let answer = c.ask(&sign_request(&key.public, &hostbound)).await;
            assert!(key.signed(&answer, &hostbound), "{what}, host-bound");
        }
    }
}

/// P3-5f-1 — nothing is signed on a connection that never binds: an `ssh`
/// older than 8.9, or any client that does not say which host it signs in to.
#[tokio::test]
async fn nothing_is_signed_on_a_connection_never_bound() {
    let key = UserKey::ed25519();
    let mut c = Client::new(agent(&key, &[&Host::ed25519()], None));
    let data = sign_in(&random::<32>(), &key).bytes();
    assert_eq!(c.ask(&sign_request(&key.public, &data)).await, [FAILURE]);
}

/// P3-5f-1 — a binding is refused unless it is to a host the secret names,
/// its signature good and not for forwarding; a refused one leaves the
/// connection listing no key and signing nothing.
#[tokio::test]
async fn a_binding_is_refused_unless_to_a_named_host_and_good() {
    let key = UserKey::ed25519();
    let host = Host::ecdsa(Curve::P256);
    let stranger = Host::ed25519();
    let session_id = random::<32>();
    let long = [7u8; MAX_SESSION_ID + 1];
    let mut after = binding(&host, &session_id);
    after.push(0);
    for (what, message) in [
        (
            "a host the secret does not name",
            binding(&stranger, &session_id),
        ),
        (
            "a signature over another session",
            bind_message(&host.key(), &session_id, &host.sign(&random::<32>()), 0),
        ),
        (
            "another host's signature",
            bind_message(&host.key(), &session_id, &stranger.sign(&session_id), 0),
        ),
        (
            "for forwarding",
            bind_message(&host.key(), &session_id, &host.sign(&session_id), 1),
        ),
        (
            "an empty session identifier",
            bind_message(&host.key(), &[], &host.sign(&[]), 0),
        ),
        ("a session identifier too long", binding(&host, &long)),
        ("bytes after it", after),
    ] {
        let mut c = Client::new(agent(&key, &[&host], None));
        assert_eq!(c.ask(&message).await, [FAILURE], "{what}");
        assert!(
            c.identities().await.is_empty(),
            "{what}: no key listed after"
        );
        let data = sign_in(&session_id, &key).bytes();
        assert_eq!(
            c.ask(&sign_request(&key.public, &data)).await,
            [FAILURE],
            "{what}: nothing signed after"
        );
    }
    // The longest session identifier OpenSSH's agent takes is taken.
    let mut c = Client::new(agent(&key, &[&host], None));
    let longest = [7u8; MAX_SESSION_ID];
    assert_eq!(c.ask(&binding(&host, &longest)).await, [SUCCESS]);
}

/// P3-5f-1 — a connection is bound once: a second binding, even the same
/// one, refuses the connection.
#[tokio::test]
async fn a_connection_is_bound_once() {
    let key = UserKey::ed25519();
    let host = Host::ed25519();
    let mut c = Client::new(agent(&key, &[&host], None));
    let session_id = random::<32>();
    assert_eq!(c.ask(&binding(&host, &session_id)).await, [SUCCESS]);
    assert_eq!(c.ask(&binding(&host, &session_id)).await, [FAILURE]);
    assert!(c.identities().await.is_empty());
    let data = sign_in(&session_id, &key).bytes();
    assert_eq!(c.ask(&sign_request(&key.public, &data)).await, [FAILURE]);
}

/// P3-5f-1 — on a bound connection, only a sign-in for its session, with the
/// key, to the bound host is signed: nothing a session might hand over as
/// "data", an `SSHSIG` among it. A refusal does not end the connection.
#[tokio::test]
async fn only_a_sign_in_for_the_bound_session_is_signed() {
    let key = UserKey::ed25519();
    let other = UserKey::ed25519();
    let host = Host::ed25519();
    let stranger = Host::ed25519().key();
    let mut c = Client::new(agent(&key, &[&host], None));
    let session_id = random::<32>();
    let another_session = random::<32>();
    assert_eq!(c.ask(&binding(&host, &session_id)).await, [SUCCESS]);
    let base = sign_in(&session_id, &key);
    let mut sshsig = b"SSHSIG".to_vec();
    sshsig.extend(strings(&[b"git", b"", b"sha512", &random::<64>()]));
    for (what, data) in [
        ("another session", sign_in(&another_session, &key).bytes()),
        (
            "another service",
            SignInData {
                service: "ssh-userauth",
                ..base
            }
            .bytes(),
        ),
        (
            "no signature to follow",
            SignInData {
                signature_follows: 0,
                ..base
            }
            .bytes(),
        ),
        (
            "another method",
            SignInData {
                method: "hostbased",
                ..base
            }
            .bytes(),
        ),
        (
            "another algorithm",
            SignInData {
                algorithm: "ecdsa-sha2-nistp256",
                ..base
            }
            .bytes(),
        ),
        (
            "another key named in it",
            SignInData {
                key: &other.public,
                ..base
            }
            .bytes(),
        ),
        (
            "host-bound to another host",
            SignInData {
                method: HOSTBOUND,
                host_key: Some(&stranger),
                ..base
            }
            .bytes(),
        ),
        (
            "host-bound with no host key",
            SignInData {
                method: HOSTBOUND,
                ..base
            }
            .bytes(),
        ),
        (
            "bytes after it",
            SignInData {
                after: b"x",
                ..base
            }
            .bytes(),
        ),
        ("an SSHSIG", sshsig),
        ("not a sign-in at all", made().into_bytes()),
    ] {
        assert_eq!(
            c.ask(&sign_request(&key.public, &data)).await,
            [FAILURE],
            "{what}"
        );
    }
    // A signature asked of a key the agent does not hold.
    let theirs = sign_in(&session_id, &other).bytes();
    assert_eq!(
        c.ask(&sign_request(&other.public, &theirs)).await,
        [FAILURE]
    );
    // And the one it may sign, still signed.
    let data = base.bytes();
    let answer = c.ask(&sign_request(&key.public, &data)).await;
    assert!(key.signed(&answer, &data));
}

/// P3-5f-1 — where the audience names a user, the key signs in as that user
/// alone; with none, as whom the host lets it.
#[tokio::test]
async fn the_audiences_user_is_the_only_one_signed_in_as() {
    let key = UserKey::ed25519();
    let host = Host::ed25519();
    let session_id = random::<32>();
    let as_root = SignInData {
        user: "root",
        ..sign_in(&session_id, &key)
    }
    .bytes();
    let as_git = sign_in(&session_id, &key).bytes();

    let mut c = Client::new(agent(&key, &[&host], Some("git")));
    assert_eq!(c.ask(&binding(&host, &session_id)).await, [SUCCESS]);
    assert_eq!(c.ask(&sign_request(&key.public, &as_root)).await, [FAILURE]);
    assert!(key.signed(&c.ask(&sign_request(&key.public, &as_git)).await, &as_git));

    let mut c = Client::new(agent(&key, &[&host], None));
    assert_eq!(c.ask(&binding(&host, &session_id)).await, [SUCCESS]);
    assert!(key.signed(&c.ask(&sign_request(&key.public, &as_root)).await, &as_root));
}

/// P3-5f-1 — everything else an agent may be asked is refused, and the
/// connection goes on: no key is added or removed, nothing locked, no other
/// extension known.
#[tokio::test]
async fn everything_else_is_refused() {
    let key = UserKey::ed25519();
    let mut c = Client::new(agent(&key, &[&Host::ed25519()], None));
    let (_, private, _) = UserKey::parts_ed25519();
    let mut add = vec![17];
    add.extend_from_slice(&private);
    add.extend(strings(&[b"added"]));
    let mut remove = vec![18];
    put_string(&mut remove, &key.public);
    let mut query = vec![EXTENSION];
    put_string(&mut query, b"query");
    let mut lock = vec![22];
    put_string(&mut lock, made().as_bytes());
    for message in [
        add,
        remove,
        vec![19],
        lock,
        vec![23],
        vec![20],
        vec![25],
        query,
        vec![1],
        vec![99],
        vec![REQUEST_IDENTITIES, 0],
    ] {
        assert_eq!(c.ask(&message).await, [FAILURE], "{message:?}");
    }
    assert_eq!(
        c.identities().await,
        [(key.public.clone(), HANDLE.to_string())],
        "the key, still the only one"
    );
}

/// P3-5f-1 — a message longer than OpenSSH's own agent takes, or an empty
/// one, ends the connection.
#[tokio::test]
async fn a_message_too_long_or_empty_ends_the_connection() {
    let key = UserKey::ed25519();
    for len in [MAX_MESSAGE + 1, 0] {
        let mut c = Client::new(agent(&key, &[&Host::ed25519()], None));
        c.io.write_all(&u32::try_from(len).unwrap().to_be_bytes())
            .await
            .unwrap();
        let served = tokio::time::timeout(WAIT, c.served)
            .await
            .expect("ended within 10 s")
            .unwrap();
        assert!(served.is_err(), "{len}");
    }
    // The longest one is read, and answered.
    let mut c = Client::new(agent(&key, &[&Host::ed25519()], None));
    let mut longest = vec![99u8];
    longest.resize(MAX_MESSAGE, 0);
    assert_eq!(c.ask(&longest).await, [FAILURE]);
}

/// P3-5f-1 — the secret's `key` is read strictly: one unencrypted OpenSSH
/// key, of a type the agent signs with, laid out as `PROTOCOL.key` says; and
/// a refusal names no byte of it.
#[test]
fn the_secrets_key_is_read_strictly() {
    let hosts = Host::ed25519().line();
    // Neither message prints the key: a failing run would put a private key
    // block in a CI log, made for the test or not.
    let refused = |pem: &str| match Agent::new(pem, &hosts, HANDLE, None) {
        Ok(_) => panic!("a key the agent must refuse was taken"),
        Err(why) => {
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            for piece in body.as_bytes().chunks(12).filter(|p| p.len() == 12) {
                assert!(
                    !why.contains(std::str::from_utf8(piece).unwrap()),
                    "a refusal holds a piece of the key"
                );
            }
            why
        }
    };
    let (public, private, pk) = UserKey::parts_ed25519();
    let file = || KeyFile::new(public.clone(), private.clone());
    assert!(Agent::new(&file().pem(), &hosts, HANDLE, None).is_ok());

    assert_eq!(refused(&made()), NOT_OPENSSH);
    assert_eq!(
        refused(&armor("SOMETHING ELSE", &unarmor(&file().pem()))),
        NOT_OPENSSH
    );
    let mut garbled = file().pem().into_bytes();
    let middle = garbled.len() / 2;
    garbled[middle] = b'!';
    assert_eq!(refused(&String::from_utf8(garbled).unwrap()), NOT_OPENSSH);
    let encrypted = KeyFile {
        cipher: "aes256-ctr",
        kdf: "bcrypt",
        ..file()
    };
    assert_eq!(refused(&encrypted.pem()), ENCRYPTED);
    assert!(refused(&KeyFile { keys: 2, ..file() }.pem()).contains("more than one key"));
    let checks = KeyFile {
        checks: (1, 2),
        ..file()
    };
    assert_eq!(refused(&checks.pem()), NOT_A_KEY);
    let padding = KeyFile {
        padding: Some(vec![1, 3]),
        ..file()
    };
    assert_eq!(refused(&padding.pem()), NOT_A_KEY);
    let (other_public, _, _) = UserKey::parts_ed25519();
    assert!(refused(&KeyFile::new(other_public, private.clone()).pem()).contains("not its own"));
    // The secret half's second part is the public key again: a seed with
    // another key's public half is no key pair.
    let (_, _, other_pk) = UserKey::parts_ed25519();
    let mismatched = strings(&[
        b"ssh-ed25519",
        &pk,
        &[&random::<32>()[..], &other_pk[..]].concat(),
    ]);
    assert_eq!(
        refused(&KeyFile::new(public.clone(), mismatched).pem()),
        NOT_A_KEY
    );
    for key_type in [
        "ssh-rsa",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "ssh-dss",
    ] {
        let fields = strings(&[key_type.as_bytes(), &random::<32>()]);
        assert_eq!(
            refused(&KeyFile::new(strings(&[key_type.as_bytes()]), fields).pem()),
            UNSIGNABLE,
            "{key_type}"
        );
    }
}

/// P3-5f-1 — the secret's `host_keys` are read strictly: each line a key of
/// a type the agent checks a host by, written alone; host names before it,
/// as `known_hosts` writes them, are refused rather than ignored.
#[test]
fn the_secrets_host_keys_are_read_strictly() {
    let key = UserKey::ed25519();
    let host = Host::ed25519();
    let other = Host::ecdsa(Curve::P384);
    let taken = |text: &str| Agent::new(&key.pem, text, HANDLE, None).map(|a| a.hosts);
    assert_eq!(
        taken(&format!(
            "# the hosts\r\n{} a comment\r\n\r\n{}\r\n",
            host.line(),
            other.line()
        ))
        .unwrap(),
        [host.key(), other.key()]
    );
    for (what, text) in [
        ("no line", String::new()),
        ("only a comment", "# none here\n\n".to_string()),
        (
            "host names before it",
            format!("example.test {}", host.line()),
        ),
        (
            "a type the agent cannot check",
            format!("ssh-dss {}", b64(&host.key())),
        ),
        ("a type alone", "ssh-ed25519".to_string()),
        ("not base64", "ssh-ed25519 !!!!".to_string()),
        (
            "another type than it holds",
            format!("ssh-rsa {}", b64(&host.key())),
        ),
        (
            "a key cut short",
            format!("ssh-ed25519 {}", b64(&host.key()[..20])),
        ),
    ] {
        assert!(taken(&text).is_err(), "{what}");
    }
}

/// `ssh-keygen`'s own key in `dir`: its private file and its public line.
fn keygen(dir: &std::path::Path, name: &str, passphrase: &str, args: &[&str]) -> (String, String) {
    let path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-N", passphrase, "-C", "made-for-the-test", "-f"])
        .arg(&path)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "ssh-keygen {args:?}");
    let private = std::fs::read_to_string(&path).unwrap();
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (private, public)
}

/// P3-5f-1 — the keys `ssh-keygen` writes are read as it wrote them: an
/// Ed25519 or ECDSA key listed as its `.pub` names it; an RSA or a P-521
/// one refused for its type, and an encrypted one for its passphrase.
#[tokio::test]
async fn keys_ssh_keygen_writes_are_read() {
    if !present("ssh-keygen") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let hosts = Host::ed25519().line();
    for (name, args) in [
        ("ed25519", &["-t", "ed25519"][..]),
        ("p256", &["-t", "ecdsa", "-b", "256"]),
        ("p384", &["-t", "ecdsa", "-b", "384"]),
    ] {
        let (private, public) = keygen(dir.path(), name, "", args);
        let agent =
            Agent::new(&private, &hosts, HANDLE, None).unwrap_or_else(|e| panic!("{name}: {e}"));
        let listed = public.split_ascii_whitespace().nth(1).unwrap();
        let mut c = Client::new(agent);
        assert_eq!(
            c.identities().await,
            [(
                base64::engine::general_purpose::STANDARD
                    .decode(listed)
                    .unwrap(),
                HANDLE.to_string()
            )],
            "{name}"
        );
    }
    for (name, args) in [
        ("rsa", &["-t", "rsa", "-b", "2048"][..]),
        ("p521", &["-t", "ecdsa", "-b", "521"]),
    ] {
        let (private, _) = keygen(dir.path(), name, "", args);
        assert_eq!(
            Agent::new(&private, &hosts, HANDLE, None).err().as_deref(),
            Some(UNSIGNABLE),
            "{name}"
        );
    }
    let (private, _) = keygen(dir.path(), "encrypted", &made(), &["-t", "ed25519"]);
    assert_eq!(
        Agent::new(&private, &hosts, HANDLE, None).err().as_deref(),
        Some(ENCRYPTED)
    );
}

/// P3-5f-1 — a host whose key is RSA is bound by its `rsa-sha2-512` or
/// `rsa-sha2-256` signature; `ssh-rsa`'s, which is SHA-1, is refused. The
/// host's key is made by `ssh-keygen` and signs with `ring`.
#[tokio::test]
async fn an_rsa_host_is_bound_by_a_sha2_signature() {
    if !present("ssh-keygen") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = keygen(
        dir.path(),
        "host",
        "",
        &["-t", "rsa", "-b", "2048", "-m", "PKCS8"],
    );
    let pair = RsaKeyPair::from_pkcs8(&unarmor(&private)).unwrap();
    let line = public
        .split_ascii_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let host_key = base64::engine::general_purpose::STANDARD
        .decode(line.split_ascii_whitespace().nth(1).unwrap())
        .unwrap();
    // The key `ssh-keygen` names is the one `ring` signs with.
    let components = sig::RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
    let mut own = strings(&[b"ssh-rsa"]);
    put_mpint(&mut own, &components.e);
    put_mpint(&mut own, &components.n);
    assert_eq!(own, host_key);

    let key = UserKey::ed25519();
    for (algorithm, padding, taken) in [
        ("rsa-sha2-512", &sig::RSA_PKCS1_SHA512, true),
        ("rsa-sha2-256", &sig::RSA_PKCS1_SHA256, true),
        ("ssh-rsa", &sig::RSA_PKCS1_SHA256, false),
    ] {
        let session_id = random::<32>();
        let mut signature = vec![0u8; pair.public().modulus_len()];
        pair.sign(padding, &SystemRandom::new(), &session_id, &mut signature)
            .unwrap();
        let signed = strings(&[algorithm.as_bytes(), &signature]);
        let mut c = Client::new(Agent::new(&key.pem, &line, HANDLE, None).unwrap());
        let answer = c
            .ask(&bind_message(&host_key, &session_id, &signed, 0))
            .await;
        assert_eq!(
            answer,
            [if taken { SUCCESS } else { FAILURE }],
            "{algorithm}"
        );
    }
}

/// Run OpenSSH's own `ssh` to `git@127.0.0.1:<port>`, its agent `agent`
/// served on a socket in `dir`, checking the host by `known_hosts` alone.
#[cfg(all(unix, feature = "ssh-server"))]
async fn ssh_through(
    agent: Agent,
    dir: &std::path::Path,
    name: &str,
    port: u16,
    known_hosts: &std::path::Path,
) -> std::process::Output {
    let socket = dir.join(format!("{name}.sock"));
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let agent = std::sync::Arc::new(agent);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let agent = agent.clone();
            tokio::spawn(async move {
                let _ = serve(s, &agent).await;
            });
        }
    });
    crate::vault_proxy::testing::run_ssh(&socket, port, known_hosts).await
}

/// P3-5f-1 — OpenSSH's own `ssh` signs in through the agent. It binds the
/// agent's connection to the host it reached; the agent checks that binding
/// against the host's own key-exchange signature and signs the sign-in,
/// which the host (russh) checks and accepts. Each key type the agent signs
/// with. To a host the secret does not name, the same `ssh` is refused.
#[cfg(all(unix, feature = "ssh-server"))]
#[tokio::test]
async fn openssh_signs_in_through_the_agent_to_a_named_host_only() {
    use crate::vault_proxy::testing::sshd;
    use russh::keys::ssh_key;
    if !present("ssh") {
        return;
    }
    let host_key =
        ssh_key::PrivateKey::from_openssh(crate::ssh::generate_host_key().unwrap()).unwrap();
    let host_line = host_key.public_key().to_openssh().unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (name, key) in [
        ("ed25519", UserKey::ed25519()),
        ("p256", UserKey::ecdsa(Curve::P256)),
        ("p384", UserKey::ecdsa(Curve::P384)),
    ] {
        let allowed = ssh_key::PublicKey::from_bytes(&key.public).unwrap();
        let port = sshd(host_key.clone(), allowed).await;
        let known_hosts = dir.path().join(format!("{name}.known_hosts"));
        std::fs::write(&known_hosts, format!("[127.0.0.1]:{port} {host_line}\n")).unwrap();

        let named = Agent::new(&key.pem, &host_line, HANDLE, Some("git")).unwrap();
        let out = ssh_through(named, dir.path(), name, port, &known_hosts).await;
        let log = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name}: {log}");
        assert!(
            log.contains("bound agent to hostkey"),
            "{name}: ssh bound the agent: {log}"
        );

        let other = Agent::new(&key.pem, &Host::ed25519().line(), HANDLE, Some("git")).unwrap();
        let out = ssh_through(
            other,
            dir.path(),
            &format!("{name}-other"),
            port,
            &known_hosts,
        )
        .await;
        let log = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{name}: signed in to a host the secret does not name"
        );
        assert!(log.contains("Permission denied"), "{name}: {log}");
    }
}

/// P3-5f-1 — `ssh-add`, OpenSSH's own agent client, lists the key as the
/// agent answers it, and cannot remove it.
#[cfg(unix)]
#[tokio::test]
async fn ssh_add_lists_the_key_and_cannot_remove_it() {
    if !present("ssh-add") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let key = UserKey::ed25519();
    let agent = agent(&key, &[&Host::ed25519()], None);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let _ = serve(s, &agent).await;
        }
    });
    let ssh_add = |arg: &'static str| {
        let socket = socket.clone();
        async move {
            tokio::time::timeout(
                WAIT,
                tokio::process::Command::new("ssh-add")
                    .arg(arg)
                    .env("SSH_AUTH_SOCK", &socket)
                    .output(),
            )
            .await
            .expect("ssh-add within 10 s")
            .unwrap()
        }
    };
    let listed = ssh_add("-L").await;
    assert!(listed.status.success(), "{listed:?}");
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap(),
        format!("ssh-ed25519 {} {HANDLE}\n", b64(&key.public))
    );
    let removed = ssh_add("-D").await;
    assert!(!removed.status.success(), "{removed:?}");
    let listed = ssh_add("-L").await;
    assert!(
        String::from_utf8(listed.stdout)
            .unwrap()
            .contains(&b64(&key.public))
    );
}
