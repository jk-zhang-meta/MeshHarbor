// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5f-1 — the SSH agent's session: one client connection on the
//! endpoint, answered as an SSH agent that holds the secret's one key and
//! signs a sign-in to one of the secret's hosts, and nothing else.
//!
//! | Message | What it is answered |
//! |---|---|
//! | `REQUEST_IDENTITIES` | the key, under the handle's name; no key on a connection whose binding was refused |
//! | `session-bind@openssh.com` | the host's signature over the session identifier checked with the host's key, which must be one of the secret's `host_keys`; a connection bound once only, and never for forwarding. `SUCCESS`, or `FAILURE` and the connection refused |
//! | `SIGN_REQUEST` | a signature only for an SSH sign-in (RFC 4252 §7) with the key, on a bound connection, carrying its session identifier, and as the audience's user where it names one |
//! | anything else | `FAILURE`: adding or removing keys, `LOCK`, smartcards, every other extension |
//!
//! ⚠️ A connection that never binds is signed nothing. OpenSSH 8.9 and later
//! binds each agent connection before it signs (`get_agent_identities` in its
//! `sshconnect2.c`), so a signature is good for one SSH session with a host
//! the secret names, and nowhere else: OpenSSH's own destination constraint
//! (`ssh-add -h`), made the only mode.
//!
//! ⚠️ Nothing but a sign-in is signed: an `SSHSIG` (`ssh-keygen -Y sign`,
//! git's commit signing), a challenge, anything a session might hand over
//! as "data". Any of those would be the key's signature on the session's
//! say-so, good wherever that key is trusted.
//!
//! ⚠️ The key never crosses the endpoint. Its bytes are zeroized where this
//! module holds them; `ring`'s key pair, which holds the key while the
//! connection lasts, is not zeroed when it is dropped.

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, Ed25519KeyPair,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;
use zeroize::Zeroizing;

/// The longest message a client may send: the limit OpenSSH's own agent
/// keeps (`AGENT_MAX_LEN`).
const MAX_MESSAGE: usize = 256 * 1024;
/// The longest session identifier a binding may name (`AGENT_MAX_SID_LEN`).
const MAX_SESSION_ID: usize = 128;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
/// RFC 4252 §6: `SSH_MSG_USERAUTH_REQUEST`, which a sign-in's data names.
const USERAUTH_REQUEST: u8 = 50;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// OpenSSH's sign-in that also names the host's key (`PROTOCOL` §2.6).
const HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// The PEM label OpenSSH writes its private keys under. The armor is read
/// around it, so no whole header is ever written out here.
pub(super) const LABEL: &str = "OPENSSH PRIVATE KEY";
/// `PROTOCOL.key`'s `AUTH_MAGIC`, with the NUL OpenSSH writes after it.
pub(super) const MAGIC: &[u8] = b"openssh-key-v1\0";

const NOT_OPENSSH: &str = "key is not an OpenSSH private key (the format ssh-keygen writes, \
                           its armor labelled OPENSSH PRIVATE KEY)";
const ENCRYPTED: &str = "key is encrypted under a passphrase: store it unencrypted (ssh-keygen \
                         -p -N ''), since the vault is its encryption";
const NOT_A_KEY: &str = "key does not hold a key pair the agent can sign with";
const UNSIGNABLE: &str = "key is of a type the agent does not sign with: Ed25519, or ECDSA on \
                          P-256 or P-384 (ssh-keygen -t ed25519)";

/// The curves the agent signs and checks on (RFC 5656). `ring` has no P-521.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
}

impl Curve {
    /// The curve a key type names.
    fn of(key_type: &[u8]) -> Option<Self> {
        match key_type {
            b"ecdsa-sha2-nistp256" => Some(Self::P256),
            b"ecdsa-sha2-nistp384" => Some(Self::P384),
            _ => None,
        }
    }

    fn key_type(self) -> &'static str {
        match self {
            Self::P256 => "ecdsa-sha2-nistp256",
            Self::P384 => "ecdsa-sha2-nistp384",
        }
    }

    /// The curve's name, as a key names it after its type.
    fn name(self) -> &'static [u8] {
        match self {
            Self::P256 => b"nistp256",
            Self::P384 => b"nistp384",
        }
    }

    /// The length of a scalar on it, and of each half of a signature.
    fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    fn signing(self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Self::P256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Self::P384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        }
    }

    fn verifying(self) -> &'static EcdsaVerificationAlgorithm {
        match self {
            Self::P256 => &signature::ECDSA_P256_SHA256_FIXED,
            Self::P384 => &signature::ECDSA_P384_SHA384_FIXED,
        }
    }
}

/// The secret's key, as the agent signs with it.
enum Signer {
    Ed25519(Ed25519KeyPair),
    Ecdsa(EcdsaKeyPair, Curve),
}

/// What one connection's agent holds: the key, and the hosts it signs a
/// sign-in to.
pub(crate) struct Agent {
    signer: Signer,
    /// The key's public half, as SSH writes it: what a client names it by.
    public: Vec<u8>,
    /// Its type, as a sign-in names its algorithm.
    key_type: &'static str,
    /// What `REQUEST_IDENTITIES` calls it.
    comment: String,
    /// The keys of the hosts a connection may be bound to, as SSH writes them.
    hosts: Vec<Vec<u8>>,
    /// The one account it signs in as, where the audience names one.
    user: Option<String>,
}

impl Agent {
    /// The agent for the secret's `key` (an OpenSSH private key) and
    /// `host_keys` (one `<type> <base64>` per line), named `comment`, signing
    /// in as `user` alone where the audience names one. An `Err` says what is
    /// wrong, and never holds a byte of either value.
    pub(crate) fn new(
        key: &str,
        host_keys: &str,
        comment: &str,
        user: Option<&str>,
    ) -> Result<Self, String> {
        let (signer, public, key_type) = private_key(key)?;
        Ok(Self {
            signer,
            public,
            key_type,
            comment: comment.to_string(),
            hosts: hosts(host_keys)?,
            user: user.map(str::to_string),
        })
    }

    /// P3-5f-2 — the secret's host keys as `known_hosts` lines for `host`
    /// (`[host]:port` where the port is not 22), so the session's `ssh`
    /// checks the host by the very keys the agent binds to. Public keys
    /// only: nothing in them is secret.
    pub(crate) fn known_hosts(&self, host: &str, port: u16) -> String {
        let name = if port == 22 {
            host.to_string()
        } else {
            format!("[{host}]:{port}")
        };
        let mut out = String::new();
        for key in &self.hosts {
            // `hosts` read each one's type already: it is there, and text.
            let key_type = Reader::new(key).text().unwrap_or_default();
            let encoded = base64::engine::general_purpose::STANDARD.encode(key);
            out.push_str(&format!("{name} {key_type} {encoded}\n"));
        }
        out
    }

    /// `IDENTITIES_ANSWER`: the key, unless the connection's binding was
    /// refused.
    fn identities(&self, binding: &Binding) -> Vec<u8> {
        let mut out = vec![IDENTITIES_ANSWER];
        if matches!(binding, Binding::Refused) {
            put_u32(&mut out, 0);
        } else {
            put_u32(&mut out, 1);
            put_string(&mut out, &self.public);
            put_string(&mut out, self.comment.as_bytes());
        }
        out
    }

    /// `SIGN_RESPONSE` for a sign-in this agent may sign, or `None`.
    fn sign_request(&self, binding: &Binding, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let (key, data, _flags) = (r.string()?, r.string()?, r.u32()?);
        r.end()?;
        if key != self.public.as_slice() {
            return None;
        }
        let Binding::Bound {
            session_id,
            host_key,
        } = binding
        else {
            debug!("ssh agent: a signature asked on a connection not bound to a host");
            return None;
        };
        let Some(sign_in) = SignIn::parse(data) else {
            debug!("ssh agent: a signature asked for data that is not a sign-in");
            return None;
        };
        let to_bound_host = sign_in.host_key.is_none_or(|h| h == host_key.as_slice());
        let as_named_user = self.user.as_deref().is_none_or(|u| sign_in.user == u);
        if sign_in.session_id != session_id.as_slice()
            || sign_in.algorithm != self.key_type
            || sign_in.key != self.public.as_slice()
            || !to_bound_host
            || !as_named_user
        {
            debug!("ssh agent: a sign-in that is not for the bound session, key, host and user");
            return None;
        }
        let mut out = vec![SIGN_RESPONSE];
        put_string(&mut out, &self.sign(data)?);
        Some(out)
    }

    /// The key's signature on `data`, as SSH writes one (RFC 8709, RFC 5656).
    fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        match &self.signer {
            Signer::Ed25519(pair) => {
                put_string(&mut out, b"ssh-ed25519");
                put_string(&mut out, pair.sign(data).as_ref());
            }
            Signer::Ecdsa(pair, curve) => {
                let fixed = pair.sign(&SystemRandom::new(), data).ok()?;
                let (r, s) = fixed.as_ref().split_at(curve.scalar_len());
                let mut blob = Vec::new();
                put_mpint(&mut blob, r);
                put_mpint(&mut blob, s);
                put_string(&mut out, curve.key_type().as_bytes());
                put_string(&mut out, &blob);
            }
        }
        Some(out)
    }
}

/// What a connection's agent knows of the SSH session it signs for.
enum Binding {
    /// No `session-bind@openssh.com` yet: the key is listed, and nothing
    /// signed.
    Unbound,
    /// Bound to one SSH session with one of the secret's hosts.
    Bound {
        session_id: Vec<u8>,
        host_key: Vec<u8>,
    },
    /// A binding refused, or a second one asked for: nothing more is listed
    /// or signed on this connection.
    Refused,
}

/// Serve one client connection until it closes: each message answered in
/// turn. An `Err` says why the connection was dropped.
pub(crate) async fn serve<C>(mut client: C, agent: &Agent) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut binding = Binding::Unbound;
    while let Some(message) = read_message(&mut client).await? {
        let answer = answer(agent, &mut binding, &message);
        let mut framed = Vec::with_capacity(4 + answer.len());
        put_string(&mut framed, &answer);
        client.write_all(&framed).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// One message's answer.
fn answer(agent: &Agent, binding: &mut Binding, message: &[u8]) -> Vec<u8> {
    let (kind, body) = (message[0], &message[1..]);
    match kind {
        REQUEST_IDENTITIES if body.is_empty() => agent.identities(binding),
        SIGN_REQUEST => agent
            .sign_request(binding, body)
            .unwrap_or_else(|| vec![FAILURE]),
        EXTENSION => extension(agent, binding, body),
        _ => vec![FAILURE],
    }
}

/// `SSH_AGENTC_EXTENSION`: `session-bind@openssh.com` alone is known.
fn extension(agent: &Agent, binding: &mut Binding, body: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(body);
    if r.string() != Some(SESSION_BIND) {
        return vec![FAILURE];
    }
    // A connection is bound once: ssh binds it before it lists keys, and
    // never again.
    if !matches!(binding, Binding::Unbound) {
        debug!("ssh agent: a second binding asked for: the connection is refused");
        *binding = Binding::Refused;
        return vec![FAILURE];
    }
    match bind(agent, r) {
        Some(bound) => {
            *binding = bound;
            vec![SUCCESS]
        }
        None => {
            *binding = Binding::Refused;
            vec![FAILURE]
        }
    }
}

/// A binding this agent accepts: the host's key one of the secret's, its
/// signature over the session identifier good, and not for forwarding.
fn bind(agent: &Agent, mut r: Reader<'_>) -> Option<Binding> {
    let (host_key, session_id, sig) = (r.string()?, r.string()?, r.string()?);
    let forwarding = r.u8()?;
    r.end()?;
    if forwarding != 0 {
        debug!("ssh agent: a binding for forwarding refused");
        return None;
    }
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return None;
    }
    if !agent.hosts.iter().any(|h| h.as_slice() == host_key) {
        debug!("ssh agent: a binding to a host the secret does not name refused");
        return None;
    }
    if !HostKey::parse(host_key)?.verifies(sig, session_id) {
        debug!("ssh agent: a binding whose signature does not verify refused");
        return None;
    }
    Some(Binding::Bound {
        session_id: session_id.to_vec(),
        host_key: host_key.to_vec(),
    })
}

/// An SSH sign-in, as a client asks for its signature (RFC 4252 §7, and
/// OpenSSH's `publickey-hostbound-v00@openssh.com`): read as strictly as
/// OpenSSH's agent reads one (`parse_userauth_request`).
struct SignIn<'a> {
    session_id: &'a [u8],
    user: &'a str,
    algorithm: &'a str,
    key: &'a [u8],
    host_key: Option<&'a [u8]>,
}

impl<'a> SignIn<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(data);
        let session_id = r.string()?;
        if session_id.is_empty() || r.u8()? != USERAUTH_REQUEST {
            return None;
        }
        let (user, service, method) = (r.text()?, r.text()?, r.text()?);
        if r.u8()? != 1 || service != "ssh-connection" {
            return None;
        }
        let (algorithm, key) = (r.text()?, r.string()?);
        let host_key = match method {
            "publickey" => None,
            HOSTBOUND => Some(r.string()?),
            _ => return None,
        };
        r.end()?;
        Some(Self {
            session_id,
            user,
            algorithm,
            key,
            host_key,
        })
    }
}

/// A host's public key, as the agent checks a binding's signature with it.
enum HostKey<'a> {
    Ed25519(&'a [u8]),
    Ecdsa(Curve, &'a [u8]),
    /// RFC 8332, its exponent and modulus with no leading zero.
    Rsa {
        e: &'a [u8],
        n: &'a [u8],
    },
}

impl<'a> HostKey<'a> {
    fn parse(blob: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(blob);
        let key_type = r.string()?;
        let key = match key_type {
            b"ssh-ed25519" => {
                let pk = r.string()?;
                (pk.len() == 32).then_some(Self::Ed25519(pk))?
            }
            b"ssh-rsa" => {
                let (e, n) = (r.mpint()?, r.mpint()?);
                (!e.is_empty() && !n.is_empty()).then_some(Self::Rsa { e, n })?
            }
            _ => {
                let curve = Curve::of(key_type)?;
                if r.string()? != curve.name() {
                    return None;
                }
                Self::Ecdsa(curve, r.string()?)
            }
        };
        r.end()?;
        Some(key)
    }

    /// Whether `sig` (as SSH writes a signature) is this key's on `data`.
    fn verifies(&self, sig: &[u8], data: &[u8]) -> bool {
        let mut r = Reader::new(sig);
        let (Some(algorithm), Some(blob)) = (r.string(), r.string()) else {
            return false;
        };
        if r.end().is_none() {
            return false;
        }
        match *self {
            Self::Ed25519(pk) => {
                algorithm == b"ssh-ed25519"
                    && UnparsedPublicKey::new(&signature::ED25519, pk)
                        .verify(data, blob)
                        .is_ok()
            }
            Self::Ecdsa(curve, point) => {
                if algorithm != curve.key_type().as_bytes() {
                    return false;
                }
                let mut halves = Reader::new(blob);
                let (Some(r), Some(s)) = (halves.mpint(), halves.mpint()) else {
                    return false;
                };
                let width = curve.scalar_len();
                let (Some(mut fixed), Some(s)) = (fixed(r, width), fixed(s, width)) else {
                    return false;
                };
                fixed.extend_from_slice(&s);
                halves.end().is_some()
                    && UnparsedPublicKey::new(curve.verifying(), point)
                        .verify(data, &fixed)
                        .is_ok()
            }
            Self::Rsa { e, n } => {
                // `ssh-rsa`'s own signature is SHA-1, which OpenSSH stopped
                // accepting in 8.8: refused.
                let params = match algorithm {
                    b"rsa-sha2-256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                    b"rsa-sha2-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => return false,
                };
                // A signature may come shorter than the modulus, its leading
                // zeros dropped (OpenSSH pads it back in `ssh_rsa_verify`).
                let Some(padded) = fixed(blob, n.len()) else {
                    return false;
                };
                RsaPublicKeyComponents { n, e }
                    .verify(params, data, &padded)
                    .is_ok()
            }
        }
    }
}

/// What a PEM block labelled [`LABEL`] holds between its two armor lines.
fn armored(pem: &str) -> Option<&str> {
    let rest = pem
        .trim()
        .strip_prefix("-----BEGIN ")?
        .strip_prefix(LABEL)?
        .strip_prefix("-----")?;
    rest.strip_suffix("-----")?
        .strip_suffix(LABEL)?
        .strip_suffix("-----END ")
}

/// The secret's `key`: its signer, its public half as SSH writes it, and its
/// type. `PROTOCOL.key`, unencrypted, one key.
fn private_key(pem: &str) -> Result<(Signer, Vec<u8>, &'static str), String> {
    let body = armored(pem).ok_or(NOT_OPENSSH)?;
    let armored: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_ascii_whitespace()).collect());
    let raw = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(armored.as_bytes())
            .map_err(|_| NOT_OPENSSH)?,
    );
    let mut r = Reader::new(&raw);
    if r.take(MAGIC.len()) != Some(MAGIC) {
        return Err(NOT_OPENSSH.into());
    }
    let (cipher, kdf, kdf_options) = (
        r.string().ok_or(NOT_OPENSSH)?,
        r.string().ok_or(NOT_OPENSSH)?,
        r.string().ok_or(NOT_OPENSSH)?,
    );
    if cipher != b"none" || kdf != b"none" {
        return Err(ENCRYPTED.into());
    }
    if !kdf_options.is_empty() {
        return Err(NOT_OPENSSH.into());
    }
    if r.u32().ok_or(NOT_OPENSSH)? != 1 {
        return Err("key holds more than one key: a secret holds one".into());
    }
    let public = r.string().ok_or(NOT_OPENSSH)?.to_vec();
    let private = r.string().ok_or(NOT_OPENSSH)?;
    r.end().ok_or(NOT_OPENSSH)?;

    let mut p = Reader::new(private);
    let (check, again) = (p.u32().ok_or(NOT_A_KEY)?, p.u32().ok_or(NOT_A_KEY)?);
    if check != again {
        return Err(NOT_A_KEY.into());
    }
    let key_type = p.string().ok_or(NOT_A_KEY)?;
    let (signer, name, own_public) = match key_type {
        b"ssh-ed25519" => {
            let (pk, sk) = (p.string().ok_or(NOT_A_KEY)?, p.string().ok_or(NOT_A_KEY)?);
            // The secret half is the seed, then the public key again.
            if pk.len() != 32 || sk.len() != 64 || sk[32..] != *pk {
                return Err(NOT_A_KEY.into());
            }
            let pair =
                Ed25519KeyPair::from_seed_and_public_key(&sk[..32], pk).map_err(|_| NOT_A_KEY)?;
            let mut own = Vec::new();
            put_string(&mut own, b"ssh-ed25519");
            put_string(&mut own, pk);
            (Signer::Ed25519(pair), "ssh-ed25519", own)
        }
        _ => {
            let Some(curve) = Curve::of(key_type) else {
                return Err(UNSIGNABLE.into());
            };
            if p.string().ok_or(NOT_A_KEY)? != curve.name() {
                return Err(NOT_A_KEY.into());
            }
            let point = p.string().ok_or(NOT_A_KEY)?;
            let scalar = p.mpint().ok_or(NOT_A_KEY)?;
            let scalar = Zeroizing::new(fixed(scalar, curve.scalar_len()).ok_or(NOT_A_KEY)?);
            let pair = EcdsaKeyPair::from_private_key_and_public_key(
                curve.signing(),
                &scalar,
                point,
                &SystemRandom::new(),
            )
            .map_err(|_| NOT_A_KEY)?;
            let mut own = Vec::new();
            put_string(&mut own, curve.key_type().as_bytes());
            put_string(&mut own, curve.name());
            put_string(&mut own, point);
            (Signer::Ecdsa(pair, curve), curve.key_type(), own)
        }
    };
    p.string().ok_or(NOT_A_KEY)?; // its comment: the handle names it here
    // Then the padding: 1, 2, 3, ...
    if !p
        .rest()
        .iter()
        .enumerate()
        .all(|(i, &b)| usize::from(b) == (i + 1) & 0xff)
    {
        return Err(NOT_A_KEY.into());
    }
    if own_public != public {
        return Err("key lists a public key that is not its own".into());
    }
    Ok((signer, public, name))
}

/// The secret's `host_keys`: one key per line, `<type> <base64>`, and
/// optionally a comment after; blank lines and `#` lines skipped.
fn hosts(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut keys = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = at + 1;
        let mut words = line.split_ascii_whitespace();
        let (Some(key_type), Some(encoded)) = (words.next(), words.next()) else {
            return Err(format!(
                "host_keys line {at}: write a key as <type> <base64>"
            ));
        };
        if !matches!(
            key_type,
            "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ssh-rsa"
        ) {
            return Err(format!(
                "host_keys line {at}: a key of a type the agent cannot check a host by (ssh-ed25519, \
                 ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ssh-rsa), or host names before it: write \
                 the key alone, as known_hosts holds it after the names"
            ));
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| format!("host_keys line {at}: the key is not base64"))?;
        if Reader::new(&blob).string() != Some(key_type.as_bytes())
            || HostKey::parse(&blob).is_none()
        {
            return Err(format!(
                "host_keys line {at}: not a {key_type} key, as SSH writes one"
            ));
        }
        keys.push(blob);
    }
    if keys.is_empty() {
        return Err(
            "host_keys names no key: the agent signs a sign-in only to a host it names".into(),
        );
    }
    Ok(keys)
}

/// One message from the client: `None` when it closes between messages.
async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(format!(
            "a message of {len} bytes: the agent takes one of 1 byte to {MAX_MESSAGE}"
        ));
    }
    let mut message = vec![0u8; len];
    r.read_exact(&mut message)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(message))
}

/// SSH's wire types (RFC 4251 §5), read from a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A string that is text: UTF-8 with no NUL, as OpenSSH's
    /// `sshbuf_get_cstring` reads one.
    fn text(&mut self) -> Option<&'a str> {
        let raw = self.string()?;
        if raw.contains(&0) {
            return None;
        }
        std::str::from_utf8(raw).ok()
    }

    /// A non-negative `mpint`, its leading zeros dropped (empty for zero).
    fn mpint(&mut self) -> Option<&'a [u8]> {
        let raw = self.string()?;
        if raw.first().is_some_and(|b| b & 0x80 != 0) {
            return None;
        }
        let first = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
        Some(&raw[first..])
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    fn end(&self) -> Option<()> {
        self.buf.is_empty().then_some(())
    }
}

pub(super) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(super) fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    // Every string here is far below 4 GiB: a message is at most 256 KiB.
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

/// A non-negative integer as an `mpint`: no leading zero, and one put back
/// where the first byte would read as a sign.
pub(super) fn put_mpint(out: &mut Vec<u8>, v: &[u8]) {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let v = &v[first..];
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        put_u32(out, v.len() as u32 + 1);
        out.push(0);
        out.extend_from_slice(v);
    } else {
        put_string(out, v);
    }
}

/// A big-endian integer, its leading zeros dropped, as exactly `width`
/// bytes: `None` where it is wider. Made at its full width at once, so a
/// secret scalar is never left behind in a buffer that grew.
fn fixed(v: &[u8], width: usize) -> Option<Vec<u8>> {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let v = &v[first..];
    if v.len() > width {
        return None;
    }
    let mut out = vec![0u8; width];
    out[width - v.len()..].copy_from_slice(v);
    Some(out)
}

#[cfg(test)]
mod tests;
