// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-3 — the device's half of the vault: the key a leased value is
//! sealed to.
//!
//! The vault (`crates/modules/vault`) sends a value it leases to a session on
//! this device as a sealed box for a key only this daemon holds. That key is
//! made here: an X25519 key, made at the first hello that asks for it while
//! the device's own `vault_enabled` is on, kept in this process's memory and
//! written nowhere. Its public half rides the PRIMARY enrollment's hello
//! (`AgentHello::vault_key`), and the server stores it on every hello.
//!
//! Memory, not the config where the overlay and SSH keys live: those are
//! identities a peer pins, and a pin must outlive a restart. Nothing pins this
//! key. A leased value lives in daemon memory for its lease only, so a restart
//! ends every lease whatever becomes of the key, and a key kept on disk would
//! add one thing only: a way for whoever reads the config, or a backup of it,
//! to open a sealed value captured earlier. A new key at each start leaves
//! nothing on disk to read.
//!
//! ⚠️ Never the WireGuard key, and never on a secondary org's connection: that
//! org's server would learn a key another org's server holds too, which ties
//! the device's enrollments together (`docs/multi-org.md`).
//!
//! A build without the `vault` feature makes no key, its hello carries none,
//! and the vault leases it nothing.

/// The public half of this daemon's vault key for a hello, or the empty
/// string.
///
/// Empty unless the device's owner switched `vault_enabled` on, the
/// connection is the primary enrollment's, and this build has the `vault`
/// feature. The first call that passes makes the key; every later one gives
/// the same public half until the process ends.
pub fn hello_key(vault_enabled: bool, is_primary: bool) -> String {
    if !vault_enabled || !is_primary {
        return String::new();
    }
    public_key()
}

#[cfg(feature = "vault")]
static KEY: std::sync::OnceLock<crypto_box::SecretKey> = std::sync::OnceLock::new();

/// The process's key, made on first use.
#[cfg(feature = "vault")]
fn key() -> &'static crypto_box::SecretKey {
    KEY.get_or_init(|| {
        tracing::info!("vault: made this run's vault key (memory only)");
        crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng)
    })
}

#[cfg(feature = "vault")]
fn public_key() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key().public_key().as_bytes())
}

#[cfg(not(feature = "vault"))]
fn public_key() -> String {
    String::new()
}

/// P3-4a — whether this daemon takes leases on a connection: a build that
/// has the `vault` feature and runs agent sessions, its owner's
/// `vault_enabled`, and the primary enrollment's connection. The vault
/// answers a lease only from a connection that advertises `vault` AND whose
/// hello carried a key, so the word follows the key ([`hello_key`]).
pub fn takes_leases(vault_enabled: bool, is_primary: bool) -> bool {
    cfg!(all(feature = "vault", hive_host)) && vault_enabled && is_primary
}

/// P3-4a — `vault` in a connection's `rpc` list, on exactly the connections
/// that [`takes_leases`]. The hello and every re-announcement apply it: the
/// server replaces its stored caps with each.
pub fn apply_word(rpc: &mut Vec<String>, on: bool) {
    let word = roomler_ai_remote_control::models::RpcCap::Vault.wire();
    rpc.retain(|w| w != word);
    if on {
        rpc.push(word.to_string());
    }
}

#[cfg(feature = "vault")]
pub use client::*;

/// P3-4a — the device's lease client: ask the vault for a value over the
/// primary connection (`rc:vault.lease`), hold what it seals to this
/// daemon's key in this process's memory, and let it go at its expiry, at
/// `rc:vault.revoke`, or when its session's run ends here.
///
/// ⚠️ A value never leaves this process: [`Client::with_value`] lends it to a
/// closure and nothing returns it, and it is zeroed when it is let go.
///
/// ⚠️ A lease is held until the server's expiry as measured on this clock,
/// and never longer than the longest lease the vault grants
/// (`lease_limits::MAX_TTL_SECS`): a device whose clock runs behind cannot
/// hold a value past its lease by more than that.
#[cfg(feature = "vault")]
mod client {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use bson::oid::ObjectId;
    use roomler_ai_remote_control::signaling::ClientMsg;
    use roomler_ai_remote_control::vault::{
        LeaseRefusal, NetKind, VaultActivityKind, VaultSecretMeta, canonical_net_host, lease_limits,
    };
    use tokio::sync::{mpsc, oneshot};
    use tracing::{debug, info, warn};
    use zeroize::Zeroizing;

    use super::key;
    use crate::vault_proxy::minter;

    /// P3-6b-2b — the providers this build mints for, on the device: a lease
    /// of theirs is held (its bundle lent to no tool) and its credential
    /// minted at its first use. Every other provider's bundle is refused
    /// unopened. P3-6d-1b keeps the list with the minters it names.
    pub use crate::vault_proxy::minter::MINTS;

    /// P3-6b-2b — the mode a dynamic secret is leased in.
    pub const SHORT_LIVED: &str = "short-lived";

    /// How long a request waits for the vault's answer. A server without the
    /// vault mounted never answers one.
    pub const ANSWER_DEADLINE: Duration = Duration::from_secs(15);

    /// P3-4e-2 — how soon a request whose card waits for a person is asked
    /// again, and how seldom at most: each ask is a decision the vault
    /// records, so the pause doubles to its ceiling.
    const APPROVAL_FIRST_PAUSE: Duration = Duration::from_secs(2);
    const APPROVAL_MAX_PAUSE: Duration = Duration::from_secs(15);

    /// How often the daemon lets go of what has expired, though nothing asked.
    const PRUNE_EVERY: Duration = Duration::from_secs(5);

    /// What a session asks for.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LeaseAsk {
        pub session_id: ObjectId,
        /// The fence the session runs at here: the vault believes a request
        /// only at its record's fence.
        pub fence: u64,
        /// A path, or an RRN of this organization.
        pub secret: String,
        /// Empty for a static secret's one field.
        pub field: String,
        pub mode: String,
        pub audience: String,
        pub ttl_secs: u32,
        /// P3-4c-3 — asked for ahead (`vault_request`): a use tool asking
        /// for the same secret, mode and audience takes it, and no call lets
        /// it go. It ends at its expiry, its revocation or the run's end.
        pub ahead: bool,
    }

    /// FR-90 P3-9-2 — what a person's endpoint asks for (`meshharbor connect`,
    /// `rc:vault.connect`): one field of a secret, toward the upstream the
    /// endpoint signs in to, for the device's owner. It names no person: the
    /// vault reads the owner from the device's row.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PersonAsk {
        /// The endpoint the lease serves, by the id this daemon gave it: what
        /// lets go of its leases when it closes ([`Client::drop_person`]).
        pub endpoint: u64,
        /// A path, or an RRN of this organization.
        pub secret: String,
        /// Empty for a static secret's one field.
        pub field: String,
        pub audience: String,
        pub ttl_secs: u32,
    }

    /// FR-90 P3-9-2 — whose a held lease is: a session's run, or a person's
    /// endpoint, by the id this daemon gave it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Holder {
        Session { id: ObjectId, fence: u64 },
        Person(u64),
    }

    /// A lease this daemon holds: what it is, never its value.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LeaseInfo {
        pub lease_id: String,
        /// The run, or (P3-9-2) the person's endpoint, it was asked for: what
        /// lets it go when that ends.
        pub holder: Holder,
        pub secret: String,
        pub field: String,
        pub n: i64,
        pub mode: String,
        /// P3-4c-3 — what it was asked for toward, and whether ahead.
        pub audience: String,
        pub ahead: bool,
        /// When the server says it ends, in milliseconds of its clock.
        pub expires_at_ms: i64,
        /// P3-6b-2b — a dynamic secret's provider: the lease holds its
        /// issuer's fields, which no tool is lent, and serves the credential
        /// minted for it ([`Client::mint`], [`Client::minted`]).
        pub provider: Option<String>,
    }

    /// Why a request got no lease.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LeaseError {
        /// The vault refused, in one word: a `LeaseRefusal`'s, or a newer
        /// server's this build cannot name, which is a refusal all the same.
        Refused(String),
        /// P3-4e — the vault's policies allow this only with a person's yes,
        /// and its card waits in the session's room: the approval's id.
        /// [`Client::request_until_approved`] asks again while it waits.
        AwaitingApproval(String),
        /// No connection to ask on.
        NotConnected,
        /// No answer within the deadline.
        NoAnswer,
        /// The answer did not open with this daemon's key.
        Unopenable,
        /// FR-90 P3-7-3a — the answer grants something other than what was
        /// asked: refused here, never used.
        NotAsked,
    }

    struct Held {
        info: LeaseInfo,
        until: Instant,
        value: Zeroizing<Vec<u8>>,
        /// P3-4c-2 — files a tool wrote with this lease's value: removed
        /// whenever the lease is let go, however that happens.
        files: Vec<std::path::PathBuf>,
        /// P3-5b-2 — what a tool serves with this lease's value (a proxy
        /// endpoint): cancelled whenever the lease is let go.
        stops: Vec<tokio_util::sync::CancellationToken>,
        /// P3-6b-2b — a dynamic secret's lease: `value` is its bundle, and
        /// this is the credential minted with it.
        minting: Option<Arc<Minting>>,
    }

    /// P3-6b-2b — the credential a dynamic secret's lease serves: minted at
    /// its first use, once, and taken back when the lease is let go.
    #[derive(Default)]
    struct Minting {
        /// Held across the mint, so a second use waits for the first's
        /// credential rather than mint its own.
        once: tokio::sync::Mutex<()>,
        /// Where it stands. Letting the lease go and a mint's last step each
        /// change it under this lock, so a credential minted while the lease
        /// was let go is taken back by whichever comes second.
        state: Mutex<MintState>,
    }

    #[derive(Default)]
    enum MintState {
        #[default]
        Fresh,
        Minted(Box<(minter::Issuer, minter::Minted)>),
        /// The lease is let go: a mint that ends now takes its own credential
        /// back at once.
        Gone,
    }

    /// Let go of leases already taken out of the map: each value is zeroed as
    /// it drops, every file written with it is removed, everything served
    /// with it is stopped, and (P3-6b-2b) a credential minted for it is taken
    /// back. Answers how many.
    fn let_go(gone: Vec<Held>) -> usize {
        let n = gone.len();
        for h in gone {
            for s in &h.stops {
                s.cancel();
            }
            for f in &h.files {
                match std::fs::remove_file(f) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => warn!(
                        lease = %h.info.lease_id, path = %f.display(), %e,
                        "vault: a file written with a lease's value was not removed"
                    ),
                }
            }
            if let Some(m) = &h.minting {
                let was = std::mem::replace(&mut *lock(&m.state), MintState::Gone);
                if let MintState::Minted(role) = was {
                    revoke_later(&h.info.lease_id, *role);
                }
            }
        }
        n
    }

    /// P3-6b-2b — take a minted credential back, in the background: the
    /// revocation dials the database (from P3-6f-2, or the API server), and
    /// nothing that lets a lease go waits on it. Without a runtime to spawn
    /// on (never so in the daemon), the credential is left to the end its
    /// provider keeps (Postgres's `VALID UNTIL`, MySQL's event, a token's own
    /// expiry) and its issuer's next sweep.
    fn revoke_later(lease_id: &str, role: (minter::Issuer, minter::Minted)) {
        let lease = lease_id.to_string();
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            warn!(%lease, "vault: a minted credential was left to its end: no runtime to revoke it on");
            return;
        };
        rt.spawn(async move {
            let (issuer, minted) = role;
            match minter::revoke(&issuer, &minted).await {
                Ok(()) => {
                    info!(%lease, role = %minted.label(), "vault: a minted credential taken back")
                }
                Err(why) => warn!(
                    %lease, role = %minted.label(), %why,
                    "vault: a minted credential was not taken back: it lives to its end"
                ),
            }
        });
    }

    /// P3-4b — what a session's role may list: metadata only, and whether
    /// the vault's bound left some out.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Listing {
        pub secrets: Vec<VaultSecretMeta>,
        pub more: bool,
    }

    /// FR-90 P3-7-3a — what a session asks for its own egress
    /// (`rc:vault.net`): flows that exit through `exit`, to anywhere (SOCKS)
    /// or to one destination (a forward).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NetAsk {
        pub session_id: ObjectId,
        /// The fence the session runs at here.
        pub fence: u64,
        /// The device the flows exit through.
        pub exit: ObjectId,
        /// A forward's destination, as the session names it; `None` for SOCKS.
        pub dst: Option<(String, u16)>,
        pub ttl_secs: u32,
    }

    /// FR-90 P3-7-3a — the vault's grant of a session's own egress: what a
    /// tunnel presents at its open (`tunnel_core::driver::SessionGrantRef`).
    ///
    /// ⚠️ `token` is a credential until its end: `Debug` names the grant by
    /// its id alone, and nothing logs the token.
    #[derive(Clone, PartialEq, Eq)]
    pub struct NetGrant {
        pub grant_id: String,
        pub token: String,
        /// A forward's destination exactly as granted: its host in
        /// `canonical_net_host`'s spelling, which the device dials. `None`
        /// for SOCKS.
        pub dst: Option<(String, u16)>,
        /// When it ends, on this daemon's clock: the vault's end, and never
        /// later than the longest a grant lives (`lease_limits::MAX_TTL_SECS`)
        /// from its answer.
        pub until: Instant,
    }

    impl std::fmt::Debug for NetGrant {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NetGrant")
                .field("grant_id", &self.grant_id)
                .field("dst", &self.dst)
                .field("until", &self.until)
                .finish_non_exhaustive()
        }
    }

    impl NetGrant {
        /// What the tunnel presents at its open.
        pub fn tunnel_ref(&self) -> tunnel_core::driver::SessionGrantRef {
            tunnel_core::driver::SessionGrantRef {
                token: self.token.clone(),
                grant_id: self.grant_id.clone(),
            }
        }
    }

    /// FR-90 P3-7-3a — the grant an answer makes, if it grants what was
    /// asked: a forward its one destination in the vault's spelling, SOCKS
    /// none. An answer for anything else is refused here, never used.
    fn net_granted(
        ask: &NetAsk,
        grant_id: &str,
        token: &str,
        expires_at_ms: i64,
        host: &str,
        port: u16,
    ) -> Result<NetGrant, LeaseError> {
        let dst = match &ask.dst {
            Some((asked, asked_port)) => {
                if canonical_net_host(asked).as_deref() != Some(host) || port != *asked_port {
                    return Err(LeaseError::NotAsked);
                }
                Some((host.to_string(), port))
            }
            None if host.is_empty() && port == 0 => None,
            None => return Err(LeaseError::NotAsked),
        };
        if grant_id.is_empty() || token.is_empty() {
            return Err(LeaseError::NotAsked);
        }
        // As a lease's: the server's end on this clock, never past the ceiling.
        let left =
            (expires_at_ms - now_ms()).clamp(0, i64::from(lease_limits::MAX_TTL_SECS) * 1000);
        Ok(NetGrant {
            grant_id: grant_id.to_string(),
            token: token.to_string(),
            dst,
            until: Instant::now() + Duration::from_millis(u64::try_from(left).unwrap_or(0)),
        })
    }

    /// FR-90 P3-8-2b — what a session asks for to run one command on
    /// another device of its organization over Roomler SSH (`rc:vault.ssh`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SshAsk {
        pub session_id: ObjectId,
        /// The fence the session runs at here.
        pub fence: u64,
        /// The device the command runs on. Never this one: the vault refuses
        /// that ask.
        pub target: ObjectId,
        pub ttl_secs: u32,
    }

    /// FR-90 P3-8-2b — the vault's ticket for it, what `rc:ssh.request`
    /// presents, and what the device can show the person it asks.
    ///
    /// ⚠️ `ticket` is a credential until its end: `Debug` names it by its id
    /// alone, and nothing logs it.
    #[derive(Clone, PartialEq, Eq)]
    pub struct SshTicket {
        pub ticket_id: String,
        pub ticket: String,
        /// The target's OS as its row holds it (`linux`, `macos`, `windows`),
        /// whose shell meets the command.
        pub os: String,
        /// The account the target's policy maps, which the command runs as
        /// (an `SshAccountMode` word).
        pub account: String,
        /// When it ends, on this daemon's clock: the vault's end, and never
        /// later than the longest a lease lives from its answer.
        pub until: Instant,
    }

    impl std::fmt::Debug for SshTicket {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SshTicket")
                .field("ticket_id", &self.ticket_id)
                .field("os", &self.os)
                .field("account", &self.account)
                .field("until", &self.until)
                .finish_non_exhaustive()
        }
    }

    /// FR-90 P3-8-2b — the ticket an answer makes. The daemon cannot read
    /// a ticket's claims, and need not: the network module binds every one of
    /// them where the request arrives. What it can check is that the answer
    /// is whole.
    fn ssh_granted(
        ticket_id: &str,
        ticket: &str,
        expires_at_ms: i64,
        os: &str,
        account: &str,
    ) -> Result<SshTicket, LeaseError> {
        if ticket_id.is_empty() || ticket.is_empty() || account.is_empty() {
            return Err(LeaseError::NotAsked);
        }
        let left =
            (expires_at_ms - now_ms()).clamp(0, i64::from(lease_limits::MAX_TTL_SECS) * 1000);
        Ok(SshTicket {
            ticket_id: ticket_id.to_string(),
            ticket: ticket.to_string(),
            os: os.to_string(),
            account: account.to_string(),
            until: Instant::now() + Duration::from_millis(u64::try_from(left).unwrap_or(0)),
        })
    }

    /// What a lease request asked, as its answer is held: a session's
    /// ([`LeaseAsk`]) or (P3-9-2) a person's endpoint's ([`PersonAsk`]).
    struct Asked {
        holder: Holder,
        secret: String,
        field: String,
        mode: String,
        audience: String,
        ahead: bool,
    }

    impl From<LeaseAsk> for Asked {
        fn from(a: LeaseAsk) -> Self {
            Self {
                holder: Holder::Session {
                    id: a.session_id,
                    fence: a.fence,
                },
                secret: a.secret,
                field: a.field,
                mode: a.mode,
                audience: a.audience,
                ahead: a.ahead,
            }
        }
    }

    impl From<PersonAsk> for Asked {
        /// Always `proxy`: a person's lease serves an endpoint, never a value.
        fn from(a: PersonAsk) -> Self {
            Self {
                holder: Holder::Person(a.endpoint),
                secret: a.secret,
                field: a.field,
                mode: "proxy".into(),
                audience: a.audience,
                ahead: false,
            }
        }
    }

    /// What a request waits for, by kind.
    enum Waiting {
        Lease {
            asked: Asked,
            reply: oneshot::Sender<Result<LeaseInfo, LeaseError>>,
        },
        List {
            reply: oneshot::Sender<Result<Listing, LeaseError>>,
        },
        Describe {
            reply: oneshot::Sender<Result<VaultSecretMeta, LeaseError>>,
        },
        /// FR-90 P3-7-3a.
        Net {
            ask: NetAsk,
            reply: oneshot::Sender<Result<NetGrant, LeaseError>>,
        },
        /// FR-90 P3-8-2b.
        Ssh {
            reply: oneshot::Sender<Result<SshTicket, LeaseError>>,
        },
    }

    impl Waiting {
        /// Answer whichever request this is with `why`.
        fn fail(self, why: LeaseError) {
            match self {
                Self::Lease { reply, .. } => {
                    let _ = reply.send(Err(why));
                }
                Self::List { reply } => {
                    let _ = reply.send(Err(why));
                }
                Self::Describe { reply } => {
                    let _ = reply.send(Err(why));
                }
                Self::Net { reply, .. } => {
                    let _ = reply.send(Err(why));
                }
                Self::Ssh { reply } => {
                    let _ = reply.send(Err(why));
                }
            }
        }
    }

    /// One daemon's leases: the process has one ([`CLIENT`]), a test makes
    /// its own.
    #[derive(Default)]
    pub struct Client {
        outbound: Mutex<Option<mpsc::Sender<ClientMsg>>>,
        /// P3-4b — whether that connection takes leases: a session's vault
        /// tools are offered only then.
        takes: AtomicBool,
        /// P3-4d-2 — whether the device's owner has it report what it does
        /// with its leases (`vault_activity_log`).
        reports: AtomicBool,
        pending: Mutex<HashMap<String, Waiting>>,
        held: Mutex<HashMap<String, Held>>,
    }

    /// P3-4d-2 — one use of leased values, as the device reports it
    /// (`rc:vault.activity`): never a value.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Report {
        pub session_id: ObjectId,
        pub fence: u64,
        pub kind: VaultActivityKind,
        /// The leases whose values were used.
        pub lease_ids: Vec<String>,
        /// `exec`: the program's bare name; `render`: the file's.
        pub target: String,
        /// `exec`: how the command ended; `None` when it was killed.
        pub exit_code: Option<i32>,
        pub timed_out: bool,
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Forgets one request when its wait ends, however it ends.
    struct Forget<'a> {
        client: &'a Client,
        req_id: &'a str,
    }

    impl Drop for Forget<'_> {
        fn drop(&mut self) {
            lock(&self.client.pending).remove(self.req_id);
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn new_req_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    impl Client {
        /// The primary connection's outbound queue, from its hello on, and
        /// whether that connection takes leases.
        pub fn connected(&self, tx: mpsc::Sender<ClientMsg>, takes: bool) {
            *lock(&self.outbound) = Some(tx);
            self.takes.store(takes, Ordering::Relaxed);
        }

        /// FR-90 P3-8-2b-2 — that queue, for a frame asked under a vault
        /// answer that must leave on the connection the answer came on: a
        /// session's `rc:ssh.request`, whose ticket names this device. None
        /// before the first hello.
        pub fn outbound(&self) -> Option<mpsc::Sender<ClientMsg>> {
            lock(&self.outbound).clone()
        }

        /// P3-4b — whether the primary connection takes leases: what offers a
        /// session its vault tools.
        pub fn takes_leases(&self) -> bool {
            self.takes.load(Ordering::Relaxed)
        }

        /// P3-4d-2 — whether to report what this daemon does with its leases:
        /// the device's own `vault_activity_log`, set at each primary hello.
        pub fn set_reports(&self, on: bool) {
            self.reports.store(on, Ordering::Relaxed);
        }

        /// P3-4d-2 — tell the vault this daemon used leased values
        /// (`rc:vault.activity`), where the device's owner has it report;
        /// nothing otherwise. Fire-and-forget: a full or closed connection
        /// drops the report rather than hold the call that made it. Answers
        /// whether it was queued.
        pub fn report(&self, r: Report) -> bool {
            if !self.reports.load(Ordering::Relaxed) || r.lease_ids.is_empty() {
                return false;
            }
            let Some(tx) = lock(&self.outbound).clone() else {
                return false;
            };
            let frame = ClientMsg::VaultActivity {
                session_id: r.session_id,
                fence: r.fence,
                kind: r.kind.wire().into(),
                lease_ids: r.lease_ids,
                target: r.target,
                exit_code: r.exit_code,
                timed_out: r.timed_out,
            };
            match tx.try_send(frame) {
                Ok(()) => true,
                Err(e) => {
                    debug!(%e, "vault: an activity report was dropped");
                    false
                }
            }
        }

        /// Send `frame` as request `req_id`, waiting as `waiting`.
        fn send(&self, req_id: &str, frame: ClientMsg, waiting: Waiting) -> Result<(), LeaseError> {
            let Some(tx) = lock(&self.outbound).clone() else {
                return Err(LeaseError::NotConnected);
            };
            lock(&self.pending).insert(req_id.to_string(), waiting);
            if tx.try_send(frame).is_err() {
                lock(&self.pending).remove(req_id);
                return Err(LeaseError::NotConnected);
            }
            Ok(())
        }

        /// Wait `deadline` for request `req_id`'s answer.
        async fn wait<T>(
            &self,
            req_id: &str,
            answer: oneshot::Receiver<Result<T, LeaseError>>,
            deadline: Duration,
        ) -> Result<T, LeaseError> {
            // P3-4b — however the wait ends, its request waits no longer:
            // answered, past its deadline, or its asker gone (a cancelled
            // tool call drops this future), so nothing is left behind for a
            // server that never answers.
            let _forget = Forget {
                client: self,
                req_id,
            };
            match tokio::time::timeout(deadline, answer).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) | Err(_) => Err(LeaseError::NoAnswer),
            }
        }

        /// The requests waiting for an answer.
        #[cfg(test)]
        pub(super) fn waiting(&self) -> usize {
            lock(&self.pending).len()
        }

        /// Ask for a lease, and wait [`ANSWER_DEADLINE`] for the answer.
        pub async fn request(&self, ask: LeaseAsk) -> Result<LeaseInfo, LeaseError> {
            self.request_within(ask, ANSWER_DEADLINE).await
        }

        /// P3-4e-2 — ask for a lease, and while the vault answers that its
        /// card waits for a person, ask again: 2 s later, then twice as long
        /// each time up to 15 s, until a lease, any other answer, or `window`
        /// since the first wait (a card's own: `APPROVAL_ANSWER_SECS`). A card
        /// still waiting then is the answer. A caller that stops waiting (a
        /// cancelled tool call drops this future) stops the asking with it.
        pub async fn request_until_approved(
            &self,
            ask: LeaseAsk,
            window: Duration,
        ) -> Result<LeaseInfo, LeaseError> {
            let mut since = None;
            let mut pause = APPROVAL_FIRST_PAUSE;
            loop {
                match self.request(ask.clone()).await {
                    Err(LeaseError::AwaitingApproval(id)) => {
                        let since = *since.get_or_insert_with(tokio::time::Instant::now);
                        if since.elapsed() + pause > window {
                            return Err(LeaseError::AwaitingApproval(id));
                        }
                        tokio::time::sleep(pause).await;
                        pause = (pause * 2).min(APPROVAL_MAX_PAUSE);
                    }
                    other => return other,
                }
            }
        }

        /// Ask for a lease, and wait `deadline` for the answer.
        pub async fn request_within(
            &self,
            ask: LeaseAsk,
            deadline: Duration,
        ) -> Result<LeaseInfo, LeaseError> {
            let req_id = new_req_id();
            let frame = ClientMsg::VaultLease {
                req_id: req_id.clone(),
                session_id: ask.session_id,
                fence: ask.fence,
                secret: ask.secret.clone(),
                field: ask.field.clone(),
                mode: ask.mode.clone(),
                audience: ask.audience.clone(),
                ttl_secs: ask.ttl_secs,
            };
            let (reply, answer) = oneshot::channel();
            let asked = ask.into();
            self.send(&req_id, frame, Waiting::Lease { asked, reply })?;
            self.wait(&req_id, answer, deadline).await
        }

        /// FR-90 P3-9-2 — ask for a person's lease (`rc:vault.connect`), and
        /// wait [`ANSWER_DEADLINE`] for the answer. It is held as any lease
        /// is, for `ask.endpoint`, until its expiry, `rc:vault.revoke`, or
        /// that endpoint's end ([`Self::drop_person`]).
        pub async fn connect(&self, ask: PersonAsk) -> Result<LeaseInfo, LeaseError> {
            let req_id = new_req_id();
            let frame = ClientMsg::VaultConnect {
                req_id: req_id.clone(),
                secret: ask.secret.clone(),
                field: ask.field.clone(),
                audience: ask.audience.clone(),
                ttl_secs: ask.ttl_secs,
            };
            let (reply, answer) = oneshot::channel();
            let asked = ask.into();
            self.send(&req_id, frame, Waiting::Lease { asked, reply })?;
            self.wait(&req_id, answer, ANSWER_DEADLINE).await
        }

        /// P3-4b — what the session's role may list under `prefix`.
        pub async fn list(
            &self,
            session_id: ObjectId,
            fence: u64,
            prefix: &str,
        ) -> Result<Listing, LeaseError> {
            self.list_within(session_id, fence, prefix, ANSWER_DEADLINE)
                .await
        }

        /// P3-4b — [`Self::list`], waiting `deadline`.
        pub async fn list_within(
            &self,
            session_id: ObjectId,
            fence: u64,
            prefix: &str,
            deadline: Duration,
        ) -> Result<Listing, LeaseError> {
            let req_id = new_req_id();
            let frame = ClientMsg::VaultList {
                req_id: req_id.clone(),
                session_id,
                fence,
                prefix: prefix.to_string(),
            };
            let (reply, answer) = oneshot::channel();
            self.send(&req_id, frame, Waiting::List { reply })?;
            self.wait(&req_id, answer, deadline).await
        }

        /// P3-4b — one secret's metadata, by its path or RRN.
        pub async fn describe(
            &self,
            session_id: ObjectId,
            fence: u64,
            secret: &str,
        ) -> Result<VaultSecretMeta, LeaseError> {
            let req_id = new_req_id();
            let frame = ClientMsg::VaultDescribe {
                req_id: req_id.clone(),
                session_id,
                fence,
                secret: secret.to_string(),
            };
            let (reply, answer) = oneshot::channel();
            self.send(&req_id, frame, Waiting::Describe { reply })?;
            self.wait(&req_id, answer, ANSWER_DEADLINE).await
        }

        /// FR-90 P3-7-3a — ask the vault for a session's own egress
        /// (`rc:vault.net`): SOCKS through `ask.exit`, or a forward to one
        /// destination. The vault decides by its policies (`net:socks`,
        /// `net:forward`) and answers with a grant the tunnel presents at its
        /// open, which the network module holds every flow of it to.
        pub async fn net(&self, ask: NetAsk) -> Result<NetGrant, LeaseError> {
            let req_id = new_req_id();
            let (kind, host, port) = match &ask.dst {
                Some((host, port)) => (NetKind::Forward, host.clone(), *port),
                None => (NetKind::Socks, String::new(), 0),
            };
            let frame = ClientMsg::VaultNet {
                req_id: req_id.clone(),
                session_id: ask.session_id,
                fence: ask.fence,
                exit: ask.exit,
                kind: kind.wire().to_string(),
                host,
                port,
                ttl_secs: ask.ttl_secs,
            };
            let (reply, answer) = oneshot::channel();
            self.send(&req_id, frame, Waiting::Net { ask, reply })?;
            self.wait(&req_id, answer, ANSWER_DEADLINE).await
        }

        /// FR-90 P3-8-2b — ask the vault for a ticket to run one command on
        /// another device (`rc:vault.ssh`). The vault decides Cedar's
        /// `ssh:run` for the account the target's policy maps, and answers
        /// with a ticket the network module holds the SSH request to.
        pub async fn ssh(&self, ask: SshAsk) -> Result<SshTicket, LeaseError> {
            let req_id = new_req_id();
            let frame = ClientMsg::VaultSsh {
                req_id: req_id.clone(),
                session_id: ask.session_id,
                fence: ask.fence,
                target: ask.target,
                ttl_secs: ask.ttl_secs,
            };
            let (reply, answer) = oneshot::channel();
            self.send(&req_id, frame, Waiting::Ssh { reply })?;
            self.wait(&req_id, answer, ANSWER_DEADLINE).await
        }

        /// `rc:vault.leased`: open it, hold it, and answer the request.
        pub fn on_leased(
            &self,
            req_id: &str,
            lease_id: &str,
            n: i64,
            sealed: &str,
            expires_at_ms: i64,
            provider: Option<&str>,
        ) {
            // P3-6b — a dynamic secret's bundle: its issuer's fields. Held,
            // and lent to no tool, where this build mints for its provider
            // (P3-6b-2b); refused unopened otherwise, rather than taken for
            // a stored value.
            if let Some(provider) = provider
                && !MINTS.contains(&provider)
            {
                debug!(%lease_id, %provider, "vault: a bundle this build cannot mint with — refused unopened");
                return self.on_refused(req_id, LeaseRefusal::Unsupported.wire(), None);
            }
            let (ask, reply) = match lock(&self.pending).remove(req_id) {
                Some(Waiting::Lease { asked, reply }) => (asked, reply),
                // An answer of the wrong kind answers nothing it was asked.
                Some(other) => return other.fail(LeaseError::NoAnswer),
                None => {
                    debug!(req_id, "vault: a lease nobody here waits for — not opened");
                    return;
                }
            };
            let opened = base64::engine::general_purpose::STANDARD
                .decode(sealed)
                .ok()
                .and_then(|b| key().unseal(&b).ok())
                .map(Zeroizing::new);
            let Some(value) = opened else {
                let _ = reply.send(Err(LeaseError::Unopenable));
                return;
            };
            let left =
                (expires_at_ms - now_ms()).clamp(0, i64::from(lease_limits::MAX_TTL_SECS) * 1000);
            let until = Instant::now() + Duration::from_millis(u64::try_from(left).unwrap_or(0));
            let info = LeaseInfo {
                lease_id: lease_id.to_string(),
                holder: ask.holder,
                secret: ask.secret,
                field: ask.field,
                n,
                mode: ask.mode,
                audience: ask.audience,
                ahead: ask.ahead,
                expires_at_ms,
                provider: provider.map(String::from),
            };
            lock(&self.held).insert(
                lease_id.to_string(),
                Held {
                    info: info.clone(),
                    until,
                    value,
                    files: Vec::new(),
                    stops: Vec::new(),
                    minting: provider.map(|_| Arc::default()),
                },
            );
            if reply.send(Ok(info)).is_err() {
                // Its asker stopped waiting: nothing will use it.
                let gone = lock(&self.held).remove(lease_id);
                let_go(gone.into_iter().collect());
            }
        }

        /// `rc:vault.refused`: answer the request, whatever it asked, in the
        /// vault's word — P3-4e: `awaiting_approval` with the approval it
        /// names.
        pub fn on_refused(&self, req_id: &str, reason: &str, approval_id: Option<&str>) {
            if let Some(w) = lock(&self.pending).remove(req_id) {
                w.fail(if reason == LeaseRefusal::AwaitingApproval.wire() {
                    LeaseError::AwaitingApproval(approval_id.unwrap_or_default().to_string())
                } else {
                    LeaseError::Refused(reason.to_string())
                });
            }
        }

        /// P3-4b — `rc:vault.listed`.
        pub fn on_listed(&self, req_id: &str, secrets: Vec<VaultSecretMeta>, more: bool) {
            match lock(&self.pending).remove(req_id) {
                Some(Waiting::List { reply }) => {
                    let _ = reply.send(Ok(Listing { secrets, more }));
                }
                Some(other) => other.fail(LeaseError::NoAnswer),
                None => debug!(req_id, "vault: a listing nobody here waits for"),
            }
        }

        /// P3-4b — `rc:vault.described`.
        pub fn on_described(&self, req_id: &str, secret: VaultSecretMeta) {
            match lock(&self.pending).remove(req_id) {
                Some(Waiting::Describe { reply }) => {
                    let _ = reply.send(Ok(secret));
                }
                Some(other) => other.fail(LeaseError::NoAnswer),
                None => debug!(req_id, "vault: a description nobody here waits for"),
            }
        }

        /// FR-90 P3-7-3a — `rc:vault.net.granted`: answer the request with
        /// its grant, if it grants what was asked. Never logs the token.
        pub fn on_net_granted(
            &self,
            req_id: &str,
            grant_id: &str,
            token: &str,
            expires_at_ms: i64,
            host: &str,
            port: u16,
        ) {
            match lock(&self.pending).remove(req_id) {
                Some(Waiting::Net { ask, reply }) => {
                    let granted = net_granted(&ask, grant_id, token, expires_at_ms, host, port);
                    if granted.is_err() {
                        warn!(
                            req_id,
                            grant_id,
                            host,
                            port,
                            "vault: a grant for something other than was asked — refused"
                        );
                    }
                    let _ = reply.send(granted);
                }
                Some(other) => other.fail(LeaseError::NoAnswer),
                None => debug!(req_id, grant_id, "vault: a grant nobody here waits for"),
            }
        }

        /// FR-90 P3-8-2b — `rc:vault.ssh.granted`: answer the request with
        /// its ticket, if the answer is whole. Never logs the ticket.
        pub fn on_ssh_granted(
            &self,
            req_id: &str,
            ticket_id: &str,
            ticket: &str,
            expires_at_ms: i64,
            os: &str,
            account: &str,
        ) {
            match lock(&self.pending).remove(req_id) {
                Some(Waiting::Ssh { reply }) => {
                    let granted = ssh_granted(ticket_id, ticket, expires_at_ms, os, account);
                    if granted.is_err() {
                        warn!(
                            req_id,
                            ticket_id, "vault: a ticket that is not whole — refused"
                        );
                    }
                    let _ = reply.send(granted);
                }
                Some(other) => other.fail(LeaseError::NoAnswer),
                None => debug!(req_id, ticket_id, "vault: a ticket nobody here waits for"),
            }
        }

        /// `rc:vault.revoke`: let go of every lease it names, whatever the
        /// word. An id this daemon does not hold is ignored: a hello is told
        /// again of what an earlier process held. Answers how many went.
        pub fn on_revoke(&self, lease_ids: &[String], reason: &str) -> usize {
            let dropped = let_go(self.take_ids(lease_ids));
            if dropped > 0 {
                info!(dropped, reason, "vault: leases taken back");
            }
            dropped
        }

        /// P3-4c — a tool is done with these leases: let them go now, not at
        /// their expiry. Answers how many it held.
        pub fn release(&self, lease_ids: &[String]) -> usize {
            let_go(self.take_ids(lease_ids))
        }

        /// P3-4c-2 — `path` was written with `lease_id`'s value: it is removed
        /// when the lease is let go, however that happens. `false` when the
        /// lease is not held (any more): the caller removes the file itself.
        pub fn attach(&self, lease_id: &str, path: &std::path::Path) -> bool {
            match lock(&self.held).get_mut(lease_id) {
                Some(h) => {
                    h.files.push(path.to_path_buf());
                    true
                }
                None => false,
            }
        }

        /// P3-5b-2 — `stop` is cancelled when `lease_id` is let go, however
        /// that happens: what a tool serves with the lease's value (a proxy
        /// endpoint and its connections) ends with it. `false` when the
        /// lease is not held (any more): the caller stops itself.
        pub fn stop_with(&self, lease_id: &str, stop: tokio_util::sync::CancellationToken) -> bool {
            match lock(&self.held).get_mut(lease_id) {
                Some(h) => {
                    h.stops.push(stop);
                    true
                }
                None => false,
            }
        }

        /// P3-4c-3 — a lease asked for ahead for `ask`'s run, secret, field,
        /// mode and audience, with at least `at_least` left: the one held
        /// longest. A lease a call asked for itself is never found: that
        /// call lets it go when it ends. (`ask.ttl_secs` and `ask.ahead` are
        /// not read.)
        pub fn find_ahead(&self, ask: &LeaseAsk, at_least: Duration) -> Option<String> {
            self.prune();
            let now = Instant::now();
            lock(&self.held)
                .iter()
                .filter(|(_, h)| {
                    let i = &h.info;
                    i.ahead
                        && i.holder
                            == Holder::Session {
                                id: ask.session_id,
                                fence: ask.fence,
                            }
                        && i.secret == ask.secret
                        && i.field == ask.field
                        && i.mode == ask.mode
                        && i.audience == ask.audience
                        && h.until.saturating_duration_since(now) >= at_least
                })
                .max_by_key(|(_, h)| h.until)
                .map(|(id, _)| id.clone())
        }

        /// P3-4c-3 — how long a held lease has left by this daemon's clock.
        pub fn left(&self, lease_id: &str) -> Option<Duration> {
            let now = Instant::now();
            lock(&self.held)
                .get(lease_id)
                .map(|h| h.until.saturating_duration_since(now))
        }

        /// The run of `session` at `fence` ended here: its leases go with it.
        pub fn drop_run(&self, session: ObjectId, fence: u64) -> usize {
            let run = Holder::Session { id: session, fence };
            let_go(self.take(|h| h.info.holder == run))
        }

        /// FR-90 P3-9-2 — a person's endpoint closed: its leases go with it,
        /// and nothing any other endpoint or run holds.
        pub fn drop_person(&self, endpoint: u64) -> usize {
            let_go(self.take(|h| h.info.holder == Holder::Person(endpoint)))
        }

        /// Let go of every lease past its time.
        pub fn prune(&self) -> usize {
            let now = Instant::now();
            let_go(self.take(|h| h.until <= now))
        }

        /// The held leases `lease_ids` names, taken out of the map.
        fn take_ids(&self, lease_ids: &[String]) -> Vec<Held> {
            let mut held = lock(&self.held);
            lease_ids
                .iter()
                .filter_map(|id| held.remove(id.as_str()))
                .collect()
        }

        /// Every held lease `f` picks, taken out of the map.
        fn take(&self, f: impl Fn(&Held) -> bool) -> Vec<Held> {
            let mut held = lock(&self.held);
            let ids: Vec<String> = held
                .iter()
                .filter(|(_, h)| f(h))
                .map(|(id, _)| id.clone())
                .collect();
            ids.iter().filter_map(|id| held.remove(id)).collect()
        }

        /// Use a held value without it leaving this daemon: `None` once the
        /// lease has expired or been taken back, and (P3-6b-2b) for a
        /// dynamic secret's lease, whose bundle holds its issuer's fields:
        /// those are lent to nothing, and a tool reads the credential minted
        /// with them ([`Self::minted`]).
        pub fn with_value<R>(&self, lease_id: &str, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
            self.prune();
            lock(&self.held)
                .get(lease_id)
                .filter(|h| h.minting.is_none())
                .map(|h| f(&h.value))
        }

        /// P3-6b-2b — mint the credential a dynamic secret's lease serves, if
        /// it has none yet: once per lease, a second use waiting for the
        /// first's, by the minter its provider names (P3-6d-1b). Its end is
        /// the lease's. Err, in words that name no value, for a lease no
        /// longer held or no dynamic secret's, or a mint the issuer or its
        /// database refused.
        pub async fn mint(&self, lease_id: &str) -> Result<(), String> {
            let ended = || "the lease ended before its credential was minted".to_string();
            let (minting, provider, bundle, expires_at_ms) = {
                let held = lock(&self.held);
                let h = held.get(lease_id).ok_or_else(ended)?;
                let no = || "the lease is no dynamic secret's".to_string();
                let m = h.minting.clone().ok_or_else(no)?;
                let provider = h.info.provider.clone().ok_or_else(no)?;
                (
                    m,
                    provider,
                    Zeroizing::new(h.value.to_vec()),
                    h.info.expires_at_ms,
                )
            };
            let _one = minting.once.lock().await;
            match &*lock(&minting.state) {
                MintState::Minted(_) => return Ok(()),
                MintState::Gone => return Err(ended()),
                MintState::Fresh => {}
            }
            let issuer = minter::Issuer::from_bundle(&provider, &bundle)?;
            drop(bundle);
            let minted = minter::mint(&issuer, lease_id, expires_at_ms).await?;
            let mut state = lock(&minting.state);
            if matches!(*state, MintState::Gone) {
                drop(state);
                revoke_later(lease_id, (issuer, minted));
                return Err(
                    "the lease ended while its credential was minted: it is taken back".into(),
                );
            }
            *state = MintState::Minted(Box::new((issuer, minted)));
            info!(lease = %lease_id, "vault: a credential minted for a lease");
            Ok(())
        }

        /// P3-6b-2b — one field of the credential minted for `lease_id`, by
        /// the name a session gives it (its provider's minted fields: a
        /// database user's `user`, `password`, `host`, `port`, `database`;
        /// from P3-6f-2 a token's `token`, `server`, `ca`, `namespace`):
        /// `None` before its mint, once the lease is let go, or for any other
        /// name.
        pub fn minted(&self, lease_id: &str, field: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.prune();
            let held = lock(&self.held);
            let minting = held.get(lease_id)?.minting.as_ref()?;
            match &*lock(&minting.state) {
                MintState::Minted(role) => role
                    .1
                    .field(field)
                    .map(|v| Zeroizing::new(v.as_bytes().to_vec())),
                MintState::Fresh | MintState::Gone => None,
            }
        }

        /// What this daemon holds, never a value.
        pub fn held(&self) -> Vec<LeaseInfo> {
            self.prune();
            lock(&self.held).values().map(|h| h.info.clone()).collect()
        }

        /// How long this daemon holds a lease from now.
        #[cfg(test)]
        pub(super) fn held_for(&self, lease_id: &str) -> Option<Duration> {
            lock(&self.held)
                .get(lease_id)
                .map(|h| h.until.saturating_duration_since(Instant::now()))
        }
    }

    /// The daemon's own leases.
    pub static CLIENT: LazyLock<Client> = LazyLock::new(Client::default);

    static PRUNER: OnceLock<()> = OnceLock::new();

    /// The primary connection's outbound queue, at each of its hellos,
    /// whether it takes leases, and (P3-4d-2) whether the device reports what
    /// it does with them; the first also starts letting go of expired leases
    /// in the background.
    pub fn on_connected(tx: mpsc::Sender<ClientMsg>, takes: bool, reports: bool) {
        CLIENT.connected(tx, takes);
        CLIENT.set_reports(reports);
        PRUNER.get_or_init(|| {
            tokio::spawn(async {
                loop {
                    tokio::time::sleep(PRUNE_EVERY).await;
                    CLIENT.prune();
                }
            });
        });
    }

    /// The daemon's [`Client::on_leased`].
    pub fn on_leased(
        req_id: &str,
        lease_id: &str,
        n: i64,
        sealed: &str,
        expires_at_ms: i64,
        provider: Option<&str>,
    ) {
        CLIENT.on_leased(req_id, lease_id, n, sealed, expires_at_ms, provider);
    }

    /// The daemon's [`Client::on_refused`].
    pub fn on_refused(req_id: &str, reason: &str, approval_id: Option<&str>) {
        CLIENT.on_refused(req_id, reason, approval_id);
    }

    /// The daemon's [`Client::on_revoke`].
    pub fn on_revoke(lease_ids: &[String], reason: &str) {
        CLIENT.on_revoke(lease_ids, reason);
    }

    /// The daemon's [`Client::on_listed`].
    pub fn on_listed(req_id: &str, secrets: Vec<VaultSecretMeta>, more: bool) {
        CLIENT.on_listed(req_id, secrets, more);
    }

    /// The daemon's [`Client::on_described`].
    pub fn on_described(req_id: &str, secret: VaultSecretMeta) {
        CLIENT.on_described(req_id, secret);
    }

    /// FR-90 P3-7-3a — the daemon's [`Client::net`].
    pub async fn net(ask: NetAsk) -> Result<NetGrant, LeaseError> {
        CLIENT.net(ask).await
    }

    /// FR-90 P3-7-3a — the daemon's [`Client::on_net_granted`].
    pub fn on_net_granted(
        req_id: &str,
        grant_id: &str,
        token: &str,
        expires_at_ms: i64,
        host: &str,
        port: u16,
    ) {
        CLIENT.on_net_granted(req_id, grant_id, token, expires_at_ms, host, port);
    }

    /// FR-90 P3-8-2b — the daemon's [`Client::ssh`].
    pub async fn ssh(ask: SshAsk) -> Result<SshTicket, LeaseError> {
        CLIENT.ssh(ask).await
    }

    /// FR-90 P3-8-2b — the daemon's [`Client::on_ssh_granted`].
    pub fn on_ssh_granted(
        req_id: &str,
        ticket_id: &str,
        ticket: &str,
        expires_at_ms: i64,
        os: &str,
        account: &str,
    ) {
        CLIENT.on_ssh_granted(req_id, ticket_id, ticket, expires_at_ms, os, account);
    }

    /// The daemon's [`Client::drop_run`]: hive's supervisor calls it when a
    /// run stops being live here.
    pub fn drop_run(session: ObjectId, fence: u64) {
        let dropped = CLIENT.drop_run(session, fence);
        if dropped > 0 {
            info!(%session, fence, dropped, "vault: a run's leases let go with it");
        }
    }

    /// FR-90 P3-9-2 — the daemon's [`Client::connect`].
    pub async fn connect(ask: PersonAsk) -> Result<LeaseInfo, LeaseError> {
        CLIENT.connect(ask).await
    }

    /// FR-90 P3-9-2 — the daemon's [`Client::drop_person`]: a person's
    /// endpoint calls it as it closes.
    pub fn drop_person(endpoint: u64) {
        let dropped = CLIENT.drop_person(endpoint);
        if dropped > 0 {
            info!(
                endpoint,
                dropped, "vault: a person's endpoint's leases let go with it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off, or on a secondary org's connection, there is no key to give.
    #[test]
    fn no_key_while_off_or_on_a_secondary_connection() {
        assert_eq!(hello_key(false, true), "");
        assert_eq!(hello_key(false, false), "");
        assert_eq!(
            hello_key(true, false),
            "",
            "a secondary org never learns it"
        );
    }

    /// A build without the feature has no key to give, even switched on.
    #[cfg(not(feature = "vault"))]
    #[test]
    fn a_build_without_the_vault_has_no_key() {
        assert_eq!(hello_key(true, true), "");
    }

    /// On the primary connection: a key the server will store, and the same
    /// one at every hello this process says.
    #[cfg(feature = "vault")]
    #[test]
    fn the_primary_hello_carries_one_key_for_the_life_of_the_process() {
        use roomler_ai_remote_control::signaling::vault_key_is_well_formed;
        let first = hello_key(true, true);
        assert!(vault_key_is_well_formed(&first), "{first}");
        assert_eq!(
            hello_key(true, true),
            first,
            "a reconnect says the same key"
        );
    }

    /// What the vault seals to the published half, this process opens; a box
    /// for any other key it does not. Sealed here the way the server will,
    /// with the same crate.
    #[cfg(feature = "vault")]
    #[test]
    fn a_box_sealed_to_the_published_half_opens_here_and_no_other_does() {
        use base64::Engine;
        let rng = &mut crypto_box::aead::OsRng;
        let published = base64::engine::general_purpose::STANDARD
            .decode(hello_key(true, true))
            .unwrap();
        let to_us = crypto_box::PublicKey::from_slice(&published).unwrap();
        let sealed = to_us.seal(rng, b"canary-vault-value").unwrap();
        assert_eq!(key().unseal(&sealed).unwrap(), b"canary-vault-value");

        let other = crypto_box::SecretKey::generate(rng).public_key();
        let elsewhere = other.seal(rng, b"canary-vault-value").unwrap();
        assert!(key().unseal(&elsewhere).is_err());
        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(key().unseal(&tampered).is_err());
    }

    /// P3-4a — the word travels with the key: on the connections that take
    /// leases, once, and on no other.
    #[test]
    fn the_vault_word_follows_the_key() {
        let mut rpc = vec!["exec".to_string(), "vault".to_string()];
        apply_word(&mut rpc, false);
        assert_eq!(rpc, ["exec"]);
        apply_word(&mut rpc, true);
        apply_word(&mut rpc, true);
        assert_eq!(rpc, ["exec", "vault"], "once, however often applied");
        assert!(!takes_leases(false, true), "off");
        assert!(
            !takes_leases(true, false),
            "never a secondary org's connection"
        );
        assert_eq!(
            takes_leases(true, true),
            cfg!(all(feature = "vault", hive_host))
        );
    }

    #[cfg(feature = "vault")]
    mod client {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use base64::Engine;
        use bson::oid::ObjectId;
        use roomler_ai_remote_control::signaling::ClientMsg;
        use roomler_ai_remote_control::vault::{VaultActivityKind, VaultSecretMeta, lease_limits};
        use tokio::sync::mpsc;

        use super::super::{
            Client, Holder, LeaseAsk, LeaseError, LeaseInfo, Listing, NetAsk, NetGrant, PersonAsk,
            Report, SshAsk, SshTicket, hello_key,
        };
        use crate::vault_proxy::testing::{FakeIssuer, fake_issuer, fake_k8s, fake_mysql, made};

        fn in_ms(ms: i64) -> i64 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            i64::try_from(now).unwrap() + ms
        }

        /// A value sealed the way the vault seals it: to the half this
        /// daemon's hello publishes.
        fn sealed_for_us(value: &[u8]) -> String {
            let b64 = base64::engine::general_purpose::STANDARD;
            let to_us =
                crypto_box::PublicKey::from_slice(&b64.decode(hello_key(true, true)).unwrap())
                    .unwrap();
            b64.encode(to_us.seal(&mut crypto_box::aead::OsRng, value).unwrap())
        }

        fn ask(session: ObjectId, fence: u64) -> LeaseAsk {
            LeaseAsk {
                session_id: session,
                fence,
                secret: "db/main".into(),
                field: String::new(),
                mode: "env".into(),
                audience: String::new(),
                ttl_secs: 60,
                ahead: false,
            }
        }

        fn connected() -> (Arc<Client>, mpsc::Receiver<ClientMsg>) {
            let c = Arc::new(Client::default());
            let (tx, rx) = mpsc::channel(8);
            c.connected(tx, true);
            (c, rx)
        }

        fn meta(path: &str) -> VaultSecretMeta {
            VaultSecretMeta {
                rrn: format!("rrn:grox:secret:{path}"),
                path: path.into(),
                kind: "static".into(),
                provider: None,
                description: String::new(),
                fields: vec!["value".into()],
                audiences: Vec::new(),
                exec_allow: Vec::new(),
                tags: Vec::new(),
                disabled: false,
            }
        }

        /// P3-4b — a listing and a description go out on the connection and
        /// come back to their askers, never a value among them.
        #[tokio::test]
        async fn a_listing_and_a_description_come_back_to_their_askers() {
            let (c, mut rx) = connected();
            assert!(c.takes_leases());
            let sid = ObjectId::new();
            let lister = {
                let c = c.clone();
                tokio::spawn(async move { c.list(sid, 3, "db/").await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultList {
                    req_id,
                    session_id,
                    fence,
                    prefix,
                } => {
                    assert_eq!((session_id, fence, prefix.as_str()), (sid, 3, "db/"));
                    req_id
                }
                other => panic!("{other:?}"),
            };
            c.on_listed(&req_id, vec![meta("db/main")], true);
            assert_eq!(
                lister.await.unwrap().unwrap(),
                Listing {
                    secrets: vec![meta("db/main")],
                    more: true,
                }
            );
            let describer = {
                let c = c.clone();
                tokio::spawn(async move { c.describe(sid, 3, "db/main").await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultDescribe { req_id, secret, .. } => {
                    assert_eq!(secret, "db/main");
                    req_id
                }
                other => panic!("{other:?}"),
            };
            c.on_described(&req_id, meta("db/main"));
            assert_eq!(describer.await.unwrap().unwrap(), meta("db/main"));
        }

        /// A refusal answers whichever request it names, and an answer of the
        /// wrong kind answers nothing that was asked: no lease is held for a
        /// listing.
        #[tokio::test]
        async fn a_refusal_answers_any_request_and_a_wrong_answer_none() {
            let (c, mut rx) = connected();
            let lister = {
                let c = c.clone();
                tokio::spawn(async move { c.list(ObjectId::new(), 1, "").await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultList { req_id, .. } => req_id,
                other => panic!("{other:?}"),
            };
            c.on_refused(&req_id, "no_role", None);
            assert_eq!(
                lister.await.unwrap(),
                Err(LeaseError::Refused("no_role".into()))
            );
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 1)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            c.on_listed(&req_id, vec![meta("db/main")], false);
            assert_eq!(asker.await.unwrap(), Err(LeaseError::NoAnswer));
            assert!(c.held().is_empty());
        }

        fn req_id_of(frame: ClientMsg) -> String {
            match frame {
                ClientMsg::VaultLease { req_id, .. } | ClientMsg::VaultConnect { req_id, .. } => {
                    req_id
                }
                other => panic!("{other:?}"),
            }
        }

        fn net_ask(dst: Option<(&str, u16)>) -> NetAsk {
            NetAsk {
                session_id: ObjectId::new(),
                fence: 2,
                exit: ObjectId::new(),
                dst: dst.map(|(h, p)| (h.to_string(), p)),
                ttl_secs: 300,
            }
        }

        /// FR-90 P3-7-3a — ask for a session's egress and answer the
        /// `rc:vault.net` it sends with `answer`; the asker's result.
        async fn granted_as(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            ask: NetAsk,
            answer: impl FnOnce(&Client, &str),
        ) -> Result<NetGrant, LeaseError> {
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.net(ask).await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultNet { req_id, .. } => req_id,
                other => panic!("{other:?}"),
            };
            answer(c.as_ref(), &req_id);
            asker.await.unwrap()
        }

        /// FR-90 P3-7-3a — a session's egress goes out as `rc:vault.net`,
        /// naming what it asks, and its grant comes back to its asker: a
        /// forward's destination in the vault's one spelling, SOCKS with
        /// none, and its end no later than the ceiling from now. `Debug`
        /// never shows the token.
        #[tokio::test]
        async fn a_net_grant_comes_back_to_its_asker() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.net(net_ask(Some(("DB.Internal.", 5432)))).await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultNet {
                    req_id,
                    fence,
                    kind,
                    host,
                    port,
                    ttl_secs,
                    ..
                } => {
                    assert_eq!(
                        (fence, kind.as_str(), host.as_str(), port, ttl_secs),
                        (2, "forward", "DB.Internal.", 5432, 300)
                    );
                    req_id
                }
                other => panic!("{other:?}"),
            };
            // An end past the ceiling is held to it.
            c.on_net_granted(
                &req_id,
                "g1",
                "a.b.c",
                in_ms(3_600_000),
                "db.internal",
                5432,
            );
            let g = asker.await.unwrap().expect("granted");
            assert_eq!(g.grant_id, "g1");
            assert_eq!(g.dst, Some(("db.internal".to_string(), 5432)));
            assert!(
                g.until
                    <= Instant::now() + Duration::from_secs(u64::from(lease_limits::MAX_TTL_SECS))
            );
            assert_eq!(g.tunnel_ref().token, "a.b.c");
            assert!(!format!("{g:?}").contains("a.b.c"), "{g:?}");

            let socks = granted_as(&c, &mut rx, net_ask(None), |c, id| {
                c.on_net_granted(id, "g2", "d.e.f", in_ms(60_000), "", 0)
            })
            .await
            .expect("granted");
            assert_eq!((socks.grant_id.as_str(), socks.dst), ("g2", None));
        }

        /// FR-90 P3-7-3a — a grant for anything but what was asked is refused
        /// here, never used: another destination, another port, a destination
        /// for SOCKS, no token. A refusal answers in the vault's own word.
        #[tokio::test]
        async fn a_net_grant_for_anything_else_is_refused() {
            let (c, mut rx) = connected();
            for (dst, token, host, port) in [
                (Some(("db.internal", 5432)), "t", "other.internal", 5432),
                (Some(("db.internal", 5432)), "t", "db.internal", 22),
                (None, "t", "db.internal", 5432),
                (None, "", "", 0),
            ] {
                let got = granted_as(&c, &mut rx, net_ask(dst), |c, id| {
                    c.on_net_granted(id, "g1", token, in_ms(60_000), host, port)
                })
                .await;
                assert_eq!(got, Err(LeaseError::NotAsked), "{dst:?} {host}:{port}");
            }
            let refused = granted_as(&c, &mut rx, net_ask(None), |c, id| {
                c.on_refused(id, "no_exit", None)
            })
            .await;
            assert_eq!(refused, Err(LeaseError::Refused("no_exit".into())));
        }

        /// FR-90 P3-8-2b — ask for a ticket and answer the `rc:vault.ssh` it
        /// sends with `answer`; the asker's result.
        async fn ticketed_as(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            ask: SshAsk,
            answer: impl FnOnce(&Client, &str),
        ) -> Result<SshTicket, LeaseError> {
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.ssh(ask).await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultSsh { req_id, .. } => req_id,
                other => panic!("{other:?}"),
            };
            answer(c.as_ref(), &req_id);
            asker.await.unwrap()
        }

        /// FR-90 P3-8-2b — a session's command on another device goes out
        /// as `rc:vault.ssh`, naming what it asks, and its ticket comes back
        /// to its asker with the target's os and account, its end no later
        /// than the ceiling from now. `Debug` never shows the ticket.
        #[tokio::test]
        async fn an_ssh_ticket_comes_back_to_its_asker() {
            let (c, mut rx) = connected();
            let ask = SshAsk {
                session_id: ObjectId::new(),
                fence: 3,
                target: ObjectId::new(),
                ttl_secs: 330,
            };
            let asker = {
                let (c, ask) = (c.clone(), ask.clone());
                tokio::spawn(async move { c.ssh(ask).await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultSsh {
                    req_id,
                    session_id,
                    fence,
                    target,
                    ttl_secs,
                } => {
                    assert_eq!(
                        (session_id, fence, target, ttl_secs),
                        (ask.session_id, 3, ask.target, 330)
                    );
                    req_id
                }
                other => panic!("{other:?}"),
            };
            // An end past the ceiling is held to it.
            c.on_ssh_granted(
                &req_id,
                "k1",
                "a.b.c",
                in_ms(3_600_000),
                "linux",
                "console_user",
            );
            let t = asker.await.unwrap().expect("ticketed");
            assert_eq!(
                (
                    t.ticket_id.as_str(),
                    t.ticket.as_str(),
                    t.os.as_str(),
                    t.account.as_str()
                ),
                ("k1", "a.b.c", "linux", "console_user")
            );
            assert!(
                t.until
                    <= Instant::now() + Duration::from_secs(u64::from(lease_limits::MAX_TTL_SECS))
            );
            assert!(!format!("{t:?}").contains("a.b.c"), "{t:?}");
        }

        /// FR-90 P3-8-2b — an answer that is not whole is refused here,
        /// never used: no ticket id, no ticket, no account. A refusal answers
        /// in the vault's own word, the session's own device's included.
        #[tokio::test]
        async fn an_ssh_ticket_that_is_not_whole_is_refused() {
            let (c, mut rx) = connected();
            let ask = SshAsk {
                session_id: ObjectId::new(),
                fence: 1,
                target: ObjectId::new(),
                ttl_secs: 60,
            };
            for (id, ticket, account) in [("", "t", "daemon"), ("k", "", "daemon"), ("k", "t", "")]
            {
                let got = ticketed_as(&c, &mut rx, ask.clone(), |c, req| {
                    c.on_ssh_granted(req, id, ticket, in_ms(60_000), "linux", account)
                })
                .await;
                assert_eq!(
                    got,
                    Err(LeaseError::NotAsked),
                    "{id:?} {ticket:?} {account:?}"
                );
            }
            let refused = ticketed_as(&c, &mut rx, ask, |c, req| {
                c.on_refused(req, "bad_request", None)
            })
            .await;
            assert_eq!(refused, Err(LeaseError::Refused("bad_request".into())));
        }

        /// P3-4e-2 — the next lease request on the connection, within a
        /// minute of the test's paused clock: an ask that never comes fails
        /// the test rather than hanging it.
        async fn next_ask(rx: &mut mpsc::Receiver<ClientMsg>) -> String {
            let frame = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .expect("a lease request within a minute")
                .expect("the connection is open");
            req_id_of(frame)
        }

        /// Lease `lease_id` for (`session`, `fence`), the vault answering
        /// with `expires_at_ms`.
        async fn lease(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            lease_id: &str,
            session: ObjectId,
            fence: u64,
            expires_at_ms: i64,
        ) -> LeaseInfo {
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(session, fence)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            c.on_leased(
                &req_id,
                lease_id,
                1,
                &sealed_for_us(b"canary-vault-value"),
                expires_at_ms,
                None,
            );
            asker.await.unwrap().unwrap()
        }

        /// P3-6b — a dynamic secret's bundle of a provider this build mints
        /// nothing for: the asker is told `unsupported`, and nothing is held.
        #[tokio::test]
        async fn a_bundle_this_build_cannot_mint_with_is_refused_unopened() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(sid, 3)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            c.on_leased(
                &req_id,
                "L-bundle",
                0,
                &sealed_for_us(br#"{"audience":"https://api.github.com","fields":{}}"#),
                in_ms(60_000),
                Some("github_app"),
            );
            assert_eq!(
                asker.await.unwrap(),
                Err(LeaseError::Refused("unsupported".into()))
            );
            assert!(c.held().is_empty(), "a bundle is never held as a value");
        }

        /// P3-6b-2b — lease `lease_id` as the vault leases a dynamic secret:
        /// the frame names `postgres`, and its bundle `f`'s database, the
        /// issuer `admin` signing in with `password`.
        async fn lease_bundle(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            lease_id: &str,
            f: &FakeIssuer,
            password: &str,
        ) -> LeaseInfo {
            lease_bundle_of(c, rx, lease_id, "postgres", (f.port, &f.ca), password).await
        }

        /// P3-6d-1b — the same, for `provider`'s issuer at `localhost` on
        /// `port`, its TLS verified against `ca`.
        async fn lease_bundle_of(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            lease_id: &str,
            provider: &str,
            (port, ca): (u16, &str),
            password: &str,
        ) -> LeaseInfo {
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 3)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            let bundle = serde_json::to_vec(&serde_json::json!({
                "audience": format!("localhost:{port}"),
                "fields": {
                    "admin_user": "admin",
                    "admin_password": password,
                    "database": "orders",
                    "ca": ca,
                },
            }))
            .unwrap();
            c.on_leased(
                &req_id,
                lease_id,
                0,
                &sealed_for_us(&bundle),
                in_ms(60_000),
                Some(provider),
            );
            asker.await.unwrap().unwrap()
        }

        /// What a background revocation leaves: polled for 5 s.
        async fn eventually(what: &str, done: impl Fn() -> bool) {
            for _ in 0..200 {
                if done() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("{what}: not within 5 s");
        }

        /// P3-6b-2b — a dynamic secret's lease is held, its bundle lent to
        /// no tool. Its credential is minted at its first use, once, two uses
        /// at once sharing it, valid until the lease's end; and taken back
        /// when the lease is let go.
        #[tokio::test]
        async fn a_bundle_is_held_its_credential_minted_once_and_taken_back() {
            let admin = made();
            let f = fake_issuer(&admin).await;
            let (c, mut rx) = connected();
            let lease_id = ObjectId::new().to_hex();
            let info = lease_bundle(&c, &mut rx, &lease_id, &f, &admin).await;
            assert_eq!(info.provider.as_deref(), Some("postgres"));
            assert_eq!(
                c.with_value(&lease_id, |_| ()),
                None,
                "no tool is lent the issuer's fields"
            );
            assert!(
                c.minted(&lease_id, "user").is_none(),
                "nothing is minted before its first use"
            );
            let (a, b) = tokio::join!(c.mint(&lease_id), c.mint(&lease_id));
            assert_eq!((a, b), (Ok(()), Ok(())));
            let role = format!("roomler_{lease_id}");
            let roles = f.roles.lock().unwrap().clone();
            assert_eq!(
                roles.keys().collect::<Vec<_>>(),
                [&role],
                "one credential per lease"
            );
            let until = bson::DateTime::from_millis(info.expires_at_ms)
                .try_to_rfc3339_string()
                .unwrap();
            assert_eq!(
                roles[&role].valid_until, until,
                "valid until the lease's end"
            );
            let field = |name: &str| c.minted(&lease_id, name).map(|v| v.to_vec());
            assert_eq!(field("user"), Some(role.clone().into_bytes()));
            assert_eq!(field("port"), Some(f.port.to_string().into_bytes()));
            assert_eq!(field("password").map(|p| p.len()), Some(43));
            assert_eq!(
                field("admin_password"),
                None,
                "an issuer's field is no credential's"
            );
            assert_eq!(c.release(std::slice::from_ref(&lease_id)), 1);
            eventually("the role taken back", || {
                !f.roles.lock().unwrap().contains_key(&role)
            })
            .await;
            assert_eq!(
                c.mint(&lease_id).await,
                Err("the lease ended before its credential was minted".into())
            );
        }

        /// P3-6d-1b — a MySQL issuer's lease is served as Postgres's is, by
        /// the minter its provider names: one user for the lease, marked with
        /// the lease's end in whole seconds, its event made; the user and its
        /// event taken back when the lease is let go.
        #[tokio::test]
        async fn a_mysql_bundle_mints_by_its_providers_minter_and_is_taken_back() {
            let admin = made();
            let f = fake_mysql(&admin).await;
            let (c, mut rx) = connected();
            let lease_id = ObjectId::new().to_hex();
            let info =
                lease_bundle_of(&c, &mut rx, &lease_id, "mysql", (f.port, &f.ca), &admin).await;
            assert_eq!(info.provider.as_deref(), Some("mysql"));
            assert_eq!(c.with_value(&lease_id, |_| ()), None, "nothing lent");
            let (a, b) = tokio::join!(c.mint(&lease_id), c.mint(&lease_id));
            assert_eq!((a, b), (Ok(()), Ok(())));
            let user = format!("roomler_{lease_id}");
            let users = f.users.lock().unwrap().clone();
            assert_eq!(
                users.keys().collect::<Vec<_>>(),
                [&user],
                "one credential per lease"
            );
            let until = info.expires_at_ms.div_euclid(1000);
            assert_eq!(
                users[&user].attribute,
                Some(format!(
                    "{{\"roomler\": {{\"lease\": \"{lease_id}\", \"until\": {until}}}}}"
                )),
                "its end, the lease's, in whole seconds"
            );
            let event = format!("roomler_end_{lease_id}");
            assert!(f.events.lock().unwrap().contains(&event));
            let field = |name: &str| c.minted(&lease_id, name).map(|v| v.to_vec());
            assert_eq!(field("user"), Some(user.clone().into_bytes()));
            assert_eq!(field("port"), Some(f.port.to_string().into_bytes()));
            assert_eq!(field("database"), Some(b"orders".to_vec()));
            assert_eq!(field("password").map(|p| p.len()), Some(43));
            assert_eq!(c.release(std::slice::from_ref(&lease_id)), 1);
            eventually("the user taken back", || {
                !f.users.lock().unwrap().contains_key(&user)
            })
            .await;
            eventually("its event dropped", || {
                !f.events.lock().unwrap().contains(&event)
            })
            .await;
        }

        /// P3-6f-2 — a Kubernetes issuer's lease is served as a database
        /// user's is, by the minter its provider names: one token for the
        /// lease, bound to one Secret made for it, for Kubernetes' shortest
        /// where the lease is shorter; the Secret deleted when the lease is
        /// let go, and the token with it.
        #[tokio::test]
        async fn a_kubernetes_bundle_mints_a_token_bound_to_its_lease_and_takes_it_back() {
            let k = fake_k8s(false).await;
            let (c, mut rx) = connected();
            let lease_id = ObjectId::new().to_hex();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 3)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            let bundle = serde_json::to_vec(&serde_json::json!({
                "audience": k.origin(),
                "fields": {
                    "namespace": "hive-tokens",
                    "service_account": "session-runner",
                    "admin_token": made(),
                    "ca": k.ca,
                },
            }))
            .unwrap();
            c.on_leased(
                &req_id,
                &lease_id,
                0,
                &sealed_for_us(&bundle),
                in_ms(60_000),
                Some("kubernetes"),
            );
            let info = asker.await.unwrap().unwrap();
            assert_eq!(info.provider.as_deref(), Some("kubernetes"));
            assert_eq!(c.with_value(&lease_id, |_| ()), None, "nothing lent");
            let (a, b) = tokio::join!(c.mint(&lease_id), c.mint(&lease_id));
            assert_eq!((a, b), (Ok(()), Ok(())));
            let secret = format!("roomler-{lease_id}");
            {
                let st = k.state();
                assert_eq!(
                    st.secrets.keys().collect::<Vec<_>>(),
                    [&secret],
                    "one Secret per lease"
                );
                let asks: Vec<_> = st
                    .saw
                    .iter()
                    .filter(|s| s.target.ends_with("/token"))
                    .collect();
                assert_eq!(asks.len(), 1, "one token per lease");
                assert_eq!(
                    asks[0].body["spec"]["expirationSeconds"], 600,
                    "a minute's lease asks for Kubernetes' shortest"
                );
            }
            let field = |name: &str| c.minted(&lease_id, name).map(|v| v.to_vec());
            assert_eq!(
                field("token"),
                Some(format!("minted.session-runner.{secret}").into_bytes())
            );
            assert_eq!(field("server"), Some(k.origin().into_bytes()));
            assert_eq!(field("ca"), Some(k.ca.clone().into_bytes()));
            assert_eq!(field("namespace"), Some(b"hive-tokens".to_vec()));
            assert_eq!(
                field("admin_token"),
                None,
                "an issuer's field is no credential's"
            );
            assert_eq!(c.release(std::slice::from_ref(&lease_id)), 1);
            eventually("the Secret deleted, and its token with it", || {
                !k.state().secrets.contains_key(&secret)
            })
            .await;
        }

        /// P3-6b-2b — a lease let go while its credential is being minted:
        /// the mint, when it ends, takes its own credential back at once.
        #[tokio::test]
        async fn a_credential_minted_while_its_lease_is_let_go_is_taken_back() {
            let admin = made();
            let mut f = fake_issuer(&admin).await;
            f.hold_create
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let (c, mut rx) = connected();
            let lease_id = ObjectId::new().to_hex();
            lease_bundle(&c, &mut rx, &lease_id, &f, &admin).await;
            let minting = {
                let (c, id) = (c.clone(), lease_id.clone());
                tokio::spawn(async move { c.mint(&id).await })
            };
            // The mint is at the database: its CREATE ROLE came, unanswered.
            while !f.saw.recv().await.unwrap().starts_with("CREATE ROLE ") {}
            assert_eq!(c.release(std::slice::from_ref(&lease_id)), 1);
            f.let_create.notify_one();
            assert_eq!(
                minting.await.unwrap(),
                Err("the lease ended while its credential was minted: it is taken back".into())
            );
            let role = format!("roomler_{lease_id}");
            eventually("the role taken back", || {
                !f.roles.lock().unwrap().contains_key(&role)
            })
            .await;
        }

        /// P3-6b-2b — a stored secret's lease mints nothing and has no
        /// credential; its value is lent as before.
        #[tokio::test]
        async fn a_stored_lease_mints_nothing() {
            let (c, mut rx) = connected();
            let info = lease(&c, &mut rx, "L-stored", ObjectId::new(), 1, in_ms(60_000)).await;
            assert_eq!(info.provider, None);
            assert_eq!(
                c.mint("L-stored").await,
                Err("the lease is no dynamic secret's".into())
            );
            assert!(c.minted("L-stored", "user").is_none());
            assert_eq!(
                c.with_value("L-stored", |v| v.to_vec()),
                Some(b"canary-vault-value".to_vec())
            );
        }

        /// A request goes out on the connection, bounded as the vault bounds
        /// it; the answer opens with this daemon's key and is held.
        #[tokio::test]
        async fn a_lease_is_asked_for_on_the_connection_opened_and_held() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(sid, 3)).await })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultLease {
                    req_id,
                    session_id,
                    fence,
                    secret,
                    mode,
                    ttl_secs,
                    ..
                } => {
                    assert_eq!(
                        (session_id, fence, secret.as_str(), mode.as_str(), ttl_secs),
                        (sid, 3, "db/main", "env", 60)
                    );
                    assert!(req_id.len() <= lease_limits::MAX_REQ_ID_LEN);
                    req_id
                }
                other => panic!("{other:?}"),
            };
            c.on_leased(
                &req_id,
                "L1",
                7,
                &sealed_for_us(b"canary-vault-value"),
                in_ms(60_000),
                None,
            );
            let info = asker.await.unwrap().unwrap();
            assert_eq!(
                (info.lease_id.as_str(), info.n, info.holder),
                ("L1", 7, Holder::Session { id: sid, fence: 3 })
            );
            assert_eq!(
                c.with_value("L1", |v| v.to_vec()).unwrap(),
                b"canary-vault-value"
            );
            assert_eq!(c.held(), [info]);
        }

        /// A refusal is answered in the vault's word, and nothing is held.
        #[tokio::test]
        async fn a_refusal_answers_in_the_vaults_word() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 1)).await })
            };
            c.on_refused(&req_id_of(rx.recv().await.unwrap()), "denied", None);
            assert_eq!(
                asker.await.unwrap(),
                Err(LeaseError::Refused("denied".into()))
            );
            assert!(c.held().is_empty());
        }

        /// P3-4e-2 — a lease whose card waits for a person is asked for
        /// again, 2 s and then 4 s later, each time as a request of its own,
        /// until the yes leases it.
        #[tokio::test(start_paused = true)]
        async fn a_lease_a_card_waits_on_is_asked_again_until_a_yes() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.request_until_approved(ask(sid, 1), Duration::from_secs(600))
                        .await
                })
            };
            let first = next_ask(&mut rx).await;
            let t0 = tokio::time::Instant::now();
            c.on_refused(&first, "awaiting_approval", Some("A1"));
            let second = next_ask(&mut rx).await;
            assert_ne!(second, first, "a request of its own");
            assert_eq!(t0.elapsed().as_secs(), 2);
            let t1 = tokio::time::Instant::now();
            c.on_refused(&second, "awaiting_approval", Some("A1"));
            let third = next_ask(&mut rx).await;
            assert_eq!(t1.elapsed().as_secs(), 4);
            c.on_leased(
                &third,
                "L1",
                1,
                &sealed_for_us(b"canary-vault-value"),
                in_ms(60_000),
                None,
            );
            assert_eq!(asker.await.unwrap().unwrap().lease_id, "L1");
        }

        /// P3-4e-2 — a no after a wait is the answer, and nothing asks again.
        #[tokio::test(start_paused = true)]
        async fn a_no_after_a_wait_is_the_answer() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.request_until_approved(ask(ObjectId::new(), 1), Duration::from_secs(600))
                        .await
                })
            };
            let first = next_ask(&mut rx).await;
            c.on_refused(&first, "awaiting_approval", Some("A1"));
            c.on_refused(&next_ask(&mut rx).await, "denied", None);
            assert_eq!(
                asker.await.unwrap(),
                Err(LeaseError::Refused("denied".into()))
            );
            assert!(rx.try_recv().is_err(), "nothing asked again");
        }

        /// P3-4e-2 — a card nobody answers ends the wait at its window: asked
        /// at 0, 2, 6, 14 and 29 s (the pause doubling to 15 s), and the
        /// card still waiting is the answer, naming it.
        #[tokio::test(start_paused = true)]
        async fn a_card_nobody_answers_ends_the_wait_at_its_window() {
            let (c, mut rx) = connected();
            let t0 = tokio::time::Instant::now();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.request_until_approved(ask(ObjectId::new(), 1), Duration::from_secs(30))
                        .await
                })
            };
            let mut at = Vec::new();
            for _ in 0..5 {
                let req_id = next_ask(&mut rx).await;
                at.push(t0.elapsed().as_secs());
                c.on_refused(&req_id, "awaiting_approval", Some("A1"));
            }
            assert_eq!(
                asker.await.unwrap(),
                Err(LeaseError::AwaitingApproval("A1".into()))
            );
            assert_eq!(at, [0, 2, 6, 14, 29]);
            assert!(rx.try_recv().is_err(), "nothing asked past the window");
        }

        /// Without a connection there is no request; without an answer in
        /// time there is no lease, and an answer that comes late opens
        /// nothing.
        #[tokio::test]
        async fn without_a_connection_or_an_answer_there_is_no_lease() {
            let lone = Client::default();
            assert_eq!(
                lone.request(ask(ObjectId::new(), 1)).await,
                Err(LeaseError::NotConnected)
            );
            let (c, mut rx) = connected();
            assert_eq!(
                c.request_within(ask(ObjectId::new(), 1), Duration::from_millis(50))
                    .await,
                Err(LeaseError::NoAnswer)
            );
            let late = req_id_of(rx.try_recv().unwrap());
            c.on_leased(
                &late,
                "late",
                1,
                &sealed_for_us(b"canary-vault-value"),
                in_ms(60_000),
                None,
            );
            assert!(c.held().is_empty(), "a late answer is not held");
        }

        /// P3-4b — an asker that stops waiting (a cancelled tool call drops
        /// its future) leaves nothing waiting, and the answer that comes
        /// after opens nothing.
        #[tokio::test]
        async fn an_asker_that_stops_waiting_leaves_nothing_waiting() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 1)).await })
            };
            let req_id = req_id_of(rx.recv().await.unwrap());
            assert_eq!(c.waiting(), 1);
            asker.abort();
            let _ = asker.await;
            assert_eq!(c.waiting(), 0, "the dropped wait forgot its request");
            c.on_leased(
                &req_id,
                "after",
                1,
                &sealed_for_us(b"canary-vault-value"),
                in_ms(60_000),
                None,
            );
            assert!(
                c.held().is_empty(),
                "an answer after its asker left is not held"
            );
            let lister = {
                let c = c.clone();
                tokio::spawn(async move { c.list(ObjectId::new(), 1, "").await })
            };
            match rx.recv().await.unwrap() {
                ClientMsg::VaultList { .. } => {}
                other => panic!("{other:?}"),
            }
            assert_eq!(c.waiting(), 1);
            lister.abort();
            let _ = lister.await;
            assert_eq!(c.waiting(), 0, "a listing's dropped wait, the same");
        }

        /// A box sealed to any other key does not open, and is not held.
        #[tokio::test]
        async fn a_box_for_another_key_is_unopenable() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move { c.request(ask(ObjectId::new(), 1)).await })
            };
            let rng = &mut crypto_box::aead::OsRng;
            let elsewhere = crypto_box::SecretKey::generate(rng).public_key();
            let sealed = base64::engine::general_purpose::STANDARD
                .encode(elsewhere.seal(rng, b"canary-vault-value").unwrap());
            c.on_leased(
                &req_id_of(rx.recv().await.unwrap()),
                "L",
                1,
                &sealed,
                in_ms(60_000),
                None,
            );
            assert_eq!(asker.await.unwrap(), Err(LeaseError::Unopenable));
            assert!(c.held().is_empty());
        }

        /// A revocation lets go of what it names, and an id this daemon does
        /// not hold changes nothing.
        #[tokio::test]
        async fn a_revocation_lets_go_of_what_it_names_and_nothing_else() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            lease(&c, &mut rx, "L1", sid, 1, in_ms(60_000)).await;
            let kept = lease(&c, &mut rx, "L2", sid, 1, in_ms(60_000)).await;
            assert_eq!(
                c.on_revoke(
                    &["L1".into(), "an-earlier-process-held".into()],
                    "session_ended"
                ),
                1
            );
            assert!(c.with_value("L1", |_| ()).is_none());
            assert_eq!(c.held(), [kept]);
        }

        /// A run that ends takes its own leases, and only those: another
        /// fence of the session is another run.
        #[tokio::test]
        async fn a_run_that_ends_takes_only_its_own_leases() {
            let (c, mut rx) = connected();
            let (sid, other) = (ObjectId::new(), ObjectId::new());
            lease(&c, &mut rx, "L1", sid, 3, in_ms(60_000)).await;
            lease(&c, &mut rx, "L2", sid, 4, in_ms(60_000)).await;
            lease(&c, &mut rx, "L3", other, 3, in_ms(60_000)).await;
            assert_eq!(c.drop_run(sid, 3), 1);
            let mut left: Vec<String> = c.held().into_iter().map(|l| l.lease_id).collect();
            left.sort();
            assert_eq!(left, ["L2", "L3"]);
        }

        /// FR-90 P3-9-2 — a person's lease for `endpoint`: asked, answered
        /// `lease_id`, held until `expires_at_ms`.
        async fn person_lease(
            c: &Arc<Client>,
            rx: &mut mpsc::Receiver<ClientMsg>,
            lease_id: &str,
            endpoint: u64,
            expires_at_ms: i64,
        ) -> LeaseInfo {
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.connect(PersonAsk {
                        endpoint,
                        secret: "db/orders".into(),
                        field: "password".into(),
                        audience: "db.internal:5432".into(),
                        ttl_secs: 600,
                    })
                    .await
                })
            };
            let req_id = next_ask(rx).await;
            c.on_leased(
                &req_id,
                lease_id,
                2,
                &sealed_for_us(b"canary-person-value"),
                expires_at_ms,
                None,
            );
            asker.await.unwrap().unwrap()
        }

        /// FR-90 P3-9-2 — a person's ask names no session and no person: one
        /// field, toward its upstream. The answer opens with this daemon's
        /// key, as any lease does, and is held for the endpoint that asked,
        /// in `proxy`: what it serves is an endpoint, never a value.
        #[tokio::test]
        async fn a_persons_lease_is_asked_with_no_session_and_held_for_its_endpoint() {
            let (c, mut rx) = connected();
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.connect(PersonAsk {
                        endpoint: 7,
                        secret: "db/orders".into(),
                        field: "password".into(),
                        audience: "db.internal:5432".into(),
                        ttl_secs: 600,
                    })
                    .await
                })
            };
            let req_id = match rx.recv().await.unwrap() {
                ClientMsg::VaultConnect {
                    req_id,
                    secret,
                    field,
                    audience,
                    ttl_secs,
                } => {
                    assert_eq!(
                        (secret.as_str(), field.as_str(), audience.as_str(), ttl_secs),
                        ("db/orders", "password", "db.internal:5432", 600)
                    );
                    assert!(req_id.len() <= lease_limits::MAX_REQ_ID_LEN);
                    req_id
                }
                other => panic!("{other:?}"),
            };
            c.on_leased(
                &req_id,
                "P1",
                2,
                &sealed_for_us(b"canary-person-value"),
                in_ms(600_000),
                None,
            );
            let info = asker.await.unwrap().unwrap();
            assert_eq!(info.holder, Holder::Person(7));
            assert_eq!((info.mode.as_str(), info.ahead), ("proxy", false));
            assert_eq!(
                c.with_value("P1", |v| v.to_vec()).unwrap(),
                b"canary-person-value"
            );

            // A refusal answers it in the vault's word, decision 24's
            // included, and nothing is held for it.
            let asker = {
                let c = c.clone();
                tokio::spawn(async move {
                    c.connect(PersonAsk {
                        endpoint: 7,
                        secret: "db/orders".into(),
                        field: "user".into(),
                        audience: "db.internal:5432".into(),
                        ttl_secs: 600,
                    })
                    .await
                })
            };
            let req_id = next_ask(&mut rx).await;
            c.on_refused(&req_id, "approval_unavailable", None);
            assert_eq!(
                asker.await.unwrap(),
                Err(LeaseError::Refused("approval_unavailable".into()))
            );
            assert_eq!(c.held(), [info]);
        }

        /// FR-90 P3-9-2 — an endpoint that closes takes its own leases and
        /// nothing else: not another endpoint's, not a session's; and a run
        /// that ends takes none of an endpoint's.
        #[tokio::test]
        async fn an_endpoint_that_closes_takes_only_its_own_leases() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            lease(&c, &mut rx, "L1", sid, 1, in_ms(60_000)).await;
            person_lease(&c, &mut rx, "P1", 7, in_ms(60_000)).await;
            person_lease(&c, &mut rx, "P2", 7, in_ms(60_000)).await;
            person_lease(&c, &mut rx, "P3", 8, in_ms(60_000)).await;
            assert_eq!(c.drop_person(7), 2);
            assert!(c.with_value("P1", |_| ()).is_none());
            assert_eq!(c.drop_run(sid, 1), 1);
            let left: Vec<String> = c.held().into_iter().map(|l| l.lease_id).collect();
            assert_eq!(left, ["P3"]);
        }

        /// P3-4c-2 — a file written with a lease's value goes whenever the
        /// lease does: at a revocation, a release, the run's end and its
        /// expiry. A lease no longer held takes no file.
        #[tokio::test]
        async fn a_leases_files_go_whenever_it_does() {
            let dir = tempfile::tempdir().unwrap();
            let file = |name: &str| {
                let p = dir.path().join(name);
                std::fs::write(&p, b"x").unwrap();
                p
            };
            let (c, mut rx) = connected();
            let sid = ObjectId::new();

            lease(&c, &mut rx, "R", sid, 1, in_ms(60_000)).await;
            let revoked = file("revoked");
            assert!(c.attach("R", &revoked));
            c.on_revoke(&["R".to_string()], "value_changed");
            assert!(!revoked.exists(), "a revocation takes the file");

            lease(&c, &mut rx, "S", sid, 1, in_ms(60_000)).await;
            let released = file("released");
            assert!(c.attach("S", &released));
            c.release(&["S".to_string()]);
            assert!(!released.exists(), "a release takes the file");

            lease(&c, &mut rx, "D", sid, 2, in_ms(60_000)).await;
            let ended = file("run-ended");
            assert!(c.attach("D", &ended));
            c.drop_run(sid, 2);
            assert!(!ended.exists(), "the run's end takes the file");

            lease(&c, &mut rx, "E", sid, 3, in_ms(1)).await;
            let expired = file("expired");
            assert!(c.attach("E", &expired));
            tokio::time::sleep(Duration::from_millis(20)).await;
            c.prune();
            assert!(!expired.exists(), "the expiry takes the file");

            assert!(
                !c.attach("gone", &dir.path().join("never")),
                "a lease not held takes no file"
            );
        }

        /// P3-5b-2 — what is served with a lease's value stops whenever the
        /// lease goes: at a revocation, a release, the run's end and its
        /// expiry. A lease no longer held takes no stop, and one still held
        /// stops nothing.
        #[tokio::test]
        async fn what_is_served_with_a_lease_stops_whenever_it_goes() {
            use tokio_util::sync::CancellationToken;
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            let served = |id: &str| {
                let stop = CancellationToken::new();
                assert!(c.stop_with(id, stop.clone()), "{id} is held");
                stop
            };

            lease(&c, &mut rx, "R", sid, 1, in_ms(60_000)).await;
            let revoked = served("R");
            lease(&c, &mut rx, "K", sid, 1, in_ms(60_000)).await;
            let kept = served("K");
            c.on_revoke(&["R".to_string()], "value_changed");
            assert!(revoked.is_cancelled(), "a revocation stops it");
            assert!(!kept.is_cancelled(), "another lease's stays");

            lease(&c, &mut rx, "S", sid, 1, in_ms(60_000)).await;
            let released = served("S");
            c.release(&["S".to_string()]);
            assert!(released.is_cancelled(), "a release stops it");

            lease(&c, &mut rx, "D", sid, 2, in_ms(60_000)).await;
            let ended = served("D");
            c.drop_run(sid, 2);
            assert!(ended.is_cancelled(), "the run's end stops it");

            lease(&c, &mut rx, "E", sid, 3, in_ms(1)).await;
            let expired = served("E");
            tokio::time::sleep(Duration::from_millis(20)).await;
            c.prune();
            assert!(expired.is_cancelled(), "the expiry stops it");

            assert!(
                !c.stop_with("gone", CancellationToken::new()),
                "a lease not held takes no stop"
            );
            assert!(!kept.is_cancelled());
        }

        /// P3-4c-3 — a lease asked for ahead is found only for exactly what
        /// it was asked for, while it has the time a call needs, and a lease
        /// a call asked for itself is never found.
        #[tokio::test]
        async fn a_lease_asked_for_ahead_is_found_only_for_what_it_was_asked_for() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            let exec_for = |audience: &str, ahead: bool| LeaseAsk {
                mode: "exec".into(),
                audience: audience.into(),
                ahead,
                ..ask(sid, 1)
            };
            for (id, ahead, ms) in [("A", true, 60_000), ("B", false, 120_000)] {
                let asker = {
                    let (c, a) = (c.clone(), exec_for("psql", ahead));
                    tokio::spawn(async move { c.request(a).await })
                };
                let req_id = req_id_of(rx.recv().await.unwrap());
                c.on_leased(&req_id, id, 1, &sealed_for_us(b"v"), in_ms(ms), None);
                asker.await.unwrap().unwrap();
            }
            let held = c.held();
            let a = held.iter().find(|i| i.lease_id == "A").unwrap();
            assert_eq!((a.audience.as_str(), a.ahead), ("psql", true));
            let soon = Duration::from_secs(10);
            assert_eq!(
                c.find_ahead(&exec_for("psql", false), soon).as_deref(),
                Some("A"),
                "the one asked for ahead, never B, which a call asked for itself"
            );
            assert!(c.left("A").unwrap() > Duration::from_secs(50));
            let elsewhere = [
                exec_for("kubectl", true),
                LeaseAsk {
                    mode: "file".into(),
                    ..exec_for("psql", true)
                },
                LeaseAsk {
                    field: "password".into(),
                    ..exec_for("psql", true)
                },
                LeaseAsk {
                    fence: 2,
                    ..exec_for("psql", true)
                },
                LeaseAsk {
                    session_id: ObjectId::new(),
                    ..exec_for("psql", true)
                },
                LeaseAsk {
                    secret: "db/other".into(),
                    ..exec_for("psql", true)
                },
            ];
            for other in elsewhere {
                assert_eq!(c.find_ahead(&other, soon), None, "{other:?}");
            }
            assert_eq!(
                c.find_ahead(&exec_for("psql", true), Duration::from_secs(120)),
                None,
                "a lease ending before the call would is not taken"
            );
            c.drop_run(sid, 1);
            assert_eq!(c.find_ahead(&exec_for("psql", true), soon), None);
        }

        /// P3-4d-2 — a report goes out on the connection only where the
        /// device's owner has it report, names its leases and never a value,
        /// and is dropped rather than wait on a full connection.
        #[tokio::test]
        async fn a_report_goes_out_only_where_the_owner_has_it_report() {
            let c = Arc::new(Client::default());
            let (tx, mut rx) = mpsc::channel(1);
            c.connected(tx, true);
            let sid = ObjectId::new();
            let report = || Report {
                session_id: sid,
                fence: 2,
                kind: VaultActivityKind::Exec,
                lease_ids: vec!["L1".into()],
                target: "psql".into(),
                exit_code: Some(0),
                timed_out: false,
            };
            assert!(!c.report(report()), "off by default: nothing sent");
            assert!(rx.try_recv().is_err());

            c.set_reports(true);
            assert!(c.report(report()));
            match rx.try_recv().unwrap() {
                ClientMsg::VaultActivity {
                    session_id,
                    fence,
                    kind,
                    lease_ids,
                    target,
                    exit_code,
                    timed_out,
                } => {
                    assert_eq!((session_id, fence), (sid, 2));
                    assert_eq!((kind.as_str(), target.as_str()), ("exec", "psql"));
                    assert_eq!(lease_ids, ["L1"]);
                    assert_eq!((exit_code, timed_out), (Some(0), false));
                }
                other => panic!("expected a report, got {other:?}"),
            }
            assert!(c.report(report()));
            assert!(
                !c.report(report()),
                "the connection holds one: the next is dropped, not waited for"
            );
            let _ = rx.try_recv();
            let mut no_lease = report();
            no_lease.lease_ids.clear();
            assert!(!c.report(no_lease), "no lease used, nothing to report");
        }

        /// A lease is let go at its expiry, and held no longer than the
        /// longest lease the vault grants, whatever the server's clock says.
        #[tokio::test]
        async fn an_expired_lease_is_let_go_and_none_outlives_the_longest() {
            let (c, mut rx) = connected();
            let sid = ObjectId::new();
            lease(&c, &mut rx, "soon", sid, 1, in_ms(150)).await;
            assert!(c.with_value("soon", |_| ()).is_some());
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(
                c.with_value("soon", |_| ()).is_none(),
                "let go at its expiry"
            );
            lease(&c, &mut rx, "far", sid, 1, in_ms(10 * 24 * 3_600_000)).await;
            let held = c.held_for("far").unwrap();
            assert!(
                held <= Duration::from_secs(u64::from(lease_limits::MAX_TTL_SECS)),
                "{held:?}"
            );
        }
    }
}
