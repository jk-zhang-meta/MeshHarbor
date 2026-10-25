// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Roomler SSH — the in-daemon SSH surface on this node's overlay address.
//!
//! # Where this is
//!
//! * **P1 — transport.** `tunnel_core::overlay::split_tun` diverts TCP for
//!   `<overlay ip>:<ssh_port>` into the daemon's userspace stack before the OS
//!   sees it, so the endpoint needs no socket bind, no firewall rule, and can
//!   coexist with an `sshd` that already holds `0.0.0.0:22`.
//! * **P2 — this file's server.** russh over that stream: publickey auth
//!   against [`ssh_authorized_keys`], and an `exec` channel routed through the
//!   daemon's existing [`crate::exec`] engine — since FR-89 its streaming
//!   variant, so output flows as it is produced with no ceiling and the
//!   channel owns the command's lifetime. PTY, SFTP and forwarding came later
//!   (P4, P7); anything else is refused with an explicit reason rather than
//!   left to hang.
//! * **P3a — the device half of authorization.** `rc:ssh.grant` carries a
//!   server-minted, single-use, short-lived authorization naming a roomler
//!   principal and an ephemeral public key; [`record_grant`] holds it and
//!   [`auth_publickey`] redeems it. The server half that decides *whether* to
//!   mint one (`SshPolicy`, `SSH_DEVICE`, the org kill-switch) is P3b.
//!
//! Built without the `ssh-server` feature the module still compiles and serves
//! the P1 banner+echo, which keeps the transport independently testable in a
//! build carrying no SSH code — and costs those builds nothing (russh measures
//! +1.86 MiB in `roomlerd`).
//!
//! # Two facts about identity, and the gap between them
//!
//! Anything arriving here has already been decrypted by WireGuard against a
//! peer key the coordination server put in our netmap, so the peer address is
//! the overlay address of a specific enrolled node in a specific org — not a
//! claim, a cryptographic fact. That is what the whole design rests on, and
//! what eventually lets roomler SSH have no key distribution at all.
//!
//! It is not *authorization*. An enrolled peer is authenticated, not entitled.
//! Two things close that gap, in this order:
//!
//! 1. A **server grant** ([`record_grant`]) names a roomler principal and one
//!    ephemeral key, is redeemed once, and dies in seconds. This is the path
//!    that will make key distribution unnecessary.
//! 2. [`ssh_authorized_keys`] — a device-owned list, empty by default, so
//!    `ssh_enabled` on its own grants nobody anything. It stays after P3 as
//!    the break-glass route for when the control plane is the broken thing,
//!    which is when a remote shell is wanted most.
//!
//! Grants are tried first and consumed; the list is the fallback.
//!
//! # What a session runs as
//!
//! Never something more privileged than was actually asked for — the rule
//! [`crate::exec::RunAs`] exists to enforce, applied to BOTH paths:
//!
//! * A **grant** carries the account mode from the device's server-side
//!   `SshPolicy`, which is authoritative for that session.
//! * A **key-list** session has no policy behind it, so it uses the
//!   device-owned `ssh_account_mode`. Unset — the default — means the session
//!   authenticates and then runs nothing, with the reason on stderr.
//!
//! That second rule is deliberate and was a fix: key-list sessions used to
//! fall back to the daemon's own identity, so listing a key quietly handed out
//! SYSTEM/root and a policy of `account_mode = console_user` was untrue for
//! that path. Authenticating-then-refusing is chosen over refusing the auth
//! because it can explain itself.
//!
//! [`ssh_authorized_keys`]: crate::config::AgentConfig::ssh_authorized_keys

use roomler_ai_remote_control::models::{SshActivityEvent, SshActivityKind};
use tracing::{debug, warn};

/// Process services a session depends on, threaded EXPLICITLY from the daemon
/// into the SSH server instead of discovered through process globals.
///
/// The asker is non-optional on purpose. "No broker ⇒ deny" used to be a doc
/// comment on a `static` (`consent::shared()`), and a doc comment is not a
/// property the compiler holds anyone to — a server that can be constructed at
/// all now provably has someone to ask. The struct exists (rather than a bare
/// broker parameter) so the NEXT thing a session needs — the P3c audit sink is
/// the known candidate — is one field here, not another parameter cascade.
#[derive(Clone)]
pub struct SessionServices {
    /// FR-55 — the activity counter, so a live SSH session holds the machine
    /// awake for as long as it lasts. Threaded here for the same reason the
    /// consent broker is: the server is built inside the overlay's TUN
    /// factory, far from where the keeper lives, and "the session was cut by
    /// an idle timer" must not be a state a server can be constructed into.
    ///
    /// `None` where no keeper exists, in which case nothing is held and
    /// behaviour is unchanged.
    ///
    /// ⚠️ Named `power_activity`, not `activity`: that name is already taken
    /// by the P8 [`ActivitySink`] which REPORTS what a session did. Two
    /// different meanings under one name is a trap.
    pub power_activity: Option<crate::power::ActivityCounter>,
    /// Who asks the person at the device before a session runs anything.
    pub asker: Asker,
    /// Where P8 activity reports go: this WS session's outbound queue.
    ///
    /// Scoped to the connection on purpose — a report belongs to the org
    /// whose control channel carried the grant, and a multi-org daemon must
    /// not leak one org's session activity onto another's WS. A reconnect
    /// builds a new sink; reports that raced the teardown are dropped, which
    /// is the right trade for a log line that must never block a session.
    pub activity: Option<ActivitySink>,
}

/// Who asks the person at the device before a session runs anything.
///
/// FR-105 — a session the SYSTEM service serves runs in session 0, where no
/// panel reaches anyone. The person is at the console, where the worker that
/// carried the connection runs, so the service asks THAT worker over the SSH
/// pipe, and the worker asks exactly as it does for a session of its own. A
/// worker that answers "yes" itself lets through only a session the server
/// already granted (FR-94's position on consent).
#[derive(Clone)]
pub enum Asker {
    /// This process asks.
    Here {
        /// The operator-consent broker — the same instance the tray and the
        /// LocalAPI decide through, so an SSH prompt resolves from any of
        /// them.
        broker: crate::consent::ConsentBroker,
        /// FR-27 — the native prompt surface, threaded here for the same
        /// reason the broker is: an SSH server is built inside the overlay's
        /// TUN factory, far from `signaling::run`, and "the prompt reached no
        /// screen" must not be a state a server can be constructed into.
        /// Field-measured 2026-08-29 on NEO16: with only the companion path an
        /// SSH prompt from mars timed out on a desktop whose native panel had
        /// just served three exec prompts in a row.
        indicator: crate::indicator::ViewerIndicator,
    },
    /// FR-105 — the worker on the other end of this connection asks: the
    /// SYSTEM service's server, one relay per connection.
    Worker(crate::ssh_service::ConsentRelay),
}

/// Fire-and-forget reporter for [`SshActivityKind`] events (P8).
///
/// Holds the gate as well as the channel so no call site has to remember to
/// check it: with `ssh_activity_log = false` the constructor returns `None`
/// and every `report` becomes a no-op at the type level.
#[derive(Clone)]
pub struct ActivitySink {
    tx: tokio::sync::mpsc::Sender<roomler_ai_remote_control::signaling::ClientMsg>,
}

impl ActivitySink {
    /// `None` when the device has not opted in — the default.
    pub fn new(
        cfg: &crate::config::AgentConfig,
        tx: tokio::sync::mpsc::Sender<roomler_ai_remote_control::signaling::ClientMsg>,
    ) -> Option<Self> {
        cfg.ssh_activity_log.then_some(Self { tx })
    }

    /// Report one event. Never blocks and never fails a session: a full
    /// outbound queue means the connection is already struggling, and losing
    /// a log line is strictly better than stalling the shell that produced it.
    pub fn report(
        &self,
        grant_id: Option<String>,
        caller: &str,
        kind: SshActivityKind,
        detail: Option<String>,
        exit_code: Option<i32>,
        allowed: bool,
    ) {
        use roomler_ai_remote_control::signaling::ClientMsg;

        let msg = ClientMsg::SshActivity {
            grant_id,
            caller: caller.to_string(),
            kind,
            detail: detail.map(|d| redact_and_cap(&d)),
            exit_code,
            allowed,
        };
        if self.tx.try_send(msg).is_err() {
            debug!("ssh: activity report dropped (outbound queue full or closed)");
        }
    }
}

/// Redact known secrets and bound the length BEFORE anything leaves the host.
///
/// A command line is operator-controlled text that we are about to ship off
/// the machine, so it gets the same treatment `exec` gives its output: the
/// registered-secret redactor (agent token, `Bearer …`, JWT-shaped strings),
/// then a hard cap. Truncation is MARKED — a silently shortened command would
/// read in the audit log as a different command from the one that ran.
fn redact_and_cap(detail: &str) -> String {
    let mut s = crate::exec::redactor().apply(detail);
    if s.chars().count() > SshActivityEvent::MAX_DETAIL {
        s = s.chars().take(SshActivityEvent::MAX_DETAIL).collect();
        s.push('…');
    }
    s
}

/// Decorate a TUN factory so TCP to `<overlay ip>:<ssh_port>` terminates in the
/// daemon instead of reaching the OS. Returns `inner` unchanged when the node
/// has not opted in, so the default path is byte-for-byte the old one.
///
/// The decoration happens per device build (i.e. per WS session), which is what
/// we want: a reconnect re-creates the netstack alongside the device it is
/// spliced into, and the previous one is torn down with it.
#[cfg(feature = "overlay-netstack")]
pub fn maybe_intercept(
    inner: tunnel_core::overlay::runtime::TunFactory,
    cfg: &crate::config::AgentConfig,
    services: SessionServices,
) -> tunnel_core::overlay::runtime::TunFactory {
    use std::sync::Arc;

    use tunnel_core::overlay::split_tun::{SplitTun, warn_if_os_listener};
    use tunnel_core::overlay::tun::TunIo;

    if !cfg.ssh_enabled {
        return inner;
    }
    let port = cfg.effective_ssh_port();
    // FR-105 — on Windows, the SYSTEM service's port too: carried to the
    // service's pipe, never served here. Not when the kill switch is set, nor
    // when this node's own port is configured onto it.
    #[cfg(all(windows, feature = "ssh-server"))]
    let service = {
        use roomler_ai_remote_control::models::ssh_limits::SERVICE_PORT;
        if crate::ssh_service::disabled() {
            None
        } else if port == SERVICE_PORT {
            warn!(
                port,
                "ssh: ssh_port is the SYSTEM service's port — SSH through the service is off \
                 on this device"
            );
            None
        } else {
            Some((SERVICE_PORT, services.clone()))
        }
    };
    // Resolve what we serve ONCE, here, rather than per connection: parsing the
    // host key and the authorized-key list is where an operator's typo shows
    // up, and it should surface at start-up in the daemon log, not as a silent
    // per-connection failure the caller sees as a dropped socket.
    let ctx = build_ctx(cfg, services);
    Box::new(move |ip, nm, mtu| {
        let ctx = ctx.clone();
        let dev = inner(ip, nm, mtu)?;
        // Loud about the one case where switching this on changes who answers
        // an address that already had a server: `devbox` (sshd bound to the
        // overlay IP) and the Linux boxes (sshd on `0.0.0.0:22`).
        warn_if_os_listener(ip, port);

        #[cfg(all(windows, feature = "ssh-server"))]
        let ports: Vec<u16> = match &service {
            Some((service_port, _)) => vec![port, *service_port],
            None => vec![port],
        };
        #[cfg(not(all(windows, feature = "ssh-server")))]
        let ports = [port];
        let split =
            SplitTun::wrap_ports(dev, ip, crate::overlay::netmask_to_prefix(nm), mtu, &ports);

        #[cfg(all(windows, feature = "ssh-server"))]
        if let Some((service_port, services)) = service.clone() {
            let weak = Arc::downgrade(&split);
            tokio::spawn(async move {
                let listener = {
                    let Some(dev) = weak.upgrade() else { return };
                    match dev.listen_on(service_port).await {
                        Ok(l) => l,
                        Err(e) => {
                            warn!(%e, port = service_port, "ssh: could not listen on the SYSTEM service's overlay port");
                            return;
                        }
                    }
                };
                carry_loop(listener, service_port, services).await;
            });
        }

        // The accept loop must NOT hold a strong reference: `SplitTun` owns the
        // netstack, whose poll loop exits when the last handle drops. Upgrade
        // once to open the listener, then keep only the listener — which ends
        // by itself when the stack goes away, so the task cannot outlive the
        // session it belongs to.
        let weak = Arc::downgrade(&split);
        tokio::spawn(async move {
            let listener = {
                let Some(dev) = weak.upgrade() else { return };
                match dev.listen().await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(%e, port, "ssh: could not listen on the intercepted overlay port");
                        return;
                    }
                }
            };
            accept_loop(listener, port, ctx).await;
        });

        Ok(split as Arc<dyn TunIo>)
    })
}

/// Builds without the userspace stack cannot intercept anything; say so once
/// rather than leaving the operator to wonder why `ssh_enabled` did nothing.
#[cfg(not(feature = "overlay-netstack"))]
pub fn maybe_intercept(
    inner: tunnel_core::overlay::runtime::TunFactory,
    cfg: &crate::config::AgentConfig,
    _services: SessionServices,
) -> tunnel_core::overlay::runtime::TunFactory {
    if cfg.ssh_enabled {
        warn!(
            "ssh_enabled is set but this build lacks the `overlay-netstack` feature — \
             SSH is NOT being served on the overlay address"
        );
    }
    inner
}

/// FR-105 — carry each connection to the SYSTEM service's port to the
/// service, until the netstack goes away. Nothing is served here: the worker
/// holds no key for these sessions.
#[cfg(all(windows, feature = "ssh-server"))]
async fn carry_loop(
    mut listener: tunnel_core::overlay::netstack::NsListener,
    port: u16,
    services: SessionServices,
) {
    use tracing::info;

    info!(
        port,
        "ssh: carrying the SYSTEM service's overlay port to its pipe"
    );
    while let Some(stream) = listener.accept().await {
        let peer = stream.peer_addr();
        let services = services.clone();
        tokio::spawn(async move {
            match crate::ssh_service::carry(stream, peer, services).await {
                Ok(()) => info!(%peer, "ssh: a SYSTEM service session closed"),
                Err(e) => warn!(%peer, %e, "ssh: a SYSTEM service session ended"),
            }
        });
    }
    info!(
        port,
        "ssh: the SYSTEM service's port is no longer carried (session ended)"
    );
}

/// Serve intercepted connections until the netstack goes away.
#[cfg(feature = "overlay-netstack")]
async fn accept_loop(
    mut listener: tunnel_core::overlay::netstack::NsListener,
    port: u16,
    ctx: ServeCtx,
) {
    use tracing::info;

    info!(port, "ssh: serving the intercepted overlay port");
    while let Some(stream) = listener.accept().await {
        tokio::spawn(serve_conn(stream, ctx.clone()));
    }
    info!(
        port,
        "ssh: intercepted port no longer served (session ended)"
    );
}

/// What a connection is served with, resolved once per session.
///
/// With the `ssh-server` feature this is the SSH server's configuration (host
/// key + the accepted public keys); without it, the P1 banner+echo, so the
/// transport stays independently testable in a build that carries no SSH code
/// at all.
#[cfg(all(feature = "overlay-netstack", feature = "ssh-server"))]
type ServeCtx = Option<std::sync::Arc<sshd::Ctx>>;
#[cfg(all(feature = "overlay-netstack", not(feature = "ssh-server")))]
type ServeCtx = ();

#[cfg(all(feature = "overlay-netstack", not(feature = "ssh-server")))]
fn build_ctx(cfg: &crate::config::AgentConfig, services: SessionServices) -> ServeCtx {
    let _ = (cfg, services);
    warn!(
        "ssh_enabled is on but this build lacks the `ssh-server` feature — \
         the intercepted port answers with the P1 echo, not SSH"
    );
}

/// P1 payload, kept for builds without `ssh-server`: prove the path, then get
/// out of the way. Echoes until EOF so a tester can confirm both directions.
#[cfg(all(feature = "overlay-netstack", not(feature = "ssh-server")))]
async fn serve_conn(mut stream: tunnel_core::overlay::netstack::NsTcpStream, _ctx: ServeCtx) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    let peer = stream.peer_addr();
    info!(%peer, "ssh: intercepted connection accepted (P1 transport seam)");

    let banner = format!(
        "roomler-ssh P1: transport seam OK. You are {peer}, served in-process \
         with no OS socket. Echoing until EOF.\r\n"
    );
    if let Err(e) = stream.write_all(banner.as_bytes()).await {
        warn!(%peer, %e, "ssh: banner write failed");
        return;
    }

    let mut buf = [0u8; 2048];
    let mut echoed: u64 = 0;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = stream.write_all(&buf[..n]).await {
                    warn!(%peer, %e, echoed, "ssh: echo write failed");
                    return;
                }
                echoed += n as u64;
            }
            Err(e) => {
                warn!(%peer, %e, echoed, "ssh: read failed");
                return;
            }
        }
    }
    info!(%peer, echoed, "ssh: intercepted connection closed");
}

// ===========================================================================
// P2 — the SSH server.
// ===========================================================================

/// Mint a fresh ed25519 host identity, OpenSSH-encoded.
///
/// Ed25519 only, and not by accident: it is the algorithm every client since
/// OpenSSH 6.5 supports, it needs no parameter choices that can be got wrong,
/// and it lets the `rsa` feature stay off — which keeps a `0.10.0-rc`
/// pre-release out of the dependency graph and ~0.32 MiB out of the binary.
///
/// The seed comes from `rand::random`, i.e. the OS CSPRNG, and the key is
/// constructed from those bytes rather than through an RNG-generic API so this
/// never has to agree with russh about which `rand_core` generation is in the
/// tree.
/// The OpenSSH **public** half of this device's host key, for the server to
/// publish so callers can verify what they dialled instead of trusting it on
/// first use (P6).
///
/// Empty when there is nothing to prove — no key stored, or a build without
/// `ssh-server`. Deliberately NOT an error: a device with SSH switched off is
/// in a perfectly normal state, and the empty value already means "cannot
/// prove itself" on the wire.
///
/// Derived on every hello rather than cached, so rotating `ssh_host_key` in
/// the config and restarting is all it takes for the fleet view to follow —
/// a cache here would leave the server advertising a key the device no longer
/// holds, which is worse than advertising none.
#[cfg(feature = "ssh-server")]
pub fn host_public_key(cfg: &crate::config::AgentConfig) -> String {
    let Some(pem) = cfg.ssh_host_key.as_deref() else {
        return String::new();
    };
    match russh::keys::ssh_key::PrivateKey::from_openssh(pem) {
        Ok(k) => k.public_key().to_openssh().unwrap_or_default(),
        Err(e) => {
            // Same unreadable-key case `Ctx::build` refuses to serve on; say
            // so once here too, because the symptom a user sees is remote
            // (their client cannot verify the host) and the cause is local.
            warn!(%e, "ssh: stored host key is unreadable — publishing no host pubkey");
            String::new()
        }
    }
}

#[cfg(not(feature = "ssh-server"))]
pub fn host_public_key(_cfg: &crate::config::AgentConfig) -> String {
    String::new()
}

/// Whether the stored host key can actually be used — parsed, not merely
/// present.
///
/// The distinction is the whole point. `Some(garbage)` and `None` look the same
/// to every caller that only asks whether a key is configured, and they are
/// opposite states: `None` is a device that has not started SSH yet and will
/// mint one, while `Some(garbage)` is a device that believes it is done and
/// serves nothing, forever.
///
/// Measured in the field 2026-09-09 on a corp laptop running 0.4.96: its stored
/// key had picked up literal `\r` escape text inside the PEM, so its BEGIN line
/// was not newline-terminated (`PEM error in pre-encapsulation boundary`). The
/// daemon correctly refused to serve SSH and correctly published no host
/// pubkey — and then never recovered, because the mint in `main.rs` was gated
/// on `is_none()`. Every restart re-logged the same warning. Nothing surfaced
/// it: not `roomler status`, not `roomler config ls`, not the dashboard; and
/// what a caller saw was *"has not published an SSH host key … needs an agent
/// that has had SSH enabled at least once (rc.444+)"*, i.e. advice to upgrade an
/// agent that was already current.
#[cfg(feature = "ssh-server")]
pub fn stored_host_key_is_usable(cfg: &crate::config::AgentConfig) -> bool {
    cfg.ssh_host_key
        .as_deref()
        .is_some_and(|pem| russh::keys::ssh_key::PrivateKey::from_openssh(pem).is_ok())
}

#[cfg(not(feature = "ssh-server"))]
pub fn stored_host_key_is_usable(_cfg: &crate::config::AgentConfig) -> bool {
    true
}

/// FR-105 — how a worker answers the question its SYSTEM service relays.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) use sshd::ask_here;

#[cfg(feature = "ssh-server")]
pub fn generate_host_key() -> anyhow::Result<String> {
    use russh::keys::ssh_key::LineEnding;
    use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};

    let seed: [u8; 32] = rand::random();
    let keypair = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::from(keypair);
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

#[cfg(feature = "ssh-server")]
pub(crate) mod sshd {
    use std::sync::Arc;
    use std::time::Duration;

    use roomler_ai_remote_control::models::SshActivityKind;
    use russh::keys::ssh_key::{self, PublicKey};
    use russh::server::{Auth, Msg, Session};
    use russh::{Channel, ChannelId};
    use tracing::{info, warn};

    use super::{ActivitySink, Asker};

    /// The receive window each channel offers; russh re-opens it at half.
    /// One channel can have at most this much unacknowledged data in flight,
    /// and the bytes still sitting in the client's own socket buffers count
    /// against it, so a long round trip bounds a bulk upload near
    /// window / RTT. Field, 2026-10-26 (HK↔Tokyo over the netstack, 43 ms):
    /// uploads held at 167 Mbit/s with russh's 2 MiB default, 243–249 with
    /// 16 MiB, and 64 MiB was no faster. Memory stays bounded whatever the
    /// window: russh hands each data packet to a 100-message channel and
    /// waits, so a slow consumer backs the reader into TCP flow control.
    /// `ROOMLERD_SSH_WINDOW_SIZE` overrides, in bytes.
    const WINDOW_DEFAULT: u32 = 16 * 1024 * 1024;
    const WINDOW_RANGE: std::ops::RangeInclusive<u32> = 256 * 1024..=64 * 1024 * 1024;

    fn channel_window() -> u32 {
        tunnel_core::env::node_env("SSH_WINDOW_SIZE")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| WINDOW_RANGE.contains(n))
            .unwrap_or(WINDOW_DEFAULT)
    }

    /// Everything a session needs, resolved once when the overlay device is
    /// built rather than per connection.
    pub struct Ctx {
        pub config: Arc<russh::server::Config>,
        /// Keys allowed to authenticate. Empty is a valid, safe state: the
        /// transport answers, every authentication attempt fails, and the
        /// operator sees exactly why in the log.
        pub authorized: Vec<PublicKey>,
        /// What a key-list session runs as, resolved once from
        /// `ssh_account_mode`.
        ///
        /// `Err` when the operator has not chosen — which is the default, and
        /// which refuses. A key-list session carries no server policy, so
        /// there is nothing to infer an identity from; the old behaviour of
        /// quietly using the daemon's own identity meant listing a key handed
        /// out SYSTEM/root without saying so, and made a device policy of
        /// `account_mode = console_user` untrue for this path.
        pub key_list_run_as: Result<crate::exec::RunAs, String>,
        /// M5: refuse a SERVER GRANT that asks to run as the daemon identity
        /// (SYSTEM/root), resolved once from `ssh_max_privilege`.
        ///
        /// Every other gate on an SSH session is decided by the server. This
        /// one is decided here, so it is the only one that still holds when
        /// the server is the compromised thing: a control plane that mints
        /// `account_mode = daemon, consent_mode = auto` otherwise gets an
        /// unattended root shell on every device that answers.
        ///
        /// Default `false` — permissive, no behaviour change — because a
        /// device-side ceiling that arrives switched ON revokes a working
        /// configuration mid-roll, and the device you lose root SSH to is
        /// liable to be the one you needed it for. The start-up log says so
        /// on every device that has not chosen.
        pub deny_daemon_grants: bool,
        /// Daemon services a session depends on — the consent broker, threaded
        /// from `run_cmd` so it provably exists wherever a server does.
        pub services: super::SessionServices,
        /// The operator's forward allowlist, snapshotted at server start —
        /// the ONLY gate on `direct-tcpip` (P7b), since no server authorizes
        /// an SSH forward. See [`forward_allowed`].
        pub forward_acl: crate::tunnel::acl::AgentForwardAcl,
        /// Ceiling on concurrent forwards, process-wide (P7b).
        ///
        /// `exec` caps its concurrency; a forward is the other thing a session
        /// can start unboundedly, and `ssh -D` opens one channel per browser
        /// connection — hundreds of live sockets is a resource story the
        /// operator never agreed to when they allowlisted one destination.
        /// Refuses rather than queues, matching `exec`: a forward that opens
        /// two minutes late is worse than one that fails now and says so.
        pub forwards: Arc<tokio::sync::Semaphore>,
        /// FR-89 — `ssh_exec_streaming`: a one-shot command's output goes to
        /// the channel as it is produced, with no ceiling and no wall clock
        /// (the default), or — the kill switch — through the engine's
        /// buffered path with its 1 MiB ceiling and 300 s limit, exactly as
        /// before FR-89.
        pub exec_streaming: bool,
        /// FR-105 — the anchor's `ssh` ceiling, on the SYSTEM service's
        /// server; `None` on the worker's. The machine administrator's, in a
        /// file only SYSTEM and Administrators can write.
        pub service_ceiling: Option<roomler_ai_remote_control::models::SshServiceCeiling>,
        /// FR-105 — refuse every `direct-tcpip` forward, with this reason, on
        /// the SYSTEM service's server: the allowlist that would gate one
        /// there is the signed-in user's to edit.
        pub forward_refusal: Option<&'static str>,
    }

    /// Process-wide ceiling on live `direct-tcpip` channels. Generous enough
    /// for `-D` against a browser (which is the heaviest legitimate use),
    /// small enough that a runaway client cannot exhaust the device's fds.
    pub(super) const MAX_CONCURRENT_FORWARDS: usize = 64;

    impl Ctx {
        /// Returns `None` when the node has no usable host key — the caller
        /// then serves nothing, which is the right failure: an SSH endpoint
        /// with an improvised identity is worse than no endpoint.
        pub fn build(
            cfg: &crate::config::AgentConfig,
            services: super::SessionServices,
        ) -> Option<Arc<Self>> {
            let pem = cfg.ssh_host_key.as_deref()?;
            let host_key = match ssh_key::PrivateKey::from_openssh(pem) {
                Ok(k) => k,
                Err(e) => {
                    warn!(%e, "ssh: the stored host key is unreadable — not serving SSH");
                    return None;
                }
            };
            let host_fingerprint = host_key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string();

            let mut authorized = Vec::new();
            for (i, line) in cfg.ssh_authorized_keys.iter().enumerate() {
                match PublicKey::from_openssh(line) {
                    Ok(k) => authorized.push(k),
                    // Name the index, never the line: a malformed entry is
                    // still key material and does not belong in a log.
                    Err(e) => warn!(
                        index = i,
                        %e, "ssh: ignoring an unparseable ssh_authorized_keys entry"
                    ),
                }
            }
            if authorized.is_empty() {
                warn!(
                    "ssh: no usable entries in ssh_authorized_keys — the port will answer \
                     but every authentication attempt will be refused"
                );
            }

            let config = russh::server::Config {
                // A session left open by a dropped carrier should not pin
                // resources forever; ten minutes of silence ends it.
                inactivity_timeout: Some(Duration::from_secs(600)),
                // Slow down guessing without making a legitimate retry painful.
                auth_rejection_time: Duration::from_secs(2),
                auth_rejection_time_initial: Some(Duration::from_secs(0)),
                keys: vec![host_key],
                window_size: channel_window(),
                ..Default::default()
            };

            // Resolve the key-list identity ONCE, here, so a missing or
            // malformed `ssh_account_mode` is a start-up log line rather than
            // a per-session surprise.
            let key_list_run_as = match cfg.ssh_account_mode.as_deref() {
                Some(m) => parse_account_mode(m),
                None => Err(
                    "ssh_account_mode is not set on this device, so keys in ssh_authorized_keys \
                     may authenticate but cannot run anything. Set it to daemon, console_user or \
                     named:<account> to choose what those keys get."
                        .to_string(),
                ),
            };
            if let Err(e) = &key_list_run_as
                && !authorized.is_empty()
            {
                warn!(%e, "ssh: ssh_authorized_keys is populated but has no account mode");
            }

            // Unset is permissive (see `Ctx::deny_daemon_grants`), so the
            // device that has not chosen is the one worth saying it out loud
            // on — an operator reading this log should not have to know the
            // key exists to learn that it is off.
            let deny_daemon_grants = cfg.ssh_max_privilege.as_deref() == Some("console_user");
            if !deny_daemon_grants {
                warn!(
                    "ssh: ssh_max_privilege is not set to console_user, so a server grant asking \
                     for the daemon identity would run as SYSTEM/root here. Set it if this device \
                     should refuse that even from a control plane that asks."
                );
            }

            info!(
                fingerprint = %host_fingerprint,
                authorized_keys = authorized.len(),
                key_list_run_as = key_list_run_as.as_ref().map(|r| r.label()).unwrap_or_else(|_| "unset".into()),
                %deny_daemon_grants,
                exec_streaming = cfg.ssh_exec_streaming,
                "ssh: server ready"
            );
            Some(Arc::new(Self {
                config: Arc::new(config),
                authorized,
                key_list_run_as,
                deny_daemon_grants,
                services,
                forward_acl: cfg.forward_acl.clone(),
                forwards: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FORWARDS)),
                exec_streaming: cfg.ssh_exec_streaming,
                service_ceiling: None,
                forward_refusal: None,
            }))
        }

        /// FR-105 — the SYSTEM service's server, built per connection: its
        /// own host key, the anchor's ceiling, and nothing from any config
        /// the signed-in user can write. No key list (that list is the user's
        /// to edit, so a key in it would be SYSTEM for the asking), and no
        /// forwards (their allowlist is the user's too). `services.asker` is
        /// that connection's worker ([`super::Asker::Worker`]). `None` when
        /// the key does not parse.
        pub fn for_service(
            host_key_pem: &str,
            ceiling: roomler_ai_remote_control::models::SshServiceCeiling,
            services: super::SessionServices,
        ) -> Option<Arc<Self>> {
            let host_key = match ssh_key::PrivateKey::from_openssh(host_key_pem) {
                Ok(k) => k,
                Err(e) => {
                    warn!(%e, "ssh-service: the service's host key is unreadable — not serving SSH");
                    return None;
                }
            };
            let fingerprint = host_key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string();
            let config = russh::server::Config {
                // The worker's values: an abandoned session ends after ten
                // minutes of silence, and guessing is slowed.
                inactivity_timeout: Some(Duration::from_secs(600)),
                auth_rejection_time: Duration::from_secs(2),
                auth_rejection_time_initial: Some(Duration::from_secs(0)),
                keys: vec![host_key],
                window_size: channel_window(),
                ..Default::default()
            };
            info!(%fingerprint, ?ceiling, "ssh-service: serving a connection");
            Some(Arc::new(Self {
                config: Arc::new(config),
                authorized: Vec::new(),
                key_list_run_as: Err("keys in ssh_authorized_keys are not accepted on the \
                                      SYSTEM service's port: that list is the signed-in \
                                      user's to edit"
                    .to_string()),
                // The anchor's ceiling decides instead (`service_ceiling`).
                deny_daemon_grants: false,
                services,
                // Off as well as refused below, so no path to a forward
                // exists here even past `forward_refusal`.
                forward_acl: crate::tunnel::acl::AgentForwardAcl {
                    enabled: false,
                    allowlist: Vec::new(),
                },
                forwards: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FORWARDS)),
                exec_streaming: true,
                service_ceiling: Some(ceiling),
                forward_refusal: Some(
                    "port forwarding is not served through the SYSTEM service: the allowlist \
                     that would gate it is the signed-in user's to edit",
                ),
            }))
        }
    }

    /// Everything a session is allowed to do, decided in ONE place — at
    /// authentication, from the server grant or the device-owned key list —
    /// and the only shape the request handlers consume.
    ///
    /// This type exists to kill a bug class, not to organise code: rc.419
    /// (key-list identity fell through to SYSTEM) and P5d (`consent_mode`
    /// destructured away) were both fields that crossed into a session and
    /// were dropped on the floor, silently. Its constructors destructure
    /// their inputs EXHAUSTIVELY — no `..`, and every field either flows into
    /// the type or is consumed against a written decision — so the next field
    /// added to a grant fails to compile until someone decides what a session
    /// does with it.
    pub struct ResolvedSessionPolicy {
        /// What the session runs as. `Err` = authenticate-then-refuse with
        /// this reason when something is asked to run — a bare auth failure
        /// cannot explain itself, which is why the refusal is deferred.
        pub run_as: Result<crate::exec::RunAs, String>,
        /// Sentinel the operator is prompted on before anything runs. `None`
        /// = no prompt: either the policy said an explicit `Auto`, or this is
        /// a key-list session — the break-glass path, deliberately exempt
        /// from a gate the control plane owns.
        pub consent_sentinel: Option<String>,
        /// Hard end of the session, enforced by disconnect. `None` =
        /// unbounded, which ONLY the key-list path produces — deliberately:
        /// the break-glass session must not die under whoever is fixing the
        /// control plane. A grant always carries a bound (0 clamps to the
        /// ceiling), making `ssh_limits::MAX_SESSION_SECS`'s "after which the
        /// agent closes it" true rather than aspirational.
        pub deadline: Option<tokio::time::Instant>,
        /// Who to attribute every action to, in every log line.
        pub caller: String,
        /// The grant this session redeemed, for P8 activity reports —
        /// correlating a reported action back to the server's own decision
        /// row in `ssh_audit`. `None` for a key-list session, which no grant
        /// backs and which therefore has nothing to correlate to.
        pub grant_id: Option<String>,
        /// FR-90 P3-8-2a — an agent session's: one `exec` on one channel, and
        /// nothing else ([`super::Grant::one_command`]). Every request handler
        /// that could do more reads it.
        pub one_command: bool,
    }

    impl ResolvedSessionPolicy {
        /// Resolve a redeemed server grant. The grant is authoritative for
        /// everything a session may do; nothing the CLIENT said is consulted.
        ///
        /// `deny_daemon_grants` is the one exception, and it is the device's,
        /// not the client's — the M5 ceiling from `ssh_max_privilege`. See
        /// [`Ctx::deny_daemon_grants`].
        pub(super) fn from_grant(
            grant: super::Grant,
            peer: std::net::SocketAddr,
            deny_daemon_grants: bool,
        ) -> Self {
            use roomler_ai_remote_control::models::{ConsentMode, ssh_limits};

            // EXHAUSTIVE on purpose — see the type doc. A field added to the
            // grant must be routed here, in writing, before this compiles.
            let super::Grant {
                grant_id,
                public_key,
                caller,
                account_mode,
                account,
                consent_mode,
                session_secs,
                one_command,
                deadline,
            } = grant;
            // Two fields were spent BEFORE resolution, and that is their
            // decision: `public_key` is how `take_grant_for` found this grant
            // (auth logged its fingerprint), and `deadline` is the redemption
            // window `prune` already enforced. Consumed here so the
            // destructure stays exhaustive and a NEW field cannot borrow this
            // line as precedent for being dropped.
            let _ = (public_key, deadline);

            // The ceiling REFUSES rather than downgrading. A caller who asked
            // for root and silently got a user shell has been told something
            // untrue about their own session — they would read a permission
            // error as the command's problem, not the device's answer. The
            // refusal is deferred to run time (an `Err` here) so it can say
            // this on stderr; an auth failure cannot explain itself.
            let run_as = match crate::exec::RunAs::from_wire(&account_mode, account.as_deref()) {
                Ok(crate::exec::RunAs::Daemon) if deny_daemon_grants => Err(
                    "this device refuses ssh sessions that run as the daemon identity \
                     (ssh_max_privilege = console_user). Ask for console_user instead."
                        .to_string(),
                ),
                other => other,
            };

            Self {
                run_as,
                // Only an explicit `Auto` skips the operator. `Prompt`,
                // `Email`, `Push` and a server that said NOTHING all ask —
                // the fail-safe direction for a gate whose whole purpose is a
                // human in the loop, and the same rule Fleet RPC applies. The
                // grant id doubles as the sentinel the decision arrives on.
                consent_sentinel: match consent_mode {
                    Some(ConsentMode::Auto) => None,
                    _ => Some(grant_id.clone()),
                },
                grant_id: Some(grant_id),
                // A grant session is ALWAYS time-bounded. `record_grant`
                // already clamped this, but resolving is total on its own:
                // 0 means the ceiling, never "forever".
                deadline: Some(
                    tokio::time::Instant::now()
                        + std::time::Duration::from_secs(ssh_limits::clamp_session_secs(
                            session_secs,
                        )),
                ),
                caller: format!("ssh:{caller}@{peer}"),
                one_command,
            }
        }

        /// Resolve a key-list session — the break-glass path with no server
        /// policy behind it. Everything it may do is device-owned config.
        pub(super) fn from_key_list(ctx: &Ctx, user: &str, peer: std::net::SocketAddr) -> Self {
            Self {
                // Resolved once at start-up (`Ctx::build`), so a typo'd
                // `ssh_account_mode` is a boot log line; unset refuses with
                // the reason on stderr rather than falling through to the
                // daemon's own identity (the rc.419 bug).
                run_as: ctx.key_list_run_as.clone(),
                // Deliberately EXEMPT from consent: this path exists for when
                // the control plane is the broken thing, and blocking it on a
                // policy the control plane owns would take the emergency
                // route away exactly when it is needed.
                consent_sentinel: None,
                // Deliberately UNBOUNDED for the same reason; the server's
                // inactivity timeout still reaps an abandoned session.
                deadline: None,
                // All a key-list session can honestly claim: the username the
                // client typed, and the overlay address WireGuard proved.
                caller: format!("ssh:{user}@{peer} (key-list)"),
                // No grant, so nothing to correlate to. Its activity is still
                // reported (it is the path most worth watching), just without
                // a decision row to join against — the `(key-list)` suffix on
                // `caller` is what identifies it.
                grant_id: None,
                // The device owner's own break-glass key: no agent session's
                // grant backs it, so nothing limits it to one command.
                one_command: false,
            }
        }

        /// FR-105 — hold a resolved grant to the anchor's `ssh` ceiling, on
        /// the SYSTEM service's server. It REFUSES, never downgrades (the M5
        /// rule): a caller who asked for SYSTEM and quietly got the signed-in
        /// user would read the device's answer as their command's. The server
        /// routes only grants the published ceiling permits, so this bites
        /// only when an administrator lowered it since.
        pub(super) fn within_service_ceiling(
            mut self,
            ceiling: roomler_ai_remote_control::models::SshServiceCeiling,
        ) -> Self {
            use roomler_ai_remote_control::models::{SshAccountMode, SshServiceCeiling};
            if let Ok(run_as) = &self.run_as {
                let mode = match run_as {
                    crate::exec::RunAs::Daemon => Some(SshAccountMode::Daemon),
                    crate::exec::RunAs::ConsoleUser => Some(SshAccountMode::ConsoleUser),
                    crate::exec::RunAs::Named(_) => None,
                };
                if !mode.is_some_and(|m| ceiling.permits(m)) {
                    let allowed = match ceiling {
                        SshServiceCeiling::Off => "not at all",
                        SshServiceCeiling::ConsoleUser => "only as the signed-in user",
                        SshServiceCeiling::System => "as SYSTEM or the signed-in user",
                    };
                    self.run_as = Err(format!(
                        "this device's administrator allows SSH through its SYSTEM service \
                         {allowed} (`roomlerd anchor ssh`), and this session asked to run as \
                         {}",
                        run_as.label()
                    ));
                }
            }
            self
        }
    }

    /// Parse the device-owned `ssh_account_mode` into a [`RunAs`].
    ///
    /// Accepts the same vocabulary the server's `SshPolicy.account_mode` uses,
    /// plus `named:<account>` — the wire carries the account in its own field,
    /// but a single config string needs somewhere to put it.
    ///
    /// [`RunAs`]: crate::exec::RunAs
    pub(super) fn parse_account_mode(mode: &str) -> Result<crate::exec::RunAs, String> {
        match mode.trim() {
            "daemon" => Ok(crate::exec::RunAs::Daemon),
            "console_user" => Ok(crate::exec::RunAs::ConsoleUser),
            other => match other.strip_prefix("named:") {
                Some(a) if !a.trim().is_empty() => {
                    Ok(crate::exec::RunAs::Named(a.trim().to_string()))
                }
                _ => Err(format!(
                    "ssh_account_mode {other:?} is not one of daemon | console_user | \
                     named:<account>"
                )),
            },
        }
    }

    /// Per-connection state.
    pub struct Handler {
        ctx: Arc<Ctx>,
        /// The calling node's overlay address. Unforgeable — the packet reached
        /// us only by clearing WireGuard against a key from our netmap — so it
        /// is what every log line and audit record is keyed on.
        peer: std::net::SocketAddr,
        /// What this session may do, resolved ONCE at authentication. `None`
        /// only before auth — russh does not deliver channel requests until
        /// auth succeeded, so the handlers treat its absence as a refusal
        /// rather than a reachable state.
        policy: Option<ResolvedSessionPolicy>,
        /// A share stream owns precisely one grant, never the global/key-list fallback.
        shared_stream: bool,
        shared_cancel: Option<tokio_util::sync::CancellationToken>,
        stream_grant: Option<super::Grant>,
        /// Whether the session-deadline watchdog is running; armed on the
        /// first channel open so multiplexed channels share one timer.
        deadline_armed: bool,
        /// Terminal type and geometry from `pty_request`, held until the shell
        /// starts. `Some` is also what distinguishes an interactive session
        /// from a one-shot command.
        pty_req: Option<(String, crate::pty::WinSize)>,
        /// Sink for client keystrokes, live only while a terminal is. Cleared
        /// on EOF so the shell sees end-of-input.
        channel_input: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        /// Resize half of the live terminal.
        pty_handle: Option<crate::pty::PtyHandle>,
        /// FR-89 — one abort per exec channel (FR-97 P4b: and per Windows console-user
        /// sftp channel), fired when the client closes that channel
        /// ([`channel_close`](russh::server::Handler::channel_close)) or when the session
        /// ends (`Drop`). A streamed command has no wall clock, so THIS is what ends
        /// one whose reader has gone; a token cancels synchronously, which is what
        /// `Drop` needs. Minted before the consent wait, so a channel closed during the
        /// prompt leaves nothing to run (the engine checks it before spawning).
        exec_aborts: std::collections::HashMap<ChannelId, tokio_util::sync::CancellationToken>,
        /// FR-55 — holds the machine awake for as long as this session lives.
        ///
        /// A field rather than a call pair, for the same reason `Drop` below
        /// carries the activity report: a session ends in many ways and only
        /// one of them is a path anyone would remember to annotate. Dropping
        /// the handler is the event they all share, so the guard rides along
        /// with it and cannot be leaked.
        _awake: Option<crate::power::ActivityGuard>,
        /// Who asks the person before anything runs: this process, or
        /// (FR-105) the worker that carried this connection.
        asker: Asker,
        /// FR-90 P3-8-2a — what a session granted one command has used of it.
        /// Read only when its policy says `one_command`.
        used: OneCommandUse,
    }

    /// FR-90 P3-8-2a — a one-command session's one channel and one `exec`.
    /// An attempt counts as used whether or not it runs, so a refused or
    /// failed `exec` cannot be followed by another.
    #[derive(Default)]
    struct OneCommandUse {
        channel: bool,
        exec: bool,
    }

    impl Handler {
        pub fn new(ctx: Arc<Ctx>, peer: std::net::SocketAddr) -> Self {
            // Taken before `ctx` moves into the struct below.
            let awake = ctx
                .services
                .power_activity
                .as_ref()
                .map(crate::power::ActivityGuard::new);
            let asker = ctx.services.asker.clone();
            Self {
                ctx,
                peer,
                policy: None,
                shared_stream: false,
                shared_cancel: None,
                stream_grant: None,
                deadline_armed: false,
                pty_req: None,
                channel_input: None,
                pty_handle: None,
                exec_aborts: std::collections::HashMap::new(),
                _awake: awake,
                asker,
                used: OneCommandUse::default(),
            }
        }

        pub(crate) fn new_shared(
            ctx: Arc<Ctx>,
            peer: std::net::SocketAddr,
            grant: super::Grant,
            cancel: tokio_util::sync::CancellationToken,
        ) -> Self {
            let mut handler = Self::new(ctx, peer);
            handler.shared_stream = true;
            handler.shared_cancel = Some(cancel);
            handler.stream_grant = Some(grant);
            handler
        }
        /// FR-90 P3-8-2a — was this session granted one command? `false`
        /// before authentication, when russh delivers no request anyway.
        fn one_command(&self) -> bool {
            self.policy.as_ref().is_some_and(|p| p.one_command)
        }

        /// Start the one-per-session watchdog that ends the connection when
        /// the granted lifetime runs out. A deadline already in the past
        /// fires immediately, so a channel opened late in a session cannot
        /// outrun the bound.
        ///
        /// Disconnecting is the whole enforcement: the pty pump's writes then
        /// fail, which drops the terminal and kills its process group, and an
        /// exec still in flight is cancelled by the handler's `Drop` (FR-89 —
        /// a streamed command has no wall clock of its own; the buffered
        /// kill-switch path is additionally bounded by the engine's).
        /// Key-list sessions have no deadline (see
        /// [`ResolvedSessionPolicy::from_key_list`]) and never arm this.
        /// Report one P8 activity event for this session, if the device opted
        /// in AND the session has resolved a policy.
        ///
        /// Both conditions are checked HERE rather than at each call site, so
        /// adding a new kind of session action cannot accidentally report
        /// from a device that never consented to reporting.
        fn report(
            &self,
            kind: SshActivityKind,
            detail: Option<String>,
            exit_code: Option<i32>,
            allowed: bool,
        ) {
            let (Some(sink), Some(policy)) = (&self.ctx.services.activity, &self.policy) else {
                return;
            };
            sink.report(
                policy.grant_id.clone(),
                &policy.caller,
                kind,
                detail,
                exit_code,
                allowed,
            );
        }

        fn arm_session_deadline(&mut self, session: &mut Session) {
            if self.deadline_armed {
                return;
            }
            let Some(policy) = &self.policy else { return };
            let Some(deadline) = policy.deadline else {
                return;
            };
            let caller = policy.caller.clone();
            self.deadline_armed = true;
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                warn!(%caller, "ssh: session reached its granted time limit — disconnecting");
                let _ = handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "roomler-ssh: session time limit reached".to_string(),
                        String::new(),
                    )
                    .await;
            });
        }

        /// Serve the `sftp` subsystem — which is also how modern `scp` moves
        /// files (OpenSSH 9 replaced the old rcp-over-exec protocol).
        ///
        /// **It spawns OpenSSH's `sftp-server` as the session's account rather
        /// than serving SFTP in-process**, and that is a privilege decision,
        /// not convenience. In-process file I/O would run as the DAEMON —
        /// SYSTEM on Windows, root under systemd — so a session resolved to
        /// `console_user` would silently read and write every file as root.
        /// `exec` and the pty both drop privilege by handing work to a child;
        /// doing anything else here would introduce a second, weaker privilege
        /// story for the one subsystem that exists to touch files. Same
        /// `apply_run_as`, same consent gate, same identity.
        ///
        /// The bytes are opaque to us: the channel is spliced to the child's
        /// stdio and roomler never parses a single SFTP packet.
        async fn start_sftp_session(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            let Some(policy) = &self.policy else {
                return refuse(session, channel, self.peer, "sftp", "no session policy");
            };
            let run_as = match policy.run_as.clone() {
                Ok(r) => r,
                Err(why) => {
                    return refuse(session, channel, self.peer, "sftp", &why);
                }
            };

            // Windows can only spawn as another user through
            // `CreateProcessAsUserW`, which `tokio::process` cannot do: a
            // `console_user` session takes `exec`'s console-user spawn instead
            // (FR-97 P4b, below). A named account is refused there as it is
            // everywhere on Windows: becoming one needs its credentials.
            #[cfg(windows)]
            if let crate::exec::RunAs::Named(account) = &run_as {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    "sftp",
                    &format!(
                        "cannot transfer files as the local account {account:?}: becoming an \
                         arbitrary user on Windows requires that user's credentials. Use \
                         account_mode `console_user` for the signed-in user."
                    ),
                );
            }
            #[cfg(windows)]
            if matches!(run_as, crate::exec::RunAs::ConsoleUser) && !sftp_as_user_enabled() {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    "sftp",
                    "SFTP as the signed-in user is switched off on this device \
                     (ROOMLERD_SFTP_AS_USER=0).",
                );
            }

            let program = match sftp_server_path() {
                Some(p) => p,
                None => {
                    return refuse(
                        session,
                        channel,
                        self.peer,
                        "sftp",
                        "no `sftp-server` binary on this device. roomler serves SFTP by \
                         handing the channel to OpenSSH's own server so transfers run as \
                         the session's account; install the OpenSSH server package to \
                         enable scp/sftp.",
                    );
                }
            };

            session.channel_success(channel)?;
            let handle = session.handle();
            let caller = policy.caller.clone();
            let consent = policy.consent_sentinel.clone();
            let asker = self.asker.clone();

            if let Some(sentinel) = consent
                && let Err(why) = await_consent(
                    &asker,
                    &handle,
                    channel,
                    &caller,
                    &sentinel,
                    "transfer files over SFTP",
                )
                .await
            {
                let _ = handle
                    .extended_data(channel, 1, format!("roomler: {why}\r\n").into_bytes())
                    .await;
                let _ = handle.close(channel).await;
                return Ok(());
            }

            // FR-97 P4b — Windows `console_user`: `sftp-server` as the person
            // signed in at the console, through `CreateProcessAsUserW`.
            #[cfg(windows)]
            if matches!(run_as, crate::exec::RunAs::ConsoleUser) {
                self.sftp_as_console_user(program, handle, channel, caller);
                return Ok(());
            }

            let mut cmd = tokio::process::Command::new(&program);
            cmd.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // FR-97 P5b — in the person's home, where sshd starts `sftp-server`:
            // a client resolves every relative path against it.
            if let Err(why) = crate::exec::apply_run_as_at_home(&mut cmd, &run_as) {
                let _ = handle
                    .extended_data(channel, 1, format!("roomler: {why}\r\n").into_bytes())
                    .await;
                let _ = handle.close(channel).await;
                return Ok(());
            }

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = handle
                        .extended_data(
                            channel,
                            1,
                            format!("roomler: could not start sftp-server: {e}\r\n").into_bytes(),
                        )
                        .await;
                    let _ = handle.close(channel).await;
                    return Ok(());
                }
            };

            info!(
                peer = %self.peer, %caller, run_as = %run_as.label(),
                privileged = run_as.is_privileged(), server = %program.display(),
                "ssh: sftp session started"
            );

            // Bounded, for the same reason the pty's queue is: a client
            // streaming a large upload must not grow the daemon's memory
            // faster than sftp-server drains it.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
            self.channel_input = Some(tx);

            let mut stdin = child.stdin.take().expect("stdin was piped");
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                while let Some(chunk) = rx.recv().await {
                    if stdin.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                // EOF to the child, so it finishes and exits rather than
                // waiting on a client that has already gone.
                let _ = stdin.shutdown().await;
            });

            let mut stdout = child.stdout.take().expect("stdout was piped");
            let stderr = child.stderr.take();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if handle.data(channel, buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Reap before closing so the child cannot outlive the channel
                // as a zombie holding the user's files open — but WAIT for it
                // first rather than killing it. It closed stdout because it is
                // finishing, and a kill here would throw away the exit code the
                // client is about to be told.
                //
                // ⚠️ That status is not a nicety: `scp` reads it as the verdict
                // on the whole transfer. Without an `exit-status` message
                // OpenSSH reports `Exit status -1` and exits 1 — so before this
                // every scp against a roomler device FAILED on the caller's
                // side while the file arrived complete and byte-correct on the
                // device (measured 2026-09-09 from mars to a corp laptop: 2 MiB
                // uploaded, SHA matched on the far end, `scp rc=1`). A script
                // that branches on that status retries a transfer that already
                // worked. Every other channel path here — pty, exec, and each
                // refusal — sends it; the sftp subsystem was the one that did
                // not.
                let status =
                    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
                        .await
                    {
                        Ok(Ok(st)) => st.code().unwrap_or(0).max(0) as u32,
                        Ok(Err(_)) => 1,
                        Err(_) => {
                            // Only now, and the status is the timeout's, not the
                            // child's — a hung sftp-server must not hang the
                            // channel too.
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            1
                        }
                    };
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });

            // sftp-server writes diagnostics here. They belong in OUR log, not
            // on the client's channel: the SFTP stream is a binary protocol
            // and injecting text into it corrupts the transfer.
            if let Some(mut stderr) = stderr {
                let peer = self.peer;
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut s = String::new();
                    if stderr.read_to_string(&mut s).await.is_ok() && !s.trim().is_empty() {
                        warn!(%peer, msg = %s.trim(), "ssh: sftp-server stderr");
                    }
                });
            }

            Ok(())
        }

        /// FR-97 P4b — the Windows `console_user` half of
        /// [`start_sftp_session`](Self::start_sftp_session): `sftp-server` as
        /// the person signed in at the console, through `exec`'s
        /// `CreateProcessAsUserW` spawn, which `tokio::process` cannot do.
        ///
        /// The same splice as the `tokio::process` path, for the same reasons:
        /// the client's bytes feed its stdin through a bounded queue, and the
        /// client's EOF (the queue's last sender dropping) ends its input. Its
        /// stdout reaches the channel raw, never redacted, because SFTP is a
        /// binary protocol. Its stderr goes to this log, never the channel.
        /// When it exits, the client gets the exit status (`scp`'s verdict on
        /// the whole transfer), then EOF, then close. A client that has gone
        /// kills the process tree: the channel closed or the session ended
        /// (its abort sits beside the exec channels', FR-89), or a send
        /// failed. It starts in the person's profile, where OpenSSH starts
        /// it, so a relative path lands in their home.
        #[cfg(windows)]
        fn sftp_as_console_user(
            &mut self,
            program: std::path::PathBuf,
            handle: russh::server::Handle,
            channel: ChannelId,
            caller: String,
        ) {
            let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
            self.channel_input = Some(tx);
            let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel::<crate::exec::Chunk>(4);
            let abort = tokio_util::sync::CancellationToken::new();
            self.exec_aborts.insert(channel, abort.clone());
            let peer = self.peer;
            info!(
                %peer, %caller, run_as = "console_user", privileged = false,
                server = %program.display(),
                "ssh: sftp session started (CreateProcessAsUserW)"
            );

            let pump_handle = handle.clone();
            let pump_abort = abort.clone();
            let pump = tokio::spawn(async move {
                while let Some(chunk) = raw_rx.recv().await {
                    match chunk.stream {
                        crate::exec::OutStream::Stdout => {
                            if pump_handle.data(channel, chunk.bytes).await.is_err() {
                                pump_abort.cancel();
                                break;
                            }
                        }
                        crate::exec::OutStream::Stderr => {
                            let s = String::from_utf8_lossy(&chunk.bytes);
                            if !s.trim().is_empty() {
                                warn!(%peer, msg = %s.trim(), "ssh: sftp-server stderr");
                            }
                        }
                    }
                }
            });

            let program = program.to_string_lossy().into_owned();
            tokio::spawn(async move {
                let outcome =
                    crate::exec::run_console_user_program(&program, rx, raw_tx, abort).await;
                // Every byte reaches the client before its verdict does.
                let _ = pump.await;
                if let Some(e) = &outcome.error {
                    warn!(%peer, error = %e, "ssh: sftp-server as the console user");
                    // The stderr stream, beside the binary one: the client
                    // prints it, and the transfer was over anyway.
                    let _ = handle
                        .extended_data(channel, 1, format!("roomler: {e}\r\n").into_bytes())
                        .await;
                }
                let status = outcome.exit_code.map(|c| c.max(0) as u32).unwrap_or(1);
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
        }

        /// Start an interactive session on the terminal `pty_request` asked
        /// for.
        ///
        /// Runs the SAME two gates a one-shot command does, in the same order:
        /// resolve the identity from the server (never from the client), then
        /// settle operator consent. An interactive shell is strictly more than
        /// a single command, so it cannot be held to a weaker standard.
        async fn start_pty_session(
            &mut self,
            channel: ChannelId,
            command: Option<String>,
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            let Some((term, size)) = self.pty_req.clone() else {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    "shell",
                    "no terminal was requested for this session",
                );
            };

            // The session's whole entitlement was resolved at auth; requests
            // only READ it. Absent means unauthenticated, which russh does
            // not deliver requests for — refuse rather than reason about it.
            let Some(policy) = &self.policy else {
                return refuse(session, channel, self.peer, "shell", "no session policy");
            };
            let run_as = match policy.run_as.clone() {
                Ok(r) => r,
                Err(e) => {
                    warn!(peer = %self.peer, %e, "ssh: refusing a shell — unusable account mode");
                    let _ = session.extended_data(
                        channel,
                        1,
                        format!("roomler-ssh: {e}\r\n").into_bytes(),
                    );
                    session.channel_failure(channel)?;
                    return Ok(());
                }
            };

            session.channel_success(channel)?;
            let handle = session.handle();
            let caller = policy.caller.clone();
            let consent = policy.consent_sentinel.clone();
            let asker = self.asker.clone();

            if let Some(sentinel) = consent
                && let Err(why) = crate::ssh_shared_stream::while_authorized(
                    self.shared_cancel.as_ref(),
                    await_consent(
                        &asker,
                        &handle,
                        channel,
                        &caller,
                        &sentinel,
                        "open an interactive shell",
                    ),
                )
                .await
            {
                let _ = handle
                    .extended_data(channel, 1, format!("roomler-ssh: {why}\r\n").into_bytes())
                    .await;
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.close(channel).await;
                return Ok(());
            }

            if self
                .shared_cancel
                .as_ref()
                .is_some_and(|c| c.is_cancelled())
            {
                return Ok(());
            }
            let pty = match crate::pty::PtyProcess::spawn(command.as_deref(), &term, size, &run_as)
            {
                Ok(p) => p,
                Err(e) => {
                    warn!(peer = %self.peer, %e, "ssh: could not start the terminal session");
                    let _ = handle
                        .extended_data(channel, 1, format!("roomler-ssh: {e}\r\n").into_bytes())
                        .await;
                    let _ = handle.exit_status_request(channel, 1).await;
                    let _ = handle.close(channel).await;
                    return Ok(());
                }
            };

            // A shared lease is a hard authorization deadline, not a terminal
            // hangup request that a shell may ignore. Only Unix needs this
            // distinction (the Windows pseudoconsole already owns its job).
            #[cfg(unix)]
            let pty = {
                let mut pty = pty;
                if self.shared_stream {
                    pty.hard_kill_on_drop();
                }
                pty
            };

            info!(
                peer = %self.peer, %caller, run_as = %run_as.label(),
                privileged = run_as.is_privileged(), %term,
                "ssh: interactive session started"
            );

            // A bounded queue: an operator holding a key down must not be able
            // to grow the daemon's memory faster than the shell drains it.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
            self.channel_input = Some(tx);
            self.pty_handle = Some(pty.handle());

            let writer = pty.handle();
            tokio::spawn(async move {
                while let Some(chunk) = rx.recv().await {
                    if writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            });

            let caller_for_pump = caller.clone();
            let mut pump = tokio::spawn(async move {
                let mut pty = pty;
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match pty.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if handle.data(channel, buf[..n].to_vec()).await.is_err() {
                                // The client vanished. Drop the session rather
                                // than keep a shell alive against a channel
                                // nobody reads.
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(%e, "ssh: terminal read failed");
                            break;
                        }
                    }
                }
                let status = pty.wait().await;
                info!(caller = %caller_for_pump, status, "ssh: interactive session ended");
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.close(channel).await;
                // `pty` drops here, which kills anything still in the group.
            });
            if let Some(cancel) = self.shared_cancel.clone() {
                tokio::spawn(async move {
                    tokio::select! { biased; _ = cancel.cancelled() => pump.abort(), _ = &mut pump => {} }
                });
            }

            Ok(())
        }
    }

    /// Close the P8 activity envelope (see [`SshActivityKind::SessionClose`]).
    ///
    /// `Drop` rather than a disconnect hook because a session ends in many
    /// ways — clean exit, client vanishing, the `session_secs` deadline firing,
    /// a consent refusal — and only one of those is a code path anyone would
    /// remember to annotate. Dropping the handler is the single event they all
    /// share.
    ///
    /// Reporting is `try_send`, so this is safe in a destructor: no await, no
    /// runtime needed, and a full queue drops the line rather than blocking
    /// teardown.
    ///
    /// FR-89 — the same event ends every exec the session still has running:
    /// a client that disconnected (or whose carrier died, or whose grant
    /// reached its time limit) no longer has a channel the output could go
    /// to, and a streamed command has no wall clock that would end it
    /// otherwise. Cancelling a token is synchronous, so this needs no
    /// runtime either.
    impl Drop for Handler {
        fn drop(&mut self) {
            self.report(SshActivityKind::SessionClose, None, None, true);
            for (_, abort) in self.exec_aborts.drain() {
                abort.cancel();
            }
        }
    }

    impl russh::server::Handler for Handler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
            let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();

            // A server-minted grant is tried FIRST, and consumed when it
            // matches. It is the path that carries a roomler identity, and it
            // is single-use — so a captured public key cannot be replayed into
            // a second session even within the grant's lifetime.
            if self
                .shared_cancel
                .as_ref()
                .is_some_and(|c| c.is_cancelled())
            {
                return Ok(Auth::reject());
            }
            let grant = if self.shared_stream {
                if !self.stream_grant.as_ref().is_some_and(|g| {
                    g.deadline > std::time::Instant::now()
                        && PublicKey::from_openssh(&g.public_key)
                            .is_ok_and(|k| k.key_data() == key.key_data())
                }) {
                    return Ok(Auth::reject());
                }
                self.stream_grant.take()
            } else {
                super::take_grant_for(key)
            };
            if let Some(grant) = grant {
                info!(
                    peer = %self.peer, %user, %fingerprint,
                    grant_id = %grant.grant_id, caller = %grant.caller,
                    account_mode = %grant.account_mode,
                    "ssh: authenticated (server grant)"
                );
                // Resolving HERE — not lazily at each request — is the P5
                // design: one place turns a grant into what a session may do,
                // and the request handlers can only read the result.
                let mut policy = ResolvedSessionPolicy::from_grant(
                    grant,
                    self.peer,
                    self.ctx.deny_daemon_grants,
                );
                // FR-105 — on the SYSTEM service's server, the anchor's
                // ceiling as well.
                if let Some(ceiling) = self.ctx.service_ceiling {
                    policy = policy.within_service_ceiling(ceiling);
                }
                self.policy = Some(policy);
                self.report(SshActivityKind::SessionOpen, None, None, true);
                return Ok(Auth::Accept);
            }

            if self.shared_stream {
                return Ok(Auth::reject());
            }
            // Otherwise the device-owned list. Compare KEY DATA, not the
            // `PublicKey` itself: the parsed value carries the trailing
            // comment, so the same key recorded with a different comment would
            // not be equal.
            let listed = self
                .ctx
                .authorized
                .iter()
                .any(|k| k.key_data() == key.key_data());
            if listed {
                info!(
                    peer = %self.peer, %user, %fingerprint,
                    "ssh: authenticated (ssh_authorized_keys)"
                );
                self.policy = Some(ResolvedSessionPolicy::from_key_list(
                    &self.ctx, user, self.peer,
                ));
                self.report(SshActivityKind::SessionOpen, None, None, true);
                Ok(Auth::Accept)
            } else {
                warn!(
                    peer = %self.peer, %user, %fingerprint,
                    pending_grants = super::pending_grants(),
                    "ssh: rejected — no live grant for this key and it is not in ssh_authorized_keys"
                );
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: russh::server::ChannelOpenHandle,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            // FR-90 P3-8-2a — a session granted one command gets ONE channel:
            // a second could carry a second command.
            if self.one_command() {
                if self.used.channel {
                    warn!(
                        peer = %self.peer,
                        "ssh: refused a second channel: this session was granted one command"
                    );
                    reply
                        .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                        .await;
                    return Ok(());
                }
                self.used.channel = true;
            }
            reply.accept().await;
            self.arm_session_deadline(session);
            Ok(())
        }

        /// `ssh -L`, `-J` and `-W` all arrive here (P7b): the client asks this
        /// device to connect somewhere and splice the socket to the channel.
        ///
        /// Deliberately NOT gated on the session's account: a TCP connect runs
        /// no code and takes on no user identity, so `RunAs` has nothing to
        /// say about it. The gate is the operator's forward allowlist —
        /// default-deny, for the reason in [`forward_allowed`].
        ///
        /// **No interactive consent prompt here, on purpose.** The channel is
        /// not open yet — we are deciding whether to open it — so there is no
        /// stderr to announce a wait on, and a silent 30 s block ending in an
        /// unexplained failure is precisely what P5d rejected for grants. The
        /// operator's consent for a forward is the allowlist entry itself:
        /// given in advance, naming the destination, and default-deny until
        /// they write it. That is a more considered act than a prompt, not a
        /// weaker one.
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            use russh::ChannelOpenFailure;
            if self.shared_stream {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
            let host = host_to_connect.to_string();
            // A u32 on the wire; anything above 65535 is a malformed request,
            // not a port we should try.
            let Ok(port) = u16::try_from(port_to_connect) else {
                warn!(peer = %self.peer, port_to_connect, "ssh: forward refused — port out of range");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            };

            let Some(policy) = &self.policy else {
                warn!(peer = %self.peer, "ssh: forward refused — no session policy");
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            };
            let caller = policy.caller.clone();

            // FR-90 P3-8-2a — nor for a session granted one command, whatever
            // this device's allowlist would let another session reach.
            if policy.one_command {
                warn!(
                    peer = %self.peer, %caller, %host, port,
                    "ssh: forward refused: this session was granted one command"
                );
                self.report(
                    SshActivityKind::Forward,
                    Some(format!("{host}:{port}")),
                    None,
                    false,
                );
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }

            // FR-105 — no forward at all on the SYSTEM service's server.
            let verdict = match self.ctx.forward_refusal {
                Some(why) => Err(why.to_string()),
                None => forward_allowed(&self.ctx.forward_acl, &host, port),
            };
            if let Err(why) = verdict {
                // `ssh` renders this as "administratively prohibited", which
                // tells the caller it was a policy decision and not a dead
                // destination. The *reason* stays here, next to the operator
                // who can act on it — it names internal topology.
                warn!(peer = %self.peer, %caller, %host, port, %why, "ssh: forward refused");
                // Reported as DENIED. A refused forward is the row an operator
                // most wants to see — it is someone probing what this device
                // can reach.
                self.report(
                    SshActivityKind::Forward,
                    Some(format!("{host}:{port}")),
                    None,
                    false,
                );
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }

            // Held for the life of the splice, released when the task ends.
            let Ok(permit) = self.ctx.forwards.clone().try_acquire_owned() else {
                warn!(
                    peer = %self.peer, %caller, %host, port,
                    cap = MAX_CONCURRENT_FORWARDS,
                    "ssh: forward refused — concurrent-forward ceiling reached"
                );
                reply.reject(ChannelOpenFailure::ResourceShortage).await;
                return Ok(());
            };

            // Connect BEFORE accepting, so a dead destination is reported as
            // `ConnectFailed` rather than an accepted channel that immediately
            // hangs up — which the client can only present as a mystery.
            let target = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %self.peer, %host, port, %e, "ssh: forward could not connect");
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                    return Ok(());
                }
            };
            let _ = target.set_nodelay(true);

            reply.accept().await;
            info!(peer = %self.peer, %caller, %host, port, "ssh: forward opened");
            self.report(
                SshActivityKind::Forward,
                Some(format!("{host}:{port}")),
                None,
                true,
            );
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let mut target = target;
                // Bidirectional until either side closes — `copy_bidirectional`
                // already half-closes correctly, which is the thing a
                // hand-rolled select! gets wrong (see `sshcmd::pump`).
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                drop(permit);
            });
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            // FR-90 P3-8-2a — one command, asked once: the attempt is spent
            // here, before anything can refuse or fail it.
            if self.one_command() {
                if self.used.exec {
                    return refuse(
                        session,
                        channel,
                        self.peer,
                        "exec",
                        "this session was granted one command, and has asked for it.",
                    );
                }
                self.used.exec = true;
            }
            // The SSH exec payload is bytes, not necessarily UTF-8. Refuse
            // rather than lossily convert: a command with replacement
            // characters in it is not the command the caller asked for.
            let Ok(command) = std::str::from_utf8(data) else {
                warn!(peer = %self.peer, "ssh: exec payload is not valid UTF-8 — refused");
                session.channel_failure(channel)?;
                return Ok(());
            };
            let command = command.to_string();
            session.channel_success(channel)?;

            let handle = session.handle();
            // Everything this session may do — identity, consent, bound — was
            // resolved ONCE at authentication ([`ResolvedSessionPolicy`]);
            // this handler only reads it. Identity comes from the server or
            // the device's own config, never from anything the client said.
            let Some(policy) = &self.policy else {
                let _ = session.extended_data(
                    channel,
                    1,
                    b"roomler-ssh: no session policy\r\n".to_vec(),
                );
                session.exit_status_request(channel, 1)?;
                session.close(channel)?;
                return Ok(());
            };
            let run_as = match policy.run_as.clone() {
                Ok(r) => r,
                Err(e) => {
                    // An unreadable identity is a refusal, never a fallback:
                    // running as the daemon because the policy could not be
                    // parsed is exactly the silent escalation this design
                    // exists to prevent.
                    warn!(peer = %self.peer, %e, "ssh: refusing exec — unusable account mode");
                    let _ = session.extended_data(
                        channel,
                        1,
                        format!("roomler-ssh: {e}\r\n").into_bytes(),
                    );
                    session.exit_status_request(channel, 1)?;
                    session.close(channel)?;
                    return Ok(());
                }
            };
            let caller = policy.caller.clone();
            let consent = policy.consent_sentinel.clone();
            let asker = self.asker.clone();
            // Captured here, where the policy is still borrowed, and reported
            // from inside the task once the exit code exists.
            let activity = self
                .ctx
                .services
                .activity
                .clone()
                .map(|s| (s, policy.grant_id.clone()));
            // The client's stdin, to the command. Without this `data()` had
            // nowhere to put it and dropped every byte, so the command read
            // NUL and `ssh node 'cat > f' < file` wrote an empty file with
            // exit 0. Bounded like the pty's and sftp's queues: a client
            // streaming into a command that is not reading is held back by
            // SSH flow control rather than by the daemon's memory. Bytes that
            // arrive while consent is pending wait here; a refusal drops them.
            let (tx, stdin) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
            self.channel_input = Some(tx);
            // FR-89 — minted HERE, before the consent wait, so a channel that
            // closes while the operator is being asked leaves nothing to run.
            let abort = self
                .shared_cancel
                .as_ref()
                .map_or_else(tokio_util::sync::CancellationToken::new, |c| {
                    c.child_token()
                });
            self.exec_aborts.insert(channel, abort.clone());
            let job = ExecJob {
                handle,
                channel,
                command,
                caller,
                run_as,
                consent,
                asker,
                activity,
                stdin,
                abort,
                // Shared sessions must remain cancellable even when ordinary SSH opts
                // into the legacy buffered engine (which has no abort input).
                shared_stream: self.shared_stream,
                streaming: self.ctx.exec_streaming || self.shared_stream,
            };
            tokio::spawn(run_exec(job));
            Ok(())
        }

        /// A shell request without a prior PTY request is a non-interactive
        /// shell — rare, and not what this exists to serve. Refused with a
        /// reason rather than silently handed a terminal the client never
        /// asked for.
        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            // FR-90 P3-8-2a — never a shell for a session granted one command.
            if self.one_command() {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    "shell",
                    "this session was granted one command, not a shell.",
                );
            }
            if self.pty_req.is_some() {
                // The shell's CONTENTS are never recorded; this row exists so
                // a reader can see that an interactive session happened.
                self.report(SshActivityKind::Shell, None, None, true);
                self.start_pty_session(channel, None, session).await
            } else {
                refuse(
                    session,
                    channel,
                    self.peer,
                    "shell",
                    "a shell needs a terminal here — drop `-T`, or use \
                     `ssh <node> <command>` for a one-shot command.",
                )
            }
        }

        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            term: &str,
            col_width: u32,
            row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            // FR-90 P3-8-2a — nor a terminal: refused before it is recorded,
            // so nothing a later request asks can find one.
            if self.one_command() {
                warn!(
                    peer = %self.peer, %term,
                    "ssh: refused a terminal: this session was granted one command"
                );
                session.channel_failure(channel)?;
                return Ok(());
            }
            // Recorded, not acted on: the terminal is allocated when the
            // shell starts, because that is when the identity it runs as
            // is known and when consent has been settled. Allocating here
            // would leave a pty (and later a shell) alive for a session
            // that is about to be refused.
            self.pty_req = Some((
                term.to_string(),
                crate::pty::WinSize {
                    cols: col_width as u16,
                    rows: row_height as u16,
                },
            ));
            info!(peer = %self.peer, %term, cols = col_width, rows = row_height, "ssh: pty requested");
            session.channel_success(channel)?;
            Ok(())
        }

        /// Client bytes for the channel's process: keystrokes for a terminal,
        /// the client's stdin for an exec'd command, the protocol for
        /// `sftp-server`. With nothing to deliver to (no process yet, or the
        /// session has ended) the send fails and the data is dropped.
        async fn data(
            &mut self,
            _channel: ChannelId,
            data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = &self.channel_input {
                let _ = tx.send(data.to_vec()).await;
            }
            Ok(())
        }

        /// The client's window changed. Resizing the terminal is what makes
        /// the far side reflow. On Unix the kernel also SIGWINCHes the
        /// foreground group, which is how a full-screen application learns to
        /// redraw; ConPTY delivers the equivalent through the console host.
        async fn window_change_request(
            &mut self,
            _channel: ChannelId,
            col_width: u32,
            row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(h) = &self.pty_handle {
                let size = crate::pty::WinSize {
                    cols: col_width as u16,
                    rows: row_height as u16,
                };
                if let Err(e) = h.resize(size) {
                    warn!(peer = %self.peer, %e, "ssh: could not resize the terminal");
                }
            }
            Ok(())
        }

        /// The client stopped sending. Close the terminal's input side so the
        /// shell sees end-of-input and exits on its own, rather than being
        /// killed — a shell that exits normally runs its logout hooks.
        async fn channel_eof(
            &mut self,
            _channel: ChannelId,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.channel_input = None;
            Ok(())
        }

        /// The client closed the channel (FR-89). A command still running on
        /// it has nowhere to write to — russh accepts and DISCARDS data for a
        /// closed channel, so the pump cannot tell — and no wall clock would
        /// end it, so it is ended here: the abort kills the process tree.
        /// A channel whose command already finished has a token that fires
        /// into nothing.
        async fn channel_close(
            &mut self,
            channel: ChannelId,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(abort) = self.exec_aborts.remove(&channel) {
                abort.cancel();
            }
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if self.shared_stream {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    name,
                    "device sharing grants SSH shell/exec only, not subsystems or file transfer",
                );
            }
            // FR-90 P3-8-2a — nor a subsystem, `sftp` included.
            if self.one_command() {
                return refuse(
                    session,
                    channel,
                    self.peer,
                    name,
                    "this session was granted one command, not a subsystem.",
                );
            }
            if name == "sftp" {
                // File operations happen inside `sftp-server`; this records
                // only that a transfer channel was opened.
                self.report(SshActivityKind::Sftp, None, None, true);
                return self.start_sftp_session(channel, session).await;
            }
            refuse(
                session,
                channel,
                self.peer,
                name,
                "only the `sftp` subsystem is implemented.",
            )
        }
    }

    /// May this session open a forward to `host:port`? (P7b)
    ///
    /// **Default-DENY, unlike the tunnel path that shares this ACL**, and the
    /// difference is not an oversight. For a tunnel the SERVER has already
    /// authorized the destination, so an empty `forward_acl.allowlist` sensibly
    /// means "no extra local restriction — trust that decision". A
    /// `direct-tcpip` channel has no server in the path at all: roomler hands
    /// the client a socket and never sees the bytes. The local allowlist is
    /// therefore the ONLY gate, and an empty one has to mean *nothing*, or
    /// every SSH session would silently be an open pivot into whatever the
    /// device can reach.
    ///
    /// So the operator opts in per destination, and the refusal names the key
    /// to set — an unexplained "administratively prohibited" is how `-L` turns
    /// into a mystery.
    pub(super) fn forward_allowed(
        acl: &crate::tunnel::acl::AgentForwardAcl,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        if !acl.enabled {
            return Err("port forwarding is switched off on this device \
                        (`forward_acl.enabled = false`)."
                .into());
        }
        if acl.allowlist.is_empty() {
            return Err(format!(
                "this device forwards nowhere by default. To allow {host}:{port}, add a rule \
                 to `forward_acl.allowlist` in its config. (Tunnels may still work: those are \
                 authorized by the server, and an SSH forward is not.)"
            ));
        }
        match acl.check(
            host,
            port,
            roomler_ai_remote_control::models::ProtocolKind::Tcp,
        ) {
            d if d.is_allow() => Ok(()),
            _ => Err(format!(
                "{host}:{port} is not in this device's `forward_acl.allowlist`."
            )),
        }
    }

    /// Where OpenSSH keeps `sftp-server` on this platform.
    ///
    /// Distribution-specific by nature — Debian puts it under `/usr/lib`,
    /// Red Hat under `/usr/libexec`, macOS ships its own — so this probes a
    /// list rather than hardcoding one and being wrong on half the fleet.
    /// `None` is a normal answer (no OpenSSH server installed) and the caller
    /// turns it into a refusal that says what to install.
    fn sftp_server_path() -> Option<std::path::PathBuf> {
        // `ROOMLER_SFTP_SERVER` first, for a host that keeps it somewhere
        // unusual — an escape hatch beats a support ticket.
        if let Ok(p) = std::env::var("ROOMLER_SFTP_SERVER") {
            let p = std::path::PathBuf::from(p);
            return p.is_file().then_some(p);
        }
        #[cfg(windows)]
        const CANDIDATES: &[&str] = &[
            r"C:\Windows\System32\OpenSSH\sftp-server.exe",
            r"C:\Program Files\OpenSSH\sftp-server.exe",
        ];
        #[cfg(target_os = "macos")]
        const CANDIDATES: &[&str] = &["/usr/libexec/sftp-server", "/usr/lib/ssh/sftp-server"];
        #[cfg(all(unix, not(target_os = "macos")))]
        const CANDIDATES: &[&str] = &[
            "/usr/lib/openssh/sftp-server",     // Debian, Ubuntu
            "/usr/libexec/openssh/sftp-server", // Fedora, RHEL
            "/usr/lib/ssh/sftp-server",         // Arch, Alpine
            "/usr/libexec/sftp-server",
        ];
        CANDIDATES
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file())
    }

    /// FR-97 P4b's kill switch: `ROOMLERD_SFTP_AS_USER=0` puts back the
    /// refusal a Windows `console_user` session got before P4b.
    #[cfg(windows)]
    fn sftp_as_user_enabled() -> bool {
        tunnel_core::env::flag("SFTP_AS_USER", true)
    }

    /// Tell the client no, in a way a human reads on their terminal.
    ///
    /// A bare `channel_failure` surfaces as a blank "administratively
    /// prohibited", which is indistinguishable from a policy denial — so send
    /// the reason on stderr first.
    fn refuse(
        session: &mut Session,
        channel: ChannelId,
        peer: std::net::SocketAddr,
        what: &str,
        why: &str,
    ) -> Result<(), russh::Error> {
        warn!(%peer, request = %what, "ssh: refused an unsupported request");
        let _ = session.extended_data(channel, 1, format!("roomler-ssh: {why}\r\n").into_bytes());
        session.channel_failure(channel)?;
        Ok(())
    }

    /// Ask the operator at this device, and say so on stderr first.
    ///
    /// The advisory line matters: without it a policy of `prompt` looks to the
    /// caller like a 30-second hang, which is the same "a bare failure cannot
    /// explain itself" problem that shapes every other refusal here.
    ///
    /// Who asks arrives with the handler ([`Asker`]): the broker through
    /// [`super::SessionServices`], or (FR-105) the worker's relay. Either way
    /// "nobody can be asked" is not a reachable state — a server that exists
    /// was handed one at construction. (It used to be a process global whose
    /// absence this function had to treat as a denial.)
    ///
    /// `what` names the activity being approved ("open an interactive shell",
    /// "run a command", "transfer files"). FR-27 puts it in front of the person
    /// deciding, not just in the daemon log: "grant SSH" and "give this account
    /// a root shell on my machine right now" are not the same question.
    async fn await_consent(
        asker: &Asker,
        handle: &russh::server::Handle,
        channel: ChannelId,
        caller: &str,
        sentinel: &str,
        what: &str,
    ) -> Result<(), String> {
        let timeout = crate::consent::DEFAULT_PROMPT_TIMEOUT;
        let _ = handle
            .extended_data(
                channel,
                1,
                format!(
                    "roomler-ssh: waiting up to {}s for approval at the device…\r\n",
                    timeout.as_secs()
                )
                .into_bytes(),
            )
            .await;
        match asker {
            Asker::Here { broker, indicator } => {
                ask_here(broker, indicator, caller, sentinel, what, timeout).await
            }
            Asker::Worker(relay) => {
                let verdict = relay.ask(sentinel, caller, what, timeout).await;
                match &verdict {
                    Ok(()) => info!(
                        %caller, %sentinel,
                        "ssh-service: the person at the device approved the session"
                    ),
                    Err(why) => warn!(
                        %caller, %sentinel, %why,
                        "ssh-service: the person at the device did not approve the session"
                    ),
                }
                verdict
            }
        }
    }

    /// Ask the person at this device from THIS process: the native panel,
    /// the desktop companion, the CLI sentinel. `Err` is what the caller's
    /// terminal is told. FR-105 — also how a worker answers the question its
    /// SYSTEM service relays.
    pub(crate) async fn ask_here(
        broker: &crate::consent::ConsentBroker,
        indicator: &crate::indicator::ViewerIndicator,
        caller: &str,
        sentinel: &str,
        what: &str,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        // FR-27 — the same surface chain as a screen-control or exec prompt:
        // the daemon's own panel first, the desktop companion (started if it
        // is not running) second, the CLI sentinel always. SSH used to write
        // the companion marker only, which on a host with the companion closed
        // meant no screen at all — while the native panel on the same desktop
        // was answering exec prompts a minute earlier. `what` is the lead,
        // because "grant SSH" and "open an interactive shell as SYSTEM" are not
        // the same question.
        let view = crate::indicator::PromptView {
            session_hex: sentinel.to_string(),
            title: "SSH session request".into(),
            lead: format!("{caller} wants to {what} on this device."),
            detail: String::new(),
            permissions: String::new(),
            org: String::new(),
            expires_at: std::time::Instant::now() + timeout,
        };
        let native = indicator.show_prompt(view.clone());
        let mut prompt = crate::consent::PendingPrompt {
            kind: crate::consent::PromptKind::Ssh,
            asked_by: caller,
            permissions: String::new(),
            detail: what.to_string(),
            org: String::new(),
            timeout,
            // Written either way — `roomlerd consent --list` must show a
            // natively-prompted session too; the field is what stops the
            // companion from asking the same question twice.
            surface: if native {
                crate::consent::PromptSurface::Native
            } else {
                crate::consent::PromptSurface::Companion
            },
        };
        let marker = match broker.write_prompt(sentinel, &prompt) {
            Ok(_) => true,
            Err(e) => {
                warn!(%caller, %sentinel, %e, native, "ssh: could not write the .pending consent marker");
                false
            }
        };
        let mut have_surface = native;
        let mut notified = false;
        if !native {
            // Awaited, not spawned, and bounded: its verdict is what lets the
            // refusal below say "nobody could be asked" instead of "nobody
            // answered" — different fixes, and the caller cannot tell them
            // apart afterwards.
            let companion_up = tokio::time::timeout(
                crate::signaling::COMPANION_START_BUDGET,
                crate::companion::ensure_running(),
            )
            .await
            .unwrap_or(false);
            // FR-93 P6f — the last on-screen surface, as for a screen-control
            // request: a desktop notification where the companion cannot show
            // the question.
            if !(companion_up && marker) {
                notified = indicator.show_notification_prompt(view).await;
            }
            if notified && marker {
                prompt.surface = crate::consent::PromptSurface::Notification;
                if let Err(e) = broker.write_prompt(sentinel, &prompt) {
                    warn!(%caller, %sentinel, %e, "ssh: could not mark the consent prompt as shown by a notification");
                }
            }
            // A companion that is up and has the marker to read IS a surface:
            // this read `native` alone, so a question the companion showed
            // and nobody answered was reported as one nobody could be asked.
            have_surface = (companion_up && marker) || notified;
        }
        info!(%caller, %sentinel, native, notified, have_surface, "consent prompt surface (ssh)");

        let decision = broker
            .request_with_mode(sentinel, crate::consent::Mode::Prompt { timeout })
            .await;
        // The single convergence point: answered, timed out, or resolved from
        // the CLI — the panel comes down here regardless of who decided.
        indicator.hide_prompt(sentinel);
        if decision.granted() {
            info!(%caller, %sentinel, "ssh: operator approved the session");
            return Ok(());
        }
        warn!(%caller, %sentinel, ?decision, have_surface, "ssh: operator did not approve the session");
        Err(match decision {
            crate::consent::Decision::Timeout if !have_surface => {
                "nobody could be asked at this device — it has no prompt surface (no one at its \
                 screen and the Roomler desktop app is not running); answer with `roomlerd \
                 consent` there, start the desktop app, or set this device's SSH policy to auto"
                    .to_string()
            }
            crate::consent::Decision::Timeout => format!(
                "nobody approved this session at the device within {}s",
                timeout.as_secs()
            ),
            // #1632 — nothing withdraws an SSH prompt today (the cancel path is
            // the RC `Terminate`), but "denied" would be the wrong story if
            // one ever did: nobody said no.
            crate::consent::Decision::Cancelled => {
                "the request was withdrawn before the operator at this device answered".to_string()
            }
            // `Granted` returned `Ok` above; only `Denied` reaches this arm.
            // Spelled out rather than `_` so a new variant fails to compile
            // instead of quietly reading as a refusal.
            crate::consent::Decision::Granted | crate::consent::Decision::Denied => {
                "the operator at this device denied this session".to_string()
            }
        })
    }

    /// Everything [`run_exec`] needs. Each field is a distinct decision —
    /// resolved at authentication (identity, consent, reporting) or in
    /// `exec_request` (the client's input, the abort, the device's streaming
    /// switch) — named so a reader can see which of them a path must check;
    /// nothing here is derived from anything the client said.
    struct ExecJob {
        handle: russh::server::Handle,
        channel: ChannelId,
        command: String,
        caller: String,
        run_as: crate::exec::RunAs,
        /// The consent sentinel to prompt on; `None` = no prompt.
        consent: Option<String>,
        /// Who asks the person (FR-105: this process, or the worker).
        asker: Asker,
        /// The P8 sink and the grant to attribute the report to.
        activity: Option<(ActivitySink, Option<String>)>,
        stdin: crate::exec::StdinFeed,
        /// FR-89 — fired when the channel closes or the session ends.
        abort: tokio_util::sync::CancellationToken,
        /// Shared sessions require immediate revocation, including during consent.
        shared_stream: bool,
        /// Ordinary device setting; shared sessions always use the abortable engine.
        streaming: bool,
    }

    /// What a run came to, whichever path ran it.
    struct Finished {
        exit_code: Option<i32>,
        duration_ms: u64,
        /// Bytes that reached the channel, both streams.
        bytes: u64,
        error: Option<String>,
    }

    /// Chunks waiting between the engine's redaction stage and the channel.
    /// Small on purpose: the whole point of streaming is that a slow client
    /// stops the command rather than filling the daemon (FR-89 D1).
    const SINK_QUEUE: usize = 8;

    /// Run one command through the daemon's existing execution engine and
    /// stream the result back over the channel.
    ///
    /// Deliberately NOT a fresh `Command::spawn`: [`crate::exec`] already owns
    /// the identity model, the per-device concurrency cap, secret redaction,
    /// and process-tree kill. An SSH transport is not a reason to re-implement
    /// any of that.
    ///
    /// FR-89: the default path is the engine's **streaming** variant —
    /// output goes to the channel as it is produced, with no ceiling and no
    /// wall clock; what ends the command is the channel (`abort`). The
    /// buffered variant, with the engine's 1 MiB ceiling and 300 s limit,
    /// stays whole behind `ssh_exec_streaming = false`.
    ///
    /// `stdin` is the client's stdin, fed to the command in order and closed
    /// at the client's EOF. So a command that reads stdin waits for it, as
    /// under OpenSSH — and because the output streams, a command that
    /// PROMPTS now shows its prompt. `ssh -n` is still the answer for
    /// commands that must not read stdin.
    async fn run_exec(job: ExecJob) {
        use roomler_ai_remote_control::models::exec_limits;

        let ExecJob {
            handle,
            channel,
            command,
            caller,
            run_as,
            consent,
            asker,
            activity,
            stdin,
            abort,
            shared_stream,
            streaming,
        } = job;

        // Ask BEFORE anything runs, and refuse rather than fall through. The
        // prompt is deliberately here and not at grant-arrival time: the server
        // has already told the caller where to dial by then, so a refusal there
        // would surface as a connection that rejects them for no stated reason.
        if let Some(sentinel) = consent
            && let Err(why) = crate::ssh_shared_stream::while_authorized(
                if shared_stream { Some(&abort) } else { None },
                await_consent(
                    &asker,
                    &handle,
                    channel,
                    &caller,
                    &sentinel,
                    "run a command",
                ),
            )
            .await
        {
            let _ = handle
                .extended_data(channel, 1, format!("roomler-ssh: {why}\r\n").into_bytes())
                .await;
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = handle.close(channel).await;
            return;
        }

        // FR-89 — the channel closed while the operator was being asked. The
        // consent prompt ran its course (its own teardown is one place, and
        // stays so); what must not happen is the command starting now, as
        // SYSTEM/root, for a reader that left. The engine checks the token
        // again before it spawns; this check just spares the log a run that
        // was never going to deliver anything.
        if abort.is_cancelled() {
            info!(%caller, "ssh: the channel closed before the command started — not running it");
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = handle.close(channel).await;
            return;
        }

        let request_id = format!("ssh-{:016x}", rand::random::<u64>());
        let identity = run_as.label();
        let privileged = run_as.is_privileged();
        let req = crate::exec::ExecRequest {
            request_id,
            // Empty = the host's own default shell, matching `roomler exec`.
            shell: String::new(),
            command: command.clone(),
            // Read by the buffered path only; the streamed path has no wall
            // clock and no ceiling (FR-89 D4).
            timeout_ms: exec_limits::MAX_TIMEOUT_MS,
            max_output_bytes: exec_limits::MAX_OUTPUT_BYTES,
            cwd: None,
            caller: caller.clone(),
            run_as,
            // FR-97 P5b — in the person's home, where sshd runs a command.
            start_in_home: true,
        };

        let finished = if streaming {
            stream_to_channel(&handle, channel, req, stdin, abort).await
        } else {
            buffer_to_channel(&handle, channel, req, stdin).await
        };

        // A run that never reached a process still has to say so on stderr:
        // an empty stream plus exit 0 would read as "the command succeeded and
        // printed nothing", which is the opposite of what happened.
        if let Some(err) = &finished.error {
            let _ = handle
                .extended_data(channel, 1, format!("roomler-ssh: {err}\r\n").into_bytes())
                .await;
        }

        // SSH carries an unsigned status, so anything that is not a clean
        // 0..=255 has to be mapped — and it must map to FAILURE. Clamping
        // instead would turn a negative code (a signal-encoded exit) into 0,
        // reporting success for a process that was killed. `None` means the
        // command never ran at all (refused, timed out, cancelled); 1 is the
        // conventional shell answer for both.
        let status = match finished.exit_code {
            Some(c) if (0..=255).contains(&c) => c as u32,
            _ => 1,
        };
        let _ = handle.exit_status_request(channel, status).await;
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;

        // `privileged` is on the line on purpose: "who ran this, and was it as
        // root?" is the question anyone reading these logs after an incident
        // is actually asking, and it should not require joining against the
        // device's policy to answer.
        info!(
            %caller, run_as = %identity, privileged,
            exit = status, duration_ms = finished.duration_ms,
            bytes = finished.bytes, streamed = streaming,
            "ssh: exec finished"
        );

        // P8 — reported AFTER the run, so the row carries the real exit code
        // rather than "a command was accepted". The command text is the only
        // thing recorded; its OUTPUT stays on this host, which is the whole
        // distinction this feature is built around.
        if let Some((sink, grant_id)) = activity {
            sink.report(
                grant_id,
                &caller,
                SshActivityKind::Exec,
                Some(command),
                finished.exit_code,
                true,
            );
        }
    }

    /// FR-89 — the streamed path: a pump task moves redacted chunks from the
    /// engine's sink onto the channel as they come, and the engine run is
    /// awaited beside it. The pump ends when the sink closes, which the
    /// engine does only after the last chunk, so by the time this returns
    /// everything the command wrote has been handed to russh — the exit
    /// status the caller sends next cannot overtake the output.
    ///
    /// Backpressure is the chain of bounded queues (`docs/roomler-ssh.md`
    /// §3): `handle.data` blocks while the client's window is spent, the sink
    /// fills, the engine's readers stop, the pipe fills, the child blocks.
    async fn stream_to_channel(
        handle: &russh::server::Handle,
        channel: ChannelId,
        req: crate::exec::ExecRequest,
        stdin: crate::exec::StdinFeed,
        abort: tokio_util::sync::CancellationToken,
    ) -> Finished {
        use crate::exec::{Chunk, OutStream};

        let (sink, mut chunks) = tokio::sync::mpsc::channel::<Chunk>(SINK_QUEUE);
        let pump_handle = handle.clone();
        let pump_abort = abort.clone();
        let pump = tokio::spawn(async move {
            let mut delivered = 0u64;
            while let Some(chunk) = chunks.recv().await {
                let n = chunk.bytes.len() as u64;
                let sent = match chunk.stream {
                    OutStream::Stdout => pump_handle.data(channel, chunk.bytes).await.is_ok(),
                    OutStream::Stderr => pump_handle
                        .extended_data(channel, 1, chunk.bytes)
                        .await
                        .is_ok(),
                };
                if !sent {
                    // The SESSION is gone (a closed channel still accepts and
                    // discards — `channel_close` covers that one). Nothing can
                    // be delivered any more, so end the command rather than
                    // let it run on for nobody.
                    pump_abort.cancel();
                    break;
                }
                delivered += n;
            }
            delivered
        });

        let outcome = crate::exec::shared()
            .run_streamed(req, &crate::exec::redactor(), Some(stdin), sink, abort)
            .await;
        let delivered = pump.await.unwrap_or(0);
        Finished {
            exit_code: outcome.exit_code,
            duration_ms: outcome.duration_ms,
            bytes: delivered,
            error: outcome.error,
        }
    }

    /// The pre-FR-89 path, kept whole behind `ssh_exec_streaming = false`:
    /// the engine's wall clock and ceiling, the output after the run, and a
    /// notice when the ceiling cut it.
    async fn buffer_to_channel(
        handle: &russh::server::Handle,
        channel: ChannelId,
        req: crate::exec::ExecRequest,
        stdin: crate::exec::StdinFeed,
    ) -> Finished {
        use roomler_ai_remote_control::models::exec_limits;

        let outcome = crate::exec::shared()
            .run_fed(req, &crate::exec::redactor(), Some(stdin))
            .await;

        // The BYTES, not the text view: an SSH channel is a byte stream, and
        // `ssh <node> cat f > f` must land the file as it is on the device.
        // Sending the decoded text turned every byte that is not UTF-8 into
        // U+FFFD — a 4.4 MB MP4 arrived as 1.9 MB of noise (2026-10-06).
        if !outcome.stdout_bytes.is_empty() {
            let _ = handle.data(channel, outcome.stdout_bytes.clone()).await;
        }
        if !outcome.stderr_bytes.is_empty() {
            let _ = handle
                .extended_data(channel, 1, outcome.stderr_bytes.clone())
                .await;
        }
        // The ceiling is the exec engine's (`docs/roomler-ssh.md` §3). Hitting
        // it must say so: the output simply stopping, with exit 1 and no word,
        // read as a corrupt transfer rather than a limit.
        if outcome.truncated {
            let _ = handle
                .extended_data(
                    channel,
                    1,
                    format!(
                        "roomler-ssh: output stopped at {} bytes, the exec ceiling (ssh_exec_streaming is off on this device). Copy files with scp or sftp, which stream them whole.\r\n",
                        exec_limits::MAX_OUTPUT_BYTES
                    )
                    .into_bytes(),
                )
                .await;
        }
        Finished {
            exit_code: outcome.exit_code,
            duration_ms: outcome.duration_ms,
            bytes: outcome.output_bytes(),
            error: outcome.error,
        }
    }
}

/// Build the per-session server context from config.
#[cfg(all(feature = "overlay-netstack", feature = "ssh-server"))]
fn build_ctx(cfg: &crate::config::AgentConfig, services: SessionServices) -> ServeCtx {
    sshd::Ctx::build(cfg, services)
}

/// Run the SSH protocol over one intercepted connection.
#[cfg(all(feature = "overlay-netstack", feature = "ssh-server"))]
async fn serve_conn(stream: tunnel_core::overlay::netstack::NsTcpStream, ctx: ServeCtx) {
    use tracing::info;

    let peer = stream.peer_addr();
    let Some(ctx) = ctx else {
        // No host key ⇒ nothing to serve. Drop the connection rather than
        // leaving the client hanging on a banner that never arrives.
        warn!(%peer, "ssh: connection dropped — this node has no usable host key");
        return;
    };

    info!(%peer, "ssh: session opening");
    let _live = LiveConnection::open();
    let handler = sshd::Handler::new(ctx.clone(), peer);
    match russh::server::run_stream(ctx.config.clone(), stream, handler).await {
        Ok(session) => match session.await {
            Ok(()) => info!(%peer, "ssh: session closed"),
            Err(e) => info!(%peer, %e, "ssh: session ended"),
        },
        Err(e) => warn!(%peer, %e, "ssh: handshake failed"),
    }
}

/// FR-105 — serve one SSH connection for the SYSTEM service, over `stream`
/// (the service's end of the SSH pipe, after the framing): the service's own
/// host key, the anchor's ceiling, and the person asked through `relay`, the
/// worker that carried the connection. Returns when the session ends.
///
/// Nothing is held awake and nothing is reported from here: the service has
/// no power keeper and no control socket (activity reports from the service
/// are a later phase).
#[cfg(feature = "ssh-server")]
pub async fn serve_for_service<S>(
    stream: S,
    peer: std::net::SocketAddr,
    host_key_pem: &str,
    ceiling: roomler_ai_remote_control::models::SshServiceCeiling,
    relay: crate::ssh_service::ConsentRelay,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let services = SessionServices {
        power_activity: None,
        asker: Asker::Worker(relay),
        activity: None,
    };
    let Some(ctx) = sshd::Ctx::for_service(host_key_pem, ceiling, services) else {
        return;
    };
    let handler = sshd::Handler::new(ctx.clone(), peer);
    match russh::server::run_stream(ctx.config.clone(), stream, handler).await {
        Ok(session) => match session.await {
            Ok(()) => tracing::info!(%peer, "ssh-service: session closed"),
            Err(e) => tracing::info!(%peer, %e, "ssh-service: session ended"),
        },
        Err(e) => warn!(%peer, %e, "ssh-service: handshake failed"),
    }
}

/// FR-96 P2b — SSH connections open on this device right now. A daemon
/// restart ends every one of them, so the restart onto a replaced binary
/// waits while any is open: the likeliest way that binary gets replaced is an
/// admin's `apt upgrade` typed INTO one of these sessions.
static LIVE_CONNECTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many SSH connections are open right now; zero in a build without the
/// SSH server.
pub fn live_connections() -> usize {
    LIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Counts one connection in [`LIVE_CONNECTIONS`] for as long as it lives,
/// whichever way `serve_conn` returns.
#[cfg(feature = "ssh-server")]
pub(crate) struct LiveConnection;

#[cfg(feature = "ssh-server")]
impl LiveConnection {
    pub(crate) fn open() -> Self {
        LIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self
    }
}

#[cfg(feature = "ssh-server")]
impl Drop for LiveConnection {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// ===========================================================================
// P3 — server-minted session grants.
// ===========================================================================

/// One authorization to open a session, pushed by the server as
/// `rc:ssh.grant` after it cleared the org kill-switch, the caller's
/// `SSH_DEVICE` permission and this device's `SshPolicy`.
///
/// The agent does not verify a signature on this. It does not need to: the
/// frame arrived over the control WebSocket the daemon is already
/// authenticated on, which is the same trust path `rc:request` uses to open a
/// remote-control session. What the agent *does* enforce are the bounds it can
/// check locally — expiry, single use, and a cap on how many can be pending —
/// because "the server said so" is not a reason to accept an unbounded table
/// or an eternal key.
#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone)]
pub struct Grant {
    pub grant_id: String,
    /// The public key this grant admits, in OpenSSH form. Matched by key data.
    pub public_key: String,
    /// Display name of the acting principal, for the log and the audit record.
    pub caller: String,
    /// Which local account the session runs as. Carried through now; P5 is
    /// what makes anything other than `daemon` actually happen.
    pub account_mode: String,
    pub account: Option<String>,
    /// Whether the operator AT the device has to approve this session before
    /// anything runs, per the device's `SshPolicy`.
    ///
    /// `None` means the server said nothing, which is treated exactly like
    /// `Prompt` — the fail-safe direction for a gate whose whole purpose is to
    /// put a human in the loop. Only an explicit `Auto` skips the prompt.
    pub consent_mode: Option<roomler_ai_remote_control::models::ConsentMode>,
    /// Server-clamped session lifetime once redeemed.
    pub session_secs: u64,
    /// FR-90 P3-8-2a — an agent session's grant: the session it opens is
    /// served ONE `exec` on ONE channel, and refused a shell, a terminal, a
    /// subsystem, a forward and any second channel. This device enforces it,
    /// not the client: the daemon that holds the key could ask for anything a
    /// key may ask for.
    pub one_command: bool,
    /// LOCAL deadline after which this grant is dead.
    ///
    /// Deliberately an `Instant` derived from arrival rather than the server's
    /// wall-clock `expires_at_ms`: the two machines' clocks can differ by
    /// minutes, and a skewed or malformed timestamp must not be able to
    /// produce a grant that never expires. The server's value only ever
    /// SHORTENS the local ceiling.
    deadline: std::time::Instant,
}

#[cfg(feature = "ssh-server")]
impl Grant {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_shared_stream(
        grant_id: String,
        public_key: String,
        caller: String,
        account_mode: String,
        account: Option<String>,
        consent_mode: Option<roomler_ai_remote_control::models::ConsentMode>,
        session_secs: u64,
        deadline: std::time::Instant,
    ) -> Self {
        Self {
            grant_id,
            public_key,
            caller,
            account_mode,
            account,
            consent_mode,
            session_secs,
            one_command: false,
            deadline,
        }
    }
}

/// Pending grants, oldest first.
///
/// A `Vec` rather than a map because the lookup key is "whichever entry's key
/// data matches", the table is capped at a handful of entries, and a linear
/// scan of eight items is not worth a hashing strategy.
#[cfg(feature = "ssh-server")]
static GRANTS: std::sync::LazyLock<std::sync::Mutex<Vec<Grant>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Most grants we will hold at once. A grant is redeemed within seconds of
/// being issued, so a backlog means something is wrong — and an unbounded
/// table would be a memory sink reachable from the control plane.
#[cfg(feature = "ssh-server")]
const MAX_PENDING_GRANTS: usize = 16;

/// Why [`record_grant`] would not hold a grant.
///
/// A type rather than the string it used to be because the caller now
/// ANSWERS with it (FR-83): the variant crosses the wire in
/// `rc:ssh.grant_ack`, and the person who asked for the session is told which
/// one it was instead of meeting `Permission denied (publickey)`. The text a
/// log line prints is unchanged.
#[cfg(feature = "ssh-server")]
#[derive(Debug)]
pub enum GrantRejected {
    /// The key the server validated does not parse here.
    UnparseableKey(String),
    /// Nothing is left of the window between arrival and the server's
    /// deadline: this clock is ahead of the server's, or the grant spent its
    /// whole life in transit.
    ExpiredOnArrival,
}

#[cfg(feature = "ssh-server")]
impl GrantRejected {
    /// The refusal as the server — and through it the caller — hears it.
    pub fn refusal(&self) -> roomler_ai_remote_control::models::SshGrantRefusal {
        use roomler_ai_remote_control::models::SshGrantRefusal;
        match self {
            Self::UnparseableKey(_) => SshGrantRefusal::Invalid,
            Self::ExpiredOnArrival => SshGrantRefusal::Expired,
        }
    }
}

#[cfg(feature = "ssh-server")]
impl std::fmt::Display for GrantRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnparseableKey(e) => write!(f, "grant carries an unparseable public key: {e}"),
            Self::ExpiredOnArrival => {
                f.write_str("grant is already expired on arrival (clock skew?)")
            }
        }
    }
}

/// Record an `rc:ssh.grant`.
///
/// On `Ok` the grant is in `GRANTS` — the table the auth path reads — so a
/// connection authenticating with its key succeeds from this moment. That is
/// what the caller's `rc:ssh.grant_ack` promises the server (FR-83), which is
/// why the ack is sent only after this returns.
#[cfg(feature = "ssh-server")]
#[allow(clippy::too_many_arguments)]
pub fn record_grant(
    grant_id: String,
    public_key: String,
    caller: String,
    account_mode: String,
    account: Option<String>,
    consent_mode: Option<roomler_ai_remote_control::models::ConsentMode>,
    expires_at_ms: u64,
    session_secs: u64,
    one_command: bool,
) -> Result<(), GrantRejected> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use roomler_ai_remote_control::models::ssh_limits;

    // Parse now, not at authentication time: a malformed key should be a
    // start-up-shaped error in the log, not a mysterious auth failure later.
    russh::keys::ssh_key::PublicKey::from_openssh(&public_key)
        .map_err(|e| GrantRejected::UnparseableKey(e.to_string()))?;

    // Re-clamp the lifetime against our own clock. The server's timestamp can
    // only make the window SMALLER than the local ceiling, never larger.
    let ceiling = Duration::from_secs(ssh_limits::GRANT_TTL_SECS);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let server_window = Duration::from_millis(expires_at_ms.saturating_sub(now_ms));
    let window = server_window.min(ceiling);
    if window.is_zero() {
        return Err(GrantRejected::ExpiredOnArrival);
    }

    let grant = Grant {
        grant_id,
        public_key,
        caller,
        account_mode,
        account,
        consent_mode,
        session_secs: ssh_limits::clamp_session_secs(session_secs),
        one_command,
        deadline: Instant::now() + window,
    };

    let mut grants = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    prune(&mut grants);
    if grants.len() >= MAX_PENDING_GRANTS {
        // Drop the OLDEST rather than refusing the newest: the newest is the
        // one a caller is actively waiting on, and the oldest is within
        // seconds of expiring anyway.
        grants.remove(0);
        tracing::warn!("ssh: pending-grant table full — dropped the oldest");
    }
    tracing::info!(
        grant_id = %grant.grant_id, caller = %grant.caller,
        account_mode = %grant.account_mode, ttl_secs = window.as_secs(),
        one_command = grant.one_command,
        "ssh: grant recorded"
    );
    grants.push(grant);
    Ok(())
}

/// Drop everything past its deadline.
#[cfg(feature = "ssh-server")]
fn prune(grants: &mut Vec<Grant>) {
    let now = std::time::Instant::now();
    grants.retain(|g| {
        let live = g.deadline > now;
        if !live {
            tracing::debug!(grant_id = %g.grant_id, "ssh: grant expired unredeemed");
        }
        live
    });
}

/// Consume the live grant admitting `key`, if any. Single use: a redeemed
/// grant is gone, so a captured public key cannot be replayed into a second
/// session.
#[cfg(feature = "ssh-server")]
fn take_grant_for(key: &russh::keys::ssh_key::PublicKey) -> Option<Grant> {
    let mut grants = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    prune(&mut grants);
    let idx = grants.iter().position(|g| {
        russh::keys::ssh_key::PublicKey::from_openssh(&g.public_key)
            .is_ok_and(|k| k.key_data() == key.key_data())
    })?;
    Some(grants.remove(idx))
}

/// How many grants are pending — surfaced in diagnostics.
#[cfg(feature = "ssh-server")]
pub fn pending_grants() -> usize {
    let mut grants = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    prune(&mut grants);
    grants.len()
}

/// Test-only: empty the table so cases cannot leak into each other through
/// process-global state.
#[cfg(all(test, feature = "ssh-server"))]
fn clear_grants() {
    GRANTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(all(test, feature = "ssh-server"))]
mod tests {
    use roomler_ai_remote_control::models::{SshActivityEvent, SshActivityKind};
    use std::sync::Arc;

    use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
    use tokio::net::{TcpListener, TcpStream};

    /// A client key pair: the private key to authenticate with, and its
    /// `authorized_keys` line for the server side.
    fn client_key(seed: u8) -> (PrivateKey, String) {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
        let line = key.public_key().to_openssh().unwrap();
        (key, line)
    }

    fn cfg_with(authorized: Vec<String>) -> crate::config::AgentConfig {
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = true;
        cfg.ssh_host_key = Some(super::generate_host_key().unwrap());
        cfg.ssh_authorized_keys = authorized;
        cfg
    }

    #[test]
    fn host_public_key_is_the_public_half_of_the_stored_key() {
        // The point of publishing this is that a client can compare what it
        // dialled against it, so it has to be the SAME key the server will
        // actually present — not merely a well-formed one.
        let cfg = cfg_with(vec![]);
        let published = super::host_public_key(&cfg);
        assert!(
            !published.is_empty(),
            "an SSH-enabled device must publish one"
        );

        let served = PrivateKey::from_openssh(cfg.ssh_host_key.as_deref().unwrap())
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        assert_eq!(published, served);

        // And it must be parseable BY A CLIENT, since that is the only thing
        // that ever consumes it.
        let parsed = russh::keys::ssh_key::PublicKey::from_openssh(&published).unwrap();
        assert_eq!(parsed.algorithm().as_str(), "ssh-ed25519");
    }

    #[test]
    fn a_device_with_no_host_key_publishes_nothing_rather_than_junk() {
        // Empty is a meaningful answer on the wire ("cannot prove itself").
        // Returning a placeholder, or panicking, would both be worse: one
        // invites a false verify, the other takes the hello down over a
        // device that is simply not serving SSH.
        let mut cfg = cfg_with(vec![]);
        cfg.ssh_host_key = None;
        assert_eq!(super::host_public_key(&cfg), "");

        // Same for a corrupted key — `Ctx::build` already refuses to serve on
        // it, and publishing an identity the device cannot back would be the
        // one genuinely dangerous outcome.
        cfg.ssh_host_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n".into());
        assert_eq!(super::host_public_key(&cfg), "");
    }

    #[test]
    fn an_unreadable_stored_key_counts_as_no_key_so_the_daemon_can_heal() {
        // The bug this locks: `main.rs` minted only when the key was ABSENT, so
        // a key that was present-but-garbage wedged SSH on that device forever —
        // refusing to serve, publishing nothing, and never replacing it. The
        // device was one restart away from being fine and could not take it.
        //
        // Field case, 0.4.96 on a corp laptop: the stored PEM had picked up
        // literal `\r` escape text, so the BEGIN line was not newline-terminated
        // and the parse failed with `PEM error in pre-encapsulation boundary`.
        // That exact shape is the first case below, because a test written
        // around a tidily-invalid key would not have caught it.
        let mut cfg = cfg_with(vec![]);

        cfg.ssh_host_key = Some(
            "-----BEGIN OPENSSH PRIVATE KEY-----\\r\\r\\\nAAAA\n\
             -----END OPENSSH PRIVATE KEY-----\n"
                .into(),
        );
        assert!(
            !super::stored_host_key_is_usable(&cfg),
            "a PEM whose boundary line is mangled must read as unusable, not as present"
        );

        cfg.ssh_host_key = None;
        assert!(!super::stored_host_key_is_usable(&cfg));

        cfg.ssh_host_key = Some(String::new());
        assert!(!super::stored_host_key_is_usable(&cfg));

        // …and the positive control, without which the three above would pass
        // on a function that simply always returned false.
        cfg.ssh_host_key = Some(super::generate_host_key().unwrap());
        assert!(super::stored_host_key_is_usable(&cfg));
        assert_ne!(super::host_public_key(&cfg), "");
    }

    struct TestClient;

    impl russh::client::Handler for TestClient {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// A fresh services bundle on a unique sentinel dir, exactly what the
    /// daemon hands the server — the startup mode is irrelevant because the
    /// server always prompts with an explicit per-session mode.
    fn test_services() -> super::SessionServices {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("roomler-ssh-consent-{nanos}"));
        super::SessionServices {
            // FR-55 — tests hold nothing awake. `None` is the real production
            // value anywhere no power keeper exists, not a stub.
            power_activity: None,
            asker: super::Asker::Here {
                broker: crate::consent::ConsentBroker::new(crate::consent::Mode::AutoGrant, dir)
                    .expect("a temp sentinel dir"),
                indicator: crate::indicator::ViewerIndicator::disabled(),
            },
            // Reporting off in tests unless a case opts in — the default a
            // device ships with.
            activity: None,
        }
    }

    /// The broker a test's services ask through, so the test can play the
    /// operator.
    fn broker_of(services: &super::SessionServices) -> crate::consent::ConsentBroker {
        match &services.asker {
            super::Asker::Here { broker, .. } => broker.clone(),
            super::Asker::Worker(_) => panic!("a worker's server asks here"),
        }
    }

    /// Serve exactly one connection on a loopback port and hand back its
    /// address plus the consent broker the server was built with, so a test
    /// can play the operator. The transport is a plain TCP socket here on
    /// purpose: P1's tests already prove the interception path, so this
    /// exercises only the SSH layer sitting on top of it.
    async fn serve_one_with(
        cfg: &crate::config::AgentConfig,
    ) -> (std::net::SocketAddr, crate::consent::ConsentBroker) {
        let services = test_services();
        let broker = broker_of(&services);
        let ctx = super::sshd::Ctx::build(cfg, services).expect("a usable host key");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let handler = super::sshd::Handler::new(ctx.clone(), peer);
            if let Ok(session) =
                russh::server::run_stream(ctx.config.clone(), stream, handler).await
            {
                let _ = session.await;
            }
        });
        (addr, broker)
    }

    async fn serve_one(cfg: &crate::config::AgentConfig) -> std::net::SocketAddr {
        serve_one_with(cfg).await.0
    }

    async fn connect(
        addr: std::net::SocketAddr,
        key: PrivateKey,
    ) -> russh::client::Handle<TestClient> {
        let config = Arc::new(russh::client::Config::default());
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = russh::client::connect_stream(config, stream, TestClient)
            .await
            .expect("ssh handshake");
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let res = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .expect("auth exchange");
        assert!(res.success(), "expected the authorized key to be accepted");
        session
    }

    #[test]
    fn a_generated_host_key_round_trips_as_ed25519() {
        let pem = super::generate_host_key().unwrap();
        let parsed = PrivateKey::from_openssh(&pem).expect("parses back");
        assert_eq!(
            parsed.algorithm(),
            russh::keys::ssh_key::Algorithm::Ed25519,
            "the host identity must be ed25519 so the `rsa` feature can stay off"
        );
        // Two calls must not produce the same key, or every device in the fleet
        // would share one host identity.
        assert_ne!(pem, super::generate_host_key().unwrap());
    }

    /// The property that makes `ssh_enabled` safe to ship default-off-but-on:
    /// reaching the port is not the same as getting in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_outside_the_list_cannot_authenticate() {
        let (_authorized_key, authorized_line) = client_key(1);
        let (stranger, _) = client_key(2);
        let addr = serve_one(&cfg_with(vec![authorized_line])).await;

        let config = Arc::new(russh::client::Config::default());
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = russh::client::connect_stream(config, stream, TestClient)
            .await
            .expect("ssh handshake");
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let res = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(stranger), hash),
            )
            .await
            .expect("auth exchange completes");
        assert!(
            !res.success(),
            "a key absent from ssh_authorized_keys must be refused"
        );
    }

    /// An empty list is the default, and it must deny rather than allow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_authorized_list_denies_everyone() {
        let (key, _) = client_key(3);
        let addr = serve_one(&cfg_with(Vec::new())).await;

        let config = Arc::new(russh::client::Config::default());
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = russh::client::connect_stream(config, stream, TestClient)
            .await
            .expect("ssh handshake");
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let res = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .expect("auth exchange completes");
        assert!(!res.success(), "ssh_enabled alone must grant nobody access");
    }

    // ── The key-list account mode ─────────────────────────────────────────

    fn cfg_with_mode(authorized: Vec<String>, mode: Option<&str>) -> crate::config::AgentConfig {
        let mut cfg = cfg_with(authorized);
        cfg.ssh_account_mode = mode.map(str::to_string);
        cfg
    }

    #[test]
    fn account_mode_parses_the_documented_vocabulary() {
        use crate::exec::RunAs;
        assert_eq!(
            super::sshd::parse_account_mode("daemon").unwrap(),
            RunAs::Daemon
        );
        assert_eq!(
            super::sshd::parse_account_mode("console_user").unwrap(),
            RunAs::ConsoleUser
        );
        assert_eq!(
            super::sshd::parse_account_mode("named:goran").unwrap(),
            RunAs::Named("goran".into())
        );
        // Whitespace is tolerated; an empty account and an unknown word are not.
        assert_eq!(
            super::sshd::parse_account_mode(" named: goran ").unwrap(),
            RunAs::Named("goran".into())
        );
        assert!(super::sshd::parse_account_mode("named:").is_err());
        assert!(super::sshd::parse_account_mode("root").is_err());
        assert!(super::sshd::parse_account_mode("").is_err());
    }

    /// THE regression this slice exists for.
    ///
    /// A key-list session used to fall back to `RunAs::Daemon` — SYSTEM/root —
    /// no matter what the device policy said. Listing a key silently handed out
    /// the most privileged identity on the box, and a policy of
    /// `account_mode = console_user` was simply untrue for that path.
    #[test]
    fn an_unset_account_mode_refuses_rather_than_granting_the_daemon_identity() {
        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(20).1], None),
            test_services(),
        )
        .expect("a usable host key");

        let err = ctx
            .key_list_run_as
            .as_ref()
            .expect_err("an unset account mode must NOT resolve to an identity");
        assert!(
            err.contains("ssh_account_mode"),
            "the refusal must name the key to set, got {err:?}"
        );

        // The specific bug: it must not be Daemon.
        assert!(
            !matches!(ctx.key_list_run_as, Ok(crate::exec::RunAs::Daemon)),
            "unset must never mean the daemon's own identity"
        );
    }

    #[test]
    fn a_set_account_mode_is_what_key_list_sessions_get() {
        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(21).1], Some("console_user")),
            test_services(),
        )
        .expect("a usable host key");
        assert_eq!(
            ctx.key_list_run_as.as_ref().unwrap(),
            &crate::exec::RunAs::ConsoleUser
        );

        // `daemon` stays available — but only when asked for by name.
        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(22).1], Some("daemon")),
            test_services(),
        )
        .expect("a usable host key");
        assert_eq!(
            ctx.key_list_run_as.as_ref().unwrap(),
            &crate::exec::RunAs::Daemon
        );
    }

    /// A malformed value must not degrade into a working-but-wrong identity.
    #[test]
    fn a_malformed_account_mode_refuses() {
        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(23).1], Some("administrator")),
            test_services(),
        )
        .expect("a usable host key");
        assert!(ctx.key_list_run_as.is_err());
    }

    /// End to end over a real SSH connection: an authorized key with no account
    /// mode authenticates — so the operator gets a readable explanation rather
    /// than a bare auth failure — and then runs nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_key_list_session_without_an_account_mode_authenticates_but_runs_nothing() {
        let (key, line) = client_key(24);
        let addr = serve_one(&cfg_with_mode(vec![line], None)).await;
        let session = connect(addr, key).await; // auth SUCCEEDS

        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, "echo should-never-run").await.unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr.extend_from_slice(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }

        let out = String::from_utf8_lossy(&stdout);
        let err = String::from_utf8_lossy(&stderr);
        assert!(
            !out.contains("should-never-run"),
            "the command ran without an account mode — the silent-SYSTEM bug is back"
        );
        assert!(
            err.contains("ssh_account_mode"),
            "the caller must be told which key to set, got stderr {err:?}"
        );
        assert_eq!(exit, Some(1));
    }

    /// The end-to-end P2 claim: a real SSH client runs a real command through
    /// the daemon's real exec engine and gets its output and exit status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_authorized_key_runs_a_command_and_gets_its_output() {
        let _slot = exec_slot().await;
        let (key, line) = client_key(4);
        // `daemon` is stated explicitly. It used to be what an unset mode
        // silently produced, and this test passing without naming it was how
        // that went unnoticed — listing a key handed out SYSTEM/root and the
        // suite called it success.
        let addr = serve_one(&cfg_with_mode(vec![line], Some("daemon"))).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, "echo roomler-ssh-p2-ok").await.unwrap();

        let mut stdout = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                russh::ChannelMsg::Close | russh::ChannelMsg::Eof => {}
                _ => {}
            }
        }

        let stdout = String::from_utf8_lossy(&stdout);
        assert!(
            stdout.contains("roomler-ssh-p2-ok"),
            "expected the command's output, got {stdout:?}"
        );
        assert_eq!(exit, Some(0), "a successful command reports exit 0");
    }

    /// The client's stdin reaches an exec'd command, and the client's EOF
    /// ends it: `ssh node 'cat > f' < file`, `tar c . | ssh node 'tar x'`.
    /// Before, `data()` had nowhere to put the bytes and dropped them. The
    /// command read NUL and succeeded with nothing, so the client saw exit 0
    /// and an empty file.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_clients_stdin_reaches_an_execd_command() {
        let _slot = exec_slot().await;
        let (key, line) = client_key(44);
        let addr = serve_one(&cfg_with_mode(vec![line], Some("daemon"))).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        let echo_stdin = if cfg!(windows) {
            "[Console]::In.ReadToEnd()"
        } else {
            "cat"
        };
        channel.exec(true, echo_stdin).await.unwrap();
        channel.data(&b"piped-into-"[..]).await.unwrap();
        channel.data(&b"roomler-ssh"[..]).await.unwrap();
        channel.eof().await.unwrap();

        let mut stdout = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }

        let stdout = String::from_utf8_lossy(&stdout);
        assert!(
            stdout.contains("piped-into-roomler-ssh"),
            "the client's stdin never reached the command: stdout {stdout:?}"
        );
        assert_eq!(exit, Some(0));
    }

    /// A command that emits `bytes` bytes of output in ONE fast operation —
    /// far past the exec engine's 1 MiB ceiling. One operation rather than a
    /// shell loop on purpose: these run against the process-wide
    /// `exec::shared()` engine, whose 4-permit cap the whole SSH suite
    /// competes for, and a slow command holds its permit long enough to
    /// starve the others. A single write also arrives as one long
    /// whitespace-free run, which exercises the redactor's force-settle path.
    fn big_output(bytes: usize) -> String {
        if cfg!(windows) {
            format!("[Console]::Out.Write('x' * {bytes})")
        } else {
            format!("head -c {bytes} /dev/zero | tr '\\0' x")
        }
    }

    /// Drive a command over a real SSH connection and return
    /// `(stdout_len, stderr_text, exit)`.
    async fn run_over_ssh(
        cfg: &crate::config::AgentConfig,
        key: PrivateKey,
        cmd: &str,
    ) -> (usize, String, Option<u32>) {
        let _slot = exec_slot().await;
        let addr = serve_one(cfg).await;
        let session = connect(addr, key).await;
        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, cmd).await.unwrap();
        let mut stdout_len = 0usize;
        let mut stderr = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout_len += data.len(),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr.extend_from_slice(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
        (
            stdout_len,
            String::from_utf8_lossy(&stderr).into_owned(),
            exit,
        )
    }

    /// AC1 — a command whose output is far larger than the engine's 1 MiB
    /// ceiling arrives WHOLE, with exit 0 and no ceiling notice: the streamed
    /// path (the default) has no ceiling. This is the file `ssh <node> cat
    /// bigfile > f` could not move before FR-89.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_command_output_streams_whole() {
        let (key, line) = client_key(60);
        let (stdout_len, stderr, exit) = run_over_ssh(
            &cfg_with_mode(vec![line], Some("daemon")),
            key,
            &big_output(1_500_000),
        )
        .await;
        assert_eq!(exit, Some(0), "stderr: {stderr}");
        assert!(
            stdout_len > 1024 * 1024,
            "streamed output was capped at {stdout_len} bytes — the ceiling was not lifted"
        );
        assert!(
            !stderr.contains("ceiling"),
            "a streamed run must not announce a ceiling it does not have: {stderr:?}"
        );
    }

    /// AC9 — the kill switch restores the pre-FR-89 behaviour exactly: the
    /// same large command, with `ssh_exec_streaming = false`, is capped at
    /// 1 MiB and says so on stderr.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_kill_switch_restores_the_buffered_ceiling() {
        let (key, line) = client_key(61);
        let mut cfg = cfg_with_mode(vec![line], Some("daemon"));
        cfg.ssh_exec_streaming = false;
        let (stdout_len, stderr, _exit) = run_over_ssh(&cfg, key, &big_output(1_500_000)).await;
        assert!(
            stdout_len <= 1024 * 1024,
            "the buffered path must cap at 1 MiB, got {stdout_len} bytes"
        );
        assert!(
            stderr.contains("exec ceiling"),
            "hitting the ceiling must be announced on stderr: {stderr:?}"
        );
    }

    /// A refused request must say why. `scp` turning into a silent hang is the
    /// specific failure this guards against.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unsupported_requests_are_refused_with_a_reason() {
        let (key, line) = client_key(5);
        let addr = serve_one(&cfg_with(vec![line])).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        // `request_subsystem` only reports that the request was *sent*; the
        // verdict comes back on the channel, so read it rather than trusting
        // the send to mean acceptance.
        // `sftp` is served since P7, so the unsupported case needs a
        // subsystem we genuinely do not implement. The point of the test is
        // unchanged: a refusal must arrive WITH a reason.
        channel.request_subsystem(true, "netconf").await.unwrap();

        let mut refused = false;
        let mut reason = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Failure => {
                    refused = true;
                    break;
                }
                russh::ChannelMsg::Success => panic!("an unknown subsystem must not be accepted"),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    reason.extend_from_slice(data)
                }
                _ => {}
            }
        }

        assert!(
            refused,
            "the server must answer sftp with a channel failure"
        );
        let reason = String::from_utf8_lossy(&reason);
        assert!(
            reason.contains("subsystem"),
            "the refusal must say why — a silent failure is how a client turns into a hang; got {reason:?}"
        );
    }

    /// SFTP inherits the session's identity, so a session that resolved to NO
    /// account must not transfer files either.
    ///
    /// This is the same rule P5c set for commands — a key-list session with
    /// `ssh_account_mode` unset authenticates and then runs nothing rather
    /// than quietly taking SYSTEM/root. File transfer is the subsystem where
    /// getting that wrong would be worst, so it is asserted separately
    /// instead of assumed to follow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sftp_is_refused_when_the_session_resolved_to_no_account() {
        let (key, line) = client_key(9);
        // `cfg_with` leaves `ssh_account_mode` unset — the default.
        let addr = serve_one(&cfg_with(vec![line])).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel.request_subsystem(true, "sftp").await.unwrap();

        let mut refused = false;
        let mut reason = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Failure => {
                    refused = true;
                    break;
                }
                russh::ChannelMsg::Success => {
                    panic!("sftp must not open for a session with no account")
                }
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    reason.extend_from_slice(data)
                }
                _ => {}
            }
        }
        assert!(refused, "sftp must be refused without a resolved account");
        assert!(
            !reason.is_empty(),
            "and the refusal must explain itself, or scp just hangs"
        );
    }

    // ── P3: server-minted grants ──────────────────────────────────────────

    /// The grant table is process-global, and `cargo test` runs these
    /// concurrently — so every grant test takes this first and starts from an
    /// empty table. Without it, the capped-table case (which deliberately
    /// overflows the table) evicts the grants the other cases are relying on,
    /// and the failures look like product bugs.
    static GRANT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Take the lock and hand back an empty table.
    async fn grant_test<'a>() -> tokio::sync::MutexGuard<'a, ()> {
        let guard = GRANT_TEST_LOCK.lock().await;
        super::clear_grants();
        guard
    }

    /// The SSH server runs commands through the PROCESS-WIDE exec engine
    /// (`crate::exec::shared()`), whose per-device cap —
    /// `exec_limits::MAX_CONCURRENT_PER_AGENT`, 4 — is a product invariant,
    /// not a test knob. `cargo test` runs this whole suite in one process on
    /// many threads, so every test that actually runs a command holds one of
    /// exactly that many slots for its duration: the suite can then never
    /// have more commands in flight than the engine admits. Without this a
    /// fifth overlapping test is refused with "device is already running 4
    /// commands" and reads as a product bug — measured 2026-10-07 as two
    /// grant tests, then the kill-switch test, each failing on an empty
    /// stdout while passing serialized.
    static EXEC_TEST_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(
        roomler_ai_remote_control::models::exec_limits::MAX_CONCURRENT_PER_AGENT,
    );

    /// Hold a slot for the life of a test that runs a command. Taken AFTER
    /// [`grant_test`] wherever both apply, so there is exactly one lock order.
    async fn exec_slot() -> tokio::sync::SemaphorePermit<'static> {
        EXEC_TEST_SLOTS
            .acquire()
            .await
            .expect("the slot semaphore is never closed")
    }

    fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// A grant that needs no operator approval.
    ///
    /// `Auto` is stated explicitly rather than left to the default because the
    /// default is the OPPOSITE: an absent consent mode means prompt. These
    /// tests assert that a grant runs, so they have to say why nobody is asked.
    fn grant_for(line: &str, ttl_ms: u64) -> Result<String, String> {
        grant_for_with_consent(
            line,
            ttl_ms,
            Some(roomler_ai_remote_control::models::ConsentMode::Auto),
        )
    }

    /// Returns the grant id on success — it doubles as the consent sentinel,
    /// which the operator-approval tests need to answer the prompt.
    fn grant_for_with_consent(
        line: &str,
        ttl_ms: u64,
        consent: Option<roomler_ai_remote_control::models::ConsentMode>,
    ) -> Result<String, String> {
        let grant_id = format!("g-{}", rand::random::<u32>());
        super::record_grant(
            grant_id.clone(),
            line.to_string(),
            "alice@example.com".into(),
            "daemon".into(),
            None,
            consent,
            now_ms() + ttl_ms,
            0,
            false,
        )
        .map(|()| grant_id)
        .map_err(|e| e.to_string())
    }

    /// FR-90 P3-8-2a — an agent session's grant, held to one command, that
    /// needs no operator approval (`Auto`, as [`grant_for`] says why).
    fn one_command_grant_for(line: &str) -> Result<String, String> {
        let grant_id = format!("g-one-{}", rand::random::<u32>());
        super::record_grant(
            grant_id.clone(),
            line.to_string(),
            "agent session 0 of someone (via a device)".into(),
            "daemon".into(),
            None,
            Some(roomler_ai_remote_control::models::ConsentMode::Auto),
            now_ms() + 30_000,
            0,
            true,
        )
        .map(|()| grant_id)
        .map_err(|e| e.to_string())
    }

    /// A grant admits its key, and admits it exactly once. Without single-use,
    /// a captured public key would be a standing credential for the whole
    /// grant lifetime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_grant_admits_its_key_exactly_once() {
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let (key, line) = client_key(10);
        // The device-owned list is EMPTY: this proves the grant alone let the
        // session in.
        let addr = serve_one(&cfg_with(Vec::new())).await;
        grant_for(&line, 30_000).unwrap();
        assert_eq!(super::pending_grants(), 1);

        let session = connect(addr, key.clone()).await;
        assert_eq!(
            super::pending_grants(),
            0,
            "redeeming a grant must consume it"
        );

        // Prove it is a working session, not just an accepted handshake.
        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, "echo granted").await.unwrap();
        let mut out = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { ref data } = msg {
                out.extend_from_slice(data);
            }
        }
        assert!(String::from_utf8_lossy(&out).contains("granted"));

        // The same key a second time now has nothing backing it.
        let addr2 = serve_one(&cfg_with(Vec::new())).await;
        let config = Arc::new(russh::client::Config::default());
        let stream = TcpStream::connect(addr2).await.unwrap();
        let mut replay = russh::client::connect_stream(config, stream, TestClient)
            .await
            .unwrap();
        let hash = replay.best_supported_rsa_hash().await.unwrap().flatten();
        let res = replay
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .unwrap();
        assert!(!res.success(), "a redeemed grant must not be replayable");
    }

    /// An expired grant is not a grant. The deadline is derived from arrival,
    /// so this does not depend on the two clocks agreeing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_expired_grant_admits_nobody() {
        let _lock = grant_test().await;
        let (key, line) = client_key(11);
        let addr = serve_one(&cfg_with(Vec::new())).await;

        // Arrives already past its expiry — rejected outright rather than
        // stored as a live credential.
        assert!(grant_for(&line, 0).is_err());
        assert_eq!(super::pending_grants(), 0);

        // FR-83 — and the refusal that reaches the caller says WHICH: expiry
        // means "the clocks disagree", which someone can fix, where an
        // unusable key means "report a bug". Both paths reject before
        // anything is stored, so this needs no table state of its own.
        use roomler_ai_remote_control::models::SshGrantRefusal;
        let (_, other_line) = client_key(12);
        let expired = super::record_grant(
            "g-expired".into(),
            other_line,
            "alice@example.com".into(),
            "daemon".into(),
            None,
            None,
            0,
            0,
            false,
        )
        .unwrap_err();
        assert!(matches!(expired, super::GrantRejected::ExpiredOnArrival));
        assert_eq!(expired.refusal(), SshGrantRefusal::Expired);
        assert_eq!(
            expired.to_string(),
            "grant is already expired on arrival (clock skew?)",
            "the device's log line must not change with the type"
        );
        let garbage = super::record_grant(
            "g-garbage".into(),
            "not a key".into(),
            "alice@example.com".into(),
            "daemon".into(),
            None,
            None,
            now_ms() + 30_000,
            0,
            false,
        )
        .unwrap_err();
        assert_eq!(garbage.refusal(), SshGrantRefusal::Invalid);
        assert_eq!(super::pending_grants(), 0);

        let config = Arc::new(russh::client::Config::default());
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = russh::client::connect_stream(config, stream, TestClient)
            .await
            .unwrap();
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let res = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .unwrap();
        assert!(!res.success());
    }

    /// The server can only ever SHORTEN the local window. A grant claiming a
    /// year of validity — a skewed clock, or a compromised control plane —
    /// still dies at the local ceiling.
    #[tokio::test]
    async fn a_far_future_expiry_is_clamped_to_the_local_ceiling() {
        use roomler_ai_remote_control::models::ssh_limits;

        let _lock = grant_test().await;
        let (_key, line) = client_key(12);
        grant_for(&line, 365 * 24 * 3600 * 1000).unwrap();

        let grants = super::GRANTS.lock().unwrap();
        let remaining = grants[0]
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        assert!(
            remaining.as_secs() <= ssh_limits::GRANT_TTL_SECS,
            "a grant must never outlive the local ceiling; got {remaining:?}"
        );
    }

    /// A malformed key is refused when the grant arrives, not discovered later
    /// as an unexplained authentication failure.
    #[tokio::test]
    async fn a_grant_with_an_unparseable_key_is_refused_on_arrival() {
        let _lock = grant_test().await;
        assert!(grant_for("ssh-ed25519 not-actually-base64", 30_000).is_err());
        assert_eq!(super::pending_grants(), 0);
    }

    /// The table cannot be grown without bound from the control plane.
    #[tokio::test]
    async fn the_pending_table_is_capped() {
        let _lock = grant_test().await;
        for i in 0..40u8 {
            let (_k, line) = client_key(100u8.wrapping_add(i));
            grant_for(&line, 30_000).unwrap();
        }
        assert!(
            super::pending_grants() <= super::MAX_PENDING_GRANTS,
            "pending grants must stay capped, got {}",
            super::pending_grants()
        );
    }

    // ── Resolution (A1) — the one place session entitlements are decided ──

    fn test_grant(
        consent: Option<roomler_ai_remote_control::models::ConsentMode>,
        session_secs: u64,
    ) -> super::Grant {
        super::Grant {
            grant_id: "g-1".into(),
            public_key: String::new(),
            caller: "alice@example.com".into(),
            account_mode: "daemon".into(),
            account: None,
            consent_mode: consent,
            session_secs,
            one_command: false,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        }
    }

    fn test_peer() -> std::net::SocketAddr {
        "100.64.0.9:55555".parse().unwrap()
    }

    /// Only an explicit `Auto` skips the prompt. Everything else — including a
    /// server that said nothing — puts a human in the loop. The rule now lives
    /// in resolution, the only path a session's consent requirement can take.
    #[test]
    fn resolve_only_an_explicit_auto_skips_the_operator_prompt() {
        use roomler_ai_remote_control::models::ConsentMode;

        let auto = super::sshd::ResolvedSessionPolicy::from_grant(
            test_grant(Some(ConsentMode::Auto), 0),
            test_peer(),
            false,
        );
        assert!(
            auto.consent_sentinel.is_none(),
            "auto is the one mode that runs without asking"
        );
        for m in [
            Some(ConsentMode::Prompt),
            Some(ConsentMode::Email),
            Some(ConsentMode::Push),
            None, // the fail-safe: absent directive ⇒ ask
        ] {
            let resolved = super::sshd::ResolvedSessionPolicy::from_grant(
                test_grant(m, 0),
                test_peer(),
                false,
            );
            assert_eq!(
                resolved.consent_sentinel.as_deref(),
                Some("g-1"),
                "{m:?} must require approval and prompt on the grant id"
            );
        }
    }

    /// A grant session is ALWAYS time-bounded — 0 means the ceiling, never
    /// "forever" — and only the key-list break-glass path is unbounded.
    /// `session_secs` is the third member of the ignored-field class: it was
    /// carried, clamped and stored while nothing ever acted on it.
    #[test]
    fn resolve_bounds_grant_sessions_and_exempts_the_key_list() {
        use roomler_ai_remote_control::models::ssh_limits;

        let secs_until = |deadline: tokio::time::Instant| {
            deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_secs()
        };

        let bounded = super::sshd::ResolvedSessionPolicy::from_grant(
            test_grant(None, 3600),
            test_peer(),
            false,
        );
        let left = secs_until(bounded.deadline.expect("a grant session has a deadline"));
        assert!(
            (3595..=3600).contains(&left),
            "expected ≈3600s, got {left}s"
        );

        let zero =
            super::sshd::ResolvedSessionPolicy::from_grant(test_grant(None, 0), test_peer(), false);
        let left = secs_until(zero.deadline.expect("0 must mean the ceiling, not forever"));
        assert!(
            (ssh_limits::MAX_SESSION_SECS - 5..=ssh_limits::MAX_SESSION_SECS).contains(&left),
            "expected ≈the ceiling, got {left}s"
        );

        // The break-glass path: unbounded, consent-exempt, honestly labelled.
        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(25).1], Some("console_user")),
            test_services(),
        )
        .expect("a usable host key");
        let key_list =
            super::sshd::ResolvedSessionPolicy::from_key_list(&ctx, "roomler", test_peer());
        assert!(key_list.deadline.is_none());
        assert!(key_list.consent_sentinel.is_none());
        assert!(key_list.caller.contains("(key-list)"));
        assert_eq!(key_list.run_as.unwrap(), crate::exec::RunAs::ConsoleUser);
    }

    /// FR-90 P3-8-2a — a grant's `one_command` reaches the session's policy,
    /// which every request handler reads; an ordinary grant's does not, and a
    /// key-list session, the owner's break-glass path, never has it.
    #[test]
    fn resolve_carries_one_command_and_a_key_list_session_never_has_it() {
        let mut grant = test_grant(None, 60);
        grant.one_command = true;
        let session = super::sshd::ResolvedSessionPolicy::from_grant(grant, test_peer(), false);
        assert!(session.one_command);
        let person = super::sshd::ResolvedSessionPolicy::from_grant(
            test_grant(None, 60),
            test_peer(),
            false,
        );
        assert!(!person.one_command);

        let ctx = super::sshd::Ctx::build(
            &cfg_with_mode(vec![client_key(26).1], Some("daemon")),
            test_services(),
        )
        .expect("a usable host key");
        let key_list =
            super::sshd::ResolvedSessionPolicy::from_key_list(&ctx, "roomler", test_peer());
        assert!(!key_list.one_command);
    }

    // ── M5: the device-side privilege ceiling ─────────────────────────────

    /// The hole this closes: every other gate on an SSH session is the
    /// server's, so a control plane that mints `account_mode = daemon` +
    /// `consent_mode = auto` gets an unattended SYSTEM/root shell on every
    /// device that answers. `ssh_max_privilege` is the device's own answer,
    /// and it is the only one that still holds when the server is the
    /// compromised thing.
    #[test]
    fn the_ceiling_refuses_a_daemon_grant_rather_than_downgrading_it() {
        // `test_grant` asks for `daemon` — the shape that matters.
        let refused =
            super::sshd::ResolvedSessionPolicy::from_grant(test_grant(None, 0), test_peer(), true);
        // REFUSED, not downgraded: a caller told they have a session that
        // silently is not the one they asked for reads every later permission
        // error as the command's problem.
        let why = refused
            .run_as
            .expect_err("a daemon grant must be refused, never quietly substituted");
        assert!(
            why.contains("ssh_max_privilege"),
            "the refusal must name the setting that caused it, got {why:?}"
        );
    }

    /// The ceiling bounds ONE thing. A grant that never wanted the daemon
    /// identity is untouched, and so is everything else the grant decides —
    /// otherwise "turn the ceiling on" would be a change nobody could scope.
    #[test]
    fn the_ceiling_leaves_a_console_user_grant_alone() {
        let mut grant = test_grant(None, 3600);
        grant.account_mode = "console_user".into();
        let resolved = super::sshd::ResolvedSessionPolicy::from_grant(grant, test_peer(), true);
        assert_eq!(
            resolved.run_as.expect("console_user is under the ceiling"),
            crate::exec::RunAs::ConsoleUser
        );
        assert_eq!(resolved.consent_sentinel.as_deref(), Some("g-1"));
        assert!(resolved.deadline.is_some());
    }

    /// Unset is PERMISSIVE, deliberately: a device-side ceiling that arrives
    /// switched on revokes a working configuration in the middle of a fleet
    /// roll, and the device you lose root SSH to is liable to be the one you
    /// needed it for. This test is the record of that decision — if it ever
    /// flips, it should be because someone chose to, not by drift.
    #[test]
    fn an_unset_ceiling_changes_nothing() {
        let cfg = cfg_with_mode(vec![client_key(26).1], Some("console_user"));
        assert!(cfg.ssh_max_privilege.is_none(), "unset is the default");
        let ctx = super::sshd::Ctx::build(&cfg, test_services()).expect("a usable host key");
        assert!(
            !ctx.deny_daemon_grants,
            "an unset ceiling must not refuse anything"
        );

        let allowed = super::sshd::ResolvedSessionPolicy::from_grant(
            test_grant(None, 0),
            test_peer(),
            ctx.deny_daemon_grants,
        );
        assert_eq!(
            allowed.run_as.expect("unset ⇒ pre-M5 behaviour"),
            crate::exec::RunAs::Daemon
        );
    }

    /// `console_user` is the ONLY value that arms it — a typo must not read
    /// as "on" (which would break a working device) and must not read as a
    /// silent "off" either, which is why `config set` rejects the value on
    /// the way in rather than here.
    #[test]
    fn only_console_user_arms_the_ceiling() {
        for (value, armed) in [
            (Some("console_user"), true),
            (Some("daemon"), false),
            (None, false),
        ] {
            let mut cfg = cfg_with_mode(vec![client_key(27).1], Some("console_user"));
            cfg.ssh_max_privilege = value.map(str::to_string);
            let ctx = super::sshd::Ctx::build(&cfg, test_services()).expect("a usable host key");
            assert_eq!(
                ctx.deny_daemon_grants, armed,
                "ssh_max_privilege = {value:?} should arm={armed}"
            );
        }
    }

    // ── Operator consent ──────────────────────────────────────────────────

    /// Drive one exec through a consent-gated session and collect the outcome.
    /// The operator's decision is played through the SAME broker the server
    /// was built with — `record_decision` only lands while the prompt is
    /// actually pending (the confused-deputy guard), so the approver polls.
    async fn exec_with_operator_decision(
        approve: bool,
        key_seed: u8,
    ) -> (String, String, Option<u32>, bool) {
        use roomler_ai_remote_control::models::ConsentMode;

        // The callers hold `grant_test()` already; the slot comes second.
        let _slot = exec_slot().await;
        let (key, line) = client_key(key_seed);
        let (addr, broker) = serve_one_with(&cfg_with(Vec::new())).await;
        let grant_id = grant_for_with_consent(&line, 30_000, Some(ConsentMode::Prompt)).unwrap();

        let operator = {
            let sid = grant_id.clone();
            tokio::spawn(async move {
                for _ in 0..200 {
                    if broker.record_decision(&sid, approve) {
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                false
            })
        };

        let session = connect(addr, key).await; // auth SUCCEEDS — consent is not auth
        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, "echo consent-gated-ran").await.unwrap();

        let (mut stdout, mut stderr, mut exit) = (Vec::new(), Vec::new(), None);
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr.extend_from_slice(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
        let decided = operator.await.unwrap();
        (
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            exit,
            decided,
        )
    }

    /// THE positive half P5d could never test: a policy of `prompt` runs the
    /// command once — and only once — a human approves, end to end through a
    /// real broker. Before A2 the broker was a process global no test could
    /// safely publish, so only the refusal side was ever exercised.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_grant_requiring_consent_runs_after_the_operator_approves() {
        let _lock = grant_test().await;
        let (out, err, exit, decided) = exec_with_operator_decision(true, 30).await;
        assert!(decided, "the approval must have been recorded");
        assert!(
            err.contains("waiting up to"),
            "the caller must be warned it is waiting on a human, got stderr {err:?}"
        );
        assert!(
            out.contains("consent-gated-ran"),
            "an approved session must run the command, got {out:?}"
        );
        assert_eq!(exit, Some(0));
    }

    /// The refusal half: a denial refuses with the reason on stderr, and the
    /// command never runs. (`consent_mode` being IGNORED — the P5d bug — would
    /// run it regardless of the decision.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_grant_requiring_consent_refuses_when_the_operator_denies() {
        let _lock = grant_test().await;
        let (out, err, exit, decided) = exec_with_operator_decision(false, 32).await;
        assert!(decided, "the denial must have been recorded");
        assert!(
            !out.contains("consent-gated-ran"),
            "the command ran despite a denial — the ignored-consent_mode bug is back"
        );
        assert!(
            err.contains("denied"),
            "the caller must be told WHY it was refused, got stderr {err:?}"
        );
        assert_eq!(exit, Some(1));
    }

    /// THE session bound (A1): a grant's `session_secs` now ENDS the session.
    /// `ssh_limits::MAX_SESSION_SECS` always said "after which the agent
    /// closes it" — before this slice, nothing did, and the field was carried,
    /// clamped, stored and ignored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_granted_session_ends_at_its_time_bound() {
        use roomler_ai_remote_control::models::ConsentMode;

        let _lock = grant_test().await;
        let (key, line) = client_key(33);
        let addr = serve_one(&cfg_with(Vec::new())).await;
        super::record_grant(
            "g-deadline".into(),
            line,
            "alice@example.com".into(),
            "daemon".into(),
            None,
            Some(ConsentMode::Auto),
            now_ms() + 30_000,
            1, // a one-second session budget
            false,
        )
        .unwrap();

        let start = std::time::Instant::now();
        let session = connect(addr, key).await;
        let mut channel = session.channel_open_session().await.unwrap();
        // No command — just hold the channel and wait for the SERVER to end
        // the session. Nothing on the client side closes anything.
        let ended = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while channel.wait().await.is_some() {}
        })
        .await;
        assert!(
            ended.is_ok(),
            "the server must disconnect a session past its granted lifetime"
        );
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "the session ended before its budget: {:?}",
            start.elapsed()
        );
    }

    // ── Interactive sessions (P4a) ────────────────────────────────────────

    /// THE feature: `ssh <node>` with no command gets a real shell on a real
    /// terminal, types into it, and gets the output back.
    ///
    /// Deliberately asserts on `tty`'s answer rather than just on echoed text —
    /// a pair of pipes would also echo. Only a pty makes `tty` print a device.
    ///
    /// Unix-only because the ASSERTIONS are (`tty`, `tput`); the Windows twin
    /// below covers the same claim with what a console there can answer.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_interactive_session_gets_a_real_terminal() {
        let (key, line) = client_key(40);
        let addr = serve_one(&cfg_with_mode(vec![line], Some("daemon"))).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel
            .data(&b"tty; echo COLS=$(tput cols); exit 0\n"[..])
            .await
            .unwrap();

        let mut out = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }

        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("/dev/pts/") || text.contains("/dev/ttys"),
            "the session must be on a real tty, got {text:?}"
        );
        assert!(
            text.contains("COLS=120"),
            "the shell must see the geometry the client asked for, got {text:?}"
        );
        assert_eq!(exit, Some(0));
    }

    /// THE P4b feature, at the SSH layer: `ssh <windows-node>` with no command
    /// gets a real ConPTY shell, takes typed input, and streams back what the
    /// shell printed.
    ///
    /// The console host's own VT would arrive even from a BROKEN session (that
    /// was precisely the P4b symptom — title and `ESC[2J` and nothing else), so
    /// this asserts on a marker the SHELL produced. Geometry is not asserted:
    /// `mode con` reports the pseudoconsole's buffer, not the client's request,
    /// and pinning that would test the console host rather than us.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_interactive_session_gets_a_real_console() {
        let (key, line) = client_key(43);
        let addr = serve_one(&cfg_with_mode(vec![line], Some("daemon"))).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel
            .data(&b"echo roomler-conpty-ssh-ok\r\nexit\r\n"[..])
            .await
            .unwrap();

        let mut out = Vec::new();
        let mut exit = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }

        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("roomler-conpty-ssh-ok"),
            "the shell's own output must reach the client — the console host's \
             VT alone is exactly the P4b defect; got {text:?}"
        );
        assert!(exit.is_some(), "the session must report an exit status");
    }

    /// A shell without a terminal is refused with a reason rather than handed
    /// one it never asked for. Both platforms, one code path (P4b).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_shell_without_a_pty_is_refused_with_a_reason() {
        let (key, line) = client_key(41);
        let addr = serve_one(&cfg_with_mode(vec![line], Some("daemon"))).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel.request_shell(true).await.unwrap();

        let mut refused = false;
        let mut reason = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Failure => {
                    refused = true;
                    break;
                }
                russh::ChannelMsg::Success => panic!("a shell with no pty must not be accepted"),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    reason.extend_from_slice(data)
                }
                _ => {}
            }
        }
        assert!(refused, "expected a channel failure");
        assert!(
            String::from_utf8_lossy(&reason).contains("terminal"),
            "the refusal must explain itself, got {:?}",
            String::from_utf8_lossy(&reason)
        );
    }

    /// The identity gate applies to interactive sessions exactly as it does to
    /// one-shot commands: an unset key-list account mode means the client gets
    /// a channel failure and a reason, not a root shell. Both platforms —
    /// the refusal happens before any terminal is allocated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_interactive_session_without_an_account_mode_gets_no_shell() {
        let (key, line) = client_key(42);
        let addr = serve_one(&cfg_with_mode(vec![line], None)).await;
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();

        let mut reason = Vec::new();
        let mut out = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    reason.extend_from_slice(data)
                }
                russh::ChannelMsg::Failure => break,
                _ => {}
            }
        }
        assert!(
            out.is_empty(),
            "no shell output may reach a session with no account mode, got {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(
            String::from_utf8_lossy(&reason).contains("ssh_account_mode"),
            "the refusal must name the key to set, got {:?}",
            String::from_utf8_lossy(&reason)
        );
    }

    /// The mode survives the trip into the grant table, so what the server
    /// asked for is what redemption sees.
    #[tokio::test]
    async fn a_recorded_grant_keeps_its_consent_mode() {
        use roomler_ai_remote_control::models::ConsentMode;

        let _lock = grant_test().await;
        let (key, line) = client_key(31);
        grant_for_with_consent(&line, 30_000, Some(ConsentMode::Prompt)).unwrap();

        let parsed = russh::keys::ssh_key::PublicKey::from_openssh(&line).unwrap();
        let taken = super::take_grant_for(&parsed).expect("the grant is redeemable");
        assert_eq!(taken.consent_mode, Some(ConsentMode::Prompt));
        let _ = key;
    }

    // ── P7b: the forward gate ────────────────────────────────────────────
    //
    // These lock the ONE thing that distinguishes an SSH forward from a
    // tunnel forward: the empty allowlist. Both read the same struct, and
    // the tunnel side treats empty as "trust the server" — so if someone
    // ever "unifies" the two readers, `an_empty_allowlist_forwards_nowhere`
    // is what fails, and it says why in its name.

    use crate::tunnel::acl::AgentForwardAcl;
    use roomler_ai_remote_control::models::{
        DestinationRule, HostPattern, PortRange, ProtocolKind,
    };

    fn acl_allowing(host: &str, low: u16, high: u16) -> AgentForwardAcl {
        AgentForwardAcl {
            enabled: true,
            allowlist: vec![DestinationRule {
                host_pattern: HostPattern::Exact(host.into()),
                port_range: PortRange { low, high },
                proto: ProtocolKind::Any,
            }],
        }
    }

    #[test]
    fn an_empty_allowlist_forwards_nowhere() {
        // The DEFAULT config. A tunnel would be allowed here (the server
        // already authorized it); an SSH forward has no such prior decision,
        // so it must be refused or every session is an open pivot.
        let acl = AgentForwardAcl::default();
        assert!(acl.allowlist.is_empty() && acl.enabled, "test premise");
        let why = super::sshd::forward_allowed(&acl, "db.intranet", 5432)
            .expect_err("default config must not forward");
        assert!(
            why.contains("forward_acl.allowlist"),
            "the refusal must name the key to set, got {why:?}"
        );
    }

    #[test]
    fn a_listed_destination_is_allowed_and_only_that_one() {
        let acl = acl_allowing("db.intranet", 5432, 5432);
        assert!(super::sshd::forward_allowed(&acl, "db.intranet", 5432).is_ok());
        // Same host, different port.
        assert!(super::sshd::forward_allowed(&acl, "db.intranet", 22).is_err());
        // Different host, listed port.
        assert!(super::sshd::forward_allowed(&acl, "other.intranet", 5432).is_err());
    }

    #[test]
    fn the_master_switch_beats_a_populated_allowlist() {
        let mut acl = acl_allowing("db.intranet", 5432, 5432);
        acl.enabled = false;
        let why = super::sshd::forward_allowed(&acl, "db.intranet", 5432)
            .expect_err("`enabled = false` must refuse everything");
        assert!(
            why.contains("forward_acl.enabled"),
            "the refusal must name the switch that closed it, got {why:?}"
        );
    }

    #[test]
    fn the_forward_ceiling_refuses_rather_than_queues() {
        // Matches `exec`'s semantics deliberately: a forward that opens two
        // minutes late is worse than one that fails now and says so. If this
        // ever becomes `acquire().await`, a wedged forward silently becomes a
        // wedged *session*.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(
            super::sshd::MAX_CONCURRENT_FORWARDS,
        ));
        let held: Vec<_> = (0..super::sshd::MAX_CONCURRENT_FORWARDS)
            .map(|_| sem.clone().try_acquire_owned().expect("under the cap"))
            .collect();
        assert!(
            sem.clone().try_acquire_owned().is_err(),
            "the {}th concurrent forward must be refused, not queued",
            super::sshd::MAX_CONCURRENT_FORWARDS + 1
        );
        // …and a finished splice returns its permit.
        drop(held);
        assert!(sem.try_acquire_owned().is_ok(), "permits must be released");
    }

    #[test]
    fn a_port_above_the_u16_range_is_not_silently_truncated() {
        // The wire carries a u32. 65536+22 must not become 22 — the
        // conversion lives in the handler, so this locks the reasoning
        // rather than the call.
        assert!(u16::try_from(65_536u32 + 22).is_err());
    }

    // ── FR-90 P3-8-2a: an agent session's grant holds ONE command ─────────

    /// What a channel said until the server closed it.
    struct Heard {
        successes: usize,
        failures: usize,
        out: String,
        err: String,
        exit: Option<u32>,
    }

    async fn hear(channel: &mut russh::Channel<russh::client::Msg>) -> Heard {
        let (mut successes, mut failures, mut exit) = (0, 0, None);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Success => successes += 1,
                russh::ChannelMsg::Failure => failures += 1,
                russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => err.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
        Heard {
            successes,
            failures,
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
            exit,
        }
    }

    /// Read a channel until it has said `n` failures, or 10 s pass: the
    /// answers to refused requests, which leave it open. Any acceptance is a
    /// failure of the test.
    async fn refusals_heard(
        channel: &mut russh::Channel<russh::client::Msg>,
        n: usize,
    ) -> (usize, String) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut failures, mut err) = (0, Vec::new());
        while failures < n {
            match tokio::time::timeout_at(deadline, channel.wait()).await {
                Ok(Some(russh::ChannelMsg::Failure)) => failures += 1,
                Ok(Some(russh::ChannelMsg::Success)) => panic!("a request was accepted"),
                Ok(Some(russh::ChannelMsg::ExtendedData { ref data, ext: 1 })) => {
                    err.extend_from_slice(data)
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        (failures, String::from_utf8_lossy(&err).into_owned())
    }

    /// FR-90 P3-8-2a — an agent session's grant runs its ONE command and no
    /// more: a terminal is refused before it is recorded (the command runs
    /// without one), a second `exec` on the same channel is refused while
    /// the first runs, and a second channel is refused outright. The
    /// device-owned key list is empty, so the grant alone let it in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_granted_one_command_runs_it_once_and_nothing_more() {
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let (key, line) = client_key(60);
        let addr = serve_one(&cfg_with(Vec::new())).await;
        one_command_grant_for(&line).unwrap();
        let session = connect(addr, key).await;

        let mut channel = session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.exec(true, "sleep 1; echo once").await.unwrap();
        channel.exec(true, "echo twice").await.unwrap();
        let heard = hear(&mut channel).await;
        assert!(
            heard.out.contains("once"),
            "the command ran: {:?}",
            heard.out
        );
        assert!(!heard.out.contains("twice"), "and only it: {:?}", heard.out);
        assert_eq!(heard.exit, Some(0));
        assert_eq!(heard.successes, 1, "only the first exec is accepted");
        assert_eq!(
            heard.failures, 2,
            "the terminal and the second exec are refused"
        );
        assert!(
            heard.err.contains("has asked for it"),
            "the second exec's refusal says why: {:?}",
            heard.err
        );

        assert!(
            session.channel_open_session().await.is_err(),
            "a second channel must be refused"
        );
    }

    /// FR-90 P3-8-2a — nor a forward, even to a destination this device
    /// forwards to for any other session (the positive control first); nor a
    /// shell or a subsystem, `sftp` included, on its one channel. Each
    /// refusal of a request on the channel says why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_granted_one_command_gets_no_forward_shell_or_subsystem() {
        let _lock = grant_test().await;
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dest.local_addr().unwrap().port();
        let mut cfg = cfg_with(Vec::new());
        cfg.forward_acl = acl_allowing("127.0.0.1", port, port);

        // An ordinary grant on this device forwards there…
        let (key, line) = client_key(61);
        let addr = serve_one(&cfg).await;
        grant_for(&line, 30_000).unwrap();
        let session = connect(addr, key).await;
        let forward = session
            .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 5555)
            .await;
        assert!(
            forward.is_ok(),
            "the positive control: this device forwards there"
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), dest.accept())
            .await
            .expect("the forward reached its destination")
            .unwrap();

        // …and does not for a session granted one command.
        let (key, line) = client_key(62);
        let addr = serve_one(&cfg).await;
        one_command_grant_for(&line).unwrap();
        let session = connect(addr, key).await;
        let forward = session
            .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 5555)
            .await;
        assert!(
            forward.is_err(),
            "a forward for a session granted one command"
        );

        let mut channel = session.channel_open_session().await.unwrap();
        channel.request_shell(true).await.unwrap();
        channel.request_subsystem(true, "sftp").await.unwrap();
        let (failures, why) = refusals_heard(&mut channel, 2).await;
        assert_eq!(
            failures, 2,
            "the shell and the subsystem are refused: {why:?}"
        );
        assert!(
            why.contains("not a shell") && why.contains("not a subsystem"),
            "each refusal says why: {why:?}"
        );
    }

    // ── FR-90 P3-8-2b: this daemon's own client, against this server ──────

    /// The server's host key, as a client pins it.
    fn served_key(cfg: &crate::config::AgentConfig) -> russh::keys::ssh_key::PublicKey {
        russh::keys::ssh_key::PublicKey::from_openssh(&super::host_public_key(cfg)).unwrap()
    }

    /// FR-90 P3-8-2b — the daemon's client runs ONE command under an agent
    /// session's grant, its key minted for the call and the target's host key
    /// pinned: the exit status and the output come back, nothing cut, and the
    /// grant is spent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_daemons_client_runs_a_sessions_one_command() {
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let cfg = cfg_with(Vec::new());
        let addr = serve_one(&cfg).await;
        let key = crate::ssh_client::mint_key();
        one_command_grant_for(&key.public_key().to_openssh().unwrap()).unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        let ran = crate::ssh_client::exec_one(
            stream,
            served_key(&cfg),
            key,
            "echo one",
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("ran");
        assert_eq!(ran.exit_code, Some(0), "{ran:?}");
        assert!(ran.stdout.contains("one"), "{ran:?}");
        assert!(!ran.truncated);
        assert_eq!(super::pending_grants(), 0, "the grant was redeemed");
    }

    /// FR-90 P3-8-2b — a device that answers with another host key is not
    /// the target: the client refuses it before it authenticates, so the
    /// grant is not spent and nothing runs. And a key no grant admits is
    /// refused by the target.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_daemons_client_pins_the_host_key_and_needs_its_grant() {
        let _lock = grant_test().await;
        let cfg = cfg_with(Vec::new());
        let addr = serve_one(&cfg).await;
        let key = crate::ssh_client::mint_key();
        one_command_grant_for(&key.public_key().to_openssh().unwrap()).unwrap();
        let other = crate::ssh_client::mint_key().public_key().clone();
        let stream = TcpStream::connect(addr).await.unwrap();
        let got = crate::ssh_client::exec_one(
            stream,
            other,
            key,
            "echo one",
            std::time::Duration::from_secs(30),
        )
        .await;
        assert_eq!(got.unwrap_err(), crate::ssh_client::RunError::WrongHostKey);
        assert_eq!(
            super::pending_grants(),
            1,
            "it never authenticated, so its grant is not spent"
        );

        let addr = serve_one(&cfg).await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let got = crate::ssh_client::exec_one(
            stream,
            served_key(&cfg),
            crate::ssh_client::mint_key(),
            "echo one",
            std::time::Duration::from_secs(30),
        )
        .await;
        assert_eq!(got.unwrap_err(), crate::ssh_client::RunError::NotAdmitted);
    }

    /// FR-90 P3-8-2b — one call, whole, through the OS's routes: the request
    /// presents the ticket and the call's key, the "server" grants that key
    /// on this device and answers with the echo, and the client dials, pins,
    /// and runs the command.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_daemons_client_runs_a_whole_call() {
        use roomler_ai_remote_control::ClientMsg;

        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let cfg = cfg_with(Vec::new());
        let addr = serve_one(&cfg).await;
        let host = super::host_public_key(&cfg);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let server = tokio::spawn(async move {
            let Some(ClientMsg::SshRequest {
                request_id,
                public_key,
                ssh_ticket,
                ..
            }) = rx.recv().await
            else {
                panic!("no rc:ssh.request");
            };
            assert_eq!(ssh_ticket.as_deref(), Some("the-ticket"));
            one_command_grant_for(&public_key).unwrap();
            crate::ssh_origin::deliver(
                &request_id,
                crate::ssh_origin::SshGrantAnswer {
                    address: Some(addr.ip().to_string()),
                    port: Some(addr.port()),
                    host_pubkey: Some(host),
                    ssh_ticket_id: Some("k1".into()),
                    ..Default::default()
                },
            );
        });
        let ran = crate::ssh_client::run(
            &tx,
            &crate::ssh_client::OsDialer,
            bson::oid::ObjectId::new(),
            "the-ticket",
            "k1",
            "echo whole",
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("ran");
        server.await.unwrap();
        assert_eq!(ran.exit_code, Some(0), "{ran:?}");
        assert!(ran.stdout.contains("whole"), "{ran:?}");
    }

    // ── P8: activity reporting ───────────────────────────────────────────

    /// Reporting is the DEVICE's decision and it is off unless asked for.
    /// `ActivitySink::new` returning `None` is what makes that structural —
    /// with the gate here, no call site can report from a device that never
    /// opted in, however many new event kinds get added later.
    #[test]
    fn a_device_that_did_not_opt_in_has_no_sink_at_all() {
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.ssh_activity_log, "off must be the shipped default");
        assert!(
            super::ActivitySink::new(&cfg, tx.clone()).is_none(),
            "no sink unless the device opted in"
        );

        cfg.ssh_activity_log = true;
        assert!(super::ActivitySink::new(&cfg, tx).is_some());
    }

    #[tokio::test]
    async fn a_report_carries_the_grant_id_and_the_command() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_activity_log = true;
        let sink = super::ActivitySink::new(&cfg, tx).expect("opted in");

        sink.report(
            Some("grant-7".into()),
            "ssh:Someone@100.65.4.2:1",
            SshActivityKind::Exec,
            Some("uptime".into()),
            Some(0),
            true,
        );

        let msg = rx.try_recv().expect("a frame was queued");
        match msg {
            roomler_ai_remote_control::signaling::ClientMsg::SshActivity {
                grant_id,
                kind,
                detail,
                exit_code,
                allowed,
                ..
            } => {
                assert_eq!(grant_id.as_deref(), Some("grant-7"));
                assert_eq!(kind, SshActivityKind::Exec);
                assert_eq!(detail.as_deref(), Some("uptime"));
                assert_eq!(exit_code, Some(0));
                assert!(allowed);
            }
            other => panic!("expected SshActivity, got {other:?}"),
        }
    }

    /// A command line is about to leave the host, so it gets the same
    /// treatment `exec` gives its output. Without this, `curl -H 'Authorization:
    /// Bearer …'` would put a live token in the org's audit log.
    #[test]
    fn a_reported_command_is_redacted_before_it_leaves_the_host() {
        let out = super::redact_and_cap("curl -H 'Authorization: Bearer sk-not-a-real-token'");
        assert!(
            !out.contains("sk-not-a-real-token"),
            "the bearer token survived redaction: {out}"
        );
    }

    /// Truncation must be VISIBLE. A silently shortened command reads in the
    /// log as a different command from the one that ran.
    #[test]
    fn an_overlong_command_is_capped_and_marked() {
        let long = "x".repeat(SshActivityEvent::MAX_DETAIL * 2);
        let out = super::redact_and_cap(&long);
        assert_eq!(out.chars().count(), SshActivityEvent::MAX_DETAIL + 1);
        assert!(out.ends_with('…'), "truncation must be marked: {out}");
    }

    /// A full outbound queue must lose the log line, never block the session
    /// that produced it. `report` takes `&self` and cannot await, so this is
    /// really a lock on `try_send` never becoming `send`.
    #[test]
    fn a_full_queue_drops_the_report_instead_of_blocking() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_activity_log = true;
        let sink = super::ActivitySink::new(&cfg, tx).expect("opted in");

        // Two reports into a 1-slot channel nobody is draining. The second has
        // nowhere to go; the call must still return.
        for _ in 0..2 {
            sink.report(None, "c", SshActivityKind::Shell, None, None, true);
        }
    }

    // ── FR-105 — the SYSTEM service's server, through the framed pipe ──────

    /// The questions the worker was asked, in order.
    type Asks = Arc<std::sync::Mutex<Vec<crate::ssh_service::ConsentAsk>>>;

    /// One connection to the SYSTEM service's port, carried the way a device
    /// carries it: the returned stream is the caller's connection, the worker
    /// splices it into the "pipe", and the service serves it with its own
    /// host key under `ceiling`. The worker answers every question with
    /// `granted` and `reason`.
    fn through_the_service(
        ceiling: roomler_ai_remote_control::models::SshServiceCeiling,
        granted: bool,
        reason: Option<&'static str>,
    ) -> (tokio::io::DuplexStream, Asks) {
        let pem = super::generate_host_key().unwrap();
        let (service_pipe, worker_pipe) = tokio::io::duplex(256 * 1024);
        tokio::spawn(crate::ssh_service::serve_framed(
            service_pipe,
            move |stream, peer, relay| async move {
                super::serve_for_service(stream, peer, &pem, ceiling, relay).await;
            },
        ));
        let (caller, carried) = tokio::io::duplex(256 * 1024);
        let asks: Asks = Default::default();
        let seen = Arc::clone(&asks);
        tokio::spawn(crate::ssh_service::splice_framed(
            carried,
            worker_pipe,
            "100.64.0.9:41000".parse().unwrap(),
            move |ask: crate::ssh_service::ConsentAsk| {
                seen.lock().unwrap().push(ask.clone());
                async move {
                    crate::ssh_service::ConsentAnswer {
                        id: ask.id,
                        granted,
                        reason: reason.map(String::from),
                    }
                }
            },
        ));
        (caller, asks)
    }

    /// Handshake and authenticate over `stream`; `Err` = refused.
    async fn connect_over(
        stream: tokio::io::DuplexStream,
        key: PrivateKey,
    ) -> Result<russh::client::Handle<TestClient>, ()> {
        let config = Arc::new(russh::client::Config::default());
        let mut session = russh::client::connect_stream(config, stream, TestClient)
            .await
            .expect("ssh handshake");
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let res = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .expect("auth exchange");
        if res.success() { Ok(session) } else { Err(()) }
    }

    /// Run `cmd` on a new channel: (stdout, stderr, exit status).
    async fn exec_over(
        session: &russh::client::Handle<TestClient>,
        cmd: &str,
    ) -> (String, String, Option<u32>) {
        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, cmd).await.unwrap();
        let (mut out, mut err, mut exit) = (Vec::new(), Vec::new(), None);
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => err.extend_from_slice(data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
            exit,
        )
    }

    /// FR-105 — a granted session on the SYSTEM service's port runs once the
    /// person says yes, asked through the worker that carried the
    /// connection, about exactly this grant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_service_session_runs_once_the_worker_says_the_person_approved() {
        use roomler_ai_remote_control::models::{ConsentMode, SshServiceCeiling};
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let (key, line) = client_key(80);
        let grant_id = grant_for_with_consent(&line, 30_000, Some(ConsentMode::Prompt)).unwrap();
        let (caller, asks) = through_the_service(SshServiceCeiling::System, true, None);
        let session = connect_over(caller, key)
            .await
            .expect("the grant admits its key");
        let (out, err, exit) = exec_over(&session, "echo through-the-service").await;
        assert!(
            out.contains("through-the-service"),
            "stdout {out:?}, stderr {err:?}"
        );
        assert_eq!(exit, Some(0));
        let asks = asks.lock().unwrap().clone();
        assert_eq!(asks.len(), 1, "asked once: {asks:?}");
        assert_eq!(asks[0].sentinel, grant_id);
        assert_eq!(asks[0].what, "run a command");
        assert!(asks[0].caller.contains("alice@example.com"), "{asks:?}");
    }

    /// FR-105 — the person's no reaches the caller in words, and nothing runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_service_session_the_person_refuses_runs_nothing() {
        use roomler_ai_remote_control::models::{ConsentMode, SshServiceCeiling};
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let (key, line) = client_key(81);
        grant_for_with_consent(&line, 30_000, Some(ConsentMode::Prompt)).unwrap();
        let (caller, asks) =
            through_the_service(SshServiceCeiling::System, false, Some("not today"));
        let session = connect_over(caller, key).await.expect("admitted");
        let (out, err, exit) = exec_over(&session, "echo should-not-run").await;
        assert!(!out.contains("should-not-run"), "it ran: {out:?}");
        assert!(err.contains("not today"), "stderr {err:?}");
        assert_eq!(exit, Some(1));
        assert_eq!(asks.lock().unwrap().len(), 1);
    }

    /// FR-105 — the anchor's ceiling refuses what it does not permit, before
    /// anyone is asked: a SYSTEM session under a ceiling of `console_user`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_anchor_ceiling_refuses_a_system_session_before_asking() {
        use roomler_ai_remote_control::models::{ConsentMode, SshServiceCeiling};
        let _lock = grant_test().await;
        let _slot = exec_slot().await;
        let (key, line) = client_key(82);
        // `daemon`, the account mode `grant_for_with_consent` asks for.
        grant_for_with_consent(&line, 30_000, Some(ConsentMode::Prompt)).unwrap();
        let (caller, asks) = through_the_service(SshServiceCeiling::ConsoleUser, true, None);
        let session = connect_over(caller, key).await.expect("admitted");
        let (out, err, exit) = exec_over(&session, "echo should-not-run").await;
        assert!(!out.contains("should-not-run"), "it ran: {out:?}");
        assert!(err.contains("only as the signed-in user"), "stderr {err:?}");
        assert_eq!(exit, Some(1));
        assert!(asks.lock().unwrap().is_empty(), "nobody is asked");
    }

    /// FR-105 — nothing the signed-in user can write opens the service's
    /// port: a key with no grant is refused (the service has no key list),
    /// and a granted session cannot open a forward (no allowlist either).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_service_port_takes_no_unlisted_key_and_opens_no_forward() {
        use roomler_ai_remote_control::models::SshServiceCeiling;
        let _lock = grant_test().await;
        let (key, _) = client_key(83);
        let (caller, _) = through_the_service(SshServiceCeiling::System, true, None);
        assert!(
            connect_over(caller, key).await.is_err(),
            "no grant, no session"
        );

        let (key, line) = client_key(84);
        grant_for(&line, 30_000).unwrap();
        let (caller, _) = through_the_service(SshServiceCeiling::System, true, None);
        let session = connect_over(caller, key).await.expect("admitted");
        let opened = session
            .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 5555)
            .await;
        assert!(opened.is_err(), "a forward through the SYSTEM service");
    }
}
