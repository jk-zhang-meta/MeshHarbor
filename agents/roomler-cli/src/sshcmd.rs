// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `meshharbor ssh <device> [args…]` — open an SSH session to another device in
//! this org over the overlay (P6b).
//!
//! ## Why this execs the system `ssh` instead of embedding a client
//!
//! What roomler adds is *discovery, authorization and host-key distribution*:
//! which device, may you, where does it live, and what key will answer. Once
//! those are known, the remaining problem — terminal raw mode, window resize,
//! escape sequences, agent forwarding, `scp`, everything a user expects — is
//! one OpenSSH already solves better than a second implementation would.
//!
//! So this mints a single-session identity, asks the daemon for a grant, drops
//! the pieces into a private temp directory, and hands off. The user's own
//! `ssh` does the session; roomler is not in the data path, which is the same
//! property the server has by design.
//!
//! ## Host-key verification is the point
//!
//! The grant carries the target's host public key (P6a). We write it to a
//! throwaway `known_hosts` and run with `StrictHostKeyChecking=yes`, so a
//! mismatch is a hard failure rather than a prompt. **If the server has no key
//! for the device we refuse to connect** rather than falling back to
//! trust-on-first-use — a client that cannot verify should say so, not quietly
//! accept whatever answers.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::localclient;

/// Username presented to the target. Cosmetic: the roomler SSH server
/// authenticates by KEY and resolves the local account from the device's
/// policy (`account_mode`), so this never selects an identity. A fixed,
/// recognisable value beats echoing the local username, which would imply a
/// correspondence that does not exist.
const SSH_USER: &str = "roomler";

pub async fn run(device: &str, session_secs: u64, args: &[String]) -> Result<i32> {
    // 1. A fresh identity per session. Never reused, never written anywhere
    //    but the private temp dir below, and the daemon never sees the
    //    private half.
    let key = mint_session_key().context("minting a session key")?;
    let public_openssh = key
        .public_key()
        .to_openssh()
        .context("encoding the session public key")?;

    // 2. Ask the daemon, which relays to the server over its authenticated WS.
    //    A dashboard display name is turned into the hex agent id first
    //    (`docs/device-naming.md`); anything the server resolves itself —
    //    a fleet name, an id — goes exactly as typed.
    let node = localclient::agent_selector(device).await?;
    let grant = localclient::ssh_session(&node, &public_openssh, session_secs).await?;

    if let Some(err) = grant.error {
        bail!("{err}");
    }
    let (address, port) = match (grant.address, grant.port) {
        (Some(a), Some(p)) => (a, p),
        // The server answers either a place to dial or a reason; neither is a
        // protocol violation we should paper over with a guess.
        _ => bail!("the server did not say where to dial and gave no reason"),
    };
    let Some(host_pubkey) = grant.host_pubkey else {
        bail!(
            "{device} has not published an SSH host key, so this connection cannot be \
             verified.\nRefusing rather than trusting it on first use. The device needs \
             an agent that has had SSH enabled at least once (rc.444+)."
        );
    };

    // 3. Everything `ssh` needs, in a directory only this user can read.
    let dir = PrivateDir::new().context("creating a private directory for the session")?;
    let key_path = dir.path().join("id");
    write_private(
        &key_path,
        key.to_openssh(ssh_key::LineEnding::LF)?.as_bytes(),
    )
    .context("writing the session key")?;
    let kh_path = dir.path().join("known_hosts");
    // Bracketed host form — required whenever the port is not 22, which for
    // roomler SSH is the normal case (default 2222).
    write_private(
        &kh_path,
        format!("[{address}]:{port} {host_pubkey}\n").as_bytes(),
    )
    .context("writing known_hosts")?;

    // 4. Hand off.
    let status = std::process::Command::new("ssh")
        .arg("-i")
        .arg(&key_path)
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh_path.display()))
        // Verify, never prompt: we just wrote the expected key.
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        // Offer ONLY our session key. Without this, ssh also tries every key
        // in the agent and ~/.ssh, and a device with an authorized_keys entry
        // could authenticate a session the grant never covered.
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{SSH_USER}@{address}"))
        .args(args)
        .status();

    let status = match status {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "no `ssh` client found on this machine. roomler uses the system OpenSSH \
                 client for the session itself.\nInstall it (Windows: \
                 `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`; \
                 Linux/macOS: your distribution's openssh-client)."
            );
        }
        Err(e) => return Err(anyhow!("could not start ssh: {e}")),
    };

    // `dir` drops here, taking the key with it.
    Ok(status
        .code()
        .unwrap_or(if status.success() { 0 } else { 1 }))
}

/// `roomler proxy <host> <port>` — a stdio↔TCP pipe for OpenSSH's
/// `ProxyCommand` (P6c).
///
/// ```text
/// Host *.roomler
///   ProxyCommand roomler proxy %h %p
///   Port 2222
/// ```
///
/// `%h` arrives as `corplap-3.roomler`; the lookup strips that suffix, and a
/// MagicDNS name's, before matching (#1573 — before it did, this very recipe
/// failed for every host). `Port 2222` is roomler SSH's default intercept
/// port; without it `%p` is 22, which reaches only a device's own `sshd`.
///
/// This is TRANSPORT AND NAME RESOLUTION ONLY, and the distinction matters.
/// `ProxyCommand` hands the client a byte pipe; it cannot supply an identity
/// or a host key, because by the time it runs, `ssh` has already decided which
/// key to offer and which `known_hosts` to check. A roomler grant is a
/// single-use key with a ~60 s life, so it cannot live in a static
/// `~/.ssh/config` either — which is exactly why [`run`] exists and why this
/// is a *different* tool rather than the same one.
///
/// So: use this to reach a device **by name** with keys you already manage —
/// a host running its own `sshd`, or a roomler-SSH device where your key is in
/// `ssh_authorized_keys` (the break-glass path). Use `meshharbor ssh` when you
/// want the grant, the policy-resolved account, and host-key verification
/// handled for you.
///
/// A literal IP passes straight through, so `%h` works whether the user wrote
/// a device name or an address.
pub async fn proxy(host: &str, port: u16) -> Result<()> {
    use tokio::net::TcpStream;

    // An address is already an answer. Only a NAME needs the daemon, so a
    // proxy to a literal address keeps working when the daemon is busy.
    let literal = host.parse::<std::net::IpAddr>().ok();
    let addr = if literal.is_some() {
        host.to_string()
    } else {
        match localclient::resolve_overlay_ip(host).await? {
            Some(ip) => ip,
            None => bail!(
                "no device named {host:?} on this mesh (or it has no overlay address). \
                 A device is matched by its bare name, as <name>.roomler, or by its \
                 MagicDNS name; `meshharbor peers` lists what is reachable."
            ),
        }
    };

    let sock = TcpStream::connect((addr.as_str(), port))
        .await
        .with_context(|| {
            let hint = match literal {
                Some(ip) if !is_overlay_address(ip) => HOSTNAME_BEFORE_PERCENT_H,
                _ => "",
            };
            format!("connecting to {addr}:{port}{hint}")
        })?;
    // Nagle would add up to 40 ms to every keystroke of an interactive
    // session riding this pipe.
    let _ = sock.set_nodelay(true);

    pump(sock, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Appended to a failed connect when `%h` was an address the mesh does not
/// own. The trap it names cost a field session several minutes (#1573):
/// OpenSSH applies a `HostName` line BEFORE substituting `%h`, so an existing
/// `Host zeus / HostName <public ip>` block hands the ProxyCommand the PUBLIC
/// address. What surfaces is a bare `actively refused` / `timed out` that
/// names no host and reads exactly like a broken overlay.
const HOSTNAME_BEFORE_PERCENT_H: &str = " (not a mesh overlay address — if you \
     meant a device by name, check ssh_config for a `HostName` line: OpenSSH \
     substitutes it into %h before running the ProxyCommand, so the name \
     never reached roomler)";

/// Whether `ip` lies in the overlay's own space: IPv4 `100.64.0.0/10`, which
/// every tenant's block is carved from, or the derived IPv6
/// `fd72:6f6f:6d6c::/48`. Only ever used to decide whether a failed connect
/// deserves [`HOSTNAME_BEFORE_PERCENT_H`] — never to refuse an address, since
/// a literal outside the overlay can be legitimate (an advertised subnet).
fn is_overlay_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xc0) == 64
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd72 && s[1] == 0x6f6f && s[2] == 0x6d6c
        }
    }
}

/// Splice `input`→socket→`output` until the PEER closes.
///
/// Split out from [`proxy`] so the EOF semantics below are testable without a
/// real stdin — they are the whole substance of this function, and they are
/// easy to get wrong in a way no interactive session reveals.
///
/// ⚠️ **Input EOF half-closes; it does NOT end the proxy.** The obvious
/// `select!` over both directions — first one to finish wins — looks right and
/// breaks every non-interactive use: `scp`, `rsync` and `ssh host cmd` all
/// close stdin immediately, so the proxy would tear the connection down before
/// the peer's first byte arrived. (Caught in the field on rc.447: piping
/// `echo |` into the proxy returned an empty banner instead of the target's
/// `SSH-2.0-…`.) Correct behaviour is netcat's: on input EOF send FIN and keep
/// draining, then exit when the peer closes.
async fn pump<I, O>(sock: tokio::net::TcpStream, mut input: I, mut output: O) -> Result<()>
where
    I: tokio::io::AsyncRead + Unpin + Send + 'static,
    O: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncWriteExt, copy};

    let (mut sr, mut sw) = sock.into_split();

    let up = tokio::spawn(async move {
        // Errors here are the ordinary way a session ends (the peer resets, we
        // are killed mid-write); the downstream copy is what decides the exit
        // status, so nothing is gained by surfacing them twice.
        let _ = copy(&mut input, &mut sw).await;
        let _ = sw.shutdown().await;
    });

    let r = copy(&mut sr, &mut output).await.context("peer → output");
    let _ = output.flush().await;
    // The uploader may still be parked on a read that will never complete
    // (an interactive stdin nobody is typing into). The session is over.
    up.abort();
    r?;
    Ok(())
}

pub(crate) fn mint_session_key() -> Result<ssh_key::PrivateKey> {
    use ssh_key::private::{Ed25519Keypair, PrivateKey};
    // Seeded from the OS CSPRNG and constructed from the bytes rather than an
    // RNG-generic API, for the same reason the agent's host-key mint does it
    // this way: no need to agree with anyone about `rand_core` generations.
    let seed: [u8; 32] = rand::random();
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment("roomler-session");
    Ok(key)
}

/// A directory only the current user can enter, removed on drop.
pub(crate) struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> Result<Self> {
        Self::named("roomler-ssh")
    }

    /// FR-90 P3-9-2b — one whose name starts `prefix-`, for `roomler
    /// connect`'s files too.
    pub(crate) fn named(prefix: &str) -> Result<Self> {
        // Name from the OS CSPRNG, not the pid or the clock: a predictable
        // name in a shared /tmp is how someone pre-creates the path.
        let nonce: u128 = rand::random();
        let dir = std::env::temp_dir().join(format!("{prefix}-{nonce:032x}"));
        std::fs::create_dir(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(dir))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        // Best effort: a leftover key in a 0700 dir is bad, but panicking in
        // a destructor while the user is reading their session output is
        // worse. The key is single-use and already expired by now anyway.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write owner-only. On Unix the mode is set BEFORE any bytes land —
/// `ssh` refuses a group/world-readable key, and more to the point a
/// window where the key exists at 0644 is a window.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_reports_an_unknown_name_instead_of_dialling_something() {
        // The failure this prevents: treating an unresolvable name as a
        // hostname and letting the OS resolver find SOMETHING — a LAN box, a
        // search-domain match, a wildcard DNS answer. A mesh name that is not
        // on the mesh must be an error, not a different destination.
        //
        // No daemon is running under test, so this exercises the same refusal
        // path a live-but-unknown name takes: it must fail, and never reach a
        // connect() to an OS-resolved host.
        let err = proxy("definitely-not-a-device-9f3a", 22)
            .await
            .expect_err("an unknown name must not resolve to anything");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("Name or service not known") && !msg.contains("nodename nor servname"),
            "the OS resolver must never see a mesh name: {msg}"
        );
    }

    #[tokio::test]
    async fn already_closed_input_still_delivers_the_peers_reply() {
        // The rc.447 bug, in one test. `scp`, `rsync` and `ssh host cmd` all
        // present an input that is EOF straight away; a proxy that treats
        // "input finished" as "session finished" tears the connection down
        // before the peer's banner arrives and the tool sees an empty stream.
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Speak first, like a real sshd, and only then close.
            s.write_all(b"SSH-2.0-RoomlerTest\r\n").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let input = std::io::Cursor::new(Vec::new()); // EOF immediately
        let mut out: Vec<u8> = Vec::new();
        pump(sock, input, &mut out).await.unwrap();

        assert_eq!(
            String::from_utf8_lossy(&out),
            "SSH-2.0-RoomlerTest\r\n",
            "input EOF must half-close, not abandon the peer's reply"
        );
    }

    #[tokio::test]
    async fn input_reaches_the_peer_and_eof_is_seen_as_eof() {
        // The other half: the peer must actually receive what we sent AND see
        // a clean FIN, or an `scp` upload would hang waiting for more.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            // Returns only on EOF — so this hanging means no FIN was sent.
            s.read_to_end(&mut got).await.unwrap();
            s.write_all(b"ack").await.unwrap();
            s.shutdown().await.unwrap();
            got
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let mut out: Vec<u8> = Vec::new();
        pump(sock, std::io::Cursor::new(b"hello".to_vec()), &mut out)
            .await
            .unwrap();

        assert_eq!(echo.await.unwrap(), b"hello", "the peer must receive input");
        assert_eq!(&out, b"ack", "and its answer must reach the output");
    }

    /// A loopback port nothing listens on: bound to learn a free number, then
    /// released, so a connect to it is REFUSED at once.
    ///
    /// ⚠️ Not a fixed "surely closed" port. These tests used `:9` (discard),
    /// and under WSL a connect to `127.0.0.1:9` is not refused — it hangs
    /// until the SYN-retry budget runs out, ~134 s per test, while a
    /// just-freed ephemeral port is refused in single-digit ms (measured).
    async fn refusing_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn proxy_takes_a_literal_address_without_asking_the_daemon() {
        // Nothing listens on the port, so this fails at CONNECT — which is
        // the point: it got past resolution without a daemon, proving an
        // address short-circuits the lookup.
        let port = refusing_port().await;
        let err = proxy("127.0.0.1", port)
            .await
            .expect_err("nothing listens on the freed port");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("connecting to 127.0.0.1:{port}")),
            "a literal address must go straight to connect, got: {msg}"
        );
    }

    #[tokio::test]
    async fn a_failed_connect_to_a_non_mesh_literal_names_the_hostname_trap() {
        // #1573: `Host zeus / HostName <public ip>` hands the ProxyCommand the
        // PUBLIC address, and the bare connect error named no host at all —
        // it read as a broken overlay for several minutes in the field.
        let err = proxy("127.0.0.1", refusing_port().await)
            .await
            .expect_err("nothing listens on the freed port");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("`HostName` line"),
            "a non-mesh literal must point at the HostName trap, got: {msg}"
        );
    }

    #[test]
    fn overlay_space_is_the_cgnat_slash_ten_and_the_derived_ula() {
        let yes = [
            "100.64.0.1",
            "100.65.4.2", // a carved tenant block
            "100.127.255.254",
            "fd72:6f6f:6d6c::6441:402",
        ];
        let no = [
            "100.63.255.255",
            "100.128.0.1",
            "203.0.113.7",
            "127.0.0.1",
            "192.168.1.10",
            "fd72:6f6f:6d6d::1",
            "::1",
        ];
        for a in yes {
            assert!(is_overlay_address(a.parse().unwrap()), "{a} is overlay");
        }
        for a in no {
            assert!(!is_overlay_address(a.parse().unwrap()), "{a} is not");
        }
    }

    #[test]
    fn a_session_key_is_ed25519_and_parses_as_a_client_would() {
        let key = mint_session_key().unwrap();
        let line = key.public_key().to_openssh().unwrap();
        assert!(line.starts_with("ssh-ed25519 "), "got {line}");
        let parsed = ssh_key::PublicKey::from_openssh(&line).unwrap();
        assert_eq!(parsed.key_data(), key.public_key().key_data());
    }

    #[test]
    fn every_session_key_is_distinct() {
        // The grant is bound to this key and single-use; reuse across
        // sessions would turn a captured public key into a replay target.
        let a = mint_session_key()
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let b = mint_session_key()
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_private_dir_is_owner_only_and_vanishes() {
        let path;
        {
            let d = PrivateDir::new().unwrap();
            path = d.path().to_path_buf();
            assert!(path.is_dir());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700, "temp dir must be owner-only");
            }
        }
        assert!(
            !path.exists(),
            "the key directory must not outlive the session"
        );
    }

    #[test]
    fn a_written_key_is_not_readable_by_anyone_else() {
        let d = PrivateDir::new().unwrap();
        let p = d.path().join("id");
        write_private(&p, b"secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "ssh refuses a loose key, and rightly");
        }
        // create_new: a pre-existing path is an error, never a silent
        // overwrite of something we did not create.
        assert!(write_private(&p, b"again").is_err());
    }
}
