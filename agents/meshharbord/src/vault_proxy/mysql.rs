// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6d-1 — MySQL's client protocol, as a dynamic secret's issuer
//! speaks it to mint (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-6d,
//! MySQL, SQL Server and Redis users, as designed").
//!
//! | Step | What holds |
//! |---|---|
//! | the dial | TCP to the secret's one audience within 10 s, and the server's greeting (protocol 10), which must offer TLS |
//! | TLS | an `SSLRequest`, then TLS verified as `proxy`'s is (the issuer's `ca`, or the system's roots), before a byte of the sign-in |
//! | the sign-in | `caching_sha2_password`: its scramble, then, from a server that has not cached the account, the password itself inside the verified TLS. A switch to `sha256_password` (an account under it, or one that is not there, which MySQL answers so as not to say which) takes the password itself inside that TLS too. Any other plugin, `mysql_native_password` included, is refused |
//! | a query | `COM_QUERY`; text rows, a NULL as `None`; the server's error in its own words; each packet at most 1 MiB, each answer at most 10,000 rows |
//!
//! ⚠️ The client never offers `CLIENT_LOCAL_FILES`. A server that asks for a
//! local file anyway is refused, and is sent no byte of one.

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::pg::Upstream;
use super::tls;

const CLIENT_LONG_PASSWORD: u32 = 0x1;
const CLIENT_LONG_FLAG: u32 = 0x4;
const CLIENT_CONNECT_WITH_DB: u32 = 0x8;
pub(super) const CLIENT_LOCAL_FILES: u32 = 0x80;
pub(super) const CLIENT_PROTOCOL_41: u32 = 0x200;
pub(super) const CLIENT_SSL: u32 = 0x800;
const CLIENT_TRANSACTIONS: u32 = 0x2000;
pub(super) const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
pub(super) const CLIENT_PLUGIN_AUTH: u32 = 0x8_0000;
pub(super) const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x20_0000;

/// What this client offers. Never `CLIENT_LOCAL_FILES`, never multiple
/// statements in one query.
pub(super) const CAPS: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_SSL
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

// The client never offers a local file, checked as it builds.
const _: () = assert!(CAPS & CLIENT_LOCAL_FILES == 0);

/// What a server must offer for the client to go on.
const NEEDS: u32 = CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;

/// `utf8mb4_0900_ai_ci`.
const UTF8MB4: u8 = 255;
/// The plugin the client signs in by, and the one it follows a switch to.
pub(super) const CACHING_SHA2: &str = "caching_sha2_password";
pub(super) const SHA256: &str = "sha256_password";
/// The longest packet the client says it takes.
const MAX_PACKET: u32 = 16 * 1024 * 1024;
/// The longest packet before the session starts.
const MAX_AUTH_PACKET: usize = 64 * 1024;
/// The longest packet of an answer, and the most rows one holds.
const MAX_RESULT_PACKET: usize = 1024 * 1024;
const MAX_ROWS: usize = 10_000;
/// How long the dial may take, and the whole sign-in.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const START_DEADLINE: Duration = Duration::from_secs(30);

/// A signed-in session, over verified TLS.
pub(crate) struct Session {
    s: TlsStream<TcpStream>,
}

/// One packet: its sequence number and its payload, at most `max` bytes. A
/// payload that would continue into the next packet (16 MiB) is refused.
pub(super) async fn read_packet<S: AsyncRead + Unpin>(
    s: &mut S,
    max: usize,
) -> Result<(u8, Vec<u8>), String> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(|e| format!("the upstream: {e}"))?;
    let len = usize::from(head[0]) | usize::from(head[1]) << 8 | usize::from(head[2]) << 16;
    if len > max {
        return Err(format!(
            "the upstream sent a packet of {len} bytes, past the {max} allowed"
        ));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)
        .await
        .map_err(|e| format!("the upstream: {e}"))?;
    Ok((head[3], body))
}

/// Write one packet with sequence number `seq`.
pub(super) async fn write_packet<S: AsyncWrite + Unpin>(
    s: &mut S,
    seq: u8,
    body: &[u8],
) -> Result<(), String> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|n| *n < 0xFF_FFFF)
        .ok_or("a packet too long to send")?;
    let mut p = Vec::with_capacity(4 + body.len());
    p.extend(&len.to_le_bytes()[..3]);
    p.push(seq);
    p.extend(body);
    s.write_all(&p)
        .await
        .map_err(|e| format!("the upstream: {e}"))
}

/// A length-encoded integer at the start of `b`: its value, and how many
/// bytes it took. `None` for the NULL marker (`0xFB`) or a short buffer.
pub(super) fn lenenc(b: &[u8]) -> Option<(u64, usize)> {
    let le = |n: usize| -> Option<u64> {
        let bytes = b.get(1..1 + n)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0u64, |v, x| (v << 8) | u64::from(*x)),
        )
    };
    match *b.first()? {
        x @ 0..=0xFA => Some((u64::from(x), 1)),
        0xFC => Some((le(2)?, 3)),
        0xFD => Some((le(3)?, 4)),
        0xFE => Some((le(8)?, 9)),
        _ => None,
    }
}

/// An `ERR` packet's message: `<code> (<state>): <message>`.
pub(super) fn error_message(p: &[u8]) -> String {
    let code = p
        .get(1..3)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .unwrap_or_default();
    let (state, text) = match p.get(3) {
        Some(b'#') if p.len() >= 9 => (String::from_utf8_lossy(&p[4..9]).into_owned(), &p[9..]),
        _ => (String::new(), p.get(3..).unwrap_or_default()),
    };
    let text = String::from_utf8_lossy(text);
    if state.is_empty() {
        format!("{code}: {text}")
    } else {
        format!("{code} ({state}): {text}")
    }
}

/// `OK`, as a packet's first byte; `ERR`; and `EOF`, which a packet shorter
/// than 9 bytes beginning `0xFE` is.
fn is_eof(p: &[u8]) -> bool {
    p.first() == Some(&0xFE) && p.len() < 9
}

/// The server's greeting, as far as the sign-in needs it. Its plugin name is
/// not: an account under another plugin is a switch, which is refused.
struct Greeting {
    caps: u32,
    nonce: Vec<u8>,
}

fn parse_greeting(p: &[u8]) -> Result<Greeting, String> {
    if p.first() == Some(&0xFF) {
        return Err(format!("the upstream refused: {}", error_message(p)));
    }
    let bad = || "the upstream's greeting does not parse as MySQL's".to_string();
    if p.first() != Some(&10) {
        return Err(bad());
    }
    let version_end = p[1..].iter().position(|b| *b == 0).ok_or_else(bad)? + 1;
    let mut at = version_end + 1 + 4;
    let part1 = p.get(at..at + 8).ok_or_else(bad)?.to_vec();
    at += 8 + 1;
    let lo = p.get(at..at + 2).ok_or_else(bad)?;
    let mut caps = u32::from(u16::from_le_bytes([lo[0], lo[1]]));
    at += 2;
    // Character set, status: not read.
    at += 1 + 2;
    let hi = p.get(at..at + 2).ok_or_else(bad)?;
    caps |= u32::from(u16::from_le_bytes([hi[0], hi[1]])) << 16;
    at += 2;
    let data_len = usize::from(*p.get(at).ok_or_else(bad)?);
    at += 1 + 10;
    // The scramble's second part: the rest of `data_len`, at least 13 bytes
    // (its own NUL among them).
    let part2_len = data_len.saturating_sub(8).max(13);
    let part2 = p.get(at..at + part2_len).ok_or_else(bad)?;
    let mut nonce = part1;
    nonce.extend(part2.iter().take_while(|b| **b != 0));
    Ok(Greeting { caps, nonce })
}

/// `caching_sha2_password`'s scramble: SHA-256(password) XOR
/// SHA-256(SHA-256(SHA-256(password)) ‖ nonce).
pub(super) fn scramble(password: &[u8], nonce: &[u8]) -> [u8; 32] {
    let stage1 = Sha256::digest(password);
    let stage2 = Sha256::digest(stage1);
    let mix = Sha256::new()
        .chain_update(stage2)
        .chain_update(nonce)
        .finalize();
    let mut out = [0u8; 32];
    for (o, (a, b)) in out.iter_mut().zip(stage1.iter().zip(mix.iter())) {
        *o = a ^ b;
    }
    out
}

/// Dial `up`, verify its TLS, and sign in as its user to `database`. Every
/// refusal in words, never the password's.
pub(crate) async fn sign_in(up: &Upstream, database: &str) -> Result<Session, String> {
    if up.user.is_empty() || up.user.contains('\0') || database.contains('\0') {
        return Err("the issuer's user or database is not a name MySQL takes".into());
    }
    let started = tokio::time::timeout(START_DEADLINE, async {
        let name = tls::server_name(&up.host)?;
        let mut tcp = tokio::time::timeout(
            CONNECT_DEADLINE,
            TcpStream::connect((up.host.as_str(), up.port)),
        )
        .await
        .map_err(|_| {
            format!(
                "{}:{} did not answer within {CONNECT_DEADLINE:?}",
                up.host, up.port
            )
        })?
        .map_err(|e| format!("{}:{}: {e}", up.host, up.port))?;
        let (seq, greeting) = read_packet(&mut tcp, MAX_AUTH_PACKET).await?;
        let g = parse_greeting(&greeting)?;
        if g.caps & CLIENT_SSL == 0 {
            return Err(
                "the upstream does not offer TLS, and the minter signs in only over TLS".into(),
            );
        }
        if g.caps & NEEDS != NEEDS {
            return Err("the upstream does not speak MySQL's 4.1 protocol".into());
        }
        let caps = (CAPS & g.caps) | CLIENT_SSL;
        let mut ssl = Vec::with_capacity(32);
        ssl.extend(caps.to_le_bytes());
        ssl.extend(MAX_PACKET.to_le_bytes());
        ssl.push(UTF8MB4);
        ssl.extend([0u8; 23]);
        write_packet(&mut tcp, seq.wrapping_add(1), &ssl).await?;
        let mut s = up
            .tls
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS to {}: {e}", up.host))?;
        // The sign-in, from its first byte inside the TLS.
        let mut nonce = g.nonce;
        let first = scramble(up.password.as_bytes(), &nonce);
        let mut hello = ssl.clone();
        hello.extend(up.user.as_bytes());
        hello.push(0);
        hello.push(32);
        hello.extend(first);
        hello.extend(database.as_bytes());
        hello.push(0);
        hello.extend(CACHING_SHA2.as_bytes());
        hello.push(0);
        // A server whose account uses another plugin answers with a switch
        // to it, which is refused below.
        let mut seq = seq.wrapping_add(2);
        write_packet(&mut s, seq, &hello).await?;
        loop {
            let (got, p) = read_packet(&mut s, MAX_AUTH_PACKET).await?;
            seq = got.wrapping_add(1);
            match p.first() {
                Some(0x00) => break,
                Some(0xFF) => {
                    return Err(format!("the upstream refused: {}", error_message(&p)));
                }
                // More data: 3, signed in from the server's cache; 4, it asks
                // for the password itself, which goes only inside this TLS.
                Some(0x01) => match p.get(1) {
                    Some(3) => {}
                    Some(4) => {
                        let mut plain = zeroize::Zeroizing::new(up.password.as_bytes().to_vec());
                        plain.push(0);
                        write_packet(&mut s, seq, &plain).await?;
                    }
                    _ => return Err("the upstream's sign-in does not parse".into()),
                },
                // A switch: to `caching_sha2_password` with a fresh nonce; or
                // to `sha256_password`, which an account under it, and one
                // that is not there at all, is answered with, and which takes
                // the password itself, inside this verified TLS as the full
                // sign-in above does. Any other is refused.
                Some(0xFE) => {
                    let rest = &p[1..];
                    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
                    let plugin = String::from_utf8_lossy(&rest[..end]);
                    if plugin == SHA256 {
                        let mut plain = zeroize::Zeroizing::new(up.password.as_bytes().to_vec());
                        plain.push(0);
                        write_packet(&mut s, seq, &plain).await?;
                        continue;
                    }
                    if plugin != CACHING_SHA2 {
                        return Err(format!(
                            "the upstream asks for the {plugin} sign-in, and this client signs in \
                             by {CACHING_SHA2} or {SHA256} alone"
                        ));
                    }
                    nonce = rest
                        .get(end + 1..)
                        .unwrap_or_default()
                        .iter()
                        .take_while(|b| **b != 0)
                        .copied()
                        .collect();
                    write_packet(&mut s, seq, &scramble(up.password.as_bytes(), &nonce)).await?;
                }
                _ => return Err("the upstream's sign-in does not parse".into()),
            }
        }
        Ok(Session { s })
    })
    .await;
    started.unwrap_or_else(|_| {
        Err(format!(
            "the issuer's session did not start within {START_DEADLINE:?}"
        ))
    })
}

/// One query (`COM_QUERY`): each row's columns as text (`None` for a
/// NULL), or the server's error in its own words.
pub(crate) async fn query(
    session: &mut Session,
    sql: &str,
) -> Result<Vec<Vec<Option<String>>>, String> {
    let s = &mut session.s;
    let mut q = Vec::with_capacity(1 + sql.len());
    q.push(0x03);
    q.extend(sql.as_bytes());
    write_packet(s, 0, &q).await?;
    let (_, first) = read_packet(s, MAX_RESULT_PACKET).await?;
    match first.first() {
        Some(0x00) => return Ok(Vec::new()),
        Some(0xFF) => return Err(error_message(&first)),
        Some(0xFB) => {
            return Err(
                "the upstream asked for a local file, which this client never sends".into(),
            );
        }
        _ => {}
    }
    let (columns, _) = lenenc(&first).ok_or("the upstream's answer does not parse")?;
    let columns = usize::try_from(columns)
        .ok()
        .filter(|n| *n > 0 && *n <= 4096)
        .ok_or("the upstream's answer does not parse")?;
    for _ in 0..columns {
        read_packet(s, MAX_RESULT_PACKET).await?;
    }
    let (_, eof) = read_packet(s, MAX_RESULT_PACKET).await?;
    if !is_eof(&eof) {
        return Err("the upstream's answer does not parse".into());
    }
    let mut rows = Vec::new();
    loop {
        let (_, p) = read_packet(s, MAX_RESULT_PACKET).await?;
        if is_eof(&p) {
            return Ok(rows);
        }
        if p.first() == Some(&0xFF) {
            return Err(error_message(&p));
        }
        if rows.len() == MAX_ROWS {
            return Err(format!("the upstream answered more than {MAX_ROWS} rows"));
        }
        rows.push(row(&p, columns)?);
    }
}

/// A text row: each column a length-encoded string, or `0xFB` for NULL.
fn row(p: &[u8], columns: usize) -> Result<Vec<Option<String>>, String> {
    let bad = || "the upstream sent a row that does not parse".to_string();
    let mut at = 0;
    let mut out = Vec::with_capacity(columns);
    for _ in 0..columns {
        if p.get(at) == Some(&0xFB) {
            out.push(None);
            at += 1;
            continue;
        }
        let (len, took) = lenenc(p.get(at..).ok_or_else(bad)?).ok_or_else(bad)?;
        let len = usize::try_from(len).map_err(|_| bad())?;
        at += took;
        let text = p.get(at..at + len).ok_or_else(bad)?;
        out.push(Some(String::from_utf8_lossy(text).into_owned()));
        at += len;
    }
    Ok(out)
}

/// End the session: `COM_QUIT`, then TLS's close.
pub(crate) async fn quit(mut session: Session) {
    let _ = write_packet(&mut session.s, 0, &[0x01]).await;
    let _ = session.s.shutdown().await;
}

#[cfg(test)]
mod tests;
