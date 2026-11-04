// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5c-1 — the MongoDB proxy's session: one client connection on the
//! endpoint, and one upstream connection the proxy authenticates itself.
//!
//! | Step | What happens |
//! |---|---|
//! | the client's first message | read whole, at most 1 MiB: its handshake, `hello` or the legacy `isMaster`, as `OP_MSG` or `OP_QUERY` |
//! | the upstream | TCP, then TLS from its first byte, verified ([`super::tls`]) |
//! | its authentication | SCRAM-SHA-256 by `saslStart` and `saslContinue` in the secret's auth database, the server's signature checked before a byte of the client's is sent. MongoDB's SCRAM has no channel binding |
//! | then | the client's first message, then every byte both ways |
//!
//! ⚠️ The proxy sends no `hello` of its own. A server takes client metadata
//! only in the first `hello` a connection sees, and refuses it in any later
//! one (`ClientMetadataCannotBeMutated`), so the client's own handshake, sent
//! after the authentication, must be the connection's first.
//!
//! ⚠️ The client never authenticates: the endpoint is its credential. A
//! refusal answers the client's first message with an error document, as a
//! server answers it, then hangs up.

use std::time::Duration;

use bson::spec::BinarySubtype;
use bson::{Binary, Bson, Document, doc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use super::scram::{Binding, ScramClient};
use super::tls;

/// Where, and as whom, the proxy authenticates.
pub(crate) struct Upstream {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: Zeroizing<String>,
    /// The database the user is defined in (`authSource`).
    pub(crate) auth_source: String,
    pub(crate) tls: tokio_rustls::TlsConnector,
}

pub(super) const OP_REPLY: i32 = 1;
pub(super) const OP_QUERY: i32 = 2004;
pub(super) const OP_MSG: i32 = 2013;
/// The longest first message read before the session starts: a handshake is
/// a few hundred bytes.
const MAX_FIRST: usize = 1 << 20;
/// The longest reply read while the proxy authenticates.
const MAX_REPLY: usize = 1 << 20;
/// How long the client has to send its first message, and the session to
/// start after it.
pub(crate) const START_DEADLINE: Duration = Duration::from_secs(30);
/// How long the upstream may take to accept a connection.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// The code a refusal carries, as the server's own for a failed sign-in.
const AUTHENTICATION_FAILED: i32 = 18;

/// One wire message, whole.
pub(super) struct Message {
    pub(super) request_id: i32,
    pub(super) response_to: i32,
    pub(super) op_code: i32,
    /// The whole message, its header included.
    pub(super) bytes: Vec<u8>,
}

impl Message {
    /// What follows the header.
    pub(super) fn body(&self) -> &[u8] {
        &self.bytes[16..]
    }
}

/// Serve one client: read its first message, start its session upstream,
/// then relay both ways until either side closes. An `Err` says why no
/// session started (the client was told too, where it could be).
pub(crate) async fn serve<C>(mut client: C, up: &Upstream) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let first =
        match tokio::time::timeout(START_DEADLINE, read_message(&mut client, MAX_FIRST)).await {
            Ok(Ok(first)) => first,
            Ok(Err(why)) => return Err(format!("the client: {why}")),
            Err(_) => return Err(format!("no first message within {START_DEADLINE:?}")),
        };
    let started = tokio::time::timeout(START_DEADLINE, start(up))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "the session did not start within {START_DEADLINE:?}"
            ))
        });
    let mut upstream = match started {
        Ok(upstream) => upstream,
        Err(why) => {
            if let Some(answer) = refusal(&first, &why) {
                let _ = client.write_all(&answer).await;
            }
            return Err(why);
        }
    };
    upstream
        .write_all(&first.bytes)
        .await
        .map_err(|e| format!("the upstream: {e}"))?;
    // A reset at the end is how many clients close: the session ran.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// The upstream, connected and authenticated.
async fn start(up: &Upstream) -> Result<TlsStream<TcpStream>, String> {
    let mut upstream = connect(up).await?;
    authenticate(&mut upstream, up).await?;
    Ok(upstream)
}

/// TCP to the upstream, then TLS from its first byte, verified.
async fn connect(up: &Upstream) -> Result<TlsStream<TcpStream>, String> {
    let name = tls::server_name(&up.host)?;
    let tcp = tokio::time::timeout(
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
    up.tls
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS to {}: {e}", up.host))
}

/// SCRAM-SHA-256 over `saslStart` and `saslContinue`: done only once the
/// server's signature checks.
async fn authenticate<S>(s: &mut S, up: &Upstream) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut scram = ScramClient::bound(&up.user, &up.password, Binding::No)?;
    let binary = |bytes: Vec<u8>| Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    };
    let reply = command(
        s,
        1,
        doc! {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-256",
            "payload": binary(scram.client_first().into_bytes()),
            "autoAuthorize": 1,
            "options": { "skipEmptyExchange": true },
            "$db": &up.auth_source,
        },
    )
    .await?;
    let conversation = reply
        .get("conversationId")
        .cloned()
        .ok_or("the upstream's saslStart named no conversation")?;
    let fin = scram.client_final(&payload(&reply)?)?;
    let reply = command(
        s,
        2,
        doc! {
            "saslContinue": 1,
            "conversationId": conversation.clone(),
            "payload": binary(fin.into_bytes()),
            "$db": &up.auth_source,
        },
    )
    .await?;
    scram.verify_server_final(&payload(&reply)?)?;
    // A server that does not skip the empty exchange (before 4.4) asks for
    // one more round, with nothing in it.
    if !done(&reply) {
        let reply = command(
            s,
            3,
            doc! {
                "saslContinue": 1,
                "conversationId": conversation,
                "payload": binary(Vec::new()),
                "$db": &up.auth_source,
            },
        )
        .await?;
        if !done(&reply) {
            return Err("the upstream's SCRAM did not end".into());
        }
    }
    Ok(())
}

/// One command of the proxy's own, and its answer: Err for a refusal, in the
/// server's words.
async fn command<S>(s: &mut S, id: i32, body: Document) -> Result<Document, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(&op_msg(id, 0, &body))
        .await
        .map_err(|e| format!("the upstream: {e}"))?;
    let reply = read_message(s, MAX_REPLY)
        .await
        .map_err(|e| format!("the upstream: {e}"))?;
    if reply.op_code != OP_MSG || reply.response_to != id {
        return Err(format!(
            "the upstream answered with op code {}, to request {}",
            reply.op_code, reply.response_to
        ));
    }
    let doc = op_msg_document(reply.body())?;
    if ok(&doc) {
        Ok(doc)
    } else {
        Err(format!(
            "the upstream refused: {}",
            doc.get_str("errmsg").unwrap_or("no reason given")
        ))
    }
}

/// A SCRAM message a reply carries, as text.
fn payload(reply: &Document) -> Result<String, String> {
    match reply.get("payload") {
        Some(Bson::Binary(b)) => String::from_utf8(b.bytes.clone())
            .map_err(|_| "the upstream's SCRAM is not text".into()),
        _ => Err("the upstream's SCRAM reply carries no payload".into()),
    }
}

/// Whether a reply says it succeeded: `ok` of 1, in whichever number type.
fn ok(doc: &Document) -> bool {
    match doc.get("ok") {
        Some(Bson::Double(v)) => *v == 1.0,
        Some(Bson::Int32(v)) => *v == 1,
        Some(Bson::Int64(v)) => *v == 1,
        _ => false,
    }
}

fn done(doc: &Document) -> bool {
    matches!(doc.get("done"), Some(Bson::Boolean(true)))
}

/// One message off `r`, whole: its 16-byte header, then the rest its length
/// names, at most `max` bytes in all.
pub(super) async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Message, String> {
    let mut head = [0u8; 16];
    r.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    let field =
        |at: usize| i32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    let len = usize::try_from(field(0)).unwrap_or(0);
    if !(16..=max).contains(&len) {
        return Err(format!("a message of {} bytes", field(0)));
    }
    let mut bytes = head.to_vec();
    bytes.resize(len, 0);
    r.read_exact(&mut bytes[16..])
        .await
        .map_err(|e| e.to_string())?;
    Ok(Message {
        request_id: field(4),
        response_to: field(8),
        op_code: field(12),
        bytes,
    })
}

/// An `OP_MSG` carrying `body` as its one section.
pub(super) fn op_msg(request_id: i32, response_to: i32, body: &Document) -> Vec<u8> {
    let mut doc = Vec::new();
    body.to_writer(&mut doc)
        .expect("a document writes into memory");
    let mut out = header(request_id, response_to, OP_MSG, 4 + 1 + doc.len());
    out.extend(0u32.to_le_bytes());
    out.push(0);
    out.extend(doc);
    out
}

/// An `OP_REPLY` carrying `doc`: how a server answers an `OP_QUERY`.
pub(super) fn op_reply(response_to: i32, doc: &Document) -> Vec<u8> {
    let mut bytes = Vec::new();
    doc.to_writer(&mut bytes)
        .expect("a document writes into memory");
    let mut out = header(0, response_to, OP_REPLY, 4 + 8 + 4 + 4 + bytes.len());
    out.extend(0i32.to_le_bytes());
    out.extend(0i64.to_le_bytes());
    out.extend(0i32.to_le_bytes());
    out.extend(1i32.to_le_bytes());
    out.extend(bytes);
    out
}

/// A message header for a body of `body_len` bytes.
fn header(request_id: i32, response_to: i32, op_code: i32, body_len: usize) -> Vec<u8> {
    let len = i32::try_from(16 + body_len).expect("a message the proxy makes is small");
    let mut out = Vec::with_capacity(16 + body_len);
    out.extend(len.to_le_bytes());
    out.extend(request_id.to_le_bytes());
    out.extend(response_to.to_le_bytes());
    out.extend(op_code.to_le_bytes());
    out
}

/// The body document of an `OP_MSG`: its first section of kind 0, past its
/// flags (and before a checksum, where it carries one).
pub(super) fn op_msg_document(body: &[u8]) -> Result<Document, String> {
    let bad = || "an OP_MSG that does not read".to_string();
    let flags = u32::from_le_bytes(
        body.get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    );
    let mut rest = &body[4..];
    if flags & 1 != 0 {
        rest = rest.get(..rest.len().saturating_sub(4)).ok_or_else(bad)?;
    }
    while let Some((&kind, tail)) = rest.split_first() {
        match kind {
            0 => return Document::from_reader(&mut &tail[..]).map_err(|_| bad()),
            1 => {
                let size = i32::from_le_bytes(
                    tail.get(..4)
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?,
                );
                let size = usize::try_from(size).map_err(|_| bad())?;
                rest = tail.get(size..).ok_or_else(bad)?;
            }
            _ => return Err(bad()),
        }
    }
    Err(bad())
}

/// P3-5c-2 — answer a client the endpoint does not serve: its first
/// message, read as [`serve`] reads it, is answered with `why` as a refusal
/// answers it. A client that sends nothing readable is told nothing.
pub(crate) async fn refuse<C>(client: &mut C, why: &str) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(first) = read_message(client, MAX_FIRST).await else {
        return Ok(());
    };
    match refusal(&first, why) {
        Some(answer) => client.write_all(&answer).await,
        None => Ok(()),
    }
}

/// The answer to the client's first message that tells it why no session
/// started: as a server answers that kind of message, or nothing for a kind
/// a handshake never is.
fn refusal(first: &Message, why: &str) -> Option<Vec<u8>> {
    let error = doc! {
        "ok": 0.0,
        "errmsg": why,
        "code": AUTHENTICATION_FAILED,
        "codeName": "AuthenticationFailed",
    };
    match first.op_code {
        OP_MSG => Some(op_msg(0, first.request_id, &error)),
        OP_QUERY => Some(op_reply(first.request_id, &error)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
