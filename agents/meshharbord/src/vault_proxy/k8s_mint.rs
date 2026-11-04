// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6f-1 — a Kubernetes service account's token minted for one lease
//! by a dynamic secret's issuer, bound to a Secret made for the lease, so that
//! deleting the Secret ends the token (`docs/fr/FR-90-hive-agent-sessions.md`
//! §3e, "P3-6f, a Kubernetes `TokenRequest`, as designed"; `docs/vault.md`
//! §20). Since P3-6f-2 the lease client reaches it through `super::minter`,
//! by the bundle's provider, `kubernetes`.
//!
//! | Step | What happens |
//! |---|---|
//! | the issuer | the bundle's `namespace` and `service_account`, signed in to the API server at the bundle's one audience, an origin, by `admin_token` or by `admin_cert` and `admin_key`, over TLS verified against its `ca` or the system's roots ([`Issuer::from_bundle`]) |
//! | the sweep | first, where the issuer may list its namespace's Secrets, every one a mint made whose end has passed, deleted on its uid: what a daemon that died before revoking left |
//! | the mint | an empty Secret `roomler-<lease>`, labelled with its lease and annotated with its end; then a `TokenRequest` bound to it by name and uid, for the lease's TTL or 600 s, whichever is longer ([`mint`]) |
//! | the revocation | the Secret deleted on its uid ([`revoke`]): the API server refuses a token whose bound object is gone |
//!
//! ⚠️ `namespace` and `service_account` go into a request's path, so each is
//! held to the name Kubernetes allows it before anything is dialled.
//!
//! ⚠️ A Secret is never deleted unless its name is a minted one
//! ([`SECRET_PREFIX`] and a lease's id), and never but on the uid it was made
//! with: a revocation takes back what this module made, and nothing else.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue, USER_AGENT};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_rustls::rustls::RootCertStore;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

use super::bundle::Opened;
use super::tls;

/// What every minted Secret's name begins with.
pub(crate) const SECRET_PREFIX: &str = "roomler-";
/// The label every minted Secret carries, its lease's id: the sweep's mark.
const LEASE_LABEL: &str = "roomler.ai/lease";
/// The same, as a query names it.
const LEASE_SELECTOR: &str = "roomler.ai%2Flease";
/// The annotation every minted Secret carries: its lease's end, RFC 3339.
const UNTIL_ANNOTATION: &str = "roomler.ai/until";
/// The shortest token Kubernetes mints (`expirationSeconds` below it is
/// refused).
pub(crate) const MIN_EXPIRATION_SECS: u32 = 600;
/// How long one request to the API server may take, from the dial to the
/// last byte of its answer.
const DEADLINE: Duration = Duration::from_secs(10);
/// The most of an answer read: a token, a Secret, or a list of Secrets.
const MAX_ANSWER: usize = 4 << 20;

/// How the issuer signs in to the API server.
enum SignIn {
    /// `Authorization: Bearer`, a service account's token or an OIDC one.
    Bearer(Zeroizing<String>),
    /// A client certificate and its key (PEM), presented in the handshake of
    /// each connection, so the key lives in that connection's TLS alone.
    Certificate {
        cert: Zeroizing<String>,
        key: Zeroizing<String>,
    },
}

/// A dynamic secret's Kubernetes issuer, read from its lease's bundle.
pub(crate) struct Issuer {
    host: String,
    port: u16,
    /// The origin the bundle mints toward: the `server` a minted credential
    /// names.
    origin: String,
    roots: Arc<RootCertStore>,
    /// The cluster's CA (PEM), where the issuer names one: the `ca` a minted
    /// credential names.
    ca: Option<String>,
    sign_in: SignIn,
    namespace: String,
    service_account: String,
    /// The minted token's audiences; none, the API server's own.
    audiences: Vec<String>,
}

impl Issuer {
    /// The issuer in a lease's `bundle` (`super::bundle`). Err, in words that
    /// name no value, for a bundle that does not parse, an audience that is
    /// not an origin, a name Kubernetes would not take, or a credential that
    /// is missing or given twice.
    pub(crate) fn from_bundle(bundle: &[u8]) -> Result<Self, String> {
        let opened = Opened::open(bundle)?;
        let origin = opened.audience().to_string();
        let (host, port) = super::origin_of(&origin)?;
        let namespace = opened.required("namespace")?.clone();
        if !dns_label(&namespace) {
            return Err("the issuer's namespace is not a name Kubernetes gives a namespace".into());
        }
        let service_account = opened.required("service_account")?.clone();
        if !dns_subdomain(&service_account) {
            return Err(
                "the issuer's service_account is not a name Kubernetes gives an account".into(),
            );
        }
        let sign_in = match (
            opened.optional("admin_token"),
            opened.optional("admin_cert"),
            opened.optional("admin_key"),
        ) {
            (Some(token), None, None) => {
                if !token.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err("the issuer's admin_token is not a bearer token".into());
                }
                SignIn::Bearer(Zeroizing::new(token.clone()))
            }
            (None, Some(cert), Some(key)) => {
                // Read once here, so a bad pair is refused before anything is
                // dialled; each connection reads it again for its own TLS.
                tls::identity(cert, key)?;
                SignIn::Certificate {
                    cert: Zeroizing::new(cert.clone()),
                    key: Zeroizing::new(key.clone()),
                }
            }
            (None, None, None) => {
                return Err("the issuer has no admin_token, nor admin_cert and admin_key".into());
            }
            _ => {
                return Err(
                    "the issuer signs in by admin_token, or by admin_cert and admin_key: one of \
                     the two"
                        .into(),
                );
            }
        };
        let ca = opened.optional("ca").cloned();
        let roots = tls::roots(ca.as_deref())?;
        let audiences = opened.lines("audiences");
        if audiences
            .iter()
            .any(|a| a.len() > 256 || a.chars().any(char::is_control))
        {
            return Err("one of the issuer's audiences is not an audience".into());
        }
        Ok(Self {
            host,
            port,
            origin,
            roots,
            ca,
            sign_in,
            namespace,
            service_account,
            audiences,
        })
    }

    /// The API server's authority, as `Host` names it: an IPv6 address in
    /// brackets, and the port only where it is not 443.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn secrets_path(&self) -> String {
        format!("/api/v1/namespaces/{}/secrets", self.namespace)
    }
}

/// A token minted for a lease: what a session names, and the Secret it is
/// bound to, which its revocation deletes.
pub(crate) struct Minted {
    pub(crate) token: Zeroizing<String>,
    pub(crate) server: String,
    /// The cluster's CA (PEM), or empty where the system's roots verify it.
    pub(crate) ca: String,
    pub(crate) namespace: String,
    pub(crate) secret: String,
    pub(crate) uid: String,
}

impl Minted {
    /// One of its fields, by the name a session gives it; `None` for any
    /// other name.
    pub(crate) fn field(&self, name: &str) -> Option<Zeroizing<String>> {
        let value = match name {
            "token" => self.token.to_string(),
            "server" => self.server.clone(),
            "ca" => self.ca.clone(),
            "namespace" => self.namespace.clone(),
            _ => return None,
        };
        Some(Zeroizing::new(value))
    }
}

/// The Secret minted for a lease: [`SECRET_PREFIX`] and the lease's id, its
/// 24 lowercase hex characters, which no other name has.
pub(crate) fn secret_for(lease_id: &str) -> Result<String, String> {
    if lease_id.len() == 24
        && lease_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(format!("{SECRET_PREFIX}{lease_id}"))
    } else {
        Err("a lease's id is 24 lowercase hex characters".into())
    }
}

/// Whether `secret` is a name a mint made: Err for any other, which nothing
/// here ever deletes.
pub(crate) fn minted(secret: &str) -> Result<(), String> {
    let lease = secret
        .strip_prefix(SECRET_PREFIX)
        .ok_or("only a minted Secret is ever deleted")?;
    secret_for(lease).map(|_| ())
}

/// A name Kubernetes gives a namespace: an RFC 1123 label, lowercase.
fn dns_label(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// A name Kubernetes gives a service account: an RFC 1123 subdomain,
/// lowercase labels joined by dots.
fn dns_subdomain(name: &str) -> bool {
    name.len() <= 253 && name.split('.').all(dns_label)
}

/// Mint a token for `lease_id`, its lease's TTL `ttl_secs` and its end
/// `until_ms` (milliseconds of the server's clock): first the sweep, then the
/// lease's Secret, then the token bound to it. A token the API server refuses
/// takes the Secret back, and the call is refused in the API server's words.
pub(crate) async fn mint(
    issuer: &Issuer,
    lease_id: &str,
    ttl_secs: u32,
    until_ms: i64,
) -> Result<Minted, String> {
    let secret = secret_for(lease_id)?;
    let until = bson::DateTime::from_millis(until_ms)
        .try_to_rfc3339_string()
        .map_err(|_| "the lease's end is not a time Kubernetes takes".to_string())?;
    let swept = sweep(issuer).await;
    if swept > 0 {
        info!(
            swept,
            "vault: Kubernetes Secrets an earlier mint left, deleted"
        );
    }
    let body = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": secret,
            "labels": {LEASE_LABEL: lease_id},
            "annotations": {UNTIL_ANNOTATION: until},
        },
    });
    let (status, answer) = call(issuer, Method::POST, &issuer.secrets_path(), Some(&body)).await?;
    if !status.is_success() {
        return Err(refused("the lease's Secret", status, &answer));
    }
    let uid = uid_of(&answer)?;
    let mut spec = json!({
        "expirationSeconds": ttl_secs.max(MIN_EXPIRATION_SECS),
        "boundObjectRef": {"apiVersion": "v1", "kind": "Secret", "name": secret, "uid": uid},
    });
    if !issuer.audiences.is_empty() {
        spec["audiences"] = json!(issuer.audiences);
    }
    let request = json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": spec,
    });
    let path = format!(
        "/api/v1/namespaces/{}/serviceaccounts/{}/token",
        issuer.namespace, issuer.service_account
    );
    let token = match call(issuer, Method::POST, &path, Some(&request)).await {
        Ok((status, answer)) if status.is_success() => token_of(&answer),
        Ok((status, answer)) => Err(refused("the token", status, &answer)),
        Err(e) => Err(e),
    };
    match token {
        Ok(token) => Ok(Minted {
            token,
            server: issuer.origin.clone(),
            ca: issuer.ca.clone().unwrap_or_default(),
            namespace: issuer.namespace.clone(),
            secret,
            uid,
        }),
        Err(why) => {
            // Taken back: a Secret no token is bound to is litter.
            if let Err(e) = delete(issuer, &secret, &uid).await {
                warn!(%secret, %e, "vault: a refused mint's Secret was not taken back");
            }
            Err(why)
        }
    }
}

/// Take back the token bound to `secret`, made with `uid`: the Secret
/// deleted on that uid. One already gone, or replaced by another under the
/// same name, is a revocation done: the token went with the object it was
/// bound to.
pub(crate) async fn revoke(issuer: &Issuer, secret: &str, uid: &str) -> Result<(), String> {
    minted(secret)?;
    delete(issuer, secret, uid).await
}

/// `DELETE` the Secret `name`, on `uid` as a precondition.
async fn delete(issuer: &Issuer, name: &str, uid: &str) -> Result<(), String> {
    minted(name)?;
    let body = json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
    });
    let path = format!("{}/{name}", issuer.secrets_path());
    let (status, answer) = call(issuer, Method::DELETE, &path, Some(&body)).await?;
    match status {
        s if s.is_success() => Ok(()),
        StatusCode::NOT_FOUND => Ok(()),
        // Another object under the name: ours, with its token, is gone.
        StatusCode::CONFLICT => {
            debug!(%name, "vault: a minted Secret's name holds another object now — left alone");
            Ok(())
        }
        _ => Err(refused("the lease's Secret", status, &answer)),
    }
}

/// What a daemon that died before revoking left: every Secret a mint made
/// whose end has passed, deleted on its uid. Only where the issuer may list
/// its namespace's Secrets; where it may not, nothing. How many it deleted.
async fn sweep(issuer: &Issuer) -> usize {
    let path = format!("{}?labelSelector={LEASE_SELECTOR}", issuer.secrets_path());
    let answer = match call(issuer, Method::GET, &path, None).await {
        Ok((status, answer)) if status.is_success() => answer,
        Ok((status, _)) => {
            debug!(%status, "vault: the issuer may not list its Secrets — no sweep");
            return 0;
        }
        Err(e) => {
            debug!(%e, "vault: the sweep's list went unanswered");
            return 0;
        }
    };
    #[derive(Deserialize)]
    struct List {
        #[serde(default)]
        items: Vec<Item>,
    }
    #[derive(Deserialize)]
    struct Item {
        metadata: Meta,
    }
    #[derive(Deserialize)]
    struct Meta {
        name: String,
        uid: String,
        #[serde(default)]
        annotations: std::collections::BTreeMap<String, String>,
    }
    let Ok(list) = serde_json::from_slice::<List>(&answer) else {
        return 0;
    };
    let now = bson::DateTime::now();
    let mut deleted = 0;
    for Item { metadata: m } in list.items {
        let ended = m
            .annotations
            .get(UNTIL_ANNOTATION)
            .and_then(|t| bson::DateTime::parse_rfc3339_str(t).ok())
            .is_some_and(|until| until < now);
        if !ended || minted(&m.name).is_err() {
            continue;
        }
        match delete(issuer, &m.name, &m.uid).await {
            Ok(()) => deleted += 1,
            Err(e) => debug!(name = %m.name, %e, "vault: an ended minted Secret was not deleted"),
        }
    }
    deleted
}

/// The uid of the object an answer describes.
fn uid_of(answer: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Object {
        metadata: Meta,
    }
    #[derive(Deserialize)]
    struct Meta {
        uid: String,
    }
    serde_json::from_slice::<Object>(answer)
        .map(|o| o.metadata.uid)
        .ok()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "the API server answered the Secret with no uid".to_string())
}

/// The token a `TokenRequest`'s answer carries, moved straight into memory
/// that is zeroed when it drops.
fn token_of(answer: &[u8]) -> Result<Zeroizing<String>, String> {
    #[derive(Deserialize)]
    struct Answer {
        status: Status,
    }
    #[derive(Deserialize)]
    struct Status {
        token: String,
    }
    let token = serde_json::from_slice::<Answer>(answer)
        .map(|a| Zeroizing::new(a.status.token))
        .map_err(|_| "the API server answered the token request with no token".to_string())?;
    if token.is_empty() {
        return Err("the API server answered the token request with no token".into());
    }
    Ok(token)
}

/// A refusal, in the API server's words: the `message` of the `Status` it
/// answered with, where it sent one.
fn refused(what: &str, status: StatusCode, answer: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Refusal {
        message: String,
    }
    match serde_json::from_slice::<Refusal>(answer) {
        Ok(r) if !r.message.is_empty() => {
            format!(
                "{what}: the API server refused it ({status}): {}",
                r.message
            )
        }
        _ => format!("{what}: the API server refused it ({status})"),
    }
}

/// One request to the API server, on a connection of its own, signed in as
/// the issuer: the answer's status, and its body in memory that is zeroed
/// when it drops (a token's answer carries the token).
async fn call(
    issuer: &Issuer,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Result<(StatusCode, Zeroizing<Vec<u8>>), String> {
    let identity = match &issuer.sign_in {
        SignIn::Certificate { cert, key } => Some(tls::identity(cert, key)?),
        SignIn::Bearer(_) => None,
    };
    let connector = tls::connector_for(Arc::clone(&issuer.roots), identity)?;
    let name = tls::server_name(&issuer.host)?;
    let authority = issuer.authority();
    let exchange = async {
        let tcp = TcpStream::connect((issuer.host.as_str(), issuer.port))
            .await
            .map_err(|e| format!("{authority}: {e}"))?;
        let stream = connector
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS to {}: {e}", issuer.host))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("{authority}: {e}"))?;
        let task = AbortOnDrop(tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(%e, "vault: a Kubernetes issuer's connection ended with an error");
            }
        }));
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, authority.as_str())
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "meshharbord vault");
        if let SignIn::Bearer(token) = &issuer.sign_in {
            let value = Zeroizing::new(format!("Bearer {}", token.as_str()));
            let mut value = HeaderValue::from_str(&value)
                .map_err(|_| "the issuer's admin_token is not a bearer token".to_string())?;
            value.set_sensitive(true);
            req = req.header(AUTHORIZATION, value);
        }
        let payload = match body {
            Some(v) => {
                req = req.header(CONTENT_TYPE, "application/json");
                serde_json::to_vec(v).map_err(|e| e.to_string())?
            }
            None => Vec::new(),
        };
        let req = req
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| e.to_string())?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| format!("{authority}: {e}"))?;
        let status = resp.status();
        let mut answer = Zeroizing::new(Vec::new());
        let mut incoming = resp.into_body();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|e| format!("{authority}: {e}"))?;
            if let Some(data) = frame.data_ref() {
                append(&mut answer, data)?;
            }
        }
        drop(task);
        Ok((status, answer))
    };
    tokio::time::timeout(DEADLINE, exchange)
        .await
        .map_err(|_| format!("{authority} did not answer within {DEADLINE:?}"))?
}

/// `data` added to `answer`, which grows into a new buffer of its own and
/// zeroes the old one, so no copy of what it held is left behind unzeroed.
fn append(answer: &mut Zeroizing<Vec<u8>>, data: &[u8]) -> Result<(), String> {
    let needed = answer.len() + data.len();
    if needed > MAX_ANSWER {
        return Err("the API server's answer is longer than any this asks for".into());
    }
    if needed > answer.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(answer.capacity() * 2)));
        grown.extend_from_slice(answer);
        std::mem::swap(answer, &mut grown);
        grown.zeroize();
    }
    answer.extend_from_slice(data);
    Ok(())
}

/// A connection's task, ended with the request that opened it.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests;
