// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-7-3c — a session's own egress, its tools: `net_socks` and
//! `net_forward`.
//!
//! Each call asks the vault for a grant (`rc:vault.net`, P3-7-3a), and serves
//! it on a loopback listener of its own, at a port the system picks, admitted
//! to the session's account alone (P3-7-3b):
//! - `net_socks` is SOCKS5 with RFC 1929: the session's id and a capability
//!   made for this listener, which its answer's proxy URL carries;
//! - `net_forward` is a forward to the one destination the vault granted.
//!
//! The listener and every connection on it end at the grant's end, or when
//! the session's run ends here, whichever comes first ([`drop_run`]).
//!
//! ⚠️ The capability lands in the transcript. It is the session's own: no
//! other account is admitted to the listener, and it is gone with it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Instant;

use bson::oid::ObjectId;
use serde_json::{Value, json};
use tracing::{info, warn};
use tunnel_core::driver::Target;
use tunnel_core::socks5::Socks5Credential;

use super::toolbelt::{PeerId, VaultTools};
use crate::tunnel::client_mgr::TunnelClientHub;
use crate::vault::NetAsk;

/// The tools, by the names a session calls them.
pub(crate) const SOCKS: &str = "net_socks";
pub(crate) const FORWARD: &str = "net_forward";

/// How long a grant is asked for when the call names none. The vault holds
/// it to its own bounds (30 to 900 seconds).
pub(crate) const DEFAULT_TTL_SECS: u32 = 300;

/// The most listeners one run holds at once, counting the calls still asking
/// for one: each is a listener and a tunnel, so a call past it asks the vault
/// nothing.
pub(crate) const MAX_FLOWS: usize = 8;

/// A session's run, by its session and fence.
type RunKey = (ObjectId, u64);

/// One run's listeners, each a flow on its hub, and the calls still asking
/// for one.
#[derive(Default)]
struct RunFlows {
    /// Which life of the run's entry this is: [`drop_run`] removes the entry,
    /// and a later call makes a new one, which an older call's place is not
    /// in.
    life: u64,
    flows: Vec<(TunnelClientHub, String)>,
    asking: usize,
}

/// Every run's listeners: ended with the run ([`drop_run`]).
type Open = HashMap<RunKey, RunFlows>;

static OPEN: LazyLock<Mutex<Open>> = LazyLock::new(Mutex::default);

/// The next entry's life.
static LIVES: AtomicU64 = AtomicU64::new(1);

fn open_flows() -> MutexGuard<'static, Open> {
    OPEN.lock().unwrap_or_else(|e| e.into_inner())
}

/// A call's place among its run's listeners, held from before the vault is
/// asked, so the calls still asking count against [`MAX_FLOWS`] too. A call
/// that ends without a listener, refused or cancelled by the harness, gives
/// its place back as the place drops.
#[derive(Debug)]
struct Place {
    run: RunKey,
    life: u64,
}

impl Place {
    /// A place in `run`, or why not.
    fn hold(run: RunKey) -> Result<Self, String> {
        let mut open = open_flows();
        let r = open.entry(run).or_insert_with(|| RunFlows {
            life: LIVES.fetch_add(1, Ordering::Relaxed),
            ..RunFlows::default()
        });
        // A flow the hub no longer has ended already: at its grant's end, or
        // for good on a refusal.
        r.flows.retain(|(hub, id)| hub.has_flow(id));
        if r.flows.len() + r.asking >= MAX_FLOWS {
            return Err(format!(
                "this session holds {MAX_FLOWS} egress listeners already: end one first"
            ));
        }
        r.asking += 1;
        Ok(Self { run, life: r.life })
    }

    /// The call's listener, `flow` on `hub`, recorded in its place. False,
    /// and the flow ended at once, where the run ended here while the call
    /// asked for it.
    fn fill(self, hub: &TunnelClientHub, flow: &str) -> bool {
        let mut open = open_flows();
        let recorded = match open.get_mut(&self.run) {
            Some(r) if r.life == self.life => {
                r.flows.push((hub.clone(), flow.to_string()));
                true
            }
            _ => false,
        };
        drop(open);
        if !recorded {
            hub.kill_flow(flow);
        }
        recorded
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut open = open_flows();
        if let Some(r) = open.get_mut(&self.run)
            && r.life == self.life
        {
            r.asking = r.asking.saturating_sub(1);
        }
    }
}

/// What one call asks: its exit, and a forward's destination.
#[derive(Debug, PartialEq, Eq)]
struct Ask {
    exit: ObjectId,
    dst: Option<(String, u16)>,
    ttl_secs: u32,
}

/// Parse `name`'s arguments.
fn parse(name: &str, args: &Value) -> Result<Ask, String> {
    let exit = args
        .get("exit")
        .and_then(Value::as_str)
        .ok_or("exit is required: the id of the device the flows leave from")?;
    let exit = ObjectId::parse_str(exit.trim())
        .map_err(|_| format!("exit {exit:?} is not a device id"))?;
    let ttl_secs = match args.get("ttl_s") {
        None | Some(Value::Null) => DEFAULT_TTL_SECS,
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("ttl_s is a whole number of seconds")?,
    };
    let dst = match name {
        SOCKS => None,
        FORWARD => {
            let host = args
                .get("host")
                .and_then(Value::as_str)
                .filter(|h| !h.trim().is_empty())
                .ok_or("host is required: the one destination to forward to")?;
            let port = args
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or("port is required: 1 to 65535")?;
            Some((host.trim().to_string(), port))
        }
        other => return Err(format!("{other} is not a net tool")),
    };
    Ok(Ask {
        exit,
        dst,
        ttl_secs,
    })
}

/// A capability made for one listener: 32 random bytes, hex — the way the
/// sidecar mints its token.
fn capability() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// One call of `net_socks` or `net_forward` for the session's run: the
/// vault's grant served on a loopback listener for `peer`, the session's
/// account. Its answer, or why not.
pub(crate) async fn call(
    name: &str,
    vault: &dyn VaultTools,
    hub: &TunnelClientHub,
    session: ObjectId,
    fence: u64,
    peer: PeerId,
    args: &Value,
) -> Result<Value, String> {
    let ask = parse(name, args)?;
    // Held from before the vault is asked; given back if no listener comes
    // of it.
    let place = Place::hold((session, fence))?;
    // Refused before the vault is asked where this system cannot say who
    // connects to a loopback port.
    let admit = super::vault_connect::session_admit(peer)?;
    let grant = vault
        .net(NetAsk {
            session_id: session,
            fence,
            exit: ask.exit,
            dst: ask.dst,
            ttl_secs: ask.ttl_secs,
        })
        .await?;
    let (target, serves) = match &grant.dst {
        // The destination exactly as granted: the vault's one spelling.
        Some((host, port)) => (
            Target::Static {
                host: host.clone(),
                port: *port,
            },
            Serves::Forward(format!("{host}:{port}")),
        ),
        None => {
            let credential = Socks5Credential {
                username: session.to_hex(),
                password: capability(),
            };
            (
                Target::SessionSocks5(credential.clone()),
                Serves::Socks(credential),
            )
        }
    };
    let (flow, addr) = hub
        .create_session_flow(ask.exit, target, grant.tunnel_ref(), grant.until, admit)
        .await?;
    if !place.fill(hub, &flow) {
        warn!(%session, fence, %flow, "a session's run ended here while its egress was made: ended it");
        return Err("the session's run ended here while its listener was made".into());
    }
    let expires_in_secs = grant
        .until
        .saturating_duration_since(Instant::now())
        .as_secs();
    info!(%session, fence, %flow, %addr, grant = %grant.grant_id, tool = name, "a session's egress serves");
    Ok(match serves {
        Serves::Socks(c) => json!({
            "proxy": format!("socks5h://{}:{}@{addr}", c.username, c.password),
            "host": "127.0.0.1",
            "port": addr.port(),
            "expires_in_secs": expires_in_secs,
        }),
        Serves::Forward(destination) => json!({
            "address": addr.to_string(),
            "host": "127.0.0.1",
            "port": addr.port(),
            "destination": destination,
            "expires_in_secs": expires_in_secs,
        }),
    })
}

/// What a listener serves: SOCKS with its credential, or a forward to one
/// destination.
enum Serves {
    Socks(Socks5Credential),
    Forward(String),
}

/// The run's end here (its end, or a move): every flow its tools opened ends
/// with it, listener and connections. How many ended.
pub(crate) fn drop_run(session: ObjectId, fence: u64) -> usize {
    let flows = open_flows()
        .remove(&(session, fence))
        .map(|r| r.flows)
        .unwrap_or_default();
    let ended = flows.iter().filter(|(hub, id)| hub.kill_flow(id)).count();
    if ended > 0 {
        info!(%session, fence, ended, "a run's egress listeners ended with it");
    }
    ended
}

#[cfg(test)]
mod tests;
