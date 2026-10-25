// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #20 (v039 §6), slice 1: the managed forward as a declared,
//! validated INTENT, and its dry-run plan. Nothing here touches a node: a
//! stored forward is `desired`, never `applied` or `verified`, until the
//! apply slice exists.
//!
//! The planner refuses before any effect, each refusal with its reason:
//!
//! - **Explicit scope.** An ingress binds one address; `0.0.0.0` / `::`
//!   needs `public_listener` and sources narrower than `/0`.
//! - **Collisions.** Against the ingress node's REPORTED listeners
//!   (`net_inventory`; a stale or absent inventory fails closed) and every
//!   other live managed forward on that node, port and protocol.
//! - **Loops.** A destination equal to the ingress.
//! - **Hard regional isolation.** Ingress and destination must share one
//!   known zone (`business_isolation`); forwarded traffic keeps its origin's
//!   restriction, so a server hop cannot launder it. An unenrolled
//!   destination has no verified attachment and fails under `enforce`.
//! - **Management.** The userspace backend only listens; it never alters a
//!   node's outbound control path to `www.itachi.fans`. Recorded as a check.
//! - **Revisions.** An update names the revision it read; a stale one is
//!   refused (the route returns 409).

use std::net::IpAddr;

use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_remote_control::models::RpcCap;
use roomler_ai_remote_control::net_inventory::{L4, truncate_str};
use roomler_ai_remote_control::signaling::{
    ManagedForwardAssignment, ManagedForwardStatusWire, ServerMsg,
};
use serde::{Deserialize, Serialize};

use crate::NetworkState;
use crate::business_isolation::{self, Mode};

pub const COLLECTION: &str = "managed_forwards";
pub const AUDIT_COLLECTION: &str = "managed_forward_audit";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NatMode {
    /// The destination sees the ingress node as the source.
    Masquerade,
    /// The destination sees the original client address (needs a return
    /// path through the ingress; not supported by the userspace backend).
    PreserveSource,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Desired {
    Enabled,
    Disabled,
}

/// What an administrator asks for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ForwardSpec {
    pub name: String,
    pub ingress_agent_id: String,
    pub bind_addr: String,
    pub port: u16,
    pub proto: L4,
    /// Who may connect, as CIDRs. Never empty.
    pub sources: Vec<String>,
    /// An enrolled destination node, or `None` for a raw address.
    #[serde(default)]
    pub dest_agent_id: Option<String>,
    pub dest_addr: String,
    pub dest_port: u16,
    pub nat: NatMode,
    pub desired: Desired,
    /// Required to bind a wildcard address.
    #[serde(default)]
    pub public_listener: bool,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ManagedForward {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub tenant_id: ObjectId,
    pub revision: u64,
    pub spec: ForwardSpec,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    #[serde(default)]
    pub deleted_at: Option<DateTime>,
    /// The applied layer, written only from the ingress agent's own ack.
    #[serde(default)]
    pub applied: Option<Applied>,
}

/// What the ingress agent reported for one revision.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Applied {
    pub revision: u64,
    pub listening: bool,
    #[serde(default)]
    pub error: Option<String>,
    pub at: DateTime,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    /// Could not be established; fails the plan like `Fail`.
    Unknown,
    /// Would fail under `enforce`; the setting is `warn`.
    Warn,
}

#[derive(Serialize, Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Plan {
    /// Every check passed (a `warn` passes).
    pub ok: bool,
    pub checks: Vec<Check>,
    /// The backend this plan targets.
    pub backend: &'static str,
}

fn check(checks: &mut Vec<Check>, name: &'static str, verdict: Verdict, detail: impl Into<String>) {
    checks.push(Check {
        name,
        verdict,
        detail: detail.into(),
    });
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = s.split_once('/').unwrap_or((s, ""));
    let ip: IpAddr = ip.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = if len.is_empty() {
        max
    } else {
        len.trim().parse().ok().filter(|l| *l <= max)?
    };
    Some((ip, len))
}

/// The input-only checks (no state needed).
pub fn check_input(spec: &ForwardSpec, checks: &mut Vec<Check>) {
    let name_ok = !spec.name.trim().is_empty() && spec.name.len() <= 80;
    check(
        checks,
        "name",
        if name_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        "1-80 characters",
    );
    let ports_ok = spec.port != 0 && spec.dest_port != 0;
    check(
        checks,
        "ports",
        if ports_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        "listen and destination ports are 1-65535",
    );
    let bind: Option<IpAddr> = spec.bind_addr.trim().parse().ok();
    let sources: Vec<_> = spec.sources.iter().map(|s| parse_cidr(s)).collect();
    let sources_ok = !sources.is_empty() && sources.iter().all(Option::is_some);
    check(
        checks,
        "sources",
        if sources_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        "at least one source, each a CIDR",
    );
    match bind {
        None => check(
            checks,
            "ingress scope",
            Verdict::Fail,
            "bind_addr is not an address",
        ),
        Some(ip) if ip.is_unspecified() => {
            let any_source = sources.iter().flatten().any(|(_, len)| *len == 0);
            if !spec.public_listener {
                check(
                    checks,
                    "ingress scope",
                    Verdict::Fail,
                    "a wildcard bind needs public_listener",
                );
            } else if any_source {
                check(
                    checks,
                    "ingress scope",
                    Verdict::Fail,
                    "a public listener needs sources narrower than /0",
                );
            } else {
                check(
                    checks,
                    "ingress scope",
                    Verdict::Pass,
                    "public listener, restricted sources",
                );
            }
        }
        Some(_) => check(
            checks,
            "ingress scope",
            Verdict::Pass,
            "one explicit address",
        ),
    }
    let dest_ok = spec.dest_addr.trim().parse::<IpAddr>().is_ok();
    check(
        checks,
        "destination",
        if dest_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        "dest_addr is an address",
    );
    let backend_ok = spec.nat == NatMode::Masquerade;
    check(
        checks,
        "backend capability",
        if backend_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        if backend_ok {
            "userspace TCP/UDP relay, masquerading"
        } else {
            "preserve_source needs a native NAT backend, which is not built; refused rather than masqueraded"
        },
    );
    if let Some(at) = spec.expires_at_ms {
        let future = at > DateTime::now().timestamp_millis();
        check(
            checks,
            "expiry",
            if future { Verdict::Pass } else { Verdict::Fail },
            "expires in the future",
        );
    }
}

fn oid(s: &str) -> Option<ObjectId> {
    ObjectId::parse_str(s.trim()).ok()
}

/// The full dry run of `spec` in `tenant_id`; `self_id` is the forward
/// being updated (its own rule is not a collision).
pub async fn plan(
    state: &NetworkState,
    tenant_id: ObjectId,
    spec: &ForwardSpec,
    self_id: Option<ObjectId>,
) -> Plan {
    let mut checks = Vec::new();
    check_input(spec, &mut checks);

    // The ingress node and its reported listeners.
    let ingress = oid(&spec.ingress_agent_id);
    let ingress_agent = match ingress {
        Some(id) => state
            .fleet
            .agents
            .find_live_in_tenant(tenant_id, id)
            .await
            .ok(),
        None => None,
    };
    match &ingress_agent {
        None => check(
            &mut checks,
            "ingress node",
            Verdict::Fail,
            "not a live device in this tenant",
        ),
        Some(_) => check(
            &mut checks,
            "ingress node",
            Verdict::Pass,
            "a live device in this tenant",
        ),
    }
    if let Some(id) = ingress.filter(|_| ingress_agent.is_some()) {
        let bind: Option<IpAddr> = spec.bind_addr.trim().parse().ok();
        match crate::net_inventory::get(state, tenant_id, id).await {
            Ok(Some(row)) if row.fresh(DateTime::now()) => {
                let l = &row.inventory.listeners;
                let clash = l.items.iter().find(|x| {
                    x.proto == spec.proto
                        && x.port == spec.port
                        && x.addr.parse::<IpAddr>().is_ok_and(|a| {
                            a.is_unspecified() || bind.is_some_and(|b| b.is_unspecified() || b == a)
                        })
                });
                if let Some(x) = clash {
                    let who = x.process.as_deref().unwrap_or("an unknown process");
                    check(
                        &mut checks,
                        "port collision",
                        Verdict::Fail,
                        format!("{who} already listens on {}:{}", x.addr, x.port),
                    );
                } else if l.state
                    != roomler_ai_remote_control::net_inventory::SectionState::Complete
                {
                    check(
                        &mut checks,
                        "port collision",
                        Verdict::Unknown,
                        format!("the node's listener list is {:?}", l.state),
                    );
                } else {
                    check(
                        &mut checks,
                        "port collision",
                        Verdict::Pass,
                        "no reported listener on that port",
                    );
                }
            }
            Ok(Some(_)) => check(
                &mut checks,
                "port collision",
                Verdict::Unknown,
                "the node's inventory is stale",
            ),
            Ok(None) => check(
                &mut checks,
                "port collision",
                Verdict::Unknown,
                "the node has reported no inventory",
            ),
            Err(e) => check(
                &mut checks,
                "port collision",
                Verdict::Unknown,
                format!("inventory unreadable: {e}"),
            ),
        }
        match list(state, tenant_id).await {
            Ok(others) => {
                let dup = others.iter().any(|f| {
                    Some(f.id) != self_id
                        && f.spec.ingress_agent_id == spec.ingress_agent_id
                        && f.spec.proto == spec.proto
                        && f.spec.port == spec.port
                });
                check(
                    &mut checks,
                    "managed overlap",
                    if dup { Verdict::Fail } else { Verdict::Pass },
                    if dup {
                        "another managed forward holds that node, port and protocol"
                    } else {
                        "none"
                    },
                );
            }
            Err(e) => check(&mut checks, "managed overlap", Verdict::Unknown, e),
        }
    }

    // Loops.
    let same_node = spec
        .dest_agent_id
        .as_deref()
        .is_some_and(|d| d.trim() == spec.ingress_agent_id.trim());
    let looped =
        same_node && spec.dest_port == spec.port && spec.dest_addr.trim() == spec.bind_addr.trim();
    check(
        &mut checks,
        "loop",
        if looped { Verdict::Fail } else { Verdict::Pass },
        if looped {
            "the destination is the ingress itself"
        } else {
            "none"
        },
    );

    // Hard regional isolation over ingress and destination.
    let mode = business_isolation::mode(state);
    if mode == Mode::Off {
        check(
            &mut checks,
            "region",
            Verdict::Pass,
            "business_isolation is off",
        );
    } else {
        let zone = |id: Option<ObjectId>| async move {
            let id = id?;
            let agent = state
                .fleet
                .agents
                .find_live_in_tenant(tenant_id, id)
                .await
                .ok()?;
            crate::org_relay::agent_zone(state, &agent)
        };
        let a = zone(ingress).await;
        let b = match spec.dest_agent_id.as_deref() {
            Some(d) => zone(oid(d)).await,
            None => None,
        };
        let (verdict, detail) = match (a, b) {
            (Some(x), Some(y)) if x == y => (Verdict::Pass, format!("both in {x:?}")),
            (Some(_), Some(_)) => (
                Verdict::Fail,
                "ingress and destination are in different zones".to_string(),
            ),
            _ if spec.dest_agent_id.is_none() => (
                Verdict::Fail,
                "an unenrolled destination has no verified zone attachment".to_string(),
            ),
            _ => (
                Verdict::Fail,
                "a zone is unknown (no live connection or no evidence)".to_string(),
            ),
        };
        let verdict = if verdict == Verdict::Fail && mode == Mode::Warn {
            Verdict::Warn
        } else {
            verdict
        };
        check(&mut checks, "region", verdict, detail);
    }

    check(
        &mut checks,
        "management",
        Verdict::Pass,
        "the userspace backend only listens; the node's control connection to www.itachi.fans is untouched",
    );

    let ok = checks
        .iter()
        .all(|c| matches!(c.verdict, Verdict::Pass | Verdict::Warn));
    Plan {
        ok,
        checks,
        backend: "userspace",
    }
}

pub async fn list(
    state: &NetworkState,
    tenant_id: ObjectId,
) -> Result<Vec<ManagedForward>, String> {
    use futures::TryStreamExt;
    state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .find(doc! { "tenant_id": tenant_id, "deleted_at": null })
        .sort(doc! { "created_at": 1 })
        .limit(1000)
        .await
        .map_err(|e| e.to_string())?
        .try_collect()
        .await
        .map_err(|e| e.to_string())
}

pub async fn get(
    state: &NetworkState,
    tenant_id: ObjectId,
    id: ObjectId,
) -> Result<Option<ManagedForward>, String> {
    state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .find_one(doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null })
        .await
        .map_err(|e| e.to_string())
}

/// One audit row per mutation: who, what, which revision, the plan verdict.
pub async fn audit(
    state: &NetworkState,
    tenant_id: ObjectId,
    forward_id: ObjectId,
    actor: ObjectId,
    action: &str,
    revision: u64,
    plan: Option<&Plan>,
) {
    let row = doc! {
        "tenant_id": tenant_id,
        "forward_id": forward_id,
        "actor": actor,
        "action": action,
        "revision": revision as i64,
        "plan_ok": plan.map(|p| p.ok),
        "failed": plan.map(|p| p.checks.iter().filter(|c| matches!(c.verdict, Verdict::Fail | Verdict::Unknown)).map(|c| c.name).collect::<Vec<_>>()),
        "at": DateTime::now(),
    };
    if let Err(e) = state
        .core
        .db
        .collection::<bson::Document>(AUDIT_COLLECTION)
        .insert_one(row)
        .await
    {
        tracing::warn!(%forward_id, %e, "managed forward: audit write failed");
    }
}

/// Push `agent_id` the whole set it should run, when it is online and
/// advertises [`RpcCap::ManagedForward`]. The hard region gate is checked
/// again at every push: a zone that changed since the forward was planned
/// withdraws it (fails closed under `enforce`).
pub async fn push_to(state: &NetworkState, tenant_id: ObjectId, agent_id: ObjectId) {
    let Ok(agent) = state
        .fleet
        .agents
        .find_live_in_tenant(tenant_id, agent_id)
        .await
    else {
        return;
    };
    if !agent.capabilities.has_rpc(RpcCap::ManagedForward)
        || !state.fleet.rc_hub.is_agent_online(agent_id)
    {
        return;
    }
    let Ok(all) = list(state, tenant_id).await else {
        return;
    };
    let (hex, now) = (agent_id.to_hex(), DateTime::now().timestamp_millis());
    let mut forwards = Vec::new();
    for f in all.iter().filter(|f| {
        f.spec.ingress_agent_id == hex
            && f.spec.desired == Desired::Enabled
            && f.spec.expires_at_ms.is_none_or(|e| e > now)
    }) {
        let p = plan(state, tenant_id, &f.spec, Some(f.id)).await;
        if p.checks
            .iter()
            .any(|c| c.name == "region" && c.verdict == Verdict::Fail)
        {
            tracing::warn!(forward = %f.id, "managed forward: region gate failed at push; withheld");
            continue;
        }
        forwards.push(ManagedForwardAssignment {
            id: f.id.to_hex(),
            revision: f.revision,
            bind_addr: f.spec.bind_addr.clone(),
            port: f.spec.port,
            proto: f.spec.proto,
            sources: f.spec.sources.clone(),
            dest_addr: f.spec.dest_addr.clone(),
            dest_port: f.spec.dest_port,
        });
    }
    if let Err(e) = state
        .fleet
        .rc_hub
        .send_to_agent(agent_id, ServerMsg::ManagedForwardSet { forwards })
    {
        tracing::debug!(%agent_id, %e, "managed forward: push failed");
    }
}

/// Record the agent's ack. Each entry lands only on a forward of THIS
/// tenant whose ingress is THIS agent and whose revision is the one acked.
pub async fn record_status(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    statuses: Vec<ManagedForwardStatusWire>,
) {
    let rows = state.core.db.collection::<ManagedForward>(COLLECTION);
    let hex = agent_id.to_hex();
    for s in statuses.into_iter().take(1000) {
        let Ok(id) = ObjectId::parse_str(&s.id) else {
            continue;
        };
        let mut error = s.error;
        if let Some(e) = error.as_mut() {
            truncate_str(e, 200);
        }
        let applied = Applied {
            revision: s.revision,
            listening: s.listening,
            error,
            at: DateTime::now(),
        };
        let Ok(applied) = bson::to_bson(&applied) else {
            continue;
        };
        let filter = doc! {
            "_id": id, "tenant_id": tenant_id, "spec.ingress_agent_id": &hex,
            "revision": s.revision as i64, "deleted_at": null,
        };
        if let Err(e) = rows
            .update_one(filter, doc! { "$set": { "applied": applied } })
            .await
        {
            tracing::warn!(forward = %id, %e, "managed forward: status write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ForwardSpec {
        ForwardSpec {
            name: "db".into(),
            ingress_agent_id: ObjectId::new().to_hex(),
            bind_addr: "100.64.0.2".into(),
            port: 15432,
            proto: L4::Tcp,
            sources: vec!["100.64.0.0/10".into()],
            dest_agent_id: None,
            dest_addr: "10.0.0.5".into(),
            dest_port: 5432,
            nat: NatMode::Masquerade,
            desired: Desired::Enabled,
            public_listener: false,
            expires_at_ms: None,
        }
    }

    fn failed(s: &ForwardSpec) -> Vec<&'static str> {
        let mut c = Vec::new();
        check_input(s, &mut c);
        c.into_iter()
            .filter(|c| c.verdict == Verdict::Fail)
            .map(|c| c.name)
            .collect()
    }

    #[test]
    fn a_well_formed_spec_passes_its_input_checks() {
        assert!(failed(&spec()).is_empty());
    }

    #[test]
    fn a_wildcard_bind_needs_public_listener_and_narrow_sources() {
        let mut s = spec();
        s.bind_addr = "0.0.0.0".into();
        assert_eq!(failed(&s), vec!["ingress scope"]);
        s.public_listener = true;
        assert!(failed(&s).is_empty());
        s.sources = vec!["0.0.0.0/0".into()];
        assert_eq!(failed(&s), vec!["ingress scope"]);
        s.bind_addr = "::".into();
        s.sources = vec!["::/0".into()];
        assert_eq!(failed(&s), vec!["ingress scope"]);
    }

    #[test]
    fn malformed_fields_and_unsupported_nat_are_refused_not_converted() {
        let mut s = spec();
        s.sources = vec![];
        s.port = 0;
        s.dest_addr = "db.internal".into();
        s.nat = NatMode::PreserveSource;
        s.expires_at_ms = Some(1);
        assert_eq!(
            failed(&s),
            vec![
                "ports",
                "sources",
                "destination",
                "backend capability",
                "expiry"
            ]
        );
        let mut s = spec();
        s.sources = vec!["10.0.0.0/33".into()];
        assert_eq!(failed(&s), vec!["sources"]);
    }
}
