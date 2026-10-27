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
//!   node's outbound control path to `www.itachi.fans`. The nft backend
//!   hooks only inbound flows to the forward's own address and port, and
//!   its change rolls back unless this server confirms it still hears the
//!   node. Recorded as a check.
//! - **Overlay destinations** (FWD-02). A destination that is a node's
//!   overlay address, or inside a subnet a node routes (an approved route),
//!   is dialled through the ingress's overlay, so the overlay ACL applies: the
//!   ingress must be allowed that address, port and protocol, and so must
//!   every overlay node the forward's sources admit, or the forward would
//!   carry it past its own ACL. The destination node's zone is the
//!   destination's for the region gate. TCP on the userspace backend only.
//! - **Native preconditions** (nft only), from the ingress's advertised
//!   capability and fresh inventory: forwarding on for the family, no
//!   foreign forward chain that drops by default, and for preserve-source a
//!   destination on a subnet the ingress connects. A blocking host setting
//!   is reported, never changed.
//! - **Revisions.** An update names the revision it read; a stale one is
//!   refused (the route returns 409).

use std::net::IpAddr;

use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_remote_control::models::{NodeRef, RpcCap};
use roomler_ai_remote_control::net_inventory::{FirewallOwner, L4, SectionState, truncate_str};
pub use roomler_ai_remote_control::signaling::ForwardBackend;
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
    /// The engine on the ingress; `userspace` when absent.
    #[serde(default)]
    pub backend: ForwardBackend,
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
    /// The destination is behind the overlay: dialled through it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub via_overlay: bool,
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
    let (backend_ok, detail) = match (spec.backend, spec.nat) {
        (ForwardBackend::Userspace, NatMode::Masquerade) => {
            (true, "userspace TCP/UDP relay, masquerading")
        }
        (ForwardBackend::Userspace, NatMode::PreserveSource) => (
            false,
            "preserve_source needs the nft backend; refused rather than masqueraded",
        ),
        (ForwardBackend::Nft, NatMode::Masquerade) => (true, "nft DNAT, masquerading"),
        (ForwardBackend::Nft, NatMode::PreserveSource) => {
            (true, "nft DNAT, the client's source address preserved")
        }
    };
    check(
        checks,
        "backend capability",
        if backend_ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        detail,
    );
    if spec.backend == ForwardBackend::Nft {
        let dest: Option<IpAddr> = spec.dest_addr.trim().parse().ok();
        let same = bind
            .zip(dest)
            .is_none_or(|(b, d)| b.is_ipv4() == d.is_ipv4());
        let in_family = bind.is_none_or(|b| {
            sources
                .iter()
                .flatten()
                .any(|(ip, _)| ip.is_ipv4() == b.is_ipv4())
        });
        check(
            checks,
            "address family",
            if same && in_family {
                Verdict::Pass
            } else {
                Verdict::Fail
            },
            if !same {
                "nft does not translate between IPv4 and IPv6"
            } else if !in_family {
                "no source CIDR in the ingress address's family"
            } else {
                "one family end to end"
            },
        );
    }
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
        // The ports this node's managed forwards hold: once applied, their
        // own listeners show in the inventory as roomlerd's, and are not
        // foreign (another forward on the same port fails `managed overlap`).
        let managed_ports: Vec<(L4, u16)> = list(state, tenant_id)
            .await
            .unwrap_or_default()
            .iter()
            .filter(|f| f.spec.ingress_agent_id == spec.ingress_agent_id)
            .map(|f| (f.spec.proto, f.spec.port))
            .collect();
        match crate::net_inventory::get(state, tenant_id, id).await {
            Ok(Some(row)) if row.fresh(DateTime::now()) => {
                let l = &row.inventory.listeners;
                let clash = l.items.iter().find(|x| {
                    let ours = matches!(x.process.as_deref(), Some("meshharbord" | "roomlerd"))
                        && managed_ports.contains(&(x.proto, x.port));
                    !ours
                        && x.proto == spec.proto
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

    if spec.backend == ForwardBackend::Nft
        && let (Some(id), Some(agent)) = (ingress, ingress_agent.as_ref())
    {
        native_checks(state, tenant_id, id, agent, spec, &mut checks).await;
    }

    let path = match (ingress, ingress_agent.as_ref()) {
        (Some(id), Some(_)) => overlay_path(state, tenant_id, id, spec, &mut checks).await,
        _ => None,
    };

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
        // Two servers meet by their topology link, any other pair by one zone
        // (`business_isolation::permit_refs`).
        let ingress_ref = ingress.map(|agent_id| NodeRef::Agent { agent_id });
        let dest_ref = match (spec.dest_agent_id.as_deref(), &path) {
            (Some(d), _) => oid(d).map(|agent_id| NodeRef::Agent { agent_id }),
            // Behind the overlay: the node that holds the address or routes
            // the subnet is where the traffic lands.
            (None, Some(node)) => Some(node.node_ref.clone()),
            (None, None) => None,
        };
        let permit = match (&ingress_ref, &dest_ref) {
            (Some(a), Some(b)) => {
                business_isolation::permit_refs(state, mode, tenant_id, a, b).await
            }
            _ => business_isolation::Permit::Denied,
        };
        let (verdict, detail) = match permit {
            business_isolation::Permit::Zone(z) => (Verdict::Pass, format!("both in {z:?}")),
            business_isolation::Permit::Linked(..) => {
                (Verdict::Pass, "a server link joins them".to_string())
            }
            business_isolation::Permit::Denied if dest_ref.is_none() => (
                Verdict::Fail,
                "an unenrolled destination has no verified zone attachment".to_string(),
            ),
            business_isolation::Permit::Denied => (
                Verdict::Fail,
                "not in one known zone, and no server link joins them".to_string(),
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
        match spec.backend {
            ForwardBackend::Userspace => {
                "the userspace backend only listens; the node's control connection to www.itachi.fans is untouched"
            }
            ForwardBackend::Nft => {
                "nft hooks only inbound flows to this address and port; the change rolls back within 30 s unless this server confirms it still hears the node"
            }
        },
    );

    let ok = checks
        .iter()
        .all(|c| matches!(c.verdict, Verdict::Pass | Verdict::Warn));
    Plan {
        ok,
        checks,
        backend: match spec.backend {
            ForwardBackend::Userspace => "userspace",
            ForwardBackend::Nft => "nft",
        },
        via_overlay: path.is_some(),
    }
}

/// Does one of `rules` (a source's grants into a node) cover `ip`, `port`
/// and `proto`?
pub fn rules_allow(
    rules: &[roomler_ai_remote_control::models::OverlayRule],
    ip: IpAddr,
    port: u16,
    proto: L4,
) -> bool {
    use roomler_ai_remote_control::models::ProtocolKind;
    rules.iter().any(|r| {
        parse_cidr(&r.cidr).is_some_and(|n| in_net(ip, n))
            && (r.port_range.low..=r.port_range.high).contains(&port)
            && match r.proto {
                ProtocolKind::Any => true,
                ProtocolKind::Tcp => proto == L4::Tcp,
                ProtocolKind::Udp => proto == L4::Udp,
            }
    })
}

/// FWD-02: is the destination behind the overlay, and may the forward reach
/// it there? The destination node is the one whose overlay address it is,
/// or the one routing an approved subnet that holds it (an exit node's `/0`
/// does not count, nor does a subnet the ingress routes itself: that is its
/// own LAN). Records the path, ACL and source-principal checks, and returns
/// the destination node; `None` for a destination that is not behind the
/// overlay (no check is added then).
async fn overlay_path(
    state: &NetworkState,
    tenant_id: ObjectId,
    ingress_agent: ObjectId,
    spec: &ForwardSpec,
    checks: &mut Vec<Check>,
) -> Option<roomler_ai_remote_control::models::OverlayNode> {
    use roomler_ai_remote_control::models::{OverlayAclMode, OverlayNode};
    let dest: IpAddr = spec.dest_addr.trim().parse().ok()?;
    let ingress = state
        .overlay_nodes
        .find_live_by_agent(tenant_id, ingress_agent)
        .await
        .ok()
        .flatten();
    let network_id = match &ingress {
        Some(n) => n.network_id,
        None => {
            state
                .overlay_networks
                .get_or_create(tenant_id)
                .await
                .ok()?
                .id?
        }
    };
    let nodes = match state
        .overlay_nodes
        .list_active_in_network(tenant_id, network_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            check(
                checks,
                "overlay path",
                Verdict::Unknown,
                format!("overlay nodes unreadable: {e}"),
            );
            return None;
        }
    };
    let routed = |n: &OverlayNode| {
        n.effective_routes()
            .into_iter()
            .find(|r| parse_cidr(r).is_some_and(|(net, len)| len > 0 && in_net(dest, (net, len))))
    };
    let (dest_node, route) = nodes
        .iter()
        .find(|n| n.overlay_ip.parse::<IpAddr>().ok() == Some(dest))
        .map(|n| (n.clone(), None))
        .or_else(|| {
            nodes
                .iter()
                .find_map(|n| routed(n).map(|r| (n.clone(), Some(r))))
        })?;
    if ingress.as_ref().is_some_and(|i| i.id == dest_node.id) {
        return None;
    }
    let where_ = match &route {
        Some(r) => format!(
            "via {} ({}), which routes {r}",
            dest_node.name, dest_node.overlay_ip
        ),
        None => format!(
            "{} ({}) on the overlay",
            dest_node.name, dest_node.overlay_ip
        ),
    };
    let Some(ingress) = ingress else {
        check(
            checks,
            "overlay path",
            Verdict::Fail,
            format!("the destination is {where_}, and the ingress is not on the overlay"),
        );
        return Some(dest_node);
    };
    if spec.backend == ForwardBackend::Nft {
        check(
            checks,
            "overlay path",
            Verdict::Fail,
            format!(
                "the destination is {where_}; a forward into the overlay runs on the userspace backend only"
            ),
        );
        return Some(dest_node);
    }
    check(
        checks,
        "overlay path",
        Verdict::Pass,
        format!("dialled through the ingress's overlay: {where_}"),
    );
    source_region(state, tenant_id, &nodes, &ingress, &dest_node, spec, checks).await;

    let acl =
        match crate::overlay::try_load_acl(state, tenant_id, crate::overlay::PolicyLoad::Always)
            .await
        {
            Ok(a) => a,
            Err(e) => {
                check(
                    checks,
                    "overlay acl",
                    Verdict::Unknown,
                    format!("overlay policies unreadable: {e}"),
                );
                return Some(dest_node);
            }
        };
    if acl.mode == OverlayAclMode::Off {
        check(
            checks,
            "overlay acl",
            Verdict::Pass,
            "the overlay ACL is off: every node already reaches it",
        );
        return Some(dest_node);
    }
    let soft = |ok: bool| match (ok, acl.mode) {
        (true, _) => Verdict::Pass,
        (false, OverlayAclMode::Warn) => Verdict::Warn,
        (false, _) => Verdict::Fail,
    };
    let Some(dest_id) = dest_node.id else {
        return Some(dest_node);
    };
    let allows = |src: &tunnel_core::policy::OverlaySource| {
        rules_allow(
            &tunnel_core::policy::evaluate_overlay_ingress(&acl.policies, src, dest_id),
            dest,
            spec.dest_port,
            spec.proto,
        )
    };
    let proto = match spec.proto {
        L4::Tcp => "tcp",
        L4::Udp => "udp",
    };
    match crate::overlay::try_overlay_source_of(state, &ingress).await {
        Ok(src) => {
            let ok = allows(&src);
            check(
                checks,
                "overlay acl",
                soft(ok),
                if ok {
                    format!(
                        "the ingress may reach {}:{}/{proto}",
                        spec.dest_addr, spec.dest_port
                    )
                } else {
                    format!(
                        "the overlay ACL does not let the ingress reach {}:{}/{proto}",
                        spec.dest_addr, spec.dest_port
                    )
                },
            );
        }
        Err(e) => check(
            checks,
            "overlay acl",
            Verdict::Unknown,
            format!("the ingress's identity is unreadable: {e}"),
        ),
    }
    // The forward's own clients: every overlay node its sources admit must
    // be allowed the destination itself.
    let sources: Vec<(IpAddr, u8)> = spec.sources.iter().filter_map(|s| parse_cidr(s)).collect();
    let mut denied = Vec::new();
    let mut unreadable = false;
    for n in nodes
        .iter()
        .filter(|n| n.id != ingress.id && n.id != dest_node.id)
    {
        let Ok(ip) = n.overlay_ip.parse::<IpAddr>() else {
            continue;
        };
        if !sources.iter().any(|c| in_net(ip, *c)) {
            continue;
        }
        match crate::overlay::try_overlay_source_of(state, n).await {
            Ok(src) if allows(&src) => {}
            Ok(_) => denied.push(format!("{} ({})", n.name, n.overlay_ip)),
            Err(_) => unreadable = true,
        }
    }
    if !denied.is_empty() {
        denied.truncate(5);
        check(
            checks,
            "source principals",
            soft(false),
            format!(
                "{} may not reach the destination themselves; the forward would carry them past the overlay ACL",
                denied.join(", ")
            ),
        );
    } else if unreadable {
        check(
            checks,
            "source principals",
            Verdict::Unknown,
            "an admitted node's identity is unreadable",
        );
    } else {
        check(
            checks,
            "source principals",
            Verdict::Pass,
            "every overlay node the sources admit may reach the destination",
        );
    }
    Some(dest_node)
}

/// v039 GEO-03: a forward must not launder an origin across the zone rule.
/// The destination sees the ingress, so a source the rule keeps from the
/// destination (another zone, no server link) is refused here as the ingress
/// itself is by "region", whatever the overlay ACL's mode.
async fn source_region(
    state: &NetworkState,
    tenant_id: ObjectId,
    nodes: &[roomler_ai_remote_control::models::OverlayNode],
    ingress: &roomler_ai_remote_control::models::OverlayNode,
    dest_node: &roomler_ai_remote_control::models::OverlayNode,
    spec: &ForwardSpec,
    checks: &mut Vec<Check>,
) {
    let mode = business_isolation::mode(state);
    if mode == Mode::Off {
        return;
    }
    let sources: Vec<(IpAddr, u8)> = spec.sources.iter().filter_map(|s| parse_cidr(s)).collect();
    let mut crossing = Vec::new();
    for n in nodes
        .iter()
        .filter(|n| n.id != ingress.id && n.id != dest_node.id)
    {
        let Ok(ip) = n.overlay_ip.parse::<IpAddr>() else {
            continue;
        };
        if !sources.iter().any(|c| in_net(ip, *c)) {
            continue;
        }
        let permit = business_isolation::permit_refs(
            state,
            mode,
            tenant_id,
            &n.node_ref,
            &dest_node.node_ref,
        )
        .await;
        if permit == business_isolation::Permit::Denied {
            crossing.push(format!("{} ({})", n.name, n.overlay_ip));
        }
    }
    let fail = if mode == Mode::Enforce {
        Verdict::Fail
    } else {
        Verdict::Warn
    };
    if crossing.is_empty() {
        check(
            checks,
            "source region",
            Verdict::Pass,
            "every overlay node the sources admit shares the destination's zone or server link",
        );
    } else {
        crossing.truncate(5);
        check(
            checks,
            "source region",
            fail,
            format!(
                "{} may not reach the destination's zone; the forward would carry them across it",
                crossing.join(", ")
            ),
        );
    }
}

/// The table the agent's nft backend owns (roomlerd's
/// `managed_forward_nft::TABLE`; the inventory names it).
pub const NFT_TABLE: &str = "meshharbor_fwd";

/// Is `r`, from the ingress's inventory, `spec`'s DNAT rule in the owned
/// table: its address and port, to its destination?
pub fn is_nft_rule_of(
    r: &roomler_ai_remote_control::net_inventory::FirewallRule,
    spec: &ForwardSpec,
) -> bool {
    let words: Vec<&str> = r.matches.split_whitespace().collect();
    let has = |seq: &[&str]| words.windows(seq.len()).any(|w| w == seq);
    let port = spec.port.to_string();
    let proto = match spec.proto {
        L4::Tcp => "tcp",
        L4::Udp => "udp",
    };
    let dest: Option<IpAddr> = spec.dest_addr.trim().parse().ok();
    let target_ok = r.target.as_deref().is_some_and(|t| {
        t.parse::<std::net::SocketAddr>()
            .ok()
            .map(|s| (s.ip(), s.port()))
            == dest.map(|d| (d, spec.dest_port))
            || t.rsplit_once(':').is_some_and(|(a, p)| {
                a.trim_matches(['[', ']']).parse::<IpAddr>().ok() == dest
                    && p.parse::<u16>().ok() == Some(spec.dest_port)
            })
    });
    r.table == NFT_TABLE
        && r.chain == "prerouting"
        && r.verdict == "dnat"
        && target_ok
        && has(&["daddr", spec.bind_addr.trim()])
        && has(&[proto, "dport", &port])
}

/// Is `ip` inside `net/len` (both of one family)?
fn in_net(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let len = u32::from(len.min(32));
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let len = u32::from(len.min(128));
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// The nft backend's preconditions on the ingress: its advertised
/// capability, then its fresh inventory. A host setting that blocks the
/// forward fails the plan with its name; MeshHarbor never changes it.
async fn native_checks(
    state: &NetworkState,
    tenant_id: ObjectId,
    id: ObjectId,
    agent: &roomler_ai_remote_control::models::Agent,
    spec: &ForwardSpec,
    checks: &mut Vec<Check>,
) {
    let cap = agent.capabilities.has_rpc(RpcCap::ManagedForwardNft);
    check(
        checks,
        "native backend",
        if cap { Verdict::Pass } else { Verdict::Fail },
        if cap {
            "the ingress runs the nft backend"
        } else {
            "the ingress does not advertise the nft backend (Linux, root, nft); refused rather than run in userspace"
        },
    );
    let inv = match crate::net_inventory::get(state, tenant_id, id).await {
        Ok(Some(row)) if row.fresh(DateTime::now()) => row.inventory,
        _ => {
            check(
                checks,
                "ip forwarding",
                Verdict::Unknown,
                "the ingress has no fresh inventory",
            );
            return;
        }
    };
    let bind: Option<IpAddr> = spec.bind_addr.trim().parse().ok();
    let dest: Option<IpAddr> = spec.dest_addr.trim().parse().ok();
    let v4 = bind.is_none_or(|b| b.is_ipv4());
    let nets: Vec<(IpAddr, u8)> = inv
        .interfaces
        .items
        .iter()
        .filter(|i| i.up)
        .flat_map(|i| i.addrs.iter())
        .filter_map(|a| parse_cidr(a))
        .collect();
    let local = dest.is_some_and(|d| nets.iter().any(|(ip, _)| *ip == d));
    if local {
        check(
            checks,
            "ip forwarding",
            Verdict::Pass,
            "the destination is an address of the ingress; nothing is forwarded",
        );
    } else {
        let (on, knob) = if v4 {
            (inv.forwarding.ipv4, "net.ipv4.ip_forward")
        } else {
            (inv.forwarding.ipv6, "net.ipv6.conf.all.forwarding")
        };
        match on {
            Some(true) => check(
                checks,
                "ip forwarding",
                Verdict::Pass,
                format!("{knob} is on"),
            ),
            Some(false) => check(
                checks,
                "ip forwarding",
                Verdict::Fail,
                format!(
                    "{knob} is off on the ingress; MeshHarbor reports it and does not change it"
                ),
            ),
            None => check(
                checks,
                "ip forwarding",
                Verdict::Unknown,
                format!("the ingress did not report {knob}"),
            ),
        }
        let fams: &[&str] = if v4 {
            &["ip", "inet"]
        } else {
            &["ip6", "inet"]
        };
        let chains = &inv.firewall_chains;
        let dropping = chains.items.iter().find(|c| {
            c.owner != FirewallOwner::Meshharbor
                && c.hook.as_deref() == Some("forward")
                && c.policy.as_deref() == Some("drop")
                && fams.contains(&c.family.as_str())
        });
        match (chains.state, dropping) {
            (_, Some(c)) => check(
                checks,
                "foreign forward policy",
                Verdict::Fail,
                format!(
                    "{} {} {}/{} ({:?}) drops forwarded traffic by default; MeshHarbor does not edit foreign tables",
                    c.backend, c.family, c.table, c.name, c.owner
                ),
            ),
            (SectionState::Complete, None) => check(
                checks,
                "foreign forward policy",
                Verdict::Pass,
                "no foreign forward chain drops by default",
            ),
            (s, None) => check(
                checks,
                "foreign forward policy",
                Verdict::Unknown,
                format!("the ingress's firewall chain list is {s:?}"),
            ),
        }
    }
    if spec.nat == NatMode::PreserveSource {
        let on_link = dest.is_some_and(|d| nets.iter().any(|n| in_net(d, *n)));
        check(
            checks,
            "return path",
            if on_link {
                Verdict::Pass
            } else {
                Verdict::Fail
            },
            if on_link {
                "the destination is on a subnet the ingress connects; it must route these clients' replies via the ingress"
            } else {
                "preserve_source needs the destination's replies to come back through the ingress, and the destination is on no subnet the ingress connects"
            },
        );
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
        // The gates a later change can close: zones, the native backend's
        // capability, and the overlay ACL (a policy edit withdraws a forward
        // that would now carry someone past it).
        if let Some(c) = p.checks.iter().find(|c| {
            matches!(
                c.name,
                "region" | "native backend" | "overlay acl" | "source principals" | "source region"
            ) && c.verdict == Verdict::Fail
        }) {
            tracing::warn!(forward = %f.id, check = c.name, "managed forward: gate failed at push; withheld");
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
            backend: f.spec.backend,
            preserve_source: f.spec.nat == NatMode::PreserveSource,
            via_overlay: p.via_overlay,
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
            backend: ForwardBackend::Userspace,
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

    #[test]
    fn nft_takes_preserve_source_but_one_family_end_to_end() {
        let mut s = spec();
        s.backend = ForwardBackend::Nft;
        s.nat = NatMode::PreserveSource;
        assert!(failed(&s).is_empty(), "{:?}", failed(&s));
        s.dest_addr = "fd00::5".into();
        assert_eq!(failed(&s), vec!["address family"]);
        let mut s = spec();
        s.backend = ForwardBackend::Nft;
        s.sources = vec!["fd00::/8".into()];
        assert_eq!(failed(&s), vec!["address family"]);
    }

    #[test]
    fn an_nft_rule_is_recognised_by_address_port_and_destination() {
        use roomler_ai_remote_control::net_inventory::{FirewallOwner, FirewallRule};
        let mut s = spec();
        s.backend = ForwardBackend::Nft;
        let rule = |matches: &str, target: &str| FirewallRule {
            backend: "nftables".into(),
            family: "inet".into(),
            table: NFT_TABLE.into(),
            chain: "prerouting".into(),
            handle: Some(4),
            matches: matches.into(),
            verdict: "dnat".into(),
            target: Some(target.into()),
            packets: None,
            bytes: None,
            owner: FirewallOwner::Meshharbor,
        };
        let m = "ip daddr 100.64.0.2 tcp dport 15432 ip saddr {100.64.0.0/10}";
        assert!(is_nft_rule_of(&rule(m, "10.0.0.5:5432"), &s));
        assert!(
            !is_nft_rule_of(&rule(m, "10.0.0.5:5433"), &s),
            "another destination"
        );
        assert!(!is_nft_rule_of(
            &rule("ip daddr 100.64.0.2 tcp dport 154320", "10.0.0.5:5432"),
            &s
        ));
        assert!(!is_nft_rule_of(
            &rule("ip daddr 100.64.0.2 udp dport 15432", "10.0.0.5:5432"),
            &s
        ));
        let mut foreign = rule(m, "10.0.0.5:5432");
        foreign.table = "nat".into();
        assert!(!is_nft_rule_of(&foreign, &s), "only the owned table counts");
        s.bind_addr = "fd00::2".into();
        s.dest_addr = "fd00::5".into();
        assert!(is_nft_rule_of(
            &rule("ip6 daddr fd00::2 tcp dport 15432", "[fd00::5]:5432"),
            &s
        ));
    }

    #[test]
    fn overlay_rules_match_address_port_and_protocol() {
        use roomler_ai_remote_control::models::{OverlayRule, PortRange, ProtocolKind};
        let rule = |cidr: &str, low: u16, high: u16, proto: ProtocolKind| OverlayRule {
            cidr: cidr.into(),
            port_range: PortRange { low, high },
            proto,
        };
        let ip: IpAddr = "10.84.6.9".parse().unwrap();
        let tcp = [rule("10.84.6.0/24", 5432, 5432, ProtocolKind::Tcp)];
        assert!(rules_allow(&tcp, ip, 5432, L4::Tcp));
        assert!(!rules_allow(&tcp, ip, 5433, L4::Tcp), "another port");
        assert!(!rules_allow(&tcp, ip, 5432, L4::Udp), "another protocol");
        assert!(
            !rules_allow(&tcp, "10.84.7.9".parse().unwrap(), 5432, L4::Tcp),
            "outside the prefix"
        );
        let any = [rule("100.64.0.7/32", 1, u16::MAX, ProtocolKind::Any)];
        assert!(rules_allow(
            &any,
            "100.64.0.7".parse().unwrap(),
            22,
            L4::Udp
        ));
        assert!(!rules_allow(&[], ip, 5432, L4::Tcp), "no grant is a denial");
    }

    #[test]
    fn in_net_masks_both_families() {
        let n = |s: &str| parse_cidr(s).unwrap();
        assert!(in_net("10.0.3.9".parse().unwrap(), n("10.0.3.1/24")));
        assert!(!in_net("10.0.4.9".parse().unwrap(), n("10.0.3.1/24")));
        assert!(in_net("fd00::9".parse().unwrap(), n("fd00::1/64")));
        assert!(!in_net("10.0.3.9".parse().unwrap(), n("fd00::1/64")));
    }
}
