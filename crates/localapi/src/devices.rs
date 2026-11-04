// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D5b — a device's own view of its org, as the LocalAPI carries it.
//!
//! The desktop companion reaches only its local daemon, and the daemon holds an
//! AGENT token — never a user's — so the admin grid and the org mesh are out of
//! the companion's reach. The server answers the same questions for one device
//! (`GET /api/agent/self/devices` and `/mesh`, FR-84 D5a); the daemon asks them
//! with the right org's agent token and hands the answer over the pipe as the
//! types below.
//!
//! These are LEAF MIRRORS of the server's wire, not the server's own types:
//! this crate stays serde-only (see the manifest), and a thin client must not
//! compile the remote-control crate to read a list of names. The daemon parses
//! the server's `VisibleDevicesPage` and converts it field by field into
//! [`DevicesPage`] (`agents/meshharbord/src/self_view.rs`), the same way the overlay
//! runtime turns a `NetmapPeer` into a [`crate::PeerInfo`]; a daemon test
//! converts a fully populated server row and compares the two wires, so the
//! mirrors cannot drift apart without a test saying so.
//!
//! ⚠️ Every field is `#[serde(default)]` and every string tolerates `null`:
//! a newer server may add a field, send a value this build has never seen (an
//! OS it does not know), or leave something out, and none of that may turn a
//! device list into an error. The mesh payload in particular is JSON the server
//! builds by hand, so there is no typed shape on that side to lean on.

use serde::{Deserialize, Deserializer, Serialize};

/// `null` → the type's default. `#[serde(default)]` alone only covers a
/// MISSING key; a key present with `null` still fails a `String` field, and a
/// hand-built JSON payload is exactly where such a `null` turns up.
fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// The page query a client asks for — the server grid's own contract. Every
/// field is optional: `0` / `None` means "the server's default" (page 1, 25
/// per page, the online-first-then-name order).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DevicesQuery {
    /// 1-based; `0` = the server's default (1).
    #[serde(default)]
    pub page: u64,
    /// `0` = the server's default (25); the server clamps to 100.
    #[serde(default)]
    pub per_page: u64,
    /// Case-insensitive search the SERVER runs, over the fields a device may
    /// see (fields it may not see are blanked before the search runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// One of the server's sort keys (`name` · `kind` · `os` · `status` ·
    /// `version` · `overlay_ip` · `magic_dns` · `last_seen_at`). The server
    /// refuses an unknown key with a 400 rather than sorting by something
    /// else, and the daemon passes that refusal through as `bad_request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
    /// `asc` (default) | `desc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

/// One device this device may see — itself, or a peer its netmap carries.
/// The leaf mirror of the server's `VisibleDeviceRow`: same field names, same
/// omission rules, so the JSON a client receives reads exactly like the
/// server's.
///
/// ⚠️ Deliberately absent, by shape: `machine_id`, owner ids, WireGuard keys,
/// consent settings, codecs. The server never sends them on this route and a
/// device has no business holding them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceRowLite {
    /// `agent` | `tunnel_client`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub kind: String,
    /// The agent / tunnel-client id (hex).
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    /// The machine-reported (or admin-renamed) technical name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    /// The admin's friendly label, shown over `name` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `linux` | `macos` | `windows` — a string, not an enum, so an OS a
    /// newer server knows and this build does not is shown, not an error.
    #[serde(default, deserialize_with = "null_as_default")]
    pub os: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub version: String,
    /// `online` | `stale` | `offline` — the control-plane presence.
    #[serde(default, deserialize_with = "null_as_default")]
    pub presence: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub is_online: bool,
    /// RFC 3339.
    #[serde(default, deserialize_with = "null_as_default")]
    pub last_seen_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    /// The peer's overlay node id (hex) — the join key to [`crate::PeerInfo::node_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_fqdn: Option<String>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tags: Vec<String>,
    /// The netmap's verdict: may this device dial the peer right now?
    #[serde(default, deserialize_with = "null_as_default")]
    pub reachable: bool,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub ephemeral: bool,
    /// The row is the asking device itself.
    #[serde(default, deserialize_with = "null_as_default")]
    pub is_self: bool,
}

/// One page of [`DeviceRowLite`]s plus the envelope — the answer to
/// [`crate::Request::Devices`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DevicesPage {
    /// Which enrollment the page is for (`primary` or an `[[orgs]]` label).
    /// Stamped by the DAEMON, not the server: the server knows only the
    /// token it was shown.
    #[serde(default, deserialize_with = "null_as_default")]
    pub org: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub items: Vec<DeviceRowLite>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub total: u64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub page: u64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub per_page: u64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub total_pages: u64,
    /// Why the list is what it is: `ok` (the netmap shaping applied) ·
    /// `no_node` (this device is not on the private network) · `no_network`
    /// (the org has none yet) · `unavailable` (the server has no network
    /// module). Every value but `ok` lists the device alone.
    #[serde(default, deserialize_with = "null_as_default")]
    pub overlay: String,
    /// The org's overlay ACL posture: `off` | `warn` | `enforce` | `unknown`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub acl_mode: String,
    /// This device's own overlay node id (hex), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_node_id: Option<String>,
}

/// The centre of the mesh graph — the control plane.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshCenter {
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
}

/// One live overlay node the device may see.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshNodeLite {
    /// Overlay node id (hex) — what edges are keyed by.
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    /// Server-computed: display_name > agent name > node name > overlay ip >
    /// id tail (the web dashboard's rule).
    #[serde(default, deserialize_with = "null_as_default")]
    pub label: String,
    /// The node's own (MagicDNS) name.
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub overlay_ip: String,
    /// The agent backing the node; `None` for a tunnel-client node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_home: Option<String>,
    /// The node row's stored status (`online` / `offline` / …).
    #[serde(default, deserialize_with = "null_as_default")]
    pub status: String,
}

/// One live agent backing a visible node — presence and version for the graph.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshAgentLite {
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `online` | `stale` | `offline` (empty from an agent that never reported).
    #[serde(default, deserialize_with = "null_as_default")]
    pub last_presence: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub agent_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_home: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub os: String,
}

/// One end's OWN report of how it reaches the other end of an edge.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshEdgeEndLite {
    /// Overlay node id of the REPORTER.
    #[serde(default, deserialize_with = "null_as_default")]
    pub node: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub carrier: String,
    /// CLI-style qualifier (`turn/udp`, `derp/tcp`); absent from old agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<i64>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub stalled: bool,
}

/// One undirected peer edge, both ends visible to the device (an edge to a
/// node it may not see would name that node, so the server never sends one).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshEdgeLite {
    #[serde(default, deserialize_with = "null_as_default")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub from: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub to: String,
    /// The pessimistic merge of both ends (the worse carrier wins).
    #[serde(default, deserialize_with = "null_as_default")]
    pub carrier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<i64>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub stalled: bool,
    /// 1 = only one end reported this pair — a weaker claim.
    #[serde(default, deserialize_with = "null_as_default")]
    pub reports: u32,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ends: Vec<MeshEdgeEndLite>,
}

/// The mesh graph restricted to what the device may see — the answer to
/// [`crate::Request::Mesh`].
///
/// ⚠️ `enabled: false` is DATA, not an error: the server has statistics
/// switched off, and a client says so instead of drawing an empty graph.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshView {
    /// Which enrollment the graph is for (daemon-stamped, as on [`DevicesPage`]).
    #[serde(default, deserialize_with = "null_as_default")]
    pub org: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center: Option<MeshCenter>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub nodes: Vec<MeshNodeLite>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub agents: Vec<MeshAgentLite>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub edges: Vec<MeshEdgeLite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_node_id: Option<String>,
    /// Same meaning as [`DevicesPage::overlay`], so an empty graph can say why.
    #[serde(default, deserialize_with = "null_as_default")]
    pub overlay: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub acl_mode: String,
}

/// Why a [`crate::Client::devices`] / [`crate::Client::mesh`] call produced
/// no answer — kept apart so a client can pick its fallback by cause rather
/// than by sniffing prose.
#[derive(Debug)]
pub enum DirectoryError {
    /// The daemon answered, for the server: it could not get the list.
    /// `code` is one of `server_unreachable` · `unauthorized` ·
    /// `unsupported_server` · `module_unmounted` · `rate_limited` ·
    /// `server_error` · `bad_request` · `bad_response` · `unknown_org` ·
    /// `org_disabled` · `unsupported` (a node with no server to ask); `status`
    /// is the HTTP status when the server answered one.
    Upstream {
        code: String,
        message: String,
        status: Option<u16>,
    },
    /// The daemon predates the verb (it answered "unknown variant").
    UnsupportedDaemon { message: String },
    /// Talking to the daemon failed (not running, pipe error, bad frame).
    Io(std::io::Error),
}

impl DirectoryError {
    /// The machine-readable cause: the upstream code, `unsupported_daemon`,
    /// `daemon_unreachable` (no LocalAPI endpoint — the service is not
    /// running) or `daemon_error`.
    pub fn code(&self) -> &str {
        match self {
            DirectoryError::Upstream { code, .. } => code,
            DirectoryError::UnsupportedDaemon { .. } => "unsupported_daemon",
            DirectoryError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                "daemon_unreachable"
            }
            DirectoryError::Io(_) => "daemon_error",
        }
    }

    /// The HTTP status behind an upstream failure, when there was one.
    pub fn status(&self) -> Option<u16> {
        match self {
            DirectoryError::Upstream { status, .. } => *status,
            _ => None,
        }
    }

    /// Classify a daemon's plain `Response::Error`: an old daemon answers a
    /// verb it has never heard of with serde's "unknown variant", which is the
    /// one signal a client has that it is talking to an older service.
    pub(crate) fn from_daemon_error(message: String) -> Self {
        if message.contains("unknown variant") {
            DirectoryError::UnsupportedDaemon { message }
        } else {
            DirectoryError::Upstream {
                code: "daemon_error".to_string(),
                message,
                status: None,
            }
        }
    }
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::Upstream {
                code,
                message,
                status: Some(s),
            } => write!(f, "{code} (HTTP {s}): {message}"),
            DirectoryError::Upstream { code, message, .. } => write!(f, "{code}: {message}"),
            DirectoryError::UnsupportedDaemon { message } => {
                write!(f, "the device service predates this request: {message}")
            }
            DirectoryError::Io(e) => write!(f, "talking to the device service: {e}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl From<std::io::Error> for DirectoryError {
    fn from(e: std::io::Error) -> Self {
        DirectoryError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Client, FlowInfo, LocalApiState, NodeStatus, PeerInfo, Request, Response, handle,
        serve_connection,
    };
    use async_trait::async_trait;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    fn row() -> DeviceRowLite {
        DeviceRowLite {
            kind: "agent".into(),
            id: "0123456789abcdef01234567".into(),
            name: "bravo-box".into(),
            display_name: Some("Kilo".into()),
            os: "linux".into(),
            version: "0.4.103".into(),
            presence: "online".into(),
            is_online: true,
            last_seen_at: "2026-09-25T09:00:00Z".into(),
            overlay_ip: Some("100.64.0.3".into()),
            overlay_node_id: Some("76543210fedcba9876543210".into()),
            magic_dns_name: Some("bravo-box".into()),
            magic_dns_fqdn: None,
            tags: vec!["lab".into()],
            reachable: true,
            ephemeral: false,
            is_self: false,
        }
    }

    fn page() -> DevicesPage {
        DevicesPage {
            org: "primary".into(),
            items: vec![row()],
            total: 1,
            page: 1,
            per_page: 25,
            total_pages: 1,
            overlay: "ok".into(),
            acl_mode: "enforce".into(),
            self_node_id: Some("aaaaaaaaaaaaaaaaaaaaaaaa".into()),
        }
    }

    /// The discriminators and field spellings every client depends on. An
    /// empty `org` and absent query parts are omitted, so the default ask is
    /// the smallest line that still says what it is.
    #[test]
    fn devices_and_mesh_wire_shape_is_locked() {
        assert_eq!(
            serde_json::to_string(&Request::Devices {
                org: String::new(),
                page: 2,
                per_page: 10,
                q: Some("kilo".into()),
                sort: Some("name".into()),
                dir: Some("desc".into()),
            })
            .unwrap(),
            r#"{"t":"devices","d":{"page":2,"per_page":10,"q":"kilo","sort":"name","dir":"desc"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Mesh { org: "acme".into() }).unwrap(),
            r#"{"t":"mesh","d":{"org":"acme"}}"#
        );
        // A terse client may send nothing but the tag's payload object.
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"t":"devices","d":{}}"#).unwrap(),
            Request::Devices {
                org: String::new(),
                page: 0,
                per_page: 0,
                q: None,
                sort: None,
                dir: None,
            }
        );
        assert_eq!(
            serde_json::to_string(&Response::Upstream {
                code: "unauthorized".into(),
                message: "m".into(),
                status: Some(401),
            })
            .unwrap(),
            r#"{"t":"upstream","d":{"code":"unauthorized","message":"m","status":401}}"#
        );
        // No HTTP status (a connect failure, an unknown org) is omitted.
        assert_eq!(
            serde_json::to_string(&Response::Upstream {
                code: "unknown_org".into(),
                message: "m".into(),
                status: None,
            })
            .unwrap(),
            r#"{"t":"upstream","d":{"code":"unknown_org","message":"m"}}"#
        );
        let resp = Response::Devices(Box::new(page()));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(
            s.starts_with(r#"{"t":"devices","d":{"org":"primary","items":[{"#),
            "{s}"
        );
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), resp);
    }

    /// Additive in the direction that matters mid-roll: a NEWER server may
    /// list an OS this build has never heard of, add a field, or send `null`
    /// for a string — none of which may turn the whole list into an error.
    #[test]
    fn a_row_from_a_newer_server_still_parses() {
        let row: DeviceRowLite = serde_json::from_str(
            r#"{"kind":"agent","id":"x","name":"n","display_name":null,"os":"android",
                "version":null,"presence":"online","reachable":true,"is_self":false,
                "tags":null,"some_future_field":{"nested":1}}"#,
        )
        .unwrap();
        assert_eq!(row.os, "android");
        assert_eq!(row.version, "");
        assert!(row.display_name.is_none());
        assert!(row.tags.is_empty());
        assert!(row.reachable);

        // A page from an older server: no overlay / acl_mode / self_node_id.
        let old: DevicesPage = serde_json::from_str(
            r#"{"items":[{"kind":"agent","id":"x","name":"n","os":"windows"}],"total":1}"#,
        )
        .unwrap();
        assert_eq!(old.items.len(), 1);
        assert_eq!(old.overlay, "");
        assert!(old.self_node_id.is_none());
    }

    /// The mesh payload is JSON the server builds by hand (`stats::to_payload`
    /// over aggregation rows), so it carries what the typed side would never
    /// produce: a BSON `{"$date": …}` object for `last_seen_at`, explicit
    /// `null`s for a relay qualifier or an RTT. This is its shape, verbatim.
    #[test]
    fn mesh_view_parses_the_servers_hand_built_payload() {
        let body = r#"{
          "enabled": true,
          "center": {"id": "control-plane", "name": "meshharbor.itachi.fans"},
          "nodes": [
            {"id": "aaaaaaaaaaaaaaaaaaaaaaaa", "agent_id_hex": "111111111111111111111111",
             "name": "alpha", "overlay_ip": "100.64.0.2", "status": "online",
             "last_seen_at": {"$date": {"$numberLong": "1758790000000"}},
             "label": "Alpha"},
            {"id": "bbbbbbbbbbbbbbbbbbbbbbbb", "agent_id_hex": null, "name": "tc-1",
             "overlay_ip": "100.64.0.9", "relay_home": null, "status": "offline",
             "label": "tc-1"}
          ],
          "agents": [
            {"id": "111111111111111111111111", "name": "alpha-box", "display_name": "Alpha",
             "last_presence": "online", "agent_version": "0.4.103", "os": "linux"}
          ],
          "edges": [
            {"kind": "peer", "from": "aaaaaaaaaaaaaaaaaaaaaaaa", "to": "bbbbbbbbbbbbbbbbbbbbbbbb",
             "carrier": "relay", "rtt_ms": null, "stalled": false, "reports": 2,
             "ends": [
               {"node": "aaaaaaaaaaaaaaaaaaaaaaaa", "carrier": "direct", "relay": null, "rtt_ms": 4, "stalled": false},
               {"node": "bbbbbbbbbbbbbbbbbbbbbbbb", "carrier": "relay", "relay": "turn/udp", "rtt_ms": 52, "stalled": false}
             ]}
          ],
          "self_node_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
          "overlay": "ok",
          "acl_mode": "enforce"
        }"#;
        let v: MeshView = serde_json::from_str(body).unwrap();
        assert!(v.enabled);
        assert_eq!(v.center.as_ref().unwrap().name, "meshharbor.itachi.fans");
        assert_eq!(v.nodes.len(), 2);
        assert_eq!(v.nodes[0].label, "Alpha");
        assert_eq!(v.nodes[1].agent_id_hex, None);
        assert_eq!(v.agents[0].display_name.as_deref(), Some("Alpha"));
        let e = &v.edges[0];
        assert_eq!(e.rtt_ms, None);
        assert_eq!(e.reports, 2);
        assert_eq!(e.ends[1].relay.as_deref(), Some("turn/udp"));
        assert_eq!(e.ends[0].rtt_ms, Some(4));
        assert_eq!(v.self_node_id.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaa"));

        // Statistics off: `{"enabled": false}` is the WHOLE payload, and it is
        // data — the client says "the server has statistics off".
        let off: MeshView = serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        assert!(!off.enabled);
        assert!(off.nodes.is_empty() && off.edges.is_empty());
    }

    /// A state that answers the two verbs like a daemon would, so the whole
    /// path — client framing, `serve_connection`'s async dispatch, the typed
    /// errors — runs end to end over an in-memory pipe.
    struct Directory;
    #[async_trait]
    impl LocalApiState for Directory {
        fn status(&self) -> NodeStatus {
            serde_json::from_str(
                r#"{"node_id":"n","name":"h","version":"v","mode":"service","connected":true}"#,
            )
            .unwrap()
        }
        fn peers(&self) -> Vec<PeerInfo> {
            Vec::new()
        }
        fn flows(&self) -> Vec<FlowInfo> {
            Vec::new()
        }
        async fn devices(&self, org: &str, query: &DevicesQuery) -> Response {
            if org == "ghost" {
                return Response::Upstream {
                    code: "unknown_org".into(),
                    message: "no enrollment labelled ghost".into(),
                    status: None,
                };
            }
            let mut p = page();
            // Echo what crossed the pipe, so the test proves it did.
            p.org = if org.is_empty() {
                "primary".into()
            } else {
                org.into()
            };
            p.page = query.page;
            p.per_page = query.per_page;
            p.items[0].name = format!(
                "{}|{}|{}",
                query.q.as_deref().unwrap_or("-"),
                query.sort.as_deref().unwrap_or("-"),
                query.dir.as_deref().unwrap_or("-")
            );
            Response::Devices(Box::new(p))
        }
        async fn mesh(&self, _org: &str) -> Response {
            Response::Upstream {
                code: "unsupported_server".into(),
                message: "the server predates /api/agent/self/mesh".into(),
                status: Some(404),
            }
        }
    }

    #[tokio::test]
    async fn client_round_trips_devices_and_names_upstream_failures() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { serve_connection(server_end, &Directory).await });
        let mut client = Client::new(Box::new(client_end));

        let query = DevicesQuery {
            page: 3,
            per_page: 10,
            q: Some("kilo".into()),
            sort: Some("name".into()),
            dir: Some("desc".into()),
        };
        let got = client.devices("acme", &query).await.unwrap();
        assert_eq!(got.org, "acme");
        assert_eq!((got.page, got.per_page), (3, 10));
        assert_eq!(got.items[0].name, "kilo|name|desc");

        match client.devices("ghost", &DevicesQuery::default()).await {
            Err(e @ DirectoryError::Upstream { .. }) => {
                assert_eq!(e.code(), "unknown_org");
                assert_eq!(e.status(), None);
            }
            other => panic!("expected an upstream failure, got {other:?}"),
        }
        match client.mesh("").await {
            Err(e) => {
                assert_eq!(e.code(), "unsupported_server");
                assert_eq!(e.status(), Some(404));
            }
            Ok(v) => panic!("expected an upstream failure, got {v:?}"),
        }

        drop(client);
        srv.await.unwrap().unwrap();
    }

    /// A daemon older than the verb answers the request with serde's own
    /// "unknown variant" — produced here by a request enum that genuinely
    /// lacks the variant, not by a hand-typed string. The client must name
    /// that `unsupported_daemon` (the desktop falls back to the peers table
    /// and says "update the service"), never an empty list.
    #[tokio::test]
    async fn an_old_daemon_is_unsupported_daemon_not_an_empty_list() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(tag = "t", content = "d", rename_all = "snake_case")]
        #[allow(dead_code)]
        enum OldRequest {
            Status,
            Peers,
        }

        let (client_end, server_end) = tokio::io::duplex(8 * 1024);
        let old = tokio::spawn(async move {
            let (rd, mut wr) = tokio::io::split(server_end);
            let mut lines = tokio::io::BufReader::new(rd).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                let err = serde_json::from_str::<OldRequest>(&line).unwrap_err();
                let mut out = serde_json::to_vec(&Response::Error {
                    message: format!("bad request: {err}"),
                })
                .unwrap();
                out.push(b'\n');
                wr.write_all(&out).await.unwrap();
            }
        });
        let mut client = Client::new(Box::new(client_end));

        let err = client
            .devices("", &DevicesQuery::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "unsupported_daemon", "{err}");
        let err = client.mesh("").await.unwrap_err();
        assert_eq!(err.code(), "unsupported_daemon", "{err}");

        drop(client);
        old.await.unwrap();
    }

    /// A node with no server connection (the trait default) answers with an
    /// `Upstream` the client can fall back on, and the sync path refuses the
    /// async-only verbs.
    #[tokio::test]
    async fn trait_defaults_are_upstream_unsupported() {
        struct Bare;
        #[async_trait]
        impl LocalApiState for Bare {
            fn status(&self) -> NodeStatus {
                Directory.status()
            }
            fn peers(&self) -> Vec<PeerInfo> {
                Vec::new()
            }
            fn flows(&self) -> Vec<FlowInfo> {
                Vec::new()
            }
        }
        assert!(matches!(
            Bare.devices("", &DevicesQuery::default()).await,
            Response::Upstream { ref code, .. } if code == "unsupported"
        ));
        assert!(matches!(
            Bare.mesh("").await,
            Response::Upstream { ref code, .. } if code == "unsupported"
        ));
        assert!(matches!(
            handle(&Request::Mesh { org: String::new() }, &Bare),
            Response::Error { .. }
        ));
    }

    /// The cause classifier: the daemon-not-running case is its own code,
    /// separate from a pipe that failed mid-exchange.
    #[test]
    fn directory_error_codes() {
        let nf = DirectoryError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        assert_eq!(nf.code(), "daemon_unreachable");
        let other = DirectoryError::Io(std::io::Error::other("broken pipe"));
        assert_eq!(other.code(), "daemon_error");
        assert_eq!(
            DirectoryError::from_daemon_error("bad request: unknown variant `devices`".into())
                .code(),
            "unsupported_daemon"
        );
        assert_eq!(
            DirectoryError::from_daemon_error("something else".into()).code(),
            "daemon_error"
        );
    }
}
