//! Source-callsite event replay; verifies filtering, not a live discovery run.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing::debug;
fn emit_metadata(peer_node_id: &str, count: usize) {
    let source = include_str!("../../../crates/tunnel-core/src/overlay/runtime.rs");
    let old = r#"debug!(peer = %peer_node_id, candidates = count, "overlay: org-relay discovery metadata received (not a session or path decision)");"#;
    let new = r#"debug!(target: "tunnel_core::overlay::runtime::org_discovery_metadata", peer = %peer_node_id, candidates = count, "overlay: org-relay discovery metadata received (not a session or path decision)");"#;
    assert_eq!(
        source
            .matches(
                "overlay: org-relay discovery metadata received (not a session or path decision)"
            )
            .count(),
        1,
        "metadata callsite must be unique"
    );
    match (source.matches(old).count(), source.matches(new).count()) {
        (1, 0) => {
            debug!(target: "tunnel_core::overlay::runtime", peer = %peer_node_id, candidates = count, "overlay: org-relay discovery metadata received (not a session or path decision)")
        }
        (0, 1) => {
            debug!(target: "tunnel_core::overlay::runtime::org_discovery_metadata", peer = %peer_node_id, candidates = count, "overlay: org-relay discovery metadata received (not a session or path decision)")
        }
        _ => panic!("unknown metadata event shape; review test contract"),
    }
}
#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn capture(filter: &str) -> Vec<serde_json::Value> {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Sink(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        emit_metadata("0123456789abcdef01234567", 17);
        debug!(target: "tunnel_core::overlay::runtime", diagnostic="SECRET", "parent-debug-SECRET");
    });
    let raw = bytes.lock().unwrap().clone();
    String::from_utf8(raw)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
#[test]
fn directory_metadata_child_only_contains_only_public_fields() {
    let rows = capture("info,tunnel_core::overlay::runtime::org_discovery_metadata=debug");
    assert_eq!(
        rows.len(),
        1,
        "child-only filter must receive actual metadata callsite event"
    );
    let event = &rows[0];
    assert_eq!(
        event["target"],
        "tunnel_core::overlay::runtime::org_discovery_metadata"
    );
    assert_eq!(event["fields"]["peer"], "0123456789abcdef01234567");
    assert_eq!(event["fields"]["candidates"], 17);
    assert_eq!(
        event["fields"]["message"],
        "overlay: org-relay discovery metadata received (not a session or path decision)"
    );
    assert_eq!(event["fields"].as_object().unwrap().len(), 3);
    assert!(!serde_json::to_string(&rows).unwrap().contains("SECRET"));
}
#[test]
fn directory_metadata_default_info_stays_quiet() {
    assert!(capture("info").is_empty());
}
#[test]
fn directory_metadata_parent_debug_remains_compatible() {
    let rows = capture("info,tunnel_core::overlay::runtime=debug");
    assert_eq!(
        rows.len(),
        2,
        "existing parent-prefix debug must still include the child event"
    );
    assert!(rows.iter().any(|x| x["fields"]["candidates"] == 17));
}
