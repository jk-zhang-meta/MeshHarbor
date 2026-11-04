// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-7-3c — what a net tool's call asks. Its serving, over the
//! toolbelt's socket, is in the toolbelt's tests.

use serde_json::json;

use super::*;

/// `net_socks` asks its exit alone, for the default time unless it names
/// one; a host it is handed is not a destination (SOCKS names one per
/// connection).
#[test]
fn a_socks_call_asks_its_exit_for_its_time() {
    let exit = ObjectId::new();
    assert_eq!(
        parse(SOCKS, &json!({"exit": exit.to_hex()})),
        Ok(Ask {
            exit,
            dst: None,
            ttl_secs: DEFAULT_TTL_SECS,
        })
    );
    assert_eq!(
        parse(
            SOCKS,
            &json!({"exit": format!(" {} ", exit.to_hex()), "ttl_s": 60, "host": "db.internal", "port": 5432})
        ),
        Ok(Ask {
            exit,
            dst: None,
            ttl_secs: 60,
        })
    );
    assert_eq!(
        parse(SOCKS, &json!({"exit": exit.to_hex(), "ttl_s": null}))
            .unwrap()
            .ttl_secs,
        DEFAULT_TTL_SECS
    );
}

/// `net_forward` asks its one destination, as the session names it: the
/// vault answers it in its own spelling.
#[test]
fn a_forward_asks_its_one_destination() {
    let exit = ObjectId::new();
    assert_eq!(
        parse(
            FORWARD,
            &json!({"exit": exit.to_hex(), "host": " DB.Internal. ", "port": 5432, "ttl_s": 900})
        ),
        Ok(Ask {
            exit,
            dst: Some(("DB.Internal.".into(), 5432)),
            ttl_secs: 900,
        })
    );
}

/// A call without what it needs is refused here, before the vault is asked.
#[test]
fn a_call_without_what_it_needs_is_refused_here() {
    let exit = ObjectId::new().to_hex();
    let refused = |name: &str, args: Value| parse(name, &args).unwrap_err();
    assert!(refused(SOCKS, json!({})).contains("exit is required"));
    assert!(refused(SOCKS, json!({"exit": 7})).contains("exit is required"));
    assert!(refused(SOCKS, json!({"exit": "mars"})).contains("not a device id"));
    for ttl in [
        json!(-1),
        json!("60"),
        json!(1.5),
        json!(u64::from(u32::MAX) + 1),
    ] {
        assert!(
            refused(SOCKS, json!({"exit": exit, "ttl_s": ttl})).contains("ttl_s"),
            "{ttl}"
        );
    }
    assert!(refused(FORWARD, json!({"exit": exit, "port": 22})).contains("host is required"));
    assert!(
        refused(FORWARD, json!({"exit": exit, "host": " ", "port": 22}))
            .contains("host is required")
    );
    for port in [json!(null), json!(0), json!(65536), json!("22"), json!(-22)] {
        assert!(
            refused(FORWARD, json!({"exit": exit, "host": "db", "port": port}))
                .contains("port is required"),
            "{port}"
        );
    }
    assert!(refused("net_udp", json!({"exit": exit})).contains("not a net tool"));
}

/// A listener's capability: 32 bytes, as 64 hex characters, made again for
/// each listener.
#[test]
fn a_capability_is_made_for_each_listener() {
    let (a, b) = (capability(), capability());
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
    assert_ne!(a, b);
}

/// A call holds its place from before the vault is asked: the calls still
/// asking count against the run's listeners, and one that ends without a
/// listener (refused, or cancelled) gives its place back.
#[test]
fn a_call_holds_its_place_while_it_asks() {
    let run = (ObjectId::new(), 1);
    let held: Vec<Place> = (0..MAX_FLOWS).map(|_| Place::hold(run).unwrap()).collect();
    let refused = Place::hold(run).unwrap_err();
    assert!(refused.contains("listeners already"), "{refused}");
    drop(held);
    drop(Place::hold(run).expect("its place is given back"));
    assert_eq!(drop_run(run.0, run.1), 0, "nothing was opened");
}

/// A listener made after its run ended here is ended at once, not left to
/// its grant's end; and a later call's run is not the ended one, even at
/// the same fence.
#[tokio::test]
async fn a_listener_made_after_its_run_ended_ends_at_once() {
    let hub = TunnelClientHub::new("test".into());
    let run = (ObjectId::new(), 2);
    let admit: tunnel_core::flow_listener::Admit =
        std::sync::Arc::new(|_: &tokio::net::TcpStream, _| Ok(()));
    let flow = || {
        hub.create_session_flow(
            ObjectId::new(),
            Target::Static {
                host: "db.internal".into(),
                port: 5432,
            },
            tunnel_core::driver::SessionGrantRef {
                token: ["a", "b", "c"].join("."),
                grant_id: "g1".into(),
            },
            Instant::now() + std::time::Duration::from_secs(60),
            admit.clone(),
        )
    };
    let place = Place::hold(run).unwrap();
    assert_eq!(
        drop_run(run.0, run.1),
        0,
        "the run ends while its call asks"
    );
    let later = Place::hold(run).unwrap();
    let (ended, _) = flow().await.unwrap();
    assert!(!place.fill(&hub, &ended), "its run ended");
    assert!(!hub.has_flow(&ended), "ended at once");
    let (kept, _) = flow().await.unwrap();
    assert!(later.fill(&hub, &kept), "the later call's run lives");
    assert_eq!(drop_run(run.0, run.1), 1);
    assert!(!hub.has_flow(&kept));
}
