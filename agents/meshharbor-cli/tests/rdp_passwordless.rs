// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! X17 — `mh rdp` passwordless acceptance & security boundary tests (TDD).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use meshharbor_cli::cli::parse_rdp_from;
use meshharbor_cli::rdpcmd::{
    PlannedRdpInvocation, RdpCliOptions, RdpCredentialScope, RdpCredentialStore, ResolvedRdpDevice,
    StoredRdpCredential, allocate_session_loopback_ip, build_linux_secret_tool_store_plan,
    build_macos_security_store_plan, normalize_cert_sha256, parse_linux_secret_tool_username,
    parse_user_and_device, plan_rdp_session, resolve_freerdp_program_in_path, resolve_peer_scope,
    validate_extra_client_args,
};
use tunnel_core::localapi::{ConnectionType, DaemonMode, NodeStatus, OrgStatus, PeerInfo};

#[derive(Default, Clone)]
struct RecordingCredStore {
    inner: Arc<Mutex<StoreState>>,
}

#[derive(Default)]
struct StoreState {
    entries: BTreeMap<String, StoredRdpCredential>,
    saves: usize,
    loads: usize,
    deletes: usize,
}

impl RecordingCredStore {
    fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.saves, g.loads, g.deletes)
    }
}

impl RdpCredentialStore for RecordingCredStore {
    fn save(&self, scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.saves += 1;
        g.entries.insert(scope.store_target_name(), cred.clone());
        Ok(())
    }

    fn load(&self, scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        let mut g = self.inner.lock().unwrap();
        g.loads += 1;
        Ok(g.entries.get(&scope.store_target_name()).cloned())
    }

    fn delete(&self, scope: &RdpCredentialScope) -> Result<bool> {
        let mut g = self.inner.lock().unwrap();
        g.deletes += 1;
        Ok(g.entries.remove(&scope.store_target_name()).is_some())
    }
}

fn sample_device() -> ResolvedRdpDevice {
    ResolvedRdpDevice {
        org_id: "65f000000000000000000001".to_string(),
        device_id: "65f000000000000000000099".to_string(),
        device_name: "win-workstation".to_string(),
        ..Default::default()
    }
}

fn loopback_addr() -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(allocate_session_loopback_ip()), 53389)
}

fn assert_no_secret_in_invocation(plan: &PlannedRdpInvocation, secret: &str) {
    assert!(
        !plan.program.contains(secret),
        "program path leaked secret: {}",
        plan.program
    );
    for arg in &plan.args {
        assert!(!arg.contains(secret), "argv leaked secret: {arg}");
        let lower = arg.to_ascii_lowercase();
        assert!(
            !lower.starts_with("/p:") && !lower.starts_with("--password"),
            "argv used forbidden password flag: {arg}"
        );
        assert!(
            !lower.contains("cmdkey") && !lower.contains("/pass:"),
            "argv referenced forbidden cmdkey /pass: {arg}"
        );
        assert!(
            !lower.contains("/cert:ignore") && !lower.contains("/cert-ignore"),
            "argv disabled certificate check: {arg}"
        );
    }
    for (k, v) in &plan.env {
        assert!(
            !k.contains(secret) && !v.contains(secret),
            "env leaked secret"
        );
    }
}

#[test]
fn cli_parses_rdp_subcommand_with_default_passwordless_off() {
    let opts = parse_rdp_from(["mh", "rdp", "alice@win-workstation"]).unwrap();
    assert_eq!(opts.target, "alice@win-workstation");
    assert!(opts.user.is_none());
    assert!(opts.domain.is_none());
    assert_eq!(opts.port, 3389);
    assert!(opts.explicit_port.is_none());
    assert!(!opts.check);
    assert!(opts.cert_sha256.is_none());
    assert!(
        !opts.save_credentials && !opts.use_saved_credentials,
        "passwordless credential storage/auto-fill must default to OFF"
    );
    assert!(!opts.clear_credentials);
    assert!(!opts.no_saved_credentials);
    assert!(opts.extra_args.is_empty());

    let check_opts = parse_rdp_from(["mh", "rdp", "win-workstation", "--check", "--port", "13389"])
        .expect("parse --check");
    assert!(check_opts.check);
    assert_eq!(check_opts.port, 13389);
    assert_eq!(check_opts.explicit_port, Some(13389));

    // Verify no skip-verification CLI flag exists (`V0028 §3`), neither as a
    // top-level `mh rdp` option nor smuggled via trailing client args.
    for forbidden_flag in [
        "--insecure",
        "--skip-cert-check",
        "--no-verify-cert",
        "--ignore-cert",
    ] {
        assert!(
            parse_rdp_from(["mh", "rdp", forbidden_flag, "win-workstation"]).is_err(),
            "forbidden skip-verification flag must be rejected by clap before <device>: {forbidden_flag}"
        );
        if let Ok(trailing) = parse_rdp_from(["mh", "rdp", "win-workstation", forbidden_flag]) {
            assert!(
                validate_extra_client_args(&trailing.extra_args).is_err(),
                "forbidden skip-verification flag must be rejected in trailing extra_args: {forbidden_flag}"
            );
        }
    }

    let (parsed_user, parsed_host) = parse_user_and_device("alice@win-workstation").unwrap();
    assert_eq!(parsed_user.as_deref(), Some("alice"));
    assert_eq!(parsed_host, "win-workstation");
}

#[test]
fn default_off_neither_reads_nor_writes_credential_store() {
    let store = RecordingCredStore::default();
    let dev = sample_device();
    let opts = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: false,
        use_saved_credentials: false,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };

    let addr = loopback_addr();
    let plan = plan_rdp_session(&opts, &dev, addr, &store, None, None, "linux")
        .unwrap()
        .expect("should return an RDP client invocation plan");

    assert_eq!(
        store.counts(),
        (0, 0, 0),
        "default OFF must neither read nor write OS credential store"
    );
    assert!(plan.stdin_payload.is_none());
    assert!(plan.windows_session_target.is_none());
    assert!(
        plan.args.iter().any(|a| a == &format!("/v:{addr}")),
        "must dial local loopback tunnel: {:?}",
        plan.args
    );
}

#[test]
fn kill_switch_cli_flag_and_env_reject_saved_credentials_and_never_touch_store() {
    let store = RecordingCredStore::default();
    let dev = sample_device();

    // 1. CLI kill switch (--no-saved-credentials) rejects --save-credentials and --use-saved-credentials
    let opts_cli_kill = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: true,
        use_saved_credentials: true,
        clear_credentials: false,
        no_saved_credentials: true,
        extra_args: vec![],
        ..Default::default()
    };
    let err = plan_rdp_session(
        &opts_cli_kill,
        &dev,
        loopback_addr(),
        &store,
        Some("S3cretPass!"),
        None,
        "windows",
    )
    .unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("disabled")
            || err.to_string().to_ascii_lowercase().contains("kill"),
        "unexpected error: {err}"
    );
    assert_eq!(store.counts(), (0, 0, 0));

    // 2. Environment kill switch (MESHHARBOR_RDP_PASSWORDLESS_DISABLED=1) rejects saved credentials
    let opts_env_kill = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: false,
        use_saved_credentials: true,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };
    let err2 = plan_rdp_session(
        &opts_env_kill,
        &dev,
        loopback_addr(),
        &store,
        None,
        Some("1"),
        "linux",
    )
    .unwrap_err();
    assert!(
        err2.to_string().to_ascii_lowercase().contains("disabled"),
        "unexpected error: {err2}"
    );
    assert_eq!(store.counts(), (0, 0, 0));
}

#[test]
fn configure_once_then_repeat_use_without_prompt_or_argv_leak() {
    let store = RecordingCredStore::default();
    let dev = sample_device();
    let secret = "Rdp#Sup3rS3cret!2026";

    // Step 1: First-time opt-in (--save-credentials) stores credential in client OS store
    let save_opts = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: Some("CORP".to_string()),
        port: 3389,
        cert_sha256: None,
        save_credentials: true,
        use_saved_credentials: true,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };
    let plan1 = plan_rdp_session(
        &save_opts,
        &dev,
        loopback_addr(),
        &store,
        Some(secret),
        None,
        "linux",
    )
    .unwrap()
    .expect("should return invocation plan");
    assert_eq!(store.counts().0, 1, "must write once to OS store");
    assert_no_secret_in_invocation(&plan1, secret);
    assert!(
        plan1.args.iter().any(|a| a.starts_with("/from-stdin")),
        "FreeRDP must read password from stdin, never argv: {:?}",
        plan1.args
    );
    assert!(
        !format!("{plan1:?}").contains(secret) || plan1.stdin_payload.as_deref() == Some(secret)
    );

    // Step 2: Subsequent invocation (--use-saved-credentials, no password prompt)
    // retrieves from OS store without asking the user again
    let use_opts = RdpCliOptions {
        target: "win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: false,
        use_saved_credentials: true,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };
    let win_addr = loopback_addr();
    let plan2 = plan_rdp_session(
        &use_opts, &dev, win_addr, &store, None, // NO password prompt on repeat use!
        None, "windows",
    )
    .unwrap()
    .expect("should return Windows mstsc invocation plan");
    assert_no_secret_in_invocation(&plan2, secret);
    assert_eq!(plan2.program, "mstsc.exe");
    assert_eq!(plan2.args, vec![format!("/v:{win_addr}")]);
    assert_eq!(
        plan2.windows_session_target.as_deref(),
        Some(format!("TERMSRV/{}", win_addr.ip()).as_str())
    );

    // Step 3: --clear-credentials deletes the saved credential and exits without connecting
    let clear_opts = RdpCliOptions {
        target: "win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: false,
        use_saved_credentials: false,
        clear_credentials: true,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };
    let cleared = plan_rdp_session(
        &clear_opts,
        &dev,
        loopback_addr(),
        &store,
        None,
        None,
        "windows",
    )
    .unwrap();
    assert!(cleared.is_none(), "clear_credentials must not dial RDP");
    assert_eq!(store.counts().2, 1, "must delete credential from OS store");
}

#[test]
fn rejects_cmdkey_pass_and_plaintext_password_flags_and_cert_ignore() {
    validate_extra_client_args(&[
        "/f".to_string(),
        "/w:1920".to_string(),
        "/h:1080".to_string(),
    ])
    .expect("safe display flags must be allowed");
    for bad in [
        vec!["/p:secret123".to_string()],
        vec!["/password:secret123".to_string()],
        vec!["--password".to_string(), "secret123".to_string()],
        vec!["--password=secret123".to_string()],
        vec!["cmdkey".to_string(), "/pass:secret".to_string()],
        vec!["/pass:secret".to_string()],
        vec!["/cert:ignore".to_string()],
        vec!["/cert-ignore".to_string()],
        vec!["--ignore-certificate".to_string()],
    ] {
        assert!(
            validate_extra_client_args(&bad).is_err(),
            "must reject unsafe client args: {bad:?}"
        );
    }
}

#[test]
fn pins_tls_certificate_sha256_fingerprint_and_never_disables_verification() {
    let fp = normalize_cert_sha256(
        "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
    )
    .unwrap();
    assert_eq!(
        fp,
        "a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
    );

    let store = RecordingCredStore::default();
    let dev = sample_device();
    let opts = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: Some(
            "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                .to_string(),
        ),
        save_credentials: false,
        use_saved_credentials: false,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };
    let plan = plan_rdp_session(&opts, &dev, loopback_addr(), &store, None, None, "linux")
        .unwrap()
        .unwrap();
    assert_eq!(plan.pinned_cert_sha256.as_deref(), Some(fp.as_str()));
    assert!(
        plan.args
            .iter()
            .any(|a| a == &format!("/cert:fingerprint:sha256:{fp}")),
        "FreeRDP invocation must pin target certificate fingerprint: {:?}",
        plan.args
    );

    // V0028: On Windows (`mstsc.exe`), `--cert-sha256` is accepted and retained on
    // `PlannedRdpInvocation::pinned_cert_sha256` (enforced fail-closed by
    // `precheck_rdp_tunnel_tls` before spawning `mstsc.exe`).
    let win_addr = loopback_addr();
    let win_plan = plan_rdp_session(&opts, &dev, win_addr, &store, None, None, "windows")
        .expect("Windows must accept --cert-sha256 for pre-mstsc TLS verification")
        .expect("should return Windows mstsc plan");
    assert_eq!(win_plan.program, "mstsc.exe");
    assert_eq!(win_plan.args, vec![format!("/v:{win_addr}")]);
    assert_eq!(win_plan.pinned_cert_sha256.as_deref(), Some(fp.as_str()));
}

#[test]
fn windows_per_session_loopback_is_unique_and_shared_localhost_is_refused() {
    let ip1 = allocate_session_loopback_ip();
    let ip2 = allocate_session_loopback_ip();
    assert_ne!(
        ip1, ip2,
        "concurrent sessions must get distinct loopback IPs"
    );
    assert_eq!(ip1.octets()[0], 127);
    assert_eq!(ip1.octets()[1], 77);
    assert_ne!(ip1, std::net::Ipv4Addr::LOCALHOST);
    assert_ne!(ip2, std::net::Ipv4Addr::LOCALHOST);

    let store = RecordingCredStore::default();
    let dev = sample_device();
    let opts = RdpCliOptions {
        target: "alice@win-workstation".to_string(),
        user: None,
        domain: None,
        port: 3389,
        cert_sha256: None,
        save_credentials: true,
        use_saved_credentials: true,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
        ..Default::default()
    };

    // Shared 127.0.0.1 must be refused for Windows session credential target
    let shared_addr: SocketAddr = "127.0.0.1:53389".parse().unwrap();
    let shared_err = plan_rdp_session(
        &opts,
        &dev,
        shared_addr,
        &store,
        Some("S3cret!"),
        None,
        "windows",
    )
    .expect_err("Windows passwordless session must refuse shared 127.0.0.1 target");
    assert!(
        shared_err.to_string().contains("127.0.0.1"),
        "unexpected error: {shared_err}"
    );

    // Two sessions with distinct per-session loopback IPs get distinct TERMSRV targets
    let p1 = plan_rdp_session(
        &opts,
        &dev,
        SocketAddr::new(std::net::IpAddr::V4(ip1), 50001),
        &store,
        Some("S3cret!"),
        None,
        "windows",
    )
    .unwrap()
    .unwrap();
    let p2 = plan_rdp_session(
        &opts,
        &dev,
        SocketAddr::new(std::net::IpAddr::V4(ip2), 50002),
        &store,
        Some("S3cret!"),
        None,
        "windows",
    )
    .unwrap()
    .unwrap();
    assert_ne!(
        p1.windows_session_target, p2.windows_session_target,
        "two concurrent sessions must have distinct TERMSRV targets"
    );
}

#[test]
fn resolve_peer_scope_enforces_real_tenant_id_and_node_id_and_fails_closed() {
    let status = NodeStatus {
        path_trials: None,
        node_id: "local-node-00".to_string(),
        name: "local-box".to_string(),
        version: "0.4.59".to_string(),
        mode: DaemonMode::Service,
        privileged: Some(true),
        tenant_id: Some("65f000000000000000000001".to_string()),
        overlay_ip: Some("100.64.0.1".to_string()),
        overlay_ip6: None,
        overlay_socks5_port: Some(1080),
        connected: true,
        ephemeral: false,
        exit_node: None,
        route_offer_withheld: None,
        host_firewall: None,
        config_path: None,
        dns: None,
        srflx: None,
        warm_relay: None,
        lan_captures: None,
        lan_capture_probe: None,
        join_refusal: None,
        netcheck: None,
        orgs: vec![
            OrgStatus {
                label: "primary".to_string(),
                server_url: "https://one.example".to_string(),
                tenant_id: Some("65f000000000000000000001".to_string()),
                agent_id: Some("agent-primary-self".to_string()),
                primary: true,
                enabled: true,
                connected: true,
                terminal_error: None,
                updates_ignored: 0,
                overlay_mode: "tun".to_string(),
                token_expires_at: None,
            },
            OrgStatus {
                label: "acme-corp".to_string(),
                server_url: "https://two.example".to_string(),
                tenant_id: Some("65f000000000000000000002".to_string()),
                agent_id: Some("agent-acme-self".to_string()),
                primary: false,
                enabled: true,
                connected: true,
                terminal_error: None,
                updates_ignored: 0,
                overlay_mode: "tun".to_string(),
                token_expires_at: None,
            },
        ],
        direct_socks: vec![],
        derp_inbound_drops: None,
        direct_bind_walks: None,
        roam_adoptions: None,
        route_guard: None,
        route_wave_arms: None,
        route_yields: None,
        route_wave_pulls: None,
        disco_answered: None,
        org_relay: None,
        legacy_env_uses: None,
        retired_env_present: None,
        pid: None,
        started_at_ms: None,
        files_dir: None,
    };

    let make_peer = |node_id: &str, name: &str, org: &str, ip: &str| PeerInfo {
        node_id: node_id.to_string(),
        name: name.to_string(),
        org: org.to_string(),
        overlay_ip: Some(ip.to_string()),
        overlay_ip6: None,
        online: true,
        connection: ConnectionType::Direct,
        upgrading: false,
        stalled: false,
        relay_kind: None,
        relay_transport: None,
        relay_server: None,
        rtt_ms: Some(5),
        last_seen_ms: None,
        agent_id: None,
        relay_local: None,
        relay_dst: None,
        debug: None,
        why: None,
        probes: vec![],
    };

    let peers = vec![
        make_peer("node-primary-111", "shared-host", "primary", "100.64.0.10"),
        make_peer("node-acme-222", "shared-host", "acme-corp", "100.65.0.10"),
        make_peer("node-acme-333", "acme-only-rdp", "acme-corp", "100.65.0.11"),
    ];

    // 1. Secondary org peer must use secondary org's real tenant_id (not primary's and not label)
    let (dev_acme, dial_ip, socks) =
        resolve_peer_scope(&status, &peers, "acme-only-rdp").expect("resolve acme peer");
    assert_eq!(dev_acme.org_id, "65f000000000000000000002");
    assert_eq!(dev_acme.device_id, "node-acme-333");
    assert_eq!(dev_acme.device_name, "acme-only-rdp");
    assert_eq!(dial_ip, "100.65.0.11");
    assert_eq!(socks, Some(1080));

    // 2. Same device name in two orgs must fail closed when unqualified
    let ambig_err = resolve_peer_scope(&status, &peers, "shared-host")
        .expect_err("same hostname in two orgs must fail closed when unqualified");
    assert!(
        ambig_err
            .to_string()
            .to_ascii_lowercase()
            .contains("ambiguous"),
        "unexpected error: {ambig_err}"
    );

    // 3. Disambiguated via <org>/<device> or node_id produces strictly disjoint scopes
    let (dev_p, _, _) =
        resolve_peer_scope(&status, &peers, "primary/shared-host").expect("resolve primary");
    let (dev_a, _, _) =
        resolve_peer_scope(&status, &peers, "acme-corp/shared-host").expect("resolve acme");
    assert_eq!(dev_p.org_id, "65f000000000000000000001");
    assert_eq!(dev_p.device_id, "node-primary-111");
    assert_eq!(dev_a.org_id, "65f000000000000000000002");
    assert_eq!(dev_a.device_id, "node-acme-222");

    // 4. Unknown device must fail closed (never fall back to raw hostname)
    let unknown_err = resolve_peer_scope(&status, &peers, "unknown-workstation")
        .expect_err("unknown device must fail closed");
    assert!(
        unknown_err.to_string().contains("not found"),
        "unexpected error: {unknown_err}"
    );

    // 5. Missing real tenant_id must fail closed (never fall back to org label)
    let mut status_no_tid = status.clone();
    status_no_tid.tenant_id = None;
    status_no_tid.orgs[1].tenant_id = None;
    let no_tid_err = resolve_peer_scope(&status_no_tid, &peers, "acme-only-rdp")
        .expect_err("missing tenant_id must fail closed");
    assert!(
        no_tid_err.to_string().contains("tenant_id"),
        "unexpected error: {no_tid_err}"
    );
}

#[test]
fn linux_secret_tool_username_fails_closed_and_freerdp_binary_falls_back() {
    assert!(
        parse_linux_secret_tool_username("label = test\nattribute.service = meshharbor-rdp\n")
            .is_err(),
        "missing attribute.username must fail closed"
    );
    assert!(
        parse_linux_secret_tool_username("attribute.username =   \n").is_err(),
        "empty attribute.username must fail closed"
    );
    assert_eq!(
        parse_linux_secret_tool_username("attribute.username = CORP\\alice\n").unwrap(),
        "CORP\\alice"
    );

    // Verify FreeRDP binary resolution fallback (xfreerdp3 -> xfreerdp)
    let tmp = std::env::temp_dir().join(format!("mh-freerdp-path-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let xfreerdp_bin = tmp.join("xfreerdp");
    std::fs::write(&xfreerdp_bin, b"#!/bin/sh\n").unwrap();
    assert_eq!(
        resolve_freerdp_program_in_path(Some(tmp.as_os_str())),
        "xfreerdp"
    );
    let xfreerdp3_bin = tmp.join("xfreerdp3");
    std::fs::write(&xfreerdp3_bin, b"#!/bin/sh\n").unwrap();
    assert_eq!(
        resolve_freerdp_program_in_path(Some(tmp.as_os_str())),
        "xfreerdp3"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn linux_and_macos_os_store_builders_pass_secret_only_via_stdin_never_argv() {
    let scope = RdpCredentialScope {
        org_id: "org1".to_string(),
        device_id: "dev1".to_string(),
    };
    let secret = "TopSecret#Rdp99!";
    let cred = StoredRdpCredential::new("alice", Some("CORP".to_string()), secret);

    let (linux_prog, linux_args, linux_stdin) =
        build_linux_secret_tool_store_plan(&scope, &cred).unwrap();
    assert_eq!(linux_prog, "secret-tool");
    for a in &linux_args {
        assert!(
            !a.contains(secret),
            "linux secret-tool argv leaked secret: {a}"
        );
    }
    assert!(linux_stdin.contains(secret));

    let (mac_prog, mac_args, mac_stdin) = build_macos_security_store_plan(&scope, &cred).unwrap();
    assert_eq!(mac_prog, "/usr/bin/security");
    assert_eq!(mac_args, vec!["-i".to_string()]);
    for a in &mac_args {
        assert!(
            !a.contains(secret),
            "macos security argv leaked secret: {a}"
        );
    }
    assert!(mac_stdin.contains("add-generic-password"));
    assert!(mac_stdin.contains(secret));
}

/// End-to-end test inside an isolated Linux network namespace (`ip netns`) with
/// a real TLS `xrdp` server, `dbus-run-session` + `gnome-keyring-daemon`,
/// `secret-tool`, and `xfreerdp3 +auth-only`.
///
/// Run explicitly as root with:
/// `cargo test -p meshharbor-cli --test rdp_passwordless linux_isolated_netns_xrdp_tls_secret_tool_end_to_end -- --ignored --nocapture`
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root (ip netns), xrdp, xfreerdp3, secret-tool, and gnome-keyring-daemon; run with -- --ignored"]
fn linux_isolated_netns_xrdp_tls_secret_tool_end_to_end() {
    use std::process::Command;

    for bin in [
        "/usr/sbin/xrdp",
        "/usr/bin/xfreerdp3",
        "/usr/bin/secret-tool",
        "/usr/bin/gnome-keyring-daemon",
        "/usr/bin/dbus-run-session",
        "/usr/bin/openssl",
        "/usr/bin/python3",
    ] {
        assert!(
            std::path::Path::new(bin).exists(),
            "required E2E binary missing on test host: {bin}"
        );
    }

    let mh_bin = env!("CARGO_BIN_EXE_mh");
    let netns = format!("mh_rdp_t_{}", std::process::id());

    struct NetnsDropGuard(String);
    impl Drop for NetnsDropGuard {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
        }
    }
    let _ = Command::new("ip").args(["netns", "del", &netns]).status();
    let add_st = Command::new("ip")
        .args(["netns", "add", &netns])
        .status()
        .expect("ip netns add");
    assert!(add_st.success(), "ip netns add {netns} must succeed");
    let _ns_guard = NetnsDropGuard(netns.clone());

    assert!(
        Command::new("ip")
            .args(["-n", &netns, "link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args(["-n", &netns, "addr", "add", "100.64.0.42/32", "dev", "lo"])
            .status()
            .unwrap()
            .success()
    );

    let tmpdir = std::env::temp_dir().join(format!("mh_rdp_e2e_cargo_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    struct DirDropGuard(std::path::PathBuf);
    impl Drop for DirDropGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _dir_guard = DirDropGuard(tmpdir.clone());

    let script_path = tmpdir.join("e2e_driver.py");
    let script = r#"import json, os, select, socket, subprocess, sys, threading, time

mh_bin = sys.argv[1]
tmpdir = sys.argv[2]
secret_pw = "RdpCargoE2e#Pass!2026"
org_id = "65f000000000000000000001"
dev_id = "65f000000000000000000099"
dev_name = "win-workstation"
overlay_ip = "100.64.0.42"
rdp_port = 13389
xrdp_backend_port = 23389

xdg_runtime = os.path.join(tmpdir, "xdg_runtime")
os.makedirs(xdg_runtime, mode=0o700, exist_ok=True)
sock_path = os.path.join(xdg_runtime, "meshharbor.sock")
for sub in ("xdg_config", "xdg_data", "xdg_cache"):
    os.makedirs(os.path.join(tmpdir, sub), mode=0o700, exist_ok=True)
os.environ["HOME"] = tmpdir
os.environ["XDG_RUNTIME_DIR"] = xdg_runtime
os.environ["XDG_CONFIG_HOME"] = os.path.join(tmpdir, "xdg_config")
os.environ["XDG_DATA_HOME"] = os.path.join(tmpdir, "xdg_data")
os.environ["XDG_CACHE_HOME"] = os.path.join(tmpdir, "xdg_cache")

kr = subprocess.run(
    ["gnome-keyring-daemon", "--unlock", "--components=secrets"],
    input="keyring-unlock-pass\n",
    capture_output=True,
    text=True,
    check=True,
)
for line in kr.stdout.splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip().rstrip(";")

status_resp = {
    "t": "status",
    "d": {
        "node_id": "local-node-01",
        "name": "linux-client",
        "version": "0.4.151",
        "mode": "service",
        "privileged": True,
        "tenant_id": org_id,
        "overlay_ip": "100.64.0.1",
        "connected": True,
        "orgs": [{
            "label": "primary",
            "server_url": "https://control.example.invalid",
            "tenant_id": org_id,
            "agent_id": "65f000000000000000000010",
            "primary": True,
            "enabled": True,
            "connected": True,
            "overlay_mode": "tun",
        }],
    },
}
peers_resp = {
    "t": "peers",
    "d": [{
        "node_id": dev_id,
        "name": dev_name,
        "org": "primary",
        "overlay_ip": overlay_ip,
        "online": True,
        "connection": "direct",
        "agent_id": dev_id,
    }],
}

stop_ev = threading.Event()

def serve_localapi():
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(16)
    srv.settimeout(0.2)
    while not stop_ev.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        def handle(c):
            with c:
                f = c.makefile("rwb")
                for line in f:
                    if not line.strip():
                        continue
                    req = json.loads(line.decode("utf-8"))
                    if req.get("t") == "status":
                        f.write((json.dumps(status_resp) + "\n").encode("utf-8"))
                        f.flush()
                    elif req.get("t") == "peers":
                        f.write((json.dumps(peers_resp) + "\n").encode("utf-8"))
                        f.flush()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    srv.close()

threading.Thread(target=serve_localapi, daemon=True).start()

key_pem = os.path.join(tmpdir, "key.pem")
cert_pem = os.path.join(tmpdir, "cert.pem")
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key_pem, "-out", cert_pem, "-days", "1", "-subj", f"/CN={overlay_ip}"],
    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
fp_out = subprocess.check_output(["openssl", "x509", "-in", cert_pem, "-noout", "-fingerprint", "-sha256"], text=True)
good_fp = fp_out.strip().split("=", 1)[1].strip().lower()
bad_fp = "00:" * 31 + "00"

xrdp_ini = os.path.join(tmpdir, "xrdp.ini")
with open(xrdp_ini, "w") as f:
    f.write(f"[Globals]\nini_version=1\nfork=true\nport=tcp://{overlay_ip}:{xrdp_backend_port}\ntcp_nodelay=true\nsecurity_layer=tls\ncrypt_level=high\ncertificate={cert_pem}\nkey_file={key_pem}\nssl_protocols=TLSv1.2, TLSv1.3\nautorun=\n")

xrdp_proc = subprocess.Popen(["/usr/sbin/xrdp", "--nodaemon", "-c", xrdp_ini], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.6)

def run_paced_bridge():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((overlay_ip, rdp_port))
    lsock.listen(16)
    lsock.settimeout(0.2)
    while not stop_ev.is_set():
        try:
            cli, _ = lsock.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        def bridge(c):
            try:
                time.sleep(0.20)
                up = socket.create_connection((overlay_ip, xrdp_backend_port), timeout=5.0)
                while True:
                    r, _, _ = select.select([c, up], [], [], 5.0)
                    if not r:
                        break
                    for s in r:
                        data = s.recv(16384)
                        if not data:
                            c.close(); up.close(); return
                        (up if s is c else c).sendall(data)
            except Exception:
                pass
            finally:
                try: c.close()
                except Exception: pass
        threading.Thread(target=bridge, args=(cli,), daemon=True).start()
    lsock.close()

threading.Thread(target=run_paced_bridge, daemon=True).start()

xfreerdp_seen = []
secret_leaks = []

def scan_proc():
    seen = set()
    while not stop_ev.is_set():
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                raw_cmd = open(f"/proc/{entry}/cmdline", "rb").read()
                argv = [x.decode("utf-8", "replace") for x in raw_cmd.split(b"\x00") if x]
                if not argv:
                    continue
                exe0 = os.path.basename(argv[0])
                if exe0 in ("xfreerdp3", "xfreerdp", "wlfreerdp", "mh", "secret-tool"):
                    raw_env = open(f"/proc/{entry}/environ", "rb").read()
                    key = (int(entry), tuple(argv))
                    if key not in seen:
                        seen.add(key)
                        c_hits = raw_cmd.count(secret_pw.encode("utf-8"))
                        e_hits = raw_env.count(secret_pw.encode("utf-8"))
                        if c_hits > 0 or e_hits > 0:
                            secret_leaks.append((exe0, c_hits, e_hits))
                        if exe0.startswith("xfreerdp") or exe0 == "wlfreerdp":
                            xfreerdp_seen.append(argv)
            except Exception:
                pass
        time.sleep(0.01)

scanner = threading.Thread(target=scan_proc, daemon=True)
scanner.start()

try:
    r1 = subprocess.run(
        [mh_bin, "rdp", f"alice@{dev_name}", "--domain", "CORP", "--port", str(rdp_port), "--cert-sha256", good_fp, "--save-credentials", "--use-saved-credentials", "--", "+auth-only"],
        input=secret_pw + "\n", capture_output=True, text=True, timeout=20,
    )
    assert r1.returncode == 0, f"step1 failed ({r1.returncode}): {r1.stderr}"

    r2 = subprocess.run(
        [mh_bin, "rdp", dev_name, "--port", str(rdp_port), "--cert-sha256", good_fp, "--use-saved-credentials", "--", "+auth-only"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
    )
    assert r2.returncode == 0, f"step2 failed ({r2.returncode}): {r2.stderr}"

    r3 = subprocess.run(
        [mh_bin, "rdp", dev_name, "--port", str(rdp_port), "--cert-sha256", bad_fp, "--use-saved-credentials", "--", "+auth-only"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
    )
    assert r3.returncode != 0, "step3 with wrong --cert-sha256 must fail"

    r4 = subprocess.run(
        [mh_bin, "rdp", dev_name, "--clear-credentials"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
    )
    assert r4.returncode == 0, f"step4 clear failed: {r4.stderr}"

    lookup = subprocess.run(
        ["secret-tool", "lookup", "service", "meshharbor-rdp", "org", org_id, "device", dev_id],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
    )
    assert lookup.stdout.strip() == "", f"secret-tool lookup after clear must be empty, got: {lookup.stdout!r}"
finally:
    stop_ev.set()
    scanner.join(timeout=1.0)
    xrdp_proc.terminate()

assert len(xfreerdp_seen) >= 2, f"expected to sample xfreerdp processes in /proc, got {xfreerdp_seen}"
assert len(secret_leaks) == 0, f"secret leaked in /proc cmdline or environ: {secret_leaks}"
"#;
    std::fs::write(&script_path, script).unwrap();

    let out = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns,
            "dbus-run-session",
            "--",
            "python3",
            script_path.to_str().unwrap(),
            mh_bin,
            tmpdir.to_str().unwrap(),
        ])
        .output()
        .expect("run isolated netns RDP E2E test");
    assert!(
        out.status.success(),
        "isolated netns RDP E2E failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(windows)]
#[test]
fn windows_credman_os_store_roundtrip_and_ephemeral_session_target_guard() {
    use meshharbor_cli::rdpcmd::{OsRdpCredentialStore, WindowsSessionTargetGuard};

    struct TestScopeDropGuard {
        scope: RdpCredentialScope,
    }
    impl Drop for TestScopeDropGuard {
        fn drop(&mut self) {
            let _ = OsRdpCredentialStore.delete(&self.scope);
        }
    }

    let store = OsRdpCredentialStore;
    let nonce = format!("test-{}", std::process::id());
    let scope = RdpCredentialScope {
        org_id: format!("org-{nonce}"),
        device_id: format!("dev-{nonce}"),
    };
    let _ = store.delete(&scope);
    let _scope_guard = TestScopeDropGuard {
        scope: scope.clone(),
    };

    let cred = StoredRdpCredential::new(
        "rdpuser",
        Some("WORKGROUP".to_string()),
        "Win32#CredMan!Secret42",
    );
    store
        .save(&scope, &cred)
        .expect("CredWriteW save must succeed");

    let loaded = store
        .load(&scope)
        .expect("CredReadW load must succeed")
        .expect("saved credential must exist");
    assert_eq!(loaded.username, "rdpuser");
    assert_eq!(loaded.domain.as_deref(), Some("WORKGROUP"));
    assert_eq!(loaded.password(), "Win32#CredMan!Secret42");

    // Shared TERMSRV/127.0.0.1 must be refused by WindowsSessionTargetGuard::install
    assert!(
        WindowsSessionTargetGuard::install("TERMSRV/127.0.0.1", &loaded).is_err(),
        "WindowsSessionTargetGuard must refuse shared TERMSRV/127.0.0.1"
    );

    // Verify per-session TERMSRV/127.77.x.y credential guard writes, refuses to overwrite
    // an existing credential at the same target without modifying or deleting it, and
    // auto-deletes on drop.
    let session_ip = allocate_session_loopback_ip();
    let session_target = format!("TERMSRV/{session_ip}");
    {
        let _guard = WindowsSessionTargetGuard::install(&session_target, &loaded)
            .expect("session target CredWriteW");
        assert!(
            WindowsSessionTargetGuard::exists(&session_target).expect("CredReadW check"),
            "ephemeral session target must exist while guard is alive"
        );

        // Attempting to install over an already-existing target must fail closed
        // and leave the existing credential unmodified and undeleted.
        let intruder = StoredRdpCredential::new(
            "otheruser",
            Some("OTHERDOM".to_string()),
            "ShouldNeverOverwrite!99",
        );
        let overwrite_err = WindowsSessionTargetGuard::install(&session_target, &intruder)
            .expect_err("install must refuse to overwrite an existing credential");
        assert!(
            overwrite_err.to_string().contains("overwrite")
                || overwrite_err.to_string().contains("existing"),
            "unexpected error: {overwrite_err}"
        );

        let intact = WindowsSessionTargetGuard::read(&session_target)
            .expect("CredReadW after refused overwrite")
            .expect("original session target must still exist after refused overwrite");
        assert_eq!(intact.username, "rdpuser");
        assert_eq!(intact.domain.as_deref(), Some("WORKGROUP"));
        assert_eq!(intact.password(), "Win32#CredMan!Secret42");
    }
    assert!(
        !WindowsSessionTargetGuard::exists(&session_target).expect("CredReadW post-drop check"),
        "ephemeral session target must be deleted by CredDeleteW when owning guard drops"
    );

    assert!(
        store
            .delete(&scope)
            .expect("CredDeleteW delete must succeed"),
        "CredDeleteW must report deleted=true"
    );
    assert!(
        store
            .load(&scope)
            .expect("CredReadW after delete")
            .is_none(),
        "credential must be gone after delete"
    );
}
