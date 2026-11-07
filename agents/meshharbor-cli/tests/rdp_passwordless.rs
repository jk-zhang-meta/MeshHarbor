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
    StoredRdpCredential, build_linux_secret_tool_store_plan, build_macos_security_store_plan,
    normalize_cert_sha256, parse_user_and_device, plan_rdp_session, validate_extra_client_args,
};

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
        rdp_cert_sha256: Some(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00".to_string(),
        ),
    }
}

fn loopback_addr() -> SocketAddr {
    "127.0.0.1:53389".parse().unwrap()
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
    assert!(opts.cert_sha256.is_none());
    assert!(
        !opts.save_credentials && !opts.use_saved_credentials,
        "passwordless credential storage/auto-fill must default to OFF"
    );
    assert!(!opts.clear_credentials);
    assert!(!opts.no_saved_credentials);
    assert!(opts.extra_args.is_empty());

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
    };

    let plan = plan_rdp_session(&opts, &dev, loopback_addr(), &store, None, None, "linux")
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
        plan.args.iter().any(|a| a == "/v:127.0.0.1:53389"),
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
        plan1.args.iter().any(|a| a == "/from-stdin"),
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
    };
    let plan2 = plan_rdp_session(
        &use_opts,
        &dev,
        loopback_addr(),
        &store,
        None, // NO password prompt on repeat use!
        None,
        "windows",
    )
    .unwrap()
    .expect("should return Windows mstsc invocation plan");
    assert_no_secret_in_invocation(&plan2, secret);
    assert_eq!(plan2.program, "mstsc.exe");
    assert_eq!(plan2.args, vec!["/v:127.0.0.1:53389".to_string()]);
    assert_eq!(
        plan2.windows_session_target.as_deref(),
        Some("TERMSRV/127.0.0.1")
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
        cert_sha256: None,
        save_credentials: false,
        use_saved_credentials: false,
        clear_credentials: false,
        no_saved_credentials: false,
        extra_args: vec![],
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

#[cfg(windows)]
#[test]
fn windows_credman_os_store_roundtrip_and_ephemeral_session_target_guard() {
    use meshharbor_cli::rdpcmd::{OsRdpCredentialStore, WindowsSessionTargetGuard};

    let store = OsRdpCredentialStore;
    let nonce = format!("test-{}", std::process::id());
    let scope = RdpCredentialScope {
        org_id: format!("org-{nonce}"),
        device_id: format!("dev-{nonce}"),
    };
    let _ = store.delete(&scope);

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

    // Verify ephemeral TERMSRV session credential guard writes and auto-deletes on drop
    let session_target = format!("TERMSRV/127.0.0.1:test-{nonce}");
    {
        let _guard = WindowsSessionTargetGuard::install(&session_target, &loaded)
            .expect("session target CredWriteW");
        assert!(
            WindowsSessionTargetGuard::exists(&session_target).expect("CredReadW check"),
            "ephemeral session target must exist while guard is alive"
        );
    }
    assert!(
        !WindowsSessionTargetGuard::exists(&session_target).expect("CredReadW post-drop check"),
        "ephemeral session target must be deleted by CredDeleteW when guard drops"
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
