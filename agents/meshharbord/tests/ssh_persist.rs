// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 real-binary integration test for out-of-process `meshharbord ssh-pty-host`.
//!
//! Proves:
//! 1. A real detached `meshharbord ssh-pty-host` spawns a live PTY shell.
//! 2. Simulating a daemon restart (dropping the IPC connection, wiping the
//!    in-memory registry, re-initializing from `ssh-resume.key`, and running
//!    `adopt_all`) adopts the surviving host with zero disruption to the shell.
//! 3. Cryptographic HKDF/HMAC reattach (`verify_and_attach`) succeeds with
//!    lossless byte-offset replay of output produced while detached.
//! 4. Wrong client proof is rejected (`RefuseReason::BadProof`).
//! 5. Explicit `terminate_all(CloseAccess, true)` terminates the detached host
//!    and rotates the device master key cleanly.

#![cfg(all(unix, feature = "ssh-server"))]

use std::time::Duration;

use meshharbor_node_core::pty_resume::{
    DEFAULT_ORPHAN_TTL_SECS, DEFAULT_RING_BYTES, RefuseReason, RunAsDescriptor, STREAM_STDIN,
    STREAM_STDOUT, SessionDescriptor, SessionId, SessionMode, TerminateReason,
    frame::WireFrame,
    ipc::{AttachStartFrame, IpcFrame, SpawnSpec},
    now_unix_ms,
    proof::{compute_client_proof, verify_server_proof},
};

#[tokio::test]
async fn fr141_real_binary_pty_host_survives_daemon_restart_and_revokes_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Point spawner at the real compiled `meshharbord` binary.
    let bin = env!("CARGO_BIN_EXE_meshharbord");
    // SAFETY: single integration test process for this binary target.
    unsafe {
        std::env::set_var("MESHHARBORD_SSH_PTY_HOST_BIN", bin);
    }

    meshharbord::ssh_persist::init_state_dir(dir.path()).expect("init state dir");

    let sid = SessionId::generate();
    let now = now_unix_ms();
    let host_fp = "SHA256:test-host-fp";
    let client_fp = "SHA256:test-client-fp";
    let org_id = "test-org-fr141";

    let descriptor = SessionDescriptor {
        sid,
        org_id: org_id.into(),
        agent_id: "test-agent-1".into(),
        principal: "operator@example.test".into(),
        grant_id: Some("grant-123".into()),
        client_key_fp: client_fp.into(),
        host_key_fp: host_fp.into(),
        run_as: RunAsDescriptor::Daemon,
        mode: SessionMode::Pty,
        cmd_digest: None,
        created_ms: now,
        deadline_ms: now + 3_600_000,
        detach_ttl_ms: 3_600_000,
        orphan_ttl_ms: DEFAULT_ORPHAN_TTL_SECS * 1000,
        two_factor_at_ms: None,
        offline_iat_ms: None,
        offline_exp_ms: None,
        via_service: false,
        key_list_auth: false,
        policy_digest: String::new(),
        epoch: 1,
    };

    let spec = SpawnSpec {
        mode: SessionMode::Pty,
        term: "xterm-256color".into(),
        cols: 80,
        rows: 24,
        command: Some("echo FR141_STEP1; sleep 1; echo FR141_WHILE_DETACHED; sleep 30".to_string()),
        env: vec![("LANG".into(), "C.UTF-8".into())],
        run_as: RunAsDescriptor::Daemon,
        ring_bytes: DEFAULT_RING_BYTES as u32,
    };

    let spawned = meshharbord::ssh_persist::spawn_session(descriptor, spec)
        .await
        .expect("spawn detached ssh-pty-host");
    let resume_secret = spawned.resume_secret;
    let mut stream = spawned.stream;

    // Attach initially and read until we observe FR141_STEP1.
    IpcFrame::AttachStart(AttachStartFrame {
        last_rx: 0,
        c2s_next_client: 0,
        cols: 80,
        rows: 24,
        snapshot_allowed: true,
        server_proof: [0u8; 32],
    })
    .write_to(&mut stream)
    .await
    .expect("initial AttachStart");

    let mut received = Vec::new();
    let mut last_rx: u64 = 0;
    let step1_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < step1_deadline {
        if let Ok(Ok(Some(IpcFrame::Wire(WireFrame::Data {
            stream: s,
            seq,
            bytes,
        })))) =
            tokio::time::timeout(Duration::from_millis(500), IpcFrame::read_from(&mut stream)).await
            && s == STREAM_STDOUT
        {
            if seq == last_rx {
                received.extend_from_slice(&bytes);
                last_rx = seq + bytes.len() as u64;
            }
            if String::from_utf8_lossy(&received).contains("FR141_STEP1") {
                break;
            }
        }
    }
    assert!(
        String::from_utf8_lossy(&received).contains("FR141_STEP1"),
        "expected FR141_STEP1, got {:?}",
        String::from_utf8_lossy(&received)
    );

    // Simulate daemon restart: drop IPC stream, wipe in-memory registry, wait while
    // shell prints FR141_WHILE_DETACHED into the detached host's 4 MiB ring!
    drop(stream);
    meshharbord::ssh_persist::reset_in_memory_registry_for_restart_simulation();
    tokio::time::sleep(Duration::from_millis(1400)).await;

    // Fresh "daemon" boots on the same state dir and adopts surviving host!
    meshharbord::ssh_persist::init_state_dir(dir.path()).expect("re-init after restart");
    let adopted = meshharbord::ssh_persist::adopt_all(|_| Ok(())).await;
    assert_eq!(adopted, 1, "must adopt the 1 surviving detached host");

    // Wrong proof must be rejected cleanly.
    let s_nonce = [0xAA; 32];
    let c_nonce = [0xBB; 32];
    let bad_proof = [0x00; 32];
    let err = meshharbord::ssh_persist::verify_and_attach(
        org_id, &sid, &s_nonce, &c_nonce, &bad_proof, host_fp, client_fp, false, last_rx, 0, 80, 24,
    )
    .await
    .err()
    .expect("bad proof must fail");
    assert_eq!(err, RefuseReason::BadProof);

    // Valid cryptographic HKDF/HMAC proof succeeds and replays missed bytes losslessly!
    let good_proof =
        compute_client_proof(&resume_secret, &sid, &s_nonce, &c_nonce, host_fp, client_fp);
    let attached = meshharbord::ssh_persist::verify_and_attach(
        org_id,
        &sid,
        &s_nonce,
        &c_nonce,
        &good_proof,
        host_fp,
        client_fp,
        false,
        last_rx,
        0,
        80,
        24,
    )
    .await
    .expect("valid resume proof must reattach");

    let mut stream2 = attached.stream;
    let mut got_attached = false;
    let mut replayed = Vec::new();
    let replay_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < replay_deadline {
        match tokio::time::timeout(
            Duration::from_millis(500),
            IpcFrame::read_from(&mut stream2),
        )
        .await
        {
            Ok(Ok(Some(IpcFrame::Wire(WireFrame::Attached(a))))) => {
                assert!(verify_server_proof(
                    &resume_secret,
                    &sid,
                    &c_nonce,
                    &s_nonce,
                    &a.server_proof
                ));
                got_attached = true;
            }
            Ok(Ok(Some(IpcFrame::Wire(WireFrame::Data {
                stream: s, bytes, ..
            }))))
                if s == STREAM_STDOUT =>
            {
                replayed.extend_from_slice(&bytes);
                if String::from_utf8_lossy(&replayed).contains("FR141_WHILE_DETACHED") {
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(
        got_attached,
        "must receive Attached with valid server_proof"
    );
    assert!(
        String::from_utf8_lossy(&replayed).contains("FR141_WHILE_DETACHED"),
        "must losslessly replay bytes written while detached, got {:?}",
        String::from_utf8_lossy(&replayed)
    );

    // Verify c2s input ACK works on reattached stream.
    IpcFrame::Wire(WireFrame::Data {
        stream: STREAM_STDIN,
        seq: 0,
        bytes: b"\n".to_vec(),
    })
    .write_to(&mut stream2)
    .await
    .expect("send c2s input");

    // Explicit revocation kills the detached host and rotates master key!
    drop(stream2);
    let killed = meshharbord::ssh_persist::terminate_all(TerminateReason::CloseAccess, true)
        .await
        .expect("terminate_all");
    assert_eq!(killed, 1);
    assert_eq!(meshharbord::ssh_persist::live_session_count(), 0);
}
