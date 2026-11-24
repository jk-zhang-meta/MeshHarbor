// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Live companion liveness reporting (`CompanionHello` / `CompanionBye`) over
//! the daemon's LocalAPI.
//!
//! Sends this running companion's `CARGO_PKG_VERSION` and PID immediately at
//! startup and refreshes every 30 s so the daemon reports the LIVE connected
//! companion version in server heartbeats and `NodeStatus` instead of reading
//! a file on disk. Older daemons that predate the verb are tolerated silently.

use std::time::Duration;

const HELLO_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);
const BYE_TIMEOUT: Duration = Duration::from_millis(400);

/// Background loop spawned from Tauri `.setup()`: announces this companion
/// immediately and refreshes every 30 s (retrying every 5 s while the daemon
/// is starting or restarting).
pub async fn run_loop() {
    let version = env!("CARGO_PKG_VERSION");
    let pid = std::process::id();
    loop {
        let delay = match send_hello_once(version, pid).await {
            HelloOutcome::Sent | HelloOutcome::Unsupported => HELLO_INTERVAL,
            HelloOutcome::Disconnected => RETRY_INTERVAL,
        };
        tokio::time::sleep(delay).await;
    }
}

enum HelloOutcome {
    Sent,
    Unsupported,
    Disconnected,
}

async fn send_hello_once(version: &str, pid: u32) -> HelloOutcome {
    let exchange = async {
        let mut client = meshharbor_localapi::connect().await?;
        client.companion_hello(version, Some(pid)).await
    };
    match tokio::time::timeout(RPC_TIMEOUT, exchange).await {
        Ok(Ok(_)) => HelloOutcome::Sent,
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("unknown variant") || msg.contains("bad request") {
                tracing::debug!(error = %msg, "daemon predates companion_hello; ignoring");
                HelloOutcome::Unsupported
            } else {
                tracing::debug!(error = %msg, "companion_hello deferred (daemon unavailable)");
                HelloOutcome::Disconnected
            }
        }
        Err(_) => {
            tracing::debug!("companion_hello timed out");
            HelloOutcome::Disconnected
        }
    }
}

/// Best-effort `CompanionBye` notification before clean process exit.
pub async fn send_bye_best_effort() {
    let pid = std::process::id();
    let exchange = async {
        let mut client = meshharbor_localapi::connect().await?;
        client.companion_bye(Some(pid)).await
    };
    let _ = tokio::time::timeout(BYE_TIMEOUT, exchange).await;
}

/// Clear our `companion-instance.json` record, send a best-effort
/// `CompanionBye` with a short timeout, and exit the Tauri app cleanly.
pub fn notify_bye_and_exit<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    crate::singleton::clear_own_instance_record();
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        send_bye_best_effort().await;
        handle.exit(0);
    });
}
