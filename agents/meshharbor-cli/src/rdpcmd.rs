// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! X17 — `mh rdp` CLI entrypoint wrapping [`meshharbor_node_core::rdp_client`].
//!
//! All core session planning, `127.77.x.y:0` per-session loopback tunneling,
//! LocalAPI peer/tenant scope resolution, and OS secure credential-store
//! primitives live in [`meshharbor_node_core::rdp_client`] so `mh rdp` and
//! `meshharbor-desktop` share one implementation without pulling transport
//! crates into the desktop companion (RC/RDP Phase A).

use std::io::{IsTerminal, Read};
use std::net::SocketAddr;

use anyhow::{Context, Result, bail};

pub use meshharbor_node_core::rdp_client::*;

fn read_password_from_stdin_or_tty(user: &str, device_name: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        let prompt = format!("RDP password for {user}@{device_name} (saved locally): ");
        let pw = rpassword::prompt_password(prompt)
            .context("failed reading RDP password from terminal")?;
        if pw.is_empty() {
            bail!("RDP password must not be empty");
        }
        Ok(pw)
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed reading RDP password from stdin")?;
        let trimmed = buf.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            bail!("RDP password on stdin must not be empty");
        }
        Ok(trimmed)
    }
}

/// Top-level `mh rdp` execution entrypoint.
pub async fn run(opts: RdpCliOptions) -> Result<i32> {
    validate_extra_client_args(&opts.extra_args)?;
    if opts.check && (opts.save_credentials || opts.use_saved_credentials || opts.clear_credentials)
    {
        bail!(
            "--check is a read-only diagnostic command and cannot be combined with --save-credentials, --use-saved-credentials, or --clear-credentials"
        );
    }
    if opts.explicit_port == Some(0) || (!opts.clear_credentials && opts.port == 0) {
        bail!("remote RDP port must be between 1 and 65535");
    }

    let (parsed_user, target_host) = parse_user_and_device(&opts.target)?;
    let (device, dial_ip, socks_port) = resolve_target_device(&target_host).await?;
    let store = OsRdpCredentialStore;
    let kill_env = std::env::var(KILL_SWITCH_ENV).ok();

    if opts.clear_credentials {
        let placeholder =
            SocketAddr::new(std::net::IpAddr::V4(allocate_session_loopback_ip()), 3389);
        let _ = plan_rdp_session(
            &opts,
            &device,
            placeholder,
            &store,
            None,
            kill_env.as_deref(),
            std::env::consts::OS,
        )?;
        return Ok(0);
    }

    if is_kill_switch_enabled(opts.no_saved_credentials, kill_env.as_deref())
        && (opts.save_credentials || opts.use_saved_credentials)
    {
        bail!(
            "saved RDP credentials are disabled by kill switch (--no-saved-credentials or {}=1)",
            KILL_SWITCH_ENV
        );
    }

    let save_user = if opts.save_credentials {
        Some(
            opts.user
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .or(parsed_user.as_deref())
                .context(
                    "--save-credentials requires an RDP username (`--user <u>` or `<user>@<device>`)",
                )?
                .to_string(),
        )
    } else {
        None
    };

    let remote_port = effective_rdp_port(&opts, &device);
    let pinned_cert = effective_pinned_cert_sha256(&opts, &device)?;

    // Bind a per-session local loopback listener in 127.77.x.y:0 (never shared
    // 127.0.0.1) and bridge each accepted TCP stream to the target device's RDP
    // port (via overlay SOCKS5 in netstack mode, or direct overlay TCP in OS-TUN mode).
    let listener = bind_unique_session_loopback_listener().await?;
    let local_addr = listener.local_addr()?;
    let (pump_task, probe) =
        spawn_rdp_loopback_tunnel_with_probe(listener, dial_ip, remote_port, socks_port);

    if opts.check {
        let outcome_res = precheck_rdp_tunnel_tls(
            local_addr,
            &probe,
            &device.device_name,
            remote_port,
            pinned_cert.as_deref(),
        )
        .await;
        // A second connection on the SAME loopback listener, the way the RDP
        // client's own connection follows the pre-check in a real session.
        let second_res = match &outcome_res {
            Ok(_) => Some(
                precheck_rdp_tunnel_reachability(
                    local_addr,
                    &probe,
                    &device.device_name,
                    remote_port,
                )
                .await,
            ),
            Err(_) => None,
        };
        pump_task.abort();
        let outcome = outcome_res?;
        if let Some(second) = second_res {
            second?;
        }
        if pinned_cert.is_none() {
            eprintln!("{UNPINNED_CERT_MSTSC_NOTICE}");
        }
        println!(
            "RDP 预检通过：device={} ({}) port={} selected_protocol={:#x} cert_sha256={} pinned_verified={} second_connection=ok",
            device.device_name,
            device.device_id,
            remote_port,
            outcome.selected_protocol,
            outcome.leaf_cert_sha256.as_deref().unwrap_or("none"),
            outcome.pinned_verified,
        );
        return Ok(0);
    }

    // Pre-check runs BEFORE reading/writing credentials or spawning any client
    // (`V0028` + `V0029 §3.1`), failing closed within 5 seconds.
    if let Some(expected_fp) = pinned_cert.as_deref() {
        if let Err(err) = precheck_rdp_tunnel_tls(
            local_addr,
            &probe,
            &device.device_name,
            remote_port,
            Some(expected_fp),
        )
        .await
        {
            pump_task.abort();
            return Err(err.into());
        }
    } else {
        if let Err(err) =
            precheck_rdp_tunnel_reachability(local_addr, &probe, &device.device_name, remote_port)
                .await
        {
            pump_task.abort();
            return Err(err.into());
        }
        eprintln!("{UNPINNED_CERT_MSTSC_NOTICE}");
    }

    let prompt_pw = match save_user.as_deref() {
        Some(user_for_prompt) => {
            match read_password_from_stdin_or_tty(user_for_prompt, &device.device_name) {
                Ok(pw) => Some(pw),
                Err(e) => {
                    pump_task.abort();
                    return Err(e);
                }
            }
        }
        None => None,
    };

    let plan = match plan_rdp_session(
        &opts,
        &device,
        local_addr,
        &store,
        prompt_pw.as_deref(),
        kill_env.as_deref(),
        std::env::consts::OS,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            pump_task.abort();
            bail!("internal error: expected an RDP invocation plan");
        }
        Err(e) => {
            pump_task.abort();
            return Err(e);
        }
    };

    let scope = RdpCredentialScope {
        org_id: device.org_id.clone(),
        device_id: device.device_id.clone(),
    };
    let _win_guard = if let Some(target) = &plan.windows_session_target {
        let cred = match store
            .load(&scope)
            .and_then(|c| c.context("missing stored credential for Windows session target"))
        {
            Ok(c) => c,
            Err(e) => {
                pump_task.abort();
                return Err(e);
            }
        };
        match WindowsSessionTargetGuard::install(target, &cred) {
            Ok(g) => Some(g),
            Err(e) => {
                pump_task.abort();
                return Err(e);
            }
        }
    } else {
        None
    };

    let mut child = match spawn_planned_rdp_client(&plan) {
        Ok(c) => c,
        Err(e) => {
            pump_task.abort();
            return Err(e);
        }
    };
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("RDP client wait task panicked")?
        .context("failed waiting for native RDP client")?;
    pump_task.abort();
    Ok(status.code().unwrap_or(1))
}
