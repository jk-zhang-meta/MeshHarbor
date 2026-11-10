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

    let prompt_pw = if opts.save_credentials {
        let user_for_prompt = opts.user.as_deref().or(parsed_user.as_deref()).context(
            "--save-credentials requires an RDP username (`--user <u>` or `<user>@<device>`)",
        )?;
        Some(read_password_from_stdin_or_tty(
            user_for_prompt,
            &device.device_name,
        )?)
    } else {
        None
    };

    // Bind a per-session local loopback listener in 127.77.x.y:0 (never shared
    // 127.0.0.1) and bridge each accepted TCP stream to the target device's RDP
    // port (via overlay SOCKS5 in netstack mode, or direct overlay TCP in OS-TUN mode).
    let listener = bind_unique_session_loopback_listener().await?;
    let local_addr = listener.local_addr()?;

    let plan = plan_rdp_session(
        &opts,
        &device,
        local_addr,
        &store,
        prompt_pw.as_deref(),
        kill_env.as_deref(),
        std::env::consts::OS,
    )?
    .context("internal error: expected an RDP invocation plan")?;

    let scope = RdpCredentialScope {
        org_id: device.org_id.clone(),
        device_id: device.device_id.clone(),
    };
    let _win_guard = if let Some(target) = &plan.windows_session_target {
        let cred = store
            .load(&scope)?
            .context("missing stored credential for Windows session target")?;
        Some(WindowsSessionTargetGuard::install(target, &cred)?)
    } else {
        None
    };

    let pump_task = spawn_rdp_loopback_tunnel(listener, dial_ip, opts.port, socks_port);
    let mut child = spawn_planned_rdp_client(&plan)?;
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("RDP client wait task panicked")?
        .context("failed waiting for native RDP client")?;
    pump_task.abort();
    Ok(status.code().unwrap_or(1))
}
