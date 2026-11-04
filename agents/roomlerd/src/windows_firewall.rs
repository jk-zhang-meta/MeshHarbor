//! Explicit installer firewall operations. No daemon, listener, enrollment, or
//! service is started; only the selected command may request administrator UI.
#![cfg(target_os = "windows")]
use anyhow::{Context, Result, bail};
use std::os::windows::process::CommandExt;

fn elevated(args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().context("locating the installed daemon")?;
    let literal = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let arguments = args
        .iter()
        .map(|s| literal(s))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -ArgumentList @({}) \
         -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
        literal(&exe.to_string_lossy()),
        arguments
    );
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x0800_0000)
        .status()
        .context("requesting administrator approval for firewall preparation/removal")?;
    if !status.success() {
        bail!("firewall operation was cancelled or failed ({status})")
    }
    Ok(())
}

pub fn prepare(public: bool, elevate: bool) -> Result<()> {
    if elevate {
        let mut args = vec!["service", "prepare-firewall"];
        if public {
            args.push("--allow-public")
        }
        elevated(&args)
    } else {
        tunnel_core::winfw::install::prepare(&std::env::current_exe()?, public)
    }
}

pub fn remove(elevate: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    if !tunnel_core::winfw::install::has_rules(&exe)? {
        return Ok(());
    }
    if elevate {
        elevated(&["service", "remove-firewall"])
    } else {
        tunnel_core::winfw::install::remove(&exe)
    }
}
