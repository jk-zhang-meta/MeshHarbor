// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-8-2b-2 — `ssh_run`: a session's one command on another device of
//! its organization over Roomler SSH (the FR-90 spec's §3e "P3-8, `ssh_run`,
//! as designed").
//!
//! Each call:
//! 1. checks its arguments, so a call this tool would refuse asks the vault
//!    nothing ([`parse`]);
//! 2. asks the vault for a ticket (`rc:vault.ssh`, P3-8-1a), decided by
//!    Cedar's `ssh:run` for the account the target maps, and long enough for
//!    the server's answer, the target's prompt and the command
//!    ([`ticket_secs`]);
//! 3. hands it to this daemon's own SSH client ([`crate::ssh_client::run`],
//!    P3-8-2b-1), which presents it with a key minted for the call, checks
//!    the echo and the target's host key, and runs the one `exec`;
//! 4. answers what ran: the target's os, the account, the exit code and both
//!    streams.
//!
//! ⚠️ The ticket never reaches the session. The answer names it by its id,
//! the join key to `ssh_audit`, and the key is the client's alone.
//!
//! ⚠️ A person approves the call before the vault is asked (the settings
//! ask for it, [`super::toolbelt::SSH_TOOLS`]), so the approval names the
//! device and the command, not the account: a ticket ends within 900 s, and
//! an approval may wait 25 minutes. The account comes back in the answer.

use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use serde_json::{Value, json};
use tracing::info;

use super::toolbelt::VaultTools;
pub(crate) use crate::ssh_client::Ran;
use crate::ssh_client::{ASK_WAIT, MAX_TIMEOUT_SECS, OverlayDialer, PROMPT_SECS};
use crate::vault::{SshAsk, SshTicket};

/// The tool, by the name a session calls it.
pub(crate) const RUN: &str = "ssh_run";

/// How long the command may run when the call names no `timeout_s`.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// How this daemon runs the command once the vault has given its ticket: its
/// own SSH client ([`DaemonSsh`]); a test's stands in for it.
#[async_trait::async_trait]
pub(crate) trait SshRunner: Send + Sync {
    /// Run `command` on `target` under `ticket`, within `timeout` and the
    /// target's prompt: what it ran to, or why not, in words.
    async fn run(
        &self,
        target: ObjectId,
        ticket: &SshTicket,
        command: &str,
        timeout: Duration,
    ) -> Result<Ran, String>;
}

/// The daemon's runner: the request on the primary connection, which the
/// vault answered on, and the dial through this daemon's own overlay.
pub(crate) struct DaemonSsh {
    dialer: Arc<dyn OverlayDialer>,
}

impl DaemonSsh {
    pub(crate) fn new(cfg: &crate::config::AgentConfig) -> Self {
        Self {
            dialer: crate::ssh_client::dialer_for(cfg),
        }
    }
}

#[async_trait::async_trait]
impl SshRunner for DaemonSsh {
    async fn run(
        &self,
        target: ObjectId,
        ticket: &SshTicket,
        command: &str,
        timeout: Duration,
    ) -> Result<Ran, String> {
        // The ticket names this device as its origin, and the network module
        // holds the request to the connection it arrives on.
        let sink = crate::vault::CLIENT
            .outbound()
            .ok_or("this device is not connected to its server")?;
        crate::ssh_client::run(
            &sink,
            self.dialer.as_ref(),
            target,
            &ticket.ticket,
            &ticket.ticket_id,
            command,
            timeout,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// One call's arguments, checked.
#[derive(Debug, PartialEq, Eq)]
struct Ask {
    target: ObjectId,
    command: String,
    timeout: Duration,
}

/// Parse a call's arguments. A call this tool would refuse is refused here,
/// before the vault is asked anything.
fn parse(args: &Value) -> Result<Ask, String> {
    let device = args
        .get("device")
        .and_then(Value::as_str)
        .ok_or("device is required: the id of the device to run on")?;
    let target = ObjectId::parse_str(device.trim())
        .map_err(|_| format!("device {device:?} is not a device id"))?;
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .ok_or("command is required: one line for that device's shell")?;
    crate::ssh_client::check_command(command).map_err(|e| e.to_string())?;
    let secs = match args.get("timeout_s") {
        None | Some(Value::Null) => DEFAULT_TIMEOUT_SECS,
        Some(v) => v
            .as_u64()
            .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s))
            .ok_or_else(|| {
                format!("timeout_s is a whole number of seconds, 1 to {MAX_TIMEOUT_SECS}")
            })?,
    };
    Ok(Ask {
        target,
        command: command.to_string(),
        timeout: Duration::from_secs(secs),
    })
}

/// The ticket's life, as asked of the vault: the server's answer, the
/// target's prompt and the command's own time. The network module ends the
/// SSH session with what is left of the ticket, so a ticket asked for less
/// would cut the command short. The vault holds it to its own bounds (at
/// most 900 s), which the longest call stays within.
fn ticket_secs(timeout: Duration) -> u32 {
    let secs = ASK_WAIT.as_secs() + PROMPT_SECS + timeout.as_secs();
    u32::try_from(secs).unwrap_or(u32::MAX)
}

/// One `ssh_run` call for the session's run: the vault's ticket, then the one
/// command under it. Its answer, or why not.
pub(crate) async fn call(
    vault: &dyn VaultTools,
    runner: &dyn SshRunner,
    session: ObjectId,
    fence: u64,
    args: &Value,
) -> Result<Value, String> {
    let ask = parse(args)?;
    let ticket = vault
        .ssh(SshAsk {
            session_id: session,
            fence,
            target: ask.target,
            ttl_secs: ticket_secs(ask.timeout),
        })
        .await?;
    // Never the command: what a session runs is its own, as a terminal's
    // content is (docs/roomler-ssh.md).
    let ran = runner
        .run(ask.target, &ticket, &ask.command, ask.timeout)
        .await;
    info!(
        %session,
        target = %ask.target,
        ticket = %ticket.ticket_id,
        account = %ticket.account,
        exit_code = ?ran.as_ref().ok().map(|r| r.exit_code),
        "hive: ssh_run"
    );
    let ran = ran?;
    Ok(json!({
        "device": ask.target.to_hex(),
        "os": ticket.os,
        "account": ticket.account,
        "ticket_id": ticket.ticket_id,
        "exit_code": ran.exit_code,
        "stdout": ran.stdout,
        "stderr": ran.stderr,
        "truncated": ran.truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call is checked whole before anything is asked: the device an id,
    /// the command one line within its bound, the timeout within the tool's.
    #[test]
    fn a_call_is_checked_before_anything_is_asked() {
        let device = ObjectId::new();
        let ok = parse(&json!({"device": format!(" {} ", device.to_hex()), "command": "uptime"}))
            .unwrap();
        assert_eq!(
            ok,
            Ask {
                target: device,
                command: "uptime".into(),
                timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            }
        );
        let timed = json!({"device": device.to_hex(), "command": "uptime", "timeout_s": 300});
        assert_eq!(parse(&timed).unwrap().timeout, Duration::from_secs(300));
        let refused = [
            (json!({"command": "uptime"}), "device is required"),
            (
                json!({"device": "nas", "command": "uptime"}),
                "is not a device id",
            ),
            (json!({"device": device.to_hex()}), "command is required"),
            (
                json!({"device": device.to_hex(), "command": "uptime\nreboot"}),
                "not one this tool runs",
            ),
            (
                json!({"device": device.to_hex(), "command": "x".repeat(crate::ssh_client::MAX_COMMAND + 1)}),
                "not one this tool runs",
            ),
        ];
        for (args, why) in refused {
            let e = parse(&args).unwrap_err();
            assert!(e.contains(why), "{args}: {e}");
        }
        for t in [json!(0), json!(301), json!("60"), json!(-1), json!(1.5)] {
            let args = json!({"device": device.to_hex(), "command": "uptime", "timeout_s": t});
            let e = parse(&args).unwrap_err();
            assert!(e.contains("1 to 300"), "{t}: {e}");
        }
    }

    /// The ticket outlives everything the call waits for: the server's
    /// answer, the prompt and the command, so the session the network module
    /// bounds by it is never shorter than the one the client asks for. And
    /// the longest call stays within the vault's 900 s.
    #[test]
    fn the_ticket_outlives_the_answer_the_prompt_and_the_command() {
        for secs in [1, DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS] {
            let t = Duration::from_secs(secs);
            let ticket = u64::from(ticket_secs(t));
            assert_eq!(ticket, ASK_WAIT.as_secs() + PROMPT_SECS + secs);
            assert!(
                ticket > secs + PROMPT_SECS,
                "the session the client asks for"
            );
        }
        assert!(ticket_secs(Duration::from_secs(MAX_TIMEOUT_SECS)) <= 900);
    }
}
