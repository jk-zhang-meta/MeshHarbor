// SPDX-License-Identifier: MPL-2.0
//! Internal local-bundle adapter for the existing native Unix installer.
//! No new UI role is exposed until reviewed platform artifacts and elevation
//! are available. No latest/download fallback, alternate startup framework,
//! fabricated OS success, or host effects from preparing an invocation.
use std::io::Write;
use std::process::{Command, Stdio};

const INSTALLER: &str = include_str!("../../../scripts/install.sh");

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform { Linux, MacOs }

/// Digests come from the reviewed/bundled release manifest, not a download's
/// self-assertion. The installer snapshots and verifies BOTH files before sudo.
/// This type deliberately has no Debug/Serialize: inputs include live tokens.
pub(crate) struct LocalInstall {
    pub platform: Platform,
    pub package_path: String,
    pub package_sha256: String,
    pub cli_path: String,
    pub cli_sha256: String,
    pub server: String,
    pub device_name: String,
    pub enrollment_token: String,
    /// macOS requires a distinct identity for its privileged network backend;
    /// the per-user LaunchAgent remains the screen/input owner.
    pub backend_enrollment_token: Option<String>,
}

/// Kept out of argv/environment/files; written literally to an anonymous pipe.
pub(crate) struct Credentials<'a> { agent: &'a str, backend: Option<&'a str> }
impl Credentials<'_> {
    fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        writeln!(out, "{}", self.agent)?;
        writeln!(out, "{}", self.backend.unwrap_or(""))
    }
}
pub(crate) trait Runner {
    fn execute(&mut self, platform: Platform, script: &str, args: &[String], credentials: Credentials<'_>) -> Result<(), String>;
}
fn native_command(script: &str, args: &[String]) -> Command {
    let mut command = Command::new("/bin/sh");
    // Only trusted compile-time source is passed to -c. No input is inserted
    // into shell code; credentials travel on a separate anonymous stdin pipe.
    command.env_remove("TOKEN").env_remove("DAEMON_TOKEN")
        .args(["-c", script, "roomler-local-install"]).args(args)
        .stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    command
}

pub(crate) struct NativeRunner;
impl Runner for NativeRunner {
    fn execute(&mut self, platform: Platform, script: &str, args: &[String], credentials: Credentials<'_>) -> Result<(), String> {
        if !matches!((std::env::consts::OS, platform), ("linux", Platform::Linux) | ("macos", Platform::MacOs)) {
            return Err("local bundle does not match this Unix platform".into());
        }
        // Existing install.sh owns sudo, console-user selection, enrollment and
        // systemd/launchd. No shell interpolation or privilege-prompt workaround.
        let mut child = native_command(script, args).spawn()
            .map_err(|_| "cannot launch native Unix installer".to_string())?;
        let written = child.stdin.take().ok_or("installer stdin unavailable")
            .and_then(|mut pipe| credentials.write_to(&mut pipe).map_err(|_| "credential pipe unavailable"));
        // Taking/dropping the pipe closes it before wait; never export, persist
        // or print credentials. A failed transfer cannot leave a live wrapper.
        if written.is_err() { let _ = child.kill(); let _ = child.wait(); return Err("cannot provide installer credentials".into()); }
        let status = match child.wait() {
            Ok(status) => status,
            Err(_) => { let _ = child.kill(); let _ = child.wait(); return Err("cannot observe native installer exit".into()); }
        };
        if status.success() { Ok(()) } else { Err("native Unix local install did not complete".into()) }
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str) -> bool { !value.is_empty() && !value.chars().any(char::is_control) }

pub(crate) fn run_with(input: &LocalInstall, runner: &mut impl Runner) -> Result<(), String> {
    let suffix = match input.platform { Platform::Linux => ".deb", Platform::MacOs => ".pkg" };
    if !input.package_path.starts_with('/') || !input.package_path.ends_with(suffix)
        || !input.cli_path.starts_with('/') || !digest(&input.package_sha256) || !digest(&input.cli_sha256)
        || !text(&input.package_path) || !text(&input.cli_path) || !text(&input.device_name)
        || !text(&input.enrollment_token) {
        return Err("reviewed local daemon package, CLI, SHA256 values and enrollment are required".into());
    }
    let server = if input.server.is_empty() { crate::proxy::DEFAULT_SERVER } else { &input.server };
    if !text(server) { return Err("invalid enrollment center".into()); }
    let secured = roomler_ai_remote_control::server_url::secure(server, false).url;
    let parsed = reqwest::Url::parse(&secured).map_err(|_| "invalid enrollment center")?;
    if parsed.host_str().is_none() || !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty() || parsed.password().is_some()
        || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("center must be an HTTP(S) origin with optional deployment prefix".into());
    }
    let mut args = vec!["--role".into(), "daemon".into(), "--server".into(),
        secured.trim_end_matches('/').into(), "--name".into(), input.device_name.clone(),
        "--credentials-stdin".into(), "--no-desktop".into(),
        "--local-package".into(), input.package_path.clone(), "--local-package-sha256".into(), input.package_sha256.clone(),
        "--local-cli".into(), input.cli_path.clone(), "--local-cli-sha256".into(), input.cli_sha256.clone()];
    match input.platform {
        Platform::Linux => {
            if input.backend_enrollment_token.is_some() { return Err("Linux system backend uses one enrollment identity".into()); }
            args.push("--system".into());
        }
        Platform::MacOs => {
            let token = input.backend_enrollment_token.as_ref().filter(|t| text(t) && **t != input.enrollment_token)
                .ok_or("macOS full network setup requires a distinct backend enrollment token")?;
            let _ = token; // validated here; sent through the protected pipe below
        }
    }
    runner.execute(input.platform, INSTALLER, &args, Credentials { agent: &input.enrollment_token, backend: input.backend_enrollment_token.as_deref() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Capture { calls: usize, args: Vec<String>, fail: bool }
    impl Runner for Capture {
        fn execute(&mut self, _: Platform, script: &str, args: &[String], credentials: Credentials<'_>) -> Result<(), String> {
            self.calls += 1; self.args = args.to_vec();
            let mut pipe = Vec::new(); credentials.write_to(&mut pipe).unwrap();
            assert!(!pipe.is_empty());
            let command = native_command(script, args);
            let actual: Vec<_> = command.get_args().map(|v| v.to_string_lossy()).collect();
            assert!(!actual.iter().any(|v| v.contains("SYNTHETIC_AGENT") || v.contains("SYNTHETIC_BACKEND")));
            assert!(!args.iter().any(|v| v == "--token" || v == "--daemon-token"));
            assert!(script.contains("prepare_local_artifacts"));
            if self.fail { Err("fixture native failure".into()) } else { Ok(()) }
        }
    }
    fn fixture(platform: Platform) -> LocalInstall {
        LocalInstall { platform, package_path: match platform { Platform::Linux => "/reviewed/daemon.deb", Platform::MacOs => "/reviewed/daemon.pkg" }.into(),
            package_sha256: "a".repeat(64), cli_path: "/reviewed/roomler".into(), cli_sha256: "b".repeat(64),
            server: "https://center.example/private/prefix/".into(), device_name: "fixture name; literal".into(),
            enrollment_token: "SYNTHETIC_AGENT".into(), backend_enrollment_token: (platform == Platform::MacOs).then(|| "SYNTHETIC_BACKEND".into()) }
    }
    #[test]
    fn linux_system_uses_existing_local_script_and_keeps_center_prefix_literal() {
        let mut r = Capture::default(); run_with(&fixture(Platform::Linux), &mut r).unwrap();
        assert_eq!(r.calls, 1); assert!(r.args.contains(&"--system".into()));
        assert!(r.args.contains(&"https://center.example/private/prefix".into()));
        assert!(r.args.contains(&"fixture name; literal".into()));
        assert!(!r.args.contains(&"--daemon-token".into()));
    }
    #[test]
    fn macos_full_network_keeps_two_identities_and_existing_launchd_script() {
        let mut r = Capture::default(); run_with(&fixture(Platform::MacOs), &mut r).unwrap();
        assert!(r.args.contains(&"--credentials-stdin".into()));
        assert!(!r.args.contains(&"--system".into()));
    }
    #[test]
    fn invalid_bundle_or_reused_macos_identity_never_reaches_runner() {
        let mut r = Capture::default();
        let mut x = fixture(Platform::Linux); x.cli_sha256.clear(); assert!(run_with(&x, &mut r).is_err());
        let mut x = fixture(Platform::MacOs); x.backend_enrollment_token = Some(x.enrollment_token.clone()); assert!(run_with(&x, &mut r).is_err());
        let mut x = fixture(Platform::Linux); x.package_path = "daemon.deb".into(); assert!(run_with(&x, &mut r).is_err());
        assert_eq!(r.calls, 0);
    }
    #[test]
    fn center_auth_controls_and_query_are_rejected_without_effects() {
        for server in ["https://user:secret@center.example", "https://center.example?x=1", "https://center.example\n/private"] {
            let mut x = fixture(Platform::Linux); x.server=server.into();
            let mut r=Capture::default(); assert!(run_with(&x,&mut r).is_err()); assert_eq!(r.calls,0);
        }
    }
    #[test]
    fn empty_center_uses_meshharbor_default_and_native_failure_is_not_success() {
        let mut x=fixture(Platform::Linux); x.server.clear();
        let mut r=Capture { fail:true,..Default::default() };
        assert!(run_with(&x,&mut r).is_err());
        assert!(r.args.contains(&"https://www.itachi.fans/meshharbor".into()));
    }
    #[test]
    fn actual_native_spawn_uses_pipe_not_argv_and_reaps_failure() {
        #[cfg(target_os="linux")] let platform=Platform::Linux;
        #[cfg(target_os="macos")] let platform=Platform::MacOs;
        #[cfg(not(any(target_os="linux",target_os="macos")))] return;
        #[cfg(any(target_os="linux",target_os="macos"))] {
            let args=vec!["--credentials-stdin".into()];
            let script="IFS= read -r first; IFS= read -r second; [ ${#first} -eq 15 ] && [ ${#second} -eq 17 ]";
            let command=native_command(script,&args);
            assert!(!command.get_args().any(|v| v.to_string_lossy().contains("SYNTHETIC")));
            for name in ["TOKEN", "DAEMON_TOKEN"] {
                assert!(command.get_envs().any(|(key,value)| key == name && value.is_none()));
            }
            NativeRunner.execute(platform,script,&args,Credentials { agent:"SYNTHETIC_AGENT", backend:Some("SYNTHETIC_BACKEND") }).unwrap();
            assert!(NativeRunner.execute(platform,"exit 23",&args,Credentials { agent:"SYNTHETIC_AGENT", backend:None }).is_err());
        }
    }

}
