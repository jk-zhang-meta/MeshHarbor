// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler.exe` on daemon hosts — a launcher that re-execs `meshharbord cli`.
//!
//! # Why
//!
//! Both MSI flavours used to bundle the full standalone tunnel CLI next to the
//! daemon (P4b). Measured on rc.361 that was 22.1 MiB of which only ~1.2 MiB
//! was CLI-specific code: `cargo bloat` puts `roomler_cli` + its bin at
//! 1.16 MiB of a 15.0 MiB `.text`, and everything else (std, the webrtc
//! family, tunnel_core, tokio, rustls, reqwest, quinn, clap) is a second copy
//! of crates `roomlerd.exe` already links. It also cost the Windows MSI job a
//! serial 143 s `cargo build -p roomler-cli` with a different feature set.
//!
//! So the daemon now owns that command surface (`meshharbord cli <args>` →
//! `roomler_cli::cli::run_from`), and this ~150 KB launcher keeps the
//! user-facing `roomler` command, its PATH entry, and the installer-smoke
//! payload assertions exactly where they were. Tunnel-ONLY hosts are
//! unaffected — they still install the real standalone binary from
//! `release-tunnel.yml`.
//!
//! # Behaviour notes
//!
//! * stdio is INHERITED, so streaming verbs (`meshharbor exec`, `meshharbor run`)
//!   behave identically to the standalone binary.
//! * Ctrl-C is deliberately ignored HERE so the child owns it. Windows
//!   delivers CTRL_C_EVENT to every process in the console group; if this
//!   launcher took the default action it would exit first and leave the
//!   long-running child (`meshharbor run`, `meshharbor forward`) orphaned. Unix is
//!   the same story with SIGINT/SIGQUIT and the foreground process group —
//!   parent ignores, child resets to default in pre_exec (P3e Phase 2: the
//!   .deb ships this launcher as /usr/bin/meshharbor on daemon hosts).
//! * The child is located next to this executable rather than via PATH, so a
//!   different Roomler install elsewhere on PATH can never be dispatched to.

use std::process::Command;

/// Exit code for "we could not even start the daemon binary". 127 is the
/// shell convention for command-not-found, which is exactly this case.
const EXIT_NO_DAEMON: i32 = 127;

#[cfg(target_os = "windows")]
fn ignore_ctrl_c() {
    // Passing a NULL handler with `add = TRUE` tells Windows to IGNORE
    // Ctrl-C in this process; the child (which installs its own handler)
    // still receives the event.
    unsafe {
        let _ = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 1);
    }
}

#[cfg(unix)]
fn ignore_ctrl_c() {
    // P3e Phase 2 — the .deb ships this launcher as /usr/bin/meshharbor too.
    // The terminal delivers SIGINT/SIGQUIT to the whole foreground process
    // GROUP, i.e. to us AND the child. The child must handle them (Ctrl-C
    // tears down `meshharbor run` / `meshharbor forward` cleanly); we must NOT die
    // first and orphan it — the standard wrapper convention (what `sh -c`
    // does while waiting on a foreground job). The child would inherit the
    // ignored disposition across fork+exec, so spawn() below resets both to
    // SIG_DFL in the child via pre_exec.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

#[cfg(not(any(target_os = "windows", unix)))]
fn ignore_ctrl_c() {}

/// Where the daemon might be, in priority order.
///
/// A sibling `roomlerd` covers the Linux .deb and the Windows MSI, which
/// install both binaries into one directory. macOS cannot: the daemon lives
/// inside an .app bundle (its executable is named after the bundle, and
/// renaming it would change the binary's TCC identity and void every existing
/// Screen Recording / Accessibility grant), while a CLI has to be on PATH. So
/// there the two are genuinely in different places and the bundle path is the
/// fallback.
fn daemon_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        out.push(dir.join(DAEMON_FILE_NAME));
    }
    #[cfg(target_os = "macos")]
    out.push(std::path::PathBuf::from(MACOS_BUNDLE_DAEMON));
    out
}

// Exits via `std::process::exit` rather than returning `ExitCode`, because
// `ExitCode: From<u8>` would TRUNCATE the child's code — a script checking for
// a specific nonzero exit must see exactly what the standalone CLI would have
// returned.
fn main() -> ! {
    let candidates = daemon_candidates();
    let daemon = match candidates.iter().find(|p| p.is_file()) {
        Some(p) => p.clone(),
        None if candidates.is_empty() => {
            eprintln!("roomler: could not resolve this executable's own path");
            std::process::exit(EXIT_NO_DAEMON);
        }
        None => {
            eprintln!(
                "roomler: the daemon binary is missing (looked in: {}) — reinstall the \
                 Roomler package, or use the standalone tunnel CLI on hosts without a daemon.",
                candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(EXIT_NO_DAEMON);
        }
    };

    ignore_ctrl_c();

    // argv[0] is dropped: the daemon re-labels it as `roomler` before handing
    // the vector to clap, so usage/help text still reads `roomler ...`.
    let mut cmd = Command::new(&daemon);
    cmd.arg("cli").args(std::env::args_os().skip(1));

    // Undo the parent's SIG_IGN in the child (inherited across fork+exec) so
    // the CLI sees Ctrl-C exactly as the standalone binary would.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }

    match cmd.status() {
        // Pass the child's exit code through UNTRUNCATED. A child killed by a
        // signal has no code — mirror the shell's 128+n so callers can still
        // tell SIGINT (130) from a real failure.
        Ok(s) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = s.signal() {
                    std::process::exit(128 + sig);
                }
            }
            std::process::exit(s.code().unwrap_or(1))
        }
        Err(e) => {
            eprintln!("roomler: failed to launch {}: {e}", daemon.display());
            std::process::exit(EXIT_NO_DAEMON);
        }
    }
}

#[cfg(target_os = "windows")]
const DAEMON_FILE_NAME: &str = "roomlerd.exe";
#[cfg(not(target_os = "windows"))]
const DAEMON_FILE_NAME: &str = "meshharbord";

/// The macOS bundle's executable. `CFBundleExecutable` matches the bundle name,
/// and CI asserts the launchd plists point here — FR-46 P5b moved all three
/// together, which is the only way a bundle rename is safe.
#[cfg(target_os = "macos")]
const MACOS_BUNDLE_DAEMON: &str = "/Library/Roomler/roomlerd.app/Contents/MacOS/roomlerd";
