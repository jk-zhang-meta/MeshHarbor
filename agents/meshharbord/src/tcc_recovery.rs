//! Refresh permissions through this exact executable, in a fresh process.
//! Children only preflight; restart requires loaded launchd policy plus every
//! existing LocalAPI gate. No unverified process ever exits itself.
#[cfg(any(target_os = "macos", all(test, unix)))]
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub screen: bool,
    pub ax: bool,
}

fn needs_restart(fresh: Probe, parent: Probe) -> bool {
    (fresh.screen && !parent.screen) || (fresh.ax && !parent.ax)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
async fn run_probe(
    mut command: tokio::process::Command,
    deadline: Duration,
) -> anyhow::Result<Probe> {
    use anyhow::{Context, bail};
    use std::process::Stdio;
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start TCC probe child")?;
    let output = tokio::time::timeout(deadline, child.wait_with_output())
        .await
        .context("TCC probe child timed out")?
        .context("wait for TCC probe child")?;
    if !output.status.success() {
        bail!("TCC probe child failed ({})", output.status);
    }
    if output.stdout.len() > 128 {
        bail!("TCC probe child returned oversized output");
    }
    serde_json::from_slice(&output.stdout).context("TCC probe child returned invalid JSON")
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use crate::localapi_state::RestartHandle;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tunnel_core::localapi::{LocalApiState, Response};

    static WATCH_NEEDED: AtomicBool = AtomicBool::new(true);
    static SCREEN_READY: AtomicBool = AtomicBool::new(false);
    pub fn watch_permissions() {
        WATCH_NEEDED.store(true, Ordering::Release);
    }
    pub fn screen_ready() -> bool {
        SCREEN_READY.load(Ordering::Acquire)
    }
    fn parent_probe() -> Probe {
        Probe {
            screen: crate::tcc::screen_recording_granted(),
            ax: crate::tcc::accessibility_trusted(),
        }
    }

    /// Both main functions call this before AppKit, runtime, logging or config.
    pub fn probe_if_requested() -> anyhow::Result<bool> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() != 1 || args[0] != "tcc-probe" {
            return Ok(false);
        }
        println!("{}", serde_json::to_string(&parent_probe())?);
        Ok(true)
    }

    pub fn spawn(
        state: Arc<dyn LocalApiState>,
        restart: RestartHandle,
    ) -> tokio::task::JoinHandle<()> {
        let initial = parent_probe();
        SCREEN_READY.store(initial.screen, Ordering::Release);
        if initial.screen && initial.ax {
            WATCH_NEEDED.store(false, Ordering::Release);
        }
        let mut shutdown = restart.shutdown_rx();
        tokio::spawn(async move {
            let mut last_notice = String::new();
            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
                if !WATCH_NEEDED.load(Ordering::Acquire) {
                    continue;
                }
                let exe = match std::env::current_exe() {
                    Ok(exe) => exe,
                    Err(error) => {
                        tracing::warn!(%error, "tcc: cannot locate probe executable");
                        continue;
                    }
                };
                let mut command = tokio::process::Command::new(exe);
                command.arg("tcc-probe");
                let fresh = match run_probe(command, Duration::from_secs(2)).await {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        tracing::debug!(%error, "tcc: probe unavailable; no restart requested");
                        continue;
                    }
                };
                let parent = parent_probe();
                SCREEN_READY.store(fresh.screen && parent.screen, Ordering::Release);
                if fresh.screen && fresh.ax && parent.screen && parent.ax {
                    WATCH_NEEDED.store(false, Ordering::Release);
                    tracing::info!(
                        "tcc: current process sees Screen Recording and Accessibility grants"
                    );
                    continue;
                }
                if !needs_restart(fresh, parent) {
                    continue;
                }
                let policy = if restart.supervision() == crate::supervision::Supervision::Launchd {
                    crate::supervision::confirm_launchd().await
                } else {
                    Err("the current process is not a verified launchd job".into())
                };
                let refusal = match policy {
                    Err(reason) => reason,
                    Ok(()) => match state
                        .restart_daemon("refresh newly granted macOS privacy permissions")
                        .await
                    {
                        Response::DaemonRestarting { .. } => {
                            tracing::info!(
                                screen = fresh.screen,
                                ax = fresh.ax,
                                "tcc: fresh child sees new grants; committing the gated graceful restart"
                            );
                            restart.commit();
                            return;
                        }
                        Response::Error { message } => message,
                        _ => "the local restart request was not accepted".into(),
                    },
                };
                if refusal != last_notice {
                    tracing::warn!(%refusal, screen = fresh.screen, ax = fresh.ax,
                        "tcc: new permission grant needs a fresh process; restart MeshHarbor to apply it; this process stays online");
                    last_notice = refusal;
                }
            }
        })
    }
}

#[cfg(target_os = "macos")]
pub use mac::{probe_if_requested, screen_ready, spawn, watch_permissions};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_new_grants_that_the_parent_cannot_use_need_a_restart() {
        let denied = Probe {
            screen: false,
            ax: false,
        };
        let granted = Probe {
            screen: true,
            ax: true,
        };
        assert!(!needs_restart(denied, denied));
        assert!(!needs_restart(denied, granted));
        assert!(!needs_restart(granted, granted));
        assert!(needs_restart(
            Probe {
                screen: true,
                ax: false
            },
            denied
        ));
        assert!(needs_restart(
            Probe {
                screen: false,
                ax: true
            },
            denied
        ));
        assert!(serde_json::from_str::<Probe>(r#"{"screen":true,"ax":"yes"}"#).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_probe_requires_success_and_valid_typed_json() {
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", r#"printf '{"screen":true,"ax":false}'"#]);
        assert_eq!(
            run_probe(command, Duration::from_secs(2)).await.unwrap(),
            Probe {
                screen: true,
                ax: false
            }
        );
        for body in [
            "printf invalid",
            r#"printf '{"screen":true,"ax":true}'; exit 2"#,
        ] {
            let mut command = tokio::process::Command::new("sh");
            command.args(["-c", body]);
            assert!(run_probe(command, Duration::from_secs(2)).await.is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_timed_out_probe_is_killed_and_reaped() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("probe.pid");
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", r#"echo $$ > "$PIDFILE"; exec sleep 30"#])
            .env("PIDFILE", &pid_file);
        assert!(
            run_probe(command, Duration::from_millis(200))
                .await
                .is_err()
        );
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..100 {
            // Signal zero only checks the existence of this test-owned child.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed-out probe {pid} remains alive");
    }
}
