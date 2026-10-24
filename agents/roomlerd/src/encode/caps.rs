// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Codec capability detection.
//!
//! Probes which video codecs the local host can encode and reports
//! them in the agent's `rc:agent.hello` payload. The result populates
//! `AgentCaps.codecs` (mime-style names like `"h264"`, `"h265"`,
//! `"av1"`) and `AgentCaps.hw_encoders` (descriptive labels like
//! `"mf-h264-hw"`, `"openh264-sw"`).
//!
//! Used by Phase 2 codec negotiation: the controller's browser
//! advertises its `RTCRtpReceiver.getCapabilities('video').codecs`
//! and the agent picks the best intersection.
//!
//! Detection is **probe-gated** for codecs without a safe demotion
//! path (HEVC, AV1): we actually run a tiny MfEncoder::new at startup
//! and only advertise codecs that successfully activate. This closes
//! the "enumerates but won't activate" false-advertising gap (e.g.
//! NVIDIA RTX 5090 Blackwell where the AV1 MFT enumerates but every
//! `ActivateObject` returns 0x8000FFFF). Without this guard a browser
//! session could negotiate AV1, the pump's runtime cascade would fail,
//! and the fail-closed NoopEncoder would leave the browser with a
//! black screen. The probe result is cached behind a `OnceLock` so
//! the ~300ms / codec init cost runs once per agent process, not per
//! `rc:agent.hello`.

use roomler_ai_remote_control::models::AgentCaps;
// FR-77 — the cell vocabulary. Which of these a build uses depends on its
// encoder features, so the import is allowed to be partly idle.
#[allow(unused_imports)]
use roomler_ai_remote_control::models::{ChromaFormat, VideoBackend, VideoCell, VideoCodec};
use std::sync::OnceLock;

#[allow(unused_imports)]
use super::cells::{cell_denied, denied_cells, ffmpeg_444_capable};

static CACHED_CAPS: OnceLock<AgentCaps> = OnceLock::new();

/// FR-84 D4 — the probe's result if it has run in this process, else `None`.
///
/// Reads the `OnceLock` and nothing else — deliberately NOT `detect()`. The
/// LocalAPI serves this on every Overview poll, and the first `detect()` in a
/// process spawns the probe children (vendor driver code, the reason the
/// probe is out-of-process at all); a control-surface read must never be what
/// launches that. The probe runs at the first `rc:agent.hello`, so before a
/// daemon has reached its server this is `None`, and the Overview says
/// "not probed yet" and asks again later.
pub fn cached() -> Option<AgentCaps> {
    CACHED_CAPS.get().cloned()
}

/// Whether this build carries ANY video encoder. A signalling-only build
/// (`cargo build -p roomlerd` with no media feature) has nothing to probe and
/// nothing to advertise, so the Overview says `unsupported` instead of
/// waiting for a probe that will never produce a cell.
pub const ENCODERS_COMPILED: bool = cfg!(any(
    feature = "openh264-encoder",
    feature = "mf-encoder",
    feature = "ffmpeg-encoder",
    feature = "vp9-444"
));

/// FR-84 D4 — the Overview's view of a caps value: the cell matrix, the
/// legacy labels, the probe timing, the denylist and the resolved preference.
/// Pure — `caps` is whatever the caller holds (the cache, a fixture).
pub fn summarize(
    caps: Option<&AgentCaps>,
    denied: Vec<String>,
    preference: Option<&str>,
) -> tunnel_core::localapi::EncoderCapsSummary {
    use tunnel_core::localapi::{EncoderCapsSummary, EncoderCell};
    let state = if !ENCODERS_COMPILED {
        "unsupported"
    } else if caps.is_some() {
        "ready"
    } else {
        "not_probed"
    };
    let mut out = EncoderCapsSummary {
        state: state.to_string(),
        denied,
        encoder_preference: preference.map(str::to_string),
        ..Default::default()
    };
    if let Some(c) = caps {
        out.cells = c
            .video_cells
            .iter()
            .map(|cell| EncoderCell {
                codec: cell.codec.clone(),
                backend: cell.backend.clone(),
                chroma: cell.chroma.clone(),
                hardware: cell.hw,
            })
            .collect();
        out.hw_encoders = c.hw_encoders.clone();
        out.codecs = c.codecs.clone();
        out.probe_ms = c.probe_ms;
        out.probe_cached = c.probe_cached;
    }
    out
}

/// FR-84 D4 — what the LocalAPI `EncoderCaps` verb answers: the CACHED
/// probe (never a fresh one), the denylist in force (env > config > built-in)
/// and the preference `run` resolved.
pub fn summarize_cached() -> tunnel_core::localapi::EncoderCapsSummary {
    summarize(
        cached().as_ref(),
        denied_cells(),
        super::resolved_preference().map(|p| p.wire()),
    )
}

/// Running the hardware probes in a CHILD PROCESS.
///
/// A capability probe is untrusted third-party code by definition — it calls
/// into vendor drivers and, through them, GPU firmware. In-process, a fault
/// anywhere in that stack takes the daemon down, and the service manager
/// restarts it straight back into the same probe: a crash-LOOP, not a
/// degraded-but-running agent.
///
/// Observed on the WSL sibling, 2026-08-20: WSL ships
/// `/usr/lib/wsl/lib/libcuda.so.1` as a stub with no usable driver, so
/// `hevc_nvenc` **dlopens successfully** and then segfaults when `cuInit(0)`
/// fails — the loaded-but-unusable state that no "is it present?" check
/// catches. Hosts with no libcuda at all take the clean dlopen-failed branch
/// and were never affected, which is why this stayed latent.
///
/// So the probes run behind a process boundary and **"the child died" is read
/// as "codec unavailable"**. That retires the whole class rather than the one
/// CUDA symptom: any future driver that faults, hangs, or calls `exit()` costs
/// this host its HW advertisement and nothing more.
mod child {
    use super::AgentCaps;
    use roomler_ai_remote_control::models::{ChromaFormat, VideoBackend, VideoCodec};

    /// Marks the line carrying the child's JSON, so log output on the same
    /// stream cannot be mistaken for the result. Parsing the last line, or
    /// all of stdout, would break the first time anything logged there.
    pub(super) const MARKER: &str = "ROOMLER_CAPS_JSON:";
    /// FR-77 P3c — the 4:4:4 phase's answer: a JSON array of the encoder
    /// names whose 4:4:4 form opened.
    pub(super) const MARKER_444: &str = "ROOMLER_CAPS_444:";
    /// FR-77 P3c — printed by the child BEFORE each open it attempts. On a
    /// service host the child's stderr reaches no log, so this is the only
    /// record of which open a dying child was inside; the parent quotes the
    /// last one in its verdict.
    pub(super) const PROGRESS: &str = "ROOMLER_CAPS_PROGRESS:";

    /// Set in the child's environment. A belt-and-braces recursion guard:
    /// `detect()` in a process carrying this must never spawn again.
    pub(super) const CHILD_ENV: &str = "ROOMLERD_CAPS_CHILD";
    /// FR-77 P3c — which phase the child runs: `base` (every 4:2:0 open, no
    /// FFmpeg 4:4:4 attempt) or `444` (only the 4:4:4 forms named in
    /// [`NAMES_444_ENV`]). Unset = the pre-P3c single-phase probe.
    pub(super) const PHASE_ENV: &str = "ROOMLERD_CAPS_PHASE";
    pub(super) const NAMES_444_ENV: &str = "ROOMLERD_CAPS_444_NAMES";

    /// Generous, because a cold GPU driver init on a loaded corp laptop is
    /// genuinely slow (~300 ms per codec, several codecs, plus process
    /// start). This is a backstop against a HUNG driver, not a performance
    /// budget — and even at the ceiling it beats the in-process behaviour it
    /// replaces, which was to hang forever.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    /// What the child hands back: the caps, plus the per-host verdicts the
    /// probe measured that are NOT wire capabilities.
    ///
    /// The vp9_qsv runtime-IDR verdict (P4) used to be set in a `OnceLock`
    /// — in the CHILD, where nothing ever read it again. rc.433 moved the
    /// probe out of process and the verdict never crossed back: every
    /// vp9_qsv session since ran the GOP-60 containment the probe existed to
    /// lift. It rides this envelope now and the parent installs it
    /// (`install_vp9_qsv_idr`), and the cache keeps it with the caps.
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
    pub(super) struct ProbeReport {
        pub(super) caps: AgentCaps,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) vp9_qsv_idr: Option<(bool, bool)>,
    }

    /// FR-77 P3c — which phase THIS process was started for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Phase {
        /// The pre-P3c shape: everything in one process (a bare
        /// `roomlerd caps-probe`).
        Full,
        /// Every 4:2:0 open, the software cells, the IDR verdict — and NO
        /// FFmpeg 4:4:4 attempt.
        Base,
        /// Only the 4:4:4 forms of the names in [`NAMES_444_ENV`].
        Only444,
    }

    pub(super) fn phase_from_env() -> Phase {
        match std::env::var(PHASE_ENV).as_deref() {
            Ok("base") => Phase::Base,
            Ok("444") => Phase::Only444,
            _ => Phase::Full,
        }
    }

    pub(super) fn names_444_from_env() -> Vec<String> {
        std::env::var(NAMES_444_ENV)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What one child run came back with. `stdout` is everything it printed
    /// (the progress lines survive a crash: Rust's stdout is line-buffered).
    struct Run {
        ok: bool,
        stdout: String,
        elapsed: std::time::Duration,
    }

    /// Probe in two children. `None` = no usable answer from the BASE phase,
    /// for ANY reason (spawn failed, non-zero exit, killed by a signal, timed
    /// out, unparseable output) — the caller treats every one of them the
    /// same way. A failure of the 4:4:4 phase costs only the 4:4:4 cells:
    /// the base matrix is advertised, with the last open the child reported
    /// named in the log so the operator can denylist it.
    ///
    /// Why two processes (FR-77 P3c, field 2026-09-08): CORPLAP-3's Intel
    /// media runtime died with 0xc0000005 on the first `vp9_qsv` 4:4:4 open
    /// over VUYX, and one child meant the daemon advertised NO hardware at
    /// all — `av1_qsv`, `h264_qsv`, `vp9_qsv` 4:2:0 all gone for a cell the
    /// session pump would never have needed.
    pub(super) fn probe() -> Option<ProbeReport> {
        if std::env::var_os(CHILD_ENV).is_some() {
            // We ARE the child (or something re-entered). Probing in-process
            // is what this process was started to do.
            return Some(super::in_process_report(phase_from_env() != Phase::Base));
        }
        let started = std::time::Instant::now();

        let base = run_child(&[(PHASE_ENV, "base".to_string())])?;
        if !base.ok {
            return None;
        }
        let mut report = parse_line(&base.stdout, base.elapsed)?;

        let names = candidates_444(&report.caps);
        if names.is_empty() {
            tracing::info!(
                elapsed_ms = base.elapsed.as_millis(),
                "caps probe: no 4:4:4 candidate on this host — single phase"
            );
        } else {
            match run_child(&[
                (PHASE_ENV, "444".to_string()),
                (NAMES_444_ENV, names.join(",")),
            ]) {
                Some(run) if run.ok => match parse_444_line(&run.stdout) {
                    Some(ok) => {
                        tracing::info!(
                            elapsed_ms = run.elapsed.as_millis(),
                            tried = ?names,
                            opened = ?ok,
                            "caps probe: 4:4:4 phase reported"
                        );
                        merge_444(&mut report, &ok);
                    }
                    None => tracing::warn!(
                        tried = ?names,
                        "caps probe: 4:4:4 phase printed no answer — advertising the 4:2:0 matrix"
                    ),
                },
                other => {
                    let last = other
                        .as_ref()
                        .and_then(|r| last_progress(&r.stdout))
                        .unwrap_or_else(|| "(none reported)".to_string());
                    tracing::error!(
                        tried = ?names,
                        last_open = %last,
                        "caps probe: the 4:4:4 probe child DIED or hung — advertising the \
                         4:2:0 matrix only. The open it was inside is the cell to add to \
                         `encoder_cells_deny` (`<name>:yuv444`); the daemon is unaffected."
                    );
                }
            }
        }

        // The whole cost the daemon paid: both spawns, every open, both parses.
        report.caps.probe_ms =
            Some(u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX));
        tracing::info!(
            elapsed_ms = report.caps.probe_ms.unwrap_or(0),
            codecs = ?report.caps.codecs,
            hw_encoders = ?report.caps.hw_encoders,
            cells = report.caps.video_cells.len(),
            vp9_qsv_idr = ?report.vp9_qsv_idr,
            "caps probe: child reported"
        );
        Some(report)
    }

    /// Spawn one `caps-probe` child with `extra` on top of the recursion
    /// guard and the S2 config fallbacks; read its stdout on a thread while
    /// waiting, bounded by [`TIMEOUT`]. `None` = could not spawn / hung.
    fn run_child(extra: &[(&str, String)]) -> Option<Run> {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%e, "caps probe: cannot resolve our own path — skipping HW probes");
                return None;
            }
        };
        let started = std::time::Instant::now();
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("caps-probe")
            .env(CHILD_ENV, "1")
            // S2 config fallbacks are process-local: hand them to the child as
            // real env vars, or every knob it reads falls to its built-in
            // default (FR-19 P4c: `relay-server` was never advertised).
            .envs(tunnel_core::env::config_fallbacks_for_child())
            .envs(extra.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            // Inherited on purpose: on an attended host the child's own
            // probe logging lands next to the verdict. On a service host it
            // reaches no log — which is what the PROGRESS lines are for.
            .stderr(std::process::Stdio::inherit());
        #[cfg(windows)]
        {
            // No console window when the daemon runs attended.
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut childp = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%e, "caps probe: could not spawn the probe child — no HW advertisement");
                return None;
            }
        };

        // Read stdout on this thread while waiting, so a chatty child cannot
        // fill the pipe and deadlock against our own wait.
        let stdout = childp.stdout.take();
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = String::new();
            if let Some(mut s) = stdout {
                let _ = s.read_to_string(&mut buf);
            }
            buf
        });

        let status = match wait_bounded(&mut childp) {
            Some(s) => s,
            None => {
                // A hung driver. Kill it and carry on without this phase.
                let _ = childp.kill();
                let _ = childp.wait();
                let stdout = reader.join().unwrap_or_default();
                tracing::warn!(
                    timeout_s = TIMEOUT.as_secs(),
                    phase = ?extra.iter().find(|(k, _)| *k == PHASE_ENV).map(|(_, v)| v.as_str()),
                    last_open = %last_progress(&stdout).unwrap_or_default(),
                    "caps probe: the probe child hung — the daemon is unaffected; this is \
                     the process boundary doing its job."
                );
                return Some(Run {
                    ok: false,
                    stdout,
                    elapsed: started.elapsed(),
                });
            }
        };
        let stdout = reader.join().unwrap_or_default();

        if !status.success() {
            // THE case this module exists for. A signal death here is a
            // driver fault that would otherwise have been ours.
            tracing::error!(
                status = %status,
                elapsed_ms = started.elapsed().as_millis(),
                phase = ?extra.iter().find(|(k, _)| *k == PHASE_ENV).map(|(_, v)| v.as_str()),
                last_open = %last_progress(&stdout).unwrap_or_default(),
                "caps probe: the probe child DIED. Before this ran out-of-process the same \
                 fault crash-looped the daemon."
            );
            return Some(Run {
                ok: false,
                stdout,
                elapsed: started.elapsed(),
            });
        }
        Some(Run {
            ok: true,
            stdout,
            elapsed: started.elapsed(),
        })
    }

    /// The last `PROGRESS` line in a child's output: the open it was inside
    /// when it stopped answering.
    pub(super) fn last_progress(out: &str) -> Option<String> {
        out.lines()
            .rev()
            .find_map(|l| l.trim().strip_prefix(PROGRESS))
            .map(|s| s.trim().to_string())
    }

    /// FR-77 P3c — the FFmpeg encoder names whose 4:4:4 form the second
    /// phase should try: every hardware cell of the base matrix whose name
    /// the source matrix lists for 4:4:4, minus the denylist. Cells the base
    /// phase could not open are never asked (no `vp9_qsv` 4:4:4 on a host
    /// without `vp9_qsv`).
    pub(super) fn candidates_444(caps: &AgentCaps) -> Vec<String> {
        let deny = crate::encode::cells::denied_cells();
        let mut names: Vec<String> = Vec::new();
        for cell in caps.typed_cells() {
            let backend = match cell.backend {
                VideoBackend::Nvenc
                | VideoBackend::Qsv
                | VideoBackend::Vaapi
                | VideoBackend::Vulkan => cell.backend.wire(),
                _ => continue,
            };
            if cell.codec == VideoCodec::Av1 {
                continue;
            }
            let name = format!("{}_{}", cell.codec.wire(), backend);
            if crate::encode::cells::ffmpeg_444_capable(&name)
                && !crate::encode::cells::cell_denied(&deny, &name, ChromaFormat::Yuv444)
                && !names.contains(&name)
            {
                names.push(name);
            }
        }
        names
    }

    /// FR-77 P3c — fold the 4:4:4 phase's answer into the base report: the
    /// named cells gain `yuv444`, and the legacy `hevc_chroma` says 4:4:4
    /// exactly when the HEVC winner is `hevc_nvenc` and it opened (the P7
    /// contract the viewer's legacy derivation reads).
    pub(super) fn merge_444(report: &mut ProbeReport, ok: &[String]) {
        for name in ok {
            let Some((codec, backend)) = VideoBackend::from_ffmpeg_name(name) else {
                continue;
            };
            for cell in report.caps.video_cells.iter_mut() {
                if cell.codec == codec.wire() && cell.backend == backend.wire() {
                    let c444 = ChromaFormat::Yuv444.wire().to_string();
                    if !cell.chroma.contains(&c444) {
                        cell.chroma.push(c444);
                    }
                }
            }
            let hevc_winner_is_nvenc = report
                .caps
                .hw_encoders
                .iter()
                .find(|h| h.starts_with("ffmpeg-hevc_"))
                .is_some_and(|h| h == "ffmpeg-hevc_nvenc");
            if name == "hevc_nvenc"
                && hevc_winner_is_nvenc
                && !report.caps.hevc_chroma.iter().any(|c| c == "yuv444")
            {
                report.caps.hevc_chroma.push("yuv444".into());
            }
        }
    }

    /// The child's marked line → the report, with `probe_ms` stamped by the
    /// PARENT (the caller overwrites it with the whole two-phase cost). A
    /// bare `AgentCaps` line (the P1 shape) still parses, so the two halves
    /// of a binary can never disagree on the envelope.
    pub(super) fn parse_line(out: &str, elapsed: std::time::Duration) -> Option<ProbeReport> {
        let line = out.lines().find_map(|l| l.trim().strip_prefix(MARKER))?;
        let mut report = match serde_json::from_str::<ProbeReport>(line) {
            Ok(r) => r,
            Err(e) => match serde_json::from_str::<AgentCaps>(line) {
                Ok(caps) => ProbeReport {
                    caps,
                    vp9_qsv_idr: None,
                },
                Err(_) => {
                    tracing::warn!(%e, "caps probe: child output was not parseable — no HW advertisement");
                    return None;
                }
            },
        };
        report.caps.probe_ms = Some(u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX));
        Some(report)
    }

    /// The 4:4:4 phase's marked line → the names that opened.
    pub(super) fn parse_444_line(out: &str) -> Option<Vec<String>> {
        let line = out
            .lines()
            .find_map(|l| l.trim().strip_prefix(MARKER_444))?;
        serde_json::from_str::<Vec<String>>(line).ok()
    }

    /// `wait` with a deadline. `None` = still running when time ran out.
    ///
    /// Polling rather than a platform wait-with-timeout: it is a handful of
    /// wakeups on a path that runs ONCE per process, and it keeps this
    /// module free of per-platform process APIs.
    fn wait_bounded(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(s)) => return Some(s),
                // Treat "cannot ask" as death; the caller's fallback is the
                // safe answer either way.
                Err(_) => return None,
                Ok(None) => {}
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// The `caps-probe` child's entire job: probe, print one marked JSON line.
///
/// Printing a MARKED line rather than bare JSON so that anything else on
/// stdout — a library that logs there, a driver that prints a banner — cannot
/// be mistaken for the result.
pub fn print_probe_result() {
    match child::phase_from_env() {
        child::Phase::Only444 => {
            let names = child::names_444_from_env();
            let opened = probe_444(&names);
            match serde_json::to_string(&opened) {
                Ok(json) => println!("{}{json}", child::MARKER_444),
                Err(e) => {
                    tracing::error!(%e, "caps probe: could not serialise the 4:4:4 answer");
                    std::process::exit(2);
                }
            }
        }
        phase => {
            let report = in_process_report(phase != child::Phase::Base);
            match serde_json::to_string(&report) {
                Ok(json) => println!("{}{json}", child::MARKER),
                Err(e) => {
                    tracing::error!(%e, "caps probe: could not serialise caps");
                    std::process::exit(2);
                }
            }
        }
    }
}

/// FR-77 P3c — the 4:4:4 phase: open the 4:4:4 form of each named encoder,
/// announcing every attempt on stdout first so a dying process leaves the
/// name of the open it was inside. Returns the names that opened.
#[cfg(feature = "ffmpeg-encoder")]
fn probe_444(names: &[String]) -> Vec<String> {
    use crate::encode::ffmpeg::FfmpegEncoder;
    let mut opened = Vec::new();
    if !crate::encode::ffmpeg::available() {
        return opened;
    }
    for name in names {
        // The cascade tables own the `&'static str`; a name outside them is
        // not something this build can open anyway.
        let Some(name) = FfmpegEncoder::static_name(name) else {
            continue;
        };
        println!("{}{name}:yuv444", child::PROGRESS);
        let t = std::time::Instant::now();
        match FfmpegEncoder::new_named_probe(name, PROBE_WIDTH, PROBE_HEIGHT, true) {
            Ok(enc) => {
                drop(enc);
                tracing::info!(
                    encoder = name,
                    elapsed_ms = t.elapsed().as_millis(),
                    "caps probe: 4:4:4 cell opened"
                );
                opened.push(name.to_string());
            }
            Err(e) => tracing::info!(
                encoder = name,
                %e,
                elapsed_ms = t.elapsed().as_millis(),
                "caps probe: 4:4:4 cell did not open — advertising 4:2:0 only"
            ),
        }
    }
    opened
}

#[cfg(not(feature = "ffmpeg-encoder"))]
fn probe_444(_names: &[String]) -> Vec<String> {
    Vec::new()
}

/// Probe dimensions for codec activation checks (HEVC, AV1, VP9-444).
/// Even number, small enough that any encoder accepts it, matching
/// what the internal `probe_pipeline` uses for MFT output
/// verification. Used by the MF cascade probes (Windows-only,
/// `mf-encoder` feature) and the libvpx VP9-444 probe (any platform
/// with `vp9-444` feature). The `dead_code` allowance covers builds
/// that compile in neither feature group.
#[allow(dead_code)]
const PROBE_WIDTH: u32 = 480;
#[allow(dead_code)]
const PROBE_HEIGHT: u32 = 270;

/// Detect the codecs and HW backends compiled into this agent build
/// and currently functional on this host. First call runs the
/// activation probes (~300ms per codec on HEVC/AV1-capable boxes,
/// <10ms on boxes with no HW encoder); subsequent calls return the
/// cached result.
pub fn detect() -> AgentCaps {
    let caps = CACHED_CAPS
        .get_or_init(|| {
            with_honest_words(with_config_lists(cached_or_probed()), &HostFacts::here())
        })
        .clone();
    // Listener lifetime is not part of the expensive encoder probe cache.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    let caps = with_relay_server_readiness(caps, crate::relay_server::listening_port().is_some());
    caps
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn with_relay_server_readiness(mut caps: AgentCaps, ready: bool) -> AgentCaps {
    use roomler_ai_remote_control::models::RpcCap;
    caps.rpc.retain(|cap| cap != RpcCap::RelayServer.wire());
    if ready {
        caps.rpc.push(RpcCap::RelayServer.wire().to_owned());
    }
    caps
}

/// FR-97 P0c — what this host can actually serve, as plain facts, so the
/// decision ([`with_honest_words`]) runs, and is tested, on every OS (FR-43's
/// practice: the decision stays out of `cfg(target_os)`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostFacts {
    pub(crate) os: roomler_ai_remote_control::models::OsKind,
    /// The `audio` feature is compiled in.
    pub(crate) audio_built: bool,
    /// This host can capture the computer's own sound:
    ///
    /// - Windows: always (WASAPI loopback).
    /// - Linux: when `audio_source::linux_route` finds a way to it: the
    ///   default output's monitor through Pulse's client library (FR-97
    ///   P3c-2), or a capture device the owner named. Never the default input,
    ///   which is a microphone (P3c-1).
    /// - macOS: never, until FR-97 P2a.
    pub(crate) audio_backend: bool,
    /// Linux: why there is no way to the computer's sound, by the route's own
    /// code ([`linux_audio_refusal`]). `None` elsewhere, and where there is one.
    pub(crate) linux_audio_refusal: Option<crate::audio_source::AudioUnavailableCode>,
    /// The clipboard watcher reports copied images: Windows, and (FR-97
    /// P3e-3a) a Linux X11 session whose server takes the change gate
    /// (`clipboard::x11_gate`); `clipboard::install_watcher` drops image
    /// events elsewhere.
    pub(crate) watches_clipboard_images: bool,
    /// This process has a clipboard to reach at all.
    pub(crate) clipboard_reachable: bool,
    /// The keyboard layout is this process's to read and switch: on Windows
    /// always; on Linux in an X11 session (FR-97 P3e,
    /// `input::layout_x11::offered`); on macOS not before P2d.
    pub(crate) layout_reachable: bool,
    /// A layout switch stays switched: not under GNOME, which puts its own
    /// back (FR-97 P3e, `input::layout_x11::switchable`). There the chip
    /// reports and the picker is not offered.
    pub(crate) layout_switchable: bool,
    /// Display match can switch this host's display (FR-97 P3e-2): Windows;
    /// on Linux a person's own X11 display or the daemon's own virtual desktop
    /// on Xorg's dummy driver; not macOS.
    pub(crate) display_switchable: bool,
}

impl HostFacts {
    pub(crate) fn here() -> Self {
        use roomler_ai_remote_control::models::OsKind;
        let linux_audio_refusal = linux_audio_refusal();
        Self {
            os: if cfg!(target_os = "windows") {
                OsKind::Windows
            } else if cfg!(target_os = "macos") {
                OsKind::Macos
            } else {
                OsKind::Linux
            },
            audio_built: cfg!(feature = "audio"),
            audio_backend: cfg!(target_os = "windows")
                || (cfg!(target_os = "linux") && linux_audio_refusal.is_none()),
            linux_audio_refusal,
            watches_clipboard_images: watches_clipboard_images(),
            clipboard_reachable: clipboard_reachable(),
            layout_reachable: layout_reachable(),
            layout_switchable: layout_switchable(),
            display_switchable: display_switchable(),
        }
    }
}

/// FR-97 P3e — see [`HostFacts::layout_switchable`].
fn layout_switchable() -> bool {
    #[cfg(all(target_os = "linux", feature = "enigo-input"))]
    {
        crate::input::layout_x11::switchable()
    }
    #[cfg(not(all(target_os = "linux", feature = "enigo-input")))]
    {
        cfg!(target_os = "windows")
    }
}

/// FR-97 P3e — see [`HostFacts::layout_reachable`]. Under Wayland the layout
/// is the compositor's, and a system install has no X connection at all.
fn layout_reachable() -> bool {
    #[cfg(all(target_os = "linux", feature = "enigo-input"))]
    {
        crate::input::layout_x11::offered()
    }
    #[cfg(not(all(target_os = "linux", feature = "enigo-input")))]
    {
        cfg!(target_os = "windows")
    }
}

/// FR-97 P3e-3a — see [`HostFacts::watches_clipboard_images`]. Asks the X
/// server once (a connection and XFixes' version), for the hello.
fn watches_clipboard_images() -> bool {
    #[cfg(all(target_os = "linux", feature = "clipboard"))]
    {
        crate::clipboard::x11_gate::available()
    }
    #[cfg(not(all(target_os = "linux", feature = "clipboard")))]
    {
        cfg!(target_os = "windows")
    }
}

/// FR-97 P3e-2 — see [`HostFacts::display_switchable`]. A virtual desktop is
/// up before the hello (`main.rs` starts it before connecting).
fn display_switchable() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::display_match::x11_offered()
            || crate::virtual_desktop::switchable_display().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        cfg!(target_os = "windows")
    }
}

/// FR-97 P3c-2 — Linux: why a session could not reach the computer's sound,
/// by the route the capture itself takes, or `None` when it can. Asked of the
/// disk (`audio::pulse::present`): the hello loads no library to answer.
fn linux_audio_refusal() -> Option<crate::audio_source::AudioUnavailableCode> {
    #[cfg(all(target_os = "linux", feature = "audio"))]
    {
        use crate::audio_source::{linux_facts, linux_route};
        linux_route(linux_facts(crate::audio::pulse::present()))
            .err()
            .map(|r| r.code)
    }
    #[cfg(not(all(target_os = "linux", feature = "audio")))]
    {
        None
    }
}

/// FR-97 P3c — the hello's word for a Linux host with no way to the computer's
/// sound, by why. Before P3c-1 this track carried the microphone.
fn linux_audio_word(
    why: Option<crate::audio_source::AudioUnavailableCode>,
) -> roomler_ai_remote_control::models::Unavailable {
    use crate::audio_source::AudioUnavailableCode as Why;
    use roomler_ai_remote_control::models::Unavailable;
    match why {
        Some(Why::NoSoundServer) => Unavailable::new(
            "no-sound-server",
            "This host sends no sound: it has no Pulse client library (libpulse-simple), so the agent cannot reach its sound server",
        ),
        Some(Why::NoSession) => Unavailable::new(
            "no-session",
            "This host sends no sound: the agent runs as root without the session helper that records a session's sound",
        ),
        _ => Unavailable::new(
            "no-monitor",
            "This host sends no sound: session audio is switched off on it (ROOMLERD_AUDIO_SESSION=0), and no capture device is named for it (ROOMLERD_AUDIO_SOURCE)",
        ),
    }
}

/// A root Linux daemon (a system install) runs outside every desktop session:
/// with neither display variable it has no clipboard to reach, the same test
/// capture makes before it reports `no_display`. A per-user daemon, and every
/// other OS, keeps the compile-time answer. FR-93 P7 makes the root case work
/// through the session; until then the honest answer is no.
fn clipboard_reachable() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let root = unsafe { libc::geteuid() } == 0;
        let display =
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
        !root || display
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// FR-97 P0c — take out of `caps` what this host cannot serve, and say why in
/// [`AgentCaps::unavailable`]. A word in the hello is a promise; the viewer
/// shows these reasons instead of a control that fails silently (FR-97 §3.1).
/// The census (`scripts/fr97-caps-census.sh`) counts the result by OS.
pub(crate) fn with_honest_words(mut caps: AgentCaps, facts: &HostFacts) -> AgentCaps {
    use roomler_ai_remote_control::models::{OsKind, Unavailable};
    if facts.audio_built && !facts.audio_backend {
        // Without a backend the session would carry a silent track (R1).
        caps.audio.clear();
        let why = match facts.os {
            OsKind::Linux => linux_audio_word(facts.linux_audio_refusal),
            OsKind::Windows | OsKind::Macos => Unavailable::new(
                "no-backend",
                "System-audio capture is not implemented on this OS yet, so this host sends no sound",
            ),
        };
        caps.unavailable.insert("audio".into(), why);
    }
    if !facts.clipboard_reachable && (caps.supports_clipboard || !caps.clipboard.is_empty()) {
        caps.supports_clipboard = false;
        caps.clipboard.clear();
        caps.unavailable.insert(
            "clipboard".into(),
            Unavailable::new(
                "no-session",
                "This daemon runs as root outside any desktop session, so it has no clipboard to reach",
            ),
        );
    } else if !facts.watches_clipboard_images
        && caps.clipboard.iter().any(|w| w == "events")
        && caps.clipboard.iter().any(|w| w == "images")
    {
        // `events` still pushes text; only copied images go unwatched (R8).
        caps.unavailable.insert(
            "clipboard-image-events".into(),
            Unavailable::new(
                "not-watched",
                "Copied images are not watched on this host, so they do not sync on their own: send or fetch one with the clipboard buttons",
            ),
        );
    }
    // FR-97 P3e — the layout chip and picker only where the layout can be
    // read and switched. No reason in `unavailable`: there is no control to
    // grey, the chip simply does not appear, as on a host before P3e.
    if !facts.layout_reachable {
        caps.layout.clear();
    } else if !facts.layout_switchable {
        // GNOME on Xorg: the chip reports; a picker would only snap back.
        caps.layout.retain(|w| w != "set");
    }
    // FR-97 P3e-2 — where display match cannot switch this host's display.
    // Until now the viewer offered the toggle by OS (Windows only), which hid
    // a Linux virtual desktop that could switch; it follows this word now.
    if !facts.display_switchable {
        let why = match facts.os {
            OsKind::Macos => Unavailable::new(
                "unsupported",
                "This Mac's display cannot be switched to your window: display match is built for Windows and for Linux on X11",
            ),
            OsKind::Linux | OsKind::Windows => Unavailable::new(
                "unsupported",
                "This host's display cannot be switched to your window: display match needs an X11 desktop with a per-user install, or the agent's own virtual desktop; a Wayland desktop and a system install keep their screen as it is",
            ),
        };
        caps.unavailable.insert("display-match".into(), why);
    }
    // The viewer's button types three ordinary keys everywhere.
    let sas = match facts.os {
        // A host that may send the real one (FR-97 P4a: SYSTEM, and a policy
        // that lets services) says so live, in the announcement, and drops
        // this entry; the rest keep it with the reason for theirs.
        OsKind::Windows => Unavailable::new(
            "keys-only",
            "Ctrl+Alt+Del is sent as ordinary keys: apps on the desktop get it, but the Windows lock and sign-in screens do not",
        ),
        // Not meaningless: the desktop binds the chord, and what it binds is
        // worth knowing before pressing it.
        OsKind::Linux => Unavailable::new(
            "keys-only",
            "Ctrl+Alt+Del is sent as ordinary keys, and the desktop decides what they do: GNOME and KDE bind them to log out",
        ),
        OsKind::Macos => Unavailable::new(
            Unavailable::NOT_APPLICABLE,
            "Ctrl+Alt+Del has no system meaning on macOS",
        ),
    };
    caps.unavailable.insert("sas".into(), sas);
    caps
}

/// The config-derived lists, assigned by the DAEMON over whatever
/// `cached_or_probed` answered — the caps-probe child's struct on a miss, the
/// merged cache on a hit, the driver-free fallback when the child died. All
/// three arrive here by this one line, and every list is OVERWRITTEN, never
/// merged: the child loads no config, so anything it carried in these fields
/// was computed against the built-in defaults.
///
/// - `rpc` — config-derived, not driver-probed (`relay_server_enabled` is an
///   opt-in), so it is computed where the config fallbacks are registered.
/// - `apps` — FR-56 AC10 (review of #1667): until it moved here,
///   `[virtual_desktop_apps] enabled = false` did not stop the hello
///   advertising `list` on every release's first boot, or on any boot of a
///   host with no hardware cell (never cached). And the child must not run a
///   privilege-dropped desktop walk.
/// - `files` — #1672, the same hole: `browse` follows `enable_remote_browse`,
///   and the child's flag is the built-in default (`true`). Set once at
///   startup and never live, so a boot-time snapshot here is exactly as fresh
///   as the flag itself.
///
/// A named seam rather than three lines inside the `OnceLock` closure so a
/// test can lock EACH assignment (`the_daemon_assigns_every_config_list`):
/// with the lines inline, deleting `caps.files = files_caps()` left every lib
/// test green while every hello shipped an empty `files` and every browser
/// fell back to upload-only — `detect()` itself cannot be called from a unit
/// test without spawning the probe child.
fn with_config_lists(mut caps: AgentCaps) -> AgentCaps {
    caps.rpc = rpc_caps();
    caps.apps = apps_caps();
    caps.files = files_caps();
    caps
}

/// FR-77 P3 — the probe cache in front of the child probe. A hit reuses the
/// last probe's encoder matrix (see `caps_cache` for exactly which fields);
/// a miss probes and, when the answer is worth keeping, stores it. Every
/// outcome is one log line, because "why did this host re-probe" is the
/// question the cache will be asked.
fn cached_or_probed() -> AgentCaps {
    use super::caps_cache as cache;

    let now = cache::now_unix();
    let enabled = cache::enabled();
    let key = if enabled { cache::current_key() } else { None };
    let path = cache::path();
    match (&key, &path) {
        (Some(key), Some(path)) => match cache::load_matching(path, key, now) {
            Ok(hit) => {
                tracing::info!(
                    path = %path.display(),
                    age_secs = now.saturating_sub(hit.probed_at_unix),
                    probe_ms = hit.probe_ms,
                    cells = hit.caps.video_cells.len(),
                    hardware = %key.hardware,
                    "caps probe: cache hit — reusing the last probe's encoder matrix"
                );
                install_vp9_qsv_idr(hit.vp9_qsv_idr);
                return merge_cached(hit);
            }
            Err(miss) => tracing::info!(
                path = %path.display(),
                reason = %miss.reason(),
                "caps probe: cache miss — probing"
            ),
        },
        _ if !enabled => {
            tracing::info!("caps probe: cache disabled (ROOMLERD_CAPS_CACHE=0) — probing")
        }
        (Some(_), None) => {
            tracing::debug!("caps probe: no directory to cache in — probing")
        }
        _ => tracing::debug!("caps probe: no cache key on this platform — probing"),
    }

    match child::probe() {
        Some(report) => {
            install_vp9_qsv_idr(report.vp9_qsv_idr);
            if let (Some(key), Some(path)) = (key, path) {
                if cache::worth_caching(&report.caps) {
                    let file = cache::CacheFile::new(
                        key,
                        now,
                        report.caps.probe_ms.unwrap_or(0),
                        report.caps.clone(),
                        report.vp9_qsv_idr,
                    );
                    match cache::store(&path, &file) {
                        Ok(()) => tracing::info!(
                            path = %path.display(),
                            "caps probe: result cached for the next start"
                        ),
                        Err(e) => tracing::warn!(
                            %e,
                            path = %path.display(),
                            "caps probe: could not write the cache — harmless, the next start probes again"
                        ),
                    }
                } else {
                    tracing::info!(
                        "caps probe: no hardware cell opened — not cached (a boot-time driver race must not be frozen for a week)"
                    );
                }
            }
            report.caps
        }
        None => {
            // The child died, hung, or could not be launched. "Codec
            // unavailable" is the only honest reading: we have no
            // evidence this host can encode with any of them, and
            // advertising one we cannot produce costs a black session.
            // Everything that needs no driver still stands.
            compute_caps(false, false)
        }
    }
}

/// A cache hit: the driver-derived fields from the cache, everything else
/// computed fresh by THIS process (permissions, the GUI session and the
/// clipboard verbs change without any driver changing). The config-derived
/// lists — `rpc`, `apps`, `files` — are neither cached nor computed here:
/// `detect()` assigns them after the merge, by the same line a miss takes.
fn merge_cached(hit: super::caps_cache::CacheFile) -> AgentCaps {
    let mut fresh = compute_caps(false, false);
    let cached = hit.caps;
    fresh.hw_encoders = cached.hw_encoders;
    fresh.codecs = cached.codecs;
    fresh.transports = cached.transports;
    fresh.hevc_chroma = cached.hevc_chroma;
    fresh.vp9_chroma = cached.vp9_chroma;
    fresh.video_cells = cached.video_cells;
    fresh.probe_ms = Some(hit.probe_ms);
    fresh.probe_cached = true;
    fresh
}

#[cfg(feature = "ffmpeg-encoder")]
fn install_vp9_qsv_idr(verdict: Option<(bool, bool)>) {
    if let Some(v) = verdict {
        crate::encode::ffmpeg::FfmpegEncoder::set_vp9_qsv_idr_verdict(v);
    }
}

#[cfg(not(feature = "ffmpeg-encoder"))]
fn install_vp9_qsv_idr(_verdict: Option<(bool, bool)>) {}

#[cfg(feature = "ffmpeg-encoder")]
fn vp9_qsv_idr_verdict() -> Option<(bool, bool)> {
    crate::encode::ffmpeg::FfmpegEncoder::vp9_qsv_idr_verdict()
}

#[cfg(not(feature = "ffmpeg-encoder"))]
fn vp9_qsv_idr_verdict() -> Option<(bool, bool)> {
    None
}

/// The in-process probe as a report: what the `caps-probe` child computes
/// and prints, and what a process that IS the child answers directly.
/// `attempt_444` = false is the BASE phase (FR-77 P3c): every 4:2:0 open
/// and the software cells, with no FFmpeg 4:4:4 attempt — those run in the
/// second child so a faulting driver costs only the 4:4:4 form.
fn in_process_report(attempt_444: bool) -> child::ProbeReport {
    let caps = compute_caps(true, attempt_444);
    child::ProbeReport {
        caps,
        vp9_qsv_idr: vp9_qsv_idr_verdict(),
    }
}

/// Compute caps IN THIS PROCESS, running the hardware probes. This is what
/// the `caps-probe` child executes; nothing else should call it, because a
/// vendor driver that faults takes the whole process with it.
pub fn detect_in_process() -> AgentCaps {
    compute_caps(true, true)
}

/// Whether the OS will let this process capture the screen.
///
/// macOS is the only platform with a gate, and it is a silent one:
/// `CGDisplayStream` opens successfully without the Screen Recording grant
/// and delivers wallpaper-only frames forever. Probed rather than assumed so
/// the server can be told the truth. Cheap — a preflight call, no prompt.
/// Can this process reach a GUI session at all?
///
/// macOS's root LaunchDaemon cannot: session 0 has no WindowServer, so capture
/// and input are unavailable there no matter what TCC says. Every other
/// platform always can.
fn gui_session_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::tcc::has_gui_session()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

fn capture_permission_granted() -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::tcc::screen_recording_granted()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// Whether the OS will let this process inject input.
///
/// Same shape as [`capture_permission_granted`]: macOS drops every
/// `CGEventPost` on the floor without the Accessibility grant and reports
/// success. Uses the TCC probe directly rather than constructing an injector,
/// which is lazy by design (first injected event) and has side effects.
fn input_permission_granted() -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::tcc::accessibility_trusted()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// `AgentCaps.video`: properties of the video wire this build speaks.
/// `chunk-framing` always (FR-17); `bench` only on a bench target (FR-16 L4:
/// the synthetic source selected and `ROOMLERD_BENCH` on), so a viewer sends
/// its probes only where a frame will answer them. The probe child inherits
/// the environment, so it reads the same answer the daemon would.
fn video_features() -> Vec<String> {
    let mut features = vec!["chunk-framing".to_string()];
    #[cfg(feature = "synthetic-frame-source")]
    if crate::capture::synthetic_backend::bench_active() {
        features.push("bench".to_string());
    }
    // FR-119 P1 — the viewer may ask for more than 60 fps (`rc:fps`); the
    // answer rides `rc:video-info`. Off unless `ROOMLERD_FPS_HIGH=1`.
    if crate::encode::fps_high_enabled() {
        features.push(crate::encode::frame_rate::CAP.to_string());
    }
    features
}

/// `run_hw_probes = false` computes everything that needs no driver call —
/// which is exactly the honest answer when the probe child did not come back.
///
/// `unused_variables` is allowed because EVERY consumer of the flag sits
/// behind a `#[cfg]` (mf-encoder / ffmpeg-encoder / vp9-444); a default-feature
/// build probes nothing and legitimately never reads it.
#[allow(unused_variables)]
fn compute_caps(run_hw_probes: bool, attempt_444: bool) -> AgentCaps {
    // `mut` is only consumed inside the cfg-gated push blocks below
    // (openh264-encoder / mf-encoder). Default-feature builds skip
    // both blocks and the vecs stay empty; silence the unused-mut
    // lint to keep the CI `cargo clippy --workspace -- -D warnings`
    // build green on Linux.
    #[allow(unused_mut)]
    let mut codecs: Vec<String> = Vec::new();
    #[allow(unused_mut)]
    let mut hw_encoders: Vec<String> = Vec::new();
    // FR-77 — every cell (codec × chroma) this host OPENED, one entry per
    // encoder (codec × backend). Filled next to the legacy fields, which keep
    // their exact pre-FR-77 meaning; the cells carry the whole matrix.
    #[allow(unused_mut)]
    let mut video_cells: Vec<VideoCell> = Vec::new();

    #[cfg(feature = "openh264-encoder")]
    {
        codecs.push("h264".into());
        hw_encoders.push("openh264-sw".into());
        // Software by definition — needs no driver, so it is a cell even when
        // the hardware probes are not run.
        video_cells.push(VideoCell::new(
            VideoCodec::H264,
            VideoBackend::Openh264,
            &[ChromaFormat::Yuv420],
            false,
        ));
    }

    #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
    if run_hw_probes {
        // H.264: enumeration is sufficient. If any H.264 MFT
        // enumerates the cascade always succeeds (at worst it falls
        // through to the default-adapter SW MFT via
        // CLSID_MSH264EncoderMFT); runtime activation failure would
        // be caught by open_default's triple-fallback (MF → openh264
        // → Noop). No probe needed.
        if let Ok(adapters) = super::mf::probe_adapter_count()
            && adapters > 0
        {
            hw_encoders.push("mf-h264-hw".into());
            // FR-77 — the cell must say whether the cascade lands on
            // silicon, and only an activation knows (the legacy label above
            // is enumeration-only and says `-hw` even for the SW MFT).
            let probe = activates(CodecProbe::H264);
            if !matches!(probe, ProbeResult::Failed) {
                video_cells.push(VideoCell::new(
                    VideoCodec::H264,
                    VideoBackend::MediaFoundation,
                    &[ChromaFormat::Yuv420],
                    matches!(probe, ProbeResult::Hardware),
                ));
            }
        }

        let allow_sw = allow_sw_heavy_override();
        let advertise = |r: ProbeResult| -> bool {
            matches!(r, ProbeResult::Hardware)
                || (allow_sw && matches!(r, ProbeResult::SoftwareOnly))
        };

        // HEVC: enumeration + real activation probe. MFTs that
        // enumerate but fail ActivateObject (driver/adapter
        // mismatches, missing HEVC Video Extension) would poison a
        // negotiated session — the track is bound to video/HEVC
        // before the encoder opens, so failure means black video not
        // fallback-decode. Gate advertising on a successful HW probe;
        // SW-only paths are dropped so H.264 wins negotiation
        // (mediasoup-screenshare-grade quality on iGPU hosts).
        if let Ok(adapters) = super::mf::probe_hevc_adapter_count()
            && adapters > 0
        {
            let probe = activates(CodecProbe::Hevc);
            if advertise(probe) {
                codecs.push("h265".into());
                hw_encoders.push("mf-h265-hw".into());
                video_cells.push(VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::MediaFoundation,
                    &[ChromaFormat::Yuv420],
                    matches!(probe, ProbeResult::Hardware),
                ));
            }
        }

        // AV1: same reasoning as HEVC, with sharper impact — the
        // RTX 5090 Blackwell regression causes the NVIDIA AV1 MFT to
        // enumerate-and-fail on every activation on dev hardware
        // (see `Known Issues` in CLAUDE.md). Probe-at-startup
        // filters this out so the agent doesn't advertise a codec
        // it can't actually produce.
        if let Ok(adapters) = super::mf::probe_av1_adapter_count()
            && adapters > 0
        {
            let probe = activates(CodecProbe::Av1);
            if advertise(probe) {
                codecs.push("av1".into());
                hw_encoders.push("mf-av1-hw".into());
                video_cells.push(VideoCell::new(
                    VideoCodec::Av1,
                    VideoBackend::MediaFoundation,
                    &[ChromaFormat::Yuv420],
                    matches!(probe, ProbeResult::Hardware),
                ));
            }
        }
    }

    #[allow(unused_mut)]
    let mut transports: Vec<String> = Vec::new();
    // P7 — chroma formats the HEVC DC transport can emit (see the probe's
    // Ok arm below + AgentCaps::hevc_chroma). Stays empty when the ffmpeg
    // HEVC probe fails or the feature is off.
    #[allow(unused_mut)]
    let mut hevc_chroma: Vec<String> = Vec::new();

    // rc.77 — FFmpeg HEVC over DataChannel.
    //
    // **DEFAULT ON** since rc.107 — `ffmpeg_backend_enabled()` is an explicit
    // opt-OUT (`ROOMLERD_USE_FFMPEG=0`), not the rc.77 opt-IN this comment
    // used to describe. The flip was forced in the field: an MSI
    // MajorUpgrade WIPES the service env block, so the dropped `=1`
    // silently disabled HEVC fleet-wide (black canvas, rc.105→rc.106).
    //
    // Advertisement is still gated on a REAL `FfmpegEncoder::new_hevc`
    // probe at the standard resolution, so a host without working HW
    // HEVC falls back cleanly regardless of the flag. On success
    // advertise both the `h265` codec (additive to whatever
    // MF found) and the `data-channel-hevc` transport. The browser's
    // rc:session.request can then ask for codec=h265 + transport=
    // data-channel-hevc and `peer.rs::media_pump` will route to the
    // HEVC DC pump.
    //
    // Pre-flight WebCodecs spike (2026-05-26) confirmed Chrome + Edge
    // decode Annex-B no-description HEVC. Gate 0 smoke (2026-05-29)
    // confirmed hevc_qsv works on Iris Xe Tiger Lake AND hevc_nvenc
    // works on RTX 5090 Blackwell — the two boxes MF was broken on.
    #[cfg(feature = "ffmpeg-encoder")]
    if run_hw_probes && crate::encode::ffmpeg::available() {
        // `name()` is on the `VideoEncoder` trait — need the trait in
        // scope at the call site for method-resolution.
        use super::VideoEncoder;
        use crate::encode::ffmpeg::FfmpegEncoder;

        // FR-77 — cells this build will not even TRY (the kill switch), and
        // whether a QSV open proves hardware on this build (see
        // `qsv_is_hardware_by_construction`).
        let deny = denied_cells();
        let qsv_hw = FfmpegEncoder::qsv_is_hardware_by_construction();
        if !deny.is_empty() {
            tracing::info!(denied = ?deny, "caps probe: cells on the denylist are not opened");
        }

        // rc.83 — probe vp9_qsv to surface in caps + heartbeat whether
        // this host can use Intel HW VP9. The transport advertisement
        // (`data-channel-vp9-444`) stays gated on the libvpx probe
        // above — both encoder paths emit the same VP9 bitstream that
        // the same browser worker decodes; only the encoder source
        // differs. The runtime peer.rs dispatch picks vp9_qsv at
        // session-establish time when this probe passed AND the host
        // didn't request 4:4:4 chroma (which vp9_qsv doesn't support).
        {
            let start_vp9 = std::time::Instant::now();
            match crate::encode::ffmpeg::FfmpegEncoder::new_vp9(PROBE_WIDTH, PROBE_HEIGHT) {
                Ok(enc) => {
                    let name = enc.name();
                    drop(enc);
                    tracing::info!(
                        encoder = name,
                        elapsed_ms = start_vp9.elapsed().as_millis(),
                        "caps probe: ffmpeg VP9 (vp9_qsv) encoder activates — runtime peer dispatch will prefer it over libvpx SW on data-channel-vp9-444 sessions"
                    );
                    hw_encoders.push(format!("ffmpeg-{name}"));
                    // FR-77 — the VP9 cell. 4:4:4 (profile 1) is attempted
                    // when the FFmpeg source matrix allows it for this name
                    // and the cell is not denylisted; today the open asks for
                    // planar yuv444p, which vp9_qsv refuses (it wants packed
                    // VUYX) — an honest failure until P3 teaches the pump
                    // that format. The session pump keeps vp9_qsv 4:2:0-only
                    // regardless (`peer.rs`).
                    let mut chroma = vec![ChromaFormat::Yuv420];
                    if let Some((cell_codec, backend)) = VideoBackend::from_ffmpeg_name(name) {
                        if attempt_444
                            && ffmpeg_444_capable(name)
                            && !cell_denied(&deny, name, ChromaFormat::Yuv444)
                        {
                            match FfmpegEncoder::new_named_probe(
                                name,
                                PROBE_WIDTH,
                                PROBE_HEIGHT,
                                true,
                            ) {
                                Ok(e) => {
                                    drop(e);
                                    chroma.push(ChromaFormat::Yuv444);
                                }
                                Err(e) => {
                                    tracing::debug!(encoder = name, %e, "caps probe: 4:4:4 cell did not open")
                                }
                            }
                        }
                        video_cells.push(VideoCell::new(cell_codec, backend, &chroma, qsv_hw));
                    }
                    // P4 — measure whether THIS host's vp9_qsv honours
                    // runtime forced IDRs, per low_power mode. Hosts that
                    // do get GOP 64800 + on-demand-only keys (kills the
                    // residual ~1 Hz natural-key pulse on VP9-over-DC);
                    // hosts that don't keep the rc.219 containment. Escape
                    // hatch ROOMLERD_VP9_QSV_IDR_PROBE=0.
                    if tunnel_core::env::node_env("VP9_QSV_IDR_PROBE").as_deref() != Some("0") {
                        let t_idr = std::time::Instant::now();
                        if let Some((lp1, lp0)) =
                            crate::encode::ffmpeg::FfmpegEncoder::probe_and_cache_vp9_qsv_idr()
                        {
                            tracing::info!(
                                honors_low_power = lp1,
                                honors_vme = lp0,
                                elapsed_ms = t_idr.elapsed().as_millis(),
                                "caps probe: vp9_qsv runtime-IDR verdict (either true → long GOP + on-demand keys; both false → GOP-60 containment)"
                            );
                        }
                    } else {
                        tracing::info!(
                            "caps probe: vp9_qsv IDR probe disabled (ROOMLERD_VP9_QSV_IDR_PROBE=0) — keeping GOP-60 containment"
                        );
                    }
                }
                Err(e) => {
                    tracing::info!(
                        %e,
                        elapsed_ms = start_vp9.elapsed().as_millis(),
                        "caps probe: no ffmpeg VP9 hardware encoder opened (vp9_qsv, vp9_vaapi: NVIDIA host, Intel without QSV, no VAAPI device, or a driver issue) — VP9 sessions stay on libvpx SW"
                    );
                }
            }
        }

        // FR-77 — the MATRIX pass for HEVC / AV1 / H.264. Every backend in
        // cascade order is opened (not just the first that works) so
        // `video_cells` carries the host's whole encoder × chroma matrix, and
        // every winner the FFmpeg source matrix says can do 4:4:4 is re-opened
        // in that format — asked for, never asserted by name (P7 used to
        // advertise HEVC 4:4:4 for `hevc_nvenc` without opening it). The
        // legacy fields (`codecs`, `transports`, `hw_encoders`, `hevc_chroma`)
        // keep their exact pre-FR-77 meaning: the FIRST backend in cascade
        // order that opens, because a session still cascades in that order
        // and a viewer older than FR-77 reads nothing else.
        //
        // P2 (Parsec-class plan) — H.264 over DataChannel joins the reliable-
        // DC + WebCodecs + canvas pipeline (the RTP track + <video> path stays
        // as the universal fallback). The bitstream is Annex-B with in-band
        // SPS/PPS — the contract the HEVC path ships. `ROOMLERD_DC_H264=0`
        // stops that advertisement without a rebuild; the H.264 cells are
        // then not probed either (a cell nobody can negotiate is noise).
        let dc_h264 = tunnel_core::env::node_env("DC_H264").as_deref() != Some("0");
        for codec in [VideoCodec::Hevc, VideoCodec::Av1, VideoCodec::H264] {
            if codec == VideoCodec::H264 && !dc_h264 {
                tracing::info!(
                    "caps probe: data-channel-h264 advertisement disabled (ROOMLERD_DC_H264=0)"
                );
                continue;
            }
            let start = std::time::Instant::now();
            let mut winner: Option<&'static str> = None;
            let mut winner_has_444 = false;
            for name in FfmpegEncoder::cascade_names(codec) {
                // A table name outside the vocabulary would open and then
                // advertise nothing; `every_cascade_name_is_in_the_cell_vocabulary`
                // makes that a test failure rather than a silent hole.
                let Some((cell_codec, backend)) = VideoBackend::from_ffmpeg_name(name) else {
                    continue;
                };
                // FR-77 P4 — the denylist is the kill switch for BOTH chroma
                // forms. Until this arm it gated only the 4:4:4 open, so
                // `hevc_vaapi:yuv420` in `encoder_cells_deny` still opened the
                // cell (measured on jupiter): an operator's one lever against
                // a driver that faults on open did nothing for 4:2:0.
                if cell_denied(&deny, name, ChromaFormat::Yuv420) {
                    tracing::info!(
                        encoder = name,
                        "caps probe: 4:2:0 cell on the denylist — not opened, not advertised"
                    );
                    continue;
                }
                let t = std::time::Instant::now();
                match FfmpegEncoder::new_named_probe(name, PROBE_WIDTH, PROBE_HEIGHT, false) {
                    Ok(enc) => {
                        drop(enc);
                        let mut chroma = vec![ChromaFormat::Yuv420];
                        if attempt_444
                            && ffmpeg_444_capable(name)
                            && !cell_denied(&deny, name, ChromaFormat::Yuv444)
                        {
                            match FfmpegEncoder::new_named_probe(
                                name,
                                PROBE_WIDTH,
                                PROBE_HEIGHT,
                                true,
                            ) {
                                Ok(e) => {
                                    drop(e);
                                    chroma.push(ChromaFormat::Yuv444);
                                }
                                Err(e) => tracing::info!(
                                    encoder = name,
                                    %e,
                                    "caps probe: 4:4:4 cell did not open — advertising 4:2:0 only"
                                ),
                            }
                        }
                        let hw = match backend {
                            VideoBackend::Qsv => qsv_hw,
                            _ => true,
                        };
                        tracing::info!(
                            encoder = name,
                            chroma = ?chroma.iter().map(|c| c.wire()).collect::<Vec<_>>(),
                            hw,
                            elapsed_ms = t.elapsed().as_millis(),
                            "caps probe: ffmpeg encoder cell opened"
                        );
                        if winner.is_none() {
                            winner = Some(name);
                            winner_has_444 = chroma.contains(&ChromaFormat::Yuv444);
                        }
                        video_cells.push(VideoCell::new(cell_codec, backend, &chroma, hw));
                    }
                    Err(e) => {
                        // A backend the host lacks failing is the matrix doing
                        // its job — DEBUG, like the cascade's own candidates.
                        tracing::debug!(encoder = name, %e, "caps probe: ffmpeg encoder cell did not open");
                    }
                }
            }
            let elapsed_ms = start.elapsed().as_millis();
            match (codec, winner) {
                (VideoCodec::Hevc, Some(name)) => {
                    tracing::info!(
                        encoder = name,
                        elapsed_ms,
                        "caps probe: ffmpeg HEVC encoder activates — advertising h265 + data-channel-hevc"
                    );
                    if !codecs.iter().any(|c| c == "h265") {
                        codecs.push("h265".into());
                    }
                    transports.push("data-channel-hevc".into());
                    hw_encoders.push(format!("ffmpeg-{name}"));
                    // P7 — the session's 4:4:4 (Rext) path tries `hevc_nvenc`
                    // only, so the legacy field says 4:4:4 only when THAT
                    // backend won AND its 4:4:4 open succeeded just now.
                    hevc_chroma.push("yuv420".into());
                    if name == "hevc_nvenc" && winner_has_444 {
                        hevc_chroma.push("yuv444".into());
                    }
                }
                (VideoCodec::Hevc, None) => tracing::warn!(
                    elapsed_ms,
                    "caps probe: ffmpeg HEVC encoder failed to init — NOT advertising data-channel-hevc"
                ),
                (VideoCodec::Av1, Some(name)) => {
                    tracing::info!(
                        encoder = name,
                        elapsed_ms,
                        "caps probe: ffmpeg AV1 encoder activates — advertising av1 + data-channel-av1"
                    );
                    if !codecs.iter().any(|c| c == "av1") {
                        codecs.push("av1".into());
                    }
                    transports.push("data-channel-av1".into());
                    hw_encoders.push(format!("ffmpeg-{name}"));
                }
                (VideoCodec::Av1, None) => tracing::info!(
                    elapsed_ms,
                    "caps probe: ffmpeg AV1 encoder not available (no AV1 encode silicon on this host) — NOT advertising data-channel-av1"
                ),
                (VideoCodec::H264, Some(name)) => {
                    tracing::info!(
                        encoder = name,
                        elapsed_ms,
                        "caps probe: ffmpeg H.264 encoder activates — advertising data-channel-h264"
                    );
                    transports.push("data-channel-h264".into());
                    hw_encoders.push(format!("ffmpeg-{name}"));
                }
                (VideoCodec::H264, None) => tracing::info!(
                    elapsed_ms,
                    "caps probe: ffmpeg H.264 HW encoder not available — H.264 sessions stay on the RTP track"
                ),
                (VideoCodec::Vp9, _) => {}
            }
        }
    }

    #[cfg(feature = "vp9-444")]
    if run_hw_probes {
        // Phase Y.4 caps probe (Y.runtime-encoder rewrite landed,
        // 0.1.47). Try to instantiate the libvpx encoder at a probe
        // resolution; on success advertise both the transport and
        // the encoder label, on failure stay silent so no session
        // ever negotiates onto a broken path. The probe runs once
        // per agent process via the OnceLock cache.
        let start = std::time::Instant::now();
        match crate::encode::libvpx::Vp9Encoder::new(PROBE_WIDTH, PROBE_HEIGHT) {
            Ok(enc) => {
                drop(enc);
                tracing::info!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "caps probe: vp9-444 libvpx encoder activates — advertising data-channel-vp9-444 transport"
                );
                transports.push("data-channel-vp9-444".into());
                hw_encoders.push("libvpx-vp9-444-sw".into());
                // FR-77 — the libvpx cell: profile 0 (4:2:0) is opened for
                // real too, so the cell claims only what opened.
                let mut chroma = Vec::new();
                match crate::encode::libvpx::Vp9Encoder::new_with_fps_chroma(
                    PROBE_WIDTH,
                    PROBE_HEIGHT,
                    30,
                    crate::encode::libvpx::Vp9Chroma::Yuv420,
                ) {
                    Ok(e) => {
                        drop(e);
                        chroma.push(ChromaFormat::Yuv420);
                    }
                    Err(e) => tracing::debug!(%e, "caps probe: libvpx 4:2:0 cell did not open"),
                }
                chroma.push(ChromaFormat::Yuv444);
                video_cells.push(VideoCell::new(
                    VideoCodec::Vp9,
                    VideoBackend::Libvpx,
                    &chroma,
                    false,
                ));
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    elapsed_ms = start.elapsed().as_millis(),
                    "caps probe: vp9-444 libvpx encoder failed to init — NOT advertising"
                );
            }
        }
    }

    // File-DC verbs: deliberately NOT computed here. `detect()` assigns them
    // from `files_caps()` in the daemon — `browse` follows a config flag the
    // caps-probe child never loads (#1672); see that function.

    // rc.61 — surface VP9 chroma format in caps so the browser worker
    // picks the right codec string for VideoDecoder.configure(). Empty
    // when vp9-444 transport isn't advertised (so we don't lie to the
    // client about a format we don't emit).
    let vp9_chroma: String = if transports.iter().any(|t| t == "data-channel-vp9-444") {
        #[cfg(feature = "vp9-444")]
        {
            crate::encode::libvpx::vp9_chroma_from_env()
                .as_str()
                .to_string()
        }
        #[cfg(not(feature = "vp9-444"))]
        {
            String::new()
        }
    } else {
        String::new()
    };

    // Audio track advertisement. Only when the `audio` feature is
    // compiled in do we offer a WebRTC Opus track (system/desktop
    // audio, opt-in per session). The browser reads this list to decide
    // whether to set `audio_enabled` in `rc:session.request`; an empty
    // list means the agent won't add an audio track at all. Mirrors the
    // vp9-444 pattern (advertise a capability only when the code path
    // that fulfils it is actually built). No runtime probe: a failed
    // audio-device open leaves the track silent and tells the controller
    // why (`rc:audio-unavailable`, FR-97 P3c-1). What the OS cannot
    // capture at all is taken out by `with_honest_words` (FR-97 P0c).
    #[allow(unused_mut)]
    let mut audio: Vec<String> = Vec::new();
    #[cfg(feature = "audio")]
    {
        audio.push("opus".into());
    }

    // Remote Apps verbs: deliberately NOT computed here. `detect()` assigns
    // them from `apps_caps()` in the daemon — see that function for why the
    // caps-probe child must never be the one to answer.

    // Clipboard protocol-v2 flags. Advertised purely on feature
    // presence (like `supports_clipboard`): the handlers for ack /
    // subscribe / image framing are compiled in with the `clipboard`
    // feature and degrade at runtime (a headless host without a
    // clipboard no-ops the DC exactly as v1 did). The browser gates
    // its auto-sync engine + image paths on these values.
    let clipboard: Vec<String> = if cfg!(feature = "clipboard") {
        let mut c: Vec<String> = vec![
            "ack".into(),
            "events".into(),
            "images".into(),
            // v2.1 — html lane: formatted text + web-hosted images
            // survive the round-trip (CF_HTML / text/html both ways).
            "html".into(),
        ];
        // v2.2 — native lane (RTF with embedded images). Windows-only:
        // the RTF read/write rides clipboard-win's raw format API.
        if cfg!(target_os = "windows") {
            c.push("native".into());
        }
        c
    } else {
        Vec::new()
    };

    // Keyboard-layout integration (rc.227) — status reporting +
    // manual set ride the control DC: Windows code in `input::layout`
    // behind enigo-input, and (FR-97 P3e) X11's in `input::layout_x11`,
    // which `with_honest_words` takes out where there is no X11 session.
    // The browser gates its layout chip + picker on these.
    let layout: Vec<String> = if cfg!(all(
        any(target_os = "windows", target_os = "linux"),
        feature = "enigo-input"
    )) {
        vec!["report".into(), "set".into()]
    } else {
        Vec::new()
    };

    // What the OS has actually granted, not what we were compiled with.
    // See `AgentCaps::permissions`: `None` (a pre-rc.454 agent) and
    // `Some([])` mean opposite things, so this is always `Some` here.
    let mut permissions: Vec<String> = Vec::new();
    if !gui_session_available() {
        // THIRD state, distinct from granted and denied: this process is not
        // in a GUI login session (macOS's root LaunchDaemon), so capture and
        // input are impossible regardless of any grant. Without saying so, a
        // mesh-only daemon reports "holds neither permission" and the device
        // list tells the operator to go fix something that is not broken.
        permissions.push("no-gui-session".into());
    } else {
        if capture_permission_granted() {
            permissions.push("screen-capture".into());
        }
        if input_permission_granted() {
            permissions.push("input".into());
        }
    }

    AgentCaps {
        hw_encoders,
        codecs,
        // Was `cfg!(feature = "enigo-input")` — a COMPILE-TIME constant, so a
        // Mac with Accessibility denied still advertised working input while
        // silently dropping every event. The feature must be compiled in AND
        // the OS must have granted it.
        has_input_permission: cfg!(feature = "enigo-input")
            && gui_session_available()
            && input_permission_granted(),
        permissions: Some(permissions),
        supports_clipboard: cfg!(feature = "clipboard"),
        supports_file_transfer: true,
        max_simultaneous_sessions: rc_max_sessions(),
        transports,
        // FR-17 — this build frames every DataChannel message, so a
        // receiver can reassemble without relying on the channel being
        // ordered. Advertised unconditionally: it is a property of the
        // code, not of the host or its hardware.
        video: video_features(),
        // Empty in the child's struct BY DESIGN; `detect()` fills it in the
        // daemon (`files_caps`). A test locks this.
        files: Vec::new(),
        vp9_chroma,
        hevc_chroma,
        audio,
        // Empty in the child's struct BY DESIGN; `detect()` fills it in the
        // daemon (`apps_caps`). A test locks this.
        apps: Vec::new(),
        clipboard,
        layout,
        video_cells,
        // Stamped by the PARENT after the child reports (`child::probe`);
        // the driver-free fallback has no probe to time.
        probe_ms: None,
        probe_cached: false,
        // P6 — the InputArbiter runs on every build (injection degrades to
        // Noop without enigo-input, but the arbitration/floor semantics
        // hold), so the server can safely lift the P3 single-INPUT-holder
        // downgrade for this agent.
        input: vec!["arbiter".into(), "exclusive".into(), "ghost-cursor".into()],
        // Multi-org — this agent honours `rc:agent.join_org` (enroll into an
        // additional org from a pushed token, no restart). Build-independent:
        // the enroll + config paths are in every flavour.
        multi_org: vec!["join".into()],
        // FR-67 P7 — `None` HERE on purpose: whether an update is acted on
        // depends on the connection (primary or secondary org) and on the
        // daemon's updater, neither of which the probe child knows.
        // `signaling::stub_caps` fills it at every announcement.
        update_mode: None,
        // Fleet RPC — build-independent (the exec engine is std process
        // spawning, no feature-gated backend). Advertising the capability
        // says only "this agent understands the verbs": the org kill-switch,
        // the device's ExecPolicy, and the agent's own `exec_enabled` config
        // key all still have to say yes before anything runs.
        rpc: rpc_caps(),
        // FR-85 P3b — empty HERE on purpose: `detect()` is memoized and
        // config-blind, while the record words follow the owner's LIVE gate.
        // `signaling::stub_caps` fills them at every announcement (the hello,
        // and a heartbeat that re-announces when they change).
        record: Vec::new(),
        // FR-93 P2b — `None` HERE on purpose, like `record`: the desktop brief
        // is live (a login or a logout changes it) and reads logind, which has
        // no business in the probe child. `stub_caps` fills it from the
        // daemon's own refresher at every announcement.
        desktop: None,
        // FR-101 P2b — `None` HERE for the same reason: the owner's floor is
        // live config, and `stub_caps` fills it at every announcement.
        session_policy: None,
        // FR-97 P0c — empty HERE: the honest "no" is the daemon's
        // (`with_honest_words`), like the config lists above.
        unavailable: Default::default(),
    }
}

/// FR-56 — the Remote Apps verbs, assigned by [`detect`] in the DAEMON and
/// never computed inside `compute_caps`.
///
/// Two reasons, one measured in the review of #1667. On a caps-cache MISS the
/// hello takes the caps-probe child's struct wholesale, and the child loads
/// no config — so an apps block inside `compute_caps` advertised `list` on a
/// device whose owner had set `[virtual_desktop_apps] enabled = false`, on
/// every release's first boot and on every boot of a host with no hardware
/// cell (a no-hardware answer is never cached). And the child exists to
/// contain untrusted driver code; a privilege-dropped `loginctl`/`wmctrl`
/// walk of somebody's login session has no business in it.
///
/// `list` / `focus` / `launch` are advertised only when this process can
/// manage a desktop right now (a Linux virtual desktop or a logged-in
/// X11/Xwayland session, or Windows) AND the operator hasn't disabled it; the
/// browser gates its Apps menu on this list, and older agents omit the field.
/// `status` (AC10) says "this build has a Remote Apps backend and answers
/// `rc:apps.list` honestly": with the list when there is a desktop, with
/// `unavailable: {code, reason}` when there is not. It is what lets the viewer
/// show WHY instead of hiding the button — and it matters because this struct
/// is a boot-time snapshot (`detect` memoizes it), so `list` absent here can
/// simply mean nobody had logged in yet when the daemon started. The reply is
/// live; the hello is not.
fn apps_caps() -> Vec<String> {
    apps_caps_for(&crate::apps::apps_config())
}

/// [`apps_caps`] against an explicit config — testable without installing the
/// process-global one, and the same seam the reply path answers through.
fn apps_caps_for(cfg: &crate::apps::VirtualDesktopAppsConfig) -> Vec<String> {
    let mut apps: Vec<String> = Vec::new();
    if crate::apps::has_backend() {
        apps.push("status".into());
    }
    if crate::apps::availability_for(cfg).is_ok() {
        apps.push("list".into());
        apps.push("focus".into());
        apps.push("launch".into());
    }
    apps
}

/// #1672 — the file-DC verbs, assigned by [`detect`] in the DAEMON and never
/// computed inside `compute_caps`.
///
/// The same hole #1667 closed for `apps`. On a caps-cache MISS the hello takes
/// the caps-probe child's struct wholesale, and the child loads no config, so
/// a files block inside `compute_caps` read `REMOTE_BROWSE_ENABLED` at its
/// built-in default (`true`) and advertised `browse` on a device whose owner
/// had set `enable_remote_browse = false` (or `ROOMLERD_DISABLE_BROWSE`) — on
/// every release's first boot and on every boot of a host with no hardware
/// cell (a no-hardware answer is never cached). The `files:dir` handler still
/// refused, so the controller drew a Browse affordance that failed when used:
/// a false capability, not an access hole.
///
/// `upload` / `download` / `download-folder` are always built into this agent;
/// `resume` (rc.19) says the agent stages uploads under
/// `<dest_dir>/.roomler-partial/<id>/` and can resume a mid-flight transfer
/// after a DC drop, and a browser that does not see it keeps the rc.18
/// fail-fast path. `browse` alone follows the config. Old browsers that see
/// an empty `files` list fall back to `supports_file_transfer` (upload-only),
/// which is why the daemon must fill the list and not merely append to it.
///
/// A boot-time snapshot in `detect()` is the honest home: the flag is stored
/// once by `main.rs::run_cmd` before the signalling loop starts and is not
/// live (`config_surface.rs` says so; no LocalAPI `ConfigSet` re-seeds it) —
/// unlike `record`, whose gate IS live and is therefore filled at every
/// announcement by `signaling::stub_caps`.
fn files_caps() -> Vec<String> {
    files_caps_for(crate::files::is_remote_browse_enabled())
}

/// [`files_caps`] against an explicit flag — testable without touching the
/// process-global one (a test that flipped it would leak into every other
/// test in the process).
fn files_caps_for(browse_enabled: bool) -> Vec<String> {
    let mut files = vec![
        "upload".to_string(),
        "download".to_string(),
        "download-folder".to_string(),
        "resume".to_string(),
    ];
    if browse_enabled {
        files.push("browse".to_string());
    }
    files
}

/// Fleet-RPC + roomler-SSH verb capabilities.
///
/// `exec` / `originate` are build-independent (the exec engine is std process
/// spawning). `ssh` is NOT: it is gated on the `ssh-server` feature, because
/// `rc:ssh.grant` reaching a build without the server would be recorded by
/// nobody and the caller would hang against a port that answers nothing — the
/// exact failure the capability list exists to prevent.
///
/// Advertising a verb says only "this agent understands it". The org
/// kill-switch, the device's policy and the agent-local config key all still
/// have to say yes before anything happens.
fn rpc_caps() -> Vec<String> {
    use roomler_ai_remote_control::models::RpcCap;

    // Named by VARIANT, not by string literal: the wire spelling lives in
    // exactly one place (`RpcCap::wire`) that both this producer and every
    // server-side consumer go through, so the two can no longer drift.
    // `Config` is unconditional: understanding the frame is a property of the
    // BUILD, not of any feature or local setting. Whether the device obeys it
    // is a separate question answered by `remote_config_enabled` and by
    // whether the frame arrived on the primary org's socket — advertising
    // here must not imply either, or the server would read "will comply" from
    // a verb that only means "will parse".
    // `ConfigReport` rides alongside `Config` in THIS build, but it is a
    // separate verb because rc.457/rc.458 shipped `config` alone: those agents
    // apply a pushed config and never say a word about it. A server that read
    // "reports back" out of `config` would wait forever for an answer from
    // most of the fleet — the identical trap `ssh` / `ssh-consent` exists to
    // avoid, recurring exactly as that doc predicted it would.
    // FR-52 — `external-access` is unconditional for the same reason `Config`
    // is: it says this build UNDERSTANDS cross-org access, which for the
    // server means one specific thing — that a consent prompt raised by this
    // agent can tell the person at the machine the controller is from OUTSIDE
    // their organization. That is why the server gates the ADMIN APPROVAL on
    // the verb and not just the session: approving a device that cannot say it
    // would put a promise on screen the device does not keep, and consent
    // given under it would not be informed consent.
    //
    // ⚠️ It says NOTHING about `external_access_enabled` (gate 3). Deriving
    // the verb from the opt-in would collapse "too old to be approved" and
    // "approved but opted out" into one state, and those have different fixes
    // — the first needs an agent update, the second a line in the device's own
    // config. The fleet view renders them apart, which it can only do because
    // these two facts arrive separately.
    let mut caps = vec![
        RpcCap::Exec,
        RpcCap::Originate,
        RpcCap::Config,
        RpcCap::ConfigReport,
        RpcCap::ExternalAccess,
        RpcCap::SharedSessionLease,
    ];
    // FR-97 P5a — a Linux or macOS build runs `console_user` as the person at
    // its screen: SSH's account mode, and the `run_as` of `rc:rpc.exec`,
    // which the server sends only to a connection advertising this. A
    // property of the BUILD, like `exec`: whether anyone is at the screen is
    // asked at each command. Windows' `console_user` is its service's.
    #[cfg(unix)]
    caps.push(RpcCap::ConsoleUser);
    if cfg!(feature = "ssh-server") {
        caps.push(RpcCap::Ssh);
        caps.push(RpcCap::SharedSshStream);
        // P5d. Distinct from `ssh` because agents rc.419 and earlier advertise
        // `ssh` while silently ignoring `SshPolicy.consent_mode` — the server
        // refuses to store a non-auto consent policy for a device that cannot
        // honour it, rather than hand an admin a rule that reads as enforced
        // and isn't.
        caps.push(RpcCap::SshConsent);
        // FR-83. This build answers every `rc:ssh.grant` with
        // `rc:ssh.grant_ack` once the grant is redeemable, so the server may
        // hold the caller for it. A property of the BUILD, like `ssh`: the
        // ack is sent even when the device refuses — that is the point.
        caps.push(RpcCap::SshGrantAck);
        // FR-90 P3-8-2a. This build's SSH server holds an agent session's
        // grant (`one_command`) to ONE `exec` and nothing else. Distinct from
        // `ssh`, its prefix, because every build before it would read past
        // the field and serve that session's key a shell: the server sends a
        // session's grant only to a device that says this. A property of the
        // BUILD; the SYSTEM service says it for itself, when it publishes.
        caps.push(RpcCap::SshOneCommand);
    }
    // FR-52 P4 — this build can ADMIT an external session: bind it to a
    // verified login, check its offer's MAC, seal its answer. The server opens
    // an external session only on a device that says so, because one that
    // cannot would ignore `Request.external` and serve an outsider as an
    // ordinary controller — the password proven but never bound to anything.
    // A property of the BUILD, like `external-access`: gate 3 is the device's
    // own, and is read when the request arrives.
    if cfg!(feature = "external-access") {
        caps.push(RpcCap::ExternalSession);
    }
    // FR-100 P1b — this build signs its session answer with its device key
    // when the offer asks (a nonce). A property of the BUILD, in every build:
    // an enrollment that could not keep a key says so with an empty
    // `peer_auth_key` on its hello, and signs nothing.
    caps.push(RpcCap::PeerAuth);
    // FR-19 — advertise the org-relay SERVER only after the opted-in
    // listener actually bound (configuration alone is not readiness). The server never installs a session
    // on a device that does not advertise this, so a device that has not opted
    // in is simply never asked — and a build without the overlay features has
    // no relay to advertise at all.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    if crate::relay_server::listening_port().is_some() {
        caps.push(RpcCap::RelayServer);
    }
    // FR-40 — a build with an overlay surface can retire its overlay key on
    // order. A property of the BUILD, like `config`: the device may still
    // refuse (`overlay_key_rotation=false`), and says so in its report.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    caps.push(RpcCap::KeyRotate);
    // FR-90 — a build that runs agent sessions answers `rc:hive.start` and
    // reports with `rc:hive.state`. A property of the BUILD, like `ssh`: the
    // device still refuses unless its owner switched `hive_enabled` on, and
    // says so in the ack. Every `hive_host` build: Linux, macOS, Windows.
    #[cfg(hive_host)]
    caps.push(RpcCap::Hive);
    // FR-90 P0d-2 — and serves a session's transcript to a browser over a
    // viewer peer: answers `rc:hive.view.grant` before the browser dials.
    #[cfg(hive_host)]
    caps.push(RpcCap::HiveView);
    // FR-90 P1e — and understands a session's core memory (`rc:hive.memory`).
    // A property of the BUILD: whether a session ever sees it is the device's
    // own `hive_core_memory`, default off.
    #[cfg(hive_host)]
    caps.push(RpcCap::HiveMemory);
    // FR-90 P1j — and mirrors terminal sessions its people adopted. NOT a
    // property of the build alone: advertised only while the device's owner
    // allows it (`hive_adopt`), and the server honours an offer only from a
    // connection that advertises it.
    #[cfg(hive_host)]
    if crate::hive::adopt_enabled() {
        caps.push(RpcCap::HiveAdopt);
    }
    // FR-90 P2c-3 — and holds copies of its owner's sessions run elsewhere:
    // answers `rc:hive.replica.join`. Not a property of the build alone:
    // only while the owner's `hive_replica` is on and the store is open, and
    // on the primary enrollment's connection only (the hello strips both
    // words from any other). `hive-archive` only ever with it.
    #[cfg(hive_host)]
    if crate::hive::replica_enabled() {
        caps.push(RpcCap::HiveReplica);
    }
    #[cfg(hive_host)]
    if crate::hive::archive_enabled() {
        caps.push(RpcCap::HiveArchive);
    }
    // FR-90 P2i-1 — and answers a search over those copies, as an archive
    // replica: `hive-search`, only with `hive-archive` and `hive-replica`,
    // which the device's own gate asks again at each grant.
    #[cfg(hive_host)]
    if crate::hive::archive_enabled() && crate::hive::replica_enabled() {
        caps.push(RpcCap::HiveSearch);
    }
    // FR-90 P2d-3b — and carries the replica stream: serves a member's grant
    // as a source and follows a dial as a member. While its store is open,
    // whatever its owner says of holding copies: a primary serves its own
    // sessions' members. Stripped from any connection but the primary
    // enrollment's (the hello), like every Hive word.
    #[cfg(hive_host)]
    if crate::hive::stream_enabled() {
        caps.push(RpcCap::HiveStream);
    }
    // FR-90 P2e-2 — and holds a leased session to the server's word on each
    // connection (`rc:hive.lease`): after a restart or a reconnect it runs
    // one only once the server has said so there. A property of the BUILD,
    // like `hive`, and kept on a secondary org's connection like it: that
    // org's Hive frames are refused there either way.
    #[cfg(hive_host)]
    caps.push(RpcCap::HiveLease);
    // FR-90 P2e-5c — and takes part in a promotion at either end: as the
    // primary it drains (`rc:hive.drain`), as the member it prepares
    // (`rc:hive.prepare`) and takes the session over from its copy at the
    // move (`rc:hive.move`), and its joins take where each superseded fence
    // ended (P2e-5b). A property of the BUILD, like `hive-lease`: the device
    // still refuses a drain or a prepare its own gates do not pass, in its
    // own words, and a secondary org's connection refuses both.
    #[cfg(hive_host)]
    caps.push(RpcCap::HivePromote);
    // FR-90 P2f-1a — and takes part in a teleport, a move to a device that
    // holds no copy yet: as the target, a teleport's prepare passes every
    // start gate but the copy and admits that one session's join, whatever
    // `hive_replica` says; as the primary, a join in the primary's role
    // checkpoints at once when no turn runs and says where its copy ends. A
    // property of the BUILD, like `hive-promote`, and kept on a secondary
    // org's connection like it: no placement chooses a teleport's target, and
    // that org's prepare and join are refused there either way.
    #[cfg(hive_host)]
    caps.push(RpcCap::HiveTeleport);
    // FR-90 P2f-3a — and starts a fork of a session it holds a copy of: a
    // start carrying `fork_of` takes the parent's last checkpoint under the
    // fork's ids and launches `--resume <parent> --fork-session --session-id
    // <fork>`. A property of the BUILD; a build before it would start the
    // fork empty.
    #[cfg(hive_host)]
    caps.push(RpcCap::HiveFork);
    // FR-90 P2f-4a — and makes a terminal session it adopted, whose terminal
    // ended here, a managed one: a start carrying `from_terminal` puts the
    // terminal's own history in place as the account it ran as, by this
    // device's record of whose terminal it was, and resumes it. A property of
    // the BUILD, Unix only: Windows adopts since FR-97 P4c, but putting a
    // terminal's history in place runs as the account through Unix tools. The
    // device's start gates still decide, `hive_enabled` first.
    #[cfg(all(hive_host, unix))]
    caps.push(RpcCap::HiveManage);
    // FR-90 P2g-1 — and purges a session on `rc:hive.purge`, answering per
    // part: its own copy, then as the session's account its state directory
    // and its checkpoints' refs. A property of the BUILD, on every platform
    // that runs sessions.
    #[cfg(hive_host)]
    caps.push(RpcCap::HivePurge);
    // FR-90 P2g-4a — and purges every session it holds on
    // `rc:hive.purge_all`, which its enrollment's removal sends. A property
    // of the BUILD, as `hive-purge` is.
    #[cfg(hive_host)]
    caps.push(RpcCap::HivePurgeAll);
    // #2294 — and finishes that purge before it exits on the removal's
    // goodbye (`hive::finish_removal_purge`), so the server's kick may tell
    // it. A property of the BUILD, as `hive-purge-all` is.
    #[cfg(hive_host)]
    caps.push(RpcCap::HivePurgeDrain);
    // ⚠️ FR-99's `privacy-*` words are NOT here: this list is memoized at boot
    // (`detect()`), and those follow the owner's live gate and the overlay
    // coming up. `signaling::stub_caps` adds them at every announcement.
    caps.into_iter().map(|c| c.wire().to_string()).collect()
}

/// Multi-user P3 — how many CONCURRENT remote-control sessions this agent
/// advertises (the server's `AgentBusy` gate enforces the value). Pinned to
/// 1 since v1; the whole capacity model (server gate, per-session
/// `AgentPeer`s, per-session consent/permissions) was already N-ready.
///
/// Default 2 — pair-working: each extra session runs its OWN capture +
/// encoder until the P5 shared-floor encoder lands, so weak-GPU hosts
/// (Iris-Xe-class) may prefer `rc_max_sessions = 1`; the DXGI
/// duplication app-limit (~4) bounds the useful ceiling — clamp at 8.
/// Concurrent-INPUT chaos is prevented server-side (one INPUT holder per
/// agent until the P6 arbitration modes land).
///
/// `ROOMLERD_RC_MAX_SESSIONS` env > `rc_max_sessions` config key
/// (bridged via the S2 fallback map) > built-in 2.
pub(crate) fn rc_max_sessions() -> u8 {
    tunnel_core::env::node_env("RC_MAX_SESSIONS")
        .and_then(|v| v.trim().parse::<u8>().ok())
        .map(|n| n.clamp(1, 8))
        .unwrap_or(2)
}

/// Codec to probe. We only probe codecs that fail closed on activation
/// error (HEVC + AV1 today); H.264 has a working triple-fallback path
/// and is not gated.
#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
#[derive(Debug, Clone, Copy)]
enum CodecProbe {
    /// FR-77 — probed for the CELL only (`video_cells` must say whether the
    /// cascade lands on silicon); the legacy `mf-h264-hw` label stays
    /// enumeration-gated as it always was.
    H264,
    Hevc,
    Av1,
}

/// Outcome of a codec probe. We split SW from HW because shipping
/// HEVC over the SW MFT (`HEVCVideoExtensionEncoder`) is a UX
/// regression vs negotiating H.264 with the host's HW H.264 path
/// (Intel QuickSync, NVENC, AMF). Two reasons: chroma artefacts at
/// low bitrate, and roughly 3x CPU cost vs HW H.264. Field reports
/// 2026-04-24 and 2026-04-26 from boxes where the IHV HEVC MFT
/// (Intel Hardware H265 Encoder MFT) fails ActivateObject 0x80004005
/// and the cascade falls to SW HEVC. Demoting those hosts out of
/// HEVC advertising forces the browser to negotiate H.264 where the
/// cascade lands on real HW.
#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeResult {
    /// Cascade landed on dedicated HW MFT — codec is safe to advertise.
    Hardware,
    /// Cascade activated, but only on the SW fallback (`backend="sw"`).
    /// Caller decides whether to advertise; default policy is to drop
    /// HEVC/AV1 when SW-only and let H.264 win negotiation.
    SoftwareOnly,
    /// No working encoder found at all. Caller MUST drop from caps.
    Failed,
}

/// Spin up the real MF encoder for `codec` at a tiny probe resolution,
/// inspect the resulting backend kind, then drop it. Logs the verdict
/// at info / warn so the cascade outcome is visible in startup logs.
#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
fn activates(codec: CodecProbe) -> ProbeResult {
    let start = std::time::Instant::now();
    let result = match codec {
        CodecProbe::H264 => super::mf::MfEncoder::new_h264(PROBE_WIDTH, PROBE_HEIGHT),
        CodecProbe::Hevc => super::mf::MfEncoder::new_hevc(PROBE_WIDTH, PROBE_HEIGHT),
        CodecProbe::Av1 => super::mf::MfEncoder::new_av1(PROBE_WIDTH, PROBE_HEIGHT),
    };
    let elapsed_ms = start.elapsed().as_millis();
    match result {
        Ok(enc) => {
            use super::VideoEncoder;
            let is_hw = enc.is_hardware();
            // Dropping `enc` triggers the worker's Shutdown cmd which
            // in turn runs MFShutdown + CoUninitialize on its thread.
            drop(enc);
            if is_hw {
                tracing::info!(
                    codec = ?codec,
                    elapsed_ms,
                    "caps probe: codec activates on HW — advertising"
                );
                ProbeResult::Hardware
            } else {
                tracing::warn!(
                    codec = ?codec,
                    elapsed_ms,
                    "caps probe: codec activates only on SW — NOT advertising (H.264 HW likely better). Set ROOMLERD_ALLOW_SW_HEAVY=1 to override."
                );
                ProbeResult::SoftwareOnly
            }
        }
        Err(e) => {
            tracing::warn!(
                codec = ?codec,
                %e,
                elapsed_ms,
                "caps probe: codec enumerates but does NOT activate — NOT advertising"
            );
            ProbeResult::Failed
        }
    }
}

/// Operator escape hatch: advertise HEVC/AV1 even when the cascade
/// only lands on SW. Off by default. Useful when the host has no
/// working H.264 HW path and SW HEVC is a strict improvement over
/// SW H.264 (rare but possible on machines without Intel QSV / NVENC
/// / AMF).
#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
fn allow_sw_heavy_override() -> bool {
    use tunnel_core::env::node_env;
    node_env("ALLOW_SW_HEAVY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Intersection + priority for codec negotiation (Phase 2 2B.2).
/// Takes the browser-advertised codec list + the agent's supported
/// codec list, returns the best codec both sides support.
///
/// Priority order: **av1 > h265 > vp9 > h264 > vp8**. AV1 + HEVC
/// cut 30-50% off the bitrate at equal quality vs H.264; VP9 is
/// closer to H.264 but natively supported in every WebRTC stack so
/// we prefer it over H.264 when available. H.264 is the universal
/// fallback.
///
/// Returns `"h264"` on empty inputs — maintains back-compat with
/// pre-2B.1 browsers that don't advertise anything.
pub fn pick_best_codec(browser_caps: &[String], agent_caps: &[String]) -> String {
    const PRIORITY: &[&str] = &["av1", "h265", "vp9", "h264", "vp8"];
    let browser_has = |c: &str| browser_caps.iter().any(|b| b.eq_ignore_ascii_case(c));
    let agent_has = |c: &str| agent_caps.iter().any(|a| a.eq_ignore_ascii_case(c));
    for candidate in PRIORITY {
        if browser_has(candidate) && agent_has(candidate) {
            return (*candidate).to_string();
        }
    }
    // Fallback — universal baseline. If the browser advertises nothing
    // (pre-2B.1 controller) we assume it decodes H.264.
    "h264".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-119 P1 — `fps-high` is off unless `ROOMLERD_FPS_HIGH=1`: until P2
    /// builds the grant, a viewer must not be offered a picker the agent can
    /// never honour. `chunk-framing` stays unconditional (FR-17).
    #[test]
    fn fps_high_is_not_advertised_by_default() {
        if tunnel_core::env::node_env("FPS_HIGH").is_some() {
            return; // a host that set it asked for it; nothing to check here
        }
        let features = video_features();
        assert!(features.iter().any(|f| f == "chunk-framing"));
        assert!(
            !features.iter().any(|f| f == crate::encode::frame_rate::CAP),
            "fps-high advertised with the switch unset: {features:?}"
        );
    }

    /// FR-84 D4 — the LocalAPI's read of the encoder matrix must never be
    /// what launches the probe. `summarize_cached` reads the `OnceLock` and
    /// reports `not_probed` while it is empty; a version that reached for
    /// `detect()` to have something to show would spawn the probe children
    /// from a control-surface poll on every host that has not connected yet
    /// — vendor driver code, run because someone opened the Overview.
    ///
    /// The lock is read DIRECTLY, not through `cached()`: a `cached()` that
    /// called `detect()` would fill the lock before `before` was taken and
    /// pass. (Negative control, run for the PR: `cached()` returning
    /// `Some(detect())` turns this red.) No other lib test fills the lock.
    #[test]
    fn not_probed_never_triggers_a_probe() {
        // It reads `ENCODER_CELLS_DENY` twice (inside `summarize_cached` and
        // in the final `assert_eq!`), and three tests rewrite that var under
        // DENY_ENV_LOCK; without the lock, one of their writes can land
        // between the two reads.
        let _guard = crate::encode::DENY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = CACHED_CAPS.get().is_some();
        let summary = summarize_cached();
        let after = CACHED_CAPS.get().is_some();
        assert_eq!(
            before, after,
            "reading the summary must not populate the probe cache"
        );
        match (ENCODERS_COMPILED, before) {
            (false, _) => assert_eq!(summary.state, "unsupported"),
            (true, false) => {
                assert_eq!(summary.state, "not_probed");
                assert!(summary.cells.is_empty());
                assert!(summary.hw_encoders.is_empty());
                assert_eq!(summary.probe_ms, None);
                assert!(!summary.probe_cached);
            }
            (true, true) => assert_eq!(summary.state, "ready"),
        }
        // The denylist and the preference are facts about the process, not
        // about the probe: reported whatever the state.
        assert_eq!(summary.denied, denied_cells());
        assert_eq!(
            summary.encoder_preference.as_deref(),
            super::super::resolved_preference().map(|p| p.wire())
        );
    }

    /// FR-84 D4 — a populated caps value maps cell for cell onto the wire
    /// summary: codec / backend / chroma / hardware, the legacy labels, the
    /// probe timing, plus the denylist and preference the caller supplies.
    #[test]
    fn summary_of_a_populated_caps_carries_every_cell() {
        let caps = AgentCaps {
            hw_encoders: vec!["ffmpeg-hevc_nvenc".into(), "openh264-sw".into()],
            codecs: vec!["h264".into(), "h265".into()],
            video_cells: vec![
                VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Nvenc,
                    &[ChromaFormat::Yuv420, ChromaFormat::Yuv444],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::H264,
                    VideoBackend::Openh264,
                    &[ChromaFormat::Yuv420],
                    false,
                ),
            ],
            probe_ms: Some(812),
            probe_cached: true,
            ..Default::default()
        };
        let s = summarize(
            Some(&caps),
            vec!["hevc_qsv:yuv444".into()],
            Some("hardware"),
        );
        assert_eq!(
            s.state,
            if ENCODERS_COMPILED {
                "ready"
            } else {
                "unsupported"
            }
        );
        assert_eq!(s.cells.len(), 2);
        assert_eq!(s.cells[0].codec, "hevc");
        assert_eq!(s.cells[0].backend, "nvenc");
        assert_eq!(s.cells[0].chroma, vec!["yuv420", "yuv444"]);
        assert!(s.cells[0].hardware);
        assert_eq!(s.cells[1].backend, "openh264");
        assert!(!s.cells[1].hardware);
        assert_eq!(s.hw_encoders, caps.hw_encoders);
        assert_eq!(s.codecs, caps.codecs);
        assert_eq!(s.probe_ms, Some(812));
        assert!(s.probe_cached);
        assert_eq!(s.denied, vec!["hevc_qsv:yuv444"]);
        assert_eq!(s.encoder_preference.as_deref(), Some("hardware"));
        // No caps at all: the process facts still travel, nothing invented.
        let none = summarize(None, Vec::new(), None);
        assert!(none.cells.is_empty() && none.probe_ms.is_none());
        assert_eq!(none.encoder_preference, None);
    }

    /// Closes the loop the `RpcCap` enum exists to close: every verb this
    /// agent PUTS ON THE WIRE must be one the server can parse back. A typo
    /// here used to be invisible — the device would simply look like it lacked
    /// the feature, which is indistinguishable from an old agent.
    #[test]
    fn every_advertised_verb_is_a_known_capability() {
        use roomler_ai_remote_control::models::RpcCap;

        let advertised = rpc_caps();
        assert!(
            !advertised.is_empty(),
            "every build advertises exec at least"
        );
        for verb in &advertised {
            assert!(
                RpcCap::from_wire(verb).is_some(),
                "advertised {verb:?} is not a verb the server knows"
            );
        }
        // Build-independent floor: the exec engine is plain process spawning,
        // so these hold in every feature configuration.
        assert!(advertised.iter().any(|v| v == RpcCap::Exec.wire()));
        assert!(advertised.iter().any(|v| v == RpcCap::Originate.wire()));

        // The SSH pair is feature-gated TOGETHER: advertising `ssh` without
        // `ssh-consent` is precisely the rc.419 state the server has to refuse
        // a consent policy for, so they must never drift apart in one build.
        assert_eq!(
            advertised.iter().any(|v| v == RpcCap::Ssh.wire()),
            advertised.iter().any(|v| v == RpcCap::SshConsent.wire()),
            "ssh and ssh-consent must be advertised together in a single build"
        );
        assert_eq!(
            advertised.iter().any(|v| v == RpcCap::Ssh.wire()),
            cfg!(feature = "ssh-server"),
            "the ssh verbs must track the ssh-server feature, not the version"
        );
        // FR-83 — and the ack travels with them. A build advertising
        // `ssh-grant-ack` without an SSH server would have the server wait on
        // grants nothing records; one serving SSH without it would put every
        // caller back in the #1597 race.
        assert_eq!(
            advertised.iter().any(|v| v == RpcCap::SshGrantAck.wire()),
            cfg!(feature = "ssh-server"),
            "ssh-grant-ack must be advertised exactly when the SSH server is built"
        );
        // FR-90 P3-8-2a — and so does one command: the server sends an agent
        // session's grant only where this is said, and the SSH server is what
        // holds it there.
        assert_eq!(
            advertised.iter().any(|v| v == RpcCap::SshOneCommand.wire()),
            cfg!(feature = "ssh-server"),
            "ssh-one-command must be advertised exactly when the SSH server is built"
        );
        // FR-97 P5a — `console-user` on every Unix build and never on
        // Windows, whose `console_user` is its SYSTEM service's: a Windows
        // worker sent `run_as` would answer for an identity it never offered.
        assert_eq!(
            advertised.iter().any(|v| v == RpcCap::ConsoleUser.wire()),
            cfg!(unix),
            "console-user must be advertised exactly on Unix builds"
        );

        // FR-52 — build-independent, like `config`, and NOT derived from
        // `external_access_enabled`. The server gates the admin approval on
        // this verb, so an agent that stopped sending it would make every
        // device in the fleet un-approvable for cross-org access — a silent
        // fleet-wide close, not an error anyone would see.
        assert!(
            advertised
                .iter()
                .any(|v| v == RpcCap::ExternalAccess.wire()),
            "external-access must be advertised by every build: it says this \
             agent can tell the person at the machine that a controller is \
             from outside their organization, which is what makes gate 2 \
             approvable at all"
        );

        // FR-52 P4 — but `external-session` exactly when the build can bind a
        // session to a login. Advertised without it, the server would open
        // external sessions a device then refuses every time; withheld from a
        // build that has it, the feature is dark on that device.
        assert_eq!(
            advertised
                .iter()
                .any(|v| v == RpcCap::ExternalSession.wire()),
            cfg!(feature = "external-access"),
            "external-session must be advertised exactly when the external-access \
             stack is built"
        );

        // FR-100 P1b — `peer-auth` in every build: the signing needs no
        // feature, only a device key, and the hello says whether there is one.
        assert!(
            advertised.iter().any(|v| v == RpcCap::PeerAuth.wire()),
            "peer-auth must be advertised by every build"
        );
    }

    /// Permissions are always REPORTED, even when everything is granted.
    ///
    /// `None` means "this agent is too old to know", and a server or UI must
    /// be able to tell that apart from "this agent holds nothing" — so a
    /// current agent must never send `None`. The list itself is
    /// platform-dependent (only macOS actually gates these), which is why this
    /// asserts the reporting contract rather than the contents.
    #[test]
    fn caps_always_report_permission_state() {
        let caps = compute_caps(false, false);
        let perms = caps
            .permissions
            .expect("a current agent must report permissions, so None can keep meaning 'unknown'");
        for p in &perms {
            assert!(
                matches!(p.as_str(), "screen-capture" | "input"),
                "unrecognised permission {p:?} — readers skip unknown values, so a typo \
                 here silently reads as 'not granted'"
            );
        }
        // Platforms with no permission model must not look muzzled.
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            perms,
            vec!["screen-capture".to_string(), "input".to_string()],
            "a platform that does not gate these must report both granted"
        );
    }

    /// `has_input_permission` must track the OS, not the build.
    ///
    /// It was `cfg!(feature = "enigo-input")` — a compile-time constant — so a
    /// Mac with Accessibility denied advertised working input while silently
    /// dropping every event. Without the feature it must stay false regardless.
    #[test]
    fn input_permission_is_not_merely_a_compile_flag() {
        let caps = compute_caps(false, false);
        if !cfg!(feature = "enigo-input") {
            assert!(!caps.has_input_permission);
        }
        assert_eq!(
            caps.has_input_permission,
            cfg!(feature = "enigo-input") && input_permission_granted(),
            "the advertised bool must agree with the runtime probe"
        );
    }

    /// THE property this slice exists for: a host whose hardware probes
    /// cannot be trusted still produces usable caps, and never claims a codec
    /// it has no evidence for.
    ///
    /// `compute_caps(false, false)` is exactly what `detect()` falls back to when the
    /// probe child dies, so this is the shape a driver fault now yields —
    /// where before it yielded a crash-looping daemon.
    #[test]
    fn a_failed_probe_still_yields_usable_caps_and_advertises_no_hardware() {
        let caps = compute_caps(false, false);

        // Nothing that required asking a driver.
        for name in ["mf-h264-hw", "mf-h265-hw", "mf-av1-hw"] {
            assert!(
                !caps.hw_encoders.iter().any(|h| h == name),
                "{name} was advertised without a successful probe: {:?}",
                caps.hw_encoders
            );
        }
        assert!(
            !caps.hw_encoders.iter().any(|h| h.starts_with("ffmpeg-")),
            "an ffmpeg HW encoder was advertised without a successful probe: {:?}",
            caps.hw_encoders
        );
        // Transports are the sharp end — negotiating one the host cannot
        // fulfil is a black session, not a downgrade.
        for t in [
            "data-channel-hevc",
            "data-channel-av1",
            "data-channel-h264",
            "data-channel-vp9-444",
        ] {
            assert!(
                !caps.transports.iter().any(|x| x == t),
                "{t} was advertised without a successful probe: {:?}",
                caps.transports
            );
        }

        // ...but the agent is still a working agent: the parts that never
        // depended on a driver survive, so a probe fault degrades the host
        // rather than disabling it. File transfer is the clearest case, and
        // since #1672 it is not even IN the probe's answer: `detect()` assigns
        // `files` in the daemon after the probe has answered or failed, so no
        // probe outcome can reach it. The "upload survives" assertion that
        // used to sit here moved to `the_daemon_assigns_every_config_list`,
        // which runs this same fallback struct through that assignment.
        assert!(caps.max_simultaneous_sessions > 0);

        // FR-77 — no hardware cell without a probe, and no probe time either
        // (the parent stamps it only when the child came back).
        assert!(
            caps.video_cells.iter().all(|c| !c.hw),
            "a hardware cell was advertised without a probe: {:?}",
            caps.video_cells
        );
        assert!(caps.probe_ms.is_none());
        // Whatever software cells survive must speak the vocabulary.
        for cell in &caps.video_cells {
            assert!(cell.typed().is_some(), "{cell:?} is outside the vocabulary");
        }
    }

    #[test]
    fn picks_av1_when_both_sides_support() {
        let chosen = pick_best_codec(
            &["h264".into(), "av1".into(), "h265".into()],
            &["h264".into(), "av1".into(), "h265".into()],
        );
        assert_eq!(chosen, "av1");
    }

    #[test]
    fn picks_h265_over_h264_when_browser_lacks_av1() {
        let chosen = pick_best_codec(
            &["h264".into(), "h265".into()],
            &["h264".into(), "av1".into(), "h265".into()],
        );
        assert_eq!(chosen, "h265");
    }

    #[test]
    fn picks_h264_when_only_common_codec() {
        let chosen = pick_best_codec(&["h264".into()], &["h264".into(), "h265".into()]);
        assert_eq!(chosen, "h264");
    }

    #[test]
    fn falls_back_to_h264_on_empty_browser_caps() {
        // Pre-2B.1 controller that doesn't advertise anything.
        let chosen = pick_best_codec(&[], &["h264".into(), "h265".into()]);
        assert_eq!(chosen, "h264");
    }

    #[test]
    fn falls_back_to_h264_on_no_intersection() {
        // Browser advertises only VP8, agent only H.264. No overlap;
        // we return h264 so the caller has a usable default.
        let chosen = pick_best_codec(&["vp8".into()], &["h264".into()]);
        assert_eq!(chosen, "h264");
    }

    #[test]
    fn case_insensitive_match() {
        let chosen = pick_best_codec(&["H264".into(), "H265".into()], &["h265".into()]);
        assert_eq!(chosen, "h265");
    }

    #[test]
    fn prefers_vp9_over_h264() {
        let chosen = pick_best_codec(
            &["h264".into(), "vp9".into()],
            &["h264".into(), "vp9".into()],
        );
        assert_eq!(chosen, "vp9");
    }

    /// Y.4: in default-feature (no `vp9-444`) builds, the transports
    /// list must NOT advertise `data-channel-vp9-444`. The browser
    /// reads this list to decide whether to even open the DC; an
    /// agent that lies about transport support would crash the
    /// session at media-pump time.
    #[cfg(not(feature = "vp9-444"))]
    #[test]
    fn detect_omits_vp9_444_transport_when_feature_disabled() {
        // Probing ENABLED on purpose: the claim is that a build without the
        // feature never advertises the transport even when probes run. (The
        // vp9 probe itself is cfg'd out here, so nothing is actually opened.)
        let caps = compute_caps(true, true);
        assert!(
            !caps.transports.iter().any(|t| t == "data-channel-vp9-444"),
            "default-feature build advertised vp9-444 transport: {:?}",
            caps.transports
        );
        assert!(
            !caps.hw_encoders.iter().any(|e| e == "libvpx-vp9-444-sw"),
            "default-feature build advertised libvpx encoder: {:?}",
            caps.hw_encoders
        );
    }

    /// Y.4 caps probe (post Y.runtime-encoder rewrite, 0.1.47): the
    /// libvpx encoder at the probe resolution must successfully
    /// activate, and `compute_caps` must surface both the
    /// `data-channel-vp9-444` transport and the `libvpx-vp9-444-sw`
    /// encoder label. CI runs this with `libvpx-dev` apt-installed
    /// so the link succeeds. If the probe ever regresses (libvpx
    /// missing on the build host, encoder init failure on the probe
    /// dimensions), this test catches it before a session ever
    /// negotiates onto a broken transport.
    #[cfg(feature = "vp9-444")]
    #[test]
    fn detect_advertises_vp9_444_transport_when_encoder_works() {
        // Probing ENABLED: this test's whole claim is that the probe runs and
        // succeeds. libvpx is our own software encoder, not a vendor driver,
        // so running it in-process here is safe.
        let caps = compute_caps(true, true);
        assert!(
            caps.transports.iter().any(|t| t == "data-channel-vp9-444"),
            "vp9-444 transport must be advertised when libvpx probe succeeds; got {:?}",
            caps.transports
        );
        assert!(
            caps.hw_encoders.iter().any(|e| e == "libvpx-vp9-444-sw"),
            "libvpx encoder label must be advertised when probe succeeds; got {:?}",
            caps.hw_encoders
        );
    }

    /// Audio caps: a build WITH the `audio` feature must advertise
    /// `opus` so the browser knows it may request `audio_enabled`.
    #[cfg(feature = "audio")]
    #[test]
    fn detect_advertises_opus_audio_when_feature_enabled() {
        // Feature-gated, never probe-gated — no driver call needed.
        let caps = compute_caps(false, false);
        assert!(
            caps.audio.iter().any(|c| c == "opus"),
            "audio-feature build must advertise opus; got {:?}",
            caps.audio
        );
    }

    /// Audio caps: a default (no `audio` feature) build must NOT
    /// advertise any audio codec — the agent adds no audio track, so a
    /// browser that saw `opus` and asked for `audio_enabled` would wait
    /// forever for a track that never arrives.
    #[cfg(not(feature = "audio"))]
    #[test]
    fn detect_omits_audio_when_feature_disabled() {
        // Audio advertisement is feature-gated, never probe-gated, so this
        // needs no driver call.
        let caps = compute_caps(false, false);
        assert!(
            caps.audio.is_empty(),
            "default build must not advertise audio; got {:?}",
            caps.audio
        );
    }

    /// rc.19 file-DC v3 capability lock. The browser opts into
    /// resumable uploads ONLY when this string appears in
    /// `caps.files`. Removing or renaming it would silently disable
    /// the resume path for every rc.19+ browser — lock here.
    #[test]
    fn detect_advertises_resume_files_cap() {
        // File caps never depended on a probe, and since #1672 they are the
        // daemon's list (`files_caps`), whatever the browse flag says.
        for browse in [false, true] {
            let files = files_caps_for(browse);
            assert!(
                files.iter().any(|s| s == "resume"),
                "rc.19 caps.files must include \"resume\" (browse={browse}); got {files:?}"
            );
        }
    }

    /// #1672 — `files` is the DAEMON's to assign, in `detect()`, never the
    /// caps-probe child's to compute. On a cache miss `cached_or_probed`
    /// returns the child's struct wholesale, and the child loads no config:
    /// with the files block inside `compute_caps`, `browse` rode the flag's
    /// built-in default (`true`) and a device with `enable_remote_browse =
    /// false` advertised it on every release's first boot and on every boot
    /// of a host with no hardware cell. So what the child runs must leave the
    /// field empty — a re-added block here is exactly the regression, and
    /// this is red on it.
    #[test]
    fn files_are_assigned_by_the_daemon_never_by_the_probe_child() {
        let caps = compute_caps(false, false);
        assert!(
            caps.files.is_empty(),
            "compute_caps is what the caps-probe child runs; it must leave `files` to \
             detect(), which reads the browse flag in the daemon — got {:?}",
            caps.files
        );
    }

    /// #1672 — the daemon's list follows the CONFIG: `browse` present exactly
    /// when remote browse is enabled, and the four build-constant verbs in
    /// both cases (an empty or shortened list would send browsers back to
    /// the upload-only fallback). Driven through `files_caps_for` so the
    /// process-global flag is never flipped under the other tests.
    #[test]
    fn files_caps_follow_the_config() {
        let off = files_caps_for(false);
        assert_eq!(
            off,
            vec!["upload", "download", "download-folder", "resume"],
            "browse disabled: the four always-built verbs and nothing else"
        );
        let on = files_caps_for(true);
        assert_eq!(
            on,
            vec!["upload", "download", "download-folder", "resume", "browse"],
            "browse enabled: the same four, plus `browse`"
        );
    }

    // ─── FR-97 P0c — a word is a promise this host keeps ─────────────────
    // Each test below fails on master, where every one of these words was a
    // compile-time constant (the census before P0c, FR-97 §8).

    fn p0c_facts(os: roomler_ai_remote_control::models::OsKind) -> HostFacts {
        HostFacts {
            os,
            audio_built: true,
            audio_backend: true,
            linux_audio_refusal: None,
            watches_clipboard_images: true,
            clipboard_reachable: true,
            layout_reachable: true,
            layout_switchable: true,
            display_switchable: true,
        }
    }

    fn p0c_caps() -> AgentCaps {
        AgentCaps {
            audio: vec!["opus".into()],
            supports_clipboard: true,
            clipboard: ["ack", "events", "images", "html"]
                .map(String::from)
                .to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn a_host_without_an_audio_backend_offers_no_track_and_says_why() {
        use roomler_ai_remote_control::models::OsKind;
        let mac = with_honest_words(
            p0c_caps(),
            &HostFacts {
                audio_backend: false,
                ..p0c_facts(OsKind::Macos)
            },
        );
        assert!(
            mac.audio.is_empty(),
            "no backend, no opus (R1): {:?}",
            mac.audio
        );
        assert_eq!(mac.unavailable["audio"].code, "no-backend");
        // A Linux host with a way to the computer's sound.
        let linux = with_honest_words(p0c_caps(), &p0c_facts(OsKind::Linux));
        assert_eq!(linux.audio, vec!["opus".to_string()]);
        assert!(!linux.unavailable.contains_key("audio"));
        // FR-97 P3c — and without one: no track, rather than the microphone
        // every Linux session carried before (measured 2026-10-17), and the
        // route's own reason.
        use crate::audio_source::AudioUnavailableCode as Why;
        for (why, code, names) in [
            (Why::NoMonitor, "no-monitor", "ROOMLERD_AUDIO_SESSION=0"),
            (Why::NoSoundServer, "no-sound-server", "libpulse-simple"),
            (Why::NoSession, "no-session", "session helper"),
        ] {
            let c = with_honest_words(
                p0c_caps(),
                &HostFacts {
                    audio_backend: false,
                    linux_audio_refusal: Some(why),
                    ..p0c_facts(OsKind::Linux)
                },
            );
            assert!(c.audio.is_empty(), "{why:?}: {:?}", c.audio);
            assert_eq!(c.unavailable["audio"].code, code, "{why:?}");
            assert!(c.unavailable["audio"].reason.contains(names), "{why:?}");
        }
        // A build without the feature had nothing to claim, and says nothing.
        let none = with_honest_words(
            AgentCaps {
                audio: Vec::new(),
                ..p0c_caps()
            },
            &HostFacts {
                audio_built: false,
                audio_backend: false,
                ..p0c_facts(OsKind::Macos)
            },
        );
        assert!(!none.unavailable.contains_key("audio"));
    }

    #[test]
    fn copied_images_are_claimed_only_where_the_watcher_reports_them() {
        use roomler_ai_remote_control::models::OsKind;
        let unwatched = with_honest_words(
            p0c_caps(),
            &HostFacts {
                watches_clipboard_images: false,
                ..p0c_facts(OsKind::Linux)
            },
        );
        assert_eq!(
            unwatched.unavailable["clipboard-image-events"].code,
            "not-watched"
        );
        // Text events and on-request images still work: the words stay.
        assert!(unwatched.clipboard.iter().any(|w| w == "events"));
        assert!(unwatched.clipboard.iter().any(|w| w == "images"));
        assert!(unwatched.supports_clipboard);
        let watched = with_honest_words(p0c_caps(), &p0c_facts(OsKind::Windows));
        assert!(!watched.unavailable.contains_key("clipboard-image-events"));
    }

    #[test]
    fn a_root_daemon_outside_every_session_offers_no_clipboard() {
        use roomler_ai_remote_control::models::OsKind;
        let root = with_honest_words(
            p0c_caps(),
            &HostFacts {
                clipboard_reachable: false,
                watches_clipboard_images: false,
                ..p0c_facts(OsKind::Linux)
            },
        );
        assert!(!root.supports_clipboard, "R10");
        assert!(root.clipboard.is_empty(), "{:?}", root.clipboard);
        assert_eq!(root.unavailable["clipboard"].code, "no-session");
        assert!(
            !root.unavailable.contains_key("clipboard-image-events"),
            "no clipboard at all says so once, not twice"
        );
    }

    /// FR-97 P3e-2 — the viewer offered display match by OS (Windows only);
    /// it follows the device's word now, so a host that cannot switch says
    /// so, and one that can says nothing.
    #[test]
    fn a_host_whose_display_cannot_be_switched_says_so() {
        use roomler_ai_remote_control::models::OsKind;
        for os in [OsKind::Windows, OsKind::Linux] {
            let can = with_honest_words(p0c_caps(), &p0c_facts(os));
            assert!(!can.unavailable.contains_key("display-match"), "{os:?}");
        }
        for os in [OsKind::Linux, OsKind::Macos] {
            let cannot = with_honest_words(
                p0c_caps(),
                &HostFacts {
                    display_switchable: false,
                    ..p0c_facts(os)
                },
            );
            let why = &cannot.unavailable["display-match"];
            assert_eq!(why.code, "unsupported", "{os:?}");
            assert!(why.reason.contains("cannot be switched"), "{os:?}: {why:?}");
        }
    }

    #[test]
    fn the_layout_is_offered_only_where_it_can_be_switched() {
        use roomler_ai_remote_control::models::OsKind;
        let with_layout = || AgentCaps {
            layout: vec!["report".into(), "set".into()],
            ..p0c_caps()
        };
        // FR-97 P3e — an X11 session, and every Windows host.
        for os in [OsKind::Linux, OsKind::Windows] {
            let c = with_honest_words(with_layout(), &p0c_facts(os));
            assert_eq!(c.layout, ["report", "set"], "{os:?}");
        }
        // Wayland, or a system install: no chip, and nothing greyed to explain.
        let wayland = with_honest_words(
            with_layout(),
            &HostFacts {
                layout_reachable: false,
                ..p0c_facts(OsKind::Linux)
            },
        );
        assert!(wayland.layout.is_empty(), "{:?}", wayland.layout);
        assert!(!wayland.unavailable.contains_key("layout"));
        // GNOME on Xorg puts its own layout back: the chip, and no picker.
        let gnome = with_honest_words(
            with_layout(),
            &HostFacts {
                layout_switchable: false,
                ..p0c_facts(OsKind::Linux)
            },
        );
        assert_eq!(gnome.layout, ["report"]);
    }

    #[test]
    fn ctrl_alt_del_says_what_the_keys_reach_and_goes_on_a_mac() {
        use roomler_ai_remote_control::models::{OsKind, Unavailable};
        for os in [OsKind::Windows, OsKind::Linux] {
            let c = with_honest_words(p0c_caps(), &p0c_facts(os));
            assert_eq!(c.unavailable["sas"].code, "keys-only", "{os:?}");
        }
        let mac = with_honest_words(p0c_caps(), &p0c_facts(OsKind::Macos));
        assert_eq!(mac.unavailable["sas"].code, Unavailable::NOT_APPLICABLE);
    }

    #[test]
    fn every_reason_uses_a_known_key_and_says_something() {
        use roomler_ai_remote_control::models::{OsKind, Unavailable};
        for os in [OsKind::Windows, OsKind::Macos, OsKind::Linux] {
            for reachable in [true, false] {
                let c = with_honest_words(
                    p0c_caps(),
                    &HostFacts {
                        os,
                        audio_built: true,
                        audio_backend: false,
                        linux_audio_refusal: None,
                        watches_clipboard_images: false,
                        clipboard_reachable: reachable,
                        layout_reachable: reachable,
                        layout_switchable: reachable,
                        display_switchable: reachable,
                    },
                );
                for (key, why) in &c.unavailable {
                    assert!(Unavailable::KEYS.contains(&key.as_str()), "{key}");
                    assert!(
                        !why.code.is_empty() && why.reason.len() > 20,
                        "{key}: {why:?}"
                    );
                }
            }
        }
    }

    /// The facts this build reports for its own OS: what the census will count.
    #[test]
    fn this_hosts_facts_follow_its_os() {
        let f = HostFacts::here();
        if cfg!(target_os = "windows") {
            assert!(f.audio_backend, "WASAPI loopback");
        } else if cfg!(target_os = "linux") {
            // FR-97 P3c: a way to the computer's sound, and a reason exactly
            // when there is none.
            assert_eq!(
                f.audio_backend,
                f.linux_audio_refusal.is_none(),
                "{:?}",
                f.linux_audio_refusal
            );
        } else {
            assert!(!f.audio_backend, "macOS until FR-97 P2a");
        }
        // FR-97 P3e-3a — on Linux, wherever the X11 change gate opens.
        #[cfg(all(target_os = "linux", feature = "clipboard"))]
        assert_eq!(
            f.watches_clipboard_images,
            crate::clipboard::x11_gate::available()
        );
        #[cfg(not(all(target_os = "linux", feature = "clipboard")))]
        assert_eq!(f.watches_clipboard_images, cfg!(target_os = "windows"));
        if cfg!(target_os = "windows") {
            assert!(f.layout_reachable && f.layout_switchable);
            assert!(f.display_switchable);
        } else if cfg!(target_os = "macos") {
            assert!(!f.layout_reachable, "macOS until FR-97 P2d");
            assert!(!f.display_switchable);
        }
    }

    /// #1672 (review of #1679) — the daemon's side of the split, locked. The
    /// two `files_*` tests above prove the child carries nothing and the seam
    /// follows the config; neither proves `detect()` ASSIGNS it. With the
    /// three assignments inline in the `OnceLock` closure, deleting
    /// `caps.files = files_caps()` left every lib test green while every hello
    /// shipped an empty `files` and every browser fell back to upload-only —
    /// and the same latent gap sat under `apps` (#1667) and `rpc`. `detect()`
    /// cannot be called here (it spawns the probe child), so its closure is
    /// the named seam `with_config_lists`, and this drives the exact struct
    /// the driver-free fallback hands it, with the three lists poisoned so an
    /// assignment that is skipped shows as `stale` surviving. Also the home of
    /// the "file transfer survives a probe failure" assertion.
    ///
    /// ⚠️ On Linux `apps_caps()` performs the daemon's own read-only session
    /// discovery (`loginctl`, then `wmctrl -m` per candidate display). The
    /// assertion on `apps` does not depend on what it finds — `status` is a
    /// property of the build — which is what makes calling the real seam,
    /// rather than a copy with the sources injected, the honest choice here.
    #[test]
    fn the_daemon_assigns_every_config_list() {
        let mut base = compute_caps(false, false);
        base.rpc = vec!["stale".into()];
        base.apps = vec!["stale".into()];
        base.files = vec!["stale".into()];
        let caps = with_config_lists(base);

        assert_eq!(
            caps.files,
            files_caps(),
            "`files` must be the daemon's list, assigned over whatever the probe path carried"
        );
        assert!(
            caps.files.iter().any(|f| f == "upload") && caps.files.iter().any(|f| f == "resume"),
            "file transfer must survive a probe failure — this IS the fallback struct: {:?}",
            caps.files
        );
        assert_eq!(
            caps.rpc,
            rpc_caps(),
            "`rpc` must be the daemon's list, assigned over whatever the probe path carried"
        );
        assert!(
            !caps.apps.iter().any(|a| a == "stale"),
            "`apps` must be overwritten by the daemon, never kept from the probe path: {:?}",
            caps.apps
        );
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        assert!(
            caps.apps.iter().any(|a| a == "status"),
            "a build with a Remote Apps backend advertises `status` whatever the host is doing: {:?}",
            caps.apps
        );
    }

    /// FR-56 AC10 (review of #1667) — `apps` is the DAEMON's to assign, in
    /// `detect()`, never the caps-probe child's to compute. On a cache miss
    /// `cached_or_probed` returns the child's struct wholesale, and the child
    /// loads no config: with the apps block inside `compute_caps`, a device
    /// with `[virtual_desktop_apps] enabled = false` still advertised `list`
    /// on every release's first boot and on every boot of a host with no
    /// hardware cell. So what the child runs must leave the field empty — a
    /// re-added block here is exactly the regression, and this is red on it.
    #[test]
    fn apps_are_assigned_by_the_daemon_never_by_the_probe_child() {
        let caps = compute_caps(false, false);
        assert!(
            caps.apps.is_empty(),
            "compute_caps is what the caps-probe child runs; it must leave `apps` to \
             detect(), which reads the installed config in the daemon — got {:?}",
            caps.apps
        );
    }

    /// FR-56 AC10 — `status` is locked on every build with a backend and absent
    /// elsewhere, and the three verbs follow the CONFIG the daemon installed,
    /// not the built-in default. Driven through `apps_caps_for` so no
    /// process-global config is installed and no login session is looked for.
    #[test]
    fn apps_caps_lock_status_and_follow_the_config() {
        use crate::apps::VirtualDesktopAppsConfig;
        let off = VirtualDesktopAppsConfig {
            enabled: false,
            ..Default::default()
        };
        let apps = apps_caps_for(&off);
        let apps: Vec<&str> = apps.iter().map(String::as_str).collect();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            assert_eq!(
                apps,
                vec!["status"],
                "disabled: `status` alone — the entry shows, and the reply says `disabled`"
            );
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            assert!(
                apps.is_empty(),
                "no backend on this platform, nothing to advertise: {apps:?}"
            );
        }
        // Windows always drives the active desktop, so with the feature on the
        // three verbs follow. On Linux the answer depends on a login session,
        // which a unit test must not go looking for.
        #[cfg(target_os = "windows")]
        {
            let on = VirtualDesktopAppsConfig::default();
            let apps = apps_caps_for(&on);
            let apps: Vec<&str> = apps.iter().map(String::as_str).collect();
            assert_eq!(apps, vec!["status", "list", "focus", "launch"]);
        }
    }

    /// The child's output has to survive the round trip, or the parent falls
    /// back on every host and the probe silently stops meaning anything.
    /// FR-77 P3 — the envelope carries the vp9_qsv IDR verdict, and the P1
    /// bare-caps line still parses.
    #[test]
    fn the_marked_json_line_round_trips() {
        let caps = compute_caps(false, false);
        let report = child::ProbeReport {
            caps: caps.clone(),
            vp9_qsv_idr: Some((true, false)),
        };
        let line = format!(
            "{}{}",
            child::MARKER,
            serde_json::to_string(&report).unwrap()
        );
        let out = format!("some driver banner\n{line}\n");
        let back = child::parse_line(&out, std::time::Duration::from_millis(1234))
            .expect("the report must parse back");
        assert_eq!(back.caps.codecs, caps.codecs);
        assert_eq!(back.caps.transports, caps.transports);
        assert_eq!(back.caps.hw_encoders, caps.hw_encoders);
        assert_eq!(
            back.caps.video_cells, caps.video_cells,
            "FR-77 cells must survive the round trip"
        );
        assert_eq!(back.vp9_qsv_idr, Some((true, false)));
        assert_eq!(back.caps.probe_ms, Some(1234), "stamped by the parent");

        // A P1-shaped line (bare caps, no envelope) is still a valid answer.
        let bare = format!("{}{}", child::MARKER, serde_json::to_string(&caps).unwrap());
        let back =
            child::parse_line(&bare, std::time::Duration::from_millis(7)).expect("bare caps");
        assert_eq!(back.caps.video_cells, caps.video_cells);
        assert_eq!(back.vp9_qsv_idr, None);
        assert_eq!(back.caps.probe_ms, Some(7));

        assert!(
            child::parse_line("no marker here\n", std::time::Duration::ZERO).is_none(),
            "without the marker there is no answer"
        );
    }

    /// FR-77 P3 — a cache hit takes the encoder matrix from the cache and
    /// NOTHING else: permissions, files, verbs are this process's own.
    #[test]
    fn a_cache_hit_takes_only_the_driver_derived_fields() {
        let mut cached = compute_caps(false, false);
        cached.hw_encoders = vec!["ffmpeg-hevc_nvenc".into()];
        cached.codecs = vec!["h265".into()];
        cached.transports = vec!["data-channel-hevc".into()];
        cached.hevc_chroma = vec!["yuv420".into(), "yuv444".into()];
        cached.video_cells = vec![VideoCell::new(
            VideoCodec::Hevc,
            VideoBackend::Nvenc,
            &[ChromaFormat::Yuv420, ChromaFormat::Yuv444],
            true,
        )];
        // Poison the fields that must NOT come from the cache.
        cached.files = vec!["stale".into()];
        cached.permissions = Some(vec!["stale".into()]);
        cached.rpc = vec!["stale".into()];
        let hit = super::super::caps_cache::CacheFile::new(
            super::super::caps_cache::CacheKey {
                build: "b".into(),
                hardware: "h".into(),
                knobs: "k".into(),
            },
            1,
            3986,
            cached,
            None,
        );
        let merged = merge_cached(hit);
        assert_eq!(merged.hw_encoders, vec!["ffmpeg-hevc_nvenc".to_string()]);
        assert_eq!(merged.transports, vec!["data-channel-hevc".to_string()]);
        assert_eq!(merged.video_cells.len(), 1);
        assert!(merged.video_cells[0].hw);
        assert_eq!(merged.probe_ms, Some(3986));
        assert!(merged.probe_cached);
        assert!(
            !merged.files.iter().any(|f| f == "stale"),
            "files never come from the cache: {:?}",
            merged.files
        );
        // #1672 — and the merge does not compute them either: like `apps`
        // and `rpc`, `detect()` assigns them in the daemon after the merge,
        // so a hit and a miss reach the hello by the same line.
        assert!(
            merged.files.is_empty(),
            "the merge leaves `files` to detect(): {:?}",
            merged.files
        );
        assert_ne!(
            merged.permissions.as_deref(),
            Some(&["stale".to_string()][..])
        );
        assert!(!merged.rpc.iter().any(|r| r == "stale"));
    }

    /// FR-77 P3c — the 4:4:4 phase asks only for hardware cells the base
    /// phase opened whose name the source matrix lists, minus the denylist:
    /// no AV1, no AMF/VideoToolbox/MF, nothing denied, and nothing the host
    /// never opened in 4:2:0.
    #[test]
    fn candidates_444_are_the_hardware_cells_the_matrix_allows_minus_the_denylist() {
        use tunnel_core::env::test_env::Saved;
        let _guard = crate::encode::DENY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = Saved::cleared("ENCODER_CELLS_DENY");
        let caps = AgentCaps {
            video_cells: vec![
                VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Nvenc,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::H264,
                    VideoBackend::Nvenc,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::Av1,
                    VideoBackend::Nvenc,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Amf,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::Vp9,
                    VideoBackend::Qsv,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Qsv,
                    &[ChromaFormat::Yuv420],
                    true,
                ),
                VideoCell::new(
                    VideoCodec::Vp9,
                    VideoBackend::Libvpx,
                    &[ChromaFormat::Yuv420],
                    false,
                ),
            ],
            ..AgentCaps::default()
        };
        // Built-in denylist: hevc_qsv, hevc_vaapi AND vp9_qsv (CORPLAP-3, 2026-09-08).
        assert_eq!(
            child::candidates_444(&caps),
            vec!["hevc_nvenc".to_string(), "h264_nvenc".to_string()]
        );
        unsafe { tunnel_core::env::test_env::set("ENCODER_CELLS_DENY", "none") };
        assert_eq!(
            child::candidates_444(&caps),
            vec!["hevc_nvenc", "h264_nvenc", "vp9_qsv", "hevc_qsv"]
        );
        assert!(child::candidates_444(&AgentCaps::default()).is_empty());
    }

    /// FR-77 P3c — the merge adds `yuv444` to exactly the named cells, and
    /// the legacy `hevc_chroma` follows the P7 rule (hevc_nvenc won AND opened).
    #[test]
    fn merge_444_marks_the_cells_and_the_legacy_hevc_chroma() {
        let mut report = child::ProbeReport {
            caps: AgentCaps {
                hw_encoders: vec![
                    "openh264-sw".into(),
                    "ffmpeg-hevc_nvenc".into(),
                    "ffmpeg-h264_nvenc".into(),
                ],
                hevc_chroma: vec!["yuv420".into()],
                video_cells: vec![
                    VideoCell::new(
                        VideoCodec::Hevc,
                        VideoBackend::Nvenc,
                        &[ChromaFormat::Yuv420],
                        true,
                    ),
                    VideoCell::new(
                        VideoCodec::H264,
                        VideoBackend::Nvenc,
                        &[ChromaFormat::Yuv420],
                        true,
                    ),
                    VideoCell::new(
                        VideoCodec::Vp9,
                        VideoBackend::Qsv,
                        &[ChromaFormat::Yuv420],
                        true,
                    ),
                ],
                ..AgentCaps::default()
            },
            vp9_qsv_idr: None,
        };
        child::merge_444(
            &mut report,
            &["hevc_nvenc".to_string(), "vp9_qsv".to_string()],
        );
        let cell = |r: &child::ProbeReport, codec: &str, backend: &str| {
            r.caps
                .video_cells
                .iter()
                .find(|c| c.codec == codec && c.backend == backend)
                .unwrap()
                .chroma
                .clone()
        };
        assert_eq!(cell(&report, "hevc", "nvenc"), vec!["yuv420", "yuv444"]);
        assert_eq!(cell(&report, "vp9", "qsv"), vec!["yuv420", "yuv444"]);
        assert_eq!(
            cell(&report, "h264", "nvenc"),
            vec!["yuv420"],
            "not named — untouched"
        );
        assert_eq!(report.caps.hevc_chroma, vec!["yuv420", "yuv444"]);
        // Idempotent.
        child::merge_444(&mut report, &["hevc_nvenc".to_string()]);
        assert_eq!(cell(&report, "hevc", "nvenc"), vec!["yuv420", "yuv444"]);
        assert_eq!(report.caps.hevc_chroma, vec!["yuv420", "yuv444"]);
        // A QSV HEVC winner never makes the legacy field say 4:4:4 (the P7
        // session path is hevc_nvenc's).
        let mut qsv = child::ProbeReport {
            caps: AgentCaps {
                hw_encoders: vec!["ffmpeg-hevc_qsv".into()],
                hevc_chroma: vec!["yuv420".into()],
                video_cells: vec![VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Qsv,
                    &[ChromaFormat::Yuv420],
                    true,
                )],
                ..AgentCaps::default()
            },
            vp9_qsv_idr: None,
        };
        child::merge_444(&mut qsv, &["hevc_qsv".to_string()]);
        assert_eq!(qsv.caps.hevc_chroma, vec!["yuv420"]);
        assert_eq!(qsv.caps.video_cells[0].chroma, vec!["yuv420", "yuv444"]);
    }

    /// FR-77 P3c — the 4:4:4 phase's answer and the progress trail parse; a
    /// crashed child leaves the name of the open it was inside.
    #[test]
    fn the_444_phase_lines_and_the_progress_trail_parse() {
        let out = format!(
            "{}hevc_nvenc:yuv444\nsome driver banner\n{}h264_nvenc:yuv444\n{}[\"hevc_nvenc\"]\n",
            child::PROGRESS,
            child::PROGRESS,
            child::MARKER_444
        );
        assert_eq!(
            child::parse_444_line(&out),
            Some(vec!["hevc_nvenc".to_string()])
        );
        assert_eq!(
            child::last_progress(&out).as_deref(),
            Some("h264_nvenc:yuv444")
        );
        let died = format!("{}vp9_qsv:yuv444\n", child::PROGRESS);
        assert_eq!(child::parse_444_line(&died), None);
        assert_eq!(
            child::last_progress(&died).as_deref(),
            Some("vp9_qsv:yuv444")
        );
        assert_eq!(child::last_progress(""), None);
    }

    /// FR-77 P3c — the child reads its phase from the environment; unset is
    /// the pre-P3c single-phase probe.
    #[test]
    fn the_phase_is_read_from_the_environment() {
        // These env vars are private to the probe child, so the plain
        // std::env API is the contract (no ROOMLERD_ prefix bridging).
        // SAFETY: no other test in this crate touches ROOMLERD_CAPS_PHASE.
        unsafe { std::env::remove_var(child::PHASE_ENV) };
        assert_eq!(child::phase_from_env(), child::Phase::Full);
        unsafe { std::env::set_var(child::PHASE_ENV, "base") };
        assert_eq!(child::phase_from_env(), child::Phase::Base);
        unsafe { std::env::set_var(child::PHASE_ENV, "444") };
        assert_eq!(child::phase_from_env(), child::Phase::Only444);
        unsafe { std::env::set_var(child::NAMES_444_ENV, " hevc_nvenc, vp9_qsv ,") };
        assert_eq!(child::names_444_from_env(), vec!["hevc_nvenc", "vp9_qsv"]);
        unsafe {
            std::env::remove_var(child::PHASE_ENV);
            std::env::remove_var(child::NAMES_444_ENV);
        }
    }

    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    #[test]
    fn relay_readiness_refresh_only_changes_the_relay_capability() {
        let mut caps = AgentCaps::default();
        caps.rpc = vec!["ssh".into(), "files".into()];
        let ready = with_relay_server_readiness(caps.clone(), true);
        assert_eq!(ready.rpc, vec!["ssh", "files", "relay-server"]);
        assert_eq!(with_relay_server_readiness(ready, false).rpc, caps.rpc);
    }
}
