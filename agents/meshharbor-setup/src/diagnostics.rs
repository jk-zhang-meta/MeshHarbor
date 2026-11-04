// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P3b — the wizard's **opt-in** setup diagnostics
//! (`docs/growth-observability.md`, the install trace; spec §3e item 5, D4).
//!
//! When — and only when — the person ticks "Send anonymous setup
//! diagnostics" on the Welcome page, the wizard sends one
//! `POST {server}/api/setup/diagnostics` per **step boundary**: the three
//! pages (measured by the SPA, reported through `cmd_diagnostics_page`) and
//! every step of the install pipeline (measured here, around the
//! orchestrators' steps). A record is exactly
//! `{run, step, outcome, elapsed_ms, error_code, os, wizard_version}`
//! ([`SetupDiagnostic`]): a random id per launch, a step name, `ok` /
//! `failed` / `cancelled`, a duration, an error **code** from a fixed
//! vocabulary, the OS family and this crate's version. Never the token,
//! a name, a path, a hostname or an address — the shape cannot carry one.
//!
//! Three properties, each locked by a test below:
//!
//! * **Unticked, nothing leaves the machine** — not one request. The box
//!   lives in memory for this run (`cmd_diagnostics_opt_in`), is never
//!   written to the wizard's saved state and never defaulted from an
//!   earlier run. ⚠️ The recorder is the gate, not the SPA: a boundary
//!   reported while unticked is dropped here, so the SPA cannot leak one by
//!   calling at the wrong time.
//! * **The diagnostics go to the server being enrolled into**, so a
//!   self-hosted server gets its own and meshharbor.itachi.fans never hears of them.
//!   The pages happen before the wizard knows that server, so their
//!   boundaries are **buffered** in memory and flushed when `cmd_install`
//!   names it ([`Diagnostics::server_known`]); a run cancelled before then
//!   sends nothing anywhere — the buffer dies with the process.
//! * **Fire-and-forget**: a send is spawned with a short timeout, never
//!   retried, never shown, never awaited by a step. A diagnostics failure
//!   is a debug line.
//!
//! The run id also rides the enroll (`install.run`,
//! [`Diagnostics::run_id`]), so a ticked run joins the device it enrolled;
//! unticked, the enroll carries no `run`.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use meshharbor_remote_control::setup_diagnostics::{
    ELAPSED_MS_MAX, ErrorCode, OS_FAMILIES, Outcome, SetupDiagnostic, Step,
};

/// How long one send may take, connect included. A step never waits on it,
/// but a wizard that exits right after its last boundary should not hold
/// a socket open for long either.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(3);

/// The path every record is posted to, under the enrolling server's origin.
pub const ROUTE: &str = "/api/setup/diagnostics";

/// Where a record goes. Fire-and-forget by contract: an implementation
/// returns at once and never reports back.
pub trait Sender: Send + Sync {
    fn send(&self, url: String, record: SetupDiagnostic);
}

/// The real sender: one POST per record on Tauri's async runtime, with
/// [`SEND_TIMEOUT`], no retry, the answer dropped at debug level.
pub struct HttpSender;

impl Sender for HttpSender {
    fn send(&self, url: String, record: SetupDiagnostic) {
        tauri::async_runtime::spawn(async move {
            let client = match reqwest::Client::builder()
                .user_agent(crate::proxy::USER_AGENT)
                .timeout(SEND_TIMEOUT)
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "setup diagnostics: no client");
                    return;
                }
            };
            match client.post(&url).json(&record).send().await {
                Ok(r) => tracing::debug!(
                    status = %r.status(), step = %record.step, outcome = %record.outcome,
                    "setup diagnostics: sent"
                ),
                Err(e) => {
                    tracing::debug!(error = %e, step = %record.step, "setup diagnostics: not sent")
                }
            }
        });
    }
}

#[derive(Default)]
struct Inner {
    /// The box on the Welcome page, for this process only.
    opted_in: bool,
    /// Minted on the first record, kept for the process.
    run: Option<String>,
    /// `{server}/api/setup/diagnostics` once `cmd_install` named the server.
    endpoint: Option<String>,
    /// Boundaries passed before the server was known.
    buffered: Vec<SetupDiagnostic>,
    /// The pipeline step in progress and when it began.
    open: Option<(Step, Instant)>,
    /// When the pipeline began — `done`'s elapsed is the whole install.
    pipeline_started: Option<Instant>,
}

/// The recorder: the opt-in gate, the run id, the buffer, and the open
/// step. One per process ([`Diagnostics::global`]); tests build their own
/// around a counting [`Sender`].
pub struct Diagnostics {
    sender: Arc<dyn Sender>,
    inner: Mutex<Inner>,
}

impl Diagnostics {
    pub fn new(sender: Arc<dyn Sender>) -> Self {
        Self {
            sender,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The process-wide recorder, sending over HTTP.
    pub fn global() -> &'static Diagnostics {
        static GLOBAL: OnceLock<Diagnostics> = OnceLock::new();
        GLOBAL.get_or_init(|| Diagnostics::new(Arc::new(HttpSender)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The Welcome box. Unticking drops whatever was buffered and the open
    /// step: nothing recorded while the box was ticked is sent later.
    pub fn set_opt_in(&self, on: bool) {
        let mut g = self.lock();
        g.opted_in = on;
        if !on {
            g.buffered.clear();
            g.open = None;
        }
    }

    pub fn opted_in(&self) -> bool {
        self.lock().opted_in
    }

    /// The run id for the enroll's `install.run` — only while ticked, so an
    /// unticked enroll carries none.
    pub fn run_id(&self) -> Option<String> {
        let mut g = self.lock();
        if !g.opted_in {
            return None;
        }
        Some(Self::run_of(&mut g))
    }

    fn run_of(g: &mut Inner) -> String {
        g.run
            .get_or_insert_with(|| uuid::Uuid::new_v4().simple().to_string())
            .clone()
    }

    /// A page boundary the SPA measured: only the three page steps, so the
    /// pipeline's steps have one source (the orchestrators).
    pub fn page(&self, step: Step, outcome: Outcome, elapsed_ms: u64) {
        if !matches!(step, Step::Welcome | Step::Server | Step::Token) {
            return;
        }
        let mut g = self.lock();
        self.record(&mut g, step, outcome, elapsed_ms, None);
    }

    /// `cmd_install` names the server: from here on a record is sent at
    /// once, and the pages' buffered boundaries go first, in order.
    pub fn server_known(&self, server: &str) {
        let mut g = self.lock();
        let endpoint = format!("{}{ROUTE}", server.trim_end_matches('/'));
        g.endpoint = Some(endpoint.clone());
        if !g.opted_in {
            g.buffered.clear();
            return;
        }
        for d in std::mem::take(&mut g.buffered) {
            self.sender.send(endpoint.clone(), d);
        }
    }

    /// The install pipeline begins: `done`'s elapsed counts from here.
    pub fn pipeline_started(&self) {
        let mut g = self.lock();
        g.pipeline_started = Some(Instant::now());
        g.open = None;
    }

    /// A pipeline step begins. A step still open from a site that forgot to
    /// close it is closed as `ok` first — it did reach the next step.
    pub fn begin(&self, step: Step) {
        let mut g = self.lock();
        if let Some((open, since)) = g.open.take() {
            let elapsed = Self::ms(since);
            self.record(&mut g, open, Outcome::Ok, elapsed, None);
        }
        g.open = Some((step, Instant::now()));
    }

    /// The open step passed.
    pub fn ok(&self) {
        self.close(Outcome::Ok, None);
    }

    /// The open step failed with `code` — or was cancelled, when the
    /// cancel flag is what made it fail (a download aborted between chunks
    /// is a cancel, not a download failure).
    pub fn fail(&self, code: ErrorCode, cancelled: bool) {
        if cancelled {
            self.close(Outcome::Cancelled, None);
        } else {
            self.close(Outcome::Failed, Some(code));
        }
    }

    /// The operator cancelled during the open step.
    pub fn cancelled(&self) {
        self.close(Outcome::Cancelled, None);
    }

    /// The open step did not apply after all (a conditional step that found
    /// nothing to do): forget it, record nothing.
    pub fn discard(&self) {
        self.lock().open = None;
    }

    /// The pipeline finished: `done`, with the whole pipeline's elapsed.
    pub fn done(&self) {
        let mut g = self.lock();
        if let Some((open, since)) = g.open.take() {
            let elapsed = Self::ms(since);
            self.record(&mut g, open, Outcome::Ok, elapsed, None);
        }
        let elapsed = g.pipeline_started.take().map(Self::ms).unwrap_or(0);
        self.record(&mut g, Step::Done, Outcome::Ok, elapsed, None);
    }

    /// The pipeline ended in an error with a step still open: close it as
    /// failed with `code` (or cancelled). Nothing to do when every site
    /// closed its own step, which is the normal case.
    pub fn abandon(&self, code: ErrorCode, cancelled: bool) {
        let mut g = self.lock();
        if g.open.is_some() {
            drop(g);
            self.fail(code, cancelled);
        } else {
            g.pipeline_started = None;
        }
    }

    fn close(&self, outcome: Outcome, code: Option<ErrorCode>) {
        let mut g = self.lock();
        let Some((step, since)) = g.open.take() else {
            return;
        };
        let elapsed = Self::ms(since);
        self.record(&mut g, step, outcome, elapsed, code);
    }

    fn ms(since: Instant) -> u64 {
        u64::try_from(since.elapsed().as_millis())
            .unwrap_or(ELAPSED_MS_MAX)
            .min(ELAPSED_MS_MAX)
    }

    /// Build and route one record. The gate: nothing while unticked. The
    /// OS family must be one the server accepts, else there is no record
    /// to send at all.
    fn record(
        &self,
        g: &mut Inner,
        step: Step,
        outcome: Outcome,
        elapsed_ms: u64,
        code: Option<ErrorCode>,
    ) {
        if !g.opted_in {
            return;
        }
        let os = std::env::consts::OS;
        if !OS_FAMILIES.contains(&os) {
            return;
        }
        let d = SetupDiagnostic {
            run: Self::run_of(g),
            step: step.wire().to_string(),
            outcome: outcome.wire().to_string(),
            elapsed_ms: elapsed_ms.min(ELAPSED_MS_MAX),
            error_code: match outcome {
                Outcome::Failed => Some(code.unwrap_or(ErrorCode::Other).wire().to_string()),
                _ => None,
            },
            os: os.to_string(),
            wizard_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        match &g.endpoint {
            Some(url) => self.sender.send(url.clone(), d),
            None => g.buffered.push(d),
        }
    }
}

/// The operator's pre-spawn cancel flag, as the orchestrators read it.
pub fn cancel_requested() -> bool {
    crate::CANCEL_REQUESTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Close the open diagnostics step as failed with `code` — or cancelled,
/// when the cancel flag is what failed it — and hand the message back
/// unchanged, so an orchestrator's error site reads `Err(failed(code, msg))`
/// and its message to the operator is exactly what it was.
pub fn failed(code: ErrorCode, message: String) -> String {
    Diagnostics::global().fail(code, cancel_requested());
    message
}

/// Which code an enroll error is: a failure to get an answer (a
/// `reqwest::Error` anywhere in the chain — a refused connection, a
/// timeout, a TLS failure, an unreadable answer) is `enroll_network`; a
/// server that answered and said no is `enroll_rejected`. Decided on the
/// error's types, never on its text.
pub fn enroll_error_code(e: &anyhow::Error) -> ErrorCode {
    if e.chain()
        .any(|c| c.downcast_ref::<reqwest::Error>().is_some())
    {
        ErrorCode::EnrollNetwork
    } else {
        ErrorCode::EnrollRejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sender that keeps what it was given.
    #[derive(Default)]
    struct Counting {
        sent: Mutex<Vec<(String, SetupDiagnostic)>>,
    }

    impl Sender for Counting {
        fn send(&self, url: String, record: SetupDiagnostic) {
            self.sent.lock().unwrap().push((url, record));
        }
    }

    fn recorder() -> (Diagnostics, Arc<Counting>) {
        let sender = Arc::new(Counting::default());
        (Diagnostics::new(sender.clone()), sender)
    }

    /// Every boundary a daemon-role run passes, in the order the SPA and
    /// the orchestrator pass them: three pages, the server named at
    /// `cmd_install`, eight pipeline steps, done.
    const PIPELINE: [Step; 8] = [
        Step::Preflight,
        Step::Resolve,
        Step::Download,
        Step::Verify,
        Step::Msi,
        Step::Enroll,
        Step::Companion,
        Step::Anchor,
    ];

    fn full_run(d: &Diagnostics) {
        d.page(Step::Welcome, Outcome::Ok, 1200);
        d.page(Step::Server, Outcome::Ok, 800);
        d.page(Step::Token, Outcome::Ok, 400);
        d.server_known("https://meshharbor.itachi.fans/");
        d.pipeline_started();
        for step in PIPELINE {
            d.begin(step);
            d.ok();
        }
        d.done();
    }

    /// AC12, the unticked half: a full run makes zero requests — and
    /// buffers nothing either, so nothing can leave later.
    #[test]
    fn unticked_a_full_run_sends_nothing() {
        let (d, sent) = recorder();
        assert!(!d.opted_in(), "off by default");
        full_run(&d);
        assert_eq!(sent.sent.lock().unwrap().len(), 0);
        assert!(d.lock().buffered.is_empty());
        assert_eq!(d.run_id(), None, "no run id rides the enroll");
    }

    /// AC12, the ticked half: one request per boundary — 3 pages + 8 steps
    /// + done — each with exactly the seven documented keys, every one
    /// valid by the server's own check, one run id across all of them, to
    /// the enrolling server's route.
    #[test]
    fn ticked_sends_one_record_per_boundary_with_exactly_the_fields() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        full_run(&d);
        let sent = sent.sent.lock().unwrap();
        assert_eq!(sent.len(), 3 + PIPELINE.len() + 1);
        let run = d.run_id().expect("ticked: the run id rides the enroll");
        assert_eq!(run.len(), 32);
        assert!(
            run.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let mut steps = Vec::new();
        for (url, record) in sent.iter() {
            assert_eq!(url, "https://meshharbor.itachi.fans/api/setup/diagnostics");
            let v = serde_json::to_value(record).unwrap();
            let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(
                keys,
                [
                    "run",
                    "step",
                    "outcome",
                    "elapsed_ms",
                    "error_code",
                    "os",
                    "wizard_version"
                ]
            );
            assert_eq!(record.validate(), Ok(()), "{record:?}");
            assert_eq!(record.run, run);
            assert_eq!(record.outcome, "ok");
            assert!(record.error_code.is_none());
            assert_eq!(record.wizard_version, env!("CARGO_PKG_VERSION"));
            assert_eq!(record.os, std::env::consts::OS);
            steps.push(record.step.clone());
        }
        let mut expected = vec!["welcome", "server", "token"];
        expected.extend(PIPELINE.iter().map(|s| s.wire()));
        expected.push("done");
        assert_eq!(steps, expected, "in order, the pages first");
        assert_eq!(sent[0].1.elapsed_ms, 1200);
        assert_eq!(
            d.run_id().as_deref(),
            Some(run.as_str()),
            "stable for the process"
        );
    }

    /// The pages happen before the server is known: buffered, then flushed
    /// in order at the first known server, then sent at once.
    #[test]
    fn page_boundaries_are_buffered_until_the_server_is_known() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        d.page(Step::Welcome, Outcome::Ok, 10);
        d.page(Step::Server, Outcome::Ok, 20);
        assert_eq!(sent.sent.lock().unwrap().len(), 0, "nowhere to send yet");
        assert_eq!(d.lock().buffered.len(), 2);
        d.server_known("https://self-hosted.example");
        {
            let s = sent.sent.lock().unwrap();
            assert_eq!(s.len(), 2);
            assert_eq!(s[0].0, "https://self-hosted.example/api/setup/diagnostics");
            assert_eq!(s[0].1.step, "welcome");
            assert_eq!(s[1].1.step, "server");
        }
        assert!(d.lock().buffered.is_empty());
        d.page(Step::Token, Outcome::Ok, 30);
        assert_eq!(sent.sent.lock().unwrap().len(), 3, "sent at once now");
    }

    /// A run cancelled before a server is known sends nothing anywhere —
    /// and unticking drops the buffer, so a server named later gets
    /// nothing from before either.
    #[test]
    fn a_run_cancelled_before_the_server_is_known_sends_nothing() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        d.page(Step::Welcome, Outcome::Ok, 10);
        d.page(Step::Server, Outcome::Cancelled, 20);
        assert_eq!(sent.sent.lock().unwrap().len(), 0);
        d.set_opt_in(false);
        assert!(d.lock().buffered.is_empty(), "unticking drops the buffer");
        d.server_known("https://meshharbor.itachi.fans");
        assert_eq!(sent.sent.lock().unwrap().len(), 0);
    }

    /// A failed step carries its code; a cancel is `cancelled` with none;
    /// a step the pipeline abandoned is closed by `abandon`; a conditional
    /// step that found nothing to do is discarded; a forgotten open step
    /// is closed as `ok` by the next `begin`.
    #[test]
    fn outcomes_and_codes_follow_the_sites() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        d.server_known("https://meshharbor.itachi.fans");
        d.pipeline_started();
        d.begin(Step::Msi);
        d.fail(ErrorCode::MsiUserCancel, false);
        d.begin(Step::Download);
        d.fail(ErrorCode::Download, true);
        d.begin(Step::Companion);
        d.discard();
        d.begin(Step::Preflight);
        d.begin(Step::Resolve); // preflight was never closed
        d.abandon(ErrorCode::Other, false);
        d.abandon(ErrorCode::Other, false); // nothing open: nothing recorded
        let s = sent.sent.lock().unwrap();
        let view: Vec<(&str, &str, Option<&str>)> = s
            .iter()
            .map(|(_, r)| (r.step.as_str(), r.outcome.as_str(), r.error_code.as_deref()))
            .collect();
        assert_eq!(
            view,
            [
                ("msi", "failed", Some("msi_user_cancel")),
                ("download", "cancelled", None),
                ("preflight", "ok", None),
                ("resolve", "failed", Some("other")),
            ]
        );
        for (_, r) in s.iter() {
            assert_eq!(r.validate(), Ok(()), "{r:?}");
        }
    }

    /// A page name outside the three pages is not a page boundary.
    #[test]
    fn only_the_pages_are_page_boundaries() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        d.server_known("https://meshharbor.itachi.fans");
        d.page(Step::Msi, Outcome::Ok, 1);
        d.page(Step::Done, Outcome::Ok, 1);
        assert_eq!(sent.sent.lock().unwrap().len(), 0);
    }

    /// `done` carries the whole pipeline's elapsed and closes an open step.
    #[test]
    fn done_closes_the_open_step_and_measures_the_pipeline() {
        let (d, sent) = recorder();
        d.set_opt_in(true);
        d.server_known("https://meshharbor.itachi.fans");
        d.pipeline_started();
        d.begin(Step::Enroll);
        d.done();
        let s = sent.sent.lock().unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1.step, "enroll");
        assert_eq!(s[1].1.step, "done");
        assert!(s[1].1.elapsed_ms <= ELAPSED_MS_MAX);
    }

    /// The enroll's code is decided on the error chain's types.
    #[test]
    fn an_enroll_error_is_network_or_rejected_by_its_type() {
        let rejected =
            anyhow::anyhow!("enrollment rejected (status 401 Unauthorized): Token expired");
        assert_eq!(enroll_error_code(&rejected), ErrorCode::EnrollRejected);
        // A reqwest::Error is only produced by reqwest itself; the public
        // surface that yields one without a network is an invalid URL on
        // the request builder. Wrapped the way `enroll` wraps its errors.
        let err = reqwest::Client::new()
            .get("::not a url::")
            .build()
            .expect_err("an invalid URL is a reqwest::Error");
        let wrapped = anyhow::Error::new(err).context("POST /api/agent/enroll");
        assert_eq!(enroll_error_code(&wrapped), ErrorCode::EnrollNetwork);
    }
}
