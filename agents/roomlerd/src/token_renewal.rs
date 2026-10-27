// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-103 — an enrollment renews its own agent token before it expires.
//!
//! An agent token lives 365 days from enrollment, and until FR-103 nothing
//! renewed it: every device would have dropped offline on its anniversary,
//! and getting it back needed hands on the machine. The server's half
//! (`POST /api/agent/self/renew`) hands a device a fresh token for itself:
//!
//! * **idempotent, no rotation** — the old token stays valid until its own
//!   `exp`, so a lost answer costs nothing and a copy that missed the change
//!   keeps working;
//! * **a 90-day grace** — that route alone accepts a token up to 90 days past
//!   its expiry, so a device that slept through its anniversary still comes
//!   back on its own;
//! * **refused** for a removed, quarantined or superseded device: a removal,
//!   not this route, is what ends a credential.
//!
//! This is the device's half. Per enrollment (the primary and every
//! `[[orgs]]` entry, each against its own server):
//!
//! | When | What |
//! |---|---|
//! | after every connect, and every 12 h while connected | renew if due |
//! | the server refused the token (HTTP 401) | use a newer token from the config file if there is one, else try a renewal (the grace) |
//!
//! "Due" = less than [`DEFAULT_HORIZON_DAYS`] of life left, or less than half
//! the token's lifetime, whichever comes first: a 365-day token renews with
//! 180 days to spare, and a short-lived one at half-life rather than after
//! it has already expired.
//!
//! A renewed token is saved (a compare-and-swap under the daemon's config
//! lock, [`crate::remote_config::RemoteConfigServices::persist_agent_token`])
//! and then put in the enrollment's [`TokenSlot`], which every consumer reads
//! at the moment of use: the next reconnect, DERP dial, device-list request
//! and log or crash upload carry it. A save that fails does not hold the
//! renewal back: nothing is rotated, so the token on disk stays valid, and
//! the new one is used until a restart reads the file again.
//!
//! Kill switch: `ROOMLERD_TOKEN_RENEWAL=0` turns all of it off, and the
//! daemon keeps the token it started with, as before FR-103.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::remote_config::{RemoteConfigServices, TokenWrite};
use crate::token_slot::TokenSlot;

/// Renew once a token has less than this many days left: the tunnel client's
/// constant, so the two can never drift apart.
pub use roomler_cli::credential::DEFAULT_HORIZON_DAYS;
/// How often a connected enrollment looks again.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
/// After an attempt that failed for a reason that may pass (the server
/// unreachable, a 5xx, a save that failed), look again this soon.
const DEFAULT_RETRY: Duration = Duration::from_secs(60 * 60);
/// Never look again sooner than this, however close the token is to its
/// renewal point.
const MIN_RECHECK: Duration = Duration::from_secs(60);
/// The whole renewal request, connect to body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The renewal knobs. Production reads them once with [`Settings::from_env`];
/// a test passes its own, because a test that sets an environment variable
/// races every other test in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Off = no renewal and no adopting a token from the config file.
    pub enabled: bool,
    /// `None` = the default rule: renew with [`DEFAULT_HORIZON_DAYS`] left,
    /// or at half the token's lifetime if that comes first. `Some` = renew
    /// once the token has less than exactly this left, whatever its
    /// lifetime: the override the field test uses to make a fresh token due.
    pub horizon: Option<Duration>,
    pub interval: Duration,
    pub retry: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            horizon: None,
            interval: DEFAULT_INTERVAL,
            retry: DEFAULT_RETRY,
        }
    }
}

impl Settings {
    /// `ROOMLERD_TOKEN_RENEWAL` (default on) and
    /// `ROOMLERD_TOKEN_RENEW_BEFORE_DAYS` (1–3650 days, an exact override of
    /// the default rule; a value above the token's lifetime makes it due at
    /// once and at every look after, so it is a testing knob).
    pub fn from_env() -> Self {
        Self {
            enabled: tunnel_core::env::flag("TOKEN_RENEWAL", true),
            horizon: tunnel_core::env::node_env("TOKEN_RENEW_BEFORE_DAYS")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|d| (1..=3650).contains(d))
                .map(|days| Duration::from_secs(days * 86_400)),
            ..Self::default()
        }
    }
}

/// Where a token stands against its renewal point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Time to renew. `expires_at` is the token's `exp` (unix seconds).
    Now { expires_at: i64 },
    /// Not yet: due in `in_secs`.
    Later { expires_at: i64, in_secs: i64 },
    /// The token carries no readable `exp`, so there is nothing to schedule
    /// by. A device keeps such a token as it is.
    Unknown,
}

/// Is `token` due for renewal at `now_unix`? `horizon` as in
/// [`Settings::horizon`]; the default rule is in the module doc.
pub fn due(token: &str, now_unix: i64, horizon: Option<Duration>) -> Due {
    let Ok(view) = crate::jwt_introspect::parse_unverified(token) else {
        return Due::Unknown;
    };
    let Some(expires_at) = view.expires_at_unix else {
        return Due::Unknown;
    };
    // The ONE rule, shared with the tunnel client, so the daemon and the
    // client never disagree about when a credential is due.
    let renew_at = roomler_cli::credential::renew_at(expires_at, view.issued_at_unix, horizon);
    if now_unix >= renew_at {
        Due::Now { expires_at }
    } else {
        Due::Later {
            expires_at,
            in_secs: renew_at - now_unix,
        }
    }
}

/// The token's `exp` (unix seconds), read without verifying it. For
/// display: `meshharbor status` shows when each enrollment's credential lapses.
pub fn expires_at(token: &str) -> Option<i64> {
    crate::jwt_introspect::parse_unverified(token)
        .ok()?
        .expires_at_unix
}

/// What the server said to a renewal request.
pub enum Reply {
    Renewed {
        token: String,
    },
    /// 404: a server without the route (older than FR-103), or with
    /// `rc.token_renewal` off. The current token stays in use.
    Unsupported,
    /// 401/403: this token is not renewable: the device was removed,
    /// quarantined or re-enrolled elsewhere, or the token is past the grace.
    Refused {
        status: u16,
    },
}

#[derive(Deserialize)]
struct RenewBody {
    agent_token: String,
}

/// `POST {server}/api/agent/self/renew` with `token`. An `Err` is a failure
/// that may pass (unreachable, a 5xx, a body that did not parse).
pub async fn request(server_url: &str, token: &str) -> anyhow::Result<Reply> {
    let base = server_url.trim().trim_end_matches('/');
    let url = format!("{base}/api/agent/self/renew");
    let client = reqwest::Client::builder()
        .user_agent(concat!(
            "roomlerd-token-renewal/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("building the renewal client")?;
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .send()
        .await
        .context("POST /api/agent/self/renew")?;
    match resp.status().as_u16() {
        200..=299 => {
            let body: RenewBody = resp.json().await.context("reading the renewal answer")?;
            if body.agent_token.trim().is_empty() {
                bail!("the renewal answer carried no token");
            }
            Ok(Reply::Renewed {
                token: body.agent_token,
            })
        }
        404 => Ok(Reply::Unsupported),
        status @ (401 | 403) => Ok(Reply::Refused { status }),
        status => bail!("the server answered {status}"),
    }
}

/// The enrollment a renewal acts for: its server, tenant and device, and the
/// live slot its consumers read.
#[derive(Clone, Debug)]
pub struct Enrollment {
    /// `primary` or the `[[orgs]]` label, for log lines.
    pub label: String,
    pub server_url: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub token: TokenSlot,
}

/// What one renewal attempt came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Renewed, saved, and in use.
    Renewed,
    /// Renewed and in use, but the config could not be saved: the next
    /// restart goes back to the token on disk, which is still valid.
    RenewedUnsaved,
    /// The config file already held a newer token for this device (it was
    /// re-enrolled meanwhile); that one is in use now.
    AdoptedFromFile,
    Unsupported,
    Refused,
    /// May pass: look again after [`Settings::retry`].
    Failed,
}

/// Ask for a renewal of the token in use; on success save it, then use it.
pub async fn renew(enrollment: &Enrollment, remote_cfg: &RemoteConfigServices) -> Outcome {
    let current = enrollment.token.get();
    let reply = match request(&enrollment.server_url, &current).await {
        Ok(reply) => reply,
        Err(e) => {
            warn!(
                org = %enrollment.label,
                error = %format!("{e:#}"),
                "token renewal: no answer from the server; trying again later"
            );
            return Outcome::Failed;
        }
    };
    let fresh = match reply {
        Reply::Renewed { token } => token,
        Reply::Unsupported => {
            info!(
                org = %enrollment.label,
                "token renewal: this server does not offer it; keeping the current token"
            );
            return Outcome::Unsupported;
        }
        Reply::Refused { status } => {
            warn!(
                org = %enrollment.label,
                status,
                "token renewal refused: the device was removed, quarantined or re-enrolled \
                 elsewhere, or its token expired more than 90 days ago"
            );
            return Outcome::Refused;
        }
    };
    // Teach the redactor before the token can reach any output.
    crate::exec::register_secret(&fresh);
    let expires = expires_at(&fresh);
    match remote_cfg
        .persist_agent_token(
            &enrollment.server_url,
            &enrollment.tenant_id,
            &enrollment.agent_id,
            &current,
            fresh.clone(),
        )
        .await
    {
        Ok(TokenWrite::Saved) => {
            enrollment.token.set(fresh);
            info!(
                org = %enrollment.label,
                expires_at = expires.unwrap_or_default(),
                "agent token renewed"
            );
            Outcome::Renewed
        }
        Ok(TokenWrite::Superseded(stored)) => {
            crate::exec::register_secret(&stored);
            enrollment.token.set(stored);
            info!(
                org = %enrollment.label,
                "token renewal: the device was re-enrolled meanwhile; using the token in the config file"
            );
            Outcome::AdoptedFromFile
        }
        Err(e) => {
            // Unlike a rotated overlay key, nothing is retired here: the token
            // on disk stays valid until its own `exp`. Using the renewed one
            // now costs nothing if the save keeps failing (an unwritable
            // config, a full disk), and keeps the device connected until a
            // restart reads the file again.
            enrollment.token.set(fresh);
            warn!(
                org = %enrollment.label,
                error = %e,
                "token renewal: renewed, but the config could not be saved; \
                 using the new token until the daemon restarts"
            );
            Outcome::RenewedUnsaved
        }
    }
}

/// The server refused this enrollment's token. Before the reconnect ladder
/// waits it out:
///
/// 1. a token in the config file that is not the one in use, written by
///    `roomlerd re-enroll` (or the companion) while this daemon ran;
/// 2. a renewal, which the server grants up to 90 days past expiry.
///
/// `true` = a different token is in use now, and a reconnect is worth trying
/// at once.
pub async fn recover(
    enrollment: &Enrollment,
    remote_cfg: &RemoteConfigServices,
    settings: Settings,
) -> bool {
    if !settings.enabled {
        return false;
    }
    if let Some(stored) = remote_cfg
        .stored_agent_token(
            &enrollment.server_url,
            &enrollment.tenant_id,
            &enrollment.agent_id,
        )
        .await
        && stored != enrollment.token.get()
    {
        crate::exec::register_secret(&stored);
        enrollment.token.set(stored);
        info!(
            org = %enrollment.label,
            "the server refused the token in use; switching to the newer one in the config file"
        );
        return true;
    }
    matches!(
        renew(enrollment, remote_cfg).await,
        Outcome::Renewed | Outcome::RenewedUnsaved | Outcome::AdoptedFromFile
    )
}

/// What one look decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    /// When to look next.
    pub next: Duration,
    /// The look asked the server and failed for a reason that may pass.
    /// Until `next`, a reconnect does not earn another try: on a link that
    /// flaps while the server fails, every reconnect would otherwise ask.
    pub failed: bool,
}

/// One look: renew if due.
pub async fn check_once(
    enrollment: &Enrollment,
    remote_cfg: &RemoteConfigServices,
    settings: Settings,
    now_unix: i64,
) -> Look {
    let later = |next: Duration| Look {
        next,
        failed: false,
    };
    let in_secs = match due(&enrollment.token.get(), now_unix, settings.horizon) {
        Due::Unknown => {
            debug!(org = %enrollment.label, "token renewal: the token carries no expiry");
            return later(settings.interval);
        }
        Due::Later { in_secs, .. } => in_secs,
        Due::Now { .. } => match renew(enrollment, remote_cfg).await {
            Outcome::Failed => {
                return Look {
                    next: settings.retry,
                    failed: true,
                };
            }
            Outcome::Renewed | Outcome::RenewedUnsaved | Outcome::AdoptedFromFile => {
                // Schedule by the token now in use.
                match due(&enrollment.token.get(), now_unix, settings.horizon) {
                    Due::Later { in_secs, .. } => in_secs,
                    _ => return later(settings.interval),
                }
            }
            Outcome::Unsupported | Outcome::Refused => return later(settings.interval),
        },
    };
    later(
        Duration::from_secs(u64::try_from(in_secs).unwrap_or(0))
            .clamp(MIN_RECHECK, settings.interval),
    )
}

/// The per-enrollment task, owned by its signalling loop: the first look
/// waits for a connect (`connected`), so a device that cannot reach its
/// server does not ask it for anything; after that, a look after every
/// connect and on the schedule [`check_once`] returns.
pub async fn run(
    enrollment: Enrollment,
    remote_cfg: RemoteConfigServices,
    settings: Settings,
    connected: Arc<tokio::sync::Notify>,
) {
    if !settings.enabled {
        return;
    }
    let mut last: Option<Look> = None;
    loop {
        match last {
            None => connected.notified().await,
            // After a failure, the full retry delay: reconnects meanwhile
            // leave one stored wake-up, which the next look's wait consumes.
            Some(look) if look.failed => tokio::time::sleep(look.next).await,
            Some(look) => {
                tokio::select! {
                    _ = tokio::time::sleep(look.next) => {},
                    _ = connected.notified() => {},
                }
            }
        }
        // Spread a fleet that reconnected at once (a server roll) over a
        // minute, so its renewals do not all land in the same second.
        tokio::time::sleep(Duration::from_millis(rand::random_range(0..60_000))).await;
        last = Some(check_once(&enrollment, &remote_cfg, settings, unix_now()).await);
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const DAY: i64 = 86_400;

    fn token(claims: serde_json::Value) -> String {
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        format!(
            "{}.{}.sig",
            enc(br#"{"alg":"HS256","typ":"JWT"}"#),
            enc(claims.to_string().as_bytes())
        )
    }

    fn horizon() -> Option<Duration> {
        Settings::default().horizon
    }

    /// A year-long token renews with 180 days left, not before.
    #[test]
    fn a_year_long_token_is_due_with_180_days_left() {
        let t = token(serde_json::json!({ "iat": 0, "exp": 365 * DAY }));
        assert_eq!(
            due(&t, 184 * DAY, horizon()),
            Due::Later {
                expires_at: 365 * DAY,
                in_secs: DAY
            }
        );
        assert_eq!(
            due(&t, 185 * DAY, horizon()),
            Due::Now {
                expires_at: 365 * DAY
            }
        );
        // Expired is due too: the server's grace may still renew it.
        assert_eq!(
            due(&t, 400 * DAY, horizon()),
            Due::Now {
                expires_at: 365 * DAY
            }
        );
    }

    /// A short-lived token renews at half-life: inside a 180-day horizon a
    /// one-hour token would otherwise be "due" from birth, and renewed on
    /// every look.
    #[test]
    fn a_short_token_is_due_at_half_life() {
        let t = token(serde_json::json!({ "iat": 1_000, "exp": 4_600 }));
        assert_eq!(
            due(&t, 2_000, horizon()),
            Due::Later {
                expires_at: 4_600,
                in_secs: 800
            }
        );
        assert_eq!(due(&t, 2_800, horizon()), Due::Now { expires_at: 4_600 });
    }

    /// Without `iat`, only the horizon decides.
    #[test]
    fn without_iat_the_horizon_decides() {
        let t = token(serde_json::json!({ "exp": 365 * DAY }));
        assert!(matches!(due(&t, 100 * DAY, horizon()), Due::Later { .. }));
        assert!(matches!(due(&t, 200 * DAY, horizon()), Due::Now { .. }));
    }

    #[test]
    fn a_token_without_a_readable_expiry_is_never_due() {
        assert_eq!(due("not-a-jwt", 0, horizon()), Due::Unknown);
        assert_eq!(
            due(&token(serde_json::json!({ "sub": "x" })), 0, horizon()),
            Due::Unknown
        );
    }

    /// The field-test knob is an EXACT override: a horizon longer than the
    /// lifetime makes a token due from birth. Under the default rule the
    /// half-life cap would win and the knob would change nothing.
    #[test]
    fn the_override_makes_a_fresh_token_due() {
        let t = token(serde_json::json!({ "iat": 0, "exp": 365 * DAY }));
        let long = Some(Duration::from_secs(400 * 86_400));
        assert!(matches!(due(&t, 0, long), Due::Now { .. }));
        assert!(matches!(due(&t, 0, horizon()), Due::Later { .. }));
        // And a short override renews later than the default would.
        let short = Some(Duration::from_secs(10 * 86_400));
        assert!(matches!(due(&t, 300 * DAY, short), Due::Later { .. }));
    }

    #[test]
    fn expires_at_reads_exp() {
        assert_eq!(
            expires_at(&token(serde_json::json!({ "exp": 42 }))),
            Some(42)
        );
        assert_eq!(expires_at("garbage"), None);
    }

    fn enrollment(dir: &std::path::Path) -> (Enrollment, RemoteConfigServices) {
        let path = dir.join("config.toml");
        let cfg = crate::config::test_fixture();
        crate::config::save(&path, &cfg).unwrap();
        let svc =
            RemoteConfigServices::new(path, Arc::new(tokio::sync::Mutex::new(())), false, false);
        let e = Enrollment {
            label: "primary".into(),
            server_url: cfg.server_url.clone(),
            tenant_id: cfg.tenant_id.clone(),
            agent_id: cfg.agent_id.clone(),
            token: TokenSlot::new(cfg.agent_token.clone()),
        };
        (e, svc)
    }

    /// A 401 with a newer token on disk (`roomlerd re-enroll` ran while the
    /// daemon did) switches to it without asking the server anything.
    #[tokio::test]
    async fn a_refused_token_switches_to_a_newer_one_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let (e, svc) = enrollment(dir.path());
        let reader = e.token.clone();
        let path = dir.path().join("config.toml");
        let mut on_disk = crate::config::load(&path).unwrap();
        on_disk.agent_token = "re-enrolled-token-0123456789".into();
        crate::config::save(&path, &on_disk).unwrap();

        assert!(recover(&e, &svc, Settings::default()).await);
        assert_eq!(reader.get(), "re-enrolled-token-0123456789");
    }

    /// The kill switch: nothing is adopted, nothing is asked.
    #[tokio::test]
    async fn the_kill_switch_keeps_the_token_it_started_with() {
        let dir = tempfile::tempdir().unwrap();
        let (e, svc) = enrollment(dir.path());
        let before = e.token.get();
        let path = dir.path().join("config.toml");
        let mut on_disk = crate::config::load(&path).unwrap();
        on_disk.agent_token = "re-enrolled-token-0123456789".into();
        crate::config::save(&path, &on_disk).unwrap();

        let off = Settings {
            enabled: false,
            ..Settings::default()
        };
        assert!(!recover(&e, &svc, off).await);
        assert_eq!(e.token.get(), before);
    }

    /// A file whose enrollment now names ANOTHER device is not adopted: that
    /// token is the other device's.
    #[tokio::test]
    async fn a_token_on_disk_for_another_device_is_not_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let (e, svc) = enrollment(dir.path());
        let before = e.token.get();
        let path = dir.path().join("config.toml");
        let mut on_disk = crate::config::load(&path).unwrap();
        on_disk.agent_token = "another-devices-token-0123456789".into();
        on_disk.agent_id = "another-agent-id".into();
        crate::config::save(&path, &on_disk).unwrap();

        assert_eq!(
            svc.stored_agent_token(&e.server_url, &e.tenant_id, &e.agent_id)
                .await,
            None
        );
        assert_eq!(e.token.get(), before);
    }
}
