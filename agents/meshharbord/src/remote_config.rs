// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Applying a pushed desired-config (`docs/remote-config.md` step 4).
//!
//! Rides into `signaling::run` as one value rather than three loose
//! parameters, the same way `ssh::SessionServices` rides through
//! `overlay::maybe_start` — and for the same reason: "no services ⇒ cannot
//! apply" should be unrepresentable rather than a `None` check somebody
//! forgets.
//!
//! # Why `exec_enabled` is live and `ssh_enabled` is not
//!
//! `signaling::run` takes an OWNED `AgentConfig` snapshot at startup, so a key
//! read from it can never change in a running daemon. Persisting to disk alone
//! would leave the dashboard reporting a change that does nothing until
//! somebody restarts the box — worse than not shipping, because it reads as
//! applied.
//!
//! `exec_enabled` escapes that: it has exactly ONE read site (the `rc:rpc.exec`
//! gate, checked per request), so routing it through an `AtomicBool` makes it
//! genuinely live. Flipping it takes effect on the next command, with no
//! restart and therefore no risk of taking a host offline.
//!
//! `ssh_enabled` does NOT escape it. The SSH server is spliced into the packet
//! path at overlay-runtime build time (`ssh::maybe_intercept` → `SplitTun`),
//! and `overlay::RuntimeFingerprint` — which decides whether a respawned
//! runtime re-attaches or rebuilds — has no SSH field, so a flipped value does
//! not even trigger a rebuild. It is persisted here and honestly reported as
//! needing a restart, rather than pretended into effect.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use meshharbor_remote_control::models::DesiredConfig;

/// What applying a desired-config actually achieved. Split because the two
/// halves are genuinely different and an operator needs to know which they
/// got: one is in force now, the other is written down and waiting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Keys that changed and are ALREADY in force.
    pub live: Vec<&'static str>,
    /// Keys that changed on disk but need a daemon restart to take effect.
    pub needs_restart: Vec<&'static str>,
}

impl Applied {
    pub fn is_noop(&self) -> bool {
        self.live.is_empty() && self.needs_restart.is_empty()
    }
}

#[derive(Clone)]
pub struct RemoteConfigServices {
    path: PathBuf,
    lock: crate::config::WriteLock,
    /// The LIVE `exec_enabled`, read by the `rc:rpc.exec` gate. Seeded from
    /// the startup config and the only copy that decides anything.
    exec_enabled: Arc<AtomicBool>,
    /// The LIVE opt-in, read by the `rc:agent.config` handler.
    ///
    /// Live for a reason that is the whole point of the key: it is how the
    /// person holding the machine REVOKES the delegation. A revocation that
    /// only took effect after a service restart — while the control plane's
    /// assertions took effect immediately — would be a strange kind of last
    /// word. The server can never write this; only [`Self::adopt_local`] can.
    remote_config_enabled: Arc<AtomicBool>,
    /// FR-52 P3 — the device's external-login state: guess budget, in-flight
    /// logins, verified grants.
    ///
    /// Here because this struct is built ONCE per daemon (`main.rs`) and cloned
    /// into every org's control loop and the LocalAPI: the budget has to be the
    /// DEVICE's, and one per loop would hand an attacker a separate budget for
    /// every org the device belongs to. It is NOT a process-wide static — that
    /// would be device-global too, but the integration tests run many agents in
    /// one process, and a shared static would make one test's wrong passwords
    /// throttle another's.
    #[cfg(feature = "external-access")]
    external_logins: Arc<crate::external_logins::ExternalLogins>,
    /// FR-100 P1b — what signing each session's answer needs, gathered as its
    /// frames pass through the daemon. Here for `external_logins`' reason:
    /// one per daemon, never a static the integration tests' agents share.
    peer_auth_offers: Arc<crate::peer_auth::PendingOffers>,
    /// FR-100 P1c — the LIVE `peer_auth` policy, read at every offer. `audit`
    /// until [`Self::adopt_local`] seeds the configured value; only the
    /// person at the console can change it, and never the server.
    peer_auth_policy: Arc<std::sync::atomic::AtomicU8>,
}

/// FR-100 P1c — the policy in an atomic: `0` off, `1` audit.
fn policy_bits(p: crate::peer_auth::PeerAuthPolicy) -> u8 {
    match p {
        crate::peer_auth::PeerAuthPolicy::Off => 0,
        crate::peer_auth::PeerAuthPolicy::Audit => 1,
    }
}

/// FR-52 P4 — the device's own terms for an external session, as stored.
/// See [`RemoteConfigServices::external_session_live`].
#[cfg(feature = "external-access")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalSessionConfig {
    /// `external_consent_mode`, unparsed. `None` = `prompt`.
    pub consent_mode: Option<String>,
    /// `external_max_permissions`, unparsed. `None` = defer to the org.
    pub max_permissions: Option<String>,
}

impl RemoteConfigServices {
    pub fn new(
        path: PathBuf,
        lock: crate::config::WriteLock,
        exec_enabled: bool,
        remote_config_enabled: bool,
    ) -> Self {
        Self {
            path,
            lock,
            exec_enabled: Arc::new(AtomicBool::new(exec_enabled)),
            remote_config_enabled: Arc::new(AtomicBool::new(remote_config_enabled)),
            #[cfg(feature = "external-access")]
            external_logins: Arc::new(crate::external_logins::ExternalLogins::new()),
            peer_auth_offers: Arc::new(crate::peer_auth::PendingOffers::default()),
            peer_auth_policy: Arc::new(std::sync::atomic::AtomicU8::new(policy_bits(
                crate::peer_auth::PeerAuthPolicy::Audit,
            ))),
        }
    }

    /// FR-100 P1c — the device's `peer_auth` policy at this moment.
    pub fn peer_auth_policy(&self) -> crate::peer_auth::PeerAuthPolicy {
        match self.peer_auth_policy.load(Ordering::Relaxed) {
            0 => crate::peer_auth::PeerAuthPolicy::Off,
            _ => crate::peer_auth::PeerAuthPolicy::Audit,
        }
    }

    /// FR-100 P1b — the daemon's table of what each session's answer will be
    /// signed against (see the field).
    pub fn peer_auth_offers(&self) -> &crate::peer_auth::PendingOffers {
        &self.peer_auth_offers
    }

    /// The config file this daemon runs from. #2293 — the removal's sentinel
    /// names the restart that fits its install.
    pub fn config_path(&self) -> &std::path::Path {
        &self.path
    }

    /// FR-52 P3 — the device's one external-login state (see the field).
    #[cfg(feature = "external-access")]
    pub fn external_logins(&self) -> &crate::external_logins::ExternalLogins {
        &self.external_logins
    }

    /// Gate 4 for Fleet RPC, read per request.
    pub fn exec_enabled(&self) -> bool {
        self.exec_enabled.load(Ordering::Relaxed)
    }

    /// Does this device accept pushed config at all? Read per push.
    pub fn remote_config_enabled(&self) -> bool {
        self.remote_config_enabled.load(Ordering::Relaxed)
    }

    /// FR-52 P3 — gate 3 and the gate-4 record, read from the config FILE at
    /// the moment an outsider knocks.
    ///
    /// Live for the reason `exec_enabled` is live: `meshharbor rc password clear`
    /// and `config set external_access_enabled false` are how the person at the
    /// machine REVOKES cross-org access. A revocation that took effect only at
    /// the next restart would leave an outsider able to log in after the owner
    /// believed they had shut them out — the one direction in which "stale"
    /// cannot be allowed.
    ///
    /// `None` = gate 3 is shut, or no complete record is stored: the device is
    /// not accepting external logins. An unreadable file is the same answer —
    /// failing closed is the only safe reading of "cannot tell".
    #[cfg(feature = "external-access")]
    pub async fn external_access_live(&self) -> Option<crate::external_access::Credential> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let cfg = crate::config::load(&path).ok()?;
            if !cfg.external_access_enabled {
                return None;
            }
            Some(crate::external_access::Credential {
                setup: cfg.external_access_setup?,
                verifier: cfg.external_access_verifier?,
            })
        })
        .await
        .ok()
        .flatten()
    }

    /// FR-52 P4 — what an external SESSION is admitted under, read from the
    /// FILE when its `Request` arrives: live for the reason
    /// [`Self::external_access_live`] is, and one read so the session is
    /// judged on one consistent config.
    ///
    /// `None` exactly where `external_access_live` would say `None` — gate 3
    /// shut, no complete password record, or an unreadable file. The consent
    /// mode and the ceiling come back RAW: parsing them is the caller's, so
    /// that a value it cannot read is a refusal it can name.
    #[cfg(feature = "external-access")]
    pub async fn external_session_live(&self) -> Option<ExternalSessionConfig> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let cfg = crate::config::load(&path).ok()?;
            let password_set =
                cfg.external_access_setup.is_some() && cfg.external_access_verifier.is_some();
            (cfg.external_access_enabled && password_set).then_some(ExternalSessionConfig {
                consent_mode: cfg.external_consent_mode,
                max_permissions: cfg.external_max_permissions,
            })
        })
        .await
        .ok()
        .flatten()
    }

    /// Re-seed the live flags from a config the LOCAL owner just wrote.
    ///
    /// Called by the LocalAPI's `ConfigSet` (the desktop companion, `meshharbor
    /// config set`) after a successful save, and it closes a genuine inversion:
    /// [`Self::apply`] made a SERVER push to `exec_enabled` take effect
    /// immediately, while an owner's own edit sat in the file until the daemon
    /// restarted. Gate 4 exists so the person holding the machine has the last
    /// word — it cannot be the slower of the two.
    ///
    /// ⚠️ This does NOT stop the next reconnect from re-applying a standing
    /// `desired_config`, and it should not: a device with
    /// `remote_config_enabled = true` has delegated the key, which is the
    /// documented bargain (`docs/remote-config.md` §2). The owner's real
    /// remedy is to turn the OPT-IN off — which is exactly why that one is
    /// live here too, and why turning it off takes effect before the next push
    /// rather than after a restart.
    ///
    /// The caller already holds the write lock, so this reads a config that
    /// cannot be mid-write.
    pub fn adopt_local(&self, cfg: &crate::config::AgentConfig) {
        self.exec_enabled.store(cfg.exec_enabled, Ordering::Relaxed);
        self.remote_config_enabled
            .store(cfg.remote_config_enabled, Ordering::Relaxed);
        // FR-100 P1c — the next offer is judged under the owner's new word.
        self.peer_auth_policy
            .store(policy_bits(cfg.peer_auth), Ordering::Relaxed);
    }

    /// Reconcile the on-disk config against `desired`, persist, and put the
    /// live keys into force.
    ///
    /// Idempotent by construction: a desired state that already matches writes
    /// NOTHING and returns an empty [`Applied`]. That matters more than it
    /// looks — delivery is reconcile-on-connect, so this runs on every single
    /// reconnect, and a version that wrote unconditionally would rewrite
    /// config.toml (and later, restart the daemon) every time a flaky link
    /// bounced.
    ///
    /// Reloads from DISK rather than mutating the startup snapshot: another
    /// writer (the CLI, the desktop companion) may have changed the file since
    /// this process started, and clobbering their edit is not ours to do.
    pub async fn apply(&self, desired: &DesiredConfig) -> Result<Applied, String> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let desired = desired.clone();
        let exec_flag = self.exec_enabled.clone();

        tokio::task::spawn_blocking(move || {
            let mut cfg =
                crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
            let mut applied = Applied::default();

            if let Some(want) = desired.exec_enabled
                && cfg.exec_enabled != want
            {
                cfg.exec_enabled = want;
                applied.live.push("exec_enabled");
            }
            if let Some(want) = desired.ssh_enabled
                && cfg.ssh_enabled != want
            {
                cfg.ssh_enabled = want;
                applied.needs_restart.push("ssh_enabled");
            }
            if let Some(want) = desired.ssh_authorized_keys.as_ref()
                && &cfg.ssh_authorized_keys != want
            {
                cfg.ssh_authorized_keys = want.clone();
                applied.needs_restart.push("ssh_authorized_keys");
            }
            if let Some(want) = desired.ssh_account_mode.as_ref()
                && cfg.ssh_account_mode.as_ref() != Some(want)
            {
                cfg.ssh_account_mode = Some(want.clone());
                applied.needs_restart.push("ssh_account_mode");
            }
            if let Some(want) = desired.ssh_port
                && cfg.ssh_port != Some(want)
            {
                cfg.ssh_port = Some(want);
                applied.needs_restart.push("ssh_port");
            }
            // FR-77 P3 — the cell denylist. A blank push clears the key back
            // to the built-in list; `none` denies nothing. Read once per
            // process by the probe child, hence `needs_restart`.
            if let Some(want) = desired.encoder_cells_deny.as_deref() {
                let next = Some(want.trim())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                if cfg.encoder_cells_deny != next {
                    cfg.encoder_cells_deny = next;
                    applied.needs_restart.push("encoder_cells_deny");
                }
            }
            // FR-119 P2b — the frame-rate denylist, the same shape: a blank
            // push clears it (deny nothing). It reaches the pump through the
            // config fallbacks, registered once per process, hence
            // `needs_restart`.
            if let Some(want) = desired.fps_deny.as_deref() {
                let next = Some(want.trim())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                if cfg.fps_deny != next {
                    cfg.fps_deny = next;
                    applied.needs_restart.push("fps_deny");
                }
            }

            if applied.is_noop() {
                return Ok(applied);
            }
            crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
            // AFTER the durable write, never before: a live flag that is on
            // while the file says off would survive a crash as a device
            // running exec that its own config denies.
            if applied.live.contains(&"exec_enabled") {
                exec_flag.store(cfg.exec_enabled, Ordering::Relaxed);
            }
            Ok(applied)
        })
        .await
        .unwrap_or_else(|e| Err(format!("config apply task join: {e}")))
    }

    /// FR-40 — persist a freshly minted overlay key for ONE enrollment and
    /// bump its epoch, under the daemon-wide write lock, through the same
    /// atomic `config::save` as everything else (fsync + `.prev` + 0600/ACL).
    ///
    /// `is_primary` selects the config's scalar identity; otherwise the
    /// `[[orgs]]` entry whose `tenant_id` matches. Returns the new epoch.
    /// The caller adopts the key in memory ONLY after this succeeds — a key
    /// that is not written down would be lost at the next restart, and the
    /// device would come back as the identity it just retired.
    pub async fn rotate_overlay_key(
        &self,
        is_primary: bool,
        tenant_id: &str,
        new_secret: String,
    ) -> Result<u32, String> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let tenant_id = tenant_id.to_string();

        tokio::task::spawn_blocking(move || {
            let mut cfg =
                crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
            let epoch = if is_primary {
                cfg.overlay_wg_secret_key = Some(new_secret);
                cfg.overlay_wg_key_epoch = cfg.overlay_wg_key_epoch.wrapping_add(1);
                cfg.overlay_wg_key_epoch
            } else {
                let org = cfg
                    .orgs
                    .iter_mut()
                    .find(|o| o.tenant_id == tenant_id)
                    .ok_or_else(|| format!("no [[orgs]] entry for tenant {tenant_id}"))?;
                org.overlay_wg_secret_key = Some(new_secret);
                org.overlay_wg_key_epoch = org.overlay_wg_key_epoch.wrapping_add(1);
                org.overlay_wg_key_epoch
            };
            crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
            Ok(epoch)
        })
        .await
        .unwrap_or_else(|e| Err(format!("key rotation task join: {e}")))
    }

    /// FR-103 — save a renewed agent token for ONE enrollment, under the
    /// daemon-wide write lock, through the same atomic `config::save` as
    /// [`Self::rotate_overlay_key`].
    ///
    /// The enrollment is found by its identity, `(server_url, tenant_id)`, in
    /// the scalar primary or an `[[orgs]]` entry, wherever it is NOW: an
    /// `org promote` since this process started moves it between the two.
    ///
    /// The write is a compare-and-swap on the token that was renewed. A file
    /// that already holds a DIFFERENT token for this device was re-enrolled
    /// while the renewal was in flight, and that newer token wins
    /// ([`TokenWrite::Superseded`]). A file naming ANOTHER device for this
    /// enrollment is refused with nothing written: the renewed token belongs
    /// to this one, and saving it there would pair one device's token with
    /// another's id.
    pub async fn persist_agent_token(
        &self,
        server_url: &str,
        tenant_id: &str,
        agent_id: &str,
        renewed_from: &str,
        new_token: String,
    ) -> Result<TokenWrite, String> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let (server_url, tenant_id) = (server_url.to_string(), tenant_id.to_string());
        let (agent_id, renewed_from) = (agent_id.to_string(), renewed_from.to_string());

        tokio::task::spawn_blocking(move || {
            let mut cfg =
                crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
            let (token, stored_id) = if cfg.is_primary_identity(&server_url, &tenant_id) {
                (&mut cfg.agent_token, &cfg.agent_id)
            } else {
                let org = cfg
                    .find_org_by_identity_mut(&server_url, &tenant_id)
                    .ok_or_else(|| format!("no enrollment for tenant {tenant_id} in the config"))?;
                (&mut org.agent_token, &org.agent_id)
            };
            if *stored_id != agent_id {
                return Err(format!(
                    "the config now holds another device ({stored_id}) for tenant {tenant_id}"
                ));
            }
            if *token != renewed_from {
                return Ok(TokenWrite::Superseded(token.clone()));
            }
            *token = new_token;
            crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
            Ok(TokenWrite::Saved)
        })
        .await
        .unwrap_or_else(|e| Err(format!("token save task join: {e}")))
    }

    /// FR-103 — the agent token the config file holds for this device's
    /// enrollment, found as [`Self::persist_agent_token`] finds it. `None`
    /// when the file cannot be read, has no such enrollment, or now names
    /// another device for it.
    ///
    /// Read under the write lock so it never sees a save half-applied.
    pub async fn stored_agent_token(
        &self,
        server_url: &str,
        tenant_id: &str,
        agent_id: &str,
    ) -> Option<String> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let (server_url, tenant_id) = (server_url.to_string(), tenant_id.to_string());
        let agent_id = agent_id.to_string();

        tokio::task::spawn_blocking(move || {
            let mut cfg = match crate::config::load(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %format!("{e:#}"), "token: config unreadable");
                    return None;
                }
            };
            let (token, stored_id) = if cfg.is_primary_identity(&server_url, &tenant_id) {
                (cfg.agent_token, cfg.agent_id)
            } else {
                let org = cfg.find_org_by_identity_mut(&server_url, &tenant_id)?;
                (std::mem::take(&mut org.agent_token), org.agent_id.clone())
            };
            (stored_id == agent_id).then_some(token)
        })
        .await
        .ok()
        .flatten()
    }
}

/// FR-103 — what [`RemoteConfigServices::persist_agent_token`] did.
#[derive(PartialEq, Eq)]
pub enum TokenWrite {
    /// The renewed token is on disk.
    Saved,
    /// The file already held this newer token for the device; nothing was
    /// written.
    Superseded(String),
}

/// Hand-written so that logging an outcome can never print a token.
impl std::fmt::Debug for TokenWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saved => f.write_str("Saved"),
            Self::Superseded(_) => f.write_str("Superseded(<redacted>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(exec: bool) -> RemoteConfigServices {
        svc_with(exec, true)
    }

    fn svc_with(exec: bool, opted_in: bool) -> RemoteConfigServices {
        RemoteConfigServices::new(
            PathBuf::from("unused-in-this-test.toml"),
            Arc::new(tokio::sync::Mutex::new(())),
            exec,
            opted_in,
        )
    }

    /// FR-119 P2b — a pushed frame-rate denylist is written and reported as
    /// needing a restart; the same push again changes nothing; a blank push
    /// clears it.
    #[tokio::test]
    async fn a_pushed_frame_rate_denylist_is_written_and_a_blank_clears_it() {
        let dir = std::env::temp_dir().join(format!("fr119-fps-deny-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        crate::config::save(&path, &crate::config::test_fixture()).unwrap();
        let svc = RemoteConfigServices::new(
            path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            false,
            true,
        );
        let push = |v: &str| DesiredConfig {
            fps_deny: Some(v.to_string()),
            ..Default::default()
        };
        let applied = svc.apply(&push(" hevc_qsv:120 ")).await.unwrap();
        assert_eq!(applied.needs_restart, vec!["fps_deny"]);
        let back = crate::config::load(&path).unwrap();
        assert_eq!(back.fps_deny.as_deref(), Some("hevc_qsv:120"));
        assert!(svc.apply(&push("hevc_qsv:120")).await.unwrap().is_noop());
        svc.apply(&push("")).await.unwrap();
        assert_eq!(crate::config::load(&path).unwrap().fps_deny, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-40 — a rotation writes ONE enrollment's key + epoch through the
    /// atomic save and leaves the other identity on disk untouched; an
    /// unknown org is refused with nothing written.
    #[tokio::test]
    async fn rotate_overlay_key_moves_one_identity_and_bumps_its_epoch() {
        let dir = std::env::temp_dir().join(format!("fr40-rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut cfg = crate::config::test_fixture();
        cfg.overlay_wg_secret_key = Some("PRIMARY-OLD".into());
        cfg.overlay_wg_key_epoch = 4;
        cfg.orgs.push(crate::config::OrgEntry {
            label: "beta".into(),
            server_url: cfg.server_url.clone(),
            ws_url: None,
            agent_token: "tok-beta".into(),
            agent_id: "aid-beta".into(),
            tenant_id: "tid-beta".into(),
            enabled: true,
            overlay_mode: crate::config::OrgOverlayMode::Off,
            overlay_wg_secret_key: Some("BETA-OLD".into()),
            overlay_wg_key_epoch: 0,
            overlay_advertised_routes: Vec::new(),
            overlay_exit_node_enabled: false,
            advertise_routes: Vec::new(),
            netstack_socks_port: None,
        });
        crate::config::save(&path, &cfg).unwrap();
        let svc = RemoteConfigServices::new(
            path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            false,
            true,
        );

        // A secondary org: only its entry moves.
        let epoch = svc
            .rotate_overlay_key(false, "tid-beta", "BETA-NEW".into())
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        let back = crate::config::load(&path).unwrap();
        assert_eq!(
            back.orgs[0].overlay_wg_secret_key.as_deref(),
            Some("BETA-NEW")
        );
        assert_eq!(back.orgs[0].overlay_wg_key_epoch, 1);
        assert_eq!(back.overlay_wg_secret_key.as_deref(), Some("PRIMARY-OLD"));
        assert_eq!(back.overlay_wg_key_epoch, 4);

        // The primary: the scalar moves, the org stays.
        let epoch = svc
            .rotate_overlay_key(true, "tid-primary", "PRIMARY-NEW".into())
            .await
            .unwrap();
        assert_eq!(epoch, 5);
        let back = crate::config::load(&path).unwrap();
        assert_eq!(back.overlay_wg_secret_key.as_deref(), Some("PRIMARY-NEW"));
        assert_eq!(back.overlay_wg_key_epoch, 5);
        assert_eq!(
            back.orgs[0].overlay_wg_secret_key.as_deref(),
            Some("BETA-NEW")
        );

        // An org this device is not enrolled in: refused, nothing written.
        assert!(
            svc.rotate_overlay_key(false, "tid-nope", "X".into())
                .await
                .is_err()
        );
        let back = crate::config::load(&path).unwrap();
        assert_eq!(back.overlay_wg_key_epoch, 5);
        assert_eq!(back.orgs[0].overlay_wg_key_epoch, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_live_flag_is_what_the_gate_reads() {
        assert!(!svc(false).exec_enabled());
        assert!(svc(true).exec_enabled());
    }

    #[test]
    fn the_opt_in_is_seeded_from_the_config_this_daemon_loaded() {
        assert!(!svc_with(false, false).remote_config_enabled());
        assert!(svc_with(false, true).remote_config_enabled());
    }

    /// The inversion this closes.
    ///
    /// `apply` (a SERVER push) puts `exec_enabled` into force immediately. If
    /// the owner's own edit only reached the file, their "off" would wait for a
    /// service restart while the control plane's "on" did not — and gate 4
    /// exists precisely so the person holding the machine has the last word.
    /// It cannot be the slower of the two.
    #[test]
    fn an_owners_local_edit_is_at_least_as_live_as_a_pushed_one() {
        let svc = svc_with(true, true);
        assert!(svc.exec_enabled());

        let mut cfg = crate::config::test_fixture();
        cfg.exec_enabled = false;
        cfg.remote_config_enabled = false;
        svc.adopt_local(&cfg);

        assert!(!svc.exec_enabled(), "the owner turned exec off; it is off");
        assert!(
            !svc.remote_config_enabled(),
            "revoking the delegation must not wait for a restart either — \
             otherwise the server keeps pushing over a decision already made"
        );
    }

    #[test]
    fn an_empty_applied_is_a_noop() {
        assert!(Applied::default().is_noop());
        assert!(
            !Applied {
                live: vec!["exec_enabled"],
                ..Default::default()
            }
            .is_noop()
        );
        assert!(
            !Applied {
                needs_restart: vec!["ssh_enabled"],
                ..Default::default()
            }
            .is_noop()
        );
    }

    /// The split is the honest part of this module: an operator has to be able
    /// to tell "in force now" from "written down, waiting for a restart".
    /// Collapsing them would let the dashboard claim SSH is on when the daemon
    /// has not re-spliced the packet path.
    #[test]
    fn live_and_restart_required_keys_stay_separate() {
        let applied = Applied {
            live: vec!["exec_enabled"],
            needs_restart: vec!["ssh_enabled"],
        };
        assert!(!applied.is_noop());
        assert!(!applied.live.contains(&"ssh_enabled"));
        assert!(!applied.needs_restart.contains(&"exec_enabled"));
    }
}
