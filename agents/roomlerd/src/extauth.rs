// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-52 P3c — the device's answer to `rc:extauth.ke1` and `rc:extauth.ke3`.
//!
//! Compiled into EVERY build, credential stack or not, because every build
//! advertises `RpcCap::ExternalAccess` (P2a) and so can be sent a KE1. A build
//! that cannot hold a password must still ANSWER — `unavailable`, at once — or
//! the server waits out its whole bound and the outsider is told nothing for
//! seconds. Before this module, `handle_server_msg`'s catch-all dropped the
//! frame at `debug!`.
//!
//! Every refusal that concerns the device's configuration is the same
//! `unavailable`: not the primary org, gate 3 off, no password, an unreadable
//! record, a build without the stack. Telling them apart would let whoever
//! holds the connect code — which is dictated aloud — read the device's setup.

use bson::oid::ObjectId;
use roomler_ai_remote_control::models::ExtauthRefusal;
use roomler_ai_remote_control::permissions::Permissions;
use roomler_ai_remote_control::signaling::{ClientMsg, ExternalGrant};

use crate::remote_config::RemoteConfigServices;

fn refused(attempt_id: String, why: ExtauthRefusal, retry_after_secs: Option<u32>) -> ClientMsg {
    ClientMsg::ExtauthOutcome {
        attempt_id,
        refused: Some(why),
        retry_after_secs,
    }
}

/// `rc:extauth.ke1` → the frame to send back: `rc:extauth.ke2`, or an outcome
/// refusing it.
pub async fn on_ke1(
    is_primary: bool,
    remote_cfg: &RemoteConfigServices,
    attempt_id: String,
    principal: String,
    ke1: &str,
) -> ClientMsg {
    #[cfg(feature = "external-access")]
    {
        imp::on_ke1(
            remote_cfg.external_logins(),
            is_primary,
            remote_cfg,
            attempt_id,
            principal,
            ke1,
            std::time::Instant::now(),
        )
        .await
    }
    #[cfg(not(feature = "external-access"))]
    {
        let _ = (is_primary, remote_cfg, principal, ke1);
        tracing::info!(%attempt_id, "extauth: KE1 refused — this build cannot hold a password");
        refused(attempt_id, ExtauthRefusal::Unavailable, None)
    }
}

/// `rc:extauth.ke3` → the outcome to send back.
pub async fn on_ke3(
    is_primary: bool,
    remote_cfg: &RemoteConfigServices,
    attempt_id: String,
    principal: String,
    ke3: &str,
) -> ClientMsg {
    #[cfg(feature = "external-access")]
    {
        imp::on_ke3(
            remote_cfg.external_logins(),
            is_primary,
            remote_cfg,
            attempt_id,
            principal,
            ke3,
            std::time::Instant::now(),
        )
        .await
    }
    #[cfg(not(feature = "external-access"))]
    {
        let _ = (is_primary, remote_cfg, principal, ke3);
        refused(attempt_id, ExtauthRefusal::Unavailable, None)
    }
}

// ─── P4 — the session a verified login opens ─────────────────────────────────
//
// The server admits an external session on gates 1 and 2 and names the login it
// rests on (`Request.external`); everything else is decided HERE, and none of it
// on the server's word. Six refusal points, in the order a session meets them:
//
// 1. `admit_session` — the primary org's socket; gate 3 and a password, read
//    live; this device's own consent mode and ceiling; and the verified login,
//    consumed (one login, one session).
// 2. `grant_consent` — gate 5 is this device's decision; recorded before the
//    grant leaves, so the offer it unlocks cannot overtake it.
// 3. `check_offer` — no offer before that consent, exactly one offer, and a MAC
//    over its DTLS certificate under the login's key: the controller that sends
//    it is the one that proved the password, and the certificate is the one
//    DTLS will be pinned to. Taken BEFORE an offer can be delegated to a GUI
//    worker (FR-43), because the binding lives only in this process.
// 4. `seal_answer` — the answer carries a MAC over the DEVICE's certificate, so
//    the browser can check it is talking to the device and not to whoever
//    relays the signalling. Sealing ends the binding; the key goes with it.
//
// ⚠️ "Not bound" means ORDINARY session and is the only answer on which an offer
// proceeds without a MAC — so a session that WAS external is remembered after
// its binding ends (`external_logins::Inner::ended`), never forgotten into one.

/// FR-52 P4 — who is asking, wherever the person at the machine is shown it:
/// the consent prompt and the "being viewed by" banner. Never an organization's
/// name — the one thing this label is for is saying that it is not theirs.
pub const OUTSIDE_THE_ORG: &str = "Outside your organization";

/// FR-52 P4 — the consent prompt's title for an external request. In the title
/// because the controller's NAME is whatever they chose to call themselves.
pub const EXTERNAL_PROMPT_TITLE: &str = "Remote control request from OUTSIDE your organization";

/// … and the line under it: what the request rests on, and what to do.
pub const EXTERNAL_PROMPT_DETAIL: &str = "This person is not a member of your organization. \
     They proved this device's external-access password. Approve only if you are expecting them.";

/// How THIS device obtains consent for an external session
/// (`external_consent_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalConsent {
    /// Ask whoever is at the machine. The default.
    Prompt,
    /// Unattended — chosen on this device, by whoever holds it.
    Auto,
}

/// An external session this device admitted, on its own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The grant after this device's own ceiling (`external_max_permissions`).
    pub permissions: Permissions,
    pub consent: ExternalConsent,
}

/// `rc:request` with `external` set → admitted on this device's terms, or the
/// reason it is not. The reason is for this device's log: the controller is
/// told only that the device ended the session.
pub async fn admit_session(
    is_primary: bool,
    remote_cfg: &RemoteConfigServices,
    grant: &ExternalGrant,
    principal: ObjectId,
    session_id: ObjectId,
    requested: Permissions,
) -> Result<Admitted, &'static str> {
    #[cfg(feature = "external-access")]
    {
        imp::admit_session(
            remote_cfg.external_logins(),
            is_primary,
            remote_cfg,
            &grant.attempt_id,
            &principal.to_hex(),
            &session_id.to_hex(),
            requested,
            std::time::Instant::now(),
        )
        .await
    }
    #[cfg(not(feature = "external-access"))]
    {
        let _ = (
            is_primary, remote_cfg, grant, principal, session_id, requested,
        );
        Err("this build cannot hold an external-access password")
    }
}

/// THIS device granted consent for external session `session_id`. Call BEFORE
/// the grant is sent. `false` = its binding is gone (it ended meanwhile): send a
/// refusal instead of the grant.
pub fn grant_consent(remote_cfg: &RemoteConfigServices, session_id: ObjectId) -> bool {
    #[cfg(feature = "external-access")]
    {
        remote_cfg
            .external_logins()
            .grant_consent(&session_id.to_hex())
    }
    #[cfg(not(feature = "external-access"))]
    {
        let _ = (remote_cfg, session_id);
        false
    }
}

/// The session is over. A no-op for a session that was never external, so every
/// path that ends a session may call it without asking which kind it was.
pub fn end_session(remote_cfg: &RemoteConfigServices, session_id: ObjectId) {
    #[cfg(feature = "external-access")]
    remote_cfg
        .external_logins()
        .end_session(&session_id.to_hex());
    #[cfg(not(feature = "external-access"))]
    let _ = (remote_cfg, session_id);
}

/// May this `rc:sdp.offer` build a peer? `Ok` for an ordinary session and for
/// an external one whose offer verifies; `Err(why)` = end the session.
pub fn check_offer(
    remote_cfg: &RemoteConfigServices,
    session_id: ObjectId,
    sdp: &str,
    mac: Option<&str>,
) -> Result<(), &'static str> {
    #[cfg(feature = "external-access")]
    {
        imp::check_offer(
            remote_cfg.external_logins(),
            &session_id.to_hex(),
            sdp,
            mac,
            std::time::Instant::now(),
        )
    }
    #[cfg(not(feature = "external-access"))]
    {
        // No binding can exist in this build: every session is ordinary.
        let _ = (remote_cfg, session_id, sdp, mac);
        Ok(())
    }
}

/// What to do with an outgoing `rc:sdp.answer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seal {
    /// An ordinary session: send it as it is.
    Ordinary,
    /// An external session: send it with this `extauth_mac`.
    Sealed(String),
    /// An external session whose answer must NOT go out; end the session.
    Refused(&'static str),
}

/// Seal an answer for `session_id`, if it is an external session's.
pub fn seal_answer(remote_cfg: &RemoteConfigServices, session_id: ObjectId, sdp: &str) -> Seal {
    #[cfg(feature = "external-access")]
    {
        imp::seal_answer(remote_cfg.external_logins(), &session_id.to_hex(), sdp)
    }
    #[cfg(not(feature = "external-access"))]
    {
        let _ = (remote_cfg, session_id, sdp);
        Seal::Ordinary
    }
}

/// Seal `msg` in place if it is an external session's answer — the choke point
/// for answers that did not come from this process's own offer handler (a GUI
/// worker's, relayed up by `delegate::DelegateHost`). `false` = it must not be
/// sent; the caller ends the session instead.
pub fn seal_outbound(remote_cfg: &RemoteConfigServices, msg: &mut ClientMsg) -> bool {
    // `peer_auth` is FR-100's, signed at the same choke point by
    // `peer_auth::sign_outbound`, which runs after this.
    let ClientMsg::SdpAnswer {
        session_id,
        sdp,
        extauth_mac,
        ..
    } = msg
    else {
        return true;
    };
    match seal_answer(remote_cfg, *session_id, sdp) {
        // Whatever a worker put there is not ours to vouch for.
        Seal::Ordinary => {
            *extauth_mac = None;
            true
        }
        Seal::Sealed(mac) => {
            *extauth_mac = Some(mac);
            true
        }
        Seal::Refused(why) => {
            tracing::warn!(%session_id, why, "external session: answer withheld");
            false
        }
    }
}

#[cfg(feature = "external-access")]
mod imp {
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use roomler_ai_remote_control::models::ExtauthRefusal;
    use roomler_ai_remote_control::permissions::Permissions;
    use roomler_ai_remote_control::signaling::ClientMsg;
    use tracing::info;

    use super::{Admitted, ExternalConsent, Seal, refused};
    use crate::external_logins::{BindingError, ExternalLogins, Refusal};
    use crate::remote_config::RemoteConfigServices;

    /// What an external session never holds, whatever was asked or allowed.
    /// RECORD: §10 keeps recording an outsider's session out of scope.
    /// PRIVACY (decision 13): a curtain would hide what a stranger does from
    /// the person at the device.
    const NEVER_FOR_AN_OUTSIDER: Permissions = Permissions::RECORD.union(Permissions::PRIVACY);

    /// `@serenity-kit/opaque`'s encoding, strictly: a padded or standard-alphabet
    /// blob is a client this protocol does not speak, and is refused as
    /// malformed before anything is answered or debited.
    fn b64url() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    }

    /// Whole seconds, rounded UP: a client told "retry in 29 s" when 29.4 s
    /// remain would retry into a second refusal.
    fn retry_secs(d: Duration) -> u32 {
        let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
        u32::try_from(secs).unwrap_or(u32::MAX)
    }

    fn map(r: Refusal) -> (ExtauthRefusal, Option<u32>) {
        match r {
            Refusal::Throttled { retry_after } => {
                (ExtauthRefusal::Throttled, Some(retry_secs(retry_after)))
            }
            Refusal::Busy => (ExtauthRefusal::Busy, None),
            // A malformed attempt id or principal came from the SERVER, not the
            // outsider, but it is the same answer to them: the request could
            // not be read.
            Refusal::BadIdentifier | Refusal::Malformed => (ExtauthRefusal::Malformed, None),
            Refusal::Unavailable => (ExtauthRefusal::Unavailable, None),
            Refusal::UnknownAttempt => (ExtauthRefusal::UnknownAttempt, None),
            Refusal::PrincipalMismatch | Refusal::Rejected => (ExtauthRefusal::Rejected, None),
        }
    }

    pub(super) async fn on_ke1(
        logins: &ExternalLogins,
        is_primary: bool,
        remote_cfg: &RemoteConfigServices,
        attempt_id: String,
        principal: String,
        ke1: &str,
        now: Instant,
    ) -> ClientMsg {
        if !is_primary {
            info!(%attempt_id, "extauth: KE1 refused — not the primary org's socket");
            return refused(attempt_id, ExtauthRefusal::Unavailable, None);
        }
        // Gate 3 and the record, from the FILE: a revocation takes effect for
        // the next knock, not the next restart.
        let Some(cred) = remote_cfg.external_access_live().await else {
            info!(%attempt_id, "extauth: KE1 refused — external access is not enabled here");
            return refused(attempt_id, ExtauthRefusal::Unavailable, None);
        };
        let Ok(ke1) = b64url().decode(ke1) else {
            return refused(attempt_id, ExtauthRefusal::Malformed, None);
        };
        match logins.begin(&attempt_id, &principal, &cred, &ke1, now) {
            Ok(ke2) => {
                info!(%attempt_id, %principal, "extauth: KE1 answered (one guess spent)");
                ClientMsg::ExtauthKe2 {
                    attempt_id,
                    ke2: b64url().encode(ke2),
                }
            }
            Err(r) => {
                info!(%attempt_id, %principal, refusal = ?r, "extauth: KE1 refused");
                let (why, retry) = map(r);
                refused(attempt_id, why, retry)
            }
        }
    }

    pub(super) async fn on_ke3(
        logins: &ExternalLogins,
        is_primary: bool,
        remote_cfg: &RemoteConfigServices,
        attempt_id: String,
        principal: String,
        ke3: &str,
        now: Instant,
    ) -> ClientMsg {
        if !is_primary {
            return refused(attempt_id, ExtauthRefusal::Unavailable, None);
        }
        // Re-checked at KE3: an owner who switches external access off while a
        // login is in flight must not see it complete a moment later.
        if remote_cfg.external_access_live().await.is_none() {
            info!(%attempt_id, "extauth: KE3 refused — external access was switched off mid-login");
            return refused(attempt_id, ExtauthRefusal::Unavailable, None);
        }
        let Ok(ke3) = b64url().decode(ke3) else {
            return refused(attempt_id, ExtauthRefusal::Malformed, None);
        };
        match logins.finish(&attempt_id, &principal, &ke3, now) {
            Ok(()) => {
                info!(%attempt_id, %principal, "extauth: login VERIFIED");
                ClientMsg::ExtauthOutcome {
                    attempt_id,
                    refused: None,
                    retry_after_secs: None,
                }
            }
            Err(r) => {
                info!(%attempt_id, %principal, refusal = ?r, "extauth: KE3 refused");
                let (why, retry) = map(r);
                refused(attempt_id, why, retry)
            }
        }
    }

    /// See [`super::admit_session`]. The login is consumed LAST, so a refusal
    /// on this device's own terms leaves it unspent.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn admit_session(
        logins: &ExternalLogins,
        is_primary: bool,
        remote_cfg: &RemoteConfigServices,
        attempt_id: &str,
        principal: &str,
        session_id: &str,
        requested: Permissions,
        now: Instant,
    ) -> Result<Admitted, &'static str> {
        // PRIMARY ORG ONLY, as for the login: the screen, the keyboard and the
        // password are the host's, and the host's belong to the enrollment
        // that owns it.
        if !is_primary {
            return Err("not the primary org's socket");
        }
        let Some(terms) = remote_cfg.external_session_live().await else {
            return Err("external access is off here (gate 3), or no password is set");
        };
        // An unreadable mode is a refusal, never a fallback: `auto` is the one
        // value that skips a human, and a typo must not be what decides that.
        let consent = match terms.consent_mode.as_deref().map(str::trim) {
            None | Some("") | Some("prompt") => ExternalConsent::Prompt,
            Some("auto") => ExternalConsent::Auto,
            Some(_) => return Err("external_consent_mode is neither prompt nor auto"),
        };
        let permissions = match terms
            .max_permissions
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            // Unset defers to the org's ceiling, which the server applied.
            None => requested,
            Some(ceiling) => match Permissions::from_wire_names(ceiling) {
                Some(ceiling) => requested & ceiling,
                None => return Err("external_max_permissions names an unknown permission"),
            },
        };
        // FR-52 decision 13 — an outsider's session is never recorded and
        // never curtained. The hub strips both; this device strips them again
        // so the server is not the only thing keeping them out. No ceiling an
        // owner sets can let either back in. Before the empty check, so a
        // request for nothing else is still refused.
        let never = permissions & NEVER_FOR_AN_OUTSIDER;
        if !never.is_empty() {
            info!(%attempt_id, ?never, "extauth: stripped what an outsider never holds");
        }
        let permissions = permissions - NEVER_FOR_AN_OUTSIDER;
        if permissions.is_empty() {
            return Err("nothing the session asked for is within this device's ceiling");
        }
        if !logins.bind_session(attempt_id, principal, session_id, now) {
            return Err(
                "no verified login for this session: expired, used, or another principal's",
            );
        }
        Ok(Admitted {
            permissions,
            consent,
        })
    }

    pub(super) fn check_offer(
        logins: &ExternalLogins,
        session_id: &str,
        sdp: &str,
        mac: Option<&str>,
        now: Instant,
    ) -> Result<(), &'static str> {
        match logins.verify_offer(session_id, sdp, mac, now) {
            Ok(()) | Err(BindingError::NotBound) => Ok(()),
            Err(e) => Err(describe(e)),
        }
    }

    pub(super) fn seal_answer(logins: &ExternalLogins, session_id: &str, sdp: &str) -> Seal {
        match logins.seal_answer(session_id, sdp) {
            Ok(mac) => Seal::Sealed(mac),
            Err(BindingError::NotBound) => Seal::Ordinary,
            Err(e) => Seal::Refused(describe(e)),
        }
    }

    fn describe(e: BindingError) -> &'static str {
        match e {
            BindingError::NotBound => "not an external session",
            BindingError::Ended => "the external session is already over",
            BindingError::NotConsented => "an offer before this device granted consent",
            BindingError::AlreadyOffered => "a second offer",
            BindingError::NotOffered => "an answer to no admitted offer",
            BindingError::NoFingerprint => "the SDP names no DTLS certificate",
            BindingError::AmbiguousFingerprint => "the SDP names more than one DTLS certificate",
            BindingError::MissingMac => "an external offer without its MAC",
            BindingError::BadMac => {
                "the offer's MAC does not verify: it was not made by the login that admitted the session"
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::external_access::{Suite, set_password};
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
        use rand_opaque::rngs::OsRng;

        const WHO: &str = "665f1c2a9b3e4d5f6a7b8c9d";

        fn pw(tag: &str) -> String {
            format!("fr52-not-a-credential-{tag}")
        }

        /// A daemon's config on disk, with gate 3 and gate 4 as asked.
        fn device(
            enabled: bool,
            password: Option<&str>,
        ) -> (tempfile::TempDir, RemoteConfigServices) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let mut cfg = crate::config::test_fixture();
            cfg.external_access_enabled = enabled;
            if let Some(p) = password {
                let (cred, _) = set_password(None, p).unwrap();
                cfg.external_access_setup = Some(cred.setup);
                cfg.external_access_verifier = Some(cred.verifier);
            }
            crate::config::save(&path, &cfg).unwrap();
            let svc = RemoteConfigServices::new(
                path,
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
                false,
                false,
            );
            (dir, svc)
        }

        fn client_ke1(password: &str) -> (ClientLogin<Suite>, String) {
            let s = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
            let ke1 = b64url().encode(s.message.serialize());
            (s.state, ke1)
        }

        fn refusal_of(m: &ClientMsg) -> Option<(ExtauthRefusal, Option<u32>)> {
            match m {
                ClientMsg::ExtauthOutcome {
                    refused: Some(r),
                    retry_after_secs,
                    ..
                } => Some((*r, *retry_after_secs)),
                _ => None,
            }
        }

        /// The whole device-side exchange: KE1 → KE2 → KE3 → verified, with
        /// the blobs in the browser library's encoding throughout.
        #[tokio::test]
        async fn a_correct_login_is_answered_and_verified() {
            let logins = ExternalLogins::new();
            let (_dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();

            let (state, ke1) = client_ke1(&pw("right"));
            let reply = on_ke1(&logins, true, &svc, "a1".into(), WHO.into(), &ke1, now).await;
            let ClientMsg::ExtauthKe2 { attempt_id, ke2 } = reply else {
                panic!("expected a KE2, got {reply:?}");
            };
            assert_eq!(attempt_id, "a1");

            let ke2 = b64url().decode(ke2).expect("KE2 is base64url, no padding");
            let done = state
                .finish(
                    &mut OsRng,
                    pw("right").as_bytes(),
                    CredentialResponse::<Suite>::deserialize(&ke2).unwrap(),
                    ClientLoginFinishParameters::default(),
                )
                .expect("the right password opens KE2");
            let ke3 = b64url().encode(done.message.serialize());

            let outcome = on_ke3(&logins, true, &svc, "a1".into(), WHO.into(), &ke3, now).await;
            assert!(
                matches!(outcome, ClientMsg::ExtauthOutcome { refused: None, .. }),
                "expected VERIFIED, got {outcome:?}"
            );
            assert!(logins.take_verified("a1", WHO, now).is_some());
        }

        /// Every configuration refusal is the same `unavailable`, and none of
        /// them spends a guess — nothing was answered.
        #[tokio::test]
        async fn every_configuration_refusal_is_the_same_unavailable() {
            let now = Instant::now();
            let (_, ke1) = client_ke1(&pw("right"));
            for (label, primary, enabled, password) in [
                ("secondary org", false, true, Some(pw("right"))),
                ("gate 3 off", true, false, Some(pw("right"))),
                ("no password", true, true, None),
            ] {
                let logins = ExternalLogins::new();
                let (_dir, svc) = device(enabled, password.as_deref());
                let reply =
                    on_ke1(&logins, primary, &svc, "a1".into(), WHO.into(), &ke1, now).await;
                assert_eq!(
                    refusal_of(&reply),
                    Some((ExtauthRefusal::Unavailable, None)),
                    "{label}"
                );
                assert_eq!(
                    logins.answered_guesses(now),
                    0,
                    "{label}: nothing was answered"
                );
            }
        }

        /// Revocation is live: an owner who switches external access off
        /// between KE1 and KE3 does not see the login complete.
        #[tokio::test]
        async fn switching_gate_3_off_mid_login_refuses_the_ke3() {
            let logins = ExternalLogins::new();
            let (dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();

            let (state, ke1) = client_ke1(&pw("right"));
            let ClientMsg::ExtauthKe2 { ke2, .. } =
                on_ke1(&logins, true, &svc, "a1".into(), WHO.into(), &ke1, now).await
            else {
                panic!("expected a KE2");
            };

            // The owner runs `meshharbor config set external_access_enabled false`.
            let path = dir.path().join("config.toml");
            let mut cfg = crate::config::load(&path).unwrap();
            cfg.external_access_enabled = false;
            crate::config::save(&path, &cfg).unwrap();

            let ke2 = b64url().decode(ke2).unwrap();
            let done = state
                .finish(
                    &mut OsRng,
                    pw("right").as_bytes(),
                    CredentialResponse::<Suite>::deserialize(&ke2).unwrap(),
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
            let ke3 = b64url().encode(done.message.serialize());
            let outcome = on_ke3(&logins, true, &svc, "a1".into(), WHO.into(), &ke3, now).await;
            assert_eq!(
                refusal_of(&outcome),
                Some((ExtauthRefusal::Unavailable, None))
            );
            assert!(logins.take_verified("a1", WHO, now).is_none());
        }

        /// The throttle's wait reaches the outsider, rounded UP.
        #[tokio::test]
        async fn a_throttled_device_says_when_to_retry() {
            let logins = ExternalLogins::new();
            let (_dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();
            for n in 0..crate::external_logins::FREE_GUESSES {
                let (_, ke1) = client_ke1(&pw("wrong"));
                let r = on_ke1(&logins, true, &svc, format!("a{n}"), WHO.into(), &ke1, now).await;
                assert!(matches!(r, ClientMsg::ExtauthKe2 { .. }));
            }
            let (_, ke1) = client_ke1(&pw("wrong"));
            let r = on_ke1(&logins, true, &svc, "a99".into(), WHO.into(), &ke1, now).await;
            assert_eq!(refusal_of(&r), Some((ExtauthRefusal::Throttled, Some(30))));
            assert_eq!(retry_secs(Duration::from_millis(29_400)), 30, "rounded up");
        }

        /// Not the browser library's encoding → malformed, and not a guess.
        #[tokio::test]
        async fn a_ke1_in_the_wrong_encoding_is_malformed_and_free() {
            let logins = ExternalLogins::new();
            let (_dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();
            let (_, ke1) = client_ke1(&pw("right"));
            let padded = format!("{ke1}==");
            let r = on_ke1(&logins, true, &svc, "a1".into(), WHO.into(), &padded, now).await;
            assert_eq!(refusal_of(&r), Some((ExtauthRefusal::Malformed, None)));
            assert_eq!(logins.answered_guesses(now), 0);
        }

        // ─── P4 — admitting the session ─────────────────────────────────

        const SESSION: &str = "66f0c0ffee0000000000000a";
        const SESSION_B: &str = "66f0c0ffee0000000000000b";

        /// A whole login through this device's own handlers, as a browser
        /// would run it.
        async fn verified_login(
            logins: &ExternalLogins,
            svc: &RemoteConfigServices,
            attempt: &str,
            now: Instant,
        ) {
            let (state, ke1) = client_ke1(&pw("right"));
            let ClientMsg::ExtauthKe2 { ke2, .. } =
                on_ke1(logins, true, svc, attempt.into(), WHO.into(), &ke1, now).await
            else {
                panic!("expected a KE2");
            };
            let done = state
                .finish(
                    &mut OsRng,
                    pw("right").as_bytes(),
                    CredentialResponse::<Suite>::deserialize(&b64url().decode(ke2).unwrap())
                        .unwrap(),
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
            let ke3 = b64url().encode(done.message.serialize());
            let outcome = on_ke3(logins, true, svc, attempt.into(), WHO.into(), &ke3, now).await;
            assert!(matches!(
                outcome,
                ClientMsg::ExtauthOutcome { refused: None, .. }
            ));
        }

        /// The device's own terms, as its owner would set them.
        fn set_terms(
            dir: &tempfile::TempDir,
            enabled: bool,
            consent: Option<&str>,
            ceiling: Option<&str>,
        ) {
            let path = dir.path().join("config.toml");
            let mut cfg = crate::config::load(&path).unwrap();
            cfg.external_access_enabled = enabled;
            cfg.external_consent_mode = consent.map(str::to_string);
            cfg.external_max_permissions = ceiling.map(str::to_string);
            crate::config::save(&path, &cfg).unwrap();
        }

        #[tokio::test]
        async fn a_session_is_admitted_on_the_devices_own_terms() {
            let logins = ExternalLogins::new();
            let (dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();
            let asked = Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD;

            // Unset: prompt, and the grant as the server clamped it.
            verified_login(&logins, &svc, "a1", now).await;
            let admitted = admit_session(&logins, true, &svc, "a1", WHO, SESSION, asked, now)
                .await
                .unwrap();
            assert_eq!(
                admitted,
                Admitted {
                    permissions: asked,
                    consent: ExternalConsent::Prompt,
                }
            );

            // Set: the device's ceiling INTERSECTS (FILES is not granted
            // because it is allowed here — it was never asked for), and
            // `auto` is honoured.
            set_terms(&dir, true, Some("auto"), Some(" VIEW | FILES "));
            verified_login(&logins, &svc, "a2", now).await;
            let admitted = admit_session(&logins, true, &svc, "a2", WHO, SESSION_B, asked, now)
                .await
                .unwrap();
            assert_eq!(
                admitted,
                Admitted {
                    permissions: Permissions::VIEW,
                    consent: ExternalConsent::Auto,
                }
            );
        }

        /// FR-52 decision 13 — RECORD and PRIVACY never survive admission,
        /// whatever the server sent and whatever this device's ceiling names:
        /// the server is not the only gate keeping them out. A request for
        /// nothing else is refused, never admitted empty.
        #[tokio::test]
        async fn an_outsider_is_never_granted_record_or_privacy() {
            const SESSION_C: &str = "66f0c0ffee0000000000000c";
            let logins = ExternalLogins::new();
            let (dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();
            let rest = Permissions::VIEW | Permissions::INPUT;
            let asked = rest | Permissions::RECORD | Permissions::PRIVACY;

            // No ceiling: the path that otherwise takes the grant as sent.
            verified_login(&logins, &svc, "a1", now).await;
            let admitted = admit_session(&logins, true, &svc, "a1", WHO, SESSION, asked, now)
                .await
                .unwrap();
            assert_eq!(admitted.permissions, rest);

            // A ceiling that names both lets neither back in.
            set_terms(&dir, true, None, Some("VIEW | INPUT | RECORD | PRIVACY"));
            verified_login(&logins, &svc, "a2", now).await;
            let admitted = admit_session(&logins, true, &svc, "a2", WHO, SESSION_B, asked, now)
                .await
                .unwrap();
            assert_eq!(admitted.permissions, rest);

            verified_login(&logins, &svc, "a3", now).await;
            let only = Permissions::RECORD | Permissions::PRIVACY;
            assert!(
                admit_session(&logins, true, &svc, "a3", WHO, SESSION_C, only, now)
                    .await
                    .is_err()
            );
        }

        /// Every refusal on the device's own terms leaves the login UNSPENT and
        /// NO binding behind: the login is consumed only once the session is
        /// otherwise admissible. Consumed first, each refused session would
        /// hold a binding — a table slot — until it aged out.
        ///
        /// ⚠️ The survivor check admits a FRESH session id. Re-admitting the
        /// refused one on the same login is idempotent (the server re-pushes a
        /// pending Request after a socket flap), so it would pass even with the
        /// login consumed on the first refusal — which is how the first
        /// version of this test let exactly that mutation through.
        #[tokio::test]
        async fn a_refusal_on_the_devices_terms_leaves_the_login_unspent() {
            let logins = ExternalLogins::new();
            let (dir, svc) = device(true, Some(&pw("right")));
            let now = Instant::now();
            let asked = Permissions::INPUT;
            verified_login(&logins, &svc, "a1", now).await;
            for (label, primary, enabled, consent, ceiling) in [
                ("a secondary org's socket", false, true, None, None),
                (
                    "gate 3 switched off since the login",
                    true,
                    false,
                    None,
                    None,
                ),
                (
                    "an unreadable consent mode",
                    true,
                    true,
                    Some("sometimes"),
                    None,
                ),
                (
                    "an unreadable ceiling",
                    true,
                    true,
                    None,
                    Some("VIEW | TELEPORT"),
                ),
                (
                    "a ceiling that leaves nothing",
                    true,
                    true,
                    None,
                    Some("VIEW"),
                ),
            ] {
                set_terms(&dir, enabled, consent, ceiling);
                let r = admit_session(&logins, primary, &svc, "a1", WHO, SESSION, asked, now).await;
                assert!(r.is_err(), "{label}: admitted {r:?}");
            }
            set_terms(&dir, true, None, None);
            assert!(
                admit_session(&logins, true, &svc, "a1", WHO, SESSION_B, asked, now)
                    .await
                    .is_ok(),
                "the login survived every refusal, and no refused session kept it"
            );
            assert!(
                admit_session(
                    &logins,
                    true,
                    &svc,
                    "a1",
                    WHO,
                    "66f0c0ffee0000000000000c",
                    asked,
                    now
                )
                .await
                .is_err(),
                "and admits exactly one session"
            );
            assert!(
                admit_session(
                    &logins,
                    true,
                    &svc,
                    "a9",
                    WHO,
                    "66f0c0ffee0000000000000d",
                    asked,
                    now
                )
                .await
                .is_err(),
                "no login, no session"
            );
        }

        /// The GUI worker's answers reach the server through `seal_outbound`:
        /// an ordinary session's answer goes as it is — minus anything a
        /// worker claimed — and an ended external session's does not go.
        #[tokio::test]
        async fn the_outbound_choke_point_vouches_only_for_what_it_holds() {
            let (_dir, svc) = device(true, Some(&pw("right")));
            let sid = bson::oid::ObjectId::parse_str(SESSION).unwrap();
            let mut ordinary = ClientMsg::SdpAnswer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: Some("forged-by-a-worker".into()),
                peer_auth: None,
                peer_auth_verdict: None,
            };
            assert!(super::super::seal_outbound(&svc, &mut ordinary));
            assert!(
                matches!(
                    ordinary,
                    ClientMsg::SdpAnswer {
                        extauth_mac: None,
                        ..
                    }
                ),
                "not ours to vouch for"
            );
            let now = Instant::now();
            verified_login(svc.external_logins(), &svc, "a1", now).await;
            admit_session(
                svc.external_logins(),
                true,
                &svc,
                "a1",
                WHO,
                SESSION,
                Permissions::VIEW,
                now,
            )
            .await
            .unwrap();
            super::super::end_session(&svc, sid);
            let mut ended = ClientMsg::SdpAnswer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: None,
                peer_auth: None,
                peer_auth_verdict: None,
            };
            assert!(
                !super::super::seal_outbound(&svc, &mut ended),
                "an external session's answer is never sent unsealed"
            );
        }
    }
}
