// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-133 — a device changes hands: the device's half.
//!
//! A cross-organization primary rebind (`mh login --replace`, the tray's
//! "Move", `enroll-personal-system` with `replace`) used to leave the old
//! organization's row behind: offline forever, still in that org's list,
//! still the old admins' to remove. After the new enrollment is saved, the
//! device now asks the old organization's server to remove the old row
//! (`POST /api/agent/self/move`), with the OLD agent credential as the bearer
//! and the NEW agent credential as the proof. The server checks the new
//! credential against the device-login decision that minted it; nothing the
//! device says is trusted (`crates/modules/fleet/src/device_move.rs`).
//!
//! ```text
//!  enroll(new org) ──▶ save config (new primary) ──▶ POST old server /api/agent/self/move
//!                                                    │  2xx            → Removed
//!                                                    │  404/405        → Kept: server predates moves
//!                                                    │  403 / other    → Kept: the server's reason
//!                                                    ▼
//!                                   restart into the new organization (either way)
//! ```
//!
//! The order is deliberate: the config is saved BEFORE the old row is
//! removed, so the worst case of any failure is an old row an admin must
//! remove (today's behaviour), never a device whose only enrollment is gone.
//!
//! ⚠️ FR-127 / FR-129: a move changes who controls the machine, and no local
//! confirmation hook exists for it, so a PROTECTED or TWO-FACTOR device
//! refuses the move outright ([`move_refusal`]), before any token is spent.

use std::path::Path;

use anyhow::Result;

use crate::config::AgentConfig;

/// How long the removal may take. The caller is a person waiting on a
/// sign-in, and the move has already happened locally either way.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Single construction point for this module's HTTP client.
fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()?)
}

fn same_server(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        meshharbor_remote_control::server_url::secure(s.trim(), false)
            .url
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// What a sign-in by a person from ANOTHER organization offers: move this
/// device there. Built only for a permanent, non-temporary device whose
/// signed-in account is not a member of the device's primary organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveOffer {
    /// The device's server (the account's too: the session is kept per server).
    pub server: String,
    /// The device's organization by name, when its server says.
    pub org_name: Option<String>,
    /// Why this device will not move (protected or two-factor), when it will not.
    pub refusal: Option<String>,
}

impl MoveOffer {
    /// «name», or "another organization" from a server that does not say.
    pub fn org_label(&self) -> String {
        match self
            .org_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            Some(n) => format!("\u{ab}{n}\u{bb}"),
            None => "another organization".to_string(),
        }
    }

    /// The question, and what each answer does.
    pub fn question(&self) -> String {
        let org = self.org_label();
        format!(
            "This device belongs to {org}. Move it to your organization?\n\n\
             Move: it joins your organization (you approve it in the browser), and {org} \
             no longer lists it.\n\
             Keep: it stays in {org}. You are signed in to your account only."
        )
    }

    /// What the person is told once the move is done.
    pub fn done(&self, notice: Option<&str>) -> String {
        match notice {
            Some(n) => n.to_string(),
            None => format!(
                "This device is now in your organization. {} no longer lists it.",
                self.org_label()
            ),
        }
    }
}

/// Facts read from the local daemon and user session to decide whether to offer
/// a device move after tray sign-in.
#[derive(Debug, Clone)]
pub struct MoveOfferInput<'a> {
    pub personal_enrolled: Option<bool>,
    pub ephemeral: bool,
    pub primary_server: Option<&'a str>,
    pub has_primary_tenant: bool,
    pub session_server: &'a str,
    pub is_member: Option<bool>,
    pub org_name: Option<String>,
    pub protected: bool,
    pub two_factor: bool,
}

/// Decide whether a sign-in should offer to move the device: `None` asks
/// nothing (a member of the device's organization, unknown membership, a
/// temporary/ephemeral device, or a different server).
pub fn offer_for(input: MoveOfferInput<'_>) -> Option<MoveOffer> {
    if input.personal_enrolled != Some(true) || input.ephemeral {
        return None;
    }
    match input.primary_server {
        Some(primary) => {
            if !same_server(primary, input.session_server) {
                return None;
            }
        }
        None => {
            if !input.has_primary_tenant {
                return None;
            }
        }
    }
    // Unknown membership or an existing member: never ask (today's behaviour).
    if input.is_member != Some(false) {
        return None;
    }
    let refusal = if input.protected {
        Some(
            "This device is protected, so it cannot be moved to another organization from \
             here. Its owner can switch protection off on the device and sign in again. You \
             are signed in to your account only."
                .to_string(),
        )
    } else if input.two_factor {
        Some(
            "This device asks for a two-factor code, so it cannot be moved to another \
             organization from here. Switch two-factor off first (on its organization's admin \
             page, or `meshharbord two-factor reset` on the device), then sign in again. You \
             are signed in to your account only."
                .to_string(),
        )
    } else {
        None
    };
    Some(MoveOffer {
        server: input.session_server.to_string(),
        org_name: input.org_name,
        refusal,
    })
}

/// The organization an enrollment token names, from its UNVERIFIED payload.
/// Used only to tell a move from a refresh before the token is spent; the
/// server decides everything that matters.
pub fn token_tenant(enrollment_token: &str) -> Option<String> {
    use base64::Engine as _;
    if enrollment_token.len() > 16 * 1024 {
        return None;
    }
    let payload = enrollment_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(claims.get("tenant_id")?.as_str()?.to_string())
}

/// Whether enrolling `enrollment_token` at `server` with `replace` moves
/// this device's PRIMARY into another organization on the same server.
pub fn is_cross_org_replace(
    existing: &AgentConfig,
    server: &str,
    enrollment_token: &str,
    replace: bool,
) -> bool {
    replace
        && !existing.agent_token.is_empty()
        && same_server(&existing.server_url, server)
        && token_tenant(enrollment_token).is_some_and(|t| t != existing.tenant_id)
}

/// FR-127 / FR-129 — why this device refuses to be moved, if it does. A
/// protected device closes every way in its owner did not allow, and a
/// two-factor device asks for a code on every way in; a move hands the
/// machine to another organization's admins, so it is refused on both until
/// the owner switches the protection off on the device. A two-factor state
/// file that cannot even be checked counts as on (closed), as the daemon
/// counts it.
pub fn move_refusal(existing: &AgentConfig, config_path: &Path) -> Option<String> {
    if existing.protected {
        return Some(
            "This device is protected, so it cannot be moved to another organization. \
             Its owner can switch protection off on the device (`mh config set protected \
             false`, then restart the service) and sign in again."
                .to_string(),
        );
    }
    if crate::two_factor::state_path(config_path)
        .try_exists()
        .unwrap_or(true)
    {
        return Some(
            "This device asks for a two-factor code, so it cannot be moved to another \
             organization. Switch two-factor off first (on its organization's admin page, \
             or `meshharbord two-factor reset` on the device), then sign in again."
                .to_string(),
        );
    }
    None
}

/// The primary enrollment a cross-organization rebind leaves behind: what
/// [`remove_old_row`] needs to ask its server to remove it.
#[derive(Clone)]
pub struct LeavingPrimary {
    pub server_url: String,
    pub tenant_id: String,
    agent_token: String,
}

impl std::fmt::Debug for LeavingPrimary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeavingPrimary")
            .field("server_url", &self.server_url)
            .field("tenant_id", &self.tenant_id)
            .field("agent_token", &"<redacted>")
            .finish()
    }
}

/// The old primary that `fresh` replaced, when the move path applies: the
/// same server (the proof is checked there), another organization, a
/// permanent enrollment, and not a temporary (invitation) one, which leaves
/// with `mh leave` instead. Secondary `[[orgs]]` entries are never touched.
pub fn leaving_primary(
    existing: &AgentConfig,
    fresh: &AgentConfig,
    temporary: bool,
) -> Option<LeavingPrimary> {
    if temporary
        || existing.ephemeral
        || existing.agent_token.is_empty()
        || existing.tenant_id == fresh.tenant_id
        || !same_server(&existing.server_url, &fresh.server_url)
    {
        return None;
    }
    Some(LeavingPrimary {
        server_url: existing.server_url.clone(),
        tenant_id: existing.tenant_id.clone(),
        agent_token: existing.agent_token.clone(),
    })
}

/// What became of the old organization's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveOut {
    /// The old organization's server removed it.
    Removed,
    /// It is still there; the text says why.
    Kept(String),
}

impl MoveOut {
    /// What to tell the person, when there is something to do: the old
    /// organization's admin must remove the device by hand.
    pub fn notice(&self) -> Option<String> {
        match self {
            Self::Removed => None,
            Self::Kept(why) => Some(format!(
                "This device is now in your organization, but its old organization still \
                 lists it: an admin there must remove it ({why})."
            )),
        }
    }

    /// One line for a log or a terminal.
    pub fn line(&self) -> String {
        match self {
            Self::Removed => {
                "This device was removed from its old organization's list.".to_string()
            }
            Self::Kept(_) => self.notice().unwrap_or_default(),
        }
    }
}

/// Map the server's answer. Pure, so the compatibility rules are tested.
pub fn outcome_for(status: u16, body: &str) -> MoveOut {
    match status {
        200..=299 => MoveOut::Removed,
        // An older server has no such route (axum answers 404, or 405 when
        // the path matches another method).
        404 | 405 => MoveOut::Kept("its server does not support moving devices yet".into()),
        _ => {
            let reason = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| {
                    // The server's error body is `{error: <kind>, message}`.
                    v.get("message")
                        .or_else(|| v.get("error"))
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                })
                .filter(|m| !m.trim().is_empty())
                .map(|m| m.chars().take(300).collect::<String>());
            MoveOut::Kept(reason.unwrap_or_else(|| format!("the server answered HTTP {status}")))
        }
    }
}

/// Ask the old organization's server to remove the old row, proving the
/// move with the new enrollment's agent token. Never fails: the device has
/// already moved, so every problem is a [`MoveOut::Kept`] for the person.
pub async fn remove_old_row(old: &LeavingPrimary, new_agent_token: &str) -> MoveOut {
    match try_remove(old, new_agent_token).await {
        Ok(out) => out,
        Err(e) => MoveOut::Kept(format!("its server could not be reached: {e}")),
    }
}

async fn try_remove(old: &LeavingPrimary, new_agent_token: &str) -> Result<MoveOut> {
    let server = meshharbor_remote_control::server_url::secure(old.server_url.trim(), false)
        .url
        .trim_end_matches('/')
        .to_string();
    let resp = http_client()?
        .post(format!("{server}/api/agent/self/move"))
        .bearer_auth(&old.agent_token)
        .json(&serde_json::json!({ "agent_token": new_agent_token }))
        .send()
        .await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let out = outcome_for(status, &body);
    match &out {
        MoveOut::Removed => {
            tracing::info!(tenant = %old.tenant_id, "fr-133: old organization's row removed")
        }
        MoveOut::Kept(why) => {
            tracing::warn!(tenant = %old.tenant_id, status, %why, "fr-133: old organization's row kept")
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn token_for(tenant: &str) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"tenant_id":"{tenant}"}}"#));
        format!("h.{payload}.s")
    }

    fn cfg(server: &str, tenant: &str) -> AgentConfig {
        let mut c = crate::config::test_fixture();
        c.server_url = server.into();
        c.tenant_id = tenant.into();
        c.agent_token = format!("tok-{tenant}");
        c
    }

    #[test]
    fn only_a_replace_into_another_org_on_the_same_server_is_a_move() {
        let a = cfg("https://hub.example", "aaaa");
        assert!(is_cross_org_replace(
            &a,
            "https://hub.example/",
            &token_for("bbbb"),
            true
        ));
        assert!(!is_cross_org_replace(
            &a,
            "https://hub.example",
            &token_for("bbbb"),
            false
        ));
        assert!(!is_cross_org_replace(
            &a,
            "https://hub.example",
            &token_for("aaaa"),
            true
        ));
        assert!(!is_cross_org_replace(
            &a,
            "https://other.example",
            &token_for("bbbb"),
            true
        ));
        assert!(!is_cross_org_replace(
            &a,
            "https://hub.example",
            "not-a-jwt",
            true
        ));
    }

    #[test]
    fn the_leaving_primary_is_the_old_org_and_never_a_temporary_or_ephemeral_one() {
        let a = cfg("https://hub.example", "aaaa");
        let b = cfg("https://hub.example", "bbbb");
        let left = leaving_primary(&a, &b, false).expect("a move");
        assert_eq!(left.tenant_id, "aaaa");
        assert!(
            !format!("{left:?}").contains("tok-aaaa"),
            "the token is redacted"
        );
        assert!(
            leaving_primary(&a, &b, true).is_none(),
            "temporary leaves with mh leave"
        );
        assert!(leaving_primary(&a, &a, false).is_none(), "same org");
        assert!(leaving_primary(&a, &cfg("https://other.example", "bbbb"), false).is_none());
        let mut eph = a.clone();
        eph.ephemeral = true;
        assert!(leaving_primary(&eph, &b, false).is_none());
    }

    #[test]
    fn an_older_server_or_a_refusal_keeps_the_row_and_says_who_must_remove_it() {
        assert_eq!(outcome_for(200, "{}"), MoveOut::Removed);
        let old = outcome_for(404, "");
        assert!(
            old.notice()
                .unwrap()
                .contains("an admin there must remove it")
        );
        assert!(matches!(outcome_for(405, ""), MoveOut::Kept(_)));
        match outcome_for(403, r#"{"error":"forbidden","message":"switched off"}"#) {
            MoveOut::Kept(why) => assert_eq!(why, "switched off"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(outcome_for(500, "<html>"), MoveOut::Kept(w) if w.contains("500")));
    }

    #[test]
    fn a_protected_or_two_factor_device_refuses_the_move() {
        let dir = std::env::temp_dir().join(format!("fr133-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut c = cfg("https://hub.example", "aaaa");
        assert_eq!(move_refusal(&c, &path), None);
        c.protected = true;
        assert!(move_refusal(&c, &path).unwrap().contains("protected"));
        c.protected = false;
        std::fs::write(crate::two_factor::state_path(&path), "{}").unwrap();
        assert!(move_refusal(&c, &path).unwrap().contains("two-factor"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_move_is_offered_only_to_a_non_member_of_a_permanent_personal_device() {
        let base = || MoveOfferInput {
            personal_enrolled: Some(true),
            ephemeral: false,
            primary_server: Some("https://hub.example"),
            has_primary_tenant: true,
            session_server: "https://hub.example/",
            is_member: Some(false),
            org_name: Some("Org A".into()),
            protected: false,
            two_factor: false,
        };
        let offer = offer_for(base()).expect("non-member on personal device is asked");
        assert!(offer.question().starts_with(
            "This device belongs to \u{ab}Org A\u{bb}. Move it to your organization?"
        ));
        assert!(offer.question().contains("Keep:"));
        assert_eq!(offer.refusal, None);
        assert!(offer.done(None).contains("\u{ab}Org A\u{bb}"));
        assert_eq!(
            offer.done(Some("an admin there must remove it")),
            "an admin there must remove it"
        );

        // Member or unknown membership: never asked.
        assert_eq!(
            offer_for(MoveOfferInput {
                is_member: Some(true),
                ..base()
            }),
            None
        );
        assert_eq!(
            offer_for(MoveOfferInput {
                is_member: None,
                ..base()
            }),
            None
        );
        // Temporary/non-personal, ephemeral, or another server: never asked.
        assert_eq!(
            offer_for(MoveOfferInput {
                personal_enrolled: Some(false),
                ..base()
            }),
            None
        );
        assert_eq!(
            offer_for(MoveOfferInput {
                personal_enrolled: None,
                ..base()
            }),
            None
        );
        assert_eq!(
            offer_for(MoveOfferInput {
                ephemeral: true,
                ..base()
            }),
            None
        );
        assert_eq!(
            offer_for(MoveOfferInput {
                session_server: "https://other.example",
                ..base()
            }),
            None
        );
        // Single-org daemon omitting `orgs` still works when primary tenant is present.
        assert!(
            offer_for(MoveOfferInput {
                primary_server: None,
                ..base()
            })
            .is_some(),
            "single-org fallback"
        );
        assert_eq!(
            offer_for(MoveOfferInput {
                primary_server: None,
                has_primary_tenant: false,
                ..base()
            }),
            None
        );
        // Protected (FR-127) and two-factor (FR-129) devices refuse upfront.
        let prot = offer_for(MoveOfferInput {
            org_name: None,
            protected: true,
            ..base()
        })
        .unwrap();
        assert!(prot.refusal.as_deref().unwrap().contains("protected"));
        assert_eq!(prot.org_label(), "another organization");
        let tf = offer_for(MoveOfferInput {
            two_factor: true,
            ..base()
        })
        .unwrap();
        assert!(tf.refusal.as_deref().unwrap().contains("two-factor"));
    }
}
