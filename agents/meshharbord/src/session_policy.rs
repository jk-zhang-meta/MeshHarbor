// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P2b — the device's half of the session policy for the clipboard,
//! file transfer and audio (spec `docs/fr/FR-101-rc-session-hygiene.md` §3a).
//!
//! The org's policy arrives on `rc:request` (`session_policy`, P2a), and the
//! hub has already taken out of the grant what it refuses. This applies the
//! policy AGAIN, together with the device owner's own floor (`rc_clipboard`,
//! `rc_files`, `rc_audio`), before the grant reaches anything that acts on it:
//!
//! - the stricter of the org's and the device's value wins;
//! - `off` takes the feature out;
//! - `ask` keeps it only for a session the person here approves, on a prompt
//!   that names it ([`consent_line`]). Any other session goes without it.
//!
//! That is the half that survives a hub that was bypassed (AC4): the `files`
//! and `clipboard` channels already refuse a grant without the bit
//! (`peer.rs`), and no audio track is added without `audio_enabled`, so
//! masking the grant here is enough to make every channel follow.

use std::sync::Mutex;

use meshharbor_remote_control::models::{ConsentMode, FeaturePolicy, SessionPolicy};
use meshharbor_remote_control::permissions::Permissions;

// ── The owner's floor ───────────────────────────────────────────────────────

static DEVICE: Mutex<SessionPolicy> = Mutex::new(SessionPolicy {
    clipboard: FeaturePolicy::On,
    files: FeaturePolicy::On,
    audio: FeaturePolicy::On,
});

/// Seeded at start and on a LocalAPI `ConfigSet`, never by the server: the
/// three keys are absent from `DesiredConfig`.
pub fn set_device_policy(policy: SessionPolicy) {
    *DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = policy;
}

/// The owner's floor as it stands now; read at every session start.
pub fn device_policy() -> SessionPolicy {
    *DEVICE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The floor from a config, the three keys as one value.
pub fn from_config(cfg: &crate::config::AgentConfig) -> SessionPolicy {
    SessionPolicy {
        clipboard: cfg.rc_clipboard,
        files: cfg.rc_files,
        audio: cfg.rc_audio,
    }
}

/// What the caps report (`AgentCaps.session_policy`): the floor when it
/// restricts anything, nothing when it does not, so a device that set
/// nothing announces nothing new.
pub fn caps_policy() -> Option<SessionPolicy> {
    report(device_policy())
}

fn report(p: SessionPolicy) -> Option<SessionPolicy> {
    (!p.is_unrestricted()).then_some(p)
}

// ── The masking ─────────────────────────────────────────────────────────────

/// One of the three features a session policy covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Clipboard,
    Files,
    Audio,
}

impl Feature {
    /// The key the wire and the audit use (`features_refused`).
    pub fn wire(self) -> &'static str {
        match self {
            Self::Clipboard => "clipboard",
            Self::Files => "files",
            Self::Audio => "audio",
        }
    }

    /// How the consent prompt names it.
    fn words(self) -> &'static str {
        match self {
            Self::Clipboard => "clipboard",
            Self::Files => "file transfer",
            Self::Audio => "audio",
        }
    }
}

/// Will the person at this device be the one who approves the session?
///
/// Only on a prompt this agent raises, and never under `email`, `push` (the
/// owner approves, the agent does not prompt) or `prompt_then_email` (the
/// owner's mail may approve instead of the person here) — the hub's rule for
/// `ask`, held again here. `prompts` is whether the resolved mode, the
/// directive against the device's own floor, is a prompt.
pub fn person_asked(directive: Option<ConsentMode>, prompts: bool) -> bool {
    prompts
        && !matches!(
            directive,
            Some(ConsentMode::Email | ConsentMode::Push | ConsentMode::PromptThenEmail)
        )
}

/// The grant after the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Masked {
    pub permissions: Permissions,
    pub audio_enabled: bool,
    /// Features kept because the person here will be asked: the prompt names
    /// them, and approving the session grants them.
    pub ask: Vec<Feature>,
    /// Features taken out, each with why, for the log.
    pub refused: Vec<(Feature, &'static str)>,
}

/// Apply the org's policy (`None` from a server before P2a, or one that
/// restricts nothing) and the device's floor to a requested grant.
///
/// Audio is `audio_enabled`, which is what a track is added on; the AUDIO bit
/// is read by nothing, and goes with it. A feature that was not asked for is
/// left alone and never named.
pub fn mask(
    permissions: Permissions,
    audio_enabled: bool,
    org: Option<SessionPolicy>,
    device: SessionPolicy,
    person_asked: bool,
) -> Masked {
    let org = org.unwrap_or_default();
    let mut out = Masked {
        permissions,
        audio_enabled,
        ask: Vec::new(),
        refused: Vec::new(),
    };
    for (feature, org_p, device_p) in [
        (Feature::Clipboard, org.clipboard, device.clipboard),
        (Feature::Files, org.files, device.files),
        (Feature::Audio, org.audio, device.audio),
    ] {
        let asked_for = match feature {
            Feature::Clipboard => out.permissions.contains(Permissions::CLIPBOARD),
            Feature::Files => out.permissions.contains(Permissions::FILES),
            Feature::Audio => out.audio_enabled || out.permissions.contains(Permissions::AUDIO),
        };
        if !asked_for {
            continue;
        }
        let why = match org_p.stricter(device_p) {
            FeaturePolicy::On => None,
            FeaturePolicy::Off if org_p == FeaturePolicy::Off => Some("org_policy_off"),
            FeaturePolicy::Off => Some("device_policy_off"),
            FeaturePolicy::Ask if person_asked => {
                out.ask.push(feature);
                None
            }
            FeaturePolicy::Ask => Some("needs_consent"),
        };
        if let Some(why) = why {
            match feature {
                Feature::Clipboard => out.permissions -= Permissions::CLIPBOARD,
                Feature::Files => out.permissions -= Permissions::FILES,
                Feature::Audio => {
                    out.audio_enabled = false;
                    out.permissions -= Permissions::AUDIO;
                }
            }
            out.refused.push((feature, why));
        }
    }
    out
}

/// The consent prompt's line for the features the person is asked about,
/// or `None` when there are none. Short on purpose: it shares the native
/// panel's two-line detail with privacy mode's line, at the panel's width.
pub fn consent_line(ask: &[Feature]) -> Option<String> {
    let words: Vec<&str> = ask.iter().map(|f| f.words()).collect();
    let list = match words.as_slice() {
        [] => return None,
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    Some(format!("Approving also allows {list}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use FeaturePolicy::{Ask, Off, On};

    fn policy(
        clipboard: FeaturePolicy,
        files: FeaturePolicy,
        audio: FeaturePolicy,
    ) -> SessionPolicy {
        SessionPolicy {
            clipboard,
            files,
            audio,
        }
    }

    const ALL: Permissions = Permissions::VIEW
        .union(Permissions::INPUT)
        .union(Permissions::CLIPBOARD)
        .union(Permissions::FILES);
    const BASE: Permissions = Permissions::VIEW.union(Permissions::INPUT);

    /// AC4's core: the server sent the bits anyway (no policy at all, a hub
    /// that was bypassed), and the device's own `off` still takes them out.
    #[test]
    fn the_device_floor_holds_when_the_server_sends_no_policy() {
        let m = mask(ALL, true, None, policy(On, Off, Off), true);
        assert_eq!(m.permissions, BASE | Permissions::CLIPBOARD);
        assert!(!m.audio_enabled);
        assert_eq!(
            m.refused,
            vec![
                (Feature::Files, "device_policy_off"),
                (Feature::Audio, "device_policy_off"),
            ]
        );
        assert!(m.ask.is_empty());
    }

    #[test]
    fn an_unrestricted_policy_and_floor_change_nothing() {
        let m = mask(ALL, true, None, SessionPolicy::default(), false);
        assert_eq!((m.permissions, m.audio_enabled), (ALL, true));
        assert!(m.refused.is_empty() && m.ask.is_empty());
        let m = mask(
            ALL,
            true,
            Some(SessionPolicy::default()),
            SessionPolicy::default(),
            true,
        );
        assert_eq!((m.permissions, m.audio_enabled), (ALL, true));
    }

    /// The org's `off` is named as the org's even when the device is `off`
    /// too; the device's is named when only the device says so.
    #[test]
    fn an_off_names_whose_it_is() {
        let m = mask(
            ALL,
            false,
            Some(policy(Off, On, On)),
            policy(Off, Off, On),
            true,
        );
        assert_eq!(
            m.refused,
            vec![
                (Feature::Clipboard, "org_policy_off"),
                (Feature::Files, "device_policy_off"),
            ]
        );
    }

    /// `ask`, the org's or the device's, survives only a session the person
    /// here approves, and is then named on the prompt.
    #[test]
    fn ask_survives_only_a_prompt_the_person_answers() {
        for (org, device) in [
            (policy(Ask, On, On), SessionPolicy::default()),
            (SessionPolicy::default(), policy(Ask, On, On)),
        ] {
            let m = mask(ALL, false, Some(org), device, true);
            assert_eq!(m.permissions, ALL);
            assert_eq!(m.ask, vec![Feature::Clipboard]);
            assert!(m.refused.is_empty());

            let m = mask(ALL, false, Some(org), device, false);
            assert_eq!(m.permissions, ALL - Permissions::CLIPBOARD);
            assert!(m.ask.is_empty());
            assert_eq!(m.refused, vec![(Feature::Clipboard, "needs_consent")]);
        }
    }

    #[test]
    fn audio_is_the_flag_and_the_bit_goes_with_it() {
        let m = mask(
            BASE | Permissions::AUDIO,
            false,
            None,
            policy(On, On, Off),
            true,
        );
        assert_eq!((m.permissions, m.audio_enabled), (BASE, false));
        assert_eq!(m.refused, vec![(Feature::Audio, "device_policy_off")]);
        // Not asked for: not named.
        let m = mask(BASE, false, None, policy(Off, Off, Off), true);
        assert_eq!((m.permissions, m.audio_enabled), (BASE, false));
        assert!(m.refused.is_empty());
    }

    #[test]
    fn the_person_is_asked_only_on_a_prompt_they_answer() {
        assert!(person_asked(Some(ConsentMode::Prompt), true));
        assert!(person_asked(None, true), "an older server, a local prompt");
        assert!(
            person_asked(Some(ConsentMode::Auto), true),
            "the device's own floor raised a prompt under `auto`"
        );
        for owner_side in [
            ConsentMode::Email,
            ConsentMode::Push,
            ConsentMode::PromptThenEmail,
        ] {
            assert!(!person_asked(Some(owner_side), true), "{owner_side:?}");
        }
        assert!(!person_asked(Some(ConsentMode::Prompt), false));
        assert!(!person_asked(Some(ConsentMode::Auto), false));
    }

    /// The line names each feature in words, and fits the native panel
    /// (460 px, about 70 characters at its font) even with all three.
    #[test]
    fn the_consent_line_names_the_features_and_fits() {
        assert_eq!(consent_line(&[]), None);
        assert_eq!(
            consent_line(&[Feature::Files]).as_deref(),
            Some("Approving also allows file transfer.")
        );
        assert_eq!(
            consent_line(&[Feature::Clipboard, Feature::Files]).as_deref(),
            Some("Approving also allows clipboard and file transfer.")
        );
        let all = consent_line(&[Feature::Clipboard, Feature::Files, Feature::Audio]).unwrap();
        assert_eq!(
            all,
            "Approving also allows clipboard, file transfer and audio."
        );
        assert!(all.chars().count() <= 64, "{all}");
    }

    /// Pure, not through the process-wide floor: a test that set it would
    /// race every other test in the binary that reads it.
    #[test]
    fn the_caps_report_the_floor_only_when_it_restricts() {
        assert_eq!(report(SessionPolicy::default()), None);
        assert_eq!(report(policy(On, Off, On)), Some(policy(On, Off, On)));
        assert_eq!(report(policy(Ask, On, On)), Some(policy(Ask, On, On)));
    }
}
